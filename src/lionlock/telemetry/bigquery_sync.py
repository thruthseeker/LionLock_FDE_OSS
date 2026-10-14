"""Copy the reference receiver's warehouse into BigQuery (standard library only).

Run it next to the receiver, for example hourly from a systemd timer::

    lionlock-telemetry bigquery-sync --data-dir /var/lib/lionlock-telemetry \\
        --state-file /var/lib/lionlock-bigquery/state.json \\
        --project my-project --dataset lionlock_telemetry --location us-central1

Only rows the receiver has already validated and committed are copied, and nothing is
transformed: each BigQuery table has the warehouse table's columns, types and nullability, and
each row is the warehouse row serialized as canonical JSON (sorted keys, no whitespace).

Every row is loaded exactly once:

- ``events`` and ``trust_records`` are insert-only in the warehouse, so rows are copied in
  ``rowid`` order. Each batch is a fixed ``rowid`` range that is written to the state file
  before its load job is submitted. The job ID is derived from the target, the range and the
  SHA-256 of the batch, so after a crash the same range is rebuilt byte for byte and the
  existing job is found instead of loading the rows twice.
- ``uploads`` is small and its ``chain_status`` changes when a late predecessor arrives, so it
  is replaced as a whole whenever its content changes.

Load jobs are atomic, and a batch counts as loaded only when BigQuery reports the job done with
no error and with exactly as many output rows as were sent. The state file also keeps the hash
of the last row loaded from each table; if that row no longer matches (for example, the
warehouse was replaced), the sync refuses to continue rather than skip or repeat rows.

Credentials come from the Compute Engine metadata server (the VM's attached service account),
so no key file is needed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Sequence, Tuple
from urllib.parse import quote

from .receiver import _fsync_directory, _warehouse_state

STATE_FORMAT = "lionlock-bigquery-sync/1"
APPEND_TABLES: Tuple[str, ...] = ("events", "trust_records")
REPLACE_TABLES: Tuple[str, ...] = ("uploads",)
DEFAULT_BATCH_ROWS = 20_000
DEFAULT_BATCH_BYTES = 8 * 1024 * 1024

METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)
API_ROOT = "https://bigquery.googleapis.com"

_BQ_TYPES = {"TEXT": "STRING", "INTEGER": "INTEGER", "REAL": "FLOAT"}

# (method, url, headers, body) -> (status, response body)
Transport = Callable[[str, str, Mapping[str, str], "bytes | None"], Tuple[int, bytes]]


class BigQuerySyncError(Exception):
    """The sync stopped without loading the current batch; nothing was marked as loaded."""


@dataclass(frozen=True)
class SyncTarget:
    project: str
    dataset: str
    location: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str):
        return None


def urllib_transport(timeout_s: float = 60.0) -> Transport:
    """HTTPS transport that never follows redirects, so the access token stays with Google."""
    opener = urllib.request.build_opener(_NoRedirect())

    def send(method: str, url: str, headers: Mapping[str, str], body: bytes | None):
        request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with opener.open(request, timeout=timeout_s) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except OSError as exc:  # DNS failure, refused or reset connection, timeout
            raise BigQuerySyncError(f"{method} {url.split('?')[0]} failed: {exc}") from exc

    return send


def metadata_token_provider(timeout_s: float = 10.0) -> Callable[[], str]:
    """Access tokens for the VM's service account, cached until a minute before they expire."""
    # The metadata server is link-local: never route it through a proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    cached: Dict[str, Any] = {"token": "", "expires": 0.0}

    def token() -> str:
        if cached["token"] and time.monotonic() < cached["expires"]:
            return str(cached["token"])
        request = urllib.request.Request(METADATA_TOKEN_URL, headers={"Metadata-Flavor": "Google"})
        try:
            with opener.open(request, timeout=timeout_s) as response:
                payload = json.loads(response.read())
            access_token = str(payload["access_token"])
            lifetime = int(payload.get("expires_in", 0))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise BigQuerySyncError(
                f"could not get an access token from the metadata server: {exc!r}"
            ) from exc
        cached["token"] = access_token
        cached["expires"] = time.monotonic() + max(0, lifetime - 60)
        return access_token

    return token


def _error_message(status: int, body: bytes) -> str:
    try:
        message = json.loads(body)["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = body[:200].decode("utf-8", "replace")
    return f"HTTP {status}: {message}"


class BigQueryClient:
    """The two BigQuery job calls the sync needs: submit a load job and read a job back."""

    def __init__(
        self,
        target: SyncTarget,
        token: Callable[[], str],
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        poll_timeout_s: float = 900.0,
    ) -> None:
        self.target = target
        self._token = token
        self._transport = transport or urllib_transport()
        self._sleep = sleep
        self._poll_timeout_s = poll_timeout_s

    def _call(self, method: str, url: str, body: bytes | None = None, content_type: str = ""):
        headers = {"Authorization": f"Bearer {self._token()}"}
        if content_type:
            headers["Content-Type"] = content_type
        status, payload = self._transport(method, url, headers, body)
        return status, payload

    def get_job(self, job_id: str) -> Dict[str, Any] | None:
        url = (
            f"{API_ROOT}/bigquery/v2/projects/{quote(self.target.project, safe='')}/jobs/"
            f"{quote(job_id, safe='')}?location={quote(self.target.location, safe='')}"
        )
        status, payload = self._call("GET", url)
        if status == 404:
            return None
        if status != 200:
            raise BigQuerySyncError(
                f"reading job {job_id} failed: {_error_message(status, payload)}"
            )
        return dict(json.loads(payload))

    def delete_table(self, table: str) -> None:
        """Delete a table in the target dataset; a table that does not exist counts as deleted."""
        url = (
            f"{API_ROOT}/bigquery/v2/projects/{quote(self.target.project, safe='')}/datasets/"
            f"{quote(self.target.dataset, safe='')}/tables/{quote(table, safe='')}"
        )
        status, payload = self._call("DELETE", url)
        if status not in (200, 204, 404):
            raise BigQuerySyncError(
                f"deleting table {table} failed: {_error_message(status, payload)}"
            )

    def submit_load(
        self, job_id: str, table: str, schema: List[Dict[str, str]], data: bytes, *, replace: bool
    ) -> None:
        load: Dict[str, Any] = {
            "destinationTable": {
                "projectId": self.target.project,
                "datasetId": self.target.dataset,
                "tableId": table,
            },
            "schema": {"fields": schema},
            "sourceFormat": "NEWLINE_DELIMITED_JSON",
            "createDisposition": "CREATE_IF_NEEDED",
            "writeDisposition": "WRITE_TRUNCATE" if replace else "WRITE_APPEND",
            "ignoreUnknownValues": False,
            "maxBadRecords": 0,
        }
        if not replace:
            # Daily ingestion-time partitions, so the dataset's partition expiration applies.
            load["timePartitioning"] = {"type": "DAY"}
        job = {
            "jobReference": {
                "projectId": self.target.project,
                "jobId": job_id,
                "location": self.target.location,
            },
            "configuration": {"load": load},
        }
        boundary = "lionlock_" + hashlib.sha256(data).hexdigest()
        if boundary.encode("ascii") in data:
            raise BigQuerySyncError("multipart boundary occurs in the batch")
        body = b"".join(
            (
                f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode(),
                json.dumps(job, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                f"\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n".encode(),
                data,
                f"\r\n--{boundary}--\r\n".encode(),
            )
        )
        url = (
            f"{API_ROOT}/upload/bigquery/v2/projects/{quote(self.target.project, safe='')}"
            "/jobs?uploadType=multipart"
        )
        status, payload = self._call(
            "POST", url, body, content_type=f"multipart/related; boundary={boundary}"
        )
        if status == 409:
            return  # the job already exists; the caller reads it back
        if status != 200:
            raise BigQuerySyncError(
                f"submitting load job {job_id} failed: {_error_message(status, payload)}"
            )

    def wait(self, job_id: str) -> Dict[str, Any]:
        deadline = time.monotonic() + self._poll_timeout_s
        delay = 1.0
        while True:
            job = self.get_job(job_id)
            if job is None:
                raise BigQuerySyncError(f"job {job_id} was submitted but cannot be found")
            if job.get("status", {}).get("state") == "DONE":
                return job
            if time.monotonic() >= deadline:
                raise BigQuerySyncError(f"job {job_id} did not finish in time; run the sync again")
            self._sleep(delay)
            delay = min(delay * 2, 15.0)

    def load_once(
        self,
        base_id: str,
        table: str,
        schema: List[Dict[str, str]],
        data: bytes,
        rows: int,
        *,
        replace: bool,
        attempt: int = 1,
        record_failure: Callable[[int], None] = lambda _next_attempt: None,
    ) -> str:
        """Load ``data`` unless an earlier run already did; returns the ID of the job that did.

        Job IDs are ``base_id-<attempt>``, starting from the first attempt not known to have
        failed. An existing job that succeeded means the batch is loaded. A failed job loaded
        nothing: ``record_failure`` is told the next attempt number so the state file remembers
        it, and the next ID is tried. A job submitted by this call that fails stops the sync
        instead, so a persistent error is retried once per run, never in a loop.
        """
        while True:
            job_id = f"{base_id}-{attempt}"
            job = self.get_job(job_id)
            submitted = job is None
            if submitted:
                self.submit_load(job_id, table, schema, data, replace=replace)
            job = self.wait(job_id)
            error = job.get("status", {}).get("errorResult")
            if error:
                attempt += 1
                record_failure(attempt)
                if submitted:
                    raise BigQuerySyncError(
                        f"load job {job_id} into {table} failed: {error.get('message', error)}; "
                        "nothing was loaded, and the next run retries it"
                    )
                continue
            output = int(job.get("statistics", {}).get("load", {}).get("outputRows", -1))
            if output != rows:
                raise BigQuerySyncError(
                    f"load job {job_id} into {table} reports {output} rows, expected {rows}"
                )
            return job_id


def _json_line(columns: Sequence[str], values: Sequence[Any]) -> bytes:
    for value in values:
        if isinstance(value, (bytes, bytearray, memoryview)):
            raise BigQuerySyncError("warehouse rows must not contain binary values")
    record = dict(zip(columns, values))
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "ascii"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def table_schema(conn: sqlite3.Connection, table: str) -> Tuple[List[str], List[Dict[str, str]]]:
    columns: List[str] = []
    fields: List[Dict[str, str]] = []
    for _cid, name, decl, notnull, _default, pk in conn.execute(f"PRAGMA table_info({table})"):
        bq_type = _BQ_TYPES.get(str(decl).upper())
        if bq_type is None:
            raise BigQuerySyncError(f"{table}.{name} has unsupported type {decl!r}")
        columns.append(str(name))
        mode = "REQUIRED" if notnull or pk else "NULLABLE"
        fields.append({"name": str(name), "type": bq_type, "mode": mode})
    return columns, fields


def _empty_state(target: SyncTarget) -> Dict[str, Any]:
    return {
        "format": STATE_FORMAT,
        "project": target.project,
        "dataset": target.dataset,
        "location": target.location,
        "watermarks": {table: 0 for table in APPEND_TABLES},
        "anchors": {table: "" for table in APPEND_TABLES},
        "replaced_sha256": {table: "" for table in REPLACE_TABLES},
        # Counts completed replacements. It is part of each replacement's job ID, so content
        # that recurs (a deletion can restore an earlier state) is loaded again, not skipped.
        "replace_generation": {table: 0 for table in REPLACE_TABLES},
        # The next job attempt for a table's current content, after failed loads of it.
        "replace_attempts": {table: {"sha256": "", "attempt": 1} for table in REPLACE_TABLES},
        "pending": None,
    }


def load_state(path: Path, target: SyncTarget) -> Dict[str, Any]:
    if not path.exists():
        return _empty_state(target)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BigQuerySyncError(f"state file {path} is unreadable: {exc}") from exc
    if not isinstance(state, dict) or state.get("format") != STATE_FORMAT:
        raise BigQuerySyncError(f"state file {path} is not a {STATE_FORMAT} file")
    for key in ("project", "dataset", "location"):
        if state.get(key) != getattr(target, key):
            raise BigQuerySyncError(
                f"state file {path} belongs to {key} {state.get(key)!r}, not "
                f"{getattr(target, key)!r}; use a new state file for a new destination"
            )
    expected = _empty_state(target)
    for key in (
        "watermarks",
        "anchors",
        "replaced_sha256",
        "replace_generation",
        "replace_attempts",
    ):
        if not isinstance(state.get(key), dict) or set(state[key]) != set(expected[key]):
            raise BigQuerySyncError(f"state file {path} has a malformed {key!r}")
    for table, mark in state["watermarks"].items():
        if not _count(mark, 0):
            raise BigQuerySyncError(f"state file {path} has a bad watermark for {table}")
    for table, generation in state["replace_generation"].items():
        if not _count(generation, 0):
            raise BigQuerySyncError(f"state file {path} has a bad replace generation for {table}")
    for table, entry in state["replace_attempts"].items():
        if (
            not isinstance(entry, dict)
            or set(entry) != {"sha256", "attempt"}
            or not _count(entry["attempt"], 1)
        ):
            raise BigQuerySyncError(f"state file {path} has a bad replace attempt for {table}")
    pending = state.get("pending")
    if pending is not None:
        keys = {"table", "first_rowid", "last_rowid", "rows", "sha256", "base_id", "attempt"}
        if not isinstance(pending, dict) or set(pending) != keys:
            raise BigQuerySyncError(f"state file {path} has a malformed pending batch")
        if pending["table"] not in APPEND_TABLES or not _count(pending["attempt"], 1):
            raise BigQuerySyncError(f"state file {path} has a malformed pending batch")
    return state


def _count(value: Any, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def save_state(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    data = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(partial, path)
    _fsync_directory(path.parent)


@contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """Hold an advisory lock so two syncs never share one state file."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path.with_name(path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise BigQuerySyncError(
                "another bigquery-sync is running with this state file"
            ) from exc
        yield
    finally:
        os.close(fd)


def _open_warehouse(data_dir: Path) -> sqlite3.Connection:
    path = data_dir / "warehouse.db"
    if not path.is_file():
        raise BigQuerySyncError(f"{path} does not exist")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        state = _warehouse_state(conn)
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise BigQuerySyncError(f"{path} is not a readable SQLite database") from exc
    if state != "current":
        conn.close()
        raise BigQuerySyncError(f"{path} cannot be synced: {state}")
    return conn


def _range_lines(
    conn: sqlite3.Connection, table: str, columns: Sequence[str], first: int, last: int
) -> List[Tuple[int, bytes]]:
    query = (
        f"SELECT rowid, {', '.join(columns)} FROM {table} "
        "WHERE rowid BETWEEN ? AND ? ORDER BY rowid"
    )
    return [(row[0], _json_line(columns, row[1:])) for row in conn.execute(query, (first, last))]


def _next_batch(
    conn: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
    after: int,
    max_rows: int,
    max_bytes: int,
) -> List[Tuple[int, bytes]]:
    query = (
        f"SELECT rowid, {', '.join(columns)} FROM {table} WHERE rowid > ? ORDER BY rowid LIMIT ?"
    )
    batch: List[Tuple[int, bytes]] = []
    size = 0
    for row in conn.execute(query, (after, max_rows)):
        line = _json_line(columns, row[1:])
        if batch and size + len(line) + 1 > max_bytes:
            break
        batch.append((row[0], line))
        size += len(line) + 1
    return batch


def _ndjson(lines: Sequence[Tuple[int, bytes]]) -> bytes:
    return b"".join(line + b"\n" for _rowid, line in lines)


def _check_anchor(conn: sqlite3.Connection, state: Mapping[str, Any], table: str, columns) -> None:
    mark = state["watermarks"][table]
    if mark == 0:
        return
    lines = _range_lines(conn, table, columns, mark, mark)
    if not lines or _sha256(lines[0][1]) != state["anchors"][table]:
        raise BigQuerySyncError(
            f"{table}: the last row loaded (rowid {mark}) is missing or changed in the warehouse; "
            "refusing to continue so rows are neither skipped nor loaded twice"
        )


def _base_id(target: SyncTarget, table: str, label: str, data: bytes) -> str:
    digest = _sha256(f"{target.project}\n{target.dataset}\n{table}\n".encode("utf-8") + data)
    return f"lionlock_{table}_{label}_{digest[:32]}"


def sync(
    data_dir: Path,
    state_file: Path,
    client: BigQueryClient,
    *,
    batch_rows: int = DEFAULT_BATCH_ROWS,
    batch_bytes: int = DEFAULT_BATCH_BYTES,
) -> Dict[str, Any]:
    """Load every warehouse row not yet in BigQuery; returns a summary of what was loaded."""
    target = client.target
    summary: Dict[str, Any] = {"ok": True, "tables": {}}
    with _exclusive(state_file):
        state = load_state(state_file, target)
        conn = _open_warehouse(data_dir)
        try:
            schemas = {
                table: table_schema(conn, table) for table in (*REPLACE_TABLES, *APPEND_TABLES)
            }
            # Replaced tables go first: they do not depend on the append watermarks, so a
            # deletion reaches them even when an append table stops on a missing anchor.
            for table in REPLACE_TABLES:
                summary["tables"][table] = _replace_table(
                    conn, client, state, state_file, table, schemas[table]
                )

            for table in APPEND_TABLES:
                _check_anchor(conn, state, table, schemas[table][0])
                summary["tables"][table] = {"rows_loaded": 0, "jobs": []}

            pending = state["pending"]
            if pending is not None:
                _finish_batch(conn, client, state, state_file, schemas, pending, summary)

            for table in APPEND_TABLES:
                columns, _fields = schemas[table]
                while True:
                    batch = _next_batch(
                        conn, table, columns, state["watermarks"][table], batch_rows, batch_bytes
                    )
                    if not batch:
                        break
                    data = _ndjson(batch)
                    first, last = batch[0][0], batch[-1][0]
                    pending = {
                        "table": table,
                        "first_rowid": first,
                        "last_rowid": last,
                        "rows": len(batch),
                        "sha256": _sha256(data),
                        "base_id": _base_id(target, table, f"{first}_{last}", data),
                        "attempt": 1,
                    }
                    # Recorded before the job exists, so a crash resumes this exact range.
                    state["pending"] = pending
                    save_state(state_file, state)
                    _finish_batch(conn, client, state, state_file, schemas, pending, summary)
                summary["tables"][table]["watermark"] = state["watermarks"][table]
        finally:
            conn.close()
    return summary


def _finish_batch(
    conn: sqlite3.Connection,
    client: BigQueryClient,
    state: Dict[str, Any],
    state_file: Path,
    schemas: Mapping[str, Tuple[List[str], List[Dict[str, str]]]],
    pending: Mapping[str, Any],
    summary: Dict[str, Any],
) -> None:
    table = pending["table"]
    columns, fields = schemas[table]
    if not _no_gap(conn, table, state["watermarks"][table], pending["first_rowid"]):
        raise BigQuerySyncError(f"{table}: pending batch does not follow the last loaded row")
    lines = _range_lines(conn, table, columns, pending["first_rowid"], pending["last_rowid"])
    data = _ndjson(lines)
    if len(lines) != pending["rows"] or _sha256(data) != pending["sha256"]:
        raise BigQuerySyncError(
            f"{table}: rows {pending['first_rowid']}-{pending['last_rowid']} changed since they "
            "were scheduled; refusing to load them"
        )

    def record_failure(next_attempt: int) -> None:
        state["pending"] = {**pending, "attempt": next_attempt}
        save_state(state_file, state)

    job_id = client.load_once(
        pending["base_id"],
        table,
        fields,
        data,
        len(lines),
        replace=False,
        attempt=pending["attempt"],
        record_failure=record_failure,
    )
    state["watermarks"][table] = pending["last_rowid"]
    state["anchors"][table] = _sha256(lines[-1][1])
    state["pending"] = None
    save_state(state_file, state)
    summary["tables"][table]["rows_loaded"] += len(lines)
    summary["tables"][table]["jobs"].append(job_id)


def _replace_table(
    conn: sqlite3.Connection,
    client: BigQueryClient,
    state: Dict[str, Any],
    state_file: Path,
    table: str,
    schema: Tuple[List[str], List[Dict[str, str]]],
) -> Dict[str, Any]:
    """Make the BigQuery table hold exactly the warehouse table's current rows."""
    columns, fields = schema
    order = "install_id, segment_index"
    lines = [
        (0, _json_line(columns, row))
        for row in conn.execute(f"SELECT {', '.join(columns)} FROM {table} ORDER BY {order}")
    ]
    data = _ndjson(lines)
    digest = _sha256(data)
    entry: Dict[str, Any] = {"rows": len(lines), "unchanged": True}
    loaded = state["replaced_sha256"][table]
    if digest == loaded or (not lines and not loaded):
        return entry  # unchanged, or empty and never copied
    generation = state["replace_generation"][table] + 1
    if lines:
        tried = state["replace_attempts"][table]
        entry["job"] = client.load_once(
            _base_id(client.target, table, f"g{generation}", data),
            table,
            fields,
            data,
            len(lines),
            replace=True,
            attempt=tried["attempt"] if tried["sha256"] == digest else 1,
            record_failure=_replace_failure_recorder(state, state_file, table, digest),
        )
    else:
        # Every row was deleted. A load job cannot be relied on to accept an empty file, so
        # the copy is cleared by deleting the table; the next replacement recreates it.
        client.delete_table(table)
        entry["deleted"] = True
    entry["unchanged"] = False
    state["replaced_sha256"][table] = digest
    state["replace_generation"][table] = generation
    state["replace_attempts"][table] = {"sha256": "", "attempt": 1}
    save_state(state_file, state)
    return entry


def _replace_failure_recorder(
    state: Dict[str, Any], state_file: Path, table: str, digest: str
) -> Callable[[int], None]:
    def record(next_attempt: int) -> None:
        state["replace_attempts"][table] = {"sha256": digest, "attempt": next_attempt}
        save_state(state_file, state)

    return record


def _no_gap(conn: sqlite3.Connection, table: str, after: int, first: int) -> bool:
    """True when no row lies between the watermark and the start of the pending batch."""
    row = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE rowid > ? AND rowid < ?", (after, first)
    ).fetchone()
    return int(row[0]) == 0
