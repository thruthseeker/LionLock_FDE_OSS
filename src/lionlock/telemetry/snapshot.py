"""Upload snapshot file format, shared by the exporter and the receiver.

A snapshot is a small standalone SQLite file holding only policy-sanitized rows plus a
``snapshot_meta`` table. Its ``content_digest`` is a SHA-256 over the canonical JSON of every
meta entry and row, so it is identical for identical content on any platform and SQLite
version. The receiver treats every snapshot as untrusted input: see ``open_untrusted`` and
``validate_snapshot``.

Validation sees what SQL sees, and a SQLite file can carry more than that: bytes appended
after the last page, or freed pages that still hold deleted rows. So a validated file is never
sent or stored as-is. ``rebuild_clean`` writes the validated meta and rows into a brand-new file,
and only those bytes are uploaded or kept.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Sequence, Tuple

from . import policy
from .canonical import canonical_json

_LOGGER = logging.getLogger(__name__)

SNAPSHOT_FORMAT = "lionlock-telemetry-snapshot"
# v2: label fields hold only public values, and transfers carry rebuilt files (docs/TELEMETRY.md).
SNAPSHOT_SCHEMA_VERSION = 2
SNAPSHOT_APPLICATION_ID = 0x4C4C4B53  # "LLKS"
SQLITE_HEADER = b"SQLite format 3\x00"
DEFAULT_MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024

DATA_TABLES: Tuple[str, ...] = ("events", "trust_records")

EVENT_COLUMNS: Tuple[str, ...] = (
    "seq",
    "ts_hour",
    "decision",
    "severity",
    "reason_code",
    "aggregate_score",
    "signal_scores_json",
    "signal_bundle_json",
    "duration_ms",
    "config_hash",
)

TRUST_COLUMNS: Tuple[str, ...] = (
    "seq",
    "ts_hour",
    "session_key",
    "turn_index",
    "model_family",
    "prompt_type",
    "trust_score",
    "trust_label",
    "badge",
    "volatility",
    "drift_detected",
    "trigger_flags_json",
    "detail_json",
)

COLUMNS: Dict[str, Tuple[str, ...]] = {"events": EVENT_COLUMNS, "trust_records": TRUST_COLUMNS}

# Exact DDL. The receiver rejects any file whose schema differs from this in any way.
TABLE_DDL: Dict[str, str] = {
    "snapshot_meta": (
        "CREATE TABLE snapshot_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
    ),
    "events": (
        "CREATE TABLE events ("
        "seq INTEGER PRIMARY KEY NOT NULL, "
        "ts_hour TEXT, "
        "decision TEXT NOT NULL, "
        "severity TEXT, "
        "reason_code TEXT, "
        "aggregate_score REAL, "
        "signal_scores_json TEXT NOT NULL, "
        "signal_bundle_json TEXT, "
        "duration_ms INTEGER, "
        "config_hash TEXT)"
    ),
    "trust_records": (
        "CREATE TABLE trust_records ("
        "seq INTEGER PRIMARY KEY NOT NULL, "
        "ts_hour TEXT, "
        "session_key TEXT NOT NULL, "
        "turn_index INTEGER, "
        "model_family TEXT NOT NULL, "
        "prompt_type TEXT, "
        "trust_score REAL NOT NULL, "
        "trust_label TEXT NOT NULL, "
        "badge TEXT, "
        "volatility REAL, "
        "drift_detected INTEGER, "
        "trigger_flags_json TEXT NOT NULL, "
        "detail_json TEXT NOT NULL)"
    ),
}
_AUTOINDEX = "sqlite_autoindex_snapshot_meta_1"

META_KEYS: Tuple[str, ...] = (
    "format",
    "schema_version",
    "install_id",
    "segment_index",
    "prev_segment_digest",
    "lionlock_version",
    "python",
    "platform",
    "events_rows",
    "events_pruned_before_export",
    "trust_records_rows",
    "trust_records_pruned_before_export",
    "content_digest",
)

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COUNT = re.compile(r"^(0|[1-9][0-9]{0,17})$")


class SnapshotError(ValueError):
    """Raised when a snapshot file is malformed or violates the export policy."""


@dataclass(frozen=True)
class SnapshotInfo:
    meta: Dict[str, str]
    rows: Dict[str, List[Tuple[Any, ...]]]

    @property
    def install_id(self) -> str:
        return self.meta["install_id"]

    @property
    def segment_index(self) -> int:
        return int(self.meta["segment_index"])

    @property
    def content_digest(self) -> str:
        return self.meta["content_digest"]


def compute_digest(conn: sqlite3.Connection) -> str:
    """SHA-256 over canonical meta (minus ``content_digest``) and all rows in ``seq`` order."""
    digest = hashlib.sha256(f"{SNAPSHOT_FORMAT}/{SNAPSHOT_SCHEMA_VERSION}\n".encode("ascii"))
    meta = sorted(
        (str(key), str(value))
        for key, value in conn.execute("SELECT key, value FROM snapshot_meta")
        if key != "content_digest"
    )
    digest.update(f"meta {canonical_json(meta)}\n".encode("ascii"))
    for table in DATA_TABLES:
        columns = ",".join(COLUMNS[table])
        for row in conn.execute(f"SELECT {columns} FROM {table} ORDER BY seq"):
            digest.update(f"{table} {canonical_json(list(row))}\n".encode("ascii"))
    return digest.hexdigest()


def write_snapshot(
    path: Path, meta: Mapping[str, str], rows: Mapping[str, Sequence[Tuple[Any, ...]]]
) -> Tuple[str, str]:
    """Write a snapshot atomically; return ``(content_digest, file_sha256)``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.unlink(missing_ok=True)
    conn = sqlite3.connect(str(tmp_path), isolation_level=None)
    try:
        conn.execute("PRAGMA page_size=4096")
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute(f"PRAGMA application_id={SNAPSHOT_APPLICATION_ID}")
        conn.execute(f"PRAGMA user_version={SNAPSHOT_SCHEMA_VERSION}")
        conn.execute("BEGIN")
        for ddl in TABLE_DDL.values():
            conn.execute(ddl)
        conn.executemany(
            "INSERT INTO snapshot_meta (key, value) VALUES (?, ?)",
            sorted((str(key), str(value)) for key, value in meta.items()),
        )
        for table in DATA_TABLES:
            columns = COLUMNS[table]
            placeholders = ",".join("?" for _ in columns)
            conn.executemany(
                f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})",
                rows.get(table, ()),
            )
        # Digest what SQLite will hand back to a reader, not the Python values passed in.
        content_digest = compute_digest(conn)
        conn.execute(
            "INSERT INTO snapshot_meta (key, value) VALUES ('content_digest', ?)",
            (content_digest,),
        )
        conn.execute("COMMIT")
    finally:
        conn.close()
    # SQLite syncs the file on COMMIT; syncing the directory makes the rename durable too.
    os.replace(tmp_path, path)
    _fsync_directory(path.parent)
    return content_digest, file_sha256(path)


def _fsync_directory(directory: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def open_untrusted(path: Path) -> Iterator[sqlite3.Connection]:
    """Open a snapshot read-only with SQLite's hardening options for untrusted files."""
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    try:
        defensive = getattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE", None)
        if defensive is not None and hasattr(conn, "setconfig"):
            conn.setconfig(defensive, True)
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA cell_size_check=ON")
        yield conn
    finally:
        conn.close()


def _normalize_sql(sql: str | None) -> str | None:
    return " ".join(sql.split()) if sql is not None else None


def _check_schema(conn: sqlite3.Connection) -> None:
    app_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if app_id != SNAPSHOT_APPLICATION_ID or version != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotError("not a LionLock telemetry snapshot (application_id/user_version)")
    expected = {("table", name, _normalize_sql(ddl)) for name, ddl in TABLE_DDL.items()}
    expected.add(("index", _AUTOINDEX, None))
    found = {
        (str(kind), str(name), _normalize_sql(sql))
        for kind, name, sql in conn.execute("SELECT type, name, sql FROM sqlite_master")
    }
    if found != expected:
        raise SnapshotError("snapshot schema does not match the expected schema exactly")


def _check_meta(meta: Mapping[str, str]) -> None:
    if set(meta) != set(META_KEYS):
        raise SnapshotError("snapshot_meta keys do not match the expected set")
    if meta["format"] != SNAPSHOT_FORMAT or meta["schema_version"] != str(SNAPSHOT_SCHEMA_VERSION):
        raise SnapshotError("unsupported snapshot format or schema version")
    if not _HEX32.fullmatch(meta["install_id"]):
        raise SnapshotError("install_id must be 32 lowercase hex characters")
    if not _COUNT.fullmatch(meta["segment_index"]) or int(meta["segment_index"]) < 1:
        raise SnapshotError("segment_index must be a positive integer")
    if meta["prev_segment_digest"] and not _HEX64.fullmatch(meta["prev_segment_digest"]):
        raise SnapshotError("prev_segment_digest must be empty or 64 lowercase hex characters")
    if not _HEX64.fullmatch(meta["content_digest"]):
        raise SnapshotError("content_digest must be 64 lowercase hex characters")
    for key in (
        "events_rows",
        "events_pruned_before_export",
        "trust_records_rows",
        "trust_records_pruned_before_export",
    ):
        if not _COUNT.fullmatch(meta[key]):
            raise SnapshotError(f"{key} must be a non-negative integer")
    if meta["lionlock_version"] != policy.package_version_label(meta["lionlock_version"]):
        raise SnapshotError("lionlock_version is not a public release version")
    if meta["python"] != policy.python_label(meta["python"]):
        raise SnapshotError("python must be a major.minor label")
    if meta["platform"] not in set(policy.PLATFORMS.values()) | {"other"}:
        raise SnapshotError("platform must be a coarse OS label")


def _json_column(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SnapshotError("JSON column holds a non-text value")
    try:
        return json.loads(value)
    except ValueError as exc:
        raise SnapshotError("JSON column holds invalid JSON") from exc


def _policy_event_row(row: Tuple[Any, ...]) -> Tuple[Any, ...] | None:
    values = dict(zip(EVENT_COLUMNS, row))
    return policy.event_row(
        seq=values["seq"],
        ts=values["ts_hour"],
        decision=values["decision"],
        severity=values["severity"],
        reason_code=values["reason_code"],
        aggregate_score=values["aggregate_score"],
        scores=_json_column(values["signal_scores_json"]),
        bundle=_json_column(values["signal_bundle_json"]),
        duration_ms=values["duration_ms"],
        config_hash=values["config_hash"],
    )


def _policy_trust_row(row: Tuple[Any, ...]) -> Tuple[Any, ...] | None:
    values = dict(zip(TRUST_COLUMNS, row))
    return policy.trust_row(
        seq=values["seq"],
        ts=values["ts_hour"],
        session_key=values["session_key"],
        turn_index=values["turn_index"],
        model=values["model_family"],
        prompt_type=values["prompt_type"],
        trust_score=values["trust_score"],
        trust_label=values["trust_label"],
        badge=values["badge"],
        volatility=values["volatility"],
        drift_detected=values["drift_detected"],
        flags=_json_column(values["trigger_flags_json"]),
        detail=_json_column(values["detail_json"]),
    )


def validate_snapshot(path: Path, *, max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES) -> SnapshotInfo:
    """Fully validate an untrusted snapshot file; raise ``SnapshotError`` on any violation."""
    size = path.stat().st_size
    if size > max_bytes:
        raise SnapshotError("snapshot exceeds the size limit")
    with path.open("rb") as handle:
        if handle.read(len(SQLITE_HEADER)) != SQLITE_HEADER:
            raise SnapshotError("not a SQLite database file")
    try:
        with open_untrusted(path) as conn:
            _check_schema(conn)
            check = conn.execute("PRAGMA quick_check").fetchall()
            if check != [("ok",)]:
                raise SnapshotError("SQLite quick_check failed")
            meta = {str(k): str(v) for k, v in conn.execute("SELECT key, value FROM snapshot_meta")}
            _check_meta(meta)
            if compute_digest(conn) != meta["content_digest"]:
                raise SnapshotError("content_digest does not match snapshot contents")
            rows: Dict[str, List[Tuple[Any, ...]]] = {}
            for table, rebuild in (
                ("events", _policy_event_row),
                ("trust_records", _policy_trust_row),
            ):
                columns = ",".join(COLUMNS[table])
                table_rows = [
                    tuple(row)
                    for row in conn.execute(f"SELECT {columns} FROM {table} ORDER BY seq")
                ]
                for row in table_rows:
                    if rebuild(row) != row:
                        raise SnapshotError(
                            f"{table} row seq={row[0]!r} violates the export policy"
                        )
                if len(table_rows) != int(meta[f"{table}_rows"]):
                    raise SnapshotError(f"{table}_rows does not match the row count")
                rows[table] = table_rows
    except SnapshotError:
        raise
    except sqlite3.DatabaseError as exc:
        raise SnapshotError(f"unreadable SQLite file: {type(exc).__name__}") from exc
    except (TypeError, ValueError) as exc:
        # e.g. a BLOB planted in a TEXT column cannot be canonicalized.
        raise SnapshotError(f"snapshot holds non-canonical values: {type(exc).__name__}") from exc
    return SnapshotInfo(meta=meta, rows=rows)


def read_capped(path: Path, max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES) -> bytes:
    """Read a snapshot file once, refusing anything larger than ``max_bytes``."""
    if path.stat().st_size > max_bytes:
        raise SnapshotError("snapshot exceeds the size limit")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SnapshotError("snapshot exceeds the size limit")
    return data


@contextmanager
def _private_dir(parent: Path | None) -> Iterator[Path]:
    """A fresh owner-only directory, removed with everything in it when the block exits.

    A failed removal is logged and raised, never ignored: the directory may hold raw input.
    """
    directory = Path(tempfile.mkdtemp(prefix="lionlock-", dir=parent))
    try:
        yield directory
    finally:
        try:
            shutil.rmtree(directory)
        except OSError:
            _LOGGER.error("could not remove private work directory %s", directory)
            raise


def validate_snapshot_bytes(
    data: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
    work_dir: Path | None = None,
) -> SnapshotInfo:
    """Validate one captured snapshot. Its raw bytes touch disk only in an owner-only file
    under ``work_dir`` (default: the system temp directory) that is deleted before returning.
    """
    if len(data) > max_bytes:
        raise SnapshotError("snapshot exceeds the size limit")
    with _private_dir(work_dir) as directory:
        path = directory / "snapshot.db"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return validate_snapshot(path, max_bytes=max_bytes)


def rebuild_clean(info: SnapshotInfo, *, work_dir: Path | None = None) -> bytes:
    """Write validated content into a brand-new snapshot file and return that file's bytes.

    Nothing is copied from the file ``info`` was read from, so only its validated meta and rows
    can appear in the result. The rebuilt file must validate and reproduce the same meta, rows
    and content digest, and must have no free pages or bytes past its last page.
    """
    meta = {key: value for key, value in info.meta.items() if key != "content_digest"}
    with _private_dir(work_dir) as directory:
        path = directory / "snapshot.db"
        write_snapshot(path, meta, info.rows)
        rebuilt = validate_snapshot(path)
        if rebuilt.meta != info.meta or rebuilt.rows != info.rows:
            raise SnapshotError("rebuilt snapshot does not reproduce the validated content")
        with open_untrusted(path) as conn:
            page_size, page_count, free_pages = (
                int(conn.execute(f"PRAGMA {name}").fetchone()[0])
                for name in ("page_size", "page_count", "freelist_count")
            )
        if free_pages or path.stat().st_size != page_size * page_count:
            raise SnapshotError("rebuilt snapshot is not compact")
        return path.read_bytes()
