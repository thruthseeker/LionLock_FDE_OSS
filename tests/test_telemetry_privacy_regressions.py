"""Privacy-boundary regressions for snapshot transfer (hidden bytes) and exported labels, plus the
R2 correction-round cases at the end of the file.

Every case drives the checked-out ``lionlock`` package with synthetic data: fixtures are small
SQLite files built in the test, HTTP stays on loopback, and each canary is first confirmed in its
source so that its absence afterwards means something.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Sequence, Tuple

import pytest

from lionlock.logging.token_auth import hash_token
from lionlock.telemetry import export as export_module
from lionlock.telemetry import policy
from lionlock.telemetry import receiver as receiver_module
from lionlock.telemetry import store as store_module
from lionlock.telemetry import upload as upload_module
from lionlock.telemetry.canonical import canonical_json
from lionlock.telemetry.cli import main as cli_main
from lionlock.telemetry.export import export_all, export_snapshot
from lionlock.telemetry.receiver import (
    WAREHOUSE_DDL,
    Receiver,
    ReceiverConfig,
    WarehouseVersionError,
    load_token_hashes,
    make_server,
)
from lionlock.telemetry.snapshot import (
    EVENT_COLUMNS,
    TRUST_COLUMNS,
    SnapshotError,
    validate_snapshot,
    write_snapshot,
)
from lionlock.telemetry.store import STORE_APPLICATION_ID, LogStore, StoreError
from lionlock.telemetry.upload import (
    CONTENT_TYPE,
    UPLOAD_PATH,
    UploadOutcome,
    endpoint_problem,
    resolve_upload_settings,
    upload_pending,
    upload_snapshot,
)

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10; tomli is a declared dependency there
    import tomli as tomllib

APPENDED_CANARY = b"SYNTHETIC_PRIVATE_ASSET_CANARY_APPENDED_ONLY"
RESIDUE_CANARY = b"SYNTHETIC_PRIVATE_ASSET_CANARY_DELETED_RESIDUE"
LABEL_CANARIES: Dict[str, str] = {
    "reason_code": "synthetic_private_customer_orion",
    "signal_schema_version": "SyntheticPrivate-Orion",
    "runtime_mode": "synthetic_private_workspace",
    "trust_logic_version": "SyntheticPrivate-Orion",
}
LABEL_NEEDLES = tuple(sorted({value.encode() for value in LABEL_CANARIES.values()}))
# The documented public values (docs/TELEMETRY.md). Each one gets a positive control.
PUBLIC_VALUES: Dict[str, Tuple[str, ...]] = {
    "reason_code": (
        "repetition_loop",
        "low_novelty",
        "low_coherence",
        "context_drift",
        "hallucination_risk",
        "fatigue_risk",
        "congestion_risk",
        "policy_violation",
        "connector_error",
    ),
    "signal_schema_version": ("SE-0.2.0", "SE-0.3.0", "SE-0.4.0"),
    "runtime_mode": ("oss",),
    "trust_logic_version": ("TO-0.1.0",),
}

INSTALL_ID = "5e" * 16
EXPORT_KEY = "a5" * 32
RAW_SESSION_ID = "synthetic-private-session-orion"
RAW_MODEL_ID = "synthetic-private-llama-ft"
RAW_RESPONSE = "synthetic private response text"
RAW_REQUEST_PREFIX = "synthetic-private-request-"

_UPLOAD_ENV = (
    "DO_NOT_TRACK",
    "LIONLOCK_TELEMETRY_UPLOAD",
    "LIONLOCK_TELEMETRY_ENDPOINT",
    "LIONLOCK_UPLOAD_TOKEN",
)
_PROXY_ENV = ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")
# Direct connections only: the tests talk to servers they started on 127.0.0.1.
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@pytest.fixture(autouse=True)
def _loopback_only(monkeypatch) -> None:
    for name in _UPLOAD_ENV + _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    monkeypatch.setenv("NO_PROXY", "*")


# ---------------------------------------------------------------------------------------------
# Synthetic fixtures. Public so the run record can regenerate and hash the same files.
# ---------------------------------------------------------------------------------------------


def seed_store(
    db_path: Path,
    *,
    events: int = 3,
    trust: int = 2,
    labels: Dict[str, str] | None = None,
) -> Path:
    """A local log holding synthetic events and trust records, with a fixed export identity."""
    labels = labels or {}
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = LogStore(db_path)
    for i in range(events):
        store.append_event(
            {
                "timestamp_utc": f"2026-09-27T10:{i % 60:02d}:00Z",
                "request_id": f"{RAW_REQUEST_PREFIX}{i}",
                "decision": "REFRESH",
                "severity": "yellow",
                "reason_code": labels.get("reason_code", "low_coherence"),
                "aggregate_score": 0.5,
                "signal_scores": {"coherence_structure": 0.5},
                "signal_bundle": {
                    "signal_schema_version": labels.get("signal_schema_version", "SE-0.4.0"),
                    "signal_scores": {"coherence_structure": 0.5},
                    "derived_signals": {"low_conf_halluc": 0.1},
                    "missing_inputs": ["entropy_decay"],
                },
                "duration_ms": 100 + i,
            }
        )
    for i in range(trust):
        store.append_trust_record(
            {
                "timestamp": f"2026-09-27T11:{i % 60:02d}:00Z",
                "session_id": RAW_SESSION_ID,
                "turn_index": i,
                "model_id": RAW_MODEL_ID,
                "prompt_type": "qa",
                "trust_score": 0.8,
                "trust_label": "TRUSTED",
                "badge": "STABLE",
                "volatility": 0.1,
                "trust_logic_version": labels.get("trust_logic_version", "TO-0.1.0"),
                "deployment_context_snapshot": {"runtime_mode": labels.get("runtime_mode", "oss")},
                "response_text": RAW_RESPONSE,
            }
        )
    store.set_meta({"install_id": INSTALL_ID, "export_key": EXPORT_KEY})
    return db_path


def make_clean(workdir: Path) -> Path:
    db = seed_store(workdir / "log" / "lionlock.db")
    result = export_snapshot(LogStore(db), workdir / "clean")
    assert result is not None
    return result.path


def make_appended(clean: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(clean.read_bytes() + APPENDED_CANARY)
    return target


def make_deleted_residue(clean: Path, target: Path) -> Path:
    """Insert canary rows into a scratch table, commit, drop it, commit; secure_delete is OFF."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(clean, target)
    conn = sqlite3.connect(str(target), isolation_level=None)
    try:
        conn.execute("PRAGMA secure_delete=OFF")
        conn.execute("BEGIN")
        conn.execute("CREATE TABLE residue_scratch (payload TEXT NOT NULL)")
        conn.executemany(
            "INSERT INTO residue_scratch (payload) VALUES (?)",
            [(f"{RESIDUE_CANARY.decode()} {i} " + "p" * 3000,) for i in range(5)],
        )
        conn.execute("COMMIT")
        conn.execute("DROP TABLE residue_scratch")
    finally:
        conn.close()
    return target


def _rewrite(source: Path, target: Path, edit: Callable[[List[Any], List[Any]], None]) -> Path:
    """Copy a snapshot's rows, apply ``edit`` per row pair, and write it with a fresh digest."""
    info = validate_snapshot(source)
    events = [list(row) for row in info.rows["events"]]
    trust = [list(row) for row in info.rows["trust_records"]]
    edit(events, trust)
    meta = {key: value for key, value in info.meta.items() if key != "content_digest"}
    target.parent.mkdir(parents=True, exist_ok=True)
    write_snapshot(
        target,
        meta,
        {"events": [tuple(row) for row in events], "trust_records": [tuple(row) for row in trust]},
    )
    return target


def make_private_labels(clean: Path, target: Path) -> Path:
    """Forge all four identifier-shaped private labels into an otherwise valid snapshot."""
    reason = EVENT_COLUMNS.index("reason_code")
    bundle = EVENT_COLUMNS.index("signal_bundle_json")
    detail = TRUST_COLUMNS.index("detail_json")

    def edit(events: List[Any], trust: List[Any]) -> None:
        for row in events:
            row[reason] = LABEL_CANARIES["reason_code"]
            parsed = json.loads(row[bundle])
            parsed["signal_schema_version"] = LABEL_CANARIES["signal_schema_version"]
            row[bundle] = canonical_json(parsed)
        for row in trust:
            parsed = json.loads(row[detail])
            parsed["runtime_mode"] = LABEL_CANARIES["runtime_mode"]
            parsed["trust_logic_version"] = LABEL_CANARIES["trust_logic_version"]
            row[detail] = canonical_json(parsed)

    return _rewrite(clean, target, edit)


def make_invalid_reason(clean: Path, target: Path) -> Path:
    reason = EVENT_COLUMNS.index("reason_code")

    def edit(events: List[Any], _trust: List[Any]) -> None:
        events[0][reason] = "free text reason: synthetic visible note"

    return _rewrite(clean, target, edit)


def make_extra_table(clean: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(clean, target)
    conn = sqlite3.connect(str(target), isolation_level=None)
    try:
        conn.execute("CREATE TABLE extra (secret TEXT)")
        conn.execute("INSERT INTO extra (secret) VALUES ('synthetic extra table value')")
    finally:
        conn.close()
    return target


def make_conflicting(source: Path, target: Path) -> Path:
    duration = EVENT_COLUMNS.index("duration_ms")

    def edit(events: List[Any], _trust: List[Any]) -> None:
        events[0][duration] = 999

    return _rewrite(source, target, edit)


def make_bytewise_variant(source: Path, target: Path) -> Path:
    """The same logical snapshot in a different container layout (page size 1024)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    conn = sqlite3.connect(str(target), isolation_level=None)
    try:
        conn.execute("PRAGMA page_size=1024")
        conn.execute("VACUUM")
    finally:
        conn.close()
    return target


def build_fixtures(workdir: Path) -> Dict[str, Path]:
    clean = make_clean(workdir)
    return {
        "clean": clean,
        "appended": make_appended(clean, workdir / "fixtures" / "appended.db"),
        "deleted_residue": make_deleted_residue(clean, workdir / "fixtures" / "deleted_residue.db"),
        "private_labels": make_private_labels(clean, workdir / "fixtures" / "private_labels.db"),
        "invalid_reason": make_invalid_reason(clean, workdir / "fixtures" / "invalid_reason.db"),
        "extra_table": make_extra_table(clean, workdir / "fixtures" / "extra_table.db"),
    }


def visible_content(path: Path) -> Tuple[Any, ...]:
    """Header ids, schema and every row, as SQL sees them (independent of the package)."""
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        header = tuple(
            conn.execute(f"PRAGMA {name}").fetchone()[0]
            for name in ("application_id", "user_version")
        )
        schema = sorted(
            conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master"), key=repr
        )
        tables = sorted(name for kind, name, *_ in schema if kind == "table")
        rows = {
            name: conn.execute(f'SELECT * FROM "{name}" ORDER BY rowid').fetchall()
            for name in tables
        }
    finally:
        conn.close()
    return header, schema, rows


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------------------------
# Loopback HTTP helpers
# ---------------------------------------------------------------------------------------------


class _CaptureHandler(BaseHTTPRequestHandler):
    captured: List[Tuple[Dict[str, str], bytes]] = []

    def log_message(self, *_args: Any) -> None:
        pass

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        type(self).captured.append(({k.lower(): v for k, v in self.headers.items()}, body))
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _RedirectHandler(BaseHTTPRequestHandler):
    location = ""

    def log_message(self, *_args: Any) -> None:
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(307)
        self.send_header("Location", type(self).location)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _serve(handler: type) -> Tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def capture_endpoint() -> Iterator[Tuple[str, List[Tuple[Dict[str, str], bytes]]]]:
    handler = type("Capture", (_CaptureHandler,), {"captured": []})
    server, url = _serve(handler)
    try:
        yield url, handler.captured
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def receiver_server(tmp_path) -> Iterator[Callable[[str], Tuple[str, Path]]]:
    servers = []

    def _start(name: str) -> Tuple[str, Path]:
        data_dir = tmp_path / name
        server = make_server(ReceiverConfig(data_dir=data_dir), host="127.0.0.1", port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}", data_dir

    yield _start
    for server in servers:
        server.shutdown()
        server.server_close()


def _upload_config(tmp_path: Path, db: Path, endpoint: str, outbox: Path | None = None) -> dict:
    return {
        "logging": {"enabled": True, "backend": "sqlite", "sqlite_path": str(db)},
        "logging_sql": {"enabled": False},
        "telemetry_upload": {
            "enabled": True,
            "endpoint": endpoint,
            "outbox_dir": str(outbox or tmp_path / "outbox"),
        },
    }


def _declared_meta(path: Path) -> Dict[str, str]:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        return {str(k): str(v) for k, v in conn.execute("SELECT key, value FROM snapshot_meta")}
    finally:
        conn.close()


def _transport_headers(path: Path) -> Dict[str, str]:
    """Headers a client would declare for the file's raw bytes and its visible metadata."""
    meta = _declared_meta(path)
    return {
        "Content-Type": CONTENT_TYPE,
        "X-LionLock-File-SHA256": sha256_file(path),
        "X-LionLock-Install-Id": meta["install_id"],
        "X-LionLock-Segment": meta["segment_index"],
        "X-LionLock-Content-Digest": meta["content_digest"],
    }


def post_snapshot(url: str, path: Path) -> Tuple[int, Dict[str, Any]]:
    """Send a file's raw bytes straight to a receiver, bypassing every client-side check."""
    request = urllib.request.Request(
        url + UPLOAD_PATH,
        data=gzip.compress(path.read_bytes(), mtime=0),
        headers={**_transport_headers(path), "Content-Encoding": "gzip"},
        method="POST",
    )
    try:
        with _DIRECT.open(request, timeout=30) as response:
            return int(response.status), json.loads(response.read())
    except urllib.error.HTTPError as exc:
        with exc:
            return int(exc.code), json.loads(exc.read())


def _warehouse(data_dir: Path, query: str) -> list:
    conn = sqlite3.connect(str(data_dir / "warehouse.db"))
    try:
        return conn.execute(query).fetchall()
    finally:
        conn.close()


def _counts(data_dir: Path) -> Tuple[int, ...]:
    return tuple(
        _warehouse(data_dir, f"SELECT COUNT(*) FROM {table}")[0][0]
        for table in ("uploads", "events", "trust_records")
    )


def files_containing(root: Path, needles: Sequence[bytes]) -> List[str]:
    hits = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            hits.extend(f"{path.relative_to(root)}" for needle in needles if needle in data)
    return hits


def _assert_marker_never_sent(
    outcome: UploadOutcome, captured: List[Tuple[Dict[str, str], bytes]], marker: bytes
) -> None:
    if not captured:
        assert outcome.status == "invalid", outcome
        return
    assert outcome.status == "uploaded", outcome
    for headers, body in captured:
        sent = gzip.decompress(body) if headers.get("content-encoding") == "gzip" else body
        assert marker not in sent, "the canary left the uploader in the HTTP request body"
        digest = hashlib.sha256(sent).hexdigest()
        assert headers["x-lionlock-file-sha256"] == digest
        assert headers["idempotency-key"] == digest


# ---------------------------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------------------------


def test_clean_snapshot_transfer_control(tmp_path, receiver_server) -> None:
    """Acceptance: an uploader-to-loopback-receiver transfer stores exactly the logical rows."""
    url, data_dir = receiver_server("server")
    db = seed_store(tmp_path / "log" / "lionlock.db")
    exported = export_all(LogStore(db), tmp_path / "outbox")
    assert len(exported) == 1
    expected = validate_snapshot(exported[0].path).rows

    outcomes = upload_pending(
        resolve_upload_settings(_upload_config(tmp_path, db, url)), sleep=lambda _s: None
    )
    assert [outcome.status for outcome in outcomes] == ["uploaded"]
    for table, columns in (("events", EVENT_COLUMNS), ("trust_records", TRUST_COLUMNS)):
        stored = _warehouse(data_dir, f"SELECT {','.join(columns)} FROM {table} ORDER BY seq")
        assert stored == expected[table]
        assert stored
    assert _warehouse(data_dir, "SELECT segment_index, chain_status FROM uploads") == [(1, "ok")]


def test_appended_bytes_never_leave_uploader(tmp_path, capture_endpoint) -> None:
    """Acceptance: rejected without sending, or the decompressed request body lacks the canary."""
    url, captured = capture_endpoint
    fixtures = build_fixtures(tmp_path)
    source = fixtures["appended"]
    assert APPENDED_CANARY in source.read_bytes(), "precondition: canary present in the source"
    assert visible_content(source) == visible_content(fixtures["clean"])
    before = sha256_file(source)

    db = tmp_path / "log" / "lionlock.db"
    outcome = upload_snapshot(source, resolve_upload_settings(_upload_config(tmp_path, db, url)))
    _assert_marker_never_sent(outcome, captured, APPENDED_CANARY)
    assert sha256_file(source) == before


def test_deleted_residue_never_leaves_uploader(tmp_path, capture_endpoint) -> None:
    """Acceptance: rejected without sending, or the decompressed request body lacks the canary."""
    url, captured = capture_endpoint
    fixtures = build_fixtures(tmp_path)
    source = fixtures["deleted_residue"]
    if RESIDUE_CANARY not in source.read_bytes():
        pytest.fail("PRECONDITION_FAILED: deleted-row residue is not present in the raw bytes")
    if visible_content(source) != visible_content(fixtures["clean"]):
        pytest.fail("PRECONDITION_FAILED: the visible schema or rows changed")
    before = sha256_file(source)

    db = tmp_path / "log" / "lionlock.db"
    outcome = upload_snapshot(source, resolve_upload_settings(_upload_config(tmp_path, db, url)))
    _assert_marker_never_sent(outcome, captured, RESIDUE_CANARY)
    assert sha256_file(source) == before


def test_receiver_persists_only_clean_reconstruction(tmp_path, receiver_server, caplog) -> None:
    """Acceptance: a directly submitted contaminated file is rejected or stored only as a clean
    reconstruction, and no receiver artifact retains the canary afterwards."""
    caplog.set_level(logging.DEBUG)
    fixtures = build_fixtures(tmp_path / "work")
    cases = {
        "appended": (APPENDED_CANARY,),
        "deleted_residue": (RESIDUE_CANARY,),
        "private_labels": LABEL_NEEDLES,
    }
    fixture_hashes = {name: sha256_file(fixtures[name]) for name in cases}
    all_needles = tuple(needle for needles in cases.values() for needle in needles)

    for name, needles in cases.items():
        raw = fixtures[name].read_bytes()
        assert all(needle in raw for needle in needles), f"precondition: canary present in {name}"
        url, data_dir = receiver_server(f"server-{name}")
        status, body = post_snapshot(url, fixtures[name])
        assert status in (200, 201, 422), (name, status, body)
        assert not any(needle.decode() in json.dumps(body) for needle in needles)
        assert files_containing(data_dir, needles) == [], f"{name}: canary retained by receiver"
        assert [p for p in (data_dir / "quarantine").rglob("*") if p.is_file()] == []
        for stored in sorted((data_dir / "accepted").glob("*.db")):
            info = validate_snapshot(stored)
            assert info.content_digest == _declared_meta(fixtures[name])["content_digest"]

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert not any(needle.decode() in logged for needle in all_needles)
    assert {name: sha256_file(fixtures[name]) for name in cases} == fixture_hashes


def test_identifier_shaped_private_labels_are_removed(tmp_path, receiver_server, monkeypatch):
    """Acceptance: private labels never survive policy, export, outbound bytes or accepted
    storage; forged-label snapshots are rejected; every public value still passes."""
    event = policy.event_row(
        seq=1,
        ts="2026-09-27T10:00:00Z",
        decision="REFRESH",
        severity="yellow",
        reason_code=LABEL_CANARIES["reason_code"],
        aggregate_score=0.5,
        scores={"coherence_structure": 0.5},
        bundle={"signal_schema_version": LABEL_CANARIES["signal_schema_version"]},
        duration_ms=10,
        config_hash=None,
    )
    detail = policy.trust_detail(
        {
            "runtime_mode": LABEL_CANARIES["runtime_mode"],
            "trust_logic_version": LABEL_CANARIES["trust_logic_version"],
        }
    )
    sanitized = canonical_json([list(event or ()), detail])
    for field, value in LABEL_CANARIES.items():
        assert value not in sanitized, f"policy kept the private {field}"
    assert policy.trust_detail(detail) == detail

    # Positive controls: every documented public value survives the policy...
    reason = EVENT_COLUMNS.index("reason_code")
    events: List[Tuple[Any, ...]] = []
    versions = PUBLIC_VALUES["signal_schema_version"]
    for seq, code in enumerate(PUBLIC_VALUES["reason_code"], start=1):
        row = policy.event_row(
            seq=seq,
            ts="2026-09-27T10:00:00Z",
            decision="REFRESH",
            severity="yellow",
            reason_code=code,
            aggregate_score=0.5,
            scores={"coherence_structure": 0.5},
            bundle={"signal_schema_version": versions[seq % len(versions)]},
            duration_ms=10,
            config_hash=None,
        )
        assert row is not None and row[reason] == code
        events.append(row)
    for version in versions:
        assert policy.signal_bundle({"signal_schema_version": version})[
            "signal_schema_version"
        ] == (version)
    trust: List[Tuple[Any, ...]] = []
    for seq, (mode, logic) in enumerate(
        (
            (mode, logic)
            for mode in PUBLIC_VALUES["runtime_mode"]
            for logic in PUBLIC_VALUES["trust_logic_version"]
        ),
        start=1,
    ):
        public_detail = policy.trust_detail({"runtime_mode": mode, "trust_logic_version": logic})
        assert (public_detail["runtime_mode"], public_detail["trust_logic_version"]) == (
            mode,
            logic,
        )
        row = policy.trust_row(
            seq=seq,
            ts="2026-09-27T11:00:00Z",
            session_key="ab" * 16,
            turn_index=0,
            model="llama",
            prompt_type="qa",
            trust_score=0.9,
            trust_label="TRUSTED",
            badge="STABLE",
            volatility=0.1,
            drift_detected=False,
            flags=[],
            detail=public_detail,
        )
        assert row is not None
        trust.append(row)

    # ...and a snapshot carrying all of them validates and is accepted by the receiver.
    clean = make_clean(tmp_path / "work")
    meta = {k: v for k, v in validate_snapshot(clean).meta.items() if k != "content_digest"}
    meta.update({"events_rows": str(len(events)), "trust_records_rows": str(len(trust))})
    public = tmp_path / "work" / "public_values.db"
    write_snapshot(public, meta, {"events": events, "trust_records": trust})
    validate_snapshot(public)
    direct = Receiver(ReceiverConfig(data_dir=tmp_path / "direct-public"))
    assert direct.handle_upload(_transport_headers(public), public.read_bytes()).status == 201

    # Ordinary export from a local log that holds the private labels.
    db = seed_store(tmp_path / "labels" / "lionlock.db", labels=LABEL_CANARIES)
    local = db.read_bytes()
    assert all(needle in local for needle in LABEL_NEEDLES), "precondition: labels in the log"
    outbox = tmp_path / "labels" / "outbox"
    exported = export_all(LogStore(db), outbox)
    assert exported
    for result in exported:
        assert files_containing(result.path.parent, LABEL_NEEDLES) == []

    # The actual outbound request bodies and the receiver's accepted storage.
    sent: List[bytes] = []
    original = Receiver.handle_upload

    def recording(self: Receiver, headers: Any, body: bytes) -> Any:
        sent.append(body)
        return original(self, headers, body)

    monkeypatch.setattr(Receiver, "handle_upload", recording)
    url, data_dir = receiver_server("server-labels")
    outcomes = upload_pending(
        resolve_upload_settings(_upload_config(tmp_path, db, url, outbox)), sleep=lambda _s: None
    )
    assert [outcome.status for outcome in outcomes] == ["uploaded"] * len(exported)
    assert len(sent) == len(exported)
    for body in sent:
        decoded = gzip.decompress(body)
        assert not any(needle in decoded for needle in LABEL_NEEDLES)
    assert files_containing(data_dir, LABEL_NEEDLES) == []

    # A directly forged snapshot with a correctly recomputed digest is still rejected.
    forged = make_private_labels(clean, tmp_path / "work" / "forged.db")
    with pytest.raises(SnapshotError):
        validate_snapshot(forged)
    rejecting = Receiver(ReceiverConfig(data_dir=tmp_path / "direct-forged"))
    result = rejecting.handle_upload(_transport_headers(forged), forged.read_bytes())
    assert result.status == 422
    assert files_containing(tmp_path / "direct-forged", LABEL_NEEDLES) == []


def test_invalid_visible_reason_and_extra_table_are_rejected(tmp_path) -> None:
    """Acceptance: both original negative controls stay rejected; neither becomes accepted."""
    fixtures = build_fixtures(tmp_path / "work")
    for name in ("invalid_reason", "extra_table"):
        path = fixtures[name]
        with pytest.raises(SnapshotError):
            validate_snapshot(path)
        data_dir = tmp_path / f"server-{name}"
        result = Receiver(ReceiverConfig(data_dir=data_dir)).handle_upload(
            _transport_headers(path), path.read_bytes()
        )
        assert result.status == 422, (name, result.body)
        assert _counts(data_dir) == (0, 0, 0)
        assert list((data_dir / "accepted").glob("*")) == []


def test_clean_reconstruction_preserves_transfer_contract(tmp_path, receiver_server) -> None:
    """Acceptance: repeated sends, bytewise-different equal content, conflicting content and
    multi-segment linkage keep their meaning: no duplicate rows, no false conflicts."""
    url, data_dir = receiver_server("server")
    db = seed_store(tmp_path / "log" / "lionlock.db", events=6, trust=2)
    exported = export_all(LogStore(db), tmp_path / "outbox", rows_per_snapshot=2)
    assert [result.segment_index for result in exported] == [1, 2, 3]
    kept: Dict[int, Path] = {}
    for result in exported:
        kept[result.segment_index] = tmp_path / "kept" / result.path.name
        kept[result.segment_index].parent.mkdir(exist_ok=True)
        shutil.copyfile(result.path, kept[result.segment_index])

    settings = resolve_upload_settings(_upload_config(tmp_path, db, url))
    outcomes = upload_pending(settings, sleep=lambda _s: None)
    assert [outcome.status for outcome in outcomes] == ["uploaded"] * 3

    uploads = _warehouse(
        data_dir,
        "SELECT segment_index, chain_status, content_digest, prev_segment_digest "
        "FROM uploads ORDER BY segment_index",
    )
    assert [(row[0], row[1]) for row in uploads] == [(1, "ok"), (2, "ok"), (3, "ok")]
    assert [row[2] for row in uploads] == [result.content_digest for result in exported]
    assert [row[3] for row in uploads] == ["", uploads[0][2], uploads[1][2]]
    counts = _counts(data_dir)
    assert counts == (3, 6, 2)

    again = upload_snapshot(kept[1], settings)
    assert (again.status, again.http_status) == ("duplicate", 200)
    assert _counts(data_dir) == counts

    conflicting = make_conflicting(kept[1], tmp_path / "variants" / "conflicting.db")
    status, _body = post_snapshot(url, conflicting)
    assert status == 409
    assert _counts(data_dir) == counts

    variant = make_bytewise_variant(kept[2], tmp_path / "variants" / "page1024.db")
    assert variant.read_bytes() != kept[2].read_bytes()
    assert visible_content(variant) == visible_content(kept[2])
    status, body = post_snapshot(url, variant)
    assert (status, body.get("status")) == (200, "duplicate"), body
    assert _counts(data_dir) == counts


def test_existing_upload_privacy_controls_remain_effective(tmp_path, monkeypatch) -> None:
    """Acceptance: opt-in defaults, DO_NOT_TRACK, redirect/token and loopback rules, model
    coarsening, session pseudonyms and content exclusion all still hold."""
    db = seed_store(tmp_path / "log" / "lionlock.db")
    base = {"logging": {"enabled": True, "backend": "sqlite", "sqlite_path": str(db)}}

    default = resolve_upload_settings(base)
    assert default.allowed is False and default.endpoint == ""
    no_endpoint = resolve_upload_settings({**base, "telemetry_upload": {"enabled": True}})
    assert no_endpoint.allowed is False

    https = {**base, "telemetry_upload": {"enabled": True, "endpoint": "https://t.example.org"}}
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    monkeypatch.setenv("LIONLOCK_TELEMETRY_UPLOAD", "on")
    assert resolve_upload_settings(https).blocked_reason == "DO_NOT_TRACK is set"
    monkeypatch.delenv("DO_NOT_TRACK")
    monkeypatch.delenv("LIONLOCK_TELEMETRY_UPLOAD")

    assert endpoint_problem("http://telemetry.example.org") is not None
    assert endpoint_problem("http://127.0.0.1:8787") is None

    target_handler = type("Target", (_CaptureHandler,), {"captured": []})
    target, target_url = _serve(target_handler)
    redirect_handler = type("Redirect", (_RedirectHandler,), {"location": target_url + UPLOAD_PATH})
    redirector, redirect_url = _serve(redirect_handler)
    try:
        monkeypatch.setenv("LIONLOCK_UPLOAD_TOKEN", "llk_synthetic_do_not_forward_0123")
        clean = make_clean(tmp_path / "work")
        settings = resolve_upload_settings(_upload_config(tmp_path, db, redirect_url))
        assert settings.token is not None
        outcome = upload_snapshot(clean, settings)
        assert outcome.status == "misconfigured"
        assert target_handler.captured == []
    finally:
        for server in (target, redirector):
            server.shutdown()
            server.server_close()

    result = export_snapshot(LogStore(db), tmp_path / "outbox")
    assert result is not None
    data = result.path.read_bytes()
    for raw in (RAW_SESSION_ID, RAW_MODEL_ID, RAW_RESPONSE, RAW_REQUEST_PREFIX):
        assert raw.encode() not in data
    trust = validate_snapshot(result.path).rows["trust_records"]
    assert {row[TRUST_COLUMNS.index("model_family")] for row in trust} == {"llama"}
    expected_key = policy.rekey(EXPORT_KEY, "session", RAW_SESSION_ID)
    assert {row[TRUST_COLUMNS.index("session_key")] for row in trust} == {expected_key}


# =============================================================================================
# Correction round R2: published package versions, warehouse compatibility, hash byte domains,
# accepted-file durability and the reviewed findings. Failures are injected at module
# boundaries the code already uses (``sqlite3``, ``os``, ``shutil``), so these cases run
# unchanged before and after the fixes.
# =============================================================================================

REPO = Path(__file__).resolve().parents[1]
# Verified public package versions: pyproject.toml has declared 0.1.0, then 1.0.0b1 and
# 1.0.0b2, the public betas. Kept literal so this file runs against any revision.
PUBLIC_PACKAGE_VERSIONS = ("0.1.0", "1.0.0b1", "1.0.0b2")
PRIVATE_NUMERIC_VERSION = "31.41.5926"
PRIVATE_VERSION_LABELS = (
    PRIVATE_NUMERIC_VERSION,
    "1.2.3rc1",
    "2.0.0.dev3",
    "0.0.0-dev",
    "0.1.0+acme.internal",
    "acme-private-1.0",
    "SyntheticPrivate-Orion",
)

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------


def _attempt(receiver: Receiver, path: Path) -> Tuple[int, Dict[str, Any]]:
    """Post a file's raw bytes to ``receiver``; an escaping exception counts as a 500, which is
    what the HTTP layer turns it into."""
    try:
        result = receiver.handle_upload(_transport_headers(path), path.read_bytes())
    except Exception as exc:  # noqa: BLE001 - the HTTP layer maps this to 500
        return 500, {"status": "error", "error": f"exception: {type(exc).__name__}"}
    return result.status, result.body


def _rows(data_dir: Path, query: str) -> list:
    conn = sqlite3.connect(f"{(data_dir / 'warehouse.db').resolve().as_uri()}?mode=ro", uri=True)
    try:
        return conn.execute(query).fetchall()
    finally:
        conn.close()


def _warehouse_counts(data_dir: Path) -> Tuple[int, ...]:
    return tuple(
        _rows(data_dir, f"SELECT COUNT(*) FROM {table}")[0][0]
        for table in ("uploads", "events", "trust_records")
    )


def evidence_state(data_dir: Path) -> Dict[str, Any]:
    """Committed uploads whose accepted file is missing or wrong, and unreferenced clean files."""
    referenced = {row[0] for row in _rows(data_dir, "SELECT stored_sha256 FROM uploads")}
    accepted = data_dir / "accepted"
    files = {p.name[:-3]: p for p in accepted.glob("*.db")} if accepted.is_dir() else {}
    dangling = sorted(
        sha
        for sha in referenced
        if sha not in files or hashlib.sha256(files[sha].read_bytes()).hexdigest() != sha
    )
    orphans = sorted(set(files) - referenced)
    return {"dangling": dangling, "orphans": orphans}


def _quarantine_files(data_dir: Path) -> List[Path]:
    return [p for p in (data_dir / "quarantine").rglob("*") if p.is_file()]


def _segments(tmp_path: Path, events: int = 6, per: int = 2) -> List[Path]:
    db = seed_store(tmp_path / "log" / "lionlock.db", events=events, trust=0)
    results = export_all(LogStore(db), tmp_path / "outbox", rows_per_snapshot=per)
    kept = []
    for result in results:
        target = tmp_path / "kept" / result.path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(result.path, target)
        kept.append(target)
    return kept


class _ConnShim:
    """Delegates to a real connection; lets a test observe or fail a COMMIT on the warehouse."""

    def __init__(self, conn: sqlite3.Connection, on_commit: Callable[[Any], None]) -> None:
        self._conn = conn
        self._on_commit = on_commit

    def execute(self, sql: str, *args: Any) -> Any:
        if sql.strip().upper() == "COMMIT":
            self._on_commit(self._conn)
        return self._conn.execute(sql, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    def __enter__(self) -> "_ConnShim":
        self._conn.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return self._conn.__exit__(*exc)


class _Sqlite3Shim:
    """Stands in for the receiver module's ``sqlite3``; wraps warehouse connections only."""

    def __init__(self, on_commit: Callable[[Any], None]) -> None:
        self._on_commit = on_commit

    def connect(self, database: Any, *args: Any, **kwargs: Any) -> Any:
        conn = sqlite3.connect(database, *args, **kwargs)
        if str(database).endswith("warehouse.db"):
            return _ConnShim(conn, self._on_commit)
        return conn

    def __getattr__(self, name: str) -> Any:
        return getattr(sqlite3, name)


# ---------------------------------------------------------------------------------------------
# C1: package versions are admitted by membership in the verified public set
# ---------------------------------------------------------------------------------------------


def test_private_package_versions_never_leave_or_get_accepted(tmp_path, monkeypatch) -> None:
    """Acceptance: private numeric and identifier-shaped versions become ``unknown`` in the
    policy, export metadata, the request body and the User-Agent; a forged snapshot carrying
    one is refused even with a recomputed digest; public versions pass; labels are idempotent."""
    for value in PRIVATE_VERSION_LABELS:
        assert policy.package_version_label(value) == "unknown", value
    for value in (*PUBLIC_PACKAGE_VERSIONS, "unknown"):
        assert policy.package_version_label(value) == value
        assert policy.package_version_label(policy.package_version_label(value)) == value
    assert policy.package_version_label(None) == "unknown"

    # Ordinary export and upload while the installed version is a private numeric label.
    monkeypatch.setattr(export_module, "get_lionlock_version", lambda _c: PRIVATE_NUMERIC_VERSION)
    monkeypatch.setattr(upload_module, "get_lionlock_version", lambda _c: PRIVATE_NUMERIC_VERSION)
    needle = PRIVATE_NUMERIC_VERSION.encode()
    db = seed_store(tmp_path / "log" / "lionlock.db")
    exported = export_all(LogStore(db), tmp_path / "outbox")
    assert exported
    for result in exported:
        assert validate_snapshot(result.path).meta["lionlock_version"] == "unknown"
        assert needle not in result.path.read_bytes()

    handler = type("Capture", (_CaptureHandler,), {"captured": []})
    server, url = _serve(handler)
    try:
        settings = resolve_upload_settings(_upload_config(tmp_path, db, url))
        outcome = upload_snapshot(exported[0].path, settings)
    finally:
        server.shutdown()
        server.server_close()
    assert outcome.status == "uploaded", outcome
    assert len(handler.captured) == 1
    headers, body = handler.captured[0]
    assert needle not in gzip.decompress(body)
    assert headers["user-agent"] == "lionlock/unknown"
    assert not any(PRIVATE_NUMERIC_VERSION in value for value in headers.values())

    # A directly submitted snapshot carrying the private version, digest recomputed.
    clean = make_clean(tmp_path / "work")
    forged = tmp_path / "work" / "forged_version.db"
    info = validate_snapshot(clean)
    meta = {k: v for k, v in info.meta.items() if k != "content_digest"}
    meta["lionlock_version"] = PRIVATE_NUMERIC_VERSION
    write_snapshot(forged, meta, info.rows)
    assert needle in forged.read_bytes(), "precondition: private version in the forged file"
    with pytest.raises(SnapshotError):
        validate_snapshot(forged)
    data_dir = tmp_path / "direct"
    status, _body = _attempt(Receiver(ReceiverConfig(data_dir=data_dir)), forged)
    assert status == 422
    assert _warehouse_counts(data_dir) == (0, 0, 0)
    assert not any(needle in p.read_bytes() for p in data_dir.rglob("*") if p.is_file())

    # Public positive control: the verified public version is accepted end to end.
    for version in PUBLIC_PACKAGE_VERSIONS:
        public = tmp_path / "work" / f"public_{version}.db"
        write_snapshot(public, {**meta, "lionlock_version": version}, info.rows)
        assert validate_snapshot(public).meta["lionlock_version"] == version
        target = tmp_path / f"direct-{version}"
        assert _attempt(Receiver(ReceiverConfig(data_dir=target)), public)[0] == 201


def test_declared_package_version_is_in_the_public_set() -> None:
    """Drift guard: the version pyproject.toml declares must be admitted as itself."""
    declared = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    assert declared in PUBLIC_PACKAGE_VERSIONS
    assert policy.package_version_label(declared) == declared


# ---------------------------------------------------------------------------------------------
# C2: unsupported warehouses are refused before anything is changed
# ---------------------------------------------------------------------------------------------


def _v1_layout(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE uploads (file_sha256 TEXT PRIMARY KEY NOT NULL, install_id TEXT)")
    conn.execute("CREATE TABLE events (install_id TEXT NOT NULL, seq INTEGER NOT NULL)")
    conn.execute("INSERT INTO uploads VALUES ('ab', 'cd')")


def _v2_wrong_columns(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE uploads (install_id TEXT NOT NULL, segment_index INTEGER NOT NULL, "
        "file_sha256 TEXT NOT NULL, PRIMARY KEY (install_id, segment_index))"
    )
    conn.execute("INSERT INTO uploads VALUES ('ab', 1, 'cd')")
    conn.execute("PRAGMA user_version=2")


def _v2_missing_events(conn: sqlite3.Connection) -> None:
    conn.execute(WAREHOUSE_DDL[0])
    conn.execute(WAREHOUSE_DDL[1])
    conn.execute("PRAGMA user_version=2")


def _v2_wrong_key(conn: sqlite3.Connection) -> None:
    for ddl in WAREHOUSE_DDL:
        if "CREATE TABLE IF NOT EXISTS events" in ddl:
            ddl = ddl.replace("PRIMARY KEY (install_id, seq)", "PRIMARY KEY (seq)")
        conn.execute(ddl)
    conn.execute("PRAGMA user_version=2")


def _zero_row_foreign(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE notes (body TEXT)")


def _foreign_application_id(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA application_id=1234567")


UNSUPPORTED_WAREHOUSES: Dict[str, Callable[[sqlite3.Connection], None]] = {
    "v1_layout": _v1_layout,
    "v2_wrong_columns": _v2_wrong_columns,
    "v2_missing_events": _v2_missing_events,
    "v2_wrong_key": _v2_wrong_key,
    "zero_row_foreign_table": _zero_row_foreign,
    "foreign_application_id": _foreign_application_id,
}


def _snapshot_dir(data_dir: Path) -> Dict[str, Any]:
    db = data_dir / "warehouse.db"
    conn = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
    try:
        header = tuple(
            conn.execute(f"PRAGMA {name}").fetchone()[0]
            for name in ("user_version", "application_id")
        )
        tables = [
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        ]
        rows = {name: conn.execute(f'SELECT * FROM "{name}"').fetchall() for name in tables}
    finally:
        conn.close()
    return {
        "listing": sorted(str(p.relative_to(data_dir)) for p in data_dir.rglob("*")),
        "sha256": sha256_file(db),
        "mode": db.stat().st_mode & 0o777,
        "header": header,
        "rows": rows,
    }


@pytest.mark.parametrize("layout", sorted(UNSUPPORTED_WAREHOUSES))
def test_unsupported_warehouse_is_refused_unchanged(tmp_path, layout) -> None:
    """Acceptance: an unsupported warehouse is refused, and its bytes, mode, version fields,
    records and the data directory listing are identical afterwards."""
    data_dir = tmp_path / layout
    data_dir.mkdir()
    conn = sqlite3.connect(data_dir / "warehouse.db")
    try:
        UNSUPPORTED_WAREHOUSES[layout](conn)
        conn.commit()
    finally:
        conn.close()
    os.chmod(data_dir / "warehouse.db", 0o640)
    before = _snapshot_dir(data_dir)
    with pytest.raises(WarehouseVersionError):
        Receiver(ReceiverConfig(data_dir=data_dir))
    assert _snapshot_dir(data_dir) == before


def test_supported_and_empty_warehouses_still_open(tmp_path) -> None:
    """Positive controls: a new directory, a zero-length file and an existing v2 warehouse."""
    fresh = tmp_path / "fresh"
    Receiver(ReceiverConfig(data_dir=fresh))
    Receiver(ReceiverConfig(data_dir=fresh))
    assert _rows(fresh, "PRAGMA user_version") == [(2,)]

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "warehouse.db").write_bytes(b"")
    Receiver(ReceiverConfig(data_dir=empty))
    assert _rows(empty, "PRAGMA user_version") == [(2,)]


# ---------------------------------------------------------------------------------------------
# C3: each hash field covers its declared byte domain
# ---------------------------------------------------------------------------------------------


def test_hash_fields_use_the_declared_byte_domains(tmp_path) -> None:
    """Acceptance: the file-SHA header and Idempotency-Key equal the SHA-256 of the
    decompressed request body (never of the gzip bytes); received_sha256 is that same digest
    after bounded decompression; stored_sha256 is the accepted file's SHA-256; content_digest
    is the logical digest of the stored rows."""
    handler = type("Capture", (_CaptureHandler,), {"captured": []})
    server, url = _serve(handler)
    db = seed_store(tmp_path / "log" / "lionlock.db")
    exported = export_all(LogStore(db), tmp_path / "outbox")
    try:
        settings = resolve_upload_settings(_upload_config(tmp_path, db, url))
        assert upload_snapshot(exported[0].path, settings).status == "uploaded"
    finally:
        server.shutdown()
        server.server_close()
    headers, body = handler.captured[0]
    assert headers["content-encoding"] == "gzip"
    decompressed = gzip.decompress(body)
    rebuilt_sha = hashlib.sha256(decompressed).hexdigest()
    assert headers["x-lionlock-file-sha256"] == rebuilt_sha
    assert headers["idempotency-key"] == rebuilt_sha
    assert hashlib.sha256(body).hexdigest() != rebuilt_sha

    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    result = receiver.handle_upload(headers, body)
    assert result.status == 201, result.body
    assert result.body["file_sha256"] == rebuilt_sha
    received, stored, digest = _rows(
        data_dir, "SELECT received_sha256, stored_sha256, content_digest FROM uploads"
    )[0]
    assert received == rebuilt_sha
    accepted = data_dir / "accepted" / f"{stored}.db"
    assert (
        hashlib.sha256(accepted.read_bytes()).hexdigest() == stored == result.body["stored_sha256"]
    )
    assert (
        digest == headers["x-lionlock-content-digest"] == validate_snapshot(accepted).content_digest
    )


# ---------------------------------------------------------------------------------------------
# A1: accepted files are durable before an upload is recorded, and never silently missing
# ---------------------------------------------------------------------------------------------


def test_accepted_file_is_durable_before_the_upload_commits(tmp_path, monkeypatch) -> None:
    """Acceptance: at the moment the warehouse COMMIT runs, the accepted file already exists
    with the recorded stored_sha256 and has been fsynced."""
    clean = make_clean(tmp_path / "work")
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    order: List[str] = []
    observed: List[bool] = []
    real_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        order.append("fsync")
        real_fsync(fd)

    def on_commit(conn: sqlite3.Connection) -> None:
        order.append("commit")
        for (stored,) in conn.execute("SELECT stored_sha256 FROM uploads").fetchall():
            path = data_dir / "accepted" / f"{stored}.db"
            observed.append(
                path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == stored
            )

    monkeypatch.setattr(os, "fsync", recording_fsync)
    monkeypatch.setattr(receiver_module, "sqlite3", _Sqlite3Shim(on_commit))
    status, body = _attempt(receiver, clean)
    assert status == 201, body
    assert observed and all(observed), "the upload was recorded before its file existed"
    assert "fsync" in order and order.index("fsync") < order.index("commit")
    assert evidence_state(data_dir)["dangling"] == []


def test_accepted_file_write_failure_then_retry_recovers(tmp_path, monkeypatch) -> None:
    """Acceptance: a failed accepted-file write is not reported as success, leaves no committed
    upload pointing at a missing file, and a retry stores the file."""
    clean = make_clean(tmp_path / "work")
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    real_replace = os.replace
    armed = [True]

    def failing_replace(src: Any, dst: Any) -> None:
        if armed[0] and Path(dst).parent == data_dir / "accepted":
            raise OSError("injected accepted-file write failure")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", failing_replace)
    status, _body = _attempt(receiver, clean)
    assert status >= 500
    assert evidence_state(data_dir)["dangling"] == []
    assert _quarantine_files(data_dir) == []

    armed[0] = False
    status, body = _attempt(receiver, clean)
    assert (status, body.get("status")) == (201, "created"), body
    state = evidence_state(data_dir)
    assert state["dangling"] == [] and _warehouse_counts(data_dir)[0] == 1


def test_warehouse_insert_failure_then_retry_recovers(tmp_path) -> None:
    """Acceptance: an INSERT failure records nothing, leaves no dangling reference, and a retry
    succeeds. Clean orphans are allowed and reported."""
    clean = make_clean(tmp_path / "work")
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    conn = sqlite3.connect(data_dir / "warehouse.db")
    conn.execute(
        "CREATE TRIGGER inject_failure BEFORE INSERT ON events "
        "BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END"
    )
    conn.commit()
    status, _body = _attempt(receiver, clean)
    assert status >= 500
    assert _warehouse_counts(data_dir) == (0, 0, 0)
    assert evidence_state(data_dir)["dangling"] == []
    conn.execute("DROP TRIGGER inject_failure")
    conn.commit()
    conn.close()
    status, body = _attempt(receiver, clean)
    assert status == 201, body
    assert evidence_state(data_dir)["dangling"] == []


def test_warehouse_commit_failure_then_retry_recovers(tmp_path, monkeypatch) -> None:
    """Acceptance: a failure at COMMIT (not at INSERT) records nothing, leaves no dangling
    reference, may leave a reported clean orphan, and a retry succeeds."""
    clean = make_clean(tmp_path / "work")
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    armed = [True]

    def failing_commit(_conn: sqlite3.Connection) -> None:
        if armed[0]:
            armed[0] = False
            raise sqlite3.OperationalError("injected commit failure")

    monkeypatch.setattr(receiver_module, "sqlite3", _Sqlite3Shim(failing_commit))
    status, _body = _attempt(receiver, clean)
    assert status >= 500
    assert armed[0] is False, "precondition: the COMMIT was reached and failed"
    assert _warehouse_counts(data_dir) == (0, 0, 0)
    first = evidence_state(data_dir)
    assert first["dangling"] == []
    assert len(first["orphans"]) <= 1
    assert _quarantine_files(data_dir) == []

    status, body = _attempt(receiver, clean)
    assert status == 201, body
    state = evidence_state(data_dir)
    assert state["dangling"] == [] and state["orphans"] == []


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_duplicate_with_missing_or_corrupt_evidence_is_not_success(tmp_path, damage) -> None:
    """Acceptance: a resend (same bytes, or the same content in different bytes) whose recorded
    accepted file is missing or corrupt gets an explicit integrity failure, never ``duplicate``,
    and the warehouse record is preserved."""
    clean = make_clean(tmp_path / "work")
    variant = make_bytewise_variant(clean, tmp_path / "work" / "variant.db")
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    assert _attempt(receiver, clean)[0] == 201
    (stored,) = _rows(data_dir, "SELECT stored_sha256 FROM uploads")[0]
    accepted = data_dir / "accepted" / f"{stored}.db"
    if damage == "missing":
        accepted.unlink()
    else:
        accepted.write_bytes(accepted.read_bytes()[:-1] + b"\x00")
    record = _rows(data_dir, "SELECT * FROM uploads")
    for resend in (clean, variant):
        status, body = _attempt(receiver, resend)
        assert not (200 <= status < 300), (resend.name, status, body)
        assert body.get("status") != "duplicate"
        assert _rows(data_dir, "SELECT * FROM uploads") == record


def test_concurrent_equal_uploads_create_exactly_once_threads(tmp_path) -> None:
    """Acceptance (threads, one process): identical and bytewise-different equal-content posts
    racing on one receiver produce exactly one ``created`` and leave no dangling reference."""
    clean = make_clean(tmp_path / "work")
    variant = make_bytewise_variant(clean, tmp_path / "work" / "variant.db")
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir, max_concurrent_uploads=8))
    barrier = threading.Barrier(6)
    results: List[Tuple[int, Dict[str, Any]]] = []
    lock = threading.Lock()

    def worker(path: Path) -> None:
        barrier.wait()
        outcome = _attempt(receiver, path)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker, args=(p,)) for p in [clean, variant] * 3]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    statuses = sorted(status for status, _ in results)
    assert statuses == [200] * 5 + [201], results
    assert _warehouse_counts(data_dir)[0] == 1
    assert evidence_state(data_dir)["dangling"] == []


_CHILD = r"""
import json, sys, time
from pathlib import Path
from lionlock.telemetry.receiver import Receiver, ReceiverConfig
data_dir, snapshot, headers_json, go = sys.argv[1:5]
receiver = Receiver(ReceiverConfig(data_dir=Path(data_dir)))
deadline = time.time() + 30
while not Path(go).exists() and time.time() < deadline:
    time.sleep(0.005)
try:
    result = receiver.handle_upload(json.loads(headers_json), Path(snapshot).read_bytes())
    print(json.dumps({"status": result.status, "body": result.body}))
except Exception as exc:
    print(json.dumps({"status": 500, "body": {"error": type(exc).__name__}}))
"""


def test_concurrent_equal_uploads_create_exactly_once_processes(tmp_path) -> None:
    """Acceptance (two OS processes, one data directory): the same segment posted by separate
    receiver processes released together is created exactly once, with its file present."""
    clean = make_clean(tmp_path / "work")
    variant = make_bytewise_variant(clean, tmp_path / "work" / "variant.db")
    data_dir = tmp_path / "server"
    Receiver(ReceiverConfig(data_dir=data_dir))
    go = tmp_path / "go"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    children = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _CHILD,
                str(data_dir),
                str(path),
                json.dumps(_transport_headers(path)),
                str(go),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        for path in (clean, variant)
    ]
    time.sleep(1.0)
    go.write_text("go")
    outputs = []
    for child in children:
        out, err = child.communicate(timeout=60)
        assert child.returncode == 0, err
        outputs.append(json.loads(out.strip().splitlines()[-1]))
    assert sorted(o["status"] for o in outputs) == [200, 201], outputs
    assert _warehouse_counts(data_dir)[0] == 1
    assert evidence_state(data_dir)["dangling"] == []


def test_quarantine_cleanup_failure_is_reported(tmp_path, monkeypatch, caplog) -> None:
    """Acceptance: if raw upload bytes cannot be removed, the upload does not succeed and the
    failure is logged rather than swallowed."""
    caplog.set_level(logging.ERROR)
    clean = make_clean(tmp_path / "work")
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    real_rmtree = shutil.rmtree

    def failing_rmtree(path: Any, *args: Any, **kwargs: Any) -> None:
        if Path(path).parent == data_dir / "quarantine":
            raise OSError("injected cleanup failure")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", failing_rmtree)
    status, _body = _attempt(receiver, clean)
    monkeypatch.setattr(shutil, "rmtree", real_rmtree)
    assert not (200 <= status < 300)
    assert _warehouse_counts(data_dir) == (0, 0, 0)
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "could not remove" in logged


# ---------------------------------------------------------------------------------------------
# B1-B9: reviewed bot findings in the allowed paths
# ---------------------------------------------------------------------------------------------


def test_b1_handler_errors_never_print_the_client_address(tmp_path, monkeypatch, capfd, caplog):
    """B1: an unexpected handler exception is logged without the client address or port."""
    caplog.set_level(logging.DEBUG)

    def boom(self: Any) -> None:
        raise RuntimeError("injected handler failure")

    monkeypatch.setattr(receiver_module._Handler, "do_POST", boom)
    server = make_server(ReceiverConfig(data_dir=tmp_path / "server"), host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("POST", UPLOAD_PATH, body=b"x", headers={"Content-Length": "1"})
            try:
                conn.getresponse()
            except (http.client.HTTPException, OSError):
                pass
        finally:
            conn.close()
        time.sleep(0.3)
    finally:
        server.shutdown()
        server.server_close()
    captured = capfd.readouterr()
    logged = "\n".join(record.getMessage() for record in caplog.records)
    text = captured.err + captured.out + logged
    assert "injected handler failure" in text or "RuntimeError" in text, "precondition"
    assert "127.0.0.1" not in text
    assert f", {port})" not in text


def test_b2_loopback_uploads_ignore_environment_proxies(tmp_path, monkeypatch) -> None:
    """B2: a plain-http loopback upload goes straight to the endpoint, never via HTTP_PROXY."""
    proxy_handler = type("Proxy", (_CaptureHandler,), {"captured": []})
    target_handler = type("Target", (_CaptureHandler,), {"captured": []})
    proxy, proxy_url = _serve(proxy_handler)
    target, target_url = _serve(target_handler)
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("http_proxy", proxy_url)
    monkeypatch.setenv("HTTP_PROXY", proxy_url)
    monkeypatch.setenv("LIONLOCK_UPLOAD_TOKEN", "llk_synthetic_never_to_a_proxy_0123")
    try:
        db = seed_store(tmp_path / "log" / "lionlock.db")
        exported = export_all(LogStore(db), tmp_path / "outbox")
        settings = resolve_upload_settings(_upload_config(tmp_path, db, target_url))
        outcome = upload_snapshot(exported[0].path, settings)
    finally:
        for server in (proxy, target):
            server.shutdown()
            server.server_close()
    assert proxy_handler.captured == [], "the snapshot and token were sent to a proxy"
    assert len(target_handler.captured) == 1
    assert outcome.status == "uploaded"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_b3_existing_log_files_are_made_owner_only(tmp_path, monkeypatch) -> None:
    """B3: an existing log is made owner-only on first open and after a cached open; foreign
    files keep their bytes and mode; a failed chmod is reported, not ignored."""
    original = tmp_path / "a" / "lionlock.db"
    seed_store(original, events=1, trust=0)
    copied = tmp_path / "b" / "lionlock.db"
    copied.parent.mkdir()
    shutil.copyfile(original, copied)
    os.chmod(copied, 0o644)
    LogStore(copied).append_event({"timestamp_utc": "2026-09-27T10:00:00Z", "decision": "ALLOW"})
    assert copied.stat().st_mode & 0o777 == 0o600, "first open left an existing log readable"

    os.chmod(original, 0o644)
    LogStore(original).append_event({"timestamp_utc": "2026-09-27T10:00:00Z", "decision": "ALLOW"})
    assert original.stat().st_mode & 0o777 == 0o600, "a cached open skipped the mode check"

    foreign = tmp_path / "c" / "other.db"
    foreign.parent.mkdir()
    with sqlite3.connect(foreign) as conn:
        conn.execute("PRAGMA application_id=1234567")
        conn.execute("CREATE TABLE notes (body TEXT)")
    os.chmod(foreign, 0o644)
    before = sha256_file(foreign)
    with pytest.raises(StoreError):
        LogStore(foreign).append_event({"decision": "ALLOW"})
    assert sha256_file(foreign) == before and foreign.stat().st_mode & 0o777 == 0o644

    def failing_chmod(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("injected chmod failure")

    monkeypatch.setattr(store_module.os, "chmod", failing_chmod)
    with pytest.raises(StoreError):
        LogStore(tmp_path / "d" / "lionlock.db").append_event({"decision": "ALLOW"})


def _collide(source: Path, target: Path, seq_from: Path) -> Path:
    """Rewrite a later segment so its event seqs reuse an earlier segment's, digest recomputed."""
    seq = EVENT_COLUMNS.index("seq")
    earlier = [row[seq] for row in validate_snapshot(seq_from).rows["events"]]
    duration = EVENT_COLUMNS.index("duration_ms")

    def edit(events: List[Any], _trust: List[Any]) -> None:
        for row, reused in zip(events, earlier):
            row[seq] = reused
            row[duration] = 4242

    return _rewrite(source, target, edit)


def test_b4_sequence_collisions_are_conflicts_not_silent_drops(tmp_path) -> None:
    """B4: a segment whose rows reuse already-stored sequence numbers is refused as a conflict
    and changes nothing; it is not recorded as created with rows silently dropped."""
    seg1, seg2, _seg3 = _segments(tmp_path)
    colliding = _collide(seg2, tmp_path / "forged" / seg2.name, seg1)
    validate_snapshot(colliding)
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    assert _attempt(receiver, seg1)[0] == 201
    before = (_warehouse_counts(data_dir), _rows(data_dir, "SELECT * FROM events ORDER BY seq"))
    status, body = _attempt(receiver, colliding)
    assert status == 409, body
    assert (
        _warehouse_counts(data_dir),
        _rows(data_dir, "SELECT * FROM events ORDER BY seq"),
    ) == before
    assert evidence_state(data_dir)["dangling"] == []


def test_b5_chain_status_is_recomputed_when_a_predecessor_arrives(tmp_path) -> None:
    """B5: uploading segment 2 before segment 1 ends with both ``ok``; a successor whose
    declared predecessor digest is wrong ends ``broken``."""
    seg1, seg2, _seg3 = _segments(tmp_path)
    data_dir = tmp_path / "server"
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    assert _attempt(receiver, seg2)[0] == 201
    assert _rows(data_dir, "SELECT chain_status FROM uploads WHERE segment_index=2") == [("gap",)]
    assert _attempt(receiver, seg1)[0] == 201
    assert _rows(data_dir, "SELECT segment_index, chain_status FROM uploads ORDER BY 1") == [
        (1, "ok"),
        (2, "ok"),
    ]

    info = validate_snapshot(seg2)
    meta = {k: v for k, v in info.meta.items() if k != "content_digest"}
    meta["prev_segment_digest"] = "0" * 64
    tampered = tmp_path / "forged" / "tampered_prev.db"
    tampered.parent.mkdir(parents=True, exist_ok=True)
    write_snapshot(tampered, meta, info.rows)
    other = tmp_path / "server-tampered"
    receiver = Receiver(ReceiverConfig(data_dir=other))
    assert _attempt(receiver, tampered)[0] == 201
    assert _attempt(receiver, seg1)[0] == 201
    assert _rows(other, "SELECT chain_status FROM uploads WHERE segment_index=2") == [("broken",)]


def _write_config(tmp_path: Path, **upload: Any) -> Path:
    lines = [
        "[logging]",
        'backend = "sqlite"',
        f'sqlite_path = "{tmp_path / "log" / "lionlock.db"}"',
        "[telemetry_upload]",
    ]
    for key, value in upload.items():
        lines.append(f"{key} = {json.dumps(value)}")
    path = tmp_path / "lionlock.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def cli_environment(monkeypatch) -> None:
    """``load_config`` also reads these; the module's autouse fixture does not clear them."""
    for name in ("LIONLOCK_TELEMETRY_DB_URI", "LIONLOCK_GATING_ENABLED"):
        monkeypatch.delenv(name, raising=False)


def _cli(capsys, *argv: str) -> Tuple[int, Dict[str, Any]]:
    code = cli_main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_b6_export_reports_rows_left_by_the_segment_cap(
    tmp_path, monkeypatch, capsys, cli_environment
) -> None:
    """B6: when the per-run segment cap stops an export with rows left, the CLI says so and
    exits non-zero; an export that finishes still exits 0 without the flag."""
    seed_store(tmp_path / "log" / "lionlock.db", events=6, trust=0)
    config = _write_config(tmp_path, rows_per_snapshot=2)
    monkeypatch.setattr(export_module, "MAX_SEGMENTS_PER_RUN", 2)
    code, out = _cli(capsys, "--config", str(config), "export", "--out", str(tmp_path / "o1"))
    assert len(out["exported"]) == 2
    assert out.get("more_pending") is True
    assert code == 1

    monkeypatch.setattr(export_module, "MAX_SEGMENTS_PER_RUN", 1_000)
    code, out = _cli(capsys, "--config", str(config), "export", "--out", str(tmp_path / "o1"))
    assert len(out["exported"]) == 1
    assert not out.get("more_pending")
    assert code == 0


def test_b7_upload_exits_non_zero_when_a_snapshot_is_not_delivered(
    tmp_path, capsys, cli_environment
) -> None:
    """B7: ``upload`` exits non-zero when a snapshot is rejected or invalid, and 0 when every
    snapshot is delivered."""
    handler = type("Capture", (_CaptureHandler,), {"captured": []})
    server, url = _serve(handler)
    try:
        outbox = tmp_path / "outbox"
        source = make_clean(tmp_path / "work")
        outbox.mkdir()
        make_invalid_reason(source, outbox / source.name)
        config = _write_config(tmp_path, enabled=True, endpoint=url, outbox_dir=str(outbox))
        code, out = _cli(capsys, "--config", str(config), "upload")
        assert [u["status"] for u in out["uploads"]] == ["invalid"]
        assert code == 1

        seed_store(tmp_path / "log" / "lionlock.db", events=2, trust=0)
        code, out = _cli(capsys, "--config", str(config), "upload")
        assert [u["status"] for u in out["uploads"]] == ["uploaded"]
        assert code == 0
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    ("endpoint", "ok"),
    [
        ("https://telemetry.example.org:99999/x", False),
        ("https://telemetry.example.org:abc/x", False),
        ("http://127.0.0.1:70000", False),
        ("https://telemetry.example.org:8443/x", True),
        ("http://127.0.0.1:8787", True),
    ],
)
def test_b8_malformed_ports_are_refused(endpoint, ok) -> None:
    """B8: an endpoint whose port is not a valid TCP port is refused."""
    assert (endpoint_problem(endpoint) is None) is ok


def test_b9_store_refuses_a_non_empty_database_without_its_application_id(tmp_path) -> None:
    """B9: a database with application_id 0 that already has tables (even with LionLock's table
    names) is refused unchanged; an empty file and an existing LionLock log still open."""
    path = tmp_path / "lookalike.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE events (body TEXT)")
        conn.execute("INSERT INTO events VALUES ('synthetic foreign row')")
    before = sha256_file(path)
    with pytest.raises(StoreError):
        LogStore(path).append_event({"decision": "ALLOW"})
    assert sha256_file(path) == before

    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    LogStore(empty).append_event({"decision": "ALLOW"})
    log = tmp_path / "log.db"
    LogStore(log).append_event({"decision": "ALLOW"})
    with sqlite3.connect(log) as conn:
        assert conn.execute("PRAGMA application_id").fetchone()[0] == STORE_APPLICATION_ID
    assert LogStore(log).counts()["events"] == 1


# =============================================================================================
# Follow-up review round: an explicitly empty token allowlist, literal matching of SQLite's
# internal names, and the log's identity checked again on every open.
# =============================================================================================


class _IdleServer:
    """Stands in for the HTTP server so `serve` returns instead of blocking."""

    server_port = 8787

    def serve_forever(self) -> None:
        pass

    def server_close(self) -> None:
        pass


def _record_server_starts(monkeypatch) -> List[Any]:
    started: List[Any] = []

    def factory(config: Any, **_kwargs: Any) -> _IdleServer:
        started.append(config)
        return _IdleServer()

    monkeypatch.setattr(receiver_module, "make_server", factory)
    return started


def _run_serve_command(tmp_path: Path, *extra: str) -> int:
    return cli_main(
        [
            "--config",
            str(tmp_path / "absent.toml"),
            "serve",
            "--data-dir",
            str(tmp_path / "receiver"),
            *extra,
        ]
    )


@pytest.mark.parametrize("contents", ["", "# synthetic comments-only allowlist\n\n"])
def test_explicitly_empty_token_allowlist_refuses_to_start(
    tmp_path, monkeypatch, capsys, cli_environment, contents
) -> None:
    """A token allowlist that is given but lists no hashes stops `serve` before a server or any
    receiver state exists, instead of silently accepting anonymous uploads."""
    allowlist = tmp_path / "token_hashes.txt"
    allowlist.write_text(contents, encoding="utf-8")
    started = _record_server_starts(monkeypatch)
    code = _run_serve_command(tmp_path, "--token-hashes-file", str(allowlist))
    assert code != 0, "an empty allowlist started the receiver in anonymous mode"
    assert started == []
    assert not (tmp_path / "receiver").exists()
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and "token" in out["error"]
    with pytest.raises(ValueError):
        load_token_hashes(allowlist)


def test_omitted_token_allowlist_keeps_anonymous_mode(
    tmp_path, monkeypatch, capsys, cli_environment
) -> None:
    """Control: without --token-hashes-file the receiver still runs anonymously by design."""
    started = _record_server_starts(monkeypatch)
    assert _run_serve_command(tmp_path) == 0
    assert len(started) == 1 and started[0].token_hashes == frozenset()
    assert "anonymous" in capsys.readouterr().err


def test_listed_tokens_are_still_required(tmp_path, monkeypatch, cli_environment) -> None:
    """Control: a non-empty allowlist starts the receiver and admits only listed tokens."""
    token = "synthetic-listed-token-control"
    allowlist = tmp_path / "token_hashes.txt"
    allowlist.write_text(f"# synthetic\n{hash_token(token)}\n", encoding="utf-8")
    started = _record_server_starts(monkeypatch)
    assert _run_serve_command(tmp_path, "--token-hashes-file", str(allowlist)) == 0
    gate = Receiver(started[0])
    assert gate.authorize(None) is False
    assert gate.authorize("Bearer synthetic-unlisted-token") is False
    assert gate.authorize(f"Bearer {token}") is True


_PREFIXED_USER_TABLE = "sqliteX_customer_records"


def _write_db(path: Path, *statements: str) -> None:
    conn = sqlite3.connect(path)
    try:
        for statement in statements:
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()


def _set_mode(path: Path, mode: int) -> None:
    if os.name == "posix":
        os.chmod(path, mode)


def _fingerprint(path: Path) -> Tuple[str, Any]:
    mode = path.stat().st_mode & 0o777 if os.name == "posix" else None
    return sha256_file(path), mode


_PREFIXED_TABLE_DDL = (
    f"CREATE TABLE {_PREFIXED_USER_TABLE} (payload TEXT)",
    f"INSERT INTO {_PREFIXED_USER_TABLE} VALUES ('synthetic foreign record')",
)


@pytest.mark.parametrize("layout", ["prefixed_table_only", "current_layout_plus_prefixed_table"])
def test_sqlite_prefixed_user_tables_are_seen_by_the_warehouse_check(tmp_path, layout) -> None:
    """A user table whose name merely starts like SQLite's internal names (sqliteX_...) is still
    user schema: the warehouse is refused, with its bytes, mode, records and directory intact."""
    data_dir = tmp_path / layout
    data_dir.mkdir()
    statements = _PREFIXED_TABLE_DDL
    if layout == "current_layout_plus_prefixed_table":
        statements = (*WAREHOUSE_DDL, "PRAGMA user_version=2", *_PREFIXED_TABLE_DDL)
    _write_db(data_dir / "warehouse.db", *statements)
    _set_mode(data_dir / "warehouse.db", 0o640)
    before = _snapshot_dir(data_dir)
    with pytest.raises(WarehouseVersionError):
        Receiver(ReceiverConfig(data_dir=data_dir))
    assert _snapshot_dir(data_dir) == before


def test_sqlite_prefixed_user_tables_are_seen_by_the_log_check(tmp_path) -> None:
    """The local log refuses a database whose only table is sqliteX_..., unchanged."""
    path = tmp_path / "foreign.db"
    _write_db(path, *_PREFIXED_TABLE_DDL)
    _set_mode(path, 0o640)
    before = _fingerprint(path)
    with pytest.raises(StoreError):
        LogStore(path).append_event({"decision": "ALLOW"})
    assert _fingerprint(path) == before


def test_replaced_log_file_is_checked_again_before_any_change(tmp_path) -> None:
    """After a log has been opened, a different database moved onto the same path is checked
    afresh and refused, with its bytes and mode unchanged."""
    path = tmp_path / "active.db"
    LogStore(path).append_event({"decision": "ALLOW"})
    replacement = tmp_path / "replacement.db"
    shutil.copyfile(path, replacement)
    _write_db(replacement, "PRAGMA application_id=0", "PRAGMA user_version=0")
    _set_mode(replacement, 0o640)
    os.replace(replacement, path)
    before = _fingerprint(path)
    with pytest.raises(StoreError):
        LogStore(path).append_event({"decision": "ALLOW"})
    assert _fingerprint(path) == before


def test_log_changed_in_place_is_checked_again_before_any_change(tmp_path) -> None:
    """The same file losing its LionLock identity in place is refused by writes and reads."""
    path = tmp_path / "active.db"
    store = LogStore(path)
    store.append_event({"decision": "ALLOW"})
    inode = path.stat().st_ino
    _write_db(path, "PRAGMA application_id=0")
    _set_mode(path, 0o640)
    assert path.stat().st_ino == inode
    before = _fingerprint(path)
    with pytest.raises(StoreError):
        store.append_event({"decision": "ALLOW"})
    assert _fingerprint(path) == before
    with pytest.raises(StoreError):
        store.counts()
    assert _fingerprint(path) == before


def test_repeated_opens_of_a_legitimate_log_keep_working(tmp_path) -> None:
    """Control: ordinary repeated opens of a genuine log still append, read and verify."""
    path = tmp_path / "lionlock.db"
    for _ in range(3):
        LogStore(path).append_event({"decision": "ALLOW"})
    store = LogStore(path)
    assert store.counts()["events"] == 3
    assert all(status.ok for status in store.verify().values())
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
