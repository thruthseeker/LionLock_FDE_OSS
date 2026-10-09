"""Privacy-boundary regressions for snapshot transfer (hidden bytes) and exported labels.

Every case drives the checked-out ``lionlock`` package with synthetic data: fixtures are small
SQLite files built in the test, HTTP stays on loopback, and each canary is first confirmed in its
source so that its absence afterwards means something.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import shutil
import sqlite3
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Sequence, Tuple

import pytest

from lionlock.telemetry import policy
from lionlock.telemetry.canonical import canonical_json
from lionlock.telemetry.export import export_all, export_snapshot
from lionlock.telemetry.receiver import Receiver, ReceiverConfig, make_server
from lionlock.telemetry.snapshot import (
    EVENT_COLUMNS,
    TRUST_COLUMNS,
    SnapshotError,
    validate_snapshot,
    write_snapshot,
)
from lionlock.telemetry.store import LogStore
from lionlock.telemetry.upload import (
    CONTENT_TYPE,
    UPLOAD_PATH,
    UploadOutcome,
    endpoint_problem,
    resolve_upload_settings,
    upload_pending,
    upload_snapshot,
)

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
