import gzip
import hashlib
import logging
import os
import shutil
import sqlite3
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from lionlock.logging.token_auth import hash_token
from lionlock.telemetry import snapshot as snapshot_module
from lionlock.telemetry import upload as upload_module
from lionlock.telemetry.export import export_snapshot, pending_snapshots
from lionlock.telemetry.receiver import (
    WAREHOUSE_SCHEMA_VERSION,
    Receiver,
    ReceiverConfig,
    WarehouseVersionError,
    gunzip_capped,
    load_token_hashes,
    make_server,
)
from lionlock.telemetry.snapshot import (
    SnapshotError,
    file_sha256,
    validate_snapshot,
    write_snapshot,
)
from lionlock.telemetry.store import LogStore
from lionlock.telemetry.upload import (
    CONTENT_TYPE,
    UploadDisabledError,
    endpoint_problem,
    export_and_upload,
    maybe_export_and_upload,
    resolve_upload_settings,
    upload_pending,
    upload_snapshot,
)

_ENV = (
    "DO_NOT_TRACK",
    "LIONLOCK_TELEMETRY_UPLOAD",
    "LIONLOCK_TELEMETRY_ENDPOINT",
    "LIONLOCK_UPLOAD_TOKEN",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def start_receiver(tmp_path):
    servers = []

    def _start(**overrides):
        config = ReceiverConfig(data_dir=tmp_path / "server", **overrides)
        server = make_server(config, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    yield _start
    for server in servers:
        server.shutdown()
        server.server_close()


def _config(tmp_path: Path, endpoint: str = "", enabled: bool = False, **upload) -> dict:
    return {
        "logging": {"enabled": True, "backend": "sqlite", "sqlite_path": str(tmp_path / "log.db")},
        "logging_sql": {"enabled": False},
        "telemetry_upload": {"enabled": enabled, "endpoint": endpoint, **upload},
    }


def _log(tmp_path: Path, count: int = 3, start: int = 0) -> LogStore:
    store = LogStore(tmp_path / "log.db")
    for i in range(start, start + count):
        store.append_event(
            {
                "timestamp_utc": f"2026-09-27T10:{i % 60:02d}:00Z",
                "request_id": f"req-{i}",
                "decision": "REFRESH",
                "severity": "yellow",
                "reason_code": "low_coherence",
                "aggregate_score": 0.5,
                "signal_scores": {"coherence_structure": 0.5},
                "duration_ms": 100 + i,
            }
        )
    return store


def _warehouse(tmp_path: Path, query: str) -> list:
    with sqlite3.connect(tmp_path / "server" / "warehouse.db") as conn:
        return conn.execute(query).fetchall()


def _upload_headers(path: Path) -> dict:
    info = validate_snapshot(path)
    return {
        "Content-Type": CONTENT_TYPE,
        "X-LionLock-File-SHA256": file_sha256(path),
        "X-LionLock-Install-Id": info.install_id,
        "X-LionLock-Segment": str(info.segment_index),
        "X-LionLock-Content-Digest": info.content_digest,
    }


def test_uploads_are_off_by_default_and_never_touch_the_network(tmp_path, monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise AssertionError("network access attempted while uploads are disabled")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    config = _config(tmp_path, endpoint="https://telemetry.example.org")
    _log(tmp_path)
    settings = resolve_upload_settings(config)
    assert settings.allowed is False
    assert "opt-in" in (settings.blocked_reason or "")
    with pytest.raises(UploadDisabledError):
        export_and_upload(config)
    with pytest.raises(UploadDisabledError):
        upload_pending(settings)
    assert maybe_export_and_upload(config)["status"] == "disabled"


@pytest.mark.parametrize(
    "value, allowed",
    [
        (True, True),
        ("true", True),
        (" Yes ", True),
        ("on", True),
        (False, False),
        ("false", False),
        ("False", False),
        ("no", False),
        ("0", False),
        ("off", False),
        ("", False),
        ("ture", False),
        (1, False),
        (None, False),
    ],
)
def test_enabled_switch_fails_closed(tmp_path, monkeypatch, value, allowed) -> None:
    monkeypatch.delenv("LIONLOCK_TELEMETRY_UPLOAD", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    config = _config(tmp_path, endpoint="https://telemetry.example.org")
    config["telemetry_upload"]["enabled"] = value
    assert resolve_upload_settings(config).allowed is allowed


def test_do_not_track_overrides_every_opt_in(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    monkeypatch.setenv("LIONLOCK_TELEMETRY_UPLOAD", "on")
    config = _config(tmp_path, endpoint="https://telemetry.example.org", enabled=True)
    assert resolve_upload_settings(config).blocked_reason == "DO_NOT_TRACK is set"


def test_environment_can_opt_in_and_set_the_endpoint(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LIONLOCK_TELEMETRY_UPLOAD", "on")
    monkeypatch.setenv("LIONLOCK_TELEMETRY_ENDPOINT", "https://telemetry.example.org")
    settings = resolve_upload_settings(_config(tmp_path))
    assert settings.allowed is True
    assert settings.url == "https://telemetry.example.org/v1/snapshots"


@pytest.mark.parametrize(
    ("endpoint", "ok"),
    [
        ("https://telemetry.example.org", True),
        ("https://telemetry.example.org/lionlock/", True),
        ("http://127.0.0.1:8787", True),
        ("http://localhost:8787", True),
        ("http://telemetry.example.org", False),
        ("https://user:secret@telemetry.example.org", False),
        ("https://telemetry.example.org/?key=secret", False),
        ("ftp://telemetry.example.org", False),
        ("not a url", False),
    ],
)
def test_endpoint_must_be_https_without_embedded_secrets(endpoint, ok) -> None:
    assert (endpoint_problem(endpoint) is None) is ok


def test_end_to_end_upload_is_idempotent_and_chained(tmp_path, start_receiver) -> None:
    _, url = start_receiver()
    config = _config(tmp_path, endpoint=url, enabled=True)
    _log(tmp_path, count=3)
    first = export_and_upload(config, sleep=lambda _s: None)
    assert [item["status"] for item in first["uploads"]] == ["uploaded"]
    assert first["pending"] == 0

    _log(tmp_path, count=2, start=3)
    second = export_and_upload(config, sleep=lambda _s: None)
    assert [item["status"] for item in second["uploads"]] == ["uploaded"]
    assert _warehouse(tmp_path, "SELECT segment_index, chain_status FROM uploads ORDER BY 1") == [
        (1, "ok"),
        (2, "ok"),
    ]
    assert _warehouse(tmp_path, "SELECT COUNT(*) FROM events") == [(5,)]

    accepted = sorted((tmp_path / "server" / "accepted").glob("*.db"))
    resend = tmp_path / "log-outbox-copy" / accepted[0].name
    resend.parent.mkdir()
    shutil.copy(accepted[0], resend)
    outcome = upload_snapshot(resend, resolve_upload_settings(config))
    assert (outcome.status, outcome.http_status) == ("duplicate", 200)
    assert _warehouse(tmp_path, "SELECT COUNT(*) FROM events") == [(5,)]


def test_receiver_can_require_bearer_tokens(tmp_path, start_receiver, monkeypatch) -> None:
    token = "llk_test_token_value_0123456789"
    hashes = tmp_path / "token_hashes.txt"
    hashes.write_text(f"# accepted tokens\n{hash_token(token)}\n", encoding="utf-8")
    _, url = start_receiver(token_hashes=load_token_hashes(hashes))
    config = _config(tmp_path, endpoint=url, enabled=True)
    _log(tmp_path)

    refused = export_and_upload(config, sleep=lambda _s: None)
    assert [item["status"] for item in refused["uploads"]] == ["auth_failed"]
    assert refused["pending"] == 1

    monkeypatch.setenv("LIONLOCK_UPLOAD_TOKEN", token)
    accepted = export_and_upload(config, sleep=lambda _s: None)
    assert [item["status"] for item in accepted["uploads"]] == ["uploaded"]
    assert accepted["pending"] == 0


def test_token_mode_rate_limits_per_token_not_per_install(tmp_path) -> None:
    token = "llk_test_token_value_0123456789"
    receiver = Receiver(
        ReceiverConfig(
            data_dir=tmp_path / "server",
            token_hashes=frozenset({hash_token(token)}),
            uploads_per_hour=1,
        )
    )
    first, second = _exported(tmp_path / "a"), _exported(tmp_path / "b")
    assert validate_snapshot(first).install_id != validate_snapshot(second).install_id
    auth = {"Authorization": f"Bearer {token}"}

    accepted = receiver.handle_upload({**_upload_headers(first), **auth}, first.read_bytes())
    assert accepted.status == 201
    # A new install id under the same token does not reset the budget.
    rotated = receiver.handle_upload({**_upload_headers(second), **auth}, second.read_bytes())
    assert rotated.status == 429


def test_token_hash_file_refuses_raw_tokens(tmp_path) -> None:
    path = tmp_path / "hashes.txt"
    path.write_text("llk_this_is_a_raw_token\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_token_hashes(path)


def _exported(tmp_path: Path) -> Path:
    _log(tmp_path)
    result = export_snapshot(LogStore(tmp_path / "log.db"), tmp_path / "outbox")
    assert result is not None
    return result.path


def test_receiver_rejects_rows_that_violate_the_policy(tmp_path) -> None:
    info = validate_snapshot(_exported(tmp_path))
    row = list(info.rows["events"][0])
    row[4] = "free text reason: the user asked about salaries"
    forged = tmp_path / "forged.db"
    meta = {key: value for key, value in info.meta.items() if key != "content_digest"}
    meta["events_rows"] = "1"
    write_snapshot(forged, meta, {"events": [tuple(row)], "trust_records": []})

    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    result = receiver.handle_upload(_upload_headers_unchecked(forged), forged.read_bytes())
    assert result.status == 422
    assert "export policy" in result.body["error"]
    # A rejection is recorded by its reason alone; the uploaded file is not kept anywhere.
    rejected = tmp_path / "server" / "rejected"
    assert list(rejected.glob("*.db")) == []
    reasons = list(rejected.glob("*.reason.txt"))
    assert [path.name for path in reasons] == [f"{file_sha256(forged)}.reason.txt"]
    note = reasons[0].read_text(encoding="utf-8")
    assert "export policy" in note and "salaries" not in note
    assert [p for p in (tmp_path / "server" / "quarantine").rglob("*") if p.is_file()] == []
    assert _warehouse(tmp_path, "SELECT COUNT(*) FROM events") == [(0,)]


def _upload_headers_unchecked(path: Path) -> dict:
    with sqlite3.connect(path) as conn:
        meta = dict(conn.execute("SELECT key, value FROM snapshot_meta"))
    return {
        "Content-Type": CONTENT_TYPE,
        "X-LionLock-File-SHA256": file_sha256(path),
        "X-LionLock-Install-Id": meta["install_id"],
        "X-LionLock-Segment": meta["segment_index"],
        "X-LionLock-Content-Digest": meta["content_digest"],
    }


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TRIGGER t AFTER INSERT ON events BEGIN SELECT 1; END",
        "CREATE VIEW v AS SELECT * FROM events",
        "CREATE TABLE extra (secret TEXT)",
        "CREATE INDEX idx ON events (decision)",
    ],
)
def test_receiver_rejects_unexpected_schema_objects(tmp_path, ddl) -> None:
    path = _exported(tmp_path)
    with sqlite3.connect(path) as conn:
        conn.execute(ddl)
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    result = receiver.handle_upload(_upload_headers_unchecked(path), path.read_bytes())
    assert result.status == 422
    assert "schema" in result.body["error"]


def test_receiver_rejects_bad_transport_metadata(tmp_path) -> None:
    path = _exported(tmp_path)
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    headers = _upload_headers(path)
    body = path.read_bytes()

    assert receiver.handle_upload({**headers, "Content-Type": "text/plain"}, body).status == 415
    wrong_sha = {**headers, "X-LionLock-File-SHA256": "0" * 64}
    assert receiver.handle_upload(wrong_sha, body).status == 400
    wrong_segment = {**headers, "X-LionLock-Segment": "9"}
    assert receiver.handle_upload(wrong_segment, body).status == 422
    assert receiver.handle_upload(headers, b"not sqlite" + body).status == 400


def test_receiver_caps_decompressed_size(tmp_path) -> None:
    bomb = gzip.compress(b"\0" * (2 * 1024 * 1024))
    with pytest.raises(ValueError, match="size limit"):
        gunzip_capped(bomb, 1024 * 1024)
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server", max_snapshot_bytes=1 << 20))
    headers = {
        "Content-Type": CONTENT_TYPE,
        "Content-Encoding": "gzip",
        "X-LionLock-File-SHA256": "0" * 64,
        "X-LionLock-Install-Id": "0" * 32,
    }
    assert receiver.handle_upload(headers, bomb).status == 413


def test_receiver_detects_conflicting_segments(tmp_path) -> None:
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    original = _exported(tmp_path)
    assert receiver.handle_upload(_upload_headers(original), original.read_bytes()).status == 201

    info = validate_snapshot(original)
    row = list(info.rows["events"][0])
    row[8] = 999
    meta = {key: value for key, value in info.meta.items() if key != "content_digest"}
    other = tmp_path / "other.db"
    write_snapshot(
        other, meta, {"events": [tuple(row), *info.rows["events"][1:]], "trust_records": []}
    )
    result = receiver.handle_upload(_upload_headers(other), other.read_bytes())
    assert result.status == 409


def test_receiver_sheds_load_before_reading_bodies(tmp_path, start_receiver) -> None:
    server, url = start_receiver(max_concurrent_uploads=1)
    config = _config(tmp_path, endpoint=url, enabled=True)
    _log(tmp_path)
    with server.receiver.upload_slot() as acquired:
        assert acquired
        busy = export_and_upload(config, max_attempts=1)
    assert [(item["status"], item["http_status"]) for item in busy["uploads"]] == [("retry", 503)]
    assert busy["pending"] == 1
    after = export_and_upload(config, max_attempts=1)
    assert [item["status"] for item in after["uploads"]] == ["uploaded"]


def test_receiver_never_logs_client_addresses(tmp_path, start_receiver, caplog) -> None:
    _, url = start_receiver()
    caplog.set_level(logging.INFO, logger="lionlock.telemetry.receiver")
    config = _config(tmp_path, endpoint=url, enabled=True)
    _log(tmp_path)
    export_and_upload(config, sleep=lambda _s: None)
    urllib.request.urlopen(f"{url}/healthz", timeout=5).read()
    assert "POST /v1/snapshots" in caplog.text
    assert "127.0.0.1" not in caplog.text


class _Recorder(BaseHTTPRequestHandler):
    """Stub endpoint whose behaviour is scripted per test through class attributes."""

    responses: list = []
    seen: list = []

    def log_message(self, *_args) -> None:
        pass

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        type(self).seen.append({key.lower(): value for key, value in self.headers.items()})
        status, headers = type(self).responses.pop(0) if type(self).responses else (201, {})
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _stub(responses: list):
    handler = type("Stub", (_Recorder,), {"responses": list(responses), "seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler, f"http://127.0.0.1:{server.server_address[1]}"


def test_uploader_never_follows_redirects_or_forwards_tokens(tmp_path, monkeypatch) -> None:
    target, target_handler, target_url = _stub([])
    redirector, _, redirect_url = _stub([(307, {"Location": f"{target_url}/v1/snapshots"})])
    try:
        monkeypatch.setenv("LIONLOCK_UPLOAD_TOKEN", "llk_do_not_forward_me_0123")
        path = _exported(tmp_path)
        settings = resolve_upload_settings(_config(tmp_path, endpoint=redirect_url, enabled=True))
        outcome = upload_snapshot(path, settings)
        assert outcome.status == "misconfigured"
        assert target_handler.seen == []
    finally:
        for server in (target, redirector):
            server.shutdown()
            server.server_close()


def test_uploader_retries_transient_failures(tmp_path) -> None:
    server, handler, url = _stub([(503, {"Retry-After": "1"}), (503, {}), (201, {})])
    try:
        _exported(tmp_path)
        settings = resolve_upload_settings(_config(tmp_path, endpoint=url, enabled=True))
        waits: list = []
        outcomes = upload_pending(settings, max_attempts=3, sleep=waits.append)
        assert [outcome.status for outcome in outcomes] == ["uploaded"]
        assert len(handler.seen) == 3 and len(waits) == 2
        assert pending_snapshots(settings.outbox_dir) == []
        sent = handler.seen[-1]
        assert sent["content-encoding"] == "gzip"
        assert sent["user-agent"].startswith("lionlock/")
        assert "authorization" not in sent
    finally:
        server.shutdown()
        server.server_close()


def test_rejected_snapshots_are_set_aside_not_retried(tmp_path) -> None:
    server, handler, url = _stub([(422, {})])
    try:
        path = _exported(tmp_path)
        settings = resolve_upload_settings(_config(tmp_path, endpoint=url, enabled=True))
        outcomes = upload_pending(settings, sleep=lambda _s: None)
        assert [outcome.status for outcome in outcomes] == ["rejected"]
        assert (settings.outbox_dir / "rejected" / path.name).exists()
        assert pending_snapshots(settings.outbox_dir) == []
    finally:
        server.shutdown()
        server.server_close()


def test_tampered_outbox_files_are_never_sent(tmp_path) -> None:
    server, handler, url = _stub([])
    try:
        path = _exported(tmp_path)
        with sqlite3.connect(path) as conn:
            conn.execute("UPDATE events SET reason_code = 'Contact alice@example.com'")
        settings = resolve_upload_settings(_config(tmp_path, endpoint=url, enabled=True))
        outcomes = upload_pending(settings, sleep=lambda _s: None)
        assert [outcome.status for outcome in outcomes] == ["invalid"]
        assert handler.seen == []
    finally:
        server.shutdown()
        server.server_close()


def test_maybe_export_and_upload_runs_once_per_interval(tmp_path, start_receiver) -> None:
    _, url = start_receiver()
    config = _config(tmp_path, endpoint=url, enabled=True, interval_hours=24)
    _log(tmp_path)
    first = maybe_export_and_upload(config)
    assert first["status"] == "ok"
    assert [item["status"] for item in first["uploads"]] == ["uploaded"]
    assert maybe_export_and_upload(config)["status"] == "skipped"


def test_gzip_body_is_reproducible(tmp_path) -> None:
    path = _exported(tmp_path)
    raw = path.read_bytes()
    assert gzip.compress(raw, mtime=0) == gzip.compress(raw, mtime=0)
    assert hashlib.sha256(gunzip_capped(gzip.compress(raw, mtime=0), len(raw))).hexdigest() == (
        file_sha256(path)
    )


def test_receiver_stores_a_rebuild_and_records_both_digests(tmp_path) -> None:
    path = _exported(tmp_path)
    padded = tmp_path / "padded.db"
    padded.write_bytes(path.read_bytes() + b"bytes after the last database page")
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    result = receiver.handle_upload(_upload_headers_unchecked(padded), padded.read_bytes())
    assert result.status == 201

    query = "SELECT received_sha256, stored_sha256 FROM uploads"
    [(received, stored)] = _warehouse(tmp_path, query)
    assert received == file_sha256(padded) == result.body["file_sha256"]
    assert stored == result.body["stored_sha256"] != received
    kept = tmp_path / "server" / "accepted" / f"{stored}.db"
    assert file_sha256(kept) == stored
    assert b"bytes after the last database page" not in kept.read_bytes()
    assert validate_snapshot(kept).content_digest == validate_snapshot(path).content_digest
    assert [p for p in (tmp_path / "server" / "quarantine").rglob("*") if p.is_file()] == []


@pytest.mark.skipif(os.name != "posix", reason="checks POSIX permission bits")
def test_raw_upload_bytes_live_only_in_an_owner_only_quarantine_file(tmp_path, monkeypatch):
    seen: list = []
    original = snapshot_module.validate_snapshot

    def spy(path, **kwargs):
        seen.append((path, path.stat().st_mode & 0o777, path.parent.stat().st_mode & 0o777))
        return original(path, **kwargs)

    monkeypatch.setattr(snapshot_module, "validate_snapshot", spy)
    path = _exported(tmp_path)
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    assert receiver.handle_upload(_upload_headers(path), path.read_bytes()).status == 201
    raw_copy, file_mode, dir_mode = seen[0]
    assert raw_copy.parent.parent == tmp_path / "server" / "quarantine"
    assert (file_mode, dir_mode) == (0o600, 0o700)
    assert not raw_copy.parent.exists()


def test_uploader_fails_closed_when_the_rebuild_fails(tmp_path, monkeypatch) -> None:
    def broken(_info, **_kwargs):
        raise SnapshotError("rebuilt snapshot does not reproduce the validated content")

    monkeypatch.setattr(upload_module, "rebuild_clean", broken)
    server, handler, url = _stub([])
    try:
        path = _exported(tmp_path)
        settings = resolve_upload_settings(_config(tmp_path, endpoint=url, enabled=True))
        outcome = upload_snapshot(path, settings)
        assert outcome.status == "invalid"
        assert handler.seen == []
    finally:
        server.shutdown()
        server.server_close()


def test_receiver_refuses_a_warehouse_with_an_older_layout(tmp_path) -> None:
    old = tmp_path / "old"
    old.mkdir()
    with sqlite3.connect(old / "warehouse.db") as conn:
        conn.execute("CREATE TABLE uploads (file_sha256 TEXT PRIMARY KEY NOT NULL)")
    before = file_sha256(old / "warehouse.db")
    with pytest.raises(WarehouseVersionError, match="new data directory"):
        Receiver(ReceiverConfig(data_dir=old))
    assert file_sha256(old / "warehouse.db") == before

    fresh = tmp_path / "fresh"
    Receiver(ReceiverConfig(data_dir=fresh))
    Receiver(ReceiverConfig(data_dir=fresh))
    with sqlite3.connect(fresh / "warehouse.db") as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == WAREHOUSE_SCHEMA_VERSION


def test_resending_identical_bytes_counts_against_the_rate_limit(tmp_path) -> None:
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server", uploads_per_hour=2))
    snapshot = _exported(tmp_path / "a")
    headers, body = _upload_headers(snapshot), snapshot.read_bytes()

    statuses = [receiver.handle_upload(headers, body).status for _ in range(3)]
    assert statuses == [201, 200, 429]


def test_a_full_rate_table_keeps_current_budgets_instead_of_resetting_them(
    tmp_path, monkeypatch
) -> None:
    from lionlock.telemetry import receiver as receiver_module

    monkeypatch.setattr(receiver_module, "_RATE_KEYS_MAX", 3)
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server", uploads_per_hour=1))
    for key in ("install:a", "install:b", "install:c"):
        assert receiver._within_rate(key)
    # A fourth client cannot get in by overflowing the table...
    assert not receiver._within_rate("install:d")
    # ...and the clients already counted keep their spent budget.
    assert not receiver._within_rate("install:a")

    hour = int(receiver_module.time.time() // 3600)
    receiver._rate = {key: (hour - 1, 1) for key in receiver._rate}
    receiver._rate_pruned_hour = hour - 1  # simulate the hour having turned since the last prune
    # Buckets from an earlier hour are dropped to make room.
    assert receiver._within_rate("install:d")


def test_a_full_rate_table_is_pruned_at_most_once_per_hour(tmp_path, monkeypatch) -> None:
    from lionlock.telemetry import receiver as receiver_module

    monkeypatch.setattr(receiver_module, "_RATE_KEYS_MAX", 2)
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server", uploads_per_hour=5))
    assert receiver._within_rate("install:a") and receiver._within_rate("install:b")
    assert not receiver._within_rate("install:c")
    table = receiver._rate
    assert not receiver._within_rate("install:d")
    assert receiver._rate is table  # not rebuilt again within the same hour
