import hashlib
import json
import re
import shutil
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from lionlock.telemetry import bigquery_sync as bigquery_sync_module
from lionlock.telemetry import cli as cli_module
from lionlock.telemetry.bigquery_sync import (
    BigQueryClient,
    BigQuerySyncError,
    SyncTarget,
    load_state,
    metadata_token_provider,
    sync,
    urllib_transport,
)
from lionlock.telemetry.export import export_snapshot
from lionlock.telemetry.receiver import Receiver, ReceiverConfig
from lionlock.telemetry.snapshot import file_sha256, validate_snapshot
from lionlock.telemetry.store import LogStore
from lionlock.telemetry.upload import CONTENT_TYPE

TARGET = SyncTarget(project="proj", dataset="lionlock_telemetry", location="us-central1")


class FakeBigQuery:
    """Just enough of the BigQuery jobs API: multipart load jobs and jobs.get."""

    def __init__(self) -> None:
        self.jobs = {}
        self.tables = {}
        self.posts = []
        self.gets = []
        self.deletes = []
        self.fail_job_ids = set()
        self.drop_response_after_post = 0
        self.output_rows_delta = 0
        self.running_polls = 0

    def __call__(self, method, url, headers, body):
        assert headers["Authorization"] == "Bearer test-token"
        if method == "DELETE":
            table = re.search(r"/datasets/lionlock_telemetry/tables/([^/?]+)$", url).group(1)
            self.deletes.append(table)
            if self.tables.pop(table, None) is None:
                return 404, b'{"error": {"message": "Not found: Table"}}'
            return 204, b""
        if method == "GET":
            job_id = re.search(r"/jobs/([^?]+)\?location=us-central1$", url).group(1)
            self.gets.append(job_id)
            job = self.jobs.get(job_id)
            if job is None:
                return 404, b'{"error": {"message": "Not found"}}'
            if self.running_polls:
                self.running_polls -= 1
                return 200, json.dumps({**job, "status": {"state": "RUNNING"}}).encode()
            return 200, json.dumps(job).encode()
        assert method == "POST" and url.endswith("/projects/proj/jobs?uploadType=multipart")
        boundary = headers["Content-Type"].split("boundary=")[1]
        parts = body.split(f"--{boundary}".encode())
        config = json.loads(parts[1].split(b"\r\n\r\n", 1)[1].rstrip(b"\r\n"))
        data = parts[2].split(b"\r\n\r\n", 1)[1][: -len(b"\r\n")]
        job_id = config["jobReference"]["jobId"]
        if job_id in self.jobs:
            return 409, b'{"error": {"message": "Already Exists"}}'
        self.posts.append((job_id, data))
        load = config["configuration"]["load"]
        table = load["destinationTable"]["tableId"]
        assert load["destinationTable"]["datasetId"] == "lionlock_telemetry"
        rows = [json.loads(line) for line in data.splitlines()]
        status = {"state": "DONE"}
        if job_id in self.fail_job_ids:
            status["errorResult"] = {"message": "simulated failure"}
        else:
            if load["writeDisposition"] == "WRITE_TRUNCATE":
                self.tables[table] = list(rows)
            else:
                assert load["timePartitioning"] == {"type": "DAY"}
                self.tables.setdefault(table, []).extend(rows)
            self.schema = getattr(self, "schema", {})
            self.schema[table] = load["schema"]["fields"]
        output = len(rows) + self.output_rows_delta if "errorResult" not in status else 0
        self.jobs[job_id] = {
            "jobReference": config["jobReference"],
            "status": status,
            "statistics": {"load": {"outputRows": str(output)}},
        }
        if self.drop_response_after_post:
            self.drop_response_after_post -= 1
            raise ConnectionError("connection lost after the job was created")
        return 200, json.dumps(self.jobs[job_id]).encode()


def _client(fake: FakeBigQuery) -> BigQueryClient:
    return BigQueryClient(TARGET, lambda: "test-token", transport=fake, sleep=lambda _s: None)


def _store(path: Path) -> LogStore:
    return LogStore(path / "log.db")


def _append(store: LogStore, start: int, count: int) -> None:
    for i in range(start, start + count):
        store.append_event(
            {
                "timestamp_utc": f"2026-09-27T10:{i % 60:02d}:00Z",
                "request_id": f"req-{i}",
                "decision": "REFRESH",
                "severity": "yellow",
                "reason_code": "low_coherence",
                "aggregate_score": 0.5 + i / 1000,
                "signal_scores": {"coherence_structure": 0.5},
                "duration_ms": 100 + i,
            }
        )
        store.append_trust_record(
            {
                "timestamp": f"2026-09-27T11:{i % 60:02d}:00Z",
                "session_id": "session-a",
                "turn_index": i,
                "model_id": "gpt-4o-mini",
                "prompt_type": "qa",
                "trust_score": 0.8,
                "trust_label": "TRUSTED",
                "badge": "STABLE",
                "volatility": 0.1,
            }
        )


def _segments(workdir: Path, sizes) -> list:
    store = _store(workdir)
    paths, start = [], 0
    for size in sizes:
        _append(store, start, size)
        start += size
        result = export_snapshot(store, workdir / "outbox")
        assert result is not None
        paths.append(result.path)
    return paths


def _ingest(receiver: Receiver, path: Path) -> None:
    info = validate_snapshot(path)
    headers = {
        "Content-Type": CONTENT_TYPE,
        "X-LionLock-File-SHA256": file_sha256(path),
        "X-LionLock-Install-Id": info.install_id,
        "X-LionLock-Segment": str(info.segment_index),
        "X-LionLock-Content-Digest": info.content_digest,
    }
    assert receiver.handle_upload(headers, path.read_bytes()).status == 201


def _server(tmp_path: Path, sizes=(3, 4)):
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    paths = _segments(tmp_path / "client", sizes)
    return receiver, paths


def _warehouse_rows(data_dir: Path, table: str) -> list:
    conn = sqlite3.connect(data_dir / "warehouse.db")
    conn.row_factory = sqlite3.Row
    order = "install_id, segment_index" if table == "uploads" else "rowid"
    rows = [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY {order}")]
    conn.close()
    return rows


def _run(tmp_path: Path, fake: FakeBigQuery, **kwargs):
    return sync(tmp_path / "server", tmp_path / "bq" / "state.json", _client(fake), **kwargs)


def test_sync_copies_every_warehouse_row_unchanged_and_only_once(tmp_path) -> None:
    receiver, paths = _server(tmp_path)
    for path in paths:
        _ingest(receiver, path)
    fake = FakeBigQuery()

    summary = _run(tmp_path, fake)

    data_dir = tmp_path / "server"
    for table in ("uploads", "events", "trust_records"):
        assert fake.tables[table] == _warehouse_rows(data_dir, table)
    assert summary["tables"]["events"]["rows_loaded"] == 7
    assert summary["tables"]["trust_records"]["rows_loaded"] == 7
    assert summary["tables"]["uploads"]["rows"] == 2
    events_schema = {field["name"]: field for field in fake.schema["events"]}
    assert events_schema["seq"] == {"name": "seq", "type": "INTEGER", "mode": "REQUIRED"}
    assert events_schema["aggregate_score"]["type"] == "FLOAT"
    assert events_schema["severity"]["mode"] == "NULLABLE"

    posts = len(fake.posts)
    again = _run(tmp_path, fake)
    assert len(fake.posts) == posts
    assert again["tables"]["uploads"]["unchanged"] is True
    assert again["tables"]["events"]["rows_loaded"] == 0


def test_new_rows_are_appended_in_bounded_batches(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3, 4, 5))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    _run(tmp_path, fake, batch_rows=2)
    _ingest(receiver, paths[1])
    _ingest(receiver, paths[2])

    summary = _run(tmp_path, fake, batch_rows=2)

    assert fake.tables["events"] == _warehouse_rows(tmp_path / "server", "events")
    assert summary["tables"]["events"]["rows_loaded"] == 9
    assert len(summary["tables"]["events"]["jobs"]) == 5
    assert len({job_id for job_id, _data in fake.posts}) == len(fake.posts)


def test_a_crash_after_submitting_never_loads_rows_twice(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3, 4))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    fake.drop_response_after_post = 2  # the uploads job, then the first events job

    with pytest.raises(ConnectionError):
        _run(tmp_path, fake)
    with pytest.raises(ConnectionError):
        _run(tmp_path, fake)
    state = load_state(tmp_path / "bq" / "state.json", TARGET)
    assert state["pending"]["table"] == "events"
    assert state["watermarks"]["events"] == 0

    _ingest(receiver, paths[1])  # more rows arrive before the retry
    _run(tmp_path, fake)

    data_dir = tmp_path / "server"
    for table in ("uploads", "events", "trust_records"):
        assert fake.tables[table] == _warehouse_rows(data_dir, table)
    assert load_state(tmp_path / "bq" / "state.json", TARGET)["pending"] is None


def test_a_failed_job_loads_nothing_and_is_retried_under_a_new_id(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    probe = FakeBigQuery()
    _run(tmp_path, probe)  # learn the deterministic job IDs
    first_events_job = next(job for job, _ in probe.posts if job.startswith("lionlock_events_"))
    shutil.rmtree(tmp_path / "bq")

    fake = FakeBigQuery()
    fake.fail_job_ids.add(first_events_job)
    with pytest.raises(BigQuerySyncError, match="simulated failure"):
        _run(tmp_path, fake)
    assert "events" not in fake.tables
    state = load_state(tmp_path / "bq" / "state.json", TARGET)
    assert state["watermarks"]["events"] == 0

    summary = _run(tmp_path, fake)

    assert summary["tables"]["events"]["jobs"] == [first_events_job[:-2] + "-2"]
    assert fake.tables["events"] == _warehouse_rows(tmp_path / "server", "events")


def _first_job(tmp_path: Path, prefix: str) -> str:
    """The deterministic ID of the first load job for a table, learned from a throwaway run."""
    probe = FakeBigQuery()
    _run(tmp_path, probe)
    shutil.rmtree(tmp_path / "bq")
    return next(job for job, _ in probe.posts if job.startswith(prefix))


def test_a_persistent_failure_is_retried_once_per_run_and_never_sticks(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    base = _first_job(tmp_path, "lionlock_events_")[: -len("-1")]
    fake = FakeBigQuery()
    fake.fail_job_ids.update(f"{base}-{attempt}" for attempt in range(1, 8))

    for attempt in range(1, 8):
        fake.gets.clear()
        with pytest.raises(BigQuerySyncError, match="the next run retries it"):
            _run(tmp_path, fake)
        events_posts = [job for job, _ in fake.posts if job.startswith(base)]
        assert events_posts[-1] == f"{base}-{attempt}" and len(events_posts) == attempt
        # The recorded attempt number means a run never walks the earlier failed jobs again.
        assert [job for job in fake.gets if job.startswith(base)] == [f"{base}-{attempt}"] * 2
        state = load_state(tmp_path / "bq" / "state.json", TARGET)
        assert state["pending"]["attempt"] == attempt + 1
        assert state["watermarks"]["events"] == 0
        assert "events" not in fake.tables

    summary = _run(tmp_path, fake)

    assert summary["tables"]["events"]["jobs"] == [f"{base}-8"]
    assert fake.tables["events"] == _warehouse_rows(tmp_path / "server", "events")
    assert load_state(tmp_path / "bq" / "state.json", TARGET)["pending"] is None


def test_a_job_that_failed_unseen_before_a_crash_is_retried_under_the_next_id(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    base = _first_job(tmp_path, "lionlock_events_")[: -len("-1")]
    fake = FakeBigQuery()
    fake.fail_job_ids.add(f"{base}-1")
    fake.drop_response_after_post = 2  # the uploads job, then the failing events job

    with pytest.raises(ConnectionError):
        _run(tmp_path, fake)
    with pytest.raises(ConnectionError):
        _run(tmp_path, fake)
    # The events job exists and failed, but no run has seen that yet.
    assert load_state(tmp_path / "bq" / "state.json", TARGET)["pending"]["attempt"] == 1

    summary = _run(tmp_path, fake)

    assert summary["tables"]["events"]["jobs"] == [f"{base}-2"]
    assert fake.tables["events"] == _warehouse_rows(tmp_path / "server", "events")


def test_a_failed_uploads_replace_is_retried_under_a_new_id(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    first_uploads_job = _first_job(tmp_path, "lionlock_uploads_")
    fake = FakeBigQuery()
    fake.fail_job_ids.add(first_uploads_job)

    with pytest.raises(BigQuerySyncError, match="simulated failure"):
        _run(tmp_path, fake)
    state = load_state(tmp_path / "bq" / "state.json", TARGET)
    assert state["replace_attempts"]["uploads"]["attempt"] == 2
    assert state["replaced_sha256"]["uploads"] == ""

    fake.gets.clear()
    summary = _run(tmp_path, fake)

    retry = first_uploads_job[: -len("-1")] + "-2"
    assert summary["tables"]["uploads"]["job"] == retry
    # The retry starts from the recorded attempt instead of re-reading the failed job.
    assert [job for job in fake.gets if job.startswith("lionlock_uploads_")] == [retry] * 2
    assert fake.tables["uploads"] == _warehouse_rows(tmp_path / "server", "uploads")
    state = load_state(tmp_path / "bq" / "state.json", TARGET)
    assert state["replace_attempts"]["uploads"] == {"sha256": "", "attempt": 1}


def test_a_row_count_mismatch_stops_without_marking_rows_loaded(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    fake.output_rows_delta = -1

    with pytest.raises(BigQuerySyncError, match="expected"):
        _run(tmp_path, fake)

    state_path = tmp_path / "bq" / "state.json"
    if state_path.exists():
        state = load_state(state_path, TARGET)
        assert state["watermarks"] == {"events": 0, "trust_records": 0}
        assert state["replaced_sha256"]["uploads"] == ""


def test_jobs_still_running_are_awaited(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(2,))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    fake.running_polls = 3

    _run(tmp_path, fake)

    assert fake.tables["events"] == _warehouse_rows(tmp_path / "server", "events")


def test_uploads_are_replaced_when_a_late_segment_relinks_the_chain(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3, 4))
    _ingest(receiver, paths[1])  # segment 2 first: recorded as a gap
    fake = FakeBigQuery()
    _run(tmp_path, fake)
    assert [row["chain_status"] for row in fake.tables["uploads"]] != ["ok"]

    _ingest(receiver, paths[0])
    _run(tmp_path, fake)

    assert fake.tables["uploads"] == _warehouse_rows(tmp_path / "server", "uploads")
    assert [row["chain_status"] for row in fake.tables["uploads"]] == ["ok", "ok"]
    assert fake.tables["events"] == _warehouse_rows(tmp_path / "server", "events")


def _delete_install(data_dir: Path, install_id: str) -> None:
    """The documented deletion workflow, applied to the warehouse."""
    with sqlite3.connect(data_dir / "warehouse.db") as conn:
        for table in ("uploads", "events", "trust_records"):
            conn.execute(f"DELETE FROM {table} WHERE install_id = ?", (install_id,))


def _delete_uploads_rows(data_dir: Path, install_id: str | None = None) -> None:
    """Change only uploads, leaving the append tables (and so their anchors) intact."""
    with sqlite3.connect(data_dir / "warehouse.db") as conn:
        if install_id is None:
            conn.execute("DELETE FROM uploads")
        else:
            conn.execute("DELETE FROM uploads WHERE install_id = ?", (install_id,))


def test_a_deletion_of_the_last_copied_rows_stops_before_bigquery_changes(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    _run(tmp_path, fake)
    before = _bigquery_snapshot(fake)

    _delete_install(tmp_path / "server", validate_snapshot(paths[0]).install_id)

    # The deleted rows include the last ones copied, which is indistinguishable from a
    # replaced warehouse, so the sync stops before touching BigQuery; the operator deletes the
    # same rows there, as the deletion workflow documents.
    with pytest.raises(BigQuerySyncError, match="missing or changed"):
        _run(tmp_path, fake)
    assert _bigquery_snapshot(fake) == before


def test_uploads_content_that_recurs_is_loaded_again(tmp_path) -> None:
    receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    first = _segments(tmp_path / "install-x", (3,))[0]
    second = _segments(tmp_path / "install-y", (2,))[0]
    _ingest(receiver, first)
    fake = FakeBigQuery()
    _run(tmp_path, fake)
    earlier_uploads = list(fake.tables["uploads"])
    _ingest(receiver, second)
    _run(tmp_path, fake)
    assert len(fake.tables["uploads"]) == 2

    # uploads returns to content an earlier job already loaded; a content-only job ID would
    # find that job and skip the replacement, leaving the removed row in BigQuery.
    _delete_uploads_rows(tmp_path / "server", validate_snapshot(second).install_id)
    summary = _run(tmp_path, fake)

    assert summary["tables"]["uploads"]["unchanged"] is False
    assert fake.tables["uploads"] == earlier_uploads
    assert fake.tables["uploads"] == _warehouse_rows(tmp_path / "server", "uploads")


def test_an_emptied_uploads_table_is_cleared_in_bigquery_once(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    _run(tmp_path, fake)
    assert len(fake.tables["uploads"]) == 1

    _delete_uploads_rows(tmp_path / "server")
    summary = _run(tmp_path, fake)

    assert summary["tables"]["uploads"]["deleted"] is True
    assert "uploads" not in fake.tables and fake.deletes == ["uploads"]
    state = load_state(tmp_path / "bq" / "state.json", TARGET)
    assert state["replaced_sha256"]["uploads"] == hashlib.sha256(b"").hexdigest()
    _run(tmp_path, fake)
    assert fake.deletes == ["uploads"]  # cleared once, not on every run
    _client(fake).delete_table("uploads")  # already gone (a retry after a crash): not an error


def test_an_empty_warehouse_never_touches_bigquery(tmp_path) -> None:
    Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    fake = FakeBigQuery()

    summary = _run(tmp_path, fake)

    assert summary["tables"]["uploads"] == {"rows": 0, "unchanged": True}
    assert fake.posts == [] and fake.deletes == []


def test_job_ids_and_batches_are_deterministic(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3, 4))
    for path in paths:
        _ingest(receiver, path)
    copy = tmp_path / "copy"
    (copy / "server").mkdir(parents=True)
    shutil.copy2(tmp_path / "server" / "warehouse.db", copy / "server" / "warehouse.db")

    first, second = FakeBigQuery(), FakeBigQuery()
    _run(tmp_path, first, batch_rows=3)
    _run(copy, second, batch_rows=3)

    assert first.posts == second.posts


def test_a_state_file_for_another_destination_is_refused(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(2,))
    _ingest(receiver, paths[0])
    _run(tmp_path, FakeBigQuery())
    other = BigQueryClient(
        SyncTarget(project="proj", dataset="other", location="us-central1"),
        lambda: "test-token",
        transport=FakeBigQuery(),
    )
    with pytest.raises(BigQuerySyncError, match="new state file"):
        sync(tmp_path / "server", tmp_path / "bq" / "state.json", other)


def _bigquery_snapshot(fake: FakeBigQuery):
    return json.dumps(fake.tables, sort_keys=True), len(fake.posts), list(fake.deletes)


@pytest.mark.parametrize("replacement_segments", [(5,), ()], ids=["other-data", "empty"])
def test_a_replaced_warehouse_is_refused_before_bigquery_changes(
    tmp_path, replacement_segments
) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    _run(tmp_path, fake)
    before = _bigquery_snapshot(fake)

    shutil.rmtree(tmp_path / "server")
    other_receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    for path in (
        _segments(tmp_path / "other-client", replacement_segments) if replacement_segments else []
    ):
        _ingest(other_receiver, path)

    with pytest.raises(BigQuerySyncError, match="missing or changed"):
        _run(tmp_path, fake)

    # Nothing was loaded, replaced or deleted on the strength of the replaced warehouse.
    assert _bigquery_snapshot(fake) == before


def test_a_concurrent_sync_is_refused(tmp_path) -> None:
    fcntl = pytest.importorskip("fcntl")
    receiver, paths = _server(tmp_path, sizes=(2,))
    _ingest(receiver, paths[0])
    lock = tmp_path / "bq" / "state.json.lock"
    lock.parent.mkdir(parents=True)
    with lock.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        with pytest.raises(BigQuerySyncError, match="another bigquery-sync"):
            _run(tmp_path, FakeBigQuery())


def test_cli_reports_a_missing_warehouse_as_json(tmp_path, capsys) -> None:
    code = cli_module.main(
        [
            "--config",
            str(tmp_path / "absent.toml"),
            "bigquery-sync",
            "--data-dir",
            str(tmp_path / "nowhere"),
            "--state-file",
            str(tmp_path / "state.json"),
            "--project",
            "proj",
            "--dataset",
            "lionlock_telemetry",
            "--location",
            "us-central1",
        ]
    )
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False and "does not exist" in payload["error"]


def test_network_errors_are_reported_as_sync_errors(monkeypatch) -> None:
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    send = urllib_transport(timeout_s=5)
    # Port 1 on loopback refuses connections.
    with pytest.raises(BigQuerySyncError, match="GET http://127.0.0.1:1/jobs failed"):
        send("GET", "http://127.0.0.1:1/jobs?location=x", {}, None)


def _metadata_server(monkeypatch, body: bytes):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Metadata-Flavor"))
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/token"
    monkeypatch.setattr(bigquery_sync_module, "METADATA_TOKEN_URL", url)
    return server, seen


def test_metadata_tokens_are_fetched_with_the_flavor_header_and_cached(monkeypatch) -> None:
    server, seen = _metadata_server(monkeypatch, b'{"access_token": "abc", "expires_in": 3599}')
    try:
        token = metadata_token_provider()
        assert token() == "abc"
        assert token() == "abc"
    finally:
        server.shutdown()
        server.server_close()
    assert seen == ["Google"]


def test_a_malformed_metadata_token_is_a_sync_error(monkeypatch) -> None:
    server, _seen = _metadata_server(monkeypatch, b'{"token_type": "Bearer"}')
    try:
        with pytest.raises(BigQuerySyncError, match="could not get an access token"):
            metadata_token_provider()()
    finally:
        server.shutdown()
        server.server_close()
