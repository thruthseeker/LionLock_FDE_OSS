import json
import re
import shutil
import sqlite3
from pathlib import Path

import pytest

from lionlock.telemetry import cli as cli_module
from lionlock.telemetry.bigquery_sync import (
    BigQueryClient,
    BigQuerySyncError,
    SyncTarget,
    load_state,
    sync,
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
        self.fail_job_ids = set()
        self.drop_response_after_post = 0
        self.output_rows_delta = 0
        self.running_polls = 0

    def __call__(self, method, url, headers, body):
        assert headers["Authorization"] == "Bearer test-token"
        if method == "GET":
            job_id = re.search(r"/jobs/([^?]+)\?location=us-central1$", url).group(1)
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


def test_a_replaced_warehouse_is_refused(tmp_path) -> None:
    receiver, paths = _server(tmp_path, sizes=(3,))
    _ingest(receiver, paths[0])
    fake = FakeBigQuery()
    _run(tmp_path, fake)

    shutil.rmtree(tmp_path / "server")
    other_receiver = Receiver(ReceiverConfig(data_dir=tmp_path / "server"))
    for path in _segments(tmp_path / "other-client", (5,)):
        _ingest(other_receiver, path)

    with pytest.raises(BigQuerySyncError, match="missing or changed"):
        _run(tmp_path, fake)


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
