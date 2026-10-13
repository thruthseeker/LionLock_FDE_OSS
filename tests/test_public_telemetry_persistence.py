import json
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path
from typing import Callable

import pytest

from lionlock.logging.event_log import FORBIDDEN_KEYS, log_event
from lionlock.logging.sql_telemetry import get_writer, stop_writer


def _wait_for_signal_row(db_path: Path, table: str, timeout_s: float = 2.0) -> tuple | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(f"SELECT * FROM {table}").fetchone()
        if row:
            return row
        time.sleep(0.05)
    return None


def _build_config(db_path: Path, jsonl_path: Path, verbosity: str, allowlist: list[str]) -> dict:
    return {
        "logging": {
            "enabled": True,
            "backend": "both",
            "path": str(jsonl_path),
            "verbosity": verbosity,
            "content_policy": "signals_only",
            "notes_allowlist": allowlist,
            "notes_max_length": 120,
        },
        "logging_sql": {
            "enabled": True,
            "uri": f"sqlite:///{db_path}",
            "table": "lionlock_signals",
            "batch_size": 1,
            "flush_interval_ms": 10,
            "connect_timeout_s": 1,
        },
        "telemetry": {"sessions_table": "lionlock_sessions"},
    }


def test_log_event_persists_signals_only_sql_and_jsonl() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_root = Path(tmpdir)
        db_path = temp_root / "telemetry.db"
        jsonl_path = temp_root / "signals.jsonl"
        config = _build_config(db_path, jsonl_path, verbosity="normal", allowlist=[])

        event = {
            "timestamp_utc": "2025-12-19T00:00:00Z",
            "request_id": "req-1",
            "decision": "ALLOW",
            "severity": "green",
            "reason_code": "ok",
            "aggregate_score": 0.12,
            "signal_scores": {"repetition_loopiness": 0.1},
            "config_hash": "hash",
            "duration_ms": 12,
            "Prompt": "never_store_prompt",
            "response": "never_store_response",
            "payload_b64": "never_store_payload",
            "messages": "never_store_messages",
            "notes": {"connector_meta": "never_store_notes"},
        }

        log_event(event, config)
        row = _wait_for_signal_row(db_path, "lionlock_signals")
        writer = get_writer(config["logging_sql"])
        if writer is not None:
            writer.stop()

        assert row is not None
        row_text = " ".join(str(value) for value in row if value is not None)
        assert "never_store_prompt" not in row_text
        assert "never_store_response" not in row_text
        assert "never_store_payload" not in row_text
        assert "never_store_messages" not in row_text

        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        for forbidden in FORBIDDEN_KEYS:
            assert forbidden not in {key.lower() for key in record.keys()}
        assert "notes" not in record


def test_notes_allowlist_and_length_enforced() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_root = Path(tmpdir)
        db_path = temp_root / "telemetry.db"
        jsonl_path = temp_root / "signals.jsonl"
        config = _build_config(
            db_path,
            jsonl_path,
            verbosity="debug",
            allowlist=["connector_meta", "Prompt"],
        )

        long_note = "x" * 121
        event = {
            "timestamp_utc": "2025-12-19T00:00:00Z",
            "request_id": "req-2",
            "decision": "WARN",
            "severity": "orange",
            "reason_code": "fatigue_spike",
            "aggregate_score": 0.67,
            "signal_scores": {"repetition_loopiness": 0.7},
            "config_hash": "hash",
            "duration_ms": 20,
            "notes": {"connector_meta": long_note, "Prompt": "bad"},
        }

        log_event(event, config)
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert "notes" not in record

        event["request_id"] = "req-3"
        event["notes"] = {"connector_meta": "ok"}
        log_event(event, config)
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        record = json.loads(lines[-1])
        assert record["notes"] == {"connector_meta": "ok"}
        # Flush and join the SQL writer before tmpdir is deleted; otherwise its
        # in-flight insert can recreate files there and make cleanup fail.
        stop_writer()


def _signal_event(request_id: str) -> dict:
    return {
        "timestamp_utc": "2025-12-19T00:00:00Z",
        "request_id": request_id,
        "decision": "ALLOW",
        "severity": "green",
        "reason_code": "ok",
        "aggregate_score": 0.12,
        "signal_scores": {"repetition_loopiness": 0.1},
        "config_hash": "hash",
        "duration_ms": 12,
    }


def _stored_request_ids(db_path: Path) -> list[str]:
    with closing(sqlite3.connect(db_path)) as conn:
        rows = conn.execute("SELECT request_id FROM lionlock_signals ORDER BY event_pk").fetchall()
    return [row[0] for row in rows]


def _wait_until(predicate: Callable[[], bool], timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached before timeout")
        time.sleep(0.01)


def test_stop_writer_flushes_events_logged_before_shutdown(tmp_path: Path) -> None:
    db_path = tmp_path / "telemetry.db"
    config = _build_config(db_path, tmp_path / "signals.jsonl", verbosity="normal", allowlist=[])
    config["logging_sql"].update(batch_size=10, flush_interval_ms=60_000)
    request_ids = [f"req-{i:02d}" for i in range(25)]
    for request_id in request_ids:
        log_event(_signal_event(request_id), config)

    final = stop_writer()

    # The last partial batch (req-20..24) is only written by the flush in stop_writer().
    assert _stored_request_ids(db_path) == request_ids
    assert final is not None
    assert (final["written"], final["dropped"], final["failed"], final["pending"]) == (25, 0, 0, 0)


def test_database_lock_is_retried_without_breaking_log_event(tmp_path: Path) -> None:
    db_path = tmp_path / "telemetry.db"
    config = _build_config(db_path, tmp_path / "signals.jsonl", verbosity="normal", allowlist=[])
    log_event(_signal_event("req-before-lock"), config)
    writer = get_writer(config["logging_sql"])
    assert writer is not None
    _wait_until(lambda: writer.stats()["written"] == 1)

    locker = sqlite3.connect(db_path, isolation_level=None)
    locker.execute("BEGIN EXCLUSIVE")  # Every insert now fails with "database is locked".
    try:
        log_event(_signal_event("req-during-lock-1"), config)
        _wait_until(lambda: writer.stats()["retries"] >= 1)
        assert "database is locked" in (writer.last_error or "")
        # Previously the lock error disabled the writer and this call raised RuntimeError.
        log_event(_signal_event("req-during-lock-2"), config)
        assert writer.available
    finally:
        locker.execute("ROLLBACK")
        locker.close()

    _wait_until(lambda: writer.stats()["written"] == 3)
    assert get_writer(config["logging_sql"]) is writer  # Same writer, never torn down.
    final = stop_writer()
    assert _stored_request_ids(db_path) == [
        "req-before-lock",
        "req-during-lock-1",
        "req-during-lock-2",
    ]
    assert final is not None
    assert (final["failed"], final["dropped"], final["pending"]) == (0, 0, 0)


def test_stopped_writer_is_replaced_instead_of_raising(tmp_path: Path) -> None:
    db_path = tmp_path / "telemetry.db"
    config = _build_config(db_path, tmp_path / "signals.jsonl", verbosity="normal", allowlist=[])
    writer = get_writer(config["logging_sql"])
    assert writer is not None
    writer.stop()

    log_event(_signal_event("req-after-stop"), config)

    replacement = get_writer(config["logging_sql"])
    assert replacement is not writer and replacement is not None and replacement.available
    stop_writer()
    assert _stored_request_ids(db_path) == ["req-after-stop"]


def test_writer_init_failure_raises_runtime_error(tmp_path: Path) -> None:
    not_a_directory = tmp_path / "blocker"
    not_a_directory.write_text("", encoding="utf-8")
    config = _build_config(
        not_a_directory / "telemetry.db",
        tmp_path / "signals.jsonl",
        verbosity="normal",
        allowlist=[],
    )

    # Previously an AttributeError ('NoneType' object has no attribute 'error').
    with pytest.raises(RuntimeError, match="SQL telemetry init failed"):
        log_event(_signal_event("req-1"), config)
