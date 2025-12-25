import json
import sqlite3
import tempfile
import time
from pathlib import Path

from lionlock.logging.event_log import FORBIDDEN_KEYS, log_event
from lionlock.logging.sql_telemetry import get_writer


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
