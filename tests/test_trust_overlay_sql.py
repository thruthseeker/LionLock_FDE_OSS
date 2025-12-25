import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from lionlock.trust_overlay.logger import append_trust_record, build_trust_record
from lionlock.trust_overlay.schemas import EXACT_BANNED_KEYS
from lionlock.trust_overlay.sql_sink import TRUST_OVERLAY_COLUMNS, get_writer, stop_writer


def _build_record(config: dict | None = None) -> dict:
    return build_trust_record(
        session_id="session-1",
        turn_index=1,
        model_id="model-1",
        prompt_type="qa",
        derived_signals={"overall_risk": 0.2},
        aggregate_score=0.2,
        response_text="ok",
        response_hash=None,
        score_history=[],
        timestamps=[],
        config=config or {},
        user_id="user-1",
    )


def _build_sql_config(db_path: Path, enabled: bool) -> dict:
    return {
        "trust_overlay": {
            "sql": {
                "enabled": enabled,
                "backend": "sqlite3",
                "sqlite_path": str(db_path),
                "table": "trust_overlay_records",
                "batch_size": 1,
                "flush_interval_ms": 10,
                "connect_timeout_s": 1,
            }
        }
    }


def _wait_for_row(db_path: Path, table: str, timeout_s: float = 2.0) -> tuple | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if db_path.exists():
            with sqlite3.connect(db_path) as conn:
                row = conn.execute(f"SELECT * FROM {table}").fetchone()
            if row:
                return row
        time.sleep(0.05)
    return None


def _wait_for_count(db_path: Path, table: str, expected: int, timeout_s: float = 2.0) -> int:
    deadline = time.monotonic() + timeout_s
    count = 0
    while time.monotonic() < deadline:
        if db_path.exists():
            with sqlite3.connect(db_path) as conn:
                row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            if row:
                count = int(row[0])
                if count >= expected:
                    return count
        time.sleep(0.05)
    return count


def _contains_banned_keys(value: Any) -> bool:
    banned = {key.lower() for key in EXACT_BANNED_KEYS}
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in banned:
                return True
            if _contains_banned_keys(item):
                return True
    if isinstance(value, list):
        return any(_contains_banned_keys(item) for item in value)
    return False


def test_trust_overlay_dual_write_jsonl_and_sql(tmp_path: Path) -> None:
    db_path = tmp_path / "overlay.db"
    jsonl_dir = tmp_path / "logs"
    config = _build_sql_config(db_path, enabled=True)
    record = _build_record(config=config)

    path = append_trust_record(record, base_dir=jsonl_dir, config=config)
    row = _wait_for_row(db_path, "trust_overlay_records")
    stop_writer()

    assert path.exists()
    assert row is not None
    saved = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert saved["turn_index"] == 1
    columns = [name for name, _ in TRUST_OVERLAY_COLUMNS]
    row_map = dict(zip(columns, row))
    assert row_map["turn_index"] == 1


def test_trust_overlay_sql_sanitizes_record_json(tmp_path: Path) -> None:
    db_path = tmp_path / "overlay.db"
    config = _build_sql_config(db_path, enabled=True)
    record = _build_record(config=config)
    record["prompt"] = "secret"
    record["signal_summary"]["response_text"] = "secret"
    record["signal_summary"]["raw_prompt"] = "secret"

    append_trust_record(record, base_dir=tmp_path, config=config)
    row = _wait_for_row(db_path, "trust_overlay_records")
    stop_writer()

    assert row is not None
    columns = [name for name, _ in TRUST_OVERLAY_COLUMNS]
    row_map = dict(zip(columns, row))
    stored_record = json.loads(row_map["record_json"])
    assert _contains_banned_keys(stored_record) is False


def test_trust_overlay_sql_exactly_once(tmp_path: Path) -> None:
    db_path = tmp_path / "overlay.db"
    config = _build_sql_config(db_path, enabled=True)
    record = _build_record(config=config)

    append_trust_record(record, base_dir=tmp_path, config=config)
    append_trust_record(record, base_dir=tmp_path, config=config)
    count = _wait_for_count(db_path, "trust_overlay_records", expected=2)
    stop_writer()

    assert count == 2


def test_trust_overlay_sql_writer_singleton_stop_on_reconfig(tmp_path: Path) -> None:
    db_path = tmp_path / "overlay.db"
    config = _build_sql_config(db_path, enabled=True)
    writer_one = get_writer(config["trust_overlay"]["sql"])
    writer_two = get_writer(config["trust_overlay"]["sql"])

    db_path_alt = tmp_path / "overlay_alt.db"
    config_alt = _build_sql_config(db_path_alt, enabled=True)
    writer_three = get_writer(config_alt["trust_overlay"]["sql"])
    stop_writer()

    assert writer_one is writer_two
    assert writer_one is not writer_three
    assert writer_one is not None and writer_one.stop_event.is_set()


def test_trust_overlay_sql_disabled_skips_db(tmp_path: Path) -> None:
    db_path = tmp_path / "overlay.db"
    config = _build_sql_config(db_path, enabled=False)
    record = _build_record(config=config)

    append_trust_record(record, base_dir=tmp_path, config=config)

    assert db_path.exists() is False


def test_trust_overlay_invalid_record_no_writes(tmp_path: Path) -> None:
    db_path = tmp_path / "overlay.db"
    jsonl_dir = tmp_path / "logs"
    config = _build_sql_config(db_path, enabled=True)
    record = _build_record(config=config)
    record["trust_score"] = 2.0

    with pytest.raises(ValueError):
        append_trust_record(record, base_dir=jsonl_dir, config=config)

    assert list(jsonl_dir.glob("*")) == []
    assert db_path.exists() is False
