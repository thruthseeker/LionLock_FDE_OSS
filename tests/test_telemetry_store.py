import os
import sqlite3
import threading
from pathlib import Path

import pytest

from lionlock.config import DEFAULT_CONFIG
from lionlock.core.gating import evaluate_policy
from lionlock.core.scoring import score_response
from lionlock.logging.event_log import build_signal_event, log_event
from lionlock.telemetry import store as store_module
from lionlock.telemetry.store import STORE_APPLICATION_ID, LogStore, StoreError
from lionlock.trust_overlay.logger import append_trust_record, build_trust_record


def _event(i: int, **overrides):
    event = {
        "timestamp_utc": f"2026-09-27T10:{i % 60:02d}:00Z",
        "request_id": f"req-{i}",
        "decision": "ALLOW",
        "severity": "green",
        "reason_code": "repetition_loop",
        "aggregate_score": 0.1,
        "signal_scores": {"repetition_loopiness": 0.1},
        "config_hash": "a" * 64,
        "duration_ms": 12,
    }
    event.update(overrides)
    return event


def _trust_record(session_id: str = "session-1", turn_index: int = 1) -> dict:
    return build_trust_record(
        session_id=session_id,
        turn_index=turn_index,
        model_id="llama3.1:8b",
        prompt_type="qa",
        derived_signals={"overall_risk": 0.2},
        aggregate_score=0.2,
        response_text="ok",
        response_hash=None,
        score_history=[],
        timestamps=[],
        config={},
        timestamp_utc="2026-09-27T10:00:00Z",
    )


def _sqlite_config(tmp_path: Path, **logging_overrides) -> dict:
    logging_cfg = {
        "enabled": True,
        "backend": "sqlite",
        "sqlite_path": str(tmp_path / "lionlock.db"),
        "path": str(tmp_path / "events.jsonl"),
    }
    logging_cfg.update(logging_overrides)
    return {"logging": logging_cfg, "logging_sql": {"enabled": False}}


def _row_hashes(path: Path, table: str = "events") -> list[str]:
    with sqlite3.connect(path) as conn:
        return [row[0] for row in conn.execute(f"SELECT row_hash FROM {table} ORDER BY seq")]


def test_defaults_log_to_sqlite_and_keep_uploads_off() -> None:
    assert DEFAULT_CONFIG["logging"]["backend"] == "sqlite"
    assert DEFAULT_CONFIG["telemetry_upload"]["enabled"] is False
    assert DEFAULT_CONFIG["telemetry_upload"]["endpoint"] == ""


def test_append_and_verify_round_trip(tmp_path: Path) -> None:
    store = LogStore(tmp_path / "lionlock.db")
    assert [store.append_event(_event(i)) for i in range(3)] == [1, 2, 3]
    assert store.append_trust_record(_trust_record()) == 1
    assert store.counts() == {"events": 3, "trust_records": 1}
    results = store.verify()
    assert all(result.ok for result in results.values())
    assert results["events"].rows_checked == 3


def test_verify_detects_an_edited_row(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = LogStore(path)
    for i in range(3):
        store.append_event(_event(i))
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE events SET decision = 'BLOCK' WHERE seq = 2")
    status = store.verify()["events"]
    assert status.ok is False
    assert status.first_bad_seq == 2


def test_verify_detects_a_deleted_row(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = LogStore(path)
    for i in range(3):
        store.append_event(_event(i))
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM events WHERE seq = 2")
    status = store.verify()["events"]
    assert status.ok is False
    assert status.first_bad_seq == 3


def test_verify_detects_a_rehashed_row(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = LogStore(path)
    for i in range(3):
        store.append_event(_event(i))
    with sqlite3.connect(path) as conn:
        # Forge row 2 and give it a self-consistent hash; row 3 no longer links to it.
        conn.execute(
            "UPDATE events SET decision = 'BLOCK', row_hash = ? WHERE seq = 2", ("f" * 64,)
        )
    status = store.verify()["events"]
    assert status.ok is False
    assert status.first_bad_seq in (2, 3)


def test_pruning_keeps_the_chain_verifiable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(store_module, "PRUNE_CHECK_INTERVAL", 4)
    store = LogStore(tmp_path / "lionlock.db", max_rows=5)
    for i in range(23):
        store.append_event(_event(i))
    rows = store.read_rows("events", limit=100)
    assert len(rows) <= 5 + 4
    assert rows[0]["seq"] > 1
    assert rows[-1]["seq"] == 23
    assert store.verify()["events"].ok is True


def test_negative_row_limit_never_turns_pruning_off(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        LogStore(tmp_path / "lionlock.db", max_rows=-1)
    config = {"logging": {"sqlite_path": str(tmp_path / "lionlock.db"), "sqlite_max_rows": -1}}
    assert store_module.open_store(config).max_rows == store_module.DEFAULT_MAX_ROWS
    assert LogStore(tmp_path / "lionlock.db", max_rows=0).max_rows == 0


def test_concurrent_writers_do_not_fork_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    errors: list[BaseException] = []

    def writer(worker: int) -> None:
        try:
            store = LogStore(path)
            for i in range(25):
                store.append_event(_event(i, request_id=f"w{worker}-{i}"))
        except BaseException as exc:  # pragma: no cover - surfaced by the assert below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    store = LogStore(path)
    assert store.counts()["events"] == 200
    assert store.verify()["events"].ok is True


def test_identical_inputs_produce_identical_hash_chains(tmp_path: Path) -> None:
    first, second = tmp_path / "a.db", tmp_path / "b.db"
    for path in (first, second):
        store = LogStore(path)
        for i in range(5):
            store.append_event(_event(i))
    assert _row_hashes(first) == _row_hashes(second)
    assert len(set(_row_hashes(first))) == 5


def test_refuses_a_database_that_is_not_a_lionlock_log(tmp_path: Path) -> None:
    path = tmp_path / "other.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE lionlock_signals (event_pk INTEGER PRIMARY KEY)")
    with pytest.raises(StoreError):
        LogStore(path).append_event(_event(0))


def test_refuses_a_newer_log_schema(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as conn:
        conn.execute(f"PRAGMA application_id={STORE_APPLICATION_ID}")
        conn.execute("PRAGMA user_version=99")
    with pytest.raises(StoreError):
        LogStore(path).append_event(_event(0))


def test_identity_is_created_lazily_and_never_printed(tmp_path: Path) -> None:
    store = LogStore(tmp_path / "lionlock.db")
    store.append_event(_event(0))
    assert store.get_meta("install_id", "export_key") == {}
    identity = store.identity()
    assert len(identity.install_id) == 32 and len(identity.export_key) == 64
    assert identity.export_key not in repr(identity)
    assert store.identity() == identity


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_log_file_is_private_to_the_owner(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    LogStore(path).append_event(_event(0))
    assert path.stat().st_mode & 0o077 == 0


def test_log_event_sqlite_backend_writes_the_store_only(tmp_path: Path) -> None:
    config = _sqlite_config(tmp_path)
    bundle = score_response("What is 2 + 2?", "2 + 2 equals 4.", {"turn_index": 1})
    decision = evaluate_policy(bundle)
    event = build_signal_event(
        timestamp_utc="2026-09-27T10:00:00Z",
        request_id="req-1",
        base_url="http://localhost:11434",
        model="llama3.1:8b",
        decision=decision.gating_decision,
        severity=decision.severity,
        reason_code=decision.reason_code,
        aggregate_score=decision.decision_risk_score,
        signal_scores=decision.signal_scores,
        duration_ms=5,
        config_hash="b" * 64,
        signal_bundle=decision.signal_bundle,
    )
    log_event(event, config)

    rows = LogStore(tmp_path / "lionlock.db").read_rows("events")
    assert len(rows) == 1
    assert rows[0]["decision"] == decision.gating_decision
    assert rows[0]["signal_bundle_json"] is not None
    assert "base_url" not in rows[0]["record_json"] and "llama3.1" not in rows[0]["record_json"]
    assert not (tmp_path / "events.jsonl").exists()


def test_trust_records_are_mirrored_into_the_store(tmp_path: Path) -> None:
    config = _sqlite_config(tmp_path)
    append_trust_record(_trust_record(), base_dir=tmp_path / "overlay", config=config)
    store = LogStore(tmp_path / "lionlock.db")
    assert store.counts()["trust_records"] == 1
    assert store.verify()["trust_records"].ok is True
