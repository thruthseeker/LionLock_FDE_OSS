import json

from lionlock.logging import missed_signal_sql, sql_init
from lionlock.logging.privacy import contains_forbidden_keys


def test_module05_missed_signal_insert_sqlite_memory() -> None:
    uri = "sqlite:///:memory:"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    record = {
        "session_id": "session-1",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {
            "signal_scores": {"hallucination_risk": 0.2},
            "derived_signals": {"fatigue_risk_index": 0.3},
            "missing_inputs": [],
        },
        "gating_decision": "WARN",
        "decision_risk_score": 0.3,
        "trigger_signal": "fatigue_risk_index",
        "trust_logic_version": "v1",
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-missed-1",
        "replay_id": "replay-1",
        "miss_reason": "threshold",
        "expected_decision": "WARN",
        "actual_decision": "ALLOW",
    }

    ok, message = missed_signal_sql.record_missed_signal_event(uri_or_dsn=uri, record=record)
    assert ok, message

    conn = missed_signal_sql._memory_connection()
    row = conn.execute(
        "SELECT expected_decision, actual_decision, signal_bundle, replay_id "
        "FROM missed_signal_events WHERE response_hash=?",
        ("hash-missed-1",),
    ).fetchone()
    assert row is not None
    expected_decision, actual_decision, signal_bundle, replay_id = row
    assert expected_decision == "REFRESH"
    assert actual_decision == "ALLOW"
    assert replay_id == "replay-1"

    bundle_payload = json.loads(signal_bundle)
    assert not contains_forbidden_keys(bundle_payload)

    ok, message = missed_signal_sql.record_missed_signal_event(uri_or_dsn=uri, record=record)
    assert ok, message
    count = conn.execute("SELECT COUNT(*) FROM missed_signal_events").fetchone()
    assert count is not None and count[0] == 1

    columns = [row[1] for row in conn.execute("PRAGMA table_info(missed_signal_events)")]
    for field in sql_init.MANDATORY_FIELDS:
        assert field in columns
    assert "replay_id" in columns


def test_module05_missed_signal_rejects_forbidden_value_content() -> None:
    uri = "sqlite:///:memory:"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    record = {
        "session_id": "session-2",
        "turn_index": 2,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {
            "signal_scores": {"hallucination_risk": 0.2},
            "derived_signals": {"fatigue_risk_index": 0.3},
            "missing_inputs": [],
        },
        "gating_decision": "ALLOW",
        "decision_risk_score": 0.2,
        "trigger_signal": "hallucination_risk",
        "trust_logic_version": "v1",
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-2",
        "miss_reason": "threshold",
        "expected_decision": "REFRESH",
        "actual_decision": "ALLOW",
        "notes": "response: do not store this",
    }

    ok, message = missed_signal_sql.record_missed_signal_event(uri_or_dsn=uri, record=record)
    assert ok is False
    assert "forbidden content" in message.lower()
