import json
import math

from lionlock.core import evaluate_policy
from lionlock.core.scoring import score_response
from lionlock.logging import events_sql, sql_init
from lionlock.logging.privacy import contains_forbidden_keys


def test_module05_end_to_end_sql_pipeline() -> None:
    uri = "sqlite:///:memory:"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    prompt = "alpha beta gamma delta epsilon"
    response = "alpha beta gamma delta epsilon"
    metadata = {
        "entropy_decay": 1.0,
        "drift_slope": 1.0,
        "turn_index": 50,
        "latency_window_stats": [10.0, 10.0, 10.0],
        "duration_ms": 120,
    }

    bundle = score_response(prompt, response, metadata=metadata)
    decision = evaluate_policy(bundle)
    second = evaluate_policy(bundle)

    assert decision.decision_risk_score == second.decision_risk_score
    assert decision.trigger_signal == second.trigger_signal
    assert decision.gating_decision in {"ALLOW", "REFRESH", "BLOCK"}

    derived = bundle.derived_signals.as_dict()
    derived_channel = max(
        derived["fatigue_risk_index"],
        derived["low_conf_halluc"],
        derived["congestion_signature"],
    )
    assert derived_channel >= decision.aggregate_score
    assert math.isclose(
        decision.decision_risk_score,
        max(derived_channel, decision.aggregate_score),
        rel_tol=0.0,
        abs_tol=1e-9,
    )
    assert decision.trigger_signal == "low_conf_halluc"

    event = {
        "session_id": "session-1",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": bundle.as_dict(),
        "gating_decision": decision.gating_decision,
        "decision_risk_score": decision.decision_risk_score,
        "trigger_signal": decision.trigger_signal,
        "trust_logic_version": "TO-0.1.0",
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-1",
        "severity": decision.severity,
    }

    ok, message = events_sql.record_gating_event(uri_or_dsn=uri, event=event)
    assert ok, message

    conn = events_sql._memory_connection()
    row = conn.execute(
        "SELECT gating_decision, decision_risk_score, trigger_signal, signal_bundle FROM events"
    ).fetchone()
    assert row is not None
    gating_decision, decision_risk_score, trigger_signal, signal_bundle = row
    assert gating_decision in {"ALLOW", "REFRESH", "BLOCK"}
    assert math.isfinite(decision_risk_score)
    assert trigger_signal

    bundle_payload = json.loads(signal_bundle)
    assert not contains_forbidden_keys(bundle_payload)

    columns = [row[1] for row in conn.execute("PRAGMA table_info(events)")]
    for field in sql_init.MANDATORY_FIELDS:
        assert field in columns
