import json
import sqlite3

from lionlock.anomaly import detect_anomaly_events
from lionlock.config import DEFAULT_CONFIG
from lionlock.core.models import (
    DerivedSignals,
    SignalBundle,
    SignalScores,
    canonical_gating_decision,
)
from lionlock.logging.anomaly_sql import record_anomalies


def _bundle() -> SignalBundle:
    scores = SignalScores(
        repetition_loopiness=0.1,
        novelty_entropy_proxy=0.1,
        coherence_structure=0.1,
        context_adherence=0.1,
        hallucination_risk=0.1,
    )
    derived = DerivedSignals(
        fatigue_risk_index=0.1,
        fatigue_risk_25t=0.1,
        fatigue_risk_50t=0.1,
        low_conf_halluc=0.1,
        congestion_signature=0.1,
    )
    return SignalBundle(
        signal_schema_version="SE-0.2.0",
        signal_scores=scores,
        derived_signals=derived,
        missing_inputs=(),
    )


def _has_gate_mismatch(events: list[dict]) -> bool:
    return any(event.get("anomaly_type") == "gate_mismatch" for event in events)


def test_canonical_gating_decision_warn_maps_to_refresh() -> None:
    assert canonical_gating_decision("WARN") == "REFRESH"
    assert canonical_gating_decision("refresh") == "REFRESH"
    assert canonical_gating_decision("ALLOW") == "ALLOW"
    assert canonical_gating_decision("BLOCK") == "BLOCK"
    assert canonical_gating_decision("") == "UNKNOWN"
    assert canonical_gating_decision(None) == "UNKNOWN"


def test_detector_accepts_refresh_and_warn_equivalence() -> None:
    bundle = _bundle()
    common = dict(
        session_id="session-1",
        turn_index=1,
        timestamp="2025-01-01T00:00:00Z",
        prompt_type="qa",
        response_hash="resp-1",
        signal_bundle=bundle,
        decision_risk_score=0.1,
        aggregate_score=0.5,
        latency_window_stats=[10.0, 12.0],
        duration_ms=12.0,
        syntactic_abnormality=0.1,
        config=DEFAULT_CONFIG,
    )

    events_refresh, _, _, _ = detect_anomaly_events(gating_decision="REFRESH", **common)
    events_warn, _, _, _ = detect_anomaly_events(gating_decision="WARN", **common)

    assert not _has_gate_mismatch(events_refresh)
    assert not _has_gate_mismatch(events_warn)


def test_canonical_sql_fields_do_not_store_warn(tmp_path) -> None:
    db_path = tmp_path / "anomalies.db"
    anomaly_cfg = {
        "enabled": True,
        "db_uri": f"sqlite:///{db_path}",
        "table": "anomalies",
        "diagnostics_table": "lionlock_session_diagnostics",
    }
    anomaly = {
        "anomaly_type": "gate_mismatch",
        "severity": 0.4,
        "details": {
            "expected_decision": "WARN",
            "actual_decision": "WARN",
            "miss_reason": "threshold",
        },
        "session_id": "session-1",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {"signal_scores": {}, "derived_signals": {}},
        "gating_decision": "WARN",
        "decision_risk_score": 0.2,
        "trigger_signal": "hallucination_risk",
        "trust_logic_version": "v1",
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-1",
    }

    ok, message = record_anomalies(
        anomaly_cfg,
        session_id="session-1",
        session_pk=None,
        timestamp_utc="2025-01-01T00:00:00Z",
        anomalies=[anomaly],
        anomaly_count=1,
        severity_score=0.4,
        severity_tag="test",
        first_seen_utc="2025-01-01T00:00:00Z",
        last_seen_utc="2025-01-01T00:00:00Z",
    )
    assert ok, message

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT gating_decision, details_json FROM anomalies"
        ).fetchone()

    assert row is not None
    gating_decision, details_json = row
    assert gating_decision == "REFRESH"
    details = json.loads(details_json)
    assert details["expected_decision"] == "REFRESH"
    assert details["actual_decision"] == "REFRESH"
