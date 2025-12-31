import json
import sqlite3
import tempfile
from pathlib import Path

from lionlock.anomaly import ANOMALY_TYPES, AnomalyState, detect_anomaly_events, validate_anomaly_event
from lionlock.config import DEFAULT_CONFIG
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores
from lionlock.logging.anomaly_sql import record_anomalies


def _bundle(
    *,
    hallucination: float = 0.95,
    fatigue: float = 0.8,
    congestion: float = 0.7,
) -> SignalBundle:
    scores = SignalScores(
        repetition_loopiness=0.9,
        novelty_entropy_proxy=0.1,
        coherence_structure=0.2,
        context_adherence=0.3,
        hallucination_risk=hallucination,
    )
    derived = DerivedSignals(
        fatigue_risk_index=fatigue,
        fatigue_risk_25t=fatigue,
        fatigue_risk_50t=fatigue,
        low_conf_halluc=0.2,
        congestion_signature=congestion,
    )
    return SignalBundle(
        signal_schema_version="SE-0.2.0",
        signal_scores=scores,
        derived_signals=derived,
        missing_inputs=(),
    )


def _contains_forbidden(value: object) -> bool:
    forbidden = {"prompt", "response", "prompt_text", "response_text", "user_id", "ip", "device_id"}
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in forbidden:
                return True
            if _contains_forbidden(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    return False


def test_anomaly_events_required_fields_and_taxonomy() -> None:
    bundle = _bundle()
    events, _, _, _ = detect_anomaly_events(
        session_id="session-1",
        turn_index=0,
        timestamp="2025-01-01T00:00:00Z",
        prompt_type=None,
        response_hash="resp-hash",
        signal_bundle=bundle,
        gating_decision="ALLOW",
        decision_risk_score=0.1,
        aggregate_score=0.92,
        config=DEFAULT_CONFIG,
    )

    assert events
    missing_fields = None
    for event in events:
        assert event["anomaly_type"] in ANOMALY_TYPES
        validate_anomaly_event(event)
        details = event.get("details", {})
        if isinstance(details, dict) and "missing_fields" in details:
            missing_fields = details["missing_fields"]
    assert missing_fields is not None
    assert "prompt_type" in missing_fields


def test_missed_signal_event_details() -> None:
    bundle = _bundle(hallucination=0.97, fatigue=0.2, congestion=0.1)
    events, _, _, _ = detect_anomaly_events(
        session_id="session-2",
        turn_index=1,
        timestamp="2025-01-01T00:00:00Z",
        prompt_type="qa",
        response_hash="resp-2",
        signal_bundle=bundle,
        gating_decision="ALLOW",
        decision_risk_score=0.05,
        aggregate_score=0.2,
        config=DEFAULT_CONFIG,
    )

    missed = [event for event in events if event["anomaly_type"] == "missed_signal_event"]
    assert missed
    details = missed[0]["details"]
    assert details["expected_decision"] == "BLOCK"
    assert details["actual_decision"] == "ALLOW"
    assert details["miss_reason"] == "threshold"
    assert details["response_hash"] == "resp-2"


def test_anomaly_determinism_same_inputs() -> None:
    bundle = _bundle(hallucination=0.85, fatigue=0.85, congestion=0.65)
    first, _, _, _ = detect_anomaly_events(
        session_id="session-3",
        turn_index=2,
        timestamp="2025-01-01T00:00:00Z",
        prompt_type="code",
        response_hash="resp-3",
        signal_bundle=bundle,
        gating_decision="WARN",
        decision_risk_score=0.4,
        aggregate_score=0.81,
        config=DEFAULT_CONFIG,
        state=AnomalyState(),
    )
    second, _, _, _ = detect_anomaly_events(
        session_id="session-3",
        turn_index=2,
        timestamp="2025-01-01T00:00:00Z",
        prompt_type="code",
        response_hash="resp-3",
        signal_bundle=bundle,
        gating_decision="WARN",
        decision_risk_score=0.4,
        aggregate_score=0.81,
        config=DEFAULT_CONFIG,
        state=AnomalyState(),
    )

    assert first == second


def test_partial_thresholds_fallback_to_defaults() -> None:
    bundle = _bundle(hallucination=0.1, fatigue=0.1, congestion=0.1)
    events, _, _, _ = detect_anomaly_events(
        session_id="session-pt",
        turn_index=4,
        timestamp="2025-01-01T00:00:00Z",
        prompt_type="qa",
        response_hash="resp-pt",
        signal_bundle=bundle,
        gating_decision="ALLOW",
        decision_risk_score=0.1,
        aggregate_score=0.5,
        thresholds={"yellow": 0.9},
        config=DEFAULT_CONFIG,
    )

    gate_mismatches = [
        event for event in events if event.get("anomaly_type") == "gate_mismatch"
    ]
    assert gate_mismatches
    details = gate_mismatches[0]["details"]
    assert details["expected_decision"] == "REFRESH"


def test_anomaly_sql_persistence() -> None:
    bundle = _bundle()
    events, _, severity_score, severity_tag = detect_anomaly_events(
        session_id="session-4",
        turn_index=3,
        timestamp="2025-01-01T00:00:00Z",
        prompt_type="other",
        response_hash="resp-4",
        signal_bundle=bundle,
        gating_decision="ALLOW",
        decision_risk_score=0.1,
        aggregate_score=0.92,
        config=DEFAULT_CONFIG,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "anomalies.db"
        anomaly_cfg = {
            "enabled": True,
            "db_uri": f"sqlite:///{db_path}",
            "table": "lionlock_anomalies",
            "diagnostics_table": "lionlock_session_diagnostics",
        }
        ok, _ = record_anomalies(
            anomaly_cfg,
            session_id="session-4",
            session_pk=None,
            timestamp_utc="2025-01-01T00:00:00Z",
            anomalies=events,
            anomaly_count=len(events),
            severity_score=severity_score,
            severity_tag=severity_tag,
            first_seen_utc="2025-01-01T00:00:00Z",
            last_seen_utc="2025-01-01T00:00:00Z",
        )
        assert ok
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT anomaly_type,severity,details,trust_logic_version,code_fingerprint "
                "FROM lionlock_anomalies"
            ).fetchone()
        assert row is not None
        details = json.loads(row[2])
        assert not _contains_forbidden(details)
