import json

from lionlock.logging import events_sql, sql_init
from lionlock.replay import policy_registry, replay_engine, reporting
from lionlock.replay.sql_reader import read_events


def _write_registry(tmp_path) -> str:
    policy_path = tmp_path / "policies.toml"
    policy_path.write_text(
        (
            '[policies."GC-0.3.1"]\n'
            "gating.enabled = true\n"
            'gating.hallucination_mode = "warn_only"\n'
            "gating.thresholds.yellow = 0.45\n"
            "gating.thresholds.orange = 0.65\n"
            "gating.thresholds.red = 0.80\n"
            "signals.enabled = [\n"
            '  "repetition_loopiness",\n'
            '  "novelty_entropy_proxy",\n'
            '  "coherence_structure",\n'
            '  "context_adherence",\n'
            '  "hallucination_risk",\n'
            "]\n"
            '[policies."GC-0.3.1".signals.weights]\n'
            "repetition_loopiness = 0.30\n"
            "novelty_entropy_proxy = 0.25\n"
            "coherence_structure = 0.25\n"
            "context_adherence = 0.20\n"
            "hallucination_risk = 0.00\n"
        ),
        encoding="utf-8",
    )
    return str(policy_path)


def test_replay_deterministic_report(tmp_path) -> None:
    db_path = tmp_path / "replay.db"
    uri = f"sqlite:///{db_path}"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)

    signal_bundle = {
        "signal_schema_version": "SE-0.2.0",
        "signal_scores": {
            "repetition_loopiness": 0.5,
            "novelty_entropy_proxy": 0.5,
            "coherence_structure": 0.5,
            "context_adherence": 0.5,
            "hallucination_risk": 0.5,
        },
        "derived_signals": {
            "fatigue_risk_index": 0.0,
            "fatigue_risk_25t": 0.0,
            "fatigue_risk_50t": 0.0,
            "low_conf_halluc": 0.0,
            "congestion_signature": 0.0,
        },
        "missing_inputs": [],
    }

    event = {
        "session_id": "session-1",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": signal_bundle,
        "gating_decision": "REFRESH",
        "decision_risk_score": 0.5,
        "trigger_signal": "hallucination_risk",
        "trust_logic_version": "TO-0.1.0",
        "policy_version": bundle.policy_version,
        "config_hash": bundle.config_hash,
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-replay-1",
        "replay_id": "replay-1",
        "severity": "yellow",
    }

    ok, message = events_sql.record_gating_event(uri_or_dsn=uri, event=event)
    assert ok, message

    events = read_events(uri, session_id="session-1")
    result_first = replay_engine.replay(events, bundle)
    result_second = replay_engine.replay(events, bundle)

    report_first = reporting.render_json(result_first.report)
    report_second = reporting.render_json(result_second.report)
    assert report_first == report_second
    assert report_first == json.dumps(
        result_first.report,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert result_first.report["summary"]["diff_count"] == 0
    assert len(result_first.diff_artifact["events"]) == 1
