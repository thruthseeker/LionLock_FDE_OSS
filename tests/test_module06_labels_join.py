from lionlock.logging import events_sql, sql_init
from lionlock.replay import evaluation_labels, policy_registry, replay_engine
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


def test_labels_join_metrics(tmp_path) -> None:
    db_path = tmp_path / "labels.db"
    uri = f"sqlite:///{db_path}"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)

    event = {
        "session_id": "session-2",
        "turn_index": 3,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {
            "signal_schema_version": "SE-0.2.0",
            "signal_scores": {
                "repetition_loopiness": 0.1,
                "novelty_entropy_proxy": 0.1,
                "coherence_structure": 0.1,
                "context_adherence": 0.1,
                "hallucination_risk": 0.1,
            },
            "derived_signals": {
                "fatigue_risk_index": 0.0,
                "fatigue_risk_25t": 0.0,
                "fatigue_risk_50t": 0.0,
                "low_conf_halluc": 0.0,
                "congestion_signature": 0.0,
            },
            "missing_inputs": [],
        },
        "gating_decision": "ALLOW",
        "decision_risk_score": 0.1,
        "trigger_signal": "repetition_loopiness",
        "trust_logic_version": "TO-0.1.0",
        "policy_version": bundle.policy_version,
        "config_hash": bundle.config_hash,
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-label-1",
        "replay_id": "replay-9",
        "severity": "green",
    }
    ok, message = events_sql.record_gating_event(uri_or_dsn=uri, event=event)
    assert ok, message

    labels_path = tmp_path / "labels.jsonl"
    labels_path.write_text(
        (
            '{"session_id":"session-2","turn_index":3,'
            '"replay_id":"replay-9","expected_decision":"ALLOW"}\n'
        ),
        encoding="utf-8",
    )

    labels = evaluation_labels.load_labels(str(labels_path))
    events = read_events(uri, session_id="session-2")
    result = replay_engine.replay(events, bundle, labels=labels)
    label_summary = result.report["labels"]
    assert label_summary["total"] == 1
    assert label_summary["matches"] == 1
    assert label_summary["confusion"]["ALLOW"]["ALLOW"] == 1


def test_labels_optional_and_never_invented(tmp_path) -> None:
    db_path = tmp_path / "labels_optional.db"
    uri = f"sqlite:///{db_path}"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)

    event = {
        "session_id": "session-5",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {
            "signal_schema_version": "SE-0.2.0",
            "signal_scores": {
                "repetition_loopiness": 0.1,
                "novelty_entropy_proxy": 0.1,
                "coherence_structure": 0.1,
                "context_adherence": 0.1,
                "hallucination_risk": 0.1,
            },
            "derived_signals": {
                "fatigue_risk_index": 0.0,
                "fatigue_risk_25t": 0.0,
                "fatigue_risk_50t": 0.0,
                "low_conf_halluc": 0.0,
                "congestion_signature": 0.0,
            },
            "missing_inputs": [],
        },
        "gating_decision": "ALLOW",
        "decision_risk_score": 0.1,
        "trigger_signal": "repetition_loopiness",
        "trust_logic_version": "TO-0.1.0",
        "policy_version": bundle.policy_version,
        "config_hash": bundle.config_hash,
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-label-optional",
        "replay_id": "replay-10",
        "severity": "green",
    }
    ok, message = events_sql.record_gating_event(uri_or_dsn=uri, event=event)
    assert ok, message

    events = read_events(uri, session_id="session-5")
    result = replay_engine.replay(events, bundle)
    assert result.report["labels"] is None
    assert result.proposed_missed_signal_events == []
