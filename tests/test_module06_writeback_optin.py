from lionlock.logging import events_sql, missed_signal_sql, sql_init
from lionlock.replay import cli, policy_registry


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


def _seed_event(tmp_path):
    db_path = tmp_path / "writeback.db"
    uri = f"sqlite:///{db_path}"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)

    event = {
        "session_id": "session-3",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {
            "signal_schema_version": "SE-0.2.0",
            "signal_scores": {
                "repetition_loopiness": 0.2,
                "novelty_entropy_proxy": 0.2,
                "coherence_structure": 0.2,
                "context_adherence": 0.2,
                "hallucination_risk": 0.2,
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
        "decision_risk_score": 0.2,
        "trigger_signal": "repetition_loopiness",
        "trust_logic_version": "TO-0.1.0",
        "policy_version": bundle.policy_version,
        "config_hash": bundle.config_hash,
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-writeback-1",
        "replay_id": "replay-1",
        "severity": "green",
    }
    ok, message = events_sql.record_gating_event(uri_or_dsn=uri, event=event)
    assert ok, message

    labels_path = tmp_path / "labels.jsonl"
    labels_path.write_text(
        (
            '{"session_id":"session-3","turn_index":1,'
            '"replay_id":"replay-1","expected_decision":"BLOCK"}\n'
        ),
        encoding="utf-8",
    )
    return uri, registry_path, str(labels_path)


def test_writeback_requires_ack(tmp_path, monkeypatch) -> None:
    uri, registry_path, labels_path = _seed_event(tmp_path)
    calls = []

    def _fake_record(*, uri_or_dsn, record, schema="public"):
        calls.append(record)
        return True, "ok"

    monkeypatch.setattr(missed_signal_sql, "record_missed_signal_event", _fake_record)
    exit_code = cli.run(
        [
            "--db",
            uri,
            "--policy",
            "GC-0.3.1",
            "--policy-registry",
            registry_path,
            "--labels",
            labels_path,
            "--out",
            str(tmp_path / "out"),
            "--write-back",
        ]
    )
    assert exit_code == 2
    assert calls == []


def test_writeback_opt_in(tmp_path, monkeypatch) -> None:
    uri, registry_path, labels_path = _seed_event(tmp_path)
    calls = []

    def _fake_record(*, uri_or_dsn, record, schema="public"):
        calls.append(record)
        return True, "ok"

    monkeypatch.setattr(missed_signal_sql, "record_missed_signal_event", _fake_record)
    exit_code = cli.run(
        [
            "--db",
            uri,
            "--policy",
            "GC-0.3.1",
            "--policy-registry",
            registry_path,
            "--labels",
            labels_path,
            "--out",
            str(tmp_path / "out"),
            "--write-back",
            "--i-understand-write-back",
        ]
    )
    assert exit_code == 0
    assert len(calls) == 1


def test_no_writeback_no_mutation(tmp_path, monkeypatch) -> None:
    uri, registry_path, labels_path = _seed_event(tmp_path)
    calls = []

    def _fake_record(*, uri_or_dsn, record, schema="public"):
        calls.append(record)
        return True, "ok"

    monkeypatch.setattr(missed_signal_sql, "record_missed_signal_event", _fake_record)
    exit_code = cli.run(
        [
            "--db",
            uri,
            "--policy",
            "GC-0.3.1",
            "--policy-registry",
            registry_path,
            "--labels",
            labels_path,
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert exit_code == 0
    assert calls == []
