import json
import sqlite3

import pytest

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


def test_labels_reject_forbidden_keys(tmp_path) -> None:
    labels_path = tmp_path / "labels.jsonl"
    labels_path.write_text(
        (
            '{"session_id":"s1","turn_index":1,"replay_id":"r1",'
            '"expected_decision":"ALLOW","prompt":"nope"}\n'
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        evaluation_labels.load_labels(str(labels_path))


def test_labels_reject_forbidden_content(tmp_path) -> None:
    labels_path = tmp_path / "labels_content.jsonl"
    labels_path.write_text(
        (
            '{"session_id":"s1","turn_index":1,"replay_id":"r1",'
            '"expected_decision":"ALLOW","actual_failure_type":"prompt: leak"}\n'
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        evaluation_labels.load_labels(str(labels_path))


def test_replay_flags_malformed_signal_bundle(tmp_path) -> None:
    db_path = tmp_path / "poisoned.db"
    uri = f"sqlite:///{db_path}"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            (
                "INSERT INTO events (session_id,turn_index,timestamp,signal_bundle,"
                "gating_decision,decision_risk_score,trigger_signal,trust_logic_version,"
                "policy_version,config_hash,code_fingerprint,prompt_type,response_hash,"
                "replay_id,event_type,event_severity) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            ),
            (
                "session-poison",
                1,
                "2025-01-01T00:00:00Z",
                "{not-json",
                "ALLOW",
                0.1,
                "repetition_loopiness",
                "TO-0.1.0",
                bundle.policy_version,
                bundle.config_hash,
                "fp",
                "qa",
                "hash-poison-1",
                "replay-1",
                "gating_decision",
                "green",
            ),
        )
        conn.commit()

    events = read_events(uri, session_id="session-poison")
    result = replay_engine.replay(events, bundle)
    summary = result.report["summary"]
    assert summary["bundle_errors"] == 1
    assert summary["diff_count"] == 1
    assert summary["replayed_count"] == 0


def test_signal_bundle_rejects_forbidden_keys() -> None:
    uri = "sqlite:///:memory:"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    event = {
        "session_id": "session-guard",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {
            "prompt": "do not store",
        },
        "gating_decision": "ALLOW",
        "decision_risk_score": 0.1,
        "trigger_signal": "repetition_loopiness",
        "trust_logic_version": "TO-0.1.0",
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash-guard-1",
        "severity": "green",
    }
    ok, message = events_sql.record_gating_event(uri_or_dsn=uri, event=event)
    assert ok is False
    assert "forbidden" in message.lower()


def test_replay_dedupes_duplicate_events(tmp_path) -> None:
    db_path = tmp_path / "dupes.db"
    uri = f"sqlite:///{db_path}"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)

    signal_bundle = json.dumps(
        {
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
        sort_keys=True,
        separators=(",", ":"),
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP INDEX events_session_turn_response_event_type_unique")
        conn.execute(
            (
                "INSERT INTO events (session_id,turn_index,timestamp,signal_bundle,"
                "gating_decision,decision_risk_score,trigger_signal,trust_logic_version,"
                "policy_version,config_hash,code_fingerprint,prompt_type,response_hash,"
                "replay_id,event_type,event_severity) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            ),
            (
                "session-dupe",
                1,
                "2025-01-02T00:00:00Z",
                signal_bundle,
                "ALLOW",
                0.2,
                "repetition_loopiness",
                "TO-0.1.0",
                bundle.policy_version,
                bundle.config_hash,
                "fp",
                "qa",
                "hash-dupe-1",
                "replay-1",
                "gating_decision",
                "green",
            ),
        )
        conn.execute(
            (
                "INSERT INTO events (session_id,turn_index,timestamp,signal_bundle,"
                "gating_decision,decision_risk_score,trigger_signal,trust_logic_version,"
                "policy_version,config_hash,code_fingerprint,prompt_type,response_hash,"
                "replay_id,event_type,event_severity) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            ),
            (
                "session-dupe",
                1,
                "2025-01-01T00:00:00Z",
                signal_bundle,
                "BLOCK",
                0.9,
                "hallucination_risk",
                "TO-0.1.0",
                bundle.policy_version,
                bundle.config_hash,
                "fp",
                "qa",
                "hash-dupe-1",
                "replay-1",
                "gating_decision",
                "red",
            ),
        )
        conn.commit()

    events = read_events(uri, session_id="session-dupe")
    result = replay_engine.replay(events, bundle)
    assert result.report["summary"]["event_count"] == 1
    stored_decision = result.diff_artifact["events"][0]["stored"]["gating_decision"]
    assert stored_decision == "ALLOW"


def test_replay_flags_missing_identifiers(tmp_path) -> None:
    db_path = tmp_path / "identifiers.db"
    uri = f"sqlite:///{db_path}"
    ok, message = sql_init.init_schema(uri)
    assert ok, message

    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            (
                "INSERT INTO events (session_id,turn_index,timestamp,signal_bundle,"
                "gating_decision,decision_risk_score,trigger_signal,trust_logic_version,"
                "policy_version,config_hash,code_fingerprint,prompt_type,response_hash,"
                "replay_id,event_type,event_severity) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            ),
            (
                "session-bad",
                2,
                "2025-01-01T00:00:00Z",
                '{"signal_schema_version":"SE-0.2.0","signal_scores":{},"derived_signals":{},"missing_inputs":[]}',
                "ALLOW",
                0.1,
                "repetition_loopiness",
                "TO-0.1.0",
                bundle.policy_version,
                bundle.config_hash,
                "fp",
                "qa",
                None,
                "replay-1",
                "gating_decision",
                "green",
            ),
        )
        conn.commit()

    events = read_events(uri, session_id="session-bad")
    result = replay_engine.replay(events, bundle)
    summary = result.report["summary"]
    assert summary["identifier_errors"] == 1
    assert summary["diff_count"] == 1
