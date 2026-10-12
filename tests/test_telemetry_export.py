import hashlib
import json
import math
import socket
import sqlite3
from pathlib import Path

import pytest

from lionlock.core import gating
from lionlock.core.gating import REASON_CODE_MAP, evaluate_policy
from lionlock.core.scoring import SIGNAL_SCHEMA_VERSION, score_response
from lionlock.logging.event_log import build_connector_error_event, build_signal_event, log_event
from lionlock.telemetry import policy
from lionlock.telemetry import store as store_module
from lionlock.telemetry.export import export_all, export_snapshot, pending_snapshots
from lionlock.telemetry.snapshot import (
    EVENT_COLUMNS,
    SnapshotError,
    validate_snapshot,
    write_snapshot,
)
from lionlock.telemetry.store import LogStore
from lionlock.trust_overlay.config import TRUST_LOGIC_VERSION_DEFAULT, resolve_runtime_mode
from lionlock.trust_overlay.logger import append_trust_record, build_trust_record
from lionlock.versioning import get_lionlock_version

FIXED_INSTALL_ID = "0123456789abcdef0123456789abcdef"
FIXED_EXPORT_KEY = "11" * 32

CANARIES = {
    "request_id": "canary-request-7f3a9c",
    "session_id": "canary-session-alice@example.com",
    "model_id": "canary-acmecorp-llama-legal-ft",
    "user_id": "canary-user-bob-42",
    "response_text": "canary response about quarterly revenue",
    "stop": "canary-stop-sequence",
    "note": "canary-debug-note",
    "base_url": "http://canary-internal-host.example",
    "salt": "canary-salt-value",
}


def _config(tmp_path: Path) -> dict:
    return {
        "logging": {
            "enabled": True,
            "backend": "sqlite",
            "sqlite_path": str(tmp_path / "lionlock.db"),
            "verbosity": "debug",
            "notes_allowlist": ["note"],
        },
        "logging_sql": {"enabled": False},
        "trust_overlay": {"salt": CANARIES["salt"]},
    }


def _set_identity(path: Path, export_key: str = FIXED_EXPORT_KEY) -> None:
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO log_meta (key, value) VALUES (?, ?)",
            [("install_id", FIXED_INSTALL_ID), ("export_key", export_key)],
        )


def _log_session(config: dict, tmp_path: Path, turns: int = 3) -> None:
    bundle = score_response(
        "Summarize the incident report.", "The service recovered after a restart.", {}
    )
    decision = evaluate_policy(bundle)
    for turn in range(turns):
        timestamp = f"2026-09-27T14:{10 + turn:02d}:33Z"
        event = build_signal_event(
            timestamp_utc=timestamp,
            request_id=f"{CANARIES['request_id']}-{turn}",
            base_url=CANARIES["base_url"],
            model=CANARIES["model_id"],
            decision=decision.gating_decision,
            severity=decision.severity,
            reason_code=decision.reason_code,
            aggregate_score=decision.decision_risk_score,
            signal_scores=decision.signal_scores,
            duration_ms=250 + turn,
            config_hash="c" * 64,
            notes={"note": CANARIES["note"]},
            signal_bundle=decision.signal_bundle,
        )
        log_event(event, config)
        record = build_trust_record(
            session_id=CANARIES["session_id"],
            turn_index=turn,
            model_id=CANARIES["model_id"],
            prompt_type="qa",
            derived_signals=bundle.derived_signals,
            aggregate_score=decision.decision_risk_score,
            response_text=CANARIES["response_text"],
            response_hash=None,
            score_history=[0.5, 0.6],
            timestamps=["2026-09-27T13:00:00Z", "2026-09-27T13:30:00Z"],
            config=config,
            user_id=CANARIES["user_id"],
            model_config_snapshot={
                "model_id": CANARIES["model_id"],
                "temperature": 0.2,
                "max_tokens": 512,
                "stop": [CANARIES["stop"]],
                "seed": 7,
            },
            timestamp_utc=timestamp,
        )
        append_trust_record(record, base_dir=tmp_path / "overlay", config=config)


def test_no_sensitive_value_survives_export(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _log_session(config, tmp_path)
    local_bytes = (tmp_path / "lionlock.db").read_bytes()
    # The canaries really did reach the local log, so the export check below is meaningful.
    for key in ("request_id", "session_id", "model_id", "note"):
        assert CANARIES[key].encode() in local_bytes

    result = export_snapshot(LogStore(tmp_path / "lionlock.db"), tmp_path / "outbox")
    assert result is not None
    exported = result.path.read_bytes()
    for key, canary in CANARIES.items():
        assert canary.encode() not in exported, f"{key} leaked into the snapshot"
    hostname_hash = hashlib.sha256(socket.gethostname().encode()).hexdigest()
    response_hash = hashlib.sha256(CANARIES["response_text"].encode()).hexdigest()
    for forbidden in (hostname_hash, response_hash, "response_hash", "pseudonymous", "host_id"):
        assert forbidden.encode() not in exported

    info = validate_snapshot(result.path)
    trust = info.rows["trust_records"]
    assert {row[4] for row in trust} == {"llama"}
    export_key = LogStore(tmp_path / "lionlock.db").identity().export_key
    expected_key = policy.rekey(export_key, "session", CANARIES["session_id"])
    assert {row[2] for row in trust} == {expected_key}
    assert info.rows["events"][0][1] == "2026-09-27T14:00:00Z"


def test_export_is_deterministic_for_identical_inputs(tmp_path: Path) -> None:
    results = []
    for name in ("first", "second"):
        directory = tmp_path / name
        config = _config(directory)
        _log_session(config, directory)
        _set_identity(directory / "lionlock.db")
        results.append(export_snapshot(LogStore(directory / "lionlock.db"), directory / "outbox"))
    first, second = results
    assert first is not None and second is not None
    assert first.content_digest == second.content_digest
    assert first.path.read_bytes() == second.path.read_bytes()

    third_dir = tmp_path / "third"
    config = _config(third_dir)
    _log_session(config, third_dir)
    _set_identity(third_dir / "lionlock.db", export_key="22" * 32)
    third = export_snapshot(LogStore(third_dir / "lionlock.db"), third_dir / "outbox")
    assert third is not None
    assert third.content_digest != first.content_digest


def test_segments_chain_and_watermarks_advance(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = LogStore(tmp_path / "lionlock.db")
    _log_session(config, tmp_path, turns=2)
    first = export_snapshot(store, tmp_path / "outbox")
    assert first is not None and first.segment_index == 1
    assert export_snapshot(store, tmp_path / "outbox") is None

    _log_session(config, tmp_path, turns=5)
    later = export_all(store, tmp_path / "outbox", rows_per_snapshot=2)
    assert [result.segment_index for result in later] == [2, 3, 4]
    metas = [validate_snapshot(result.path).meta for result in [first, *later]]
    for previous, current in zip(metas, metas[1:]):
        assert current["prev_segment_digest"] == previous["content_digest"]
    assert sum(int(meta["events_rows"]) for meta in metas) == 7
    assert [path.name for path in pending_snapshots(tmp_path / "outbox")] == [
        result.path.name for result in [first, *later]
    ]


def test_rows_pruned_before_export_are_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(store_module, "PRUNE_CHECK_INTERVAL", 2)
    store = LogStore(tmp_path / "lionlock.db", max_rows=2)
    for turn in range(8):
        store.append_event({"timestamp_utc": "2026-09-27T10:00:00Z", "decision": "ALLOW"})
    result = export_snapshot(store, tmp_path / "outbox")
    assert result is not None
    meta = validate_snapshot(result.path).meta
    assert int(meta["events_pruned_before_export"]) > 0
    assert int(meta["events_rows"]) + int(meta["events_pruned_before_export"]) == 8


def test_reset_identity_unlinks_future_uploads(tmp_path: Path) -> None:
    config = _config(tmp_path)
    store = LogStore(tmp_path / "lionlock.db")
    _log_session(config, tmp_path, turns=1)
    before = validate_snapshot(export_snapshot(store, tmp_path / "outbox").path)
    old_identity = store.identity()

    new_identity = store.reset_identity()
    _log_session(config, tmp_path, turns=1)
    after = validate_snapshot(export_snapshot(store, tmp_path / "outbox").path)

    assert new_identity.install_id != old_identity.install_id
    assert after.install_id == new_identity.install_id
    assert after.segment_index == 1 and after.meta["prev_segment_digest"] == ""
    assert after.rows["events"][0][0] == 1
    assert int(after.meta["events_rows"]) == 1
    # Same raw session id, different pseudonym once the key has rotated.
    assert after.rows["trust_records"][0][2] != before.rows["trust_records"][0][2]


def test_snapshot_rows_that_violate_policy_are_rejected(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _log_session(config, tmp_path, turns=1)
    result = export_snapshot(LogStore(tmp_path / "lionlock.db"), tmp_path / "outbox")
    info = validate_snapshot(result.path)
    trust_row = list(info.rows["trust_records"][0])
    trust_row[2] = CANARIES["session_id"]
    forged = tmp_path / "forged.db"
    meta = {key: value for key, value in info.meta.items() if key != "content_digest"}
    write_snapshot(
        forged, meta, {"events": info.rows["events"], "trust_records": [tuple(trust_row)]}
    )
    with pytest.raises(SnapshotError, match="violates the export policy"):
        validate_snapshot(forged)


@pytest.mark.parametrize(
    ("model_id", "family"),
    [
        ("llama3.1:8b", "llama"),
        ("meta-llama/Llama-3.1-8B-Instruct", "llama"),
        ("codellama:7b", "llama"),
        ("gpt-4o-mini", "gpt-4o"),
        ("us.vendor.claude-example-model-v1:0", "claude"),
        ("mistral-nemo", "mistral"),
        ("qwen2.5-coder:14b", "qwen"),
        ("phi3:mini", "phi"),
        ("acme-delphi-legal-v2", "other"),
        ("acmecorp-private-model", "other"),
        ("", "unknown"),
        (None, "unknown"),
        ("llama", "llama"),
        ("openai-o", "openai-o"),
    ],
)
def test_model_ids_are_reduced_to_public_families(model_id, family) -> None:
    assert policy.model_family(model_id) == family


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-27T14:37:12Z", "2026-09-27T14:00:00Z"),
        ("2026-09-27T14:37:12.123456+02:00", "2026-09-27T12:00:00Z"),
        ("2026-09-27T14:00:00Z", "2026-09-27T14:00:00Z"),
        ("not a timestamp", None),
        ("", None),
        (1234567890, None),
    ],
)
def test_timestamps_are_truncated_to_the_utc_hour(value, expected) -> None:
    assert policy.hour_bucket(value) == expected


def test_rekey_is_deterministic_and_key_dependent() -> None:
    first = policy.rekey("11" * 32, "session", "abc")
    assert first == policy.rekey("11" * 32, "session", "abc")
    assert first != policy.rekey("22" * 32, "session", "abc")
    assert first != policy.rekey("11" * 32, "request", "abc")
    assert len(first) == 32


@pytest.mark.parametrize(
    "value",
    [
        {"signal_scores": {"repetition_loopiness": 0.5, "prompt": "leak"}, "missing_inputs": ["x"]},
        {"signal_schema_version": "SE 0.2.0\nprompt: leak", "derived_signals": {"a": math.nan}},
        {
            "signal_scores": {"coherence_structure": 7},
            "missing_inputs": ["turn_index", "turn_index"],
        },
        "not a mapping",
    ],
)
def test_signal_bundle_policy_is_idempotent(value) -> None:
    once = policy.signal_bundle(value)
    assert policy.signal_bundle(once) == once
    assert "leak" not in json.dumps(once)


def test_trust_detail_policy_is_idempotent_and_drops_free_text() -> None:
    detail = policy.trust_detail(
        {
            "model_params": {"temperature": 0.7, "stop": ["secret"], "seed": 3},
            "signal_summary": {"overall_risk": 0.4, "notes": "free text", "components": {"x": 1}},
            "drift": {"drift_detected": True, "method": "made-up", "delta": -0.2},
            "runtime_mode": "Mixed Case With Spaces",
            "extra": "dropped",
        }
    )
    assert policy.trust_detail(detail) == detail
    text = json.dumps(detail)
    for dropped in ("secret", "free text", "made-up", "Mixed", "extra", "seed"):
        assert dropped not in text


def test_public_label_sets_match_the_values_the_code_emits() -> None:
    connector_error = build_connector_error_event(
        timestamp_utc="2026-09-27T10:00:00Z",
        request_id="r",
        base_url="http://localhost",
        model="m",
        duration_ms=None,
        config_hash="c" * 64,
    )["reason_code"]
    emitted = set(REASON_CODE_MAP.values())
    emitted |= {gating._reason_code_for("not_a_known_signal"), connector_error}
    assert set(policy.REASON_CODES) == emitted
    assert len(policy.REASON_CODES) == len(set(policy.REASON_CODES))
    assert policy.SIGNAL_SCHEMA_VERSIONS[-1] == SIGNAL_SCHEMA_VERSION
    assert policy.TRUST_LOGIC_VERSIONS == (TRUST_LOGIC_VERSION_DEFAULT,)
    assert policy.RUNTIME_MODES == (resolve_runtime_mode(None),)
    installed = get_lionlock_version({})
    assert policy.package_version_label(installed) == installed


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0.1.0", "0.1.0"),
        ("unknown", "unknown"),
        ("31.41.5926", "unknown"),
        ("1.2.3rc1", "unknown"),
        ("2.0.0.dev3", "unknown"),
        ("1.0.0.post1", "unknown"),
        ("0.0.0-dev", "unknown"),
        ("0.1.0+acme.internal", "unknown"),
        ("acme-1.0", "unknown"),
        ("SyntheticPrivate-Orion", "unknown"),
        ("1", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_package_versions_are_published_releases_only(value, expected) -> None:
    assert policy.package_version_label(value) == expected
    assert policy.package_version_label(expected) == expected


def test_unrecognized_labels_become_neutral_and_stay_idempotent() -> None:
    row = policy.event_row(
        seq=1,
        ts=None,
        decision="ALLOW",
        severity="green",
        reason_code="acme_customer_reason",
        aggregate_score=0.1,
        scores={},
        bundle={"signal_schema_version": "SE-9.9.9"},
        duration_ms=None,
        config_hash=None,
    )
    assert row is not None
    assert row[EVENT_COLUMNS.index("reason_code")] is None
    bundle = json.loads(row[EVENT_COLUMNS.index("signal_bundle_json")])
    assert bundle["signal_schema_version"] == "unknown"
    assert policy.signal_bundle(bundle) == bundle
    detail = policy.trust_detail(
        {"runtime_mode": "acme_workspace", "trust_logic_version": "TO-9.9"}
    )
    assert "runtime_mode" not in detail and "trust_logic_version" not in detail
    assert policy.trust_detail(detail) == detail
