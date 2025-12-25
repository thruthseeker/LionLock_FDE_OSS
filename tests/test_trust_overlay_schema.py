import json
from pathlib import Path

import pytest

from lionlock.trust_overlay.schemas import (
    ALLOWED_BADGES,
    ALLOWED_FIELDS,
    ALLOWED_LABELS,
    ALLOWED_PROMPT_TYPES,
    REQUIRED_FIELDS,
    sanitize_record,
    validate_trust_record,
)


def _base_record() -> dict:
    return {
        "trust_logic_version": "TO-0.1.0",
        "code_fingerprint": "abc123",
        "timestamp": "2025-12-23T00:00:00Z",
        "session_id": "session-1",
        "turn_index": 1,
        "model_id": "model-1",
        "trust_score": 0.8,
        "trust_label": "TRUSTED",
        "confidence_band": {
            "lower": 0.7,
            "upper": 0.9,
            "method": "std-band",
            "n": 3,
            "std": 0.1,
            "k": 1.0,
        },
        "volatility": 0.05,
        "drift": {
            "drift_detected": False,
            "method": "two_window_mean",
            "recent_mean": 0.8,
            "baseline_mean": 0.82,
            "delta": -0.02,
            "threshold": -0.1,
            "recent_n": 20,
            "baseline_n": 80,
        },
        "badge": "STABLE",
        "prompt_type": "qa",
        "model_config_snapshot": {"model_id": "model-1"},
        "deployment_context_snapshot": {
            "trust_logic_version": "TO-0.1.0",
            "code_fingerprint": "abc123",
            "runtime_mode": "oss",
            "lionlock_version": "0.0.0-dev",
        },
        "signal_summary": {"overall_risk": 0.2},
        "trigger_flags": [],
        "response_hash": None,
    }


def test_schema_accepts_minimal_record() -> None:
    record = _base_record()
    validate_trust_record(record)


def test_schema_rejects_missing_signal_summary() -> None:
    record = _base_record()
    record["signal_summary"] = {}
    with pytest.raises(ValueError):
        validate_trust_record(record)


def test_schema_accepts_null_turn_index_and_badge() -> None:
    record = _base_record()
    record["turn_index"] = None
    record["badge"] = None
    validate_trust_record(record)


def test_prompt_type_and_response_hash_not_sanitized() -> None:
    record = _base_record()
    record["prompt_type"] = "code"
    record["response_hash"] = "abc123"
    sanitized = sanitize_record(record)
    assert "prompt_type" in sanitized
    assert "response_hash" in sanitized
    validate_trust_record(sanitized)


def test_schema_json_mirror_matches_code() -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "docs" / "trust_overlay_schema.json").read_text(encoding="utf-8"))
    properties = set(schema["properties"].keys())
    required = set(schema["required"])

    assert properties == set(ALLOWED_FIELDS)
    assert required == set(REQUIRED_FIELDS)

    badge_enum = {value for value in schema["properties"]["badge"]["enum"] if value is not None}
    assert badge_enum == set(ALLOWED_BADGES)
    assert set(schema["properties"]["prompt_type"]["enum"]) == set(ALLOWED_PROMPT_TYPES)
    assert set(schema["properties"]["trust_label"]["enum"]) == set(ALLOWED_LABELS)
