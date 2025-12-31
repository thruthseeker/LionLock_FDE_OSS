from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable

ANOMALY_TYPES = {
    "fatigue_spike",
    "hallucination_jump",
    "minor_signal_drift",
    "prompt_injection_suspected",
    "gate_mismatch",
    "model_degradation",
    "model_congestion",
    "missed_signal_event",
}

REQUIRED_FIELDS = {
    "anomaly_type",
    "severity",
    "details",
    "session_id",
    "turn_index",
    "timestamp",
    "trust_logic_version",
    "code_fingerprint",
}

ALLOWED_FIELDS = {
    "anomaly_type",
    "severity",
    "details",
    "session_id",
    "turn_index",
    "timestamp",
    "trust_logic_version",
    "code_fingerprint",
    "prompt_type",
    "response_hash",
    "related_request_id",
}

# REFRESH is canonical; WARN remains a legacy alias for compatibility.
ALLOWED_DECISIONS = {"ALLOW", "REFRESH", "WARN", "BLOCK", "UNKNOWN"}
ALLOWED_MISS_REASONS = {"threshold", "masking", "conflict"}
ALLOWED_PROMPT_TYPES = {"qa", "code", "creative", "other", "unknown"}

EXACT_BANNED_KEYS = {
    "assistant_response",
    "completion",
    "content",
    "device_id",
    "input",
    "ip",
    "messages",
    "output",
    "payload_b64",
    "prompt",
    "prompt_text",
    "raw_messages",
    "raw_text",
    "response",
    "response_text",
    "system_prompt",
    "tool_calls",
    "user_id",
    "user_prompt",
}


@dataclass(frozen=True)
class AnomalyEvent:
    anomaly_type: str
    severity: float
    details: Dict[str, Any]
    session_id: str
    turn_index: int
    timestamp: str
    trust_logic_version: str
    code_fingerprint: str
    prompt_type: str | None = None
    response_hash: str | None = None
    related_request_id: str | None = None

    def as_dict(self) -> Dict[str, Any]:
        data = {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "details": self.details,
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "timestamp": self.timestamp,
            "trust_logic_version": self.trust_logic_version,
            "code_fingerprint": self.code_fingerprint,
        }
        if self.prompt_type is not None:
            data["prompt_type"] = self.prompt_type
        if self.response_hash is not None:
            data["response_hash"] = self.response_hash
        if self.related_request_id is not None:
            data["related_request_id"] = self.related_request_id
        return data


def _is_banned_key(key: str) -> bool:
    return key.lower() in EXACT_BANNED_KEYS


def _sanitize_nested(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for key, item in value.items():
            if _is_banned_key(key):
                continue
            cleaned[key] = _sanitize_nested(item)
        return cleaned
    if isinstance(value, list):
        return [_sanitize_nested(item) for item in value]
    return value


def sanitize_event(record: Dict[str, Any]) -> Dict[str, Any]:
    filtered = {key: record[key] for key in ALLOWED_FIELDS if key in record}
    details = filtered.get("details")
    if isinstance(details, dict):
        filtered["details"] = _sanitize_nested(details)
    return filtered


def contains_banned_keys(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_banned_key(key):
                return True
            if contains_banned_keys(item):
                return True
    elif isinstance(value, list):
        return any(contains_banned_keys(item) for item in value)
    return False


def normalize_prompt_type(prompt_type: str | None) -> str:
    if not prompt_type:
        return "unknown"
    lowered = str(prompt_type).strip().lower()
    if lowered in ALLOWED_PROMPT_TYPES:
        return lowered
    return "other"


def validate_anomaly_event(record: Dict[str, Any]) -> None:
    missing = [field for field in REQUIRED_FIELDS if field not in record]
    if missing:
        raise ValueError(f"AnomalyEvent missing required fields: {sorted(missing)}")
    if contains_banned_keys(record):
        raise ValueError("AnomalyEvent contains banned keys")

    anomaly_type = record.get("anomaly_type")
    if anomaly_type not in ANOMALY_TYPES:
        raise ValueError("anomaly_type invalid")

    severity = record.get("severity")
    if not isinstance(severity, (int, float)):
        raise ValueError("severity must be numeric")
    if not 0.0 <= float(severity) <= 1.0:
        raise ValueError("severity out of bounds")

    details = record.get("details")
    if not isinstance(details, dict):
        raise ValueError("details must be a dict")
    if contains_banned_keys(details):
        raise ValueError("details contains banned keys")

    session_id = record.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session_id must be non-empty str")

    turn_index = record.get("turn_index")
    if not isinstance(turn_index, int) or turn_index < 0:
        raise ValueError("turn_index must be non-negative int")

    timestamp = record.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError("timestamp must be str")

    trust_logic_version = record.get("trust_logic_version")
    if not isinstance(trust_logic_version, str) or not trust_logic_version:
        raise ValueError("trust_logic_version must be str")

    code_fingerprint = record.get("code_fingerprint")
    if not isinstance(code_fingerprint, str) or not code_fingerprint:
        raise ValueError("code_fingerprint must be str")

    prompt_type = record.get("prompt_type")
    if prompt_type is not None and prompt_type not in ALLOWED_PROMPT_TYPES:
        raise ValueError("prompt_type invalid")

    response_hash = record.get("response_hash")
    if response_hash is not None and not isinstance(response_hash, str):
        raise ValueError("response_hash must be str when provided")

    related_request_id = record.get("related_request_id")
    if related_request_id is not None and not isinstance(related_request_id, str):
        raise ValueError("related_request_id must be str when provided")

    if anomaly_type == "missed_signal_event":
        for key in ("expected_decision", "actual_decision", "miss_reason", "response_hash"):
            if key not in details:
                raise ValueError(f"missed_signal_event details missing {key}")
        expected = details.get("expected_decision")
        actual = details.get("actual_decision")
        miss_reason = details.get("miss_reason")
        if expected not in ALLOWED_DECISIONS:
            raise ValueError("expected_decision invalid")
        if actual not in ALLOWED_DECISIONS:
            raise ValueError("actual_decision invalid")
        if miss_reason not in ALLOWED_MISS_REASONS:
            raise ValueError("miss_reason invalid")
