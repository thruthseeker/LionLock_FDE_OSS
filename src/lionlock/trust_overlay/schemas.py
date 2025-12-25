from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable

from .config import DEFAULT_PROFILE, PROFILE_THRESHOLDS, resolve_profile

EXACT_BANNED_KEYS = {
    "assistant_response",
    "content",
    "device_id",
    "input",
    "ip",
    "output",
    "payload_b64",
    "prompt",
    "prompt_text",
    "raw_prompt",
    "raw_text",
    "response",
    "response_text",
    "raw_response",
    "system_prompt",
    "tool_calls",
    "user_id",
    "user_prompt",
    "messages",
    "raw_messages",
    "completion",
}

ALLOWED_FIELDS = {
    "trust_logic_version",
    "code_fingerprint",
    "timestamp",
    "session_id",
    "turn_index",
    "model_id",
    "trust_score",
    "trust_label",
    "confidence_band",
    "volatility",
    "drift",
    "badge",
    "prompt_type",
    "model_config_snapshot",
    "deployment_context_snapshot",
    "signal_summary",
    "trigger_flags",
    "response_hash",
    "pseudonymous_user_key",
}

REQUIRED_FIELDS = {
    "trust_logic_version",
    "code_fingerprint",
    "timestamp",
    "session_id",
    "turn_index",
    "model_id",
    "trust_score",
    "trust_label",
    "confidence_band",
    "volatility",
    "drift",
    "prompt_type",
    "model_config_snapshot",
    "deployment_context_snapshot",
    "signal_summary",
    "trigger_flags",
    "response_hash",
}

TOP_LEVEL_EXEMPT_KEYS = {"prompt_type", "response_hash"}

ALLOWED_PROMPT_TYPES = {"qa", "code", "creative", "other"}
ALLOWED_LABELS = {"TRUSTED", "MONITOR", "AT_RISK", "UNTRUSTED"}
ALLOWED_BADGES = {
    "INSUFFICIENT_DATA",
    "STABLE",
    "VOLATILE",
    "DRIFTING",
    "RECOVERING",
    "CLEAN_RUN",
}


@dataclass(frozen=True)
class TrustRecord:
    trust_logic_version: str
    code_fingerprint: str
    timestamp: str
    session_id: str
    turn_index: int | None
    model_id: str
    trust_score: float
    trust_label: str
    confidence_band: Dict[str, Any]
    volatility: float
    drift: Dict[str, Any]
    badge: str | None
    prompt_type: str
    model_config_snapshot: Dict[str, Any]
    deployment_context_snapshot: Dict[str, Any]
    signal_summary: Dict[str, Any]
    trigger_flags: list[str]
    response_hash: str | None
    pseudonymous_user_key: str | None = None

    def as_dict(self) -> Dict[str, Any]:
        data = {
            "trust_logic_version": self.trust_logic_version,
            "code_fingerprint": self.code_fingerprint,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "model_id": self.model_id,
            "trust_score": self.trust_score,
            "trust_label": self.trust_label,
            "confidence_band": self.confidence_band,
            "volatility": self.volatility,
            "drift": self.drift,
            "badge": self.badge,
            "prompt_type": self.prompt_type,
            "model_config_snapshot": self.model_config_snapshot,
            "deployment_context_snapshot": self.deployment_context_snapshot,
            "signal_summary": self.signal_summary,
            "trigger_flags": self.trigger_flags,
            "response_hash": self.response_hash,
        }
        if self.pseudonymous_user_key:
            data["pseudonymous_user_key"] = self.pseudonymous_user_key
        return data


def _is_banned_key(key: str, exempt: Iterable[str] | None = None) -> bool:
    lowered = key.lower()
    if exempt and lowered in {item.lower() for item in exempt}:
        return False
    return lowered in EXACT_BANNED_KEYS


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


def sanitize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    filtered = {key: record[key] for key in ALLOWED_FIELDS if key in record}
    for key in list(filtered):
        if _is_banned_key(key, exempt=TOP_LEVEL_EXEMPT_KEYS):
            filtered.pop(key)
    for key, value in list(filtered.items()):
        filtered[key] = _sanitize_nested(value)
    return filtered


def contains_banned_keys(value: Any, *, top_level: bool = False) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_banned_key(key, exempt=TOP_LEVEL_EXEMPT_KEYS if top_level else None):
                return True
            if contains_banned_keys(item, top_level=False):
                return True
    elif isinstance(value, list):
        return any(contains_banned_keys(item, top_level=False) for item in value)
    return False


def _require_fields(record: Dict[str, Any]) -> None:
    missing = [field for field in REQUIRED_FIELDS if field not in record]
    if missing:
        raise ValueError(f"TrustRecord missing required fields: {sorted(missing)}")


def _validate_signal_summary(signal_summary: Dict[str, Any]) -> None:
    if "overall_risk" not in signal_summary and "fatigue_score" not in signal_summary:
        raise ValueError("signal_summary missing overall_risk or fatigue_score")
    risk_key = "overall_risk" if "overall_risk" in signal_summary else "fatigue_score"
    risk_value = signal_summary.get(risk_key)
    if not isinstance(risk_value, (int, float)):
        raise ValueError("signal_summary risk value must be numeric")


def _validate_confidence_band(confidence_band: Dict[str, Any]) -> None:
    for key in ("lower", "upper", "method", "n", "std", "k"):
        if key not in confidence_band:
            raise ValueError(f"confidence_band missing {key}")


def _validate_drift(drift: Dict[str, Any]) -> None:
    for key in (
        "drift_detected",
        "method",
        "recent_mean",
        "baseline_mean",
        "delta",
        "threshold",
        "recent_n",
        "baseline_n",
    ):
        if key not in drift:
            raise ValueError(f"drift missing {key}")


def validate_trust_record(record: Dict[str, Any]) -> None:
    _require_fields(record)
    if contains_banned_keys(record, top_level=True):
        raise ValueError("TrustRecord contains banned keys")

    prompt_type = record.get("prompt_type")
    if prompt_type not in ALLOWED_PROMPT_TYPES:
        raise ValueError("prompt_type must be one of qa, code, creative, other")

    label = record.get("trust_label")
    if label not in ALLOWED_LABELS:
        raise ValueError("trust_label invalid")

    badge = record.get("badge")
    if badge is not None and badge not in ALLOWED_BADGES:
        raise ValueError("badge invalid")

    turn_index = record.get("turn_index")
    if turn_index is not None and not isinstance(turn_index, int):
        raise ValueError("turn_index must be int or null")

    trust_score = record.get("trust_score")
    if not isinstance(trust_score, (int, float)):
        raise ValueError("trust_score must be numeric")
    if not 0.0 <= float(trust_score) <= 1.0:
        raise ValueError("trust_score out of bounds")

    volatility = record.get("volatility")
    if not isinstance(volatility, (int, float)):
        raise ValueError("volatility must be numeric")

    response_hash = record.get("response_hash")
    if response_hash is not None and not isinstance(response_hash, str):
        raise ValueError("response_hash must be str or null")

    pseudonymous_user_key = record.get("pseudonymous_user_key")
    if pseudonymous_user_key is not None and not isinstance(pseudonymous_user_key, str):
        raise ValueError("pseudonymous_user_key must be str when provided")

    model_snapshot = record.get("model_config_snapshot")
    if not isinstance(model_snapshot, dict):
        raise ValueError("model_config_snapshot must be a dict")

    deployment_snapshot = record.get("deployment_context_snapshot")
    if not isinstance(deployment_snapshot, dict):
        raise ValueError("deployment_context_snapshot must be a dict")

    trigger_flags = record.get("trigger_flags")
    if not isinstance(trigger_flags, list) or not all(
        isinstance(item, str) for item in trigger_flags
    ):
        raise ValueError("trigger_flags must be list[str]")

    _validate_signal_summary(record.get("signal_summary", {}))
    _validate_confidence_band(record.get("confidence_band", {}))
    _validate_drift(record.get("drift", {}))


def signal_summary_from(
    derived_signals: Any,
    aggregate_score: float | None = None,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    components: Dict[str, Any] | None = None
    notes = None

    if hasattr(derived_signals, "as_dict"):
        try:
            components = derived_signals.as_dict()
        except Exception:
            components = None
    if isinstance(derived_signals, dict):
        if "overall_risk" in derived_signals:
            summary["overall_risk"] = derived_signals.get("overall_risk")
        elif "fatigue_score" in derived_signals:
            summary["fatigue_score"] = derived_signals.get("fatigue_score")
        if isinstance(derived_signals.get("components"), dict):
            components = derived_signals.get("components")
        if isinstance(derived_signals.get("notes"), str):
            notes = derived_signals.get("notes")
        if components is None and isinstance(derived_signals.get("signal_scores"), dict):
            components = derived_signals.get("signal_scores")

    if not summary:
        if aggregate_score is not None:
            summary["overall_risk"] = aggregate_score
        else:
            raise ValueError("derived signals missing overall_risk/fatigue_score")

    if components:
        summary["components"] = components
    if notes:
        summary["notes"] = notes
    _validate_signal_summary(summary)
    return summary


def label_for_profile(score: float, profile: str | None = None) -> str:
    profile = resolve_profile(profile or DEFAULT_PROFILE)
    thresholds = PROFILE_THRESHOLDS[profile]
    if score >= thresholds["TRUSTED"]:
        return "TRUSTED"
    if score >= thresholds["MONITOR"]:
        return "MONITOR"
    if score >= thresholds["AT_RISK"]:
        return "AT_RISK"
    return "UNTRUSTED"
