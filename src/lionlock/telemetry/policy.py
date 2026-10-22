"""Export policy: exactly which values may leave the machine, and in what form.

Every value copied into an upload snapshot passes through a sanitizer in this module. They are
allowlists: anything not explicitly recognized is dropped or replaced with a neutral value, and
there is no path for free text, prompts, responses, hostnames, raw identifiers, or content hashes.

Each sanitizer is idempotent. The receiver re-runs the same policy over every uploaded row and
rejects the snapshot if the policy would change anything, so a modified client cannot smuggle
extra data through.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Tuple

from .canonical import canonical_json, finite_float

DECISIONS = ("ALLOW", "REFRESH", "BLOCK", "UNKNOWN", "ERROR")
SEVERITIES = ("green", "yellow", "orange", "red")
SIGNAL_KEYS = (
    "repetition_loopiness",
    "novelty_entropy_proxy",
    "coherence_structure",
    "context_adherence",
    "hallucination_risk",
)
DERIVED_KEYS = (
    "fatigue_risk_index",
    "fatigue_risk_25t",
    "fatigue_risk_50t",
    "low_conf_halluc",
    "congestion_signature",
)
MISSING_INPUT_KEYS = (
    "entropy_decay",
    "turn_index",
    "drift_slope",
    "duration_ms",
    "latency_window_stats",
)
PROMPT_TYPES = ("qa", "code", "creative", "other")
TRUST_LABELS = ("TRUSTED", "MONITOR", "AT_RISK", "UNTRUSTED", "UNKNOWN")
BADGES = ("INSUFFICIENT_DATA", "STABLE", "VOLATILE", "DRIFTING", "RECOVERING", "CLEAN_RUN")
TRIGGER_FLAGS = ("score_below_threshold", "drift_detected", "volatility_spike")
PLATFORMS = {"linux": "linux", "darwin": "macos", "windows": "windows", "freebsd": "freebsd"}

# Public label values. A private name can look like an identifier or a version string, so these
# fields are checked for membership, never for shape. tests/test_telemetry_export.py keeps each
# set equal to the constants the OSS code emits.
REASON_CODES = (
    "repetition_loop",
    "low_novelty",
    "low_coherence",
    "context_drift",
    "hallucination_risk",
    "fatigue_risk",
    "congestion_risk",
    "policy_violation",
    "connector_error",
)
SIGNAL_SCHEMA_VERSIONS = ("SE-0.2.0", "SE-0.3.0", "SE-0.4.0")
TRUST_LOGIC_VERSIONS = ("TO-0.1.0",)
RUNTIME_MODES = ("oss",)
# Published lionlock package versions: the values pyproject.toml has declared for a release
# (0.1.0, then 1.0.0b1 and 1.0.0b2, the public betas). A new release is added here in a reviewed
# change, never from logs, the environment or a received value.
PACKAGE_VERSIONS = ("0.1.0", "1.0.0b1", "1.0.0b2")
UNKNOWN_VERSION = "unknown"

MAX_DURATION_MS = 86_400_000
MAX_TURN_INDEX = 1_000_000_000

# Custom model names often embed customer or project names, so only the public family is kept.
# Rules are matched in order against the last path segment of the lowercased model id, and only
# where the pattern starts at a word boundary ("delphi" does not match "phi").
MODEL_FAMILY_RULES: Tuple[Tuple[str, str], ...] = (
    ("gpt-oss", "gpt-oss"),
    ("gpt-5", "gpt-5"),
    ("gpt-4o", "gpt-4o"),
    ("gpt-4", "gpt-4"),
    ("gpt-3.5", "gpt-3.5"),
    ("o1", "openai-o"),
    ("o3", "openai-o"),
    ("o4", "openai-o"),
    ("claude", "claude"),
    ("codellama", "llama"),
    ("llama", "llama"),
    ("mixtral", "mistral"),
    ("mistral", "mistral"),
    ("ministral", "mistral"),
    ("codestral", "mistral"),
    ("gemma", "gemma"),
    ("gemini", "gemini"),
    ("qwen", "qwen"),
    ("qwq", "qwen"),
    ("phi", "phi"),
    ("deepseek", "deepseek"),
    ("command", "command"),
    ("granite", "granite"),
    ("falcon", "falcon"),
    ("olmo", "olmo"),
    ("grok", "grok"),
    ("nemotron", "nemotron"),
)
MODEL_FAMILIES = frozenset({family for _, family in MODEL_FAMILY_RULES} | {"other", "unknown"})
_MODEL_FAMILY_PATTERNS = tuple(
    (re.compile(r"(?:^|[^a-z0-9])" + re.escape(pattern)), family)
    for pattern, family in MODEL_FAMILY_RULES
)

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Numeric release versions only (PEP 440 public form without local labels), so no name fits.


def rekey(export_key: str, namespace: str, value: str) -> str:
    """Keyed pseudonym for an identifier. Without ``export_key`` it cannot be reversed."""
    digest = hmac.new(
        bytes.fromhex(export_key), f"{namespace}\x00{value}".encode("utf-8"), hashlib.sha256
    )
    return digest.hexdigest()[:32]


def hour_bucket(value: Any) -> str | None:
    """ISO-8601 timestamp truncated to the UTC hour; anything unparseable becomes None."""
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        return None
    raw = value.strip()
    if raw[-1] in "Zz":
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        parsed = parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None
    if not 1970 <= parsed.year <= 9999:
        return None
    return parsed.strftime("%Y-%m-%dT%H:00:00Z")


def unit_interval(value: Any) -> float | None:
    number = finite_float(value)
    if number is None or not 0.0 <= number <= 1.0:
        return None
    return number


def bounded_float(value: Any, low: float, high: float) -> float | None:
    number = finite_float(value)
    if number is None or not low <= number <= high:
        return None
    return number


def bounded_int(value: Any, low: int, high: int) -> int | None:
    if value is None or isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def enum_or_none(value: Any, allowed: Tuple[str, ...]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def hex64_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and _HEX64.fullmatch(value) else None


def signal_schema_version(value: Any) -> str:
    """A public signal schema version, or ``unknown``; never a guess at the real version."""
    return value if enum_or_none(value, SIGNAL_SCHEMA_VERSIONS) else UNKNOWN_VERSION


def package_version_label(value: Any) -> str:
    """A published package version from ``PACKAGE_VERSIONS``, else ``unknown``.

    Membership, not shape: a private build number such as ``31.41.5926`` is as identifying as a
    name, so it becomes ``unknown`` too.
    """
    return value if enum_or_none(value, PACKAGE_VERSIONS) else UNKNOWN_VERSION


def platform_label(system: Any) -> str:
    return PLATFORMS.get(str(system or "").strip().lower(), "other")


def python_label(version: Any) -> str:
    parts = str(version or "").split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"{int(parts[0])}.{int(parts[1])}"
    return "unknown"


def model_family(model_id: Any) -> str:
    if not isinstance(model_id, str) or not model_id.strip():
        return "unknown"
    normalized = model_id.strip().lower()
    if normalized in MODEL_FAMILIES:
        return normalized
    segment = normalized.rsplit("/", 1)[-1]
    for pattern, family in _MODEL_FAMILY_PATTERNS:
        if pattern.search(segment):
            return family
    return "other"


def _flag(value: Any) -> int | None:
    if value is True or value == 1:
        return 1
    if value is False or value == 0:
        return 0
    return None


def _unit_map(value: Any, keys: Tuple[str, ...]) -> Dict[str, float]:
    if not isinstance(value, Mapping):
        return {}
    cleaned: Dict[str, float] = {}
    for key in keys:
        number = unit_interval(value.get(key))
        if number is not None:
            cleaned[key] = number
    return cleaned


def signal_scores(value: Any) -> Dict[str, float]:
    return _unit_map(value, SIGNAL_KEYS)


def signal_bundle(value: Any) -> Dict[str, Any] | None:
    """Numeric signal bundle, enough to replay a gating decision against another policy."""
    if not isinstance(value, Mapping):
        return None
    missing = value.get("missing_inputs")
    missing_inputs: List[str] = []
    if isinstance(missing, (list, tuple)):
        for item in missing:
            if item in MISSING_INPUT_KEYS and item not in missing_inputs:
                missing_inputs.append(item)
    return {
        "signal_schema_version": signal_schema_version(value.get("signal_schema_version")),
        "signal_scores": _unit_map(value.get("signal_scores"), SIGNAL_KEYS),
        "derived_signals": _unit_map(value.get("derived_signals"), DERIVED_KEYS),
        "missing_inputs": missing_inputs,
    }


def trigger_flags(value: Any) -> List[str]:
    if not isinstance(value, (list, tuple)):
        return []
    flags: List[str] = []
    for item in value:
        if item in TRIGGER_FLAGS and item not in flags:
            flags.append(item)
    return flags


def _confidence_band(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    cleaned: Dict[str, Any] = {}
    for key in ("lower", "upper"):
        number = unit_interval(value.get(key))
        if number is not None:
            cleaned[key] = number
    std = bounded_float(value.get("std"), 0.0, 1.0)
    if std is not None:
        cleaned["std"] = std
    k = bounded_float(value.get("k"), 0.0, 100.0)
    if k is not None:
        cleaned["k"] = k
    n = bounded_int(value.get("n"), 0, MAX_TURN_INDEX)
    if n is not None:
        cleaned["n"] = n
    if value.get("method") == "std-band":
        cleaned["method"] = "std-band"
    return cleaned


def _drift(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    cleaned: Dict[str, Any] = {}
    if isinstance(value.get("drift_detected"), bool):
        cleaned["drift_detected"] = value["drift_detected"]
    if value.get("method") == "two_window_mean":
        cleaned["method"] = "two_window_mean"
    for key in ("recent_mean", "baseline_mean"):
        number = unit_interval(value.get(key))
        if number is not None:
            cleaned[key] = number
    for key in ("delta", "threshold"):
        number = bounded_float(value.get(key), -1.0, 1.0)
        if number is not None:
            cleaned[key] = number
    for key in ("recent_n", "baseline_n"):
        count = bounded_int(value.get(key), 0, MAX_TURN_INDEX)
        if count is not None:
            cleaned[key] = count
    return cleaned


def _signal_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    cleaned: Dict[str, Any] = {}
    for key in ("overall_risk", "fatigue_score"):
        number = unit_interval(value.get(key))
        if number is not None:
            cleaned[key] = number
    components = _unit_map(value.get("components"), SIGNAL_KEYS + DERIVED_KEYS)
    if components:
        cleaned["components"] = components
    return cleaned


def _model_params(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    cleaned: Dict[str, Any] = {}
    temperature = bounded_float(value.get("temperature"), 0.0, 10.0)
    if temperature is not None:
        cleaned["temperature"] = temperature
    top_p = unit_interval(value.get("top_p"))
    if top_p is not None:
        cleaned["top_p"] = top_p
    max_tokens = bounded_int(value.get("max_tokens"), 0, 10_000_000)
    if max_tokens is not None:
        cleaned["max_tokens"] = max_tokens
    for key in ("frequency_penalty", "presence_penalty"):
        number = bounded_float(value.get(key), -10.0, 10.0)
        if number is not None:
            cleaned[key] = number
    if isinstance(value.get("tool_calling_enabled"), bool):
        cleaned["tool_calling_enabled"] = value["tool_calling_enabled"]
    return cleaned


def trust_detail(value: Any) -> Dict[str, Any]:
    """Allowlisted nested Trust Overlay fields, in snapshot shape."""
    if not isinstance(value, Mapping):
        value = {}
    detail: Dict[str, Any] = {
        "confidence_band": _confidence_band(value.get("confidence_band")),
        "drift": _drift(value.get("drift")),
        "signal_summary": _signal_summary(value.get("signal_summary")),
        "model_params": _model_params(value.get("model_params")),
    }
    trust_logic_version = enum_or_none(value.get("trust_logic_version"), TRUST_LOGIC_VERSIONS)
    if trust_logic_version is not None:
        detail["trust_logic_version"] = trust_logic_version
    fingerprint = hex64_or_none(value.get("code_fingerprint"))
    if fingerprint is not None:
        detail["code_fingerprint"] = fingerprint
    runtime_mode = enum_or_none(value.get("runtime_mode"), RUNTIME_MODES)
    if runtime_mode is not None:
        detail["runtime_mode"] = runtime_mode
    return detail


def trust_detail_from_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Pick the nested fields of a full Trust Overlay record, then apply ``trust_detail``."""
    deployment = record.get("deployment_context_snapshot")
    deployment = deployment if isinstance(deployment, Mapping) else {}
    return trust_detail(
        {
            "confidence_band": record.get("confidence_band"),
            "drift": record.get("drift"),
            "signal_summary": record.get("signal_summary"),
            "model_params": record.get("model_config_snapshot"),
            "trust_logic_version": record.get("trust_logic_version"),
            "code_fingerprint": record.get("code_fingerprint"),
            "runtime_mode": deployment.get("runtime_mode"),
        }
    )


def event_row(
    *,
    seq: Any,
    ts: Any,
    decision: Any,
    severity: Any,
    reason_code: Any,
    aggregate_score: Any,
    scores: Any,
    bundle: Any,
    duration_ms: Any,
    config_hash: Any,
) -> Tuple[Any, ...] | None:
    """One ``events`` snapshot row, in ``snapshot.EVENT_COLUMNS`` order."""
    seq_value = bounded_int(seq, 1, 2**62)
    if seq_value is None:
        return None
    sanitized_bundle = signal_bundle(bundle)
    return (
        seq_value,
        hour_bucket(ts),
        decision if decision in DECISIONS else "UNKNOWN",
        enum_or_none(severity, SEVERITIES),
        enum_or_none(reason_code, REASON_CODES),
        unit_interval(aggregate_score),
        canonical_json(signal_scores(scores)),
        canonical_json(sanitized_bundle) if sanitized_bundle is not None else None,
        bounded_int(duration_ms, 0, MAX_DURATION_MS),
        hex64_or_none(config_hash),
    )


def trust_row(
    *,
    seq: Any,
    ts: Any,
    session_key: Any,
    turn_index: Any,
    model: Any,
    prompt_type: Any,
    trust_score: Any,
    trust_label: Any,
    badge: Any,
    volatility: Any,
    drift_detected: Any,
    flags: Any,
    detail: Any,
) -> Tuple[Any, ...] | None:
    """One ``trust_records`` snapshot row, in ``snapshot.TRUST_COLUMNS`` order."""
    seq_value = bounded_int(seq, 1, 2**62)
    score = unit_interval(trust_score)
    if seq_value is None or score is None:
        return None
    key = session_key if isinstance(session_key, str) and _HEX32.fullmatch(session_key) else ""
    return (
        seq_value,
        hour_bucket(ts),
        key,
        bounded_int(turn_index, 0, MAX_TURN_INDEX),
        model_family(model),
        enum_or_none(prompt_type, PROMPT_TYPES),
        score,
        trust_label if trust_label in TRUST_LABELS else "UNKNOWN",
        enum_or_none(badge, BADGES),
        unit_interval(volatility),
        _flag(drift_detected),
        canonical_json(trigger_flags(flags)),
        canonical_json(trust_detail(detail)),
    )
