import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set

from . import sql_telemetry
from .privacy import scrub_forbidden_keys
from .token_auth import AUTH_SIGNATURE_FIELD, AUTH_TOKEN_ID_FIELD
from lionlock.core.models import canonical_gating_decision


def _serialize(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def config_hash_from(config: Dict[str, Any]) -> str:
    gating = config.get("gating", {}) if isinstance(config, dict) else {}
    signals = config.get("signals", {}) if isinstance(config, dict) else {}
    subset = {
        "gating": {
            "enabled": gating.get("enabled"),
            "thresholds": gating.get("thresholds", {}),
            "hallucination_mode": gating.get("hallucination_mode"),
        },
        "signals": {
            "enabled": signals.get("enabled", []),
            "weights": signals.get("weights", {}),
        },
    }
    return hashlib.sha256(_serialize(subset).encode()).hexdigest()


PUBLIC_EVENT_FIELDS = {
    "timestamp_utc",
    "request_id",
    "decision",
    "severity",
    "reason_code",
    "aggregate_score",
    "signal_scores",
    "config_hash",
    "duration_ms",
    "notes",
    AUTH_TOKEN_ID_FIELD,
    AUTH_SIGNATURE_FIELD,
}

FORBIDDEN_KEYS = {
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


def _is_forbidden_key(key: str) -> bool:
    return key.lower() in FORBIDDEN_KEYS


def _sanitize_notes(
    notes: Any,
    allowlist: Set[str],
    max_length: int,
) -> Optional[Dict[str, str]]:
    if not isinstance(notes, dict) or not allowlist:
        return None
    ok, cleaned, _ = scrub_forbidden_keys(notes, mode="reject")
    if not ok or not isinstance(cleaned, dict):
        return None
    notes = cleaned
    sanitized: Dict[str, str] = {}
    for key, value in notes.items():
        if key not in allowlist:
            continue
        if _is_forbidden_key(key):
            return None
        if not isinstance(value, str):
            continue
        if len(value) > max_length:
            continue
        lowered = value.lower()
        if any(token in lowered for token in FORBIDDEN_KEYS):
            continue
        sanitized[key] = value
    return sanitized or None


def sanitize_public_event(
    event: Dict[str, Any],
    verbosity: str = "normal",
    notes_allowlist: Optional[Iterable[str]] = None,
    notes_max_length: int = 120,
) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    allowlist = {item for item in (notes_allowlist or []) if isinstance(item, str)}
    for key in PUBLIC_EVENT_FIELDS:
        if key not in event:
            continue
        if _is_forbidden_key(key):
            continue
        if key == "notes" and verbosity != "debug":
            continue
        if key == "notes":
            notes = _sanitize_notes(event.get("notes"), allowlist, notes_max_length)
            if notes is None:
                continue
            sanitized[key] = notes
            continue
        if key == "decision":
            raw_decision = event.get("decision")
            if raw_decision is None:
                sanitized[key] = canonical_gating_decision(None)
                continue
            decision_text = str(raw_decision).strip()
            if decision_text.upper() == "ERROR":
                sanitized[key] = "ERROR"
                continue
            sanitized[key] = canonical_gating_decision(decision_text)
            continue
        if key == "signal_scores":
            ok, cleaned, _ = scrub_forbidden_keys(event.get("signal_scores"), mode="reject")
            if not ok or not isinstance(cleaned, dict):
                continue
            sanitized[key] = cleaned
            continue
        sanitized[key] = event[key]
    return sanitized


def build_signal_event(
    *,
    timestamp_utc: str,
    request_id: str,
    base_url: str,
    model: str,
    decision: str,
    severity: str,
    reason_code: str | None,
    aggregate_score: float | None,
    signal_scores: Dict[str, float] | None,
    duration_ms: int | None,
    config_hash: str,
    notes: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    event = {
        "timestamp_utc": timestamp_utc,
        "request_id": request_id,
        "base_url": base_url,
        "model": model,
        "decision": decision,
        "severity": severity,
        "reason_code": reason_code,
        "aggregate_score": aggregate_score,
        "signal_scores": signal_scores or {},
        "config_hash": config_hash,
        "duration_ms": duration_ms,
    }
    if notes:
        event["notes"] = notes
    return event


def build_connector_error_event(
    *,
    timestamp_utc: str,
    request_id: str,
    base_url: str,
    model: str,
    duration_ms: int | None,
    config_hash: str,
    notes: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "timestamp_utc": timestamp_utc,
        "request_id": request_id,
        "base_url": base_url,
        "model": model,
        "decision": "ERROR",
        "severity": "orange",
        "reason_code": "connector_error",
        "aggregate_score": None,
        "signal_scores": {},
        "config_hash": config_hash,
        "duration_ms": duration_ms,
    }
    if notes:
        event["notes"] = notes
    return event


def append_event(
    path: str | Path,
    event: Dict[str, Any],
    verbosity: str = "normal",
    notes_allowlist: Optional[Iterable[str]] = None,
    notes_max_length: int = 120,
) -> None:
    record = sanitize_public_event(
        event,
        verbosity=verbosity,
        notes_allowlist=notes_allowlist,
        notes_max_length=notes_max_length,
    )
    log_path = Path(path).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(_serialize(record) + "\n")


def log_event(event: Dict[str, Any], config: Dict[str, Any]) -> None:
    logging_cfg = config.get("logging", {}) if isinstance(config, dict) else {}
    sql_cfg = dict(config.get("logging_sql", {})) if isinstance(config, dict) else {}
    telemetry_cfg = config.get("telemetry", {}) if isinstance(config, dict) else {}
    if "sessions_table" not in sql_cfg and telemetry_cfg:
        sql_cfg["sessions_table"] = telemetry_cfg.get("sessions_table", "lionlock_sessions")
    if not logging_cfg.get("enabled", True):
        return
    backend = str(logging_cfg.get("backend", "jsonl")).lower()
    if backend == "off":
        return
    verbosity = str(logging_cfg.get("verbosity", "normal")).lower()
    notes_allowlist = logging_cfg.get("notes_allowlist", [])
    notes_max_length = int(logging_cfg.get("notes_max_length", 120))
    session_pk = event.get("session_pk")

    record = sanitize_public_event(
        event,
        verbosity=verbosity,
        notes_allowlist=notes_allowlist,
        notes_max_length=notes_max_length,
    )

    if backend in ("jsonl", "both"):
        path = logging_cfg.get("path", "logs/lionlock_events.jsonl")
        append_event(
            path,
            record,
            verbosity=verbosity,
            notes_allowlist=notes_allowlist,
            notes_max_length=notes_max_length,
        )

    if backend in ("sql", "both") and sql_cfg.get("enabled"):
        sql_telemetry.enqueue_event(sql_cfg, record, session_pk=session_pk)
