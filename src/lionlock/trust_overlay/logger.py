from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, cast

from lionlock.versioning import get_lionlock_version

from .config import (
    resolve_profile,
    resolve_runtime_mode,
    resolve_salt,
    resolve_trust_overlay_config,
    resolve_trust_overlay_sql_config,
)
from .engine import (
    assign_badge,
    compute_confidence_band,
    compute_trust_score,
    compute_volatility,
    detect_drift,
    map_label,
    trigger_flags,
)
from .schemas import TrustRecord, sanitize_record, signal_summary_from, validate_trust_record
from .sql_sink import enqueue_record as enqueue_sql_record
from .versioning import code_fingerprint


def _serialize(entry: Dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def hash_response(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pseudonymous_user_key(user_id: str, salt: str) -> str:
    digest = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def _daily_log_path(base_dir: str | Path, date: datetime | None = None) -> Path:
    date = date or datetime.now(timezone.utc)
    filename = f"trust_overlay_{date:%Y-%m-%d}.jsonl"
    return Path(base_dir) / filename


def _daily_annotations_path(base_dir: str | Path, date: datetime | None = None) -> Path:
    date = date or datetime.now(timezone.utc)
    filename = f"annotations_{date:%Y-%m-%d}.jsonl"
    return Path(base_dir) / filename


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_model_config_snapshot(
    model_id: str,
    *,
    temperature: float | None = None,
    top_p: float | None = None,
    max_tokens: int | None = None,
    frequency_penalty: float | None = None,
    presence_penalty: float | None = None,
    seed: int | None = None,
    stop: Any | None = None,
    response_format: str | None = None,
    tool_calling_enabled: bool | None = None,
) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {}
    if model_id:
        snapshot["model_id"] = model_id
    if temperature is not None:
        snapshot["temperature"] = temperature
    if top_p is not None:
        snapshot["top_p"] = top_p
    if max_tokens is not None:
        snapshot["max_tokens"] = max_tokens
    if frequency_penalty is not None:
        snapshot["frequency_penalty"] = frequency_penalty
    if presence_penalty is not None:
        snapshot["presence_penalty"] = presence_penalty
    if seed is not None:
        snapshot["seed"] = seed
    if stop is not None:
        snapshot["stop"] = stop
    if response_format is not None:
        snapshot["response_format"] = response_format
    if tool_calling_enabled is not None:
        snapshot["tool_calling_enabled"] = tool_calling_enabled
    return snapshot


def build_deployment_context_snapshot(
    *,
    trust_logic_version: str,
    fingerprint: str,
    runtime_mode: str,
    config: Dict[str, Any] | None,
) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {
        "trust_logic_version": trust_logic_version,
        "code_fingerprint": fingerprint,
        "runtime_mode": runtime_mode,
        "lionlock_version": get_lionlock_version(config or {}),
    }

    python_version = platform.python_version()
    if python_version:
        snapshot["python_version"] = python_version
    platform_info = platform.platform()
    if platform_info:
        snapshot["platform"] = platform_info

    hostname = socket.gethostname()
    if hostname:
        snapshot["host_id_hash"] = _hash_value(hostname)

    container_id = os.getenv("CONTAINER_ID", "").strip() or os.getenv("HOSTNAME", "").strip()
    if container_id and container_id != hostname:
        snapshot["container_id_hash"] = _hash_value(container_id)

    return snapshot


def build_trust_record(
    *,
    session_id: str,
    turn_index: int | None = None,
    model_id: str,
    prompt_type: str,
    derived_signals: Any,
    aggregate_score: float | None,
    response_text: str | None,
    response_hash: str | None,
    score_history: Iterable[float] | None,
    timestamps: Iterable[str] | None,
    config: Dict[str, Any] | None,
    user_id: str | None = None,
    model_config_snapshot: Dict[str, Any] | None = None,
    deployment_context_snapshot: Dict[str, Any] | None = None,
    timestamp_utc: str | None = None,
) -> Dict[str, Any]:
    overlay_cfg = resolve_trust_overlay_config(config)
    profile = resolve_profile(overlay_cfg.get("profile"))
    summary = signal_summary_from(derived_signals, aggregate_score)
    trust_score = compute_trust_score(summary, profile=profile)

    raw_history = list(score_history or [])
    raw_timestamps = list(timestamps or [])
    history: list[float] = []
    history_timestamps: list[str] = []
    if raw_history and raw_timestamps and len(raw_history) == len(raw_timestamps):
        for score, ts in zip(raw_history, raw_timestamps):
            if isinstance(score, (int, float)) and isinstance(ts, str):
                history.append(float(score))
                history_timestamps.append(ts)
    else:
        history = [float(score) for score in raw_history if isinstance(score, (int, float))]
        history_timestamps = [ts for ts in raw_timestamps if isinstance(ts, str)]

    history.append(trust_score)
    timestamp = timestamp_utc or utc_now_iso()
    history_timestamps.append(timestamp)

    volatility = compute_volatility(history, window_n=overlay_cfg.get("volatility_window_n"))
    confidence_band = compute_confidence_band(
        summary, history, window_n=overlay_cfg.get("score_window_n"), k=1.0
    )
    drift = detect_drift(
        history,
        history_timestamps,
        profile=profile,
        lookback_days=overlay_cfg.get("drift_lookback_days"),
        min_points=overlay_cfg.get("drift_min_points"),
    )
    badge = assign_badge(trust_score, volatility, drift)
    trust_label = map_label(trust_score, profile=profile)
    flags = trigger_flags(trust_score, volatility, drift, profile)

    if response_hash is None and response_text:
        response_hash = hash_response(response_text)

    salt = resolve_salt(config)
    pseudonymous_key = None
    if salt and user_id:
        pseudonymous_key = pseudonymous_user_key(user_id, salt)

    trust_logic_version = cast(str, overlay_cfg.get("trust_logic_version"))
    fingerprint = code_fingerprint()
    runtime_mode = resolve_runtime_mode(config)

    model_snapshot = model_config_snapshot or build_model_config_snapshot(model_id)
    deployment_snapshot = deployment_context_snapshot or build_deployment_context_snapshot(
        trust_logic_version=trust_logic_version,
        fingerprint=fingerprint,
        runtime_mode=runtime_mode,
        config=config,
    )

    record = TrustRecord(
        trust_logic_version=trust_logic_version,
        code_fingerprint=fingerprint,
        timestamp=timestamp,
        session_id=session_id,
        turn_index=turn_index,
        model_id=model_id,
        trust_score=trust_score,
        trust_label=trust_label,
        confidence_band=confidence_band,
        volatility=volatility,
        drift=drift,
        badge=badge,
        prompt_type=prompt_type,
        model_config_snapshot=model_snapshot,
        deployment_context_snapshot=deployment_snapshot,
        signal_summary=summary,
        trigger_flags=flags,
        response_hash=response_hash,
        pseudonymous_user_key=pseudonymous_key,
    ).as_dict()

    sanitized = sanitize_record(record)
    validate_trust_record(sanitized)
    return sanitized


def append_trust_record(
    record: Dict[str, Any],
    base_dir: str | Path = "logs/trust_overlay",
    *,
    config: Dict[str, Any] | None = None,
) -> Path:
    sanitized = sanitize_record(record)
    validate_trust_record(sanitized)
    path = _daily_log_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(_serialize(sanitized) + "\n")
    if config:
        sql_cfg = resolve_trust_overlay_sql_config(config)
        try:
            enqueue_sql_record(sql_cfg, sanitized)
        except Exception:
            pass
    return path


def append_annotation(
    annotation: Dict[str, Any],
    base_dir: str | Path = "logs/trust_overlay/annotations",
) -> Path:
    path = _daily_annotations_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(_serialize(annotation) + "\n")
    return path
