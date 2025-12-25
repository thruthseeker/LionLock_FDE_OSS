from __future__ import annotations

import os
from typing import Any, Dict

TRUST_LOGIC_VERSION_DEFAULT = "TO-0.1.0"

DEFAULT_PROFILE = "STANDARD"

PROFILE_THRESHOLDS: Dict[str, Dict[str, float]] = {
    "STANDARD": {
        "TRUSTED": 0.75,
        "MONITOR": 0.55,
        "AT_RISK": 0.35,
        "UNTRUSTED": 0.0,
    },
    "STRICT": {
        "TRUSTED": 0.85,
        "MONITOR": 0.65,
        "AT_RISK": 0.45,
        "UNTRUSTED": 0.0,
    },
    "LENIENT": {
        "TRUSTED": 0.65,
        "MONITOR": 0.45,
        "AT_RISK": 0.25,
        "UNTRUSTED": 0.0,
    },
}

DRIFT_THRESHOLDS_BY_PROFILE: Dict[str, float] = {
    "STANDARD": -0.10,
    "STRICT": -0.08,
    "LENIENT": -0.12,
}

DEFAULTS: Dict[str, Any] = {
    "profile": DEFAULT_PROFILE,
    "trust_logic_version": TRUST_LOGIC_VERSION_DEFAULT,
    "runtime_mode": "oss",
    "score_window_n": 50,
    "volatility_window_n": 20,
    "drift_lookback_days": 30,
    "drift_min_points": 20,
    "volatility_spike_threshold": 0.2,
}

SQL_DEFAULTS: Dict[str, Any] = {
    "enabled": False,
    "backend": "sqlite3",
    "dsn": "",
    "sqlite_path": "",
    "table": "trust_overlay_records",
    "batch_size": 50,
    "flush_interval_ms": 1000,
    "connect_timeout_s": 5,
}


def resolve_trust_overlay_config(config: Dict[str, Any] | None) -> Dict[str, Any]:
    overlay = config.get("trust_overlay", {}) if isinstance(config, dict) else {}
    resolved = dict(DEFAULTS)
    if isinstance(overlay, dict):
        for key, value in overlay.items():
            if key == "sql":
                continue
            resolved[key] = value
    resolved["profile"] = resolve_profile(resolved.get("profile"))
    resolved["trust_logic_version"] = resolve_trust_logic_version(config)
    resolved["sql"] = resolve_trust_overlay_sql_config(config)
    return resolved


def resolve_trust_overlay_sql_config(config: Dict[str, Any] | None) -> Dict[str, Any]:
    overlay = config.get("trust_overlay", {}) if isinstance(config, dict) else {}
    sql_cfg = overlay.get("sql", {}) if isinstance(overlay, dict) else {}
    resolved = dict(SQL_DEFAULTS)
    if isinstance(sql_cfg, dict):
        resolved.update(sql_cfg)
    return resolved


def resolve_profile(profile: str | None) -> str:
    if not profile:
        return DEFAULT_PROFILE
    value = str(profile).upper()
    return value if value in PROFILE_THRESHOLDS else DEFAULT_PROFILE


def resolve_trust_logic_version(config: Dict[str, Any] | None) -> str:
    overlay = config.get("trust_overlay", {}) if isinstance(config, dict) else {}
    if isinstance(overlay, dict):
        value = str(overlay.get("trust_logic_version", "")).strip()
        if value:
            return value
    return TRUST_LOGIC_VERSION_DEFAULT


def resolve_runtime_mode(config: Dict[str, Any] | None) -> str:
    overlay = config.get("trust_overlay", {}) if isinstance(config, dict) else {}
    value = overlay.get("runtime_mode") if isinstance(overlay, dict) else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return DEFAULTS["runtime_mode"]


def resolve_salt(config: Dict[str, Any] | None) -> str | None:
    env_value = os.getenv("TRUST_OVERLAY_SALT", "").strip()
    if env_value:
        return env_value
    overlay = config.get("trust_overlay", {}) if isinstance(config, dict) else {}
    value = overlay.get("salt") if isinstance(overlay, dict) else None
    if isinstance(value, str):
        value = value.strip()
    return value or None
