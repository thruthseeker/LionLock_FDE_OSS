from __future__ import annotations

import copy
import os
import warnings
from pathlib import Path
from typing import Any, Dict

from lionlock.logging.connection import build_postgres_dsn
try:
    import tomllib  # py>=3.11
except ModuleNotFoundError:  # pragma: no cover - fallback for older runtimes
    import tomli as tomllib

DEFAULT_CONFIG: Dict[str, Any] = {
    "llm": {
        "base_url": "http://localhost:11434",
        "model": "llama3.1:8b",
        "preferred_api": "openai_compat",
        "fallback_api": "ollama_native",
        "timeout_s": 60,
        "api_key_env": "",
    },
    "gating": {
        "enabled": True,
        "thresholds": {"yellow": 0.45, "orange": 0.65, "red": 0.80},
        "hallucination_mode": "warn_only",
        "hard_gate_show_reason": True,
        "show_disable_warning": True,
    },
    "signals": {
        "enabled": [
            "repetition_loopiness",
            "novelty_entropy_proxy",
            "coherence_structure",
            "context_adherence",
            "hallucination_risk",
        ],
        "weights": {
            "repetition_loopiness": 0.30,
            "novelty_entropy_proxy": 0.25,
            "coherence_structure": 0.25,
            "context_adherence": 0.20,
            "hallucination_risk": 0.00,
        },
    },
    "ui": {
        "show_dev_panel": False,
        "show_soft_gate_details": False,
        "graph_history_points": 40,
        "buffered_scoring": True,
        "buffered_chunk_chars": 80,
        "buffered_tick_ms": 50,
    },
    "trust_overlay": {
        "profile": "STANDARD",
        "trust_logic_version": "TO-0.1.0",
        "runtime_mode": "oss",
        "score_window_n": 50,
        "volatility_window_n": 20,
        "drift_lookback_days": 30,
        "drift_min_points": 20,
        "volatility_spike_threshold": 0.2,
        "sql": {
            "enabled": False,
            "backend": "sqlite3",
            "dsn": "",
            "sqlite_path": "",
            "table": "trust_overlay_records",
            "batch_size": 50,
            "flush_interval_ms": 1000,
            "connect_timeout_s": 5,
        },
    },
    "telemetry": {
        "sessions_table": "lionlock_sessions",
        "version_mode": "package",
        "lionlock_version": "",
    },
    "logging": {
        "enabled": True,
        "backend": "jsonl",
        "path": "logs/lionlock_events.jsonl",
        "verbosity": "normal",
        "retention_events": 2000,
        "content_policy": "signals_only",
        "notes_allowlist": [],
        "notes_max_length": 120,
    },
    "logging_sql": {
        "enabled": False,
        "uri": "",
        "table": "lionlock_signals",
        "batch_size": 50,
        "flush_interval_ms": 1000,
        "connect_timeout_s": 5,
        "token_auth": {
            "enabled": False,
            "mode": "required",
            "required": False,
            "token_env": "LIONLOCK_LOG_TOKEN",
            "token_path": "",
            "token_hashes": [],
            "token_hashes_path": "",
            "token_db_uri": "",
            "refresh_interval_s": 60,
        },
    },
    "failsafe": {
        "enabled": False,
        "trigger_mode": "catastrophic_only",
        "encrypt": True,
        "key_env": "LIONLOCK_FAILSAFE_KEY_B64",
        "storage": "file",
        "file_path": "logs/failsafe_events.encjsonl",
        "sql_table": "lionlock_failsafe",
    },
    "anomaly": {
        "enabled": True,
        "db_uri": "sqlite:///logs/lionlock_anomalies.db",
        "table": "lionlock_anomalies",
        "diagnostics_table": "lionlock_session_diagnostics",
        "user_escalation_threshold": 3,
        "repeat_type_threshold": 3,
        "fatigue_spike_delta": 0.25,
        "hallucination_jump_delta": 0.3,
        "minor_signal_threshold": 0.75,
        "congestion_signature_threshold": 0.6,
        "congestion_window_n": 20,
        "degradation_window_n": 20,
        "degradation_min_points": 12,
        "degradation_delta": 0.08,
        "missed_warn_threshold": 0.75,
        "missed_block_threshold": 0.9,
        "weights": {
            "minor_signal_drift": 0.20,
            "fatigue_spike": 0.40,
            "hallucination_jump": 0.50,
            "scoring_nan": 0.60,
            "gate_mismatch": 0.70,
            "prompt_injection_suspected": 0.80,
            "gate_override_failure": 1.00,
            "model_degradation": 0.55,
            "model_congestion": 0.45,
            "missed_signal_event": 0.90,
        },
        "severity_bands": {"normal_max": 0.30, "unstable_max": 0.60, "critical_min": 0.61},
    },
}


def _merge_dict(default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for key, default_value in default.items():
        if key not in override:
            merged[key] = copy.deepcopy(default_value)
            continue
        override_value = override[key]
        if isinstance(default_value, dict) and isinstance(override_value, dict):
            merged[key] = _merge_dict(default_value, override_value)
        else:
            merged[key] = override_value
    for key, value in override.items():
        if key not in merged:
            merged[key] = value
    return merged


def load_config(path: str = "lionlock.toml") -> Dict[str, Any]:
    """Load config with safe defaults; missing files are non-fatal."""
    config = copy.deepcopy(DEFAULT_CONFIG)
    config_path = Path(path)
    if not config_path.exists():
        return config
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except Exception:
        return config
    if isinstance(raw, dict):
        config = _merge_dict(config, raw)

    logging_cfg = config.get("logging", {})
    sql_cfg = config.get("logging_sql", {})
    telemetry_db_uri = os.getenv("LIONLOCK_TELEMETRY_DB_URI", "").strip()
    if not telemetry_db_uri:
        try:
            telemetry_db_uri = build_postgres_dsn("writer")
        except Exception:
            telemetry_db_uri = ""
    if telemetry_db_uri:
        sql_cfg["uri"] = telemetry_db_uri
        sql_cfg["enabled"] = True
    if sql_cfg.get("enabled") and logging_cfg.get("content_policy") != "signals_only":
        logging_cfg["content_policy"] = "signals_only"
        warnings.warn(
            "logging.content_policy forced to signals_only for public SQL telemetry.",
            RuntimeWarning,
        )
    return config
