import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

from . import sql_telemetry

try:
    from cryptography.fernet import Fernet  # type: ignore
except Exception:
    Fernet = None  # type: ignore[assignment]


def _serialize(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def failsafe_status(config: Dict[str, Any]) -> Tuple[bool, str]:
    cfg = config.get("failsafe", {}) if isinstance(config, dict) else {}
    if not cfg.get("enabled"):
        return False, "Failsafe disabled."
    if cfg.get("trigger_mode") != "catastrophic_only":
        return False, "Failsafe trigger_mode must be catastrophic_only."
    if not cfg.get("encrypt", True):
        return False, "Failsafe encryption required; encrypt=false is not allowed."
    if Fernet is None:
        return False, "cryptography not installed; failsafe disabled."
    key_env = str(cfg.get("key_env", "")).strip()
    if not key_env:
        return False, "Failsafe key_env missing."
    key = os.getenv(key_env, "")
    if not key:
        return False, f"Failsafe key missing in env var {key_env}."
    return True, "Failsafe ready."


def record_failsafe_event(config: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
    ok, message = failsafe_status(config)
    if not ok:
        return False, message

    cfg = config.get("failsafe", {})
    key_env = str(cfg.get("key_env", "")).strip()
    key = os.getenv(key_env, "").encode("utf-8")
    if Fernet is None:
        return False, "cryptography not installed; failsafe disabled."

    try:
        token = Fernet(key).encrypt(_serialize(payload))
    except Exception as exc:
        return False, f"Failsafe encryption failed: {exc}"

    storage = str(cfg.get("storage", "file")).lower()
    if storage == "file":
        path = Path(str(cfg.get("file_path", "logs/failsafe_events.encjsonl"))).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(token.decode("utf-8") + "\n")
        return True, f"Failsafe wrote encrypted payload to {path}."
    if storage == "sql":
        sql_cfg = config.get("logging_sql", {})
        merged_cfg = dict(sql_cfg)
        merged_cfg["sql_table"] = cfg.get("sql_table", "lionlock_failsafe")
        timestamp = payload.get("timestamp_utc", "")
        request_id = payload.get("request_id", "")
        ok, msg = sql_telemetry.write_failsafe_blob(
            merged_cfg, str(timestamp), str(request_id), token.decode("utf-8")
        )
        return ok, msg
    return False, f"Unknown failsafe storage target: {storage}"
