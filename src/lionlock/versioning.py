from __future__ import annotations

from importlib import metadata
from typing import Any, Dict


def get_lionlock_version(config: Dict[str, Any]) -> str:
    telemetry = config.get("telemetry", {}) if isinstance(config, dict) else {}
    mode = str(telemetry.get("version_mode", "package")).lower()
    if mode == "toml":
        value = str(telemetry.get("lionlock_version", "")).strip()
        return value or "0.0.0-dev"
    if mode == "manual":
        value = str(telemetry.get("lionlock_version", "")).strip()
        return value or "0.0.0-dev"
    try:
        return metadata.version("lionlock")
    except Exception:
        return "0.0.0-dev"
