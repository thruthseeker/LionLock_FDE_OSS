from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from lionlock import config as lionlock_config
from lionlock.logging.event_log import config_hash_from

try:
    import tomllib  # py>=3.11
except ModuleNotFoundError:  # pragma: no cover - fallback for older runtimes
    import tomli as tomllib


@dataclass(frozen=True)
class PolicyBundle:
    policy_version: str
    config: Dict[str, Any]
    config_hash: str


def validate_policy_version(policy_version: str) -> str:
    text = str(policy_version or "").strip()
    if not text:
        raise ValueError("policy_version is empty.")
    if len(text) > 64:
        raise ValueError("policy_version must be a short identifier.")
    if "/" in text or "\\" in text:
        raise ValueError("policy_version must be an identifier, not a path.")
    lowered = text.lower()
    if lowered.endswith((".toml", ".json", ".yaml", ".yml")):
        raise ValueError("policy_version must be an identifier, not a filename.")
    return text


def _merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for key, value in base.items():
        merged[key] = value
    for key, value in override.items():
        existing = merged.get(key)
        if isinstance(value, dict) and isinstance(existing, dict):
            merged[key] = _merge_dict(existing, value)
        else:
            merged[key] = value
    return merged


def _policy_subset(config: Dict[str, Any]) -> Dict[str, Any]:
    gating = config.get("gating", {}) if isinstance(config, dict) else {}
    signals = config.get("signals", {}) if isinstance(config, dict) else {}
    return {"gating": gating, "signals": signals}


def _validate_policy_entry(entry: Dict[str, Any]) -> None:
    if "gating" in entry and not isinstance(entry["gating"], dict):
        raise ValueError("policy registry gating entry must be a table.")
    if "signals" in entry and not isinstance(entry["signals"], dict):
        raise ValueError("policy registry signals entry must be a table.")
    gating = entry.get("gating", {}) if isinstance(entry.get("gating", {}), dict) else {}
    signals = entry.get("signals", {}) if isinstance(entry.get("signals", {}), dict) else {}
    if "thresholds" in gating and not isinstance(gating["thresholds"], dict):
        raise ValueError("policy registry gating.thresholds must be a table.")
    if "weights" in signals and not isinstance(signals["weights"], dict):
        raise ValueError("policy registry signals.weights must be a table.")
    if "enabled" in signals and not isinstance(signals["enabled"], list):
        raise ValueError("policy registry signals.enabled must be a list.")


def load_policy_registry(path: str | Path) -> Dict[str, Dict[str, Any]]:
    registry_path = Path(path)
    if not registry_path.exists():
        raise FileNotFoundError(f"Policy registry not found: {registry_path}")
    with registry_path.open("rb") as handle:
        raw = tomllib.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("Policy registry must be a TOML table.")
    policies = raw.get("policies")
    if policies is None:
        policies = raw
    if not isinstance(policies, dict):
        raise ValueError("Policy registry must define a policies table.")
    return {str(key): value for key, value in policies.items() if isinstance(value, dict)}


def resolve_policy(
    policy_version: str,
    registry_path: str | Path | None = None,
    base_config: Dict[str, Any] | None = None,
) -> PolicyBundle:
    policy_version = validate_policy_version(policy_version)
    registry = load_policy_registry(registry_path or "policies.toml")
    entry = registry.get(policy_version)
    if entry is None:
        raise KeyError(f"Policy version not found: {policy_version}")
    _validate_policy_entry(entry)

    if base_config is None:
        base_config = lionlock_config.load_config()
    base_subset = _policy_subset(base_config)
    entry_subset = _policy_subset(entry)
    resolved = _merge_dict(base_subset, entry_subset)

    config_hash = config_hash_from(resolved)
    return PolicyBundle(
        policy_version=policy_version,
        config=resolved,
        config_hash=config_hash,
    )
