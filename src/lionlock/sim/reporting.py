from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict


_HASH_EXCLUDE_KEYS = {"report_json_sha256"}


def _normalize(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for key in sorted(value.keys(), key=lambda item: str(item)):
            normalized[str(key)] = _normalize(value[key])
        return normalized
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    normalized = _normalize(payload)
    text = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def report_json_hash(report: Dict[str, Any]) -> str:
    stripped = {key: value for key, value in report.items() if key not in _HASH_EXCLUDE_KEYS}
    return sha256_hex(canonical_json_bytes(stripped))


def render_json(report: Dict[str, Any]) -> str:
    return canonical_json_bytes(report).decode("utf-8")


def render_markdown(report: Dict[str, Any]) -> str:
    decisions = report.get("decisions", {})
    missed = report.get("missed", {})
    coverage = report.get("coverage", {})
    logging_cfg = report.get("logging", {})
    warnings = logging_cfg.get("warnings", []) if isinstance(logging_cfg, dict) else []
    lines = [
        "# LionLock Simulation Report",
        "",
        f"- run_id: {report.get('run_id', '')}",
        f"- profile: {report.get('profile', '')}",
        f"- turns: {report.get('turns', '')}",
        f"- seed: {report.get('seed', '')}",
        f"- policy_version: {report.get('policy_version', '')}",
        f"- config_hash: {report.get('config_hash', '')}",
        f"- code_fingerprint: {report.get('code_fingerprint', '')}",
        f"- trust_logic_version: {report.get('trust_logic_version', '')}",
        "",
        "## Decision Distribution",
        f"- ALLOW: {decisions.get('ALLOW', 0)}",
        f"- REFRESH: {decisions.get('REFRESH', 0)}",
        f"- BLOCK: {decisions.get('BLOCK', 0)}",
        "",
        "## Missed Signal",
        f"- missed_count: {missed.get('count', 0)}",
        f"- missed_rate: {missed.get('rate', 0)}",
        f"- status: {missed.get('status', '')}",
        f"- overtrigger_rate: {report.get('overtrigger_rate', 0)}",
        "",
        "## Logging",
        f"- chosen_db_engine: {logging_cfg.get('chosen_db_engine', '')}",
        f"- db_source: {logging_cfg.get('db_source', '')}",
        f"- schema_in_use: {logging_cfg.get('schema_in_use', '')}",
        f"- offline_fallback_engaged: {logging_cfg.get('offline_fallback_engaged', False)}",
        f"- warnings: {warnings if warnings else '[]'}",
        "",
        "## Coverage",
        f"- fatigue_high: {coverage.get('fatigue_high', False)}",
        f"- low_conf_halluc: {coverage.get('low_conf_halluc', False)}",
        f"- congestion_high: {coverage.get('congestion_high', False)}",
        f"- expected_block: {coverage.get('expected_block', False)}",
        "",
        "## Determinism",
        f"- report_json_sha256: {report.get('report_json_sha256', '')}",
        f"- labels_sha256: {report.get('labels_sha256', '')}",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(output_dir: str | Path, report: Dict[str, Any]) -> Dict[str, str]:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_json_path = out_path / "report.json"
    report_md_path = out_path / "report.md"

    report_json_path.write_text(render_json(report) + "\n", encoding="utf-8")
    report_md_path.write_text(render_markdown(report), encoding="utf-8")

    return {
        "report_json": str(report_json_path),
        "report_md": str(report_md_path),
    }

