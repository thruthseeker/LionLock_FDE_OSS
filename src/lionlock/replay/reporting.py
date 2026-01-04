from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .replay_engine import ReplayResult


def render_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, separators=(",", ":"))


def render_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary", {})
    labels = report.get("labels")
    lines = [
        "# LionLock Replay Report",
        "",
        f"- policy_version: {report.get('policy_version', '')}",
        f"- config_hash: {report.get('config_hash', '')}",
        "",
        "## Summary",
        f"- events: {summary.get('event_count', 0)}",
        f"- replayed: {summary.get('replayed_count', 0)}",
        f"- diffs: {summary.get('diff_count', 0)}",
        f"- bundle_errors: {summary.get('bundle_errors', 0)}",
        f"- identifier_errors: {summary.get('identifier_errors', 0)}",
        f"- decision_mismatch: {summary.get('decision_mismatch', 0)}",
        f"- score_mismatch: {summary.get('score_mismatch', 0)}",
        f"- trigger_mismatch: {summary.get('trigger_mismatch', 0)}",
        f"- severity_mismatch: {summary.get('severity_mismatch', 0)}",
        f"- policy_version_mismatch: {summary.get('policy_version_mismatch', 0)}",
        f"- config_hash_mismatch: {summary.get('config_hash_mismatch', 0)}",
        f"- writeback_candidates: {summary.get('writeback_candidates', 0)}",
        f"- writeback_skipped: {summary.get('writeback_skipped', 0)}",
    ]
    if labels:
        lines.extend(
            [
                "",
                "## Labels",
                f"- total: {labels.get('total', 0)}",
                f"- matches: {labels.get('matches', 0)}",
                "",
                "### Block Metrics",
                f"- tp: {labels.get('block', {}).get('tp', 0)}",
                f"- fp: {labels.get('block', {}).get('fp', 0)}",
                f"- fn: {labels.get('block', {}).get('fn', 0)}",
                f"- tn: {labels.get('block', {}).get('tn', 0)}",
            ]
        )
    return "\n".join(lines) + "\n"


def write_outputs(output_dir: str, result: ReplayResult) -> Dict[str, str]:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    report_json = render_json(result.report)
    report_md = render_markdown(result.report)
    diff_json = json.dumps(result.diff_artifact, sort_keys=True, separators=(",", ":"))

    report_json_path = out_path / "replay_report.json"
    report_md_path = out_path / "replay_report.md"
    diff_path = out_path / "replay_diff.json"
    proposals_path = out_path / "proposed_missed_signal_events.jsonl"

    report_json_path.write_text(report_json + "\n", encoding="utf-8")
    report_md_path.write_text(report_md, encoding="utf-8")
    diff_path.write_text(diff_json + "\n", encoding="utf-8")

    with proposals_path.open("w", encoding="utf-8") as handle:
        for proposal in result.proposed_missed_signal_events:
            handle.write(json.dumps(proposal, sort_keys=True, separators=(",", ":")))
            handle.write("\n")

    return {
        "report_json": str(report_json_path),
        "report_md": str(report_md_path),
        "diff_json": str(diff_path),
        "proposed_events": str(proposals_path),
    }
