"""LionLock quickstart: score, gate, and log sample fixture sessions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lionlock.config import load_config, resolve_gating_enabled
from lionlock.core.gating import evaluate_policy
from lionlock.core.scoring import score_payload
from lionlock.logging.event_log import build_signal_event, config_hash_from, log_event
from lionlock.trust_overlay.logger import append_trust_record, build_trust_record

FIXTURE_PATH = Path("tests/fixtures/sample_sessions.json")


def load_fixture_sessions(path: str | Path = FIXTURE_PATH) -> list[dict[str, Any]]:
    """Load quickstart fixture sessions from JSON."""
    fixture_path = Path(path)
    records = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("Fixture must be a list of sample sessions")
    return [record for record in records if isinstance(record, dict)]


def run_quickstart(path: str | Path = FIXTURE_PATH) -> dict[str, int]:
    """Run end-to-end demo and print FLAGGED vs CLEAN summary."""
    config = load_config()
    config["logging"]["backend"] = "jsonl"
    config["logging_sql"]["enabled"] = False
    gating_enabled = resolve_gating_enabled(config)
    records = load_fixture_sessions(path)

    flagged = 0
    clean = 0
    config_hash = config_hash_from(config)

    for idx, record in enumerate(records):
        prompt = str(record.get("text", ""))
        payload = {"prompt": prompt, "response": prompt, "metadata": {"turn_index": idx}}
        bundle = score_payload(payload)
        if bundle is None:
            continue
        decision = evaluate_policy(bundle, gating_enabled=gating_enabled)

        if decision.gating_decision in {"REFRESH", "BLOCK"}:
            flagged += 1
        else:
            clean += 1

        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event = build_signal_event(
            timestamp_utc=timestamp,
            request_id=f"quickstart-{record.get('id', idx)}",
            base_url="local",
            model="quickstart-demo",
            decision=decision.gating_decision,
            severity=decision.severity,
            reason_code=decision.reason_code,
            aggregate_score=decision.decision_risk_score,
            signal_scores=decision.signal_scores,
            duration_ms=0,
            config_hash=config_hash,
        )
        log_event(event, config)

        trust_record = build_trust_record(
            session_id=str(record.get("id", idx)),
            turn_index=idx,
            model_id="quickstart-demo",
            prompt_type="fixture",
            derived_signals=bundle.derived_signals,
            aggregate_score=decision.decision_risk_score,
            response_text=prompt,
            response_hash=None,
            score_history=[decision.decision_risk_score],
            timestamps=[timestamp],
            config=config,
            timestamp_utc=timestamp,
        )
        append_trust_record(trust_record, config=config)

    mode = "active-gating" if gating_enabled else "log-only"
    summary = {"FLAGGED": flagged, "CLEAN": clean}
    print(f"Quickstart mode: {mode}")
    print(f"Quickstart summary: FLAGGED={flagged} CLEAN={clean}")
    return summary


if __name__ == "__main__":
    run_quickstart()
