from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from lionlock.core import gating as gating_module
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores, canonical_gating_decision
from lionlock.core.scoring import aggregate_score

from .evaluation_labels import ALLOWED_DECISIONS, LabelRecord
from .policy_registry import PolicyBundle
from .sql_reader import TelemetryEvent


@dataclass(frozen=True)
class ReplayResult:
    report: Dict[str, Any]
    diff_artifact: Dict[str, Any]
    proposed_missed_signal_events: List[Dict[str, Any]]


def _safe_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    try:
        parsed = float(value)
    except Exception:
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _round_score(value: float | None, digits: int) -> float | None:
    if value is None:
        return None
    return round(float(value), digits)


def _parse_signal_bundle(raw: Any) -> SignalBundle | None:
    if raw is None:
        return None
    payload = raw
    if hasattr(raw, "as_dict"):
        try:
            payload = raw.as_dict()
        except Exception:
            payload = raw
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            return None
    if not isinstance(payload, dict):
        return None
    signal_scores = payload.get("signal_scores", {})
    derived_signals = payload.get("derived_signals", {})
    if not isinstance(signal_scores, dict):
        signal_scores = {}
    if not isinstance(derived_signals, dict):
        derived_signals = {}

    def _score(source: Dict[str, Any], key: str) -> float:
        value = _safe_float(source.get(key))
        return float(value) if value is not None else 0.0

    missing_inputs = payload.get("missing_inputs", [])
    if not isinstance(missing_inputs, list):
        missing_inputs = []
    missing_tuple = tuple(
        str(item) for item in missing_inputs if isinstance(item, (str, int, float))
    )

    scores = SignalScores(
        repetition_loopiness=_score(signal_scores, "repetition_loopiness"),
        novelty_entropy_proxy=_score(signal_scores, "novelty_entropy_proxy"),
        coherence_structure=_score(signal_scores, "coherence_structure"),
        context_adherence=_score(signal_scores, "context_adherence"),
        hallucination_risk=_score(signal_scores, "hallucination_risk"),
    )
    derived = DerivedSignals(
        fatigue_risk_index=_score(derived_signals, "fatigue_risk_index"),
        fatigue_risk_25t=_score(derived_signals, "fatigue_risk_25t"),
        fatigue_risk_50t=_score(derived_signals, "fatigue_risk_50t"),
        low_conf_halluc=_score(derived_signals, "low_conf_halluc"),
        congestion_signature=_score(derived_signals, "congestion_signature"),
    )
    schema_version = str(payload.get("signal_schema_version") or "unknown")
    return SignalBundle(
        signal_schema_version=schema_version,
        signal_scores=scores,
        derived_signals=derived,
        missing_inputs=missing_tuple,
    )


def _evaluate_with_policy(bundle: SignalBundle, policy: PolicyBundle) -> Any:
    gating_cfg = policy.config.get("gating", {})
    signals_cfg = policy.config.get("signals", {})
    thresholds = gating_cfg.get("thresholds") if isinstance(gating_cfg, dict) else None
    gating_enabled = True
    hallucination_mode = "warn_only"
    if isinstance(gating_cfg, dict):
        gating_enabled = bool(gating_cfg.get("enabled", True))
        hallucination_mode = str(gating_cfg.get("hallucination_mode") or "warn_only")
    weights = signals_cfg.get("weights") if isinstance(signals_cfg, dict) else None
    enabled_signals = signals_cfg.get("enabled") if isinstance(signals_cfg, dict) else None
    if not isinstance(weights, dict):
        weights = None
    if not isinstance(enabled_signals, list):
        enabled_signals = None
    aggregate = aggregate_score(bundle, weights=weights, enabled_signals=enabled_signals)
    return gating_module._evaluate_policy_with_scores(
        aggregate=aggregate,
        signal_scores=bundle.signal_scores,
        derived_signals=bundle.derived_signals,
        thresholds=thresholds,
        gating_enabled=gating_enabled,
        hallucination_mode=hallucination_mode,
        hard_gate_reasons_enabled=None,
        signal_bundle=bundle,
    )


def _dedupe_events(events: Iterable[TelemetryEvent]) -> List[TelemetryEvent]:
    def _sort_key(event: TelemetryEvent) -> Tuple[Any, ...]:
        event_pk = event.event_pk
        timestamp = event.timestamp or ""
        return (
            event.session_id,
            event.turn_index,
            event.response_hash or "",
            event.event_type or "",
            event_pk is None,
            event_pk if event_pk is not None else 0,
            timestamp,
        )

    ordered = sorted(events, key=_sort_key)
    seen: set[Tuple[str, int, str, str]] = set()
    unique: List[TelemetryEvent] = []
    for event in ordered:
        key = (
            event.session_id,
            event.turn_index,
            event.response_hash or "",
            event.event_type or "",
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)
    return unique


def replay(
    events: Iterable[TelemetryEvent],
    policy: PolicyBundle,
    labels: Dict[tuple[str, int, str | None, str | None], LabelRecord] | None = None,
    *,
    round_digits: int = 6,
) -> ReplayResult:
    events_sorted = _dedupe_events(events)
    labels_present = labels is not None
    labels = labels or {}

    diffs: List[Dict[str, Any]] = []
    artifact_events: List[Dict[str, Any]] = []
    proposals: List[Dict[str, Any]] = []

    summary = {
        "event_count": 0,
        "replayed_count": 0,
        "diff_count": 0,
        "bundle_errors": 0,
        "identifier_errors": 0,
        "decision_mismatch": 0,
        "score_mismatch": 0,
        "trigger_mismatch": 0,
        "severity_mismatch": 0,
        "policy_version_mismatch": 0,
        "config_hash_mismatch": 0,
        "writeback_candidates": 0,
        "writeback_skipped": 0,
    }

    label_metrics: Dict[str, Any] = {
        "total": 0,
        "matches": 0,
        "confusion": {},
        "block": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
    }

    for event in events_sorted:
        summary["event_count"] += 1
        bundle = _parse_signal_bundle(event.signal_bundle)
        label = labels.get(
            (event.session_id, event.turn_index, event.replay_id, event.response_hash)
        )
        if label is None:
            label = labels.get((event.session_id, event.turn_index, event.replay_id, None))

        stored_decision = canonical_gating_decision(event.gating_decision)
        stored_score = _round_score(_safe_float(event.decision_risk_score), round_digits)
        stored_trigger = event.trigger_signal
        stored_severity = event.event_severity
        stored_policy_version = event.policy_version
        stored_config_hash = event.config_hash

        if (
            not event.session_id
            or event.turn_index < 0
            or not event.response_hash
            or not event.event_type
        ):
            summary["identifier_errors"] += 1
            entry = {
                "session_id": event.session_id,
                "turn_index": event.turn_index,
                "replay_id": event.replay_id,
                "response_hash": event.response_hash,
                "stored": {
                    "gating_decision": stored_decision,
                    "decision_risk_score": stored_score,
                    "trigger_signal": stored_trigger,
                    "severity": stored_severity,
                    "policy_version": stored_policy_version,
                    "config_hash": stored_config_hash,
                },
                "recomputed": None,
                "mismatches": {"identifiers": True},
                "error": "invalid_identifiers",
            }
            diffs.append(entry)
            artifact_events.append(entry)
            summary["diff_count"] += 1
            continue

        if bundle is None:
            summary["bundle_errors"] += 1
            entry = {
                "session_id": event.session_id,
                "turn_index": event.turn_index,
                "replay_id": event.replay_id,
                "response_hash": event.response_hash,
                "stored": {
                    "gating_decision": stored_decision,
                    "decision_risk_score": stored_score,
                    "trigger_signal": stored_trigger,
                    "severity": stored_severity,
                    "policy_version": stored_policy_version,
                    "config_hash": stored_config_hash,
                },
                "recomputed": None,
                "mismatches": {"signal_bundle": True},
                "error": "invalid_signal_bundle",
            }
            diffs.append(entry)
            artifact_events.append(entry)
            summary["diff_count"] += 1
            continue

        summary["replayed_count"] += 1
        recomputed = _evaluate_with_policy(bundle, policy)
        recomputed_score = _round_score(recomputed.decision_risk_score, round_digits)

        mismatches = {
            "gating_decision": stored_decision != recomputed.gating_decision,
            "decision_risk_score": stored_score != recomputed_score,
            "trigger_signal": bool(stored_trigger) and stored_trigger != recomputed.trigger_signal,
            "severity": bool(stored_severity) and stored_severity != recomputed.severity,
            "policy_version": bool(stored_policy_version)
            and stored_policy_version != policy.policy_version,
            "config_hash": bool(stored_config_hash) and stored_config_hash != policy.config_hash,
        }

        if mismatches["gating_decision"]:
            summary["decision_mismatch"] += 1
        if mismatches["decision_risk_score"]:
            summary["score_mismatch"] += 1
        if mismatches["trigger_signal"]:
            summary["trigger_mismatch"] += 1
        if mismatches["severity"]:
            summary["severity_mismatch"] += 1
        if mismatches["policy_version"]:
            summary["policy_version_mismatch"] += 1
        if mismatches["config_hash"]:
            summary["config_hash_mismatch"] += 1

        entry = {
            "session_id": event.session_id,
            "turn_index": event.turn_index,
            "replay_id": event.replay_id,
            "response_hash": event.response_hash,
            "stored": {
                "gating_decision": stored_decision,
                "decision_risk_score": stored_score,
                "trigger_signal": stored_trigger,
                "severity": stored_severity,
                "policy_version": stored_policy_version,
                "config_hash": stored_config_hash,
            },
            "recomputed": {
                "gating_decision": recomputed.gating_decision,
                "decision_risk_score": recomputed_score,
                "trigger_signal": recomputed.trigger_signal,
                "severity": recomputed.severity,
                "policy_version": policy.policy_version,
                "config_hash": policy.config_hash,
            },
            "mismatches": mismatches,
        }
        artifact_events.append(entry)
        if any(mismatches.values()):
            diffs.append(entry)
            summary["diff_count"] += 1

        if label is not None:
            label_metrics["total"] += 1
            expected = label.expected_decision
            actual = recomputed.gating_decision
            confusion = label_metrics["confusion"].setdefault(expected, {})
            confusion[actual] = confusion.get(actual, 0) + 1
            if expected == actual:
                label_metrics["matches"] += 1
            if expected == "BLOCK" and actual == "BLOCK":
                label_metrics["block"]["tp"] += 1
            elif expected == "BLOCK" and actual != "BLOCK":
                label_metrics["block"]["fn"] += 1
            elif expected != "BLOCK" and actual == "BLOCK":
                label_metrics["block"]["fp"] += 1
            else:
                label_metrics["block"]["tn"] += 1

            if (
                stored_decision in ALLOWED_DECISIONS
                and label.expected_decision in ALLOWED_DECISIONS
                and label.expected_decision != stored_decision
            ):
                if stored_score is None or not stored_trigger or not event.response_hash:
                    summary["writeback_skipped"] += 1
                else:
                    proposals.append(
                        {
                            "session_id": event.session_id,
                            "turn_index": event.turn_index,
                            "timestamp": event.timestamp or "",
                            "signal_bundle": bundle.as_dict(),
                            "gating_decision": stored_decision,
                            "decision_risk_score": stored_score,
                            "trigger_signal": stored_trigger,
                            "trust_logic_version": event.trust_logic_version or "",
                            "policy_version": policy.policy_version,
                            "config_hash": policy.config_hash,
                            "code_fingerprint": event.code_fingerprint or "",
                            "prompt_type": event.prompt_type or "unknown",
                            "response_hash": event.response_hash or "",
                            "replay_id": event.replay_id,
                            "miss_reason": label.actual_failure_type or "label_mismatch",
                            "expected_decision": label.expected_decision,
                            "actual_decision": stored_decision,
                        }
                    )

    summary["writeback_candidates"] = len(proposals)

    report = {
        "report_version": "RE-0.6.0",
        "policy_version": policy.policy_version,
        "config_hash": policy.config_hash,
        "summary": summary,
        "diffs": diffs,
        "labels": label_metrics if labels_present else None,
    }
    diff_artifact = {
        "policy_version": policy.policy_version,
        "config_hash": policy.config_hash,
        "events": artifact_events,
    }
    return ReplayResult(
        report=report,
        diff_artifact=diff_artifact,
        proposed_missed_signal_events=proposals,
    )
