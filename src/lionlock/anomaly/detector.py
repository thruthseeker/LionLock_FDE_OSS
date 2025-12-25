from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

from lionlock.core.gating import severity_band


@dataclass
class AnomalyRecord:
    anomaly_type: str
    weight: float
    details: str | None = None
    related_request_id: str | None = None


@dataclass
class AnomalyState:
    last_aggregate: float | None = None
    last_hallucination: float | None = None


PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore (all|any|previous) instructions", re.I),
    re.compile(r"system prompt", re.I),
    re.compile(r"developer message", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"disregard (all|any|previous) instructions", re.I),
]


def _weight(config: Dict[str, Any], key: str) -> float:
    weights = config.get("weights", {}) if isinstance(config, dict) else {}
    try:
        return float(weights.get(key, 0.0))
    except Exception:
        return 0.0


def _delta(config: Dict[str, Any], key: str, fallback: float) -> float:
    try:
        return float(config.get(key, fallback))
    except Exception:
        return fallback


def _signal_score(signal_scores: Dict[str, float], key: str) -> float | None:
    value = signal_scores.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def detect_anomalies(
    *,
    prompt_text: str,
    signal_scores: Dict[str, float] | None,
    aggregate_score: float | None,
    decision: str,
    thresholds: Dict[str, float],
    gating_enabled: bool,
    config: Dict[str, Any],
    state: AnomalyState,
    request_id: str | None = None,
) -> Tuple[List[AnomalyRecord], AnomalyState]:
    anomalies: List[AnomalyRecord] = []
    scores = signal_scores or {}
    weights_cfg = config.get("weights", {}) if isinstance(config, dict) else {}
    enabled = config.get("enabled", True)
    if not enabled:
        return anomalies, state

    def add(anomaly_type: str, details: str | None = None) -> None:
        weight = _weight(weights_cfg, anomaly_type)
        if weight <= 0.0:
            return
        anomalies.append(
            AnomalyRecord(
                anomaly_type=anomaly_type,
                weight=weight,
                details=details,
                related_request_id=request_id,
            )
        )

    if not scores:
        add("scoring_nan", "signal_scores_missing")
    else:
        for key, value in scores.items():
            if value is None or not math.isfinite(value):
                add("scoring_nan", f"non_finite:{key}")
                break

    if aggregate_score is not None and math.isfinite(aggregate_score):
        if state.last_aggregate is not None:
            delta = aggregate_score - state.last_aggregate
            threshold = _delta(config, "fatigue_spike_delta", 0.25)
            if delta > threshold:
                add("fatigue_spike", f"delta={delta:.3f}")
        state.last_aggregate = aggregate_score
    else:
        add("scoring_nan", "aggregate_missing")

    hallucination_score = _signal_score(scores, "hallucination_risk")
    if hallucination_score is not None and math.isfinite(hallucination_score):
        if state.last_hallucination is not None:
            delta = hallucination_score - state.last_hallucination
            threshold = _delta(config, "hallucination_jump_delta", 0.3)
            if delta > threshold:
                add("hallucination_jump", f"delta={delta:.3f}")
        state.last_hallucination = hallucination_score

    if aggregate_score is not None and math.isfinite(aggregate_score):
        expected_severity = severity_band(aggregate_score, thresholds)
        if gating_enabled:
            if expected_severity == "red" and decision != "BLOCK":
                add("gate_mismatch", "expected_block")
            if expected_severity in ("yellow", "orange") and decision == "ALLOW":
                add("gate_mismatch", "expected_warn")
            if expected_severity == "green" and decision in ("WARN", "BLOCK"):
                add("gate_mismatch", "expected_allow")
        else:
            if decision != "ALLOW":
                add("gate_override_failure", "gating_disabled")

    if prompt_text:
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(prompt_text):
                add("prompt_injection_suspected", f"pattern={pattern.pattern}")
                break

    if aggregate_score is not None and scores:
        high_signal = any(value > 0.75 for value in scores.values() if value is not None)
        low_aggregate = aggregate_score < thresholds.get("yellow", 0.45)
        if high_signal and low_aggregate:
            add("minor_signal_drift", "high_signal_low_aggregate")

    return anomalies, state


def score_anomalies(
    anomalies: Iterable[AnomalyRecord],
    config: Dict[str, Any],
) -> Tuple[float, str]:
    total = sum(anomaly.weight for anomaly in anomalies)
    bands = config.get("severity_bands", {}) if isinstance(config, dict) else {}
    normal_max = float(bands.get("normal_max", 0.3))
    unstable_max = float(bands.get("unstable_max", 0.6))
    critical_min = float(bands.get("critical_min", 0.61))
    if total <= normal_max:
        return total, "normal"
    if total <= unstable_max:
        return total, "unstable"
    if total >= critical_min:
        return total, "critical"
    return total, "unstable"
