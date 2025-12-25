from typing import Dict, Iterable

from .models import GateDecision, SignalScores

DEFAULT_THRESHOLDS: Dict[str, float] = {
    "yellow": 0.45,
    "orange": 0.65,
    "red": 0.8,
}

DEFAULT_HARD_GATE_REASONS: tuple[str, ...] = (
    "repetition_loop",
    "low_novelty",
    "low_coherence",
    "context_drift",
    "hallucination_risk",
)

REASON_CODE_MAP: Dict[str, str] = {
    "repetition_loopiness": "repetition_loop",
    "novelty_entropy_proxy": "low_novelty",
    "coherence_structure": "low_coherence",
    "context_adherence": "context_drift",
    "hallucination_risk": "hallucination_risk",
}


def severity_band(aggregate_score: float, thresholds: Dict[str, float] | None = None) -> str:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    if aggregate_score >= thresholds["red"]:
        return "red"
    if aggregate_score >= thresholds["orange"]:
        return "orange"
    if aggregate_score >= thresholds["yellow"]:
        return "yellow"
    return "green"


def _top_reason_code(scores: SignalScores) -> str:
    signal_map = scores.as_dict()
    top_signal = max(signal_map, key=signal_map.__getitem__)
    return REASON_CODE_MAP.get(top_signal, "policy_violation")


def decide_gate(
    aggregate_score: float,
    scores: SignalScores,
    thresholds: Dict[str, float] | None = None,
    gating_enabled: bool = True,
    hallucination_mode: str = "warn_only",
    hard_gate_reasons_enabled: Iterable[str] | None = None,
) -> GateDecision:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    severity = severity_band(aggregate_score, thresholds=thresholds)
    reason_code = _top_reason_code(scores)

    if (
        severity == "red"
        and hallucination_mode == "warn_only"
        and reason_code == "hallucination_risk"
    ):
        severity = "orange"

    if severity == "red" and hard_gate_reasons_enabled is not None:
        enabled_set = set(hard_gate_reasons_enabled)
        if reason_code not in enabled_set:
            severity = "orange"

    decision = "ALLOW"
    if gating_enabled:
        if severity == "red":
            decision = "BLOCK"
        elif severity in ("yellow", "orange"):
            decision = "WARN"

    return GateDecision(
        severity=severity,
        decision=decision,
        reason_code=reason_code,
        aggregate_score=aggregate_score,
        signal_scores=scores.as_dict(),
    )
