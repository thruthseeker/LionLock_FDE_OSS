import math
from typing import Dict, Iterable

from .models import (
    DerivedSignals,
    GateDecision,
    SignalBundle,
    SignalScores,
    canonical_gating_decision,
)
from .scoring import SIGNAL_SCHEMA_VERSION, aggregate_score, low_conf_halluc_score

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
    "fatigue_risk_index": "fatigue_risk",
    "low_conf_halluc": "hallucination_risk",
    "congestion_signature": "congestion_risk",
}

DERIVED_RISK_KEYS = (
    "fatigue_risk_index",
    "low_conf_halluc",
    "congestion_signature",
)

# Metadata inputs that fatigue_risk_index is computed from. None of them has a definition in this
# repo, so any of them being absent means the fatigue score is an all-defaults artifact.
FATIGUE_INPUT_KEYS = (
    "entropy_decay",
    "turn_index",
    "drift_slope",
)

TRIGGER_SIGNAL_ORDER = (
    "fatigue_risk_index",
    "congestion_signature",
    "low_conf_halluc",
    "hallucination_risk",
    "context_adherence",
    "coherence_structure",
    "novelty_entropy_proxy",
    "repetition_loopiness",
)


def severity_band(aggregate_score: float, thresholds: Dict[str, float] | None = None) -> str:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    if aggregate_score >= thresholds["red"]:
        return "red"
    if aggregate_score >= thresholds["orange"]:
        return "orange"
    if aggregate_score >= thresholds["yellow"]:
        return "yellow"
    return "green"


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_unit_interval(value: float | int | None) -> float:
    if value is None or isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return _clamp(float(value))
    return 0.0


def _safe_signal_map(raw: Dict[str, float]) -> Dict[str, float]:
    return {key: _safe_unit_interval(value) for key, value in raw.items()}


def _reason_code_for(trigger_signal: str) -> str:
    if trigger_signal in REASON_CODE_MAP:
        return REASON_CODE_MAP[trigger_signal]
    return "policy_violation"


def gating_derived_risk_keys(missing_inputs: Iterable[str]) -> tuple[str, ...]:
    """Derived signals allowed to raise the severity band.

    SE-0.4.0: ``fatigue_risk_index`` is withheld from the decision channel when any of
    ``FATIGUE_INPUT_KEYS`` is missing. Its sigmoid is uncalibrated (see the note on
    ``FATIGUE_SIGMOID_GAIN`` in scoring.py), so a caller that supplies no fatigue metadata must not
    be gated on the resulting all-defaults score. The value is still reported in the bundle for
    observability; it just cannot move a band.
    """
    if set(missing_inputs) & set(FATIGUE_INPUT_KEYS):
        return tuple(key for key in DERIVED_RISK_KEYS if key != "fatigue_risk_index")
    return DERIVED_RISK_KEYS


def _pick_by_order(values: Dict[str, float], order: Iterable[str]) -> str:
    if not values:
        return "unknown"
    best_value = -1.0
    for key in order:
        if key in values:
            best_value = max(best_value, values[key])
    if best_value < 0.0:
        return "unknown"
    for key in order:
        if values.get(key, -1.0) == best_value:
            return key
    return "unknown"


def _evaluate_policy_with_scores(
    *,
    aggregate: float,
    signal_scores: SignalScores,
    derived_signals: DerivedSignals,
    thresholds: Dict[str, float] | None,
    gating_enabled: bool,
    hallucination_mode: str,
    hard_gate_reasons_enabled: Iterable[str] | None,
    signal_bundle: SignalBundle,
) -> GateDecision:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    safe_signal_scores = _safe_signal_map(signal_scores.as_dict())
    safe_derived = _safe_signal_map(derived_signals.as_dict())
    raw_channel = _safe_unit_interval(aggregate)
    gating_keys = gating_derived_risk_keys(signal_bundle.missing_inputs)
    derived_risk_map = {key: safe_derived.get(key, 0.0) for key in gating_keys}
    derived_channel = max(derived_risk_map.values()) if derived_risk_map else 0.0
    decision_risk_score = _clamp(max(raw_channel, derived_channel))

    severity = severity_band(decision_risk_score, thresholds=thresholds)
    if derived_channel >= raw_channel:
        trigger_signal = _pick_by_order(derived_risk_map, TRIGGER_SIGNAL_ORDER)
    else:
        trigger_signal = _pick_by_order(safe_signal_scores, TRIGGER_SIGNAL_ORDER)
    reason_code = _reason_code_for(trigger_signal)

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

    gating_decision = "ALLOW"
    if gating_enabled:
        if severity == "red":
            gating_decision = "BLOCK"
        elif severity in ("yellow", "orange"):
            gating_decision = "REFRESH"

    gating_decision = canonical_gating_decision(gating_decision)
    decision = gating_decision

    return GateDecision(
        severity=severity,
        decision=decision,
        reason_code=reason_code,
        aggregate_score=raw_channel,
        signal_scores=safe_signal_scores,
        gating_decision=gating_decision,
        decision_risk_score=decision_risk_score,
        trigger_signal=trigger_signal,
        signal_bundle=signal_bundle.as_dict(),
    )


def evaluate_policy(
    bundle: SignalBundle,
    thresholds: Dict[str, float] | None = None,
    gating_enabled: bool = True,
    hallucination_mode: str = "warn_only",
    hard_gate_reasons_enabled: Iterable[str] | None = None,
) -> GateDecision:
    aggregate = aggregate_score(bundle)
    return _evaluate_policy_with_scores(
        aggregate=aggregate,
        signal_scores=bundle.signal_scores,
        derived_signals=bundle.derived_signals,
        thresholds=thresholds,
        gating_enabled=gating_enabled,
        hallucination_mode=hallucination_mode,
        hard_gate_reasons_enabled=hard_gate_reasons_enabled,
        signal_bundle=bundle,
    )


def decide_gate(
    aggregate_score: float,
    scores: SignalScores,
    thresholds: Dict[str, float] | None = None,
    gating_enabled: bool = True,
    hallucination_mode: str = "warn_only",
    hard_gate_reasons_enabled: Iterable[str] | None = None,
) -> GateDecision:
    derived_signals = DerivedSignals(
        fatigue_risk_index=0.0,
        fatigue_risk_25t=0.0,
        fatigue_risk_50t=0.0,
        low_conf_halluc=low_conf_halluc_score(scores),
        congestion_signature=0.0,
    )
    bundle = SignalBundle(
        signal_schema_version=SIGNAL_SCHEMA_VERSION,
        signal_scores=scores,
        derived_signals=derived_signals,
        # SE-0.4.0: this entry point accepts raw signal scores only and never receives fatigue
        # metadata, so the fatigue_risk_index=0.0 above is an all-defaults placeholder rather than a
        # measurement. Declaring those inputs missing keeps the placeholder out of the decision
        # channel and out of trigger attribution. Without this, fatigue_risk_index stayed in the
        # derived map and, being first in TRIGGER_SIGNAL_ORDER, won ties: an all-zero call reported
        # reason_code "fatigue_risk".
        missing_inputs=FATIGUE_INPUT_KEYS,
    )
    return _evaluate_policy_with_scores(
        aggregate=aggregate_score,
        signal_scores=scores,
        derived_signals=derived_signals,
        thresholds=thresholds,
        gating_enabled=gating_enabled,
        hallucination_mode=hallucination_mode,
        hard_gate_reasons_enabled=hard_gate_reasons_enabled,
        signal_bundle=bundle,
    )
