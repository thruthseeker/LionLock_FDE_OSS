import math

from lionlock.core import evaluate_policy
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores


def _bundle(
    *,
    repetition: float = 0.1,
    novelty: float = 0.1,
    coherence: float = 0.1,
    context: float = 0.1,
    hallucination: float = 0.1,
    fatigue: float = 0.1,
    low_conf_halluc: float = 0.1,
    congestion: float = 0.1,
) -> SignalBundle:
    scores = SignalScores(
        repetition_loopiness=repetition,
        novelty_entropy_proxy=novelty,
        coherence_structure=coherence,
        context_adherence=context,
        hallucination_risk=hallucination,
    )
    derived = DerivedSignals(
        fatigue_risk_index=fatigue,
        fatigue_risk_25t=fatigue,
        fatigue_risk_50t=fatigue,
        low_conf_halluc=low_conf_halluc,
        congestion_signature=congestion,
    )
    return SignalBundle(
        signal_schema_version="SE-0.2.0",
        signal_scores=scores,
        derived_signals=derived,
        missing_inputs=(),
    )


def test_derived_channel_escalates_decision() -> None:
    bundle = _bundle(
        repetition=0.05,
        novelty=0.05,
        coherence=0.05,
        context=0.05,
        hallucination=0.05,
        fatigue=0.9,
        low_conf_halluc=0.1,
        congestion=0.1,
    )
    decision = evaluate_policy(bundle)
    assert decision.decision_risk_score == 0.9
    assert decision.gating_decision == "BLOCK"
    assert decision.trigger_signal == "fatigue_risk_index"


def test_tie_break_deterministic_for_derived_signals() -> None:
    bundle = _bundle(
        fatigue=0.6,
        low_conf_halluc=0.6,
        congestion=0.6,
        repetition=0.1,
        novelty=0.1,
        coherence=0.1,
        context=0.1,
        hallucination=0.1,
    )
    decision = evaluate_policy(bundle)
    assert decision.trigger_signal == "fatigue_risk_index"


def test_tie_break_deterministic_for_raw_signals() -> None:
    bundle = _bundle(
        repetition=0.4,
        novelty=0.4,
        coherence=0.4,
        context=0.4,
        hallucination=0.4,
        fatigue=0.1,
        low_conf_halluc=0.1,
        congestion=0.1,
    )
    decision = evaluate_policy(bundle)
    assert decision.trigger_signal == "hallucination_risk"


def test_risk_score_clamped_and_finite_with_bad_inputs() -> None:
    bundle = _bundle(
        repetition=math.nan,
        novelty=math.inf,
        coherence=-1.0,
        context=0.2,
        hallucination=0.1,
        fatigue=math.inf,
        low_conf_halluc=math.nan,
        congestion=-0.5,
    )
    decision = evaluate_policy(bundle)
    assert math.isfinite(decision.decision_risk_score)
    assert 0.0 <= decision.decision_risk_score <= 1.0
