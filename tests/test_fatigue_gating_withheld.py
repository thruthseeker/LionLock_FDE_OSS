"""SE-0.4.0: fatigue_risk_index is reported but cannot gate while its inputs are undefined.

``entropy_decay`` and ``drift_slope`` have no definition anywhere in this repo, and real callers
supply no fatigue metadata at all, so the score they produce is an all-defaults artifact. These
tests are the evidence for that claim: the invariant test below is the one that matters, and the
positive control next to it keeps the invariant from passing vacuously.
"""

import math
from dataclasses import replace

from lionlock.core.gating import (
    DEFAULT_THRESHOLDS,
    DERIVED_RISK_KEYS,
    FATIGUE_INPUT_KEYS,
    decide_gate,
    evaluate_policy,
    gating_derived_risk_keys,
)
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores
from lionlock.core.scoring import (
    FATIGUE_SIGMOID_BIAS,
    FATIGUE_SIGMOID_GAIN,
    SIGNAL_SCHEMA_VERSION,
    score_response,
)

PROMPT = "summarise the quarterly maintenance policy"
RESPONSE = "The policy requires quarterly inspection, logging, and sign-off by the duty engineer."

# Deliberately omits entropy_decay, turn_index and drift_slope, which is what every caller in this
# repo does today.
METADATA_WITHOUT_FATIGUE_INPUTS = {
    "duration_ms": 180.0,
    "latency_window_stats": [90.0, 140.0, 210.0],
}

METADATA_WITH_EVERY_INPUT = {
    "entropy_decay": 1.0,
    "turn_index": 50,
    "drift_slope": 1.0,
    "duration_ms": 180.0,
    "latency_window_stats": [90.0, 140.0, 210.0],
}

DECISION_FIELDS = (
    "decision_risk_score",
    "severity",
    "gating_decision",
    "trigger_signal",
    "reason_code",
)


def _decision_fields(decision) -> dict:
    return {field: getattr(decision, field) for field in DECISION_FIELDS}


def _with_fatigue(bundle, value: float):
    derived = replace(
        bundle.derived_signals,
        fatigue_risk_index=value,
        fatigue_risk_25t=value,
        fatigue_risk_50t=value,
    )
    return replace(bundle, derived_signals=derived)


def test_fatigue_cannot_change_the_decision_when_inputs_are_missing() -> None:
    """The SE-0.4.0 guarantee: an undefined fatigue score moves nothing that is acted on."""
    bundle = score_response(PROMPT, RESPONSE, METADATA_WITHOUT_FATIGUE_INPUTS)
    assert set(FATIGUE_INPUT_KEYS) <= set(bundle.missing_inputs)

    floor = _decision_fields(evaluate_policy(_with_fatigue(bundle, 0.0)))
    ceiling = _decision_fields(evaluate_policy(_with_fatigue(bundle, 1.0)))

    assert floor == ceiling, (floor, ceiling)
    assert ceiling["trigger_signal"] != "fatigue_risk_index"
    assert ceiling["reason_code"] != "fatigue_risk"


def test_fatigue_still_drives_the_decision_when_every_input_is_present() -> None:
    """Positive control, so the invariant above is not passing for the wrong reason."""
    bundle = score_response(PROMPT, RESPONSE, METADATA_WITH_EVERY_INPUT)
    assert not set(FATIGUE_INPUT_KEYS) & set(bundle.missing_inputs)
    assert gating_derived_risk_keys(bundle.missing_inputs) == DERIVED_RISK_KEYS

    floor = _decision_fields(evaluate_policy(_with_fatigue(bundle, 0.0)))
    ceiling = _decision_fields(evaluate_policy(_with_fatigue(bundle, 1.0)))

    assert floor != ceiling
    assert ceiling["trigger_signal"] == "fatigue_risk_index"
    assert ceiling["severity"] == "red"


def test_fatigue_is_reported_even_though_it_cannot_gate() -> None:
    """Withholding is about the decision channel only; observability is unaffected."""
    bundle = score_response(PROMPT, RESPONSE, METADATA_WITHOUT_FATIGUE_INPUTS)
    reported = bundle.as_dict()["derived_signals"]

    assert "fatigue_risk_index" in reported
    assert reported["fatigue_risk_index"] == bundle.derived_signals.fatigue_risk_50t
    assert "fatigue_risk_index" not in gating_derived_risk_keys(bundle.missing_inputs)


def test_uncalibrated_fatigue_ceiling_sits_below_the_yellow_band() -> None:
    """With the committed constants the score cannot reach the lowest band on its own."""
    bundle = score_response(PROMPT, RESPONSE, METADATA_WITH_EVERY_INPUT)
    expected = 1.0 / (1.0 + math.exp(-FATIGUE_SIGMOID_GAIN * (1.0 - FATIGUE_SIGMOID_BIAS)))

    assert math.isclose(bundle.derived_signals.fatigue_risk_index, expected, rel_tol=1e-9)
    assert bundle.derived_signals.fatigue_risk_index < DEFAULT_THRESHOLDS["yellow"]


def test_fatigue_is_monotonic_in_each_input() -> None:
    """Raising any single input must not lower the score."""
    for key, low, high in (
        ("entropy_decay", 0.0, 1.0),
        ("turn_index", 0, 50),
        ("drift_slope", 0.0, 1.0),
    ):
        base = dict(METADATA_WITH_EVERY_INPUT)
        base.update({"entropy_decay": 0.0, "turn_index": 0, "drift_slope": 0.0})
        lower = score_response(PROMPT, RESPONSE, {**base, key: low})
        upper = score_response(PROMPT, RESPONSE, {**base, key: high})
        assert (
            upper.derived_signals.fatigue_risk_index >= lower.derived_signals.fatigue_risk_index
        ), key


def _hand_built_bundle(*, fatigue: float, missing_inputs: tuple[str, ...]) -> SignalBundle:
    """Mirrors the bundle in test_module05_derived_influence, but with missing_inputs settable."""
    return SignalBundle(
        signal_schema_version=SIGNAL_SCHEMA_VERSION,
        signal_scores=SignalScores(
            repetition_loopiness=0.05,
            novelty_entropy_proxy=0.05,
            coherence_structure=0.05,
            context_adherence=0.05,
            hallucination_risk=0.05,
        ),
        derived_signals=DerivedSignals(
            fatigue_risk_index=fatigue,
            fatigue_risk_25t=fatigue,
            fatigue_risk_50t=fatigue,
            low_conf_halluc=0.1,
            congestion_signature=0.1,
        ),
        missing_inputs=missing_inputs,
    )


def test_one_missing_fatigue_input_stops_a_hand_built_escalation() -> None:
    """Negative twin of test_module05_derived_influence.test_derived_channel_escalates_decision.

    That case drives fatigue_risk_index to 0.9 with an empty missing_inputs and gets a BLOCK on
    trigger fatigue_risk_index. Declaring a *single* fatigue input missing has to remove the whole
    channel, because the rule is "any input absent", not "all inputs absent".
    """
    escalating = evaluate_policy(_hand_built_bundle(fatigue=0.9, missing_inputs=()))
    withheld = evaluate_policy(
        _hand_built_bundle(fatigue=0.9, missing_inputs=("entropy_decay",)),
    )

    assert escalating.gating_decision == "BLOCK"
    assert escalating.trigger_signal == "fatigue_risk_index"

    assert withheld.gating_decision != "BLOCK"
    assert withheld.decision_risk_score < escalating.decision_risk_score
    assert withheld.trigger_signal != "fatigue_risk_index"
    assert withheld.reason_code != "fatigue_risk"


def test_decide_gate_does_not_attribute_an_all_zero_call_to_fatigue() -> None:
    """Regression test: decide_gate never receives fatigue metadata, so it must declare it missing.

    Before SE-0.4.0 this path built its bundle with an empty ``missing_inputs``, so the hardcoded
    fatigue_risk_index=0.0 stayed in the derived map and, being first in TRIGGER_SIGNAL_ORDER, won
    the tie: an all-zero call was reported with reason_code "fatigue_risk".
    """
    zeroed = SignalScores(
        repetition_loopiness=0.0,
        novelty_entropy_proxy=0.0,
        coherence_structure=0.0,
        context_adherence=0.0,
        hallucination_risk=0.0,
    )
    decision = decide_gate(0.0, zeroed)

    assert set(FATIGUE_INPUT_KEYS) <= set(decision.signal_bundle["missing_inputs"])
    assert decision.trigger_signal != "fatigue_risk_index"
    assert decision.reason_code != "fatigue_risk"


def test_withheld_fatigue_gating_is_deterministic() -> None:
    bundle = score_response(PROMPT, RESPONSE, METADATA_WITHOUT_FATIGUE_INPUTS)
    first = evaluate_policy(bundle)
    second = evaluate_policy(bundle)

    assert first == second
    assert gating_derived_risk_keys(bundle.missing_inputs) == gating_derived_risk_keys(
        bundle.missing_inputs
    )
