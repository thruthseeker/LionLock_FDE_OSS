"""evaluate_policy must apply the weights a caller passes, so logged config hashes are true."""

from __future__ import annotations

from lionlock.core.gating import evaluate_policy
from lionlock.core.scoring import DEFAULT_SIGNAL_WEIGHTS, aggregate_score, score_response

PROMPT = "What is the capital of France?"
REPLY = "Paris. Paris. Paris. Paris. Paris is the capital, the capital, the capital of France."


def test_default_weights_are_unchanged() -> None:
    bundle = score_response(PROMPT, REPLY)
    assert evaluate_policy(bundle).decision_risk_score == aggregate_score(bundle)
    assert evaluate_policy(
        bundle, weights=dict(DEFAULT_SIGNAL_WEIGHTS), enabled_signals=list(DEFAULT_SIGNAL_WEIGHTS)
    ) == evaluate_policy(bundle)


def test_custom_weights_change_the_decision_score() -> None:
    bundle = score_response(PROMPT, REPLY)
    only_repetition = {name: 0.0 for name in DEFAULT_SIGNAL_WEIGHTS}
    only_repetition["repetition_loopiness"] = 1.0
    custom = evaluate_policy(bundle, weights=only_repetition)
    assert custom.decision_risk_score == aggregate_score(bundle, weights=only_repetition)
    assert custom.decision_risk_score != evaluate_policy(bundle).decision_risk_score


def test_enabled_signals_restrict_the_score() -> None:
    bundle = score_response(PROMPT, REPLY)
    restricted = evaluate_policy(bundle, enabled_signals=["context_adherence"])
    assert restricted.decision_risk_score == aggregate_score(
        bundle, enabled_signals=["context_adherence"]
    )
