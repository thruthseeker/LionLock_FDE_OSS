"""Core scoring and gating helpers for the LionLock demo."""

from .gating import (
    DEFAULT_HARD_GATE_REASONS,
    DEFAULT_THRESHOLDS,
    decide_gate,
    evaluate_policy,
    severity_band,
)
from .models import (
    DerivedSignals,
    GateDecision,
    SignalBundle,
    SignalScores,
    canonical_gating_decision,
)
from .scoring import DEFAULT_SIGNAL_WEIGHTS, aggregate_score, score_response

__all__ = [
    "DEFAULT_HARD_GATE_REASONS",
    "DEFAULT_SIGNAL_WEIGHTS",
    "DerivedSignals",
    "DEFAULT_THRESHOLDS",
    "GateDecision",
    "SignalBundle",
    "SignalScores",
    "canonical_gating_decision",
    "aggregate_score",
    "decide_gate",
    "evaluate_policy",
    "score_response",
    "severity_band",
]
