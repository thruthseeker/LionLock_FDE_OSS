"""Core scoring and gating helpers for the LionLock demo."""

from .gating import DEFAULT_HARD_GATE_REASONS, DEFAULT_THRESHOLDS, decide_gate, severity_band
from .models import GateDecision, SignalScores
from .scoring import DEFAULT_SIGNAL_WEIGHTS, aggregate_score, score_response

__all__ = [
    "DEFAULT_HARD_GATE_REASONS",
    "DEFAULT_SIGNAL_WEIGHTS",
    "DEFAULT_THRESHOLDS",
    "GateDecision",
    "SignalScores",
    "aggregate_score",
    "decide_gate",
    "score_response",
    "severity_band",
]
