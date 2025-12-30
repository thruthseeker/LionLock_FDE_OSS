from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class SignalScores:
    repetition_loopiness: float
    novelty_entropy_proxy: float
    coherence_structure: float
    context_adherence: float
    hallucination_risk: float

    def as_dict(self) -> Dict[str, float]:
        return {
            "repetition_loopiness": self.repetition_loopiness,
            "novelty_entropy_proxy": self.novelty_entropy_proxy,
            "coherence_structure": self.coherence_structure,
            "context_adherence": self.context_adherence,
            "hallucination_risk": self.hallucination_risk,
        }


@dataclass(frozen=True)
class DerivedSignals:
    fatigue_risk_index: float
    fatigue_risk_25t: float
    fatigue_risk_50t: float
    low_conf_halluc: float
    congestion_signature: float

    def as_dict(self) -> Dict[str, float]:
        return {
            "fatigue_risk_index": self.fatigue_risk_index,
            "fatigue_risk_25t": self.fatigue_risk_25t,
            "fatigue_risk_50t": self.fatigue_risk_50t,
            "low_conf_halluc": self.low_conf_halluc,
            "congestion_signature": self.congestion_signature,
        }


@dataclass(frozen=True)
class SignalBundle:
    signal_schema_version: str
    signal_scores: SignalScores
    derived_signals: DerivedSignals
    missing_inputs: tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signal_schema_version": self.signal_schema_version,
            "signal_scores": self.signal_scores.as_dict(),
            "derived_signals": self.derived_signals.as_dict(),
            "missing_inputs": list(self.missing_inputs),
        }


@dataclass(frozen=True)
class GateDecision:
    severity: str
    decision: str
    reason_code: str | None
    aggregate_score: float
    signal_scores: Dict[str, float]
