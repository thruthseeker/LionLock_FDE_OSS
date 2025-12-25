from dataclasses import dataclass
from typing import Dict


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
class GateDecision:
    severity: str
    decision: str
    reason_code: str | None
    aggregate_score: float
    signal_scores: Dict[str, float]
