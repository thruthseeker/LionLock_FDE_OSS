import re
from typing import Dict

from .models import SignalScores

TOKEN_RE = re.compile(r"[A-Za-z0-9']+")

DEFAULT_SIGNAL_WEIGHTS: Dict[str, float] = {
    "repetition_loopiness": 0.30,
    "novelty_entropy_proxy": 0.25,
    "coherence_structure": 0.25,
    "context_adherence": 0.20,
    "hallucination_risk": 0.00,
}


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def score_response(prompt: str, response: str) -> SignalScores:
    prompt_tokens = tokenize(prompt)
    response_tokens = tokenize(response)

    total_tokens = len(response_tokens)
    unique_tokens = len(set(response_tokens))
    unique_ratio = _safe_ratio(unique_tokens, total_tokens)

    repetition_loopiness = _clamp(1.0 - unique_ratio)

    if total_tokens > 1:
        bigrams = list(zip(response_tokens, response_tokens[1:]))
        bigram_diversity = _safe_ratio(len(set(bigrams)), len(bigrams))
        novelty_entropy_proxy = _clamp(1.0 - bigram_diversity)
    else:
        novelty_entropy_proxy = 0.0

    sentence_chunks = [chunk for chunk in re.split(r"[.!?]+", response) if chunk.strip()]
    sentence_count = len(sentence_chunks)

    if sentence_count == 0:
        coherence_structure = 0.8
    else:
        avg_sentence_len = _safe_ratio(total_tokens, sentence_count)
        long_risk = _clamp((avg_sentence_len - 30.0) / 50.0)
        short_risk = _clamp((5.0 - avg_sentence_len) / 5.0)
        coherence_structure = _clamp(long_risk + short_risk)

    prompt_set = set(prompt_tokens)
    response_set = set(response_tokens)
    overlap_ratio = _safe_ratio(len(prompt_set & response_set), len(prompt_set))
    context_adherence = _clamp(1.0 - overlap_ratio) if prompt_set else 0.0

    hallucination_risk = _clamp((context_adherence + coherence_structure) / 2.0)

    return SignalScores(
        repetition_loopiness=repetition_loopiness,
        novelty_entropy_proxy=novelty_entropy_proxy,
        coherence_structure=coherence_structure,
        context_adherence=context_adherence,
        hallucination_risk=hallucination_risk,
    )


def aggregate_score(
    scores: SignalScores,
    weights: Dict[str, float] | None = None,
    enabled_signals: list[str] | None = None,
) -> float:
    weights = weights or DEFAULT_SIGNAL_WEIGHTS
    signal_map = scores.as_dict()
    weighted_sum = 0.0
    weight_total = 0.0
    for key, value in signal_map.items():
        if enabled_signals is not None and key not in enabled_signals:
            continue
        weight = weights.get(key, 0.0)
        weighted_sum += value * weight
        weight_total += weight
    return weighted_sum / weight_total if weight_total else 0.0
