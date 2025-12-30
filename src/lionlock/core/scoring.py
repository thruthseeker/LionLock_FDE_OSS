import math
import re
from statistics import pstdev
from typing import Dict

from .models import DerivedSignals, SignalBundle, SignalScores

TOKEN_RE = re.compile(r"[A-Za-z0-9']+")

SIGNAL_SCHEMA_VERSION = "SE-0.2.0"

DEFAULT_SIGNAL_WEIGHTS: Dict[str, float] = {
    "repetition_loopiness": 0.30,
    "novelty_entropy_proxy": 0.25,
    "coherence_structure": 0.25,
    "context_adherence": 0.20,
    "hallucination_risk": 0.00,
}

FATIGUE_SIGMOID_GAIN = 4.0
FATIGUE_SIGMOID_BIAS = 1.5
FATIGUE_WEIGHTS = {
    "entropy_decay": 0.4,
    "turns": 0.4,
    "drift": 0.2,
}


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _sigmoid(value: float, gain: float, bias: float) -> float:
    z = -gain * (value - bias)
    if z > 60.0:
        return 0.0
    if z < -60.0:
        return 1.0
    return 1.0 / (1.0 + math.exp(z))


def _append_missing(missing_inputs: list[str], key: str) -> None:
    if key not in missing_inputs:
        missing_inputs.append(key)


def _finalize_missing_inputs(missing_inputs: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for key in missing_inputs:
        if key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return tuple(ordered)


def _get_unit_interval(
    metadata: dict | None,
    key: str,
    *,
    missing_inputs: list[str],
) -> float:
    value = metadata.get(key) if metadata else None
    if isinstance(value, bool):
        value = None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return _clamp(float(value))
    _append_missing(missing_inputs, key)
    return 0.0


def _get_turn_index(metadata: dict | None, *, missing_inputs: list[str]) -> int:
    value = metadata.get("turn_index") if metadata else None
    if isinstance(value, bool):
        value = None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return max(0, int(value))
    _append_missing(missing_inputs, "turn_index")
    return 0


def _get_duration_ms(metadata: dict | None, *, missing_inputs: list[str]) -> float:
    value = metadata.get("duration_ms") if metadata else None
    if isinstance(value, bool):
        value = None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return max(0.0, float(value))
    _append_missing(missing_inputs, "duration_ms")
    return 0.0


def _get_latency_window(
    metadata: dict | None,
    *,
    missing_inputs: list[str],
) -> list[float]:
    value = metadata.get("latency_window_stats") if metadata else None
    if not isinstance(value, list):
        _append_missing(missing_inputs, "latency_window_stats")
        return []
    filtered = [
        float(item)
        for item in value
        if isinstance(item, (int, float))
        and not isinstance(item, bool)
        and math.isfinite(item)
        and float(item) >= 0.0
    ]
    if not filtered:
        _append_missing(missing_inputs, "latency_window_stats")
        return []
    return filtered


def _normalized_turn_count(turn_index: float, cap: float) -> float:
    safe_turn = max(0.0, turn_index)
    return min(safe_turn, cap) / cap


def _fatigue_risk_score(
    *,
    entropy_decay: float,
    turn_index: float,
    drift_slope: float,
    turn_cap: float,
) -> float:
    normalized_turns = _normalized_turn_count(turn_index, turn_cap)
    weighted = (
        FATIGUE_WEIGHTS["entropy_decay"] * entropy_decay
        + FATIGUE_WEIGHTS["turns"] * normalized_turns
        + FATIGUE_WEIGHTS["drift"] * drift_slope
    )
    return _clamp(_sigmoid(weighted, FATIGUE_SIGMOID_GAIN, FATIGUE_SIGMOID_BIAS))


def _latency_jitter_score(latencies: list[float]) -> float:
    if len(latencies) < 2:
        return 0.0
    mean = sum(latencies) / len(latencies)
    if mean <= 0.0:
        return 0.0
    jitter = pstdev(latencies)
    return _clamp(jitter / mean)


def _low_conf_halluc(scores: SignalScores) -> float:
    entropy_high = _clamp(1.0 - scores.novelty_entropy_proxy)
    hallucination_low = _clamp(1.0 - scores.hallucination_risk)
    return _clamp(entropy_high * hallucination_low)


def _congestion_signature(
    latencies: list[float],
    scores: SignalScores,
) -> float:
    jitter = _latency_jitter_score(latencies)
    entropy_instability = scores.novelty_entropy_proxy
    syntax_proxy = scores.coherence_structure
    return _clamp(jitter * entropy_instability * syntax_proxy)


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def _score_raw_signals(prompt: str, response: str) -> SignalScores:
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


def score_response(prompt: str, response: str, metadata: dict | None = None) -> SignalBundle:
    missing_inputs: list[str] = []

    entropy_decay = _get_unit_interval(
        metadata,
        "entropy_decay",
        missing_inputs=missing_inputs,
    )
    turn_index = _get_turn_index(metadata, missing_inputs=missing_inputs)
    drift_slope = _get_unit_interval(
        metadata,
        "drift_slope",
        missing_inputs=missing_inputs,
    )
    duration_ms = _get_duration_ms(metadata, missing_inputs=missing_inputs)
    latency_window_stats = _get_latency_window(metadata, missing_inputs=missing_inputs)

    signal_scores = _score_raw_signals(prompt, response)

    fatigue_risk_25t = _fatigue_risk_score(
        entropy_decay=entropy_decay,
        turn_index=turn_index,
        drift_slope=drift_slope,
        turn_cap=25.0,
    )
    fatigue_risk_50t = _fatigue_risk_score(
        entropy_decay=entropy_decay,
        turn_index=turn_index,
        drift_slope=drift_slope,
        turn_cap=50.0,
    )
    _ = duration_ms

    derived_signals = DerivedSignals(
        fatigue_risk_index=fatigue_risk_50t,
        fatigue_risk_25t=fatigue_risk_25t,
        fatigue_risk_50t=fatigue_risk_50t,
        low_conf_halluc=_low_conf_halluc(signal_scores),
        congestion_signature=_congestion_signature(latency_window_stats, signal_scores),
    )

    final_missing_inputs = _finalize_missing_inputs(missing_inputs)
    return SignalBundle(
        signal_schema_version=SIGNAL_SCHEMA_VERSION,
        signal_scores=signal_scores,
        derived_signals=derived_signals,
        missing_inputs=final_missing_inputs,
    )


def aggregate_score(
    scores: SignalScores | SignalBundle,
    weights: Dict[str, float] | None = None,
    enabled_signals: list[str] | None = None,
) -> float:
    weights = weights or DEFAULT_SIGNAL_WEIGHTS
    signal_scores = scores.signal_scores if isinstance(scores, SignalBundle) else scores
    signal_map = signal_scores.as_dict()
    weighted_sum = 0.0
    weight_total = 0.0
    for key, value in signal_map.items():
        if enabled_signals is not None and key not in enabled_signals:
            continue
        weight = weights.get(key, 0.0)
        weighted_sum += value * weight
        weight_total += weight
    return weighted_sum / weight_total if weight_total else 0.0
