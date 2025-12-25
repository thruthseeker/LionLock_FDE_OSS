from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import pstdev
from typing import Any, Iterable

from .config import (
    DEFAULT_PROFILE,
    DEFAULTS,
    DRIFT_THRESHOLDS_BY_PROFILE,
    PROFILE_THRESHOLDS,
    resolve_profile,
)


@dataclass(frozen=True)
class DriftResult:
    drift_detected: bool
    method: str
    recent_mean: float
    baseline_mean: float
    delta: float
    threshold: float
    recent_n: int
    baseline_n: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "drift_detected": self.drift_detected,
            "method": self.method,
            "recent_mean": self.recent_mean,
            "baseline_mean": self.baseline_mean,
            "delta": self.delta,
            "threshold": self.threshold,
            "recent_n": self.recent_n,
            "baseline_n": self.baseline_n,
        }


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def compute_trust_score(
    derived_signals: dict[str, Any],
    history: Iterable[float] | None = None,
    profile: str | None = None,
) -> float:
    """Compute trust score from overall risk (v1 rule)."""
    _ = history
    _ = profile
    overall_risk = derived_signals.get("overall_risk")
    if overall_risk is None:
        overall_risk = derived_signals.get("fatigue_score")
    if overall_risk is None:
        raise ValueError("signal_summary missing overall_risk or fatigue_score")
    return _clamp(1.0 - float(overall_risk), 0.0, 1.0)


def map_label(score: float, profile: str | None = None) -> str:
    profile = resolve_profile(profile or DEFAULT_PROFILE)
    thresholds = PROFILE_THRESHOLDS[profile]
    if score >= thresholds["TRUSTED"]:
        return "TRUSTED"
    if score >= thresholds["MONITOR"]:
        return "MONITOR"
    if score >= thresholds["AT_RISK"]:
        return "AT_RISK"
    return "UNTRUSTED"


def compute_volatility(score_history: Iterable[float], window_n: int | None = None) -> float:
    window = list(score_history)[-int(window_n or DEFAULTS["volatility_window_n"]) :]
    if len(window) < 2:
        return 0.0
    return _clamp(float(pstdev(window)), 0.0, 1.0)


def compute_confidence_band(
    derived_signals: dict[str, Any],
    score_history: Iterable[float],
    window_n: int | None = None,
    k: float | None = None,
) -> dict[str, Any]:
    scores = list(score_history)
    window_size = int(window_n or DEFAULTS["score_window_n"])
    window = scores[-window_size:] if window_size > 0 else scores
    std = float(pstdev(window)) if len(window) > 1 else 0.0
    current = scores[-1] if scores else compute_trust_score(derived_signals)
    k_value = float(k if k is not None else 1.0)
    lower = _clamp(current - k_value * std)
    upper = _clamp(current + k_value * std)
    return {
        "lower": lower,
        "upper": upper,
        "method": "std-band",
        "n": len(window),
        "std": std,
        "k": k_value,
    }


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def detect_drift(
    score_history: Iterable[float],
    timestamps: Iterable[Any],
    profile: str | None = None,
    lookback_days: int | None = None,
    min_points: int | None = None,
) -> dict[str, Any]:
    profile = resolve_profile(profile or DEFAULT_PROFILE)
    threshold = DRIFT_THRESHOLDS_BY_PROFILE[profile]
    scores = list(score_history)
    ts_list = list(timestamps)
    if ts_list and len(ts_list) == len(scores):
        parsed_pairs = [(_parse_timestamp(ts), score) for ts, score in zip(ts_list, scores)]
        parsed: list[tuple[datetime, float]] = [
            (ts, score) for ts, score in parsed_pairs if ts is not None
        ]
        if parsed:
            latest = parsed[-1][0]
            cutoff = latest - timedelta(days=int(lookback_days or DEFAULTS["drift_lookback_days"]))
            parsed = [(ts, score) for ts, score in parsed if ts >= cutoff]
            scores = [score for _, score in parsed]
    min_points = int(min_points or DEFAULTS["drift_min_points"])
    if len(scores) < min_points:
        return DriftResult(
            drift_detected=False,
            method="two_window_mean",
            recent_mean=0.0,
            baseline_mean=0.0,
            delta=0.0,
            threshold=threshold,
            recent_n=0,
            baseline_n=0,
        ).as_dict()

    recent_n = min(20, len(scores))
    baseline_n = min(80, len(scores) - recent_n)
    if baseline_n <= 0 or recent_n <= 0:
        return DriftResult(
            drift_detected=False,
            method="two_window_mean",
            recent_mean=0.0,
            baseline_mean=0.0,
            delta=0.0,
            threshold=threshold,
            recent_n=recent_n,
            baseline_n=baseline_n,
        ).as_dict()

    recent_scores = scores[-recent_n:]
    baseline_scores = scores[-(recent_n + baseline_n) : -recent_n]
    recent_mean = sum(recent_scores) / recent_n
    baseline_mean = sum(baseline_scores) / baseline_n
    delta = recent_mean - baseline_mean
    drift_detected = delta <= threshold

    return DriftResult(
        drift_detected=drift_detected,
        method="two_window_mean",
        recent_mean=recent_mean,
        baseline_mean=baseline_mean,
        delta=delta,
        threshold=threshold,
        recent_n=recent_n,
        baseline_n=baseline_n,
    ).as_dict()


def assign_badge(score: float, volatility: float, drift: dict[str, Any]) -> str:
    total_points = int(drift.get("recent_n", 0)) + int(drift.get("baseline_n", 0))
    if total_points < int(DEFAULTS["drift_min_points"]):
        return "INSUFFICIENT_DATA"
    if drift.get("drift_detected"):
        return "DRIFTING"
    if volatility >= float(DEFAULTS["volatility_spike_threshold"]):
        return "VOLATILE"
    threshold = drift.get("threshold")
    delta = drift.get("delta")
    if isinstance(threshold, (int, float)) and isinstance(delta, (int, float)):
        if delta > threshold / 2.0 and score >= drift.get("recent_mean", score):
            return "RECOVERING"
    return "STABLE"


def trigger_flags(
    score: float,
    volatility: float,
    drift: dict[str, Any],
    profile: str | None,
) -> list[str]:
    flags: list[str] = []
    label = map_label(score, profile=profile)
    if label in {"AT_RISK", "UNTRUSTED"}:
        flags.append("score_below_threshold")
    if drift.get("drift_detected"):
        flags.append("drift_detected")
    if volatility >= float(DEFAULTS["volatility_spike_threshold"]):
        flags.append("volatility_spike")
    return flags
