from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import pstdev
from typing import Any, Dict, Iterable, List, Tuple

from lionlock.core.gating import severity_band
from lionlock.trust_overlay.config import resolve_trust_logic_version
from lionlock.trust_overlay.versioning import code_fingerprint

from .schemas import ANOMALY_TYPES, AnomalyEvent, normalize_prompt_type


@dataclass
class AnomalyRecord:
    anomaly_type: str
    weight: float
    details: str | None = None
    related_request_id: str | None = None


@dataclass
class AnomalyState:
    last_aggregate: float | None = None
    last_hallucination: float | None = None
    last_fatigue: float | None = None
    reliability_history: list[float] = field(default_factory=list)
    congestion_history: list[float] = field(default_factory=list)
    first_seen_utc: str | None = None
    last_seen_utc: str | None = None


PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore (all|any|previous) instructions", re.I),
    re.compile(r"system prompt", re.I),
    re.compile(r"developer message", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"disregard (all|any|previous) instructions", re.I),
]


def _weight(config: Dict[str, Any], key: str) -> float:
    if not isinstance(config, dict):
        return 0.0
    if "weights" in config:
        weights = config.get("weights", {})
    else:
        weights = config
    if not isinstance(weights, dict):
        return 0.0
    try:
        return float(weights.get(key, 0.0))
    except Exception:
        return 0.0


def _delta(config: Dict[str, Any], key: str, fallback: float) -> float:
    try:
        return float(config.get(key, fallback))
    except Exception:
        return fallback


def _signal_score(signal_scores: Dict[str, float], key: str) -> float | None:
    value = signal_scores.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    return None


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return max(0, int(value))
    return None


def _coerce_decision(value: Any) -> str:
    if not value:
        return "UNKNOWN"
    text = str(value).strip().upper()
    # WARN is the canonical OSS value; REFRESH can be mapped to WARN if introduced later.
    if text in {"ALLOW", "WARN", "BLOCK"}:
        return text
    return "UNKNOWN"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _extract_signal_bundle(
    signal_bundle: Any,
) -> Tuple[Dict[str, float], Dict[str, float], List[str]]:
    scores: Dict[str, float] = {}
    derived: Dict[str, float] = {}
    missing_fields: List[str] = []
    if signal_bundle is None:
        missing_fields.append("signal_bundle")
        return scores, derived, missing_fields

    if hasattr(signal_bundle, "signal_scores"):
        try:
            raw_scores = signal_bundle.signal_scores
            if hasattr(raw_scores, "as_dict"):
                scores = dict(raw_scores.as_dict())
            elif isinstance(raw_scores, dict):
                scores = dict(raw_scores)
        except Exception:
            scores = {}

    if hasattr(signal_bundle, "derived_signals"):
        try:
            raw_derived = signal_bundle.derived_signals
            if hasattr(raw_derived, "as_dict"):
                derived = dict(raw_derived.as_dict())
            elif isinstance(raw_derived, dict):
                derived = dict(raw_derived)
        except Exception:
            derived = {}

    if isinstance(signal_bundle, dict):
        if isinstance(signal_bundle.get("signal_scores"), dict):
            scores = dict(signal_bundle.get("signal_scores", {}))
        if isinstance(signal_bundle.get("derived_signals"), dict):
            derived = dict(signal_bundle.get("derived_signals", {}))
        missing_inputs = signal_bundle.get("missing_inputs")
        if isinstance(missing_inputs, (list, tuple)):
            missing_fields.extend([str(item) for item in missing_inputs if item])

    return scores, derived, missing_fields


def _resolve_thresholds(thresholds: Dict[str, float] | None) -> Dict[str, float] | None:
    if not isinstance(thresholds, dict):
        return None
    required = {"yellow", "orange", "red"}
    if not required.issubset(thresholds.keys()):
        return None
    for key in required:
        value = thresholds.get(key)
        if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            return None
    return {key: float(thresholds[key]) for key in required}


def _latency_jitter_score(latencies: Iterable[Any]) -> float | None:
    values = [
        float(item)
        for item in latencies
        if isinstance(item, (int, float))
        and not isinstance(item, bool)
        and math.isfinite(item)
        and float(item) >= 0.0
    ]
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    if mean <= 0.0:
        return None
    jitter = pstdev(values)
    return _clamp(jitter / mean)


def _append_history(history: list[float], value: float, max_len: int) -> None:
    history.append(value)
    if max_len <= 0:
        return
    if len(history) > max_len:
        del history[: len(history) - max_len]


def _split_window(values: list[float]) -> Tuple[List[float], List[float]]:
    if len(values) < 2:
        return [], []
    midpoint = max(1, len(values) // 2)
    return values[:midpoint], values[midpoint:]


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def detect_anomaly_events(
    *,
    session_id: str | None,
    turn_index: int | None,
    timestamp: str | None,
    prompt_type: str | None,
    response_hash: str | None,
    signal_bundle: Any,
    gating_decision: str | None,
    decision_risk_score: float | None,
    trigger_signal: str | None = None,
    aggregate_score: float | None = None,
    latency_window_stats: Iterable[Any] | None = None,
    duration_ms: float | None = None,
    syntactic_abnormality: float | None = None,
    thresholds: Dict[str, float] | None = None,
    config: Dict[str, Any] | None = None,
    state: AnomalyState | None = None,
    prompt_text: str | None = None,
    related_request_id: str | None = None,
) -> Tuple[List[Dict[str, Any]], AnomalyState, float, str]:
    cfg = config if isinstance(config, dict) else {}
    anomaly_cfg = cfg.get("anomaly", {}) if isinstance(cfg, dict) else {}
    thresholds = thresholds or cfg.get("gating", {}).get("thresholds")
    resolved_thresholds = _resolve_thresholds(thresholds)
    gating_enabled = cfg.get("gating", {}).get("enabled", True)
    timestamp = timestamp or utc_now_iso()
    state = state or AnomalyState()

    normalized_prompt_type = normalize_prompt_type(prompt_type)
    safe_session_id = str(session_id).strip() if session_id else "unknown"
    safe_turn_index = _safe_int(turn_index)
    if safe_turn_index is None:
        safe_turn_index = 0

    decision = _coerce_decision(gating_decision)
    risk_score = _safe_float(decision_risk_score)
    if risk_score is None:
        risk_score = 0.0

    safe_aggregate = _safe_float(aggregate_score)
    if safe_aggregate is not None:
        safe_aggregate = _clamp(safe_aggregate)

    safe_duration_ms = _safe_float(duration_ms)
    safe_syntactic = _safe_float(syntactic_abnormality)

    scores, derived, bundle_missing = _extract_signal_bundle(signal_bundle)
    missing_fields: List[str] = []
    if not session_id:
        missing_fields.append("session_id")
    if turn_index is None:
        missing_fields.append("turn_index")
    if not prompt_type:
        missing_fields.append("prompt_type")
    if not response_hash:
        missing_fields.append("response_hash")
    if gating_decision is None:
        missing_fields.append("gating_decision")
    if decision_risk_score is None:
        missing_fields.append("decision_risk_score")
    if safe_aggregate is None:
        missing_fields.append("aggregate_score")
    if latency_window_stats is None:
        missing_fields.append("latency_window_stats")
    if safe_duration_ms is None:
        missing_fields.append("duration_ms")
    if safe_syntactic is None:
        missing_fields.append("syntactic_abnormality")
    missing_fields.extend(bundle_missing)
    missing_fields = sorted({field for field in missing_fields if field})

    base_details: Dict[str, Any] = {}
    if missing_fields:
        base_details["missing_fields"] = missing_fields
    if trigger_signal:
        base_details["trigger_signal"] = str(trigger_signal)
    if decision != "UNKNOWN":
        base_details["gating_decision"] = decision
    if risk_score is not None:
        base_details["decision_risk_score"] = _clamp(risk_score)

    events: List[Dict[str, Any]] = []
    weights_cfg = anomaly_cfg.get("weights", {}) if isinstance(anomaly_cfg, dict) else {}
    # Module 03 intentionally reuses trust_overlay provenance for system-wide lineage.
    trust_version = resolve_trust_logic_version(cfg)
    fingerprint = code_fingerprint()

    def add_event(anomaly_type: str, severity: float, details: Dict[str, Any]) -> None:
        if anomaly_type not in ANOMALY_TYPES:
            return
        payload = AnomalyEvent(
            anomaly_type=anomaly_type,
            severity=_clamp(severity),
            details=details,
            session_id=safe_session_id,
            turn_index=safe_turn_index,
            timestamp=timestamp,
            trust_logic_version=trust_version,
            code_fingerprint=fingerprint,
            prompt_type=normalized_prompt_type,
            response_hash=response_hash or "unknown",
            related_request_id=related_request_id,
        ).as_dict()
        events.append(payload)

    hallucination_risk = _safe_float(scores.get("hallucination_risk"))
    if hallucination_risk is not None:
        hallucination_risk = _clamp(hallucination_risk)
        if state.last_hallucination is not None:
            delta = hallucination_risk - state.last_hallucination
            threshold = _delta(anomaly_cfg, "hallucination_jump_delta", 0.3)
            if delta > threshold:
                details = dict(base_details)
                details.update(
                    {
                        "delta": round(delta, 6),
                        "threshold": float(threshold),
                        "current": hallucination_risk,
                    }
                )
                add_event("hallucination_jump", _weight(weights_cfg, "hallucination_jump"), details)
        state.last_hallucination = hallucination_risk

    fatigue_risk = _safe_float(derived.get("fatigue_risk_index"))
    if fatigue_risk is not None:
        fatigue_risk = _clamp(fatigue_risk)
        if state.last_fatigue is not None:
            delta = fatigue_risk - state.last_fatigue
            threshold = _delta(anomaly_cfg, "fatigue_spike_delta", 0.25)
            if delta > threshold:
                details = dict(base_details)
                details.update(
                    {
                        "delta": round(delta, 6),
                        "threshold": float(threshold),
                        "current": fatigue_risk,
                        "metric": "fatigue_risk_index",
                    }
                )
                add_event("fatigue_spike", _weight(weights_cfg, "fatigue_spike"), details)
        state.last_fatigue = fatigue_risk

    if safe_aggregate is not None:
        if state.last_aggregate is not None:
            delta = safe_aggregate - state.last_aggregate
            threshold = _delta(anomaly_cfg, "fatigue_spike_delta", 0.25)
            if delta > threshold and fatigue_risk is None:
                details = dict(base_details)
                details.update(
                    {
                        "delta": round(delta, 6),
                        "threshold": float(threshold),
                        "current": safe_aggregate,
                        "metric": "aggregate_score",
                    }
                )
                add_event("fatigue_spike", _weight(weights_cfg, "fatigue_spike"), details)
        state.last_aggregate = safe_aggregate

    if safe_aggregate is not None and scores:
        signal_threshold = _delta(anomaly_cfg, "minor_signal_threshold", 0.75)
        high_signal_keys = [
            key for key, value in scores.items() if _safe_float(value) is not None and value > signal_threshold
        ]
        yellow_threshold = (
            resolved_thresholds.get("yellow") if resolved_thresholds else 0.45
        )
        low_aggregate = safe_aggregate < float(yellow_threshold)
        if high_signal_keys and low_aggregate:
            details = dict(base_details)
            details.update(
                {
                    "high_signal_keys": sorted(high_signal_keys),
                    "aggregate_score": safe_aggregate,
                    "threshold": float(signal_threshold),
                }
            )
            add_event("minor_signal_drift", _weight(weights_cfg, "minor_signal_drift"), details)

    if prompt_text:
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(prompt_text):
                details = dict(base_details)
                details["pattern"] = pattern.pattern
                add_event(
                    "prompt_injection_suspected",
                    _weight(weights_cfg, "prompt_injection_suspected"),
                    details,
                )
                break

    if safe_aggregate is not None and decision != "UNKNOWN" and gating_enabled:
        expected_severity = severity_band(safe_aggregate, resolved_thresholds)
        expected_decision = "ALLOW"
        if expected_severity == "red":
            expected_decision = "BLOCK"
        elif expected_severity in ("yellow", "orange"):
            expected_decision = "WARN"
        if expected_decision != decision:
            details = dict(base_details)
            details.update(
                {
                    "expected_decision": expected_decision,
                    "actual_decision": decision,
                    "aggregate_score": safe_aggregate,
                }
            )
            add_event("gate_mismatch", _weight(weights_cfg, "gate_mismatch"), details)

    congestion_signature = _safe_float(derived.get("congestion_signature"))
    if congestion_signature is not None:
        congestion_signature = _clamp(congestion_signature)
    latency_jitter = (
        _latency_jitter_score(latency_window_stats or []) if latency_window_stats is not None else None
    )
    congestion_components = {
        "congestion_signature": congestion_signature,
        "latency_jitter": latency_jitter,
        "syntactic_abnormality": _clamp(safe_syntactic) if safe_syntactic is not None else None,
    }
    congestion_candidates = [
        value for value in congestion_components.values() if isinstance(value, (int, float))
    ]
    if congestion_candidates:
        congestion_score = _clamp(max(congestion_candidates))
        _append_history(
            state.congestion_history,
            congestion_score,
            int(anomaly_cfg.get("congestion_window_n", 20)),
        )
        congestion_threshold = _delta(anomaly_cfg, "congestion_signature_threshold", 0.6)
        if congestion_score >= congestion_threshold:
            details = dict(base_details)
            details.update(
                {
                    "congestion_score": congestion_score,
                    "threshold": float(congestion_threshold),
                }
            )
            for key, value in congestion_components.items():
                if value is not None:
                    details[key] = value
            if safe_duration_ms is not None:
                details["duration_ms"] = max(0.0, safe_duration_ms)
            add_event("model_congestion", _weight(weights_cfg, "model_congestion"), details)

    reliability_inputs = []
    if safe_aggregate is not None:
        reliability_inputs.append(safe_aggregate)
    if hallucination_risk is not None:
        reliability_inputs.append(hallucination_risk)
    if fatigue_risk is not None:
        reliability_inputs.append(fatigue_risk)
    if reliability_inputs:
        reliability = _clamp(1.0 - max(reliability_inputs))
        _append_history(
            state.reliability_history,
            reliability,
            int(anomaly_cfg.get("degradation_window_n", 20)),
        )
        history = state.reliability_history
        min_points = int(anomaly_cfg.get("degradation_min_points", 12))
        if len(history) >= min_points:
            baseline, recent = _split_window(history)
            if baseline and recent:
                baseline_mean = _mean(baseline)
                recent_mean = _mean(recent)
                delta = recent_mean - baseline_mean
                threshold = _delta(anomaly_cfg, "degradation_delta", 0.08)
                if baseline_mean - recent_mean >= threshold:
                    details = dict(base_details)
                    details.update(
                        {
                            "baseline_mean": round(baseline_mean, 6),
                            "recent_mean": round(recent_mean, 6),
                            "delta": round(delta, 6),
                            "threshold": float(threshold),
                            "window_n": len(history),
                        }
                    )
                    add_event("model_degradation", _weight(weights_cfg, "model_degradation"), details)

    severity_score, _ = score_anomaly_events(events, anomaly_cfg)

    posthoc_risk_inputs = [severity_score]
    if hallucination_risk is not None:
        posthoc_risk_inputs.append(hallucination_risk)
    if fatigue_risk is not None:
        posthoc_risk_inputs.append(fatigue_risk)
    posthoc_failure_risk = _clamp(max(posthoc_risk_inputs)) if posthoc_risk_inputs else 0.0
    warn_threshold = _delta(anomaly_cfg, "missed_warn_threshold", 0.75)
    block_threshold = _delta(anomaly_cfg, "missed_block_threshold", 0.9)
    if decision in {"ALLOW", "WARN"} and posthoc_failure_risk >= warn_threshold:
        expected_decision = "BLOCK" if posthoc_failure_risk >= block_threshold else "WARN"
        details = dict(base_details)
        details.update(
            {
                "expected_decision": expected_decision,
                "actual_decision": decision,
                "miss_reason": "threshold",
                "response_hash": response_hash or "unknown",
                "posthoc_failure_risk": posthoc_failure_risk,
                "missed_warn_threshold": float(warn_threshold),
                "missed_block_threshold": float(block_threshold),
            }
        )
        if hallucination_risk is not None:
            details["hallucination_risk"] = hallucination_risk
        if fatigue_risk is not None:
            details["fatigue_risk_index"] = fatigue_risk
        details["anomaly_severity_context"] = severity_score
        add_event("missed_signal_event", posthoc_failure_risk, details)

    final_severity_score, final_severity_tag = score_anomaly_events(events, anomaly_cfg)
    state.first_seen_utc = state.first_seen_utc or timestamp
    state.last_seen_utc = timestamp
    return events, state, final_severity_score, final_severity_tag


def score_anomaly_events(
    anomalies: Iterable[Dict[str, Any]],
    config: Dict[str, Any],
) -> Tuple[float, str]:
    total = 0.0
    for anomaly in anomalies:
        value = _safe_float(anomaly.get("severity"))
        if value is not None:
            total += value
    total = _clamp(total)
    bands = config.get("severity_bands", {}) if isinstance(config, dict) else {}
    normal_max = float(bands.get("normal_max", 0.3))
    unstable_max = float(bands.get("unstable_max", 0.6))
    critical_min = float(bands.get("critical_min", 0.61))
    if total <= normal_max:
        return total, "normal"
    if total <= unstable_max:
        return total, "unstable"
    if total >= critical_min:
        return total, "critical"
    return total, "unstable"


def monitor_turn(
    *,
    session_id: str | None,
    turn_index: int | None,
    signal_bundle: Any,
    gating_decision: str | None,
    decision_risk_score: float | None,
    config: Dict[str, Any] | None,
    prompt_type: str | None = None,
    response_hash: str | None = None,
    trigger_signal: str | None = None,
    aggregate_score: float | None = None,
    latency_window_stats: Iterable[Any] | None = None,
    duration_ms: float | None = None,
    syntactic_abnormality: float | None = None,
    prompt_text: str | None = None,
    related_request_id: str | None = None,
    state: AnomalyState | None = None,
    session_pk: int | None = None,
    timestamp: str | None = None,
) -> Tuple[List[Dict[str, Any]], AnomalyState, float, str]:
    events, next_state, severity_score, severity_tag = detect_anomaly_events(
        session_id=session_id,
        turn_index=turn_index,
        timestamp=timestamp,
        prompt_type=prompt_type,
        response_hash=response_hash,
        signal_bundle=signal_bundle,
        gating_decision=gating_decision,
        decision_risk_score=decision_risk_score,
        trigger_signal=trigger_signal,
        aggregate_score=aggregate_score,
        latency_window_stats=latency_window_stats,
        duration_ms=duration_ms,
        syntactic_abnormality=syntactic_abnormality,
        thresholds=(config or {}).get("gating", {}).get("thresholds") if config else None,
        config=config,
        state=state,
        prompt_text=prompt_text,
        related_request_id=related_request_id,
    )
    if not events or not isinstance(config, dict):
        return events, next_state, severity_score, severity_tag

    anomaly_cfg = config.get("anomaly", {}) if isinstance(config, dict) else {}
    if not anomaly_cfg.get("enabled", True):
        return events, next_state, severity_score, severity_tag

    from lionlock.logging import anomaly_sql, sql_telemetry

    first_seen = next_state.first_seen_utc or timestamp or utc_now_iso()
    last_seen = next_state.last_seen_utc or timestamp or first_seen
    anomaly_sql.record_anomalies(
        anomaly_cfg,
        session_id=str(session_id or "unknown"),
        session_pk=session_pk,
        timestamp_utc=last_seen,
        anomalies=events,
        anomaly_count=len(events),
        severity_score=severity_score,
        severity_tag=severity_tag,
        first_seen_utc=first_seen,
        last_seen_utc=last_seen,
    )

    sql_cfg = dict(config.get("logging_sql", {}))
    telemetry_cfg = config.get("telemetry", {})
    if "sessions_table" not in sql_cfg and telemetry_cfg:
        sql_cfg["sessions_table"] = telemetry_cfg.get("sessions_table", "lionlock_sessions")
    if sql_cfg.get("enabled"):
        sql_telemetry.update_session_anomalies(
            sql_cfg,
            session_id=str(session_id or "unknown"),
            session_pk=session_pk,
            anomaly_count=len(events),
            severity_score=severity_score,
            severity_tag=severity_tag,
        )
    return events, next_state, severity_score, severity_tag


def detect_anomalies(
    *,
    prompt_text: str,
    signal_scores: Dict[str, float] | None,
    aggregate_score: float | None,
    decision: str,
    thresholds: Dict[str, float],
    gating_enabled: bool,
    config: Dict[str, Any],
    state: AnomalyState,
    request_id: str | None = None,
) -> Tuple[List[AnomalyRecord], AnomalyState]:
    anomalies: List[AnomalyRecord] = []
    scores = signal_scores or {}
    weights_cfg = config.get("weights", {}) if isinstance(config, dict) else {}
    enabled = config.get("enabled", True)
    if not enabled:
        return anomalies, state

    def add(anomaly_type: str, details: str | None = None) -> None:
        weight = _weight(weights_cfg, anomaly_type)
        if weight <= 0.0:
            return
        anomalies.append(
            AnomalyRecord(
                anomaly_type=anomaly_type,
                weight=weight,
                details=details,
                related_request_id=request_id,
            )
        )

    if not scores:
        add("scoring_nan", "signal_scores_missing")
    else:
        for key, value in scores.items():
            if value is None or not math.isfinite(value):
                add("scoring_nan", f"non_finite:{key}")
                break

    if aggregate_score is not None and math.isfinite(aggregate_score):
        if state.last_aggregate is not None:
            delta = aggregate_score - state.last_aggregate
            threshold = _delta(config, "fatigue_spike_delta", 0.25)
            if delta > threshold:
                add("fatigue_spike", f"delta={delta:.3f}")
        state.last_aggregate = aggregate_score
    else:
        add("scoring_nan", "aggregate_missing")

    hallucination_score = _signal_score(scores, "hallucination_risk")
    if hallucination_score is not None and math.isfinite(hallucination_score):
        if state.last_hallucination is not None:
            delta = hallucination_score - state.last_hallucination
            threshold = _delta(config, "hallucination_jump_delta", 0.3)
            if delta > threshold:
                add("hallucination_jump", f"delta={delta:.3f}")
        state.last_hallucination = hallucination_score

    if aggregate_score is not None and math.isfinite(aggregate_score):
        expected_severity = severity_band(aggregate_score, thresholds)
        if gating_enabled:
            if expected_severity == "red" and decision != "BLOCK":
                add("gate_mismatch", "expected_block")
            if expected_severity in ("yellow", "orange") and decision == "ALLOW":
                add("gate_mismatch", "expected_warn")
            if expected_severity == "green" and decision in ("WARN", "BLOCK"):
                add("gate_mismatch", "expected_allow")
        else:
            if decision != "ALLOW":
                add("gate_override_failure", "gating_disabled")

    if prompt_text:
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(prompt_text):
                add("prompt_injection_suspected", f"pattern={pattern.pattern}")
                break

    if aggregate_score is not None and scores:
        high_signal = any(value > 0.75 for value in scores.values() if value is not None)
        low_aggregate = aggregate_score < thresholds.get("yellow", 0.45)
        if high_signal and low_aggregate:
            add("minor_signal_drift", "high_signal_low_aggregate")

    return anomalies, state


def score_anomalies(
    anomalies: Iterable[AnomalyRecord],
    config: Dict[str, Any],
) -> Tuple[float, str]:
    total = sum(anomaly.weight for anomaly in anomalies)
    bands = config.get("severity_bands", {}) if isinstance(config, dict) else {}
    normal_max = float(bands.get("normal_max", 0.3))
    unstable_max = float(bands.get("unstable_max", 0.6))
    critical_min = float(bands.get("critical_min", 0.61))
    if total <= normal_max:
        return total, "normal"
    if total <= unstable_max:
        return total, "unstable"
    if total >= critical_min:
        return total, "critical"
    return total, "unstable"
