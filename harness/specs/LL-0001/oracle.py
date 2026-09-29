"""LL-0001 oracle: what the SE-0.4.0 product *should* be, computed without the SE-0.4.0 code.

The golden file has to be trustworthy before any implementation exists, so this module recomputes
the decision itself rather than calling ``evaluate_policy``/``decide_gate``. It mirrors
``_evaluate_policy_with_scores`` in ``src/lionlock/core/gating.py`` with one difference, which is
the whole subject of the spec: when any fatigue input is missing, ``fatigue_risk_index`` is dropped
from the derived risk map before the channel maximum and the trigger tie-break are taken.

``expected(apply_rule=False)`` must reproduce the library's current output exactly. ``make golden``
asserts that before writing the file — if the mirror has drifted from the real function, generation
fails rather than baking a wrong expectation into the golden.

Scoring is not in scope: R2 says signal and derived values do not change, so the oracle takes them
from the real scorer and only recomputes what the decision does with them.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable

from lionlock.core.gating import (
    DEFAULT_THRESHOLDS,
    DERIVED_RISK_KEYS,
    REASON_CODE_MAP,
    TRIGGER_SIGNAL_ORDER,
)
from lionlock.core.models import SignalScores
from lionlock.core.scoring import (
    SIGNAL_SCHEMA_VERSION,
    aggregate_score,
    low_conf_halluc_score,
    score_payload,
)

SE_0_4_0 = "SE-0.4.0"

# Deliberately not imported from product.py. An oracle that shares its subject's helpers can agree
# with it for the wrong reason, and specs are loaded by file path rather than as packages, so a
# relative import would not resolve anyway.
CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"

ZERO_SCORES = SignalScores(
    repetition_loopiness=0.0,
    novelty_entropy_proxy=0.0,
    coherence_structure=0.0,
    context_adherence=0.0,
    hallucination_risk=0.0,
)


def _load_payloads() -> list[dict[str, Any]]:
    return list(json.loads(CORPUS_PATH.read_text())["payloads"])


def _payload_for(entry: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"prompt": entry["prompt"], "response": entry["response"]}
    if entry.get("metadata") is not None:
        payload["metadata"] = entry["metadata"]
    return payload


# The three metadata inputs the fatigue sigmoid consumes. Named here rather than imported, because
# at the base commit the library has no such constant — that constant is part of the job.
FATIGUE_INPUT_KEYS = ("entropy_decay", "turn_index", "drift_slope")


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_unit_interval(value: Any) -> float:
    if value is None or isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return _clamp(float(value))
    return 0.0


def _safe_signal_map(raw: Dict[str, Any]) -> Dict[str, float]:
    return {key: _safe_unit_interval(value) for key, value in raw.items()}


def _severity_band(score: float) -> str:
    if score >= DEFAULT_THRESHOLDS["red"]:
        return "red"
    if score >= DEFAULT_THRESHOLDS["orange"]:
        return "orange"
    if score >= DEFAULT_THRESHOLDS["yellow"]:
        return "yellow"
    return "green"


def _pick_by_order(values: Dict[str, float], order: Iterable[str]) -> str:
    order = tuple(order)
    if not values:
        return "unknown"
    best_value = -1.0
    for key in order:
        if key in values:
            best_value = max(best_value, values[key])
    if best_value < 0.0:
        return "unknown"
    for key in order:
        if values.get(key, -1.0) == best_value:
            return key
    return "unknown"


def _gating_keys(missing_inputs: Iterable[str], *, apply_rule: bool) -> tuple[str, ...]:
    """The SE-0.4.0 rule, and the only intended difference from the current library."""
    if apply_rule and set(missing_inputs) & set(FATIGUE_INPUT_KEYS):
        return tuple(key for key in DERIVED_RISK_KEYS if key != "fatigue_risk_index")
    return DERIVED_RISK_KEYS


def _decide(
    *,
    aggregate: float,
    signal_scores: Dict[str, Any],
    derived_signals: Dict[str, Any],
    missing_inputs: Iterable[str],
    apply_rule: bool,
) -> dict[str, Any]:
    safe_scores = _safe_signal_map(signal_scores)
    safe_derived = _safe_signal_map(derived_signals)
    raw_channel = _safe_unit_interval(aggregate)

    keys = _gating_keys(missing_inputs, apply_rule=apply_rule)
    derived_risk_map = {key: safe_derived.get(key, 0.0) for key in keys}
    derived_channel = max(derived_risk_map.values()) if derived_risk_map else 0.0
    decision_risk_score = _clamp(max(raw_channel, derived_channel))

    severity = _severity_band(decision_risk_score)
    if derived_channel >= raw_channel:
        trigger_signal = _pick_by_order(derived_risk_map, TRIGGER_SIGNAL_ORDER)
    else:
        trigger_signal = _pick_by_order(safe_scores, TRIGGER_SIGNAL_ORDER)
    reason_code = REASON_CODE_MAP.get(trigger_signal, "policy_violation")

    # hallucination_mode defaults to warn_only and hard_gate_reasons_enabled to None, which is how
    # product.py calls the library.
    if severity == "red" and reason_code == "hallucination_risk":
        severity = "orange"

    gating_decision = "ALLOW"
    if severity == "red":
        gating_decision = "BLOCK"
    elif severity in ("yellow", "orange"):
        gating_decision = "REFRESH"

    return {
        "decision_risk_score": decision_risk_score,
        "severity": severity,
        "gating_decision": gating_decision,
        "trigger_signal": trigger_signal,
        "reason_code": reason_code,
    }


def _no_metadata_missing_inputs() -> tuple[str, ...]:
    """What ``score_payload`` reports when a payload carries no metadata at all.

    R5 pins ``decide_gate``'s ``missing_inputs`` to exactly this, because ``decide_gate`` receives
    no metadata either. Read from the real scorer, so the oracle can't disagree with it.
    """
    probe = score_payload({"prompt": "probe prompt", "response": "probe response"})
    assert probe is not None, "the probe payload must validate"
    return tuple(probe.missing_inputs)


def expected(*, apply_rule: bool = True) -> dict[str, Any]:
    """The full product, as it should be with (or without) the SE-0.4.0 rule."""
    zero_scores_dict = ZERO_SCORES.as_dict()
    gate_missing = _no_metadata_missing_inputs() if apply_rule else ()

    cases = []
    for entry in _load_payloads():
        bundle = score_payload(_payload_for(entry))
        if bundle is None:
            cases.append({"id": entry["id"], "rejected": True})
            continue

        aggregate = aggregate_score(bundle)
        scores_dict = bundle.signal_scores.as_dict()
        derived_dict = bundle.derived_signals.as_dict()

        # decide_gate builds its own derived signals: fatigue and congestion are hardcoded
        # placeholders, low_conf_halluc is computed from the raw scores.
        gate_derived = {
            "fatigue_risk_index": 0.0,
            "fatigue_risk_25t": 0.0,
            "fatigue_risk_50t": 0.0,
            "low_conf_halluc": low_conf_halluc_score(bundle.signal_scores),
            "congestion_signature": 0.0,
        }

        cases.append(
            {
                "id": entry["id"],
                "signal_schema_version": SE_0_4_0 if apply_rule else bundle.signal_schema_version,
                "missing_inputs": list(bundle.missing_inputs),
                "signal_scores": scores_dict,
                "derived_signals": derived_dict,
                "aggregate_score": aggregate,
                "evaluate_policy": _decide(
                    aggregate=aggregate,
                    signal_scores=scores_dict,
                    derived_signals=derived_dict,
                    missing_inputs=bundle.missing_inputs,
                    apply_rule=apply_rule,
                ),
                "decide_gate": {
                    **_decide(
                        aggregate=aggregate,
                        signal_scores=scores_dict,
                        derived_signals=gate_derived,
                        missing_inputs=gate_missing,
                        apply_rule=apply_rule,
                    ),
                    "missing_inputs": list(gate_missing),
                },
            }
        )

    all_zero_derived = {
        "fatigue_risk_index": 0.0,
        "fatigue_risk_25t": 0.0,
        "fatigue_risk_50t": 0.0,
        "low_conf_halluc": low_conf_halluc_score(ZERO_SCORES),
        "congestion_signature": 0.0,
    }
    return {
        "spec": "LL-0001",
        "signal_schema_version": SE_0_4_0 if apply_rule else SIGNAL_SCHEMA_VERSION,
        "cases": cases,
        "decide_gate_all_zero": {
            **_decide(
                aggregate=0.0,
                signal_scores=zero_scores_dict,
                derived_signals=all_zero_derived,
                missing_inputs=gate_missing,
                apply_rule=apply_rule,
            ),
            "missing_inputs": list(gate_missing),
        },
    }
