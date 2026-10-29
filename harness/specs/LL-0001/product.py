"""LL-0001 product: everything an SE-0.4.0 change is allowed to be observed through.

``product()`` returns the observable output of the real pipeline for the whole corpus. It reads
nothing but the corpus and the library, so two agents running it on the same commit get the same
answer regardless of how they implemented the change.

This file is part of the harness contract. An agent working LL-0001 must not edit it: if the
product changes, the golden fingerprint stops meaning anything.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lionlock.core.gating import decide_gate, evaluate_policy
from lionlock.core.models import SignalScores
from lionlock.core.scoring import SIGNAL_SCHEMA_VERSION, aggregate_score, score_payload

CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"

DECISION_FIELDS = (
    "decision_risk_score",
    "severity",
    "gating_decision",
    "trigger_signal",
    "reason_code",
)

ZERO_SCORES = SignalScores(
    repetition_loopiness=0.0,
    novelty_entropy_proxy=0.0,
    coherence_structure=0.0,
    context_adherence=0.0,
    hallucination_risk=0.0,
)


def load_payloads() -> list[dict[str, Any]]:
    corpus = json.loads(CORPUS_PATH.read_text())
    return list(corpus["payloads"])


def _decision_view(decision: Any) -> dict[str, Any]:
    return {field: getattr(decision, field) for field in DECISION_FIELDS}


def _payload_for(entry: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"prompt": entry["prompt"], "response": entry["response"]}
    if entry.get("metadata") is not None:
        payload["metadata"] = entry["metadata"]
    return payload


def product() -> dict[str, Any]:
    cases = []
    for entry in load_payloads():
        bundle = score_payload(_payload_for(entry))
        if bundle is None:
            # A rejected payload would silently shrink the product, so record it loudly instead.
            cases.append({"id": entry["id"], "rejected": True})
            continue
        aggregate = aggregate_score(bundle)
        cases.append(
            {
                "id": entry["id"],
                "signal_schema_version": bundle.signal_schema_version,
                "missing_inputs": list(bundle.missing_inputs),
                "signal_scores": bundle.signal_scores.as_dict(),
                "derived_signals": bundle.derived_signals.as_dict(),
                "aggregate_score": aggregate,
                "evaluate_policy": _decision_view(evaluate_policy(bundle)),
                "decide_gate": {
                    **_decision_view(decide_gate(aggregate, bundle.signal_scores)),
                    "missing_inputs": list(
                        decide_gate(aggregate, bundle.signal_scores).signal_bundle["missing_inputs"]
                    ),
                },
            }
        )

    all_zero = decide_gate(0.0, ZERO_SCORES)
    return {
        "spec": "LL-0001",
        "signal_schema_version": SIGNAL_SCHEMA_VERSION,
        "cases": cases,
        "decide_gate_all_zero": {
            **_decision_view(all_zero),
            "missing_inputs": list(all_zero.signal_bundle["missing_inputs"]),
        },
    }
