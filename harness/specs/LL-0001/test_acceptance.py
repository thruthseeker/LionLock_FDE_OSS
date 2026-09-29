"""LL-0001 acceptance tests: one test per requirement, plus the golden comparison.

These run against whatever implementation exists. At the base commit they fail, which is the point:
the spec describes work that has not been done. ``make verify SPEC=LL-0001`` turns these into a
blocking gate.

R6 alone would be enough to catch a wrong implementation, but it cannot say *why* it is wrong. R1-R5
and R7 exist so a failure names the requirement that was missed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

SPEC_DIR = Path(__file__).resolve().parent
REPO_ROOT = SPEC_DIR.parents[2]

# The harness package and the library both have to be importable regardless of how pytest was
# invoked, and specs are loaded by path rather than as packages.
for candidate in (str(REPO_ROOT), str(REPO_ROOT / "src")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from harness.fingerprint import canonical, fingerprint  # noqa: E402
from lionlock.core.gating import decide_gate, evaluate_policy  # noqa: E402
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores  # noqa: E402
from lionlock.core.scoring import SIGNAL_SCHEMA_VERSION, score_payload, score_response  # noqa: E402

DECISION_FIELDS = (
    "decision_risk_score",
    "severity",
    "gating_decision",
    "trigger_signal",
    "reason_code",
)

FATIGUE_INPUTS = ("entropy_decay", "turn_index", "drift_slope")

NO_FATIGUE_METADATA = {"duration_ms": 180.0, "latency_window_stats": [90.0, 140.0, 210.0]}
EVERY_FATIGUE_INPUT = {"entropy_decay": 1.0, "drift_slope": 1.0, "turn_index": 50}


def _load_product_module() -> Any:
    module_spec = importlib.util.spec_from_file_location("_ll0001_product", SPEC_DIR / "product.py")
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    return json.loads((SPEC_DIR / "golden.json").read_text())


@pytest.fixture(scope="module")
def observed() -> dict[str, Any]:
    return _load_product_module().product()


def _decision_fields(decision: Any) -> dict[str, Any]:
    return {field: getattr(decision, field) for field in DECISION_FIELDS}


def _with_fatigue(bundle: SignalBundle, value: float) -> SignalBundle:
    derived = replace(
        bundle.derived_signals,
        fatigue_risk_index=value,
        fatigue_risk_25t=value,
        fatigue_risk_50t=value,
    )
    return replace(bundle, derived_signals=derived)


def test_r1_schema_version_is_se_0_4_0() -> None:
    assert SIGNAL_SCHEMA_VERSION == "SE-0.4.0"


def test_r2_signal_and_derived_values_are_unchanged(
    observed: dict[str, Any], golden: dict[str, Any]
) -> None:
    """The change is about participation in the decision, not about arithmetic."""
    baseline_cases = {case["id"]: case for case in golden["baseline"]["cases"]}
    for case in observed["cases"]:
        baseline = baseline_cases[case["id"]]
        assert canonical(case["signal_scores"]) == canonical(baseline["signal_scores"]), case["id"]
        assert canonical(case["derived_signals"]) == canonical(baseline["derived_signals"]), case[
            "id"
        ]
        assert canonical(case["aggregate_score"]) == canonical(baseline["aggregate_score"]), case[
            "id"
        ]


def test_r3_fatigue_cannot_move_the_decision_when_an_input_is_missing() -> None:
    bundle = score_response(
        "summarise the policy", "The policy is reviewed quarterly.", NO_FATIGUE_METADATA
    )
    assert set(FATIGUE_INPUTS) <= set(bundle.missing_inputs)

    floor = _decision_fields(evaluate_policy(_with_fatigue(bundle, 0.0)))
    ceiling = _decision_fields(evaluate_policy(_with_fatigue(bundle, 1.0)))

    assert floor == ceiling, (floor, ceiling)
    assert ceiling["trigger_signal"] != "fatigue_risk_index"
    assert ceiling["reason_code"] != "fatigue_risk"


def test_r4_fatigue_still_escalates_when_every_input_is_present() -> None:
    """Without this, a rule that simply disabled fatigue everywhere would pass R3."""
    bundle = SignalBundle(
        signal_schema_version=SIGNAL_SCHEMA_VERSION,
        signal_scores=SignalScores(
            repetition_loopiness=0.05,
            novelty_entropy_proxy=0.05,
            coherence_structure=0.05,
            context_adherence=0.05,
            hallucination_risk=0.05,
        ),
        derived_signals=DerivedSignals(
            fatigue_risk_index=0.9,
            fatigue_risk_25t=0.9,
            fatigue_risk_50t=0.9,
            low_conf_halluc=0.1,
            congestion_signature=0.1,
        ),
        missing_inputs=(),
    )
    decision = evaluate_policy(bundle)
    assert decision.gating_decision == "BLOCK"
    assert decision.trigger_signal == "fatigue_risk_index"


def test_r4_negative_twin_one_missing_input_stops_the_escalation() -> None:
    """Same bundle, one fatigue input declared missing: the rule is 'any', not 'all'."""
    scores = SignalScores(
        repetition_loopiness=0.05,
        novelty_entropy_proxy=0.05,
        coherence_structure=0.05,
        context_adherence=0.05,
        hallucination_risk=0.05,
    )
    derived = DerivedSignals(
        fatigue_risk_index=0.9,
        fatigue_risk_25t=0.9,
        fatigue_risk_50t=0.9,
        low_conf_halluc=0.1,
        congestion_signature=0.1,
    )
    withheld = evaluate_policy(
        SignalBundle(
            signal_schema_version=SIGNAL_SCHEMA_VERSION,
            signal_scores=scores,
            derived_signals=derived,
            missing_inputs=("entropy_decay",),
        )
    )
    assert withheld.gating_decision != "BLOCK"
    assert withheld.trigger_signal != "fatigue_risk_index"
    assert withheld.reason_code != "fatigue_risk"


def test_r5_decide_gate_declares_every_input_it_never_receives() -> None:
    probe = score_payload({"prompt": "probe prompt", "response": "probe response"})
    assert probe is not None
    expected_missing = tuple(probe.missing_inputs)
    assert len(expected_missing) == 5, expected_missing

    zeroed = SignalScores(
        repetition_loopiness=0.0,
        novelty_entropy_proxy=0.0,
        coherence_structure=0.0,
        context_adherence=0.0,
        hallucination_risk=0.0,
    )
    decision = decide_gate(0.0, zeroed)

    assert tuple(decision.signal_bundle["missing_inputs"]) == expected_missing
    assert decision.trigger_signal != "fatigue_risk_index"
    assert decision.reason_code != "fatigue_risk"


def test_r6_product_matches_the_golden_exactly(
    observed: dict[str, Any], golden: dict[str, Any]
) -> None:
    assert fingerprint(observed) == golden["expected_fingerprint"], (
        "product fingerprint does not match the golden; "
        f"got {fingerprint(observed)}, expected {golden['expected_fingerprint']}"
    )
    assert canonical(observed) == canonical(golden["expected"])


def test_r7_telemetry_doc_has_an_se_0_4_0_replay_note() -> None:
    text = (REPO_ROOT / "docs" / "TELEMETRY.md").read_text()
    assert "SE-0.4.0" in text
