import importlib.util
import json
from pathlib import Path

import pytest

from lionlock.core import gating, scoring
from lionlock.core.gating import DEFAULT_THRESHOLDS, decide_gate, evaluate_policy
from lionlock.core.models import SignalScores
from lionlock.core.scoring import (
    SIGNAL_SCHEMA_VERSION,
    aggregate_score,
    low_conf_halluc_score,
    score_payload,
    score_response,
)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "sample_sessions.json"
YELLOW = DEFAULT_THRESHOLDS["yellow"]

CLEAN_ANSWERS = [
    ("What is the capital of France?", "Paris is the capital of France."),
    ("How many days are in a leap year?", "A leap year has 366 days instead of the usual 365."),
    (
        "Who wrote the play Romeo and Juliet?",
        "William Shakespeare wrote Romeo and Juliet in the 1590s.",
    ),
    (
        "What is the boiling point of water at sea level in Celsius?",
        "At sea level, water boils at 100 degrees Celsius.",
    ),
    (
        "Explain what a hash function does.",
        "A hash function maps input data of any size to a fixed-size value, and the same input "
        "always produces the same output.",
    ),
    (
        "How do I list the files in a directory on Linux?",
        "Run the ls command in the directory, or use ls -la to include hidden files and details.",
    ),
    (
        "Why is the sky blue?",
        "Sunlight scatters off air molecules, and blue light scatters more than red light, so "
        "the sky looks blue.",
    ),
]


def _scores(novelty: float = 0.0, hallucination: float = 0.0) -> SignalScores:
    return SignalScores(
        repetition_loopiness=0.0,
        novelty_entropy_proxy=novelty,
        coherence_structure=0.0,
        context_adherence=0.0,
        hallucination_risk=hallucination,
    )


def _fixtures() -> list[dict]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


def test_low_conf_halluc_rises_with_hallucination_risk() -> None:
    values = [low_conf_halluc_score(_scores(hallucination=h)) for h in (0.0, 0.25, 0.5, 1.0)]
    assert values == [0.0, 0.25, 0.5, 1.0]


def test_low_conf_halluc_is_damped_for_repetitive_text() -> None:
    values = [low_conf_halluc_score(_scores(novelty=n, hallucination=0.8)) for n in (0.0, 0.5, 1.0)]
    assert values == [0.8, 0.4, 0.0]


def test_scoring_and_gating_share_one_formula() -> None:
    assert gating.low_conf_halluc_score is scoring.low_conf_halluc_score
    bundle = score_response("What is the capital of France?", "Paris is the capital of France.")
    scores = bundle.signal_scores
    gate = decide_gate(aggregate_score(scores), scores)
    expected = low_conf_halluc_score(scores)
    assert bundle.derived_signals.low_conf_halluc == expected
    assert gate.signal_bundle["derived_signals"]["low_conf_halluc"] == expected


def test_grounded_answer_is_not_flagged() -> None:
    bundle = score_response("What is the capital of France?", "Paris is the capital of France.")
    decision = evaluate_policy(bundle)
    assert decision.decision_risk_score < YELLOW
    assert decision.gating_decision == "ALLOW"


@pytest.mark.parametrize(("prompt", "response"), CLEAN_ANSWERS)
def test_clean_qa_answers_score_below_yellow(prompt: str, response: str) -> None:
    decision = evaluate_policy(score_response(prompt, response))
    assert decision.decision_risk_score < YELLOW
    assert decision.gating_decision == "ALLOW"


def test_looping_answer_is_attributed_to_repetition() -> None:
    decision = evaluate_policy(score_response("Repeat this phrase.", "Repeat this phrase. " * 6))
    assert decision.gating_decision == "REFRESH"
    assert decision.reason_code == "repetition_loop"


@pytest.mark.parametrize(
    ("turn_index", "sample"),
    list(enumerate(_fixtures())),
    ids=lambda value: f"{value['id']}-{value['label']}" if isinstance(value, dict) else None,
)
def test_quickstart_fixtures_match_their_labels(turn_index: int, sample: dict) -> None:
    bundle = score_payload(
        {
            "prompt": sample["text"],
            "response": sample["response"],
            "metadata": {"turn_index": turn_index},
        }
    )
    assert bundle is not None
    decision = evaluate_policy(bundle)
    flagged = decision.gating_decision in {"REFRESH", "BLOCK"}
    assert flagged is (sample["label"] == "FLAGGED"), (
        decision.decision_risk_score,
        decision.reason_code,
    )


def test_quickstart_summary_matches_fixture_labels(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    for name in ("LIONLOCK_GATING_ENABLED", "LIONLOCK_TELEMETRY_DB_URI"):
        monkeypatch.delenv(name, raising=False)
    spec = importlib.util.spec_from_file_location("quickstart", REPO / "examples" / "quickstart.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    labels = [sample["label"] for sample in _fixtures()]
    summary = module.run_quickstart(FIXTURES)
    assert summary == {"FLAGGED": labels.count("FLAGGED"), "CLEAN": labels.count("CLEAN")}


def test_signal_schema_version_marks_the_fixed_formula() -> None:
    assert SIGNAL_SCHEMA_VERSION == "SE-0.3.0"
    assert score_response("alpha beta", "alpha beta").signal_schema_version == "SE-0.3.0"
    gate = decide_gate(0.1, _scores())
    assert gate.signal_bundle["signal_schema_version"] == "SE-0.3.0"
