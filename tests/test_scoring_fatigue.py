import math

from lionlock.core.scoring import SIGNAL_SCHEMA_VERSION, score_response


def test_fatigue_scores_bounded() -> None:
    bundle = score_response(
        "prompt",
        "response",
        {
            "entropy_decay": 10.0,
            "turn_index": 500,
            "drift_slope": 5.0,
            "duration_ms": 120.0,
            "latency_window_stats": [90.0, 110.0, 130.0],
        },
    )

    assert bundle.signal_schema_version == SIGNAL_SCHEMA_VERSION
    assert 0.0 <= bundle.derived_signals.fatigue_risk_index <= 1.0
    assert 0.0 <= bundle.derived_signals.fatigue_risk_25t <= 1.0
    assert 0.0 <= bundle.derived_signals.fatigue_risk_50t <= 1.0
    assert bundle.derived_signals.fatigue_risk_index == bundle.derived_signals.fatigue_risk_50t


def test_fatigue_missing_inputs_defaults() -> None:
    bundle = score_response("prompt", "response", None)

    assert bundle.missing_inputs == (
        "entropy_decay",
        "turn_index",
        "drift_slope",
        "duration_ms",
        "latency_window_stats",
    )

    expected = 1.0 / (1.0 + math.exp(-4.0 * (0.0 - 1.5)))
    assert math.isclose(bundle.derived_signals.fatigue_risk_25t, expected, rel_tol=1e-9)
    assert math.isclose(bundle.derived_signals.fatigue_risk_50t, expected, rel_tol=1e-9)


def test_fatigue_partial_missing_inputs() -> None:
    bundle = score_response(
        "prompt",
        "response",
        {
            "entropy_decay": None,
            "turn_index": 10,
            "drift_slope": None,
            "duration_ms": 100.0,
        },
    )

    assert bundle.missing_inputs == (
        "entropy_decay",
        "drift_slope",
        "latency_window_stats",
    )
    assert bundle.derived_signals.fatigue_risk_25t >= bundle.derived_signals.fatigue_risk_50t


def test_fatigue_determinism() -> None:
    metadata = {
        "entropy_decay": 0.12,
        "turn_index": 7,
        "drift_slope": 0.05,
        "duration_ms": 80.0,
        "latency_window_stats": [70.0, 75.0, 82.0],
    }
    first = score_response("prompt", "response", metadata).as_dict()
    second = score_response("prompt", "response", metadata).as_dict()

    assert first == second
