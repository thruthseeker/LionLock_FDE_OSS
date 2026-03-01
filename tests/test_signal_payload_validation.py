import logging

import pytest

from lionlock.core import scoring


def test_valid_payload_passes_validation_boundary() -> None:
    payload = {
        "prompt": "summarize this",
        "response": "This is a concise answer.",
        "metadata": {
            "entropy_decay": 0.2,
            "drift_slope": 0.3,
            "turn_index": 2,
            "duration_ms": 11,
            "latency_window_stats": [10.0, 12.5],
        },
    }
    bundle = scoring.score_payload(payload)
    assert bundle is not None
    assert bundle.signal_scores.coherence_structure >= 0.0


def test_invalid_payload_rejected_and_does_not_reach_scorer(monkeypatch, caplog) -> None:
    invalid_payload = {
        "prompt": "prompt",
        "response": "response",
        "metadata": {"turn_index": "not-an-int"},
    }

    def _unexpected(*args, **kwargs):  # pragma: no cover - defensive
        raise AssertionError("core scorer should not be called")

    monkeypatch.setattr(scoring, "_score_response_core", _unexpected)

    with caplog.at_level(logging.WARNING):
        result = scoring.score_payload(invalid_payload)

    assert result is None
    assert "Signal payload rejected by validation" in caplog.text


def test_score_response_raises_for_invalid_payload() -> None:
    with pytest.raises(ValueError):
        scoring.score_response("ok", "also ok", metadata={"turn_index": "bad"})
