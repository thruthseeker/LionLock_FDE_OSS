from datetime import datetime, timezone

from lionlock.trust_overlay.engine import (
    compute_confidence_band,
    compute_trust_score,
    detect_drift,
)


def test_trust_score_mapping_from_overall_risk() -> None:
    summary = {"overall_risk": 0.2}
    score = compute_trust_score(summary)
    assert score == 0.8


def test_confidence_band_structure() -> None:
    summary = {"overall_risk": 0.2}
    history = [0.8, 0.7, 0.9]
    band = compute_confidence_band(summary, history, window_n=3, k=1.0)
    for key in ("lower", "upper", "method", "n", "std", "k"):
        assert key in band
    assert band["method"] == "std-band"


def test_drift_dict_fields_present() -> None:
    scores = [0.9] * 80 + [0.7] * 20
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    timestamps = [now for _ in scores]
    drift = detect_drift(scores, timestamps, profile="STANDARD")
    for key in (
        "drift_detected",
        "method",
        "recent_mean",
        "baseline_mean",
        "delta",
        "threshold",
        "recent_n",
        "baseline_n",
    ):
        assert key in drift
