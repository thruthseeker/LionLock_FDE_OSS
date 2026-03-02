import os

from lionlock.config import DEFAULT_CONFIG, load_config, resolve_gating_enabled
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores
from lionlock.core.gating import evaluate_policy


def _high_risk_bundle() -> SignalBundle:
    return SignalBundle(
        signal_schema_version="SE-0.2.0",
        signal_scores=SignalScores(
            repetition_loopiness=1.0,
            novelty_entropy_proxy=1.0,
            coherence_structure=1.0,
            context_adherence=1.0,
            hallucination_risk=1.0,
        ),
        derived_signals=DerivedSignals(
            fatigue_risk_index=1.0,
            fatigue_risk_25t=1.0,
            fatigue_risk_50t=1.0,
            low_conf_halluc=1.0,
            congestion_signature=1.0,
        ),
        missing_inputs=(),
    )


def test_gating_disabled_is_log_only() -> None:
    decision = evaluate_policy(_high_risk_bundle(), gating_enabled=False)
    assert decision.severity == "red"
    assert decision.gating_decision == "ALLOW"


def test_gating_enabled_enforces_policy() -> None:
    decision = evaluate_policy(_high_risk_bundle(), gating_enabled=True)
    assert decision.severity == "red"
    assert decision.gating_decision == "BLOCK"


def test_load_config_preserves_default_when_env_missing(monkeypatch) -> None:
    monkeypatch.delenv("LIONLOCK_GATING_ENABLED", raising=False)
    config = load_config(path="missing-does-not-exist.toml")
    assert config["gating"]["enabled"] is True
    assert config["gating"]["enabled"] == DEFAULT_CONFIG["gating"]["enabled"]


def test_resolve_gating_enabled_env_override(monkeypatch) -> None:
    config = {"gating": {"enabled": True}}

    monkeypatch.setenv("LIONLOCK_GATING_ENABLED", "false")
    assert resolve_gating_enabled(config) is False

    monkeypatch.setenv("LIONLOCK_GATING_ENABLED", "true")
    assert resolve_gating_enabled(config) is True

    monkeypatch.setenv("LIONLOCK_GATING_ENABLED", "invalid")
    assert resolve_gating_enabled(config) is True

    monkeypatch.delenv("LIONLOCK_GATING_ENABLED", raising=False)
    assert resolve_gating_enabled({"gating": {"enabled": False}}) is False


def test_default_logging_sql_token_is_empty() -> None:
    config = load_config(path="missing-does-not-exist.toml")
    assert config["logging_sql"]["token"] == ""
