import pytest

from lionlock.logging.event_log import config_hash_from
from lionlock.replay import cli, policy_registry


def _write_registry(tmp_path) -> str:
    policy_path = tmp_path / "policies.toml"
    policy_path.write_text(
        (
            '[policies."GC-0.3.1"]\n'
            "gating.enabled = true\n"
            'gating.hallucination_mode = "warn_only"\n'
            "gating.thresholds.yellow = 0.40\n"
            "gating.thresholds.orange = 0.60\n"
            "gating.thresholds.red = 0.80\n"
            "signals.enabled = [\n"
            '  "repetition_loopiness",\n'
            '  "novelty_entropy_proxy",\n'
            '  "coherence_structure",\n'
            '  "context_adherence",\n'
            '  "hallucination_risk",\n'
            "]\n"
            '[policies."GC-0.3.1".signals.weights]\n'
            "repetition_loopiness = 0.30\n"
            "novelty_entropy_proxy = 0.25\n"
            "coherence_structure = 0.25\n"
            "context_adherence = 0.20\n"
            "hallucination_risk = 0.00\n"
        ),
        encoding="utf-8",
    )
    return str(policy_path)


def test_policy_registry_resolves_deterministically(tmp_path) -> None:
    registry_path = _write_registry(tmp_path)
    bundle = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)
    bundle_again = policy_registry.resolve_policy("GC-0.3.1", registry_path=registry_path)
    assert bundle.config_hash == bundle_again.config_hash
    assert bundle.config_hash == config_hash_from(bundle.config)
    assert bundle.config["gating"]["thresholds"]["yellow"] == 0.40


def test_policy_registry_rejects_invalid_version() -> None:
    with pytest.raises(ValueError):
        policy_registry.validate_policy_version("policies.toml")


def test_policy_registry_requires_known_version(tmp_path) -> None:
    registry_path = _write_registry(tmp_path)
    with pytest.raises(KeyError):
        policy_registry.resolve_policy("GC-9.9.9", registry_path=registry_path)


def test_cli_missing_policy_fails(tmp_path) -> None:
    registry_path = _write_registry(tmp_path)
    exit_code = cli.run(
        [
            "--db",
            "sqlite:///:memory:",
            "--policy",
            "GC-9.9.9",
            "--policy-registry",
            registry_path,
        ]
    )
    assert exit_code == 2
