"""How configuration reaches the runtime, and what a .env file is allowed to decide.

`docs/GATING_POLICY.md` tells operators to put `LIONLOCK_GATING_ENABLED` in a `.env` file,
so these tests pin when that file is read and what it may set.
"""

import os

import pytest

from lionlock.config import load_config, resolve_gating_enabled
from lionlock.logging.connection import build_postgres_dsn, dotenv_key_allowed

_RELEVANT = (
    "LIONLOCK_GATING_ENABLED",
    "LIONLOCK_TELEMETRY_DB_URI",
    "LIONLOCK_TELEMETRY_DB_HOST",
    "LIONLOCK_TELEMETRY_DB_PORT",
    "LIONLOCK_DB_HOST",
    "LIONLOCK_DB_PORT",
    "LIONLOCK_WRITER_PASSWORD",
    "LIONLOCK_TELEMETRY_TOKEN",
    "LIONLOCK_SQL_TOKEN",
    "HOST",
    "PORT",
    "LD_PRELOAD",
)


@pytest.fixture(autouse=True)
def _isolated_environ(monkeypatch, tmp_path):
    """load_dotenv writes straight into os.environ, so snapshot and restore the real thing."""
    before = dict(os.environ)
    for name in _RELEVANT:
        os.environ.pop(name, None)
    monkeypatch.chdir(tmp_path)
    yield
    os.environ.clear()
    os.environ.update(before)


def test_a_dotenv_gating_override_applies_to_the_first_load(tmp_path) -> None:
    """It used to be read as a side effect of building a database DSN, which happens after
    gating has already been resolved: the first load_config of a process ignored the file
    and every later one honoured it, so the same inputs gave two different decisions."""
    (tmp_path / ".env").write_text("LIONLOCK_GATING_ENABLED=false\n", encoding="utf-8")

    first = load_config(path="no-such-config.toml")["gating"]["enabled"]
    second = load_config(path="no-such-config.toml")["gating"]["enabled"]

    assert first is False
    assert second is False
    assert resolve_gating_enabled({}) is False


def test_a_dotenv_cannot_inject_a_variable_the_library_never_reads(tmp_path) -> None:
    """os.environ is inherited by subprocesses, so PATH or LD_PRELOAD must not be settable."""
    (tmp_path / ".env").write_text(
        "LIONLOCK_GATING_ENABLED=false\nLD_PRELOAD=/tmp/evil.so\n", encoding="utf-8"
    )

    load_config(path="no-such-config.toml")

    assert "LD_PRELOAD" not in os.environ
    assert os.environ.get("LIONLOCK_GATING_ENABLED") == "false"


@pytest.mark.parametrize(
    "key, allowed",
    [
        ("LIONLOCK_GATING_ENABLED", True),
        ("DO_NOT_TRACK", True),
        ("TRUST_OVERLAY_SALT", True),
        ("LD_PRELOAD", False),
        ("PATH", False),
        ("HOST", False),
    ],
)
def test_only_variables_the_library_reads_may_come_from_a_dotenv(key: str, allowed: bool) -> None:
    assert dotenv_key_allowed(key) is allowed


def test_a_generic_host_and_port_are_not_treated_as_the_database() -> None:
    """HOST and PORT name the app's own listen address on most PaaS."""
    os.environ["LIONLOCK_WRITER_PASSWORD"] = "pw"
    os.environ["HOST"] = "0.0.0.0"
    os.environ["PORT"] = "8080"

    with pytest.raises(ValueError, match="Database host missing"):
        build_postgres_dsn("writer")


def test_a_config_file_that_will_not_parse_is_fatal(tmp_path) -> None:
    """Falling back to defaults would quietly disable token auth and failsafe."""
    broken = tmp_path / "lionlock.toml"
    broken.write_text("[gating\nthresholds = ", encoding="utf-8")

    with pytest.raises(RuntimeError, match="not valid TOML"):
        load_config(path=str(broken))


def test_a_missing_config_file_is_still_non_fatal() -> None:
    assert load_config(path="no-such-config.toml")["gating"]["enabled"] is True


def test_an_explicit_sql_opt_out_survives_a_dsn_in_the_environment(tmp_path) -> None:
    """A DSN in the environment is a usable target, not an instruction to start publishing."""
    os.environ["LIONLOCK_TELEMETRY_DB_URI"] = "postgresql://u:pw@dbhost:5432/x"
    cfg_file = tmp_path / "lionlock.toml"
    cfg_file.write_text("[logging_sql]\nenabled = false\n", encoding="utf-8")

    config = load_config(path=str(cfg_file))

    assert config["logging_sql"]["enabled"] is False


def test_the_dsn_password_is_not_copied_into_the_token_field(tmp_path) -> None:
    os.environ["LIONLOCK_TELEMETRY_DB_URI"] = "postgresql://u:s3cret@dbhost:5432/x"
    cfg_file = tmp_path / "lionlock.toml"
    cfg_file.write_text('[logging]\nbackend = "sql"\n', encoding="utf-8")

    config = load_config(path=str(cfg_file))
    sql_cfg = config["logging_sql"]

    assert sql_cfg["enabled"] is True
    assert "s3cret" not in str(sql_cfg.get("token", ""))
