"""Configuration must not be changed by files or variables meant for something else."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lionlock import config as lionlock_config
from lionlock.logging import connection

ENV_NAMES = (
    "LIONLOCK_GATING_ENABLED",
    "LIONLOCK_TELEMETRY_ENDPOINT",
    "LIONLOCK_TELEMETRY_UPLOAD",
    "LIONLOCK_DB_HOST",
    "LIONLOCK_DB_PORT",
    "LIONLOCK_TELEMETRY_DB_HOST",
    "LIONLOCK_TELEMETRY_DB_PORT",
    "LIONLOCK_TELEMETRY_DB_URI",
    "LIONLOCK_WRITER_PASSWORD",
    "LIONLOCK_TELEMETRY_DB_PASSWORD",
    "LIONLOCK_TELEMETRY_TOKEN",
    "LIONLOCK_SQL_TOKEN",
    "HOST",
    "PORT",
)


@pytest.fixture(autouse=True)
def _clean_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(connection, "_repo_root", lambda: tmp_path / "no-repo")


def test_implicit_dotenv_cannot_switch_gating_or_uploads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text(
        "LIONLOCK_GATING_ENABLED=false\n"
        "LIONLOCK_TELEMETRY_UPLOAD=on\n"
        "LIONLOCK_TELEMETRY_ENDPOINT=https://collector.example\n"
        "LIONLOCK_DB_HOST=db.internal\n"
    )
    try:
        assert connection.load_dotenv() is True
        assert "LIONLOCK_GATING_ENABLED" not in os.environ
        assert "LIONLOCK_TELEMETRY_UPLOAD" not in os.environ
        assert "LIONLOCK_TELEMETRY_ENDPOINT" not in os.environ
        assert os.environ["LIONLOCK_DB_HOST"] == "db.internal"
        assert lionlock_config.load_config("missing.toml")["gating"]["enabled"] is True
    finally:
        os.environ.pop("LIONLOCK_DB_HOST", None)


def test_explicit_dotenv_path_is_loaded_in_full(tmp_path: Path) -> None:
    env_file = tmp_path / "chosen.env"
    env_file.write_text("LIONLOCK_TELEMETRY_ENDPOINT=https://collector.example\n")
    try:
        assert connection.load_dotenv(env_file) is True
        assert os.environ["LIONLOCK_TELEMETRY_ENDPOINT"] == "https://collector.example"
    finally:
        os.environ.pop("LIONLOCK_TELEMETRY_ENDPOINT", None)


def test_generic_host_and_port_are_never_used_for_the_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LIONLOCK_WRITER_PASSWORD", "pw")
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "8080")
    with pytest.raises(ValueError, match="Database host missing"):
        connection.build_postgres_dsn("writer")


def test_database_credentials_alone_do_not_enable_sql_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LIONLOCK_WRITER_PASSWORD", "pw")
    monkeypatch.setenv("LIONLOCK_DB_HOST", "db.internal")
    monkeypatch.setenv("LIONLOCK_TELEMETRY_DB_URI", "postgresql://u:pw@dbhost:5432/x")
    config = lionlock_config.load_config("missing.toml")
    sql_cfg = config["logging_sql"]
    assert sql_cfg["enabled"] is False
    assert "pw" not in str(sql_cfg.get("token", ""))
    assert "pw" not in str(sql_cfg.get("uri", ""))


def test_explicit_opt_in_takes_the_uri_from_the_environment_without_copying_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LIONLOCK_TELEMETRY_DB_URI", "postgresql://u:pw@dbhost:5432/x")
    toml = tmp_path / "lionlock.toml"
    toml.write_text('[logging]\nbackend = "both"\n\n[logging_sql]\nenabled = true\n')
    config = lionlock_config.load_config(str(toml))
    sql_cfg = config["logging_sql"]
    assert sql_cfg["enabled"] is True
    assert sql_cfg["uri"] == "postgresql://u:pw@dbhost:5432/x"
    assert sql_cfg["token"] == ""


def test_a_broken_config_file_is_an_error_not_silent_defaults(tmp_path: Path) -> None:
    toml = tmp_path / "lionlock.toml"
    toml.write_text("[logging_sql.token_auth]\nenabled = true\nmode = required\n")
    with pytest.raises(ValueError, match="cannot load"):
        lionlock_config.load_config(str(toml))


def test_a_missing_config_file_still_uses_defaults() -> None:
    config = lionlock_config.load_config("does-not-exist.toml")
    assert config["logging_sql"]["enabled"] is False
