"""Per-event SQL telemetry work must not rebuild the token verifier or re-read .env each time."""

from __future__ import annotations

from pathlib import Path

import pytest

from lionlock.logging import connection, token_auth


def test_the_token_verifier_is_built_once_per_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LIONLOCK_LOG_TOKEN_HASHES", raising=False)
    monkeypatch.delenv("LIONLOCK_LOG_TOKEN_DB_URI", raising=False)
    monkeypatch.setattr(token_auth, "_VERIFIER_CACHE", {})
    built: list[dict] = []
    real = token_auth.build_verifier

    def counting(cfg):  # type: ignore[no-untyped-def]
        built.append(dict(cfg or {}))
        return real(cfg)

    monkeypatch.setattr(token_auth, "build_verifier", counting)
    for _ in range(5):
        token_auth.prepare_event_for_sql({"decision": "ALLOW"}, token_config={"enabled": False})
    assert len(built) == 1

    monkeypatch.setenv("LIONLOCK_LOG_TOKEN_HASHES", "a" * 64)
    token_auth.prepare_event_for_sql({"decision": "ALLOW"}, token_config={"enabled": False})
    assert len(built) == 2  # a changed allowlist source gets a fresh verifier


def test_an_unchanged_dotenv_is_read_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("LIONLOCK_DB_NAME_UNUSED=x\n")
    monkeypatch.setattr(connection, "_DOTENV_LOADED", set())
    reads: list[Path] = []
    real_read = Path.read_text

    def counting_read(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self == env_file:
            reads.append(self)
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counting_read)
    for _ in range(4):
        assert connection.load_dotenv(env_file) is True
    assert len(reads) == 1
    monkeypatch.delenv("LIONLOCK_DB_NAME_UNUSED", raising=False)


def test_replacing_the_hash_file_with_the_same_mtime_invalidates_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    monkeypatch.delenv("LIONLOCK_LOG_TOKEN_HASHES", raising=False)
    monkeypatch.delenv("LIONLOCK_LOG_TOKEN_DB_URI", raising=False)
    hashes = tmp_path / "hashes.txt"
    hashes.write_text("a" * 64 + "\n")
    cfg = {"enabled": True, "token_hashes_path": str(hashes)}
    first = token_auth._verifier_cache_key(cfg)
    stat = hashes.stat()
    replacement = tmp_path / "new.txt"
    replacement.write_text("b" * 64 + "\n")
    os.utime(replacement, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    os.replace(replacement, hashes)  # same mtime, like cp -p or rsync -a
    assert hashes.stat().st_mtime_ns == stat.st_mtime_ns
    assert token_auth._verifier_cache_key(cfg) != first
