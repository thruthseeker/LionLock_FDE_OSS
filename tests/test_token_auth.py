import pytest

from lionlock.logging.token_auth import (
    attach_auth_fields,
    hash_token,
    prepare_event_for_sql,
    token_id,
    verify_and_prepare_event,
)


def test_verify_strips_raw_token() -> None:
    token = "llk_test_token"
    payload = {"request_id": "req-1", "timestamp": "2025-01-01T00:00:00Z"}
    signed = attach_auth_fields(payload, token)

    ok, message, prepared = verify_and_prepare_event(
        signed,
        token_config={"enabled": True, "mode": "required", "token_hashes": [hash_token(token)]},
    )

    assert ok, message
    assert "auth_token" not in prepared
    assert prepared["auth_token_id"] == token_id(token)
    assert prepared["auth_signature"] == signed["auth_signature"]


def test_verify_rejects_unknown_token() -> None:
    signed = attach_auth_fields({"request_id": "req-2"}, "llk_unknown")
    ok, message, _ = verify_and_prepare_event(
        signed,
        token_config={"enabled": True, "mode": "required", "token_hashes": [hash_token("llk_other")]},
    )
    assert ok is False
    assert message == "token_not_allowed"


def test_prepare_event_for_sql_uses_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "llk_env_token"
    monkeypatch.setenv("LIONLOCK_LOG_TOKEN", token)
    ok, message, prepared = prepare_event_for_sql(
        {"request_id": "req-3"},
        token_config={"enabled": True, "mode": "required", "token_hashes": [hash_token(token)]},
    )
    assert ok, message
    assert "auth_token" not in prepared
    assert prepared["auth_token_id"] == token_id(token)


def test_prepare_event_for_sql_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LIONLOCK_LOG_TOKEN", raising=False)
    ok, message, _ = prepare_event_for_sql(
        {"request_id": "req-4"},
        token_config={"enabled": True, "mode": "required", "token_hashes": []},
    )
    assert ok is False
    assert message == "missing_token_or_signature"


def test_required_mode_denies_empty_allowlist() -> None:
    token = "llk_any_token"
    signed = attach_auth_fields({"request_id": "req-5"}, token)
    ok, message, _ = verify_and_prepare_event(
        signed,
        token_config={"enabled": True, "mode": "required", "token_hashes": []},
    )
    assert ok is False
    assert message == "allowlist_empty"


def test_permissive_mode_allows_any_token() -> None:
    token = "llk_permissive_token"
    signed = attach_auth_fields({"request_id": "req-6"}, token)
    ok, message, _ = verify_and_prepare_event(
        signed,
        token_config={"enabled": True, "mode": "permissive", "token_hashes": []},
    )
    assert ok is True
    assert message == "ok"


def test_required_mode_denies_on_refresh_error(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "llk_refresh_token"
    signed = attach_auth_fields({"request_id": "req-7"}, token)

    def fake_refresh(self) -> bool:
        self.last_error = "RefreshError"
        return False

    monkeypatch.setattr(
        "lionlock.logging.token_auth.TokenVerifier._refresh_from_db", fake_refresh
    )
    ok, message, _ = verify_and_prepare_event(
        signed,
        token_config={
            "enabled": True,
            "mode": "required",
            "token_db_uri": "postgresql://example.invalid/db",
        },
    )
    assert ok is False
    assert message == "allowlist_refresh_failed"
