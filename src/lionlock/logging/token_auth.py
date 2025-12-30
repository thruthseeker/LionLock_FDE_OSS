from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

AUTH_TOKEN_FIELD = "auth_token"
AUTH_SIGNATURE_FIELD = "auth_signature"
AUTH_TOKEN_ID_FIELD = "auth_token_id"
TOKEN_ENV_DEFAULT = "LIONLOCK_LOG_TOKEN"
TOKEN_PATH_ENV_DEFAULT = "LIONLOCK_LOG_TOKEN_PATH"

_SIGN_EXCLUDE_FIELDS = {
    AUTH_TOKEN_FIELD,
    AUTH_SIGNATURE_FIELD,
    AUTH_TOKEN_ID_FIELD,
}

_LOGGER = logging.getLogger(__name__)


def generate_token(prefix: str = "llk_") -> str:
    return f"{prefix}{uuid.uuid4().hex}{secrets.token_hex(16)}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_id(token: str, length: int = 12) -> str:
    return hash_token(token)[:length]


def _canonical_payload(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _payload_for_signing(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in payload.items() if key not in _SIGN_EXCLUDE_FIELDS}


def sign_payload(token: str, payload: Dict[str, Any]) -> str:
    body = _canonical_payload(_payload_for_signing(payload))
    digest = hmac.new(token.encode("utf-8"), body.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def verify_signature(token: str, payload: Dict[str, Any], signature: str) -> bool:
    if not token or not signature:
        return False
    expected = sign_payload(token, payload)
    return hmac.compare_digest(expected, signature)


def attach_auth_fields(payload: Dict[str, Any], token: str) -> Dict[str, Any]:
    if not token:
        return dict(payload)
    signed = dict(payload)
    signed[AUTH_TOKEN_FIELD] = token
    signed[AUTH_SIGNATURE_FIELD] = sign_payload(token, signed)
    signed[AUTH_TOKEN_ID_FIELD] = token_id(token)
    return signed


def _split_hashes(raw: str) -> set[str]:
    return {item.strip() for item in raw.split(",") if item.strip()}


def _load_hashes_from_lines(lines: Iterable[str]) -> set[str]:
    hashes: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        hashes.add(stripped)
    return hashes


def _read_token_from_path(path: str) -> str | None:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except Exception:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return stripped
    return None


def load_token(config: Dict[str, Any] | None = None) -> str | None:
    cfg = dict(config or {})
    token_env = str(cfg.get("token_env") or TOKEN_ENV_DEFAULT).strip() or TOKEN_ENV_DEFAULT
    token = os.getenv(token_env, "").strip()
    if token:
        return token
    path_env = str(cfg.get("token_path_env") or TOKEN_PATH_ENV_DEFAULT).strip() or TOKEN_PATH_ENV_DEFAULT
    token_path = os.getenv(path_env, "").strip()
    if not token_path:
        token_path = str(cfg.get("token_path", "")).strip()
    if token_path:
        return _read_token_from_path(token_path)
    return None


@dataclass
class TokenVerifier:
    enabled: bool = False
    mode: str = "required"
    token_hashes: set[str] = field(default_factory=set)
    token_db_uri: str | None = None
    refresh_interval_s: int = 60
    last_error: str | None = field(default=None, init=False)
    _last_refresh: float = field(default=0.0, init=False)

    def _refresh_from_db(self) -> bool:
        if not self.token_db_uri:
            return True
        now = time.time()
        if now - self._last_refresh < self.refresh_interval_s:
            return True
        try:
            import psycopg

            with psycopg.connect(self.token_db_uri) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT token_hash FROM auth_tokens WHERE revoked_utc IS NULL"
                    )
                    rows = cur.fetchall()
            self.token_hashes = {row[0] for row in rows}
            self._last_refresh = now
            self.last_error = None
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}"
            _LOGGER.warning(
                "token_allowlist_refresh_failed error=%s",
                self.last_error,
            )
            return False

    def is_token_allowed(self, token: str) -> Tuple[bool, str]:
        if not token:
            return False, "missing_token"
        if not self.enabled:
            return True, "auth_disabled"
        if self.mode == "permissive":
            return True, "permissive"
        if self.token_db_uri:
            if not self._refresh_from_db():
                return False, "allowlist_refresh_failed"
        if not self.token_hashes:
            return False, "allowlist_empty"
        if hash_token(token) in self.token_hashes:
            return True, "ok"
        return False, "token_not_allowed"

    def verify_and_prepare(self, payload: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        if not self.enabled:
            cleaned = dict(payload)
            cleaned.pop(AUTH_TOKEN_FIELD, None)
            cleaned.pop(AUTH_SIGNATURE_FIELD, None)
            cleaned.pop(AUTH_TOKEN_ID_FIELD, None)
            return True, "auth_disabled", cleaned

        token = str(payload.get(AUTH_TOKEN_FIELD, "") or "").strip()
        signature = str(payload.get(AUTH_SIGNATURE_FIELD, "") or "").strip()
        if not token or not signature:
            return False, "missing_token_or_signature", payload
        if len(signature) < 64:
            return False, "signature_invalid", payload
        if not verify_signature(token, payload, signature):
            return False, "signature_invalid", payload
        allowed, reason = self.is_token_allowed(token)
        if not allowed:
            return False, reason, payload
        cleaned = dict(payload)
        cleaned.pop(AUTH_TOKEN_FIELD, None)
        cleaned[AUTH_TOKEN_ID_FIELD] = token_id(token)
        cleaned[AUTH_SIGNATURE_FIELD] = signature
        return True, "ok", cleaned


def build_verifier(config: Dict[str, Any] | None) -> TokenVerifier:
    cfg = dict(config or {})
    enabled = bool(cfg.get("enabled"))
    mode = str(cfg.get("mode", "")).strip().lower()
    if not mode:
        mode = "required" if bool(cfg.get("required", True)) else "permissive"
    if mode not in {"required", "permissive"}:
        mode = "required"

    token_hashes: set[str] = set()
    raw_hashes = cfg.get("token_hashes")
    if isinstance(raw_hashes, (list, tuple)):
        token_hashes.update(str(item).strip() for item in raw_hashes if str(item).strip())
    if isinstance(raw_hashes, str):
        token_hashes.update(_split_hashes(raw_hashes))

    path = cfg.get("token_hashes_path")
    if isinstance(path, str) and path.strip():
        try:
            token_hashes.update(
                _load_hashes_from_lines(Path(path).read_text(encoding="utf-8").splitlines())
            )
        except Exception:
            pass

    env_hashes = os.getenv("LIONLOCK_LOG_TOKEN_HASHES", "").strip()
    if env_hashes:
        enabled = True
        token_hashes.update(_split_hashes(env_hashes))

    token_db_uri = os.getenv("LIONLOCK_LOG_TOKEN_DB_URI", "").strip()
    if not token_db_uri:
        token_db_uri = str(cfg.get("token_db_uri", "")).strip()

    refresh_interval = int(cfg.get("refresh_interval_s", 60))

    return TokenVerifier(
        enabled=enabled,
        mode=mode,
        token_hashes=token_hashes,
        token_db_uri=token_db_uri or None,
        refresh_interval_s=max(5, refresh_interval),
    )


def verify_and_prepare_event(
    payload: Dict[str, Any],
    *,
    token_config: Dict[str, Any] | None = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    verifier = build_verifier(token_config)
    return verifier.verify_and_prepare(payload)


def prepare_event_for_sql(
    payload: Dict[str, Any],
    *,
    token_config: Dict[str, Any] | None = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    cfg = dict(token_config or {})
    verifier = build_verifier(cfg)
    signed_payload = payload
    if verifier.enabled and (
        AUTH_TOKEN_FIELD not in payload
        and AUTH_SIGNATURE_FIELD not in payload
        and AUTH_TOKEN_ID_FIELD not in payload
    ):
        token = load_token(cfg)
        if token:
            signed_payload = attach_auth_fields(payload, token)
    return verifier.verify_and_prepare(signed_payload)
