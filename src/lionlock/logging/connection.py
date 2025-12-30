from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_DEFAULT_ADMIN_USER = "lionlock_admin"
_DEFAULT_WRITER_USER = "lionlock_writer"
_DEFAULT_PORT = 25060

_ENV_DB_HOST_KEYS = ("LIONLOCK_TELEMETRY_DB_HOST", "LIONLOCK_DB_HOST", "HOST")
_ENV_DB_PORT_KEYS = ("LIONLOCK_TELEMETRY_DB_PORT", "LIONLOCK_DB_PORT", "PORT")
_ENV_DB_NAME_KEYS = ("LIONLOCK_TELEMETRY_DB_NAME", "LIONLOCK_DB_NAME")
_ENV_SSLMODE_KEYS_ADMIN = ("LIONLOCK_SSLMODE",)
_ENV_SSLMODE_KEYS_TELEMETRY = ("LIONLOCK_TELEMETRY_SSLMODE", "LIONLOCK_SSLMODE")
_ENV_SSLROOTCERT_KEYS_ADMIN = ("LIONLOCK_SSLROOTCERT",)
_ENV_SSLROOTCERT_KEYS_TELEMETRY = ("LIONLOCK_TELEMETRY_SSLROOTCERT", "LIONLOCK_SSLROOTCERT")


def validate_identifier(name: str, label: str) -> None:
    if not name or not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError(f"Invalid SQL identifier for {label}: {name!r}")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is None:
            continue
        value = str(value).strip()
        if value:
            return value
    return None


def _read_env_lines(lines: Iterable[str]) -> None:
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if value and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def load_dotenv(path: str | Path | None = None) -> bool:
    candidate: Path | None
    if path is not None:
        candidate = Path(path)
    else:
        cwd_env = Path.cwd() / ".env"
        root = _repo_root()
        candidates = [
            cwd_env,
            root / ".env",
        ]
        candidate = None
        for item in candidates:
            if item.is_file():
                candidate = item
                break
    if candidate is None or not candidate.is_file():
        return False
    _read_env_lines(candidate.read_text(encoding="utf-8").splitlines())
    return True


def _resolve_host_port() -> tuple[str, int]:
    host = _env_first(*_ENV_DB_HOST_KEYS)
    if not host:
        raise ValueError("Database host missing (LIONLOCK_TELEMETRY_DB_HOST or LIONLOCK_DB_HOST).")
    port_raw = _env_first(*_ENV_DB_PORT_KEYS) or str(_DEFAULT_PORT)
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ValueError("Database port must be an integer.") from exc
    return host, port


def _resolve_database_name(database: str | None) -> str:
    env_value = _env_first(*_ENV_DB_NAME_KEYS)
    return env_value or (database or "lionlock_prod")


def _resolve_user_password(role: str) -> tuple[str, str]:
    normalized = role.strip().lower()
    if normalized in {"admin", "lionlock_admin"}:
        user = _env_first("LIONLOCK_ADMIN_USER") or _DEFAULT_ADMIN_USER
        password = _env_first("LIONLOCK_ADMIN_PASSWORD")
        if not password:
            raise ValueError("Missing LIONLOCK_ADMIN_PASSWORD.")
        return user, password
    if normalized in {"writer", "lionlock_writer", "telemetry"}:
        user = _env_first("LIONLOCK_WRITER_USER", "LIONLOCK_TELEMETRY_DB_USER") or _DEFAULT_WRITER_USER
        password = _env_first("LIONLOCK_WRITER_PASSWORD", "LIONLOCK_TELEMETRY_DB_PASSWORD")
        if not password:
            raise ValueError("Missing LIONLOCK_WRITER_PASSWORD or LIONLOCK_TELEMETRY_DB_PASSWORD.")
        return user, password
    raise ValueError("Role must be 'admin' or 'writer'.")


def _discover_sslrootcert(env_keys: tuple[str, ...]) -> str | None:
    env_path = _env_first(*env_keys)
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return str(candidate)
    return None


def _resolve_ssl_settings(role: str) -> tuple[str, str | None]:
    normalized = role.strip().lower()
    if normalized in {"admin", "lionlock_admin"}:
        sslmode = _env_first(*_ENV_SSLMODE_KEYS_ADMIN)
        sslrootcert = _discover_sslrootcert(_ENV_SSLROOTCERT_KEYS_ADMIN)
    else:
        sslmode = _env_first(*_ENV_SSLMODE_KEYS_TELEMETRY)
        sslrootcert = _discover_sslrootcert(_ENV_SSLROOTCERT_KEYS_TELEMETRY)
    if sslmode:
        normalized = sslmode.strip().lower()
        if normalized == "require":
            return normalized, None
        return normalized, sslrootcert
    sslmode = "verify-ca" if sslrootcert else "require"
    return sslmode, sslrootcert


def build_postgres_dsn(role: str, *, database: str = "lionlock_prod") -> str:
    load_dotenv()
    user, password = _resolve_user_password(role)
    host, port = _resolve_host_port()
    database = _resolve_database_name(database)
    sslmode, sslrootcert = _resolve_ssl_settings(role)
    params: list[tuple[str, str]] = [("sslmode", sslmode)]
    if sslrootcert and sslmode != "require":
        params.append(("sslrootcert", sslrootcert))
    query = urlencode(params)
    safe_user = quote(user, safe="")
    safe_password = quote(password, safe="")
    return f"postgresql://{safe_user}:{safe_password}@{host}:{port}/{database}?{query}"


def redact_dsn(dsn: str) -> str:
    if "://" in dsn:
        split = urlsplit(dsn)
        user = split.username
        host = split.hostname or ""
        port = f":{split.port}" if split.port is not None else ""
        netloc = ""
        if user:
            netloc = quote(user, safe="")
            if split.password is not None:
                netloc += ":REDACTED"
            netloc += "@"
        netloc += f"{host}{port}"
        query_pairs = []
        for key, value in parse_qsl(split.query, keep_blank_values=True):
            if key.lower() in {"password", "pass", "pwd"}:
                query_pairs.append((key, "REDACTED"))
            else:
                query_pairs.append((key, value))
        query = urlencode(query_pairs)
        return urlunsplit((split.scheme, netloc, split.path, query, split.fragment))

    parts = []
    for token in dsn.split():
        if "=" not in token:
            parts.append(token)
            continue
        key, value = token.split("=", 1)
        if key.lower() in {"password", "pass", "pwd"}:
            parts.append(f"{key}=REDACTED")
        else:
            parts.append(f"{key}={value}")
    return " ".join(parts)
