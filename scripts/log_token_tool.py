#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from lionlock.logging.connection import build_postgres_dsn, load_dotenv, redact_dsn  # noqa: E402
from lionlock.logging.token_auth import (  # noqa: E402
    generate_token,
    hash_token,
    load_token,
    token_id,
)


def _write_secure(path: Path, content: str, *, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists")
    path.write_text(content, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        # Best-effort; permissions may not be supported on all platforms.
        pass


def _resolve_db_uri(explicit: str) -> str:
    if explicit:
        return explicit
    for name in ("LIONLOCK_LOG_TOKEN_DB_URI", "LIONLOCK_ADMIN_DB_URI"):
        value = os.getenv(name, "").strip()
        if value:
            return value
    try:
        return build_postgres_dsn("admin")
    except Exception:
        return ""


def _connect_execute(dsn: str, sql_text: str, params: tuple) -> None:
    try:
        import psycopg

        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(sql_text, params)
        return
    except ImportError:
        pass

    import psycopg2  # type: ignore[import-not-found]

    conn = psycopg2.connect(dsn)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql_text, params)
    finally:
        conn.close()


def cmd_generate(args: argparse.Namespace) -> int:
    token = generate_token()
    out_path = Path(args.token_path).expanduser()
    _write_secure(out_path, token + "\n", overwrite=args.force)

    token_hash = hash_token(token)
    if args.hashes_path:
        hashes_path = Path(args.hashes_path).expanduser()
        line = token_hash + "\n"
        if hashes_path.exists() and not args.force:
            with hashes_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        else:
            _write_secure(hashes_path, line, overwrite=args.force)

    sys.stdout.write("token_written=true\n")
    sys.stdout.write(f"token_path={out_path}\n")
    sys.stdout.write(f"token_id={token_id(token)}\n")
    sys.stdout.write(f"token_hash={token_hash}\n")
    if args.hashes_path:
        sys.stdout.write(f"hashes_path={Path(args.hashes_path).expanduser()}\n")
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    if args.env_file:
        load_dotenv(Path(args.env_file))

    token = load_token({"token_env": args.token_env, "token_path": args.token_path})
    if not token:
        sys.stderr.write("Token missing. Set env or pass --token-path.\n")
        return 2

    dsn = _resolve_db_uri(args.db_uri or "")
    if not dsn:
        sys.stderr.write("DB URI missing. Set LIONLOCK_LOG_TOKEN_DB_URI or pass --db-uri.\n")
        return 2

    token_hash = hash_token(token)
    token_id_value = token_id(token)
    created_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    label = args.label or ""
    scope = args.scope or ""

    sql_text = (
        "INSERT INTO auth_tokens (token_hash, token_id, created_utc, label, scope) "
        "VALUES (%s,%s,%s,%s,%s) "
        "ON CONFLICT (token_hash) DO NOTHING"
    )
    try:
        _connect_execute(dsn, sql_text, (token_hash, token_id_value, created_utc, label, scope))
    except Exception as exc:
        sys.stderr.write(f"Token register failed: {type(exc).__name__}\n")
        return 1

    sys.stdout.write("token_registered=true\n")
    sys.stdout.write(f"token_id={token_id_value}\n")
    sys.stdout.write(f"token_hash={token_hash}\n")
    if args.verbose:
        sys.stdout.write(f"db_uri={redact_dsn(dsn)}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage LionLock log tokens (no secrets printed).")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen = subparsers.add_parser("generate", help="Generate a new token and write it to a file.")
    gen.add_argument("--token-path", required=True, help="Path to write the token file.")
    gen.add_argument("--hashes-path", default="", help="Optional allowlist hash file to append.")
    gen.add_argument("--force", action="store_true", help="Overwrite existing files.")
    gen.set_defaults(func=cmd_generate)

    reg = subparsers.add_parser("register", help="Register token hash in auth_tokens table.")
    reg.add_argument("--env-file", default="", help="Optional .env file to load.")
    reg.add_argument("--token-path", default="", help="Path to token file.")
    reg.add_argument(
        "--token-env",
        default="LIONLOCK_LOG_TOKEN",
        help="Env var name holding the token (default: LIONLOCK_LOG_TOKEN).",
    )
    reg.add_argument("--db-uri", default="", help="Postgres URI/DSN for auth_tokens.")
    reg.add_argument("--label", default="", help="Optional label stored with the token hash.")
    reg.add_argument("--scope", default="", help="Optional scope stored with the token hash.")
    reg.add_argument("--verbose", action="store_true", help="Print redacted DB URI.")
    reg.set_defaults(func=cmd_register)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
