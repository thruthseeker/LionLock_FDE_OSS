from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from lionlock.logging.connection import validate_identifier

MANDATORY_FIELDS = (
    "session_id",
    "turn_index",
    "timestamp",
    "signal_bundle",
    "gating_decision",
    "decision_risk_score",
    "trigger_signal",
    "trust_logic_version",
    "code_fingerprint",
    "prompt_type",
    "response_hash",
    "auth_token_id",
    "auth_signature",
)

FORBIDDEN_COLUMNS = {
    "prompt",
    "response",
    "prompt_text",
    "response_text",
    "user_id",
    "ip",
    "device_id",
    "messages",
    "payload_b64",
}


def _sqlite_path_from_uri(uri: str) -> str | None:
    prefix = "sqlite:///"
    if not uri.startswith(prefix):
        return None
    path = uri[len(prefix) :]
    if path == ":memory:":
        return path
    if path.startswith("/"):
        return path
    return path


def _create_table_sql(table: str, columns: Iterable[Tuple[str, str]]) -> str:
    cols = ", ".join(f"{name} {col_type}" for name, col_type in columns)
    return f"CREATE TABLE IF NOT EXISTS {table} ({cols})"


def _common_columns(json_type: str) -> List[Tuple[str, str]]:
    return [
        ("session_id", "TEXT"),
        ("turn_index", "INTEGER"),
        ("timestamp", "TEXT"),
        ("signal_bundle", json_type),
        ("gating_decision", "TEXT"),
        ("decision_risk_score", "REAL"),
        ("trigger_signal", "TEXT"),
        ("trust_logic_version", "TEXT"),
        ("code_fingerprint", "TEXT"),
        ("prompt_type", "TEXT"),
        ("response_hash", "TEXT"),
        ("replay_id", "TEXT"),
        (
            "auth_token_id",
            "TEXT CHECK (auth_token_id IS NULL OR length(auth_token_id) >= 12)",
        ),
        (
            "auth_signature",
            "TEXT CHECK (auth_signature IS NULL OR length(auth_signature) >= 64)",
        ),
    ]


def _table_specs(backend: str) -> Dict[str, List[Tuple[str, str]]]:
    json_type = "JSONB" if backend == "postgres" else "TEXT"
    pk_type = "BIGSERIAL PRIMARY KEY" if backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    common = _common_columns(json_type)
    return {
        "events": [
            ("event_pk", pk_type),
            *common,
            ("event_type", "TEXT"),
            ("event_severity", "TEXT"),
        ],
        "sessions": [
            ("session_pk", pk_type),
            *common,
            ("session_status", "TEXT"),
            ("session_opened_utc", "TEXT"),
            ("session_closed_utc", "TEXT"),
        ],
        "anomalies": [
            ("anomaly_pk", pk_type),
            *common,
            ("anomaly_type", "TEXT"),
            ("severity", "REAL"),
            ("details_json", json_type),
        ],
        "missed_signal_events": [
            ("missed_pk", pk_type),
            *common,
            ("miss_reason", "TEXT"),
            ("expected_decision", "TEXT"),
            ("actual_decision", "TEXT"),
        ],
        "trust_overlay": [
            ("overlay_pk", pk_type),
            *common,
            ("trust_score", "REAL"),
            ("trust_label", "TEXT"),
            ("overlay_json", json_type),
        ],
        "auth_tokens": [
            ("token_hash", "TEXT PRIMARY KEY"),
            ("token_id", "TEXT"),
            ("created_utc", "TEXT"),
            ("revoked_utc", "TEXT"),
            ("label", "TEXT"),
            ("scope", "TEXT"),
            ("metadata_json", json_type),
        ],
    }


def _sqlite_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _sqlite_table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row[1] for row in rows]


def _create_sqlite_unique_index(
    conn: sqlite3.Connection,
    table: str,
    index_name: str,
    columns: Iterable[str],
) -> None:
    validate_identifier(table, "table")
    validate_identifier(index_name, "index")
    cols = []
    for column in columns:
        validate_identifier(column, "column")
        cols.append(column)
    conn.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} ON {table} ({','.join(cols)})"
    )


def _ensure_sqlite_unique_indexes(conn: sqlite3.Connection) -> None:
    _create_sqlite_unique_index(
        conn,
        "events",
        "events_session_turn_response_event_type_unique",
        ("session_id", "turn_index", "response_hash", "event_type"),
    )
    _create_sqlite_unique_index(
        conn,
        "anomalies",
        "anomalies_session_turn_response_type_unique",
        ("session_id", "turn_index", "response_hash", "anomaly_type"),
    )
    _create_sqlite_unique_index(
        conn,
        "missed_signal_events",
        "missed_signal_session_turn_response_reason_unique",
        ("session_id", "turn_index", "response_hash", "miss_reason"),
    )


def _ensure_sqlite_columns(
    conn: sqlite3.Connection,
    table: str,
    columns: Iterable[Tuple[str, str]],
) -> None:
    existing = set(_sqlite_table_columns(conn, table))
    for name, col_type in columns:
        if name in existing:
            continue
        validate_identifier(table, "table")
        validate_identifier(name, "column")
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}")


def _ensure_postgres_columns(
    conn: Any,
    schema: str,
    table: str,
    columns: Iterable[Tuple[str, str]],
) -> None:
    if text is None:
        raise RuntimeError("SQLAlchemy required for Postgres column checks.")
    validate_identifier(schema, "schema")
    validate_identifier(table, "table")
    existing = conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema=:schema AND table_name=:table"
        ),
        {"schema": schema, "table": table},
    ).fetchall()
    existing_cols = {row[0] for row in existing}
    for name, col_type in columns:
        if name in existing_cols:
            continue
        validate_identifier(name, "column")
        conn.execute(
            text(f"ALTER TABLE {schema}.{table} ADD COLUMN IF NOT EXISTS {name} {col_type}")
        )


def init_schema(uri_or_dsn: str, *, schema: str = "public") -> Tuple[bool, str]:
    if not uri_or_dsn:
        return False, "SQL URI is empty."
    sqlite_path = _sqlite_path_from_uri(uri_or_dsn)
    if sqlite_path is not None:
        try:
            tables = _table_specs("sqlite")
            for table in tables:
                validate_identifier(table, "table")
            if sqlite_path != ":memory:":
                Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(sqlite_path) as conn:
                for table, columns in tables.items():
                    conn.execute(_create_table_sql(table, columns))
                    _ensure_sqlite_columns(conn, table, columns)
                _ensure_sqlite_unique_indexes(conn)
                conn.commit()
            if sqlite_path != ":memory:":
                ok, message = validate_schema(uri_or_dsn, schema=schema)
                if not ok:
                    return False, message
            return True, "Initialized sqlite schema."
        except Exception as exc:
            return False, f"SQLite schema init failed: {exc}"

    if create_engine is None or text is None:
        ok, message = _init_postgres_schema_via_psycopg(uri_or_dsn, schema=schema)
        return ok, message
    if schema != "public":
        return False, "Only the public schema is supported for Postgres."
    try:
        validate_identifier(schema, "schema")
        tables = _table_specs("postgres")
        for table in tables:
            validate_identifier(table, "table")
        engine = create_engine(uri_or_dsn)
        with engine.begin() as conn:
            for table, columns in tables.items():
                qualified = f"{schema}.{table}"
                conn.execute(text(_create_table_sql(qualified, columns)))
                _ensure_postgres_columns(conn, schema, table, columns)
        return True, "Initialized Postgres schema."
    except Exception as exc:
        return False, f"Postgres schema init failed: {exc}"


def _init_postgres_schema_via_psycopg(uri_or_dsn: str, *, schema: str) -> Tuple[bool, str]:
    if schema != "public":
        return False, "Only the public schema is supported for Postgres."
    try:
        import psycopg

        validate_identifier(schema, "schema")
        tables = _table_specs("postgres")
        for table in tables:
            validate_identifier(table, "table")
        with psycopg.connect(uri_or_dsn) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                for table, columns in tables.items():
                    qualified = f"{schema}.{table}"
                    cur.execute(_create_table_sql(qualified, columns))
        return True, "Initialized Postgres schema."
    except ImportError:
        pass
    except Exception as exc:
        return False, f"Postgres schema init failed: {exc}"

    try:
        import psycopg2

        validate_identifier(schema, "schema")
        tables = _table_specs("postgres")
        for table in tables:
            validate_identifier(table, "table")
        conn = psycopg2.connect(uri_or_dsn)
        try:
            conn.autocommit = True
            cur = conn.cursor()
            try:
                for table, columns in tables.items():
                    qualified = f"{schema}.{table}"
                    cur.execute(_create_table_sql(qualified, columns))
            finally:
                cur.close()
        finally:
            conn.close()
        return True, "Initialized Postgres schema."
    except Exception as exc:
        return False, f"Postgres schema init failed: {exc}"


def validate_schema(uri_or_dsn: str, *, schema: str = "public") -> Tuple[bool, str]:
    sqlite_path = _sqlite_path_from_uri(uri_or_dsn)
    if sqlite_path is None:
        return False, "Schema validation is available for sqlite only."
    if sqlite_path == ":memory:":
        return False, "Schema validation is not supported for in-memory sqlite."
    try:
        tables = _table_specs("sqlite")
        forbidden = {name.lower() for name in FORBIDDEN_COLUMNS}
        with sqlite3.connect(sqlite_path) as conn:
            missing_tables = [table for table in tables if not _sqlite_table_exists(conn, table)]
            if missing_tables:
                return False, f"Missing tables: {', '.join(missing_tables)}"
            for table, columns in tables.items():
                existing_cols = set(_sqlite_table_columns(conn, table))
                missing_cols = [name for name, _ in columns if name not in existing_cols]
                if missing_cols:
                    return False, f"Missing columns in {table}: {', '.join(missing_cols)}"
                forbidden_found = [col for col in existing_cols if col.lower() in forbidden]
                if forbidden_found:
                    return (
                        False,
                        f"Forbidden columns present in {table}: {', '.join(sorted(forbidden_found))}",
                    )
        return True, "Schema validated."
    except Exception as exc:
        return False, f"Schema validation failed: {exc}"
