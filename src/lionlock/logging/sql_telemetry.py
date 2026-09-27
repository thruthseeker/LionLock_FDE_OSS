import atexit
import os
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from lionlock.core.models import canonical_gating_decision
from lionlock.utils.sql_batch_writer import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_BACKOFF_MS,
    DEFAULT_STOP_TIMEOUT_S,
    SQLBatchWriter,
)

from .connection import load_dotenv, validate_identifier
from .token_auth import AUTH_SIGNATURE_FIELD, AUTH_TOKEN_ID_FIELD, prepare_event_for_sql

SESSIONS_COLUMNS: List[Tuple[str, str]] = [
    ("session_pk", "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("session_id", "TEXT UNIQUE"),
    ("created_utc", "TEXT"),
    ("closed_utc", "TEXT"),
    ("lionlock_version", "TEXT"),
    ("model", "TEXT"),
    ("base_url", "TEXT"),
    ("config_hash", "TEXT"),
    ("content_policy", "TEXT"),
    ("has_anomalies", "INTEGER"),
    ("anomaly_count", "INTEGER"),
    ("anomaly_severity_score", "REAL"),
    ("anomaly_severity_tag", "TEXT"),
]

PUBLIC_SIGNALS_COLUMNS: List[Tuple[str, str]] = [
    ("event_pk", "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("session_pk", "INTEGER"),
    ("timestamp_utc", "TEXT"),
    ("request_id", "TEXT"),
    ("decision", "TEXT"),
    ("severity", "TEXT"),
    ("reason_code", "TEXT"),
    ("aggregate_score", "REAL"),
    ("repetition_score", "REAL"),
    ("novelty_score", "REAL"),
    ("coherence_score", "REAL"),
    ("context_score", "REAL"),
    ("hallucination_score", "REAL"),
    ("duration_ms", "INTEGER"),
    ("config_hash", "TEXT"),
    (
        AUTH_TOKEN_ID_FIELD,
        f"TEXT CHECK ({AUTH_TOKEN_ID_FIELD} IS NULL OR length({AUTH_TOKEN_ID_FIELD}) >= 12)",
    ),
    (
        AUTH_SIGNATURE_FIELD,
        f"TEXT CHECK ({AUTH_SIGNATURE_FIELD} IS NULL OR length({AUTH_SIGNATURE_FIELD}) >= 64)",
    ),
]

FAILSAFE_COLUMNS: List[Tuple[str, str]] = [
    ("timestamp_utc", "TEXT"),
    ("request_id", "TEXT"),
    ("payload_b64", "TEXT"),
]

SIGNAL_KEY_MAP = {
    "repetition_score": "repetition_loopiness",
    "novelty_score": "novelty_entropy_proxy",
    "coherence_score": "coherence_structure",
    "context_score": "context_adherence",
    "hallucination_score": "hallucination_risk",
}


def _canonicalize_decision(value: Any) -> str:
    if value is None:
        return canonical_gating_decision(None)
    text = str(value).strip()
    if text.upper() == "ERROR":
        return "ERROR"
    return canonical_gating_decision(text)

_WRITER: "SQLTelemetryWriter | None" = None
_WRITER_KEY: Tuple[Any, ...] | None = None
_WRITER_LOCK = threading.Lock()
_ALLOWED_TABLES = {
    "lionlock_signals",
    "lionlock_sessions",
    "lionlock_failsafe",
}
DEFAULT_SQL_TELEMETRY_TOKEN = ""
_SQL_TOKEN_ENV_KEYS = (
    "LIONLOCK_TELEMETRY_TOKEN",
    "LIONLOCK_SQL_TELEMETRY_TOKEN",
    "LIONLOCK_SQL_TOKEN",
)
_SQL_URI_ENV_KEYS = ("LIONLOCK_TELEMETRY_DB_URI",)
_TOKEN_MAP = {}
_ALLOWED_SCHEMES = ("postgres", "postgresql", "sqlite")


def _env_first(*keys: str) -> str:
    for key in keys:
        value = os.getenv(key)
        if value is None:
            continue
        stripped = value.strip()
        if stripped:
            return stripped
    return ""


def resolve_sql_uri(token: str) -> str:
    """Map a token to a SQL URI; fallback allows direct URIs for testing."""
    load_dotenv()
    env_token = _env_first(*_SQL_TOKEN_ENV_KEYS)
    chosen = env_token or token or ""
    chosen = chosen.strip()
    if not chosen:
        raise RuntimeError("Missing telemetry token.")
    mapped = _TOKEN_MAP.get(chosen) or chosen
    uri = mapped.strip()
    if not uri:
        raise RuntimeError("Telemetry token did not resolve to a SQL URI.")
    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()
    if not scheme or not scheme.startswith(_ALLOWED_SCHEMES):
        raise RuntimeError(
            "Telemetry token must resolve to a Postgres URI (sqlite allowed for tests only)."
        )
    return uri


def resolve_sql_config(config: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(config or {})
    load_dotenv()
    env_token = _env_first(*_SQL_TOKEN_ENV_KEYS)
    env_uri = _env_first(*_SQL_URI_ENV_KEYS)
    token = (
        env_token
        or env_uri
        or str(cfg.get("token", "")).strip()
        or str(cfg.get("uri", "")).strip()
    )
    if not token:
        raise RuntimeError("logging_sql.token is required when SQL telemetry is enabled.")
    resolved_uri = resolve_sql_uri(token)
    cfg["token"] = token
    cfg["uri"] = resolved_uri
    return cfg


def _validate_table_name(name: str, label: str) -> str:
    validate_identifier(name, label)
    if name not in _ALLOWED_TABLES:
        raise ValueError(f"Table not allowed for {label}: {name}")
    return name


def _create_table_sql(table: str, columns: Iterable[Tuple[str, str]]) -> str:
    cols = ", ".join(f"{name} {col_type}" for name, col_type in columns)
    return f"CREATE TABLE IF NOT EXISTS {table} ({cols})"


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


def _sqlite_table_columns(db_path: str, table: str) -> List[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row[1] for row in rows]


def _sqlite_table_exists(db_path: str, table: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
    return row is not None


def _init_sqlite_table(db_path: str, table: str, columns: Iterable[Tuple[str, str]]) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(_create_table_sql(table, columns))
        conn.commit()


def _init_sqlite_failsafe_table(db_path: str, table: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(_create_table_sql(table, FAILSAFE_COLUMNS))
        conn.commit()


def _init_sqlalchemy_table(uri: str, table: str, columns: Iterable[Tuple[str, str]]) -> None:
    if create_engine is None or text is None:
        raise RuntimeError("SQLAlchemy is required for non-sqlite URIs.")
    engine = create_engine(uri)
    ddl = _create_table_sql(table, columns)
    with engine.begin() as conn:
        conn.execute(text(ddl))


def _migrate_sqlite_signals_table(db_path: str, table: str) -> bool:
    if not _sqlite_table_exists(db_path, table):
        return False
    columns = _sqlite_table_columns(db_path, table)
    if "session_pk" in columns and "event_pk" in columns:
        return False
    new_table = f"{table}_v2"
    _init_sqlite_table(db_path, new_table, PUBLIC_SIGNALS_COLUMNS)
    copy_columns = [
        "timestamp_utc",
        "request_id",
        "decision",
        "severity",
        "reason_code",
        "aggregate_score",
        "repetition_score",
        "novelty_score",
        "coherence_score",
        "context_score",
        "hallucination_score",
        "duration_ms",
        "config_hash",
    ]
    available = [col for col in copy_columns if col in columns]
    select_expr = ", ".join(available) if available else ""
    insert_cols = ", ".join(available)
    if available:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                f"INSERT INTO {new_table} ({insert_cols}) SELECT {select_expr} FROM {table}"
            )
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f"ALTER TABLE {new_table} RENAME TO {table}")
            conn.commit()
    else:
        with sqlite3.connect(db_path) as conn:
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f"ALTER TABLE {new_table} RENAME TO {table}")
            conn.commit()
    return True


def init_db(
    uri: str,
    table: str,
    sessions_table: str,
    failsafe_table: str | None = None,
) -> Tuple[bool, str]:
    if not uri:
        return False, "SQL URI is empty."
    try:
        table = _validate_table_name(table, "table")
        sessions_table = _validate_table_name(sessions_table, "sessions_table")
        if failsafe_table:
            _validate_table_name(failsafe_table, "failsafe_table")
    except ValueError as exc:
        return False, f"SQL init failed: {exc}"
    sqlite_path = _sqlite_path_from_uri(uri)
    try:
        if sqlite_path is not None:
            _init_sqlite_table(sqlite_path, sessions_table, SESSIONS_COLUMNS)
            _migrate_sqlite_signals_table(sqlite_path, table)
            _init_sqlite_table(sqlite_path, table, PUBLIC_SIGNALS_COLUMNS)
            if failsafe_table:
                _init_sqlite_failsafe_table(sqlite_path, failsafe_table)
            return True, "Initialized sqlite tables."
        if create_engine is None or text is None:
            return False, "SQLAlchemy not installed; cannot initialize non-sqlite URI."
        _init_sqlalchemy_table(uri, sessions_table, SESSIONS_COLUMNS)
        _init_sqlalchemy_table(uri, table, PUBLIC_SIGNALS_COLUMNS)
        if failsafe_table:
            _init_sqlalchemy_table(uri, failsafe_table, FAILSAFE_COLUMNS)
        return True, "Initialized SQL tables."
    except Exception as exc:
        return False, f"SQL init failed: {exc}"


def _signal_value(signal_scores: Any, key: str) -> float | None:
    if not isinstance(signal_scores, dict):
        return None
    value = signal_scores.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _event_to_row(event: Dict[str, Any], session_pk: int | None) -> Tuple[Any, ...]:
    scores = event.get("signal_scores") or {}
    return (
        session_pk,
        event.get("timestamp_utc"),
        event.get("request_id"),
        _canonicalize_decision(event.get("decision")),
        event.get("severity"),
        event.get("reason_code"),
        event.get("aggregate_score"),
        _signal_value(scores, SIGNAL_KEY_MAP["repetition_score"]),
        _signal_value(scores, SIGNAL_KEY_MAP["novelty_score"]),
        _signal_value(scores, SIGNAL_KEY_MAP["coherence_score"]),
        _signal_value(scores, SIGNAL_KEY_MAP["context_score"]),
        _signal_value(scores, SIGNAL_KEY_MAP["hallucination_score"]),
        event.get("duration_ms"),
        event.get("config_hash"),
        event.get(AUTH_TOKEN_ID_FIELD),
        event.get(AUTH_SIGNATURE_FIELD),
    )


def _event_to_named_row(event: Dict[str, Any], session_pk: int | None) -> Dict[str, Any]:
    scores = event.get("signal_scores") or {}
    return {
        "session_pk": session_pk,
        "timestamp_utc": event.get("timestamp_utc"),
        "request_id": event.get("request_id"),
        "decision": _canonicalize_decision(event.get("decision")),
        "severity": event.get("severity"),
        "reason_code": event.get("reason_code"),
        "aggregate_score": event.get("aggregate_score"),
        "repetition_score": _signal_value(scores, SIGNAL_KEY_MAP["repetition_score"]),
        "novelty_score": _signal_value(scores, SIGNAL_KEY_MAP["novelty_score"]),
        "coherence_score": _signal_value(scores, SIGNAL_KEY_MAP["coherence_score"]),
        "context_score": _signal_value(scores, SIGNAL_KEY_MAP["context_score"]),
        "hallucination_score": _signal_value(scores, SIGNAL_KEY_MAP["hallucination_score"]),
        "duration_ms": event.get("duration_ms"),
        "config_hash": event.get("config_hash"),
        AUTH_TOKEN_ID_FIELD: event.get(AUTH_TOKEN_ID_FIELD),
        AUTH_SIGNATURE_FIELD: event.get(AUTH_SIGNATURE_FIELD),
    }


class SQLTelemetryWriter(SQLBatchWriter):
    """Batched SQL writer for public signal events; delivery policy in SQLBatchWriter."""

    sink_name = "sql_telemetry"

    def __init__(
        self,
        uri: str,
        table: str,
        sessions_table: str,
        batch_size: int,
        flush_interval_ms: int,
        connect_timeout_s: int,
        *,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_ms: int = DEFAULT_RETRY_BACKOFF_MS,
        stop_timeout_s: float = DEFAULT_STOP_TIMEOUT_S,
    ) -> None:
        super().__init__(
            batch_size=batch_size,
            flush_interval_ms=flush_interval_ms,
            max_retries=max_retries,
            retry_backoff_ms=retry_backoff_ms,
            stop_timeout_s=stop_timeout_s,
        )
        self.uri = uri
        self.table = table
        self.sessions_table = sessions_table
        self.connect_timeout_s = max(1, connect_timeout_s)
        self.sqlite_path = _sqlite_path_from_uri(uri)
        try:
            _validate_table_name(table, "table")
            _validate_table_name(sessions_table, "sessions_table")
        except ValueError as exc:
            self._disable(f"SQL telemetry init failed: {exc}")
            return
        if self.sqlite_path is None and (create_engine is None or text is None):
            self._disable("SQLAlchemy not installed; SQL telemetry disabled.")
            return
        self._init_tables()
        if self.available:
            self._start()

    def _init_tables(self) -> None:
        try:
            if self.sqlite_path is not None:
                _init_sqlite_table(self.sqlite_path, self.sessions_table, SESSIONS_COLUMNS)
                _migrate_sqlite_signals_table(self.sqlite_path, self.table)
                _init_sqlite_table(self.sqlite_path, self.table, PUBLIC_SIGNALS_COLUMNS)
            else:
                if create_engine is None or text is None:
                    raise RuntimeError("SQLAlchemy not installed.")
                self.engine = create_engine(self.uri)
                ddl_sessions = _create_table_sql(self.sessions_table, SESSIONS_COLUMNS)
                ddl_events = _create_table_sql(self.table, PUBLIC_SIGNALS_COLUMNS)
                with self.engine.begin() as conn:
                    conn.execute(text(ddl_sessions))
                    conn.execute(text(ddl_events))
        except Exception as exc:
            self.available = False
            self.error = f"SQL telemetry init failed: {exc}"

    def _write_batch(self, events: List[Dict[str, Any]]) -> None:
        columns = ",".join(name for name, _ in PUBLIC_SIGNALS_COLUMNS if name != "event_pk")
        if self.sqlite_path is not None:
            placeholders = ",".join("?" for _ in columns.split(","))
            sql = f"INSERT INTO {self.table} ({columns}) VALUES ({placeholders})"
            rows = [_event_to_row(event, event.get("session_pk")) for event in events]
            with closing(sqlite3.connect(self.sqlite_path, timeout=self.connect_timeout_s)) as conn:
                with conn:  # Commits on success, rolls back on error.
                    conn.executemany(sql, rows)
            return
        if self.engine is None or text is None:
            raise RuntimeError("SQLAlchemy not installed.")
        values = ",".join(f":{name}" for name in columns.split(","))
        stmt = text(f"INSERT INTO {self.table} ({columns}) VALUES ({values})")
        with self.engine.begin() as conn:
            conn.execute(
                stmt,
                [_event_to_named_row(event, event.get("session_pk")) for event in events],
            )


def get_writer(config: Dict[str, Any]) -> SQLTelemetryWriter | None:
    """Return the shared writer for ``config``, creating it on first use.

    Raises RuntimeError for invalid configuration or when the writer cannot
    start. Write errors never raise here: the writer retries or counts them
    (see ``SQLBatchWriter.stats``) and stays in service.
    """
    global _WRITER, _WRITER_KEY
    resolved_cfg = resolve_sql_config(config)
    uri = str(resolved_cfg.get("uri", "")).strip()
    table = str(resolved_cfg.get("table", "lionlock_signals")).strip()
    sessions_table = str(resolved_cfg.get("sessions_table", "lionlock_sessions")).strip()
    try:
        table = _validate_table_name(table, "table")
        sessions_table = _validate_table_name(sessions_table, "sessions_table")
    except ValueError as exc:
        stop_writer()
        raise RuntimeError(f"SQL telemetry config invalid: {exc}") from exc
    batch_size = int(config.get("batch_size", 50))
    flush_interval_ms = int(config.get("flush_interval_ms", 1000))
    connect_timeout_s = int(config.get("connect_timeout_s", 5))
    max_retries = int(config.get("max_retries", DEFAULT_MAX_RETRIES))
    retry_backoff_ms = int(config.get("retry_backoff_ms", DEFAULT_RETRY_BACKOFF_MS))
    stop_timeout_s = float(config.get("stop_timeout_s", DEFAULT_STOP_TIMEOUT_S))
    key = (
        uri,
        table,
        sessions_table,
        batch_size,
        flush_interval_ms,
        connect_timeout_s,
        max_retries,
        retry_backoff_ms,
        stop_timeout_s,
    )
    if not uri:
        stop_writer()
        raise RuntimeError("SQL telemetry URI is empty.")
    with _WRITER_LOCK:
        if _WRITER is not None and _WRITER_KEY == key and _WRITER.available:
            return _WRITER
        if _WRITER is not None:
            # Reconfigured, or stopped by its owner: flush what it still holds.
            _WRITER.stop()
        _WRITER = None
        _WRITER_KEY = None
        writer = SQLTelemetryWriter(
            uri=uri,
            table=table,
            sessions_table=sessions_table,
            batch_size=batch_size,
            flush_interval_ms=flush_interval_ms,
            connect_timeout_s=connect_timeout_s,
            max_retries=max_retries,
            retry_backoff_ms=retry_backoff_ms,
            stop_timeout_s=stop_timeout_s,
        )
        if not writer.available:
            writer.stop()
            raise RuntimeError(writer.error or "SQL telemetry writer unavailable.")
        _WRITER = writer
        _WRITER_KEY = key
        return writer


def enqueue_event(
    config: Dict[str, Any],
    event: Dict[str, Any],
    session_pk: int | None = None,
) -> bool:
    if not config.get("enabled"):
        return False
    resolved_cfg = resolve_sql_config(config)
    if session_pk is not None:
        event = dict(event)
        event["session_pk"] = session_pk
    ok, reason, prepared = prepare_event_for_sql(
        event, token_config=resolved_cfg.get("token_auth")
    )
    if not ok:
        raise RuntimeError(f"SQL telemetry token verification failed: {reason}.")
    event = prepared
    writer = get_writer(resolved_cfg)
    if writer is None:
        raise RuntimeError("SQL telemetry writer unavailable.")
    if writer.error:
        raise RuntimeError(writer.error)
    if not writer.enqueue(event):
        raise RuntimeError("SQL telemetry queue rejected the event.")
    return True


def stop_writer(timeout_s: float | None = None) -> Dict[str, int] | None:
    """Stop the shared writer, flushing queued events within ``timeout_s`` seconds
    (default: the writer's ``stop_timeout_s``). Returns its final delivery
    counters, or None when no writer was running."""
    global _WRITER, _WRITER_KEY
    with _WRITER_LOCK:
        writer = _WRITER
        _WRITER = None
        _WRITER_KEY = None
    if writer is None:
        return None
    writer.stop(timeout_s)
    return writer.stats()


def writer_stats() -> Dict[str, int] | None:
    """Delivery counters of the shared writer, or None when none is running."""
    writer = _WRITER
    return writer.stats() if writer is not None else None


# Flush events still queued when the interpreter exits (bounded by stop_timeout_s).
atexit.register(stop_writer)


def begin_session(
    config: Dict[str, Any],
    session_id: str,
    created_utc: str,
    lionlock_version: str,
    model: str,
    base_url: str,
    config_hash: str,
    content_policy: str,
) -> int | None:
    resolved_cfg = resolve_sql_config(config)
    uri = str(resolved_cfg.get("uri", "")).strip()
    sessions_table = str(resolved_cfg.get("sessions_table", "lionlock_sessions")).strip()
    try:
        sessions_table = _validate_table_name(sessions_table, "sessions_table")
    except ValueError:
        return None
    if not uri or not session_id:
        return None
    sqlite_path = _sqlite_path_from_uri(uri)
    try:
        if sqlite_path is not None:
            _init_sqlite_table(sqlite_path, sessions_table, SESSIONS_COLUMNS)
            with sqlite3.connect(sqlite_path) as conn:
                conn.execute(
                    (
                        f"INSERT OR IGNORE INTO {sessions_table} "
                        "(session_id,created_utc,lionlock_version,model,base_url,config_hash,content_policy,"
                        "has_anomalies,anomaly_count,anomaly_severity_score,anomaly_severity_tag) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?)"
                    ),
                    (
                        session_id,
                        created_utc,
                        lionlock_version,
                        model,
                        base_url,
                        config_hash,
                        content_policy,
                        0,
                        0,
                        0.0,
                        "normal",
                    ),
                )
                conn.execute(
                    (
                        f"UPDATE {sessions_table} SET model=?, base_url=?, config_hash=?, "
                        "content_policy=? WHERE session_id=?"
                    ),
                    (model, base_url, config_hash, content_policy, session_id),
                )
                row = conn.execute(
                    f"SELECT session_pk FROM {sessions_table} WHERE session_id=?",
                    (session_id,),
                ).fetchone()
                return int(row[0]) if row else None
        if create_engine is None or text is None:
            return None
        engine = create_engine(uri)
        ddl = _create_table_sql(sessions_table, SESSIONS_COLUMNS)
        with engine.begin() as conn:
            conn.execute(text(ddl))
            conn.execute(
                text(
                    (
                        f"INSERT INTO {sessions_table} "
                        "(session_id,created_utc,lionlock_version,model,base_url,config_hash,content_policy,"
                        "has_anomalies,anomaly_count,anomaly_severity_score,anomaly_severity_tag) "
                        "VALUES (:session_id,:created_utc,:lionlock_version,:model,"
                        ":base_url,:config_hash,:content_policy,:has_anomalies,:anomaly_count,"
                        ":anomaly_severity_score,:anomaly_severity_tag)"
                    )
                ),
                {
                    "session_id": session_id,
                    "created_utc": created_utc,
                    "lionlock_version": lionlock_version,
                    "model": model,
                    "base_url": base_url,
                    "config_hash": config_hash,
                    "content_policy": content_policy,
                    "has_anomalies": 0,
                    "anomaly_count": 0,
                    "anomaly_severity_score": 0.0,
                    "anomaly_severity_tag": "normal",
                },
            )
            conn.execute(
                text(
                    (
                        f"UPDATE {sessions_table} SET model=:model, base_url=:base_url, "
                        "config_hash=:config_hash, content_policy=:content_policy "
                        "WHERE session_id=:session_id"
                    )
                ),
                {
                    "model": model,
                    "base_url": base_url,
                    "config_hash": config_hash,
                    "content_policy": content_policy,
                    "session_id": session_id,
                },
            )
            row = conn.execute(
                text(f"SELECT session_pk FROM {sessions_table} WHERE session_id=:session_id"),
                {"session_id": session_id},
            ).fetchone()
            return int(row[0]) if row else None
    except Exception:
        return None


def update_session_anomalies(
    config: Dict[str, Any],
    session_id: str,
    session_pk: int | None,
    anomaly_count: int,
    severity_score: float,
    severity_tag: str,
) -> None:
    resolved_cfg = resolve_sql_config(config)
    uri = str(resolved_cfg.get("uri", "")).strip()
    sessions_table = str(resolved_cfg.get("sessions_table", "lionlock_sessions")).strip()
    try:
        sessions_table = _validate_table_name(sessions_table, "sessions_table")
    except ValueError:
        return
    if not uri or not session_id:
        return
    sqlite_path = _sqlite_path_from_uri(uri)
    try:
        if sqlite_path is not None:
            with sqlite3.connect(sqlite_path) as conn:
                conn.execute(
                    (
                        f"UPDATE {sessions_table} SET has_anomalies=?, anomaly_count=?, "
                        "anomaly_severity_score=?, anomaly_severity_tag=? WHERE session_id=?"
                    ),
                    (
                        1 if anomaly_count > 0 else 0,
                        anomaly_count,
                        severity_score,
                        severity_tag,
                        session_id,
                    ),
                )
                conn.commit()
            return
        if create_engine is None or text is None:
            return
        engine = create_engine(uri)
        with engine.begin() as conn:
            conn.execute(
                text(
                    (
                        f"UPDATE {sessions_table} SET has_anomalies=:has_anomalies, "
                        "anomaly_count=:anomaly_count, anomaly_severity_score=:severity_score, "
                        "anomaly_severity_tag=:severity_tag WHERE session_id=:session_id"
                    )
                ),
                {
                    "has_anomalies": 1 if anomaly_count > 0 else 0,
                    "anomaly_count": anomaly_count,
                    "severity_score": severity_score,
                    "severity_tag": severity_tag,
                    "session_id": session_id,
                },
            )
    except Exception:
        return


def write_failsafe_blob(
    config: Dict[str, Any],
    timestamp_utc: str,
    request_id: str,
    payload_b64: str,
) -> Tuple[bool, str]:
    try:
        resolved_cfg = resolve_sql_config(config)
    except Exception as exc:
        return False, f"Failsafe SQL insert failed: {exc}"
    uri = str(resolved_cfg.get("uri", "")).strip()
    table = str(resolved_cfg.get("sql_table", "lionlock_failsafe")).strip()
    if not uri:
        return False, "SQL URI is empty."
    try:
        table = _validate_table_name(table, "failsafe_table")
    except ValueError as exc:
        return False, f"Failsafe SQL insert failed: {exc}"
    sqlite_path = _sqlite_path_from_uri(uri)
    try:
        if sqlite_path is not None:
            _init_sqlite_failsafe_table(sqlite_path, table)
            with sqlite3.connect(
                sqlite_path,
                timeout=int(config.get("connect_timeout_s", 5)),
            ) as conn:
                sql_stmt = (
                    f"INSERT INTO {table} (timestamp_utc,request_id,payload_b64) VALUES (?,?,?)"
                )
                conn.execute(sql_stmt, (timestamp_utc, request_id, payload_b64))
                conn.commit()
            return True, "Failsafe SQL insert ok."
        if create_engine is None or text is None:
            return False, "SQLAlchemy not installed; cannot write failsafe SQL."
        _init_sqlalchemy_table(uri, table, FAILSAFE_COLUMNS)
        engine = create_engine(uri)
        sql_text = text(
            (
                f"INSERT INTO {table} (timestamp_utc,request_id,payload_b64) "
                "VALUES (:timestamp_utc,:request_id,:payload_b64)"
            )
        )
        with engine.begin() as conn:
            conn.execute(
                sql_text,
                {
                    "timestamp_utc": timestamp_utc,
                    "request_id": request_id,
                    "payload_b64": payload_b64,
                },
            )
        return True, "Failsafe SQL insert ok."
    except Exception as exc:
        return False, f"Failsafe SQL insert failed: {exc}"
