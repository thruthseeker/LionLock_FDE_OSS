from __future__ import annotations

import atexit
import json
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from lionlock.utils.sql_batch_writer import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_BACKOFF_MS,
    DEFAULT_STOP_TIMEOUT_S,
    SQLBatchWriter,
)

TRUST_OVERLAY_COLUMNS: List[Tuple[str, str]] = [
    ("timestamp", "TEXT"),
    ("session_id", "TEXT"),
    ("turn_index", "INTEGER"),
    ("model_id", "TEXT"),
    ("prompt_type", "TEXT"),
    ("response_hash", "TEXT"),
    ("pseudonymous_user_key", "TEXT"),
    ("trust_score", "REAL"),
    ("trust_label", "TEXT"),
    ("volatility", "REAL"),
    ("badge", "TEXT"),
    ("trust_logic_version", "TEXT"),
    ("code_fingerprint", "TEXT"),
    ("confidence_band_json", "TEXT"),
    ("trigger_flags_json", "TEXT"),
    ("drift_json", "TEXT"),
    ("record_json", "TEXT"),
]

_WRITER: "TrustOverlaySQLWriter | None" = None
_WRITER_KEY: Tuple[Any, ...] | None = None
_WRITER_LOCK = threading.Lock()


def _serialize(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return _serialize(value)


def _create_table_sql(table: str, columns: Iterable[Tuple[str, str]]) -> str:
    cols = ", ".join(f"{name} {col_type}" for name, col_type in columns)
    return f"CREATE TABLE IF NOT EXISTS {table} ({cols})"


def _sqlite_path_from_dsn(dsn: str) -> str | None:
    prefix = "sqlite:///"
    if not dsn.startswith(prefix):
        return None
    path = dsn[len(prefix) :]
    if path == ":memory:":
        return path
    if path.startswith("/"):
        return path
    return path


def _resolve_sqlite_path(backend: str, dsn: str, sqlite_path: str) -> str | None:
    if sqlite_path:
        return sqlite_path
    if not dsn:
        return None
    if backend == "sqlite3":
        if dsn.startswith("sqlite:///"):
            return _sqlite_path_from_dsn(dsn)
        if "://" in dsn:
            return None
        return dsn
    return _sqlite_path_from_dsn(dsn)


def _init_sqlite_table(db_path: str, table: str, columns: Iterable[Tuple[str, str]]) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(_create_table_sql(table, columns))
        conn.commit()


def _init_sqlalchemy_table(uri: str, table: str, columns: Iterable[Tuple[str, str]]) -> None:
    if create_engine is None or text is None:
        raise RuntimeError("SQLAlchemy is required for non-sqlite Trust Overlay SQL.")
    engine = create_engine(uri)
    ddl = _create_table_sql(table, columns)
    with engine.begin() as conn:
        conn.execute(text(ddl))


def _normalize_backend(value: str | None) -> str:
    backend = str(value or "").strip().lower()
    return backend if backend in {"sqlite3", "sqlalchemy"} else "sqlite3"


def _resolve_targets(config: Dict[str, Any]) -> tuple[str, str, str | None]:
    backend = _normalize_backend(config.get("backend"))
    dsn = str(config.get("dsn", "") or config.get("uri", "")).strip()
    sqlite_path = str(config.get("sqlite_path", "")).strip()
    if backend == "sqlalchemy" and not dsn and sqlite_path:
        dsn = f"sqlite:///{sqlite_path}"
    resolved_sqlite_path = (
        _resolve_sqlite_path(backend, dsn, sqlite_path) if backend == "sqlite3" else None
    )
    return backend, dsn, resolved_sqlite_path


def init_db(config: Dict[str, Any]) -> Tuple[bool, str]:
    backend, dsn, sqlite_path = _resolve_targets(config)
    table = str(config.get("table", "trust_overlay_records")).strip()
    if not table:
        return False, "Trust overlay table name is empty."
    try:
        if backend == "sqlite3":
            if not sqlite_path:
                return False, "Trust overlay sqlite_path is empty."
            _init_sqlite_table(sqlite_path, table, TRUST_OVERLAY_COLUMNS)
            return True, "Initialized trust overlay sqlite table."
        if create_engine is None or text is None:
            return False, "SQLAlchemy not installed; cannot init trust overlay SQL."
        if not dsn:
            return False, "Trust overlay SQL DSN is empty."
        _init_sqlalchemy_table(dsn, table, TRUST_OVERLAY_COLUMNS)
        return True, "Initialized trust overlay SQL table."
    except Exception as exc:
        return False, f"Trust overlay SQL init failed: {exc}"


def _record_to_row(record: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        record.get("timestamp"),
        record.get("session_id"),
        record.get("turn_index"),
        record.get("model_id"),
        record.get("prompt_type"),
        record.get("response_hash"),
        record.get("pseudonymous_user_key"),
        record.get("trust_score"),
        record.get("trust_label"),
        record.get("volatility"),
        record.get("badge"),
        record.get("trust_logic_version"),
        record.get("code_fingerprint"),
        _json_or_none(record.get("confidence_band")),
        _json_or_none(record.get("trigger_flags")),
        _json_or_none(record.get("drift")),
        _serialize(record),
    )


def _record_to_named_row(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": record.get("timestamp"),
        "session_id": record.get("session_id"),
        "turn_index": record.get("turn_index"),
        "model_id": record.get("model_id"),
        "prompt_type": record.get("prompt_type"),
        "response_hash": record.get("response_hash"),
        "pseudonymous_user_key": record.get("pseudonymous_user_key"),
        "trust_score": record.get("trust_score"),
        "trust_label": record.get("trust_label"),
        "volatility": record.get("volatility"),
        "badge": record.get("badge"),
        "trust_logic_version": record.get("trust_logic_version"),
        "code_fingerprint": record.get("code_fingerprint"),
        "confidence_band_json": _json_or_none(record.get("confidence_band")),
        "trigger_flags_json": _json_or_none(record.get("trigger_flags")),
        "drift_json": _json_or_none(record.get("drift")),
        "record_json": _serialize(record),
    }


class TrustOverlaySQLWriter(SQLBatchWriter):
    """Batched SQL writer for trust overlay records; delivery policy in SQLBatchWriter."""

    sink_name = "trust_overlay_sql"

    def __init__(
        self,
        *,
        backend: str,
        dsn: str,
        sqlite_path: str | None,
        table: str,
        batch_size: int,
        flush_interval_ms: int,
        connect_timeout_s: int,
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
        self.backend = _normalize_backend(backend)
        self.dsn = dsn
        self.sqlite_path = sqlite_path
        self.table = table
        self.connect_timeout_s = max(1, connect_timeout_s)

        if self.backend == "sqlite3":
            if not self.sqlite_path:
                self.available = False
                self.error = "Trust overlay sqlite_path missing."
            else:
                self._init_tables()
        else:
            if create_engine is None or text is None:
                self.available = False
                self.error = "SQLAlchemy not installed; trust overlay SQL disabled."
            elif not self.dsn:
                self.available = False
                self.error = "Trust overlay SQL DSN missing."
            else:
                self._init_tables()

        if self.available:
            self._start()

    def _init_tables(self) -> None:
        try:
            if self.backend == "sqlite3":
                assert self.sqlite_path is not None
                _init_sqlite_table(self.sqlite_path, self.table, TRUST_OVERLAY_COLUMNS)
            else:
                if create_engine is None or text is None:
                    raise RuntimeError("SQLAlchemy not installed.")
                self.engine = create_engine(self.dsn)
                ddl = _create_table_sql(self.table, TRUST_OVERLAY_COLUMNS)
                with self.engine.begin() as conn:
                    conn.execute(text(ddl))
        except Exception as exc:
            self.available = False
            self.error = f"Trust overlay SQL init failed: {exc}"

    def _write_batch(self, records: List[Dict[str, Any]]) -> None:
        columns = ",".join(name for name, _ in TRUST_OVERLAY_COLUMNS)
        if self.backend == "sqlite3":
            assert self.sqlite_path is not None
            placeholders = ",".join("?" for _ in TRUST_OVERLAY_COLUMNS)
            sql = f"INSERT INTO {self.table} ({columns}) VALUES ({placeholders})"
            rows = [_record_to_row(record) for record in records]
            with closing(sqlite3.connect(self.sqlite_path, timeout=self.connect_timeout_s)) as conn:
                with conn:  # Commits on success, rolls back on error.
                    conn.executemany(sql, rows)
            return
        if self.engine is None or text is None:
            raise RuntimeError("SQLAlchemy not installed.")
        values = ",".join(f":{name}" for name, _ in TRUST_OVERLAY_COLUMNS)
        stmt = text(f"INSERT INTO {self.table} ({columns}) VALUES ({values})")
        with self.engine.begin() as conn:
            conn.execute(stmt, [_record_to_named_row(record) for record in records])


def get_writer(config: Dict[str, Any]) -> TrustOverlaySQLWriter | None:
    global _WRITER, _WRITER_KEY
    backend, dsn, sqlite_path = _resolve_targets(config)
    table = str(config.get("table", "trust_overlay_records")).strip()
    batch_size = int(config.get("batch_size", 50))
    flush_interval_ms = int(config.get("flush_interval_ms", 1000))
    connect_timeout_s = int(config.get("connect_timeout_s", 5))
    max_retries = int(config.get("max_retries", DEFAULT_MAX_RETRIES))
    retry_backoff_ms = int(config.get("retry_backoff_ms", DEFAULT_RETRY_BACKOFF_MS))
    stop_timeout_s = float(config.get("stop_timeout_s", DEFAULT_STOP_TIMEOUT_S))

    if backend == "sqlite3":
        if not sqlite_path or not table:
            stop_writer()
            return None
    else:
        if not dsn or not table:
            stop_writer()
            return None

    key = (
        backend,
        dsn,
        sqlite_path,
        table,
        batch_size,
        flush_interval_ms,
        connect_timeout_s,
        max_retries,
        retry_backoff_ms,
        stop_timeout_s,
    )
    with _WRITER_LOCK:
        if _WRITER is not None and (_WRITER_KEY != key or _WRITER.stop_event.is_set()):
            # Reconfigured, or stopped by its owner: flush what it still holds.
            _WRITER.stop()
            _WRITER = None
            _WRITER_KEY = None
        if _WRITER is None:
            _WRITER = TrustOverlaySQLWriter(
                backend=backend,
                dsn=dsn,
                sqlite_path=sqlite_path,
                table=table,
                batch_size=batch_size,
                flush_interval_ms=flush_interval_ms,
                connect_timeout_s=connect_timeout_s,
                max_retries=max_retries,
                retry_backoff_ms=retry_backoff_ms,
                stop_timeout_s=stop_timeout_s,
            )
            _WRITER_KEY = key
        # A writer that failed to start stays cached, so init is not retried per record.
        return _WRITER if _WRITER.available else None


def enqueue_record(config: Dict[str, Any], record: Dict[str, Any]) -> bool:
    if not config.get("enabled"):
        return False
    writer = get_writer(config)
    if writer is None:
        return False
    return writer.enqueue(record)


def stop_writer(timeout_s: float | None = None) -> Dict[str, int] | None:
    """Stop the shared writer, flushing queued records within ``timeout_s`` seconds
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


# Flush records still queued when the interpreter exits (bounded by stop_timeout_s).
atexit.register(stop_writer)
