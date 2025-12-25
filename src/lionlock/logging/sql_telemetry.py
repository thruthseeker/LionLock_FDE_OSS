import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

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

_WRITER: "SQLTelemetryWriter | None" = None
_WRITER_KEY: Tuple[Any, ...] | None = None


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
        event.get("decision"),
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
    )


def _event_to_named_row(event: Dict[str, Any], session_pk: int | None) -> Dict[str, Any]:
    scores = event.get("signal_scores") or {}
    return {
        "session_pk": session_pk,
        "timestamp_utc": event.get("timestamp_utc"),
        "request_id": event.get("request_id"),
        "decision": event.get("decision"),
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
    }


class SQLTelemetryWriter:
    def __init__(
        self,
        uri: str,
        table: str,
        sessions_table: str,
        batch_size: int,
        flush_interval_ms: int,
        connect_timeout_s: int,
    ) -> None:
        self.uri = uri
        self.table = table
        self.sessions_table = sessions_table
        self.batch_size = max(1, batch_size)
        self.flush_interval = max(10, flush_interval_ms) / 1000.0
        self.connect_timeout_s = max(1, connect_timeout_s)
        self.queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(
            maxsize=max(100, self.batch_size * 10)
        )
        self.stop_event = threading.Event()
        self.available = True
        self.error: str | None = None
        self.sqlite_path = _sqlite_path_from_uri(uri)
        self.engine: Any = None

        if self.sqlite_path is None and (create_engine is None or text is None):
            self.available = False
            self.error = "SQLAlchemy not installed; SQL telemetry disabled."
        else:
            self._init_tables()
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

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

    def enqueue(self, event: Dict[str, Any]) -> bool:
        if not self.available:
            return False
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            try:
                _ = self.queue.get_nowait()
                self.queue.put_nowait(event)
            except Exception:
                return False
        return True

    def _run(self) -> None:
        buffer: List[Dict[str, Any]] = []
        last_flush = time.monotonic()
        while not self.stop_event.is_set():
            timeout = max(0.1, self.flush_interval - (time.monotonic() - last_flush))
            try:
                item = self.queue.get(timeout=timeout)
                buffer.append(item)
                if len(buffer) >= self.batch_size:
                    self._flush(buffer)
                    buffer = []
                    last_flush = time.monotonic()
            except queue.Empty:
                if buffer:
                    self._flush(buffer)
                    buffer = []
                    last_flush = time.monotonic()
            except Exception as exc:
                self.error = f"SQL telemetry worker error: {exc}"
        if buffer:
            self._flush(buffer)

    def _flush(self, buffer: List[Dict[str, Any]]) -> None:
        if not buffer:
            return
        try:
            if self.sqlite_path is not None:
                columns = ",".join(
                    name for name, _ in PUBLIC_SIGNALS_COLUMNS if name != "event_pk"
                )
                placeholders = ",".join("?" for _ in columns.split(","))
                sql = f"INSERT INTO {self.table} ({columns}) VALUES ({placeholders})"
                with sqlite3.connect(self.sqlite_path, timeout=self.connect_timeout_s) as conn:
                    conn.executemany(
                        sql,
                        [
                            _event_to_row(event, event.get("session_pk"))
                            for event in buffer
                        ],
                    )
                    conn.commit()
            else:
                if self.engine is None or text is None:
                    raise RuntimeError("SQLAlchemy not installed.")
                columns = ",".join(
                    name for name, _ in PUBLIC_SIGNALS_COLUMNS if name != "event_pk"
                )
                values = ",".join(f":{name}" for name in columns.split(","))
                stmt = text(f"INSERT INTO {self.table} ({columns}) VALUES ({values})")
                with self.engine.begin() as conn:
                    conn.execute(
                        stmt,
                        [
                            _event_to_named_row(event, event.get("session_pk"))
                            for event in buffer
                        ],
                    )
        except Exception as exc:
            self.error = f"SQL telemetry insert failed: {exc}"

    def stop(self) -> None:
        self.stop_event.set()


def get_writer(config: Dict[str, Any]) -> SQLTelemetryWriter | None:
    global _WRITER, _WRITER_KEY
    uri = str(config.get("uri", "")).strip()
    table = str(config.get("table", "lionlock_signals")).strip()
    sessions_table = str(config.get("sessions_table", "lionlock_sessions")).strip()
    batch_size = int(config.get("batch_size", 50))
    flush_interval_ms = int(config.get("flush_interval_ms", 1000))
    connect_timeout_s = int(config.get("connect_timeout_s", 5))
    key = (uri, table, sessions_table, batch_size, flush_interval_ms, connect_timeout_s)
    if not uri:
        _WRITER = None
        _WRITER_KEY = None
        return None
    if _WRITER is None or _WRITER_KEY != key:
        _WRITER = SQLTelemetryWriter(
            uri=uri,
            table=table,
            sessions_table=sessions_table,
            batch_size=batch_size,
            flush_interval_ms=flush_interval_ms,
            connect_timeout_s=connect_timeout_s,
        )
        _WRITER_KEY = key
        if not _WRITER.available:
            return None
    return _WRITER


def enqueue_event(
    config: Dict[str, Any],
    event: Dict[str, Any],
    session_pk: int | None = None,
) -> bool:
    if not config.get("enabled"):
        return False
    if session_pk is not None:
        event = dict(event)
        event["session_pk"] = session_pk
    writer = get_writer(config)
    if writer is None:
        return False
    return writer.enqueue(event)


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
    uri = str(config.get("uri", "")).strip()
    sessions_table = str(config.get("sessions_table", "lionlock_sessions")).strip()
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
    uri = str(config.get("uri", "")).strip()
    sessions_table = str(config.get("sessions_table", "lionlock_sessions")).strip()
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
    uri = str(config.get("uri", "")).strip()
    table = str(config.get("sql_table", "lionlock_failsafe")).strip()
    if not uri:
        return False, "SQL URI is empty."
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
