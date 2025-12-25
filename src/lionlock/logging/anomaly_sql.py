import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

ANOMALY_COLUMNS: List[Tuple[str, str]] = [
    ("anomaly_pk", "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("session_id", "TEXT"),
    ("session_pk", "INTEGER"),
    ("timestamp_utc", "TEXT"),
    ("anomaly_type", "TEXT"),
    ("weight", "REAL"),
    ("details", "TEXT"),
    ("related_request_id", "TEXT"),
]

DIAGNOSTICS_COLUMNS: List[Tuple[str, str]] = [
    ("session_id", "TEXT UNIQUE"),
    ("anomaly_count", "INTEGER"),
    ("severity_score", "REAL"),
    ("severity_tag", "TEXT"),
    ("first_seen_utc", "TEXT"),
    ("last_seen_utc", "TEXT"),
]


def _create_table_sql(table: str, columns: Iterable[Tuple[str, str]]) -> str:
    cols = ", ".join(f"{name} {col_type}" for name, col_type in columns)
    return f"CREATE TABLE IF NOT EXISTS {table} ({cols})"


def _sqlite_path_from_uri(uri: str) -> str | None:
    prefix = "sqlite:///"
    if not uri.startswith(prefix):
        return None
    return uri[len(prefix) :]


def init_db(uri: str, anomalies_table: str, diagnostics_table: str) -> Tuple[bool, str]:
    if not uri:
        return False, "Anomaly DB URI is empty."
    sqlite_path = _sqlite_path_from_uri(uri)
    try:
        if sqlite_path is not None:
            Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(sqlite_path) as conn:
                conn.execute(_create_table_sql(anomalies_table, ANOMALY_COLUMNS))
                conn.execute(_create_table_sql(diagnostics_table, DIAGNOSTICS_COLUMNS))
                conn.commit()
            return True, "Initialized anomaly sqlite tables."
        if create_engine is None or text is None:
            return False, "SQLAlchemy not installed; cannot init anomaly DB."
        engine = create_engine(uri)
        with engine.begin() as conn:
            conn.execute(text(_create_table_sql(anomalies_table, ANOMALY_COLUMNS)))
            conn.execute(text(_create_table_sql(diagnostics_table, DIAGNOSTICS_COLUMNS)))
        return True, "Initialized anomaly SQL tables."
    except Exception as exc:
        return False, f"Anomaly SQL init failed: {exc}"


def _sanitize_details(details: str | None) -> str | None:
    if not details:
        return None
    lowered = details.lower()
    forbidden = ("prompt", "response", "user_id", "ip", "device_id")
    if any(token in lowered for token in forbidden):
        return None
    return details


def record_anomalies(
    config: Dict[str, Any],
    session_id: str,
    session_pk: int | None,
    timestamp_utc: str,
    anomalies: Iterable[Dict[str, Any]],
    anomaly_count: int,
    severity_score: float,
    severity_tag: str,
    first_seen_utc: str,
    last_seen_utc: str,
) -> Tuple[bool, str]:
    if not config.get("enabled", True):
        return False, "Anomaly logging disabled."
    uri = str(config.get("db_uri", "")).strip()
    anomalies_table = str(config.get("table", "lionlock_anomalies")).strip()
    diagnostics_table = str(config.get("diagnostics_table", "lionlock_session_diagnostics")).strip()
    if not uri or not session_id:
        return False, "Anomaly logging missing URI or session_id."

    ok, message = init_db(uri, anomalies_table, diagnostics_table)
    if not ok:
        return False, message

    rows = []
    for anomaly in anomalies:
        rows.append(
            (
                session_id,
                session_pk,
                timestamp_utc,
                anomaly.get("anomaly_type"),
                anomaly.get("weight"),
                _sanitize_details(anomaly.get("details")),
                anomaly.get("related_request_id"),
            )
        )

    sqlite_path = _sqlite_path_from_uri(uri)
    try:
        if sqlite_path is not None:
            with sqlite3.connect(sqlite_path) as conn:
                conn.executemany(
                    (
                        f"INSERT INTO {anomalies_table} "
                        "(session_id,session_pk,timestamp_utc,anomaly_type,weight,"
                        "details,related_request_id) "
                        "VALUES (?,?,?,?,?,?,?)"
                    ),
                    rows,
                )
                conn.execute(
                    (
                        f"INSERT INTO {diagnostics_table} "
                        "(session_id,anomaly_count,severity_score,severity_tag,first_seen_utc,"
                        "last_seen_utc) "
                        "VALUES (?,?,?,?,?,?) "
                        "ON CONFLICT(session_id) DO UPDATE SET "
                        "anomaly_count=excluded.anomaly_count, "
                        "severity_score=excluded.severity_score, "
                        "severity_tag=excluded.severity_tag, "
                        "last_seen_utc=excluded.last_seen_utc"
                    ),
                    (
                        session_id,
                        anomaly_count,
                        severity_score,
                        severity_tag,
                        first_seen_utc,
                        last_seen_utc,
                    ),
                )
                conn.commit()
            return True, "Anomaly records written."
        if create_engine is None or text is None:
            return False, "SQLAlchemy not installed; cannot write anomaly DB."
        engine = create_engine(uri)
        with engine.begin() as conn:
            conn.execute(
                text(
                    (
                        f"INSERT INTO {anomalies_table} "
                        "(session_id,session_pk,timestamp_utc,anomaly_type,weight,"
                        "details,related_request_id) "
                        "VALUES (:session_id,:session_pk,:timestamp_utc,:anomaly_type,"
                        ":weight,:details,:related_request_id)"
                    )
                ),
                [
                    {
                        "session_id": row[0],
                        "session_pk": row[1],
                        "timestamp_utc": row[2],
                        "anomaly_type": row[3],
                        "weight": row[4],
                        "details": row[5],
                        "related_request_id": row[6],
                    }
                    for row in rows
                ],
            )
            update_result = conn.execute(
                text(
                    (
                        f"UPDATE {diagnostics_table} SET "
                        "anomaly_count=:anomaly_count, "
                        "severity_score=:severity_score, "
                        "severity_tag=:severity_tag, "
                        "last_seen_utc=:last_seen_utc "
                        "WHERE session_id=:session_id"
                    )
                ),
                {
                    "session_id": session_id,
                    "anomaly_count": anomaly_count,
                    "severity_score": severity_score,
                    "severity_tag": severity_tag,
                    "last_seen_utc": last_seen_utc,
                },
            )
            if update_result.rowcount == 0:
                conn.execute(
                    text(
                        (
                            f"INSERT INTO {diagnostics_table} "
                            "(session_id,anomaly_count,severity_score,severity_tag,"
                            "first_seen_utc,last_seen_utc) "
                            "VALUES (:session_id,:anomaly_count,:severity_score,:severity_tag,"
                            ":first_seen_utc,:last_seen_utc)"
                        )
                    ),
                    {
                        "session_id": session_id,
                        "anomaly_count": anomaly_count,
                        "severity_score": severity_score,
                        "severity_tag": severity_tag,
                        "first_seen_utc": first_seen_utc,
                        "last_seen_utc": last_seen_utc,
                    },
                )
        return True, "Anomaly records written."
    except Exception as exc:
        return False, f"Anomaly insert failed: {exc}"
