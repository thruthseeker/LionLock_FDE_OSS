from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from lionlock.logging.connection import validate_identifier


EVENT_COLUMNS = (
    "event_pk",
    "session_id",
    "turn_index",
    "timestamp",
    "signal_bundle",
    "gating_decision",
    "decision_risk_score",
    "trigger_signal",
    "trust_logic_version",
    "policy_version",
    "config_hash",
    "code_fingerprint",
    "prompt_type",
    "response_hash",
    "replay_id",
    "event_type",
    "event_severity",
)


@dataclass(frozen=True)
class TelemetryEvent:
    event_pk: int | None
    session_id: str
    turn_index: int
    timestamp: str | None
    signal_bundle: Any
    gating_decision: str | None
    decision_risk_score: float | None
    trigger_signal: str | None
    trust_logic_version: str | None
    policy_version: str | None
    config_hash: str | None
    code_fingerprint: str | None
    prompt_type: str | None
    response_hash: str | None
    replay_id: str | None
    event_type: str | None
    event_severity: str | None


class ReadError(RuntimeError):
    pass


def _sqlite_path_from_uri(uri: str) -> str | None:
    prefix = "sqlite:///"
    if not uri.startswith(prefix):
        return None
    return uri[len(prefix) :]


def _normalize_event(row: Iterable[Any]) -> TelemetryEvent:
    values = list(row)
    data = dict(zip(EVENT_COLUMNS, values))
    event_pk_raw = data.get("event_pk")
    try:
        event_pk = int(event_pk_raw)
    except Exception:
        event_pk = None
    turn_index = data.get("turn_index")
    try:
        turn_index = int(turn_index)
    except Exception:
        turn_index = 0
    replay_id = data.get("replay_id")
    replay_id = str(replay_id).strip() if replay_id is not None else None
    if replay_id == "":
        replay_id = None
    return TelemetryEvent(
        event_pk=event_pk,
        session_id=str(data.get("session_id") or ""),
        turn_index=turn_index,
        timestamp=str(data.get("timestamp") or "") or None,
        signal_bundle=data.get("signal_bundle"),
        gating_decision=str(data.get("gating_decision") or "") or None,
        decision_risk_score=data.get("decision_risk_score"),
        trigger_signal=str(data.get("trigger_signal") or "") or None,
        trust_logic_version=str(data.get("trust_logic_version") or "") or None,
        policy_version=str(data.get("policy_version") or "") or None,
        config_hash=str(data.get("config_hash") or "") or None,
        code_fingerprint=str(data.get("code_fingerprint") or "") or None,
        prompt_type=str(data.get("prompt_type") or "") or None,
        response_hash=str(data.get("response_hash") or "") or None,
        replay_id=replay_id,
        event_type=str(data.get("event_type") or "") or None,
        event_severity=str(data.get("event_severity") or "") or None,
    )


def read_events(
    uri_or_dsn: str,
    *,
    session_id: str | None = None,
    limit: int | None = None,
    schema: str = "public",
) -> List[TelemetryEvent]:
    if not uri_or_dsn:
        raise ReadError("SQL URI is empty.")
    sqlite_path = _sqlite_path_from_uri(uri_or_dsn)
    columns = ",".join(EVENT_COLUMNS)
    order_by = "session_id,turn_index,replay_id,response_hash,event_type,event_pk"
    sqlite_params: list[Any] = []
    sqlite_where = ["event_type = ?"]
    sqlite_params.append("gating_decision")
    if session_id:
        sqlite_where.append("session_id = ?")
        sqlite_params.append(session_id)
    sqlite_where_sql = " AND ".join(sqlite_where)
    sqlalchemy_params: dict[str, Any] = {"event_type": "gating_decision"}
    sqlalchemy_where = ["event_type = :event_type"]
    if session_id:
        sqlalchemy_where.append("session_id = :session_id")
        sqlalchemy_params["session_id"] = session_id
    sqlalchemy_where_sql = " AND ".join(sqlalchemy_where)
    limit_sql = ""
    if isinstance(limit, int) and limit > 0:
        limit_sql = f" LIMIT {limit}"

    if sqlite_path is not None:
        conn = None
        try:
            if sqlite_path != ":memory:":
                db_path = sqlite_path
                if not Path(db_path).exists():
                    raise ReadError(f"SQLite database not found: {db_path}")
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            else:
                conn = sqlite3.connect(sqlite_path)
            rows = conn.execute(
                f"SELECT {columns} FROM events WHERE {sqlite_where_sql} "
                f"ORDER BY {order_by}{limit_sql}",
                sqlite_params,
            ).fetchall()
            return [_normalize_event(row) for row in rows]
        except Exception as exc:
            raise ReadError(f"SQLite read failed: {exc}") from exc
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass

    if create_engine is None or text is None:
        raise ReadError("SQLAlchemy not installed; cannot read non-sqlite URI.")

    validate_identifier(schema, "schema")
    table = f"{schema}.events" if schema else "events"
    try:
        engine = create_engine(uri_or_dsn)
        stmt = text(
            f"SELECT {columns} FROM {table} WHERE {sqlalchemy_where_sql} "
            f"ORDER BY {order_by}{limit_sql}"
        )
        with engine.begin() as conn:
            rows = conn.execute(stmt, sqlalchemy_params).fetchall()
        return [_normalize_event(row) for row in rows]
    except Exception as exc:
        raise ReadError(f"SQL read failed: {exc}") from exc
    finally:
        try:
            engine.dispose()
        except Exception:
            pass
