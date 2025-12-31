from __future__ import annotations

import json
import math
import sqlite3
from typing import Any, Dict, Iterable, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from lionlock.core.models import canonical_gating_decision

from . import sql_init
from .connection import validate_identifier
from .privacy import find_forbidden_content, scrub_forbidden_keys
from .token_auth import AUTH_SIGNATURE_FIELD, AUTH_TOKEN_ID_FIELD, prepare_event_for_sql

MISSED_SIGNAL_COLUMNS = (
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
    "replay_id",
    "miss_reason",
    "expected_decision",
    "actual_decision",
    AUTH_TOKEN_ID_FIELD,
    AUTH_SIGNATURE_FIELD,
)

ALLOWED_PROMPT_TYPES = {"qa", "code", "creative", "other", "unknown"}
ALLOWED_DECISIONS = {"ALLOW", "REFRESH", "BLOCK"}

_MEMORY_CONNECTION: sqlite3.Connection | None = None


def _sqlite_path_from_uri(uri: str) -> str | None:
    prefix = "sqlite:///"
    if not uri.startswith(prefix):
        return None
    return uri[len(prefix) :]


def _serialize_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    try:
        parsed = float(value)
    except Exception:
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _normalize_prompt_type(value: Any) -> str:
    if value is None:
        return "unknown"
    lowered = str(value).strip().lower()
    if lowered in ALLOWED_PROMPT_TYPES:
        return lowered
    return "other"


def _signal_bundle_payload(value: Any) -> Tuple[bool, Any | None, str | None]:
    bundle = value
    if hasattr(value, "as_dict"):
        try:
            bundle = value.as_dict()
        except Exception:
            bundle = value
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except Exception:
            return False, None, "signal_bundle must be JSON-serializable"
    if not isinstance(bundle, (dict, list)):
        return False, None, "signal_bundle must be a dict or list"
    ok, cleaned, message = scrub_forbidden_keys(bundle, mode="reject")
    if not ok:
        return False, None, message or "signal_bundle contains forbidden keys"
    found = find_forbidden_content(cleaned)
    if found:
        return False, None, f"signal_bundle contains forbidden content at {found}"
    return True, cleaned, None


def _ensure_memory_schema(conn: sqlite3.Connection) -> None:
    tables = sql_init._table_specs("sqlite")
    for table, columns in tables.items():
        conn.execute(sql_init._create_table_sql(table, columns))
        sql_init._ensure_sqlite_columns(conn, table, columns)
    sql_init._ensure_sqlite_unique_indexes(conn)
    conn.commit()


def _memory_connection() -> sqlite3.Connection:
    global _MEMORY_CONNECTION
    if _MEMORY_CONNECTION is None:
        _MEMORY_CONNECTION = sqlite3.connect(":memory:")
        _ensure_memory_schema(_MEMORY_CONNECTION)
    return _MEMORY_CONNECTION


def record_missed_signal_event(
    *,
    uri_or_dsn: str,
    record: Dict[str, Any],
    schema: str = "public",
) -> tuple[bool, str]:
    if not uri_or_dsn:
        return False, "SQL URI is empty."
    if not isinstance(record, dict):
        return False, "Record payload must be a dict."

    ok, message = sql_init.init_schema(uri_or_dsn, schema=schema)
    if not ok:
        return False, message

    payload = dict(record)
    token_config = payload.pop("token_auth", None)

    ok, cleaned, message = scrub_forbidden_keys(payload, mode="reject")
    if not ok:
        return False, message or "Record payload contains forbidden keys"
    payload = cleaned
    found = find_forbidden_content(payload)
    if found:
        return False, f"Record payload contains forbidden content at {found}"

    missing = []
    session_id = str(payload.get("session_id") or "").strip()
    if not session_id:
        missing.append("session_id")

    turn_index_raw = payload.get("turn_index")
    turn_index: int | None = None
    if isinstance(turn_index_raw, bool) or turn_index_raw is None:
        missing.append("turn_index")
    else:
        try:
            turn_index = int(turn_index_raw)
        except Exception:
            missing.append("turn_index")
        else:
            if turn_index < 0:
                missing.append("turn_index")

    timestamp = str(payload.get("timestamp") or "").strip()
    if not timestamp:
        missing.append("timestamp")

    gating_decision_raw = payload.get("gating_decision")
    if gating_decision_raw is None:
        gating_decision_raw = payload.get("decision")
    gating_decision = canonical_gating_decision(
        str(gating_decision_raw) if gating_decision_raw is not None else None
    )
    if gating_decision not in ALLOWED_DECISIONS:
        missing.append("gating_decision")

    decision_risk_score = _safe_float(payload.get("decision_risk_score"))
    if decision_risk_score is None:
        missing.append("decision_risk_score")
    else:
        decision_risk_score = _clamp(decision_risk_score)

    trigger_signal = str(payload.get("trigger_signal") or "").strip()
    if not trigger_signal:
        missing.append("trigger_signal")

    trust_logic_version = str(payload.get("trust_logic_version") or "").strip()
    if not trust_logic_version:
        missing.append("trust_logic_version")

    code_fingerprint = str(payload.get("code_fingerprint") or "").strip()
    if not code_fingerprint:
        missing.append("code_fingerprint")

    response_hash = str(payload.get("response_hash") or "").strip()
    if not response_hash:
        missing.append("response_hash")

    replay_id_raw = payload.get("replay_id")
    replay_id = str(replay_id_raw).strip() if replay_id_raw is not None else None
    if not replay_id:
        replay_id = None

    miss_reason = str(payload.get("miss_reason") or "").strip()
    if not miss_reason:
        missing.append("miss_reason")

    expected_raw = payload.get("expected_decision")
    actual_raw = payload.get("actual_decision")
    expected_decision = canonical_gating_decision(
        str(expected_raw) if expected_raw is not None else None
    )
    actual_decision = canonical_gating_decision(
        str(actual_raw) if actual_raw is not None else None
    )
    if expected_decision not in ALLOWED_DECISIONS:
        missing.append("expected_decision")
    if actual_decision not in ALLOWED_DECISIONS:
        missing.append("actual_decision")

    prompt_type = _normalize_prompt_type(payload.get("prompt_type"))

    bundle_ok, bundle_payload, bundle_message = _signal_bundle_payload(payload.get("signal_bundle"))
    if not bundle_ok:
        return False, bundle_message or "Invalid signal_bundle"

    if missing:
        return False, f"Missing required fields: {sorted(set(missing))}"

    row_data: Dict[str, Any] = {
        "session_id": session_id,
        "turn_index": turn_index,
        "timestamp": timestamp,
        "signal_bundle": _serialize_json(bundle_payload),
        "gating_decision": gating_decision,
        "decision_risk_score": decision_risk_score,
        "trigger_signal": trigger_signal,
        "trust_logic_version": trust_logic_version,
        "code_fingerprint": code_fingerprint,
        "prompt_type": prompt_type,
        "response_hash": response_hash,
        "replay_id": replay_id,
        "miss_reason": miss_reason,
        "expected_decision": expected_decision,
        "actual_decision": actual_decision,
        AUTH_TOKEN_ID_FIELD: payload.get(AUTH_TOKEN_ID_FIELD),
        AUTH_SIGNATURE_FIELD: payload.get(AUTH_SIGNATURE_FIELD),
    }

    if token_config is not None:
        ok, message, prepared = prepare_event_for_sql(row_data, token_config=token_config)
        if not ok:
            return False, f"Auth failed: {message}"
        row_data = prepared
        row_data.setdefault(AUTH_TOKEN_ID_FIELD, None)
        row_data.setdefault(AUTH_SIGNATURE_FIELD, None)

    validate_identifier("missed_signal_events", "table")
    for column in MISSED_SIGNAL_COLUMNS:
        validate_identifier(column, "column")
        if column not in row_data:
            return False, f"Missing column value for {column}"

    sqlite_path = _sqlite_path_from_uri(uri_or_dsn)
    if sqlite_path is not None:
        conn = _memory_connection() if sqlite_path == ":memory:" else None
        try:
            if conn is None:
                conn = sqlite3.connect(sqlite_path)
            placeholders = ",".join("?" for _ in MISSED_SIGNAL_COLUMNS)
            sql = (
                f"INSERT INTO missed_signal_events "
                f"({','.join(MISSED_SIGNAL_COLUMNS)}) "
                f"VALUES ({placeholders})"
            )
            conn.execute(sql, [row_data[col] for col in MISSED_SIGNAL_COLUMNS])
            conn.commit()
            return True, "Missed-signal event recorded."
        except sqlite3.IntegrityError as exc:
            if "unique" in str(exc).lower():
                return True, "Duplicate missed-signal event ignored."
            return False, f"SQLite insert failed: {exc}"
        except Exception as exc:
            return False, f"SQLite insert failed: {exc}"
        finally:
            if sqlite_path != ":memory:" and conn is not None:
                conn.close()

    if create_engine is None or text is None:
        return False, "SQLAlchemy not installed; cannot insert non-sqlite URI."
    validate_identifier(schema, "schema")
    table = f"{schema}.missed_signal_events" if schema else "missed_signal_events"
    engine = create_engine(uri_or_dsn)
    try:
        stmt = text(
            (
                f"INSERT INTO {table} "
                f"({','.join(MISSED_SIGNAL_COLUMNS)}) "
                f"VALUES ({','.join(':'+col for col in MISSED_SIGNAL_COLUMNS)})"
            )
        )
        with engine.begin() as conn:
            conn.execute(stmt, row_data)
        return True, "Missed-signal event recorded."
    except Exception as exc:
        if "unique" in str(exc).lower():
            return True, "Duplicate missed-signal event ignored."
        return False, f"SQL insert failed: {exc}"
    finally:
        try:
            engine.dispose()
        except Exception:
            pass
