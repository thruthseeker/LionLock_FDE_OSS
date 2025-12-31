import json
import math
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from .connection import validate_identifier
from .token_auth import AUTH_SIGNATURE_FIELD, AUTH_TOKEN_ID_FIELD, prepare_event_for_sql
from .privacy import FORBIDDEN_PAYLOAD_KEYS, scrub_forbidden_keys
from lionlock.core.models import canonical_gating_decision

ANOMALY_COLUMNS: List[Tuple[str, str]] = [
    ("anomaly_pk", "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("session_id", "TEXT"),
    ("session_pk", "INTEGER"),
    ("timestamp_utc", "TEXT"),
    ("turn_index", "INTEGER"),
    ("prompt_type", "TEXT"),
    ("response_hash", "TEXT"),
    ("anomaly_type", "TEXT"),
    ("severity", "REAL"),
    ("weight", "REAL"),
    ("details", "TEXT"),
    ("related_request_id", "TEXT"),
    ("expected_decision", "TEXT"),
    ("actual_decision", "TEXT"),
    ("miss_reason", "TEXT"),
    ("trust_logic_version", "TEXT"),
    ("code_fingerprint", "TEXT"),
    (AUTH_TOKEN_ID_FIELD, "TEXT"),
    (AUTH_SIGNATURE_FIELD, "TEXT"),
]

CANONICAL_ANOMALY_COLUMNS: List[Tuple[str, str]] = [
    ("anomaly_pk", "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("session_id", "TEXT"),
    ("turn_index", "INTEGER"),
    ("timestamp", "TEXT"),
    ("signal_bundle", "TEXT"),
    ("gating_decision", "TEXT"),
    ("decision_risk_score", "REAL"),
    ("trigger_signal", "TEXT"),
    ("trust_logic_version", "TEXT"),
    ("code_fingerprint", "TEXT"),
    ("prompt_type", "TEXT"),
    ("response_hash", "TEXT"),
    ("anomaly_type", "TEXT"),
    ("severity", "REAL"),
    ("details_json", "TEXT"),
    (AUTH_TOKEN_ID_FIELD, "TEXT"),
    (AUTH_SIGNATURE_FIELD, "TEXT"),
]

CANONICAL_COLUMN_NAMES = {
    name
    for name, _ in CANONICAL_ANOMALY_COLUMNS
    if name != "anomaly_pk" and name not in {AUTH_TOKEN_ID_FIELD, AUTH_SIGNATURE_FIELD}
}

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


def _postgres_table_columns(uri: str, table: str, schema: str = "public") -> set[str] | None:
    if create_engine is None or text is None:
        return None
    engine = None
    try:
        engine = create_engine(uri)
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema=:schema AND table_name=:table"
                ),
                {"schema": schema, "table": table},
            ).fetchall()
        return {row[0] for row in rows}
    except Exception:
        return None
    finally:
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                pass


def _serialize_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _contains_forbidden_tokens(value: str) -> bool:
    lowered = value.lower()
    for key in FORBIDDEN_PAYLOAD_KEYS:
        if f"{key}=" in lowered or f"{key}:" in lowered:
            return True
    return False


def _sanitize_details(details: Any) -> str | None:
    if details is None:
        return None
    if isinstance(details, (dict, list)):
        ok, cleaned, _ = scrub_forbidden_keys(details, mode="strip")
        if not ok:
            return None
        return _serialize_json(cleaned)
    if isinstance(details, str):
        stripped = details.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(details)
            except Exception:
                parsed = None
            if isinstance(parsed, (dict, list)):
                ok, cleaned, _ = scrub_forbidden_keys(parsed, mode="strip")
                if not ok:
                    return None
                return _serialize_json(cleaned)
        if _contains_forbidden_tokens(stripped):
            return None
        return details
    return None


def _canonical_details_payload(
    details: Any,
    *,
    related_request_id: str | None,
    weight: float | None,
    expected_decision: str | None,
    actual_decision: str | None,
    miss_reason: str | None,
) -> Any | None:
    canonical_expected = _canonicalize_decision(expected_decision)
    canonical_actual = _canonicalize_decision(actual_decision)
    payload: Any
    if details is None:
        payload = {}
    elif isinstance(details, dict):
        payload = dict(details)
    elif isinstance(details, list):
        payload = {"details": details}
    elif isinstance(details, str):
        stripped = details.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(details)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                payload = dict(parsed)
            elif isinstance(parsed, list):
                payload = {"details": parsed}
            else:
                if _contains_forbidden_tokens(stripped):
                    return None
                payload = {"detail": details}
        else:
            if _contains_forbidden_tokens(stripped):
                return None
            payload = {"detail": details}
    else:
        payload = {}

    if isinstance(payload, dict):
        if related_request_id and "related_request_id" not in payload:
            payload["related_request_id"] = related_request_id
        if weight is not None and "weight" not in payload:
            payload["weight"] = weight
        if canonical_expected and "expected_decision" not in payload:
            payload["expected_decision"] = canonical_expected
        if canonical_actual and "actual_decision" not in payload:
            payload["actual_decision"] = canonical_actual
        if miss_reason and "miss_reason" not in payload:
            payload["miss_reason"] = miss_reason
        for key in ("expected_decision", "actual_decision", "gating_decision"):
            if key in payload:
                payload[key] = _canonicalize_decision(payload.get(key))

    return payload


def _canonical_details_json(
    details: Any,
    *,
    related_request_id: str | None,
    weight: float | None,
    expected_decision: str | None,
    actual_decision: str | None,
    miss_reason: str | None,
) -> str | None:
    payload = _canonical_details_payload(
        details,
        related_request_id=related_request_id,
        weight=weight,
        expected_decision=expected_decision,
        actual_decision=actual_decision,
        miss_reason=miss_reason,
    )
    if payload is None:
        return None
    ok, cleaned, _ = scrub_forbidden_keys(payload, mode="strip")
    if not ok:
        return None
    return _serialize_json(cleaned)


def _extract_canonical_fields(details: Any, anomaly: Dict[str, Any]) -> tuple[str | None, float | None, str | None]:
    gating_decision = anomaly.get("gating_decision")
    decision_risk_score = anomaly.get("decision_risk_score")
    trigger_signal = anomaly.get("trigger_signal")

    source: Dict[str, Any] = {}
    if isinstance(details, dict):
        source = details
    elif isinstance(details, str):
        stripped = details.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(details)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                source = parsed

    if gating_decision is None:
        gating_decision = source.get("gating_decision")
    if decision_risk_score is None:
        decision_risk_score = source.get("decision_risk_score")
    if trigger_signal is None:
        trigger_signal = source.get("trigger_signal")

    if decision_risk_score is not None:
        try:
            decision_risk_score = float(decision_risk_score)
        except Exception:
            decision_risk_score = None
        if decision_risk_score is not None and not math.isfinite(decision_risk_score):
            decision_risk_score = None

    if gating_decision is not None:
        gating_decision = _canonicalize_decision(gating_decision)
    if trigger_signal is not None:
        trigger_signal = str(trigger_signal)

    return gating_decision, decision_risk_score, trigger_signal


def _canonicalize_decision(value: Any) -> str | None:
    if value is None:
        return None
    return canonical_gating_decision(str(value))


def _sanitize_signal_bundle(bundle: Any) -> str | None:
    if not isinstance(bundle, (dict, list)):
        return None
    ok, cleaned, _ = scrub_forbidden_keys(bundle, mode="strip")
    if not ok:
        return None
    return _serialize_json(cleaned)


def _is_unique_constraint_error(exc: Exception) -> bool:
    return "unique" in str(exc).lower()


def init_db(uri: str, anomalies_table: str, diagnostics_table: str) -> Tuple[bool, str]:
    if not uri:
        return False, "Anomaly DB URI is empty."
    validate_identifier(anomalies_table, "anomalies_table")
    validate_identifier(diagnostics_table, "diagnostics_table")
    sqlite_path = _sqlite_path_from_uri(uri)
    anomalies_columns = (
        CANONICAL_ANOMALY_COLUMNS
        if anomalies_table.lower() == "anomalies"
        else ANOMALY_COLUMNS
    )
    try:
        if sqlite_path is not None:
            Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(sqlite_path) as conn:
                conn.execute(_create_table_sql(anomalies_table, anomalies_columns))
                conn.execute(_create_table_sql(diagnostics_table, DIAGNOSTICS_COLUMNS))
                conn.commit()
            return True, "Initialized anomaly sqlite tables."
        if create_engine is None or text is None:
            return False, "SQLAlchemy not installed; cannot init anomaly DB."
        engine = create_engine(uri)
        with engine.begin() as conn:
            conn.execute(text(_create_table_sql(anomalies_table, anomalies_columns)))
            conn.execute(text(_create_table_sql(diagnostics_table, DIAGNOSTICS_COLUMNS)))
        return True, "Initialized anomaly SQL tables."
    except Exception as exc:
        return False, f"Anomaly SQL init failed: {exc}"


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

    try:
        validate_identifier(anomalies_table, "anomalies_table")
        validate_identifier(diagnostics_table, "diagnostics_table")
    except ValueError as exc:
        return False, f"Anomaly SQL init failed: {exc}"

    try:
        ok, message = init_db(uri, anomalies_table, diagnostics_table)
    except ValueError as exc:
        return False, f"Anomaly SQL init failed: {exc}"
    if not ok:
        return False, message

    sqlite_path = _sqlite_path_from_uri(uri)
    canonical_table = anomalies_table.lower() == "anomalies"
    use_canonical = canonical_table

    if sqlite_path is not None and canonical_table and _sqlite_table_exists(sqlite_path, anomalies_table):
        existing_cols = set(_sqlite_table_columns(sqlite_path, anomalies_table))
        use_canonical = CANONICAL_COLUMN_NAMES.issubset(existing_cols)
    elif sqlite_path is None and canonical_table:
        columns = _postgres_table_columns(uri, anomalies_table)
        if columns is not None and not CANONICAL_COLUMN_NAMES.issubset(columns):
            use_canonical = False

    supported_columns = CANONICAL_ANOMALY_COLUMNS if use_canonical else ANOMALY_COLUMNS
    insert_columns = [name for name, _ in supported_columns if name != "anomaly_pk"]

    if sqlite_path is not None:
        if not _sqlite_table_exists(sqlite_path, anomalies_table):
            return False, "Anomaly table missing."
        existing = set(_sqlite_table_columns(sqlite_path, anomalies_table))
        insert_columns = [name for name in insert_columns if name in existing]

    if not insert_columns:
        return False, "No writable anomaly columns available."

    rows = []
    for anomaly in anomalies:
        ok, message, prepared = prepare_event_for_sql(
            anomaly, token_config=config.get("token_auth")
        )
        if not ok:
            return False, f"Anomaly auth failed: {message}"
        details = anomaly.get("details")
        parsed_details = details
        if isinstance(details, str):
            stripped = details.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    parsed_details = json.loads(details)
                except Exception:
                    parsed_details = details
        expected = None
        actual = None
        miss_reason = None
        if isinstance(parsed_details, dict):
            expected = parsed_details.get("expected_decision")
            actual = parsed_details.get("actual_decision")
            miss_reason = parsed_details.get("miss_reason")
        expected = _canonicalize_decision(expected)
        actual = _canonicalize_decision(actual)

        severity = anomaly.get("severity")
        if severity is None:
            severity = anomaly.get("weight")
        weight = anomaly.get("weight")
        if weight is None:
            weight = severity

        expected_override = _canonicalize_decision(anomaly.get("expected_decision")) or expected
        actual_override = _canonicalize_decision(anomaly.get("actual_decision")) or actual

        if use_canonical:
            gating_decision, decision_risk_score, trigger_signal = _extract_canonical_fields(
                parsed_details, anomaly
            )
            row_data = {
                "session_id": session_id,
                "turn_index": anomaly.get("turn_index"),
                "timestamp": anomaly.get("timestamp") or timestamp_utc,
                "signal_bundle": _sanitize_signal_bundle(anomaly.get("signal_bundle")),
                "gating_decision": gating_decision,
                "decision_risk_score": decision_risk_score,
                "trigger_signal": trigger_signal,
                "trust_logic_version": anomaly.get("trust_logic_version"),
                "code_fingerprint": anomaly.get("code_fingerprint"),
                "prompt_type": anomaly.get("prompt_type"),
                "response_hash": anomaly.get("response_hash"),
                "anomaly_type": anomaly.get("anomaly_type"),
                "severity": severity,
                "details_json": _canonical_details_json(
                    details,
                    related_request_id=anomaly.get("related_request_id"),
                    weight=weight,
                    expected_decision=expected_override,
                    actual_decision=actual_override,
                    miss_reason=anomaly.get("miss_reason") or miss_reason,
                ),
                AUTH_TOKEN_ID_FIELD: prepared.get(AUTH_TOKEN_ID_FIELD),
                AUTH_SIGNATURE_FIELD: prepared.get(AUTH_SIGNATURE_FIELD),
            }
        else:
            row_data = {
                "session_id": session_id,
                "session_pk": session_pk,
                "timestamp_utc": anomaly.get("timestamp") or timestamp_utc,
                "turn_index": anomaly.get("turn_index"),
                "prompt_type": anomaly.get("prompt_type"),
                "response_hash": anomaly.get("response_hash"),
                "anomaly_type": anomaly.get("anomaly_type"),
                "severity": severity,
                "weight": weight,
                "details": _sanitize_details(details),
                "related_request_id": anomaly.get("related_request_id"),
                "expected_decision": expected_override,
                "actual_decision": actual_override,
                "miss_reason": anomaly.get("miss_reason") or miss_reason,
                "trust_logic_version": anomaly.get("trust_logic_version"),
                "code_fingerprint": anomaly.get("code_fingerprint"),
                AUTH_TOKEN_ID_FIELD: prepared.get(AUTH_TOKEN_ID_FIELD),
                AUTH_SIGNATURE_FIELD: prepared.get(AUTH_SIGNATURE_FIELD),
            }

        rows.append(tuple(row_data.get(name) for name in insert_columns))

    try:
        if sqlite_path is not None:
            duplicate = False
            with sqlite3.connect(sqlite_path) as conn:
                insert_cols = ",".join(insert_columns)
                placeholders = ",".join("?" for _ in insert_columns)
                try:
                    conn.executemany(
                        (
                            f"INSERT INTO {anomalies_table} "
                            f"({insert_cols}) "
                            f"VALUES ({placeholders})"
                        ),
                        rows,
                    )
                except sqlite3.IntegrityError as exc:
                    if _is_unique_constraint_error(exc):
                        # Treat UNIQUE violations as duplicate records (non-fatal).
                        duplicate = True
                        conn.rollback()
                    else:
                        raise
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
            if duplicate:
                return True, "Duplicate anomalies ignored."
            return True, "Anomaly records written."
        if create_engine is None or text is None:
            return False, "SQLAlchemy not installed; cannot write anomaly DB."
        engine = create_engine(uri)
        with engine.begin() as conn:
            conn.execute(
                text(
                    (
                        f"INSERT INTO {anomalies_table} "
                        f"({','.join(insert_columns)}) "
                        f"VALUES ({','.join(':'+name for name in insert_columns)})"
                    )
                ),
                [{name: row[idx] for idx, name in enumerate(insert_columns)} for row in rows],
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
