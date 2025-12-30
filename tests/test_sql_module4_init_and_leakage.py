import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from lionlock.logging.anomaly_sql import record_anomalies
from lionlock.logging.connection import build_postgres_dsn, redact_dsn
from lionlock.logging.sql_init import init_schema

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

TABLES = (
    "events",
    "sessions",
    "anomalies",
    "missed_signal_events",
    "trust_overlay",
)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row[1] for row in rows]


def _set_base_env(monkeypatch) -> None:
    monkeypatch.setenv("LIONLOCK_DB_HOST", "db.example.com")
    monkeypatch.setenv("LIONLOCK_DB_PORT", "25060")
    monkeypatch.setenv("LIONLOCK_ADMIN_PASSWORD", "secret-pass")


def _query_params(dsn: str) -> dict[str, str]:
    parts = urlsplit(dsn)
    return dict(parse_qsl(parts.query))


def test_module4_sqlite_schema_init(tmp_path: Path) -> None:
    db_path = tmp_path / "module4.db"
    uri = f"sqlite:///{db_path}"
    ok, message = init_schema(uri)
    assert ok, message

    with sqlite3.connect(db_path) as conn:
        for table in TABLES:
            assert _table_exists(conn, table) is True
        for table in TABLES:
            cols = _table_columns(conn, table)
            for field in MANDATORY_FIELDS:
                assert field in cols
            forbidden = {col.lower() for col in cols} & FORBIDDEN_COLUMNS
            assert forbidden == set()


def test_dsn_sslmode_require_without_cert(monkeypatch) -> None:
    _set_base_env(monkeypatch)
    monkeypatch.delenv("LIONLOCK_SSLROOTCERT", raising=False)
    dsn = build_postgres_dsn("admin")
    params = _query_params(dsn)
    assert params["sslmode"] == "require"


def test_dsn_sslmode_verify_ca_with_cert(monkeypatch, tmp_path: Path) -> None:
    _set_base_env(monkeypatch)
    cert_path = tmp_path / "ca.crt"
    cert_path.write_text("test-cert", encoding="utf-8")
    monkeypatch.setenv("LIONLOCK_SSLROOTCERT", str(cert_path))
    dsn = build_postgres_dsn("admin")
    params = _query_params(dsn)
    assert params["sslmode"] == "verify-ca"
    assert params["sslrootcert"] == str(cert_path)


def test_redact_dsn_removes_password(monkeypatch) -> None:
    _set_base_env(monkeypatch)
    dsn = build_postgres_dsn("admin")
    redacted = redact_dsn(dsn)
    assert "secret-pass" not in redacted
    assert "REDACTED" in redacted


def test_sqlite_unique_indexes_enforced(tmp_path: Path) -> None:
    db_path = tmp_path / "module4_unique.db"
    uri = f"sqlite:///{db_path}"
    ok, message = init_schema(uri)
    assert ok, message

    with sqlite3.connect(db_path) as conn:
        indexes = conn.execute("PRAGMA index_list(events)").fetchall()
        assert any(row[1] == "events_session_turn_response_event_type_unique" and row[2] for row in indexes)
        insert_event = (
            "INSERT INTO events (session_id, turn_index, response_hash, event_type) VALUES (?,?,?,?)"
        )
        conn.execute(insert_event, ("s1", 1, "hash1", "signal"))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(insert_event, ("s1", 1, "hash1", "signal"))

        indexes = conn.execute("PRAGMA index_list(anomalies)").fetchall()
        assert any(row[1] == "anomalies_session_turn_response_type_unique" and row[2] for row in indexes)
        insert_anomaly = (
            "INSERT INTO anomalies (session_id, turn_index, response_hash, anomaly_type) VALUES (?,?,?,?)"
        )
        conn.execute(insert_anomaly, ("s2", 2, "hash2", "missed_signal_event"))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(insert_anomaly, ("s2", 2, "hash2", "missed_signal_event"))


def test_anomaly_duplicates_nonfatal_sqlite(tmp_path: Path) -> None:
    db_path = tmp_path / "module4_dupe.db"
    uri = f"sqlite:///{db_path}"
    ok, message = init_schema(uri)
    assert ok, message

    anomaly_cfg = {
        "enabled": True,
        "db_uri": uri,
        "table": "anomalies",
        "diagnostics_table": "lionlock_session_diagnostics",
    }
    anomaly = {
        "anomaly_type": "missed_signal_event",
        "severity": 0.5,
        "details": {"gating_decision": "ALLOW", "decision_risk_score": 0.2},
        "session_id": "session-1",
        "turn_index": 1,
        "timestamp": "2025-01-01T00:00:00Z",
        "trust_logic_version": "v1",
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": "hash1",
    }

    ok, message = record_anomalies(
        anomaly_cfg,
        session_id="session-1",
        session_pk=None,
        timestamp_utc="2025-01-01T00:00:00Z",
        anomalies=[anomaly],
        anomaly_count=1,
        severity_score=0.5,
        severity_tag="test",
        first_seen_utc="2025-01-01T00:00:00Z",
        last_seen_utc="2025-01-01T00:00:00Z",
    )
    assert ok, message

    ok, message = record_anomalies(
        anomaly_cfg,
        session_id="session-1",
        session_pk=None,
        timestamp_utc="2025-01-01T00:00:00Z",
        anomalies=[anomaly],
        anomaly_count=1,
        severity_score=0.5,
        severity_tag="test",
        first_seen_utc="2025-01-01T00:00:00Z",
        last_seen_utc="2025-01-01T00:00:00Z",
    )
    assert ok, message

    with sqlite3.connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()
    assert count is not None and count[0] == 1
