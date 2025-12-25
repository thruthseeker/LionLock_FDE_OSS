from lionlock.logging.anomaly_sql import ANOMALY_COLUMNS, DIAGNOSTICS_COLUMNS, _sanitize_details
from lionlock.logging.event_log import sanitize_public_event
from lionlock.logging.sql_telemetry import PUBLIC_SIGNALS_COLUMNS, SESSIONS_COLUMNS


def test_sessions_table_schema_normalized() -> None:
    names = {name for name, _ in SESSIONS_COLUMNS}
    assert "session_pk" in names
    assert "session_id" in names
    assert "model" in names
    assert "base_url" in names
    assert "config_hash" in names
    assert "content_policy" in names


def test_events_table_schema_normalized() -> None:
    names = {name for name, _ in PUBLIC_SIGNALS_COLUMNS}
    forbidden = {"prompt", "response", "prompt_text", "response_text", "user_id", "ip", "device_id"}
    assert "session_pk" in names
    assert "event_pk" in names
    assert "model" not in names
    assert "base_url" not in names
    assert not (names & forbidden)


def test_anomaly_schema_excludes_prompt_response() -> None:
    names = {name for name, _ in ANOMALY_COLUMNS}
    diag_names = {name for name, _ in DIAGNOSTICS_COLUMNS}
    forbidden = {"prompt", "response", "prompt_text", "response_text", "user_id", "ip", "device_id"}
    assert not (names & forbidden)
    assert not (diag_names & forbidden)


def test_anomaly_details_sanitized() -> None:
    assert _sanitize_details("prompt=secret") is None
    assert _sanitize_details("response=secret") is None
    assert _sanitize_details("ip=127.0.0.1") is None
    assert _sanitize_details("safe_detail") == "safe_detail"


def test_public_event_sanitizes_sensitive_fields() -> None:
    event = {
        "timestamp_utc": "2024-01-01T00:00:00Z",
        "request_id": "req123",
        "decision": "ALLOW",
        "severity": "green",
        "reason_code": None,
        "aggregate_score": 0.12,
        "signal_scores": {},
        "config_hash": "hash",
        "duration_ms": 12,
        "prompt": "secret",
        "response": "secret",
        "user_id": "u1",
        "ip": "127.0.0.1",
    }
    sanitized = sanitize_public_event(event, verbosity="normal")
    for key in ("prompt", "response", "user_id", "ip"):
        assert key not in sanitized
