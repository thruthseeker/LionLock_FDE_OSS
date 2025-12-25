from lionlock.logging.event_log import build_connector_error_event, build_signal_event
from lionlock.logging.sql_telemetry import PUBLIC_SIGNALS_COLUMNS


def test_public_event_excludes_sensitive_keys() -> None:
    event = build_signal_event(
        timestamp_utc="2024-01-01T00:00:00Z",
        request_id="req123",
        base_url="http://localhost:11434",
        model="llama3.1:8b",
        decision="ALLOW",
        severity="green",
        reason_code=None,
        aggregate_score=0.12,
        signal_scores={"repetition_loopiness": 0.1},
        duration_ms=150,
        config_hash="hash",
        notes={"connector_meta": {"http_status": 200}},
    )

    for key in ("prompt", "response", "user_id", "ip", "device_id", "prompt_text", "response_text"):
        assert key not in event


def test_connector_error_event_schema() -> None:
    event = build_connector_error_event(
        timestamp_utc="2024-01-01T00:00:00Z",
        request_id="req124",
        base_url="http://localhost:11434",
        model="llama3.1:8b",
        duration_ms=42,
        config_hash="hash",
    )

    assert event["decision"] == "ERROR"
    assert event["severity"] == "orange"
    assert event["reason_code"] == "connector_error"
    assert event["aggregate_score"] is None
    assert event["signal_scores"] == {}
    for key in ("prompt", "response", "prompt_text", "response_text"):
        assert key not in event


def test_public_sql_schema_has_no_prompt_response_columns() -> None:
    names = {name for name, _ in PUBLIC_SIGNALS_COLUMNS}
    forbidden = {"prompt", "response", "prompt_text", "response_text", "user_id", "ip", "device_id"}
    assert not (names & forbidden)
