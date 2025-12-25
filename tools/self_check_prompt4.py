#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from lionlock.logging import anomaly_sql, event_log, sql_telemetry  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    sessions = {name for name, _ in sql_telemetry.SESSIONS_COLUMNS}
    events = {name for name, _ in sql_telemetry.PUBLIC_SIGNALS_COLUMNS}
    forbidden = {"prompt", "response", "prompt_text", "response_text", "user_id", "ip", "device_id"}

    _assert("session_pk" in sessions, "sessions table missing session_pk")
    _assert("session_id" in sessions, "sessions table missing session_id")
    _assert("model" in sessions, "sessions table missing model")
    _assert("base_url" in sessions, "sessions table missing base_url")
    _assert("session_pk" in events, "events table missing session_pk")
    _assert("event_pk" in events, "events table missing event_pk")
    _assert("model" not in events, "events table should not include model")
    _assert("base_url" not in events, "events table should not include base_url")
    _assert(not (events & forbidden), "events table includes forbidden columns")

    anomaly_cols = {name for name, _ in anomaly_sql.ANOMALY_COLUMNS}
    diag_cols = {name for name, _ in anomaly_sql.DIAGNOSTICS_COLUMNS}
    _assert(not (anomaly_cols & forbidden), "anomaly table includes forbidden columns")
    _assert(not (diag_cols & forbidden), "diagnostics table includes forbidden columns")

    _assert(anomaly_sql._sanitize_details("prompt=secret") is None, "sanitize_details keeps prompt")
    _assert(
        anomaly_sql._sanitize_details("response=secret") is None,
        "sanitize_details keeps response",
    )

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
    sanitized = event_log.sanitize_public_event(event, verbosity="normal")
    _assert("prompt" not in sanitized, "public event includes prompt")
    _assert("response" not in sanitized, "public event includes response")
    _assert("user_id" not in sanitized, "public event includes user_id")
    _assert("ip" not in sanitized, "public event includes ip")

    print("self_check_prompt4: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
