"""Every sanitizer refuses the same raw-text key names."""

from __future__ import annotations

import pytest

from lionlock.logging import event_log, privacy


@pytest.mark.parametrize("key", ["content", "completion", "system_prompt", "tool_calls"])
def test_sql_scrubber_refuses_raw_text_keys(key: str) -> None:
    ok, cleaned, message = privacy.scrub_forbidden_keys({"details": {key: "text"}}, mode="reject")
    assert ok is False and cleaned is None
    assert key in str(message)
    ok, cleaned, _ = privacy.scrub_forbidden_keys({"details": {key: "text"}}, mode="strip")
    assert ok is True and cleaned == {"details": {}}


def test_scrubber_covers_the_event_log_text_keys() -> None:
    text_keys = {
        "assistant_response",
        "completion",
        "content",
        "raw_messages",
        "raw_text",
        "system_prompt",
        "tool_calls",
        "user_prompt",
    }
    assert text_keys <= event_log.FORBIDDEN_KEYS
    assert text_keys <= privacy.FORBIDDEN_PAYLOAD_KEYS


def test_value_scan_does_not_reject_harmless_words() -> None:
    assert "content" not in privacy.FORBIDDEN_VALUE_TOKENS
