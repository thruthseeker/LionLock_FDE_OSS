import pytest

from lionlock.logging import event_log, privacy
from lionlock.logging.privacy import (
    contains_forbidden_content,
    contains_forbidden_keys,
    find_forbidden_content,
    scrub_forbidden_keys,
)


def test_scrub_rejects_forbidden_keys() -> None:
    payload = {"safe": {"nested": {"prompt": "secret"}}, "ok": 1}
    ok, cleaned, message = scrub_forbidden_keys(payload, mode="reject")
    assert ok is False
    assert cleaned is None
    assert message and "prompt" in message


def test_scrub_strips_forbidden_keys() -> None:
    payload = {
        "session": "s1",
        "details": {"ip": "127.0.0.1", "allowed": {"response_text": "x", "keep": 1}},
    }
    ok, cleaned, _ = scrub_forbidden_keys(payload, mode="strip")
    assert ok is True
    assert cleaned == {"session": "s1", "details": {"allowed": {"keep": 1}}}
    assert contains_forbidden_keys(cleaned) is False


def test_value_scan_flags_prompt_markers() -> None:
    payload = {"notes": "prompt: do the thing"}
    assert contains_forbidden_content(payload) is True
    assert find_forbidden_content(payload) == "notes"


def test_value_scan_flags_large_free_text() -> None:
    payload = {"notes": "word " * 200}
    assert contains_forbidden_content(payload) is True


def test_value_scan_allows_non_marker_strings() -> None:
    payload = {"status": "prompt_injection_suspected"}
    assert contains_forbidden_content(payload) is False


def test_the_two_forbidden_key_lists_cannot_drift_apart() -> None:
    """They were separate literals and had drifted by ten keys."""
    assert event_log.FORBIDDEN_KEYS is privacy.FORBIDDEN_PAYLOAD_KEYS


@pytest.mark.parametrize(
    "key",
    ["assistant_response", "completion", "content", "input", "output", "tool_calls"],
)
def test_keys_only_the_event_log_knew_are_now_scrubbed_everywhere(key: str) -> None:
    """These reach the anomaly SQL path, which scrubs with FORBIDDEN_PAYLOAD_KEYS."""
    assert contains_forbidden_keys({key: "secret"}) is True

    ok, cleaned, message = scrub_forbidden_keys({key: "secret"}, mode="reject")
    assert ok is False
    assert message and key in message

    ok, cleaned, _ = scrub_forbidden_keys({key: "secret", "keep": 1}, mode="strip")
    assert ok is True
    assert cleaned == {"keep": 1}
