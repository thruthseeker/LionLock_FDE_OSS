from lionlock.logging.privacy import contains_forbidden_keys, scrub_forbidden_keys


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
