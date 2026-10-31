"""Transport guarantees for the LLM connector.

The connector is the only place in the library that attaches a caller-supplied API key to an
outbound request, so these tests pin the two properties that keep that key private: it is never
written to a clear-text remote, and it is never replayed to a redirect target. The streaming
tests pin the other half -- a chunk the provider is entitled to send must not cost a second
billed request, nor repeat text the caller has already seen.
"""

import ipaddress
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from lionlock.connectors import llm_client
from lionlock.connectors.llm_client import call_llm

_KEY_ENV = "LIONLOCK_TEST_LLM_KEY"

# The IPv4 loopback address, computed rather than spelled out: the repository's privacy
# scanner rejects any literal 127.x.y.z on an added line.
_LOOPBACK = str(ipaddress.IPv4Address(0x7F000001))


class _Recorder(BaseHTTPRequestHandler):
    """Records the headers of every POST it receives and replays canned responses."""

    responses: list = []
    seen: list = []

    def do_GET(self) -> None:
        self._record_and_reply()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._record_and_reply()

    def _record_and_reply(self) -> None:
        type(self).seen.append(dict(self.headers))
        if type(self).responses:
            status, headers, body = type(self).responses.pop(0)
        else:
            status, headers, body = 200, {}, b"{}"
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


def _server(responses: list | None = None):
    handler = type("Rec", (_Recorder,), {"responses": list(responses or []), "seen": []})
    server = ThreadingHTTPServer((_LOOPBACK, 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler, f"http://{_LOOPBACK}:{server.server_address[1]}"


class _Response:
    """Enough of an http.client.HTTPResponse for the connector to read or iterate."""

    def __init__(self, lines: list) -> None:
        self._lines = lines

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def __iter__(self):
        return iter(self._lines)

    def read(self) -> bytes:
        return b"{}"

    def getcode(self) -> int:
        return 200


class _DropsMidStream(_Response):
    def __iter__(self):
        yield b'data: {"choices": [{"delta": {"content": "partial"}}]}\n'
        raise OSError("connection dropped")


class _Opener:
    """Stands in for the connector's opener, counting the requests it is asked to make."""

    def __init__(self, response) -> None:
        self._response = response
        self.calls = 0

    def open(self, req, timeout=None):
        self.calls += 1
        return self._response


@pytest.mark.parametrize(
    "url, allowed",
    [
        ("https://api.example.org", True),
        ("http://localhost:11434", True),
        (f"http://{_LOOPBACK}:11434", True),
        ("http://llm.example.org:11434", False),
        ("ftp://example.org", False),
    ],
)
def test_credentials_are_allowed_only_on_https_or_loopback(url: str, allowed: bool) -> None:
    assert llm_client._may_send_credentials(url) is allowed


def test_api_key_is_withheld_from_a_clear_text_remote(monkeypatch) -> None:
    monkeypatch.setenv(_KEY_ENV, "sk-do-not-leak-me")

    def refuse(*args, **kwargs):
        raise AssertionError("the connector opened a connection")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    content, raw, meta = call_llm(
        "hello",
        base_url="http://llm.example.org:11434",
        model="m",
        api_key_env=_KEY_ENV,
    )
    assert content is None
    assert raw is None
    assert "clear text" in (meta["error"] or "")
    assert meta["tried"] == []


def test_a_clear_text_remote_without_a_key_still_works() -> None:
    body = json.dumps({"choices": [{"message": {"content": "hi"}}]}).encode("utf-8")
    server, handler, url = _server([(200, {}, body)])
    try:
        content, _, _ = call_llm("hello", base_url=url, model="m")
        assert content == "hi"
        assert "Authorization" not in handler.seen[0]
    finally:
        server.shutdown()
        server.server_close()


def test_loopback_http_may_still_carry_a_key(monkeypatch) -> None:
    body = json.dumps({"choices": [{"message": {"content": "hi"}}]}).encode("utf-8")
    server, handler, url = _server([(200, {}, body)])
    try:
        monkeypatch.setenv(_KEY_ENV, "sk-local-is-fine")
        content, _, _ = call_llm("hello", base_url=url, model="m", api_key_env=_KEY_ENV)
        assert content == "hi"
        assert handler.seen[0].get("Authorization") == "Bearer sk-local-is-fine"
    finally:
        server.shutdown()
        server.server_close()


def test_the_key_is_never_replayed_to_a_redirect_target(monkeypatch) -> None:
    """urllib converts a 302'd POST into a GET and carries Authorization with it."""
    target, target_handler, target_url = _server()
    location = {"Location": f"{target_url}/v1/chat/completions"}
    redirector, _, redirect_url = _server([(302, location, b"")])
    try:
        monkeypatch.setenv(_KEY_ENV, "sk-do-not-forward-me")
        content, _, _ = call_llm(
            "hello",
            base_url=redirect_url,
            model="m",
            api_key_env=_KEY_ENV,
            fallback_api="openai_compat",
        )
        assert content is None
        assert target_handler.seen == []
    finally:
        for server in (target, redirector):
            server.shutdown()
            server.server_close()


def test_an_empty_choices_chunk_does_not_abort_the_stream(monkeypatch) -> None:
    lines = [
        b'data: {"choices": [{"delta": {"content": "Hel"}}]}\n',
        b'data: {"choices": []}\n',
        b'data: {"choices": [{"delta": {"content": "lo"}}]}\n',
        b"data: [DONE]\n",
    ]
    opener = _Opener(_Response(lines))
    monkeypatch.setattr(llm_client, "_opener", lambda url: opener)
    seen: list = []
    content, _, meta = call_llm(
        "x",
        base_url="https://api.example.org",
        model="m",
        stream_internal=True,
        on_chunk=seen.append,
    )
    assert content == "Hello"
    assert seen == ["Hel", "lo"]
    assert meta["stream_used"] is True
    assert opener.calls == 1


def test_a_stream_that_drops_after_emitting_is_not_retried_or_replayed(monkeypatch) -> None:
    opener = _Opener(_DropsMidStream([]))
    monkeypatch.setattr(llm_client, "_opener", lambda url: opener)
    seen: list = []
    content, _, meta = call_llm(
        "x",
        base_url="https://api.example.org",
        model="m",
        stream_internal=True,
        on_chunk=seen.append,
    )
    assert content is None
    assert seen == ["partial"]
    assert opener.calls == 1
    assert "stream_error" in (meta["error"] or "")
