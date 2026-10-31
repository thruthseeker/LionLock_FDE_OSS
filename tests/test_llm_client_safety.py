"""The LLM connector must not leak its API key or bill a reply twice."""

from __future__ import annotations

import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator

import pytest

from lionlock.connectors import llm_client
from lionlock.connectors.llm_client import call_llm

KEY_ENV = "LIONLOCK_TEST_LLM_KEY"


def _serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("localhost", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def receiver() -> Iterator[tuple[ThreadingHTTPServer, list[dict[str, Any]]]]:
    seen: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self._record()

        def do_GET(self) -> None:  # noqa: N802
            # urllib turns a redirected POST (301/302/303) into a GET that keeps Authorization.
            self._record()

        def _record(self) -> None:
            seen.append({"path": self.path, "authorization": self.headers.get("Authorization")})
            body = json.dumps({"choices": [{"message": {"content": "leaked"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    yield from ((server, seen) for server in _serve(Handler))


def test_redirect_is_not_followed_and_key_is_not_resent(
    receiver: tuple[ThreadingHTTPServer, list[dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, seen = receiver
    target_url = f"http://localhost:{target.server_address[1]}"

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", target_url + self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    monkeypatch.setenv(KEY_ENV, "sk-secret")
    for redirector in _serve(Redirector):
        text, _, meta = call_llm(
            "hi",
            base_url=f"http://localhost:{redirector.server_address[1]}",
            model="m",
            api_key_env=KEY_ENV,
        )
    assert seen == []
    assert text is None
    assert meta["http_status"] == 302


@pytest.mark.parametrize(
    ("base_url", "problem"),
    [
        ("http://llm.example.com:11434", "insecure_endpoint_for_api_key"),
        ("file:///etc/passwd", "unsupported_scheme"),
        ("ftp://llm.example.com", "unsupported_scheme"),
        ("https://", "invalid_base_url"),
    ],
)
def test_unsafe_endpoints_are_refused_before_any_request(
    base_url: str, problem: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, "sk-secret")

    def no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("no request may be made")

    monkeypatch.setattr(llm_client, "_open", no_network)
    text, raw, meta = call_llm("hi", base_url=base_url, model="m", api_key_env=KEY_ENV)
    assert (text, raw) == (None, None)
    assert meta["error"] == problem


def test_plain_http_without_a_key_is_still_allowed_on_a_lan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert llm_client._endpoint_problem("http://llm.lan:11434", sends_key=False) is None
    assert llm_client._endpoint_problem("http://localhost:11434", sends_key=True) is None


class _Response(io.BytesIO):
    def __init__(self, lines: list[bytes], fail_after: int | None = None) -> None:
        super().__init__(b"")
        self._lines = lines
        self._fail_after = fail_after

    def __iter__(self) -> Iterator[bytes]:  # type: ignore[override]
        for index, line in enumerate(self._lines):
            if self._fail_after is not None and index == self._fail_after:
                raise ConnectionResetError("peer closed the stream")
            yield line

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


def _sse(payload: dict[str, Any]) -> bytes:
    return b"data: " + json.dumps(payload).encode() + b"\n"


def test_empty_choices_chunk_does_not_trigger_a_second_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lines = [
        _sse({"choices": [{"delta": {"content": "Hello "}}]}),
        _sse({"choices": [{"delta": {"content": "world"}}]}),
        _sse({"choices": [], "usage": {"total_tokens": 5}}),
        b"data: [DONE]\n",
    ]
    calls: list[str] = []

    def fake_open(req: Any, timeout_s: int) -> _Response:
        calls.append(req.full_url)
        return _Response(lines)

    monkeypatch.setattr(llm_client, "_open", fake_open)
    chunks: list[str] = []
    text, _, meta = call_llm(
        "hi",
        base_url="http://localhost:11434",
        model="m",
        stream_internal=True,
        on_chunk=chunks.append,
    )
    assert text == "Hello world"
    assert chunks == ["Hello ", "world"]
    assert len(calls) == 1
    assert meta["stream_used"] is True


def test_interrupted_stream_is_not_replayed_or_billed_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lines = [
        _sse({"choices": [{"delta": {"content": "Partial "}}]}),
        _sse({"choices": [{"delta": {"content": "never sent"}}]}),
    ]
    calls: list[str] = []

    def fake_open(req: Any, timeout_s: int) -> _Response:
        calls.append(req.full_url)
        return _Response(lines, fail_after=1)

    monkeypatch.setattr(llm_client, "_open", fake_open)
    chunks: list[str] = []
    text, _, meta = call_llm(
        "hi",
        base_url="http://localhost:11434",
        model="m",
        stream_internal=True,
        on_chunk=chunks.append,
    )
    assert text is None
    assert chunks == ["Partial "]
    assert len(calls) == 1
    assert meta["error"].startswith("stream_interrupted")
