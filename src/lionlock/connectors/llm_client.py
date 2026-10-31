import json
import os
import time
from typing import Any, Callable, Dict, Tuple
from urllib import error, request
from urllib.parse import urlsplit

from lionlock.telemetry.upload import LOOPBACK_HOSTS


class _NoRedirect(request.HTTPRedirectHandler):
    """Never follow redirects: urllib would re-send the Authorization header to the new host."""

    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _open(req: request.Request, timeout_s: int) -> Any:
    handlers: list[request.BaseHandler] = [_NoRedirect()]
    if (urlsplit(req.full_url).hostname or "").lower() in LOOPBACK_HOSTS:
        # Loopback traffic is plain http; never relay it (or its key) through a proxy.
        handlers.append(request.ProxyHandler({}))
    return request.build_opener(*handlers).open(req, timeout=timeout_s)


def _endpoint_problem(base_url: str, sends_key: bool) -> str | None:
    """Why ``base_url`` must not be called, or ``None`` when it is acceptable."""
    try:
        parts = urlsplit(base_url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return "invalid_base_url"
    if parts.scheme not in {"http", "https"}:
        return "unsupported_scheme"
    if not host:
        return "invalid_base_url"
    if sends_key and parts.scheme == "http" and host not in LOOPBACK_HOSTS:
        return "insecure_endpoint_for_api_key"
    return None


def _post_json(
    url: str, payload: Dict[str, Any], timeout_s: int, headers: Dict[str, str]
) -> Tuple[int | None, Dict[str, Any] | None, str | None, bool]:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    try:
        with _open(req, timeout_s) as resp:
            body = resp.read()
            status = resp.getcode()
    except error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return exc.code, _safe_json(body), "http_error", True
    except error.URLError as exc:
        return None, None, f"connection_error: {exc}", False
    except Exception as exc:  # pragma: no cover - unexpected
        return None, None, f"unexpected_error: {exc}", False
    return status, _safe_json(body), None, False


def _safe_json(body: bytes) -> Dict[str, Any] | None:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def _extract_openai_content(payload: Dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    choices = payload.get("choices")
    if not choices or not isinstance(choices, list):
        return None
    first = choices[0] if choices else None
    if not isinstance(first, dict):
        return None
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    text = first.get("text")
    return text if isinstance(text, str) else None


def _extract_ollama_content(payload: Dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    message = payload.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]
    if isinstance(payload.get("response"), str):
        return payload["response"]
    return _extract_openai_content(payload)


def _openai_delta_content(parsed: Any) -> str | None:
    if not isinstance(parsed, dict):
        return None
    choices = parsed.get("choices")
    # Usage and content-filter chunks carry an empty ``choices`` list.
    if not choices or not isinstance(choices, list) or not isinstance(choices[0], dict):
        return None
    delta = choices[0].get("delta")
    content = delta.get("content") if isinstance(delta, dict) else None
    return content if isinstance(content, str) else None


def _stream_openai(
    url: str,
    payload: Dict[str, Any],
    timeout_s: int,
    headers: Dict[str, str],
    on_chunk: Callable[[str], None] | None,
) -> Tuple[str | None, Dict[str, Any] | None, str | None, int]:
    """Stream a reply. The last value counts chunks already passed to ``on_chunk``."""
    payload = dict(payload)
    payload["stream"] = True
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    buffer: list[str] = []
    try:
        with _open(req, timeout_s) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line or not line.startswith("data:"):
                    continue
                item = line[len("data:") :].strip()
                if item == "[DONE]":
                    break
                try:
                    parsed = json.loads(item)
                except Exception:
                    continue
                content = _openai_delta_content(parsed)
                if content is not None:
                    buffer.append(content)
                    if on_chunk:
                        on_chunk(content)
        return "".join(buffer), {"stream": True}, None, len(buffer)
    except Exception as exc:
        return None, None, f"stream_error: {exc}", len(buffer)


def _stream_ollama(
    url: str,
    payload: Dict[str, Any],
    timeout_s: int,
    headers: Dict[str, str],
    on_chunk: Callable[[str], None] | None,
) -> Tuple[str | None, Dict[str, Any] | None, str | None, int]:
    """Stream a reply. The last value counts chunks already passed to ``on_chunk``."""
    payload = dict(payload)
    payload["stream"] = True
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    buffer: list[str] = []
    try:
        with _open(req, timeout_s) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except Exception:
                    continue
                if not isinstance(parsed, dict):
                    continue
                content = None
                message = parsed.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                if content is None:
                    content = parsed.get("response")
                if isinstance(content, str):
                    buffer.append(content)
                    if on_chunk:
                        on_chunk(content)
                if isinstance(parsed, dict) and parsed.get("done"):
                    break
        return "".join(buffer), {"stream": True}, None, len(buffer)
    except Exception as exc:
        return None, None, f"stream_error: {exc}", len(buffer)


def call_llm(
    prompt: str,
    base_url: str,
    model: str,
    system_prompt: str | None = None,
    temperature: float = 0.2,
    timeout_s: int = 60,
    preferred_api: str = "openai_compat",
    fallback_api: str = "ollama_native",
    api_key_env: str = "",
    stream_internal: bool = False,
    on_chunk: Callable[[str], None] | None = None,
    buffered_chunk_chars: int = 80,
    buffered_tick_ms: int = 50,
) -> Tuple[str | None, Dict[str, Any] | None, Dict[str, Any]]:
    base = base_url.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if api_key_env:
        api_key = os.getenv(api_key_env, "")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
    problem = _endpoint_problem(base, "Authorization" in headers)
    if problem:
        return None, None, {"used_api": None, "endpoint": base, "error": problem, "tried": []}

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    order = [preferred_api, fallback_api]
    tried = []
    last_meta: Dict[str, Any] = {}

    for api in order:
        tried.append(api)
        stream_used = False
        if api == "openai_compat":
            url = f"{base}/v1/chat/completions"
            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "stream": False,
            }
            content = None
            raw_json = None
            error_msg = None
            status = None
            is_http_error = False
            stream_interrupted = False
            if stream_internal and on_chunk:
                content, raw_json, error_msg, emitted = _stream_openai(
                    url, payload, timeout_s, headers, on_chunk
                )
                if content is not None and error_msg is None:
                    stream_used = True
                elif emitted:
                    # Part of the reply already reached on_chunk. A second request would be
                    # billed again and replay the whole reply after the partial one.
                    stream_interrupted = True
            if content is None and not stream_interrupted:
                status, raw_json, error_msg, is_http_error = _post_json(
                    url, payload, timeout_s, headers
                )
                content = _extract_openai_content(raw_json)
        else:
            url = f"{base}/api/chat"
            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
            }
            content = None
            raw_json = None
            error_msg = None
            status = None
            is_http_error = False
            stream_interrupted = False
            if stream_internal and on_chunk:
                content, raw_json, error_msg, emitted = _stream_ollama(
                    url, payload, timeout_s, headers, on_chunk
                )
                if content is not None and error_msg is None:
                    stream_used = True
                elif emitted:
                    # Part of the reply already reached on_chunk. A second request would be
                    # billed again and replay the whole reply after the partial one.
                    stream_interrupted = True
            if content is None and not stream_interrupted:
                status, raw_json, error_msg, is_http_error = _post_json(
                    url, payload, timeout_s, headers
                )
                content = _extract_ollama_content(raw_json)

        meta = {
            "used_api": api,
            "endpoint": url,
            "http_status": status,
            "error": error_msg,
            "tried": tried[:],
            "stream_internal": stream_internal,
            "stream_used": stream_used,
        }
        last_meta = meta

        if stream_interrupted:
            meta["error"] = f"stream_interrupted: {error_msg}"
            return None, None, meta

        if content is not None:
            if stream_internal and on_chunk and buffered_chunk_chars > 0 and not stream_used:
                chunk_size = max(1, buffered_chunk_chars)
                for idx in range(0, len(content), chunk_size):
                    on_chunk(content[idx : idx + chunk_size])
                    time.sleep(max(0, buffered_tick_ms) / 1000.0)
            meta["fallback_used"] = api != preferred_api
            return content, raw_json, meta

        invalid_shape = raw_json is not None and content is None
        should_fallback = status in (404, 405) or invalid_shape

        if not should_fallback:
            meta["error"] = meta["error"] or "invalid_response"
            return None, raw_json, meta

    last_meta["error"] = last_meta.get("error") or "fallback_failed"
    return None, None, last_meta
