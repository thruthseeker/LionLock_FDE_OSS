import ipaddress
import json
import os
import time
from typing import Any, Callable, Dict, List, Tuple
from urllib import error, request
from urllib.parse import urlsplit


class _NoRedirect(request.HTTPRedirectHandler):
    """Refuse redirects, so the Authorization header is never replayed to another host."""

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


def _is_loopback(url: str) -> bool:
    """True for localhost and for any address in a loopback range.

    Plain http is tolerated only here. Anywhere else it would put the API key on the wire.
    """
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _opener(url: str) -> request.OpenerDirector:
    handlers: List[request.BaseHandler] = [_NoRedirect()]
    if _is_loopback(url):
        # A loopback call (and any token on it) must never be relayed via a proxy.
        handlers.append(request.ProxyHandler({}))
    return request.build_opener(*handlers)


def _may_send_credentials(url: str) -> bool:
    """True when an Authorization header may be attached to ``url``."""
    scheme = urlsplit(url).scheme.lower()
    return scheme == "https" or (scheme == "http" and _is_loopback(url))


def _post_json(
    url: str, payload: Dict[str, Any], timeout_s: int, headers: Dict[str, str]
) -> Tuple[int | None, Dict[str, Any] | None, str | None, bool]:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    try:
        with _opener(url).open(req, timeout=timeout_s) as resp:
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


def _first_choice(payload: Dict[str, Any]) -> Dict[str, Any]:
    """The first entry of ``choices``, or an empty mapping.

    A streamed chunk may legitimately carry ``"choices": []`` -- OpenAI's final usage chunk
    and Azure's prompt-filter chunk both do -- so indexing ``[0]`` unguarded raises IndexError.
    """
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return {}
    first = choices[0]
    return first if isinstance(first, dict) else {}


def _extract_openai_content(payload: Dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    first = _first_choice(payload)
    if not first:
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


def _stream_openai(
    url: str,
    payload: Dict[str, Any],
    timeout_s: int,
    headers: Dict[str, str],
    on_chunk: Callable[[str], None] | None,
) -> Tuple[str | None, Dict[str, Any] | None, str | None, int]:
    payload = dict(payload)
    payload["stream"] = True
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    buffer: List[str] = []
    emitted = 0
    try:
        with _opener(url).open(req, timeout=timeout_s) as resp:
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
                delta = _first_choice(parsed).get("delta")
                content = delta.get("content") if isinstance(delta, dict) else None
                if isinstance(content, str):
                    buffer.append(content)
                    if on_chunk:
                        on_chunk(content)
                        emitted += 1
        return "".join(buffer), {"stream": True}, None, emitted
    except Exception as exc:
        return None, None, f"stream_error: {exc}", emitted


def _stream_ollama(
    url: str,
    payload: Dict[str, Any],
    timeout_s: int,
    headers: Dict[str, str],
    on_chunk: Callable[[str], None] | None,
) -> Tuple[str | None, Dict[str, Any] | None, str | None, int]:
    payload = dict(payload)
    payload["stream"] = True
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    buffer: List[str] = []
    emitted = 0
    try:
        with _opener(url).open(req, timeout=timeout_s) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except Exception:
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
                        emitted += 1
                if parsed.get("done"):
                    break
        return "".join(buffer), {"stream": True}, None, emitted
    except Exception as exc:
        return None, None, f"stream_error: {exc}", emitted


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
            if not _may_send_credentials(base):
                return (
                    None,
                    None,
                    {
                        "used_api": None,
                        "endpoint": base,
                        "http_status": None,
                        "error": (
                            "refusing to send the API key in clear text: base_url must use "
                            "https (plain http is allowed only for localhost)"
                        ),
                        "tried": [],
                        "stream_internal": stream_internal,
                        "stream_used": False,
                    },
                )
            headers["Authorization"] = f"Bearer {api_key}"

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    order = [preferred_api, fallback_api]
    tried = []
    last_meta: Dict[str, Any] = {}
    # Chunks already handed to on_chunk. Once the caller has seen text, a second request would
    # bill twice and replay the same text, so the error is reported instead.
    emitted_total = 0

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
            if stream_internal and on_chunk:
                content, raw_json, error_msg, emitted = _stream_openai(
                    url, payload, timeout_s, headers, on_chunk
                )
                emitted_total += emitted
                if content is not None and error_msg is None:
                    stream_used = True
            if content is None and emitted_total == 0:
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
            if stream_internal and on_chunk:
                content, raw_json, error_msg, emitted = _stream_ollama(
                    url, payload, timeout_s, headers, on_chunk
                )
                emitted_total += emitted
                if content is not None and error_msg is None:
                    stream_used = True
            if content is None and emitted_total == 0:
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

        if content is not None:
            if (
                stream_internal
                and on_chunk
                and buffered_chunk_chars > 0
                and not stream_used
                and emitted_total == 0
            ):
                chunk_size = max(1, buffered_chunk_chars)
                for idx in range(0, len(content), chunk_size):
                    on_chunk(content[idx : idx + chunk_size])
                    time.sleep(max(0, buffered_tick_ms) / 1000.0)
            meta["fallback_used"] = api != preferred_api
            return content, raw_json, meta

        if emitted_total:
            # Partial text already reached the caller; do not retry and duplicate it.
            meta["error"] = meta["error"] or "stream_incomplete"
            return None, raw_json, meta

        invalid_shape = raw_json is not None and content is None
        should_fallback = status in (404, 405) or invalid_shape

        if not should_fallback:
            meta["error"] = meta["error"] or "invalid_response"
            return None, raw_json, meta

    last_meta["error"] = last_meta.get("error") or "fallback_failed"
    return None, None, last_meta
