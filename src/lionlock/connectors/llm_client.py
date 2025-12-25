import json
import os
import time
from typing import Any, Callable, Dict, Tuple
from urllib import error, request


def _post_json(
    url: str, payload: Dict[str, Any], timeout_s: int, headers: Dict[str, str]
) -> Tuple[int | None, Dict[str, Any] | None, str | None, bool]:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout_s) as resp:
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


def _stream_openai(
    url: str,
    payload: Dict[str, Any],
    timeout_s: int,
    headers: Dict[str, str],
    on_chunk: Callable[[str], None] | None,
) -> Tuple[str | None, Dict[str, Any] | None, str | None]:
    payload = dict(payload)
    payload["stream"] = True
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    buffer: list[str] = []
    try:
        with request.urlopen(req, timeout=timeout_s) as resp:
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
                delta = parsed.get("choices", [{}])[0].get("delta", {})
                content = delta.get("content")
                if isinstance(content, str):
                    buffer.append(content)
                    if on_chunk:
                        on_chunk(content)
        return "".join(buffer), {"stream": True}, None
    except Exception as exc:
        return None, None, f"stream_error: {exc}"


def _stream_ollama(
    url: str,
    payload: Dict[str, Any],
    timeout_s: int,
    headers: Dict[str, str],
    on_chunk: Callable[[str], None] | None,
) -> Tuple[str | None, Dict[str, Any] | None, str | None]:
    payload = dict(payload)
    payload["stream"] = True
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    buffer: list[str] = []
    try:
        with request.urlopen(req, timeout=timeout_s) as resp:
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
                if parsed.get("done"):
                    break
        return "".join(buffer), {"stream": True}, None
    except Exception as exc:
        return None, None, f"stream_error: {exc}"


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
            if stream_internal and on_chunk:
                content, raw_json, error_msg = _stream_openai(
                    url, payload, timeout_s, headers, on_chunk
                )
                if content is not None and error_msg is None:
                    stream_used = True
            if content is None:
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
                content, raw_json, error_msg = _stream_ollama(
                    url, payload, timeout_s, headers, on_chunk
                )
                if content is not None and error_msg is None:
                    stream_used = True
            if content is None:
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
