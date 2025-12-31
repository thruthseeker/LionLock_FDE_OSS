from __future__ import annotations

from typing import Any, Iterable

FORBIDDEN_PAYLOAD_KEYS = {
    "prompt",
    "response",
    "prompt_text",
    "response_text",
    "messages",
    "payload_b64",
    "user_id",
    "ip",
    "device_id",
}

FORBIDDEN_VALUE_TOKENS = FORBIDDEN_PAYLOAD_KEYS | {
    "assistant_response",
    "raw_messages",
    "raw_text",
    "system_prompt",
    "user_prompt",
}

DEFAULT_VALUE_SCAN_MAX_CHARS = 500


def scrub_forbidden_keys(
    value: Any,
    *,
    forbidden_keys: Iterable[str] | None = None,
    mode: str = "reject",
) -> tuple[bool, Any, str | None]:
    forbidden = {key.lower() for key in (forbidden_keys or FORBIDDEN_PAYLOAD_KEYS)}

    def _scrub(node: Any, path: str) -> tuple[bool, Any, str | None]:
        if isinstance(node, dict):
            cleaned: dict[str, Any] = {}
            for key, item in node.items():
                if key.lower() in forbidden:
                    if mode == "strip":
                        continue
                    return False, None, f"Forbidden key '{key}' at {path or 'root'}"
                ok, cleaned_item, message = _scrub(item, f"{path}.{key}" if path else key)
                if not ok:
                    return False, None, message
                cleaned[key] = cleaned_item
            return True, cleaned, None
        if isinstance(node, list):
            cleaned_list: list[Any] = []
            for idx, item in enumerate(node):
                ok, cleaned_item, message = _scrub(item, f"{path}[{idx}]")
                if not ok:
                    return False, None, message
                cleaned_list.append(cleaned_item)
            return True, cleaned_list, None
        return True, node, None

    if mode not in {"reject", "strip"}:
        return False, None, "Invalid scrub mode (expected 'reject' or 'strip')."
    return _scrub(value, "")


def _contains_forbidden_markers(value: str, *, forbidden_tokens: set[str]) -> bool:
    lowered = value.lower()
    for token in forbidden_tokens:
        if f"{token}:" in lowered or f"{token}=" in lowered:
            return True
    return False


def _looks_like_free_text(value: str, max_string_length: int) -> bool:
    if max_string_length <= 0:
        return False
    if len(value) < max_string_length:
        return False
    return any(ch.isspace() for ch in value)


def find_forbidden_content(
    value: Any,
    *,
    forbidden_tokens: Iterable[str] | None = None,
    max_string_length: int = DEFAULT_VALUE_SCAN_MAX_CHARS,
) -> str | None:
    tokens = {
        token.lower()
        for token in (forbidden_tokens or FORBIDDEN_VALUE_TOKENS)
        if isinstance(token, str)
    }

    def _scan(node: Any, path: str) -> str | None:
        if isinstance(node, dict):
            for key, item in node.items():
                next_path = f"{path}.{key}" if path else str(key)
                found = _scan(item, next_path)
                if found:
                    return found
            return None
        if isinstance(node, (list, tuple)):
            for idx, item in enumerate(node):
                next_path = f"{path}[{idx}]"
                found = _scan(item, next_path)
                if found:
                    return found
            return None
        if isinstance(node, str):
            if _contains_forbidden_markers(node, forbidden_tokens=tokens):
                return path or "root"
            if _looks_like_free_text(node, max_string_length):
                return path or "root"
        return None

    return _scan(value, "")


def contains_forbidden_content(
    value: Any,
    *,
    forbidden_tokens: Iterable[str] | None = None,
    max_string_length: int = DEFAULT_VALUE_SCAN_MAX_CHARS,
) -> bool:
    return (
        find_forbidden_content(
            value,
            forbidden_tokens=forbidden_tokens,
            max_string_length=max_string_length,
        )
        is not None
    )


def contains_forbidden_keys(
    value: Any,
    *,
    forbidden_keys: Iterable[str] | None = None,
) -> bool:
    forbidden = {key.lower() for key in (forbidden_keys or FORBIDDEN_PAYLOAD_KEYS)}

    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in forbidden:
                return True
            if contains_forbidden_keys(item, forbidden_keys=forbidden):
                return True
    elif isinstance(value, list):
        return any(contains_forbidden_keys(item, forbidden_keys=forbidden) for item in value)
    return False
