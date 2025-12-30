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
