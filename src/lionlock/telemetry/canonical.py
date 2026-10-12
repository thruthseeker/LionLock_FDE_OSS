"""Canonical encoding and hashing shared by the telemetry store, exporter, and receiver.

Every digest in this package is computed over the same canonical JSON encoding, so identical
inputs produce identical digests on any platform and any Python version.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any

from lionlock.utils.chain_verifier import GENESIS_HASH

__all__ = [
    "GENESIS_HASH",
    "canonical_json",
    "chain_hash",
    "finite_float",
    "json_safe",
    "sha256_hex",
    "utc_now_iso",
]


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace, ASCII only; NaN and Infinity are rejected."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """Hash of one log row, bound to the hash of the row before it."""
    return sha256_hex(f"{prev_hash}\n{canonical_json(payload)}")


def finite_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    return None


def json_safe(value: Any, *, max_text: int = 1024) -> Any:
    """Coerce a value into something ``canonical_json`` accepts, deterministically."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(key): json_safe(item, max_text=max_text) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item, max_text=max_text) for item in value]
    return str(value)[:max_text]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
