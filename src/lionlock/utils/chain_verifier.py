"""Hash-chain verification helpers for append-only LionLock logs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

GENESIS_HASH = "0" * 64


class TamperDetectedError(RuntimeError):
    """Raised when a hash chain break indicates probable tampering."""


def canonical_serialize(entry: dict[str, Any]) -> str:
    """Serialize an entry with deterministic key ordering for stable hashing."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def entry_hash(entry: dict[str, Any]) -> str:
    """Compute the deterministic SHA-256 hash for a chain entry."""
    payload = {key: value for key, value in entry.items() if key != "sha256"}
    return hashlib.sha256(canonical_serialize(payload).encode("utf-8")).hexdigest()


def verify_chain(entries: Iterable[dict[str, Any]]) -> None:
    """Validate prev_hash links and hashes for each chain entry."""
    previous_hash = GENESIS_HASH
    count = 0
    for count, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise TamperDetectedError(f"Entry #{count} is not an object")
        expected_prev = entry.get("prev_hash")
        if expected_prev != previous_hash:
            raise TamperDetectedError(f"Entry #{count} prev_hash mismatch")
        current_hash = str(entry.get("sha256") or "")
        expected_hash = entry_hash(entry)
        if current_hash != expected_hash:
            raise TamperDetectedError(f"Entry #{count} hash mismatch")
        previous_hash = current_hash


def verify_chain_file(path: str | Path) -> None:
    """Load JSONL entries from disk and validate their hash chain."""
    log_path = Path(path)
    if not log_path.exists():
        raise TamperDetectedError(f"Log file does not exist: {log_path}")
    entries: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise TamperDetectedError(f"Invalid JSON at line {line_number}") from exc
            if not isinstance(parsed, dict):
                raise TamperDetectedError(f"Invalid JSON object at line {line_number}")
            entries.append(parsed)
    verify_chain(entries)
