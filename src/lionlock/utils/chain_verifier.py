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


def verify_chain(
    entries: Iterable[dict[str, Any]],
    *,
    expected_head: str | None = None,
    expected_count: int | None = None,
) -> None:
    """Validate prev_hash links and hashes for each chain entry.

    The chain alone detects edited, inserted, reordered and leading-removed entries. Removing the
    newest entries, or rewriting the whole log, is detected only against a head recorded outside
    the log: pass it as ``expected_head`` (last ``sha256``) and/or ``expected_count``. A log that
    has grown since the head was recorded passes as long as the recorded head is still in it.
    """
    previous_hash = GENESIS_HASH
    seen_head = expected_head is None or expected_head == GENESIS_HASH
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
        if expected_count is not None and count == expected_count and expected_head is not None:
            if current_hash != expected_head:
                raise TamperDetectedError(f"Entry #{count} is not the recorded head")
        if current_hash == expected_head:
            seen_head = True
    if expected_count is not None and count < expected_count:
        raise TamperDetectedError(
            f"Log holds {count} entries but {expected_count} were recorded (truncated)"
        )
    if not seen_head:
        raise TamperDetectedError("Recorded head is not in the log (truncated or rewritten)")


def verify_chain_file(
    path: str | Path,
    *,
    expected_head: str | None = None,
    expected_count: int | None = None,
) -> None:
    """Load JSONL entries from disk and validate their hash chain (see ``verify_chain``)."""
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
    verify_chain(entries, expected_head=expected_head, expected_count=expected_count)
