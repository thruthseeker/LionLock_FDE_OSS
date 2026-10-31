from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator

from lionlock.utils.chain_verifier import GENESIS_HASH, entry_hash, verify_chain_file

# Entries are small, so a single tail read of this size finds the previous hash without
# walking the file. It doubles on the rare entry that does not fit.
_TAIL_WINDOW = 8192


class ChainStateError(RuntimeError):
    """Raised when an existing log's tail cannot be read, so its chain cannot be continued."""


class TrustVaultLogger:
    """Minimal append-only logger with tamper-evident hash chaining."""

    def __init__(self, path: str | Path = "trustvault.log") -> None:
        self.path = Path(path)
        self._thread_lock = threading.Lock()

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Serialize appends across threads and processes.

        Two writers that read the same head hash both link to it, and the duplicate
        prev_hash makes verify_chain() report tampering on a log nothing tampered with.
        """
        with self._thread_lock:
            try:
                import fcntl
            except ImportError:  # pragma: no cover - non-POSIX
                yield
                return
            fd = os.open(f"{self.path}.lock", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def _last_line(self) -> str | None:
        """The last non-blank line, read from the tail so an append stays O(1)."""
        if not self.path.exists():
            return None
        with self.path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size == 0:
                return None
            window = _TAIL_WINDOW
            while True:
                start = max(0, size - window)
                handle.seek(start)
                chunk = handle.read(size - start)
                if start > 0:
                    # The window may open mid-entry, so drop that partial first line.
                    cut = chunk.find(b"\n")
                    if cut == -1:
                        window *= 2
                        continue
                    chunk = chunk[cut + 1 :]
                lines = [line for line in chunk.split(b"\n") if line.strip()]
                if lines:
                    return lines[-1].decode("utf-8")
                if start == 0:
                    return None
                window *= 2

    def _last_hash(self) -> str:
        """The hash to chain the next entry to.

        An absent or empty log legitimately starts at GENESIS. A log whose final entry
        cannot be read does not: that is a process that died mid-append, and silently
        restarting from GENESIS would break the chain's continuity without saying so.
        """
        last_line = self._last_line()
        if last_line is None:
            return GENESIS_HASH
        try:
            parsed = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise ChainStateError(
                f"{self.path} ends with an unreadable entry; refusing to start a new chain"
            ) from exc
        if not isinstance(parsed, dict):
            raise ChainStateError(f"{self.path} ends with an entry that is not an object")
        digest = parsed.get("sha256")
        if not isinstance(digest, str) or not digest:
            raise ChainStateError(f"{self.path} ends with an entry carrying no sha256")
        return digest

    def record(self, event: str, payload: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._exclusive():
            prev_hash = self._last_hash()
            entry = {
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "event": event,
                "payload": payload,
                "prev_hash": prev_hash,
            }
            entry["sha256"] = entry_hash(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
                fh.flush()
                # An audit entry that is acknowledged but not on disk is a silent gap, and
                # a lost tail is the one kind of gap the chain cannot detect on its own.
                os.fsync(fh.fileno())

    def verify_chain(self, *, expected_count: int | None = None) -> None:
        """Verify current on-disk chain; raises if tampering is detected.

        Pass ``expected_count`` when the number of entries is known from somewhere outside
        this file. Without it, entries removed from the *end* of the log cannot be detected:
        what is left still links back to GENESIS unbroken.
        """
        verify_chain_file(self.path, expected_count=expected_count)

    def flush(self) -> None:
        """Synchronous logger; nothing buffered, but ensure file exists for readers."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def close(self) -> None:
        """Idempotent close for API symmetry; delegates to flush."""
        self.flush()
