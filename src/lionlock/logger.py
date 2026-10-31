from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Dict, Iterator

from lionlock.utils.chain_verifier import (
    GENESIS_HASH,
    TamperDetectedError,
    entry_hash,
    verify_chain_file,
)

try:  # POSIX: an advisory lock shared by every process appending to the same file.
    import fcntl
except ImportError:  # pragma: no cover - Windows; the in-process lock still applies.
    fcntl = None  # type: ignore[assignment]

_TAIL_BLOCK = 64 * 1024
_PROCESS_LOCK = threading.Lock()


@contextmanager
def _locked(handle: IO[Any]) -> Iterator[None]:
    with _PROCESS_LOCK:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _last_line(handle: IO[bytes]) -> bytes:
    """The last line of the file, read backwards from the end so appends stay O(1)."""
    handle.seek(0, os.SEEK_END)
    end = handle.tell()
    data = b""
    position = end
    while position > 0:
        step = min(_TAIL_BLOCK, position)
        position -= step
        handle.seek(position)
        data = handle.read(step) + data
        if data.rstrip(b"\n").count(b"\n") >= 1:
            break
    return data.rstrip(b"\n").rsplit(b"\n", 1)[-1]


class TrustVaultLogger:
    """Minimal append-only logger with tamper-evident hash chaining.

    Appends are serialized across threads, and across processes on POSIX, so the chain head read
    and the append happen atomically. A damaged last line stops further writes instead of silently
    starting a new chain.
    """

    def __init__(self, path: str | Path = "trustvault.log") -> None:
        self.path = Path(path)

    def _head_from(self, handle: IO[bytes]) -> str:
        line = _last_line(handle)
        if not line.strip():
            return GENESIS_HASH
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TamperDetectedError(
                f"last entry of {self.path} is damaged (partial or invalid JSON); "
                "refusing to append, run verify_chain()"
            ) from exc
        digest = parsed.get("sha256") if isinstance(parsed, dict) else None
        if not isinstance(digest, str) or len(digest) != 64:
            raise TamperDetectedError(
                f"last entry of {self.path} has no valid sha256; refusing to append"
            )
        return digest

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        with self.path.open("rb") as handle:
            return self._head_from(handle)

    def record(self, event: str, payload: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+b") as handle, _locked(handle):
            entry = {
                "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "event": event,
                "payload": payload,
                "prev_hash": self._head_from(handle),
            }
            entry["sha256"] = entry_hash(entry)
            handle.seek(0, os.SEEK_END)
            handle.write((json.dumps(entry) + "\n").encode("utf-8"))
            handle.flush()

    def head(self) -> tuple[int, str]:
        """``(entry_count, last_sha256)``. Store it outside the log to detect truncation later."""
        count = 0
        last = GENESIS_HASH
        if self.path.exists():
            with self.path.open("rb") as handle:
                for line in handle:
                    if line.strip():
                        count += 1
                last = self._head_from(handle) if count else GENESIS_HASH
        return count, last

    def verify_chain(
        self, *, expected_head: str | None = None, expected_count: int | None = None
    ) -> None:
        """Verify the on-disk chain; raises if tampering is detected.

        A self-contained hash chain cannot tell that its newest entries were removed. Pass a
        ``head()`` recorded elsewhere as ``expected_head``/``expected_count`` to detect that too.
        """
        verify_chain_file(self.path, expected_head=expected_head, expected_count=expected_count)

    def flush(self) -> None:
        """Synchronous logger; nothing buffered, but ensure file exists for readers."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def close(self) -> None:
        """Idempotent close for API symmetry; delegates to flush."""
        self.flush()
