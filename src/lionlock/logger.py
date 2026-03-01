from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from lionlock.utils.chain_verifier import GENESIS_HASH, entry_hash, verify_chain_file


class TrustVaultLogger:
    """Minimal append-only logger with tamper-evident hash chaining."""

    def __init__(self, path: str | Path = "trustvault.log") -> None:
        self.path = Path(path)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last_line = ""
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line
        if not last_line:
            return GENESIS_HASH
        try:
            parsed = json.loads(last_line)
        except json.JSONDecodeError:
            return GENESIS_HASH
        if not isinstance(parsed, dict):
            return GENESIS_HASH
        digest = parsed.get("sha256")
        return str(digest) if isinstance(digest, str) and digest else GENESIS_HASH

    def record(self, event: str, payload: Dict[str, Any]) -> None:
        prev_hash = self._last_hash()
        entry = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": event,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        entry["sha256"] = entry_hash(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def verify_chain(self) -> None:
        """Verify current on-disk chain; raises if tampering is detected."""
        verify_chain_file(self.path)

    def flush(self) -> None:
        """Synchronous logger; nothing buffered, but ensure file exists for readers."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def close(self) -> None:
        """Idempotent close for API symmetry; delegates to flush."""
        self.flush()
