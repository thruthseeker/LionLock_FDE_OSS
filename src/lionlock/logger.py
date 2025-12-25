import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _serialize(entry: Dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


class TrustVaultLogger:
    """Minimal append-only logger for auditability."""

    def __init__(self, path: str | Path = "trustvault.log") -> None:
        self.path = Path(path)

    def record(self, event: str, payload: Dict[str, Any]) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": event,
            "payload": payload,
        }
        digest = hashlib.sha256(_serialize(entry).encode()).hexdigest()
        entry["sha256"] = digest
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def flush(self) -> None:
        """Synchronous logger; nothing buffered, but ensure file exists for readers."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def close(self) -> None:
        """Idempotent close for API symmetry; delegates to flush."""
        self.flush()
