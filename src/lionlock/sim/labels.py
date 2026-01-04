from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping, Any


def write_labels(path: str | Path, records: Iterable[Mapping[str, Any]]) -> str:
    label_path = Path(path)
    label_path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with label_path.open("wb") as handle:
        for record in records:
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            data = line.encode("utf-8")
            handle.write(data)
            handle.write(b"\n")
            digest.update(data)
            digest.update(b"\n")
    return digest.hexdigest()
