from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable


def _iter_py_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path


def code_fingerprint(root: Path | None = None) -> str:
    """Hash overlay .py files by relative path + bytes for deterministic provenance."""
    overlay_root = root or Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in _iter_py_files(overlay_root):
        rel_path = path.relative_to(overlay_root).as_posix()
        digest.update(rel_path.encode("utf-8"))
        digest.update(b"\n")
        digest.update(path.read_bytes())
        digest.update(b"\n")
    return digest.hexdigest()
