#!/usr/bin/env python3
from __future__ import annotations

import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trust_overlay_smoke.py"


def main() -> int:
    if not SCRIPT.exists():
        sys.stderr.write("Trust overlay smoke script missing: scripts/trust_overlay_smoke.py\n")
        return 1
    try:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    except SystemExit as exc:
        if exc.code is None:
            return 0
        return int(exc.code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
