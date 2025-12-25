#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

SNAPSHOT_DIR="$ROOT_DIR/.snapshots"
mkdir -p "$SNAPSHOT_DIR"

STAMP="$(date +%Y%m%d_%H%M)"
PACK_PATH="$SNAPSHOT_DIR/approval_pack_${STAMP}.zip"

echo "Creating approval pack at $PACK_PATH"

if command -v zip >/dev/null 2>&1; then
  zip -rq "$PACK_PATH" \
    README.md \
    LICENSE \
    NOTICE \
    pyproject.toml \
    CHANGELOG.md \
    RELEASE.md \
    docs \
    src/lionlock \
    tests \
    .github/workflows \
    tools \
    --exclude "archive/*" "dist/*" ".git/*"
else
  PY_BIN="python3"
  if ! command -v "$PY_BIN" >/dev/null 2>&1; then
    PY_BIN="python"
  fi
  if ! command -v "$PY_BIN" >/dev/null 2>&1; then
    echo "No Python interpreter found to build approval pack." >&2
    exit 1
  fi
  "$PY_BIN" - <<'PYCODE'
import os
import zipfile
from datetime import datetime

root = os.path.dirname(os.path.abspath(__file__))
root = os.path.normpath(os.path.join(root, ".."))
snapshot_dir = os.path.join(root, ".snapshots")
os.makedirs(snapshot_dir, exist_ok=True)
stamp = datetime.now().strftime("%Y%m%d_%H%M")
pack_path = os.path.join(snapshot_dir, f"approval_pack_{stamp}.zip")

paths = [
    "README.md",
    "LICENSE",
    "NOTICE",
    "pyproject.toml",
    "CHANGELOG.md",
    "RELEASE.md",
    os.path.join("docs"),
    os.path.join("src", "lionlock"),
    os.path.join("tests"),
    os.path.join(".github", "workflows"),
    "tools",
]
exclude_prefixes = [os.path.join(root, "archive"), os.path.join(root, "dist"), os.path.join(root, ".git")]

with zipfile.ZipFile(pack_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in paths:
        abs_path = os.path.join(root, path)
        if os.path.isdir(abs_path):
            for dirpath, dirnames, filenames in os.walk(abs_path):
                if any(os.path.commonpath([dirpath, p]) == p for p in exclude_prefixes):
                    continue
                for fname in filenames:
                    full = os.path.join(dirpath, fname)
                    rel = os.path.relpath(full, root)
                    zf.write(full, rel)
        elif os.path.isfile(abs_path):
            rel = os.path.relpath(abs_path, root)
            zf.write(abs_path, rel)
        else:
            continue
print(f"Approval pack created: {pack_path}")
PYCODE
fi

echo "Approval pack created: $PACK_PATH"
