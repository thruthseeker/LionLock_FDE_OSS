#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v pytest >/dev/null 2>&1; then
  echo "[checks] pytest not found. Install dev extras: pip install -e '.[dev]'" >&2
  exit 1
fi

echo "[checks] python:"
python --version

echo "[checks] compileall:"
python -m compileall -q src

echo "[checks] pytest:"
pytest -q

echo "[checks] ruff:"
ruff check .

echo "[checks] mypy:"
mypy src

echo "[checks] OK"
