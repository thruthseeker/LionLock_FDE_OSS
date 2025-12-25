#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v pytest >/dev/null 2>&1; then
  echo "pytest not found. Install dev extras: pip install -e '.[dev]'" >&2
  exit 1
fi

echo "Running ruff format check..."
ruff format --check .

echo "Running ruff lint..."
ruff check .

echo "Running mypy..."
mypy src/lionlock

echo "Running pytest..."
pytest -q

echo "Local CI checks completed."
