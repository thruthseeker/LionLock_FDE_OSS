#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1. Install dev extras: pip install -e '.[dev]'" >&2
    exit 1
  fi
}

require_cmd ruff
require_cmd mypy
require_cmd pytest
require_cmd python
require_cmd twine

echo "Running ruff format check..."
ruff format --check .

echo "Running ruff lint..."
ruff check .

echo "Running mypy..."
mypy src/lionlock

echo "Running pytest..."
pytest -q

if [ -x "tools/secret_scan.sh" ]; then
  echo "Running secret scan..."
  bash tools/secret_scan.sh
fi

if [ -x "tools/security_audit.sh" ]; then
  echo "Running security audit..."
  bash tools/security_audit.sh
fi

echo "Building package..."
python -m build

echo "Running twine check..."
twine check dist/*

echo "Pre-push checks completed."
