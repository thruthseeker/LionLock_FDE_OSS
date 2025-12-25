#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT_DIR"

if ! command -v pip-audit >/dev/null 2>&1; then
  echo "pip-audit is required. Install dev extras: pip install -e '.[dev]'" >&2
  exit 1
fi

echo "Running pip-audit..."
pip-audit
