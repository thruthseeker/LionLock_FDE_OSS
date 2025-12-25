#!/usr/bin/env sh
set -e

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if [ ! -d ".venv" ]; then
  python -m venv .venv
fi

. .venv/bin/activate

pip install --upgrade pip
pip install -e ".[dev]"

pytest -q
