#!/usr/bin/env sh
set -e

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

VENV_PATH="${LIONLOCK_VENV_PATH:-$ROOT_DIR/.venv}"

if [ ! -d "$VENV_PATH" ]; then
  python -m venv "$VENV_PATH"
fi

. "$VENV_PATH/bin/activate"

pip install --upgrade pip
pip install -e ".[dev]"

pytest -q
