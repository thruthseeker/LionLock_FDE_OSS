#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v streamlit >/dev/null 2>&1; then
  echo "[run_gui] streamlit not found."
  echo "[run_gui] Install: python -m pip install -e \".[dev,gui]\""
  exit 1
fi

export LIONLOCK_TRUSTVAULT_PATH="${LIONLOCK_TRUSTVAULT_PATH:-./trustvault_logs/trustvault.jsonl}"
echo "[run_gui] Using log: $LIONLOCK_TRUSTVAULT_PATH"
streamlit run apps/streamlit_gui/app.py
