#!/usr/bin/env bash
set -euo pipefail

# Wrapper guard to enforce the canonical venv for Module 4 tooling.
# Delegates to tools/venv_guard.sh to keep a single source of truth.

SOURCE_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd "$(dirname "$SOURCE_PATH")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_GUARD="$ROOT_DIR/tools/venv_guard.sh"

if [ ! -f "$TOOLS_GUARD" ]; then
  echo "[venv_guard] missing tools/venv_guard.sh at $TOOLS_GUARD" >&2
  exit 1
fi

# shellcheck source=../tools/venv_guard.sh
. "$TOOLS_GUARD"
