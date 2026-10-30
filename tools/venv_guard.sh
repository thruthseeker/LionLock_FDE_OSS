#!/usr/bin/env sh
set -eu

# Enforce the canonical virtualenv for this repo and refuse silent fallbacks.
# Usage: source "$(dirname "$0")/venv_guard.sh"

script_path="${BASH_SOURCE:-$0}"
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$script_path")/.." && pwd)
# Set LIONLOCK_VENV_PATH to keep the venv outside the repository; the default is <repo>/.venv.
VENV_PATH="${LIONLOCK_VENV_PATH:-$ROOT_DIR/.venv}"

fail() {
  echo "[venv_guard] $*" >&2
  if [ "${BASH_SOURCE:-$0}" = "$0" ]; then
    exit 1
  else
    return 1
  fi
}

ensure_python_bin() {
  if command -v python3 >/dev/null 2>&1; then
    echo "python3"
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    echo "python"
    return 0
  fi
  fail "Python interpreter not found (expected python3 or python)"
}

if [ ! -d "$VENV_PATH" ]; then
  pybin=$(ensure_python_bin)
  "$pybin" -m venv "$VENV_PATH" || fail "Unable to create venv at $VENV_PATH"
fi

# Activation and sys.executable use absolute paths, even for a relative override.
VENV_PATH=$(CDPATH= cd -- "$VENV_PATH" && pwd)

if [ ! -f "$VENV_PATH/bin/activate" ]; then
  fail "Missing activate script at $VENV_PATH/bin/activate"
fi

if [ "${VIRTUAL_ENV:-}" != "$VENV_PATH" ]; then
  # shellcheck disable=SC1090
  . "$VENV_PATH/bin/activate"
fi

if [ "${VIRTUAL_ENV:-}" != "$VENV_PATH" ]; then
  fail "VIRTUAL_ENV mismatch; expected $VENV_PATH, got ${VIRTUAL_ENV:-unset}"
fi

py_cmd=$(command -v python || true)
expected_py="$VENV_PATH/bin/python"
if [ "$py_cmd" != "$expected_py" ]; then
  fail "PATH python mismatch; expected $expected_py, got ${py_cmd:-unset}"
fi

py_exe=$(python - <<'PY'
import sys
print(sys.executable)
PY
) || fail "Python executable check failed"

if [ "$py_exe" != "$expected_py" ]; then
  fail "sys.executable mismatch; expected $expected_py, got $py_exe"
fi

export PIP_DISABLE_PIP_VERSION_CHECK=1

echo "[venv_guard] using venv at $VENV_PATH"
