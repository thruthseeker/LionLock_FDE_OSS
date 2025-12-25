#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${ROOT_DIR}/lockdown.sha256"
OTS_PROOF="${MANIFEST}.ots"

cd "$ROOT_DIR"

# Generate deterministic SHA256 manifest (excludes caches, venvs, and archived prototypes).
find . -type f \
  ! -path "./node_modules/*" \
  ! -path "./.venv/*" \
  ! -path "./.pytest_cache/*" \
  ! -path "./build/*" \
  ! -path "./dist/*" \
  ! -path "./archive/experimental/*" \
  ! -path "./.git/*" \
  | LC_ALL=C sort | xargs sha256sum > "$MANIFEST"

echo "Manifest written to $MANIFEST"

# Submit to OpenTimestamps if available.
if command -v ots >/dev/null 2>&1; then
  ots stamp "$MANIFEST"
  ots upgrade "$OTS_PROOF" || true
  echo "OpenTimestamps proof: $OTS_PROOF"
else
  echo "ots client not found; install from https://opentimestamps.org to create proofs." >&2
fi
