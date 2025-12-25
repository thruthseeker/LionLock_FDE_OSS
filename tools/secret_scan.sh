#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT_DIR"

echo "Scanning for potential secrets..."

patterns=(
  "BEGIN PRIVATE KEY"
  "AWS_SECRET_ACCESS_KEY"
  "api_key="
  "token="
  "Authorization: Bearer"
)

find . -type f \
  ! -path "./.git/*" \
  ! -path "./archive/experimental/*" \
  ! -path "./.venv/*" \
  ! -path "./.pytest_cache/*" \
  ! -path "./build/*" \
  ! -path "./dist/*" \
  ! -path "./tools/secret_scan.sh" \
  | while read -r file; do
    for pat in "${patterns[@]}"; do
      if LC_ALL=C grep -Hn --binary-files=without-match -F "$pat" "$file" >/dev/null; then
        echo "Potential secret match: $file ($pat)"
      fi
    done
  done

echo "Secret scan completed."
