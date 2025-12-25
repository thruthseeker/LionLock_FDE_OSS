#!/usr/bin/env bash
set -euo pipefail

echo "Scanning for potential secrets..."

PATTERNS=(
  "BEGIN PRIVATE KEY"
  "AWS_SECRET_ACCESS_KEY"
  "api_key="
  "token="
  "Authorization: Bearer"
)

# Directories we do NOT scan (noise + open-core hygiene + local artifacts)
EXCLUDE_DIRS=(
  "./.git"
  "./.venv"
  "./__pycache__"
  "./logs"
  "./_split"
  "./_split_v2"
  "./archive"
  "./repos"
  "./.history"
)

# Build find exclusions
FIND_EXCLUDES=()
for d in "${EXCLUDE_DIRS[@]}"; do
  FIND_EXCLUDES+=( -path "$d" -prune -o )
done

# Scan all files except secret_scan.sh (prevents self-trigger, even if copied)
while IFS= read -r -d '' file; do
  for pat in "${PATTERNS[@]}"; do
    if grep -nH --fixed-strings "$pat" "$file" >/dev/null 2>&1; then
      echo "Potential secret match: $file ($pat)"
    fi
  done
done < <(
  find . \
    "${FIND_EXCLUDES[@]}" \
    -type f \
    ! -name "secret_scan.sh" \
    -print0
)

echo "Secret scan completed."
