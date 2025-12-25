#!/usr/bin/env bash
# Usage: tools/make_thinslice.sh [output_path]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-"$ROOT/lionlock_thinslice.tgz"}"
MAX_MB="${SNAPSHOT_MAX_MB:-80}"

default_includes=(
  src
  tests
  apps
  docs
  .github
  configs
  README.md
  SECURITY.md
  USAGE.md
  CHANGELOG.md
  RELEASE.md
  CITATION.cff
  CODE_OF_CONDUCT.md
  LICENSE
  NOTICE
  docker-compose.yml
  Dockerfile
  pyproject.toml
  MANIFEST.in
  *.md
)

fallback_includes=(
  src
  tests
  docs
  apps
  .github
  configs
  README.md
  SECURITY.md
  USAGE.md
  docker-compose.yml
  Dockerfile
  pyproject.toml
)

excludes=(
  .git
  .venv
  venv
  node_modules
  __pycache__
  .pytest_cache
  .ruff_cache
  .mypy_cache
  dist
  build
  logs
  "*.log"
  "*.sqlite"
  "*.sqlite3"
  "*.db"
  "*.gguf"
  "*.bin"
  "*.pt"
  "*.onnx"
  "*.zip"
  "*.tar"
  "*.tgz"
  archive/experimental
  .history
  trustvault_logs
)

collect_includes() {
  local -a acc=()
  declare -A seen=()
  shopt -s nullglob dotglob
  for path in "$@"; do
    local -a matches=("$ROOT"/$path)
    if [[ ${#matches[@]} -gt 0 ]]; then
      for match in "${matches[@]}"; do
        [[ -e "$match" ]] || continue
        rel="${match#$ROOT/}"
        if [[ -z "${seen[$rel]+set}" ]]; then
          seen[$rel]=1
          acc+=("$rel")
        fi
      done
    fi
  done
  shopt -u nullglob dotglob
  echo "${acc[@]}"
}

build_archive() {
  local out="$1"
  shift
  local -a includes=("$@")
  local -a tar_excludes=()
  for ex in "${excludes[@]}"; do
    tar_excludes+=(--exclude="$ex")
  done
  rm -f "$out"
  (cd "$ROOT" && tar -czf "$out" --exclude-vcs "${tar_excludes[@]}" "${includes[@]}")
}

read -r -a include_set <<<"$(collect_includes "${default_includes[@]}")"
if [[ ${#include_set[@]} -eq 0 ]]; then
  echo "No include targets found." >&2
  exit 1
fi

build_archive "$OUT" "${include_set[@]}"
size_bytes="$(stat -c%s "$OUT")"
size_mb=$(( (size_bytes + 1024*1024 - 1) / (1024*1024) ))

if (( size_mb > MAX_MB )); then
  echo "Archive ${size_mb}MB exceeds ${MAX_MB}MB. Rebuilding with narrower set..." >&2
  read -r -a include_set <<<"$(collect_includes "${fallback_includes[@]}")"
  build_archive "$OUT" "${include_set[@]}"
  size_bytes="$(stat -c%s "$OUT")"
  size_mb=$(( (size_bytes + 1024*1024 - 1) / (1024*1024) ))
fi

echo "Archive ready: $OUT ($(du -h "$OUT" | cut -f1))"
echo "Includes:"
printf ' - %s\n' "${include_set[@]}"
echo "Excludes:"
printf ' - %s\n' "${excludes[@]}"
