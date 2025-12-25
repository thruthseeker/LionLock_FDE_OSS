#!/usr/bin/env bash
# Usage: tools/make_state_digest.sh [output_path]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTFILE="${1:-"$ROOT/LIONLOCK_STATE_DIGEST.md"}"

python_version="$(python3 --version 2>/dev/null || echo "python3 not found")"
git_root="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null || true)"

if [[ -n "$git_root" ]]; then
  git_hash="$(git -C "$ROOT" rev-parse HEAD)"
  git_status="$(git -C "$ROOT" status --short || true)"
else
  git_hash="(not a git repo in $ROOT)"
  git_status="(n/a)"
fi

total_size="$(du -sh "$ROOT" | cut -f1)"
top_dirs="$(du -h -d 2 "$ROOT" | sort -hr | head -n 15 | sed "s#$ROOT/#./#")"
set +o pipefail
top_files="$(find "$ROOT" -type f -printf '%s\t%P\n' | sort -nr | head -n 20 | awk 'BEGIN{OFS="\t"}{printf "%.2f MB\t%s\n", $1/1024/1024, $2}')"
set -o pipefail

declare -a bloat_lines=()
for path in .venv .mypy_cache .ruff_cache .pytest_cache logs .history archive dist build; do
  if [[ -e "$ROOT/$path" ]]; then
    size="$(du -sh "$ROOT/$path" 2>/dev/null | cut -f1)"
    bloat_lines+=("$size"$'\t'"$path")
  fi
done
bloat_section="$(printf '%s\n' "${bloat_lines[@]:-}" | sort -hr)"

run_check() {
  local name="$1"
  shift
  local cmd_display="$*"
  if ! command -v "$1" >/dev/null 2>&1; then
    printf -- "- %s: missing (%s)\n" "$name" "$cmd_display"
    return
  fi
  local tmp_err tmp_out exit_code status snip
  tmp_err="$(mktemp)"
  tmp_out="$(mktemp)"
  set +e
  (cd "$ROOT" && "$@") >"$tmp_out" 2>"$tmp_err"
  exit_code=$?
  set -e
  if [[ $exit_code -eq 0 ]]; then
    status="pass"
  else
    status="fail (exit $exit_code)"
  fi
  snip="$(head -n 8 "$tmp_err" || true)"
  rm -f "$tmp_err" "$tmp_out"
  printf -- "- %s: %s\n" "$name" "$status"
  if [[ -n "$snip" ]]; then
    echo "  stderr (first 8 lines):"
    printf '%s\n' "$snip" | sed 's/^/    /'
  fi
}

checks_tmp="$(mktemp)"
run_check "pytest" pytest -q >>"$checks_tmp"
run_check "ruff" ruff check . >>"$checks_tmp"
checks_section="$(cat "$checks_tmp")"
rm -f "$checks_tmp"

key_tree_section() {
  local label="$1"
  local target="$2"
  if [[ -d "$ROOT/$target" ]]; then
    echo "### $label ($target)"
    (cd "$ROOT/$target" && find . -maxdepth 2 -type d | sort)
    echo
  fi
}

cat >"$OUTFILE" <<EOF
# LionLock State Digest

- Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- Repo root: $ROOT
- Total size: $total_size
- Python: $python_version
- Git HEAD: $git_hash

## Git status
$git_status

## Bloat checkpoints
$bloat_section

## Largest directories (depth 2)
$top_dirs

## Top 20 files by size
$top_files

## Key tree (max depth 2)
EOF

key_tree_section "Source" "src" >>"$OUTFILE"
key_tree_section "Apps" "apps" >>"$OUTFILE"
key_tree_section "Tests" "tests" >>"$OUTFILE"
key_tree_section "Docs" "docs" >>"$OUTFILE"
key_tree_section "Configs" "configs" >>"$OUTFILE"
key_tree_section "GitHub" ".github" >>"$OUTFILE"

cat >>"$OUTFILE" <<EOF
## Checks
$checks_section

## Notes
- This digest omits dependency/env folders in the snapshot recommendations; see cleanup plan for exclusions.
EOF

echo "Wrote digest to $OUTFILE"
