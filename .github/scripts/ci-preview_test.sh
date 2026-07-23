#!/usr/bin/env bash
#
# Snapshot tests for ci-preview.sh. For each named preset scenario, invoke
# the preview in --json mode and assert the computed flag values match the
# expectations documented here. This is a second layer of protection on top
# of variables_test.sh: variables_test.sh checks the flag functions in
# isolation; this checks the scenario wiring in ci-preview.sh + the
# translation of workflow_dispatch inputs (e.g. docs_only being force-false
# on workflow_dispatch).
#
# Run: bash .github/scripts/ci-preview_test.sh [-v|--verbose]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREVIEW="$SCRIPT_DIR/ci-preview.sh"

VERBOSE=0
case "${1:-}" in -v | --verbose) VERBOSE=1 ;; esac

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_PASS=$'\033[0;32m' C_FAIL=$'\033[0;31m' C_DIM=$'\033[0;90m' C_OFF=$'\033[0m'
else
  C_PASS='' C_FAIL='' C_DIM='' C_OFF=''
fi

pass=0
fail=0

# extract_flags_line <json-blob>
# Collapses the JSON emitted by ci-preview --json to a single-line form:
#   run_tests=<v> docker_build=<v> run_unit_tests=<v> run_e2e=<v> tag_stable=<v> promote=<v>
extract_flags_line() {
  awk -F'"' '
    /"run_tests":/      { r=$4 }
    /"docker_build":/   { d=$4 }
    /"run_unit_tests":/ { u=$4 }
    /"run_e2e":/        { e=$4 }
    /"tag_stable":/     { t=$4 }
    /"promote":/        { p=$4 }
    END { printf "run_tests=%s docker_build=%s run_unit_tests=%s run_e2e=%s tag_stable=%s promote=%s", r, d, u, e, t, p }
  '
}

# assert_scenario_flags <preset> <expected-flags-line>
assert_scenario_flags() {
  local preset="$1" want="$2"
  local got
  got=$(NO_COLOR=1 "$PREVIEW" --scenario "$preset" --json 2>/dev/null | extract_flags_line)
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b✓ PASS%b %-18s %s\n' "$C_PASS" "$C_OFF" "$preset" "$got"
    fi
  else
    fail=$((fail + 1))
    printf '%b✗ FAIL%b %-18s\n  want: %s\n  got:  %s\n' \
      "$C_FAIL" "$C_OFF" "$preset" "$want" "$got"
  fi
}

# assert_current_flags <label> <extra-args...> -- <expected-flags-line>
# Runs `--current <extra-args>` and asserts the resulting flags. The `--`
# separator marks where the expected line begins so we can pass an arbitrary
# number of extra ci-preview flags before it.
assert_current_flags() {
  local label="$1"; shift
  local args=() want=""
  while [ $# -gt 0 ]; do
    if [ "$1" = "--" ]; then shift; want="$1"; shift; break; fi
    args+=("$1"); shift
  done
  local got
  got=$(NO_COLOR=1 "$PREVIEW" --current "${args[@]}" --json 2>/dev/null | extract_flags_line)
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b✓ PASS%b %-18s %s\n' "$C_PASS" "$C_OFF" "$label" "$got"
    fi
  else
    fail=$((fail + 1))
    printf '%b✗ FAIL%b %-18s\n  want: %s\n  got:  %s\n' \
      "$C_FAIL" "$C_OFF" "$label" "$want" "$got"
  fi
}

# --- presets -----------------------------------------------------------------
# Keep aligned with the docstring in ci-preview.sh. Each row: the flag values
# that ci.yml would use to gate every downstream job for that scenario.

assert_scenario_flags normal \
  "run_tests=true docker_build=true run_unit_tests=true run_e2e=true tag_stable=true promote=false"

assert_scenario_flags docs-only \
  "run_tests=false docker_build=false run_unit_tests=false run_e2e=false tag_stable=false promote=false"

assert_scenario_flags up-to-date \
  "run_tests=false docker_build=false run_unit_tests=false run_e2e=false tag_stable=false promote=false"

assert_scenario_flags cache-only \
  "run_tests=true docker_build=true run_unit_tests=false run_e2e=true tag_stable=true promote=false"

assert_scenario_flags stable-only \
  "run_tests=false docker_build=false run_unit_tests=false run_e2e=false tag_stable=false promote=false"

assert_scenario_flags forked \
  "run_tests=true docker_build=true run_unit_tests=true run_e2e=false tag_stable=false promote=false"

assert_scenario_flags forked-docs \
  "run_tests=false docker_build=false run_unit_tests=false run_e2e=false tag_stable=false promote=false"

assert_scenario_flags force-main \
  "run_tests=false docker_build=true run_unit_tests=true run_e2e=true tag_stable=true promote=true"

assert_scenario_flags force-main-no-tests \
  "run_tests=false docker_build=true run_unit_tests=false run_e2e=false tag_stable=false promote=false"

assert_scenario_flags force-release \
  "run_tests=false docker_build=true run_unit_tests=true run_e2e=true tag_stable=true promote=true"

assert_scenario_flags force-feature \
  "run_tests=true docker_build=true run_unit_tests=true run_e2e=true tag_stable=true promote=false"

assert_scenario_flags run-tests-false \
  "run_tests=false docker_build=true run_unit_tests=false run_e2e=false tag_stable=false promote=false"

assert_scenario_flags merge-queue \
  "run_tests=true docker_build=true run_unit_tests=true run_e2e=true tag_stable=true promote=false"

# --- --current mode ----------------------------------------------------------
# Smoke-test the auto-detect wiring. Explicit overrides must beat the
# auto-detected value; this is what makes `make ci-preview` safe on any branch.
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  assert_current_flags "current+docs-only" --docs-only true -- \
    "run_tests=false docker_build=false run_unit_tests=false run_e2e=false tag_stable=false promote=false"

  assert_current_flags "current+optimistic" --cache-hit true --stable-exists true -- \
    "run_tests=false docker_build=false run_unit_tests=false run_e2e=false tag_stable=false promote=false"
else
  if [ "$VERBOSE" -eq 1 ]; then
    printf '%b- SKIP%b %-18s %b[not in a git repo]%b\n' \
      "$C_DIM" "$C_OFF" "current mode" "$C_DIM" "$C_OFF"
  fi
fi

if [ "$fail" -eq 0 ]; then
  printf '%b✓ all %d preview scenarios passed%b\n' "$C_PASS" "$pass" "$C_OFF"
else
  printf '%b✗ %d of %d preview scenarios failed%b\n' "$C_FAIL" "$fail" "$((pass + fail))" "$C_OFF"
fi
[ "$fail" -eq 0 ]
