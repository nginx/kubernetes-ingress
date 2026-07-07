#!/usr/bin/env bash
#
# Unit tests for the CI decision logic in variables.sh.
#
# These test the pure decision functions (get_run_tests, get_docker_build,
# get_run_unit_tests, get_run_build, get_run_e2e, get_tag_stable, get_promote)
# by sourcing the script; the source guard in the script prevents main() from
# running, so git / the wider environment is not required here.
#
# Run directly:         bash .github/scripts/variables_test.sh
# Verbose (per-test):   bash .github/scripts/variables_test.sh -v

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/variables.sh"

# -v / --verbose prints a line for every test case (not just failures).
VERBOSE=0
case "${1:-}" in
-v | --verbose) VERBOSE=1 ;;
esac

# Colours, disabled when not writing to a terminal or when NO_COLOR is set.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_PASS=$'\033[0;32m' C_FAIL=$'\033[0;31m' C_DIM=$'\033[0;90m' C_OFF=$'\033[0m'
else
  C_PASS='' C_FAIL='' C_DIM='' C_OFF=''
fi

pass=0
fail=0

# assert_flag <fn> <expected> <description> [ENV=VAL ...]
# Runs <fn> in a subshell with ONLY the given environment overrides set (via
# `env -i`) so each case is isolated, and compares its stdout to <expected>.
assert_flag() {
  local fn="$1" want="$2" desc="$3"
  shift 3
  local got
  got=$(env -i "$@" bash -c "source '$SCRIPT_DIR/variables.sh'; $fn")
  if [[ "$got" == "$want" ]]; then
    pass=$((pass + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b✓ PASS%b %-18s %-40s => %-5s %b[%s]%b\n' \
        "$C_PASS" "$C_OFF" "$fn" "$desc" "$want" "$C_DIM" "${*:-<defaults>}" "$C_OFF"
    fi
  else
    fail=$((fail + 1))
    printf '%b✗ FAIL%b %-18s %-40s => want=%s got=%s %b[%s]%b\n' \
      "$C_FAIL" "$C_OFF" "$fn" "$desc" "$want" "$got" "$C_DIM" "${*:-<defaults>}" "$C_OFF"
  fi
}

# --- get_run_tests ------------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_run_tests true  "default PR (empty inputs)"
assert_flag get_run_tests false "workflow_dispatch run_tests=false" RUN_TESTS_INPUT=false
assert_flag get_run_tests false "docs-only change"                  DOCS_ONLY=true
assert_flag get_run_tests false "cache hit and stable exists"       BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_run_tests true  "cache hit but no stable image"     BINARY_CACHE_HIT=true STABLE_EXISTS=false
assert_flag get_run_tests true  "stable exists but no cache hit"    BINARY_CACHE_HIT=false STABLE_EXISTS=true

# --- get_docker_build ---------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_docker_build true  "force always builds"                FORCE=true DOCS_ONLY=true BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_docker_build true  "forked non-docs change"             FORKED=true DOCS_ONLY=false
assert_flag get_docker_build false "forked docs-only change"            FORKED=true DOCS_ONLY=true
assert_flag get_docker_build true  "main repo, no cache hit"            FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=true
assert_flag get_docker_build true  "main repo, cache hit, no stable"    FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=false
assert_flag get_docker_build false "main repo, cache hit and stable"    FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_docker_build false "main repo docs-only"                FORKED=false DOCS_ONLY=true

# --- get_run_unit_tests -------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_run_unit_tests true  "force runs unit tests"           FORCE=true BINARY_CACHE_HIT=true
assert_flag get_run_unit_tests true  "tests requested, no cache hit"   BINARY_CACHE_HIT=false
assert_flag get_run_unit_tests false "tests requested but cache hit"   BINARY_CACHE_HIT=true STABLE_EXISTS=false
assert_flag get_run_unit_tests false "docs-only skips unit tests"      DOCS_ONLY=true
assert_flag get_run_unit_tests false "cache hit and stable exists"     BINARY_CACHE_HIT=true STABLE_EXISTS=true

# --- get_run_build ------------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_run_build true  "force triggers build"                 FORCE=true DOCS_ONLY=true BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_run_build true  "run_tests triggers build"             BINARY_CACHE_HIT=false
assert_flag get_run_build true  "docker_build triggers build"          RUN_TESTS_INPUT=false FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false
assert_flag get_run_build false "nothing to do"                        DOCS_ONLY=true BINARY_CACHE_HIT=true STABLE_EXISTS=true

# --- get_run_e2e --------------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_run_e2e true  "main repo with work"                    FORKED=false BINARY_CACHE_HIT=false
assert_flag get_run_e2e false "forked never runs e2e"                  FORKED=true DOCS_ONLY=false
assert_flag get_run_e2e false "main repo, nothing to do"               FORKED=false DOCS_ONLY=true BINARY_CACHE_HIT=true STABLE_EXISTS=true

# --- get_tag_stable -----------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_tag_stable true  "main repo, no stable image"          FORKED=false STABLE_EXISTS=false
assert_flag get_tag_stable false "main repo, stable already exists"    FORKED=false STABLE_EXISTS=true
assert_flag get_tag_stable false "forked never tags stable"            FORKED=true STABLE_EXISTS=false

# --- get_promote --------------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_promote true  "force on main"                          FORCE=true REF_NAME=main
assert_flag get_promote true  "force on release branch"                FORCE=true REF_NAME=release-4.0
assert_flag get_promote false "force on feature branch"                FORCE=true REF_NAME=my-feature
assert_flag get_promote false "no force on main"                       FORCE=false REF_NAME=main

if [ "$fail" -eq 0 ]; then
  printf '%b✓ all %d tests passed%b\n' "$C_PASS" "$pass" "$C_OFF"
else
  printf '%b✗ %d of %d tests failed%b\n' "$C_FAIL" "$fail" "$((pass + fail))" "$C_OFF"
fi
[ "$fail" -eq 0 ]
