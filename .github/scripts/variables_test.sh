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

echo "Running CI decision logic unit tests..."
# --- get_run_tests ------------------------------------------------------------
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

# =============================================================================
# Scenario tests: verify the full get_ci_flags output for realistic CI
# situations. Each scenario sets all relevant env vars and checks the complete
# set of flags as a unit, catching cross-flag interaction bugs.
#
# Flag → ci.yml job mapping (kept in sync with .github/workflows/ci.yml):
#
#   run_unit_tests -> verify-codegen, unit-tests, staticcheck, govulncheck
#   run_build      -> build-artifacts (AND success/skipped result gates)
#   docker_build   -> build-artifacts.yml `force:` input
#   run_e2e        -> tag-target, package-tests, helm-tests, setup-matrix,
#                     smoke-tests-{oss,plus,nap}
#   tag_stable     -> tag-stable
#   promote        -> trigger-image-promotion
#   run_tests      -> setup-smoke.yml `force:` input
#
# Not gated by any flag (only the `github.repository` check):
#   checks, final-results (final-results additionally uses !cancelled()).
#
# Note: `tag_stable=true` in scenarios where no build/e2e runs (e.g. docs-only
# on the main repo) is a harmless false positive at the flag layer — the
# tag-stable job's `needs: [..., smoke-tests-*]` causes GitHub Actions to skip
# it when its dependencies are skipped.
# =============================================================================

# assert_ci_flags <description> <expected_multiline> [ENV=VAL ...]
# Runs get_ci_flags in an isolated env and compares all output lines.
assert_ci_flags() {
  local desc="$1" want="$2"
  shift 2
  local got
  got=$(env -i "$@" bash -c "source '$SCRIPT_DIR/variables.sh'; get_ci_flags")
  if [[ "$got" == "$want" ]]; then
    pass=$((pass + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b✓ PASS%b get_ci_flags  %-50s %b[%s]%b\n' \
        "$C_PASS" "$C_OFF" "$desc" "$C_DIM" "${*:-<defaults>}" "$C_OFF"
    fi
  else
    fail=$((fail + 1))
    printf '%b✗ FAIL%b get_ci_flags  %-50s %b[%s]%b\n' \
      "$C_FAIL" "$C_OFF" "$desc" "$C_DIM" "${*:-<defaults>}" "$C_OFF"
    printf '  want:\n'
    echo "$want" | sed 's/^/    /'
    printf '  got:\n'
    echo "$got" | sed 's/^/    /'
  fi
}

# --- Scenario: Normal PR (main repo, no cache, no stable image) ---------------
# This is the most common case for a code change on the main repo.
# Everything runs: unit tests, build, e2e, tag stable.
assert_ci_flags "normal PR (main repo, fresh)" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=true
tag_stable=true
promote=false" \
  FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=feature-branch

# --- Scenario: Docs-only PR (main repo) --------------------------------------
# Only documentation changed; every build/test flag is false.
# `tag_stable=true` here is a harmless false positive at the flag layer — see
# the header comment above.
assert_ci_flags "docs-only PR (main repo, no stable)" \
"run_tests=false
docker_build=false
run_unit_tests=false
run_build=false
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=false DOCS_ONLY=true BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=docs-update

# --- Scenario: Docs-only PR with stable image already present -----------------
# Same as above but stable image exists — tag_stable is correctly false.
# Confirms `get_tag_stable` still gates on STABLE_EXISTS regardless of DOCS_ONLY.
assert_ci_flags "docs-only PR (main repo, stable exists)" \
"run_tests=false
docker_build=false
run_unit_tests=false
run_build=false
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=false DOCS_ONLY=true BINARY_CACHE_HIT=false STABLE_EXISTS=true REF_NAME=docs-update

# --- Scenario: Full cache hit + stable image exists ---------------------------
# Binary hasn't changed and stable image already exists — maximum skip path.
assert_ci_flags "full cache hit + stable exists (main repo)" \
"run_tests=false
docker_build=false
run_unit_tests=false
run_build=false
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=true REF_NAME=feature-branch

# --- Scenario: Cache hit but no stable image ----------------------------------
# Binary is cached but stable tag is missing: need docker build + e2e + tag.
assert_ci_flags "cache hit, no stable image (main repo)" \
"run_tests=true
docker_build=true
run_unit_tests=false
run_build=true
run_e2e=true
tag_stable=true
promote=false" \
  FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=false REF_NAME=feature-branch

# --- Scenario: No cache hit but stable image exists ---------------------------
# Code changed (cache miss) but stable already exists — run tests and build
# but skip tagging stable.
assert_ci_flags "no cache hit, stable exists (main repo)" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=true
tag_stable=false
promote=false" \
  FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=true REF_NAME=feature-branch

# --- Scenario: Forked PR (non-docs) ------------------------------------------
# Fork contributions: build docker for validation, run unit tests, but no e2e
# or stable tagging (no registry access).
assert_ci_flags "forked PR (non-docs)" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=true DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=fork-feature

# --- Scenario: Forked PR (docs-only) -----------------------------------------
# Fork PR that only touches docs — everything skipped.
assert_ci_flags "forked PR (docs-only)" \
"run_tests=false
docker_build=false
run_unit_tests=false
run_build=false
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=true DOCS_ONLY=true BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=fork-docs

# --- Scenario: Force rebuild on main -----------------------------------------
# Manual workflow_dispatch with force=true on main: everything runs + promote.
assert_ci_flags "force rebuild on main" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=true
tag_stable=true
promote=true" \
  FORCE=true FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=main

# --- Scenario: Force on release branch ----------------------------------------
# Force rebuild on a release branch: triggers promotion.
assert_ci_flags "force rebuild on release branch" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=true
tag_stable=true
promote=true" \
  FORCE=true FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=release-4.1

# --- Scenario: Force on feature branch ----------------------------------------
# Force rebuild on a non-release branch: no promotion.
assert_ci_flags "force rebuild on feature branch" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=true
tag_stable=true
promote=false" \
  FORCE=true FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=my-feature

# --- Scenario: Force with full cache (override) -------------------------------
# Force overrides docker_build and run_unit_tests, but get_run_tests still
# respects cache+stable (returns false). run_e2e is true via docker_build.
assert_ci_flags "force overrides full cache" \
"run_tests=false
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=true
tag_stable=false
promote=true" \
  FORCE=true FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=true REF_NAME=main

# --- Scenario: workflow_dispatch run_tests=false ------------------------------
# Operator explicitly disabled tests but docker build still needed (no cache).
# run_e2e is true because docker_build is true (no cache hit).
assert_ci_flags "workflow_dispatch run_tests=false (no cache)" \
"run_tests=false
docker_build=true
run_unit_tests=false
run_build=true
run_e2e=true
tag_stable=true
promote=false" \
  RUN_TESTS_INPUT=false FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=main

# --- Scenario: workflow_dispatch run_tests=false + cache hit -------------------
# Tests disabled and binary cached but no stable image — docker build needed,
# so run_e2e is true (docker_build drives it).
assert_ci_flags "workflow_dispatch run_tests=false + cache hit, no stable" \
"run_tests=false
docker_build=true
run_unit_tests=false
run_build=true
run_e2e=true
tag_stable=true
promote=false" \
  RUN_TESTS_INPUT=false FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=false REF_NAME=main

# --- Scenario: workflow_dispatch run_tests=false + everything cached -----------
# Tests disabled and both binary and stable exist — minimal work.
assert_ci_flags "workflow_dispatch run_tests=false + full cache" \
"run_tests=false
docker_build=false
run_unit_tests=false
run_build=false
run_e2e=false
tag_stable=false
promote=false" \
  RUN_TESTS_INPUT=false FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=true REF_NAME=main

# --- Scenario: Merge queue (main repo, fresh) ---------------------------------
# merge_group event behaves like a normal PR on the main repo.
assert_ci_flags "merge queue event (main repo, fresh)" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_build=true
run_e2e=true
tag_stable=true
promote=false" \
  FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=gh-readonly-queue/main/pr-123

# =============================================================================

if [ "$fail" -eq 0 ]; then
  printf '%b✓ all %d tests passed%b\n' "$C_PASS" "$pass" "$C_OFF"
else
  printf '%b✗ %d of %d tests failed%b\n' "$C_FAIL" "$fail" "$((pass + fail))" "$C_OFF"
fi
[ "$fail" -eq 0 ]
