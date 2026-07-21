#!/usr/bin/env bash
#
# Unit tests for the CI decision logic in variables.sh.
#
# These test the pure decision functions (get_run_tests, get_docker_build,
# get_run_unit_tests, get_run_e2e, get_tag_stable, get_promote) by sourcing
# the script; the source guard in the script prevents main() from running,
# so git / the wider environment is not required for those.
#
# They also assert the docs-only hash invariant (get_chart_md5 / get_tests_md5 /
# get_actions_md5 must ignore *.md files, so a docs-only change never moves the
# stable tag). Those cases need a real checkout + coreutils and self-skip if
# unavailable.
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

# assert_ci_flags <description> <expected-multiline> [ENV=VAL ...]
# End-to-end check of the full `ci_flags` output (get_ci_flags) for a scenario,
# comparing every emitted key=value line against <expected-multiline>.
assert_ci_flags() {
  local desc="$1" want="$2"
  shift 2
  local got
  got=$(env -i "$@" bash -c "source '$SCRIPT_DIR/variables.sh'; get_ci_flags")
  if [[ "$got" == "$want" ]]; then
    pass=$((pass + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b✓ PASS%b %-18s %-40s %b[%s]%b\n' \
        "$C_PASS" "$C_OFF" "get_ci_flags" "$desc" "$C_DIM" "$*" "$C_OFF"
    fi
  else
    fail=$((fail + 1))
    printf '%b✗ FAIL%b %-18s %-40s %b[%s]%b\n' \
      "$C_FAIL" "$C_OFF" "get_ci_flags" "$desc" "$C_DIM" "$*" "$C_OFF"
    printf '  want:\n%s\n  got:\n%s\n' \
      "$(printf '%s\n' "$want" | sed 's/^/    /')" \
      "$(printf '%s\n' "$got" | sed 's/^/    /')"
  fi
}

# assert_md_ignored <fn> <hashed-dir> <description>
# Regression guard for the docs / stable-tag coupling: dropping a *.md file into
# a hashed tree must NOT change that tree's build hash, so a docs-only change
# never moves the stable tag. Unlike the pure asserts above this runs the real
# hashing helper, so it needs a checkout + coreutils and self-skips otherwise.
# Everything happens in a subshell (with an EXIT trap) so the temp file and cd
# never leak into the other tests.
assert_md_ignored() {
  local fn="$1" dir="$2" desc="$3" root ok=1
  if ! command -v md5sum >/dev/null 2>&1 || ! command -v find >/dev/null 2>&1 \
    || ! root=$(git rev-parse --show-toplevel 2>/dev/null); then
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b- SKIP%b %-18s %-40s %b[no git/coreutils]%b\n' \
        "$C_DIM" "$C_OFF" "$fn" "$desc" "$C_DIM" "$C_OFF"
    fi
    return
  fi
  (
    cd "$root" || exit 1
    tmp="$dir/.docs_invariant_$$_${RANDOM}.md"
    trap 'rm -f "$tmp"' EXIT
    before=$("$fn" 2>/dev/null)
    printf '# temporary documentation file\n' >"$tmp"
    after=$("$fn" 2>/dev/null)
    [ "$before" = "$after" ]
  ) || ok=0
  if [ "$ok" -eq 1 ]; then
    pass=$((pass + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b✓ PASS%b %-18s %-40s => %-9s %b[+%s/*.md ignored]%b\n' \
        "$C_PASS" "$C_OFF" "$fn" "$desc" "invariant" "$C_DIM" "$dir" "$C_OFF"
    fi
  else
    fail=$((fail + 1))
    printf '%b✗ FAIL%b %-18s %-40s %b[adding %s/*.md changed the hash]%b\n' \
      "$C_FAIL" "$C_OFF" "$fn" "$desc" "$C_DIM" "$dir" "$C_OFF"
  fi
}

# assert_docker_build_equivalence
# Regression guard: the historic `get_run_build` flag was defined as
# (FORCE || run_tests || docker_build). It was removed from variables.sh
# because it is algebraically identical to `docker_build` across every input
# combination -- see the reasoning in variables.sh above `get_docker_build`.
# This test enumerates the full 3^5 = 243 input space (each of FORCE,
# RUN_TESTS_INPUT, DOCS_ONLY, BINARY_CACHE_HIT, STABLE_EXISTS ∈ {true, false, ""})
# and asserts the equivalence still holds, so if anyone reintroduces the flag
# or changes `get_docker_build` / `get_run_tests` in a way that breaks it,
# this test will fail loudly.
assert_docker_build_equivalence() {
  local total=0 mismatches=0 first_fail=""
  local _force _run_tests_input _docs_only _cache _stable
  for _force in true false ""; do
    for _run_tests_input in true false ""; do
      for _docs_only in true false ""; do
        for _cache in true false ""; do
          for _stable in true false ""; do
            local db rb
            db=$(env -i FORCE="$_force" RUN_TESTS_INPUT="$_run_tests_input" \
              DOCS_ONLY="$_docs_only" BINARY_CACHE_HIT="$_cache" STABLE_EXISTS="$_stable" \
              bash -c "source '$SCRIPT_DIR/variables.sh'; get_docker_build")
            rb=$(env -i FORCE="$_force" RUN_TESTS_INPUT="$_run_tests_input" \
              DOCS_ONLY="$_docs_only" BINARY_CACHE_HIT="$_cache" STABLE_EXISTS="$_stable" \
              bash -c "source '$SCRIPT_DIR/variables.sh'; \
                rt=\$(get_run_tests); db=\$(get_docker_build); \
                if [ \"\${FORCE:-}\" = 'true' ] || [ \"\$rt\" = 'true' ] || [ \"\$db\" = 'true' ]; then \
                  echo true; else echo false; fi")
            total=$((total + 1))
            if [ "$db" != "$rb" ]; then
              mismatches=$((mismatches + 1))
              if [ -z "$first_fail" ]; then
                first_fail="FORCE=$_force RUN_TESTS_INPUT=$_run_tests_input DOCS_ONLY=$_docs_only BINARY_CACHE_HIT=$_cache STABLE_EXISTS=$_stable -> docker_build=$db run_build=$rb"
              fi
            fi
          done
        done
      done
    done
  done
  if [ "$mismatches" -eq 0 ]; then
    pass=$((pass + 1))
    if [ "$VERBOSE" -eq 1 ]; then
      printf '%b✓ PASS%b %-18s %-40s => %-5s %b[checked %d combos]%b\n' \
        "$C_PASS" "$C_OFF" "docker_build ≡ (F||rt||db)" "run_build equivalence" \
        "true" "$C_DIM" "$total" "$C_OFF"
    fi
  else
    fail=$((fail + 1))
    printf '%b✗ FAIL%b %-18s %-40s %b[%d/%d mismatches, first: %s]%b\n' \
      "$C_FAIL" "$C_OFF" "docker_build ≡ (F||rt||db)" "run_build equivalence" \
      "$C_DIM" "$mismatches" "$total" "$first_fail" "$C_OFF"
  fi
}

# --- get_run_tests ------------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_run_tests true  "default PR (empty inputs)"
assert_flag get_run_tests false "workflow_dispatch run_tests=false" RUN_TESTS_INPUT=false
assert_flag get_run_tests false "docs-only change"                  DOCS_ONLY=true
assert_flag get_run_tests false "cache hit and stable exists"       BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_run_tests true  "cache hit but no stable image"     BINARY_CACHE_HIT=true STABLE_EXISTS=false
assert_flag get_run_tests false "stable exists (cache miss OK)"     BINARY_CACHE_HIT=false STABLE_EXISTS=true

# --- get_docker_build ---------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_docker_build true  "force always builds"                FORCE=true DOCS_ONLY=true STABLE_EXISTS=true BINARY_CACHE_HIT=true
assert_flag get_docker_build true  "forked non-docs change"             FORKED=true DOCS_ONLY=false
assert_flag get_docker_build false "forked docs-only change"            FORKED=true DOCS_ONLY=true
assert_flag get_docker_build false "main repo, stable exists (cache miss OK)" FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=true
assert_flag get_docker_build true  "main repo, stable missing"          FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=false
assert_flag get_docker_build false "main repo, cache warm + stable"     FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_docker_build false "main repo docs-only"                FORKED=false DOCS_ONLY=true

# --- get_run_unit_tests -------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_run_unit_tests true  "force runs unit tests"           FORCE=true BINARY_CACHE_HIT=true
assert_flag get_run_unit_tests true  "forked non-docs always runs"     FORKED=true DOCS_ONLY=false BINARY_CACHE_HIT=true
assert_flag get_run_unit_tests true  "tests requested, no cache hit"   BINARY_CACHE_HIT=false
assert_flag get_run_unit_tests false "tests requested but cache hit"   BINARY_CACHE_HIT=true STABLE_EXISTS=false
assert_flag get_run_unit_tests false "docs-only skips unit tests"      DOCS_ONLY=true
assert_flag get_run_unit_tests false "cache hit and stable exists"     BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_run_unit_tests false "run_tests_input=false hard skip" RUN_TESTS_INPUT=false BINARY_CACHE_HIT=false
assert_flag get_run_unit_tests false "opt-out beats force"             FORCE=true RUN_TESTS_INPUT=false BINARY_CACHE_HIT=false


# --- get_run_e2e --------------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_run_e2e true  "main repo with work"                    FORKED=false BINARY_CACHE_HIT=false
assert_flag get_run_e2e false "forked non-docs skips authenticated e2e" FORKED=true DOCS_ONLY=false
assert_flag get_run_e2e false "forked docs-only skips e2e"             FORKED=true DOCS_ONLY=true
assert_flag get_run_e2e false "main repo, nothing to do"               FORKED=false DOCS_ONLY=true BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_run_e2e false "run_tests_input=false skips e2e"        RUN_TESTS_INPUT=false BINARY_CACHE_HIT=false STABLE_EXISTS=false
assert_flag get_run_e2e false "opt-out beats docker_build cache-miss"  RUN_TESTS_INPUT=false BINARY_CACHE_HIT=false STABLE_EXISTS=true

# --- get_tag_stable -----------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_tag_stable true  "main repo, built, no stable image"   FORKED=false STABLE_EXISTS=false
assert_flag get_tag_stable false "main repo, stable already exists"    FORKED=false STABLE_EXISTS=true
assert_flag get_tag_stable false "forked never tags stable"            FORKED=true STABLE_EXISTS=false
assert_flag get_tag_stable false "docs-only never tags stable"         FORKED=false DOCS_ONLY=true STABLE_EXISTS=false
assert_flag get_tag_stable false "up-to-date (cache+stable) no tag"    FORKED=false BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_tag_stable true  "force re-tags existing stable"       FORCE=true FORKED=false BINARY_CACHE_HIT=true STABLE_EXISTS=true
assert_flag get_tag_stable false "force on fork still skips"           FORCE=true FORKED=true STABLE_EXISTS=true
assert_flag get_tag_stable false "force with tests opt-out skips"      FORCE=true RUN_TESTS_INPUT=false FORKED=false STABLE_EXISTS=true

# --- get_promote --------------------------------------------------------------
# assert_flag   function | expected | description
assert_flag get_promote true  "force on main"                          FORCE=true REF_NAME=main
assert_flag get_promote true  "force on release branch"                FORCE=true REF_NAME=release-4.0
assert_flag get_promote false "force on feature branch"                FORCE=true REF_NAME=my-feature
assert_flag get_promote false "no force on main"                       FORCE=false REF_NAME=main
assert_flag get_promote false "tests opt-out blocks promotion"         FORCE=true RUN_TESTS_INPUT=false REF_NAME=main

# --- get_ci_flags (end-to-end scenarios) --------------------------------------
# Full `ci_flags` output for the scenarios documented in the CI pipeline. These
# guard the composed behaviour (not just individual functions), e.g. that a
# docs-only PR does NOT tag a stable image.
assert_ci_flags "default PR (main repo, no cache)" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_e2e=true
tag_stable=true
promote=false" \
  FORKED=false REF_NAME=feature-branch

assert_ci_flags "docs-only PR (main repo, no stable)" \
"run_tests=false
docker_build=false
run_unit_tests=false
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=false DOCS_ONLY=true BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=docs-update

assert_ci_flags "up-to-date PR (cache + stable hit)" \
"run_tests=false
docker_build=false
run_unit_tests=false
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=false BINARY_CACHE_HIT=true STABLE_EXISTS=true REF_NAME=feature-branch

assert_ci_flags "forked PR (build unauthenticated, no tag)" \
"run_tests=true
docker_build=true
run_unit_tests=true
run_e2e=false
tag_stable=false
promote=false" \
  FORKED=true DOCS_ONLY=false REF_NAME=feature-branch

assert_ci_flags "force dispatch on main (cache + stable hit, force re-tags)" \
"run_tests=false
docker_build=true
run_unit_tests=true
run_e2e=true
tag_stable=true
promote=true" \
  FORCE=true RUN_TESTS_INPUT=true FORKED=false BINARY_CACHE_HIT=true STABLE_EXISTS=true REF_NAME=main

assert_ci_flags "dispatch run_tests=false (still builds, no e2e, no tag)" \
"run_tests=false
docker_build=true
run_unit_tests=false
run_e2e=false
tag_stable=false
promote=false" \
  FORCE=false RUN_TESTS_INPUT=false FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=false STABLE_EXISTS=false REF_NAME=feature-branch

assert_ci_flags "force dispatch with tests disabled does not promote" \
"run_tests=false
docker_build=true
run_unit_tests=false
run_e2e=false
tag_stable=false
promote=false" \
  FORCE=true RUN_TESTS_INPUT=false FORKED=false DOCS_ONLY=false BINARY_CACHE_HIT=true STABLE_EXISTS=true REF_NAME=main

# --- docs-only hash invariant (regression guard for the stable-tag coupling) ---
# A *.md file under a hashed tree is documentation per get_docs_only, so it must
# not feed the corresponding build hash; otherwise a docs-only PR could compute a
# stable_tag for an image that is never built.
assert_md_ignored get_chart_md5   charts  "chart hash ignores *.md docs"
assert_md_ignored get_tests_md5   tests   "tests hash ignores *.md docs"
assert_md_ignored get_actions_md5 .github "actions hash ignores *.md docs"

# --- run_build removal invariant ---------------------------------------------
# Guards against reintroducing the removed `get_run_build` flag by proving
# `docker_build` is algebraically equivalent to (FORCE || run_tests || docker_build)
# across every input combination.
assert_docker_build_equivalence

if [ "$fail" -eq 0 ]; then
  printf '%b✓ all %d tests passed%b\n' "$C_PASS" "$pass" "$C_OFF"
else
  printf '%b✗ %d of %d tests failed%b\n' "$C_FAIL" "$fail" "$((pass + fail))" "$C_OFF"
fi
[ "$fail" -eq 0 ]
