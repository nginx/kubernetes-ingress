#!/usr/bin/env bash
#
# ci-preview.sh -- preview which .github/workflows/ci.yml jobs would run for
# a given scenario, without pushing a branch.
#
# The gate expressions in ci.yml all resolve to the flag outputs computed by
# .github/scripts/variables.sh in the `checks` job. This script sources the
# same variables.sh, evaluates the flags for a scenario, and prints a table
# mapping each ci.yml job to RUN / SKIP with the exact reason.
#
# Usage:
#   .github/scripts/ci-preview.sh [--current] [--scenario <preset>] [flags...]
#
# Auto-detect mode (recommended default):
#   --current           infer DOCS_ONLY (git diff), REF_NAME (current branch),
#                       FORKED (false), CACHE_HIT/STABLE_EXISTS (pessimistic
#                       defaults; override with the individual flags below).
#   --base <ref>        base ref to diff against for --current
#                       (default: origin/main, fallback main, fallback HEAD^)
#
# Scenario presets (each is a shorthand for a full input combination):
#   normal            fresh PR, no cache / stable, main repo, feature branch
#   docs-only         PR touching only *.md / docs/ / examples/
#   up-to-date        cache hit + stable image exists (fast path)
#   cache-only        cache hit but stable image missing
#   stable-only       stable image exists but binary cache miss (eviction fast path)
#   forked            PR from a fork (no auth to registry)
#   forked-docs       PR from a fork touching only docs
#   force-main        workflow_dispatch force=true on main
#   force-release     workflow_dispatch force=true on release-4.0
#   force-feature     workflow_dispatch force=true on feature branch
#   run-tests-false   workflow_dispatch run_tests=false (build only, no tests)
#   merge-queue       merge_group event on main
#
# Overrides (any preset value can be overridden by an explicit flag):
#   --event <e>          pull_request | merge_group | workflow_dispatch
#   --force <bool>       workflow_dispatch force input
#   --run-tests <bool>   workflow_dispatch run_tests input
#   --docs-only <bool>   only documentation changed
#   --forked <bool>      PR/run is from a fork
#   --cache-hit <bool>   Go binary cache hit
#   --stable-exists <bool>  stable image exists in registry
#   --ref-name <name>    github.ref_name (branch or ref name)
#
# Options:
#   --with-act        additionally run `act -l` for cross-reference
#   --json            emit the flag values as JSON only (no table)
#   --no-color        disable ANSI colours (also honours NO_COLOR)
#   -h, --help        show this help
#
# Exit status: 0 (always). This is a preview tool; it does not fail based on
# the outcome of any single job.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/variables.sh"

# ---------------------------------------------------------------------------
# Defaults & colours
# ---------------------------------------------------------------------------
EVENT="pull_request"
FORCE_INPUT=""            # workflow_dispatch only
RUN_TESTS_INPUT_ARG=""    # workflow_dispatch only
DOCS_ONLY_ARG="false"
FORKED_ARG="false"
CACHE_HIT_ARG="false"
STABLE_EXISTS_ARG="false"
REF_NAME_ARG="my-feature-branch"
WITH_ACT=0
JSON_ONLY=0
SCENARIO=""
CURRENT_MODE=0
BASE_REF=""
DETECTED_INFO=""
# Track which flags the user set explicitly so --current does not clobber them.
EXPLICIT_DOCS_ONLY=0
EXPLICIT_FORKED=0
EXPLICIT_REF_NAME=0

# Colours (disabled when stdout is not a tty or NO_COLOR is set).
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RUN=$'\033[0;32m' C_SKIP=$'\033[0;33m' C_DIM=$'\033[0;90m' C_BOLD=$'\033[1m' C_OFF=$'\033[0m'
else
  C_RUN='' C_SKIP='' C_DIM='' C_BOLD='' C_OFF=''
fi

usage() {
  sed -n '2,55p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

apply_scenario() {
  case "$1" in
  normal)
    EVENT="pull_request"; DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="feature-branch"
    ;;
  docs-only)
    EVENT="pull_request"; DOCS_ONLY_ARG="true"; FORKED_ARG="false"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="docs-update"
    ;;
  up-to-date)
    EVENT="pull_request"; DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="true"; STABLE_EXISTS_ARG="true"; REF_NAME_ARG="feature-branch"
    ;;
  cache-only)
    EVENT="pull_request"; DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="true"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="feature-branch"
    ;;
  stable-only)
    EVENT="pull_request"; DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="true"; REF_NAME_ARG="feature-branch"
    ;;
  forked)
    EVENT="pull_request"; DOCS_ONLY_ARG="false"; FORKED_ARG="true"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="feature-branch"
    ;;
  forked-docs)
    EVENT="pull_request"; DOCS_ONLY_ARG="true"; FORKED_ARG="true"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="docs-update"
    ;;
  force-main)
    EVENT="workflow_dispatch"; FORCE_INPUT="true"; RUN_TESTS_INPUT_ARG="true"
    DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="true"; STABLE_EXISTS_ARG="true"; REF_NAME_ARG="main"
    ;;
  force-release)
    EVENT="workflow_dispatch"; FORCE_INPUT="true"; RUN_TESTS_INPUT_ARG="true"
    DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="true"; STABLE_EXISTS_ARG="true"; REF_NAME_ARG="release-4.0"
    ;;
  force-feature)
    EVENT="workflow_dispatch"; FORCE_INPUT="true"; RUN_TESTS_INPUT_ARG="true"
    DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="my-feature"
    ;;
  run-tests-false)
    EVENT="workflow_dispatch"; FORCE_INPUT="false"; RUN_TESTS_INPUT_ARG="false"
    DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="feature-branch"
    ;;
  merge-queue)
    EVENT="merge_group"; DOCS_ONLY_ARG="false"; FORKED_ARG="false"
    CACHE_HIT_ARG="false"; STABLE_EXISTS_ARG="false"; REF_NAME_ARG="main"
    ;;
  *)
    echo "unknown scenario: $1" >&2
    echo "known: normal docs-only up-to-date cache-only stable-only forked forked-docs force-main force-release force-feature run-tests-false merge-queue" >&2
    exit 2
    ;;
  esac
}

# apply_current -- infer scenario from the current git working tree.
# Sets: EVENT=pull_request, DOCS_ONLY_ARG from `variables.sh docs_only`,
# REF_NAME_ARG from `git branch --show-current`, FORKED_ARG=false.
# CACHE_HIT_ARG / STABLE_EXISTS_ARG stay pessimistic ("false") unless the
# user overrides them, because we can't reach the registry / GHA cache from
# a local shell.
apply_current() {
  local repo_root branch base
  repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "not inside a git repo; --current requires a git working tree" >&2
    exit 2
  }
  branch=$(git -C "$repo_root" branch --show-current 2>/dev/null)
  [ -z "$branch" ] && branch="HEAD-detached"

  # Pick a base for the diff: explicit --base first, then origin/main, then
  # main, then HEAD^ as a last resort.
  if [ -n "$BASE_REF" ]; then
    base="$BASE_REF"
  elif git -C "$repo_root" rev-parse --verify --quiet origin/main >/dev/null; then
    base="origin/main"
  elif git -C "$repo_root" rev-parse --verify --quiet main >/dev/null; then
    base="main"
  else
    base="HEAD^"
  fi

  # Convert "origin/main" -> "main" for GITHUB_BASE_REF (variables.sh prepends
  # "origin/" itself). For non-remote refs, use HEAD^-style range directly.
  local base_short docs_only
  case "$base" in
  origin/*) base_short="${base#origin/}" ;;
  *)        base_short="$base" ;;
  esac

  # Run get_docs_only in the repo root so its `git diff` sees the right tree.
  # Force non-interactive git so a missing SSH agent / passphrase-protected key
  # does not block the preview (variables.sh already has `|| true` on failure).
  docs_only=$(
    cd "$repo_root" &&
      env -i PATH="$PATH" HOME="$HOME" \
        GIT_TERMINAL_PROMPT=0 \
        GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new" \
        GITHUB_BASE_REF="$base_short" \
        bash -c "source '$SCRIPT_DIR/variables.sh' && get_docs_only" |
      awk -F= '/^docs_only=/ { print $2 }'
  )
  [ -z "$docs_only" ] && docs_only="false"

  EVENT="pull_request"
  DOCS_ONLY_ARG="$docs_only"
  FORKED_ARG="false"
  REF_NAME_ARG="$branch"
  # CACHE_HIT_ARG / STABLE_EXISTS_ARG keep their defaults (false); a subsequent
  # explicit flag can override.

  DETECTED_INFO="branch=$branch base=$base docs_only=$docs_only"
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
  --current) CURRENT_MODE=1; shift ;;
  --base) BASE_REF="$2"; shift 2 ;;
  --scenario) SCENARIO="$2"; apply_scenario "$2"; shift 2 ;;
  --event) EVENT="$2"; shift 2 ;;
  --force) FORCE_INPUT="$2"; shift 2 ;;
  --run-tests) RUN_TESTS_INPUT_ARG="$2"; shift 2 ;;
  --docs-only) DOCS_ONLY_ARG="$2"; EXPLICIT_DOCS_ONLY=1; shift 2 ;;
  --forked) FORKED_ARG="$2"; EXPLICIT_FORKED=1; shift 2 ;;
  --cache-hit) CACHE_HIT_ARG="$2"; shift 2 ;;
  --stable-exists) STABLE_EXISTS_ARG="$2"; shift 2 ;;
  --ref-name) REF_NAME_ARG="$2"; EXPLICIT_REF_NAME=1; shift 2 ;;
  --with-act) WITH_ACT=1; shift ;;
  --json) JSON_ONLY=1; shift ;;
  --no-color) C_RUN='' C_SKIP='' C_DIM='' C_BOLD='' C_OFF=''; shift ;;
  -h | --help) usage 0 ;;
  *) echo "unknown flag: $1" >&2; usage 2 ;;
  esac
done

# --current runs *after* arg parsing so any explicit overrides (tracked by
# the EXPLICIT_* flags) win over the auto-detected values.
if [ "$CURRENT_MODE" -eq 1 ]; then
  __user_docs_only="$DOCS_ONLY_ARG"
  __user_forked="$FORKED_ARG"
  __user_ref_name="$REF_NAME_ARG"
  apply_current
  [ "$EXPLICIT_DOCS_ONLY" -eq 1 ] && DOCS_ONLY_ARG="$__user_docs_only"
  [ "$EXPLICIT_FORKED" -eq 1 ] && FORKED_ARG="$__user_forked"
  [ "$EXPLICIT_REF_NAME" -eq 1 ] && REF_NAME_ARG="$__user_ref_name"
fi

# workflow_dispatch defaults mirror the ci.yml input defaults so a user only
# has to pass --force / --run-tests when overriding them.
if [ "$EVENT" = "workflow_dispatch" ]; then
  [ -z "$FORCE_INPUT" ] && FORCE_INPUT="false"
  [ -z "$RUN_TESTS_INPUT_ARG" ] && RUN_TESTS_INPUT_ARG="true"
fi

# ---------------------------------------------------------------------------
# Compute flags via variables.sh (single source of truth)
# ---------------------------------------------------------------------------
# ci.yml treats docs_only=true only for pull_request / merge_group events
# (workflow_dispatch always exercises the full pipeline). Mirror that here.
effective_docs_only="$DOCS_ONLY_ARG"
if [ "$EVENT" = "workflow_dispatch" ]; then
  effective_docs_only="false"
fi

FLAGS=$(env -i \
  FORCE="$FORCE_INPUT" \
  RUN_TESTS_INPUT="$RUN_TESTS_INPUT_ARG" \
  DOCS_ONLY="$effective_docs_only" \
  FORKED="$FORKED_ARG" \
  BINARY_CACHE_HIT="$CACHE_HIT_ARG" \
  STABLE_EXISTS="$STABLE_EXISTS_ARG" \
  REF_NAME="$REF_NAME_ARG" \
  bash -c "source '$SCRIPT_DIR/variables.sh'; get_ci_flags")

flag() {
  # extract "<key>=<value>" from the ci_flags output; returns the value only.
  echo "$FLAGS" | awk -F= -v k="$1" '$1 == k { print $2 }'
}

RUN_TESTS=$(flag run_tests)
DOCKER_BUILD=$(flag docker_build)
RUN_UNIT_TESTS=$(flag run_unit_tests)
RUN_E2E=$(flag run_e2e)
TAG_STABLE=$(flag tag_stable)
PROMOTE=$(flag promote)

# ---------------------------------------------------------------------------
# JSON output (for scripting / CI cross-checks)
# ---------------------------------------------------------------------------
if [ "$JSON_ONLY" -eq 1 ]; then
  scenario_label="${SCENARIO:-custom}"
  [ "$CURRENT_MODE" -eq 1 ] && [ -z "$SCENARIO" ] && scenario_label="current"
  cat <<EOF
{
  "scenario":         "$scenario_label",
  "detected":         "${DETECTED_INFO}",
  "event":            "$EVENT",
  "inputs": {
    "force":          "$FORCE_INPUT",
    "run_tests":      "$RUN_TESTS_INPUT_ARG",
    "docs_only":      "$effective_docs_only",
    "forked":         "$FORKED_ARG",
    "cache_hit":      "$CACHE_HIT_ARG",
    "stable_exists":  "$STABLE_EXISTS_ARG",
    "ref_name":       "$REF_NAME_ARG"
  },
  "flags": {
    "run_tests":      "$RUN_TESTS",
    "docker_build":   "$DOCKER_BUILD",
    "run_unit_tests": "$RUN_UNIT_TESTS",
    "run_e2e":        "$RUN_E2E",
    "tag_stable":     "$TAG_STABLE",
    "promote":        "$PROMOTE"
  }
}
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# Pretty-printed scenario + flags
# ---------------------------------------------------------------------------
printf '\n%bScenario%b: %s\n' "$C_BOLD" "$C_OFF" \
  "${SCENARIO:-${CURRENT_MODE:+current}}${SCENARIO:+}"
if [ "$CURRENT_MODE" -eq 1 ]; then
  printf '  %bdetected%b: %s\n' "$C_DIM" "$C_OFF" "$DETECTED_INFO"
  printf '  %bnote%b: cache_hit / stable_exists cannot be checked locally; assumed false (worst case).\n' \
    "$C_DIM" "$C_OFF"
  printf '        %boverride with --cache-hit true --stable-exists true to see the optimistic case.%b\n' \
    "$C_DIM" "$C_OFF"
fi
printf '  event=%s ref_name=%s\n' "$EVENT" "$REF_NAME_ARG"
printf '  force=%s run_tests_input=%s docs_only=%s forked=%s cache_hit=%s stable_exists=%s\n' \
  "${FORCE_INPUT:-<n/a>}" "${RUN_TESTS_INPUT_ARG:-<n/a>}" "$effective_docs_only" \
  "$FORKED_ARG" "$CACHE_HIT_ARG" "$STABLE_EXISTS_ARG"

printf '\n%bComputed flags%b:\n' "$C_BOLD" "$C_OFF"
printf '  run_tests=%s docker_build=%s run_unit_tests=%s run_e2e=%s tag_stable=%s promote=%s\n' \
  "$RUN_TESTS" "$DOCKER_BUILD" "$RUN_UNIT_TESTS" "$RUN_E2E" "$TAG_STABLE" "$PROMOTE"

# ---------------------------------------------------------------------------
# Job-by-job decisions
# ---------------------------------------------------------------------------
# Each row: <job> | <would-run bool> | <reason>. The would-run column mirrors
# the exact `if:` conditions in .github/workflows/ci.yml (plus the runtime
# needs.*.result guards where they matter for correctness).
row() {
  local job="$1" run="$2" reason="$3"
  local marker colour
  if [ "$run" = "true" ]; then
    marker="RUN " colour="$C_RUN"
  else
    marker="SKIP" colour="$C_SKIP"
  fi
  printf '  %b%s%b  %-26s %b%s%b\n' \
    "$colour" "$marker" "$C_OFF" "$job" "$C_DIM" "$reason" "$C_OFF"
}

# helper: e2e-authenticated jobs share a gate.
e2e_auth() {
  if [ "$RUN_E2E" = "true" ] && [ "$FORKED_ARG" != "true" ]; then
    echo "true|run_e2e=true, not forked"
  elif [ "$RUN_E2E" != "true" ]; then
    echo "false|run_e2e=false"
  else
    echo "false|run_e2e=true but forked (no GCR auth)"
  fi
}
e2e_gate="$(e2e_auth)"; e2e_run="${e2e_gate%%|*}"; e2e_reason="${e2e_gate#*|}"

printf '\n%bJobs%b:\n' "$C_BOLD" "$C_OFF"

row checks                   true  "always (repository guard only)"

if [ "$RUN_UNIT_TESTS" = "true" ]; then
  row verify-codegen         true  "run_unit_tests=true"
  row unit-tests             true  "run_unit_tests=true"
  row staticcheck            true  "run_unit_tests=true"
  row govulncheck            true  "run_unit_tests=true"
else
  row verify-codegen         false "run_unit_tests=false"
  row unit-tests             false "run_unit_tests=false"
  row staticcheck            false "run_unit_tests=false"
  row govulncheck            false "run_unit_tests=false"
fi

if [ "$DOCKER_BUILD" = "true" ]; then
  row build-artifacts        true  "docker_build=true"
else
  row build-artifacts        false "docker_build=false"
fi

row tag-target               "$e2e_run" "$e2e_reason"
row package-tests            "$e2e_run" "$e2e_reason"
row helm-tests               "$e2e_run" "$e2e_reason"
row setup-matrix             "$e2e_run" "$e2e_reason"
row smoke-tests-oss          "$e2e_run" "$e2e_reason"
row smoke-tests-plus         "$e2e_run" "$e2e_reason"
row smoke-tests-nap          "$e2e_run" "$e2e_reason"

if [ "$TAG_STABLE" = "true" ]; then
  row tag-stable             true  "tag_stable=true"
else
  reason="tag_stable=false"
  if [ "$FORKED_ARG" = "true" ]; then reason="tag_stable=false (forked)"; fi
  if [ "$STABLE_EXISTS_ARG" = "true" ] && [ "$FORCE_INPUT" != "true" ]; then reason="tag_stable=false (stable already exists)"; fi
  if [ "$RUN_E2E" != "true" ]; then reason="tag_stable=false (run_e2e=false)"; fi
  row tag-stable             false "$reason"
fi

# final-results runs unless the whole workflow is cancelled; it aggregates.
row final-results            true  "always (!cancelled())"

if [ "$PROMOTE" = "true" ]; then
  row trigger-image-promotion true  "promote=true (force on main/release-*)"
else
  row trigger-image-promotion false "promote=false"
fi

# ---------------------------------------------------------------------------
# Optional: cross-reference with `act -l`
# ---------------------------------------------------------------------------
if [ "$WITH_ACT" -eq 1 ]; then
  if ! command -v act >/dev/null 2>&1; then
    printf '\n%bact not installed; skipping --with-act%b\n' "$C_DIM" "$C_OFF"
  else
    printf '\n%bact -l (all jobs, no gate evaluation)%b:\n' "$C_BOLD" "$C_OFF"
    ( cd "$(git rev-parse --show-toplevel)" && act "$EVENT" -W .github/workflows/ci.yml -l 2>/dev/null ) || true
  fi
fi

echo
