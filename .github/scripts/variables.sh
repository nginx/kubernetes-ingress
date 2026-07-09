#!/usr/bin/env bash

# renovate: datasource=docker depName=kindest/node
K8S_LATEST_VERSION=1.36.1

# NOTE: the *_md5 helpers below deliberately exclude documentation files
# (*.md) so that a docs-only change never alters a build hash and therefore
# never moves the build/stable image tag. This must stay consistent with
# get_docs_only: any path it treats as documentation must not feed these
# hashes, otherwise a "docs-only" PR could compute a stable_tag for an image
# that is never built (see get_tag_stable / STABLE_EXISTS).
get_docker_md5() {
  docker_md5=$(find build .github/data/version.txt internal/configs/njs internal/configs/oidc -type f ! -name "*.md" -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }')
  echo "${docker_md5:0:8}"
}

get_go_code_md5() {
  find . -type f \( -name "*.go" -o -name go.mod -o -name go.sum -o -name "*.tmpl" -o -name "version.txt" \) -not -path "./site*"  -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_tests_md5() {
  find tests perf-tests .github/data/version.txt -type f ! -name "*.md" -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_chart_md5() {
  find charts .github/data/version.txt config/crd/bases -type f ! -name "*.md" -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_actions_md5() {
  exclude_list="$(dirname $0)/exclude_ci_files.txt"
  find_command="find .github -type f ! -name '*.md' -not -path '${exclude_list}'"
  while IFS= read -r file
  do
    find_command+=" -not -path '$file'"
  done < "$exclude_list"

  find_command+=" -exec md5sum {} +"
  eval "$find_command" | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_build_tag() {
  echo "$(get_docker_md5) $(get_go_code_md5)" | md5sum | awk '{ print $1 }'
}

get_stable_tag() {
  echo "$(get_build_tag) $(get_tests_md5) $(get_chart_md5) $(get_actions_md5)" | md5sum | awk '{ print $1 }'
}

get_additional_tag() {
  if [[ ${REF} =~ /merge$ ]]; then
    pr=${REF%*/merge}
    echo "pr-${pr##*/}"
  else
    echo "${REF//\//-}"
  fi
}

get_k8s_latest_version() {
  echo "$K8S_LATEST_VERSION"
}

# Outputs docs_only=true if all changed files (vs. PR/merge base) match doc paths.
# Doc paths include: *.md, docs/**, examples/**, site/**, .github/ISSUE_TEMPLATE/**,
# .github/PULL_REQUEST_TEMPLATE.md, CHANGELOG*, LICENSE, CODEOWNERS.
get_docs_only() {
  local range
  if [ -n "${GITHUB_BASE_REF:-}" ]; then
    # PR or merge_group event: compare against the target branch.
    git fetch --quiet --depth=50 origin "${GITHUB_BASE_REF}" 2>/dev/null || true
    range="origin/${GITHUB_BASE_REF}...HEAD"
  else
    range="HEAD^...HEAD"
  fi
  local diff_output
  if ! diff_output=$(git diff --name-only "${range}" 2>/dev/null); then
    echo "docs_only=false"
    return
  fi
  non_doc_files=$(echo "$diff_output" | grep -Ev '(\.md$|^docs/|^examples/|^site/|^\.github/ISSUE_TEMPLATE/|^\.github/PULL_REQUEST_TEMPLATE\.md$|^CHANGELOG|^LICENSE$|^CODEOWNERS$)' || true)
  if [ -z "$non_doc_files" ]; then
    echo "docs_only=true"
  else
    echo "docs_only=false"
  fi
}

get_lts_tags() {
  git tag --sort=-version:refname | grep -E -- '-lts-r[0-9]+' | awk -F'-r' '!seen[$1]++' | head -n3 | jq -R -s -c 'split("\n")[:-1]'
}

# ---------------------------------------------------------------------------
# CI decision logic.
#
# The functions below centralise the branching logic that used to live as
# inline bash steps and composite `if:` expressions in .github/workflows/ci.yml.
# Each reads its inputs from environment variables (so they are pure and
# testable) and echoes a literal "true" or "false".
#
# Inputs (all optional; unset is treated as empty/false unless noted):
#   FORCE            - workflow_dispatch "force" input.
#   RUN_TESTS_INPUT  - workflow_dispatch "run_tests" input (defaults to true
#                      when empty, e.g. on pull_request / merge_group events).
#   DOCS_ONLY        - "true" when the change only touches documentation.
#   FORKED           - "true" when running from a fork / mirror.
#   BINARY_CACHE_HIT - "true" when the Go binary cache was hit.
#   STABLE_EXISTS    - "true" when a stable image already exists in the registry.
#   REF_NAME         - github.ref_name (used to gate image promotion).
# ---------------------------------------------------------------------------

# Whether a docker image build is required.
get_docker_build() {
  if [ "${FORCE:-}" = "true" ]; then
    echo "true"
  elif [ "${FORKED:-}" = "true" ] && [ "${DOCS_ONLY:-}" != "true" ]; then
    echo "true"
  elif [ "${FORKED:-}" != "true" ] && [ "${DOCS_ONLY:-}" != "true" ] && [ "${BINARY_CACHE_HIT:-}" != "true" ]; then
    echo "true"
  elif [ "${FORKED:-}" != "true" ] && [ "${DOCS_ONLY:-}" != "true" ] && [ "${STABLE_EXISTS:-}" != "true" ]; then
    echo "true"
  else
    echo "false"
  fi
}

# Whether unit/e2e tests should run at all.
get_run_tests() {
  if [ "${RUN_TESTS_INPUT:-}" = "false" ]; then
    echo "false"
  elif [ "${DOCS_ONLY:-}" = "true" ]; then
    echo "false"
  elif [ "${BINARY_CACHE_HIT:-}" = "true" ] && [ "${STABLE_EXISTS:-}" = "true" ]; then
    echo "false"
  else
    echo "true"
  fi
}

# Gate for the Go-only jobs (verify-codegen, unit-tests, staticcheck,
# govulncheck): force, or tests requested without a binary cache hit.
get_run_unit_tests() {
  local run_tests
  run_tests=$(get_run_tests)
  if [ "${FORCE:-}" = "true" ]; then
    echo "true"
  elif [ "$run_tests" = "true" ] && [ "${BINARY_CACHE_HIT:-}" != "true" ]; then
    echo "true"
  else
    echo "false"
  fi
}

# Data-driven part of the build-artifacts gate. The workflow keeps the runtime
# `needs.*.result` / `!cancelled()` checks in YAML and ANDs them with this.
get_run_build() {
  local run_tests docker_build
  run_tests=$(get_run_tests)
  docker_build=$(get_docker_build)
  if [ "${FORCE:-}" = "true" ] || [ "$run_tests" = "true" ] || [ "$docker_build" = "true" ]; then
    echo "true"
  else
    echo "false"
  fi
}

# Gate for the authenticated e2e jobs (tag-target, package-tests, helm-tests,
# setup-matrix, smoke-tests-*): only on the main repo, when there is work to do.
get_run_e2e() {
  local run_tests docker_build
  run_tests=$(get_run_tests)
  docker_build=$(get_docker_build)
  if [ "${FORKED:-}" != "true" ] && { [ "$run_tests" = "true" ] || [ "$docker_build" = "true" ]; }; then
    echo "true"
  else
    echo "false"
  fi
}

# Gate for the tag-stable job. Only tag an image as stable when we actually ran
# the build + e2e cycle (get_run_e2e) AND no stable image exists yet. Requiring
# run_e2e prevents tagging a non-existent image on docs-only / no-build runs,
# and keeps this flag consistent with the jobs tag-stable depends on.
get_tag_stable() {
  local run_e2e
  run_e2e=$(get_run_e2e)
  if [ "$run_e2e" = "true" ] && [ "${STABLE_EXISTS:-}" != "true" ]; then
    echo "true"
  else
    echo "false"
  fi
}

# Gate for image promotion on a forced run of a release-able branch.
get_promote() {
  if [ "${FORCE:-}" = "true" ] && { [ "${REF_NAME:-}" = "main" ] || [[ "${REF_NAME:-}" == release-* ]]; }; then
    echo "true"
  else
    echo "false"
  fi
}

# Emits every CI decision flag as key=value lines for $GITHUB_OUTPUT.
get_ci_flags() {
  echo "run_tests=$(get_run_tests)"
  echo "docker_build=$(get_docker_build)"
  echo "run_unit_tests=$(get_run_unit_tests)"
  echo "run_build=$(get_run_build)"
  echo "run_e2e=$(get_run_e2e)"
  echo "tag_stable=$(get_tag_stable)"
  echo "promote=$(get_promote)"
}

# Dispatches the requested variable/flag. Kept in a function so the script can
# be sourced (e.g. by variables_test.sh) without executing anything.
main() {
  if [ "$1" = "" ]; then
    echo "ERROR: parameter needed"
    exit 2
  fi

  local INPUT=$1
  local ROOTDIR
  ROOTDIR=$(git rev-parse --show-toplevel || echo ".")
  if [ "$PWD" != "$ROOTDIR" ]; then
    # shellcheck disable=SC2164
    cd "$ROOTDIR"
  fi

  case $INPUT in
  docker_md5)
    echo "docker_md5=$(get_docker_md5)"
    ;;

  go_code_md5)
    echo "go_code_md5=$(get_go_code_md5)"
    ;;

  build_tag)
    echo "build_tag=t-$(get_build_tag)"
    ;;

  stable_tag)
    echo "stable_tag=s-$(get_stable_tag)"
    ;;

  additional_tag)
    echo "additional_tag=$(get_additional_tag)"
    ;;

  k8s_latest_version)
    echo "k8s_latest=$(get_k8s_latest_version)"
    ;;

  docs_only)
    get_docs_only
    ;;

  lts_tags)
    echo "lts_tags=$(get_lts_tags)"
    ;;

  ci_flags)
    get_ci_flags
    ;;

  *)
    echo "ERROR: option not found"
    exit 2
    ;;
  esac
}

# Only run the driver when executed directly, not when sourced (e.g. by tests).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
