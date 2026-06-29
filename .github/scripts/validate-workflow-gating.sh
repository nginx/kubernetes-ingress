#!/usr/bin/env bash
set -euo pipefail

# This is called from the lint-format.yml workflow file.
#
# Purpose of this is to make sure that every job in workflow files that don't start with
# "mirror-" have a gate that only runs them on the main repository (nginx/kubernetes-ingress).
#
# Workflow files starting with "mirror-" will be used in mirror repositories where slightly
# different workflows are needed due to access requirements and different jobs. Separating
# them into different files allows us to keep various branches up to date where we don't need
# to deal with merge conflicts in the workflow files.
workflows=$(find .github/workflows -maxdepth 1 \( -name "*.yml" -o -name "*.yaml" \) ! -name "mirror-*")

# Determine which yq binary to use.
YQ_BIN="yq"
if ! command -v yq &> /dev/null; then
  if [ -f "/tmp/yq" ]; then
    YQ_BIN="/tmp/yq"
  else
    echo "❌ Error: yq is not installed." >&2
    exit 1
  fi
fi

errors=0

for file in $workflows; do
  # 1. Capture yq stderr and exit status; do not suppress failures
  if ! failed_jobs=$($YQ_BIN '
    select(.jobs != null) |
    .jobs |
    with_entries(select(
      .value.if == null or
      ((.value.if | (contains("github.repository == '\''nginx/kubernetes-ingress'\''") or contains("github.repository == \"nginx/kubernetes-ingress\""))) | not)
    )) |
    keys |
    .[]
  ' "$file" 2>&1); then
    echo "❌ Error: Failed to parse or evaluate '$file' with yq:"
    echo "   $failed_jobs"
    errors=$((errors + 1))
    continue
  fi

  # 2. Use a native Bash loop instead of sed (resolves Shellcheck SC2001)
  if [ -n "$failed_jobs" ]; then
    echo "❌ File '$file' has ungated jobs:"
    while IFS= read -r job; do
      [ -n "$job" ] && echo "  - Job: $job"
    done <<< "$failed_jobs"
    errors=$((errors + 1))
  fi
done

if [ "$errors" -ne 0 ]; then
  echo "❌ Workflow validation failed! All public jobs must have strict repository gating."
  exit 1
else
  echo "✅ All public workflows are successfully gated."
  exit 0
fi
