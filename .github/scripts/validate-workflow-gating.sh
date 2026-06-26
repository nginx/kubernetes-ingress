#!/usr/bin/env bash
set -euo pipefail

# Find all workflow files, excluding mirror-specific ones
workflows=$(find .github/workflows -maxdepth 1 \( -name "*.yml" -o -name "*.yaml" \) | grep -v "mirror-")

# Determine which yq binary to use
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
  # Run yq directly to find any jobs missing repository gating
  failed_jobs=$($YQ_BIN '
    select(.jobs != null) |
    .jobs |
    with_entries(select(
      .value.if == null or
      ((.value.if | (contains("nginx/kubernetes-ingress") or contains("github.repository_owner"))) | not)
    )) |
    keys |
    .[]
  ' "$file" 2>/dev/null || true)

  if [ -n "$failed_jobs" ]; then
    echo "❌ File '$file' has ungated jobs:"
    # Indent and display each failed job
    echo "$failed_jobs" | sed 's/^/  - Job: /'
    errors=$((errors + 1))
  fi
done

if [ "$errors" -ne 0 ]; then
  echo "❌ Workflow validation failed! All public jobs must have repository/owner gating."
  exit 1
else
  echo "✅ All public workflows are successfully gated."
  exit 0
fi
