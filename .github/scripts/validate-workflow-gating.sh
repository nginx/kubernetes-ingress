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

validate_if_condition() {
  local job_name="$1"
  local cond="$2"

  if [ -z "$cond" ]; then
    echo "  - Job '$job_name' has no 'if:' condition (ungated)."
    return 1
  fi

  # Normalize spaces without stripping quotes
  cond=$(echo "$cond" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')

  local gate_single="github.repository == 'nginx/kubernetes-ingress'"
  local gate_double='github.repository == "nginx/kubernetes-ingress"'

  if [[ "$cond" != *"$gate_single"* && "$cond" != *"$gate_double"* ]]; then
    echo "  - Job '$job_name' does not contain the required repository gate."
    return 1
  fi

  local prev=""
  local simplified="$cond"
  while [[ "$simplified" != "$prev" ]]; do
    prev="$simplified"
    simplified="${simplified//\(\)/}"
    if [[ "$simplified" =~ \(([^()]+)\) ]]; then
      local inner="${BASH_REMATCH[1]}"
      local replacement="()"
      if [[ "$inner" == *"$gate_single"* || "$inner" == *"$gate_double"* || "$inner" == *"GATE"* ]]; then
        replacement="GATE"
      fi
      simplified="${simplified/\($inner\)/$replacement}"
    fi
  done

  # Final cleanup of any empty parentheses
  simplified="${simplified//\(\)/}"

  if [[ "$simplified" != *"$gate_single"* && "$simplified" != *"$gate_double"* && "$simplified" != *"GATE"* ]]; then
    echo "  - Job '$job_name': Gate is missing after simplifying."
    return 1
  fi

  if [[ "$simplified" == *"||"* ]]; then
    echo "  - Job '$job_name' has an ineffectual repository gate because of a top-level '||' operator: '$cond'"
    return 1
  fi

  return 0
}

for file in $workflows; do
  # Extract job names and if conditions (removing internal newlines)
  if ! jobs_data=$($YQ_BIN '.jobs | to_entries | .[] | .key + ":::" + (.value.if // "" | split("\n") | join(" "))' "$file" 2>&1); then
    echo "❌ Error: Failed to parse or evaluate '$file' with yq:"
    echo "   $jobs_data"
    errors=$((errors + 1))
    continue
  fi

  file_has_errors=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    job_name="${line%%:::*}"
    if_cond="${line#*:::}"

    if ! validate_if_condition "$job_name" "$if_cond"; then
      if [ "$file_has_errors" -eq 0 ]; then
        echo "❌ File '$file' has ungated or poorly gated jobs:"
        file_has_errors=1
      fi
      errors=$((errors + 1))
    fi
  done <<< "$jobs_data"
done

if [ "$errors" -ne 0 ]; then
  echo "❌ Workflow validation failed! All public jobs must have strict repository gating."
  exit 1
else
  echo "✅ All public workflows are successfully gated."
  exit 0
fi
