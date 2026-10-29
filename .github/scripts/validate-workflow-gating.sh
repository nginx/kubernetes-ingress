#!/usr/bin/env bash
set -euo pipefail

# This is called from the lint-format.yml workflow file.
#
# Purpose of this is to make sure that every job in workflow files has a gate
# that only runs it on the public repository (nginx/kubernetes-ingress), the
# internal repository (nginx/kubernetes-ingress-internal), or both.
#
# Workflow files are shared between the two repositories under the in-repo twin
# CI model, where each job is gated on `github.repository` rather than split
# across separate workflow files.
#
# A job's `if:` condition is "correctly gated" when it starts with one of these
# repository gates, optionally followed by `&& ( <extra conditions> )`:
#
#     github.repository == 'nginx/kubernetes-ingress'
#     github.repository == 'nginx/kubernetes-ingress-internal'
#     (github.repository == 'nginx/kubernetes-ingress' || github.repository == 'nginx/kubernetes-ingress-internal')
#
# The gate must come first, and any extra conditions must be wrapped in a single
# balanced parenthesis group. GitHub Actions gives `&&` higher precedence than
# `||`, so without the single-group requirement a top-level `||` could bypass the
# gate, e.g. "gate && (a) || (b)" parses as "(gate && (a)) || (b)" and would run
# on a fork/mirror. (Unbalanced parentheses are rejected by GitHub Actions' own
# syntax validation, so we only guard against the balanced-but-bypassing case.)

# Returns 0 only if the entire string is one balanced parenthesis group,
# e.g. "(a && (b || c))". Rejects "(a) || (b)" (the first '(' closes before the
# end) and any unbalanced input.
is_single_group() {
  local s="$1" depth=0 i
  [[ "$s" == "("* ]] || return 1
  for ((i = 0; i < ${#s}; i++)); do
    case "${s:i:1}" in
    "(") depth=$((depth + 1)) ;;
    ")") depth=$((depth - 1)) ;;
    esac
    # Returning to depth 0 before the final char means it is not a single group.
    if ((depth == 0 && i < ${#s} - 1)); then
      return 1
    fi
  done
  ((depth == 0))
}

# Validates a single job's `if:` condition. Prints a message and returns 1 when
# the job is not correctly gated; returns 0 otherwise.
validate_if_condition() {
  local job_name="$1" cond="$2"

  # Normalize all whitespace (including newlines) to single spaces.
  cond=$(printf '%s' "$cond" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')

  if [ -z "$cond" ]; then
    echo "  - Job '$job_name' has no 'if:' condition (ungated)."
    return 1
  fi

  # <gate>  or  <gate> && ( ... ). The alternation forces the quotes to match
  # (there is no mixed '..." branch). Capture group 6 is the optional tail and
  # group 7 is the tail's inner parenthesised content.
  local pub_gate='github\.repository == ('\''nginx/kubernetes-ingress'\''|"nginx/kubernetes-ingress")'
  local int_gate='github\.repository == ('\''nginx/kubernetes-ingress-internal'\''|"nginx/kubernetes-ingress-internal")'
  local dual_gate='\('"${pub_gate}"' \|\| '"${int_gate}"'\)'
  local gate_re='^('"${pub_gate}"'|'"${int_gate}"'|'"${dual_gate}"')( && \((.+)\))?$'
  if [[ ! "$cond" =~ $gate_re ]]; then
    echo "  - Job '$job_name' is not correctly gated: '$cond'"
    echo "    Expected: github.repository == 'nginx/kubernetes-ingress' (or -internal, or dual-repo gate) [ && ( ... ) ]"
    return 1
  fi

  # If there is a parenthesised tail, it must be one balanced group so that a
  # top-level '||' cannot bypass the gate (rejects e.g. "gate && (a) || (b)").
  if [ -n "${BASH_REMATCH[6]}" ] && ! is_single_group "(${BASH_REMATCH[7]})"; then
    echo "  - Job '$job_name' extra conditions must be a single ( ... ) group: '$cond'"
    return 1
  fi

  return 0
}

main() {
  local workflows
  workflows=$(find .github/workflows -maxdepth 1 \( -name "*.yml" -o -name "*.yaml" \) ! \( -name "mirror-*" -o -name "build-oss.yml" -o -name "build-plus.yml" -o -name "build-artifacts.yml" -o -name "publish-helm.yml" \) )

  # Determine which yq binary to use.
  local YQ_BIN="yq"
  if ! command -v yq &>/dev/null; then
    if [ -f "/tmp/yq" ]; then
      YQ_BIN="/tmp/yq"
    else
      echo "❌ Error: yq is not installed." >&2
      exit 1
    fi
  fi

  local errors=0
  local file jobs_data file_has_errors line job_name if_cond

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
    done <<<"$jobs_data"
  done

  if [ "$errors" -ne 0 ]; then
    echo "❌ Workflow validation failed! All public jobs must have strict repository gating."
    exit 1
  else
    echo "✅ All public workflows are successfully gated."
    exit 0
  fi
}

# Only run the driver when executed directly, not when sourced (e.g. by tests).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
