#!/usr/bin/env bash
#
# Unit tests for validate-workflow-gating.sh.
#
# These test the pure validation logic (validate_if_condition and
# is_single_group) by sourcing the script; the source guard in the script
# prevents main() from running, so yq is not required here.
#
# Run directly: bash .github/scripts/validate-workflow-gating_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/validate-workflow-gating.sh"

# Sourcing the script enables `set -e`; disable it so every assertion runs even
# after an expected failure.
set +e

pass=0
fail=0

GATE_SQ="github.repository == 'nginx/kubernetes-ingress'"
GATE_DQ='github.repository == "nginx/kubernetes-ingress"'

# assert_if <pass|fail> <description> <condition>
assert_if() {
  local want="$1" desc="$2" cond="$3" got
  if validate_if_condition "test-job" "$cond" >/dev/null 2>&1; then
    got="pass"
  else
    got="fail"
  fi
  if [[ "$got" == "$want" ]]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL [validate_if_condition] $desc (want=$want got=$got): '$cond'"
  fi
}

# assert_group <pass|fail> <description> <string>
assert_group() {
  local want="$1" desc="$2" str="$3" got
  if is_single_group "$str" >/dev/null 2>&1; then
    got="pass"
  else
    got="fail"
  fi
  if [[ "$got" == "$want" ]]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL [is_single_group] $desc (want=$want got=$got): '$str'"
  fi
}

# --- validate_if_condition: valid gates ---------------------------------------
assert_if pass "bare gate, single quotes" "$GATE_SQ"
assert_if pass "bare gate, double quotes" "$GATE_DQ"
assert_if pass "gate with simple parenthesised tail" "$GATE_SQ && (!cancelled())"
assert_if pass "gate with nested single group" "$GATE_SQ && (inputs.force && (github.ref_name == 'main' || startsWith(github.ref_name, 'release-')))"
assert_if pass "leading/trailing/extra whitespace normalized" "   $GATE_SQ    &&   (!cancelled())   "
assert_if pass "embedded newline normalized" "$GATE_SQ &&
(!cancelled())"

# --- validate_if_condition: invalid gates -------------------------------------
assert_if fail "empty condition" ""
assert_if fail "whitespace-only condition" "   "
assert_if fail "no gate at all" "!cancelled()"
assert_if fail "gate not first" "foo && $GATE_SQ"
assert_if fail "mismatched quotes" "github.repository == 'nginx/kubernetes-ingress\""
assert_if fail "wrong repository" "github.repository == 'nginx/other-repo'"
assert_if fail "top-level || bypass" "$GATE_SQ && (a) || (b)"
assert_if fail "two separate groups" "$GATE_SQ && (a) && (b)"
assert_if fail "unparenthesised tail" "$GATE_SQ && a"
assert_if fail "unparenthesised tail with ||" "$GATE_SQ && a || b"

# --- is_single_group ----------------------------------------------------------
assert_group pass "single group" "(a)"
assert_group pass "nested groups" "(a && (b || c))"
assert_group pass "double-wrapped" "((a))"
assert_group fail "two top-level groups with ||" "(a) || (b)"
assert_group fail "adjacent groups" "(a)(b)"
assert_group fail "unbalanced open" "(a"
assert_group fail "unbalanced close" "a)"
assert_group fail "no parentheses" "a"
assert_group fail "empty string" ""

echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
