#!/usr/bin/env bash
# Manual test runner for OIDCNative placement, coexistence, and error scenarios.
#
# Usage:
#   ./run-test.sh <NN>              Apply test manifest NN
#   ./run-test.sh <NN> check        Apply + show generated NGINX config
#   ./run-test.sh clean             Remove all test resources
#   ./run-test.sh list              Show all scenarios
#
# Assumes the base example (Keycloak, webapp, oidcnative-policy, client-secret,
# tls-secret) is already deployed per ../README.md, and that hostnames in the
# manifests have been sed-substituted the same way (webapp.example.com and
# keycloak.example.com -> your nip.io names).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR"

NIC_POD=$(kubectl get pods -A -l app.kubernetes.io/name=nginx-ingress -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
NIC_NS=$(kubectl get pods -A -l app.kubernetes.io/name=nginx-ingress -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)

check_config() {
  [[ -z "${NIC_POD}" ]] && { echo "(NGINX Ingress pod not found)"; return; }
  echo ""
  echo "--- oidc_provider blocks ---"
  kubectl exec -n "$NIC_NS" "$NIC_POD" -- nginx -T 2>/dev/null | grep -A15 "oidc_provider " || echo "(none)"
  echo ""
  echo "--- auth_oidc directives ---"
  kubectl exec -n "$NIC_NS" "$NIC_POD" -- nginx -T 2>/dev/null | grep "auth_oidc " || echo "(none)"
  echo ""
  echo "--- nginx -t ---"
  kubectl exec -n "$NIC_NS" "$NIC_POD" -- nginx -t 2>&1
}

cleanup() {
  echo "Removing test VirtualServers, VSRs, extra Policies and Secrets..."
  kubectl get vs -o name 2>/dev/null | grep -vE '/(keycloak)$' | xargs -r kubectl delete --ignore-not-found 2>/dev/null || true
  kubectl delete vsr webapp-vsr --ignore-not-found 2>/dev/null || true
  kubectl delete policy oidcnative-policy-2 oidc-njs-policy \
    test17-policy test18-policy test19-policy test20-policy test21-policy \
    test13-no-issuer test13-no-clientid test13-http-issuer test13-bad-scope test13-bad-redirect \
    test22-both-oidc --ignore-not-found 2>/dev/null || true
  kubectl delete secret test18-wrong-type test20-wrong-ca-type test21-wrong-key --ignore-not-found 2>/dev/null || true
  kubectl delete ns oidc-policies --ignore-not-found 2>/dev/null || true
}

list_tests() {
  ls test-*.yaml | sort
}

TEST="${1:-}"
CHECK="${2:-}"

case "${TEST}" in
  clean)   cleanup ;;
  list)    list_tests ;;
  "")
    echo "Usage: $0 <NN> [check] | clean | list"
    echo ""
    echo "Available scenarios:"
    for f in test-*.yaml; do
      # Grab first non-blank comment line as a short description
      desc=$(awk '/^# /{print substr($0,3); exit}' "$f")
      printf "  %s  %s\n" "${f%.yaml}" "$desc"
    done
    exit 0
    ;;
  *)
    if ! kubectl get policy oidcnative-policy >/dev/null 2>&1; then
      echo "warning: base policy 'oidcnative-policy' not found; re-apply with:" >&2
      echo "  kubectl apply -f ../oidc-native-policy.yaml" >&2
    fi
    FILE=$(ls test-"${TEST}"-*.yaml 2>/dev/null | head -1)
    if [[ -z "${FILE}" ]]; then
      echo "No manifest found for test '${TEST}'." >&2
      exit 1
    fi
    echo "=== Applying ${FILE} ==="
    awk '/^# ?/{sub(/^# ?/,""); print; next} /^[[:space:]]*$/{print; next} {exit}' "${FILE}"
    echo "==="
    # Substitute example.com placeholder hostnames with the exported nip.io
    # names on the fly so users don't have to sed the files first. Falls back
    # to the placeholders if the env vars aren't set.
    sed \
      -e "s/webapp\\.example\\.com/${WEBAPP_HOST:-webapp.example.com}/g" \
      -e "s/keycloak\\.example\\.com/${KEYCLOAK_HOST:-keycloak.example.com}/g" \
      -e "s/app1\\.example\\.com/${APP1_HOST:-app1.example.com}/g" \
      -e "s/app2\\.example\\.com/${APP2_HOST:-app2.example.com}/g" \
      "${FILE}" | kubectl apply -f -
    if [[ "${CHECK}" == "check" ]]; then
      sleep 2
      check_config
    fi
    ;;
esac
