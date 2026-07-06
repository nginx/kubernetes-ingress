#!/usr/bin/env bash
#
# sync-chart.sh
#
# Regenerates operators/openshift/openshift-charts/nginx-ingress from the in-repo NGINX
# Ingress Controller Helm chart (charts/nginx-ingress).
#
# In the standalone nginx-ingress-openshift-operator repo this was done by pulling
# the released chart from the OCI registry. In the monorepo the chart lives in
# the same tree, so we vendor it directly and apply the operator-specific
# modifications:
#   * drop the namespaced/cluster RBAC templates (the operator ships its own
#     RBAC under config/rbac)
#   * pin the ClusterRoleBinding roleRef to the operator-managed ClusterRole
#   * rewrite values.schema.json $ref URLs to the bundled k8s definitions file
#
# Usage: operators/openshift/scripts/sync-chart.sh [K8S_VERSION]
#   K8S_VERSION defaults to the version already bundled under openshift-charts/nginx-ingress/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPERATOR_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${OPERATOR_DIR}/../.." && pwd)"

SRC_CHART="${REPO_ROOT}/charts/nginx-ingress"
DST_CHART="${OPERATOR_DIR}/helm-charts/nginx-ingress"

# Determine the Kubernetes JSON-schema version to reference.
K8S_VERSION="${1:-}"
if [ -z "${K8S_VERSION}" ]; then
  if [ -d "${DST_CHART}" ]; then
    K8S_VERSION="$(basename "$(find "${DST_CHART}" -maxdepth 1 -type d -name 'v*' | head -1)")"
  fi
fi
if [ -z "${K8S_VERSION}" ]; then
  echo "ERROR: could not determine K8S_VERSION; pass it as the first argument (e.g. v1.36.1)" >&2
  exit 1
fi

if [ ! -d "${SRC_CHART}" ]; then
  echo "ERROR: source chart not found at ${SRC_CHART}" >&2
  exit 1
fi

echo "Syncing chart:"
echo "  source:      ${SRC_CHART}"
echo "  destination: ${DST_CHART}"
echo "  k8s schema:  ${K8S_VERSION}"

# Preserve any previously bundled k8s definitions file.
TMP_DEFS=""
if [ -f "${DST_CHART}/${K8S_VERSION}/_definitions.json" ]; then
  TMP_DEFS="$(mktemp)"
  cp "${DST_CHART}/${K8S_VERSION}/_definitions.json" "${TMP_DEFS}"
fi

rm -rf "${DST_CHART}"
mkdir -p "${DST_CHART}"

# Copy the chart, dereferencing the crds symlink and dropping the icon (*.png
# is already excluded by .helmignore, but we do not vendor it).
cp -rL "${SRC_CHART}/." "${DST_CHART}/"
rm -f "${DST_CHART}/chart-icon.png"

# The operator provides its own RBAC via config/rbac.
rm -f "${DST_CHART}/templates/clusterrole.yaml"
rm -f "${DST_CHART}/templates/controller-role.yaml"
rm -f "${DST_CHART}/templates/controller-rolebinding.yaml"

# Point the ClusterRoleBinding at the operator-managed ClusterRole. Only the
# name inside the roleRef block is changed (the metadata name is left intact).
awk '
  /^roleRef:/ { in_roleref = 1 }
  in_roleref && /^  name:/ {
    print "  name: nginx-ingress-operator-nginx-ingress-admin"
    in_roleref = 0
    next
  }
  { print }
' "${DST_CHART}/templates/clusterrolebinding.yaml" > "${DST_CHART}/templates/clusterrolebinding.yaml.tmp"
mv "${DST_CHART}/templates/clusterrolebinding.yaml.tmp" "${DST_CHART}/templates/clusterrolebinding.yaml"

# Rewrite values.schema.json $ref URLs to the locally bundled definitions.
sed -i.bak \
  "s#https://raw.githubusercontent.com/nginxinc/kubernetes-json-schema/master/#file://./helm-charts/nginx-ingress/#g" \
  "${DST_CHART}/values.schema.json"
rm -f "${DST_CHART}/values.schema.json.bak"

# Restore the bundled k8s definitions file.
mkdir -p "${DST_CHART}/${K8S_VERSION}"
if [ -n "${TMP_DEFS}" ]; then
  mv "${TMP_DEFS}" "${DST_CHART}/${K8S_VERSION}/_definitions.json"
else
  echo "WARNING: no bundled ${K8S_VERSION}/_definitions.json found; fetch it from" >&2
  echo "         https://github.com/nginxinc/kubernetes-json-schema and place it at" >&2
  echo "         ${DST_CHART}/${K8S_VERSION}/_definitions.json" >&2
fi

echo "Done. Vendored chart written to ${DST_CHART}"
