#!/usr/bin/env bash
# Replaces the definitions block of values.schema.json with the Kubernetes definitions,
# so Helm needs no network access to validate values.

set -euo pipefail

SCHEMA=charts/nginx-ingress/values.schema.json

version=$(sed -n 's/^K8S_CLUSTER_VERSION[[:space:]]*?=[[:space:]]*\([^[:space:]]*\).*/\1/p' tests/Makefile)
[ -n "${version}" ] || { echo "K8S_CLUSTER_VERSION not found in tests/Makefile" >&2; exit 1; }

result=$(curl -fsSL "https://raw.githubusercontent.com/nginxinc/kubernetes-json-schema/master/${version}/_definitions.json" |
    jq --slurpfile schema "${SCHEMA}" '. as $k8s | $schema[0] | .definitions = $k8s.definitions')

printf '%s\n' "${result}" > "${SCHEMA}"
