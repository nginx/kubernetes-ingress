#!/usr/bin/env bash
# Tear down the OIDC Native example
set -euo pipefail

echo "==> Removing webapp and VirtualServers..."
kubectl delete -f virtual-server.yaml --ignore-not-found
kubectl delete -f virtual-server-idp.yaml --ignore-not-found
kubectl delete -f webapp.yaml --ignore-not-found
kubectl delete -f oidc-native-policy.yaml --ignore-not-found
kubectl delete secret oidcnative-secret --ignore-not-found

echo "==> Removing Keycloak and DNS..."
kubectl delete -f keycloak.yaml --ignore-not-found

echo "==> Removing OIDC DNS resolver..."
kubectl delete deployment oidc-dns -n keycloak --ignore-not-found
kubectl delete service oidc-dns -n keycloak --ignore-not-found
kubectl delete configmap oidc-dns-config -n keycloak --ignore-not-found
kubectl delete namespace keycloak --ignore-not-found

echo "==> Done. Remember to restore your nginx-config ConfigMap resolver-addresses if needed."
