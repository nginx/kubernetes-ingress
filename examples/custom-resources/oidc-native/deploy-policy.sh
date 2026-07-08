#!/usr/bin/env bash
# Deploy the OIDC policy and VirtualServer after Keycloak is configured.
# Usage: CLIENT_SECRET=<your-secret> ./deploy-policy.sh
set -euo pipefail

if [[ -z "${CLIENT_SECRET:-}" ]]; then
  echo "Usage: CLIENT_SECRET=<keycloak-client-secret> ./deploy-policy.sh"
  exit 1
fi

WEBAPP_HOST="${WEBAPP_HOST:-webapp.example.com}"

echo "==> Creating OIDC client secret..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: oidcnative-secret
type: nginx.org/oidc
stringData:
  client-secret: "${CLIENT_SECRET}"
EOF

echo "==> Deploying OIDCNative policy..."
kubectl apply -f oidc-native-policy.yaml

echo "==> Deploying VirtualServer for webapp (${WEBAPP_HOST})..."
kubectl apply -f virtual-server.yaml

echo ""
echo "==> Done! Open https://${WEBAPP_HOST} in your browser."
echo "    You should be redirected to Keycloak to log in."
echo ""
