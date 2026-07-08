#!/usr/bin/env bash
# Setup script for OIDC Native Module example with Keycloak
# Usage: ./setup.sh
#
# Prerequisites:
#   - Run `make run` in hack/secrets-gen/ to generate TLS secrets
#   - NIC deployed with -enable-oidc
set -euo pipefail

KEYCLOAK_HOST="${KEYCLOAK_HOST:-keycloak.example.com}"
WEBAPP_HOST="${WEBAPP_HOST:-webapp.example.com}"
KEYCLOAK_NS="keycloak"
NIC_NS="nginx-ingress"
CLIENT_ID="nginx-plus"

echo "==> Applying Keycloak TLS secrets..."
kubectl apply -f keycloak-tls-secret.yaml -n "${KEYCLOAK_NS}" || \
  kubectl create ns "${KEYCLOAK_NS}" && kubectl apply -f keycloak-tls-secret.yaml -n "${KEYCLOAK_NS}"
kubectl apply -f keycloak-ca-secret.yaml

echo "==> Deploying Keycloak to namespace '${KEYCLOAK_NS}'..."
kubectl apply -f keycloak.yaml

echo "==> Waiting for Keycloak to become ready..."
kubectl rollout status deployment/keycloak -n "${KEYCLOAK_NS}" --timeout=180s

KEYCLOAK_IP=$(kubectl get svc keycloak -n "${KEYCLOAK_NS}" -o jsonpath='{.spec.clusterIP}')
echo "    Keycloak ClusterIP: ${KEYCLOAK_IP}"

echo "==> Setting up in-cluster DNS for ${KEYCLOAK_HOST} → ${KEYCLOAK_IP}..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: oidc-dns-config
  namespace: ${KEYCLOAK_NS}
data:
  Corefile: |
    .:53 {
      hosts {
        ${KEYCLOAK_IP} ${KEYCLOAK_HOST}
      }
      forward . /etc/resolv.conf
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oidc-dns
  namespace: ${KEYCLOAK_NS}
  labels:
    app: oidc-dns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: oidc-dns
  template:
    metadata:
      labels:
        app: oidc-dns
    spec:
      containers:
        - name: coredns
          image: coredns/coredns:1.12.0
          args: ["-conf", "/etc/coredns/Corefile"]
          ports:
            - containerPort: 53
              protocol: UDP
            - containerPort: 53
              protocol: TCP
          volumeMounts:
            - name: config
              mountPath: /etc/coredns
      volumes:
        - name: config
          configMap:
            name: oidc-dns-config
---
apiVersion: v1
kind: Service
metadata:
  name: oidc-dns
  namespace: ${KEYCLOAK_NS}
spec:
  selector:
    app: oidc-dns
  ports:
    - port: 53
      protocol: UDP
      name: udp
    - port: 53
      protocol: TCP
      name: tcp
EOF

kubectl rollout status deployment/oidc-dns -n "${KEYCLOAK_NS}" --timeout=60s
OIDC_DNS_IP=$(kubectl get svc oidc-dns -n "${KEYCLOAK_NS}" -o jsonpath='{.spec.clusterIP}')
echo "    OIDC DNS ClusterIP: ${OIDC_DNS_IP}"

echo ""
echo "==> Configure NIC resolver to use OIDC DNS (${OIDC_DNS_IP}):"
echo ""
echo "    If using Helm, upgrade with:"
echo "      --set controller.config.entries.resolver-addresses=${OIDC_DNS_IP}"
echo "      --set controller.config.entries.resolver-valid=5s"
echo ""
echo "    If using manifests, patch your nginx-config ConfigMap:"
echo "      kubectl patch cm nginx-config -n ${NIC_NS} --type merge \\"
echo "        -p '{\"data\":{\"resolver-addresses\":\"${OIDC_DNS_IP}\",\"resolver-valid\":\"5s\"}}'"
echo ""

echo "==> Deploying VirtualServer for Keycloak (${KEYCLOAK_HOST})..."
kubectl apply -f virtual-server-idp.yaml

echo "==> Deploying backend webapp..."
kubectl apply -f webapp.yaml
kubectl apply -f tls-secret.yaml

echo ""
echo "============================================"
echo "  Keycloak is running. Configure it now:"
echo "============================================"
echo ""
echo "  1. Add to /etc/hosts:  <YOUR_NIC_EXTERNAL_IP>  ${KEYCLOAK_HOST} ${WEBAPP_HOST}"
echo ""
echo "  2. Open https://${KEYCLOAK_HOST} and log in:"
echo "     Username: admin"
echo "     Password: admin"
echo ""
echo "  3. Create a client:"
echo "     - Client ID:              ${CLIENT_ID}"
echo "     - Client authentication:  ON"
echo "     - Valid redirect URIs:     https://${WEBAPP_HOST}/oidc_callback"
echo "     - Post logout URIs:       https://${WEBAPP_HOST}/*"
echo ""
echo "  4. Copy the client secret from the Credentials tab, then run:"
echo ""
echo "     CLIENT_SECRET=<paste-secret-here> ./deploy-policy.sh"
echo ""
