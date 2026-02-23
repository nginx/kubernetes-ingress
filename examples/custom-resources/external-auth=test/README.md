# External Auth (minimal OAuth2 demo)

This example shows how to protect a route using the OSS pattern auth_request with an external OAuth2 proxy (oauth2-proxy) and Keycloak as the identity provider. It is written in the same step-by-step style as the OIDC example so you can follow it from start to finish once the NGINX Ingress Controller (NIC) is deployed.

Important: this example is for local/dev testing only. Keycloak is configured to serve HTTPS on standard port 443 (container listens on 8443, the Service exposes 443). For production, use CA-signed certificates and secure secret management.

## Assumptions
- You have already installed the NGINX Ingress Controller (NIC) in the cluster.
- Your kubectl context is set to the cluster and the default namespace is `default` or you adjust namespace values in the commands below.

You can check/set the current namespace with:

```shell
kubectl config view --minify | grep namespace
kubectl config set-context --namespace default --current
```

## Prerequisites
1. (Recommended) From the repo root run:

```shell
make secrets
```

This generates example TLS/secrets used by the examples (including `keycloak-tls-secret`). If you prefer to create your own certs, create a TLS secret named `keycloak-tls-secret` in namespace `default` (see next step).

Note: `make secrets` will generate the Keycloak TLS secret manifest and real secret files under `common-secrets/` and create a symlink at `examples/custom-resources/external-auth/keycloak-tls-secret.yaml`. Running `make secrets` is sufficient to provide the `keycloak-tls-secret` used by this example.

After running `make secrets`, apply the generated Keycloak TLS secret to the cluster before deploying Keycloak:

```shell
# Apply the generated TLS secret for Keycloak
kubectl -n default apply -f examples/custom-resources/external-auth=test/keycloak-tls-secret.yaml
```

Notes:
- `make secrets` will write YAML files into `common-secrets/` and create symlinks into example folders; it does not automatically apply them to the cluster.
- The top-level `Makefile` runs `hack/secrets-gen` and will invoke `go run` if you have Go installed; otherwise the Make target runs inside a Docker container so you don't need Go locally.

2. Ensure the cluster is running NIC and that NIC HTTPS port is reachable (example uses port 443 for ingress; we test Keycloak locally via port-forwarding).

## Overview of files in this example
- `keycloak.yaml` — Keycloak Deployment + Service (HTTPS on 8443, mounts `keycloak-tls-secret`).
- `keycloak-realm.json` — Keycloak realm JSON used to create the `example` realm (clients + users) via the Admin API.
- `oauth2-proxy.yaml` — oauth2-proxy Deployment + Service (reads client secret from `/etc/secrets/client-secret` and cookie secret from `oauth2-proxy-cookie-secret`).
- `backend.yaml` — simple httpbin backend Service + Deployment.
- `policy-external-auth.yaml` — `Policy` with `spec.externalAuth.proxyPass` pointing to oauth2-proxy.
- `virtualserver-external-auth.yaml` — `VirtualServer` referencing the policy and protecting `/private/`.

## Step 1 — Deploy Keycloak

Apply the Keycloak Service and Deployment (the Service exposes HTTP on port 80 and HTTPS on port 443):

```shell
kubectl -n default apply -f examples/custom-resources/external-auth=test/keycloak.yaml
kubectl -n default rollout status deploy/keycloak -n default
```

## Step 2 — Make Keycloak admin API reachable (port-forward)

Port-forward Keycloak so you can call the admin REST API from your machine:

```shell
# map local ports 8080 and 8443 to the Keycloak service (no sudo required):
kubectl -n default port-forward svc/keycloak 8080:8080 8443:8443 &
# then open in a browser: https://localhost:8443 (admin UI) or https://localhost:8443/realms/master
```

Because this example uses a self-signed cert, API requests below use `-k` to ignore TLS verification for local testing. If you port-forwarded to different ports, substitute the host/port accordingly (see token examples below).

## Step 3 — Import the realm (or create client & user manually)

The example includes a prepared realm JSON at `examples/custom-resources/external-auth/keycloak-realm.json`. Import it with the Admin API.

1) Get an admin token. Use the port you forwarded Keycloak to; the examples below assume `https://localhost:8443` (if you forwarded to other ports, replace host:port accordingly).

```shell
# with jq (preferred)
KC_TOKEN=$(curl -s -k -X POST "https://localhost:8443/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'client_id=admin-cli' -d 'username=admin' -d 'password=admin' -d 'grant_type=password' \
  | jq -r .access_token)

# without jq (python fallback)
KC_TOKEN=$(curl -s -k -X POST "https://localhost:8443/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'client_id=admin-cli' -d 'username=admin' -d 'password=admin' -d 'grant_type=password' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "$KC_TOKEN"
```

2) Import the realm JSON (creates realm `example` as shipped):

```shell
curl -v -k -X POST "https://localhost:8443/admin/realms" \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @examples/custom-resources/external-auth=test/keycloak-realm.json
```

If you prefer to create the client and user manually via the Keycloak admin UI, skip the import and follow the UI steps to create a confidential client `oauth2-proxy-client` (redirect URI `http://localhost:4180/oauth2/callback`) and a test user.

> If the realm already exists and you want to replace it:

```shell
curl -s -k -X DELETE "https://localhost:8443/admin/realms/example" -H "Authorization: Bearer $KC_TOKEN"
# then re-run the POST import command above
```

## Step 4 — Create the oauth2 client secret and Kubernetes OIDC secret

The oauth2 client used by `oauth2-proxy` should be a *confidential* client (server-side) in Keycloak. Confidential clients authenticate to Keycloak with a client secret when exchanging the authorization code for tokens. Therefore you must set a client secret for the client (unless you intentionally use a public/PKCE flow — not covered by this example).

Yes — a *confidential* client must have a client secret (essentially a "password" for the client). The client secret is what oauth2-proxy uses server‑side to authenticate to Keycloak when exchanging an authorization code for tokens; the commands below show how to create/set that secret via the Admin API and create the matching Kubernetes secret.

1) Confirm the client is confidential (optional check):

```shell
curl -s -k "https://localhost:8443/admin/realms/example/clients?clientId=oauth2-proxy-client" \
  -H "Authorization: Bearer $KC_TOKEN" | jq .

# look for "publicClient": false  -> means confidential
```

2) Generate and set the client secret in Keycloak and create the Kubernetes secret (controller expects `type: nginx.org/oidc`):

```shell
CLIENT_SECRET=$(openssl rand -hex 16)
CLIENT_ID=$(curl -s -k "https://localhost:8443/admin/realms/example/clients?clientId=oauth2-proxy-client" \
  -H "Authorization: Bearer $KC_TOKEN" | jq -r '.[0].id')

curl -s -k -X POST "https://localhost:8443/admin/realms/example/clients/$CLIENT_ID/client-secret" \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"value\":\"$CLIENT_SECRET\"}"

kubectl -n default create secret generic oauth2-proxy-client-secret \
  --type='nginx.org/oidc' \
  --from-literal=client-secret="$CLIENT_SECRET" --dry-run=client -o yaml | kubectl apply -f -
```

Notes:
- The secret key name must be `client-secret` because the oauth2-proxy manifest mounts `/etc/secrets/client-secret`.
- `type: nginx.org/oidc` is a controller-specific secret type used for validation; it is acceptable for OSS.
- If you prefer a PKCE/public-client flow (no client secret), that is possible but requires configuration changes in Keycloak and oauth2-proxy and is outside this minimal example.

### (UI) How to create the confidential client in the Keycloak admin console
If you'd rather use the Keycloak web UI instead of the Admin API, follow these steps (assumes you're in the `example` realm):

1. Open the Keycloak admin console at `https://localhost:8443` and log in as the admin user.
2. In the left menu click "Clients", then click "Create".
3. Fill the initial form:
   - Client ID: `oauth2-proxy-client`
   - Client Protocol: `openid-connect`
   - Root URL: `http://localhost:4180` (optional for local testing)
   - Click "Save".
4. On the client's Settings page update these fields:
   - Access Type: select `confidential` (this enables client authentication)
   - Standard Flow Enabled: ON
   - Direct Access Grants Enabled: OFF
   - Implicit Flow Enabled: OFF
   - Valid Redirect URIs: add `http://localhost:4180/oauth2/callback` (and/or `http://localhost:4180/*` for local testing)
   - Web Origins: add `http://localhost:4180` or use `+` to allow all (not recommended for production)
   - Save the changes.
5. After saving, go to the "Credentials" tab for the client. Keycloak will show the client secret value under "Secret". Click "Regenerate" if you want to create a fresh secret — copy the value.
6. Create the Kubernetes secret from the copied client secret (see the Admin API section above). Example:

```shell
kubectl -n default create secret generic oauth2-proxy-client-secret \
  --type='nginx.org/oidc' --from-literal=client-secret='<PASTE_SECRET_HERE>' --dry-run=client -o yaml | kubectl apply -f -
```

7. (Optional) In the client's "Settings" you can also configure `Root URL`, `Base URL`, and other timeouts if you plan to use a different host (for example `https://external-auth.example.com`). If you change the host, update the `Valid Redirect URIs` and `oauth2-proxy` `--redirect-url` accordingly.

## Step 5 — Create the oauth2-proxy cookie secret

Generate a secure cookie secret and create the k8s secret referenced by the oauth2-proxy Deployment:

```shell
COOKIE_SECRET=$(python3 - <<'PY'
import os,base64
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)

kubectl -n default create secret generic oauth2-proxy-cookie-secret \
  --from-literal=cookie-secret="$COOKIE_SECRET" --dry-run=client -o yaml | kubectl apply -f -
```

## Step 6 — Deploy oauth2-proxy, the backend, Policy and VirtualServer

Apply the example manifests (the oauth2-proxy manifest expects the two secrets you created above):

```shell
kubectl -n default apply -f examples/custom-resources/external-auth=test/oauth2-proxy.yaml
kubectl -n default apply -f examples/custom-resources/external-auth=test/backend.yaml
kubectl -n default apply -f examples/custom-resources/external-auth=test/policy-external-auth=test.yaml
kubectl -n default apply -f examples/custom-resources/external-auth=test/virtualserver-external-auth=test.yaml

kubectl -n default rollout status deploy/oauth2-proxy
kubectl -n default rollout status deploy/httpbin
```

## Step 7 — Test the auth flow

Port-forward oauth2-proxy and perform a browser login test:

```shell
kubectl -n default port-forward svc/oauth2-proxy 4180:4180 &
# in browser: http://localhost:4180/oauth2/start?rd=/private/
```

- You should be redirected to Keycloak (https://localhost), authenticate, then be returned to oauth2-proxy and be allowed to access `/private/`.

Curl checks:

```shell
# before login
curl -i http://localhost:4180/oauth2/auth
# after login (use session cookie captured from the browser)
curl -i --cookie "oauth2_proxy=<SESSION_COOKIE>" http://localhost:4180/oauth2/auth
```

## What to change for your environment
- `virtualserver-external-auth.yaml` currently uses host `external-auth.example.com`. If you want to test end-to-end via the NIC ingress, add an `/etc/hosts` entry mapping that host to your NIC IP, or change the host in the VirtualServer to a domain you control.

Example `/etc/hosts` entry (replace `X.Y.Z.W` with your NIC ingress IP):

```text
X.Y.Z.W external-auth.example.com
```
- If the realm name in `keycloak-realm.json` is not `example`, replace `example` in the README commands with your realm name.
- If you run Keycloak on a different port/hostname, update `--oidc-issuer-url` in `oauth2-proxy.yaml` accordingly.
- For production: use real TLS certs, set `--cookie-secure=true` in `oauth2-proxy.yaml`, and do not use `-k` in curl commands.

## Troubleshooting
- If `kubectl apply` complains about `keycloak-realm.json`, remember it is not a k8s resource — import it via the Keycloak Admin API (steps above) or create the client/user manually.
- If NIC rejects the policy due to secret validation, confirm that `oauth2-proxy-client-secret` uses `type: nginx.org/oidc` and contains `client-secret`.
- If login redirects fail, check oauth2-proxy logs and Keycloak logs:

```shell
kubectl -n default logs deploy/oauth2-proxy
kubectl -n default logs deploy/keycloak
```