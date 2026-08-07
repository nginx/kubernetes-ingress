# OIDC Native

In this example, we deploy a web application, load-balance it via a VirtualServer, and protect it using the NGINX Plus native `ngx_http_oidc_module` (`oidcNative` policy) and [Keycloak](https://www.keycloak.org/).

**Note**: The Keycloak container does not support IPv6 environments.

## Prerequisites

1. Run `make secrets` to generate the TLS secrets for the example.
2. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests) instructions to deploy NGINX Ingress Controller with `-enable-oidc`. The HTTPS port of the Ingress Controller must be `443`.
3. Get the external IP of the Ingress Controller service:

    ```shell
    kubectl get svc nginx-ingress -n nginx-ingress
    ```

## Step 1 - Rewrite the Example Manifests for Your Cluster

Substitute the placeholder `example.com` hostnames with `nip.io` names that resolve to your Ingress Controller IP:

```shell
LB_IP=$(kubectl get svc nginx-ingress -n nginx-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
WEBAPP_HOST=webapp.${LB_IP}.nip.io
KEYCLOAK_HOST=keycloak.${LB_IP}.nip.io

sed -i "s/webapp.example.com/${WEBAPP_HOST}/g; s/keycloak.example.com/${KEYCLOAK_HOST}/g" \
  keycloak.yaml virtual-server-idp.yaml virtual-server.yaml oidc-native-policy.yaml
```

## Step 2 - Deploy TLS Secrets

Create the TLS secrets used for TLS termination of the web application and Keycloak:

```shell
kubectl apply -f tls-secret.yaml
kubectl apply -f keycloak-tls-secret.yaml
```

## Step 3 - Deploy Resolver ConfigMap

Apply the ConfigMap `nginx-config.yaml` to configure the NGINX DNS resolver so the native OIDC module can resolve the IdP issuer hostname:

```shell
kubectl apply -f nginx-config.yaml
```

## Step 4 - Deploy Keycloak and the Web Application

Create Keycloak, its VirtualServer, and the web application deployment:

```shell
kubectl apply -f keycloak.yaml
kubectl apply -f virtual-server-idp.yaml
kubectl apply -f webapp.yaml
```

The shipped TLS secrets are self-signed, so your browser will show a certificate warning when visiting either page — accept it once per hostname. Backchannel communication (NGINX ↔ Keycloak) is handled via `sslVerify: false` in the policy.

## Step 5 - Configure Keycloak

1. Open `https://${KEYCLOAK_HOST}` in your browser (accept the cert warning) and log in with `admin` / `admin`.
2. Follow [`keycloak_setup.md`](./keycloak_setup.md) to create the `nginx-plus` client with these values:
   - **Client authentication**: On
   - **Valid redirect URIs**: `https://${WEBAPP_HOST}/*`
   - **Valid post logout redirect URIs**: `https://${WEBAPP_HOST}/_logout`
3. Create the user `nginx-user` with password `test`.
4. Copy the client secret shown on the Credentials tab.

## Step 6 - Deploy the Client Secret

1. Base64-encode the client secret obtained in Step 5:

    ```shell
    echo -n "<client-secret-value>" | base64
    ```

2. Edit [`client-secret.yaml`](./client-secret.yaml), replacing `<insert-secret-here>` with the encoded secret.

3. Deploy the client secret:

    ```shell
    kubectl apply -f client-secret.yaml
    ```

## Step 7 - Deploy the OIDC Native Policy and VirtualServer

```shell
kubectl apply -f oidc-native-policy.yaml
kubectl apply -f virtual-server.yaml
```

## Step 8 - Test the Authentication Flow

1. Open `https://${WEBAPP_HOST}` in your browser. You are redirected to Keycloak.
2. Log in as `nginx-user` / `test`. ![keycloak](./keycloak.png)
3. You are redirected back to the web application.

## Step 9 - Log Out

1. Navigate to `https://${WEBAPP_HOST}/logout`. Your session is terminated and you land on `/_logout`. ![logout](./logout.png)
2. Visit `https://${WEBAPP_HOST}` again — you are prompted to log in.

## How it Differs from the NJS OIDC Example

| Feature | NJS OIDC (`spec.oidc`) | Native OIDC (`spec.oidcNative`) |
| ------- | ---------------------- | ------------------------------- |
| Implementation | JavaScript (njs) | Native C module |
| Endpoints | Explicit (auth, token, jwks) | Auto-discovered from issuer metadata |
| Session storage | Explicit keyval zones | Managed by the module |
| Multiple providers per VS | No | Yes (per route) |
| PKCE | Manual toggle | Configurable per policy |
| Callback URI | `/_codexch` | `/oidc_callback` (default) |
