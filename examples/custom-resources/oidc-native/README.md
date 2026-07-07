# OIDC Native Module Example (OIDCNative)

This example demonstrates using the NGINX Plus native `ngx_http_oidc_module` for OpenID Connect authentication with Keycloak.

Unlike the NJS-based OIDC implementation, the native module handles the entire Authorization Code Flow internally — no JavaScript, no keyval zones, no extra locations.

## Prerequisites

- NGINX Plus with the native OIDC module (R33+)
- NIC built with `-enable-oidc` flag
- A TLS secret named `tls-secret` for your domain
- DNS entries for `webapp.example.com` and `keycloak.example.com`

## Setup

### 1. Deploy the NIC ConfigMap with resolver

The native OIDC module requires a DNS resolver to fetch provider metadata:

```console
kubectl apply -f nginx-config.yaml
```

### 2. Deploy Keycloak

```console
kubectl apply -f keycloak.yaml
kubectl apply -f virtual-server-idp.yaml
```

### 3. Configure Keycloak

Once Keycloak is running, access `https://keycloak.example.com` and:

1. Log in with `admin`/`admin`
2. Create a client:
   - **Client ID**: `nginx-plus`
   - **Client authentication**: On
   - **Valid redirect URIs**: `https://webapp.example.com/oidc_callback`
   - **Valid post logout redirect URIs**: `https://webapp.example.com/*`
3. Copy the client secret from the **Credentials** tab

### 4. Create the client secret

Base64-encode the client secret and update `client-secret.yaml`:

```console
echo -n 'your-client-secret' | base64
```

```console
kubectl apply -f client-secret.yaml
```

### 5. Deploy the OIDCNative policy and webapp

```console
kubectl apply -f oidcnative-policy.yaml
kubectl apply -f webapp.yaml
kubectl apply -f virtual-server.yaml
```

### 6. Test

Navigate to `https://webapp.example.com`. You should be redirected to Keycloak to log in. After authentication, you'll be redirected back to the webapp.

## Key differences from NJS-based OIDC

| Feature | NJS OIDC (`spec.oidc`) | Native OIDC (`spec.oidcNative`) |
| --- | --- | --- |
| Implementation | JavaScript (njs) | Native C module |
| Configuration | Explicit endpoints (auth, token, jwks) | Auto-discovery via issuer metadata |
| Session storage | keyval zones | Built-in |
| Multiple providers per VS | No (one per server block) | Yes (different per route) |
| PKCE | Manual toggle | Auto-detected from metadata |
| Callback URI | `/_codexch` | `/oidc_callback` |
