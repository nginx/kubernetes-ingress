# OIDC Native Module Example (OIDCNative)

This example demonstrates using the NGINX Plus native `ngx_http_oidc_module` for OpenID Connect authentication with Keycloak.

Unlike the NJS-based OIDC implementation, the native module handles the entire Authorization Code Flow internally — no JavaScript, no keyval zones, no extra locations.

## Prerequisites

- NGINX Plus with the native OIDC module (R33+)
- NIC started with `-enable-oidc` flag
- A TLS secret named `tls-secret` for your domain

## Quick Start

### 1. Run the setup script

This deploys Keycloak, sets up in-cluster DNS resolution, and configures the NIC resolver:

```console
./setup.sh
```

### 2. Add hosts entries

Add entries to `/etc/hosts` on your machine pointing both hostnames to the NIC external IP:

```text
<NIC_EXTERNAL_IP>  keycloak.example.com webapp.example.com
```

### 3. Configure Keycloak

Open `https://keycloak.example.com` and log in with `admin`/`admin`, then:

1. Create a client:
   - **Client ID**: `nginx-plus`
   - **Client authentication**: On
   - **Valid redirect URIs**: `https://webapp.example.com/oidc_callback`
   - **Valid post logout redirect URIs**: `https://webapp.example.com/*`
2. Copy the client secret from the **Credentials** tab

### 4. Deploy the policy and webapp

```console
CLIENT_SECRET='<paste-secret-here>' ./deploy-policy.sh
```

### 5. Test

Navigate to `https://webapp.example.com`. You should be redirected to Keycloak to log in. After authentication, you'll be redirected back to the webapp.

### 6. Teardown

```console
./teardown.sh
```

## How it works

The setup script deploys a lightweight CoreDNS instance that maps `keycloak.example.com` to the Keycloak service ClusterIP. This allows the native OIDC module to resolve the issuer hostname when fetching OpenID Provider metadata and exchanging tokens. The NIC ConfigMap is updated to use this DNS server as its resolver.

## Key differences from NJS-based OIDC

| Feature | NJS OIDC (`spec.oidc`) | Native OIDC (`spec.oidcNative`) |
| --- | --- | --- |
| Implementation | JavaScript (njs) | Native C module |
| Configuration | Explicit endpoints (auth, token, jwks) | Auto-discovery via issuer metadata |
| Session storage | keyval zones | Built-in |
| Multiple providers per VS | No (one per server block) | Yes (different per route) |
| PKCE | Manual toggle | Auto-detected from metadata |
| Callback URI | `/_codexch` | `/oidc_callback` |
