# Design Document: Native OIDC Module Policy (`oidcNative`)

## Status: PoC Complete — Seeking Approval for GA Development

## Summary

Add support for the NGINX Plus native `ngx_http_oidc_module` (available since R33) as a new Policy type `oidcNative` on VirtualServer and VirtualServerRoute resources. This replaces the NJS-based OIDC implementation with a native C module that handles the entire Authorization Code Flow internally.

## Motivation

The current NJS-based OIDC implementation (`spec.oidc`) has several limitations:
- Complex configuration (requires explicit auth, token, JWKS endpoints)
- Heavy infrastructure (keyval zones, NJS scripts, multiple internal locations)
- Single provider per VirtualServer (one OIDC policy per server block)
- Manual PKCE toggle
- No built-in session management

The native module addresses all of these with auto-discovery, built-in session storage, automatic PKCE detection, and no JavaScript dependencies.

## User Experience

### Minimal Policy

```yaml
apiVersion: k8s.nginx.org/v1
kind: Policy
metadata:
  name: my-oidc
spec:
  oidcNative:
    issuer: https://accounts.google.com
    clientID: my-app
    clientSecret: my-oidc-secret
```

### VirtualServer Reference

```yaml
spec:
  routes:
    - path: /api
      policies:
        - name: my-oidc
      action:
        pass: backend
    - path: /public
      action:
        pass: backend
```

Only `/api` requires authentication. `/public` is open. The callback URI is auto-generated.

## CRD Specification

### `PolicySpec.oidcNative`

| Field | Type | Required | NGINX Directive | Default (auto) |
| --- | --- | --- | --- | --- |
| `issuer` | string | Yes | `issuer` | — |
| `clientID` | string | Yes | `client_id` | — |
| `clientSecret` | string | No | `client_secret` | — (PKCE if omitted) |
| `configURL` | string | No | `config_url` | Module default: `<issuer>/.well-known/openid-configuration` |
| `scope` | string | No | `scope` | Module default: `openid` |
| `redirectURI` | string | No | `redirect_uri` | Auto: `/oidc_callback_<providerName>` |
| `cookieName` | string | No | `cookie_name` | Auto: `NGX_OIDC_<providerName>` |
| `extraAuthArgs` | string | No | `extra_auth_args` | — |
| `pkce` | enum(on,off) | No | `pkce` | Module default: auto-detected |
| `logoutURI` | string | No | `logout_uri` | — |
| `postLogoutRedirectURI` | string | No | `post_logout_uri` | — |
| `frontChannelLogoutURI` | string | No | `frontchannel_logout_uri` | — |
| `logoutTokenHint` | bool | No | `logout_token_hint` | `false` |
| `sessionTimeout` | string | No | `session_timeout` | Module default: `8h` |
| `userInfoEnable` | bool | No | `userinfo` | `false` |
| `trustedCertSecret` | string | No | `ssl_trusted_certificate` (provider block) + `proxy_ssl_trusted_certificate` (proxy location) | System CA bundle |
| `sslVerify` | *bool | No | `proxy_ssl_verify` on the proxy location | `true` |
| `sslName` | string | No | `proxy_ssl_name` + `Host` header on the proxy location | Hostname parsed from `issuer` |
| `sslVerifyDepth` | *int | No | `proxy_ssl_verify_depth` on the proxy location | `1` |
| `proxyBufferSize` | string | No | `proxy_buffer_size`, `proxy_buffers`, `proxy_busy_buffers_size` on the proxy location | `32k` |

### Validation Strategy

| Level | What's validated |
| --- | --- |
| **CRD (kubebuilder markers)** | issuer pattern (https), clientSecret RFC 1123, redirectURI/logoutURI/postLogoutRedirectURI path pattern, scope contains openid (CEL), sessionTimeout time format, pkce enum, proxyBufferSize format |
| **Go validation** | issuer hostname chars, clientID injection-safe chars (no $, \, ") |
| **Config generation** | Secret existence, secret type, CA secret type, NJS/Native conflict on same context, IdP hostname extraction from issuer |

Design principle: CRD validation for format checks (instant API server feedback). Go validation only for checks that can't be expressed in CRD markers.

## Architecture

### Generated NGINX Config

```nginx
# http-level: keyval zone for session store (sync flag when zone-sync enabled)
keyval_zone zone=oidc_sessions_oidc_default_my_oidc_default_webapp:10m;

# http-level: one oidc_provider block per provider
oidc_provider oidc_default_my_oidc_default_webapp {
    issuer https://accounts.google.com;
    client_id my-app;
    client_secret <resolved-from-k8s-secret>;
    redirect_uri /oidc_callback_oidc_default_my_oidc_default_webapp;
    cookie_name NGX_OIDC_oidc_default_my_oidc_default_webapp;
    session_store oidc_sessions_oidc_default_my_oidc_default_webapp;
    ssl_trusted_certificate /etc/nginx/secrets/default-ca-secret-ca.crt;
    proxy_location /_oidc_idp_oidc_default_my_oidc_default_webapp;
}

server {
    # Callback location (auto-generated, handles auth code exchange)
    location = /oidc_callback_oidc_default_my_oidc_default_webapp {
        auth_oidc oidc_default_my_oidc_default_webapp;
    }

    # IdP proxy location (auto-generated, controls SNI/Host/TLS/DNS to the IdP)
    location = /_oidc_idp_oidc_default_my_oidc_default_webapp {
        auth_oidc off;
        proxy_pass $oidc_idp_request_uri;
        proxy_ssl_server_name on;
        proxy_ssl_name accounts.google.com;
        proxy_set_header Host accounts.google.com;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/nginx/secrets/default-ca-secret-ca.crt;
        proxy_ssl_verify_depth 1;
        proxy_buffers 8 32k;
        proxy_buffer_size 32k;
        proxy_busy_buffers_size 32k;
        subrequest_output_buffer_size 64k;
    }

    # Protected route
    location /api {
        auth_oidc oidc_default_my_oidc_default_webapp;
        proxy_pass http://backend;
    }

    # Unprotected route (no auth_oidc directive)
    location /public {
        proxy_pass http://backend;
    }
}
```

With `zone-sync: "true"` in ConfigMap, the keyval zone gets the sync flag:
```nginx
keyval_zone zone=oidc_sessions_oidc_default_my_oidc_default_webapp:10m sync;
```

### IdP Proxy Location (proxy_location)

Every provider gets an auto-generated `proxy_location` at `/_oidc_idp_<providerName>`. All requests the module makes to the IdP (metadata discovery, JWKS, token exchange, userinfo) are routed through this location. This gives NIC full control over:

- **SNI** (`proxy_ssl_name`) — set to the IdP hostname (from `sslName` or derived from `issuer`)
- **Host header** — same as SNI, ensuring the IdP receives the expected virtual host
- **TLS verification** — `proxy_ssl_verify on/off` from `sslVerify`, with `proxy_ssl_trusted_certificate` from `trustedCertSecret`
- **DNS resolution** — uses NIC's standard `resolver` directive from ConfigMap
- **Buffer sizes** — tunable via `proxyBufferSize` (default `32k`)

**Why this matters**: Without `proxy_location`, in-cluster IdPs (e.g. Keycloak in the same cluster) require custom DNS setup, careful cert/hostname alignment, and often fail with SNI mismatches or loopback issues. With `proxy_location`, the OIDC module makes internal requests to `/_oidc_idp_<name>` which NIC then proxies to the actual IdP with correct settings.

### Provider Naming

Provider names must be globally unique across the entire NGINX config (multiple VirtualServers share the same `nginx.conf`):

```
oidc_<policyNamespace>_<policyName>_<vsNamespace>_<vsName>
```

Hyphens converted to underscores via `rfc1123ToSnake()`.

### Callback URI Generation

Each provider gets a dedicated `location = <callbackURI>` with `auth_oidc` enabled. This solves the key problem: the native module's callback must land in a location with `auth_oidc` active, regardless of which routes the user protects.

Default: `/oidc_callback_<providerName>`. User can override via `redirectURI`.

### Cookie Isolation

Each provider gets a unique cookie name (`NGX_OIDC_<providerName>`) to prevent session sharing between providers on the same domain. Without this, authenticating with provider A on `/api` would satisfy provider B on `/admin` (both set/read the same domain-scoped cookie).

### Session Storage and Zone-Sync

Each provider gets a dedicated keyval zone for session storage:

| Zone-sync setting | Generated config |
| --- | --- |
| Disabled (default) | `keyval_zone zone=oidc_sessions_<providerName>:10m;` |
| Enabled (`zone-sync: "true"`) | `keyval_zone zone=oidc_sessions_<providerName>:10m sync;` |

The `session_store` directive on the `oidc_provider` block always references this zone. This ensures:
- Each provider has isolated session data
- Multi-instance deployments sync sessions when zone-sync is enabled
- Zone name is globally unique (derived from provider name)

### Scope Format

The native module's `scope` directive expects space-separated values (`openid profile email`), unlike the NJS OIDC which used `+`-separated (`openid+profile+email`). The config generation automatically converts `+` to spaces for backward compatibility.

### Secret Handling

| Secret | K8s Type | Written to disk? | How consumed |
| --- | --- | --- | --- |
| `clientSecret` | `nginx.org/oidc` (key: `client-secret`) | No | Value injected into `client_secret` directive |
| `trustedCertSecret` | `nginx.org/ca` (key: `ca.crt`) | Yes | File path in `ssl_trusted_certificate` directive |

Secret rotation triggers VS re-sync via `findPoliciesForSecret()` → `FindResourcesForPolicy()`. Both `clientSecret` and `trustedCertSecret` are registered in `findPoliciesForSecret()`, ensuring that changes to either secret type trigger config regeneration.

## Placement Rules

| Level | Behavior |
| --- | --- |
| VS `spec.policies` | `auth_oidc` at server level + all locations inherit |
| VS route `policies` | `auth_oidc` only on that location |
| VSR subroute `policies` | `auth_oidc` only on that subroute's location |
| Multiple providers per VS | Allowed — different routes can use different providers |
| Same provider on multiple VS | Allowed — generates unique provider names per VS |

### NJS/Native Coexistence

The two OIDC implementations (`spec.oidc` NJS-based and `spec.oidcNative`
Plus-native) can both be present on the same NIC install, but they are
**mutually exclusive within a single authentication context**. NIC enforces
this in [addOIDCConfig / addOIDCNativeConfig](../../internal/configs/policy.go);
the matrix below is what the team should expect and what test-manifests 8a/8b/9
verify.

| Scenario | Behavior | Rationale |
| --- | --- | --- |
| **NJS on VS1, Native on VS2** (separate VirtualServers) | Works. Each VS gets its own `server{}` block with its own auth mechanism. | Both implementations live in the same nginx.conf; only the per-VS wiring differs. Independent NIC-level enablement (`-enable-oidc`) covers both. |
| **NJS on VS spec, Native on one route in the same VS** | Works, but the native route does **not** inherit the NJS server-level auth. The route runs only the native flow. | NIC deliberately breaks the server-level OIDC inheritance when a route sets a native provider — otherwise the NJS `error_page 401 = @do_oidc_flow` would fire alongside `auth_oidc`, producing an ambiguous response. See the `specHasOIDC && routePoliciesCfg.OIDCProvider == nil` guard in [virtualserver.go](../../internal/configs/virtualserver.go). |
| **Both NJS and native on the *same* route/spec** | **Hard error**. The second one to be processed sets `res.isError = true`; the entire policy config is replaced with `ErrorReturn: 500`. VS goes to Warning state with a message about the OIDC/OIDCNative conflict. | Preserves fail-loud semantics for a configuration that cannot possibly work — `auth_oidc` and NJS `error_page 401 = @do_oidc_flow` on the same location would drive the browser through two different login flows. |
| **Multiple native providers in the same context** | First wins, second is ignored with a warning event on the VS. Config still renders. | Matches the existing behavior for multiple NJS OIDC policies in the same context (warning-only, not `isError`). |
| **Multiple native providers across different routes / VSRs** | Fully supported. Each provider gets a unique auto-generated name, callback path, cookie, and session store. | This is the main win over the NJS OIDC implementation. |

The mutex is bidirectional: whichever policy type gets processed first wins the
context; the second raises the appropriate warning/error. Order is only
deterministic within a single VS spec, so authors mixing types on the same
spec should not rely on order — they should use one type per context.

Files carrying this behavior:

- Cross-type mutex (native seeing existing NJS, and vice-versa) — `addOIDCConfig` / `addOIDCNativeConfig` in [`internal/configs/policy.go`](../../internal/configs/policy.go)
- Server-to-route inheritance guard — the `specHasOIDC && routePoliciesCfg.OIDCProvider == nil` branch in [`internal/configs/virtualserver.go`](../../internal/configs/virtualserver.go)
- Policy-spec exclusivity at the API level (both `oidc` and `oidcNative` set on one Policy CR) — `validatePolicySpec` in [`pkg/apis/configuration/validation/policy.go`](../../pkg/apis/configuration/validation/policy.go)

## Prerequisites

- **NGINX Plus R33+** with `ngx_http_oidc_module`
- **`-enable-oidc` flag** on NIC (reused from NJS OIDC)
- **`resolver-addresses`** in ConfigMap — required for the module to fetch provider metadata

## Differences from NJS OIDC (`spec.oidc`)

| Aspect | NJS OIDC | Native OIDC |
| --- | --- | --- |
| Configuration | Explicit endpoints (auth, token, jwks) | Auto-discovery from issuer |
| Dependencies | NJS scripts, keyval zones, internal locations | None |
| Providers per VS | One | Multiple |
| PKCE | Manual toggle | Auto-detected from metadata |
| Session storage | keyval zones + zone-sync | keyval zone per provider (auto-generated, zone-sync aware) |
| Callback URI | `/_codexch` (fixed) | `/oidc_callback_<name>` (per-provider) |
| Ingress support | No | Planned (future) |

## Open Issues

### Callback URI must be in a protected location — RESOLVED

**Problem**: The native module only handles the callback within locations that have `auth_oidc` enabled. If the callback path doesn't match any protected location, it 404s.

**Solution**: NIC auto-generates a dedicated `location = <callbackURI> { auth_oidc <provider>; }` for each provider. Users can protect any route (spec-level or per-route) and the callback always works.

### In-cluster IdP setup is awkward — KNOWN LIMITATION

**Problem**: Running the IdP (Keycloak, Dex, Authelia, etc.) in the same cluster
that NIC serves is a common demo/dev topology, but the native module makes it
substantially harder than deploying the IdP externally. The pain surfaces at
four independent layers, and there is no single knob that fixes them together:

1. **DNS resolution from inside the NIC pod.** The native module resolves the
   issuer hostname via NGINX's `resolver` directive at request time, which
   uses cluster DNS (kube-dns) — it does **not** consult `/etc/hosts`. So
   Kubernetes-level tricks like pod `hostAliases` (or manually editing
   `/etc/hosts`) do not work. This was tried and confirmed non-working on the
   `feat/oidc-policy-v2` branch. The only options that actually resolve are:
   - A real DNS record for the IdP hostname (public, or a nip.io / sslip.io
     wildcard where the hostname encodes the target IP)
   - CoreDNS custom entries in the cluster
   - Configuring the IdP to advertise a Kubernetes-service DNS name for its
     backchannel endpoints (`hostname-backchannel-dynamic` in Keycloak) plus
     setting `oidcNative.configURL` to fetch metadata from the service DNS name

2. **TLS cert / SAN alignment.** The module verifies the IdP TLS cert against
   the issuer hostname. In-cluster IdPs typically ship a cert whose SAN is
   `<svc>.<ns>.svc.cluster.local`, which does not match the `issuer` value.
   Users must either (a) generate a cert covering both the internal and the
   externally-facing hostname, or (b) set `sslVerify: false` on the policy
   (dev/test only, insecure). Our shipped example uses (b) because generating
   per-cluster SANs is out of scope for a checked-in example.

3. **Browser-side trust.** Even after the backchannel is happy, the browser
   still hits the IdP directly for the interactive login. If the shipped IdP
   cert is self-signed, users click through cert warnings twice (once for the
   webapp VS, once for the IdP VS). No way around this without real DNS +
   real certs (cert-manager or manual).

4. **Callback URI registration.** The native module's auto-generated callback
   path is per-provider (`/oidc_callback_<providerName>`), where the provider
   name embeds the policy namespace, policy name, VS namespace, and VS name.
   Users cannot know the callback path until after they've applied the VS.
   Two workarounds are documented: register `https://<host>/*` as a wildcard
   redirect URI in the IdP client (chosen in the example), or set an explicit
   `redirectURI` on the policy to force a stable path.

**What NIC does to mitigate this**: NIC auto-generates a `proxy_location` per
provider (see the IdP Proxy Location section above). The module makes all
IdP-bound requests through that location, which gives us:

- SNI override via `sslName` — decouples the backchannel SNI from the issuer
  hostname if needed
- Host-header override — helps when the IdP validates by Host
- TLS trust chain override via `trustedCertSecret` / `sslVerify`
- Use of NIC's configured `resolver` — which at least routes through cluster
  DNS uniformly

But `proxy_location` only addresses the mechanics of the *outbound* request;
it does not solve DNS (the module still passes `proxy_pass $oidc_idp_request_uri`
with a variable, so runtime resolution still applies), it does not solve
browser-side reachability, and it does not solve cert-trust ergonomics.

**Guidance for the docs team**: recommend nip.io / sslip.io wildcard DNS in
the getting-started docs for in-cluster IdPs. External IdPs (Auth0, Okta, Azure
AD, external Keycloak) do not hit any of these problems and should be the
recommended production topology. The shipped example (`examples/custom-resources/oidc-native/`)
uses nip.io + `sslVerify: false` and is explicitly marked as a dev/demo setup.

**Future work worth considering**:

- Add an optional `hostname-backchannel-url`-style abstraction so users can
  supply a service-DNS URL for backchannel while keeping the public issuer.
  Would eliminate DNS pain for Keycloak users specifically.
- Extend `make secrets` (or a fresh helper) to (re)generate the shipped example
  certs with SANs matching a user-supplied hostname, so demos can be
  cert-warning-free without hand-crafting `openssl` invocations.

### In-cluster IdP DNS/TLS/loopback issues — PARTIALLY RESOLVED

**Problem**: For in-cluster IdPs like Keycloak, the module would fail with SNI mismatches, missing DNS entries, or loopback deadlocks when trying to reach the IdP directly.

**Partial solution**: NIC auto-generates a `proxy_location` per provider. See the IdP Proxy Location section above and the "In-cluster IdP setup is awkward" section for the residual pain points that `proxy_location` does not solve.

### Server-level + Location-level auth_oidc interaction

When `auth_oidc provider1;` is at server level and `auth_oidc provider2;` is at a specific location, the module may not re-authenticate for the location-level provider (session from server-level provider satisfies it). The cookie isolation fix mitigates this, but the module behavior needs clarification from the Plus team.

### No Ingress support (this release)

OIDCNative is VirtualServer/VSR only. Ingress support is planned for a future release.

### Zone-sync for multi-instance session persistence — IMPLEMENTED

Each provider gets a dedicated keyval zone (`oidc_sessions_<providerName>`) with the `session_store` directive set on the provider. When ConfigMap `zone-sync` is `"true"`, the keyval zone gets the `sync` flag.

This is fully implemented in the PoC. No further work needed for GA unless the zone size (currently hardcoded at `10m`) needs to be configurable.

**Question for Plus team**: What is the recommended zone size? The NJS OIDC used separate zones (id_tokens: 1M, access_tokens: 1M, refresh_tokens: 1M, sids: 1M). Does the native module's single session store need more or less?

## Files Changed (PoC)

| File | Change |
| --- | --- |
| `pkg/apis/configuration/v1/types.go` | `OIDCNative` struct + `PolicySpec.OIDCNative` field |
| `pkg/apis/configuration/validation/policy.go` | `validateOIDCNative()`, `policyFields()` entry, `validateIssuerURL()` |
| `internal/configs/version2/http.go` | `OIDCProvider` struct, `VirtualServerConfig.OIDCProviders`, `Server.OIDCProviderName`, `Location.OIDCProviderName`, `KeyValZone.Sync` field |
| `internal/configs/policy.go` | `addOIDCNativeConfig()`, conflict detection, scope conversion, session store/cookie/callback auto-generation |
| `internal/configs/virtualserver.go` | Provider collection, dedup, session store keyval zone generation, `addPoliciesCfgToLocation` mutual exclusivity, NJS inheritance guard |
| `internal/configs/version2/nginx-plus.virtualserver.tmpl` | `oidc_provider` blocks, callback locations, `auth_oidc` at server/location, keyval zone sync flag |
| `internal/k8s/controller.go` | `addOIDCNativeSecretRefs()`, `addOIDCNativeTrustedCertSecretRefs()`, `findPoliciesForSecret()` entries for secret rotation |

## Test Coverage

### Unit Tests
- `validateOIDCNative()` — valid/invalid input, gate checks (Plus-only, OIDC-enabled)
- `addOIDCNativeConfig()` — secret resolution, duplicate handling, conflict detection
- Template snapshot — `oidc_provider` block + `auth_oidc` + callback location

### Manual Test Scenarios (22 cases)
- Placement: spec, route, subroute, mixed levels, multi-VS, same policy multi-VS
- Coexistence: NJS+Native same VS different routes, same route (error), separate VS
- Lifecycle: policy delete/recovery, secret rotation, policy update
- Validation: invalid fields (CRD rejection), NJS+Native conflict
- Secret errors: missing, wrong type, missing CA, wrong CA type, wrong key name
- Edge cases: no TLS, mixed routes, cross-namespace

## Rollout Plan

1. Feature-flagged behind existing `-enable-oidc`
2. Plus-only (gated in validation)
3. VirtualServer/VSR only (no Ingress in v1)
4. NJS OIDC unchanged — both coexist, users migrate at their own pace
