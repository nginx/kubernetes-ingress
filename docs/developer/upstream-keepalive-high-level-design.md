# High-Level Design: Upstream Keepalive Defaults

> Status: Proposal
>
> Related issue: [#10322](https://github.com/nginx/kubernetes-ingress/issues/10322)

## Overview

NGINX 1.29.7+ and NGINX Plus R37+ enable upstream keepalive by default.
NGINX Ingress Controller (NIC) must distinguish an omitted keepalive setting
from an explicit zero so that users can adopt the NGINX default or disable it.

This proposal applies to the ConfigMap `keepalive` key, the Ingress
`nginx.org/keepalive` annotation, and the VirtualServer and VirtualServerRoute
upstream `keepalive` field. NIC writes an upstream `keepalive` directive only
when a value has been configured. An explicit `0` disables keepalive and sends
`Connection: close` for ordinary HTTP/1.1 upstream requests.

The external APIs remain unchanged. Configuration generation represents the
resolved value as a string, keeping unset (`""`), zero (`"0"`), and a positive
value distinct without a separate `HasKeepalive` flag.

## Goals

- Write no upstream `keepalive` directive when the setting is absent from
  the ConfigMap, annotation, and applicable VS/VSR upstream field.
- Render every explicitly configured value, including `0` and `32`.
- Use `keepalive N local;` for configured values, with a simple template
  presence check and no special case for NGINX's default of `32`.
- Send `Connection: close` for explicit `0` on ordinary HTTP/1.1 upstream
  requests, and omit keepalive-related header overrides for unset or positive
  values.
- Preserve existing setting precedence and WebSocket, gRPC, HTTP/1.0, and
  HTTP/2 handling in both NGINX and NGINX Plus templates.
- Verify upstream connection reuse and received headers, not only generated
  configuration strings.

## Non-Goals

- New annotations, CRD fields, or Helm values.
- Changing master/minion annotation inheritance.
- Changing HTTP-version resolution or removing explicitly configured
  `proxy_http_version 1.1;` directives. The existing templates already omit
  `proxy_http_version` when the resolved version is unset.
- Changing WebSocket upgrade maps or gRPC handling.
- Changing downstream client keepalive, upstream `max-conns`, or other
  keepalive-related timeout and request-limit settings.

## Background

The NGINX [keepalive directive documentation](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive)
defines `keepalive connections [local];` in the `upstream` context. Since
1.29.7, its default is `keepalive 32 local;`, and zero disables upstream
keepalive. The `local` parameter prevents reuse across different locations.
The connection count limits idle cached connections per worker, not total
active connections.

The [NGINX announcement](https://blog.nginx.org/blog/keep-alive-to-upstreams-is-now-default-in-nginx-1-29-7)
also explains the new HTTP/1.1 and cleared `Connection` header defaults.

NIC's integer keepalive representation loses the distinction between unset
and zero during configuration generation. Ingress further converts only
positive values to its template string. Both upstream templates skip zero
because their presence checks evaluate an integer zero as false.

VirtualServer locations use `HasKeepalive` to select the ordinary upstream
connection header. With the historical zero default, they select `close`
even when the user has not configured keepalive. This overrides NGINX's new
default instead of allowing it to apply.

## User Contract

### Existing setting precedence (unchanged)

- **Ingress:** existing precedence is unchanged: the
  `nginx.org/keepalive` annotation overrides the ConfigMap `keepalive` key.
  Existing master/minion inheritance is also unchanged.
- **VirtualServer and VirtualServerRoute:** existing precedence is unchanged:
  an explicitly set upstream `keepalive` field overrides the ConfigMap key,
  including when set to zero.

### Rendering and behavior

The following contract applies to ordinary HTTP/1.1 requests, excluding
WebSocket upgrades:

When no source supplies a value, NIC renders no upstream `keepalive`
directive and NGINX applies its default of `32`. NIC does not assign `32`
during configuration generation.

| User setting | Resolved internal value | Upstream configuration | Ingress location override | VirtualServer location override |
| --- | --- | --- | --- | --- |
| Unset everywhere | `""` | No `keepalive` directive | None | No `set $default_connection_header` |
| Explicit `0` | `"0"` | `keepalive 0 local;` | `proxy_set_header Connection close;` | `set $default_connection_header close;` |
| Explicit positive `N` | `"N"` | `keepalive N local;` | None | No `set $default_connection_header` |

An explicit `32` is rendered as `keepalive 32 local;`, even though it equals
NGINX's default. Rendering depends on presence, not comparison with `32`.
An invalid value is rejected through the existing validation/error-reporting
path and must not reach a template.

## Architecture

### Affected layers

| Layer | Proposed change |
| --- | --- |
| External APIs | None; ConfigMap and annotation values remain strings, and the VS/VSR API field remains an optional integer |
| Input validation | Validate and normalize the ConfigMap and annotation integer values; retain existing VS/VSR nonnegative validation |
| Configuration types | `ConfigParams.Keepalive` and `version2.Upstream.Keepalive` become strings; replace `version2.Location.HasKeepalive` with `Keepalive string`; retain the Ingress upstream string |
| Configuration builders | Propagate the effective string into upstreams and locations, including explicit zero |
| Templates | Conditional upstream rendering and explicit-zero header handling in both OSS and Plus variants |
| Controller, process management, Helm, telemetry | No changes |

There is no public API type change, so this proposal does not require CRD or
client-code generation.

### Value resolution

In [`config_params.go`](../../internal/configs/config_params.go), change
`ConfigParams.Keepalive` from `int` to `string`, leaving its default empty.
Do not assign `32` in `NewDefaultConfigParams()`.

In [`configmaps.go`](../../internal/configs/configmaps.go) and
[`annotations.go`](../../internal/configs/annotations.go), parse and validate
the supplied integer, then store `strconv.Itoa(value)`. This normalizes input
such as `"00"` to `"0"`, so the explicit-zero comparison is reliable.

Ingress retains `version1.Upstream.Keepalive string` in
[`version1/config.go`](../../internal/configs/version1/config.go).
`createUpstream` and `createExternalAuthUpstream` in
[`ingress.go`](../../internal/configs/ingress.go) assign the resolved string
directly instead of dropping nonpositive values. Locations already carry
their upstream; no extra Ingress location field is needed.

In [`version2/http.go`](../../internal/configs/version2/http.go), change
`Upstream.Keepalive` to `string` and replace `Location.HasKeepalive bool` with
`Location.Keepalive string`.

In [`virtualserver.go`](../../internal/configs/virtualserver.go), use one
resolution helper for both upstreams and proxying locations: return
`strconv.Itoa(*upstream.Keepalive)` when the API pointer is non-nil, otherwise
return the ConfigMap string. Delete `upstreamHasKeepalive`; the resolved value
provides both presence and explicit-zero information.

### Upstream templates

Apply the same presence check to both
[Ingress](../../internal/configs/version1/nginx.ingress.tmpl) and
[Plus Ingress](../../internal/configs/version1/nginx-plus.ingress.tmpl)
templates:

```gotemplate
{{- if $upstream.Keepalive}}
keepalive {{$upstream.Keepalive}} local;
{{- end}}
```

Use the equivalent `$u` block in the
[VirtualServer](../../internal/configs/version2/nginx.virtualserver.tmpl) and
[Plus VirtualServer](../../internal/configs/version2/nginx-plus.virtualserver.tmpl)
templates. A nonempty string `"0"` is true in a Go template presence check and
therefore renders the directive; an empty string renders nothing.

### Ingress connection headers

Keep the existing HTTP-version and WebSocket branches. Within ordinary
HTTP/1.1, non-WebSocket handling, replace the positive-keepalive
`Connection ""` override with:

```gotemplate
{{- if eq $location.Upstream.Keepalive "0"}}
proxy_set_header Connection close;
{{- end}}
```

Unset and positive values require no ordinary header override. The existing
WebSocket map still selects `upgrade`, HTTP/1.0 still sends `close`, and
HTTP/2 still omits hop-by-hop headers.

### VirtualServer variable flow

Retain these existing maps in the main OSS and Plus templates:

```nginx
map $http_upgrade $default_connection_header {
    default "";
}

map $http_upgrade $vs_connection_header {
    default upgrade;
    ''      $default_connection_header;
}
```

The first map defines `$default_connection_header` globally and supplies an
empty default. Its existence does not depend on a location emitting `set`.
The second map selects `upgrade` for an upgrade request, or the ordinary
connection-header value otherwise.

Only explicit zero overrides that default in the VirtualServer location:

```gotemplate
{{- if and (ne $l.ProxyHTTPVersion "2") (ne $l.ProxyHTTPVersion "1.0") (eq $l.Keepalive "0") }}
set $default_connection_header close;
{{- end }}
```

Keep `proxy_set_header Connection $vs_connection_header;` in the existing
HTTP/1.1 branch. An empty resolved value suppresses the upstream header; it
does not send an empty header. Do not generate the redundant per-location
`set $default_connection_header "";` for unset or positive values.

## Security Model

No new credentials, Secret references, privileges, RBAC rules, or raw
configuration inputs are introduced.

Keepalive input is still numeric even though its internal representation
becomes a string. ConfigMap and annotation values must parse as integers and
be nonnegative before conversion with `strconv.Itoa`. VS/VSR values retain
the existing nonnegative-integer validation. Only canonical decimal digits
reach the templates, preventing directive injection. Templates must not
render the original unvalidated text.

Rejected input must be logged or reported through the existing resource
error/event handling without generating an invalid NGINX directive. Test
negative, non-integer, and configuration-injection strings as rejected input.

## Compatibility

This proposal adopts the NGINX 1.29.7+ / Plus R37+ default rather than
preserving NIC's historical VirtualServer close-by-default behavior. Existing
VirtualServers that require nonpersistent upstream connections must explicitly
set `keepalive: 0`, either in their upstreams or through the ConfigMap.

Adding `local` also prevents sharing cached connections across locations for
users with an explicit positive keepalive value. Document both behavior
changes in the release note and configuration reference.

The syntax depends on versions that support `local` and `keepalive 0`.
Custom images using older NGINX versions are not compatible with explicitly
generated `keepalive N local;`. When the setting is omitted, those versions
retain their own older defaults. This proposal does not add version detection
or alternate templates for such images.

## Delivery Plan

1. Write/update validation, propagation, and template tests to encode the
   user contract, and add the four behavior-test cases described below.
2. Change the internal configuration types and validated value conversion.
3. Update Ingress and VS/VSR value propagation, replacing the boolean helper
   with the common string resolver.
4. Update all four upstream templates and both resource types' connection
   header handling. Update inline template copies in the executor and
   configurator tests to match.
5. Generate snapshots, review each changed directive, and run the tests.
   Correct compilation errors; report actual assertion or runtime failures
   before attempting fixes.
6. Update configuration references and release notes after verification.

## Verification

### Go unit tests

- ConfigMap and annotation parsing: missing, zero, positive, normalization,
  and rejected invalid values. Missing input preserves the inherited value;
  explicit zero overrides a positive value.
- VS/VSR resolution: unset field falls back to the ConfigMap, explicit zero
  overrides a positive ConfigMap value, and a positive field overrides a
  zero ConfigMap value.
- Configuration propagation: upstream and location receive the same resolved
  value, including explicit zero. Retain existing mergeable Ingress
  inheritance coverage without adding special inheritance logic.
- Remove `TestUpstreamHasKeepalive` with the deleted helper; test the resolved
  value rather than a separate enabled flag.

### Template and snapshot tests

Exercise unset, explicit zero, and positive values in OSS and Plus templates
for both resource types. Include explicit `32` to prove it is not omitted
just because it equals the NGINX default.

- Unset: no upstream `keepalive` directive and no keepalive-related location
  override.
- Zero: `keepalive 0 local;` and the appropriate `close` directive.
- Positive: `keepalive N local;` and no ordinary header override.
- Ingress mixed-upstream tests must no longer expect `Connection ""` for
  positive values.
- VirtualServer tests must expect no location-level
  `set $default_connection_header` for unset or positive values, but retain
  `proxy_set_header Connection $vs_connection_header;` for HTTP/1.1.
- Keep existing WebSocket, gRPC, HTTP/1.0, and HTTP/2 regression coverage.

Run `make test-update-snaps` and inspect the nonempty snapshot diff. Expected
changes are `local` on rendered keepalive directives, removal of redundant
empty overrides and default VirtualServer `close`, and explicit zero rendering
both the upstream directive and `close` handling. Snapshot regeneration alone
does not establish runtime correctness.

### Python integration tests

Add one focused module with a single backend replica that returns
`$connection_requests` and `$http_connection`. Once the tested configuration
has been applied successfully, send five sequential requests through a fresh
`requests.Session()` for each case, consuming each response. Do not change
the controller's worker count.

| Resource | Setting | Backend connection assertions | Received header assertion |
| --- | --- | --- | --- |
| VirtualServer | Unset | At least one `$connection_requests` value is greater than 1 | `$http_connection` is empty |
| VirtualServer | `upstreams[].keepalive: 0` | Every `$connection_requests` value is 1 | `$http_connection` is `close` |
| Ingress | Unset | At least one `$connection_requests` value is greater than 1 | `$http_connection` is empty |
| Ingress | `nginx.org/keepalive: "0"` | Every `$connection_requests` value is 1 | `$http_connection` is `close` |

These are the four behavior cases. Value precedence and positive-value
rendering are covered by Go tests rather than expanding the Python matrix.

Update the existing VS, VSR, and ConfigMap configuration-string tests:

- Positive values expect `keepalive N local;` and no location-level
  `set $default_connection_header`.
- Unset expects no upstream `keepalive ` directive and no location-level
  `set $default_connection_header`.
- Explicit zero expects `keepalive 0 local;` and
  `set $default_connection_header close;` in VirtualServer locations.

Scope substring assertions to the tested configuration. Use `keepalive `,
including the space, rather than `keepalive`, which also matches unrelated
directives such as `keepalive_time`. Register a new pytest marker in
[`pyproject.toml`](../../pyproject.toml) if one is introduced.

### Gates and documentation

Run `make test` and `make lint`, review the generated snapshots, and run the
four integration cases with the changed controller image. The implementation
is not verified until those runtime cases execute successfully.

Document the effective default as `32`, explicit zero as disabling keepalive,
and the `local` behavior in:

- [ConfigMap reference](https://docs.nginx.com/nginx-ingress-controller/configuration/global-configuration/configmap-resource/)
- [Ingress annotation reference](https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/advanced-configuration-with-annotations/)
- [VirtualServer and VirtualServerRoute reference](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)

No API types, generated clients, CRDs, Helm values, or telemetry schemas are
changed, so their generators and dedicated test suites are not required by
this proposal.
