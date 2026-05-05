---
name: nic-structure
description: 'NIC architecture, resource processing pipeline, template systems, and key type definitions. Use when exploring the codebase, understanding data flow, debugging config generation, or working on controller logic.'
---

# NIC Architecture and Structure

## Repository Layout

```text
cmd/nginx-ingress/              Main binary entry point
pkg/apis/configuration/v1/
  types.go                      CRD struct definitions (source of truth)
  zz_generated.deepcopy.go      Auto-generated DeepCopy (never edit)
pkg/apis/configuration/validation/
  policy.go                     ValidatePolicy entry point
  virtualserver.go              VirtualServer/VSR validation
pkg/client/                     Auto-generated typed clients, informers, listers
internal/k8s/
  controller.go                 Informer setup, sync loop, task dispatch
  policy.go                     syncPolicy handler
  handlers.go                   Event handler factories
  configuration.go              In-memory resource state
  secrets/                      Secret store and validation
  policies/policy_refs.go       Policy reference conversion
internal/configs/
  configurator.go               Orchestrator: merge config, render, write, reload
  virtualserver.go              VirtualServer -> version2 config generation
  ingress.go                    Ingress -> version1 config generation
  transportserver.go            TransportServer -> version2 stream config generation
  policy.go                     generatePolicies() dispatcher + add*Config() methods
  annotations.go                Annotation constants + parseAnnotations()
  config_params.go              ConfigParams struct + defaults
  configmaps.go                 ConfigMap -> ConfigParams merge
  dos.go                        DoS protection config generation
  common.go                     Shared config utilities
  warnings.go                   Warning accumulation types
  validation_results.go         validationResults type (isError + warnings)
  commonhelpers/                Shared template helper functions (v1 + v2)
  oidc/                         OIDC config files (openid_connect.js, oidc_common.conf)
  njs/                          NJS scripts (apikey_auth.js)
  version1/                     Ingress template structs + .tmpl files
    __snapshots__/              Snapshot golden files
  version2/                     VirtualServer/TS template structs + .tmpl files
    __snapshots__/              Snapshot golden files
internal/nginx/                 NGINX process manager, reload, rollback, version detection
internal/metrics/               Prometheus metrics collectors and listeners
internal/telemetry/             Usage telemetry collection and export
internal/certmanager/           cert-manager integration controller
internal/externaldns/           ExternalDNS integration controller
charts/nginx-ingress/           Helm chart (values.yaml, schema, templates)
charts/tests/                   Helm snapshot tests (terratest + go-snaps)
tests/suite/                    Python integration tests (pytest)
tests/data/                     Test YAML manifests by feature
config/crd/bases/               Generated CRD YAML (from controller-gen)
deploy/                         Pre-built CRD YAML bundles (crds.yaml, crds-nap-*.yaml)
hack/                           update-codegen.sh, verify-codegen.sh
```

---

## Resource Processing Pipeline

```text
kubectl apply -f resource.yaml
  -> K8s API Server persists resource
  -> Informer detects Add/Update/Delete event
  -> Event handler (internal/k8s/) enqueues task onto syncQueue
  -> Controller dispatches: syncPolicy / syncVirtualServer / syncIngress
  -> Validation: pkg/apis/configuration/validation/ (CRD fields)
                 internal/k8s/validation.go (Ingress annotations)
  -> Find affected resources: configuration.FindResourcesForPolicy()
  -> Build extended resources (VirtualServerEx, IngressEx)
  -> Configurator generates NGINX config:
       generatePolicies() -> add*Config() methods -> policiesCfg
       GenerateVirtualServerConfig() -> version2.VirtualServerConfig
       generateNginxCfg() -> version1.IngressNginxConfig
  -> Template executor renders NGINX config text
  -> NginxManager writes file + reloads NGINX
  -> Update resource status + emit events
```

---

## Two Template Systems

| Pipeline | Resources | Package | Templates |
| --- | --- | --- | --- |
| Version 1 | Ingress | `internal/configs/version1/` | `nginx.ingress.tmpl`, `nginx-plus.ingress.tmpl` |
| Version 2 | VirtualServer, VSR, TS | `internal/configs/version2/` | `nginx.virtualserver.tmpl`, `nginx-plus.virtualserver.tmpl` |

- Version 1: `IngressNginxConfig` with multiple `Server` blocks per config
- Version 2: `VirtualServerConfig` with single `Server` block per config
- Main templates (`nginx.tmpl`, `nginx-plus.tmpl`) produce global `nginx.conf`
- Both share `generatePolicies()` in `internal/configs/policy.go`

---

## Policy System

Policies are mutually exclusive: each Policy CR has exactly ONE non-nil field in `PolicySpec`.

**Types**: AccessControl, RateLimit, JWTAuth, ExternalAuth, BasicAuth, IngressMTLS, EgressMTLS, OIDC, WAF, APIKey, Cache, CORS.

**Application levels (VirtualServer)**:

- `spec.policies` -- server-level (all routes unless overridden)
- `route.policies` -- route-level (overrides spec-level)
- `subroute.policies` -- VirtualServerRoute subroute-level

**Ingress**: Policies referenced via `IngressEx.Policies` map. Annotations are Ingress-only, never on VS/VSR.

---

## Key Types

**`policiesCfg`** (`internal/configs/policy.go`): Aggregation struct holding resolved policies per context (Allow/Deny slices, RateLimit, JWTAuth, ExternalAuth, BasicAuth, IngressMTLS, EgressMTLS, OIDC, APIKey, WAF, Cache, CORSHeaders/CORSMap, Context, BundleValidator, ErrorReturn).

**`version2.VirtualServerConfig`**: Top-level struct with HTTP-level directives (Maps, LimitReqZones, CacheZones) and a single Server block.

**`version2.Location`**: Per-route struct with all policy fields (Allow, Deny, LimitReqs, JWTAuth, Cache, CORSEnabled, AddHeaders).

**`version1.IngressNginxConfig`**: Top-level Ingress struct with multiple Server blocks plus Maps, CORSHeaders, LimitReqZones.

**`ConfigParams`** (`config_params.go`): ~125 fields for tunable NGINX params. Flow: defaults -> ConfigMap -> Ingress annotations.

### CRD Struct Pattern

```go
// +kubebuilder:resource:shortName=pol
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
type Policy struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata"`
    Spec              PolicySpec   `json:"spec"`
    Status            PolicyStatus `json:"status"`
}
```

- Types: PascalCase singular. Spec/Status: `<CRD>Spec`, `<CRD>Status`. Lists: `<CRD>List`.
- Short names: `vs`, `vsr`, `ts`, `gc`, `pol`. API group: `k8s.nginx.org/v1`.

### Kubebuilder Markers

| Marker | Purpose |
| --- | --- |
| `+kubebuilder:validation:Required` | Field must be present |
| `+kubebuilder:validation:Optional` | Field is optional |
| `+kubebuilder:validation:Pattern=` `` `regex` `` | Regex validation |
| `+kubebuilder:validation:Minimum=N` | Numeric minimum |
| `+kubebuilder:default=value` | Default value |
| `+kubebuilder:validation:XValidation:rule="CEL"` | Cross-field CEL validation |

### Error Handling

- **Warnings**: `map[runtime.Object][]string` in `internal/configs/warnings.go`
- **validationResults**: `isError bool` + `warnings []string`. When `isError = true`, policy dispatcher returns `ErrorReturn: {Code: 500}`
- **Validation errors**: Kubernetes `field.ErrorList` from `k8s.io/apimachinery/pkg/util/validation/field`
