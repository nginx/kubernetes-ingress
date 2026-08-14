# NIC Architecture Guide

This document describes the internal architecture of the NGINX Kubernetes Ingress
Controller (NIC) for developers working on the codebase. It covers the primary
layers, how data flows from a Kubernetes API event to an NGINX reload, where
validation occurs, and how secrets are managed.

## How a Kubernetes Controller Works (Brief Primer)

A Kubernetes controller follows a **watch → queue → reconcile** loop:

1. **Informers** establish a watch against the Kubernetes API server and maintain
   a local in-memory cache of resources (Ingress, VirtualServer, Secret, etc.).
2. When a resource changes, the informer fires an **event handler** (Add, Update,
   Delete) which places a lightweight **task** on a work queue.
3. A **sync loop** dequeues tasks one at a time and reconciles the desired state
   (what the user declared) with the actual state (what NGINX is currently
   running).

NIC uses raw [client-go](https://pkg.go.dev/k8s.io/client-go) with
`SharedInformerFactory` and a single work queue — it does **not** use
controller-runtime or the Operator SDK.

---

## Architectural Layers

NIC is organised into five layers with strict ownership boundaries. Knowing which
layer owns a responsibility is the most important thing when deciding where to
place a change.

```text
┌──────────────────────────────────────────────────────────┐
│  Data Model          pkg/apis/configuration/v1/          │
│  (CRD structs)       types.go, zz_generated.deepcopy.go │
├──────────────────────────────────────────────────────────┤
│  Validation          pkg/apis/configuration/validation/  │
│                      internal/k8s/validation.go          │
├──────────────────────────────────────────────────────────┤
│  Controller          internal/k8s/                       │
│  (event loop)        controller.go, handlers.go,         │
│                      configuration.go, secrets/, status  │
├──────────────────────────────────────────────────────────┤
│  Config Generation   internal/configs/                   │
│                      configurator.go, virtualserver.go,  │
│                      ingress.go, policy.go, version1/,   │
│                      version2/                           │
├──────────────────────────────────────────────────────────┤
│  Process Management  internal/nginx/                     │
│                      manager.go, rollback_manager.go     │
└──────────────────────────────────────────────────────────┘
```

### What each layer owns

| Layer | Package(s) | Responsibility |
| --- | --- | --- |
| Data model | `pkg/apis/configuration/v1/` | CRD Go struct definitions with kubebuilder markers. Auto-generated DeepCopy. Source of truth for the API. |
| Validation | `pkg/apis/configuration/validation/`, `internal/k8s/validation.go` | Field-level CRD validation (VirtualServer, Policy, TransportServer). Ingress annotation validation. Returns `field.ErrorList`. |
| Controller | `internal/k8s/` | Informer setup, event handlers, sync dispatch, in-memory resource state, secret resolution, status updates, Kubernetes event emission. |
| Config generation | `internal/configs/`, `version1/`, `version2/` | Converts extended resources (`VirtualServerEx`, `IngressEx`) into NGINX config structs, renders `.tmpl` templates into config text, writes files. |
| Process management | `internal/nginx/` | Starts, reloads, and quits the NGINX process. Validates config with `nginx -t`. Manages rollback on failed validation. |

### Layer crossing rules

These are invariants — violating them causes architectural drift and makes the
codebase harder to reason about:

- **Config generation must NOT call the Kubernetes API or access the secret store
  directly.** It receives pre-resolved filesystem paths via extended resources.
- **Controller must NOT generate NGINX config text or render templates.** It hands
  fully assembled extended resources to the Configurator.
- **Data model (`types.go`) must NOT import `internal/configs` or `internal/k8s`.**
  It is a pure API definition with no business logic.
- **Validation must NOT trigger NGINX reloads or update Kubernetes resource
  status.** It only returns errors; the caller decides what to do with them.

---

## Data Flow: From `kubectl apply` to NGINX Reload

```text
kubectl apply -f virtualserver.yaml
  │
  ▼
K8s API Server persists the VirtualServer resource
  │
  ▼
Informer detects the event (Add/Update/Delete)
  │  [internal/k8s/handlers.go — createVirtualServerHandlers()]
  ▼
Event handler enqueues a task onto the syncQueue
  │  [internal/k8s/controller.go — AddSyncQueue()]
  ▼
Sync loop dequeues and dispatches the task
  │  [controller.go — sync() → syncVirtualServer()]
  ▼
Build / update in-memory state → returns []ResourceChange
  │  [internal/k8s/configuration.go — AddOrUpdateVirtualServer()]
  │
  ├─► Validation (CRD fields)
  │     [pkg/apis/configuration/validation/virtualserver.go]
  │
  ├─► Validation (Ingress annotations — Ingress path only)
  │     [internal/k8s/validation.go]
  │
  ├─► Find affected resources (fans out on secret/policy changes)
  │     [configuration.go — FindResourcesForSecret() / FindResourcesForPolicy()]
  │
  ▼
Resolve secret references → SecretReference{Path, Error}
  │  [controller.go — createVirtualServerEx() calls secretStore.GetSecret()]
  │  Secret store writes valid secrets to /etc/nginx/secrets/ on first reference
  ▼
Build extended resource (VirtualServerEx)
  │  [controller.go — createVirtualServerEx()]
  │  Bundles: VirtualServer + VirtualServerRoutes + Endpoints + SecretRefs + Policies
  ▼
Configurator generates NGINX config
  │  [internal/configs/configurator.go — AddOrUpdateVirtualServer()]
  │
  │  HTTP:    GenerateVirtualServerConfig()  → version2.VirtualServerConfig
  │  Ingress: generateNginxCfg()            → version1.IngressNginxConfig
  │  Stream:  generateTransportServerConfig(...) → *version2.TransportServerConfig
  │  Policies: generatePolicies() → add*Config() → policiesCfg
  │
  ▼
Template executor renders config text from .tmpl files
  │  [version1.TemplateExecutor or version2.TemplateExecutorV2;
  │   TransportServer uses ExecuteTransportServerTemplate(...)]
  ▼
NginxManager writes config file + reloads NGINX
  │  [internal/nginx/ — Manager.CreateConfig() + Manager.Reload()]
  │  On failure: ConfigRollbackManager rolls back to previous working config
  ▼
Update resource status + emit Kubernetes events
   [controller.go — updateVirtualServerStatusAndEvents()]
   [k8s/status.go — statusUpdater.UpdateVirtualServerStatus()]

   Note: status updates happen AFTER the reload returns.
   During startup (before NGINX is ready), status updates are deferred
   into pendingVSStatus slices and flushed asynchronously after the
   first successful reload.
```

### The same flow applies to other resources

| Resource | Sync handler | Extended resource | Config generator |
| --- | --- | --- | --- |
| VirtualServer | `syncVirtualServer()` | `VirtualServerEx` | `GenerateVirtualServerConfig()` |
| Ingress | `syncIngress()` | `IngressEx` / `MergeableIngresses` | `generateNginxCfg()` |
| TransportServer | `syncTransportServer()` | `TransportServerEx` | `GenerateTransportServerConfig()` |
| Policy | `syncPolicy()` | — (fans out to VS/Ingress) | `generatePolicies()` |
| Secret | `syncSecret()` | — (fans out to VS/Ingress) | (via affected resources) |

---

## Validation

Validation happens at two levels and is always completed **before** config
generation:

### 1. CRD field validation (`pkg/apis/configuration/validation/`)

- Structural validation of VirtualServer, VirtualServerRoute, TransportServer,
  and Policy resources.
- Uses the standard Kubernetes `field.ErrorList` pattern.
- Examples: regex pattern checks on paths, valid NGINX directive values, mutual
  exclusivity of policy fields.
- Some validation is also done at the CRD schema level via kubebuilder markers
  (enum, pattern, minimum) and CEL `XValidation` rules — these are enforced by
  the API server before the controller ever sees the resource.

### 2. Ingress annotation validation (`internal/k8s/validation.go`)

- Validates annotation values on Ingress resources (e.g., valid size strings,
  valid proxy settings).
- Only applies to the Ingress (v1) path. VirtualServer/VirtualServerRoute use
  typed CRD fields instead of annotations.

### Where validation does NOT happen

- The config generation layer (`internal/configs/`) trusts that input has already
  been validated. It does not re-validate CRD fields.
- NGINX itself performs a final syntax check (`nginx -t`) after config files are
  written. If this fails, the `ConfigRollbackManager` restores the previous
  working configuration.

---

## Secret Store

The secret store (`internal/k8s/secrets/`) manages Kubernetes Secrets that NIC
uses for TLS certificates, JWKs, OIDC client secrets, and more. It sits entirely
in the **controller layer**.

### Two-phase model

**Phase 1 — In-memory validation** (`SecretStore.AddOrUpdateSecret()`):

When a Secret event arrives, the store validates the secret (correct type, valid
TLS cert/key, etc.) and records a `SecretReference{Secret, Error}` in memory.
It does **not** write to the filesystem unless a path already exists for that
secret (avoiding leftover files for unreferenced secrets).

**Phase 2 — Lazy filesystem write** (`SecretStore.GetSecret()`):

When the controller builds an extended resource (`createVirtualServerEx()`,
`createIngressEx()`), it calls `GetSecret()`. If the secret is valid and not yet
on disk, the store materializes supported secrets under `/etc/nginx/secrets/` via the
`SecretFileManager` interface (implemented by `Configurator`). The exact filename is
derived from `<namespace>-<secretName>` rather than a single path, and some secret types
create multiple files (for example, CA cert/CRL files). Secrets such as OIDC and API key
secrets are not written to disk, so their `Path` is empty. The returned `SecretReference`
contains the filesystem `Path` the config generation layer needs when a file-backed secret
is used.

### Supported secret types

| Constant | Kubernetes type | Used for |
| --- | --- | --- |
| — | `kubernetes.io/tls` | TLS server certificates |
| `SecretTypeCA` | `nginx.org/ca` | CA cert for mTLS / upstream trust |
| `SecretTypeJWK` | `nginx.org/jwk` | JWT validation keys |
| `SecretTypeOIDC` | `nginx.org/oidc` | OIDC client secret |
| `SecretTypeHtpasswd` | `nginx.org/htpasswd` | HTTP Basic auth |
| `SecretTypeAPIKey` | `nginx.org/apikey` | API key auth |
| `SecretTypeLicense` | `nginx.com/license` | NGINX Plus license |

### Special secrets

Some secrets are not referenced by user resources but are required by the
controller itself (default server TLS, wildcard TLS, NGINX Plus license, mgmt
client cert, mgmt trusted CA). These are handled by
`handleSpecialSecretUpdate()` in the controller, which triggers an NGINX reload
directly — independent of any resource re-sync.

### Key invariant

**The controller resolves secrets and attaches the resolved references; config
generation consumes `secrets.SecretReference` values only.** The extended
resources (`VirtualServerEx.SecretRefs`, `IngressEx.SecretRefs`) carry
`map[string]*secrets.SecretReference`. Config generation may read resolved data
from those references, including `.Path`, `.Secret.Type`, and secret payload
from `.Secret.Data` where needed, but it must not call `SecretStore.GetSecret()`
or the Kubernetes API directly.

---

## NGINX Reload and Rollback

### Normal reload flow

1. `Configurator` calls `Manager.CreateConfig(name, content)` to write the
   rendered config file to disk.
2. `Configurator` calls `Manager.Reload()` which:
   - Increments and writes a config version number.
   - Sends `nginx -s reload` to the NGINX process.
   - Waits for NGINX to confirm it loaded the new version.
   - Records metrics (reload count, duration, errors).

### Rollback protection (`ConfigRollbackManager`)

When rollback is enabled, `CreateConfig()` follows a safe write sequence:

1. Read existing config file (if any) as a backup.
2. Write new config content.
3. Run `nginx -t` to validate.
4. **If validation passes** — proceed to reload.
5. **If validation fails** — restore the backup, re-run `nginx -t`, and reload
   with the known-good config. If even the rollback fails, the bad config file
   is deleted (unless it is the main `nginx.conf`).

This protects against a single bad resource taking down the entire NGINX
instance.

### NGINX Plus dynamic reconfiguration

For NGINX Plus, upstream server changes (endpoint updates) can be applied via the
NGINX Plus API without a full reload, avoiding traffic disruption. Weight changes
below a threshold are also handled dynamically.

---

## Two Template Systems

NIC maintains two separate template pipelines. Always update both when a feature
could apply to either path.

| Pipeline | Resources | Package | Templates |
| --- | --- | --- | --- |
| Version 1 | Ingress | `internal/configs/version1/` | `nginx.ingress.tmpl`, `nginx-plus.ingress.tmpl` |
| Version 2 | VirtualServer, VSR, TransportServer | `internal/configs/version2/` | `nginx.virtualserver.tmpl`, `nginx-plus.virtualserver.tmpl` |

- **Version 1**: `IngressNginxConfig` struct with multiple `Server` blocks.
- **Version 2**: `VirtualServerConfig` struct with a single `Server` block.
- **Main templates** (`nginx.tmpl`, `nginx-plus.tmpl`) produce the global
  `nginx.conf`.
- Both pipelines share `generatePolicies()` in `internal/configs/policy.go`.
- OSS and Plus templates are separate files — always update both when making
  template changes.

---

## Key Source Files

| File | What to look at it for |
| --- | --- |
| `pkg/apis/configuration/v1/types.go` | CRD struct definitions — the source of truth for the API |
| `pkg/apis/configuration/validation/policy.go` | How policy fields are validated |
| `internal/k8s/controller.go` | Sync handlers, extended resource construction, status updates |
| `internal/k8s/configuration.go` | In-memory resource state and change detection |
| `internal/k8s/handlers.go` | Event handler registration for each resource type |
| `internal/k8s/secrets/store.go` | SecretStore interface and LocalSecretStore implementation |
| `internal/configs/configurator.go` | Orchestrator that ties config generation to NGINX reload |
| `internal/configs/virtualserver.go` | VirtualServer → version2 config struct conversion |
| `internal/configs/policy.go` | `generatePolicies()` dispatcher and `add*Config()` methods |
| `internal/nginx/manager.go` | NGINX process management (start, reload, quit) |
| `internal/nginx/rollback_manager.go` | Write-validate-rollback protection |
