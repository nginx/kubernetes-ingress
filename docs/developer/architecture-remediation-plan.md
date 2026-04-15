# Architecture Remediation Plan

This document is an executable implementation plan for improving the separation of concerns,
reducing coupling, and making the codebase easier to extend. Each phase is a standalone unit
of work that can be shipped as one or more PRs with no change in user-facing behaviour.

AI agents implementing any phase MUST read the referenced files in full before making changes,
run `make test` after every logical change, and never combine phases in a single PR.

---

## Table of Contents

- [Current Architecture](#current-architecture)
- [Identified Boundary Violations](#identified-boundary-violations)
- [Phase 1: Eliminate Duplicate Constants and Types](#phase-1-eliminate-duplicate-constants-and-types)
- [Phase 2: Relocate Shared Packages Out of k8s/](#phase-2-relocate-shared-packages-out-of-k8s)
- [Phase 3: Encapsulate Configurator State](#phase-3-encapsulate-configurator-state)
- [Phase 4: Define a Configurator Interface](#phase-4-define-a-configurator-interface)
- [Phase 5: Internalize Template Executor Creation](#phase-5-internalize-template-executor-creation)
- [Phase 6: Split God Objects](#phase-6-split-god-objects)
- [Phase 7: Extract Metrics Label Management](#phase-7-extract-metrics-label-management)
- [Validation Checklist](#validation-checklist)

---

## Current Architecture

The codebase has five logical layers. Data flows top-to-bottom.

```
+-------------------------------------------------------------------+
|  Layer 1 -- Entry Point          cmd/nginx-ingress/               |
|  main.go, flags.go, utils.go                                      |
|  Wires all objects, creates K8s clients, starts NGINX process      |
+------------------------------+------------------------------------+
                               |
                               v
+-------------------------------------------------------------------+
|  Layer 2 -- K8s Controller       internal/k8s/                    |
|  LoadBalancerController (controller.go ~3930 LOC)                  |
|  Watches K8s API, resolves endpoints, builds enriched resource     |
|  bundles (*Ex types), manages status, leader election              |
|  Sub-packages: secrets/, policies/, appprotect/, appprotectdos/    |
+------------------------------+------------------------------------+
                               |
                               v
+-------------------------------------------------------------------+
|  Layer 3 -- Config Generation    internal/configs/                |
|  Configurator (configurator.go ~2185 LOC)                          |
|  Translates enriched bundles into NGINX config structs, renders    |
|  Go templates, manages NGINX Plus dynamic upstream updates         |
|  Sub-packages: version1/ (Ingress), version2/ (VS/TS), oidc/,njs/ |
+------------------------------+------------------------------------+
                               |
                               v
+-------------------------------------------------------------------+
|  Layer 4 -- NGINX Process Mgmt   internal/nginx/                  |
|  Manager interface + LocalManager / FakeManager / RollbackManager  |
|  Writes config files, reloads NGINX, manages Plus API client       |
+-------------------------------------------------------------------+

+-------------------------------------------------------------------+
|  Layer 5 -- API Types            pkg/apis/, pkg/client/           |
|  CRD type definitions and generated K8s client code                |
+-------------------------------------------------------------------+

+-------------------------------------------------------------------+
|  Supporting Packages             internal/                        |
|  certmanager, externaldns, healthcheck, logger, metrics,           |
|  telemetry, validation, metadata, license_reporting, nsutils,      |
|  common_cluster_info                                               |
+-------------------------------------------------------------------+
```

### Intended dependency direction

```
cmd  -->  k8s  -->  configs  -->  nginx
                       |
                       +--> version1, version2
All layers  -->  pkg/apis (CRD types)
```

---

## Identified Boundary Violations

Each violation is tagged with the phase that resolves it.

### BV-1: Exported mutable fields on Configurator (Phase 3)

`Configurator.CfgParams` and `Configurator.MgmtCfgParams` are exported struct fields.
The k8s controller layer reads and writes them directly:

- `internal/k8s/controller.go:907`  -- `lbc.configurator.CfgParams = cfgParams`
- `internal/k8s/controller.go:908`  -- `lbc.configurator.MgmtCfgParams = mgmtCfgParams`
- `internal/k8s/controller.go:928`  -- `lbc.configurator.MgmtCfgParams.Secrets.TrustedCRL = secret.Name`
- `internal/k8s/controller.go:1104` -- `lbc.configurator.CfgParams.ZoneSync.Domain`
- `internal/k8s/controller.go:2388` -- `lbc.configurator.CfgParams.ZoneSync.Enable`
- `internal/k8s/controller.go:2534` -- `lbc.configurator.CfgParams.ZoneSync.Enable`
- `internal/k8s/service.go:139`     -- `lbc.configurator.CfgParams.ZoneSync.Enable && ...Port`
- `internal/k8s/controller.go:1957-1958` -- `lbc.configurator.MgmtCfgParams.Secrets.ClientAuth`
- `internal/healthcheck/healthcheck.go:29` -- `cnf.CfgParams.Context`

### BV-2: No interface for Configurator (Phase 4)

`LoadBalancerController.configurator` is typed as `*configs.Configurator` (concrete).
The k8s layer is coupled to every public method and field on the struct.

### BV-3: configs imports k8s sub-packages (Phase 2)

`internal/configs/` imports `internal/k8s/secrets` and `internal/k8s/policies`.
This is a reverse dependency from Layer 3 up into Layer 2's namespace.

Files affected:
- `internal/configs/configurator.go` -- imports `internal/k8s/secrets`
- `internal/configs/ingress.go` -- imports `internal/k8s/secrets` and `internal/k8s/policies`
- `internal/configs/virtualserver.go` -- imports `internal/k8s/secrets`
- `internal/configs/transportserver.go` -- imports `internal/k8s/secrets`
- `internal/configs/policy.go` -- imports `internal/k8s/secrets`

### BV-4: Duplicate constants (Phase 1)

| Constant | Location A | Location B |
|----------|-----------|-----------|
| `JWTKeyKey = "jwk"` | `internal/configs/configurator.go:63` | `internal/k8s/secrets/validation.go:14` |
| `HtpasswdFileKey = "htpasswd"` | `internal/configs/configurator.go:66` | `internal/k8s/secrets/validation.go:23` |
| `ClientSecretKey = "client-secret"` | `internal/configs/configurator.go:75` | `internal/k8s/secrets/validation.go:20` |
| `CACrtKey` / `CAKey = "ca.crt"` | `internal/configs/configurator.go:69` | `internal/k8s/secrets/validation.go:17` |
| `splitClientAmountWhenWeightChangesDynamicReload = 101` | `internal/configs/virtualserver.go:31` | `internal/k8s/controller.go:82` |

### BV-5: Duplicate type UpstreamLabels (Phase 1)

Identical struct in `internal/configs/version1/config.go:9` and `internal/configs/version2/http.go:9`.

### BV-6: Entry point creates template executors (Phase 5)

`cmd/nginx-ingress/main.go` imports `internal/configs/version1` and `internal/configs/version2`
directly to construct `TemplateExecutor` objects. The entry point has knowledge of template
implementation details that should be internal to the config layer.

### BV-7: God objects (Phase 6)

- `internal/k8s/controller.go` -- ~3930 lines, dispatches 15+ resource types in `sync()`
- `internal/configs/configurator.go` -- ~2185 lines, ~85 public methods mixing CRUD, metrics, templates, Plus API

---

## Phase 1: Eliminate Duplicate Constants and Types

**Risk:** Low
**Estimated scope:** ~15 files changed, import-path updates only, plus moving two struct definitions.
**Prerequisite:** None.

### Step 1.1: Consolidate secret-related constants

Create a single source of truth. Until Phase 2 moves the `secrets` package, keep the
canonical constants in `internal/k8s/secrets/validation.go` (where they already exist and
are used for validation). Remove the duplicates from `internal/configs/configurator.go`
and replace all usages with imports from the secrets package.

**Constants to deduplicate:**

| Constant | Keep in | Remove from |
|----------|---------|-------------|
| `JWTKeyKey` | `internal/k8s/secrets/validation.go` | `internal/configs/configurator.go` |
| `HtpasswdFileKey` | `internal/k8s/secrets/validation.go` | `internal/configs/configurator.go` |
| `ClientSecretKey` | `internal/k8s/secrets/validation.go` | `internal/configs/configurator.go` |
| `CACrtKey` | `internal/k8s/secrets/validation.go` (rename `CAKey` to `CACrtKey` here, or alias) | `internal/configs/configurator.go` |

**Actions:**

1. Read `internal/configs/configurator.go` and `internal/k8s/secrets/validation.go` in full.
2. In `internal/k8s/secrets/validation.go`, ensure `CACrtKey = "ca.crt"` exists (currently named `CAKey`).
   Add `CACrtKey` as an alias or rename. If renaming `CAKey` to `CACrtKey`, update all usages of `secrets.CAKey`.
3. Remove `JWTKeyKey`, `HtpasswdFileKey`, `ClientSecretKey`, `CACrtKey` from `internal/configs/configurator.go`.
4. Update all files that referenced `configs.JWTKeyKey` (etc.) to use `secrets.JWTKeyKey` instead.
5. Run `make test`.
6. Also add a `CACrlKey = "ca.crl"` constant to `internal/k8s/secrets/validation.go` if it does not exist,
   then remove the duplicate from `internal/configs/configurator.go`.

### Step 1.2: Consolidate `splitClientAmountWhenWeightChangesDynamicReload`

1. Keep the constant in `internal/configs/virtualserver.go`. Export it:
   `const SplitClientAmountWhenWeightChangesDynamicReload = 101`.
2. Remove the duplicate from `internal/k8s/controller.go`.
3. Update all usages in `internal/k8s/controller.go` to reference
   `configs.SplitClientAmountWhenWeightChangesDynamicReload`.
4. Run `make test`.

### Step 1.3: Consolidate `UpstreamLabels`

1. Create `internal/configs/commonhelpers/upstream_labels.go` (or use the existing
   `internal/configs/commonhelpers/` directory if appropriate):
   ```go
   package commonhelpers

   type UpstreamLabels struct {
       Service           string
       ResourceType      string
       ResourceName      string
       ResourceNamespace string
   }
   ```
2. Update `internal/configs/version1/config.go` to import and alias:
   `type UpstreamLabels = commonhelpers.UpstreamLabels` (type alias preserves all call sites).
3. Update `internal/configs/version2/http.go` the same way.
4. Run `make test`.

### Verification

```bash
# Confirm no remaining duplicates
grep -rn 'JWTKeyKey' internal/configs/configurator.go   # expect 0 matches
grep -rn 'HtpasswdFileKey' internal/configs/configurator.go   # expect 0 matches
grep -rn 'splitClientAmountWhenWeightChangesDynamicReload' internal/k8s/controller.go  # expect 0 definitions
make test
make lint
```

---

## Phase 2: Relocate Shared Packages Out of k8s/

**Risk:** Low (import path changes only, no logic changes).
**Estimated scope:** ~30-40 files changed (import paths).
**Prerequisite:** Phase 1 complete.

### Step 2.1: Move `internal/k8s/secrets/` to `internal/secrets/`

1. `mv internal/k8s/secrets/ internal/secrets/`
2. The package declaration stays `package secrets`.
3. Find and replace the import path `"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"`
   with `"github.com/nginx/kubernetes-ingress/internal/secrets"` across the entire codebase.
4. Run `make test && make lint`.

### Step 2.2: Move `internal/k8s/policies/` to `internal/policies/`

1. `mv internal/k8s/policies/ internal/policies/`
2. The package declaration stays `package policies`.
3. Find and replace the import path.
4. Run `make test && make lint`.

### Step 2.3: Evaluate `internal/k8s/appprotectcommon/`

If `appprotectcommon` is imported by `internal/configs/`, move it to `internal/appprotectcommon/`.
If it is only used within `internal/k8s/`, leave it in place.

Check with:
```bash
grep -rn 'internal/k8s/appprotectcommon' internal/configs/
```

### Verification

```bash
# No remaining references to old paths
grep -rn 'internal/k8s/secrets' --include='*.go' .  # expect 0
grep -rn 'internal/k8s/policies' --include='*.go' .  # expect 0
make test
make lint
```

---

## Phase 3: Encapsulate Configurator State

**Risk:** Medium (changes the public API surface of `Configurator`).
**Estimated scope:** ~10 files changed.
**Prerequisite:** Phase 2 complete.

### Step 3.1: Make config fields unexported

In `internal/configs/configurator.go`, rename:
- `CfgParams` to `cfgParams` (already used by internal methods via this name in some places)
- `MgmtCfgParams` to `mgmtCfgParams`

### Step 3.2: Add accessor methods

Add the following methods to `Configurator`:

```go
// SetConfigParams replaces the current ConfigParams.
func (cnf *Configurator) SetConfigParams(cfg *ConfigParams) {
    cnf.cfgParams = cfg
}

// GetConfigParams returns the current ConfigParams.
// Callers MUST NOT mutate the returned value.
func (cnf *Configurator) GetConfigParams() *ConfigParams {
    return cnf.cfgParams
}

// SetMGMTConfigParams replaces the current MGMTConfigParams.
func (cnf *Configurator) SetMGMTConfigParams(cfg *MGMTConfigParams) {
    cnf.mgmtCfgParams = cfg
}

// GetMGMTConfigParams returns the current MGMTConfigParams.
// Callers MUST NOT mutate the returned value.
func (cnf *Configurator) GetMGMTConfigParams() *MGMTConfigParams {
    return cnf.mgmtCfgParams
}

// IsZoneSyncEnabled reports whether zone sync is enabled in the current config.
func (cnf *Configurator) IsZoneSyncEnabled() bool {
    return cnf.cfgParams != nil && cnf.cfgParams.ZoneSync.Enable
}

// ZoneSyncDomain returns the configured zone sync domain.
func (cnf *Configurator) ZoneSyncDomain() string {
    if cnf.cfgParams == nil {
        return ""
    }
    return cnf.cfgParams.ZoneSync.Domain
}

// ZoneSyncPort returns the configured zone sync port.
func (cnf *Configurator) ZoneSyncPort() int {
    if cnf.cfgParams == nil {
        return 0
    }
    return cnf.cfgParams.ZoneSync.Port
}

// MGMTClientAuthSecretName returns the MGMT client auth secret name.
func (cnf *Configurator) MGMTClientAuthSecretName() string {
    if cnf.mgmtCfgParams == nil {
        return ""
    }
    return cnf.mgmtCfgParams.Secrets.ClientAuth
}

// SetMGMTTrustedCRL sets the trusted CRL name on the MGMT config.
func (cnf *Configurator) SetMGMTTrustedCRL(name string) {
    if cnf.mgmtCfgParams != nil {
        cnf.mgmtCfgParams.Secrets.TrustedCRL = name
    }
}
```

### Step 3.3: Update all external call sites

Replace every direct field access found in the [BV-1 list](#bv-1-exported-mutable-fields-on-configurator-phase-3)
with the corresponding accessor method. Typical replacements:

| Before | After |
|--------|-------|
| `lbc.configurator.CfgParams = cfgParams` | `lbc.configurator.SetConfigParams(cfgParams)` |
| `lbc.configurator.MgmtCfgParams = mgmtCfgParams` | `lbc.configurator.SetMGMTConfigParams(mgmtCfgParams)` |
| `lbc.configurator.MgmtCfgParams.Secrets.TrustedCRL = secret.Name` | `lbc.configurator.SetMGMTTrustedCRL(secret.Name)` |
| `lbc.configurator.CfgParams.ZoneSync.Enable` | `lbc.configurator.IsZoneSyncEnabled()` |
| `lbc.configurator.CfgParams.ZoneSync.Domain` | `lbc.configurator.ZoneSyncDomain()` |
| `lbc.configurator.CfgParams.ZoneSync.Port` | `lbc.configurator.ZoneSyncPort()` |
| `lbc.configurator.MgmtCfgParams.Secrets.ClientAuth` | `lbc.configurator.MGMTClientAuthSecretName()` |
| `cnf.CfgParams.Context` (in healthcheck) | Pass `context.Context` as a function parameter instead |

### Step 3.4: Fix healthcheck package

Change the `RunHealthCheck` signature to accept a `context.Context` parameter instead of
extracting it from `cnf.CfgParams.Context`. Update the call site in `cmd/nginx-ingress/main.go`.

### Verification

```bash
# No external access to the old exported fields
grep -rn '\.CfgParams' internal/k8s/ cmd/  # expect 0
grep -rn '\.MgmtCfgParams' internal/k8s/ cmd/  # expect 0
make test
make lint
```

---

## Phase 4: Define a Configurator Interface

**Risk:** Medium.
**Estimated scope:** ~5-8 files changed.
**Prerequisite:** Phase 3 complete.

### Step 4.1: Audit the methods the controller actually calls

Run this command to list the Configurator methods called from the k8s layer:

```bash
grep -ohP '\.configurator\.\K[A-Z]\w+' internal/k8s/*.go | sort -u
```

Document the result set. Expected ~25-30 methods.

### Step 4.2: Define the interface

Create `internal/configs/configurator_iface.go`:

```go
package configs

// ConfigManager defines the contract between the k8s controller and the config
// generation layer. The LoadBalancerController depends on this interface rather
// than the concrete Configurator struct.
type ConfigManager interface {
    // -- list only the methods found in Step 4.1 --
}
```

Ensure `Configurator` satisfies the interface by adding a compile-time check:

```go
var _ ConfigManager = (*Configurator)(nil)
```

### Step 4.3: Change the controller to use the interface

In `internal/k8s/controller.go`, change:

```go
configurator *configs.Configurator
```

to:

```go
configurator configs.ConfigManager
```

Update `NewLoadBalancerControllerInput.NginxConfigurator` to accept `configs.ConfigManager`.

### Step 4.4: Create a test fake

Create `internal/configs/fake_configurator.go` implementing `ConfigManager` with no-op or
recording methods for use in controller unit tests.

### Verification

```bash
make test
# Confirm the interface is satisfied
go vet ./internal/configs/...
go vet ./internal/k8s/...
```

---

## Phase 5: Internalize Template Executor Creation

**Risk:** Low.
**Estimated scope:** ~3 files changed.
**Prerequisite:** Phase 4 complete (so the interface is in place).

### Step 5.1: Add template path options to ConfiguratorParams

In `internal/configs/configurator.go`, add fields to `ConfiguratorParams`:

```go
type ConfiguratorParams struct {
    // ... existing fields ...
    MainTemplatePath             string
    IngressTemplatePath          string
    VirtualServerTemplatePath    string
    TransportServerTemplatePath  string
    OIDCTemplatePath             string
}
```

### Step 5.2: Move template executor creation into NewConfigurator

Have `NewConfigurator` create `version1.TemplateExecutor` and `version2.TemplateExecutor`
internally based on the template paths and `IsPlus` flag.

Default paths should be set inside `NewConfigurator` when the provided paths are empty.

### Step 5.3: Remove version1/version2 imports from cmd/

Update `cmd/nginx-ingress/main.go`:
1. Remove `createTemplateExecutors()`.
2. Remove imports of `internal/configs/version1` and `internal/configs/version2`.
3. Pass template path overrides directly into `ConfiguratorParams`.

### Verification

```bash
# cmd should no longer import version1 or version2
grep -rn 'configs/version1\|configs/version2' cmd/  # expect 0
make test
```

---

## Phase 6: Split God Objects

**Risk:** Higher (many files renamed/created, large diffs). Ship as a series of sub-PRs.
**Estimated scope:** ~2 files split into ~15 files total.
**Prerequisite:** Phases 1-5 complete.

### General rules for splitting

- Move methods only. Do not change any logic.
- Keep the struct definition and constructor in the original file.
- Each new file gets the same `package` declaration and required imports.
- Run `make test && make lint` after every file move.
- Prefer one new file per sub-PR.

### Step 6.1: Split `internal/k8s/controller.go`

Create the following files by extracting the listed method groups.
The `LoadBalancerController` struct, `NewLoadBalancerController`, `Run`, `Stop`,
`sync` dispatcher, and `AddSyncQueue` remain in `controller.go`.

| New file | Methods to move |
|----------|----------------|
| `sync_ingress.go` | `syncIngress`, `createIngressEx`, `createMergeableIngresses`, `mergeIngressPolicyWarnings`, ingress-related helpers |
| `sync_virtualserver.go` | `syncVirtualServer`, `syncVirtualServerRoute`, `createVirtualServerEx`, `haltIfVSConfigInvalid`, `haltIfVSRConfigInvalid`, `vsHasWeightChanges`, `vsrHasWeightChanges`, weight-change helper methods |
| `sync_transportserver.go` | `syncTransportServer`, `createTransportServerEx` |
| `sync_configmap.go` | `syncConfigMap`, `syncMGMTConfigMap`, `updateAllConfigs` |
| `sync_endpoints.go` | `syncEndpointSlices`, `getEndpointsForIngressBackend`, `getEndpointsForVirtualServer`, endpoint resolution helpers |
| `sync_secret.go` | `syncSecret`, secret-related helper methods |
| `sync_policy.go` | `syncPolicy` |
| `zone_sync.go` | `syncZoneSyncHeadlessService`, `createCombinedDeploymentHeadlessServiceName`, zone-sync helpers |

### Step 6.2: Split `internal/configs/configurator.go`

The `Configurator` struct, `NewConfigurator`, `ConfiguratorParams`, and core reload
orchestration remain in `configurator.go`.

| New file | Methods to move |
|----------|----------------|
| `configurator_ingress.go` | `AddOrUpdateIngress`, `AddOrUpdateIngresses`, `addOrUpdateIngress`, `AddOrUpdateMergeableIngress`, `AddOrUpdateMergeableIngresses`, `addOrUpdateMergeableIngress`, `DeleteIngress`, `BatchDeleteIngresses`, `UpdateEndpoints`, `UpdateEndpointsMergeableIngress`, `updatePlusEndpoints`, `HasIngress`, `HasMinion`, `GetIngressCounts`, `GetIngressAnnotations`, `getStandardIngressAnnotations`, `getMinionIngressAnnotations` |
| `configurator_virtualserver.go` | `AddOrUpdateVirtualServer`, `AddOrUpdateVirtualServers`, `addOrUpdateVirtualServer`, `DeleteVirtualServer`, `BatchDeleteVirtualServers`, `UpdateVirtualServers`, `UpdateEndpointsForVirtualServers`, `updatePlusEndpointsForVirtualServer`, `GetVirtualServerRoutesForVirtualServer`, `GetVirtualServerCounts`, `UpstreamsForHost`, `virtualServerExForHost`, `upstreamsForVirtualServer`, `UpsertSplitClientsKeyVal` |
| `configurator_transportserver.go` | `AddOrUpdateTransportServer`, `addOrUpdateTransportServer`, `DeleteTransportServer`, `deleteTransportServer`, `UpdateTransportServers`, `UpdateEndpointsForTransportServers`, `updatePlusEndpointsForTransportServer`, `GetTransportServerCounts`, `StreamUpstreamsForName`, `transportServerForActionName`, `streamUpstreamsForTransportServer` |
| `configurator_metrics.go` | `updateIngressMetricsLabels`, `deleteIngressMetricsLabels`, `updateVirtualServerMetricsLabels`, `deleteVirtualServerMetricsLabels`, `updateTransportServerMetricsLabels`, `deleteTransportServerMetricsLabels` |
| `configurator_secrets.go` | `AddOrUpdateSecret`, `DeleteSecret`, `AddOrUpdateCASecret`, `addOrUpdateJWKSecret`, `addOrUpdateHtpasswdSecret`, `addOrUpdateTLSSecret`, `AddOrUpdateSpecialTLSSecrets`, `AddOrUpdateLicenseSecret`, `AddOrUpdateMGMTClientAuthSecret`, `AddOrUpdateDHParam`, `DynamicSSLReloadEnabled`, `AddOrUpdateSpiffeCerts` |
| `configurator_appprotect.go` | `AddOrUpdateAppProtectResource`, `DeleteAppProtectPolicy`, `DeleteAppProtectLogConf`, `DeleteAppProtectDosPolicy`, `DeleteAppProtectDosLogConf`, `DeleteAppProtectDosAllowList`, `AddOrUpdateResourcesThatUseDosProtected`, `updateApResources`, `updateApResourcesForMergeableIngresses`, `updateApResourcesForVs`, `updateDosResource` |

### Verification

```bash
# Every Go file should compile
go build ./...
# No methods should be missing
make test
make lint
# File line counts should all be under 600 LOC
wc -l internal/k8s/controller.go internal/k8s/sync_*.go internal/k8s/zone_sync.go
wc -l internal/configs/configurator*.go
```

---

## Phase 7: Extract Metrics Label Management

**Risk:** Medium.
**Estimated scope:** ~3 files changed.
**Prerequisite:** Phase 6 complete (metrics methods already in `configurator_metrics.go`).

### Step 7.1: Create MetricsIndex struct

Create `internal/configs/metrics_index.go`:

```go
package configs

// MetricsIndex tracks the relationship between Ingress Controller resources
// and NGINX configuration objects for Prometheus label management.
type MetricsIndex struct {
    ingressUpstreams             map[string][]string
    virtualServerUpstreams       map[string][]string
    transportServerUpstreams     map[string][]string
    ingressServerZones           map[string][]string
    virtualServerServerZones     map[string][]string
    transportServerServerZones   map[string][]string
    ingressUpstreamPeers         map[string][]string
    virtualServerUpstreamPeers   map[string][]string
    transportServerUpstreamPeers map[string][]string
}

// NewMetricsIndex creates a MetricsIndex with initialized maps.
func NewMetricsIndex() *MetricsIndex { ... }
```

### Step 7.2: Move label update/delete logic onto MetricsIndex

Move the body of each metrics label method from `configurator_metrics.go` into methods on
`MetricsIndex`. The `Configurator` methods become thin wrappers that delegate.

### Step 7.3: Update Configurator

Replace `metricLabelsIndex *metricLabelsIndex` field with `metricsIndex *MetricsIndex`.
Update `NewConfigurator` to use `NewMetricsIndex()`.

### Verification

```bash
make test
make lint
```

---

## Validation Checklist

After all phases are complete, confirm:

- [ ] `make build` succeeds
- [ ] `make test` passes (all unit tests including `-tags=aws,helmunit`)
- [ ] `make lint` passes
- [ ] `make verify-codegen` passes
- [ ] No file in `internal/k8s/` imports `internal/configs/version1` or `internal/configs/version2`
- [ ] No file in `internal/configs/` imports `internal/k8s/` (only `internal/secrets/`, `internal/policies/`)
- [ ] No file in `cmd/` imports `internal/configs/version1` or `internal/configs/version2`
- [ ] `grep -rn '\.CfgParams' internal/k8s/ cmd/` returns zero matches
- [ ] `grep -rn '\.MgmtCfgParams' internal/k8s/ cmd/` returns zero matches
- [ ] `controller.go` is under 800 lines
- [ ] `configurator.go` is under 500 lines
- [ ] Every new file is under 600 lines

---

## Dependency Graph After Remediation

```
cmd/nginx-ingress
  --> internal/k8s            (via ConfigManager interface)
  --> internal/configs        (factory, no version1/v2 direct use)
  --> internal/nginx

internal/k8s
  --> configs.ConfigManager   (interface, not concrete struct)
  --> internal/secrets         (shared package)
  --> internal/policies        (shared package)

internal/configs
  --> internal/secrets         (shared package, clean direction)
  --> internal/policies        (shared package, clean direction)
  --> internal/nginx           (Manager interface, clean)
  --> internal/configs/version1  (internal to configs)
  --> internal/configs/version2  (internal to configs)

internal/secrets               (no upward dependencies)
internal/policies              (no upward dependencies)
```
