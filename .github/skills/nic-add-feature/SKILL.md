---
name: nic-add-feature
description: 'Checklists for adding Ingress annotations, VirtualServer/VSR fields, or Helm chart values to NIC. Use when adding new configuration options, new NGINX directives, new annotations, new CRD fields, or new Helm values.'
---

# Adding Features to NIC

## Adding a New Annotation (Ingress Only)

Annotations apply ONLY to Ingress objects, never to VirtualServer or VirtualServerRoute.

1. Add constant in `internal/configs/annotations.go` (e.g., `MyAnnotation = "nginx.org/my-annotation"`)
2. Add field to `ConfigParams` in `internal/configs/config_params.go`
3. Parse it in `parseAnnotations()` in `internal/configs/annotations.go`
4. Update `masterDenylist` / `minionDenylist` if it should not be on master/minion
5. Apply it in `generateNginxCfg()` in `internal/configs/ingress.go`
6. Add the NGINX directive in `internal/configs/version1/nginx.ingress.tmpl` and `internal/configs/version1/nginx-plus.ingress.tmpl`
7. Add validation in `internal/k8s/validation.go` annotation validation chains
8. Add tests in `annotations_test.go` and `ingress_test.go`
9. **Add a snapshot case** in `internal/configs/version1/template_test.go` whose fixture sets the new `ConfigParams` field, then run `make test-update-snaps` and confirm the directive appears in both the OSS and Plus golden files under `internal/configs/version1/__snapshots__/`

### Gotchas

- **Never** forget both OSS and Plus templates -- they are separate files
- Use `containsDangerousChars()` for any user-provided string that ends up in NGINX config
- `parseAnnotations()` silently ignores unknown annotations -- add the constant first
- An unchanged `__snapshots__` diff after a `.tmpl` edit means no fixture exercises the new branch -- the annotation is untested

---

## Adding a New VirtualServer/VSR Field

1. Add field to the appropriate struct in `pkg/apis/configuration/v1/types.go` with kubebuilder markers
2. Run `make update-codegen` and `make update-crds`
3. Add validation in `pkg/apis/configuration/validation/virtualserver.go`
4. Add to the version2 template struct in `internal/configs/version2/http.go`
5. Wire in `internal/configs/virtualserver.go` (`GenerateVirtualServerConfig` or helper)
6. Add template rendering in `nginx.virtualserver.tmpl` / `nginx-plus.virtualserver.tmpl`
7. **Add a snapshot case** in `internal/configs/version2/templates_test.go` that populates the new field in the fixture, then run `make test-update-snaps` and verify the directive appears in both OSS and Plus golden files under `internal/configs/version2/__snapshots__/`
8. Check whether Ingress (v1) needs the same capability as an annotation

### JSON Tag Conventions

- NGINX-proxy-related fields: **kebab-case** (`json:"lb-method"`, `json:"fail-timeout"`)
- K8s/application fields: **camelCase** (`json:"ingressClassName"`, `json:"rewritePath"`)

### Pointer vs Value Types

- `*int`, `*bool`, `*SomeStruct` = optional/nullable
- Plain `int`, `bool` = required or zero-value default
- Booleans defaulting to `false` must be non-pointer

### Kubebuilder Markers

| Marker | Purpose |
| --- | --- |
| `+kubebuilder:validation:Required` | Field must be present |
| `+kubebuilder:validation:Optional` | Field is optional |
| `+kubebuilder:validation:Pattern=` `` `regex` `` | Regex validation |
| `+kubebuilder:validation:Minimum=N` | Numeric minimum |
| `+kubebuilder:validation:MinItems=N` / `MaxItems=N` | Array length |
| `+kubebuilder:validation:MaxLength=N` | Max string length |
| `+kubebuilder:default=value` | Default value |
| `+kubebuilder:validation:XValidation:rule="CEL"` | Cross-field CEL validation |

### CEL Validation Examples

```go
// Prevent wildcard origin with credentials
// +kubebuilder:validation:XValidation:rule="!(self.allowOrigin.exists(origin, origin == '*') && has(self.allowCredentials) && self.allowCredentials == true)",message="..."

// Require time when allowedCodes is set
// +kubebuilder:validation:XValidation:rule="!has(self.allowedCodes) || (has(self.allowedCodes) && has(self.time))",message="..."
```

### Gotchas

- **Never** skip `make update-codegen` after changing `types.go`
- **Never** edit `zz_generated.deepcopy.go` manually
- `make update-crds` also refreshes `deploy/crds*.yaml` and `docs/crd/` -- commit all of it
- `charts/nginx-ingress/crds` is a symlink to `config/crd/bases/` -- never edit it directly
- Version 2 has a single `Server` block; Version 1 has multiple `Server` blocks

---

## Adding a Helm Chart Value

1. Add to `charts/nginx-ingress/values.yaml` with `##` documentation above the field
2. Add JSON schema in `charts/nginx-ingress/values.schema.json`
3. If it maps to a CLI arg: add to `nginx-ingress.args` in `charts/nginx-ingress/templates/_helpers.tpl`
4. If it maps to a ConfigMap key: add to `charts/nginx-ingress/templates/controller-configmap.yaml`
5. If it needs volumes/mounts: add to the volume helpers in `_helpers.tpl`
6. Create a testdata file in `charts/tests/testdata/<feature>.yaml`
7. Add test case in `charts/tests/helmunit_test.go`
8. Run `make test-update-snaps` and confirm `charts/tests/__snapshots__/` contains the rendered value

### Gotchas

- **Always** update all three workload templates (deployment, daemonset, statefulset) when they share logic via helpers
- **Always** update `values.schema.json` alongside `values.yaml`
- Helm tests use terratest + go-snaps: `charts/tests/helmunit_test.go`, gated behind the `helmunit` build tag
- A chart change with no `charts/tests/__snapshots__` diff means no testdata file renders the new value
