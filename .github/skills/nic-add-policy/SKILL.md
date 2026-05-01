---
name: nic-add-policy
description: 'Step-by-step checklist for adding a new Policy CRD type to NIC. Use when implementing a new policy like AccessControl, RateLimit, JWTAuth, ExternalAuth, BasicAuth, IngressMTLS, EgressMTLS, OIDC, WAF, APIKey, Cache, or CORS, or extending the policy system with a new policy type.'
---

# Adding a New Policy Type

Follow these steps IN ORDER. Each step depends on the previous.

## Step 1: Define the CRD type

File: `pkg/apis/configuration/v1/types.go`

- Add a new struct (e.g., `type MyPolicy struct { ... }`)
- Add a `*MyPolicy` pointer field to `PolicySpec`
- Use kubebuilder markers for validation
- JSON tags: **kebab-case** for NGINX-proxy fields, **camelCase** for K8s fields
- `*bool`/`*int` = optional/nullable. Plain `bool`/`int` = required or zero-default
- Booleans defaulting to `false` must be non-pointer value types

## Step 2: Regenerate deep copy

Run `make update-codegen` to update `zz_generated.deepcopy.go`.

## Step 3: Regenerate CRDs

Run `make update-crds` to regenerate `config/crd/bases/`, `deploy/crds.yaml`, and chart CRDs.

## Step 4: Add validation

File: `pkg/apis/configuration/validation/policy.go`

- Add `validate<MyPolicy>(spec *v1.MyPolicy, fieldPath *field.Path) field.ErrorList`
- Wire into `validatePolicySpec()` with field count increment and feature gate check
- Add tests in `policy_test.go` with valid and invalid cases

## Step 5: Add template structs

File: `internal/configs/version2/http.go`

- Add struct (e.g., `type MyPolicyConfig struct { ... }`)
- Add `*MyPolicyConfig` or fields to `Server`, `Location`, or both
- If the policy needs HTTP-level directives (zones, maps), add fields to `VirtualServerConfig`

## Step 6: Add config generation

File: `internal/configs/policy.go`

- Add field(s) to `policiesCfg`
- Add `add<MyPolicy>Config()` method following the pattern below
- Wire into the `switch` in `generatePolicies()`
- Add tests in `policy_test.go`

## Step 7: Wire into VirtualServer generation

File: `internal/configs/virtualserver.go`

- In `GenerateVirtualServerConfig()`, extract from `policiesCfg` and assign to `version2` fields
- Use `addPoliciesCfgToLocation()` for location-level assignment

## Step 8: Wire into Ingress generation (if applicable)

File: `internal/configs/ingress.go`

- In `generateNginxCfg()`, extract from `policiesCfg` and assign to `version1` fields
- Handle mergeable ingress in `generateNginxCfgForMergeableIngresses()`

## Step 9: Add NGINX template directives

- Version 2: `internal/configs/version2/nginx.virtualserver.tmpl` and `nginx-plus.virtualserver.tmpl`
- Version 1: `internal/configs/version1/nginx.ingress.tmpl` and `nginx-plus.ingress.tmpl`
- Use `{{- if }}` / `{{- with }}` guards around directive blocks
- Template helpers go in `template_helper.go`
- HTTP-level directives (zones, maps) go BEFORE `server{}`
- Server-level inside `server{}`, location-level inside each `location{}`

## Step 10: Update snapshot tests

File: `internal/configs/version2/templates_test.go`

- Add new policy fields to test data structs
- Run `make test-update-snaps` to regenerate snapshots
- Verify generated NGINX config in `__snapshots__/`

## Step 11: Update the Helm chart (if policy needs CLI flag or ConfigMap entry)

- `charts/nginx-ingress/values.yaml` -- add value with `##` doc
- `charts/nginx-ingress/values.schema.json` -- add schema entry
- `charts/nginx-ingress/templates/_helpers.tpl` -- add CLI arg or ConfigMap key
- `charts/tests/testdata/` -- add test values file
- `charts/tests/helmunit_test.go` -- add test case

## Step 12: Add controller support

File: `internal/k8s/`

- In `syncPolicy()`, ensure the new type is handled for VS/VSR/Ingress
- Check if it needs feature-gate guarding (isPlus, enableOIDC, etc.)

## Step 13: Write integration tests

Directory: `tests/suite/`

- Create test data YAMLs in `tests/data/<feature>/`
- Create `test_<feature>_policies_vs.py`, `_vsr.py`, `_ingress.py`
- Use `@pytest.mark.policies` and `@pytest.mark.policies_<feature>` markers

---

## Gotchas

- **Never** skip `make update-codegen` after changing `types.go` -- the build will fail with missing DeepCopy methods
- **Never** use raw user strings in NGINX config without `containsDangerousChars()` validation
- Both OSS and Plus templates must be updated -- they are separate files
- `policiesCfg` duplicate check must warn and return, not error (exception: `addCORSConfig` has no duplicate check -- it overwrites, since CORS is additive via headers)

---

## Policy add*Config() Pattern

Every `add*Config()` method in `internal/configs/policy.go` follows this pattern:

```go
func (p *policiesCfg) addMyPolicyConfig(spec *conf_v1.MyPolicy, key, namespace string,
    secretRefs map[string]*secrets.SecretReference) *validationResults {
    res := newValidationResults()

    // 1. Duplicate check
    if p.MyPolicy != nil {
        res.addWarningf("MyPolicy policy already configured, ignoring")
        return res
    }

    // 2. Secret resolution (if applicable)
    secretKey := namespace + "/" + spec.Secret
    secretRef := secretRefs[secretKey]
    if secretRef.Error != nil {
        res.isError = true
        res.addWarningf("secret %s has error: %v", secretKey, secretRef.Error)
        return res
    }
    if secretRef.Type != secrets.SecretTypeExpected {
        res.isError = true
        res.addWarningf("secret %s has wrong type", secretKey)
        return res
    }

    // 3. Build template struct and assign
    p.MyPolicy = &version2.MyPolicyConfig{
        Field1: spec.Field1,
        Field2: spec.Field2,
        Secret: secretRef.Path,
    }

    return res
}
```

## NGINX Template Pattern

```nginx
{{- with $s.MyPolicy }}
my_directive {{ .Value }};
{{- if .OptionalField }}
my_optional_directive {{ .OptionalField }};
{{- end }}
{{- end }}
```
