---
name: nic-testing
description: 'Testing patterns for NIC including Go table-driven tests, snapshot tests, and Python integration tests. Use when writing unit tests, snapshot tests, policy tests, template tests, Helm tests, or pytest integration tests for the Ingress Controller.'
---

# NIC Testing Patterns

## Build and Test Commands

| Command | Purpose |
| --- | --- |
| `make test` | Run all Go tests (`-tags=aws,helmunit -shuffle=on ./...`) |
| `make test-update-snaps` | Regenerate snapshot golden files (`UPDATE_SNAPS=always`) |
| `make lint` | golangci-lint via Docker, diff against `origin/main` |
| `make format` | goimports + gofumpt |
| `make cover` | Generate test coverage report |
| `make lint-python` | Python test formatting: isort + black |

Always use `make test` over raw `go test`. Run `make test-update-snaps` when template output changes.

Note: Helm tests use the `//go:build helmunit` build tag -- they are only compiled and run when `-tags=helmunit` is passed (included in `make test`).

---

## Snapshot Tests -- MANDATORY workflow

This is the single most frequently missed step. Treat it as a hard gate, not an optional cleanup.

### The three snapshot packages

| Package | Golden files | Covers |
| --- | --- | --- |
| `internal/configs/version1` | `internal/configs/version1/__snapshots__/` | Ingress templates (`nginx.tmpl`, `nginx.ingress.tmpl`, and Plus variants) |
| `internal/configs/version2` | `internal/configs/version2/__snapshots__/` | VirtualServer / VSR / TransportServer templates (OSS + Plus) |
| `charts/tests` | `charts/tests/__snapshots__/` | Rendered Helm manifests (terratest, `helmunit` build tag) |

### Trigger table -- if you touched this, snapshots are in scope

| Change | Snapshot action required |
| --- | --- |
| Any `*.tmpl` file | Regenerate **and** add a case that exercises the new directive |
| Template struct field (`version1/config.go`, `version2/http.go`, `version2/stream.go`) | Add the field to the fixture used by the snapshot test, then regenerate |
| Config generation (`internal/configs/*.go`) that changes rendered output | Regenerate; confirm the diff matches the intended output |
| `charts/nginx-ingress/templates/**`, `values.yaml`, `_helpers.tpl` | Add `charts/tests/testdata/<feature>.yaml` + a `helmunit_test.go` case, then regenerate |
| Deleting or renaming a snapshot test | Regenerate -- `snaps.Clean` prunes the obsolete entry from the golden file |

### Required sequence

1. **Add or extend a test case first.** Regenerating alone only re-records existing fixtures. If no fixture sets your new field, the golden file will never contain your directive and the feature ships untested.
2. Run `make test-update-snaps`.
3. Inspect what actually changed:

   ```bash
   git status --short internal/configs/version1/__snapshots__ \
     internal/configs/version2/__snapshots__ charts/tests/__snapshots__
   git diff -- '**/__snapshots__/**'
   ```

4. **Read the diff and confirm your directive is present** in both the OSS and Plus golden output. An empty diff after a `.tmpl` change means no fixture exercises the new branch -- go back to step 1.
5. Run `make test` to confirm the suite is green against the regenerated files.
6. Commit the `__snapshots__` changes in the same commit as the template change.

### Self-check before declaring done

- [ ] Every `.tmpl` I edited has at least one snapshot case that renders the new directive.
- [ ] Both the OSS and Plus golden files changed (or I can explain why only one did).
- [ ] `git diff` on `__snapshots__` is non-empty and reviewed line by line.
- [ ] `make test` passes without `UPDATE_SNAPS`.
- [ ] The regenerated golden files are staged for commit.

---

## Go Unit Tests

### Table-Driven Tests (primary pattern)

```go
func TestValidateMyPolicy(t *testing.T) {
    t.Parallel()
    tests := []struct {
        policy *v1.Policy
        isPlus bool
        msg    string
    }{
        { /* valid case */ },
        { /* edge case */ },
    }
    for _, test := range tests {
        err := ValidatePolicy(test.policy, test.isPlus, false, false)
        if err != nil {
            t.Errorf("ValidatePolicy returned error %v for case: %s", err, test.msg)
        }
    }
}
```

### Naming Convention

Two conventions are in use -- both are acceptable:

**Policy/transport tests** (`policy_test.go`, `transportserver_test.go`):

- `TestValidate<Thing>_PassesOnValidInput`
- `TestValidate<Thing>_FailsOnInvalidInput`

**VirtualServer/general tests** (`virtualserver_test.go` and most other files):

- `TestValidate<Thing>` (valid input, often with subtests)
- `TestValidate<Thing>Fails` (invalid input)
- `TestGenerate<Feature>`

### Snapshot Test Mechanics

Every **package** that uses `snaps.MatchSnapshot` needs exactly one `TestMain` that prunes stale snapshots. It lives in a single file per package (`version1/template_test.go`, `version2/templates_test.go`, `charts/tests/helmunit_test.go`) -- do not add a second one when you create a new test file in an existing package:

```go
func TestMain(m *testing.M) {
    snaps.Clean(m, snaps.CleanOpts{Sort: true})
}
```

Example snapshot test:

```go
func TestVirtualServerForNginx(t *testing.T) {
    t.Parallel()
    executor := newTmplExecutorNGINX(t)
    data, err := executor.ExecuteVirtualServerTemplate(&virtualServerCfg)
    require.NoError(t, err)
    snaps.MatchSnapshot(t, string(data))
}
```

### Helper Conventions

- Always call `t.Parallel()` at the start
- Use `t.Helper()` in helper functions
- Use `github.com/google/go-cmp/cmp` for deep struct comparison
- Use `github.com/gkampitakis/go-snaps/snaps` for snapshot tests

---

## Helm Tests

Location: `charts/tests/`

- `helmunit_test.go` -- Helm snapshot tests using terratest + go-snaps
- `testdata/` -- values.yaml overrides per test scenario

Add a test values file in `charts/tests/testdata/<feature>.yaml` and a corresponding test case in `helmunit_test.go`.

---

## Python Integration Tests

Location: `tests/suite/`

### Markers must be registered

pytest runs with `--strict-markers` (`pyproject.toml`, `[tool.pytest.ini_options] addopts`). Any new `@pytest.mark.<name>` must be added to the `markers` list in [pyproject.toml](pyproject.toml) or the whole suite errors out. If the marker should run in CI, also add it to the relevant smoke matrix in `.github/data/matrix-smoke-*.json`.

### Test Class Pattern

```python
@pytest.mark.policies
@pytest.mark.policies_myfeature
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [({"type": "complete", "extra_args": [...]},
      {"example": "virtual-server", "app_type": "simple"})],
    indirect=True,
)
class TestMyFeaturePolicies:
    def test_basic_functionality(self, kube_apis, crd_ingress_controller,
                                  virtual_server_setup, test_namespace):
        # 1. Create policy from YAML
        pol_name = create_policy_from_yaml(
            kube_apis.custom_objects, yaml_src, test_namespace
        )
        wait_before_test()
        # 2. Patch VS to reference policy
        patch_virtual_server_from_yaml(...)
        # 3. Assert HTTP responses
        resp = requests.get(url, headers={"host": vs_host})
        assert resp.status_code == 200
        assert "Expected-Header" in resp.headers
        # 4. Cleanup
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        patch_virtual_server_from_yaml(...)  # restore original
```

### Fixtures and Utilities

- Common fixtures: `kube_apis`, `crd_ingress_controller`, `virtual_server_setup`, `test_namespace`
- Fixtures: `tests/suite/fixtures/` (setup/teardown lifecycle)
- Utilities: `tests/suite/utils/` (`create_policy_from_yaml`, `patch_virtual_server_from_yaml`, `delete_policy`, `wait_before_test`)
- Prefer event/status-based waits over fixed sleeps when possible

### File Naming

- `test_<feature>_policies_vs.py` -- VirtualServer policy tests
- `test_<feature>_policies_vsr.py` -- VirtualServerRoute policy tests
- `test_<feature>_policies_ingress.py` -- Ingress policy tests

### Test Data

Store YAML manifests in `tests/data/<feature>/`.

---

## Generated Artifacts Verified by CI

`ci.yml` fails the build on any diff after regeneration. Run the matching target and commit the result:

| You changed | Run | CI asserts no diff in |
| --- | --- | --- |
| `pkg/apis/**/types.go` | `make update-codegen` | `pkg/**` |
| `pkg/apis/**` kubebuilder markers | `make update-crds` | `config/crd/bases` (also refreshes `deploy/crds*.yaml` and `docs/crd/`) |
| Telemetry `Data` / `NICResourceCounts` in `internal/telemetry/exporter.go` | `make telemetry-schema` | `internal/telemetry` |
| Any import / dependency | `go mod tidy` | `go.mod`, `go.sum` |
| Any `.tmpl` or template struct | `make test-update-snaps` | snapshot tests fail in `unit-tests` |

`charts/nginx-ingress/crds` is a **symlink** to `config/crd/bases/` -- never edit it directly.

---

## Gotchas

- **Always** run `make test-update-snaps` after changing any `.tmpl` file -- snapshot tests will fail otherwise
- **Regenerating is not the same as testing.** If no fixture sets your new field, the golden file will not change and the feature has zero coverage. Add the test case first
- **Never** run raw `go test` -- use `make test` which includes required build tags (`aws`, `helmunit`)
- Snapshot golden files are in `__snapshots__/` directories -- commit the regenerated files with the change that caused them
- `TestMain` with `snaps.Clean(m, snaps.CleanOpts{Sort: true})` is **per package**, not per file -- adding a second one to the same package breaks the build
- OSS and Plus templates are separate files, so they have separate snapshot entries -- a one-sided diff usually means you forgot the sibling template
- New pytest markers must be registered in `pyproject.toml` -- `--strict-markers` is enabled
- Python tests use `indirect=True` parametrize for IC + VS setup -- do not remove this
