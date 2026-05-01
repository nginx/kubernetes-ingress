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

### Snapshot Tests (template output)

Every test file that uses `snaps.MatchSnapshot` must have a `TestMain` that cleans up stale snapshots:

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

## Gotchas

- **Always** run `make test-update-snaps` after changing any `.tmpl` file -- snapshot tests will fail otherwise
- **Never** run raw `go test` -- use `make test` which includes required build tags
- Snapshot golden files are in `__snapshots__/` directories -- commit the regenerated files
- Every snapshot test file requires a `TestMain` with `snaps.Clean(m, snaps.CleanOpts{Sort: true})` -- omitting it causes stale snapshots to accumulate
- Python tests use `indirect=True` parametrize for IC + VS setup -- do not remove this
