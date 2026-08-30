---
name: nic-testing
description: 'Testing patterns for NIC including Go table-driven tests, snapshot tests, Helm tests, and Python E2E integration tests. Use when writing unit tests, snapshot tests, policy tests, template tests, Helm tests, or pytest integration/E2E tests for the Ingress Controller.'
---

# NIC Testing Patterns

## Build and Test Commands

| Command | Purpose |
| --- | --- |
| `make test` | Run all Go unit & template tests (`-tags=aws,helmunit -shuffle=on ./...`) |
| `make test-update-snaps` | Regenerate snapshot golden files (`UPDATE_SNAPS=always`) |
| `make lint` | golangci-lint via Docker, diff against `origin/main` |
| `make format` | goimports + gofumpt |
| `make cover` | Generate Go test coverage report |
| `make secrets` | Generate test TLS certificates and keys required for E2E tests |
| `make run-local-tests` | Run Python E2E test suite locally using virtual environment |
| `make run-tests-in-kind` | Run E2E test suite inside a Kind Kubernetes cluster |
| `make run-tests-in-minikube` | Run E2E test suite inside a Minikube Kubernetes cluster |
| `make test-lint` | Python test formatting: `isort` + `black` |

Always use `make test` over raw `go test`. Run `make test-update-snaps` when template output changes.

---

## Go Unit & Snapshot Tests

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

### Naming Conventions

- Policy/transport tests (`policy_test.go`, `transportserver_test.go`):
  - `TestValidate<Thing>_PassesOnValidInput`
  - `TestValidate<Thing>_FailsOnInvalidInput`
- VirtualServer/general tests (`virtualserver_test.go`):
  - `TestValidate<Thing>`
  - `TestValidate<Thing>Fails`
  - `TestGenerate<Feature>`

### Snapshot Tests (template output)

Every test file using `snaps.MatchSnapshot` must have a `TestMain` that cleans up stale snapshots:

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

---

## Helm Tests

Location: `charts/tests/`

- `helmunit_test.go` -- Helm snapshot tests using terratest + go-snaps (requires `-tags=helmunit`, included in `make test`)
- `testdata/` -- values.yaml overrides per test scenario

---

## Python E2E & Integration Tests

Location: `tests/` (suite in `tests/suite/`, fixtures in `tests/suite/fixtures/`, utils in `tests/suite/utils/`, data in `tests/data/`)

### Setup and Environment Prerequisites

1. **Generate Test Secrets**: Before running tests individually, generate just-in-time test TLS certificates and keys:

   ```bash
   make secrets
   ```

2. **Setup Python Virtual Environment**:

   ```bash
   cd tests
   make setup-venv
   source venv/bin/activate
   ```

### Execution Workflows

- **Run locally against Minikube**:

  ```bash
  cd tests
  pytest --node-ip=$(minikube ip)
  ```

- **Run locally via Makefile**:

  ```bash
  make run-local-tests NODE_IP=$(minikube ip)
  ```

- **Run in Kind cluster**:

  ```bash
  cd tests
  make create-kind-cluster
  make build
  make run-tests-in-kind
  ```

- **Run in Minikube cluster**:

  ```bash
  cd tests
  make create-mini-cluster
  make run-tests-in-minikube
  ```

### CLI Arguments & Makefile Options

| CLI Argument | Makefile Variable | Description | Default |
| --- | --- | --- | --- |
| `--image` | `BUILD_IMAGE` | Ingress Controller container image | `nginx/nginx-ingress:edge` |
| `--ic-type` | `IC_TYPE` | IC variant: `nginx-ingress` or `nginx-plus-ingress` | `nginx-ingress` |
| `--deployment-type` | `DEPLOYMENT_TYPE` | Workload type: `deployment`, `daemon-set`, `stateful-set` | `deployment` |
| `--service` | `SERVICE` | Service type: `nodeport` or `loadbalancer` | `nodeport` |
| `--node-ip` | `NODE_IP` | Cluster node IP address | `""` |
| `--show-ic-logs` | `SHOW_IC_LOGS` | Output IC pod logs on test failure (`yes`/`no`) | `no` |
| `--skip-fixture-teardown` | `N/A` | Skip teardown of test fixtures for interactive debugging | `no` |
| `--plus-jwt` | `PLUS_JWT` | JWT token for NGINX Plus image authentication | `""` |
| `N/A` | `PYTEST_ARGS` | Extra flags passed to pytest (e.g., `-m smoke`) | `""` |

### IC Pooling & Test Collection Reordering

To minimize test suite churn and execution time:

- **Session-scoped IC Pool (`ICPool` in `ic_fixtures.py`)**: A single IC deployment is kept alive across consecutive test classes sharing identical `extra_args`. Changing configuration triggers an in-place IC recycle rather than per-class setup/teardown.
- **Session-scoped CRD & RBAC Registration**: CRD schemas (`crds`, `ap_crds`, `dos_crds`, `ed_crds`) and RBAC rules (`ap_rbac`, `dos_rbac`) are registered once per session.
- **Stable Collection Sorting (`conftest.py`)**: Pytest stably sorts items so tests are grouped by IC profile (non-IC tests first, pool-backed CRD tests grouped by `extra_args` second, inline non-pool IC tests last).

### Test Class Pattern

```python
@pytest.mark.policies
@pytest.mark.policies_mtls
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [({
        "type": "complete",
        "extra_args": ["-global-configuration=nginx-ingress/nginx-configuration"]
    }, {
        "example": "virtual-server-mtls",
        "app_type": "simple"
    })],
    indirect=True,
)
class TestIngressMtlsPolicyVS:
    def test_mtls_policy_execution(self, kube_apis, crd_ingress_controller, virtual_server_setup, test_namespace):
        # 1. Deploy CRD/Policy resource
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, yaml_src, test_namespace)
        wait_before_test()

        # 2. Patch VirtualServer to reference policy
        patch_virtual_server_from_yaml(kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, test_namespace)

        # 3. Assert HTTP response
        resp = requests.get(virtual_server_setup.backend_1_url_ssl, headers={"host": virtual_server_setup.vs_host}, verify=False)
        assert resp.status_code == 200

        # 4. Teardown
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
```

### Key Pytest Markers

Filter test runs with `pytest -m <marker>` or `PYTEST_ARGS="-m <marker>"`:

- Core areas: `smoke`, `ingresses`, `vs`, `vsr`, `policies`, `annotations`, `ts`, `oidc`, `otel`
- Modules: `appprotect`, `appprotect_waf_v5`, `dos`
- Platform/Target filtering: `skip_for_nginx_oss`, `skip_for_loadbalancer`, `multi_ns`

---

## Gotchas

- **Always** run `make secrets` before running individual pytest files directly.
- **Always** run `make test-update-snaps` after changing `.tmpl` files -- snapshot tests will fail otherwise.
- **Never** run raw `go test` -- use `make test` (includes build tags like `helmunit`).
- Snapshot golden files live in `__snapshots__/` directories -- commit regenerated snapshot diffs alongside template changes.
- Python test classes using `crd_ingress_controller` MUST use `indirect=True` parameterization to pass IC arguments through the fixture pool.
