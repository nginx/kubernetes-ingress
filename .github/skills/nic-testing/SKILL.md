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

4. **Read the diff and confirm your directive is present** in the golden output for every edition that supports it. An empty diff after a `.tmpl` change means no fixture exercises the new branch -- go back to step 1.
5. Run `make test` to confirm the suite is green against the regenerated files.
6. Commit the `__snapshots__` changes in the same commit as the template change.

### Edition parity -- OSS vs Plus

OSS and Plus templates are separate files with separate golden entries, so decide up front which editions the feature targets:

| Feature | Expected snapshot diff |
| --- | --- |
| Supported by both editions | Both the OSS **and** Plus golden files change |
| Plus-only (health checks, OIDC, WAF, `zone_sync`, NGINX Plus API) | **Only** the Plus golden file changes -- the directive must never appear in OSS output |
| OSS-only | Only the OSS golden file changes |

A one-sided diff is a bug only when the feature is supposed to be shared. Never add a Plus-only directive to an OSS snapshot to "fix" a one-sided diff -- that means the directive leaked into the OSS template and NGINX OSS will fail to start.

### Self-check before declaring done

- [ ] Every `.tmpl` I edited has at least one snapshot case that renders the new directive.
- [ ] The golden files changed for exactly the editions the feature supports -- both for shared features, Plus-only for Plus features.
- [ ] No Plus-only directive appears in an OSS golden file.
- [ ] `git diff` on `__snapshots__` is non-empty and reviewed line by line.
- [ ] `make test` passes without `UPDATE_SNAPS`.
- [ ] The regenerated golden files are staged for commit.

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

### Markers must be registered

pytest runs with `--strict-markers` (`pyproject.toml`, `[tool.pytest.ini_options] addopts`). Any new `@pytest.mark.<name>` must be added to the `markers` list in `pyproject.toml` at the repository root or the whole suite errors out. If the marker should run in CI, also add it to the relevant smoke matrix in `.github/data/matrix-smoke-*.json`.

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

## Generated Artifacts Verified by CI

The `verify-codegen` job in `ci.yml` re-runs each generator and diffs a **specific path**. Run the matching target and commit the result:

| You changed | Run | Path CI diffs |
| --- | --- | --- |
| `pkg/apis/**/types.go` | `make update-codegen` | `pkg/**` |
| `pkg/apis/**` kubebuilder markers | `make update-crds` | `config/crd/bases` only |
| Telemetry `Data` / `NICResourceCounts` in `internal/telemetry/exporter.go` | `make telemetry-schema` | `internal/telemetry` |
| Any import / dependency | `go mod tidy` | `go.mod`, `go.sum` |
| Any `.tmpl` or template struct | `make test-update-snaps` | not checked by `verify-codegen` -- fails in `unit-tests` instead |

**The checks are path-scoped, not repository-wide.** `make update-crds` also rewrites `deploy/crds*.yaml` and `docs/crd/`, but CI never diffs those paths -- forgetting to commit them produces a green build and stale published CRD bundles. Verify them yourself with `git status` after regenerating.

`charts/nginx-ingress/crds` is a **symlink** to `config/crd/bases/` -- never edit it directly.

---

## Gotchas

- **Always** run `make secrets` before running individual pytest files directly.
- **Always** run `make test-update-snaps` after changing `.tmpl` files -- snapshot tests will fail otherwise.
- **Never** run raw `go test` -- use `make test` (includes build tags like `helmunit`).
- Snapshot golden files live in `__snapshots__/` directories -- commit regenerated snapshot diffs alongside template changes.
- Python test classes using `crd_ingress_controller` MUST use `indirect=True` parameterization to pass IC arguments through the fixture pool.
- **Always** run `make test-update-snaps` after changing any `.tmpl` file -- snapshot tests will fail otherwise
- **Regenerating is not the same as testing.** If no fixture sets your new field, the golden file will not change and the feature has zero coverage. Add the test case first
- **Never** run raw `go test` -- use `make test` which includes required build tags (`aws`, `helmunit`)
- Snapshot golden files are in `__snapshots__/` directories -- commit the regenerated files with the change that caused them
- `TestMain` with `snaps.Clean(m, snaps.CleanOpts{Sort: true})` is **per package**, not per file -- adding a second one to the same package breaks the build
- OSS and Plus templates are separate files, so they have separate snapshot entries -- a one-sided diff means you forgot the sibling template, **unless** the feature is Plus-only, in which case only the Plus golden file must change
- New pytest markers must be registered in `pyproject.toml` -- `--strict-markers` is enabled
- Python tests use `indirect=True` parametrize for IC + VS setup -- do not remove this
