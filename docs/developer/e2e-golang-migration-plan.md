# High-Level Design: Migrating NIC End-to-End & Performance Tests from Python to Go

## Executive Summary

This document outlines the architectural plan to migrate the NGINX Ingress Controller (NIC) end-to-end integration tests (`tests/suite/`, ~54,500 lines across 175 Python files) and performance tests (`perf-tests/`, ~2,500 lines) from Python (`pytest`, `requests`, `playwright`, `locust`) to a **pure Go, ultra-low wall-clock time, highly parallel architecture**.

### Core Architecture Highlights
* **Maximum Parallelization & Ultra-Low Wall Time**:
  * **Dynamic Sandboxing**: Runs tests concurrently across CPU threads and worker processes against the same Kubernetes cluster using ephemeral namespaces (`test-ns-<uuid>`) and dynamic hostnames (`vs-<uuid>.example.com`).
  * **Shared Multi-Tenant Controller Pool**: Replaces the expensive Python pattern of destroying and redeploying the Ingress Controller pod for every test class (which wasted 10–15s per test suite).
  * **Zero Fixed Sleeps**: Replaces all `time.sleep()` calls with 50ms event-driven polling (`Eventually`). Tests succeed the millisecond NGINX is ready.
  * **Parallel vs Serial Tiering**: ~85% of tests run in parallel (`Label("parallel")`). Stateful tests (modifying root ConfigMaps or asserting exact reload count increments) are isolated into a serial tier (`Label("serial")`).
* **Zero Browser Dependencies**: OIDC authentication and Front-Channel Logout (FCLO) flows are tested end-to-end using a pure Go HTTP client with cookie management and HTML form parsing, completely eliminating Playwright, Chromium, and Node.js.
* **100% Manifest Reuse**: All existing YAML manifests in `tests/data/` are reused directly via Go's dynamic client and Server-Side Apply with dynamic namespace/host templating.
* **Type-Safe Controller Verification**: Direct use of NIC's generated typed clientset (`pkg/client/clientset/versioned`) for CRD assertions, catching API regressions at compile time.
* **In-Process Performance Engine**: Python `locust` is replaced with `vegeta` embedded directly as a Go library, generating 10,000+ RPS in-process with microsecond latency precision.
* **Lightweight CI Footprint**: Drops the test runner container image from ~1.5GB (Python, Chromium, Node.js, pip dependencies) to an ultra-lightweight ~30MB Go binary.

---

## High-Concurrency Architecture & Parallelization

```
                               ┌────────────────────────────────────────────────────────┐
                               │           High-Concurrency Go E2E Architecture        │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
        ┌──────────────────────────────────┬───────────────┴───────────────┬──────────────────────────────────┐
        ▼                                  ▼                               ▼                                  ▼
┌──────────────────────┐        ┌──────────────────────┐        ┌──────────────────────┐        ┌──────────────────────┐
│  1. Dynamic Sandbox  │        │  2. Shared Multi-    │        │  3. Parallel vs      │        │  4. Zero Fixed Sleeps│
│                      │        │     Tenant Pool      │        │     Serial Split     │        │                      │
├──────────────────────┤        ├──────────────────────┤        ├──────────────────────┤        ├──────────────────────┤
│• Random namespace    │        │• Keep Ingress        │        │• 85% tests: Parallel │        │• Replace all         │
│  per test (test-xxxx)│        │  Controller running  │        │  (routing, policies) │        │  time.Sleep() with   │
│• Unique Host headers │        │• Skip 10-15s pod     │        │• 15% tests: Serial   │        │  Eventually()        │
│  (vs-xxxx.example)   │        │  teardown per test   │        │  (reload counts,     │        │  50ms event polling  │
│• Zero resource clash │        │• 10-20 concurrent req│        │  global ConfigMaps)  │        │• Tests pass the ms   │
│                      │        │  through single NIC  │        │                      │        │  NGINX is ready      │
└──────────────────────┘        └──────────────────────┘        └──────────────────────┘        └──────────────────────┘
```

### 1. Dynamic Sandboxing (Namespaces & Dynamic Hostnames)

In the Python suite, test classes hardcode resource names (`nginx-ingress`, `default` namespace, Secret `tls-secret`, Service `backend-svc`, VirtualServer `virtual-server`). If multiple tests run simultaneously, they collide and overwrite each other's routing.

To enable full parallel execution:
* **Dynamic Ephemeral Namespaces**: Each parallel spec creates an isolated namespace (`test-ns-<uuid>`) via the framework. On test completion, `t.Cleanup()` or Ginkgo `DeferCleanup()` asynchronously tears down the namespace.
* **Dynamic Hostnames / SNI**: Hostnames are dynamically generated per test execution (`fmt.Sprintf("vs-%s.example.com", testID)`). Because NGINX routes traffic using the HTTP `Host` header and TLS SNI (`server_name`), **hundreds of tests can route through the same NGINX instance simultaneously without any cross-talk**.
* **Manifest Templating**: The dynamic YAML manifest loader automatically substitutes `{{ .Namespace }}` and `{{ .Host }}` when applying existing YAML files from `tests/data/`.

### 2. Shift from "Ephemeral Controller per Test" to "Shared Multi-Tenant Pool"

* **The Problem**: In Python, the `ingress_controller` fixture deploys a new Ingress Controller pod for almost every test class, waits for readiness, and deletes it. Tearing down and restarting pods takes 10–15 seconds per test class. Across 80+ suites, this wastes **15–20 minutes of wall-clock time just waiting for pods to restart**.
* **The Solution**:
  * **Tier 1 (Shared Controller Pool — ~85% of tests)**: Deploy **one** Ingress Controller instance at suite startup. All standard tests (VirtualServers, Ingresses, Annotations, RateLimits, BasicAuth, CORS, etc.) execute concurrently against this single running controller, isolated by namespace and dynamic hostnames.
  * **Tier 2 (Namespaced IngressClasses — ~10% of tests)**: For tests requiring specific CLI flags (e.g. `-enable-oidc`), deploy a secondary controller scoped to its own `IngressClass` (`ingress-class: nic-oidc`). This runs in parallel without interfering with Tier 1.
  * **Result**: Eliminates 10–15 seconds of startup tax from every test suite, cutting total execution time by ~80%.

### 3. Separation of Concerns: Parallel vs Serial Tiering

* **The Reload Contention Problem**:
  * When 10 parallel tests apply VirtualServers at the same time, NGINX reloads multiple times.
  * If a test asserts on exact reload counts (e.g. verifying that modifying upstream endpoints does not reload NGINX Plus), background reloads from other tests will cause a test failure.
* **The Solution**:
  * **Parallel Tests (`Label("parallel")`)**: Functional tests verifying data-plane routing, HTTP responses, status codes, and policies. These do not assert on global reload counters and run with maximum concurrency (e.g. 8–16 workers).
  * **Serial Tests (`Label("serial")`)**: Tests that verify:
    * Reload metrics (`last_reload_milliseconds` or exact reload count increments).
    * Cluster-wide global state (`GlobalConfiguration`, root `nginx-config` ConfigMap modifications).
  * Run sequentially or against a dedicated IngressClass:
    ```bash
    # Step 1: Run 85% of tests in parallel across 8 CPU workers
    ginkgo run -p --procs=8 --label-filter="!serial" ./tests/e2e/...

    # Step 2: Run remaining 15% stateful/reload tests serially
    ginkgo run --label-filter="serial" ./tests/e2e/...
    ```

### 4. Zero Fixed Sleeps $\rightarrow$ Pure Event-Driven Polling

* **The Problem**: Python tests contain hundreds of `time.sleep(1)` and `wait_before_test()` calls, adding up to over 30 minutes of idle wait time across the suite.
* **The Solution**: Strict rule: **Zero `time.Sleep` in Go test code**.
* All assertions use Gomega's `Eventually()` with a **50ms polling interval**. The millisecond NGINX finishes reloading and returns `200 OK`, the assertion succeeds and the test immediately finishes.
* Average test wait time drops from **3–5 seconds to 100–250 milliseconds**.

### 5. Multi-Process Ginkgo v2 Runner Model

Ginkgo v2 provides native multi-process parallel execution:
```bash
ginkgo run -p --procs=8 --label-filter="parallel" ./tests/e2e/...
```
* **Process Isolation**: Each worker runs in its own OS process, preventing any risk of package-level variable races or memory leaks.
* **`SynchronizedBeforeSuite`**: Worker 1 deploys the shared cluster prerequisites (CRDs, Common RBAC, Shared Ingress Controller) once, then signals workers 2..N to begin running specs simultaneously.
* **Failure Isolation**: A crash or panic in Worker 3 does not abort Workers 1, 2, 4..N.

---

## Wall-Clock Time Projections

| Test Stage | Python (Current Sequential) | Go (Sequential) | Go (High-Concurrency Parallel) |
| :--- | :--- | :--- | :--- |
| **Pod Teardown / Re-creation** | 10–15s per test suite | 10–15s per test suite | **0s (Shared Controller Pool)** |
| **Wait for NGINX Reload** | Fixed 2–5s sleep | 100–300ms (`Eventually`) | **100–300ms (`Eventually`)** |
| **Smoke Suite (10 tests)** | ~45–60s | ~15–20s | **~3–5 seconds** |
| **Full Ingress Suite (90+ tests)**| ~12–18 minutes | ~4–5 minutes | **~45–90 seconds** |
| **CI Matrix Job Total** | ~10–15 minutes | ~3–4 minutes | **~1.5–2.5 minutes** |

---

## Browserless OIDC Testing: Zero External Browsers

The OIDC Authorization Code Flow and Front-Channel Logout (FCLO) are completely testable using standard HTTP requests:

```
[Go Test Client]                      [NGINX Ingress]                         [Keycloak IdP]
       │                                     │                                       │
       │─── 1. GET /protected ──────────────►│                                       │
       │◄── 2. 302 Redirect to IdP ──────────┼───────────────────────────────────────┤
       │                                     │                                       │
       │─── 3. GET /auth (follows redirect) ────────────────────────────────────────►│
       │◄── 4. 200 OK (HTML login form with action URL & hidden session code) ───────┤
       │                                     │                                       │
       │─── 5. POST /login-actions (form: username & password) ─────────────────────►│
       │◄── 6. 302 Redirect to /oauth/callback?code=... ─────────────────────────────┤
       │                                     │                                       │
       │─── 7. GET /oauth/callback?code=... ─►│                                       │
       │                                     │─── 8. Back-channel POST /token ──────►│
       │                                     │◄── 9. JWT ID & Access tokens ─────────┤
       │◄── 10. 302 Redirect to / (Set-Cookie)┼──────────────────────────────────────┤
       │                                     │                                       │
       │─── 11. GET /protected (with Cookie) ─►│─── Proxies to backend pod ──────────►│
       │◄── 12. 200 OK ("Server address: ...")┼──────────────────────────────────────┤
```

### Browserless OIDC Implementation in Go
```go
package oidc

import (
    "crypto/tls"
    "net/http"
    "net/http/cookiejar"
    "strings"
    "testing"

    "github.com/stretchr/testify/require"
)

// LoginOIDC performs the full Authorization Code Flow using standard HTTP.
func LoginOIDC(t *testing.T, targetURL, host, username, password string) *http.Response {
    jar, _ := cookiejar.New(nil)
    client := &http.Client{
        Jar: jar,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    // 1. Initial GET to Ingress -> redirects to Keycloak login page
    req, err := http.NewRequest("GET", targetURL, nil)
    require.NoError(t, err)
    req.Host = host

    resp, err := client.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()

    // 2. Parse form action and hidden fields from Keycloak HTML
    actionURL, formValues := parseLoginForm(resp.Body)
    formValues.Set("username", username)
    formValues.Set("password", password)

    // 3. POST credentials to Keycloak
    // Client follows redirects: Keycloak -> NGINX callback -> target URL
    postReq, err := http.NewRequest("POST", actionURL, strings.NewReader(formValues.Encode()))
    require.NoError(t, err)
    postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    finalResp, err := client.Do(postReq)
    require.NoError(t, err)
    return finalResp
}
```

### Front-Channel Logout (FCLO) Without a Browser
In FCLO, Keycloak’s logout page renders hidden `<iframe src="https://app/front_channel_logout?iss=...&sid=...">`. 
The Go HTTP client:
1. Performs `GET https://keycloak/realms/master/protocol/openid-connect/logout`.
2. Parses all `<iframe src="...">` URLs from the returned HTML.
3. Issues `client.Get(iframeURL)` for each iframe URL.
4. Asserts that the NIC pod log records: `OIDC Front-Channel Logout initiated for sid:`.

*Result*: 100% verification of NIC's session revocation logic with **zero browser binaries**.

---

## Reusing Existing Manifests (`tests/data/`) with Dynamic Templating

Rather than rewriting thousands of lines of YAML into Go structs, the Go framework implements a dynamic manifest applier that replaces namespace and host placeholders at apply time:

```go
type ManifestOptions struct {
    Namespace string
    Host      string
}

func (f *Framework) ApplyYAML(ctx context.Context, yamlPath string, opts ManifestOptions) ([]schema.GroupVersionResource, error) {
    data, err := os.ReadFile(yamlPath)
    if err != nil { return nil, err }

    // Replace template variables for dynamic sandboxing
    content := string(data)
    if opts.Namespace != "" {
        content = strings.ReplaceAll(content, "{{ .Namespace }}", opts.Namespace)
    }
    if opts.Host != "" {
        content = strings.ReplaceAll(content, "{{ .Host }}", opts.Host)
    }

    decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(content), 4096)
    var applied []schema.GroupVersionResource

    for {
        var rawObj unstructured.Unstructured
        if err := decoder.Decode(&rawObj); err != nil {
            if err == io.EOF { break }
            return nil, err
        }
        if len(rawObj.Object) == 0 { continue }

        rawObj.SetNamespace(opts.Namespace)
        gvr, err := f.findGVR(rawObj.GroupVersionKind())
        if err != nil { return nil, err }

        _, err = f.DynamicClient.Resource(gvr).Namespace(opts.Namespace).Apply(
            ctx, rawObj.GetName(), &rawObj, metav1.ApplyOptions{FieldManager: "e2e-test", Force: true},
        )
        if err != nil { return nil, err }
        applied = append(applied, gvr)
    }
    return applied, nil
}
```

---

## Performance Tests Migration (`perf-tests/`)

Replace Python's `locust` subprocess execution with **`vegeta` (`github.com/tsenart/vegeta/v12/lib`)** running directly in-process:

```go
func RunLoadTest(targetURL, host string, ratePerSec int, duration time.Duration) (*vegeta.Metrics, error) {
    targeter := vegeta.NewStaticTargeter(vegeta.Target{
        Method: "GET",
        URL:    targetURL,
        Header: http.Header{"Host": []string{host}},
    })
    attacker := vegeta.NewAttacker(
        vegeta.Timeout(5 * time.Second),
        vegeta.TLSConfig(&tls.Config{InsecureSkipVerify: true}),
    )

    var metrics vegeta.Metrics
    for res := range attacker.Attack(targeter, vegeta.Rate{Freq: ratePerSec, Per: time.Second}, duration, "NIC Perf") {
        metrics.Add(res)
    }
    metrics.Close()
    return &metrics, nil
}
```

#### Metrics & Resource Scraping
* **Reload Timing**: Scraped directly from `:9113/metrics` using `github.com/prometheus/client_golang` (`expfmt.TextParser`), which is already in `go.mod`.
* **K8s Metrics**: Scraped using official typed `k8s.io/metrics/pkg/client/clientset/versioned` (`PodMetrics` and `NodeMetrics`).

---

## Target Package Structure

```
tests/e2e/
├── framework/
│   ├── config.go            # CLI Flags: --kubeconfig, --image, --ic-type, --service, --parallel
│   ├── framework.go         # Test harness, client sets, namespace isolation & cleanup
│   ├── sandbox.go           # Dynamic sandboxing (unique namespaces, dynamic hosts)
│   ├── controller.go        # Shared Ingress Controller lifecycle & management
│   ├── manifest.go          # Dynamic YAML manifest loader with variable templating
│   ├── traffic.go           # HTTP/HTTPS/HTTP2/gRPC client with Host override & TLS bypass
│   ├── stream.go            # TCP/UDP socket dialing for TransportServer tests
│   ├── metrics.go           # Prometheus metrics parser (/metrics)
│   ├── nginx_api.go         # NGINX Plus API client (/api/9/...)
│   ├── pod_exec.go          # Remote command execution (reading /etc/nginx/conf.d/...)
│   └── oidc.go              # Pure Go browserless OIDC login & FCLO helpers
├── suite/
│   ├── e2e_suite_test.go    # SynchronizedBeforeSuite & Ginkgo runner setup
│   ├── smoke_test.go        # PoC: Smoke tests migrated from test_smoke.py
│   ├── ingress_test.go      # Ingress & Annotation tests (parallel)
│   ├── virtualserver_test.go# VirtualServer & VSR tests (parallel)
│   ├── policies_test.go     # RateLimit, JWT, BasicAuth, ExternalAuth, CORS, mTLS (parallel)
│   ├── transportserver_test.go # TCP/UDP stream tests (parallel)
│   ├── plus_test.go         # NGINX Plus API & dynamic upstream tests (parallel)
│   ├── oidc_test.go         # Browserless OIDC & FCLO tests (parallel)
│   └── reload_serial_test.go# Reload metrics & GlobalConfiguration tests (serial)
├── perf/
│   ├── load.go              # Vegeta in-process HTTP load generator
│   ├── reload_test.go       # NGINX reload benchmarks
│   └── request_test.go      # Request latency & throughput benchmarks
└── data/                    # Existing YAML manifests (reused directly)
```

---

## Phased Migration Roadmap

```
┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
│ Phase 1: Foundation  │ ───► │  Phase 2: PoC Smoke  │ ───► │ Phase 3: Perf Tests  │ ───► │ Phase 4: Domain Batch│ ───► │ Phase 5: Switchover  │
├──────────────────────┤      ├──────────────────────┤      ├──────────────────────┤      ├──────────────────────┤      ├──────────────────────┤
│• Framework core      │      │• Port test_smoke.py  │      │• Port perf-tests/    │      │• Port VS, VSR, Policy│      │• Switch CI matrix    │
│• Dynamic sandboxing  │      │• Benchmark 8-proc    │      │• Replace Locust with │      │• Port TransportServer│      │• Consolidate runners │
│• Shared controller   │      │  concurrency         │      │  Vegeta in Go        │      │• Port OIDC (browser- │      │• Remove tests/runner │
│• Build tag //go:build│      │• Validate in CI Kind │      │• Output JSON metrics │      │  less HTTP flow)     │      │• Delete Python venv  │
└──────────────────────┘      └──────────────────────┘      └──────────────────────┘      └──────────────────────┘      └──────────────────────┘
```

### Phase 1: Framework Foundation & Concurrency Engine
* Build `tests/e2e/framework/` with dynamic sandboxing (ephemeral namespaces + host generation).
* Implement the **Shared Multi-Tenant Controller Pool** with `SynchronizedBeforeSuite`.
* Implement typed Kubernetes clientset + typed NIC clientset (`pkg/client/clientset/versioned`).
* Implement dynamic YAML manifest applier with placeholder templating.
* Tag all tests with `//go:build e2e` so unit/snapshot tests (`make test`) remain isolated.

### Phase 2: Proof of Concept (`smoke_test.go`) & Concurrency Validation
* Port `tests/suite/test_smoke.py` to `tests/e2e/suite/smoke_test.go`.
* Benchmark 8-worker parallel execution (`ginkgo -p --procs=8`) against a local Kind cluster.
* Add parallel CI job in `.github/workflows/setup-smoke.yml` to validate stability and record wall-clock time reduction.

### Phase 3: Performance Tests Migration
* Port `perf-tests/` to `tests/e2e/perf/`.
* Implement Vegeta load generator and Prometheus reload duration recorder.
* Output compatible JSON reload metrics (`reload_ing.json`, `reload_vs.json`).

### Phase 4: Domain-by-Domain Migration
Port remaining suites in prioritized batches:
1. Core Ingress & Annotations (`test_ingress*.py`, `test_annotations.py`)
2. VirtualServer & VirtualServerRoute (`test_virtual_server*.py`, `test_v_s_route*.py`)
3. Policies (RateLimit, JWT, BasicAuth, ExternalAuth, CORS, mTLS, Cache)
4. TransportServer (TCP/UDP socket tests)
5. NGINX Plus Features (API, dynamic upstreams, zone sync)
6. OIDC & FCLO Tests (Browserless Go implementation)
7. Serial Reload & GlobalConfiguration Tests (`Label("serial")`)
8. AppProtect WAF & DoS

### Phase 5: CI Switchover & Decommissioning
* Transition `.github/data/matrix-smoke-*.json` runners to invoke the parallel Go test runner.
* Consolidate 25+ slow single-threaded matrix jobs into 4–6 fast parallel matrix jobs.
* Replace the heavy `ghcr.io/nginx/kubernetes-ingress/test-runner` Docker image with a minimal Go binary container.
* Delete `tests/requirements.txt`, Python virtualenv targets from Makefile, and `locust`.
