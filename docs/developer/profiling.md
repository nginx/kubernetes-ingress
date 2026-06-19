# Profiling

This guide covers how to build, deploy, and profile NGINX Ingress Controller using Go's built-in [pprof](https://pkg.go.dev/net/http/pprof) tooling. The pprof HTTP server is compiled in only when the `debug` build tag is set, so production binaries are completely unaffected.

- [How it works](#how-it-works)
- [Quickstart](#quickstart)
- [Building the profiling image](#building-the-profiling-image)
  - [Local binary (recommended)](#local-binary-recommended)
  - [Container-built binary](#container-built-binary)
- [Deploying to Kubernetes](#deploying-to-kubernetes)
  - [Using the provided manifest](#using-the-provided-manifest)
  - [Using Helm](#using-helm)
- [Accessing pprof](#accessing-pprof)
  - [kubectl port-forward](#kubectl-port-forward)
  - [NodePort](#nodeport)
- [K8s API call tracking](#k8s-api-call-tracking)
  - [Viewing stats](#viewing-stats)
  - [Isolating API calls for a specific action](#isolating-api-calls-for-a-specific-action)
  - [Verb classification](#verb-classification)
  - [What is tracked](#what-is-tracked)
  - [Implementation](#implementation)
- [Collecting profiles](#collecting-profiles)
  - [Function call frequency (CPU profile)](#function-call-frequency-cpu-profile)
  - [Goroutine analysis](#goroutine-analysis)
  - [Execution trace](#execution-trace)
  - [Heap (memory) profile](#heap-memory-profile)
  - [All available profiles](#all-available-profiles)
- [Continuous profiling with an external tool](#continuous-profiling-with-an-external-tool)
- [Interactive debugging with Delve](#interactive-debugging-with-delve)
- [Make targets reference](#make-targets-reference)

## How it works

Profiling is controlled entirely by Go [build tags](https://pkg.go.dev/go/build#hdr-Build_Constraints). Two files in `cmd/nginx-ingress/` implement the toggle:

| File | Build constraint | Effect |
| --- | --- | --- |
| `pprof_debug.go` | `//go:build debug` | Imports `net/http/pprof` and starts an HTTP server on `:6060` in an `init()` function |
| `pprof_release.go` | `//go:build !debug` | No-op stub; documents the debug counterpart |

When built without `-tags debug` (the default), the Go compiler excludes `pprof_debug.go` entirely. The resulting binary contains zero pprof code or symbols.

## Quickstart

```shell
# 1. Build the debug binary with pprof
make build-debug

# 2. Build the profiling Docker image
make debian-image-profiling TAG=profiling

# 3. Create a local Kind cluster (if you don't have one)
make -f tests/Makefile create-kind-cluster

# 4. Load the image into the cluster
kind load docker-image nginx/nginx-ingress:profiling

# 5. Deploy prerequisites
kubectl apply -f deploy/crds.yaml
kubectl apply -f deployments/common/ns-and-sa.yaml
kubectl apply -f deployments/rbac/rbac.yaml
kubectl apply -f deployments/common/nginx-config.yaml
kubectl apply -f deployments/common/ingress-class.yaml

# 6. Deploy NIC with pprof exposed
kubectl apply -f deployments/profiling/nginx-ingress-profiling.yaml

# 7. Forward the pprof port
kubectl port-forward -n nginx-ingress deploy/nginx-ingress 6060:6060

# 8. Collect a 30-second CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```

## Building the profiling image

### Local binary (recommended)

This cross-compiles the binary on the host and copies it into the container. Faster iteration.

```shell
# Builds with -tags debug, debug symbols, and no optimizations
make build-debug

# Packages into a Debian-based image targeting the "profiling" Dockerfile stage
make debian-image-profiling TAG=profiling
```

Set `ARCH=arm64` or `ARCH=amd64` to match your target architecture (defaults to `amd64`):

```shell
make build-debug ARCH=arm64
make debian-image-profiling TAG=profiling ARCH=arm64
```

### Container-built binary

If you prefer the binary to be built inside Docker (no local Go toolchain required), the `debug-builder` stage in `build/Dockerfile` also includes `-tags debug`. Use the existing debug image targets:

```shell
make debian-image TARGET=debug TAG=profiling
```

Note: this image uses `/dlv` as its entrypoint (Delve debugger), not `/nginx-ingress`. For profiling without Delve, use the `debian-image-profiling` target above.

## Deploying to Kubernetes

### Using the provided manifest

A ready-to-use manifest is provided at `deployments/profiling/nginx-ingress-profiling.yaml`. It contains:

- A **Deployment** identical to the standard one, with an additional `pprof` container port (6060)
- A **NodePort Service** (`nginx-ingress-pprof`) exposing port 6060 for pprof
- A **NodePort Service** (`nginx-ingress`) for standard HTTP/HTTPS traffic

```shell
# Deploy prerequisites (if not already done)
kubectl apply -f deploy/crds.yaml
kubectl apply -f deployments/common/ns-and-sa.yaml
kubectl apply -f deployments/rbac/rbac.yaml
kubectl apply -f deployments/common/nginx-config.yaml
kubectl apply -f deployments/common/ingress-class.yaml

# Deploy the profiling variant
kubectl apply -f deployments/profiling/nginx-ingress-profiling.yaml
```

Verify the pod is running and pprof is active:

```shell
kubectl get pods -n nginx-ingress
kubectl logs -n nginx-ingress deploy/nginx-ingress | grep pprof
# Expected: [debug] pprof server listening on :6060
```

### Using Helm

If you use the Helm chart, add port 6060 via `customPorts` and ensure the image is the profiling build:

```yaml
controller:
  image:
    tag: profiling
    repository: nginx/nginx-ingress
  customPorts:
    - name: pprof
      containerPort: 6060
      protocol: TCP
  service:
    type: NodePort
    customPorts:
      - name: pprof
        nodePort: 30060
        port: 6060
        protocol: TCP
        targetPort: 6060
```

```shell
helm upgrade --install my-release charts/nginx-ingress -f values-profiling.yaml
```

## Accessing pprof

### kubectl port-forward

The simplest method, works with any cluster and requires no extra Service configuration:

```shell
kubectl port-forward -n nginx-ingress deploy/nginx-ingress 6060:6060
```

pprof is then available at `http://localhost:6060/debug/pprof/`.

### NodePort

If you deployed with the provided manifest or the Helm configuration above, find the assigned NodePort:

```shell
kubectl get svc -n nginx-ingress nginx-ingress-pprof
```

Access pprof at `http://<node-ip>:<nodeport>/debug/pprof/`.

## K8s API call tracking

The debug build includes a custom HTTP transport wrapper that records **every Kubernetes API call** NIC makes. It tracks per-verb, per-resource call counts, error counts, and latency statistics. This is the most direct way to answer "how often are we calling the K8s API, and for what?"

Served on the same `:6060` port at `/debug/api-stats`.

### Viewing stats

```shell
# Launch the pprof web UI on port 8088 (may take some time to come up, depends on cluster size and activity)
> go tool pprof -http=:8088 "http://localhost:6060"
Fetching profile over HTTP from http://localhost:6060/debug/pprof/profile
```

```shell
# Human-readable table: per-verb, per-resource call counts, error rates, and latencies
# Shows e.g.: LIST pods (156 calls, avg 12ms), WATCH ingresses (12 calls), etc.
curl http://localhost:6060/debug/api-stats?format=text

# JSON output for programmatic consumption by an external monitoring tool
curl http://localhost:6060/debug/api-stats
```

#### Text response example

```text
K8s API Call Statistics
Uptime: 5m32s | Total calls: 1234

VERB    RESOURCE        GROUP                  COUNT  ERRORS  AVG      MIN      MAX      LAST CALL
----    --------        -----                  -----  ------  ---      ---      ---      ---------
LIST    pods            core                   156    2       12.0ms   8.1ms    45.3ms   1s ago
WATCH   ingresses       networking.k8s.io      12     0       2.3s     1.2s     5.0s     2s ago
GET     configmaps      core                   89     0       5.2ms    3.1ms    22.0ms   3s ago
GET     ingressclasses  networking.k8s.io      45     0       4.8ms    2.9ms    18.7ms   5s ago
```

#### JSON response example

```json
{
  "uptime": "5m32s",
  "uptime_seconds": 332,
  "total_calls": 1234,
  "calls": [
    {
      "verb": "LIST",
      "resource": "pods",
      "group": "core",
      "count": 156,
      "errors": 2,
      "total_ms": 1872.5,
      "avg_ms": 12.0,
      "min_ms": 8.1,
      "max_ms": 45.3,
      "last_call": "2026-06-05T10:30:15Z"
    }
  ]
}
```

### Isolating API calls for a specific action

Reset counters, trigger an action, then see exactly what API calls it caused:

```shell
# Clear all counters
curl -X POST http://localhost:6060/debug/api-stats/reset

# Trigger the action you want to measure
kubectl apply -f my-virtualserver.yaml
sleep 5

# See what API calls NIC made in response
curl http://localhost:6060/debug/api-stats?format=text
```

### Verb classification

The tracker classifies HTTP methods into Kubernetes-style verbs:

| HTTP method | K8s verb | Condition |
| --- | --- | --- |
| GET | `LIST` | No resource name in URL path |
| GET | `GET` | Resource name present in URL path |
| GET | `WATCH` | `?watch=true` query parameter |
| POST | `POST` | Always |
| PUT | `PUT` | Always |
| PATCH | `PATCH` | Always |
| DELETE | `DELETE` | Always |

### What is tracked

The transport wrapper intercepts **all** K8s API calls made by NIC, including those from:

- `kubeClient` (core Kubernetes API: pods, services, secrets, configmaps, namespaces, events)
- `confClient` (CRD API: VirtualServers, VirtualServerRoutes, TransportServers, Policies, GlobalConfiguration)
- `dynClient` (dynamic client: AppProtect, AppProtectDos, IngressLink)

The wrapper sits on the `rest.Config` transport, so every client created from that config is automatically instrumented.

### Implementation

The tracking is implemented in `cmd/nginx-ingress/debug_transport.go` (only compiled with `-tags debug`). It:

1. Wraps `rest.Config.WrapTransport` with a custom `http.RoundTripper` before any clients are created
2. Records verb, resource, API group, latency, and error status for each request
3. Aggregates stats in a concurrency-safe collector
4. Registers HTTP handlers on `http.DefaultServeMux` (shared with pprof on `:6060`)

In release builds, `wrapTransportWithDebugTracking()` is a no-op (see `debug_transport_release.go`).

## Collecting profiles

All examples below assume pprof is accessible at `localhost:6060` (via port-forward or otherwise).

### Function call frequency (CPU profile)

CPU profiles show how much time is spent in each function. Functions that appear most often are being called most frequently. This is the primary tool for answering "what functions do we spend the most time in?"

```shell
# Collect a 30-second CPU profile and open the interactive pprof shell
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Inside the pprof shell:
#   top 20          -- top 20 functions by self CPU time
#   top -cum 20     -- top 20 by cumulative time (includes time spent in callees)
#   list <funcname> -- show annotated source with per-line CPU time
#   web             -- open a call graph in the browser
```

To focus specifically on K8s client-go calls, use the web UI with filtering:

```shell
# Open profile in browser with flame graph
go tool pprof -http=:8080 http://localhost:6060/debug/pprof/profile?seconds=30
# In the web UI: use the "Search" box to filter by "client-go" or "k8s.io"
# The flame graph view shows the full call chain from NIC code into K8s API calls
```

To compare before and after a change:

```shell
# Save a baseline profile
curl -o before.prof http://localhost:6060/debug/pprof/profile?seconds=30

# ... make a code or config change, redeploy ...

# Save a second profile
curl -o after.prof http://localhost:6060/debug/pprof/profile?seconds=30

# Diff them to see what got slower or faster
go tool pprof -diff_base=before.prof after.prof
#   top 20          -- shows delta: functions that got slower (+) or faster (-)
```

### Goroutine analysis

Goroutine dumps show what every goroutine is doing right now. Useful for seeing how many concurrent K8s API calls or watches are in-flight, and identifying goroutine leaks.

```shell
# Full goroutine stacks -- every goroutine individually
# Look for goroutines blocked in:
#   k8s.io/client-go/tools/cache.(*Reflector).ListAndWatch  -- active watches
#   net/http.(*Transport).roundTrip                          -- in-flight API calls
#   internal/k8s.(*LoadBalancerController).sync              -- sync loop processing
curl http://localhost:6060/debug/pprof/goroutine?debug=2

# Summary grouped by stack -- shows how many goroutines share the same call stack
# Useful for spotting goroutine leaks (e.g., 500 goroutines stuck in the same place)
curl http://localhost:6060/debug/pprof/goroutine?debug=1

# Analyze in pprof (top goroutine creation sites)
go tool pprof http://localhost:6060/debug/pprof/goroutine
#   top 20          -- functions that created the most goroutines
#   traces          -- full stack traces grouped by count
```

### Execution trace

Execution traces capture goroutine scheduling, syscalls, GC events, and network I/O over a time window. This gives the most detailed view of K8s API call timing and concurrency, but produces large files. Keep the capture short (5-10 seconds).

```shell
# Capture a 5-second trace and open the trace viewer
curl -o trace.out http://localhost:6060/debug/pprof/trace?seconds=5
go tool trace trace.out

# In the trace viewer:
#   "Goroutine analysis"                -- time each goroutine spent running/waiting/blocked
#   "Network blocking profile"          -- time spent waiting on network I/O (K8s API calls)
#   "Synchronization blocking profile"  -- lock contention between goroutines
```

### Heap (memory) profile

Shows which functions allocate the most memory. Useful for identifying objects retained by K8s informer caches and API response parsing.

```shell
# Current live allocations (what's in memory right now)
go tool pprof http://localhost:6060/debug/pprof/heap
#   top 20          -- functions holding the most memory
#   top -cum 20     -- cumulative (includes memory held by callees)

# All allocations since start (total bytes allocated, even if already GC'd)
# Useful for finding functions that allocate frequently, causing GC pressure
go tool pprof -alloc_space http://localhost:6060/debug/pprof/heap
#   top 20          -- highest total allocation volume

# Count of allocated objects instead of bytes
# Useful for finding high-frequency small allocations
go tool pprof -alloc_objects http://localhost:6060/debug/pprof/heap
#   top 20          -- functions creating the most objects
```

### All available profiles

Browse the full index:

```shell
curl http://localhost:6060/debug/pprof/
```

This includes: `allocs`, `block`, `cmdline`, `goroutine`, `heap`, `mutex`, `profile`, `threadcreate`, and `trace`.

## Continuous profiling with an external tool

If you are building an external tool to continuously monitor NIC, both the pprof and API stats endpoints are available on `:6060`. Poll them programmatically:

```go
import "net/http"

// Fetch K8s API call stats (JSON)
resp, err := http.Get("http://localhost:6060/debug/api-stats")

// Fetch a heap profile
resp, err := http.Get("http://localhost:6060/debug/pprof/heap")

// Fetch a CPU profile (blocks for the specified duration)
resp, err := http.Get("http://localhost:6060/debug/pprof/profile?seconds=10")
```

### Endpoint summary

| Endpoint | What it reveals |
| --- | --- |
| `/debug/api-stats` | Per-verb, per-resource K8s API call counts, error rates, and latencies |
| `/debug/api-stats/reset` | Reset all API call counters (POST) |
| `/debug/pprof/profile?seconds=N` | CPU time per function -- shows time spent in client-go, reflector, informer, and API call paths |
| `/debug/pprof/trace?seconds=N` | Execution trace -- goroutine scheduling, shows API call concurrency and latency |
| `/debug/pprof/goroutine?debug=2` | All goroutine stacks -- shows in-flight API calls, blocked watchers, pending list/watch |
| `/debug/pprof/heap` | Memory allocations -- identifies objects retained by API caches and informer stores |
| `/debug/pprof/block` | Blocking profile -- shows where goroutines block on channels/mutexes (enable with `runtime.SetBlockProfileRate`) |
| `/debug/pprof/mutex` | Mutex contention -- shows lock contention hotspots (enable with `runtime.SetMutexProfileFraction`) |

## Interactive debugging with Delve

The profiling image includes [Delve](https://github.com/go-delve/delve) at `/dlv`. You can attach to the running NIC process for interactive debugging alongside pprof:

```shell
# Get the pod name
POD=$(kubectl get pod -n nginx-ingress -l app=nginx-ingress -o jsonpath='{.items[0].metadata.name}')

# Attach Delve to the NIC process (PID 1)
kubectl exec -it -n nginx-ingress "$POD" -- /dlv attach 1 --headless --listen=:2345 --api-version=2 --accept-multiclient &

# Forward the Delve port
kubectl port-forward -n nginx-ingress "$POD" 2345:2345
```

Then connect your IDE to `localhost:2345`. See the [Debugging guide](./debugging.md) for IDE configuration details.

## Make targets reference

| Target | Description |
| --- | --- |
| `make build-debug` | Build the NIC binary with `-tags debug`, debug symbols, and no optimizations. pprof server on `:6060`. |
| `make debian-image-profiling TAG=<tag>` | Build a Debian-based Docker image using the `profiling` Dockerfile stage. Depends on `build-debug`. |
| `make build TARGET=debug` | Equivalent to `build-debug`, used by the `build` dispatcher. |
| `make debian-image TARGET=debug TAG=<tag>` | Build the Delve-based debug image (entrypoint `/dlv`, also includes pprof). |
