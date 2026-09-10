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
- [Benchmarking](#benchmarking)
  - [Benchmark coverage](#benchmark-coverage)
  - [Running benchmarks](#running-benchmarks)
  - [Per-test profiling with hack/profile.sh](#per-test-profiling-with-hackprofilesh)
  - [Tracking memory and CPU spikes](#tracking-memory-and-cpu-spikes)
  - [Scaled benchmarks](#scaled-benchmarks)
  - [Burst simulation](#burst-simulation)
  - [Regression tracking with benchstat](#regression-tracking-with-benchstat)
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

The debug build includes a custom HTTP transport wrapper that records **every Kubernetes API call** NIC makes. It tracks per-verb, per-resource call counts, error counts, and latency statistics.

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

## Benchmarking

Go benchmarks measure config generation performance and track allocation regressions. They live in
`*_bench_test.go` files alongside the unit tests and run with the standard `go test -bench` tooling.

### Benchmark coverage

| File | What it benchmarks |
| --- | --- |
| `internal/configs/configurator_bench_test.go` | **Full-path** (config struct + template + file write): Ingress, mergeable Ingress, VirtualServer (base/splits/matches), TransportServer, endpoint updates. **Config-struct-only**: `GenerateVirtualServerConfig` (base/splits/matches), `GenerateTransportServerConfig`. **Other**: annotation parsing, metrics label computation. |
| `internal/configs/version2/templates_bench_test.go` | **Template execution only** (no config generation): VirtualServer Plus, VirtualServer OSS, TransportServer. Isolates `text/template` rendering cost from config struct generation. |
| `internal/configs/configurator_bench_peak_test.go` | **Scaled benchmarks**: config generation and full-path at varying sizes (3-500 upstreams/routes). **Burst simulation**: loading 10-100 VirtualServer configs in sequence (reconciliation storm). All benchmarks report **peak per-iteration** allocation alongside the average via `memTracker`. |

### Running benchmarks

```shell
# Run all benchmarks in the configs packages with memory stats
go test -tags=aws,helmunit -bench=. -benchmem -count=1 -run='^$' \
  ./internal/configs/ ./internal/configs/version2/

# Run only VirtualServer-related benchmarks
go test -tags=aws,helmunit -bench='VirtualServer' -benchmem -count=1 -run='^$' \
  ./internal/configs/

# Run with multiple iterations for statistical significance (required for benchstat)
go test -tags=aws,helmunit -bench='BenchmarkAddOrUpdateVirtualServer$' \
  -benchmem -count=10 -run='^$' ./internal/configs/

# Run scaled benchmarks to see how performance changes with config size
go test -tags=aws,helmunit -bench='_Scale' -benchmem -count=1 -run='^$' \
  ./internal/configs/

# Run burst simulation
go test -tags=aws,helmunit -bench='Burst' -benchmem -count=1 -run='^$' \
  ./internal/configs/
```

Key flags:

| Flag | Purpose |
| --- | --- |
| `-bench=<regex>` | Run benchmarks matching the pattern (`-bench=.` for all) |
| `-benchmem` | Report B/op and allocs/op alongside ns/op |
| `-count=N` | Repeat each benchmark N times (use 10+ for `benchstat`) |
| `-run='^$'` | Skip unit tests, run only benchmarks |
| `-benchtime=2s` | Run each benchmark for at least 2 seconds (more samples) |
| `-cpuprofile=cpu.prof` | Write CPU profile (only meaningful for single-benchmark runs) |
| `-memprofile=mem.prof` | Write memory profile |

### Per-test profiling with hack/profile.sh

The `hack/profile.sh` script runs each benchmark function individually and saves per-function CPU
and memory profile files. This is useful for drilling into a specific benchmark with `go tool pprof`.

```shell
# Run all benchmarks, save profiles to ./profiles/
./hack/profile.sh

# Custom output directory
PROF_DIR=/tmp/profiles ./hack/profile.sh

# Only benchmark functions (skip Test* functions)
PROF_BENCH_ONLY=1 ./hack/profile.sh

# Only functions matching a pattern
PROF_PATTERN="VirtualServer" PROF_BENCH_ONLY=1 ./hack/profile.sh

# Specific package only
PROF_PKG="./internal/configs/..." PROF_BENCH_ONLY=1 ./hack/profile.sh
```

There is also a Makefile target:

```shell
make test-profile
```

Output structure:

```
profiles/
  internal_configs/
    001_BenchmarkAddOrUpdateIngress_cpu.prof
    001_BenchmarkAddOrUpdateIngress_mem.prof
    001_BenchmarkAddOrUpdateIngress.log
    002_BenchmarkAddOrUpdateMergeableIngress_cpu.prof
    ...
  internal_configs_version2/
    001_BenchmarkExecuteVirtualServerTemplate_cpu.prof
    ...
```

Analyse a profile:

```shell
# Interactive pprof shell
go tool pprof profiles/internal_configs/001_BenchmarkAddOrUpdateIngress_cpu.prof

# Web UI with flame graph
go tool pprof -http=:8080 profiles/internal_configs/001_BenchmarkAddOrUpdateIngress_cpu.prof

# Show only application code (filter out runtime)
go tool pprof -text profiles/internal_configs/001_BenchmarkAddOrUpdateIngress_cpu.prof \
  | grep 'configs\.\|fmt\.\|version2\.'

# Memory allocations by function
go tool pprof -alloc_space -text profiles/internal_configs/001_BenchmarkAddOrUpdateIngress_mem.prof \
  | grep 'configs\.' | sort -k5 -rn | head -20
```

### Tracking memory and CPU spikes

Standard benchmarks report **averages** (`B/op`, `allocs/op`), which smooth out exactly the spikes
you care about during burst config loading. The benchmarks in `configurator_bench_peak_test.go` use
a `memTracker` helper that records `runtime.MemStats` per iteration and reports peak values via
`b.ReportMetric`:

```
BenchmarkGenerateVirtualServerConfig_Scale/up=100/rt=200
  919us   665,968 B/op   4,341 allocs/op           # standard (averages)
  668,248 peak-B/op      4,353 peak-allocs/op       # worst single iteration
  7.180 peak-heap-MB                                 # process heap high-water mark
```

How to interpret:

- **`peak-B/op` vs `avg-B/op`**: A large gap means some iterations allocate significantly more
  than others. This indicates spiky allocation patterns that can trigger GC pauses at
  unpredictable times.
- **`peak-allocs/op` vs `avg-allocs/op`**: Same for allocation count. High peak alloc counts
  cause more GC mark work.
- **`peak-heap-MB`**: Process-wide heap high-water mark during the benchmark. Shows the maximum
  memory footprint reached. Compare across config sizes to see if large configs cause
  disproportionate heap growth.

The `memTracker` adds ~1-5% overhead from `runtime.ReadMemStats` per iteration, which is acceptable
for operations taking >50us. It should not be used on micro-benchmarks (<10us/op) where the
overhead would dominate.

### Scaled benchmarks

Benchmarks with the `_Scale` suffix run the same operation at multiple config sizes to reveal
scaling characteristics. This answers: "does a 100-upstream VirtualServer cost 33x more than a
3-upstream one, or is there super-linear growth?"

```shell
go test -tags=aws,helmunit -bench='_Scale' -benchmem -count=1 -run='^$' ./internal/configs/
```

Example output for `BenchmarkGenerateVirtualServerConfig_Scale`:

| Scale | ns/op | B/op | allocs/op | peak-B/op | peak-heap-MB |
| --- | ---: | ---: | ---: | ---: | ---: |
| up=3/rt=6 | 106K | 19.5K | 149 | 21.6K | 5.8 |
| up=10/rt=20 | 189K | 76.6K | 457 | 78.8K | 6.1 |
| up=50/rt=100 | 539K | 331K | 2,186 | 334K | 6.4 |
| up=100/rt=200 | 919K | 666K | 4,341 | 668K | 7.2 |
| up=500/rt=500 | 1.86M | 1.73M | 14,551 | 1.73M | 7.5 |

What to look for:

- **Linear scaling**: B/op and allocs/op should grow roughly proportionally with upstream/route
  count. The table above shows ~linear growth (good).
- **Super-linear spikes**: If B/op grows faster than the config size, there may be quadratic
  loops or unbounded slice growth in the generation code.
- **Peak-heap divergence**: If `peak-heap-MB` grows much faster than `B/op`, memory is being
  retained across iterations (possible leak or cache growth).

### Burst simulation

`BenchmarkVirtualServerBurst` simulates a reconciliation storm: N distinct VirtualServer configs
are generated and written in rapid sequence, as happens during controller startup or a large batch
`kubectl apply`. It reports per-burst aggregate metrics:

```shell
go test -tags=aws,helmunit -bench='Burst' -benchmem -count=1 -run='^$' ./internal/configs/
```

Example output:

| Burst size | Time | burst-avg-B/vs | burst-heap-delta-MB | burst-gc-cycles |
| --- | ---: | ---: | ---: | ---: |
| 10 | 1.8ms | 27.4K | 0.1 | 0 |
| 50 | 5.9ms | 27.2K | 1.0 | 0 |
| 100 | 8.3ms | 27.2K | 2.2 | 0 |

How to interpret:

- **`burst-avg-B/vs`**: Average bytes allocated per VirtualServer within the burst. Should be
  stable regardless of burst size. If it grows with burst size, there is amplification (e.g.,
  a shared data structure growing with each config added).
- **`burst-heap-delta-MB`**: Heap growth during the burst. Shows how much memory the burst
  consumes before GC can reclaim it. Use this to size memory requests for pods that handle
  large numbers of VirtualServers.
- **`burst-gc-cycles`**: Number of GC cycles triggered during the burst. A value > 0 means
  the burst is generating enough garbage to trigger GC mid-reconcile, which adds latency.
  Watch this metric after code changes -- a regression that increases per-VS allocation
  can push a previously GC-free burst over the threshold.

### Regression tracking with benchstat

To detect performance regressions between code changes, use
[`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) to compare benchmark runs with
statistical confidence:

```shell
# Install benchstat (one time)
go install golang.org/x/perf/cmd/benchstat@latest

# Capture baseline (10 runs for statistical significance)
go test -tags=aws,helmunit \
  -bench='BenchmarkAddOrUpdateVirtualServer$|BenchmarkGenerateVirtualServerConfig$' \
  -benchmem -count=10 -run='^$' \
  ./internal/configs/ > before.txt

# ... make code changes ...

# Capture after
go test -tags=aws,helmunit \
  -bench='BenchmarkAddOrUpdateVirtualServer$|BenchmarkGenerateVirtualServerConfig$' \
  -benchmem -count=10 -run='^$' \
  ./internal/configs/ > after.txt

# Compare
benchstat before.txt after.txt
```

Example `benchstat` output:

```
                              │ before.txt  │           after.txt            │
                              │   sec/op    │   sec/op     vs base           │
AddOrUpdateVirtualServer-12     222.0u ± 3%   211.5u ± 2%  -4.73% (p=0.001)
GenerateVirtualServerConfig-12  23.40u ± 2%   17.90u ± 1%  -23.5% (p=0.000)

                              │ before.txt  │           after.txt            │
                              │    B/op     │    B/op      vs base           │
AddOrUpdateVirtualServer-12     93.64Ki ± 0%  66.15Ki ± 0%  -27.7% (p=0.000)
GenerateVirtualServerConfig-12  24.86Ki ± 0%  21.93Ki ± 0%  -11.8% (p=0.000)
```

A regression is any row where `vs base` shows a statistically significant increase (p < 0.05).
Pay most attention to `B/op` and `allocs/op` -- these directly affect GC pressure under load.

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
