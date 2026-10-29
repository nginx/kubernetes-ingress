# Go e2e PoC: findings

Context: [#11061 Migrate Python tests to Go](https://github.com/nginx/kubernetes-ingress/issues/11061) and the
migration plan in `docs/developer/e2e-golang-migration-plan.md`. The PoC tests the plan's central bet:
**one shared Ingress Controller, every spec in its own namespace with its own hostnames, specs run in parallel
with Ginkgo.**

## TL;DR

- **Same scenarios, same cluster: Python 280 s, Go 18 s (~15×) — running Go sequentially.** Almost all of
  the Python time is controller deploy/teardown (128 s) and fixed waits inside tests (~145 s).
- **Parallel isolation works.** 13 runs at 1–8 processes: 0 failures, 0 dropped connections, and every
  response was proven to come from a pod in the spec's own namespace.
- **Parallelism alone is worth ~2×, not 8×, on a 4-vCPU machine** — the same CPU count as a CI runner.
  One controller reloads NGINX one change at a time; on OSS, ~40% of reloads come from backend pod churn.
  CPU, not memory, sets the ceiling (see [Runner size](#runner-size-and-its-effect-on-speed-and-concurrency)).
- **Most of the win is design, not language:** no controller redeploy per test class (228 classes today)
  and no fixed sleeps (845 calls, ≥46 min). Both could be done in pytest too; the case for Go is a single
  language, typed clients and dropping the Python toolchain.
- **The design is clean for the easy half; the cost is in the tail.** 47% of controller configurations fit
  one shared controller, 5 profiles cover another ~25%, and 25 flag sets are used once.
- **Only 31 of 154 test files (127 of 669 tests) are portable today** without new framework features.
  Multi-namespace sandboxes and controller profiles unlock the next ~25 files; a per-sandbox controller
  is the likely answer for most of the rest (see [Isolating the tail](#isolating-the-tail)).
- **vCluster becomes feasible again.** The earlier Python attempt (`tests/vcluster` branch) stalled on
  session-scoped fixtures; the Go framework does not assume a single cluster.
- **Recommendation:** a 1–2 day spike (second controller profile, per-sandbox controller, multi-namespace
  VSR, one Plus run, one run on a real CI runner; vCluster optional) with go/no-go criteria before
  committing to the migration. Realistic for one engineer with AI in two sprints: framework plus 50–70
  files, not the whole suite.

## What was built

```
tests/
├── Makefile             # e2e-poc-cluster / e2e-poc-kubeconfig (host), e2e-poc-deploy / e2e-poc
└── e2e/
    ├── framework/       # ~690 lines
    │   ├── framework.go # clients, IC pod, reload metric (API pod proxy), exec
    │   ├── sandbox.go   # namespace per spec, host rewrite on apply, failure artifacts, Serial quiesce
    │   ├── http.go      # requests to NodePorts with Host/SNI from URL, options, conn-drop counter
    │   └── resources.go # generated NGINX conf, CR status, events
    └── poc/             # suite + 5 specs, 25–50 lines each
```

- Specs ported: VirtualServer lifecycle, mergeable Ingress over TLS, VS traffic split, basic-auth policy
  attach/detach, reload batching (`Serial`).
- `tests/data` YAML is reused unchanged; hostnames are rewritten in memory (`<id>.virtual-server.example.com`).
- On failure: NIC logs since spec start, `nginx -T` and namespace events go to `.e2e/artifacts/<namespace>/`.
- New Go deps: `ginkgo/v2` (also as a `go tool`), `gomega`, `k8s.io/streaming` (indirect, for exec).
  Everything is behind `//go:build e2e`, so `make test` is unaffected.

### Running it

```
make -C tests e2e-poc-cluster              # on the host, once: minikube with NodePorts 30080/30443 published
make -C tests e2e-poc PROCS=2 COPIES=4     # anywhere with access: installs NIC (Helm), runs the specs
```

Local setup notes: kind could not be made to work (arm64 image arch issues, see `Makefile:57`
`ARCH ?= amd64`); minikube (docker driver) works. A containerised agent sandbox reaches minikube via
`host.docker.internal` because joining Docker networks conflicts with minikube's internal `172.17/16`.

## Results

OSS `nginx/nginx-ingress:edge`, 17 specs per run (4 copies × 4 parallel specs + 1 serial).
Hardware: minikube `--cpus=4 --memory=4g` (docker driver) in a Docker Desktop VM (12 vCPU, ~8 GB, shared
with the agent sandbox) on a 16 GB arm64 Mac.

| procs | runs | failures | conn drops | parallel phase | serial spec | suite wall |
| ---: | ---: | ---: | ---: | --- | --- | --- |
| 1 | 1 | 0 | 0 | ~33 s | 13 s | 47 s |
| 2 | 4 | 0 | 0 | 14–16 s | 13–28 s | 28–43 s |
| 4 | 4 | 0 | 0 | 21–31 s | 13–14 s | 34–45 s |
| 8 | 3 | 0 | 0 | 16–34 s | 13–28 s | 29–63 s |

- Individual specs take 1–2 s. Summed spec time grows from ~26 s (2 procs) to 80–250 s (4–8 procs):
  contention, not more work.
- Bottlenecks: NIC applies reloads serially (~140 ms each); OSS reloads on endpoint changes (173 of 439
  reloads by the end of testing); 4 local CPUs. Not separated; a Plus run would isolate the controller part.
- The `Serial` spec spends most of its 13–28 s waiting for parallel specs' namespaces to finish deleting
  before it can measure reloads.

## Head-to-head with Python

Same minikube, same image (`nginx/nginx-ingress:edge`), equivalent scenarios. Python ran in the test-runner
container on the `minikube` Docker network (no port-forwarding hop, which favours Python).

| scenario | Python selection | Go spec |
| --- | --- | --- |
| VS lifecycle | `TestVirtualServer`: setup, VS update, VS removal | VirtualServer lifecycle |
| mergeable Ingress | `TestSmoke::test_response_code_200_and_server_name[mergeable-*-one-additional-cli-args]` (2) | mergeable Ingress over TLS |
| traffic split | `TestTrafficSplitting::test_several_requests` | VS traffic split |
| basic auth | `TestAuthBasicPolicies::test_auth_basic_policy_credentials` (8 credential cases) | basic auth (3 cases + detach) |
| reload batching | `TestSmoke::test_batch_create_reload_count[standard]` | reload batching (`Serial`) |

| | tests | suite time | where the time goes |
| --- | ---: | ---: | --- |
| Python (pytest) | 15 | **279.7 s** (4 m 52 s incl. image/secrets) | setup 52 s + teardown 76 s (controller and fixture lifecycle); calls 151 s, of which ~145 s are the 8 basic-auth cases at ~16 s each, mostly `wait_before_test()` (3 s default) |
| Go, `--procs=1` | 5 | **18.4 s** | specs 1–2 s each + the `Serial` spec's quiesce wait |
| Go, `--procs=2` | 5 | 17.7 s | too few specs to benefit from parallelism |

- ~15× on the same scenarios, before any parallelism. The gain comes from the shared controller and from
  polling instead of sleeping; both are independent of language.
- Not a perfect match: Python checks 8 credential cases (Go 3) and Go additionally detaches the policy.
  Dropping the 5 extra Python credential cases (~80 s) still leaves ~200 s vs 18 s.

Wider CI context:

- CI merge-queue run 40858466406: 54 smoke jobs, 768 runner-minutes, average 14 min, longest 29 min
  (28 min of it running tests), ~47 min end to end.
- Python suite: 228 test classes each (re)deploy the controller (~10–15 s); 845 explicit sleeps adding up
  to ≥2,773 s.

## Runner size and its effect on speed and concurrency

| environment | CPU | RAM | notes |
| --- | --- | --- | --- |
| CI smoke/regression jobs: `ubuntu-26.04`, public repo | 4 vCPU x64 | 16 GB | kind runs on the runner, sharing it with the test container and image loads |
| same label in a private repo (e.g. `kubernetes-ingress-internal`) | 2 vCPU | 8 GB | if e2e ever runs there, halve the concurrency below |
| PoC (local) | 4 vCPU (minikube limit) | 4 GB (minikube limit) | Docker Desktop VM on a 16 GB Mac; extra port-forwarding hop per request |
| GitHub larger runners | 8–64 vCPU | more | Team/Enterprise plans, billed per minute; not tested |

Source: [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

- **CPU is the limit, and the PoC matched CI (4 vCPU).** API server, etcd, kubelet, NIC config generation
  and serial NGINX reloads, backend pod start-up and the Ginkgo processes all share those CPUs. That is why
  speed-up stopped at 2 processes and summed spec time grew from ~26 s to 80–250 s at 4–8 processes. Expect
  the same ceiling per CI job: default to `--procs=2` on 4-vCPU runners (configurable), not the 8–16
  workers assumed in the migration plan.
- **Memory is not the limit at 2–4 processes.** CI has 4× the PoC's cluster memory. It starts to matter for
  several controller profiles running at once (one NIC pod each) and for App Protect/DoS images, which need
  several GB and likely keep their own jobs.
- **Absolute PoC times are pessimistic for CI** (no Docker Desktop forwarding hop there); the scaling
  between process counts is what carries over.
- **Keep sharding across jobs.** Today 54 jobs × 4 vCPU = 216 vCPU run concurrently. Consolidating into
  4–6 jobs (as the migration plan proposes) would cut that to 16–24 vCPU while one job only gains ~2× from
  parallelism, so wall time would likely get worse. Shard by label across jobs, parallelise within a job,
  and consider larger runners only if measurements justify the cost.
- **Not yet measured on CI hardware** — see the CI run in the spike below.

## How much of the suite fits the design

Controller configurations requested by the Python tests (approximate static parse):

| | count |
| --- | ---: |
| controller configurations | 224 |
| fit the shared default (ignoring metrics/leader-election/log-level) | 106 (47%) |
| top profiles: App Protect 23, OIDC 11, GlobalConfiguration 8+6, allow-empty-host 7, snippets | ~25% |
| distinct flag sets | 45 |
| used by a single test class | 25 |

Per-file triage of the 154 files:

| | files |
| --- | ---: |
| portable today (default controller, one namespace, OSS, no ConfigMap/controller changes) | 31 (127 tests) |
| one blocker: multi-namespace | 16 |
| one blocker: controller flags | 7 |
| one blocker: Plus-only | 6 |
| one blocker: nginx-config ConfigMap | 6 |
| two or more blockers | ~82 |

## Isolating the tail

Python test files that mutate state a shared controller cannot isolate (approximate text search):

| mutates | files | needs |
| --- | ---: | --- |
| `nginx-config` ConfigMap | 43 | a controller the spec owns |
| controller restart/scale | 22 | a controller the spec owns |
| GlobalConfiguration flag | 17 | a controller the spec owns |
| watch-namespace flags | 9 | a controller the spec owns |
| IngressClass objects | 2 | unique names, or vCluster |
| RBAC (ClusterRoles) | 1 | vCluster |
| CRD delete/recreate, upgrade tests | 1+ | vCluster |

Options, cheapest first:

| | A. shared profiles | B. per-sandbox controller | C. vCluster |
| --- | --- | --- | --- |
| what | a few extra NIC releases in the host cluster, each with its own flags and IngressClass | a NIC release inside the spec's namespace with `-watch-namespace=<ns>`, own IngressClass and ConfigMap | own API server, CRDs, ClusterRoles and IngressClasses; pods sync to the host cluster |
| covers | recurring profiles (~25%) | ConfigMap, flags, restarts, GlobalConfiguration: most of the tail | everything, including CRD, RBAC and upgrade tests |
| cost | start-up once per run | controller start-up (~10–15 s) per spec, still in parallel | vCluster create + control-plane pod per instance (not measured) |
| on a 4 vCPU / 16 GB runner | fine | CPU-bound, ~2–4 at once | probably 1–3 at once |
| new dependency | none | none | vCluster Helm chart or CLI + images |

B covers most of the tail without new infrastructure and is parallel-safe, unlike Python's per-class
controller. C is the escape hatch for the few tests that touch cluster-scoped objects, or could host a
whole profile if it proves cheap.

### Earlier vCluster attempt (`tests/vcluster` branch)

Commit `a6595f406` (Oct 2025) added a vCluster CLI wrapper fixture (`vcluster create/delete`, class-scoped,
vCluster v0.29.1 in the test-runner image) and `KubeApis.reset_context()`. It stalled because
`kube_apis`, `cli_arguments` and the controller prerequisites are session fixtures created before any
vCluster exists, and the Python client and `vcluster create` switch a process-wide kube context, which is
not parallel-safe. No timings were recorded.

The Go framework does not have these constraints: a `Framework` is a value built from a kubeconfig, so a
spec can create a second one for a vCluster at any time, and each holds its own client config. Sandboxes,
HTTP, status and artifacts work unchanged inside it; the only framework change is a constructor that
takes a kubeconfig and endpoint. Creating the vCluster through its Helm chart and reading the kubeconfig
from its secret would also remove the CLI dependency (to be confirmed for the current release).

Open questions for the optional spike item:

1. Reaching the vCluster API from outside: its kubeconfig points at `localhost`. On CI (kind) a NodePort on
   the node IP should work; locally minikube needs extra `--ports` at creation or the host API server's
   service proxy.
2. Data plane: does the synced NIC NodePort service keep a pinned host port, and does NIC inside the
   vCluster see EndpointSlices of synced pods correctly?
3. Cost on a 4 vCPU / 16 GB runner: create time, control-plane memory/CPU, how many fit next to the
   default controller.
4. Version: the branch pinned v0.29.1; re-check against the current release.

## AI-assisted porting sample (unreviewed, not executed)

20 of the 31 portable files were ported in one pass by AI agents before the work was stopped. They are
stashed (`git stash list`: "e2e-go: unreviewed AI ports …"), not part of the PoC.

- Compiles; `go vet` clean; 3 minor lint findings. No `time.Sleep`; one sandbox per spec; Python classes
  with dependent steps became one `It` with `By` steps or `Ordered` containers.
- Size: 2,137 lines of Go for 6,629 lines of Python (~32%).
- Coverage loss found: the API-key test dropped its `/no-auth` assertion because the shared controller
  runs without `-enable-snippets` — exactly the profile problem above.
- Framework gaps the ports hit: asserting an admission rejection, event counts, VSR namespace rewriting,
  controller profiles.
- **Not run against the cluster, so pass rate is unknown.** Review effort for AI output is the real
  constraint: ~30% of Python size still means 15–20k lines of Go for the whole suite.

## Two-language cost (git history, last 12 months)

- 155 commits changed Go, 59 changed Python e2e, 46 changed both (78% of Python test commits).
- 13 people changed Python tests; 12 of them also changed Go. 12 of 24 Go authors never touched them.
- Python e2e grew +20.6k / −2.0k lines (~35%); 130 commits touched Python deps/tooling (108 by bots).

## Status against #11061 acceptance criteria

| criterion | PoC status |
| --- | --- |
| pytest markers → Ginkgo labels, CI matrix runs Go | labels used; mapping and CI not done |
| tracking table per `test_*.py` | not done; triage above is the starting point |
| `make -C tests …` runs locally with no Python | yes (`e2e-poc`, minikube) |
| parallel-safe by default, `Serial` where not | yes |
| failure artifacts: NIC logs + rendered config | yes, locally; CI upload not wired |
| no credentials on command line | not exercised (OSS only) |
| runtime same or lower | yes for 5 scenarios locally: 279.7 s Python vs 18.4 s Go; not yet on CI |

## Recommendation and next steps

1. **Spike (1–2 days)** before committing:
   - second controller profile (e.g. `-enable-snippets`) with its own IngressClass, in parallel with the
     default one — check how NIC treats VirtualServers without `ingressClassName` with two controllers;
   - per-sandbox controller (option B above): a NIC release in the spec's namespace with
     `-watch-namespace` and its own IngressClass, porting one `nginx-config` ConfigMap test;
   - multi-namespace sandbox and one cross-namespace VSR port;
   - one Plus run (no endpoint reloads; JWT from env/file, not CLI);
   - one run on a real CI runner (`ubuntu-26.04`, kind) with `--procs` 1/2/4, recording CPU and memory of
     the kind node (`docker stats`), plus the same Python selection on the same runner for a CI head-to-head;
   - optional: one vCluster (option C) running the PoC specs, answering the open questions above.

   Go if: specs stay ≤ ~50 lines, the spike adds ≤ ~300 framework lines, 10 consecutive runs are green, and
   the CI run confirms the local scaling (or shows where the per-job ceiling really is).
2. **Then:** new e2e tests in Go only; migrate one CI matrix job at a time and delete its Python in the same
   change, so there is never double coverage to maintain.
3. **Estimate (one engineer with AI):** whole suite ≈ 30–50 engineer-days plus 15–30 reviewer-days;
   two sprints ≈ framework + 50–70 files.

## Known limitations of the PoC

- OSS only; Plus, App Protect, OIDC not tried.
- minikube on a laptop, not CI hardware: same CPU count (4) but a quarter of the memory, arm64 instead of
  x64, and Docker Desktop port forwarding on every request. Timings are relative, not absolute.
- Head-to-head covers 5 scenarios only; Python and Go selections are equivalent, not identical.
- Counts for flag sets and blockers come from static text parsing and are approximate.
