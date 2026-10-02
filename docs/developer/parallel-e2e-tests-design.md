# Design Document: Parallel E2E Test Execution

## Status: Draft — Seeking Team Input

## TL;DR

- **Problem.** CI critical path is ~47 min (measured on
  [run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492)).
  Under Renovate volume the merge queue backs up; urgent releases wait
  hours. Merge queue has already been tried and did not deliver at
  the current flake rate.
- **Primary proposal.** Run multiple kind clusters per GHA runner and
  drive them with parallel pytest processes (Path B). With current
  shard sizes this cuts NAP runner-minutes by ~33 % but leaves the
  smoke critical path at ~29 min (bounded by the two `ingresses`
  shards). Reaching ~15–16 min requires the outlier-shard splits in
  [Phase 0.5](#phase-05--split-outlier-shards-parallel-workstream) —
  which are independent of the parallel-e2e infrastructure and can
  ship in parallel. Details in [Design Options](#design-options) and
  [Wall-Time Target](#wall-time-target).
- **Secondary proposals.** Trim `merge_group` test surface below
  `pull_request`, add a hotfix bypass workflow, cap Renovate
  concurrency, broaden path-based skips. Ship in parallel with the
  main work. Details in [Merge Throughput and Urgent Releases](#merge-throughput-and-urgent-releases).
- **Load-bearing prerequisite.** Flake reduction. No throughput
  scheme (including this one) survives long-term at a 2 % per-shard
  flake rate. Treated as its own initiative.
- **Non-goals.** Replacing pre-merge e2e with a synthetic cloud
  canary (considered, kept as a complementary post-merge signal).
  Push-to-`main` trunk-based dev without pre-merge signal (rejected
  for a foundational infrastructure component). Details in
  [Considered Alternatives](#considered-alternatives).
- **Effort.** Phase 0 local prototype in days. Full rollout across
  NAP / Plus / OSS matrices over one release cycle. Merge-throughput
  items are independent and can land immediately.

## Summary

Reduce CI wall-clock time by running multiple Kubernetes clusters and pytest
processes in parallel on each GitHub Actions runner. Today each smoke-test
matrix cell owns one runner and one kind cluster; this document proposes a
model where each runner hosts 2–3 kind clusters and drives them concurrently
with independent pytest processes and independent result reporting.

Two complementary paths are considered:

- **Path B (recommended first step)**: multiple kind clusters per runner, each
  driven by its own pytest process. Minimal test-code changes.
- **Path A (follow-up)**: single kind cluster per runner with N pytest-xdist
  workers isolated by namespace and IngressClass. Larger fixture rework but
  higher density per runner.

Trunk-based development with a cloud canary was considered as an
alternative and is discussed under [Considered Alternatives](#considered-alternatives);
it is complementary, not a substitute. PR-size discipline — the other
driver of stale PRs — is covered in the same section.

## Motivation

CI end-to-end (e2e) tests dominate PR wall time. Data below is from a
dedicated pytest `--durations=0` run on `chore/pytest-speedup`
([workflow run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492))
aggregated across 55 smoke shards, plus 30 days of sampled per-shard wall
times:

- The slowest full CI run in the sample was 44:20; the median completed run
  is ~25 min. The critical path is always a python smoke-test shard.
- The single longest individual test observation was **752.73 s**
  (`test_dos.py::test_dos_under_attack_with_learning`), which has a
  hardcoded 900 s App Protect DoS ML-learning cap and cannot be reduced by
  sharding.
- Longer-tail shards (`policies 2/2 alpine`, `AP_WAF 3/4`) routinely take
  22–25 minutes. Measured: `test_app_protect_waf_policies.py` averages
  133 s per test across 9 tests → ~20 min of call time plus setup/teardown.
- ~60–70 % of every CI run is spent inside python e2e tests. Everything
  else (Go unit tests, lint, static analysis, image build) sums to
  <10 minutes.

### Measured slowest test files (top 10)

From [run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492),
mean call duration grouped by file (n = number of test invocations across
the run's shards):

| File | mean (s) | max (s) | n |
|---|---:|---:|---:|
| `test_dos.py` | 242.78 | 752.73 | 6 |
| `test_app_protect_waf_policies.py` | 133.06 | 139.22 | 9 |
| `test_app_protect_waf_policies_ing.py` | 121.02 | 121.02 | 2 |
| `test_virtual_server_dos.py` | 59.69 | 202.53 | 4 |
| `test_virtual_server_custom_ip_listeners.py` | 48.11 | 48.12 | 4 |
| `test_virtual_server_externaldns.py` | 43.50 | 63.21 | 6 |
| `test_app_protect_watch_namespace_label.py` | 36.12 | 36.12 | 1 |
| `test_use_cluster_ip.py` | 35.08 | 36.42 | 4 |
| `test_app_protect_integration.py` | 33.65 | 132.12 | 8 |
| `test_virtual_server_wildcard.py` | 28.60 | 29.11 | 2 |

Key observations:

- DoS is a two-file problem, not one. `test_dos.py` owns the 900 s ML
  outlier; `test_virtual_server_dos.py` has a 202 s max. Any "move DoS
  learning to nightly" decision must cover both, not just `test_dos.py`.
- Individual non-DoS test calls cap at ~140 s. Policy tests are individually
  fast (~20–30 s) but numerous — they are already grouped into `policies_1/2`
  and `policies_2/2` shards for that reason.
- No non-NAP, non-DoS test breaks 1 minute of call time. Wall-time gains
  outside NAP/DoS must come from parallelism, not from cutting individual
  tests.
- **DoS is no longer the critical path.** Per-shard measurement below
  shows `ingresses 1/3 alpine-plus` at **28:40** as the slowest single
  shard — longer than `AP_DOS 3/3` at 16:38 and `AP_WAF 3/4` at 23:12.
  Until the ingresses shards are further split, they set the pre-merge
  wall-time floor, not the App Protect DoS ML wait.

### Measured slowest shards (top 10, wall time)

Same [run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492),
per-shard wall time from `--mode jobs` (includes NIC setup, test
call time, teardown, artefact upload):

| # | Shard | Wall time |
|---:|---|---:|
| 1 | `ingresses 1/3 alpine-plus` | 28:40 |
| 2 | `ingresses 1/2 debian` | 28:29 |
| 3 | `AP_WAF 3/4 alpine-plus-nap-fips` | 23:12 |
| 4 | `VS 1/4 debian` | 22:53 |
| 5 | `policies 2/9 ubi-10-plus` | 21:42 |
| 6 | `ingresses 3/3 alpine-plus-fips` | 20:07 |
| 7 | `policies 4/9 ubi-10-plus` | 20:06 |
| 8 | `VS 1/5 debian-plus` | 18:33 |
| 9 | `ingresses 2/2 debian` | 18:30 |
| 10 | `TS ubi` | 18:29 |

AGENT / AGENT_V3_NAP shards are defined in
[.github/data/matrix-smoke-nap.json](../../.github/data/matrix-smoke-nap.json)
but did not run in this workflow. Worth confirming whether they are
expected on this branch before finalising NAP grouping.

We already re-sharded the highest-signal offenders (splitting
`test_app_protect_waf_policies.py` `_vsr` classes and
`test_app_protect_integration.py` into their own shards). Further wall-time
gains require executing shards in parallel per runner, not just in parallel
across runners.

## Current State

### Runner topology (today)

- ~30 smoke shards defined across `matrix-smoke-oss.json`,
  `matrix-smoke-plus.json`, `matrix-smoke-nap.json`.
- One GitHub Actions runner per shard (ubuntu-24.04, 4 vCPU / 16 GB RAM).
- Each runner:
  1. Checks out the repo (~30 s)
  2. Authenticates to Azure/GCR/DockerHub (~30 s)
  3. Creates one kind cluster (~30–60 s)
  4. Loads the NIC image into the cluster via `ctr images import` (~15–30 s)
  5. Runs pytest against that cluster (10–25 min)
- Total per-shard setup overhead is ~2 min before any test runs.

### What NIC already supports for multi-tenancy

- `-ingress-class` isolates resource reconciliation between NIC instances.
- `-watch-namespace` / `-watch-namespace-label` restricts each NIC to a
  namespace subset.
- Leader election is scoped to the NIC's own namespace.
- CRDs are cluster-scoped definitions; resources are namespaced.
- Kind supports arbitrarily many named clusters on the same Docker daemon,
  each on its own Docker network.

The controller is designed for parallel deployment; the friction lives in the
test harness.

## Design Options

### Option B — Multiple kind clusters per runner (recommended first)

Each runner spins up N kind clusters (`test-1`, `test-2`, …) and runs N
pytest processes in parallel, one per cluster. Test isolation is provided by
the fact that each pytest process talks to a fully separate cluster.

**Pros**

- Zero test-code changes. Each pytest process runs an unmodified test suite
  against its own cluster.
- Complete isolation: cluster-scoped resources, CRDs, IngressClass names,
  webhooks — all independent because clusters are independent.
- Amortises per-runner setup (auth, checkout, image build) across multiple
  shards.
- Straightforward failure attribution: per-cluster kubeconfig, per-cluster
  logs, per-cluster result artefact.

**Cons**

- Each kind control plane costs ~500 MB RAM and ~30 s of spin-up time,
  paid N times per runner.
- The NIC image must be loaded into each cluster (~20 s per cluster).
- The runner's disk fills faster (each cluster stores its own container
  images).

**Resource budget on ubuntu-24.04 (4 vCPU / 16 GB)**

| Item | Per cluster |
|---|---|
| kind control-plane (etcd + apiserver + kubelet) | ~700 MB RAM |
| NIC pod | ~200 MB RAM |
| Test workload pods (nginx-hello etc.) | ~50–100 MB each |

Comfortable ceiling: **3 clusters concurrently**. Aggressive: 4. Beyond 4,
docker networking and disk pressure become the flake source.

### Option A — Single cluster, N pytest-xdist workers (follow-up)

Each runner runs one kind cluster. Pytest-xdist (`-n auto`) starts N worker
processes. Each worker uses a distinct IngressClass and NIC installation to
avoid cross-worker interference.

**Pros**

- Higher density per runner (one control plane serves N workers).
- Smaller per-runner memory footprint than N clusters.
- Faster startup — one cluster, one image load.

**Cons**

- Substantial fixture rework required (see [Fixture rework](#fixture-rework)).
- Cluster-scoped state (GlobalConfiguration, cluster-wide policies) forces a
  subset of tests to remain serial.
- A test that corrupts the cluster (e.g. crashes NIC) can affect other
  workers.
- Coverage regressions harder to spot — a leaked resource from one worker can
  cause a spurious failure in another.

**Recommendation**

Build Option B first. It gives most of the wall-time win with far less risk.
Revisit Option A as a follow-up if per-runner density becomes the bottleneck.

## Failure Isolation

The primary team concern with multi-shard-per-runner execution is failure
blast radius. The design guarantees:

1. **Independent exit codes.** Each pytest process runs backgrounded; its
   exit code is captured into an array. The job step aggregates but does not
   propagate a single early failure.
2. **Independent artefacts.** Each shard's `pytest-html` report, JUnit XML,
   and captured NIC logs upload as a distinctly named artefact
   (`shard-<label>-*`), so reviewers can download only the failing shard's
   data.
3. **Independent kind clusters.** Cluster corruption cannot leak between
   shards — kind puts each cluster on its own Docker network.
4. **`continue-on-error` at the loop level.** One shard failing at minute 3
   does not cancel siblings still running at minute 15.
5. **Step summary table.** Per-shard status published to
   `$GITHUB_STEP_SUMMARY` so failures are visible without opening logs.
6. **Cluster deletion in a `finally` block.** Failing to clean up one cluster
   never blocks cleanup of siblings.

The only unavoidable coupling: if the runner exhausts disk or RAM, all
clusters on it die. Mitigated by capping concurrent clusters at 3 (safe on
ubuntu-24.04-16GB); switch runner class before going higher.

## Fixture Rework

### For Option B (kind-per-shard-process)

Minimal. Each pytest process runs against a distinct kubeconfig context and
its own namespace pool. What needs verifying:

- `--context` and `--node-ip` CLI options must correctly route to each
  cluster's kind node. Already supported.
- The `test_namespace` fixture generates unique namespaces per test. Verify
  no shared global state (e.g. hardcoded namespace names) in fixture code.
- The `ingress_controller_prerequisites` fixture installs NIC into a fixed
  `nginx-ingress` namespace. Fine when each process owns its own cluster;
  becomes a problem for Option A.
- `--html` output path must be per-process. Already parameterisable.

### For Option A (xdist within one cluster)

Substantial. The following fixtures need worker-awareness:

- **`ingress_controller_prerequisites`** — currently session-scoped and
  assumes single `nginx-ingress` namespace. Needs a worker-scoped variant
  producing `nginx-ingress-<worker_id>` + unique IngressClass.
- **`crd_ingress_controller`** — installs and uninstalls NIC per class
  parametrisation. Worker-scoped installation with unique deployment name.
- **`test_namespace`** — already unique per test; verify no cross-worker
  collision from PID-based naming.
- **Hardcoded `nginx` IngressClass** — many YAML files under `tests/data/`
  reference `ingressClassName: nginx`. Needs templating or fixture-level
  patching.
- **`ingress_controller_endpoint`** — stores NodePort assignments; must look
  up NodePorts of the correct NIC instance.
- **Cluster-scoped tests** (`GlobalConfiguration`, cert-manager,
  cluster-wide policies) must stay serial. Mark with a `@pytest.mark.serial`
  and use `pytest-xdist --dist loadgroup` to keep them on a single worker.

Estimated effort: ~1 sprint of one engineer, plus stabilisation.

## Shard Grouping Strategy

Groups combine shards that share a runner. Grouping rules:

1. **Never group shards that mutate cluster-scoped state.** `GlobalConfiguration`
   tests, cluster policies — group of size 1.
2. **Group by base image / NAP module.** WAF shards together (they share the
   NAP-WAF image already loaded on the runner); DoS shards together.
3. **LPT balance within a group.** Pair a long shard with a short shard so
   total group time ≈ longest shard time.
4. **Isolate the immovable outlier.** Any shard whose runtime already
   exceeds the group budget is a group of one — pairing wastes
   parallelism on an idle cluster.

Measured NAP grouping (from [run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492),
bin-packed with a ~25 min group budget matching the longest single NAP
shard):

| Group | Shards | Wall time |
|---|---|---:|
| G1 | `AP_WAF 3/4` (23:12) alone | ~23 min |
| G2 | `AP_DOS 3/3` (16:38) + `AP_DOS 1/3` (8:06) | ~25 min |
| G3 | `AP_WAF 2/4` (16:15) + `AP_WAF_INT` (8:58) | ~25 min |
| G4 | `AP_DOS 2/3` (16:04) + `AP_WAF 1/4` (9:40) | ~26 min |
| G5 | `AP_WAF_V5` (15:46) + `AP_WAF_VSR` (10:07) | ~26 min |
| G6 | `AP_WAF 4/4` (10:06) + `AGENT` / `AGENT_V3_NAP` if enabled | ~10–20 min |

Runner count for NAP: **10 → 6**. Total NAP shard-minutes measured at
~135 (vs the previous ~160 estimate).

### Non-NAP outliers

The binding wall-time constraint is not NAP. Two `ingresses` shards
run >28 min each:

- `ingresses 1/3 alpine-plus`: 28:40
- `ingresses 1/2 debian`: 28:29

Plus `VS 1/4 debian` (22:53), `policies 2/9 ubi-10-plus` (21:42),
`ingresses 3/3 alpine-plus-fips` (20:07), `policies 4/9 ubi-10-plus`
(20:06). No grouping scheme can drop the smoke critical path below the
longest single shard, so these need further splitting to unlock the
full benefit of parallel-e2e. Suggested next actions:

- Profile `ingresses 1/3 alpine-plus` and `ingresses 1/2 debian`
  (both marked `ingresses_smoke`) with `--durations=0` to find the
  splittable classes.
- Consider a `policies 2/9` / `policies 4/9` split by policy family
  (jwt, rate-limit, external-auth) rather than sequential numbering.
- Similar exercise for `matrix-smoke-plus.json` and
  `matrix-smoke-oss.json`.

## Wall-Time Target

Baseline from [run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492):
total CI 47:30; slowest single shard `ingresses 1/3 alpine-plus` at
28:40; slowest NAP shard `AP_WAF 3/4` at 23:12; NAP shard-minutes
~135.

| Scope | Today (measured) | With Option B | Reduction |
|---|---:|---:|---:|
| Slowest NAP shard | 23:12 (`AP_WAF 3/4`) | 23:12 (unchanged; longest single NAP shard sets the group floor) | 0 % |
| Slowest single smoke shard | 28:40 (`ingresses 1/3 alpine-plus`) | 28:40 (unchanged unless split; see [Shard Grouping Strategy](#shard-grouping-strategy)) | 0 % |
| Total NAP runner-minutes billed | ~135 | ~90 | ~33 % |
| End-to-end CI critical path | ~47 min | ~35 min | ~25 % |
| Best-case CI (with ingresses shard split, DoS-learning to nightly) | — | ~25 min | ~47 % |

**Binding constraint (measured): ~29 minutes for the smoke critical
path**, set by `ingresses 1/3 alpine-plus` and `ingresses 1/2 debian`
at ~28:40 each. Neither is a NAP shard. No grouping scheme drops the
critical path below the longest single shard, so materially cutting
wall time below ~29 min requires splitting these shards first.

**DoS learning floor.** `test_dos_under_attack_with_learning` still
waits up to 900 s for App Protect DoS ML convergence (measured max
752.73 s in the run above). Total `AP_DOS 3/3` shard wall time was
16:38 — below the ingresses floor. Moving DoS learning to nightly
frees ~17 min of runner-minutes per PR but does not reduce wall time
until the ingresses shards are also split.

Additional gains from Option A (if pursued later) would be marginal on top
of B — the outlier shards still set the critical path.

## Considered Alternatives

### Trunk-based development with cloud canary

**Proposal.** Push directly to `main`. Replace pre-merge e2e (where
possible) with a permanently-running cloud Kubernetes cluster hosting
multiple NIC installations. Drive it with a synthetic site that
exercises the `examples/` directory under sustained traffic. Rely on
observability to detect regressions post-merge.

**What it addresses**

- Perceived merge latency: authors stop waiting on a 40 min pipeline.
- Integration risk: short-lived work, no long merge queue.
- Some classes of bug that pre-merge e2e cannot catch — reload timing
  under sustained load, memory-leak curves, connection reuse patterns.

**Why it does not replace pre-merge e2e for NIC**

1. **Blast radius on `main`.** NIC is foundational infrastructure. A
   regression corrupts real users' clusters. Rollback is a
   re-published image plus a customer-driven Helm upgrade — not a
   control-plane flip. The cost of shipping a bug is materially higher
   than for SaaS products whose trunk-based practices we usually cite.
2. **NAP/WAF and DoS shape is wrong for synthetic traffic.** These
   shards dominate wall time today. They also require malicious
   payloads and attack traffic that a "normal-traffic" synthetic site
   does not naturally produce. They would have to stay pre-merge, which
   keeps ~70 % of the current wall time in place.
3. **`examples/` ≠ coverage.** The examples cover happy paths. The
   current e2e suite exercises edge cases: broken CRDs, invalid TLS
   bundles, VSR nesting, GlobalConfiguration collisions, cert-manager
   races, IngressClass mismatches, malformed annotations,
   TransportServer under packet loss. A synthetic site would be a
   strict subset of current coverage.
4. **Release model mismatch.** NIC ships versioned container images
   and a Helm chart, with `release-x.y` branches and LTS commitments.
   "Trunk = production" is really "trunk = the next release candidate";
   the stabilisation branch cadence does not go away.
5. **Cost.** A permanently-running cluster + traffic generators +
   observability stack (Prometheus, Grafana, log aggregation, tracing)
   running 24/7 is not clearly cheaper than the current GHA runner
   spend. A dedicated cost model is required before commitment.

**Where it does fit**

As a *post-merge* signal complementing pre-merge e2e — not as a
replacement. Deploy from `main` on a schedule, run the synthetic
workload, alert on regression, gate the next release on canary health.
Best value: catches production-shaped issues (long-running reload
behaviour, memory curves, connection churn) that unit and e2e tests
fundamentally cannot.

**Prerequisites before this is viable**

- Feature-flag discipline: every user-visible change lands behind a
  controller flag, annotation, or Helm value. Extend the existing NIC
  pattern rather than invent a new one.
- Automatic rollback on canary regression. Manual "someone gets paged,
  investigates, reverts, re-releases" is too slow for a foundational
  component.
- A clear owner for the synthetic site. These systems get stale fast
  when they are nobody's day job.
- Parallel-e2e (this document) already shipped — you still need fast
  pre-merge signal, the surface just gets smaller.

**Recommendation**

Not a substitute for the work in this document. Revisit as a follow-up
release-model change once parallel-e2e is in production and PR-size
discipline (below) is established.

### PR-size discipline

The other driver of stale PRs is size: features landing in one
large, largely AI-authored change. This is upstream of any workflow or
CI choice — no merge model fixes an unreviewable diff.

Levers, in decreasing order of leverage:

1. **PR-size budget with an enforced check.** Hard limit on
   non-generated, non-vendored changed lines (e.g. 600). Above the
   limit requires a linked justification or a stack of PRs. Even a
   soft budget with a bot comment shifts behaviour quickly.
2. **Feature = 1 tracking issue, N linked PRs, gated by a flag.**
   Extend the existing controller-flag / annotation-gate pattern. This
   naturally slices a "full feature" into infra-PR + implementation-PR
   + wire-up-PR + enablement-PR, each independently reviewable.
3. **AI-authored diff hygiene, made explicit in the PR template.**
   Required field: "What did you remove that the AI generated but
   wasn't necessary?" Small friction that flips the incentive.
4. **Reviewer tooling for AI-authored diffs.** LLM-assisted diff
   summarisation, deviation-from-convention detection, new-import
   flagging. Reviewer attention is scarcer than author time; direct
   tooling there.
5. **Flake-rate reduction as a first-class metric.** With volume of
   PRs increasing, the marginal cost of every rerun rises. Track flake
   rate on the pipeline dashboard and burn it down like any other bug.

Relationship to this document: parallel-e2e removes the pipeline-speed
excuse for large PRs. Today, small and large PRs pay the same ~47 min
tax, which perversely rewards batching. Cutting the critical path to
~35 min (or ~25 min once the ingresses shards are split) makes
small-PR discipline economically obvious to authors.

## Merge Throughput and Urgent Releases

Parallel-e2e cuts per-PR wall time. It does not address queue depth
under Renovate volume, nor urgent-release paths that today share the
same CI gates as every other PR. The following interventions target
throughput directly and can ship in parallel with the main work.

### Context

- Merge queue is enabled on `ci.yml`, `lint-format.yml`,
  `codeql-analysis.yml`, `dependency-review.yml`.
- Renovate has `automerge: true`, daily schedule, 10+ dependency
  groups already configured, `prConcurrentLimit` unset.
- `docs_only` path filter skips tests and Docker builds via
  `.github/scripts/variables.sh`; no other path filters.
- No documented hotfix workflow. All releases go through
  `workflow_dispatch` with the same CI gates as every PR.

### Why the existing merge queue is not delivering

Batched merge queue only wins when per-run success is high. At a 2 %
per-shard flake rate across ~30 shards, per-run flake probability is
$1 - 0.98^{30} \approx 45 \%$. Batch attempts fail spuriously, retries
dominate, and the queue effectively serialises with extra latency.
**Flake reduction is a prerequisite for any throughput scheme —
including this one — to hold long-term.**

### Interventions, in ranked order

1. **Trim `merge_group` test surface below `pull_request`.** Today
   `merge_group` re-runs the full smoke suite the PR just passed.
   `merge_group`'s job is narrower: catch regressions from interaction
   with what merged since PR review. Run unit + build + a fast smoke
   subset (~5–8 min) on `merge_group`; full suite on `pull_request`
   only. Cuts queue-tax per PR by ~4× and drops flake exposure by the
   same factor. Trade-off: rare merge-conflict-induced regressions may
   leak to `main`; caught by nightly regression that already exists.

2. **Hotfix bypass workflow.** Triggered by a `hotfix` label on a PR
   against a `release-x.y` branch. Runs unit + build + lint + a
   curated ~5 min smoke subset (`smoke` + `ingresses_smoke` markers).
   Requires two maintainer approvals and a linked issue. Skips the
   merge queue. Produces a release candidate with the normal tag
   scheme. Decouples urgent bug fixes from Renovate queue depth
   entirely.

3. **Cap Renovate `prConcurrentLimit`.** Currently unlimited. Set to
   3 in `renovate.json`. Bounds queue depth without reducing total
   Renovate work; predictable batch shape day-to-day.

4. **Broaden path-based skips.** Extend `.github/scripts/variables.sh`
   with additional classifications:
   - `workflow_only` — only `.github/workflows/**` changed → skip
     smoke, run lint + workflow validation. Absorbs Renovate
     GitHub-Actions bumps (a large fraction of Renovate volume).
   - `helm_only` — only `charts/**` changed → skip Go tests + Docker
     build, run Helm unit tests + one smoke shard.
   - `python_test_only` — only `tests/suite/**` changed → skip Go
     tests + Docker build.
   - `agent_config_only` — only `.agents/**`, `AGENTS.md`, `CLAUDE.md`,
     `.github/copilot-instructions.md` → skip everything except lint.

5. **Flake budget with quarantine lane** *(prerequisite for anything
   above to last)*. Instrument per-shard outcome tracking on `main`,
   publish a rolling failure rate, set an SLO: any test above 0.5 %
   failure rate over 20 runs is a bug. Failing the SLO moves the test
   to a `quarantine` marker that runs nightly but does not gate merges
   until root-caused. Bounded rerun policy via `pytest-rerunfailures`
   limited to tests explicitly marked `@pytest.mark.known_flake` — not
   blanket rerun-on-fail.

6. **Infra-flake auto-retry.** Kind boot timeout, image pull backoff,
   Docker daemon EOF are infrastructure, not test bugs. Add a workflow
   step that scans the failed job's logs for a known-infra-flake
   fingerprint and retries the shard once before failing the
   `merge_group`. Pragmatic bridge until (5) lands.

### Sequencing against the parallel-e2e rollout

| Timing | Item | Effort |
|---|---|---|
| Days | Cap `prConcurrentLimit`; add `workflow_only` and `helm_only` filters | Hours |
| Sprint | Hotfix bypass workflow; slim `merge_group` surface with comparison window | Days |
| Alongside [Phase 1](#phase-1--new-composite-action) | Infra-flake auto-retry in `smoke-tests-parallel` action | Days |
| Quarterly | Flake budget + quarantine + SLO dashboard | Multiple sprints |

The near-term items are independent of parallel-e2e and can ship in
any order. The flake-budget work is what makes any throughput scheme
durable; without it, the same conversation recurs.

## Phased Rollout

### Phase 0 — Local prototype (mechanics PoC)

Proves the runtime model works; does **not** cut CI wall time.

Delivered:

- [tests/scripts/run-parallel-shards.sh](../../tests/scripts/run-parallel-shards.sh)
  — round-robin fan-out driver.
- [tests/ci-files/parallel-kind-config.yaml](../../tests/ci-files/parallel-kind-config.yaml)
  — kind config without `extraPortMappings` (host-port collisions
  otherwise).
- [tests/Makefile](../../tests/Makefile) targets:
  `create-parallel-kind-clusters`, `delete-parallel-kind-clusters`,
  `parallel-image-load`, `run-parallel-shards`, `parallel-smoke`,
  `ensure-test-runner-image`.

What this validates:

- Multiple kind clusters coexist on the shared `kind` docker network
  without stepping on each other.
- Each pytest process talks to the correct cluster via `--context` and
  a per-cluster kubeconfig mounted as `/root/.kube/config`.
- Session-scoped fixtures behave when isolated per-cluster (Path B
  minimal-change assumption).
- Per-shard artefacts (`report.html`, `junit.xml`, `pytest.log`,
  `exit_code`, `duration`) capture cleanly.

Success criterion: wall time for 3 shards ≤ 1.4 × wall time of the
slowest shard on a laptop (or on a Linux CI runner).

#### Gotchas discovered while building Phase 0

Captured so Phase 1 (CI composite action) doesn't re-hit them:

1. **Do not merge per-cluster kubeconfigs.** Merging into a single file
   forces one `current-context`, so any pytest fixture using `kubectl`
   without an explicit `--context` writes to the wrong cluster. Result:
   cluster-scoped resources like `IngressClass` collide across shards.
   Fix: keep per-cluster `config-<N>` files, mount the one matching the
   shard as `/root/.kube/config:ro`.
2. **Matrix JSON marker values contain literal single quotes** (e.g.
   `"marker": "'foo and not bar'"`). The CI composite action passes
   them through the shell unquoted so the outer quotes act as shell
   quoting; a bash driver must strip them before `pytest -m` or pytest
   sees an invalid marker expression and exits `rc=4`.
3. **`--image-pull-policy=Never`, not `IfNotPresent`.** With
   `IfNotPresent` Kubernetes still tries the registry when the image
   isn't found locally, producing `ImagePullBackOff` for kind-loaded
   dev images. CI's composite action already uses `Never` for the same
   reason.
4. **Default kind config publishes host ports 80/443/32345.** Fine for
   one cluster; guaranteed collision for N. Parallel runs need a
   config without `extraPortMappings` — pytest runs inside a
   docker container on the `kind` network and reaches each API server
   by container name, so host publishing is not required.
5. **macOS + Docker Desktop + kind image load is unreliable.** BuildKit
   attaches OCI attestation manifests that neither `docker save |
   ctr images import` nor `kind load docker-image` unpacks correctly
   on Apple Silicon; the image "loads" without error but is missing
   from containerd. Linux CI runners are unaffected. Local Mac
   validation currently requires either rebuilding the image with
   `--provenance=false --sbom=false` or the future minikube-parallel
   targets (see [Open Questions](#open-questions)).
6. **Kind CLI version ≥ v0.32 required** for `kindest/node:v1.36.1`
   (older CLIs error with `unknown containerd config version: 4`).

Known caveat: kind on macOS is historically flaky (points 5 and 6
above); fall back to minikube profiles for local iteration if needed.
CI is unaffected (Linux runners with kind are stable).

### Phase 0.5 — Split outlier shards (parallel workstream)

**Prerequisite for any wall-time reduction.** Path B's bin-packing
wins runner-minutes but cannot cut wall time below the longest single
shard. Splitting the outliers is what actually moves the critical
path.

Targets, in priority order (from [Wall-Time Target](#wall-time-target)):

| # | Shard | Today | Target after split |
|---:|---|---:|---:|
| 1 | `ingresses 1/3 alpine-plus` | 28:40 | ~14 min × 2 |
| 2 | `ingresses 1/2 debian` | 28:29 | ~14 min × 2 |
| 3 | `AP_WAF 3/4 alpine-plus-nap-fips` | 23:12 | ~12 min × 2 |
| 4 | `VS 1/4 debian` | 22:53 | ~11 min × 2 |
| 5 | `policies 2/9 ubi-10-plus` | 21:42 | ~11 min × 2 |

Method for each shard:

1. Enable `pytest --durations=0` on the shard.
2. Run once on `main` (or a scratch branch) via the existing CI.
3. Feed the log to [tests/scripts/longest_test_job.py](../../tests/scripts/longest_test_job.py)
   `--mode durations --group-by file --run-id <ID>` to find the
   heaviest test classes.
4. Split the marker in the relevant
   [`.github/data/matrix-smoke-*.json`](../../.github/data/) entry
   into two disjoint pytest markers of roughly equal weight.
5. Verify the split shards each land under the target budget on the
   next CI run.

Each split is independent, low-risk, and does **not** depend on
parallel-e2e infrastructure. The five splits together drop the smoke
critical path from ~29 min to ~15–16 min (bounded by `AP_DOS 3/3` at
16:38 unless `dos_learning` is also moved to nightly).

### Phase 1 — New composite action

- Fork `.github/actions/smoke-tests/action.yaml` into
  `smoke-tests-parallel/action.yaml` (keep the old one working).
- Accepts a JSON array of shard configs.
- Spawns one cluster + one pytest per config in parallel.
- Uploads one artefact bundle per shard.
- Publishes a per-shard result table to `$GITHUB_STEP_SUMMARY`.
- Exits non-zero only after all shards complete.

### Phase 2 — Grouped matrix

- Add `matrix-smoke-nap-grouped.json` next to the existing per-shard file.
- Groups configured per the [grouping table](#shard-grouping-strategy).
- New CI job `smoke-tests-nap-parallel` runs alongside the existing
  `smoke-tests-nap` for a comparison window.

**Wall-time expectation.** The runner-count and runner-minute wins
land in this phase regardless of Phase 0.5. The **wall-time win** only
materialises for matrices whose Phase 0.5 splits have shipped; before
those splits, grouping preserves the current critical path (bounded
by the pre-split longest shard).

### Phase 3 — Comparison window

- Both paths run on every PR and merge_group for one release cycle.
- Compare wall time, flake rate, and total runner-minutes billed.
- If parallel path is at least as reliable and materially faster, cut over.

### Phase 4 — Cut over

- Rename `smoke-tests-nap-parallel` to `smoke-tests-nap`.
- Retire the old per-shard matrix.
- Repeat for `matrix-smoke-plus.json` and `matrix-smoke-oss.json`.

### Phase 5 — Post-launch audit

- Measure correlation of failures across shards within the same group. Should
  be near zero; non-zero indicates a shared-cluster leak or runner-level
  flake (disk, docker daemon).
- Measure re-run success rate. If groups re-run cleanly, isolation is
  working; if one shard consistently fails on re-run while siblings pass,
  it's a test flake, not a parallelism issue.

## Open Questions

- Do we want to change GHA runner class (e.g. to a 16-core self-hosted) to
  push beyond 3 concurrent clusters? Cost vs. speed trade-off.
- Should `AP_DOS 3/3` be moved to a nightly job instead of blocking every
  PR? Frees ~17 min of runner-minutes per PR but does **not** cut wall
  time until the ingresses shards are also split (see
  [Wall-Time Target](#wall-time-target)).
- What is the plan for splitting `ingresses 1/3 alpine-plus` and
  `ingresses 1/2 debian` (both ~28:40)? Until they shrink, the smoke
  critical path stays at ~29 min regardless of parallel-e2e work.
- Is `pytest --durations=0` staying on for `main` runs going forward, or
  only used for one-off measurement runs? Log cost is modest; ongoing data
  informs LPT sharding.
- Are AGENT / AGENT_V3_NAP shards intentionally disabled on
  `chore/pytest-speedup`, or missing from that run? Affects final NAP
  grouping in [Shard Grouping Strategy](#shard-grouping-strategy).
- Is there appetite for Option A (xdist rework) as a follow-up, or does
  Option B provide sufficient headroom?
- What is the team's appetite for enforceable PR-size limits and
  feature-flag discipline, independent of the CI throughput work?

## Risks

- **Kind stability on constrained runners.** Multiple clusters share the
  runner's Docker daemon; a slow cluster start can time out. Mitigation:
  stagger cluster creation with a small delay; monitor Phase 3 flake rate.
- **Log volume.** Per-shard logs multiply artefact storage. Mitigation:
  compress before upload; retain per-run for 14 days.
- **Cluster-scoped test leaks.** A test creating a cluster-scoped resource
  under a fixed name from two shards would collide. Only an issue in Option
  A; Option B is immune. Audit as part of Phase 1.
- **Developer confusion.** Two similar smoke workflows in Phase 3. Clearly
  labelled and time-limited by design.

## References

- Duration-parsing script: `tests/scripts/longest_test_job.py`
  (supports `--mode jobs` for per-shard wall time and
  `--mode durations --run-id <ID>` for per-test call-time aggregation from
  a specific workflow run).
- Baseline measurement:
  [CI run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492)
  on `chore/pytest-speedup` — the first CI run with `pytest --durations=0`
  enabled; source of the Motivation table.
- Current smoke matrix files: `.github/data/matrix-smoke-{oss,plus,nap}.json`
- Current smoke action: `.github/actions/smoke-tests/action.yaml`
- Reusable setup-smoke workflow: `.github/workflows/setup-smoke.yml`
- Test Makefile: `tests/Makefile`
- Kind image load: `tests/Makefile` (`image-load` target uses direct
  `ctr images import` — faster and more reliable than legacy
  `kind load docker-image`)
