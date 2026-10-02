# Plan: Parallel Python E2E Tests

## Status: Draft

## Summary

**Goal:** cut the wall time each CI run spends on the Python e2e tests.

**Baseline**, from [run 29586045012](https://github.com/nginx/kubernetes-ingress/actions/runs/29586045012?pr=10492):

- The CI critical path is about 47 minutes.
- The slowest shard is `ingresses 1/3 alpine-plus` at 28:40.
- One test (`test_dos.py::test_dos_under_attack_with_learning`) took 752 s, and its upper limit is 900 s.

**Route:**

1. **Several kind clusters per runner.** This is
   [#10492](https://github.com/nginx/kubernetes-ingress/pull/10492)'s
   "Option B". It needs no changes to the tests and makes small shards
   cheap.
2. **pytest-xdist workers inside each cluster.** This is #10492's "Option A".
   Each shard gets shorter directly. It needs the tests to be isolated and
   independent of run order.

Running several clusters per runner **does not shorten wall time on its
own**. It packs shards onto fewer runners, which saves runner-minutes, but
the run still takes as long as its slowest shard. Wall time only drops
when we:

- split shards finer, which becomes cheap once one runner hosts several
  clusters, or
- run tests in parallel inside a shard, which is what xdist does.

**Where the PRs fit:**

| PR | What it does | Phases |
|---|---|---|
| [#10850](https://github.com/nginx/kubernetes-ingress/pull/10850) | Labels each test's workloads with a run ID, so pod waits and lookups only see that test's pods. A prerequisite for xdist; reduces flakes now. | 0, prerequisite for 3–5 |
| [#10492](https://github.com/nginx/kubernetes-ingress/pull/10492) | Design doc, duration tooling, and a proof of concept for several kind clusters per runner. Also proposes ways to get PRs merged faster. | 1, 2, plus [Throughput work](#throughput-work-alongside-not-on-the-critical-path) |

Every step below is tagged with where it comes from: **[10850]**,
**[10492]**, or **[new]** for work neither PR covers.

## Target End State

Each CI matrix job:

- runs on one runner hosting N kind clusters;
- runs one pytest process per cluster;
- runs `-n M` xdist workers in each process;
- runs a short serial pass at the end.

The shards come from measured durations, not from hand-numbered splits
like `policies 1/9`.

### Acceptance criteria

| # | Requirement | How we verify it |
|---|---|---|
| 1 | **No bleed.** A test only creates, waits on, reads and deletes its own resources. | (a) Fail any unscoped `list_namespaced_pod` or readiness wait in a lint or unit check. (b) Within a cluster: run the parallel suite with `-n 2` on the same commit as a serial run, and compare the failure sets. (c) Across clusters: Phase 5 audit, where failures among shards sharing a runner are close to uncorrelated. |
| 2 | **No order dependence.** Every test class passes in any class order, and when run alone. | A nightly job using `pytest -p random_order` (or `pytest-randomly`) with a recorded seed, plus `--dist loadscope`. |
| 3 | **Serial group.** Tests that need the whole cluster or controller are marked `@pytest.mark.serial` and run in their own pass after the parallel pass. | CI runs `-m "not serial" -n M`, then `-m serial`. Review checklist: any test that changes cluster-wide state must carry the marker. |
| 4 | **Wall time.** The critical path drops at each phase (targets below). | The `longest_test_job.py --mode jobs` trend in each phase's PR. |

### Wall-time targets

The rough numbers come from 10492's measurements. Phase 1 re-measures
them.

| After phase | Smoke critical path | Bound by |
|---|---|---|
| Today | ~29 min shard, ~47 min CI | `ingresses 1/3`, `ingresses 1/2` |
| 1 (split outlier shards) | ~16 min | `AP_DOS 3/3`, unless DoS learning moves to nightly |
| 2 (several clusters per runner) | ~16 min, fewer runners | longest single shard |
| 5–6 (xdist in each cluster) | longest *class* in a shard, plus the serial pass | `test_dos`, `test_app_protect_waf_policies` |

## Phases

### Phase 0 — Stability groundwork **[10850]**

**Why:** concurrent tests can't share a namespace while their pod waits
match every pod in it. Flakes also eat the gains from every later phase.

**Done in #10850:**

- `e2e.nginx.org/run-id` label on the pod templates of workloads created
  through `create_deployment`, `create_daemon_set`, `create_stateful_set`,
  `create_items_from_yaml`, `create_example_app` and
  `create_generic_from_yaml`.
- `wait_until_all_pods_are_ready` and `are_all_pods_in_ready_state` now
  *require* a label selector.
- `get_pod_list` and `get_first_pod_name` skip pods that are terminating.
- The Ingress Controller is selected with `IC_SELECTOR` (`app=nginx-ingress`)
  instead of "first pod in the namespace".
- `scale_deployment` and `create_dos_arbitrator` wait on the Deployment's own
  `matchLabels`. When scaling up, `scale_deployment` first waits until the
  requested number of pods exists, then waits for them to be Ready. Before,
  it could return before the new pods were created.
- `get_nginx_template_conf` falls back to the `IC_SELECTOR` pod, not the
  first pod in the namespace.
- Unit tests for the helpers: `tests/suite/utils/test_e2e_run_id.py`.
- Every remaining pod lookup by name substring now uses the workload's
  existing `app=` label: `app=nginx-ingress` (`IC_SELECTOR`), `app=syslog`,
  `app=syslog2`, `app=accesslog`.
  - Files: `test_filter_secrets`, `test_oidc_fclo`,
    `test_app_protect_waf_policies`, `test_app_protect_integration`,
    `test_dos`, `test_virtual_server_dos`.
  - The DoS-only `TestDos.getPodNameThatContains` copies are deleted.
  - The shared helpers `get_pod_name_that_contains` and
    `get_pods_amount_with_name` are deleted.
  - This also fixes `"syslog"` matching `syslog2-*` pods in
    `test_app_protect_waf_policies`.
  - No raw `list_namespaced_pod` without a selector is left in
    `tests/suite`.

**Follow-up [new]:**

- [ ] Update the `nic-testing` and `nic-code-review` skills with how to
      write tests that use `e2e_run_id` (requested in #10850 review).
- [ ] `test_filter_secrets.py` still hard-codes the `nginx-ingress`
      namespace, for both pod lookups and Secrets. Moving it to
      `ingress_controller_prerequisites.namespace` is part of Phase 5.

### Phase 1 — Measure and split outlier shards **[10492]**

Independent of everything else. It is the cheapest wall-time win
available.

- [ ] Land the duration tooling from #10492:
      - the `durations` input on `.github/actions/smoke-tests`
      - `tests/scripts/longest_test_job.py`
- [ ] Decide whether `--durations=0` stays on for runs on `main`. Ongoing
      data feeds duration-based shard balancing in Phase 2.
- [ ] Split by test class, using markers in `.github/data/matrix-smoke-*.json`:
      - `ingresses 1/3 alpine-plus` (28:40)
      - `ingresses 1/2 debian` (28:29)
      - `AP_WAF 3/4` (23:12)
      - `VS 1/4 debian` (22:53)
      - `policies 2/9` and `4/9`, split by policy family
- [ ] Decide whether `dos_learning` (both `test_dos.py` and
      `test_virtual_server_dos.py`) moves to a nightly job. After the
      splits, `AP_DOS 3/3` sets the lower limit.

### Phase 2 — Several kind clusters per runner **[10492]**

The proof of concept already exists in #10492:

- `tests/scripts/run-parallel-shards.sh`
- `tests/ci-files/parallel-kind-config.yaml`
- `tests/Makefile` targets `create-parallel-kind-clusters`,
  `parallel-image-load` and `run-parallel-shards`

Its "Gotchas" section must be carried forward: separate kubeconfig per
cluster, no `extraPortMappings`, `--image-pull-policy=Never`, and stripping
the quotes from markers.

- [ ] New composite action `.github/actions/smoke-tests-parallel`:
      - takes a JSON array of shards and runs one cluster plus one pytest
        process per shard;
      - produces one artefact bundle and one row in `$GITHUB_STEP_SUMMARY`
        per shard;
      - exits non-zero only after every shard has finished;
      - automatically retries known infrastructure flakes (kind boot,
        image pull, Docker EOF).
- [ ] Grouped matrix (`matrix-smoke-nap-grouped.json` first). Use
      longest-first balancing on Phase 1 durations, and never group shards
      that change cluster-wide state with each other.
- [ ] **Turn the saved runners into wall time:** split shards finer (for
      example 3 clusters per runner with shards ⅓ the size) so that more
      clusters means shorter shards, not just fewer runners.
- [ ] Comparison window: old and new jobs side by side for one release
      cycle. Compare wall time, flake rate and runner-minutes. Then cut over
      NAP, then Plus, then OSS.

**What #10850 contributes here:** nothing directly. Each cluster runs the
existing suite serially. It still matters because flakes multiply with
more shards.

### Phase 3 — Isolation and order independence **[new]**

These are the remaining causes of bleed between tests in the same
cluster.

**Names and namespaces:**

- [ ] `test_namespace` (`tests/suite/fixtures/fixtures.py`) uses
      `test-namespace-{time.time()*1000}`. Switch to a uuid suffix: two
      workers can create one in the same millisecond.
- [ ] The autouse session fixture `delete_test_namespaces` removes **every**
      `test-namespace-*` namespace. Under xdist, the first worker to finish
      deletes the others' namespaces. Scope it with a label for the
      session or worker.
- [ ] 18 test files and `v_s_route_setup` (used by 26 files) use fixed
      namespace names that come from YAML. Generate unique names and patch
      the VS/VSR `route:` references to match. Examples: `external-ns`,
      `backends-namespace`, `backend2-namespace`, `filtered-ns-*`,
      `watched-ns`, `foreign-ns`, `ns-{i}`.

**CRDs:**

- [ ] The `crds` fixture is class-scoped: every class creates and deletes the
      5 `k8s.nginx.org` CRDs, and deleting a CRD removes its resources across
      the whole cluster. Make it session-scoped, with an xdist-safe
      file-lock "install once" step.
- [ ] Do the same for the AP, DoS and DNSEndpoint CRDs in
      `crd_ingress_controller_with_ap`, `_with_waf_v5`, `_with_dos` and
      `_with_ed`.

**Order dependence:**

- [ ] Explicit chains of steps across methods. Either make each method
      self-contained or mark the class `xdist_group` and document why:
      - `test_virtual_server.py::TestVirtualServer` (steps 1–13, including an
        RBAC patch and CRD deletion in the middle of the test)
      - `test_virtual_server_configmap_keys.py::TestVirtualServerConfigMapNoTls`
      - `test_virtual_server_foreign_upstream.py::TestVirtualServerForeignUpstream`
      - `test_upgrade_resources.py` (create → delete)
- [ ] `test_virtual_server_backup_service.py` deletes and recreates
      `external-ns` so that teardown works.
- [ ] Event-count assertions (`assert_event_count_increased` and similar,
      23 files) depend on events accumulated earlier in the class. Assert on
      events filtered by object and newer than a timestamp.
- [ ] Module-level `global` state set by fixtures:
      - `log_name`, `ap_pol_name` in `test_app_protect_waf_policies*.py`
      - `test_batch_reloads.py`, `test_batch_startup_times.py`
      - `watched_namespaces` in `test_multiple_ns_perf.py`

      Replace these with fixture return values.
- [ ] Nightly job running in random class order with a recorded seed
      (acceptance criterion 2).

Note: 201 of the 222 test classes use indirect class-level
parametrization of the IC or setup fixtures, and 115 have several methods
that share class state. Classes **stay** the unit of scheduling
(`--dist loadscope`). We are not making individual methods independent
of each other, only classes.

### Phase 4 — `serial` marker **[new]**

- [ ] Register `serial` in `pyproject.toml` (`--strict-markers` is on). While
      there, register `skip_for_nginx_plus`, which is used in
      `tests/conftest.py` but not registered, and remove the duplicate
      `vs_grpc`.
- [ ] Mark these as serial:

  | Category | Files |
  |---|---|
  | Scale or restart the IC | `test_smoke`, `test_app_protect_integration`, `test_batch_startup_times`, `test_dos`, `test_rl_ingress`, `test_rl_policies`, `test_rl_policies_vsr`, `test_cache_policies_vs`, `test_cache_policies_vsr`, `test_config_rollback_startup`, `test_zone_sync` |
  | Watch-namespace / filtering | `test_watch_namespace`, `test_watch_namespace_label`, `test_watch_secret_namespace`, `test_app_protect_watch_namespace`, `test_app_protect_watch_namespace_label`, `test_filter_secrets` |
  | Install cluster-wide add-ons | `test_virtual_server_certmanager` (cert-manager CRDs, ClusterRoles, webhooks), `test_virtual_server_externaldns` |
  | Change RBAC, CRDs or IngressClass mid-test | `test_virtual_server` (`TestVirtualServer`), `test_ingress_class`, `test_policy_ingress_class` |
  | Startup / perf / upgrade | `test_batch_reloads`, `test_multiple_ns_perf`, `test_upgrade_resources`, `test_empty_host_ingress_reload` |
  | Reload-count / metrics assertions on the shared IC | review the 18 files case by case; many become safe once each worker has its own IC (Phase 5) |

- [ ] CI runs `-m "<shard> and not serial" -n M`, then `-m "<shard> and serial"`.
- [ ] Review rule (add to `nic-testing` and `nic-code-review` skills): a test
      that changes anything cluster-scoped or IC-scoped, other than its own
      worker's IC, must be `serial`.

### Phase 5 — xdist on one cluster **[new; 10492 "Option A" covers it at a high level]**

**Main blocker:** every IC fixture deploys a Deployment named `nginx-ingress`
in the fixed namespace `nginx-ingress`, behind one NodePort Service. These
fixtures are `ingress_controller`, `crd_ingress_controller`, `*_with_ap`,
`*_with_waf_v5`, `*_with_dos` and `*_with_ed`, plus the direct
`create_ingress_controller` callers. Two workers would conflict (409) or
tear down each other's IC.

Every class already deploys its own IC, so per-worker ICs map directly
onto today's model.

- [ ] Per-worker prerequisites in `ingress_controller_prerequisites` and
      `ingress_controller_endpoint`, keyed on `worker_id`, each with its own:
      - namespace `nginx-ingress-<worker>` and ServiceAccount
      - ConfigMap `nginx-config` (and `nginx-config-mgmt`)
      - default-server Secret and Plus `license-token`
      - NodePort Service and the NodePorts read back from it
      - IngressClass `nginx-<worker>`, passed as `-ingress-class`
      - ClusterRoleBinding subject (or a binding per worker)
      - GlobalConfiguration (`-global-configuration=<ns>/nginx-configuration`)
- [ ] Use the per-worker IngressClass in test resources. `tests/data/**` hard-codes
      `ingressClassName: nginx`. Patch it when creating the resource rather
      than editing the YAML.
- [ ] Replace hard-coded `"nginx-ingress"` namespaces in 13 test files with
      `ingress_controller_prerequisites.namespace`.
- [ ] `crd_ingress_controller` `type: tls-passthrough-custom-port` changes
      `port_ssl` on the session-scoped endpoint object. Make that change
      local to the class.
- [ ] The 41 files that change `nginx-config` now only touch their own
      worker's copy, so they become safe to run in parallel. No change
      needed beyond the namespace.
- [ ] `tests/conftest.py` failure-log hook: already uses `IC_SELECTOR` [10850].
      Make sure it reads the worker's namespace.
- [ ] Add `pytest-xdist` to `tests/requirements.in` / `requirements.txt`.
- [ ] `addopts` includes `-x`. Under xdist it only stops the worker that hit
      the failure. Decide between dropping it and `--maxfail`.
- [ ] `flaky` (17 files) is compatible with xdist. Confirm the rerun stays
      on the same worker.
- [ ] Resource budget: each worker runs its own IC (~200 MB) plus backends.
      Measure the number of workers that fit per cluster at each cluster
      count from Phase 2.

### Phase 6 — Rollout **[new]**

- [ ] Turn on `-n M` inside each Phase 2 cluster, NAP first. NAP shards are
      long and hold few classes, so they gain the least; OSS and Plus gain
      the most.
- [ ] Retune clusters × workers per runner and the shard groups using
      `--durations` data.
- [ ] Rebalance shards on measured durations, replacing the hand-numbered
      `1/9` splits.
- [ ] Post-launch audit, as in 10492 Phase 5: failures among shards and
      workers sharing a runner should be close to uncorrelated.

## Throughput work alongside, not on the critical path

All of these are proposed in #10492 and are independent of the phases
above. Effects are as estimated in #10492.

| Item | Source | Effect |
|---|---|---|
| Run a smaller test set on `merge_group` than on `pull_request` | [10492] | Up to ~4× less e2e time per PR in the merge queue |
| Hotfix bypass workflow for `release-x.y` (curated smoke subset, two approvals) | [10492] | Urgent fixes stop waiting behind Renovate |
| Cap Renovate `prConcurrentLimit` (e.g. 3) | [10492] | Bounded queue depth |
| Path-based skips: `workflow_only`, `helm_only`, `python_test_only`, `agent_config_only` in `.github/scripts/variables.sh` | [10492] | Skip smoke for changes that don't need it |
| Flake budget + `quarantine` marker + SLO dashboard | [10492] | Makes every other gain last. At 2 % flakes per shard, ~45 % of runs flake |
| Automatic retry for infrastructure flakes | [10492] | Stopgap until the flake budget lands; belongs in the Phase 2 action |
| Enforced PR-size limit, feature-flag discipline | [10492] | Fewer, smaller PRs through the queue |
| Post-merge cloud canary | [10492], considered | Complements pre-merge e2e, doesn't replace it |

## What's Left — Checklist

| Phase | Item | Source | Status |
|---|---|---|---|
| 0 | Run-ID labels, label-scoped pod waits and lookups, scale-up wait | [10850] | Done |
| 0 | Skills update for `e2e_run_id` | [new] | Not started |
| 1 | Duration tooling | [10492] | Draft PR |
| 1 | Split outlier shards | [10492] | Not started |
| 1 | Decide DoS learning → nightly | [10492] | Open question |
| 2 | Proof of concept for several clusters per runner | [10492] | Draft PR |
| 2 | `smoke-tests-parallel` action, grouped matrix, comparison window, cutover | [10492] | Not started |
| 3 | uuid test namespaces, scoped namespace sweep, generated fixed-name namespaces | [new] | Not started |
| 3 | Session-scoped CRDs | [new] | Not started |
| 3 | Break up step chains, event-count assertions, module globals | [new] | Not started |
| 3 | Nightly random-order job | [new] | Not started |
| 4 | `serial` marker + classification + split serial pass in CI | [new] | Not started |
| 5 | Per-worker IC prerequisites, IngressClass, hard-coded namespaces | [new] | Not started |
| 5 | pytest-xdist, `-x` decision, resource sizing | [new] | Not started |
| 6 | Rollout, retuning, rebalancing on durations, audit | [new] | Not started |
| — | Throughput items | [10492] | Not started |

## Open Questions

- **Runner size.** Do we move to bigger runners (for example 16 vCPU) to
  fit more clusters × workers? The cost-versus-speed trade-off needs
  Phase 2 data.
- **DoS learning.** Move to nightly? It is the lower limit after the
  Phase 1 splits.
- **Comparison window.** Is a full release cycle of running both setups
  worth the doubled runner cost, or is one week enough?
- **Workers per cluster.** Fixed `-n`, or `-n auto` capped by memory?
- **Docs.** Merge this plan into #10492's `parallel-e2e-tests-design.md`
  once both land, or keep the plan (what and when) separate from the
  design (why and how)?

## References

- #10850 — e2e test stability fixes (run-ID labels)
- #10492 — durations tooling, design doc
  `docs/developer/parallel-e2e-tests-design.md`, and the proof of concept
  for several kind clusters per runner
- `tests/suite/FLAKY_RELOAD_REQUESTS.md` — retrying requests that hit a
  reload
- Smoke matrix: `.github/data/matrix-smoke-{oss,plus,nap}.json`
- Smoke action: `.github/actions/smoke-tests/action.yaml`
- Fixtures: `tests/suite/fixtures/{fixtures,ic_fixtures,custom_resource_fixtures}.py`
