# Plan: Fixing Flaky Python E2E Tests

## Status: Draft

## Summary

**Goal:** make the Python e2e tests fail only when the product is broken, not when
a reload or a pod start takes a little longer than a fixed sleep.

**Approach:** data driven. Rank tests by how often they fail in CI, then fix the
worst ones. Do not sweep every `wait_before_test()` call.

**Why not sweep:** `wait_before_test()` is `time.sleep(3)` by default
(`tests/suite/utils/resources_utils.py`, `settings.py`). There are many calls,
but most of the tests that actually fail have none in the test body. The cause
is usually a fixture that applies config and a test that then asserts on one
request with no polling.

## Inventory (snapshot, Nov 2026)

| Metric | Count |
| --- | --- |
| Test files | 158 |
| `def test_*` functions (before parametrize) | 689 |
| `wait_before_test()` calls in test files | 884 (142 files) |
| ...inside a loop (delay between retries, fine) | 95 |
| ...not in a loop (fixed sleep, then act once) | 789 |
| Test functions with at least one fixed sleep | 425 |
| Fixed sleeps in fixtures or helpers inside test files | 104 |

Delays used: default 3 s (501 calls), 1 s (248), 2 s, 5 s, 10 s, `WAIT_TIME`, 120 s.

What follows each fixed sleep (first statement after it, so approximate, about +/-10%):

| Next action | Calls | Assessment |
| --- | --- | --- |
| A polling helper already (`wait_and_assert_status_code`, `ensure_response_from_backend`, `retry_get*`, `wait_until_all_pods_are_ready`) | ~73 | Redundant. Delete to save time. No flake risk |
| One `requests.get`, then an assert | ~112 | High risk. Swap for `retry_get_until_*` |
| Read generated NGINX config | ~80 | High risk. No "config contains X" poller exists yet |
| Read resource status or events | ~60 | Medium. `wait_for_resource_status` and `wait_for_event` exist |
| Rate-limit and time-window checks | ~26 | The wait is part of the test. Leave it |
| `print`, assignment, end of block | ~220 | Case by case. Many are setup sleeps |

Not every fixed sleep is a bug. Tests that assert something does *not* happen,
or that a time window passes, need a real wait.

## CI failure data

**Source:** failed `ci.yml` merge-queue runs and all nightly `regression.yml`
runs created after 2026-10-17 (after #10850, "e2e test stability fixes"):
74 failed merge-queue runs and 26 nightly runs. PR runs were left out because
real bugs in PRs make them noisy. Only 19 distinct tests failed.

| # | Test | Failing runs | Error | Likely cause |
| --- | --- | --- | --- | --- |
| 1 | `test_ac_polices_vs::test_deny_policy` | every nightly LTS job | Setup error after 600 s, IC pod never Ready | LTS image or infra, not a test bug |
| 2 | `test_rl_policies::test_rl_policy_scaled` | every nightly job, all 8 k8s versions | `rate=10r/s` not in config (config has `rate=40r/s ... sync`) | **State leaked by an earlier test.** `test_rl_ingress.py::TestRateLimitIngressScaledWithZoneSync` left zone sync on in the shared `nginx-config` ConfigMap. Fixed, see below |
| 3 | `test_custom_http_errors::test_annotation_intercepts_upstream_error` | 16 | One request to `/fail` returns the stock 502 page | Asserts once, no polling |
| 4 | `test_virtual_server_certmanager::test_responses_after_setup` | 11 (8 merge queue) | Setup error in a fixture | Needs log triage |
| 5 | `test_empty_host_ingress_reload::..._on_startup` | 11 | Startup event not found | Fixed in `972e0772c`. Watch it |
| 6 | `test_rl_policies_vsr` tiered apikey/jwt (3 tests) | 13 | `13 in range(14, 17)` | Request count just outside a narrow range. The 1 s sleeps are part of the test. Fix tolerance or timing window |
| 7 | `test_oidc_native_fclo_ingress::test_rp_initiated_logout` | 4 | 502 after login | Sleep, then no readiness check on the backend |
| 8 | `test_virtual_server_use_cluster_ip_reloads` | 3 | 4 reloads, expected 3 | Baseline taken before earlier reloads settle |
| 9 | VSR weight splits, TCP `max_connections`, `jwt_secrets`, `ac_policies_ingress` allow/deny | 2-4 each | Mixed: 404s, socket not refused | Triage per test |

The causes are hypotheses from one traceback each, not confirmed.

### Three problems that hide most of the signal

- **The suite stops at the first failure.** `pyproject.toml` has `-x` in pytest
  `addopts`. Rows 1 and 2 fail every night, so the LTS nightly runs no tests
  after the first one, and the main nightly never runs the tests after
  `test_rl_policies`. Other flaky tests are probably hiding behind them.
- **The pattern is broader than `wait_before_test()`.** The usual flaky shape is
  "a fixture applies config, then the test asserts on a single request". The
  sleep is often in the fixture, or there is no wait at all.
- **State left behind by one test breaks a later one.** The `nginx-config`
  ConfigMap lives for the whole session. A test that changes it and does not
  restore it (or only restores it on success) breaks an unrelated test further
  on, and the failure is blamed on the victim. This only shows up when the
  tests share a session, which is the nightly. PR and merge-queue runs shard by
  marker and rarely put the two tests together.

#### Row 2 root cause

The failed nightly (run 42949803732) showed the 4 IC pods Ready in 7 s, so
scaling was fine. The generated config had
`limit_req_zone ... rate=40r/s sync;`. With zone sync on, NIC does not divide
the rate across replicas, so `rate=10r/s` can never appear.
`TestRateLimitIngressScaledWithZoneSync` applied
`zone-sync/configmap-with-zonesync-minimal.yaml` and never put the default back.
`TestRateLimitIngressZoneSync` did restore it, but only when every assert passed.

Fixed with a `zone_sync_configmap` fixture in `test_rl_ingress.py` that restores
the default ConfigMap in a `finally`.

#### Leak detector

`tests/conftest.py` has a `pytest_runtest_teardown` hook. At each class
boundary, after class fixtures are torn down, it compares the live
`nginx-config` data with the default and reports a difference:

- a `::warning title=Leaked nginx-config::<class> left nginx-config as {...}`
  line in the log, which GitHub shows as an annotation;
- a `LEAKED nginx-config after <class>: {...}` line in the pytest terminal summary.

A leak is reported once, against the class that was running when it was first
seen, and again only if the data changes. It only warns, it does not fail the
run. Only the ConfigMap is checked: every IC fixture recreates the Deployment, so
IC replicas cannot leak between classes.

To use it, run the nightly and search the log for `Leaked nginx-config`. Fix each
class it names (restore in a fixture or `finally`). Once the list is empty,
consider making the hook fail the run.

Suspect list for manual review: an AST scan found 75 test functions that replace
the ConfigMap or scale a deployment, and only 7 use `try/finally`. The scan is
noisy (some scale backend deployments, some restore in a class fixture), so use
the detector output first. Files with a ConfigMap change and no restore visible
in the test function: `test_annotations.py`, `test_jwt_policies_jwksuri*.py`,
`test_oidc_fclo.py`, `test_otel.py`, `test_ts_tls_passthrough.py`,
`test_v_s_route_upstream_options.py`, `test_virtual_server_configmap_keys.py`,
`test_virtual_server_upstream_options.py`.

### Reproducing the ranking

```bash
# failed merge-queue run ids since the cut-off, plus nightly run ids
gh run list -R nginx/kubernetes-ingress -w ci.yml -L 1000 -s failure \
  --json databaseId,event,createdAt \
  --jq '.[]|select(.event=="merge_group" and .createdAt>"2026-10-17")|.databaseId'
gh run list -R nginx/kubernetes-ingress -w regression.yml -L 30 --json databaseId,createdAt \
  --jq '.[]|select(.createdAt>"2026-10-17")|.databaseId'

# per run: distinct failing tests (parameters stripped)
gh run view -R nginx/kubernetes-ingress <id> --log-failed \
  | rg -o "(FAILED|ERROR) suite/[^\[ ]+" | sort -u
```

Run the per-run step with `xargs -P8`, then `sort | uniq -c | sort -rn`.
`--log-failed` takes about 12 s per run. Re-run the ranking after Phase A,
because the nightly will then reach tests it has not run in weeks.

## Plan

### Phase A: get the nightly signal back (about 1-2 days)

1. Find out why the LTS image never becomes Ready (row 1). Probably image or CI
   config, not test code. May belong to another owner.
   - Known: the LTS job was added 2026-05-22 and has never passed. It fails the
     same way on LTS tags r6 to r10. The dev-image Plus jobs pass the same test.
   - Cause found in the workflow: the job checked out main (tests, manifests,
     CRDs) but ran the LTS image. Fixed: `regression.yml` now checks out the LTS
     tag (`matrix.images.lts_tag`) for LTS entries. The first test's flags,
     `create_ingress_controller` and the RBAC were already compatible, so
     whether this alone makes the pod Ready is unconfirmed.
   - Side effects of checking out the tag: the local `smoke-tests` action, the
     test-runner image hash and `tests/` all come from the tag. The test-runner
     image for the tag's hash must exist in GHCR (it does for `2026-lts-r10`).
     A new LTS tag whose `tests/requirements.txt` or `tests/Dockerfile` changed
     needs its LTS branch CI to have built the image first.
   - The test-suite changes in this plan (leak detector, pod diagnostics,
     `pytest-args`, test fixes) are on main only. To get them in the LTS job,
     cherry-pick them to `release-2026-lts` and cut a new LTS tag.
   - Diagnostics: a failing fixture setup prints the state, logs (including the
     previous container) and events of the IC pods
     (`print_ic_pod_diagnostics` in `tests/conftest.py`, needs
     `--show-ic-logs=yes`, which CI sets).
   - Next: run the nightly. If the LTS job still fails in setup, cherry-pick the
     diagnostics to the LTS branch to see why.

### Phase B: fix the top flaky tests (about 3-4 days)

- Rows 3, 7, 8: replace single-shot checks with `retry_get_*`,
  `ensure_response_from_backend` or `wait_for_reload`.
- Row 4: read the fixture logs, then poll the right condition.
- Row 6: widen the tolerance, or count requests over a measured window.
- Row 9: triage each test, then apply the polling fix.
- Add one generic `wait_until(fn, predicate, timeout)` helper to
  `resources_utils.py` for config reads, if two or more fixes need it.
- One small PR per area. Validate each with a `workflow_dispatch` regression run
  on the branch.

### Phase C: cleanup (optional, about half a day)

Remove the ~73 sleeps that come right before a polling helper. Saves CI time,
does not fix flakes.

### Then

Re-run the ranking. Apply the same fixes to the next tests on the list, and stop
when the failure rate is low enough. The remaining ~700 fixed sleeps are only
worth touching when a test shows up in the ranking.

## Effort

Writing the edits is about 1-2 engineer-weeks for a full sweep, but the
data-driven route is about 3-4 days of edits plus CI validation. Validation costs
more than the edits: every change needs a real cluster run, and the Plus, App
Protect and DoS suites need licensed images.

## Open questions

1. Is the LTS nightly in scope (row 1)?
2. One PR per test or area, or one batched PR like #10850?
3. Should the ranking script be committed (for example under `tests/scripts/`)?

## Not checked

PR-run failures, and reruns that passed on a second attempt, so real flake rates
are probably higher than the counts above.

## Reference: fixing connection drops during reloads

The sections below were `tests/suite/FLAKY_RELOAD_REQUESTS.md`. They describe the
fix for one specific flake pattern and are the model for the `retry_get_*` fixes
in Phase B.

### Symptom

A test intermittently fails with:

    requests.exceptions.ConnectionError:
      ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))

Often accompanied in the IC logs by an access-log line with status `000`, and
around a config change (Ingress/Policy/namespace-label update) that triggers an
NGINX reload. With App Protect, the WAF "soft reset" recycles workers and can
take several seconds, widening the window where in-flight connections are closed.

### Root cause

The test sends an HTTP request that lands exactly while NGINX is reloading and
recycling worker processes. NGINX closes the connection, `requests` raises an
uncaught `ConnectionError`, and the test crashes instead of retrying. This is a
timing race, not a product bug -- a dropped connection during a reload is
expected and should be retried (the same way `ensure_response_from_backend` and
`wait_for_reload` already tolerate transients).

### When this pattern applies

Apply the fix to any e2e test that BOTH:

1. Mutates config that causes a reload (apply/patch/delete of Ingress, VS/VSR,
   TransportServer, Policy, ConfigMap, or namespace label/watch changes), AND
2. Sends traffic (`requests.get/post/...`) shortly after, while a reload may be
   in progress -- especially inside a body/status polling loop.

Do NOT apply it to tests that only send traffic against already-stable config
and never reload mid-traffic (e.g. `test_app_protect_watch_namespace.py`).

### The fix

Do not wrap the whole test in `@pytest.mark.flaky` -- that reruns the entire
expensive test and can mask real regressions. Instead, make the specific request
resilient.

Use one of the shared helpers in `suite/utils/resources_utils.py`, all of which
catch `requests.exceptions.ConnectionError` while retrying:

- `retry_get_until_body_contains(req_url, host, expected_body)` -- poll until a
  substring appears in the body.
- `retry_get_until_status_code(req_url, host, expected_status, session=..., **kwargs)`
  -- poll until a status code matches; supports an SNI/client-cert `session` and
  extra `requests.get` kwargs (`cert`, `verify`, `allow_redirects`, ...).
- `retry_get(req_url, host, **kwargs)` -- guard a single request whose assertion
  cannot be expressed as "body contains X" or "status == Y" (e.g. asserting a
  substring is absent, or an arbitrary status); retries only on `ConnectionError`.

The shared helpers `wait_and_assert_status_code` (`suite/utils/custom_assertions.py`)
and `send_malicious_request_with_retry` (`suite/utils/ap_resources_utils.py`) also
tolerate `ConnectionError`, so their many callers are covered automatically.

    ```python
    from suite.utils.resources_utils import retry_get_until_body_contains

    resp = retry_get_until_body_contains(req_url, ingress_host, expected_body)
    assert expected_body in resp.text
    assert resp.status_code == 200
    ```

Replace hand-rolled loops like:

    ```python
    resp = requests.get(url, headers={"host": host}, verify=False)
    retry = 0
    while expected not in resp.text and retry <= 60:
        resp = requests.get(url, headers={"host": host}, verify=False)  # can raise ConnectionError
        retry += 1
        wait_before_test(1)
    ```

with a single `retry_get_until_body_contains(...)` call.

If a test needs a method/headers/body the helper doesn't cover, replicate its
core guarantee: catch `requests.exceptions.ConnectionError` inside the retry loop
and continue, rather than letting it propagate.

Note: `requests.exceptions.SSLError` is a *subclass* of `ConnectionError`. When a
test relies on catching `SSLError` (e.g. mTLS client-cert tests), keep the
`except SSLError` handler **before** any `except ConnectionError` handler so the
SSL case is not swallowed.

### Reference implementation

See `test_app_protect_watch_namespace_label.py` and the
`retry_get_until_body_contains` helper in `suite/utils/resources_utils.py`.
For status-based and single-request variants, see `retry_get_until_status_code`
and `retry_get` in the same file, and the mTLS tests (`test_ingress_mtls*.py`)
for the SSLError-ordering pattern.

### Checklist for the AI applying this

- [ ] Confirm the test reloads config AND sends traffic that could overlap it.
- [ ] Replace unguarded `requests.*` retry loops with `retry_get_until_body_contains`
      (or add `except requests.exceptions.ConnectionError: continue` to the loop).
- [ ] Guard single pre-loop requests that immediately follow a config change too.
- [ ] Preserve existing assertions and the ~60s retry budget.
- [ ] Remove the now-unused `import requests` if no other usage remains in the file.
- [ ] Do NOT add `@pytest.mark.flaky`.
- [ ] Test-only change: no product code, codegen, or snapshot updates.
