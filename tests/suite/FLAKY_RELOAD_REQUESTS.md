# Fixing flaky e2e tests: connection drops during NGINX reloads

## Symptom

A test intermittently fails with:

    requests.exceptions.ConnectionError:
      ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))

Often accompanied in the IC logs by an access-log line with status `000`, and
around a config change (Ingress/Policy/namespace-label update) that triggers an
NGINX reload. With App Protect, the WAF "soft reset" recycles workers and can
take several seconds, widening the window where in-flight connections are closed.

## Root cause

The test sends an HTTP request that lands exactly while NGINX is reloading and
recycling worker processes. NGINX closes the connection, `requests` raises an
uncaught `ConnectionError`, and the test crashes instead of retrying. This is a
timing race, not a product bug -- a dropped connection during a reload is
expected and should be retried (the same way `ensure_response_from_backend` and
`wait_for_reload` already tolerate transients).

## When this pattern applies

Apply the fix to any e2e test that BOTH:

1. Mutates config that causes a reload (apply/patch/delete of Ingress, VS/VSR,
   TransportServer, Policy, ConfigMap, or namespace label/watch changes), AND
2. Sends traffic (`requests.get/post/...`) shortly after, while a reload may be
   in progress -- especially inside a body/status polling loop.

Do NOT apply it to tests that only send traffic against already-stable config
and never reload mid-traffic (e.g. `test_app_protect_watch_namespace.py`).

## The fix

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

## Reference implementation

See `test_app_protect_watch_namespace_label.py` and the
`retry_get_until_body_contains` helper in `suite/utils/resources_utils.py`.
For status-based and single-request variants, see `retry_get_until_status_code`
and `retry_get` in the same file, and the mTLS tests (`test_ingress_mtls*.py`)
for the SSLError-ordering pattern.

## Checklist for the AI applying this

- [ ] Confirm the test reloads config AND sends traffic that could overlap it.
- [ ] Replace unguarded `requests.*` retry loops with `retry_get_until_body_contains`
      (or add `except requests.exceptions.ConnectionError: continue` to the loop).
- [ ] Guard single pre-loop requests that immediately follow a config change too.
- [ ] Preserve existing assertions and the ~60s retry budget.
- [ ] Remove the now-unused `import requests` if no other usage remains in the file.
- [ ] Do NOT add `@pytest.mark.flaky`.
- [ ] Test-only change: no product code, codegen, or snapshot updates.
