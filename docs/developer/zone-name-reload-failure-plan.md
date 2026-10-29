# Plan: edits to a live shared memory zone must not fail the NGINX reload

Status: Draft

Issue: nginx/kubernetes-ingress#11142. Scope: Medium (config generation only, one implementation PR).

## Problem

NGINX keeps a shared memory zone across a reload when its name matches, and refuses the reload if a setting it cannot change
on a live zone differs. NIC names zones only from resource names, so editing such a setting fails the reload. `nginx -t`
cannot detect it. The broken config stays on disk, so every tenant's later changes fail too.

Affected settings:
- RateLimit Policy `key` and `condition`
- Ingress annotation `nginx.org/limit-req-key`
- Cache Policy `levels`
- OIDC native `sessionTimeout` (unset to set) and ConfigMap `zone-sync` (Plus)

The same naming also lets different resources collide (`team-a`/`rate-limit` and `team`/`a-rate-limit`).

## Approach

Zone name = existing readable prefix + `_` + a short, stable hash. A changed setting gives a new name, so NGINX allocates a
fresh zone and never runs the failing check.

- The hash covers the resource identity (namespace, name, parent) and every setting NGINX cannot change on a live zone.
- Safe settings (rate, burst, `inactive`, timeout value) stay out of the hash, so counters and caches survive those edits.
  A size change also stays out of the hash and reloads cleanly, but NGINX allocates a new zone, so its counters reset.
- The raw setting text is hashed, never normalised, because NGINX compares it as text (`$x` and `${x}` are different keys).
- Identity parts are joined with a separator that cannot appear in Kubernetes names, so different boundaries give different hashes.
- The `_sync` suffix stays last where it already exists.
- The OIDC provider name is left alone: it builds the callback URI and cookie name.
- Rejected: the raw key in the name (unbounded length, characters that break the directive), and CRD immutability (cannot cover
  the annotation or the ConfigMap, and delete-and-recreate causes errors).

What goes in the hash:

| Resource | Hashed (besides identity) |
|---|---|
| RateLimit Policy | `key`, or a marker when `condition` is set |
| Ingress annotation | `limit-req-key` |
| Cache Policy | `levels` |
| OIDC native session store | zone sync on or off, and whether a timeout is set |

## Acceptance criteria

1. Editing each affected setting in place reloads successfully, and the resource stays `Valid`.
2. Editing a safe setting (rate, size) does not change the zone name.
3. Resources whose names differ only by `-` versus `_` get different zone names.
4. Zone names are identical across NIC replicas and restarts.
5. OIDC callback URI and cookie name are unchanged.

## Security impact

No new external input. The hash output is hex only, so nothing user-controlled reaches the NGINX config that did not before.
No credential, RBAC or secret path is touched.

## Layers and invariants

- Layer: config generation only. No types, CRDs, validation, templates, Helm or controller changes.
- Checked, unaffected: OIDC NJS, dynamic split weights, upstream zones.
- Invariants checked: no codegen needed. No template change, so an empty snapshot diff is expected. No new pytest marker.

## Files to change, in order

1. Policy config generation (`internal/configs/policy.go`): add the hash helper next to the existing name helper. Use it for
   the RateLimit zone name, the Cache zone name and the OIDC native session store name.
2. Ingress config generation (`internal/configs/ingress.go`): add the hash to the `limit-req` zone name.
3. Go unit tests (`policy_test.go`, `ingress_test.go`, `virtualserver_policy_test.go`, `virtualserver_ratelimit_groups_test.go`):
   update the expected zone names to the new literal names. Add table-driven cases for each setting.
4. Python tests (`test_rl_policies.py`, `test_rl_policies_vsr.py`, `test_rl_ingress.py`): match the hash with a regex in the
   existing zone-sync assertions.
5. Python tests (`test_rl_policies.py`, `test_rl_ingress.py`, `test_cache_policies_vs.py`, `test_oidc_native.py`): add in-place edit tests.
6. Python helper (`utils/policy_resources_utils.py`): add a helper that patches a Policy.

No template, struct, CRD or codegen changes.

## Tests

- Unit: for each setting, changing it renames the zone and changing a safe setting does not. Collision cases per resource kind.
  Expected names are literal strings.
- Integration: edit the resource in place and assert the new setting is in the generated config. For VirtualServer tests,
  also assert the VirtualServer stays `Valid`.
  Run first against an image built from `main` (must fail), then against the branch image (must pass).
- Negative: none applicable, since no input is added.

## Must not break

- One Policy used from several places in a VirtualServer still produces one zone.
- Editing rate, burst and similar keeps the zone, so counters and cache contents survive. A size change reloads cleanly but resets the zone's counters.
- OIDC callback URI and cookie name.

## Definition of done

- `make test` and lint pass.
- New Python tests fail on `main` and pass on the branch.
- Release note: zone names and NGINX Plus `zone` metric labels change once on upgrade. Rate-limit counters, caches and OIDC
  sessions reset.
