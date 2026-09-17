# Issue: a VirtualServer attached via `routeSelector` silently loses routes and stays `Valid`

- **Component:** `internal/k8s` (Configuration / VirtualServer status)
- **Type:** Bug (observability / status reporting)
- **Severity:** Medium - no traffic is misrouted, but a route outage is undetectable from NIC's own status and events
- **Affects:** VirtualServers that attach VirtualServerRoutes with `routeSelector`. Most visible with hostless
  VirtualServerRoutes, because those are shared across several VirtualServers, but the bug is not specific to
  hostless mode.

## Summary

When a VirtualServerRoute (VSR) is removed from the Ingress Controller's internal store, every VirtualServer (VS)
that attached it loses the corresponding routes. A VS that attached the VSR **by name** (`route: default/coffee`)
reports a warning and goes to `State: Warning`. A VS that attached the same VSR **by `routeSelector`** reports
nothing and stays `State: Valid`, while serving no locations for the affected paths.

In the worst cases the route outage has **no signal anywhere in NIC**: not on the VS, and not on the VSR either.

## Expected vs actual

**Expected:** the two attachment methods are two ways of expressing the same intent ("serve this path from this
VirtualServerRoute"), so losing the route should be equally visible in both cases.

**Actual:** only the named form is visible. A `routeSelector` route that resolves to zero VirtualServerRoutes is
indistinguishable, to the reporting code, from a selector that was never expected to match.

## Behaviour matrix

Verified against `internal/k8s/configuration.go` at `2927b8bc1`, using a shared hostless VSR
(`default/coffee`, label `app: cafe`, subroute `/coffee`) attached by two VirtualServers on different hosts
(`cafe.example.com`, `cafe2.example.com`).

### Category 1 - VSR is removed from the store (the bug)

All four transitions delete the VSR from `c.virtualServerRoutes`, so both VirtualServers lose the route.

| Transition | VS attached by name | VS attached by `routeSelector` | VSR status |
| --- | --- | --- | --- |
| VSR fails `ValidateVirtualServerRoute` (e.g. `action.pass` to an undeclared upstream) | `Warning` | **`Valid`** | `Invalid` / `Rejected` |
| VSR fails `ValidateVirtualServerRoute` (e.g. dangerous chars in `action.return.body`) | `Warning` | **`Valid`** | `Invalid` / `Rejected` |
| VSR deleted from the cluster | `Warning` | **`Valid`** | *(object gone - no status)* |
| VSR `ingressClassName` changed to another controller | `Warning` | **`Valid`** | *(not owned - no status)* |

The named form emits `VirtualServerRoute default/coffee doesn't exist or invalid`. The selector form emits nothing.

The last two rows are the worst case: the VSR object is either gone or not owned by this Ingress Controller, so NIC
writes no VSR status at all. A selector-attached VS therefore reports `Valid` with **no corroborating signal on any
other resource**.

### Category 2 - VSR stays in the store but is rejected for one VS (correct today)

| Transition | VS attached by name | VS attached by `routeSelector` |
| --- | --- | --- |
| VSR gains `spec.host` matching only one VS | `Valid` if host matches, `Warning` if not | identical |
| VSR subroute path no longer under the VS route path | `Warning` | identical |

**No bug here.** The VSR is still in the store, so the selector still matches it,
`ValidateVirtualServerRouteForVirtualServer` then runs and its failure is attributable to a specific VS. Both
attachment methods produce the same warning. This is the behaviour Category 1 should match.

### Category 3 - VSR stays in the store but no longer matches the selector

| Transition | VS attached by name | VS attached by `routeSelector` | VSR status |
| --- | --- | --- | --- |
| Label removed from the VSR | unaffected (still attached) | `Valid`, route dropped | `Warning` / `NoVirtualServerFound` |

Debatable, and **out of scope for this issue**. Removing the label is a deliberate detach, and there is at least a
signal on the VSR side (`NoVirtualServerFound`). Listed for completeness so the fix is not over-scoped.

## Root cause

Two sibling functions resolve routes, and only one of them reports a failure to resolve.

`validateVSRs` handles `route:` by name and warns when the key is not in the store
(`internal/k8s/configuration.go:1967`):

```go
vsr, exists := c.virtualServerRoutes[vsrKey]

// if route is defined
if !exists {
    warning := fmt.Sprintf("VirtualServerRoute %s doesn't exist or invalid", vsrKey)
    warnings = append(warnings, warning)
    return vsrs, warnings
}
```

The same warning exists on the regex named-route path (`internal/k8s/configuration.go:2168`).

`validateVSRSelectors` handles `routeSelector:` and has **no equivalent**
(`internal/k8s/configuration.go:1983`). It iterates the store, collects matches, and returns an empty slice with no
warning when nothing matches:

```go
for vsrKey, vsr := range c.virtualServerRoutes {
    if sel.Matches(labels.Set(vsr.Labels)) {
        err := c.virtualServerValidator.ValidateVirtualServerRouteForVirtualServer(vsr, vsHost, []string{r.Path})
        if err != nil {
            warning := fmt.Sprintf("VirtualServerRoute %s is invalid: %v", vsrKey, err)
            warnings = append(warnings, warning)
            continue
        }
        matched = append(matched, matchedVSR{key: vsrKey, vsr: vsr})
    }
}
```

Note that the per-VS validation failure *inside* the loop **is** reported - that is why Category 2 behaves
correctly. Only the "matched nothing" outcome is silent.

The VS status then follows directly from the warning list
(`internal/k8s/controller.go:2127`), so no warnings means `StateValid`:

```go
if len(vsConfig.Warnings) > 0 {
    eventType = api_v1.EventTypeWarning
    eventTitle = nl.EventReasonAddedOrUpdatedWithWarning
    eventWarningMessage = fmt.Sprintf("with warning(s): %s", formatWarningMessages(vsConfig.Warnings))
    state = conf_v1.StateWarning
}
```

The removals from the store are at `internal/k8s/configuration.go:702` (wrong ingress class),
`:706` (validation failure) and `:752` (delete).

### Is it an omission or a decision?

Evidence that it is an omission:

- There is no comment in `validateVSRSelectors` justifying the silence. The only nearby comment
  (`internal/k8s/configuration.go:1999`, "Initialize the selector entry regardless of whether routes match")
  concerns change-tracking, not reporting - and it shows the zero-match case is already an explicitly handled state.
- No "matched no VirtualServerRoutes"-style message exists anywhere in the tree.
- `git log -L 1983,2041:internal/k8s/configuration.go` shows the last functional change to this function was
  an unrelated determinism fix (`5b317a051`, "Sort selector-matched VirtualServerRoutes deterministically").
- The divergence produces an outcome nobody would choose deliberately: for the delete and ingress-class transitions
  there is no signal on *any* resource.

Evidence to the contrary, which should be checked with whoever added selector support:

- `TestValidateVSRSelectors/VSR does not exist` (`internal/k8s/configuration_test.go:6038`) asserts
  `expectedWarns: nil` for a selector that matches nothing. This is a deliberate, explicitly-written assertion of
  the current behaviour, not merely an incidental consequence. It may have been written to describe the
  reconcile-ordering case (VS before VSR) rather than to endorse silence on route loss - the test cannot distinguish
  the two, because at the function level they are the same input.

This ambiguity is the main reason to confirm intent before changing the behaviour.

## Reproduction

### Unit (fastest)

The behaviour is pinned by tests added in `internal/k8s/configuration_test.go`:

- `TestHostlessVSR_SharedVSRBecomesAbsent_WarningDependsOnAttachMethod` (`:7982`) - the boundary; 3 transitions from
  Category 1 x 2 attachment methods.
- `TestHostlessVSR_SharedVSRRejected_StatesOfBothVSs` (`:7907`) - Category 1 in detail, including the VSR's
  `Rejected` problem and cleared `referencedBy`.
- `TestHostlessVSR_SharedVSRHostAdded_PerVSRejectionIsSymmetric` (`:8060`) - Category 2, showing both attachment
  methods already agree.

```console
go test ./internal/k8s/ -run 'TestHostlessVSR_SharedVSR' -v
```

These tests currently assert **today's** behaviour (`wantWarnings: nil` for the selector rows) and are commented as
such. They must be updated as part of the fix - see [Impact of the fix](#impact-of-the-fix).

### In a cluster

`examples/custom-resources/vsr-hostless/` reproduces it end to end; Step 5 of its `README.md` is a walkthrough.

```console
# Healthy: cafe (attaches by name) and cafe2 (attaches by routeSelector) both serve /coffee
kubectl apply -f examples/custom-resources/vsr-hostless/coffee-virtual-server-route.yaml

# Break the shared VirtualServerRoute
kubectl apply -f examples/custom-resources/vsr-hostless/coffee-virtual-server-route-invalid.yaml

kubectl get virtualservers
```

```text
NAME    STATE     HOST                IP    PORTS   AGE
cafe    Warning   cafe.example.com                  5m
cafe2   Valid     cafe2.example.com                 5m
```

`cafe2` reports `Valid`, but its NGINX server block is generated with zero locations, so `/coffee` returns `404`.
Applying `cafe2-virtual-server-by-name.yaml` switches `cafe2` to attach by name and it moves to `Warning`,
confirming the attachment method is the only variable.

## Impact

- **Silent route outage.** A selector-attached VS reports `Valid` while serving no locations for the affected paths.
  If the VS has only selector routes, the whole server block is generated with zero locations: TLS still terminates
  and the host still answers, but every request gets `404`.
- **Monitoring on VS `state` misses it.** Any alerting that watches VirtualServer `status.state` will not fire.
- **Blast radius scales with sharing.** A hostless VSR can be attached by many VirtualServers, so one bad edit can
  take down a path across an entire fleet with a single `Warning` (or none, if every VS uses selectors).
- **No workaround via the VSR either** for the delete and ingress-class transitions, where NIC writes no VSR status.

Current partial workaround: alert on the VSR's own `status.state` **and** `status.referencedBy`, rather than on the
consuming VirtualServers' `state`.

## Scope: this is a pre-existing `routeSelector` bug, not a hostless-VSR bug

This needs deciding before the fix is scheduled, because fixing it changes behaviour for `routeSelector` users who
have nothing to do with hostless VirtualServerRoutes.

Verified against `origin/main` (merge base `1063934ed`):

| Fact | Evidence |
| --- | --- |
| `routeSelector` already ships | `RouteSelector` is on `origin/main` at `pkg/apis/configuration/v1/types.go:280` |
| The bug is already on `main` | `validateVSRSelectors` on `origin/main:internal/k8s/configuration.go:1899` is the same function with the same silence |
| The hostless feature only makes `spec.host` optional | `main` validates the host unconditionally (`validation/virtualserver.go:1670`); this branch guards it with `if spec.Host != ""` |
| The bug needs no hostless VSR to reproduce | Measured with two **host-based** VSRs (`spec.host: cafe.example.com`) selected by one `routeSelector`: identical behaviour |

So hostless mode does not cause this bug. It only removes the precondition that every VirtualServerRoute declare the
VirtualServer's host, which makes selectors match more broadly and therefore makes the bug easier to hit. The bug is
reachable by anyone using `routeSelector` on `main` today.

### The fix cannot be scoped to hostless VirtualServerRoutes

This is a hard constraint, not a preference. When a selector matches **zero** VirtualServerRoutes there is no
VirtualServerRoute object to inspect, so the code cannot know whether the route the user intended would have been
hostless or host-based. All that exists at that point is the selector string and the VirtualServer route path. Any
warning must therefore be emitted at the `routeSelector` level, for all users of the feature.

"Fix it only for the new feature" is therefore not an available option. The real choice is between fixing it for
`routeSelector` generally and not fixing it now.

### Options

1. **Fix it now, as part of the hostless-VSR work.** Correct, but it lands a semantic change to an
   already-shipped feature inside a feature branch: the new warning volume gets attributed to hostless VSRs, cannot be
   reverted independently, and blocks the feature behind [Open question 1](#open-questions).
2. **Fix it now, as a separate change on its own merits** (recommended). Same correctness win, decoupled release
   note, independently revertible if the transient startup warnings prove too noisy. Does not gate the hostless
   feature.
3. **Defer, and document the limitation.** Defensible only if [Open question 1](#open-questions) resolves to "zero
   match is benign". Note that hostless mode measurably increases exposure, so deferring means shipping a feature that
   makes a known blind spot easier to hit.

Option 2 is recommended: the decision about what a zero-match selector *means* is a product decision about
`routeSelector`, and it should not be made implicitly by a hostless-VSR pull request.

Note that this scoping argument applies **only to this issue**. The sibling issue
[`issue-vs-warnings-discarded-when-config-unchanged.md`](issue-vs-warnings-discarded-when-config-unchanged.md) is also
pre-existing and also not hostless-specific, but it introduces no new warning *types* -- it only stops discarding
warnings the controller already computed -- so it carries materially less risk and is the better candidate to fix
alongside the feature. The two fixes are independent; neither blocks the other.

## Proposed fix

Give `validateVSRSelectors` the warning its named counterpart already has.

**Important:** the warning must fire only when the selector matched *no VirtualServerRoutes at all* - not merely when
the validated result set is empty. A naive `if len(matched) == 0` is wrong: in Category 2 the selector *does* match a
VSR which is then rejected by `ValidateVirtualServerRouteForVirtualServer`, leaving `matched` empty, so the VS would
receive a spurious second warning on top of the accurate per-VS one. This was measured, not assumed.

Count label matches separately from validated matches (`internal/k8s/configuration.go:1983`):

```go
var matched []matchedVSR
labelMatches := 0

for vsrKey, vsr := range c.virtualServerRoutes {
    if sel.Matches(labels.Set(vsr.Labels)) {
        labelMatches++
        // ... existing per-VS validation, unchanged
    }
}

sort.Slice(matched, func(i, j int) bool { return matched[i].key < matched[j].key })

if labelMatches == 0 {
    warnings = append(warnings, fmt.Sprintf(
        "VirtualServerRoute routeSelector %s matched no VirtualServerRoutes", selectorStr))
}
```

Verified with this applied:

- All Category 1 transitions report `Warning` for selector-attached VirtualServers, matching the named form.
- Category 2 is untouched - exactly one warning, the accurate per-VS one.
- No package outside `internal/k8s` changes behaviour (`make test` otherwise green, ignoring the pre-existing
  `charts/tests` failures which require the `helm` binary).

### The startup-ordering objection is real, but consistent with existing behaviour

> Warning on zero matches will fire during reconcile ordering, when a VirtualServer is processed before the
> VirtualServerRoutes it selects.

This **does** happen - it is the cause of 3 of the 4 pre-existing test failures listed below, all of which add a VS
with a selector route before the matching VSR exists.

It is nonetheless consistent: the named path already warns in exactly that situation
(`VirtualServerRoute <key> doesn't exist or invalid` until the VSR appears), and that is accepted and documented as
expected in `examples/custom-resources/vsr-hostless/README.md`. The warning is transient and clears on the next
rebuild once the VSR exists. But it is a real change in the volume of warning events during startup and rollout, and
the team should weigh that rather than treat it as a non-issue.

### Impact of the fix

Behaviour:

- Category 1 selector rows move from `Valid` to `Warning` (the intent).
- Category 3 (label removed) would **also** start warning. That is a behaviour change beyond the reported bug and
  needs an explicit decision - see [Open questions](#open-questions).
- Transient warnings appear on selector-attached VirtualServers during reconcile ordering, as above.
- No `.tmpl` or template-struct change, so no snapshot regeneration is required.

Test expectations to update - 4 pre-existing, all asserting today's silence:

| Test | Location | Why it changes |
| --- | --- | --- |
| `TestValidateVSRSelectors/VSR does not exist` | `configuration_test.go:6038` | Directly codifies `expectedWarns: nil` for a selector matching nothing |
| `TestAddVirtualServerWithVirtualServerRoutesVSR` | `configuration_test.go:5764`, `:5788` | VS added before the selector-matched VSR exists |
| `TestAddVirtualServerWithExistingVirtualServerRoute` | `configuration_test.go:1406` | VS added before the selector-matched VSR exists |
| `TestMatchVSwithVSRusingSelector` | `configuration_test.go:5638` | VS added before the selector-matched VSR exists |

Plus the selector rows of the 3 tests listed under [Reproduction](#reproduction), whose doc comments already flag
this. Note that `TestValidateVSRSelectors/VSR exists but host mismatch` does **not** need changing with the
`labelMatches` form of the fix - it does with the naive form, which is the cheapest way to tell the two apart.

## Open questions

1. **Is zero-match a `Warning` or benign?** The fix treats a route path that resolves to nothing as a warning
   regardless of cause. Alternative: warn only when the selector previously matched and now does not, which avoids
   the Category 3 and reconcile-ordering cases but requires comparing against prior state and would be inconsistent
   with the named path. This is the central decision; the answer determines whether
   `TestValidateVSRSelectors/VSR does not exist` is updated or kept.
2. **Should the message name the unresolved path?** `selectorStr` alone (`app=cafe`) may be ambiguous on a VS with
   several selector routes; including `r.Path` would pinpoint it.
3. **Should the VSR side gain a signal too** for the delete and ingress-class transitions, or is warning on the
   consuming VirtualServers sufficient? A VS-side warning is enough to detect the outage, so this may be
   unnecessary.

## Related

- `examples/custom-resources/vsr-hostless/` - reproduction manifests and Step 5 walkthrough.
- `internal/k8s/configuration.go:1952` `validateVSRs` / `:1983` `validateVSRSelectors` - the divergent pair.
- `internal/k8s/controller.go:2121` `updateVirtualServerStatusAndEvents` - maps warnings to `state`.
- `internal/k8s/controller.go:1729` `processProblems` - maps `ConfigurationProblem` to `Invalid` / `Warning`.
