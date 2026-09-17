# Issue: VirtualServer warnings are discarded when the rendered configuration is unchanged

- **Component:** `internal/k8s` (Configuration change detection / VirtualServer status)
- **Type:** Bug (observability / status reporting)
- **Severity:** Medium - the data plane is correct, but a dropped VirtualServerRoute is invisible on the VirtualServer,
  and the VirtualServer's reported state depends on apply order rather than on the resources themselves
- **Affects:** Any VirtualServer whose warnings are produced by a change that leaves its rendered configuration
  identical. Reached via `routeSelector`, which is what allows several VirtualServerRoutes to attach to one
  VirtualServer route path and therefore allows one to arrive and be rejected without altering what the VirtualServer
  serves. **Pre-existing on `origin/main` and not specific to hostless VirtualServerRoutes** -- see
  [Scope](#scope-pre-existing-and-not-hostless-specific).

## Summary

`buildVirtualServerRoutes` computes warnings correctly and stores them in `VirtualServerConfiguration.Warnings`. They
are then **thrown away without ever being reported**, because change detection concludes the VirtualServer did not
change and so never calls the status/event code.

Concretely: two hostless VirtualServerRoutes claim the same subroute path. The conflict is detected, the loser is
dropped, and the warning `path /coffee has conflicting subroutes on default/coffee-v2 and default/coffee-v1` is
generated. If the loser is the VirtualServerRoute that arrived *last*, the VirtualServer's accepted route set is
unchanged, no `ResourceChange` is emitted, and the VirtualServer stays `Valid` with no warning and no event.

This is distinct from
[`issue-routeselector-silent-route-loss.md`](issue-routeselector-silent-route-loss.md), where the warning is **never
generated**. Here the warning *is* generated and is then suppressed one layer further down. The two bugs can hide the
same route outage and need separate fixes.

## Expected vs actual

**Expected:** if the Ingress Controller computes a warning for a VirtualServer, that warning reaches the
VirtualServer's `status` and events. Reporting should depend on the resources, not on the order they were applied in.

**Actual:** a warning is reported only if it happens to coincide with a change to the VirtualServer's metadata,
accepted VirtualServerRoute list, or selector map. A warning that arises *because* a resource was rejected -- and so
by construction leaves the rendered configuration untouched -- is silently dropped.

## Behaviour matrix

Verified against `2927b8bc1` by driving `Configuration` directly. Resources: VirtualServer `default/cafe`
(`cafe.example.com`, one route `/coffee` with `routeSelector: route-group=cafe`) and hostless VirtualServerRoutes
`coffee-v1` (`/coffee`) and `coffee-v2` (`/coffee`, `/coffee/decaf`), both labelled `route-group: cafe`.

In every row the data plane is identical: `coffee-v1` wins, `coffee-v2` is dropped, and `coffee-v2` reports
`Warning` / `NoVirtualServerFound`. Only the VirtualServer's reporting differs.

| Apply order | VS change emitted | VS state | Conflict named on VS |
| --- | --- | --- | --- |
| `coffee-v2`, `coffee-v1`, then VS | yes | `Warning` | yes |
| `coffee-v1`, `coffee-v2`, then VS | yes | `Warning` | yes |
| VS, `coffee-v2`, then `coffee-v1` | yes | `Warning` | yes |
| **VS, `coffee-v1`, then `coffee-v2`** | **no** | **`Valid`** | **no** |

The last row is the natural order when building resources up incrementally, and it is the one that hides the problem.
The rule is: the warning surfaces only when the arriving VirtualServerRoute **wins** (changing the accepted set), or
when the VirtualServer itself is added or its `generation` changes. When the arriving VirtualServerRoute **loses**, it
is dropped, the configuration is byte-identical, and the warning dies.

### The bug is not specific to path conflicts

Any warning from `buildVirtualServerRoutes` is suppressed under the same condition. Starting from a steady state of VS
+ accepted `coffee-v1`, adding a **new** labelled VirtualServerRoute that fails
`ValidateVirtualServerRouteForVirtualServer` is equally silent:

| Newly added labelled VSR | Warning generated (stored, unreported) | VS change emitted |
| --- | --- | --- |
| `spec.host: wrong.example.com` | `VirtualServerRoute default/tea-v1 is invalid: spec.host: Invalid value: "wrong.example.com": must be equal to 'cafe.example.com'` | no |
| subroute `/tea`, not under the VS route path `/coffee` | `VirtualServerRoute default/tea-v2 is invalid: spec.subroutes[0].path: Invalid value: "/tea": must start with '/coffee'` | no |

Both were measured. This matters for scoping, because it partially contradicts Category 2 of
[`issue-routeselector-silent-route-loss.md`](issue-routeselector-silent-route-loss.md), which states that a per-VS
validation failure "**is** reported - that is why Category 2 behaves correctly". That holds only for the transition
that doc measured, where an **already-accepted** VirtualServerRoute gains a bad host: removing it from the accepted set
*is* a change, so it is reported. For a VirtualServerRoute that arrives already-invalid and was never accepted, the
same warning is generated and then discarded. Category 2 is correct as written but does not cover this transition.

### Scope: pre-existing and not hostless-specific

Verified against `origin/main` (merge base `1063934ed`). Every component of this bug is already on `main`:

| Component | On `origin/main` |
| --- | --- |
| `IsEqual` omitting `Warnings` | `internal/k8s/configuration.go:269` - identical |
| Reporting coupled to re-rendering | `internal/k8s/controller.go:1752` - identical |
| `validateDuplicateVSRPaths` and its warning | `internal/k8s/configuration.go:1959`, called at `:2015` |
| `routeSelector` itself | `pkg/apis/configuration/v1/types.go:280` |

The conflict scenario reproduces on `main` semantics with **host-based** VirtualServerRoutes -- two VSRs both
declaring `spec.host: cafe.example.com`, both labelled, both claiming `/coffee`, selected by one `routeSelector`.
Measured: the loser is dropped and the warning is discarded exactly as in the hostless case.

The hostless feature therefore does not cause this bug; it only removes the requirement that every VirtualServerRoute
declare the VirtualServer's host, so selectors match more broadly and conflicts become much easier to create.

Unlike [`issue-routeselector-silent-route-loss.md`](issue-routeselector-silent-route-loss.md), fixing this issue
introduces **no new warning types**: it only delivers warnings the controller already computes and currently throws
away. That makes it materially lower risk than the sibling issue and a reasonable candidate to fix alongside the
hostless-VSR work, even though the bug itself predates it. The behaviour change to call out in a release note is that
VirtualServers which were silently `Valid` will begin reporting `Warning`.

### The reported state is not stable

The warning is recomputed from scratch on any full rebuild, so a VirtualServer that is silently `Valid` can become
`Warning` with no change to any resource:

- **Ingress Controller restart.** During startup `AddOrUpdate*` returns early without rebuilding
  (`internal/k8s/configuration.go:536` and siblings); `CompleteStartup` (`:944`) then performs a single
  `rebuildHosts()` against an empty `c.hosts`, so every VirtualServer is a newly added host and a change is always
  emitted. Measured: the warning is reported after restart **regardless of informer replay order**.
- **Any VirtualServer spec edit**, because `metadata.generation` changes and `compareObjectMetas`
  (`internal/k8s/configuration.go:368`) compares it.

An annotation-only touch does **not** resurface it: `generation` does not change and, unlike the Ingress path
(`compareObjectMetasWithAnnotations`, `:374`), the VirtualServer comparison ignores annotations.

So the same set of resources yields `Valid` or `Warning` depending on apply order and on whether the controller has
restarted since. That non-determinism is arguably worse than the missing warning, because it makes the condition look
intermittent.

## Root cause

Two coupled facts.

**1. `IsEqual` does not compare `Warnings`** (`internal/k8s/configuration.go:269`). It compares the VirtualServer's
metadata, the accepted VirtualServerRoute list and the selector map, and nothing else:

```go
func (vsc *VirtualServerConfiguration) IsEqual(resource Resource) bool {
	vsConfig, ok := resource.(*VirtualServerConfiguration)
	if !ok {
		return false
	}

	if !compareObjectMetas(&vsc.VirtualServer.ObjectMeta, &vsConfig.VirtualServer.ObjectMeta) {
		return false
	}

	if len(vsc.VirtualServerRoutes) != len(vsConfig.VirtualServerRoutes) {
		return false
	}
	// ... positional VSR comparison, then the selector map. Warnings are never read.
	return true
}
```

`Warnings` is a field on the same struct (`:227`) and is populated by `NewVirtualServerConfiguration` (`:237`), so the
data is present and simply not consulted.

**2. Status reporting only happens as a side effect of re-rendering** (`internal/k8s/controller.go:1792`). The only
call site of `updateVirtualServerStatusAndEvents` for this path sits behind the same change that triggers the NGINX
write:

```go
func (lbc *LoadBalancerController) processAddOrUpdate(c ResourceChange) {
	switch impl := c.Resource.(type) {
	case *VirtualServerConfiguration:
		vsEx := lbc.createVirtualServerEx(impl.VirtualServer, impl.VirtualServerRoutes, impl.VirtualServerRouteSelectors)

		warnings, addOrUpdateErr := lbc.configurator.AddOrUpdateVirtualServer(vsEx)
		lbc.updateVirtualServerStatusAndEvents(impl, warnings, addOrUpdateErr)
```

No `ResourceChange` means no `processAddOrUpdate`, which means no status update and no event. There is no path by
which a VirtualServer's status can be refreshed without also regenerating its configuration.

The conflict warning itself is generated correctly in `validateDuplicateVSRPaths`
(`internal/k8s/configuration.go:2043`), called from `buildVirtualServerRoutes` step 4 (`:2099`). That function is not
at fault; its output is just never delivered.

### Is it an omission or a decision?

`IsEqual`'s purpose is explicitly reload-avoidance, and that is deliberate and documented. The comment at
`internal/k8s/configuration.go:2022` explains why selector matches are sorted:

> ... which `VirtualServerConfiguration.IsEqual` compares positionally. [...] Without it, an unchanged VirtualServer
> compares as changed and gets needlessly re-rendered and reloaded.

So excluding `Warnings` from `IsEqual` is coherent *for its stated purpose*: warnings do not affect the generated
configuration, so they should not trigger a reload. The bug is not that `IsEqual` ignores warnings; it is that
**reporting has been made dependent on a predicate designed for reload avoidance**. Nothing suggests the reporting
consequence was considered.

Supporting evidence:

- No test asserts that configurations differing only in warnings are equal. `TestIsEqualForVirtualServers`
  (`internal/k8s/configuration_test.go:5238`) and `TestIsEqualForVirtualServersVSR` (`:5818`) pass `[]string{}` for
  both sides in every case, so warnings are untested rather than pinned.
- No comment anywhere notes that warnings are intentionally not reported when the configuration is unchanged.

## Reproduction

### Unit (fastest)

No existing test covers this. Drop this into `internal/k8s/` and run
`go test ./internal/k8s/ -run TestWarningDiscardedWhenConfigUnchanged -v`:

```go
func TestWarningDiscardedWhenConfigUnchanged(t *testing.T) {
	hostlessVSR := func(name string, paths ...string) *conf_v1.VirtualServerRoute {
		var sr []conf_v1.Route
		for _, p := range paths {
			sr = append(sr, conf_v1.Route{
				Path:   p,
				Action: &conf_v1.Action{Return: &conf_v1.ActionReturn{Body: name}},
			})
		}
		return &conf_v1.VirtualServerRoute{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default", Name: name,
				Labels: map[string]string{"route-group": "cafe"},
			},
			Spec: conf_v1.VirtualServerRouteSpec{IngressClass: "nginx", Subroutes: sr},
		}
	}
	vs := createTestVirtualServerWithRoutes("cafe", "cafe.example.com", []conf_v1.Route{{
		Path:          "/coffee",
		RouteSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"route-group": "cafe"}},
	}})

	c := createTestConfiguration()
	c.AddOrUpdateVirtualServer(vs)
	c.AddOrUpdateVirtualServerRoute(hostlessVSR("coffee-v1", "/coffee"))

	// coffee-v2 loses the /coffee conflict, so it is dropped and the rendered
	// config is unchanged.
	changes, _ := c.AddOrUpdateVirtualServerRoute(
		hostlessVSR("coffee-v2", "/coffee", "/coffee/decaf"))

	// The warning exists in the stored configuration...
	var stored []string
	for _, r := range c.GetResources() {
		if vsc, ok := r.(*VirtualServerConfiguration); ok {
			stored = vsc.Warnings
		}
	}
	if len(stored) == 0 {
		t.Fatal("expected the conflict warning to be computed")
	}

	// ...but no change is emitted, so updateVirtualServerStatusAndEvents never
	// runs and the warning is never reported.
	for _, ch := range changes {
		if _, ok := ch.Resource.(*VirtualServerConfiguration); ok {
			t.Fatalf("BUG IS FIXED: a VS change was emitted, warnings %v would be reported", stored)
		}
	}
	t.Logf("bug reproduced: warning computed but discarded: %v", stored)
}
```

Swapping the last two `AddOrUpdateVirtualServerRoute` calls makes the change appear and the test fail, which is the
apply-order dependence in isolation.

### In a cluster

`examples/custom-resources/vsr-hostless-conflict/` reproduces it end to end. Steps 2-4 of its `README.md` walk the
reported ordering; **Step 7 walks this bug**, including the `generation`-bump that makes the warning appear.

```console
kubectl create -f examples/custom-resources/vsr-hostless-conflict/coffee.yaml
kubectl create -f examples/custom-resources/vsr-hostless-conflict/tea.yaml

# VirtualServer first, then the winner, then the loser
kubectl create -f examples/custom-resources/vsr-hostless-conflict/cafe-virtual-server.yaml
kubectl create -f examples/custom-resources/vsr-hostless-conflict/coffee-v1-virtual-server-route.yaml
kubectl create -f examples/custom-resources/vsr-hostless-conflict/coffee-v2-virtual-server-route.yaml

kubectl get virtualserver cafe
kubectl get virtualserverroutes
```

```text
NAME   STATE   HOST               IP             PORTS      AGE
cafe   Valid   cafe.example.com   XX.YY.ZZ.III   [80,443]   1m

NAME        STATE     HOST   IP             PORTS      AGE
coffee-v1   Valid            XX.YY.ZZ.III   [80,443]   1m
coffee-v2   Warning                                    10s
```

`kubectl describe virtualserver cafe` shows no conflict warning and no `AddedOrUpdatedWithWarning` event. Creating the
same three resources with the VirtualServer **last** yields `cafe   Warning` and names the conflict.

## Impact

- **A dropped VirtualServerRoute is invisible on the consuming VirtualServer.** The VirtualServer reports `Valid`
  while silently not serving what the dropped VirtualServerRoute declared. In the conflict case `/coffee/decaf` is
  absorbed by the surviving `location /coffee` prefix, so requests are served by the **wrong backend** with no `404`
  and no error to alert on.
- **Apply order changes the reported state.** The same manifests yield `Valid` or `Warning` depending on the order
  applied, so GitOps replays, `kubectl apply -f <dir>` and incremental edits can disagree.
- **The state flips on restart.** A silently `Valid` VirtualServer becomes `Warning` after an unrelated controller
  restart, making the condition look intermittent and hindering diagnosis.
- **Monitoring on VirtualServer `state` misses it**, identically to
  [`issue-routeselector-silent-route-loss.md`](issue-routeselector-silent-route-loss.md). The two bugs compound: that
  one loses the warning at generation, this one loses it at delivery.
- **Blast radius scales with sharing**, since a hostless VirtualServerRoute can be attached by many VirtualServers.

Workaround, same as the sibling issue: alert on each VirtualServerRoute's `status.state` and `status.referencedBy`
rather than on the consuming VirtualServers' `state`. A dropped VirtualServerRoute reliably reports `Warning` /
`NoVirtualServerFound` with an empty `referencedBy` in every ordering measured.

## Proposed fix

Two options. They are not equivalent, and the choice is the substance of this issue.

### Option A - add `Warnings` to `IsEqual`

Smallest diff: compare `Warnings` in `VirtualServerConfiguration.IsEqual` so a warning change counts as a change.

**Cost:** `IsEqual` gates re-rendering *and* reporting, so this buys correct reporting at the price of an NGINX
regeneration and reload every time a warning set changes, for a change that by definition does not alter the generated
configuration. That directly defeats the intent documented at `internal/k8s/configuration.go:2022`. It also makes
reload behaviour sensitive to warning text.

Viable if warning churn is rare, but it trades an observability bug for a reload-churn bug.

### Option B - decouple status reporting from re-rendering (preferred)

Keep `IsEqual` as the reload predicate, and report status when the warning set changes even if no re-render is needed.
Sketch:

- In `rebuildHosts`, when a VirtualServerConfiguration `IsEqual` to its predecessor but its `Warnings` differ, record
  it in a side list (e.g. `vsWithChangedWarnings`), mirroring the existing `vsrsWithChangedRefs` mechanism at
  `internal/k8s/configuration.go:1522`, which already exists to re-report VirtualServerRoute `referencedBy` without
  re-rendering the VirtualServer.
- Expose it the same way (`GetVirtualServersWithChangedWarnings`) and, in the controller, call
  `updateVirtualServerStatusAndEvents` for those VirtualServers **without** calling
  `configurator.AddOrUpdateVirtualServer`.

This requires splitting `processAddOrUpdate` (`internal/k8s/controller.go:1792`) so the status/event half can be
invoked on its own. `vsrsWithChangedRefs` is direct precedent that this shape is acceptable in this codebase.

**Note:** `updateVirtualServerStatusAndEvents` also emits a Kubernetes **event** on every call, so whichever option is
taken, guard against re-emitting an identical event on every rebuild. Reporting should be driven by a *change* in the
warning set, not by its mere presence.

### Impact of the fix

- No `.tmpl` or template-struct change, so no snapshot regeneration.
- No existing test asserts today's silence, so unlike the sibling issue there is no list of tests to re-baseline.
  `TestIsEqualForVirtualServers` (`configuration_test.go:5238`) and `TestIsEqualForVirtualServersVSR` (`:5818`) pass
  equal warning slices on both sides and stay green under Option A; they should gain cases covering differing
  warnings.
- Under Option A, expect new reload activity wherever warning sets change; worth measuring before committing.
- **This fix and the sibling issue's fix are independent; neither blocks the other.** Measured: when a selector drops
  from one match to zero, the accepted set changes from `[coffee]` to `[]`, which *is* a change, so a zero-match
  warning added by [`issue-routeselector-silent-route-loss.md`](issue-routeselector-silent-route-loss.md) would be
  delivered without this bug being fixed. The same holds for a VirtualServer created while its selector matches
  nothing. The two bugs overlap in symptom, not in mechanism, and can be scheduled separately.

## Open questions

1. **Option A or Option B?** i.e. is an extra NGINX reload on warning-set changes acceptable in exchange for a
   one-line fix? This is the central decision.
2. **Should a VirtualServer be re-reported on restart if nothing changed?** Option B makes the restart flip *more*
   visible, not less, since warnings would then always be reported. That is the correct outcome, but it means existing
   silently-`Valid` deployments will start reporting `Warning` after upgrading. Worth a release note.
3. **Should `NoVirtualServerFound` distinguish "dropped due to conflict" from "orphaned"?** Today a dropped
   VirtualServerRoute is indistinguishable from one no VirtualServer ever selected
   (`internal/k8s/configuration.go:1573`, in `addProblemsForOrphanOrIgnoredVsrs`), and the message
   `VirtualServer is invalid or doesn't exist` is actively
   misleading when the VirtualServer exists and is serving. A distinct reason would make the VirtualServerRoute-side
   signal -- currently the only reliable one -- self-explanatory.
4. **Is a dropped VirtualServerRoute the right resolution for a path conflict at all?** `validateDuplicateVSRPaths`
   drops the whole losing VirtualServerRoute including non-conflicting subroutes, and keeps its paths reserved so the
   conflict cascades to a third VirtualServerRoute that never overlapped with the winner (both measured). That is a
   separate design question from reporting, but it is what makes the missing warning consequential.

## Related

- `examples/custom-resources/vsr-hostless-conflict/` - reproduction manifests; Step 7 of its `README.md` is the
  walkthrough for this bug.
- [`issue-routeselector-silent-route-loss.md`](issue-routeselector-silent-route-loss.md) - sibling bug; the warning is
  never generated, where here it is generated and then discarded. See the Category 2 correction above.
- `internal/k8s/configuration.go:269` `VirtualServerConfiguration.IsEqual` - the change predicate that omits
  `Warnings`.
- `internal/k8s/configuration.go:2043` `validateDuplicateVSRPaths` - generates the conflict warning correctly.
- `internal/k8s/configuration.go:1522` `GetVirtualServerRoutesWithChangedReferences` - precedent for re-reporting
  status without re-rendering.
- `internal/k8s/controller.go:1792` `processAddOrUpdate` - couples reporting to re-rendering.
- `internal/k8s/controller.go:2121` `updateVirtualServerStatusAndEvents` - maps warnings to `state`.
