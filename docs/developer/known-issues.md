# Known Issues

Bugs and quirks that are understood but intentionally not fixed yet, tracked here until
they're promoted to a GitHub issue and fixed properly.

## Weight-update VirtualServers silently cancel batch mode

**Where:** `internal/configs/configurator.go`, `Configurator.AddOrUpdateVirtualServer`

```go
if len(weightUpdates) > 0 {
    cnf.EnableReloads()
}
```

**What happens:** `sync()` (`internal/k8s/controller.go`) enters batch mode by calling
`Configurator.DisableReloads()` when the work queue has more than one item, deferring
reloads and NGINX Plus API writes until the batch drains. `AddOrUpdateVirtualServer` is
one of the sync paths that can run mid-batch (e.g. a VirtualServer with traffic-splitting
weights is updated while other events are queued). If that VirtualServer has pending
`weightUpdates`, this line calls `EnableReloads()` unconditionally — re-enabling reloads
and NGINX Plus API writes for the rest of the process, not just for this call.

The controller's `batchSyncEnabled` bookkeeping in `sync()` is untouched, so the
controller still believes it's batching and will later call `EnableReloads()` again and
run its own batch-end reload logic. The visible effect is just that batching is
defeated early for whatever mid-batch work follows this call — reloads and Plus API
writes start happening immediately instead of being deferred to the batch end. It
doesn't corrupt state, but it undermines the point of batching (coalescing reloads
under churn) for the remainder of that batch.

**Why it hasn't been fixed:** Low impact (reload storms are cosmetic/perf, not
correctness) and it's adjacent to, but distinct from, the batch-reload staleness work
(nginx/kubernetes-ingress#7778, #7779, #10397). Flagged here instead of folded into
that fix to keep that change's diff focused.

**Suggested fix:** Don't call the package-wide `EnableReloads()`/`DisableReloads()`
toggle from inside a single resource's update path. Either gate the weight-update reload
on whether the caller is already in batch mode (skip `EnableReloads()` if
`!cnf.isReloadsEnabled` was already true going in, perform a one-off reload instead of
flipping the global flag), or have the controller re-assert `DisableReloads()` after
`AddOrUpdateVirtualServer` returns when still inside a batch.

**Action:** Open a GitHub issue before fixing; this note is not itself a fix.
