# External-DNS v0.21.0 Compatibility

Status: In progress
Target branch: `poc/external-dns-crd`

## TL;DR

`external-dns` v0.21.0 changed its CRD source so it only recognises the upstream `externaldns.k8s.io/v1alpha1 DNSEndpoint`. NGINX Ingress Controller currently ships and writes `externaldns.nginx.org/v1`, which breaks the integration on v0.21.0+.

We are adding a **runtime toggle** (`-external-dns-group-version` flag, or `controller.externalDNSGroupVersion` Helm value) that selects which API group NGINX Ingress Controller watches and writes. The default remains `externaldns.nginx.org/v1`, so existing users are unaffected. Users on external-dns v0.21.0+ flip the toggle and install the upstream `DNSEndpoint` CRD themselves.

## Problem

- external-dns v0.21.0 migrated the CRD source to a controller-runtime cache ([external-dns#6312](https://github.com/kubernetes-sigs/external-dns/pull/6312)). The upstream CRD examples and tutorials now use only `externaldns.k8s.io/v1alpha1 DNSEndpoint`, and the community chart ships that CRD under `config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml`.
- NGINX Ingress Controller's ExternalDNS integration writes `externaldns.nginx.org/v1` (a custom CRD, an extension model previously supported), which is no longer the extension model supported in v0.21.0, so the integration silently no-ops in a fresh v0.21.0 install.
- We cannot force users to stay on external-dns ≤ v0.20.x, and we cannot break users who are.

## Goals

- Support both external-dns versions from a single NGINX Ingress Controller binary.
- Zero-behaviour-change default on upgrade — existing charts and deployments keep working.
- Explicit, discoverable opt-in via a single flag / Helm value.
- Avoid CRD ownership conflicts with the external-dns Helm chart.

## Non-goals

- Auto-detecting the installed external-dns version. Explicit is safer than clever here.
- Migrating existing `externaldns.nginx.org/v1` `DNSEndpoint` resources on the fly — NGINX Ingress Controller neither converts nor deletes them. This is not a gap: external-dns ≤ v0.20.x reads either API group, so operators can cut over losslessly by sequencing the two toggles (see [Upgrade paths](#upgrade-paths)). Automating it would mean NGINX Ingress Controller issuing deletes against a group it no longer manages, gated on a signal (`status.observedGeneration`) that only proves external-dns has *read* the resource, not that the record is live.
- Shipping the upstream `externaldns.k8s.io/v1alpha1` CRD from the NGINX Ingress Controller chart (see decision below).

## Decisions

### 1. Explicit toggle (rejected: auto-detect / drop legacy)

| Option | Chosen? | Why |
| ------ | ------- | --- |
| **A. Explicit CLI + Helm toggle** | ✅ | Deterministic, reviewable, no cluster probes at startup, works with air-gapped clusters. |
| B. Auto-detect installed CRDs and pick the group | ❌ | Adds a startup RBAC dependency (list CRDs cluster-wide) and hides configuration in log lines. |
| C. Drop `externaldns.nginx.org/v1` outright and require the upstream group | ❌ | Breaks every existing user on external-dns ≤ v0.20.x. |
| D. Ship two controllers / two deployments | ❌ | Doubles operational complexity for a single-bit choice. |

**Result:** new CLI flag `-external-dns-group-version` and Helm value `controller.externalDNSGroupVersion`. Allowed values: `externaldns.nginx.org/v1` (default) and `externaldns.k8s.io/v1alpha1`.

### 2. Default = `externaldns.nginx.org/v1` (rejected: default to upstream)

Existing users upgrade NGINX Ingress Controller without changing behaviour. Anyone on external-dns v0.21.0+ opts in with one line.

### 3. NGINX Ingress Controller does not ship the upstream CRD (rejected: ship both CRDs)

The external-dns Helm chart also ships `externaldns.k8s.io/v1alpha1 DNSEndpoint`. If NGINX Ingress Controller shipped it too, both charts would fight over ownership, upgrades, and field validation drift. Instead:

- The generated CRD lives in `config/crd/upstream/` (out of `config/crd/bases/`, which is symlinked into `charts/nginx-ingress/crds`).
- The Helm chart, `deploy/crds.yaml`, and NGINX Ingress Controller manifests continue to ship only `externaldns.nginx.org/v1`.
- Users of the upstream group install the CRD themselves (from the external-dns repo, or their existing external-dns chart).

### 4. Adapter pattern in the controller (rejected: parallel controllers)

`internal/externaldns` gains a small `dnsEndpointBackend` interface with two implementations — `nginxBackend` (`externaldns.nginx.org/v1`) and `upstreamBackend` (`externaldns.k8s.io/v1alpha1`). All reconciler code speaks the canonical internal `*extdnsapi.DNSEndpoint` type; the backend converts to/from the upstream type at the wire boundary via `toUpstream` / `fromUpstream`. Only one informer is registered per NGINX Ingress Controller process, chosen at startup from the flag.

Benefits: single reconciliation loop, single set of tests, easy to add a third group later if needed.

### 5. RBAC lists both groups (rejected: two RBAC bundles)

`deployments/rbac/rbac.yaml` grants access to both `externaldns.nginx.org` and `externaldns.k8s.io` under one rule. The Helm `ClusterRole` derives the API group from the chosen group-version string (`trimSuffix "/v1" (trimSuffix "/v1alpha1" ...)`), so only the selected group gets granted. Users of the raw manifests get both permissions and can toggle the flag without editing RBAC.

## What changed (by area)

| Area | Change |
| ---- | ------ |
| `pkg/apis/externaldnsk8s/v1alpha1/` | New API package mirroring the existing v1 types, wire-compatible with `github.com/kubernetes-sigs/external-dns/endpoint`. `+groupGoName=ExternaldnsK8s` marker prevents a duplicate `Externaldns()` method on the informer factory. |
| `pkg/client/**` | Regenerated clientset/informers/listers/applyconfig for the new group. |
| `config/crd/upstream/` | New output dir for the upstream CRD, separate from `config/crd/bases/` (which is symlinked into the Helm chart). |
| `Makefile` — `update-crds` | Runs `controller-gen` twice: NGINX Ingress Controller groups → `config/crd/bases/`, upstream group → `config/crd/upstream/`. |
| `internal/externaldns/` | Added `groupversion.go` constants + validation, `backend.go` adapter, controller/sync rewired to talk to `backend`. |
| `cmd/nginx-ingress/flags.go` | New `-external-dns-group-version` flag, validated against the two supported values. |
| `internal/k8s/controller.go` | `NewLoadBalancerControllerInput.ExternalDNSGroupVersion` plumbed through to `BuildOpts`. |
| Helm chart | New `controller.externalDNSGroupVersion` value, arg rendered only when `enableExternalDNS`, schema enum + examples, RBAC block derives the group from the value. |
| `deployments/rbac/rbac.yaml` | Rule now lists both API groups. |
| `charts/tests/` | Two new helm unit test cases (nginx and upstream variants), snapshots regenerated. |
| Integration tests | Fixtures now install the upstream CRD from `config/crd/upstream/`, start NGINX Ingress Controller with `-external-dns-group-version=externaldns.k8s.io/v1alpha1`, and target the upstream group. External-dns test manifest pinned to `registry.k8s.io/external-dns/external-dns:v0.21.0` with `--crd-source-kind=DNSEndpoint`. |
| Example (`examples/custom-resources/external-dns/`) | Pinned to external-dns v0.21.0, RBAC + args use the upstream group, README documents the toggle and points at the upstream CRD. |
| Docs | `docs/crd/externaldns.nginx.org_dnsendpoints.md` note explains the flag and the upstream-CRD requirement for v0.21.0+. |

## Upgrade paths

| Situation | Action |
| --------- | ------ |
| Existing user on external-dns ≤ v0.20.x | None. Upgrade NGINX Ingress Controller, keep default. |
| New install on external-dns v0.21.0+ | Install the upstream `DNSEndpoint` CRD (from the external-dns repo/chart), then set `-external-dns-group-version=externaldns.k8s.io/v1alpha1` (flag) or `controller.externalDNSGroupVersion: externaldns.k8s.io/v1alpha1` (Helm). |
| Existing user with live `externaldns.nginx.org/v1` records | Staged cut-over, below. |
| Air-gapped / no external-dns | Nothing to do — flag defaults are safe. |

### Staged cut-over for existing records

external-dns ≤ v0.20.x builds its CRD client from whatever `--crd-source-apiversion` is set to (`NewCRDClientForAPIVersionKind` parses the group-version and registers the types under it), so it reads `externaldns.nginx.org/v1` and `externaldns.k8s.io/v1alpha1` equally well. v0.21.0 is what hard-codes the upstream group. That overlap gives a lossless migration with no dual-run and no window where the desired record set is empty:

0. **Install the upstream CRD.** NGINX Ingress Controller does not ship it, so it does not arrive with an NGINX Ingress Controller upgrade.
1. Upgrade NGINX Ingress Controller, leaving the group at its `externaldns.nginx.org/v1` default.
2. Flip NGINX Ingress Controller to `externaldns.k8s.io/v1alpha1`. NGINX Ingress Controller creates the new object; the old one stays in place and is still what external-dns reads. **Gate:** the new object exists and its `.spec.endpoints` matches the old one.
3. Remove `--crd-source-apiversion` from the v0.20.x config — its default is already `externaldns.k8s.io/v1alpha1` (`pkg/apis/externaldns/types.go`), so removing it selects the upstream group. **Gate:** `status.observedGeneration == metadata.generation`, plus one clean sync interval.
4. Upgrade external-dns to v0.21.0+.
5. Delete the old `externaldns.nginx.org/v1` object.

Steps 3–5 produce no record churn: both objects share a name and namespace, so external-dns derives the same `crd/<namespace>/<name>` ownership label for each and the TXT registry record is unchanged.

Steps 2 and 3 are kept separate deliberately. Step 4 switches the group on its own (v0.21.0+ accepts `--crd-source-apiversion` but ignores it — there is no validation, so a stale value is silently dropped), but combining the group switch with the version upgrade leaves no way to attribute a records change to one or the other.

Operator-visible caveats, documented in `examples/custom-resources/external-dns/README.md`:

- **Step 0 is load-bearing under `--policy=sync`.** Without the CRD, NGINX Ingress Controller's upstream informer never syncs and its ExternalDNS control loop stalls before creating anything, while the old object keeps DNS healthy — so the mistake is invisible until step 3/4. At that point a missing CRD or missing RBAC makes external-dns fail to start (no records change), but a *present* CRD containing *no objects* is a successful empty result: `plan.calculateChanges` moves every current record with no candidate into `Changes.Delete`, and `SyncPolicy` passes it through unmodified. `--policy=upsert-only` strips the deletions; `--policy=sync` executes them.
- Letting external-dns read the upstream group before NGINX Ingress Controller has populated it is the same empty-desired-set condition.
- Between steps 2 and 3 NGINX Ingress Controller has stopped updating the old object while external-dns is still reading it, so VirtualServer changes in that window are not published.
- Aborting is possible up to step 5 because the old object is never deleted — but both settings must be reverted together, since reverting one leaves external-dns pointed at an unpopulated group.
- Skipping step 5 is not a leak: the old object carries an owner reference to the VirtualServer and is garbage-collected with it. NGINX Ingress Controller will not delete it itself; after step 2 the Helm-generated ClusterRole no longer grants `externaldns.nginx.org`.

## Risks and open questions

- **User confusion about which CRD to install.** Mitigation: README + CRD doc call this out, Helm value description enumerates both cases, CLI flag description does the same.
- **Snapshot drift.** Helm unit test snapshots for the two new toggle cases are checked in; existing snapshots are unchanged because the new arg is gated by `enableExternalDNS: true`, which no existing testdata sets.
- **CHANGELOG.** NGINX Ingress Controller's `CHANGELOG.md` header says releases are auto-generated on GitHub — not touched in this branch. If we want a manual entry, we can add one before release.
- **Future-proofing.** If external-dns later removes `externaldns.nginx.org/v1` handling entirely (unlikely — it never handled that group), we can flip the default. The adapter pattern lets us do that in one line.

## Verification status

- ✅ `go build ./...`
- ✅ `go test` — scoped to `internal/externaldns/…`, `internal/k8s/…`, `cmd/…`
- ✅ Helm unit tests — 37 snapshots pass; 1 pre-existing `startupStatusInvalid` failure is unrelated (schema message wording changed upstream)
- ✅ Full `make test` (`go test -tags=aws,helmunit -shuffle=on ./...`) after rebase onto `main`
- ✅ Staged cut-over validated end-to-end on a live GCP Cloud DNS zone with `--policy=sync`, external-dns v0.20.0 → v0.23.0: no records added, changed, or deleted at any step. Also confirmed in reverse — v0.20.0 reads `externaldns.k8s.io/v1alpha1` without complaint, which is what makes the staged sequence possible.
- ⏳ `make lint`
- ⏳ Manual `helm template` sanity check for both toggle values

## References

- external-dns v0.21.0 release notes — <https://github.com/kubernetes-sigs/external-dns/releases/tag/v0.21.0>
- external-dns#6312 — CRD source refactor (controller-runtime cache) — <https://github.com/kubernetes-sigs/external-dns/pull/6312>
- external-dns#5243 — Defining a path to Beta for DNSEndpoint API — <https://github.com/kubernetes-sigs/external-dns/issues/5243>
- Upstream `DNSEndpoint` CRD (v0.21.0) — <https://github.com/kubernetes-sigs/external-dns/blob/v0.21.0/config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml>
- Upstream `DNSEndpoint` Go type (v0.21.0) — <https://github.com/kubernetes-sigs/external-dns/blob/v0.21.0/endpoint/endpoint.go>
- CRD source docs (v0.21.0) — <https://github.com/kubernetes-sigs/external-dns/blob/v0.21.0/docs/sources/crd.md>
- CRD source (v0.20.0) — group-agnostic `NewCRDClientForAPIVersionKind`, the basis for the staged cut-over — <https://github.com/kubernetes-sigs/external-dns/blob/v0.20.0/source/crd.go>
- DNSEndpoint graduation proposal — <https://github.com/kubernetes-sigs/external-dns/blob/master/docs/proposal/003-dnsendpoint-graduation-to-beta.md>
