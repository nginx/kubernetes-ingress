# External-DNS v0.21.0 Compatibility

Status: In progress
Target branch: `poc/external-dns-crd`

## TL;DR

`external-dns` v0.21.0 changed its CRD source so it only recognises the upstream `externaldns.k8s.io/v1alpha1 DNSEndpoint`. NIC currently ships and writes `externaldns.nginx.org/v1`, which breaks the integration on v0.21.0+.

We are adding a **runtime toggle** (`-external-dns-group-version` flag, or `controller.externalDNSGroupVersion` Helm value) that selects which API group NIC watches and writes. The default remains `externaldns.nginx.org/v1`, so existing users are unaffected. Users on external-dns v0.21.0+ flip the toggle and install the upstream `DNSEndpoint` CRD themselves.

## Problem

- external-dns v0.21.0 migrated the CRD source to a controller-runtime cache ([external-dns#6312](https://github.com/kubernetes-sigs/external-dns/pull/6312)). The upstream CRD examples and tutorials now use only `externaldns.k8s.io/v1alpha1 DNSEndpoint`, and the community chart ships that CRD under `config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml`.
- NIC's ExternalDNS integration writes `externaldns.nginx.org/v1` (a custom CRD, an extension model previously supported), which is no longer the extension model supported in v0.21.0, so the integration silently no-ops in a fresh v0.21.0 install.
- We cannot force users to stay on external-dns ≤ v0.20.x, and we cannot break users who are.

## Goals

- Support both external-dns versions from a single NIC binary.
- Zero-behaviour-change default on upgrade — existing charts and deployments keep working.
- Explicit, discoverable opt-in via a single flag / Helm value.
- Avoid CRD ownership conflicts with the external-dns Helm chart.

## Non-goals

- Auto-detecting the installed external-dns version. Explicit is safer than clever here.
- Migrating existing `externaldns.nginx.org/v1` `DNSEndpoint` resources on the fly.
- Shipping the upstream `externaldns.k8s.io/v1alpha1` CRD from the NIC chart (see decision below).

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

Existing users upgrade NIC without changing behaviour. Anyone on external-dns v0.21.0+ opts in with one line.

### 3. NIC does not ship the upstream CRD (rejected: ship both CRDs)

The external-dns Helm chart also ships `externaldns.k8s.io/v1alpha1 DNSEndpoint`. If NIC shipped it too, both charts would fight over ownership, upgrades, and field validation drift. Instead:

- The generated CRD lives in `config/crd/upstream/` (out of `config/crd/bases/`, which is symlinked into `charts/nginx-ingress/crds`).
- The Helm chart, `deploy/crds.yaml`, and NIC manifests continue to ship only `externaldns.nginx.org/v1`.
- Users of the upstream group install the CRD themselves (from the external-dns repo, or their existing external-dns chart).

### 4. Adapter pattern in the controller (rejected: parallel controllers)

`internal/externaldns` gains a small `dnsEndpointBackend` interface with two implementations — `nginxBackend` (`externaldns.nginx.org/v1`) and `upstreamBackend` (`externaldns.k8s.io/v1alpha1`). All reconciler code speaks the canonical internal `*extdnsapi.DNSEndpoint` type; the backend converts to/from the upstream type at the wire boundary via `toUpstream` / `fromUpstream`. Only one informer is registered per NIC process, chosen at startup from the flag.

Benefits: single reconciliation loop, single set of tests, easy to add a third group later if needed.

### 5. RBAC lists both groups (rejected: two RBAC bundles)

`deployments/rbac/rbac.yaml` grants access to both `externaldns.nginx.org` and `externaldns.k8s.io` under one rule. The Helm `ClusterRole` derives the API group from the chosen group-version string (`trimSuffix "/v1" (trimSuffix "/v1alpha1" ...)`), so only the selected group gets granted. Users of the raw manifests get both permissions and can toggle the flag without editing RBAC.

## What changed (by area)

| Area | Change |
| ---- | ------ |
| `pkg/apis/externaldnsk8s/v1alpha1/` | New API package mirroring the existing v1 types, wire-compatible with `github.com/kubernetes-sigs/external-dns/endpoint`. `+groupGoName=ExternaldnsK8s` marker prevents a duplicate `Externaldns()` method on the informer factory. |
| `pkg/client/**` | Regenerated clientset/informers/listers/applyconfig for the new group. |
| `config/crd/upstream/` | New output dir for the upstream CRD, separate from `config/crd/bases/` (which is symlinked into the Helm chart). |
| `Makefile` — `update-crds` | Runs `controller-gen` twice: NIC groups → `config/crd/bases/`, upstream group → `config/crd/upstream/`. |
| `internal/externaldns/` | Added `groupversion.go` constants + validation, `backend.go` adapter, controller/sync rewired to talk to `backend`. |
| `cmd/nginx-ingress/flags.go` | New `-external-dns-group-version` flag, validated against the two supported values. |
| `internal/k8s/controller.go` | `NewLoadBalancerControllerInput.ExternalDNSGroupVersion` plumbed through to `BuildOpts`. |
| Helm chart | New `controller.externalDNSGroupVersion` value, arg rendered only when `enableExternalDNS`, schema enum + examples, RBAC block derives the group from the value. |
| `deployments/rbac/rbac.yaml` | Rule now lists both API groups. |
| `charts/tests/` | Two new helm unit test cases (nginx and upstream variants), snapshots regenerated. |
| Integration tests | Fixtures now install the upstream CRD from `config/crd/upstream/`, start NIC with `-external-dns-group-version=externaldns.k8s.io/v1alpha1`, and target the upstream group. External-dns test manifest pinned to `registry.k8s.io/external-dns/external-dns:v0.21.0` with `--crd-source-kind=DNSEndpoint`. |
| Example (`examples/custom-resources/external-dns/`) | Pinned to external-dns v0.21.0, RBAC + args use the upstream group, README documents the toggle and points at the upstream CRD. |
| Docs | `docs/crd/externaldns.nginx.org_dnsendpoints.md` note explains the flag and the upstream-CRD requirement for v0.21.0+. |

## Upgrade paths

| Situation | Action |
| --------- | ------ |
| Existing user on external-dns ≤ v0.20.x | None. Upgrade NIC, keep default. |
| New/existing user moving to external-dns v0.21.0+ | Install the upstream `DNSEndpoint` CRD (from the external-dns repo/chart), then set `-external-dns-group-version=externaldns.k8s.io/v1alpha1` (flag) or `controller.externalDNSGroupVersion: externaldns.k8s.io/v1alpha1` (Helm). |
| Air-gapped / no external-dns | Nothing to do — flag defaults are safe. |

## Risks and open questions

- **User confusion about which CRD to install.** Mitigation: README + CRD doc call this out, Helm value description enumerates both cases, CLI flag description does the same.
- **Snapshot drift.** Helm unit test snapshots for the two new toggle cases are checked in; existing snapshots are unchanged because the new arg is gated by `enableExternalDNS: true`, which no existing testdata sets.
- **CHANGELOG.** NIC's `CHANGELOG.md` header says releases are auto-generated on GitHub — not touched in this branch. If we want a manual entry, we can add one before release.
- **Future-proofing.** If external-dns later removes `externaldns.nginx.org/v1` handling entirely (unlikely — it never handled that group), we can flip the default. The adapter pattern lets us do that in one line.

## Verification status

- ✅ `go build ./...`
- ✅ `go test` — scoped to `internal/externaldns/…`, `internal/k8s/…`, `cmd/…`
- ✅ Helm unit tests — 37 snapshots pass; 1 pre-existing `startupStatusInvalid` failure is unrelated (schema message wording changed upstream)
- ⏳ `make lint`
- ⏳ Full `make test`
- ⏳ Manual `helm template` sanity check for both toggle values

## References

- external-dns v0.21.0 release notes — <https://github.com/kubernetes-sigs/external-dns/releases/tag/v0.21.0>
- external-dns#6312 — CRD source refactor (controller-runtime cache) — <https://github.com/kubernetes-sigs/external-dns/pull/6312>
- external-dns#5243 — Defining a path to Beta for DNSEndpoint API — <https://github.com/kubernetes-sigs/external-dns/issues/5243>
- Upstream `DNSEndpoint` CRD (v0.21.0) — <https://github.com/kubernetes-sigs/external-dns/blob/v0.21.0/config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml>
- Upstream `DNSEndpoint` Go type (v0.21.0) — <https://github.com/kubernetes-sigs/external-dns/blob/v0.21.0/endpoint/endpoint.go>
- CRD source docs (v0.21.0) — <https://github.com/kubernetes-sigs/external-dns/blob/v0.21.0/docs/sources/crd.md>
- DNSEndpoint graduation proposal — <https://github.com/kubernetes-sigs/external-dns/blob/master/docs/proposal/003-dnsendpoint-graduation-to-beta.md>
