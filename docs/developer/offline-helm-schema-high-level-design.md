# High-Level Design: Offline Helm Schema Validation

> Status: Proposal
>
> Related work: [#7193](https://github.com/nginx/kubernetes-ingress/issues/7193),
> [#5493](https://github.com/nginx/kubernetes-ingress/pull/5493) (reverted by
> [#5528](https://github.com/nginx/kubernetes-ingress/pull/5528)),
> [nginx-ingress-helm-operator#706](https://github.com/nginx/nginx-ingress-helm-operator/pull/706),
> [nginx-ingress-helm-operator#709](https://github.com/nginx/nginx-ingress-helm-operator/issues/709),
> [helm/helm#10481](https://github.com/helm/helm/issues/10481),
> [helm/helm#31260](https://github.com/helm/helm/issues/31260),
> [helm/helm#32720](https://github.com/helm/helm/pull/32720)

## Overview

Every `helm install`, `helm upgrade`, `helm template`, and `helm lint` of the
NGINX Ingress Controller (NIC) chart downloads Kubernetes type definitions from
`raw.githubusercontent.com`. `charts/nginx-ingress/values.schema.json` contains
82 `$ref`s of this form:

```json
"$ref": "https://raw.githubusercontent.com/nginxinc/kubernetes-json-schema/master/v1.37.0/_definitions.json#/definitions/io.k8s.api.core.v1.ResourceRequirements"
```

Without access to GitHub, schema validation fails and the chart can't be
installed unless the user passes `--skip-schema-validation`. This affects
air-gapped clusters, environments where egress to `raw.githubusercontent.com`
is blocked by policy, and CI systems hitting GitHub rate limits.

The fix is to make `values.schema.json` self-contained. The Kubernetes
definitions are copied into a top-level `definitions` block in the same
file, and every `$ref` becomes a reference within that file:

```json
"$ref": "#/definitions/io.k8s.api.core.v1.ResourceRequirements"
```

A generator produces the `definitions` block, and CI keeps it current.

The same change removes the reason the NGINX Ingress Operator ships the chart
twice in its image, so the operator is covered here too.

## Background

### How Helm resolves `$ref`

Helm doesn't give the schema validator access to the chart's other files, and
doesn't set the schema's base location to the chart directory.

| Helm version | JSON Schema library | How the schema is registered | `file://./x.json` resolves to |
| --- | --- | --- | --- |
| up to v3.18.4 | `xeipuuv/gojsonschema` | in-memory bytes | `./x.json` relative to the **current working directory** ([helm/helm#10481](https://github.com/helm/helm/issues/10481)) |
| v3.18.5 and later, v4 | `santhosh-tekuri/jsonschema/v6` | `file:///values.schema.json` | `/x.json`, an **absolute path from the filesystem root** ([helm/helm#31260](https://github.com/helm/helm/issues/31260)) |

The second row is a URL-parsing detail: `file://./helm-charts/x.json` parses
with host `.` and path `/helm-charts/x.json`, and the library's `FileLoader`
only uses the path.

In every version, a `$ref` that starts with `#` resolves within the document
that is already loaded, so no loader, file, or network access is involved.

[helm/helm#32720](https://github.com/helm/helm/pull/32720) proposes resolving
relative `$ref`s from the chart's own files. It's still open, and even if merged
it would only help users on Helm versions released after it.

### The previous attempt (#5493, reverted by #5528)

PR #5493 added the full `_definitions.json` as a separate file at
`charts/nginx-ingress/v1.29.2/_definitions.json` and changed the `$ref`s to
`file://./charts/nginx-ingress/v1.29.2/_definitions.json#/definitions/...`. It
only worked when `helm` was run from the repository root, which CI was changed
to do. Installing from the OCI registry failed:

```text
Error: UPGRADE FAILED: values don't meet the specifications of the schema(s) in the following chart(s):
nginx-ingress:
open ./charts/nginx-ingress/v1.29.2/_definitions.json: no such file or directory
```

The definitions were in the chart, but in a file Helm never reads during
validation. This design puts them in `values.schema.json`, the one file Helm
always reads.

### Why the operator works today

The operator's `sync-chart.yml` takes the published chart, adds
`v1.37.0/_definitions.json` (1.6 MiB) to it, and rewrites the `$ref`s to
`file://./helm-charts/nginx-ingress/v1.37.0/_definitions.json`. The operator
controls both the file location and the process working directory
(`WORKDIR /opt/helm`, chart at `/opt/helm/helm-charts/nginx-ingress`), so that
path resolves.

That stopped working when the operator SDK moved to Helm v3.18.5 or later,
because the reference now resolves to `/helm-charts/...` from the filesystem
root. [#644](https://github.com/nginx/nginx-ingress-helm-operator/pull/644)
downgraded the SDK, and
[#706](https://github.com/nginx/nginx-ingress-helm-operator/pull/706) then
upgraded it again with a workaround: a second copy of the chart at the
filesystem root.

```dockerfile
COPY helm-charts  ${HOME}/helm-charts   # used by watches.yaml (chart: helm-charts/nginx-ingress)
COPY helm-charts  /helm-charts          # only exists so file://./helm-charts/... resolves
```

[#709](https://github.com/nginx/nginx-ingress-helm-operator/issues/709) tracked
removing the duplicate and was closed as stale. The bundled definitions also
caused an earlier release-Secret size failure
([#529](https://github.com/nginx/nginx-ingress-helm-operator/issues/529)).

## Goals

- `helm install`, `upgrade`, `template`, and `lint` validate the chart's values
  with no network access, from any working directory, for a chart directory, a
  packaged `.tgz`, or an OCI or repository pull.
- Validation rejects exactly what it rejects today. The Kubernetes definitions
  are the same, only their location changes.
- Kubernetes version bumps stay automated through Renovate.
- CI fails if the schema has a remote `$ref` or a `$ref` that doesn't resolve.
- CI fails if the bundled definitions are stale, missing, or edited by hand.
- The operator ships one copy of the chart and needs no schema-specific steps
  in its sync workflow.

## Non-Goals

- Keeping `values.yaml` and `values.schema.json` in sync. Seven default keys
  currently have no schema entry; that should be a separate issue.
- Generating the whole schema from `values.yaml` annotations.
- Changing which values are validated, or how strictly.
- Backporting to release or LTS branches.

## Acceptance Criteria

- With network access blocked, `helm template` of the packaged chart run from
  an unrelated directory succeeds with default values.
- In the same setup, `controller.image.pullPolicy=Bogus` and
  `controller.resources.requests=notamap` are rejected.
- `values.schema.json` has no `$ref` with an `http`, `https`, or `file` scheme.
  A check in CI enforces this, and it runs on chart-only changes.
- Running the generator on a clean checkout produces no diff, and CI enforces
  this, including on chart-only changes.
- A Renovate Kubernetes version bump produces a PR with the regenerated block,
  without manual steps.
- The operator image contains the chart once and the operator installs
  `NginxIngress` resources with egress blocked.

Must not break:

- `.github/scripts/release-version-update.sh`, which edits the image tag
  fields in `values.schema.json` with `jq`.
- The `check-jsonschema` pre-commit hook.
- Helm unit tests and snapshots. No chart template changes, so the expected
  `charts/tests/__snapshots__` diff is empty.
- The operator sync dispatch from `release-publish.yml` during the
  `k8s_version` removal.

## Design

### Schema layout

`values.schema.json` keeps its current hand-maintained content, with one
generated top-level key added at the end:

```json
{
  "$schema": "https://json-schema.org/draft/2019-09/schema",
  "type": "object",
  "properties": { "...hand-maintained, $refs point to #/definitions/..." },
  "examples": [ "..." ],
  "definitions": {
    "io.k8s.api.apps.v1.DeploymentSpec": { "...": "..." },
    "io.k8s.api.core.v1.ResourceRequirements": { "...": "..." },
    "io.k8s.apimachinery.pkg.api.resource.Quantity": { "...": "..." }
  }
}
```

- **Key name `definitions`.** The upstream definitions already reference each
  other as `#/definitions/...`, so they can be copied without changes. The
  draft 2019-09 name is `$defs`, but a `$ref` is a JSON pointer and works for
  any location; this was verified on all three Helm versions below.
- **All upstream definitions.** All 862 types are bundled, so any Kubernetes
  type can be referenced and editors can complete `#/definitions/...` names
  without regenerating the block.
- **The `definitions` block is generated.** Contributors edit everything
  else, and the generator overwrites the whole block on every run.

The bundled definitions include their `description` fields. Artifact Hub's
Values Schema tab and editors display them. Helm does not.

### Generator

Add a bash script `hack/generate-helm-schema.sh`, which needs only `curl` and
`jq`, and a Makefile target `update-helm-schema`, alongside `update-crds`.

1. Read the Kubernetes version from `K8S_CLUSTER_VERSION` in `tests/Makefile`.
   This is the version Renovate already bumps with `kindest/node`, and the
   release workflows already read it. Today the same Renovate PR bumps both, so
   the two versions are already tied together.
2. Download
   `https://raw.githubusercontent.com/nginxinc/kubernetes-json-schema/master/<version>/_definitions.json`,
   the same source the current `$ref` URLs use. The repo is a mirror of
   [`yannh/kubernetes-json-schema`](https://github.com/yannh/kubernetes-json-schema),
   and is only read when regenerating, never at install time.
3. Replace the top-level `definitions` value with the downloaded definitions.

Output requirements:

- **Preserve the hand-maintained part.** Only the `definitions` value may
  change. The generator must keep the top-level order and leave the other
  values as they are.
- **Match `jq` formatting.** `release-version-update.sh` rewrites the file
  with `jq`, so the generator must produce the same bytes: two-space
  indentation, and no HTML escaping (the descriptions contain `<` and `>`).
  Otherwise each release would reformat the file.
- **Be deterministic.** Running it twice must produce identical output.

### CI and automation

| Where | Change |
| --- | --- |
| `ci.yml`, `verify-codegen` job | New step: fail if `values.schema.json` has a `$ref` that doesn't start with `#`. It needs no Helm binary and no network. |
| `ci.yml`, `verify-codegen` job | New step: `make update-helm-schema && git diff --exit-code charts/nginx-ingress/values.schema.json`, the same pattern as the CRD and telemetry checks. |
| `ci.yml`, `verify-codegen` job | Run when files under `charts/`, `tests/Makefile` or `hack/generate-helm-schema.sh` changed, as well as on a binary-cache miss. The cache key hashes only Go code, templates and `version.txt`, so a change that touches only the chart, the generator or the Kubernetes version skips the job. Add a `charts_changed` output to the `checks` job using `dorny/paths-filter`, as `renovate-build.yml` does. |
| `renovate-build.yml` | Add a `tests/Makefile` path filter; run `make update-helm-schema` and commit. `main` only. |

Unchanged: `.pre-commit-config.yaml` (`check-jsonschema` also stops needing
network access), `release-version-update.sh` (covered by the `jq` formatting
requirement), and the `values.schema.json` rule in `renovate.json` (release
branches use it to bump their schema URLs).

### Operator changes (`nginx/nginx-ingress-helm-operator`)

**`sync-chart.yml`**

- Remove the "Checkout Kubernetes json schemas" step, the
  `mkdir`/`mv _definitions.json` lines, the `sed` that rewrites `$ref`s to
  `file://./helm-charts/...`, and `rm -rf ../schemas`.
- Add a guard that fails the sync if the pulled chart's `values.schema.json`
  contains a `$ref` that doesn't start with `#`. That stops the operator from
  shipping a schema that needs network access, and makes the required NIC
  version explicit.
- Remove the `k8s_version` input. NIC `release-publish.yml` stops sending it,
  because GitHub rejects a dispatch with an undeclared input, so both changes
  must merge before the next NIC release is published.

**`Dockerfile`**

- Remove `COPY helm-charts  /helm-charts`.
- Keep `COPY helm-charts  ${HOME}/helm-charts`, because `watches.yaml` loads
  `chart: helm-charts/nginx-ingress` relative to `WORKDIR /opt/helm`.

This addresses the purpose of #709. The image drops from two copies of the
chart to one.

**Repository contents.** `helm-charts/nginx-ingress/v1.37.0/` disappears
when the sync replaces the chart directory.

### Rollout

1. **NIC PR on `main`.** Schema, generator, Makefile target, CI, Renovate, and
   removing `k8s_version` from `release-publish.yml`.
2. **Operator PR.** The `sync-chart.yml` and `Dockerfile` changes above, and the
   chart from the latest release with the same `definitions` block, so the
   single `COPY` works before the next sync.

Both PRs must merge before the next NIC release is published. The sync that
release triggers then pulls a self-contained chart.

### LTS and release branches

No backport. The LTS workflows (`release-prep-lts.yml`,
`release-publish-lts.yml`) don't touch the schema or the operator, so the
pipeline doesn't change. The LTS chart keeps its remote schema URLs.

## Verification Done for This Proposal

A prototype applied the change to a temporary copy of the chart: 82 `$ref`s
rewritten, and 129 definitions from v1.37.0 added. It was run from `/` with
`HTTP_PROXY` and `HTTPS_PROXY` set to a closed port.

| Case | Helm v3.18.4 | Helm v3.18.6 (operator's version) | Helm v4.3.1 (CI) |
| --- | --- | --- | --- |
| Current chart, defaults (network blocked) | Fails | Fails | Fails |
| Bundled packaged chart, defaults | Passes | Passes | Passes |
| Bundled, `pullPolicy=Bogus` | Rejected | Rejected | Rejected |
| Bundled, `resources.requests=notamap` | Rejected | Rejected | Rejected |

The prototype was a throwaway script. It doesn't cover the formatting
requirements, CI wiring, or the operator.

## Alternatives Considered

| Alternative | Why not |
| --- | --- |
| Separate definitions file in the chart with a `file://` reference, as in #5493 | Helm resolves it against the working directory (v3.18.4 and earlier) or the filesystem root (later). Never the chart. |
| Wait for helm/helm#32720 | Not merged, and only helps users on Helm versions released afterwards. The chart doesn't declare a minimum Helm version. |
| Host the schema on another domain | Still needs network access, so air-gapped installs still fail. |
| Bundle only the types the chart uses | Editors can't complete a type until it is added, and the generator must be rerun whenever a `$ref` to a new type is added. |
| Replace Kubernetes types with plain `"type": "object"` | Removes validation of Kubernetes fields such as `resources`, `affinity`, and `tolerations`. |
| Recommend `--skip-schema-validation` | Removes all validation. |
| Generate from `yannh/kubernetes-json-schema` directly | Same content. Switching adds churn for no gain. |
| Convert Kubernetes' `swagger.json` ourselves | Removes the mirror dependency, but we would own the conversion. Can be done later. |
| Generate the full schema from `values.yaml` annotations | Rewrites a 3,277-line maintained schema. Could be done later without conflicting with this design. |

## Risks

- **Larger diffs on Kubernetes bumps.** Each bump regenerates part of a
  hand-edited file. The generated block is at the end of the file, and
  `renovate-build.yml` commits it automatically.
- **Upstream lag.** If `nginxinc/kubernetes-json-schema` doesn't yet publish a
  new Kubernetes version, the Renovate PR fails at generation. Today the same
  gap would only show up when users install, so this is an improvement.
- **Formatting churn.** If the generator and `jq` format differently, each
  release reformats the file. The CI drift check catches this, and the
  generator's output requirements prevent it.

## Security Impact

No user input reaches NGINX configuration, and no RBAC or credential paths
change. Installs no longer fetch schema content from a third-party repository's
`master` branch at install time, so a change upstream can no longer change how
values are validated. The definitions are reviewed and committed with the
chart.

## Affected Areas

| Repository | Path | Change |
| --- | --- | --- |
| kubernetes-ingress | `charts/nginx-ingress/values.schema.json` | `$ref` rewrite and generated `definitions` |
| kubernetes-ingress | `hack/` | New `generate-helm-schema.sh` |
| kubernetes-ingress | `Makefile` | `update-helm-schema` target |
| kubernetes-ingress | `.github/workflows/ci.yml` | Schema checks; run `verify-codegen` on chart changes |
| kubernetes-ingress | `.github/workflows/renovate-build.yml` | Regenerate on Kubernetes bumps |
| kubernetes-ingress | `.github/workflows/release-publish.yml` | Stop sending `k8s_version` |
| nginx-ingress-helm-operator | `.github/workflows/sync-chart.yml` | Remove schema steps and `k8s_version`, add guard |
| nginx-ingress-helm-operator | `Dockerfile` | Remove `/helm-charts` copy |

No controller, CRD, or NGINX template changes.
