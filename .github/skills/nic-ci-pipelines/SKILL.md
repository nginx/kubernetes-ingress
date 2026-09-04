---
name: nic-ci-pipelines
description: 'CI/CD pipeline structure, GitHub Actions workflows, reusable workflow patterns, and matrix builds for NIC. Use when working on CI workflows, debugging build failures, adding new workflow steps, modifying build matrices, or understanding the release pipeline.'
---

# NIC CI/CD Pipelines

## Repository Split -- read this first

Workflow files are shared between two repositories, and **every job is gated on `github.repository`**. The same file behaves differently depending on which repo runs it.

| Repository | Owns | Gate string |
| --- | --- | --- |
| `nginx/kubernetes-ingress-internal` | **Release image and binary builds.** Builds all OSS/Plus/NAP variants, stages them plus the Helm chart in the internal registry, signs binaries, uploads tarballs to Azure | `github.repository == 'nginx/kubernetes-ingress-internal'` |
| `nginx/kubernetes-ingress` (public) | **Publishing only.** Pulls prepped images from the internal staging registry and pushes them to every public registry, publishes the Helm chart, certifies UBI images, opens the operator PR, tags and publishes the GitHub release | `github.repository == 'nginx/kubernetes-ingress'` |

Consequences:

- `release-prep.yml` / `release-prep-lts.yml` are **internal-repo only**. They are the only workflows that build release images. Dispatching them on the public repo is a no-op -- every job skips.
- `release-publish.yml` / `release-publish-lts.yml` are **public-repo only**. They never run `docker build`; `oss-release.yml` and `plus-release.yml` copy image manifests with `skopeo` from `source_registry` (default `docker-mgmt-test.nginx.com`) to the public targets.
- The public repo still builds images **for PR/CI testing** (`ci.yml` -> `build-artifacts.yml`, pushing to the GCR dev registry) and for `edge`/`stable` promotion on merge (`image-promotion.yml`). Those are test artifacts, not release artifacts.
- A publish failure is retryable on its own -- nothing needs rebuilding because the images already exist in the staging registry.

```text
   internal repo                        public repo
   -------------                        -----------
   release-prep.yml                     release-publish.yml
     build-artifacts.yml                  oss-release.yml   (skopeo copy)
     push-prep-images  --> docker-mgmt-test.nginx.com --> GCR / Docker Hub / ECR Public / Quay / GHCR / NGINX Registry
     stage-helm-chart  --> oci://docker-mgmt-test...  --> publish-helm.yml (Helm repo + GHCR)
     binaries (SBOM, Cosign)                            certify-openshift-images (Pyxis)
     azure-upload      --> Azure blob                   operator (dispatch nginx-ingress-helm-operator/sync-chart.yml)
                                                        release-gate -> tag -> release-assets -> github-release
```

## Workflow Architecture

The CI system uses GitHub Actions with extensive **reusable workflow** composition.

```text
ci.yml (main CI orchestrator)                          [public repo]
  -> checks (format, lint, codegen, CRDs, chart version)
  -> verify-codegen (go mod tidy, make update-crds, make update-codegen, make telemetry-schema -- all must produce no diff)
  -> unit-tests, staticcheck, govulncheck
  -> build-artifacts.yml (reusable)   <- CI/test images only, pushed to GCR dev registry
       -> build-oss.yml (per-variant, matrix)
       -> build-plus.yml (per-variant, matrix)  <- also used for NAP variants
  -> package-tests, helm-tests
  -> setup-smoke.yml (reusable)
  -> smoke / e2e tests

image-promotion.yml (post-merge)                       [public repo]
  -> tags images edge/stable
  -> Trivy + DockerScout security scans
  -> publishes edge Helm charts to GHCR
  -> updates GitHub Release draft notes

release-prep.yml (dispatchable Stage 1: Creation)      [INTERNAL repo only]
  -> build-artifacts.yml (reusable)   <- the only release image build
  -> push-prep-images -> stages images in docker-mgmt-test.nginx.com
  -> stage-helm-chart -> stages Helm chart in oci://docker-mgmt-test.nginx.com/nginx-ic/helm
  -> binaries -> generates SBOM (Syft), signs (Cosign), creates tarballs
  -> azure-upload -> uploads signed tarballs to Azure blob storage

release-publish.yml (dispatchable Stage 2: Publish)    [PUBLIC repo only -- no builds]
  -> oss-release.yml (skopeo copy from source_registry: docker-mgmt-test.nginx.com)
  -> plus-release.yml (skopeo copy from source_registry: docker-mgmt-test.nginx.com)
  -> publish-helm.yml (publishes Helm chart to Helm repo & GHCR)
  -> certify-openshift-images (certifies UBI images on OpenShift / Pyxis)
  -> operator -> dispatches nginx-ingress-helm-operator/sync-chart.yml to raise the operator PR
  -> release-gate -> verifies all artifact publications succeed
  -> tag -> creates and pushes the vX.Y.Z git tag
  -> release-assets -> downloads tarballs from Azure and uploads to GitHub release draft
  -> github-release -> closes milestone and publishes the GitHub release draft
```

### Two-Stage Release Architecture

Release pipelines are split into two independently dispatchable stages that run in **different repositories**:

1. **Stage 1 (Prep / Creation)** (`release-prep.yml` / `release-prep-lts.yml`) -- runs in `nginx/kubernetes-ingress-internal`:
   - Builds binaries and container images (the only place release images are built)
   - Stages container images and Helm charts in the internal test registry (`docker-mgmt-test.nginx.com`)
   - Generates Syft SBOMs, signs artifacts with Cosign, and uploads release tarballs to Azure blob storage
   - Does **not** create git tags, publish public images, or publish the GitHub release
2. **Stage 2 (Publish)** (`release-publish.yml` / `release-publish-lts.yml`) -- runs in `nginx/kubernetes-ingress` (public):
   - Copies prepped images from `docker-mgmt-test.nginx.com` to public registries (GCR, Docker Hub, ECR Public, Quay, GHCR, NGINX Registry) plus the marketplace registries (GCR Marketplace, ECR Marketplace, Azure Marketplace) for Plus
   - Publishes public Helm charts and certifies UBI images on OpenShift
   - Dispatches `sync-chart.yml` in `nginx/nginx-ingress-helm-operator` to raise the operator PR (requires a non-empty `operator_version` input, otherwise the job skips)
   - Verifies all prerequisites via `release-gate`
   - Creates and pushes the release git tag (`vX.Y.Z` or `<lts_version>`)
   - Downloads signed binaries from Azure blob storage and attaches them to the GitHub release draft
   - Closes the release milestone and publishes the GitHub release

Because the stages are decoupled and live in separate repos, a transient failure in publishing or external registry sync can be retried directly via `release-publish.yml` without rebuilding any images or binaries.

---

## Key Workflows

### Core CI & Testing

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `ci.yml` | PR to `main`/`release-*`, merge_group, workflow_dispatch | Main CI orchestrator: checks + build + test. Images built here are **test** images pushed to the GCR dev registry |
| `lint-format.yml` | PR to `main`/`release-*`, merge_group | Format & lint checks (gofumpt, goimports, golangci-lint, actionlint, markdownlint, yamllint, workflow gating validation) |
| `regression.yml` | Daily cron (03:00 UTC), manual dispatch | Multi-K8s-version regression matrix tests |
| `single-image-regression.yml` | Manual dispatch | Runs Python e2e tests on a single image variant and K8s version |
| `build-base-images.yml` | Weekday cron (04:30 UTC), manual, workflow_call | Rebuilds all base images (alpine, debian, ubi) |
| `build-ubi-dependency.yml` | Push to `main` touching `build/dependencies/Dockerfile.ubi10`, manual | Builds the UBI dependency image published to `ghcr.io/nginx/dependencies/nginx-ubi` |
| `image-promotion.yml` | Push to `main`/`release-*`, workflow_call | Post-merge image tagging (`edge`/`stable`), security scanning, GHCR edge chart publish |

### Release Workflows

| Workflow | Repo | Trigger | Purpose |
| --- | --- | --- | --- |
| `release-prep.yml` | internal | Manual dispatch | Stage 1: build artifacts, stage images and Helm chart in test registry (`docker-mgmt-test.nginx.com`), sign binaries, upload tarballs to Azure blob storage |
| `release-publish.yml` | public | Manual dispatch | Stage 2: copy staged images to public registries, publish Helm chart, certify UBI images, dispatch operator sync PR, create git tag, upload release assets, close milestone, publish GitHub release |
| `release-prep-lts.yml` | internal | Manual dispatch | LTS Stage 1: build LTS Plus images & binaries, stage in test registry, sign binaries, upload tarballs to Azure blob storage |
| `release-publish-lts.yml` | public | Manual dispatch | LTS Stage 2: copy staged LTS Plus images to public registries, publish LTS Helm chart (`nginx-ingress-lts`), create git tag, attach release assets, close milestone, publish GitHub release |
| `oss-release.yml` | public | Manual dispatch, workflow_call | Copies OSS images from staging registry to public registries via skopeo (called by `release-publish.yml`) |
| `plus-release.yml` | public | Manual dispatch, workflow_call | Copies Plus/NAP images from staging registry to GCR, NGINX Registry and the GCR/ECR/Azure marketplaces via skopeo (called by `release-publish.yml`) |
| `plus-release-lts.yml` | public | Manual dispatch, workflow_call | Copies LTS Plus images from staging registry to GCR and NGINX Registry (called by `release-publish-lts.yml` and `update-docker-images.yml`) |
| `publish-helm.yml` | both | Manual dispatch, workflow_call | Packages and publishes Helm charts to OCI registries (GHCR, docker-mgmt-test) or the public Helm repo |
| `create-release-branch.yml` | public | Manual dispatch | Creates a new `release-X.Y` branch and bumps versions |
| `release-pr.yml` | public | Manual dispatch | Automates creation of release PRs for version updates and changelogs |
| `version-bump.yml` | public | Manual dispatch | Bumps `IC_VERSION` and `HELM_CHART_VERSION` across the repository |

### Reusable Build Workflows (called via `workflow_call`)

| Workflow | Purpose |
| --- | ------------------------------------------------------------------------------------------------------------------ |
| `build-artifacts.yml` | Orchestrates GoReleaser binary builds + multi-variant image build matrix |
| `build-oss.yml` | Builds a single OSS image variant |
| `build-plus.yml` | Builds a single Plus/NAP image variant (maps `pkg-src-repo`, `pkg-src-waf`, `pkg-src-dos` to docker build args) |
| `build-single-image.yml` | Builds a single image variant on demand (manual dispatch) |
| `build-test-image.yml` | Builds Python e2e test image (`kic-test-image`) |
| `setup-smoke.yml` | Sets up Kind cluster and runs smoke tests |
| `patch-image.yml` | OS-level security patches on existing images |
| `retag-images.yml` | Re-tags images in GCR Dev Registry |

### Security, Compliance & Automation

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `codeql-analysis.yml` | Push, PR, merge_group | GitHub CodeQL security analysis |
| `scorecards.yml` | Weekly cron (Sun 20:43 UTC), push to `main` | OpenSSF Scorecards security scanning |
| `dependency-review.yml` | PR to `main`/`release-*`, merge_group | GitHub Dependency Review for PRs |
| `certify-ubi-image.yml` | Manual dispatch, called | Red Hat UBI certification for OpenShift (Pyxis) |
| `f5-cla.yml` | PR target, issue comment | CLA Assistant check for PRs |
| `external-pr.yml` | Issue comment | Triggers CI for external contributor PRs after review |
| `cherry-pick.yml` | Issue comment (`/cherry-pick`) | Automated cherry-picking of PRs to release branches |
| `renovate-build.yml` | PR (opened, synchronize) | CI validation for Renovate dependency updates |
| `update-release-draft.yml` | Manual dispatch, push | Automatically updates GitHub Release draft release notes from PRs |
| `labeler.yml` | `pull_request_target` | Applies PR labels from `.github/labeler.yml` config |
| `issues.yaml` | Issue opened | Posts the triage acknowledgement comment |

### Maintenance & Repository Hygiene

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `update-docker-images.yml` | Weekly cron (Sun 01:00 UTC), manual | Rebuilds / updates Docker images with latest base packages |
| `update-docker-sha.yml` | Manual dispatch | Updates pinned base image digests in Dockerfiles |
| `dockerhub-description.yml` | Push to `main` | Updates description and README on Docker Hub |
| `cache-update.yml` | Manual dispatch | Refreshes Go binary and image build caches |
| `pull-nap-images.yml` | Manual dispatch | Pulls/syncs NAP images from internal registry |
| `stale.yml` | Daily cron (01:30 UTC) | Closes stale issues and PRs |

---

## CI Patterns

### Matrix Builds

Image variants and test configurations are defined in JSON under `.github/data/`:

- `matrix-images-oss.json`: debian, alpine, ubi (amd64 + arm64)
- `matrix-images-plus.json`: debian-plus, alpine-plus, alpine-plus-fips, ubi-10-plus
- `matrix-images-plus-lts.json`: LTS Plus image definitions
- `matrix-images-nap.json`: WAF v4/v5, DoS, UBI 10 (amd64 only). Every NAP image appears **twice** -- the unsuffixed entry pins nginx-agent v2 and the `-agent` suffixed entry pins v3
- `matrix-smoke-oss.json`, `matrix-smoke-plus.json`, `matrix-smoke-nap.json`: Smoke test matrices
- `matrix-regression.json`: Regression test matrix (K8s version combinations)
- `patch-images.json`, `patch-images-lts.json`: Patch image definitions for `patch-image.yml`

### Caching Strategy

- **Go binaries**: cached by `go_code_md5` hash (computed in `.github/scripts/variables.sh` over all `*.go`, `go.mod`, `go.sum`, `*.tmpl`, `version.txt`)
- **Docker images**: cached by `docker_md5` hash (computed over `build/`, `.github/data/version.txt`, `internal/configs/njs`, `internal/configs/oidc`)
- **Build tags**: `build_tag` (`t-<md5>`) and `stable_tag` (`s-<md5>`) determine image freshness
- Stable images in GCR Dev Registry are checked before rebuilding to prevent redundant Docker builds

### Change Detection & Optimization

- `docs_only` detection in `variables.sh` identifies PRs touching only docs (`*.md`, `docs/**`, `examples/**`) and skips expensive image builds and integration tests.

### Fork Awareness

- `forked_workflow` variable gates authenticated operations. Forked PRs get local-only builds without secret access.

### Concurrency

- CI workflows use `group: ${{ github.ref_name }}-<suffix>` with `cancel-in-progress: true`.
- Release workflows (`release-prep.yml` and `release-publish.yml`) share `group: ${{ inputs.release_branch }}-release` with `cancel-in-progress: false` to ensure a publish dispatch cannot overtake a prep in flight.
- LTS release workflows (`release-prep-lts.yml` and `release-publish-lts.yml`) share `group: ${{ inputs.release_branch }}-release-lts` with `cancel-in-progress: false`.

### Secrets & Authentication

- Secrets are retrieved from Azure Key Vault via `nginx/ci-self-hosted/.github/actions/get-from-vault` using OIDC / Workload Identity -- not stored directly as GitHub repository secrets.
- Google Cloud authentication uses Workload Identity Federation (`google-github-actions/auth`).

### Version Source of Truth

- `.github/data/version.txt` contains `IC_VERSION` and `HELM_CHART_VERSION`.

### Generated-Artifact Gates

The `verify-codegen` job in `ci.yml` regenerates and fails on any diff. A PR that edits the source without committing the regenerated output will not merge:

| Command | Asserted clean |
| --- | --- |
| `go mod tidy` | `go.mod`, `go.sum` |
| `make update-crds` | `config/crd/bases` |
| `make update-codegen` | `pkg/**` |
| `make telemetry-schema` | `internal/telemetry` |

Snapshot golden files are not covered by `verify-codegen` -- they fail in `unit-tests` instead.

---

## Gotchas

- **Release images are never built in the public repo.** `release-prep*.yml` is gated to `nginx/kubernetes-ingress-internal`; the public repo only copies manifests with skopeo. Never add a `docker build` step to a publish-stage workflow
- **Never** add secrets as GitHub repository secrets -- use Azure Key Vault OIDC flow via `get-from-vault` action
- **Always** pin GitHub Actions to immutable SHA hashes with version comments, not mutable tags
- Matrix JSON files in `.github/data/` must stay in sync with Makefile image targets
- NAP variants are `linux/amd64` only -- do not add `arm64` to NAP matrices
- Renovate manages tool versions via `# renovate:` comments -- do not update manually
- `image-promotion.yml` runs on merge to `main` and `release-*`, not on PR -- don't expect images from PRs
- Release-only workflows and `.github/config/config-*` files must be listed in `.github/scripts/exclude_ci_files.txt`, otherwise they feed `get_actions_md5()` and invalidate `stable_tag`, forcing a full image rebuild
- `.github/config/config-*` files are shared between `release-publish.yml`, `image-promotion.yml`, `regression.yml` and `update-docker-images.yml`. Never add a `SOURCE_*_IMAGE_PREFIX` override to one -- the other callers read from the dev registry and would break. Override `TARGET_*` only
- Every job in a non-`mirror-*` workflow must be gated as `github.repository == 'nginx/kubernetes-ingress'` (or `nginx/kubernetes-ingress-internal` for internal-only jobs like prep) optionally followed by `&& ( ... )` with **all** extra conditions inside one balanced group. `&&` binds tighter than `||`, so an ungrouped chain like `gate && (a) || (b)` parses as `(gate && (a)) || (b)` and would run on a fork. Enforced by `.github/scripts/validate-workflow-gating.sh` (pre-commit + `lint-format.yml`); run it locally after editing any job's `if`
- Adding a job to a shared workflow means picking the right gate string. An internal-repo gate in `release-publish.yml` (or vice versa) silently skips the job forever -- there is no error, just a permanently grey box
- The `operator` job skips silently when `operator_version` is empty. If a release ships without an operator PR, check that input before assuming the dispatch failed
- A job whose `if` contains `always()`, `!cancelled()` or `failure()` runs **even when a `needs` dependency failed**. Such jobs must assert every dependency explicitly (`needs.<job>.result == 'success'`), which is why the release jobs list results one by one
- Asserting a *downstream* job is not enough -- a dependency that failed leaves its dependants `skipped`, and `result == 'skipped'` is usually an accepted arm. Assert the job that actually does the work (e.g. `tag` asserts `release-gate`, `release-assets` asserts `variables`)
- `contains()` is a **substring** match, not a token match. Never gate on a value that is a prefix of another job name: `contains(skip_step, 'prep')` also matches `push-prep-images`, and `contains(skip_step, 'publish')` also matches `publish-helm-chart`
- `release-prep.yml` and `release-publish.yml` share the `<branch>-release` concurrency group so a publish dispatch cannot overtake a prep still writing to the staging registry (likewise for LTS release workflows sharing `<branch>-release-lts`)
- `copy-images.sh` resolves `SOURCE_REGISTRY`/`TARGET_REGISTRY` *after* sourcing `CONFIG_PATH`, so an explicit positional argument beats the config file. Pass the source registry as `$1`; let the config own `TARGET_REGISTRY`
- Jobs that publish externally visible artifacts must fail loudly when there is nothing to publish. `github-release` errors on a missing draft release **before** closing the milestone, so a green run guarantees a published release
