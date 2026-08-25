---
name: nic-ci-pipelines
description: 'CI/CD pipeline structure, GitHub Actions workflows, reusable workflow patterns, and matrix builds for NIC. Use when working on CI workflows, debugging build failures, adding new workflow steps, modifying build matrices, or understanding the release pipeline.'
---

# NIC CI/CD Pipelines

## Workflow Architecture

The CI system uses GitHub Actions with extensive **reusable workflow** composition.

```text
ci.yml (main CI orchestrator)
  -> checks (format, lint, codegen, CRDs, chart version)
  -> unit-tests
  -> build-artifacts.yml (reusable)
       -> build-oss.yml (per-variant, matrix)
       -> build-plus.yml (per-variant, matrix)  <- also used for NAP variants
  -> helm-tests
  -> setup-smoke.yml (reusable)
  -> e2e tests

image-promotion.yml (post-merge)
  -> builds images, tags edge/stable
  -> Trivy + DockerScout security scans
  -> publishes edge Helm charts

release.yml (manual dispatch, mode: prep | publish | all)
  -> release-prep.yml            (mode: prep / all)
       -> build-artifacts.yml    (reusable)
       -> pushes prepped images to docker-mgmt-test.nginx.com
       -> tarballs -> Azure blob storage
       -> creates the vX.Y.Z tag
       -> attaches assets to the GitHub release draft
  -> release-publish.yml         (mode: publish / all, needs prep)
       -> oss-release.yml        (source_registry: docker-mgmt-test.nginx.com)
       -> plus-release.yml       (source_registry: docker-mgmt-test.nginx.com)
       -> publish-helm.yml
       -> certify-ubi-image.yml
       -> triggers nginx-ingress-helm-operator sync
       -> publishes the GitHub release draft
       -> marketplace pushes (AWS, Azure, GCP)
```

The two stages are independently dispatchable, so a failed publish can be
retried without rebuilding. `release-prep.yml` stages every image in
`docker-mgmt-test.nginx.com`; `release-publish.yml` only ever copies from
there, never from the dev registry.

---

## Key Workflows

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `ci.yml` | PR to `main`/`release-*`, merge_group, workflow_dispatch | Main CI: checks + build + test |
| `lint-format.yml` | PR to `main`, merge_group | goimports, gofumpt, golangci-lint, actionlint |
| `regression.yml` | Daily cron (03:00 UTC), manual | Multi-K8s-version regression |
| `image-promotion.yml` | Push to `main`/`release-*` | Post-merge image tagging + scanning |
| `release.yml` | Manual dispatch | Release orchestrator; `mode` input selects `prep`, `publish` or `all` |
| `build-base-images.yml` | Weekday cron (04:30 UTC) | Rebuilds all base images |

### Release Sub-Workflows (called by `release.yml` / LTS releases)

| Workflow | Purpose |
| --- | --- |
| `release-prep.yml` | Stage 1: build artifacts, stage images in the test registry, upload tarballs, tag, attach release assets |
| `release-publish.yml` | Stage 2: copy staged images to public registries, publish Helm chart and GitHub release |
| `release-prep-lts.yml` | LTS Stage 1: build LTS Plus images and binaries, stage in test registry, upload tarballs |
| `release-publish-lts.yml` | LTS Stage 2: copy staged LTS images to public registries, publish LTS Helm chart and GitHub release |
| `oss-release.yml` | OSS image release (called by `release-publish.yml`) |
| `plus-release.yml` | Plus/NAP image release (called by `release-publish.yml`) |
| `plus-release-lts.yml` | LTS Plus image release (called by `release-publish-lts.yml` and `update-docker-images.yml`) |
| `publish-helm.yml` | Helm chart publishing to registry |

`release-prep.yml`, `release-publish.yml`, `release-prep-lts.yml`, and `release-publish-lts.yml` also accept `workflow_dispatch`, so either stage can be run on its own.

### Reusable Build Workflows (called via `workflow_call`)

| Workflow | Purpose |
| --- | --- |
| `build-artifacts.yml` | Orchestrates GoReleaser binary builds + image matrix |
| `build-oss.yml` | Builds single OSS image variant |
| `build-plus.yml` | Builds single Plus/NAP image variant |
| `build-test-image.yml` | Builds Python e2e test image |
| `setup-smoke.yml` | Sets up and runs smoke tests |
| `patch-image.yml` | OS-level patches on existing images |
| `retag-images.yml` | Re-tags images in GCR Dev Registry |

### Security & Compliance

| Workflow | Purpose |
| --- | --- |
| `codeql-analysis.yml` | GitHub CodeQL scanning |
| `scorecards.yml` | OpenSSF Scorecards |
| `dependency-review.yml` | Dependency review for PRs |
| `certify-ubi-image.yml` | Red Hat UBI certification for OpenShift |

---

## CI Patterns

### Matrix Builds

Image variants are defined in JSON under `.github/data/`:

- `matrix-images-oss.json`: debian, alpine, ubi (amd64 + arm64)
- `matrix-images-plus.json`: debian-plus, alpine-plus, alpine-plus-fips, ubi-10-plus
- `matrix-images-nap.json`: WAF v4/v5, DoS, UBI 10 (amd64 only)
- `matrix-smoke-oss.json`, `matrix-smoke-plus.json`, `matrix-smoke-nap.json`: Smoke test matrices
- `matrix-regression.json`: Regression test matrix (K8s version combinations)
- `patch-images.json`: Patch image definitions for `patch-image.yml`

### Caching Strategy

- Go binaries: cached by `go_code_md5` hash
- Docker images: cached by `docker_md5` hash
- Stable images in GCR are checked before rebuilding

### Fork Awareness

`forked_workflow` variable gates authenticated operations. Forked PRs get local-only builds without secret access.

### Concurrency

Each workflow uses `group: ${{ github.ref_name }}-<suffix>` with `cancel-in-progress: true`.

### Secrets

Retrieved from Azure Key Vault via OIDC -- not stored as GitHub secrets directly.

### Version Source of Truth

`.github/data/version.txt` contains `IC_VERSION` and `HELM_CHART_VERSION`.

---

## Gotchas

- **Never** add secrets as GitHub repository secrets -- use Azure Key Vault OIDC flow
- **Always** pin GitHub Actions to immutable SHA hashes, not mutable tags
- Matrix JSON files in `.github/data/` must stay in sync with Makefile image targets
- NAP variants are `linux/amd64` only -- do not add `arm64` to NAP matrices
- Renovate manages tool versions via `# renovate:` comments -- do not update manually
- `image-promotion.yml` runs on merge to `main`, not on PR -- don't expect images from PRs
- Release-only workflows and `.github/config/config-*` files must be listed in `.github/scripts/exclude_ci_files.txt`, otherwise they feed `get_actions_md5()` and invalidate `stable_tag`, forcing a full image rebuild
- `.github/config/config-*` files are shared between `release-publish.yml`, `image-promotion.yml`, `regression.yml` and `update-docker-images.yml`. Never add a `SOURCE_*_IMAGE_PREFIX` override to one -- the other callers read from the dev registry and would break. Override `TARGET_*` only
- Every job in a non-`mirror-*` workflow must be gated as `github.repository == 'nginx/kubernetes-ingress'` optionally followed by `&& ( ... )` with **all** extra conditions inside one balanced group. `&&` binds tighter than `||`, so an ungrouped chain like `gate && (a) || (b)` parses as `(gate && (a)) || (b)` and would run on a fork. Enforced by `.github/scripts/validate-workflow-gating.sh` (pre-commit + `lint-format.yml`); run it locally after editing any job's `if`
- A job whose `if` contains `always()`, `!cancelled()` or `failure()` runs **even when a `needs` dependency failed**. Such jobs must assert every dependency explicitly (`needs.<job>.result == 'success'`), which is why the release jobs list results one by one
- Asserting a *downstream* job is not enough -- a dependency that failed leaves its dependants `skipped`, and `result == 'skipped'` is usually an accepted arm. Assert the job that actually does the work (e.g. `tag` asserts `binaries`, not just `azure-upload`)
- `contains()` is a **substring** match, not a token match. Never gate on a value that is a prefix of another job name: `contains(skip_step, 'prep')` also matches `push-prep-images`, and `contains(skip_step, 'publish')` also matches `publish-helm-chart`. Release *stage* selection is `release.yml`'s `mode` input; `skip_step` is job-level only
- `release-prep.yml` and `release-publish.yml` share the `<branch>-release` concurrency group so a publish dispatch cannot overtake a prep still writing to the staging registry. `release.yml` must **not** join that group -- as the calling workflow it would hold the group and deadlock its own children
- `copy-images.sh` resolves `SOURCE_REGISTRY`/`TARGET_REGISTRY` *after* sourcing `CONFIG_PATH`, so an explicit positional argument beats the config file. Pass the source registry as `$1`; let the config own `TARGET_REGISTRY`
- Jobs that publish externally visible artifacts must fail loudly when there is nothing to publish. `github-release` errors on a missing draft release **before** closing the milestone, so a green run guarantees a published release
