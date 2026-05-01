---
name: nic-ci-pipelines
description: 'CI/CD pipeline structure, GitHub Actions workflows, reusable workflow patterns, and matrix builds for NIC. Use when working on CI workflows, debugging build failures, adding new workflow steps, modifying build matrices, or understanding the release pipeline.'
---

# NIC CI/CD Pipelines

## Workflow Architecture

The CI system uses GitHub Actions with extensive **reusable workflow** composition.

```
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

release.yml (manual dispatch)
  -> oss-release.yml
  -> plus-release.yml
  -> publish-helm.yml
  -> certify-ubi-image.yml
  -> marketplace pushes (AWS, Azure, GCP)
```

---

## Key Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR to `main`/`release-*`, merge_group, workflow_dispatch | Main CI: checks + build + test |
| `lint-format.yml` | PR to `main`, merge_group | goimports, gofumpt, golangci-lint, actionlint |
| `regression.yml` | Daily cron (03:00 UTC), manual | Multi-K8s-version regression |
| `image-promotion.yml` | Push to `main`/`release-*` | Post-merge image tagging + scanning |
| `release.yml` | Manual dispatch | Full release orchestrator |
| `build-base-images.yml` | Weekday cron (04:30 UTC) | Rebuilds all base images |

### Release Sub-Workflows (called by `release.yml`)

| Workflow | Purpose |
|----------|---------|
| `oss-release.yml` | OSS image release |
| `plus-release.yml` | Plus/NAP image release |
| `publish-helm.yml` | Helm chart publishing to registry |

### Reusable Build Workflows (called via `workflow_call`)

| Workflow | Purpose |
|----------|---------|
| `build-artifacts.yml` | Orchestrates GoReleaser binary builds + image matrix |
| `build-oss.yml` | Builds single OSS image variant |
| `build-plus.yml` | Builds single Plus/NAP image variant |
| `build-test-image.yml` | Builds Python e2e test image |
| `setup-smoke.yml` | Sets up and runs smoke tests |
| `patch-image.yml` | OS-level patches on existing images |
| `retag-images.yml` | Re-tags images in GCR Dev Registry |

### Security & Compliance

| Workflow | Purpose |
|----------|---------|
| `codeql-analysis.yml` | GitHub CodeQL scanning |
| `scorecards.yml` | OpenSSF Scorecards |
| `dependency-review.yml` | Dependency review for PRs |
| `mend.yml` | Mend (WhiteSource) software composition analysis |
| `certify-ubi-image.yml` | Red Hat UBI certification for OpenShift |

---

## CI Patterns

### Matrix Builds

Image variants are defined in JSON under `.github/data/`:
- `matrix-images-oss.json`: debian, alpine, ubi (amd64 + arm64)
- `matrix-images-plus.json`: debian-plus, alpine-plus, alpine-plus-fips, ubi-9-plus
- `matrix-images-nap.json`: WAF v4/v5, DoS, UBI 8/9 (amd64 only)
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
