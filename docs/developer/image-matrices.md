# Image Matrices

How the container image build matrices in `.github/data/matrix-images-*.json` work, what each field
drives, and what to touch when you add or change an image.

## Overview

Four files describe the images CI builds, scans and publishes:

| File | Edition | Platforms |
| --- | --- | --- |
| `matrix-images-oss.json` | NGINX OSS (debian, alpine, ubi) | amd64, arm64 |
| `matrix-images-plus.json` | NGINX Plus (debian, alpine, alpine-fips, ubi) | amd64, arm64 |
| `matrix-images-plus-lts.json` | NGINX Plus LTS (debian only) | amd64, arm64 |
| `matrix-images-nap.json` | NGINX Plus with App Protect WAF v4/v5, DoS, WAF+DoS | amd64 |

The files are loaded as workflow outputs by `ci.yml`, `image-promotion.yml`, `release-prep.yml`,
`release-prep-lts.yml`, `build-base-images.yml` and `cache-update.yml`. They are consumed through
`strategy.matrix` by `build-artifacts.yml`, which calls `build-oss.yml` or `build-plus.yml` once per row.
The callers forward the whole JSON blob, so they need no change when you add a row.

Smoke test, regression and patch matrices (`matrix-smoke-*.json`, `matrix-regression.json`,
`patch-images*.json`) are separate files with their own schema. See [Known gaps](#known-gaps).

## Row schema

Every row is a flat object under `include`. There is no top-level cross product.

```jsonc
{
  "build_os":    "ubi-10-plus-nap-agent",           // Dockerfile stage -> BUILD_OS build arg
  "image":       "nginx-ic-nap/nginx-plus-ingress", // repo path under the registry prefix
  "tag_suffix":  "-ubi-agent",                      // literal tag postfix, "" for the base variant
  "platforms":   "linux/amd64",
  "target":      "goreleaser",                      // plus and nap only
  "nap_modules": "waf"                              // nap only: waf, dos or waf,dos
}
```

| Field | Drives |
| --- | --- |
| `build_os` | The `BUILD_OS` build arg and so the Dockerfile stage. Also the base-image tag, GHA cache scope, concurrency group, job name and Scout results directory. |
| `image` | The repository path under `gcr.io/.../dev/`. The published reference is `<image>:<tag><tag_suffix>`. |
| `tag_suffix` | The literal postfix appended to the tag. It is never derived from other fields. |
| `platforms` | The `platforms` input of the build action. |
| `target` | The Dockerfile target (`goreleaser`) and the metadata annotation level. |
| `nap_modules` | The `NAP_MODULES` build arg, and part of the NAP base-image tag and cache scope. |

### Invariants

`.github/scripts/validate-image-matrices.sh` enforces these on every matrix file:

- `include` is a non-empty array of objects.
- Every row has `build_os`, `image`, `tag_suffix` and `platforms`. NAP rows also need `nap_modules`, and
  Plus and NAP rows need `target`.
- `(build_os, nap_modules)` is unique per file. This is the **build** key.
- `(image, tag_suffix)` is unique per file. This is the **identity** key.
- Every `build_os` matches a `FROM ... AS <stage>` in `build/Dockerfile`.
- `image` contains a `/`, so a stage name cannot be used by mistake.

The script runs in the `lint-format.yml` job and as a pre-commit hook. The pre-commit hooks are skipped on
pre-commit.ci (see the `ci.skip` list in `.pre-commit-config.yaml`) because that runner has no `jq`. To run it
locally:

```sh
.github/scripts/validate-image-matrices_test.sh
.github/scripts/validate-image-matrices.sh
```

The check goes one way only: matrix rows must match a Dockerfile stage. It does not flag a stage that no row
builds, because helper stages (`*-base`, `goreleaser`, `common` and so on) are legitimately unreferenced.

### Per-job keys use `build_os`, never `image`

`image` is not unique per row. All four rows of `matrix-images-plus.json` share
`nginx-ic/nginx-plus-ingress`. Anything that needs a unique per-job key must use `build_os`, plus
`nap_modules` for NAP. That covers the concurrency group, GHA cache scope, prebuilt base-image tag, job name
and Scout results directory. Keying on `image` would serialise the four Plus jobs into one concurrency group
and collide their caches.

## Images produced

CI builds and publishes 25 images from the OSS, Plus and NAP matrices, plus 1 LTS image.

| Repo | Edition | Variants (tag suffix) | Count | Platforms |
| --- | --- | --- | --- | --- |
| `nginx-ic/nginx-ingress` | OSS | debian (none), `-alpine`, `-ubi` | 3 | amd64, arm64 |
| `nginx-ic/nginx-plus-ingress` | Plus | debian (none), `-alpine`, `-alpine-fips`, `-ubi` | 4 | amd64, arm64 |
| `nginx-ic-nap/nginx-plus-ingress` | NAP WAF v4 | none, `-ubi`, `-alpine-fips`, `-agent`, `-ubi-agent`, `-alpine-fips-agent` | 6 | amd64 |
| `nginx-ic-nap-v5/nginx-plus-ingress` | NAP WAF v5 | none, `-ubi`, `-alpine-fips`, `-agent`, `-ubi-agent`, `-alpine-fips-agent` | 6 | amd64 |
| `nginx-ic-dos/nginx-plus-ingress` | NAP DoS-only | none, `-ubi` | 2 | amd64 |
| `nginx-ic-nap-dos/nginx-plus-ingress` | NAP WAF+DoS | none, `-ubi`, `-agent`, `-ubi-agent` | 4 | amd64 |
| | | **Total** | **25** | |

The LTS matrix has one row, `debian-plus` with no tag suffix. It builds into the same dev repo as regular Plus,
`nginx-ic/nginx-plus-ingress`, and is told apart by its tag. It is built by `release-prep-lts.yml`, not by the
regular CI flow, and the `/lts/` path (`nginx-ic/lts/nginx-plus-ingress`) only exists after the build: in
`docker-mgmt-test` staging, in the release GCR, and in the NGINX registry. The `config-plus-*-lts*` configs and
`patch-images-lts.json` set those paths. Do not add `/lts/` to the matrix `image`, or the staging copy will read
a repo the build never writes to.

AWS and Azure marketplace tags (`-mktpl`) are not in the matrices. They are produced at release time by the
publish configs.

## NGINX Agent versions

- OSS and plain Plus images ship nginx-agent v3 only.
- NAP **WAF** and **WAF+DoS** images come in pairs. The unsuffixed stage pins `AGENT_V2_VERSION` and the
  `-agent` stage pins `AGENT_V3_VERSION`. For example `debian-plus-nap` is Agent v2 and
  `debian-plus-nap-agent` is Agent v3. Agent v2 is required for WAF Security Monitoring with NIM.
- NAP **DoS-only** has a single variant per OS and ships Agent v3 under the standard tags. It builds on the
  `debian-plus-nap` and `ubi-10-plus-nap` stages, which install Agent v3 when `NAP_MODULES=dos` and Agent v2
  otherwise. There are no DoS-only `-agent` images, so none are built, scanned or published.
- The `debian-image-dos-plus` and `ubi-image-dos-plus` Makefile targets build the same stages, so local
  builds match CI.
- Python e2e tests distinguish the two agents with the `agentv2` and `agentv3` pytest markers.

## Adding or changing an image

1. **Dockerfile.** Add the `FROM ... AS <stage>` stage. Add NAP WAF stages in pairs (`foo` and `foo-agent`).
   See the `nic-docker-images` skill.
2. **Matrix row.** Add the row to the right `matrix-images-*.json`. Pick a `(build_os, nap_modules)` and an
   `(image, tag_suffix)` that are not already used, then run the validator.
3. **Publish lists.** Add the new `tag_suffix` to the postfix list for its repo in `copy-images.sh` and in
   every release config that publishes it. Configs live in `.github/config/`:
   `config-prep-nginx-test`, `config-plus-nginx`, `config-plus-gcr-release`, `config-gcr-retag`, and the
   marketplace configs where relevant. A tag that is built but not in a postfix list is never published, and
   a tag in a list that nothing builds makes the copy fail.
4. **Makefile.** Add a local build target and add it to `all-images`.
5. **Tests data.** Add the image to `tests/data/modules/data.json` so `check_container_packages.py` checks its
   packages, and to the smoke matrices if it needs e2e coverage.
6. **Patch matrix.** If the image must be patched weekly, add it to `.github/data/patch-images.json`.
7. **Docs.** Update the image table above and the `nic-ci-pipelines` and `nic-docker-images` skills.

CI will rebuild every image once after a matrix or `build-*.yml` change, because those files are not in
`.github/scripts/exclude_ci_files.txt`, so `stable_tag` changes.

## Registry naming

- The NGINX registry uses `nginx-ic-nap-dos` for WAF+DoS, and the dev and release GCR paths match it.
- `config-plus-ecr` deliberately keeps `nginx-plus-ingress-dos-nap`. It is the name of the AWS Marketplace
  repository, not an internal path, and ECR does not create repositories on push.
- Staging in `docker-mgmt-test` mirrors the dev and release GCR layout. `config-prep-nginx-test` leaves the
  image prefixes at their `copy-images.sh` defaults on purpose, and the publish stage reads them back with the
  same defaults. Any prefix override in a prep config must be matched by a `SOURCE_*` override in every publish
  config.

### Renaming an image path

The weekly cron in `update-docker-images.yml` (`0 1 * * 0`) is restricted by GitHub to the default branch. It
reads `main`'s `patch-images.json` and picks the tag to patch with `git tag --sort=-version:refname | head -n1`,
the newest tag overall.

A rename on `main` also has to reach the newest release branch. The cron publishes from that branch, using its
own `copy-images.sh`, so the `target_image` dev path in `patch-images.json` must match that script's source
prefix. Older release branches are not patched by the cron and can keep the old name.

The risk is the gap between the rename landing on `main` and the first release cut under the new name. In that
window the cron looks for `release/<new-path>/...:<latest-tag>`, which does not exist. Before merging a rename,
copy the existing release tags to the new path with no rebuild:

```sh
skopeo copy -a \
  docker://gcr.io/<project>/release/<old-path>/nginx-plus-ingress:<tag><postfix> \
  docker://gcr.io/<project>/release/<new-path>/nginx-plus-ingress:<tag><postfix>
```

Do this for the latest `X.Y.Z`, the short `X.Y`, `latest`, any `X.Y.Z-<date>` patch tags still in use, and every
postfix in the repo's release list. Verify with `skopeo inspect` on the new path. Leave the old path in place,
because existing release branches keep reading it.

## Verifying a change

- `.github/scripts/validate-image-matrices_test.sh` and `.github/scripts/validate-image-matrices.sh`.
- `actionlint` on the workflows.
- Check that every `(image, tag_suffix)` in the matrices has a slot in the postfix lists in `copy-images.sh`
  and the release configs, and the reverse.
- Run `DRY_RUN=true CONFIG_PATH=.github/config/config-prep-nginx-test .github/scripts/copy-images.sh` to see the
  source and target references the prep stage would copy.
- A `release-prep.yml` dry run (`dry_run: true`) on the internal repository confirms the staging prefix set.
  It reads the matrices from the `release_branch` input, so that branch must contain your change.
- For a Dockerfile agent change, run `apt list | grep nginx-agent` (or `rpm -q nginx-agent` on UBI) in a built
  image. `tests/scripts/check_container_packages.py` enforces the versions in `tests/data/modules/data.json`.

## Known gaps

- `matrix-smoke-*.json` and `matrix-regression.json` still use the old schema, where `image` holds the
  Dockerfile stage name. `setup-smoke.yml` and `regression.yml` still derive the registry path and tag suffix
  with `contains()`, and the two copies have drifted. For example, the `regression.yml` tag derivation has no
  `-agent` component, so a regression run against an `-agent` image pulls the wrong tag. Migrating them to
  `build_os` / `image` / `tag_suffix` removes the last copies of that logic.
- `patch-images.json` uses `source_os` as a tag suffix, with `debian` as the sentinel for "no suffix". It is
  a candidate to rename to `tag_suffix` once the smoke and regression matrices are migrated.
