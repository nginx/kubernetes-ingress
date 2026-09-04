---
name: nic-docker-images
description: 'Docker image build system, Dockerfile structure, image variants, build scripts, and Makefile targets for NIC. Use when building container images, modifying the Dockerfile, adding new image variants, debugging image builds, or working with build scripts.'
---

# NIC Docker Image Build System

## Dockerfile Architecture

Single `build/Dockerfile` (~1100 lines), heavily multi-stage. The `BUILD_OS` arg selects which base image stage is used, and `TARGET` selects the final stage.

```text
nginx-files (scratch)           <- Repo files, signing keys, package repo definitions, scripts
  |                                (rewrites repo hosts + user-agent strings via sed)
OS-specific base stages         <- One per variant (debian, alpine, ubi, *-plus, *-nap[-v5][-fips][-agent])
  |
FROM ${BUILD_OS} AS common      <- Runs common.sh + patch-os.sh, sets permissions
  |
TARGET stages (final image)     <- local, container, goreleaser, debug, debug-container,
                                   download, aws, patched, and *-prebuilt variants
```

Supporting images built outside this Dockerfile:

- `build/dependencies/Dockerfile.ubi10` builds the UBI package image published to `ghcr.io/nginx/dependencies/nginx-ubi`, consumed via the `UBI10_PACKAGES_IMAGE` build arg (pinned by digest in the `Makefile`). Built by `build-ubi-dependency.yml` on changes to that file, or locally with `make ubi10-dependency-image-local` (requires `rhel_license`).
- `build/dependencies/tracking.info.default` is copied in as `tracking.info` to attribute the install to NIC before the Plus licence reporter initialises.

---

## Image Variants

`make all-images` builds **25** variants. Three axes combine:

1. **OS family**: Debian 13 (trixie), Alpine 3.24, UBI 10 minimal
2. **NGINX edition**: OSS or Plus, plus optional NAP WAF v4 / WAF v5 / DoS and FIPS on Alpine
3. **NGINX Agent version**: v2 (default on NAP variants) or v3 (`-agent` suffixed stages)

| OS | OSS | Plus | Plus+WAF | Plus+WAFv5 | Plus+DoS | Plus+WAF+DoS | Plus+FIPS | Plus+WAF+FIPS | Plus+WAFv5+FIPS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Debian | yes | yes | yes | yes | yes | yes | - | - | - |
| Alpine | yes | yes | - | - | - | - | yes | yes | yes |
| UBI 10 | yes | yes | yes | yes | yes | yes | - | - | - |

**Architecture**: `amd64` + `arm64` for OSS and Plus. NAP variants are `amd64` only.

### Agent v2 vs v3 -- easy to miss

- OSS and plain Plus images ship **nginx-agent v3 only** (`AGENT_V3_VERSION`).
- Every NAP variant exists **twice**: the unsuffixed stage pins `AGENT_V2_VERSION`, and the `-agent` suffixed stage pins `AGENT_V3_VERSION`. For example `debian-plus-nap` (agent v2) and `debian-plus-nap-agent` (agent v3).
- Both halves of the pair are in `.github/data/matrix-images-nap.json` and in `make all-images`. Adding a NAP stage without its `-agent` twin leaves half the matrix broken.
- Python e2e tests distinguish them with the `agentv2` / `agentv3` pytest markers.

---

## Makefile Image Targets

All targets call `$(DOCKER_CMD)` = `docker build --platform linux/$(ARCH) --target $(TARGET) -f build/Dockerfile`.

| Target | BUILD_OS | NAP_MODULES | Agent |
| --- | --- | --- | --- |
| `debian-image` | `debian` | - | v3 |
| `alpine-image` | `alpine` | - | v3 |
| `ubi-image` | `ubi` | - | v3 |
| `debian-image-plus` | `debian-plus` | - | v3 |
| `alpine-image-plus` | `alpine-plus` | - | v3 |
| `alpine-image-plus-fips` | `alpine-plus-fips` | - | v3 |
| `ubi-image-plus` | `ubi-10-plus` | - | v3 |
| `alpine-image-nap-plus-fips` | `alpine-plus-nap-fips` | `waf` | v2 |
| `alpine-image-nap-plus-fips-agent` | `alpine-plus-nap-fips-agent` | `waf` | v3 |
| `alpine-image-nap-v5-plus-fips` | `alpine-plus-nap-v5-fips` | `waf` | v2 |
| `alpine-image-nap-v5-plus-fips-agent` | `alpine-plus-nap-v5-fips-agent` | `waf` | v3 |
| `debian-image-nap-plus` | `debian-plus-nap` | `waf` | v2 |
| `debian-image-nap-plus-agent` | `debian-plus-nap-agent` | `waf` | v3 |
| `debian-image-nap-v5-plus` | `debian-plus-nap-v5` | `waf` | v2 |
| `debian-image-nap-v5-plus-agent` | `debian-plus-nap-v5-agent` | `waf` | v3 |
| `debian-image-dos-plus` | `debian-plus-nap` | `dos` | v2 |
| `debian-image-nap-dos-plus` | `debian-plus-nap` | `waf,dos` | v2 |
| `debian-image-nap-dos-plus-agent` | `debian-plus-nap-agent` | `waf,dos` | v3 |
| `ubi-image-nap-plus` | `ubi-10-plus-nap` | `waf` | v2 |
| `ubi-image-nap-plus-agent` | `ubi-10-plus-nap-agent` | `waf` | v3 |
| `ubi-image-nap-v5-plus` | `ubi-10-plus-nap-v5` | `waf` | v2 |
| `ubi-image-nap-v5-plus-agent` | `ubi-10-plus-nap-v5-agent` | `waf` | v3 |
| `ubi-image-dos-plus` | `ubi-10-plus-nap` | `dos` | v2 |
| `ubi-image-nap-dos-plus` | `ubi-10-plus-nap` | `waf,dos` | v2 |
| `ubi-image-nap-dos-plus-agent` | `ubi-10-plus-nap-agent` | `waf,dos` | v3 |

Other targets: `all-images` (all 25, prunes the builder cache first), `ubi10-dependency-image-local` (UBI package image), `push` (`docker push` to `PREFIX:TAG`), `patch-os` (OS patches an existing image).

Plus images receive `$(PLUS_ARGS)`: `--secret id=nginx-repo.crt --secret id=nginx-repo.key` plus `NGINX_PLUS_VERSION` and `PLUS_PACKAGE_REPO`.

### TARGET Variable

`make build` accepts only `local`, `container`, `download`, `goreleaser`, `debug` and errors on anything else. The remaining stages are selected by CI or by `make patch-os` directly.

| Target | Use Case |
| --- | --- |
| `local` | Default -- binary pre-built on host, copied in |
| `container` | Binary built inside Docker (multi-arch capable) |
| `goreleaser` | Binary from GoReleaser `dist/` (CI builds) |
| `debug` | Includes delve debugger |
| `debug-container` | Delve build with the binary compiled inside Docker |
| `download` | Extracts binary from a published Docker Hub image (`DOWNLOAD_TAG`, resolved by `hack/docker.sh`) |
| `aws` | AWS marketplace variant |
| `patched` | OS patches an existing image (`IMAGE_NAME`) |
| `local-prebuilt`, `goreleaser-prebuilt`, `aws-prebuilt` | Same as their counterparts but layered onto `PREBUILT_BASE_IMG` instead of rebuilding the OS stage |

---

## Key Build Args

| Arg | Purpose | Source of truth |
| --- | --- | --- |
| `BUILD_OS` | Base image stage | `Makefile` targets + Dockerfile stages |
| `IC_VERSION` | Ingress controller version | `.github/data/version.txt` |
| `NGINX_PLUS_VERSION` | NGINX Plus version | `Makefile` |
| `NGINX_OSS_VERSION` | NGINX OSS version | `Makefile` |
| `AGENT_V2_VERSION` / `AGENT_V3_VERSION` | nginx-agent version per variant | `Makefile` |
| `NAP_MODULES` | App Protect modules | Any of `waf`, `dos`, or `waf,dos` |
| `NAP_WAF_VERSION`, `NAP_WAF_COMMON_VERSION`, `NAP_WAF_PLUGIN_VERSION`, `NAP_WAF_IPI_VERSION` | NAP WAF package pins | `Makefile` |
| `UBI10_PACKAGES_IMAGE` | UBI package image, digest-pinned | `Makefile` (`ghcr.io/nginx/dependencies/nginx-ubi`) |
| `PREBUILT_BASE_IMG` | Base for `*-prebuilt` targets | GCR image ref (set by CI) |
| `IMAGE_NAME` | Image to patch for `TARGET=patched` | `make patch-os` / `patch-image.yml` |
| `DOWNLOAD_TAG` | Published tag for `TARGET=download` | `hack/docker.sh` |
| `OSS_PACKAGE_REPO` | Repo host for OSS packages | `Makefile` / CI inputs (defaults to packages.nginx.org) |
| `AGENT_PACKAGE_REPO` | Repo host for NGINX Agent packages | `Makefile` / CI inputs (defaults to packages.nginx.org) |
| `PLUS_PACKAGE_REPO` | Repo host for Plus packages | `Makefile` / CI inputs (defaults to pkgs.nginx.com) |
| `WAF_PACKAGE_REPO` | Repo host for F5 NAP WAF packages | `Makefile` / CI inputs (defaults to pkgs.nginx.com) |
| `DOS_PACKAGE_REPO` | Repo host for F5 NAP DoS packages | `Makefile` / CI inputs (defaults to pkgs.nginx.com) |

Do not hard-code `IC_VERSION`, `NGINX_*_VERSION`, `AGENT_*_VERSION` or `NAP_WAF_*` values in this file or in other docs as they change every release. Always reference the `Makefile` variables or `.github/data/version.txt`.

---

## Build Scripts (`build/scripts/`)

| Script | Purpose |
| --- | --- |
| `common.sh` | Sets up directories, copies NGINX templates (v1/v2), sets file permissions (101:0), runs `setcap` on nginx binaries |
| `agent.sh` | Configures nginx-agent ownership; creates NMS compiler symlinks for NAP v4 |
| `nap-waf.sh` | Creates WAF directories (`/etc/nginx/waf/nac-policies`, `/opt/app_protect/`) |
| `nap-dos.sh` | Creates DoS directories (`/root/app_protect_dos`, `/shared/cores`) |
| `ubi-setup.sh` | UBI-specific: installs shadow-utils, creates nginx user/group (101:0) |
| `ubi-clean.sh` | UBI-specific: removes build-time packages, cleans dnf cache |

`patch-os.sh` is **not** in this repo -- the `nginx-files` stage fetches it from `nginx/k8s-common` (`files/patch-os.sh`). Changes to it must be made in that repository.

Package repo definitions (`*.repo`, `*.sources`, `90pkgs-nginx`) are likewise fetched in `nginx-files` from `cs.nginx.com` and `nginx/k8s-common`, then rewritten with `sed` to inject the version, the `*_PACKAGE_REPO` host override, and the `k8s-ic-<IC_VERSION>` user-agent used for usage attribution.

---

## Key Conventions

- All images run as **UID 101** (nginx user), with `setcap cap_net_bind_service` for ports 80/443
- Docker BuildKit always enabled: uses `--mount=type=bind`, `--mount=type=secret`, `--mount=type=cache`
- Plus credentials use `--secret` mounts, **never** `COPY` into layers
- OSS builds use optional `--secret` mounts (`required=false`) for `nginx-repo.crt`/`nginx-repo.key` to authenticate against non-default repo hosts like `pkgs-test.nginx.com` when running authenticated CI builds.
- Fixed upstream base images use **pinned `@sha256:` digests** for reproducibility; some stages intentionally use build-arg/tag-selected bases (for example `BUILD_OS`, `UBI10_PACKAGES_IMAGE`, or download/prebuilt images)
- FIPS variants build on `ghcr.io/nginx/alpine-fips`; UBI variants build on `redhat/ubi10-minimal`
- All images include `nginx-module-otel` (OpenTelemetry) and `nginx-agent` (usage reporting)
- Plus images add `njs` and `fips-check` modules
- Renovate manages base image digests and tool versions via `# renovate:` comments

---

## Gotchas

- **Never** store Plus credentials in image layers -- always use `--secret` mounts
- **Never** add `arm64` to NAP image matrices -- NAP is `amd64` only
- **Always** use `BUILD_OS` to select variants, not separate Dockerfiles
- **Always add or change NAP stages in pairs.** A new `foo-nap` stage needs a matching `foo-nap-agent` stage, a Makefile target, an entry in `make all-images`, and both entries in `.github/data/matrix-images-nap.json`
- The `common` stage unifies all variants -- changes there affect every image
- `common.sh` detects Plus via `BUILD_OS` containing "plus" and creates OIDC directories
- `patch-os.sh` lives in `nginx/k8s-common`, not `build/scripts/` -- editing it here is impossible
- `UBI10_PACKAGES_IMAGE` is digest-pinned in the `Makefile`; rebuilding `build/dependencies/Dockerfile.ubi10` requires bumping that digest afterwards
- When adding new image dependencies, update the relevant OS-specific stage AND the common stage if needed
