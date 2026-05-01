---
name: nic-docker-images
description: 'Docker image build system, Dockerfile structure, image variants, build scripts, and Makefile targets for NIC. Use when building container images, modifying the Dockerfile, adding new image variants, debugging image builds, or working with build scripts.'
---

# NIC Docker Image Build System

## Dockerfile Architecture

Single `build/Dockerfile` (~850 lines), heavily multi-stage. The `BUILD_OS` arg selects which base image stage is used.

```
nginx-files (scratch)           <- Collects repo files, signing keys, scripts
  |
OS-specific base stages         <- One per variant (debian, alpine, ubi, *-plus, *-nap)
  |
FROM ${BUILD_OS} AS common      <- Runs common.sh + patch-os.sh, sets permissions
  |
TARGET stages (final image)     <- local, container, goreleaser, debug, download, aws, patched
```

---

## Image Variants

3 OS families x 2 NGINX editions x optional NAP = ~20 variants.

| OS | OSS | Plus | Plus+WAF | Plus+WAFv5 | Plus+DoS | Plus+WAF+DoS | Plus+FIPS | Plus+WAF+FIPS | Plus+WAFv5+FIPS |
|----|-----|------|----------|------------|----------|-------------|-----------|---------------|-----------------|
| Debian | yes | yes | yes | yes | yes | yes | - | - | - |
| Alpine | yes | yes | - | - | - | - | yes | yes | yes |
| UBI 9 | yes | yes | yes | yes | yes | yes | - | - | - |
| UBI 8 | - | - | yes | yes | - | - | - | - | - |

**Architecture**: `amd64` + `arm64` for OSS and Plus. NAP variants are `amd64` only.

---

## Makefile Image Targets

All targets call `docker build --platform linux/$(ARCH) --target $(TARGET) -f build/Dockerfile`.

| Target | BUILD_OS | NAP_MODULES |
|--------|----------|-------------|
| `debian-image` | `debian` | - |
| `alpine-image` | `alpine` | - |
| `ubi-image` | `ubi` | - |
| `debian-image-plus` | `debian-plus` | - |
| `alpine-image-plus` | `alpine-plus` | - |
| `alpine-image-plus-fips` | `alpine-plus-fips` | - |
| `alpine-image-nap-plus-fips` | `alpine-plus-nap-fips` | `waf` |
| `alpine-image-nap-v5-plus-fips` | `alpine-plus-nap-v5-fips` | `waf` |
| `ubi-image-plus` | `ubi-9-plus` | - |
| `debian-image-nap-plus` | `debian-plus-nap` | `waf` |
| `debian-image-nap-v5-plus` | `debian-plus-nap-v5` | `waf` |
| `debian-image-dos-plus` | `debian-plus-nap` | `dos` |
| `debian-image-nap-dos-plus` | `debian-plus-nap` | `waf,dos` |
| `ubi-image-nap-plus` | `ubi-9-plus-nap` | `waf` |
| `ubi-image-nap-v5-plus` | `ubi-9-plus-nap-v5` | `waf` |
| `ubi-image-dos-plus` | `ubi-9-plus-nap` | `dos` |
| `ubi-image-nap-dos-plus` | `ubi-9-plus-nap` | `waf,dos` |
| `ubi8-image-nap-plus` | `ubi-8-plus-nap` | `waf` |
| `ubi8-image-nap-v5-plus` | `ubi-8-plus-nap-v5` | `waf` |
| `all-images` | Builds 18 variants (excludes `ubi8-image-nap-plus`) | - |
| `push` | `docker push` to `PREFIX:TAG` | - |
| `patch-os` | OS patches existing image | - |

Plus images receive `$(PLUS_ARGS)`: `--secret id=nginx-repo.crt --secret id=nginx-repo.key`.

### TARGET Variable

| Target | Use Case |
|--------|----------|
| `local` | Default -- binary pre-built on host, copied in |
| `container` | Binary built inside Docker (multi-arch capable) |
| `goreleaser` | Binary from GoReleaser `dist/` (CI builds) |
| `debug` | Includes delve debugger |
| `download` | Extracts binary from published Docker Hub image |
| `aws` | AWS marketplace variant |
| `patched` | OS patches an existing image |

---

## Key Build Args

| Arg | Purpose | Example |
|-----|---------|---------|
| `BUILD_OS` | Base image stage | `debian`, `alpine-plus`, `ubi-9-plus-nap` |
| `IC_VERSION` | Ingress controller version | `5.5.0` |
| `NGINX_PLUS_VERSION` | NGINX Plus version | `R36` |
| `NAP_MODULES` | App Protect modules | `waf`, `dos`, `waf,dos` |
| `PREBUILT_BASE_IMG` | Base for prebuilt targets | GCR image ref |

---

## Build Scripts (`build/scripts/`)

| Script | Purpose |
|--------|---------|
| `common.sh` | Sets up directories, copies NGINX templates (v1/v2), sets file permissions (101:0), runs `setcap` on nginx binaries |
| `agent.sh` | Configures nginx-agent ownership; creates NMS compiler symlinks for NAP v4 |
| `nap-waf.sh` | Creates WAF directories (`/etc/nginx/waf/nac-policies`, `/opt/app_protect/`) |
| `nap-dos.sh` | Creates DoS directories (`/root/app_protect_dos`, `/shared/cores`) |
| `ubi-setup.sh` | UBI-specific: installs shadow-utils, creates nginx user/group (101:0) |
| `ubi-clean.sh` | UBI-specific: removes build-time packages, cleans dnf cache |

---

## Key Conventions

- All images run as **UID 101** (nginx user), with `setcap cap_net_bind_service` for ports 80/443
- Docker BuildKit always enabled: uses `--mount=type=bind`, `--mount=type=secret`, `--mount=type=cache`
- Plus credentials use `--secret` mounts, **never** `COPY` into layers
- All `FROM` statements use **pinned `@sha256:` digests** for reproducibility
- All images include `nginx-module-otel` (OpenTelemetry) and `nginx-agent` (usage reporting)
- Plus images add `njs` and `fips-check` modules
- Renovate manages base image digests and tool versions via `# renovate:` comments

---

## Gotchas

- **Never** store Plus credentials in image layers -- always use `--secret` mounts
- **Never** add `arm64` to NAP image matrices -- NAP is `amd64` only
- **Always** use `BUILD_OS` to select variants, not separate Dockerfiles
- The `common` stage unifies all variants -- changes there affect every image
- `common.sh` detects Plus via `BUILD_OS` containing "plus" and creates OIDC directories
- `patch-os.sh` handles OS-level security updates at build time
- When adding new image dependencies, update the relevant OS-specific stage AND the common stage if needed
