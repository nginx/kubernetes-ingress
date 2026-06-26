---
name: nic-docker-images
description: 'Docker image build system, Dockerfile structure, image variants, build scripts, and Makefile targets for NIC. Use when building container images, modifying the Dockerfile, adding new image variants, debugging image builds, or working with build scripts.'
---

# NIC Docker Image Build System

## Dockerfile Architecture

Single `build/Dockerfile` (~850 lines), heavily multi-stage. The `BUILD_OS` arg selects which base image stage is used.

```text
nginx-files (scratch)           <- Collects repo files, signing keys, scripts
  |
OS-specific base stages         <- One per variant (debian, alpine, ubi, *-plus, *-nap)
  |
FROM ${BUILD_OS} AS common      <- patch-os.sh -> common.sh -> harden.sh
  |                                 (harden.sh purges runtime-unused packages
  |                                  and runs ldd verification; build fails
  |                                  if any runtime binary loses a NEEDED lib)
  |                                 Copies ldd-analyze.sh to /usr/local/bin
  |
TARGET stages (final image)     <- local, container, goreleaser, debug, download, aws, patched
```

---

## Image Variants

3 OS families x 2 NGINX editions x optional NAP = ~20 variants.

| OS | OSS | Plus | Plus+WAF | Plus+WAFv5 | Plus+DoS | Plus+WAF+DoS | Plus+FIPS | Plus+WAF+FIPS | Plus+WAFv5+FIPS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Debian | yes | yes | yes | yes | yes | yes | - | - | - |
| Alpine | yes | yes | - | - | - | - | yes | yes | yes |
| UBI 10 | yes | yes | yes | yes | yes | yes | - | - | - |

**Architecture**: `amd64` + `arm64` for OSS and Plus. NAP variants are `amd64` only.

---

## Makefile Image Targets

All targets call `docker build --platform linux/$(ARCH) --target $(TARGET) -f build/Dockerfile`.

| Target | BUILD_OS | NAP_MODULES |
| --- | --- | --- |
| `debian-image` | `debian` | - |
| `alpine-image` | `alpine` | - |
| `ubi-image` | `ubi` | - |
| `debian-image-plus` | `debian-plus` | - |
| `alpine-image-plus` | `alpine-plus` | - |
| `alpine-image-plus-fips` | `alpine-plus-fips` | - |
| `alpine-image-nap-plus-fips` | `alpine-plus-nap-fips` | `waf` |
| `alpine-image-nap-v5-plus-fips` | `alpine-plus-nap-v5-fips` | `waf` |
| `ubi-image-plus` | `ubi-10-plus` | - |
| `debian-image-nap-plus` | `debian-plus-nap` | `waf` |
| `debian-image-nap-v5-plus` | `debian-plus-nap-v5` | `waf` |
| `debian-image-dos-plus` | `debian-plus-nap` | `dos` |
| `debian-image-nap-dos-plus` | `debian-plus-nap` | `waf,dos` |
| `ubi-image-nap-plus` | `ubi-10-plus-nap` | `waf` |
| `ubi-image-nap-v5-plus` | `ubi-10-plus-nap-v5` | `waf` |
| `ubi-image-dos-plus` | `ubi-10-plus-nap` | `dos` |
| `ubi-image-nap-dos-plus` | `ubi-10-plus-nap` | `waf,dos` |
| `all-images` | Builds 18 variants | - |
| `push` | `docker push` to `PREFIX:TAG` | - |
| `patch-os` | OS patches existing image | - |

Plus images receive `$(PLUS_ARGS)`: `--secret id=nginx-repo.crt --secret id=nginx-repo.key`.

### TARGET Variable

| Target | Use Case |
| --- | --- |
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
| --- | --- | --- |
| `BUILD_OS` | Base image stage | `debian`, `alpine-plus`, `ubi-10-plus-nap` |
| `IC_VERSION` | Ingress controller version | `5.5.0` |
| `NGINX_PLUS_VERSION` | NGINX Plus version | `R36` |
| `NAP_MODULES` | App Protect modules | `waf`, `dos`, `waf,dos` |
| `PREBUILT_BASE_IMG` | Base for prebuilt targets | GCR image ref |

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
| `harden.sh` | Universal image hardener: purges runtime-unused packages, verifies every runtime binary still resolves all NEEDED libs (build fails if not). Reads `BUILD_OS` + `NAP_MODULES`. Runs in the `common` stage. |
| `ldd-analyze.sh` | Read-only runtime-dependency inspector. Shipped at `/usr/local/bin/ldd-analyze.sh` in every built image. |

---

## Hardening (harden.sh + ldd-analyze.sh)

Every built image goes through `harden.sh` automatically in the `common` stage. Hardening removes packages that no runtime binary needs, gated by `BUILD_OS` and `NAP_MODULES`.

### Variant helpers in `harden.sh`

| Helper | True when |
| --- | --- |
| `is_plus` | `BUILD_OS` contains `plus` |
| `is_waf` | `BUILD_OS` contains `nap` |
| `is_waf_v5` | `BUILD_OS` contains `nap-v5` |
| `is_waf_v4` | `is_waf && ! is_waf_v5` |
| `is_dos` | `NAP_MODULES` contains `dos` |
| `needs_control_plane_runtime` | Alias for `is_waf_v4` -- gates retention of perl/sed/tar/libcurl-chain on Debian + libcurl/krb5/idn2/nghttp2 on UBI |

### Things hardening preserves on every image

- `libtinfo6` / `ncurses-libs` -- bash dep in downstream `local`/`debug` stages
- `libcap2-bin` / `libcap` -- `setcap` in downstream stages
- `dpkg` / `rpm` / `apk` -- the package manager performing the purges
- `libgcrypt20` + `libgpg-error0` -- `ngx_http_xslt_filter_module.so`
- `libbrotli1` -- `ngx_http_image_filter_module.so`

### Verifying or inspecting an image

```bash
# Full runtime dependency report
docker run --rm --entrypoint /usr/local/bin/ldd-analyze.sh <image>

# Just the missing-libraries section (should always be empty)
docker run --rm --entrypoint /usr/local/bin/ldd-analyze.sh <image> \
    | sed -n '/=== Missing Libraries/,/=== /p'

# Diff two images' runtime graphs (e.g. before/after a hardening change)
docker run --rm --entrypoint /usr/local/bin/ldd-analyze.sh <image-old> > /tmp/old.txt
docker run --rm --entrypoint /usr/local/bin/ldd-analyze.sh <image-new> > /tmp/new.txt
diff /tmp/old.txt /tmp/new.txt
```

### When changing hardening

- Removing a package from a purge list: run `ldd-analyze.sh` first, confirm no runtime binary NEEDs it.
- Adding a package to a purge list: run `harden.sh` against every affected variant via `docker run -v $PWD/build/scripts/harden.sh:/usr/local/bin/harden.sh:ro --entrypoint /bin/sh <built-image> -c '/usr/local/bin/harden.sh'`. The script's own `verify_binaries` step will fail loudly if a runtime binary loses a NEEDED lib.
- Adding a new runtime binary path to a variant: extend `verify_binaries()` in `harden.sh` AND the `BINARIES` list in `ldd-analyze.sh`.
- Debian package names: cover the time_t-transition aliases (`libfoo` AND `libfoot64`) so the purge works on both Bookworm and Trixie.

---

## Key Conventions

- All images run as **UID 101** (nginx user), with `setcap cap_net_bind_service` for ports 80/443
- Docker BuildKit always enabled: uses `--mount=type=bind`, `--mount=type=secret`, `--mount=type=cache`
- Plus credentials use `--secret` mounts, **never** `COPY` into layers
- Fixed upstream base images use **pinned `@sha256:` digests** for reproducibility; some stages intentionally use build-arg/tag-selected bases (for example `BUILD_OS` or download/prebuilt images)
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
- `harden.sh` runs in `common` and **fails the build** if it removes a package a runtime binary still NEEDs -- if a build breaks with `ERROR: Some binaries have missing libraries!`, run `ldd-analyze.sh` against the pre-harden image to find the right gate
- When adding new image dependencies, update the relevant OS-specific stage AND the common stage if needed; if the dep is shared-lib, also confirm `harden.sh` does not purge it
