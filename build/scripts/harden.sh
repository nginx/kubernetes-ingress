#!/bin/sh

set -e

# Image hardening for NIC container images.
# Removes packages that no runtime binary needs. Runs in the shared "common"
# Dockerfile stage and supports Alpine, Debian, and UBI bases across the OSS,
# Plus, WAF v4, WAF v5, and DoS variants.
#
# Inputs (set by the Dockerfile):
#   BUILD_OS      — base-image variant token (used to detect Plus vs OSS)
#   NAP_MODULES   — comma-separated module list (informational only)
#
# Variant detection: WAF v4, WAF v5, and DoS are detected from the
# filesystem, not from NAP_MODULES, because the upstream Dockerfile installs
# those components conditionally per NAP_MODULES and the CI workflow has
# historically passed an empty NAP_MODULES in some "waf,dos" matrix entries.
# Inspecting what is actually installed is the source of truth.
#
# Constraint: downstream stages (local, debug, goreleaser-setcap) inherit
# from common and run RUN commands needing bash, coreutils, setcap. This
# script therefore preserves libtinfo/ncurses-libs, libcap2-bin/libcap,
# coreutils/busybox, and the package manager tool itself (dpkg / rpm / apk).

# ─── Variant gates ────────────────────────────────────────────────────────────
# Detection probes the filesystem for vendor-shipped marker files rather than
# reading BUILD_OS / NAP_MODULES. The Dockerfile installs WAF v4, WAF v5,
# and DoS components conditionally per NAP_MODULES, so what is actually on
# disk is the source of truth and is robust to env-var propagation glitches.
is_plus() { echo "${BUILD_OS:-}" | grep -q "plus"; }

is_waf_v4() { [ -f /opt/app_protect/VERSION.common ]; }

is_waf_v5() {
    [ -f /usr/lib/libsocketplugin.so ] || [ -f /usr/lib64/libsocketplugin.so ]
}

is_waf() { is_waf_v4 || is_waf_v5; }

is_dos() {
    [ -x /usr/bin/admd ] || \
    [ -f /etc/nginx/modules/ngx_http_app_protect_dos_module.so ] || \
    [ -f /usr/lib/nginx/modules/ngx_http_app_protect_dos_module.so ] || \
    [ -f /usr/lib64/nginx/modules/ngx_http_app_protect_dos_module.so ]
}

# WAF v4 forks an external perl interpreter and invokes sed and tar.
needs_perl_runtime() { is_waf_v4; }

# WAF v4 and DoS both link against libcurl and pull its transitive chain
# (krb5 / ldap / ssh2 / nghttp2 / idn2 / libgnutls / ...).
needs_libcurl_runtime() { is_waf_v4 || is_dos; }

# ─── Verification ─────────────────────────────────────────────────────────────
verify_binaries() {
    echo "  Verifying runtime binaries..."
    _failed=0

    # Always-present binaries
    _check_bins="/usr/sbin/nginx /usr/bin/nginx-agent"
    [ -x /nginx-ingress ] && _check_bins="$_check_bins /nginx-ingress"

    # WAF v4 binaries
    if is_waf_v4; then
        _check_bins="$_check_bins /usr/share/ts/bin/bd-socket-plugin"
        for _b in /opt/app_protect/bin/apcompile \
                  /opt/app_protect/bin/config_set_apply \
                  /opt/app_protect/bin/is_json_schema_valid; do
            [ -x "$_b" ] && _check_bins="$_check_bins $_b"
        done
    fi
    # DoS binaries
    if is_dos; then
        _check_bins="$_check_bins /usr/bin/admd"
    fi

    for _bin in $_check_bins; do
        if [ -f "$_bin" ] && [ -x "$_bin" ]; then
            if [ "$_bin" = "/usr/share/ts/bin/bd-socket-plugin" ]; then
                _result=$(LD_LIBRARY_PATH=/usr/lib64/bd ldd "$_bin" 2>/dev/null | grep "not found" || true)
            else
                _result=$(ldd "$_bin" 2>/dev/null | grep "not found" || true)
            fi
            if [ -n "$_result" ]; then
                echo "  WARNING: $_bin has missing libraries:"
                echo "$_result" | while read -r line; do echo "    $line"; done
                _failed=1
            fi
        fi
    done

    # Check NGINX modules
    for _moddir in /etc/nginx/modules /usr/lib/nginx/modules /usr/lib64/nginx/modules; do
        if [ -d "$_moddir" ]; then
            for _mod in "$_moddir"/*.so; do
                [ -f "$_mod" ] || continue
                _result=$(ldd "$_mod" 2>/dev/null | grep "not found" || true)
                if [ -n "$_result" ]; then
                    echo "  WARNING: $_mod has missing libraries:"
                    echo "$_result" | while read -r line; do echo "    $line"; done
                    _failed=1
                fi
            done
        fi
    done

    # WAF v5 loads a standalone shared object into nginx
    if is_waf_v5; then
        for _so in /usr/lib/libsocketplugin.so /usr/lib64/libsocketplugin.so; do
            [ -f "$_so" ] || continue
            _result=$(ldd "$_so" 2>/dev/null | grep "not found" || true)
            if [ -n "$_result" ]; then
                echo "  WARNING: $_so has missing libraries:"
                echo "$_result" | while read -r line; do echo "    $line"; done
                _failed=1
            fi
        done
    fi

    # WAF v4 control plane invokes external perl + sed.
    # On Alpine these come from busybox at /bin/sed; on Debian and UBI from
    # the perl-base and sed packages.
    if needs_perl_runtime; then
        for _tool in perl sed; do
            if ! command -v "$_tool" >/dev/null 2>&1; then
                echo "  WARNING: $_tool missing (required by WAF v4 control plane)"
                _failed=1
            fi
        done
    fi

    if [ "$_failed" -eq 0 ]; then
        echo "  All runtime binaries OK"
    else
        echo "  ERROR: Some binaries have missing libraries!"
        exit 1
    fi
}

# ─── Debian hardening ─────────────────────────────────────────────────────────
# Targets Debian 13 (Trixie). Package-name aliases also cover Trixie's
# time_t-transition naming (libldap2 vs libldap-2.5-0, libgnutls30t64 vs
# libgnutls30, libcurl4t64 vs libcurl4, libssh2-1t64 vs libssh2-1,
# libunistring5 vs libunistring2) — both names may coexist as transitional
# packages, so the purge lists name both.
harden_debian() {
    echo "Hardening Debian image (BUILD_OS=${BUILD_OS:-unset}, NAP_MODULES=${NAP_MODULES:-none})..."

    # ── Removed from every Debian variant ──

    # Package management (keep dpkg — it executes the purges)
    dpkg --purge --force-all apt libapt-pkg7.0 gpgv 2>/dev/null || true

    # User/login management (UID 101 was created in an earlier stage)
    dpkg --purge --force-all login passwd 2>/dev/null || true

    # PAM stack — no OS-level auth in container
    dpkg --purge --force-all \
        libpam-modules libpam-modules-bin libpam-runtime libpam0g \
        2>/dev/null || true

    # ncurses utilities only — keep libtinfo6 (bash links against it)
    dpkg --purge --force-all ncurses-bin ncurses-base 2>/dev/null || true

    # Block-device / mount tooling (no disks mounted at runtime)
    # util-linux-extra not present in Trixie slim (harmless no-op)
    dpkg --purge --force-all \
        bsdutils mount util-linux util-linux-extra \
        libblkid1 libmount1 libsmartcols1 libuuid1 \
        2>/dev/null || true

    # systemd / udev — purge AFTER apt + util-linux so nothing still NEEDs them.
    # DoS variants link against libsystemd, so keep it on those.
    if is_dos; then
        echo "  DoS variant — preserving libsystemd0 + libudev1"
    else
        dpkg --purge --force-all libsystemd0 libudev1 2>/dev/null || true
    fi

    # jq (debugging tool — no runtime consumer)
    dpkg --purge --force-all jq libjq1 libonig5 2>/dev/null || true

    # ── WAF v4 control-plane dependencies (perl interpreter + text tools) ──
    # The perl interpreter, sed, and tar are only forked by WAF v4. Plus /
    # WAF v5 / DoS / OSS do not need them. libgnutls is handled below as part
    # of the libcurl chain.
    if ! needs_perl_runtime; then
        dpkg --purge --force-all perl-base 2>/dev/null || true
        dpkg --purge --force-all sed tar 2>/dev/null || true
    else
        echo "  WAF v4 variant — preserving perl-base, sed, tar"
    fi

    # ── libcurl + transitive dependency chain ──
    # libcurl is linked by WAF v4 and DoS variants. Its Debian transitive
    # chain pulls in libgnutls, krb5, ldap, ssh2, nghttp2, rtmp, psl, idn2,
    # unistring, sasl2 — keep them as a group.
    # Trixie ships libgnutls30t64 (real .so); libgnutls30 is the compat marker.
    # Keep libgcrypt20 + libgpg-error0 — used by ngx_http_xslt_filter_module.so.
    if needs_libcurl_runtime; then
        if is_waf_v4 && is_dos; then
            echo "  WAF v4 + DoS variant — preserving libcurl + libgnutls + krb5/ldap/ssh/nghttp2 chain"
        elif is_waf_v4; then
            echo "  WAF v4 variant — preserving libcurl + libgnutls + krb5/ldap/ssh/nghttp2 chain"
        else
            echo "  DoS variant — preserving libcurl + libgnutls + krb5/ldap/ssh/nghttp2 chain"
        fi
    else
        dpkg --purge --force-all \
            libcurl4 libcurl4t64 libnghttp2-14 libnghttp3-9 \
            libgnutls30 libgnutls30t64 \
            libgssapi-krb5-2 libk5crypto3 libkrb5-3 libkrb5support0 \
            libldap-2.5-0 libldap2 liblber-2.5-0 liblber2 \
            libssh2-1 libssh2-1t64 \
            librtmp1 libpsl5 libidn2-0 libunistring2 libunistring5 \
            libsasl2-2 libsasl2-modules-db \
            2>/dev/null || true
    fi

    # ── Filesystem cleanup ──
    rm -rf \
        /var/lib/apt /var/cache/apt /var/log/apt /var/log/dpkg* \
        /etc/apt /usr/lib/apt \
        /usr/share/doc /usr/share/man /usr/share/info \
        /usr/share/lintian /usr/share/bug \
        /tmp/*

    verify_binaries
}

# ─── UBI / RHEL hardening ───────────────────────────────────────────────────
harden_ubi() {
    echo "Hardening UBI/RHEL image (BUILD_OS=${BUILD_OS:-unset}, NAP_MODULES=${NAP_MODULES:-none})..."

    # ubi-clean.sh already removes shadow-utils, subscription-manager, python3.

    # UBI 10 ships only microdnf; dnf is here for older bases.
    _pm=""
    if command -v microdnf >/dev/null 2>&1; then
        _pm="microdnf"
    elif command -v dnf >/dev/null 2>&1; then
        _pm="dnf"
    fi

    if [ -n "$_pm" ]; then
        # Orphans on every UBI variant — not NEEDED by any runtime binary or
        # NGINX module (verified via readelf -d on every built UBI variant).
        $_pm remove -y libssh libssh-config libssh2 openldap gnutls 2>/dev/null || true

        if needs_libcurl_runtime; then
            # WAF v4 and DoS variants both link libcurl, which on UBI's
            # libcurl-minimal transitively NEEDs libgssapi_krb5 + libidn2 +
            # libnghttp2. Keep them.
            if is_waf_v4 && is_dos; then
                echo "  WAF v4 + DoS variant — preserving libcurl-minimal, krb5-libs, libidn2, libnghttp2"
            elif is_waf_v4; then
                echo "  WAF v4 variant — preserving libcurl-minimal, krb5-libs, libidn2, libnghttp2"
            else
                echo "  DoS variant — preserving libcurl-minimal, krb5-libs, libidn2, libnghttp2"
            fi
        else
            $_pm remove -y libcurl-minimal libcurl libnghttp2 2>/dev/null || true
            $_pm remove -y krb5-libs 2>/dev/null || true
            $_pm remove -y libidn2 2>/dev/null || true
        fi

        $_pm clean all 2>/dev/null || true
    fi

    rm -rf /var/cache/dnf /var/cache/yum 2>/dev/null || true
    rm -rf /usr/share/doc /usr/share/man /usr/share/info 2>/dev/null || true
    rm -rf /tmp/* 2>/dev/null || true

    verify_binaries
}

# ─── Alpine hardening ─────────────────────────────────────────────────────────
# Alpine is already minimal (busybox + musl). High-value removals:
#   - libcurl/curl on OSS variants (Plus variants keep libcurl for parity
#     with the glibc images).
#   - ssl_client (busybox helper for `apk fetch` over HTTPS, not used by
#     immutable container images).
#   - gpg/gnupg (build-time only).
harden_alpine() {
    echo "Hardening Alpine image (BUILD_OS=${BUILD_OS:-unset}, NAP_MODULES=${NAP_MODULES:-none})..."

    rm -rf /var/cache/apk/* 2>/dev/null || true
    rm -rf /usr/share/doc /usr/share/man /usr/share/info 2>/dev/null || true
    rm -rf /tmp/* 2>/dev/null || true

    if ! is_plus; then
        apk del --no-cache libcurl curl 2>/dev/null || true
    fi

    apk del --no-cache ssl_client 2>/dev/null || true
    apk del --no-cache gpg gnupg 2>/dev/null || true

    verify_binaries
}

# ─── Main ─────────────────────────────────────────────────────────────────────
if [ ! -f /etc/os-release ]; then
    echo "harden.sh: /etc/os-release not found, skipping"
    exit 0
fi

. /etc/os-release

echo "==> harden.sh: BUILD_OS=${BUILD_OS:-unset} NAP_MODULES=${NAP_MODULES:-none} OS_ID=${ID}"

case "${ID}" in
    "debian")
        harden_debian
        ;;
    "rhel")
        harden_ubi
        ;;
    "alpine")
        harden_alpine
        ;;
    *)
        echo "harden.sh: unsupported OS [${ID}], skipping"
        exit 0
        ;;
esac

echo "==> harden.sh complete"
