#!/bin/sh

set -e

# ldd-analyze.sh — runtime dependency analysis for NIC container images.
#
# Walks every binary and shared object the image will execute, runs ldd on
# each, and produces:
#   - the list of inspected binaries and modules
#   - the unique set of shared libraries they pull in
#   - the package that owns each library (via dpkg / rpm / apk)
#   - the binaries themselves mapped back to their owning package
#   - any missing-library errors (the script exits non-zero if any are found
#     via the verify step in harden.sh; this script only reports)
#   - the Go build-info module list for every static Go binary it finds
#   - the full installed-package list for diffing against the SBOM
#
# Usage:
#   # Inspect a built image
#   docker run --rm --entrypoint /usr/local/bin/ldd-analyze.sh <image-ref>
#
#   # Inspect with a non-root user (read-only operations)
#   docker run --rm --user 0 \
#       --entrypoint /usr/local/bin/ldd-analyze.sh <image-ref>
#
#   # Save report for later diffing
#   docker run --rm --entrypoint /usr/local/bin/ldd-analyze.sh \
#       <image-ref> > /tmp/<image>.ldd-report.txt
#
#   # Compare two images (e.g. before / after a hardening change)
#   diff /tmp/before.ldd-report.txt /tmp/after.ldd-report.txt
#
# The script is read-only and safe to run against any image. It does not
# modify the filesystem.

echo "=== NIC Runtime Dependency Analysis ==="
echo "OS: $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "Date: $(date -u 2>/dev/null || echo unknown)"
echo ""

# Detect package manager
pkg_owner() {
    local lib="$1"
    # Resolve symlinks (handles usrmerge: /lib -> /usr/lib, and SONAME -> real .so)
    local real
    real=$(readlink -f "$lib" 2>/dev/null || echo "$lib")
    if command -v dpkg >/dev/null 2>&1; then
        # Try canonical path first, then fall back to basename match
        local out
        out=$(dpkg -S "$real" 2>/dev/null | cut -d: -f1)
        if [ -z "$out" ]; then
            out=$(dpkg -S "$(basename "$real")" 2>/dev/null | awk -F: -v b="$(basename "$real")" '$NF ~ b {print $1; exit}')
        fi
        [ -z "$out" ] && out="unknown"
        echo "$out"
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qf "$real" 2>/dev/null || echo "unknown"
    elif command -v apk >/dev/null 2>&1; then
        apk info --who-owns "$real" 2>/dev/null | awk '{print $NF}' || echo "unknown"
    else
        echo "unknown"
    fi
}

# Collect all runtime binaries (only those that exist)
BINARIES=""
for bin in \
    /usr/sbin/nginx \
    /usr/sbin/nginx-debug \
    /usr/bin/nginx-agent \
    /usr/share/ts/bin/bd-socket-plugin \
    /opt/app_protect/bin/apcompile \
    /opt/app_protect/bin/config_set_apply \
    /opt/app_protect/bin/is_json_schema_valid \
    /opt/app_protect/bin/is_policy_valid \
    /opt/app_protect/bin/is_log_profile_valid \
    /opt/app_protect/bin/set_log_level \
    /opt/app_protect/bin/iprepd \
    /usr/bin/admd \
    /usr/bin/adminstall \
    /usr/bin/app_protect_dos_agent \
    /nginx-ingress; do
    if [ -f "$bin" ] && [ -x "$bin" ]; then
        BINARIES="$BINARIES $bin"
    fi
done

# Collect all NGINX modules
MODULES=""
for moddir in /etc/nginx/modules /usr/lib/nginx/modules /usr/lib64/nginx/modules /usr/share/nginx/modules; do
    if [ -d "$moddir" ]; then
        for mod in "$moddir"/*.so; do
            [ -f "$mod" ] && MODULES="$MODULES $mod"
        done
    fi
done

# Extra shared-object locations probed by some variants via LD_LIBRARY_PATH
WAF_LIBS=""
for extra_libdir in /usr/lib64/bd /opt/app_protect/lib /opt/app_protect/lib64; do
    [ -d "$extra_libdir" ] || continue
    for lib in "$extra_libdir"/*.so*; do
        [ -f "$lib" ] && WAF_LIBS="$WAF_LIBS $lib"
    done
done

# Perl XS modules (loaded by /usr/bin/perl on variants that fork an
# external perl interpreter from /opt/app_protect/bin/*).
PERL_XS=""
if [ -d /opt/app_protect/lib/perl ]; then
    for xs in $(find /opt/app_protect/lib/perl -path "*/auto/*.so" 2>/dev/null); do
        [ -f "$xs" ] && PERL_XS="$PERL_XS $xs"
    done
fi

# Standalone shared object that some variants load directly into nginx.
NAP_V5_SO=""
for so in /usr/lib/libsocketplugin.so /usr/lib64/libsocketplugin.so; do
    [ -f "$so" ] && NAP_V5_SO="$NAP_V5_SO $so"
done

echo "=== Runtime Binaries ==="
for bin in $BINARIES; do
    echo "  $bin"
done
echo ""

echo "=== NGINX Modules ==="
for mod in $MODULES; do
    echo "  $mod"
done
echo ""

echo "=== Extra LD_LIBRARY_PATH shared objects ==="
for lib in $WAF_LIBS; do
    echo "  $lib"
done
echo ""

echo "=== Perl XS modules (under /opt/app_protect/lib/perl) ==="
for xs in $PERL_XS; do
    echo "  $xs"
done
echo ""

echo "=== Standalone shared object (libsocketplugin) ==="
for so in $NAP_V5_SO; do
    echo "  $so"
done
echo ""

# Run ldd on all binaries and modules, collect unique .so paths
echo "=== Shared Library Dependencies ==="
ALL_LIBS_FILE=$(mktemp 2>/dev/null || echo /tmp/ldd-libs.txt)
: > "$ALL_LIBS_FILE"

trace_binary() {
    local bin="$1"
    local extra_env="$2"
    echo "--- $bin ---"
    if [ -n "$extra_env" ]; then
        env $extra_env ldd "$bin" 2>/dev/null || echo "  (ldd failed or static binary)"
    else
        ldd "$bin" 2>/dev/null || echo "  (ldd failed or static binary)"
    fi
    echo ""

    # Extract .so paths (tolerate static binaries / empty ldd output under set -e)
    if [ -n "$extra_env" ]; then
        env $extra_env ldd "$bin" 2>/dev/null | grep -o '/[^ ]*' >> "$ALL_LIBS_FILE" || true
    else
        ldd "$bin" 2>/dev/null | grep -o '/[^ ]*' >> "$ALL_LIBS_FILE" || true
    fi
}

for bin in $BINARIES; do
    if [ "$bin" = "/usr/share/ts/bin/bd-socket-plugin" ]; then
        trace_binary "$bin" "LD_LIBRARY_PATH=/usr/lib64/bd:/opt/app_protect/lib:/opt/app_protect/lib64"
    elif echo "$bin" | grep -q "^/opt/app_protect/bin/"; then
        trace_binary "$bin" "LD_LIBRARY_PATH=/opt/app_protect/lib:/opt/app_protect/lib64"
    else
        trace_binary "$bin" ""
    fi
done

for mod in $MODULES; do
    trace_binary "$mod" ""
done

for xs in $PERL_XS; do
    trace_binary "$xs" ""
done

for so in $NAP_V5_SO; do
    trace_binary "$so" ""
done

# Deduplicate and sort
echo "=== Unique Required Libraries ==="
sort -u "$ALL_LIBS_FILE" | while read -r lib; do
    [ -n "$lib" ] && echo "  $lib"
done
echo ""

# Map libraries to packages
echo "=== Required Packages ==="
sort -u "$ALL_LIBS_FILE" | while read -r lib; do
    if [ -n "$lib" ] && [ -f "$lib" ]; then
        pkg=$(pkg_owner "$lib")
        echo "  $lib -> $pkg"
    fi
done
echo ""

# Map the runtime binaries themselves to their owning packages.
# This gives evidence credit to packages that ship an executable but
# whose executable is not loaded by any other package's ldd graph
# (e.g. nginx-plus, nginx-agent, app-protect helpers).
echo "=== Runtime Binary Owners ==="
for bin in $BINARIES $MODULES $WAF_LIBS $PERL_XS $NAP_V5_SO; do
    if [ -f "$bin" ]; then
        pkg=$(pkg_owner "$bin")
        echo "  $bin -> $pkg"
    fi
done
echo ""

# Check for missing libraries
echo "=== Missing Libraries (CRITICAL) ==="
MISSING=0
for bin in $BINARIES; do
    if [ "$bin" = "/usr/share/ts/bin/bd-socket-plugin" ]; then
        result=$(env LD_LIBRARY_PATH=/usr/lib64/bd:/opt/app_protect/lib:/opt/app_protect/lib64 ldd "$bin" 2>/dev/null | grep "not found" || true)
    elif echo "$bin" | grep -q "^/opt/app_protect/bin/"; then
        result=$(env LD_LIBRARY_PATH=/opt/app_protect/lib:/opt/app_protect/lib64 ldd "$bin" 2>/dev/null | grep "not found" || true)
    else
        result=$(ldd "$bin" 2>/dev/null | grep "not found" || true)
    fi
    if [ -n "$result" ]; then
        echo "  $bin:"
        echo "$result" | sed 's/^/    /'
        MISSING=1
    fi
done

for mod in $MODULES $PERL_XS $NAP_V5_SO; do
    result=$(ldd "$mod" 2>/dev/null | grep "not found" || true)
    if [ -n "$result" ]; then
        echo "  $mod:"
        echo "$result" | sed 's/^/    /'
        MISSING=1
    fi
done

if [ "$MISSING" -eq 0 ]; then
    echo "  None — all dependencies satisfied"
fi
echo ""

# Dump Go module list embedded in static Go binaries shipped in this image.
# Confirms which Go modules are actually linked into each binary,
# independent of the host go.mod.
echo "=== Go Modules Embedded in Binaries ==="
for gobin in /usr/bin/nginx-agent /nginx-ingress \
             /opt/app_protect/bin/apcompile \
             /opt/app_protect/bin/config_set_apply; do
    if [ -f "$gobin" ] && [ -x "$gobin" ]; then
        echo "--- $gobin ---"
        if command -v go >/dev/null 2>&1; then
            go version -m "$gobin" 2>/dev/null || echo "  (go version -m failed)"
        else
            tr -c '[:print:]\n' '\n' < "$gobin" 2>/dev/null \
                | grep -E '^(dep|mod|=>)[[:space:]]+[^[:space:]]+/[^[:space:]]+[[:space:]]+v[0-9]' \
                | sort -u \
                || echo "  (no module info extracted)"
        fi
        echo ""
    fi
done
echo ""

# Summary of installed packages (for comparison with removal list)
echo "=== All Installed Packages ==="
if command -v dpkg >/dev/null 2>&1; then
    dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2}' | sort
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa --queryformat "%{NAME}\n" 2>/dev/null | sort
elif command -v apk >/dev/null 2>&1; then
    apk list --installed 2>/dev/null | awk '{print $1}' | sort
fi

rm -f "$ALL_LIBS_FILE" 2>/dev/null
echo ""
echo "=== Analysis Complete ==="
