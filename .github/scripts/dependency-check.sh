#!/usr/bin/env bash

# Local convenience wrapper around check-packages.py.
#
# Verifies that the NGINX packages build/Dockerfile pins, and the container
# images the Helm chart deploys, are actually published -- packages for every OS
# and architecture NIC builds, images for every required platform. Declared
# versions are read from build/Dockerfile and the chart, never from this script.
#
# Plus, NAP WAF and NAP DoS repositories are behind mTLS. OSS and nginx-agent
# (packages.nginx.org) are not. Without certs the Plus/NAP checks report ERROR
# rather than silently skipping.
#
# ENVIRONMENT
#   CERT          Client certificate path. Default: nginx-repo.crt
#   KEY           Client key path.         Default: nginx-repo.key
#   NO_COLOR      Set to any value to disable colour. See https://no-color.org
#   FORCE_COLOR   Set to any value to force colour even when piped.
#   CI            When set, colour is disabled automatically.
#
# ARGUMENTS
#   All arguments are passed straight through to check-packages.py. Because
#   they are appended after --cert/--key, an explicit --cert or --key on the
#   command line overrides the CERT/KEY environment variables.
#
#   --config PATH        Dependency config.
#                        Default: .github/data/dependency-check.ini
#   --dockerfile PATH    Dockerfile to read declared versions (ARG lines) and
#                        build OSes (FROM alpine:, FROM debian:, centos/N) from.
#                        Default: build/Dockerfile
#   --chart-values PATH  Chart values file to read image tags from.
#                        Default: charts/nginx-ingress/values.yaml
#   --chart-yaml PATH    Chart.yaml to read appVersion from, used when an image
#                        tag is commented out in values.yaml.
#                        Default: charts/nginx-ingress/Chart.yaml
#   --repo-root PATH     Root used to resolve yaml-image paths.
#                        Default: inferred from this script's location
#   --cert PATH          Client certificate. Default: nginx-repo.crt
#   --key PATH           Client key. Default: nginx-repo.key
#   --host <name>=<host> Override the repository host. <name> is either a config
#                        section (a single package) or a group (all packages in
#                        it). Repeatable. Unknown names are rejected.
#                        Precedence, independent of command-line order:
#                          section > group > --staging/--all-hosts > config
#                        Groups: oss  agent  plus  nap-waf  nap-signatures
#                                nap-dos  chart-images
#   --group <list>       Comma-separated groups to check, e.g. oss,nap-waf.
#                        Default: all. Restricts the whole report, not just the
#                        matrices, so the exit code reflects only those groups.
#   --staging            Check the staging locations release candidates land in,
#                        and that releases are cut from. Paths are unchanged;
#                        only the host moves:
#                          packages -> pkgs-test.nginx.com
#                          images   -> private-registry-test.nginx.com
#                        Certs are REQUIRED for every package here, including
#                        nginx and nginx-agent, which need none against the
#                        public packages.nginx.org. The staging registry also
#                        needs a certificate authorised for it -- the package
#                        cert may authenticate to /v2/ and still get 403 per
#                        repository.
#                        Override per dependency with the `staging` key in
#                        .github/data/dependency-check.ini.
#   --all-hosts HOST     Check every package against an arbitrary host, for any
#                        other mirror. Mutually exclusive with --staging. Never
#                        applies to container images -- a package mirror is not
#                        a registry.
#   --strict             Also fail when a newer version is available, not just
#                        when one is missing or incomplete. Off by default, so
#                        deliberately holding a version back does not block.
#   --jwt PATH           NGINX subscription JWT for the private registries
#                        (default: nginx-repo.jwt). Sent as HTTP Basic with the
#                        token as the username and the literal string 'any' as
#                        the password -- the scheme `docker login
#                        private-registry.nginx.com` uses. Required for
#                        --staging, where the client certificate does not work.
#                        Never sent to Docker Hub. Download it from MyF5.
#   --deps               Also list what our packages themselves depend on, read
#                        from the native metadata (Packages / APKINDEX.tar.gz /
#                        primary.xml) -- index.xml carries no dependency data.
#                        Prints a per-package list plus a deduplicated distinct
#                        set per build target, with which packages require each.
#                        Purely informational: never affects the exit code.
#                        Identifiers are verbatim per distro and NOT comparable
#                        across them -- the same library is a package name on
#                        Debian (libssl3t64), a soname on Alpine
#                        (so:libssl.so.3) and a soname on CentOS/UBI
#                        (libssl.so.3). Only version constraints are stripped
#                        when deduplicating.
#                        Debian Recommends/Suggests are excluded, matching the
#                        images' --no-install-recommends --no-install-suggests.
#   --deps-arch ARCH     x86 (default) | arm. Affects --deps only. Dependencies
#                        are arch-specific because sonames are.
#   --matrix             Also print the full per-group OS matrices. Availability
#                        for the OSes NIC builds on is already a column in the
#                        results table; the matrices additionally cover every
#                        distro the repositories carry (ubuntu, sles, amzn,
#                        older alpine), which is planning information rather
#                        than release gating. Adds ~135 lines.
#   --os <list>          Comma-separated distros to show in the matrix, e.g.
#                        alpine,debian. Default: all distros found. Affects
#                        --matrix only, and never the verdict.
#   --index-dir PATH     Read index XML from this directory instead of fetching,
#                        for offline debugging. Filenames derive from the uri,
#                        not the section, since many packages share a repo:
#                          /nginx/mainline               nginx-mainline.xml
#                          /nginx-agent                  nginx-agent.xml
#                          /plus                         plus.xml
#                          /app-protect                  app-protect.xml
#                          /app-protect-x-plus           app-protect-x-plus.xml
#                          /app-protect-security-updates app-protect-security-updates.xml
#                          /app-protect-dos              app-protect-dos.xml
#                        Container images have no offline form and are reported
#                        as skipped when this is used.
#   --color MODE         auto (default) | always | never.
#                        auto emits colour only to a terminal: disabled when
#                        CI or NO_COLOR is set, when TERM=dumb, or when stdout
#                        is piped or redirected. Status values, build-target
#                        availability and the verdict are coloured; column
#                        alignment is identical either way.
#   -h, --help           Full help from check-packages.py.
#
# EXIT CODES
#   0  All declared versions published for every required OS/arch. A newer
#      version being available warns but still exits 0 without --strict.
#   1  At least one MISSING, INCOMPLETE or ERROR dependency, or a STALE one
#      when --strict is set.
#   2  Could not run the check at all -- bad config, unreadable Dockerfile,
#      unknown --host name.
#
# EXAMPLES
#   ./.github/scripts/dependency-check.sh
#   CERT=~/certs/nginx-repo.crt KEY=~/certs/nginx-repo.key \
#       ./.github/scripts/dependency-check.sh
#   # Pre-release: everything against staging.
#   ./.github/scripts/dependency-check.sh --staging
#   # Staging for all but one group.
#   ./.github/scripts/dependency-check.sh --staging --host oss=packages.nginx.org
#   # Just the NAP packages.
#   ./.github/scripts/dependency-check.sh --group nap-waf,nap-signatures,nap-dos
#   # Just the Helm chart container images.
#   ./.github/scripts/dependency-check.sh --group chart-images
#   # Inventory of our dependencies' own dependencies.
#   ./.github/scripts/dependency-check.sh --deps
#   ./.github/scripts/dependency-check.sh --deps --deps-arch arm --group oss
#   # Add the full distro matrices, narrowed to two distros.
#   ./.github/scripts/dependency-check.sh --matrix --os alpine,debian
#   ./.github/scripts/dependency-check.sh --strict
#   ./.github/scripts/dependency-check.sh --index-dir /tmp/indexes
#   # Keep colour when paging or piping.
#   ./.github/scripts/dependency-check.sh --color always | less -R
#   NO_COLOR=1 ./.github/scripts/dependency-check.sh
#   ./.github/scripts/dependency-check.sh --dockerfile /tmp/Dockerfile.candidate

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CERT="${CERT:-nginx-repo.crt}"
KEY="${KEY:-nginx-repo.key}"

PYTHON_BIN="python3"
if ! command -v python3 &>/dev/null; then
    if [ -x "/usr/bin/python3" ]; then
        PYTHON_BIN="/usr/bin/python3"
    else
        echo "Error: python3 is required to run check-packages.py." >&2
        exit 1
    fi
fi

exec "$PYTHON_BIN" "${SCRIPT_DIR}/check-packages.py" --cert "$CERT" --key "$KEY" "$@"
