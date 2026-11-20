#!/usr/bin/env bash
# Adds a new NGINX Ingress Controller version to an nkp-partner-catalog clone, using the
# latest version already in the catalog as the template. Used by the nkp-catalog-pr.yml
# workflow.
#
# Usage: .github/scripts/nkp-catalog-new-version.sh <nic-version> <chart-version>

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
CATALOG_DIR=${CATALOG_DIR:-$(dirname "${REPO_ROOT}")/nkp-partner-catalog}
APP_DIR=${CATALOG_DIR}/applications/nginx-ingress-controller

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

[ $# -eq 2 ] || die "usage: $(basename "$0") <nic-version> <chart-version>"
version=$1
chart_version=$2
semver='^[0-9]+\.[0-9]+\.[0-9]+$'
[[ ${version} =~ ${semver} ]] || die "invalid NIC version '${version}', expected X.Y.Z"
[[ ${chart_version} =~ ${semver} ]] || die "invalid chart version '${chart_version}', expected X.Y.Z"
[ -d "${APP_DIR}" ] || die "${APP_DIR} not found. Set CATALOG_DIR to your nkp-partner-catalog clone."

target=${APP_DIR}/${version}
[ ! -e "${target}" ] || die "${version} already exists in ${APP_DIR}"

template=$(find "${APP_DIR}" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort -V | tail -1)
[ -n "${template}" ] || die "no existing version in ${APP_DIR} to use as a template"

helmrelease=helmrelease/helmrelease.yaml
template_chart=$(perl -0ne 'print $1 if /\n\s*ref:\n\s*tag:\s*"?([^"\s]+)/' "${APP_DIR}/${template}/${helmrelease}")
[ -n "${template_chart}" ] || die "no OCIRepository ref.tag found in ${template}/${helmrelease}"

echo "Creating ${version} (chart ${chart_version}) from ${template} (chart ${template_chart})"
cp -R "${APP_DIR}/${template}" "${target}"

# shellcheck disable=SC2016 # $ENV{...} is expanded by perl, not the shell
find "${target}" -type f -exec env FROM="${template}" TO="${version}" perl -pi -e 's/\Q$ENV{FROM}\E/$ENV{TO}/g' {} +
FROM="${template_chart}" TO="${chart_version}" perl -0pi -e 's/(\n\s*ref:\n\s*tag:\s*"?)\Q$ENV{FROM}\E/$1$ENV{TO}/' "${target}/${helmrelease}"

# The chart tag is not tied to the NIC version, so a missed replacement would still deploy
# the new image, with the previous chart, and pass the e2e tests.
grep -rqF "${template}" "${target}" && die "${template} is still referenced in ${target}"
CHART="${chart_version}" perl -0ne 'exit(/\n\s*ref:\n\s*tag:\s*"?\Q$ENV{CHART}\E"?\n/ ? 0 : 1)' "${target}/${helmrelease}" ||
    die "chart tag in ${target}/${helmrelease} is not ${chart_version}"
grep -qF "tag: \"${version}\"" "${target}/helmrelease/cm.yaml" || die "image tag in ${target}/helmrelease/cm.yaml is not ${version}"

echo "Changes compared to ${template}:"
(cd "${APP_DIR}" && diff -r "${template}" "${version}" | grep -v '^[<>] .\{200,\}') || true
