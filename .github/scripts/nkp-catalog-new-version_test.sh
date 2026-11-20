#!/usr/bin/env bash
#
# Unit tests for nkp-catalog-new-version.sh.
#
# Run directly: .github/scripts/nkp-catalog-new-version_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${SCRIPT_DIR}/nkp-catalog-new-version.sh"

pass=0
fail=0

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

# write_bundle <dir> <nic-version> <chart-version> writes a minimal catalog bundle with the
# same version references as the real one.
write_bundle() {
    local dir=$1 version=$2 chart=$3
    mkdir -p "${dir}/helmrelease"
    cat >"${dir}/helmrelease/helmrelease.yaml" <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: \${releaseName}-${version}-chart
spec:
  ref:
    tag: ${chart}
  url: oci://ghcr.io/nginx/charts/nginx-ingress
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
spec:
  chartRef:
    name: \${releaseName}-${version}-chart
  valuesFrom:
  - kind: ConfigMap
    name: \${releaseName}-${version}-config-defaults
EOF
    cat >"${dir}/helmrelease/cm.yaml" <<EOF
data:
  values.yaml: |
    controller:
      image:
        tag: "${version}"
metadata:
  name: \${releaseName}-${version}-config-defaults
EOF
    printf '#private-registry.nginx.com/nginx-ic/nginx-plus-ingress:%s\n' "${version}" >"${dir}/helmrelease/extra-images.txt"
    printf 'nkp create catalog-bundle --apps=nginx-ingress-controller=%s --airgapped\n' "${version}" >"${dir}/metadata.yaml"
}

# assert_new_version <want: pass|fail> <description> <nic-version> <chart-version>
# Runs the script on a catalog holding only 5.7.1 (chart 2.8.1). A passing run must produce
# exactly the bundle written for the new versions.
assert_new_version() {
    local want=$1 desc=$2 version=$3 chart=$4 catalog got
    catalog=$(mktemp -d "${TMP_DIR}/catalog.XXXXXX")
    write_bundle "${catalog}/applications/nginx-ingress-controller/5.7.1" 5.7.1 2.8.1

    if CATALOG_DIR="${catalog}" "${SCRIPT}" "${version}" "${chart}" >"${catalog}/out" 2>&1; then
        got=pass
        write_bundle "${catalog}/expected" "${version}" "${chart}"
        diff -r "${catalog}/expected" "${catalog}/applications/nginx-ingress-controller/${version}" >"${catalog}/out" ||
            got="pass with a wrong bundle"
    else
        got=fail
    fi

    if [[ "${got}" == "${want}" ]]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        echo "FAIL: ${desc} (want=${want}, got=${got})"
        sed 's/^/    /' "${catalog}/out"
    fi
}

assert_new_version pass "minor release" 5.8.0 2.9.0
assert_new_version pass "new version contains the template version" 5.7.10 2.8.10
assert_new_version fail "version already in the catalog" 5.7.1 2.8.1
assert_new_version fail "version is not X.Y.Z" 5.8 2.9.0

echo "Results: ${pass} passed, ${fail} failed."
[ "${fail}" -eq 0 ]
