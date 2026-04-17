#!/usr/bin/env bash

set -o pipefail

 usage() {
    echo "Usage: $0 <docs_folder> <new_ic_version> <new_helm_chart_version> <new_operator_version> [<waf_version>] [<waf_release_version>]"
    exit 1
 }

docs_folder=$1
new_ic_version=$2
new_helm_chart_version=$3
new_operator_version=$4
waf_version=$5
waf_release_version=$6

if [ -z "${docs_folder}" ]; then
    usage
fi

if [ -z "${new_ic_version}" ]; then
    usage
fi

if [ -z "${new_helm_chart_version}" ]; then
    usage
fi

if [ -z "${new_operator_version}" ]; then
    usage
fi

# update docs with new versions
echo -n "${new_ic_version}" > "${docs_folder}/layouts/shortcodes/nic-version.html"
echo -n "${new_helm_chart_version}" > "${docs_folder}/layouts/shortcodes/nic-helm-version.html"
echo -n "${new_operator_version}" > "${docs_folder}/layouts/shortcodes/nic-operator-version.html"

# Update appprotect-compiler-version shortcode from the NAP WAF package version.
# The package version format is "<plus_version>+<compiler_version>" (e.g. "36+5.607").
# The part after the + is the compiler/module version used in the docs NAP table.
if [ -n "${waf_version}" ]; then
    if [[ "${waf_version}" == *"+"* ]]; then
        compiler_version="${waf_version#*+}"
        echo -n "${compiler_version}" > "${docs_folder}/layouts/shortcodes/appprotect-compiler-version.html"
        echo "INFO: Updated appprotect-compiler-version shortcode: ${compiler_version} (from ${waf_version})"
    else
        echo "WARNING: waf_version '${waf_version}' does not contain '+', expected format '<plus_version>+<compiler_version>' (e.g. '36+5.607'). Skipping appprotect-compiler-version shortcode update."
    fi
fi

# Update nic-waf-release-version shortcode with the WAF container image version (e.g. 5.12.0).
# This version is shared by the compiler, config-mgr, and enforcer container images.
if [ -n "${waf_release_version}" ]; then
    echo -n "${waf_release_version}" > "${docs_folder}/layouts/shortcodes/nic-waf-release-version.html"
    echo "INFO: Updated nic-waf-release-version shortcode: ${waf_release_version}"
fi

echo "INFO: Updated shortcodes:"
echo "  NIC version: ${new_ic_version}"
echo "  Helm chart version: ${new_helm_chart_version}"
echo "  Operator version: ${new_operator_version}"
if [ -n "${waf_version}" ]; then
    if [[ "${waf_version}" == *"+"* ]]; then
        echo "  App Protect compiler version (from package): ${waf_version#*+}"
    fi
    echo "  App Protect WAF package version (for tables): ${waf_version}"
fi
if [ -n "${waf_release_version}" ]; then
    echo "  App Protect WAF release version (container images): ${waf_release_version}"
fi
