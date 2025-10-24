#!/usr/bin/env bash

set -o pipefail

 usage() {
    echo "Usage: $0 <docs_folder> <new_ic_version> <new_helm_chart_version> <new_operator_version> <waf_version> <waf_release_version>"
    echo ""
    echo "All arguments are required:"
    echo "  docs_folder: Path to documentation folder"
    echo "  new_ic_version: New NGINX Ingress Controller version"
    echo "  new_helm_chart_version: New Helm chart version"
    echo "  new_operator_version: New operator version"
    echo "  waf_version: NAP-WAF combined version (e.g., '35+5.527.0') - NGINX Plus + compiler version"
    echo "  waf_release_version: Not used (kept for compatibility)"
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

# If WAF arguments are empty, use current shortcode values (for minor/major releases without WAF updates)
if [ -z "${waf_version}" ]; then
    if [ -f "${docs_folder}/layouts/shortcodes/appprotect-compiler-version.html" ]; then
        waf_version=$(cat "${docs_folder}/layouts/shortcodes/appprotect-compiler-version.html")
        echo "INFO: Using current WAF version from appprotect-compiler-version shortcode: ${waf_version}"
    else
        echo "ERROR: WAF version not provided and appprotect-compiler-version shortcode not found"
        usage
    fi
fi

# For the combined format (waf_release_version is not used, waf_version should be like "35+5.527.0")
if [ -z "${waf_release_version}" ]; then
    echo "INFO: WAF release version not provided, using combined format in waf_version"
    waf_release_version=""
fi


# update docs with new versions
echo -n "${new_ic_version}" > ${docs_folder}/layouts/shortcodes/nic-version.html
echo -n "${new_helm_chart_version}" > ${docs_folder}/layouts/shortcodes/nic-helm-version.html
echo -n "${new_operator_version}" > ${docs_folder}/layouts/shortcodes/nic-operator-version.html

# update WAF shortcode (use existing appprotect-compiler-version.html)
# Extract only the compiler version part (after the +) for the shortcode
if [ -n "${waf_version}" ]; then
    if [[ "${waf_version}" == *"+"* ]]; then
        # Extract compiler version (part after +)
        compiler_version="${waf_version#*+}"
        echo -n "${compiler_version}" > ${docs_folder}/layouts/shortcodes/appprotect-compiler-version.html
        echo "INFO: Extracted compiler version for shortcode: ${compiler_version}"
    else
        # If no +, assume it's already just the compiler version
        echo -n "${waf_version}" > ${docs_folder}/layouts/shortcodes/appprotect-compiler-version.html
        echo "INFO: Using WAF version as compiler version: ${waf_version}"
    fi
fi

echo "INFO: Updated shortcodes:"
echo "  NIC version: ${new_ic_version}"
echo "  Helm chart version: ${new_helm_chart_version}"
echo "  Operator version: ${new_operator_version}"
if [[ "${waf_version}" == *"+"* ]]; then
    compiler_version="${waf_version#*+}"
    echo "  App Protect compiler version (shortcode): ${compiler_version}"
    echo "  App Protect full version (for tables): ${waf_version}"
else
    echo "  App Protect compiler version: ${waf_version}"
fi
