#!/usr/bin/env bash

set -o pipefail

 usage() {
    echo "Usage: $0 <docs_folder> <new_ic_version> <new_helm_chart_version> <new_operator_version>"
    exit 1
 }

docs_folder=$1
new_ic_version=$2
new_helm_chart_version=$3
new_operator_version=$4

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
echo -n "${new_ic_version}" > ${docs_folder}/layouts/shortcodes/nic-version.html
echo -n "${new_helm_chart_version}" > ${docs_folder}/layouts/shortcodes/nic-helm-version.html
echo -n "${new_operator_version}" > ${docs_folder}/layouts/shortcodes/nic-operator-version.html
