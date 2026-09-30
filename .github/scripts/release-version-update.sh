#!/usr/bin/env bash

set -o pipefail

ROOTDIR=$(git rev-parse --show-toplevel || echo ".")
TMPDIR=/tmp
HELM_CHART_PATH="${ROOTDIR}/charts/nginx-ingress"
DEPLOYMENT_PATH="${ROOTDIR}/deployments"
EXAMPLES_PATH="${ROOTDIR}/examples"
DEBUG=${DEBUG:-"false"}

LTS=${LTS:-"false"}

FILES_TO_UPDATE_IC_VERSION=(
    "${ROOTDIR}/.github/data/version.txt"
    "${ROOTDIR}/README.md"
    "${DEPLOYMENT_PATH}/daemon-set/nginx-ingress.yaml"
    "${DEPLOYMENT_PATH}/daemon-set/nginx-plus-ingress.yaml"
    "${DEPLOYMENT_PATH}/deployment/nginx-ingress.yaml"
    "${DEPLOYMENT_PATH}/deployment/nginx-plus-ingress.yaml"
    "${DEPLOYMENT_PATH}/stateful-set/nginx-ingress.yaml"
    "${DEPLOYMENT_PATH}/stateful-set/nginx-plus-ingress.yaml"
    "${HELM_CHART_PATH}/Chart.yaml"
    "${HELM_CHART_PATH}/values-icp.yaml"
    "${HELM_CHART_PATH}/values-plus.yaml"
    "${HELM_CHART_PATH}/values.yaml"
)
FILE_TO_UPDATE_HELM_CHART_VERSION=(
    "${ROOTDIR}/.github/data/version.txt"
    "${HELM_CHART_PATH}/Chart.yaml"
)

 usage() {
    if [ "${LTS}" != "false" ]; then
        echo "Usage: LTS=true $0 <new_ic_version> <new_helm_chart_version>"
    else
        echo "Usage: $0 <new_ic_version> <new_helm_chart_version> <new_operator_version>"
    fi

    exit 1
}

validate_format() {
    local label="$1" value="$2" pattern="$3" example="$4"
    if [[ ! "${value}" =~ ${pattern} ]]; then
        echo "ERROR: Invalid ${label}: '${value}'. Expected format like '${example}'. (Pattern: ${pattern})"
        exit 1
    fi
}

if [ "${LTS}" != "false" ]; then
    if [ $# -eq 2 ]; then
        source "${ROOTDIR}/.github/data/version.txt"
        current_ic_version="${IC_VERSION}"
        current_helm_chart_version="${HELM_CHART_VERSION}"
        new_ic_version=$1
        new_helm_chart_version=$2
    elif [ $# -eq 4 ]; then
        current_ic_version=$1
        current_helm_chart_version=$2
        new_ic_version=$3
        new_helm_chart_version=$4
    else
        usage
    fi
    current_operator_version=""
    new_operator_version=""
else
    if [ $# -eq 3 ]; then
        source "${ROOTDIR}/.github/data/version.txt"
        current_ic_version="${IC_VERSION}"
        current_helm_chart_version="${HELM_CHART_VERSION}"
        # Fetch current operator version from latest release
        current_operator_version=$(curl -s "https://api.github.com/repos/nginx/nginx-ingress-helm-operator/releases/latest" | jq -r '.tag_name')
        current_operator_version="${current_operator_version#v}"
        if [ -z "${current_operator_version}" ] || [ "${current_operator_version}" == "null" ]; then
            echo "ERROR: Failed to fetch current operator version from GitHub API"
            exit 1
        fi
        new_ic_version=$1
        new_helm_chart_version=$2
        new_operator_version=$3
    elif [ $# -eq 6 ]; then
        current_ic_version=$1
        current_helm_chart_version=$2
        current_operator_version=$3
        new_ic_version=$4
        new_helm_chart_version=$5
        new_operator_version=$6
    else
        usage
    fi

fi

if [ -z "${current_ic_version}" ]; then
    usage
fi

if [ -z "${current_helm_chart_version}" ]; then
    usage
fi

if [ -z "${new_ic_version}" ]; then
    usage
fi

if [ -z "${new_helm_chart_version}" ]; then
    usage
fi

if [ "${LTS}" == "false" ]; then
    if [ -z "${current_operator_version}" ]; then
        usage
    fi

    if [ -z "${new_operator_version}" ]; then
        usage
    fi
fi

if [ "${LTS}" != "false" ]; then
    validate_format "LTS version" "${new_ic_version}" '^[0-9]{4}-lts-r[0-9]+$' "2026-lts-r8"
    validate_format "Current LTS version" "${current_ic_version}" '^[0-9]{4}-lts-r[0-9]+$' "2026-lts-r7"
else
    validate_format "NIC version" "${new_ic_version}" '^[0-9]+\.[0-9]+\.[0-9]+$' "5.7.0"
    validate_format "Current NIC version" "${current_ic_version}" '^[0-9]+\.[0-9]+\.[0-9]+$' "5.6.0"
    validate_format "Operator version" "${new_operator_version}" '^[0-9]+\.[0-9]+\.[0-9]+$' "3.8.0"
    validate_format "Current Operator version" "${current_operator_version}" '^[0-9]+\.[0-9]+\.[0-9]+$' "3.7.0"
fi
validate_format "Helm version" "${new_helm_chart_version}" '^[0-9]+\.[0-9]+\.[0-9]+$' "2.7.3 or 2026.0.6"
validate_format "Current Helm version" "${current_helm_chart_version}" '^[0-9]+\.[0-9]+\.[0-9]+$' "2.7.2 or 2026.0.5"


escaped_current_ic_version=$(printf '%s' "$current_ic_version" | sed -e 's/\./\\./g');
escaped_current_helm_chart_version=$(printf '%s' "$current_helm_chart_version" | sed -e 's/\./\\./g');

echo "Updating versions: "
echo "ic_version: ${current_ic_version} -> ${new_ic_version}"
echo "helm_chart_version: ${current_helm_chart_version} -> ${new_helm_chart_version}"
echo "operator_version: ${current_operator_version} -> ${new_operator_version}"

regex_ic="s#$escaped_current_ic_version#$new_ic_version#g"
regex_helm="s#$escaped_current_helm_chart_version#$new_helm_chart_version#g"

if [ "${LTS}" == "false" ]; then
    escaped_current_operator_version=$(printf '%s' "$current_operator_version" | sed -e 's/\./\\./g');
    echo "operator_version: ${current_operator_version} -> ${new_operator_version}"
    regex_operator="s#$escaped_current_operator_version#$new_operator_version#g"
else
    echo "operator_version: skipped (LTS release has no operator)"
    # An empty sed expression is a no-op, so the examples pipeline below stays
    # identical in both modes.
    regex_operator=""
fi

mv "${HELM_CHART_PATH}/values.schema.json" "${TMPDIR}/"
jq --arg version "${new_ic_version}" \
    '.properties.controller.properties.image.properties.tag.default = $version | .properties.controller.properties.image.properties.tag.examples[0] = $version | .properties.controller.examples[0].image.tag = $version | .properties.controller.properties.image.examples[0].tag = $version | .examples[0].controller.image.tag = $version' \
    "${TMPDIR}/values.schema.json" \
    > "${HELM_CHART_PATH}/values.schema.json"
rc=$?
if [ $rc -ne 0 ]; then
    echo "ERROR: failed updating ic_version in values.schema.json"
    mv "${TMPDIR}/values.schema.json" "${HELM_CHART_PATH}/values.schema.json"
    exit 2
fi

# update helm chart & deployment files with IC version
for i in "${FILES_TO_UPDATE_IC_VERSION[@]}"; do
    if [ "${DEBUG}" != "false" ]; then
        echo "Processing ${i}"
    fi
    file_name=$(basename "${i}")
    mv "${i}" "${TMPDIR}/${file_name}"
    cat "${TMPDIR}/${file_name}" | sed -e "$regex_ic" > "${i}"
    if [ $? -ne 0 ]; then
        echo "ERROR: failed processing ${i}"
        mv "${TMPDIR}/${file_name}" "${i}"
        exit 2
    fi
done

# update helm chart files with helm chart version
for i in "${FILE_TO_UPDATE_HELM_CHART_VERSION[@]}"; do
    if [ "${DEBUG}" != "false" ]; then
        echo "Processing ${i}"
    fi
    file_name=$(basename "${i}")
    mv "${i}" "${TMPDIR}/${file_name}"
    cat "${TMPDIR}/${file_name}" | sed -e "$regex_helm" > "${i}"
    if [ $? -ne 0 ]; then
        echo "ERROR: failed processing ${i}"
        mv "${TMPDIR}/${file_name}" "${i}"
        exit 2
    fi
done

# update examples with new versions
example_files=$(find "${EXAMPLES_PATH}" -type f -name "*.md")
for i in ${example_files}; do
    if [ "${DEBUG}" != "false" ]; then
        echo "Processing ${i}"
    fi
    file_name=$(basename "${i}")
    mv "${i}" "${TMPDIR}/${file_name}"
    cat "${TMPDIR}/${file_name}" | sed -e "$regex_ic" | sed -e "$regex_helm" | sed -e "$regex_operator" > "${i}"
    if [ $? -ne 0 ]; then
        echo "ERROR: failed processing ${i}"
        mv "${TMPDIR}/${file_name}" "${i}"
        exit 2
    fi
done

# insert new IC version into bug report template immediately after the "- edge" entry
bug_report="${ROOTDIR}/.github/ISSUE_TEMPLATE/BUG-REPORT.yml"
if [ "${LTS}" == "false" ] && [ -f "${bug_report}" ]; then
    if [ "${DEBUG}" != "false" ]; then
        echo "Processing ${bug_report}"
    fi
    # Only insert the new version if it is not already listed
    if ! grep -q "^        - ${new_ic_version}\$" "${bug_report}"; then
        file_name=$(basename "${bug_report}")
        mv "${bug_report}" "${TMPDIR}/${file_name}"
        sed -e "/^        - edge$/a\\        - ${new_ic_version}" "${TMPDIR}/${file_name}" > "${bug_report}"
        if [ $? -ne 0 ]; then
            echo "ERROR: failed processing ${bug_report}"
            mv "${TMPDIR}/${file_name}" "${bug_report}"
            exit 2
        fi
    fi
fi

UPDATE_TECH_SPECS=${UPDATE_TECH_SPECS:-"true"}
TECH_SPECS_JSON=${TECH_SPECS_JSON:-"${ROOTDIR}/.github/scripts/tech-specs.json"}
K8S_VERSIONS=${K8S_VERSIONS:-""}
NGINX_VERSION=${NGINX_VERSION:-""}
RELEASE_DATE=${RELEASE_DATE:-""}
NAP_WAF_VERSION=${NAP_WAF_VERSION:-""}
NAP_WAF_RELEASE_VERSION=${NAP_WAF_RELEASE_VERSION:-""}

if [ "${UPDATE_TECH_SPECS}" != "false" ]; then
    if [ -z "${K8S_VERSIONS}" ] || [ -z "${NGINX_VERSION}" ]; then
        echo "ERROR: UPDATE_TECH_SPECS is enabled but K8S_VERSIONS and/or NGINX_VERSION is unset"
        echo "       set both, or pass UPDATE_TECH_SPECS=false to skip the tech-specs refresh"
        exit 2
    fi

    validate_format "K8s versions" "${K8S_VERSIONS}" '^[0-9]+\.[0-9]+ *- *[0-9]+\.[0-9]+$' "1.30 - 1.37"
    if [ "${LTS}" != "false" ]; then
        validate_format "NGINX Plus version" "${NGINX_VERSION}" '^R[0-9]+(\.[0-9]+)+$' "R37.0.1.1"
    else
        validate_format "NGINX version" "${NGINX_VERSION}" '^[0-9]+\.[0-9]+\.[0-9]+( */ *R[0-9]+(\.[0-9]+)+)?$' "1.31.6 / R37.1.1.2"
    fi

    echo "Updating $(basename "${TECH_SPECS_JSON}"): ${current_ic_version} -> ${new_ic_version}"

    # Built as an array so every value stays individually quoted -- this replaces
    # the fragile "${{ x && format('--flag \"{0}\"', x) || '' }}" YAML pattern.
    tech_specs_args=(
        --json-file "${TECH_SPECS_JSON}"
        --json-only
        --update-json
        --current-nic-version "${current_ic_version}"
        --current-helm-version "${current_helm_chart_version}"
    )

    if [ "${LTS}" != "false" ]; then
        if [ -n "${RELEASE_DATE}" ]; then
            normalized_date=$(python3 -c "
            import sys
            from datetime import datetime
            for fmt in ('%d %b %Y', '%d %B %Y'):
                try:
                    d = datetime.strptime(sys.argv[1], fmt)
                    print(d.strftime('%-d %b %Y'))
                    sys.exit(0)
                except ValueError:
                    continue
            sys.exit(1)
            " "${RELEASE_DATE}" 2>/dev/null)

            if [ -z "${normalized_date}" ]; then
                echo "ERROR: Invalid release date '${RELEASE_DATE}'. Expected format like '16 Sept 2026' or '16 September 2026'"
                exit 1
            fi

            RELEASE_DATE="${normalized_date}"
        fi
        tech_specs_args+=(--lts)
        tech_specs_args+=(--lts-helm-version "${new_helm_chart_version}")
        tech_specs_args+=(--nginx-plus-version "${NGINX_VERSION}")
        tech_specs_args+=(--lts-release-date "${RELEASE_DATE}")
    else
        tech_specs_args+=(--current-operator-version "${current_operator_version}")
        if [ -n "${NAP_WAF_RELEASE_VERSION}" ]; then
            tech_specs_args+=(--nap-waf-release-version "${NAP_WAF_RELEASE_VERSION}")
        fi
    fi

    if [ "${DEBUG}" != "false" ]; then
        tech_specs_args+=(--verbose)
    fi

    # Positional: ic_version k8s_versions nginx_version docs_root [nap_waf_version]
    # docs_root is deliberately empty: --json-only never touches the docs repo.
    tech_specs_args+=("${new_ic_version}" "${K8S_VERSIONS}" "${NGINX_VERSION}" "")

    if [ "${LTS}" == "false" ] && [ -n "${NAP_WAF_VERSION}" ]; then
        tech_specs_args+=("${NAP_WAF_VERSION}")
    fi

    if ! python3 "${ROOTDIR}/.github/scripts/tech-specs-update.py" "${tech_specs_args[@]}"; then
        echo "ERROR: failed updating ${TECH_SPECS_JSON}"
        exit 2
    fi
fi

make test-update-snaps
