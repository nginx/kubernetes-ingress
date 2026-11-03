# shellcheck shell=bash
#
# Shared helpers for release-version-update.sh and release-docs.sh.
#
# Source this file; it only defines functions and constants. Callers must set
# ROOTDIR (repo root) and DEBUG before calling the resolve_* functions.
#
# Version resolution (run from the release branch after the version-bump PR):
#   new versions      -> .github/data/version.txt          (override: NEW_IC_VERSION, NEW_HELM_VERSION)
#   release mode      -> detected from the new IC version  (override/cross-check: LTS=true|false)
#   previous versions -> nearest lower release tag          (override: PREVIOUS_IC_VERSION, PREVIOUS_HELM_VERSION)
#   current operator  -> latest nginx-ingress-helm-operator release (override: CURRENT_OPERATOR_VERSION)

LTS_VERSION_PATTERN='^[0-9]{4}-lts-r[0-9]+$'
MAINLINE_VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+$'
SEMVER_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+$'
K8S_VERSIONS_PATTERN='^[0-9]+\.[0-9]+ *- *[0-9]+\.[0-9]+$'
NGINX_PLUS_VERSION_PATTERN='^R[0-9]+(\.[0-9]+)+$'
NGINX_VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+( */ *R[0-9]+(\.[0-9]+)+)?$'
VERSION_FILE_PATH=".github/data/version.txt"
OPERATOR_REPO="nginx/nginx-ingress-helm-operator"

release_debug() {
    if [ "${DEBUG:-false}" != "false" ]; then
        echo "DEBUG: $*"
    fi
}

# validate_format <label> <value> <pattern> <example>
validate_format() {
    local label="$1" value="$2" pattern="$3" example="$4"
    if [[ ! "${value}" =~ ${pattern} ]]; then
        echo "ERROR: Invalid ${label}: '${value}'. Expected format like '${example}'. (Pattern: ${pattern})"
        exit 1
    fi
}

# normalize_release_date <date>
# Accepts "D Mon YYYY" or "D Month YYYY" and prints "D Mon YYYY".
# Prints an error to stderr and returns 1 on failure, so call it as:
#   release_date=$(normalize_release_date "${release_date}") || exit 1
normalize_release_date() {
    local input="$1" normalized
    if ! command -v python3 > /dev/null 2>&1; then
        echo "ERROR: python3 is required to parse the release date" >&2
        return 1
    fi
    normalized=$(python3 -c "
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
" "${input}" 2>/dev/null)

    if [ -z "${normalized}" ]; then
        echo "ERROR: Invalid release date '${input}'. Expected format like '16 Sep 2026' or '16 September 2026'" >&2
        return 1
    fi
    echo "${normalized}"
}

# read_version_value <KEY>  (version.txt content on stdin)
# Parses instead of sourcing so tag contents are never executed.
read_version_value() {
    sed -n "s/^$1=//p" | head -1 | tr -d '[:space:]'
}

# Sets: new_ic_version, new_helm_chart_version
resolve_new_versions() {
    local version_file="${ROOTDIR}/${VERSION_FILE_PATH}"

    if [ -n "${NEW_IC_VERSION:-}" ]; then
        new_ic_version="${NEW_IC_VERSION}"
    elif [ -f "${version_file}" ]; then
        new_ic_version=$(read_version_value IC_VERSION < "${version_file}")
    fi

    if [ -n "${NEW_HELM_VERSION:-}" ]; then
        new_helm_chart_version="${NEW_HELM_VERSION}"
    elif [ -f "${version_file}" ]; then
        new_helm_chart_version=$(read_version_value HELM_CHART_VERSION < "${version_file}")
    fi

    if [ -z "${new_ic_version}" ] || [ -z "${new_helm_chart_version}" ]; then
        echo "ERROR: could not read IC_VERSION/HELM_CHART_VERSION from ${version_file}"
        echo "       run from the release branch after the version bump, or set NEW_IC_VERSION and NEW_HELM_VERSION"
        exit 1
    fi

    release_debug "new versions: ic=${new_ic_version} helm=${new_helm_chart_version}"
}

# Detects LTS vs mainline from new_ic_version and cross-checks an explicit LTS
# env var in both directions. Exports LTS=true|false for child scripts.
resolve_lts_mode() {
    local detected
    if [[ "${new_ic_version}" =~ ${LTS_VERSION_PATTERN} ]]; then
        detected="true"
    elif [[ "${new_ic_version}" =~ ${MAINLINE_VERSION_PATTERN} ]]; then
        detected="false"
    else
        echo "ERROR: IC version '${new_ic_version}' is neither a mainline version (e.g. '5.7.0') nor an LTS version (e.g. '2026-lts-r9')"
        exit 1
    fi

    case "${LTS:-}" in
        "") ;;
        true | false)
            if [ "${LTS}" != "${detected}" ]; then
                if [ "${LTS}" == "true" ]; then
                    echo "ERROR: LTS=true but the IC version is '${new_ic_version}' (mainline). Are you on an LTS release branch?"
                else
                    echo "ERROR: LTS=false but the IC version is '${new_ic_version}' (LTS). Are you on a mainline release branch?"
                fi
                exit 1
            fi
            ;;
        *)
            echo "ERROR: LTS must be 'true', 'false' or unset, got '${LTS}'"
            exit 1
            ;;
    esac

    export LTS="${detected}"
    release_debug "release mode: LTS=${LTS}"
}

# find_previous_tag -> prints the highest release tag that sorts below the new version
find_previous_tag() {
    local prefix tag_pattern target
    if [ "${LTS}" == "true" ]; then
        prefix=""
        tag_pattern="${LTS_VERSION_PATTERN}"
    else
        prefix="v"
        tag_pattern='^v[0-9]+\.[0-9]+\.[0-9]+$'
    fi
    target="${prefix}${new_ic_version}"

    {
        git -C "${ROOTDIR}" tag -l | grep -E "${tag_pattern}"
        echo "${target}"
    } | sort -uV | awk -v n="${target}" '$0 == n { print p; exit } { p = $0 }'
}

# resolve_previous_versions [ic-only]
# Sets: previous_ic_version, previous_release_tag, previous_helm_chart_version (unless ic-only)
resolve_previous_versions() {
    local need_helm="true" prev_tag prefix=""
    if [ "${1:-}" == "ic-only" ]; then
        need_helm="false"
    fi
    if [ "${LTS}" != "true" ]; then
        prefix="v"
    fi

    if [ -n "${PREVIOUS_IC_VERSION:-}" ]; then
        previous_ic_version="${PREVIOUS_IC_VERSION}"
        prev_tag="${prefix}${previous_ic_version}"
    else
        prev_tag=$(find_previous_tag)
        if [ -z "${prev_tag}" ]; then
            echo "ERROR: no release tag found below '${new_ic_version}'"
            echo "       run 'git fetch --tags', or set PREVIOUS_IC_VERSION and PREVIOUS_HELM_VERSION"
            exit 1
        fi
        previous_ic_version="${prev_tag#"${prefix}"}"
    fi

    if [ "${need_helm}" == "true" ]; then
        if [ -n "${PREVIOUS_HELM_VERSION:-}" ]; then
            previous_helm_chart_version="${PREVIOUS_HELM_VERSION}"
        else
            previous_helm_chart_version=$(git -C "${ROOTDIR}" show "${prev_tag}:${VERSION_FILE_PATH}" 2>/dev/null | read_version_value HELM_CHART_VERSION)
            if [ -z "${previous_helm_chart_version}" ]; then
                echo "ERROR: could not read HELM_CHART_VERSION from tag '${prev_tag}'"
                echo "       run 'git fetch --tags', or set PREVIOUS_HELM_VERSION"
                exit 1
            fi
        fi
    fi

    if [ "${previous_ic_version}" == "${new_ic_version}" ]; then
        echo "ERROR: previous IC version equals the new version (${new_ic_version}); nothing to release"
        exit 1
    fi

    previous_release_tag="${prev_tag}"
    release_debug "previous versions (tag ${prev_tag}): ic=${previous_ic_version} helm=${previous_helm_chart_version:-n/a}"
}

# previous_tech_specs_json <output_file>
# Writes tech-specs.json as it was at previous_release_tag, so rows frozen for
# that release record what it shipped rather than what main has moved on to.
# Prints the file path on success; prints nothing (and warns) if unavailable.
previous_tech_specs_json() {
    local out="$1"
    if [ -z "${previous_release_tag:-}" ]; then
        return 0
    fi
    if git -C "${ROOTDIR}" show "${previous_release_tag}:.github/scripts/tech-specs.json" > "${out}" 2>/dev/null; then
        release_debug "previous tech-specs.json extracted from ${previous_release_tag} to ${out}"
        echo "${out}"
    else
        rm -f "${out}"
        echo "WARNING: tag '${previous_release_tag}' has no .github/scripts/tech-specs.json; frozen rows will use current values" >&2
    fi
}

# Sets: current_operator_version (mainline only)
resolve_current_operator() {
    if [ -n "${CURRENT_OPERATOR_VERSION:-}" ]; then
        current_operator_version="${CURRENT_OPERATOR_VERSION}"
    else
        local auth=()
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
        fi
        current_operator_version=$(curl -fsSL "${auth[@]}" "https://api.github.com/repos/${OPERATOR_REPO}/releases/latest" | jq -r '.tag_name')
        current_operator_version="${current_operator_version#v}"
        if [ -z "${current_operator_version}" ] || [ "${current_operator_version}" == "null" ]; then
            echo "ERROR: failed to fetch the current operator version from ${OPERATOR_REPO}"
            echo "       set CURRENT_OPERATOR_VERSION to skip the lookup"
            exit 1
        fi
    fi

    release_debug "current operator version: ${current_operator_version}"
}
