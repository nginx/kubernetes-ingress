#!/usr/bin/env bash

set -o pipefail

ROOTDIR=$(git rev-parse --show-toplevel || echo ".")
TMPDIR=/tmp
DEBUG=${DEBUG:-"false"}
DRY_RUN=${DRY_RUN:-"false"}
TIDY=${TIDY:-"true"}
DOCS_REPO=${DOCS_REPO:-"nginx/documentation"}
GITHUB_USERNAME=${GITHUB_USERNAME:-""}
GITHUB_EMAIL=${GITHUB_EMAIL:-""}
NEW_RELEASE_BRANCH=${NEW_RELEASE_BRANCH:-"nic-release-next"}
PATCH_RELEASE_BRANCH=${PATCH_RELEASE_BRANCH:-"nic-patch-next"}
export GH_TOKEN=${GITHUB_TOKEN:-""}
DOCS_FOLDER=${TMPDIR}/documentation

# shellcheck source=release-common.sh
source "${ROOTDIR}/.github/scripts/release-common.sh"

usage() {
    echo "Run from the release branch after the version-bump PR has merged."
    echo ""
    echo "Usage (mainline): $0 <operator_version> <k8s_versions> <nginx_version> <release_date> [<nap_waf_version> <nap_waf_release_version>]"
    echo "Usage (LTS):      $0 <k8s_versions> <nginx_plus_version> <release_date>"
    echo ""
    echo "Required env: GITHUB_TOKEN"
    echo ""
    echo "Optional overrides:"
    echo "  LTS=true|false                      cross-checked against version.txt"
    echo "  NEW_IC_VERSION, NEW_HELM_VERSION    default: .github/data/version.txt"
    echo "  PREVIOUS_IC_VERSION                 default: nearest lower release tag"
    exit 1
}

if [ "${1:-}" == "-h" ] || [ "${1:-}" == "--help" ]; then
    usage
fi

# ---- Resolve versions ----
resolve_new_versions
resolve_lts_mode
resolve_previous_versions ic-only
ic_version="${new_ic_version}"
helm_chart_version="${new_helm_chart_version}"
previous_version="${previous_ic_version}"

if [ "${LTS}" == "true" ]; then
    CHANGELOG_DIR=${CHANGELOG_DIR:-"content/nic/lts"}
    if [ $# -ne 3 ]; then
        usage
    fi
    k8s_versions=$1
    nginx_version=$2
    release_date=$3
    operator_version=""
    NAP_WAF_VERSION=""
    NAP_WAF_RELEASE_VERSION=""
else
    CHANGELOG_DIR=${CHANGELOG_DIR:-"content/nic/changelog"}
    # NAP versions are both-or-neither, so only 4 or 6 args are valid
    if [ $# -ne 4 ] && [ $# -ne 6 ]; then
        usage
    fi
    operator_version=$1
    k8s_versions=$2
    nginx_version=$3
    release_date=$4
    NAP_WAF_VERSION=${5:-}
    NAP_WAF_RELEASE_VERSION=${6:-}
fi

for required in k8s_versions nginx_version release_date; do
    if [ -z "${!required}" ]; then
        echo "ERROR: ${required} is required"
        usage
    fi
done
if [ "${LTS}" == "false" ] && [ -z "${operator_version}" ]; then
    echo "ERROR: operator_version is required"
    usage
fi
if { [ -n "${NAP_WAF_VERSION}" ] && [ -z "${NAP_WAF_RELEASE_VERSION}" ]; } || { [ -z "${NAP_WAF_VERSION}" ] && [ -n "${NAP_WAF_RELEASE_VERSION}" ]; }; then
    echo "ERROR: nap_waf_version and nap_waf_release_version must both be set or both be empty"
    usage
fi

if [ -n "${NAP_WAF_VERSION}" ]; then
    echo "INFO: NAP WAF version provided: ${NAP_WAF_VERSION}"
fi

# ---- Validate ----
if [ "${LTS}" == "true" ]; then
    validate_format "LTS version" "${ic_version}" "${LTS_VERSION_PATTERN}" "2026-lts-r9"
    validate_format "previous LTS version" "${previous_version}" "${LTS_VERSION_PATTERN}" "2026-lts-r8"
    validate_format "NGINX Plus version" "${nginx_version}" "${NGINX_PLUS_VERSION_PATTERN}" "R37.0.6.3"
else
    validate_format "NIC version" "${ic_version}" "${MAINLINE_VERSION_PATTERN}" "5.6.4"
    validate_format "previous NIC version" "${previous_version}" "${MAINLINE_VERSION_PATTERN}" "5.6.3"
    validate_format "operator version" "${operator_version}" "${SEMVER_PATTERN}" "3.7.4"
    validate_format "NGINX version" "${nginx_version}" "${NGINX_VERSION_PATTERN}" "1.31.6 / R37.1.1.2"
fi
validate_format "Helm version" "${helm_chart_version}" "${SEMVER_PATTERN}" "2.7.3 or 2026.0.6"
validate_format "K8s versions" "${k8s_versions}" "${K8S_VERSIONS_PATTERN}" "1.30 - 1.37"

release_date=$(normalize_release_date "${release_date}") || exit 1

if [ -z "${GH_TOKEN}" ]; then
    echo "ERROR: GITHUB_TOKEN is not set"
    exit 2
fi

echo "INFO: Setting git credentials"
if [ -n "${GITHUB_USERNAME}" ]; then
    git config --global user.name "${GITHUB_USERNAME}"
fi

if [ -n "${GITHUB_EMAIL}" ]; then
    git config --global user.email "${GITHUB_EMAIL}"
fi

if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: DRY_RUN: ${DRY_RUN}"
    echo "DEBUG: TIDY: ${TIDY}"
    echo "DEBUG: DOCS_REPO: ${DOCS_REPO}"
    echo "DEBUG: GITHUB_USERNAME: ${GITHUB_USERNAME}"
    echo "DEBUG: GITHUB_EMAIL: ${GITHUB_EMAIL}"
    echo "DEBUG: NEW_RELEASE_BRANCH: ${NEW_RELEASE_BRANCH}"
    echo "DEBUG: PATCH_RELEASE_BRANCH: ${PATCH_RELEASE_BRANCH}"
    echo "DEBUG: GH_TOKEN: ****$(echo -n $GH_TOKEN | tail -c 4)"
    echo "DEBUG: DOCS_FOLDER: ${DOCS_FOLDER}"
    echo "DEBUG: ic_version: ${ic_version}"
    echo "DEBUG: previous_version: ${previous_version}"
    echo "DEBUG: helm_chart_version: ${helm_chart_version}"
    echo "DEBUG: operator_version: ${operator_version}"
    echo "DEBUG: k8s_versions: ${k8s_versions}"
    echo "DEBUG: release_date: ${release_date}"
    echo "DEBUG: nginx_version: ${nginx_version}"
    echo "DEBUG: NAP_WAF_VERSION: ${NAP_WAF_VERSION}"
    echo "DEBUG: NAP_WAF_RELEASE_VERSION: ${NAP_WAF_RELEASE_VERSION}"
fi

echo "INFO: Generating release notes from github draft release"
release_notes_content=$("${ROOTDIR}"/.github/scripts/pull-release-notes.py "${ic_version}" "${previous_version}" "${helm_chart_version}" "${k8s_versions}" "${release_date}")
if [ $? -ne 0 ]; then
    echo "ERROR: failed to fetch release notes from GitHub draft release for version ${ic_version}"
    exit 2
fi

if [ -z "${release_notes_content}" ]; then
    echo "ERROR: no release notes content"
    exit 2
fi

# Fix HTML entity encoding issues that happen when converting github draft to .md
release_notes_content=$(echo "${release_notes_content}" | sed 's/&amp;/\&/g' | sed 's/&lt;/</g' | sed 's/&gt;/>/g' | sed 's/&quot;/"/g' | sed 's/&#34;/"/g')

if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Release notes content:"
    echo "${release_notes_content}"
fi

echo "INFO: Cloning ${DOCS_REPO}"
gh_bin=$(which gh)
if [ -z "${gh_bin}" ]; then
    echo "ERROR: gh is not installed"
    exit 2
fi

if [ -d "${DOCS_FOLDER}" ]; then
    rm -rf "${DOCS_FOLDER}"
fi

$gh_bin repo clone "${DOCS_REPO}" "${DOCS_FOLDER}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: failed cloning ${DOCS_REPO}"
    exit 2
fi

cd ${DOCS_FOLDER} || exit 2

# Configure git credential helper so git push can authenticate via GH_TOKEN
$gh_bin auth setup-git

if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Cloned doc repo to ${DOCS_FOLDER} and changed directory"
fi

# Select the target branch based on release type:
# - New major/minor release (major.minor differs from previous_version) -> static "nic-release-next" branch
# - Patch release (same major.minor as previous_version) -> static "nic-patch-next" branch
if [ "${LTS}" != "false" ]; then
    if [ "${ic_version%-r*}" != "${previous_version%-r*}" ]; then
        branch=${NEW_RELEASE_BRANCH}
    else
        branch=${PATCH_RELEASE_BRANCH}
    fi
else
    if [ "${ic_version%.*}" != "${previous_version%.*}" ]; then
        branch=${NEW_RELEASE_BRANCH}
    else
        branch=${PATCH_RELEASE_BRANCH}
    fi
fi

if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Generated branch name: ${branch} (from version ${ic_version}, previous ${previous_version})"
fi

echo "INFO: Checking out branch ${branch} in the documentation repository"
remote_branch=$(git ls-remote --heads origin "${branch}" 2> /dev/null)

if [ -n "${remote_branch}" ]; then
    git checkout "${branch}"
    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Checked out existing branch ${branch}"
    fi
else
    git checkout -b "${branch}"
    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Created new branch ${branch}"
    fi
fi

# Extract year from release date
release_year=$(date -j -f "%d %b %Y" "${release_date}" "+%Y" 2>/dev/null || date -d "${release_date}" "+%Y" 2>/dev/null)

if [ -z "${release_year}" ]; then
    echo "ERROR: failed to parse release year from date: ${release_date}"
    exit 2
fi

# Determine what changelog file to use
if [ "${LTS}" == "false" ]; then
    index_file_path=${DOCS_FOLDER}/${CHANGELOG_DIR}/_index.md
else
    index_file_path=${DOCS_FOLDER}/${CHANGELOG_DIR}/changelog.md
fi

if [ "${LTS}" != "false" ]; then
    # LTS uses a single changelog.md with no year-based archiving.
    cp "${index_file_path}" "${TMPDIR}/temp_index.md"
    insert_line=$(grep -n "^## " "${TMPDIR}/temp_index.md" | head -1 | cut -d: -f1)

    if [ -z "${insert_line}" ]; then
        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: No existing releases found, looking for {{< /details >}} tag"
        fi
        insert_line=$(grep -n "{{< /details >}}" "${TMPDIR}/temp_index.md" | tail -1 | cut -d: -f1)
        [ -n "${insert_line}" ] && insert_line=$((insert_line + 2)) || insert_line=8
    fi

    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Will insert new LTS release at line ${insert_line}"
    fi

    head -n $((insert_line - 1)) "${TMPDIR}/temp_index.md" > "${TMPDIR}/final_index.md"
    echo "${release_notes_content}" >> "${TMPDIR}/final_index.md"
    echo "" >> "${TMPDIR}/final_index.md"
    tail -n +"${insert_line}" "${TMPDIR}/temp_index.md" >> "${TMPDIR}/final_index.md"

    mv "${TMPDIR}/final_index.md" "${index_file_path}"
else

    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Attempting to detect current changelog year from ${index_file_path}"
    fi

    # First: look for "releases in 2025" in the header
    current_year=$(grep "releases in" "${index_file_path}" | grep -o "[0-9]\{4\}" | head -1)
    if [ "${DEBUG}" != "false" ] && [ -n "${current_year}" ]; then
        echo "DEBUG: Found year in header text: ${current_year}"
    fi

    # Second: if that fails, look for year in release date entries
    if [ -z "${current_year}" ]; then
        current_year=$(grep -oE "[0-9]{1,2} [A-Z][a-z]+ [0-9]{4}" "${index_file_path}" | grep -o "[0-9]\{4\}" | head -1)
        if [ "${DEBUG}" != "false" ] && [ -n "${current_year}" ]; then
            echo "DEBUG: Found year in release date entries: ${current_year}"
        fi
    fi

    # Third: if both fail, assume it's the previous year as a safe fallback
    if [ -z "${current_year}" ]; then
        current_year=$((release_year - 1))
        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: No year found in changelog, using fallback: ${current_year}"
        fi
    fi

    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Current index year: ${current_year}, Release year: ${release_year}"
    fi

    # Compare release year vs current index year
    # If different years: archive current year's releases and create new index
    # If same year: just add to existing index
    if [ "${release_year}" != "${current_year}" ]; then
        # New year - archive current year and start fresh
        echo "INFO: New year detected (${release_year}). Archiving ${current_year} and creating new index."

        # Create archive file with Hugo frontmatter for the current year's releases
        archive_file=${DOCS_FOLDER}/${CHANGELOG_DIR}/${current_year}.md
        cp "${index_file_path}" "${TMPDIR}/temp_index.md"

        # Update weights in existing archive files (bump each by 100 to make room for new archive at 100)
        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: Updating weights in existing archive files"
        fi
        for existing_archive in ${DOCS_FOLDER}/${CHANGELOG_DIR}/[0-9][0-9][0-9][0-9].md; do
            if [ -f "${existing_archive}" ]; then
                # Extract current weight and add 100
                current_weight=$(grep "^weight:" "${existing_archive}" | sed 's/^weight:[[:space:]]*//')
                new_weight=$((current_weight + 100))
                sed -i.bak "s/^weight: *${current_weight}/weight: ${new_weight}/" "${existing_archive}"
                rm -f "${existing_archive}.bak"
                if [ "${DEBUG}" != "false" ]; then
                    echo "DEBUG: Updated $(basename "${existing_archive}") weight from ${current_weight} to ${new_weight}"
                fi
            fi
        done

        # Create archive with frontmatter
        cat > "${archive_file}" << EOF
---
title: "${current_year} archive"
# Weights are assigned in increments of 100: determines sorting order
weight: 100
# Creates a table of contents and sidebar, useful for large documents
toc: true
# Types have a 1:1 relationship with Hugo archetypes, so you shouldn't need to change this
nd-content-type: reference
nd-product: INGRESS
---

EOF

        # Find where releases start (first "## " heading) and copy everything after that
        # This skips the frontmatter and intro text, keeping only actual release entries
        release_start=$(grep -n "^## " "${TMPDIR}/temp_index.md" | head -1 | cut -d: -f1)
        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: Release content starts at line: ${release_start:-'not found'}"
        fi
        [ -n "${release_start}" ] && tail -n +"${release_start}" "${TMPDIR}/temp_index.md" >> "${archive_file}"

        # Create new index for new year
        echo "INFO: Creating new _index.md for year ${release_year}"

        # Extract header content (everything before the newest release) and update year references
        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: Extracting header and updating year references from ${current_year} to ${release_year}"
        fi

        if [ -n "${release_start}" ]; then
            # Extract everything before the newest release heading
            head -n $((release_start - 1)) "${TMPDIR}/temp_index.md"
        else
            # No releases found, extract most of the file (excluding footer)
            head -n $(($(wc -l < "${TMPDIR}/temp_index.md") - 3)) "${TMPDIR}/temp_index.md"
        fi | sed "s/${current_year}/${release_year}/g" | awk -v archived_year="${current_year}" '
        # Add the archived year to the "previous years" link list
        /For older releases, check the changelogs for previous years:/ {
            # Insert the archived year at the beginning
            sub(/For older releases, check the changelogs for previous years: /, "For older releases, check the changelogs for previous years: [" archived_year "]({{< ref \"/nic/changelog/" archived_year ".md\" >}}), ")
        }
        { print }
        ' > "${TMPDIR}/new_header.md"

        # Assemble new index file: header + new release notes
        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: Assembling new _index.md with header and new release notes"
        fi
        cat "${TMPDIR}/new_header.md" > "${index_file_path}"
        echo "${release_notes_content}" >> "${index_file_path}"

    else
        # Same year - add to existing changelog
        echo "INFO: Adding release notes to existing changelog/_index.md for year ${release_year}"

        # Find where to insert new release notes in existing changelog
        # Look for first release heading ("## ") or fallback to after compatibility matrix
        cp "${index_file_path}" "${TMPDIR}/temp_index.md"
        insert_line=$(grep -n "^## " "${TMPDIR}/temp_index.md" | head -1 | cut -d: -f1)

        if [ -z "${insert_line}" ]; then
            # No existing releases found, insert after the compatibility matrix
            if [ "${DEBUG}" != "false" ]; then
                echo "DEBUG: No existing releases found, looking for {{< /details >}} tag"
            fi
            insert_line=$(grep -n "{{< /details >}}" "${TMPDIR}/temp_index.md" | tail -1 | cut -d: -f1)
            [ -n "${insert_line}" ] && insert_line=$((insert_line + 2)) || insert_line=8
        fi

        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: Will insert new release at line ${insert_line}"
        fi

        # Reconstruct the file: header + new release + existing releases
        # This inserts the new release at the top of the releases section
        head -n $((insert_line - 1)) "${TMPDIR}/temp_index.md" > "${TMPDIR}/final_index.md"
        echo "${release_notes_content}" >> "${TMPDIR}/final_index.md"
        echo "" >> "${TMPDIR}/final_index.md"
        tail -n +"${insert_line}" "${TMPDIR}/temp_index.md" >> "${TMPDIR}/final_index.md"

        mv "${TMPDIR}/final_index.md" "${index_file_path}"
    fi
fi

if [ $? -ne 0 ]; then
    echo "ERROR: failed processing changelog files"
    exit 2
fi

# Update the technical specifications and NAP compatibility table
if [ -n "${nginx_version}" ]; then
    echo "INFO: Updating technical specifications"

    if [ -n "${NAP_WAF_VERSION}" ]; then
        echo "INFO: NAP compatibility table will also be updated with version: ${NAP_WAF_VERSION}"
    fi

    # Run the consolidated tech specs update script (driven by tech-specs.json)
    tech_specs_args=()
    previous_json=$(previous_tech_specs_json "${TMPDIR}/tech-specs-previous.json")
    if [ -n "${previous_json}" ]; then
        tech_specs_args+=(--previous-json "${previous_json}")
    fi
    if [ "${LTS}" != "false" ]; then
        tech_specs_args+=(--lts)
        tech_specs_args+=(--lts-helm-version "${helm_chart_version}")
        tech_specs_args+=(--nginx-plus-version "${nginx_version}")
        tech_specs_args+=(--lts-release-date "${release_date}")
    fi
    tech_specs_args+=("${ic_version}" "${k8s_versions}" "${nginx_version}" "${DOCS_FOLDER}")
    if [ -n "${NAP_WAF_VERSION}" ]; then
        tech_specs_args+=("${NAP_WAF_VERSION}")
    fi

    python3 ${ROOTDIR}/.github/scripts/tech-specs-update.py \
        --json-file "${ROOTDIR}/.github/scripts/tech-specs.json" \
        "${tech_specs_args[@]}"

    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to update technical specifications"
        exit 1
    fi

    echo "INFO: Technical specifications updated"
    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Updated technical specifications content:"
        if [ "${LTS}" != "false" ]; then
            cat "${DOCS_FOLDER}/content/includes/nic/compatibility-tables/nic-lts-k8s.md"
        else
            cat "${DOCS_FOLDER}/content/nic/technical-specifications.md"
        fi
    fi

    # Stage and commit tech specs changes (skip commit in dry-run mode)
    if [ "${DRY_RUN}" == "false" ]; then
        if [ "${LTS}" != "false" ]; then
            git add "content/includes/nic/compatibility-tables/nic-lts-k8s.md"
            git commit -m "Update LTS technical specifications for ${ic_version}"
        else
            git add "content/nic/technical-specifications.md"
            git add "content/includes/nic/compatibility-tables/nic-k8s.md"
            if [ -n "${NAP_WAF_VERSION}" ]; then
                nap_table_file="content/includes/nic/compatibility-tables/nic-nap.md"
                if [ -f "${nap_table_file}" ]; then
                    git add "${nap_table_file}"
                fi
                git commit -m "Update technical specifications and NAP compatibility table for ${ic_version}"
            else
                git commit -m "Update technical specifications for ${ic_version}"
            fi
        fi
    fi
else
    echo "INFO: nginx_version not set, skipping tech specs update"
fi

echo "INFO: Updating shortcodes in the documentation repository"
LTS="${LTS}" ${ROOTDIR}/.github/scripts/docs-shortcode-update.sh "${DOCS_FOLDER}" "${ic_version}" "${helm_chart_version}" "${operator_version}" "${NAP_WAF_VERSION}" "${NAP_WAF_RELEASE_VERSION}"
if [ $? -ne 0 ]; then
    echo "ERROR: failed updating shortcodes"
    exit 2
fi

echo "INFO: Staging changes for commit"
git add -A
if [ $? -ne 0 ]; then
    echo "ERROR: failed adding files to git"
    exit 2
fi

if [ "${DRY_RUN}" == "false" ]; then
    echo "INFO: Committing changes to the documentation repository"
    git commit -m "Update NIC release notes for ${ic_version}"
    if [ $? -ne 0 ]; then
        echo "ERROR: failed committing changes to the docs repo"
        exit 2
    fi

    echo "INFO: Pushing changes to the documentation repository"
    if git push origin "${branch}" 2>&1; then
        # Direct push succeeded — create PR in the same repo
        echo "INFO: Creating pull request for the documentation repository"
        gh pr create --title "Update NIC release notes for ${ic_version}" \
            --body "Update NIC release notes for ${ic_version}" \
            --head "${branch}" --draft
    else
        # Push failed (no write access) — fork and push there instead
        echo "INFO: Direct push failed, forking repository and retrying"
        gh repo fork --remote --remote-name fork
        if [ $? -ne 0 ]; then
            echo "ERROR: failed forking ${DOCS_REPO}"
            exit 2
        fi

        git push fork "${branch}"
        if [ $? -ne 0 ]; then
            echo "ERROR: failed pushing to fork"
            exit 2
        fi

        # Determine fork owner from the fork remote URL
        fork_url=$(git remote get-url fork)
        fork_full_name=$(echo "${fork_url}" | sed -E 's#.*/([^/]+/[^/]+?)(\.git)?$#\1#')
        fork_owner=$(echo "${fork_full_name}" | cut -d'/' -f1)

        if [ "${DEBUG}" != "false" ]; then
            echo "DEBUG: Fork remote URL: ${fork_url}"
            echo "DEBUG: Fork owner: ${fork_owner}"
        fi

        echo "INFO: Creating pull request from fork against ${DOCS_REPO}"
        gh pr create --repo "${DOCS_REPO}" \
            --title "Update NIC release notes for ${ic_version}" \
            --body "Update NIC release notes for ${ic_version}" \
            --head "${fork_owner}:${branch}" --draft
    fi
else
    echo "INFO: DRY_RUN: Showing what would be committed:"
    git add -A
    git status --porcelain
    echo "INFO: DRY_RUN: Full diff:"
    git diff --cached
    git reset HEAD > /dev/null 2>&1
    echo "INFO: DRY_RUN: Skipping commit, push and pull request creation"
fi

if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Returning to NIC directory"
fi
cd - > /dev/null 2>&1

if [ "${TIDY}" == "true" ]; then
    echo "INFO: Clean up"
    rm -rf "${TMPDIR}/temp_index.md" "${TMPDIR}/final_index.md" "${TMPDIR}/current_index.md" "${TMPDIR}/new_header.md" "${DOCS_FOLDER}"
else
    echo "INFO: Skipping tidy (docs folder: ${DOCS_FOLDER})"
fi

exit 0
