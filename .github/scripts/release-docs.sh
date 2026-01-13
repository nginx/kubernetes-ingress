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
RELEASE_BRANCH_PREFIX=${RELEASE_BRANCH_PREFIX:-"nic-release-"}
export GH_TOKEN=${GITHUB_TOKEN:-""}

 usage() {
    echo "Usage: $0 <ic_version> <helm_chart_version> <operator_version> <k8s_versions> <release_date>"
    exit 1
 }

 # clone local doc repo
 # if branch for the release doesnt exist, create it, otherwise checkout

DOCS_FOLDER=${TMPDIR}/documentation
ic_version=$1
helm_chart_version=$2
operator_version=$3
k8s_versions=$4
release_date=$5

if [ -z "${ic_version}" ]; then
    usage
fi

if [ -z "${helm_chart_version}" ]; then
    usage
fi

if [ -z "${k8s_versions}" ]; then
    usage
fi

if [ -z "${release_date}" ]; then
    usage
fi

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
    echo "DEBUG: RELEASE_BRANCH_PREFIX: ${RELEASE_BRANCH_PREFIX}"
    echo "DEBUG: GH_TOKEN: ****$(echo -n $GH_TOKEN | tail -c 4)"
    echo "DEBUG: DOCS_FOLDER: ${DOCS_FOLDER}"
    echo "DEBUG: ic_version: ${ic_version}"
    echo "DEBUG: helm_chart_version: ${helm_chart_version}"
    echo "DEBUG: operator_version: ${operator_version}"
    echo "DEBUG: k8s_versions: ${k8s_versions}"
    echo "DEBUG: release_date: ${release_date}"
fi

echo "INFO: Generating release notes from github draft release"
release_notes_content=$("${ROOTDIR}"/.github/scripts/pull-release-notes.py "${ic_version}" "${helm_chart_version}" "${k8s_versions}" "${release_date}")
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
if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Cloned doc repo to ${DOCS_FOLDER} and changed directory"
fi

# Generate branch name using major.minor version (e.g., nic-release-5.2)
branch=${RELEASE_BRANCH_PREFIX}${ic_version%.*}
if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Generated branch name: ${branch} (from version ${ic_version})"
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

# Determine what year the current _index.md represents
index_file_path=${DOCS_FOLDER}/content/nic/changelog/_index.md

if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Attempting to detect current changelog year from ${index_file_path}"
fi

# First: look for "releases in 2025" in the header
current_year=$(grep "releases in" "${index_file_path}" | grep -o "[0-9]\{4\}" | head -1)
if [ "${DEBUG}" != "false" ] && [ -n "${current_year}" ]; then
    echo "DEBUG: Found year in header text: ${current_year}"
fi

# Second: if that fails, look for year in release headings like "## 5.2.1"
if [ -z "${current_year}" ]; then
    current_year=$(grep -o "^## .*[0-9]\{4\}" "${index_file_path}" | grep -o "[0-9]\{4\}" | head -1)
    if [ "${DEBUG}" != "false" ] && [ -n "${current_year}" ]; then
        echo "DEBUG: Found year in release headings: ${current_year}"
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
    archive_file=${DOCS_FOLDER}/content/nic/changelog/${current_year}.md
    cp "${index_file_path}" "${TMPDIR}/temp_index.md"

    # Update weights in existing archive files (bump each by 100 to make room for new archive at 100)
    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Updating weights in existing archive files"
    fi
    for existing_archive in ${DOCS_FOLDER}/content/nic/changelog/[0-9][0-9][0-9][0-9].md; do
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
    echo "" >> "${index_file_path}"
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
    echo "" >> "${TMPDIR}/final_index.md"
    echo "${release_notes_content}" >> "${TMPDIR}/final_index.md"
    echo "" >> "${TMPDIR}/final_index.md"
    tail -n +"${insert_line}" "${TMPDIR}/temp_index.md" >> "${TMPDIR}/final_index.md"

    mv "${TMPDIR}/final_index.md" "${index_file_path}"
fi

if [ $? -ne 0 ]; then
    echo "ERROR: failed processing changelog files"
    exit 2
fi

echo "INFO: Updating shortcodes in the documentation repository"
${ROOTDIR}/.github/scripts/docs-shortcode-update.sh "${DOCS_FOLDER}" "${ic_version}" "${helm_chart_version}" "${operator_version}"
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
    git commit -m "Update release notes for ${ic_version}"
    if [ $? -ne 0 ]; then
        echo "ERROR: failed committing changes to the docs repo"
        exit 2
    fi

    echo "INFO: Pushing changes to the documentation repository"
    git push origin "${branch}"
    if [ $? -ne 0 ]; then
        echo "ERROR: failed pushing changes to the docs repo"
        exit 2
    fi
    echo "INFO: Creating pull request for the documentation repository"
    gh pr create --title "Update release notes for ${ic_version}" --body "Update release notes for ${ic_version}" --head "${branch}" --draft
else
    echo "INFO: DRY_RUN: Showing what would be committed:"
    git status --porcelain
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
