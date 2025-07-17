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
release_notes_content=$(${ROOTDIR}/.github/scripts/pull-release-notes.py ${ic_version} ${helm_chart_version} ${k8s_versions} "${release_date}")
if [ $? -ne 0 ]; then
    echo "ERROR: failed processing release notes"
    exit 2
fi

if [ -z "${release_notes_content}" ]; then
    echo "ERROR: no release notes content"
    exit 2
fi

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

cd ${DOCS_FOLDER}
if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Cloned doc repo to ${DOCS_FOLDER} and changed directory"
fi

# generate branch name
branch=${RELEASE_BRANCH_PREFIX}${ic_version%.*}
if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Generating branch ${branch}"
fi

echo "INFO: Checking out branch ${branch} in the documentation repository"
remote_branch=$(git ls-remote --heads origin ${branch} 2> /dev/null)

if [ -n "${remote_branch}" ]; then
    git checkout ${branch}
    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Checked out branch ${branch}"
    fi
else
    git checkout -b ${branch}
    if [ "${DEBUG}" != "false" ]; then
        echo "DEBUG: Created branch ${branch}"
    fi
fi

echo "INFO: Adding release notes content to release.md in the documentation repository"
file_path=${DOCS_FOLDER}/content/nic/releases.md
if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Processing ${file_path}"
fi
file_name=$(basename "${file_path}")
mv "${file_path}" "${TMPDIR}/${file_name}"
head -n 8 "${TMPDIR}/${file_name}" > "${TMPDIR}/header"
tail -n +9 "${TMPDIR}/${file_name}" > "${TMPDIR}/body"
echo "${release_notes_content}" > "${TMPDIR}/release_notes"
cat "${TMPDIR}/header" "${TMPDIR}/release_notes" "${TMPDIR}/body" > "${file_path}"
if [ $? -ne 0 ]; then
    echo "ERROR: failed processing ${file_path}"
    mv "${TMPDIR}/${file_name}" "${file_path}"
    exit 2
fi

echo "INFO: Updating shortcodes in the documentation repository"
${ROOTDIR}/.github/scripts/docs-shortcode-update.sh "${DOCS_FOLDER}" "${ic_version}" "${helm_chart_version}" "${operator_version}"
if [ $? -ne 0 ]; then
    echo "ERROR: failed updating shortcodes"
    exit 2
fi

echo "INFO: Committing changes to the documentation repository"
git add -A
if [ $? -ne 0 ]; then
    echo "ERROR: failed adding files to git"
    exit 2
fi

git commit -m "Update release notes for ${ic_version}"
if [ $? -ne 0 ]; then
    echo "ERROR: failed committing changes to the docs repo"
    exit 2
fi

if [ "${DRY_RUN}" == "false" ]; then
    echo "INFO: Pushing changes to the documentation repository"
    git push origin ${branch}
    if [ $? -ne 0 ]; then
        echo "ERROR: failed pushing changes to the docs repo"
        exit 2
    fi
    echo "INFO: Creating pull request for the documentation repository"
    gh pr create --title "Update release notes for ${ic_version}" --body "Update release notes for ${ic_version}" --head ${branch} --draft
else
    echo "INFO: DRY_RUN: Skipping push and pull request creation"
fi

if [ "${DEBUG}" != "false" ]; then
    echo "DEBUG: Returning to NIC directory"
fi
cd - > /dev/null 2>&1

if [ "${TIDY}" == "true" ]; then
    echo "INFO: Clean up"
    rm -rf "${TMPDIR}/header" "${TMPDIR}/body" "${TMPDIR}/release_notes" "${DOCS_FOLDER}"
fi

exit 0
