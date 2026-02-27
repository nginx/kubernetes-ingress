#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Required environment variable
if [ -z "${NAP_WAF_REPO_URL}" ]; then
    echo "Error: NAP_WAF_REPO_URL environment variable must be set"
    echo "Example: export NAP_WAF_REPO_URL=https://mydomain.artifactory.net/artifactory/f5-waf_on_nginx-alpine"
    exit 1
fi

# Optional variables with defaults
IMAGE_PREFIX="${IMAGE_PREFIX:-nginx/nginx-ingress}"
TAG="${TAG:-dev}"
GOARCH=amd64
TARGET="${TARGET:-container}"
APP_PROTECT_VERSION="${APP_PROTECT_VERSION:-36.5.603.0-r1}"
NAP_WAF_VERSION="${NAP_WAF_VERSION:-36+5.603.0}"
NAP_AGENT_VERSION="${NAP_AGENT_VERSION:-2}"

DOCKERFILE="${ROOT_DIR}/build/Dockerfile"
DOCKERFILE_TMP="${ROOT_DIR}/build/Dockerfile.nap-dev"

cleanup() {
    rm -f "${DOCKERFILE_TMP}"
}
trap cleanup EXIT

echo "Creating temporary Dockerfile with NAP dev repo..."

# Read the original Dockerfile and create a modified version.
# Replace the app-protect-x-plus repo URL with the dev Artifactory repo URLs
# and switch from ~= (prefix match) to = (exact match) with --allow-untrusted.
cat "${DOCKERFILE}" | awk -v repo_url="${NAP_WAF_REPO_URL}" -v app_protect_version="${APP_PROTECT_VERSION}" '
/app-protect-x-plus/ {
    # Replace the pkgs.nginx.com x-plus repo with the dev Artifactory release-napx repo,
    # then add the master repo on the next line (same as NGF pattern)
    gsub(/https:\/\/\$\{PACKAGE_REPO\}\/app-protect-x-plus\/alpine\/v\$\(grep -E -o/, repo_url "/release-napx/$(grep -E -o")
    gsub(/\/main/, "")
    sub(/>> \/etc\/apk\/repositories \\$/, ">> /etc/apk/repositories \\")
    print
    print "\t&& printf \"%s\\n\" \"" repo_url "/master/$(grep -E -o '"'"'^[0-9]+\\.[0-9]+'"'"' /etc/alpine-release)\" >> /etc/apk/repositories \\"
    next
}
/apk add --no-cache app-protect-module-plus/ {
    # Switch from prefix match (~=) to exact version (=) with --allow-untrusted,
    # then remove the untrusted Artifactory repos so subsequent apk add calls are not affected
    gsub(/apk add --no-cache app-protect-module-plus~=\$\{NAP_WAF_VERSION\/\+\/\.\}/, "apk add --no-cache --allow-untrusted app-protect-module-plus=" app_protect_version)
    gsub(/ \\$/, " \\")
    print
    print "\t&& sed -i '/artifactory/d' /etc/apk/repositories \\"
    next
}
{ print }
' >"${DOCKERFILE_TMP}"

echo "Building NAP dev image (target=${TARGET}, arch=${GOARCH}, version=${APP_PROTECT_VERSION})..."
docker build \
    --platform "linux/amd64" \
    --target "${TARGET}" \
    --build-arg BUILD_OS=alpine-plus-nap-v5-fips \
    --build-arg NAP_WAF_VERSION="${NAP_WAF_VERSION}" \
    --build-arg NAP_AGENT_VERSION="${NAP_AGENT_VERSION}" \
    --build-arg NGINX_PLUS_VERSION="${NGINX_PLUS_VERSION:-R36}" \
    --build-arg PACKAGE_REPO="${PACKAGE_REPO:-pkgs.nginx.com}" \
    --secret id=nginx-repo.crt,src="${ROOT_DIR}/nginx-repo.crt" \
    --secret id=nginx-repo.key,src="${ROOT_DIR}/nginx-repo.key" \
    -f "${DOCKERFILE_TMP}" \
    -t "${IMAGE_PREFIX}:${TAG}" \
    "${ROOT_DIR}"

echo "Successfully built ${IMAGE_PREFIX}:${TAG}"
