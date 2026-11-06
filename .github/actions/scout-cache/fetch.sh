#!/usr/bin/env bash
# Downloads and verifies one docker/scout-action release binary.
#
# Usage: fetch.sh <version> <sha> <asset> <dest-dir>
#   e.g. fetch.sh v1.27.0 a4119c5a... docker-scout-action_linux_amd64 "$RUNNER_TEMP/docker-scout"
# Env:   GH_TOKEN  token for the GitHub REST API (github.token is enough: the repository is public)
#
# Exits non-zero, leaving nothing in <dest-dir>, if the tag does not point at <sha>,
# a download fails after retries, or the checksum does not match.
set -euo pipefail

version="$1" sha="$2" asset="$3" dest="$4"
repo="docker/scout-action"
checksums="docker-scout_${version#v}_checksums.txt"
: "${GH_TOKEN:?GH_TOKEN must be set}"

# git protocol, not the REST API, so this does not use API rate limit. ^{} peels annotated tags.
actual="$(git ls-remote "https://github.com/${repo}" "refs/tags/${version}" "refs/tags/${version}^{}" | tail -n1 | cut -f1)"
if [ "${actual}" != "${sha}" ]; then
  echo "::error::${repo} ${version} points to '${actual}', expected '${sha}'"
  exit 1
fi

# Authenticated, unlike docker/scout-action's own download, which shares the
# unauthenticated per-IP limit (60 requests/hour) with every job behind the same NAT.
api() {
  curl -fsSL --connect-timeout 20 --retry 5 --retry-all-errors \
    -H "Authorization: Bearer ${GH_TOKEN}" -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

api -H "Accept: application/vnd.github+json" -o "${work}/release.json" \
  "https://api.github.com/repos/${repo}/releases/tags/${version}"

for name in "${checksums}" "${asset}"; do
  id="$(jq -er --arg n "${name}" '.assets[] | select(.name == $n) | .id' "${work}/release.json")" || {
    echo "::error::${repo} ${version} has no asset named ${name}"
    exit 1
  }
  # The asset endpoint redirects to storage; curl does not forward Authorization to the other host.
  api -H "Accept: application/octet-stream" -o "${work}/${name}" \
    "https://api.github.com/repos/${repo}/releases/assets/${id}"
done

(cd "${work}" && grep -E "  ${asset}\$" "${checksums}" | sha256sum -c -)

mkdir -p "${dest}"
install -m 0755 "${work}/${asset}" "${dest}/${asset}"
echo "Downloaded ${asset} ${version} ($(du -h "${dest}/${asset}" | cut -f1))"
