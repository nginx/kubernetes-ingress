#!/usr/bin/env bash
# Makes values.schema.json self-contained, so Helm needs no network access to validate values.
#
# 1. Rewrites every $ref that points at the Kubernetes definitions on GitHub to point inside the file.
# 2. Replaces the top-level "definitions" block with the Kubernetes types the schema uses.
#
# Requires curl and jq. Set DEFINITIONS_FILE to use a local _definitions.json instead of downloading it.

set -euo pipefail

SCHEMA=${1:-charts/nginx-ingress/values.schema.json}
MAKEFILE=${2:-tests/Makefile}

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
upstream="${tmp}/upstream.json"

# Prints the type names used by the "$ref" values on stdin, e.g. "#/definitions/io.k8s.Foo/properties/bar" -> "io.k8s.Foo"
type_names() {
    sed -n 's|.*"#/definitions/\([^"/]*\).*|\1|p; s|^#/definitions/\([^/]*\).*|\1|p'
}

# Prints the type names that the given upstream types refer to. Fails if one of them does not exist upstream.
refs_of_types() {
    jq -r '.definitions as $defs | $ARGS.positional[]
           | if $defs[.] then $defs[.] | .. | .["$ref"]? | strings else error("type \(.) is not in the upstream definitions") end' \
        "${upstream}" --args "$@" | type_names
}

# 1. Get the Kubernetes definitions for the version used by the test clusters.
if [ -n "${DEFINITIONS_FILE:-}" ]; then
    cp "${DEFINITIONS_FILE}" "${upstream}"
else
    version=$(sed -n 's/^K8S_CLUSTER_VERSION[[:space:]]*?=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${MAKEFILE}")
    [ -n "${version}" ] || { echo "K8S_CLUSTER_VERSION not found in ${MAKEFILE}" >&2; exit 1; }
    curl -fsSL "https://raw.githubusercontent.com/nginxinc/kubernetes-json-schema/master/${version}/_definitions.json" -o "${upstream}"
fi

# 2. Drop the old definitions block, then point every remote $ref at the local definitions block.
jq 'del(.definitions)' "${SCHEMA}" > "${tmp}/schema.json"
sed -i.bak '/"\$ref"/s|"https://raw.githubusercontent.com/nginxinc/kubernetes-json-schema/[^"#]*#|"#|' "${tmp}/schema.json"

# 3. Any $ref that is still not local cannot be bundled.
if grep '"\$ref": "[^#]' "${tmp}/schema.json"; then
    echo "Unsupported \$ref, only #/definitions/... is allowed" >&2
    exit 1
fi

# 4. Collect the types the schema uses, plus the types those types use, until nothing new turns up.
needed=$(grep '"\$ref"' "${tmp}/schema.json" | type_names | sort -u)
while true; do
    # shellcheck disable=SC2086 # type names never contain spaces
    more=$(refs_of_types ${needed})
    all=$(printf '%s\n%s\n' "${needed}" "${more}" | sort -u | sed '/^$/d')
    [ "${all}" = "${needed}" ] && break
    needed=${all}
done

# 5. Keep only those types, sorted by name, and add them as the last key of the schema.
names=$(printf '%s\n' "${needed}" | jq -R . | jq -s .)
jq --argjson names "${names}" '.definitions | to_entries | map(select(.key | IN($names[]))) | sort_by(.key) | from_entries' \
    "${upstream}" > "${tmp}/definitions.json"
jq --slurpfile defs "${tmp}/definitions.json" '. + {definitions: $defs[0]}' "${tmp}/schema.json" > "${tmp}/result.json"

cat "${tmp}/result.json" > "${SCHEMA}"
