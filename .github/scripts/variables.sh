#!/usr/bin/env bash

if [ "$1" = "" ]; then
    echo "ERROR: paramater needed"
    exit 2
fi

INPUT=$1
ROOTDIR=$(git rev-parse --show-toplevel || echo ".")
if [ "$PWD" != "$ROOTDIR" ]; then
    # shellcheck disable=SC2164
    cd "$ROOTDIR";
fi

# renovate: datasource=docker depName=kindest/node
K8S_LATEST_VERSION=1.35.1

get_docker_md5() {
  docker_md5=$(find build .github/data/version.txt internal/configs/njs internal/configs/oidc -type f ! -name "*.md" -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }')
  echo "${docker_md5:0:8}"
}

get_go_code_md5() {
  find . -type f \( -name "*.go" -o -name go.mod -o -name go.sum -o -name "*.tmpl" -o -name "version.txt" \) -not -path "./site*"  -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_tests_md5() {
  find tests perf-tests .github/data/version.txt -type f -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_chart_md5() {
  find charts .github/data/version.txt config/crd/bases -type f -exec md5sum {} + | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_actions_md5() {
  exclude_list="$(dirname $0)/exclude_ci_files.txt"
  find_command="find .github -type f -not -path '${exclude_list}'"
  while IFS= read -r file
  do
    find_command+=" -not -path '$file'"
  done < "$exclude_list"

  find_command+=" -exec md5sum {} +"
  eval "$find_command" | LC_ALL=C sort  | md5sum | awk '{ print $1 }'
}

get_build_tag() {
  echo "$(get_docker_md5) $(get_go_code_md5)" | md5sum | awk '{ print $1 }'
}

get_stable_tag() {
  echo "$(get_build_tag) $(get_tests_md5) $(get_chart_md5) $(get_actions_md5)" | md5sum | awk '{ print $1 }'
}

get_additional_tag() {
  if [[ ${REF} =~ /merge$ ]]; then
    pr=${REF%*/merge}
    echo "pr-${pr##*/}"
  else
    echo "${REF//\//-}"
  fi
}

get_k8s_latest_version() {
  echo "$K8S_LATEST_VERSION"
}

# Outputs docs_only=true if all changed files match doc paths (*.md, docs/**, examples/**)
get_docs_only() {
  non_doc_files=$(git diff --name-only HEAD^ | grep -Ev '(\.md$|^docs/|^examples/)')
  if [ -z "$non_doc_files" ]; then
    echo "docs_only=true"
  else
    echo "docs_only=false"
  fi
}

case $INPUT in
  docker_md5)
    echo "docker_md5=$(get_docker_md5)"
    ;;

  go_code_md5)
    echo "go_code_md5=$(get_go_code_md5)"
    ;;

  build_tag)
    echo "build_tag=t-$(get_build_tag)"
    ;;

  stable_tag)
    echo "stable_tag=s-$(get_stable_tag)"
    ;;

  additional_tag)
    echo "additional_tag=$(get_additional_tag)"
    ;;

  k8s_latest_version)
    echo "k8s_latest=$(get_k8s_latest_version)"
    ;;

  docs_only)
    get_docs_only
    ;;

  *)
    echo "ERROR: option not found"
    exit 2
    ;;
esac
