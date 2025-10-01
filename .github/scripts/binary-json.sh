#!/usr/bin/env bash

set -eo pipefail

path=$1
project=$2

if [ -z "$path" ] || [ -z "$project" ]; then
  echo "Usage: $0 <path> <project>"
  exit 1
fi


json='[]'
for bin in $(find "$path" -type f -name "nginx-ingress"); do
  dir=$(basename "$(dirname $bin)")
  if [[ "$dir" =~ ${project}_([a-zA-Z0-9]+)_([a-zA-Z0-9]+) ]]; then
    os="${BASH_REMATCH[1]}"
    arch="${BASH_REMATCH[2]}"
    digest=$(sha256sum "$bin" | cut -d' ' -f1)
    json=$(echo "$json" | jq -c --arg path "$bin" --arg os "$os" --arg arch "$arch" --arg digest "$digest" '. += [{"path": $path, "os": $os, "arch": $arch, "digest": $digest}]')
  fi
done
echo "$json"
