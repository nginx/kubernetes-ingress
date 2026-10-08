#!/usr/bin/env bash
set -euo pipefail

# Validates image matrix definitions in .github/data/matrix-images-*.json against rules:
# 0. include is an array of objects, non-empty except for matrices listed in
#    allow_empty_matrices (OSS and NAP on this LTS branch).
# 1. Every row has non-empty build_os, image, tag_suffix, platforms.
# 2. NAP rows additionally have non-empty nap_modules.
# 3. Plus/NAP rows have non-empty target.
# 4. In every file, (build_os, nap_modules) is unique (build key).
# 5. In every file, (image, tag_suffix) is unique (identity key).
# 6. Every build_os value matches a `FROM ... AS <stage>` in build/Dockerfile.
# 7. No image value is a stage name (must contain '/').

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Validates a single matrix file against the provided stages list (newline-separated).
# Pass "allow-empty" as the third argument for matrices that are intentionally empty
# on this branch. Returns 0 on success, >0 on failure.
validate_matrix_file() {
  local file="$1"
  local stages="$2"
  local allow_empty="${3:-}"
  local file_errors=0

  if [ ! -f "$file" ]; then
    echo "❌ Error: Matrix file not found: $file"
    return 1
  fi

  # include must be an array of objects, non-empty unless allow-empty is set. jq
  # `length` also accepts strings, objects and numbers, and this function is called
  # from an `if`, so `set -e` does not stop on later jq failures -- check the shape
  # explicitly.
  local min_rows=1
  [ "$allow_empty" = "allow-empty" ] && min_rows=0
  if ! jq -e --argjson min "$min_rows" '(.include | type == "array") and (.include | length >= $min) and (.include | all(type == "object"))' "$file" >/dev/null 2>&1; then
    if [ "$min_rows" -eq 0 ]; then
      echo "❌ Error: 'include' must be an array of objects (valid JSON) in $file"
    else
      echo "❌ Error: 'include' must be a non-empty array of objects (valid JSON) in $file"
    fi
    return 1
  fi

  local is_nap=false
  local is_plus=false
  # Match on the basename only: a checkout path such as /home/snap/... must not
  # make the OSS matrix look like a NAP/Plus matrix.
  local base
  base=$(basename "$file")
  [[ "$base" == *"nap"* ]] && is_nap=true
  [[ "$base" == *"plus"* ]] && is_plus=true

  # 1. Field presence and format
  local invalid_rows
  invalid_rows=$(jq -r --arg is_nap "$is_nap" --arg is_plus "$is_plus" '
    .include[] |
    select(
      (.build_os == null or .build_os == "") or
      (.image == null or .image == "") or
      (.tag_suffix == null) or
      (.platforms == null or .platforms == "") or
      ($is_nap == "true" and (.nap_modules == null or .nap_modules == "")) or
      (($is_plus == "true" or $is_nap == "true") and (.target == null or .target == ""))
    )
  ' "$file")
  if [ -n "$invalid_rows" ]; then
    echo "❌ Error: Missing required fields in $file:"
    echo "$invalid_rows"
    file_errors=$((file_errors + 1))
  fi

  # 2. Image must be repo path (contain '/'), not stage name
  local invalid_images
  invalid_images=$(jq -r '
    .include[] | .image | select(contains("/") | not)
  ' "$file")
  if [ -n "$invalid_images" ]; then
    echo "❌ Error: Image must be a repository path containing '/', not stage name in $file:"
    echo "$invalid_images"
    file_errors=$((file_errors + 1))
  fi

  # 3. build_os must match Dockerfile stage
  while IFS= read -r os; do
    [ -z "$os" ] && continue
    if ! echo "$stages" | grep -qx "$os"; then
      echo "❌ Error: build_os '$os' in $file does not match any stage in build/Dockerfile"
      file_errors=$((file_errors + 1))
    fi
  done < <(jq -r '.include[].build_os' "$file" | sort -u)

  # 4. (build_os, nap_modules) uniqueness
  local dup_build_keys
  dup_build_keys=$(jq -r '
    [.include[] | "\(.build_os)|\(.nap_modules // "")"] | group_by(.) | map(select(length > 1)) | .[] | .[0]
  ' "$file")
  if [ -n "$dup_build_keys" ]; then
    echo "❌ Error: Duplicate build key (build_os, nap_modules) in $file: $dup_build_keys"
    file_errors=$((file_errors + 1))
  fi

  # 5. (image, tag_suffix) uniqueness
  local dup_identities
  dup_identities=$(jq -r '
    [.include[] | "\(.image)|\(.tag_suffix)"] | group_by(.) | map(select(length > 1)) | .[] | .[0]
  ' "$file")
  if [ -n "$dup_identities" ]; then
    echo "❌ Error: Duplicate identity key (image, tag_suffix) in $file: $dup_identities"
    file_errors=$((file_errors + 1))
  fi

  return "$file_errors"
}

main() {
  local dockerfile="${DOCKERFILE:-$REPO_ROOT/build/Dockerfile}"

  if [ ! -f "$dockerfile" ]; then
    echo "❌ Error: Dockerfile not found at $dockerfile" >&2
    exit 1
  fi

  if ! command -v jq &>/dev/null; then
    echo "❌ Error: jq is required but not installed." >&2
    exit 1
  fi

  local stages
  stages=$(grep -iE "^FROM\s+.*\s+AS\s+" "$dockerfile" | awk '{print $NF}')

  local matrices=(
    "$REPO_ROOT/.github/data/matrix-images-oss.json"
    "$REPO_ROOT/.github/data/matrix-images-plus.json"
    "$REPO_ROOT/.github/data/matrix-images-plus-lts.json"
    "$REPO_ROOT/.github/data/matrix-images-nap.json"
  )

  # This is an LTS branch: it only builds Plus, so the OSS and NAP matrices are
  # intentionally empty. Every other matrix must have at least one row.
  local allow_empty_matrices=(
    "$REPO_ROOT/.github/data/matrix-images-oss.json"
    "$REPO_ROOT/.github/data/matrix-images-nap.json"
  )

  local errors=0
  for file in "${matrices[@]}"; do
    local rel_file="${file#"$REPO_ROOT/"}"
    local mode=""
    local m
    for m in "${allow_empty_matrices[@]}"; do
      [ "$m" = "$file" ] && mode="allow-empty"
    done
    if validate_matrix_file "$file" "$stages" "$mode"; then
      local count
      count=$(jq '.include | length' "$file")
      echo "✅ $rel_file ($count rows) valid"
    else
      errors=$((errors + 1))
    fi
  done

  if [ "$errors" -ne 0 ]; then
    echo "❌ Image matrix validation failed with $errors error(s)."
    exit 1
  else
    echo "✅ All image matrices passed validation."
    exit 0
  fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
