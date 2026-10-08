#!/usr/bin/env bash
#
# Unit tests for validate-image-matrices.sh.
#
# Run directly: bash .github/scripts/validate-image-matrices_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/validate-image-matrices.sh"

set +e

pass=0
fail=0

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

MOCK_STAGES="debian
alpine
ubi
debian-plus
ubi-10-plus
debian-plus-nap
debian-plus-nap-agent"

# assert_validate <want: pass|fail> <description> <json_content> [filename_suffix] [mode]
assert_validate() {
  local want="$1" desc="$2" json="$3" suffix="${4:-matrix-images-test.json}" mode="${5:-}" got
  local tmp_file="$TMP_DIR/$suffix"
  mkdir -p "$(dirname "$tmp_file")"
  printf '%s' "$json" > "$tmp_file"

  if validate_matrix_file "$tmp_file" "$MOCK_STAGES" "$mode" >/dev/null 2>&1; then
    got="pass"
  else
    got="fail"
  fi

  if [[ "$got" == "$want" ]]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL: $desc (want=$want, got=$got)"
  fi
}

# 1. Valid rows
assert_validate pass "valid oss rows" '{
  "include": [
    {"build_os": "debian", "image": "nginx-ic/nginx-ingress", "tag_suffix": "", "platforms": "linux/amd64"},
    {"build_os": "alpine", "image": "nginx-ic/nginx-ingress", "tag_suffix": "-alpine", "platforms": "linux/amd64"}
  ]
}'

assert_validate pass "valid nap rows with unique build and identity keys" '{
  "include": [
    {"build_os": "debian-plus-nap", "image": "nginx-ic-nap/nginx-plus-ingress", "target": "goreleaser", "nap_modules": "waf", "tag_suffix": "", "platforms": "linux/amd64"},
    {"build_os": "debian-plus-nap", "image": "nginx-ic-nap-dos/nginx-plus-ingress", "target": "goreleaser", "nap_modules": "waf,dos", "tag_suffix": "", "platforms": "linux/amd64"},
    {"build_os": "debian-plus-nap-agent", "image": "nginx-ic-nap/nginx-plus-ingress", "target": "goreleaser", "nap_modules": "waf", "tag_suffix": "-agent", "platforms": "linux/amd64"}
  ]
}' "matrix-images-nap.json"

# 2. Missing required fields
assert_validate fail "missing build_os" '{
  "include": [
    {"image": "nginx-ic/nginx-ingress", "tag_suffix": "", "platforms": "linux/amd64"}
  ]
}'

assert_validate fail "missing platforms" '{
  "include": [
    {"build_os": "debian", "image": "nginx-ic/nginx-ingress", "tag_suffix": ""}
  ]
}'

assert_validate fail "missing nap_modules in nap matrix" '{
  "include": [
    {"build_os": "debian-plus-nap", "image": "nginx-ic-nap/nginx-plus-ingress", "target": "goreleaser", "tag_suffix": "", "platforms": "linux/amd64"}
  ]
}' "matrix-images-nap.json"

# 3. Image without '/' (e.g. stage name used as image)
assert_validate fail "image name is stage name without slash" '{
  "include": [
    {"build_os": "debian", "image": "debian-plus", "tag_suffix": "", "platforms": "linux/amd64"}
  ]
}'

# 4. Unknown build_os stage
assert_validate fail "unknown build_os stage" '{
  "include": [
    {"build_os": "non-existent-stage", "image": "nginx-ic/nginx-ingress", "tag_suffix": "", "platforms": "linux/amd64"}
  ]
}'

# 5. Duplicate build key (build_os, nap_modules)
assert_validate fail "duplicate build key in nap matrix" '{
  "include": [
    {"build_os": "debian-plus-nap", "image": "nginx-ic-nap/nginx-plus-ingress", "target": "goreleaser", "nap_modules": "waf", "tag_suffix": "", "platforms": "linux/amd64"},
    {"build_os": "debian-plus-nap", "image": "nginx-ic-nap/nginx-plus-ingress", "target": "goreleaser", "nap_modules": "waf", "tag_suffix": "-other", "platforms": "linux/amd64"}
  ]
}' "matrix-images-nap.json"

# 6. Duplicate identity key (image, tag_suffix)
assert_validate fail "duplicate identity key in oss matrix" '{
  "include": [
    {"build_os": "debian", "image": "nginx-ic/nginx-ingress", "tag_suffix": "", "platforms": "linux/amd64"},
    {"build_os": "alpine", "image": "nginx-ic/nginx-ingress", "tag_suffix": "", "platforms": "linux/amd64"}
  ]
}'

# 7. include must be a non-empty array of objects (jq `length` accepts scalars/objects)
assert_validate fail "include is a string" '{"include": "abc"}'
assert_validate fail "include is an object" '{"include": {"build_os": "debian"}}'
assert_validate fail "include is a number" '{"include": 5}'
assert_validate fail "include is null" '{"include": null}'
assert_validate fail "include is empty array" '{"include": []}'
assert_validate fail "include is missing" '{}'
assert_validate fail "include contains a non-object" '{"include": ["debian"]}'
assert_validate fail "file is not valid json" '{"include": ['

# 8. allow-empty accepts an empty include (LTS OSS/NAP matrices) but still checks the shape
assert_validate pass "empty include with allow-empty" '{"include": []}' "matrix-images-test.json" "allow-empty"
assert_validate fail "include is a string with allow-empty" '{"include": "abc"}' "matrix-images-test.json" "allow-empty"
assert_validate fail "include is missing with allow-empty" '{}' "matrix-images-test.json" "allow-empty"

# 9. File type is derived from the basename, not the directory path
assert_validate pass "oss matrix in a directory whose name contains 'nap' and 'plus'" '{
  "include": [
    {"build_os": "debian", "image": "nginx-ic/nginx-ingress", "tag_suffix": "", "platforms": "linux/amd64"}
  ]
}' "snap-plus-checkout/matrix-images-oss.json"

echo "Results: $pass passed, $fail failed."
[ "$fail" -eq 0 ]
