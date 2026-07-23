#!/usr/bin/env bash
# Run pytest shards in parallel against multiple pre-existing kind clusters.
#
# Prerequisites (satisfied by the calling Makefile):
#   - Clusters ${PARALLEL_PREFIX}-1 .. ${PARALLEL_PREFIX}-${NUM_CLUSTERS}
#     exist on the shared "kind" docker network.
#   - ${BUILD_IMAGE} is loaded into each cluster.
#   - ${KIND_KUBE_CONFIG_FOLDER}/config contains contexts kind-<name>
#     for every cluster (merged kubeconfig).
#   - ${TEST_PREFIX}:${TEST_TAG} test-runner image is built.
#   - ${ROOT_DIR}/common-secrets already populated (make secrets).
#
# Shards are read from ${SHARD_CONFIG} (JSON with .images[] entries) and
# distributed round-robin across clusters. Each cluster runs its assigned
# shards sequentially; clusters run in parallel. Per-shard results are
# written under ${RESULTS_DIR}/<slug>/.

set -uo pipefail

: "${ROOT_DIR:?}"
: "${NUM_CLUSTERS:?}"
: "${PARALLEL_PREFIX:?}"
: "${SHARD_CONFIG:?}"
: "${BUILD_IMAGE:?}"
: "${KIND_KUBE_CONFIG_FOLDER:?}"
: "${TEST_PREFIX:?}"
: "${TEST_TAG:?}"
: "${RESULTS_DIR:?}"

IC_TYPE="${IC_TYPE:-nginx-ingress}"
PLUS_JWT="${PLUS_JWT:-}"
PYTEST_ARGS="${PYTEST_ARGS:-}"
SHARD_LABELS="${SHARD_LABELS:-}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

if [[ ! -f "${SHARD_CONFIG}" ]]; then
  echo "SHARD_CONFIG not found: ${SHARD_CONFIG}" >&2
  exit 2
fi

if ! docker image inspect "${TEST_PREFIX}:${TEST_TAG}" >/dev/null 2>&1; then
  echo "Test-runner image ${TEST_PREFIX}:${TEST_TAG} not found. Run 'make -C tests build' first." >&2
  exit 2
fi

# Verify all clusters exist.
existing_clusters=$(kind get clusters 2>/dev/null || true)
for (( i=1; i<=NUM_CLUSTERS; i++ )); do
  name="${PARALLEL_PREFIX}-${i}"
  if ! grep -qx "${name}" <<<"${existing_clusters}"; then
    echo "Cluster ${name} not found. Run 'make -C tests create-parallel-kind-clusters' first." >&2
    exit 2
  fi
done

mkdir -p "${RESULTS_DIR}"

# Build the shard list as an array of "<label>\t<marker>" TSV rows.
mapfile -t SHARDS < <(
  jq -r --arg labels "${SHARD_LABELS}" '
    .images
    | (if $labels == "" then . else
        (($labels | split(",") | map(gsub("^ +| +$"; ""))) as $wanted
        | map(select(.label as $l | $wanted | index($l))))
      end)
    | .[]
    | [.label, .marker] | @tsv
  ' "${SHARD_CONFIG}"
)

if [[ ${#SHARDS[@]} -eq 0 ]]; then
  echo "No shards to run (config=${SHARD_CONFIG}, labels=${SHARD_LABELS:-<all>})" >&2
  exit 1
fi

echo "Running ${#SHARDS[@]} shard(s) across ${NUM_CLUSTERS} cluster(s)."
echo "Results: ${RESULTS_DIR}"
echo

slugify() {
  printf '%s' "$1" | sed -E 's#[/ ]+#_#g; s#[^A-Za-z0-9_.-]#_#g'
}

run_shard() {
  local cluster_idx="$1"
  local cluster_name="$2"
  local label="$3"
  local marker="$4"
  local slug dir start rc elapsed kubeconfig
  slug=$(slugify "${label}")
  dir="${RESULTS_DIR}/${slug}"
  mkdir -p "${dir}"
  kubeconfig="${KIND_KUBE_CONFIG_FOLDER}/config-${cluster_idx}"

  if [[ ! -f "${kubeconfig}" ]]; then
    printf '!!! [%s] kubeconfig not found: %s\n' "${cluster_name}" "${kubeconfig}" >&2
    printf '1' > "${dir}/exit_code"
    printf '0' > "${dir}/duration"
    return 1
  fi

  printf '>>> [%s] %s (marker=%s)\n' "${cluster_name}" "${label}" "${marker}"
  start=${SECONDS}
  # shellcheck disable=SC2086
  docker run --network=kind --rm \
    -v "${kubeconfig}:/root/.kube/config:ro" \
    -v "${ROOT_DIR}/tests:/workspace/tests" \
    -v "${ROOT_DIR}/common-secrets:/workspace/common-secrets" \
    -v "${ROOT_DIR}/deployments:/workspace/deployments" \
    -v "${ROOT_DIR}/config:/workspace/config" \
    -v "${ROOT_DIR}/pyproject.toml:/workspace/pyproject.toml" \
    -v "${dir}:/workspace/results" \
    "${TEST_PREFIX}:${TEST_TAG}" \
    --context="kind-${cluster_name}" \
    --image="${BUILD_IMAGE}" \
    --image-pull-policy=Never \
    --deployment-type=deployment \
    --ic-type="${IC_TYPE}" \
    --service=nodeport \
    --node-ip="${cluster_name}-control-plane" \
    --show-ic-logs=yes \
    --plus-jwt="${PLUS_JWT}" \
    --html=/workspace/results/report.html \
    --self-contained-html \
    --junitxml=/workspace/results/report.xml \
    -m "${marker}" \
    ${PYTEST_ARGS} \
    > "${dir}/pytest.log" 2>&1
  rc=$?
  elapsed=$(( SECONDS - start ))
  printf '%s' "${rc}" > "${dir}/exit_code"
  printf '%s' "${elapsed}" > "${dir}/duration"
  printf '<<< [%s] %s rc=%d duration=%dm%02ds\n' \
    "${cluster_name}" "${label}" "${rc}" $(( elapsed / 60 )) $(( elapsed % 60 ))
  return "${rc}"
}

run_cluster_batch() {
  local cluster_idx="$1"
  local cluster_name="${PARALLEL_PREFIX}-${cluster_idx}"
  local batch_rc=0
  while IFS=$'\t' read -r label marker; do
    [[ -z "${label}" ]] && continue
    # Matrix JSON marker values are wrapped in literal single quotes so
    # the CI composite action can pass them through the shell unquoted.
    # Strip surrounding quotes here so pytest -m gets a clean expression.
    marker="${marker#\'}"
    marker="${marker%\'}"
    run_shard "${cluster_idx}" "${cluster_name}" "${label}" "${marker}" || batch_rc=1
  done
  exit "${batch_rc}"
}

# Round-robin: cluster i gets SHARDS[j] where (j % N) == (i-1).
pids=()
for (( i=1; i<=NUM_CLUSTERS; i++ )); do
  {
    for (( j=0; j<${#SHARDS[@]}; j++ )); do
      if (( j % NUM_CLUSTERS == i - 1 )); then
        printf '%s\n' "${SHARDS[$j]}"
      fi
    done
  } | run_cluster_batch "${i}" &
  pids+=($!)
done

overall=0
for pid in "${pids[@]}"; do
  wait "${pid}" || overall=1
done

# Summary.
echo
echo '=== Parallel Shards Summary ==='
printf '%-40s %5s %10s\n' 'shard' 'rc' 'duration'
printf '%-40s %5s %10s\n' '-----' '--' '--------'
for line in "${SHARDS[@]}"; do
  IFS=$'\t' read -r label _ <<< "${line}"
  slug=$(slugify "${label}")
  dir="${RESULTS_DIR}/${slug}"
  rc_v='?'
  dur_v='?'
  [[ -f "${dir}/exit_code" ]] && rc_v=$(cat "${dir}/exit_code")
  if [[ -f "${dir}/duration" ]]; then
    d=$(cat "${dir}/duration")
    dur_v=$(printf '%dm%02ds' $(( d / 60 )) $(( d % 60 )))
  fi
  printf '%-40s %5s %10s\n' "${label}" "${rc_v}" "${dur_v}"
done

exit "${overall}"
