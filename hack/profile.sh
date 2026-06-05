#!/usr/bin/env bash
set -euo pipefail

# Profile every test and benchmark function individually.
#
# Each test gets its own CPU and memory profile file, numbered for easy
# ordering and named after the test function:
#
#   profiles/
#     internal_configs/
#       001_TestGetMapKeyAsBool_cpu.prof
#       001_TestGetMapKeyAsBool_mem.prof
#       002_TestGetMapKeyAsInt_cpu.prof
#       ...
#
# Usage:
#   ./hack/profile.sh                         # all internal/ packages, tests + benchmarks
#   PROF_DIR=/tmp/prof ./hack/profile.sh       # custom output directory
#   PROF_PATTERN="TestParse" ./hack/profile.sh # only tests matching a pattern
#   PROF_BENCH_ONLY=1 ./hack/profile.sh        # only benchmark functions
#   PROF_TEST_ONLY=1 ./hack/profile.sh         # only test functions
#   PROF_PKG="./internal/configs/..." ./hack/profile.sh  # specific package(s)

PROF_DIR="${PROF_DIR:-./profiles}"
PROF_PATTERN="${PROF_PATTERN:-}"
PROF_BENCH_ONLY="${PROF_BENCH_ONLY:-}"
PROF_TEST_ONLY="${PROF_TEST_ONLY:-}"
PROF_PKG="${PROF_PKG:-}"

GOTEST_BASE_FLAGS=(-tags=aws,helmunit -count=1 -benchmem)

total_tests=0
total_failed=0

# Run a single test/benchmark function with its own profile files.
#   $1 = package import path
#   $2 = test number (zero-padded)
#   $3 = function name
#   $4 = package output directory
#   $5 = "test" or "bench"
run_one() {
  local pkg=$1 num=$2 func=$3 pkg_dir=$4 kind=$5

  local cpu_prof="${pkg_dir}/${num}_${func}_cpu.prof"
  local mem_prof="${pkg_dir}/${num}_${func}_mem.prof"

  local run_flags=()
  if [[ "${kind}" == "bench" ]]; then
    # Run only this benchmark; -run=^$ ensures no test functions run.
    run_flags=(-run='^$' -bench="^${func}$")
  else
    run_flags=(-run="^${func}$")
  fi

  printf "  %s %-50s " "${num}" "${func}"

  if go test "${GOTEST_BASE_FLAGS[@]}" "${run_flags[@]}" \
       -cpuprofile "${cpu_prof}" \
       -memprofile "${mem_prof}" \
       "${pkg}" > "${pkg_dir}/${num}_${func}.log" 2>&1; then
    echo "ok"
  else
    echo "FAIL (see ${pkg_dir}/${num}_${func}.log)"
    ((total_failed++)) || true
  fi
  ((total_tests++)) || true
}

# List test or benchmark function names in a package.
#   $1 = package import path
#   $2 = "Test" or "Benchmark"
list_funcs() {
  local pkg=$1 prefix=$2
  local pattern=".*"
  if [[ -n "${PROF_PATTERN}" ]]; then
    pattern="${PROF_PATTERN}"
  fi
  # -list prints matching test names to stdout, one per line.
  # It may also print "ok <pkg>" on the last line -- filter that out.
  go test -tags=aws,helmunit -list "${prefix}${pattern}" "${pkg}" 2>/dev/null \
    | grep "^${prefix}" || true
}

# Process one package: enumerate functions, run each with its own profiles.
profile_package() {
  local pkg=$1

  # Derive a directory name: .../internal/configs/version2 -> internal_configs_version2
  local dir_name
  dir_name=$(echo "${pkg}" | sed 's|.*/internal/|internal/|; s|/|_|g')
  local pkg_dir="${PROF_DIR}/${dir_name}"

  # Collect function names.
  local funcs=()
  if [[ -z "${PROF_BENCH_ONLY}" ]]; then
    while IFS= read -r f; do
      [[ -n "$f" ]] && funcs+=("test:${f}")
    done < <(list_funcs "${pkg}" "Test")
  fi
  if [[ -z "${PROF_TEST_ONLY}" ]]; then
    while IFS= read -r f; do
      [[ -n "$f" ]] && funcs+=("bench:${f}")
    done < <(list_funcs "${pkg}" "Benchmark")
  fi

  if [[ ${#funcs[@]} -eq 0 ]]; then
    return
  fi

  mkdir -p "${pkg_dir}"
  echo "--- ${pkg}  (${#funcs[@]} functions)"

  local i=1
  for entry in "${funcs[@]}"; do
    local kind="${entry%%:*}"
    local func="${entry#*:}"
    local num
    num=$(printf "%03d" "${i}")
    run_one "${pkg}" "${num}" "${func}" "${pkg_dir}" "${kind}"
    ((i++))
  done
  echo ""
}

## Main

echo "Saving per-test profiles to ${PROF_DIR}/"
echo ""

if [[ -n "${PROF_PKG}" ]]; then
  packages=$(go list -tags=aws,helmunit ${PROF_PKG} | sort -u)
else
  packages=$(go list -tags=aws,helmunit ./... | sort -u | grep "/internal/")
fi

for pkg in ${packages}; do
  profile_package "${pkg}"
done

echo "========================================"
echo "Total: ${total_tests} functions profiled, ${total_failed} failed"
echo "Profiles: ${PROF_DIR}/"
echo ""
echo "Analyze a profile:"
echo "  go tool pprof ${PROF_DIR}/<package>/<NNN>_<TestName>_cpu.prof"
echo "  go tool pprof -http=:8080 ${PROF_DIR}/<package>/<NNN>_<TestName>_cpu.prof"
