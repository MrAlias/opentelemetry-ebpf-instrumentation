#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# This harness keeps a bounded sustained client workload separate from the
# runner's bounded trace-correctness assertion. Its artifacts are evidence for
# a benchmark run, not a substitute for the runner's exact-parent assertions.

set -Eeuo pipefail

export LC_ALL=C
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
EXAMPLE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
REPO_ROOT="$(cd -- "$EXAMPLE_DIR/../.." && pwd -P)"
RUNNER="$EXAMPLE_DIR/run.sh"
COMPOSE_FILE="$EXAMPLE_DIR/docker-compose.yml"
RUNTIME_DIR="$EXAMPLE_DIR/.runtime"
RESULTS_ROOT="$RUNTIME_DIR/results"
LOCK_FILE="$RUNTIME_DIR/benchmark.lock"

readonly SCRIPT_DIR EXAMPLE_DIR REPO_ROOT RUNNER COMPOSE_FILE RUNTIME_DIR RESULTS_ROOT LOCK_FILE
readonly PROJECT_NAMESPACE="obi-apache-java-https"
readonly PROJECT_SENTINEL_LABEL="io.opentelemetry.obi.apache-java-https.owner"
readonly PROJECT_SENTINEL_VALUE="acceptance-demo-v1"
readonly WORKLOAD_BASE_URL="http://127.0.0.1:18080"
readonly WORKLOAD_PATH="/api/echo?delay_ms=150"
readonly WORKLOAD_CONNECTION_MODE="close"
readonly DIRECT_JAVA_WORKLOAD_BASE_URL="https://127.0.0.1:18443"
readonly DIRECT_JAVA_WORKLOAD_CA_FILE="/benchmark-ca.crt"
readonly PREFLIGHT_REQUESTS=16
readonly SUSTAINED_LOAD_SEED=0
readonly REQUEST_TIMEOUT_SECONDS=10
readonly REQUEST_LIMIT=1000000
# The measurement deadline closes admissions while admitted requests drain
# under their per-request deadline. Retained results bound that drain separately
# from the external command's startup allowance.
readonly MEASUREMENT_OVERRUN_TOLERANCE_SECONDS=2
readonly MIN_DURATION_SECONDS=2
readonly MAX_DURATION_SECONDS=600
readonly MIN_CONCURRENCY=1
readonly MAX_CONCURRENCY=256
readonly REQUIRED_REPETITIONS=5
readonly MIN_REPETITIONS="$REQUIRED_REPETITIONS"
readonly MAX_REPETITIONS="$REQUIRED_REPETITIONS"
readonly MAX_SEED=9223372036854775807
readonly MAX_JAVA_DIAGNOSTIC_COUNTER=999999999
readonly MAX_BPF_OPERATION_COUNTER=9223372036854775807
readonly MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES=4096
readonly MAX_PROC_CGROUP_BYTES=65536
readonly MAX_BPF_FDINFO_FILES=4096
readonly MAX_BPF_FDINFO_BYTES=16384
readonly MAX_BENCHMARK_CA_CERTIFICATE_BYTES=16384
readonly MAX_BENCHMARK_CA_METADATA_BYTES=16384
readonly MAX_SUSTAINED_WORKLOAD_SUCCESSFUL_REQUESTS="$(((MAX_REPETITIONS + 1) * REQUEST_LIMIT))"
readonly MAX_W3C_WORKLOAD_SUCCESSFUL_REQUESTS="$MAX_SUSTAINED_WORKLOAD_SUCCESSFUL_REQUESTS"
readonly MAX_HELPER_IDLE_WORKLOAD_SUCCESSFUL_REQUESTS="$MAX_SUSTAINED_WORKLOAD_SUCCESSFUL_REQUESTS"
readonly MAX_WORKER_SECONDS=120000
readonly MAX_TOTAL_WORKER_SECONDS=120000
readonly METRICS_SETTLE_SECONDS=1
readonly DOCKER_QUERY_TIMEOUT_SECONDS=15
readonly DOCKER_STATS_TIMEOUT_SECONDS=20
readonly BENCHMARK_PROCESS_GROUP_GRACE_SECONDS=10
readonly RUNNER_START_TIMEOUT_SECONDS=1500
readonly RUNNER_CLEANUP_TIMEOUT_SECONDS=300
readonly POSTLOAD_SENTINEL_TIMEOUT_SECONDS=120
readonly JNI_BENCHMARK_TIMEOUT_SECONDS=180
readonly JNI_BENCHMARK_ITERATIONS=10000
readonly MAX_PERFORMANCE_REGRESSION_PERCENT=10
readonly CORE_CELLS=(uninstrumented bridge-disabled getsockopt-hit unix-hit getsockopt-w3c getsockopt-helper-idle)
readonly BOUNDED_PATH_CELLS=(getsockopt-stale unix-stale unix-timeout getsockopt-pressure)
readonly PATH_OBSERVATION_CELLS=(getsockopt-hit unix-hit "${BOUNDED_PATH_CELLS[@]}")
readonly NATIVE_BENCHMARK_COMPILE_FLAGS=(
  -fPIC -O2 -Wall -Wextra -Wno-unused-parameter -pthread -DOBI_JNI_TESTING
)
readonly NATIVE_BENCHMARK_LINK_FLAGS=(-pthread)
readonly NATIVE_BENCHMARK_TRUSTED_PATH="/usr/bin:/bin"
readonly NATIVE_BENCHMARK_SOURCE_PATHS=(
  examples/apache-java-https/java/Dockerfile
  pkg/internal/java/agent/Makefile.jni
  pkg/internal/java/agent/src/main/c/io_opentelemetry_obi_java_jni.c
  pkg/internal/java/agent/src/test/c/remote_parent_jni_benchmark.c
)
readonly W3C_DISCARD_CELLS=(getsockopt-w3c)
readonly PRESSURE_REQUESTS=128
readonly PRESSURE_MAP_MAX_SUPPORTED_ENTRIES=50000
readonly PRESSURE_RECOVERY_REQUIRED_SAMPLES=2
readonly PRESSURE_ADMISSION_MAX_EVENTS_PER_REQUEST=9
readonly PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES=32768
readonly PROC_CGROUP_CONTAINER_BINDING="full_container_id_at_non_hex_boundaries"

OUTPUT_DIR=""
OUTPUT_PARENT=""
AGENT="otel"
TLS_PROTOCOL="TLSv1.3"
WARMUP_SECONDS=10
DURATION_SECONDS=30
CONCURRENCY=16
REPETITIONS=5
SEED=20260721
CELLS_MODE="core"
RUN_TOKEN=""
SHOW_HELP=false
LOCK_FD=""
LOCK_HELD=false
OUTPUT_READY=false
ACTIVE_PROJECT=""
ACTIVE_CELL_DIR=""
BENCHMARK_PID=""
# A single assignment publishes the launch or dedicated-session identity, so
# an EXIT trap cannot observe a partially recorded identity.
BENCHMARK_IDENTITY=""
PS_COMMAND="$(type -P ps 2>/dev/null || true)"
SLEEP_COMMAND="$(type -P sleep 2>/dev/null || true)"
HARNESS_STATUS="failed"
STARTED_AT=""
HARNESS_INVOCATION=""
NATIVE_BENCHMARK_COMPILER=""
NATIVE_BENCHMARK_COMPILER_SELECTION=""
NATIVE_BENCHMARK_ENV_COMMAND=""
NATIVE_BENCHMARK_GIT_COMMAND=""
NATIVE_BENCHMARK_MAKE_COMMAND=""
NATIVE_BENCHMARK_SHA256_COMMAND=""
NATIVE_BENCHMARK_TIMEOUT_COMMAND=""
DOCKER_ACTIVE_CONTEXT=""
DOCKER_ACTIVE_ENDPOINT=""
DOCKER_CONTEXT_OVERRIDE=""
DOCKER_ACTIVE_SOCKET_PATH=""
DOCKER_ACTIVE_SOCKET_DEVICE=""
DOCKER_ACTIVE_SOCKET_INODE=""

CELL_SLUG=""
CELL_TRANSPORT=""
CELL_SCENARIO=""
CELL_ASSERTION_MODE=""
CELL_REQUIRES_OBI=false
CELL_SELECTED_TRANSPORT=""
CELL_SENTINEL_SCENARIO=""
CELL_SUSTAINED_W3C=false
CELL_EXPECTED_STANDARD_PARENT_DISCARDS=0
CELL_EXPECTED_W3C_VALID_TAKES=0
CELL_W3C_WORKLOAD_SUCCESSFUL_REQUESTS=0
CELL_WORKLOAD_BASE_URL=""
CELL_WORKLOAD_PATH=""
CELL_WORKLOAD_CONNECTION_MODE=""
CELL_WORKLOAD_CA_FILE=""
CELL_EXPECTED_TLS_VERIFICATION=""
CELL_UPSTREAM_HANDOFF=""
CELL_HELPER_IDLE=false
CELL_BOUNDED_PATH=false
CELL_PREFLIGHT_REQUESTS="$PREFLIGHT_REQUESTS"
CELL_RESULT_LABEL=""
CELL_PATH_CLASSIFICATION=""
CELL_EXPECTED_JAVA_STATUS=""
CELL_MEASUREMENT_REQUESTS="$PREFLIGHT_REQUESTS"

declare -a CELL_EXTRA_RUNNER_FILES=()

declare -a COMPOSE=()

usage() {
  printf '%s\n' \
    "Usage: $(basename -- "${BASH_SOURCE[0]}") --output ABSOLUTE_FRESH_DIRECTORY [OPTIONS]" \
    '' \
    'Run the comparable Java remote-parent sustained benchmark artifact harness.' \
    '' \
    'Required:' \
    '  --output DIRECTORY       Fresh absolute directory for private retained artifacts.' \
    '' \
    'Options:' \
    '  --agent NAME             otel or splunk. Default: otel' \
    '  --tls VERSION            TLSv1.2 or TLSv1.3. Default: TLSv1.3' \
    '  --warmup-seconds N       2-600. Default: 10' \
    '  --duration-seconds N     2-600. Default: 30' \
    '  --concurrency N          1-256. Default: 16' \
    '  --repetitions N          Exactly 5 (the predeclared PoC sample count). Default: 5' \
    '  --seed N                 0-9223372036854775807. Default: 20260721' \
    '  --cells SET              core or complete. Default: core' \
    '                           complete adds bounded stale, timeout, and pressure evidence.' \
    '  -h, --help               Show this help text.' \
    '' \
    'The total worker-seconds across all six cells must not exceed 120000.' \
    'Exact OBI-owned BPF map attribution must enumerate the root-owned OBI process fd and fdinfo directories.' \
    'Run as root unless the host procfs/ptrace policy grants equivalent complete read access; Docker-group access alone is insufficient.'
}

log_info() {
  printf '[%(%Y-%m-%dT%H:%M:%SZ)T] INFO: %s\n' -1 "$*" >&2
}

log_error() {
  printf '[%(%Y-%m-%dT%H:%M:%SZ)T] ERROR: %s\n' -1 "$*" >&2
}

die() {
  log_error "$*"
  return 1
}

normalize_decimal() {
  local -r raw="$1"
  local -r maximum="$2"
  local -r allow_zero="$3"
  local normalized="$raw"

  [[ "$raw" =~ ^[0-9]+$ ]] || return 1
  while [[ ${#normalized} -gt 1 && "${normalized:0:1}" == "0" ]]; do
    normalized="${normalized:1}"
  done
  if [[ "$allow_zero" == "false" && "$normalized" == "0" ]]; then
    return 1
  fi
  if (( ${#normalized} > ${#maximum} )); then
    return 1
  fi
  if (( ${#normalized} == ${#maximum} )) && [[ "$normalized" > "$maximum" ]]; then
    return 1
  fi
  printf '%s\n' "$normalized"
}

run_bounded() {
  local -r timeout_seconds="$1"
  shift

  timeout --signal=TERM --kill-after=10s "${timeout_seconds}s" "$@"
}

resolve_docker_daemon_locality() {
  local context=""
  local endpoint_json=""
  local endpoint=""
  local socket_path=""
  local socket_identity=""
  local socket_device=""
  local socket_inode=""
  local extra=""

  [[ ! -v DOCKER_HOST ]] || {
    die "DOCKER_HOST is not allowed; select a verified local Docker context"
    return $?
  }
  context="$(run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    docker context show)" || return 1
  [[ "$context" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ &&
    "$context" != *$'\n'* && "$context" != *$'\r'* ]] || {
    die "the active Docker context name is invalid"
    return $?
  }
  if [[ -n "${DOCKER_CONTEXT:-}" && "$DOCKER_CONTEXT" != "$context" ]]; then
    die "DOCKER_CONTEXT does not match the active Docker context"
    return $?
  fi
  endpoint_json="$(run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    docker context inspect "$context" \
      --format '{{json .Endpoints.docker.Host}}')" || return 1
  endpoint="$(jq -ser '
    if length == 1 and (.[0] | type == "string") then .[0] else empty end
  ' <<<"$endpoint_json")" || return 1
  [[ "$endpoint" =~ ^unix:///([A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+$ ]] || {
    die "the active Docker endpoint must be an absolute local Unix socket"
    return $?
  }
  socket_path="${endpoint#unix://}"
  [[ "$socket_path" == /* && "$socket_path" != *'/../'* &&
    "$socket_path" != */.. && "$socket_path" != *'/./'* &&
    "$socket_path" != */. ]] || return 1
  [[ -S "$socket_path" && ! -L "$socket_path" ]] || {
    die "the active Docker endpoint is not an existing non-symlink Unix socket"
    return $?
  }
  socket_identity="$(stat --format '%d %i' -- "$socket_path")" || return 1
  read -r socket_device socket_inode extra <<<"$socket_identity" || return 1
  [[ "$socket_device" =~ ^[0-9]+$ && "$socket_inode" =~ ^[1-9][0-9]*$ &&
    -z "$extra" ]] || return 1
  DOCKER_ACTIVE_CONTEXT="$context"
  DOCKER_ACTIVE_ENDPOINT="$endpoint"
  DOCKER_CONTEXT_OVERRIDE="${DOCKER_CONTEXT:-}"
  DOCKER_ACTIVE_SOCKET_PATH="$socket_path"
  DOCKER_ACTIVE_SOCKET_DEVICE="$socket_device"
  DOCKER_ACTIVE_SOCKET_INODE="$socket_inode"
}

write_docker_daemon_provenance() {
  local -r output="$OUTPUT_DIR/docker-daemon.json"
  local expected_context="$DOCKER_ACTIVE_CONTEXT"
  local expected_endpoint="$DOCKER_ACTIVE_ENDPOINT"
  local expected_override="$DOCKER_CONTEXT_OVERRIDE"
  local expected_socket_path="$DOCKER_ACTIVE_SOCKET_PATH"
  local expected_socket_device="$DOCKER_ACTIVE_SOCKET_DEVICE"
  local expected_socket_inode="$DOCKER_ACTIVE_SOCKET_INODE"
  local temporary=""

  [[ "$OUTPUT_READY" == "true" && ! -e "$output" && ! -L "$output" &&
    -n "$expected_context" && -n "$expected_endpoint" &&
    -n "$expected_socket_path" && -n "$expected_socket_device" &&
    -n "$expected_socket_inode" ]] || return 1
  resolve_docker_daemon_locality || return 1
  [[ "$DOCKER_ACTIVE_CONTEXT" == "$expected_context" &&
    "$DOCKER_ACTIVE_ENDPOINT" == "$expected_endpoint" &&
    "$DOCKER_CONTEXT_OVERRIDE" == "$expected_override" &&
    "$DOCKER_ACTIVE_SOCKET_PATH" == "$expected_socket_path" &&
    "$DOCKER_ACTIVE_SOCKET_DEVICE" == "$expected_socket_device" &&
    "$DOCKER_ACTIVE_SOCKET_INODE" == "$expected_socket_inode" ]] || return 1
  temporary="$(mktemp "$OUTPUT_DIR/.docker-daemon.json.XXXXXX")" || return 1
  if ! jq -n \
    --arg active_context "$DOCKER_ACTIVE_CONTEXT" \
    --arg active_endpoint "$DOCKER_ACTIVE_ENDPOINT" \
    --arg context_override "$DOCKER_CONTEXT_OVERRIDE" \
    --arg socket_path "$DOCKER_ACTIVE_SOCKET_PATH" \
    --argjson socket_device "$DOCKER_ACTIVE_SOCKET_DEVICE" \
    --argjson socket_inode "$DOCKER_ACTIVE_SOCKET_INODE" '
      {
        schema_version: 2,
        kind: "docker-endpoint-evidence",
        status: "verified_local_unix_socket_endpoint_only",
        active_context: $active_context,
        active_endpoint: $active_endpoint,
        endpoint_transport: "unix",
        socket_path: $socket_path,
        socket_device: $socket_device,
        socket_inode: $socket_inode,
        socket_evidence: "existing_non_symlink_unix_socket",
        daemon_process_locality: "not_established_by_unix_socket_endpoint",
        container_process_binding: "required_separately_for_each_process_sample",
        docker_host_environment: "unset",
        docker_context_environment: (
          if $context_override == "" then "unset" else $context_override end
        ),
        verified_before_container_execution: true
      }
    ' >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  validate_docker_daemon_provenance_schema "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  mv -T -- "$temporary" "$output"
}

validate_docker_daemon_provenance_schema() {
  local -r artifact="$1"

  [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
  jq -se '
    length == 1 and
    (.[0] |
      ((keys | sort) == [
        "active_context", "active_endpoint", "container_process_binding",
        "daemon_process_locality", "docker_context_environment",
        "docker_host_environment", "endpoint_transport", "kind", "schema_version",
        "socket_device", "socket_evidence", "socket_inode", "socket_path",
        "status", "verified_before_container_execution"
      ]) and
      .schema_version == 2 and .kind == "docker-endpoint-evidence" and
      .status == "verified_local_unix_socket_endpoint_only" and
      (.active_context | test("^[A-Za-z0-9][A-Za-z0-9_.-]*$")) and
      (.active_endpoint | test("^unix:///([A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+$")) and
      .endpoint_transport == "unix" and
      .socket_path == (.active_endpoint | sub("^unix://"; "")) and
      (.socket_device | type == "number" and isfinite and floor == . and . >= 0) and
      (.socket_inode | type == "number" and isfinite and floor == . and . > 0) and
      .socket_evidence == "existing_non_symlink_unix_socket" and
      .daemon_process_locality == "not_established_by_unix_socket_endpoint" and
      .container_process_binding == "required_separately_for_each_process_sample" and
      .docker_host_environment == "unset" and
      (.docker_context_environment == "unset" or
        .docker_context_environment == .active_context) and
      .verified_before_container_execution == true)
  ' "$artifact" >/dev/null
}

validate_docker_daemon_provenance() {
  local -r artifact="$1"
  local recorded_context=""
  local recorded_endpoint=""
  local recorded_override=""
  local recorded_socket_path=""
  local recorded_socket_device=""
  local recorded_socket_inode=""

  validate_docker_daemon_provenance_schema "$artifact" || return 1
  recorded_context="$(jq -er '.active_context' "$artifact")" || return 1
  recorded_endpoint="$(jq -er '.active_endpoint' "$artifact")" || return 1
  recorded_override="$(jq -er '.docker_context_environment' "$artifact")" || return 1
  recorded_socket_path="$(jq -er '.socket_path' "$artifact")" || return 1
  recorded_socket_device="$(jq -er '.socket_device' "$artifact")" || return 1
  recorded_socket_inode="$(jq -er '.socket_inode' "$artifact")" || return 1
  resolve_docker_daemon_locality || return 1
  [[ "$DOCKER_ACTIVE_CONTEXT" == "$recorded_context" &&
    "$DOCKER_ACTIVE_ENDPOINT" == "$recorded_endpoint" &&
    "$DOCKER_ACTIVE_SOCKET_PATH" == "$recorded_socket_path" &&
    "$DOCKER_ACTIVE_SOCKET_DEVICE" == "$recorded_socket_device" &&
    "$DOCKER_ACTIVE_SOCKET_INODE" == "$recorded_socket_inode" ]] || return 1
  if [[ "$recorded_override" == unset ]]; then
    [[ -z "$DOCKER_CONTEXT_OVERRIDE" ]]
  else
    [[ "$DOCKER_CONTEXT_OVERRIDE" == "$recorded_override" ]]
  fi
}

is_owned_directory() {
  local -r directory="$1"
  local -r current_user_id="$2"
  local owner=""

  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  owner="$(stat --format '%u' -- "$directory")" || return 1
  [[ "$owner" == "$current_user_id" ]]
}

is_private_owned_directory() {
  local -r directory="$1"
  local -r current_user_id="$2"
  local mode=""

  is_owned_directory "$directory" "$current_user_id" || return 1
  mode="$(stat --format '%a' -- "$directory")" || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 077) == 0 ))
}

is_private_owned_regular_file() {
  local -r file="$1"
  local -r current_user_id="$2"
  local owner=""
  local mode=""

  [[ -f "$file" && ! -L "$file" ]] || return 1
  owner="$(stat --format '%u' -- "$file")" || return 1
  mode="$(stat --format '%a' -- "$file")" || return 1
  [[ "$owner" == "$current_user_id" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 077) == 0 ))
}

is_absolute_regular_executable() {
  local -r executable="$1"

  [[ "$executable" == /* && -f "$executable" && -x "$executable" ]]
}

resolve_lifecycle_tools() {
  PS_COMMAND="$(type -P ps 2>/dev/null || true)"
  SLEEP_COMMAND="$(type -P sleep 2>/dev/null || true)"
  return 0
}

resolve_trusted_native_tool() {
  local -r tool_name="$1"
  local candidate=""
  local canonical=""

  [[ "$tool_name" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || return 1
  for candidate in /usr/bin/"$tool_name" /bin/"$tool_name"; do
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    canonical="$(readlink -f -- "$candidate")" || return 1
    is_absolute_regular_executable "$canonical" || return 1
    printf '%s\n' "$canonical"
    return 0
  done
  return 1
}

resolve_benchmark_identity_tools() {
  NATIVE_BENCHMARK_ENV_COMMAND="$(resolve_trusted_native_tool env)" || return 1
  NATIVE_BENCHMARK_GIT_COMMAND="$(resolve_trusted_native_tool git)" || return 1
  NATIVE_BENCHMARK_SHA256_COMMAND="$(resolve_trusted_native_tool sha256sum)" || return 1
}

resolve_native_benchmark_tools() {
  resolve_benchmark_identity_tools || return 1
  NATIVE_BENCHMARK_MAKE_COMMAND="$(resolve_trusted_native_tool make)" || return 1
  NATIVE_BENCHMARK_TIMEOUT_COMMAND="$(resolve_trusted_native_tool timeout)" || return 1
}

run_native_clean_environment() (
  [[ -n "$NATIVE_BENCHMARK_ENV_COMMAND" ]] || resolve_benchmark_identity_tools || return 1
  # Bash exec -c removes the parent environment before the loader starts
  # env(1). env -i then makes the compiler, Make recipes, and native benchmark
  # receive only the explicitly declared locale and trusted executable path.
  exec -c "$NATIVE_BENCHMARK_ENV_COMMAND" -i \
    "PATH=$NATIVE_BENCHMARK_TRUSTED_PATH" LC_ALL=C "$@"
)

run_native_bounded() {
  local -r timeout_seconds="$1"
  shift

  [[ -n "$NATIVE_BENCHMARK_TIMEOUT_COMMAND" ]] ||
    resolve_native_benchmark_tools || return 1
  run_native_clean_environment \
    "$NATIVE_BENCHMARK_TIMEOUT_COMMAND" --signal=TERM --kill-after=10s \
      "${timeout_seconds}s" "$@"
}

query_clean_native_benchmark_compiler() (
  local -r inherited_compiler="$1"
  local staging_directory=""
  local source_copy_root=""
  local before_identity=""
  local after_identity=""
  local -a resolver_environment=()

  if [[ -n "$inherited_compiler" ]]; then
    resolver_environment+=("CC=$inherited_compiler")
  fi
  staging_directory="$(create_native_build_staging_directory)" || return 1
  trap 'cleanup_native_build_staging_directory "$staging_directory"' EXIT
  source_copy_root="$staging_directory/repository"
  capture_native_source_snapshot \
    "$REPO_ROOT" "$staging_directory/source-state-before.json" || return 1
  copy_native_source_snapshot \
    "$REPO_ROOT" "$staging_directory/source-state-before.json" \
    "$source_copy_root" || return 1
  # shellcheck disable=SC2016 # Make, not Bash, expands $(CC) in this injected target.
  run_native_clean_environment \
    "$NATIVE_BENCHMARK_ENV_COMMAND" "${resolver_environment[@]}" \
    "$NATIVE_BENCHMARK_MAKE_COMMAND" --no-print-directory --silent \
    --directory "$source_copy_root/pkg/internal/java/agent" \
    --file Makefile.jni \
    --eval='.PHONY: print-benchmark-compiler' \
    --eval='print-benchmark-compiler: ; @printf "%s\n" "$(CC)"' \
    print-benchmark-compiler || return 1
  capture_native_source_snapshot \
    "$REPO_ROOT" "$staging_directory/source-state-after.json" || return 1
  before_identity="$(jq -er '.content_identity' \
    "$staging_directory/source-state-before.json")" || return 1
  after_identity="$(jq -er '.content_identity' \
    "$staging_directory/source-state-after.json")" || return 1
  [[ "$before_identity" == "$after_identity" ]] || return 1
  cleanup_native_build_staging_directory "$staging_directory" || return 1
  staging_directory=""
  trap - EXIT
)

resolve_native_benchmark_compiler() {
  local configured_compiler=""
  local resolved_compiler=""

  resolve_native_benchmark_tools || return 1
  if [[ -n "${CC:-}" ]]; then
    [[ "$CC" =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]*$ ||
      "$CC" =~ ^/([A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+$ ]] || {
      die "inherited CC must be one compiler executable without Make or shell metacharacters"
      return $?
    }
  fi
  configured_compiler="$(query_clean_native_benchmark_compiler "${CC:-}")" || return 1
  [[ -n "$configured_compiler" && "$configured_compiler" != *[[:space:]]* &&
    "$configured_compiler" != *$'\n'* ]] || {
    die "Makefile.jni CC must resolve to one compiler executable without arguments"
    return $?
  }
  if [[ "$configured_compiler" == /* ]]; then
    resolved_compiler="$configured_compiler"
  elif [[ -n "${CC:-}" ]]; then
    resolved_compiler="$(type -P -- "$configured_compiler" 2>/dev/null || true)"
  else
    resolved_compiler="$(resolve_trusted_native_tool "$configured_compiler" 2>/dev/null || true)"
  fi
  [[ -n "$resolved_compiler" ]] || {
    die "Makefile.jni compiler is unavailable: $configured_compiler"
    return $?
  }
  resolved_compiler="$(readlink -f -- "$resolved_compiler")" || return 1
  is_absolute_regular_executable "$resolved_compiler" || {
    die "Makefile.jni compiler did not resolve to an absolute regular executable"
    return $?
  }
  NATIVE_BENCHMARK_COMPILER="$resolved_compiler"
  if [[ -n "${CC:-}" ]]; then
    NATIVE_BENCHMARK_COMPILER_SELECTION="inherited_CC"
  else
    NATIVE_BENCHMARK_COMPILER_SELECTION="make_default"
  fi
}

require_value() {
  local -r option="$1"
  local -r argument_count="$2"

  ((argument_count >= 2)) || die "missing value for $option"
}

parse_args() {
  local value=""
  local output_seen=false

  while (($# > 0)); do
    case "$1" in
      --output)
        require_value "$1" "$#" || return $?
        [[ "$output_seen" == "false" ]] || {
          die "--output may only be supplied once"
          return $?
        }
        OUTPUT_DIR="$2"
        output_seen=true
        shift 2
        ;;
      --agent)
        require_value "$1" "$#" || return $?
        AGENT="$2"
        shift 2
        ;;
      --tls)
        require_value "$1" "$#" || return $?
        TLS_PROTOCOL="$2"
        shift 2
        ;;
      --warmup-seconds)
        require_value "$1" "$#" || return $?
        value="$(normalize_decimal "$2" "$MAX_DURATION_SECONDS" false)" || {
          die "$1 must be an integer between $MIN_DURATION_SECONDS and $MAX_DURATION_SECONDS"
          return $?
        }
        ((value >= MIN_DURATION_SECONDS)) || {
          die "$1 must be an integer between $MIN_DURATION_SECONDS and $MAX_DURATION_SECONDS"
          return $?
        }
        WARMUP_SECONDS="$value"
        shift 2
        ;;
      --duration-seconds)
        require_value "$1" "$#" || return $?
        value="$(normalize_decimal "$2" "$MAX_DURATION_SECONDS" false)" || {
          die "$1 must be an integer between $MIN_DURATION_SECONDS and $MAX_DURATION_SECONDS"
          return $?
        }
        ((value >= MIN_DURATION_SECONDS)) || {
          die "$1 must be an integer between $MIN_DURATION_SECONDS and $MAX_DURATION_SECONDS"
          return $?
        }
        DURATION_SECONDS="$value"
        shift 2
        ;;
      --concurrency)
        require_value "$1" "$#" || return $?
        value="$(normalize_decimal "$2" "$MAX_CONCURRENCY" false)" || {
          die "$1 must be an integer between $MIN_CONCURRENCY and $MAX_CONCURRENCY"
          return $?
        }
        ((value >= MIN_CONCURRENCY)) || {
          die "$1 must be an integer between $MIN_CONCURRENCY and $MAX_CONCURRENCY"
          return $?
        }
        CONCURRENCY="$value"
        shift 2
        ;;
      --repetitions)
        require_value "$1" "$#" || return $?
        value="$(normalize_decimal "$2" "$MAX_REPETITIONS" false)" || {
          die "$1 must equal the predeclared PoC sample count $REQUIRED_REPETITIONS"
          return $?
        }
        ((value >= MIN_REPETITIONS)) || {
          die "$1 must equal the predeclared PoC sample count $REQUIRED_REPETITIONS"
          return $?
        }
        REPETITIONS="$value"
        shift 2
        ;;
      --seed)
        require_value "$1" "$#" || return $?
        value="$(normalize_decimal "$2" "$MAX_SEED" true)" || {
          die "$1 must be a non-negative signed 64-bit integer"
          return $?
        }
        SEED="$value"
        shift 2
        ;;
      --cells)
        require_value "$1" "$#" || return $?
        CELLS_MODE="$2"
        shift 2
        ;;
      -h|--help)
        SHOW_HELP=true
        shift
        ;;
      --)
        shift
        (($# == 0)) || {
          die "unexpected positional arguments: $*"
          return $?
        }
        ;;
      *)
        die "unknown argument: $1"
        return $?
        ;;
    esac
  done

  if [[ "$SHOW_HELP" == "true" ]]; then
    return 0
  fi
  [[ "$output_seen" == "true" ]] || {
    die "--output is required"
    return $?
  }
  case "$AGENT" in
    otel|splunk) ;;
    *)
      die "--agent must be otel or splunk"
      return $?
      ;;
  esac
  case "$TLS_PROTOCOL" in
    TLSv1.2|TLSv1.3) ;;
    *)
      die "--tls must be TLSv1.2 or TLSv1.3"
      return $?
      ;;
  esac
  case "$CELLS_MODE" in
    core|complete) ;;
    *)
      die "--cells must be core or complete"
      return $?
      ;;
  esac
  ((DURATION_SECONDS * CONCURRENCY <= MAX_WORKER_SECONDS)) || {
    die "--duration-seconds times --concurrency must not exceed $MAX_WORKER_SECONDS"
    return $?
  }
  (((WARMUP_SECONDS + (REPETITIONS * DURATION_SECONDS)) * CONCURRENCY * ${#CORE_CELLS[@]}
    <= MAX_TOTAL_WORKER_SECONDS)) || {
    die "total worker-seconds across the six cells must not exceed $MAX_TOTAL_WORKER_SECONDS"
    return $?
  }
}

assert_no_symlink_components() {
  local -r path="$1"
  local relative=""
  local component=""
  local current="/"
  local -a components=()

  [[ "$path" == /* ]] || return 1
  relative="${path#/}"
  IFS=/ read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" ]] || continue
    current="${current%/}/$component"
    [[ ! -L "$current" ]] || return 1
  done
}

prepare_output_directory() {
  local output_name=""
  local parent_canonical=""
  local current_user_id=""
  local parent_identity_before=""
  local parent_identity_after=""

  [[ "$OUTPUT_DIR" == /* && "$OUTPUT_DIR" != "/" ]] || {
    die "--output must be an absolute non-root directory"
    return $?
  }
  [[ "$OUTPUT_DIR" != *$'\n'* && "$OUTPUT_DIR" != *$'\r'* &&
    "$OUTPUT_DIR" != *'//' && "$OUTPUT_DIR" != *'/./'* &&
    "$OUTPUT_DIR" != *'/../'* && "$OUTPUT_DIR" != */. && "$OUTPUT_DIR" != */.. ]] || {
    die "--output must not contain ambiguous path components"
    return $?
  }
  [[ "$OUTPUT_DIR" != "$REPO_ROOT" && "$OUTPUT_DIR" != "$REPO_ROOT"/* ]] || {
    die "--output must be outside the repository to preserve runner source provenance"
    return $?
  }
  [[ ! -e "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || {
    die "--output must not already exist"
    return $?
  }
  assert_no_symlink_components "$OUTPUT_DIR" || {
    die "--output must not traverse a symbolic link"
    return $?
  }
  OUTPUT_PARENT="${OUTPUT_DIR%/*}"
  current_user_id="$(id -u)" || return $?
  [[ "$current_user_id" =~ ^[0-9]+$ && -n "$OUTPUT_PARENT" ]] || return 1
  parent_canonical="$(cd -- "$OUTPUT_PARENT" && pwd -P)" || {
    die "--output parent must be an existing private directory"
    return $?
  }
  is_private_owned_directory "$parent_canonical" "$current_user_id" || {
    die "--output parent must be private and owned by the current user"
    return $?
  }
  parent_identity_before="$(stat --format '%d:%i:%u:%a' -- "$parent_canonical")" || return $?
  output_name="${OUTPUT_DIR##*/}"
  [[ -n "$output_name" && "$output_name" != . && "$output_name" != .. ]] || {
    die "--output has an invalid final path component"
    return $?
  }
  OUTPUT_PARENT="$parent_canonical"
  OUTPUT_DIR="$OUTPUT_PARENT/$output_name"
  mkdir --mode=0700 -- "$OUTPUT_DIR" || return $?
  chmod 0700 -- "$OUTPUT_DIR" || return $?
  parent_identity_after="$(stat --format '%d:%i:%u:%a' -- "$OUTPUT_PARENT")" || return $?
  [[ "$parent_identity_before" == "$parent_identity_after" ]] || {
    die "--output parent changed while creating the output directory"
    return $?
  }
  assert_no_symlink_components "$OUTPUT_DIR" &&
    is_private_owned_directory "$OUTPUT_DIR" "$current_user_id" || {
    die "could not create a private output directory"
    return $?
  }
  OUTPUT_READY=true
}

check_dependencies() {
  local command_name=""
  local -a missing=()

  [[ "$(uname -s)" == "Linux" ]] || {
    die "the benchmark harness requires Linux"
    return $?
  }
  for command_name in awk chmod cmp curl date docker env find flock git grep head id install jq mkdir mktemp mv openssl readlink rm setsid sha256sum sort stat timeout tr uname wc; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if [[ "$CELLS_MODE" == "complete" ]]; then
    if ! command -v make >/dev/null 2>&1; then
      missing+=(make)
    fi
  fi
  resolve_lifecycle_tools
  if ! is_absolute_regular_executable "$PS_COMMAND"; then
    missing+=(ps)
  fi
  if ! is_absolute_regular_executable "$SLEEP_COMMAND"; then
    missing+=(sleep)
  fi
  if ((${#missing[@]} > 0)); then
    die "missing required commands: ${missing[*]}"
    return $?
  fi
  resolve_benchmark_identity_tools || return $?
  if [[ "$CELLS_MODE" == "complete" ]]; then
    resolve_native_benchmark_compiler || return $?
  fi
  jq -n 'isfinite' >/dev/null 2>&1 || {
    die "jq with finite-number predicates is required"
    return $?
  }
  [[ -x "$RUNNER" && -f "$COMPOSE_FILE" ]] || {
    die "demo runner or Compose file is unavailable"
    return $?
  }
  resolve_docker_daemon_locality || return $?
  run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker compose version >/dev/null 2>&1 || {
    die "Docker Compose v2 is required"
    return $?
  }
}

acquire_lock() {
  local current_user_id=""
  local runtime_identity_before=""
  local runtime_identity_after=""

  current_user_id="$(id -u)" || return $?
  [[ "$current_user_id" =~ ^[0-9]+$ ]] || return 1
  assert_no_symlink_components "$RUNTIME_DIR" || {
    die "the demo runtime directory path is unsafe"
    return $?
  }
  if [[ -e "$RUNTIME_DIR" || -L "$RUNTIME_DIR" ]]; then
    is_owned_directory "$RUNTIME_DIR" "$current_user_id" || {
      die "the demo runtime directory must be owned by the current user"
      return $?
    }
    runtime_identity_before="$(stat --format '%d:%i:%u' -- "$RUNTIME_DIR")" || return $?
    chmod 0700 -- "$RUNTIME_DIR" || return $?
    runtime_identity_after="$(stat --format '%d:%i:%u' -- "$RUNTIME_DIR")" || return $?
    [[ "$runtime_identity_before" == "$runtime_identity_after" ]] || {
      die "the demo runtime directory changed while securing the benchmark lock"
      return $?
    }
  else
    mkdir --mode=0700 -- "$RUNTIME_DIR" || return $?
  fi
  assert_no_symlink_components "$RUNTIME_DIR" &&
    is_private_owned_directory "$RUNTIME_DIR" "$current_user_id" || {
    die "the demo runtime directory must be private and owned by the current user"
    return $?
  }
  if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
    if (set -C; : >"$LOCK_FILE") 2>/dev/null; then
      :
    elif [[ -e "$LOCK_FILE" || -L "$LOCK_FILE" ]]; then
      :
    else
      return 1
    fi
  fi
  is_private_owned_regular_file "$LOCK_FILE" "$current_user_id" || {
    die "the benchmark lock must be a private regular file owned by the current user"
    return $?
  }
  exec {LOCK_FD}>>"$LOCK_FILE"
  flock --nonblock "$LOCK_FD" || {
    die "another benchmark harness owns $LOCK_FILE"
    return $?
  }
  LOCK_HELD=true
}

release_lock() {
  if [[ "$LOCK_HELD" == "true" ]]; then
    flock --unlock "$LOCK_FD" || true
    exec {LOCK_FD}>&-
    LOCK_HELD=false
  fi
}

cell_spec() {
  local -r cell="$1"

  CELL_SLUG="$cell"
  CELL_BOUNDED_PATH=false
  CELL_PREFLIGHT_REQUESTS="$PREFLIGHT_REQUESTS"
  CELL_MEASUREMENT_REQUESTS="$PREFLIGHT_REQUESTS"
  CELL_SENTINEL_SCENARIO="concurrency"
  CELL_RESULT_LABEL="concurrency"
  CELL_PATH_CLASSIFICATION=""
  CELL_EXPECTED_JAVA_STATUS=""
  CELL_EXTRA_RUNNER_FILES=()
  CELL_SUSTAINED_W3C=false
  CELL_EXPECTED_STANDARD_PARENT_DISCARDS=0
  CELL_EXPECTED_W3C_VALID_TAKES=0
  CELL_W3C_WORKLOAD_SUCCESSFUL_REQUESTS=0
  CELL_WORKLOAD_BASE_URL="$WORKLOAD_BASE_URL"
  CELL_WORKLOAD_PATH="$WORKLOAD_PATH"
  CELL_WORKLOAD_CONNECTION_MODE="$WORKLOAD_CONNECTION_MODE"
  CELL_WORKLOAD_CA_FILE=""
  CELL_EXPECTED_TLS_VERIFICATION="not_applicable"
  CELL_UPSTREAM_HANDOFF="apache_proxy"
  CELL_HELPER_IDLE=false
  case "$cell" in
    uninstrumented)
      CELL_TRANSPORT="disabled"
      CELL_SCENARIO="benchmark-uninstrumented"
      CELL_ASSERTION_MODE="uninstrumented"
      CELL_REQUIRES_OBI=false
      CELL_SELECTED_TRANSPORT="disabled"
      ;;
    bridge-disabled)
      CELL_TRANSPORT="disabled"
      CELL_SCENARIO="benchmark-disabled"
      CELL_ASSERTION_MODE="disabled"
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="disabled"
      ;;
    getsockopt-hit)
      CELL_TRANSPORT="getsockopt"
      CELL_SCENARIO="concurrency"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="getsockopt"
      CELL_PATH_CLASSIFICATION="hit"
      CELL_EXPECTED_JAVA_STATUS="valid"
      ;;
    getsockopt-w3c)
      CELL_TRANSPORT="getsockopt"
      CELL_SCENARIO="w3c"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="getsockopt"
      CELL_SENTINEL_SCENARIO="w3c"
      CELL_RESULT_LABEL="w3c"
      CELL_SUSTAINED_W3C=true
      CELL_EXPECTED_STANDARD_PARENT_DISCARDS="$(((PREFLIGHT_REQUESTS + 1) / 2))"
      CELL_EXPECTED_W3C_VALID_TAKES="$PREFLIGHT_REQUESTS"
      ;;
    unix-hit)
      CELL_TRANSPORT="unix"
      CELL_SCENARIO="concurrency"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="unix"
      CELL_PATH_CLASSIFICATION="hit"
      CELL_EXPECTED_JAVA_STATUS="valid"
      ;;
    getsockopt-helper-idle)
      CELL_TRANSPORT="getsockopt"
      CELL_SCENARIO="concurrency"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="getsockopt"
      CELL_WORKLOAD_BASE_URL="$DIRECT_JAVA_WORKLOAD_BASE_URL"
      CELL_WORKLOAD_CA_FILE="$DIRECT_JAVA_WORKLOAD_CA_FILE"
      CELL_EXPECTED_TLS_VERIFICATION="verified_ca_file"
      CELL_UPSTREAM_HANDOFF="none"
      CELL_HELPER_IDLE=true
      ;;
    getsockopt-stale)
      CELL_TRANSPORT="getsockopt"
      CELL_SCENARIO="primary-w3c-stale"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="getsockopt"
      CELL_SENTINEL_SCENARIO="primary-w3c-stale"
      CELL_RESULT_LABEL="primary-w3c-stale"
      CELL_PATH_CLASSIFICATION="failure"
      CELL_EXPECTED_JAVA_STATUS="stale"
      CELL_PREFLIGHT_REQUESTS=1
      CELL_MEASUREMENT_REQUESTS=1
      CELL_BOUNDED_PATH=true
      CELL_EXTRA_RUNNER_FILES=(
        scenario-basic-primary-w3c-stale-recovery.json
        scenario-basic-primary-w3c-stale-recovery-status.json
        scenario-basic-primary-w3c-stale-recovery.stderr.log
      )
      ;;
    unix-stale)
      CELL_TRANSPORT="unix"
      CELL_SCENARIO="unix-w3c-stale"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="unix"
      CELL_SENTINEL_SCENARIO="unix-w3c-stale"
      CELL_RESULT_LABEL="unix-w3c-stale"
      CELL_PATH_CLASSIFICATION="failure"
      CELL_EXPECTED_JAVA_STATUS="stale"
      CELL_PREFLIGHT_REQUESTS=1
      CELL_MEASUREMENT_REQUESTS=1
      CELL_BOUNDED_PATH=true
      CELL_EXTRA_RUNNER_FILES=(
        scenario-basic-unix-w3c-stale-recovery.json
        scenario-basic-unix-w3c-stale-recovery-status.json
        scenario-basic-unix-w3c-stale-recovery.stderr.log
      )
      ;;
    unix-timeout)
      CELL_TRANSPORT="unix"
      CELL_SCENARIO="w3c-fault"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="unix"
      CELL_SENTINEL_SCENARIO="w3c-fault-timeout"
      CELL_RESULT_LABEL="w3c-fault-timeout"
      CELL_PATH_CLASSIFICATION="failure"
      CELL_EXPECTED_JAVA_STATUS="timeout"
      # The runner's bounded fault suite accepts two requests for its initial
      # alternating control, then emits one request for each named fault mode.
      CELL_PREFLIGHT_REQUESTS=2
      CELL_MEASUREMENT_REQUESTS=1
      CELL_BOUNDED_PATH=true
      CELL_EXTRA_RUNNER_FILES=(w3c-fault-timeout-bridge.log)
      ;;
    getsockopt-pressure)
      CELL_TRANSPORT="getsockopt"
      CELL_SCENARIO="pressure"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="getsockopt"
      CELL_SENTINEL_SCENARIO="pressure"
      CELL_RESULT_LABEL="pressure"
      CELL_PATH_CLASSIFICATION="pressure"
      CELL_EXPECTED_JAVA_STATUS="mixed"
      CELL_PREFLIGHT_REQUESTS="$PRESSURE_REQUESTS"
      CELL_MEASUREMENT_REQUESTS="$PRESSURE_REQUESTS"
      CELL_BOUNDED_PATH=true
      CELL_EXTRA_RUNNER_FILES=(
        map-pressure-pressure-prepare.json
        map-pressure-pressure-prepare.stderr.log
        map-pressure-pressure-fill.json
        map-pressure-pressure-fill.stderr.log
        map-pressure-pressure-verify.json
        map-pressure-pressure-verify.stderr.log
        map-pressure-pressure-barrier-ready.txt
        map-pressure-pressure-barrier-release.txt
        map-pressure-pressure-barrier-status.json
        map-pressure-pressure-container-inspections.json
        map-pressure-pressure-cleanup.json
        map-pressure-pressure-cleanup.stderr.log
        map-pressure-pressure-recovered.prom
        map-pressure-pressure-recovered-sample-01.prom
        map-pressure-pressure-recovered-sample-02.prom
        map-pressure-pressure-recovered-samples.log
      )
      ;;
    *)
      return 1
      ;;
  esac
}

cell_workload_contract() {
  local -r cell="$1"

  cell_spec "$cell" || return 1
  jq -cn \
    --arg cell "$CELL_SLUG" \
    --arg base_url "$CELL_WORKLOAD_BASE_URL" \
    --arg path "$CELL_WORKLOAD_PATH" \
    --arg connection_mode "$CELL_WORKLOAD_CONNECTION_MODE" \
    --arg ca_file "$CELL_WORKLOAD_CA_FILE" \
    --arg tls_verification "$CELL_EXPECTED_TLS_VERIFICATION" \
    --arg upstream_handoff "$CELL_UPSTREAM_HANDOFF" \
    --argjson w3c "$CELL_SUSTAINED_W3C" \
    --argjson helper_idle "$CELL_HELPER_IDLE" \
    '{
      cell: $cell,
      base_url: $base_url,
      path: $path,
      connection_mode: $connection_mode,
      ca_file: ($ca_file | if . == "" then null else . end),
      tls_verification: $tls_verification,
      upstream_handoff: $upstream_handoff,
      w3c_headers: $w3c,
      helper_idle_direct_java: $helper_idle,
      state_map_absence_proof: false
    }'
}

project_for_cell() {
  local -r cell="$1"
  local project_cell="$cell"

  # Compose project names are capped at 63 characters. Keep the retained cell
  # slug descriptive while using a collision-free short form only in the
  # ephemeral project name.
  if [[ "$cell" == "getsockopt-helper-idle" ]]; then
    project_cell="helper-idle"
  fi

  printf '%s-b-%s-%s\n' "$PROJECT_NAMESPACE" "$RUN_TOKEN" "$project_cell"
}

configure_compose() {
  local -r project="$1"

  [[ "$project" =~ ^${PROJECT_NAMESPACE}-[a-z0-9][a-z0-9_-]*$ &&
    ${#project} -le 63 ]] || return 1
  COMPOSE=(docker compose --project-name "$project" --file "$COMPOSE_FILE")
}

prepare_benchmark_ca() {
  local -r result_directory="$1"
  local -r cell_dir="$2"
  local -r metadata="$result_directory/certificates.json"
  local -r certificate="$cell_dir/preflight/benchmark-ca.crt"
  local -r provenance="$cell_dir/preflight/benchmark-ca.json"
  local -r source_identity="$cell_dir/preflight/benchmark-ca-source-identity.txt"
  local -r source_service="apache-proxy"
  local -r source_path="/run/obi-demo/certs/ca.crt"
  local -a basic_constraints_lines=()
  local -a temporary_paths=()
  local basic_constraints=""
  local container_id=""
  local expected_fingerprint=""
  local metadata_size=""
  local observed_fingerprint=""
  local observed_size=""
  local temporary=""
  local canonical=""
  local temporary_identity=""
  local temporary_metadata=""
  local temporary_provenance=""

  unset BENCHMARK_CA_SOURCE
  [[ -f "$metadata" && ! -L "$metadata" &&
    ! -e "$certificate" && ! -L "$certificate" &&
    ! -e "$provenance" && ! -L "$provenance" &&
    ! -e "$source_identity" && ! -L "$source_identity" ]] || return 1
  temporary_metadata="$(mktemp "$cell_dir/preflight/.benchmark-ca-metadata.json.XXXXXX")" || return 1
  temporary_paths+=("$temporary_metadata")
  if ! head -c "$((MAX_BENCHMARK_CA_METADATA_BYTES + 1))" -- "$metadata" \
    >"$temporary_metadata"; then
    rm -f -- "${temporary_paths[@]}"
    return 1
  fi
  metadata_size="$(stat --format '%s' -- "$temporary_metadata")" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  if [[ ! "$metadata_size" =~ ^[1-9][0-9]*$ ]] ||
    ((metadata_size > MAX_BENCHMARK_CA_METADATA_BYTES)); then
    rm -f -- "${temporary_paths[@]}"
    return 1
  fi
  expected_fingerprint="$(jq -ser '
    if length == 1 then
      .[0].ca_sha256 |
      select(type == "string" and test("^([0-9A-F]{2}:){31}[0-9A-F]{2}$"))
    else
      empty
    end
  ' "$temporary_metadata")" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  temporary="$(mktemp "$cell_dir/preflight/.benchmark-ca.crt.XXXXXX")" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  temporary_paths+=("$temporary")
  canonical="$(mktemp "$cell_dir/preflight/.benchmark-ca-canonical.crt.XXXXXX")" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  temporary_paths+=("$canonical")
  temporary_identity="$(mktemp "$cell_dir/preflight/.benchmark-ca-source-identity.txt.XXXXXX")" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  temporary_paths+=("$temporary_identity")
  temporary_provenance="$(mktemp "$cell_dir/preflight/.benchmark-ca.json.XXXXXX")" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  temporary_paths+=("$temporary_provenance")
  if ! capture_service_identity "$source_service" "$temporary_identity"; then
    rm -f -- "${temporary_paths[@]}"
    return 1
  fi
  container_id="$(identity_field "$temporary_identity" container_id)" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }

  if ! run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    docker exec "$container_id" cat "$source_path" 2>/dev/null | \
    head -c "$((MAX_BENCHMARK_CA_CERTIFICATE_BYTES + 1))" >"$temporary"; then
    rm -f -- "${temporary_paths[@]}"
    return 1
  fi
  observed_size="$(stat --format '%s' -- "$temporary")" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  if [[ ! "$observed_size" =~ ^[1-9][0-9]*$ ]] ||
    ((observed_size > MAX_BENCHMARK_CA_CERTIFICATE_BYTES)) ||
    ! openssl x509 -in "$temporary" -outform PEM -out "$canonical" 2>/dev/null ||
    ! cmp -s -- "$temporary" "$canonical" ||
    ! openssl x509 -checkend 3600 -noout -in "$temporary" >/dev/null 2>&1; then
    rm -f -- "${temporary_paths[@]}"
    return 1
  fi
  basic_constraints="$(
    openssl x509 -noout -ext basicConstraints -in "$temporary" 2>/dev/null
  )" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  mapfile -t basic_constraints_lines <<<"$basic_constraints"
  if ((${#basic_constraints_lines[@]} != 2)) ||
    [[ "${basic_constraints_lines[0]:-}" != "X509v3 Basic Constraints: critical" ||
      ! "${basic_constraints_lines[1]:-}" =~ ^[[:space:]]+CA:TRUE(,[[:space:]]pathlen:[0-9]+)?$ ]] ||
    ! openssl verify -check_ss_sig -trusted "$temporary" "$temporary" >/dev/null 2>&1; then
    rm -f -- "${temporary_paths[@]}"
    return 1
  fi
  observed_fingerprint="$(
    openssl x509 -noout -fingerprint -sha256 -in "$temporary" 2>/dev/null
  )" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  observed_fingerprint="${observed_fingerprint#*=}"
  if [[ "$observed_fingerprint" != "$expected_fingerprint" ]]; then
    rm -f -- "${temporary_paths[@]}"
    return 1
  fi
  jq -n \
    --arg source_service "$source_service" \
    --arg source_path "$source_path" \
    --arg source_identity "$(basename -- "$source_identity")" \
    --arg source_container_id "$container_id" \
    --arg certificate "$(basename -- "$certificate")" \
    --arg expected_fingerprint "$expected_fingerprint" \
    --arg observed_fingerprint "$observed_fingerprint" \
    --argjson observed_size "$observed_size" '
      {
        source_service: $source_service,
        source_path: $source_path,
        source_identity: $source_identity,
        source_container_id: $source_container_id,
        certificate: $certificate,
        expected_sha256_fingerprint: $expected_fingerprint,
        observed_sha256_fingerprint: $observed_fingerprint,
        size_bytes: $observed_size,
        assertion: {
          source_container_identity_verified: true,
          recorded_fingerprint_matched: true,
          canonical_single_pem_certificate: true,
          private_key_or_keystore_copied: false
        }
      }
    ' >"$temporary_provenance" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  rm -f -- "$canonical" "$temporary_metadata" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  chmod 0444 -- "$temporary" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  chmod 0400 -- "$temporary_identity" "$temporary_provenance" || {
    rm -f -- "${temporary_paths[@]}"
    return 1
  }
  if ! mv -T -- "$temporary" "$certificate" ||
    ! mv -T -- "$temporary_identity" "$source_identity" ||
    ! mv -T -- "$temporary_provenance" "$provenance"; then
    rm -f -- "${temporary_paths[@]}" "$certificate" "$source_identity" "$provenance"
    return 1
  fi
  BENCHMARK_CA_SOURCE="$certificate"
  export BENCHMARK_CA_SOURCE
}

write_manifest() {
  local cells_json=""
  local bounded_path_cells_json="[]"
  local complete_requested=false
  local jni_lookup_status="not_collected"
  local w3c_discard_cells_json=""
  local w3c_headers_by_cell_json=""
  local workload_by_cell_json=""

  cells_json="$(jq -cn '$ARGS.positional' --args "${CORE_CELLS[@]}")" || return 1
  if [[ "$CELLS_MODE" == "complete" ]]; then
    bounded_path_cells_json="$(jq -cn '$ARGS.positional' \
      --args "${BOUNDED_PATH_CELLS[@]}")" || return 1
    complete_requested=true
    jni_lookup_status="native_fixture_requested"
  fi
  w3c_discard_cells_json="$(jq -cn '$ARGS.positional' --args "${W3C_DISCARD_CELLS[@]}")" || return 1
  w3c_headers_by_cell_json="$(jq -cn \
    --argjson cells "$cells_json" \
    --argjson w3c_discard_cells "$w3c_discard_cells_json" '
      reduce $cells[] as $cell ({};
        .[$cell] = (($w3c_discard_cells | index($cell)) != null))
    ')" || return 1
  workload_by_cell_json="$({
    local cell=""

    for cell in "${CORE_CELLS[@]}"; do
      cell_workload_contract "$cell"
    done
  } | jq -s 'reduce .[] as $workload ({}; .[$workload.cell] = ($workload | del(.cell)) )')" || return 1
  jq -n \
    --arg started_at "$STARTED_AT" \
    --arg invocation "$HARNESS_INVOCATION" \
    --arg agent "$AGENT" \
    --arg tls "$TLS_PROTOCOL" \
    --arg cells_mode "$CELLS_MODE" \
    --arg jni_lookup_status "$jni_lookup_status" \
    --arg base_url "$WORKLOAD_BASE_URL" \
    --arg path "$WORKLOAD_PATH" \
    --arg connection_mode "$WORKLOAD_CONNECTION_MODE" \
    --argjson warmup_seconds "$WARMUP_SECONDS" \
    --argjson duration_seconds "$DURATION_SECONDS" \
    --argjson concurrency "$CONCURRENCY" \
    --argjson repetitions "$REPETITIONS" \
    --argjson preflight_requests "$PREFLIGHT_REQUESTS" \
    --argjson tracecheck_seed "$SEED" \
    --argjson sustained_load_seed "$SUSTAINED_LOAD_SEED" \
    --argjson traffic_elapsed_overrun_tolerance_seconds "$MEASUREMENT_OVERRUN_TOLERANCE_SECONDS" \
    --argjson request_limit "$REQUEST_LIMIT" \
    --argjson cells "$cells_json" \
    --argjson bounded_path_cells "$bounded_path_cells_json" \
    --argjson complete_requested "$complete_requested" \
    --argjson jni_benchmark_iterations "$JNI_BENCHMARK_ITERATIONS" \
    --argjson w3c_discard_cells "$w3c_discard_cells_json" \
    --argjson w3c_headers_by_cell "$w3c_headers_by_cell_json" \
    --argjson workload_by_cell "$workload_by_cell_json" \
    --argjson total_worker_seconds "$((
      (WARMUP_SECONDS + (REPETITIONS * DURATION_SECONDS)) * CONCURRENCY * ${#CORE_CELLS[@]}
    ))" \
    '{
      schema_version: 2,
      status: "in_progress",
      started_at: $started_at,
      invocation: $invocation,
      docker_endpoint_evidence: "docker-daemon.json",
      container_process_binding_evidence: "cells/*/resources-{before,idle-recovery}/*-proc.txt",
      obi_bpf_fd_ownership_evidence:
        "cells/*/resources-{before,idle-recovery}/obi-bpf-fd-ownership.txt",
      application_source_identity: "application-source-identity.json",
      agent: $agent,
      tls_protocol: $tls,
      cells_mode: $cells_mode,
      workload: {
        base_url: $base_url,
        path: $path,
        connection_mode: $connection_mode,
        warmup_seconds: $warmup_seconds,
        duration_seconds: $duration_seconds,
        concurrency: $concurrency,
        repetitions: $repetitions,
        request_limit: $request_limit,
        w3c_headers: false,
        w3c_headers_by_cell: $w3c_headers_by_cell,
        w3c_discard_cells: $w3c_discard_cells,
        by_cell: $workload_by_cell,
        sustained_load_seed: $sustained_load_seed,
        traffic_elapsed_overrun_tolerance_seconds: $traffic_elapsed_overrun_tolerance_seconds
      },
      correctness_preflight: {
        requests: $preflight_requests,
        seed: $tracecheck_seed,
        postload_sentinel: true
      },
      predeclared_poc_gates: {
        declaration_source: "BENCHMARK.md#predeclared-poc-gates",
        evaluation_artifact: "poc-gates.json",
        issue_acceptance_complete: false,
        correctness_failures_max: 0,
        repetitions: {
          required: 5,
          variance_summary: "variance.json"
        },
        steady_state_application: {
          baseline_cell: "bridge-disabled",
          comparison_cells: [
            "getsockopt-hit", "unix-hit", "getsockopt-w3c"
          ],
          excluded_cells: {
            uninstrumented: "no_official_agent",
            getsockopt_helper_idle: "direct_java_workload_is_not_comparable_to_the_apache_baseline"
          },
          throughput_regression_max_percent: 10,
          p99_latency_regression_max_percent: 10
        },
        bounded_growth: {
          fd_delta_max: 0,
          thread_delta_max: 0,
          java_bridge_map_entries_delta_max: 0,
          samples: ["before", "idle_recovery"],
          unavailable_samples_fail_closed: true,
          java_bridge_map_evaluation: {
            status: "evaluated_when_exact_ownership_receipts_are_complete",
            metric_scope: "exact_obi_process_open_bpf_map_ids",
            ownership_attribution: true,
            required_ownership_samples: true,
            bridge_disabled_project_map_configured_max_entries: 1,
            completion_requirement:
              "stable_exact_obi_process_bpf_fd_rosters_bracketing_each_metrics_scrape"
          }
        }
      },
      cells: $cells,
      bounded_path_observations: {
        requested: $complete_requested,
        cells: $bounded_path_cells,
        native_jni_lookup: {
          status: (if $complete_requested then "requested" else "not_requested" end),
          iterations_per_series: $jni_benchmark_iterations,
          artifact: (if $complete_requested then "native-jni/benchmark.json" else null end)
        },
        normalized_summary: (if $complete_requested then "lookup-paths.json" else null end),
        application_state_map_miss: {
          status: "blocked",
          reason: "no test-only fixture removes the exact Apache-to-Java request state before lookup; helper-idle is not a map-miss proof"
        }
      },
      total_worker_seconds: $total_worker_seconds,
      unavailable_dimensions: {
        jni_lookup_latency_percentiles: $jni_lookup_status,
        jfr_nmt_allocation_native_direct_memory: "not_collected",
        primary_cgroupsockopt_program_cpu: "not_collected",
        bpf_map_insert_failures: (if $complete_requested then "capacity_rejection_only" else "not_collected" end),
        bpf_map_evictions: (if $complete_requested then "not_applicable_non_evicting_hash_pressure" else "not_collected" end),
        bpf_lock_contention: "not_collected",
        application_cpu_rss_fd_threads: "requested_for_bounded_growth_gate",
        java_allocations: "not_collected",
        java_native_memory: "not_collected",
        java_direct_memory: "not_collected"
      }
    }' >"$OUTPUT_DIR/manifest.json"
}

capture_host_environment() {
  {
    printf 'captured_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    uname -a
    awk -F ': *' '/^(model name|Hardware|MemTotal):/ { print $1 "=" $2 }' /proc/cpuinfo /proc/meminfo 2>/dev/null || true
    printf 'logical_cpu_count='
    awk '/^processor[[:space:]]*:/ { count++ } END { print count + 0 }' /proc/cpuinfo 2>/dev/null || true
    if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
      printf 'cpu0_scaling_governor='
      awk 'NR == 1 { print }' /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor || true
    fi
    if [[ -r /sys/fs/cgroup/cpu.max ]]; then
      printf 'cgroup_cpu_max='
      awk 'NR == 1 { print }' /sys/fs/cgroup/cpu.max || true
    fi
    if [[ -r /sys/fs/cgroup/memory.max ]]; then
      printf 'cgroup_memory_max='
      awk 'NR == 1 { print }' /sys/fs/cgroup/memory.max || true
    fi
    printf 'git_revision='
    git -C "$REPO_ROOT" rev-parse HEAD || true
    printf 'docker_context=%s\n' "$DOCKER_ACTIVE_CONTEXT"
    printf 'docker_endpoint=%s\n' "$DOCKER_ACTIVE_ENDPOINT"
    run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
      docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}' || true
    run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker compose version || true
  } >"$OUTPUT_DIR/host-environment.txt" 2>&1
}

validate_native_source_snapshot_schema() {
  local -r snapshot="$1"

  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 1
  resolve_native_benchmark_tools || return 1
  jq -se --argjson expected_paths "$(printf '%s\n' \
    "${NATIVE_BENCHMARK_SOURCE_PATHS[@]}" | jq -Rsc 'split("\n")[:-1]')" '
    length == 1 and
    (.[0] |
      ((keys | sort) == [
        "content_identity", "kind", "paths", "revision", "schema_version", "status"
      ]) and
      .schema_version == 1 and
      .kind == "native-jni-source-snapshot" and
      .status == "clean" and
      (.revision | test("^[0-9a-f]{40}$")) and
      ([.paths[].path] == $expected_paths) and
      all(.paths[];
        ((keys | sort) == [
          "head_blob", "index_blob", "mode", "path", "working_blob", "working_sha256"
        ]) and
        (.mode == "100644" or .mode == "100755") and
        (.head_blob | test("^[0-9a-f]{40}$")) and
        .index_blob == .head_blob and .working_blob == .head_blob and
        (.working_sha256 | test("^[0-9a-f]{64}$"))) and
      (.content_identity | test("^[0-9a-f]{64}$"))
    )
  ' "$snapshot" >/dev/null || return 1
  local observed_identity=""
  local recorded_identity=""
  observed_identity="$(jq -cS '{revision, paths}' "$snapshot" |
    run_native_clean_environment "$NATIVE_BENCHMARK_SHA256_COMMAND")" || return 1
  observed_identity="${observed_identity%% *}"
  recorded_identity="$(jq -er '.content_identity' "$snapshot")" || return 1
  [[ "$observed_identity" == "$recorded_identity" ]]
}

capture_native_source_snapshot() {
  local -r repository="$1"
  local -r output="$2"
  local revision=""
  local path=""
  local head_line=""
  local index_line=""
  local head_mode=""
  local head_type=""
  local head_blob=""
  local head_path=""
  local index_mode=""
  local index_blob=""
  local index_stage=""
  local index_path=""
  local working_blob=""
  local working_sha256=""
  local paths_json=""
  local identity=""
  local temporary=""
  local entry=""
  local -a entries=()

  [[ -d "$repository" && ! -L "$repository" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  resolve_native_benchmark_tools || return 1
  revision="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" rev-parse HEAD)" || return 1
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || return 1
  for path in "${NATIVE_BENCHMARK_SOURCE_PATHS[@]}"; do
    [[ -f "$repository/$path" && ! -L "$repository/$path" ]] || return 1
    head_line="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" ls-tree "$revision" -- "$path")" || return 1
    index_line="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" ls-files --stage -- "$path")" || return 1
    read -r head_mode head_type head_blob head_path <<<"$head_line" || return 1
    read -r index_mode index_blob index_stage index_path <<<"$index_line" || return 1
    [[ "$head_path" == "$path" && "$index_path" == "$path" &&
      "$head_type" == blob && "$index_stage" == 0 &&
      ( "$head_mode" == 100644 || "$head_mode" == 100755 ) &&
      "$index_mode" == "$head_mode" &&
      "$head_blob" =~ ^[0-9a-f]{40}$ && "$index_blob" == "$head_blob" ]] || return 1
    working_blob="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" hash-object \
      --no-filters -- "$repository/$path")" || return 1
    [[ "$working_blob" == "$head_blob" ]] || return 1
    working_sha256="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_SHA256_COMMAND" -- "$repository/$path")" || return 1
    working_sha256="${working_sha256%% *}"
    [[ "$working_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
    entry="$(jq -cn \
      --arg path "$path" --arg mode "$head_mode" \
      --arg head_blob "$head_blob" --arg index_blob "$index_blob" \
      --arg working_blob "$working_blob" --arg working_sha256 "$working_sha256" '
        {path: $path, mode: $mode, head_blob: $head_blob,
         index_blob: $index_blob, working_blob: $working_blob,
         working_sha256: $working_sha256}
      ')" || return 1
    entries+=("$entry")
  done
  paths_json="$(printf '%s\n' "${entries[@]}" | jq -s .)" || return 1
  identity="$(jq -cnS --arg revision "$revision" --argjson paths "$paths_json" \
    '{revision: $revision, paths: $paths}' |
    run_native_clean_environment "$NATIVE_BENCHMARK_SHA256_COMMAND")" || return 1
  identity="${identity%% *}"
  [[ "$identity" =~ ^[0-9a-f]{64}$ ]] || return 1
  temporary="$(mktemp "${output%/*}/.native-source-snapshot.XXXXXX")" || return 1
  jq -n --arg revision "$revision" --arg identity "$identity" \
    --argjson paths "$paths_json" '
      {
        schema_version: 1,
        kind: "native-jni-source-snapshot",
        status: "clean",
        revision: $revision,
        paths: $paths,
        content_identity: $identity
      }
    ' >"$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  validate_native_source_snapshot_schema "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  mv -T -- "$temporary" "$output"
}

copy_native_source_snapshot() {
  local -r repository="$1"
  local -r snapshot="$2"
  local -r destination="$3"
  local path=""
  local expected_blob=""
  local copied_blob=""
  local expected_sha256=""
  local copied_sha256=""

  validate_native_source_snapshot_schema "$snapshot" || return 1
  [[ ! -e "$destination" && ! -L "$destination" ]] || return 1
  mkdir -- "$destination"
  for path in "${NATIVE_BENCHMARK_SOURCE_PATHS[@]}"; do
    mkdir -p -- "$destination/${path%/*}"
    install -m 0600 -- "$repository/$path" "$destination/$path" || return 1
    expected_blob="$(jq -er --arg path "$path" \
      '.paths[] | select(.path == $path) | .working_blob' "$snapshot")" || return 1
    copied_blob="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" hash-object \
      --no-filters -- "$destination/$path")" || return 1
    [[ "$copied_blob" == "$expected_blob" ]] || return 1
    expected_sha256="$(jq -er --arg path "$path" \
      '.paths[] | select(.path == $path) | .working_sha256' "$snapshot")" || return 1
    copied_sha256="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_SHA256_COMMAND" -- "$destination/$path")" || return 1
    copied_sha256="${copied_sha256%% *}"
    [[ "$copied_sha256" == "$expected_sha256" ]] || return 1
  done
}

finalize_native_source_state() {
  local -r before="$1"
  local -r after="$2"
  local -r output="$3"
  local before_identity=""
  local after_identity=""

  validate_native_source_snapshot_schema "$before" || return 1
  validate_native_source_snapshot_schema "$after" || return 1
  before_identity="$(jq -er '.content_identity' "$before")" || return 1
  after_identity="$(jq -er '.content_identity' "$after")" || return 1
  [[ "$before_identity" == "$after_identity" ]] || return 1
  jq -n --slurpfile before "$before" --arg before_link "${before##*/}" \
    --arg after_link "${after##*/}" '
      $before[0] + {
        kind: "native-jni-source-state",
        status: "clean_and_stable",
        captures: {before: $before_link, after: $after_link}
      }
    ' >"$output"
}

validate_native_source_state_schema() {
  local -r state="$1"
  local -r state_directory="${state%/*}"
  local before_link=""
  local after_link=""

  [[ -f "$state" && ! -L "$state" ]] || return 1
  jq -se --argjson expected_paths "$(printf '%s\n' \
    "${NATIVE_BENCHMARK_SOURCE_PATHS[@]}" | jq -Rsc 'split("\n")[:-1]')" '
    length == 1 and
    (.[0] |
      ((keys | sort) == [
        "captures", "content_identity", "kind", "paths", "revision",
        "schema_version", "status"
      ]) and
      .schema_version == 1 and .kind == "native-jni-source-state" and
      .status == "clean_and_stable" and
      (.revision | test("^[0-9a-f]{40}$")) and
      ([.paths[].path] == $expected_paths) and
      all(.paths[];
        ((keys | sort) == [
          "head_blob", "index_blob", "mode", "path", "working_blob", "working_sha256"
        ]) and
        (.mode == "100644" or .mode == "100755") and
        (.head_blob | test("^[0-9a-f]{40}$")) and
        .index_blob == .head_blob and .working_blob == .head_blob and
        (.working_sha256 | test("^[0-9a-f]{64}$"))) and
      (.content_identity | test("^[0-9a-f]{64}$")) and
      .captures == {
        before: "source-state-before.json", after: "source-state-after.json"
      }
    )
  ' "$state" >/dev/null || return 1
  before_link="$(jq -er '.captures.before' "$state")" || return 1
  after_link="$(jq -er '.captures.after' "$state")" || return 1
  validate_native_source_snapshot_schema "$state_directory/$before_link" || return 1
  validate_native_source_snapshot_schema "$state_directory/$after_link" || return 1
  jq -e --slurpfile before "$state_directory/$before_link" \
    --slurpfile after "$state_directory/$after_link" '
      .revision == $before[0].revision and .revision == $after[0].revision and
      .paths == $before[0].paths and .paths == $after[0].paths and
      .content_identity == $before[0].content_identity and
      .content_identity == $after[0].content_identity
    ' "$state" >/dev/null
}

validate_relative_artifact_link() {
  local -r base_directory="$1"
  local -r containment_root="$2"
  local -r link="$3"
  local resolved=""

  [[ "$base_directory" == /* && "$containment_root" == /* &&
    -n "$link" && "$link" != /* && "$link" != *$'\n'* && "$link" != *$'\r'* ]] || return 1
  resolved="$(readlink -m -- "$base_directory/$link")" || return 1
  [[ "$resolved" == "$containment_root"/* && -f "$resolved" && ! -L "$resolved" ]] || return 1
  assert_no_symlink_components "$resolved"
}

validate_native_jni_benchmark_schema() {
  local -r artifact="$1"
  local artifact_directory=""
  local artifact_root=""
  local compiler_path=""
  local compiler_sha256=""
  local binary_sha256=""
  local link=""

  [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
  resolve_native_benchmark_tools || return 1
  jq -se --argjson iterations "$JNI_BENCHMARK_ITERATIONS" '
    def nonnegative_integer:
      type == "number" and isfinite and floor == . and . >= 0;
    def positive_integer:
      nonnegative_integer and . > 0;
    length == 1 and
    (.[0] |
      .schema_version == 1 and
      .kind == "native-jni-lookup-benchmark" and
      .benchmark == "obi_java_remote_parent_native" and
      .status == "passed" and
      .acceptance_evidence == false and
      .iterations == $iterations and .warmup_iterations == 1000 and
      .fixture_scope.application_path == false and
      .fixture_scope.getsockopt == "deterministic_syscall_shim" and
      .fixture_scope.unix == "deterministic_abstract_socket_responder" and
      (.series | type == "array" and length == 6) and
      ([.series[] | [.transport, .outcome]] == [
        ["getsockopt", "hit"], ["getsockopt", "miss"],
        ["getsockopt", "failure"], ["unix", "hit"],
        ["unix", "miss"], ["unix", "failure"]
      ]) and
      all(.series[];
        .iterations == $iterations and .warmup_iterations == 1000 and
        (.elapsed_nanos | positive_integer) and
        (.nanos_per_operation | type == "number" and isfinite and . > 0) and
        (.operations_per_second | type == "number" and isfinite and . > 0) and
        (.latency_p50_nanos | positive_integer) and
        (.latency_p95_nanos | positive_integer) and
        (.latency_p99_nanos | positive_integer) and
        .latency_p50_nanos <= .latency_p95_nanos and
        .latency_p95_nanos <= .latency_p99_nanos and
        .elapsed_nanos >= .latency_p99_nanos and
        (.status_code | nonnegative_integer) and
        (.checksum | positive_integer) and
        .checksum == (.status_code * .iterations) and
        (if .outcome == "hit" then .status_code == 1
         elif .outcome == "miss" then .status_code == 2
         else .outcome == "failure" and .status_code == 12
         end)) and
      (.provenance |
        ((keys | sort) == [
          "binary", "binary_sha256", "compiler", "compiler_artifact",
          "host_environment", "java_runtime", "jdk_header_image", "jdk_image_inspection",
          "raw_output", "raw_stderr", "source_revision", "source_state"
        ])) and
      (.provenance.source_revision | test("^[0-9a-f]{40}$")) and
      .provenance.host_environment == "../host-environment.txt" and
      .provenance.raw_output == "raw.txt" and
      .provenance.raw_stderr == "raw.stderr.log" and
      .provenance.source_state == "source-state.json" and
      .provenance.compiler_artifact == "compiler-provenance.json" and
      (.provenance.compiler |
        ((keys | sort) == [
          "build_command", "canonical_path", "compile_flags",
          "environment", "executable_sha256", "expanded_build_command", "link_flags",
          "pinned_for_make", "selection", "version"
        ]) and
        (.canonical_path | test("^/")) and
        (.executable_sha256 | test("^[0-9a-f]{64}$")) and
        (.selection == "inherited_CC" or .selection == "make_default") and
        .pinned_for_make == true and
        .version == "compiler-version.txt" and
        .build_command == "build-command.txt" and
        .expanded_build_command == "expanded-build-command.txt" and
        .environment == {
          policy: "empty_parent_environment_with_explicit_allowlist",
          parent_environment: {
            path: "/usr/bin:/bin",
            locale: "C",
            allowed_variables: ["PATH", "LC_ALL"],
            dynamic_loader_parent_cleared: true
          },
          controlled_make_environment: {
            command_line_variables: ["BENCHMARK_ITERATIONS", "BUILD_DIR", "CC", "JAVA_HOME"],
            make_generated_variables: ["MAKEFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "MFLAGS"],
            working_directory: "private_source_snapshot"
          }
        } and
        .compile_flags == [
          "-fPIC", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter",
          "-pthread", "-DOBI_JNI_TESTING"
        ] and
        .link_flags == ["-pthread"]) and
      .provenance.java_runtime == "java-version.txt" and
      (.provenance.jdk_header_image | test("^maven:[^@]+@sha256:[0-9a-f]{64}$")) and
      .provenance.jdk_image_inspection == "jdk-image.json" and
      .provenance.binary == "build/remote_parent_jni_benchmark" and
      (.provenance.binary_sha256 | test("^[0-9a-f]{64}$")) and
      .limitations.jvm_transition_measured == false and
      .limitations.application_request_measured == false
    )
  ' "$artifact" >/dev/null || return 1
  artifact_directory="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  artifact_root="$(cd -- "$artifact_directory/.." && pwd -P)" || return 1
  for link in \
    "$(jq -er '.provenance.host_environment' "$artifact")" \
    "$(jq -er '.provenance.raw_output' "$artifact")" \
    "$(jq -er '.provenance.raw_stderr' "$artifact")" \
    "$(jq -er '.provenance.compiler_artifact' "$artifact")" \
    "$(jq -er '.provenance.compiler.version' "$artifact")" \
    "$(jq -er '.provenance.compiler.build_command' "$artifact")" \
    "$(jq -er '.provenance.compiler.expanded_build_command' "$artifact")" \
    "$(jq -er '.provenance.java_runtime' "$artifact")" \
    "$(jq -er '.provenance.jdk_image_inspection' "$artifact")" \
    "$(jq -er '.provenance.binary' "$artifact")" \
    "$(jq -er '.provenance.source_state' "$artifact")"; do
    validate_relative_artifact_link "$artifact_directory" "$artifact_root" "$link" || return 1
  done
  validate_native_source_state_schema \
    "$artifact_directory/$(jq -er '.provenance.source_state' "$artifact")" || return 1
  [[ "$(jq -er '.provenance.source_revision' "$artifact")" == \
    "$(jq -er '.revision' "$artifact_directory/source-state.json")" ]] || return 1
  compiler_path="$(jq -er '.provenance.compiler.canonical_path' "$artifact")" || return 1
  jq -e --slurpfile compiler "$artifact_directory/compiler-provenance.json" \
    '.provenance.compiler == $compiler[0]' "$artifact" >/dev/null || return 1
  for link in ../host-environment.txt raw.txt compiler-provenance.json \
    compiler-version.txt build-command.txt expanded-build-command.txt \
    java-version.txt jdk-image.json source-state.json \
    build/remote_parent_jni_benchmark; do
    [[ -s "$artifact_directory/$link" ]] || return 1
  done
  [[ "$(wc -l <"$artifact_directory/build-command.txt")" == 1 ]] || return 1
  grep -Eq -- '^\( exec -c .*env -i .*PATH=/usr/bin:/bin LC_ALL=C .*timeout .*make .* \)$' \
    "$artifact_directory/build-command.txt" || return 1
  validate_native_expanded_build_command \
    "$artifact_directory/expanded-build-command.txt" "$compiler_path" || return 1
  jq -se 'length == 1' "$artifact_directory/jdk-image.json" >/dev/null || return 1
  is_absolute_regular_executable "$compiler_path" || return 1
  compiler_sha256="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_SHA256_COMMAND" -- "$compiler_path")" || return 1
  compiler_sha256="${compiler_sha256%% *}"
  [[ "$compiler_sha256" == "$(jq -er '.provenance.compiler.executable_sha256' "$artifact")" ]] || return 1
  binary_sha256="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_SHA256_COMMAND" -- \
    "$artifact_directory/$(jq -er '.provenance.binary' "$artifact")")" || return 1
  binary_sha256="${binary_sha256%% *}"
  [[ "$binary_sha256" == "$(jq -er '.provenance.binary_sha256' "$artifact")" ]] || return 1
  validate_native_raw_reconciliation "$artifact"
}

normalize_native_jni_benchmark() {
  local -r raw_output="$1"
  local -r binary_sha256="$2"
  local -r source_revision="$3"
  local -r header_image="$4"
  local -r compiler_provenance="$5"
  local -r source_state="$6"
  local -r output="$7"
  local index=0
  local expected_transport=""
  local expected_outcome=""
  local expected_status=0
  local transport_field=""
  local outcome_field=""
  local warmup_field=""
  local iterations_field=""
  local elapsed_field=""
  local nanos_per_operation_field=""
  local p50_field=""
  local p95_field=""
  local p99_field=""
  local operations_per_second_field=""
  local status_field=""
  local checksum_field=""
  local extra=""
  local warmup=""
  local iterations=""
  local elapsed=""
  local p50=""
  local p95=""
  local p99=""
  local status=""
  local checksum=""
  local nanos_per_operation=""
  local operations_per_second=""
  local row_json=""
  local rows_json=""
  local -a lines=()
  local -a rows=()
  local -a expected_series=(
    getsockopt:hit:1 getsockopt:miss:2 getsockopt:failure:12
    unix:hit:1 unix:miss:2 unix:failure:12
  )

  [[ -f "$raw_output" && ! -L "$raw_output" &&
    "$binary_sha256" =~ ^[0-9a-f]{64}$ &&
    "$source_revision" =~ ^[0-9a-f]{40}$ &&
    -f "$compiler_provenance" && ! -L "$compiler_provenance" &&
    -f "$source_state" && ! -L "$source_state" &&
    "$header_image" =~ ^maven:[^@]+@sha256:[0-9a-f]{64}$ ]] || return 1
  jq -se 'length == 1' "$compiler_provenance" >/dev/null || return 1
  validate_native_source_state_schema "$source_state" || return 1
  [[ "$(jq -er '.revision' "$source_state")" == "$source_revision" ]] || return 1
  mapfile -t lines <"$raw_output" || return 1
  [[ ${#lines[@]} == 7 &&
    "${lines[0]}" == "benchmark=obi_java_remote_parent_native getsockopt_backend=deterministic_syscall_shim" ]] || return 1
  for ((index = 0; index < ${#expected_series[@]}; index++)); do
    IFS=: read -r expected_transport expected_outcome expected_status \
      <<<"${expected_series[$index]}" || return 1
    read -r \
      transport_field outcome_field warmup_field iterations_field elapsed_field \
      nanos_per_operation_field p50_field p95_field p99_field \
      operations_per_second_field status_field checksum_field extra \
      <<<"${lines[$((index + 1))]}" || return 1
    [[ -z "$extra" &&
      "$transport_field" == "transport=$expected_transport" &&
      "$outcome_field" == "outcome=$expected_outcome" &&
      "$warmup_field" == warmup_iterations=* &&
      "$iterations_field" == iterations=* &&
      "$elapsed_field" == elapsed_ns=* &&
      "$nanos_per_operation_field" == ns_per_op=* &&
      "$p50_field" == p50_ns=* && "$p95_field" == p95_ns=* &&
      "$p99_field" == p99_ns=* &&
      "$operations_per_second_field" == ops_per_second=* &&
      "$status_field" == status=* && "$checksum_field" == checksum=* ]] || return 1
    warmup="$(normalize_decimal "${warmup_field#*=}" "$JNI_BENCHMARK_ITERATIONS" true)" || return 1
    iterations="$(normalize_decimal "${iterations_field#*=}" "$JNI_BENCHMARK_ITERATIONS" false)" || return 1
    elapsed="$(normalize_decimal "${elapsed_field#*=}" "$MAX_SEED" false)" || return 1
    p50="$(normalize_decimal "${p50_field#*=}" "$MAX_SEED" false)" || return 1
    p95="$(normalize_decimal "${p95_field#*=}" "$MAX_SEED" false)" || return 1
    p99="$(normalize_decimal "${p99_field#*=}" "$MAX_SEED" false)" || return 1
    status="$(normalize_decimal "${status_field#*=}" 255 true)" || return 1
    checksum="$(normalize_decimal "${checksum_field#*=}" "$MAX_SEED" false)" || return 1
    nanos_per_operation="${nanos_per_operation_field#*=}"
    operations_per_second="${operations_per_second_field#*=}"
    [[ "$warmup" == 1000 && "$iterations" == "$JNI_BENCHMARK_ITERATIONS" &&
      "$status" == "$expected_status" &&
      "$checksum" == "$((expected_status * JNI_BENCHMARK_ITERATIONS))" &&
      "$nanos_per_operation" =~ ^(0|[1-9][0-9]*)\.[0-9]{2}$ &&
      "$operations_per_second" =~ ^(0|[1-9][0-9]*)\.[0-9]{2}$ ]] || return 1
    row_json="$(jq -cn \
      --arg transport "$expected_transport" \
      --arg outcome "$expected_outcome" \
      --argjson warmup "$warmup" \
      --argjson iterations "$iterations" \
      --argjson elapsed "$elapsed" \
      --argjson nanos_per_operation "$nanos_per_operation" \
      --argjson p50 "$p50" \
      --argjson p95 "$p95" \
      --argjson p99 "$p99" \
      --argjson operations_per_second "$operations_per_second" \
      --argjson status "$status" \
      --argjson checksum "$checksum" '
        {
          transport: $transport,
          outcome: $outcome,
          warmup_iterations: $warmup,
          iterations: $iterations,
          elapsed_nanos: $elapsed,
          nanos_per_operation: $nanos_per_operation,
          latency_p50_nanos: $p50,
          latency_p95_nanos: $p95,
          latency_p99_nanos: $p99,
          operations_per_second: $operations_per_second,
          status_code: $status,
          checksum: $checksum
        }
      ')" || return 1
    rows+=("$row_json")
  done
  rows_json="$(printf '%s\n' "${rows[@]}" | jq -s .)" || return 1
  jq -n \
    --arg source_revision "$source_revision" \
    --arg binary_sha256 "$binary_sha256" \
    --arg header_image "$header_image" \
    --argjson iterations "$JNI_BENCHMARK_ITERATIONS" \
    --argjson rows "$rows_json" \
    --slurpfile compiler "$compiler_provenance" '
      {
        schema_version: 1,
        kind: "native-jni-lookup-benchmark",
        benchmark: "obi_java_remote_parent_native",
        status: "passed",
        acceptance_evidence: false,
        iterations: $iterations,
        warmup_iterations: 1000,
        fixture_scope: {
          application_path: false,
          getsockopt: "deterministic_syscall_shim",
          unix: "deterministic_abstract_socket_responder"
        },
        series: $rows,
        provenance: {
          source_revision: $source_revision,
          source_state: "source-state.json",
          host_environment: "../host-environment.txt",
          raw_output: "raw.txt",
          raw_stderr: "raw.stderr.log",
          compiler: $compiler[0],
          compiler_artifact: "compiler-provenance.json",
          java_runtime: "java-version.txt",
          jdk_header_image: $header_image,
          jdk_image_inspection: "jdk-image.json",
          binary: "build/remote_parent_jni_benchmark",
          binary_sha256: $binary_sha256
        },
        limitations: {
          jvm_transition_measured: false,
          application_request_measured: false,
          note: "This deterministic native fixture measures the production C transport/provider implementation; application end-to-end rows are retained separately."
        }
      }
  ' >"$output"
}

validate_native_raw_reconciliation() (
  local -r artifact="$1"
  local artifact_directory=""
  local expected=""

  [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
  artifact_directory="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  expected="$(mktemp "$artifact_directory/.native-reconciled.XXXXXX")" || return 1
  trap 'rm -f -- "$expected"' EXIT
  normalize_native_jni_benchmark \
    "$artifact_directory/raw.txt" \
    "$(jq -er '.provenance.binary_sha256' "$artifact")" \
    "$(jq -er '.provenance.source_revision' "$artifact")" \
    "$(jq -er '.provenance.jdk_header_image' "$artifact")" \
    "$artifact_directory/compiler-provenance.json" \
    "$artifact_directory/source-state.json" "$expected" || return 1
  jq -e --slurpfile expected "$expected" '. == $expected[0]' \
    "$artifact" >/dev/null
)

validate_native_expanded_build_command() {
  local -r expanded_command="$1"
  local -r compiler="$2"
  local flag=""

  [[ -f "$expanded_command" && ! -L "$expanded_command" &&
    "$compiler" == /* ]] || return 1
  awk -v prefix="$compiler " '
    index($0, prefix) == 1 { matches++ }
    END { exit matches == 1 ? 0 : 1 }
  ' "$expanded_command" || return 1
  grep -Fq -- 'src/main/c/io_opentelemetry_obi_java_jni.c' \
    "$expanded_command" || return 1
  grep -Fq -- 'src/test/c/remote_parent_jni_benchmark.c' \
    "$expanded_command" || return 1
  grep -Fq -- 'remote_parent_jni_benchmark' "$expanded_command" || return 1
  for flag in "${NATIVE_BENCHMARK_COMPILE_FLAGS[@]}" \
    "${NATIVE_BENCHMARK_LINK_FLAGS[@]}"; do
    grep -Fq -- "$flag" "$expanded_command" || return 1
  done
}

write_native_make_build_command() {
  local -r output="$1"
  local -r timeout_seconds="$2"
  shift 2
  local argument=""
  local separator=""
  local -a command=(
    "$NATIVE_BENCHMARK_ENV_COMMAND" -i
    "PATH=$NATIVE_BENCHMARK_TRUSTED_PATH" LC_ALL=C
    "$NATIVE_BENCHMARK_TIMEOUT_COMMAND" --signal=TERM --kill-after=10s
    "${timeout_seconds}s" "$NATIVE_BENCHMARK_MAKE_COMMAND" "$@"
  )

  [[ ! -e "$output" && ! -L "$output" && $# -gt 0 ]] || return 1
  {
    printf '( exec -c'
    separator=" "
    for argument in "${command[@]}"; do
      printf '%s%q' "$separator" "$argument"
      separator=" "
    done
    printf ' )\n'
  } >"$output"
}

create_native_build_staging_directory() {
  local staging=""
  local canonical=""
  local current_user_id=""

  staging="$(mktemp -d /tmp/obi-java-native-benchmark.XXXXXXXXXX)" || return 1
  canonical="$(readlink -f -- "$staging")" || {
    cleanup_native_build_staging_directory "$staging" || true
    return 1
  }
  current_user_id="$(id -u)" || {
    cleanup_native_build_staging_directory "$staging" || true
    return 1
  }
  [[ "$canonical" == "$staging" &&
    "$canonical" =~ ^/tmp/obi-java-native-benchmark\.[A-Za-z0-9]+$ &&
    "$current_user_id" =~ ^[0-9]+$ ]] || {
    cleanup_native_build_staging_directory "$staging" || true
    return 1
  }
  chmod 0700 -- "$canonical" || {
    cleanup_native_build_staging_directory "$staging" || true
    return 1
  }
  is_private_owned_directory "$canonical" "$current_user_id" || {
    cleanup_native_build_staging_directory "$staging" || true
    return 1
  }
  printf '%s\n' "$canonical"
}

cleanup_native_build_staging_directory() {
  local -r staging="$1"
  local current_user_id=""

  [[ "$staging" =~ ^/tmp/obi-java-native-benchmark\.[A-Za-z0-9]+$ ]] || return 1
  if [[ ! -e "$staging" && ! -L "$staging" ]]; then
    return 0
  fi
  current_user_id="$(id -u)" || return 1
  is_private_owned_directory "$staging" "$current_user_id" || return 1
  rm -rf -- "$staging"
}

run_native_jni_benchmark() (
  local -r benchmark_directory="$OUTPUT_DIR/native-jni"
  local -r raw_output="$benchmark_directory/raw.txt"
  local -r raw_stderr="$benchmark_directory/raw.stderr.log"
  local -r artifact="$benchmark_directory/benchmark.json"
  local staging_directory=""
  local source_copy_root=""
  local build_directory=""
  local jdk_directory=""
  local agent_directory=""
  local java_dockerfile=""
  local retained_binary=""
  local binary_sha256=""
  local compiler_sha256=""
  local compiler_sha256_after=""
  local compile_flags_json=""
  local header_image=""
  local link_flags_json=""
  local current_user_id=""
  local current_group_id=""
  local source_revision=""
  local -a make_arguments=()

  [[ "$CELLS_MODE" == "complete" && ! -e "$benchmark_directory" &&
    ! -L "$benchmark_directory" &&
    -n "$NATIVE_BENCHMARK_COMPILER" &&
    -n "$NATIVE_BENCHMARK_COMPILER_SELECTION" ]] || return 1
  mkdir -- "$benchmark_directory"
  mkdir -- "$benchmark_directory/build"
  staging_directory="$(create_native_build_staging_directory)" || return 1
  trap 'cleanup_native_build_staging_directory "$staging_directory"' EXIT
  source_copy_root="$staging_directory/repository"
  build_directory="$staging_directory/build"
  jdk_directory="$staging_directory/jdk"
  agent_directory="$source_copy_root/pkg/internal/java/agent"
  java_dockerfile="$source_copy_root/examples/apache-java-https/java/Dockerfile"
  retained_binary="$benchmark_directory/build/remote_parent_jni_benchmark"
  capture_native_source_snapshot \
    "$REPO_ROOT" "$benchmark_directory/source-state-before.json" || return 1
  copy_native_source_snapshot \
    "$REPO_ROOT" "$benchmark_directory/source-state-before.json" \
    "$source_copy_root" || return 1
  header_image="$(awk '
    $1 == "FROM" && $2 ~ /^maven:[^@[:space:]]+@sha256:[0-9a-f]{64}$/ &&
      $3 == "AS" && $4 == "builder" { matches++; image = $2 }
    END { if (matches != 1) exit 1; print image }
  ' "$java_dockerfile")" || return 1
  current_user_id="$(id -u)" || return 1
  current_group_id="$(id -g)" || return 1
  [[ "$current_user_id" =~ ^[0-9]+$ && "$current_group_id" =~ ^[0-9]+$ ]] || return 1
  mkdir -- "$build_directory" "$jdk_directory" "$jdk_directory/include"
  # shellcheck disable=SC2016 # JAVA_HOME expands inside the pinned JDK container.
  if ! run_bounded "$JNI_BENCHMARK_TIMEOUT_SECONDS" docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user "$current_user_id:$current_group_id" \
    --mount "type=bind,src=$jdk_directory/include,dst=/output" \
    --entrypoint /bin/sh \
    "$header_image" \
    -ec 'test -d "$JAVA_HOME/include/linux"; cp -R "$JAVA_HOME/include/." /output/' \
    >"$benchmark_directory/jdk-header-extraction.log" \
    2>"$benchmark_directory/jdk-header-extraction.stderr.log"; then
    return 1
  fi
  run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker image inspect "$header_image" \
    >"$benchmark_directory/jdk-image.json" || return 1
  compiler_sha256="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_SHA256_COMMAND" -- "$NATIVE_BENCHMARK_COMPILER")" || return 1
  compiler_sha256="${compiler_sha256%% *}"
  [[ "$compiler_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  run_native_bounded 15 "$NATIVE_BENCHMARK_COMPILER" --version \
    >"$benchmark_directory/compiler-version.txt" 2>&1 || return 1
  compile_flags_json="$(jq -cn --args '$ARGS.positional' -- \
    "${NATIVE_BENCHMARK_COMPILE_FLAGS[@]}")" || return 1
  link_flags_json="$(jq -cn --args '$ARGS.positional' -- \
    "${NATIVE_BENCHMARK_LINK_FLAGS[@]}")" || return 1
  make_arguments=(
    --silent --directory "$agent_directory" --file Makefile.jni
    benchmark
    "CC=$NATIVE_BENCHMARK_COMPILER"
    "BUILD_DIR=$build_directory"
    "JAVA_HOME=$jdk_directory"
    "BENCHMARK_ITERATIONS=$JNI_BENCHMARK_ITERATIONS"
  )
  write_native_make_build_command \
    "$benchmark_directory/build-command.txt" "$JNI_BENCHMARK_TIMEOUT_SECONDS" \
    "${make_arguments[@]}" || return 1
  if ! run_native_bounded "$JNI_BENCHMARK_TIMEOUT_SECONDS" \
    "$NATIVE_BENCHMARK_MAKE_COMMAND" \
    --no-print-directory --dry-run --always-make \
    --directory "$agent_directory" --file Makefile.jni \
    benchmark \
    "CC=$NATIVE_BENCHMARK_COMPILER" \
    "BUILD_DIR=$build_directory" \
    "JAVA_HOME=$jdk_directory" \
    "BENCHMARK_ITERATIONS=$JNI_BENCHMARK_ITERATIONS" \
    >"$benchmark_directory/expanded-build-command.txt" 2>&1; then
    return 1
  fi
  validate_native_expanded_build_command \
    "$benchmark_directory/expanded-build-command.txt" \
    "$NATIVE_BENCHMARK_COMPILER" || return 1
  jq -n \
    --arg canonical_path "$NATIVE_BENCHMARK_COMPILER" \
    --arg executable_sha256 "$compiler_sha256" \
    --arg selection "$NATIVE_BENCHMARK_COMPILER_SELECTION" \
    --argjson compile_flags "$compile_flags_json" \
    --argjson link_flags "$link_flags_json" '
      {
        canonical_path: $canonical_path,
        executable_sha256: $executable_sha256,
        selection: $selection,
        pinned_for_make: true,
        environment: {
          policy: "empty_parent_environment_with_explicit_allowlist",
          parent_environment: {
            path: "/usr/bin:/bin",
            locale: "C",
            allowed_variables: ["PATH", "LC_ALL"],
            dynamic_loader_parent_cleared: true
          },
          controlled_make_environment: {
            command_line_variables: ["BENCHMARK_ITERATIONS", "BUILD_DIR", "CC", "JAVA_HOME"],
            make_generated_variables: ["MAKEFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "MFLAGS"],
            working_directory: "private_source_snapshot"
          }
        },
        version: "compiler-version.txt",
        compile_flags: $compile_flags,
        link_flags: $link_flags,
        build_command: "build-command.txt",
        expanded_build_command: "expanded-build-command.txt"
      }
    ' >"$benchmark_directory/compiler-provenance.json" || return 1
  if ! run_native_bounded "$JNI_BENCHMARK_TIMEOUT_SECONDS" \
    "$NATIVE_BENCHMARK_MAKE_COMMAND" "${make_arguments[@]}" \
      >"$raw_output" 2>"$raw_stderr"; then
    return 1
  fi
  compiler_sha256_after="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_SHA256_COMMAND" -- "$NATIVE_BENCHMARK_COMPILER")" || return 1
  compiler_sha256_after="${compiler_sha256_after%% *}"
  [[ "$compiler_sha256_after" == "$compiler_sha256" ]] || return 1
  capture_native_source_snapshot \
    "$REPO_ROOT" "$benchmark_directory/source-state-after.json" || return 1
  finalize_native_source_state \
    "$benchmark_directory/source-state-before.json" \
    "$benchmark_directory/source-state-after.json" \
    "$benchmark_directory/source-state.json" || return 1
  validate_native_source_state_schema "$benchmark_directory/source-state.json" || return 1
  [[ -x "$build_directory/remote_parent_jni_benchmark" &&
    -f "$build_directory/remote_parent_jni_benchmark" &&
    ! -L "$build_directory/remote_parent_jni_benchmark" ]] || return 1
  install -m 0700 -- "$build_directory/remote_parent_jni_benchmark" \
    "$retained_binary" || return 1
  binary_sha256="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_SHA256_COMMAND" -- "$retained_binary")" || return 1
  binary_sha256="${binary_sha256%% *}"
  source_revision="$(jq -er '.revision' "$benchmark_directory/source-state.json")" || return 1
  run_bounded "$JNI_BENCHMARK_TIMEOUT_SECONDS" docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user "$current_user_id:$current_group_id" \
    --entrypoint java \
    "$header_image" -version \
    >"$benchmark_directory/java-version.txt" 2>&1 || return 1
  normalize_native_jni_benchmark \
    "$raw_output" "$binary_sha256" "$source_revision" "$header_image" \
    "$benchmark_directory/compiler-provenance.json" \
    "$benchmark_directory/source-state.json" "$artifact" || return 1
  validate_native_jni_benchmark_schema "$artifact" || return 1
  cleanup_native_build_staging_directory "$staging_directory" || return 1
  staging_directory=""
  trap - EXIT
)

write_cell_contract() {
  local -r cell_dir="$1"

  mkdir -- "$cell_dir/preflight"
  jq -n \
    --arg cell "$CELL_SLUG" \
    --arg transport "$CELL_TRANSPORT" \
    --arg scenario "$CELL_SCENARIO" \
    --arg assertion_mode "$CELL_ASSERTION_MODE" \
    --arg selected_transport "$CELL_SELECTED_TRANSPORT" \
    --arg sentinel_scenario "$CELL_SENTINEL_SCENARIO" \
    --arg workload_base_url "$CELL_WORKLOAD_BASE_URL" \
    --arg workload_path "$CELL_WORKLOAD_PATH" \
    --arg workload_connection_mode "$CELL_WORKLOAD_CONNECTION_MODE" \
    --arg workload_ca_file "$CELL_WORKLOAD_CA_FILE" \
    --arg expected_tls_verification "$CELL_EXPECTED_TLS_VERIFICATION" \
    --arg upstream_handoff "$CELL_UPSTREAM_HANDOFF" \
    --arg path_classification "$CELL_PATH_CLASSIFICATION" \
    --arg expected_java_status "$CELL_EXPECTED_JAVA_STATUS" \
    --argjson requests "$CELL_PREFLIGHT_REQUESTS" \
    --argjson seed "$SEED" \
    --argjson requires_obi "$CELL_REQUIRES_OBI" \
    --argjson sustained_w3c "$CELL_SUSTAINED_W3C" \
    --argjson helper_idle "$CELL_HELPER_IDLE" \
    --argjson bounded_path "$CELL_BOUNDED_PATH" \
    --argjson expected_standard_parent_discards "$CELL_EXPECTED_STANDARD_PARENT_DISCARDS" \
    --argjson expected_w3c_valid_takes "$CELL_EXPECTED_W3C_VALID_TAKES" \
    '{
      cell: $cell,
      transport: $transport,
      scenario: $scenario,
      assertion_mode: ($assertion_mode | if . == "" then null else . end),
      selected_transport: $selected_transport,
      sentinel_scenario: $sentinel_scenario,
      workload: {
        base_url: $workload_base_url,
        path: $workload_path,
        connection_mode: $workload_connection_mode,
        ca_file: ($workload_ca_file | if . == "" then null else . end),
        tls_verification: $expected_tls_verification,
        upstream_handoff: $upstream_handoff
      },
      helper_idle_direct_java: $helper_idle,
      state_map_absence_proof: false,
      bounded_correctness_observation: $bounded_path,
      path_classification: ($path_classification | if . == "" then null else . end),
      expected_java_status: ($expected_java_status | if . == "" then null else . end),
      requests: $requests,
      seed: $seed,
      requires_obi: $requires_obi,
      sustained_w3c: $sustained_w3c,
      expected_standard_parent_discards: $expected_standard_parent_discards,
      expected_w3c_valid_takes: $expected_w3c_valid_takes
    }' >"$cell_dir/preflight/contract.json"
}

runner_result_directory() {
  local -r runner_log="$1"
  local candidate=""
  local -a candidates=()

  mapfile -t candidates < <(
    awk '/retained run evidence: / {
      sub(/^.*retained run evidence: /, "")
      print
    }' "$runner_log"
  )
  ((${#candidates[@]} == 1)) || return 1
  candidate="${candidates[0]}"
  [[ "$candidate" == "$RESULTS_ROOT"/* && -d "$candidate" && ! -L "$candidate" ]] || return 1
  assert_no_symlink_components "$candidate" || return 1
  printf '%s\n' "$candidate"
}

validate_runner_result() {
  local -r result_directory="$1"

  [[ -f "$result_directory/run-status.json" && ! -L "$result_directory/run-status.json" ]] || return 1
  jq -se --arg result_directory "$result_directory" '
    length == 1 and
    (.[0] |
      .status == "passed" and
      .exit_status == 0 and
      .evidence_directory == $result_directory
    )
  ' "$result_directory/run-status.json" >/dev/null
}

runner_environment_value() {
  local -r environment_file="$1"
  local -r key="$2"
  local line=""
  local value=""
  local matches=0

  [[ -f "$environment_file" && ! -L "$environment_file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "$key="* ]]; then
      value="${line#*=}"
      ((matches += 1))
    fi
  done <"$environment_file"
  ((matches == 1)) || return 1
  [[ "$value" != *$'\r'* ]] || return 1
  printf '%s\n' "$value"
}

runner_environment_matches() {
  local -r environment_file="$1"
  local -r key="$2"
  local -r expected="$3"
  local actual=""

  actual="$(runner_environment_value "$environment_file" "$key")" || return 1
  [[ "$actual" == "$expected" ]]
}

validate_runner_environment() {
  local -r result_directory="$1"
  local -r environment_file="$result_directory/environment.txt"

  runner_environment_matches "$environment_file" transport "$CELL_TRANSPORT" &&
    runner_environment_matches "$environment_file" agent_distribution "$AGENT" &&
    runner_environment_matches "$environment_file" tls_protocol "$TLS_PROTOCOL" &&
    runner_environment_matches "$environment_file" scenario "$CELL_SCENARIO" &&
    runner_environment_matches "$environment_file" request_count "$CELL_PREFLIGHT_REQUESTS" &&
    runner_environment_matches "$environment_file" repeat_count 1 &&
    runner_environment_matches "$environment_file" scenario_seed "$SEED" &&
    runner_environment_matches "$environment_file" compose_project "$ACTIVE_PROJECT"
}

retain_required_runner_file() {
  local -r result_directory="$1"
  local -r destination="$2"
  local -r filename="$3"
  local source="$result_directory/$filename"

  [[ -f "$source" && ! -L "$source" ]] || return 1
  install -m 0600 "$source" "$destination/$filename"
  printf '%s\n' "$filename"
}

retain_runner_phase_artifacts() {
  local -r result_directory="$1"
  local -r destination="$2"
  local source=""
  local relative=""
  local retained=0

  [[ -d "$result_directory/phases" && ! -L "$result_directory/phases" ]] || return 1
  while IFS= read -r -d '' source; do
    relative="${source#"$result_directory"/}"
    mkdir -p -- "$destination/${relative%/*}"
    install -m 0600 "$source" "$destination/$relative"
    ((retained += 1))
  done < <(find "$result_directory/phases" -type f -print0)
  ((retained > 0))
}

retain_runner_artifacts() {
  local -r result_directory="$1"
  local -r cell_dir="$2"
  local -r destination="$cell_dir/preflight/runner"
  local file=""
  local transport_configuration_artifacts="not_applicable"
  local -a retained=()
  local -a required=(
    run-status.json
    environment.txt
    source-state.txt
    source-tree.manifest
    git-status.txt
    official-javaagent.json
    bridge-artifacts.json
    bridge-artifacts.sha256
    bridge-metadata.sha256
    bridge-source-revision.txt
    bridge-source-tree.sha256
    certificates.json
    compose-resolved.yaml
    compose-up.log
    compose-ps.txt
    compose.log
    compose-images.json
    container-identities.txt
    image-identities.txt
    host-topology.txt
    bpftool-feature-probe.txt
    bpftool-programs.txt
    bpftool-maps.txt
    java-version.txt
    apache-version.txt
    apache-openssl-version.txt
    obi-startup.log
    java-startup.log
    apache-startup.log
    final-receiver-snapshot.json
    "scenario-$CELL_SENTINEL_SCENARIO.json"
    "scenario-$CELL_SENTINEL_SCENARIO-status.json"
    "scenario-$CELL_SENTINEL_SCENARIO.stderr.log"
  )

  required+=("${CELL_EXTRA_RUNNER_FILES[@]}")

  if [[ "$CELL_TRANSPORT" != "disabled" ]]; then
    transport_configuration_artifacts="retained"
    required+=(
      java-transport-configuration.txt
      java-selected-transport-configuration.txt
    )
  fi

  mkdir -- "$destination"
  for file in "${required[@]}"; do
    retain_required_runner_file "$result_directory" "$destination" "$file" >/dev/null || return 1
    retained+=("$file")
  done
  retain_runner_phase_artifacts "$result_directory" "$destination" || return 1
  jq -n --arg result_directory "$result_directory" \
    --arg transport_configuration_artifacts "$transport_configuration_artifacts" \
    '{
      runner_result_directory: $result_directory,
      retained_files: $ARGS.positional,
      transport_configuration_artifacts: $transport_configuration_artifacts
    }' \
    --args "${retained[@]}" >"$destination/provenance.json"
}

compose_service_id() {
  local -r service="$1"
  local container_id=""

  container_id="$(run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" ps --quiet "$service")" || return 1
  [[ "$container_id" =~ ^[0-9a-f]{12,64}$ ]] || return 1
  printf '%s\n' "$container_id"
}

proc_cgroup_binds_container_id() {
  local -r cgroup_file="$1"
  local -r container_id="$2"

  [[ -f "$cgroup_file" && ! -L "$cgroup_file" &&
    "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  awk -v container_id="$container_id" '
    $0 ~ ("(^|[^0-9A-Fa-f])" container_id "([^0-9A-Fa-f]|$)") {
      matched = 1
    }
    END { exit matched == 1 ? 0 : 1 }
  ' "$cgroup_file"
}

proc_identity_from_root() {
  local -r proc_root="$1"
  local -r host_pid="$2"
  local -r container_id="$3"
  local -r process_directory="$proc_root/$host_pid"
  local start_time=""
  local cgroup_size=""
  local cgroup_sha256=""

  [[ "$proc_root" == /* && -d "$proc_root" && ! -L "$proc_root" &&
    "$host_pid" =~ ^[1-9][0-9]*$ && "$container_id" =~ ^[0-9a-f]{64}$ &&
    -d "$process_directory" && ! -L "$process_directory" &&
    -r "$process_directory/stat" && -f "$process_directory/stat" &&
    ! -L "$process_directory/stat" && -f "$process_directory/cgroup" &&
    ! -L "$process_directory/cgroup" ]] || return 1
  start_time="$(awk '
    match($0, /^[0-9]+ \(.*\) /) == 0 { exit 1 }
    {
      fields_count = split(substr($0, RLENGTH + 1), fields, " ")
      if (fields_count < 20 || fields[1] == "Z" ||
          fields[20] !~ /^[1-9][0-9]*$/) {
        exit 1
      }
      print fields[20]
    }
  ' "$process_directory/stat" 2>/dev/null)" || return 1
  cgroup_size="$(wc -c <"$process_directory/cgroup")" || return 1
  [[ "$cgroup_size" =~ ^[1-9][0-9]*$ &&
    "$cgroup_size" -le "$MAX_PROC_CGROUP_BYTES" ]] || return 1
  proc_cgroup_binds_container_id "$process_directory/cgroup" "$container_id" || return 1
  cgroup_sha256="$(sha256_regular_file "$process_directory/cgroup")" || return 1
  printf '%s %s %s\n' \
    "$start_time" "$cgroup_sha256" "$PROC_CGROUP_CONTAINER_BINDING"
}

local_proc_identity() {
  local -r host_pid="$1"
  local -r container_id="$2"

  # Production is intentionally fixed to the kernel procfs. Tests exercise
  # copied proc fixtures through proc_identity_from_root directly; no caller
  # environment or CLI option can redirect the production sampling root.
  proc_identity_from_root /proc "$host_pid" "$container_id"
}

capture_service_identity() {
  local -r service="$1"
  local -r output="$2"
  local container_id=""
  local inspected_id=""
  local host_pid=""
  local project=""
  local sentinel=""
  local extra=""
  local inspection_before=""
  local inspection_after=""
  local proc_identity_before=""
  local proc_identity_after=""
  local proc_start_time=""
  local proc_cgroup_sha256=""
  local proc_cgroup_container_binding=""

  container_id="$(compose_service_id "$service")" || return 1
  inspection_before="$(run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker inspect --format \
    "{{.Id}} {{.State.Pid}} {{index .Config.Labels \"com.docker.compose.project\"}} {{index .Config.Labels \"$PROJECT_SENTINEL_LABEL\"}}" \
    "$container_id")" || return 1
  read -r inspected_id host_pid project sentinel extra <<<"$inspection_before" || return 1
  [[ "$inspected_id" =~ ^[0-9a-f]{64}$ && "$inspected_id" == "$container_id"* &&
    "$host_pid" =~ ^[1-9][0-9]*$ &&
    "$project" == "$ACTIVE_PROJECT" && "$sentinel" == "$PROJECT_SENTINEL_VALUE" &&
    -z "$extra" ]] || return 1
  container_id="$inspected_id"
  proc_identity_before="$(local_proc_identity "$host_pid" "$container_id")" || return 1
  inspection_after="$(run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker inspect --format \
    "{{.Id}} {{.State.Pid}} {{index .Config.Labels \"com.docker.compose.project\"}} {{index .Config.Labels \"$PROJECT_SENTINEL_LABEL\"}}" \
    "$container_id")" || return 1
  proc_identity_after="$(local_proc_identity "$host_pid" "$container_id")" || return 1
  [[ "$inspection_after" == "$inspection_before" &&
    "$proc_identity_after" == "$proc_identity_before" ]] || return 1
  read -r proc_start_time proc_cgroup_sha256 proc_cgroup_container_binding extra \
    <<<"$proc_identity_before" || return 1
  [[ "$proc_start_time" =~ ^[1-9][0-9]*$ &&
    "$proc_cgroup_sha256" =~ ^[0-9a-f]{64}$ &&
    "$proc_cgroup_container_binding" == "$PROC_CGROUP_CONTAINER_BINDING" &&
    -z "$extra" ]] || return 1
  {
    printf 'service=%s\n' "$service"
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$host_pid"
    printf 'proc_start_time=%s\n' "$proc_start_time"
    printf 'proc_cgroup_sha256=%s\n' "$proc_cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' "$proc_cgroup_container_binding"
    printf 'project=%s\n' "$project"
    printf 'owner_sentinel=%s\n' "$sentinel"
  } >"$output"
}

identity_field() {
  local -r identity="$1"
  local -r name="$2"
  local line=""
  local value=""
  local matches=0

  while IFS= read -r line; do
    if [[ "$line" == "$name="* ]]; then
      value="${line#*=}"
      ((matches += 1))
    fi
  done <"$identity"
  [[ "$matches" == 1 && -n "$value" ]] || return 1
  printf '%s\n' "$value"
}

capture_proc_snapshot_from_root() {
  local -r identity_file="$1"
  local -r output="$2"
  local -r proc_root="$3"
  local container_id=""
  local host_pid=""
  local expected_start_time=""
  local expected_cgroup_sha256=""
  local expected_cgroup_container_binding=""
  local before_identity=""
  local after_identity=""
  local fd_count=""
  local task_count=""
  local temporary=""

  container_id="$(identity_field "$identity_file" container_id)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  host_pid="$(identity_field "$identity_file" host_pid)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  expected_start_time="$(identity_field "$identity_file" proc_start_time)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  expected_cgroup_sha256="$(identity_field \
    "$identity_file" proc_cgroup_sha256)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  expected_cgroup_container_binding="$(identity_field \
    "$identity_file" proc_cgroup_container_binding)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  [[ "$container_id" =~ ^[0-9a-f]{64}$ && "$host_pid" =~ ^[1-9][0-9]*$ &&
    "$expected_start_time" =~ ^[1-9][0-9]*$ &&
    "$expected_cgroup_sha256" =~ ^[0-9a-f]{64}$ &&
    "$expected_cgroup_container_binding" == "$PROC_CGROUP_CONTAINER_BINDING" &&
    "$proc_root" == /* && -d "$proc_root" && ! -L "$proc_root" &&
    -r "$proc_root/$host_pid/status" && -f "$proc_root/$host_pid/status" &&
    ! -L "$proc_root/$host_pid/status" ]] || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  before_identity="$(proc_identity_from_root \
    "$proc_root" "$host_pid" "$container_id")" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  [[ "$before_identity" == \
    "$expected_start_time $expected_cgroup_sha256 $expected_cgroup_container_binding" ]] || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  fd_count="$(find "$proc_root/$host_pid/fd" -mindepth 1 -maxdepth 1 -printf '.\n' \
    2>/dev/null | wc -l)" || fd_count="unavailable"
  task_count="$(find "$proc_root/$host_pid/task" -mindepth 1 -maxdepth 1 -printf '.\n' \
    2>/dev/null | wc -l)" || task_count="unavailable"
  [[ "$fd_count" =~ ^(0|[1-9][0-9]*)$ && "$task_count" =~ ^[1-9][0-9]*$ ]] || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  temporary="$(mktemp "${output%/*}/.proc-snapshot.XXXXXX")" || return 1
  {
    printf 'status=available\n'
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$host_pid"
    printf 'proc_start_time=%s\n' "$expected_start_time"
    printf 'proc_cgroup_sha256=%s\n' "$expected_cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' "$expected_cgroup_container_binding"
    awk '/^(VmPeak|VmSize|VmRSS|VmData|VmStk|VmExe|VmLib|Threads):/ {print}' \
      "$proc_root/$host_pid/status"
    printf 'fd_count=%s\n' "$fd_count"
    printf 'task_count=%s\n' "$task_count"
    printf 'stat='
    tr '\n' ' ' <"$proc_root/$host_pid/stat"
    printf '\n'
  } >"$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  after_identity="$(proc_identity_from_root \
    "$proc_root" "$host_pid" "$container_id")" || {
    rm -f -- "$temporary"
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  if [[ "$after_identity" != "$before_identity" ]]; then
    rm -f -- "$temporary"
    printf 'status=unavailable\n' >"$output"
    return 0
  fi
  mv -T -- "$temporary" "$output"
}

capture_proc_snapshot() {
  local -r identity_file="$1"
  local -r output="$2"

  capture_proc_snapshot_from_root "$identity_file" "$output" /proc
}

capture_bpf_fd_roster_from_directories() {
  local -r fd_directory="$1"
  local -r fdinfo_directory="$2"
  local -r output="$3"
  local fd_listing=""
  local listing=""
  local fd_entry=""
  local fd_name=""
  local fd_type=""
  local entry_name=""
  local entry_type=""
  local entry_path=""
  local entry_size=""
  local entry_index=0
  local parsed=""
  local entry_copy=""
  local map_count=0
  local -a fd_entries=()
  local -a entries=()

  [[ -d "$fd_directory" && ! -L "$fd_directory" &&
    -d "$fdinfo_directory" && ! -L "$fdinfo_directory" &&
    -f "$output" && ! -L "$output" ]] || return 1
  fd_listing="$(find "$fd_directory" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' 2>/dev/null)" || return 1
  listing="$(find "$fdinfo_directory" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' 2>/dev/null)" || return 1
  if [[ -n "$fd_listing" ]]; then
    mapfile -t fd_entries < <(printf '%s\n' "$fd_listing" | sort -t $'\t' -k1,1n)
  fi
  if [[ -n "$listing" ]]; then
    mapfile -t entries < <(printf '%s\n' "$listing" | sort -t $'\t' -k1,1n)
  fi
  ((${#entries[@]} > 0 && ${#entries[@]} <= MAX_BPF_FDINFO_FILES &&
    ${#fd_entries[@]} == ${#entries[@]})) || return 1
  : >"$output" || return 1
  entry_copy="$(mktemp "${output%/*}/.bpf-fdinfo.XXXXXX")" || return 1
  for ((entry_index = 0; entry_index < ${#entries[@]}; entry_index++)); do
    parsed="${entries[entry_index]}"
    fd_entry="${fd_entries[entry_index]}"
    IFS=$'\t' read -r fd_name fd_type <<<"$fd_entry" || {
      rm -f -- "$entry_copy"
      return 1
    }
    IFS=$'\t' read -r entry_name entry_type <<<"$parsed" || {
      rm -f -- "$entry_copy"
      return 1
    }
    [[ "$fd_name" =~ ^(0|[1-9][0-9]*)$ && "$fd_type" == l &&
      "$entry_name" == "$fd_name" && "$entry_type" == f ]] || {
      rm -f -- "$entry_copy"
      return 1
    }
    entry_path="$fdinfo_directory/$entry_name"
    [[ -f "$entry_path" && ! -L "$entry_path" ]] || {
      rm -f -- "$entry_copy"
      return 1
    }
    if ! head -c "$((MAX_BPF_FDINFO_BYTES + 1))" -- "$entry_path" >"$entry_copy"; then
      rm -f -- "$entry_copy"
      return 1
    fi
    entry_size="$(wc -c <"$entry_copy")" || {
      rm -f -- "$entry_copy"
      return 1
    }
    [[ "$entry_size" =~ ^(0|[1-9][0-9]*)$ &&
      "$entry_size" -le "$MAX_BPF_FDINFO_BYTES" ]] || {
      rm -f -- "$entry_copy"
      return 1
    }
    if ! parsed="$(awk '
      /^(map_id|prog_id):/ {
        if ($0 !~ /^(map_id|prog_id):[[:space:]]+[1-9][0-9]*$/) {
          invalid = 1
          next
        }
        kind = $1
        sub(/:$/, "", kind)
        if (++seen[kind] != 1 || ++identities != 1) {
          invalid = 1
          next
        }
        print kind "=" $2
      }
      END { if (invalid) exit 1 }
    ' "$entry_copy")"; then
      rm -f -- "$entry_copy"
      return 1
    fi
    if [[ -n "$parsed" ]]; then
      printf 'fd=%s %s\n' "$entry_name" "$parsed" >>"$output" || {
        rm -f -- "$entry_copy"
        return 1
      }
    fi
  done
  rm -f -- "$entry_copy" || return 1
  map_count="$(awk '$2 ~ /^map_id=/ {
      split($2, identity, "="); ids[identity[2]] = 1
    } END { print length(ids) }' \
    "$output")" || return 1
  [[ "$map_count" =~ ^[1-9][0-9]*$ ]]
}

capture_bpf_fd_ownership_from_root() {
  local -r identity_file="$1"
  local -r output="$2"
  local -r proc_root="$3"
  local container_id=""
  local host_pid=""
  local expected_start_time=""
  local expected_cgroup_sha256=""
  local expected_cgroup_container_binding=""
  local before_identity=""
  local after_identity=""
  local fd_directory=""
  local fdinfo_directory=""
  local temporary=""
  local first_roster=""
  local second_roster=""

  container_id="$(identity_field "$identity_file" container_id)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  host_pid="$(identity_field "$identity_file" host_pid)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  expected_start_time="$(identity_field "$identity_file" proc_start_time)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  expected_cgroup_sha256="$(identity_field \
    "$identity_file" proc_cgroup_sha256)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  expected_cgroup_container_binding="$(identity_field \
    "$identity_file" proc_cgroup_container_binding)" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  fd_directory="$proc_root/$host_pid/fd"
  fdinfo_directory="$proc_root/$host_pid/fdinfo"
  [[ "$container_id" =~ ^[0-9a-f]{64}$ && "$host_pid" =~ ^[1-9][0-9]*$ &&
    "$expected_start_time" =~ ^[1-9][0-9]*$ &&
    "$expected_cgroup_sha256" =~ ^[0-9a-f]{64}$ &&
    "$expected_cgroup_container_binding" == "$PROC_CGROUP_CONTAINER_BINDING" &&
    "$proc_root" == /* && -d "$proc_root" && ! -L "$proc_root" &&
    -d "$fd_directory" && ! -L "$fd_directory" &&
    -d "$fdinfo_directory" && ! -L "$fdinfo_directory" ]] || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  before_identity="$(proc_identity_from_root \
    "$proc_root" "$host_pid" "$container_id")" || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  [[ "$before_identity" == \
    "$expected_start_time $expected_cgroup_sha256 $expected_cgroup_container_binding" ]] || {
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  temporary="$(mktemp "${output%/*}/.bpf-fd-ownership.XXXXXX")" || return 1
  first_roster="$(mktemp "${output%/*}/.bpf-fd-roster-first.XXXXXX")" || {
    rm -f -- "$temporary"
    return 1
  }
  second_roster="$(mktemp "${output%/*}/.bpf-fd-roster-second.XXXXXX")" || {
    rm -f -- "$temporary" "$first_roster"
    return 1
  }
  if ! capture_bpf_fd_roster_from_directories \
      "$fd_directory" "$fdinfo_directory" "$first_roster" ||
    ! capture_bpf_fd_roster_from_directories \
      "$fd_directory" "$fdinfo_directory" "$second_roster" ||
    ! cmp -s -- "$first_roster" "$second_roster"; then
    rm -f -- "$temporary" "$first_roster" "$second_roster"
    printf 'status=unavailable\n' >"$output"
    return 0
  fi
  {
    printf 'status=available\n'
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$host_pid"
    printf 'proc_start_time=%s\n' "$expected_start_time"
    printf 'proc_cgroup_sha256=%s\n' "$expected_cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' \
      "$expected_cgroup_container_binding"
    cat -- "$first_roster"
  } >"$temporary" || {
    rm -f -- "$temporary" "$first_roster" "$second_roster"
    return 1
  }
  after_identity="$(proc_identity_from_root \
    "$proc_root" "$host_pid" "$container_id")" || {
    rm -f -- "$temporary" "$first_roster" "$second_roster"
    printf 'status=unavailable\n' >"$output"
    return 0
  }
  rm -f -- "$first_roster" "$second_roster" || {
    rm -f -- "$temporary"
    return 1
  }
  if [[ "$after_identity" != "$before_identity" ]]; then
    rm -f -- "$temporary"
    printf 'status=unavailable\n' >"$output"
    return 0
  fi
  mv -T -- "$temporary" "$output"
}

capture_bpf_fd_ownership() {
  local -r identity_file="$1"
  local -r output="$2"

  capture_bpf_fd_ownership_from_root "$identity_file" "$output" /proc
}

capture_obi_metrics() {
  local -r output="$1"

  if [[ "$CELL_REQUIRES_OBI" != "true" ]]; then
    printf 'status=not_applicable\n' >"$output"
    return 0
  fi
  if run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    curl --fail --silent --show-error --max-time 5 \
      "http://127.0.0.1:18990/internal/metrics" >"$output" 2>"$output.stderr"; then
    return 0
  fi
  printf 'status=unavailable\n' >"$output"
  return 0
}

capture_obi_metrics_with_ownership() {
  local -r identity_file="$1"
  local -r ownership_output="$2"
  local -r metrics_output="$3"
  local ownership_before="${ownership_output}.before"
  local ownership_after="${ownership_output}.after"

  [[ "$CELL_REQUIRES_OBI" == "true" ]] || return 1
  [[ ! -e "$ownership_output" && ! -L "$ownership_output" &&
    ! -e "$ownership_before" && ! -L "$ownership_before" &&
    ! -e "$ownership_after" && ! -L "$ownership_after" ]] || return 1
  capture_bpf_fd_ownership "$identity_file" "$ownership_before" || return 1
  capture_obi_metrics "$metrics_output" || return 1
  capture_bpf_fd_ownership "$identity_file" "$ownership_after" || return 1
  if grep -Fxq 'status=available' "$ownership_before" &&
    cmp -s -- "$ownership_before" "$ownership_after"; then
    mv -T -- "$ownership_before" "$ownership_output" || return 1
  else
    rm -f -- "$ownership_before"
    printf 'status=unavailable\n' >"$ownership_output"
  fi
  rm -f -- "$ownership_after"
}

capture_java_diagnostics() {
  local -r output="$1"
  local -r partial="$output.partial"
  local captured_bytes=""

  [[ ! -e "$output" && ! -L "$output" && ! -e "$partial" && ! -L "$partial" ]] || return 1
  if run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    curl --fail --silent --show-error --max-time 5 \
      --max-filesize "$MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES" \
      --cacert "$BENCHMARK_CA_SOURCE" \
      "https://127.0.0.1:18443/obi-diagnostics" 2>"$output.stderr" | \
    head -c "$((MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES + 1))" >"$partial"; then
    captured_bytes="$(stat --format '%s' -- "$partial")" || return 1
    if [[ "$captured_bytes" =~ ^[0-9]+$ &&
      "$captured_bytes" -le "$MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES" ]] &&
      install -m 0600 "$partial" "$output"; then
      rm -f -- "$partial" || return 1
      return 0
    fi
  fi
  rm -f -- "$partial"
  printf 'status=unavailable\n' >"$output"
  return 0
}

capture_resource_snapshot() {
  local -r snapshot_directory="$1"
  local -r timing="$2"
  local -r java_diagnostics_mode="${3:-requested}"
  local service=""
  local container_id=""
  local host_pid=""
  local -a services=(trace-receiver apache-proxy java-backend)
  local -a container_ids=()

  [[ "$timing" == "before" || "$timing" == "after" || "$timing" == "idle_recovery" ||
    "$timing" == "unsynchronized_midpoint" ]] || return 1
  [[ "$java_diagnostics_mode" == requested || "$java_diagnostics_mode" == not_collected ]] || return 1
  if [[ "$java_diagnostics_mode" == not_collected ]]; then
    [[ "$CELL_HELPER_IDLE" == "true" && "$timing" == "unsynchronized_midpoint" ]] || return 1
  fi
  if [[ "$CELL_REQUIRES_OBI" == "true" ]]; then
    services+=(obi)
  fi
  mkdir -- "$snapshot_directory"
  jq -n --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg timing "$timing" \
    --arg cell "$CELL_SLUG" --arg java_diagnostics_mode "$java_diagnostics_mode" \
    '{
      captured_at: $captured_at,
      timing: $timing,
      cell: $cell,
      java_diagnostics: (
        if $java_diagnostics_mode == "requested" then {status: "requested"}
        else {
          status: "not_collected",
          reason: "would_mutate_exact_helper_idle_java_diagnostics_window"
        }
        end
      )
    }' \
    >"$snapshot_directory/snapshot.json"

  for service in "${services[@]}"; do
    if capture_service_identity "$service" "$snapshot_directory/$service-identity.txt"; then
      container_id="$(identity_field "$snapshot_directory/$service-identity.txt" container_id)" || return 1
      host_pid="$(identity_field "$snapshot_directory/$service-identity.txt" host_pid)" || return 1
      container_ids+=("$container_id")
      run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker inspect "$container_id" \
        >"$snapshot_directory/$service-inspect.json" 2>"$snapshot_directory/$service-inspect.stderr" || true
      capture_proc_snapshot "$snapshot_directory/$service-identity.txt" \
        "$snapshot_directory/$service-proc.txt"
    else
      printf 'status=unavailable\n' >"$snapshot_directory/$service-identity.txt"
      printf 'status=unavailable\n' >"$snapshot_directory/$service-proc.txt"
    fi
  done
  if ((${#container_ids[@]} > 0)); then
    run_bounded "$DOCKER_STATS_TIMEOUT_SECONDS" docker stats --no-stream --format \
      '{{json .Name}} {{json .ID}} {{json .CPUPerc}} {{json .MemUsage}} {{json .PIDs}} {{json .NetIO}}' \
      "${container_ids[@]}" >"$snapshot_directory/container-stats.jsonl" \
      2>"$snapshot_directory/container-stats.stderr" || \
      printf 'status=unavailable\n' >"$snapshot_directory/container-stats.jsonl"
  else
    printf 'status=unavailable\n' >"$snapshot_directory/container-stats.jsonl"
  fi
  if [[ "$CELL_REQUIRES_OBI" == "true" ]]; then
    capture_obi_metrics_with_ownership \
      "$snapshot_directory/obi-identity.txt" \
      "$snapshot_directory/obi-bpf-fd-ownership.txt" \
      "$snapshot_directory/obi-metrics.prom"
  else
    capture_obi_metrics "$snapshot_directory/obi-metrics.prom"
    printf 'status=not_applicable\n' >"$snapshot_directory/obi-bpf-fd-ownership.txt"
  fi
  if [[ "$java_diagnostics_mode" == requested ]]; then
    capture_java_diagnostics "$snapshot_directory/java-diagnostics.txt"
  fi
}

# Emits one sorted `status value` row for every matching, semantically distinct
# operation series. The parser intentionally accepts only the three labels
# emitted by this metric, rejects duplicate label sets, and rejects non-integer
# counter samples. This prevents a malformed scrape from being silently
# interpreted as an idle control.
helper_idle_metric_series() {
  local -r input="$1"
  local -r wanted_operation="$2"
  local -r wanted_transport="$3"
  local -r wanted_status="${4:-}"
  local metric=""
  local raw_value=""
  local extra=""
  local labels=""
  local label=""
  local operation=""
  local status=""
  local transport=""
  local canonical=""
  local normalized_value=""
  local -a label_parts=()
  local -a matching_series=()
  local -A seen=()

  [[ -f "$input" && ! -L "$input" &&
    "$wanted_operation" =~ ^[a-z][a-z0-9_]*$ &&
    "$wanted_transport" =~ ^[a-z][a-z0-9_]*$ &&
    ( -z "$wanted_status" || "$wanted_status" =~ ^[a-z][a-z0-9_]*$ ) ]] || return 1
  while IFS=' ' read -r metric raw_value extra || [[ -n "$metric" ]]; do
    [[ -z "$metric" || "$metric" == \#* ]] && continue
    if [[ "$metric" == obi_java_remote_parent_operations_total* ]]; then
      [[ "$metric" == 'obi_java_remote_parent_operations_total{'*'}' && -z "$extra" ]] || return 1
      normalized_value="$(normalize_decimal "$raw_value" "$MAX_BPF_OPERATION_COUNTER" true)" || return 1
      labels="${metric#*\{}"
      labels="${labels%\}}"
      IFS=, read -r -a label_parts <<<"$labels"
      ((${#label_parts[@]} == 3)) || return 1
      operation=""
      status=""
      transport=""
      for label in "${label_parts[@]}"; do
        if [[ "$label" =~ ^operation=\"([a-z][a-z0-9_]*)\"$ ]]; then
          [[ -z "$operation" ]] || return 1
          operation="${BASH_REMATCH[1]}"
        elif [[ "$label" =~ ^status=\"([a-z][a-z0-9_]*)\"$ ]]; then
          [[ -z "$status" ]] || return 1
          status="${BASH_REMATCH[1]}"
        elif [[ "$label" =~ ^transport=\"([a-z][a-z0-9_]*)\"$ ]]; then
          [[ -z "$transport" ]] || return 1
          transport="${BASH_REMATCH[1]}"
        else
          return 1
        fi
      done
      [[ -n "$operation" && -n "$status" && -n "$transport" ]] || return 1
      canonical="$operation,$status,$transport"
      [[ -z "${seen[$canonical]+present}" ]] || return 1
      seen[$canonical]=true
      if [[ "$operation" == "$wanted_operation" && "$transport" == "$wanted_transport" &&
        ( -z "$wanted_status" || "$status" == "$wanted_status" ) ]]; then
        matching_series+=("$status $normalized_value")
      fi
    fi
  done <"$input"
  if ((${#matching_series[@]} > 0)); then
    printf '%s\n' "${matching_series[@]}" | sort
  fi
}

# Returns the number of matching, semantically distinct operation series and
# their summed non-negative integer value. This is suitable only for metrics
# whose aggregate is informational or independently fixed; zero-delta controls
# use helper_idle_metric_series_are_zero_delta so label churn cannot mask activity.
helper_idle_metric_total() {
  local -r input="$1"
  local -r wanted_operation="$2"
  local -r wanted_transport="$3"
  local -r wanted_status="${4:-}"
  local status=""
  local value=""
  local extra=""
  local series_output=""
  local count=0
  local total=0

  series_output="$(helper_idle_metric_series \
    "$input" "$wanted_operation" "$wanted_transport" "$wanted_status")" || return 1
  if [[ -n "$series_output" ]]; then
    while read -r status value extra; do
      [[ "$status" =~ ^[a-z][a-z0-9_]*$ && "$value" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
      ((count += 1))
      ((total <= MAX_BPF_OPERATION_COUNTER - value)) || return 1
      total="$((total + value))"
    done <<<"$series_output"
  fi
  printf '%s %s\n' "$count" "$total"
}

helper_idle_report_value() {
  local -r input="$1"
  local result=""
  local count=""
  local value=""
  local extra=""

  result="$(helper_idle_metric_total "$input" report tcp valid)" || return 1
  read -r count value extra <<<"$result"
  [[ "$count" == 1 && "$value" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
  printf '%s\n' "$value"
}

helper_idle_metric_series_are_zero_delta() {
  local -r before="$1"
  local -r after="$2"
  local -r operation="$3"
  local -r transport="$4"
  local before_output=""
  local after_output=""
  local status=""
  local value=""
  local extra=""
  local -A before_values=()
  local -A after_values=()

  before_output="$(helper_idle_metric_series "$before" "$operation" "$transport")" || return 1
  after_output="$(helper_idle_metric_series "$after" "$operation" "$transport")" || return 1
  if [[ -n "$before_output" ]]; then
    while read -r status value extra; do
      [[ "$status" =~ ^[a-z][a-z0-9_]*$ && "$value" =~ ^[0-9]+$ && -z "$extra" &&
        -z "${before_values[$status]+present}" ]] || return 1
      before_values[$status]="$value"
    done <<<"$before_output"
  fi
  if [[ -n "$after_output" ]]; then
    while read -r status value extra; do
      [[ "$status" =~ ^[a-z][a-z0-9_]*$ && "$value" =~ ^[0-9]+$ && -z "$extra" &&
        -z "${after_values[$status]+present}" ]] || return 1
      after_values[$status]="$value"
    done <<<"$after_output"
  fi
  for status in "${!before_values[@]}"; do
    [[ -n "${after_values[$status]+present}" ]] || return 1
    ((after_values[$status] >= before_values[$status])) || return 1
    ((after_values[$status] - before_values[$status] == 0)) || return 1
  done
  for status in "${!after_values[@]}"; do
    [[ -n "${before_values[$status]+present}" ]] || return 1
  done
}

wait_for_helper_idle_report_marker() {
  local -r baseline="$1"
  local -r output="$2"
  local -r marker_output="$3"
  local -r description="$4"
  local deadline="${5:-}"
  local -r candidate="$output.partial"
  local baseline_report=""
  local observed_report=""
  local polls=0

  [[ ! -e "$output" && ! -L "$output" && ! -e "$marker_output" && ! -L "$marker_output" &&
    ! -e "$candidate" && ! -L "$candidate" ]] || return 1
  baseline_report="$(helper_idle_report_value "$baseline")" || return 1
  if [[ -z "$deadline" ]]; then
    deadline="$((SECONDS + POSTLOAD_SENTINEL_TIMEOUT_SECONDS))"
  fi
  [[ "$deadline" =~ ^[0-9]+$ ]] || return 1
  ((deadline > SECONDS)) || return 1
  while ((SECONDS < deadline)); do
    ((polls += 1))
    capture_obi_metrics "$candidate"
    observed_report="$(helper_idle_report_value "$candidate")" || {
      rm -f -- "$candidate"
      return 1
    }
    if ((observed_report > baseline_report)); then
      install -m 0600 "$candidate" "$output" || {
        rm -f -- "$candidate"
        return 1
      }
      rm -f -- "$candidate" || return 1
      jq -n \
        --arg description "$description" \
        --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson polls "$polls" \
        --argjson baseline_report "$baseline_report" \
        --argjson observed_report "$observed_report" \
        '{
          description: $description,
          captured_at: $captured_at,
          polls: $polls,
          metric: "obi_java_remote_parent_operations_total",
          operation: "report",
          status: "valid",
          transport: "tcp",
          baseline: $baseline_report,
          observed: $observed_report,
          observed_delta: ($observed_report - $baseline_report)
        }' >"$marker_output"
      return 0
    fi
    rm -f -- "$candidate" || return 1
    sleep "$METRICS_SETTLE_SECONDS"
  done
  rm -f -- "$candidate" || return 1
  die "timed out waiting for $description tcp/report/valid marker"
}

wait_for_helper_idle_two_pass_fence() {
  local -r initial="$1"
  local -r output="$2"
  local -r fence_output="$3"
  local -r description="$4"
  local -r first="$output.fence-first"
  local -r first_marker="$fence_output.fence-first.json"
  local -r second="$output.fence-second"
  local -r second_marker="$fence_output.fence-second.json"
  local initial_report=""
  local first_report=""
  local second_report=""
  local deadline=0

  [[ -f "$initial" && ! -L "$initial" &&
    ! -e "$output" && ! -L "$output" &&
    ! -e "$fence_output" && ! -L "$fence_output" &&
    ! -e "$first" && ! -L "$first" &&
    ! -e "$first_marker" && ! -L "$first_marker" &&
    ! -e "$second" && ! -L "$second" &&
    ! -e "$second_marker" && ! -L "$second_marker" ]] || return 1
  initial_report="$(helper_idle_report_value "$initial")" || return 1
  deadline="$((SECONDS + POSTLOAD_SENTINEL_TIMEOUT_SECONDS))"
  # The report marker is emitted last by one serial BPF stats reader. A pass
  # that was already in flight at the boundary can satisfy the first marker;
  # the second begins after it, so its snapshot is a causal post-boundary
  # fence without relying on a request-caused report count.
  if ! wait_for_helper_idle_report_marker \
    "$initial" "$first" "$first_marker" "$description first post-boundary BPF pass" "$deadline"; then
    rm -f -- "$first" "$first_marker" "$second" "$second_marker" || true
    return 1
  fi
  if ! wait_for_helper_idle_report_marker \
    "$first" "$second" "$second_marker" "$description second post-boundary BPF pass" "$deadline"; then
    rm -f -- "$first" "$first_marker" "$second" "$second_marker" || true
    return 1
  fi
  first_report="$(helper_idle_report_value "$first")" || {
    rm -f -- "$first" "$first_marker" "$second" "$second_marker" || true
    return 1
  }
  second_report="$(helper_idle_report_value "$second")" || {
    rm -f -- "$first" "$first_marker" "$second" "$second_marker" || true
    return 1
  }
  install -m 0600 "$second" "$output" || {
    rm -f -- "$first" "$first_marker" "$second" "$second_marker" || true
    return 1
  }
  jq -n \
    --arg description "$description" \
    --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson initial_report "$initial_report" \
    --argjson first_report "$first_report" \
    --argjson second_report "$second_report" \
    '{
      description: $description,
      captured_at: $captured_at,
      metric: "obi_java_remote_parent_operations_total",
      operation: "report",
      status: "valid",
      transport: "tcp",
      initial_report: $initial_report,
      first_post_boundary_report: $first_report,
      second_post_boundary_report: $second_report,
      observed_delta: ($second_report - $initial_report),
      fence: {
        required_serial_post_boundary_report_passes: 2,
        report_is_published_after_each_successful_bpf_counter_pass: true
      }
    }' >"$fence_output" || {
    rm -f -- "$output" "$first" "$first_marker" "$second" "$second_marker" || true
    return 1
  }
  rm -f -- "$first" "$first_marker" "$second" "$second_marker" || return 1
}

helper_idle_metric_delta_json() {
  local -r before="$1"
  local -r after="$2"
  local -r output="$3"
  local operation=""
  local transport=""
  local name=""
  local before_result=""
  local after_result=""
  local before_count=""
  local after_count=""
  local before_value=""
  local after_value=""
  local extra=""
  local delta=0
  local report_before=""
  local report_after=""
  local negotiate_before_result=""
  local negotiate_after_result=""
  local negotiate_before_count=""
  local negotiate_after_count=""
  local negotiate_before_value=""
  local negotiate_after_value=""
  local counters_json=""
  local -a counter_json=()

  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  report_before="$(helper_idle_report_value "$before")" || return 1
  report_after="$(helper_idle_report_value "$after")" || return 1
  ((report_after > report_before)) || return 1
  for name in tcp-candidate tcp-inject tcp-stage tcp-handoff \
    tcp-handoff_admission getsockopt-take getsockopt-discard; do
    case "$name" in
      tcp-*)
        operation="${name#tcp-}"
        transport=tcp
        ;;
      getsockopt-*)
        operation="${name#getsockopt-}"
        transport=getsockopt
        ;;
      *) return 1 ;;
    esac
    # A zero aggregate is insufficient: a reset or a new status-labelled
    # series can otherwise hide activity. Require the canonical series set and
    # every series value to remain exactly unchanged before summarizing it.
    helper_idle_metric_series_are_zero_delta "$before" "$after" "$operation" "$transport" || return 1
    before_result="$(helper_idle_metric_total "$before" "$operation" "$transport")" || return 1
    after_result="$(helper_idle_metric_total "$after" "$operation" "$transport")" || return 1
    read -r before_count before_value extra <<<"$before_result"
    [[ "$before_count" =~ ^[0-9]+$ && "$before_value" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
    read -r after_count after_value extra <<<"$after_result"
    [[ "$after_count" =~ ^[0-9]+$ && "$after_value" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
    ((after_value >= before_value)) || return 1
    delta="$((after_value - before_value))"
    ((delta == 0)) || return 1
    counter_json+=("$(jq -cn \
      --arg category "$name" \
      --arg operation "$operation" \
      --arg transport "$transport" \
      --argjson before_series "$before_count" \
      --argjson after_series "$after_count" \
      --argjson before "$before_value" \
      --argjson after "$after_value" \
      --argjson observed_delta "$delta" \
      '{
        category: $category,
        operation: $operation,
        transport: $transport,
        before_series: $before_series,
        after_series: $after_series,
        before: $before,
        after: $after,
        observed_delta: $observed_delta,
        expected_delta: 0
      }')") || return 1
  done
  negotiate_before_result="$(helper_idle_metric_total "$before" negotiate getsockopt missing)" || return 1
  negotiate_after_result="$(helper_idle_metric_total "$after" negotiate getsockopt missing)" || return 1
  read -r negotiate_before_count negotiate_before_value extra <<<"$negotiate_before_result"
  [[ "$negotiate_before_count" =~ ^[0-9]+$ && "$negotiate_before_value" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
  read -r negotiate_after_count negotiate_after_value extra <<<"$negotiate_after_result"
  [[ "$negotiate_after_count" =~ ^[0-9]+$ && "$negotiate_after_value" =~ ^[0-9]+$ && -z "$extra" ]] || return 1
  ((negotiate_after_value >= negotiate_before_value)) || return 1
  counters_json="$(printf '%s\n' "${counter_json[@]}" | jq -s .)" || return 1
  jq -n \
    --arg semantic "direct_java_no_upstream_handoff_not_state_map_miss_proof" \
    --argjson report_before "$report_before" \
    --argjson report_after "$report_after" \
    --argjson constrained_zero_deltas "$counters_json" \
    --argjson informative_negotiate_missing_before_count "$negotiate_before_count" \
    --argjson informative_negotiate_missing_after_count "$negotiate_after_count" \
    --argjson informative_negotiate_missing_before "$negotiate_before_value" \
    --argjson informative_negotiate_missing_after "$negotiate_after_value" \
    '{
      semantic: $semantic,
      report_watermark: {
        operation: "report",
        status: "valid",
        transport: "tcp",
        before: $report_before,
        after: $report_after,
        observed_delta: ($report_after - $report_before)
      },
      constrained_zero_deltas: $constrained_zero_deltas,
      informative_getsockopt_negotiate_missing: {
        before_series: $informative_negotiate_missing_before_count,
        after_series: $informative_negotiate_missing_after_count,
        before: $informative_negotiate_missing_before,
        after: $informative_negotiate_missing_after,
        observed_delta: ($informative_negotiate_missing_after - $informative_negotiate_missing_before),
        interpretation: "informative_only_not_a_retrieval_outcome_reconciliation"
      },
      assertion: {
        tcp_upstream_candidate_inject_stage_handoff_and_admission_delta_zero: true,
        getsockopt_take_discard_delta_zero: true
      }
    }' >"$output"
}

validate_benchmark_result() {
  local -r result="$1"
  local -r duration_seconds="$2"

  [[ -f "$result" && ! -L "$result" ]] || return 1
  jq -se \
    --arg base_url "$CELL_WORKLOAD_BASE_URL" \
    --arg path "$CELL_WORKLOAD_PATH" \
    --arg connection_mode "$CELL_WORKLOAD_CONNECTION_MODE" \
    --arg tls_verification "$CELL_EXPECTED_TLS_VERIFICATION" \
    --argjson duration_nanos "$((duration_seconds * 1000000000))" \
    --argjson maximum_traffic_elapsed_nanos "$(((duration_seconds + MEASUREMENT_OVERRUN_TOLERANCE_SECONDS) * 1000000000))" \
    --argjson request_timeout_nanos "$((REQUEST_TIMEOUT_SECONDS * 1000000000))" \
    --argjson concurrency "$CONCURRENCY" \
    --argjson request_limit "$REQUEST_LIMIT" \
    --argjson sustained_load_seed "$SUSTAINED_LOAD_SEED" \
    --argjson expected_w3c "$CELL_SUSTAINED_W3C" '
      def finite_number:
        type == "number" and isfinite;
      def positive_integer:
        finite_number and floor == . and . > 0;
      def non_negative_integer:
        finite_number and floor == . and . >= 0;
      def positive_number:
        finite_number and . > 0;
      length == 1 and
      (.[0] |
        .status == "passed" and
        .base_url == $base_url and
        .path == $path and
        .connection_mode == $connection_mode and
        .tls_verification == $tls_verification and
        .w3c == $expected_w3c and
        .seed == $sustained_load_seed and
        .requested_duration_nanos == $duration_nanos and
        .request_timeout_nanos == $request_timeout_nanos and
        .concurrency == $concurrency and
        .request_limit == $request_limit and
        .request_limit_reached == false and
        .canceled == false and
        (.successful_requests | positive_integer and . <= $request_limit) and
        (.failed_requests | non_negative_integer and . == 0) and
        (.traffic_elapsed_nanos |
          positive_integer and . >= $duration_nanos and . <= $maximum_traffic_elapsed_nanos) and
        (.throughput_per_second | positive_number) and
        (.latency | type == "object") and
        (.latency.p50_nanos | positive_integer) and
        (.latency.p95_nanos | positive_integer) and
        (.latency.p99_nanos | positive_integer) and
        .latency.p95_nanos >= .latency.p50_nanos and
        .latency.p99_nanos >= .latency.p95_nanos
      )
    ' "$result" >/dev/null
}

benchmark_successful_request_count() {
  local -r result="$1"
  local count=""

  [[ -f "$result" && ! -L "$result" ]] || return 1
  count="$(jq -ser '
    if length == 1 and
      (.[0].successful_requests |
        if type == "number" then floor == . else false end)
    then .[0].successful_requests
    else empty
    end
  ' "$result")" || return 1
  normalize_decimal "$count" "$REQUEST_LIMIT" false
}

record_w3c_workload_successes() {
  local -r result="$1"
  local count=""

  [[ "$CELL_SUSTAINED_W3C" == "true" ]] || return 1
  count="$(benchmark_successful_request_count "$result")" || return 1
  ((CELL_W3C_WORKLOAD_SUCCESSFUL_REQUESTS <= MAX_W3C_WORKLOAD_SUCCESSFUL_REQUESTS - count)) || return 1
  CELL_W3C_WORKLOAD_SUCCESSFUL_REQUESTS="$((CELL_W3C_WORKLOAD_SUCCESSFUL_REQUESTS + count))"
}

run_benchmark_client() {
  local -r output="$1"
  local -r duration_seconds="$2"
  local launch_status=0

  launch_benchmark_client "$output" "$duration_seconds" || launch_status=$?
  ((launch_status == 0)) || return "$launch_status"
  wait_for_active_benchmark
}

start_benchmark_client() {
  local -r output="$1"
  local -r duration_seconds="$2"
  local -a arguments=(
    --base-url "$CELL_WORKLOAD_BASE_URL"
    --path "$CELL_WORKLOAD_PATH"
    --connection-mode "$CELL_WORKLOAD_CONNECTION_MODE"
    --duration "${duration_seconds}s"
    --request-timeout "${REQUEST_TIMEOUT_SECONDS}s"
    --concurrency "$CONCURRENCY"
    --request-limit "$REQUEST_LIMIT"
    --seed "$SUSTAINED_LOAD_SEED"
    --w3c="$CELL_SUSTAINED_W3C"
  )

  if [[ -n "$CELL_WORKLOAD_CA_FILE" ]]; then
    arguments+=(--ca-file "$CELL_WORKLOAD_CA_FILE")
  fi

  # Measurements run in the background. Make their PID a dedicated session
  # and process-group leader so interruption can terminate timeout, Compose,
  # and every client descendant as one bounded unit.
  exec setsid -- timeout --signal=TERM --kill-after=10s "$((duration_seconds + 30))s" \
    "${COMPOSE[@]}" run --rm --no-deps --no-TTY benchmark \
      "${arguments[@]}" >"$output" 2>"$output.stderr"
}

clear_active_benchmark() {
  BENCHMARK_PID=""
  BENCHMARK_IDENTITY=""
}

benchmark_process_identity() {
  local -r benchmark_pid="$1"

  [[ "$benchmark_pid" =~ ^[1-9][0-9]*$ && -r "/proc/$benchmark_pid/stat" ]] || return 1
  awk '
    match($0, /^[0-9]+ \(.*\) /) == 0 { exit 1 }
    {
      fields_count = split(substr($0, RLENGTH + 1), fields, " ")
      if (fields_count < 20 || fields[1] == "Z") {
        exit 1
      }
      if (fields[3] !~ /^[1-9][0-9]*$/ || fields[4] !~ /^[1-9][0-9]*$/ ||
          fields[20] !~ /^[1-9][0-9]*$/) {
        exit 1
      }
      printf "%s %s %s\n", fields[3], fields[4], fields[20]
    }
  ' "/proc/$benchmark_pid/stat" 2>/dev/null
}

benchmark_job_is_running() {
  local -r benchmark_pid="$1"
  local job_pid=""

  while IFS= read -r job_pid; do
    [[ "$job_pid" == "$benchmark_pid" ]] && return 0
  done < <(jobs -pr)
  return 1
}

benchmark_identity_matches_leader() {
  local -r benchmark_pid="$1"
  local current_identity=""

  [[ "$BENCHMARK_IDENTITY" =~ ^${benchmark_pid}\ ${benchmark_pid}\ [1-9][0-9]*$ ]] || return 1
  current_identity="$(benchmark_process_identity "$benchmark_pid")" || return 1
  [[ "$current_identity" == "$BENCHMARK_IDENTITY" ]]
}

benchmark_pending_identity_matches_leader() {
  local -r benchmark_pid="$1"
  local expected_start_time=""
  local current_identity=""
  local start_time=""

  [[ "$BENCHMARK_IDENTITY" =~ ^pending\ [1-9][0-9]*$ ]] || return 1
  expected_start_time="${BENCHMARK_IDENTITY#pending }"
  current_identity="$(benchmark_process_identity "$benchmark_pid")" || return 1
  read -r _ _ start_time <<<"$current_identity"
  [[ "$start_time" == "$expected_start_time" ]]
}

benchmark_pid_is_absent_or_zombie() {
  local -r benchmark_pid="$1"

  [[ ! -e "/proc/$benchmark_pid/stat" ]] && return 0
  awk '
    match($0, /^[0-9]+ \(.*\) /) == 0 { exit 1 }
    {
      split(substr($0, RLENGTH + 1), fields, " ")
      exit fields[1] == "Z" ? 0 : 1
    }
  ' "/proc/$benchmark_pid/stat" 2>/dev/null
}

benchmark_group_has_member() {
  local -r expected_process_group="$1"
  local -r expected_session="$2"

  "$PS_COMMAND" -eo pgid=,sid=,stat= 2>/dev/null | awk \
    -v expected_process_group="$expected_process_group" \
    -v expected_session="$expected_session" '
      $1 == expected_process_group && $2 == expected_session && $3 !~ /^Z/ {
        found = 1
      }
      END { exit found ? 0 : 1 }
    '
}

terminate_verified_benchmark_group() {
  local -r benchmark_pid="$1"
  local attempt=0

  # A live member retains this Linux process-group/session identity, so the
  # numeric PID cannot have been reused by an unrelated session.
  if ! benchmark_group_has_member "$benchmark_pid" "$benchmark_pid"; then
    wait "$benchmark_pid" 2>/dev/null || true
    clear_active_benchmark
    return 0
  fi
  kill -TERM -- "-$benchmark_pid" 2>/dev/null || true
  for ((attempt = 0; attempt < BENCHMARK_PROCESS_GROUP_GRACE_SECONDS; attempt++)); do
    if ! benchmark_group_has_member "$benchmark_pid" "$benchmark_pid"; then
      wait "$benchmark_pid" 2>/dev/null || true
      clear_active_benchmark
      return 0
    fi
    "$SLEEP_COMMAND" 1
  done
  if benchmark_group_has_member "$benchmark_pid" "$benchmark_pid"; then
    kill -KILL -- "-$benchmark_pid" 2>/dev/null || true
  fi
  wait "$benchmark_pid" 2>/dev/null || true
  clear_active_benchmark
}

record_active_benchmark_identity() {
  local identity=""
  local process_group=""
  local session=""
  local start_time=""
  local attempt=0
  local wait_status=0

  for ((attempt = 0; attempt < 50; attempt++)); do
    if ! benchmark_job_is_running "$BENCHMARK_PID"; then
      if wait "$BENCHMARK_PID" 2>/dev/null; then
        # A successful client cannot legitimately finish before it has entered
        # its dedicated session: every allowed run lasts at least two seconds.
        wait_status=1
      else
        wait_status=$?
      fi
      # Do not clear the PID before cleanup: timeout can exit while a client
      # descendant remains in its dedicated session.
      terminate_active_benchmark || true
      return "$wait_status"
    fi
    if identity="$(benchmark_process_identity "$BENCHMARK_PID")"; then
      read -r process_group session start_time <<<"$identity"
      if [[ -z "$BENCHMARK_IDENTITY" ]]; then
        BENCHMARK_IDENTITY="pending $start_time"
      fi
      if [[ "$process_group" == "$BENCHMARK_PID" && "$session" == "$BENCHMARK_PID" ]]; then
        if [[ "$BENCHMARK_IDENTITY" == "pending $start_time" ]]; then
          BENCHMARK_IDENTITY="$identity"
          return 0
        fi
        # The original launch identity changed before it entered its session.
        # Do not promote a reused PID into a signalable process group.
        return 1
      fi
    fi
    "$SLEEP_COMMAND" 0.1
  done
  return 1
}

launch_benchmark_client() {
  local -r output="$1"
  local -r duration_seconds="$2"
  local identity_status=0

  clear_active_benchmark
  start_benchmark_client "$output" "$duration_seconds" &
  BENCHMARK_PID=$!
  if record_active_benchmark_identity; then
    return 0
  else
    identity_status=$?
  fi
  terminate_active_benchmark || true
  return "$identity_status"
}

wait_for_active_benchmark() {
  local benchmark_pid="$BENCHMARK_PID"
  local wait_status=0
  local cleanup_status=0

  [[ "$benchmark_pid" =~ ^[1-9][0-9]*$ ]] || {
    clear_active_benchmark
    return 1
  }
  if wait "$benchmark_pid"; then
    :
  else
    wait_status=$?
  fi
  # `timeout` can finish before a client descendant leaves its session. Keep
  # the recorded identity until group cleanup has inspected that possibility.
  terminate_active_benchmark || cleanup_status=$?
  ((wait_status == 0)) || return "$wait_status"
  return "$cleanup_status"
}

run_measurement_rep() {
  local -r cell_dir="$1"
  local -r repetition="$2"
  local repetition_label=""
  local result=""
  local launch_status=0

  printf -v repetition_label 'rep-%02d' "$repetition"
  result="$cell_dir/measurements/$repetition_label.json"
  launch_benchmark_client "$result" "$DURATION_SECONDS" || launch_status=$?
  ((launch_status == 0)) || return "$launch_status"
  sleep "$METRICS_SETTLE_SECONDS"
  if benchmark_job_is_running "$BENCHMARK_PID" &&
    benchmark_identity_matches_leader "$BENCHMARK_PID"; then
    capture_resource_snapshot "$cell_dir/measurements/$repetition_label-midpoint" \
      unsynchronized_midpoint
  else
    jq -n --arg timing unsynchronized_midpoint --arg status unavailable \
      '{timing: $timing, status: $status, reason: "load_client_exited_before_sample"}' \
      >"$cell_dir/measurements/$repetition_label-midpoint.json"
  fi
  wait_for_active_benchmark || return $?
  validate_benchmark_result "$result" "$DURATION_SECONDS"
}

run_helper_idle_measurement_rep() {
  local -r cell_dir="$1"
  local -r repetition="$2"
  local repetition_label=""
  local result=""
  local launch_status=0

  [[ "$CELL_HELPER_IDLE" == "true" ]] || return 1
  printf -v repetition_label 'rep-%02d' "$repetition"
  result="$cell_dir/measurements/$repetition_label.json"
  launch_benchmark_client "$result" "$DURATION_SECONDS" || launch_status=$?
  ((launch_status == 0)) || return "$launch_status"
  sleep "$METRICS_SETTLE_SECONDS"
  if benchmark_job_is_running "$BENCHMARK_PID" &&
    benchmark_identity_matches_leader "$BENCHMARK_PID"; then
    # Retain the same unsynchronized CPU/RSS/thread/FD/container point sample
    # as the other cells, but omit only the Java diagnostics HTTP request. That
    # request is server-instrumented and would invalidate exact t_missing
    # accounting inside this direct-Java workload window.
    capture_resource_snapshot "$cell_dir/measurements/$repetition_label-midpoint" \
      unsynchronized_midpoint not_collected
  else
    jq -n --arg timing unsynchronized_midpoint --arg status unavailable \
      '{timing: $timing, status: $status, reason: "load_client_exited_before_sample"}' \
      >"$cell_dir/measurements/$repetition_label-midpoint.json"
  fi
  wait_for_active_benchmark || return $?
  validate_benchmark_result "$result" "$DURATION_SECONDS"
}

variance_summary_cell() {
  local -r cell="$1"
  local -r root="${2:-$OUTPUT_DIR}"
  local -r cell_dir="$root/cells/$cell"
  local -r measurement_dir="$cell_dir/measurements"
  local -r status_file="$cell_dir/status.json"
  local -r contract_file="$cell_dir/preflight/contract.json"
  local expected_sources=""
  local observed_sources=""
  local repetition=0
  local repetition_label=""
  local result=""
  local source=""
  local sample_json=""
  local samples_json=""
  local -a samples=()

  cell_spec "$cell" || return 1
  [[ -d "$measurement_dir" && ! -L "$measurement_dir" ]] || return 1
  [[ -f "$status_file" && ! -L "$status_file" ]] || return 1
  [[ -f "$contract_file" && ! -L "$contract_file" ]] || return 1
  jq -se --arg cell "$cell" '
    length == 1 and
    (.[0] | (.status == "passed" or .status == "failed") and .cell == $cell)
  ' "$status_file" >/dev/null || return 1
  jq -se --arg cell "$cell" '
    length == 1 and (.[0] | .cell == $cell)
  ' "$contract_file" >/dev/null || return 1

  expected_sources="$(
    for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
      printf -v repetition_label 'rep-%02d.json' "$repetition"
      printf '%s\n' "$repetition_label"
    done
  )"
  observed_sources="$(
    find "$measurement_dir" -mindepth 1 -maxdepth 1 -name 'rep-[0-9][0-9].json' -printf '%f\n' | sort
  )" || return 1
  [[ "$observed_sources" == "$expected_sources" ]] || return 1

  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    printf -v repetition_label 'rep-%02d' "$repetition"
    result="$measurement_dir/$repetition_label.json"
    source="cells/$cell/measurements/$repetition_label.json"
    validate_benchmark_result "$result" "$DURATION_SECONDS" || return 1
    sample_json="$(jq -sce \
      --argjson repetition "$repetition" \
      --arg source "$source" '
        if length != 1 then
          error("expected exactly one benchmark result")
        else
          .[0] | {
            repetition: $repetition,
            source: $source,
            successful_requests,
            failed_requests,
            traffic_elapsed_nanos,
            throughput_per_second,
            latency: {
              p50_nanos: .latency.p50_nanos,
              p95_nanos: .latency.p95_nanos,
              p99_nanos: .latency.p99_nanos
            }
          }
        end
      ' "$result")" || return 1
    samples+=("$sample_json")
  done
  samples_json="$(printf '%s\n' "${samples[@]}" | jq -s .)" || return 1
  jq -cn \
    --arg cell "$cell" \
    --arg contract "cells/$cell/preflight/contract.json" \
    --argjson expected_sample_count "$REPETITIONS" \
    --argjson samples "$samples_json" '
      def observed_stats:
        sort as $ordered |
        ($ordered | length) as $count |
        ($count / 2 | floor) as $middle |
        if $count == 0 then
          error("cannot summarize an empty sample set")
        else
          {
            min: $ordered[0],
            median: (
              if ($count % 2) == 1 then $ordered[$middle]
              else (($ordered[$middle - 1] + $ordered[$middle]) / 2)
              end
            ),
            max: $ordered[$count - 1]
          }
        end;
      {
        cell: $cell,
        contract: $contract,
        expected_sample_count: $expected_sample_count,
        valid_sample_count: ($samples | length),
        samples: $samples,
        statistics: {
          successful_requests: ($samples | map(.successful_requests) | observed_stats),
          failed_requests: ($samples | map(.failed_requests) | observed_stats),
          traffic_elapsed_nanos: ($samples | map(.traffic_elapsed_nanos) | observed_stats),
          throughput_per_second: ($samples | map(.throughput_per_second) | observed_stats),
          latency: {
            p50_nanos: ($samples | map(.latency.p50_nanos) | observed_stats),
            p95_nanos: ($samples | map(.latency.p95_nanos) | observed_stats),
            p99_nanos: ($samples | map(.latency.p99_nanos) | observed_stats)
          }
        }
      }
    '
}

variance_summary_cells() {
  local -r root="${1:-$OUTPUT_DIR}"
  local cell=""
  local cell_json=""
  local -a cells=()

  for cell in "${CORE_CELLS[@]}"; do
    cell_json="$(variance_summary_cell "$cell" "$root")" || return 1
    cells+=("$cell_json")
  done
  printf '%s\n' "${cells[@]}" | jq -s .
}

variance_summary_json() {
  local -r root="${1:-$OUTPUT_DIR}"
  local cells_json=""

  [[ -d "$root" && ! -L "$root" ]] || return 1
  cells_json="$(variance_summary_cells "$root")" || return 1
  jq -cn \
    --arg manifest manifest.json \
    --argjson cells "$cells_json" '
      {
        schema_version: 1,
        kind: "application-performance-repetition-summary",
        status: "complete",
        acceptance_evidence: false,
        manifest: $manifest,
        aggregation: {
          sample_unit: "one completed sustained-client repetition",
          sample_selection: "all requested schema-valid repetitions for one cell; none are dropped",
          median: "odd: middle sorted numeric value; even: arithmetic mean of the two middle sorted numeric values",
          spread: "observed minimum and maximum; not a variance estimator or confidence interval",
          cross_cell_aggregation: false,
          per_request_latency_aggregation: false
        },
        cells: $cells,
        notes: [
          "Each latency statistic summarizes one percentile value from each completed repetition.",
          "This application performance artifact applies no threshold itself and does not establish a production SLO; poc-gates.json evaluates the predeclared PoC threshold."
        ]
      }
    '
}

write_variance_summary() {
  local -r output="$OUTPUT_DIR/variance.json"
  local temporary=""

  [[ "$OUTPUT_READY" == "true" ]] || return 1
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "$OUTPUT_DIR/.variance.json.XXXXXX")" || return 1
  if ! variance_summary_json "$OUTPUT_DIR" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  validate_variance_summary_schema "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  mv -T -- "$temporary" "$output" || {
    rm -f -- "$temporary"
    return 1
  }
  validate_variance_summary_schema "$output" || {
    rm -f -- "$output"
    return 1
  }
}

proc_growth_snapshot_values() {
  local -r snapshot="$1"

  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 1
  awk -F= '
    $1 == "status" {
      status_matches++
      status = $2
      next
    }
    $1 == "host_pid" {
      pid_matches++
      pid = $2
      next
    }
    $1 == "container_id" {
      container_matches++
      container = $2
      next
    }
    $1 == "proc_start_time" {
      start_matches++
      start = $2
      next
    }
    $1 == "proc_cgroup_sha256" {
      cgroup_matches++
      cgroup = $2
      next
    }
    $1 == "proc_cgroup_container_binding" {
      binding_matches++
      binding = $2
      next
    }
    $1 == "fd_count" {
      fd_matches++
      fd = $2
      next
    }
    $1 == "task_count" {
      task_matches++
      tasks = $2
      next
    }
    END {
      if (status_matches != 1 || status != "available" ||
          container_matches != 1 || container !~ /^[0-9a-f]{64}$/ ||
          pid_matches != 1 || pid !~ /^[1-9][0-9]*$/ ||
          start_matches != 1 || start !~ /^[1-9][0-9]*$/ ||
          cgroup_matches != 1 || cgroup !~ /^[0-9a-f]{64}$/ ||
          binding_matches != 1 ||
          binding != "full_container_id_at_non_hex_boundaries" ||
          fd_matches != 1 || fd !~ /^(0|[1-9][0-9]*)$/ ||
          task_matches != 1 || tasks !~ /^[1-9][0-9]*$/) {
        exit 1
      }
      printf "%s %s %s %s %s %s %s\n", container, pid, start, cgroup, binding, fd, tasks
    }
  ' "$snapshot"
}

proc_growth_identity_json() {
  local -r snapshot="$1"
  local values=""
  local container_id=""
  local host_pid=""
  local proc_start_time=""
  local proc_cgroup_sha256=""
  local proc_cgroup_container_binding=""
  local fd_count=""
  local task_count=""

  values="$(proc_growth_snapshot_values "$snapshot")" || return 1
  read -r container_id host_pid proc_start_time proc_cgroup_sha256 \
    proc_cgroup_container_binding fd_count task_count <<<"$values" || return 1
  jq -cn \
    --arg container_id "$container_id" \
    --arg proc_cgroup_sha256 "$proc_cgroup_sha256" \
    --arg proc_cgroup_container_binding "$proc_cgroup_container_binding" \
    --argjson host_pid "$host_pid" \
    --argjson proc_start_time "$proc_start_time" '
      {
        container_id: $container_id,
        host_pid: $host_pid,
        proc_start_time: $proc_start_time,
        proc_cgroup_sha256: $proc_cgroup_sha256,
        proc_cgroup_container_binding: $proc_cgroup_container_binding
      }
    '
}

process_growth_observation() {
  local -r cell="$1"
  local -r service="$2"
  local -r before_snapshot="$3"
  local -r recovery_snapshot="$4"
  local before_values=""
  local recovery_values=""
  local before_pid=""
  local before_container=""
  local before_start_time=""
  local before_cgroup_sha256=""
  local before_cgroup_container_binding=""
  local before_fds=""
  local before_threads=""
  local recovery_pid=""
  local recovery_container=""
  local recovery_start_time=""
  local recovery_cgroup_sha256=""
  local recovery_cgroup_container_binding=""
  local recovery_fds=""
  local recovery_threads=""

  if ! before_values="$(proc_growth_snapshot_values "$before_snapshot")" ||
    ! recovery_values="$(proc_growth_snapshot_values "$recovery_snapshot")"; then
    jq -cn \
      --arg cell "$cell" \
      --arg service "$service" \
      --arg before "cells/$cell/resources-before/$service-proc.txt" \
      --arg recovery "cells/$cell/resources-idle-recovery/$service-proc.txt" '
        {
          cell: $cell,
          service: $service,
          status: "partial",
          result: "not_evaluated",
          reason: "required_before_or_idle_recovery_proc_sample_unavailable_or_malformed",
          sources: {before: $before, idle_recovery: $recovery}
        }
      '
    return 0
  fi
  read -r before_container before_pid before_start_time before_cgroup_sha256 \
    before_cgroup_container_binding \
    before_fds before_threads <<<"$before_values" || return 1
  read -r recovery_container recovery_pid recovery_start_time recovery_cgroup_sha256 \
    recovery_cgroup_container_binding \
    recovery_fds recovery_threads <<<"$recovery_values" || return 1
  if [[ "$before_container $before_pid $before_start_time $before_cgroup_sha256 $before_cgroup_container_binding" != \
    "$recovery_container $recovery_pid $recovery_start_time $recovery_cgroup_sha256 $recovery_cgroup_container_binding" ]]; then
    jq -cn \
      --arg cell "$cell" \
      --arg service "$service" \
      --arg before "cells/$cell/resources-before/$service-proc.txt" \
      --arg recovery "cells/$cell/resources-idle-recovery/$service-proc.txt" '
        {
          cell: $cell,
          service: $service,
          status: "partial",
          result: "not_evaluated",
          reason: "service_container_or_process_identity_changed_between_required_samples",
          sources: {before: $before, idle_recovery: $recovery}
        }
      '
    return 0
  fi
  jq -cn \
    --arg cell "$cell" \
    --arg service "$service" \
    --arg before "cells/$cell/resources-before/$service-proc.txt" \
    --arg recovery "cells/$cell/resources-idle-recovery/$service-proc.txt" \
    --arg container_id "$before_container" \
    --arg proc_cgroup_sha256 "$before_cgroup_sha256" \
    --arg proc_cgroup_container_binding "$before_cgroup_container_binding" \
    --argjson host_pid "$before_pid" \
    --argjson proc_start_time "$before_start_time" \
    --argjson before_fds "$before_fds" \
    --argjson recovery_fds "$recovery_fds" \
    --argjson before_threads "$before_threads" \
    --argjson recovery_threads "$recovery_threads" '
      {
        cell: $cell,
        service: $service,
        status: "complete",
        result: (
          if $recovery_fds <= $before_fds and $recovery_threads <= $before_threads
          then "passed" else "failed" end
        ),
        container_id: $container_id,
        host_pid: $host_pid,
        proc_start_time: $proc_start_time,
        proc_cgroup_sha256: $proc_cgroup_sha256,
        proc_cgroup_container_binding: $proc_cgroup_container_binding,
        fd: {
          before: $before_fds,
          idle_recovery: $recovery_fds,
          delta: ($recovery_fds - $before_fds),
          maximum_delta: 0
        },
        threads: {
          before: $before_threads,
          idle_recovery: $recovery_threads,
          delta: ($recovery_threads - $before_threads),
          maximum_delta: 0
        },
        sources: {before: $before, idle_recovery: $recovery}
      }
    '
}

java_bridge_map_metric_rows() {
  local -r metrics_file="$1"

  [[ -f "$metrics_file" && ! -L "$metrics_file" ]] || return 1
  awk '
    function invalid() {
      malformed = 1
    }
    /^obi_bpf_map_(entries|max_entries)_total\{/ {
      if (NF != 2 || $2 !~ /^(0|[1-9][0-9]*)(\.0+)?$/) {
        invalid()
        next
      }
      metric_and_labels = $1
      open = index(metric_and_labels, "{")
      if (open == 0 || substr(metric_and_labels, length(metric_and_labels), 1) != "}") {
        invalid()
        next
      }
      metric = substr(metric_and_labels, 1, open - 1)
      labels = substr(metric_and_labels, open + 1, length(metric_and_labels) - open - 1)
      label_count = split(labels, pairs, ",")
      delete values
      delete seen
      for (label_index = 1; label_index <= label_count; label_index++) {
        separator = index(pairs[label_index], "=")
        if (separator == 0) {
          invalid()
          next
        }
        name = substr(pairs[label_index], 1, separator - 1)
        value = substr(pairs[label_index], separator + 1)
        if (name !~ /^(map_id|map_name|map_type)$/ || seen[name] ||
            value !~ /^"[A-Za-z0-9_]+"$/) {
          invalid()
          next
        }
        seen[name] = 1
        values[name] = substr(value, 2, length(value) - 2)
      }
      if (label_count != 3 || !seen["map_id"] || !seen["map_name"] ||
          !seen["map_type"] || values["map_id"] !~ /^[1-9][0-9]*$/) {
        invalid()
        next
      }
      if (values["map_name"] != "java_remote_par") {
        next
      }
      metric_name = metric == "obi_bpf_map_entries_total" ? "entries" :
        (metric == "obi_bpf_map_max_entries_total" ? "max_entries" : "")
      if (metric_name == "") {
        invalid()
        next
      }
      numeric = $2
      sub(/\.0+$/, "", numeric)
      printf "%s\t%s\t%s\t%s\t%s\n", metric_name, values["map_id"],
        values["map_name"], values["map_type"], numeric
      emitted++
    }
    END {
      if (malformed || emitted == 0) {
        exit 1
      }
    }
  ' "$metrics_file"
}

map_rows_json() {
  jq -Rsc '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    map({
      metric: .[0], map_id: (.[1] | tonumber), map_name: .[2],
      map_type: .[3], value: (.[4] | tonumber)
    })
  '
}

bpf_fd_ownership_json() {
  local -r ownership_file="$1"

  [[ -f "$ownership_file" && ! -L "$ownership_file" ]] || return 1
  jq -Rsc '
    (split("\n") |
      if .[-1] == "" then .[0:-1] else error("missing final newline") end
    ) as $lines |
    if ($lines | length) < 7 or $lines[0] != "status=available"
    then error("BPF FD ownership unavailable") else . end |
    ($lines[1] |
      capture("^container_id=(?<value>[0-9a-f]{64})$").value) as $container_id |
    ($lines[2] |
      capture("^host_pid=(?<value>[1-9][0-9]*)$").value | tonumber) as $host_pid |
    ($lines[3] |
      capture("^proc_start_time=(?<value>[1-9][0-9]*)$").value | tonumber) as $start |
    ($lines[4] |
      capture("^proc_cgroup_sha256=(?<value>[0-9a-f]{64})$").value) as $cgroup |
    if $lines[5] !=
      "proc_cgroup_container_binding=full_container_id_at_non_hex_boundaries"
    then error("invalid proc cgroup binding") else . end |
    ($lines[6:] |
      map(capture("^fd=(?<fd>0|[1-9][0-9]*) (?<kind>map_id|prog_id)=(?<id>[1-9][0-9]*)$") |
        .fd |= tonumber | .id |= tonumber)) as $descriptors |
    ($descriptors | map(select(.kind == "map_id") | .id) | sort | unique) as $maps |
    ($descriptors | map(select(.kind == "prog_id") | .id) | sort | unique) as $programs |
    if ($maps | length) == 0 or
      ($descriptors | length) == 0 or
      ([ $descriptors[].fd ] != ([ $descriptors[].fd ] | sort | unique))
    then error("invalid BPF FD ownership roster")
    else {
      container_id: $container_id,
      host_pid: $host_pid,
      proc_start_time: $start,
      proc_cgroup_sha256: $cgroup,
      proc_cgroup_container_binding:
        "full_container_id_at_non_hex_boundaries",
      descriptors: $descriptors,
      map_ids: $maps,
      program_ids: $programs
    }
    end
  ' "$ownership_file"
}

java_bridge_map_growth_observation() {
  local -r cell="$1"
  local -r before_metrics="$2"
  local -r recovery_metrics="$3"
  local -r before_ownership="$4"
  local -r recovery_ownership="$5"
  local -r before_process_snapshot="$6"
  local -r recovery_process_snapshot="$7"
  local before_rows=""
  local recovery_rows=""
  local before_json="[]"
  local recovery_json="[]"
  local before_owner="{}"
  local recovery_owner="{}"
  local before_process="{}"
  local recovery_process="{}"

  if ! before_rows="$(java_bridge_map_metric_rows "$before_metrics")" ||
    ! recovery_rows="$(java_bridge_map_metric_rows "$recovery_metrics")"; then
    jq -cn \
      --arg cell "$cell" \
      --arg before "cells/$cell/resources-before/obi-metrics.prom" \
      --arg recovery "cells/$cell/resources-idle-recovery/obi-metrics.prom" \
      --arg before_ownership "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
      --arg recovery_ownership "cells/$cell/resources-idle-recovery/obi-bpf-fd-ownership.txt" \
      --arg before_process "cells/$cell/resources-before/obi-proc.txt" \
      --arg recovery_process "cells/$cell/resources-idle-recovery/obi-proc.txt" '
        {
          cell: $cell,
          status: "partial",
          result: "not_evaluated",
          data_status: "unavailable",
          descriptive_result: "not_available",
          scope: "host_global_java_remote_par_superset",
          ownership_attribution: false,
          reason: "required_before_or_idle_recovery_java_bridge_map_sample_unavailable_or_malformed",
          sources: {before: $before, idle_recovery: $recovery},
          ownership_sources: {
            before: $before_ownership,
            idle_recovery: $recovery_ownership
          },
          process_sources: {
            before: $before_process,
            idle_recovery: $recovery_process
          }
        }
      '
    return 0
  fi
  if ! before_owner="$(bpf_fd_ownership_json "$before_ownership")" ||
    ! recovery_owner="$(bpf_fd_ownership_json "$recovery_ownership")"; then
    jq -cn \
      --arg cell "$cell" \
      --arg before "cells/$cell/resources-before/obi-metrics.prom" \
      --arg recovery "cells/$cell/resources-idle-recovery/obi-metrics.prom" \
      --arg before_ownership "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
      --arg recovery_ownership "cells/$cell/resources-idle-recovery/obi-bpf-fd-ownership.txt" \
      --arg before_process "cells/$cell/resources-before/obi-proc.txt" \
      --arg recovery_process "cells/$cell/resources-idle-recovery/obi-proc.txt" '
        {
          cell: $cell,
          status: "partial",
          result: "not_evaluated",
          data_status: "unavailable",
          descriptive_result: "not_available",
          scope: "host_global_java_remote_par_superset",
          ownership_attribution: false,
          reason: "required_stable_obi_bpf_fd_ownership_sample_unavailable_or_malformed",
          sources: {before: $before, idle_recovery: $recovery},
          ownership_sources: {
            before: $before_ownership,
            idle_recovery: $recovery_ownership
          },
          process_sources: {
            before: $before_process,
            idle_recovery: $recovery_process
          }
        }
      '
    return 0
  fi
  if ! before_process="$(proc_growth_identity_json "$before_process_snapshot")" ||
    ! recovery_process="$(proc_growth_identity_json "$recovery_process_snapshot")"; then
    jq -cn \
      --arg cell "$cell" \
      --arg before "cells/$cell/resources-before/obi-metrics.prom" \
      --arg recovery "cells/$cell/resources-idle-recovery/obi-metrics.prom" \
      --arg before_ownership "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
      --arg recovery_ownership "cells/$cell/resources-idle-recovery/obi-bpf-fd-ownership.txt" \
      --arg before_process "cells/$cell/resources-before/obi-proc.txt" \
      --arg recovery_process "cells/$cell/resources-idle-recovery/obi-proc.txt" '
        {
          cell: $cell,
          status: "partial",
          result: "not_evaluated",
          data_status: "unavailable",
          descriptive_result: "not_available",
          scope: "host_global_java_remote_par_superset",
          ownership_attribution: false,
          reason: "required_bound_obi_process_sample_unavailable_or_malformed",
          sources: {before: $before, idle_recovery: $recovery},
          ownership_sources: {
            before: $before_ownership,
            idle_recovery: $recovery_ownership
          },
          process_sources: {
            before: $before_process,
            idle_recovery: $recovery_process
          }
        }
      '
    return 0
  fi
  before_json="$(map_rows_json <<<"$before_rows")" || return 1
  recovery_json="$(map_rows_json <<<"$recovery_rows")" || return 1
  jq -cn \
    --arg cell "$cell" \
    --arg before_source "cells/$cell/resources-before/obi-metrics.prom" \
    --arg recovery_source "cells/$cell/resources-idle-recovery/obi-metrics.prom" \
    --arg before_ownership_source "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
    --arg recovery_ownership_source "cells/$cell/resources-idle-recovery/obi-bpf-fd-ownership.txt" \
    --arg before_process_source "cells/$cell/resources-before/obi-proc.txt" \
    --arg recovery_process_source "cells/$cell/resources-idle-recovery/obi-proc.txt" \
    --argjson before "$before_json" \
    --argjson recovery "$recovery_json" \
    --argjson before_owner "$before_owner" \
    --argjson recovery_owner "$recovery_owner" \
    --argjson before_process "$before_process" \
    --argjson recovery_process "$recovery_process" '
      def rows_valid($rows):
        ($rows | length) > 0 and
        all($rows[];
          (.map_id | type == "number" and isfinite and floor == . and . > 0) and
          .map_name == "java_remote_par" and
          (.map_type | type == "string" and length > 0) and
          (.metric == "entries" or .metric == "max_entries") and
          (.value | type == "number" and isfinite and floor == . and . >= 0)) and
        ($rows | group_by([.map_id, .metric]) | all(length == 1)) and
        ($rows | group_by(.map_id) | all(
          length == 2 and ([.[].metric] | sort) == ["entries", "max_entries"] and
          (map(select(.metric == "entries"))[0].value <=
            map(select(.metric == "max_entries"))[0].value)
        ));
      def indexed($rows):
        reduce $rows[] as $row ({};
          .[($row.map_id | tostring)].map_name = $row.map_name |
          .[($row.map_id | tostring)].map_type = $row.map_type |
          .[($row.map_id | tostring)][$row.metric] = $row.value
        );
      ([$before[] |
        .map_id as $id |
        select($before_owner.map_ids | index($id))]) as $owned_before |
      ([$recovery[] |
        .map_id as $id |
        select($recovery_owner.map_ids | index($id))]) as $owned_recovery |
      (indexed($owned_before)) as $before_index |
      (indexed($owned_recovery)) as $recovery_index |
      if ($before_owner == $recovery_owner and
          $before_process == $recovery_process and
          ($before_owner | del(.descriptors, .map_ids, .program_ids)) == $before_process and
          rows_valid($owned_before) and rows_valid($owned_recovery) and
          ($before_index | keys | sort) == ($recovery_index | keys | sort) and
          ([($before_index | keys[]) as $id |
            $before_index[$id].map_name == $recovery_index[$id].map_name and
            $before_index[$id].map_type == $recovery_index[$id].map_type and
            $before_index[$id].max_entries == $recovery_index[$id].max_entries] | all))
      then
        [
          ($before_index | keys[]) as $id |
          {
            map_id: ($id | tonumber),
            map_name: $before_index[$id].map_name,
            map_type: $before_index[$id].map_type,
            before_entries: $before_index[$id].entries,
            idle_recovery_entries: $recovery_index[$id].entries,
            delta: ($recovery_index[$id].entries - $before_index[$id].entries),
            maximum_delta: 0,
            max_entries: $before_index[$id].max_entries
          }
        ] as $maps |
        {
          cell: $cell,
          status: "complete",
          result: (
            if all($maps[]; .delta <= .maximum_delta)
            then "passed" else "failed" end
          ),
          data_status: "complete",
          descriptive_result: (
            if all($maps[]; .delta <= .maximum_delta)
            then "stable_or_decreased" else "growth_observed" end
          ),
          scope: "exact_obi_process_open_bpf_map_ids",
          ownership_attribution: true,
          ownership: $before_owner,
          maps: $maps,
          sources: {before: $before_source, idle_recovery: $recovery_source},
          ownership_sources: {
            before: $before_ownership_source,
            idle_recovery: $recovery_ownership_source
          },
          process_sources: {
            before: $before_process_source,
            idle_recovery: $recovery_process_source
          }
        }
      else
        {
          cell: $cell,
          status: "partial",
          result: "not_evaluated",
          data_status: "ambiguous",
          descriptive_result: "series_set_changed_or_was_duplicate",
          scope: "host_global_java_remote_par_superset",
          ownership_attribution: false,
          reason: "owned_java_bridge_map_series_or_bpf_fd_roster_changed_or_was_duplicate_or_incomplete",
          sources: {before: $before_source, idle_recovery: $recovery_source},
          ownership_sources: {
            before: $before_ownership_source,
            idle_recovery: $recovery_ownership_source
          },
          process_sources: {
            before: $before_process_source,
            idle_recovery: $recovery_process_source
          }
        }
      end
    '
}

resource_growth_gate() {
  local cell=""
  local service=""
  local cell_dir=""
  local observation=""
  local process_json=""
  local maps_json=""
  local -a services=()
  local -a process_observations=()
  local -a map_observations=()

  for cell in "${CORE_CELLS[@]}"; do
    cell_spec "$cell" || return 1
    cell_dir="$OUTPUT_DIR/cells/$cell"
    services=(trace-receiver apache-proxy java-backend)
    if [[ "$CELL_REQUIRES_OBI" == "true" ]]; then
      services+=(obi)
    fi
    for service in "${services[@]}"; do
      observation="$(process_growth_observation \
        "$cell" "$service" \
        "$cell_dir/resources-before/$service-proc.txt" \
        "$cell_dir/resources-idle-recovery/$service-proc.txt")" || return 1
      process_observations+=("$observation")
    done
    if [[ "$CELL_REQUIRES_OBI" == "true" ]]; then
      observation="$(java_bridge_map_growth_observation \
        "$cell" \
        "$cell_dir/resources-before/obi-metrics.prom" \
        "$cell_dir/resources-idle-recovery/obi-metrics.prom" \
        "$cell_dir/resources-before/obi-bpf-fd-ownership.txt" \
        "$cell_dir/resources-idle-recovery/obi-bpf-fd-ownership.txt" \
        "$cell_dir/resources-before/obi-proc.txt" \
        "$cell_dir/resources-idle-recovery/obi-proc.txt")" || return 1
      map_observations+=("$observation")
    fi
  done
  process_json="$(printf '%s\n' "${process_observations[@]}" | jq -s .)" || return 1
  maps_json="$(printf '%s\n' "${map_observations[@]}" | jq -s .)" || return 1
  jq -cn \
    --argjson processes "$process_json" \
    --argjson maps "$maps_json" '
      {
        status: "partial",
        required_samples: ["before", "idle_recovery"],
        unavailable_samples_fail_closed: true,
        process_dimension: {
          status: (if all($processes[]; .status == "complete") then "complete" else "partial" end),
          result: (
            if any($processes[]; .status != "complete") then "not_evaluated"
            elif all($processes[]; .result == "passed") then "passed"
            else "failed"
            end
          )
        },
        map_dimension: {
          status: (if all($maps[]; .status == "complete") then "complete" else "partial" end),
          result: (
            if any($maps[]; .status == "complete" and .result == "failed") then "failed"
            elif any($maps[]; .status != "complete") then "not_evaluated"
            else "passed"
            end
          ),
          reason: (
            if all($maps[]; .status == "complete") then null
            else "stable_exact_obi_bpf_fd_ownership_is_required_for_every_map_sample"
            end
          ),
          descriptive_data_status: (
            if all($maps[]; .data_status == "complete") then "complete"
            elif any($maps[]; .data_status == "unavailable") then "unavailable"
            else "ambiguous"
            end
          )
        },
        map_sampling_scope: {
          metric_scope: (
            if all($maps[]; .status == "complete")
            then "exact_obi_process_open_bpf_map_ids"
            else "host_global_java_remote_par_superset"
            end
          ),
          ownership_attribution: all($maps[]; .status == "complete" and .ownership_attribution == true),
          descriptive_interpretation: (
            if all($maps[]; .status == "complete")
            then "stable_or_decreased_applies_only_to_exact_obi_owned_java_remote_parent_maps"
            else "unattributed_or_ambiguous_samples_cannot_pass_the_map_dimension"
            end
          ),
          evaluation_policy: "require_stable_exact_obi_process_bpf_fd_rosters_bracketing_each_metrics_scrape"
        },
        process_observations: $processes,
        java_bridge_map_observations: $maps
      } |
      .result = (
        if .process_dimension.result == "failed" or .map_dimension.result == "failed" then "failed"
        else "not_evaluated"
        end
      )
    '
}

validate_poc_gate_shape() {
  local -r artifact="$1"

  [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
  jq -se \
    --argjson required_repetitions "$REQUIRED_REPETITIONS" \
    --argjson maximum_regression "$MAX_PERFORMANCE_REGRESSION_PERCENT" '
      def nonnegative_integer:
        type == "number" and isfinite and floor == . and . >= 0;
      def positive_integer: nonnegative_integer and . > 0;
      def process_sources_are_exact:
        .sources == {
          before: ("cells/" + .cell + "/resources-before/" + .service + "-proc.txt"),
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery/" + .service + "-proc.txt")
        };
      def process_observation_is_exact:
        (.cell | type == "string" and length > 0) and
        (.service | type == "string" and length > 0) and
        process_sources_are_exact and
        if .status == "complete" then
          ((keys | sort) == [
            "cell", "container_id", "fd", "host_pid",
            "proc_cgroup_container_binding", "proc_cgroup_sha256", "proc_start_time",
            "result", "service",
            "sources", "status", "threads"
          ]) and
          (.result == "passed" or .result == "failed") and
          (.container_id | test("^[0-9a-f]{64}$")) and
          (.host_pid | positive_integer) and (.proc_start_time | positive_integer) and
          (.proc_cgroup_sha256 | test("^[0-9a-f]{64}$")) and
          .proc_cgroup_container_binding == "full_container_id_at_non_hex_boundaries" and
          all([.fd, .threads][];
            ((keys | sort) == ["before", "delta", "idle_recovery", "maximum_delta"]) and
            (.before | nonnegative_integer) and
            (.idle_recovery | nonnegative_integer) and
            (.delta | type == "number" and isfinite and floor == .) and
            .delta == .idle_recovery - .before and .maximum_delta == 0) and
          .result == (
            if .fd.delta <= .fd.maximum_delta and
              .threads.delta <= .threads.maximum_delta
            then "passed" else "failed" end
          )
        else
          ((keys | sort) == [
            "cell", "reason", "result", "service", "sources", "status"
          ]) and .status == "partial" and .result == "not_evaluated" and
          (.reason == "required_before_or_idle_recovery_proc_sample_unavailable_or_malformed" or
            .reason == "service_container_or_process_identity_changed_between_required_samples")
        end;
      def map_sources_are_exact:
        .sources == {
          before: ("cells/" + .cell + "/resources-before/obi-metrics.prom"),
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery/obi-metrics.prom")
        } and
        .ownership_sources == {
          before: ("cells/" + .cell + "/resources-before/obi-bpf-fd-ownership.txt"),
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery/obi-bpf-fd-ownership.txt")
        } and
        .process_sources == {
          before: ("cells/" + .cell + "/resources-before/obi-proc.txt"),
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery/obi-proc.txt")
        };
      def map_observation_is_exact:
        (.cell | type == "string" and length > 0) and map_sources_are_exact and
        if .status == "complete" then
          ((keys | sort) == [
            "cell", "data_status", "descriptive_result", "maps", "ownership",
            "ownership_attribution", "ownership_sources", "process_sources", "result",
            "scope", "sources", "status"
          ]) and
          (.result == "passed" or .result == "failed") and
          .data_status == "complete" and
          (.descriptive_result == "stable_or_decreased" or
            .descriptive_result == "growth_observed") and
          .scope == "exact_obi_process_open_bpf_map_ids" and
          .ownership_attribution == true and
          (.ownership |
            (keys | sort) == [
              "container_id", "descriptors", "host_pid", "map_ids",
              "proc_cgroup_container_binding", "proc_cgroup_sha256", "proc_start_time",
              "program_ids"
            ] and
            (.container_id | test("^[0-9a-f]{64}$")) and
            (.host_pid | positive_integer) and
            (.proc_start_time | positive_integer) and
            (.proc_cgroup_sha256 | test("^[0-9a-f]{64}$")) and
            .proc_cgroup_container_binding == "full_container_id_at_non_hex_boundaries" and
            (.descriptors |
              length > 0 and
              ([.[].fd] == ([.[].fd] | sort | unique)) and
              all(.[];
                ((keys | sort) == ["fd", "id", "kind"]) and
                (.fd | nonnegative_integer) and
                (.id | positive_integer) and
                (.kind == "map_id" or .kind == "prog_id"))) and
            (.map_ids | length > 0 and all(.[]; positive_integer) and
              . == (sort | unique)) and
            (.program_ids | all(.[]; positive_integer) and . == (sort | unique)) and
            .map_ids == ([.descriptors[] | select(.kind == "map_id") | .id] | sort | unique) and
            .program_ids == ([.descriptors[] | select(.kind == "prog_id") | .id] | sort | unique)) and
          (.ownership as $ownership |
            .maps | length > 0 and
            ([.[].map_id] == ([.[].map_id] | sort | unique)) and
            all(.[];
              ((keys | sort) == [
                "before_entries", "delta", "idle_recovery_entries", "map_id",
                "map_name", "map_type", "max_entries", "maximum_delta"
              ]) and
              (.map_id | positive_integer) and
              (.map_name == "java_remote_par") and
              (.map_type | type == "string" and length > 0) and
              (.before_entries | nonnegative_integer) and
              (.idle_recovery_entries | nonnegative_integer) and
              (.max_entries | positive_integer) and
              .before_entries <= .max_entries and
              .idle_recovery_entries <= .max_entries and
              (.delta | type == "number" and isfinite and floor == .) and
              .delta == .idle_recovery_entries - .before_entries and
              .maximum_delta == 0 and
              (.map_id as $id | $ownership.map_ids | index($id)) != null)) and
          .result == (
            if all(.maps[]; .delta <= .maximum_delta) then "passed" else "failed" end
          )
        else
          ((keys | sort) == [
            "cell", "data_status", "descriptive_result", "ownership_attribution",
            "ownership_sources", "process_sources", "reason", "result", "scope", "sources",
            "status"
          ]) and
          .status == "partial" and .result == "not_evaluated" and
          (.data_status == "unavailable" or .data_status == "ambiguous") and
          (.descriptive_result == "not_available" or
            .descriptive_result == "series_set_changed_or_was_duplicate") and
          .scope == "host_global_java_remote_par_superset" and
          .ownership_attribution == false and
          (.reason == "required_before_or_idle_recovery_java_bridge_map_sample_unavailable_or_malformed" or
            .reason == "required_stable_obi_bpf_fd_ownership_sample_unavailable_or_malformed" or
            .reason == "required_bound_obi_process_sample_unavailable_or_malformed" or
            .reason == "owned_java_bridge_map_series_or_bpf_fd_roster_changed_or_was_duplicate_or_incomplete")
        end;
      length == 1 and
      (.[0] |
        .schema_version == 1 and
        .kind == "predeclared-java-remote-parent-poc-gate-evaluation" and
        .status == "partial" and
        (.result == "not_evaluated" or .result == "failed") and
        .issue_acceptance_complete == false and
        (.thresholds |
          .declaration_source == "BENCHMARK.md#predeclared-poc-gates" and
          .correctness_failures_max == 0 and
          .required_repetitions == $required_repetitions and
          .throughput_regression_max_percent == $maximum_regression and
          .p99_latency_regression_max_percent == $maximum_regression and
          .fd_delta_max == 0 and .thread_delta_max == 0 and
          .java_bridge_map_entries_delta_max == 0) and
        (.correctness |
          .status == "complete" and (.result == "passed" or .result == "failed") and
          (.observed_failures | nonnegative_integer) and
          (.cells | type == "array" and length == 6)) and
        (.performance |
          .status == "complete" and (.result == "passed" or .result == "failed") and
          .baseline.cell == "bridge-disabled" and
          .required_repetitions == $required_repetitions and
          ([.comparisons[].cell] == [
            "getsockopt-hit", "unix-hit", "getsockopt-w3c"
          ]) and
          .excluded_cells == {
            uninstrumented: "no_official_agent",
            getsockopt_helper_idle: "direct_java_workload_is_not_comparable_to_the_apache_baseline"
          } and
          all(.comparisons[];
            .result == "passed" or .result == "failed")) and
        (.resources |
          .status == "partial" and
          .required_samples == ["before", "idle_recovery"] and
          .unavailable_samples_fail_closed == true and
          (.process_dimension |
            if .status == "complete"
            then (.result == "passed" or .result == "failed")
            else .status == "partial" and .result == "not_evaluated"
            end) and
          .result == (
            if .process_dimension.result == "failed" or .map_dimension.result == "failed"
            then "failed"
            else "not_evaluated"
            end
          ) and
          (.map_dimension |
            ((keys | sort) == ["descriptive_data_status", "reason", "result", "status"]) and
            if .status == "complete" then
              (.result == "passed" or .result == "failed") and
              .reason == null and .descriptive_data_status == "complete"
            else
              .status == "partial" and .result == "not_evaluated" and
              .reason == "stable_exact_obi_bpf_fd_ownership_is_required_for_every_map_sample" and
              (.descriptive_data_status == "complete" or
                .descriptive_data_status == "ambiguous" or
                .descriptive_data_status == "unavailable")
            end) and
          (.map_sampling_scope |
            ((keys | sort) == [
              "descriptive_interpretation", "evaluation_policy", "metric_scope",
              "ownership_attribution"
            ]) and
            .evaluation_policy ==
              "require_stable_exact_obi_process_bpf_fd_rosters_bracketing_each_metrics_scrape" and
            if .ownership_attribution then
              .metric_scope == "exact_obi_process_open_bpf_map_ids" and
              .descriptive_interpretation ==
                "stable_or_decreased_applies_only_to_exact_obi_owned_java_remote_parent_maps"
            else
              .metric_scope == "host_global_java_remote_par_superset" and
              .descriptive_interpretation ==
                "unattributed_or_ambiguous_samples_cannot_pass_the_map_dimension"
            end) and
          (.process_observations | type == "array" and length == 23) and
          ([.process_observations[] | [.cell, .service]] == [
            ["uninstrumented", "trace-receiver"],
            ["uninstrumented", "apache-proxy"],
            ["uninstrumented", "java-backend"],
            ["bridge-disabled", "trace-receiver"],
            ["bridge-disabled", "apache-proxy"],
            ["bridge-disabled", "java-backend"],
            ["bridge-disabled", "obi"],
            ["getsockopt-hit", "trace-receiver"],
            ["getsockopt-hit", "apache-proxy"],
            ["getsockopt-hit", "java-backend"],
            ["getsockopt-hit", "obi"],
            ["unix-hit", "trace-receiver"],
            ["unix-hit", "apache-proxy"],
            ["unix-hit", "java-backend"],
            ["unix-hit", "obi"],
            ["getsockopt-w3c", "trace-receiver"],
            ["getsockopt-w3c", "apache-proxy"],
            ["getsockopt-w3c", "java-backend"],
            ["getsockopt-w3c", "obi"],
            ["getsockopt-helper-idle", "trace-receiver"],
            ["getsockopt-helper-idle", "apache-proxy"],
            ["getsockopt-helper-idle", "java-backend"],
            ["getsockopt-helper-idle", "obi"]
          ]) and
          all(.process_observations[]; process_observation_is_exact) and
          (.java_bridge_map_observations | type == "array" and length == 5) and
          ([.java_bridge_map_observations[].cell] == [
            "bridge-disabled", "getsockopt-hit", "unix-hit",
            "getsockopt-w3c", "getsockopt-helper-idle"
          ]) and
          all(.java_bridge_map_observations[]; map_observation_is_exact) and
          (. as $resources |
            all(.java_bridge_map_observations[];
              . as $map |
              if $map.status != "complete" then true
              else
                ([$resources.process_observations[] |
                  select(.cell == $map.cell and .service == "obi" and .status == "complete")]) as $owners |
                ($owners | length) == 1 and
                ($owners[0] | {
                  container_id, host_pid, proc_start_time, proc_cgroup_sha256,
                  proc_cgroup_container_binding
                }) ==
                ($map.ownership | {
                  container_id, host_pid, proc_start_time, proc_cgroup_sha256,
                  proc_cgroup_container_binding
                })
              end))) and
        .unmeasured_dimensions == {
          jfr_nmt_allocation_native_direct_memory: "not_collected",
          primary_cgroupsockopt_program_cpu: "not_collected",
          bpf_lock_contention: "not_collected"
        } and
        .result == (
          if .correctness.result == "failed" or
             .performance.result == "failed" or
             .resources.result == "failed"
          then "failed" else "not_evaluated" end
        )
      )
    ' "$artifact" >/dev/null
}

validate_supported_poc_dimensions_pass() {
  local -r artifact="$1"

  validate_poc_gate_schema "$artifact" || return 1
  jq -se '
    length == 1 and
    (.[0] |
      .status == "partial" and .result == "not_evaluated" and
      (.correctness |
        .status == "complete" and .result == "passed" and
        .observed_failures == 0
      ) and
      .performance.status == "complete" and .performance.result == "passed" and
      .resources.process_dimension == {status: "complete", result: "passed"} and
      all(.resources.process_observations[];
        .status == "complete" and .result == "passed") and
      .resources.map_dimension == {
        status: "complete", result: "passed", reason: null,
        descriptive_data_status: "complete"
      } and
      .resources.map_dimension.descriptive_data_status == "complete" and
      all(.resources.java_bridge_map_observations[];
        .status == "complete" and .result == "passed" and
        .ownership_attribution == true and
        .data_status == "complete"))
  ' "$artifact" >/dev/null
}

poc_gate_summary_json() {
  local -r root="${1:-$OUTPUT_DIR}"
  local OUTPUT_DIR="$root"
  local cell=""
  local status_file=""
  local statuses_json=""
  local resources_json=""
  local -a statuses=()

  [[ -d "$root" && ! -L "$root" &&
    -f "$root/variance.json" && ! -L "$root/variance.json" &&
    "$REPETITIONS" == "$REQUIRED_REPETITIONS" ]] || return 1
  validate_variance_summary_schema "$root/variance.json" || return 1
  jq -se --argjson repetitions "$REQUIRED_REPETITIONS" '
    length == 1 and
    (.[0] |
      ([.cells[].cell] == [
        "uninstrumented", "bridge-disabled", "getsockopt-hit", "unix-hit",
        "getsockopt-w3c", "getsockopt-helper-idle"
      ]) and
      all(.cells[];
        .expected_sample_count == $repetitions and
        .valid_sample_count == $repetitions and
        (.samples | length) == $repetitions))
  ' "$root/variance.json" >/dev/null || return 1
  for cell in "${CORE_CELLS[@]}"; do
    status_file="$root/cells/$cell/status.json"
    [[ -f "$status_file" && ! -L "$status_file" ]] || return 1
    statuses+=("$(jq -sce --arg cell "$cell" '
      if length != 1 then error("expected one cell status") else
        .[0] |
        if ((keys | sort) == ["cell", "completed_at", "reason", "status"]) and
          .cell == $cell and
          (.completed_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
          ((.status == "passed" and .reason == null) or
           (.status == "failed" and (.reason | type == "string" and length > 0)))
        then . else error("invalid cell status") end
      end
    ' "$status_file")") || return 1
  done
  statuses_json="$(printf '%s\n' "${statuses[@]}" | jq -s .)" || return 1
  resources_json="$(resource_growth_gate)" || return 1
  jq -n \
    --argjson required_repetitions "$REQUIRED_REPETITIONS" \
    --argjson maximum_regression "$MAX_PERFORMANCE_REGRESSION_PERCENT" \
    --argjson statuses "$statuses_json" \
    --argjson resources "$resources_json" \
    --slurpfile variance "$root/variance.json" '
      def regression_percent($baseline; $candidate; $higher_is_better):
        if $higher_is_better then
          (if $candidate >= $baseline then 0
           else (($baseline - $candidate) * 100 / $baseline) end)
        else
          (if $candidate <= $baseline then 0
           else (($candidate - $baseline) * 100 / $baseline) end)
        end;
      ($variance[0].cells | map({key: .cell, value: .}) | from_entries) as $cells |
      $cells["bridge-disabled"] as $baseline |
      [
        "getsockopt-hit", "unix-hit", "getsockopt-w3c"
      ] as $comparison_cells |
      ([
        $comparison_cells[] as $cell |
        $cells[$cell] as $candidate |
        {
          cell: $cell,
          throughput_per_second: {
            baseline_median: $baseline.statistics.throughput_per_second.median,
            candidate_median: $candidate.statistics.throughput_per_second.median,
            regression_percent: regression_percent(
              $baseline.statistics.throughput_per_second.median;
              $candidate.statistics.throughput_per_second.median;
              true
            ),
            maximum_regression_percent: $maximum_regression
          },
          p99_latency_nanos: {
            baseline_median: $baseline.statistics.latency.p99_nanos.median,
            candidate_median: $candidate.statistics.latency.p99_nanos.median,
            regression_percent: regression_percent(
              $baseline.statistics.latency.p99_nanos.median;
              $candidate.statistics.latency.p99_nanos.median;
              false
            ),
            maximum_regression_percent: $maximum_regression
          }
        } |
        .result = (
          if .throughput_per_second.regression_percent <= $maximum_regression and
             .p99_latency_nanos.regression_percent <= $maximum_regression
          then "passed" else "failed" end
        )
      ]) as $comparisons |
      ([
        $variance[0].cells[].samples[].failed_requests,
        ($statuses[] | if .status == "passed" then 0 else 1 end)
      ] | add) as $observed_failures |
      {
        schema_version: 1,
        kind: "predeclared-java-remote-parent-poc-gate-evaluation",
        issue_acceptance_complete: false,
        thresholds: {
          declaration_source: "BENCHMARK.md#predeclared-poc-gates",
          correctness_failures_max: 0,
          required_repetitions: $required_repetitions,
          throughput_regression_max_percent: $maximum_regression,
          p99_latency_regression_max_percent: $maximum_regression,
          fd_delta_max: 0,
          thread_delta_max: 0,
          java_bridge_map_entries_delta_max: 0
        },
        correctness: {
          status: "complete",
          result: (if $observed_failures == 0 then "passed" else "failed" end),
          observed_failures: $observed_failures,
          cells: $statuses,
          sources: {
            cell_statuses: "cells/*/status.json",
            sustained_results: "cells/*/measurements/rep-*.json"
          }
        },
        performance: {
          status: "complete",
          result: (if all($comparisons[]; .result == "passed") then "passed" else "failed" end),
          source: "variance.json",
          required_repetitions: $required_repetitions,
          baseline: {
            cell: "bridge-disabled",
            throughput_per_second_median: $baseline.statistics.throughput_per_second.median,
            p99_latency_nanos_median: $baseline.statistics.latency.p99_nanos.median
          },
          comparisons: $comparisons,
          excluded_cells: {
            uninstrumented: "no_official_agent",
            getsockopt_helper_idle: "direct_java_workload_is_not_comparable_to_the_apache_baseline"
          }
        },
        resources: $resources,
        unmeasured_dimensions: {
          jfr_nmt_allocation_native_direct_memory: "not_collected",
          primary_cgroupsockopt_program_cpu: "not_collected",
          bpf_lock_contention: "not_collected"
        }
      } |
      .status = "partial" |
      .result = (
        if .correctness.result == "failed" or
           .performance.result == "failed" or
           .resources.result == "failed"
        then "failed" else "not_evaluated" end
      )
    '
}

validate_poc_gate_schema() {
  local -r artifact="$1"
  local artifact_root=""
  local expected=""

  validate_poc_gate_shape "$artifact" || return 1
  artifact_root="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  expected="$(poc_gate_summary_json "$artifact_root")" || return 1
  jq -se --argjson expected "$expected" '
    length == 1 and .[0] == $expected
  ' "$artifact" >/dev/null
}

write_poc_gate_summary() {
  local -r output="$OUTPUT_DIR/poc-gates.json"
  local temporary=""

  [[ "$OUTPUT_READY" == "true" && ! -e "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "$OUTPUT_DIR/.poc-gates.json.XXXXXX")" || return 1
  if ! poc_gate_summary_json "$OUTPUT_DIR" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  validate_poc_gate_schema "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  mv -T -- "$temporary" "$output" || {
    rm -f -- "$temporary"
    return 1
  }
  validate_poc_gate_schema "$output" || {
    rm -f -- "$output"
    return 1
  }
}

validate_concurrency_sentinel() {
  local -r result="$1"
  local -r assertion_mode="$2"

  [[ -f "$result" && ! -L "$result" ]] || return 1
  jq -se \
    --arg assertion_mode "$assertion_mode" \
    --arg tls "$TLS_PROTOCOL" \
    --argjson requests "$PREFLIGHT_REQUESTS" \
    --argjson seed "$SEED" '
      length == 1 and
      (.[0] |
        .status == "passed" and
        .scenario == "concurrency" and
        .request_count == $requests and
        .seed == $seed and
        (.cases | type == "array" and length == $requests) and
        (if $assertion_mode == "" then .assertion_mode == "bridge"
         else .assertion_mode == $assertion_mode end) and
        ([.cases[] | .response.tls_protocol] | all(. == $tls))
      )
    ' "$result" >/dev/null
}

validate_w3c_sentinel() {
  local -r result="$1"
  local -r endpoint="${WORKLOAD_PATH%%\?*}"

  [[ -f "$result" && ! -L "$result" ]] || return 1
  jq -se \
    --arg tls "$TLS_PROTOCOL" \
    --arg endpoint "$endpoint" \
    --argjson requests "$PREFLIGHT_REQUESTS" \
    --argjson seed "$SEED" \
    --argjson standard_parent_discards "$CELL_EXPECTED_STANDARD_PARENT_DISCARDS" '
      def marked($marker):
        (.attributes | type) == "object" and
        ([.attributes | to_entries[] |
          select(
            (.key | ascii_downcase) == "http.request.header.x-obi-demo-id" or
            (.key | ascii_downcase) == "http.request.header.x_obi_demo_id"
          ) | .value
        ]) as $marker_values |
        ($marker_values | length > 0 and
          all(.[]; type == "string" and . == $marker));
      def nonzero_trace_id:
        type == "string" and test("^[0-9a-f]{32}\\z") and
        . != "00000000000000000000000000000000";
      def nonzero_span_id:
        type == "string" and test("^[0-9a-f]{16}\\z") and
        . != "0000000000000000";
      def remote_parent:
        (.flags |
          if type == "number" then
            floor == . and . >= 0 and
            ((. / 256 | floor) % 2) == 1 and
            ((. / 512 | floor) % 2) == 1
          else false
          end);
      def trace_flags:
        (.flags | if type == "number" and floor == . and . >= 0 then . % 256 else -1 end);
      def zero_span_id:
        if . == null then true
        elif type == "string" then . == "" or test("^0+\\z")
        else false
        end;
      def endpoint_path:
        if type != "string" then null
        elif contains("#") then null
        elif startswith("/") then split("?")[0]
        else try capture("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]+(?<path>/[^?#]*)").path catch null
        end;
      def endpoint_matches($endpoint):
        if (.attributes | type) != "object" then false
        else
          .attributes["http.route"] == $endpoint or
          .attributes["url.path"] == $endpoint or
          ([.attributes["http.target"], .attributes["http.url"], .attributes["url.full"]]
            | any(.[]; endpoint_path == $endpoint))
        end;
      def descends_from($spans; $descendant; $ancestor):
        def follow($parent_id; $seen; $found_ancestor):
          if ($parent_id | zero_span_id) then $found_ancestor
          elif ($seen | index($parent_id)) != null then false
          else
            ([ $spans[] | select(
              .trace_id == $descendant.trace_id and .span_id == $parent_id
            ) ]) as $parents |
            if ($parents | length) == 0 then $found_ancestor
            elif ($parents | length) != 1 then false
            elif (($found_ancestor | not) and
              $parents[0].service_name != $ancestor.service_name) then false
            else
              follow(
                $parents[0].parent_span_id;
                $seen + [$parent_id];
                ($found_ancestor or $parent_id == $ancestor.span_id)
              )
            end
          end;
        ($descendant.trace_id == $ancestor.trace_id and
          $descendant.service_name == $ancestor.service_name and
          ([ $spans[] | select(
            .trace_id == $descendant.trace_id and .span_id == $descendant.span_id
          ) ] | length == 1) and
          ([ $spans[] | select(
            .trace_id == $ancestor.trace_id and .span_id == $ancestor.span_id
          ) ] | length == 1) and
          follow($descendant.parent_span_id; []; false));
      length == 1 and
      (.[0] |
        .status == "passed" and
        .scenario == "w3c" and
        .request_count == $requests and
        .seed == $seed and
        (.cases | type == "array" and length == $requests) and
        ([.cases[] |
          select(.request.w3c_case == "conflicting-valid-w3c-and-obi")]
          | length == $standard_parent_discards) and
        ([.cases[] |
          select(.request.w3c_case == "malformed-w3c-valid-obi" and
            .request.invalid_w3c == true)]
          | length == ($requests - $standard_parent_discards)) and
        ([.cases[] | .response.tls_protocol] | all(. == $tls)) and
        all(.cases[];
          . as $case |
          if ($case.trace.spans | type) != "array" then false
          else
            $case.request as $request |
            $request.marker as $marker |
            $case.trace.spans as $spans |
            ([ $spans[] | select(
              .service_name == "java-backend" and .kind == "SERVER" and marked($marker)
            ) ]) as $java_servers |
            ([ $spans[] | select(
              .service_name == "apache-proxy" and .kind == "SERVER" and marked($marker)
            ) ]) as $apache_servers |
            ([ $spans[] | select(
              .service_name == "apache-proxy" and .kind == "CLIENT" and marked($marker)
            ) ]) as $apache_clients |
            ($request | type == "object") and
            ($marker | type == "string" and test("^[a-z0-9-]+\\z") and
              $case.trace.dropped_spans == 0 and
              $request.endpoint == $endpoint and
              $case.response.marker == $marker and $case.trace.marker == $marker and
              ($java_servers | length == 1) and
              ($apache_servers | length == 1) and
              ($apache_clients | length == 1) and
              ($java_servers[0].trace_id | nonzero_trace_id) and
              ($java_servers[0].span_id | nonzero_span_id) and
              ($apache_servers[0].trace_id | nonzero_trace_id) and
              ($apache_servers[0].span_id | nonzero_span_id) and
              ($apache_clients[0].trace_id | nonzero_trace_id) and
              ($apache_clients[0].span_id | nonzero_span_id) and
              ($java_servers[0] | endpoint_matches($endpoint)) and
              ($apache_servers[0] | endpoint_matches($endpoint)) and
              ($apache_clients[0] | endpoint_matches($endpoint)) and
              descends_from($spans; $apache_clients[0]; $apache_servers[0]) and
              ($java_servers[0] | remote_parent) and
              (if $request.w3c_case == "conflicting-valid-w3c-and-obi" then
                ($request | has("invalid_w3c") | not) and
                ($request.w3c_trace_id | nonzero_trace_id) and
                ($request.w3c_parent_span_id | nonzero_span_id) and
                $request.w3c_trace_flags == "01" and
                $java_servers[0].trace_id == $request.w3c_trace_id and
                $java_servers[0].parent_span_id == $request.w3c_parent_span_id and
                ($java_servers[0] | trace_flags) == 1 and
                $apache_servers[0].trace_id == $request.w3c_trace_id and
                $apache_servers[0].parent_span_id == $request.w3c_parent_span_id and
                ($apache_servers[0] | trace_flags) == 1 and
                $apache_clients[0].trace_id == $request.w3c_trace_id and
                $apache_clients[0].span_id != $request.w3c_parent_span_id and
                ($apache_clients[0] | trace_flags) == 1
               elif $request.w3c_case == "malformed-w3c-valid-obi" then
                $request.invalid_w3c == true and
                ($request | has("w3c_trace_id") | not) and
                ($request | has("w3c_parent_span_id") | not) and
                ($request | has("w3c_trace_flags") | not) and
                ($apache_servers[0].parent_span_id | zero_span_id) and
                $apache_servers[0].trace_id == $apache_clients[0].trace_id and
                $java_servers[0].trace_id == $apache_clients[0].trace_id and
                $java_servers[0].parent_span_id == $apache_clients[0].span_id and
                ($java_servers[0] | trace_flags) == ($apache_clients[0] | trace_flags)
               else false
               end)
            )
          end
        )
      )
    ' "$result" >/dev/null
}

validate_cell_sentinel() {
  local -r result="$1"

  case "$CELL_SENTINEL_SCENARIO" in
    concurrency)
      validate_concurrency_sentinel "$result" "$CELL_ASSERTION_MODE"
      ;;
    w3c)
      validate_w3c_sentinel "$result"
      ;;
    *)
      return 1
      ;;
  esac
}

validate_w3c_runner_status() {
  local -r status_file="$1"

  [[ -f "$status_file" && ! -L "$status_file" ]] || return 1
  jq -se '
    length == 1 and
    (.[0] |
      .status == "passed" and
      .scenario == "w3c" and
      .exit_status == 0 and
      .metric_status == 0 and
      .result == "scenario-w3c.json" and
      .after_phase == "phases/w3c-after"
    )
  ' "$status_file" >/dev/null
}

validate_runner_scenario_status() {
  local -r status_file="$1"
  local -r expected_scenario="$2"
  local -r expected_result="$3"

  [[ -f "$status_file" && ! -L "$status_file" ]] || return 1
  jq -se \
    --arg scenario "$expected_scenario" \
    --arg result "$expected_result" '
      length == 1 and
      (.[0] |
        .status == "passed" and
        .scenario == $scenario and
        .exit_status == 0 and
        .metric_status == 0 and
        .result == $result
      )
    ' "$status_file" >/dev/null
}

validate_runner_scenario_measurement() {
  local -r result_file="$1"
  local -r expected_scenario="$2"
  local -r expected_requests="$3"

  [[ -f "$result_file" && ! -L "$result_file" ]] || return 1
  jq -se \
    --arg scenario "$expected_scenario" \
    --argjson requests "$expected_requests" '
      def nonnegative_integer:
        type == "number" and isfinite and floor == . and . >= 0;
      def positive_integer:
        nonnegative_integer and . > 0;
      length == 1 and
      (.[0] |
        .status == "passed" and
        .scenario == $scenario and
        .request_count == $requests and
        (.traffic_elapsed_nanos | positive_integer) and
        (.throughput_per_second | type == "number" and isfinite and . > 0) and
        (.latency | type == "object") and
        (.latency.p50_nanos | positive_integer) and
        (.latency.p95_nanos | positive_integer) and
        (.latency.p99_nanos | positive_integer) and
        .latency.p50_nanos <= .latency.p95_nanos and
        .latency.p95_nanos <= .latency.p99_nanos and
        (.cases | type == "array" and length == $requests) and
        all(.cases[];
          (.latency_nanos | positive_integer) and
          (.request | type == "object") and
          (.response | type == "object") and
          (.trace | type == "object"))
      )
    ' "$result_file" >/dev/null
}

diagnostic_delta_value() {
  local -r delta_file="$1"
  local -r wanted_counter="$2"

  [[ -f "$delta_file" && ! -L "$delta_file" &&
    "$wanted_counter" =~ ^t_[a-z_]+$ ]] || return 1
  awk -v wanted="$wanted_counter" -v maximum="$MAX_JAVA_DIAGNOSTIC_COUNTER" '
    function bounded(value) {
      return value ~ /^(0|[1-9][0-9]*)$/ &&
        length(value) <= length(maximum) &&
        (length(value) < length(maximum) || value < maximum)
    }
    $1 == wanted {
      matches++
      before = $2
      after = $3
      delta = $4
      if (NF != 4 || sub(/^before=/, "", before) != 1 ||
          sub(/^after=/, "", after) != 1 ||
          sub(/^delta=/, "", delta) != 1 ||
          !bounded(before) || !bounded(after) || !bounded(delta) ||
          after + 0 < before + 0 || delta + 0 != after + 0 - before + 0) {
        invalid = 1
      }
    }
    END {
      if (matches != 1 || invalid) {
        exit 1
      }
      print delta
    }
  ' "$delta_file"
}

java_path_diagnostic_counts() {
  local -r delta_file="$1"
  local status=""
  local value=""
  local -a arguments=()
  local -a statuses=(
    unknown valid missing stale unsupported malformed version_mismatch ambiguous
    unauthorized already_consumed timeout overload transport_error disabled
  )

  for status in "${statuses[@]}"; do
    value="$(diagnostic_delta_value "$delta_file" "t_$status")" || return 1
    arguments+=(--argjson "$status" "$value")
  done
  jq -cn "${arguments[@]}" '
    {
      unknown: $unknown,
      valid: $valid,
      missing: $missing,
      stale: $stale,
      unsupported: $unsupported,
      malformed: $malformed,
      version_mismatch: $version_mismatch,
      ambiguous: $ambiguous,
      unauthorized: $unauthorized,
      already_consumed: $already_consumed,
      timeout: $timeout,
      overload: $overload,
      transport_error: $transport_error,
      disabled: $disabled
    }
  '
}

validate_path_diagnostic_counts() {
  local -r counts_json="$1"
  local -r expected_valid="$2"
  local -r expected_missing="$3"
  local -r expected_stale="$4"
  local -r expected_timeout="$5"

  jq -e \
    --argjson valid "$expected_valid" \
    --argjson missing "$expected_missing" \
    --argjson stale "$expected_stale" \
    --argjson timeout "$expected_timeout" '
      .valid == $valid and
      .missing == $missing and
      .stale == $stale and
      .timeout == $timeout and
      ([
        .unknown, .unsupported, .malformed, .version_mismatch, .ambiguous,
        .unauthorized, .already_consumed, .overload, .transport_error, .disabled
      ] | all(. == 0))
    ' <<<"$counts_json" >/dev/null
}

pressure_map_sample_json() {
  local -r metrics_file="$1"
  local -r expected_map_id="$2"
  local -r expected_max_entries="$3"
  local -r expected_map_type="$4"
  local metric_rows=""
  local rows_json=""

  [[ "$expected_map_id" =~ ^[1-9][0-9]*$ &&
    "$expected_max_entries" =~ ^[1-9][0-9]*$ &&
    "$expected_map_type" =~ ^[a-z0-9_]+$ ]] || return 1
  metric_rows="$(java_bridge_map_metric_rows "$metrics_file")" || return 1
  rows_json="$(map_rows_json <<<"$metric_rows")" || return 1
  jq -cn --argjson rows "$rows_json" --argjson map_id "$expected_map_id" \
    --argjson max_entries "$expected_max_entries" --arg map_type "$expected_map_type" '
      [$rows[] | select(.map_id == $map_id)] as $selected |
      ([$selected[] | select(.metric == "entries")][0].value) as $entries |
      if ($selected | length) == 2 and
        ([$selected[].metric] | sort) == ["entries", "max_entries"] and
        all($selected[];
          .map_name == "java_remote_par" and .map_type == $map_type) and
        ([$selected[] | select(.metric == "max_entries")][0].value == $max_entries) and
        $entries <= $max_entries
      then {
        map_id: $map_id,
        map_name: "java_remote_par",
        map_type: $map_type,
        entries: $entries,
        max_entries: $max_entries
      }
      else error("pressure map sample does not match the retained map identity") end
    ' || return 1
}

pressure_recovery_evidence_json() {
  local -r runner_directory="$1"
  local -r prepare_file="$runner_directory/map-pressure-pressure-prepare.json"
  local -r baseline_file="$runner_directory/phases/pressure-before/obi-metrics.prom"
  local -r recovered_file="$runner_directory/map-pressure-pressure-recovered.prom"
  local -r recovery_log="$runner_directory/map-pressure-pressure-recovered-samples.log"
  local map_id=""
  local max_entries=""
  local map_type=""
  local baseline_json=""
  local recovered_json=""
  local baseline_entries=""
  local recovered_entries=""
  local sample_file=""
  local sample_json=""
  local sample_entries_json=""
  local sample_count=0
  local attempts=""
  local -a sample_files=()
  local -a sample_entries=()

  map_id="$(jq -er '.map_id' "$prepare_file")" || return 1
  max_entries="$(jq -er '.max_entries' "$prepare_file")" || return 1
  map_type="$(jq -er '.map_type | ascii_downcase' "$prepare_file")" || return 1
  map_id="$(normalize_decimal "$map_id" 4294967295 false)" || return 1
  max_entries="$(normalize_decimal \
    "$max_entries" "$PRESSURE_MAP_MAX_SUPPORTED_ENTRIES" false)" || return 1
  [[ "$map_type" =~ ^[a-z0-9_]+$ && -s "$recovery_log" &&
    -f "$recovery_log" && ! -L "$recovery_log" ]] || return 1
  baseline_json="$(pressure_map_sample_json \
    "$baseline_file" "$map_id" "$max_entries" "$map_type")" || return 1
  recovered_json="$(pressure_map_sample_json \
    "$recovered_file" "$map_id" "$max_entries" "$map_type")" || return 1
  baseline_entries="$(jq -er '.entries' <<<"$baseline_json")" || return 1
  recovered_entries="$(jq -er '.entries' <<<"$recovered_json")" || return 1
  baseline_entries="$(normalize_decimal "$baseline_entries" "$max_entries" true)" || return 1
  recovered_entries="$(normalize_decimal "$recovered_entries" "$max_entries" true)" || return 1
  ((baseline_entries == 0 && recovered_entries == 0)) || return 1
  shopt -s nullglob
  sample_files=("$runner_directory"/map-pressure-pressure-recovered-sample-*.prom)
  shopt -u nullglob
  sample_count="${#sample_files[@]}"
  ((sample_count == PRESSURE_RECOVERY_REQUIRED_SAMPLES)) || return 1
  for ((sample_count = 1; sample_count <= PRESSURE_RECOVERY_REQUIRED_SAMPLES; sample_count++)); do
    printf -v sample_file '%s/map-pressure-pressure-recovered-sample-%02d.prom' \
      "$runner_directory" "$sample_count"
    [[ "${sample_files[$((sample_count - 1))]}" == "$sample_file" ]] || return 1
    sample_json="$(pressure_map_sample_json \
      "$sample_file" "$map_id" "$max_entries" "$map_type")" || return 1
    sample_entries+=("$(jq -er '.entries' <<<"$sample_json")")
    sample_entries[$((sample_count - 1))]="$(normalize_decimal \
      "${sample_entries[$((sample_count - 1))]}" "$max_entries" true)" || return 1
    ((sample_entries[$((sample_count - 1))] <= baseline_entries)) || return 1
  done
  cmp -- "${sample_files[$((PRESSURE_RECOVERY_REQUIRED_SAMPLES - 1))]}" \
    "$recovered_file" >/dev/null || return 1
  [[ "$recovered_entries" == \
    "${sample_entries[$((PRESSURE_RECOVERY_REQUIRED_SAMPLES - 1))]}" ]] || return 1
  attempts="$(awk -v baseline="$baseline_entries" \
    -v first="${sample_entries[0]}" \
    -v second="${sample_entries[1]}" \
    -v required="$PRESSURE_RECOVERY_REQUIRED_SAMPLES" '
      function fail() { invalid = 1 }
      {
        if (NF != 5) { fail(); next }
        attempt = $1
        observed_at = $2
        entries = $3
        matched = $4
        consecutive = $5
        if (sub(/^attempt=/, "", attempt) != 1 ||
            sub(/^observed_at=/, "", observed_at) != 1 ||
            sub(/^entries=/, "", entries) != 1 ||
            sub(/^matched=/, "", matched) != 1 ||
            sub(/^consecutive=/, "", consecutive) != 1 ||
            attempt !~ /^[1-9][0-9]*$/ || attempt + 0 != NR ||
            observed_at !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/ ||
            (entries != "unavailable" && entries !~ /^(0|[1-9][0-9]*)$/) ||
            matched !~ /^(true|false)$/ ||
            consecutive !~ /^(0|[1-9][0-9]*)$/) {
          fail()
          next
        }
        expected_match = entries != "unavailable" && entries + 0 <= baseline
        if ((matched == "true") != expected_match) { fail() }
        if (matched == "true") { expected_consecutive++ }
        else { expected_consecutive = 0 }
        if (consecutive + 0 != expected_consecutive || expected_consecutive > required) {
          fail()
        }
        if (expected_consecutive == required) {
          terminal_line = NR
        }
        previous_entries = last_entries
        last_entries = entries
      }
      END {
        if (invalid || NR < required || terminal_line != NR ||
            expected_consecutive != required || previous_entries != first ||
            last_entries != second) {
          exit 1
        }
        print NR
      }
    ' "$recovery_log")" || return 1
  [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
  sample_entries_json="$(printf '%s\n' "${sample_entries[@]}" | jq -s 'map(tonumber)')" || return 1
  jq -cn --argjson map_id "$map_id" --arg map_type "$map_type" \
    --argjson max_entries "$max_entries" --argjson baseline "$baseline_entries" \
    --argjson recovered "$recovered_entries" \
    --argjson samples "$sample_entries_json" --argjson attempts "$attempts" '
      {
        map_id: $map_id,
        kernel_map_name: "java_remote_par",
        map_type: $map_type,
        max_entries: $max_entries,
        baseline_entries: $baseline,
        recovery_sample_count: ($samples | length),
        recovery_sample_entries: $samples,
        recovered_entries: $recovered,
        recovery_log_attempts: $attempts
      }
  '
}

pressure_artifact_sha256() {
  local -r input="$1"
  local digest=""

  [[ -f "$input" && ! -L "$input" ]] || return 1
  digest="$(sha256sum -- "$input")" || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

validate_pressure_control_file() {
  local -r input="$1"
  local -r expected="$2"
  local -a lines=()

  [[ -f "$input" && ! -L "$input" ]] || return 1
  mapfile -t lines <"$input" || return 1
  ((${#lines[@]} == 1)) || return 1
  [[ "${lines[0]}" == "$expected" && "$(stat -Lc '%s' -- "$input")" == \
    "$((${#expected} + 1))" ]]
}

validate_pressure_container_inspections() {
  local -r runner_directory="$1"
  local -r artifact="$runner_directory/map-pressure-pressure-container-inspections.json"
  local -r environment_file="$runner_directory/environment.txt"
  local canonical=""
  local project=""
  local tls=""
  local seed=""
  local owner_gid=""
  local identity=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local size=""
  local extra=""
  local -a lines=()

  [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$artifact")" || return 1
  IFS=: read -r device inode owner mode links size extra <<<"$identity"
  [[ -z "$extra" && "$device" =~ ^[0-9]+$ && "$inode" =~ ^[1-9][0-9]*$ &&
    "$owner" == "$EUID" && "$mode" == 600 && "$links" == 1 &&
    "$size" =~ ^[1-9][0-9]*$ &&
    "$size" -le "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" ]] || return 1
  mapfile -t lines <"$artifact" || return 1
  ((${#lines[@]} == 1)) || return 1
  canonical="$(jq -cS . <<<"${lines[0]}")" || return 1
  [[ "${lines[0]}" == "$canonical" && "$size" == "$((${#canonical} + 1))" &&
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$artifact")" == "$identity" ]] ||
    return 1

  project="$(runner_environment_value "$environment_file" compose_project)" ||
    return 1
  tls="$(runner_environment_value "$environment_file" tls_protocol)" || return 1
  seed="$(runner_environment_value "$environment_file" scenario_seed)" || return 1
  [[ "$project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ &&
    "$tls" =~ ^TLSv1\.[23]$ && "$seed" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  owner_gid="$(id -g)" || return 1
  [[ "$owner_gid" =~ ^(0|[1-9][0-9]*)$ ]] || return 1

  jq -e --arg project "$project" --arg tls "$tls" --arg seed "$seed" \
    --arg owner_uid "$EUID" --arg owner_gid "$owner_gid" \
    --argjson requests "$PRESSURE_REQUESTS" '
    def uint32:
      type == "number" and isfinite and floor == . and
      . >= 0 and . <= 4294967295;
    def uint32_decimal:
      type == "string" and test("^(0|[1-9][0-9]*)$") and
      (tonumber >= 0 and tonumber <= 4294967295);
    def timestamp_parts:
      capture("^(?<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\\.(?<fraction>[0-9]{0,8}[1-9]))?Z$") as $parts |
      ($parts.base + "Z" | fromdateiso8601) as $seconds |
      select(($seconds | todateiso8601) == ($parts.base + "Z")) |
      [$seconds, (((($parts.fraction // "") + "000000000")[0:9]) | tonumber)];
    . as $root |
    $root.running as $running |
    $root.terminal as $terminal |
    ($running.config.user | split(":")) as $user |
    ($running.state.started_at | timestamp_parts) as $started |
    ($terminal.state.finished_at | timestamp_parts) as $finished |
    keys == ["running", "scenario_label", "schema", "session", "status",
      "terminal", "wait_exit_code"] and
    .schema == "pressure-scenario-container-inspections-v1" and
    .status == "passed" and .scenario_label == "pressure" and
    (.session | type == "string" and test("^[0-9a-f]{32}$")) and
    .wait_exit_code == 0 and
    ($running | keys == ["config", "identity", "labels", "mount", "runtime",
      "state"]) and
    ($terminal | keys == ["config", "identity", "labels", "mount", "runtime",
      "state"]) and
    ($running | del(.state)) == ($terminal | del(.state)) and
    ($running.identity |
      keys == ["id", "image_id", "image_reference", "name"] and
      (.id | type == "string" and test("^[0-9a-f]{64}$") and
        . != ("0" * 64)) and
      (.image_id | type == "string" and test("^sha256:[0-9a-f]{64}$") and
        . != ("sha256:" + ("0" * 64))) and
      .image_reference == "obi-apache-java-https-tracecheck:local" and
      .name == ("/" + $project + "-pressure-scenario-" +
        ($root.session[0:12]))) and
    ($running.config |
      keys == ["cmd", "entrypoint", "path", "user"] and
      .entrypoint == ["/trace-scenario"] and .path == "/trace-scenario" and
      .cmd == ["--scenario", "pressure", "--expected-tls", $tls,
        "--seed", $seed, "--requests", ($requests | tostring), "--timeout",
        "75s", "--pressure-control-dir", "/run/obi-demo/pressure-control",
        "--pressure-control-session", $root.session,
        "--pressure-control-timeout", "255s"] and
      .user == ($owner_uid + ":" + $owner_gid)) and
    ($user | length == 2 and all(.[]; uint32_decimal)) and
    ($running.labels |
      keys == ["oneoff", "owner", "project", "service"] and
      .oneoff == "True" and .owner == "acceptance-demo-v1" and
      .project == $project and .service == "scenario") and
    ($running.mount |
      keys == ["destination", "rw", "source_leaf", "type"] and
      .type == "bind" and .rw == true and
      .destination == "/run/obi-demo/pressure-control" and
      .source_leaf == (".pressure-control." + $root.session)) and
    ($running.runtime |
      keys == ["attach_stdin", "network_mode", "open_stdin", "pid_mode",
        "privileged", "restart_policy", "stdin_once", "tty"] and
      .attach_stdin == false and .network_mode == "host" and
      .open_stdin == false and .pid_mode == "" and .privileged == false and
      .restart_policy == "none" and .stdin_once == false and .tty == false) and
    ($running.state |
      keys == ["dead", "error", "exit_code", "finished_at", "host_pid",
        "oom_killed", "restart_count", "running", "started_at", "status"] and
      .dead == false and .error == "" and .exit_code == 0 and
      .finished_at == "0001-01-01T00:00:00Z" and
      (.host_pid | uint32 and . >= 1) and .oom_killed == false and
      .restart_count == 0 and .running == true and .status == "running" and
      .started_at != "0001-01-01T00:00:00Z") and
    ($terminal.state |
      keys == ["dead", "error", "exit_code", "finished_at", "host_pid",
        "oom_killed", "restart_count", "running", "started_at", "status"] and
      .dead == false and .error == "" and .exit_code == 0 and
      .host_pid == 0 and .oom_killed == false and .restart_count == 0 and
      .running == false and .status == "exited" and
      .started_at == $running.state.started_at and
      .finished_at != "0001-01-01T00:00:00Z") and
    $finished > $started
  ' "$artifact" >/dev/null
}

validate_pressure_barrier_artifacts() {
  local -r runner_directory="$1"
  local -r result="$runner_directory/scenario-pressure.json"
  local -r status="$runner_directory/scenario-pressure-status.json"
  local -r fill="$runner_directory/map-pressure-pressure-fill.json"
  local -r verify="$runner_directory/map-pressure-pressure-verify.json"
  local -r ready="$runner_directory/map-pressure-pressure-barrier-ready.txt"
  local -r release="$runner_directory/map-pressure-pressure-barrier-release.txt"
  local -r barrier="$runner_directory/map-pressure-pressure-barrier-status.json"
  local -r inspections="$runner_directory/map-pressure-pressure-container-inspections.json"
  local session=""
  local canonical=""
  local ready_sha256=""
  local release_sha256=""
  local fill_sha256=""
  local verify_sha256=""
  local result_sha256=""
  local status_sha256=""
  local inspections_sha256=""
  local inspections_size=""

  [[ -f "$barrier" && ! -L "$barrier" ]] || return 1
  session="$(jq -er '.session' "$barrier")" || return 1
  [[ "$session" =~ ^[0-9a-f]{32}$ ]] || return 1
  validate_pressure_control_file "$ready" "pressure-ready-v1:$session" || return 1
  validate_pressure_control_file "$release" "pressure-release-v1:$session" || return 1
  validate_pressure_container_inspections "$runner_directory" || return 1
  canonical="$(jq -cS . "$barrier")" || return 1
  [[ "$(wc -l <"$barrier")" == 1 && "$(<"$barrier")" == "$canonical" ]] || return 1
  ready_sha256="$(pressure_artifact_sha256 "$ready")" || return 1
  release_sha256="$(pressure_artifact_sha256 "$release")" || return 1
  fill_sha256="$(pressure_artifact_sha256 "$fill")" || return 1
  verify_sha256="$(pressure_artifact_sha256 "$verify")" || return 1
  result_sha256="$(pressure_artifact_sha256 "$result")" || return 1
  status_sha256="$(pressure_artifact_sha256 "$status")" || return 1
  inspections_sha256="$(pressure_artifact_sha256 "$inspections")" || return 1
  inspections_size="$(stat -Lc '%s' -- "$inspections")" || return 1
  [[ "$inspections_size" =~ ^[1-9][0-9]*$ &&
    "$inspections_size" -le "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" ]] ||
    return 1

  jq -e \
    --arg ready_sha256 "$ready_sha256" \
    --arg release_sha256 "$release_sha256" \
    --arg fill_sha256 "$fill_sha256" \
    --arg verify_sha256 "$verify_sha256" \
    --arg result_sha256 "$result_sha256" \
    --arg status_sha256 "$status_sha256" \
    --arg inspections_sha256 "$inspections_sha256" \
    --argjson inspections_size "$inspections_size" \
    --slurpfile inspection "$inspections" \
    --argjson requests "$PRESSURE_REQUESTS" \
    --argjson admission_maximum \
      "$((PRESSURE_REQUESTS * PRESSURE_ADMISSION_MAX_EVENTS_PER_REQUEST))" '
      keys == ["container", "container_inspections", "control", "fill",
        "scenario_label", "schema", "sequence", "session", "status",
        "traffic", "verification"] and
      .schema == "pressure-traffic-barrier-v1" and .status == "passed" and
      .scenario_label == "pressure" and
      .sequence == ["scenario_ready", "capacity_fill_verified",
        "release_published", "scenario_reaped",
        "post_traffic_content_verified"] and
      (.control |
        keys == ["ready_reference", "ready_sha256", "release_reference",
          "release_sha256"] and
        .ready_reference == "map-pressure-pressure-barrier-ready.txt" and
        .ready_sha256 == $ready_sha256 and
        .release_reference == "map-pressure-pressure-barrier-release.txt" and
        .release_sha256 == $release_sha256) and
      (.container |
        keys == ["host_pid", "id", "started_at", "user"] and
        (.id | type == "string" and test("^[0-9a-f]{64}$")) and
        (.host_pid | type == "string" and test("^[1-9][0-9]*$")) and
        (.started_at | type == "string" and test("^[0-9TZ:.-]{20,64}$")) and
        (.user | type == "string" and
          test("^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$"))) and
      (.container_inspections |
        keys == ["reference", "sha256", "size_bytes"] and
        .reference == "map-pressure-pressure-container-inspections.json" and
        .sha256 == $inspections_sha256 and
        .size_bytes == $inspections_size) and
      $inspection[0].session == .session and
      .container == {
        host_pid: ($inspection[0].running.state.host_pid | tostring),
        id: $inspection[0].running.identity.id,
        started_at: $inspection[0].running.state.started_at,
        user: $inspection[0].running.config.user
      } and
      (.fill |
        keys == ["baseline_entries", "capacity_rejected_entries",
          "content_sha256", "map_id", "max_entries", "reference", "sha256",
          "synthetic_namespace", "synthetic_pid", "touched",
          "verified_absent_entries", "verified_present_entries"] and
        .reference == "map-pressure-pressure-fill.json" and
        .sha256 == $fill_sha256 and
        (.map_id | type == "string" and test("^[1-9][0-9]*$")) and
        .baseline_entries == 0 and .synthetic_pid == 0 and
        .synthetic_namespace == 0 and .touched == .max_entries and
        .verified_present_entries == .max_entries and
        .verified_absent_entries == 1 and .capacity_rejected_entries == 1 and
        (.content_sha256 | type == "string" and test("^[0-9a-f]{64}$"))) and
      (.verification as $verification | .fill as $fill |
        ($verification |
          keys == ["content_sha256", "map_id", "reference", "sha256",
            "synthetic_namespace", "synthetic_pid",
            "verified_absent_entries", "verified_present_entries"] and
          .reference == "map-pressure-pressure-verify.json" and
          .sha256 == $verify_sha256 and .map_id == $fill.map_id and
          .synthetic_pid == 0 and .synthetic_namespace == 0 and
          .verified_present_entries == $fill.max_entries and
          .verified_absent_entries == 1 and
          .content_sha256 == $fill.content_sha256)) and
      (.traffic |
        keys == ["exact_hit_count", "explicit_root_count",
          "handoff_admission_ambiguous_count",
          "handoff_admission_maximum_count",
          "handoff_admission_overload_count", "request_count",
          "result_reference", "result_sha256", "status_reference",
          "status_sha256", "unresolved_count", "wrong_parent_count"] and
        .result_reference == "scenario-pressure.json" and
        .result_sha256 == $result_sha256 and
        .status_reference == "scenario-pressure-status.json" and
        .status_sha256 == $status_sha256 and .request_count == $requests and
        .exact_hit_count + .explicit_root_count == $requests and
        .explicit_root_count >= 1 and .wrong_parent_count == 0 and
        .unresolved_count == 0 and
        .handoff_admission_overload_count >= 1 and
        .handoff_admission_overload_count <= $admission_maximum and
        .handoff_admission_ambiguous_count == 0 and
        .handoff_admission_maximum_count == $admission_maximum)
    ' "$barrier" >/dev/null || return 1

  jq -e -s '
    .[0].fill.map_id == (.[1].map_id | tostring) and
    .[0].fill.max_entries == .[1].max_entries and
    .[0].fill.touched == .[1].touched and
    .[0].fill.content_sha256 == .[1].content_sha256 and
    .[0].verification.map_id == (.[2].map_id | tostring) and
    .[0].verification.verified_present_entries ==
      .[2].verified_present_entries and
    .[0].verification.content_sha256 == .[2].content_sha256 and
    .[0].traffic.exact_hit_count ==
      .[3].pressure_correlation.exact_hit_count and
    .[0].traffic.explicit_root_count ==
      .[3].pressure_correlation.explicit_root_count and
    .[0].traffic.handoff_admission_overload_count ==
      .[4].pressure_correlation.bridge.handoff_admission_outcome_counts.overload and
    .[4].pressure_correlation.barrier_reference ==
      "map-pressure-pressure-barrier-status.json" and
    .[4].pressure_correlation.container_inspections ==
      .[0].container_inspections and
    .[5].session == .[0].session
  ' "$barrier" "$fill" "$verify" "$result" "$status" "$inspections" \
    >/dev/null
}

validate_pressure_cell_artifacts() {
  local -r runner_directory="$1"
  local -r result_file="$runner_directory/scenario-pressure.json"
  local -r status_file="$runner_directory/scenario-pressure-status.json"
  local -r prepare_file="$runner_directory/map-pressure-pressure-prepare.json"
  local -r fill_file="$runner_directory/map-pressure-pressure-fill.json"
  local -r verify_file="$runner_directory/map-pressure-pressure-verify.json"
  local -r cleanup_file="$runner_directory/map-pressure-pressure-cleanup.json"
  local recovery_evidence=""

  jq -se --argjson requests "$PRESSURE_REQUESTS" \
    --argjson inspections_maximum "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" \
    --argjson admission_maximum \
      "$((PRESSURE_REQUESTS * PRESSURE_ADMISSION_MAX_EVENTS_PER_REQUEST))" '
    def positive_integer:
      type == "number" and isfinite and floor == . and . > 0;
    length == 2 and
    .[0] as $status |
    .[1] as $result |
    ($status |
      .status == "passed" and
      .scenario == "pressure" and
      .exit_status == 0 and
      .metric_status == 0 and
      .result == "scenario-pressure.json" and
      (.pressure_correlation | type == "object") and
      (.pressure_correlation.trace |
        ((keys | sort) == [
          "exact_hit_count", "explicit_root_count", "unresolved_count",
          "wrong_parent_count"
        ]) and
        all(.[]; type == "number" and isfinite and floor == . and . >= 0) and
        .wrong_parent_count == 0 and
        .unresolved_count == 0 and
        .exact_hit_count + .explicit_root_count == $requests) and
      (.pressure_correlation.java_reconciliation_target |
        ((keys | sort) == [
          "attributable_absence_count", "diagnostic_self_miss_count",
          "take_valid_count"
        ]) and
        all(.[]; type == "number" and isfinite and floor == . and . >= 0) and
        .take_valid_count >= 0 and
        .attributable_absence_count >= 0 and
        .diagnostic_self_miss_count == 1 and
        .take_valid_count + .attributable_absence_count == $requests and
        .take_valid_count == $status.pressure_correlation.trace.exact_hit_count and
        .attributable_absence_count == $status.pressure_correlation.trace.explicit_root_count) and
      (.pressure_correlation.bridge |
        type == "object" and .transport == "getsockopt" and
        (.handoff_admission_outcome_counts |
          keys == ["ambiguous", "maximum", "overload"] and
          (.overload | positive_integer) and .overload <= .maximum and
          .ambiguous == 0 and .maximum == $admission_maximum)) and
      (.pressure_correlation.container_inspections |
        keys == ["reference", "sha256", "size_bytes"] and
        .reference == "map-pressure-pressure-container-inspections.json" and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.size_bytes | type == "number" and isfinite and floor == . and
          . >= 1 and . <= $inspections_maximum)) and
      .pressure_correlation.barrier_reference ==
        "map-pressure-pressure-barrier-status.json") and
    ($result |
      .status == "passed" and
      .request_count == $requests and
      (.pressure_correlation | type == "object") and
      .pressure_correlation == $status.pressure_correlation.trace and
      .pressure_correlation.explicit_root_count >= 1)
  ' "$status_file" "$result_file" >/dev/null || return 1
  jq -se --argjson max_supported_entries "$PRESSURE_MAP_MAX_SUPPORTED_ENTRIES" '
    def nonnegative_integer:
      type == "number" and isfinite and floor == . and . >= 0;
    def positive_integer: nonnegative_integer and . > 0;
    length == 4 and
    .[0] as $prepare |
    .[1] as $fill |
    .[2] as $verify |
    .[3] as $cleanup |
    ($prepare |
      ((keys | sort) == [
        "kernel_name", "map_id", "map_name", "map_type", "max_entries",
        "mode", "process_map_id", "process_namespace", "process_pid",
        "status", "synthetic_namespace", "synthetic_pid", "token_base",
        "touched"
      ]) and
      .status == "passed" and .mode == "prepare" and
      .map_name == "java_remote_parent_handoff_claims" and
      .kernel_name == "java_remote_par" and .map_type == "Hash" and
      (.map_id | positive_integer) and (.max_entries | positive_integer) and
      .max_entries <= $max_supported_entries and
      (.process_map_id | positive_integer) and (.process_pid | positive_integer) and
      (.process_namespace | positive_integer) and (.token_base | positive_integer) and
      .synthetic_pid == 0 and .synthetic_namespace == 0 and .touched == 0) and
    ($fill |
      ((keys | sort) == [
        "capacity_rejected_entries", "content_sha256", "kernel_name",
        "map_id", "map_name", "map_type", "max_entries", "mode",
        "process_map_id", "process_namespace", "process_pid", "status",
        "synthetic_namespace", "synthetic_pid", "token_base", "touched",
        "verified_absent_entries", "verified_present_entries"
      ]) and
      .status == "passed" and .mode == "fill" and
      .map_name == $prepare.map_name and .kernel_name == $prepare.kernel_name and
      .map_type == $prepare.map_type and .map_id == $prepare.map_id and
      .max_entries == $prepare.max_entries and
      .process_map_id == $prepare.process_map_id and
      .process_pid == $prepare.process_pid and
      .process_namespace == $prepare.process_namespace and
      .token_base == $prepare.token_base and .synthetic_pid == 0 and
      .synthetic_namespace == 0 and .touched == .max_entries and
      .capacity_rejected_entries == 1 and
      .verified_present_entries == .max_entries and
      .verified_absent_entries == 1 and
      (.content_sha256 | type == "string" and test("^[0-9a-f]{64}$"))) and
    ($verify |
      ((keys | sort) == [
        "content_sha256", "kernel_name", "map_id", "map_name", "map_type",
        "max_entries", "mode", "process_map_id", "process_namespace",
        "process_pid", "status", "synthetic_namespace", "synthetic_pid",
        "token_base", "touched", "verified_absent_entries",
        "verified_present_entries"
      ]) and
      .status == "passed" and .mode == "verify" and
      .map_name == $prepare.map_name and .kernel_name == $prepare.kernel_name and
      .map_type == $prepare.map_type and .map_id == $prepare.map_id and
      .max_entries == $prepare.max_entries and
      .process_map_id == $prepare.process_map_id and
      .process_pid == $prepare.process_pid and
      .process_namespace == $prepare.process_namespace and
      .token_base == $prepare.token_base and .synthetic_pid == 0 and
      .synthetic_namespace == 0 and .touched == 0 and
      .verified_present_entries == $prepare.max_entries and
      .verified_absent_entries == 1 and
      .content_sha256 == $fill.content_sha256) and
    ($cleanup |
      ((keys | sort) == [
        "cleanup_verified", "kernel_name", "map_id", "map_name", "map_type",
        "max_entries", "mode", "process_map_id", "process_namespace",
        "process_pid", "status", "synthetic_namespace", "synthetic_pid",
        "token_base", "touched", "verified_absent_entries"
      ]) and
      .status == "passed" and .mode == "cleanup" and
      .map_name == $prepare.map_name and .kernel_name == $prepare.kernel_name and
      .map_type == $prepare.map_type and .process_map_id == 0 and
      .map_id == $prepare.map_id and .max_entries == $prepare.max_entries and
      .process_pid == $prepare.process_pid and
      .process_namespace == $prepare.process_namespace and
      .token_base == $prepare.token_base and .synthetic_pid == 0 and
      .synthetic_namespace == 0 and .cleanup_verified == true and
      .verified_absent_entries == .max_entries + 1 and
      .touched == $prepare.max_entries)
  ' "$prepare_file" "$fill_file" "$verify_file" "$cleanup_file" >/dev/null || return 1
  validate_pressure_barrier_artifacts "$runner_directory" || return 1
  recovery_evidence="$(pressure_recovery_evidence_json "$runner_directory")" || return 1
  jq -e --argjson required "$PRESSURE_RECOVERY_REQUIRED_SAMPLES" '
    .recovery_sample_count == $required and
    (.recovery_sample_entries | length) == $required
  ' <<<"$recovery_evidence" >/dev/null
}

canonical_pressure_observation_json() {
  local -r runner_directory="$1"
  local -r status_file="$runner_directory/scenario-pressure-status.json"
  local -r prepare_file="$runner_directory/map-pressure-pressure-prepare.json"
  local -r fill_file="$runner_directory/map-pressure-pressure-fill.json"
  local -r verify_file="$runner_directory/map-pressure-pressure-verify.json"
  local -r barrier_file="$runner_directory/map-pressure-pressure-barrier-status.json"
  local -r cleanup_file="$runner_directory/map-pressure-pressure-cleanup.json"
  local recovery_evidence=""

  validate_pressure_cell_artifacts "$runner_directory" || return 1
  recovery_evidence="$(pressure_recovery_evidence_json "$runner_directory")" || return 1
  jq -cn \
    --slurpfile status "$status_file" \
    --slurpfile prepare "$prepare_file" \
    --slurpfile fill "$fill_file" \
    --slurpfile verify "$verify_file" \
    --slurpfile barrier "$barrier_file" \
    --slurpfile cleanup "$cleanup_file" \
    --argjson recovery "$recovery_evidence" '
      {
        bounded: true,
        pressure_contract_version: 1,
        barrier_schema: $barrier[0].schema,
        barrier_sequence: $barrier[0].sequence,
        exact_hit_count: $status[0].pressure_correlation.trace.exact_hit_count,
        explicit_root_count: $status[0].pressure_correlation.trace.explicit_root_count,
        wrong_parent_count: $status[0].pressure_correlation.trace.wrong_parent_count,
        unresolved_count: $status[0].pressure_correlation.trace.unresolved_count,
        take_valid_count: $status[0].pressure_correlation.java_reconciliation_target.take_valid_count,
        attributable_absence_count: $status[0].pressure_correlation.java_reconciliation_target.attributable_absence_count,
        handoff_admission_overload_count: $status[0].pressure_correlation.bridge.handoff_admission_outcome_counts.overload,
        handoff_admission_ambiguous_count: $status[0].pressure_correlation.bridge.handoff_admission_outcome_counts.ambiguous,
        handoff_admission_maximum_count: $status[0].pressure_correlation.bridge.handoff_admission_outcome_counts.maximum,
        map_name: $prepare[0].map_name,
        map_type: $prepare[0].map_type,
        map_id: $recovery.map_id,
        kernel_map_name: $recovery.kernel_map_name,
        kernel_map_type: $recovery.map_type,
        max_entries: $prepare[0].max_entries,
        synthetic_pid: $prepare[0].synthetic_pid,
        synthetic_namespace: $prepare[0].synthetic_namespace,
        touched_entries: $fill[0].touched,
        capacity_rejected_entries: $fill[0].capacity_rejected_entries,
        fill_verified_present_entries: $fill[0].verified_present_entries,
        fill_verified_absent_entries: $fill[0].verified_absent_entries,
        content_sha256: $fill[0].content_sha256,
        post_traffic_verified_present_entries: $verify[0].verified_present_entries,
        post_traffic_verified_absent_entries: $verify[0].verified_absent_entries,
        post_traffic_content_sha256: $verify[0].content_sha256,
        post_traffic_content_verified: true,
        cleanup_verified: $cleanup[0].cleanup_verified,
        cleanup_verified_absent_entries: $cleanup[0].verified_absent_entries,
        occupancy_before_fill: $recovery.baseline_entries,
        occupancy_recovery_samples: $recovery.recovery_sample_entries,
        occupancy_recovered: $recovery.recovered_entries,
        recovery_log_attempts: $recovery.recovery_log_attempts,
        recovery_samples: $recovery.recovery_sample_count
      }
    '
}

validate_runner_standard_parent_discards() {
  local -r delta_file="$1"

  [[ -f "$delta_file" && ! -L "$delta_file" ]] || return 1
  awk -v expected="$CELL_EXPECTED_STANDARD_PARENT_DISCARDS" \
    -v maximum="$MAX_JAVA_DIAGNOSTIC_COUNTER" '
    function bounded(value) {
      return value ~ /^(0|[1-9][0-9]*)$/ &&
        length(value) <= length(maximum) &&
        (length(value) < length(maximum) || value < maximum)
    }
    $1 == "discard_standard" {
      matches++
      before = $2
      after = $3
      delta = $4
      if (NF != 4 || sub(/^before=/, "", before) != 1 ||
          sub(/^after=/, "", after) != 1 || sub(/^delta=/, "", delta) != 1 ||
          !bounded(before) || !bounded(after) || !bounded(delta) ||
          after + 0 < before + 0 || delta + 0 != (after + 0) - (before + 0) ||
          delta != expected) {
        invalid = 1
      }
    }
    END { exit matches == 1 && invalid != 1 ? 0 : 1 }
  ' "$delta_file"
}

base36_to_decimal() {
  local raw="$1"
  local value=0

  [[ "$raw" =~ ^(0|[1-9a-z][0-9a-z]*)$ && ${#raw} -le 6 ]] || return 1
  value="$((36#$raw))"
  ((value < MAX_JAVA_DIAGNOSTIC_COUNTER)) || return 1
  printf '%s\n' "$value"
}

validate_java_diagnostics_snapshot() {
  local -r snapshot_file="$1"
  local snapshot_size=""
  local snapshot=""
  local entry=""
  local name=""
  local value=""
  local decoded=""
  local index=0
  local -a snapshots=()
  local -a entries=()
  local -a expected_names=(
    cfg_on cfg_off provider_ok provider_reject provider_ver extension_reg
    lookup_ready lookup_missing lookup_version lookup_error record_version
    invoke_error discard_standard extract_fields extract_invalid extract_error
    registration_ok registration_fail take_sampled take_unsampled tls_reads tls_bytes
    framework_depth framework_cycle framework_late transport_missing
    t_unknown d_unknown t_valid d_valid t_missing d_missing t_stale d_stale
    t_unsupported d_unsupported t_malformed d_malformed
    t_version_mismatch d_version_mismatch t_ambiguous d_ambiguous
    t_unauthorized d_unauthorized t_already_consumed d_already_consumed
    t_timeout d_timeout t_overload d_overload
    t_transport_error d_transport_error t_disabled d_disabled
  )

  [[ -f "$snapshot_file" && ! -L "$snapshot_file" ]] || return 1
  snapshot_size="$(stat --format '%s' -- "$snapshot_file")" || return 1
  [[ "$snapshot_size" =~ ^[0-9]+$ &&
    "$snapshot_size" -le "$MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES" ]] || return 1
  mapfile -t snapshots <"$snapshot_file" || return 1
  [[ ${#snapshots[@]} == 1 && -n "${snapshots[0]}" ]] || return 1
  snapshot="${snapshots[0]}"
  IFS=, read -r -a entries <<<"$snapshot"
  [[ ${#entries[@]} == "${#expected_names[@]}" ]] || return 1
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^[a-z_]+=(0|[1-9a-z][0-9a-z]*)$ ]] || return 1
    name="${entry%%=*}"
    value="${entry#*=}"
    [[ "$name" == "${expected_names[$index]}" ]] || return 1
    decoded="$(base36_to_decimal "$value")" || return 1
    [[ "$decoded" =~ ^[0-9]+$ ]] || return 1
    ((index += 1))
  done
}

diagnostic_counter_value() {
  local -r snapshot_file="$1"
  local -r wanted_counter="$2"
  local snapshot=""
  local entry=""
  local counter_name=""
  local encoded_value=""
  local -a entries=()

  validate_java_diagnostics_snapshot "$snapshot_file" || return 1
  IFS= read -r snapshot <"$snapshot_file" || return 1
  IFS=, read -r -a entries <<<"$snapshot"
  for entry in "${entries[@]}"; do
    counter_name="${entry%%=*}"
    encoded_value="${entry#*=}"
    if [[ "$counter_name" == "$wanted_counter" ]]; then
      printf '%s\n' "$encoded_value"
      return 0
    fi
  done
  return 1
}

validate_java_diagnostics_counter_deltas() {
  local -r before_snapshot="$1"
  local -r after_snapshot="$2"
  local -r output="$3"
  local counter=""
  local expected_delta=""
  local before_encoded=""
  local after_encoded=""
  local before_value=""
  local after_value=""
  local observed_delta=0
  local counters_json=""
  local -a counter_json=()

  shift 3
  (($# > 0 && $# % 2 == 0)) || return 1
  validate_java_diagnostics_snapshot "$before_snapshot" || return 1
  validate_java_diagnostics_snapshot "$after_snapshot" || return 1
  while (($# > 0)); do
    counter="$1"
    expected_delta="$(normalize_decimal "$2" "$MAX_JAVA_DIAGNOSTIC_COUNTER" true)" || return 1
    shift 2

    before_encoded="$(diagnostic_counter_value "$before_snapshot" "$counter")" || return 1
    after_encoded="$(diagnostic_counter_value "$after_snapshot" "$counter")" || return 1
    before_value="$(base36_to_decimal "$before_encoded")" || return 1
    after_value="$(base36_to_decimal "$after_encoded")" || return 1
    ((after_value >= before_value)) || return 1
    observed_delta=$((after_value - before_value))
    ((observed_delta == expected_delta)) || return 1
    counter_json+=("$(jq -cn \
      --arg counter "$counter" \
      --arg before_base36 "$before_encoded" \
      --arg after_base36 "$after_encoded" \
      --argjson observed_delta "$observed_delta" \
      --argjson expected_delta "$expected_delta" \
      '{
        counter: $counter,
        before_base36: $before_base36,
        after_base36: $after_base36,
        observed_delta: $observed_delta,
        expected_delta: $expected_delta
      }')") || return 1
  done
  counters_json="$(printf '%s\n' "${counter_json[@]}" | jq -s .)" || return 1
  jq -n --argjson counters "$counters_json" '{counters: $counters}' >"$output"
}

validate_standard_parent_discard_diagnostics() {
  local -r before_snapshot="$1"
  local -r after_snapshot="$2"
  local -r output="$3"
  local -r expected_standard_delta="${4:-$CELL_EXPECTED_STANDARD_PARENT_DISCARDS}"
  local -r expected_valid_take_delta="${5:-$CELL_EXPECTED_W3C_VALID_TAKES}"

  validate_java_diagnostics_counter_deltas \
    "$before_snapshot" "$after_snapshot" "$output" \
    discard_standard "$expected_standard_delta" \
    t_valid "$expected_valid_take_delta" \
    d_valid 0
}

validate_helper_idle_java_diagnostics() {
  local -r before_snapshot="$1"
  local -r after_snapshot="$2"
  local -r output="$3"
  local -r successful_requests="$4"
  local -r raw_output="$output.raw"
  local normalized_successful_requests=""
  local expected_raw_missing=0
  local raw_deltas=""
  local -a expected_counters=(
    discard_standard 0
    take_sampled 0
    take_unsampled 0
    provider_reject 0
    provider_ver 0
    lookup_missing 0
    lookup_version 0
    lookup_error 0
    record_version 0
    invoke_error 0
    extract_fields 0
    extract_invalid 0
    extract_error 0
    registration_fail 0
    t_unknown 0
    d_unknown 0
    t_valid 0
    d_valid 0
    d_missing 0
    t_stale 0
    d_stale 0
    t_unsupported 0
    d_unsupported 0
    t_malformed 0
    d_malformed 0
    t_version_mismatch 0
    d_version_mismatch 0
    t_ambiguous 0
    d_ambiguous 0
    t_unauthorized 0
    d_unauthorized 0
    t_already_consumed 0
    d_already_consumed 0
    t_timeout 0
    d_timeout 0
    t_overload 0
    d_overload 0
    t_transport_error 0
    d_transport_error 0
    t_disabled 0
    d_disabled 0
  )

  [[ ! -e "$output" && ! -L "$output" && ! -e "$raw_output" && ! -L "$raw_output" ]] || return 1
  normalized_successful_requests="$(normalize_decimal \
    "$successful_requests" "$MAX_HELPER_IDLE_WORKLOAD_SUCCESSFUL_REQUESTS" true)" || return 1
  ((normalized_successful_requests < MAX_JAVA_DIAGNOSTIC_COUNTER)) || return 1
  expected_raw_missing="$((normalized_successful_requests + 1))"
  expected_counters+=(t_missing "$expected_raw_missing")
  if ! validate_java_diagnostics_counter_deltas \
    "$before_snapshot" "$after_snapshot" "$raw_output" "${expected_counters[@]}"; then
    rm -f -- "$raw_output"
    return 1
  fi
  raw_deltas="$(jq -c . "$raw_output")" || {
    rm -f -- "$raw_output"
    return 1
  }
  jq -n \
    --arg semantic "direct_java_no_upstream_handoff_not_state_map_miss_proof" \
    --argjson successful_requests "$normalized_successful_requests" \
    --argjson expected_raw_missing "$expected_raw_missing" \
    --argjson raw_deltas "$raw_deltas" \
    '{
      semantic: $semantic,
      workload_successful_requests: $successful_requests,
      diagnostic_after_probe_t_missing: 1,
      raw_java_t_missing_delta: $expected_raw_missing,
      corrected_workload_t_missing: ($expected_raw_missing - 1),
      correction: {
        reason: "the_after_obi_diagnostics_request_is_itself_server_instrumented",
        raw_t_missing_expected: $expected_raw_missing,
        corrected_workload_t_missing_expected: $successful_requests
      },
      java_assertions: {
        all_other_take_statuses_zero: true,
        all_discard_statuses_zero: true,
        discard_standard_zero: true,
        take_sampled_zero: true,
        take_unsampled_zero: true,
        provider_lookup_record_invoke_extract_registration_failure_counters_zero: true
      },
      raw_counters: $raw_deltas.counters
    }' >"$output"
  rm -f -- "$raw_output" || return 1
}

run_postload_sentinel() {
  local -r cell_dir="$1"
  local -r output="$cell_dir/postload-sentinel/result.json"
  local diagnostics_before=""
  local diagnostics_after=""
  local -a arguments=(
    --scenario "$CELL_SENTINEL_SCENARIO"
    --requests "$PREFLIGHT_REQUESTS"
    --expected-tls "$TLS_PROTOCOL"
    --seed "$SEED"
    --timeout 75s
  )

  mkdir -- "$cell_dir/postload-sentinel"
  if [[ "$CELL_SENTINEL_SCENARIO" == "w3c" ]]; then
    diagnostics_before="$cell_dir/postload-sentinel/java-diagnostics-before.txt"
    diagnostics_after="$cell_dir/postload-sentinel/java-diagnostics-after.txt"
    capture_java_diagnostics "$diagnostics_before"
  elif [[ -n "$CELL_ASSERTION_MODE" ]]; then
    arguments+=(--assertion-mode "$CELL_ASSERTION_MODE")
  fi
  run_bounded "$POSTLOAD_SENTINEL_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" run --rm --no-deps --no-TTY scenario "${arguments[@]}" \
      >"$output" 2>"$output.stderr"
  validate_cell_sentinel "$output"
  if [[ "$CELL_SENTINEL_SCENARIO" == "w3c" ]]; then
    capture_java_diagnostics "$diagnostics_after"
    validate_standard_parent_discard_diagnostics \
      "$diagnostics_before" \
      "$diagnostics_after" \
      "$cell_dir/postload-sentinel/standard-parent-discard-diagnostics.json"
  fi
  jq -n \
    --arg status passed \
    --arg scenario "$CELL_SENTINEL_SCENARIO" \
    --argjson requests "$PREFLIGHT_REQUESTS" \
    --argjson standard_parent_discards "$CELL_EXPECTED_STANDARD_PARENT_DISCARDS" \
    '{
      status: $status,
      scenario: $scenario,
      requests: $requests,
      expected_standard_parent_discards: $standard_parent_discards
    }' \
    >"$cell_dir/postload-sentinel/status.json"
}

verify_preflight() {
  local -r result_directory="$1"
  local -r scenario_result="$result_directory/scenario-$CELL_RESULT_LABEL.json"

  if [[ "$CELL_BOUNDED_PATH" == "true" ]]; then
    validate_runner_scenario_measurement \
      "$scenario_result" "$CELL_SCENARIO" "$CELL_MEASUREMENT_REQUESTS" || return $?
    validate_runner_scenario_status \
      "$result_directory/scenario-$CELL_RESULT_LABEL-status.json" \
      "$CELL_SCENARIO" \
      "scenario-$CELL_RESULT_LABEL.json" || return $?
    case "$CELL_SLUG" in
      getsockopt-stale|unix-stale)
        validate_runner_scenario_measurement \
          "$result_directory/scenario-basic-$CELL_RESULT_LABEL-recovery.json" \
          basic 1 || return $?
        validate_runner_scenario_status \
          "$result_directory/scenario-basic-$CELL_RESULT_LABEL-recovery-status.json" \
          basic \
          "scenario-basic-$CELL_RESULT_LABEL-recovery.json" || return $?
        ;;
      getsockopt-pressure)
        validate_pressure_cell_artifacts "$result_directory" || return $?
        ;;
    esac
    return 0
  fi

  validate_cell_sentinel "$scenario_result" || return $?
  if [[ "$CELL_SENTINEL_SCENARIO" == "w3c" ]]; then
    validate_w3c_runner_status "$result_directory/scenario-w3c-status.json" || return $?
    validate_runner_standard_parent_discards \
      "$result_directory/phases/w3c-after/java-diagnostics.delta"
  fi
}

validate_path_observation_schema() {
  local -r observation="$1"

  [[ -f "$observation" && ! -L "$observation" ]] || return 1
  jq -se --argjson hit_requests "$PREFLIGHT_REQUESTS" \
    --argjson pressure_requests "$PRESSURE_REQUESTS" \
    --argjson pressure_max_supported_entries "$PRESSURE_MAP_MAX_SUPPORTED_ENTRIES" \
    --argjson recovery_samples "$PRESSURE_RECOVERY_REQUIRED_SAMPLES" '
    def nonnegative_integer:
      type == "number" and isfinite and floor == . and . >= 0;
    def positive_integer:
      nonnegative_integer and . > 0;
    def diagnostics_are($valid; $missing; $stale; $timeout):
      .valid == $valid and .missing == $missing and .stale == $stale and
      .timeout == $timeout and
      ([
        .unknown, .unsupported, .malformed, .version_mismatch, .ambiguous,
        .unauthorized, .already_consumed, .overload, .transport_error, .disabled
      ] | all(. == 0));
    def source_is($label):
      .result == ("preflight/runner/scenario-" + $label + ".json") and
      .status == ("preflight/runner/scenario-" + $label + "-status.json") and
      .java_diagnostics_delta ==
        ("preflight/runner/phases/" + $label + "-after/java-diagnostics.delta");
    def common_observation($requested; $observed):
      .observation.mode == "bounded_correctness_observed_once" and
      .observation.runner_execution_count == 1 and
      .observation.runner_requested_requests == $requested and
      .observation.observed_requests == $observed and
      .observation.result_status == "passed";
    def pressure_is_exact:
      (.pressure |
        type == "object" and
        ((keys | sort) == [
          "attributable_absence_count", "barrier_schema", "barrier_sequence",
          "bounded", "capacity_rejected_entries", "cleanup_verified",
          "cleanup_verified_absent_entries", "content_sha256",
          "exact_hit_count", "explicit_root_count",
          "fill_verified_absent_entries", "fill_verified_present_entries",
          "handoff_admission_ambiguous_count",
          "handoff_admission_maximum_count",
          "handoff_admission_overload_count", "kernel_map_name",
          "kernel_map_type", "map_id", "map_name", "map_type", "max_entries",
          "occupancy_before_fill", "occupancy_recovered",
          "occupancy_recovery_samples", "post_traffic_content_sha256",
          "post_traffic_content_verified",
          "post_traffic_verified_absent_entries",
          "post_traffic_verified_present_entries", "pressure_contract_version",
          "recovery_log_attempts", "recovery_samples", "synthetic_namespace",
          "synthetic_pid", "take_valid_count", "touched_entries",
          "unresolved_count", "wrong_parent_count"
        ]) and
        all(.[];
          type == "boolean" or type == "string" or nonnegative_integer or
          (type == "array" and
            all(.[]; type == "string" or nonnegative_integer))) and
        .bounded == true and .pressure_contract_version == 1 and
        .barrier_schema == "pressure-traffic-barrier-v1" and
        .barrier_sequence == ["scenario_ready", "capacity_fill_verified",
          "release_published", "scenario_reaped",
          "post_traffic_content_verified"] and
        .map_name == "java_remote_parent_handoff_claims" and
        .kernel_map_name == "java_remote_par" and .map_type == "Hash" and
        .kernel_map_type == "hash" and (.map_id | positive_integer) and
        (.max_entries | positive_integer) and
        .max_entries <= $pressure_max_supported_entries and
        .synthetic_pid == 0 and .synthetic_namespace == 0 and
        .touched_entries == .max_entries and .occupancy_before_fill == 0 and
        .occupancy_recovered == 0 and
        (.occupancy_recovery_samples | length) == $recovery_samples and
        all(.occupancy_recovery_samples[]; . == 0) and
        .occupancy_recovery_samples[-1] == .occupancy_recovered and
        (.recovery_log_attempts | positive_integer) and
        .recovery_log_attempts >= $recovery_samples and
        .capacity_rejected_entries == 1 and
        .fill_verified_present_entries == .max_entries and
        .fill_verified_absent_entries == 1 and
        (.content_sha256 | test("^[0-9a-f]{64}$")) and
        .post_traffic_verified_present_entries == .max_entries and
        .post_traffic_verified_absent_entries == 1 and
        .post_traffic_content_sha256 == .content_sha256 and
        .post_traffic_content_verified == true and
        .cleanup_verified == true and
        .cleanup_verified_absent_entries == .max_entries + 1 and
        .recovery_samples == $recovery_samples and
        .handoff_admission_overload_count >= 1 and
        .handoff_admission_overload_count <=
          .handoff_admission_maximum_count and
        .handoff_admission_ambiguous_count == 0 and
        .handoff_admission_maximum_count == ($pressure_requests * 9) and
        .wrong_parent_count == 0 and .unresolved_count == 0 and
        .explicit_root_count >= 1 and
        .exact_hit_count + .explicit_root_count == $pressure_requests and
        .take_valid_count + .attributable_absence_count == $pressure_requests and
        .take_valid_count == .exact_hit_count and
        .attributable_absence_count == .explicit_root_count);
    length == 1 and
    (.[0] as $observation | $observation |
      type == "object" and
      ((keys | sort) == [
        "application_path", "cell", "java_diagnostic_status_deltas",
        "java_status", "kind", "limitations", "observation",
        "path_classification", "performance_metrics", "pressure", "provenance",
        "schema_version", "source", "transport"
      ]) and
      .schema_version == 1 and
      .kind == "java-remote-parent-path-correctness-observation" and
      .application_path == true and
      (.observation |
        ((keys | sort) == [
          "mode", "observed_requests", "result_status",
          "runner_execution_count", "runner_requested_requests"
        ]) and
        (.runner_requested_requests | positive_integer) and
        (.observed_requests | positive_integer)) and
      (.java_diagnostic_status_deltas |
        ((keys | sort) == [
          "already_consumed", "ambiguous", "disabled", "malformed", "missing",
          "overload", "stale", "timeout", "transport_error", "unauthorized",
          "unknown", "unsupported", "valid", "version_mismatch"
        ]) and all(.[]; nonnegative_integer)) and
      (.performance_metrics |
        ((keys | sort) == ["reason", "status"]) and
        .status == "not_evaluated_from_bounded_observation" and
        (.reason | type == "string" and length > 0)) and
      (.source |
        ((keys | sort) == ["java_diagnostics_delta", "result", "status"]) and
        all(.[]; type == "string" and length > 0)) and
      (.provenance |
        ((keys | sort) == ["host_environment", "runner_environment", "runner_provenance", "source_state"]) and
        .host_environment == "../../host-environment.txt" and
        .runner_environment == "preflight/runner/environment.txt" and
        .runner_provenance == "preflight/runner/provenance.json" and
        .source_state == "preflight/runner/source-state.txt") and
      (.limitations |
        ((keys | sort) == ["helper_idle_relabelled_as_miss", "state_map_miss_proved"]) and
        .helper_idle_relabelled_as_miss == false and
        .state_map_miss_proved == false) and
      (if .cell == "getsockopt-hit" then
        .transport == "getsockopt" and .path_classification == "hit" and
        .java_status == "valid" and common_observation($hit_requests; $hit_requests) and
        (.java_diagnostic_status_deltas | diagnostics_are($hit_requests; 1; 0; 0)) and
        .pressure == null and (.source | source_is("concurrency"))
       elif .cell == "unix-hit" then
        .transport == "unix" and .path_classification == "hit" and
        .java_status == "valid" and common_observation($hit_requests; $hit_requests) and
        (.java_diagnostic_status_deltas | diagnostics_are($hit_requests; 1; 0; 0)) and
        .pressure == null and (.source | source_is("concurrency"))
       elif .cell == "getsockopt-stale" then
        .transport == "getsockopt" and .path_classification == "failure" and
        .java_status == "stale" and common_observation(1; 1) and
        (.java_diagnostic_status_deltas | diagnostics_are(0; 0; 1; 0)) and
        .pressure == null and (.source | source_is("primary-w3c-stale"))
       elif .cell == "unix-stale" then
        .transport == "unix" and .path_classification == "failure" and
        .java_status == "stale" and common_observation(1; 1) and
        (.java_diagnostic_status_deltas | diagnostics_are(0; 0; 1; 0)) and
        .pressure == null and (.source | source_is("unix-w3c-stale"))
       elif .cell == "unix-timeout" then
        .transport == "unix" and .path_classification == "failure" and
        .java_status == "timeout" and common_observation(2; 1) and
        (.java_diagnostic_status_deltas | diagnostics_are(0; 0; 0; 1)) and
        .pressure == null and (.source | source_is("w3c-fault-timeout"))
       elif .cell == "getsockopt-pressure" then
        .transport == "getsockopt" and .path_classification == "pressure" and
        .java_status == "mixed" and
        common_observation($pressure_requests; $pressure_requests) and
        pressure_is_exact and
        (.java_diagnostic_status_deltas |
          diagnostics_are($observation.pressure.take_valid_count;
            $observation.pressure.attributable_absence_count + 1; 0; 0)) and
        (.source | source_is("pressure"))
       else false end)
    )
  ' "$observation" >/dev/null
}

validate_path_observation_source_artifacts() (
  local -r observation="$1"
  local observation_directory=""
  local cell=""
  local result_file=""
  local status_file=""
  local diagnostics_file=""
  local diagnostics_json=""
  local canonical_pressure_json=""

  validate_path_observation_schema "$observation" || return 1
  observation_directory="$(cd -- "${observation%/*}" && pwd -P)" || return 1
  cell="$(jq -er '.cell' "$observation")" || return 1
  cell_spec "$cell" || return 1
  result_file="$observation_directory/$(jq -er '.source.result' "$observation")"
  status_file="$observation_directory/$(jq -er '.source.status' "$observation")"
  diagnostics_file="$observation_directory/$(jq -er \
    '.source.java_diagnostics_delta' "$observation")"
  validate_runner_scenario_measurement \
    "$result_file" "$CELL_SCENARIO" "$CELL_MEASUREMENT_REQUESTS" || return 1
  validate_runner_scenario_status \
    "$status_file" "$CELL_SCENARIO" "scenario-$CELL_RESULT_LABEL.json" || return 1
  diagnostics_json="$(java_path_diagnostic_counts "$diagnostics_file")" || return 1
  jq -e --argjson diagnostics "$diagnostics_json" \
    '.java_diagnostic_status_deltas == $diagnostics' "$observation" >/dev/null || return 1
  if [[ "$cell" == "getsockopt-pressure" ]]; then
    canonical_pressure_json="$(canonical_pressure_observation_json \
      "$observation_directory/preflight/runner")" || return 1
    jq -se --argjson expected "$canonical_pressure_json" '
      length == 1 and .[0].pressure == $expected
    ' "$observation" >/dev/null || return 1
  fi
)

write_path_observation() {
  local -r cell_dir="$1"
  local -r runner_directory="$cell_dir/preflight/runner"
  local -r result_file="$runner_directory/scenario-$CELL_RESULT_LABEL.json"
  local -r status_file="$runner_directory/scenario-$CELL_RESULT_LABEL-status.json"
  local -r diagnostics_file="$runner_directory/phases/$CELL_RESULT_LABEL-after/java-diagnostics.delta"
  local -r output="$cell_dir/path-observation.json"
  local temporary=""
  local result_json=""
  local diagnostics_json=""
  local pressure_json="null"
  local expected_valid=0
  local expected_missing=0
  local expected_stale=0
  local expected_timeout=0

  [[ "$CELL_PATH_CLASSIFICATION" == hit || "$CELL_BOUNDED_PATH" == true ]] || return 1
  validate_runner_scenario_measurement \
    "$result_file" "$CELL_SCENARIO" "$CELL_MEASUREMENT_REQUESTS" || return 1
  diagnostics_json="$(java_path_diagnostic_counts "$diagnostics_file")" || return 1
  case "$CELL_SLUG" in
    getsockopt-hit|unix-hit)
      expected_valid="$CELL_MEASUREMENT_REQUESTS"
      # The runner's after-scenario diagnostic request is itself instrumented.
      expected_missing=1
      ;;
    getsockopt-stale|unix-stale)
      expected_stale=1
      ;;
    unix-timeout)
      expected_timeout=1
      ;;
    getsockopt-pressure)
      pressure_json="$(canonical_pressure_observation_json "$runner_directory")" || return 1
      expected_valid="$(jq -er '.take_valid_count' <<<"$pressure_json")" || return 1
      expected_missing="$(jq -er '.attributable_absence_count + 1' \
        <<<"$pressure_json")" || return 1
      ;;
    *)
      return 1
      ;;
  esac
  validate_path_diagnostic_counts \
    "$diagnostics_json" "$expected_valid" "$expected_missing" \
    "$expected_stale" "$expected_timeout" || return 1
  result_json="$(jq -ce . "$result_file")" || return 1
  temporary="$(mktemp "$cell_dir/.path-observation.json.XXXXXX")" || return 1
  jq -n \
    --arg cell "$CELL_SLUG" \
    --arg transport "$CELL_SELECTED_TRANSPORT" \
    --arg classification "$CELL_PATH_CLASSIFICATION" \
    --arg java_status "$CELL_EXPECTED_JAVA_STATUS" \
    --arg result_source "preflight/runner/scenario-$CELL_RESULT_LABEL.json" \
    --arg status_source "preflight/runner/scenario-$CELL_RESULT_LABEL-status.json" \
    --arg diagnostics_source "preflight/runner/phases/$CELL_RESULT_LABEL-after/java-diagnostics.delta" \
    --argjson requested_runner_requests "$CELL_PREFLIGHT_REQUESTS" \
    --argjson measured_requests "$CELL_MEASUREMENT_REQUESTS" \
    --argjson result "$result_json" \
    --argjson diagnostics "$diagnostics_json" \
    --argjson pressure "$pressure_json" '
      {
        schema_version: 1,
        kind: "java-remote-parent-path-correctness-observation",
        cell: $cell,
        transport: $transport,
        path_classification: $classification,
        java_status: $java_status,
        application_path: true,
        observation: {
          mode: "bounded_correctness_observed_once",
          runner_execution_count: 1,
          runner_requested_requests: $requested_runner_requests,
          observed_requests: $measured_requests,
          result_status: $result.status
        },
        java_diagnostic_status_deltas: $diagnostics,
        performance_metrics: {
          status: "not_evaluated_from_bounded_observation",
          reason: "one bounded correctness runner execution is not a throughput or latency distribution; sustained application performance is evaluated only from variance.json"
        },
        pressure: $pressure,
        source: {
          result: $result_source,
          status: $status_source,
          java_diagnostics_delta: $diagnostics_source
        },
        provenance: {
          host_environment: "../../host-environment.txt",
          runner_environment: "preflight/runner/environment.txt",
          runner_provenance: "preflight/runner/provenance.json",
          source_state: "preflight/runner/source-state.txt"
        },
        limitations: {
          state_map_miss_proved: false,
          helper_idle_relabelled_as_miss: false
        }
      }
    ' >"$temporary" || {
      rm -f -- "$temporary"
      return 1
    }
  validate_path_observation_schema "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  mv -T -- "$temporary" "$output"
}

requested_application_cells_json() {
  if [[ "$CELLS_MODE" == "complete" ]]; then
    jq -cn '$ARGS.positional' --args "${CORE_CELLS[@]}" "${BOUNDED_PATH_CELLS[@]}"
  else
    jq -cn '$ARGS.positional' --args "${CORE_CELLS[@]}"
  fi
}

sha256_regular_file() {
  local -r input="$1"
  local digest=""

  [[ -f "$input" && ! -L "$input" ]] || return 1
  resolve_benchmark_identity_tools || return 1
  digest="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_SHA256_COMMAND" -- "$input")" || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

is_safe_git_tree_path() {
  local -r path="$1"
  local remainder="$path"
  local component=""

  [[ -n "$path" && "$path" != /* && "$path" != */ && "$path" != *'//' ]] || return 1
  while true; do
    if [[ "$remainder" == */* ]]; then
      component="${remainder%%/*}"
      remainder="${remainder#*/}"
    else
      component="$remainder"
      remainder=""
    fi
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
    [[ -n "$remainder" ]] || return 0
  done
}

write_git_tree_manifest_for_tree() {
  local -r repository="$1"
  local -r git_tree="$2"
  local -r output="$3"
  local tree_entries_file=""
  local manifest=""
  local entry=""
  local metadata=""
  local path=""
  local mode=""
  local object_type=""
  local object_id=""
  local extra=""
  local marker=""

  [[ -d "$repository" && ! -L "$repository" &&
    "$git_tree" =~ ^[0-9a-f]{40}$ && "${output%/*}" != "$output" &&
    -d "${output%/*}" && ! -L "${output%/*}" && ! -L "$output" ]] || return 1
  resolve_benchmark_identity_tools || return 1
  tree_entries_file="$(mktemp "${output%/*}/.git-tree.entries.XXXXXX")" || return 1
  manifest="$(mktemp "${output%/*}/.git-tree.manifest.XXXXXX")" || {
    rm -f -- "$tree_entries_file"
    return 1
  }
  if ! run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" \
    -C "$repository" ls-tree -r -z --full-tree "$git_tree" >"$tree_entries_file"; then
    rm -f -- "$tree_entries_file" "$manifest"
    return 1
  fi
  while IFS= read -r -d '' entry; do
    [[ "$entry" == *$'\t'* ]] || {
      rm -f -- "$tree_entries_file" "$manifest"
      return 1
    }
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    read -r mode object_type object_id extra <<<"$metadata" || {
      rm -f -- "$tree_entries_file" "$manifest"
      return 1
    }
    [[ "$object_id" =~ ^[0-9a-f]{40}$ && -z "$extra" ]] || {
      rm -f -- "$tree_entries_file" "$manifest"
      return 1
    }
    is_safe_git_tree_path "$path" || {
      rm -f -- "$tree_entries_file" "$manifest"
      return 1
    }
    case "$mode:$object_type" in
      100644:blob) marker='-' ;;
      100755:blob) marker='x' ;;
      120000:blob) marker='l' ;;
      160000:commit) marker='g' ;;
      *)
        rm -f -- "$tree_entries_file" "$manifest"
        return 1
        ;;
    esac
    LC_ALL=C printf '%s %s %q\n' "$object_id" "$marker" "$path" \
      >>"$manifest" || {
      rm -f -- "$tree_entries_file" "$manifest"
      return 1
    }
  done <"$tree_entries_file"
  rm -f -- "$tree_entries_file" || {
    rm -f -- "$manifest"
    return 1
  }
  mv -T -- "$manifest" "$output"
}

validate_recorded_git_tree_manifest() {
  local -r repository="$1"
  local -r revision="$2"
  local -r recorded_git_tree="$3"
  local -r recorded_manifest="$4"
  local expected_git_tree=""
  local expected_manifest=""
  local expected_manifest_sha256=""

  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$recorded_git_tree" =~ ^[0-9a-f]{40}$ &&
    -f "$recorded_manifest" && ! -L "$recorded_manifest" ]] || return 1
  expected_git_tree="$(run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" \
    -C "$repository" rev-parse "$revision^{tree}" 2>/dev/null)" || return 1
  [[ "$expected_git_tree" == "$recorded_git_tree" ]] || return 1
  expected_manifest="$(mktemp "${recorded_manifest%/*}/.expected-git-tree.XXXXXX")" || return 1
  if ! write_git_tree_manifest_for_tree \
    "$repository" "$recorded_git_tree" "$expected_manifest"; then
    rm -f -- "$expected_manifest"
    return 1
  fi
  if ! cmp -- "$expected_manifest" "$recorded_manifest" >/dev/null; then
    rm -f -- "$expected_manifest"
    return 1
  fi
  expected_manifest_sha256="$(sha256_regular_file "$expected_manifest")" || {
    rm -f -- "$expected_manifest"
    return 1
  }
  rm -f -- "$expected_manifest" || return 1
  printf '%s\n' "$expected_manifest_sha256"
}

validate_runner_application_source_state() {
  local -r runner_directory="$1"
  local -r state="$runner_directory/source-state.txt"
  local -r manifest="$runner_directory/source-tree.manifest"
  local -r status="$runner_directory/git-status.txt"
  local -r environment="$runner_directory/environment.txt"
  local revision=""
  local dirty=""
  local tree_sha256=""
  local manifest_schema=""
  local tracked_patch_sha256=""
  local patch_identity_sha256=""
  local empty_sha256=""
  local observed_tree_sha256=""
  local -a lines=()

  [[ -d "$runner_directory" && ! -L "$runner_directory" &&
    -f "$state" && ! -L "$state" && -s "$manifest" && ! -L "$manifest" &&
    -f "$status" && ! -L "$status" && ! -s "$status" &&
    -f "$environment" && ! -L "$environment" ]] || return 1
  mapfile -t lines <"$state" || return 1
  ((${#lines[@]} == 6)) || return 1
  [[ "${lines[0]}" == revision=* && "${lines[1]}" == dirty=* &&
    "${lines[2]}" == source_tree_sha256=* &&
    "${lines[3]}" == source_tree_manifest_schema=* &&
    "${lines[4]}" == tracked_patch_sha256=* &&
    "${lines[5]}" == patch_identity_sha256=* ]] || return 1
  revision="${lines[0]#revision=}"
  dirty="${lines[1]#dirty=}"
  tree_sha256="${lines[2]#source_tree_sha256=}"
  manifest_schema="${lines[3]#source_tree_manifest_schema=}"
  tracked_patch_sha256="${lines[4]#tracked_patch_sha256=}"
  patch_identity_sha256="${lines[5]#patch_identity_sha256=}"
  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$dirty" == false &&
    "$tree_sha256" =~ ^[0-9a-f]{64}$ && "$manifest_schema" == git-tree-v2 &&
    "$tracked_patch_sha256" =~ ^[0-9a-f]{64}$ &&
    "$patch_identity_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_tree_sha256="$(sha256_regular_file "$manifest")" || return 1
  [[ "$observed_tree_sha256" == "$tree_sha256" ]] || return 1
  empty_sha256="$(printf '' | run_native_clean_environment \
    "$NATIVE_BENCHMARK_SHA256_COMMAND")" || return 1
  empty_sha256="${empty_sha256%% *}"
  [[ "$tracked_patch_sha256" == "$empty_sha256" ]] || return 1
  runner_environment_matches "$environment" revision "$revision" &&
    runner_environment_matches "$environment" dirty false &&
    runner_environment_matches "$environment" source_tree_sha256 "$tree_sha256" &&
    runner_environment_matches "$environment" source_tree_manifest_schema git-tree-v2 &&
    runner_environment_matches "$environment" tracked_patch_sha256 "$tracked_patch_sha256" &&
    runner_environment_matches "$environment" patch_identity_sha256 "$patch_identity_sha256"
}

# run.sh records a path-bearing SHA-256 transcript as patch_identity_sha256.
# Its random private work-directory name makes that retained value unique to
# each invocation, so derive the cross-cell identity from content digests only.
canonical_application_patch_identity() {
  local -r runner_directory="$1"
  local status_sha256=""
  local tree_sha256=""
  local tracked_patch_sha256=""
  local identity=""

  validate_runner_application_source_state "$runner_directory" || return 1
  status_sha256="$(sha256_regular_file "$runner_directory/git-status.txt")" || return 1
  tree_sha256="$(runner_environment_value \
    "$runner_directory/source-state.txt" source_tree_sha256)" || return 1
  tracked_patch_sha256="$(runner_environment_value \
    "$runner_directory/source-state.txt" tracked_patch_sha256)" || return 1
  identity="$({
    printf 'git_status_sha256=%s\n' "$status_sha256"
    printf 'source_tree_sha256=%s\n' "$tree_sha256"
    printf 'tracked_patch_sha256=%s\n' "$tracked_patch_sha256"
  } | run_native_clean_environment "$NATIVE_BENCHMARK_SHA256_COMMAND")" || return 1
  identity="${identity%% *}"
  [[ "$identity" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$identity"
}

validate_current_application_checkout() {
  local -r repository="$1"
  local -r expected_revision="$2"
  local repository_root=""
  local repository_physical=""
  local revision=""
  local status=""
  local index_flags=""
  local unmerged=""

  [[ -d "$repository" && ! -L "$repository" &&
    "$expected_revision" =~ ^[0-9a-f]{40}$ ]] || return 1
  resolve_benchmark_identity_tools || return 1
  repository_physical="$(cd -- "$repository" && pwd -P)" || return 1
  repository_root="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" rev-parse --show-toplevel)" || return 1
  repository_root="$(cd -- "$repository_root" && pwd -P)" || return 1
  [[ "$repository_root" == "$repository_physical" ]] || return 1
  revision="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" rev-parse HEAD)" || return 1
  [[ "$revision" == "$expected_revision" ]] || return 1
  index_flags="$(run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" \
    -C "$repository" ls-files -v)" || return 1
  awk 'substr($0, 1, 1) ~ /^[a-zS]$/ { exit 1 }' <<<"$index_flags" || return 1
  unmerged="$(run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" \
    -C "$repository" ls-files --unmerged)" || return 1
  [[ -z "$unmerged" ]] || return 1
  run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" \
    diff --quiet --no-ext-diff "$expected_revision" -- || return 1
  run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" \
    diff --cached --quiet --no-ext-diff "$expected_revision" -- || return 1
  status="$(run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" \
    -C "$repository" status --porcelain=v1 --untracked-files=all \
      --ignore-submodules=none)" || return 1
  [[ -z "$status" ]]
}

validate_application_source_identity_schema() {
  local -r artifact="$1"
  local -r repository="${2:-$REPO_ROOT}"
  local -r validate_live_checkout="${3:-true}"
  local artifact_root=""
  local cells_mode=""
  local expected_cells_json=""
  local cell=""
  local revision=""
  local reference_runner=""
  local runner_directory=""
  local source_state_link=""
  local manifest_link=""
  local status_link=""
  local environment_link=""
  local host_environment_link=""
  local native_source_link=""
  local canonical_patch_identity=""
  local runner_patch_identity=""
  local recorded_git_tree=""
  local derived_manifest_sha256=""

  [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
  [[ "$validate_live_checkout" == true || "$validate_live_checkout" == false ]] || return 1
  artifact_root="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  cells_mode="$(jq -er '.cells_mode' "$artifact")" || return 1
  [[ "$cells_mode" == core || "$cells_mode" == complete ]] || return 1
  if [[ "$cells_mode" == complete ]]; then
    expected_cells_json="$(jq -cn '$ARGS.positional' --args \
      "${CORE_CELLS[@]}" "${BOUNDED_PATH_CELLS[@]}")" || return 1
  else
    expected_cells_json="$(jq -cn '$ARGS.positional' --args "${CORE_CELLS[@]}")" || return 1
  fi
  jq -se --arg mode "$cells_mode" --argjson expected_cells "$expected_cells_json" '
    length == 1 and
    (.[0] |
      ((keys | sort) == [
        "canonical_patch_identity_sha256", "cells", "cells_mode", "git_tree",
        "host_environment", "kind", "native_source_state", "revision",
        "schema_version", "source_tree_manifest_schema", "source_tree_sha256",
        "status", "tracked_patch_sha256"
      ]) and
      .schema_version == 1 and .kind == "benchmark-application-source-identity" and
      .status == "clean_and_stable_across_all_requested_cells" and
      .cells_mode == $mode and
      (.revision | test("^[0-9a-f]{40}$")) and
      (.git_tree | test("^[0-9a-f]{40}$")) and
      (.source_tree_sha256 | test("^[0-9a-f]{64}$")) and
      .source_tree_manifest_schema == "git-tree-v2" and
      (.tracked_patch_sha256 | test("^[0-9a-f]{64}$")) and
      (.canonical_patch_identity_sha256 | test("^[0-9a-f]{64}$")) and
      .host_environment == "host-environment.txt" and
      .native_source_state == (if $mode == "complete" then "native-jni/source-state.json" else null end) and
      ([.cells[].cell] == $expected_cells) and
      all(.cells[];
        ((keys | sort) == [
          "cell", "git_status", "runner_environment",
          "runner_patch_identity_sha256", "source_state", "source_tree_manifest"
        ]) and
        (.runner_patch_identity_sha256 | test("^[0-9a-f]{64}$")) and
        .source_state == ("cells/" + .cell + "/preflight/runner/source-state.txt") and
        .source_tree_manifest == ("cells/" + .cell + "/preflight/runner/source-tree.manifest") and
        .git_status == ("cells/" + .cell + "/preflight/runner/git-status.txt") and
        .runner_environment == ("cells/" + .cell + "/preflight/runner/environment.txt")))
  ' "$artifact" >/dev/null || return 1
  revision="$(jq -er '.revision' "$artifact")" || return 1
  for cell in $(jq -r '.cells[].cell' "$artifact"); do
    source_state_link="$(jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .source_state' "$artifact")" || return 1
    manifest_link="$(jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .source_tree_manifest' "$artifact")" || return 1
    status_link="$(jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .git_status' "$artifact")" || return 1
    environment_link="$(jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .runner_environment' "$artifact")" || return 1
    for source_state_link in "$source_state_link" "$manifest_link" "$status_link" "$environment_link"; do
      validate_relative_artifact_link "$artifact_root" "$artifact_root" \
        "$source_state_link" || return 1
    done
    runner_directory="$artifact_root/cells/$cell/preflight/runner"
    validate_runner_application_source_state "$runner_directory" || return 1
    runner_environment_matches "$runner_directory/source-state.txt" revision "$revision" || return 1
    runner_patch_identity="$(runner_environment_value \
      "$runner_directory/source-state.txt" patch_identity_sha256)" || return 1
    jq -e --arg cell "$cell" --arg identity "$runner_patch_identity" '
      (.cells[] | select(.cell == $cell) | .runner_patch_identity_sha256) == $identity
    ' "$artifact" >/dev/null || return 1
    canonical_patch_identity="$(canonical_application_patch_identity \
      "$runner_directory")" || return 1
    [[ "$canonical_patch_identity" == \
      "$(jq -er '.canonical_patch_identity_sha256' "$artifact")" ]] || return 1
    if [[ -z "$reference_runner" ]]; then
      reference_runner="$runner_directory"
    else
      cmp -- "$reference_runner/source-tree.manifest" \
        "$runner_directory/source-tree.manifest" >/dev/null || return 1
      cmp -- "$reference_runner/git-status.txt" "$runner_directory/git-status.txt" \
        >/dev/null || return 1
    fi
  done
  [[ -n "$reference_runner" ]] || return 1
  recorded_git_tree="$(jq -er '.git_tree' "$artifact")" || return 1
  derived_manifest_sha256="$(validate_recorded_git_tree_manifest \
    "$repository" "$revision" "$recorded_git_tree" \
    "$reference_runner/source-tree.manifest")" || return 1
  jq -e --arg revision "$revision" \
    --arg tree "$(runner_environment_value "$reference_runner/source-state.txt" source_tree_sha256)" \
    --arg patch "$(runner_environment_value "$reference_runner/source-state.txt" tracked_patch_sha256)" '
      .revision == $revision and .source_tree_sha256 == $tree and
      .source_tree_manifest_schema == "git-tree-v2" and
      .tracked_patch_sha256 == $patch
    ' "$artifact" >/dev/null || return 1
  [[ "$derived_manifest_sha256" == \
    "$(jq -er '.source_tree_sha256' "$artifact")" ]] || return 1
  if [[ "$validate_live_checkout" == true ]]; then
    validate_current_application_checkout "$repository" "$revision" || return 1
  fi
  host_environment_link="$(jq -er '.host_environment' "$artifact")" || return 1
  validate_relative_artifact_link "$artifact_root" "$artifact_root" \
    "$host_environment_link" || return 1
  [[ "$(awk -F= '
    $1 == "git_revision" { matches++; value = $2 }
    END { if (matches != 1) exit 1; print value }
  ' "$artifact_root/$host_environment_link")" == "$revision" ]] || return 1
  if [[ "$cells_mode" == complete ]]; then
    native_source_link="$(jq -er '.native_source_state' "$artifact")" || return 1
    validate_relative_artifact_link "$artifact_root" "$artifact_root" \
      "$native_source_link" || return 1
    validate_native_source_state_schema "$artifact_root/$native_source_link" || return 1
    [[ "$(jq -er '.revision' "$artifact_root/$native_source_link")" == "$revision" ]] || return 1
  fi
}

write_application_source_identity() {
  local -r repository="${1:-$REPO_ROOT}"
  local -r output="$OUTPUT_DIR/application-source-identity.json"
  local expected_cells_json=""
  local cells_json=""
  local cell=""
  local runner_directory=""
  local reference_runner=""
  local revision=""
  local git_tree=""
  local tree_sha256=""
  local tracked_patch_sha256=""
  local canonical_patch_identity_sha256=""
  local runner_patch_identity_sha256=""
  local native_source_state="null"
  local temporary=""

  [[ "$OUTPUT_READY" == true && ! -e "$output" && ! -L "$output" ]] || return 1
  expected_cells_json="$(requested_application_cells_json)" || return 1
  cell="$(jq -er '.[0]' <<<"$expected_cells_json")" || return 1
  reference_runner="$OUTPUT_DIR/cells/$cell/preflight/runner"
  validate_runner_application_source_state "$reference_runner" || return 1
  revision="$(runner_environment_value "$reference_runner/source-state.txt" revision)" || return 1
  tree_sha256="$(runner_environment_value \
    "$reference_runner/source-state.txt" source_tree_sha256)" || return 1
  tracked_patch_sha256="$(runner_environment_value \
    "$reference_runner/source-state.txt" tracked_patch_sha256)" || return 1
  canonical_patch_identity_sha256="$(canonical_application_patch_identity \
    "$reference_runner")" || return 1
  cells_json="$({
    for cell in $(jq -r '.[]' <<<"$expected_cells_json"); do
      runner_directory="$OUTPUT_DIR/cells/$cell/preflight/runner"
      validate_runner_application_source_state "$runner_directory" || return 1
      runner_environment_matches "$runner_directory/source-state.txt" \
        revision "$revision" || return 1
      runner_environment_matches "$runner_directory/source-state.txt" \
        source_tree_sha256 "$tree_sha256" || return 1
      runner_environment_matches "$runner_directory/source-state.txt" \
        tracked_patch_sha256 "$tracked_patch_sha256" || return 1
      [[ "$(canonical_application_patch_identity "$runner_directory")" == \
        "$canonical_patch_identity_sha256" ]] || return 1
      cmp -- "$reference_runner/source-tree.manifest" \
        "$runner_directory/source-tree.manifest" >/dev/null || return 1
      cmp -- "$reference_runner/git-status.txt" "$runner_directory/git-status.txt" \
        >/dev/null || return 1
      runner_patch_identity_sha256="$(runner_environment_value \
        "$runner_directory/source-state.txt" patch_identity_sha256)" || return 1
      jq -cn --arg cell "$cell" \
        --arg runner_patch_identity_sha256 "$runner_patch_identity_sha256" '
        {cell: $cell,
         source_state: ("cells/" + $cell + "/preflight/runner/source-state.txt"),
         source_tree_manifest: ("cells/" + $cell + "/preflight/runner/source-tree.manifest"),
         git_status: ("cells/" + $cell + "/preflight/runner/git-status.txt"),
         runner_environment: ("cells/" + $cell + "/preflight/runner/environment.txt"),
         runner_patch_identity_sha256: $runner_patch_identity_sha256}
      ' || return 1
    done
  } | jq -s .)" || return 1
  validate_current_application_checkout "$repository" "$revision" || return 1
  git_tree="$(run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" \
    -C "$repository" rev-parse "$revision^{tree}")" || return 1
  [[ "$git_tree" =~ ^[0-9a-f]{40}$ ]] || return 1
  if [[ "$CELLS_MODE" == complete ]]; then
    validate_native_source_state_schema "$OUTPUT_DIR/native-jni/source-state.json" || return 1
    [[ "$(jq -er '.revision' "$OUTPUT_DIR/native-jni/source-state.json")" == "$revision" ]] || return 1
    native_source_state='"native-jni/source-state.json"'
  fi
  temporary="$(mktemp "$OUTPUT_DIR/.application-source-identity.json.XXXXXX")" || return 1
  jq -n --arg mode "$CELLS_MODE" --arg revision "$revision" \
    --arg git_tree "$git_tree" --arg tree_sha256 "$tree_sha256" \
    --arg tracked_patch_sha256 "$tracked_patch_sha256" \
    --arg canonical_patch_identity_sha256 "$canonical_patch_identity_sha256" \
    --argjson cells "$cells_json" --argjson native_source_state "$native_source_state" '
      {
        schema_version: 1,
        kind: "benchmark-application-source-identity",
        status: "clean_and_stable_across_all_requested_cells",
        cells_mode: $mode,
        revision: $revision,
        git_tree: $git_tree,
        source_tree_sha256: $tree_sha256,
        source_tree_manifest_schema: "git-tree-v2",
        tracked_patch_sha256: $tracked_patch_sha256,
        canonical_patch_identity_sha256: $canonical_patch_identity_sha256,
        host_environment: "host-environment.txt",
        native_source_state: $native_source_state,
        cells: $cells
      }
    ' >"$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  validate_application_source_identity_schema "$temporary" "$repository" || {
    rm -f -- "$temporary"
    return 1
  }
  mv -T -- "$temporary" "$output"
}

validate_path_source_provenance() {
  local source_revision=""

  validate_application_source_identity_schema \
    "$OUTPUT_DIR/application-source-identity.json" || return 1
  [[ "$(jq -er '.cells_mode' "$OUTPUT_DIR/application-source-identity.json")" == \
    complete ]] || return 1
  source_revision="$(jq -er '.revision' \
    "$OUTPUT_DIR/application-source-identity.json")" || return 1
  validate_native_jni_benchmark_schema "$OUTPUT_DIR/native-jni/benchmark.json" || return 1
  [[ "$(jq -er '.provenance.source_revision' \
    "$OUTPUT_DIR/native-jni/benchmark.json")" == "$source_revision" ]]
}

validate_lookup_path_summary_schema() {
  local -r summary="$1"
  local -r repository="${2:-$REPO_ROOT}"
  local summary_directory=""
  local cell=""
  local source_artifact=""
  local link_base=""
  local source_file=""
  local link=""
  local -a links=()

  [[ -f "$summary" && ! -L "$summary" ]] || return 1
  jq -se '
    length == 1 and
    (.[0] |
      ((keys | sort) == [
        "acceptance_evidence", "blocked_dimensions", "coverage", "kind",
        "native_lookup_benchmark", "paths", "provenance", "schema_version", "status"
      ]) and
      .schema_version == 1 and
      .kind == "java-remote-parent-path-observation-coverage" and
      .status == "partial_with_explicit_gaps" and
      .acceptance_evidence == false and
      .provenance == {
        application_source_identity: "application-source-identity.json",
        capture_scope: "single_harness_run_with_verified_unix_socket_and_per_sample_container_process_binding",
        docker_daemon: "docker-daemon.json",
        host_environment: "host-environment.txt"
      } and
      (.native_lookup_benchmark |
        ((keys | sort) == ["benchmark", "link_base", "source_artifact"]) and
        .source_artifact == "native-jni/benchmark.json" and
        .link_base == "native-jni/" and
        (.benchmark | type == "object")) and
      (.paths | type == "array" and length == 6) and
      ([.paths[].observation.cell] == [
        "getsockopt-hit", "unix-hit", "getsockopt-stale", "unix-stale",
        "unix-timeout", "getsockopt-pressure"
      ]) and
      all(.paths[];
        ((keys | sort) == ["link_base", "observation", "source_artifact"]) and
        (.source_artifact | type == "string" and length > 0) and
        (.link_base | type == "string" and length > 0) and
        (.observation | type == "object")) and
      (.coverage.getsockopt.hit == "correctness_observed_once" and
        .coverage.getsockopt.miss == "blocked" and
        .coverage.getsockopt.stale_failure == "correctness_observed_once" and
        .coverage.unix.hit == "correctness_observed_once" and
        .coverage.unix.miss == "blocked" and
        .coverage.unix.stale_failure == "correctness_observed_once" and
        .coverage.unix.timeout_failure == "correctness_observed_once" and
        .coverage.native_lookup.getsockopt_hit_miss_failure == "benchmark_measured" and
        .coverage.native_lookup.unix_hit_miss_failure == "benchmark_measured" and
        .coverage.pressure == "correctness_observed_once") and
      (.blocked_dimensions | type == "array" and length == 2) and
      all(.blocked_dimensions[];
        (.dimension | type == "string" and length > 0) and
        .status == "blocked" and
        (.reason | type == "string" and length > 0))
    )
  ' "$summary" >/dev/null || return 1
  summary_directory="$(cd -- "${summary%/*}" && pwd -P)" || return 1
  validate_relative_artifact_link "$summary_directory" "$summary_directory" \
    "$(jq -er '.provenance.host_environment' "$summary")" || return 1
  validate_relative_artifact_link "$summary_directory" "$summary_directory" \
    "$(jq -er '.provenance.docker_daemon' "$summary")" || return 1
  validate_relative_artifact_link "$summary_directory" "$summary_directory" \
    "$(jq -er '.provenance.application_source_identity' "$summary")" || return 1
  validate_docker_daemon_provenance_schema \
    "$summary_directory/$(jq -er '.provenance.docker_daemon' "$summary")" || return 1
  validate_application_source_identity_schema \
    "$summary_directory/$(jq -er '.provenance.application_source_identity' "$summary")" \
    "$repository" false || return 1
  [[ "$(jq -er '.cells_mode' \
    "$summary_directory/$(jq -er '.provenance.application_source_identity' "$summary")")" == \
    complete ]] || return 1
  for cell in "${PATH_OBSERVATION_CELLS[@]}"; do
    source_artifact="$(jq -er --arg cell "$cell" \
      '.paths[] | select(.observation.cell == $cell) | .source_artifact' \
      "$summary")" || return 1
    link_base="$(jq -er --arg cell "$cell" \
      '.paths[] | select(.observation.cell == $cell) | .link_base' \
      "$summary")" || return 1
    [[ "$source_artifact" == "cells/$cell/path-observation.json" &&
      "$link_base" == "cells/$cell/" ]] || return 1
    validate_relative_artifact_link \
      "$summary_directory" "$summary_directory" "$source_artifact" || return 1
    source_file="$summary_directory/$source_artifact"
    validate_path_observation_schema "$source_file" || return 1
    validate_path_observation_source_artifacts "$source_file" || return 1
    jq -e --arg cell "$cell" --slurpfile source "$source_file" '
      (.paths[] | select(.observation.cell == $cell) | .observation) == $source[0]
    ' "$summary" >/dev/null || return 1
    mapfile -t links < <(jq -er --arg cell "$cell" '
      .paths[] | select(.observation.cell == $cell) | .observation |
      [.source.result, .source.status, .source.java_diagnostics_delta,
       .provenance.host_environment, .provenance.runner_environment,
       .provenance.runner_provenance, .provenance.source_state][]
    ' "$summary") || return 1
    [[ ${#links[@]} == 7 ]] || return 1
    for link in "${links[@]}"; do
      validate_relative_artifact_link \
        "$summary_directory/$link_base" "$summary_directory" "$link" || return 1
    done
  done
  source_artifact="$(jq -er '.native_lookup_benchmark.source_artifact' "$summary")" || return 1
  link_base="$(jq -er '.native_lookup_benchmark.link_base' "$summary")" || return 1
  [[ "$source_artifact" == "native-jni/benchmark.json" &&
    "$link_base" == "native-jni/" ]] || return 1
  validate_relative_artifact_link \
    "$summary_directory" "$summary_directory" "$source_artifact" || return 1
  source_file="$summary_directory/$source_artifact"
  validate_native_jni_benchmark_schema "$source_file" || return 1
  jq -e --slurpfile source "$source_file" \
    '.native_lookup_benchmark.benchmark == $source[0]' "$summary" >/dev/null
}

write_lookup_path_summary() {
  local -r output="$OUTPUT_DIR/lookup-paths.json"
  local cell=""
  local paths_json=""
  local temporary=""

  [[ "$CELLS_MODE" == "complete" && ! -e "$output" && ! -L "$output" ]] || return 1
  validate_path_source_provenance || return 1
  paths_json="$({
    for cell in "${PATH_OBSERVATION_CELLS[@]}"; do
      validate_path_observation_schema "$OUTPUT_DIR/cells/$cell/path-observation.json" || return 1
      jq -cn --arg source_artifact "cells/$cell/path-observation.json" \
        --arg link_base "cells/$cell/" \
        --slurpfile observation "$OUTPUT_DIR/cells/$cell/path-observation.json" '
          {source_artifact: $source_artifact, link_base: $link_base,
           observation: $observation[0]}
        ' || return 1
    done
  } | jq -s .)" || return 1
  temporary="$(mktemp "$OUTPUT_DIR/.lookup-paths.json.XXXXXX")" || return 1
  jq -n \
    --argjson paths "$paths_json" \
    --slurpfile native_lookup "$OUTPUT_DIR/native-jni/benchmark.json" '
    {
      schema_version: 1,
      kind: "java-remote-parent-path-observation-coverage",
      status: "partial_with_explicit_gaps",
      acceptance_evidence: false,
      provenance: {
        application_source_identity: "application-source-identity.json",
        capture_scope: "single_harness_run_with_verified_unix_socket_and_per_sample_container_process_binding",
        docker_daemon: "docker-daemon.json",
        host_environment: "host-environment.txt"
      },
      paths: $paths,
      native_lookup_benchmark: {
        source_artifact: "native-jni/benchmark.json",
        link_base: "native-jni/",
        benchmark: $native_lookup[0]
      },
      coverage: {
        getsockopt: {
          hit: "correctness_observed_once",
          miss: "blocked",
          stale_failure: "correctness_observed_once"
        },
        unix: {
          hit: "correctness_observed_once", miss: "blocked",
          stale_failure: "correctness_observed_once",
          timeout_failure: "correctness_observed_once"
        },
        native_lookup: {
          getsockopt_hit_miss_failure: "benchmark_measured",
          unix_hit_miss_failure: "benchmark_measured"
        },
        pressure: "correctness_observed_once"
      },
      blocked_dimensions: [
        {
          dimension: "application_state_map_miss",
          status: "blocked",
          reason: "the benchmark has no test-only fixture that removes the exact Apache-to-Java request state before lookup; helper-idle has no upstream handoff and is not relabelled as a map miss"
        },
        {
          dimension: "in_jvm_java_to_native_transition_latency_percentiles",
          status: "blocked",
          reason: "the retained native fixture measures the production C transport/provider lookup but the stock Java diagnostics expose no per-call Java-to-native transition duration"
        }
      ]
    }
  ' >"$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  validate_lookup_path_summary_schema "$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  mv -T -- "$temporary" "$output"
}

start_cell_stack() {
  local -r cell_dir="$1"
  local -r project="$2"
  local runner_log="$cell_dir/preflight/runner.log"
  local result_directory=""

  ACTIVE_PROJECT="$project"
  ACTIVE_CELL_DIR="$cell_dir"
  unset BENCHMARK_CA_SOURCE
  if ! run_bounded "$RUNNER_START_TIMEOUT_SECONDS" env \
    COMPOSE_PROJECT_NAME="$project" \
    "$RUNNER" \
      --transport "$CELL_TRANSPORT" \
      --scenario "$CELL_SCENARIO" \
      --agent "$AGENT" \
      --tls "$TLS_PROTOCOL" \
      --requests "$CELL_PREFLIGHT_REQUESTS" \
      --seed "$SEED" \
      --keep >"$runner_log" 2>&1; then
    return 1
  fi
  result_directory="$(runner_result_directory "$runner_log")" || return 1
  validate_runner_result "$result_directory" || return 1
  validate_runner_environment "$result_directory" || return 1
  verify_preflight "$result_directory" || return 1
  prepare_benchmark_ca "$result_directory" "$cell_dir" || return 1
  retain_runner_artifacts "$result_directory" "$cell_dir"
}

cleanup_active_project() {
  local cleanup_log=""
  local project=""
  local cell_dir=""

  [[ -n "$ACTIVE_PROJECT" ]] || return 0
  project="$ACTIVE_PROJECT"
  cell_dir="$ACTIVE_CELL_DIR"
  cleanup_log="$cell_dir/runner-cleanup.log"
  if ! run_bounded "$RUNNER_CLEANUP_TIMEOUT_SECONDS" env \
    COMPOSE_PROJECT_NAME="$project" "$RUNNER" --cleanup-only >"$cleanup_log" 2>&1; then
    return 1
  fi
  ACTIVE_PROJECT=""
  ACTIVE_CELL_DIR=""
  COMPOSE=()
  unset BENCHMARK_CA_SOURCE
}

write_cell_status() {
  local -r cell_dir="$1"
  local -r status="$2"
  local -r reason="${3:-}"

  jq -n \
    --arg status "$status" \
    --arg cell "$CELL_SLUG" \
    --arg reason "$reason" \
    --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{status: $status, cell: $cell, reason: ($reason | if . == "" then null else . end), completed_at: $completed_at}' \
    >"$cell_dir/status.json"
}

write_helper_idle_reconciliation() {
  local -r helper_directory="$1"
  local -r successful_requests="$2"
  local java_deltas=""
  local bpf_deltas=""

  [[ -f "$helper_directory/java-diagnostics-deltas.json" &&
    ! -L "$helper_directory/java-diagnostics-deltas.json" &&
    -f "$helper_directory/obi-metrics-deltas.json" &&
    ! -L "$helper_directory/obi-metrics-deltas.json" ]] || return 1
  java_deltas="$(jq -c . "$helper_directory/java-diagnostics-deltas.json")" || return 1
  bpf_deltas="$(jq -c . "$helper_directory/obi-metrics-deltas.json")" || return 1
  jq -n \
    --arg cell "$CELL_SLUG" \
    --arg semantic "direct_java_no_upstream_handoff_not_state_map_miss_proof" \
    --arg base_url "$CELL_WORKLOAD_BASE_URL" \
    --arg path "$CELL_WORKLOAD_PATH" \
    --arg connection_mode "$CELL_WORKLOAD_CONNECTION_MODE" \
    --arg ca_file "$CELL_WORKLOAD_CA_FILE" \
    --arg tls_verification "$CELL_EXPECTED_TLS_VERIFICATION" \
    --argjson successful_requests "$successful_requests" \
    --argjson java_deltas "$java_deltas" \
    --argjson bpf_deltas "$bpf_deltas" \
    '{
      cell: $cell,
      semantic: $semantic,
      workload: {
        base_url: $base_url,
        path: $path,
        connection_mode: $connection_mode,
        ca_file: $ca_file,
        tls_verification: $tls_verification,
        w3c_headers: false,
        upstream_handoff: "none"
      },
      workload_successful_requests: $successful_requests,
      java: {
        raw_t_missing_delta: $java_deltas.raw_java_t_missing_delta,
        diagnostic_after_probe_t_missing: $java_deltas.diagnostic_after_probe_t_missing,
        corrected_workload_t_missing: $java_deltas.corrected_workload_t_missing,
        exact_workload_reconciliation: ($java_deltas.corrected_workload_t_missing == $successful_requests)
      },
      bpf: {
        no_tcp_upstream_lifecycle_or_getsockopt_retrieval_outcome: true,
        report_watermark_delta: $bpf_deltas.report_watermark.observed_delta,
        negotiate_missing: $bpf_deltas.informative_getsockopt_negotiate_missing
      },
      caveat: "This direct Java HTTPS control proves no Apache upstream handoff was observed during the exact window. It does not prove a java_remote_parent_state map absence, eviction, timeout, or per-request native getsockopt retrieval."
    }' >"$helper_directory/reconciliation.json"
}

run_helper_idle_sustained() {
  local -r cell_dir="$1"
  local -r helper_directory="$cell_dir/sustained-helper-idle"
  local successful_requests=0
  local request_count=""
  local repetition=0
  local repetition_label=""

  [[ "$CELL_HELPER_IDLE" == "true" && "$CELL_REQUIRES_OBI" == "true" &&
    "$CELL_WORKLOAD_BASE_URL" == "$DIRECT_JAVA_WORKLOAD_BASE_URL" &&
    "$CELL_WORKLOAD_CA_FILE" == "$DIRECT_JAVA_WORKLOAD_CA_FILE" &&
    "$CELL_SUSTAINED_W3C" == "false" ]] || return 1
  mkdir -- "$helper_directory"
  capture_java_diagnostics "$helper_directory/java-diagnostics-before.txt"
  validate_java_diagnostics_snapshot "$helper_directory/java-diagnostics-before.txt"
  # The first observation is deliberately made after the Java diagnostic request
  # has returned. The following two report passes form a causal BPF fence, so
  # no pre-window lifecycle update can be mistaken for the workload baseline.
  capture_obi_metrics "$helper_directory/obi-metrics-before-observed.prom"
  wait_for_helper_idle_two_pass_fence \
    "$helper_directory/obi-metrics-before-observed.prom" \
    "$helper_directory/obi-metrics-before.prom" \
    "$helper_directory/metrics-watermark-before.json" \
    "post-diagnostics helper-idle baseline"

  log_info "warming $CELL_SLUG for ${WARMUP_SECONDS}s"
  run_benchmark_client "$cell_dir/warmup.json" "$WARMUP_SECONDS"
  validate_benchmark_result "$cell_dir/warmup.json" "$WARMUP_SECONDS"
  request_count="$(benchmark_successful_request_count "$cell_dir/warmup.json")" || return 1
  ((successful_requests <= MAX_JAVA_DIAGNOSTIC_COUNTER - request_count)) || return 1
  successful_requests="$((successful_requests + request_count))"
  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    log_info "measuring $CELL_SLUG repetition $repetition/$REPETITIONS"
    run_helper_idle_measurement_rep "$cell_dir" "$repetition"
    printf -v repetition_label 'rep-%02d' "$repetition"
    request_count="$(benchmark_successful_request_count \
      "$cell_dir/measurements/$repetition_label.json")" || return 1
    ((successful_requests <= MAX_JAVA_DIAGNOSTIC_COUNTER - request_count)) || return 1
    successful_requests="$((successful_requests + request_count))"
  done
  # Take a fresh observation after every workload client has exited. Waiting for
  # two subsequent BPF report passes prevents a pass that occurred during the
  # workload from being used as its completion boundary.
  capture_obi_metrics "$helper_directory/obi-metrics-after-workload-observed.prom"
  wait_for_helper_idle_two_pass_fence \
    "$helper_directory/obi-metrics-after-workload-observed.prom" \
    "$helper_directory/obi-metrics-after.prom" \
    "$helper_directory/metrics-watermark-after.json" \
    "post-workload helper-idle"
  capture_java_diagnostics "$helper_directory/java-diagnostics-after.txt"
  validate_java_diagnostics_snapshot "$helper_directory/java-diagnostics-after.txt"
  validate_helper_idle_java_diagnostics \
    "$helper_directory/java-diagnostics-before.txt" \
    "$helper_directory/java-diagnostics-after.txt" \
    "$helper_directory/java-diagnostics-deltas.json" \
    "$successful_requests"
  helper_idle_metric_delta_json \
    "$helper_directory/obi-metrics-before.prom" \
    "$helper_directory/obi-metrics-after.prom" \
    "$helper_directory/obi-metrics-deltas.json"
  write_helper_idle_reconciliation "$helper_directory" "$successful_requests"
}

write_core_hit_path_observation_if_requested() {
  local -r cell_dir="$1"

  if [[ "$CELLS_MODE" == "complete" && "$CELL_PATH_CLASSIFICATION" == "hit" ]]; then
    write_path_observation "$cell_dir"
  fi
}

run_cell() {
  local -r cell="$1"
  local cell_dir=""
  local project=""
  local repetition=0
  local repetition_label=""

  cell_spec "$cell" || return 1
  cell_dir="$OUTPUT_DIR/cells/$CELL_SLUG"
  mkdir -- "$cell_dir" "$cell_dir/measurements"
  write_cell_contract "$cell_dir"
  project="$(project_for_cell "$CELL_SLUG")" || return 1
  configure_compose "$project" || return 1
  jq -n --arg project "$project" --arg cell "$CELL_SLUG" \
    '{project: $project, cell: $cell}' >"$cell_dir/project.json"

  log_info "starting $CELL_SLUG preflight project=$project"
  start_cell_stack "$cell_dir" "$project"
  write_core_hit_path_observation_if_requested "$cell_dir"
  capture_resource_snapshot "$cell_dir/resources-before" before
  if [[ "$CELL_HELPER_IDLE" == "true" ]]; then
    run_helper_idle_sustained "$cell_dir"
  else
    if [[ "$CELL_SUSTAINED_W3C" == "true" ]]; then
      mkdir -- "$cell_dir/sustained-w3c"
      capture_java_diagnostics "$cell_dir/sustained-w3c/java-diagnostics-before.txt"
    fi
    log_info "warming $CELL_SLUG for ${WARMUP_SECONDS}s"
    run_benchmark_client "$cell_dir/warmup.json" "$WARMUP_SECONDS"
    validate_benchmark_result "$cell_dir/warmup.json" "$WARMUP_SECONDS"
    if [[ "$CELL_SUSTAINED_W3C" == "true" ]]; then
      record_w3c_workload_successes "$cell_dir/warmup.json"
    fi

    for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
      log_info "measuring $CELL_SLUG repetition $repetition/$REPETITIONS"
      run_measurement_rep "$cell_dir" "$repetition"
      if [[ "$CELL_SUSTAINED_W3C" == "true" ]]; then
        printf -v repetition_label 'rep-%02d' "$repetition"
        record_w3c_workload_successes "$cell_dir/measurements/$repetition_label.json"
      fi
    done
    if [[ "$CELL_SUSTAINED_W3C" == "true" ]]; then
      capture_java_diagnostics "$cell_dir/sustained-w3c/java-diagnostics-after.txt"
      validate_java_diagnostics_counter_deltas \
        "$cell_dir/sustained-w3c/java-diagnostics-before.txt" \
        "$cell_dir/sustained-w3c/java-diagnostics-after.txt" \
        "$cell_dir/sustained-w3c/java-diagnostics-deltas.json" \
        discard_standard "$CELL_W3C_WORKLOAD_SUCCESSFUL_REQUESTS" \
        t_valid "$CELL_W3C_WORKLOAD_SUCCESSFUL_REQUESTS" \
        d_valid 0
    fi
  fi
  capture_resource_snapshot "$cell_dir/resources-after-load" after
  run_postload_sentinel "$cell_dir"
  sleep "$METRICS_SETTLE_SECONDS"
  capture_resource_snapshot "$cell_dir/resources-idle-recovery" idle_recovery
  cleanup_active_project
  write_cell_status "$cell_dir" passed
}

run_bounded_path_cell() {
  local -r cell="$1"
  local cell_dir=""
  local project=""

  cell_spec "$cell" || return 1
  [[ "$CELL_BOUNDED_PATH" == "true" ]] || return 1
  cell_dir="$OUTPUT_DIR/cells/$CELL_SLUG"
  mkdir -- "$cell_dir"
  write_cell_contract "$cell_dir"
  project="$(project_for_cell "$CELL_SLUG")" || return 1
  configure_compose "$project" || return 1
  jq -n --arg project "$project" --arg cell "$CELL_SLUG" \
    '{project: $project, cell: $cell}' >"$cell_dir/project.json"

  log_info "starting bounded $CELL_SLUG evidence project=$project"
  start_cell_stack "$cell_dir" "$project"
  write_path_observation "$cell_dir"
  cleanup_active_project
  write_cell_status "$cell_dir" passed
}

validate_variance_summary_schema() {
  local -r artifact="$1"
  local artifact_root=""
  local expected=""

  [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
  artifact_root="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  expected="$(variance_summary_json "$artifact_root")" || return 1
  jq -se --argjson expected "$expected" '
    length == 1 and .[0] == $expected
  ' "$artifact" >/dev/null
}

write_summary() {
  local status="$1"
  local cell=""
  local status_file=""
  local cells_json=""
  local bounded_cells_json="[]"
  local lookup_paths_json='{"status":"not_requested","path":null}'
  local native_jni_json='{"status":"not_requested","path":null}'
  local docker_daemon_json='{"status":"requested_but_unavailable","path":null}'
  local application_source_json='{"status":"requested_but_unavailable","path":null}'
  local poc_gates_json='{"status":"not_available","path":null,"result":null}'
  local poc_resources_json='{"status":"not_available","result":null,"process_dimension":null,"map_dimension":null}'
  local variance_json=""
  local summary_temporary=""
  local manifest_temporary=""

  [[ "$OUTPUT_READY" == "true" ]] || return 0
  if [[ "$CELLS_MODE" == "complete" ]]; then
    lookup_paths_json='{"status":"requested_but_unavailable","path":null}'
    native_jni_json='{"status":"requested_but_unavailable","path":null}'
  fi
  if [[ "$status" == "passed" ]]; then
    validate_docker_daemon_provenance "$OUTPUT_DIR/docker-daemon.json" || return 1
    docker_daemon_json='{"status":"verified_local_unix_socket_endpoint_only","path":"docker-daemon.json"}'
    validate_application_source_identity_schema \
      "$OUTPUT_DIR/application-source-identity.json" || return 1
    [[ "$(jq -er '.cells_mode' "$OUTPUT_DIR/application-source-identity.json")" == \
      "$CELLS_MODE" ]] || return 1
    application_source_json='{"status":"clean_and_stable","path":"application-source-identity.json"}'
    validate_variance_summary_schema "$OUTPUT_DIR/variance.json" || return 1
    variance_json='{"status":"available","path":"variance.json"}'
    validate_supported_poc_dimensions_pass "$OUTPUT_DIR/poc-gates.json" || return 1
    poc_gates_json="$(jq -c '{status, path: "poc-gates.json", result}' \
      "$OUTPUT_DIR/poc-gates.json")" || return 1
    poc_resources_json="$(jq -c \
      '.resources | {status, result, process_dimension, map_dimension}' \
      "$OUTPUT_DIR/poc-gates.json")" || return 1
    if [[ "$CELLS_MODE" == "complete" ]]; then
      validate_lookup_path_summary_schema "$OUTPUT_DIR/lookup-paths.json" || return 1
      validate_native_jni_benchmark_schema "$OUTPUT_DIR/native-jni/benchmark.json" || return 1
      lookup_paths_json='{"status":"available","path":"lookup-paths.json"}'
      native_jni_json='{"status":"available","path":"native-jni/benchmark.json"}'
    fi
  else
    if validate_docker_daemon_provenance "$OUTPUT_DIR/docker-daemon.json"; then
      docker_daemon_json='{"status":"verified_local_unix_socket_endpoint_only","path":"docker-daemon.json"}'
    fi
    if validate_application_source_identity_schema \
      "$OUTPUT_DIR/application-source-identity.json" &&
      [[ "$(jq -er '.cells_mode' "$OUTPUT_DIR/application-source-identity.json")" == \
        "$CELLS_MODE" ]]; then
      application_source_json='{"status":"clean_and_stable","path":"application-source-identity.json"}'
    fi
    if validate_variance_summary_schema "$OUTPUT_DIR/variance.json"; then
      variance_json='{"status":"available","path":"variance.json"}'
    else
      rm -f -- "$OUTPUT_DIR/variance.json" || return 1
      variance_json='{"status":"not_available","path":null}'
    fi
    rm -f -- "$OUTPUT_DIR/summary.json" || return 1
    if [[ -f "$OUTPUT_DIR/poc-gates.json" && ! -L "$OUTPUT_DIR/poc-gates.json" ]] &&
      validate_poc_gate_schema "$OUTPUT_DIR/poc-gates.json"; then
      poc_gates_json="$(jq -c '{status, path: "poc-gates.json", result}' \
        "$OUTPUT_DIR/poc-gates.json")" || return 1
      poc_resources_json="$(jq -c \
        '.resources | {status, result, process_dimension, map_dimension}' \
        "$OUTPUT_DIR/poc-gates.json")" || return 1
    fi
    if [[ "$CELLS_MODE" == "complete" ]]; then
      if validate_lookup_path_summary_schema "$OUTPUT_DIR/lookup-paths.json"; then
        lookup_paths_json='{"status":"available","path":"lookup-paths.json"}'
      fi
      if validate_native_jni_benchmark_schema "$OUTPUT_DIR/native-jni/benchmark.json"; then
        native_jni_json='{"status":"available","path":"native-jni/benchmark.json"}'
      fi
    fi
  fi
  [[ ! -e "$OUTPUT_DIR/summary.json" ||
    ( -f "$OUTPUT_DIR/summary.json" && ! -L "$OUTPUT_DIR/summary.json" ) ]] || return 1
  [[ -f "$OUTPUT_DIR/manifest.json" && ! -L "$OUTPUT_DIR/manifest.json" ]] || return 1
  cells_json="$({
    for cell in "${CORE_CELLS[@]}"; do
      status_file="$OUTPUT_DIR/cells/$cell/status.json"
      if [[ -f "$status_file" && ! -L "$status_file" ]]; then
        jq -c . "$status_file"
      else
        jq -nc --arg cell "$cell" '{status: "not_run", cell: $cell}'
      fi
    done
  } | jq -s .)" || return 1
  if [[ "$CELLS_MODE" == "complete" ]]; then
    bounded_cells_json="$({
      for cell in "${BOUNDED_PATH_CELLS[@]}"; do
        status_file="$OUTPUT_DIR/cells/$cell/status.json"
        if [[ -f "$status_file" && ! -L "$status_file" ]]; then
          jq -c . "$status_file"
        else
          jq -nc --arg cell "$cell" '{status: "not_run", cell: $cell}'
        fi
      done
    } | jq -s .)" || return 1
  fi
  summary_temporary="$(mktemp "$OUTPUT_DIR/.summary.json.XXXXXX")" || return 1
  manifest_temporary="$(mktemp "$OUTPUT_DIR/.manifest.json.XXXXXX")" || {
    rm -f -- "$summary_temporary" || return 1
    return 1
  }
  if ! jq -n \
    --arg status "$status" \
    --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson cells "$cells_json" \
    --argjson bounded_cells "$bounded_cells_json" \
    --argjson variance "$variance_json" \
    --argjson lookup_paths "$lookup_paths_json" \
    --argjson native_jni "$native_jni_json" \
    --argjson docker_daemon "$docker_daemon_json" \
    --argjson application_source "$application_source_json" \
    --argjson poc_gates "$poc_gates_json" \
    --argjson poc_resources "$poc_resources_json" \
    '{
      status: $status,
      acceptance_evidence: false,
      completed_at: $completed_at,
      cells: $cells,
      bounded_path_cells: $bounded_cells,
      variance: $variance,
      docker_daemon: $docker_daemon,
      application_source: $application_source,
      lookup_paths: $lookup_paths,
      native_jni_lookup: $native_jni,
      poc_gates: $poc_gates,
      measurement_scope: {
        application_fd_threads_and_java_bridge_map_growth: {
          status: $poc_resources.status,
          result: $poc_resources.result,
          process_fd_threads: $poc_resources.process_dimension,
          java_bridge_map: $poc_resources.map_dimension
        },
        application_cpu_rss: "requested_point_samples_not_evaluated_as_a_growth_gate",
        jfr_nmt_allocation_native_direct_memory: "not_collected",
        primary_cgroupsockopt_program_cpu: "not_collected",
        bpf_lock_contention: "not_collected",
        pressure_map_occupancy_and_capacity_rejection: (
          if $lookup_paths.status == "available" then "bounded_correctness_observed_once"
          elif $lookup_paths.status == "requested_but_unavailable"
          then "requested_but_unavailable"
          else "not_requested" end
        )
      },
      notes: [
        "The bounded preflight and post-load sentinel establish the declared correctness assertion for each cell.",
        "variance.json is the sustained application performance benchmark; poc-gates.json applies the predeclared PoC thresholds to its fixed five-repetition medians.",
        "Midpoint resource snapshots are unsynchronized point samples and do not prove full in-load coverage.",
        "Unavailable dimensions in manifest.json are not measured as zero.",
        "The process-growth dimension requires complete before and idle-recovery FD and thread samples; unavailable samples cannot pass that dimension.",
        "Java bridge map counters are evaluated only when both scrapes are bracketed by the same exact OBI process identity and open BPF FD roster; unrelated host-global map IDs are excluded.",
        "docker-daemon.json proves only that the selected endpoint was a stable existing non-symlink Unix socket; it does not prove where the daemon process runs.",
        "Each available process sample separately binds the exact inspected container ID to bounded local procfs cgroup, PID-start-time, and cgroup-digest evidence.",
        "A passed summary status means the harness completed successfully; poc-gates.json remains partial and is not issue-acceptance evidence.",
        "Process and container samples do not establish JFR/NMT allocations, native/direct memory, BPF CPU, or lock contention."
      ]
    }' >"$summary_temporary"; then
    rm -f -- "$summary_temporary" "$manifest_temporary" || return 1
    return 1
  fi
  if ! jq --arg status "$status" '.status = $status' "$OUTPUT_DIR/manifest.json" \
    >"$manifest_temporary"; then
    rm -f -- "$summary_temporary" "$manifest_temporary" || return 1
    return 1
  fi
  if [[ "$status" == passed ]] && {
    ! validate_docker_daemon_provenance "$OUTPUT_DIR/docker-daemon.json" ||
    ! validate_application_source_identity_schema \
      "$OUTPUT_DIR/application-source-identity.json" ||
    [[ "$(jq -er '.cells_mode' "$OUTPUT_DIR/application-source-identity.json")" != \
      "$CELLS_MODE" ]];
  }; then
    rm -f -- "$summary_temporary" "$manifest_temporary" || return 1
    return 1
  fi
  if ! mv -T -- "$summary_temporary" "$OUTPUT_DIR/summary.json"; then
    rm -f -- "$summary_temporary" "$manifest_temporary" || return 1
    return 1
  fi
  if ! mv -T -- "$manifest_temporary" "$OUTPUT_DIR/manifest.json"; then
    rm -f -- "$manifest_temporary" || return 1
    return 1
  fi
}

terminate_active_benchmark() {
  local benchmark_pid="$BENCHMARK_PID"
  local identity=""
  local process_group=""
  local session=""
  local start_time=""
  local job_is_running=false

  [[ -n "$benchmark_pid" ]] || return 0
  [[ "$benchmark_pid" =~ ^[1-9][0-9]*$ ]] || {
    clear_active_benchmark
    return 1
  }
  if benchmark_job_is_running "$benchmark_pid"; then
    job_is_running=true
  fi
  if benchmark_identity_matches_leader "$benchmark_pid"; then
    terminate_verified_benchmark_group "$benchmark_pid"
    return $?
  fi
  if benchmark_pid_is_absent_or_zombie "$benchmark_pid" &&
    benchmark_group_has_member "$benchmark_pid" "$benchmark_pid"; then
    # The leader's PID is gone, but a member still retains the original
    # dedicated session. Its PGID/SID cannot have been recycled while live.
    terminate_verified_benchmark_group "$benchmark_pid"
    return $?
  fi
  if [[ "$job_is_running" == "false" ]]; then
    # A completed job's numeric PID may already name an unrelated process.
    # With no retained group member, only reap/clear the stale bookkeeping.
    wait "$benchmark_pid" 2>/dev/null || true
    clear_active_benchmark
    return 0
  fi
  if identity="$(benchmark_process_identity "$benchmark_pid")"; then
    read -r process_group session start_time <<<"$identity"
    if [[ "$process_group" == "$benchmark_pid" && "$session" == "$benchmark_pid" ]]; then
      if [[ -z "$BENCHMARK_IDENTITY" ]]; then
        BENCHMARK_IDENTITY="$identity"
        terminate_verified_benchmark_group "$benchmark_pid"
        return $?
      fi
      if benchmark_pending_identity_matches_leader "$benchmark_pid"; then
        BENCHMARK_IDENTITY="$identity"
        terminate_verified_benchmark_group "$benchmark_pid"
        return $?
      fi
    fi
    if [[ -z "$BENCHMARK_IDENTITY" ]]; then
      BENCHMARK_IDENTITY="pending $start_time"
    fi
  fi
  if benchmark_pending_identity_matches_leader "$benchmark_pid"; then
    # Before setsid completes, terminate only the launch identity we observed.
    kill -TERM "$benchmark_pid" 2>/dev/null || true
    wait "$benchmark_pid" 2>/dev/null || true
    clear_active_benchmark
    return 0
  fi
  # A still-running job without a matching launch/session identity must not be
  # signalled. Its bounded timeout remains the only safe cleanup authority.
  clear_active_benchmark
  return 1
}

on_exit() {
  local status="$1"
  local final_status="$status"

  trap - EXIT INT TERM
  set +e
  terminate_active_benchmark || true
  if [[ -n "$ACTIVE_PROJECT" ]]; then
    write_cell_status "$ACTIVE_CELL_DIR" failed "interrupted_or_failed_before_cleanup" || true
    if ! cleanup_active_project; then
      log_error "runner cleanup failed for project $ACTIVE_PROJECT"
      final_status=1
    fi
  fi
  release_lock
  if ((final_status == 0)) && [[ "$HARNESS_STATUS" == "passed" ]]; then
    if ! write_summary passed; then
      final_status=1
      write_summary failed || final_status=1
    fi
  else
    write_summary failed || final_status=1
  fi
  exit "$final_status"
}

main() {
  local cell=""

  printf -v HARNESS_INVOCATION '%q ' "$0" "$@"
  HARNESS_INVOCATION="${HARNESS_INVOCATION% }"
  parse_args "$@"
  if [[ "$SHOW_HELP" == "true" ]]; then
    usage
    return 0
  fi
  check_dependencies
  prepare_output_directory
  STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RUN_TOKEN="$(date -u +%s)-$$"
  [[ "$RUN_TOKEN" =~ ^[0-9]+-[0-9]+$ ]] || return 1
  # Bootstrap terminal-state evidence before the second, fallible Docker
  # context/endpoint query performed by provenance publication.
  write_manifest
  write_docker_daemon_provenance
  capture_host_environment
  acquire_lock
  mkdir -- "$OUTPUT_DIR/cells"
  if [[ "$CELLS_MODE" == "complete" ]]; then
    run_native_jni_benchmark
  fi
  for cell in "${CORE_CELLS[@]}"; do
    run_cell "$cell"
  done
  write_variance_summary
  write_poc_gate_summary
  validate_supported_poc_dimensions_pass "$OUTPUT_DIR/poc-gates.json"
  if [[ "$CELLS_MODE" == "complete" ]]; then
    for cell in "${BOUNDED_PATH_CELLS[@]}"; do
      run_bounded_path_cell "$cell"
    done
  fi
  write_application_source_identity "$REPO_ROOT"
  if [[ "$CELLS_MODE" == "complete" ]]; then
    write_lookup_path_summary
  fi
  HARNESS_STATUS="passed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap 'on_exit "$?"' EXIT
  trap 'exit 130' INT TERM
  main "$@"
fi
