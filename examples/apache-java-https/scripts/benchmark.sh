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
readonly MAX_SEED=9007199254740991
readonly MAX_JSON_EXACT_INTEGER=9007199254740991
readonly MAX_JAVA_DIAGNOSTIC_COUNTER=999999999
readonly MAX_BPF_OPERATION_COUNTER=9007199254740991
readonly MAX_BPF_PROGRAM_METRIC_COUNTER=9007199254740991
readonly MAX_BPF_PROGRAM_RUNTIME_NANOSECONDS=9007199254740991
readonly MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES=4096
readonly MAX_JAVA_RUNTIME_SNAPSHOT_BYTES=4096
readonly MAX_JAVA_TOOL_OUTPUT_BYTES=1048576
readonly MAX_JAVA_RUNTIME_ARTIFACT_BYTES=16777216
readonly MAX_JAVA_TREE_LISTING_BYTES=1048576
readonly MAX_JAVA_EVIDENCE_FILES=128
readonly MAX_JFR_BYTES=33554432
readonly MAX_JFR_RECORDS=600000
readonly MAX_NMT_LINES=4096
readonly MAX_BENCHMARK_RESULT_BYTES=100663296
readonly MAX_OBI_METRICS_SNAPSHOT_BYTES=16777216
readonly MAX_BPF_FD_OWNERSHIP_BYTES=1048576
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
readonly IDLE_RECOVERY_INTERVAL_SECONDS=30
readonly IDLE_RECOVERY_REQUIRED_SAMPLES=2
readonly MAX_PROCESS_TREE_PIDS=4096
readonly MAX_CGROUP_PROCS_BYTES=65536
readonly MAX_CGROUP_STAT_BYTES=65536
readonly MAX_PROC_STATUS_BYTES=1048576
readonly MAX_PROCESS_TREE_DIRECTORY_ROSTER_BYTES=1048576
readonly MAX_PROCESS_TREE_DIRECTORY_ENTRIES=65536
# Each PID is retained once in the authority roster and once in each of the
# two detailed passes. One KiB per retained row plus one MiB of fixed schema is
# deliberately generous while keeping validation work bounded.
readonly MAX_BOUND_CGROUP_V2_SNAPSHOT_FIXED_BYTES=1048576
readonly MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES_PER_PID=3072
readonly MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES="$((
  MAX_PROCESS_TREE_PIDS * MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES_PER_PID +
    MAX_BOUND_CGROUP_V2_SNAPSHOT_FIXED_BYTES
))"
readonly MAX_MANIFEST_BYTES=1048576
readonly MAX_BOUNDARY_SNAPSHOT_BYTES=65536
readonly MAX_MIDPOINT_RECEIPT_BYTES=65536
readonly MAX_MIDPOINT_PUBLICATION_MANIFEST_BYTES=65536
readonly MAX_RECOVERY_SCHEDULE_BYTES=65536
readonly MAX_POC_GATE_BYTES=8388608
readonly MAX_SERVICE_IDENTITY_BYTES=4096
readonly MAX_CELL_STATUS_BYTES=65536
readonly MAX_CELL_CONTRACT_BYTES=65536
readonly MAX_SUMMARY_BYTES=16777216
readonly MAX_VARIANCE_BYTES=1048576
readonly MAX_BPF_PROGRAM_RUNTIME_BYTES=1048576
readonly MAX_APPLICATION_SOURCE_IDENTITY_BYTES=1048576
readonly MAX_RUNNER_SOURCE_STATE_BYTES=65536
readonly MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES=16777216
readonly MAX_RUNNER_ENVIRONMENT_BYTES=1048576
readonly MAX_HOST_ENVIRONMENT_BYTES=1048576
readonly MAX_NATIVE_SOURCE_STATE_BYTES=1048576
readonly MAX_NATIVE_SOURCE_SNAPSHOT_BYTES=1048576
readonly MAX_NATIVE_BENCHMARK_BYTES=16777216
readonly MAX_LOOKUP_PATH_SUMMARY_BYTES=16777216
readonly MAX_PATH_OBSERVATION_BYTES=16777216
# Terminal source authority is a bounded descriptor-held snapshot. Complete
# Java evidence trees compact into independently reverified tree authorities,
# keeping the complete-mode descriptor roster below the audited 896-FD ceiling.
readonly MAX_TERMINAL_SOURCE_LEAVES=640
readonly MAX_TERMINAL_SOURCE_DIRECTORIES=128
readonly MAX_TERMINAL_SOURCE_TREES=8
readonly MAX_TERMINAL_SOURCE_CHECKOUTS=1
readonly MAX_TERMINAL_SOURCE_NEGATIVES=128
readonly MAX_TERMINAL_SOURCE_DIRECTORY_SELECTORS=128
readonly MAX_TERMINAL_SOURCE_RECORDS=4096
readonly MAX_TERMINAL_SOURCE_HELD_FDS=896
readonly MIN_TERMINAL_SOURCE_NOFILE_LIMIT=1024
readonly MAX_TERMINAL_SOURCE_RECORD_BYTES=4096
readonly MAX_TERMINAL_SOURCE_PATH_BYTES=1024
readonly MAX_TERMINAL_SOURCE_ROSTER_BYTES=4194304
readonly MAX_TERMINAL_SOURCE_LEAF_BYTES="$MAX_BENCHMARK_RESULT_BYTES"
readonly MAX_TERMINAL_JAVA_TREE_ENTRIES=128
readonly MAX_TERMINAL_JAVA_TREE_MANIFEST_BYTES=1048576
readonly MAX_TERMINAL_GIT_OUTPUT_BYTES="$MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES"
readonly MAX_TERMINAL_GIT_INDEX_ENTRIES=16384
readonly MAX_TERMINAL_GIT_WORKTREE_BYTES=268435456
readonly TERMINAL_PUBLICATION_DEADLINE_SECONDS=1800
readonly TERMINAL_PUBLICATION_COMMIT_DEADLINE_SECONDS=60
readonly MIDPOINT_TIMING_OVERRUN_SECONDS=2
readonly MILLISECONDS_PER_SECOND=1000
readonly DOCKER_QUERY_TIMEOUT_SECONDS=15
readonly DOCKER_STATS_TIMEOUT_SECONDS=20
readonly BENCHMARK_PROCESS_GROUP_GRACE_SECONDS=10
readonly RUNNER_START_TIMEOUT_SECONDS=1500
readonly RUNNER_CLEANUP_TIMEOUT_SECONDS=300
readonly POSTLOAD_SENTINEL_TIMEOUT_SECONDS=120
readonly JNI_BENCHMARK_TIMEOUT_SECONDS=180
readonly JNI_BENCHMARK_ITERATIONS=10000
readonly JAVA_TOOL_TIMEOUT_SECONDS=45
readonly JAVA_JFR_MAX_DURATION_SECONDS=3600
readonly JAVA_BENCHMARK_IMAGE_TARGET="benchmark-runtime"
readonly JAVA_DEFAULT_IMAGE_TAG="obi-apache-java-https-backend:local"
readonly JAVA_BENCHMARK_IMAGE_TAG="obi-apache-java-https-backend-benchmark:local"
readonly JAVA_BENCHMARK_TOOL_JAR="/otel/obi-benchmark-runtime-snapshot.jar"
readonly JAVA_BENCHMARK_TOOL_SOURCE="/otel/benchmark-source/RuntimeSnapshot.java"
readonly JAVA_BENCHMARK_JFR_SETTINGS="/otel/obi-benchmark.jfc"
readonly JAVA_BENCHMARK_TOOL_SOURCE_CHECKOUT="$EXAMPLE_DIR/java/benchmark/RuntimeSnapshot.java"
readonly JAVA_BENCHMARK_JFR_SETTINGS_CHECKOUT="$EXAMPLE_DIR/java/benchmark/obi-benchmark.jfc"
# The helper source is part of the runtime-attestation authority. Its digest is
# intentionally explicit so descriptor or cap semantics cannot drift silently.
readonly JAVA_BENCHMARK_TOOL_SOURCE_SHA256="d00f8d0460b51a075708c3005af19b012ff3391cfa8757b2b196d7538ac17dc9"
# This digest makes the payload-safe JFC settings an exact byte contract. A
# deliberate settings change must update both the file and this authority.
readonly JAVA_BENCHMARK_JFR_SETTINGS_SHA256="5c4a13587601f6d07b2b17af779399e4914bef227f003f225217c946fc1f0d9d"
readonly JAVA_JFR_RETENTION_SCOPE="bounded_tail_may_exclude_earliest_events_if_maximum_size_is_reached"
readonly JAVA_BOOTSTRAP_JFR_NAME="obi-benchmark-bootstrap"
readonly JAVA_BOOTSTRAP_JFR_CONTAINER_PATH="/tmp/obi-benchmark-bootstrap.jfr"
readonly JAVA_MEASUREMENT_JFR_NAME="obi-benchmark-measurement"
readonly JAVA_MEASUREMENT_JFR_CONTAINER_PATH="/tmp/obi-benchmark-measurement.jfr"
readonly JAVA_BENCHMARK_TOOL_ENV=(
  env -i HOME=/tmp LANG=C LC_ALL=C
  PATH=/opt/java/openjdk/bin:/usr/bin:/bin TZ=UTC
)
readonly MAX_PERFORMANCE_REGRESSION_PERCENT=10
readonly MAX_POPULATION_CV_PERCENT=10
readonly MAX_SAMPLED_ALLOCATION_REGRESSION_PERCENT=10
readonly MIN_SAMPLED_ALLOCATION_ALLOWANCE_BYTES_PER_REQUEST=1024
readonly CORE_CELLS=(uninstrumented bridge-disabled getsockopt-hit unix-hit getsockopt-w3c getsockopt-helper-idle)
readonly SAMPLED_ALLOCATION_COMPARISON_CELLS=(getsockopt-hit unix-hit getsockopt-w3c)
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
readonly JAVA_BRIDGE_CGROUP_SOCKOPT_PROGRAM_NAMES=(
  obi_java_remote_parent_setsockopt
  obi_java_remote_parent_getsockopt
  obi_java_remote_parent_getsockopt_direct_take
  obi_java_remote_parent_getsockopt_direct_discard
  obi_java_remote_parent_getsockopt_task_take
  obi_java_remote_parent_getsockopt_task_discard
  obi_java_remote_parent_getsockopt_health
)
readonly PRESSURE_REQUESTS=128
readonly PRESSURE_MAP_MAX_SUPPORTED_ENTRIES=50000
readonly PRESSURE_RECOVERY_REQUIRED_SAMPLES=2
readonly PRESSURE_ADMISSION_MAX_EVENTS_PER_REQUEST=9
readonly PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES=32768
readonly MAX_PRESSURE_JSON_BYTES=1048576
readonly MAX_PRESSURE_CONTROL_BYTES=256
readonly MAX_PRESSURE_LOG_BYTES=1048576
readonly PROC_CGROUP_CONTAINER_BINDING="full_container_id_at_non_hex_boundaries"

OUTPUT_DIR=""
OUTPUT_PARENT=""
OUTPUT_DIR_IDENTITY=""
AGENT="otel"
TLS_PROTOCOL="TLSv1.3"
WARMUP_SECONDS=10
DURATION_SECONDS=30
CONCURRENCY=16
REPETITIONS=5
SEED=20260721
CELLS_MODE="core"
PROCESS_TREE_FD_ABSOLUTE_MAX=""
PROCESS_TREE_TASK_ABSOLUTE_MAX=""
PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX=""
PROCESS_TREE_FD_RECOVERY_DELTA_MAX=""
PROCESS_TREE_TASK_RECOVERY_DELTA_MAX=""
PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX=""
RUN_TOKEN=""
SHOW_HELP=false
LOCK_FD=""
LOCK_HELD=false
OUTPUT_READY=false
JSON_SNAPSHOT_PERL_COMMAND="$(type -P perl 2>/dev/null || true)"
POC_GATE_HELD_VALUE=""
POC_GATE_HELD_SIZE=""
POC_GATE_HELD_SHA256=""
TERMINAL_PUBLICATION_STARTED=false
TERMINAL_SOURCE_SESSION_ACTIVE=false
TERMINAL_SOURCE_SESSION_FROZEN=false
TERMINAL_SOURCE_SESSION_PREPARED=false
TERMINAL_SOURCE_RECORD_FD=""
TERMINAL_SOURCE_RESPONSE_FD=""
TERMINAL_SOURCE_HELPER_PID=""
TERMINAL_SOURCE_OUTPUT_ROOT=""
TERMINAL_SOURCE_REPOSITORY_ROOT=""
TERMINAL_SOURCE_ROSTER_VALUE=""
# Internal hermetic-test seam. Production never changes the disabled value.
TERMINAL_NATIVE_SIGNAL_TEST_HOOK=none
ACTIVE_PROJECT=""
ACTIVE_CELL_DIR=""
BENCHMARK_PID=""
# A single assignment publishes the launch or dedicated-session identity, so
# an EXIT trap cannot observe a partially recorded identity.
BENCHMARK_IDENTITY=""
BENCHMARK_OUTPUT=""
BENCHMARK_DURATION_SECONDS=""
BENCHMARK_CELL_DIR=""
BENCHMARK_OUTPUT_PARENT_IDENTITY=""
BENCHMARK_CONFIRMED_WALL_EPOCH_SECONDS=""
BENCHMARK_CONFIRMED_MONOTONIC_MILLISECONDS=""
MIDPOINT_ACTIVE=false
MIDPOINT_CELL_DIR=""
MIDPOINT_PARTIAL=""
MIDPOINT_FINAL=""
MIDPOINT_PARENT_IDENTITY=""
MIDPOINT_PARTIAL_IDENTITY=""
MIDPOINT_PARENT_DIRECTORY_AUTHORITY=""
MIDPOINT_PARTIAL_DIRECTORY_AUTHORITY=""
MIDPOINT_REPETITION=""
MIDPOINT_DURATION_SECONDS=""
MIDPOINT_BENCHMARK_PID=""
MIDPOINT_BENCHMARK_IDENTITY=""
MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS=""
MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS=""
MIDPOINT_SLEEP_STARTED_WALL_EPOCH_SECONDS=""
MIDPOINT_SLEEP_STARTED_MONOTONIC_MILLISECONDS=""
MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS=""
MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS=""
MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS=""
MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS=""
MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS=""
MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS=""
JAVA_MEASUREMENT_PARTIAL=""
JAVA_MEASUREMENT_CELL_DIR=""
JAVA_MEASUREMENT_PARENT_IDENTITY=""
JAVA_MEASUREMENT_ROOT_IDENTITY=""
JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS=""
JAVA_MEASUREMENT_STARTED_AT=""
JAVA_MEASUREMENT_STOP_INITIATED_AT=""
JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256=""
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
NATIVE_BENCHMARK_PERL_COMMAND=""
NATIVE_BENCHMARK_READLINK_COMMAND=""
NATIVE_BENCHMARK_SHA256_COMMAND=""
NATIVE_BENCHMARK_TIMEOUT_COMMAND=""
TRUSTED_NATIVE_TOOL_RESULT=""
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
    '  --process-tree-fd-absolute-max N' \
    '                           Positive full-cgroup-tree FD ceiling.' \
    '  --process-tree-task-absolute-max N' \
    '                           Positive full-cgroup-tree task ceiling.' \
    '  --process-tree-rss-bytes-absolute-max N' \
    '                           Positive full-cgroup-tree RSS-byte ceiling.' \
    '  --process-tree-fd-recovery-delta-max N' \
    '                           Non-negative recovered FD growth allowance.' \
    '  --process-tree-task-recovery-delta-max N' \
    '                           Non-negative recovered task growth allowance.' \
    '  --process-tree-rss-bytes-recovery-delta-max N' \
    '                           Non-negative recovered RSS-byte growth allowance.' \
    '' \
    'Options:' \
    '  --agent NAME             otel or splunk. Default: otel' \
    '  --tls VERSION            TLSv1.2 or TLSv1.3. Default: TLSv1.3' \
    '  --warmup-seconds N       2-600. Default: 10' \
    '  --duration-seconds N     2-600. Default: 30' \
    '  --concurrency N          1-256. Default: 16' \
    '  --repetitions N          Exactly 5 (the predeclared PoC sample count). Default: 5' \
    '  --seed N                 0-9007199254740991. Default: 20260721' \
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

wall_clock_now_epoch_seconds() {
  local value=""

  value="$(date -u +%s)" || return 1
  normalize_decimal "$value" "$MAX_JSON_EXACT_INTEGER" false
}

# Linux /proc/uptime is a monotonic clock. Retain milliseconds rather than
# nanoseconds so long-lived hosts remain inside JSON's exact integer range.
# Tests override this function directly; production always reads fixed /proc.
monotonic_clock_now_milliseconds() {
  local uptime=""
  local idle=""
  local extra=""
  local seconds=""
  local fraction=""
  local padded_fraction=""

  [[ -f /proc/uptime && ! -L /proc/uptime ]] || return 1
  read -r uptime idle extra </proc/uptime || return 1
  [[ -z "$extra" && "$uptime" =~ ^[0-9]+\.[0-9]{1,9}$ &&
    "$idle" =~ ^[0-9]+\.[0-9]{1,9}$ ]] || return 1
  seconds="${uptime%%.*}"
  fraction="${uptime#*.}"
  seconds="$(normalize_decimal "$seconds" "$((MAX_JSON_EXACT_INTEGER / MILLISECONDS_PER_SECOND))" true)" || return 1
  padded_fraction="${fraction}000"
  padded_fraction="${padded_fraction:0:3}"
  printf '%s\n' "$((10#$seconds * MILLISECONDS_PER_SECOND + 10#$padded_fraction))"
}

clock_pair_values() {
  local wall=""
  local monotonic=""

  wall="$(wall_clock_now_epoch_seconds)" || return 1
  monotonic="$(monotonic_clock_now_milliseconds)" || return 1
  printf '%s %s\n' "$wall" "$monotonic"
}

validate_elapsed_clock_window() {
  local -r started_wall="$1"
  local -r started_monotonic="$2"
  local -r ended_wall="$3"
  local -r ended_monotonic="$4"
  local -r minimum_seconds="$5"
  local -r maximum_seconds="${6:-}"
  local minimum_milliseconds=0
  local maximum_milliseconds=0
  local wall_elapsed=0
  local monotonic_elapsed=0

  [[ "$started_wall" =~ ^(0|[1-9][0-9]*)$ &&
    "$started_monotonic" =~ ^(0|[1-9][0-9]*)$ &&
    "$ended_wall" =~ ^(0|[1-9][0-9]*)$ &&
    "$ended_monotonic" =~ ^(0|[1-9][0-9]*)$ &&
    "$minimum_seconds" =~ ^(0|[1-9][0-9]*)$ &&
    ( -z "$maximum_seconds" || "$maximum_seconds" =~ ^(0|[1-9][0-9]*)$ ) ]] || return 1
  ((ended_wall >= started_wall && ended_monotonic >= started_monotonic &&
    minimum_seconds <= MAX_JSON_EXACT_INTEGER / MILLISECONDS_PER_SECOND)) || return 1
  wall_elapsed="$((ended_wall - started_wall))"
  monotonic_elapsed="$((ended_monotonic - started_monotonic))"
  minimum_milliseconds="$((minimum_seconds * MILLISECONDS_PER_SECOND))"
  ((wall_elapsed >= minimum_seconds && monotonic_elapsed >= minimum_milliseconds)) || return 1
  if [[ -n "$maximum_seconds" ]]; then
    ((maximum_seconds >= minimum_seconds &&
      maximum_seconds <= MAX_JSON_EXACT_INTEGER / MILLISECONDS_PER_SECOND)) || return 1
    maximum_milliseconds="$((maximum_seconds * MILLISECONDS_PER_SECOND))"
    ((wall_elapsed <= maximum_seconds && monotonic_elapsed <= maximum_milliseconds)) || return 1
  fi
  printf '%s %s\n' "$wall_elapsed" "$monotonic_elapsed"
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

validate_docker_daemon_provenance_schema_json_value() {
  local -r artifact_value="$1"

  printf '%s' "$artifact_value" | jq -se '
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
  ' >/dev/null
}

validate_docker_daemon_provenance_schema() {
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$1" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  validate_docker_daemon_provenance_schema_json_value "$artifact_value"
}

validate_docker_daemon_provenance() {
  local -r artifact="$1"
  local -r output_name="${2:-}"
  local recorded_context=""
  local recorded_endpoint=""
  local recorded_override=""
  local recorded_socket_path=""
  local recorded_socket_device=""
  local recorded_socket_inode=""
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  validate_docker_daemon_provenance_schema_json_value "$artifact_value" || return 1
  # Terminal publication binds the retained endpoint evidence as a held source.
  # Re-querying Docker here would introduce mutable, non-roster authority into
  # the source-to-summary transaction; live locality was already verified when
  # this artifact was created and before container execution.
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    if [[ -n "$output_name" ]]; then
      printf -v "$output_name" '%s' "$artifact_value"
    fi
    return 0
  fi
  recorded_context="$(printf '%s' "$artifact_value" | jq -er '.active_context')" || return 1
  recorded_endpoint="$(printf '%s' "$artifact_value" | jq -er '.active_endpoint')" || return 1
  recorded_override="$(printf '%s' "$artifact_value" | \
    jq -er '.docker_context_environment')" || return 1
  recorded_socket_path="$(printf '%s' "$artifact_value" | jq -er '.socket_path')" || return 1
  recorded_socket_device="$(printf '%s' "$artifact_value" | jq -er '.socket_device')" || return 1
  recorded_socket_inode="$(printf '%s' "$artifact_value" | jq -er '.socket_inode')" || return 1
  resolve_docker_daemon_locality || return 1
  [[ "$DOCKER_ACTIVE_CONTEXT" == "$recorded_context" &&
    "$DOCKER_ACTIVE_ENDPOINT" == "$recorded_endpoint" &&
    "$DOCKER_ACTIVE_SOCKET_PATH" == "$recorded_socket_path" &&
    "$DOCKER_ACTIVE_SOCKET_DEVICE" == "$recorded_socket_device" &&
    "$DOCKER_ACTIVE_SOCKET_INODE" == "$recorded_socket_inode" ]] || return 1
  if [[ "$recorded_override" == unset ]]; then
    [[ -z "$DOCKER_CONTEXT_OVERRIDE" ]] || return 1
  else
    [[ "$DOCKER_CONTEXT_OVERRIDE" == "$recorded_override" ]] || return 1
  fi
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$artifact_value"
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

  TRUSTED_NATIVE_TOOL_RESULT=""
  [[ "$tool_name" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || return 1
  for candidate in /usr/bin/"$tool_name" /bin/"$tool_name"; do
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    canonical="$(
      POSIXLY_CORRECT=1
      [[ -o posix && -f /usr/bin/readlink && -x /usr/bin/readlink &&
        ! -L /usr/bin/readlink ]] || exit 1
      exec -c /usr/bin/readlink -f -- "$candidate"
    )" || return 1
    is_absolute_regular_executable "$canonical" || return 1
    TRUSTED_NATIVE_TOOL_RESULT="$canonical"
    return 0
  done
  return 1
}

resolve_benchmark_identity_tools() {
  resolve_trusted_native_tool env || return 1
  NATIVE_BENCHMARK_ENV_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  resolve_trusted_native_tool git || return 1
  NATIVE_BENCHMARK_GIT_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  resolve_trusted_native_tool perl || return 1
  NATIVE_BENCHMARK_PERL_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  resolve_trusted_native_tool readlink || return 1
  NATIVE_BENCHMARK_READLINK_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  resolve_trusted_native_tool sha256sum || return 1
  NATIVE_BENCHMARK_SHA256_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
}

resolve_native_benchmark_tools() {
  resolve_benchmark_identity_tools || return 1
  resolve_trusted_native_tool make || return 1
  NATIVE_BENCHMARK_MAKE_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  resolve_trusted_native_tool timeout || return 1
  NATIVE_BENCHMARK_TIMEOUT_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
}

run_native_clean_environment() (
  [[ -n "$NATIVE_BENCHMARK_ENV_COMMAND" ]] || resolve_benchmark_identity_tools || return 1
  # POSIX mode gives the special builtin exec precedence over imported or
  # same-shell functions named exec. Its -c option removes the parent
  # environment before the loader starts env(1); env -i then makes the
  # compiler, Make recipes, and native benchmark receive only the explicitly
  # declared locale and trusted executable path.
  POSIXLY_CORRECT=1
  [[ -o posix ]] || return 1
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
  elif resolve_trusted_native_tool "$configured_compiler" 2>/dev/null; then
    resolved_compiler="$TRUSTED_NATIVE_TOOL_RESULT"
  fi
  [[ -n "$resolved_compiler" ]] || {
    die "Makefile.jni compiler is unavailable: $configured_compiler"
    return $?
  }
  resolved_compiler="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "$resolved_compiler")" || return 1
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
  local process_tree_fd_absolute_max_seen=false
  local process_tree_task_absolute_max_seen=false
  local process_tree_rss_bytes_absolute_max_seen=false
  local process_tree_fd_recovery_delta_max_seen=false
  local process_tree_task_recovery_delta_max_seen=false
  local process_tree_rss_bytes_recovery_delta_max_seen=false

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
      --process-tree-fd-absolute-max)
        require_value "$1" "$#" || return $?
        [[ "$process_tree_fd_absolute_max_seen" == false ]] || {
          die "$1 may only be supplied once"
          return $?
        }
        value="$(normalize_decimal "$2" "$MAX_JSON_EXACT_INTEGER" false)" || {
          die "$1 must be a positive integer no greater than $MAX_JSON_EXACT_INTEGER"
          return $?
        }
        PROCESS_TREE_FD_ABSOLUTE_MAX="$value"
        process_tree_fd_absolute_max_seen=true
        shift 2
        ;;
      --process-tree-task-absolute-max)
        require_value "$1" "$#" || return $?
        [[ "$process_tree_task_absolute_max_seen" == false ]] || {
          die "$1 may only be supplied once"
          return $?
        }
        value="$(normalize_decimal "$2" "$MAX_JSON_EXACT_INTEGER" false)" || {
          die "$1 must be a positive integer no greater than $MAX_JSON_EXACT_INTEGER"
          return $?
        }
        PROCESS_TREE_TASK_ABSOLUTE_MAX="$value"
        process_tree_task_absolute_max_seen=true
        shift 2
        ;;
      --process-tree-rss-bytes-absolute-max)
        require_value "$1" "$#" || return $?
        [[ "$process_tree_rss_bytes_absolute_max_seen" == false ]] || {
          die "$1 may only be supplied once"
          return $?
        }
        value="$(normalize_decimal "$2" "$MAX_JSON_EXACT_INTEGER" false)" || {
          die "$1 must be a positive integer no greater than $MAX_JSON_EXACT_INTEGER"
          return $?
        }
        PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX="$value"
        process_tree_rss_bytes_absolute_max_seen=true
        shift 2
        ;;
      --process-tree-fd-recovery-delta-max)
        require_value "$1" "$#" || return $?
        [[ "$process_tree_fd_recovery_delta_max_seen" == false ]] || {
          die "$1 may only be supplied once"
          return $?
        }
        value="$(normalize_decimal "$2" "$MAX_JSON_EXACT_INTEGER" true)" || {
          die "$1 must be a non-negative integer no greater than $MAX_JSON_EXACT_INTEGER"
          return $?
        }
        PROCESS_TREE_FD_RECOVERY_DELTA_MAX="$value"
        process_tree_fd_recovery_delta_max_seen=true
        shift 2
        ;;
      --process-tree-task-recovery-delta-max)
        require_value "$1" "$#" || return $?
        [[ "$process_tree_task_recovery_delta_max_seen" == false ]] || {
          die "$1 may only be supplied once"
          return $?
        }
        value="$(normalize_decimal "$2" "$MAX_JSON_EXACT_INTEGER" true)" || {
          die "$1 must be a non-negative integer no greater than $MAX_JSON_EXACT_INTEGER"
          return $?
        }
        PROCESS_TREE_TASK_RECOVERY_DELTA_MAX="$value"
        process_tree_task_recovery_delta_max_seen=true
        shift 2
        ;;
      --process-tree-rss-bytes-recovery-delta-max)
        require_value "$1" "$#" || return $?
        [[ "$process_tree_rss_bytes_recovery_delta_max_seen" == false ]] || {
          die "$1 may only be supplied once"
          return $?
        }
        value="$(normalize_decimal "$2" "$MAX_JSON_EXACT_INTEGER" true)" || {
          die "$1 must be a non-negative integer no greater than $MAX_JSON_EXACT_INTEGER"
          return $?
        }
        PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX="$value"
        process_tree_rss_bytes_recovery_delta_max_seen=true
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
          die "$1 must be a non-negative integer no greater than $MAX_SEED"
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
  [[ "$process_tree_fd_absolute_max_seen" == true ]] || {
    die "--process-tree-fd-absolute-max is required"
    return $?
  }
  [[ "$process_tree_task_absolute_max_seen" == true ]] || {
    die "--process-tree-task-absolute-max is required"
    return $?
  }
  [[ "$process_tree_rss_bytes_absolute_max_seen" == true ]] || {
    die "--process-tree-rss-bytes-absolute-max is required"
    return $?
  }
  [[ "$process_tree_fd_recovery_delta_max_seen" == true ]] || {
    die "--process-tree-fd-recovery-delta-max is required"
    return $?
  }
  [[ "$process_tree_task_recovery_delta_max_seen" == true ]] || {
    die "--process-tree-task-recovery-delta-max is required"
    return $?
  }
  [[ "$process_tree_rss_bytes_recovery_delta_max_seen" == true ]] || {
    die "--process-tree-rss-bytes-recovery-delta-max is required"
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
  OUTPUT_DIR_IDENTITY="$(stat --format '%d:%i:%u:%g:%a' -- "$OUTPUT_DIR")" || return $?
  [[ "$OUTPUT_DIR_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+:700$ ]] || {
    die "could not bind the private output directory identity"
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
  for command_name in awk chmod cmp curl date docker env find flock git grep head id install jq mkdir mktemp mv openssl perl readlink rm setsid sha256sum sort stat timeout tr uname wc; do
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
  JSON_SNAPSHOT_PERL_COMMAND="$(type -P perl 2>/dev/null || true)"
  [[ "$JSON_SNAPSHOT_PERL_COMMAND" == /* && -f "$JSON_SNAPSHOT_PERL_COMMAND" &&
    -x "$JSON_SNAPSHOT_PERL_COMMAND" ]] || {
    die "Perl is required for immutable JSON capture and publication"
    return $?
  }
  "$JSON_SNAPSHOT_PERL_COMMAND" -MFcntl -MDigest::SHA -e '
    require "syscall.ph";
    defined(&Fcntl::O_NOFOLLOW) && defined(&Fcntl::O_DIRECTORY) &&
      defined(&SYS_openat) && defined(&SYS_linkat) or exit 1;
  ' || {
    die "Perl O_NOFOLLOW, O_TMPFILE, openat, and linkat support is required"
    return $?
  }
  is_absolute_regular_executable "$NATIVE_BENCHMARK_PERL_COMMAND" || {
    die "a trusted absolute Perl interpreter is required for midpoint publication"
    return $?
  }
  run_native_clean_environment "$NATIVE_BENCHMARK_PERL_COMMAND" -T \
    -MFcntl -MDigest::SHA -MJSON::PP -e '
      require "syscall.ph";
      defined(&Fcntl::O_NOFOLLOW) && defined(&Fcntl::O_DIRECTORY) &&
        defined(&SYS_openat) && defined(&SYS_getdents64) &&
        defined(&SYS_renameat2) or exit 1;
    ' || {
    die "isolated Perl openat and renameat2 support is required for midpoint publication"
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
  if [[ "$CELL_BOUNDED_PATH" == "true" ]]; then
    JAVA_IMAGE_TARGET="runtime"
    JAVA_BACKEND_IMAGE="$JAVA_DEFAULT_IMAGE_TAG"
    JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX=""
  else
    JAVA_IMAGE_TARGET="$JAVA_BENCHMARK_IMAGE_TARGET"
    JAVA_BACKEND_IMAGE="$JAVA_BENCHMARK_IMAGE_TAG"
    JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX=" -XX:NativeMemoryTracking=summary -XX:StartFlightRecording=name=${JAVA_BOOTSTRAP_JFR_NAME},settings=${JAVA_BENCHMARK_JFR_SETTINGS},filename=${JAVA_BOOTSTRAP_JFR_CONTAINER_PATH},disk=true,dumponexit=false,duration=${JAVA_JFR_MAX_DURATION_SECONDS}s,maxsize=32m"
  fi
  export JAVA_IMAGE_TARGET JAVA_BACKEND_IMAGE JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX
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

manifest_json() {
  local -r manifest_status="$1"
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
    --arg manifest_status "$manifest_status" \
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
    --argjson maximum_population_cv_percent "$MAX_POPULATION_CV_PERCENT" \
    --argjson maximum_sampled_allocation_regression_percent \
      "$MAX_SAMPLED_ALLOCATION_REGRESSION_PERCENT" \
    --argjson minimum_sampled_allocation_allowance_bytes_per_request \
      "$MIN_SAMPLED_ALLOCATION_ALLOWANCE_BYTES_PER_REQUEST" \
    --argjson process_tree_fd_absolute_max "$PROCESS_TREE_FD_ABSOLUTE_MAX" \
    --argjson process_tree_task_absolute_max "$PROCESS_TREE_TASK_ABSOLUTE_MAX" \
    --argjson process_tree_rss_bytes_absolute_max "$PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX" \
    --argjson process_tree_fd_recovery_delta_max "$PROCESS_TREE_FD_RECOVERY_DELTA_MAX" \
    --argjson process_tree_task_recovery_delta_max "$PROCESS_TREE_TASK_RECOVERY_DELTA_MAX" \
    --argjson process_tree_rss_bytes_recovery_delta_max \
      "$PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX" \
    --argjson w3c_discard_cells "$w3c_discard_cells_json" \
    --argjson w3c_headers_by_cell "$w3c_headers_by_cell_json" \
    --argjson workload_by_cell "$workload_by_cell_json" \
    --argjson total_worker_seconds "$((
      (WARMUP_SECONDS + (REPETITIONS * DURATION_SECONDS)) * CONCURRENCY * ${#CORE_CELLS[@]}
    ))" \
    '{
      schema_version: 4,
      status: $manifest_status,
      started_at: $started_at,
      invocation: $invocation,
      docker_endpoint_evidence: "docker-daemon.json",
      container_process_binding_evidence:
        "cells/*/{resources-before,cpu-measurement-baseline,measurements/rep-*-midpoint,cpu-measurement-end,resources-after-load,resources-idle-recovery-01,resources-idle-recovery-02}/*-cgroup-v2.json",
      obi_bpf_fd_ownership_evidence:
        "cells/*/resources-{before,idle-recovery}/obi-bpf-fd-ownership.txt",
      measurement_boundary_resource_evidence:
        "cells/*/cpu-measurement-{baseline,end}/snapshot.json",
      program_metrics_diagnostic_evidence:
        "cells/*/program-metrics-{baseline,end}/snapshot.json",
      process_tree_resource_evidence: {
        artifacts: "cells/*/{resources-before,cpu-measurement-baseline,measurements/rep-*-midpoint,cpu-measurement-end,resources-after-load,resources-idle-recovery-01,resources-idle-recovery-02}/*-cgroup-v2.json",
        services: ["obi", "java-backend"],
        scope: "complete_leaf_cgroup_v2_process_tree",
        sampling: "stable_two_pass_roster_and_conservative_resource_envelope",
        recovery_schedule: "cells/*/recovery-schedule.json"
      },
      dedicated_application_cpu_evidence: {
        artifacts: "cells/*/cpu-measurement-{baseline,end}/*-cgroup-v2.json",
        baseline_cell: "bridge-disabled",
        comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
        dimensions: ["obi", "java_backend", "combined"],
        metric: "cgroup_v2_cpu_stat_usage_usec_per_successful_request",
        maximum_regression_percent: 10,
        arithmetic: "exact_unsigned_decimal_cross_multiplication",
        primary_cgroupsockopt_program_cpu: "not_collected"
      },
      exact_owned_cgroup_sockopt_program_evidence: {
        artifact: "cells/*/bpf-program-runtime.json",
        metrics: "cells/*/program-metrics-{baseline,end}/obi-metrics.prom",
        ownership_receipts:
          "cells/*/program-metrics-{baseline,end}/obi-bpf-fd-ownership.txt",
        collection_fences:
          "cells/*/program-metrics-{baseline,end}/obi-metrics-fence.json",
        selected_getsockopt_cells: [
          "getsockopt-hit", "getsockopt-w3c", "getsockopt-helper-idle"
        ],
        metric: "kernel_reported_program_execution_count_and_cumulative_run_time_deltas",
        acceptance_evidence: false
      },
      java_runtime_indicator_evidence: {
        artifact: "cells/*/java-measurement/evidence.json",
        private_raw_jfr: "retained_bounded_diagnostic_input",
        selected_cells: $cells,
        measurement_window:
          "post_warmup_baseline_to_stop_initiated_immediately_after_final_load",
        indicators: [
          "jfr_sampled_allocation_weight", "jfr_monitor_enter_duration",
          "jfr_thread_park_duration", "nmt_reserved_and_committed",
          "direct_buffer_pool"
        ],
        normalized_receipt:
          "low_cardinality_counts_deltas_and_digests_without_payload_fields",
        sampled_allocation_gate: {
          artifact: "poc-gates.json",
          baseline_cell: "bridge-disabled",
          comparison_cells: [
            "getsockopt-hit", "unix-hit", "getsockopt-w3c"
          ],
          metric: "sampled_allocation_weight_bytes_per_successful_request",
          maximum_regression_percent:
            $maximum_sampled_allocation_regression_percent,
          minimum_allowance_bytes_per_successful_request:
            $minimum_sampled_allocation_allowance_bytes_per_request,
          classification: "exploratory_sampled_indicator_not_exact_allocation",
          acceptance_evidence: false
        },
        acceptance_evidence: false
      },
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
          variance_summary: "variance.json",
          population_variability: {
            formula: "sqrt(sum((x-mean)^2)/N)/mean*100",
            divisor: "population_N",
            metrics: ["throughput_per_second", "p99_latency_nanos"],
            required_cells: $cells,
            maximum_cv_percent: $maximum_population_cv_percent
          }
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
          p99_latency_regression_max_percent: 10,
          population_cv_max_percent: $maximum_population_cv_percent
        },
        sampled_jfr_allocation: {
          baseline_cell: "bridge-disabled",
          comparison_cells: [
            "getsockopt-hit", "unix-hit", "getsockopt-w3c"
          ],
          metric: "sampled_allocation_weight_bytes_per_successful_request",
          regression_allowance:
            "max(baseline_bytes_per_successful_request*percent/100,minimum_bytes_per_successful_request)",
          maximum_regression_percent:
            $maximum_sampled_allocation_regression_percent,
          minimum_allowance_bytes_per_successful_request:
            $minimum_sampled_allocation_allowance_bytes_per_request,
          classification: "exploratory_sampled_indicator_not_exact_allocation",
          exact_allocation: false,
          acceptance_evidence: false
        },
        bounded_growth: {
          fd_delta_max: 0,
          thread_delta_max: 0,
          java_bridge_map_entries_delta_max: 0,
          samples: ["before", "idle_recovery_02"],
          unavailable_samples_fail_closed: true,
          process_tree: {
            services: ["obi", "java-backend"],
            absolute_caps: {
              fd_count: $process_tree_fd_absolute_max,
              task_count: $process_tree_task_absolute_max,
              rss_bytes: $process_tree_rss_bytes_absolute_max
            },
            recovery_delta_caps: {
              fd_count: $process_tree_fd_recovery_delta_max,
              task_count: $process_tree_task_recovery_delta_max,
              rss_bytes: $process_tree_rss_bytes_recovery_delta_max
            },
            boundaries: [
              "before", "cpu_measurement_baseline", "rep_01_midpoint",
              "rep_02_midpoint", "rep_03_midpoint", "rep_04_midpoint",
              "rep_05_midpoint", "cpu_measurement_end", "after_load",
              "idle_recovery_01", "idle_recovery_02"
            ],
            recovery: {interval_seconds: 30, required_consecutive_samples: 2},
            unavailable_samples_fail_closed: true
          },
          cpu_per_successful_request: {
            baseline_cell: "bridge-disabled",
            comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
            excluded_cells: {
              uninstrumented: "no_official_agent",
              getsockopt_helper_idle:
                "direct_java_workload_is_not_comparable_to_the_apache_baseline"
            },
            dimensions: ["obi", "java_backend", "combined"],
            maximum_regression_percent: 10,
            formula:
              "candidate_cpu_usage_usec/candidate_successes <= baseline_cpu_usage_usec/baseline_successes * 1.10"
          },
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
        jfr_nmt_allocation_native_direct_memory: "bounded_indicators_requested",
        primary_cgroupsockopt_program_cpu: "not_collected",
        bpf_map_insert_failures: (if $complete_requested then "capacity_rejection_only" else "not_collected" end),
        bpf_map_evictions: (if $complete_requested then "not_applicable_non_evicting_hash_pressure" else "not_collected" end),
        bpf_lock_contention: "not_collected",
        application_cpu_rss_fd_threads:
          "cgroup_v2_process_tree_cpu_rss_fd_task_gates_requested",
        java_allocations:
          "exploratory_sampled_regression_gate_requested_exact_allocation_not_collected",
        java_native_memory:
          "nmt_summary_indicator_requested_not_evaluated_as_acceptance_gate",
        java_direct_memory:
          "direct_buffer_pool_indicator_requested_not_evaluated_as_acceptance_gate"
      }
    }'
}

validate_manifest_json_value() {
  local -r manifest_value="$1"
  local status=""
  local expected=""
  local expected_canonical=""

  status="$(printf '%s' "$manifest_value" | jq -er '
    if (.status == "in_progress" or .status == "passed" or .status == "failed")
    then .status else empty end
  ')" || return 1
  expected="$(manifest_json "$status")" || return 1
  expected_canonical="$(printf '%s' "$expected" | jq -ceS .)" || return 1
  printf '%s\n%s' "$manifest_value" "$expected_canonical" | jq -se '
    length == 2 and .[0] == .[1]
  ' >/dev/null
}

validated_manifest_json_image() {
  local -r artifact="$1"
  local -r value_output_name="$2"
  local -r identity_output_name="${3:-}"
  local -r size_output_name="${4:-}"
  local -r digest_output_name="${5:-}"
  local captured_manifest_value=""
  local captured_manifest_identity=""
  local captured_manifest_size=""
  local captured_manifest_digest=""

  bounded_duplicate_free_json_image "$artifact" "$MAX_MANIFEST_BYTES" \
    captured_manifest_value captured_manifest_identity captured_manifest_size \
    captured_manifest_digest || return 1
  validate_manifest_json_value "$captured_manifest_value" || return 1
  printf -v "$value_output_name" '%s' "$captured_manifest_value"
  if [[ -n "$identity_output_name" ]]; then
    printf -v "$identity_output_name" '%s' "$captured_manifest_identity"
  fi
  if [[ -n "$size_output_name" ]]; then
    printf -v "$size_output_name" '%s' "$captured_manifest_size"
  fi
  if [[ -n "$digest_output_name" ]]; then
    printf -v "$digest_output_name" '%s' "$captured_manifest_digest"
  fi
}

validated_manifest_json_value() {
  local -r artifact="$1"
  local held_manifest_value=""

  validated_manifest_json_image "$artifact" held_manifest_value || return 1
  printf '%s' "$held_manifest_value"
}

validate_manifest_schema() {
  local -r artifact="$1"
  local held_manifest_value=""

  validated_manifest_json_image "$artifact" held_manifest_value
}

write_manifest() {
  local -r output="$OUTPUT_DIR/manifest.in-progress.json"
  local manifest_value=""

  [[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  if [[ -z "$OUTPUT_DIR_IDENTITY" ]]; then
    OUTPUT_DIR_IDENTITY="$(stat --format '%d:%i:%u:%g:%a' -- \
      "$OUTPUT_DIR")" || return 1
  fi
  manifest_value="$(manifest_json in_progress)" || return 1
  manifest_value="$(printf '%s' "$manifest_value" | jq -ceS .)" || return 1
  validate_manifest_json_value "$manifest_value" || return 1
  publish_exact_json_value "$output" "$manifest_value" "$MAX_MANIFEST_BYTES" || return 1
  validate_manifest_schema "$output"
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
  local snapshot_value=""

  snapshot_value="$(bounded_duplicate_free_json_value \
    "$snapshot" "$MAX_NATIVE_SOURCE_SNAPSHOT_BYTES")" || return 1
  validate_native_source_snapshot_json_value "$snapshot_value"
}

validate_native_source_snapshot_json_value() {
  local -r snapshot_value="$1"
  local observed_identity=""
  local recorded_identity=""

  printf '%s' "$snapshot_value" | jq -se --argjson expected_paths "$(printf '%s\n' \
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
  ' >/dev/null || return 1
  observed_identity="$(printf '%s' "$snapshot_value" | jq -cS '{revision, paths}' |
    run_native_clean_environment "$NATIVE_BENCHMARK_SHA256_COMMAND")" || return 1
  observed_identity="${observed_identity%% *}"
  recorded_identity="$(printf '%s' "$snapshot_value" | \
    jq -er '.content_identity')" || return 1
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
  local state_value=""
  local before_value=""
  local after_value=""

  state_value="$(bounded_duplicate_free_json_value \
    "$state" "$MAX_NATIVE_SOURCE_STATE_BYTES")" || return 1
  before_link="$(printf '%s' "$state_value" | jq -er '.captures.before')" || return 1
  after_link="$(printf '%s' "$state_value" | jq -er '.captures.after')" || return 1
  [[ "$before_link" == source-state-before.json &&
    "$after_link" == source-state-after.json ]] || return 1
  before_value="$(bounded_duplicate_free_json_value \
    "$state_directory/$before_link" "$MAX_NATIVE_SOURCE_SNAPSHOT_BYTES")" || return 1
  after_value="$(bounded_duplicate_free_json_value \
    "$state_directory/$after_link" "$MAX_NATIVE_SOURCE_SNAPSHOT_BYTES")" || return 1
  validate_native_source_state_json_values \
    "$state_value" "$before_value" "$after_value"
}

validate_native_source_state_json_values() {
  local -r state_value="$1"
  local -r before_value="$2"
  local -r after_value="$3"

  validate_native_source_snapshot_json_value "$before_value" || return 1
  validate_native_source_snapshot_json_value "$after_value" || return 1
  printf '%s' "$state_value" | jq -se --argjson expected_paths "$(printf '%s\n' \
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
  ' >/dev/null || return 1
  printf '%s\n%s\n%s' "$state_value" "$before_value" "$after_value" | jq -es '
    length == 3 and
    .[0].revision == .[1].revision and .[0].revision == .[2].revision and
    .[0].paths == .[1].paths and .[0].paths == .[2].paths and
    .[0].content_identity == .[1].content_identity and
    .[0].content_identity == .[2].content_identity
  ' >/dev/null
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
  local -r output_name="${2:-}"
  local artifact_directory=""
  local artifact_root=""
  local compiler_path=""
  local compiler_sha256=""
  local binary_sha256=""
  local link=""
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_NATIVE_BENCHMARK_BYTES")" || return 1
  printf '%s' "$artifact_value" | jq -se \
    --argjson iterations "$JNI_BENCHMARK_ITERATIONS" '
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
  ' >/dev/null || return 1
  artifact_directory="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  artifact_root="$(cd -- "$artifact_directory/.." && pwd -P)" || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    validate_native_jni_benchmark_terminal_values \
      "$artifact_value" "$artifact_directory" "$artifact_root" || return 1
    if [[ -n "$output_name" ]]; then
      printf -v "$output_name" '%s' "$artifact_value"
    fi
    return 0
  fi
  resolve_native_benchmark_tools || return 1
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
  grep -Eq -- '^\( POSIXLY_CORRECT=1; \[\[ -o posix \]\] \|\| exit 1; exec -c .*env -i .*PATH=/usr/bin:/bin LC_ALL=C .*timeout .*make .* \)$' \
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
  validate_native_raw_reconciliation "$artifact" || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$artifact_value"
  fi
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

normalize_native_jni_benchmark_values() {
  local -r raw_output_value="$1"
  local -r binary_sha256="$2"
  local -r source_revision="$3"
  local -r header_image="$4"
  local -r compiler_value="$5"
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

  [[ -n "$raw_output_value" && "$binary_sha256" =~ ^[0-9a-f]{64}$ &&
    "$source_revision" =~ ^[0-9a-f]{40}$ &&
    "$header_image" =~ ^maven:[^@]+@sha256:[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$compiler_value" | jq -se 'length == 1' >/dev/null || return 1
  mapfile -t lines < <(printf '%s' "$raw_output_value") || return 1
  [[ ${#lines[@]} == 7 &&
    "${lines[0]}" == \
      "benchmark=obi_java_remote_parent_native getsockopt_backend=deterministic_syscall_shim" ]] || return 1
  for ((index = 0; index < ${#expected_series[@]}; index++)); do
    IFS=: read -r expected_transport expected_outcome expected_status \
      <<<"${expected_series[$index]}" || return 1
    read -r transport_field outcome_field warmup_field iterations_field \
      elapsed_field nanos_per_operation_field p50_field p95_field p99_field \
      operations_per_second_field status_field checksum_field extra \
      <<<"${lines[$((index + 1))]}" || return 1
    [[ -z "$extra" &&
      "$transport_field" == "transport=$expected_transport" &&
      "$outcome_field" == "outcome=$expected_outcome" &&
      "$warmup_field" == warmup_iterations=* &&
      "$iterations_field" == iterations=* && "$elapsed_field" == elapsed_ns=* &&
      "$nanos_per_operation_field" == ns_per_op=* &&
      "$p50_field" == p50_ns=* && "$p95_field" == p95_ns=* &&
      "$p99_field" == p99_ns=* &&
      "$operations_per_second_field" == ops_per_second=* &&
      "$status_field" == status=* && "$checksum_field" == checksum=* ]] || return 1
    warmup="$(normalize_decimal \
      "${warmup_field#*=}" "$JNI_BENCHMARK_ITERATIONS" true)" || return 1
    iterations="$(normalize_decimal \
      "${iterations_field#*=}" "$JNI_BENCHMARK_ITERATIONS" false)" || return 1
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
      --arg transport "$expected_transport" --arg outcome "$expected_outcome" \
      --argjson warmup "$warmup" --argjson iterations "$iterations" \
      --argjson elapsed "$elapsed" \
      --argjson nanos_per_operation "$nanos_per_operation" \
      --argjson p50 "$p50" --argjson p95 "$p95" --argjson p99 "$p99" \
      --argjson operations_per_second "$operations_per_second" \
      --argjson status "$status" --argjson checksum "$checksum" '
        {
          transport: $transport, outcome: $outcome,
          warmup_iterations: $warmup, iterations: $iterations,
          elapsed_nanos: $elapsed, nanos_per_operation: $nanos_per_operation,
          latency_p50_nanos: $p50, latency_p95_nanos: $p95,
          latency_p99_nanos: $p99, operations_per_second: $operations_per_second,
          status_code: $status, checksum: $checksum
        }
      ')" || return 1
    rows+=("$row_json")
  done
  rows_json="$(printf '%s\n' "${rows[@]}" | jq -cs '.')" || return 1
  printf '%s\n%s' "$rows_json" "$compiler_value" | jq -cs \
    --arg source_revision "$source_revision" \
    --arg binary_sha256 "$binary_sha256" --arg header_image "$header_image" \
    --argjson iterations "$JNI_BENCHMARK_ITERATIONS" '
      if length != 2 then error("expected native rows and compiler evidence")
      else . end |
      .[0] as $rows | .[1] as $compiler |
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
          compiler: $compiler,
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
    '
}

validate_native_jni_benchmark_terminal_values() {
  local -r artifact_value="$1"
  local -r artifact_directory="$2"
  local -r artifact_root="$3"
  local source_revision=""
  local compiler_path=""
  local binary_sha256=""
  local header_image=""
  local raw_value=""
  # shellcheck disable=SC2034 # Filled by the terminal held-value capture seam.
  local raw_stderr_value=""
  local compiler_value=""
  local compiler_version_value=""
  local build_command_value=""
  local expanded_build_command_value=""
  local java_version_value=""
  local jdk_image_value=""
  local source_state_value=""
  local source_before_value=""
  local source_after_value=""
  local host_environment_value=""
  local observed_binary_sha256=""
  local expected_value=""
  local raw_stderr="$artifact_directory/raw.stderr.log"
  local raw_stderr_size=""

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false &&
    "$artifact_directory" == /* && "$artifact_root" == /* ]] || return 1
  source_revision="$(printf '%s' "$artifact_value" | \
    jq -er '.provenance.source_revision')" || return 1
  compiler_path="$(printf '%s' "$artifact_value" | \
    jq -er '.provenance.compiler.canonical_path')" || return 1
  binary_sha256="$(printf '%s' "$artifact_value" | \
    jq -er '.provenance.binary_sha256')" || return 1
  header_image="$(printf '%s' "$artifact_value" | \
    jq -er '.provenance.jdk_header_image')" || return 1
  capture_bounded_regular_file_value "$artifact_directory/raw.txt" \
    "$MAX_NATIVE_BENCHMARK_BYTES" raw_value || return 1
  if [[ -f "$raw_stderr" && ! -L "$raw_stderr" ]]; then
    raw_stderr_size="$(stat --format '%s' -- "$raw_stderr")" || return 1
    [[ "$raw_stderr_size" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    if ((raw_stderr_size == 0)); then
      terminal_record_source_negative \
        "$raw_stderr" "$MAX_NATIVE_BENCHMARK_BYTES" empty || return 1
    else
      capture_bounded_regular_file_value "$raw_stderr" \
        "$MAX_NATIVE_BENCHMARK_BYTES" raw_stderr_value || return 1
    fi
  else
    return 1
  fi
  compiler_value="$(bounded_duplicate_free_json_value \
    "$artifact_directory/compiler-provenance.json" \
    "$MAX_NATIVE_BENCHMARK_BYTES")" || return 1
  capture_bounded_regular_file_value "$artifact_directory/compiler-version.txt" \
    "$MAX_NATIVE_BENCHMARK_BYTES" compiler_version_value || return 1
  capture_bounded_regular_file_value "$artifact_directory/build-command.txt" \
    "$MAX_NATIVE_BENCHMARK_BYTES" build_command_value || return 1
  capture_bounded_regular_file_value \
    "$artifact_directory/expanded-build-command.txt" \
    "$MAX_NATIVE_BENCHMARK_BYTES" expanded_build_command_value || return 1
  capture_bounded_regular_file_value "$artifact_directory/java-version.txt" \
    "$MAX_NATIVE_BENCHMARK_BYTES" java_version_value || return 1
  jdk_image_value="$(bounded_duplicate_free_json_value \
    "$artifact_directory/jdk-image.json" "$MAX_NATIVE_BENCHMARK_BYTES")" || return 1
  source_state_value="$(bounded_duplicate_free_json_value \
    "$artifact_directory/source-state.json" \
    "$MAX_NATIVE_SOURCE_STATE_BYTES")" || return 1
  source_before_value="$(bounded_duplicate_free_json_value \
    "$artifact_directory/source-state-before.json" \
    "$MAX_NATIVE_SOURCE_SNAPSHOT_BYTES")" || return 1
  source_after_value="$(bounded_duplicate_free_json_value \
    "$artifact_directory/source-state-after.json" \
    "$MAX_NATIVE_SOURCE_SNAPSHOT_BYTES")" || return 1
  capture_bounded_regular_file_value "$artifact_root/host-environment.txt" \
    "$MAX_HOST_ENVIRONMENT_BYTES" host_environment_value || return 1
  [[ -n "$compiler_version_value" && -n "$java_version_value" &&
    "$(printf '%s' "$build_command_value" | awk 'END { print NR }')" == 1 ]] || return 1
  grep -Eq -- \
    '^\( POSIXLY_CORRECT=1; \[\[ -o posix \]\] \|\| exit 1; exec -c .*env -i .*PATH=/usr/bin:/bin LC_ALL=C .*timeout .*make .* \)$' \
    <<<"$build_command_value" || return 1
  validate_native_expanded_build_command_value \
    "$expanded_build_command_value" "$compiler_path" || return 1
  printf '%s' "$jdk_image_value" | jq -se 'length == 1' >/dev/null || return 1
  printf '%s\n%s' "$artifact_value" "$compiler_value" | jq -es '
    length == 2 and .[0].provenance.compiler == .[1]
  ' >/dev/null || return 1
  validate_native_source_state_json_values "$source_state_value" \
    "$source_before_value" "$source_after_value" || return 1
  [[ "$(printf '%s' "$source_state_value" | jq -er '.revision')" == \
      "$source_revision" &&
    "$(printf '%s' "$host_environment_value" | awk -F= '
      $1 == "git_revision" { matches++; value = $2 }
      END { if (matches != 1) exit 1; print value }
    ')" == "$source_revision" ]] || return 1
  sha256_regular_file "$artifact_directory/build/remote_parent_jni_benchmark" \
    observed_binary_sha256 || return 1
  [[ "$observed_binary_sha256" == "$binary_sha256" ]] || return 1
  expected_value="$(normalize_native_jni_benchmark_values "$raw_value" \
    "$binary_sha256" "$source_revision" "$header_image" \
    "$compiler_value")" || return 1
  printf '%s\n%s' "$expected_value" "$artifact_value" | jq -es '
    length == 2 and .[1] == .[0]
  ' >/dev/null
}

validate_native_raw_reconciliation() (
  local -r artifact="$1"
  local artifact_directory=""
  local expected_json=""

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
  local expanded_command_value=""

  capture_bounded_regular_file_value "$expanded_command" \
    "$MAX_NATIVE_BENCHMARK_BYTES" expanded_command_value || return 1
  validate_native_expanded_build_command_value \
    "$expanded_command_value" "$compiler"
}

validate_native_expanded_build_command_value() {
  local -r expanded_command_value="$1"
  local -r compiler="$2"
  local flag=""

  [[ -n "$expanded_command_value" && "$compiler" == /* ]] || return 1
  printf '%s' "$expanded_command_value" | awk -v prefix="$compiler " '
    index($0, prefix) == 1 { matches++ }
    END { exit matches == 1 ? 0 : 1 }
  ' || return 1
  grep -Fq -- 'src/main/c/io_opentelemetry_obi_java_jni.c' \
    <<<"$expanded_command_value" || return 1
  grep -Fq -- 'src/test/c/remote_parent_jni_benchmark.c' \
    <<<"$expanded_command_value" || return 1
  grep -Fq -- 'remote_parent_jni_benchmark' \
    <<<"$expanded_command_value" || return 1
  for flag in "${NATIVE_BENCHMARK_COMPILE_FLAGS[@]}" \
    "${NATIVE_BENCHMARK_LINK_FLAGS[@]}"; do
    grep -Fq -- "$flag" <<<"$expanded_command_value" || return 1
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
    printf '( POSIXLY_CORRECT=1; [[ -o posix ]] || exit 1; exec -c'
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

  [[ -n "$NATIVE_BENCHMARK_READLINK_COMMAND" ]] ||
    resolve_benchmark_identity_tools || return 1
  staging="$(mktemp -d /tmp/obi-java-native-benchmark.XXXXXXXXXX)" || return 1
  canonical="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "$staging")" || {
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
  local environment_value=""

  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    capture_bounded_regular_file_value "$environment_file" \
      "$MAX_RUNNER_ENVIRONMENT_BYTES" environment_value || return 1
    runner_environment_value_from_value "$environment_value" "$key"
    return $?
  fi
  [[ -f "$environment_file" && ! -L "$environment_file" ]] || return 1
  environment_value="$(<"$environment_file")" || return 1
  runner_environment_value_from_value "$environment_value" "$key"
}

runner_environment_value_from_value() {
  local -r environment_value="$1"
  local -r key="$2"
  local line=""
  local value=""
  local matches=0

  [[ -n "$key" && "$key" != *$'\n'* && "$key" != *$'\r'* &&
    "$environment_value" != *$'\r'* ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "$key="* ]]; then
      value="${line#*=}"
      ((matches += 1))
    fi
  done < <(printf '%s' "$environment_value")
  ((matches == 1)) || return 1
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
  local image_id=""
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
    "{{.Id}} {{.Image}} {{.State.Pid}} {{index .Config.Labels \"com.docker.compose.project\"}} {{index .Config.Labels \"$PROJECT_SENTINEL_LABEL\"}}" \
    "$container_id")" || return 1
  read -r inspected_id image_id host_pid project sentinel extra <<<"$inspection_before" || return 1
  [[ "$inspected_id" =~ ^[0-9a-f]{64}$ && "$inspected_id" == "$container_id"* &&
    "$image_id" =~ ^sha256:[0-9a-f]{64}$ &&
    "$host_pid" =~ ^[1-9][0-9]*$ &&
    "$project" == "$ACTIVE_PROJECT" && "$sentinel" == "$PROJECT_SENTINEL_VALUE" &&
    -z "$extra" ]] || return 1
  container_id="$inspected_id"
  proc_identity_before="$(local_proc_identity "$host_pid" "$container_id")" || return 1
  inspection_after="$(run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker inspect --format \
    "{{.Id}} {{.Image}} {{.State.Pid}} {{index .Config.Labels \"com.docker.compose.project\"}} {{index .Config.Labels \"$PROJECT_SENTINEL_LABEL\"}}" \
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
    printf 'image_id=%s\n' "$image_id"
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
  local identity_value=""

  capture_bounded_regular_file_value \
    "$identity" "$MAX_SERVICE_IDENTITY_BYTES" identity_value || return 1
  identity_field_from_value "$identity_value" "$name"
}

identity_field_from_value() {
  local -r identity_value="$1"
  local -r name="$2"

  printf '%s' "$identity_value" | awk -F= -v wanted="$name" '
    $1 == wanted {
      value = substr($0, length($1) + 2)
      matches++
    }
    END {
      if (matches != 1 || value == "") exit 1
      printf "%s", value
    }
  '
}

validate_service_identity_value() {
  local -r identity_value="$1"
  local -r expected_service="$2"

  [[ "$expected_service" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
  printf '%s' "$identity_value" | awk -F= -v service="$expected_service" '
    NF < 2 { exit 1 }
    {
      key = $1
      value = substr($0, length(key) + 2)
      if (++seen[key] != 1 || value == "") exit 1
      values[key] = value
    }
    END {
      if (NR != 9 || length(seen) != 9 ||
          values["service"] != service ||
          values["container_id"] !~ /^[0-9a-f]{64}$/ ||
          values["image_id"] !~ /^sha256:[0-9a-f]{64}$/ ||
          values["host_pid"] !~ /^[1-9][0-9]*$/ ||
          values["proc_start_time"] !~ /^[1-9][0-9]*$/ ||
          values["proc_cgroup_sha256"] !~ /^[0-9a-f]{64}$/ ||
          values["proc_cgroup_container_binding"] != "full_container_id_at_non_hex_boundaries" ||
          values["project"] !~ /^[a-z0-9][a-z0-9_-]*$/ ||
          values["owner_sentinel"] !~ /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/) exit 1
      for (key in seen) {
        if (key != "service" && key != "container_id" && key != "image_id" &&
            key != "host_pid" && key != "proc_start_time" &&
            key != "proc_cgroup_sha256" &&
            key != "proc_cgroup_container_binding" && key != "project" &&
            key != "owner_sentinel") exit 1
      }
    }
  '
}

validate_service_identity_file() {
  local -r identity="$1"
  local -r expected_service="$2"
  local size=""

  [[ -f "$identity" && ! -L "$identity" &&
    "$expected_service" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
  size="$(stat --format '%s' -- "$identity")" || return 1
  [[ "$size" =~ ^[1-9][0-9]*$ && "$size" -le 4096 ]] || return 1
  local identity_value=""
  capture_bounded_regular_file_value \
    "$identity" "$MAX_SERVICE_IDENTITY_BYTES" identity_value || return 1
  validate_service_identity_value "$identity_value" "$expected_service"
}

validate_bound_cgroup_v2_identity_binding_values() {
  local -r snapshot_value="$1"
  local -r identity_value="$2"
  local -r identity_source="$3"
  local -r expected_service="$4"
  local container_id="" host_pid="" start_time="" cgroup_sha256="" binding=""

  validate_bound_cgroup_v2_snapshot_json_value "$snapshot_value" || return 1
  validate_service_identity_value "$identity_value" "$expected_service" || return 1
  [[ "$(printf '%s' "$snapshot_value" | jq -er '.identity_source')" == \
    "$identity_source" ]] || return 1
  container_id="$(identity_field_from_value "$identity_value" container_id)" || return 1
  host_pid="$(identity_field_from_value "$identity_value" host_pid)" || return 1
  start_time="$(identity_field_from_value "$identity_value" proc_start_time)" || return 1
  cgroup_sha256="$(identity_field_from_value \
    "$identity_value" proc_cgroup_sha256)" || return 1
  binding="$(identity_field_from_value \
    "$identity_value" proc_cgroup_container_binding)" || return 1
  if [[ "$(printf '%s' "$snapshot_value" | jq -er '.status')" == available ]]; then
    printf '%s' "$snapshot_value" | jq -e \
      --arg container_id "$container_id" --argjson host_pid "$host_pid" \
      --argjson start_time "$start_time" --arg cgroup_sha256 "$cgroup_sha256" \
      --arg binding "$binding" '
        .identity.container_id == $container_id and .identity.root_host_pid == $host_pid and
        .identity.root_proc_start_time == $start_time and
        .identity.proc_cgroup_sha256 == $cgroup_sha256 and
        .identity.proc_cgroup_container_binding == $binding
      ' >/dev/null
  fi
}

validate_bound_cgroup_v2_snapshot_identity_state_values() {
  local -r snapshot_value="$1"
  local -r identity_value="$2"
  local -r identity_source="$3"
  local -r expected_service="$4"
  local snapshot_status=""

  validate_bound_cgroup_v2_snapshot_json_value "$snapshot_value" || return 1
  snapshot_status="$(printf '%s' "$snapshot_value" | jq -er '.status')" || return 1
  if [[ "$snapshot_status" == available ]]; then
    validate_bound_cgroup_v2_identity_binding_values "$snapshot_value" \
      "$identity_value" "$identity_source" "$expected_service"
  elif [[ "$snapshot_status" == unavailable ]]; then
    [[ "$identity_value" == $'status=unavailable\n' ]] ||
      validate_bound_cgroup_v2_identity_binding_values "$snapshot_value" \
        "$identity_value" "$identity_source" "$expected_service"
  else
    return 1
  fi
}

validate_bound_cgroup_v2_identity_binding() {
  local -r snapshot="$1"
  local -r identity="$2"
  local -r expected_service="$3"
  local snapshot_value=""
  local identity_value=""

  snapshot_value="$(validated_bound_cgroup_v2_snapshot_json_value \
    "$snapshot")" || return 1
  capture_bounded_regular_file_value \
    "$identity" "$MAX_SERVICE_IDENTITY_BYTES" identity_value || return 1
  validate_bound_cgroup_v2_identity_binding_values "$snapshot_value" \
    "$identity_value" "${identity##*/}" "$expected_service"
}

validate_benchmark_runtime_source_value() {
  local -r source_value="$1"
  local digest=""

  [[ -n "$source_value" ]] || return 1
  digest="$(json_value_sha256 "$source_value")" || return 1
  [[ "$digest" == "$JAVA_BENCHMARK_TOOL_SOURCE_SHA256" ]] || return 1
  [[ "$source_value" == *'new RecordingFile(snapshot.descriptorPath())'* &&
    "$source_value" == *'locateOpenDescriptor'* &&
    "$source_value" == *'FileChannel.open(source, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))'* &&
    "$source_value" == *'readBoundedDescriptor(sourceDescriptor, sourceDescriptorPath, maximumBytes)'* &&
    "$source_value" == *'streamRaw(System.out)'* &&
    "$source_value" == *'failure.addSuppressed(exception)'* &&
    "$source_value" == *'HARD_MAX_JFR_BYTES = 33_554_432L'* &&
    "$source_value" == *'HARD_MAX_JFR_RECORDS = 600_000L'* &&
    "$source_value" == *'StandardCopyOption.ATOMIC_MOVE'* ]]
}

validate_benchmark_runtime_source() {
  local -r source="$1"
  local source_value=""

  capture_bounded_regular_file_value \
    "$source" "$MAX_JAVA_TOOL_OUTPUT_BYTES" source_value || return 1
  validate_benchmark_runtime_source_value "$source_value"
}

validate_benchmark_jfr_settings_source_value() {
  local -r source_value="$1"
  local digest=""

  [[ -n "$source_value" ]] || return 1
  digest="$(json_value_sha256 "$source_value")" || return 1
  [[ "$digest" == "$JAVA_BENCHMARK_JFR_SETTINGS_SHA256" ]]
}

validate_benchmark_jfr_settings_source() {
  local -r source="$1"
  local source_value=""

  capture_bounded_regular_file_value \
    "$source" "$MAX_JAVA_TOOL_OUTPUT_BYTES" source_value || return 1
  validate_benchmark_jfr_settings_source_value "$source_value"
}

# This is the only boundary classified as infrastructure-unavailable. Once
# these exact executables and files are present in the exact container image,
# malformed output or any missing assertion is a measurement-contract failure.
java_measurement_facilities_available() (
  local -r cell_dir="$1"
  local before=""
  local after=""
  local container_id=""
  local path=""
  local predicate=""

  java_measurement_cell_is_allowed "$cell_dir" || return 1
  [[ "$CELL_BOUNDED_PATH" == false &&
    "$JAVA_IMAGE_TARGET" == "$JAVA_BENCHMARK_IMAGE_TARGET" &&
    "$JAVA_BACKEND_IMAGE" == "$JAVA_BENCHMARK_IMAGE_TAG" ]] || return 1
  before="$(mktemp "$cell_dir/.java-facility-before.XXXXXX")" || return 1
  after="$(mktemp "$cell_dir/.java-facility-after.XXXXXX")" || {
    rm -f -- "$before"
    return 1
  }
  trap 'rm -f -- "$before" "$after"' EXIT
  capture_service_identity java-backend "$before" || return 1
  container_id="$(identity_field "$before" container_id)" || return 1
  while read -r predicate path; do
    run_bounded "$JAVA_TOOL_TIMEOUT_SECONDS" \
      docker exec "$container_id" "${JAVA_BENCHMARK_TOOL_ENV[@]}" \
      /usr/bin/test "$predicate" "$path" >/dev/null || return 1
  done <<EOF
-x /opt/java/openjdk/bin/java
-x /opt/java/openjdk/bin/jcmd
-x /usr/bin/sha256sum
-x /usr/bin/stat
-f $JAVA_BENCHMARK_TOOL_JAR
-f $JAVA_BENCHMARK_TOOL_SOURCE
-f $JAVA_BENCHMARK_JFR_SETTINGS
EOF
  capture_service_identity java-backend "$after" || return 1
  cmp -s -- "$before" "$after"
)

validate_java_runtime_artifacts_values() {
  local -r artifact_value="$1"
  local -r identity_value="$2"
  local -r checkout_helper_value="$3"
  local -r checkout_jfc_value="$4"
  local expected_image_id=""
  local checkout_helper_sha256=""
  local checkout_helper_size=""
  local checkout_jfc_sha256=""
  local checkout_jfc_size=""
  local raw_value_count=""

  [[ -n "$artifact_value" && -n "$identity_value" &&
    -n "$checkout_helper_value" && -n "$checkout_jfc_value" ]] || return 1
  validate_benchmark_jfr_settings_source_value "$checkout_jfc_value" || return 1
  validate_benchmark_runtime_source_value "$checkout_helper_value" || return 1
  expected_image_id="$(identity_field_from_value \
    "$identity_value" image_id)" || return 1
  checkout_helper_sha256="$(json_value_sha256 "$checkout_helper_value")" || return 1
  checkout_jfc_sha256="$(json_value_sha256 "$checkout_jfc_value")" || return 1
  checkout_helper_size="${#checkout_helper_value}"
  checkout_jfc_size="${#checkout_jfc_value}"
  raw_value_count="$(raw_json_value_count_from_value "$artifact_value")" || return 1
  [[ "$raw_value_count" == 16 ]] || return 1
  printf '%s' "$artifact_value" | jq -se \
    --arg expected_image_id "$expected_image_id" \
    --arg expected_image_tag "$JAVA_BENCHMARK_IMAGE_TAG" \
    --arg helper_source_sha256 "$checkout_helper_sha256" \
    --argjson helper_source_size "$checkout_helper_size" \
    --arg jfr_settings_sha256 "$checkout_jfc_sha256" \
    --argjson jfr_settings_size "$checkout_jfc_size" \
    --arg settings_authority_sha256 "$JAVA_BENCHMARK_JFR_SETTINGS_SHA256" \
    --arg retention_scope "$JAVA_JFR_RETENTION_SCOPE" \
    --argjson maximum_artifact_bytes "$MAX_JAVA_RUNTIME_ARTIFACT_BYTES" \
    --argjson maximum_jfr_bytes "$MAX_JFR_BYTES" \
    --argjson maximum_duration_seconds "$JAVA_JFR_MAX_DURATION_SECONDS" '
      def bounded_positive:
        type == "number" and isfinite and floor == . and . > 0 and
        . <= $maximum_artifact_bytes;
      length == 1 and (.[0] |
        (keys) == [
          "configured_image_tag", "helper_jar", "helper_source", "image_id",
          "jfr_settings", "retention", "schema_version"
        ] and
        .schema_version == 1 and .image_id == $expected_image_id and
        .configured_image_tag == $expected_image_tag and
        (.helper_jar | type == "object" and
          (keys) == ["sha256", "size_bytes"] and
          (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
          (.size_bytes | bounded_positive)) and
        (.helper_source | type == "object" and
          (keys) == ["checkout_match", "sha256", "size_bytes"] and
          .checkout_match == true and .sha256 == $helper_source_sha256 and
          .size_bytes == $helper_source_size and (.size_bytes | bounded_positive)) and
        (.jfr_settings | type == "object" and
          (keys) == [
            "checkout_match", "settings_authority_sha256", "sha256", "size_bytes"
          ] and
          .checkout_match == true and .sha256 == $jfr_settings_sha256 and
          .sha256 == $settings_authority_sha256 and
          .settings_authority_sha256 == $settings_authority_sha256 and
          .size_bytes == $jfr_settings_size and (.size_bytes | bounded_positive)) and
        (.retention | type == "object" and
          (keys) == [
            "maximum_duration_seconds", "maximum_size_bytes", "scope",
            "whole_window_retention_attested"
          ] and
          .maximum_duration_seconds == $maximum_duration_seconds and
          .maximum_size_bytes == $maximum_jfr_bytes and
          .scope == $retention_scope and
          .whole_window_retention_attested == false))
    ' >/dev/null
}

validated_java_runtime_artifacts_values() {
  local -r artifact="$1"
  local -r identity="$2"
  local -r artifact_output_name="${3:-}"
  local -r identity_output_name="${4:-}"
  local -r digest_output_name="${5:-}"
  local captured_artifact_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local captured_artifact_identity=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local captured_artifact_size=""
  local captured_artifact_digest=""
  local captured_identity_value=""
  local checkout_helper_value=""
  local checkout_jfc_value=""

  bounded_duplicate_free_json_image \
    "$artifact" "$MAX_JAVA_RUNTIME_ARTIFACT_BYTES" \
    captured_artifact_value captured_artifact_identity captured_artifact_size \
    captured_artifact_digest || return 1
  capture_bounded_regular_file_value \
    "$identity" "$MAX_SERVICE_IDENTITY_BYTES" captured_identity_value || return 1
  capture_bounded_regular_file_value \
    "$JAVA_BENCHMARK_TOOL_SOURCE_CHECKOUT" "$MAX_JAVA_TOOL_OUTPUT_BYTES" \
    checkout_helper_value || return 1
  capture_bounded_regular_file_value \
    "$JAVA_BENCHMARK_JFR_SETTINGS_CHECKOUT" "$MAX_JAVA_TOOL_OUTPUT_BYTES" \
    checkout_jfc_value || return 1
  validate_java_runtime_artifacts_values "$captured_artifact_value" \
    "$captured_identity_value" "$checkout_helper_value" "$checkout_jfc_value" || return 1
  if [[ -n "$artifact_output_name" ]]; then
    printf -v "$artifact_output_name" '%s' "$captured_artifact_value"
  fi
  if [[ -n "$identity_output_name" ]]; then
    printf -v "$identity_output_name" '%s' "$captured_identity_value"
  fi
  if [[ -n "$digest_output_name" ]]; then
    printf -v "$digest_output_name" '%s' "$captured_artifact_digest"
  fi
}

validate_java_runtime_artifacts() {
  local artifact_value=""
  local identity_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic validator output name.
  local artifact_digest=""

  validated_java_runtime_artifacts_values "$1" "$2" \
    artifact_value identity_value artifact_digest
}

capture_java_runtime_artifacts() (
  local -r root="$1"
  local -r output="$2"
  local -r identity="$root/identity.txt"
  local work=""
  local before=""
  local after=""
  local hashes=""
  local sizes=""
  local temporary=""
  local container_id=""
  local image_id=""
  local helper_sha256=""
  local helper_source_sha256=""
  local jfr_settings_sha256=""
  local helper_size=""
  local helper_source_size=""
  local jfr_settings_size=""
  local line=""
  local path=""
  local extra=""
  local -a hash_lines=()
  local -a size_lines=()

  [[ "$root" == "$JAVA_MEASUREMENT_PARTIAL" && -d "$root" && ! -L "$root" &&
    "$output" == "$root/"* && ! -e "$output" && ! -L "$output" &&
    -f "$identity" && ! -L "$identity" ]] || return 1
  work="$(mktemp -d "$root/.runtime-artifacts.XXXXXX")" || return 1
  chmod 0700 -- "$work" || return 1
  before="$work/host-before.txt"
  after="$work/host-after.txt"
  hashes="$work/hashes.txt"
  sizes="$work/sizes.txt"
  temporary="$work/artifacts.json"
  trap 'rm -f -- "$before" "$after" "$hashes" "$sizes" "$temporary"; rmdir -- "$work" 2>/dev/null || true' EXIT
  capture_service_identity java-backend "$before" || return 1
  cmp -s -- "$identity" "$before" || return 1
  container_id="$(identity_field "$identity" container_id)" || return 1
  image_id="$(identity_field "$identity" image_id)" || return 1
  capture_bounded_private_output "$hashes" "$MAX_JAVA_TOOL_OUTPUT_BYTES" \
    "$JAVA_TOOL_TIMEOUT_SECONDS" \
    docker exec "$container_id" "${JAVA_BENCHMARK_TOOL_ENV[@]}" \
    /usr/bin/sha256sum -- "$JAVA_BENCHMARK_TOOL_JAR" \
    "$JAVA_BENCHMARK_TOOL_SOURCE" "$JAVA_BENCHMARK_JFR_SETTINGS" || return 1
  capture_bounded_private_output "$sizes" "$MAX_JAVA_TOOL_OUTPUT_BYTES" \
    "$JAVA_TOOL_TIMEOUT_SECONDS" \
    docker exec "$container_id" "${JAVA_BENCHMARK_TOOL_ENV[@]}" \
    /usr/bin/stat --format=%s -- "$JAVA_BENCHMARK_TOOL_JAR" \
    "$JAVA_BENCHMARK_TOOL_SOURCE" "$JAVA_BENCHMARK_JFR_SETTINGS" || return 1
  capture_service_identity java-backend "$after" || return 1
  cmp -s -- "$identity" "$after" || return 1
  mapfile -t hash_lines <"$hashes" || return 1
  mapfile -t size_lines <"$sizes" || return 1
  [[ "${#hash_lines[@]}" == 3 && "${#size_lines[@]}" == 3 ]] || return 1
  read -r helper_sha256 path extra <<<"${hash_lines[0]}" || return 1
  [[ "$helper_sha256" =~ ^[0-9a-f]{64}$ &&
    "$path" == "$JAVA_BENCHMARK_TOOL_JAR" && -z "$extra" ]] || return 1
  read -r helper_source_sha256 path extra <<<"${hash_lines[1]}" || return 1
  [[ "$helper_source_sha256" =~ ^[0-9a-f]{64}$ &&
    "$path" == "$JAVA_BENCHMARK_TOOL_SOURCE" && -z "$extra" ]] || return 1
  read -r jfr_settings_sha256 path extra <<<"${hash_lines[2]}" || return 1
  [[ "$jfr_settings_sha256" =~ ^[0-9a-f]{64}$ &&
    "$path" == "$JAVA_BENCHMARK_JFR_SETTINGS" && -z "$extra" ]] || return 1
  read -r helper_size extra <<<"${size_lines[0]}" || return 1
  [[ "$helper_size" =~ ^[1-9][0-9]*$ && -z "$extra" ]] || return 1
  read -r helper_source_size extra <<<"${size_lines[1]}" || return 1
  [[ "$helper_source_size" =~ ^[1-9][0-9]*$ && -z "$extra" ]] || return 1
  read -r jfr_settings_size extra <<<"${size_lines[2]}" || return 1
  [[ "$jfr_settings_size" =~ ^[1-9][0-9]*$ && -z "$extra" ]] || return 1
  jq -n \
    --arg image_id "$image_id" \
    --arg configured_image_tag "$JAVA_BENCHMARK_IMAGE_TAG" \
    --arg helper_sha256 "$helper_sha256" \
    --argjson helper_size "$helper_size" \
    --arg helper_source_sha256 "$helper_source_sha256" \
    --argjson helper_source_size "$helper_source_size" \
    --arg jfr_settings_sha256 "$jfr_settings_sha256" \
    --argjson jfr_settings_size "$jfr_settings_size" \
    --arg settings_authority_sha256 "$JAVA_BENCHMARK_JFR_SETTINGS_SHA256" \
    --arg retention_scope "$JAVA_JFR_RETENTION_SCOPE" \
    --argjson maximum_jfr_bytes "$MAX_JFR_BYTES" \
    --argjson maximum_duration_seconds "$JAVA_JFR_MAX_DURATION_SECONDS" '
      {
        schema_version: 1,
        image_id: $image_id,
        configured_image_tag: $configured_image_tag,
        helper_jar: {sha256: $helper_sha256, size_bytes: $helper_size},
        helper_source: {
          sha256: $helper_source_sha256,
          size_bytes: $helper_source_size,
          checkout_match: true
        },
        jfr_settings: {
          sha256: $jfr_settings_sha256,
          size_bytes: $jfr_settings_size,
          checkout_match: true,
          settings_authority_sha256: $settings_authority_sha256
        },
        retention: {
          maximum_size_bytes: $maximum_jfr_bytes,
          maximum_duration_seconds: $maximum_duration_seconds,
          scope: $retention_scope,
          whole_window_retention_attested: false
        }
      }
    ' >"$temporary" || return 1
  chmod 0600 -- "$temporary" || return 1
  validate_java_runtime_artifacts "$temporary" "$identity" || return 1
  mv -T -- "$temporary" "$output" || return 1
  rm -f -- "$before" "$after" "$hashes" "$sizes" || return 1
  rmdir -- "$work"
)

json_value_sha256() {
  local -r json_value="$1"
  local digest=""

  digest="$(printf '%s' "$json_value" | sha256sum)" || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$digest"
}

# Map a held source read onto one of the two creation-bound roots understood by
# the terminal native transaction. Descriptor-anchored child paths are reduced
# through their already-open directory FD; private dot-prefixed derivation
# temporaries are deliberately excluded because their retained inputs, not the
# disposable projection, are the source authority.
terminal_source_locator() {
  local -r artifact="$1"
  local normalized="$artifact"
  local descriptor_tail=""
  local descriptor=""
  local suffix=""
  local descriptor_target=""
  local relative=""
  local root_name=""

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true && "$artifact" == /* ]] || return 1
  if [[ "$artifact" == /proc/self/fd/* ]]; then
    descriptor_tail="${artifact#/proc/self/fd/}"
    descriptor="${descriptor_tail%%/*}"
    [[ "$descriptor" =~ ^[0-9]+$ ]] || return 1
    resolve_benchmark_identity_tools || return 1
    descriptor_target="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_READLINK_COMMAND" -- "/proc/self/fd/$descriptor")" || return 1
    [[ "$descriptor_target" == /* && "$descriptor_target" != *' (deleted)' ]] || return 1
    if [[ "$descriptor_tail" == */* ]]; then
      suffix="${descriptor_tail#*/}"
      normalized="$descriptor_target/$suffix"
    else
      normalized="$descriptor_target"
    fi
  fi
  if [[ "$normalized" == "$TERMINAL_SOURCE_OUTPUT_ROOT/"* ]]; then
    root_name=output
    relative="${normalized#"$TERMINAL_SOURCE_OUTPUT_ROOT/"}"
  elif [[ "$normalized" == "$TERMINAL_SOURCE_REPOSITORY_ROOT/"* ]]; then
    root_name=repository
    relative="${normalized#"$TERMINAL_SOURCE_REPOSITORY_ROOT/"}"
  else
    return 1
  fi
  [[ -n "$relative" && "${#relative}" -le "$MAX_TERMINAL_SOURCE_PATH_BYTES" &&
    "$relative" =~ ^[A-Za-z0-9._/-]+$ && "$relative" != /* &&
    "$relative" != */ && "$relative" != *//* &&
    "$relative" != */./* && "$relative" != */../* &&
    "$relative" != ./* && "$relative" != ../* &&
    "$relative" != */. && "$relative" != */.. ]] || return 1
  if [[ "$relative" =~ (^|/)\. ]]; then
    return 2
  fi
  printf '%s/%s' "$root_name" "$relative"
}

# Records are written with one Bash builtin write and are strictly smaller
# than PIPE_BUF. This keeps frames atomic when source readers return from
# subshells through the one inherited anonymous session descriptor.
terminal_publication_write_source_record() {
  local -r record_type="$1"
  local -r payload="$2"
  local record=""

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false &&
    "$TERMINAL_SOURCE_RECORD_FD" =~ ^[1-9][0-9]*$ &&
    "$record_type" =~ ^[DGTN]$ && -n "$payload" &&
    "$payload" != *$'\t\t'* && "$payload" != *$'\n'* &&
    "$payload" != *$'\r'* ]] || return 1
  record="$record_type:${#payload}:$payload"
  [[ "${#record}" -lt "$MAX_TERMINAL_SOURCE_RECORD_BYTES" ]] || return 1
  printf '%s\n' "$record" >&"$TERMINAL_SOURCE_RECORD_FD"
}

terminal_record_source_negative() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local -r expected_state="${3:-}"
  local locator=""

  [[ "$artifact" == /* && "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$maximum_bytes" -le "$MAX_TERMINAL_SOURCE_LEAF_BYTES" &&
    ( -z "$expected_state" || "$expected_state" == absent ||
      "$expected_state" == nonregular || "$expected_state" == empty ||
      "$expected_state" == oversize ) ]] || return 1
  locator="$(terminal_source_locator "$artifact")" || return 1
  terminal_publication_write_source_record N \
    "$locator"$'\t'"$maximum_bytes"$'\t'"$expected_state"
}

# Classify an optional retained leaf before choosing a summary branch. A valid
# in-cap regular file is left for the caller's one-FD held parser. Every other
# state is recorded natively and rechecked at FREEZE, so Bash pathname tests
# never become unrecorded authority.
terminal_optional_source_is_capturable() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local observed_size=""
  local expected_state=""

  [[ "$artifact" == /* && "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$maximum_bytes" -le "$MAX_TERMINAL_SOURCE_LEAF_BYTES" ]] || return 2
  if [[ ! -e "$artifact" && ! -L "$artifact" ]]; then
    expected_state=absent
  elif [[ -L "$artifact" || ! -f "$artifact" ]]; then
    expected_state=nonregular
  else
    observed_size="$(stat --format '%s' -- "$artifact")" || return 2
    [[ "$observed_size" =~ ^(0|[1-9][0-9]*)$ ]] || return 2
    if ((observed_size == 0)); then
      expected_state=empty
    elif ((observed_size > maximum_bytes)); then
      expected_state=oversize
    else
      return 0
    fi
  fi
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    terminal_record_source_negative \
      "$artifact" "$maximum_bytes" "$expected_state" || return 2
  fi
  return 1
}

# Record the exact state of a fixed optional leaf without letting the caller's
# later partial/not-evaluated projection race the authority decision. Valid
# leaves become S records through one held read; every other supported state
# becomes one N record. The caller may then re-read only through the same
# recording wrapper, which the native session requires to match this receipt.
terminal_record_optional_source_authority() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local held_value=""
  local classification_status=0

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false ]] || return 1
  terminal_optional_source_is_capturable \
    "$artifact" "$maximum_bytes" || classification_status=$?
  if ((classification_status == 0)); then
    capture_bounded_regular_file_value \
      "$artifact" "$maximum_bytes" held_value || return 1
    [[ -n "$held_value" ]]
    return $?
  fi
  ((classification_status == 1)) && return 0
  return 1
}

terminal_record_directory_selector() {
  local -r directory="$1"
  local -r selector="$2"
  local locator=""

  [[ "$directory" == /* &&
    ( "$selector" == benchmark-repetition-json ||
      "$selector" == pressure-recovery-sample-prom ) ]] || return 1
  locator="$(terminal_source_locator "$directory")" || return 1
  terminal_publication_write_source_record D "$locator"$'\t'"$selector"
}

terminal_record_java_tree_authority() {
  local -r root="$1"
  local -r entry_count="$2"
  local -r file_count="$3"
  local -r directory_count="$4"
  local -r manifest_size_bytes="$5"
  local -r manifest_sha256="$6"
  local -r parent_identity="$7"
  local -r root_identity="$8"
  local locator=""
  local payload=""

  [[ "$root" == /* && "$entry_count" =~ ^[1-9][0-9]*$ &&
    "$file_count" =~ ^[1-9][0-9]*$ &&
    "$directory_count" =~ ^(0|[1-9][0-9]*)$ &&
    "$manifest_size_bytes" =~ ^[1-9][0-9]*$ &&
    "$entry_count" -eq "$((file_count + directory_count))" &&
    "$entry_count" -le "$MAX_TERMINAL_JAVA_TREE_ENTRIES" &&
    "$manifest_size_bytes" -le "$MAX_TERMINAL_JAVA_TREE_MANIFEST_BYTES" &&
    "$manifest_sha256" =~ ^[0-9a-f]{64}$ &&
    "$parent_identity" =~ ^[0-9]+:[1-9][0-9]*:[0-9]+:[0-7]{3,4}$ &&
    "$root_identity" =~ ^[0-9]+:[1-9][0-9]*:[0-9]+:[0-7]{3,4}$ ]] || return 1
  locator="$(terminal_source_locator "$root")" || return 1
  printf -v payload '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
    "$locator" "$entry_count" "$file_count" "$directory_count" \
    "$manifest_size_bytes" "$manifest_sha256" "$parent_identity" \
    "$root_identity"
  terminal_publication_write_source_record T "$payload"
}

terminal_record_git_checkout_authority() {
  local -r repository="$1"
  local -r revision="$2"
  local -r git_tree="$3"
  local -r source_tree_sha256="$4"
  local locator=""
  local payload=""
  local response=""

  [[ "$repository" == /* && -d "$repository" && ! -L "$repository" &&
    "$revision" =~ ^[0-9a-f]{40}$ && "$git_tree" =~ ^[0-9a-f]{40}$ &&
    "$source_tree_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ "$repository" == "$TERMINAL_SOURCE_REPOSITORY_ROOT" ]]; then
    locator=repository/.
  else
    locator="$(terminal_source_locator "$repository")" || return 1
  fi
  printf -v payload '%s\t%s\t%s\t%s\t%s' \
    "$locator" git-clean-checkout-v1 "$revision" "$git_tree" \
    "$source_tree_sha256"
  terminal_publication_write_source_record G "$payload" || return 1
  [[ "$TERMINAL_SOURCE_RESPONSE_FD" =~ ^[1-9][0-9]*$ ]] || return 1
  IFS= read -r response <&"$TERMINAL_SOURCE_RESPONSE_FD" || return 1
  [[ "$response" == G:READY ]]
}

# Capture a regular file through one O_RDONLY|O_NOFOLLOW descriptor and one
# bounded size+1 read. The hexadecimal frame preserves every non-NUL byte,
# including trailing newlines, across Bash command substitution.
capture_bounded_regular_file_image() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local perl_command="$JSON_SNAPSHOT_PERL_COMMAND"
  local source_locator=""
  local source_record_fd=""
  local captured_output=""
  local source_record=""
  local held_frame=""
  local locator_status=0
  local -a capture_command=()

  [[ "$artifact" == /* && "$maximum_bytes" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$TERMINAL_SOURCE_SESSION_FROZEN" != true ]] || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    source_locator="$(terminal_source_locator "$artifact")" || locator_status=$?
    if ((locator_status == 2)); then
      source_locator=""
    elif ((locator_status != 0)); then
      return 1
    fi
    source_record_fd="$TERMINAL_SOURCE_RECORD_FD"
    [[ -z "$source_locator" || "$source_record_fd" =~ ^[1-9][0-9]*$ ]] || return 1
  fi
  if [[ -z "$perl_command" ]]; then
    perl_command="$(type -P perl 2>/dev/null || true)"
  fi
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    resolve_benchmark_identity_tools || return 1
    capture_command=(run_native_clean_environment "$NATIVE_BENCHMARK_PERL_COMMAND" -T)
  else
    [[ "$perl_command" == /* && -f "$perl_command" && -x "$perl_command" ]] || return 1
    capture_command=("$perl_command")
  fi
  captured_output="$("${capture_command[@]}" \
    -MFcntl=:DEFAULT,:mode -MDigest::SHA=sha256_hex -e '
    use strict;
    use warnings;
    my ($path, $maximum, $locator, $record_maximum) = @ARGV;
    $maximum =~ /\A[1-9][0-9]*\z/ or exit 1;
    sysopen(my $handle, $path, O_RDONLY | O_NOFOLLOW) or exit 1;
    my @before = stat($handle);
    @before && S_ISREG($before[2]) && $before[7] > 0 &&
      $before[7] <= $maximum or exit 1;
    my $bytes = q{};
    my $read = sysread($handle, $bytes, $before[7] + 1);
    defined($read) && $read == $before[7] && index($bytes, "\0") < 0 or exit 1;
    my @after = stat($handle);
    @after && join(q{:}, @before[0,1,2,3,4,5,6,7]) eq
      join(q{:}, @after[0,1,2,3,4,5,6,7]) or exit 1;
    my $digest = sha256_hex($bytes);
    if (length($locator)) {
      $record_maximum =~ /\A[1-9][0-9]*\z/ or exit 1;
      my $payload = join(qq{\t}, $locator, $maximum,
        @before[0,1,2,3,4,5,6,7], $digest);
      my $record = q{S:} . length($payload) . q{:} . $payload . qq{\n};
      length($record) <= $record_maximum or exit 1;
      print $record;
    }
    close($handle) or exit 1;
    print join(q{:}, q{OBIJSON1}, $before[7], $digest,
      @before[0,1,2,3,4,5,6], unpack(q{H*}, $bytes));
  ' -- "$artifact" "$maximum_bytes" "$source_locator" \
    "$MAX_TERMINAL_SOURCE_RECORD_BYTES")" || return 1
  if [[ -n "$source_locator" ]]; then
    [[ "$captured_output" == *$'\n'* ]] || return 1
    source_record="${captured_output%%$'\n'*}"
    held_frame="${captured_output#*$'\n'}"
    [[ -n "$source_record" && "$source_record" != *$'\n'* &&
      "${#source_record}" -lt "$MAX_TERMINAL_SOURCE_RECORD_BYTES" ]] || return 1
    # Bash owns the inherited anonymous pipe. External readers return their
    # exact receipt to this wrapper so no CLOEXEC descriptor is exposed.
    printf '%s\n' "$source_record" >&"$source_record_fd" || return 1
  else
    held_frame="$captured_output"
  fi
  [[ "$held_frame" == OBIJSON1:* ]] || return 1
  printf '%s' "$held_frame"
}

decode_bounded_regular_file_image() {
  local -r held_frame="$1"
  local -r maximum_bytes="$2"
  local -r value_output_name="$3"
  local -r identity_output_name="$4"
  local -r digest_output_name="$5"
  local perl_command="$JSON_SNAPSHOT_PERL_COMMAND"
  local LC_ALL=C
  local decoded_with_marker=""
  local frame_magic=""
  local frame_size=""
  local framed_digest=""
  local frame_device=""
  local frame_inode=""
  local frame_mode=""
  local frame_links=""
  local frame_uid=""
  local frame_gid=""
  local frame_rdev=""
  local frame_hex=""
  local frame_extra=""
  local -a decode_command=()
  local -n decoded_value_ref="$value_output_name"
  local -n decoded_identity_ref="$identity_output_name"
  local -n decoded_digest_ref="$digest_output_name"

  [[ "$maximum_bytes" =~ ^[1-9][0-9]*$ && -n "$held_frame" ]] || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    resolve_benchmark_identity_tools || return 1
    decode_command=(run_native_clean_environment "$NATIVE_BENCHMARK_PERL_COMMAND" -T)
  else
    if [[ -z "$perl_command" ]]; then
      perl_command="$(type -P perl 2>/dev/null || true)"
    fi
    [[ "$perl_command" == /* && -f "$perl_command" && -x "$perl_command" ]] || return 1
    decode_command=("$perl_command")
  fi
  decoded_with_marker="$(printf '%s' "$held_frame" | "${decode_command[@]}" \
    -MDigest::SHA=sha256_hex -e '
      use strict;
      use warnings;
      local $/;
      my $frame = <STDIN>;
      my $maximum = shift @ARGV;
      $maximum =~ /\A[1-9][0-9]*\z/ or exit 1;
      $frame =~ /\AOBIJSON1:([1-9][0-9]*):([0-9a-f]{64}):([0-9]+):([1-9][0-9]*):([0-9]+):([1-9][0-9]*):([0-9]+):([0-9]+):([0-9]+):([0-9a-f]+)\z/ or exit 1;
      my ($size, $digest, $hex) = ($1, $2, $10);
      $size <= $maximum && length($hex) == $size * 2 or exit 1;
      my $bytes = pack(q{H*}, $hex);
      length($bytes) == $size && index($bytes, "\0") < 0 &&
        sha256_hex($bytes) eq $digest or exit 1;
      print $bytes, q{X};
    ' -- "$maximum_bytes")" || return 1
  [[ "$decoded_with_marker" == *X ]] || return 1
  decoded_with_marker="${decoded_with_marker%X}"
  # shellcheck disable=SC2034 # frame_hex is consumed by the trusted decoder above.
  IFS=: read -r frame_magic frame_size framed_digest frame_device frame_inode \
    frame_mode frame_links frame_uid frame_gid frame_rdev frame_hex frame_extra \
    <<<"$held_frame"
  [[ "$frame_magic" == OBIJSON1 && "$frame_size" == "${#decoded_with_marker}" &&
    "$framed_digest" == "$(json_value_sha256 "$decoded_with_marker")" &&
    -z "$frame_extra" ]] || return 1
  # shellcheck disable=SC2034 # Writes through caller-selected nameref outputs.
  decoded_value_ref="$decoded_with_marker"
  # shellcheck disable=SC2034 # Writes through caller-selected nameref outputs.
  decoded_identity_ref="$frame_device:$frame_inode:$frame_mode:$frame_links:$frame_uid:$frame_gid:$frame_rdev:$frame_size"
  # shellcheck disable=SC2034 # Writes through caller-selected nameref outputs.
  decoded_digest_ref="$framed_digest"
}

capture_bounded_regular_file_value() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local -r value_output_name="$3"
  local -r identity_output_name="${4:-}"
  local -r size_output_name="${5:-}"
  local -r digest_output_name="${6:-}"
  local captured_frame=""
  local captured_value=""
  local captured_identity=""
  local captured_digest=""

  captured_frame="$(capture_bounded_regular_file_image \
    "$artifact" "$maximum_bytes")" || return 1
  decode_bounded_regular_file_image "$captured_frame" "$maximum_bytes" \
    captured_value captured_identity captured_digest || return 1
  printf -v "$value_output_name" '%s' "$captured_value"
  if [[ -n "$identity_output_name" ]]; then
    printf -v "$identity_output_name" '%s' "$captured_identity"
  fi
  if [[ -n "$size_output_name" ]]; then
    printf -v "$size_output_name" '%s' "${#captured_value}"
  fi
  if [[ -n "$digest_output_name" ]]; then
    printf -v "$digest_output_name" '%s' "$captured_digest"
  fi
}

raw_json_value_count_from_value() {
  local -r json_value="$1"

  printf '%s' "$json_value" | jq --stream -n '
    reduce inputs as $event (0;
      if ($event | length) == 2 then . + 1 else . end)
  '
}

raw_json_value_count() {
  local -r artifact="$1"
  local artifact_value=""

  capture_bounded_regular_file_value \
    "$artifact" "$MAX_BENCHMARK_RESULT_BYTES" artifact_value || return 1
  raw_json_value_count_from_value "$artifact_value"
}

bounded_duplicate_free_json_image() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local -r value_output_name="$3"
  local -r identity_output_name="$4"
  local -r size_output_name="$5"
  local -r digest_output_name="$6"
  local captured_frame=""
  local captured_source_value=""
  local captured_source_identity=""
  local captured_source_digest=""
  local captured_source_size=""
  local canonical_value=""
  local canonical_value_count=""
  local observed_value_count=""
  local canonical_raw_value_count=""
  local observed_raw_value_count=""

  captured_frame="$(capture_bounded_regular_file_image \
    "$artifact" "$maximum_bytes")" || return 1
  decode_bounded_regular_file_image "$captured_frame" "$maximum_bytes" \
    captured_source_value captured_source_identity captured_source_digest || return 1
  captured_source_size="${#captured_source_value}"
  printf '%s' "$captured_source_value" | jq --stream -en '
    reduce inputs as $event ({valid: true, seen: {}};
      if ($event | length) == 2 then
        ($event[0] | tojson) as $path |
        if (.seen | has($path)) then .valid = false
        else .seen[$path] = true end
      else . end
    ) | .valid
  ' >/dev/null || return 1
  observed_raw_value_count="$(raw_json_value_count_from_value \
    "$captured_source_value")" || return 1
  canonical_value="$(printf '%s' "$captured_source_value" | jq -ceSs '
    if length == 1 then .[0] else error("expected exactly one JSON document") end
  ')" || return 1
  canonical_raw_value_count="$(raw_json_value_count_from_value \
    "$canonical_value")" || return 1
  [[ "$observed_raw_value_count" =~ ^[1-9][0-9]*$ &&
    "$canonical_raw_value_count" == "$observed_raw_value_count" ]] || return 1
  printf -v "$value_output_name" '%s' "$captured_source_value"
  printf -v "$identity_output_name" '%s' "$captured_source_identity"
  printf -v "$size_output_name" '%s' "$captured_source_size"
  printf -v "$digest_output_name" '%s' "$captured_source_digest"
}

bounded_duplicate_free_json_value() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local held_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local held_identity=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local held_size=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local held_digest=""

  bounded_duplicate_free_json_image "$artifact" "$maximum_bytes" \
    held_value held_identity held_size held_digest || return 1
  printf '%s' "$held_value"
}

validate_bounded_duplicate_free_json() {
  local -r artifact="$1"
  local -r maximum_bytes="$2"
  local held_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local held_identity=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local held_size=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local held_digest=""

  bounded_duplicate_free_json_image "$artifact" "$maximum_bytes" \
    held_value held_identity held_size held_digest
}

json_publication_absence_ready() {
  :
}

json_publication_target_ready() {
  :
}

# Publish a canonical held JSON value to an absent name. O_TMPFILE keeps the
# candidate unnamed; linkat(AT_EMPTY_PATH) is the only namespace mutation and
# therefore cannot replace an existing or concurrently-created leaf.
publish_exact_json_value() {
  local -r output="$1"
  local -r json_value="$2"
  local -r maximum_bytes="$3"
  local -r expected_parent_identity="${4:-}"
  local parent=""
  local name=""
  local current_user_id=""
  local parent_identity=""
  local expected_output_identity=""
  local canonical_value=""
  local observed_value_count=""
  local canonical_value_count=""
  local value_size=""
  local value_digest=""
  local publication_receipt=""
  local published_frame=""
  local published_value=""
  local published_identity=""
  local published_digest=""
  local perl_command="$JSON_SNAPSHOT_PERL_COMMAND"

  [[ "$output" == /* && "$output" != / &&
    "$maximum_bytes" =~ ^[1-9][0-9]*$ && -n "$json_value" ]] || return 1
  parent="${output%/*}"
  name="${output##*/}"
  [[ "$parent" == /* && -n "$name" && "$name" != . && "$name" != .. &&
    "$name" != */* && "$name" != *$'\n'* && "$name" != *$'\r'* ]] || return 1
  value_size="${#json_value}"
  [[ "$value_size" -gt 0 && "$value_size" -le "$maximum_bytes" ]] || return 1
  canonical_value="$(printf '%s' "$json_value" | jq -ceSs '
    if length == 1 then .[0] else error("expected exactly one JSON document") end
  ')" || return 1
  [[ "$canonical_value" == "$json_value" ]] || return 1
  # The raw/canonical leaf count equality rejects duplicate keys even when jq
  # would otherwise collapse them to the requested canonical value.
  observed_value_count="$(raw_json_value_count_from_value "$json_value")" || return 1
  canonical_value_count="$(raw_json_value_count_from_value "$canonical_value")" || return 1
  [[ "$observed_value_count" == "$canonical_value_count" ]] || return 1
  value_digest="$(json_value_sha256 "$json_value")" || return 1
  current_user_id="$(id -u)" || return 1
  [[ "$current_user_id" =~ ^[0-9]+$ ]] || return 1
  is_private_owned_directory "$parent" "$current_user_id" || return 1
  parent_identity="$(stat --format '%d:%i:%u:%g:%a' -- "$parent")" || return 1
  [[ "$parent_identity" =~ ^[0-9]+:[1-9][0-9]*:$current_user_id:[0-9]+:700$ ]] || return 1
  [[ -z "$expected_parent_identity" ||
    "$parent_identity" == "$expected_parent_identity" ]] || return 1
  if [[ -n "$OUTPUT_DIR" && "$parent" == "$OUTPUT_DIR" ]]; then
    expected_output_identity="$OUTPUT_DIR_IDENTITY"
    [[ -n "$expected_output_identity" &&
      "$parent_identity" == "$expected_output_identity" ]] || return 1
  fi
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  json_publication_absence_ready "$output" || return 1
  if [[ -z "$perl_command" ]]; then
    perl_command="$(type -P perl 2>/dev/null || true)"
  fi
  [[ "$perl_command" == /* && -f "$perl_command" && -x "$perl_command" ]] || return 1
  publication_receipt="$(printf '%s' "$json_value" | "$perl_command" \
    -MFcntl=:DEFAULT,:mode -MDigest::SHA=sha256_hex -e '
      use strict;
      use warnings;
      require "syscall.ph";
      use constant O_TMPFILE_LINUX => 020000000 | O_DIRECTORY;
      use constant AT_EMPTY_PATH_LINUX => 0x1000;
      my ($parent, $name, $expected_parent, $expected_size, $expected_digest) = @ARGV;
      local $/;
      my $bytes = <STDIN>;
      length($bytes) == $expected_size && sha256_hex($bytes) eq $expected_digest or exit 1;
      sysopen(my $directory, $parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW) or exit 1;
      my @directory_before = stat($directory);
      @directory_before or exit 1;
      my $directory_mode = sprintf(q{%o}, $directory_before[2] & 07777);
      join(q{:}, @directory_before[0,1,4,5], $directory_mode) eq $expected_parent or exit 1;
      my $dot = q{.};
      my $empty = q{};
      my $temporary_fd = syscall(SYS_openat(), fileno($directory), $dot,
        O_RDWR | O_TMPFILE_LINUX, 0600);
      $temporary_fd >= 0 or exit 1;
      open(my $temporary, q{+<&=}, $temporary_fd) or exit 1;
      my $offset = 0;
      while ($offset < length($bytes)) {
        my $written = syswrite($temporary, $bytes, length($bytes) - $offset, $offset);
        defined($written) && $written > 0 or exit 1;
        $offset += $written;
      }
      my @temporary_before = stat($temporary);
      @temporary_before && S_ISREG($temporary_before[2]) &&
        $temporary_before[7] == $expected_size && $temporary_before[3] == 0 or exit 1;
      syscall(SYS_linkat(), fileno($temporary), $empty, fileno($directory), $name,
        AT_EMPTY_PATH_LINUX) == 0 or exit 1;
      my @temporary_after = stat($temporary);
      @temporary_after && $temporary_after[3] == 1 &&
        join(q{:}, @temporary_before[0,1,2,4,5,6,7]) eq
          join(q{:}, @temporary_after[0,1,2,4,5,6,7]) or exit 1;
      my $published_fd = syscall(SYS_openat(), fileno($directory), $name,
        O_RDONLY | O_NOFOLLOW, 0);
      $published_fd >= 0 or exit 1;
      open(my $published, q{<&=}, $published_fd) or exit 1;
      my @published = stat($published);
      @published && $published[0] == $temporary_after[0] &&
        $published[1] == $temporary_after[1] && $published[7] == $expected_size or exit 1;
      my @directory_after = stat($directory);
      @directory_after or exit 1;
      my $directory_mode_after = sprintf(q{%o}, $directory_after[2] & 07777);
      join(q{:}, @directory_after[0,1,4,5], $directory_mode_after) eq
        $expected_parent or exit 1;
      close($published) && close($temporary) && close($directory) or exit 1;
      print join(q{:}, @published[0,1,2,3,4,5,6,7], $expected_digest);
    ' -- "$parent" "$name" "$parent_identity" "$value_size" \
      "$value_digest")" || return 1
  [[ "$publication_receipt" =~ ^[0-9]+:([1-9][0-9]*):[0-9]+:1:[0-9]+:[0-9]+:[0-9]+:$value_size:$value_digest$ ]] || return 1
  json_publication_target_ready "$output" || return 1
  published_frame="$(capture_bounded_regular_file_image \
    "$output" "$maximum_bytes")" || return 1
  decode_bounded_regular_file_image "$published_frame" "$maximum_bytes" \
    published_value published_identity published_digest || return 1
  [[ "$published_value" == "$json_value" &&
    "$published_digest" == "$value_digest" &&
    "$published_identity" == "${publication_receipt%:*}" ]] || return 1
}

validate_java_runtime_snapshot_value() {
  local -r snapshot_value="$1"
  local -r expected_start_epoch_millis="${2:-}"
  local raw_value_count=""

  raw_value_count="$(raw_json_value_count_from_value "$snapshot_value")" || return 1
  [[ "$raw_value_count" == 7 ]] || return 1
  printf '%s' "$snapshot_value" | jq -se \
    --argjson maximum_safe_integer "$MAX_SEED" \
    --arg expected_start_epoch_millis "$expected_start_epoch_millis" '
      def safe_positive_integer:
        type == "number" and isfinite and floor == . and . > 0 and
        . <= $maximum_safe_integer;
      def safe_non_negative_integer:
        type == "number" and isfinite and floor == . and . >= 0 and
        . <= $maximum_safe_integer;
      length == 1 and (.[0] |
        (keys) == [
          "direct_buffer", "jvm_start_epoch_millis", "runtime_pid",
          "schema_version", "target_pid"
        ] and
        .schema_version == 1 and .target_pid == 1 and .runtime_pid == 1 and
        (.jvm_start_epoch_millis | safe_positive_integer) and
        ($expected_start_epoch_millis == "" or
          (.jvm_start_epoch_millis | tostring) == $expected_start_epoch_millis) and
        (.direct_buffer | type == "object" and
          (keys) == ["count", "memory_used_bytes", "total_capacity_bytes"] and
          (.count | safe_non_negative_integer) and
          (.memory_used_bytes | safe_non_negative_integer) and
          (.total_capacity_bytes | safe_non_negative_integer)))
    ' >/dev/null
}

validate_java_runtime_snapshot() {
  local -r artifact="$1"
  local -r expected_start_epoch_millis="${2:-}"
  local snapshot_value=""

  snapshot_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_JAVA_RUNTIME_SNAPSHOT_BYTES")" || return 1
  validate_java_runtime_snapshot_value \
    "$snapshot_value" "$expected_start_epoch_millis"
}

capture_bounded_private_output() {
  local -r output="$1"
  local -r maximum_bytes="$2"
  local -r timeout_seconds="$3"
  shift 3
  local -r parent="${output%/*}"
  local temporary=""
  local captured_bytes=""

  [[ "$output" == /* && "$parent" == /* && -d "$parent" && ! -L "$parent" &&
    ! -e "$output" && ! -L "$output" &&
    "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$timeout_seconds" =~ ^[1-9][0-9]*$ && $# -gt 0 ]] || return 1
  temporary="$(mktemp "$parent/.${output##*/}.XXXXXX")" || return 1
  if ! run_bounded "$timeout_seconds" "$@" 2>&1 |
    head -c "$((maximum_bytes + 1))" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  captured_bytes="$(stat --format '%s' -- "$temporary")" || {
    rm -f -- "$temporary"
    return 1
  }
  if [[ ! "$captured_bytes" =~ ^[1-9][0-9]*$ ]] ||
    ((captured_bytes > maximum_bytes)) ||
    ! chmod 0600 -- "$temporary" ||
    ! mv -T -- "$temporary" "$output"; then
    rm -f -- "$temporary" "$output"
    return 1
  fi
}

capture_bounded_private_streams() {
  local -r stdout_output="$1"
  local -r stdout_maximum_bytes="$2"
  local -r stderr_output="$3"
  local -r stderr_maximum_bytes="$4"
  local -r timeout_seconds="$5"
  shift 5
  local -r parent="${stdout_output%/*}"
  local stdout_temporary=""
  local stderr_temporary=""
  local stdout_bytes=""
  local stderr_bytes=""
  local file_limit_bytes=""
  local file_limit_blocks=""

  [[ "$stdout_output" == "$parent/"* && "$stderr_output" == "$parent/"* &&
    "$stdout_output" != "$stderr_output" && -d "$parent" && ! -L "$parent" &&
    ! -e "$stdout_output" && ! -L "$stdout_output" &&
    ! -e "$stderr_output" && ! -L "$stderr_output" &&
    "$stdout_maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$stderr_maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$timeout_seconds" =~ ^[1-9][0-9]*$ && $# -gt 0 ]] || return 1
  stdout_temporary="$(mktemp "$parent/.${stdout_output##*/}.XXXXXX")" || return 1
  stderr_temporary="$(mktemp "$parent/.${stderr_output##*/}.XXXXXX")" || {
    rm -f -- "$stdout_temporary"
    return 1
  }
  file_limit_bytes="$stdout_maximum_bytes"
  if ((stderr_maximum_bytes > file_limit_bytes)); then
    file_limit_bytes="$stderr_maximum_bytes"
  fi
  file_limit_blocks="$(((file_limit_bytes + 1023) / 1024 + 1))"
  if ! (
    ulimit -f "$file_limit_blocks"
    run_bounded "$timeout_seconds" "$@" \
      >"$stdout_temporary" 2>"$stderr_temporary"
  ); then
    rm -f -- "$stdout_temporary" "$stderr_temporary"
    return 1
  fi
  stdout_bytes="$(stat --format '%s' -- "$stdout_temporary")" || {
    rm -f -- "$stdout_temporary" "$stderr_temporary"
    return 1
  }
  stderr_bytes="$(stat --format '%s' -- "$stderr_temporary")" || {
    rm -f -- "$stdout_temporary" "$stderr_temporary"
    return 1
  }
  if [[ ! "$stdout_bytes" =~ ^[1-9][0-9]*$ ||
    ! "$stderr_bytes" =~ ^[1-9][0-9]*$ ]] ||
    ((stdout_bytes > stdout_maximum_bytes || stderr_bytes > stderr_maximum_bytes)) ||
    ! chmod 0600 -- "$stdout_temporary" "$stderr_temporary" ||
    ! mv -T -- "$stdout_temporary" "$stdout_output" ||
    ! mv -T -- "$stderr_temporary" "$stderr_output"; then
    rm -f -- "$stdout_temporary" "$stderr_temporary" \
      "$stdout_output" "$stderr_output"
    return 1
  fi
}

java_runtime_identity_matches() {
  local -r snapshot="$1"

  validate_java_runtime_snapshot \
    "$snapshot" "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS"
}

java_measurement_root_identity_matches() {
  local -r root="$1"
  local -r phase="$2"
  local expected_root=""
  local observed_parent_identity=""
  local observed_root_identity=""

  java_measurement_cell_is_allowed "$JAVA_MEASUREMENT_CELL_DIR" || return 1
  case "$phase" in
    partial)
      expected_root="$JAVA_MEASUREMENT_PARTIAL"
      [[ "$root" == "$expected_root" &&
        ! -e "$JAVA_MEASUREMENT_CELL_DIR/java-measurement" &&
        ! -L "$JAVA_MEASUREMENT_CELL_DIR/java-measurement" ]] || return 1
      ;;
    published)
      expected_root="$JAVA_MEASUREMENT_CELL_DIR/java-measurement"
      [[ "$root" == "$expected_root" &&
        ! -e "$JAVA_MEASUREMENT_PARTIAL" && ! -L "$JAVA_MEASUREMENT_PARTIAL" ]] || return 1
      ;;
    *) return 1 ;;
  esac
  [[ -d "$JAVA_MEASUREMENT_CELL_DIR" && ! -L "$JAVA_MEASUREMENT_CELL_DIR" &&
    -d "$root" && ! -L "$root" ]] || return 1
  observed_parent_identity="$(stat --format '%d:%i:%u:%a' -- \
    "$JAVA_MEASUREMENT_CELL_DIR")" || return 1
  observed_root_identity="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  [[ "$observed_parent_identity" == "$JAVA_MEASUREMENT_PARENT_IDENTITY" &&
    "$observed_root_identity" == "$JAVA_MEASUREMENT_ROOT_IDENTITY" ]]
}

capture_stable_java_listing() (
  local -r root="$1"
  local -r mode="$2"
  local -r output="$3"
  local -r parent="${root%/*}"
  local first="${output}.first"
  local second="${output}.second"
  local root_identity_before=""
  local root_identity_after=""
  local parent_identity_before=""
  local parent_identity_after=""
  local size=""

  [[ "$root" == /* && "$parent" == /* && -d "$root" && ! -L "$root" &&
    -d "$parent" && ! -L "$parent" && "$output" == /* &&
    ! -e "$output" && ! -L "$output" &&
    ! -e "$first" && ! -L "$first" &&
    ! -e "$second" && ! -L "$second" ]] || return 1
  root_identity_before="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  parent_identity_before="$(stat --format '%d:%i:%u:%a' -- "$parent")" || return 1
  trap 'rm -f -- "$first" "$second" "$output"' EXIT
  case "$mode" in
    all)
      find -P "$root" -xdev -mindepth 1 -print0 | sort -z >"$first" || return 1
      find -P "$root" -xdev -mindepth 1 -print0 | sort -z >"$second" || return 1
      ;;
    root)
      find -P "$root" -xdev -mindepth 1 -maxdepth 1 -print0 | sort -z >"$first" || return 1
      find -P "$root" -xdev -mindepth 1 -maxdepth 1 -print0 | sort -z >"$second" || return 1
      ;;
    directories)
      find -P "$root" -xdev -mindepth 1 -maxdepth 1 -type d -print0 | sort -z >"$first" || return 1
      find -P "$root" -xdev -mindepth 1 -maxdepth 1 -type d -print0 | sort -z >"$second" || return 1
      ;;
    files)
      find -P "$root" -xdev -mindepth 1 -maxdepth 1 -print0 | sort -z >"$first" || return 1
      find -P "$root" -xdev -mindepth 1 -maxdepth 1 -print0 | sort -z >"$second" || return 1
      ;;
    *) return 1 ;;
  esac
  size="$(stat --format '%s' -- "$first")" || return 1
  [[ "$size" =~ ^[0-9]+$ ]] || return 1
  ((size <= MAX_JAVA_TREE_LISTING_BYTES)) || return 1
  cmp -s -- "$first" "$second" || return 1
  root_identity_after="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  parent_identity_after="$(stat --format '%d:%i:%u:%a' -- "$parent")" || return 1
  [[ "$root_identity_after" == "$root_identity_before" &&
    "$parent_identity_after" == "$parent_identity_before" ]] || return 1
  mv -T -- "$first" "$output" || return 1
  rm -f -- "$second"
  trap - EXIT
)

# Each target command is enclosed by two JMX runtime reads. Each JMX read is
# itself enclosed by independently captured host PID/start/cgroup receipts.
# Thus a successful operation proves that the container process and the Java
# RuntimeMXBean identity stayed exact before and after both the attach and the
# target jcmd/tool operation.
run_java_bound_operation() {
  local -r root="$1"
  local -r operation="$2"
  local -r maximum_output_bytes="$3"
  local -r mode="$4"
  shift 4
  local -r operation_directory="$root/operations/$operation"
  local -r canonical_identity="$root/identity.txt"
  local container_id=""
  local runtime_start=""
  local -a command=()

  [[ "$root" == "$JAVA_MEASUREMENT_PARTIAL" &&
    "$operation" =~ ^[0-9]{2}-[a-z][a-z0-9-]*$ &&
    -d "$root/operations" && ! -L "$root/operations" &&
    -f "$canonical_identity" && ! -L "$canonical_identity" &&
    ! -e "$operation_directory" && ! -L "$operation_directory" ]] || return 1
  java_measurement_root_identity_matches "$root" partial || return 1
  mkdir --mode=0700 -- "$operation_directory" || return 1
  capture_service_identity java-backend "$operation_directory/host-before.txt" || return 1
  cmp -s -- "$canonical_identity" "$operation_directory/host-before.txt" || return 1
  container_id="$(identity_field "$canonical_identity" container_id)" || return 1

  capture_bounded_private_output \
    "$operation_directory/runtime-before.json" \
    "$MAX_JAVA_RUNTIME_SNAPSHOT_BYTES" "$JAVA_TOOL_TIMEOUT_SECONDS" \
    docker exec "$container_id" "${JAVA_BENCHMARK_TOOL_ENV[@]}" \
      java --add-modules jdk.attach,jdk.management \
      -jar "$JAVA_BENCHMARK_TOOL_JAR" runtime-snapshot 1 || return 1
  capture_service_identity \
    java-backend "$operation_directory/host-after-runtime-before.txt" || return 1
  cmp -s -- "$canonical_identity" \
    "$operation_directory/host-after-runtime-before.txt" || return 1
  if [[ -z "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" ]]; then
    validate_java_runtime_snapshot "$operation_directory/runtime-before.json" || return 1
    runtime_start="$(jq -er '.jvm_start_epoch_millis' \
      "$operation_directory/runtime-before.json")" || return 1
    runtime_start="$(normalize_decimal "$runtime_start" "$MAX_SEED" false)" || return 1
    JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS="$runtime_start"
  else
    java_runtime_identity_matches "$operation_directory/runtime-before.json" || return 1
  fi

  case "$mode" in
    jcmd)
      (($# > 0)) || return 1
      command=(docker exec "$container_id" "${JAVA_BENCHMARK_TOOL_ENV[@]}" jcmd 1 "$@")
      ;;
    exec)
      (($# > 0)) || return 1
      command=(docker exec "$container_id" "$@")
      ;;
    jfr)
      (($# > 0)) || return 1
      command=(docker exec "$container_id" "$@")
      ;;
    runtime)
      (($# == 0)) || return 1
      ;;
    *)
      return 1
      ;;
  esac
  if [[ "$mode" == runtime ]]; then
    printf 'status=runtime-identity-only\n' >"$operation_directory/output"
    chmod 0600 -- "$operation_directory/output" || return 1
  elif [[ "$mode" == jfr ]]; then
    capture_bounded_private_streams \
      "$operation_directory/raw-output" "$MAX_JFR_BYTES" \
      "$operation_directory/output" "$maximum_output_bytes" \
      "$JAVA_TOOL_TIMEOUT_SECONDS" "${command[@]}" || return 1
  else
    capture_bounded_private_output \
      "$operation_directory/output" "$maximum_output_bytes" \
      "$JAVA_TOOL_TIMEOUT_SECONDS" "${command[@]}" || return 1
  fi

  capture_service_identity \
    java-backend "$operation_directory/host-before-runtime-after.txt" || return 1
  cmp -s -- "$canonical_identity" \
    "$operation_directory/host-before-runtime-after.txt" || return 1
  capture_bounded_private_output \
    "$operation_directory/runtime-after.json" \
    "$MAX_JAVA_RUNTIME_SNAPSHOT_BYTES" "$JAVA_TOOL_TIMEOUT_SECONDS" \
    docker exec "$container_id" "${JAVA_BENCHMARK_TOOL_ENV[@]}" \
      java --add-modules jdk.attach,jdk.management \
      -jar "$JAVA_BENCHMARK_TOOL_JAR" runtime-snapshot 1 || return 1
  capture_service_identity java-backend "$operation_directory/host-after.txt" || return 1
  cmp -s -- "$canonical_identity" "$operation_directory/host-after.txt" || return 1
  java_runtime_identity_matches "$operation_directory/runtime-after.json" || return 1
  java_measurement_root_identity_matches "$root" partial
}

nmt_summary_totals_from_value() {
  local -r artifact_value="$1"
  local line_count=""
  local total_line=""
  local reserved=""
  local committed=""

  [[ -n "$artifact_value" ]] || return 1
  line_count="$(printf '%s' "$artifact_value" | awk 'END { print NR }')" || return 1
  [[ "$line_count" =~ ^[1-9][0-9]*$ ]] || return 1
  ((line_count <= MAX_NMT_LINES)) || return 1
  [[ "$(printf '%s' "$artifact_value" | grep -c '^Native Memory Tracking:$' || true)" == 1 &&
    "$(printf '%s' "$artifact_value" | grep -c '^Total:' || true)" == 1 ]] || return 1
  total_line="$(printf '%s' "$artifact_value" | grep '^Total:')" || return 1
  [[ "$total_line" =~ ^Total:\ reserved=([0-9]+),\ committed=([0-9]+)$ ]] || return 1
  reserved="$(normalize_decimal "${BASH_REMATCH[1]}" "$MAX_SEED" false)" || return 1
  committed="$(normalize_decimal "${BASH_REMATCH[2]}" "$MAX_SEED" false)" || return 1
  printf '%s %s\n' "$reserved" "$committed"
}

nmt_summary_totals() {
  local -r artifact="$1"
  local artifact_value=""

  capture_bounded_regular_file_value \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES" artifact_value || return 1
  nmt_summary_totals_from_value "$artifact_value"
}

nmt_summary_diff_totals_from_value() {
  local -r artifact_value="$1"
  local line_count=""
  local total_line=""
  local reserved=""
  local reserved_delta="0"
  local committed=""
  local committed_delta="0"

  [[ -n "$artifact_value" ]] || return 1
  line_count="$(printf '%s' "$artifact_value" | awk 'END { print NR }')" || return 1
  [[ "$line_count" =~ ^[1-9][0-9]*$ ]] || return 1
  ((line_count <= MAX_NMT_LINES)) || return 1
  [[ "$(printf '%s' "$artifact_value" | grep -c '^Native Memory Tracking:$' || true)" == 1 &&
    "$(printf '%s' "$artifact_value" | grep -c '^Total:' || true)" == 1 ]] || return 1
  total_line="$(printf '%s' "$artifact_value" | grep '^Total:')" || return 1
  [[ "$total_line" =~ ^Total:\ reserved=([0-9]+)(\ \+([0-9]+))?,\ committed=([0-9]+)(\ \+([0-9]+))?$ ]] || return 1
  reserved="$(normalize_decimal "${BASH_REMATCH[1]}" "$MAX_SEED" false)" || return 1
  if [[ -n "${BASH_REMATCH[3]:-}" ]]; then
    reserved_delta="$(normalize_decimal "${BASH_REMATCH[3]}" "$MAX_SEED" true)" || return 1
  fi
  committed="$(normalize_decimal "${BASH_REMATCH[4]}" "$MAX_SEED" false)" || return 1
  if [[ -n "${BASH_REMATCH[6]:-}" ]]; then
    committed_delta="$(normalize_decimal "${BASH_REMATCH[6]}" "$MAX_SEED" true)" || return 1
  fi
  ((reserved >= reserved_delta && committed >= committed_delta)) || return 1
  printf '%s %s %s %s\n' \
    "$reserved" "$committed" "$reserved_delta" "$committed_delta"
}

nmt_summary_diff_totals() {
  local -r artifact="$1"
  local artifact_value=""

  capture_bounded_regular_file_value \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES" artifact_value || return 1
  nmt_summary_diff_totals_from_value "$artifact_value"
}

validate_jfr_summary_value() {
  local -r artifact_value="$1"
  local -r expected_size_bytes="$2"
  local -r expected_sha256="$3"
  local raw_value_count=""

  raw_value_count="$(raw_json_value_count_from_value "$artifact_value")" || return 1
  [[ "$raw_value_count" == 13 && "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$artifact_value" | jq -se \
    --argjson maximum_safe_integer "$MAX_SEED" \
    --argjson maximum_records "$MAX_JFR_RECORDS" \
    --argjson expected_size_bytes "$expected_size_bytes" \
    --arg expected_sha256 "$expected_sha256" '
      def safe_non_negative_integer:
        type == "number" and isfinite and floor == . and . >= 0 and
        . <= $maximum_safe_integer;
      def exact_pair:
        type == "object" and (keys) == ["records", "weight_bytes"];
      def exact_duration_pair:
        type == "object" and (keys) == ["duration_nanos", "records"];
      length == 1 and (.[0] |
        (keys) == [
          "allocation_sample", "data_loss", "file_size_bytes",
          "java_monitor_enter", "raw_sha256", "schema_version",
          "snapshot_semantics", "thread_park", "total_records"
        ] and
        .schema_version == 1 and
        .snapshot_semantics == "single_source_descriptor_bounded_private_copy" and
        .file_size_bytes == $expected_size_bytes and
        .raw_sha256 == $expected_sha256 and
        (.file_size_bytes | safe_non_negative_integer and . > 0) and
        (.total_records | safe_non_negative_integer and . <= $maximum_records) and
        (.allocation_sample | exact_pair and
          (.records | safe_non_negative_integer) and
          (.weight_bytes | safe_non_negative_integer) and
          ((.records == 0 and .weight_bytes == 0) or
            (.records > 0 and .weight_bytes > 0))) and
        (.java_monitor_enter | exact_duration_pair and
          (.records | safe_non_negative_integer) and
          (.duration_nanos | safe_non_negative_integer) and
          ((.records == 0 and .duration_nanos == 0) or
            (.records > 0 and .duration_nanos > 0))) and
        (.thread_park | exact_duration_pair and
          (.records | safe_non_negative_integer) and
          (.duration_nanos | safe_non_negative_integer) and
          ((.records == 0 and .duration_nanos == 0) or
            (.records > 0 and .duration_nanos > 0))) and
        (.data_loss | type == "object" and (keys) == ["bytes", "records"] and
          .records == 0 and .bytes == 0) and
        .total_records == (
          .allocation_sample.records + .java_monitor_enter.records +
          .thread_park.records + .data_loss.records))
    ' >/dev/null
}

validate_jfr_summary() {
  local -r artifact="$1"
  local -r expected_size_bytes="$2"
  local -r expected_sha256="$3"
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES")" || return 1
  validate_jfr_summary_value \
    "$artifact_value" "$expected_size_bytes" "$expected_sha256"
}

jfr_formatted_size_bytes() {
  local -r size_bytes="$1"

  [[ "$size_bytes" =~ ^[1-9][0-9]*$ ]] || return 1
  ((size_bytes <= MAX_JFR_BYTES)) || return 1
  if ((size_bytes == 1)); then
    printf '1 byte\n'
  elif ((size_bytes < 1024)); then
    printf '%s bytes\n' "$size_bytes"
  elif ((size_bytes < 1024 * 1024)); then
    awk -v bytes="$size_bytes" 'BEGIN { printf "%.1f kB\n", bytes / 1024 }'
  else
    awk -v bytes="$size_bytes" 'BEGIN { printf "%.1f MB\n", bytes / 1048576 }'
  fi
}

validate_jfr_command_output_value() {
  local -r artifact_value="$1"
  local -r action="$2"
  local -r recording_name="$3"
  local -r recording_path="$4"
  local -r expected_size_bytes="${5:-}"
  local stop_regex=""
  local expected_formatted_size=""
  local -a lines=()

  [[ -n "$artifact_value" && "$recording_name" =~ ^[a-z][a-z0-9-]{0,63}$ &&
    "$recording_path" =~ ^/tmp/[a-z][a-z0-9.-]{0,127}\.jfr$ ]] || return 1
  mapfile -t lines < <(printf '%s' "$artifact_value") || return 1
  [[ "${#lines[@]}" == 4 && "${lines[0]}" == '1:' &&
    -z "${lines[2]}" && "${lines[3]}" == "$recording_path" ]] || return 1
  case "$action" in
    start)
      [[ "${lines[1]}" =~ ^Started\ recording\ [1-9][0-9]{0,8}\.\ The\ result\ will\ be\ written\ to:$ ]]
      ;;
    stop)
      if [[ -n "$expected_size_bytes" ]]; then
        expected_formatted_size="$(jfr_formatted_size_bytes \
          "$expected_size_bytes")" || return 1
        [[ "${lines[1]}" == \
          "Stopped recording \"${recording_name}\", ${expected_formatted_size} written to:" ]]
      else
        stop_regex="^Stopped recording \"${recording_name}\", ((1 byte)|([1-9][0-9]{0,8} bytes)|([1-9][0-9]{0,7}\\.[0-9] (kB|MB))) written to:$"
        [[ "${lines[1]}" =~ $stop_regex ]]
      fi
      ;;
    *) return 1 ;;
  esac
}

validate_jfr_command_output() {
  local -r artifact="$1"
  local -r action="$2"
  local -r recording_name="$3"
  local -r recording_path="$4"
  local -r expected_size_bytes="${5:-}"
  local artifact_value=""

  capture_bounded_regular_file_value \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES" artifact_value || return 1
  validate_jfr_command_output_value "$artifact_value" "$action" \
    "$recording_name" "$recording_path" "$expected_size_bytes"
}

validate_bootstrap_jfr_discard_value() {
  local -r artifact_value="$1"
  local raw_value_count=""

  raw_value_count="$(raw_json_value_count_from_value "$artifact_value")" || return 1
  [[ "$raw_value_count" == 5 ]] || return 1
  printf '%s' "$artifact_value" | jq -se --argjson maximum_size_bytes "$MAX_JFR_BYTES" '
    length == 1 and (.[0] |
      (keys) == [
        "discard_semantics", "schema_version", "sha256", "size_bytes", "status"
      ] and
      .schema_version == 1 and .status == "discarded" and
      .discard_semantics == "atomic_move_then_descriptor_bounded_delete" and
      (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.size_bytes | type == "number" and isfinite and floor == . and
        . > 0 and . <= $maximum_size_bytes))
  ' >/dev/null
}

validate_bootstrap_jfr_discard() {
  local -r artifact="$1"
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES")" || return 1
  validate_bootstrap_jfr_discard_value "$artifact_value"
}

validate_nmt_baseline_output_value() {
  local -r artifact_value="$1"

  [[ "$artifact_value" == $'1:\nBaseline taken\n' ]]
}

validate_nmt_baseline_output() {
  local -r artifact="$1"
  local artifact_value=""

  capture_bounded_regular_file_value \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES" artifact_value || return 1
  validate_nmt_baseline_output_value "$artifact_value"
}

validate_runtime_identity_only_output_value() {
  local -r artifact_value="$1"

  [[ "$artifact_value" == $'status=runtime-identity-only\n' ]]
}

validate_runtime_identity_only_output() {
  local -r artifact="$1"
  local artifact_value=""

  capture_bounded_regular_file_value \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES" artifact_value || return 1
  validate_runtime_identity_only_output_value "$artifact_value"
}

canonical_utc_rfc3339_nano() {
  local timestamp=""
  local base=""
  local fraction=""

  timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" || return 1
  [[ "$timestamp" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})\.([0-9]{9})Z$ ]] || return 1
  base="${BASH_REMATCH[1]}"
  fraction="${BASH_REMATCH[2]}"
  while [[ -n "$fraction" && "${fraction: -1}" == 0 ]]; do
    fraction="${fraction::-1}"
  done
  if [[ -n "$fraction" ]]; then
    printf '%s.%sZ\n' "$base" "$fraction"
  else
    printf '%sZ\n' "$base"
  fi
}

java_measurement_evidence_json() {
  local -r root="$1"
  local -r cell="$2"
  local -r started_at="$3"
  local -r stop_initiated_at="$4"
  local -r identity="$root/identity.txt"
  local -r jfr="$root/measurement.jfr"
  local -r jfr_summary="$root/operations/08-jfr-summary/output"
  local -r baseline_diff="$root/operations/04-nmt-baseline-confirmation/output"
  local -r baseline_runtime="$root/operations/05-runtime-baseline/runtime-after.json"
  local -r postload_summary="$root/operations/10-nmt-postload-summary/output"
  local -r postload_diff="$root/operations/11-nmt-postload-diff/output"
  local -r postload_runtime="$root/operations/12-runtime-postload/runtime-after.json"
  local -r runtime_artifacts="$root/runtime-artifacts.json"
  local host_pid=""
  local proc_start_time=""
  local proc_cgroup_sha256=""
  local proc_cgroup_binding=""
  local identity_sha256=""
  local jfr_sha256=""
  local jfr_size=""
  local baseline_current_reserved=""
  local baseline_current_committed=""
  local baseline_reserved_delta=""
  local baseline_committed_delta=""
  local baseline_reserved=""
  local baseline_committed=""
  local postload_summary_reserved=""
  local postload_summary_committed=""
  local postload_reserved=""
  local postload_committed=""
  local postload_reserved_delta=""
  local postload_committed_delta=""
  local reconstructed_reserved=""
  local reconstructed_committed=""
  local baseline_direct_count=""
  local baseline_direct_used=""
  local baseline_direct_capacity=""
  local postload_direct_count=""
  local postload_direct_used=""
  local postload_direct_capacity=""
  local jfr_json=""
  local runtime_artifacts_json=""
  local runtime_artifacts_sha256=""
  local identity_value=""
  local jfr_summary_value=""
  local baseline_diff_value=""
  local baseline_runtime_value=""
  local postload_summary_value=""
  local postload_diff_value=""
  local postload_runtime_value=""
  local baseline_diff_sha256=""
  local postload_summary_sha256=""
  local postload_diff_sha256=""

  [[ "$cell" =~ ^[a-z][a-z0-9-]*$ && -d "$root" && ! -L "$root" &&
    -f "$identity" && ! -L "$identity" && -f "$jfr" && ! -L "$jfr" ]] || return 1
  validated_java_runtime_artifacts_values "$runtime_artifacts" "$identity" \
    runtime_artifacts_json identity_value runtime_artifacts_sha256 || return 1
  runtime_artifacts_json="$(printf '%s' "$runtime_artifacts_json" | jq -ceS .)" || return 1
  host_pid="$(identity_field_from_value "$identity_value" host_pid)" || return 1
  proc_start_time="$(identity_field_from_value "$identity_value" proc_start_time)" || return 1
  proc_cgroup_sha256="$(identity_field_from_value \
    "$identity_value" proc_cgroup_sha256)" || return 1
  proc_cgroup_binding="$(identity_field_from_value \
    "$identity_value" proc_cgroup_container_binding)" || return 1
  [[ "$host_pid" =~ ^[1-9][0-9]*$ && "$proc_start_time" =~ ^[1-9][0-9]*$ &&
    "$proc_cgroup_sha256" =~ ^[0-9a-f]{64}$ &&
    "$proc_cgroup_binding" == "$PROC_CGROUP_CONTAINER_BINDING" ]] || return 1
  identity_sha256="$(json_value_sha256 "$identity_value")" || return 1
  sha256_regular_file "$jfr" jfr_sha256 jfr_size || return 1
  [[ "$jfr_size" =~ ^[1-9][0-9]*$ ]] || return 1
  ((jfr_size <= MAX_JFR_BYTES)) || return 1
  jfr_summary_value="$(bounded_duplicate_free_json_value \
    "$jfr_summary" "$MAX_JAVA_TOOL_OUTPUT_BYTES")" || return 1
  validate_jfr_summary_value \
    "$jfr_summary_value" "$jfr_size" "$jfr_sha256" || return 1
  jfr_json="$(printf '%s' "$jfr_summary_value" | jq -ceS .)" || return 1

  capture_bounded_regular_file_value \
    "$baseline_diff" "$MAX_JAVA_TOOL_OUTPUT_BYTES" baseline_diff_value || return 1
  capture_bounded_regular_file_value \
    "$postload_summary" "$MAX_JAVA_TOOL_OUTPUT_BYTES" postload_summary_value || return 1
  capture_bounded_regular_file_value \
    "$postload_diff" "$MAX_JAVA_TOOL_OUTPUT_BYTES" postload_diff_value || return 1
  baseline_diff_sha256="$(json_value_sha256 "$baseline_diff_value")" || return 1
  postload_summary_sha256="$(json_value_sha256 "$postload_summary_value")" || return 1
  postload_diff_sha256="$(json_value_sha256 "$postload_diff_value")" || return 1

  read -r baseline_current_reserved baseline_current_committed \
    baseline_reserved_delta baseline_committed_delta < <(
      nmt_summary_diff_totals_from_value "$baseline_diff_value"
    ) || return 1
  baseline_reserved="$((baseline_current_reserved - baseline_reserved_delta))"
  baseline_committed="$((baseline_current_committed - baseline_committed_delta))"
  ((baseline_reserved > 0 && baseline_committed > 0)) || return 1
  read -r postload_summary_reserved postload_summary_committed < <(
    nmt_summary_totals_from_value "$postload_summary_value"
  ) || return 1
  read -r postload_reserved postload_committed postload_reserved_delta \
    postload_committed_delta < <(
      nmt_summary_diff_totals_from_value "$postload_diff_value"
    ) || return 1
  reconstructed_reserved="$((postload_reserved - postload_reserved_delta))"
  reconstructed_committed="$((postload_committed - postload_committed_delta))"
  [[ "$reconstructed_reserved" == "$baseline_reserved" &&
    "$reconstructed_committed" == "$baseline_committed" ]] || return 1

  baseline_runtime_value="$(bounded_duplicate_free_json_value \
    "$baseline_runtime" "$MAX_JAVA_RUNTIME_SNAPSHOT_BYTES")" || return 1
  postload_runtime_value="$(bounded_duplicate_free_json_value \
    "$postload_runtime" "$MAX_JAVA_RUNTIME_SNAPSHOT_BYTES")" || return 1
  validate_java_runtime_snapshot_value \
    "$baseline_runtime_value" "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" || return 1
  validate_java_runtime_snapshot_value \
    "$postload_runtime_value" "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" || return 1
  read -r baseline_direct_count baseline_direct_used baseline_direct_capacity < <(
    printf '%s' "$baseline_runtime_value" | jq -er \
      '.direct_buffer | [.count, .memory_used_bytes, .total_capacity_bytes] | @tsv'
  ) || return 1
  read -r postload_direct_count postload_direct_used postload_direct_capacity < <(
    printf '%s' "$postload_runtime_value" | jq -er \
      '.direct_buffer | [.count, .memory_used_bytes, .total_capacity_bytes] | @tsv'
  ) || return 1
  printf '%s\n%s' "$jfr_json" "$runtime_artifacts_json" | jq -s \
    --arg cell "$cell" \
    --arg started_at "$started_at" \
    --arg stop_initiated_at "$stop_initiated_at" \
    --argjson host_pid "$host_pid" \
    --argjson proc_start_time "$proc_start_time" \
    --arg proc_cgroup_sha256 "$proc_cgroup_sha256" \
    --arg proc_cgroup_binding "$proc_cgroup_binding" \
    --arg identity_sha256 "$identity_sha256" \
    --argjson jvm_start_epoch_millis "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" \
    --arg jfr_sha256 "$jfr_sha256" \
    --argjson jfr_size "$jfr_size" \
    --argjson baseline_reserved "$baseline_reserved" \
    --argjson baseline_committed "$baseline_committed" \
    --argjson postload_summary_reserved "$postload_summary_reserved" \
    --argjson postload_summary_committed "$postload_summary_committed" \
    --argjson postload_reserved "$postload_reserved" \
    --argjson postload_committed "$postload_committed" \
    --argjson postload_reserved_delta "$postload_reserved_delta" \
    --argjson postload_committed_delta "$postload_committed_delta" \
    --arg baseline_diff_sha256 "$baseline_diff_sha256" \
    --arg postload_summary_sha256 "$postload_summary_sha256" \
    --arg postload_diff_sha256 "$postload_diff_sha256" \
    --argjson baseline_direct_count "$baseline_direct_count" \
    --argjson baseline_direct_used "$baseline_direct_used" \
    --argjson baseline_direct_capacity "$baseline_direct_capacity" \
    --argjson postload_direct_count "$postload_direct_count" \
    --argjson postload_direct_used "$postload_direct_used" \
    --argjson postload_direct_capacity "$postload_direct_capacity" \
    --argjson maximum_jfr_bytes "$MAX_JFR_BYTES" \
    --argjson maximum_jfr_records "$MAX_JFR_RECORDS" \
    --argjson maximum_jfr_duration_seconds "$JAVA_JFR_MAX_DURATION_SECONDS" \
    --arg retention_scope "$JAVA_JFR_RETENTION_SCOPE" \
    --arg runtime_artifacts_sha256 "$runtime_artifacts_sha256" '
      if length != 2 then error("expected JFR summary and runtime artifacts")
      else . end |
      .[0] as $jfr |
      .[1] as $runtime_artifacts |
      {
        schema_version: 1,
        kind: "bounded-java-runtime-indicators",
        status: "complete",
        acceptance_evidence: false,
        cell: $cell,
        measurement_window: {
          started_at: $started_at,
          stop_initiated_at: $stop_initiated_at,
          start_boundary: "post_warmup_before_first_measurement_admission",
          stop_boundary: "initiated_immediately_after_final_measurement_client"
        },
        process_binding: {
          service: "java-backend",
          container_pid: 1,
          host_pid: $host_pid,
          proc_start_time: $proc_start_time,
          proc_cgroup_sha256: $proc_cgroup_sha256,
          proc_cgroup_container_binding: $proc_cgroup_binding,
          java_runtime_start_epoch_millis: $jvm_start_epoch_millis,
          canonical_identity_sha256: $identity_sha256
        },
        runtime_artifacts: ($runtime_artifacts + {
          attestation_sha256: $runtime_artifacts_sha256
        }),
        jfr: {
          status: "available",
          raw_private_diagnostic_input: true,
          raw_sha256: $jfr_sha256,
          raw_size_bytes: $jfr_size,
          maximum_size_bytes: $maximum_jfr_bytes,
          maximum_duration_seconds: $maximum_jfr_duration_seconds,
          snapshot_semantics: $jfr.snapshot_semantics,
          retention_scope: $retention_scope,
          whole_window_retention_attested: false,
          stop_reported_size_reconciled: true,
          total_records: $jfr.total_records,
          maximum_records: $maximum_jfr_records,
          allocation_sample: $jfr.allocation_sample,
          java_monitor_enter: $jfr.java_monitor_enter,
          thread_park: $jfr.thread_park,
          data_loss: $jfr.data_loss
        },
        nmt: {
          status: "available",
          tracking_level: "summary",
          baseline: {
            reserved_bytes: $baseline_reserved,
            committed_bytes: $baseline_committed
          },
          post_load_summary_snapshot: {
            reserved_bytes: $postload_summary_reserved,
            committed_bytes: $postload_summary_committed
          },
          post_load_diff_snapshot: {
            reserved_bytes: $postload_reserved,
            committed_bytes: $postload_committed
          },
          non_negative_delta: {
            reserved_bytes: $postload_reserved_delta,
            committed_bytes: $postload_committed_delta
          },
          baseline_confirmation_sha256: $baseline_diff_sha256,
          post_load_summary_sha256: $postload_summary_sha256,
          post_load_diff_sha256: $postload_diff_sha256
        },
        direct_buffer: {
          status: "available",
          baseline: {
            count: $baseline_direct_count,
            memory_used_bytes: $baseline_direct_used,
            total_capacity_bytes: $baseline_direct_capacity
          },
          post_load: {
            count: $postload_direct_count,
            memory_used_bytes: $postload_direct_used,
            total_capacity_bytes: $postload_direct_capacity
          },
          signed_delta: {
            count: ($postload_direct_count - $baseline_direct_count),
            memory_used_bytes: ($postload_direct_used - $baseline_direct_used),
            total_capacity_bytes: ($postload_direct_capacity - $baseline_direct_capacity)
          }
        },
        interpretation: {
          allocation_sample_weight_is_not_an_exact_allocation_count: true,
          nmt_committed_is_a_jvm_native_tracking_indicator_not_process_rss: true,
          direct_buffer_pool_is_not_all_native_or_off_heap_memory: true,
          jfr_retention_may_be_a_bounded_tail_if_the_size_limit_was_reached: true,
          acceptance_evidence: false
        }
      }
    '
}

java_measurement_operation_names() {
  printf '%s\n' \
    01-bootstrap-stop \
    02-bootstrap-discard \
    03-nmt-baseline \
    04-nmt-baseline-confirmation \
    05-runtime-baseline \
    06-jfr-start \
    07-jfr-stop \
    08-jfr-summary \
    10-nmt-postload-summary \
    11-nmt-postload-diff \
    12-runtime-postload
}

validate_java_measurement_tree() (
  local -r root="$1"
  local -r parent="${root%/*}"
  local current_user_id=""
  local operation=""
  local entry=""
  local entry_count=0
  local bootstrap_size=""
  local measurement_size=""
  local measurement_sha256=""
  local canonical_identity_value=""
  local host_identity_value=""
  local bootstrap_discard_value=""
  local work=""
  local all_listing=""
  local root_listing=""
  local operations_listing=""
  local operation_listing=""
  local -a root_entries=()
  local -a operation_entries=()
  local -a expected_operations=(
    01-bootstrap-stop
    02-bootstrap-discard
    03-nmt-baseline
    04-nmt-baseline-confirmation
    05-runtime-baseline
    06-jfr-start
    07-jfr-stop
    08-jfr-summary
    10-nmt-postload-summary
    11-nmt-postload-diff
    12-runtime-postload
  )
  local -a java_tree_observed_files=()
  local -a java_tree_expected_files=(
    host-after-runtime-before.txt
    host-after.txt
    host-before-runtime-after.txt
    host-before.txt
    output
    runtime-after.json
    runtime-before.json
  )

  current_user_id="$(id -u)" || return 1
  is_private_owned_directory "$root" "$current_user_id" || return 1
  is_private_owned_directory "$root/operations" "$current_user_id" || return 1
  [[ -d "$parent" && ! -L "$parent" ]] || return 1
  capture_bounded_regular_file_value \
    "$root/identity.txt" "$MAX_SERVICE_IDENTITY_BYTES" \
    canonical_identity_value || return 1
  validate_service_identity_value \
    "$canonical_identity_value" java-backend || return 1
  work="$(mktemp -d "$parent/.java-tree-validation.XXXXXX")" || return 1
  chmod 0700 -- "$work" || return 1
  all_listing="$work/all.list"
  root_listing="$work/root.list"
  operations_listing="$work/operations.list"
  operation_listing="$work/operation.list"
  trap 'rm -f -- "$all_listing" "$root_listing" "$operations_listing" "$operation_listing"; rmdir -- "$work" 2>/dev/null || true' EXIT
  capture_stable_java_listing "$root" all "$all_listing" || return 1
  while IFS= read -r -d '' entry; do
    ((entry_count += 1))
    ((entry_count <= MAX_JAVA_EVIDENCE_FILES)) || return 1
    [[ ( -f "$entry" && ! -L "$entry" ) || ( -d "$entry" && ! -L "$entry" ) ]] || return 1
  done <"$all_listing"
  capture_stable_java_listing "$root" root "$root_listing" || return 1
  root_entries=()
  while IFS= read -r -d '' entry; do
    root_entries+=("${entry##*/}")
  done <"$root_listing"
  [[ "${root_entries[*]}" == \
    'evidence.json identity.txt measurement.jfr operations runtime-artifacts.json' ]] || return 1
  capture_stable_java_listing "$root/operations" root \
    "$operations_listing" || return 1
  operation_entries=()
  while IFS= read -r -d '' entry; do
    [[ -d "$entry" && ! -L "$entry" ]] || return 1
    operation_entries+=("${entry##*/}")
  done <"$operations_listing"
  [[ "${operation_entries[*]}" == "${expected_operations[*]}" ]] || return 1

  while IFS= read -r operation; do
    [[ -d "$root/operations/$operation" &&
      ! -L "$root/operations/$operation" ]] || return 1
    java_tree_observed_files=()
    rm -f -- "$operation_listing" || return 1
    capture_stable_java_listing "$root/operations/$operation" files \
      "$operation_listing" || return 1
    while IFS= read -r -d '' entry; do
      [[ -f "$entry" && ! -L "$entry" ]] || return 1
      is_private_owned_regular_file "$entry" "$current_user_id" || return 1
      java_tree_observed_files+=("${entry##*/}")
    done <"$operation_listing"
    [[ "${java_tree_observed_files[*]}" == \
      "${java_tree_expected_files[*]}" ]] || return 1
    for entry in host-before.txt host-after-runtime-before.txt \
      host-before-runtime-after.txt host-after.txt; do
      capture_bounded_regular_file_value \
        "$root/operations/$operation/$entry" "$MAX_SERVICE_IDENTITY_BYTES" \
        host_identity_value || return 1
      [[ "$host_identity_value" == "$canonical_identity_value" ]] || return 1
    done
    validate_java_runtime_snapshot \
      "$root/operations/$operation/runtime-before.json" \
      "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" || return 1
    validate_java_runtime_snapshot \
      "$root/operations/$operation/runtime-after.json" \
      "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" || return 1
  done < <(java_measurement_operation_names)
  bootstrap_discard_value="$(bounded_duplicate_free_json_value \
    "$root/operations/02-bootstrap-discard/output" \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES")" || return 1
  validate_bootstrap_jfr_discard_value "$bootstrap_discard_value" || return 1
  bootstrap_size="$(printf '%s' "$bootstrap_discard_value" | jq -ser \
    'if length == 1 then .[0].size_bytes else empty end')" || return 1
  bootstrap_size="$(normalize_decimal "$bootstrap_size" "$MAX_JFR_BYTES" false)" || return 1
  validate_jfr_command_output \
    "$root/operations/01-bootstrap-stop/output" stop \
    "$JAVA_BOOTSTRAP_JFR_NAME" "$JAVA_BOOTSTRAP_JFR_CONTAINER_PATH" \
    "$bootstrap_size" || return 1
  validate_nmt_baseline_output \
    "$root/operations/03-nmt-baseline/output" || return 1
  validate_runtime_identity_only_output \
    "$root/operations/05-runtime-baseline/output" || return 1
  validate_jfr_command_output \
    "$root/operations/06-jfr-start/output" start \
    "$JAVA_MEASUREMENT_JFR_NAME" "$JAVA_MEASUREMENT_JFR_CONTAINER_PATH" || return 1
  sha256_regular_file \
    "$root/measurement.jfr" measurement_sha256 measurement_size || return 1
  [[ "$measurement_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  measurement_size="$(normalize_decimal "$measurement_size" "$MAX_JFR_BYTES" false)" || return 1
  validate_jfr_command_output \
    "$root/operations/07-jfr-stop/output" stop \
    "$JAVA_MEASUREMENT_JFR_NAME" "$JAVA_MEASUREMENT_JFR_CONTAINER_PATH" \
    "$measurement_size" || return 1
  validate_runtime_identity_only_output \
    "$root/operations/12-runtime-postload/output" || return 1
  [[ -f "$root/identity.txt" && ! -L "$root/identity.txt" &&
    -f "$root/runtime-artifacts.json" && ! -L "$root/runtime-artifacts.json" &&
    -f "$root/measurement.jfr" && ! -L "$root/measurement.jfr" &&
    -f "$root/evidence.json" && ! -L "$root/evidence.json" ]] || return 1
  validate_java_runtime_artifacts "$root/runtime-artifacts.json" \
    "$root/identity.txt" &&
    is_private_owned_regular_file "$root/identity.txt" "$current_user_id" &&
    is_private_owned_regular_file "$root/runtime-artifacts.json" "$current_user_id" &&
    is_private_owned_regular_file "$root/measurement.jfr" "$current_user_id" &&
    is_private_owned_regular_file "$root/evidence.json" "$current_user_id"
)

# Hash a canonical, bounded roster of every published Java evidence path and
# every regular file's content. The receipt remains outside this root, so the
# manifest has no self-reference. Stable before/after listings and per-file
# identities make traversal or content drift fail closed.
java_measurement_tree_manifest_sha256() (
  local -r root="$1"
  local -r parent="${root%/*}"
  local work=""
  local listing_before=""
  local listing_after=""
  local manifest=""
  local entry=""
  local relative=""
  local kind=""
  local identity_before=""
  local identity_after=""
  local digest=""
  local root_identity_before=""
  local root_identity_after=""
  local parent_identity_before=""
  local parent_identity_after=""
  local entry_count=0
  local file_count=0
  local directory_count=0
  local manifest_size=""
  local manifest_sha256=""

  [[ "$root" == /* && -d "$root" && ! -L "$root" &&
    "$parent" == /* && -d "$parent" && ! -L "$parent" ]] || return 1
  root_identity_before="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  parent_identity_before="$(stat --format '%d:%i:%u:%a' -- "$parent")" || return 1
  work="$(mktemp -d "$parent/.java-tree-manifest.XXXXXX")" || return 1
  chmod 0700 -- "$work" || return 1
  listing_before="$work/before.list"
  listing_after="$work/after.list"
  manifest="$work/tree.manifest"
  trap 'rm -f -- "$listing_before" "$listing_after" "$manifest"; rmdir -- "$work" 2>/dev/null || true' EXIT
  capture_stable_java_listing "$root" all "$listing_before" || return 1
  : >"$manifest" || return 1
  chmod 0600 -- "$manifest" || return 1
  while IFS= read -r -d '' entry; do
    ((entry_count += 1))
    ((entry_count <= MAX_JAVA_EVIDENCE_FILES)) || return 1
    [[ "$entry" == "$root/"* ]] || return 1
    relative="${entry#"$root/"}"
    is_safe_git_tree_path "$relative" || return 1
    identity_before="$(stat --format '%d:%i:%u:%a:%s' -- "$entry")" || return 1
    if [[ -d "$entry" && ! -L "$entry" ]]; then
      kind='directory'
      digest='-'
      ((directory_count += 1))
    elif [[ -f "$entry" && ! -L "$entry" ]]; then
      kind='file'
      ((file_count += 1))
    else
      return 1
    fi
    if [[ "$kind" == file ]]; then
      digest="$(sha256_regular_file "$entry")" || return 1
    fi
    identity_after="$(stat --format '%d:%i:%u:%a:%s' -- "$entry")" || return 1
    [[ "$identity_after" == "$identity_before" ]] || return 1
    printf '%s\0%s\0%s\0%s\0' \
      "$kind" "$relative" "$identity_before" "$digest" >>"$manifest" || return 1
  done <"$listing_before"
  manifest_size="$(stat --format '%s' -- "$manifest")" || return 1
  [[ "$manifest_size" =~ ^[1-9][0-9]*$ ]] || return 1
  ((manifest_size <= MAX_JAVA_TREE_LISTING_BYTES)) || return 1
  capture_stable_java_listing "$root" all "$listing_after" || return 1
  cmp -s -- "$listing_before" "$listing_after" || return 1
  root_identity_after="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  parent_identity_after="$(stat --format '%d:%i:%u:%a' -- "$parent")" || return 1
  [[ "$root_identity_after" == "$root_identity_before" &&
    "$parent_identity_after" == "$parent_identity_before" ]] || return 1
  ((entry_count == file_count + directory_count && file_count > 0)) || return 1
  manifest_sha256="$(sha256_regular_file "$manifest")" || return 1
  [[ "$manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    terminal_record_java_tree_authority "$root" "$entry_count" "$file_count" \
      "$directory_count" "$manifest_size" "$manifest_sha256" \
      "$parent_identity_before" "$root_identity_before" || return 1
  fi
  printf '%s' "$manifest_sha256"
)

validated_java_measurement_evidence_json_value() {
  local -r artifact="$1"
  local -r output_name="${2:-}"
  local -r digest_output_name="${3:-}"
  local -r root="${artifact%/*}"
  local cell=""
  local expected_cell=""
  local started_at=""
  local stop_initiated_at=""
  local expected_json=""
  local expected_raw_value_count=""
  local observed_raw_value_count=""
  local captured_evidence_value=""
  local captured_evidence_identity=""
  local captured_evidence_size=""
  local captured_evidence_digest=""

  [[ "$artifact" == "$root/evidence.json" ]] || return 1
  bounded_duplicate_free_json_image \
    "$artifact" "$MAX_JAVA_TOOL_OUTPUT_BYTES" \
    captured_evidence_value captured_evidence_identity \
    captured_evidence_size captured_evidence_digest || return 1
  [[ "$captured_evidence_identity" == *:* &&
    "$captured_evidence_size" =~ ^[1-9][0-9]*$ &&
    "$captured_evidence_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  cell="$(printf '%s' "$captured_evidence_value" | jq -ser \
    'if length == 1 then .[0].cell else empty end')" || return 1
  expected_cell="${root%/*}"
  expected_cell="${expected_cell##*/}"
  [[ "$cell" == "$expected_cell" ]] || return 1
  started_at="$(printf '%s' "$captured_evidence_value" | jq -ser \
    'if length == 1 then .[0].measurement_window.started_at else empty end' \
    )" || return 1
  stop_initiated_at="$(printf '%s' "$captured_evidence_value" | jq -ser \
    'if length == 1 then .[0].measurement_window.stop_initiated_at else empty end' \
    )" || return 1
  JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS="$(printf '%s' "$captured_evidence_value" | jq -ser '
    if length == 1 then
      .[0].process_binding.java_runtime_start_epoch_millis | tostring
    else empty end
  ')" || return 1
  JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS="$(normalize_decimal \
    "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" "$MAX_SEED" false)" || return 1
  validate_java_measurement_tree "$root" || return 1
  printf '%s' "$captured_evidence_value" | jq -se '
    def timestamp_parts:
      capture("^(?<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\\.(?<fraction>[0-9]{0,8}[1-9]))?Z$") as $parts |
      ($parts.base + "Z" | fromdateiso8601) as $seconds |
      select($seconds > 0) |
      select(($seconds | todateiso8601) == ($parts.base + "Z")) |
      [$seconds, (((($parts.fraction // "") + "000000000")[0:9]) | tonumber)];
    length == 1 and (.[0] |
      (.measurement_window.started_at | timestamp_parts) as $started |
      (.measurement_window.stop_initiated_at | timestamp_parts) as $stopped |
      $started <= $stopped)
  ' >/dev/null || return 1
  expected_json="$(java_measurement_evidence_json \
    "$root" "$cell" "$started_at" "$stop_initiated_at")" || return 1
  expected_raw_value_count="$(jq --stream -n '
    reduce inputs as $event (0;
      if ($event | length) == 2 then . + 1 else . end)
  ' <<<"$expected_json")" || return 1
  observed_raw_value_count="$(raw_json_value_count_from_value \
    "$captured_evidence_value")" || return 1
  [[ "$expected_raw_value_count" =~ ^[1-9][0-9]*$ &&
    "$observed_raw_value_count" == "$expected_raw_value_count" ]] || return 1
  printf '%s\n%s' "$expected_json" "$captured_evidence_value" | jq -es '
    length == 2 and .[1] == .[0]
  ' >/dev/null || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$captured_evidence_value"
  else
    printf '%s' "$captured_evidence_value"
  fi
  if [[ -n "$digest_output_name" ]]; then
    printf -v "$digest_output_name" '%s' "$captured_evidence_digest"
  fi
}

validate_java_measurement_evidence() {
  local evidence_value=""

  validated_java_measurement_evidence_json_value "$1" evidence_value
}

validate_published_java_measurement() {
  local -r cell_dir="$1"
  local -r output_name="${2:-}"
  local -r root="$cell_dir/java-measurement"
  local -r artifact="$root/evidence.json"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local cell=""
  local current_user_id=""
  local parent_identity_before=""
  local parent_identity_after=""
  local root_identity_before=""
  local root_identity_after=""
  local evidence_sha256=""
  local receipt_sha256=""
  local runtime_artifact_sha256=""
  local tree_manifest_sha256=""
  local tree_manifest_sha256_after=""
  local raw_value_count=""
  local receipt_size=""
  local receipt_identity=""
  local evidence_value=""
  local receipt_value=""
  local captured_java_bundle=""

  java_measurement_cell_is_allowed "$cell_dir" || return 1
  cell="${cell_dir##*/}"
  [[ -d "$root" && ! -L "$root" &&
    -f "$receipt" && ! -L "$receipt" ]] || return 1
  current_user_id="$(id -u)" || return 1
  is_private_owned_regular_file "$receipt" "$current_user_id" || return 1
  bounded_duplicate_free_json_image \
    "$receipt" "$MAX_JAVA_TOOL_OUTPUT_BYTES" \
    receipt_value receipt_identity receipt_size receipt_sha256 || return 1
  [[ "$receipt_identity" == *:* &&
    "$receipt_size" =~ ^[1-9][0-9]*$ ]] || return 1
  ((receipt_size <= MAX_JAVA_TOOL_OUTPUT_BYTES)) || return 1
  parent_identity_before="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  root_identity_before="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  validated_java_measurement_evidence_json_value \
    "$artifact" evidence_value evidence_sha256 || return 1
  runtime_artifact_sha256="$(printf '%s' "$evidence_value" | jq -ser '
    if length == 1 then .[0].runtime_artifacts.attestation_sha256 else empty end
  ')" || return 1
  tree_manifest_sha256="$(java_measurement_tree_manifest_sha256 "$root")" || return 1
  [[ "$evidence_sha256" =~ ^[0-9a-f]{64}$ &&
    "$runtime_artifact_sha256" =~ ^[0-9a-f]{64}$ &&
    "$tree_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  raw_value_count="$(raw_json_value_count_from_value "$receipt_value")" || return 1
  [[ "$raw_value_count" == 10 ]] || return 1
  printf '%s' "$receipt_value" | jq -se \
    --arg cell "$cell" \
    --arg parent_identity "$parent_identity_before" \
    --arg root_identity "$root_identity_before" \
    --arg evidence_sha256 "$evidence_sha256" \
    --arg runtime_artifact_sha256 "$runtime_artifact_sha256" \
    --arg tree_manifest_sha256 "$tree_manifest_sha256" '
      length == 1 and (.[0] |
        (keys) == [
          "acceptance_evidence", "cell", "evidence_sha256", "kind",
          "parent_identity", "root_identity",
          "runtime_artifact_attestation_sha256", "schema_version", "status",
          "tree_manifest_sha256"
        ] and
        .schema_version == 2 and
        .kind == "bounded-java-runtime-indicators-publication" and
        .status == "sealed" and .acceptance_evidence == false and
        .cell == $cell and .parent_identity == $parent_identity and
        .root_identity == $root_identity and
        .evidence_sha256 == $evidence_sha256 and
        .runtime_artifact_attestation_sha256 == $runtime_artifact_sha256 and
        .tree_manifest_sha256 == $tree_manifest_sha256)
    ' >/dev/null || return 1
  tree_manifest_sha256_after="$(java_measurement_tree_manifest_sha256 "$root")" || return 1
  parent_identity_after="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  root_identity_after="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  [[ "$parent_identity_after" == "$parent_identity_before" &&
    "$root_identity_after" == "$root_identity_before" &&
    "$tree_manifest_sha256_after" == "$tree_manifest_sha256" ]] || return 1
  if [[ -n "$output_name" ]]; then
    captured_java_bundle="$(printf '%s\n%s' "$evidence_value" "$receipt_value" | jq -cs \
      --arg evidence_sha256 "$evidence_sha256" \
      --arg receipt_sha256 "$receipt_sha256" \
      --arg tree_manifest_sha256 "$tree_manifest_sha256" \
      --arg runtime_artifact_sha256 "$runtime_artifact_sha256" '
        if length != 2 then error("expected Java evidence and publication receipt")
        else {
          evidence: .[0], receipt: .[1],
          evidence_sha256: $evidence_sha256,
          receipt_sha256: $receipt_sha256,
          tree_manifest_sha256: $tree_manifest_sha256,
          runtime_artifact_attestation_sha256: $runtime_artifact_sha256
        } end
      ')" || return 1
    printf -v "$output_name" '%s' "$captured_java_bundle"
  fi
}

terminal_java_measurement_sources_are_capturable() {
  local -r cell_dir="$1"
  local -r root="$cell_dir/java-measurement"
  local -r evidence="$root/evidence.json"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local expected_state=""
  local receipt_value=""
  local evidence_value=""
  local classification_status=0

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false && "$cell_dir" == /* ]] || return 2
  if [[ ! -e "$root" && ! -L "$root" ]]; then
    expected_state=absent
  elif [[ -L "$root" || ! -d "$root" ]]; then
    expected_state=nonregular
  fi
  if [[ -n "$expected_state" ]]; then
    terminal_record_source_negative \
      "$root" "$MAX_JAVA_TOOL_OUTPUT_BYTES" "$expected_state" || return 2
    return 1
  fi
  if terminal_optional_source_is_capturable \
    "$receipt" "$MAX_JAVA_TOOL_OUTPUT_BYTES"; then
    capture_bounded_regular_file_value \
      "$receipt" "$MAX_JAVA_TOOL_OUTPUT_BYTES" receipt_value || return 2
  else
    classification_status=$?
    ((classification_status == 1)) || return 2
    return 1
  fi
  if terminal_optional_source_is_capturable \
    "$evidence" "$MAX_JAVA_TOOL_OUTPUT_BYTES"; then
    capture_bounded_regular_file_value \
      "$evidence" "$MAX_JAVA_TOOL_OUTPUT_BYTES" evidence_value || return 2
  else
    classification_status=$?
    ((classification_status == 1)) || return 2
    return 1
  fi
  [[ -n "$receipt_value" && -n "$evidence_value" ]]
}

write_java_measurement_publication_receipt() {
  local -r cell_dir="$1"
  local -r root="$cell_dir/java-measurement"
  local -r artifact="$root/evidence.json"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local evidence_sha256=""
  local runtime_artifact_sha256=""
  local tree_manifest_sha256=""
  local tree_manifest_sha256_after=""
  local temporary=""

  [[ "$cell_dir" == "$JAVA_MEASUREMENT_CELL_DIR" &&
    -d "$root" && ! -L "$root" &&
    ! -e "$receipt" && ! -L "$receipt" ]] || return 1
  java_measurement_root_identity_matches "$root" published || return 1
  validate_java_measurement_evidence "$artifact" || return 1
  evidence_sha256="$(sha256_regular_file "$artifact")" || return 1
  runtime_artifact_sha256="$(jq -ser '
    if length == 1 then .[0].runtime_artifacts.attestation_sha256 else empty end
  ' "$artifact")" || return 1
  tree_manifest_sha256="$(java_measurement_tree_manifest_sha256 "$root")" || return 1
  [[ "$evidence_sha256" =~ ^[0-9a-f]{64}$ &&
    "$runtime_artifact_sha256" == "$JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256" &&
    "$tree_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  temporary="$(mktemp "$cell_dir/.java-measurement-publication.json.XXXXXX")" || return 1
  if ! jq -n \
    --arg cell "$CELL_SLUG" \
    --arg parent_identity "$JAVA_MEASUREMENT_PARENT_IDENTITY" \
    --arg root_identity "$JAVA_MEASUREMENT_ROOT_IDENTITY" \
    --arg evidence_sha256 "$evidence_sha256" \
    --arg runtime_artifact_sha256 "$runtime_artifact_sha256" \
    --arg tree_manifest_sha256 "$tree_manifest_sha256" '
      {
        schema_version: 2,
        kind: "bounded-java-runtime-indicators-publication",
        status: "sealed",
        acceptance_evidence: false,
        cell: $cell,
        parent_identity: $parent_identity,
        root_identity: $root_identity,
        evidence_sha256: $evidence_sha256,
        runtime_artifact_attestation_sha256: $runtime_artifact_sha256,
        tree_manifest_sha256: $tree_manifest_sha256
      }
    ' >"$temporary" || ! chmod 0600 -- "$temporary" ||
    ! java_measurement_root_identity_matches "$root" published; then
    rm -f -- "$temporary"
    return 1
  fi
  tree_manifest_sha256_after="$(java_measurement_tree_manifest_sha256 "$root")" || {
    rm -f -- "$temporary"
    return 1
  }
  if [[ "$tree_manifest_sha256_after" != "$tree_manifest_sha256" ]] ||
    ! mv -T -- "$temporary" "$receipt" ||
    ! java_measurement_root_identity_matches "$root" published ||
    ! validate_published_java_measurement "$cell_dir"; then
    rm -f -- "$temporary"
    return 1
  fi
}

publish_java_measurement_tree() {
  local -r partial="$1"
  local -r final="$2"

  [[ "$partial" == "$JAVA_MEASUREMENT_PARTIAL" &&
    "$final" == "$JAVA_MEASUREMENT_CELL_DIR/java-measurement" &&
    ! -e "$final" && ! -L "$final" ]] || return 1
  java_measurement_root_identity_matches "$partial" partial || return 1
  mv -T -- "$partial" "$final" || return 1
  java_measurement_root_identity_matches "$final" published
}

quarantine_failed_java_measurement_publication() (
  local -r cell_dir="$1"
  local -r final="$cell_dir/java-measurement"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local -r rejected="$cell_dir/.java-measurement.rejected"
  local -r rejected_receipt="$cell_dir/.java-measurement-publication.rejected.json"
  local observed_parent_identity=""

  java_measurement_cell_is_allowed "$cell_dir" || return 1
  observed_parent_identity="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  [[ "$observed_parent_identity" == "$JAVA_MEASUREMENT_PARENT_IDENTITY" ]] || return 1
  if [[ -e "$final" || -L "$final" ]]; then
    [[ ! -e "$rejected" && ! -L "$rejected" ]] || return 1
    mv -T --no-clobber -- "$final" "$rejected" || return 1
    [[ ! -e "$final" && ! -L "$final" &&
      ( -e "$rejected" || -L "$rejected" ) ]] || return 1
  fi
  if [[ -e "$receipt" || -L "$receipt" ]]; then
    [[ ! -e "$rejected_receipt" && ! -L "$rejected_receipt" ]] || return 1
    mv -T --no-clobber -- "$receipt" "$rejected_receipt" || return 1
    [[ ! -e "$receipt" && ! -L "$receipt" &&
      ( -e "$rejected_receipt" || -L "$rejected_receipt" ) ]] || return 1
  fi
  [[ ! -e "$final" && ! -L "$final" &&
    ! -e "$receipt" && ! -L "$receipt" ]]
)

java_measurement_cell_is_allowed() {
  local -r cell_dir="$1"
  local cell=""
  local allowed=""

  [[ "$OUTPUT_DIR" == /* && "$cell_dir" == "$OUTPUT_DIR/cells/"* &&
    "$cell_dir" != *$'\n'* && "$cell_dir" != *$'\r'* &&
    "$cell_dir" != *'//' && "$cell_dir" != *'/./'* &&
    "$cell_dir" != *'/../'* && "$cell_dir" != */. && "$cell_dir" != */.. ]] || return 1
  cell="${cell_dir#"$OUTPUT_DIR/cells/"}"
  [[ "$cell" != */* ]] || return 1
  for allowed in "${CORE_CELLS[@]}"; do
    [[ "$cell" == "$allowed" ]] && return 0
  done
  return 1
}

clear_active_java_measurement() {
  JAVA_MEASUREMENT_PARTIAL=""
  JAVA_MEASUREMENT_CELL_DIR=""
  JAVA_MEASUREMENT_PARENT_IDENTITY=""
  JAVA_MEASUREMENT_ROOT_IDENTITY=""
  JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS=""
  JAVA_MEASUREMENT_STARTED_AT=""
  JAVA_MEASUREMENT_STOP_INITIATED_AT=""
  JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256=""
}

discard_java_measurement_partial() (
  local -r partial="$1"
  local -r cell_dir="$2"
  local -r expected_parent_identity="$3"
  local -r expected_root_identity="$4"
  local observed_parent_identity=""
  local observed_root_identity=""
  local entry=""
  local entry_count=0
  local work=""
  local listing=""

  java_measurement_cell_is_allowed "$cell_dir" || return 1
  [[ "$partial" == "$cell_dir/.java-measurement.partial" &&
    "$expected_parent_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    "$expected_root_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    ! -e "$cell_dir/java-measurement" && ! -L "$cell_dir/java-measurement" ]] || return 1
  observed_parent_identity="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  [[ "$observed_parent_identity" == "$expected_parent_identity" ]] || return 1
  if [[ ! -e "$partial" && ! -L "$partial" ]]; then
    return 0
  fi
  [[ -d "$partial" && ! -L "$partial" ]] || return 1
  observed_root_identity="$(stat --format '%d:%i:%u:%a' -- "$partial")" || return 1
  [[ "$observed_root_identity" == "$expected_root_identity" ]] || return 1
  work="$(mktemp -d "$cell_dir/.java-partial-discard.XXXXXX")" || return 1
  chmod 0700 -- "$work" || return 1
  listing="$work/entries.list"
  trap 'rm -f -- "$listing"; rmdir -- "$work" 2>/dev/null || true' EXIT
  capture_stable_java_listing "$partial" all "$listing" || return 1
  while IFS= read -r -d '' entry; do
    ((entry_count += 1))
    ((entry_count <= MAX_JAVA_EVIDENCE_FILES)) || return 1
    [[ ( -f "$entry" && ! -L "$entry" ) || ( -d "$entry" && ! -L "$entry" ) ||
      -L "$entry" ]] || return 1
  done <"$listing"
  observed_parent_identity="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  observed_root_identity="$(stat --format '%d:%i:%u:%a' -- "$partial")" || return 1
  [[ "$observed_parent_identity" == "$expected_parent_identity" &&
    "$observed_root_identity" == "$expected_root_identity" ]] || return 1
  find -P "$partial" -xdev -mindepth 1 \( -type f -o -type l \) -delete || return 1
  observed_root_identity="$(stat --format '%d:%i:%u:%a' -- "$partial")" || return 1
  [[ "$observed_root_identity" == "$expected_root_identity" ]] || return 1
  find -P "$partial" -xdev -mindepth 1 -depth -type d -empty -delete || return 1
  observed_parent_identity="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  observed_root_identity="$(stat --format '%d:%i:%u:%a' -- "$partial")" || return 1
  [[ "$observed_parent_identity" == "$expected_parent_identity" &&
    "$observed_root_identity" == "$expected_root_identity" ]] || return 1
  rmdir -- "$partial" || return 1
  [[ ! -e "$partial" && ! -L "$partial" &&
    ! -e "$cell_dir/java-measurement" && ! -L "$cell_dir/java-measurement" ]]
)

discard_active_java_measurement() {
  local -r partial="$JAVA_MEASUREMENT_PARTIAL"
  local -r cell_dir="$JAVA_MEASUREMENT_CELL_DIR"
  local -r parent_identity="$JAVA_MEASUREMENT_PARENT_IDENTITY"
  local -r root_identity="$JAVA_MEASUREMENT_ROOT_IDENTITY"
  local discard_status=0

  if [[ -n "$partial" || -n "$cell_dir" || -n "$parent_identity" ||
    -n "$root_identity" ]]; then
    discard_java_measurement_partial \
      "$partial" "$cell_dir" "$parent_identity" "$root_identity" || discard_status=1
  fi
  clear_active_java_measurement
  return "$discard_status"
}

write_java_measurement_status() {
  local -r cell_dir="$1"
  local -r stage="$2"
  local -r classification="$3"
  local -r output="$cell_dir/java-measurement-status.json"
  local temporary=""
  local status=""

  java_measurement_cell_is_allowed "$cell_dir" || return 1
  case "$stage" in
    post_warmup_preflight|post_warmup_baseline|post_load_stop|post_load_collection) ;;
    *) return 1 ;;
  esac
  case "$classification" in
    infrastructure_unavailable) status="unavailable" ;;
    measurement_contract_failed) status="failed" ;;
    *) return 1 ;;
  esac
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "$cell_dir/.java-measurement-status.json.XXXXXX")" || return 1
  if ! jq -n --arg cell "$CELL_SLUG" --arg stage "$stage" \
    --arg status "$status" --arg classification "$classification" '
    {
      schema_version: 1,
      kind: "bounded-java-runtime-indicators",
      status: $status,
      cell: $cell,
      stage: $stage,
      classification: $classification,
      acceptance_evidence: false
    }
  ' >"$temporary" || ! chmod 0600 -- "$temporary" ||
    ! mv -T -- "$temporary" "$output"; then
    rm -f -- "$temporary" "$output"
    return 1
  fi
}

begin_java_measurement_with_classification() {
  local -r cell_dir="$1"

  if ! java_measurement_facilities_available "$cell_dir"; then
    write_java_measurement_status \
      "$cell_dir" post_warmup_preflight infrastructure_unavailable || true
    return 1
  fi
  if ! begin_java_measurement "$cell_dir"; then
    write_java_measurement_status \
      "$cell_dir" post_warmup_baseline measurement_contract_failed || true
    return 1
  fi
}

stop_java_measurement_with_classification() {
  local -r cell_dir="$1"

  if ! stop_java_measurement "$cell_dir"; then
    write_java_measurement_status \
      "$cell_dir" post_load_stop measurement_contract_failed || true
    return 1
  fi
}

finish_java_measurement_with_classification() {
  local -r cell_dir="$1"

  if ! finish_java_measurement "$cell_dir"; then
    quarantine_failed_java_measurement_publication "$cell_dir" || true
    write_java_measurement_status \
      "$cell_dir" post_load_collection measurement_contract_failed || true
    return 1
  fi
}

begin_java_measurement() {
  local -r cell_dir="$1"
  local -r partial="$cell_dir/.java-measurement.partial"
  local -r final="$cell_dir/java-measurement"
  local -r expected_suffix=" -XX:NativeMemoryTracking=summary -XX:StartFlightRecording=name=${JAVA_BOOTSTRAP_JFR_NAME},settings=${JAVA_BENCHMARK_JFR_SETTINGS},filename=${JAVA_BOOTSTRAP_JFR_CONTAINER_PATH},disk=true,dumponexit=false,duration=${JAVA_JFR_MAX_DURATION_SECONDS}s,maxsize=32m"
  local output=""
  local parent_identity=""
  local parent_identity_after=""
  local root_identity=""
  local bootstrap_size=""

  java_measurement_cell_is_allowed "$cell_dir" || return 1
  [[ "$CELL_BOUNDED_PATH" == false && "$JAVA_IMAGE_TARGET" == "$JAVA_BENCHMARK_IMAGE_TARGET" &&
    "$JAVA_BACKEND_IMAGE" == "$JAVA_BENCHMARK_IMAGE_TAG" &&
    "$JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX" == "$expected_suffix" &&
    -z "$JAVA_MEASUREMENT_PARTIAL" &&
    ! -e "$partial" && ! -L "$partial" &&
    ! -e "$final" && ! -L "$final" ]] || return 1
  validate_benchmark_jfr_settings_source \
    "$JAVA_BENCHMARK_JFR_SETTINGS_CHECKOUT" || return 1
  parent_identity="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  mkdir --mode=0700 -- "$partial" "$partial/operations" || return 1
  root_identity="$(stat --format '%d:%i:%u:%a' -- "$partial")" || return 1
  parent_identity_after="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  [[ "$parent_identity_after" == "$parent_identity" ]] || return 1
  JAVA_MEASUREMENT_CELL_DIR="$cell_dir"
  JAVA_MEASUREMENT_PARTIAL="$partial"
  JAVA_MEASUREMENT_PARENT_IDENTITY="$parent_identity"
  JAVA_MEASUREMENT_ROOT_IDENTITY="$root_identity"
  JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS=""
  JAVA_MEASUREMENT_STARTED_AT=""
  JAVA_MEASUREMENT_STOP_INITIATED_AT=""
  JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256=""
  java_measurement_root_identity_matches "$partial" partial || return 1
  capture_service_identity java-backend "$partial/identity.txt" || return 1
  chmod 0600 -- "$partial/identity.txt" || return 1
  capture_java_runtime_artifacts \
    "$partial" "$partial/runtime-artifacts.json" || return 1
  JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256="$(sha256_regular_file \
    "$partial/runtime-artifacts.json")" || return 1
  java_measurement_root_identity_matches "$partial" partial || return 1

  run_java_bound_operation "$partial" 01-bootstrap-stop \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jcmd \
    JFR.stop "name=$JAVA_BOOTSTRAP_JFR_NAME" || return 1
  output="$partial/operations/01-bootstrap-stop/output"
  validate_jfr_command_output "$output" stop \
    "$JAVA_BOOTSTRAP_JFR_NAME" "$JAVA_BOOTSTRAP_JFR_CONTAINER_PATH" || return 1

  run_java_bound_operation "$partial" 02-bootstrap-discard \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" exec \
    "${JAVA_BENCHMARK_TOOL_ENV[@]}" \
      java --add-modules jdk.attach,jdk.management,jdk.jfr \
      -jar "$JAVA_BENCHMARK_TOOL_JAR" \
      discard-bootstrap-jfr "$MAX_JFR_BYTES" || return 1
  validate_bootstrap_jfr_discard \
    "$partial/operations/02-bootstrap-discard/output" || return 1
  bootstrap_size="$(jq -ser \
    'if length == 1 then .[0].size_bytes else empty end' \
    "$partial/operations/02-bootstrap-discard/output")" || return 1
  bootstrap_size="$(normalize_decimal "$bootstrap_size" "$MAX_JFR_BYTES" false)" || return 1
  validate_jfr_command_output "$output" stop \
    "$JAVA_BOOTSTRAP_JFR_NAME" "$JAVA_BOOTSTRAP_JFR_CONTAINER_PATH" \
    "$bootstrap_size" || return 1

  run_java_bound_operation "$partial" 03-nmt-baseline \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jcmd VM.native_memory baseline || return 1
  output="$partial/operations/03-nmt-baseline/output"
  validate_nmt_baseline_output "$output" || return 1

  run_java_bound_operation "$partial" 04-nmt-baseline-confirmation \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jcmd \
    VM.native_memory summary.diff scale=1 || return 1
  nmt_summary_diff_totals \
    "$partial/operations/04-nmt-baseline-confirmation/output" >/dev/null || return 1

  run_java_bound_operation "$partial" 05-runtime-baseline \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" runtime || return 1

  run_java_bound_operation "$partial" 06-jfr-start \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jcmd \
    JFR.start "name=$JAVA_MEASUREMENT_JFR_NAME" \
    "settings=$JAVA_BENCHMARK_JFR_SETTINGS" \
    "filename=$JAVA_MEASUREMENT_JFR_CONTAINER_PATH" disk=true dumponexit=false \
    "duration=${JAVA_JFR_MAX_DURATION_SECONDS}s" \
    maxsize=32m || return 1
  output="$partial/operations/06-jfr-start/output"
  validate_jfr_command_output "$output" start \
    "$JAVA_MEASUREMENT_JFR_NAME" "$JAVA_MEASUREMENT_JFR_CONTAINER_PATH" || return 1
  JAVA_MEASUREMENT_STARTED_AT="$(canonical_utc_rfc3339_nano)" || return 1
  java_measurement_root_identity_matches "$partial" partial
}

finish_java_measurement() {
  local -r cell_dir="$1"
  local -r partial="$JAVA_MEASUREMENT_PARTIAL"
  local -r final="$cell_dir/java-measurement"
  local output=""
  local jfr_size=""
  local jfr_sha256=""
  local temporary=""
  local runtime_artifacts_after="$partial/runtime-artifacts-after.json"

  [[ "$cell_dir" == "$JAVA_MEASUREMENT_CELL_DIR" &&
    "$partial" == "$cell_dir/.java-measurement.partial" &&
    -d "$partial" && ! -L "$partial" &&
    -n "$JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS" &&
    -n "$JAVA_MEASUREMENT_STARTED_AT" &&
    -n "$JAVA_MEASUREMENT_STOP_INITIATED_AT" &&
    ! -e "$final" && ! -L "$final" ]] || return 1
  java_measurement_root_identity_matches "$partial" partial || return 1
  capture_java_runtime_artifacts "$partial" "$runtime_artifacts_after" || return 1
  cmp -s -- "$partial/runtime-artifacts.json" "$runtime_artifacts_after" || return 1
  [[ "$(sha256_regular_file "$runtime_artifacts_after")" == \
    "$JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256" ]] || return 1
  rm -f -- "$runtime_artifacts_after" || return 1
  java_measurement_root_identity_matches "$partial" partial || return 1

  run_java_bound_operation "$partial" 08-jfr-summary \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jfr \
    "${JAVA_BENCHMARK_TOOL_ENV[@]}" \
      java --add-modules jdk.attach,jdk.management,jdk.jfr \
      -jar "$JAVA_BENCHMARK_TOOL_JAR" \
      jfr-snapshot "$JAVA_MEASUREMENT_JFR_CONTAINER_PATH" \
      "$MAX_JFR_BYTES" "$MAX_JFR_RECORDS" || return 1
  mv -T -- "$partial/operations/08-jfr-summary/raw-output" \
    "$partial/measurement.jfr" || return 1
  jfr_size="$(stat --format '%s' -- "$partial/measurement.jfr")" || return 1
  [[ "$jfr_size" =~ ^[1-9][0-9]*$ ]] || return 1
  ((jfr_size <= MAX_JFR_BYTES)) || return 1
  jfr_sha256="$(sha256_regular_file "$partial/measurement.jfr")" || return 1
  validate_jfr_summary \
    "$partial/operations/08-jfr-summary/output" "$jfr_size" "$jfr_sha256" || return 1
  validate_jfr_command_output \
    "$partial/operations/07-jfr-stop/output" stop \
    "$JAVA_MEASUREMENT_JFR_NAME" "$JAVA_MEASUREMENT_JFR_CONTAINER_PATH" \
    "$jfr_size" || return 1

  run_java_bound_operation "$partial" 10-nmt-postload-summary \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jcmd VM.native_memory summary scale=1 || return 1
  nmt_summary_totals \
    "$partial/operations/10-nmt-postload-summary/output" >/dev/null || return 1
  run_java_bound_operation "$partial" 11-nmt-postload-diff \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jcmd VM.native_memory summary.diff scale=1 || return 1
  nmt_summary_diff_totals \
    "$partial/operations/11-nmt-postload-diff/output" >/dev/null || return 1
  run_java_bound_operation "$partial" 12-runtime-postload \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" runtime || return 1

  temporary="$(mktemp "$partial/.evidence.json.XXXXXX")" || return 1
  if ! java_measurement_evidence_json \
    "$partial" "$CELL_SLUG" "$JAVA_MEASUREMENT_STARTED_AT" \
    "$JAVA_MEASUREMENT_STOP_INITIATED_AT" \
    >"$temporary" || ! chmod 0600 -- "$temporary" ||
    ! mv -T -- "$temporary" "$partial/evidence.json"; then
    rm -f -- "$temporary" "$partial/evidence.json"
    return 1
  fi
  validate_java_measurement_evidence "$partial/evidence.json" || return 1
  java_measurement_root_identity_matches "$partial" partial || return 1
  publish_java_measurement_tree "$partial" "$final" || return 1
  validate_java_measurement_evidence "$final/evidence.json" || return 1
  java_measurement_root_identity_matches "$final" published || return 1
  write_java_measurement_publication_receipt "$cell_dir" || return 1
  validate_published_java_measurement "$cell_dir" || return 1
  clear_active_java_measurement
}

stop_java_measurement() {
  local -r cell_dir="$1"
  local -r partial="$JAVA_MEASUREMENT_PARTIAL"
  local output=""

  [[ "$cell_dir" == "$JAVA_MEASUREMENT_CELL_DIR" &&
    "$partial" == "$cell_dir/.java-measurement.partial" &&
    -d "$partial" && ! -L "$partial" &&
    -n "$JAVA_MEASUREMENT_STARTED_AT" &&
    -z "$JAVA_MEASUREMENT_STOP_INITIATED_AT" ]] || return 1
  java_measurement_root_identity_matches "$partial" partial || return 1
  JAVA_MEASUREMENT_STOP_INITIATED_AT="$(canonical_utc_rfc3339_nano)" || return 1
  run_java_bound_operation "$partial" 07-jfr-stop \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" jcmd \
    JFR.stop "name=$JAVA_MEASUREMENT_JFR_NAME" || return 1
  output="$partial/operations/07-jfr-stop/output"
  validate_jfr_command_output "$output" stop \
    "$JAVA_MEASUREMENT_JFR_NAME" "$JAVA_MEASUREMENT_JFR_CONTAINER_PATH" || return 1
  java_measurement_root_identity_matches "$partial" partial
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

parse_cgroup_v2_path_from_root() {
  local -r proc_root="$1"
  local -r host_pid="$2"
  local -r container_id="$3"
  local -r cgroup_file="$proc_root/$host_pid/cgroup"
  local cgroup_size=""
  local path=""

  [[ "$proc_root" == /* && -d "$proc_root" && ! -L "$proc_root" &&
    "$host_pid" =~ ^[1-9][0-9]*$ && "$container_id" =~ ^[0-9a-f]{64}$ &&
    -f "$cgroup_file" && ! -L "$cgroup_file" ]] || return 1
  cgroup_size="$(wc -c <"$cgroup_file")" || return 1
  [[ "$cgroup_size" =~ ^[1-9][0-9]*$ &&
    "$cgroup_size" -le "$MAX_PROC_CGROUP_BYTES" ]] || return 1
  proc_cgroup_binds_container_id "$cgroup_file" "$container_id" || return 1
  path="$(awk '
    NR == 1 && $0 ~ /^0::\// {
      path = substr($0, 4)
      next
    }
    { invalid = 1 }
    END {
      if (NR != 1 || invalid || path == "") exit 1
      print path
    }
  ' "$cgroup_file")" || return 1
  [[ "$path" == /* && "$path" != *$'\n'* && "$path" != *$'\r'* &&
    "$path" != *//* && "$path" != *'/./'* && "$path" != *'/../'* &&
    "$path" != */. && "$path" != */.. &&
    "$path" =~ ^/[A-Za-z0-9_.:@,+/-]+$ ]] || return 1
  printf '%s\n' "$path"
}

assert_cgroup_path_components() {
  local -r cgroup_root="$1"
  local -r cgroup_path="$2"
  local relative="${cgroup_path#/}"
  local component=""
  local current="$cgroup_root"
  local -a components=()

  [[ "$cgroup_root" == /* && "$cgroup_path" == /* ]] || return 1
  cgroup_directory_reference_is_allowed "$cgroup_root" || return 1
  IFS=/ read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
    current="$current/$component"
    [[ -d "$current" && ! -L "$current" ]] || return 1
  done
}

cgroup_directory_reference_is_allowed() {
  local -r directory="$1"

  [[ -d "$directory" ]] || return 1
  if [[ ! -L "$directory" ]]; then
    return 0
  fi
  [[ "$directory" =~ ^/proc/self/fd/[0-9]+$ ]]
}

capture_cgroup_hierarchy_identity() {
  local -r cgroup_root="$1"
  local -r cgroup_path="$2"
  local -r output="$3"
  local relative="${cgroup_path#/}"
  local component=""
  local current="$cgroup_root"
  local identity=""
  local root_device=""
  local device=""
  local inode=""
  local extra=""
  local temporary=""
  local -a components=()

  [[ "$cgroup_root" == /* && "$cgroup_path" == /* &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  cgroup_directory_reference_is_allowed "$cgroup_root" || return 1
  temporary="$(mktemp "${output%/*}/.cgroup-hierarchy.XXXXXX")" || return 1
  identity="$(stat -L --format '%d %i' -- "$cgroup_root")" || {
    rm -f -- "$temporary"
    return 1
  }
  read -r root_device inode extra <<<"$identity" || {
    rm -f -- "$temporary"
    return 1
  }
  [[ "$root_device" =~ ^[0-9]+$ && "$inode" =~ ^[1-9][0-9]*$ &&
    -z "$extra" ]] || {
    rm -f -- "$temporary"
    return 1
  }
  printf '/\t%s\t%s\n' "$root_device" "$inode" >"$temporary" || {
    rm -f -- "$temporary"
    return 1
  }
  IFS=/ read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || {
      rm -f -- "$temporary"
      return 1
    }
    current="$current/$component"
    [[ -d "$current" && ! -L "$current" ]] || {
      rm -f -- "$temporary"
      return 1
    }
    identity="$(stat -L --format '%d %i' -- "$current")" || {
      rm -f -- "$temporary"
      return 1
    }
    read -r device inode extra <<<"$identity" || {
      rm -f -- "$temporary"
      return 1
    }
    [[ "$device" == "$root_device" && "$inode" =~ ^[1-9][0-9]*$ &&
      -z "$extra" ]] || {
      rm -f -- "$temporary"
      return 1
    }
    printf '%s\t%s\t%s\n' "${current#"$cgroup_root"}" "$device" "$inode" >>"$temporary" || {
      rm -f -- "$temporary"
      return 1
    }
  done
  mv -T -- "$temporary" "$output"
}

capture_cgroup_procs_roster() {
  local -r cgroup_directory="$1"
  local -r output="$2"
  local temporary=""
  local size=""
  local count=""
  local find_status=0

  cgroup_directory_reference_is_allowed "$cgroup_directory" || return 1
  [[
    -f "$cgroup_directory/cgroup.procs" &&
    ! -L "$cgroup_directory/cgroup.procs" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "${output%/*}/.cgroup-procs.XXXXXX")" || return 1
  if ! head -c "$((MAX_CGROUP_PROCS_BYTES + 1))" -- \
      "$cgroup_directory/cgroup.procs" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  size="$(wc -c <"$temporary")" || {
    rm -f -- "$temporary"
    return 1
  }
  if [[ ! "$size" =~ ^[1-9][0-9]*$ ]] ||
    ((size > MAX_CGROUP_PROCS_BYTES)) ||
    ! awk 'NF != 1 || $1 !~ /^[1-9][0-9]*$/ { exit 1 }' "$temporary" ||
    ! sort -n -u -- "$temporary" >"$output"; then
    rm -f -- "$temporary" "$output"
    return 1
  fi
  count="$(wc -l <"$output")" || {
    rm -f -- "$temporary" "$output"
    return 1
  }
  if [[ ! "$count" =~ ^[1-9][0-9]*$ ]] ||
    ((count > MAX_PROCESS_TREE_PIDS)) ||
    [[ "$count" != "$(wc -l <"$temporary")" ]]; then
    rm -f -- "$temporary" "$output"
    return 1
  fi
  rm -f -- "$temporary"
}

capture_numeric_directory_roster() {
  local -r directory="$1"
  local -r expected_type="$2"
  local -r output="$3"
  local temporary=""
  local size=""
  local count=""
  local find_status=0

  [[ -d "$directory" && ! -L "$directory" &&
    ( "$expected_type" == d || "$expected_type" == l ) &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "${output%/*}/.numeric-directory-roster.XXXXXX")" || return 1
  # Bound the directory stream before it reaches either a shell variable or a
  # retained artifact. GNU find exits with SIGPIPE when head closes an
  # over-limit stream; that status is expected and the explicit byte check
  # below classifies the roster as unavailable.
  if ! {
      find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' 2>/dev/null || {
        find_status=$?
        [[ "$find_status" == 141 ]]
      }
    } | head -c "$((MAX_PROCESS_TREE_DIRECTORY_ROSTER_BYTES + 1))" \
      >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  size="$(wc -c <"$temporary")" || {
    rm -f -- "$temporary"
    return 1
  }
  [[ "$size" =~ ^(0|[1-9][0-9]*)$ &&
    "$size" -le "$MAX_PROCESS_TREE_DIRECTORY_ROSTER_BYTES" ]] || {
    rm -f -- "$temporary"
    return 1
  }
  if ! awk -F '\t' -v expected_type="$expected_type" '
      NF != 2 || $1 !~ /^(0|[1-9][0-9]*)$/ || $2 != expected_type ||
        (expected_type == "d" && $1 == "0") { exit 1 }
      { print $1 }
    ' "$temporary" | sort -n -u >"$output"; then
    rm -f -- "$temporary" "$output"
    return 1
  fi
  count="$(wc -l <"$temporary")" || {
    rm -f -- "$temporary" "$output"
    return 1
  }
  [[ "$count" =~ ^(0|[1-9][0-9]*)$ &&
    "$count" -le "$MAX_PROCESS_TREE_DIRECTORY_ENTRIES" &&
    "$count" == "$(wc -l <"$output")" ]] || {
    rm -f -- "$temporary" "$output"
    return 1
  }
  rm -f -- "$temporary" || {
    rm -f -- "$output"
    return 1
  }
}

proc_status_resource_values() {
  local -r status_file="$1"
  local -r scratch_directory="$2"
  local temporary=""
  local size=""
  local values=""
  local rss_kib=""
  local threads=""
  local extra=""

  [[ -f "$status_file" && ! -L "$status_file" &&
    -d "$scratch_directory" && ! -L "$scratch_directory" ]] || return 1
  # Never create scratch files below /proc. Production procfs is read-only for
  # these purposes; the caller supplies its already-bound private work area.
  temporary="$(mktemp "$scratch_directory/.benchmark-status.XXXXXX")" || return 1
  if ! head -c "$((MAX_PROC_STATUS_BYTES + 1))" -- "$status_file" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  size="$(wc -c <"$temporary")" || {
    rm -f -- "$temporary"
    return 1
  }
  if [[ ! "$size" =~ ^[1-9][0-9]*$ ]] || ((size > MAX_PROC_STATUS_BYTES)); then
    rm -f -- "$temporary"
    return 1
  fi
  values="$(awk '
    $1 == "VmRSS:" {
      rss_matches++
      if (NF != 3 || $2 !~ /^(0|[1-9][0-9]*)$/ || $3 != "kB") invalid = 1
      rss = $2
    }
    $1 == "Threads:" {
      thread_matches++
      if (NF != 2 || $2 !~ /^[1-9][0-9]*$/) invalid = 1
      threads = $2
    }
    END {
      if (invalid || rss_matches != 1 || thread_matches != 1) exit 1
      print rss, threads
    }
  ' "$temporary")" || {
    rm -f -- "$temporary"
    return 1
  }
  rm -f -- "$temporary" || return 1
  read -r rss_kib threads extra <<<"$values" || return 1
  rss_kib="$(normalize_decimal "$rss_kib" \
    "$((MAX_JSON_EXACT_INTEGER / 1024))" true)" || return 1
  threads="$(normalize_decimal "$threads" "$MAX_JSON_EXACT_INTEGER" false)" || return 1
  [[ -z "$extra" ]] || return 1
  printf '%s %s\n' "$((rss_kib * 1024))" "$threads"
}

capture_process_tree_pass_from_root() {
  local -r proc_root="$1"
  local -r container_id="$2"
  local -r expected_cgroup_sha256="$3"
  local -r pid_roster="$4"
  local -r output="$5"
  local pid=""
  local identity_before=""
  local identity_after=""
  local start_time=""
  local cgroup_sha256=""
  local binding=""
  local extra=""
  local resources=""
  local rss_bytes=""
  local status_threads=""
  local fd_count=""
  local task_count=""
  local fd_roster=""
  local task_roster=""
  local fd_sha256=""
  local task_sha256=""
  local temporary=""
  local -a temporary_paths=()

  [[ "$proc_root" == /* && -d "$proc_root" && ! -L "$proc_root" &&
    "$container_id" =~ ^[0-9a-f]{64}$ &&
    "$expected_cgroup_sha256" =~ ^[0-9a-f]{64}$ &&
    -s "$pid_roster" && ! -L "$pid_roster" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "${output%/*}/.process-tree-pass.XXXXXX")" || return 1
  temporary_paths+=("$temporary")
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    identity_before="$(proc_identity_from_root \
      "$proc_root" "$pid" "$container_id")" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    read -r start_time cgroup_sha256 binding extra <<<"$identity_before" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    [[ -z "$extra" && "$cgroup_sha256" == "$expected_cgroup_sha256" &&
      "$binding" == "$PROC_CGROUP_CONTAINER_BINDING" ]] || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    fd_roster="${output%/*}/fd-roster-$pid"
    task_roster="${output%/*}/task-roster-$pid"
    [[ ! -e "$fd_roster" && ! -L "$fd_roster" &&
      ! -e "$task_roster" && ! -L "$task_roster" ]] || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    temporary_paths+=("$fd_roster" "$task_roster")
    if ! capture_numeric_directory_roster "$proc_root/$pid/fd" l "$fd_roster" ||
      ! capture_numeric_directory_roster "$proc_root/$pid/task" d "$task_roster"; then
      rm -f -- "${temporary_paths[@]}"
      return 1
    fi
    fd_count="$(wc -l <"$fd_roster")" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    task_count="$(wc -l <"$task_roster")" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    resources="$(proc_status_resource_values \
      "$proc_root/$pid/status" "${output%/*}")" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    read -r rss_bytes status_threads extra <<<"$resources" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    [[ -z "$extra" && "$fd_count" =~ ^(0|[1-9][0-9]*)$ &&
      "$task_count" =~ ^[1-9][0-9]*$ && "$status_threads" == "$task_count" ]] || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    fd_sha256="$(sha256_regular_file "$fd_roster")" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    task_sha256="$(sha256_regular_file "$task_roster")" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    identity_after="$(proc_identity_from_root \
      "$proc_root" "$pid" "$container_id")" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    [[ "$identity_after" == "$identity_before" ]] || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$pid" "$start_time" "$cgroup_sha256" "$binding" \
      "$fd_sha256" "$task_sha256" "$fd_count" "$task_count" \
      "$status_threads" "$rss_bytes" >>"$temporary" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
    rm -f -- "$fd_roster" "$task_roster" || {
      rm -f -- "${temporary_paths[@]}"
      return 1
    }
  done <"$pid_roster"
  mv -T -- "$temporary" "$output"
}

capture_cgroup_cpu_stat_from_root() {
  local -r cgroup_directory="$1"
  local -r output="$2"
  local temporary=""
  local size=""
  local values=""
  local usage=""
  local user=""
  local system=""
  local extra=""

  cgroup_directory_reference_is_allowed "$cgroup_directory" || return 1
  [[
    -f "$cgroup_directory/cpu.stat" && ! -L "$cgroup_directory/cpu.stat" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "${output%/*}/.cpu-stat.XXXXXX")" || return 1
  if ! head -c 65537 -- "$cgroup_directory/cpu.stat" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  size="$(wc -c <"$temporary")" || {
    rm -f -- "$temporary"
    return 1
  }
  if [[ ! "$size" =~ ^[1-9][0-9]*$ ]] || ((size > 65536)); then
    rm -f -- "$temporary"
    return 1
  fi
  values="$(awk '
    $1 == "usage_usec" || $1 == "user_usec" || $1 == "system_usec" {
      if (NF != 2 || $2 !~ /^(0|[1-9][0-9]*)$/ || ++seen[$1] != 1) invalid = 1
      value[$1] = $2
    }
    END {
      if (invalid || length(seen) != 3) exit 1
      print value["usage_usec"], value["user_usec"], value["system_usec"]
    }
  ' "$temporary")" || {
    rm -f -- "$temporary"
    return 1
  }
  rm -f -- "$temporary" || return 1
  read -r usage user system extra <<<"$values" || return 1
  usage="$(normalize_decimal "$usage" "$MAX_JSON_EXACT_INTEGER" true)" || return 1
  user="$(normalize_decimal "$user" "$MAX_JSON_EXACT_INTEGER" true)" || return 1
  system="$(normalize_decimal "$system" "$MAX_JSON_EXACT_INTEGER" true)" || return 1
  [[ -z "$extra" ]] || return 1
  ((user <= MAX_JSON_EXACT_INTEGER - system &&
    user + system <= usage && usage <= user + system + 1)) || return 1
  printf '%s %s %s\n' "$usage" "$user" "$system" >"$output"
}

cgroup_root_is_cgroup2() {
  local -r cgroup_root="$1"
  local filesystem_type=""

  [[ "$cgroup_root" == /* ]] || return 1
  cgroup_directory_reference_is_allowed "$cgroup_root" || return 1
  filesystem_type="$(stat -f --format '%T' -- "$cgroup_root")" || return 1
  [[ "$filesystem_type" == cgroup2fs ]]
}

cgroup_leaf_stat_values() {
  local -r cgroup_directory="$1"
  local -r snapshot="$2"
  local size=""

  cgroup_directory_reference_is_allowed "$cgroup_directory" || return 1
  [[
    -f "$cgroup_directory/cgroup.stat" &&
    ! -L "$cgroup_directory/cgroup.stat" &&
    ! -e "$snapshot" && ! -L "$snapshot" ]] || return 1
  if ! head -c "$((MAX_CGROUP_STAT_BYTES + 1))" -- \
      "$cgroup_directory/cgroup.stat" >"$snapshot"; then
    rm -f -- "$snapshot"
    return 1
  fi
  size="$(wc -c <"$snapshot")" || {
    rm -f -- "$snapshot"
    return 1
  }
  [[ "$size" =~ ^[1-9][0-9]*$ && "$size" -le "$MAX_CGROUP_STAT_BYTES" ]] || {
    rm -f -- "$snapshot"
    return 1
  }
  awk '
    $1 == "nr_descendants" || $1 == "nr_dying_descendants" {
      if (NF != 2 || $2 !~ /^(0|[1-9][0-9]*)$/ || ++seen[$1] != 1) invalid = 1
      value[$1] = $2
    }
    END {
      if (invalid || length(seen) != 2 || value["nr_descendants"] != 0 ||
          value["nr_dying_descendants"] != 0) exit 1
      print value["nr_descendants"], value["nr_dying_descendants"]
    }
  ' "$snapshot"
}

cleanup_bound_cgroup_snapshot_work_directory() {
  local -r work_directory="$1"
  local -r expected_work_identity="$2"
  local -r expected_parent_identity="$3"
  local parent=""
  local unexpected=""

  [[ "$work_directory" == /* &&
    "$expected_work_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    "$expected_parent_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ ]] || return 1
  parent="${work_directory%/*}"
  [[ -d "$parent" && ! -L "$parent" &&
    "$(stat --format '%d:%i:%u:%a' -- "$parent")" == "$expected_parent_identity" &&
    -d "$work_directory" && ! -L "$work_directory" &&
    "$(stat --format '%d:%i:%u:%a' -- "$work_directory")" == "$expected_work_identity" ]] || return 1
  unexpected="$(find -P "$work_directory" -mindepth 1 -maxdepth 1 \
    ! -type f -print -quit 2>/dev/null)" || return 1
  [[ -z "$unexpected" ]] || return 1
  find -P "$work_directory" -mindepth 1 -maxdepth 1 -type f -delete || return 1
  rmdir -- "$work_directory" || return 1
  [[ ! -e "$work_directory" && ! -L "$work_directory" ]]
}

process_tree_pass_totals() {
  local -r pass="$1"
  local pid=""
  local start_time=""
  local cgroup_sha256=""
  local binding=""
  local fd_sha256=""
  local task_sha256=""
  local fd_count=""
  local task_count=""
  local status_threads=""
  local rss_bytes=""
  local extra=""
  local process_count=0
  local fd_total=0
  local task_total=0
  local threads_total=0
  local rss_total=0

  [[ -s "$pass" && ! -L "$pass" ]] || return 1
  while IFS=$'\t' read -r pid start_time cgroup_sha256 binding fd_sha256 task_sha256 \
      fd_count task_count status_threads rss_bytes extra; do
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$start_time" =~ ^[1-9][0-9]*$ &&
      "$cgroup_sha256" =~ ^[0-9a-f]{64}$ &&
      "$binding" == "$PROC_CGROUP_CONTAINER_BINDING" &&
      "$fd_sha256" =~ ^[0-9a-f]{64}$ && "$task_sha256" =~ ^[0-9a-f]{64}$ &&
      "$fd_count" =~ ^(0|[1-9][0-9]*)$ && "$task_count" =~ ^[1-9][0-9]*$ &&
      "$status_threads" == "$task_count" && "$rss_bytes" =~ ^(0|[1-9][0-9]*)$ &&
      -z "$extra" ]] || return 1
    ((fd_total <= MAX_JSON_EXACT_INTEGER - fd_count &&
      task_total <= MAX_JSON_EXACT_INTEGER - task_count &&
      threads_total <= MAX_JSON_EXACT_INTEGER - status_threads &&
      rss_total <= MAX_JSON_EXACT_INTEGER - rss_bytes)) || return 1
    ((process_count += 1, fd_total += fd_count, task_total += task_count,
      threads_total += status_threads, rss_total += rss_bytes))
  done <"$pass"
  ((process_count > 0 && process_count <= MAX_PROCESS_TREE_PIDS)) || return 1
  printf '%s %s %s %s %s\n' \
    "$process_count" "$fd_total" "$task_total" "$threads_total" "$rss_total"
}

process_tree_pass_json() {
  local -r ordinal="$1"
  local -r pass="$2"
  local -r cpu_stat="$3"
  local totals=""
  local process_count=""
  local fd_count=""
  local task_count=""
  local status_threads=""
  local rss_bytes=""
  local usage_usec=""
  local user_usec=""
  local system_usec=""
  local extra=""
  local roster_sha256=""

  totals="$(process_tree_pass_totals "$pass")" || return 1
  read -r process_count fd_count task_count status_threads rss_bytes extra \
    <<<"$totals" || return 1
  [[ -z "$extra" ]] || return 1
  read -r usage_usec user_usec system_usec extra <"$cpu_stat" || return 1
  [[ -z "$extra" ]] || return 1
  roster_sha256="$(cut -f1-4 -- "$pass" | sha256sum)" || return 1
  roster_sha256="${roster_sha256%% *}"
  jq -cn \
    --argjson ordinal "$ordinal" \
    --arg roster_sha256 "$roster_sha256" \
    --argjson process_count "$process_count" \
    --argjson fd_count "$fd_count" \
    --argjson task_count "$task_count" \
    --argjson status_threads "$status_threads" \
    --argjson rss_bytes "$rss_bytes" \
    --argjson usage_usec "$usage_usec" \
    --argjson user_usec "$user_usec" \
    --argjson system_usec "$system_usec" \
    --rawfile rows "$pass" '
      ($rows | split("\n") | map(select(length > 0) | split("\t") | {
        pid: (.[0] | tonumber),
        proc_start_time: (.[1] | tonumber),
        proc_cgroup_sha256: .[2],
        proc_cgroup_container_binding: .[3],
        fd_roster_sha256: .[4],
        task_roster_sha256: .[5],
        fd_count: (.[6] | tonumber),
        task_count: (.[7] | tonumber),
        status_threads: (.[8] | tonumber),
        rss_bytes: (.[9] | tonumber)
      })) as $processes |
      {
        ordinal: $ordinal,
        roster_sha256: $roster_sha256,
        processes: $processes,
        totals: {
          process_count: $process_count,
          fd_count: $fd_count,
          task_count: $task_count,
          status_threads: $status_threads,
          rss_bytes: $rss_bytes
        },
        cpu_stat: {
          usage_usec: $usage_usec,
          user_usec: $user_usec,
          system_usec: $system_usec
        }
      }
    '
}

bound_cgroup_v2_snapshot_available_json() (
  local -r identity_file="$1"
  local -r timing="$2"
  local -r proc_root="$3"
  local -r cgroup_root="$4"
  local -r expected_cell="${5:-$CELL_SLUG}"
  local -r expected_service="${6:-}"
  local repetition="${7:-}"
  local repetition_json=null
  local identity_service=""
  local identity_source="${identity_file##*/}"
  local container_id=""
  local root_host_pid=""
  local expected_start_time=""
  local expected_cgroup_sha256=""
  local expected_binding=""
  local cgroup_path=""
  local cgroup_path_after=""
  local cgroup_path_sha256=""
  local cgroup_directory=""
  local cgroup_root_fd=""
  local cgroup_leaf_fd=""
  local cgroup_root_anchor=""
  local cgroup_leaf_anchor=""
  local cgroup_root_identity_before=""
  local cgroup_root_identity_after=""
  local cgroup_root_device=""
  local cgroup_root_inode=""
  local cgroup_identity_before=""
  local cgroup_identity_after=""
  local cgroup_device=""
  local cgroup_inode=""
  local hierarchy_before=""
  local hierarchy_after=""
  local hierarchy_sha256=""
  local extra=""
  local root_identity_before=""
  local root_identity_after=""
  local leaf_stat_before=""
  local leaf_stat_after=""
  local work_directory=""
  local work_directory_identity=""
  local work_parent_identity=""
  local roster_1=""
  local roster_2=""
  local pass_1=""
  local pass_2=""
  local roster_identity_1=""
  local roster_identity_2=""
  local roster_projection=""
  local cpu_1=""
  local cpu_2=""
  local pass_1_json=""
  local pass_2_json=""
  local roster_json=""
  local pass_1_totals=""
  local pass_2_totals=""
  local p1_processes="" p1_fd="" p1_tasks="" p1_threads="" p1_rss=""
  local p2_processes="" p2_fd="" p2_tasks="" p2_threads="" p2_rss=""
  local cpu1_usage="" cpu1_user="" cpu1_system=""
  local cpu2_usage="" cpu2_user="" cpu2_system=""
  local snapshot_status=0

  container_id="$(identity_field "$identity_file" container_id)" || return 1
  identity_service="$(identity_field "$identity_file" service)" || return 1
  root_host_pid="$(identity_field "$identity_file" host_pid)" || return 1
  expected_start_time="$(identity_field "$identity_file" proc_start_time)" || return 1
  expected_cgroup_sha256="$(identity_field "$identity_file" proc_cgroup_sha256)" || return 1
  expected_binding="$(identity_field "$identity_file" proc_cgroup_container_binding)" || return 1
  [[ -n "$expected_cell" && "$expected_cell" =~ ^[a-z0-9][a-z0-9-]*$ &&
    "$identity_service" =~ ^[a-z0-9][a-z0-9-]*$ &&
    ( -z "$expected_service" || "$identity_service" == "$expected_service" ) &&
    "$identity_source" == "$identity_service-identity.txt" &&
    "$container_id" =~ ^[0-9a-f]{64}$ && "$root_host_pid" =~ ^[1-9][0-9]*$ &&
    "$expected_start_time" =~ ^[1-9][0-9]*$ &&
    "$expected_cgroup_sha256" =~ ^[0-9a-f]{64}$ &&
    "$expected_binding" == "$PROC_CGROUP_CONTAINER_BINDING" &&
    "$proc_root" == /* && -d "$proc_root" && ! -L "$proc_root" &&
    "$cgroup_root" == /* && -d "$cgroup_root" && ! -L "$cgroup_root" &&
    -f "$cgroup_root/cgroup.controllers" && ! -L "$cgroup_root/cgroup.controllers" ]] || return 1
  if [[ "$timing" == scheduled_repetition_midpoint ]]; then
    repetition="$(normalize_decimal "$repetition" "$REQUIRED_REPETITIONS" false)" || return 1
    repetition_json="$repetition"
  else
    [[ -z "$repetition" ]] || return 1
  fi
  exec {cgroup_root_fd}<"$cgroup_root" || return 1
  cgroup_root_anchor="/proc/self/fd/$cgroup_root_fd"
  trap '
    snapshot_status=$?
    if [[ -n "$cgroup_leaf_fd" ]]; then
      exec {cgroup_leaf_fd}<&- 2>/dev/null || snapshot_status=1
      cgroup_leaf_fd=""
    fi
    if [[ -n "$cgroup_root_fd" ]]; then
      exec {cgroup_root_fd}<&- 2>/dev/null || snapshot_status=1
      cgroup_root_fd=""
    fi
    if [[ -n "$work_directory" ]]; then
      cleanup_bound_cgroup_snapshot_work_directory \
        "$work_directory" "$work_directory_identity" "$work_parent_identity" || snapshot_status=1
    fi
    exit "$snapshot_status"
  ' EXIT
  cgroup_root_is_cgroup2 "$cgroup_root" || return 1
  cgroup_root_is_cgroup2 "$cgroup_root_anchor" || return 1
  cgroup_root_identity_before="$(stat --format '%d %i' -- "$cgroup_root")" || return 1
  [[ "$(stat -L --format '%d %i' -- "$cgroup_root_anchor")" == "$cgroup_root_identity_before" ]] || return 1
  read -r cgroup_root_device cgroup_root_inode extra <<<"$cgroup_root_identity_before" || return 1
  [[ "$cgroup_root_device" =~ ^[0-9]+$ &&
    "$cgroup_root_inode" =~ ^[1-9][0-9]*$ && -z "$extra" ]] || return 1
  root_identity_before="$(proc_identity_from_root \
    "$proc_root" "$root_host_pid" "$container_id")" || return 1
  [[ "$root_identity_before" == \
    "$expected_start_time $expected_cgroup_sha256 $expected_binding" ]] || return 1
  cgroup_path="$(parse_cgroup_v2_path_from_root \
    "$proc_root" "$root_host_pid" "$container_id")" || return 1
  cgroup_path_sha256="$(printf '%s' "$cgroup_path" | sha256sum)" || return 1
  cgroup_path_sha256="${cgroup_path_sha256%% *}"
  cgroup_directory="${cgroup_root%/}$cgroup_path"
  assert_cgroup_path_components "$cgroup_root" "$cgroup_path" || return 1
  work_parent_identity="$(stat --format '%d:%i:%u:%a' -- "${identity_file%/*}")" || return 1
  work_directory="$(mktemp -d "${identity_file%/*}/.cgroup-snapshot.XXXXXX")" || return 1
  work_directory_identity="$(stat --format '%d:%i:%u:%a' -- "$work_directory")" || return 1
  [[ "$(stat --format '%d:%i:%u:%a' -- "${identity_file%/*}")" == "$work_parent_identity" ]] || return 1
  hierarchy_before="$work_directory/cgroup-hierarchy-before"
  hierarchy_after="$work_directory/cgroup-hierarchy-after"
  capture_cgroup_hierarchy_identity "$cgroup_root_anchor" "$cgroup_path" "$hierarchy_before" || return 1
  exec {cgroup_leaf_fd}<"$cgroup_directory" || return 1
  cgroup_leaf_anchor="/proc/self/fd/$cgroup_leaf_fd"
  cgroup_root_is_cgroup2 "$cgroup_leaf_anchor" || return 1
  [[ -f "$cgroup_leaf_anchor/cgroup.type" &&
    ! -L "$cgroup_leaf_anchor/cgroup.type" &&
    "$(<"$cgroup_leaf_anchor/cgroup.type")" == domain ]] || return 1
  leaf_stat_before="$(cgroup_leaf_stat_values "$cgroup_leaf_anchor" "$work_directory/cgroup-stat-before")" || return 1
  cgroup_identity_before="$(stat -L --format '%d %i' -- "$cgroup_leaf_anchor")" || return 1
  [[ "$(stat --format '%d %i' -- "$cgroup_directory")" == "$cgroup_identity_before" ]] || return 1
  read -r cgroup_device cgroup_inode extra <<<"$cgroup_identity_before" || return 1
  [[ "$cgroup_device" =~ ^[0-9]+$ && "$cgroup_inode" =~ ^[1-9][0-9]*$ &&
    "$cgroup_device" == "$cgroup_root_device" && -z "$extra" ]] || return 1

  roster_1="$work_directory/roster-1"
  roster_2="$work_directory/roster-2"
  pass_1="$work_directory/pass-1"
  pass_2="$work_directory/pass-2"
  roster_identity_1="$work_directory/roster-identity-1"
  roster_identity_2="$work_directory/roster-identity-2"
  roster_projection="$work_directory/roster-projection"
  cpu_1="$work_directory/cpu-1"
  cpu_2="$work_directory/cpu-2"
  capture_cgroup_procs_roster "$cgroup_leaf_anchor" "$roster_1" || {
    return 1
  }
  grep -Fxq "$root_host_pid" "$roster_1" || {
    return 1
  }
  capture_process_tree_pass_from_root "$proc_root" "$container_id" \
    "$expected_cgroup_sha256" "$roster_1" "$pass_1" || {
    return 1
  }
  capture_cgroup_cpu_stat_from_root "$cgroup_leaf_anchor" "$cpu_1" || {
    return 1
  }
  capture_process_tree_pass_from_root "$proc_root" "$container_id" \
    "$expected_cgroup_sha256" "$roster_1" "$pass_2" || {
    return 1
  }
  capture_cgroup_cpu_stat_from_root "$cgroup_leaf_anchor" "$cpu_2" || {
    return 1
  }
  capture_cgroup_procs_roster "$cgroup_leaf_anchor" "$roster_2" || {
    return 1
  }
  cut -f1-4 -- "$pass_1" >"$roster_identity_1" || return 1
  cut -f1-4 -- "$pass_2" >"$roster_identity_2" || return 1
  [[ "$(wc -l <"$roster_identity_1")" == "$(wc -l <"$roster_1")" &&
    "$(wc -l <"$roster_identity_2")" == "$(wc -l <"$roster_2")" ]] || return 1
  if ! cmp -s -- "$roster_1" "$roster_2" ||
    ! cmp -s -- "$roster_identity_1" "$roster_identity_2"; then
    return 1
  fi
  root_identity_after="$(proc_identity_from_root \
    "$proc_root" "$root_host_pid" "$container_id")" || {
    return 1
  }
  cgroup_path_after="$(parse_cgroup_v2_path_from_root "$proc_root" "$root_host_pid" "$container_id")" || return 1
  cgroup_root_identity_after="$(stat --format '%d %i' -- "$cgroup_root")" || return 1
  cgroup_identity_after="$(stat --format '%d %i' -- "$cgroup_directory")" || return 1
  capture_cgroup_hierarchy_identity "$cgroup_root_anchor" "$cgroup_path" "$hierarchy_after" || return 1
  [[ "$root_identity_after" == "$root_identity_before" &&
    "$cgroup_path_after" == "$cgroup_path" &&
    "$cgroup_root_identity_after" == "$cgroup_root_identity_before" &&
    "$(stat -L --format '%d %i' -- "$cgroup_root_anchor")" == "$cgroup_root_identity_before" &&
    "$(stat -L --format '%d %i' -- "$cgroup_leaf_anchor")" == "$cgroup_identity_before" &&
    "$cgroup_identity_after" == "$cgroup_identity_before" &&
    ! -L "$cgroup_directory" &&
    "$(<"$cgroup_leaf_anchor/cgroup.type")" == domain ]] || {
    return 1
  }
  cgroup_root_is_cgroup2 "$cgroup_root" || return 1
  cgroup_root_is_cgroup2 "$cgroup_root_anchor" || return 1
  cgroup_root_is_cgroup2 "$cgroup_leaf_anchor" || return 1
  assert_cgroup_path_components "$cgroup_root_anchor" "$cgroup_path" || return 1
  cmp -s -- "$hierarchy_before" "$hierarchy_after" || return 1
  hierarchy_sha256="$(sha256_regular_file "$hierarchy_before")" || return 1
  leaf_stat_after="$(cgroup_leaf_stat_values \
    "$cgroup_leaf_anchor" "$work_directory/cgroup-stat-after")" || return 1
  [[ "$leaf_stat_after" == "$leaf_stat_before" && "$leaf_stat_before" == "0 0" ]] || return 1

  pass_1_totals="$(process_tree_pass_totals "$pass_1")" || {
    return 1
  }
  pass_2_totals="$(process_tree_pass_totals "$pass_2")" || {
    return 1
  }
  read -r p1_processes p1_fd p1_tasks p1_threads p1_rss extra <<<"$pass_1_totals" || return 1
  [[ -z "$extra" && "$p1_processes" =~ ^[1-9][0-9]*$ &&
    "$p1_fd" =~ ^[0-9]+$ && "$p1_tasks" =~ ^[1-9][0-9]*$ &&
    "$p1_threads" =~ ^[1-9][0-9]*$ && "$p1_rss" =~ ^[0-9]+$ &&
    "$p1_tasks" == "$p1_threads" ]] || return 1
  read -r p2_processes p2_fd p2_tasks p2_threads p2_rss extra <<<"$pass_2_totals" || return 1
  [[ -z "$extra" && "$p2_processes" =~ ^[1-9][0-9]*$ &&
    "$p2_fd" =~ ^[0-9]+$ && "$p2_tasks" =~ ^[1-9][0-9]*$ &&
    "$p2_threads" =~ ^[1-9][0-9]*$ && "$p2_rss" =~ ^[0-9]+$ &&
    "$p2_tasks" == "$p2_threads" &&
    "$p1_processes" == "$p2_processes" ]] || return 1
  read -r cpu1_usage cpu1_user cpu1_system extra <"$cpu_1" || return 1
  [[ -z "$extra" ]] || return 1
  read -r cpu2_usage cpu2_user cpu2_system extra <"$cpu_2" || return 1
  [[ -z "$extra" && "$cpu2_usage" -ge "$cpu1_usage" &&
    "$cpu2_user" -ge "$cpu1_user" && "$cpu2_system" -ge "$cpu1_system" ]] || return 1
  pass_1_json="$(process_tree_pass_json 1 "$pass_1" "$cpu_1")" || return 1
  pass_2_json="$(process_tree_pass_json 2 "$pass_2" "$cpu_2")" || return 1
  cp -- "$roster_identity_1" "$roster_projection" || return 1
  [[ "$(wc -l <"$roster_projection")" == "$(wc -l <"$roster_1")" ]] || return 1
  roster_json="$(jq -Rn '
    [inputs | split("\t") | {
      pid: (.[0] | tonumber), proc_start_time: (.[1] | tonumber),
      proc_cgroup_sha256: .[2], proc_cgroup_container_binding: .[3]
    }]
  ' <"$roster_projection")" || return 1
  exec {cgroup_leaf_fd}<&- || return 1
  cgroup_leaf_fd=""
  exec {cgroup_root_fd}<&- || return 1
  cgroup_root_fd=""
  cleanup_bound_cgroup_snapshot_work_directory \
    "$work_directory" "$work_directory_identity" "$work_parent_identity" || return 1
  work_directory=""
  work_directory_identity=""
  work_parent_identity=""
  printf '%s\n%s\n%s' "$roster_json" "$pass_1_json" "$pass_2_json" | jq -cs \
    --arg cell "$expected_cell" \
    --arg service "$identity_service" \
    --arg identity_source "$identity_source" \
    --arg timing "$timing" \
    --argjson repetition "$repetition_json" \
    --arg container_id "$container_id" \
    --arg cgroup_sha256 "$expected_cgroup_sha256" \
    --arg binding "$expected_binding" \
    --arg cgroup_path "$cgroup_path" \
    --arg cgroup_path_sha256 "$cgroup_path_sha256" \
    --argjson root_host_pid "$root_host_pid" \
    --argjson root_start_time "$expected_start_time" \
    --argjson cgroup_root_device "$cgroup_root_device" \
    --argjson cgroup_root_inode "$cgroup_root_inode" \
    --argjson cgroup_device "$cgroup_device" \
    --argjson cgroup_inode "$cgroup_inode" \
    --arg cgroup_hierarchy_sha256 "$hierarchy_sha256" '
      def envelope($left; $right): {
        min: (if $left <= $right then $left else $right end),
        max: (if $left >= $right then $left else $right end)
      };
      if length != 3 then error("expected roster and exactly two passes")
      else . end |
      .[0] as $roster |
      .[1] as $pass_1 |
      .[2] as $pass_2 |
      {
        schema_version: 1,
        kind: "bound-container-cgroup-v2-snapshot",
        status: "available",
        cell: $cell,
        service: $service,
        timing: $timing,
        repetition: $repetition,
        identity_source: $identity_source,
        identity: {
          container_id: $container_id,
          root_host_pid: $root_host_pid,
          root_proc_start_time: $root_start_time,
          proc_cgroup_sha256: $cgroup_sha256,
          proc_cgroup_container_binding: $binding,
          cgroup_path: $cgroup_path,
          cgroup_path_sha256: $cgroup_path_sha256,
          cgroup_root_device: $cgroup_root_device,
          cgroup_root_inode: $cgroup_root_inode,
          cgroup_device: $cgroup_device,
          cgroup_inode: $cgroup_inode,
          cgroup_hierarchy_sha256: $cgroup_hierarchy_sha256,
          cgroup_version: 2,
          cgroup_type: "domain",
          filesystem_type: "cgroup2fs",
          leaf: true,
          nr_descendants: 0,
          nr_dying_descendants: 0
        },
        roster: $roster,
        passes: [$pass_1, $pass_2],
        envelope: {
          process_count: envelope($pass_1.totals.process_count; $pass_2.totals.process_count),
          fd_count: envelope($pass_1.totals.fd_count; $pass_2.totals.fd_count),
          task_count: envelope($pass_1.totals.task_count; $pass_2.totals.task_count),
          status_threads: envelope($pass_1.totals.status_threads; $pass_2.totals.status_threads),
          rss_bytes: envelope($pass_1.totals.rss_bytes; $pass_2.totals.rss_bytes),
          cpu_usage_usec: envelope($pass_1.cpu_stat.usage_usec; $pass_2.cpu_stat.usage_usec),
          cpu_user_usec: envelope($pass_1.cpu_stat.user_usec; $pass_2.cpu_stat.user_usec),
          cpu_system_usec: envelope($pass_1.cpu_stat.system_usec; $pass_2.cpu_stat.system_usec)
        },
        collection: {
          authority: "compose_identity_plus_fd_anchored_cgroup2_root_leaf_and_stable_hierarchy",
          roster_stability: "two_identical_sorted_pid_start_cgroup_rosters",
          resource_values: "two_pass_conservative_envelope",
          cgroup2_leaf_domain_required: true
        }
      }
    '
)

capture_bound_cgroup_v2_snapshot_from_roots() {
  local -r identity_file="$1"
  local -r output="$2"
  local -r timing="$3"
  local -r proc_root="$4"
  local -r cgroup_root="$5"
  local -r expected_cell="${6:-$CELL_SLUG}"
  local expected_service="${7:-}"
  local repetition="${8:-}"
  local repetition_json=null
  local temporary=""

  [[ -f "$identity_file" && ! -L "$identity_file" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  if [[ -z "$expected_service" ]]; then
    expected_service="$(identity_field "$identity_file" service)" || return 1
  fi
  if [[ "$timing" == scheduled_repetition_midpoint ]]; then
    repetition="$(normalize_decimal "$repetition" "$REQUIRED_REPETITIONS" false)" || return 1
    repetition_json="$repetition"
  else
    [[ -z "$repetition" ]] || return 1
  fi
  temporary="$(mktemp "${output%/*}/.cgroup-v2.json.XXXXXX")" || return 1
  if ! bound_cgroup_v2_snapshot_available_json \
      "$identity_file" "$timing" "$proc_root" "$cgroup_root" \
      "$expected_cell" "$expected_service" "$repetition" >"$temporary"; then
    if ! jq -n --arg timing "$timing" --arg cell "$expected_cell" \
      --arg service "$expected_service" \
      --argjson repetition "$repetition_json" \
      --arg identity_source "${identity_file##*/}" '{
      schema_version: 1,
      kind: "bound-container-cgroup-v2-snapshot",
      status: "unavailable",
      cell: $cell,
      service: $service,
      timing: $timing,
      repetition: $repetition,
      identity_source: $identity_source,
      reason: "authority_or_two_pass_snapshot_unavailable"
    }' >"$temporary"; then
      rm -f -- "$temporary"
      return 1
    fi
  fi
  if ! validate_bound_cgroup_v2_snapshot_schema "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  mv -T -- "$temporary" "$output" || {
    rm -f -- "$temporary"
    return 1
  }
  validate_bound_cgroup_v2_snapshot_schema "$output"
}

capture_bound_cgroup_v2_snapshot() {
  local -r identity_file="$1"
  local -r output="$2"
  local -r timing="$3"
  local -r cell="$4"
  local -r service="$5"
  local -r repetition="${6:-}"

  # Production authority is deliberately fixed. Hermetic tests call the
  # from_roots seam directly; neither CLI nor environment can redirect it.
  capture_bound_cgroup_v2_snapshot_from_roots \
    "$identity_file" "$output" "$timing" /proc /sys/fs/cgroup \
    "$cell" "$service" "$repetition"
}

validate_bound_cgroup_v2_snapshot_json_value() {
  local -r snapshot_value="$1"
  local cgroup_path=""
  local recorded_path_sha256=""
  local observed_path_sha256=""

  printf '%s' "$snapshot_value" | jq -se \
    --argjson maximum "$MAX_JSON_EXACT_INTEGER" '
    def n: type == "number" and isfinite and floor == . and . >= 0 and . <= $maximum;
    def p: n and . > 0;
    def identity_row:
      (keys | sort) == ["pid", "proc_cgroup_container_binding",
        "proc_cgroup_sha256", "proc_start_time"] and
      (.pid | p) and (.proc_start_time | p) and
      (.proc_cgroup_sha256 | test("^[0-9a-f]{64}$")) and
      .proc_cgroup_container_binding == "full_container_id_at_non_hex_boundaries";
    def process_row:
      (keys | sort) == ["fd_count", "fd_roster_sha256", "pid",
        "proc_cgroup_container_binding", "proc_cgroup_sha256", "proc_start_time",
        "rss_bytes", "status_threads", "task_count", "task_roster_sha256"] and
      (.pid | p) and (.proc_start_time | p) and
      (.proc_cgroup_sha256 | test("^[0-9a-f]{64}$")) and
      .proc_cgroup_container_binding == "full_container_id_at_non_hex_boundaries" and
      (.fd_roster_sha256 | test("^[0-9a-f]{64}$")) and
      (.task_roster_sha256 | test("^[0-9a-f]{64}$")) and
      (.fd_count | n) and (.task_count | p) and (.status_threads | p) and
      .task_count == .status_threads and (.rss_bytes | n);
    def cpu_row:
      (keys | sort) == ["system_usec", "usage_usec", "user_usec"] and
      (.usage_usec | n) and (.user_usec | n) and (.system_usec | n) and
      (.user_usec + .system_usec) <= .usage_usec and
      .usage_usec <= (.user_usec + .system_usec + 1) and .usage_usec <= $maximum;
    def pass_row:
      (keys | sort) == ["cpu_stat", "ordinal", "processes", "roster_sha256", "totals"] and
      (.ordinal == 1 or .ordinal == 2) and
      (.roster_sha256 | test("^[0-9a-f]{64}$")) and
      (.processes | type == "array" and length > 0 and
        ([.[].pid] == ([.[].pid] | sort | unique)) and all(.[]; process_row)) and
      (.cpu_stat | cpu_row) and
      .totals == {
        process_count: (.processes | length),
        fd_count: ([.processes[].fd_count] | add),
        task_count: ([.processes[].task_count] | add),
        status_threads: ([.processes[].status_threads] | add),
        rss_bytes: ([.processes[].rss_bytes] | add)
      } and all(.totals[]; n);
    def pair($left; $right): {
      min: ([$left, $right] | min), max: ([$left, $right] | max)
    };
    length == 1 and (.[0] |
      .schema_version == 1 and .kind == "bound-container-cgroup-v2-snapshot" and
      (.timing | type == "string" and length > 0) and
      (if .timing == "scheduled_repetition_midpoint"
       then (.repetition | p) and .repetition <= 5 else .repetition == null end) and
      if .status == "unavailable" then
        (keys | sort) == ["cell", "identity_source", "kind", "reason", "repetition",
          "schema_version", "service", "status", "timing"] and
        (.cell | test("^[a-z0-9][a-z0-9-]*$")) and
        (.service | test("^[a-z0-9][a-z0-9-]*$")) and
        .identity_source == (.service + "-identity.txt") and
        .reason == "authority_or_two_pass_snapshot_unavailable"
      else
        .status == "available" and
        (keys | sort) == ["cell", "collection", "envelope", "identity",
          "identity_source", "kind", "passes", "repetition", "roster", "schema_version",
          "service", "status", "timing"] and
        (.cell | test("^[a-z0-9][a-z0-9-]*$")) and
        (.service | test("^[a-z0-9][a-z0-9-]*$")) and
        .identity_source == (.service + "-identity.txt") and
        (.identity |
          (keys | sort) == ["cgroup_device", "cgroup_hierarchy_sha256",
            "cgroup_inode", "cgroup_path", "cgroup_path_sha256",
            "cgroup_root_device", "cgroup_root_inode", "cgroup_type",
            "cgroup_version", "container_id", "filesystem_type", "leaf",
            "nr_descendants", "nr_dying_descendants",
            "proc_cgroup_container_binding", "proc_cgroup_sha256",
            "root_host_pid", "root_proc_start_time"] and
          (.container_id | test("^[0-9a-f]{64}$")) and (.root_host_pid | p) and
          (.root_proc_start_time | p) and
          (.proc_cgroup_sha256 | test("^[0-9a-f]{64}$")) and
          .proc_cgroup_container_binding == "full_container_id_at_non_hex_boundaries" and
          (.cgroup_path | test("^/[A-Za-z0-9_.:@,+/-]+$")) and
          (.cgroup_path_sha256 | test("^[0-9a-f]{64}$")) and
          (.cgroup_root_device | n) and (.cgroup_root_inode | p) and
          (.cgroup_device | n) and (.cgroup_inode | p) and
          .cgroup_device == .cgroup_root_device and
          (.cgroup_hierarchy_sha256 | test("^[0-9a-f]{64}$")) and
          .cgroup_version == 2 and
          .cgroup_type == "domain" and .filesystem_type == "cgroup2fs" and
          .leaf == true and .nr_descendants == 0 and .nr_dying_descendants == 0) and
        .collection == {
          authority: "compose_identity_plus_fd_anchored_cgroup2_root_leaf_and_stable_hierarchy",
          roster_stability: "two_identical_sorted_pid_start_cgroup_rosters",
          resource_values: "two_pass_conservative_envelope",
          cgroup2_leaf_domain_required: true
        } and
        (.roster | type == "array" and length > 0 and
          ([.[].pid] == ([.[].pid] | sort | unique)) and all(.[]; identity_row)) and
        (.passes | type == "array" and length == 2 and .[0].ordinal == 1 and
          .[1].ordinal == 2 and all(.[]; pass_row)) and
        ([.passes[0].processes[] | {pid, proc_start_time, proc_cgroup_sha256,
          proc_cgroup_container_binding}] == .roster) and
        ([.passes[1].processes[] | {pid, proc_start_time, proc_cgroup_sha256,
          proc_cgroup_container_binding}] == .roster) and
        .passes[0].roster_sha256 == .passes[1].roster_sha256 and
        .passes[1].cpu_stat.usage_usec >= .passes[0].cpu_stat.usage_usec and
        .passes[1].cpu_stat.user_usec >= .passes[0].cpu_stat.user_usec and
        .passes[1].cpu_stat.system_usec >= .passes[0].cpu_stat.system_usec and
        .envelope == {
          process_count: pair(.passes[0].totals.process_count; .passes[1].totals.process_count),
          fd_count: pair(.passes[0].totals.fd_count; .passes[1].totals.fd_count),
          task_count: pair(.passes[0].totals.task_count; .passes[1].totals.task_count),
          status_threads: pair(.passes[0].totals.status_threads; .passes[1].totals.status_threads),
          rss_bytes: pair(.passes[0].totals.rss_bytes; .passes[1].totals.rss_bytes),
          cpu_usage_usec: pair(.passes[0].cpu_stat.usage_usec; .passes[1].cpu_stat.usage_usec),
          cpu_user_usec: pair(.passes[0].cpu_stat.user_usec; .passes[1].cpu_stat.user_usec),
          cpu_system_usec: pair(.passes[0].cpu_stat.system_usec; .passes[1].cpu_stat.system_usec)
        }
      end)
  ' >/dev/null || return 1
  if [[ "$(printf '%s' "$snapshot_value" | jq -er '.status')" == available ]]; then
    cgroup_path="$(printf '%s' "$snapshot_value" | \
      jq -er '.identity.cgroup_path')" || return 1
    recorded_path_sha256="$(printf '%s' "$snapshot_value" | \
      jq -er '.identity.cgroup_path_sha256')" || return 1
    observed_path_sha256="$(printf '%s' "$cgroup_path" | sha256sum)" || return 1
    observed_path_sha256="${observed_path_sha256%% *}"
    [[ "$recorded_path_sha256" == "$observed_path_sha256" ]] || return 1
  fi
}

validated_bound_cgroup_v2_snapshot_json_value() {
  local -r artifact="$1"
  local snapshot_value=""

  snapshot_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES")" || return 1
  validate_bound_cgroup_v2_snapshot_json_value "$snapshot_value" || return 1
  printf '%s' "$snapshot_value"
}

validate_bound_cgroup_v2_snapshot_schema() {
  local -r artifact="$1"
  local snapshot_value=""

  snapshot_value="$(validated_bound_cgroup_v2_snapshot_json_value "$artifact")"
}

unavailable_bound_cgroup_v2_snapshot_json_value() {
  local -r cell="$1"
  local -r service="$2"
  local -r timing="$3"
  local repetition="${4:-}"
  local repetition_json=null

  [[ "$cell" =~ ^[a-z0-9][a-z0-9-]*$ &&
    "$service" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
  if [[ "$timing" == scheduled_repetition_midpoint ]]; then
    repetition="$(normalize_decimal "$repetition" "$REQUIRED_REPETITIONS" false)" || return 1
    repetition_json="$repetition"
  else
    [[ -z "$repetition" ]] || return 1
  fi
  jq -cn --arg cell "$cell" --arg service "$service" --arg timing "$timing" \
    --argjson repetition "$repetition_json" '{
    schema_version: 1,
    kind: "bound-container-cgroup-v2-snapshot",
    status: "unavailable",
    cell: $cell,
    service: $service,
    timing: $timing,
    repetition: $repetition,
    identity_source: ($service + "-identity.txt"),
    reason: "authority_or_two_pass_snapshot_unavailable"
  }'
}

bound_cgroup_v2_snapshot_json_value_or_unavailable() {
  local -r artifact="$1"
  local -r cell="$2"
  local -r service="$3"
  local -r timing="$4"
  local -r repetition="${5:-}"
  local snapshot_value=""
  local capture_probe=""

  if snapshot_value="$(validated_bound_cgroup_v2_snapshot_json_value "$artifact")"; then
    printf '%s' "$snapshot_value"
    return 0
  fi
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    # A retained regular source may be syntactically or semantically malformed;
    # its first capture already emitted S authority. Only a path that cannot be
    # captured as a bounded nonempty regular file is represented by N.
    if capture_probe="$(capture_bounded_regular_file_image \
      "$artifact" "$MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES")"; then
      [[ "$capture_probe" == OBIJSON1:* ]] || return 1
    else
      terminal_record_source_negative \
        "$artifact" "$MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES" || return 1
    fi
  fi
  snapshot_value="$(unavailable_bound_cgroup_v2_snapshot_json_value \
    "$cell" "$service" "$timing" "$repetition")" || return 1
  validate_bound_cgroup_v2_snapshot_json_value "$snapshot_value" || return 1
  printf '%s' "$snapshot_value"
}

write_unavailable_bound_cgroup_v2_snapshot() {
  local -r output="$1"
  local -r cell="$2"
  local -r service="$3"
  local -r timing="$4"
  local -r repetition="${5:-}"
  local snapshot_value=""

  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  snapshot_value="$(unavailable_bound_cgroup_v2_snapshot_json_value \
    "$cell" "$service" "$timing" "$repetition")" || return 1
  printf '%s\n' "$snapshot_value" >"$output" || return 1
  validate_bound_cgroup_v2_snapshot_schema "$output"
}

capture_cpu_measurement_snapshot() {
  local -r snapshot_directory="$1"
  local -r timing="$2"
  local service=""
  local clocks=""
  local started_wall="" started_monotonic=""
  local ended_wall="" ended_monotonic="" extra=""
  local -a services=(java-backend)

  [[ "$timing" == cpu_measurement_baseline || "$timing" == cpu_measurement_end ]] || return 1
  if [[ "$CELL_REQUIRES_OBI" == true ]]; then
    services=(obi "${services[@]}")
  fi
  clocks="$(clock_pair_values)" || return 1
  read -r started_wall started_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  mkdir -- "$snapshot_directory" || return 1
  for service in "${services[@]}"; do
    if capture_service_identity "$service" \
      "$snapshot_directory/$service-identity.txt"; then
      capture_bound_cgroup_v2_snapshot \
        "$snapshot_directory/$service-identity.txt" \
        "$snapshot_directory/$service-cgroup-v2.json" \
        "$timing" "$CELL_SLUG" "$service" || return 1
    else
      printf 'status=unavailable\n' >"$snapshot_directory/$service-identity.txt"
      write_unavailable_bound_cgroup_v2_snapshot \
        "$snapshot_directory/$service-cgroup-v2.json" \
        "$CELL_SLUG" "$service" "$timing" || return 1
    fi
  done
  clocks="$(clock_pair_values)" || return 1
  read -r ended_wall ended_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  validate_elapsed_clock_window \
    "$started_wall" "$started_monotonic" "$ended_wall" "$ended_monotonic" 0 >/dev/null || return 1
  jq -n --arg timing "$timing" --arg cell "$CELL_SLUG" \
    --argjson started_wall "$started_wall" --argjson started_monotonic "$started_monotonic" \
    --argjson ended_wall "$ended_wall" --argjson ended_monotonic "$ended_monotonic" '{
      schema_version: 1,
      kind: "authoritative-application-cgroup-v2-boundary",
      timing: $timing,
      cell: $cell,
      services: $ARGS.positional,
      capture: {
        started: {wall_epoch_seconds: $started_wall,
          monotonic_milliseconds: $started_monotonic},
        ended: {wall_epoch_seconds: $ended_wall,
          monotonic_milliseconds: $ended_monotonic}
      },
      authority: {
        cpu_stat: "authoritative",
        process_tree_fd_task_rss: "authoritative",
        primary_cgroupsockopt_program_cpu: "not_collected"
      }
    }' --args "${services[@]}" >"$snapshot_directory/snapshot.json" || return 1
  validate_cpu_measurement_boundary "$snapshot_directory" "$CELL_SLUG" "$timing"
}

validate_cpu_measurement_boundary_json_value() {
  local -r boundary_value="$1"
  local -r expected_cell="$2"
  local -r expected_timing="$3"

  printf '%s' "$boundary_value" | jq -se \
    --arg cell "$expected_cell" --arg timing "$expected_timing" '
    def n: type == "number" and isfinite and floor == . and . >= 0 and . <= 9007199254740991;
    length == 1 and (.[0] |
      (keys | sort) == ["authority", "capture", "cell", "kind", "schema_version",
        "services", "timing"] and
      .schema_version == 1 and .kind == "authoritative-application-cgroup-v2-boundary" and
      .cell == $cell and .timing == $timing and
      (.timing == "cpu_measurement_baseline" or .timing == "cpu_measurement_end") and
      (.services == ["java-backend"] or .services == ["obi", "java-backend"]) and
      .authority == {cpu_stat: "authoritative", process_tree_fd_task_rss: "authoritative",
        primary_cgroupsockopt_program_cpu: "not_collected"} and
      (.capture | (keys | sort) == ["ended", "started"] and
        all(.[]; (keys | sort) == ["monotonic_milliseconds", "wall_epoch_seconds"] and
          (.wall_epoch_seconds | n) and (.monotonic_milliseconds | n)) and
        .ended.wall_epoch_seconds >= .started.wall_epoch_seconds and
        .ended.monotonic_milliseconds >= .started.monotonic_milliseconds))
  ' >/dev/null
}

validated_cpu_measurement_boundary_bundle() (
  local -r directory="$1"
  local -r expected_cell="$2"
  local -r expected_timing="$3"
  local directory_fd=""
  local directory_anchor=""
  local directory_identity=""
  local directory_identity_after=""
  local services_text=""
  local service=""
  local boundary_value=""
  local snapshot_value=""
  local identity_value=""
  local services_json=""
  local snapshots_json=""
  local captured_boundary_bundle=""
  local -a services=()
  local -a snapshot_values=()

  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  directory_identity="$(stat --format '%d:%i:%u:%a' -- "$directory")" || return 1
  exec {directory_fd}<"$directory" || return 1
  directory_anchor="/proc/self/fd/$directory_fd"
  trap 'exec {directory_fd}<&- 2>/dev/null || true' EXIT
  [[ ! -L "$directory" &&
    "$(stat -L --format '%d:%i:%u:%a' -- "$directory_anchor")" == \
      "$directory_identity" ]] || return 1
  boundary_value="$(bounded_duplicate_free_json_value \
    "$directory_anchor/snapshot.json" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  validate_cpu_measurement_boundary_json_value \
    "$boundary_value" "$expected_cell" "$expected_timing" || return 1
  services_text="$(printf '%s' "$boundary_value" | \
    jq -er '.services | join(" ")')" || return 1
  read -r -a services <<<"$services_text" || return 1
  for service in "${services[@]}"; do
    [[ -f "$directory_anchor/$service-identity.txt" ]] || return 1
    snapshot_value="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
      "$directory_anchor/$service-cgroup-v2.json" "$expected_cell" "$service" \
      "$expected_timing")" || return 1
    capture_bounded_regular_file_value "$directory_anchor/$service-identity.txt" \
      "$MAX_SERVICE_IDENTITY_BYTES" identity_value || return 1
    validate_bound_cgroup_v2_snapshot_identity_state_values "$snapshot_value" \
      "$identity_value" "$service-identity.txt" "$service" || return 1
    printf '%s' "$snapshot_value" | jq -e \
      --arg cell "$expected_cell" --arg service "$service" --arg timing "$expected_timing" '
      .cell == $cell and .service == $service and .timing == $timing and
      .repetition == null and .identity_source == ($service + "-identity.txt")
    ' >/dev/null || return 1
    snapshot_values+=("$snapshot_value")
  done
  directory_identity_after="$(stat --format '%d:%i:%u:%a' -- "$directory")" || return 1
  [[ ! -L "$directory" && "$directory_identity_after" == "$directory_identity" &&
    "$(stat -L --format '%d:%i:%u:%a' -- "$directory_anchor")" == \
      "$directory_identity" ]] || return 1
  services_json="$(jq -cn '$ARGS.positional' --args "${services[@]}")" || return 1
  snapshots_json="$(printf '%s\n' "${snapshot_values[@]}" | jq -s .)" || return 1
  captured_boundary_bundle="$(printf '%s\n%s\n%s' "$boundary_value" \
    "$services_json" "$snapshots_json" | jq -cs '
      if length != 3 then error("expected CPU boundary, services, and snapshots")
      else . end |
      {boundary: .[0], services: .[1], snapshots:
        (.[1] as $services | .[2] |
          to_entries | map({key: $services[.key], value: .value}) | from_entries)}
    ')" || return 1
  printf '%s' "$captured_boundary_bundle"
)

validate_cpu_measurement_boundary() {
  local -r directory="$1"
  local -r expected_cell="$2"
  local -r expected_timing="$3"
  local -r output_name="${4:-}"
  local captured_cpu_boundary_bundle=""

  captured_cpu_boundary_bundle="$(validated_cpu_measurement_boundary_bundle \
    "$directory" "$expected_cell" "$expected_timing")" || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$captured_cpu_boundary_bundle"
  fi
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
  local -r partial="${output}.partial"
  local captured_bytes=""

  [[ ! -e "$output" && ! -L "$output" && ! -e "$partial" && ! -L "$partial" ]] || return 1
  if [[ "$CELL_REQUIRES_OBI" != "true" ]]; then
    printf 'status=not_applicable\n' >"$output"
    return 0
  fi
  if run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    curl --fail --silent --show-error --max-time 5 \
      --max-filesize "$MAX_OBI_METRICS_SNAPSHOT_BYTES" \
      "http://127.0.0.1:18990/internal/metrics" >"$partial" 2>"$output.stderr"; then
    if captured_bytes="$(stat --format '%s' -- "$partial")" &&
      [[ "$captured_bytes" =~ ^[1-9][0-9]*$ ]] &&
      ((captured_bytes <= MAX_OBI_METRICS_SNAPSHOT_BYTES)) &&
      mv -T -- "$partial" "$output"; then
      return 0
    fi
  fi
  rm -f -- "$partial"
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
  local java_diagnostics_reason=""
  local measurement_metrics_captured=false
  local clocks=""
  local captured_started_wall="" captured_started_monotonic=""
  local captured_ended_wall="" captured_ended_monotonic=""
  local extra=""
  local -a services=(trace-receiver apache-proxy java-backend)
  local -a container_ids=()

  [[ "$timing" == "before" || "$timing" == "after" ||
    "$timing" == "idle_recovery_01" || "$timing" == "idle_recovery_02" ||
    "$timing" == "program_metrics_baseline" ||
    "$timing" == "program_metrics_end" ]] || return 1
  (($# >= 2 && $# <= 3)) || return 1
  [[ "$java_diagnostics_mode" == requested || "$java_diagnostics_mode" == not_collected ]] || return 1
  if [[ "$java_diagnostics_mode" == not_collected ]]; then
    if [[ "$timing" == "program_metrics_baseline" || "$timing" == "program_metrics_end" ]]; then
      java_diagnostics_reason="excluded_from_exact_sustained_measurement_counter_window"
    elif [[ "$timing" == "idle_recovery_01" || "$timing" == "idle_recovery_02" ]]; then
      java_diagnostics_reason="excluded_from_ordered_idle_recovery_window"
    else
      return 1
    fi
  fi
  if [[ "$CELL_REQUIRES_OBI" == "true" ]]; then
    if [[ "$timing" == "program_metrics_end" ]]; then
      services=(obi "${services[@]}")
    else
      services+=(obi)
    fi
  fi
  clocks="$(clock_pair_values)" || return 1
  read -r captured_started_wall captured_started_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  mkdir -- "$snapshot_directory"

  for service in "${services[@]}"; do
    if capture_service_identity "$service" "$snapshot_directory/$service-identity.txt"; then
      container_id="$(identity_field "$snapshot_directory/$service-identity.txt" container_id)" || return 1
      host_pid="$(identity_field "$snapshot_directory/$service-identity.txt" host_pid)" || return 1
      container_ids+=("$container_id")
      run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker inspect "$container_id" \
        >"$snapshot_directory/$service-inspect.json" 2>"$snapshot_directory/$service-inspect.stderr" || true
      capture_proc_snapshot "$snapshot_directory/$service-identity.txt" \
        "$snapshot_directory/$service-proc.txt"
      if [[ ( "$service" == java-backend || "$service" == obi ) &&
        "$timing" != program_metrics_baseline && "$timing" != program_metrics_end ]]; then
        capture_bound_cgroup_v2_snapshot \
          "$snapshot_directory/$service-identity.txt" \
          "$snapshot_directory/$service-cgroup-v2.json" \
          "$timing" "$CELL_SLUG" "$service" || return 1
      fi
      if [[ "$service" == obi && "$timing" == "program_metrics_end" &&
        "$CELL_SELECTED_TRANSPORT" == "getsockopt" ]]; then
        capture_fenced_obi_metrics_with_ownership \
          "$snapshot_directory/obi-identity.txt" \
          "$snapshot_directory/obi-bpf-fd-ownership.txt" \
          "$snapshot_directory/obi-metrics.prom" \
          "$snapshot_directory/obi-metrics-fence.json" \
          "$CELL_SLUG immediate post-load measurement boundary" || return 1
        measurement_metrics_captured=true
      fi
    else
      printf 'status=unavailable\n' >"$snapshot_directory/$service-identity.txt"
      printf 'status=unavailable\n' >"$snapshot_directory/$service-proc.txt"
      if [[ ( "$service" == java-backend || "$service" == obi ) &&
        "$timing" != program_metrics_baseline && "$timing" != program_metrics_end ]]; then
        write_unavailable_bound_cgroup_v2_snapshot \
          "$snapshot_directory/$service-cgroup-v2.json" \
          "$CELL_SLUG" "$service" "$timing" || return 1
      fi
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
    if [[ "$timing" == "program_metrics_baseline" || "$timing" == "program_metrics_end" ]]; then
      if [[ "$CELL_SELECTED_TRANSPORT" == "getsockopt" ]]; then
        if [[ "$measurement_metrics_captured" == "false" ]]; then
          capture_fenced_obi_metrics_with_ownership \
            "$snapshot_directory/obi-identity.txt" \
            "$snapshot_directory/obi-bpf-fd-ownership.txt" \
            "$snapshot_directory/obi-metrics.prom" \
            "$snapshot_directory/obi-metrics-fence.json" \
            "$CELL_SLUG post-warmup measurement baseline" || return 1
        fi
      else
        capture_obi_metrics_with_ownership \
          "$snapshot_directory/obi-identity.txt" \
          "$snapshot_directory/obi-bpf-fd-ownership.txt" \
          "$snapshot_directory/obi-metrics.prom" || return 1
        jq -n '{
          status: "not_applicable",
          reason: "selected_transport_does_not_use_cgroup_sockopt_bridge"
        }' >"$snapshot_directory/obi-metrics-fence.json" || return 1
      fi
    else
      capture_obi_metrics_with_ownership \
        "$snapshot_directory/obi-identity.txt" \
        "$snapshot_directory/obi-bpf-fd-ownership.txt" \
        "$snapshot_directory/obi-metrics.prom"
    fi
  else
    capture_obi_metrics "$snapshot_directory/obi-metrics.prom"
    printf 'status=not_applicable\n' >"$snapshot_directory/obi-bpf-fd-ownership.txt"
    if [[ "$timing" == "program_metrics_baseline" || "$timing" == "program_metrics_end" ]]; then
      jq -n '{status: "not_applicable", reason: "cell_has_no_obi_process"}' \
        >"$snapshot_directory/obi-metrics-fence.json"
    fi
  fi
  if [[ "$java_diagnostics_mode" == requested ]]; then
    capture_java_diagnostics "$snapshot_directory/java-diagnostics.txt"
  fi
  clocks="$(clock_pair_values)" || return 1
  read -r captured_ended_wall captured_ended_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  validate_elapsed_clock_window \
    "$captured_started_wall" "$captured_started_monotonic" \
    "$captured_ended_wall" "$captured_ended_monotonic" 0 >/dev/null || return 1
  jq -n --arg timing "$timing" --arg cell "$CELL_SLUG" \
    --arg java_diagnostics_mode "$java_diagnostics_mode" \
    --arg java_diagnostics_reason "$java_diagnostics_reason" \
    --argjson started_wall "$captured_started_wall" \
    --argjson started_monotonic "$captured_started_monotonic" \
    --argjson ended_wall "$captured_ended_wall" \
    --argjson ended_monotonic "$captured_ended_monotonic" \
    --argjson program_metrics "$([[ "$timing" == program_metrics_baseline || "$timing" == program_metrics_end ]] && printf true || printf false)" \
    '{
      schema_version: 1,
      kind: "program-and-resource-diagnostic-snapshot",
      cell: $cell,
      timing: $timing,
      capture: {
        started: {wall_epoch_seconds: $started_wall,
          monotonic_milliseconds: $started_monotonic},
        ended: {wall_epoch_seconds: $ended_wall,
          monotonic_milliseconds: $ended_monotonic}
      },
      authority: (if $program_metrics then
        {classification: "diagnostic_only", process_tree_cgroup_v2: "not_collected"}
      else
        {classification: "resource_boundary", process_tree_cgroup_v2: "collected"}
      end),
      java_diagnostics: (
        if $java_diagnostics_mode == "requested" then {status: "requested"}
        else {status: "not_collected", reason: $java_diagnostics_reason}
        end
      )
    }' >"$snapshot_directory/snapshot.json" || return 1
  validate_resource_snapshot_boundary \
    "$snapshot_directory/snapshot.json" "$CELL_SLUG" "$timing"
}

validate_resource_snapshot_boundary_json_value() {
  local -r boundary_value="$1"
  local -r expected_cell="$2"
  local -r expected_timing="$3"

  printf '%s' "$boundary_value" | jq -se \
    --arg cell "$expected_cell" --arg timing "$expected_timing" '
    def n: type == "number" and isfinite and floor == . and . >= 0 and . <= 9007199254740991;
    length == 1 and (.[0] |
      (keys | sort) == ["authority", "capture", "cell", "java_diagnostics", "kind",
        "schema_version", "timing"] and
      .schema_version == 1 and .kind == "program-and-resource-diagnostic-snapshot" and
      .cell == $cell and .timing == $timing and
      (.timing == "before" or .timing == "after" or
        .timing == "idle_recovery_01" or .timing == "idle_recovery_02" or
        .timing == "program_metrics_baseline" or .timing == "program_metrics_end") and
      (.capture | (keys | sort) == ["ended", "started"] and
        all(.[]; (keys | sort) == ["monotonic_milliseconds", "wall_epoch_seconds"] and
          (.wall_epoch_seconds | n) and (.monotonic_milliseconds | n)) and
        .ended.wall_epoch_seconds >= .started.wall_epoch_seconds and
        .ended.monotonic_milliseconds >= .started.monotonic_milliseconds) and
      (if (.timing == "program_metrics_baseline" or .timing == "program_metrics_end") then
        .authority == {classification: "diagnostic_only", process_tree_cgroup_v2: "not_collected"}
      else
        .authority == {classification: "resource_boundary", process_tree_cgroup_v2: "collected"}
      end) and
      (.java_diagnostics == {status: "requested"} or
        (.java_diagnostics | (keys | sort) == ["reason", "status"] and
          .status == "not_collected" and (.reason | type == "string" and length > 0))))
  ' >/dev/null
}

validate_resource_snapshot_boundary() {
  local -r artifact="$1"
  local -r expected_cell="$2"
  local -r expected_timing="$3"
  local boundary_value=""

  boundary_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  validate_resource_snapshot_boundary_json_value \
    "$boundary_value" "$expected_cell" "$expected_timing"
}

validate_resource_cgroup_boundary() {
  local -r directory="$1"
  local -r expected_cell="$2"
  local -r expected_timing="$3"
  local -r service="$4"
  local bundle_value=""

  bundle_value="$(validated_resource_cgroup_boundary_bundle \
    "$directory" "$expected_cell" "$expected_timing")" || return 1
  printf '%s' "$bundle_value" | jq -e --arg service "$service" '
    (.services | index($service)) != null and (.snapshots[$service] != null)
  ' >/dev/null
}

validated_resource_cgroup_boundary_bundle() (
  local -r directory="$1"
  local -r expected_cell="$2"
  local -r expected_timing="$3"
  local boundary_value=""
  local directory_fd=""
  local directory_anchor=""
  local directory_identity=""
  local directory_identity_after=""
  local snapshot_value=""
  local identity_value=""
  local services_json=""
  local snapshots_json=""
  local service=""
  local -a services=(java-backend)
  local -a snapshot_values=()

  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  directory_identity="$(stat --format '%d:%i:%u:%a' -- "$directory")" || return 1
  exec {directory_fd}<"$directory" || return 1
  directory_anchor="/proc/self/fd/$directory_fd"
  trap 'exec {directory_fd}<&- 2>/dev/null || true' EXIT
  [[ ! -L "$directory" &&
    "$(stat -L --format '%d:%i:%u:%a' -- "$directory_anchor")" == \
      "$directory_identity" ]] || return 1
  cell_spec "$expected_cell" || return 1
  if [[ "$CELL_REQUIRES_OBI" == true ]]; then
    services=(obi "${services[@]}")
  fi
  boundary_value="$(bounded_duplicate_free_json_value \
    "$directory_anchor/snapshot.json" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  validate_resource_snapshot_boundary_json_value \
    "$boundary_value" "$expected_cell" "$expected_timing" || return 1
  for service in "${services[@]}"; do
    snapshot_value="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
      "$directory_anchor/$service-cgroup-v2.json" "$expected_cell" "$service" \
      "$expected_timing")" || return 1
    capture_bounded_regular_file_value "$directory_anchor/$service-identity.txt" \
      "$MAX_SERVICE_IDENTITY_BYTES" identity_value || return 1
    validate_bound_cgroup_v2_snapshot_identity_state_values "$snapshot_value" \
      "$identity_value" "$service-identity.txt" "$service" || return 1
    printf '%s' "$snapshot_value" | jq -e \
      --arg cell "$expected_cell" --arg timing "$expected_timing" \
      --arg service "$service" '
        .cell == $cell and .timing == $timing and .service == $service and
        .repetition == null and .identity_source == ($service + "-identity.txt")
      ' >/dev/null || return 1
    snapshot_values+=("$snapshot_value")
  done
  directory_identity_after="$(stat --format '%d:%i:%u:%a' -- "$directory")" || return 1
  [[ ! -L "$directory" && "$directory_identity_after" == "$directory_identity" &&
    "$(stat -L --format '%d:%i:%u:%a' -- "$directory_anchor")" == \
      "$directory_identity" ]] || return 1
  services_json="$(jq -cn '$ARGS.positional' --args "${services[@]}")" || return 1
  snapshots_json="$(printf '%s\n' "${snapshot_values[@]}" | jq -s .)" || return 1
  printf '%s\n%s\n%s' "$boundary_value" "$services_json" "$snapshots_json" | jq -cs '
    if length != 3 then error("expected resource boundary, services, and snapshots")
    else . end |
    {boundary: .[0], services: .[1], snapshots:
      (.[1] as $services | .[2] |
        to_entries | map({key: $services[.key], value: .value}) | from_entries)}
  '
)

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
  # The report marker is emitted last by one serial Java bridge stats-map reader. A pass
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
        report_is_published_after_each_successful_java_bridge_stats_pass: true
      }
    }' >"$fence_output" || {
    rm -f -- "$output" "$first" "$first_marker" "$second" "$second_marker" || true
    return 1
  }
  rm -f -- "$first" "$first_marker" "$second" "$second_marker" || return 1
}

validate_bpf_probe_collection_fence_value() {
  local -r artifact_value="$1"
  local expected_program_names="[]"

  expected_program_names="$(jq -cn '$ARGS.positional | sort' --args \
    "${JAVA_BRIDGE_CGROUP_SOCKOPT_PROGRAM_NAMES[@]}")" || return 1
  printf '%s' "$artifact_value" | jq -se \
    --argjson expected_program_names "$expected_program_names" '
    def non_negative_integer:
      type == "number" and isfinite and floor == . and . >= 0;
    length == 1 and (.[0] |
      keys == [
        "acceptance_evidence", "captured_at", "confirmation", "description",
        "kind", "metric", "programs", "schema_version"
      ] and
      .schema_version == 1 and
      .kind == "exact-owned-bpf-probe-collection-fence" and
      .acceptance_evidence == false and
      (.captured_at | type == "string" and length > 0) and
      (.description | type == "string" and length > 0) and
      .metric == "obi_bpf_probe_collection_passes_total" and
      .confirmation == {
        required_marker_advances_per_program: 2,
        separate_scrape_started_after_fence_response: true,
        retained_confirmation_scrape: true
      } and
      (.programs | type == "array" and length == ($expected_program_names | length)) and
      (.programs | map(.probe_name) | sort) == $expected_program_names and
      (.programs | map(.program_id) | unique | length) == ($expected_program_names | length) and
      all(.programs[];
        (keys == [
          "confirmation_collection_passes", "initial_collection_passes",
          "observed_fence_collection_passes", "probe_name", "probe_type", "program_id"
        ]) and
        (.program_id | type == "number" and isfinite and floor == . and . > 0) and
        .probe_type == "CGroupSockopt" and
        (.initial_collection_passes | non_negative_integer) and
        (.observed_fence_collection_passes | non_negative_integer) and
        (.confirmation_collection_passes | non_negative_integer) and
        (.observed_fence_collection_passes - .initial_collection_passes) >= 2 and
        .confirmation_collection_passes >= .observed_fence_collection_passes)
    )
  ' >/dev/null
}

validate_bpf_probe_collection_fence() {
  local -r artifact="$1"
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_BPF_PROGRAM_RUNTIME_BYTES")" || return 1
  validate_bpf_probe_collection_fence_value "$artifact_value"
}

bpf_probe_collection_fence_confirmation_records_json() {
  local -r artifact="$1"
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_BPF_PROGRAM_RUNTIME_BYTES")" || return 1
  validate_bpf_probe_collection_fence_value "$artifact_value" || return 1
  printf '%s' "$artifact_value" | jq -ce '
    [.programs[] | {
      program_id,
      probe_type,
      probe_name,
      collection_passes: .confirmation_collection_passes
    }] | sort_by([.program_id, .probe_type, .probe_name])
  '
}

wait_for_bpf_probe_collection_confirmation() {
  local -r initial="$1"
  local -r ownership="$2"
  local -r output="$3"
  local -r fence_output="$4"
  local -r description="$5"
  local -r observed="${output}.fence-observed"
  local -r confirmation="${output}.confirmation"
  local initial_records="[]"
  local observed_records="[]"
  local confirmation_records="[]"
  local deadline=0
  local polls=0

  [[ -f "$initial" && ! -L "$initial" && -f "$ownership" && ! -L "$ownership" &&
    ! -e "$output" && ! -L "$output" &&
    ! -e "$fence_output" && ! -L "$fence_output" &&
    ! -e "$observed" && ! -L "$observed" &&
    ! -e "$confirmation" && ! -L "$confirmation" ]] || return 1
  initial_records="$(exact_owned_java_bridge_probe_records_json \
    "$initial" "$ownership")" || return 1
  deadline="$((SECONDS + POSTLOAD_SENTINEL_TIMEOUT_SECONDS))"
  while ((SECONDS < deadline)); do
    ((polls += 1))
    capture_obi_metrics "$observed" || return 1
    observed_records="$(exact_owned_java_bridge_probe_records_json \
      "$observed" "$ownership")" || {
      rm -f -- "$observed"
      return 1
    }
    if jq -en \
      --argjson initial "$initial_records" \
      --argjson observed "$observed_records" '
        def key($record):
          [$record.program_id, $record.probe_type, $record.probe_name];
        ($initial | map(key(.))) == ($observed | map(key(.))) and
        all(range(0; $initial | length);
          ($observed[.].collection_passes - $initial[.].collection_passes) >= 2 and
          $observed[.].executions >= $initial[.].executions and
          $observed[.].runtime_nanoseconds >= $initial[.].runtime_nanoseconds)
      ' >/dev/null; then
      break
    fi
    rm -f -- "$observed" || return 1
    sleep "$METRICS_SETTLE_SECONDS"
  done
  [[ -f "$observed" && ! -L "$observed" ]] || {
    die "timed out waiting for $description exact-owned program collection markers"
    return $?
  }

  # A Prometheus gather can straddle counter-vector updates. Begin a distinct
  # scrape only after the fence response completed, and retain that confirmation
  # so its count/runtime reads happen after every observed marker publication.
  capture_obi_metrics "$confirmation" || {
    rm -f -- "$observed" "$confirmation"
    return 1
  }
  confirmation_records="$(exact_owned_java_bridge_probe_records_json \
    "$confirmation" "$ownership")" || {
    rm -f -- "$observed" "$confirmation"
    return 1
  }
  if ! jq -en \
    --argjson observed "$observed_records" \
    --argjson confirmation "$confirmation_records" '
      def key($record):
        [$record.program_id, $record.probe_type, $record.probe_name];
      ($observed | map(key(.))) == ($confirmation | map(key(.))) and
      all(range(0; $observed | length);
        $confirmation[.].collection_passes >= $observed[.].collection_passes and
        $confirmation[.].executions >= $observed[.].executions and
        $confirmation[.].runtime_nanoseconds >= $observed[.].runtime_nanoseconds)
    ' >/dev/null; then
    rm -f -- "$observed" "$confirmation"
    return 1
  fi
  install -m 0600 "$confirmation" "$output" || {
    rm -f -- "$observed" "$confirmation"
    return 1
  }
  jq -n \
    --arg description "$description" \
    --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson initial "$initial_records" \
    --argjson observed "$observed_records" \
    --argjson confirmation "$confirmation_records" '
      {
        schema_version: 1,
        kind: "exact-owned-bpf-probe-collection-fence",
        acceptance_evidence: false,
        description: $description,
        captured_at: $captured_at,
        metric: "obi_bpf_probe_collection_passes_total",
        programs: [range(0; $initial | length) as $index | {
          program_id: $initial[$index].program_id,
          probe_type: $initial[$index].probe_type,
          probe_name: $initial[$index].probe_name,
          initial_collection_passes: $initial[$index].collection_passes,
          observed_fence_collection_passes: $observed[$index].collection_passes,
          confirmation_collection_passes: $confirmation[$index].collection_passes
        }],
        confirmation: {
          required_marker_advances_per_program: 2,
          separate_scrape_started_after_fence_response: true,
          retained_confirmation_scrape: true
        }
      }
    ' >"$fence_output" || {
    rm -f -- "$output" "$observed" "$confirmation" "$fence_output"
    return 1
  }
  rm -f -- "$observed" "$confirmation" || return 1
  validate_bpf_probe_collection_fence "$fence_output"
}

capture_fenced_obi_metrics_with_ownership() {
  local -r identity_file="$1"
  local -r ownership_output="$2"
  local -r metrics_output="$3"
  local -r fence_output="$4"
  local -r description="$5"
  local -r ownership_before="${ownership_output}.before"
  local -r ownership_after="${ownership_output}.after"
  local -r metrics_observed="${metrics_output}.observed"

  [[ "$CELL_REQUIRES_OBI" == "true" && -f "$identity_file" && ! -L "$identity_file" ]] || return 1
  [[ ! -e "$ownership_output" && ! -L "$ownership_output" &&
    ! -e "$ownership_before" && ! -L "$ownership_before" &&
    ! -e "$ownership_after" && ! -L "$ownership_after" &&
    ! -e "$metrics_output" && ! -L "$metrics_output" &&
    ! -e "$metrics_observed" && ! -L "$metrics_observed" &&
    ! -e "$fence_output" && ! -L "$fence_output" ]] || return 1
  capture_bpf_fd_ownership "$identity_file" "$ownership_before" || return 1
  if ! grep -Fxq 'status=available' "$ownership_before"; then
    rm -f -- "$ownership_before"
    return 1
  fi
  if ! capture_obi_metrics "$metrics_observed" ||
    ! wait_for_bpf_probe_collection_confirmation \
      "$metrics_observed" "$ownership_before" \
      "$metrics_output" "$fence_output" "$description" ||
    ! capture_bpf_fd_ownership "$identity_file" "$ownership_after"; then
    rm -f -- "$ownership_before" "$ownership_after" "$metrics_observed" \
      "$metrics_output" "$fence_output"
    return 1
  fi
  rm -f -- "$metrics_observed" || return 1
  if ! grep -Fxq 'status=available' "$ownership_after" ||
    ! cmp -s -- "$ownership_before" "$ownership_after"; then
    rm -f -- "$ownership_before" "$ownership_after" "$metrics_output" "$fence_output"
    return 1
  fi
  mv -T -- "$ownership_before" "$ownership_output" || {
    rm -f -- "$ownership_before" "$ownership_after" "$metrics_output" "$fence_output"
    return 1
  }
  rm -f -- "$ownership_after" || return 1
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

validate_benchmark_result_json_value() {
  local -r result_value="$1"
  local -r duration_seconds="$2"
  local -r expected_seed="${3:-$SUSTAINED_LOAD_SEED}"
  local result_bytes=""
  local raw_value_count=""

  LC_ALL=C result_bytes="${#result_value}"
  [[ "$result_bytes" =~ ^[1-9][0-9]*$ ]] || return 1
  ((result_bytes <= MAX_BENCHMARK_RESULT_BYTES)) || return 1
  # jq's ordinary object parser keeps the last duplicate key. Its streaming
  # input retains every raw member value, so comparing this bounded count with
  # the exact parsed schema detects duplicates at every object depth first.
  raw_value_count="$(printf '%s' "$result_value" | jq --stream -n '
    reduce inputs as $event (0;
      if ($event | length) == 2 then . + 1 else . end)
  ')" || return 1
  [[ "$raw_value_count" =~ ^[1-9][0-9]*$ ]] || return 1
  ((raw_value_count <= 23 + 2 * REQUEST_LIMIT)) || return 1
  printf '%s' "$result_value" | jq -se \
    --arg base_url "$CELL_WORKLOAD_BASE_URL" \
    --arg path "$CELL_WORKLOAD_PATH" \
    --arg connection_mode "$CELL_WORKLOAD_CONNECTION_MODE" \
    --arg tls_verification "$CELL_EXPECTED_TLS_VERIFICATION" \
    --argjson duration_nanos "$((duration_seconds * 1000000000))" \
    --argjson maximum_traffic_elapsed_nanos "$(((duration_seconds + MEASUREMENT_OVERRUN_TOLERANCE_SECONDS) * 1000000000))" \
    --argjson request_timeout_nanos "$((REQUEST_TIMEOUT_SECONDS * 1000000000))" \
    --argjson concurrency "$CONCURRENCY" \
    --argjson request_limit "$REQUEST_LIMIT" \
    --argjson sustained_load_seed "$expected_seed" \
    --argjson maximum_safe_integer "$MAX_SEED" \
    --argjson raw_value_count "$raw_value_count" \
    --argjson expected_w3c "$CELL_SUSTAINED_W3C" '
      def finite_number:
        type == "number" and isfinite;
      def positive_integer:
        finite_number and floor == . and . > 0 and . <= $maximum_safe_integer;
      def non_negative_integer:
        finite_number and floor == . and . >= 0 and . <= $maximum_safe_integer;
      def positive_number:
        finite_number and . > 0;
      def absolute:
        if . < 0 then -. else . end;
      def timestamp_parts:
        capture("^(?<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\\.(?<fraction>[0-9]{0,8}[1-9]))?Z$") as $parts |
        ($parts.base + "Z" | fromdateiso8601) as $seconds |
        select($seconds > 0) |
        select(($seconds | todateiso8601) == ($parts.base + "Z")) |
        [$seconds, (((($parts.fraction // "") + "000000000")[0:9]) | tonumber)];
      def nearest_rank($runs; $count; $percent):
        ((($count * $percent + 99) / 100) | floor) as $rank |
        (reduce $runs[] as $run (
          {seen: 0, value: null};
          if .value != null then .
          else
            (.seen + $run.count) as $next |
            .seen = $next |
            if $next >= $rank then .value = $run.nanos else . end
          end
        ) | .value);
      length == 1 and
      (.[0] |
        . as $result |
        (.started_at | timestamp_parts) as $started |
        (.finished_at | timestamp_parts) as $finished |
        (.successful_requests * 1000000000 / .traffic_elapsed_nanos) as $expected_throughput |
        ([1e-12, ($expected_throughput * 1e-12)] | max) as $throughput_tolerance |
        (keys) == [
          "base_url", "canceled", "concurrency", "connection_mode",
          "failed_requests", "finished_at", "latency", "path", "request_limit",
          "request_limit_reached", "request_timeout_nanos",
          "requested_duration_nanos", "seed", "started_at", "status",
          "successful_requests", "throughput_per_second", "tls_verification",
          "traffic_elapsed_nanos", "w3c"
        ] and
        $started <= $finished and
        .status == "passed" and
        .base_url == $base_url and
        .path == $path and
        .connection_mode == $connection_mode and
        .tls_verification == $tls_verification and
        .w3c == $expected_w3c and
        (.seed | non_negative_integer) and .seed == $sustained_load_seed and
        (.requested_duration_nanos | positive_integer) and
        .requested_duration_nanos == $duration_nanos and
        (.request_timeout_nanos | positive_integer) and
        .request_timeout_nanos == $request_timeout_nanos and
        (.concurrency | positive_integer) and .concurrency == $concurrency and
        (.request_limit | positive_integer) and .request_limit == $request_limit and
        .request_limit_reached == false and
        .canceled == false and
        (.successful_requests | positive_integer and . <= $request_limit) and
        (.failed_requests | non_negative_integer and . == 0) and
        (.traffic_elapsed_nanos |
          positive_integer and . >= $duration_nanos and . <= $maximum_traffic_elapsed_nanos) and
        (.throughput_per_second | positive_number) and
        ((.throughput_per_second - $expected_throughput) | absolute) <=
          $throughput_tolerance and
        (.latency | type == "object") and
        (.latency | keys) == [
          "histogram", "histogram_encoding", "p50_nanos", "p95_nanos", "p99_nanos"
        ] and
        .latency.histogram_encoding == "sorted_rle_nanos_v1" and
        (.latency.histogram | type == "array" and length > 0 and length <= $request_limit) and
        all(.latency.histogram[];
          (type == "object") and (keys == ["count", "nanos"]) and
          (.nanos | positive_integer and . <= $maximum_traffic_elapsed_nanos) and
          (.count | positive_integer)) and
        .latency.histogram as $histogram |
        ($histogram | length) as $histogram_length |
        $raw_value_count == (23 + 2 * $histogram_length) and
        all(range(1; $histogram_length);
          $histogram[.].nanos > $histogram[. - 1].nanos) and
        ([$histogram[].count] | add) == .successful_requests and
        (.latency.p50_nanos | positive_integer) and
        (.latency.p95_nanos | positive_integer) and
        (.latency.p99_nanos | positive_integer) and
        .latency.p50_nanos == nearest_rank($histogram; .successful_requests; 50) and
        .latency.p95_nanos == nearest_rank($histogram; .successful_requests; 95) and
        .latency.p99_nanos == nearest_rank($histogram; .successful_requests; 99)
      )
    ' >/dev/null
}

validated_benchmark_result_json_value() {
  local -r result="$1"
  local -r duration_seconds="$2"
  local -r expected_seed="${3:-$SUSTAINED_LOAD_SEED}"
  local result_value=""

  result_value="$(bounded_duplicate_free_json_value \
    "$result" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  validate_benchmark_result_json_value \
    "$result_value" "$duration_seconds" "$expected_seed" || return 1
  printf '%s' "$result_value"
}

validate_benchmark_result() {
  local -r result="$1"
  local -r duration_seconds="$2"
  local -r expected_seed="${3:-$SUSTAINED_LOAD_SEED}"
  local result_value=""

  result_value="$(validated_benchmark_result_json_value \
    "$result" "$duration_seconds" "$expected_seed")"
}

benchmark_successful_request_count_json_value() {
  local -r result_value="$1"
  local count=""

  count="$(printf '%s' "$result_value" | jq -ser '
    if length == 1 and
      (.[0].successful_requests |
        if type == "number" then floor == . else false end)
    then .[0].successful_requests
    else empty
    end
  ')" || return 1
  normalize_decimal "$count" "$REQUEST_LIMIT" false
}

benchmark_successful_request_count() {
  local -r result="$1"
  local result_value=""

  result_value="$(bounded_duplicate_free_json_value \
    "$result" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  benchmark_successful_request_count_json_value "$result_value"
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
  local -r partial="${output}.partial"
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
      "${arguments[@]}" >"$partial" 2>"$output.stderr"
}

clear_active_benchmark() {
  BENCHMARK_PID=""
  BENCHMARK_IDENTITY=""
  BENCHMARK_OUTPUT=""
  BENCHMARK_DURATION_SECONDS=""
  BENCHMARK_CELL_DIR=""
  BENCHMARK_OUTPUT_PARENT_IDENTITY=""
  BENCHMARK_CONFIRMED_WALL_EPOCH_SECONDS=""
  BENCHMARK_CONFIRMED_MONOTONIC_MILLISECONDS=""
}

benchmark_output_is_allowed() {
  local -r output="$1"
  local -r cell_dir="$2"
  local relative=""
  local repetition=""

  [[ "$output" == /* && "$cell_dir" == /* && "$cell_dir" != / &&
    -d "$cell_dir" && ! -L "$cell_dir" &&
    "$output" != *$'\n'* && "$output" != *$'\r'* &&
    "$cell_dir" != *$'\n'* && "$cell_dir" != *$'\r'* &&
    "$output" != *'//' && "$output" != *'/./'* && "$output" != *'/../'* &&
    "$output" != */. && "$output" != */.. &&
    "$cell_dir" != *'//' && "$cell_dir" != *'/./'* && "$cell_dir" != *'/../'* &&
    "$cell_dir" != */. && "$cell_dir" != */.. ]] || return 1
  if [[ "$output" == "$cell_dir/warmup.json" ]]; then
    return 0
  fi
  [[ "$output" == "$cell_dir"/* ]] || return 1
  relative="${output#"$cell_dir"/}"
  [[ "$relative" =~ ^measurements/rep-([0-9]{2})\.json$ ]] || return 1
  repetition="$((10#${BASH_REMATCH[1]}))"
  ((repetition >= 1 && repetition <= REPETITIONS))
}

benchmark_output_parent_identity() {
  local -r output="$1"
  local parent=""

  [[ "$output" == /* ]] || return 1
  parent="${output%/*}"
  [[ "$parent" == /* && -d "$parent" && ! -L "$parent" ]] || return 1
  stat --format '%d:%i:%u:%a' -- "$parent"
}

benchmark_output_contract_matches() {
  local -r output="$1"
  local -r cell_dir="$2"
  local -r expected_parent_identity="$3"
  local observed_parent_identity=""

  [[ "$expected_parent_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ ]] || return 1
  benchmark_output_is_allowed "$output" "$cell_dir" || return 1
  observed_parent_identity="$(benchmark_output_parent_identity "$output")" || return 1
  [[ "$observed_parent_identity" == "$expected_parent_identity" ]]
}

# Removes only the unpublished client result for a launch whose exact cell path
# and output-parent identity still match their launch-time values. A symlink at
# the final .partial component is unlinked without following it; directories and
# any malformed or out-of-cell path fail closed.
discard_benchmark_partial() {
  local -r output="$1"
  local -r cell_dir="$2"
  local -r expected_parent_identity="$3"
  local -r partial="${output}.partial"

  benchmark_output_contract_matches \
    "$output" "$cell_dir" "$expected_parent_identity" || return 1
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  if [[ -e "$partial" || -L "$partial" ]]; then
    [[ -L "$partial" || ! -d "$partial" ]] || return 1
    rm -f -- "$partial" || return 1
  fi
  [[ ! -e "$output" && ! -L "$output" && ! -e "$partial" && ! -L "$partial" ]]
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
  local -r cell_dir="$ACTIVE_CELL_DIR"
  local identity_status=0
  local cleanup_status=0
  local parent_identity=""
  local confirmed_clocks=""
  local confirmed_wall=""
  local confirmed_monotonic=""
  local extra=""

  clear_active_benchmark
  benchmark_output_is_allowed "$output" "$cell_dir" || return 1
  parent_identity="$(benchmark_output_parent_identity "$output")" || return 1
  [[ ! -e "$output" && ! -L "$output" &&
    ! -e "${output}.partial" && ! -L "${output}.partial" ]] || return 1
  BENCHMARK_OUTPUT="$output"
  BENCHMARK_DURATION_SECONDS="$duration_seconds"
  BENCHMARK_CELL_DIR="$cell_dir"
  BENCHMARK_OUTPUT_PARENT_IDENTITY="$parent_identity"
  start_benchmark_client "$output" "$duration_seconds" &
  BENCHMARK_PID=$!
  if record_active_benchmark_identity; then
    confirmed_clocks="$(clock_pair_values)" || {
      abort_active_benchmark || true
      return 1
    }
    read -r confirmed_wall confirmed_monotonic extra <<<"$confirmed_clocks" || {
      abort_active_benchmark || true
      return 1
    }
    if [[ -n "$extra" ]] || ! benchmark_job_is_running "$BENCHMARK_PID" ||
      ! benchmark_identity_matches_leader "$BENCHMARK_PID"; then
      abort_active_benchmark || true
      return 1
    fi
    BENCHMARK_CONFIRMED_WALL_EPOCH_SECONDS="$confirmed_wall"
    BENCHMARK_CONFIRMED_MONOTONIC_MILLISECONDS="$confirmed_monotonic"
    return 0
  else
    identity_status=$?
  fi
  abort_active_benchmark || cleanup_status=$?
  # record_active_benchmark_identity can reap and clear the globals before it
  # reports an early launch failure. Retain the launch-time path binding here
  # so that the same exact partial is still discarded.
  discard_benchmark_partial "$output" "$cell_dir" "$parent_identity" || cleanup_status=$?
  ((cleanup_status == 0)) || return 1
  return "$identity_status"
}

wait_for_active_benchmark() {
  local benchmark_pid="$BENCHMARK_PID"
  local benchmark_output="$BENCHMARK_OUTPUT"
  local benchmark_duration_seconds="$BENCHMARK_DURATION_SECONDS"
  local benchmark_partial="${BENCHMARK_OUTPUT}.partial"
  local benchmark_cell_dir="$BENCHMARK_CELL_DIR"
  local benchmark_parent_identity="$BENCHMARK_OUTPUT_PARENT_IDENTITY"
  local wait_status=0
  local cleanup_status=0

  [[ "$benchmark_pid" =~ ^[1-9][0-9]*$ && "$benchmark_output" == /* &&
    "$benchmark_duration_seconds" =~ ^[1-9][0-9]*$ ]] &&
    benchmark_output_contract_matches \
      "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity" || {
    abort_active_benchmark || true
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
  if ((wait_status != 0)); then
    discard_benchmark_partial \
      "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity" || return 1
    return "$wait_status"
  fi
  if ((cleanup_status != 0)); then
    discard_benchmark_partial \
      "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity" || return 1
    return "$cleanup_status"
  fi
  if ! benchmark_output_contract_matches \
    "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity"; then
    return 1
  fi
  if ! validate_benchmark_result "$benchmark_partial" "$benchmark_duration_seconds"; then
    discard_benchmark_partial \
      "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity" || return 1
    return 1
  fi
  if [[ -e "$benchmark_output" || -L "$benchmark_output" ]]; then
    discard_benchmark_partial \
      "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity" || return 1
    return 1
  fi
  if ! mv -T -- "$benchmark_partial" "$benchmark_output"; then
    discard_benchmark_partial \
      "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity" || return 1
    return 1
  fi
}

clear_active_midpoint_transaction() {
  MIDPOINT_ACTIVE=false
  MIDPOINT_CELL_DIR=""
  MIDPOINT_PARTIAL=""
  MIDPOINT_FINAL=""
  MIDPOINT_PARENT_IDENTITY=""
  MIDPOINT_PARTIAL_IDENTITY=""
  MIDPOINT_PARENT_DIRECTORY_AUTHORITY=""
  MIDPOINT_PARTIAL_DIRECTORY_AUTHORITY=""
  MIDPOINT_REPETITION=""
  MIDPOINT_DURATION_SECONDS=""
  MIDPOINT_BENCHMARK_PID=""
  MIDPOINT_BENCHMARK_IDENTITY=""
  MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS=""
  MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS=""
  MIDPOINT_SLEEP_STARTED_WALL_EPOCH_SECONDS=""
  MIDPOINT_SLEEP_STARTED_MONOTONIC_MILLISECONDS=""
  MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS=""
  MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS=""
  MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS=""
  MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS=""
  MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS=""
  MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS=""
}

midpoint_legacy_directory_identity_from_authority() {
  local -r authority="$1"
  local device="" inode="" owner="" group="" mode="" extra=""

  IFS=: read -r device inode owner group mode extra <<<"$authority" || return 1
  [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[1-9][0-9]*$ &&
    "$owner" =~ ^[0-9]+$ && "$group" =~ ^[0-9]+$ &&
    "$mode" =~ ^[0-7]{3,4}$ && -z "$extra" ]] || return 1
  printf '%s:%s:%s:%s' "$device" "$inode" "$owner" "$mode"
}

active_midpoint_transaction_matches() {
  local -r final_policy="${1:-require_final_absent}"
  local repetition_label=""
  local observed_parent_identity=""
  local observed_partial_identity=""
  local observed_parent_authority=""
  local observed_partial_authority=""

  [[ "$MIDPOINT_ACTIVE" == true &&
    "$MIDPOINT_REPETITION" =~ ^[1-5]$ &&
    "$MIDPOINT_DURATION_SECONDS" == "$DURATION_SECONDS" &&
    "$MIDPOINT_BENCHMARK_PID" =~ ^[1-9][0-9]*$ &&
    "$MIDPOINT_BENCHMARK_IDENTITY" =~ ^${MIDPOINT_BENCHMARK_PID}\ ${MIDPOINT_BENCHMARK_PID}\ [1-9][0-9]*$ &&
    "$MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS" =~ ^[1-9][0-9]*$ &&
    "$MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS" =~ ^(0|[1-9][0-9]*)$ &&
    "$MIDPOINT_PARENT_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    "$MIDPOINT_PARTIAL_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    "$MIDPOINT_PARENT_DIRECTORY_AUTHORITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    "$MIDPOINT_PARTIAL_DIRECTORY_AUTHORITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ ]] || return 1
  java_measurement_cell_is_allowed "$MIDPOINT_CELL_DIR" || return 1
  printf -v repetition_label 'rep-%02d' "$MIDPOINT_REPETITION"
  [[ "$MIDPOINT_PARTIAL" == "$MIDPOINT_CELL_DIR/measurements/.$repetition_label-midpoint.partial" &&
    "$MIDPOINT_FINAL" == "$MIDPOINT_CELL_DIR/measurements/$repetition_label-midpoint" &&
    "$BENCHMARK_OUTPUT" == "$MIDPOINT_CELL_DIR/measurements/$repetition_label.json" &&
    "$BENCHMARK_CELL_DIR" == "$MIDPOINT_CELL_DIR" &&
    "$BENCHMARK_DURATION_SECONDS" == "$MIDPOINT_DURATION_SECONDS" &&
    "$BENCHMARK_PID" == "$MIDPOINT_BENCHMARK_PID" &&
    "$BENCHMARK_IDENTITY" == "$MIDPOINT_BENCHMARK_IDENTITY" &&
    "$BENCHMARK_OUTPUT_PARENT_IDENTITY" == "$MIDPOINT_PARENT_IDENTITY" &&
    "$BENCHMARK_CONFIRMED_WALL_EPOCH_SECONDS" == "$MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS" &&
    "$BENCHMARK_CONFIRMED_MONOTONIC_MILLISECONDS" == "$MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS" &&
    -d "$MIDPOINT_CELL_DIR/measurements" &&
    ! -L "$MIDPOINT_CELL_DIR/measurements" ]] || return 1
  case "$final_policy" in
    require_final_absent)
      [[ ! -e "$MIDPOINT_FINAL" && ! -L "$MIDPOINT_FINAL" &&
        ! -e "$MIDPOINT_FINAL.json" && ! -L "$MIDPOINT_FINAL.json" ]] || return 1
      ;;
    allow_foreign_final) ;;
    *) return 1 ;;
  esac
  observed_parent_authority="$(stat --format '%d:%i:%u:%g:%a' -- \
    "$MIDPOINT_CELL_DIR/measurements")" || return 1
  observed_parent_identity="$(midpoint_legacy_directory_identity_from_authority \
    "$observed_parent_authority")" || return 1
  [[ "$observed_parent_identity" == "$MIDPOINT_PARENT_IDENTITY" &&
    "$observed_parent_authority" == "$MIDPOINT_PARENT_DIRECTORY_AUTHORITY" ]] || return 1
  if [[ -e "$MIDPOINT_PARTIAL" || -L "$MIDPOINT_PARTIAL" ]]; then
    [[ -d "$MIDPOINT_PARTIAL" && ! -L "$MIDPOINT_PARTIAL" ]] || return 1
    observed_partial_authority="$(stat --format '%d:%i:%u:%g:%a' -- \
      "$MIDPOINT_PARTIAL")" || return 1
    observed_partial_identity="$(midpoint_legacy_directory_identity_from_authority \
      "$observed_partial_authority")" || return 1
    [[ "$observed_partial_identity" == "$MIDPOINT_PARTIAL_IDENTITY" &&
      "$observed_partial_authority" == "$MIDPOINT_PARTIAL_DIRECTORY_AUTHORITY" ]] || return 1
  fi
}

begin_scheduled_midpoint_transaction() {
  local -r cell_dir="$1"
  local repetition=""
  local repetition_label=""
  local measurements=""
  local partial=""
  local final=""
  local parent_identity=""
  local partial_identity=""
  local parent_authority=""
  local partial_authority=""
  local clocks=""
  local sleep_wall=""
  local sleep_monotonic=""
  local extra=""

  repetition="$(normalize_decimal "$2" "$REQUIRED_REPETITIONS" false)" || return 1
  printf -v repetition_label 'rep-%02d' "$repetition"
  measurements="$cell_dir/measurements"
  partial="$measurements/.$repetition_label-midpoint.partial"
  final="$measurements/$repetition_label-midpoint"
  [[ "$MIDPOINT_ACTIVE" == false && "$BENCHMARK_CELL_DIR" == "$cell_dir" &&
    "$BENCHMARK_OUTPUT" == "$measurements/$repetition_label.json" &&
    "$BENCHMARK_DURATION_SECONDS" == "$DURATION_SECONDS" &&
    "$BENCHMARK_PID" =~ ^[1-9][0-9]*$ &&
    "$BENCHMARK_IDENTITY" =~ ^${BENCHMARK_PID}\ ${BENCHMARK_PID}\ [1-9][0-9]*$ &&
    "$BENCHMARK_CONFIRMED_WALL_EPOCH_SECONDS" =~ ^[1-9][0-9]*$ &&
    "$BENCHMARK_CONFIRMED_MONOTONIC_MILLISECONDS" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  java_measurement_cell_is_allowed "$cell_dir" || return 1
  [[ -d "$measurements" && ! -L "$measurements" &&
    ! -e "$partial" && ! -L "$partial" &&
    ! -e "$final" && ! -L "$final" &&
    ! -e "$final.json" && ! -L "$final.json" ]] || return 1
  parent_authority="$(stat --format '%d:%i:%u:%g:%a' -- "$measurements")" || return 1
  parent_identity="$(midpoint_legacy_directory_identity_from_authority \
    "$parent_authority")" || return 1
  [[ "$BENCHMARK_OUTPUT_PARENT_IDENTITY" == "$parent_identity" ]] || return 1
  mkdir --mode=0700 -- "$partial" || return 1
  partial_authority="$(stat --format '%d:%i:%u:%g:%a' -- "$partial")" || {
    rmdir -- "$partial" 2>/dev/null || true
    return 1
  }
  partial_identity="$(midpoint_legacy_directory_identity_from_authority \
    "$partial_authority")" || {
    rmdir -- "$partial" 2>/dev/null || true
    return 1
  }
  MIDPOINT_CELL_DIR="$cell_dir"
  MIDPOINT_PARTIAL="$partial"
  MIDPOINT_FINAL="$final"
  MIDPOINT_PARENT_IDENTITY="$parent_identity"
  MIDPOINT_PARTIAL_IDENTITY="$partial_identity"
  MIDPOINT_PARENT_DIRECTORY_AUTHORITY="$parent_authority"
  MIDPOINT_PARTIAL_DIRECTORY_AUTHORITY="$partial_authority"
  MIDPOINT_REPETITION="$repetition"
  MIDPOINT_DURATION_SECONDS="$DURATION_SECONDS"
  MIDPOINT_BENCHMARK_PID="$BENCHMARK_PID"
  MIDPOINT_BENCHMARK_IDENTITY="$BENCHMARK_IDENTITY"
  MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS="$BENCHMARK_CONFIRMED_WALL_EPOCH_SECONDS"
  MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS="$BENCHMARK_CONFIRMED_MONOTONIC_MILLISECONDS"
  MIDPOINT_ACTIVE=true
  active_midpoint_transaction_matches || return 1
  clocks="$(clock_pair_values)" || return 1
  read -r sleep_wall sleep_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" &&
    "$sleep_wall" -ge "$MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS" &&
    "$sleep_monotonic" -ge "$MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS" ]] || return 1
  MIDPOINT_SLEEP_STARTED_WALL_EPOCH_SECONDS="$sleep_wall"
  MIDPOINT_SLEEP_STARTED_MONOTONIC_MILLISECONDS="$sleep_monotonic"
}

discard_scheduled_midpoint_partial() {
  local -r final_policy="${1:-require_final_absent}"
  local unexpected=""
  local path=""
  local -a allowed=(
    snapshot.json midpoint-receipt.json
    obi-identity.txt obi-cgroup-v2.json
    java-backend-identity.txt java-backend-cgroup-v2.json
  )

  [[ "$MIDPOINT_ACTIVE" == true ]] || return 0
  [[ "$final_policy" == require_final_absent ||
    "$final_policy" == allow_foreign_final ]] || return 1
  active_midpoint_transaction_matches "$final_policy" || return 1
  if [[ ! -e "$MIDPOINT_PARTIAL" && ! -L "$MIDPOINT_PARTIAL" ]]; then
    clear_active_midpoint_transaction
    return 0
  fi
  # The private directory and its parent remain bound to their creation-time
  # device/inode/owner/mode identities. Only the six exact regular artifacts
  # which this transaction can create are removable; find never follows a
  # replacement symlink and emits at most one unexpected pathname.
  unexpected="$(find -P "$MIDPOINT_PARTIAL" -mindepth 1 -maxdepth 1 \
    ! \( -type f \( -name snapshot.json -o -name midpoint-receipt.json \
      -o -name obi-identity.txt -o -name obi-cgroup-v2.json \
      -o -name java-backend-identity.txt -o -name java-backend-cgroup-v2.json \) \) \
    -print -quit 2>/dev/null)" || return 1
  [[ -z "$unexpected" ]] || return 1
  for path in "${allowed[@]}"; do
    path="$MIDPOINT_PARTIAL/$path"
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -f "$path" && ! -L "$path" ]] || return 1
      rm -f -- "$path" || return 1
    fi
  done
  rmdir -- "$MIDPOINT_PARTIAL" || return 1
  [[ ! -e "$MIDPOINT_PARTIAL" && ! -L "$MIDPOINT_PARTIAL" ]] || return 1
  clear_active_midpoint_transaction
}

validate_scheduled_midpoint_receipt_json_value() {
  local -r receipt_value="$1"
  local -r expected_cell="$2"
  local -r expected_repetition="$3"
  local -r expected_status="$4"
  local -r expected_parent_identity="$5"
  local -r expected_published_identity="$6"

  printf '%s' "$receipt_value" | jq -se \
    --arg cell "$expected_cell" --arg status "$expected_status" \
    --arg parent_identity "$expected_parent_identity" \
    --arg published_identity "$expected_published_identity" \
    --argjson repetition "$expected_repetition" \
    --argjson duration "$DURATION_SECONDS" \
    --argjson requested "$((DURATION_SECONDS / 2))" \
    --argjson maximum "$((DURATION_SECONDS / 2 + MIDPOINT_TIMING_OVERRUN_SECONDS))" '
    def n: type == "number" and isfinite and floor == . and . >= 0 and . <= 9007199254740991;
    def p: n and . > 0;
    def clocks:
      (keys | sort) == ["capture_ended", "capture_started", "confirmed_launch",
        "sleep_ended", "sleep_started"] and
      all(.[]; (keys | sort) == ["monotonic_milliseconds", "wall_epoch_seconds"] and
        (.wall_epoch_seconds | p) and (.monotonic_milliseconds | n)) and
      .sleep_started.wall_epoch_seconds >= .confirmed_launch.wall_epoch_seconds and
      .sleep_started.monotonic_milliseconds >= .confirmed_launch.monotonic_milliseconds and
      .sleep_ended.wall_epoch_seconds >= .sleep_started.wall_epoch_seconds and
      .sleep_ended.monotonic_milliseconds >= .sleep_started.monotonic_milliseconds and
      .capture_started.wall_epoch_seconds >= .sleep_ended.wall_epoch_seconds and
      .capture_started.monotonic_milliseconds >= .sleep_ended.monotonic_milliseconds and
      .capture_ended.wall_epoch_seconds >= .capture_started.wall_epoch_seconds and
      .capture_ended.monotonic_milliseconds >= .capture_started.monotonic_milliseconds;
    length == 1 and (.[0] | . as $receipt |
      .schema_version == 1 and .kind == "scheduled-cgroup-v2-midpoint-receipt" and
      .status == $status and .cell == $cell and .repetition == $repetition and
      .benchmark_duration_seconds == $duration and
      .scheduled_seconds_after_confirmed_launch == $requested and
      .output_source == ("cells/" + $cell + "/measurements/rep-" +
        (if $repetition < 10 then "0" else "" end) + ($repetition | tostring) + "-midpoint") and
      .measurement_parent_identity == $parent_identity and
      .published_directory_identity == $published_identity and
      ($parent_identity | test("^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$")) and
      ($published_identity | test("^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$")) and
      (.benchmark | (keys | sort) == ["identity", "pid", "result_source"] and
        (.pid | p) and
        .identity == ((.pid | tostring) + " " + (.pid | tostring) + " " +
          (.identity | split(" ")[2])) and
        (.identity | test("^[1-9][0-9]* [1-9][0-9]* [1-9][0-9]*$")) and
        .result_source == ("cells/" + $cell + "/measurements/rep-" +
          (if $repetition < 10 then "0" else "" end) + ($repetition | tostring) + ".json")) and
      (.clocks | clocks) and
      ($receipt.elapsed | (keys | sort) == ["confirmed_launch_to_sleep_end_monotonic_milliseconds",
        "confirmed_launch_to_sleep_end_wall_seconds", "sleep_monotonic_milliseconds",
        "sleep_wall_seconds"] and all(.[]; n) and
        .sleep_wall_seconds ==
          ($receipt.clocks.sleep_ended.wall_epoch_seconds -
            $receipt.clocks.sleep_started.wall_epoch_seconds) and
        .sleep_monotonic_milliseconds ==
          ($receipt.clocks.sleep_ended.monotonic_milliseconds -
            $receipt.clocks.sleep_started.monotonic_milliseconds) and
        .confirmed_launch_to_sleep_end_wall_seconds ==
          ($receipt.clocks.sleep_ended.wall_epoch_seconds -
            $receipt.clocks.confirmed_launch.wall_epoch_seconds) and
        .confirmed_launch_to_sleep_end_monotonic_milliseconds ==
          ($receipt.clocks.sleep_ended.monotonic_milliseconds -
            $receipt.clocks.confirmed_launch.monotonic_milliseconds) and
        .sleep_wall_seconds >= $requested and .sleep_wall_seconds <= $maximum and
        .sleep_monotonic_milliseconds >= ($requested * 1000) and
        .sleep_monotonic_milliseconds <= ($maximum * 1000) and
        .confirmed_launch_to_sleep_end_wall_seconds >= $requested and
        .confirmed_launch_to_sleep_end_wall_seconds <= $maximum and
        .confirmed_launch_to_sleep_end_monotonic_milliseconds >= ($requested * 1000) and
        .confirmed_launch_to_sleep_end_monotonic_milliseconds <= ($maximum * 1000)) and
      if $status == "available" then
        (keys | sort) == ["artifacts", "benchmark", "benchmark_duration_seconds", "cell",
          "clocks", "elapsed", "kind", "measurement_parent_identity", "output_source",
          "published_directory_identity", "repetition", "scheduled_seconds_after_confirmed_launch",
          "schema_version", "scope", "status"] and
        .scope == {
          cgroup_v2_process_tree: {status: "collected"},
          docker_inspect: {status: "not_collected", reason: "excluded_from_measured_window"},
          container_stats: {status: "not_collected", reason: "excluded_from_measured_window"},
          obi_metrics: {status: "not_collected", reason: "zero_in_window_scrapes_required"},
          java_diagnostics: {status: "not_collected", reason: "excluded_from_measured_window"}
        } and
        (.artifacts | type == "array" and
          (([.[].service] == ["java-backend"]) or
            ([.[].service] == ["obi", "java-backend"])) and
          all(.[]; (keys | sort) == ["cgroup_snapshot", "identity_source", "service"] and
            (.service == "obi" or .service == "java-backend") and
            .identity_source == (.service + "-identity.txt") and
            .cgroup_snapshot == (.service + "-cgroup-v2.json")))
      else
        $status == "unavailable" and
        (keys | sort) == ["artifacts", "benchmark", "benchmark_duration_seconds", "cell",
          "clocks", "elapsed", "kind", "measurement_parent_identity", "output_source",
          "published_directory_identity", "reason", "repetition",
          "scheduled_seconds_after_confirmed_launch", "schema_version", "scope", "status"] and
        .scope == {
          cgroup_v2_process_tree: {status: "not_collected", reason: .reason},
          docker_inspect: {status: "not_collected", reason: "excluded_from_measured_window"},
          container_stats: {status: "not_collected", reason: "excluded_from_measured_window"},
          obi_metrics: {status: "not_collected", reason: "zero_in_window_scrapes_required"},
          java_diagnostics: {status: "not_collected", reason: "excluded_from_measured_window"}
        } and
        .artifacts == [] and
        (.reason == "load_client_not_live_at_scheduled_midpoint" or
          .reason == "load_client_exited_during_scheduled_midpoint_capture")
      end)
  ' >/dev/null
}

validate_scheduled_midpoint_receipt_schema() {
  local -r artifact="$1"
  local -r expected_cell="$2"
  local -r expected_repetition="$3"
  local -r expected_status="$4"
  local -r expected_parent_identity="$5"
  local -r expected_published_identity="$6"
  local -r output_name="${7:-}"
  local captured_receipt_value=""
  local captured_receipt_identity=""
  local captured_receipt_size=""
  local captured_receipt_digest=""

  bounded_duplicate_free_json_image \
    "$artifact" "$MAX_MIDPOINT_RECEIPT_BYTES" \
    captured_receipt_value captured_receipt_identity \
    captured_receipt_size captured_receipt_digest || return 1
  [[ "$captured_receipt_identity" == *:* &&
    "$captured_receipt_size" =~ ^[1-9][0-9]*$ &&
    "$captured_receipt_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  validate_scheduled_midpoint_receipt_json_value "$captured_receipt_value" \
    "$expected_cell" "$expected_repetition" "$expected_status" \
    "$expected_parent_identity" "$expected_published_identity" || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$captured_receipt_value"
  fi
}

validated_scheduled_midpoint_boundary_bundle() (
  local -r directory="$1"
  local -r expected_cell="$2"
  local -r expected_repetition="$3"
  local -r expected_receipt_value="${4:-}"
  local service=""
  local services_text=""
  local parent=""
  local parent_identity=""
  local parent_identity_after=""
  local directory_fd=""
  local directory_anchor=""
  local directory_identity=""
  local directory_identity_after=""
  local receipt_value=""
  local receipt_identity=""
  local receipt_size=""
  local receipt_digest=""
  local boundary_value=""
  local boundary_identity=""
  local boundary_size=""
  local boundary_digest=""
  local snapshot_value=""
  local snapshot_identity=""
  local snapshot_size=""
  local snapshot_digest=""
  local identity_value=""
  local identity_identity=""
  local identity_size=""
  local identity_digest=""
  local services_json=""
  local snapshots_json=""
  local publication_leaves_json=""
  local captured_midpoint_bundle=""
  local -a services=()
  local -a snapshot_values=()
  local -a publication_leaves=()

  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  parent="$(dirname -- "$directory")" || return 1
  parent_identity="$(stat --format '%d:%i:%u:%a' -- "$parent")" || return 1
  directory_identity="$(stat --format '%d:%i:%u:%a' -- "$directory")" || return 1
  exec {directory_fd}<"$directory" || return 1
  directory_anchor="/proc/self/fd/$directory_fd"
  trap 'exec {directory_fd}<&- 2>/dev/null || true' EXIT
  [[ ! -L "$directory" &&
    "$(stat -L --format '%d:%i:%u:%a' -- "$directory_anchor")" == \
      "$directory_identity" ]] || return 1
  bounded_duplicate_free_json_image \
    "$directory_anchor/midpoint-receipt.json" "$MAX_MIDPOINT_RECEIPT_BYTES" \
    receipt_value receipt_identity receipt_size receipt_digest || return 1
  [[ "$receipt_identity" == *:* && "$receipt_size" =~ ^[1-9][0-9]*$ &&
    "$receipt_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ -z "$expected_receipt_value" ||
    "$receipt_value" == "$expected_receipt_value" ]] || return 1
  validate_scheduled_midpoint_receipt_json_value \
    "$receipt_value" "$expected_cell" "$expected_repetition" available \
    "$parent_identity" "$directory_identity" || return 1
  publication_leaves+=("$(jq -cn \
    --arg name midpoint-receipt.json --arg identity "$receipt_identity" \
    --arg sha256 "$receipt_digest" --argjson size_bytes "$receipt_size" \
    --argjson maximum_bytes "$MAX_MIDPOINT_RECEIPT_BYTES" '{
      name: $name, identity: $identity, size_bytes: $size_bytes,
      maximum_bytes: $maximum_bytes, sha256: $sha256
    }')") || return 1
  bounded_duplicate_free_json_image \
    "$directory_anchor/snapshot.json" "$MAX_BOUNDARY_SNAPSHOT_BYTES" \
    boundary_value boundary_identity boundary_size boundary_digest || return 1
  [[ "$boundary_identity" == *:* && "$boundary_size" =~ ^[1-9][0-9]*$ &&
    "$boundary_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  publication_leaves+=("$(jq -cn \
    --arg name snapshot.json --arg identity "$boundary_identity" \
    --arg sha256 "$boundary_digest" --argjson size_bytes "$boundary_size" \
    --argjson maximum_bytes "$MAX_BOUNDARY_SNAPSHOT_BYTES" '{
      name: $name, identity: $identity, size_bytes: $size_bytes,
      maximum_bytes: $maximum_bytes, sha256: $sha256
    }')") || return 1
  printf '%s' "$boundary_value" | jq -se \
    --arg cell "$expected_cell" --argjson repetition "$expected_repetition" '
    length == 1 and (.[0] |
      (keys | sort) == ["cell", "java_diagnostics", "kind", "metrics", "receipt",
        "repetition", "schema_version", "services", "status", "timing"] and
      .schema_version == 1 and .kind == "scheduled-cgroup-v2-midpoint-boundary" and
      .status == "available" and .cell == $cell and .repetition == $repetition and
      .timing == "scheduled_repetition_midpoint" and
      .receipt == "midpoint-receipt.json" and
      .metrics == {status: "not_collected", reason: "zero_in_window_scrapes_required"} and
      .java_diagnostics == {status: "not_collected", reason: "excluded_from_measured_window"} and
      (.services == ["java-backend"] or .services == ["obi", "java-backend"]))
  ' >/dev/null || return 1
  printf '%s\n%s' "$boundary_value" "$receipt_value" | jq -es '
    length == 2 and .[0].services == [.[1].artifacts[].service]
  ' >/dev/null || return 1
  services_text="$(printf '%s' "$boundary_value" | \
    jq -er '.services | join(" ")')" || return 1
  read -r -a services <<<"$services_text" || return 1
  ((${#services[@]} >= 1 && ${#services[@]} <= 2)) || return 1
  for service in "${services[@]}"; do
    [[ "$service" == obi || "$service" == java-backend ]] || return 1
    bounded_duplicate_free_json_image \
      "$directory_anchor/$service-cgroup-v2.json" \
      "$MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES" snapshot_value snapshot_identity \
      snapshot_size snapshot_digest || return 1
    validate_bound_cgroup_v2_snapshot_json_value "$snapshot_value" || return 1
    capture_bounded_regular_file_value "$directory_anchor/$service-identity.txt" \
      "$MAX_SERVICE_IDENTITY_BYTES" identity_value identity_identity \
      identity_size identity_digest || return 1
    [[ "$snapshot_identity" == *:* && "$snapshot_size" =~ ^[1-9][0-9]*$ &&
      "$snapshot_digest" =~ ^[0-9a-f]{64}$ &&
      "$identity_identity" == *:* && "$identity_size" =~ ^[1-9][0-9]*$ &&
      "$identity_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
    validate_bound_cgroup_v2_identity_binding_values "$snapshot_value" \
      "$identity_value" "$service-identity.txt" "$service" || return 1
    printf '%s' "$snapshot_value" | jq -e \
      --arg cell "$expected_cell" --arg service "$service" \
      --argjson repetition "$expected_repetition" '
        .status == "available" and .cell == $cell and .service == $service and
        .timing == "scheduled_repetition_midpoint" and .repetition == $repetition and
        .identity_source == ($service + "-identity.txt")
      ' >/dev/null || return 1
    snapshot_values+=("$snapshot_value")
    publication_leaves+=("$(jq -cn \
      --arg name "$service-cgroup-v2.json" --arg identity "$snapshot_identity" \
      --arg sha256 "$snapshot_digest" --argjson size_bytes "$snapshot_size" \
      --argjson maximum_bytes "$MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES" '{
        name: $name, identity: $identity, size_bytes: $size_bytes,
        maximum_bytes: $maximum_bytes, sha256: $sha256
      }')") || return 1
    publication_leaves+=("$(jq -cn \
      --arg name "$service-identity.txt" --arg identity "$identity_identity" \
      --arg sha256 "$identity_digest" --argjson size_bytes "$identity_size" \
      --argjson maximum_bytes "$MAX_SERVICE_IDENTITY_BYTES" '{
        name: $name, identity: $identity, size_bytes: $size_bytes,
        maximum_bytes: $maximum_bytes, sha256: $sha256
      }')") || return 1
  done
  parent_identity_after="$(stat --format '%d:%i:%u:%a' -- "$parent")" || return 1
  directory_identity_after="$(stat --format '%d:%i:%u:%a' -- "$directory")" || return 1
  [[ ! -L "$directory" && "$parent_identity_after" == "$parent_identity" &&
    "$directory_identity_after" == "$directory_identity" &&
    "$(stat -L --format '%d:%i:%u:%a' -- "$directory_anchor")" == \
      "$directory_identity" ]] || return 1
  services_json="$(jq -cn '$ARGS.positional' --args "${services[@]}")" || return 1
  snapshots_json="$(printf '%s\n' "${snapshot_values[@]}" | jq -s .)" || return 1
  publication_leaves_json="$(printf '%s\n' "${publication_leaves[@]}" | \
    jq -cs 'sort_by(.name)')" || return 1
  captured_midpoint_bundle="$(printf '%s\n%s\n%s\n%s\n%s' "$boundary_value" \
    "$receipt_value" "$services_json" "$snapshots_json" \
    "$publication_leaves_json" | jq -cs '
      if length != 5
      then error("expected midpoint boundary, receipt, services, snapshots, and leaf receipts")
      else . end |
      {boundary: .[0], receipt: .[1], services: .[2], snapshots:
        (.[2] as $services | .[3] |
          to_entries | map({key: $services[.key], value: .value}) | from_entries),
        publication_leaves: .[4]}
    ')" || return 1
  printf '%s' "$captured_midpoint_bundle"
)

validate_scheduled_midpoint_boundary() {
  local -r directory="$1"
  local -r expected_cell="$2"
  local -r expected_repetition="$3"
  local -r output_name="${4:-}"
  local -r expected_receipt_value="${5:-}"
  local captured_midpoint_boundary_bundle=""

  captured_midpoint_boundary_bundle="$(validated_scheduled_midpoint_boundary_bundle \
    "$directory" "$expected_cell" "$expected_repetition" \
    "$expected_receipt_value")" || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$captured_midpoint_boundary_bundle"
  fi
}

scheduled_midpoint_publication_ready() {
  :
}

# Validate and publish the held midpoint directory as one trusted transaction.
# Every leaf is re-opened relative to pinned directory descriptors and compared
# with the identity, size, and digest captured by the boundary validator. The
# helper's successful return is the publication linearization point: no Bash
# pathname check occurs between its final validation and renameat2.
publish_scheduled_midpoint_directory() {
  local -r midpoint_bundle="$1"
  local parent=""
  local partial_name=""
  local final_name=""
  local unavailable_name=""
  local publication_manifest=""
  local publication_receipt=""

  if ! is_absolute_regular_executable "$NATIVE_BENCHMARK_PERL_COMMAND"; then
    resolve_trusted_native_tool perl || return 1
    NATIVE_BENCHMARK_PERL_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  fi
  active_midpoint_transaction_matches || return 1
  parent="${MIDPOINT_PARTIAL%/*}"
  partial_name="${MIDPOINT_PARTIAL##*/}"
  final_name="${MIDPOINT_FINAL##*/}"
  unavailable_name="$final_name.json"
  [[ "$parent" == "${MIDPOINT_FINAL%/*}" &&
    "$partial_name" == ".$final_name.partial" &&
    "$final_name" =~ ^rep-0[1-5]-midpoint$ ]] || return 1
  publication_manifest="$(printf '%s' "$midpoint_bundle" | jq -ce '
    (.services | map(. + "-cgroup-v2.json", . + "-identity.txt")) as $service_leaves |
    (["midpoint-receipt.json", "snapshot.json"] + $service_leaves | sort) as $expected |
    if (keys | sort) != ["boundary", "publication_leaves", "receipt", "services", "snapshots"] or
      (.publication_leaves | type) != "array" or
      ([.publication_leaves[].name] | sort) != $expected or
      ([.publication_leaves[].name] | unique | length) != ($expected | length) or
      any(.publication_leaves[];
        (keys | sort) != ["identity", "maximum_bytes", "name", "sha256", "size_bytes"])
    then error("invalid held midpoint publication roster")
    else {schema_version: 1, leaves: (.publication_leaves | sort_by(.name))}
    end
  ')" || return 1
  [[ -n "$publication_manifest" &&
    "${#publication_manifest}" -le "$MAX_MIDPOINT_PUBLICATION_MANIFEST_BYTES" ]] || return 1

  # Test mutations run before the helper obtains authority. They cannot create
  # a validation-to-rename gap because the helper re-opens and verifies every
  # byte below before issuing renameat2 itself.
  scheduled_midpoint_publication_ready "$MIDPOINT_PARTIAL" \
    "$MIDPOINT_FINAL" || return 1
  publication_receipt="$(printf '%s' "$publication_manifest" | \
    run_native_clean_environment "$NATIVE_BENCHMARK_PERL_COMMAND" -T \
      -MFcntl=:DEFAULT,:mode -MDigest::SHA=sha256_hex \
      -MJSON::PP=decode_json -MErrno=ENOENT -e '
        use strict;
        use warnings;
        require "syscall.ph";
        use constant RENAME_NOREPLACE_LINUX => 1;

        sub untaint_path {
          my ($value) = @_;
          defined($value) && length($value) <= 4096 &&
            $value =~ m{\A(/(?:[^/\0\r\n]+/)*[^/\0\r\n]+)\z} or exit 1;
          return $1;
        }
        sub untaint_name {
          my ($value, $pattern) = @_;
          defined($value) && length($value) <= 64 && $value =~ $pattern or exit 1;
          return $1;
        }
        sub untaint_integer {
          my ($value, $positive) = @_;
          defined($value) && "$value" =~ /\A(0|[1-9][0-9]*)\z/ or exit 1;
          my $integer = $1;
          $integer <= 9007199254740991 && (!$positive || $integer > 0) or exit 1;
          return $integer;
        }
        sub untaint_digest {
          my ($value) = @_;
          defined($value) && $value =~ /\A([0-9a-f]{64})\z/ or exit 1;
          return $1;
        }
        sub untaint_directory_identity {
          my ($value) = @_;
          defined($value) &&
            $value =~ /\A([0-9]+:[1-9][0-9]*:[0-9]+:[0-9]+:[0-7]{3,4})\z/ or exit 1;
          return $1;
        }
        sub untaint_leaf_identity {
          my ($value) = @_;
          defined($value) && $value =~
            /\A([0-9]+:[1-9][0-9]*:[0-9]+:[1-9][0-9]*:[0-9]+:[0-9]+:[0-9]+:[1-9][0-9]*)\z/
            or exit 1;
          return $1;
        }
        sub exact_keys {
          my ($value, @expected) = @_;
          ref($value) eq q{HASH} or return 0;
          return join(q{\0}, sort keys %{$value}) eq join(q{\0}, sort @expected);
        }
        sub directory_identity {
          my ($handle) = @_;
          my @stat = stat($handle);
          @stat && S_ISDIR($stat[2]) && ($stat[2] & 07777) == 0700 &&
            $stat[4] == $< or exit 1;
          return join(q{:}, $stat[0], $stat[1], $stat[4], $stat[5],
            sprintf(q{%o}, $stat[2] & 07777));
        }
        sub leaf_identity {
          my ($handle) = @_;
          my @stat = stat($handle);
          @stat && S_ISREG($stat[2]) && ($stat[2] & 07777) == 0600 &&
            $stat[3] == 1 && $stat[4] == $< or exit 1;
          return join(q{:}, @stat[0,1,2,3,4,5,6,7]);
        }
        sub openat_handle {
          my ($directory, $name, $flags) = @_;
          my $fd = syscall(SYS_openat(), fileno($directory), $name, $flags, 0);
          $fd >= 0 or return;
          open(my $handle, q{<&=}, $fd) or exit 1;
          return $handle;
        }
        sub require_absent {
          my ($directory, $name) = @_;
          my $handle = openat_handle($directory, $name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
          if (defined($handle)) {
            close($handle);
            exit 1;
          }
          $! == ENOENT or exit 1;
        }
        sub roster {
          my ($directory) = @_;
          sysseek($directory, 0, 0) == 0 or exit 1;
          my @names;
          my $total = 0;
          while (1) {
            my $buffer = "\0" x 8192;
            my $count = syscall(SYS_getdents64(), fileno($directory),
              $buffer, length($buffer));
            defined($count) && $count >= 0 or exit 1;
            last if $count == 0;
            $total += $count;
            $total <= 65536 or exit 1;
            my $offset = 0;
            while ($offset < $count) {
              $count - $offset >= 20 or exit 1;
              my (undef, undef, $record_length, $type) =
                unpack(q{QqSC}, substr($buffer, $offset, 19));
              $record_length >= 20 && $offset + $record_length <= $count or exit 1;
              my $name_field = substr($buffer, $offset + 19,
                $record_length - 19);
              my $nul = index($name_field, "\0");
              $nul > 0 or exit 1;
              my $name = substr($name_field, 0, $nul);
              if ($name ne q{.} && $name ne q{..}) {
                ($type == 0 || $type == 8) &&
                  $name !~ /[\0\r\n\/]/ or exit 1;
                push @names, $name;
                @names <= 6 or exit 1;
              }
              $offset += $record_length;
            }
            $offset == $count or exit 1;
          }
          @names = sort @names;
          return @names;
        }
        sub read_and_verify_leaf {
          my ($directory, $leaf) = @_;
          my $handle = openat_handle($directory, $leaf->{name},
            O_RDONLY | O_NOFOLLOW);
          defined($handle) or exit 1;
          leaf_identity($handle) eq $leaf->{identity} or exit 1;
          my $bytes = q{};
          while (length($bytes) <= $leaf->{maximum_bytes}) {
            my $chunk = q{};
            my $remaining = $leaf->{maximum_bytes} + 1 - length($bytes);
            my $count = sysread($handle, $chunk, $remaining);
            defined($count) or exit 1;
            last if $count == 0;
            $bytes .= $chunk;
          }
          length($bytes) == $leaf->{size_bytes} &&
            length($bytes) <= $leaf->{maximum_bytes} &&
            index($bytes, "\0") < 0 &&
            sha256_hex($bytes) eq $leaf->{sha256} &&
            leaf_identity($handle) eq $leaf->{identity} or exit 1;
          close($handle) or exit 1;
        }
        sub verify_roster {
          my ($directory, $leaves, $names) = @_;
          my @observed = roster($directory);
          join(q{\0}, @observed) eq join(q{\0}, @{$names}) or exit 1;
          read_and_verify_leaf($directory, $_) for @{$leaves};
        }

        my ($parent_arg, $partial_arg, $final_arg, $unavailable_arg,
          $parent_identity_arg, $partial_identity_arg, $manifest_max_arg,
          $boundary_max_arg, $receipt_max_arg, $identity_max_arg,
          $cgroup_max_arg) = @ARGV;
        @ARGV == 11 or exit 1;
        my $parent_path = untaint_path($parent_arg);
        my $partial_name = untaint_name($partial_arg,
          qr/\A(\.rep-0[1-5]-midpoint\.partial)\z/);
        my $final_name = untaint_name($final_arg,
          qr/\A(rep-0[1-5]-midpoint)\z/);
        my $unavailable_name = untaint_name($unavailable_arg,
          qr/\A(rep-0[1-5]-midpoint\.json)\z/);
        $partial_name eq q{.} . $final_name . q{.partial} &&
          $unavailable_name eq $final_name . q{.json} or exit 1;
        my $expected_parent = untaint_directory_identity($parent_identity_arg);
        my $expected_partial = untaint_directory_identity($partial_identity_arg);
        my $manifest_max = untaint_integer($manifest_max_arg, 1);
        my %maximum_by_name = (
          q{snapshot.json} => untaint_integer($boundary_max_arg, 1),
          q{midpoint-receipt.json} => untaint_integer($receipt_max_arg, 1),
          q{obi-identity.txt} => untaint_integer($identity_max_arg, 1),
          q{java-backend-identity.txt} => untaint_integer($identity_max_arg, 1),
          q{obi-cgroup-v2.json} => untaint_integer($cgroup_max_arg, 1),
          q{java-backend-cgroup-v2.json} => untaint_integer($cgroup_max_arg, 1),
        );
        my $manifest_bytes = q{};
        while (length($manifest_bytes) <= $manifest_max) {
          my $chunk = q{};
          my $remaining = $manifest_max + 1 - length($manifest_bytes);
          my $count = sysread(STDIN, $chunk, $remaining);
          defined($count) or exit 1;
          last if $count == 0;
          $manifest_bytes .= $chunk;
        }
        length($manifest_bytes) > 0 && length($manifest_bytes) <= $manifest_max &&
          index($manifest_bytes, "\0") < 0 or exit 1;
        my $manifest = eval { decode_json($manifest_bytes) };
        !$@ && exact_keys($manifest, qw(leaves schema_version)) &&
          $manifest->{schema_version} == 1 && ref($manifest->{leaves}) eq q{ARRAY} or exit 1;
        my @leaves;
        my %seen;
        for my $raw (@{$manifest->{leaves}}) {
          exact_keys($raw, qw(identity maximum_bytes name sha256 size_bytes)) or exit 1;
          my $name = untaint_name($raw->{name},
            qr/\A((?:obi|java-backend)-(?:identity\.txt|cgroup-v2\.json)|midpoint-receipt\.json|snapshot\.json)\z/);
          !$seen{$name}++ && exists($maximum_by_name{$name}) or exit 1;
          my $maximum = untaint_integer($raw->{maximum_bytes}, 1);
          $maximum == $maximum_by_name{$name} or exit 1;
          my $size = untaint_integer($raw->{size_bytes}, 1);
          $size <= $maximum or exit 1;
          push @leaves, {
            name => $name,
            identity => untaint_leaf_identity($raw->{identity}),
            size_bytes => $size,
            maximum_bytes => $maximum,
            sha256 => untaint_digest($raw->{sha256}),
          };
        }
        @leaves == 4 || @leaves == 6 or exit 1;
        @leaves = sort { $a->{name} cmp $b->{name} } @leaves;
        my @names = map { $_->{name} } @leaves;
        my @java_only = sort qw(java-backend-cgroup-v2.json java-backend-identity.txt
          midpoint-receipt.json snapshot.json);
        my @with_obi = sort (@java_only, qw(obi-cgroup-v2.json obi-identity.txt));
        (join(q{\0}, @names) eq join(q{\0}, @java_only) ||
          join(q{\0}, @names) eq join(q{\0}, @with_obi)) or exit 1;

        sysopen(my $parent, $parent_path,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW) or exit 1;
        directory_identity($parent) eq $expected_parent or exit 1;
        my $partial = openat_handle($parent, $partial_name,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        defined($partial) && directory_identity($partial) eq $expected_partial or exit 1;
        require_absent($parent, $final_name);
        require_absent($parent, $unavailable_name);
        verify_roster($partial, \@leaves, \@names);
        directory_identity($parent) eq $expected_parent &&
          directory_identity($partial) eq $expected_partial or exit 1;
        my $named_partial = openat_handle($parent, $partial_name,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        defined($named_partial) &&
          directory_identity($named_partial) eq $expected_partial or exit 1;
        close($named_partial) or exit 1;
        syscall(SYS_renameat2(), fileno($parent), $partial_name,
          fileno($parent), $final_name, RENAME_NOREPLACE_LINUX) == 0 or exit 1;

        my $published = openat_handle($parent, $final_name,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        defined($published) && directory_identity($published) eq $expected_partial &&
          directory_identity($partial) eq $expected_partial or exit 1;
        require_absent($parent, $partial_name);
        require_absent($parent, $unavailable_name);
        verify_roster($published, \@leaves, \@names);
        directory_identity($parent) eq $expected_parent &&
          directory_identity($published) eq $expected_partial &&
          directory_identity($partial) eq $expected_partial or exit 1;
        my $named_final = openat_handle($parent, $final_name,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        defined($named_final) &&
          directory_identity($named_final) eq $expected_partial or exit 1;
        verify_roster($named_final, \@leaves, \@names);
        close($named_final) && close($published) && close($partial) &&
          close($parent) or exit 1;
        print q{MIDPOINT1:}, $expected_partial;
      ' -- "$parent" "$partial_name" "$final_name" "$unavailable_name" \
      "$MIDPOINT_PARENT_DIRECTORY_AUTHORITY" \
      "$MIDPOINT_PARTIAL_DIRECTORY_AUTHORITY" \
      "$MAX_MIDPOINT_PUBLICATION_MANIFEST_BYTES" "$MAX_BOUNDARY_SNAPSHOT_BYTES" \
      "$MAX_MIDPOINT_RECEIPT_BYTES" "$MAX_SERVICE_IDENTITY_BYTES" \
      "$MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES")" || return 1
  [[ "$publication_receipt" == \
    "MIDPOINT1:$MIDPOINT_PARTIAL_DIRECTORY_AUTHORITY" ]] || return 1
}

scheduled_midpoint_receipt_json() {
  local -r status="$1"
  local -r reason="${2:-}"
  local repetition_label=""
  local benchmark_start_time=""
  local sleep_elapsed=""
  local confirmed_elapsed=""
  local sleep_wall="" sleep_monotonic="" extra=""
  local confirmed_wall="" confirmed_monotonic=""
  local -a services=(java-backend)
  local -a artifacts=()
  local service=""

  active_midpoint_transaction_matches || return 1
  [[ "$status" == available || "$status" == unavailable ]] || return 1
  if [[ "$status" == available ]]; then
    [[ -z "$reason" ]] || return 1
  else
    [[ "$reason" == load_client_not_live_at_scheduled_midpoint ||
      "$reason" == load_client_exited_during_scheduled_midpoint_capture ]] || return 1
  fi
  read -r _ _ benchmark_start_time <<<"$MIDPOINT_BENCHMARK_IDENTITY"
  [[ "$benchmark_start_time" =~ ^[1-9][0-9]*$ ]] || return 1
  sleep_elapsed="$(validate_elapsed_clock_window \
    "$MIDPOINT_SLEEP_STARTED_WALL_EPOCH_SECONDS" "$MIDPOINT_SLEEP_STARTED_MONOTONIC_MILLISECONDS" \
    "$MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS" "$MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS" \
    "$((MIDPOINT_DURATION_SECONDS / 2))" \
    "$((MIDPOINT_DURATION_SECONDS / 2 + MIDPOINT_TIMING_OVERRUN_SECONDS))")" || return 1
  confirmed_elapsed="$(validate_elapsed_clock_window \
    "$MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS" "$MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS" \
    "$MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS" "$MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS" \
    "$((MIDPOINT_DURATION_SECONDS / 2))" \
    "$((MIDPOINT_DURATION_SECONDS / 2 + MIDPOINT_TIMING_OVERRUN_SECONDS))")" || return 1
  read -r sleep_wall sleep_monotonic extra <<<"$sleep_elapsed"
  [[ -z "$extra" ]] || return 1
  read -r confirmed_wall confirmed_monotonic extra <<<"$confirmed_elapsed"
  [[ -z "$extra" ]] || return 1
  printf -v repetition_label 'rep-%02d' "$MIDPOINT_REPETITION"
  if [[ "$CELL_REQUIRES_OBI" == true ]]; then
    services=(obi java-backend)
  fi
  if [[ "$status" == available ]]; then
    for service in "${services[@]}"; do
      artifacts+=("$(jq -cn --arg service "$service" '{
        service: $service,
        identity_source: ($service + "-identity.txt"),
        cgroup_snapshot: ($service + "-cgroup-v2.json")
      }')") || return 1
    done
  fi
  jq -cn \
    --arg status "$status" --arg reason "$reason" --arg cell "$CELL_SLUG" \
    --arg output_source "cells/$CELL_SLUG/measurements/$repetition_label-midpoint" \
    --arg parent_identity "$MIDPOINT_PARENT_IDENTITY" \
    --arg partial_identity "$MIDPOINT_PARTIAL_IDENTITY" \
    --arg benchmark_identity "$MIDPOINT_BENCHMARK_IDENTITY" \
    --arg benchmark_result "cells/$CELL_SLUG/measurements/$repetition_label.json" \
    --argjson benchmark_pid "$MIDPOINT_BENCHMARK_PID" \
    --argjson repetition "$MIDPOINT_REPETITION" \
    --argjson duration "$MIDPOINT_DURATION_SECONDS" \
    --argjson requested "$((MIDPOINT_DURATION_SECONDS / 2))" \
    --argjson confirmed_wall "$MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS" \
    --argjson confirmed_monotonic "$MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS" \
    --argjson sleep_started_wall "$MIDPOINT_SLEEP_STARTED_WALL_EPOCH_SECONDS" \
    --argjson sleep_started_monotonic "$MIDPOINT_SLEEP_STARTED_MONOTONIC_MILLISECONDS" \
    --argjson sleep_ended_wall "$MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS" \
    --argjson sleep_ended_monotonic "$MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS" \
    --argjson capture_started_wall "$MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS" \
    --argjson capture_started_monotonic "$MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS" \
    --argjson capture_ended_wall "$MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS" \
    --argjson capture_ended_monotonic "$MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS" \
    --argjson sleep_wall "$sleep_wall" --argjson sleep_monotonic "$sleep_monotonic" \
    --argjson confirmed_elapsed_wall "$confirmed_wall" \
    --argjson confirmed_elapsed_monotonic "$confirmed_monotonic" \
    --argjson artifacts "$(printf '%s\n' "${artifacts[@]}" | jq -s .)" '
      {
        schema_version: 1,
        kind: "scheduled-cgroup-v2-midpoint-receipt",
        status: $status,
        cell: $cell,
        repetition: $repetition,
        benchmark_duration_seconds: $duration,
        scheduled_seconds_after_confirmed_launch: $requested,
        output_source: $output_source,
        measurement_parent_identity: $parent_identity,
        published_directory_identity: $partial_identity,
        benchmark: {pid: $benchmark_pid, identity: $benchmark_identity,
          result_source: $benchmark_result},
        clocks: {
          confirmed_launch: {wall_epoch_seconds: $confirmed_wall,
            monotonic_milliseconds: $confirmed_monotonic},
          sleep_started: {wall_epoch_seconds: $sleep_started_wall,
            monotonic_milliseconds: $sleep_started_monotonic},
          sleep_ended: {wall_epoch_seconds: $sleep_ended_wall,
            monotonic_milliseconds: $sleep_ended_monotonic},
          capture_started: {wall_epoch_seconds: $capture_started_wall,
            monotonic_milliseconds: $capture_started_monotonic},
          capture_ended: {wall_epoch_seconds: $capture_ended_wall,
            monotonic_milliseconds: $capture_ended_monotonic}
        },
        elapsed: {
          sleep_wall_seconds: $sleep_wall,
          sleep_monotonic_milliseconds: $sleep_monotonic,
          confirmed_launch_to_sleep_end_wall_seconds: $confirmed_elapsed_wall,
          confirmed_launch_to_sleep_end_monotonic_milliseconds: $confirmed_elapsed_monotonic
        },
        scope: {
          cgroup_v2_process_tree: (if $status == "available" then {status: "collected"}
            else {status: "not_collected", reason: $reason} end),
          docker_inspect: {status: "not_collected", reason: "excluded_from_measured_window"},
          container_stats: {status: "not_collected", reason: "excluded_from_measured_window"},
          obi_metrics: {status: "not_collected", reason: "zero_in_window_scrapes_required"},
          java_diagnostics: {status: "not_collected", reason: "excluded_from_measured_window"}
        },
        artifacts: $artifacts
      } + (if $status == "unavailable" then {reason: $reason} else {} end)
    '
}

capture_scheduled_midpoint_cgroups() {
  local -r partial="$1"
  local service=""
  local source_identity=""
  local source_sha256=""
  local -a services=(java-backend)

  active_midpoint_transaction_matches || return 1
  [[ "$partial" == "$MIDPOINT_PARTIAL" ]] || return 1
  if [[ "$CELL_REQUIRES_OBI" == true ]]; then
    services=(obi java-backend)
  fi
  validate_cpu_measurement_boundary \
    "$MIDPOINT_CELL_DIR/cpu-measurement-baseline" \
    "$CELL_SLUG" cpu_measurement_baseline || return 1
  for service in "${services[@]}"; do
    source_identity="$MIDPOINT_CELL_DIR/cpu-measurement-baseline/$service-identity.txt"
    [[ -f "$source_identity" && ! -L "$source_identity" ]] || return 1
    source_sha256="$(sha256_regular_file "$source_identity")" || return 1
    install -m 0600 -- "$source_identity" "$partial/$service-identity.txt" || return 1
    [[ "$(sha256_regular_file "$source_identity")" == "$source_sha256" &&
      "$(sha256_regular_file "$partial/$service-identity.txt")" == "$source_sha256" ]] || return 1
    capture_bound_cgroup_v2_snapshot \
      "$partial/$service-identity.txt" "$partial/$service-cgroup-v2.json" \
      scheduled_repetition_midpoint "$CELL_SLUG" "$service" "$MIDPOINT_REPETITION" || return 1
    validate_bound_cgroup_v2_snapshot_schema "$partial/$service-cgroup-v2.json" || return 1
    jq -e --arg cell "$CELL_SLUG" --arg service "$service" \
      --argjson repetition "$MIDPOINT_REPETITION" '
        .status == "available" and .cell == $cell and .service == $service and
        .timing == "scheduled_repetition_midpoint" and .repetition == $repetition
      ' "$partial/$service-cgroup-v2.json" >/dev/null || return 1
  done
}

write_unavailable_scheduled_midpoint_receipt() {
  local -r reason="$1"
  local repetition_label=""
  local output=""
  local expected_cell=""
  local expected_repetition=""
  local expected_parent_identity=""
  local expected_partial_identity=""
  local expected_parent_authority=""
  local receipt_value=""

  active_midpoint_transaction_matches || return 1
  printf -v repetition_label 'rep-%02d' "$MIDPOINT_REPETITION"
  output="$MIDPOINT_CELL_DIR/measurements/$repetition_label-midpoint.json"
  expected_cell="$CELL_SLUG"
  expected_repetition="$MIDPOINT_REPETITION"
  expected_parent_identity="$MIDPOINT_PARENT_IDENTITY"
  expected_partial_identity="$MIDPOINT_PARTIAL_IDENTITY"
  expected_parent_authority="$MIDPOINT_PARENT_DIRECTORY_AUTHORITY"
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  receipt_value="$(scheduled_midpoint_receipt_json unavailable "$reason")" || return 1
  receipt_value="$(printf '%s' "$receipt_value" | jq -ceSs '
    if length == 1 then .[0] else error("expected one unavailable midpoint receipt") end
  ')" || return 1
  validate_scheduled_midpoint_receipt_json_value "$receipt_value" \
    "$expected_cell" "$expected_repetition" unavailable \
    "$expected_parent_identity" "$expected_partial_identity" || return 1
  discard_scheduled_midpoint_partial || return 1
  publish_exact_json_value "$output" "$receipt_value" \
    "$MAX_MIDPOINT_RECEIPT_BYTES" "$expected_parent_authority"
}

capture_scheduled_repetition_midpoint_transaction() {
  local -r cell_dir="$1"
  local -r repetition="$2"
  local clocks=""
  local wall="" monotonic="" extra=""
  local receipt=""
  local receipt_value=""
  local snapshot=""
  local validated_midpoint_bundle=""
  local midpoint_seconds=0

  begin_scheduled_midpoint_transaction "$cell_dir" "$repetition" || return 1
  midpoint_seconds="$((MIDPOINT_DURATION_SECONDS / 2))"
  if ! "$SLEEP_COMMAND" "$midpoint_seconds"; then
    discard_scheduled_midpoint_partial || true
    return 1
  fi
  clocks="$(clock_pair_values)" || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  read -r wall monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS="$wall"
  MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS="$monotonic"
  validate_elapsed_clock_window \
    "$MIDPOINT_SLEEP_STARTED_WALL_EPOCH_SECONDS" "$MIDPOINT_SLEEP_STARTED_MONOTONIC_MILLISECONDS" \
    "$MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS" "$MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS" \
    "$midpoint_seconds" "$((midpoint_seconds + MIDPOINT_TIMING_OVERRUN_SECONDS))" >/dev/null || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  validate_elapsed_clock_window \
    "$MIDPOINT_CONFIRMED_WALL_EPOCH_SECONDS" "$MIDPOINT_CONFIRMED_MONOTONIC_MILLISECONDS" \
    "$MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS" "$MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS" \
    "$midpoint_seconds" "$((midpoint_seconds + MIDPOINT_TIMING_OVERRUN_SECONDS))" >/dev/null || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  if ! benchmark_job_is_running "$MIDPOINT_BENCHMARK_PID" ||
    ! benchmark_identity_matches_leader "$MIDPOINT_BENCHMARK_PID"; then
    MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS="$wall"
    MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS="$monotonic"
    MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS="$wall"
    MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS="$monotonic"
    write_unavailable_scheduled_midpoint_receipt load_client_not_live_at_scheduled_midpoint
    return $?
  fi
  MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS="$wall"
  MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS="$monotonic"
  if ! capture_scheduled_midpoint_cgroups "$MIDPOINT_PARTIAL"; then
    discard_scheduled_midpoint_partial || true
    return 1
  fi
  clocks="$(clock_pair_values)" || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  read -r wall monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS="$wall"
  MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS="$monotonic"
  validate_elapsed_clock_window \
    "$MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS" "$MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS" \
    "$MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS" "$MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS" 0 >/dev/null || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  if ! benchmark_job_is_running "$MIDPOINT_BENCHMARK_PID" ||
    ! benchmark_identity_matches_leader "$MIDPOINT_BENCHMARK_PID"; then
    write_unavailable_scheduled_midpoint_receipt load_client_exited_during_scheduled_midpoint_capture
    return $?
  fi
  receipt="$MIDPOINT_PARTIAL/midpoint-receipt.json"
  snapshot="$MIDPOINT_PARTIAL/snapshot.json"
  scheduled_midpoint_receipt_json available >"$receipt" || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  validate_scheduled_midpoint_receipt_schema \
    "$receipt" "$CELL_SLUG" "$MIDPOINT_REPETITION" available \
    "$MIDPOINT_PARENT_IDENTITY" "$MIDPOINT_PARTIAL_IDENTITY" \
    receipt_value || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  printf '%s' "$receipt_value" | jq -c '. | {
    schema_version: 1,
    kind: "scheduled-cgroup-v2-midpoint-boundary",
    status: .status,
    cell: .cell,
    repetition: .repetition,
    timing: "scheduled_repetition_midpoint",
    receipt: "midpoint-receipt.json",
    metrics: .scope.obi_metrics,
    java_diagnostics: .scope.java_diagnostics,
    services: [.artifacts[].service]
  }' >"$snapshot" || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  validate_scheduled_midpoint_boundary \
    "$MIDPOINT_PARTIAL" "$CELL_SLUG" "$MIDPOINT_REPETITION" \
    validated_midpoint_bundle "$receipt_value" || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  printf '%s\n%s' "$validated_midpoint_bundle" "$receipt_value" | jq -es '
    length == 2 and .[0].receipt == .[1]
  ' >/dev/null || {
    discard_scheduled_midpoint_partial || true
    return 1
  }
  if ! publish_scheduled_midpoint_directory "$validated_midpoint_bundle"; then
    discard_scheduled_midpoint_partial allow_foreign_final || true
    return 1
  fi
  clear_active_midpoint_transaction
}

capture_scheduled_repetition_midpoint() {
  local status=0

  capture_scheduled_repetition_midpoint_transaction "$@" || status=$?
  if ((status != 0)) && [[ "$MIDPOINT_ACTIVE" == true ]]; then
    discard_scheduled_midpoint_partial || return 1
  fi
  return "$status"
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
  if ! capture_scheduled_repetition_midpoint "$cell_dir" "$repetition"; then
    abort_active_benchmark || true
    return 1
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
  # All scheduled midpoints omit diagnostics so observation traffic cannot
  # contaminate the dedicated CPU/JFR measurement window. This is additionally
  # required for helper-idle exact t_missing accounting.
  if ! capture_scheduled_repetition_midpoint "$cell_dir" "$repetition"; then
    abort_active_benchmark || true
    return 1
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
  local result_value=""
  local status_value=""
  local contract_value=""
  local source=""
  local sample_json=""
  local samples_json=""
  local -a samples=()

  cell_spec "$cell" || return 1
  [[ "$REPETITIONS" == "$REQUIRED_REPETITIONS" ]] || return 1
  [[ -d "$measurement_dir" && ! -L "$measurement_dir" ]] || return 1
  [[ -f "$status_file" && ! -L "$status_file" ]] || return 1
  [[ -f "$contract_file" && ! -L "$contract_file" ]] || return 1
  status_value="$(validated_cell_status_json_value \
    "$status_file" "$cell")" || return 1
  contract_value="$(bounded_duplicate_free_json_value \
    "$contract_file" "$MAX_CELL_CONTRACT_BYTES")" || return 1
  printf '%s' "$contract_value" | jq -se --arg cell "$cell" '
    length == 1 and (.[0] | .cell == $cell)
  ' >/dev/null || return 1

  expected_sources="$(
    for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
      printf -v repetition_label 'rep-%02d.json' "$repetition"
      printf '%s\n' "$repetition_label"
    done
  )"
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    terminal_record_directory_selector \
      "$measurement_dir" benchmark-repetition-json || return 1
  else
    observed_sources="$(
      find "$measurement_dir" -mindepth 1 -maxdepth 1 \
        -name 'rep-[0-9][0-9].json' -printf '%f\n' | sort
    )" || return 1
    [[ "$observed_sources" == "$expected_sources" ]] || return 1
  fi

  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    printf -v repetition_label 'rep-%02d' "$repetition"
    result="$measurement_dir/$repetition_label.json"
    source="cells/$cell/measurements/$repetition_label.json"
    result_value="$(validated_benchmark_result_json_value \
      "$result" "$DURATION_SECONDS")" || return 1
    sample_json="$(printf '%s' "$result_value" | jq -sce \
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
      ')" || return 1
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
      def population_variability:
        . as $values |
        ($values | length) as $sample_count |
        if $sample_count != 5 or
          any($values[]; type != "number" or (isfinite | not))
        then error("population variability requires exactly five finite samples")
        else
          ($values | add) as $sum |
          ($sum / $sample_count) as $mean |
          if ($mean | isfinite | not) or $mean <= 0
          then error("population variability requires a positive finite mean")
          else
            ([$values[] | (. - $mean) * (. - $mean)] | add) as $squared_deviation_sum |
            ($squared_deviation_sum / $sample_count) as $population_variance |
            ($population_variance | sqrt) as $population_standard_deviation |
            {
              sample_count: $sample_count,
              sum: $sum,
              mean: $mean,
              squared_deviation_sum: $squared_deviation_sum,
              population_variance: $population_variance,
              population_standard_deviation: $population_standard_deviation,
              coefficient_of_variation_percent:
                ($population_standard_deviation / $mean * 100)
            }
          end
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
          throughput_per_second: (
            ($samples | map(.throughput_per_second)) as $values |
            ($values | observed_stats) + {
              population_variability: ($values | population_variability)
            }
          ),
          latency: {
            p50_nanos: ($samples | map(.latency.p50_nanos) | observed_stats),
            p95_nanos: ($samples | map(.latency.p95_nanos) | observed_stats),
            p99_nanos: (
              ($samples | map(.latency.p99_nanos)) as $values |
              ($values | observed_stats) + {
                population_variability: ($values | population_variability)
              }
            )
          }
        }
      }
    '
}

variance_summary_cells() {
  local -r root="${1:-$OUTPUT_DIR}"
  local cell=""
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
        schema_version: 2,
        kind: "application-performance-repetition-summary",
        status: "complete",
        acceptance_evidence: false,
        manifest: $manifest,
        aggregation: {
          sample_unit: "one completed sustained-client repetition",
          sample_selection: "all requested schema-valid repetitions for one cell; none are dropped",
          median: "odd: middle sorted numeric value; even: arithmetic mean of the two middle sorted numeric values",
          spread: "observed minimum and maximum; not a variance estimator or confidence interval",
          population_variability: {
            formula: "sqrt(sum((x-mean)^2)/N)/mean*100",
            divisor: "population_N",
            required_sample_count: 5,
            positive_finite_mean_required: true,
            metrics: ["throughput_per_second", "p99_latency_nanos"]
          },
          cross_cell_aggregation: false,
          per_request_latency_aggregation: false
        },
        cells: $cells,
        notes: [
          "Each latency statistic summarizes one percentile value from each completed repetition.",
          "Population CV uses all exactly five retained repetition values; no sample is dropped or substituted.",
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

proc_growth_snapshot_values_from_value() {
  local -r snapshot_value="$1"

  [[ -n "$snapshot_value" ]] || return 1
  printf '%s' "$snapshot_value" | \
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
  '
}

proc_growth_snapshot_values() {
  local -r snapshot="$1"
  local snapshot_value=""

  capture_bounded_regular_file_value \
    "$snapshot" "$MAX_PROC_STATUS_BYTES" snapshot_value || return 1
  proc_growth_snapshot_values_from_value "$snapshot_value"
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
      --arg recovery "cells/$cell/resources-idle-recovery-02/$service-proc.txt" '
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
      --arg recovery "cells/$cell/resources-idle-recovery-02/$service-proc.txt" '
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
    --arg recovery "cells/$cell/resources-idle-recovery-02/$service-proc.txt" \
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

java_bridge_map_metric_rows_from_value() {
  local -r metrics_value="$1"

  [[ -n "$metrics_value" ]] || return 1
  printf '%s' "$metrics_value" | \
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
  '
}

java_bridge_map_metric_rows() {
  local -r metrics_file="$1"
  local metrics_value=""

  capture_bounded_regular_file_value \
    "$metrics_file" "$MAX_OBI_METRICS_SNAPSHOT_BYTES" metrics_value || return 1
  java_bridge_map_metric_rows_from_value "$metrics_value"
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

bpf_fd_ownership_json_from_value() {
  local -r ownership_value="$1"

  [[ -n "$ownership_value" ]] || return 1
  printf '%s' "$ownership_value" | jq -Rsc '
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
  '
}

bpf_fd_ownership_json() {
  local -r ownership_file="$1"
  local ownership_value=""

  capture_bounded_regular_file_value \
    "$ownership_file" "$MAX_BPF_FD_OWNERSHIP_BYTES" ownership_value || return 1
  bpf_fd_ownership_json_from_value "$ownership_value"
}

bpf_probe_metric_rows_from_value() {
  local -r metrics_value="$1"

  [[ -n "$metrics_value" ]] || return 1
  printf '%s' "$metrics_value" | \
  awk '
    function invalid() {
      malformed = 1
    }
    /^obi_bpf_probe_(executions|latency_seconds|collection_passes)_total/ {
      if (NF != 2 || $2 !~ /^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$/) {
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
      delete labels_seen
      for (label_index = 1; label_index <= label_count; label_index++) {
        separator = index(pairs[label_index], "=")
        if (separator == 0) {
          invalid()
          continue
        }
        name = substr(pairs[label_index], 1, separator - 1)
        value = substr(pairs[label_index], separator + 1)
        if (name !~ /^(probe_id|probe_type|probe_name)$/ || labels_seen[name] ||
            value !~ /^"[A-Za-z0-9_.-]+"$/) {
          invalid()
          continue
        }
        labels_seen[name] = 1
        values[name] = substr(value, 2, length(value) - 2)
      }
      if (label_count != 3 || !labels_seen["probe_id"] || !labels_seen["probe_type"] ||
          !labels_seen["probe_name"] || values["probe_id"] !~ /^[1-9][0-9]*$/) {
        invalid()
        next
      }
      metric_name = metric == "obi_bpf_probe_executions_total" ? "executions" :
        (metric == "obi_bpf_probe_latency_seconds_total" ? "runtime_nanos" :
          (metric == "obi_bpf_probe_collection_passes_total" ? "collection_passes" : ""))
      if (metric_name == "") {
        invalid()
        next
      }
      canonical = metric_name SUBSEP values["probe_id"] SUBSEP values["probe_type"] SUBSEP values["probe_name"]
      if (series_seen[canonical]) {
        invalid()
        next
      }
      series_seen[canonical] = 1
      numeric = $2 + 0
      if (numeric < 0) {
        invalid()
        next
      }
      if (metric_name == "executions" || metric_name == "collection_passes") {
        if (numeric > 9007199254740991 || numeric != sprintf("%.0f", numeric) + 0) {
          invalid()
          next
        }
        normalized = sprintf("%.0f", numeric)
      } else {
        if (numeric > 9007199.254740991) {
          invalid()
          next
        }
        normalized = sprintf("%.0f", numeric * 1000000000)
      }
      printf "%s\t%s\t%s\t%s\t%s\n", metric_name, values["probe_id"],
        values["probe_type"], values["probe_name"], normalized
      emitted++
    }
    END {
      if (malformed || emitted == 0) {
        exit 1
      }
    }
  '
}

bpf_probe_metric_rows() {
  local -r metrics_file="$1"
  local metrics_value=""

  capture_bounded_regular_file_value \
    "$metrics_file" "$MAX_OBI_METRICS_SNAPSHOT_BYTES" metrics_value || return 1
  bpf_probe_metric_rows_from_value "$metrics_value"
}

bpf_probe_rows_json() {
  jq -Rsc '
    split("\n") |
    map(select(length > 0) | split("\t")) |
    map({
      metric: .[0], program_id: (.[1] | tonumber), probe_type: .[2],
      probe_name: .[3], value: (.[4] | tonumber)
    })
  '
}

exact_owned_java_bridge_probe_records_json() {
  local -r metrics_file="$1"
  local -r ownership_file="$2"
  local metric_rows_text=""
  local rows_json="[]"
  local owner="{}"
  local expected_program_names="[]"

  metric_rows_text="$(bpf_probe_metric_rows "$metrics_file")" || return 1
  rows_json="$(bpf_probe_rows_json <<<"$metric_rows_text")" || return 1
  owner="$(bpf_fd_ownership_json "$ownership_file")" || return 1
  expected_program_names="$(jq -cn '$ARGS.positional | sort' --args \
    "${JAVA_BRIDGE_CGROUP_SOCKOPT_PROGRAM_NAMES[@]}")" || return 1
  printf '%s\n%s\n%s' "$rows_json" "$owner" "$expected_program_names" | jq -cs '
      if length != 3 then error("expected BPF rows, owner, and program roster")
      else . end |
      .[0] as $rows |
      .[1] as $owner |
      .[2] as $expected_program_names |
      def positive_integer:
        type == "number" and isfinite and floor == . and . > 0;
      def non_negative_integer:
        type == "number" and isfinite and floor == . and . >= 0;
      ([$rows[] |
        .program_id as $id |
        .probe_name as $name |
        select(.probe_type == "CGroupSockopt" and
          ($owner.program_ids | index($id)) and
          ($expected_program_names | index($name)))]) as $owned |
      ($owned |
        group_by([.program_id, .probe_type, .probe_name]) |
        map(if length == 3 and
          ([.[].metric] | sort) == ["collection_passes", "executions", "runtime_nanos"]
        then {
          program_id: .[0].program_id,
          probe_type: .[0].probe_type,
          probe_name: .[0].probe_name,
          collection_passes: (map(select(.metric == "collection_passes"))[0].value),
          executions: (map(select(.metric == "executions"))[0].value),
          runtime_nanoseconds: (map(select(.metric == "runtime_nanos"))[0].value)
        }
        else error("incomplete BPF probe metric family")
        end) |
        sort_by([.program_id, .probe_type, .probe_name])) as $records |
      if ($records | map(.probe_name) | sort) != $expected_program_names or
        ($records | map(.program_id) | unique | length) != ($expected_program_names | length) or
        (all($records[];
          (.program_id | positive_integer) and
          (.collection_passes | non_negative_integer) and
          (.executions | non_negative_integer) and
          (.runtime_nanoseconds | non_negative_integer)) | not)
      then error("incomplete or malformed exact-owned Java bridge BPF probe roster")
      else $records
      end
    '
}

measurement_successful_request_total() {
  local -r cell_dir="$1"
  local repetition=0
  local repetition_label=""
  local count=""
  local result_value=""
  local total=0

  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    printf -v repetition_label 'rep-%02d' "$repetition"
    result_value="$(validated_benchmark_result_json_value \
      "$cell_dir/measurements/$repetition_label.json" "$DURATION_SECONDS")" || return 1
    count="$(benchmark_successful_request_count_json_value \
      "$result_value")" || return 1
    ((total <= MAX_SUSTAINED_WORKLOAD_SUCCESSFUL_REQUESTS - count)) || return 1
    total="$((total + count))"
  done
  ((total > 0)) || return 1
  printf '%s\n' "$total"
}

exact_owned_cgroup_sockopt_runtime_json() {
  local -r cell_dir="$1"
  local -r baseline_directory="$cell_dir/program-metrics-baseline"
  local -r end_directory="$cell_dir/program-metrics-end"
  local before_records="[]"
  local end_records="[]"
  local before_owner="{}"
  local end_owner="{}"
  local before_process="{}"
  local end_process="{}"
  local before_fence_records="[]"
  local end_fence_records="[]"
  local successful_requests=""
  local expected_program_names="[]"
  local not_applicable_reason=""

  if [[ "$CELL_REQUIRES_OBI" != "true" || "$CELL_SELECTED_TRANSPORT" != "getsockopt" ]]; then
    if [[ "$CELL_REQUIRES_OBI" != "true" ]]; then
      not_applicable_reason="cell_has_no_obi_process"
    else
      not_applicable_reason="selected_transport_does_not_use_cgroup_sockopt_bridge"
    fi
    jq -cn --arg cell "$CELL_SLUG" --arg reason "$not_applicable_reason" '{
      schema_version: 1,
      kind: "exact-owned-cgroup-sockopt-runtime-observation",
      status: "not_applicable",
      acceptance_evidence: false,
      cell: $cell,
      reason: $reason,
      scope: "exact_obi_process_open_java_bridge_cgroup_sockopt_program_ids",
      programs: []
    }'
    return 0
  fi
  validate_bpf_probe_collection_fence \
    "$baseline_directory/obi-metrics-fence.json" || return 1
  validate_bpf_probe_collection_fence \
    "$end_directory/obi-metrics-fence.json" || return 1
  before_records="$(exact_owned_java_bridge_probe_records_json \
    "$baseline_directory/obi-metrics.prom" \
    "$baseline_directory/obi-bpf-fd-ownership.txt")" || return 1
  end_records="$(exact_owned_java_bridge_probe_records_json \
    "$end_directory/obi-metrics.prom" \
    "$end_directory/obi-bpf-fd-ownership.txt")" || return 1
  before_fence_records="$(bpf_probe_collection_fence_confirmation_records_json \
    "$baseline_directory/obi-metrics-fence.json")" || return 1
  end_fence_records="$(bpf_probe_collection_fence_confirmation_records_json \
    "$end_directory/obi-metrics-fence.json")" || return 1
  before_owner="$(bpf_fd_ownership_json \
    "$baseline_directory/obi-bpf-fd-ownership.txt")" || return 1
  end_owner="$(bpf_fd_ownership_json \
    "$end_directory/obi-bpf-fd-ownership.txt")" || return 1
  before_process="$(proc_growth_identity_json "$baseline_directory/obi-proc.txt")" || return 1
  end_process="$(proc_growth_identity_json "$end_directory/obi-proc.txt")" || return 1
  successful_requests="$(measurement_successful_request_total "$cell_dir")" || return 1
  expected_program_names="$(jq -cn '$ARGS.positional | sort' --args \
    "${JAVA_BRIDGE_CGROUP_SOCKOPT_PROGRAM_NAMES[@]}")" || return 1
  printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$before_records" "$end_records" "$before_owner" "$end_owner" \
    "$before_process" "$end_process" "$before_fence_records" \
    "$end_fence_records" "$expected_program_names" | jq -cs \
    --arg cell "$CELL_SLUG" \
    --arg baseline_metrics "cells/$CELL_SLUG/program-metrics-baseline/obi-metrics.prom" \
    --arg end_metrics "cells/$CELL_SLUG/program-metrics-end/obi-metrics.prom" \
    --arg baseline_ownership "cells/$CELL_SLUG/program-metrics-baseline/obi-bpf-fd-ownership.txt" \
    --arg end_ownership "cells/$CELL_SLUG/program-metrics-end/obi-bpf-fd-ownership.txt" \
    --arg baseline_process "cells/$CELL_SLUG/program-metrics-baseline/obi-proc.txt" \
    --arg end_process_source "cells/$CELL_SLUG/program-metrics-end/obi-proc.txt" \
    --arg baseline_fence "cells/$CELL_SLUG/program-metrics-baseline/obi-metrics-fence.json" \
    --arg end_fence "cells/$CELL_SLUG/program-metrics-end/obi-metrics-fence.json" \
    --argjson successful_requests "$successful_requests" \
    --argjson repetitions "$REPETITIONS" \
    --argjson maximum_counter "$MAX_BPF_PROGRAM_METRIC_COUNTER" \
    --argjson maximum_runtime "$MAX_BPF_PROGRAM_RUNTIME_NANOSECONDS" '
      if length != 9 then error("expected exact BPF runtime source roster")
      else . end |
      .[0] as $before_records |
      .[1] as $end_records |
      .[2] as $before_owner |
      .[3] as $end_owner |
      .[4] as $before_process |
      .[5] as $end_process |
      .[6] as $before_fence_records |
      .[7] as $end_fence_records |
      .[8] as $expected_program_names |
      if ($before_owner != $end_owner or $before_process != $end_process or
          ($before_owner | del(.descriptors, .map_ids, .program_ids)) != $before_process or
          ($end_owner | del(.descriptors, .map_ids, .program_ids)) != $end_process)
      then error("OBI ownership or process identity drift")
      elif ($before_records | map([.program_id, .probe_type, .probe_name])) !=
        ($end_records | map([.program_id, .probe_type, .probe_name]))
      then error("exact-owned CGroupSockopt metric roster drift")
      elif ($before_records |
          map({program_id, probe_type, probe_name, collection_passes})) !=
        $before_fence_records or
        ($end_records |
          map({program_id, probe_type, probe_name, collection_passes})) !=
        $end_fence_records
      then error("exact-owned CGroupSockopt collection fence drift")
      elif any(range(0; $before_records | length);
        $end_records[.].executions < $before_records[.].executions or
        $end_records[.].runtime_nanoseconds < $before_records[.].runtime_nanoseconds or
        $end_records[.].collection_passes <= $before_records[.].collection_passes)
      then error("exact-owned CGroupSockopt counter reset")
      else
        [range(0; $before_records | length) as $index | {
          program_id: $before_records[$index].program_id,
          probe_type: $before_records[$index].probe_type,
          probe_name: $before_records[$index].probe_name,
          baseline: {
            collection_passes: $before_records[$index].collection_passes,
            executions: $before_records[$index].executions,
            runtime_nanoseconds: $before_records[$index].runtime_nanoseconds
          },
          end: {
            collection_passes: $end_records[$index].collection_passes,
            executions: $end_records[$index].executions,
            runtime_nanoseconds: $end_records[$index].runtime_nanoseconds
          },
          delta: {
            collection_passes: (
              $end_records[$index].collection_passes -
              $before_records[$index].collection_passes
            ),
            executions: ($end_records[$index].executions - $before_records[$index].executions),
            runtime_nanoseconds: (
              $end_records[$index].runtime_nanoseconds -
              $before_records[$index].runtime_nanoseconds
            )
          }
        }] as $programs |
        ($programs | map(.delta.executions) | add) as $total_executions |
        ($programs | map(.delta.runtime_nanoseconds) | add) as $total_runtime |
        if $total_executions > $maximum_counter or $total_runtime > $maximum_runtime
        then error("exact-owned CGroupSockopt delta exceeds numeric bound")
        else {
          schema_version: 1,
          kind: "exact-owned-cgroup-sockopt-runtime-observation",
          status: "complete",
          acceptance_evidence: false,
          cell: $cell,
          scope: "exact_obi_process_open_java_bridge_cgroup_sockopt_program_ids",
          window: {
            baseline: "post_warmup_before_first_measurement_repetition",
            end: "initiated_immediately_after_last_measurement_repetition",
            warmup_excluded: true,
            completed_repetitions: $repetitions
          },
          identity: $before_process,
          expected_program_names: $expected_program_names,
          successful_requests: $successful_requests,
          programs: $programs,
          totals: {
            executions: $total_executions,
            runtime_nanoseconds: $total_runtime,
            executions_per_successful_request: {
              numerator_executions: $total_executions,
              denominator_successful_requests: $successful_requests
            },
            runtime_nanoseconds_per_successful_request: {
              numerator_runtime_nanoseconds: $total_runtime,
              denominator_successful_requests: $successful_requests
            }
          },
          interpretation:
            "kernel-reported cumulative BPF program run-time and execution-counter deltas for the intersected owned program series",
          sources: {
            metrics: {baseline: $baseline_metrics, end: $end_metrics},
            ownership: {baseline: $baseline_ownership, end: $end_ownership},
            process: {baseline: $baseline_process, end: $end_process_source},
            fences: {baseline: $baseline_fence, end: $end_fence}
          }
        }
        end
      end
    '
}

validate_exact_owned_cgroup_sockopt_runtime() {
  local -r artifact="$1"
  local -r output_name="${2:-}"
  local cell_dir=""
  local expected=""
  local observed=""

  observed="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_BPF_PROGRAM_RUNTIME_BYTES")" || return 1
  cell_dir="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  expected="$(exact_owned_cgroup_sockopt_runtime_json "$cell_dir")" || return 1
  printf '%s\n%s' "$expected" "$observed" | jq -es '
    length == 2 and .[1] == .[0] and .[1].acceptance_evidence == false
  ' >/dev/null || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$observed"
  fi
}

write_exact_owned_cgroup_sockopt_runtime() {
  local -r cell_dir="$1"
  local -r output="$cell_dir/bpf-program-runtime.json"
  local runtime_value=""

  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  runtime_value="$(exact_owned_cgroup_sockopt_runtime_json "$cell_dir")" || return 1
  runtime_value="$(printf '%s' "$runtime_value" | jq -ceS .)" || return 1
  publish_exact_json_value "$output" "$runtime_value" \
    "$MAX_BPF_PROGRAM_RUNTIME_BYTES" || return 1
  validate_exact_owned_cgroup_sockopt_runtime "$output"
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
      --arg recovery "cells/$cell/resources-idle-recovery-02/obi-metrics.prom" \
      --arg before_ownership "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
      --arg recovery_ownership "cells/$cell/resources-idle-recovery-02/obi-bpf-fd-ownership.txt" \
      --arg before_process "cells/$cell/resources-before/obi-proc.txt" \
      --arg recovery_process "cells/$cell/resources-idle-recovery-02/obi-proc.txt" '
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
      --arg recovery "cells/$cell/resources-idle-recovery-02/obi-metrics.prom" \
      --arg before_ownership "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
      --arg recovery_ownership "cells/$cell/resources-idle-recovery-02/obi-bpf-fd-ownership.txt" \
      --arg before_process "cells/$cell/resources-before/obi-proc.txt" \
      --arg recovery_process "cells/$cell/resources-idle-recovery-02/obi-proc.txt" '
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
      --arg recovery "cells/$cell/resources-idle-recovery-02/obi-metrics.prom" \
      --arg before_ownership "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
      --arg recovery_ownership "cells/$cell/resources-idle-recovery-02/obi-bpf-fd-ownership.txt" \
      --arg before_process "cells/$cell/resources-before/obi-proc.txt" \
      --arg recovery_process "cells/$cell/resources-idle-recovery-02/obi-proc.txt" '
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
  printf '%s\n%s\n%s\n%s\n%s\n%s' \
    "$before_json" "$recovery_json" "$before_owner" "$recovery_owner" \
    "$before_process" "$recovery_process" | jq -cs \
    --arg cell "$cell" \
    --arg before_source "cells/$cell/resources-before/obi-metrics.prom" \
    --arg recovery_source "cells/$cell/resources-idle-recovery-02/obi-metrics.prom" \
    --arg before_ownership_source "cells/$cell/resources-before/obi-bpf-fd-ownership.txt" \
    --arg recovery_ownership_source "cells/$cell/resources-idle-recovery-02/obi-bpf-fd-ownership.txt" \
    --arg before_process_source "cells/$cell/resources-before/obi-proc.txt" \
    --arg recovery_process_source "cells/$cell/resources-idle-recovery-02/obi-proc.txt" '
      if length != 6 then error("expected map, ownership, and process boundary pairs")
      else . end |
      .[0] as $before |
      .[1] as $recovery |
      .[2] as $before_owner |
      .[3] as $recovery_owner |
      .[4] as $before_process |
      .[5] as $recovery_process |
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
    if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
      for service in "${services[@]}"; do
        terminal_record_optional_source_authority \
          "$cell_dir/resources-before/$service-proc.txt" \
          "$MAX_PROC_STATUS_BYTES" || return 1
        terminal_record_optional_source_authority \
          "$cell_dir/resources-idle-recovery-02/$service-proc.txt" \
          "$MAX_PROC_STATUS_BYTES" || return 1
      done
      if [[ "$CELL_REQUIRES_OBI" == "true" ]]; then
        terminal_record_optional_source_authority \
          "$cell_dir/resources-before/obi-metrics.prom" \
          "$MAX_OBI_METRICS_SNAPSHOT_BYTES" || return 1
        terminal_record_optional_source_authority \
          "$cell_dir/resources-idle-recovery-02/obi-metrics.prom" \
          "$MAX_OBI_METRICS_SNAPSHOT_BYTES" || return 1
        terminal_record_optional_source_authority \
          "$cell_dir/resources-before/obi-bpf-fd-ownership.txt" \
          "$MAX_BPF_FD_OWNERSHIP_BYTES" || return 1
        terminal_record_optional_source_authority \
          "$cell_dir/resources-idle-recovery-02/obi-bpf-fd-ownership.txt" \
          "$MAX_BPF_FD_OWNERSHIP_BYTES" || return 1
      fi
    fi
    for service in "${services[@]}"; do
      observation="$(process_growth_observation \
        "$cell" "$service" \
        "$cell_dir/resources-before/$service-proc.txt" \
        "$cell_dir/resources-idle-recovery-02/$service-proc.txt")" || return 1
      process_observations+=("$observation")
    done
    if [[ "$CELL_REQUIRES_OBI" == "true" ]]; then
      observation="$(java_bridge_map_growth_observation \
        "$cell" \
        "$cell_dir/resources-before/obi-metrics.prom" \
        "$cell_dir/resources-idle-recovery-02/obi-metrics.prom" \
        "$cell_dir/resources-before/obi-bpf-fd-ownership.txt" \
        "$cell_dir/resources-idle-recovery-02/obi-bpf-fd-ownership.txt" \
        "$cell_dir/resources-before/obi-proc.txt" \
        "$cell_dir/resources-idle-recovery-02/obi-proc.txt")" || return 1
      map_observations+=("$observation")
    fi
  done
  process_json="$(printf '%s\n' "${process_observations[@]}" | jq -s .)" || return 1
  maps_json="$(printf '%s\n' "${map_observations[@]}" | jq -s .)" || return 1
  printf '%s\n%s' "$process_json" "$maps_json" | jq -cs '
      if length != 2 then error("expected process and map observation rosters")
      else . end |
      .[0] as $processes |
      .[1] as $maps |
      {
        status: "partial",
        required_samples: ["before", "idle_recovery_02"],
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

process_tree_resource_observation() {
  local -r cell="$1"
  local -r service="$2"
  local before_json="" baseline_json="" end_json="" after_load_json=""
  local recovery_01_json="" recovery_02_json="" schedule_json=""
  local midpoint_01_json="" midpoint_02_json="" midpoint_03_json=""
  local midpoint_04_json="" midpoint_05_json=""

  before_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "$3" "$cell" "$service" before)" || return 1
  baseline_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "$4" "$cell" "$service" cpu_measurement_baseline)" || return 1
  end_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "$5" "$cell" "$service" cpu_measurement_end)" || return 1
  after_load_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "$6" "$cell" "$service" after)" || return 1
  recovery_01_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "$7" "$cell" "$service" idle_recovery_01)" || return 1
  recovery_02_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "$8" "$cell" "$service" idle_recovery_02)" || return 1
  # The recovery schedule has no unavailable schema: a missing lexical source is
  # an artifact-construction failure, while malformed captured contents project
  # to a partial observation below.
  schedule_json="$(bounded_duplicate_free_json_value \
    "$9" "$MAX_RECOVERY_SCHEDULE_BYTES")" || return 1
  midpoint_01_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "${10}" "$cell" "$service" scheduled_repetition_midpoint 1)" || return 1
  midpoint_02_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "${11}" "$cell" "$service" scheduled_repetition_midpoint 2)" || return 1
  midpoint_03_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "${12}" "$cell" "$service" scheduled_repetition_midpoint 3)" || return 1
  midpoint_04_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "${13}" "$cell" "$service" scheduled_repetition_midpoint 4)" || return 1
  midpoint_05_json="$(bound_cgroup_v2_snapshot_json_value_or_unavailable \
    "${14}" "$cell" "$service" scheduled_repetition_midpoint 5)" || return 1
  process_tree_resource_observation_values "$cell" "$service" \
    "$before_json" "$baseline_json" "$end_json" "$after_load_json" \
    "$recovery_01_json" "$recovery_02_json" "$schedule_json" \
    "$midpoint_01_json" "$midpoint_02_json" "$midpoint_03_json" \
    "$midpoint_04_json" "$midpoint_05_json"
}

process_tree_resource_observation_values() {
  local -r cell="$1"
  local -r service="$2"
  local -r before_json="$3"
  local -r baseline_json="$4"
  local -r end_json="$5"
  local -r after_load_json="$6"
  local -r recovery_01_json="$7"
  local -r recovery_02_json="$8"
  local -r schedule_json="$9"
  local -r midpoint_01_json="${10}"
  local -r midpoint_02_json="${11}"
  local -r midpoint_03_json="${12}"
  local -r midpoint_04_json="${13}"
  local -r midpoint_05_json="${14}"
  local schedule_cell=""

  if ! validate_recovery_schedule_shape_json_value "$schedule_json" ||
    ! schedule_cell="$(printf '%s' "$schedule_json" | jq -er '.cell')" ||
    [[ "$schedule_cell" != "$cell" ]] ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$before_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$baseline_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$end_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$after_load_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$recovery_01_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$recovery_02_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$midpoint_01_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$midpoint_02_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$midpoint_03_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$midpoint_04_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$midpoint_05_json"; then
    jq -cn --arg cell "$cell" --arg service "$service" '{
      cell: $cell, service: $service, status: "partial", result: "not_evaluated",
      reason: "required_schedule_or_cgroup_v2_snapshot_unavailable_or_malformed"
    }'
    return 0
  fi
  printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$before_json" "$baseline_json" "$end_json" "$after_load_json" \
    "$recovery_01_json" "$recovery_02_json" "$midpoint_01_json" \
    "$midpoint_02_json" "$midpoint_03_json" "$midpoint_04_json" \
    "$midpoint_05_json" | jq -cs \
    --arg cell "$cell" --arg service "$service" \
    --arg before_source "cells/$cell/resources-before/$service-cgroup-v2.json" \
    --arg baseline_source "cells/$cell/cpu-measurement-baseline/$service-cgroup-v2.json" \
    --arg end_source "cells/$cell/cpu-measurement-end/$service-cgroup-v2.json" \
    --arg after_load_source "cells/$cell/resources-after-load/$service-cgroup-v2.json" \
    --arg recovery_01_source "cells/$cell/resources-idle-recovery-01/$service-cgroup-v2.json" \
    --arg recovery_02_source "cells/$cell/resources-idle-recovery-02/$service-cgroup-v2.json" \
    --arg midpoint_01_source "cells/$cell/measurements/rep-01-midpoint/$service-cgroup-v2.json" \
    --arg midpoint_02_source "cells/$cell/measurements/rep-02-midpoint/$service-cgroup-v2.json" \
    --arg midpoint_03_source "cells/$cell/measurements/rep-03-midpoint/$service-cgroup-v2.json" \
    --arg midpoint_04_source "cells/$cell/measurements/rep-04-midpoint/$service-cgroup-v2.json" \
    --arg midpoint_05_source "cells/$cell/measurements/rep-05-midpoint/$service-cgroup-v2.json" \
    --arg schedule_source "cells/$cell/recovery-schedule.json" \
    --argjson fd_absolute_max "$PROCESS_TREE_FD_ABSOLUTE_MAX" \
    --argjson task_absolute_max "$PROCESS_TREE_TASK_ABSOLUTE_MAX" \
    --argjson rss_absolute_max "$PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX" \
    --argjson fd_recovery_max "$PROCESS_TREE_FD_RECOVERY_DELTA_MAX" \
    --argjson task_recovery_max "$PROCESS_TREE_TASK_RECOVERY_DELTA_MAX" \
    --argjson rss_recovery_max "$PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX" '
      if length != 11 then error("expected exact process-tree snapshot roster")
      else . end |
      .[0] as $before |
      .[1] as $baseline |
      .[2] as $end |
      .[3] as $after_load |
      .[4] as $recovery_01 |
      .[5] as $recovery_02 |
      .[6] as $midpoint_01 |
      .[7] as $midpoint_02 |
      .[8] as $midpoint_03 |
      .[9] as $midpoint_04 |
      .[10] as $midpoint_05 |
      def sample_values($metric): {
        before: $before.envelope[$metric].max,
        baseline: $baseline.envelope[$metric].max,
        rep_01_midpoint: $midpoint_01.envelope[$metric].max,
        rep_02_midpoint: $midpoint_02.envelope[$metric].max,
        rep_03_midpoint: $midpoint_03.envelope[$metric].max,
        rep_04_midpoint: $midpoint_04.envelope[$metric].max,
        rep_05_midpoint: $midpoint_05.envelope[$metric].max,
        end: $end.envelope[$metric].max,
        after_load: $after_load.envelope[$metric].max,
        idle_recovery_01: $recovery_01.envelope[$metric].max,
        idle_recovery_02: $recovery_02.envelope[$metric].max
      };
      def absolute_gate($metric; $maximum):
        (sample_values($metric)) as $samples | {
          samples: $samples,
          maximum: $maximum,
          result: (if all($samples[]; . <= $maximum) then "passed" else "failed" end)
        };
      def recovery_gate($metric; $maximum): {
        before_min: $before.envelope[$metric].min,
        idle_recovery_01_max: $recovery_01.envelope[$metric].max,
        idle_recovery_02_max: $recovery_02.envelope[$metric].max,
        delta_01: ($recovery_01.envelope[$metric].max - $before.envelope[$metric].min),
        delta_02: ($recovery_02.envelope[$metric].max - $before.envelope[$metric].min),
        maximum_delta: $maximum,
        result: (
          if ($recovery_01.envelope[$metric].max - $before.envelope[$metric].min) <= $maximum and
             ($recovery_02.envelope[$metric].max - $before.envelope[$metric].min) <= $maximum
          then "passed" else "failed" end
        )
      };
      if any([$before, $baseline, $end, $after_load, $recovery_01, $recovery_02,
          $midpoint_01, $midpoint_02, $midpoint_03, $midpoint_04, $midpoint_05][];
          .status != "available" or .cell != $cell or .service != $service) or
        $before.timing != "before" or $baseline.timing != "cpu_measurement_baseline" or
        $end.timing != "cpu_measurement_end" or
        $after_load.timing != "after" or
        $recovery_01.timing != "idle_recovery_01" or
        $recovery_02.timing != "idle_recovery_02" or
        any([$midpoint_01, $midpoint_02, $midpoint_03, $midpoint_04, $midpoint_05][];
          .timing != "scheduled_repetition_midpoint") or
        [$midpoint_01.repetition, $midpoint_02.repetition, $midpoint_03.repetition,
          $midpoint_04.repetition, $midpoint_05.repetition] != [1, 2, 3, 4, 5] or
        any([$before, $end, $after_load, $recovery_01, $recovery_02,
          $midpoint_01, $midpoint_02, $midpoint_03, $midpoint_04, $midpoint_05][];
          .identity != $baseline.identity)
      then {
        cell: $cell, service: $service, status: "partial", result: "not_evaluated",
        reason: "required_snapshot_unavailable_or_container_cgroup_authority_drifted"
      }
      else {
        cell: $cell,
        service: $service,
        status: "complete",
        identity: $baseline.identity,
        absolute: {
          fd_count: absolute_gate("fd_count"; $fd_absolute_max),
          task_count: absolute_gate("task_count"; $task_absolute_max),
          rss_bytes: absolute_gate("rss_bytes"; $rss_absolute_max)
        },
        recovery: {
          fd_count: recovery_gate("fd_count"; $fd_recovery_max),
          task_count: recovery_gate("task_count"; $task_recovery_max),
          rss_bytes: recovery_gate("rss_bytes"; $rss_recovery_max)
        },
        sources: {
          before: $before_source, baseline: $baseline_source,
          end: $end_source, after_load: $after_load_source,
          repetition_midpoints: [
            $midpoint_01_source, $midpoint_02_source, $midpoint_03_source,
            $midpoint_04_source, $midpoint_05_source
          ],
          idle_recovery_01: $recovery_01_source,
          idle_recovery_02: $recovery_02_source,
          recovery_schedule: $schedule_source
        }
      } end |
      .result = (
        if .status != "complete" then "not_evaluated"
        elif all([.absolute[], .recovery[]][]; .result == "passed") then "passed"
        else "failed" end
      )
    '
}

process_tree_resource_gate() {
  local -r root="${1:-$OUTPUT_DIR}"
  local -r supplied_observations="${2:-}"
  local cell=""
  local service=""
  local cell_dir=""
  local observation=""
  local observations_json=""
  local -a services=()
  local -a observations=()

  [[ "$REPETITIONS" == 5 ]] || return 1
  if [[ -z "$supplied_observations" ]]; then
    for cell in "${CORE_CELLS[@]}"; do
    cell_spec "$cell" || return 1
    cell_dir="$root/cells/$cell"
    services=(java-backend)
    if [[ "$CELL_REQUIRES_OBI" == true ]]; then
      services=(obi "${services[@]}")
    fi
    for service in "${services[@]}"; do
      if validate_resource_cgroup_boundary "$cell_dir/resources-before" "$cell" before "$service" &&
        validate_cpu_measurement_boundary "$cell_dir/cpu-measurement-baseline" \
          "$cell" cpu_measurement_baseline &&
        validate_cpu_measurement_boundary "$cell_dir/cpu-measurement-end" \
          "$cell" cpu_measurement_end &&
        validate_resource_cgroup_boundary "$cell_dir/resources-after-load" "$cell" after "$service" &&
        validate_resource_cgroup_boundary "$cell_dir/resources-idle-recovery-01" \
          "$cell" idle_recovery_01 "$service" &&
        validate_resource_cgroup_boundary "$cell_dir/resources-idle-recovery-02" \
          "$cell" idle_recovery_02 "$service" &&
        validate_recovery_schedule_schema "$cell_dir/recovery-schedule.json" &&
        validate_scheduled_midpoint_boundary "$cell_dir/measurements/rep-01-midpoint" "$cell" 1 &&
        validate_scheduled_midpoint_boundary "$cell_dir/measurements/rep-02-midpoint" "$cell" 2 &&
        validate_scheduled_midpoint_boundary "$cell_dir/measurements/rep-03-midpoint" "$cell" 3 &&
        validate_scheduled_midpoint_boundary "$cell_dir/measurements/rep-04-midpoint" "$cell" 4 &&
        validate_scheduled_midpoint_boundary "$cell_dir/measurements/rep-05-midpoint" "$cell" 5; then
        observation="$(process_tree_resource_observation \
          "$cell" "$service" \
          "$cell_dir/resources-before/$service-cgroup-v2.json" \
          "$cell_dir/cpu-measurement-baseline/$service-cgroup-v2.json" \
          "$cell_dir/cpu-measurement-end/$service-cgroup-v2.json" \
          "$cell_dir/resources-after-load/$service-cgroup-v2.json" \
          "$cell_dir/resources-idle-recovery-01/$service-cgroup-v2.json" \
          "$cell_dir/resources-idle-recovery-02/$service-cgroup-v2.json" \
          "$cell_dir/recovery-schedule.json" \
          "$cell_dir/measurements/rep-01-midpoint/$service-cgroup-v2.json" \
          "$cell_dir/measurements/rep-02-midpoint/$service-cgroup-v2.json" \
          "$cell_dir/measurements/rep-03-midpoint/$service-cgroup-v2.json" \
          "$cell_dir/measurements/rep-04-midpoint/$service-cgroup-v2.json" \
          "$cell_dir/measurements/rep-05-midpoint/$service-cgroup-v2.json")" || return 1
      else
        observation="$(jq -cn --arg cell "$cell" --arg service "$service" '{
          cell: $cell, service: $service, status: "partial", result: "not_evaluated",
          reason: "required_boundary_receipt_or_identity_binding_unavailable_or_malformed"
        }')" || return 1
      fi
      observations+=("$observation")
    done
    done
    observations_json="$(printf '%s\n' "${observations[@]}" | jq -s .)" || return 1
  else
    observations_json="$supplied_observations"
    printf '%s' "$observations_json" | jq -e '
      type == "array" and length == 11 and
      all(.[]; .cell and .service and .status and .result)
    ' >/dev/null || return 1
  fi
  printf '%s' "$observations_json" | jq -c \
    --argjson fd_absolute_max "$PROCESS_TREE_FD_ABSOLUTE_MAX" \
    --argjson task_absolute_max "$PROCESS_TREE_TASK_ABSOLUTE_MAX" \
    --argjson rss_absolute_max "$PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX" \
    --argjson fd_recovery_max "$PROCESS_TREE_FD_RECOVERY_DELTA_MAX" \
    --argjson task_recovery_max "$PROCESS_TREE_TASK_RECOVERY_DELTA_MAX" \
    --argjson rss_recovery_max "$PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX" '
      . as $observations |
      {
        status: (
          if all($observations[]; .status == "complete") then "complete" else "partial" end
        ),
        result: (
          if any($observations[]; .status == "complete" and .result == "failed") then "failed"
          elif any($observations[]; .status != "complete") then "not_evaluated"
          else "passed" end
        ),
        scope: "complete_leaf_cgroup_v2_process_tree",
        thresholds: {
          absolute: {
            fd_count: $fd_absolute_max,
            task_count: $task_absolute_max,
            rss_bytes: $rss_absolute_max
          },
          recovery_delta: {
            fd_count: $fd_recovery_max,
            task_count: $task_recovery_max,
            rss_bytes: $rss_recovery_max
          }
        },
        boundaries: [
          "before", "cpu_measurement_baseline", "rep_01_midpoint", "rep_02_midpoint",
          "rep_03_midpoint", "rep_04_midpoint", "rep_05_midpoint", "cpu_measurement_end",
          "after_load", "idle_recovery_01", "idle_recovery_02"
        ],
        recovery: {interval_seconds: 30, required_consecutive_samples: 2},
        conservative_sampling: {
          absolute_value: "two_pass_envelope_max",
          recovery_delta: "recovery_envelope_max_minus_before_envelope_min"
        },
        observations: $observations
      }
    '
}

decimal_multiply() {
  local -r left="$1"
  local -r right="$2"
  local left_index=0
  local right_index=0
  local position=0
  local carry=0
  local value=0
  local result=""
  local started=false
  local -a digits=()

  [[ "$left" =~ ^(0|[1-9][0-9]*)$ && "$right" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  for ((left_index = ${#left} - 1; left_index >= 0; left_index--)); do
    for ((right_index = ${#right} - 1; right_index >= 0; right_index--)); do
      position="$(((${#left} - 1 - left_index) + (${#right} - 1 - right_index)))"
      ((digits[position] += 10#${left:left_index:1} * 10#${right:right_index:1}))
    done
  done
  for ((position = 0; position < ${#left} + ${#right}; position++)); do
    value="${digits[position]:-0}"
    ((value += carry))
    digits[position]="$((value % 10))"
    carry="$((value / 10))"
  done
  while ((carry > 0)); do
    digits[position]="$((carry % 10))"
    carry="$((carry / 10))"
    ((position += 1))
  done
  for ((position = ${#digits[@]} - 1; position >= 0; position--)); do
    if [[ "${digits[position]}" != 0 || "$started" == true ]]; then
      result+="${digits[position]}"
      started=true
    fi
  done
  [[ "$started" == true ]] || result=0
  printf '%s\n' "$result"
}

decimal_less_than_or_equal() {
  local -r left="$1"
  local -r right="$2"

  [[ "$left" =~ ^(0|[1-9][0-9]*)$ && "$right" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  if ((${#left} < ${#right})); then
    return 0
  fi
  if ((${#left} > ${#right})); then
    return 1
  fi
  [[ "$left" == "$right" || "$left" < "$right" ]]
}

cpu_service_measurement_observation() (
  local -r root="$1"
  local -r cell="$2"
  local -r service="$3"
  local baseline_bundle=""
  local end_bundle=""
  local baseline_json=""
  local end_json=""
  local successful_requests=""

  # Result validation below reads the current cell workload contract. Bind it
  # inside this subshell before opening any per-repetition result.
  cell_spec "$cell" || return 1
  validate_cpu_measurement_boundary \
    "$root/cells/$cell/cpu-measurement-baseline" "$cell" \
    cpu_measurement_baseline baseline_bundle || return 1
  validate_cpu_measurement_boundary \
    "$root/cells/$cell/cpu-measurement-end" "$cell" \
    cpu_measurement_end end_bundle || return 1
  baseline_json="$(printf '%s' "$baseline_bundle" | \
    jq -ce --arg service "$service" '.snapshots[$service]')" || return 1
  end_json="$(printf '%s' "$end_bundle" | \
    jq -ce --arg service "$service" '.snapshots[$service]')" || return 1
  successful_requests="$(measurement_successful_request_total \
    "$root/cells/$cell")" || return 1
  cpu_service_measurement_observation_values "$root" "$cell" "$service" \
    "$baseline_json" "$end_json" "$successful_requests"
)

cpu_service_measurement_observation_values() (
  local -r root="$1"
  local -r cell="$2"
  local -r service="$3"
  local -r baseline_json="$4"
  local -r end_json="$5"
  local -r successful_requests="$6"

  # Benchmark-result validation depends on the cell's exact workload contract;
  # never inherit the globals left by whichever cell happened to run last.
  cell_spec "$cell" || return 1
  [[ "$cell" == bridge-disabled || "$cell" == getsockopt-hit ||
    "$cell" == unix-hit || "$cell" == getsockopt-w3c ]] || return 1
  [[ "$service" == obi || "$service" == java-backend ]] || return 1
  if ! validate_bound_cgroup_v2_snapshot_json_value "$baseline_json" ||
    ! validate_bound_cgroup_v2_snapshot_json_value "$end_json"; then
    jq -cn --arg cell "$cell" --arg service "$service" '{
      cell: $cell, service: $service, status: "partial", result: "not_evaluated",
      reason: "dedicated_cpu_boundary_unavailable_or_malformed"
    }'
    return 0
  fi
  printf '%s\n%s' "$baseline_json" "$end_json" | jq -cs \
    --arg cell "$cell" --arg service "$service" \
    --arg baseline_source "cells/$cell/cpu-measurement-baseline/$service-cgroup-v2.json" \
    --arg end_source "cells/$cell/cpu-measurement-end/$service-cgroup-v2.json" \
    --arg request_source "cells/$cell/measurements/rep-*.json" \
    --argjson successful_requests "$successful_requests" '
      if length != 2 then error("expected dedicated CPU baseline and end snapshots")
      else . end |
      .[0] as $baseline |
      .[1] as $end |
      if $baseline.status != "available" or $end.status != "available" or
        $baseline.cell != $cell or $end.cell != $cell or
        $baseline.service != $service or $end.service != $service or
        $baseline.timing != "cpu_measurement_baseline" or
        $end.timing != "cpu_measurement_end" or
        $baseline.identity != $end.identity or
        $end.envelope.cpu_usage_usec.min <= $baseline.envelope.cpu_usage_usec.max or
        $end.envelope.cpu_user_usec.min < $baseline.envelope.cpu_user_usec.max or
        $end.envelope.cpu_system_usec.min < $baseline.envelope.cpu_system_usec.max or
        $successful_requests <= 0
      then {
        cell: $cell, service: $service, status: "partial", result: "not_evaluated",
        reason: "dedicated_cpu_counter_reset_overlap_or_authority_drift"
      }
      else {
        cell: $cell,
        service: $service,
        status: "complete",
        result: "measured",
        identity: $baseline.identity,
        baseline_usage_usec: $baseline.envelope.cpu_usage_usec.max,
        end_usage_usec: $end.envelope.cpu_usage_usec.min,
        delta_usage_usec: (
          $end.envelope.cpu_usage_usec.min - $baseline.envelope.cpu_usage_usec.max
        ),
        cpu_stat: {
          usage_usec: {
            baseline: $baseline.envelope.cpu_usage_usec.max,
            end: $end.envelope.cpu_usage_usec.min,
            delta: ($end.envelope.cpu_usage_usec.min - $baseline.envelope.cpu_usage_usec.max)
          },
          user_usec: {
            baseline: $baseline.envelope.cpu_user_usec.max,
            end: $end.envelope.cpu_user_usec.min,
            delta: ($end.envelope.cpu_user_usec.min - $baseline.envelope.cpu_user_usec.max)
          },
          system_usec: {
            baseline: $baseline.envelope.cpu_system_usec.max,
            end: $end.envelope.cpu_system_usec.min,
            delta: ($end.envelope.cpu_system_usec.min - $baseline.envelope.cpu_system_usec.max)
          }
        },
        successful_requests: $successful_requests,
        usage_usec_per_successful_request: {
          numerator_usage_usec: (
            $end.envelope.cpu_usage_usec.min - $baseline.envelope.cpu_usage_usec.max
          ),
          denominator_successful_requests: $successful_requests
        },
        sources: {
          baseline: $baseline_source, end: $end_source,
          successful_requests: $request_source
        }
      }
      end
    '
)

application_cpu_gate() {
  local -r root="${1:-$OUTPUT_DIR}"
  local -r supplied_observations="${2:-}"
  local cell=""
  local service=""
  local dimension=""
  local observation=""
  local observations_json=""
  local baseline_delta=""
  local baseline_requests=""
  local candidate_delta=""
  local candidate_requests=""
  local candidate_scaled=""
  local maximum_scaled=""
  local result=""
  local comparison=""
  local comparisons_json=""
  local cell_json=""
  local obi_delta=""
  local java_delta=""
  local requests=""
  local -a observations=()
  local -a comparisons=()
  local -a cells=(bridge-disabled getsockopt-hit unix-hit getsockopt-w3c)

  if [[ -z "$supplied_observations" ]]; then
    for cell in "${cells[@]}"; do
      for service in obi java-backend; do
        observation="$(cpu_service_measurement_observation "$root" "$cell" "$service")" || return 1
        observations+=("$observation")
      done
    done
    observations_json="$(printf '%s\n' "${observations[@]}" | jq -s .)" || return 1
  else
    observations_json="$supplied_observations"
    printf '%s' "$observations_json" | jq -e '
      type == "array" and length == 8 and
      all(.[]; .cell and .service and .status and .result)
    ' >/dev/null || return 1
  fi
  if ! jq -e 'all(.[]; .status == "complete")' <<<"$observations_json" >/dev/null; then
    printf '%s' "$observations_json" | jq -c '. as $observations | {
      status: "partial", result: "not_evaluated",
      baseline_cell: "bridge-disabled",
      comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
      dimensions: ["obi", "java_backend", "combined"],
      maximum_regression_percent: 10,
      arithmetic: "exact_unsigned_decimal_cross_multiplication",
      observations: $observations,
      comparisons: [],
      excluded_cells: {
        uninstrumented: "no_official_agent",
        getsockopt_helper_idle: "direct_java_workload_is_not_comparable_to_the_apache_baseline"
      },
      primary_cgroupsockopt_program_cpu: "not_collected"
    }'
    return 0
  fi
  for cell in "${cells[@]}"; do
    obi_delta="$(jq -er --arg cell "$cell" \
      '.[] | select(.cell == $cell and .service == "obi") | .delta_usage_usec' \
      <<<"$observations_json")" || return 1
    java_delta="$(jq -er --arg cell "$cell" \
      '.[] | select(.cell == $cell and .service == "java-backend") | .delta_usage_usec' \
      <<<"$observations_json")" || return 1
    requests="$(jq -er --arg cell "$cell" \
      '.[] | select(.cell == $cell and .service == "obi") | .successful_requests' \
      <<<"$observations_json")" || return 1
    ((obi_delta <= MAX_JSON_EXACT_INTEGER - java_delta)) || return 1
    [[ "$requests" == "$(jq -er --arg cell "$cell" \
      '.[] | select(.cell == $cell and .service == "java-backend") | .successful_requests' \
      <<<"$observations_json")" ]] || return 1
  done
  # Build the compact per-cell CPU ledger directly from the validated service
  # observations. This second projection makes the combined value auditable.
  observations_json="$(printf '%s' "$observations_json" | jq -c '
    group_by(.cell) | map({
      cell: .[0].cell,
      successful_requests: .[0].successful_requests,
      dimensions: {
        obi: (map(select(.service == "obi"))[0].delta_usage_usec),
        java_backend: (map(select(.service == "java-backend"))[0].delta_usage_usec),
        combined: ((map(select(.service == "obi"))[0].delta_usage_usec) +
          (map(select(.service == "java-backend"))[0].delta_usage_usec))
      },
      services: .
    })
  ')" || return 1
  jq -e --argjson maximum "$MAX_JSON_EXACT_INTEGER" '
    all(.[]; . as $cell |
      .successful_requests > 0 and .dimensions.obi > 0 and
      .dimensions.java_backend > 0 and .dimensions.combined > 0 and
      .dimensions.combined <= $maximum and
      .dimensions.combined == (.dimensions.obi + .dimensions.java_backend) and
      all(.services[]; .successful_requests == $cell.successful_requests))
  ' <<<"$observations_json" >/dev/null 2>&1 || return 1
  for cell in getsockopt-hit unix-hit getsockopt-w3c; do
    for dimension in obi java_backend combined; do
      baseline_delta="$(jq -er --arg dimension "$dimension" \
        '.[] | select(.cell == "bridge-disabled") | .dimensions[$dimension]' \
        <<<"$observations_json")" || return 1
      baseline_requests="$(jq -er \
        '.[] | select(.cell == "bridge-disabled") | .successful_requests' \
        <<<"$observations_json")" || return 1
      candidate_delta="$(jq -er --arg cell "$cell" --arg dimension "$dimension" \
        '.[] | select(.cell == $cell) | .dimensions[$dimension]' \
        <<<"$observations_json")" || return 1
      candidate_requests="$(jq -er --arg cell "$cell" \
        '.[] | select(.cell == $cell) | .successful_requests' \
        <<<"$observations_json")" || return 1
      candidate_scaled="$(decimal_multiply "$candidate_delta" "$baseline_requests")" || return 1
      candidate_scaled="$(decimal_multiply "$candidate_scaled" 100)" || return 1
      maximum_scaled="$(decimal_multiply "$baseline_delta" "$candidate_requests")" || return 1
      maximum_scaled="$(decimal_multiply "$maximum_scaled" 110)" || return 1
      if decimal_less_than_or_equal "$candidate_scaled" "$maximum_scaled"; then
        result=passed
      else
        result=failed
      fi
      comparison="$(jq -cn --arg cell "$cell" --arg dimension "$dimension" \
        --arg candidate_scaled "$candidate_scaled" --arg maximum_scaled "$maximum_scaled" \
        --arg result "$result" --argjson baseline_delta "$baseline_delta" \
        --argjson baseline_requests "$baseline_requests" \
        --argjson candidate_delta "$candidate_delta" \
        --argjson candidate_requests "$candidate_requests" '{
          cell: $cell, dimension: $dimension,
          baseline: {cpu_usage_usec: $baseline_delta, successful_requests: $baseline_requests},
          candidate: {cpu_usage_usec: $candidate_delta, successful_requests: $candidate_requests},
          exact_cross_products: {
            candidate_cpu_times_baseline_requests_times_100: $candidate_scaled,
            baseline_cpu_times_candidate_requests_times_110: $maximum_scaled
          },
          maximum_regression_percent: 10,
          result: $result
        }')" || return 1
      comparisons+=("$comparison")
    done
  done
  comparisons_json="$(printf '%s\n' "${comparisons[@]}" | jq -s .)" || return 1
  printf '%s\n%s' "$observations_json" "$comparisons_json" | jq -cs '
    if length != 2 then error("expected CPU observations and comparisons")
    else . end |
    .[0] as $observations |
    .[1] as $comparisons |
    {
      status: "complete",
      result: (if all($comparisons[]; .result == "passed") then "passed" else "failed" end),
      baseline_cell: "bridge-disabled",
      comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
      dimensions: ["obi", "java_backend", "combined"],
      maximum_regression_percent: 10,
      formula: "candidate_cpu_usage_usec/candidate_successes <= baseline_cpu_usage_usec/baseline_successes * 1.10",
      arithmetic: "exact_unsigned_decimal_cross_multiplication",
      observations: $observations,
      comparisons: $comparisons,
      excluded_cells: {
        uninstrumented: "no_official_agent",
        getsockopt_helper_idle: "direct_java_workload_is_not_comparable_to_the_apache_baseline"
      },
      primary_cgroupsockopt_program_cpu: "not_collected"
    }'
}

application_resource_gates() (
  local -r root="${1:-$OUTPUT_DIR}"
  local -r held_variance_value="${2:-}"
  local cell=""
  local cell_dir=""
  local service=""
  local before_bundle="" baseline_bundle="" end_bundle="" after_load_bundle=""
  local recovery_01_bundle="" recovery_02_bundle="" schedule_value=""
  local recovery_01_boundary="" recovery_02_boundary=""
  local midpoint_01_bundle="" midpoint_02_bundle="" midpoint_03_bundle=""
  local midpoint_04_bundle="" midpoint_05_bundle=""
  local service_names=""
  local snapshot_stream=""
  local successful_requests=""
  local observation=""
  local process_observations_json=""
  local cpu_observations_json=""
  local process_gate=""
  local cpu_gate=""
  local -a services=()
  local -a snapshot_values=()
  local -a process_observations=()
  local -a cpu_observations=()

  [[ -d "$root" && ! -L "$root" && "$REPETITIONS" == 5 ]] || return 1
  for cell in "${CORE_CELLS[@]}"; do
    cell_spec "$cell" || return 1
    cell_dir="$root/cells/$cell"
    before_bundle="$(validated_resource_cgroup_boundary_bundle \
      "$cell_dir/resources-before" "$cell" before)" || return 1
    validate_cpu_measurement_boundary "$cell_dir/cpu-measurement-baseline" \
      "$cell" cpu_measurement_baseline baseline_bundle || return 1
    validate_cpu_measurement_boundary "$cell_dir/cpu-measurement-end" \
      "$cell" cpu_measurement_end end_bundle || return 1
    after_load_bundle="$(validated_resource_cgroup_boundary_bundle \
      "$cell_dir/resources-after-load" "$cell" after)" || return 1
    recovery_01_bundle="$(validated_resource_cgroup_boundary_bundle \
      "$cell_dir/resources-idle-recovery-01" "$cell" idle_recovery_01)" || return 1
    recovery_02_bundle="$(validated_resource_cgroup_boundary_bundle \
      "$cell_dir/resources-idle-recovery-02" "$cell" idle_recovery_02)" || return 1
    schedule_value="$(bounded_duplicate_free_json_value \
      "$cell_dir/recovery-schedule.json" "$MAX_RECOVERY_SCHEDULE_BYTES")" || return 1
    recovery_01_boundary="$(printf '%s' "$recovery_01_bundle" | jq -ce '.boundary')" || return 1
    recovery_02_boundary="$(printf '%s' "$recovery_02_bundle" | jq -ce '.boundary')" || return 1
    validate_recovery_schedule_json_values "$schedule_value" \
      "$recovery_01_boundary" "$recovery_02_boundary" || return 1
    validate_scheduled_midpoint_boundary \
      "$cell_dir/measurements/rep-01-midpoint" "$cell" 1 midpoint_01_bundle || return 1
    validate_scheduled_midpoint_boundary \
      "$cell_dir/measurements/rep-02-midpoint" "$cell" 2 midpoint_02_bundle || return 1
    validate_scheduled_midpoint_boundary \
      "$cell_dir/measurements/rep-03-midpoint" "$cell" 3 midpoint_03_bundle || return 1
    validate_scheduled_midpoint_boundary \
      "$cell_dir/measurements/rep-04-midpoint" "$cell" 4 midpoint_04_bundle || return 1
    validate_scheduled_midpoint_boundary \
      "$cell_dir/measurements/rep-05-midpoint" "$cell" 5 midpoint_05_bundle || return 1
    service_names="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
      "$before_bundle" "$baseline_bundle" "$end_bundle" "$after_load_bundle" \
      "$recovery_01_bundle" "$recovery_02_bundle" "$midpoint_01_bundle" \
      "$midpoint_02_bundle" "$midpoint_03_bundle" "$midpoint_04_bundle" \
      "$midpoint_05_bundle" | jq -ers '
        if length != 11 then error("application resource boundary roster length")
        else .[0].services as $services |
          if any(.[1:][]; .services != $services)
          then error("application resource boundary service roster drift")
          else $services | join(" ") end
        end
      ')" || return 1
    read -r -a services <<<"$service_names" || return 1
    ((${#services[@]} >= 1 && ${#services[@]} <= 2)) || return 1
    for service in "${services[@]}"; do
      snapshot_stream="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
        "$before_bundle" "$baseline_bundle" "$end_bundle" "$after_load_bundle" \
        "$recovery_01_bundle" "$recovery_02_bundle" "$midpoint_01_bundle" \
        "$midpoint_02_bundle" "$midpoint_03_bundle" "$midpoint_04_bundle" \
        "$midpoint_05_bundle" | jq -ces --arg service "$service" '
          if length != 11 or any(.[]; .snapshots[$service] == null)
          then error("missing held service snapshot")
          else .[].snapshots[$service] end
        ')" || return 1
      mapfile -t snapshot_values <<<"$snapshot_stream"
      ((${#snapshot_values[@]} == 11)) || return 1
      observation="$(process_tree_resource_observation_values \
        "$cell" "$service" \
        "${snapshot_values[0]}" "${snapshot_values[1]}" "${snapshot_values[2]}" \
        "${snapshot_values[3]}" "${snapshot_values[4]}" "${snapshot_values[5]}" \
        "$schedule_value" "${snapshot_values[6]}" "${snapshot_values[7]}" \
        "${snapshot_values[8]}" "${snapshot_values[9]}" \
        "${snapshot_values[10]}")" || return 1
      process_observations+=("$observation")
      case "$cell" in
        bridge-disabled|getsockopt-hit|unix-hit|getsockopt-w3c)
          if [[ -z "$successful_requests" ]]; then
            if [[ -n "$held_variance_value" ]]; then
              successful_requests="$(printf '%s' "$held_variance_value" | jq -er \
                --arg cell "$cell" '
                  [.cells[] | select(.cell == $cell) | .samples[].successful_requests] as $counts |
                  if ($counts | length) == 5 and all($counts[];
                    type == "number" and isfinite and floor == . and . > 0)
                  then ($counts | add) else error("missing held request denominator") end
                ')" || return 1
              successful_requests="$(normalize_decimal "$successful_requests" \
                "$MAX_SUSTAINED_WORKLOAD_SUCCESSFUL_REQUESTS" false)" || return 1
            else
              successful_requests="$(measurement_successful_request_total "$cell_dir")" || return 1
            fi
          fi
          observation="$(cpu_service_measurement_observation_values \
            "$root" "$cell" "$service" "${snapshot_values[1]}" \
            "${snapshot_values[2]}" "$successful_requests")" || return 1
          cpu_observations+=("$observation")
          ;;
      esac
    done
    successful_requests=""
  done
  process_observations_json="$(printf '%s\n' "${process_observations[@]}" | jq -s .)" || return 1
  cpu_observations_json="$(printf '%s\n' "${cpu_observations[@]}" | jq -s .)" || return 1
  process_gate="$(process_tree_resource_gate "$root" "$process_observations_json")" || return 1
  cpu_gate="$(application_cpu_gate "$root" "$cpu_observations_json")" || return 1
  printf '%s\n%s' "$process_gate" "$cpu_gate" | jq -cs '
    if length != 2 then error("expected process-tree and CPU gates")
    else {process_tree: .[0], application_cpu: .[1]} end
  '
)

sampled_allocation_observation() (
  local -r root="$1"
  local -r cell="$2"
  local -r supplied_variance_value="${3:-}"
  local -r cell_dir="$root/cells/$cell"
  local evidence_sha256=""
  local receipt_sha256=""
  local receipt_evidence_sha256=""
  local tree_manifest_sha256=""
  local sample_records=""
  local sampled_weight_bytes=""
  local successful_requests=""
  local java_bundle=""
  local variance_value="$supplied_variance_value"

  unavailable_observation() {
    jq -cn \
      --arg cell "$cell" \
      --arg source "cells/$cell/java-measurement/evidence.json" \
      --arg publication_receipt \
        "cells/$cell/java-measurement-publication.json" '
        {
          cell: $cell,
          status: "not_available",
          reason: "sealed_java_measurement_evidence_unavailable_or_invalid",
          source: $source,
          publication_receipt: $publication_receipt
        }
      '
  }

  if ! validate_published_java_measurement "$cell_dir" java_bundle >/dev/null 2>&1; then
    unavailable_observation
    return 0
  fi
  read -r evidence_sha256 receipt_sha256 receipt_evidence_sha256 \
    tree_manifest_sha256 < <(printf '%s' "$java_bundle" | jq -er '
      [.evidence_sha256, .receipt_sha256, .receipt.evidence_sha256,
        .tree_manifest_sha256] | @tsv
    ') || return 1
  read -r sample_records sampled_weight_bytes < <(printf '%s' "$java_bundle" | jq -er \
    --arg cell "$cell" '
      .evidence as $evidence |
      if ($evidence |
        .status == "complete" and .acceptance_evidence == false and
        .cell == $cell and .jfr.status == "available" and
        .jfr.whole_window_retention_attested == false and
        .interpretation.allocation_sample_weight_is_not_an_exact_allocation_count == true and
        (.jfr.allocation_sample | (keys) == ["records", "weight_bytes"] and
          (.records | type == "number" and isfinite and floor == . and . >= 0) and
          (.weight_bytes | type == "number" and isfinite and floor == . and . >= 0) and
          ((.records == 0 and .weight_bytes == 0) or
            (.records > 0 and .weight_bytes > 0))))
      then $evidence.jfr.allocation_sample | [.records, .weight_bytes] | @tsv
      else empty end
    ') || return 1
  if [[ -z "$variance_value" ]]; then
    validate_variance_summary_schema "$root/variance.json" variance_value || return 1
  fi
  successful_requests="$(printf '%s' "$variance_value" | jq -ser --arg cell "$cell" '
    if length == 1 then
      [.[0].cells[] | select(.cell == $cell) | .samples[].successful_requests] as $values |
      if ($values | length) == 5 and
        all($values[]; type == "number" and isfinite and floor == . and . > 0)
      then ($values | add) else empty end
    else empty end
  ')" || return 1
  sample_records="$(normalize_decimal \
    "$sample_records" "$MAX_JFR_RECORDS" true)" || return 1
  sampled_weight_bytes="$(normalize_decimal \
    "$sampled_weight_bytes" "$MAX_SEED" true)" || return 1
  successful_requests="$(normalize_decimal \
    "$successful_requests" "$MAX_SUSTAINED_WORKLOAD_SUCCESSFUL_REQUESTS" false)" || return 1
  [[ "$evidence_sha256" =~ ^[0-9a-f]{64}$ &&
    "$receipt_sha256" =~ ^[0-9a-f]{64}$ &&
    "$receipt_evidence_sha256" == "$evidence_sha256" &&
    "$tree_manifest_sha256" =~ ^[0-9a-f]{64}$ &&
    "$sample_records" =~ ^[0-9]+$ && "$sampled_weight_bytes" =~ ^[0-9]+$ &&
    "$successful_requests" =~ ^[1-9][0-9]*$ ]] || return 1
  jq -cn \
    --arg cell "$cell" \
    --arg source "cells/$cell/java-measurement/evidence.json" \
    --arg publication_receipt "cells/$cell/java-measurement-publication.json" \
    --arg successful_request_source \
      "cells/$cell/measurements/rep-*.json" \
    --arg evidence_sha256 "$evidence_sha256" \
    --arg tree_manifest_sha256 "$tree_manifest_sha256" \
    --argjson sample_records "$sample_records" \
    --argjson sampled_weight_bytes "$sampled_weight_bytes" \
    --argjson successful_requests "$successful_requests" '
      {
        cell: $cell,
        status: "complete",
        source: $source,
        publication_receipt: $publication_receipt,
        successful_request_source: $successful_request_source,
        evidence_sha256: $evidence_sha256,
        tree_manifest_sha256: $tree_manifest_sha256,
        sampled_allocation_records: $sample_records,
        sampled_allocation_weight_bytes: $sampled_weight_bytes,
        successful_requests: $successful_requests,
        sampled_allocation_weight_bytes_per_successful_request:
          ($sampled_weight_bytes / $successful_requests)
      }
    '
)

sampled_allocation_gate() {
  local -r root="${1:-$OUTPUT_DIR}"
  local -r held_variance_value="${2:-}"
  local cell=""
  local observation=""
  local observations_json=""
  local -a observations=()
  local -a selected_cells=(bridge-disabled "${SAMPLED_ALLOCATION_COMPARISON_CELLS[@]}")

  for cell in "${selected_cells[@]}"; do
    observation="$(sampled_allocation_observation \
      "$root" "$cell" "$held_variance_value")" || return 1
    observations+=("$observation")
  done
  observations_json="$(printf '%s\n' "${observations[@]}" | jq -s .)" || return 1
  jq -cn \
    --argjson observations "$observations_json" \
    --argjson maximum_regression_percent \
      "$MAX_SAMPLED_ALLOCATION_REGRESSION_PERCENT" \
    --argjson minimum_allowance_bytes_per_successful_request \
      "$MIN_SAMPLED_ALLOCATION_ALLOWANCE_BYTES_PER_REQUEST" '
      def maximum($left; $right): if $left >= $right then $left else $right end;
      (["getsockopt-hit", "unix-hit", "getsockopt-w3c"]) as $comparison_cells |
      ($observations | map(select(.cell == "bridge-disabled"))) as $baselines |
      ($observations | all(.status == "complete")) as $all_complete |
      if $all_complete and ($baselines | length) == 1 then
        $baselines[0] as $baseline_observation |
        $baseline_observation.sampled_allocation_weight_bytes_per_successful_request as $baseline_rate |
        ([
          $comparison_cells[] as $cell |
          ($observations | map(select(.cell == $cell))) as $matches |
          if ($matches | length) != 1 then
            error("sampled allocation comparison cell is missing or duplicated")
          else
            $matches[0] as $candidate |
            ($baseline_rate * $maximum_regression_percent / 100) as $percentage_allowance |
            maximum(
              $percentage_allowance;
              $minimum_allowance_bytes_per_successful_request
            ) as $allowed_regression |
            (maximum(
              0;
              ($candidate.sampled_allocation_weight_bytes_per_successful_request -
                $baseline_rate)
            )) as $observed_regression |
            {
              cell: $cell,
              baseline_sampled_allocation_weight_bytes_per_successful_request:
                $baseline_rate,
              candidate_sampled_allocation_weight_bytes_per_successful_request:
                $candidate.sampled_allocation_weight_bytes_per_successful_request,
              observed_regression_bytes_per_successful_request: $observed_regression,
              percentage_allowance_bytes_per_successful_request: $percentage_allowance,
              minimum_allowance_bytes_per_successful_request:
                $minimum_allowance_bytes_per_successful_request,
              allowed_regression_bytes_per_successful_request: $allowed_regression,
              maximum_candidate_bytes_per_successful_request:
                ($baseline_rate + $allowed_regression),
              result: (
                if $observed_regression <= $allowed_regression
                then "passed" else "failed" end
              )
            }
          end
        ]) as $comparisons |
        {
          status: "complete",
          result: (if all($comparisons[]; .result == "passed") then "passed" else "failed" end),
          classification: "exploratory_sampled_indicator_not_exact_allocation",
          acceptance_evidence: false,
          exact_allocation: false,
          metric: "sampled_allocation_weight_bytes_per_successful_request",
          measurement_window:
            "one_sealed_bounded_jfr_window_across_exactly_five_repetitions",
          baseline_cell: "bridge-disabled",
          comparison_cells: $comparison_cells,
          regression_allowance:
            "max(baseline_bytes_per_successful_request*percent/100,minimum_bytes_per_successful_request)",
          maximum_regression_percent: $maximum_regression_percent,
          minimum_allowance_bytes_per_successful_request:
            $minimum_allowance_bytes_per_successful_request,
          observations: $observations,
          baseline: {
            cell: "bridge-disabled",
            sampled_allocation_records:
              $baseline_observation.sampled_allocation_records,
            sampled_allocation_weight_bytes:
              $baseline_observation.sampled_allocation_weight_bytes,
            successful_requests: $baseline_observation.successful_requests,
            sampled_allocation_weight_bytes_per_successful_request: $baseline_rate
          },
          comparisons: $comparisons,
          excluded_cells: {
            uninstrumented: "no_official_agent",
            getsockopt_helper_idle:
              "direct_java_workload_is_not_comparable_to_the_apache_baseline"
          },
          interpretation: {
            sampled_weight_is_not_exact_allocation: true,
            bounded_recording_may_retain_only_a_tail: true,
            independent_cell_recordings_may_have_zero_or_lower_sampled_weight: true,
            production_slo_evidence: false,
            issue_acceptance_evidence: false
          }
        }
      else
        {
          status: "partial",
          result: "not_evaluated",
          classification: "exploratory_sampled_indicator_not_exact_allocation",
          acceptance_evidence: false,
          exact_allocation: false,
          metric: "sampled_allocation_weight_bytes_per_successful_request",
          measurement_window:
            "one_sealed_bounded_jfr_window_across_exactly_five_repetitions",
          baseline_cell: "bridge-disabled",
          comparison_cells: $comparison_cells,
          regression_allowance:
            "max(baseline_bytes_per_successful_request*percent/100,minimum_bytes_per_successful_request)",
          maximum_regression_percent: $maximum_regression_percent,
          minimum_allowance_bytes_per_successful_request:
            $minimum_allowance_bytes_per_successful_request,
          observations: $observations,
          baseline: null,
          comparisons: [],
          excluded_cells: {
            uninstrumented: "no_official_agent",
            getsockopt_helper_idle:
              "direct_java_workload_is_not_comparable_to_the_apache_baseline"
          },
          interpretation: {
            sampled_weight_is_not_exact_allocation: true,
            bounded_recording_may_retain_only_a_tail: true,
            independent_cell_recordings_may_have_zero_or_lower_sampled_weight: true,
            production_slo_evidence: false,
            issue_acceptance_evidence: false
          }
        }
      end
    '
}

validate_poc_gate_shape_json_value() {
  local -r poc_gate_value="$1"

  printf '%s' "$poc_gate_value" | jq -se \
    --argjson required_repetitions "$REQUIRED_REPETITIONS" \
    --argjson maximum_regression "$MAX_PERFORMANCE_REGRESSION_PERCENT" \
    --argjson maximum_population_cv "$MAX_POPULATION_CV_PERCENT" \
    --argjson maximum_sampled_allocation_regression \
      "$MAX_SAMPLED_ALLOCATION_REGRESSION_PERCENT" \
    --argjson minimum_sampled_allocation_allowance \
      "$MIN_SAMPLED_ALLOCATION_ALLOWANCE_BYTES_PER_REQUEST" \
    --argjson process_tree_fd_absolute_max "$PROCESS_TREE_FD_ABSOLUTE_MAX" \
    --argjson process_tree_task_absolute_max "$PROCESS_TREE_TASK_ABSOLUTE_MAX" \
    --argjson process_tree_rss_bytes_absolute_max "$PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX" \
    --argjson process_tree_fd_recovery_delta_max "$PROCESS_TREE_FD_RECOVERY_DELTA_MAX" \
    --argjson process_tree_task_recovery_delta_max "$PROCESS_TREE_TASK_RECOVERY_DELTA_MAX" \
    --argjson process_tree_rss_bytes_recovery_delta_max \
      "$PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX" '
      def nonnegative_integer:
        type == "number" and isfinite and floor == . and . >= 0;
      def positive_integer: nonnegative_integer and . > 0;
      def finite_nonnegative: type == "number" and isfinite and . >= 0;
      def population_metric_is_exact:
        ((keys | sort) == [
          "coefficient_of_variation_percent",
          "maximum_coefficient_of_variation_percent", "mean",
          "population_standard_deviation", "population_variance", "result",
          "sample_count", "squared_deviation_sum", "sum"
        ]) and
        .sample_count == $required_repetitions and
        (.sum | type == "number" and isfinite and . > 0) and
        (.mean | type == "number" and isfinite and . > 0) and
        (.squared_deviation_sum | finite_nonnegative) and
        (.population_variance | finite_nonnegative) and
        (.population_standard_deviation | finite_nonnegative) and
        (.coefficient_of_variation_percent | finite_nonnegative) and
        .maximum_coefficient_of_variation_percent == $maximum_population_cv and
        .result == (
          if .coefficient_of_variation_percent <=
            .maximum_coefficient_of_variation_percent
          then "passed" else "failed" end
        );
      def sampled_allocation_observation_is_exact:
        (.cell | type == "string" and length > 0) and
        .source == ("cells/" + .cell + "/java-measurement/evidence.json") and
        .publication_receipt ==
          ("cells/" + .cell + "/java-measurement-publication.json") and
        if .status == "complete" then
          ((keys | sort) == [
            "cell", "evidence_sha256", "publication_receipt",
            "sampled_allocation_records", "sampled_allocation_weight_bytes",
            "sampled_allocation_weight_bytes_per_successful_request", "source",
            "status", "successful_request_source", "successful_requests",
            "tree_manifest_sha256"
          ]) and
          .successful_request_source ==
            ("cells/" + .cell + "/measurements/rep-*.json") and
          (.evidence_sha256 | test("^[0-9a-f]{64}$")) and
          (.tree_manifest_sha256 | test("^[0-9a-f]{64}$")) and
          (.sampled_allocation_records | nonnegative_integer) and
          (.sampled_allocation_weight_bytes | nonnegative_integer) and
          (((.sampled_allocation_records == 0) and
            (.sampled_allocation_weight_bytes == 0)) or
           ((.sampled_allocation_records > 0) and
            (.sampled_allocation_weight_bytes > 0))) and
          (.successful_requests | positive_integer) and
          (.sampled_allocation_weight_bytes_per_successful_request |
            finite_nonnegative)
        else
          ((keys | sort) == [
            "cell", "publication_receipt", "reason", "source", "status"
          ]) and
          .status == "not_available" and
          .reason == "sealed_java_measurement_evidence_unavailable_or_invalid"
        end;
      def sampled_allocation_is_exact:
        ((keys | sort) == [
          "acceptance_evidence", "baseline", "baseline_cell", "classification",
          "comparison_cells", "comparisons", "exact_allocation", "excluded_cells",
          "interpretation", "maximum_regression_percent", "measurement_window",
          "metric", "minimum_allowance_bytes_per_successful_request", "observations",
          "regression_allowance", "result", "status"
        ]) and
        .classification == "exploratory_sampled_indicator_not_exact_allocation" and
        .acceptance_evidence == false and .exact_allocation == false and
        .metric == "sampled_allocation_weight_bytes_per_successful_request" and
        .measurement_window ==
          "one_sealed_bounded_jfr_window_across_exactly_five_repetitions" and
        .baseline_cell == "bridge-disabled" and
        .comparison_cells == ["getsockopt-hit", "unix-hit", "getsockopt-w3c"] and
        .regression_allowance ==
          "max(baseline_bytes_per_successful_request*percent/100,minimum_bytes_per_successful_request)" and
        .maximum_regression_percent == $maximum_sampled_allocation_regression and
        .minimum_allowance_bytes_per_successful_request ==
          $minimum_sampled_allocation_allowance and
        .excluded_cells == {
          uninstrumented: "no_official_agent",
          getsockopt_helper_idle:
            "direct_java_workload_is_not_comparable_to_the_apache_baseline"
        } and
        .interpretation == {
          sampled_weight_is_not_exact_allocation: true,
          bounded_recording_may_retain_only_a_tail: true,
          independent_cell_recordings_may_have_zero_or_lower_sampled_weight: true,
          production_slo_evidence: false,
          issue_acceptance_evidence: false
        } and
        ([.observations[].cell] == [
          "bridge-disabled", "getsockopt-hit", "unix-hit", "getsockopt-w3c"
        ]) and
        all(.observations[]; sampled_allocation_observation_is_exact) and
        if .status == "complete" then
          .result == (if all(.comparisons[]; .result == "passed") then "passed" else "failed" end) and
          (.baseline |
            ((keys | sort) == [
              "cell", "sampled_allocation_records", "sampled_allocation_weight_bytes",
              "sampled_allocation_weight_bytes_per_successful_request",
              "successful_requests"
            ]) and .cell == "bridge-disabled" and
            (.sampled_allocation_records | nonnegative_integer) and
            (.sampled_allocation_weight_bytes | nonnegative_integer) and
            (.successful_requests | positive_integer) and
            (.sampled_allocation_weight_bytes_per_successful_request |
              finite_nonnegative)) and
          ([.comparisons[].cell] == .comparison_cells) and
          all(.comparisons[];
            ((keys | sort) == [
              "allowed_regression_bytes_per_successful_request",
              "baseline_sampled_allocation_weight_bytes_per_successful_request",
              "candidate_sampled_allocation_weight_bytes_per_successful_request", "cell",
              "maximum_candidate_bytes_per_successful_request",
              "minimum_allowance_bytes_per_successful_request",
              "observed_regression_bytes_per_successful_request",
              "percentage_allowance_bytes_per_successful_request", "result"
            ]) and
            all([
              .allowed_regression_bytes_per_successful_request,
              .baseline_sampled_allocation_weight_bytes_per_successful_request,
              .candidate_sampled_allocation_weight_bytes_per_successful_request,
              .maximum_candidate_bytes_per_successful_request,
              .minimum_allowance_bytes_per_successful_request,
              .observed_regression_bytes_per_successful_request,
              .percentage_allowance_bytes_per_successful_request
            ][]; finite_nonnegative) and
            .minimum_allowance_bytes_per_successful_request ==
              $minimum_sampled_allocation_allowance and
            (.result == "passed" or .result == "failed"))
        else
          .status == "partial" and .result == "not_evaluated" and
          .baseline == null and .comparisons == [] and
          any(.observations[]; .status == "not_available")
        end;
      def process_sources_are_exact:
        .sources == {
          before: ("cells/" + .cell + "/resources-before/" + .service + "-proc.txt"),
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery-02/" + .service + "-proc.txt")
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
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery-02/obi-metrics.prom")
        } and
        .ownership_sources == {
          before: ("cells/" + .cell + "/resources-before/obi-bpf-fd-ownership.txt"),
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery-02/obi-bpf-fd-ownership.txt")
        } and
        .process_sources == {
          before: ("cells/" + .cell + "/resources-before/obi-proc.txt"),
          idle_recovery: ("cells/" + .cell + "/resources-idle-recovery-02/obi-proc.txt")
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
        ((keys | sort) == [
          "correctness", "issue_acceptance_complete", "kind", "manifest_binding", "performance",
          "resources", "result", "sampled_allocation", "schema_version", "status",
          "thresholds", "unmeasured_dimensions"
        ]) and
        .schema_version == 3 and
        .kind == "predeclared-java-remote-parent-poc-gate-evaluation" and
        .status == "partial" and
        (.result == "not_evaluated" or .result == "failed") and
        .issue_acceptance_complete == false and
        .manifest_binding == {
          source: "manifest.json", schema_version: 4,
          projection: "predeclared_poc_gates_canonical_json_sha256",
          predeclared_poc_gates_sha256: .manifest_binding.predeclared_poc_gates_sha256
        } and
        (.manifest_binding.predeclared_poc_gates_sha256 | test("^[0-9a-f]{64}$")) and
        (.thresholds |
          .declaration_source == "BENCHMARK.md#predeclared-poc-gates" and
          .correctness_failures_max == 0 and
          .required_repetitions == $required_repetitions and
          .throughput_regression_max_percent == $maximum_regression and
          .p99_latency_regression_max_percent == $maximum_regression and
          .population_cv_max_percent == $maximum_population_cv and
          .sampled_allocation_regression_max_percent ==
            $maximum_sampled_allocation_regression and
          .sampled_allocation_minimum_allowance_bytes_per_successful_request ==
            $minimum_sampled_allocation_allowance and
          .fd_delta_max == 0 and .thread_delta_max == 0 and
          .java_bridge_map_entries_delta_max == 0 and
          .application_cpu_regression_max_percent == 10 and
          .process_tree == {
            absolute: {
              fd_count: $process_tree_fd_absolute_max,
              task_count: $process_tree_task_absolute_max,
              rss_bytes: $process_tree_rss_bytes_absolute_max
            },
            recovery_delta: {
              fd_count: $process_tree_fd_recovery_delta_max,
              task_count: $process_tree_task_recovery_delta_max,
              rss_bytes: $process_tree_rss_bytes_recovery_delta_max
            }
          }) and
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
          (.population_variability |
            ((keys | sort) == [
              "cells", "divisor", "formula",
              "maximum_coefficient_of_variation_percent", "required_repetitions",
              "result", "source", "status"
            ]) and
            .status == "complete" and (.result == "passed" or .result == "failed") and
            .source == "variance.json" and
            .formula == "sqrt(sum((x-mean)^2)/N)/mean*100" and
            .divisor == "population_N" and
            .required_repetitions == $required_repetitions and
            .maximum_coefficient_of_variation_percent == $maximum_population_cv and
            ([.cells[].cell] == [
              "uninstrumented", "bridge-disabled", "getsockopt-hit", "unix-hit",
              "getsockopt-w3c", "getsockopt-helper-idle"
            ]) and
            all(.cells[];
              ((keys | sort) == [
                "cell", "p99_latency_nanos", "result", "throughput_per_second"
              ]) and
              (.throughput_per_second | population_metric_is_exact) and
              (.p99_latency_nanos | population_metric_is_exact) and
              .result == (
                if .throughput_per_second.result == "passed" and
                   .p99_latency_nanos.result == "passed"
                then "passed" else "failed" end
              )) and
            .result == (if all(.cells[]; .result == "passed") then "passed" else "failed" end)) and
          all(.comparisons[];
            .result == "passed" or .result == "failed") and
          .result == (
            if all(.comparisons[]; .result == "passed") and
              .population_variability.result == "passed"
            then "passed" else "failed" end
          )) and
        (.sampled_allocation | sampled_allocation_is_exact) and
        (.resources |
          (.status == "complete" or .status == "partial") and
          .required_samples == ["before", "idle_recovery_02"] and
          .unavailable_samples_fail_closed == true and
          (.process_tree |
            ((keys | sort) == ["boundaries", "conservative_sampling", "observations",
              "recovery", "result", "scope", "status", "thresholds"]) and
            .scope == "complete_leaf_cgroup_v2_process_tree" and
            .thresholds == {
              absolute: {
                fd_count: $process_tree_fd_absolute_max,
                task_count: $process_tree_task_absolute_max,
                rss_bytes: $process_tree_rss_bytes_absolute_max
              },
              recovery_delta: {
                fd_count: $process_tree_fd_recovery_delta_max,
                task_count: $process_tree_task_recovery_delta_max,
                rss_bytes: $process_tree_rss_bytes_recovery_delta_max
              }
            } and
            .boundaries == ["before", "cpu_measurement_baseline", "rep_01_midpoint",
              "rep_02_midpoint", "rep_03_midpoint", "rep_04_midpoint",
              "rep_05_midpoint", "cpu_measurement_end", "after_load",
              "idle_recovery_01", "idle_recovery_02"] and
            .recovery == {interval_seconds: 30, required_consecutive_samples: 2} and
            .conservative_sampling == {
              absolute_value: "two_pass_envelope_max",
              recovery_delta: "recovery_envelope_max_minus_before_envelope_min"
            } and
            (.observations | type == "array" and length == 11) and
            (.status == "complete" or .status == "partial") and
            (.result == "passed" or .result == "failed" or .result == "not_evaluated")) and
          (.application_cpu |
            .baseline_cell == "bridge-disabled" and
            .comparison_cells == ["getsockopt-hit", "unix-hit", "getsockopt-w3c"] and
            .dimensions == ["obi", "java_backend", "combined"] and
            .maximum_regression_percent == 10 and
            .arithmetic == "exact_unsigned_decimal_cross_multiplication" and
            .primary_cgroupsockopt_program_cpu == "not_collected" and
            (.status == "complete" or .status == "partial") and
            (.result == "passed" or .result == "failed" or .result == "not_evaluated") and
            if .status == "complete" then
              (.observations | length == 4) and (.comparisons | length == 9)
            else .comparisons == [] end) and
          (.process_dimension |
            if .status == "complete"
            then (.result == "passed" or .result == "failed")
            else .status == "partial" and .result == "not_evaluated"
            end) and
          .result == (
            if .process_dimension.result == "failed" or .map_dimension.result == "failed" or
               .process_tree.result == "failed" or .application_cpu.result == "failed"
            then "failed"
            elif .process_dimension.result == "passed" and .map_dimension.result == "passed" and
                 .process_tree.result == "passed" and .application_cpu.result == "passed"
            then "passed" else "not_evaluated" end
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
          exact_java_allocation:
            "sampled_jfr_weight_evaluated_as_exploratory_indicator_only_exact_allocation_not_collected",
          nmt_native_and_direct_memory:
            "bounded_indicators_retained_not_evaluated_as_acceptance_gate",
          primary_cgroupsockopt_program_cpu: "not_collected",
          bpf_lock_contention: "not_collected"
        } and
        .result == (
          if .correctness.result == "failed" or
             .performance.result == "failed" or
             .sampled_allocation.result == "failed" or
             .resources.result == "failed"
          then "failed" else "not_evaluated" end
        )
      )
    ' >/dev/null
}

validate_poc_gate_shape() {
  local -r artifact="$1"
  local poc_gate_value=""

  poc_gate_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_POC_GATE_BYTES")" || return 1
  validate_poc_gate_shape_json_value "$poc_gate_value"
}

validate_supported_poc_dimensions_json_value() {
  local -r poc_gate_value="$1"

  validate_poc_gate_shape_json_value "$poc_gate_value" || return 1
  printf '%s' "$poc_gate_value" | jq -se '
    length == 1 and
    (.[0] |
      .status == "partial" and .result == "not_evaluated" and
      (.correctness |
        .status == "complete" and .result == "passed" and
        .observed_failures == 0
      ) and
      .performance.status == "complete" and .performance.result == "passed" and
      (.performance.population_variability |
        .status == "complete" and .result == "passed" and
          all(.cells[];
            .result == "passed" and
            .throughput_per_second.result == "passed" and
            .p99_latency_nanos.result == "passed")
      ) and
      .sampled_allocation.status == "complete" and
      .sampled_allocation.result == "passed" and
      all(.sampled_allocation.observations[]; .status == "complete") and
      all(.sampled_allocation.comparisons[]; .result == "passed") and
      .resources.status == "complete" and .resources.result == "passed" and
      .resources.process_tree.status == "complete" and
      .resources.process_tree.result == "passed" and
      all(.resources.process_tree.observations[];
        .status == "complete" and .result == "passed") and
      .resources.application_cpu.status == "complete" and
      .resources.application_cpu.result == "passed" and
      all(.resources.application_cpu.comparisons[]; .result == "passed") and
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
  ' >/dev/null
}

validate_supported_poc_dimensions_pass() {
  local -r artifact="$1"
  local poc_gate_value=""

  poc_gate_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_POC_GATE_BYTES")" || return 1
  validate_poc_gate_json_value_against_root \
    "$poc_gate_value" "${artifact%/*}" || return 1
  validate_supported_poc_dimensions_json_value "$poc_gate_value"
}

validated_cell_status_json_value() {
  local -r artifact="$1"
  local -r expected_cell="$2"
  local status_value=""

  status_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_CELL_STATUS_BYTES")" || return 1
  printf '%s' "$status_value" | jq -sce --arg cell "$expected_cell" '
    if length != 1 then error("expected one cell status") else
      .[0] |
      if ((keys | sort) == ["cell", "completed_at", "reason", "status"]) and
        .cell == $cell and
        (.completed_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
        ((.status == "passed" and .reason == null) or
         (.status == "failed" and (.reason | type == "string" and length > 0)))
      then . else error("invalid cell status") end
    end
  '
}

poc_gate_summary_json() {
  local -r root="${1:-$OUTPUT_DIR}"
  local -r supplied_manifest_value="${2:-}"
  local OUTPUT_DIR="$root"
  local cell=""
  local status_file=""
  local statuses_json=""
  local resources_json=""
  local legacy_resources_json=""
  local application_resource_gates_json=""
  local process_tree_json=""
  local application_cpu_json=""
  local sampled_allocation_json=""
  local manifest_file=""
  local manifest_json_value=""
  local variance_json_value=""
  local manifest_predeclared_json=""
  local manifest_predeclared_sha256=""
  local -a statuses=()

  [[ -d "$root" && ! -L "$root" &&
    -f "$root/variance.json" && ! -L "$root/variance.json" &&
    "$REPETITIONS" == "$REQUIRED_REPETITIONS" ]] || return 1
  if [[ -n "$supplied_manifest_value" ]]; then
    validate_manifest_json_value "$supplied_manifest_value" || return 1
    manifest_json_value="$supplied_manifest_value"
  else
    if [[ -f "$root/manifest.json" && ! -L "$root/manifest.json" ]]; then
      manifest_file="$root/manifest.json"
    else
      manifest_file="$root/manifest.in-progress.json"
    fi
    manifest_json_value="$(validated_manifest_json_value \
      "$manifest_file")" || return 1
  fi
  manifest_predeclared_json="$(printf '%s' "$manifest_json_value" | \
    jq -cS '.predeclared_poc_gates')" || return 1
  manifest_predeclared_sha256="$(json_value_sha256 \
    "$manifest_predeclared_json")" || return 1
  [[ "$manifest_predeclared_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  validate_variance_summary_schema \
    "$root/variance.json" variance_json_value || return 1
  printf '%s' "$variance_json_value" | jq -se \
    --argjson repetitions "$REQUIRED_REPETITIONS" '
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
  ' >/dev/null || return 1
  for cell in "${CORE_CELLS[@]}"; do
    status_file="$root/cells/$cell/status.json"
    statuses+=("$(validated_cell_status_json_value \
      "$status_file" "$cell")") || return 1
  done
  statuses_json="$(printf '%s\n' "${statuses[@]}" | jq -s .)" || return 1
  legacy_resources_json="$(resource_growth_gate)" || return 1
  application_resource_gates_json="$(application_resource_gates \
    "$root" "$variance_json_value")" || return 1
  process_tree_json="$(printf '%s' "$application_resource_gates_json" | \
    jq -ce '.process_tree')" || return 1
  application_cpu_json="$(printf '%s' "$application_resource_gates_json" | \
    jq -ce '.application_cpu')" || return 1
  resources_json="$(printf '%s\n%s\n%s' "$legacy_resources_json" \
    "$process_tree_json" "$application_cpu_json" | jq -cs '
      if length != 3 then error("expected legacy, process-tree, and CPU resources")
      else . end |
      .[0] as $legacy |
      .[1] as $process_tree |
      .[2] as $application_cpu |
      $legacy + {
        process_tree: $process_tree,
        application_cpu: $application_cpu
      } |
      .status = (
        if .process_dimension.status == "complete" and
           .map_dimension.status == "complete" and
           .process_tree.status == "complete" and
           .application_cpu.status == "complete"
        then "complete" else "partial" end
      ) |
      .result = (
        if .process_dimension.result == "failed" or .map_dimension.result == "failed" or
           .process_tree.result == "failed" or .application_cpu.result == "failed"
        then "failed"
        elif .process_dimension.result == "passed" and .map_dimension.result == "passed" and
             .process_tree.result == "passed" and .application_cpu.result == "passed"
        then "passed" else "not_evaluated" end
      )
    ')" || return 1
  sampled_allocation_json="$(sampled_allocation_gate \
    "$root" "$variance_json_value")" || return 1
  printf '%s\n%s\n%s\n%s' "$variance_json_value" "$statuses_json" \
    "$resources_json" "$sampled_allocation_json" | jq -cs \
    --argjson required_repetitions "$REQUIRED_REPETITIONS" \
    --argjson maximum_regression "$MAX_PERFORMANCE_REGRESSION_PERCENT" \
    --argjson maximum_population_cv "$MAX_POPULATION_CV_PERCENT" \
    --argjson process_tree_fd_absolute_max "$PROCESS_TREE_FD_ABSOLUTE_MAX" \
    --argjson process_tree_task_absolute_max "$PROCESS_TREE_TASK_ABSOLUTE_MAX" \
    --argjson process_tree_rss_bytes_absolute_max "$PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX" \
    --argjson process_tree_fd_recovery_delta_max "$PROCESS_TREE_FD_RECOVERY_DELTA_MAX" \
    --argjson process_tree_task_recovery_delta_max "$PROCESS_TREE_TASK_RECOVERY_DELTA_MAX" \
    --argjson process_tree_rss_bytes_recovery_delta_max \
      "$PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX" \
    --arg manifest_predeclared_sha256 "$manifest_predeclared_sha256" '
      def regression_percent($baseline; $candidate; $higher_is_better):
        if $higher_is_better then
          (if $candidate >= $baseline then 0
           else (($baseline - $candidate) * 100 / $baseline) end)
        else
          (if $candidate <= $baseline then 0
           else (($candidate - $baseline) * 100 / $baseline) end)
        end;
      if length != 4 then error("expected held variance, statuses, resources, and allocation")
      else . end |
      .[0] as $variance |
      .[1] as $statuses |
      .[2] as $resources |
      .[3] as $sampled_allocation |
      ($variance.cells | map({key: .cell, value: .}) | from_entries) as $cells |
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
        $variance.cells[] |
        {
          cell: .cell,
          throughput_per_second: (
            .statistics.throughput_per_second.population_variability + {
              maximum_coefficient_of_variation_percent: $maximum_population_cv,
              result: (
                if .statistics.throughput_per_second.population_variability.coefficient_of_variation_percent <=
                  $maximum_population_cv
                then "passed" else "failed" end
              )
            }
          ),
          p99_latency_nanos: (
            .statistics.latency.p99_nanos.population_variability + {
              maximum_coefficient_of_variation_percent: $maximum_population_cv,
              result: (
                if .statistics.latency.p99_nanos.population_variability.coefficient_of_variation_percent <=
                  $maximum_population_cv
                then "passed" else "failed" end
              )
            }
          )
        } |
        .result = (
          if .throughput_per_second.result == "passed" and
             .p99_latency_nanos.result == "passed"
          then "passed" else "failed" end
        )
      ]) as $population_variability_cells |
      ([
        $variance.cells[].samples[].failed_requests,
        ($statuses[] | if .status == "passed" then 0 else 1 end)
      ] | add) as $observed_failures |
      {
        schema_version: 3,
        kind: "predeclared-java-remote-parent-poc-gate-evaluation",
        issue_acceptance_complete: false,
        manifest_binding: {
          source: "manifest.json",
          schema_version: 4,
          projection: "predeclared_poc_gates_canonical_json_sha256",
          predeclared_poc_gates_sha256: $manifest_predeclared_sha256
        },
        thresholds: {
          declaration_source: "BENCHMARK.md#predeclared-poc-gates",
          correctness_failures_max: 0,
          required_repetitions: $required_repetitions,
          throughput_regression_max_percent: $maximum_regression,
          p99_latency_regression_max_percent: $maximum_regression,
          population_cv_max_percent: $maximum_population_cv,
          sampled_allocation_regression_max_percent:
            $sampled_allocation.maximum_regression_percent,
          sampled_allocation_minimum_allowance_bytes_per_successful_request:
            $sampled_allocation.minimum_allowance_bytes_per_successful_request,
          fd_delta_max: 0,
          thread_delta_max: 0,
          java_bridge_map_entries_delta_max: 0,
          process_tree: {
            absolute: {
              fd_count: $process_tree_fd_absolute_max,
              task_count: $process_tree_task_absolute_max,
              rss_bytes: $process_tree_rss_bytes_absolute_max
            },
            recovery_delta: {
              fd_count: $process_tree_fd_recovery_delta_max,
              task_count: $process_tree_task_recovery_delta_max,
              rss_bytes: $process_tree_rss_bytes_recovery_delta_max
            }
          },
          application_cpu_regression_max_percent: 10
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
          result: (
            if all($comparisons[]; .result == "passed") and
              all($population_variability_cells[]; .result == "passed")
            then "passed" else "failed" end
          ),
          source: "variance.json",
          required_repetitions: $required_repetitions,
          baseline: {
            cell: "bridge-disabled",
            throughput_per_second_median: $baseline.statistics.throughput_per_second.median,
            p99_latency_nanos_median: $baseline.statistics.latency.p99_nanos.median
          },
          comparisons: $comparisons,
          population_variability: {
            status: "complete",
            result: (
              if all($population_variability_cells[]; .result == "passed")
              then "passed" else "failed" end
            ),
            source: "variance.json",
            formula: "sqrt(sum((x-mean)^2)/N)/mean*100",
            divisor: "population_N",
            required_repetitions: $required_repetitions,
            maximum_coefficient_of_variation_percent: $maximum_population_cv,
            cells: $population_variability_cells
          },
          excluded_cells: {
            uninstrumented: "no_official_agent",
            getsockopt_helper_idle: "direct_java_workload_is_not_comparable_to_the_apache_baseline"
          }
        },
        sampled_allocation: $sampled_allocation,
        resources: $resources,
        unmeasured_dimensions: {
          exact_java_allocation:
            "sampled_jfr_weight_evaluated_as_exploratory_indicator_only_exact_allocation_not_collected",
          nmt_native_and_direct_memory:
            "bounded_indicators_retained_not_evaluated_as_acceptance_gate",
          primary_cgroupsockopt_program_cpu: "not_collected",
          bpf_lock_contention: "not_collected"
        }
      } |
      .status = "partial" |
      .result = (
          if .correctness.result == "failed" or
             .performance.result == "failed" or
             .sampled_allocation.result == "failed" or
             .resources.result == "failed"
        then "failed" else "not_evaluated" end
      )
    '
}

bounded_poc_gate_json_value() {
  local -r artifact="$1"

  bounded_duplicate_free_json_value "$artifact" "$MAX_POC_GATE_BYTES"
}

validate_poc_gate_json_value_against_root() {
  local -r poc_gate_value="$1"
  local -r artifact_root="$2"
  local manifest_value="${3:-}"
  local expected_value="${4:-}"
  local manifest_path=""
  local manifest_predeclared=""
  local manifest_predeclared_sha256=""
  local regenerated_value=""

  [[ -d "$artifact_root" && ! -L "$artifact_root" ]] || return 1
  validate_poc_gate_shape_json_value "$poc_gate_value" || return 1
  if [[ -z "$manifest_value" ]]; then
    if [[ -f "$artifact_root/manifest.json" &&
      ! -L "$artifact_root/manifest.json" ]]; then
      manifest_path="$artifact_root/manifest.json"
    else
      manifest_path="$artifact_root/manifest.in-progress.json"
    fi
    manifest_value="$(validated_manifest_json_value "$manifest_path")" || return 1
  else
    validate_manifest_json_value "$manifest_value" || return 1
  fi
  manifest_predeclared="$(printf '%s' "$manifest_value" | \
    jq -ceS '.predeclared_poc_gates')" || return 1
  manifest_predeclared_sha256="$(json_value_sha256 \
    "$manifest_predeclared")" || return 1
  [[ "$(printf '%s' "$poc_gate_value" | \
    jq -er '.manifest_binding.predeclared_poc_gates_sha256')" == \
    "$manifest_predeclared_sha256" ]] || return 1
  if [[ -n "$expected_value" ]]; then
    [[ "$poc_gate_value" == "$expected_value" ]] || return 1
  else
    regenerated_value="$(poc_gate_summary_json \
      "$artifact_root" "$manifest_value")" || return 1
    regenerated_value="$(printf '%s' "$regenerated_value" | jq -ceS .)" || return 1
    [[ "$poc_gate_value" == "$regenerated_value" ]] || return 1
  fi
}

validate_poc_gate_json_value_against_manifest_value() {
  local -r poc_gate_value="$1"
  local -r manifest_value="$2"
  local -r expected_value="${3:-}"
  local manifest_predeclared=""
  local manifest_predeclared_sha256=""

  validate_poc_gate_shape_json_value "$poc_gate_value" || return 1
  validate_manifest_json_value "$manifest_value" || return 1
  manifest_predeclared="$(printf '%s' "$manifest_value" | \
    jq -ceS '.predeclared_poc_gates')" || return 1
  manifest_predeclared_sha256="$(json_value_sha256 \
    "$manifest_predeclared")" || return 1
  [[ "$(printf '%s' "$poc_gate_value" | \
    jq -er '.manifest_binding.predeclared_poc_gates_sha256')" == \
    "$manifest_predeclared_sha256" ]] || return 1
  [[ -z "$expected_value" || "$poc_gate_value" == "$expected_value" ]]
}

validated_poc_gate_json_value() {
  local -r artifact="$1"
  local -r artifact_root="${2:-${artifact%/*}}"
  local poc_gate_value=""

  poc_gate_value="$(bounded_poc_gate_json_value "$artifact")" || return 1
  validate_poc_gate_json_value_against_root \
    "$poc_gate_value" "$artifact_root" || return 1
  printf '%s' "$poc_gate_value"
}

validate_poc_gate_schema() {
  local -r artifact="$1"
  local poc_gate_value=""

  poc_gate_value="$(validated_poc_gate_json_value "$artifact")"
}

write_poc_gate_summary() {
  local poc_gate_value=""
  local manifest_value=""

  [[ "$OUTPUT_READY" == "true" &&
    ! -e "$OUTPUT_DIR/poc-gates.json" &&
    ! -L "$OUTPUT_DIR/poc-gates.json" ]] || return 1
  manifest_value="$(validated_manifest_json_value \
    "$OUTPUT_DIR/manifest.in-progress.json")" || return 1
  poc_gate_value="$(poc_gate_summary_json \
    "$OUTPUT_DIR" "$manifest_value")" || return 1
  poc_gate_value="$(printf '%s' "$poc_gate_value" | jq -ceS .)" || return 1
  validate_poc_gate_json_value_against_root \
    "$poc_gate_value" "$OUTPUT_DIR" "$manifest_value" "$poc_gate_value" || return 1
  POC_GATE_HELD_VALUE="$poc_gate_value"
  POC_GATE_HELD_SIZE="${#poc_gate_value}"
  POC_GATE_HELD_SHA256="$(json_value_sha256 "$poc_gate_value")" || return 1
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
  local status_value=""

  status_value="$(bounded_duplicate_free_json_value \
    "$status_file" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  validate_runner_scenario_status_json_value \
    "$status_value" "$expected_scenario" "$expected_result"
}

validate_runner_scenario_status_json_value() {
  local -r status_value="$1"
  local -r expected_scenario="$2"
  local -r expected_result="$3"

  printf '%s' "$status_value" | jq -se \
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
    ' >/dev/null
}

validate_runner_scenario_measurement() {
  local -r result_file="$1"
  local -r expected_scenario="$2"
  local -r expected_requests="$3"
  local result_value=""

  result_value="$(bounded_duplicate_free_json_value \
    "$result_file" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  validate_runner_scenario_measurement_json_value \
    "$result_value" "$expected_scenario" "$expected_requests"
}

validate_runner_scenario_measurement_json_value() {
  local -r result_value="$1"
  local -r expected_scenario="$2"
  local -r expected_requests="$3"

  printf '%s' "$result_value" | jq -se \
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
    ' >/dev/null
}

diagnostic_delta_value() {
  local -r delta_file="$1"
  local -r wanted_counter="$2"
  local delta_value=""

  capture_bounded_regular_file_value "$delta_file" \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" delta_value || return 1
  diagnostic_delta_value_from_value "$delta_value" "$wanted_counter"
}

diagnostic_delta_value_from_value() {
  local -r delta_value="$1"
  local -r wanted_counter="$2"

  [[ -n "$delta_value" && "$wanted_counter" =~ ^t_[a-z_]+$ ]] || return 1
  printf '%s' "$delta_value" | awk -v wanted="$wanted_counter" \
    -v maximum="$MAX_JAVA_DIAGNOSTIC_COUNTER" '
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
  '
}

java_path_diagnostic_counts() {
  local -r delta_file="$1"
  local delta_value=""

  capture_bounded_regular_file_value "$delta_file" \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" delta_value || return 1
  java_path_diagnostic_counts_from_value "$delta_value"
}

java_path_diagnostic_counts_from_value() {
  local -r delta_value="$1"
  local status=""
  local value=""
  local -a arguments=()
  local -a statuses=(
    unknown valid missing stale unsupported malformed version_mismatch ambiguous
    unauthorized already_consumed timeout overload transport_error disabled
  )

  for status in "${statuses[@]}"; do
    value="$(diagnostic_delta_value_from_value \
      "$delta_value" "t_$status")" || return 1
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
  local metrics_value=""

  [[ "$expected_map_id" =~ ^[1-9][0-9]*$ &&
    "$expected_max_entries" =~ ^[1-9][0-9]*$ &&
    "$expected_map_type" =~ ^[a-z0-9_]+$ ]] || return 1
  capture_bounded_regular_file_value "$metrics_file" \
    "$MAX_OBI_METRICS_SNAPSHOT_BYTES" metrics_value || return 1
  pressure_map_sample_json_from_value "$metrics_value" \
    "$expected_map_id" "$expected_max_entries" "$expected_map_type"
}

pressure_map_sample_json_from_value() {
  local -r metrics_value="$1"
  local -r expected_map_id="$2"
  local -r expected_max_entries="$3"
  local -r expected_map_type="$4"
  local metric_rows=""
  local rows_json=""

  [[ -n "$metrics_value" && "$expected_map_id" =~ ^[1-9][0-9]*$ &&
    "$expected_max_entries" =~ ^[1-9][0-9]*$ &&
    "$expected_map_type" =~ ^[a-z0-9_]+$ ]] || return 1
  metric_rows="$(java_bridge_map_metric_rows_from_value \
    "$metrics_value")" || return 1
  rows_json="$(map_rows_json <<<"$metric_rows")" || return 1
  printf '%s' "$rows_json" | jq -c \
    --argjson map_id "$expected_map_id" \
    --argjson max_entries "$expected_max_entries" --arg map_type "$expected_map_type" '
      . as $rows |
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

pressure_recovery_evidence_json_from_values() {
  local -r prepare_value="$1"
  local -r baseline_value="$2"
  local -r recovered_value="$3"
  local -r sample_1_value="$4"
  local -r sample_2_value="$5"
  local -r recovery_log_value="$6"
  local map_id=""
  local max_entries=""
  local map_type=""
  local baseline_json=""
  local recovered_json=""
  local baseline_entries=""
  local recovered_entries=""
  local sample_json=""
  local sample_entries_json=""
  local attempts=""
  local sample_value=""
  local sample_count=0
  local -a sample_values=("$sample_1_value" "$sample_2_value")
  local -a sample_entries=()

  map_id="$(printf '%s' "$prepare_value" | jq -er '.map_id')" || return 1
  max_entries="$(printf '%s' "$prepare_value" | jq -er '.max_entries')" || return 1
  map_type="$(printf '%s' "$prepare_value" | \
    jq -er '.map_type | ascii_downcase')" || return 1
  map_id="$(normalize_decimal "$map_id" 4294967295 false)" || return 1
  max_entries="$(normalize_decimal \
    "$max_entries" "$PRESSURE_MAP_MAX_SUPPORTED_ENTRIES" false)" || return 1
  [[ "$map_type" =~ ^[a-z0-9_]+$ && -n "$recovery_log_value" ]] || return 1
  baseline_json="$(pressure_map_sample_json_from_value \
    "$baseline_value" "$map_id" "$max_entries" "$map_type")" || return 1
  recovered_json="$(pressure_map_sample_json_from_value \
    "$recovered_value" "$map_id" "$max_entries" "$map_type")" || return 1
  baseline_entries="$(printf '%s' "$baseline_json" | jq -er '.entries')" || return 1
  recovered_entries="$(printf '%s' "$recovered_json" | jq -er '.entries')" || return 1
  baseline_entries="$(normalize_decimal "$baseline_entries" "$max_entries" true)" || return 1
  recovered_entries="$(normalize_decimal "$recovered_entries" "$max_entries" true)" || return 1
  ((baseline_entries == 0 && recovered_entries == 0)) || return 1
  ((${#sample_values[@]} == PRESSURE_RECOVERY_REQUIRED_SAMPLES)) || return 1
  for sample_value in "${sample_values[@]}"; do
    sample_json="$(pressure_map_sample_json_from_value \
      "$sample_value" "$map_id" "$max_entries" "$map_type")" || return 1
    sample_entries+=("$(printf '%s' "$sample_json" | jq -er '.entries')")
    sample_count="$((${#sample_entries[@]} - 1))"
    sample_entries[$sample_count]="$(normalize_decimal \
      "${sample_entries[$sample_count]}" "$max_entries" true)" || return 1
    ((sample_entries[$sample_count] <= baseline_entries)) || return 1
  done
  [[ "$sample_2_value" == "$recovered_value" && "$recovered_entries" == \
    "${sample_entries[$((PRESSURE_RECOVERY_REQUIRED_SAMPLES - 1))]}" ]] || return 1
  attempts="$(printf '%s' "$recovery_log_value" | awk \
    -v baseline="$baseline_entries" \
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
        if (expected_consecutive == required) { terminal_line = NR }
        previous_entries = last_entries
        last_entries = entries
      }
      END {
        if (invalid || NR < required || terminal_line != NR ||
            expected_consecutive != required || previous_entries != first ||
            last_entries != second) exit 1
        print NR
      }
    ')" || return 1
  [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
  sample_entries_json="$(printf '%s\n' "${sample_entries[@]}" | \
    jq -s 'map(tonumber)')" || return 1
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

validate_pressure_control_file() {
  local -r input="$1"
  local -r expected="$2"
  local input_value=""

  capture_bounded_regular_file_value \
    "$input" "$MAX_BOUNDARY_SNAPSHOT_BYTES" input_value || return 1
  validate_pressure_control_value "$input_value" "$expected"
}

validate_pressure_control_value() {
  local -r input_value="$1"
  local -r expected="$2"

  [[ -n "$expected" && "$expected" != *$'\n'* && "$expected" != *$'\r'* &&
    "$input_value" == "$expected"$'\n' ]]
}

validate_pressure_container_inspections() {
  local -r runner_directory="$1"
  local -r artifact="$runner_directory/map-pressure-pressure-container-inspections.json"
  local -r environment_file="$runner_directory/environment.txt"
  local artifact_value=""
  local artifact_identity=""
  local environment_value=""

  capture_bounded_regular_file_value "$artifact" \
    "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" artifact_value \
    artifact_identity || return 1
  capture_bounded_regular_file_value "$environment_file" \
    "$MAX_RUNNER_ENVIRONMENT_BYTES" environment_value || return 1
  validate_pressure_container_inspections_from_values \
    "$artifact_value" "$artifact_identity" "$environment_value"
}

validate_pressure_container_inspections_from_values() {
  local -r artifact_value="$1"
  local -r artifact_identity="$2"
  local -r environment_value="$3"
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
  IFS=: read -r device inode mode links owner owner_gid _ size extra \
    <<<"$artifact_identity"
  [[ -z "$extra" && "$device" =~ ^[0-9]+$ && "$inode" =~ ^[1-9][0-9]*$ &&
    "$mode" =~ ^[0-9]+$ && "$links" == 1 && "$owner" == "$EUID" &&
    "$owner_gid" =~ ^(0|[1-9][0-9]*)$ && "$size" =~ ^[1-9][0-9]*$ &&
    "$size" -le "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" ]] || return 1
  (((mode & 07777) == 0600)) || return 1
  canonical="$(printf '%s' "$artifact_value" | jq -cS .)" || return 1
  [[ "$artifact_value" == "$canonical"$'\n' &&
    "$size" == "$((${#canonical} + 1))" ]] || return 1

  project="$(runner_environment_value_from_value \
    "$environment_value" compose_project)" || return 1
  tls="$(runner_environment_value_from_value \
    "$environment_value" tls_protocol)" || return 1
  seed="$(runner_environment_value_from_value \
    "$environment_value" scenario_seed)" || return 1
  [[ "$project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ &&
    "$tls" =~ ^TLSv1\.[23]$ && "$seed" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  [[ "$owner_gid" == "$(id -g)" ]] || return 1

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
  ' <<<"$artifact_value" >/dev/null
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
  local result_value=""
  local status_value=""
  local fill_value=""
  local verify_value=""
  local ready_value=""
  local release_value=""
  local barrier_value=""
  local inspections_value=""
  local inspections_identity=""
  local environment_value=""

  result_value="$(bounded_duplicate_free_json_value \
    "$result" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  status_value="$(bounded_duplicate_free_json_value \
    "$status" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  fill_value="$(bounded_duplicate_free_json_value \
    "$fill" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  verify_value="$(bounded_duplicate_free_json_value \
    "$verify" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  capture_bounded_regular_file_value \
    "$ready" "$MAX_BOUNDARY_SNAPSHOT_BYTES" ready_value || return 1
  capture_bounded_regular_file_value \
    "$release" "$MAX_BOUNDARY_SNAPSHOT_BYTES" release_value || return 1
  barrier_value="$(bounded_duplicate_free_json_value \
    "$barrier" "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  capture_bounded_regular_file_value "$inspections" \
    "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" inspections_value \
    inspections_identity || return 1
  capture_bounded_regular_file_value "$runner_directory/environment.txt" \
    "$MAX_RUNNER_ENVIRONMENT_BYTES" environment_value || return 1
  validate_pressure_barrier_artifacts_from_values \
    "$result_value" "$status_value" "$fill_value" "$verify_value" \
    "$ready_value" "$release_value" "$barrier_value" \
    "$inspections_value" "$inspections_identity" "$environment_value"
}

validate_pressure_barrier_artifacts_from_values() {
  local -r result_value="$1"
  local -r status_value="$2"
  local -r fill_value="$3"
  local -r verify_value="$4"
  local -r ready_value="$5"
  local -r release_value="$6"
  local -r barrier_value="$7"
  local -r inspections_value="$8"
  local -r inspections_identity="$9"
  local -r environment_value="${10}"
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

  session="$(printf '%s' "$barrier_value" | jq -er '.session')" || return 1
  [[ "$session" =~ ^[0-9a-f]{32}$ ]] || return 1
  validate_pressure_control_value \
    "$ready_value" "pressure-ready-v1:$session" || return 1
  validate_pressure_control_value \
    "$release_value" "pressure-release-v1:$session" || return 1
  validate_pressure_container_inspections_from_values \
    "$inspections_value" "$inspections_identity" "$environment_value" || return 1
  canonical="$(printf '%s' "$barrier_value" | jq -cS .)" || return 1
  [[ "$barrier_value" == "$canonical"$'\n' ]] || return 1
  ready_sha256="$(json_value_sha256 "$ready_value")" || return 1
  release_sha256="$(json_value_sha256 "$release_value")" || return 1
  fill_sha256="$(json_value_sha256 "$fill_value")" || return 1
  verify_sha256="$(json_value_sha256 "$verify_value")" || return 1
  result_sha256="$(json_value_sha256 "$result_value")" || return 1
  status_sha256="$(json_value_sha256 "$status_value")" || return 1
  inspections_sha256="$(json_value_sha256 "$inspections_value")" || return 1
  inspections_size="${#inspections_value}"
  [[ "$inspections_size" =~ ^[1-9][0-9]*$ &&
    "$inspections_size" -le "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" ]] ||
    return 1

  printf '%s\n%s' "$barrier_value" "$inspections_value" | jq -es \
    --arg ready_sha256 "$ready_sha256" \
    --arg release_sha256 "$release_sha256" \
    --arg fill_sha256 "$fill_sha256" \
    --arg verify_sha256 "$verify_sha256" \
    --arg result_sha256 "$result_sha256" \
    --arg status_sha256 "$status_sha256" \
    --arg inspections_sha256 "$inspections_sha256" \
    --argjson inspections_size "$inspections_size" \
    --argjson requests "$PRESSURE_REQUESTS" \
    --argjson admission_maximum \
      "$((PRESSURE_REQUESTS * PRESSURE_ADMISSION_MAX_EVENTS_PER_REQUEST))" '
      def count:
        type == "number" and isfinite and floor == . and
        . >= 0 and . <= $requests;
      length == 2 and (.[0] as $barrier | .[1] as $inspection | $barrier |
      keys == ["container", "container_inspections", "control", "fill",
        "scenario_label", "schema", "sequence", "session", "status",
        "traffic", "verification"] and
      .schema == "pressure-traffic-barrier-v2" and .status == "passed" and
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
      $inspection.session == .session and
      .container == {
        host_pid: ($inspection.running.state.host_pid | tostring),
        id: $inspection.running.identity.id,
        started_at: $inspection.running.state.started_at,
        user: $inspection.running.config.user
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
        keys == ["attributable_failure_count", "exact_hit_count",
          "explicit_root_count",
          "handoff_admission_ambiguous_count",
          "handoff_admission_maximum_count",
          "handoff_admission_overload_count", "java_reconciliation_target",
          "request_count", "result_reference", "result_sha256",
          "retrieval_valid_count", "status_reference",
          "status_sha256", "unresolved_count", "w3c_masked_valid_count",
          "w3c_parent_count", "wrong_parent_count"] and
        .result_reference == "scenario-pressure.json" and
        .result_sha256 == $result_sha256 and
        .status_reference == "scenario-pressure-status.json" and
        .status_sha256 == $status_sha256 and .request_count == $requests and
        all([.exact_hit_count, .explicit_root_count, .w3c_parent_count,
          .wrong_parent_count, .unresolved_count, .retrieval_valid_count,
          .attributable_failure_count, .w3c_masked_valid_count][]; count) and
        .w3c_parent_count == 1 and .explicit_root_count >= 1 and
        .exact_hit_count + .explicit_root_count + .w3c_parent_count ==
          .request_count and
        .wrong_parent_count == 0 and .unresolved_count == 0 and
        .exact_hit_count <= .retrieval_valid_count and
        .retrieval_valid_count <= .exact_hit_count + .w3c_parent_count and
        .explicit_root_count <= .attributable_failure_count and
        .attributable_failure_count <=
          .explicit_root_count + .w3c_parent_count and
        .retrieval_valid_count + .attributable_failure_count ==
          .request_count and
        .w3c_masked_valid_count ==
          .retrieval_valid_count - .exact_hit_count and
        .w3c_masked_valid_count + .attributable_failure_count -
          .explicit_root_count == .w3c_parent_count and
        .w3c_masked_valid_count >= 0 and .w3c_masked_valid_count <= 1 and
        .java_reconciliation_target == {
          attributable_absence_count: .attributable_failure_count,
          diagnostic_self_miss_count: 1,
          discard_standard_count: .w3c_masked_valid_count,
          take_sampled_count: .retrieval_valid_count,
          take_unsampled_count: 0,
          take_valid_count: .retrieval_valid_count
        } and
        .handoff_admission_overload_count >= 1 and
        .handoff_admission_overload_count <= $admission_maximum and
        .handoff_admission_ambiguous_count == 0 and
        .handoff_admission_maximum_count == $admission_maximum))
    ' >/dev/null || return 1

  printf '%s\n%s\n%s\n%s\n%s\n%s' \
    "$barrier_value" "$fill_value" "$verify_value" "$result_value" \
    "$status_value" "$inspections_value" | jq -es '
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
    .[0].traffic.w3c_parent_count ==
      .[3].pressure_correlation.w3c_parent_count and
    .[3].pressure_correlation == .[4].pressure_correlation.trace and
    .[0].traffic.request_count ==
      .[4].pressure_correlation.trace.request_count and
    .[0].traffic.retrieval_valid_count ==
      .[4].pressure_correlation.bridge.retrieval_valid_count and
    .[0].traffic.attributable_failure_count ==
      .[4].pressure_correlation.bridge.attributable_failure_count and
    .[0].traffic.w3c_masked_valid_count ==
      .[4].pressure_correlation.bridge.w3c_masked_valid_count and
    .[0].traffic.java_reconciliation_target ==
      .[4].pressure_correlation.java_reconciliation_target and
    .[0].traffic.handoff_admission_overload_count ==
      .[4].pressure_correlation.bridge.handoff_admission_outcome_counts.overload and
    .[4].pressure_correlation.barrier_reference ==
      "map-pressure-pressure-barrier-status.json" and
    .[4].pressure_correlation.container_inspections ==
      .[0].container_inspections and
    .[5].session == .[0].session
  ' >/dev/null
}

validate_pressure_cell_artifacts() {
  local -r runner_directory="$1"
  local -r output_name="${2:-}"
  local -r result_file="$runner_directory/scenario-pressure.json"
  local -r status_file="$runner_directory/scenario-pressure-status.json"
  local -r prepare_file="$runner_directory/map-pressure-pressure-prepare.json"
  local -r fill_file="$runner_directory/map-pressure-pressure-fill.json"
  local -r verify_file="$runner_directory/map-pressure-pressure-verify.json"
  local -r cleanup_file="$runner_directory/map-pressure-pressure-cleanup.json"
  local -r barrier_file="$runner_directory/map-pressure-pressure-barrier-status.json"
  local -r ready_file="$runner_directory/map-pressure-pressure-barrier-ready.txt"
  local -r release_file="$runner_directory/map-pressure-pressure-barrier-release.txt"
  local -r inspections_file="$runner_directory/map-pressure-pressure-container-inspections.json"
  local -r environment_file="$runner_directory/environment.txt"
  local -r baseline_file="$runner_directory/phases/pressure-before/obi-metrics.prom"
  local -r recovered_file="$runner_directory/map-pressure-pressure-recovered.prom"
  local -r sample_1_file="$runner_directory/map-pressure-pressure-recovered-sample-01.prom"
  local -r sample_2_file="$runner_directory/map-pressure-pressure-recovered-sample-02.prom"
  local -r recovery_log_file="$runner_directory/map-pressure-pressure-recovered-samples.log"
  local status_value=""
  local result_value=""
  local prepare_value=""
  local fill_value=""
  local verify_value=""
  local cleanup_value=""
  local barrier_value=""
  local ready_value=""
  local release_value=""
  local inspections_value=""
  local inspections_identity=""
  local environment_value=""
  local baseline_value=""
  local recovered_value=""
  local sample_1_value=""
  local sample_2_value=""
  local recovery_log_value=""
  local recovery_evidence=""
  local pressure_observation_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local pressure_json_identity=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local pressure_json_size=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local pressure_json_digest=""
  local -a recovery_sample_files=()

  bounded_duplicate_free_json_image "$status_file" \
    "$MAX_BENCHMARK_RESULT_BYTES" status_value pressure_json_identity \
    pressure_json_size pressure_json_digest || return 1
  bounded_duplicate_free_json_image "$result_file" \
    "$MAX_BENCHMARK_RESULT_BYTES" result_value pressure_json_identity \
    pressure_json_size pressure_json_digest || return 1
  bounded_duplicate_free_json_image "$prepare_file" \
    "$MAX_PRESSURE_JSON_BYTES" prepare_value pressure_json_identity \
    pressure_json_size pressure_json_digest || return 1
  bounded_duplicate_free_json_image "$fill_file" \
    "$MAX_PRESSURE_JSON_BYTES" fill_value pressure_json_identity \
    pressure_json_size pressure_json_digest || return 1
  bounded_duplicate_free_json_image "$verify_file" \
    "$MAX_PRESSURE_JSON_BYTES" verify_value pressure_json_identity \
    pressure_json_size pressure_json_digest || return 1
  bounded_duplicate_free_json_image "$cleanup_file" \
    "$MAX_PRESSURE_JSON_BYTES" cleanup_value pressure_json_identity \
    pressure_json_size pressure_json_digest || return 1
  bounded_duplicate_free_json_image "$barrier_file" \
    "$MAX_PRESSURE_JSON_BYTES" barrier_value pressure_json_identity \
    pressure_json_size pressure_json_digest || return 1
  capture_bounded_regular_file_value \
    "$ready_file" "$MAX_PRESSURE_CONTROL_BYTES" ready_value || return 1
  capture_bounded_regular_file_value \
    "$release_file" "$MAX_PRESSURE_CONTROL_BYTES" release_value || return 1
  capture_bounded_regular_file_value "$inspections_file" \
    "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" inspections_value \
    inspections_identity || return 1
  capture_bounded_regular_file_value "$environment_file" \
    "$MAX_RUNNER_ENVIRONMENT_BYTES" environment_value || return 1
  capture_bounded_regular_file_value "$baseline_file" \
    "$MAX_OBI_METRICS_SNAPSHOT_BYTES" baseline_value || return 1
  capture_bounded_regular_file_value "$recovered_file" \
    "$MAX_OBI_METRICS_SNAPSHOT_BYTES" recovered_value || return 1
  capture_bounded_regular_file_value "$sample_1_file" \
    "$MAX_OBI_METRICS_SNAPSHOT_BYTES" sample_1_value || return 1
  capture_bounded_regular_file_value "$sample_2_file" \
    "$MAX_OBI_METRICS_SNAPSHOT_BYTES" sample_2_value || return 1
  capture_bounded_regular_file_value "$recovery_log_file" \
    "$MAX_PRESSURE_LOG_BYTES" recovery_log_value || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    terminal_record_directory_selector \
      "$runner_directory" pressure-recovery-sample-prom || return 1
  else
    shopt -s nullglob
    recovery_sample_files=(
      "$runner_directory"/map-pressure-pressure-recovered-sample-*.prom
    )
    shopt -u nullglob
    [[ "${#recovery_sample_files[@]}" == \
        "$PRESSURE_RECOVERY_REQUIRED_SAMPLES" &&
      "${recovery_sample_files[0]}" == "$sample_1_file" &&
      "${recovery_sample_files[1]}" == "$sample_2_file" ]] || return 1
  fi
  recovery_evidence="$(validate_pressure_cell_artifact_values \
    "$status_value" "$result_value" "$prepare_value" "$fill_value" \
    "$verify_value" "$cleanup_value" "$barrier_value" "$ready_value" \
    "$release_value" "$inspections_value" "$inspections_identity" \
    "$environment_value" "$baseline_value" "$recovered_value" \
    "$sample_1_value" "$sample_2_value" "$recovery_log_value")" || return 1
  if [[ -n "$output_name" ]]; then
    pressure_observation_value="$(canonical_pressure_observation_json_from_values \
      "$status_value" "$prepare_value" "$fill_value" "$verify_value" \
      "$barrier_value" "$cleanup_value" "$recovery_evidence")" || return 1
    printf -v "$output_name" '%s' "$pressure_observation_value"
  fi
}

validate_pressure_cell_artifact_values() {
  local -r status_value="$1"
  local -r result_value="$2"
  local -r prepare_value="$3"
  local -r fill_value="$4"
  local -r verify_value="$5"
  local -r cleanup_value="$6"
  local -r barrier_value="$7"
  local -r ready_value="$8"
  local -r release_value="$9"
  local -r inspections_value="${10}"
  local -r inspections_identity="${11}"
  local -r environment_value="${12}"
  local -r baseline_value="${13}"
  local -r recovered_value="${14}"
  local -r sample_1_value="${15}"
  local -r sample_2_value="${16}"
  local -r recovery_log_value="${17}"
  local recovery_evidence=""

  printf '%s\n%s' "$status_value" "$result_value" | jq -se \
    --argjson requests "$PRESSURE_REQUESTS" \
    --argjson inspections_maximum "$PRESSURE_CONTAINER_INSPECTIONS_MAX_BYTES" \
    --argjson admission_maximum \
      "$((PRESSURE_REQUESTS * PRESSURE_ADMISSION_MAX_EVENTS_PER_REQUEST))" '
    def positive_integer:
      type == "number" and isfinite and floor == . and . > 0;
    def count:
      type == "number" and isfinite and floor == . and
      . >= 0 and . <= $requests;
    length == 2 and
    .[0] as $status |
    .[1] as $result |
    ($status |
      .status == "passed" and
      .scenario == "pressure" and
      .exit_status == 0 and
      .metric_status == 0 and
      .result == "scenario-pressure.json" and
      (.pressure_correlation |
        type == "object" and
        keys == ["barrier_reference", "bridge", "container_inspections",
          "java_reconciliation_target", "trace"]) and
      (.pressure_correlation.trace |
        ((keys | sort) == [
          "exact_hit_count", "explicit_root_count", "request_count",
          "unresolved_count", "w3c_parent_count", "wrong_parent_count"
        ]) and
        all(.[]; count) and .request_count == $requests and
        .w3c_parent_count == 1 and .explicit_root_count >= 1 and
        .wrong_parent_count == 0 and .unresolved_count == 0 and
        .exact_hit_count + .explicit_root_count + .w3c_parent_count ==
          .request_count) and
      (.pressure_correlation.trace as $trace |
       .pressure_correlation.bridge as $bridge |
       .pressure_correlation.java_reconciliation_target as $java |
       ($bridge |
        type == "object" and
        ((keys | sort) == [
          "attributable_failure_count", "handoff_admission_outcome_counts",
          "retrieval_valid_count", "transport", "w3c_masked_valid_count"
        ]) and
        .transport == "getsockopt" and
        (.retrieval_valid_count | count) and
        (.attributable_failure_count | count) and
        (.w3c_masked_valid_count | count) and
        $trace.exact_hit_count <= .retrieval_valid_count and
        .retrieval_valid_count <=
          $trace.exact_hit_count + $trace.w3c_parent_count and
        $trace.explicit_root_count <= .attributable_failure_count and
        .attributable_failure_count <=
          $trace.explicit_root_count + $trace.w3c_parent_count and
        .retrieval_valid_count + .attributable_failure_count ==
          $trace.request_count and
        .w3c_masked_valid_count ==
          .retrieval_valid_count - $trace.exact_hit_count and
        .w3c_masked_valid_count + .attributable_failure_count -
          $trace.explicit_root_count == $trace.w3c_parent_count and
        .w3c_masked_valid_count >= 0 and .w3c_masked_valid_count <= 1 and
        (.handoff_admission_outcome_counts |
          keys == ["ambiguous", "maximum", "overload"] and
          (.overload | positive_integer) and .overload <= .maximum and
          .ambiguous == 0 and .maximum == $admission_maximum)) and
       $java == {
         attributable_absence_count: $bridge.attributable_failure_count,
         diagnostic_self_miss_count: 1,
         discard_standard_count: $bridge.w3c_masked_valid_count,
         take_sampled_count: $bridge.retrieval_valid_count,
         take_unsampled_count: 0,
         take_valid_count: $bridge.retrieval_valid_count
       }) and
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
      (.pressure_correlation |
        ((keys | sort) == [
          "exact_hit_count", "explicit_root_count", "request_count",
          "unresolved_count", "w3c_parent_count", "wrong_parent_count"
        ]) and all(.[]; count)) and
      .pressure_correlation == $status.pressure_correlation.trace and
      .pressure_correlation.explicit_root_count >= 1)
  ' >/dev/null || return 1
  printf '%s\n%s\n%s\n%s' \
    "$prepare_value" "$fill_value" "$verify_value" "$cleanup_value" | jq -se \
    --argjson max_supported_entries "$PRESSURE_MAP_MAX_SUPPORTED_ENTRIES" '
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
    # The single capacity rejection is the retained E2BIG proxy for a full,
    # non-evicting HASH; the post-traffic digest must remain byte-for-byte
    # identical before cleanup is accepted.
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
  ' >/dev/null || return 1
  validate_pressure_barrier_artifacts_from_values \
    "$result_value" "$status_value" "$fill_value" "$verify_value" \
    "$ready_value" "$release_value" "$barrier_value" \
    "$inspections_value" "$inspections_identity" "$environment_value" || return 1
  recovery_evidence="$(pressure_recovery_evidence_json_from_values \
    "$prepare_value" "$baseline_value" "$recovered_value" \
    "$sample_1_value" "$sample_2_value" "$recovery_log_value")" || return 1
  jq -e --argjson required "$PRESSURE_RECOVERY_REQUIRED_SAMPLES" '
    .recovery_sample_count == $required and
    (.recovery_sample_entries | length) == $required
  ' <<<"$recovery_evidence" >/dev/null || return 1
  printf '%s' "$recovery_evidence"
}

canonical_pressure_observation_json() {
  local -r runner_directory="$1"
  local canonical_value=""

  validate_pressure_cell_artifacts \
    "$runner_directory" canonical_value || return 1
  printf '%s\n' "$canonical_value"
}

canonical_pressure_observation_json_from_values() {
  local -r status_value="$1"
  local -r prepare_value="$2"
  local -r fill_value="$3"
  local -r verify_value="$4"
  local -r barrier_value="$5"
  local -r cleanup_value="$6"
  local -r recovery_evidence="$7"

  printf '%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$status_value" "$prepare_value" "$fill_value" "$verify_value" \
    "$barrier_value" "$cleanup_value" "$recovery_evidence" | jq -cs '
      if length != 7 then error("expected exact pressure value roster") else . end |
      .[0] as $status |
      .[1] as $prepare |
      .[2] as $fill |
      .[3] as $verify |
      .[4] as $barrier |
      .[5] as $cleanup |
      .[6] as $recovery |
      {
        bounded: true,
        pressure_contract_version: 2,
        barrier_schema: $barrier.schema,
        barrier_sequence: $barrier.sequence,
        exact_hit_count: $status.pressure_correlation.trace.exact_hit_count,
        explicit_root_count: $status.pressure_correlation.trace.explicit_root_count,
        w3c_parent_count: $status.pressure_correlation.trace.w3c_parent_count,
        wrong_parent_count: $status.pressure_correlation.trace.wrong_parent_count,
        unresolved_count: $status.pressure_correlation.trace.unresolved_count,
        retrieval_valid_count: $status.pressure_correlation.bridge.retrieval_valid_count,
        attributable_failure_count: $status.pressure_correlation.bridge.attributable_failure_count,
        w3c_masked_valid_count: $status.pressure_correlation.bridge.w3c_masked_valid_count,
        take_valid_count: $status.pressure_correlation.java_reconciliation_target.take_valid_count,
        take_sampled_count: $status.pressure_correlation.java_reconciliation_target.take_sampled_count,
        take_unsampled_count: $status.pressure_correlation.java_reconciliation_target.take_unsampled_count,
        discard_standard_count: $status.pressure_correlation.java_reconciliation_target.discard_standard_count,
        attributable_absence_count: $status.pressure_correlation.java_reconciliation_target.attributable_absence_count,
        diagnostic_self_miss_count: $status.pressure_correlation.java_reconciliation_target.diagnostic_self_miss_count,
        handoff_admission_overload_count: $status.pressure_correlation.bridge.handoff_admission_outcome_counts.overload,
        handoff_admission_ambiguous_count: $status.pressure_correlation.bridge.handoff_admission_outcome_counts.ambiguous,
        handoff_admission_maximum_count: $status.pressure_correlation.bridge.handoff_admission_outcome_counts.maximum,
        map_name: $prepare.map_name,
        map_type: $prepare.map_type,
        map_id: $recovery.map_id,
        kernel_map_name: $recovery.kernel_map_name,
        kernel_map_type: $recovery.map_type,
        max_entries: $prepare.max_entries,
        synthetic_pid: $prepare.synthetic_pid,
        synthetic_namespace: $prepare.synthetic_namespace,
        touched_entries: $fill.touched,
        capacity_rejected_entries: $fill.capacity_rejected_entries,
        fill_verified_present_entries: $fill.verified_present_entries,
        fill_verified_absent_entries: $fill.verified_absent_entries,
        content_sha256: $fill.content_sha256,
        post_traffic_verified_present_entries: $verify.verified_present_entries,
        post_traffic_verified_absent_entries: $verify.verified_absent_entries,
        post_traffic_content_sha256: $verify.content_sha256,
        post_traffic_content_verified: true,
        cleanup_verified: $cleanup.cleanup_verified,
        cleanup_verified_absent_entries: $cleanup.verified_absent_entries,
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
  local -r output_name="${2:-}"
  local observation_value=""

  observation_value="$(bounded_duplicate_free_json_value \
    "$observation" "$MAX_PATH_OBSERVATION_BYTES")" || return 1
  validate_path_observation_json_value "$observation_value" || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$observation_value"
  fi
}

validate_path_observation_json_value() {
  local -r observation_value="$1"

  printf '%s' "$observation_value" | jq -se \
    --argjson hit_requests "$PREFLIGHT_REQUESTS" \
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
          "attributable_absence_count", "attributable_failure_count",
          "barrier_schema", "barrier_sequence", "bounded",
          "capacity_rejected_entries", "cleanup_verified",
          "cleanup_verified_absent_entries", "content_sha256",
          "diagnostic_self_miss_count", "discard_standard_count",
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
          "recovery_log_attempts", "recovery_samples",
          "retrieval_valid_count", "synthetic_namespace", "synthetic_pid",
          "take_sampled_count", "take_unsampled_count", "take_valid_count",
          "touched_entries", "unresolved_count", "w3c_masked_valid_count",
          "w3c_parent_count", "wrong_parent_count"
        ]) and
        all(.[];
          type == "boolean" or type == "string" or nonnegative_integer or
          (type == "array" and
            all(.[]; type == "string" or nonnegative_integer))) and
        .bounded == true and .pressure_contract_version == 2 and
        .barrier_schema == "pressure-traffic-barrier-v2" and
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
        .w3c_parent_count == 1 and .explicit_root_count >= 1 and
        .exact_hit_count + .explicit_root_count + .w3c_parent_count ==
          $pressure_requests and
        .exact_hit_count <= .retrieval_valid_count and
        .retrieval_valid_count <= .exact_hit_count + .w3c_parent_count and
        .explicit_root_count <= .attributable_failure_count and
        .attributable_failure_count <=
          .explicit_root_count + .w3c_parent_count and
        .retrieval_valid_count + .attributable_failure_count ==
          $pressure_requests and
        .w3c_masked_valid_count ==
          .retrieval_valid_count - .exact_hit_count and
        .w3c_masked_valid_count + .attributable_failure_count -
          .explicit_root_count == .w3c_parent_count and
        .w3c_masked_valid_count >= 0 and .w3c_masked_valid_count <= 1 and
        .take_valid_count == .retrieval_valid_count and
        .take_sampled_count == .retrieval_valid_count and
        .take_unsampled_count == 0 and
        .discard_standard_count == .w3c_masked_valid_count and
        .attributable_absence_count == .attributable_failure_count and
        .diagnostic_self_miss_count == 1);
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
  ' >/dev/null
}

validate_path_observation_source_artifacts() (
  local -r observation="$1"
  local observation_directory=""
  local observation_value=""
  local cell=""
  local result_file=""
  local status_file=""
  local diagnostics_file=""
  local diagnostics_json=""
  local canonical_pressure_json=""

  validate_path_observation_schema \
    "$observation" observation_value || return 1
  observation_directory="$(cd -- "${observation%/*}" && pwd -P)" || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    validate_path_observation_source_artifact_values \
      "$observation_value" "$observation_directory"
    return $?
  fi
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

validate_path_observation_source_artifact_values() (
  local -r observation_value="$1"
  local -r observation_directory="$2"
  local cell=""
  local runner_directory=""
  local result_file=""
  local status_file=""
  local diagnostics_file=""
  local result_value=""
  local status_value=""
  local diagnostics_value=""
  local diagnostics_json=""
  local canonical_pressure_json=""
  local runner_environment_value=""
  local runner_provenance_value=""
  local runner_source_state_value=""
  local host_environment_value=""

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false &&
    "$observation_directory" == /* ]] || return 1
  validate_path_observation_json_value "$observation_value" || return 1
  cell="$(printf '%s' "$observation_value" | jq -er '.cell')" || return 1
  cell_spec "$cell" || return 1
  [[ "$observation_directory" == "$OUTPUT_DIR/cells/$cell" ]] || return 1
  runner_directory="$observation_directory/preflight/runner"
  result_file="$runner_directory/scenario-$CELL_RESULT_LABEL.json"
  status_file="$runner_directory/scenario-$CELL_RESULT_LABEL-status.json"
  diagnostics_file="$runner_directory/phases/$CELL_RESULT_LABEL-after/java-diagnostics.delta"
  result_value="$(bounded_duplicate_free_json_value \
    "$result_file" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  status_value="$(bounded_duplicate_free_json_value \
    "$status_file" "$MAX_BENCHMARK_RESULT_BYTES")" || return 1
  capture_bounded_regular_file_value "$diagnostics_file" \
    "$MAX_JAVA_TOOL_OUTPUT_BYTES" diagnostics_value || return 1
  validate_runner_scenario_measurement_json_value \
    "$result_value" "$CELL_SCENARIO" "$CELL_MEASUREMENT_REQUESTS" || return 1
  validate_runner_scenario_status_json_value \
    "$status_value" "$CELL_SCENARIO" "scenario-$CELL_RESULT_LABEL.json" || return 1
  diagnostics_json="$(java_path_diagnostic_counts_from_value \
    "$diagnostics_value")" || return 1
  printf '%s\n%s' "$observation_value" "$diagnostics_json" | jq -es '
    length == 2 and .[0].java_diagnostic_status_deltas == .[1]
  ' >/dev/null || return 1
  capture_bounded_regular_file_value \
    "$runner_directory/environment.txt" "$MAX_RUNNER_ENVIRONMENT_BYTES" \
    runner_environment_value || return 1
  capture_bounded_regular_file_value \
    "$runner_directory/provenance.json" "$MAX_RUNNER_ENVIRONMENT_BYTES" \
    runner_provenance_value || return 1
  capture_bounded_regular_file_value \
    "$runner_directory/source-state.txt" "$MAX_RUNNER_SOURCE_STATE_BYTES" \
    runner_source_state_value || return 1
  capture_bounded_regular_file_value \
    "$OUTPUT_DIR/host-environment.txt" \
    "$MAX_HOST_ENVIRONMENT_BYTES" host_environment_value || return 1
  [[ -n "$runner_environment_value" && -n "$runner_provenance_value" &&
    -n "$runner_source_state_value" && -n "$host_environment_value" ]] || return 1
  if [[ "$cell" == getsockopt-pressure ]]; then
    canonical_pressure_json="$(canonical_pressure_observation_json \
      "$runner_directory")" || return 1
    printf '%s\n%s' "$observation_value" "$canonical_pressure_json" | jq -es '
      length == 2 and .[0].pressure == .[1]
    ' >/dev/null || return 1
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
  printf '%s\n%s\n%s' "$result_json" "$diagnostics_json" \
    "$pressure_json" | jq -s \
    --arg cell "$CELL_SLUG" \
    --arg transport "$CELL_SELECTED_TRANSPORT" \
    --arg classification "$CELL_PATH_CLASSIFICATION" \
    --arg java_status "$CELL_EXPECTED_JAVA_STATUS" \
    --arg result_source "preflight/runner/scenario-$CELL_RESULT_LABEL.json" \
    --arg status_source "preflight/runner/scenario-$CELL_RESULT_LABEL-status.json" \
    --arg diagnostics_source "preflight/runner/phases/$CELL_RESULT_LABEL-after/java-diagnostics.delta" \
    --argjson requested_runner_requests "$CELL_PREFLIGHT_REQUESTS" \
    --argjson measured_requests "$CELL_MEASUREMENT_REQUESTS" '
      if length != 3 then error("expected result, diagnostics, and pressure observation")
      else . end |
      .[0] as $result |
      .[1] as $diagnostics |
      .[2] as $pressure |
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
  local -r digest_output_name="${2:-}"
  local -r size_output_name="${3:-}"
  local observed_digest=""
  local observed_size=""
  local digest_and_size=""
  local captured_output=""
  local source_record=""
  local source_locator=""
  local source_record_fd=""
  local locator_status=0

  [[ "$TERMINAL_SOURCE_SESSION_FROZEN" != true ]] || return 1
  [[ -f "$input" && ! -L "$input" ]] || return 1
  resolve_benchmark_identity_tools || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    source_locator="$(terminal_source_locator "$input")" || locator_status=$?
    if ((locator_status == 2)); then
      source_locator=""
    elif ((locator_status != 0)); then
      return 1
    fi
    source_record_fd="$TERMINAL_SOURCE_RECORD_FD"
    [[ -z "$source_locator" || "$source_record_fd" =~ ^[1-9][0-9]*$ ]] || return 1
  fi
  captured_output="$(run_native_clean_environment "$NATIVE_BENCHMARK_PERL_COMMAND" -T \
    -MFcntl=:DEFAULT,:mode -MDigest::SHA -e '
      use strict;
      use warnings;
      my ($path, $maximum, $locator, $record_maximum) = @ARGV;
      $maximum =~ /\A[1-9][0-9]*\z/ or exit 1;
      sysopen(my $handle, $path, O_RDONLY | O_NOFOLLOW) or exit 1;
      my @before = stat($handle);
      @before && S_ISREG($before[2]) && $before[7] > 0 &&
        $before[7] <= $maximum or exit 1;
      my $sha = Digest::SHA->new(256);
      my $total = 0;
      while ($total < $before[7]) {
        my $chunk = q{};
        my $wanted = $before[7] - $total;
        $wanted = 1048576 if $wanted > 1048576;
        my $read = sysread($handle, $chunk, $wanted);
        defined($read) && $read > 0 or exit 1;
        $total += $read;
        $total <= $before[7] or exit 1;
        $sha->add($chunk);
      }
      my $extra = q{};
      my $extra_read = sysread($handle, $extra, 1);
      defined($extra_read) && $extra_read == 0 or exit 1;
      my @after = stat($handle);
      @after && join(q{:}, @before[0,1,2,3,4,5,6,7]) eq
        join(q{:}, @after[0,1,2,3,4,5,6,7]) or exit 1;
      my $digest = $sha->hexdigest;
      if (length($locator)) {
        $record_maximum =~ /\A[1-9][0-9]*\z/ or exit 1;
        my $payload = join(qq{\t}, $locator, $maximum,
          @before[0,1,2,3,4,5,6,7], $digest);
        my $record = q{S:} . length($payload) . q{:} . $payload . qq{\n};
        length($record) <= $record_maximum or exit 1;
        print $record;
      }
      close($handle) or exit 1;
      print $digest, q{:}, $before[7];
    ' -- "$input" "$MAX_TERMINAL_SOURCE_LEAF_BYTES" "$source_locator" \
      "$MAX_TERMINAL_SOURCE_RECORD_BYTES")" || return 1
  if [[ -n "$source_locator" ]]; then
    [[ "$captured_output" == *$'\n'* ]] || return 1
    source_record="${captured_output%%$'\n'*}"
    digest_and_size="${captured_output#*$'\n'}"
    [[ -n "$source_record" && "$source_record" != *$'\n'* &&
      "${#source_record}" -lt "$MAX_TERMINAL_SOURCE_RECORD_BYTES" ]] || return 1
    printf '%s\n' "$source_record" >&"$source_record_fd" || return 1
  else
    digest_and_size="$captured_output"
  fi
  observed_digest="${digest_and_size%%:*}"
  observed_size="${digest_and_size#*:}"
  [[ "$observed_digest" =~ ^[0-9a-f]{64}$ &&
    "$observed_size" =~ ^[1-9][0-9]*$ &&
    "$digest_and_size" == "$observed_digest:$observed_size" ]] || return 1
  if [[ -n "$digest_output_name" ]]; then
    printf -v "$digest_output_name" '%s' "$observed_digest"
  else
    printf '%s\n' "$observed_digest"
  fi
  if [[ -n "$size_output_name" ]]; then
    printf -v "$size_output_name" '%s' "$observed_size"
  fi
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
  local recorded_manifest_value=""

  [[ -f "$recorded_manifest" && ! -L "$recorded_manifest" ]] || return 1
  capture_bounded_regular_file_value "$recorded_manifest" \
    "$MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES" recorded_manifest_value || return 1
  validate_recorded_git_tree_manifest_value "$repository" "$revision" \
    "$recorded_git_tree" "$recorded_manifest_value"
}

# Render the exact git-tree-v2 transcript from bounded NUL-delimited Git output
# into a Bash-held byte image. The process-substitution sentinel makes the
# producer exit status explicit without a pathname handoff.
git_tree_manifest_value_for_tree() {
  local -r repository="$1"
  local -r git_tree="$2"
  local -r output_name="$3"
  local entry=""
  local metadata=""
  local path=""
  local mode=""
  local object_type=""
  local object_id=""
  local extra=""
  local marker=""
  local quoted_path=""
  local line=""
  local manifest_value=""
  local saw_end=false
  local entry_count=0
  local input_bytes=0

  [[ -d "$repository" && ! -L "$repository" &&
    "$git_tree" =~ ^[0-9a-f]{40}$ && -n "$output_name" ]] || return 1
  while IFS= read -r -d '' entry; do
    if [[ "$entry" == OBI_GIT_TREE_END ]]; then
      [[ "$saw_end" == false ]]
      saw_end=true
      continue
    fi
    [[ "$saw_end" == false && "$entry" == *$'\t'* ]] || return 1
    input_bytes="$((input_bytes + ${#entry} + 1))"
    ((input_bytes <= MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES)) || return 1
    entry_count="$((entry_count + 1))"
    ((entry_count <= MAX_TERMINAL_GIT_INDEX_ENTRIES)) || return 1
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    read -r mode object_type object_id extra <<<"$metadata" || return 1
    [[ "$object_id" =~ ^[0-9a-f]{40}$ && -z "$extra" ]] || return 1
    is_safe_git_tree_path "$path" || return 1
    case "$mode:$object_type" in
      100644:blob) marker='-' ;;
      100755:blob) marker='x' ;;
      120000:blob) marker='l' ;;
      160000:commit) marker='g' ;;
      *) return 1 ;;
    esac
    printf -v quoted_path '%q' "$path" || return 1
    printf -v line '%s %s %s\n' "$object_id" "$marker" "$quoted_path" || return 1
    manifest_value+="$line"
    ((${#manifest_value} <= MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES)) || return 1
  done < <({
    run_native_bounded "$TERMINAL_PUBLICATION_COMMIT_DEADLINE_SECONDS" \
      "$NATIVE_BENCHMARK_GIT_COMMAND" -C "$repository" \
      ls-tree -r -z --full-tree "$git_tree" 2>&1 &&
      printf 'OBI_GIT_TREE_END\0'
  })
  [[ "$saw_end" == true && "$entry_count" -gt 0 && -n "$manifest_value" ]] || return 1
  printf -v "$output_name" '%s' "$manifest_value"
}

# Bind an already held git-tree-v2 transcript to the exact recorded Git tree.
# The derivation travels only through an anonymous bounded pipe and a held Bash
# value; only the retained manifest and subsequent native G authority survive.
validate_recorded_git_tree_manifest_value() {
  local -r repository="$1"
  local -r revision="$2"
  local -r recorded_git_tree="$3"
  local -r recorded_manifest_value="$4"
  local expected_git_tree=""
  local expected_manifest_value=""
  local expected_manifest_sha256=""

  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$recorded_git_tree" =~ ^[0-9a-f]{40}$ &&
    -n "$recorded_manifest_value" ]] || return 1
  expected_git_tree="$(run_native_clean_environment "$NATIVE_BENCHMARK_GIT_COMMAND" \
    -C "$repository" rev-parse "$revision^{tree}" 2>/dev/null)" || return 1
  [[ "$expected_git_tree" == "$recorded_git_tree" ]] || return 1
  git_tree_manifest_value_for_tree "$repository" "$recorded_git_tree" \
    expected_manifest_value || return 1
  [[ "$expected_manifest_value" == "$recorded_manifest_value" ]] || return 1
  expected_manifest_sha256="$(printf '%s' "$expected_manifest_value" | \
    run_native_clean_environment "$NATIVE_BENCHMARK_SHA256_COMMAND")" || return 1
  expected_manifest_sha256="${expected_manifest_sha256%% *}"
  [[ "$expected_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
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

validate_runner_application_source_state_values() {
  local -r state_value="$1"
  local -r manifest_value="$2"
  local -r environment_value="$3"
  local revision=""
  local dirty=""
  local tree_sha256=""
  local manifest_schema=""
  local tracked_patch_sha256=""
  local patch_identity_sha256=""
  local observed_tree_sha256=""
  local -a lines=()

  [[ -n "$state_value" && -n "$manifest_value" && -n "$environment_value" &&
    "$state_value" != *$'\r'* && "$manifest_value" != *$'\r'* &&
    "$environment_value" != *$'\r'* ]] || return 1
  mapfile -t lines < <(printf '%s' "$state_value") || return 1
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
    "$tracked_patch_sha256" == \
      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 &&
    "$patch_identity_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_tree_sha256="$(json_value_sha256 "$manifest_value")" || return 1
  [[ "$observed_tree_sha256" == "$tree_sha256" ]] || return 1
  [[ "$(runner_environment_value_from_value \
      "$environment_value" revision)" == "$revision" &&
    "$(runner_environment_value_from_value \
      "$environment_value" dirty)" == false &&
    "$(runner_environment_value_from_value \
      "$environment_value" source_tree_sha256)" == "$tree_sha256" &&
    "$(runner_environment_value_from_value \
      "$environment_value" source_tree_manifest_schema)" == git-tree-v2 &&
    "$(runner_environment_value_from_value \
      "$environment_value" tracked_patch_sha256)" == "$tracked_patch_sha256" &&
    "$(runner_environment_value_from_value \
      "$environment_value" patch_identity_sha256)" == "$patch_identity_sha256" ]]
}

canonical_application_patch_identity_values() {
  local -r state_value="$1"
  local -r status_value="$2"
  local tree_sha256=""
  local tracked_patch_sha256=""
  local status_sha256=""
  local identity_input=""

  [[ -z "$status_value" ]] || return 1
  tree_sha256="$(runner_environment_value_from_value \
    "$state_value" source_tree_sha256)" || return 1
  tracked_patch_sha256="$(runner_environment_value_from_value \
    "$state_value" tracked_patch_sha256)" || return 1
  status_sha256="$(json_value_sha256 "$status_value")" || return 1
  printf -v identity_input \
    'git_status_sha256=%s\nsource_tree_sha256=%s\ntracked_patch_sha256=%s\n' \
    "$status_sha256" "$tree_sha256" "$tracked_patch_sha256"
  json_value_sha256 "$identity_input"
}

validate_application_source_identity_terminal_values() {
  local -r artifact_value="$1"
  local -r artifact_root="$2"
  local -r repository="$3"
  local cells_mode=""
  local revision=""
  local cell=""
  local runner_directory=""
  local state_path=""
  local manifest_path=""
  local status_path=""
  local environment_path=""
  local state_value=""
  local manifest_value=""
  local status_value=""
  local environment_value=""
  local runner_patch_identity=""
  local canonical_patch_identity=""
  local reference_manifest=""
  local reference_tree_sha256=""
  local reference_tracked_patch_sha256=""
  local reference_canonical_patch_identity=""
  local host_environment_value=""
  local host_revision=""
  local native_state_value=""
  local native_before_value=""
  local native_after_value=""
  local git_tree=""
  local derived_manifest_sha256=""
  local cells_output=""
  local expected_cell_count=0
  local -a cells=()

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false && "$artifact_root" == /* &&
    "$repository" == "$TERMINAL_SOURCE_REPOSITORY_ROOT" ]] || return 1
  cells_mode="$(printf '%s' "$artifact_value" | jq -er '.cells_mode')" || return 1
  revision="$(printf '%s' "$artifact_value" | jq -er '.revision')" || return 1
  cells_output="$(printf '%s' "$artifact_value" | jq -er '.cells[].cell')" || return 1
  mapfile -t cells <<<"$cells_output" || return 1
  expected_cell_count="${#CORE_CELLS[@]}"
  if [[ "$cells_mode" == complete ]]; then
    expected_cell_count="$((expected_cell_count + ${#BOUNDED_PATH_CELLS[@]}))"
  fi
  ((${#cells[@]} == expected_cell_count)) || return 1
  for cell in "${cells[@]}"; do
    runner_directory="$artifact_root/cells/$cell/preflight/runner"
    state_path="$runner_directory/source-state.txt"
    manifest_path="$runner_directory/source-tree.manifest"
    status_path="$runner_directory/git-status.txt"
    environment_path="$runner_directory/environment.txt"
    capture_bounded_regular_file_value "$state_path" \
      "$MAX_RUNNER_SOURCE_STATE_BYTES" state_value || return 1
    capture_bounded_regular_file_value "$manifest_path" \
      "$MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES" manifest_value || return 1
    capture_bounded_regular_file_value "$environment_path" \
      "$MAX_RUNNER_ENVIRONMENT_BYTES" environment_value || return 1
    [[ -f "$status_path" && ! -L "$status_path" && ! -s "$status_path" ]] || return 1
    terminal_record_source_negative \
      "$status_path" "$MAX_CELL_STATUS_BYTES" empty || return 1
    status_value=""
    validate_runner_application_source_state_values \
      "$state_value" "$manifest_value" "$environment_value" || return 1
    [[ "$(runner_environment_value_from_value "$state_value" revision)" == \
      "$revision" ]] || return 1
    runner_patch_identity="$(runner_environment_value_from_value \
      "$state_value" patch_identity_sha256)" || return 1
    [[ "$(printf '%s' "$artifact_value" | jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .runner_patch_identity_sha256')" == \
      "$runner_patch_identity" ]] || return 1
    canonical_patch_identity="$(canonical_application_patch_identity_values \
      "$state_value" "$status_value")" || return 1
    if [[ -z "$reference_manifest" ]]; then
      reference_manifest="$manifest_value"
      reference_tree_sha256="$(runner_environment_value_from_value \
        "$state_value" source_tree_sha256)" || return 1
      reference_tracked_patch_sha256="$(runner_environment_value_from_value \
        "$state_value" tracked_patch_sha256)" || return 1
      reference_canonical_patch_identity="$canonical_patch_identity"
    else
      [[ "$manifest_value" == "$reference_manifest" &&
        "$(runner_environment_value_from_value \
          "$state_value" source_tree_sha256)" == "$reference_tree_sha256" &&
        "$(runner_environment_value_from_value \
          "$state_value" tracked_patch_sha256)" == "$reference_tracked_patch_sha256" &&
        "$canonical_patch_identity" == "$reference_canonical_patch_identity" ]] || return 1
    fi
  done
  [[ -n "$reference_manifest" &&
    "$(printf '%s' "$artifact_value" | jq -er '.source_tree_sha256')" == \
      "$reference_tree_sha256" &&
    "$(printf '%s' "$artifact_value" | jq -er '.tracked_patch_sha256')" == \
      "$reference_tracked_patch_sha256" &&
    "$(printf '%s' "$artifact_value" | \
      jq -er '.canonical_patch_identity_sha256')" == \
      "$reference_canonical_patch_identity" ]] || return 1
  capture_bounded_regular_file_value "$artifact_root/host-environment.txt" \
    "$MAX_HOST_ENVIRONMENT_BYTES" host_environment_value || return 1
  host_revision="$(printf '%s' "$host_environment_value" | awk -F= '
    $1 == "git_revision" { matches++; value = $2 }
    END { if (matches != 1) exit 1; print value }
  ')" || return 1
  [[ "$host_revision" == "$revision" ]] || return 1
  if [[ "$cells_mode" == complete ]]; then
    native_state_value="$(bounded_duplicate_free_json_value \
      "$artifact_root/native-jni/source-state.json" \
      "$MAX_NATIVE_SOURCE_STATE_BYTES")" || return 1
    native_before_value="$(bounded_duplicate_free_json_value \
      "$artifact_root/native-jni/source-state-before.json" \
      "$MAX_NATIVE_SOURCE_SNAPSHOT_BYTES")" || return 1
    native_after_value="$(bounded_duplicate_free_json_value \
      "$artifact_root/native-jni/source-state-after.json" \
      "$MAX_NATIVE_SOURCE_SNAPSHOT_BYTES")" || return 1
    validate_native_source_state_json_values "$native_state_value" \
      "$native_before_value" "$native_after_value" || return 1
    [[ "$(printf '%s' "$native_state_value" | jq -er '.revision')" == \
      "$revision" ]] || return 1
  fi
  git_tree="$(printf '%s' "$artifact_value" | jq -er '.git_tree')" || return 1
  derived_manifest_sha256="$(validate_recorded_git_tree_manifest_value \
    "$repository" "$revision" "$git_tree" "$reference_manifest")" || return 1
  [[ "$derived_manifest_sha256" == "$reference_tree_sha256" ]] || return 1
  terminal_record_git_checkout_authority \
    "$repository" "$revision" "$git_tree" "$reference_tree_sha256"
}

validate_application_source_identity_schema() {
  local -r artifact="$1"
  local -r repository="${2:-$REPO_ROOT}"
  local -r validate_live_checkout="${3:-true}"
  local -r output_name="${4:-}"
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
  local artifact_value=""

  artifact_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_APPLICATION_SOURCE_IDENTITY_BYTES")" || return 1
  [[ "$validate_live_checkout" == true || "$validate_live_checkout" == false ]] || return 1
  artifact_root="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  cells_mode="$(printf '%s' "$artifact_value" | jq -er '.cells_mode')" || return 1
  [[ "$cells_mode" == core || "$cells_mode" == complete ]] || return 1
  if [[ "$cells_mode" == complete ]]; then
    expected_cells_json="$(jq -cn '$ARGS.positional' --args \
      "${CORE_CELLS[@]}" "${BOUNDED_PATH_CELLS[@]}")" || return 1
  else
    expected_cells_json="$(jq -cn '$ARGS.positional' --args "${CORE_CELLS[@]}")" || return 1
  fi
  printf '%s' "$artifact_value" | jq -se \
    --arg mode "$cells_mode" --argjson expected_cells "$expected_cells_json" '
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
  ' >/dev/null || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    validate_application_source_identity_terminal_values \
      "$artifact_value" "$artifact_root" "$repository" || return 1
    if [[ -n "$output_name" ]]; then
      printf -v "$output_name" '%s' "$artifact_value"
    fi
    return 0
  fi
  revision="$(printf '%s' "$artifact_value" | jq -er '.revision')" || return 1
  for cell in $(printf '%s' "$artifact_value" | jq -r '.cells[].cell'); do
    source_state_link="$(printf '%s' "$artifact_value" | jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .source_state')" || return 1
    manifest_link="$(printf '%s' "$artifact_value" | jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .source_tree_manifest')" || return 1
    status_link="$(printf '%s' "$artifact_value" | jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .git_status')" || return 1
    environment_link="$(printf '%s' "$artifact_value" | jq -er --arg cell "$cell" \
      '.cells[] | select(.cell == $cell) | .runner_environment')" || return 1
    for source_state_link in "$source_state_link" "$manifest_link" "$status_link" "$environment_link"; do
      validate_relative_artifact_link "$artifact_root" "$artifact_root" \
        "$source_state_link" || return 1
    done
    runner_directory="$artifact_root/cells/$cell/preflight/runner"
    validate_runner_application_source_state "$runner_directory" || return 1
    runner_environment_matches "$runner_directory/source-state.txt" revision "$revision" || return 1
    runner_patch_identity="$(runner_environment_value \
      "$runner_directory/source-state.txt" patch_identity_sha256)" || return 1
    printf '%s' "$artifact_value" | jq -e \
      --arg cell "$cell" --arg identity "$runner_patch_identity" '
      (.cells[] | select(.cell == $cell) | .runner_patch_identity_sha256) == $identity
    ' >/dev/null || return 1
    canonical_patch_identity="$(canonical_application_patch_identity \
      "$runner_directory")" || return 1
    [[ "$canonical_patch_identity" == \
      "$(printf '%s' "$artifact_value" | \
        jq -er '.canonical_patch_identity_sha256')" ]] || return 1
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
  recorded_git_tree="$(printf '%s' "$artifact_value" | jq -er '.git_tree')" || return 1
  derived_manifest_sha256="$(validate_recorded_git_tree_manifest \
    "$repository" "$revision" "$recorded_git_tree" \
    "$reference_runner/source-tree.manifest")" || return 1
  printf '%s' "$artifact_value" | jq -e --arg revision "$revision" \
    --arg tree "$(runner_environment_value "$reference_runner/source-state.txt" source_tree_sha256)" \
    --arg patch "$(runner_environment_value "$reference_runner/source-state.txt" tracked_patch_sha256)" '
      .revision == $revision and .source_tree_sha256 == $tree and
      .source_tree_manifest_schema == "git-tree-v2" and
      .tracked_patch_sha256 == $patch
    ' >/dev/null || return 1
  [[ "$derived_manifest_sha256" == \
    "$(printf '%s' "$artifact_value" | jq -er '.source_tree_sha256')" ]] || return 1
  if [[ "$validate_live_checkout" == true ]]; then
    validate_current_application_checkout "$repository" "$revision" || return 1
  fi
  host_environment_link="$(printf '%s' "$artifact_value" | \
    jq -er '.host_environment')" || return 1
  validate_relative_artifact_link "$artifact_root" "$artifact_root" \
    "$host_environment_link" || return 1
  [[ "$(awk -F= '
    $1 == "git_revision" { matches++; value = $2 }
    END { if (matches != 1) exit 1; print value }
  ' "$artifact_root/$host_environment_link")" == "$revision" ]] || return 1
  if [[ "$cells_mode" == complete ]]; then
    native_source_link="$(printf '%s' "$artifact_value" | \
      jq -er '.native_source_state')" || return 1
    validate_relative_artifact_link "$artifact_root" "$artifact_root" \
      "$native_source_link" || return 1
    validate_native_source_state_schema "$artifact_root/$native_source_link" || return 1
    [[ "$(jq -er '.revision' "$artifact_root/$native_source_link")" == "$revision" ]] || return 1
  fi
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$artifact_value"
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
  local summary_value=""
  local summary_directory=""
  local cell=""
  local source_artifact=""
  local link_base=""
  local source_file=""
  local link=""
  local -a links=()

  summary_value="$(bounded_duplicate_free_json_value \
    "$summary" "$MAX_LOOKUP_PATH_SUMMARY_BYTES")" || return 1
  printf '%s' "$summary_value" | jq -se '
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
  ' >/dev/null || return 1
  summary_directory="$(cd -- "${summary%/*}" && pwd -P)" || return 1
  if [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true ]]; then
    validate_lookup_path_summary_terminal_values \
      "$summary_value" "$summary_directory" "$repository"
    return $?
  fi
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

validate_lookup_path_summary_terminal_values() (
  local -r summary_value="$1"
  local -r summary_directory="$2"
  local -r repository="$3"
  local application_source_value=""
  local docker_daemon_value=""
  local native_benchmark_value=""
  local observation_value=""
  local embedded_observation=""
  local source_revision=""
  local source_artifact=""
  local link_base=""
  local cell=""

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false &&
    "$summary_directory" == "$OUTPUT_DIR" && "$repository" == "$REPO_ROOT" ]] || return 1
  validate_docker_daemon_provenance \
    "$summary_directory/docker-daemon.json" docker_daemon_value || return 1
  validate_application_source_identity_schema \
    "$summary_directory/application-source-identity.json" "$repository" false \
    application_source_value || return 1
  [[ "$(printf '%s' "$application_source_value" | jq -er '.cells_mode')" == \
    complete ]] || return 1
  source_revision="$(printf '%s' "$application_source_value" | \
    jq -er '.revision')" || return 1
  for cell in "${PATH_OBSERVATION_CELLS[@]}"; do
    source_artifact="$(printf '%s' "$summary_value" | jq -er --arg cell "$cell" \
      '.paths[] | select(.observation.cell == $cell) | .source_artifact')" || return 1
    link_base="$(printf '%s' "$summary_value" | jq -er --arg cell "$cell" \
      '.paths[] | select(.observation.cell == $cell) | .link_base')" || return 1
    [[ "$source_artifact" == "cells/$cell/path-observation.json" &&
      "$link_base" == "cells/$cell/" ]] || return 1
    validate_path_observation_schema \
      "$summary_directory/$source_artifact" observation_value || return 1
    validate_path_observation_source_artifact_values \
      "$observation_value" "$summary_directory/cells/$cell" || return 1
    embedded_observation="$(printf '%s' "$summary_value" | jq -ce \
      --arg cell "$cell" \
      '.paths[] | select(.observation.cell == $cell) | .observation')" || return 1
    printf '%s\n%s' "$observation_value" "$embedded_observation" | jq -es '
      length == 2 and .[0] == .[1]
    ' >/dev/null || return 1
  done
  source_artifact="$(printf '%s' "$summary_value" | \
    jq -er '.native_lookup_benchmark.source_artifact')" || return 1
  link_base="$(printf '%s' "$summary_value" | \
    jq -er '.native_lookup_benchmark.link_base')" || return 1
  [[ "$source_artifact" == native-jni/benchmark.json &&
    "$link_base" == native-jni/ ]] || return 1
  validate_native_jni_benchmark_schema \
    "$summary_directory/$source_artifact" native_benchmark_value || return 1
  [[ "$(printf '%s' "$native_benchmark_value" | \
    jq -er '.provenance.source_revision')" == "$source_revision" ]] || return 1
  printf '%s\n%s' "$summary_value" "$native_benchmark_value" | jq -es '
    length == 2 and .[0].native_lookup_benchmark.benchmark == .[1]
  ' >/dev/null
)

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
  unset BENCHMARK_CA_SOURCE JAVA_IMAGE_TARGET JAVA_BACKEND_IMAGE \
    JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX
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
  capture_resource_snapshot \
    "$cell_dir/program-metrics-baseline" program_metrics_baseline not_collected
  begin_java_measurement_with_classification "$cell_dir" || return 1
  capture_cpu_measurement_snapshot \
    "$cell_dir/cpu-measurement-baseline" cpu_measurement_baseline
  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    log_info "measuring $CELL_SLUG repetition $repetition/$REPETITIONS"
    run_helper_idle_measurement_rep "$cell_dir" "$repetition"
    printf -v repetition_label 'rep-%02d' "$repetition"
    request_count="$(benchmark_successful_request_count \
      "$cell_dir/measurements/$repetition_label.json")" || return 1
    ((successful_requests <= MAX_JAVA_DIAGNOSTIC_COUNTER - request_count)) || return 1
    successful_requests="$((successful_requests + request_count))"
  done
  capture_cpu_measurement_snapshot \
    "$cell_dir/cpu-measurement-end" cpu_measurement_end
  stop_java_measurement_with_classification "$cell_dir" || return 1
  capture_resource_snapshot \
    "$cell_dir/program-metrics-end" program_metrics_end not_collected
  finish_java_measurement_with_classification "$cell_dir" || return 1
  # Take a fresh observation after every workload client has exited. Waiting for
  # two subsequent Java bridge stats-map report passes prevents a pass that occurred during the
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

validate_recovery_schedule_shape_json_value() {
  local -r schedule_value="$1"

  printf '%s' "$schedule_value" | jq -se \
    --argjson interval "$IDLE_RECOVERY_INTERVAL_SECONDS" \
    --argjson required "$IDLE_RECOVERY_REQUIRED_SAMPLES" '
    def n: type == "number" and isfinite and floor == . and . >= 0 and . <= 9007199254740991;
    def clock: (keys | sort) == ["monotonic_milliseconds", "wall_epoch_seconds"] and
      (.wall_epoch_seconds | n) and (.monotonic_milliseconds | n);
    def sample($ordinal; $source; $ordering):
      . as $sample |
      ((keys | sort) == ["capture", "idle_interval_seconds", "ordering", "ordinal", "sleep"] and
      .ordinal == $ordinal and .idle_interval_seconds == $interval and .ordering == $ordering and
      (.sleep | ((keys | sort) == ["elapsed_monotonic_milliseconds", "elapsed_wall_seconds",
        "ended", "started"] and (.started | clock) and (.ended | clock) and
        (.elapsed_wall_seconds | n) and (.elapsed_monotonic_milliseconds | n) and
        .ended.wall_epoch_seconds >= .started.wall_epoch_seconds and
        .ended.monotonic_milliseconds >= .started.monotonic_milliseconds and
        .elapsed_wall_seconds == (.ended.wall_epoch_seconds - .started.wall_epoch_seconds) and
        .elapsed_monotonic_milliseconds ==
          (.ended.monotonic_milliseconds - .started.monotonic_milliseconds) and
        .elapsed_wall_seconds >= $interval and .elapsed_wall_seconds <= ($interval + 2) and
        .elapsed_monotonic_milliseconds >= ($interval * 1000) and
        .elapsed_monotonic_milliseconds <= (($interval + 2) * 1000))) and
      (.capture | ((keys | sort) == ["ended", "resource_snapshot", "started"] and
        .resource_snapshot == $source and (.started | clock) and (.ended | clock) and
        .started.wall_epoch_seconds >= $sample.sleep.ended.wall_epoch_seconds and
        .started.monotonic_milliseconds >= $sample.sleep.ended.monotonic_milliseconds and
        .ended.wall_epoch_seconds >= .started.wall_epoch_seconds and
        .ended.monotonic_milliseconds >= .started.monotonic_milliseconds)));
    length == 1 and (.[0] as $schedule |
      $schedule |
      ((keys | sort) == ["cell", "completed", "kind", "load_activity_between_samples",
        "required_consecutive_samples", "samples", "schema_version", "started", "status"] and
      .schema_version == 1 and .kind == "ordered-idle-recovery-schedule" and
      .status == "complete" and (.cell | test("^[a-z0-9][a-z0-9-]*$")) and
      .required_consecutive_samples == $required and
      .load_activity_between_samples == false and
      (.started | clock) and (.completed | clock) and
      (.samples | type == "array" and length == 2 and
        (.[0] | sample(1; "resources-idle-recovery-01"; "after_postload_sentinel")) and
        (.[1] | sample(2; "resources-idle-recovery-02";
          "after_recovery_01_without_intervening_workload"))) and
      .samples[0].sleep.started == .started and
      .samples[1].sleep.started.wall_epoch_seconds >= .samples[0].capture.ended.wall_epoch_seconds and
      .samples[1].sleep.started.monotonic_milliseconds >=
        .samples[0].capture.ended.monotonic_milliseconds and
      .completed.wall_epoch_seconds >= .samples[1].capture.ended.wall_epoch_seconds and
      .completed.monotonic_milliseconds >= .samples[1].capture.ended.monotonic_milliseconds))
  ' >/dev/null
}

validate_recovery_schedule_shape() {
  local -r artifact="$1"
  local schedule_value=""

  schedule_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_RECOVERY_SCHEDULE_BYTES")" || return 1
  validate_recovery_schedule_shape_json_value "$schedule_value"
}

validate_recovery_schedule_json_values() {
  local -r schedule_value="$1"
  local -r first_boundary_value="$2"
  local -r second_boundary_value="$3"
  local cell=""

  validate_recovery_schedule_shape_json_value "$schedule_value" || return 1
  cell="$(printf '%s' "$schedule_value" | jq -er '.cell')" || return 1
  validate_resource_snapshot_boundary_json_value \
    "$first_boundary_value" "$cell" idle_recovery_01 || return 1
  validate_resource_snapshot_boundary_json_value \
    "$second_boundary_value" "$cell" idle_recovery_02 || return 1
  printf '%s\n%s\n%s' "$schedule_value" "$first_boundary_value" \
    "$second_boundary_value" | jq -es '
      if length != 3 then error("expected schedule and two recovery boundaries")
      else . end |
      .[0] as $schedule |
      .[1] as $first |
      .[2] as $second |
      def encloses($outer; $inner):
        $inner.capture.started.wall_epoch_seconds >= $outer.started.wall_epoch_seconds and
        $inner.capture.started.monotonic_milliseconds >= $outer.started.monotonic_milliseconds and
        $inner.capture.ended.wall_epoch_seconds <= $outer.ended.wall_epoch_seconds and
        $inner.capture.ended.monotonic_milliseconds <= $outer.ended.monotonic_milliseconds;
      encloses($schedule.samples[0].capture; $first) and
      encloses($schedule.samples[1].capture; $second)
    ' >/dev/null
}

validate_recovery_schedule_schema() {
  local -r artifact="$1"
  local -r cell_directory="${artifact%/*}"
  local schedule_value=""
  local first_boundary_value=""
  local second_boundary_value=""

  schedule_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_RECOVERY_SCHEDULE_BYTES")" || return 1
  first_boundary_value="$(bounded_duplicate_free_json_value \
    "$cell_directory/resources-idle-recovery-01/snapshot.json" \
    "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  second_boundary_value="$(bounded_duplicate_free_json_value \
    "$cell_directory/resources-idle-recovery-02/snapshot.json" \
    "$MAX_BOUNDARY_SNAPSHOT_BYTES")" || return 1
  validate_recovery_schedule_json_values "$schedule_value" \
    "$first_boundary_value" "$second_boundary_value"
}

capture_ordered_idle_recovery() {
  local -r cell_dir="$1"
  local -r output="$cell_dir/recovery-schedule.json"
  local temporary=""
  local clocks=""
  local started_wall="" started_monotonic=""
  local sleep_01_ended_wall="" sleep_01_ended_monotonic=""
  local capture_01_started_wall="" capture_01_started_monotonic=""
  local capture_01_ended_wall="" capture_01_ended_monotonic=""
  local sleep_02_started_wall="" sleep_02_started_monotonic=""
  local sleep_02_ended_wall="" sleep_02_ended_monotonic=""
  local capture_02_started_wall="" capture_02_started_monotonic=""
  local capture_02_ended_wall="" capture_02_ended_monotonic=""
  local completed_wall="" completed_monotonic=""
  local elapsed_01="" elapsed_02=""
  local elapsed_01_wall="" elapsed_01_monotonic=""
  local elapsed_02_wall="" elapsed_02_monotonic="" extra=""

  [[ "$SLEEP_COMMAND" == /* && -f "$SLEEP_COMMAND" && -x "$SLEEP_COMMAND" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  clocks="$(clock_pair_values)" || return 1
  read -r started_wall started_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  "$SLEEP_COMMAND" "$IDLE_RECOVERY_INTERVAL_SECONDS" || return 1
  clocks="$(clock_pair_values)" || return 1
  read -r sleep_01_ended_wall sleep_01_ended_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  elapsed_01="$(validate_elapsed_clock_window \
    "$started_wall" "$started_monotonic" \
    "$sleep_01_ended_wall" "$sleep_01_ended_monotonic" \
    "$IDLE_RECOVERY_INTERVAL_SECONDS" \
    "$((IDLE_RECOVERY_INTERVAL_SECONDS + MIDPOINT_TIMING_OVERRUN_SECONDS))")" || return 1
  read -r elapsed_01_wall elapsed_01_monotonic extra <<<"$elapsed_01" || return 1
  [[ -z "$extra" ]] || return 1
  capture_01_started_wall="$sleep_01_ended_wall"
  capture_01_started_monotonic="$sleep_01_ended_monotonic"
  capture_resource_snapshot \
    "$cell_dir/resources-idle-recovery-01" idle_recovery_01 not_collected || return 1
  clocks="$(clock_pair_values)" || return 1
  read -r capture_01_ended_wall capture_01_ended_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  validate_elapsed_clock_window \
    "$capture_01_started_wall" "$capture_01_started_monotonic" \
    "$capture_01_ended_wall" "$capture_01_ended_monotonic" 0 >/dev/null || return 1
  sleep_02_started_wall="$capture_01_ended_wall"
  sleep_02_started_monotonic="$capture_01_ended_monotonic"
  "$SLEEP_COMMAND" "$IDLE_RECOVERY_INTERVAL_SECONDS" || return 1
  clocks="$(clock_pair_values)" || return 1
  read -r sleep_02_ended_wall sleep_02_ended_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  elapsed_02="$(validate_elapsed_clock_window \
    "$sleep_02_started_wall" "$sleep_02_started_monotonic" \
    "$sleep_02_ended_wall" "$sleep_02_ended_monotonic" \
    "$IDLE_RECOVERY_INTERVAL_SECONDS" \
    "$((IDLE_RECOVERY_INTERVAL_SECONDS + MIDPOINT_TIMING_OVERRUN_SECONDS))")" || return 1
  read -r elapsed_02_wall elapsed_02_monotonic extra <<<"$elapsed_02" || return 1
  [[ -z "$extra" ]] || return 1
  capture_02_started_wall="$sleep_02_ended_wall"
  capture_02_started_monotonic="$sleep_02_ended_monotonic"
  capture_resource_snapshot \
    "$cell_dir/resources-idle-recovery-02" idle_recovery_02 not_collected || return 1
  clocks="$(clock_pair_values)" || return 1
  read -r capture_02_ended_wall capture_02_ended_monotonic extra <<<"$clocks" || return 1
  [[ -z "$extra" ]] || return 1
  validate_elapsed_clock_window \
    "$capture_02_started_wall" "$capture_02_started_monotonic" \
    "$capture_02_ended_wall" "$capture_02_ended_monotonic" 0 >/dev/null || return 1
  completed_wall="$capture_02_ended_wall"
  completed_monotonic="$capture_02_ended_monotonic"
  temporary="$(mktemp "$cell_dir/.recovery-schedule.json.XXXXXX")" || return 1
  if ! jq -n --arg cell "$CELL_SLUG" \
    --argjson interval "$IDLE_RECOVERY_INTERVAL_SECONDS" \
    --argjson required "$IDLE_RECOVERY_REQUIRED_SAMPLES" \
    --argjson started_wall "$started_wall" --argjson started_monotonic "$started_monotonic" \
    --argjson sleep_01_ended_wall "$sleep_01_ended_wall" \
    --argjson sleep_01_ended_monotonic "$sleep_01_ended_monotonic" \
    --argjson capture_01_started_wall "$capture_01_started_wall" \
    --argjson capture_01_started_monotonic "$capture_01_started_monotonic" \
    --argjson capture_01_ended_wall "$capture_01_ended_wall" \
    --argjson capture_01_ended_monotonic "$capture_01_ended_monotonic" \
    --argjson sleep_02_started_wall "$sleep_02_started_wall" \
    --argjson sleep_02_started_monotonic "$sleep_02_started_monotonic" \
    --argjson sleep_02_ended_wall "$sleep_02_ended_wall" \
    --argjson sleep_02_ended_monotonic "$sleep_02_ended_monotonic" \
    --argjson capture_02_started_wall "$capture_02_started_wall" \
    --argjson capture_02_started_monotonic "$capture_02_started_monotonic" \
    --argjson capture_02_ended_wall "$capture_02_ended_wall" \
    --argjson capture_02_ended_monotonic "$capture_02_ended_monotonic" \
    --argjson completed_wall "$completed_wall" --argjson completed_monotonic "$completed_monotonic" \
    --argjson elapsed_01_wall "$elapsed_01_wall" \
    --argjson elapsed_01_monotonic "$elapsed_01_monotonic" \
    --argjson elapsed_02_wall "$elapsed_02_wall" \
    --argjson elapsed_02_monotonic "$elapsed_02_monotonic" '{
      schema_version: 1,
      kind: "ordered-idle-recovery-schedule",
      status: "complete",
      cell: $cell,
      required_consecutive_samples: $required,
      load_activity_between_samples: false,
      started: {wall_epoch_seconds: $started_wall,
        monotonic_milliseconds: $started_monotonic},
      samples: [
        {
          ordinal: 1, idle_interval_seconds: $interval,
          ordering: "after_postload_sentinel",
          sleep: {
            started: {wall_epoch_seconds: $started_wall,
              monotonic_milliseconds: $started_monotonic},
            ended: {wall_epoch_seconds: $sleep_01_ended_wall,
              monotonic_milliseconds: $sleep_01_ended_monotonic},
            elapsed_wall_seconds: $elapsed_01_wall,
            elapsed_monotonic_milliseconds: $elapsed_01_monotonic
          },
          capture: {
            started: {wall_epoch_seconds: $capture_01_started_wall,
              monotonic_milliseconds: $capture_01_started_monotonic},
            ended: {wall_epoch_seconds: $capture_01_ended_wall,
              monotonic_milliseconds: $capture_01_ended_monotonic},
            resource_snapshot: "resources-idle-recovery-01"
          }
        },
        {
          ordinal: 2, idle_interval_seconds: $interval,
          ordering: "after_recovery_01_without_intervening_workload",
          sleep: {
            started: {wall_epoch_seconds: $sleep_02_started_wall,
              monotonic_milliseconds: $sleep_02_started_monotonic},
            ended: {wall_epoch_seconds: $sleep_02_ended_wall,
              monotonic_milliseconds: $sleep_02_ended_monotonic},
            elapsed_wall_seconds: $elapsed_02_wall,
            elapsed_monotonic_milliseconds: $elapsed_02_monotonic
          },
          capture: {
            started: {wall_epoch_seconds: $capture_02_started_wall,
              monotonic_milliseconds: $capture_02_started_monotonic},
            ended: {wall_epoch_seconds: $capture_02_ended_wall,
              monotonic_milliseconds: $capture_02_ended_monotonic},
            resource_snapshot: "resources-idle-recovery-02"
          }
        }
      ],
      completed: {wall_epoch_seconds: $completed_wall,
        monotonic_milliseconds: $completed_monotonic}
    }' >"$temporary" || ! validate_recovery_schedule_schema "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  mv -T -- "$temporary" "$output" || {
    rm -f -- "$temporary"
    return 1
  }
  validate_recovery_schedule_schema "$output"
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
    capture_resource_snapshot \
      "$cell_dir/program-metrics-baseline" program_metrics_baseline not_collected
    begin_java_measurement_with_classification "$cell_dir" || return 1
    capture_cpu_measurement_snapshot \
      "$cell_dir/cpu-measurement-baseline" cpu_measurement_baseline

    for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
      log_info "measuring $CELL_SLUG repetition $repetition/$REPETITIONS"
      run_measurement_rep "$cell_dir" "$repetition"
      if [[ "$CELL_SUSTAINED_W3C" == "true" ]]; then
        printf -v repetition_label 'rep-%02d' "$repetition"
        record_w3c_workload_successes "$cell_dir/measurements/$repetition_label.json"
      fi
    done
    capture_cpu_measurement_snapshot \
      "$cell_dir/cpu-measurement-end" cpu_measurement_end
    stop_java_measurement_with_classification "$cell_dir" || return 1
    capture_resource_snapshot \
      "$cell_dir/program-metrics-end" program_metrics_end not_collected
    finish_java_measurement_with_classification "$cell_dir" || return 1
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
  write_exact_owned_cgroup_sockopt_runtime "$cell_dir"
  capture_resource_snapshot "$cell_dir/resources-after-load" after
  run_postload_sentinel "$cell_dir"
  capture_ordered_idle_recovery "$cell_dir"
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
  local -r output_name="${2:-}"
  local artifact_root=""
  local expected=""
  local observed_value=""
  local expected_raw_value_count=""
  local observed_raw_value_count=""

  observed_value="$(bounded_duplicate_free_json_value \
    "$artifact" "$MAX_VARIANCE_BYTES")" || return 1
  artifact_root="$(cd -- "${artifact%/*}" && pwd -P)" || return 1
  expected="$(variance_summary_json "$artifact_root")" || return 1
  expected_raw_value_count="$(jq --stream -n '
    reduce inputs as $event (0;
      if ($event | length) == 2 then . + 1 else . end)
  ' <<<"$expected")" || return 1
  observed_raw_value_count="$(raw_json_value_count_from_value \
    "$observed_value")" || return 1
  [[ "$expected_raw_value_count" =~ ^[1-9][0-9]*$ &&
    "$observed_raw_value_count" == "$expected_raw_value_count" ]] || return 1
  printf '%s' "$observed_value" | jq -se \
    --argjson required_repetitions "$REQUIRED_REPETITIONS" '
    def finite_nonnegative: type == "number" and isfinite and . >= 0;
    def population_is_exact:
      ((keys | sort) == [
        "coefficient_of_variation_percent", "mean", "population_standard_deviation",
        "population_variance", "sample_count", "squared_deviation_sum", "sum"
      ]) and
      .sample_count == $required_repetitions and
      (.sum | type == "number" and isfinite and . > 0) and
      (.mean | type == "number" and isfinite and . > 0) and
      (.squared_deviation_sum | finite_nonnegative) and
      (.population_variance | finite_nonnegative) and
      (.population_standard_deviation | finite_nonnegative) and
      (.coefficient_of_variation_percent | finite_nonnegative);
    length == 1 and (.[0] |
      ((keys | sort) == [
        "acceptance_evidence", "aggregation", "cells", "kind", "manifest",
        "notes", "schema_version", "status"
      ]) and
      .schema_version == 2 and
      .kind == "application-performance-repetition-summary" and
      .status == "complete" and .acceptance_evidence == false and
      .manifest == "manifest.json" and
      ([.cells[].cell] == [
        "uninstrumented", "bridge-disabled", "getsockopt-hit", "unix-hit",
        "getsockopt-w3c", "getsockopt-helper-idle"
      ]) and
      all(.cells[];
        ((keys | sort) == [
          "cell", "contract", "expected_sample_count", "samples", "statistics",
          "valid_sample_count"
        ]) and
        .expected_sample_count == $required_repetitions and
        .valid_sample_count == $required_repetitions and
        (.samples | length) == $required_repetitions and
        ([.samples[].repetition] == [1, 2, 3, 4, 5]) and
        (.statistics.throughput_per_second.population_variability |
          population_is_exact) and
        (.statistics.latency.p99_nanos.population_variability |
          population_is_exact)))
  ' >/dev/null || return 1
  printf '%s\n%s' "$expected" "$observed_value" | jq -es '
    length == 2 and .[1] == .[0]
  ' >/dev/null || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$observed_value"
  fi
}

terminal_publication_session_clear() {
  TERMINAL_SOURCE_SESSION_ACTIVE=false
  TERMINAL_SOURCE_SESSION_FROZEN=false
  TERMINAL_SOURCE_SESSION_PREPARED=false
  TERMINAL_SOURCE_RECORD_FD=""
  TERMINAL_SOURCE_RESPONSE_FD=""
  TERMINAL_SOURCE_HELPER_PID=""
  TERMINAL_SOURCE_OUTPUT_ROOT=""
  TERMINAL_SOURCE_REPOSITORY_ROOT=""
  TERMINAL_SOURCE_ROSTER_VALUE=""
  TERMINAL_NATIVE_SIGNAL_TEST_HOOK=none
}

# Start one descriptor-only authority collector before any terminal source
# reads. The same trusted process later owns all anonymous candidates and every
# terminal link, so no pathname handoff exists between the final source check
# and the completion marker.
terminal_publication_session_begin() {
  local output_identity=""
  local repository_identity=""
  local open_file_limit=""
  local native_read_fd=""
  local native_write_fd=""
  local helper_ready=""

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == false &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false &&
    -z "$TERMINAL_SOURCE_HELPER_PID" && "$OUTPUT_DIR" == /* &&
    -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" &&
    "$REPO_ROOT" == /* && -d "$REPO_ROOT" && ! -L "$REPO_ROOT" ]] || return 1
  resolve_benchmark_identity_tools || return 1
  output_identity="$(stat --format '%d:%i:%u:%g:%a' -- "$OUTPUT_DIR")" || return 1
  repository_identity="$(stat --format '%d:%i:%u:%g:%a' -- "$REPO_ROOT")" || return 1
  [[ -n "$OUTPUT_DIR_IDENTITY" && "$output_identity" == "$OUTPUT_DIR_IDENTITY" ]] || return 1
  open_file_limit="$(ulimit -n)" || return 1
  [[ "$open_file_limit" == unlimited ||
    ( "$open_file_limit" =~ ^[1-9][0-9]*$ &&
      "$open_file_limit" -ge "$MIN_TERMINAL_SOURCE_NOFILE_LIMIT" ) ]] || return 1

  coproc TERMINAL_SOURCE_NATIVE_HELPER {
    # This coprocess itself becomes the authenticated Perl authority. POSIX
    # special-builtin lookup prevents an imported exec() function from
    # interposing, while exec -c clears the environment before env(1)'s loader.
    POSIXLY_CORRECT=1
    [[ -o posix ]] || exit 1
    exec -c "$NATIVE_BENCHMARK_ENV_COMMAND" -i \
      "PATH=$NATIVE_BENCHMARK_TRUSTED_PATH" LC_ALL=C \
      "$NATIVE_BENCHMARK_PERL_COMMAND" -T \
      -MFcntl=:DEFAULT,:mode -MDigest::SHA=sha1_hex,sha256_hex \
      -MJSON::PP=decode_json -MErrno=ENOENT \
      -MPOSIX=SIG_BLOCK,SIG_UNBLOCK,SIG_SETMASK,SIGINT,SIGTERM,SIGHUP,SIGQUIT,SIGALRM,WNOHANG,sigprocmask -e '
        use strict;
        use warnings;
        require "syscall.ph";
        use constant O_PATH_LINUX => 010000000;
        use constant O_TMPFILE_LINUX => 020000000 | O_DIRECTORY;
        use constant AT_EMPTY_PATH_LINUX => 0x1000;

        our $ACTIVE_CHILD_PID = 0;
        my $git_child_signal_set = POSIX::SigSet->new(
          SIGHUP, SIGINT, SIGTERM, SIGALRM, SIGQUIT);
        # Block every handled signal before installing any handler. This
        # closes the startup race without disturbing unrelated inherited mask
        # bits; the exact handled set is normalized after handler installation.
        defined(sigprocmask(SIG_BLOCK, $git_child_signal_set)) or
          POSIX::_exit(1);
        sub fail {
          # A signal handler must own the active child through its exact reap.
          # Blocking the full handled set prevents a second handler from
          # observing ACTIVE_CHILD_PID after it has been cleared but before
          # waitpid has completed.
          my $discarded_mask = POSIX::SigSet->new();
          sigprocmask(SIG_BLOCK, $git_child_signal_set, $discarded_mask);
          if ($ACTIVE_CHILD_PID > 0) {
            my $child = $ACTIVE_CHILD_PID;
            $ACTIVE_CHILD_PID = 0;
            kill(9, $child);
            waitpid($child, 0);
          }
          POSIX::_exit(1);
        }
        sub exact_integer {
          my ($value, $positive) = @_;
          defined($value) && "$value" =~ /\A(0|[1-9][0-9]*)\z/ or fail();
          my $integer = 0 + $1;
          $integer <= 9007199254740991 && (!$positive || $integer > 0) or fail();
          return $integer;
        }
        sub safe_path {
          my ($value) = @_;
          defined($value) && length($value) <= 4096 &&
            $value =~ m{\A(/(?:[^/\0\r\n]+/)*[^/\0\r\n]+)\z} or fail();
          return $1;
        }
        sub safe_relative {
          my ($value, $maximum) = @_;
          defined($value) && length($value) > 0 && length($value) <= $maximum &&
            $value =~ m{\A([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)\z} or fail();
          my $path = $1;
          for my $component (split(m{/}, $path)) {
            length($component) && $component ne q{.} && $component ne q{..} or fail();
          }
          return $path;
        }
        sub expected_identity {
          my ($value) = @_;
          defined($value) &&
            $value =~ /\A([0-9]+:[1-9][0-9]*:[0-9]+:[0-9]+:[0-7]{3,4})\z/ or fail();
          return $1;
        }
        sub directory_identity {
          my ($handle) = @_;
          my @stat = stat($handle);
          @stat && S_ISDIR($stat[2]) or fail();
          return join(q{:}, $stat[0], $stat[1], $stat[4], $stat[5],
            sprintf(q{%o}, $stat[2] & 07777));
        }
        sub directory_evidence_identity {
          my ($handle) = @_;
          my @stat = stat($handle);
          @stat && S_ISDIR($stat[2]) or fail();
          return join(q{:}, @stat[0,1,2,3,4,5,6]);
        }
        sub leaf_identity {
          my ($handle) = @_;
          my @stat = stat($handle);
          @stat && S_ISREG($stat[2]) && $stat[7] > 0 or fail();
          return join(q{:}, @stat[0,1,2,3,4,5,6,7]);
        }
        sub openat_handle {
          my ($directory, $name, $flags) = @_;
          my $fd = syscall(SYS_openat(), fileno($directory), $name, $flags, 0);
          $fd >= 0 or return;
          open(my $handle, q{<&=}, $fd) or fail();
          return $handle;
        }
        sub digest_handle {
          my ($handle, $size, $maximum) = @_;
          $size > 0 && $size <= $maximum or fail();
          sysseek($handle, 0, 0) == 0 or fail();
          my $sha = Digest::SHA->new(256);
          my $total = 0;
          while ($total < $size) {
            my $chunk = q{};
            my $wanted = $size - $total;
            $wanted = 1048576 if $wanted > 1048576;
            my $read = sysread($handle, $chunk, $wanted);
            defined($read) && $read > 0 or fail();
            $total += $read;
            $total <= $size or fail();
            $sha->add($chunk);
          }
          my $extra = q{};
          my $read = sysread($handle, $extra, 1);
          defined($read) && $read == 0 or fail();
          return $sha->hexdigest;
        }
        sub directory_names {
          my ($directory, $maximum_entries, $maximum_bytes,
            $allow_line_breaks) = @_;
          $allow_line_breaks //= 0;
          ($allow_line_breaks == 0 || $allow_line_breaks == 1) or fail();
          sysseek($directory, 0, 0) == 0 or fail();
          my @names;
          my $total_bytes = 0;
          while (1) {
            my $buffer = "\0" x 8192;
            my $count = syscall(SYS_getdents64(), fileno($directory),
              $buffer, length($buffer));
            defined($count) && $count >= 0 or fail();
            last if $count == 0;
            $total_bytes += $count;
            $total_bytes <= $maximum_bytes or fail();
            my $offset = 0;
            while ($offset < $count) {
              $count - $offset >= 20 or fail();
              my (undef, undef, $record_length, undef) =
                unpack(q{QqSC}, substr($buffer, $offset, 19));
              $record_length >= 20 && $offset + $record_length <= $count or fail();
              my $field = substr($buffer, $offset + 19, $record_length - 19);
              my $nul = index($field, "\0");
              $nul > 0 or fail();
              my $name = substr($field, 0, $nul);
              if ($name ne q{.} && $name ne q{..}) {
                if ($allow_line_breaks) {
                  $name =~ /\A([^\/\0]{1,255})\z/s or fail();
                  $name = $1;
                } else {
                  $name =~ /\A([^\/\0\r\n]{1,255})\z/ or fail();
                  $name = $1;
                }
                push @names, $name;
                @names <= $maximum_entries or fail();
              }
              $offset += $record_length;
            }
            $offset == $count or fail();
          }
          @names = sort @names;
          for (my $index = 1; $index < @names; $index++) {
            $names[$index] ne $names[$index - 1] or fail();
          }
          return @names;
        }
        sub decoded_json {
          my ($bytes) = @_;
          defined($bytes) && length($bytes) > 0 && index($bytes, "\0") < 0 or fail();
          my $decoded = eval { decode_json($bytes) };
          $@ eq q{} or fail();
          return $decoded;
        }
        our $INPUT_BUFFER = q{};
        sub read_line {
          my ($maximum) = @_;
          while (1) {
            my $newline = index($INPUT_BUFFER, qq{\n});
            if ($newline >= 0) {
              $newline <= $maximum or fail();
              my $line = substr($INPUT_BUFFER, 0, $newline, q{});
              substr($INPUT_BUFFER, 0, 1, q{});
              $line !~ /[\r\n\0]/ or fail();
              return $line;
            }
            length($INPUT_BUFFER) <= $maximum or fail();
            my $chunk = q{};
            my $read = sysread(STDIN, $chunk, 8192);
            defined($read) && $read > 0 or fail();
            $INPUT_BUFFER .= $chunk;
          }
        }
        sub read_exact {
          my ($length) = @_;
          my $bytes = q{};
          if (length($INPUT_BUFFER)) {
            my $take = length($INPUT_BUFFER) < $length ?
              length($INPUT_BUFFER) : $length;
            $bytes = substr($INPUT_BUFFER, 0, $take, q{});
          }
          while (length($bytes) < $length) {
            my $chunk = q{};
            my $wanted = $length - length($bytes);
            $wanted = 1048576 if $wanted > 1048576;
            my $read = sysread(STDIN, $chunk, $wanted);
            defined($read) && $read > 0 or fail();
            $bytes .= $chunk;
          }
          length($bytes) == $length && index($bytes, "\0") < 0 or fail();
          return $bytes;
        }

        my ($output_path, $expected_output, $repository_path, $expected_repository,
          $git_path, $maximum_git_output, $maximum_git_index_entries,
          $maximum_git_worktree_bytes,
          $maximum_leaves, $maximum_directories, $maximum_trees,
          $maximum_checkouts, $maximum_negatives, $maximum_selectors,
          $maximum_records,
          $maximum_held_fds, $maximum_tree_entries, $maximum_tree_manifest,
          $maximum_record,
          $maximum_path, $maximum_roster, $maximum_source_bytes,
          $maximum_poc, $maximum_manifest, $maximum_summary, $deadline,
          $commit_deadline, $signal_test_hook) = @ARGV;
        $output_path = safe_path($output_path);
        $repository_path = safe_path($repository_path);
        $git_path = safe_path($git_path);
        $expected_output = expected_identity($expected_output);
        $expected_repository = expected_identity($expected_repository);
        $maximum_git_output = exact_integer($maximum_git_output, 1);
        $maximum_git_index_entries = exact_integer($maximum_git_index_entries, 1);
        $maximum_git_worktree_bytes = exact_integer($maximum_git_worktree_bytes, 1);
        $maximum_leaves = exact_integer($maximum_leaves, 1);
        $maximum_directories = exact_integer($maximum_directories, 1);
        $maximum_trees = exact_integer($maximum_trees, 1);
        $maximum_checkouts = exact_integer($maximum_checkouts, 1);
        $maximum_negatives = exact_integer($maximum_negatives, 1);
        $maximum_selectors = exact_integer($maximum_selectors, 1);
        $maximum_records = exact_integer($maximum_records, 1);
        $maximum_held_fds = exact_integer($maximum_held_fds, 1);
        $maximum_tree_entries = exact_integer($maximum_tree_entries, 1);
        $maximum_tree_manifest = exact_integer($maximum_tree_manifest, 1);
        $maximum_record = exact_integer($maximum_record, 1);
        $maximum_path = exact_integer($maximum_path, 1);
        $maximum_roster = exact_integer($maximum_roster, 1);
        $maximum_source_bytes = exact_integer($maximum_source_bytes, 1);
        $maximum_poc = exact_integer($maximum_poc, 1);
        $maximum_manifest = exact_integer($maximum_manifest, 1);
        $maximum_summary = exact_integer($maximum_summary, 1);
        $deadline = exact_integer($deadline, 1);
        $commit_deadline = exact_integer($commit_deadline, 1);
        defined($signal_test_hook) &&
          $signal_test_hook =~ /\A(none|(?:capture|capture-with-input):(?:pre-registration|post-wait|stopped-after-eof):(?:TERM|ALRM))\z/ or fail();
        $signal_test_hook = $1;
        $SIG{ALRM} = sub { fail(); };
        $SIG{INT} = sub { fail(); };
        $SIG{TERM} = sub { fail(); };
        $SIG{HUP} = sub { fail(); };
        $SIG{QUIT} = sub { fail(); };
        defined(sigprocmask(SIG_UNBLOCK, $git_child_signal_set)) or fail();
        my $normalized_signal_mask = POSIX::SigSet->new();
        my $empty_signal_set = POSIX::SigSet->new();
        defined(sigprocmask(SIG_BLOCK, $empty_signal_set,
          $normalized_signal_mask)) or fail();
        for my $handled_signal (SIGHUP, SIGINT, SIGTERM, SIGALRM, SIGQUIT) {
          !$normalized_signal_mask->ismember($handled_signal) or fail();
        }
        alarm($deadline);
        binmode(STDIN) or fail();
        binmode(STDOUT) or fail();
        select(STDOUT); $| = 1;

        sysopen(my $output_root, $output_path,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW) or fail();
        sysopen(my $repository_root, $repository_path,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW) or fail();
        sysopen(my $git_handle, $git_path, O_RDONLY | O_NOFOLLOW) or fail();
        my @git_stat = stat($git_handle);
        @git_stat && S_ISREG($git_stat[2]) && $git_stat[4] == 0 &&
          ($git_stat[2] & 0022) == 0 && ($git_stat[2] & 0111) != 0 or fail();
        directory_identity($output_root) eq $expected_output or fail();
        directory_identity($repository_root) eq $expected_repository or fail();
        defined(&SYS_openat) && defined(&SYS_linkat) &&
          defined(&SYS_unlinkat) && defined(&SYS_getdents64) &&
          defined(&SYS_readlinkat) or fail();
        my $probe_dot = q{.};
        my $probe_name = q{.obi-terminal-linkat-probe-} . $$;
        my $probe_existing = openat_handle($output_root, $probe_name,
          O_PATH_LINUX | O_NOFOLLOW);
        if (defined($probe_existing)) {
          close($probe_existing);
          fail();
        }
        $! == ENOENT or fail();
        my $probe_fd = syscall(SYS_openat(), fileno($output_root), $probe_dot,
          O_RDWR | O_TMPFILE_LINUX, 0600);
        $probe_fd >= 0 or fail();
        open(my $probe_handle, q{+<&=}, $probe_fd) or fail();
        my @probe_unlinked = stat($probe_handle);
        @probe_unlinked && S_ISREG($probe_unlinked[2]) &&
          ($probe_unlinked[2] & 07777) == 0600 && $probe_unlinked[3] == 0 &&
          $probe_unlinked[4] == $< && $probe_unlinked[7] == 0 or fail();
        my $probe_empty = q{};
        syscall(SYS_linkat(), fileno($probe_handle), $probe_empty,
          fileno($output_root), $probe_name, AT_EMPTY_PATH_LINUX) == 0 or fail();
        my $probe_valid = 1;
        my $probe_linked = openat_handle($output_root, $probe_name,
          O_RDONLY | O_NOFOLLOW);
        if (defined($probe_linked)) {
          my @probe_linked_stat = stat($probe_linked);
          $probe_valid = 0 unless @probe_linked_stat &&
            $probe_linked_stat[0] == $probe_unlinked[0] &&
            $probe_linked_stat[1] == $probe_unlinked[1] &&
            S_ISREG($probe_linked_stat[2]) &&
            ($probe_linked_stat[2] & 07777) == 0600 &&
            $probe_linked_stat[3] == 1 && $probe_linked_stat[4] == $< &&
            $probe_linked_stat[7] == 0;
          $probe_valid = 0 unless close($probe_linked);
        } else {
          $probe_valid = 0;
        }
        my $probe_unlink_status = syscall(SYS_unlinkat(), fileno($output_root),
          $probe_name, 0);
        $probe_unlink_status == 0 or fail();
        my $probe_after_name = openat_handle($output_root, $probe_name,
          O_PATH_LINUX | O_NOFOLLOW);
        if (defined($probe_after_name)) {
          close($probe_after_name);
          fail();
        }
        $! == ENOENT or fail();
        my @probe_after = stat($probe_handle);
        $probe_valid && @probe_after && $probe_after[0] == $probe_unlinked[0] &&
          $probe_after[1] == $probe_unlinked[1] && $probe_after[3] == 0 &&
          close($probe_handle) or fail();
        print qq{H:READY\n};
        my %roots = (output => $output_root, repository => $repository_root);
        my %root_paths = (output => $output_path, repository => $repository_path);
        my %directories;
        my %directory_handles;
        my %leaves;
        my %leaf_handles;
        my %trees;
        my %tree_handles;
        my %checkouts;
        my %compacted_leaves;
        my %negatives;
        my %selectors;
        for my $root_name (sort keys %roots) {
          my $key = $root_name . q{/};
          $directories{$key} = {
            root => $root_name, path => q{.},
            identity => directory_evidence_identity($roots{$root_name})
          };
          $directory_handles{$key} = $roots{$root_name};
        }

        sub open_source_leaf {
          my ($locator, $fresh_walk) = @_;
          $locator =~ m{\A(output|repository)/(.+)\z} or fail();
          my ($root_name, $relative) = ($1, safe_relative($2, $maximum_path));
          my @parts = split(m{/}, $relative);
          my $leaf_name = pop @parts;
          my $directory = $roots{$root_name};
          my $path = q{};
          for my $component (@parts) {
            $path = length($path) ? $path . q{/} . $component : $component;
            my $key = $root_name . q{/} . $path;
            if (!$fresh_walk && exists $directory_handles{$key}) {
              $directory = $directory_handles{$key};
              next;
            }
            my $opened = openat_handle($directory, $component,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            defined($opened) or fail();
            if ($fresh_walk) {
              exists($directories{$key}) &&
                directory_evidence_identity($opened) eq
                  $directories{$key}->{identity} or fail();
            } else {
              scalar(keys %directories) < $maximum_directories or fail();
              $directories{$key} = {
                root => $root_name, path => $path,
                identity => directory_evidence_identity($opened)
              };
              $directory_handles{$key} = $opened;
            }
            $directory = $opened;
          }
          my $leaf = openat_handle($directory, $leaf_name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
          defined($leaf) or fail();
          return ($root_name, $relative, $leaf);
        }
        sub open_source_directory {
          my ($locator, $fresh_walk, $record_new) = @_;
          $locator =~ m{\A(output|repository)/(.+)\z} or fail();
          my ($root_name, $relative) = ($1, $2);
          $relative = safe_relative($relative, $maximum_path)
            unless $relative eq q{.};
          my @parts = $relative eq q{.} ? () : split(m{/}, $relative);
          my $directory = $roots{$root_name};
          my $path = q{};
          for my $component (@parts) {
            $path = length($path) ? $path . q{/} . $component : $component;
            my $key = $root_name . q{/} . $path;
            if (!$fresh_walk && exists $directory_handles{$key}) {
              $directory = $directory_handles{$key};
              next;
            }
            my $opened = openat_handle($directory, $component,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            defined($opened) or fail();
            if (exists $directories{$key}) {
              directory_evidence_identity($opened) eq
                $directories{$key}->{identity} or fail();
            } elsif ($record_new) {
              scalar(keys %directories) < $maximum_directories or fail();
              $directories{$key} = {
                root => $root_name, path => $path,
                identity => directory_evidence_identity($opened)
              };
            } else {
              fail();
            }
            if (!$fresh_walk) {
              $directory_handles{$key} = $opened;
            }
            $directory = $opened;
          }
          return ($root_name, $relative, $directory);
        }
        sub open_negative_node {
          my ($locator, $fresh_walk, $record_new) = @_;
          $locator =~ m{\A(output|repository)/(.+)\z} or fail();
          my ($root_name, $relative) = ($1, safe_relative($2, $maximum_path));
          my @parts = split(m{/}, $relative);
          my $name = pop @parts;
          my $directory = $roots{$root_name};
          my $path = q{};
          for my $component (@parts) {
            $path = length($path) ? $path . q{/} . $component : $component;
            my $key = $root_name . q{/} . $path;
            if (!$fresh_walk && exists $directory_handles{$key}) {
              $directory = $directory_handles{$key};
              next;
            }
            my $opened = openat_handle($directory, $component,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            if (!defined($opened)) {
              $! == ENOENT or fail();
              return ($root_name, $relative, $directory, $name, undef, $path);
            }
            if (exists $directories{$key}) {
              directory_evidence_identity($opened) eq
                $directories{$key}->{identity} or fail();
            } elsif ($record_new) {
              scalar(keys %directories) < $maximum_directories or fail();
              $directories{$key} = {
                root => $root_name, path => $path,
                identity => directory_evidence_identity($opened)
              };
            } else {
              fail();
            }
            if (!$fresh_walk) {
              $directory_handles{$key} = $opened;
            }
            $directory = $opened;
          }
          my $handle = openat_handle($directory, $name,
            O_PATH_LINUX | O_NOFOLLOW);
          if (!defined($handle)) {
            $! == ENOENT or fail();
            return ($root_name, $relative, $directory, $name, undef, $relative);
          }
          return ($root_name, $relative, $directory, $name, $handle, undef);
        }
        sub verify_named_root {
          my ($name, $path, $expected, $held) = @_;
          sysopen(my $fresh, $path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW) or fail();
          directory_identity($fresh) eq $expected &&
            directory_evidence_identity($fresh) eq directory_evidence_identity($held) or fail();
          close($fresh) or fail();
        }
        sub simple_directory_identity {
          my ($handle) = @_;
          my @stat = stat($handle);
          @stat && S_ISDIR($stat[2]) or fail();
          return join(q{:}, $stat[0], $stat[1], $stat[4],
            sprintf(q{%o}, $stat[2] & 07777));
        }
        sub manifest_entry_identity {
          my ($stat) = @_;
          return join(q{:}, $stat->[0], $stat->[1], $stat->[4],
            sprintf(q{%o}, $stat->[2] & 07777), $stat->[7]);
        }
        sub negative_evidence {
          my ($locator, $maximum, $fresh_walk, $record_new) = @_;
          my ($root_name, $relative, $parent, $name, $handle, $missing_path) =
            open_negative_node($locator, $fresh_walk, $record_new);
          if (!defined($handle)) {
            defined($missing_path) && length($missing_path) or fail();
            return {root => $root_name, path => $relative,
              maximum_bytes => $maximum, state => q{absent},
              missing_path => $missing_path,
              identity => undef, size_bytes => undef};
          }
          my @stat = stat($handle);
          @stat or fail();
          my $state = q{};
          if (!S_ISREG($stat[2])) { $state = q{nonregular}; }
          elsif ($stat[7] == 0) { $state = q{empty}; }
          elsif ($stat[7] > $maximum) { $state = q{oversize}; }
          else { fail(); }
          my $evidence = {root => $root_name, path => $relative,
            maximum_bytes => $maximum, state => $state,
            missing_path => undef,
            identity => join(q{:}, @stat[0,1,2,3,4,5,6,7]),
            size_bytes => 0 + $stat[7]};
          close($handle) or fail();
          return $evidence;
        }
        sub selector_evidence {
          my ($locator, $selector, $fresh_walk, $record_new) = @_;
          ($selector eq q{benchmark-repetition-json} ||
            $selector eq q{pressure-recovery-sample-prom}) or fail();
          my ($root_name, $relative, $directory) = open_source_directory(
            $locator, $fresh_walk, $record_new);
          my @all_names = directory_names($directory,
            $maximum_tree_entries, $maximum_tree_manifest);
          my (@names, @expected_names);
          if ($selector eq q{benchmark-repetition-json}) {
            @names = grep { /\Arep-[0-9][0-9]\.json\z/ } @all_names;
            @expected_names = map { sprintf(q{rep-%02d.json}, $_) } (1 .. 5);
          } else {
            @names = grep {
              /\Amap-pressure-pressure-recovered-sample-[0-9][0-9]\.prom\z/
            } @all_names;
            @expected_names = map {
              sprintf(q{map-pressure-pressure-recovered-sample-%02d.prom}, $_)
            } (1 .. 2);
          }
          join(qq{\n}, @names) eq join(qq{\n}, @expected_names) or fail();
          return {root => $root_name, path => $relative,
            identity => directory_evidence_identity($directory),
            selector => $selector, names => \@names};
        }
        sub verify_git_executable {
          sysopen(my $fresh, $git_path, O_RDONLY | O_NOFOLLOW) or fail();
          my @fresh_stat = stat($fresh);
          @fresh_stat && @git_stat &&
            join(q{:}, @fresh_stat[0,1,2,3,4,5,6,7]) eq
              join(q{:}, @git_stat[0,1,2,3,4,5,6,7]) or fail();
          close($fresh) or fail();
        }
        sub mask_git_child_signals {
          my $previous_mask = POSIX::SigSet->new();
          defined(sigprocmask(SIG_BLOCK, $git_child_signal_set,
            $previous_mask)) or fail();
          return $previous_mask;
        }
        sub restore_git_child_signal_mask {
          my ($previous_mask) = @_;
          defined($previous_mask) &&
            defined(sigprocmask(SIG_SETMASK, $previous_mask)) or fail();
        }
        sub git_signal_test_hook_matches {
          my ($kind, $point) = @_;
          return 0 if $signal_test_hook eq q{none};
          my ($expected_kind, $expected_point) =
            split(q{:}, $signal_test_hook, -1);
          return $kind eq $expected_kind && $point eq $expected_point;
        }
        sub git_signal_test_hook {
          my ($kind, $point, $child, $child_reaped) = @_;
          return unless git_signal_test_hook_matches($kind, $point);
          my ($expected_kind, $expected_point, $signal) =
            split(q{:}, $signal_test_hook, -1);
          my $marker = join(q{:}, q{X}, q{GIT-SIGNAL}, $kind, $point,
            $child, $signal);
          if (!print($marker . qq{\n}) || kill($signal, $$) != 1) {
            $ACTIVE_CHILD_PID = $child unless $child_reaped;
            fail();
          }
        }
        sub reap_git_child_bounded {
          my ($kind, $child) = @_;
          while (1) {
            my $wait_mask = mask_git_child_signals();
            my $waited = waitpid($child, WNOHANG);
            my $status = $?;
            if ($waited == $child) {
              $ACTIVE_CHILD_PID = 0;
              git_signal_test_hook($kind, q{post-wait}, $child, 1);
              restore_git_child_signal_mask($wait_mask);
              return $status;
            }
            $waited == 0 or fail();
            # The session deadline must remain deliverable while a live or
            # stopped exact child is between bounded nonblocking polls.
            !$wait_mask->ismember(SIGALRM) or fail();
            restore_git_child_signal_mask($wait_mask);
            git_signal_test_hook($kind, q{stopped-after-eof}, $child, 0);
            # A ten-millisecond maximum poll interval keeps this loop bounded;
            # an ALRM or other handled signal interrupts it and reaps via fail.
            select(undef, undef, undef, 0.01);
          }
        }
        sub git_capture {
          my ($directory, $maximum, $allow_nul, @arguments) = @_;
          $maximum > 0 && $maximum <= $maximum_git_output or fail();
          ($allow_nul == 0 || $allow_nul == 1) or fail();
          verify_git_executable();
          pipe(my $reader, my $writer) or fail();
          my $registration_mask = mask_git_child_signals();
          my $child = fork();
          if (!defined($child)) {
            restore_git_child_signal_mask($registration_mask);
            fail();
          }
          if ($child == 0) {
            close($reader) or POSIX::_exit(126);
            open(STDOUT, q{>&}, $writer) or POSIX::_exit(126);
            open(STDERR, q{>&}, $writer) or POSIX::_exit(126);
            close($writer) or POSIX::_exit(126);
            if (git_signal_test_hook_matches(q{capture},
              q{stopped-after-eof})) {
              close(STDOUT) or POSIX::_exit(126);
              close(STDERR) or POSIX::_exit(126);
              kill(q{STOP}, $$) == 1 or POSIX::_exit(126);
              POSIX::_exit(125);
            }
            open(STDIN, q{<}, q{/dev/null}) or POSIX::_exit(126);
            defined(fcntl($git_handle, F_SETFD, 0)) or POSIX::_exit(126);
            defined(fcntl($directory, F_SETFD, 0)) or POSIX::_exit(126);
            my $git_descriptor = q{/proc/self/fd/} . fileno($git_handle);
            my $checkout_descriptor = q{/proc/self/fd/} . fileno($directory);
            %ENV = (
              PATH => q{/usr/bin:/bin}, LC_ALL => q{C}, LANG => q{C},
              GIT_CONFIG_NOSYSTEM => q{1}, GIT_CONFIG_GLOBAL => q{/dev/null},
              GIT_OPTIONAL_LOCKS => q{0}, GIT_TERMINAL_PROMPT => q{0},
              GIT_PAGER => q{cat}, PAGER => q{cat},
              GIT_EXTERNAL_DIFF => q{/bin/false}, GIT_NO_REPLACE_OBJECTS => q{1}
            );
            defined(sigprocmask(SIG_SETMASK, $registration_mask)) or
              POSIX::_exit(126);
            exec {$git_descriptor} $git_path,
              q{-c}, q{core.hooksPath=/dev/null},
              q{-c}, q{core.fsmonitor=false},
              q{-c}, q{core.untrackedCache=false},
              q{-c}, q{core.trustctime=true},
              q{-c}, q{core.checkStat=default},
              q{-c}, q{core.fileMode=true},
              q{-c}, q{core.symlinks=true},
              q{-c}, q{pager.status=false},
              q{-c}, q{pager.diff=false},
              q{-C}, $checkout_descriptor, @arguments or POSIX::_exit(127);
          }
          git_signal_test_hook(q{capture}, q{pre-registration}, $child, 0);
          $ACTIVE_CHILD_PID = $child;
          close($writer) or fail();
          restore_git_child_signal_mask($registration_mask);
          binmode($reader) or fail();
          my $bytes = q{};
          while (1) {
            my $chunk = q{};
            my $read = sysread($reader, $chunk, 8192);
            defined($read) or fail();
            last if $read == 0;
            $bytes .= $chunk;
            length($bytes) <= $maximum or fail();
          }
          close($reader) or fail();
          my $status = reap_git_child_bounded(q{capture}, $child);
          $status == 0 or fail();
          $allow_nul || index($bytes, "\0") < 0 or fail();
          return $bytes;
        }
        sub git_capture_with_input {
          my ($directory, $maximum, $allow_nul, $input, @arguments) = @_;
          $maximum > 0 && $maximum <= $maximum_git_output &&
            length($input) > 0 && length($input) <= $maximum_git_output &&
            ($allow_nul == 0 || $allow_nul == 1) or fail();
          verify_git_executable();
          my $dot = q{.};
          my $input_fd = syscall(SYS_openat(), fileno($output_root), $dot,
            O_RDWR | O_TMPFILE_LINUX, 0600);
          $input_fd >= 0 or fail();
          open(my $input_handle, q{+<&=}, $input_fd) or fail();
          my $offset = 0;
          while ($offset < length($input)) {
            my $written = syswrite($input_handle, $input,
              length($input) - $offset, $offset);
            defined($written) && $written > 0 or fail();
            $offset += $written;
          }
          my @input_stat = stat($input_handle);
          @input_stat && S_ISREG($input_stat[2]) &&
            ($input_stat[2] & 07777) == 0600 && $input_stat[3] == 0 &&
            $input_stat[4] == $< && $input_stat[7] == length($input) &&
            sysseek($input_handle, 0, 0) == 0 or fail();
          pipe(my $reader, my $writer) or fail();
          my $registration_mask = mask_git_child_signals();
          my $child = fork();
          if (!defined($child)) {
            restore_git_child_signal_mask($registration_mask);
            fail();
          }
          if ($child == 0) {
            close($reader) or POSIX::_exit(126);
            open(STDOUT, q{>&}, $writer) or POSIX::_exit(126);
            open(STDERR, q{>&}, $writer) or POSIX::_exit(126);
            close($writer) or POSIX::_exit(126);
            if (git_signal_test_hook_matches(q{capture-with-input},
              q{stopped-after-eof})) {
              close(STDOUT) or POSIX::_exit(126);
              close(STDERR) or POSIX::_exit(126);
              kill(q{STOP}, $$) == 1 or POSIX::_exit(126);
              POSIX::_exit(125);
            }
            open(STDIN, q{<&}, $input_handle) or POSIX::_exit(126);
            close($input_handle) or POSIX::_exit(126);
            defined(fcntl($git_handle, F_SETFD, 0)) or POSIX::_exit(126);
            defined(fcntl($directory, F_SETFD, 0)) or POSIX::_exit(126);
            my $git_descriptor = q{/proc/self/fd/} . fileno($git_handle);
            my $checkout_descriptor = q{/proc/self/fd/} . fileno($directory);
            %ENV = (
              PATH => q{/usr/bin:/bin}, LC_ALL => q{C}, LANG => q{C},
              GIT_CONFIG_NOSYSTEM => q{1}, GIT_CONFIG_GLOBAL => q{/dev/null},
              GIT_OPTIONAL_LOCKS => q{0}, GIT_TERMINAL_PROMPT => q{0},
              GIT_PAGER => q{cat}, PAGER => q{cat},
              GIT_EXTERNAL_DIFF => q{/bin/false}, GIT_NO_REPLACE_OBJECTS => q{1}
            );
            defined(sigprocmask(SIG_SETMASK, $registration_mask)) or
              POSIX::_exit(126);
            exec {$git_descriptor} $git_path,
              q{-c}, q{core.hooksPath=/dev/null},
              q{-c}, q{core.fsmonitor=false},
              q{-c}, q{core.untrackedCache=false},
              q{-c}, q{core.trustctime=true},
              q{-c}, q{core.checkStat=default},
              q{-c}, q{core.fileMode=true},
              q{-c}, q{core.symlinks=true},
              q{-c}, q{pager.status=false},
              q{-c}, q{pager.diff=false},
              q{-C}, $checkout_descriptor, @arguments or POSIX::_exit(127);
          }
          git_signal_test_hook(q{capture-with-input}, q{pre-registration},
            $child, 0);
          $ACTIVE_CHILD_PID = $child;
          close($writer) or fail();
          close($input_handle) or fail();
          restore_git_child_signal_mask($registration_mask);
          binmode($reader) or fail();
          my $bytes = q{};
          while (1) {
            my $chunk = q{};
            my $read = sysread($reader, $chunk, 8192);
            defined($read) or fail();
            last if $read == 0;
            $bytes .= $chunk;
            length($bytes) <= $maximum or fail();
          }
          close($reader) or fail();
          my $status = reap_git_child_bounded(q{capture-with-input}, $child);
          $status == 0 or fail();
          $allow_nul || index($bytes, "\0") < 0 or fail();
          return $bytes;
        }
        sub git_single_line {
          my ($directory, @arguments) = @_;
          my $value = git_capture($directory, 4096, 0, @arguments);
          $value =~ /\A([^\r\n\0]+)\n\z/ or fail();
          return $1;
        }
        sub git_checkout_bracket {
          my ($directory) = @_;
          my $head = git_single_line($directory, qw(rev-parse HEAD));
          my $tree = git_single_line($directory, q{rev-parse}, q{HEAD^{tree}});
          my $local_config = git_capture($directory, $maximum_git_output, 1,
            qw(config --local --null --list --no-includes));
          my $stage = git_capture($directory, $maximum_git_output, 1,
            qw(ls-files --stage -z));
          my $flags = git_capture($directory, $maximum_git_output, 1,
            qw(ls-files -v -z));
          my $ignored = git_capture($directory, $maximum_git_output, 1,
            qw(status --ignored=matching --porcelain=v1 -z
              --untracked-files=all --ignore-submodules=none));
          length($stage) > 0 && substr($stage, -1) eq "\0" &&
            length($flags) > 0 && substr($flags, -1) eq "\0" or fail();
          my @flag_records = split(/\0/, $flags, -1);
          pop @flag_records;
          my @stage_records = split(/\0/, $stage, -1);
          pop @stage_records;
          @flag_records > 0 && @flag_records == @stage_records &&
            @flag_records <= $maximum_git_index_entries or fail();
          my @config_records = split(/\0/, $local_config, -1);
          pop @config_records if @config_records && $config_records[-1] eq q{};
          for my $record (@config_records) {
            $record =~ /\A([^\r\n\0]+)\n([^\0]*)\z/s or fail();
            my $key = lc($1);
            $key !~ /\Afilter\./ && $key !~ /\Adiff\..*\.command\z/ &&
              $key ne q{diff.external} && $key ne q{core.attributesfile} &&
              $key ne q{core.hookspath} && $key ne q{core.fsmonitor} &&
              $key ne q{core.untrackedcache} &&
              $key ne q{extensions.worktreeconfig} &&
              $key !~ /\Ainclude(?:if)?\./
              or fail();
          }
          @config_records <= $maximum_git_index_entries or fail();
          my (@stage_paths, @flag_paths);
          for my $record (@stage_records) {
            $record =~ /\A[0-7]{6} [0-9a-f]{40} 0\t(.+)\z/s or fail();
            push @stage_paths, $1;
          }
          for my $record (@flag_records) {
            length($record) >= 3 && substr($record, 1, 1) eq q{ } &&
              substr($record, 0, 1) !~ /[a-zS]/ or fail();
            push @flag_paths, substr($record, 2);
          }
          join("\0", @stage_paths) eq join("\0", @flag_paths) or fail();
          return ($head, $tree, $local_config, $stage, $flags, $ignored,
            scalar(@flag_records));
        }
        sub git_blob_oid_handle {
          my ($handle, $maximum_file_bytes) = @_;
          my @before = stat($handle);
          @before && S_ISREG($before[2]) && $before[7] >= 0 &&
            $before[7] <= $maximum_file_bytes or fail();
          sysseek($handle, 0, 0) == 0 or fail();
          my $sha = Digest::SHA->new(1);
          $sha->add(q{blob } . $before[7] . "\0");
          my $total = 0;
          while ($total < $before[7]) {
            my $chunk = q{};
            my $wanted = $before[7] - $total;
            $wanted = 1048576 if $wanted > 1048576;
            my $read = sysread($handle, $chunk, $wanted);
            defined($read) && $read > 0 or fail();
            $total += $read;
            $total <= $before[7] or fail();
            $sha->add($chunk);
          }
          my $extra = q{};
          my $read = sysread($handle, $extra, 1);
          defined($read) && $read == 0 or fail();
          my @after = stat($handle);
          @after && join(q{:}, @before[0,1,2,3,4,5,6,7]) eq
            join(q{:}, @after[0,1,2,3,4,5,6,7]) or fail();
          return ($sha->hexdigest, 0 + $before[7], 0 + $before[2]);
        }
        sub open_checkout_node {
          my ($root, $path) = @_;
          defined($path) && length($path) > 0 && length($path) <= $maximum_path &&
            $path !~ m{\A/|/\z|//|\0} or fail();
          my @parts = split(m{/}, $path);
          @parts > 0 && $parts[0] ne q{.git} or fail();
          my $name = pop @parts;
          my $directory = $root;
          my $owned_directory = 0;
          for my $component (@parts) {
            $component =~ /\A([^\/\0]{1,255})\z/s &&
              $1 ne q{.} && $1 ne q{..} or fail();
            $component = $1;
            my $child = openat_handle($directory, $component,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            defined($child) or fail();
            close($directory) if $owned_directory;
            $directory = $child;
            $owned_directory = 1;
          }
          $name =~ /\A([^\/\0]{1,255})\z/s &&
            $1 ne q{.} && $1 ne q{..} or fail();
          $name = $1;
          my $node = openat_handle($directory, $name,
            O_PATH_LINUX | O_NOFOLLOW);
          defined($node) or fail();
          return ($directory, $owned_directory, $name, $node);
        }
        sub verified_git_tree_rows {
          my ($directory, $expected_revision, $expected_tree) = @_;
          my $listing = git_capture($directory, $maximum_git_output, 1,
            q{ls-tree}, q{-r}, q{-t}, q{-z}, q{--full-tree}, $expected_tree);
          length($listing) > 0 && substr($listing, -1) eq "\0" or fail();
          my @listed_records = split(/\0/, $listing, -1);
          pop @listed_records;
          @listed_records > 0 &&
            @listed_records <= $maximum_git_index_entries or fail();
          my @listed_rows;
          my %requested_trees = ($expected_tree => 1);
          for my $record (@listed_records) {
            $record =~ /\A(040000|100644|100755|120000|160000) (tree|blob|commit) ([0-9a-f]{40})\t(.+)\z/s
              or fail();
            my ($mode, $type, $oid, $path) = ($1, $2, $3, $4);
            length($path) <= $maximum_path && $path !~ m{\A/|/\z|//|\0} &&
              $path ne q{.git} && index($path, q{.git/}) != 0 or fail();
            if ($mode eq q{040000}) {
              $type eq q{tree} or fail();
              $requested_trees{$oid} = 1;
            } else {
              $type eq q{blob} && $mode ne q{160000} or fail();
            }
            push @listed_rows, {
              mode => $mode, oid => $oid, path => $path, type => $type
            };
          }
          @listed_rows = sort { $a->{path} cmp $b->{path} } @listed_rows;
          for (my $index = 1; $index < @listed_rows; $index++) {
            $listed_rows[$index - 1]->{path} ne $listed_rows[$index]->{path}
              or fail();
          }
          my @object_oids = ($expected_revision, sort keys %requested_trees);
          @object_oids <= $maximum_git_index_entries + 2 or fail();
          my $requests = join(qq{\n}, @object_oids) . qq{\n};
          my $batch = git_capture_with_input($directory, $maximum_git_output, 1,
            $requests, q{cat-file}, q{--batch});
          my %tree_bytes;
          my $commit = q{};
          my $batch_offset = 0;
          for (my $index = 0; $index < @object_oids; $index++) {
            my $oid = $object_oids[$index];
            my $newline = index($batch, qq{\n}, $batch_offset);
            $newline > $batch_offset or fail();
            my $header = substr($batch, $batch_offset,
              $newline - $batch_offset);
            $header =~ /\A([0-9a-f]{40}) (commit|tree) (0|[1-9][0-9]*)\z/
              or fail();
            my ($observed_oid, $type, $size) = ($1, $2, 0 + $3);
            $observed_oid eq $oid && $size <= $maximum_git_output or fail();
            $batch_offset = $newline + 1;
            $batch_offset + $size < length($batch) &&
              substr($batch, $batch_offset + $size, 1) eq qq{\n} or fail();
            my $bytes = substr($batch, $batch_offset, $size);
            $batch_offset += $size + 1;
            sha1_hex($type . q{ } . $size . "\0" . $bytes) eq $oid or fail();
            if ($index == 0) {
              $type eq q{commit} or fail();
              $commit = $bytes;
            } else {
              $type eq q{tree} or fail();
              $tree_bytes{$oid} = $bytes;
            }
          }
          $batch_offset == length($batch) &&
            $commit =~ /\Atree ([0-9a-f]{40})\n/ && $1 eq $expected_tree or fail();
          my @raw_rows;
          my %visited_tree_oids;
          my $walk;
          $walk = sub {
            my ($tree_oid, $prefix, $depth) = @_;
            $depth <= 128 or fail();
            my $bytes = $tree_bytes{$tree_oid};
            defined($bytes) or fail();
            $visited_tree_oids{$tree_oid} = 1;
            my $offset = 0;
            my %names;
            while ($offset < length($bytes)) {
              my $space = index($bytes, q{ }, $offset);
              $space > $offset or fail();
              my $mode = substr($bytes, $offset, $space - $offset);
              my $nul = index($bytes, "\0", $space + 1);
              $nul > $space + 1 && $nul + 21 <= length($bytes) or fail();
              my $name = substr($bytes, $space + 1, $nul - $space - 1);
              length($name) <= $maximum_path && $name !~ m{/|\0} &&
                $name ne q{.} && $name ne q{..} &&
                !(length($prefix) == 0 && $name eq q{.git}) &&
                !$names{$name}++ or fail();
              my $oid = unpack(q{H40}, substr($bytes, $nul + 1, 20));
              my $path = length($prefix) ? $prefix . q{/} . $name : $name;
              length($path) <= $maximum_path or fail();
              $offset = $nul + 21;
              if ($mode eq q{40000}) {
                push @raw_rows, {
                  mode => q{040000}, oid => $oid, path => $path,
                  type => q{tree}
                };
                $walk->($oid, $path, $depth + 1);
              } else {
                $mode =~ /\A(?:100644|100755|120000)\z/ or fail();
                push @raw_rows, {
                  mode => $mode, oid => $oid, path => $path, type => q{blob}
                };
              }
              @raw_rows <= $maximum_git_index_entries or fail();
            }
            $offset == length($bytes) or fail();
          };
          $walk->($expected_tree, q{}, 0);
          @raw_rows > 0 or fail();
          @raw_rows = sort { $a->{path} cmp $b->{path} } @raw_rows;
          JSON::PP->new->canonical(1)->encode(\@raw_rows) eq
            JSON::PP->new->canonical(1)->encode(\@listed_rows) &&
            join(qq{\n}, sort keys %visited_tree_oids) eq
              join(qq{\n}, sort keys %requested_trees) or fail();
          my @leaf_rows = grep { $_->{type} eq q{blob} } @raw_rows;
          @leaf_rows > 0 or fail();
          return \@leaf_rows;
        }
        sub git_worktree_evidence {
          my ($directory, $rows_ref, $stage_bytes, $ignored_bytes) = @_;
          my @rows = @{$rows_ref};
          @rows > 0 && @rows <= $maximum_git_index_entries or fail();
          my $expected_stage = q{};
          my $tree_transcript = q{};
          my $aggregate_bytes = 0;
          my $previous_path = q{};
          my %tracked_paths;
          for my $row (@rows) {
            ref($row) eq q{HASH} or fail();
            my ($mode, $type, $oid, $path) =
              @{$row}{qw(mode type oid path)};
            $type eq q{blob} && $mode =~ /\A(?:100644|100755|120000)\z/ &&
              $oid =~ /\A[0-9a-f]{40}\z/ or fail();
            length($path) <= $maximum_path && $path !~ m{\A/|/\z|//|\0} &&
              (!length($previous_path) || $path gt $previous_path) or fail();
            $previous_path = $path;
            $tracked_paths{$path} = $mode eq q{120000} ? q{symlink} : q{file};
            $expected_stage .= join(q{ }, $mode, $oid, q{0}) . qq{\t} .
              $path . "\0";
            $tree_transcript .= join("\0", $mode, $type, $oid, $path) . "\0";
            length($expected_stage) <= $maximum_git_output &&
              length($tree_transcript) <= $maximum_git_output or fail();
            my ($parent, $parent_owned, $name, $node) =
              open_checkout_node($directory, $path);
            my @node_stat = stat($node);
            @node_stat or fail();
            if ($mode eq q{120000}) {
              S_ISLNK($node_stat[2]) && $node_stat[7] > 0 &&
                $node_stat[7] <= $maximum_source_bytes or fail();
              my $target = "\0" x ($node_stat[7] + 1);
              my $empty_path = q{};
              my $target_size = syscall(SYS_readlinkat(), fileno($node),
                $empty_path,
                $target, length($target));
              defined($target_size) && $target_size == $node_stat[7] or fail();
              $target = substr($target, 0, $target_size);
              my @after = stat($node);
              @after && join(q{:}, @node_stat[0,1,2,3,4,5,6,7]) eq
                join(q{:}, @after[0,1,2,3,4,5,6,7]) or fail();
              my $sha = Digest::SHA->new(1);
              $sha->add(q{blob } . $target_size . "\0" . $target);
              $sha->hexdigest eq $oid or fail();
              $aggregate_bytes += $target_size;
            } else {
              S_ISREG($node_stat[2]) or fail();
              my $file = openat_handle($parent, $name, O_RDONLY | O_NOFOLLOW);
              defined($file) or fail();
              my @file_stat = stat($file);
              @file_stat && $file_stat[0] == $node_stat[0] &&
                $file_stat[1] == $node_stat[1] or fail();
              my ($observed_oid, $observed_size, $observed_mode) =
                git_blob_oid_handle($file, $maximum_source_bytes);
              $observed_oid eq $oid &&
                (($mode eq q{100755} && ($observed_mode & 0111) != 0) ||
                  ($mode eq q{100644} && ($observed_mode & 0111) == 0)) or fail();
              $aggregate_bytes += $observed_size;
              close($file) or fail();
            }
            $aggregate_bytes <= $maximum_git_worktree_bytes or fail();
            close($node) or fail();
            if ($parent_owned) { close($parent) or fail(); }
          }
          $expected_stage eq $stage_bytes or fail();
          my @ignored_records = split(/\0/, $ignored_bytes, -1);
          pop @ignored_records if @ignored_records &&
            $ignored_records[-1] eq q{};
          my %ignored_paths;
          for my $record (@ignored_records) {
            $record =~ /\A!! (.+)\z/s or fail();
            my $path = $1;
            $path =~ s{/\z}{};
            length($path) > 0 && length($path) <= $maximum_path &&
              $path !~ m{\A/|/\z|//|\0} && !$ignored_paths{$path}++ or fail();
          }
          my %admitted_directories;
          for my $path (keys %tracked_paths, keys %ignored_paths) {
            my @parts = split(m{/}, $path);
            pop @parts;
            my $prefix = q{};
            for my $part (@parts) {
              $prefix = length($prefix) ? $prefix . q{/} . $part : $part;
              $admitted_directories{$prefix} = 1;
            }
          }
          my @filesystem_entries;
          my %filesystem_paths;
          my $walk_filesystem;
          $walk_filesystem = sub {
            my ($parent, $prefix) = @_;
            my @names = directory_names($parent,
              $maximum_git_index_entries, $maximum_git_output, 1);
            for my $name (@names) {
              next if !length($prefix) && $name eq q{.git};
              my $path = length($prefix) ? $prefix . q{/} . $name : $name;
              length($path) <= $maximum_path && !$filesystem_paths{$path}++ or fail();
              my $node = openat_handle($parent, $name,
                O_PATH_LINUX | O_NOFOLLOW);
              defined($node) or fail();
              my @node_stat = stat($node);
              @node_stat or fail();
              my $kind = S_ISDIR($node_stat[2]) ? q{directory} :
                S_ISREG($node_stat[2]) ? q{file} :
                S_ISLNK($node_stat[2]) ? q{symlink} : q{};
              length($kind) or fail();
              push @filesystem_entries, [$path, $kind];
              @filesystem_entries <= $maximum_git_index_entries or fail();
              if ($kind eq q{directory}) {
                my $child = openat_handle($parent, $name,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
                defined($child) or fail();
                my @child_stat = stat($child);
                @child_stat && $child_stat[0] == $node_stat[0] &&
                  $child_stat[1] == $node_stat[1] or fail();
                $walk_filesystem->($child, $path);
                close($child) or fail();
              }
              close($node) or fail();
            }
          };
          $walk_filesystem->($directory, q{});
          @filesystem_entries = sort { $a->[0] cmp $b->[0] }
            @filesystem_entries;
          my $is_ignored_path = sub {
            my ($path) = @_;
            return 1 if $ignored_paths{$path};
            my $ancestor = $path;
            while ($ancestor =~ s{/[^/]+\z}{}) {
              return 1 if $ignored_paths{$ancestor};
            }
            return 0;
          };
          my $filesystem_transcript = q{};
          for my $entry (@filesystem_entries) {
            my ($path, $kind) = @{$entry};
            if (exists($tracked_paths{$path})) {
              $tracked_paths{$path} eq $kind or fail();
            } elsif ($kind eq q{directory}) {
              ($admitted_directories{$path} || $is_ignored_path->($path)) or fail();
            } else {
              $is_ignored_path->($path) or fail();
            }
            $filesystem_transcript .= join("\0", $path, $kind) . "\0";
            length($filesystem_transcript) <= $maximum_git_output or fail();
          }
          for my $path (keys %tracked_paths, keys %ignored_paths) {
            exists($filesystem_paths{$path}) or fail();
          }
          return {
            tracked_entry_count => scalar(@rows),
            tracked_bytes => $aggregate_bytes,
            tracked_tree_transcript_sha256 => sha256_hex($tree_transcript),
            ignored_entry_count => scalar(keys %ignored_paths),
            ignored_roster_sha256 => sha256_hex($ignored_bytes),
            filesystem_entry_count => scalar(@filesystem_entries),
            filesystem_roster_sha256 => sha256_hex($filesystem_transcript)
          };
        }
        sub git_checkout_evidence {
          my ($locator, $expected_revision, $expected_tree, $source_tree_sha256,
            $fresh_walk, $record_new) = @_;
          $expected_revision =~ /\A[0-9a-f]{40}\z/ &&
            $expected_tree =~ /\A[0-9a-f]{40}\z/ &&
            $source_tree_sha256 =~ /\A[0-9a-f]{64}\z/ or fail();
          my ($root_name, $relative, $directory) = open_source_directory(
            $locator, $fresh_walk, $record_new);
          my $expected_top = $root_paths{$root_name};
          $expected_top .= q{/} . $relative unless $relative eq q{.};
          my $top_before = git_single_line($directory,
            qw(rev-parse --show-toplevel));
          my ($head_before, $tree_before, $config_before,
            $stage_before, $flags_before, $ignored_before,
            $index_entry_count) =
            git_checkout_bracket($directory);
          $top_before eq $expected_top && $head_before eq $expected_revision &&
            $tree_before eq $expected_tree or fail();
          my $tree_rows_before = verified_git_tree_rows(
            $directory, $expected_revision, $expected_tree);
          my $worktree_before = git_worktree_evidence(
            $directory, $tree_rows_before, $stage_before, $ignored_before);
          git_capture($directory, $maximum_git_output, 1,
            qw(ls-files --unmerged -z)) eq q{} or fail();
          git_capture($directory, $maximum_git_output, 0,
            q{diff}, q{--quiet}, q{--no-ext-diff}, q{--no-textconv},
            $expected_revision, q{--}) eq q{} or fail();
          git_capture($directory, $maximum_git_output, 0,
            q{diff}, q{--cached}, q{--quiet}, q{--no-ext-diff},
            q{--no-textconv}, $expected_revision, q{--}) eq q{} or fail();
          my ($head_after, $tree_after, $config_after,
            $stage_after, $flags_after, $ignored_after,
            $index_entry_count_after) =
            git_checkout_bracket($directory);
          my $top_after = git_single_line($directory,
            qw(rev-parse --show-toplevel));
          my $tree_rows_after = verified_git_tree_rows(
            $directory, $expected_revision, $expected_tree);
          my $worktree_after = git_worktree_evidence(
            $directory, $tree_rows_after, $stage_after, $ignored_after);
          $top_after eq $top_before && $head_after eq $head_before &&
            $tree_after eq $tree_before && $config_after eq $config_before &&
            $stage_after eq $stage_before &&
            $flags_after eq $flags_before &&
            $ignored_after eq $ignored_before &&
            $index_entry_count_after == $index_entry_count &&
            JSON::PP->new->canonical(1)->encode($tree_rows_after) eq
              JSON::PP->new->canonical(1)->encode($tree_rows_before) &&
            JSON::PP->new->canonical(1)->encode($worktree_after) eq
              JSON::PP->new->canonical(1)->encode($worktree_before) or fail();
          my $stage_sha = sha256_hex($stage_before);
          my $flags_sha = sha256_hex($flags_before);
          my $transcript = join(qq{\n},
            q{kind=git-clean-checkout-v1}, q{root=} . $root_name,
            q{path=} . $relative, q{revision=} . $expected_revision,
            q{git_tree=} . $expected_tree,
            q{local_config_size_bytes=} . length($config_before),
            q{local_config_sha256=} . sha256_hex($config_before),
            q{stage_size_bytes=} . length($stage_before),
            q{stage_sha256=} . $stage_sha,
            q{index_flags_size_bytes=} . length($flags_before),
            q{index_flags_sha256=} . $flags_sha,
            q{ignored_size_bytes=} . length($ignored_before),
            q{ignored_sha256=} . sha256_hex($ignored_before),
            q{unmerged=empty}, q{worktree_diff=empty},
            q{cached_diff=empty}, q{porcelain_status=ignored_only}) . qq{\n};
          my $evidence = {
            root => $root_name, path => $relative,
            checkout_kind => q{git-clean-checkout-v1},
            identity => directory_evidence_identity($directory),
            revision => $expected_revision, git_tree => $expected_tree,
            source_tree_sha256 => $source_tree_sha256,
            index_entry_count => $index_entry_count,
            stage_size_bytes => length($stage_before),
            stage_sha256 => $stage_sha,
            index_flags_size_bytes => length($flags_before),
            index_flags_sha256 => $flags_sha,
            ignored_entry_count => $worktree_before->{ignored_entry_count},
            ignored_roster_sha256 => $worktree_before->{ignored_roster_sha256},
            filesystem_entry_count => $worktree_before->{filesystem_entry_count},
            filesystem_roster_sha256 =>
              $worktree_before->{filesystem_roster_sha256},
            transcript_sha256 => sha256_hex($transcript)
            , tracked_entry_count => $worktree_before->{tracked_entry_count}
            , tracked_bytes => $worktree_before->{tracked_bytes}
            , tracked_tree_transcript_sha256 =>
                $worktree_before->{tracked_tree_transcript_sha256}
          };
          if ($fresh_walk && $relative ne q{.}) {
            close($directory) or fail();
          }
          return $evidence;
        }
        sub java_tree_evidence {
          my ($locator, $expected_entries, $expected_files, $expected_directories,
            $expected_manifest_size, $expected_manifest_sha,
            $expected_parent_identity, $expected_root_identity) = @_;
          my ($root_name, $relative, $tree_root) = open_source_directory(
            $locator, 1, 0);
          simple_directory_identity($tree_root) eq $expected_root_identity or fail();
          my @tree_root_stat = stat($tree_root);
          @tree_root_stat && $tree_root_stat[4] == $< &&
            ($tree_root_stat[2] & 077) == 0 or fail();
          my @root_parts = split(m{/}, $relative);
          pop @root_parts;
          my $parent = $roots{$root_name};
          if (@root_parts) {
            (undef, undef, $parent) = open_source_directory(
              $root_name . q{/} . join(q{/}, @root_parts), 1, 0);
          }
          simple_directory_identity($parent) eq $expected_parent_identity or fail();
          my @tree_parent_stat = stat($parent);
          @tree_parent_stat && $tree_parent_stat[4] == $< &&
            ($tree_parent_stat[2] & 077) == 0 or fail();
          my @entries;
          my %seen_files;
          my $manifest = q{};
          my $file_count = 0;
          my $directory_count = 0;
          my $walk;
          $walk = sub {
            my ($directory, $prefix) = @_;
            my @names = directory_names($directory,
              $maximum_tree_entries, $maximum_tree_manifest);
            for my $name (@names) {
              $name =~ /\A[A-Za-z0-9._-]+\z/ or fail();
              my $relative_entry = length($prefix) ?
                $prefix . q{/} . $name : $name;
              my $node = openat_handle($directory, $name,
                O_PATH_LINUX | O_NOFOLLOW);
              defined($node) or fail();
              my @stat = stat($node);
              @stat or fail();
              $stat[4] == $< && ($stat[2] & 077) == 0 or fail();
              my $manifest_identity = manifest_entry_identity(\@stat);
              if (S_ISDIR($stat[2])) {
                $stat[3] >= 2 or fail();
                $directory_count++;
                push @entries, {kind => q{directory}, path => $relative_entry,
                  identity => $manifest_identity, sha256 => undef,
                  size_bytes => 0 + $stat[7], maximum_bytes => undef};
                my $child = openat_handle($directory, $name,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
                defined($child) or fail();
                $walk->($child, $relative_entry);
                close($child) or fail();
              } elsif (S_ISREG($stat[2])) {
                $stat[3] == 1 or fail();
                $file_count++;
                my $source_locator = $locator . q{/} . $relative_entry;
                my $source = $leaves{$source_locator} //
                  $compacted_leaves{$source_locator};
                defined($source) or fail();
                my $file = openat_handle($directory, $name,
                  O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
                defined($file) && leaf_identity($file) eq $source->{identity} &&
                  digest_handle($file, $source->{size_bytes},
                    $source->{maximum_bytes}) eq $source->{sha256} or fail();
                close($file) or fail();
                $seen_files{$source_locator} = 1;
                push @entries, {kind => q{file}, path => $relative_entry,
                  identity => $manifest_identity, sha256 => $source->{sha256},
                  size_bytes => $source->{size_bytes},
                  maximum_bytes => $source->{maximum_bytes}};
              } else {
                fail();
              }
              @entries <= $maximum_tree_entries or fail();
              close($node) or fail();
            }
          };
          $walk->($tree_root, q{});
          @entries = sort { $a->{path} cmp $b->{path} } @entries;
          my @operation_names = qw(
            01-bootstrap-stop 02-bootstrap-discard 03-nmt-baseline
            04-nmt-baseline-confirmation 05-runtime-baseline 06-jfr-start
            07-jfr-stop 08-jfr-summary 10-nmt-postload-summary
            11-nmt-postload-diff 12-runtime-postload
          );
          my @operation_files = qw(
            host-after-runtime-before.txt host-after.txt
            host-before-runtime-after.txt host-before.txt output
            runtime-after.json runtime-before.json
          );
          my @expected_entries = (
            map({[q{file}, $_]} qw(
              evidence.json identity.txt measurement.jfr runtime-artifacts.json
            )),
            [q{directory}, q{operations}],
            map({
              my $operation = $_;
              ([q{directory}, q{operations/} . $operation],
                map({[q{file}, q{operations/} . $operation . q{/} . $_]}
                  @operation_files))
            } @operation_names)
          );
          @expected_entries = sort { $a->[1] cmp $b->[1] } @expected_entries;
          @entries == @expected_entries or fail();
          for (my $index = 0; $index < @entries; $index++) {
            $entries[$index]->{kind} eq $expected_entries[$index]->[0] &&
              $entries[$index]->{path} eq $expected_entries[$index]->[1] or fail();
          }
          my %file_sha = map {
            $_->{kind} eq q{file} ? ($_->{path} => $_->{sha256}) : ()
          } @entries;
          for my $operation (@operation_names) {
            for my $host_file (qw(host-before.txt host-after-runtime-before.txt
                host-before-runtime-after.txt host-after.txt)) {
              $file_sha{q{operations/} . $operation . q{/} . $host_file} eq
                $file_sha{q{identity.txt}} or fail();
            }
          }
          for my $entry (@entries) {
            $manifest .= join("\0", $entry->{kind}, $entry->{path},
              $entry->{identity},
              $entry->{kind} eq q{file} ? $entry->{sha256} : q{-}) . "\0";
            length($manifest) <= $maximum_tree_manifest or fail();
          }
          @entries == $expected_entries && $file_count == $expected_files &&
            $directory_count == $expected_directories &&
            length($manifest) == $expected_manifest_size &&
            sha256_hex($manifest) eq $expected_manifest_sha or fail();
          for my $key (keys %leaves) {
            next unless index($key, $locator . q{/}) == 0;
            $seen_files{$key} or fail();
          }
          return ({root => $root_name, path => $relative,
            parent_identity => $expected_parent_identity,
            root_identity => $expected_root_identity,
            entry_count => scalar(@entries), file_count => $file_count,
            directory_count => $directory_count,
            manifest_size_bytes => length($manifest),
            manifest_sha256 => $expected_manifest_sha,
            entries => \@entries}, $tree_root, \%seen_files);
        }
        sub held_source_fd_count {
          return scalar(keys %directory_handles) + scalar(keys %leaf_handles) +
            scalar(keys %tree_handles) + 1;
        }
        sub verify_sources {
          verify_named_root(q{output}, $output_path, $expected_output, $output_root);
          verify_named_root(q{repository}, $repository_path,
            $expected_repository, $repository_root);
          for my $key (sort keys %leaves) {
            my $entry = $leaves{$key};
            my $held = $leaf_handles{$key};
            leaf_identity($held) eq $entry->{identity} or fail();
            digest_handle($held, $entry->{size_bytes},
              $entry->{maximum_bytes}) eq $entry->{sha256} or fail();
            my (undef, undef, $fresh) = open_source_leaf($key, 1);
            leaf_identity($fresh) eq $entry->{identity} &&
              digest_handle($fresh, $entry->{size_bytes},
                $entry->{maximum_bytes}) eq $entry->{sha256} or fail();
            close($fresh) or fail();
          }
          for my $key (sort keys %trees) {
            my $expected = $trees{$key};
            my ($observed, $fresh_tree_handle, $fresh_seen_files) =
              java_tree_evidence($key,
              $expected->{entry_count}, $expected->{file_count},
              $expected->{directory_count}, $expected->{manifest_size_bytes},
              $expected->{manifest_sha256}, $expected->{parent_identity},
              $expected->{root_identity});
            JSON::PP->new->canonical(1)->encode($observed) eq
              JSON::PP->new->canonical(1)->encode($expected) or fail();
            close($fresh_tree_handle) or fail();
            simple_directory_identity($tree_handles{$key}) eq
              $expected->{root_identity} or fail();
          }
          for my $key (sort keys %negatives) {
            my $expected = $negatives{$key};
            my $observed = negative_evidence($key,
              $expected->{maximum_bytes}, 1, 0);
            JSON::PP->new->canonical(1)->encode($observed) eq
              JSON::PP->new->canonical(1)->encode($expected) or fail();
          }
          for my $key (sort keys %selectors) {
            my $expected = $selectors{$key};
            my $observed = selector_evidence($key, $expected->{selector}, 1, 0);
            JSON::PP->new->canonical(1)->encode($observed) eq
              JSON::PP->new->canonical(1)->encode($expected) or fail();
          }
          for my $key (sort keys %directories) {
            directory_evidence_identity($directory_handles{$key}) eq
              $directories{$key}->{identity} or fail();
          }
          held_source_fd_count() <= $maximum_held_fds or fail();
          # The checkout is the last source-class observation: two complete
          # object/index/raw-worktree passes are followed only by root brackets.
          for my $key (sort keys %checkouts) {
            my $expected = $checkouts{$key};
            my $observed = git_checkout_evidence($key,
              $expected->{revision}, $expected->{git_tree},
              $expected->{source_tree_sha256}, 1, 0);
            JSON::PP->new->canonical(1)->encode($observed) eq
              JSON::PP->new->canonical(1)->encode($expected) or fail();
          }
          verify_named_root(q{output}, $output_path, $expected_output, $output_root);
          verify_named_root(q{repository}, $repository_path,
            $expected_repository, $repository_root);
        }

        my $record_count = 0;
        while (1) {
          my $line = read_line($maximum_record + 64);
          if ($line eq q{F:0:}) {
            last;
          }
          $line =~ /\A([SDTNG]):([1-9][0-9]*):(.*)\z/s or fail();
          my ($type, $declared, $payload) = ($1, 0 + $2, $3);
          $declared == length($payload) && $declared <= $maximum_record or fail();
          ++$record_count <= $maximum_records or fail();
          my @fields = split(qq{\t}, $payload, -1);
          if ($type eq q{S}) {
            @fields == 11 or fail();
            my ($locator, $maximum, @identity_fields) = @fields;
            $locator = safe_relative($locator, $maximum_path + 16);
            !exists($negatives{$locator}) or fail();
            $maximum = exact_integer($maximum, 1);
            $maximum <= $maximum_source_bytes or fail();
            my $digest = pop @identity_fields;
            $digest =~ /\A[0-9a-f]{64}\z/ or fail();
            @identity_fields == 8 or fail();
            for my $field (@identity_fields) { exact_integer($field, 0); }
            my $identity = join(q{:}, @identity_fields);
            my $size = 0 + $identity_fields[7];
            $size > 0 && $size <= $maximum or fail();
            my $compacted = $compacted_leaves{$locator};
            my ($root_name, $relative, $leaf) = open_source_leaf(
              $locator, defined($compacted) ? 1 : 0);
            leaf_identity($leaf) eq $identity &&
              digest_handle($leaf, $size, $maximum) eq $digest or fail();
            if (defined($compacted)) {
              $compacted->{identity} eq $identity &&
                $compacted->{size_bytes} == $size &&
                $compacted->{sha256} eq $digest or fail();
              close($leaf) or fail();
            } elsif (exists $leaves{$locator}) {
              my $prior = $leaves{$locator};
              $prior->{identity} eq $identity && $prior->{size_bytes} == $size &&
                $prior->{sha256} eq $digest or fail();
              $prior->{maximum_bytes} = $maximum
                if $maximum < $prior->{maximum_bytes};
              close($leaf) or fail();
            } else {
              $leaves{$locator} = {
                root => $root_name, path => $relative, identity => $identity,
                maximum_bytes => $maximum, size_bytes => $size, sha256 => $digest
              };
              $leaf_handles{$locator} = $leaf;
              held_source_fd_count() <= $maximum_held_fds or fail();
            }
          } elsif ($type eq q{D}) {
            @fields == 2 or fail();
            my ($locator, $selector) = @fields;
            $locator = safe_relative($locator, $maximum_path + 16);
            $selector =~ /\A(?:benchmark-repetition-json|pressure-recovery-sample-prom)\z/
              or fail();
            my $observed = selector_evidence($locator, $selector, 0, 1);
            if (exists $selectors{$locator}) {
              JSON::PP->new->canonical(1)->encode($observed) eq
                JSON::PP->new->canonical(1)->encode($selectors{$locator}) or fail();
            } else {
              scalar(keys %selectors) < $maximum_selectors or fail();
              $selectors{$locator} = $observed;
            }
            held_source_fd_count() <= $maximum_held_fds or fail();
          } elsif ($type eq q{N}) {
            @fields == 3 or fail();
            my ($locator, $maximum, $expected_state) = @fields;
            $locator = safe_relative($locator, $maximum_path + 16);
            !exists($leaves{$locator}) && !exists($compacted_leaves{$locator}) or fail();
            $maximum = exact_integer($maximum, 1);
            $maximum <= $maximum_source_bytes or fail();
            $expected_state eq q{} ||
              $expected_state =~ /\A(?:absent|nonregular|empty|oversize)\z/ or fail();
            my $observed = negative_evidence($locator, $maximum, 0, 1);
            $expected_state eq q{} ||
              $observed->{state} eq $expected_state or fail();
            if (exists $negatives{$locator}) {
              JSON::PP->new->canonical(1)->encode($observed) eq
                JSON::PP->new->canonical(1)->encode($negatives{$locator}) or fail();
            } else {
              scalar(keys %negatives) < $maximum_negatives or fail();
              $negatives{$locator} = $observed;
            }
          } elsif ($type eq q{G}) {
            @fields == 5 or fail();
            my ($locator, $checkout_kind, $revision, $git_tree,
              $source_tree_sha256) = @fields;
            $locator =~ m{\A(output|repository)/(.+)\z} or fail();
            my ($locator_root, $locator_path) = ($1, $2);
            $locator_path = safe_relative($locator_path, $maximum_path)
              unless $locator_path eq q{.};
            $locator = $locator_root . q{/} . $locator_path;
            $checkout_kind eq q{git-clean-checkout-v1} &&
              $revision =~ /\A[0-9a-f]{40}\z/ &&
              $git_tree =~ /\A[0-9a-f]{40}\z/ &&
              $source_tree_sha256 =~ /\A[0-9a-f]{64}\z/ or fail();
            my @runner_manifests = grep {
              m{\Aoutput/cells/[A-Za-z0-9._-]+/preflight/runner/source-tree\.manifest\z}
            } keys %leaves;
            (@runner_manifests == 6 || @runner_manifests == 10) or fail();
            for my $manifest_locator (@runner_manifests) {
              $leaves{$manifest_locator}->{sha256} eq $source_tree_sha256 or fail();
            }
            my $observed = git_checkout_evidence(
              $locator, $revision, $git_tree, $source_tree_sha256, 0, 1);
            if (exists $checkouts{$locator}) {
              JSON::PP->new->canonical(1)->encode($observed) eq
                JSON::PP->new->canonical(1)->encode($checkouts{$locator}) or fail();
            } else {
              scalar(keys %checkouts) < $maximum_checkouts or fail();
              $checkouts{$locator} = $observed;
            }
            held_source_fd_count() <= $maximum_held_fds or fail();
            print qq{G:READY\n};
          } elsif ($type eq q{T}) {
            @fields == 8 or fail();
            my ($locator, $entry_count, $file_count, $directory_count,
              $manifest_size, $manifest_sha, $parent_identity,
              $root_identity) = @fields;
            $locator = safe_relative($locator, $maximum_path + 16);
            $entry_count = exact_integer($entry_count, 1);
            $file_count = exact_integer($file_count, 1);
            $directory_count = exact_integer($directory_count, 0);
            $manifest_size = exact_integer($manifest_size, 1);
            $entry_count == $file_count + $directory_count &&
              $entry_count <= $maximum_tree_entries &&
              $manifest_size <= $maximum_tree_manifest &&
              $manifest_sha =~ /\A[0-9a-f]{64}\z/ &&
              $parent_identity =~ /\A[0-9]+:[1-9][0-9]*:[0-9]+:[0-7]{3,4}\z/ &&
              $root_identity =~ /\A[0-9]+:[1-9][0-9]*:[0-9]+:[0-7]{3,4}\z/ or fail();
            for my $authority_locator (keys %negatives, keys %selectors) {
              index($authority_locator, $locator . q{/}) != 0 &&
                index($locator, $authority_locator . q{/}) != 0 &&
                $authority_locator ne $locator or fail();
            }
            my ($observed, $tree_handle, $seen_files) = java_tree_evidence(
              $locator, $entry_count, $file_count, $directory_count,
              $manifest_size, $manifest_sha, $parent_identity, $root_identity);
            if (exists $trees{$locator}) {
              JSON::PP->new->canonical(1)->encode($observed) eq
                JSON::PP->new->canonical(1)->encode($trees{$locator}) or fail();
              close($tree_handle) or fail();
            } else {
              scalar(keys %trees) < $maximum_trees or fail();
              for my $source_locator (keys %{$seen_files}) {
                my $source = delete $leaves{$source_locator};
                defined($source) or fail();
                $compacted_leaves{$source_locator} = $source;
                my $handle = delete $leaf_handles{$source_locator};
                defined($handle) && close($handle) or fail();
              }
              for my $directory_key (keys %directories) {
                next unless index($directory_key, $locator . q{/}) == 0;
                delete $directories{$directory_key};
                my $handle = delete $directory_handles{$directory_key};
                close($handle) if defined($handle) &&
                  fileno($handle) != fileno($tree_handle);
              }
              $trees{$locator} = $observed;
              $tree_handles{$locator} = $tree_handle;
            }
            held_source_fd_count() <= $maximum_held_fds or fail();
          } else {
            fail();
          }
        }
        scalar(keys %leaves) + scalar(keys %trees) + scalar(keys %checkouts) +
          scalar(keys %negatives) + scalar(keys %selectors) > 0 or fail();
        verify_sources();
        scalar(keys %leaves) <= $maximum_leaves &&
          scalar(keys %directories) <= $maximum_directories &&
          scalar(keys %trees) <= $maximum_trees &&
          scalar(keys %checkouts) <= $maximum_checkouts &&
          scalar(keys %negatives) <= $maximum_negatives &&
          scalar(keys %selectors) <= $maximum_selectors or fail();
        my @root_evidence = map {
          {name => $_, identity => directory_evidence_identity($roots{$_})}
        } sort keys %roots;
        my @directory_evidence = map { $directories{$_} } sort keys %directories;
        my @leaf_evidence = map { $leaves{$_} } sort keys %leaves;
        my @tree_evidence = map { $trees{$_} } sort keys %trees;
        my @checkout_evidence = map { $checkouts{$_} } sort keys %checkouts;
        my @negative_evidence = map { $negatives{$_} } sort keys %negatives;
        my @selector_evidence = map { $selectors{$_} } sort keys %selectors;
        my $roster = {
          schema_version => 1,
          kind => q{terminal-publication-source-authority},
          roots => \@root_evidence,
          directories => \@directory_evidence,
          leaves => \@leaf_evidence,
          trees => \@tree_evidence,
          checkouts => \@checkout_evidence,
          negatives => \@negative_evidence,
          directory_selectors => \@selector_evidence
        };
        my $roster_bytes = JSON::PP->new->canonical(1)->encode($roster);
        length($roster_bytes) > 0 && length($roster_bytes) <= $maximum_roster or fail();
        my $roster_hex = unpack(q{H*}, $roster_bytes);
        print q{R:}, length($roster_bytes), q{:}, $roster_hex, qq{\n};

        my %candidate_maximum = (
          q{poc-gates.json} => $maximum_poc,
          q{manifest.json} => $maximum_manifest,
          q{summary.json} => $maximum_summary
        );
        my %candidate_bytes;
        my %candidate_values;
        for my $expected_name (qw(poc-gates.json manifest.json summary.json)) {
          my $line = read_line(256);
          $line =~ /\AC:([a-z-]+\.json):(0|[1-9][0-9]*):([0-9a-f]{64}|-)\z/ or fail();
          my ($name, $length, $digest) = ($1, 0 + $2, $3);
          $name eq $expected_name && $length <= $candidate_maximum{$name} or fail();
          if ($name eq q{poc-gates.json} && $length == 0) {
            $digest eq q{-} or fail();
            $candidate_bytes{$name} = q{};
            next;
          }
          $length > 0 && $digest =~ /\A[0-9a-f]{64}\z/ or fail();
          my $bytes = read_exact($length);
          sha256_hex($bytes) eq $digest or fail();
          $candidate_values{$name} = decoded_json($bytes);
          $candidate_bytes{$name} = $bytes;
        }
        read_line(64) eq q{X:0:} or fail();
        my $manifest_bytes = $candidate_bytes{q{manifest.json}};
        my $summary_bytes = $candidate_bytes{q{summary.json}};
        my $poc_bytes = $candidate_bytes{q{poc-gates.json}};
        my $manifest_value = $candidate_values{q{manifest.json}};
        my $summary_value = $candidate_values{q{summary.json}};
        ref($manifest_value) eq q{HASH} && ref($summary_value) eq q{HASH} or fail();
        $manifest_value->{status} eq $summary_value->{status} or fail();
        my $summary_roster = JSON::PP->new->canonical(1)->encode(
          $summary_value->{source_authority});
        $summary_roster eq $roster_bytes or fail();
        my $application_source = $summary_value->{application_source};
        ref($application_source) eq q{HASH} &&
          defined($application_source->{status}) or fail();
        if ($application_source->{status} eq q{clean_and_stable}) {
          @checkout_evidence == 1 &&
            $application_source->{revision} eq $checkout_evidence[0]->{revision} &&
            $application_source->{git_tree} eq $checkout_evidence[0]->{git_tree} &&
            $application_source->{source_tree_sha256} eq
              $checkout_evidence[0]->{source_tree_sha256}
            or fail();
        } else {
          @checkout_evidence == 0 or fail();
        }
        my $roster_receipt = $summary_value->{source_authority_receipt};
        ref($roster_receipt) eq q{HASH} &&
          $roster_receipt->{source_count} == scalar(@leaf_evidence) +
            scalar(@tree_evidence) + scalar(@checkout_evidence) +
            scalar(@negative_evidence) +
            scalar(@selector_evidence) &&
          $roster_receipt->{directory_count} == scalar(@directory_evidence) &&
          $roster_receipt->{size_bytes} == length($roster_bytes) &&
          $roster_receipt->{sha256} eq sha256_hex($roster_bytes) or fail();
        my $receipts = $summary_value->{artifact_receipts};
        ref($receipts) eq q{HASH} && ref($receipts->{manifest}) eq q{HASH} &&
          $receipts->{manifest}->{path} eq q{manifest.json} &&
          $receipts->{manifest}->{size_bytes} == length($manifest_bytes) &&
          $receipts->{manifest}->{sha256} eq sha256_hex($manifest_bytes) or fail();
        if (length($poc_bytes)) {
          ref($candidate_values{q{poc-gates.json}}) eq q{HASH} &&
            $receipts->{poc_gates}->{status} eq q{available} &&
            $receipts->{poc_gates}->{path} eq q{poc-gates.json} &&
            $receipts->{poc_gates}->{size_bytes} == length($poc_bytes) &&
            $receipts->{poc_gates}->{sha256} eq sha256_hex($poc_bytes) or fail();
        } else {
          $receipts->{poc_gates}->{status} eq q{not_available} &&
            !defined($receipts->{poc_gates}->{path}) &&
            !defined($receipts->{poc_gates}->{size_bytes}) &&
            !defined($receipts->{poc_gates}->{sha256}) or fail();
        }

        sub create_candidate {
          my ($bytes) = @_;
          my $dot = q{.};
          my $fd = syscall(SYS_openat(), fileno($output_root), $dot,
            O_RDWR | O_TMPFILE_LINUX, 0600);
          $fd >= 0 or fail();
          open(my $handle, q{+<&=}, $fd) or fail();
          my $offset = 0;
          while ($offset < length($bytes)) {
            my $written = syswrite($handle, $bytes,
              length($bytes) - $offset, $offset);
            defined($written) && $written > 0 or fail();
            $offset += $written;
          }
          my @stat = stat($handle);
          @stat && S_ISREG($stat[2]) && ($stat[2] & 07777) == 0600 &&
            $stat[3] == 0 && $stat[4] == $< && $stat[7] == length($bytes) or fail();
          return $handle;
        }
        my %candidates;
        my $candidate_count = 2 + (length($poc_bytes) ? 1 : 0);
        held_source_fd_count() + $candidate_count <= $maximum_held_fds or fail();
        $candidates{q{poc-gates.json}} = create_candidate($poc_bytes)
          if length($poc_bytes);
        $candidates{q{manifest.json}} = create_candidate($manifest_bytes);
        $candidates{q{summary.json}} = create_candidate($summary_bytes);
        verify_sources();
        print qq{L:READY\n};
        read_line(64) eq q{K:COMMIT} or fail();

        sub require_absent {
          my ($name) = @_;
          my $handle = openat_handle($output_root, $name,
            O_PATH_LINUX | O_NOFOLLOW);
          if (defined($handle)) { close($handle); fail(); }
          $! == ENOENT or fail();
        }
        sub verify_candidate {
          my ($name) = @_;
          my $handle = $candidates{$name};
          defined($handle) or fail();
          my @held = stat($handle);
          @held && S_ISREG($held[2]) && ($held[2] & 07777) == 0600 &&
            $held[3] == 0 && $held[4] == $< &&
            $held[7] == length($candidate_bytes{$name}) &&
            digest_handle($handle, $held[7], $candidate_maximum{$name}) eq
              sha256_hex($candidate_bytes{$name}) or fail();
        }
        sub link_candidate {
          my ($name) = @_;
          my $handle = $candidates{$name};
          my $empty = q{};
          verify_candidate($name);
          syscall(SYS_linkat(), fileno($handle), $empty, fileno($output_root),
            $name, AT_EMPTY_PATH_LINUX) == 0 or fail();
          my $published = openat_handle($output_root, $name,
            O_RDONLY | O_NOFOLLOW);
          defined($published) or fail();
          my @held = stat($handle);
          my @linked = stat($published);
          @held && @linked && $held[0] == $linked[0] && $held[1] == $linked[1] &&
            $linked[3] == 1 && $linked[7] == length($candidate_bytes{$name}) &&
            digest_handle($published, $linked[7],
              $candidate_maximum{$name}) eq sha256_hex($candidate_bytes{$name}) or fail();
          close($published) or fail();
        }
        sub verify_published_candidate {
          my ($name) = @_;
          my $held = $candidates{$name};
          defined($held) or fail();
          my $published = openat_handle($output_root, $name,
            O_RDONLY | O_NOFOLLOW);
          defined($published) or fail();
          my @held_stat = stat($held);
          my @published_stat = stat($published);
          @held_stat && @published_stat &&
            $held_stat[0] == $published_stat[0] &&
            $held_stat[1] == $published_stat[1] &&
            $published_stat[3] == 1 &&
            $published_stat[7] == length($candidate_bytes{$name}) &&
            digest_handle($published, $published_stat[7],
              $candidate_maximum{$name}) eq
                sha256_hex($candidate_bytes{$name}) or fail();
          close($published) or fail();
        }
        verify_sources();
        require_absent(q{poc-gates.json});
        require_absent(q{manifest.json});
        require_absent(q{summary.json});
        my $signal_set = POSIX::SigSet->new(SIGINT, SIGTERM, SIGHUP, SIGQUIT);
        defined(sigprocmask(SIG_BLOCK, $signal_set)) or fail();
        alarm($commit_deadline);
        if (length($poc_bytes)) {
          link_candidate(q{poc-gates.json});
          verify_sources();
        }
        link_candidate(q{manifest.json});
        if (length($poc_bytes)) {
          verify_published_candidate(q{poc-gates.json});
        } else {
          require_absent(q{poc-gates.json});
        }
        verify_published_candidate(q{manifest.json});
        require_absent(q{summary.json});
        directory_identity($output_root) eq $expected_output or fail();
        verify_candidate(q{summary.json});
        my $summary_candidate_fd = fileno($candidates{q{summary.json}});
        my $output_root_fd = fileno($output_root);
        defined($summary_candidate_fd) && defined($output_root_fd) or fail();
        my $summary_empty = q{};
        my $summary_name = q{summary.json};
        print qq{M:LINKED\n};
        read_line(64) eq q{M:CONTINUE} or fail();
        # This coherent source sweep is the final fallible authority step. The
        # immediately following link is the sole completion-marker operation.
        verify_sources();
        # The summary link is the final filesystem syscall and the completion
        # marker. There is deliberately no post-marker validation or cleanup.
        syscall(SYS_linkat(), $summary_candidate_fd, $summary_empty,
          $output_root_fd, $summary_name, AT_EMPTY_PATH_LINUX) == 0 or fail();
        POSIX::_exit(0);
      ' -- "$OUTPUT_DIR" "$output_identity" "$REPO_ROOT" \
      "$repository_identity" "$NATIVE_BENCHMARK_GIT_COMMAND" \
      "$MAX_TERMINAL_GIT_OUTPUT_BYTES" "$MAX_TERMINAL_GIT_INDEX_ENTRIES" \
      "$MAX_TERMINAL_GIT_WORKTREE_BYTES" \
      "$MAX_TERMINAL_SOURCE_LEAVES" \
      "$MAX_TERMINAL_SOURCE_DIRECTORIES" "$MAX_TERMINAL_SOURCE_TREES" \
      "$MAX_TERMINAL_SOURCE_CHECKOUTS" \
      "$MAX_TERMINAL_SOURCE_NEGATIVES" \
      "$MAX_TERMINAL_SOURCE_DIRECTORY_SELECTORS" \
      "$MAX_TERMINAL_SOURCE_RECORDS" "$MAX_TERMINAL_SOURCE_HELD_FDS" \
      "$MAX_TERMINAL_JAVA_TREE_ENTRIES" \
      "$MAX_TERMINAL_JAVA_TREE_MANIFEST_BYTES" \
      "$MAX_TERMINAL_SOURCE_RECORD_BYTES" \
      "$MAX_TERMINAL_SOURCE_PATH_BYTES" "$MAX_TERMINAL_SOURCE_ROSTER_BYTES" \
      "$MAX_TERMINAL_SOURCE_LEAF_BYTES" "$MAX_POC_GATE_BYTES" \
      "$MAX_MANIFEST_BYTES" "$MAX_SUMMARY_BYTES" \
      "$TERMINAL_PUBLICATION_DEADLINE_SECONDS" \
      "$TERMINAL_PUBLICATION_COMMIT_DEADLINE_SECONDS" \
      "$TERMINAL_NATIVE_SIGNAL_TEST_HOOK"
  }
  native_read_fd="${TERMINAL_SOURCE_NATIVE_HELPER[0]:-}"
  native_write_fd="${TERMINAL_SOURCE_NATIVE_HELPER[1]:-}"
  TERMINAL_SOURCE_HELPER_PID="${TERMINAL_SOURCE_NATIVE_HELPER_PID:-}"
  if [[ ! "$native_read_fd" =~ ^[0-9]+$ || ! "$native_write_fd" =~ ^[0-9]+$ ||
    ! "$TERMINAL_SOURCE_HELPER_PID" =~ ^[1-9][0-9]*$ ]]; then
    [[ "$native_read_fd" =~ ^[0-9]+$ ]] && exec {native_read_fd}<&- || true
    [[ "$native_write_fd" =~ ^[0-9]+$ ]] && exec {native_write_fd}>&- || true
    terminal_publication_session_abort
    return 1
  fi
  if ! exec {TERMINAL_SOURCE_RESPONSE_FD}<&"$native_read_fd"; then
    exec {native_read_fd}<&- || true
    exec {native_write_fd}>&- || true
    terminal_publication_session_abort
    return 1
  fi
  if ! exec {TERMINAL_SOURCE_RECORD_FD}>&"$native_write_fd"; then
    exec {native_read_fd}<&- || true
    exec {native_write_fd}>&- || true
    terminal_publication_session_abort
    return 1
  fi
  exec {native_read_fd}<&-
  exec {native_write_fd}>&-
  if ! IFS= read -r helper_ready <&"$TERMINAL_SOURCE_RESPONSE_FD" ||
    [[ "$helper_ready" != H:READY ]]; then
    terminal_publication_session_abort
    return 1
  fi
  TERMINAL_SOURCE_OUTPUT_ROOT="$OUTPUT_DIR"
  TERMINAL_SOURCE_REPOSITORY_ROOT="$REPO_ROOT"
  TERMINAL_SOURCE_SESSION_ACTIVE=true
}

validate_terminal_source_roster_json_value() {
  local -r roster_value="$1"
  local current_user_id=""

  current_user_id="$(id -u)" || return 1
  [[ "$current_user_id" =~ ^[0-9]+$ ]] || return 1

  printf '%s' "$roster_value" | jq -se \
    --arg current_user_id "$current_user_id" \
    --argjson maximum_leaves "$MAX_TERMINAL_SOURCE_LEAVES" \
    --argjson maximum_directories "$MAX_TERMINAL_SOURCE_DIRECTORIES" \
    --argjson maximum_trees "$MAX_TERMINAL_SOURCE_TREES" \
    --argjson maximum_checkouts "$MAX_TERMINAL_SOURCE_CHECKOUTS" \
    --argjson maximum_negatives "$MAX_TERMINAL_SOURCE_NEGATIVES" \
    --argjson maximum_selectors "$MAX_TERMINAL_SOURCE_DIRECTORY_SELECTORS" \
    --argjson maximum_tree_entries "$MAX_TERMINAL_JAVA_TREE_ENTRIES" \
    --argjson maximum_tree_manifest_bytes "$MAX_TERMINAL_JAVA_TREE_MANIFEST_BYTES" \
    --argjson maximum_git_output_bytes "$MAX_TERMINAL_GIT_OUTPUT_BYTES" \
    --argjson maximum_git_index_entries "$MAX_TERMINAL_GIT_INDEX_ENTRIES" \
    --argjson maximum_git_worktree_bytes "$MAX_TERMINAL_GIT_WORKTREE_BYTES" \
    --argjson maximum_path_bytes "$MAX_TERMINAL_SOURCE_PATH_BYTES" \
    --argjson maximum_source_bytes "$MAX_TERMINAL_SOURCE_LEAF_BYTES" '
      def integer: type == "number" and isfinite and floor == . and
        . >= 0 and . <= 9007199254740991;
      def positive_integer: integer and . > 0;
      def identity($fields): type == "string" and
        (split(":") | length == $fields and all(.[]; test("^(0|[1-9][0-9]*)$")));
      def simple_directory_identity: type == "string" and
        (split(":") as $fields |
          ($fields | length) == 4 and
          ($fields[0] | test("^(0|[1-9][0-9]*)$")) and
          ($fields[1] | test("^[1-9][0-9]*$")) and
          $fields[2] == $current_user_id and
          ($fields[3] | test("^[0-7]{1,2}00$")));
      def manifest_identity: type == "string" and
        (split(":") as $fields |
          ($fields | length) == 5 and
          all($fields[]; test("^(0|[1-9][0-9]*)$")) and
          $fields[2] == $current_user_id and
          ($fields[3] | test("^[0-7]{1,2}00$")));
      def safe_path: type == "string" and length > 0 and
        (length <= $maximum_path_bytes) and
        test("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$") and
        (split("/") | all(. != "." and . != ".."));
      def safe_name: type == "string" and length > 0 and length <= 255 and
        test("^[A-Za-z0-9._-]+$") and . != "." and . != "..";
      def source_locator: .root + "/" + .path;
      def java_operations: [
        "01-bootstrap-stop", "02-bootstrap-discard", "03-nmt-baseline",
        "04-nmt-baseline-confirmation", "05-runtime-baseline", "06-jfr-start",
        "07-jfr-stop", "08-jfr-summary", "10-nmt-postload-summary",
        "11-nmt-postload-diff", "12-runtime-postload"
      ];
      def java_operation_files: [
        "host-after-runtime-before.txt", "host-after.txt",
        "host-before-runtime-after.txt", "host-before.txt", "output",
        "runtime-after.json", "runtime-before.json"
      ];
      def expected_java_entries:
        ((["evidence.json", "identity.txt", "measurement.jfr", "runtime-artifacts.json"] |
            map({kind: "file", path: .})) +
          [{kind: "directory", path: "operations"}] +
          [java_operations[] as $operation |
            {kind: "directory", path: ("operations/" + $operation)},
            (java_operation_files[] |
              {kind: "file", path: ("operations/" + $operation + "/" + .)})]) |
        sort_by(.path);
      length == 1 and (.[0] |
        (keys | sort) == ["checkouts", "directories", "directory_selectors", "kind",
          "leaves", "negatives", "roots", "schema_version", "trees"] and
        .schema_version == 1 and .kind == "terminal-publication-source-authority" and
        (.roots | type == "array" and length == 2 and
          [.[].name] == ["output", "repository"] and
          all(.[]; (keys | sort) == ["identity", "name"] and
            (.identity | identity(7)))) and
        (.directories | type == "array" and length >= 2 and
          length <= $maximum_directories and
          . == (sort_by(.root, .path)) and
          ([.[] | (.root + "/" + .path)] | length == (unique | length)) and
          all(.[]; (keys | sort) == ["identity", "path", "root"] and
            (.root == "output" or .root == "repository") and
            ((.path == ".") or (.path | safe_path)) and
            (.identity | identity(7)))) and
        (.leaves | type == "array" and length <= $maximum_leaves and
          . == (sort_by(.root, .path)) and
          ([.[] | (.root + "/" + .path)] | length == (unique | length)) and
          all(.[]; (keys | sort) == ["identity", "maximum_bytes", "path", "root",
              "sha256", "size_bytes"] and
            (.root == "output" or .root == "repository") and (.path | safe_path) and
            (.identity | identity(8)) and (.maximum_bytes | positive_integer) and
            .maximum_bytes <= $maximum_source_bytes and
            (.size_bytes | positive_integer) and .size_bytes <= .maximum_bytes and
            (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))) and
        (.trees | type == "array" and length <= $maximum_trees and
          . == (sort_by(.root, .path)) and
          ([.[] | source_locator] | length == (unique | length)) and
          all(.[]; . as $tree |
            (keys | sort) == ["directory_count", "entries", "entry_count",
              "file_count", "manifest_sha256", "manifest_size_bytes",
              "parent_identity", "path", "root", "root_identity"] and
            (.root == "output" or .root == "repository") and
            (.path | safe_path) and
            (.parent_identity | simple_directory_identity) and
            (.root_identity | simple_directory_identity) and
            .entry_count == 93 and .entry_count <= $maximum_tree_entries and
            .file_count == 81 and .directory_count == 12 and
            .entry_count == (.file_count + .directory_count) and
            (.manifest_size_bytes | positive_integer) and
            .manifest_size_bytes <= $maximum_tree_manifest_bytes and
            (.manifest_sha256 | type == "string" and
              test("^[0-9a-f]{64}$")) and
            (.entries | type == "array" and length == $tree.entry_count and
              . == (sort_by(.path)) and
              ([.[].path] | length == (unique | length)) and
              all(.[];
                (keys | sort) == ["identity", "kind", "maximum_bytes", "path",
                  "sha256", "size_bytes"] and (.path | safe_path) and
                (.identity | manifest_identity) and (.size_bytes | integer) and
                (if .kind == "file" then
                   (.size_bytes | positive_integer) and
                   (.maximum_bytes | positive_integer) and
                   .maximum_bytes <= $maximum_source_bytes and
                   .size_bytes <= .maximum_bytes and
                   (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
                 else .kind == "directory" and .maximum_bytes == null and
                   .sha256 == null
                 end)) and
              ([.[] | select(.kind == "file")] | length) == $tree.file_count and
              ([.[] | select(.kind == "directory")] | length) ==
                $tree.directory_count and
              ([.[] | {kind, path}] == expected_java_entries)))) and
        (.checkouts | type == "array" and length <= $maximum_checkouts and
          . == (sort_by(.root, .path)) and
          ([.[] | source_locator] | length == (unique | length)) and
          all(.[];
            (keys | sort) == ["checkout_kind", "filesystem_entry_count",
              "filesystem_roster_sha256", "git_tree", "identity",
              "ignored_entry_count", "ignored_roster_sha256",
              "index_entry_count", "index_flags_sha256",
              "index_flags_size_bytes", "path", "revision", "root",
              "source_tree_sha256", "stage_sha256", "stage_size_bytes",
              "tracked_bytes", "tracked_entry_count",
              "tracked_tree_transcript_sha256", "transcript_sha256"] and
            .checkout_kind == "git-clean-checkout-v1" and
            (.root == "output" or .root == "repository") and
            (.path == "." or (.path | safe_path)) and
            (.identity | identity(7)) and
            (.revision | type == "string" and test("^[0-9a-f]{40}$")) and
            (.git_tree | type == "string" and test("^[0-9a-f]{40}$")) and
            (.source_tree_sha256 | type == "string" and
              test("^[0-9a-f]{64}$")) and
            (.index_entry_count | positive_integer) and
            .index_entry_count <= $maximum_git_index_entries and
            (.tracked_entry_count | positive_integer) and
            .tracked_entry_count == .index_entry_count and
            (.tracked_bytes | integer) and
            .tracked_bytes <= $maximum_git_worktree_bytes and
            (.tracked_tree_transcript_sha256 | type == "string" and
              test("^[0-9a-f]{64}$")) and
            (.ignored_entry_count | integer) and
            .ignored_entry_count <= .filesystem_entry_count and
            (.ignored_roster_sha256 | type == "string" and
              test("^[0-9a-f]{64}$")) and
            (.filesystem_entry_count | positive_integer) and
            .filesystem_entry_count <= $maximum_git_index_entries and
            (.filesystem_roster_sha256 | type == "string" and
              test("^[0-9a-f]{64}$")) and
            (.stage_size_bytes | positive_integer) and
            .stage_size_bytes <= $maximum_git_output_bytes and
            (.stage_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
            (.index_flags_size_bytes | positive_integer) and
            .index_flags_size_bytes <= $maximum_git_output_bytes and
            (.index_flags_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
            (.transcript_sha256 | type == "string" and test("^[0-9a-f]{64}$")))) and
        (.negatives | type == "array" and length <= $maximum_negatives and
          . == (sort_by(.root, .path)) and
          ([.[] | source_locator] | length == (unique | length)) and
          all(.[]; . as $negative |
            (keys | sort) == ["identity", "maximum_bytes", "missing_path",
              "path", "root", "size_bytes", "state"] and
            (.root == "output" or .root == "repository") and (.path | safe_path) and
            (.maximum_bytes | positive_integer) and
            .maximum_bytes <= $maximum_source_bytes and
            (if .state == "absent" then
               .identity == null and .size_bytes == null and
               (.missing_path | safe_path) and
               ($negative.path == $negative.missing_path or
                 ($negative.path |
                   startswith($negative.missing_path + "/")))
             else .missing_path == null and
               (.identity | identity(8)) and (.size_bytes | integer) and
               (if .state == "nonregular" then true
                elif .state == "empty" then .size_bytes == 0
                elif .state == "oversize" then .size_bytes > .maximum_bytes
                else false end)
             end))) and
        (.directory_selectors | type == "array" and length <= $maximum_selectors and
          . == (sort_by(.root, .path)) and
          ([.[] | source_locator] | length == (unique | length)) and
          all(.[];
            (keys | sort) == ["identity", "names", "path", "root", "selector"] and
            (.root == "output" or .root == "repository") and (.path | safe_path) and
            (.identity | identity(7)) and
            (if .selector == "benchmark-repetition-json" then
               .names == ["rep-01.json", "rep-02.json", "rep-03.json",
                 "rep-04.json", "rep-05.json"] and
               all(.names[]; safe_name and test("^rep-[0-9]{2}\\.json$"))
             elif .selector == "pressure-recovery-sample-prom" then
               .names == [
                 "map-pressure-pressure-recovered-sample-01.prom",
                 "map-pressure-pressure-recovered-sample-02.prom"
               ] and
               all(.names[]; safe_name and
                 test("^map-pressure-pressure-recovered-sample-[0-9]{2}\\.prom$"))
             else false end))) and
        (([.leaves[], .negatives[]] | map(source_locator) |
          length == (unique | length))) and
        ((.leaves | length) + (.trees | length) + (.checkouts | length) +
          (.negatives | length) +
          (.directory_selectors | length) > 0))
    ' >/dev/null
}

terminal_publication_freeze_sources() {
  local response=""
  local payload=""
  local declared_size=""
  local roster_hex=""
  local roster_value=""

  [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == true &&
    "$TERMINAL_SOURCE_SESSION_FROZEN" == false &&
    "$TERMINAL_SOURCE_RECORD_FD" =~ ^[1-9][0-9]*$ &&
    "$TERMINAL_SOURCE_RESPONSE_FD" =~ ^[1-9][0-9]*$ ]] || return 1
  printf 'F:0:\n' >&"$TERMINAL_SOURCE_RECORD_FD" || return 1
  IFS= read -r response <&"$TERMINAL_SOURCE_RESPONSE_FD" || return 1
  [[ "$response" == R:*:* ]] || return 1
  payload="${response#R:}"
  declared_size="${payload%%:*}"
  roster_hex="${payload#*:}"
  [[ "$declared_size" =~ ^[1-9][0-9]*$ &&
    "$declared_size" -le "$MAX_TERMINAL_SOURCE_ROSTER_BYTES" &&
    "${#roster_hex}" -eq "$((declared_size * 2))" &&
    "$roster_hex" =~ ^[0-9a-f]+$ ]] || return 1
  roster_value="$(printf '%s' "$roster_hex" | \
    run_native_clean_environment "$NATIVE_BENCHMARK_PERL_COMMAND" -T -e '
      use strict;
      use warnings;
      my ($declared, $maximum) = @ARGV;
      $declared =~ /\A[1-9][0-9]*\z/ && $maximum =~ /\A[1-9][0-9]*\z/ &&
        $declared <= $maximum or exit 1;
      my $expected = $declared * 2;
      my $hex = q{};
      while (length($hex) < $expected) {
        my $chunk = q{};
        my $read = sysread(STDIN, $chunk, $expected - length($hex));
        defined($read) && $read > 0 or exit 1;
        $hex .= $chunk;
      }
      my $extra = q{};
      my $read = sysread(STDIN, $extra, 1);
      defined($read) && $read == 0 && $hex =~ /\A[0-9a-f]+\z/ or exit 1;
      my $bytes = pack(q{H*}, $hex);
      length($bytes) == $declared && index($bytes, "\0") < 0 or exit 1;
      print $bytes;
    ' -- "$declared_size" "$MAX_TERMINAL_SOURCE_ROSTER_BYTES")" || return 1
  [[ "${#roster_value}" -eq "$declared_size" ]] || return 1
  validate_terminal_source_roster_json_value "$roster_value" || return 1
  TERMINAL_SOURCE_ROSTER_VALUE="$roster_value"
  TERMINAL_SOURCE_SESSION_ACTIVE=false
  TERMINAL_SOURCE_SESSION_FROZEN=true
}

terminal_publication_send_candidate() {
  local -r name="$1"
  local -r value="$2"
  local -r maximum_bytes="$3"
  local value_size=0
  local value_digest="-"

  [[ "$TERMINAL_SOURCE_SESSION_FROZEN" == true &&
    "$TERMINAL_SOURCE_SESSION_PREPARED" == false &&
    "$TERMINAL_SOURCE_RECORD_FD" =~ ^[1-9][0-9]*$ &&
    ( "$name" == poc-gates.json || "$name" == manifest.json ||
      "$name" == summary.json ) ]] || return 1
  if [[ -z "$value" ]]; then
    [[ "$name" == poc-gates.json ]] || return 1
  else
    value_size="${#value}"
    [[ "$value_size" -gt 0 && "$value_size" -le "$maximum_bytes" ]] || return 1
    value_digest="$(json_value_sha256 "$value")" || return 1
  fi
  printf 'C:%s:%s:%s\n' "$name" "$value_size" "$value_digest" \
    >&"$TERMINAL_SOURCE_RECORD_FD" || return 1
  if ((value_size > 0)); then
    printf '%s' "$value" >&"$TERMINAL_SOURCE_RECORD_FD" || return 1
  fi
}

terminal_publication_prepare_candidates() {
  local -r poc_value="$1"
  local -r manifest_value="$2"
  local -r summary_value="$3"
  local response=""

  terminal_publication_send_candidate \
    poc-gates.json "$poc_value" "$MAX_POC_GATE_BYTES" || return 1
  terminal_publication_send_candidate \
    manifest.json "$manifest_value" "$MAX_MANIFEST_BYTES" || return 1
  terminal_publication_send_candidate \
    summary.json "$summary_value" "$MAX_SUMMARY_BYTES" || return 1
  printf 'X:0:\n' >&"$TERMINAL_SOURCE_RECORD_FD" || return 1
  IFS= read -r response <&"$TERMINAL_SOURCE_RESPONSE_FD" || return 1
  [[ "$response" == L:READY ]] || return 1
  TERMINAL_SOURCE_SESSION_PREPARED=true
}

terminal_publication_session_abort() {
  local helper_pid="$TERMINAL_SOURCE_HELPER_PID"

  if [[ "$TERMINAL_SOURCE_RECORD_FD" =~ ^[1-9][0-9]*$ ]]; then
    exec {TERMINAL_SOURCE_RECORD_FD}>&- || true
  fi
  if [[ "$TERMINAL_SOURCE_RESPONSE_FD" =~ ^[1-9][0-9]*$ ]]; then
    exec {TERMINAL_SOURCE_RESPONSE_FD}<&- || true
  fi
  if [[ "$helper_pid" =~ ^[1-9][0-9]*$ ]]; then
    if [[ "$TERMINAL_PUBLICATION_STARTED" != true ]]; then
      kill -TERM "$helper_pid" 2>/dev/null || true
    fi
    wait "$helper_pid" 2>/dev/null || true
  fi
  terminal_publication_session_clear
}

terminal_publication_commit() {
  local helper_pid="$TERMINAL_SOURCE_HELPER_PID"
  local protocol_status=0
  local response=""
  local wait_status=0

  [[ "$TERMINAL_SOURCE_SESSION_PREPARED" == true &&
    "$TERMINAL_PUBLICATION_STARTED" == false &&
    "$helper_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  json_publication_absence_ready "$OUTPUT_DIR/poc-gates.json" || return 1
  json_publication_absence_ready "$OUTPUT_DIR/manifest.json" || return 1
  json_publication_absence_ready "$OUTPUT_DIR/summary.json" || return 1
  # This is the irreversible commit lease. From this assignment onward no
  # caller may retry, clean visible leaves, or kill an ambiguous helper.
  TERMINAL_PUBLICATION_STARTED=true
  if ! printf 'K:COMMIT\n' >&"$TERMINAL_SOURCE_RECORD_FD"; then
    protocol_status=1
  elif ! IFS= read -r response <&"$TERMINAL_SOURCE_RESPONSE_FD"; then
    protocol_status=1
  elif [[ "$response" != M:LINKED ]]; then
    protocol_status=1
  elif ! printf 'M:CONTINUE\n' >&"$TERMINAL_SOURCE_RECORD_FD"; then
    protocol_status=1
  fi
  exec {TERMINAL_SOURCE_RECORD_FD}>&- || protocol_status=1
  exec {TERMINAL_SOURCE_RESPONSE_FD}<&- || protocol_status=1
  if wait "$helper_pid"; then
    wait_status=0
  else
    wait_status=$?
  fi
  terminal_publication_session_clear
  ((protocol_status == 0 && wait_status == 0))
}

validate_summary_json_value() {
  local -r summary_value="$1"
  local -r expected_status="$2"
  local source_authority=""
  local source_authority_receipt=""
  local source_authority_size=0
  local source_authority_sha256=""
  local source_count=0
  local directory_count=0

  [[ "$expected_status" == passed || "$expected_status" == failed ]] || return 1
  source_authority="$(printf '%s' "$summary_value" | \
    jq -ceS '.source_authority')" || return 1
  source_authority_receipt="$(printf '%s' "$summary_value" | \
    jq -ceS '.source_authority_receipt')" || return 1
  validate_terminal_source_roster_json_value "$source_authority" || return 1
  source_authority_size="${#source_authority}"
  source_authority_sha256="$(json_value_sha256 "$source_authority")" || return 1
  source_count="$(printf '%s' "$source_authority" | jq -er '
    (.leaves | length) + (.trees | length) + (.checkouts | length) +
      (.negatives | length) +
      (.directory_selectors | length)
  ')" || return 1
  directory_count="$(printf '%s' "$source_authority" | \
    jq -er '.directories | length')" || return 1
  printf '%s' "$source_authority_receipt" | jq -e \
    --argjson source_count "$source_count" \
    --argjson directory_count "$directory_count" \
    --argjson size_bytes "$source_authority_size" \
    --arg sha256 "$source_authority_sha256" '
      (keys | sort) == ["directory_count", "sha256", "size_bytes", "source_count"] and
      .source_count == $source_count and .directory_count == $directory_count and
      .size_bytes == $size_bytes and .sha256 == $sha256
    ' >/dev/null || return 1
  printf '%s' "$summary_value" | jq -se \
    --arg status "$expected_status" \
    --argjson core_cells "$(jq -cn '$ARGS.positional' --args "${CORE_CELLS[@]}")" \
    --argjson bounded_cells "$(jq -cn '$ARGS.positional' --args "${BOUNDED_PATH_CELLS[@]}")" \
    --arg mode "$CELLS_MODE" '
      def receipt:
        type == "object" and (keys | sort) == ["path", "sha256", "size_bytes"] and
        .path == "manifest.json" and
        (.size_bytes | type == "number" and isfinite and floor == . and . > 0) and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$"));
      def poc_receipt:
        type == "object" and (keys | sort) == ["path", "sha256", "size_bytes", "status"] and
        (if .status == "available" then
          .path == "poc-gates.json" and
          (.size_bytes | type == "number" and isfinite and floor == . and . > 0) and
          (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
        else .status == "not_available" and .path == null and
          .size_bytes == null and .sha256 == null end);
      def cell_status:
        type == "object" and
        (if .status == "not_run" then (keys | sort) == ["cell", "status"]
         else (keys | sort) == ["cell", "completed_at", "reason", "status"] and
           (.completed_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
           ((.status == "passed" and .reason == null) or
             (.status == "failed" and (.reason | type == "string" and length > 0)))
         end);
      def linked_state($available_status; $path):
        type == "object" and (keys | sort) == ["path", "status"] and
        ((.status == $available_status and .path == $path) or
          (.status == "requested_but_unavailable" and .path == null) or
          (.status == "not_available" and .path == null) or
          (.status == "not_requested" and .path == null));
      def bounded_count:
        type == "number" and isfinite and floor == . and . >= 0 and . <= 6;
      length == 1 and (.[0] |
        (keys | sort) == [
          "acceptance_evidence", "application_source", "artifact_receipts",
          "bounded_path_cells", "cells", "completed_at", "docker_daemon",
          "lookup_paths", "measurement_scope", "native_jni_lookup", "notes",
          "poc_gates", "source_authority", "source_authority_receipt", "status",
          "variance"
        ] and
        .status == $status and .acceptance_evidence == false and
        (.completed_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
        (.artifact_receipts | (keys | sort) == ["manifest", "poc_gates"] and
          (.manifest | receipt) and (.poc_gates | poc_receipt)) and
        (.cells | type == "array" and [.[] | .cell] == $core_cells and all(.[]; cell_status)) and
        (.bounded_path_cells | type == "array" and
          (if $mode == "complete" then [.[] | .cell] == $bounded_cells
           else length == 0 end) and all(.[]; cell_status)) and
        (.variance | linked_state("available"; "variance.json")) and
        (.docker_daemon |
          linked_state("verified_local_unix_socket_endpoint_only"; "docker-daemon.json")) and
        (.application_source as $application_source |
          (if $application_source.status == "clean_and_stable" then
             ($application_source | (keys | sort) ==
               ["git_tree", "path", "revision", "source_tree_sha256",
                "status"] and
               .path == "application-source-identity.json" and
               (.revision | test("^[0-9a-f]{40}$")) and
               (.git_tree | test("^[0-9a-f]{40}$")) and
               (.source_tree_sha256 | test("^[0-9a-f]{64}$")))
           else ($application_source |
             linked_state("clean_and_stable";
               "application-source-identity.json"))
           end) and
          (.source_authority.checkouts as $checkouts |
            if $application_source.status == "clean_and_stable" then
              ($checkouts | length) == 1 and
              $checkouts[0].revision == $application_source.revision and
              $checkouts[0].git_tree == $application_source.git_tree and
              $checkouts[0].source_tree_sha256 ==
                $application_source.source_tree_sha256
            else ($checkouts | length) == 0 end)) and
        (.lookup_paths | linked_state("available"; "lookup-paths.json")) and
        (.native_jni_lookup | linked_state("available"; "native-jni/benchmark.json")) and
        (.poc_gates | type == "object" and
          (keys | sort) == ["path", "result", "status"] and
          (if .status == "not_available" then .path == null and .result == null
           else .status == "partial" and .path == "poc-gates.json" and
             (.result == "failed" or .result == "not_evaluated") end)) and
        (.measurement_scope | type == "object" and
          (keys | sort) == [
            "application_fd_threads_and_java_bridge_map_growth", "bpf_lock_contention",
            "exact_owned_cgroupsockopt_program_counters",
            "jfr_nmt_allocation_native_direct_memory", "nmt_and_direct_memory_recovery_drift",
            "pressure_map_occupancy_and_capacity_rejection",
            "primary_cgroupsockopt_program_cpu"
          ] and
          .nmt_and_direct_memory_recovery_drift ==
            "bounded_indicators_retained_not_evaluated_as_acceptance_gates" and
          .primary_cgroupsockopt_program_cpu == "not_collected" and
          .bpf_lock_contention == "not_collected" and
          (.pressure_map_occupancy_and_capacity_rejection ==
              "bounded_correctness_observed_once" or
            .pressure_map_occupancy_and_capacity_rejection ==
              "requested_but_unavailable" or
            .pressure_map_occupancy_and_capacity_rejection == "not_requested") and
          (.application_fd_threads_and_java_bridge_map_growth | . as $resources |
            (keys | sort) == ["application_cpu_per_successful_request",
              "full_cgroup_v2_process_tree_fd_task_rss", "java_bridge_map",
              "process_fd_threads", "result", "status"] and
            if .status == "not_available" then
              .result == null and .process_fd_threads == null and
              .java_bridge_map == null and
              .full_cgroup_v2_process_tree_fd_task_rss == null and
              .application_cpu_per_successful_request == null
            else
              (.status == "complete" or .status == "partial") and
              (.result == "passed" or .result == "failed" or
                .result == "not_evaluated") and
              all([$resources.process_fd_threads, $resources.java_bridge_map,
                $resources.full_cgroup_v2_process_tree_fd_task_rss,
                $resources.application_cpu_per_successful_request][];
                type == "object")
            end) and
          (.exact_owned_cgroupsockopt_program_counters |
            (keys | sort) == ["acceptance_evidence", "artifact",
              "expected_cell_artifacts", "metric", "retained_cell_artifacts", "status"] and
            .acceptance_evidence == false and
            .artifact == "cells/*/bpf-program-runtime.json" and
            .expected_cell_artifacts == 6 and
            (.retained_cell_artifacts | bounded_count) and
            .metric ==
              "kernel_reported_program_execution_count_and_cumulative_run_time_deltas" and
            ((.status == "available" and .retained_cell_artifacts == 6) or
              (.status == "partially_available" and
                .retained_cell_artifacts > 0 and .retained_cell_artifacts < 6) or
              (.status == "not_available" and .retained_cell_artifacts == 0))) and
          (.jfr_nmt_allocation_native_direct_memory |
            (keys | sort) == ["acceptance_evidence", "artifact",
              "expected_cell_artifacts", "indicators", "retained_cell_artifacts",
              "runtime_artifact_attestation_sha256", "status"] and
            .acceptance_evidence == false and
            .artifact == "cells/*/java-measurement/evidence.json" and
            .expected_cell_artifacts == 6 and
            (.retained_cell_artifacts | bounded_count) and
            .indicators == ["sampled_allocation_weight", "monitor_enter_duration",
              "thread_park_duration", "nmt_committed_and_reserved",
              "direct_buffer_pool"] and
            ((.status == "available" and .retained_cell_artifacts == 6 and
                (.runtime_artifact_attestation_sha256 | test("^[0-9a-f]{64}$"))) or
              (.status == "partially_available" and .retained_cell_artifacts > 0 and
                .retained_cell_artifacts < 6 and
                (.runtime_artifact_attestation_sha256 | test("^[0-9a-f]{64}$"))) or
              (.status == "not_available" and .retained_cell_artifacts == 0 and
                .runtime_artifact_attestation_sha256 == null) or
              (.status == "identity_mismatch" and .retained_cell_artifacts > 0 and
                .runtime_artifact_attestation_sha256 == null)))) and
        (.notes | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)))
    ' >/dev/null
}

validate_summary_artifact_receipts() {
  local -r summary_artifact="$1"
  local -r artifact_root="$2"
  local -r expected_manifest_value="${3:-}"
  local -r expected_poc_value="${4:-}"
  local -r expected_summary_value="${5:-}"
  local summary_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local summary_identity=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local summary_size=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local summary_digest=""
  local manifest_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local manifest_identity=""
  local manifest_size=""
  local manifest_digest=""
  local poc_value=""
  # shellcheck disable=SC2034 # Filled through the dynamic snapshot output name.
  local poc_identity=""
  local poc_size=""
  local poc_digest=""
  local receipt_status=""
  local summary_status=""
  local manifest_status=""
  local receipt_path=""
  local receipt_size=""
  local receipt_digest=""

  [[ "$artifact_root" == /* && -d "$artifact_root" && ! -L "$artifact_root" &&
    "$summary_artifact" == "$artifact_root/summary.json" ]] || return 1
  bounded_duplicate_free_json_image "$summary_artifact" "$MAX_SUMMARY_BYTES" \
    summary_value summary_identity summary_size summary_digest || return 1
  if [[ -n "$expected_summary_value" ]]; then
    [[ "$summary_value" == "$expected_summary_value" ]] || return 1
  fi
  summary_status="$(printf '%s' "$summary_value" | jq -er '.status')" || return 1
  validate_summary_json_value "$summary_value" "$summary_status" || return 1
  printf '%s' "$summary_value" | jq -e '
    (.artifact_receipts | type == "object" and
      (keys | sort) == ["manifest", "poc_gates"]) and
    (.artifact_receipts.manifest | type == "object" and
      (keys | sort) == ["path", "sha256", "size_bytes"] and
      .path == "manifest.json" and
      (.size_bytes | type == "number" and floor == . and . > 0) and
      (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) and
    (.artifact_receipts.poc_gates | type == "object" and
      (keys | sort) == ["path", "sha256", "size_bytes", "status"] and
      (if .status == "available" then
         .path == "poc-gates.json" and
         (.size_bytes | type == "number" and floor == . and . > 0) and
         (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
       elif .status == "not_available" then
         .path == null and .size_bytes == null and .sha256 == null
       else false end))
  ' >/dev/null || return 1
  receipt_path="$(printf '%s' "$summary_value" | \
    jq -er '.artifact_receipts.manifest.path')" || return 1
  receipt_size="$(printf '%s' "$summary_value" | \
    jq -er '.artifact_receipts.manifest.size_bytes')" || return 1
  receipt_digest="$(printf '%s' "$summary_value" | \
    jq -er '.artifact_receipts.manifest.sha256')" || return 1
  [[ "$receipt_path" == manifest.json ]] || return 1
  bounded_duplicate_free_json_image "$artifact_root/$receipt_path" \
    "$MAX_MANIFEST_BYTES" manifest_value manifest_identity manifest_size \
    manifest_digest || return 1
  [[ "$manifest_size" == "$receipt_size" &&
    "$manifest_digest" == "$receipt_digest" ]] || return 1
  validate_manifest_json_value "$manifest_value" || return 1
  manifest_status="$(printf '%s' "$manifest_value" | jq -er '.status')" || return 1
  [[ "$summary_status" == "$manifest_status" ]] || return 1
  if [[ -n "$expected_manifest_value" ]]; then
    [[ "$manifest_value" == "$expected_manifest_value" ]] || return 1
  fi
  receipt_status="$(printf '%s' "$summary_value" | \
    jq -er '.artifact_receipts.poc_gates.status')" || return 1
  if [[ "$receipt_status" == available ]]; then
    receipt_path="$(printf '%s' "$summary_value" | \
      jq -er '.artifact_receipts.poc_gates.path')" || return 1
    receipt_size="$(printf '%s' "$summary_value" | \
      jq -er '.artifact_receipts.poc_gates.size_bytes')" || return 1
    receipt_digest="$(printf '%s' "$summary_value" | \
      jq -er '.artifact_receipts.poc_gates.sha256')" || return 1
    [[ "$receipt_path" == poc-gates.json ]] || return 1
    bounded_duplicate_free_json_image "$artifact_root/$receipt_path" \
      "$MAX_POC_GATE_BYTES" poc_value poc_identity poc_size poc_digest || return 1
    [[ "$poc_size" == "$receipt_size" &&
      "$poc_digest" == "$receipt_digest" ]] || return 1
    validate_poc_gate_json_value_against_manifest_value \
      "$poc_value" "$manifest_value" "$expected_poc_value" || return 1
    printf '%s\n%s' "$summary_value" "$poc_value" | jq -es '
      if length != 2 then error("expected summary and PoC") else . end |
      .[0] as $summary |
      .[1] as $poc |
      $summary.cells == $poc.correctness.cells and
      $summary.poc_gates ==
        ($poc | {status, path: "poc-gates.json", result}) and
      $summary.measurement_scope.application_fd_threads_and_java_bridge_map_growth == {
        status: $poc.resources.status,
        result: $poc.resources.result,
        process_fd_threads: $poc.resources.process_dimension,
        java_bridge_map: $poc.resources.map_dimension,
        full_cgroup_v2_process_tree_fd_task_rss: $poc.resources.process_tree,
        application_cpu_per_successful_request: $poc.resources.application_cpu
      }
    ' >/dev/null || return 1
  else
    printf '%s' "$summary_value" | jq -e '
      .poc_gates == {status: "not_available", path: null, result: null} and
      .measurement_scope.application_fd_threads_and_java_bridge_map_growth == {
        status: "not_available",
        result: null,
        process_fd_threads: null,
        java_bridge_map: null,
        full_cgroup_v2_process_tree_fd_task_rss: null,
        application_cpu_per_successful_request: null
      }
    ' >/dev/null || return 1
    [[ -z "$expected_poc_value" &&
      ! -e "$artifact_root/poc-gates.json" &&
      ! -L "$artifact_root/poc-gates.json" ]] || return 1
  fi
}

write_summary_transaction_body() {
  local status="$1"
  local cell=""
  local status_file=""
  local cells_json=""
  local current_cells_json=""
  local bounded_cells_json="[]"
  local lookup_paths_json='{"status":"not_requested","path":null}'
  local native_jni_json='{"status":"not_requested","path":null}'
  local docker_daemon_json='{"status":"requested_but_unavailable","path":null}'
  # shellcheck disable=SC2034 # Filled through the dynamic provenance output name.
  local docker_daemon_value=""
  local application_source_json='{"status":"requested_but_unavailable","path":null}'
  local application_source_value=""
  local poc_gates_json='{"status":"not_available","path":null,"result":null}'
  local poc_resources_json='{"status":"not_available","result":null,"process_dimension":null,"map_dimension":null,"process_tree":null,"application_cpu":null}'
  local bpf_program_counters_json=""
  local bpf_program_counters_status="not_available"
  local bpf_program_artifact=""
  # shellcheck disable=SC2034 # Filled through the dynamic BPF validator output name.
  local bpf_program_value=""
  local bpf_program_artifact_count=0
  local java_runtime_indicators_json=""
  local java_runtime_indicators_status="not_available"
  # shellcheck disable=SC2034 # Retained as a dynamic Java artifact output seam.
  local java_runtime_artifact=""
  local java_runtime_bundle=""
  local java_runtime_artifact_count=0
  local java_runtime_artifact_sha256=""
  local java_runtime_reference_sha256=""
  local java_runtime_artifact_identity_mismatch=false
  local variance_json=""
  local in_progress_manifest_value=""
  local terminal_poc_gate_value=""
  local terminal_poc_gate_size=""
  local terminal_poc_gate_sha256=""
  local terminal_manifest_value=""
  local terminal_manifest_size=""
  local terminal_manifest_sha256=""
  local manifest_receipt_json=""
  local poc_receipt_json='{"status":"not_available","path":null,"size_bytes":null,"sha256":null}'
  local summary_value=""
  local source_authority_value=""
  local source_authority_receipt_json=""
  local source_authority_size=""
  local source_authority_sha256=""
  local source_authority_count=""
  local source_authority_directory_count=""
  local completed_at=""
  local optional_source_status=0

  [[ "$OUTPUT_READY" == "true" ]] || return 0
  in_progress_manifest_value="$(validated_manifest_json_value \
    "$OUTPUT_DIR/manifest.in-progress.json")" || return 1
  if [[ -n "$POC_GATE_HELD_VALUE" ]]; then
    [[ "$POC_GATE_HELD_SIZE" == "${#POC_GATE_HELD_VALUE}" &&
      "$POC_GATE_HELD_SHA256" == \
        "$(json_value_sha256 "$POC_GATE_HELD_VALUE")" ]] || return 1
    validate_poc_gate_json_value_against_root "$POC_GATE_HELD_VALUE" \
      "$OUTPUT_DIR" "$in_progress_manifest_value" || return 1
    terminal_poc_gate_value="$POC_GATE_HELD_VALUE"
    terminal_poc_gate_size="${#terminal_poc_gate_value}"
    terminal_poc_gate_sha256="$(json_value_sha256 \
      "$terminal_poc_gate_value")" || return 1
  fi
  if [[ "$CELLS_MODE" == "complete" ]]; then
    lookup_paths_json='{"status":"requested_but_unavailable","path":null}'
    native_jni_json='{"status":"requested_but_unavailable","path":null}'
  fi
  if [[ "$status" == "passed" ]]; then
    validate_docker_daemon_provenance \
      "$OUTPUT_DIR/docker-daemon.json" docker_daemon_value || return 1
    docker_daemon_json='{"status":"verified_local_unix_socket_endpoint_only","path":"docker-daemon.json"}'
    validate_application_source_identity_schema \
      "$OUTPUT_DIR/application-source-identity.json" "$REPO_ROOT" true \
      application_source_value || return 1
    [[ "$(printf '%s' "$application_source_value" | jq -er '.cells_mode')" == \
      "$CELLS_MODE" ]] || return 1
    application_source_json="$(printf '%s' "$application_source_value" | jq -ce '
      {status: "clean_and_stable", path: "application-source-identity.json",
       revision, git_tree, source_tree_sha256}
    ')" || return 1
    validate_variance_summary_schema "$OUTPUT_DIR/variance.json" || return 1
    variance_json='{"status":"available","path":"variance.json"}'
    if [[ "$CELLS_MODE" == "complete" ]]; then
      validate_lookup_path_summary_schema "$OUTPUT_DIR/lookup-paths.json" || return 1
      validate_native_jni_benchmark_schema "$OUTPUT_DIR/native-jni/benchmark.json" || return 1
      lookup_paths_json='{"status":"available","path":"lookup-paths.json"}'
      native_jni_json='{"status":"available","path":"native-jni/benchmark.json"}'
    fi
  else
    if terminal_optional_source_is_capturable \
      "$OUTPUT_DIR/docker-daemon.json" "$MAX_BOUNDARY_SNAPSHOT_BYTES"; then
      validate_docker_daemon_provenance \
        "$OUTPUT_DIR/docker-daemon.json" docker_daemon_value || return 1
      docker_daemon_json='{"status":"verified_local_unix_socket_endpoint_only","path":"docker-daemon.json"}'
    else
      optional_source_status=$?
      ((optional_source_status == 1)) || return 1
    fi
    if terminal_optional_source_is_capturable \
      "$OUTPUT_DIR/application-source-identity.json" \
      "$MAX_APPLICATION_SOURCE_IDENTITY_BYTES"; then
      validate_application_source_identity_schema \
        "$OUTPUT_DIR/application-source-identity.json" "$REPO_ROOT" true \
        application_source_value || return 1
      [[ "$(printf '%s' "$application_source_value" | jq -er '.cells_mode')" == \
        "$CELLS_MODE" ]] || return 1
      application_source_json="$(printf '%s' "$application_source_value" | jq -ce '
        {status: "clean_and_stable", path: "application-source-identity.json",
         revision, git_tree, source_tree_sha256}
      ')" || return 1
    else
      optional_source_status=$?
      ((optional_source_status == 1)) || return 1
    fi
    if terminal_optional_source_is_capturable \
      "$OUTPUT_DIR/variance.json" "$MAX_VARIANCE_BYTES"; then
      validate_variance_summary_schema "$OUTPUT_DIR/variance.json" || return 1
      variance_json='{"status":"available","path":"variance.json"}'
    else
      optional_source_status=$?
      ((optional_source_status == 1)) || return 1
      variance_json='{"status":"not_available","path":null}'
    fi
    if [[ "$CELLS_MODE" == "complete" ]]; then
      if terminal_optional_source_is_capturable \
        "$OUTPUT_DIR/lookup-paths.json" "$MAX_LOOKUP_PATH_SUMMARY_BYTES"; then
        validate_lookup_path_summary_schema \
          "$OUTPUT_DIR/lookup-paths.json" || return 1
        lookup_paths_json='{"status":"available","path":"lookup-paths.json"}'
      else
        optional_source_status=$?
        ((optional_source_status == 1)) || return 1
      fi
      if terminal_optional_source_is_capturable \
        "$OUTPUT_DIR/native-jni/benchmark.json" "$MAX_NATIVE_BENCHMARK_BYTES"; then
        validate_native_jni_benchmark_schema \
          "$OUTPUT_DIR/native-jni/benchmark.json" || return 1
        native_jni_json='{"status":"available","path":"native-jni/benchmark.json"}'
      else
        optional_source_status=$?
        ((optional_source_status == 1)) || return 1
      fi
    fi
  fi
  [[ ! -e "$OUTPUT_DIR/summary.json" ||
    ( -f "$OUTPUT_DIR/summary.json" && ! -L "$OUTPUT_DIR/summary.json" ) ]] || return 1
  current_cells_json="$({
    for cell in "${CORE_CELLS[@]}"; do
      status_file="$OUTPUT_DIR/cells/$cell/status.json"
      if terminal_optional_source_is_capturable \
        "$status_file" "$MAX_CELL_STATUS_BYTES"; then
        validated_cell_status_json_value "$status_file" "$cell"
      else
        optional_source_status=$?
        ((optional_source_status == 1)) || return 1
        jq -nc --arg cell "$cell" '{status: "not_run", cell: $cell}'
      fi
    done
  } | jq -s .)" || return 1
  cells_json="$current_cells_json"
  for cell in "${CORE_CELLS[@]}"; do
    bpf_program_artifact="$OUTPUT_DIR/cells/$cell/bpf-program-runtime.json"
    if terminal_optional_source_is_capturable \
      "$bpf_program_artifact" "$MAX_BPF_PROGRAM_RUNTIME_BYTES"; then
      cell_spec "$cell" || return 1
      validate_exact_owned_cgroup_sockopt_runtime \
        "$bpf_program_artifact" bpf_program_value || return 1
      ((bpf_program_artifact_count += 1))
    else
      optional_source_status=$?
      ((optional_source_status == 1)) || return 1
    fi
  done
  for cell in "${CORE_CELLS[@]}"; do
    java_runtime_bundle=""
    if terminal_java_measurement_sources_are_capturable \
      "$OUTPUT_DIR/cells/$cell"; then
      validate_published_java_measurement \
        "$OUTPUT_DIR/cells/$cell" java_runtime_bundle || return 1
      [[ "$(printf '%s' "$java_runtime_bundle" | jq -er '.evidence.cell')" == \
        "$cell" ]] || return 1
      java_runtime_artifact_sha256="$(printf '%s' "$java_runtime_bundle" | jq -er \
        '.runtime_artifact_attestation_sha256')" || return 1
      [[ "$java_runtime_artifact_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
      if [[ -z "$java_runtime_reference_sha256" ]]; then
        java_runtime_reference_sha256="$java_runtime_artifact_sha256"
      elif [[ "$java_runtime_artifact_sha256" != \
        "$java_runtime_reference_sha256" ]]; then
        java_runtime_artifact_identity_mismatch=true
      fi
      ((java_runtime_artifact_count += 1))
    else
      optional_source_status=$?
      ((optional_source_status == 1)) || return 1
    fi
  done
  if [[ "$java_runtime_artifact_identity_mismatch" == true ]]; then
    java_runtime_indicators_status="identity_mismatch"
    java_runtime_reference_sha256=""
  elif ((java_runtime_artifact_count == ${#CORE_CELLS[@]})); then
    java_runtime_indicators_status="available"
  elif ((java_runtime_artifact_count > 0)); then
    java_runtime_indicators_status="partially_available"
  fi
  [[ "$status" != "passed" ||
    ( "$java_runtime_artifact_count" == "${#CORE_CELLS[@]}" &&
      "$java_runtime_artifact_identity_mismatch" == false ) ]] || return 1
  java_runtime_indicators_json="$(jq -cn \
    --arg status "$java_runtime_indicators_status" \
    --arg runtime_artifact_attestation_sha256 "$java_runtime_reference_sha256" \
    --argjson retained_cell_artifacts "$java_runtime_artifact_count" \
    --argjson expected_cell_artifacts "${#CORE_CELLS[@]}" '{
      status: $status,
      artifact: "cells/*/java-measurement/evidence.json",
      runtime_artifact_attestation_sha256: (
        if $runtime_artifact_attestation_sha256 == "" then null
        else $runtime_artifact_attestation_sha256 end
      ),
      retained_cell_artifacts: $retained_cell_artifacts,
      expected_cell_artifacts: $expected_cell_artifacts,
      indicators: [
        "sampled_allocation_weight", "monitor_enter_duration",
        "thread_park_duration", "nmt_committed_and_reserved",
        "direct_buffer_pool"
      ],
      acceptance_evidence: false
    }')" || return 1
  if ((bpf_program_artifact_count == ${#CORE_CELLS[@]})); then
    bpf_program_counters_status="available"
  elif ((bpf_program_artifact_count > 0)); then
    bpf_program_counters_status="partially_available"
  fi
  [[ "$status" != "passed" ||
    "$bpf_program_artifact_count" == "${#CORE_CELLS[@]}" ]] || return 1
  bpf_program_counters_json="$(jq -cn \
    --arg status "$bpf_program_counters_status" \
    --argjson retained_cell_artifacts "$bpf_program_artifact_count" \
    --argjson expected_cell_artifacts "${#CORE_CELLS[@]}" '{
      status: $status,
      artifact: "cells/*/bpf-program-runtime.json",
      retained_cell_artifacts: $retained_cell_artifacts,
      expected_cell_artifacts: $expected_cell_artifacts,
      metric: "kernel_reported_program_execution_count_and_cumulative_run_time_deltas",
      acceptance_evidence: false
    }')" || return 1
  if [[ "$CELLS_MODE" == "complete" ]]; then
    bounded_cells_json="$({
      for cell in "${BOUNDED_PATH_CELLS[@]}"; do
        status_file="$OUTPUT_DIR/cells/$cell/status.json"
        if terminal_optional_source_is_capturable \
          "$status_file" "$MAX_CELL_STATUS_BYTES"; then
          validated_cell_status_json_value "$status_file" "$cell"
        else
          optional_source_status=$?
          ((optional_source_status == 1)) || return 1
          jq -nc --arg cell "$cell" '{status: "not_run", cell: $cell}'
        fi
      done
    } | jq -s .)" || return 1
  fi
  # This is the final live-source operation. It regenerates from current
  # sources without an expected-value shortcut; the native session records
  # every held read and rejects a conflicting repeat. A failed harness may
  # truthfully omit PoC gates, but a passed harness cannot.
  if [[ -n "$terminal_poc_gate_value" ]]; then
    validate_poc_gate_json_value_against_root "$terminal_poc_gate_value" \
      "$OUTPUT_DIR" "$in_progress_manifest_value" || return 1
  fi
  [[ "$status" != passed || -n "$terminal_poc_gate_value" ]] || return 1
  terminal_publication_freeze_sources || return 1
  source_authority_value="$TERMINAL_SOURCE_ROSTER_VALUE"
  source_authority_size="${#source_authority_value}"
  source_authority_sha256="$(json_value_sha256 \
    "$source_authority_value")" || return 1
  source_authority_count="$(printf '%s' "$source_authority_value" | \
    jq -er '
      (.leaves | length) + (.trees | length) + (.checkouts | length) +
        (.negatives | length) +
        (.directory_selectors | length)
    ')" || return 1
  source_authority_directory_count="$(printf '%s' "$source_authority_value" | \
    jq -er '.directories | length')" || return 1
  source_authority_receipt_json="$(jq -cn \
    --argjson source_count "$source_authority_count" \
    --argjson directory_count "$source_authority_directory_count" \
    --argjson size_bytes "$source_authority_size" \
    --arg sha256 "$source_authority_sha256" '{
      source_count: $source_count,
      directory_count: $directory_count,
      size_bytes: $size_bytes,
      sha256: $sha256
    }')" || return 1
  if [[ -n "$terminal_poc_gate_value" ]]; then
    if [[ "$status" == passed ]]; then
      validate_supported_poc_dimensions_json_value \
        "$terminal_poc_gate_value" || return 1
    fi
    cells_json="$(printf '%s' "$terminal_poc_gate_value" | \
      jq -ce '.correctness.cells')" || return 1
    poc_gates_json="$(printf '%s' "$terminal_poc_gate_value" | \
      jq -c '{status, path: "poc-gates.json", result}')" || return 1
    poc_resources_json="$(printf '%s' "$terminal_poc_gate_value" | jq -c \
      '.resources | {status, result, process_dimension, map_dimension, process_tree, application_cpu}')" || return 1
  fi
  terminal_manifest_value="$(manifest_json "$status")" || return 1
  terminal_manifest_value="$(printf '%s' "$terminal_manifest_value" | \
    jq -ceS .)" || return 1
  validate_manifest_json_value "$terminal_manifest_value" || return 1
  terminal_manifest_size="${#terminal_manifest_value}"
  terminal_manifest_sha256="$(json_value_sha256 \
    "$terminal_manifest_value")" || return 1
  manifest_receipt_json="$(jq -cn \
    --arg path manifest.json \
    --argjson size_bytes "$terminal_manifest_size" \
    --arg sha256 "$terminal_manifest_sha256" \
    '{path: $path, size_bytes: $size_bytes, sha256: $sha256}')" || return 1
  if [[ "$(printf '%s' "$poc_gates_json" | jq -er '.path // empty')" == \
    poc-gates.json ]]; then
    [[ -n "$terminal_poc_gate_value" &&
      "$terminal_poc_gate_size" == "${#terminal_poc_gate_value}" &&
      "$terminal_poc_gate_sha256" == \
        "$(json_value_sha256 "$terminal_poc_gate_value")" ]] || return 1
    poc_receipt_json="$(jq -cn \
      --arg status available \
      --arg path poc-gates.json \
      --argjson size_bytes "$terminal_poc_gate_size" \
      --arg sha256 "$terminal_poc_gate_sha256" \
      '{status: $status, path: $path, size_bytes: $size_bytes, sha256: $sha256}')" || return 1
  fi
  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || return 1
  summary_value="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$cells_json" "$bounded_cells_json" "$variance_json" \
    "$lookup_paths_json" "$native_jni_json" "$docker_daemon_json" \
    "$application_source_json" "$poc_gates_json" "$poc_resources_json" \
    "$bpf_program_counters_json" "$java_runtime_indicators_json" \
    "$manifest_receipt_json" "$poc_receipt_json" \
    "$source_authority_value" "$source_authority_receipt_json" | jq -ceSs \
    --arg status "$status" \
    --arg completed_at "$completed_at" '
    if length != 15 then error("expected exact held summary input roster") else . end |
    .[0] as $cells |
    .[1] as $bounded_cells |
    .[2] as $variance |
    .[3] as $lookup_paths |
    .[4] as $native_jni |
    .[5] as $docker_daemon |
    .[6] as $application_source |
    .[7] as $poc_gates |
    .[8] as $poc_resources |
    .[9] as $bpf_program_counters |
    .[10] as $java_runtime_indicators |
    .[11] as $manifest_receipt |
    .[12] as $poc_receipt |
    .[13] as $source_authority |
    .[14] as $source_authority_receipt |
    {
      status: $status,
      acceptance_evidence: false,
      completed_at: $completed_at,
      artifact_receipts: {
        manifest: $manifest_receipt,
        poc_gates: $poc_receipt
      },
      source_authority: $source_authority,
      source_authority_receipt: $source_authority_receipt,
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
          java_bridge_map: $poc_resources.map_dimension,
          full_cgroup_v2_process_tree_fd_task_rss: $poc_resources.process_tree,
          application_cpu_per_successful_request: $poc_resources.application_cpu
        },
        nmt_and_direct_memory_recovery_drift:
          "bounded_indicators_retained_not_evaluated_as_acceptance_gates",
        jfr_nmt_allocation_native_direct_memory: $java_runtime_indicators,
        exact_owned_cgroupsockopt_program_counters: $bpf_program_counters,
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
        "variance.json is the sustained application performance benchmark; poc-gates.json applies the predeclared PoC thresholds to its fixed five-repetition medians and throughput/p99 population CVs.",
        "Each repetition has one scheduled full-tree sample at floor(duration_seconds/2) after confirmed client launch; a client that is not live at that boundary fails the absolute resource gate closed.",
        "Unavailable dimensions in manifest.json are not measured as zero.",
        "The full cgroup-v2 tree resource dimension evaluates FD, task, Threads, and RSS envelopes at before, every load boundary, after-load, and both ordered recovery samples; unavailable samples cannot pass.",
        "Java bridge map counters are evaluated only when both scrapes are bracketed by the same exact OBI process identity and open BPF FD roster; unrelated host-global map IDs are excluded.",
        "Application CPU uses exact cgroup-v2 cpu.stat deltas per successful request for OBI, Java, and their exact sum; primary BPF-program CPU and synchronization/lock-wait remain uncollected.",
        "docker-daemon.json proves only that the selected endpoint was a stable existing non-symlink Unix socket; it does not prove where the daemon process runs.",
        "Each available process sample separately binds the exact inspected container ID to bounded local procfs cgroup, PID-start-time, and cgroup-digest evidence.",
        "A passed summary status means the harness completed successfully; poc-gates.json remains partial and is not issue-acceptance evidence.",
        "Sealed JFR sampled-allocation weight per successful request is evaluated only as an exploratory regression indicator with the declared max(10% baseline, 1024-byte) allowance; it is not an exact allocation count, production SLO evidence, or issue-acceptance evidence.",
        "JFR monitor/park events, NMT summary totals/deltas, and the direct-buffer pool remain bounded indicators; they are not all native/off-heap memory or issue-acceptance evidence.",
        "The size-bounded JFR may retain only a bounded tail if its 32 MiB limit is reached; whole-window event retention is explicitly not attested.",
        "Every available Java runtime indicator cell is bound to one exact benchmark image, helper JAR/source, and JFR settings attestation shared across the six-cell aggregate.",
        "The retained raw JFR is private bounded diagnostic input; normalized receipts expose only low-cardinality counts, deltas, and digests and never class names, stack frames, JVM arguments, system properties, request markers, or source paths.",
        "Primary-program CPU utilization and BPF lock contention remain uncollected."
      ]
    }')" || return 1
  validate_summary_json_value "$summary_value" "$status" || return 1
  if [[ "$status" == passed ]]; then
    [[ -n "$application_source_value" &&
      "$(printf '%s' "$application_source_value" | jq -er '.cells_mode')" == \
        "$CELLS_MODE" ]] || return 1
  fi
  terminal_publication_prepare_candidates "$terminal_poc_gate_value" \
    "$terminal_manifest_value" "$summary_value" || return 1
  terminal_publication_commit
}

write_summary() {
  local -r status="$1"
  local result=0

  [[ "$OUTPUT_READY" == true ]] || return 0
  terminal_publication_session_begin || return 1
  if write_summary_transaction_body "$status"; then
    return 0
  else
    result=$?
  fi
  terminal_publication_session_abort
  return "$result"
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

abort_active_benchmark() {
  # Snapshot the publication target and its launch-time binding before process
  # cleanup clears the active globals. Reap first through the existing verified
  # PID/session logic, then discard only that exact unpublished .partial path.
  local -r benchmark_output="$BENCHMARK_OUTPUT"
  local -r benchmark_cell_dir="$BENCHMARK_CELL_DIR"
  local -r benchmark_parent_identity="$BENCHMARK_OUTPUT_PARENT_IDENTITY"
  local abort_status=0

  terminate_active_benchmark || abort_status=$?
  if [[ -n "$benchmark_output" || -n "$benchmark_cell_dir" ||
    -n "$benchmark_parent_identity" ]]; then
    discard_benchmark_partial \
      "$benchmark_output" "$benchmark_cell_dir" "$benchmark_parent_identity" || abort_status=1
  fi
  return "$abort_status"
}

on_exit() {
  local status="$1"
  local final_status="$status"

  trap - EXIT INT TERM
  set +e
  discard_scheduled_midpoint_partial || final_status=1
  abort_active_benchmark || final_status=1
  discard_active_java_measurement || final_status=1
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
      if [[ "$TERMINAL_PUBLICATION_STARTED" != true ]]; then
        write_summary failed || final_status=1
      fi
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
  validate_supported_poc_dimensions_json_value "$POC_GATE_HELD_VALUE"
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
