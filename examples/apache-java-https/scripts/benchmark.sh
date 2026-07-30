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
# The benchmark client gives every request the same parent duration context.
# This permits only scheduler and worker-drain jitter after that deadline; it
# is deliberately independent of the external command's startup allowance.
readonly MEASUREMENT_OVERRUN_TOLERANCE_SECONDS=2
readonly MIN_DURATION_SECONDS=2
readonly MAX_DURATION_SECONDS=600
readonly MIN_CONCURRENCY=1
readonly MAX_CONCURRENCY=256
readonly MIN_REPETITIONS=5
readonly MAX_REPETITIONS=10
readonly MAX_SEED=9223372036854775807
readonly MAX_JAVA_DIAGNOSTIC_COUNTER=999999999
readonly MAX_BPF_OPERATION_COUNTER=9223372036854775807
readonly MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES=4096
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
readonly CORE_CELLS=(uninstrumented bridge-disabled getsockopt-hit unix-hit getsockopt-w3c getsockopt-helper-idle)
readonly W3C_DISCARD_CELLS=(getsockopt-w3c)

OUTPUT_DIR=""
OUTPUT_PARENT=""
AGENT="otel"
TLS_PROTOCOL="TLSv1.3"
WARMUP_SECONDS=10
DURATION_SECONDS=30
CONCURRENCY=16
REPETITIONS=5
SEED=20260721
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
    '  --repetitions N          5-10. Default: 5' \
    '  --seed N                 0-9223372036854775807. Default: 20260721' \
    '  --cells core             The six comparable core cells. Default: core' \
    '  -h, --help               Show this help text.' \
    '' \
    'The total worker-seconds across all six cells must not exceed 120000.'
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

require_value() {
  local -r option="$1"
  local -r argument_count="$2"

  ((argument_count >= 2)) || die "missing value for $option"
}

parse_args() {
  local value=""
  local cells="core"
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
          die "$1 must be an integer between $MIN_REPETITIONS and $MAX_REPETITIONS"
          return $?
        }
        ((value >= MIN_REPETITIONS)) || {
          die "$1 must be an integer between $MIN_REPETITIONS and $MAX_REPETITIONS"
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
        cells="$2"
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
  [[ "$cells" == "core" ]] || {
    die "--cells currently supports only core"
    return $?
  }
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
  for command_name in awk chmod curl date docker env find flock git grep head id install jq mkdir mktemp mv rm setsid sort stat timeout tr uname wc; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
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
  jq -n 'isfinite' >/dev/null 2>&1 || {
    die "jq with finite-number predicates is required"
    return $?
  }
  [[ -x "$RUNNER" && -f "$COMPOSE_FILE" ]] || {
    die "demo runner or Compose file is unavailable"
    return $?
  }
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
  CELL_SENTINEL_SCENARIO="concurrency"
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
      ;;
    getsockopt-w3c)
      CELL_TRANSPORT="getsockopt"
      CELL_SCENARIO="w3c"
      CELL_ASSERTION_MODE=""
      CELL_REQUIRES_OBI=true
      CELL_SELECTED_TRANSPORT="getsockopt"
      CELL_SENTINEL_SCENARIO="w3c"
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

write_manifest() {
  local cells_json=""
  local w3c_discard_cells_json=""
  local w3c_headers_by_cell_json=""
  local workload_by_cell_json=""

  cells_json="$(jq -cn '$ARGS.positional' --args "${CORE_CELLS[@]}")" || return 1
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
      agent: $agent,
      tls_protocol: $tls,
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
      cells: $cells,
      total_worker_seconds: $total_worker_seconds,
      unavailable_dimensions: {
        jni_lookup_latency_percentiles: "not_collected",
        jfr_nmt_allocation_native_direct_memory: "not_collected",
        primary_cgroupsockopt_program_cpu: "not_collected",
        bpf_map_insert_failures: "not_collected",
        bpf_map_evictions: "not_collected",
        bpf_lock_contention: "not_collected"
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
    run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
      docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}' || true
    run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker compose version || true
  } >"$OUTPUT_DIR/host-environment.txt" 2>&1
}

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
    --argjson requests "$PREFLIGHT_REQUESTS" \
    --argjson seed "$SEED" \
    --argjson requires_obi "$CELL_REQUIRES_OBI" \
    --argjson sustained_w3c "$CELL_SUSTAINED_W3C" \
    --argjson helper_idle "$CELL_HELPER_IDLE" \
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
    runner_environment_matches "$environment_file" request_count "$PREFLIGHT_REQUESTS" &&
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

capture_service_identity() {
  local -r service="$1"
  local -r output="$2"
  local container_id=""
  local inspected_id=""
  local host_pid=""
  local project=""
  local sentinel=""
  local extra=""
  local inspection=""

  container_id="$(compose_service_id "$service")" || return 1
  inspection="$(run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" docker inspect --format \
    "{{.Id}} {{.State.Pid}} {{index .Config.Labels \"com.docker.compose.project\"}} {{index .Config.Labels \"$PROJECT_SENTINEL_LABEL\"}}" \
    "$container_id")" || return 1
  read -r inspected_id host_pid project sentinel extra <<<"$inspection" || return 1
  [[ "$inspected_id" == "$container_id"* && "$host_pid" =~ ^[1-9][0-9]*$ &&
    "$project" == "$ACTIVE_PROJECT" && "$sentinel" == "$PROJECT_SENTINEL_VALUE" &&
    -z "$extra" ]] || return 1
  {
    printf 'service=%s\n' "$service"
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$host_pid"
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

capture_proc_snapshot() {
  local -r host_pid="$1"
  local -r output="$2"
  local fd_count=""
  local task_count=""

  if [[ ! "$host_pid" =~ ^[1-9][0-9]*$ || ! -r "/proc/$host_pid/status" ]]; then
    printf 'status=unavailable\n' >"$output"
    return 0
  fi
  fd_count="$(find "/proc/$host_pid/fd" -mindepth 1 -maxdepth 1 -printf '.\n' 2>/dev/null | wc -l)" || fd_count="unavailable"
  task_count="$(find "/proc/$host_pid/task" -mindepth 1 -maxdepth 1 -printf '.\n' 2>/dev/null | wc -l)" || task_count="unavailable"
  {
    printf 'status=available\n'
    printf 'host_pid=%s\n' "$host_pid"
    awk '/^(VmPeak|VmSize|VmRSS|VmData|VmStk|VmExe|VmLib|Threads):/ {print}' \
      "/proc/$host_pid/status"
    printf 'fd_count=%s\n' "$fd_count"
    printf 'task_count=%s\n' "$task_count"
    printf 'stat='
    tr '\n' ' ' <"/proc/$host_pid/stat"
    printf '\n'
  } >"$output"
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

capture_java_diagnostics() {
  local -r output="$1"
  local -r partial="$output.partial"
  local captured_bytes=""

  [[ ! -e "$output" && ! -L "$output" && ! -e "$partial" && ! -L "$partial" ]] || return 1
  if run_bounded "$DOCKER_QUERY_TIMEOUT_SECONDS" \
    curl --fail --silent --show-error --max-time 5 \
      --max-filesize "$MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES" \
      --cacert "$RUNTIME_DIR/certs/ca.crt" \
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
      capture_proc_snapshot "$host_pid" "$snapshot_directory/$service-proc.txt"
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
  capture_obi_metrics "$snapshot_directory/obi-metrics.prom"
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
  for name in tcp-candidate tcp-inject tcp-stage tcp-handoff getsockopt-take getsockopt-discard; do
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
        tcp_upstream_candidate_inject_stage_handoff_delta_zero: true,
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
  local -r cell_dir="$OUTPUT_DIR/cells/$cell"
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
    length == 1 and (.[0] | .status == "passed" and .cell == $cell)
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
  local cell=""
  local cell_json=""
  local -a cells=()

  for cell in "${CORE_CELLS[@]}"; do
    cell_json="$(variance_summary_cell "$cell")" || return 1
    cells+=("$cell_json")
  done
  printf '%s\n' "${cells[@]}" | jq -s .
}

write_variance_summary() {
  local -r output="$OUTPUT_DIR/variance.json"
  local cells_json=""
  local temporary=""

  [[ "$OUTPUT_READY" == "true" ]] || return 1
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  cells_json="$(variance_summary_cells)" || return 1
  temporary="$(mktemp "$OUTPUT_DIR/.variance.json.XXXXXX")" || return 1
  if ! jq -n \
    --arg manifest manifest.json \
    --argjson cells "$cells_json" '
      {
        schema_version: 1,
        kind: "descriptive-repetition-summary",
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
          "This descriptive artifact applies no threshold and does not establish a performance SLO."
        ]
      }
    ' >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! mv -- "$temporary" "$output"; then
    rm -f -- "$temporary"
    return 1
  fi
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
  local -r scenario_result="$result_directory/scenario-$CELL_SENTINEL_SCENARIO.json"

  validate_cell_sentinel "$scenario_result" || return $?
  if [[ "$CELL_SENTINEL_SCENARIO" == "w3c" ]]; then
    validate_w3c_runner_status "$result_directory/scenario-w3c-status.json" || return $?
    validate_runner_standard_parent_discards \
      "$result_directory/phases/w3c-after/java-diagnostics.delta"
  fi
}

start_cell_stack() {
  local -r cell_dir="$1"
  local -r project="$2"
  local runner_log="$cell_dir/preflight/runner.log"
  local result_directory=""

  ACTIVE_PROJECT="$project"
  ACTIVE_CELL_DIR="$cell_dir"
  if ! run_bounded "$RUNNER_START_TIMEOUT_SECONDS" env \
    COMPOSE_PROJECT_NAME="$project" \
    "$RUNNER" \
      --transport "$CELL_TRANSPORT" \
      --scenario "$CELL_SCENARIO" \
      --agent "$AGENT" \
      --tls "$TLS_PROTOCOL" \
      --requests "$PREFLIGHT_REQUESTS" \
      --seed "$SEED" \
      --keep >"$runner_log" 2>&1; then
    return 1
  fi
  result_directory="$(runner_result_directory "$runner_log")" || return 1
  validate_runner_result "$result_directory" || return 1
  validate_runner_environment "$result_directory" || return 1
  verify_preflight "$result_directory" || return 1
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

write_summary() {
  local status="$1"
  local cell=""
  local status_file=""
  local cells_json=""
  local variance_json=""
  local summary_temporary=""
  local manifest_temporary=""

  [[ "$OUTPUT_READY" == "true" ]] || return 0
  if [[ "$status" == "passed" ]]; then
    [[ -f "$OUTPUT_DIR/variance.json" && ! -L "$OUTPUT_DIR/variance.json" ]] || return 1
    jq -se '
      length == 1 and
      (.[0] |
        .schema_version == 1 and
        .kind == "descriptive-repetition-summary" and
        .status == "complete" and
        .acceptance_evidence == false and
        (.cells | type == "array" and length > 0))
    ' "$OUTPUT_DIR/variance.json" >/dev/null || return 1
    variance_json='{"status":"available","path":"variance.json"}'
  else
    rm -f -- "$OUTPUT_DIR/variance.json" || return 1
    rm -f -- "$OUTPUT_DIR/summary.json" || return 1
    variance_json='{"status":"not_available","path":null}'
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
  summary_temporary="$(mktemp "$OUTPUT_DIR/.summary.json.XXXXXX")" || return 1
  manifest_temporary="$(mktemp "$OUTPUT_DIR/.manifest.json.XXXXXX")" || {
    rm -f -- "$summary_temporary" || return 1
    return 1
  }
  if ! jq -n \
    --arg status "$status" \
    --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson cells "$cells_json" \
    --argjson variance "$variance_json" \
    '{
      status: $status,
      acceptance_evidence: false,
      completed_at: $completed_at,
      cells: $cells,
      variance: $variance,
      notes: [
        "The bounded preflight and post-load sentinel establish the declared correctness assertion for each cell.",
        "variance.json is descriptive repetition data, not an acceptance threshold or production SLO.",
        "Midpoint resource snapshots are unsynchronized point samples and do not prove full in-load coverage.",
        "Unavailable dimensions in manifest.json are not measured as zero."
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
  write_manifest
  capture_host_environment
  acquire_lock
  mkdir -- "$OUTPUT_DIR/cells"
  for cell in "${CORE_CELLS[@]}"; do
    run_cell "$cell"
  done
  write_variance_summary
  HARNESS_STATUS="passed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap 'on_exit "$?"' EXIT
  trap 'exit 130' INT TERM
  main "$@"
fi
