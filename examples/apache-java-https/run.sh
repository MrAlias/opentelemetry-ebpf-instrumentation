#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
MAX_SHELL_INTEGER="9223372036854775807"
MAX_UINT32_DECIMAL="4294967295"
MAX_UINT64_DECIMAL="18446744073709551615"
JAVA_DIAGNOSTIC_COUNTER_MAX="999999999"
BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS=35
SCENARIO_RUN_TIMEOUT_SECONDS=120
PRESSURE_STATE_TIMEOUT_SECONDS=10
PRESSURE_MONITOR_METRICS_TIMEOUT_SECONDS=5
PRESSURE_MONITOR_POLL_INTERVAL_SECONDS=1
PRESSURE_MONITOR_COMPLETION_SLACK_SECONDS=4
PRESSURE_MONITOR_COMPLETION_TIMEOUT_SECONDS="$((
  (PRESSURE_MONITOR_METRICS_TIMEOUT_SECONDS * 2) +
  PRESSURE_MONITOR_POLL_INTERVAL_SECONDS +
  PRESSURE_MONITOR_COMPLETION_SLACK_SECONDS
))"
# The recovery deadline covers the configured 30-second bridge TTL without delaying an earlier recovery.
PRESSURE_ENTRY_TTL_SECONDS=30
PRESSURE_RECOVERY_TIMEOUT_SECONDS="$((PRESSURE_ENTRY_TTL_SECONDS * 2))"
PRESSURE_RECOVERY_CONSECUTIVE_SAMPLES=2
PRESSURE_HELPER_TIMEOUT_SECONDS=60
PRESSURE_CLEANUP_MAX_ATTEMPTS=3
PRESSURE_CLEANUP_DEADLINE_SECONDS=180
PRESSURE_MAX_ENTRIES=50000
# Sum explicit metric, readiness, Docker, release, and final-attempt overrun bounds.
SECURITY_PROBE_SCENARIO_BUDGET_SECONDS=232
SECURITY_PROBE_SAME_CGROUP_FIXED_BUDGET_SECONDS=143
SECURITY_PROBE_SIBLING_FIXED_BUDGET_SECONDS=408
SECURITY_PROBE_TIMEOUT_SLACK_SECONDS=60
MAX_SECURITY_PROBE_TIMEOUT_SECONDS=3600
PROJECT_NAMESPACE="obi-apache-java-https"
PROJECT_SENTINEL_LABEL="io.opentelemetry.obi.apache-java-https.owner"
PROJECT_SENTINEL_VALUE="acceptance-demo-v1"
APACHE_EXPECTED_PROCESS_COUNT=9
APACHE_HTTPS_HEALTH_ENDPOINT="http://127.0.0.1:18080/healthz?close=1"
PRIMARY_SECURITY_PROBE_PATH="/tmp/security-probe"
PRIMARY_SECURITY_PID_PATH="/tmp/security-probe.pid"
UNIX_PERMISSION_REFUSAL_PATTERN="writable without the sticky bit"
RESTART_CONTROL_CONTAINER_DIR="/run/obi-demo/restart-control"
RESTART_SIGNAL_PRE_STOP_READY="pre-stop-ready"
RESTART_SIGNAL_STOPPED_TRAFFIC_COMPLETE="stopped-traffic-complete"
RESTART_SIGNAL_POST_RESTART_TRAFFIC_COMPLETE="post-restart-traffic-complete"
RESTART_RELEASE_OBI_STOPPED="obi-stopped"
RESTART_RELEASE_OBI_READY="obi-ready"
readonly SCRIPT_DIR REPO_ROOT SCRIPT_NAME MAX_SHELL_INTEGER MAX_UINT32_DECIMAL
readonly MAX_UINT64_DECIMAL JAVA_DIAGNOSTIC_COUNTER_MAX
readonly BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS SCENARIO_RUN_TIMEOUT_SECONDS
readonly PRESSURE_STATE_TIMEOUT_SECONDS PRESSURE_MONITOR_METRICS_TIMEOUT_SECONDS
readonly PRESSURE_MONITOR_POLL_INTERVAL_SECONDS PRESSURE_MONITOR_COMPLETION_SLACK_SECONDS
readonly PRESSURE_MONITOR_COMPLETION_TIMEOUT_SECONDS
readonly PRESSURE_ENTRY_TTL_SECONDS
readonly PRESSURE_RECOVERY_TIMEOUT_SECONDS PRESSURE_RECOVERY_CONSECUTIVE_SAMPLES
readonly PRESSURE_HELPER_TIMEOUT_SECONDS PRESSURE_CLEANUP_MAX_ATTEMPTS
readonly PRESSURE_CLEANUP_DEADLINE_SECONDS PRESSURE_MAX_ENTRIES
readonly SECURITY_PROBE_SCENARIO_BUDGET_SECONDS
readonly SECURITY_PROBE_SAME_CGROUP_FIXED_BUDGET_SECONDS
readonly SECURITY_PROBE_SIBLING_FIXED_BUDGET_SECONDS
readonly SECURITY_PROBE_TIMEOUT_SLACK_SECONDS
readonly MAX_SECURITY_PROBE_TIMEOUT_SECONDS PROJECT_NAMESPACE
readonly PROJECT_SENTINEL_LABEL PROJECT_SENTINEL_VALUE APACHE_EXPECTED_PROCESS_COUNT
readonly APACHE_HTTPS_HEALTH_ENDPOINT
readonly PRIMARY_SECURITY_PROBE_PATH PRIMARY_SECURITY_PID_PATH
readonly UNIX_PERMISSION_REFUSAL_PATTERN
readonly RESTART_CONTROL_CONTAINER_DIR
readonly RESTART_SIGNAL_PRE_STOP_READY RESTART_SIGNAL_STOPPED_TRAFFIC_COMPLETE
readonly RESTART_SIGNAL_POST_RESTART_TRAFFIC_COMPLETE
readonly RESTART_RELEASE_OBI_STOPPED RESTART_RELEASE_OBI_READY

RUNTIME_DIR="$SCRIPT_DIR/.runtime"
ARTIFACT_DIR="$RUNTIME_DIR/artifacts"
CERT_DIR="$RUNTIME_DIR/certs"
RESULTS_ROOT="$RUNTIME_DIR/results"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$PROJECT_NAMESPACE}"

TRANSPORT="getsockopt"
AGENT_DISTRIBUTION="otel"
TLS_PROTOCOL="TLSv1.3"
SCENARIO="all"
KEEP_RUNNING=false
SKIP_BRIDGE_BUILD=false
CLEANUP_ONLY=false
COMMAND_TIMEOUT_SECONDS=1200
READINESS_TIMEOUT_SECONDS=90
REQUEST_COUNT=0
REPEAT_COUNT=1
SCENARIO_SEED=1
TMP_DIR=""
RESULT_DIR=""
STACK_STARTED=false
SOURCE_DIRTY=""
SOURCE_PATCH_SHA256=""
SOURCE_REVISION=""
SOURCE_TRACKED_PATCH_SHA256=""
SOURCE_TREE_SHA256=""
RUN_INVOCATION=""
RUN_STAGE="initialization"
FAILURE_STAGE=""
FAILURE_LINE=""
FAILURE_STATUS=""
FAILURE_COMMAND=""
BRIDGE_BUILD_MODE="fresh"
ACCEPTANCE_EVIDENCE=true
ACCEPTANCE_EVIDENCE_REASON=""
BRIDGE_RUNNING=false
MATCHING_BRIDGE_RUNNING=false
SELECTED_TRANSPORT=""
CONTEXT_PROPAGATION="tcp"
RUN_STATUS="failed"
PRESSURE_ACTIVE=false
PRESSURE_MAP_ID=""
PRESSURE_MAP_MAX_ENTRIES=""
PRESSURE_MAP_BASELINE_ENTRIES=""
PRESSURE_EVICTED_ENTRIES=""
PRESSURE_TOUCHED_ENTRIES=""
PRESSURE_CLEANUP_ATTEMPT=0
PRESSURE_CLEANUP_DEADLINE=0
PRESSURE_SEED=""
PRESSURE_LABEL=""
PRESSURE_PROCESS_MAP_ID=""
PRESSURE_PROCESS_PID=""
PRESSURE_PROCESS_NAMESPACE=""
PRESSURE_TOKEN_BASE=""
PRESSURE_MONITOR_PID=""
PRESSURE_MONITOR_OUTPUT=""
PRESSURE_MONITOR_FINAL_OUTPUT=""
PRESSURE_MONITOR_STATUS=0
PRESSURE_INJECT_TARGET=""
FAULT_MODE="alternating"
FAULT_REQUEST_COUNT=2
MATCHING_VALID_TAKES=1
SCENARIO_VARIANT=""
SECURITY_PROBE_MODE="abuse"
SECURITY_PROBE_TIMEOUT="60s"
PRIMARY_SECURITY_SAME_CGROUP_TIMEOUT="60s"
ALLOW_PRIMARY_SECURITY_METRICS=false
ALLOW_UNIX_SECURITY_METRICS=false
PRIMARY_SECURITY_EXEC_PID=""
PRIMARY_SECURITY_HOST_PROBE=""
PRIMARY_SECURITY_JAVA_CONTAINER=""
PRIMARY_SECURITY_NAMESPACE_PID=""
PRIMARY_SECURITY_SIBLING_CONTAINER=""
UNIX_SECURITY_DIRECTORY_RELAXED=false
UNIX_SECURITY_RACE_CONTAINER=""

declare -a COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE")

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Build, run, and assert the client -> Apache -> HTTPS Jetty trace bridge demo.

Options:
  --transport MODE        getsockopt, unix, auto, or disabled.
                          Default: getsockopt
  --agent NAME            otel or splunk. Default: otel
  --tls VERSION           TLSv1.2 or TLSv1.3. Default: TLSv1.3
  --scenario NAME         all, basic, keepalive, pipelining, concurrency,
                          connection-churn, fd-port-reuse, slow-body, tls-boundary,
                          timeout-retry,
                          pressure, handoff, virtual-thread, netty, dispatch,
                          w3c, w3c-match, obi-flags, w3c-fault, w3c-only,
                          security, restart-fault, fail-open, restart, disabled, or
                          uninstrumented.
                          Default: all
  --requests COUNT        Requests per scenario (1-1000); scenario default
                          when omitted.
  --repeat COUNT          Repeat each selected scenario (1-10). Default: 1
  --seed VALUE            Deterministic identifier seed. Default: 1
  --skip-bridge-build     Reuse verified bridge artifacts for targeted local
                          iteration. Not allowed with --scenario all.
  --keep                  Leave this scoped Compose project running.
  --cleanup-only          Stop this demo's Compose project and exit.
  --command-timeout SEC   Build/Compose command deadline. Default: 1200
  --readiness-timeout SEC Per-component readiness deadline. Default: 90
  -h, --help              Show this help text.

The all scenario runs basic, keepalive, HTTP/1.1 pipelining, concurrency,
connection churn, fd/ephemeral-port reuse, slow-body, deterministic TLS receive
boundaries, timeout/retry, pressure,
executor/virtual-thread/Netty handoff, async redispatch, W3C
precedence/match/flags/fault/no-state controls, late attach, OBI restart during
traffic, bounded primary or fallback transport abuse controls, Unix endpoint
replacement when that transport is selected, bridge/extension-disabled,
extension-absent, and uninstrumented controls. Evidence is retained under:
  $RESULTS_ROOT
EOF
}

log_info() {
  printf '[%(%Y-%m-%dT%H:%M:%SZ)T] INFO: %s\n' -1 "$*" >&2
}

log_warn() {
  printf '[%(%Y-%m-%dT%H:%M:%SZ)T] WARN: %s\n' -1 "$*" >&2
}

log_error() {
  printf '[%(%Y-%m-%dT%H:%M:%SZ)T] ERROR: %s\n' -1 "$*" >&2
}

bounded_decimal() {
  local -r raw="$1"
  local -r maximum="$2"
  local -r allow_zero="$3"
  local leading_zeros=""
  local normalized=""

  [[ "$raw" =~ ^[0-9]+$ ]] || return 1
  leading_zeros="${raw%%[!0]*}"
  normalized="${raw#"$leading_zeros"}"
  if [[ -z "$normalized" ]]; then
    normalized=0
  fi
  if [[ "$allow_zero" != "true" && "$normalized" == "0" ]]; then
    return 1
  fi
  if (( ${#normalized} > ${#maximum} )); then
    return 1
  fi
  if (( ${#normalized} == ${#maximum} )); then
    # Equal-width decimal strings compare safely without arithmetic overflow.
    # shellcheck disable=SC2071
    [[ "$normalized" > "$maximum" ]] && return 1
  fi
  printf '%s\n' "$normalized"
}

parse_args() {
  local value=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --transport)
        require_value "$1" "$#"
        TRANSPORT="$2"
        shift 2
        ;;
      --agent)
        require_value "$1" "$#"
        AGENT_DISTRIBUTION="$2"
        shift 2
        ;;
      --tls)
        require_value "$1" "$#"
        TLS_PROTOCOL="$2"
        shift 2
        ;;
      --scenario)
        require_value "$1" "$#"
        SCENARIO="$2"
        shift 2
        ;;
      --skip-bridge-build)
        SKIP_BRIDGE_BUILD=true
        shift
        ;;
      --requests)
        require_value "$1" "$#"
        value="$(bounded_decimal "$2" 1000 false)" || {
          die "$1 must be an integer between 1 and 1000"
        }
        REQUEST_COUNT="$value"
        shift 2
        ;;
      --repeat)
        require_value "$1" "$#"
        value="$(bounded_decimal "$2" 10 false)" || {
          die "$1 must be an integer between 1 and 10"
        }
        REPEAT_COUNT="$value"
        shift 2
        ;;
      --seed)
        require_value "$1" "$#"
        value="$(bounded_decimal "$2" "$MAX_SHELL_INTEGER" true)" || {
          die "$1 must be a non-negative signed 64-bit integer"
        }
        SCENARIO_SEED="$value"
        shift 2
        ;;
      --keep)
        KEEP_RUNNING=true
        shift
        ;;
      --cleanup-only)
        CLEANUP_ONLY=true
        shift
        ;;
      --command-timeout)
        require_value "$1" "$#"
        value="$(bounded_decimal "$2" "$MAX_SHELL_INTEGER" false)" || {
          die "$1 must be a positive signed 64-bit integer"
        }
        COMMAND_TIMEOUT_SECONDS="$value"
        shift 2
        ;;
      --readiness-timeout)
        require_value "$1" "$#"
        value="$(bounded_decimal "$2" "$MAX_SHELL_INTEGER" false)" || {
          die "$1 must be a positive signed 64-bit integer"
        }
        READINESS_TIMEOUT_SECONDS="$value"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        [[ $# -eq 0 ]] || die "unexpected positional arguments: $*"
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  case "$TRANSPORT" in
    getsockopt|unix|auto|disabled)
      ;;
    *)
      die "transport must be getsockopt, unix, auto, or disabled"
      ;;
  esac
  case "$AGENT_DISTRIBUTION" in
    otel|splunk)
      ;;
    *)
      die "agent must be otel or splunk"
      ;;
  esac
  case "$TLS_PROTOCOL" in
    TLSv1.2|TLSv1.3)
      ;;
    *)
      die "tls must be TLSv1.2 or TLSv1.3"
      ;;
  esac
  case "$SCENARIO" in
    all|basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|slow-body|tls-boundary|timeout-retry|pressure|handoff|virtual-thread|netty|dispatch|w3c|w3c-match|obi-flags|w3c-fault|w3c-only|security|restart-fault|fail-open|restart|disabled|uninstrumented)
      ;;
    *)
      die "unsupported scenario: $SCENARIO"
      ;;
  esac
  (( ${#PROJECT_NAME} <= 63 )) || die "COMPOSE_PROJECT_NAME must not exceed 63 characters"
  [[ "$PROJECT_NAME" == "$PROJECT_NAMESPACE" || \
    "$PROJECT_NAME" =~ ^${PROJECT_NAMESPACE}-[a-z0-9]([a-z0-9_-]*[a-z0-9])?$ ]] || {
    die "COMPOSE_PROJECT_NAME must be $PROJECT_NAMESPACE or use its reserved lowercase suffix namespace"
  }
  if [[ "$SCENARIO" == "disabled" && "$TRANSPORT" != "disabled" ]]; then
    die "the disabled scenario requires --transport disabled"
  fi
  if [[ "$SCENARIO" == "uninstrumented" && "$TRANSPORT" != "disabled" ]]; then
    die "the uninstrumented scenario requires --transport disabled"
  fi
  if [[ "$TRANSPORT" == "disabled" && "$SCENARIO" != "disabled" && "$SCENARIO" != "uninstrumented" ]]; then
    die "--transport disabled may only run --scenario disabled or uninstrumented"
  fi
  if [[ "$SCENARIO" == "all" && "$TRANSPORT" == "disabled" ]]; then
    die "the all scenario requires getsockopt, unix, or auto transport"
  fi
  if [[ "$SCENARIO" == "all" && "$SKIP_BRIDGE_BUILD" == "true" ]]; then
    die "--skip-bridge-build is not valid for the acceptance suite"
  fi
  if [[ "$SCENARIO" == "all" && "$REQUEST_COUNT" != "0" ]]; then
    mark_non_acceptance "custom-request-count"
  fi
  if [[ "$SCENARIO" == "w3c-fault" && "$TRANSPORT" != "unix" ]]; then
    die "the w3c-fault scenario requires --transport unix"
  fi
  if [[ "$SCENARIO" == "w3c-fault" && "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "2" ]]; then
    die "the w3c-fault scenario requires exactly two requests"
  fi
  if [[ ( "$SCENARIO" == "keepalive" || "$SCENARIO" == "pipelining" ) &&
    "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" -lt 3 ]]; then
    die "the $SCENARIO scenario requires at least three requests"
  fi
  if [[ "$SCENARIO" == "fd-port-reuse" && "$REQUEST_COUNT" == "1" ]]; then
    die "the fd-port-reuse scenario requires at least two requests"
  fi
  if [[ "$SCENARIO" == "tls-boundary" && "$REQUEST_COUNT" != "0" && \
    "$REQUEST_COUNT" != "2" ]]; then
    die "the tls-boundary scenario requires exactly two requests"
  fi
  if [[ "$SCENARIO" != "all" && "$CLEANUP_ONLY" == "false" ]]; then
    mark_non_acceptance "targeted-scenario"
  fi
}

require_value() {
  local -r option="$1"
  local -r count="$2"
  ((count >= 2)) || die "missing value for $option"
}

die() {
  local -r line="${BASH_LINENO[0]:-0}"

  record_failure "$RUN_STAGE" "$line" 2 "die: $*"
  log_error "$*" || true
  exit 2
}

mark_non_acceptance() {
  local -r reason="$1"

  ACCEPTANCE_EVIDENCE=false
  if [[ -z "$ACCEPTANCE_EVIDENCE_REASON" ]]; then
    ACCEPTANCE_EVIDENCE_REASON="$reason"
  else
    ACCEPTANCE_EVIDENCE_REASON+=",$reason"
  fi
}

check_dependencies() {
  local -a missing=()
  local command_name=""
  for command_name in awk cmp curl cut docker find git grep install mv openssl sed sha256sum sort tail tee timeout wc; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    die "missing required commands: ${missing[*]}"
  fi
  run_bounded 15 docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
}

run_bounded() {
  local -r seconds="$1"
  shift
  timeout --signal=TERM --kill-after=10s "${seconds}s" "$@" </dev/null
}

record_failure() {
  local -r stage="$1"
  local -r line="$2"
  local -r status="$3"
  local -r command="$4"

  if [[ -n "$FAILURE_STAGE" ]]; then
    return 0
  fi

  FAILURE_STAGE="$stage"
  FAILURE_LINE="$line"
  FAILURE_STATUS="$status"
  FAILURE_COMMAND="$command"

  if [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
    {
      printf 'stage=%q\n' "$FAILURE_STAGE"
      printf 'line=%q\n' "$FAILURE_LINE"
      printf 'exit_status=%q\n' "$FAILURE_STATUS"
      printf 'command=%q\n' "$FAILURE_COMMAND"
    } >"$RESULT_DIR/failure-context.txt" || true
  fi
}

run_logged_bounded() {
  local -r output="$1"
  local -r seconds="$2"
  local -r caller_line="${BASH_LINENO[0]:-0}"
  local command_status=0
  local capture_status=0
  local write_status=0
  local rendered_command=""
  local -a statuses=()
  shift 2

  printf -v rendered_command '%q ' "$@"
  rendered_command="${rendered_command% }"
  printf 'command=%s\n' "$rendered_command" >"$output" || write_status=$?
  if ((write_status != 0)); then
    record_failure "$RUN_STAGE" "$caller_line" "$write_status" "write $output"
    return "$write_status"
  fi

  if run_bounded "$seconds" "$@" 2>&1 | tee -a "$output"; then
    statuses=("${PIPESTATUS[@]}")
  else
    statuses=("${PIPESTATUS[@]}")
  fi
  command_status="${statuses[0]}"
  capture_status="${statuses[1]}"
  printf 'exit_status=%d\ncapture_exit_status=%d\n' \
    "$command_status" "$capture_status" >>"$output" || write_status=$?
  if ((command_status != 0)); then
    record_failure "$RUN_STAGE" "$caller_line" "$command_status" "$rendered_command"
    return "$command_status"
  fi
  if ((capture_status != 0)); then
    record_failure "$RUN_STAGE" "$caller_line" "$capture_status" "tee -a $output"
    return "$capture_status"
  fi
  if ((write_status != 0)); then
    record_failure "$RUN_STAGE" "$caller_line" "$write_status" "append $output"
    return "$write_status"
  fi
}

capture_optional_command() {
  local -r output="$1"
  local -r seconds="$2"
  local status=0
  shift 2

  {
    printf 'command='
    printf ' %q' "$@"
    printf '\n'
    if run_bounded "$seconds" "$@"; then
      status=0
    else
      status=$?
    fi
    printf 'exit_status=%d\n' "$status"
  } >"$output" 2>&1
}

compose_resource_ids() {
  local -r resource_kind="$1"
  local -a all_arguments=()

  if [[ "$resource_kind" == "container" ]]; then
    all_arguments=(--all)
  fi

  run_bounded 15 \
    docker "$resource_kind" ls "${all_arguments[@]}" --quiet \
      --filter "label=com.docker.compose.project=$PROJECT_NAME"
}

compose_resource_sentinel() {
  local -r resource_kind="$1"
  local -r resource_id="$2"
  local format=""

  if [[ "$resource_kind" == "container" ]]; then
    format="{{ index .Config.Labels \"$PROJECT_SENTINEL_LABEL\" }}"
  else
    format="{{ index .Labels \"$PROJECT_SENTINEL_LABEL\" }}"
  fi
  run_bounded 15 docker "$resource_kind" inspect --format "$format" "$resource_id"
}

verify_compose_project_ownership() {
  local resource_kind=""
  local resource_id=""
  local resources_output=""
  local sentinel=""
  local -a resource_ids=()

  for resource_kind in container volume network; do
    resources_output="$(compose_resource_ids "$resource_kind")" || {
      log_error "could not enumerate $resource_kind resources for Compose project $PROJECT_NAME"
      return 1
    }
    resource_ids=()
    if [[ -n "$resources_output" ]]; then
      mapfile -t resource_ids <<<"$resources_output"
    fi
    for resource_id in "${resource_ids[@]}"; do
      [[ -n "$resource_id" ]] || continue
      sentinel="$(compose_resource_sentinel "$resource_kind" "$resource_id")" || {
        log_error "could not inspect $resource_kind $resource_id in Compose project $PROJECT_NAME"
        return 1
      }
      if [[ "$sentinel" != "$PROJECT_SENTINEL_VALUE" ]]; then
        log_error "$resource_kind $resource_id uses reserved Compose project $PROJECT_NAME without the demo ownership sentinel"
        return 1
      fi
    done
  done
}

verify_compose_project_absent() {
  local resource_kind=""
  local resources_output=""

  for resource_kind in container volume network; do
    resources_output="$(compose_resource_ids "$resource_kind")" || {
      log_error "could not enumerate $resource_kind resources after cleaning Compose project $PROJECT_NAME"
      return 1
    }
    if [[ -n "$resources_output" ]]; then
      log_error "Compose project $PROJECT_NAME retained $resource_kind resources after cleanup"
      return 1
    fi
  done
}

safe_compose_down() {
  verify_compose_project_ownership || {
    log_error "refusing destructive cleanup for unverified Compose project $PROJECT_NAME"
    return 1
  }
  run_bounded 60 \
    "${COMPOSE[@]}" --profile '*' \
    down --volumes --remove-orphans --timeout 10 || return
  verify_compose_project_absent
}

on_error() {
  local -r line="$1"
  local -r status="$2"
  local -r command="$3"

  record_failure "$RUN_STAGE" "$line" "$status" "$command"
  log_error "command failed at line $line during $RUN_STAGE" || true
}

cleanup_security_processes() {
  if [[ -n "$PRIMARY_SECURITY_JAVA_CONTAINER" && \
    "$PRIMARY_SECURITY_NAMESPACE_PID" =~ ^[1-9][0-9]*$ ]]; then
    # Expanded by the container shell, not this process.
    # shellcheck disable=SC2016
    run_bounded 10 docker exec "$PRIMARY_SECURITY_JAVA_CONTAINER" \
      /bin/sh -ec '
        if read -r name <"/proc/$1/comm" && [ "$name" = security-probe ]; then
          kill -TERM "$1" 2>/dev/null || true
        fi
      ' sh \
      "$PRIMARY_SECURITY_NAMESPACE_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$PRIMARY_SECURITY_EXEC_PID" =~ ^[1-9][0-9]*$ ]]; then
    if kill -0 "$PRIMARY_SECURITY_EXEC_PID" 2>/dev/null; then
      kill -TERM "$PRIMARY_SECURITY_EXEC_PID" 2>/dev/null || true
    fi
    wait "$PRIMARY_SECURITY_EXEC_PID" 2>/dev/null || true
  fi
  if [[ -n "$PRIMARY_SECURITY_SIBLING_CONTAINER" ]]; then
    run_bounded 10 docker kill "$PRIMARY_SECURITY_SIBLING_CONTAINER" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$PRIMARY_SECURITY_JAVA_CONTAINER" ]]; then
    run_bounded 10 docker exec "$PRIMARY_SECURITY_JAVA_CONTAINER" \
      rm -f -- "$PRIMARY_SECURITY_PROBE_PATH" "$PRIMARY_SECURITY_PID_PATH" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$PRIMARY_SECURITY_HOST_PROBE" ]]; then
    rm -f -- "$PRIMARY_SECURITY_HOST_PROBE" || true
  fi
  if [[ -n "$UNIX_SECURITY_RACE_CONTAINER" ]]; then
    run_bounded 10 docker kill "$UNIX_SECURITY_RACE_CONTAINER" \
      >/dev/null 2>&1 || true
  fi
  if [[ "$UNIX_SECURITY_DIRECTORY_RELAXED" == "true" ]]; then
    run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
      chmod 0750 /var/run/obi >/dev/null 2>&1 || true
  fi

  PRIMARY_SECURITY_EXEC_PID=""
  PRIMARY_SECURITY_HOST_PROBE=""
  PRIMARY_SECURITY_JAVA_CONTAINER=""
  PRIMARY_SECURITY_NAMESPACE_PID=""
  PRIMARY_SECURITY_SIBLING_CONTAINER=""
  UNIX_SECURITY_DIRECTORY_RELAXED=false
  UNIX_SECURITY_RACE_CONTAINER=""
}

cleanup() {
  local -r status="$?"
  local final_status="$status"
  local cleanup_status=0
  trap - ERR EXIT INT TERM
  set +e

  if ((status != 0)) && [[ -z "$FAILURE_STAGE" ]]; then
    record_failure "$RUN_STAGE" 0 "$status" "exit"
  fi

  if [[ "$PRESSURE_ACTIVE" == "true" ]]; then
    cleanup_map_pressure_with_retries || true
  fi
  cleanup_security_processes
  if [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
    capture_evidence
  fi
  if [[ "$MATCHING_BRIDGE_RUNNING" == "true" ]]; then
    log_warn "stopping the transient controlled matching bridge"
    if run_bounded 30 "${COMPOSE[@]}" stop --timeout 5 bridge-fault; then
      MATCHING_BRIDGE_RUNNING=false
    else
      log_error "could not stop the transient controlled matching bridge"
    fi
    reset_matching_bridge_environment
  fi
  if [[ "$STACK_STARTED" == "true" && "$KEEP_RUNNING" == "false" ]]; then
    log_info "stopping scoped Compose project $PROJECT_NAME"
    if safe_compose_down >/dev/null 2>&1; then
      :
    else
      cleanup_status=$?
      log_error "Compose project cleanup was refused or failed"
      if ((final_status == 0)); then
        final_status="$cleanup_status"
        record_failure "compose-cleanup" 0 "$cleanup_status" "safe_compose_down"
      fi
    fi
  elif [[ "$STACK_STARTED" == "true" ]]; then
    log_warn "leaving Compose project $PROJECT_NAME running by request"
  fi
  if [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
    write_run_status "$final_status"
    log_info "retained run evidence: $RESULT_DIR"
  fi
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi

  exit "$final_status"
}

install_traps() {
  trap 'on_error "$LINENO" "$?" "$BASH_COMMAND"' ERR
  trap cleanup EXIT
  trap 'exit 130' INT TERM
}

prepare_directories() {
  local run_id=""

  prepare_runtime_directory "$RUNTIME_DIR"
  prepare_runtime_directory "$ARTIFACT_DIR"
  prepare_runtime_directory "$CERT_DIR"
  prepare_runtime_directory "$RESULTS_ROOT"
  run_id="$(date -u +'%Y%m%dT%H%M%SZ')-$$"
  RESULT_DIR="$RESULTS_ROOT/$run_id"
  mkdir -- "$RESULT_DIR"
}

prepare_runtime_directory() {
  local -r directory="$1"

  [[ ! -L "$directory" ]] || die "refusing symlink runtime directory: $directory"
  if [[ -e "$directory" && ! -d "$directory" ]]; then
    die "refusing non-directory runtime target: $directory"
  fi
  mkdir -p -- "$directory"
  [[ -d "$directory" && ! -L "$directory" ]] || {
    die "runtime directory changed while preparing it: $directory"
  }
}

capture_source_state() {
  local executable=""
  local object_id=""
  local path=""

  SOURCE_REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all >"$RESULT_DIR/git-status.txt"
  SOURCE_TRACKED_PATCH_SHA256="$(git -C "$REPO_ROOT" diff --binary --no-ext-diff HEAD | sha256sum)"
  SOURCE_TRACKED_PATCH_SHA256="${SOURCE_TRACKED_PATCH_SHA256%% *}"

  (
    cd -- "$REPO_ROOT"
    while IFS= read -r -d '' path; do
      if [[ ! -f "$path" && ! -L "$path" ]]; then
        continue
      fi
      object_id="$(git hash-object -- "$path")"
      executable="-"
      if [[ -x "$path" ]]; then
        executable="x"
      fi
      printf '%s %s %q\n' "$object_id" "$executable" "$path"
    done < <(git ls-files --cached --others --exclude-standard -z | sort -z)
  ) >"$RESULT_DIR/source-tree.manifest"

  SOURCE_TREE_SHA256="$(sha256sum "$RESULT_DIR/source-tree.manifest")"
  SOURCE_TREE_SHA256="${SOURCE_TREE_SHA256%% *}"
  SOURCE_PATCH_SHA256="$({
    sha256sum "$RESULT_DIR/git-status.txt"
    sha256sum "$RESULT_DIR/source-tree.manifest"
    printf '%s\n' "$SOURCE_TRACKED_PATCH_SHA256"
  } | sha256sum)"
  SOURCE_PATCH_SHA256="${SOURCE_PATCH_SHA256%% *}"
  SOURCE_DIRTY=false
  if [[ -s "$RESULT_DIR/git-status.txt" ]]; then
    SOURCE_DIRTY=true
    mark_non_acceptance "dirty-source-tree"
  fi

  {
    printf 'revision=%s\n' "$SOURCE_REVISION"
    printf 'dirty=%s\n' "$SOURCE_DIRTY"
    printf 'source_tree_sha256=%s\n' "$SOURCE_TREE_SHA256"
    printf 'tracked_patch_sha256=%s\n' "$SOURCE_TRACKED_PATCH_SHA256"
    printf 'patch_identity_sha256=%s\n' "$SOURCE_PATCH_SHA256"
  } >"$RESULT_DIR/source-state.txt"
}

prepare_certificates() {
  log_info "preparing runtime test CA"
  "$SCRIPT_DIR/certs/generate.sh" --output "$CERT_DIR"
}

prepare_official_agent() {
  log_info "preparing official $AGENT_DISTRIBUTION Java agent"
  "$SCRIPT_DIR/scripts/download-agent.sh" \
    --distribution "$AGENT_DISTRIBUTION" \
    --output "$ARTIFACT_DIR"
}

bridge_artifacts_are_valid() {
  local actual_extension_sha=""
  local actual_helper_sha=""
  local digest=""
  local extra=""
  local filename=""
  local stored_revision=""
  local stored_tree_sha=""
  local -a artifact_lines=()
  local -a expected_metadata_files=(
    bridge-artifacts.json
    bridge-artifacts.sha256
    bridge-source-revision.txt
    bridge-source-tree.sha256
  )
  local -a metadata_lines=()
  local -i index=0

  [[ -f "$ARTIFACT_DIR/obi-java-agent.jar" && ! -L "$ARTIFACT_DIR/obi-java-agent.jar" ]] || return 1
  [[ -s "$ARTIFACT_DIR/obi-java-agent.jar" ]] || return 1
  [[ -f "$ARTIFACT_DIR/obi-otel-extension.jar" && ! -L "$ARTIFACT_DIR/obi-otel-extension.jar" ]] || return 1
  [[ -s "$ARTIFACT_DIR/obi-otel-extension.jar" ]] || return 1
  [[ -f "$ARTIFACT_DIR/bridge-artifacts.sha256" && ! -L "$ARTIFACT_DIR/bridge-artifacts.sha256" ]] || return 1
  [[ -f "$ARTIFACT_DIR/bridge-metadata.sha256" && ! -L "$ARTIFACT_DIR/bridge-metadata.sha256" ]] || return 1
  [[ -f "$ARTIFACT_DIR/bridge-source-revision.txt" && ! -L "$ARTIFACT_DIR/bridge-source-revision.txt" ]] || return 1
  [[ -f "$ARTIFACT_DIR/bridge-source-tree.sha256" && ! -L "$ARTIFACT_DIR/bridge-source-tree.sha256" ]] || return 1
  [[ -f "$ARTIFACT_DIR/bridge-artifacts.json" && ! -L "$ARTIFACT_DIR/bridge-artifacts.json" ]] || return 1

  mapfile -t artifact_lines <"$ARTIFACT_DIR/bridge-artifacts.sha256"
  [[ ${#artifact_lines[@]} -eq 2 ]] || return 1
  read -r digest filename extra <<<"${artifact_lines[0]}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ && "$filename" == "obi-java-agent.jar" && -z "$extra" ]] || return 1
  actual_helper_sha="$digest"
  read -r digest filename extra <<<"${artifact_lines[1]}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ && "$filename" == "obi-otel-extension.jar" && -z "$extra" ]] || return 1
  actual_extension_sha="$digest"
  [[ "$(sha256sum "$ARTIFACT_DIR/obi-java-agent.jar")" == "$actual_helper_sha  $ARTIFACT_DIR/obi-java-agent.jar" ]] || return 1
  [[ "$(sha256sum "$ARTIFACT_DIR/obi-otel-extension.jar")" == "$actual_extension_sha  $ARTIFACT_DIR/obi-otel-extension.jar" ]] || return 1

  mapfile -t metadata_lines <"$ARTIFACT_DIR/bridge-metadata.sha256"
  [[ ${#metadata_lines[@]} -eq 4 ]] || return 1
  for index in "${!expected_metadata_files[@]}"; do
    read -r digest filename extra <<<"${metadata_lines[$index]}"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$filename" == "${expected_metadata_files[$index]}" && -z "$extra" ]] || return 1
  done
  (
    cd -- "$ARTIFACT_DIR"
    sha256sum --check --strict --status bridge-metadata.sha256
  ) || return 1

  IFS= read -r stored_revision <"$ARTIFACT_DIR/bridge-source-revision.txt"
  IFS= read -r stored_tree_sha <"$ARTIFACT_DIR/bridge-source-tree.sha256"
  [[ "$stored_revision" == "$SOURCE_REVISION" ]] || return 1
  [[ "$stored_tree_sha" == "$SOURCE_TREE_SHA256" ]]
}

write_bridge_metadata() {
  local helper_sha=""
  local extension_sha=""
  local metadata_dir=""
  local filename=""
  local -a metadata_files=(
    bridge-artifacts.json
    bridge-artifacts.sha256
    bridge-source-revision.txt
    bridge-source-tree.sha256
    bridge-metadata.sha256
  )

  helper_sha="$(sha256sum "$ARTIFACT_DIR/obi-java-agent.jar")"
  helper_sha="${helper_sha%% *}"
  extension_sha="$(sha256sum "$ARTIFACT_DIR/obi-otel-extension.jar")"
  extension_sha="${extension_sha%% *}"
  metadata_dir="$(mktemp -d "$ARTIFACT_DIR/.bridge-metadata.XXXXXX")"
  printf '%s  obi-java-agent.jar\n%s  obi-otel-extension.jar\n' \
    "$helper_sha" "$extension_sha" >"$metadata_dir/bridge-artifacts.sha256"
  printf '%s\n' "$SOURCE_REVISION" >"$metadata_dir/bridge-source-revision.txt"
  printf '%s\n' "$SOURCE_TREE_SHA256" >"$metadata_dir/bridge-source-tree.sha256"
  printf '{\n  "obi_java_agent_sha256": "%s",\n  "obi_otel_extension_sha256": "%s",\n  "source_revision": "%s",\n  "source_tree_sha256": "%s"\n}\n' \
    "$helper_sha" \
    "$extension_sha" \
    "$SOURCE_REVISION" \
    "$SOURCE_TREE_SHA256" >"$metadata_dir/bridge-artifacts.json"
  (
    cd -- "$metadata_dir"
    sha256sum \
      bridge-artifacts.json \
      bridge-artifacts.sha256 \
      bridge-source-revision.txt \
      bridge-source-tree.sha256 >bridge-metadata.sha256
  )
  for filename in "${metadata_files[@]}"; do
    install -m 0644 "$metadata_dir/$filename" "$metadata_dir/$filename.ready"
    mv -fT -- "$metadata_dir/$filename.ready" "$ARTIFACT_DIR/$filename"
  done
  rm -rf -- "$metadata_dir"
}

prepare_bridge_artifacts() {
  local export_dir=""

  if [[ "$SKIP_BRIDGE_BUILD" == "true" ]]; then
    bridge_artifacts_are_valid || {
      die "--skip-bridge-build requires checksum-verified bridge artifacts built from the current source tree"
    }
    BRIDGE_BUILD_MODE="reused-local-cache"
    mark_non_acceptance "reused-bridge-artifacts"
    log_info "reusing checksum-verified bridge artifacts for source tree $SOURCE_TREE_SHA256"
    return 0
  fi

  TMP_DIR="$(mktemp -d "$RUNTIME_DIR/.bridge-export.XXXXXX")"
  export_dir="$TMP_DIR/export"
  mkdir -p -- "$export_dir"
  log_info "building OBI Java helper and external extension"
  RUN_STAGE="bridge-build"
  run_logged_bounded "$RESULT_DIR/bridge-build.log" "$COMMAND_TIMEOUT_SECONDS" \
    docker build \
      --file "$REPO_ROOT/javaagent.Dockerfile" \
      --target export \
      --output "type=local,dest=$export_dir" \
      "$REPO_ROOT" || return

  [[ -s "$export_dir/obi-java-agent.jar" ]] || die "Java build did not export obi-java-agent.jar"
  [[ -s "$export_dir/obi-otel-extension.jar" ]] || die "Java build did not export obi-otel-extension.jar"
  install -m 0644 "$export_dir/obi-java-agent.jar" "$TMP_DIR/obi-java-agent.jar.ready"
  install -m 0644 "$export_dir/obi-otel-extension.jar" "$TMP_DIR/obi-otel-extension.jar.ready"
  mv -fT -- "$TMP_DIR/obi-java-agent.jar.ready" "$ARTIFACT_DIR/obi-java-agent.jar"
  mv -fT -- "$TMP_DIR/obi-otel-extension.jar.ready" "$ARTIFACT_DIR/obi-otel-extension.jar"
  write_bridge_metadata

  rm -rf -- "$TMP_DIR"
  TMP_DIR=""
}

configure_security_probe_timeouts() {
  local -i repeat_seconds=$((
    REPEAT_COUNT * SECURITY_PROBE_SCENARIO_BUDGET_SECONDS
  ))
  local -i maximum_readiness=$((
    (MAX_SECURITY_PROBE_TIMEOUT_SECONDS - repeat_seconds -
      SECURITY_PROBE_SAME_CGROUP_FIXED_BUDGET_SECONDS -
      SECURITY_PROBE_SIBLING_FIXED_BUDGET_SECONDS -
      SECURITY_PROBE_TIMEOUT_SLACK_SECONDS) / 3
  ))

  ((READINESS_TIMEOUT_SECONDS <= maximum_readiness)) || {
    die "readiness timeout exceeds the security probe safety bound"
  }
  local -i same_cgroup_seconds=$((
    (2 * READINESS_TIMEOUT_SECONDS) +
      SECURITY_PROBE_SAME_CGROUP_FIXED_BUDGET_SECONDS +
      repeat_seconds +
      SECURITY_PROBE_TIMEOUT_SLACK_SECONDS
  ))
  local -i sibling_seconds=$((
    same_cgroup_seconds + READINESS_TIMEOUT_SECONDS +
      SECURITY_PROBE_SIBLING_FIXED_BUDGET_SECONDS
  ))

  ((sibling_seconds <= MAX_SECURITY_PROBE_TIMEOUT_SECONDS)) || {
    die "security probe timeout exceeds the hard safety bound"
  }
  PRIMARY_SECURITY_SAME_CGROUP_TIMEOUT="${same_cgroup_seconds}s"
  SECURITY_PROBE_TIMEOUT="${sibling_seconds}s"
  export SECURITY_PROBE_TIMEOUT
}

export_compose_environment() {
  SECURITY_PROBE_TIMEOUT="60s"
  PRIMARY_SECURITY_SAME_CGROUP_TIMEOUT="60s"
  if [[ "$SCENARIO" == "all" || "$SCENARIO" == "security" ]]; then
    configure_security_probe_timeouts
  else
    export SECURITY_PROBE_TIMEOUT
  fi
  export BRIDGE_TRANSPORT="$TRANSPORT"
  export BACKEND_TLS_PROTOCOL="$TLS_PROTOCOL"
  CONTEXT_PROPAGATION="tcp"
  export CONTEXT_PROPAGATION
  if [[ "$SCENARIO" == "uninstrumented" ]]; then
    export EXTENSION_ENABLED=false
    export JAVA_TOOL_OPTIONS_VALUE=""
    export OTEL_JAVAAGENT_EXTENSIONS_VALUE=""
    export OTEL_PROPAGATORS_VALUE="tracecontext,baggage"
  else
    export EXTENSION_ENABLED=true
    export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
    export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
    export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  fi
}

start_stack() {
  local start_status=0

  RUN_STAGE="compose-ownership"
  verify_compose_project_ownership || {
    die "reserved Compose project ownership could not be verified"
  }
  log_info "validating resolved Compose configuration"
  RUN_STAGE="compose-configuration"
  run_bounded 30 "${COMPOSE[@]}" config --quiet
  run_bounded 30 "${COMPOSE[@]}" config >"$RESULT_DIR/compose-resolved.yaml"

  log_info "building and starting the demo stack"
  RUN_STAGE="compose-build-start"
  STACK_STARTED=true
  if [[ "$SCENARIO" == "uninstrumented" ]]; then
    run_logged_bounded "$RESULT_DIR/compose-up.log" "$COMMAND_TIMEOUT_SECONDS" \
      "${COMPOSE[@]}" up --build --detach \
        trace-receiver java-backend apache-proxy || start_status=$?
  else
    run_logged_bounded "$RESULT_DIR/compose-up.log" "$COMMAND_TIMEOUT_SECONDS" \
      "${COMPOSE[@]}" up --build --detach \
        trace-receiver java-backend apache-proxy obi || start_status=$?
  fi
  if ((start_status != 0)); then
    return "$start_status"
  fi
  if [[ "$SCENARIO" != "uninstrumented" && "$TRANSPORT" != "disabled" ]]; then
    BRIDGE_RUNNING=true
  fi

  RUN_STAGE="readiness"
  wait_for_http "http://127.0.0.1:14318/healthz" "trace receiver"
  if [[ "$TRANSPORT" != "disabled" ]]; then
    wait_for_log obi "Java remote parent bridge ready" "OBI remote-parent bridge"
    wait_for_log java-backend "OBI remote-parent provider ready" "injected Java helper"
    wait_for_log java-backend "OBI remote-parent propagator enabled" "external OTel extension"
    assert_selected_transport
  elif [[ "$SCENARIO" != "uninstrumented" ]]; then
    wait_for_log java-backend "OBI remote-parent propagator enabled" "external OTel extension"
  fi
  if [[ "$SCENARIO" != "uninstrumented" ]]; then
    wait_for_log java-backend "OBI Java instrumentation ready" "injected Java instrumentation"
    wait_for_apache_instrumentation startup
  fi
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "verified Apache-to-Jetty HTTPS path"
  assert_runtime_contract
}

remaining_timeout_seconds() {
  local -r deadline="$1"
  local -r maximum="$2"
  local -i remaining=0

  [[ "$deadline" =~ ^[1-9][0-9]*$ && "$maximum" =~ ^[1-9][0-9]*$ ]] || return 1
  ((remaining = deadline - SECONDS, remaining > 0)) || return 1
  if ((remaining > maximum)); then
    remaining="$maximum"
  fi
  printf '%d\n' "$remaining"
}

apache_process_count() {
  local -r deadline="$1"
  local container_id=""
  local command_timeout=""

  command_timeout="$(remaining_timeout_seconds "$deadline" 10)" || return 1
  container_id="$(run_bounded "$command_timeout" \
    "${COMPOSE[@]}" ps --quiet apache-proxy 2>/dev/null)" || return 1
  [[ "$container_id" =~ ^[0-9a-f]+$ ]] || return 1
  command_timeout="$(remaining_timeout_seconds "$deadline" 10)" || return 1
  run_bounded "$command_timeout" \
    docker top "$container_id" -eo pid,comm 2>/dev/null | awk '
    $2 == "httpd" { count++ }
    END { print count + 0 }
  '
}

instrumented_apache_process_count() {
  local -r metrics="$1"

  awk '
    $1 ~ /^obi_instrumented_processes\{/ &&
    $1 ~ /[{,]process_name="httpd"[,}]/ {
      matches++
      if ($2 !~ /^[0-9]+$/) {
        invalid = 1
      } else {
        value = $2
      }
    }
    END {
      if (matches != 1 || invalid) {
        exit 1
      }
      print value + 0
    }
  ' "$metrics"
}

wait_for_apache_instrumentation() {
  local -r label="$1"
  local metrics=""
  local metrics_timeout=""
  local process_count=0
  local instrumented_count=0
  local -i consecutive_matches=0
  local -i deadline=0

  [[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
    log_error "refusing invalid Apache readiness label: $label"
    return 1
  }
  metrics="$(mktemp "$RESULT_DIR/.apache-readiness.XXXXXX")"
  deadline="$((SECONDS + READINESS_TIMEOUT_SECONDS))"
  while ((SECONDS < deadline)); do
    process_count=0
    if process_count="$(apache_process_count "$deadline" 2>/dev/null)"; then
      :
    else
      process_count=0
    fi
    instrumented_count=0
    metrics_timeout="$(remaining_timeout_seconds "$deadline" 5)" || break
    if fetch_obi_metrics "$metrics" "$metrics_timeout" 2>/dev/null &&
      instrumented_count="$(instrumented_apache_process_count "$metrics")"; then
      :
    else
      instrumented_count=0
    fi
    if ((SECONDS < deadline)) &&
      [[ "$process_count" == "$APACHE_EXPECTED_PROCESS_COUNT" &&
      "$instrumented_count" == "$APACHE_EXPECTED_PROCESS_COUNT" ]]; then
      ((consecutive_matches += 1))
      if ((consecutive_matches == 2)); then
        install -m 0644 "$metrics" "$RESULT_DIR/apache-instrumentation-$label.prom"
        {
          printf 'expected_processes=%d\n' "$APACHE_EXPECTED_PROCESS_COUNT"
          printf 'observed_processes=%s\n' "$process_count"
          printf 'instrumented_processes=%s\n' "$instrumented_count"
        } >"$RESULT_DIR/apache-instrumentation-$label.txt"
        rm -f -- "$metrics"
        log_info "all $APACHE_EXPECTED_PROCESS_COUNT Apache processes are instrumented"
        return 0
      fi
    else
      consecutive_matches=0
    fi
    if ((SECONDS < deadline)); then
      sleep 1
    fi
  done
  rm -f -- "$metrics"
  log_error "Apache instrumentation readiness expected $APACHE_EXPECTED_PROCESS_COUNT processes, got processes=${process_count:-unavailable} instrumented=${instrumented_count:-unavailable}"
  return 1
}

wait_for_apache_instrumentation_drain() {
  local -r label="$1"
  local metrics=""
  local metrics_timeout=""
  local instrumented_count=""
  local -i consecutive_matches=0
  local -i deadline=0

  [[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
    log_error "refusing invalid Apache drain label: $label"
    return 1
  }
  metrics="$(mktemp "$RESULT_DIR/.apache-drain.XXXXXX")"
  deadline="$((SECONDS + READINESS_TIMEOUT_SECONDS))"
  while ((SECONDS < deadline)); do
    metrics_timeout="$(remaining_timeout_seconds "$deadline" 5)" || break
    instrumented_count=""
    if fetch_obi_metrics "$metrics" "$metrics_timeout" 2>/dev/null &&
      instrumented_count="$(instrumented_apache_process_count "$metrics")" &&
      ((SECONDS < deadline)) &&
      [[ "$instrumented_count" == "0" ]]; then
      ((consecutive_matches += 1))
      if ((consecutive_matches == 2)); then
        install -m 0644 "$metrics" "$RESULT_DIR/apache-instrumentation-drain-$label.prom"
        {
          printf 'expected_instrumented_processes=0\n'
          printf 'instrumented_processes=%s\n' "$instrumented_count"
        } >"$RESULT_DIR/apache-instrumentation-drain-$label.txt"
        rm -f -- "$metrics"
        log_info "Apache instrumentation drained before $label replacement"
        return 0
      fi
    else
      consecutive_matches=0
    fi
    if ((SECONDS < deadline)); then
      sleep 1
    fi
  done
  rm -f -- "$metrics"
  log_error "Apache instrumentation did not drain before $label replacement, got instrumented=${instrumented_count:-unavailable}"
  return 1
}

wait_for_http() {
  local -r endpoint="$1"
  local -r description="$2"
  local -i elapsed=0

  while ((elapsed < READINESS_TIMEOUT_SECONDS)); do
    if curl --fail --silent --show-error --max-time 3 "$endpoint" >/dev/null 2>&1; then
      log_info "$description is ready"
      return 0
    fi
    sleep 1
    ((elapsed += 1))
  done
  log_error "timed out waiting for $description"
  return 1
}

wait_for_log() {
  local -r service="$1"
  local -r pattern="$2"
  local -r description="$3"
  local -r since="${4:-}"
  local -i started_at="$SECONDS"
  local logs=""

  while ((SECONDS - started_at < READINESS_TIMEOUT_SECONDS)); do
    if [[ -n "$since" ]]; then
      logs="$(run_bounded 10 "${COMPOSE[@]}" logs --no-color --since "$since" "$service" 2>/dev/null || true)"
    else
      logs="$(run_bounded 10 "${COMPOSE[@]}" logs --no-color --tail 200 "$service" 2>/dev/null || true)"
    fi
    if [[ "$logs" == *"$pattern"* ]]; then
      log_info "$description is ready"
      return 0
    fi
    sleep 1
  done
  log_error "timed out waiting for $description log: $pattern"
  return 1
}

assert_selected_transport() {
  local -r expected="${1:-$TRANSPORT}"
  local logs=""

  case "$expected" in
    getsockopt|unix)
      logs="$(run_bounded 10 "${COMPOSE[@]}" logs --no-color --tail 500 obi 2>/dev/null || true)"
      [[ "$logs" == *"transport=$expected"* ]] || {
        log_error "OBI did not report the forced $expected transport"
        return 1
      }
      SELECTED_TRANSPORT="$expected"
      ;;
    auto)
      logs="$(run_bounded 10 "${COMPOSE[@]}" logs --no-color --tail 500 obi 2>/dev/null || true)"
      if [[ "$logs" == *"transport=getsockopt"* ]]; then
        SELECTED_TRANSPORT="getsockopt"
      elif [[ "$logs" == *"transport=unix"* ]]; then
        SELECTED_TRANSPORT="unix"
      else
        log_error "OBI did not report the transport selected by auto mode"
        return 1
      fi
      ;;
  esac
}

environment_has_line() {
  local -r environment="$1"
  local -r expected="$2"
  local line=""

  while IFS= read -r line; do
    if [[ "$line" == "$expected" ]]; then
      return 0
    fi
  done <<<"$environment"
  return 1
}

assert_runtime_contract() {
  local -r mode="${1:-$SCENARIO}"
  local -r output="$RESULT_DIR/runtime-assertions-$mode.txt"
  local java_container=""
  local java_environment=""
  local obi_container=""
  local obi_identity=""
  local java_agent="absent"
  local extension="absent"

  java_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet java-backend)"
  [[ -n "$java_container" ]] || {
    log_error "Java backend container identity is unavailable"
    return 1
  }
  java_environment="$(run_bounded 10 docker inspect \
    --format '{{range .Config.Env}}{{println .}}{{end}}' "$java_container")"
  if environment_has_line \
    "$java_environment" \
    "JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar"; then
    java_agent="official"
  fi
  if environment_has_line \
    "$java_environment" \
    "OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar"; then
    extension="disabled"
    if environment_has_line "$java_environment" "OTEL_OBI_REMOTE_PARENT_ENABLED=true"; then
      extension="enabled"
    fi
  fi

  if [[ "$mode" == "uninstrumented" ]]; then
    [[ "$java_agent" == "absent" && "$extension" == "absent" ]] || {
      log_error "uninstrumented control unexpectedly configured Java instrumentation"
      return 1
    }
    [[ -z "$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi 2>/dev/null || true)" ]] || {
      log_error "uninstrumented control unexpectedly started OBI"
      return 1
    }
  elif [[ "$mode" == "obi-absent" ]]; then
    [[ "$java_agent" == "official" && "$extension" == "enabled" ]] || {
      log_error "OBI-absent control requires the official agent and enabled extension"
      return 1
    }
    [[ -z "$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi 2>/dev/null || true)" ]] || {
      log_error "OBI-absent control unexpectedly started OBI"
      return 1
    }
  elif [[ "$mode" == "extension-absent" || "$mode" == "extension-disabled" ]]; then
    [[ "$java_agent" == "official" ]] || {
      log_error "$mode control requires the official Java agent"
      return 1
    }
    [[ "$extension" == "${mode#extension-}" ]] || {
      log_error "$mode control has extension state $extension"
      return 1
    }
    [[ -z "$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi 2>/dev/null || true)" ]] || {
      log_error "$mode control unexpectedly started OBI"
      return 1
    }
  else
    [[ "$java_agent" == "official" && "$extension" == "enabled" ]] || {
      log_error "Java runtime does not have the expected official agent and extension opt-in"
      return 1
    }
    obi_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi)"
    [[ -n "$obi_container" ]] || {
      log_error "OBI container identity is unavailable"
      return 1
    }
    obi_identity="$(run_bounded 10 docker inspect \
      --format '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}}' "$obi_container")"
    [[ "$obi_identity" == "true host" ]] || {
      log_error "OBI runtime must be privileged with the host PID namespace, got: $obi_identity"
      return 1
    }
    [[ -r /sys/kernel/btf/vmlinux ]] || {
      log_error "host vmlinux BTF is not readable"
      return 1
    }
    wait_for_java_duplicate_suppression \
      "$RESULT_DIR/duplicate-suppression-$mode.prom"
  fi

  {
    printf 'status=passed\n'
    printf 'java_container=%s\n' "$java_container"
    printf 'java_agent=%s\n' "$java_agent"
    printf 'extension=%s\n' "$extension"
    printf 'obi_container=%s\n' "${obi_container:-absent}"
    printf 'obi_privileged_pid_mode=%s\n' "${obi_identity:-absent}"
    printf 'vmlinux_btf=%s\n' "$([[ -r /sys/kernel/btf/vmlinux ]] && printf readable || printf unavailable)"
  } >"$output"
}

wait_for_java_duplicate_suppression() {
  local -r output="$1"
  local metrics=""
  local -i elapsed=0

  metrics="$(mktemp "$RESULT_DIR/.duplicate-suppression.XXXXXX")"
  while ((elapsed < 20)); do
    if fetch_obi_metrics "$metrics" 2>/dev/null && \
      java_duplicate_suppression_present "$metrics"; then
      install -m 0644 "$metrics" "$output"
      rm -f -- "$metrics"
      return 0
    fi
    sleep 1
    ((elapsed += 1))
  done
  rm -f -- "$metrics"
  log_error "OBI did not report Java duplicate-trace suppression"
  return 1
}

java_duplicate_suppression_present() {
  local -r metrics="$1"

  awk '
    $0 ~ /^obi_avoided_services/ &&
    $0 ~ /service_name="java-backend"/ &&
    $0 ~ /service_namespace="apache-java-https"/ &&
    $0 ~ /telemetry_type="traces"/ && $2 > 0 { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$metrics"
}

fetch_obi_metrics() {
  local -r output="$1"
  local -r timeout_seconds="${2:-5}"

  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 1
  curl --fail --silent --show-error --max-time "$timeout_seconds" \
    "http://127.0.0.1:18990/internal/metrics" >"$output"
}

bridge_success_total() {
  local -r metrics="$1"

  awk '
    $0 ~ /^obi_java_remote_parent_operations_total/ &&
    $0 ~ /operation="(take|discard)"/ &&
    $0 ~ /status="valid"/ &&
    $0 ~ /transport="(getsockopt|unix)"/ {
      total += $2
    }
    END { printf "%.0f\n", total }
  ' "$metrics"
}

bridge_take_attempt_total() {
  local -r metrics="$1"
  local -r transport="$SELECTED_TRANSPORT"
  local metric=""
  local labels=""
  local raw_value=""
  local value=""
  local extra=""
  local -i total=0

  [[ "$transport" == "getsockopt" || "$transport" == "unix" ]] || return 1
  while read -r metric raw_value extra; do
    [[ "$metric" == 'obi_java_remote_parent_operations_total{'*'}' ]] || continue
    labels=",${metric#*\{}"
    labels="${labels%\}},"
    [[ "$labels" == *',operation="take",'* &&
      "$labels" == *",transport=\"$transport\","* ]] || continue
    [[ -z "$extra" ]] || return 1
    value="$(bounded_decimal "$raw_value" "$MAX_SHELL_INTEGER" true)" || return 1
    ((total <= MAX_SHELL_INTEGER - value)) || return 1
    total="$((total + value))"
  done <"$metrics"
  printf '%s\n' "$total"
}

bridge_inject_attempt_total() {
  local -r metrics="$1"
  local metric=""
  local labels=""
  local raw_value=""
  local value=""
  local extra=""
  local -i total=0

  while read -r metric raw_value extra; do
    [[ "$metric" == 'obi_java_remote_parent_operations_total{'*'}' ]] || continue
    labels=",${metric#*\{}"
    labels="${labels%\}},"
    [[ "$labels" == *',operation="inject",'* &&
      "$labels" == *',transport="tcp",'* ]] || continue
    [[ -z "$extra" ]] || return 1
    value="$(bounded_decimal "$raw_value" "$MAX_SHELL_INTEGER" true)" || return 1
    ((total <= MAX_SHELL_INTEGER - value)) || return 1
    total="$((total + value))"
  done <"$metrics"
  printf '%s\n' "$total"
}

bridge_stage_total() {
  local -r metrics="$1"

  awk '
    $0 ~ /^obi_java_remote_parent_operations_total/ &&
    $0 ~ /operation="stage"/ &&
    $0 ~ /status="valid"/ &&
    $0 ~ /transport="tcp"/ {
      total += $2
    }
    END { printf "%.0f\n", total }
  ' "$metrics"
}

bridge_report_total() {
  local -r metrics="$1"

  awk '
    $0 ~ /^obi_java_remote_parent_operations_total/ &&
    $0 ~ /operation="report"/ &&
    $0 ~ /status="valid"/ &&
    $0 ~ /transport="tcp"/ {
      total += $2
    }
    END { printf "%.0f\n", total }
  ' "$metrics"
}

bridge_metric_fingerprint() {
  local -r metrics="$1"

  awk \
    -v allow_primary_security="$ALLOW_PRIMARY_SECURITY_METRICS" \
    -v allow_unix_security="$ALLOW_UNIX_SECURITY_METRICS" '
    $0 ~ /^obi_java_remote_parent_operations_total/ &&
    $0 ~ /operation="(stage|candidate|handoff|take|discard|negotiate|inject)"/ {
      if (operation_allowed_during_security_probe($0)) {
        next
      }
      print
    }
    function operation_allowed_during_security_probe(line) {
      if (line !~ /operation="take"/ || line !~ /status="unauthorized"/) {
        return 0
      }
      return (allow_primary_security == "true" && line ~ /transport="getsockopt"/) ||
        (allow_unix_security == "true" && line ~ /transport="unix"/)
    }
  ' "$metrics" | LC_ALL=C sort | sha256sum | awk '{print $1}'
}

wait_for_bridge_metrics_quiescent() {
  local -r minimum_success="$1"
  local -r minimum_stage="$2"
  local -r output="$3"
  local -r description="$4"
  local candidate=""
  local fingerprint=""
  local previous_fingerprint=""
  local report=""
  local stage=""
  local success=""
  local -i started_at="$SECONDS"
  local -i previous_report=-1

  candidate="$(mktemp "$RESULT_DIR/.bridge-metrics.XXXXXX")"
  while ((SECONDS - started_at < BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS)); do
    if fetch_obi_metrics "$candidate" 2>/dev/null; then
      success="$(bridge_success_total "$candidate")"
      stage="$(bridge_stage_total "$candidate")"
      report="$(bridge_report_total "$candidate")"
      fingerprint="$(bridge_metric_fingerprint "$candidate")"
      if [[ "$success" =~ ^[0-9]+$ && "$stage" =~ ^[0-9]+$ &&
        "$report" =~ ^[0-9]+$ ]] && ((report > previous_report)); then
        if [[ -n "$previous_fingerprint" && "$fingerprint" == "$previous_fingerprint" ]] &&
          ((success >= minimum_success && stage >= minimum_stage)); then
          install -m 0644 "$candidate" "$output"
          rm -f -- "$candidate"
          return 0
        fi
        previous_report="$report"
        previous_fingerprint="$fingerprint"
      fi
    fi
    sleep 1
  done
  rm -f -- "$candidate"
  log_error "timed out waiting for $description (minimum success=$minimum_success stage=$minimum_stage, last success=${success:-unavailable} stage=${stage:-unavailable} report=${report:-unavailable})"
  return 1
}

wait_for_primary_security_metrics_quiescent() {
  local -r output="$1"
  local -r description="$2"
  local -r previous_policy="$ALLOW_PRIMARY_SECURITY_METRICS"
  local wait_status=0

  ALLOW_PRIMARY_SECURITY_METRICS=true
  if wait_for_bridge_metrics_quiescent 0 0 "$output" "$description"; then
    wait_status=0
  else
    wait_status=$?
  fi
  ALLOW_PRIMARY_SECURITY_METRICS="$previous_policy"
  return "$wait_status"
}

flush_bridge_metric_boundary() {
  local -r label="$1"
  local current=""
  local before_stage=""
  local before_success=""

  [[ "$BRIDGE_RUNNING" == "true" ]] || return 0
  current="$(mktemp "$RESULT_DIR/.bridge-boundary.XXXXXX")"
  fetch_obi_metrics "$current"
  before_success="$(bridge_success_total "$current")"
  before_stage="$(bridge_stage_total "$current")"
  curl --fail --silent --show-error --max-time 5 \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" >/dev/null
  rm -f -- "$current"
  wait_for_bridge_metrics_quiescent \
    "$((before_success + 1))" \
    "$((before_stage + 1))" \
    "$RESULT_DIR/metrics-boundary-$label.prom" \
    "$label pre-scenario bridge metric boundary"
}

scenario_request_count() {
  local -r name="$1"

  if [[ "$name" == "w3c-fault" ]]; then
    printf '%d\n' "$FAULT_REQUEST_COUNT"
    return
  fi
  if [[ "$name" == "tls-boundary" ]]; then
    printf '2\n'
    return
  fi
  if ((REQUEST_COUNT > 0)); then
    printf '%d\n' "$REQUEST_COUNT"
    return
  fi
  case "$name" in
    keepalive|pipelining)
      printf '10\n'
      ;;
    concurrency)
      printf '16\n'
      ;;
    connection-churn|fd-port-reuse)
      printf '32\n'
      ;;
    restart-fault)
      printf '32\n'
      ;;
    slow-body)
      printf '8\n'
      ;;
    pressure)
      printf '128\n'
      ;;
    handoff|virtual-thread|netty|dispatch)
      printf '4\n'
      ;;
    w3c|obi-flags|w3c-fault)
      printf '2\n'
      ;;
    *)
      printf '1\n'
      ;;
  esac
}

scenario_bridge_take_count() {
  local -r name="$1"
  local count=""

  count="$(scenario_request_count "$name")"
  if [[ "$name" == "timeout-retry" ]]; then
    count="$((count + 1))"
  fi
  printf '%d\n' "$count"
}

scenario_java_missing_count() {
  local -r name="$1"
  local -r diagnostics_enabled="$2"
  local count=0

  if [[ "$name" != "w3c-fault" && "$diagnostics_enabled" == "true" ]]; then
    count=1
  fi
  if [[ "$name" == "tls-boundary" ]]; then
    count="$((count + 3))"
  fi
  printf '%d\n' "$count"
}

scenario_bridge_missing_count() {
  local -r name="$1"
  local -r transport="$2"

  if [[ "$transport" == "unix" && "$name" == "tls-boundary" ]]; then
    printf '3\n'
    return
  fi
  printf '0\n'
}

pressure_map_metric() {
  local -r metrics="$1"
  local -r metric_name="$2"
  local -r map_id="${3:-}"

  awk -v wanted_metric="$metric_name" -v wanted_id="$map_id" '
    $1 ~ ("^" wanted_metric "\\{") && $1 ~ /map_name="java_remote_par"/ {
      id = $1
      sub(/^.*map_id="/, "", id)
      sub(/".*$/, "", id)
      if (wanted_id == "" || id == wanted_id) {
        matches++
        selected_id = id
        selected_value = $2
      }
    }
    END {
      if (matches != 1) {
        exit 1
      }
      printf "%s %s\n", selected_id, selected_value
    }
  ' "$metrics"
}

run_map_pressure_helper() {
  local -r output="$1"
  local -r stderr_output="$2"
  local -r timeout_seconds="$3"
  local command_status=0
  local replay_status=0
  shift 3

  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || {
    log_error "map-pressure helper timeout must be a positive integer"
    return 2
  }
  if run_bounded "$timeout_seconds" \
    "${COMPOSE[@]}" run --rm --no-deps --no-TTY map-pressure \
      "$@" >"$output" 2>"$stderr_output"; then
    command_status=0
  else
    command_status=$?
  fi
  if [[ -s "$stderr_output" ]]; then
    if sed -n 'p' "$stderr_output" >&2; then
      :
    else
      replay_status=$?
    fi
  fi
  if [[ -s "$output" ]]; then
    if sed -n 'p' "$output"; then
      :
    else
      replay_status=$?
    fi
  fi
  if ((command_status != 0)); then
    return "$command_status"
  fi
  return "$replay_status"
}

pressure_result_record() {
  local -r input="$1"
  local -a records=()

  [[ -f "$input" && ! -L "$input" ]] || return 1
  mapfile -t records <"$input"
  ((${#records[@]} == 1)) || return 1
  printf '%s\n' "${records[0]}"
}

pressure_result_has_contract() {
  local -r input="$1"
  local -r mode="$2"
  local -r decimal='(0|[1-9][0-9]*)'
  local record=""
  local pattern=""

  record="$(pressure_result_record "$input")" || return 1
  case "$mode" in
    prepare)
      pattern='^\{"status":"passed","mode":"prepare","map_id":'"$decimal"',"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":'"$decimal"',"process_map_id":'"$decimal"',"process_pid":'"$decimal"',"process_namespace":'"$decimal"',"token_base":'"$decimal"',"touched":0\}$'
      ;;
    fill)
      pattern='^\{"status":"passed","mode":"fill","map_id":'"$decimal"',"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":'"$decimal"',"process_map_id":'"$decimal"',"process_pid":'"$decimal"',"process_namespace":'"$decimal"',"token_base":'"$decimal"',"touched":'"$decimal"',"evicted_entries":'"$decimal"'\}$'
      ;;
    cleanup)
      pattern='^\{"status":"passed","mode":"cleanup","map_id":'"$decimal"',"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":'"$decimal"',"process_map_id":0,"process_pid":'"$decimal"',"process_namespace":'"$decimal"',"token_base":'"$decimal"',"touched":'"$decimal"',"cleanup_verified":true,"verified_absent_entries":'"$decimal"'\}$'
      ;;
    *)
      return 1
      ;;
  esac
  [[ "$record" =~ $pattern ]]
}

pressure_result_uint() {
  local -r input="$1"
  local -r field="$2"
  local record=""
  local marker=""
  local value=""

  [[ "$field" =~ ^[a-z_]+$ ]] || return 1
  record="$(pressure_result_record "$input")" || return 1
  marker="\"$field\":"
  [[ "$record" == *"$marker"* ]] || return 1
  value="${record#*"$marker"}"
  value="${value%%,*}"
  value="${value%\}}"
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  printf '%s\n' "$value"
}

pressure_result_bool() {
  local -r input="$1"
  local -r field="$2"
  local record=""
  local marker=""
  local value=""

  [[ "$field" =~ ^[a-z_]+$ ]] || return 1
  record="$(pressure_result_record "$input")" || return 1
  marker="\"$field\":"
  [[ "$record" == *"$marker"* ]] || return 1
  value="${record#*"$marker"}"
  value="${value%%,*}"
  value="${value%\}}"
  [[ "$value" == "true" || "$value" == "false" ]] || return 1
  printf '%s\n' "$value"
}

pressure_scenario_count() {
  local -r input="$1"
  local -r field="$2"
  local -r maximum="${3:-$MAX_SHELL_INTEGER}"
  local value=""

  [[ -f "$input" && ! -L "$input" && "$field" =~ ^[a-z_]+$ ]] || return 1
  value="$(awk -v wanted="\"$field\":" '
    $1 == wanted {
      value = $2
      sub(/,$/, "", value)
      if (NF != 2 || value !~ /^(0|[1-9][0-9]*)$/) {
        invalid = 1
      }
      matches++
    }
    END {
      if (invalid || matches != 1) {
        exit 1
      }
      print value
    }
  ' "$input")" || return 1
  bounded_decimal "$value" "$maximum" true
}

pressure_result_bounded_uint() {
  local -r input="$1"
  local -r field="$2"
  local -r maximum="$3"
  local -r allow_zero="$4"
  local value=""

  value="$(pressure_result_uint "$input" "$field")" || return 1
  bounded_decimal "$value" "$maximum" "$allow_zero"
}

record_pressure_cleanup_status() {
  local -r output="$1"
  local -r command_status="$2"
  local -r validation_status="$3"
  local -r recovery_status="$4"

  {
    printf 'command_status=%s\n' "$command_status"
    printf 'validation_status=%s\n' "$validation_status"
    printf 'recovery_status=%s\n' "$recovery_status"
    printf 'monitor_status=%s\n' "${PRESSURE_MONITOR_STATUS:-0}"
  } >"$output"
}

wait_for_pressure_map_state() {
  local -r comparison="$1"
  local -r output="$2"
  local timeout_seconds="${3:-$PRESSURE_STATE_TIMEOUT_SECONDS}"
  local required_matches="${4:-1}"
  local maximum_attempts="${5:-}"
  local metrics=""
  local metrics_timeout=""
  local resolved=""
  local resolved_map_id=""
  local entries=""
  local matched=false
  local samples_log=""
  local sample_output=""
  local match_file=""
  local -a match_files=()
  local -a published_samples=()
  local -i attempts=0
  local -i consecutive_matches=0
  local -i deadline=0
  local -i index=0

  if [[ "$comparison" != "pressured" && "$comparison" != "recovered" ]]; then
    log_error "unknown handoff-claim map state comparison: $comparison"
    return 1
  fi
  timeout_seconds="$(bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false)" || {
    log_error "handoff-claim map state bounds must be positive integers"
    return 1
  }
  required_matches="$(bounded_decimal "$required_matches" "$MAX_SHELL_INTEGER" false)" || {
    log_error "handoff-claim map state bounds must be positive integers"
    return 1
  }
  if [[ -z "$maximum_attempts" ]]; then
    if [[ "$timeout_seconds" == "$MAX_SHELL_INTEGER" ]]; then
      maximum_attempts="$MAX_SHELL_INTEGER"
    else
      maximum_attempts="$((timeout_seconds + 1))"
    fi
  fi
  maximum_attempts="$(bounded_decimal "$maximum_attempts" "$MAX_SHELL_INTEGER" false)" || {
    log_error "handoff-claim map state bounds must be positive integers"
    return 1
  }
  if ((required_matches > maximum_attempts)); then
    log_error "handoff-claim map state matches must not exceed the attempt cap"
    return 1
  fi
  metrics="$(mktemp "$RESULT_DIR/.pressure-state.XXXXXX")" || return 1
  if ((required_matches > 1)); then
    samples_log="${output%.prom}-samples.log"
    if ! : >"$samples_log"; then
      rm -f -- "$metrics"
      return 1
    fi
  fi
  deadline="$((SECONDS + timeout_seconds))"
  while ((attempts < maximum_attempts && SECONDS < deadline)); do
    ((attempts += 1))
    resolved=""
    resolved_map_id=""
    entries=""
    metrics_timeout="$(remaining_timeout_seconds "$deadline" 5)" || break
    matched=false
    if fetch_obi_metrics "$metrics" "$metrics_timeout" 2>/dev/null; then
      resolved="$(pressure_map_metric \
        "$metrics" \
        obi_bpf_map_entries_total \
        "$PRESSURE_MAP_ID")"
      resolved_map_id="${resolved%% *}"
      entries="${resolved#* }"
      if [[ "$resolved_map_id" == "$PRESSURE_MAP_ID" ]] && \
        entries="$(bounded_decimal "$entries" "$PRESSURE_MAP_MAX_ENTRIES" true)" && \
        ((SECONDS < deadline)); then
        if [[ "$comparison" == "pressured" ]] &&
          ((entries > PRESSURE_MAP_BASELINE_ENTRIES && entries <= PRESSURE_MAP_MAX_ENTRIES)); then
          matched=true
        elif [[ "$comparison" == "recovered" ]] &&
          ((entries <= PRESSURE_MAP_BASELINE_ENTRIES)); then
          matched=true
        fi
      fi
    fi
    if [[ "$matched" == "true" ]]; then
      ((consecutive_matches += 1))
      if ((required_matches > 1)); then
        match_file="$(mktemp "$RESULT_DIR/.pressure-match.XXXXXX")" || {
          rm -f -- "$metrics" "${match_files[@]}"
          return 1
        }
        if ! install -m 0600 "$metrics" "$match_file"; then
          rm -f -- "$metrics" "$match_file" "${match_files[@]}"
          return 1
        fi
        match_files+=("$match_file")
      fi
    else
      if ((${#match_files[@]} > 0)); then
        rm -f -- "${match_files[@]}"
        match_files=()
      fi
      consecutive_matches=0
    fi
    if [[ -n "$samples_log" ]]; then
      if ! printf 'attempt=%d observed_at=%(%Y-%m-%dT%H:%M:%SZ)T entries=%s matched=%s consecutive=%d\n' \
        "$attempts" \
        -1 \
        "${entries:-unavailable}" \
        "$matched" \
        "$consecutive_matches" >>"$samples_log"; then
        rm -f -- "$metrics" "${match_files[@]}"
        return 1
      fi
    fi
    if ((consecutive_matches >= required_matches)); then
      if ((required_matches > 1)); then
        for ((index = 0; index < required_matches; index++)); do
          printf -v sample_output \
            '%s-sample-%02d.prom' "${output%.prom}" "$((index + 1))"
          if ! install -m 0644 "${match_files[$index]}" "$sample_output"; then
            rm -f -- "$metrics" "$output" "${match_files[@]}" "${published_samples[@]}"
            return 1
          fi
          published_samples+=("$sample_output")
        done
        if ! install -m 0644 "${match_files[$((required_matches - 1))]}" "$output"; then
          rm -f -- "$metrics" "$output" "${match_files[@]}" "${published_samples[@]}"
          return 1
        fi
      elif ! install -m 0644 "$metrics" "$output"; then
        rm -f -- "$metrics"
        return 1
      fi
      rm -f -- "$metrics" "${match_files[@]}"
      return 0
    fi
    if ((attempts < maximum_attempts && SECONDS < deadline)); then
      sleep 1
    fi
  done
  rm -f -- "$metrics" "${match_files[@]}"
  log_error "timed out waiting for handoff-claim map state $comparison, actual=${entries:-unavailable} baseline=${PRESSURE_MAP_BASELINE_ENTRIES:-unavailable} attempts=$attempts"
  return 1
}

monitor_map_pressure() {
  local metrics=""
  local resolved=""
  local resolved_map_id=""
  local entries=""
  local raw_entries=""
  local inject_total=""

  metrics="$(mktemp "$RESULT_DIR/.pressure-monitor.XXXXXX")"
  trap '[[ -z "${metrics:-}" ]] || rm -f -- "$metrics"; exit 0' TERM INT
  trap '[[ -z "${metrics:-}" ]] || rm -f -- "$metrics"' EXIT
  while true; do
    if ! fetch_obi_metrics \
      "$metrics" "$PRESSURE_MONITOR_METRICS_TIMEOUT_SECONDS" 2>/dev/null; then
      printf 'status=failed reason=metrics-unavailable\n' >>"$PRESSURE_MONITOR_OUTPUT"
      return 1
    fi
    if resolved="$(pressure_map_metric \
      "$metrics" \
      obi_bpf_map_entries_total \
      "$PRESSURE_MAP_ID")"; then
      resolved_map_id="${resolved%% *}"
      raw_entries="${resolved#* }"
    else
      resolved_map_id=""
      raw_entries=""
    fi
    entries="$(bounded_decimal \
      "$raw_entries" \
      "$PRESSURE_MAP_MAX_ENTRIES" \
      true)" || entries=""
    if [[ "$resolved_map_id" != "$PRESSURE_MAP_ID" || -z "$entries" ]] ||
      ((entries <= PRESSURE_MAP_BASELINE_ENTRIES)); then
      printf 'status=failed reason=occupancy map_id=%s baseline=%s max_entries=%s actual=%s\n' \
        "$PRESSURE_MAP_ID" \
        "$PRESSURE_MAP_BASELINE_ENTRIES" \
        "$PRESSURE_MAP_MAX_ENTRIES" \
        "${raw_entries:-unavailable}" >>"$PRESSURE_MONITOR_OUTPUT"
      return 1
    fi
    printf 'status=pressured observed_at=%(%Y-%m-%dT%H:%M:%SZ)T map_id=%s baseline=%s max_entries=%s entries=%s\n' \
      -1 \
      "$PRESSURE_MAP_ID" \
      "$PRESSURE_MAP_BASELINE_ENTRIES" \
      "$PRESSURE_MAP_MAX_ENTRIES" \
      "$entries" >>"$PRESSURE_MONITOR_OUTPUT"
    inject_total="$(bridge_inject_attempt_total "$metrics")" || inject_total=""
    inject_total="$(bounded_decimal "$inject_total" "$MAX_SHELL_INTEGER" true)" || \
      inject_total=""
    if [[ -z "$inject_total" ]] || ((inject_total > PRESSURE_INJECT_TARGET)); then
      printf 'status=failed reason=traffic-count operation=inject transport=tcp actual=%s target=%s\n' \
        "${inject_total:-unavailable}" \
        "$PRESSURE_INJECT_TARGET" >>"$PRESSURE_MONITOR_OUTPUT"
      return 1
    fi
    if ((inject_total == PRESSURE_INJECT_TARGET)); then
      if ! install -m 0644 "$metrics" "$PRESSURE_MONITOR_FINAL_OUTPUT"; then
        printf 'status=failed reason=terminal-evidence\n' >>"$PRESSURE_MONITOR_OUTPUT"
        return 1
      fi
      printf 'status=traffic-complete observed_at=%(%Y-%m-%dT%H:%M:%SZ)T map_id=%s baseline=%s max_entries=%s entries=%s operation=inject transport=tcp inject_total=%s target=%s\n' \
        -1 \
        "$PRESSURE_MAP_ID" \
        "$PRESSURE_MAP_BASELINE_ENTRIES" \
        "$PRESSURE_MAP_MAX_ENTRIES" \
        "$entries" \
        "$inject_total" \
        "$PRESSURE_INJECT_TARGET" >>"$PRESSURE_MONITOR_OUTPUT"
      return 0
    fi
    sleep "$PRESSURE_MONITOR_POLL_INTERVAL_SECONDS"
  done
}

start_map_pressure_monitor() {
  local -i elapsed=0

  PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/map-pressure-${PRESSURE_LABEL}-monitor.log"
  PRESSURE_MONITOR_FINAL_OUTPUT="$RESULT_DIR/map-pressure-${PRESSURE_LABEL}-traffic-complete.prom"
  : >"$PRESSURE_MONITOR_OUTPUT"
  monitor_map_pressure &
  PRESSURE_MONITOR_PID=$!
  while ((elapsed < 50)); do
    if grep -q '^status=pressured ' "$PRESSURE_MONITOR_OUTPUT"; then
      return 0
    fi
    if ! kill -0 "$PRESSURE_MONITOR_PID" 2>/dev/null; then
      if wait "$PRESSURE_MONITOR_PID"; then
        :
      fi
      PRESSURE_MONITOR_PID=""
      log_error "handoff-claim map occupancy monitor exited before its first sample"
      return 1
    fi
    sleep 0.1
    ((elapsed += 1))
  done
  stop_map_pressure_monitor || true
  log_error "handoff-claim map occupancy monitor did not record a pressured sample"
  return 1
}

stop_map_pressure_monitor() {
  local status=0
  local -i elapsed=0
  local -i maximum_waits="$((PRESSURE_MONITOR_COMPLETION_TIMEOUT_SECONDS * 10))"

  [[ -n "$PRESSURE_MONITOR_PID" ]] || return 0
  if kill -0 "$PRESSURE_MONITOR_PID" 2>/dev/null; then
    while ((elapsed < maximum_waits)); do
      if [[ -n "$PRESSURE_MONITOR_OUTPUT" ]] && \
        grep -Eq '^status=(traffic-complete|failed) ' "$PRESSURE_MONITOR_OUTPUT"; then
        break
      fi
      if ! kill -0 "$PRESSURE_MONITOR_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
      elapsed="$((elapsed + 1))"
    done
  fi
  if kill -0 "$PRESSURE_MONITOR_PID" 2>/dev/null; then
    kill -TERM "$PRESSURE_MONITOR_PID" 2>/dev/null || true
  fi
  if wait "$PRESSURE_MONITOR_PID"; then
    status=0
  else
    status=$?
  fi
  PRESSURE_MONITOR_PID=""
  if ((status != 0)); then
    log_error "handoff-claim map occupancy monitor failed, status=$status"
    return "$status"
  fi
  if [[ -z "$PRESSURE_MONITOR_OUTPUT" ]] || \
    ! grep -q '^status=pressured ' "$PRESSURE_MONITOR_OUTPUT" || \
    [[ "$(grep -c '^status=traffic-complete ' "$PRESSURE_MONITOR_OUTPUT" || true)" != "1" ]] || \
    [[ -z "$PRESSURE_MONITOR_FINAL_OUTPUT" || \
      ! -f "$PRESSURE_MONITOR_FINAL_OUTPUT" || \
      -L "$PRESSURE_MONITOR_FINAL_OUTPUT" ]] || \
    grep -q '^status=failed ' "$PRESSURE_MONITOR_OUTPUT"; then
    log_error "handoff-claim map occupancy monitor did not prove pressure through bridge-traffic completion"
    return 1
  fi
}

start_map_pressure() {
  local -r label="$1"
  local -r baseline_metrics="$2"
  local -r expected_inject_count="$3"
  local prepare_output=""
  local prepare_stderr=""
  local fill_output=""
  local fill_stderr=""
  local resolved=""
  local baseline_map_id=""
  local baseline_entries=""
  local baseline_inject_total=""
  local prepare_map_id=""
  local prepare_max_entries=""
  local prepare_process_map_id=""
  local prepare_process_pid=""
  local prepare_process_namespace=""
  local prepare_token_base=""
  local fill_map_id=""
  local fill_max_entries=""
  local fill_process_map_id=""
  local fill_process_pid=""
  local fill_process_namespace=""
  local fill_token_base=""
  local fill_touched=""
  local fill_evicted=""
  local prepare_status=0
  local fill_status=0
  local start_status=0
  local -i synthetic_entry_count=0

  if [[ "$PRESSURE_ACTIVE" == "true" ]]; then
    log_error "refusing to start map pressure while a prior cleanup is pending"
    return 1
  fi
  PRESSURE_LABEL="$label"
  PRESSURE_SEED="$SCENARIO_SEED"
  PRESSURE_ACTIVE=false
  PRESSURE_MAP_ID=""
  PRESSURE_MAP_MAX_ENTRIES=""
  PRESSURE_MAP_BASELINE_ENTRIES=""
  PRESSURE_EVICTED_ENTRIES=""
  PRESSURE_TOUCHED_ENTRIES=""
  PRESSURE_CLEANUP_ATTEMPT=0
  PRESSURE_CLEANUP_DEADLINE=0
  PRESSURE_PROCESS_MAP_ID=""
  PRESSURE_PROCESS_PID=""
  PRESSURE_PROCESS_NAMESPACE=""
  PRESSURE_TOKEN_BASE=""
  PRESSURE_MONITOR_PID=""
  PRESSURE_MONITOR_OUTPUT=""
  PRESSURE_MONITOR_FINAL_OUTPUT=""
  PRESSURE_MONITOR_STATUS=0
  PRESSURE_INJECT_TARGET=""
  prepare_output="$RESULT_DIR/map-pressure-$label-prepare.json"
  prepare_stderr="$RESULT_DIR/map-pressure-$label-prepare.stderr.log"
  if run_map_pressure_helper \
    "$prepare_output" \
    "$prepare_stderr" \
    "$PRESSURE_HELPER_TIMEOUT_SECONDS" \
    --seed "$PRESSURE_SEED" \
    --mode prepare; then
    prepare_status=0
  else
    prepare_status=$?
  fi
  if ((prepare_status != 0)); then
    return "$prepare_status"
  fi
  if ! pressure_result_has_contract "$prepare_output" prepare; then
    log_error "map-pressure prepare output does not match the exact evidence contract"
    return 1
  fi
  prepare_map_id="$(pressure_result_bounded_uint \
    "$prepare_output" map_id "$MAX_UINT32_DECIMAL" false)" || {
    log_error "map-pressure prepare returned an invalid map ID"
    return 1
  }
  prepare_max_entries="$(pressure_result_bounded_uint \
    "$prepare_output" max_entries "$PRESSURE_MAX_ENTRIES" false)" || {
    log_error "map-pressure prepare returned an invalid map capacity"
    return 1
  }
  prepare_process_map_id="$(pressure_result_bounded_uint \
    "$prepare_output" process_map_id "$MAX_UINT32_DECIMAL" false)" || {
    log_error "map-pressure prepare returned an invalid process-map ID"
    return 1
  }
  prepare_process_pid="$(pressure_result_bounded_uint \
    "$prepare_output" process_pid "$MAX_UINT32_DECIMAL" false)" || {
    log_error "map-pressure prepare returned an invalid process ID"
    return 1
  }
  prepare_process_namespace="$(pressure_result_bounded_uint \
    "$prepare_output" process_namespace "$MAX_UINT32_DECIMAL" false)" || {
    log_error "map-pressure prepare returned an invalid process namespace"
    return 1
  }
  prepare_token_base="$(pressure_result_bounded_uint \
    "$prepare_output" token_base "$MAX_UINT64_DECIMAL" false)" || {
    log_error "map-pressure prepare returned an invalid token base"
    return 1
  }

  resolved="$(pressure_map_metric \
    "$baseline_metrics" \
    obi_bpf_map_entries_total \
    "$prepare_map_id")"
  baseline_map_id="${resolved%% *}"
  baseline_entries="${resolved#* }"
  if [[ "$baseline_map_id" != "$prepare_map_id" ]] || \
    ! baseline_entries="$(bounded_decimal \
      "$baseline_entries" \
      "$((prepare_max_entries - 1))" \
      true)"; then
    log_error "pre-fill handoff-claim occupancy is unavailable or not below capacity"
    return 1
  fi
  baseline_inject_total="$(bridge_inject_attempt_total "$baseline_metrics")" || {
    log_error "pre-fill bridge inject count is unavailable"
    return 1
  }
  baseline_inject_total="$(bounded_decimal \
    "$baseline_inject_total" "$MAX_SHELL_INTEGER" true)" || {
    log_error "pre-fill bridge inject count is invalid"
    return 1
  }
  if ! bounded_decimal \
    "$expected_inject_count" "$MAX_SHELL_INTEGER" false >/dev/null || \
    ((baseline_inject_total > MAX_SHELL_INTEGER - expected_inject_count)); then
    log_error "pressure bridge inject target is outside the bounded counter range"
    return 1
  fi

  PRESSURE_MAP_ID="$prepare_map_id"
  PRESSURE_MAP_MAX_ENTRIES="$prepare_max_entries"
  PRESSURE_MAP_BASELINE_ENTRIES="$baseline_entries"
  PRESSURE_PROCESS_MAP_ID="$prepare_process_map_id"
  PRESSURE_PROCESS_PID="$prepare_process_pid"
  PRESSURE_PROCESS_NAMESPACE="$prepare_process_namespace"
  PRESSURE_TOKEN_BASE="$prepare_token_base"
  PRESSURE_INJECT_TARGET="$((baseline_inject_total + expected_inject_count))"
  PRESSURE_ACTIVE=true

  fill_output="$RESULT_DIR/map-pressure-$label-fill.json"
  fill_stderr="$RESULT_DIR/map-pressure-$label-fill.stderr.log"
  if run_map_pressure_helper \
    "$fill_output" \
    "$fill_stderr" \
    "$PRESSURE_HELPER_TIMEOUT_SECONDS" \
    --map-id "$PRESSURE_MAP_ID" \
    --expected-max-entries "$PRESSURE_MAP_MAX_ENTRIES" \
    --expected-process-map-id "$PRESSURE_PROCESS_MAP_ID" \
    --process-pid "$PRESSURE_PROCESS_PID" \
    --process-namespace "$PRESSURE_PROCESS_NAMESPACE" \
    --token-base "$PRESSURE_TOKEN_BASE" \
    --seed "$PRESSURE_SEED" \
    --mode fill; then
    fill_status=0
  else
    fill_status=$?
  fi
  if ((fill_status != 0)); then
    cleanup_map_pressure_with_retries || true
    return "$fill_status"
  fi
  if ! pressure_result_has_contract "$fill_output" fill; then
    log_error "map-pressure fill output does not match the exact evidence contract"
    cleanup_map_pressure_with_retries || true
    return 1
  fi
  fill_map_id="$(pressure_result_bounded_uint \
    "$fill_output" map_id "$MAX_UINT32_DECIMAL" false)" || fill_map_id=""
  fill_max_entries="$(pressure_result_bounded_uint \
    "$fill_output" max_entries "$PRESSURE_MAX_ENTRIES" false)" || fill_max_entries=""
  fill_process_map_id="$(pressure_result_bounded_uint \
    "$fill_output" process_map_id "$MAX_UINT32_DECIMAL" false)" || fill_process_map_id=""
  fill_process_pid="$(pressure_result_bounded_uint \
    "$fill_output" process_pid "$MAX_UINT32_DECIMAL" false)" || fill_process_pid=""
  fill_process_namespace="$(pressure_result_bounded_uint \
    "$fill_output" process_namespace "$MAX_UINT32_DECIMAL" false)" || \
    fill_process_namespace=""
  fill_token_base="$(pressure_result_bounded_uint \
    "$fill_output" token_base "$MAX_UINT64_DECIMAL" false)" || fill_token_base=""
  fill_touched="$(pressure_result_bounded_uint \
    "$fill_output" touched "$((PRESSURE_MAX_ENTRIES + 1))" false)" || fill_touched=""
  fill_evicted="$(pressure_result_bounded_uint \
    "$fill_output" evicted_entries "$((PRESSURE_MAX_ENTRIES + 1))" false)" || \
    fill_evicted=""
  synthetic_entry_count="$((PRESSURE_MAP_MAX_ENTRIES + 1))"
  if [[ "$fill_map_id" != "$PRESSURE_MAP_ID" || \
    "$fill_max_entries" != "$PRESSURE_MAP_MAX_ENTRIES" || \
    "$fill_process_map_id" != "$PRESSURE_PROCESS_MAP_ID" || \
    "$fill_process_pid" != "$PRESSURE_PROCESS_PID" || \
    "$fill_process_namespace" != "$PRESSURE_PROCESS_NAMESPACE" || \
    "$fill_token_base" != "$PRESSURE_TOKEN_BASE" || \
    "$fill_touched" != "$synthetic_entry_count" || \
    -z "$fill_evicted" ]] || ((fill_evicted >= fill_touched)); then
    log_error "map-pressure fill did not echo its prepared identity or prove order-independent eviction"
    cleanup_map_pressure_with_retries || true
    return 1
  fi
  PRESSURE_TOUCHED_ENTRIES="$fill_touched"
  PRESSURE_EVICTED_ENTRIES="$fill_evicted"
  log_info "map pressure armed map_id=$PRESSURE_MAP_ID baseline=$PRESSURE_MAP_BASELINE_ENTRIES max_entries=$PRESSURE_MAP_MAX_ENTRIES touched=$PRESSURE_TOUCHED_ENTRIES evicted=$PRESSURE_EVICTED_ENTRIES"

  if wait_for_pressure_map_state \
    pressured \
    "$RESULT_DIR/map-pressure-$label-pressured.prom" \
    "$PRESSURE_STATE_TIMEOUT_SECONDS" \
    1; then
    start_status=0
  else
    start_status=$?
    cleanup_map_pressure_with_retries || true
    return "$start_status"
  fi
  if start_map_pressure_monitor; then
    return 0
  else
    start_status=$?
  fi
  cleanup_map_pressure_with_retries || true
  return "$start_status"
}

cleanup_map_pressure_with_retries() {
  local cleanup_status=1

  [[ "$PRESSURE_ACTIVE" == "true" ]] || return 0
  while [[ "$PRESSURE_ACTIVE" == "true" ]] && \
    ((PRESSURE_CLEANUP_ATTEMPT < PRESSURE_CLEANUP_MAX_ATTEMPTS)); do
    if cleanup_map_pressure; then
      return 0
    else
      cleanup_status=$?
    fi
    if [[ "$PRESSURE_ACTIVE" != "true" ]] || \
      ((PRESSURE_CLEANUP_DEADLINE > 0 && SECONDS >= PRESSURE_CLEANUP_DEADLINE)); then
      break
    fi
  done
  return "$cleanup_status"
}

cleanup_map_pressure() {
  local cleanup_output=""
  local cleanup_stderr=""
  local cleanup_status_output=""
  local cleanup_prefix=""
  local cleanup_tag=""
  local canonical_cleanup_output=""
  local canonical_cleanup_stderr=""
  local cleanup_map_id=""
  local cleanup_max_entries=""
  local cleanup_process_map_id=""
  local cleanup_process_pid=""
  local cleanup_process_namespace=""
  local cleanup_token_base=""
  local cleanup_touched=""
  local cleanup_verified=""
  local verified_absent=""
  local helper_timeout=""
  local recovery_timeout=""
  local attempt_recovery_output=""
  local canonical_recovery_output=""
  local recovery_sample_source=""
  local recovery_sample_output=""
  local recovery_samples_log=""
  local canonical_samples_log=""
  local -a published_recovery=()
  local monitor_status=0
  local command_status=0
  local cleanup_status=0
  local validation_status="not-run"
  local recovery_status="not-run"
  local -i synthetic_entry_count=0
  local -i recovery_index=0

  [[ "$PRESSURE_ACTIVE" == "true" ]] || return 0
  if [[ -n "$PRESSURE_MONITOR_PID" ]]; then
    if stop_map_pressure_monitor; then
      :
    else
      monitor_status=$?
      if ((PRESSURE_MONITOR_STATUS == 0)); then
        PRESSURE_MONITOR_STATUS="$monitor_status"
      fi
    fi
  fi
  if ((PRESSURE_CLEANUP_DEADLINE == 0)); then
    PRESSURE_CLEANUP_DEADLINE="$((SECONDS + PRESSURE_CLEANUP_DEADLINE_SECONDS))"
  fi
  if ((PRESSURE_CLEANUP_ATTEMPT >= PRESSURE_CLEANUP_MAX_ATTEMPTS)); then
    log_error "map-pressure cleanup exhausted its bounded attempt count"
    return 1
  fi
  helper_timeout="$(remaining_timeout_seconds \
    "$PRESSURE_CLEANUP_DEADLINE" \
    "$PRESSURE_HELPER_TIMEOUT_SECONDS")" || {
    log_error "map-pressure cleanup exceeded its bounded deadline"
    return 1
  }
  ((PRESSURE_CLEANUP_ATTEMPT += 1))
  printf -v cleanup_tag '%02d' "$PRESSURE_CLEANUP_ATTEMPT"
  cleanup_prefix="$RESULT_DIR/map-pressure-${PRESSURE_LABEL:-exit}-cleanup-attempt-$cleanup_tag"
  cleanup_output="$cleanup_prefix.json"
  cleanup_stderr="$cleanup_prefix.stderr.log"
  cleanup_status_output="$cleanup_prefix.status"

  if run_map_pressure_helper \
    "$cleanup_output" \
    "$cleanup_stderr" \
    "$helper_timeout" \
    --map-id "$PRESSURE_MAP_ID" \
    --expected-max-entries "$PRESSURE_MAP_MAX_ENTRIES" \
    --process-pid "$PRESSURE_PROCESS_PID" \
    --process-namespace "$PRESSURE_PROCESS_NAMESPACE" \
    --token-base "$PRESSURE_TOKEN_BASE" \
    --seed "$PRESSURE_SEED" \
    --mode cleanup; then
    command_status=0
  else
    command_status=$?
  fi
  if ((command_status != 0)); then
    record_pressure_cleanup_status \
      "$cleanup_status_output" "$command_status" "$validation_status" "$recovery_status" || true
    return "$command_status"
  fi
  if ! pressure_result_has_contract "$cleanup_output" cleanup; then
    validation_status=failed
  else
    cleanup_map_id="$(pressure_result_bounded_uint \
      "$cleanup_output" map_id "$MAX_UINT32_DECIMAL" false)" || cleanup_map_id=""
    cleanup_max_entries="$(pressure_result_bounded_uint \
      "$cleanup_output" max_entries "$PRESSURE_MAX_ENTRIES" false)" || \
      cleanup_max_entries=""
    cleanup_process_map_id="$(pressure_result_bounded_uint \
      "$cleanup_output" process_map_id "$MAX_UINT32_DECIMAL" true)" || \
      cleanup_process_map_id=""
    cleanup_process_pid="$(pressure_result_bounded_uint \
      "$cleanup_output" process_pid "$MAX_UINT32_DECIMAL" false)" || \
      cleanup_process_pid=""
    cleanup_process_namespace="$(pressure_result_bounded_uint \
      "$cleanup_output" process_namespace "$MAX_UINT32_DECIMAL" false)" || \
      cleanup_process_namespace=""
    cleanup_token_base="$(pressure_result_bounded_uint \
      "$cleanup_output" token_base "$MAX_UINT64_DECIMAL" false)" || \
      cleanup_token_base=""
    cleanup_touched="$(pressure_result_bounded_uint \
      "$cleanup_output" touched "$((PRESSURE_MAX_ENTRIES + 1))" true)" || \
      cleanup_touched=""
    cleanup_verified="$(pressure_result_bool \
      "$cleanup_output" cleanup_verified)" || cleanup_verified=""
    verified_absent="$(pressure_result_bounded_uint \
      "$cleanup_output" verified_absent_entries "$((PRESSURE_MAX_ENTRIES + 1))" false)" || \
      verified_absent=""
    synthetic_entry_count="$((PRESSURE_MAP_MAX_ENTRIES + 1))"
    if [[ "$cleanup_map_id" == "$PRESSURE_MAP_ID" && \
      "$cleanup_max_entries" == "$PRESSURE_MAP_MAX_ENTRIES" && \
      "$cleanup_process_map_id" == "0" && \
      "$cleanup_process_pid" == "$PRESSURE_PROCESS_PID" && \
      "$cleanup_process_namespace" == "$PRESSURE_PROCESS_NAMESPACE" && \
      "$cleanup_token_base" == "$PRESSURE_TOKEN_BASE" && \
      -n "$cleanup_touched" && \
      "$cleanup_verified" == "true" && \
      "$verified_absent" == "$synthetic_entry_count" ]] && \
      ((cleanup_touched <= synthetic_entry_count)); then
      validation_status=passed
    else
      validation_status=failed
    fi
  fi
  if [[ "$validation_status" != "passed" ]]; then
    log_error "map-pressure cleanup did not echo its prepared identity and verify every synthetic key absent"
    record_pressure_cleanup_status \
      "$cleanup_status_output" "$command_status" "$validation_status" "$recovery_status" || true
    return 1
  fi
  canonical_cleanup_output="$RESULT_DIR/map-pressure-${PRESSURE_LABEL:-exit}-cleanup.json"
  canonical_cleanup_stderr="$RESULT_DIR/map-pressure-${PRESSURE_LABEL:-exit}-cleanup.stderr.log"
  recovery_timeout="$(remaining_timeout_seconds \
    "$PRESSURE_CLEANUP_DEADLINE" \
    "$PRESSURE_RECOVERY_TIMEOUT_SECONDS")" || {
    record_pressure_cleanup_status \
      "$cleanup_status_output" "$command_status" "$validation_status" failed || true
    return 1
  }
  attempt_recovery_output="$cleanup_prefix-recovered.prom"
  if wait_for_pressure_map_state \
    recovered \
    "$attempt_recovery_output" \
    "$recovery_timeout" \
    "$PRESSURE_RECOVERY_CONSECUTIVE_SAMPLES" \
    "$((recovery_timeout + 1))"; then
    recovery_status=passed
  else
    cleanup_status=$?
    recovery_status=failed
  fi
  if [[ "$recovery_status" == "passed" ]]; then
    canonical_recovery_output="$RESULT_DIR/map-pressure-${PRESSURE_LABEL:-exit}-recovered.prom"
    for ((recovery_index = 1; \
      recovery_index <= PRESSURE_RECOVERY_CONSECUTIVE_SAMPLES; \
      recovery_index++)); do
      printf -v recovery_sample_source \
        '%s-sample-%02d.prom' "${attempt_recovery_output%.prom}" "$recovery_index"
      printf -v recovery_sample_output \
        '%s-sample-%02d.prom' "${canonical_recovery_output%.prom}" "$recovery_index"
      published_recovery+=("$recovery_sample_output")
      if ! install -m 0644 "$recovery_sample_source" "$recovery_sample_output"; then
        recovery_status=failed
        cleanup_status=1
        break
      fi
    done
    recovery_samples_log="${attempt_recovery_output%.prom}-samples.log"
    canonical_samples_log="${canonical_recovery_output%.prom}-samples.log"
    if [[ "$recovery_status" == "passed" ]] && \
      ! install -m 0644 "$attempt_recovery_output" "$canonical_recovery_output"; then
      recovery_status=failed
      cleanup_status=1
    fi
    if [[ "$recovery_status" == "passed" ]] && \
      ! install -m 0644 "$recovery_samples_log" "$canonical_samples_log"; then
      recovery_status=failed
      cleanup_status=1
    fi
    if [[ "$recovery_status" == "passed" ]] && \
      { ! install -m 0644 "$cleanup_output" "$canonical_cleanup_output" || \
        ! install -m 0644 "$cleanup_stderr" "$canonical_cleanup_stderr"; }; then
      validation_status=failed
      cleanup_status=1
    fi
    if [[ "$recovery_status" != "passed" || "$validation_status" != "passed" ]]; then
      rm -f -- \
        "$canonical_cleanup_output" \
        "$canonical_cleanup_stderr" \
        "$canonical_recovery_output" \
        "$canonical_samples_log" \
        "${published_recovery[@]}"
    fi
  fi
  if ((cleanup_status != 0)); then
    record_pressure_cleanup_status \
      "$cleanup_status_output" "$command_status" "$validation_status" "$recovery_status" || true
    return "$cleanup_status"
  fi
  PRESSURE_ACTIVE=false
  record_pressure_cleanup_status \
    "$cleanup_status_output" "$command_status" "$validation_status" "$recovery_status" || return 1
  if ((PRESSURE_MONITOR_STATUS != 0)); then
    return "$PRESSURE_MONITOR_STATUS"
  fi
}

run_scenario() {
  local -r name="$1"
  local -r diagnostics_enabled="${2:-true}"
  local -r phase_evidence="${3:-full}"
  local -r fixture_mode="${4:-none}"
  local run_number=0
  local label=""
  local output=""
  local stderr_output=""
  local before_phase=""
  local after_phase=""
  local before_stage=0
  local before_success=0
  local expected_stage=0
  local expected_success=0
  local expected_requests=0
  local expected_sampled=0
  local expected_unsampled=0
  local expected_standard=0
  local expected_valid=0
  local expected_stale=0
  local expected_malformed=0
  local baseline_bridge_missing=0
  local baseline_java_missing=0
  local expected_bridge_valid=0
  local expected_bridge_missing=0
  local expected_java_missing=0
  local pressure_hits=0
  local pressure_roots=0
  local pressure_wrong=0
  local pressure_unresolved=0
  local pressure_trace_json="null"
  local pressure_bridge_json="null"
  local pressure_java_json="null"
  local pressure_status_json="null"
  local expected_fault_status=""
  local expected_fault_count=0
  local bridge_was_running=false
  local controlled_bridge_was_running=false
  local fixture_status=0
  local scenario_status=0
  local metric_status=0
  local status_name="passed"
  local -a request_arguments=()

  [[ "$diagnostics_enabled" == "true" || "$diagnostics_enabled" == "false" ]] || {
    log_error "scenario diagnostics mode must be true or false"
    return 1
  }
  [[ "$phase_evidence" == "full" || "$phase_evidence" == "metrics" ]] || {
    log_error "scenario phase evidence must be full or metrics"
    return 1
  }
  [[ "$fixture_mode" == "none" || "$fixture_mode" == "matching" ]] || {
    log_error "scenario fixture mode must be none or matching"
    return 1
  }
  if [[ "$fixture_mode" == "matching" && \
    ( "$name" != "w3c-match" || "$diagnostics_enabled" != "true" ) ]]; then
    log_error "the matching fixture requires the diagnostic w3c-match scenario"
    return 1
  fi
  baseline_bridge_missing="$(scenario_bridge_missing_count "$name" "$SELECTED_TRANSPORT")"
  baseline_java_missing="$(scenario_java_missing_count "$name" "$diagnostics_enabled")"
  expected_requests="$(scenario_bridge_take_count "$name")"
  if [[ "$name" == "w3c-fault" ]]; then
    request_arguments=(--requests "$FAULT_REQUEST_COUNT")
  elif [[ "$name" == "tls-boundary" ]]; then
    request_arguments=(--requests 2)
  elif (( REQUEST_COUNT > 0 )); then
    request_arguments=(--requests "$REQUEST_COUNT")
  fi
  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    controlled_bridge_was_running=false
    scenario_status=0
    metric_status=0
    status_name="passed"
    expected_bridge_valid="$expected_requests"
    expected_bridge_missing="$baseline_bridge_missing"
    expected_java_missing="$baseline_java_missing"
    pressure_hits=0
    pressure_roots=0
    pressure_wrong=0
    pressure_unresolved=0
    pressure_trace_json="null"
    pressure_bridge_json="null"
    pressure_java_json="null"
    pressure_status_json="null"
    label="$name"
    if [[ "$name" == "w3c-fault" ]]; then
      label="$name-$FAULT_MODE"
    fi
    if [[ -n "$SCENARIO_VARIANT" ]]; then
      label="$label-$SCENARIO_VARIANT"
    fi
    if (( REPEAT_COUNT > 1 )); then
      printf -v label '%s-run-%02d' "$label" "$run_number"
    fi
    output="$RESULT_DIR/scenario-$label.json"
    stderr_output="$RESULT_DIR/scenario-$label.stderr.log"
    before_phase="$label-before"
    after_phase="$label-after"

    log_info "running $label scenario"
    if [[ "$fixture_mode" == "matching" ]]; then
      if start_matching_bridge "$label" "$expected_requests"; then
        controlled_bridge_was_running=true
      else
        fixture_status=$?
        scenario_status="$fixture_status"
      fi
    fi
    if ! flush_bridge_metric_boundary "$label"; then
      metric_status=1
    fi
    if [[ "$name" != "w3c-fault" && "$diagnostics_enabled" == "true" ]]; then
      capture_java_diagnostics "$before_phase"
      if [[ "$BRIDGE_RUNNING" == "true" ]] &&
        ! wait_for_bridge_metrics_quiescent \
          0 \
          0 \
          "$RESULT_DIR/metrics-diagnostics-$label.prom" \
          "$label pre-scenario diagnostics quiescence"; then
        metric_status=1
      fi
    fi
    if [[ "$phase_evidence" == "metrics" ]]; then
      if ! capture_metric_phase_evidence "$before_phase"; then
        metric_status=1
      fi
    else
      capture_phase_evidence "$before_phase"
    fi
    bridge_was_running="$BRIDGE_RUNNING"
    if [[ "$bridge_was_running" == "true" ]]; then
      before_success="$(bridge_success_total \
        "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")"
      before_stage="$(bridge_stage_total \
        "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")"
    fi
    if [[ "$name" == "pressure" ]]; then
      if start_map_pressure \
        "$label" \
        "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
        "$expected_requests"; then
        capture_phase_evidence "$label-pressured"
      else
        scenario_status=$?
      fi
    fi
    if ((scenario_status == 0)); then
      if run_bounded "$SCENARIO_RUN_TIMEOUT_SECONDS" \
        "${COMPOSE[@]}" run --rm --no-deps --no-TTY scenario \
          --scenario "$name" \
          --expected-tls "$TLS_PROTOCOL" \
          --seed "$SCENARIO_SEED" \
          "${request_arguments[@]}" \
          --timeout 75s 2> >(tee "$stderr_output" >&2) | tee "$output"; then
        scenario_status=0
      else
        scenario_status=$?
      fi
    fi
    if [[ "$name" == "pressure" ]]; then
      if [[ -s "$output" && -f "$output" && ! -L "$output" ]]; then
        pressure_hits="$(pressure_scenario_count \
          "$output" exact_hit_count "$expected_requests")" || pressure_hits=""
        pressure_roots="$(pressure_scenario_count \
          "$output" explicit_root_count "$expected_requests")" || pressure_roots=""
        pressure_wrong="$(pressure_scenario_count \
          "$output" wrong_parent_count "$expected_requests")" || pressure_wrong=""
        pressure_unresolved="$(pressure_scenario_count \
          "$output" unresolved_count "$expected_requests")" || \
          pressure_unresolved=""
      else
        pressure_hits=""
        pressure_roots=""
        pressure_wrong=""
        pressure_unresolved=""
      fi
      if [[ -n "$pressure_hits" && -n "$pressure_roots" && \
        -n "$pressure_wrong" && -n "$pressure_unresolved" ]]; then
        printf -v pressure_trace_json \
          '{"exact_hit_count":%d,"explicit_root_count":%d,"wrong_parent_count":%d,"unresolved_count":%d}' \
          "$pressure_hits" \
          "$pressure_roots" \
          "$pressure_wrong" \
          "$pressure_unresolved"
        printf -v pressure_java_json \
          '{"take_valid_count":%d,"attributable_absence_count":%d,"diagnostic_self_miss_count":%d}' \
          "$((pressure_hits + pressure_wrong))" \
          "$pressure_roots" \
          "$baseline_java_missing"
      fi
      if [[ -z "$pressure_hits" || -z "$pressure_roots" || \
        -z "$pressure_wrong" || -z "$pressure_unresolved" ]] || \
        ((pressure_hits + pressure_roots + pressure_wrong +
          pressure_unresolved != expected_requests)); then
        log_error "pressure scenario did not report complete bounded parent outcomes"
        expected_bridge_valid=0
        expected_bridge_missing="$baseline_bridge_missing"
        expected_java_missing="$baseline_java_missing"
        if ((scenario_status == 0)); then
          scenario_status=1
        fi
      else
        expected_bridge_valid="$((pressure_hits + pressure_wrong))"
        expected_bridge_missing="$baseline_bridge_missing"
        expected_java_missing="$((baseline_java_missing + pressure_roots))"
        if ((scenario_status == 0 &&
          (pressure_wrong != 0 || pressure_unresolved != 0 ||
          pressure_hits + pressure_roots != expected_requests))); then
          log_error "pressure scenario reported a wrong or unresolved parent"
          scenario_status=1
        fi
      fi
    fi
    if [[ "$name" == "pressure" && "$PRESSURE_ACTIVE" == "true" ]]; then
      if ! cleanup_map_pressure_with_retries; then
        metric_status=1
      fi
    fi
    if [[ "$bridge_was_running" == "true" ]]; then
      expected_success="$((before_success + expected_bridge_valid))"
      expected_stage="$((before_stage + expected_bridge_valid))"
      if ! wait_for_bridge_metrics_quiescent \
        "$expected_success" \
        "$expected_stage" \
        "$RESULT_DIR/metrics-after-$label.prom" \
        "$label scenario-attributable bridge operations"; then
        metric_status=1
      fi
    fi
    if [[ "$phase_evidence" == "metrics" ]]; then
      if ! capture_metric_phase_evidence "$after_phase"; then
        metric_status=1
      fi
    else
      capture_phase_evidence "$after_phase"
    fi
    if [[ "$name" != "w3c-fault" && "$diagnostics_enabled" == "true" ]]; then
      capture_java_diagnostics "$after_phase"
    fi
    write_metrics_delta \
      "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
      "$RESULT_DIR/phases/$after_phase/obi-metrics.prom" \
      "$RESULT_DIR/phases/$after_phase/obi-metrics.delta"
    if [[ "$bridge_was_running" == "true" ]]; then
      if [[ "$name" == "pressure" && -n "$pressure_hits" &&
        -n "$pressure_roots" && -n "$pressure_wrong" && -n "$pressure_unresolved" ]]; then
        pressure_bridge_json="$(pressure_bridge_reconciliation \
          "$RESULT_DIR/phases/$after_phase/obi-metrics.delta" \
          "$SELECTED_TRANSPORT" \
          "$expected_bridge_valid" \
          "$pressure_roots" \
          "$expected_requests")" || {
          pressure_bridge_json="null"
          metric_status=1
        }
      elif ! assert_bridge_metric_delta \
        "$RESULT_DIR/phases/$after_phase/obi-metrics.delta" \
        "$SELECTED_TRANSPORT" \
        "$expected_bridge_valid" \
        0 \
        "$expected_bridge_missing"; then
        metric_status=1
      fi
    fi
    if [[ "$diagnostics_enabled" == "true" && \
      ( "$bridge_was_running" == "true" || "$controlled_bridge_was_running" == "true" ) ]]; then
      if ! write_java_diagnostics_delta \
        "$RESULT_DIR/phases/$before_phase/java-diagnostics.txt" \
        "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" \
        "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"; then
        log_error "could not parse Java diagnostics for $label"
        metric_status=1
      else
        expected_sampled="$expected_bridge_valid"
        expected_unsampled=0
        expected_standard=0
        expected_valid="$expected_bridge_valid"
        expected_stale=0
        expected_malformed=0
        expected_fault_status=""
        expected_fault_count=0
        case "$name" in
          w3c)
            expected_standard="$(((expected_requests + 1) / 2))"
            ;;
          w3c-match)
            expected_standard="$expected_requests"
            ;;
          obi-flags)
            expected_sampled="$((expected_requests / 2))"
            expected_unsampled="$(((expected_requests + 1) / 2))"
            ;;
        esac
        if ! assert_java_diagnostics_delta \
          "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" \
          "$expected_valid" \
          "$expected_stale" \
          "$expected_malformed" \
          "$expected_java_missing" \
          "$expected_sampled" \
          "$expected_unsampled" \
          "$expected_standard" \
          "$expected_fault_status" \
          "$expected_fault_count"; then
          metric_status=1
        fi
      fi
    fi
    if [[ "$controlled_bridge_was_running" == "true" ]] && \
      ! stop_matching_bridge "$label" "$expected_requests"; then
      metric_status=1
    fi
    if ((scenario_status != 0 || metric_status != 0)); then
      status_name="failed"
    fi
    if [[ "$name" == "pressure" && "$pressure_trace_json" != "null" ]]; then
      printf -v pressure_status_json \
        '{"trace":%s,"bridge":%s,"java_reconciliation_target":%s}' \
        "$pressure_trace_json" \
        "$pressure_bridge_json" \
        "$pressure_java_json"
    fi
    printf '{\n  "status": "%s",\n  "scenario": "%s",\n  "exit_status": %d,\n  "metric_status": %d,\n  "pressure_correlation": %s,\n  "result": "%s",\n  "stderr": "%s",\n  "after_phase": "%s"\n}\n' \
      "$status_name" \
      "$name" \
      "$scenario_status" \
      "$metric_status" \
      "$pressure_status_json" \
      "$(basename -- "$output")" \
      "$(basename -- "$stderr_output")" \
      "phases/$after_phase" >"$RESULT_DIR/scenario-$label-status.json"
    log_info "$label status=$status_name evidence=$RESULT_DIR/scenario-$label-status.json"
    if ((scenario_status != 0)); then
      return "$scenario_status"
    fi
    if ((metric_status != 0)); then
      return "$metric_status"
    fi
    if [[ "$name" == "w3c-fault" ]] && ((run_number < REPEAT_COUNT)); then
      sleep 1
    fi
  done
}

stop_obi_for_no_state_control() {
  local -r label="$1"

  flush_bridge_metric_boundary "$label"
  capture_phase_evidence "$label-obi-running"
  log_info "stopping OBI for the $label control"
  run_bounded 60 "${COMPOSE[@]}" stop --timeout 10 obi
  BRIDGE_RUNNING=false
}

run_fail_open_control() {
  stop_obi_for_no_state_control "fail-open"
  run_scenario fail-open
}

run_w3c_only_control() {
  stop_obi_for_no_state_control "w3c-only"
  run_scenario w3c-only
}

run_late_attach_control() {
  local attach_since=""
  local apache_since=""

  stop_obi_for_no_state_control "late-attach"
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  log_info "recreating the JVM while OBI is absent"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate java-backend apache-proxy
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "OBI-absent HTTPS path"
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "OBI-absent external extension"
  assert_runtime_contract obi-absent

  SCENARIO_VARIANT="obi-absent"
  run_scenario fail-open
  run_scenario w3c-only
  SCENARIO_VARIANT=""

  attach_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  log_info "starting OBI and requiring late helper attach without a JVM restart"
  run_bounded 120 "${COMPOSE[@]}" up --detach obi
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "late-attach OBI remote-parent bridge" \
    "$attach_since"
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "late-attached Java helper" \
    "$attach_since"
  wait_for_log \
    java-backend \
    "OBI Java instrumentation ready" \
    "late-attached Java instrumentation" \
    "$attach_since"
  BRIDGE_RUNNING=true
  assert_selected_transport
  log_info "recycling Apache connections created before late attach"
  run_bounded 60 "${COMPOSE[@]}" stop --timeout 10 apache-proxy
  wait_for_apache_instrumentation_drain late-attach
  apache_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate --no-deps apache-proxy
  wait_for_log \
    obi \
    "cmd=/usr/local/apache2/bin/httpd" \
    "late-attach Apache instrumentation" \
    "$apache_since"
  wait_for_apache_instrumentation late-attach
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "late-attach recovered HTTPS path"
  SCENARIO_VARIANT="late-attach-recovery"
  run_scenario restart
  SCENARIO_VARIANT=""
}

prepare_restart_control_directory() {
  local -r directory="$1"

  if [[ -e "$directory" || -L "$directory" ]]; then
    log_error "restart control path already exists: $directory"
    return 1
  fi
  if ! mkdir -- "$directory"; then
    log_error "could not create restart control directory: $directory"
    return 1
  fi
  [[ -d "$directory" && ! -L "$directory" ]] || {
    log_error "restart control path is not a real directory: $directory"
    return 1
  }
}

record_restart_control_event() {
  local -r directory="$1"
  local -r event="$2"
  local -r events="$directory/events.log"

  if [[ -L "$events" || ( -e "$events" && ! -f "$events" ) ]]; then
    log_error "restart control event target is not a regular file: $events"
    return 1
  fi
  printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" "$event" >>"$events"
}

publish_restart_control_release() {
  local -r directory="$1"
  local -r name="$2"
  local -r target="$directory/$name"
  local temporary=""

  [[ "$name" =~ ^[a-z][a-z-]{0,63}$ ]] || {
    log_error "invalid restart control release name: $name"
    return 1
  }
  [[ -d "$directory" && ! -L "$directory" ]] || {
    log_error "restart control directory changed before release: $directory"
    return 1
  }
  if [[ -e "$target" || -L "$target" ]]; then
    log_error "restart control release already exists: $target"
    return 1
  fi
  temporary="$(mktemp "$directory/.$name.XXXXXX")" || return $?
  if ! printf '%s\n' "$name" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! chmod 0644 -- "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! ln -- "$temporary" "$target"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! rm -f -- "$temporary"; then
    log_error "could not remove temporary restart release: $temporary"
    return 1
  fi
  record_restart_control_event "$directory" "released:$name"
}

wait_for_restart_control_signal() {
  local -r directory="$1"
  local -r name="$2"
  local -r description="$3"
  local -r scenario_pid="$4"
  local -r path="$directory/$name"
  local -i started_at="$SECONDS"

  [[ "$name" =~ ^[a-z][a-z-]{0,63}$ ]] || {
    log_error "invalid restart control signal name: $name"
    return 1
  }
  while ((SECONDS - started_at < READINESS_TIMEOUT_SECONDS)); do
    if [[ -e "$path" || -L "$path" ]]; then
      if [[ -L "$path" || ! -f "$path" ]]; then
        log_error "restart control signal is not a regular file: $path"
        return 1
      fi
      if ! cmp -s -- "$path" <(printf '%s\n' "$name"); then
        log_error "restart control signal has invalid contents: $path"
        return 1
      fi
      record_restart_control_event "$directory" "observed:$name" || return $?
      log_info "$description is complete"
      return 0
    fi
    if ! kill -0 "$scenario_pid" 2>/dev/null; then
      log_error "$description traffic ended before publishing $name"
      return 1
    fi
    sleep 0.1
  done
  log_error "timed out waiting for $description signal: $name"
  return 1
}

run_restart_during_traffic_control() (
  local -r label="restart-fault"
  local -r output="$RESULT_DIR/scenario-$label.json"
  local -r stderr_output="$RESULT_DIR/scenario-$label.stderr.log"
  local -r before_phase="$label-before"
  local -r after_phase="$label-after"
  local -r control_dir="$RESULT_DIR/restart-control"
  local restart_since=""
  local scenario_pid=""
  local scenario_status=0

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  cleanup_restart_traffic() {
    local -r status="$?"
    trap - EXIT
    if [[ -n "$scenario_pid" ]]; then
      if kill -0 "$scenario_pid" 2>/dev/null; then
        kill -TERM "$scenario_pid" 2>/dev/null || true
      fi
      wait "$scenario_pid" 2>/dev/null || true
      scenario_pid=""
    fi
    exit "$status"
  }

  trap cleanup_restart_traffic EXIT

  [[ "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "restart-during-traffic control requires a running bridge"
    return 1
  }
  prepare_restart_control_directory "$control_dir" || return $?
  log_info "running valid-W3C traffic while OBI restarts"
  capture_phase_evidence "$before_phase"
  capture_java_diagnostics "$before_phase"
  timeout --signal=TERM --kill-after=10s 180s \
    "${COMPOSE[@]}" run --rm --no-deps --no-TTY \
      --volume "$control_dir:$RESTART_CONTROL_CONTAINER_DIR:rw" \
      scenario \
      --scenario restart-fault \
      --requests 32 \
      --expected-tls "$TLS_PROTOCOL" \
      --seed "$SCENARIO_SEED" \
      --restart-control-dir "$RESTART_CONTROL_CONTAINER_DIR" \
      --timeout 120s \
      </dev/null \
      >"$output" \
      2> >(tee "$stderr_output" >&2) &
  scenario_pid=$!
  wait_for_restart_control_signal \
    "$control_dir" \
    "$RESTART_SIGNAL_PRE_STOP_READY" \
    "pre-stop restart traffic" \
    "$scenario_pid" || return $?

  restart_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  run_bounded 60 "${COMPOSE[@]}" stop --timeout 5 obi || return $?
  BRIDGE_RUNNING=false
  publish_restart_control_release \
    "$control_dir" \
    "$RESTART_RELEASE_OBI_STOPPED" || return $?
  wait_for_restart_control_signal \
    "$control_dir" \
    "$RESTART_SIGNAL_STOPPED_TRAFFIC_COMPLETE" \
    "traffic while OBI was stopped" \
    "$scenario_pid" || return $?
  run_bounded 120 "${COMPOSE[@]}" up --detach obi || return $?
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "OBI bridge restarted during traffic" \
    "$restart_since" || return $?
  BRIDGE_RUNNING=true
  assert_selected_transport || return $?
  wait_for_apache_instrumentation restart-fault-recovery || return $?
  publish_restart_control_release \
    "$control_dir" \
    "$RESTART_RELEASE_OBI_READY" || return $?
  wait_for_restart_control_signal \
    "$control_dir" \
    "$RESTART_SIGNAL_POST_RESTART_TRAFFIC_COMPLETE" \
    "traffic after OBI recovery" \
    "$scenario_pid" || return $?
  if wait "$scenario_pid"; then
    scenario_status=0
  else
    scenario_status=$?
  fi
  scenario_pid=""
  if ((scenario_status != 0)); then
    log_error "restart fault traffic failed, status=$scenario_status"
    return "$scenario_status"
  fi
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "Java bridge recovered during restart traffic" \
    "$restart_since" || return $?
  capture_phase_evidence "$after_phase"
  capture_java_diagnostics "$after_phase"
  write_java_diagnostics_delta \
    "$RESULT_DIR/phases/$before_phase/java-diagnostics.txt" \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"
  assert_restart_fault_diagnostics \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" \
    32 \
    "$RESULT_DIR/restart-fault-diagnostics.txt"
  printf '{"status":"passed","scenario":"restart-fault","result":"%s","after_phase":"phases/%s","restart_control":"restart-control/events.log"}\n' \
    "$(basename -- "$output")" \
    "$after_phase" >"$RESULT_DIR/scenario-$label-status.json"

  SCENARIO_VARIANT="restart-recovery"
  run_scenario restart
  SCENARIO_VARIANT=""
)

run_extension_controls() {
  stop_obi_for_no_state_control "extension-controls"
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"

  log_info "recreating the backend with the external extension absent"
  export EXTENSION_ENABLED=false
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE=""
  export OTEL_PROPAGATORS_VALUE="tracecontext,baggage"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate java-backend apache-proxy
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "extension-absent HTTPS path"
  assert_runtime_contract extension-absent
  SCENARIO_VARIANT="extension-absent"
  run_scenario w3c-only

  log_info "recreating the backend with the external extension disabled"
  export EXTENSION_ENABLED=false
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate java-backend apache-proxy
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "extension-disabled HTTPS path"
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator disabled by compatibility gate" \
    "disabled external extension"
  assert_runtime_contract extension-disabled
  SCENARIO_VARIANT="extension-disabled"
  run_scenario w3c-only
  SCENARIO_VARIANT=""
}

recreate_instrumented_stack() {
  local -r propagation="$1"
  local -r label="$2"
  local -r transport="${3:-$TRANSPORT}"
  local recreate_since=""

  CONTEXT_PROPAGATION="$propagation"
  export CONTEXT_PROPAGATION
  BRIDGE_TRANSPORT="$transport"
  export BRIDGE_TRANSPORT
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  recreate_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  log_info "recreating the instrumented stack for $label propagation=$propagation"
  run_bounded 180 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy obi
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "$label OBI remote-parent bridge" \
    "$recreate_since"
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "$label injected Java helper" \
    "$recreate_since"
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "$label external OTel extension" \
    "$recreate_since"
  wait_for_log \
    java-backend \
    "OBI Java instrumentation ready" \
    "$label injected Java instrumentation" \
    "$recreate_since"
  BRIDGE_RUNNING=true
  assert_selected_transport "$transport"
  wait_for_apache_instrumentation recreate-instrumented
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "$label HTTPS path"
}

reset_matching_bridge_environment() {
  FAULT_MODE="alternating"
  MATCHING_VALID_TAKES=1
  export FAULT_MODE MATCHING_VALID_TAKES
}

matching_bridge_sequence_is_exact() {
  local -r input="$1"
  local -r expected_valid="$2"

  awk -v expected_valid="$expected_valid" '
    /operation=take status=/ {
      count++
      status = count == 1 || count == expected_valid + 2 ? "missing" : "valid"
      pattern = "operation=take status=" status " take_count=" count "([^0-9]|$)"
      if ($0 !~ pattern) {
        invalid = 1
      }
    }
    END {
      exit invalid || count != expected_valid + 2 ? 1 : 0
    }
  ' "$input"
}

start_matching_bridge() {
  local -r label="$1"
  local -r expected_valid="$2"
  local start_status=0

  [[ "$BRIDGE_RUNNING" == "false" ]] || {
    log_error "refusing to start the controlled matching bridge while OBI is running"
    return 1
  }
  bounded_decimal "$expected_valid" 1000 false >/dev/null || {
    log_error "matching bridge valid-take count is invalid: $expected_valid"
    return 1
  }
  FAULT_MODE="matching"
  MATCHING_VALID_TAKES="$expected_valid"
  export FAULT_MODE MATCHING_VALID_TAKES
  log_info "starting controlled matching bridge for $label valid_takes=$expected_valid"
  MATCHING_BRIDGE_RUNNING=true
  if run_bounded 60 \
    "${COMPOSE[@]}" up --detach --no-deps --force-recreate bridge-fault; then
    :
  else
    start_status=$?
    if run_bounded 30 "${COMPOSE[@]}" stop --timeout 5 bridge-fault; then
      MATCHING_BRIDGE_RUNNING=false
    fi
    reset_matching_bridge_environment
    return "$start_status"
  fi
  if wait_for_log \
    bridge-fault \
    "mode=matching matching_valid_takes=$expected_valid" \
    "$label controlled matching bridge"; then
    :
  else
    start_status=$?
    if run_bounded 30 "${COMPOSE[@]}" stop --timeout 5 bridge-fault; then
      MATCHING_BRIDGE_RUNNING=false
    fi
    reset_matching_bridge_environment
    return "$start_status"
  fi
}

stop_matching_bridge() {
  local -r label="$1"
  local -r expected_valid="$2"
  local -r fixture_log="$RESULT_DIR/$label-matching-bridge.log"
  local status=0

  if ! run_bounded 15 \
    "${COMPOSE[@]}" logs --no-color bridge-fault >"$fixture_log"; then
    log_error "could not capture the controlled matching bridge log for $label"
    status=1
  elif ! matching_bridge_sequence_is_exact "$fixture_log" "$expected_valid"; then
    log_error "matching bridge sequence for $label was not missing, $expected_valid valid, missing"
    status=1
  fi
  if ! run_bounded 30 "${COMPOSE[@]}" stop --timeout 5 bridge-fault; then
    log_error "could not stop the controlled matching bridge for $label"
    status=1
  else
    MATCHING_BRIDGE_RUNNING=false
  fi
  reset_matching_bridge_environment
  return "$status"
}

run_w3c_match_control() {
  local -r original_transport="$TRANSPORT"

  if [[ "$SELECTED_TRANSPORT" != "unix" ]]; then
    recreate_instrumented_stack "tcp" "matching W3C and OBI preparation" unix
  fi
  stop_obi_for_no_state_control "w3c-match"
  run_scenario w3c-match true full matching
  if [[ "$SCENARIO" == "all" || "$KEEP_RUNNING" == "true" ]]; then
    recreate_instrumented_stack "tcp" "post-match bridge restoration" "$original_transport"
  fi
}

run_w3c_fault_control() {
  local fault_log=""
  local expected_requests=""
  local stale=""
  local malformed=""
  local observed=""
  local -a fault_modes=(
    alternating timeout disconnect overload truncated bad-magic bad-size
    version-mismatch zero-trace-id zero-span-id
  )

  [[ "$TRANSPORT" == "unix" && "$SELECTED_TRANSPORT" == "unix" ]] || {
    log_error "the W3C malformed/stale control requires the forced Unix transport"
    return 1
  }
  stop_obi_for_no_state_control "w3c-fault"
  for FAULT_MODE in "${fault_modes[@]}"; do
    FAULT_REQUEST_COUNT=1
    if [[ "$FAULT_MODE" == "alternating" ]]; then
      FAULT_REQUEST_COUNT=2
    fi
    export FAULT_MODE
    fault_log="$RESULT_DIR/w3c-fault-$FAULT_MODE-bridge.log"
    log_info "starting bounded Unix fault responder mode=$FAULT_MODE"
    run_bounded 60 \
      "${COMPOSE[@]}" up --detach --no-deps --force-recreate bridge-fault
    wait_for_log \
      bridge-fault \
      "mode=$FAULT_MODE" \
      "Unix fault responder mode=$FAULT_MODE"
    run_scenario w3c-fault
    run_bounded 15 "${COMPOSE[@]}" logs --no-color bridge-fault >"$fault_log"
    expected_requests="$(scenario_request_count w3c-fault)"
    expected_requests="$((expected_requests * REPEAT_COUNT))"
    if [[ "$FAULT_MODE" == "alternating" ]]; then
      stale="$(awk '/operation=take status=stale/ { count++ } END { print count + 0 }' "$fault_log")"
      malformed="$(awk '/operation=take status=malformed/ { count++ } END { print count + 0 }' "$fault_log")"
      if [[ "$stale" != "$(((expected_requests + 1) / 2))" || \
        "$malformed" != "$((expected_requests / 2))" ]]; then
        log_error "fault responder expected stale=$(((expected_requests + 1) / 2)) malformed=$((expected_requests / 2)), got stale=$stale malformed=$malformed"
        return 1
      fi
    else
      observed="$(awk -v wanted="$FAULT_MODE" \
        '$0 ~ ("operation=take status=" wanted) { count++ } END { print count + 0 }' \
        "$fault_log")"
      if [[ "$observed" != "$expected_requests" ]]; then
        log_error "fault responder mode=$FAULT_MODE expected requests=$expected_requests, got $observed"
        return 1
      fi
    fi
    sleep 1
  done
  run_bounded 30 "${COMPOSE[@]}" stop --timeout 5 bridge-fault
  FAULT_MODE="alternating"
  FAULT_REQUEST_COUNT=2
  export FAULT_MODE
  recreate_instrumented_stack "tcp" "post-fault bridge recovery"
}

assert_sanitized_java_diagnostics() {
  local -r input="$1"
  local snapshot=""
  local entry=""
  local name=""
  local value=""
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
  local index=0

  IFS= read -r snapshot <"$input" || true
  IFS=',' read -r -a entries <<<"$snapshot"
  if (( ${#entries[@]} != ${#expected_names[@]} )); then
    log_error "Java diagnostics did not contain the exact fixed counter schema"
    return 1
  fi
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^[a-z_]+=[0-9a-z]+$ ]] || {
      log_error "Java diagnostics contained a non-counter field"
      return 1
    }
    name="${entry%%=*}"
    value="${entry#*=}"
    if [[ "$name" != "${expected_names[$index]}" ]] || (( ${#value} > 6 )); then
      log_error "Java diagnostics contained an unknown, reordered, or unbounded counter"
      return 1
    fi
    ((index += 1))
  done
}

background_process_is_running() {
  local -r process_pid="$1"
  local state=""

  [[ "$process_pid" =~ ^[1-9][0-9]*$ && -r "/proc/$process_pid/stat" ]] || return 1
  state="$(sed -E 's/^[0-9]+ \(.*\) ([A-Z]) .*/\1/' "/proc/$process_pid/stat")"
  [[ "$state" != "Z" ]]
}

wait_for_background_log() {
  local -r process_pid="$1"
  local -r output="$2"
  local -r pattern="$3"
  local -r description="$4"
  local -i started_at="$SECONDS"

  while ((SECONDS - started_at < READINESS_TIMEOUT_SECONDS)); do
    if grep -Fq "$pattern" "$output" 2>/dev/null; then
      log_info "$description is ready"
      return 0
    fi
    if ! background_process_is_running "$process_pid"; then
      log_error "$description exited before emitting: $pattern"
      return 1
    fi
    sleep 0.1
  done
  log_error "timed out waiting for $description output: $pattern"
  return 1
}

wait_for_background_process() {
  local -r process_pid="$1"
  local -r timeout_seconds="$2"
  local -i elapsed=0
  local -i attempts=$((timeout_seconds * 10))
  local process_status=0

  while ((elapsed < attempts)); do
    if ! background_process_is_running "$process_pid"; then
      if wait "$process_pid"; then
        return 0
      else
        process_status=$?
        return "$process_status"
      fi
    fi
    sleep 0.1
    ((elapsed += 1))
  done
  return 124
}

wait_for_primary_security_namespace_pid() {
  local -r java_container="$1"
  local candidate=""
  local -i started_at="$SECONDS"

  while ((SECONDS - started_at < READINESS_TIMEOUT_SECONDS)); do
    candidate="$(run_bounded 5 docker exec "$java_container" \
      cat "$PRIMARY_SECURITY_PID_PATH" 2>/dev/null || true)"
    if [[ "$candidate" =~ ^[1-9][0-9]*$ ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    sleep 0.1
  done
  log_error "timed out waiting for the Java-container security probe PID"
  return 1
}

assert_primary_security_cgroup_identity() {
  local -r java_cgroup="$1"
  local -r probe_cgroup="$2"
  local -r probe_status="$3"

  [[ -s "$java_cgroup" && -s "$probe_cgroup" ]] || {
    log_error "primary security cgroup evidence was empty"
    return 1
  }
  cmp -s -- "$java_cgroup" "$probe_cgroup" || {
    log_error "primary security probe did not share the Java container cgroup"
    return 1
  }
  awk '
    $1 == "Uid:" {
      found_uid = 1
      for (field = 2; field <= 5; field++) {
        if ($field != 65534) {
          failed = 1
        }
      }
    }
    $1 == "Gid:" {
      found_gid = 1
      for (field = 2; field <= 5; field++) {
        if ($field != 65534) {
          failed = 1
        }
      }
    }
    END {
      exit failed || !found_uid || !found_gid ? 1 : 0
    }
  ' "$probe_status" || {
    log_error "primary security probe did not run with the unprivileged 65534:65534 identity"
    return 1
  }
}

run_primary_security_control() {
  local -r sibling_output="$RESULT_DIR/security-primary-sibling.log"
  local -r sibling_identity="$RESULT_DIR/security-primary-sibling.json"
  local -r same_cgroup_output="$RESULT_DIR/security-primary-same-cgroup.log"
  local -r same_cgroup_identity="$RESULT_DIR/security-primary-same-cgroup.txt"
  local -r java_cgroup="$RESULT_DIR/security-primary-java.cgroup"
  local -r probe_cgroup="$RESULT_DIR/security-primary-probe.cgroup"
  local -r probe_status="$RESULT_DIR/security-primary-probe.status"
  local -r sibling_cgroup="$RESULT_DIR/security-primary-sibling.cgroup"
  local -r sibling_delta="$RESULT_DIR/phases/security-primary-sibling-ready/obi-metrics.delta"
  local -r initial_delta="$RESULT_DIR/phases/security-primary-probe-ready/obi-metrics.delta"
  local host_probe=""
  local java_container=""
  local java_host_pid=""
  local sibling_host_pid=""
  local same_cgroup_exit=0
  local sibling_exit=""
  local network_mode=""
  local pid_mode=""
  local previous_variant=""
  local previous_metric_policy=""
  local run_number=0
  local phase_label=""

  [[ "$SELECTED_TRANSPORT" == "getsockopt" ]] || {
    log_error "the primary security control requires the selected getsockopt transport"
    return 1
  }

  capture_java_diagnostics "security-primary-diagnostics-before"
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/security-primary-diagnostics-before/java-diagnostics.txt"
  capture_phase_evidence "security-primary-before"
  SECURITY_PROBE_MODE="primary"
  export SECURITY_PROBE_MODE
  log_info "starting the isolated sibling-container getsockopt control"
  run_bounded 60 \
    "${COMPOSE[@]}" up --detach --no-deps --force-recreate security-probe
  wait_for_log \
    security-probe \
    "security probe primary ready" \
    "getsockopt sibling-container security barrier"
  PRIMARY_SECURITY_SIBLING_CONTAINER="$(run_bounded 10 \
    "${COMPOSE[@]}" ps --all --quiet security-probe)"
  [[ -n "$PRIMARY_SECURITY_SIBLING_CONTAINER" ]] || {
    log_error "could not resolve the sibling security probe container"
    return 1
  }
  run_bounded 10 docker inspect \
    --format '{"id":{{json .Id}},"user":{{json .Config.User}},"network_mode":{{json .HostConfig.NetworkMode}},"pid_mode":{{json .HostConfig.PidMode}},"host_pid":{{json .State.Pid}}}' \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER" >"$sibling_identity"
  network_mode="$(run_bounded 10 docker inspect --format '{{.HostConfig.NetworkMode}}' \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER")"
  pid_mode="$(run_bounded 10 docker inspect --format '{{.HostConfig.PidMode}}' \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER")"
  [[ "$network_mode" == "none" && -z "$pid_mode" ]] || {
    log_error "sibling security probe did not run in isolated network and PID namespaces"
    return 1
  }

  java_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet java-backend)"
  [[ -n "$java_container" ]] || {
    log_error "could not resolve the Java backend container"
    return 1
  }
  java_host_pid="$(run_bounded 10 docker inspect --format '{{.State.Pid}}' "$java_container")"
  sibling_host_pid="$(run_bounded 10 docker inspect --format '{{.State.Pid}}' \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER")"
  if [[ ! "$java_host_pid" =~ ^[1-9][0-9]*$ || \
    ! "$sibling_host_pid" =~ ^[1-9][0-9]*$ || \
    ! -r "/proc/$java_host_pid/cgroup" || ! -r "/proc/$sibling_host_pid/cgroup" ]]; then
    log_error "could not resolve host cgroups for the Java and sibling containers"
    return 1
  fi
  install -m 0644 "/proc/$sibling_host_pid/cgroup" "$sibling_cgroup"
  if cmp -s -- "/proc/$java_host_pid/cgroup" "$sibling_cgroup"; then
    log_error "sibling security probe unexpectedly shared the Java container cgroup"
    return 1
  fi

  if ! wait_for_primary_security_metrics_quiescent \
    "$RESULT_DIR/metrics-security-primary-sibling-ready.prom" \
    "sibling-container security probe publication"; then
    return 1
  fi
  if ! capture_metric_phase_evidence "security-primary-sibling-ready"; then
    return 1
  fi
  write_metrics_delta \
    "$RESULT_DIR/phases/security-primary-before/obi-metrics.prom" \
    "$RESULT_DIR/phases/security-primary-sibling-ready/obi-metrics.prom" \
    "$sibling_delta"
  assert_primary_security_metric_delta "$sibling_delta" negotiate 0 1

  host_probe="$(mktemp "$RESULT_DIR/.security-primary-probe.XXXXXX")"
  PRIMARY_SECURITY_HOST_PROBE="$host_probe"
  run_bounded 15 docker cp \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER:/security-probe" "$host_probe"
  PRIMARY_SECURITY_JAVA_CONTAINER="$java_container"
  run_bounded 10 docker exec "$java_container" \
    rm -f -- "$PRIMARY_SECURITY_PROBE_PATH" "$PRIMARY_SECURITY_PID_PATH"
  run_bounded 15 docker cp "$host_probe" \
    "$java_container:$PRIMARY_SECURITY_PROBE_PATH"
  rm -f -- "$host_probe"
  host_probe=""
  PRIMARY_SECURITY_HOST_PROBE=""
  run_bounded 10 docker exec "$java_container" \
    chmod 0755 "$PRIMARY_SECURITY_PROBE_PATH"

  : >"$same_cgroup_output"
  docker exec --user 65534:65534 "$java_container" /bin/sh -ec '
    umask 077
    printf "%s\n" "$$" >"$1"
    exec "$2" --mode primary --timeout "$3"
  ' sh "$PRIMARY_SECURITY_PID_PATH" "$PRIMARY_SECURITY_PROBE_PATH" \
    "$PRIMARY_SECURITY_SAME_CGROUP_TIMEOUT" \
    >"$same_cgroup_output" 2>&1 &
  PRIMARY_SECURITY_EXEC_PID=$!
  wait_for_background_log \
    "$PRIMARY_SECURITY_EXEC_PID" \
    "$same_cgroup_output" \
    "security probe primary ready" \
    "same-cgroup getsockopt security probe"
  PRIMARY_SECURITY_NAMESPACE_PID="$(wait_for_primary_security_namespace_pid \
    "$java_container")"

  run_bounded 10 docker exec "$java_container" \
    cat /proc/1/cgroup >"$java_cgroup"
  run_bounded 10 docker exec "$java_container" \
    cat "/proc/$PRIMARY_SECURITY_NAMESPACE_PID/cgroup" >"$probe_cgroup"
  run_bounded 10 docker exec "$java_container" \
    cat "/proc/$PRIMARY_SECURITY_NAMESPACE_PID/status" >"$probe_status"
  assert_primary_security_cgroup_identity \
    "$java_cgroup" "$probe_cgroup" "$probe_status"
  {
    printf 'java_container=%s\n' "$java_container"
    printf 'java_host_pid=%s\n' "$java_host_pid"
    printf 'probe_namespace_pid=%s\n' "$PRIMARY_SECURITY_NAMESPACE_PID"
    printf 'requested_user=65534:65534\n'
    printf 'cgroup_match=true\n'
    printf '\n/proc/1/cgroup:\n'
    cat "$java_cgroup"
    printf '\n/proc/%s/cgroup:\n' "$PRIMARY_SECURITY_NAMESPACE_PID"
    cat "$probe_cgroup"
    printf '\n/proc/%s/status identity:\n' "$PRIMARY_SECURITY_NAMESPACE_PID"
    awk '/^(Name|Pid|PPid|Uid|Gid|Groups|NoNewPrivs):/ { print }' "$probe_status"
  } >"$same_cgroup_identity"

  if ! wait_for_primary_security_metrics_quiescent \
    "$RESULT_DIR/metrics-security-primary-probe-ready.prom" \
    "same-cgroup security probe publication"; then
    return 1
  fi
  if ! capture_metric_phase_evidence "security-primary-probe-ready"; then
    return 1
  fi
  write_metrics_delta \
    "$RESULT_DIR/phases/security-primary-sibling-ready/obi-metrics.prom" \
    "$RESULT_DIR/phases/security-primary-probe-ready/obi-metrics.prom" \
    "$initial_delta"
  assert_primary_security_metric_delta "$initial_delta" negotiate 1
  assert_primary_security_metric_delta "$initial_delta" take 5

  previous_variant="$SCENARIO_VARIANT"
  previous_metric_policy="$ALLOW_PRIMARY_SECURITY_METRICS"
  SCENARIO_VARIANT="security-primary-victim"
  ALLOW_PRIMARY_SECURITY_METRICS=true
  if ! run_scenario concurrency false metrics; then
    SCENARIO_VARIANT="$previous_variant"
    ALLOW_PRIMARY_SECURITY_METRICS="$previous_metric_policy"
    return 1
  fi
  SCENARIO_VARIANT="$previous_variant"
  ALLOW_PRIMARY_SECURITY_METRICS="$previous_metric_policy"

  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    phase_label="concurrency-security-primary-victim"
    if ((REPEAT_COUNT > 1)); then
      printf -v phase_label '%s-run-%02d' "$phase_label" "$run_number"
    fi
    assert_primary_security_metric_delta \
      "$RESULT_DIR/phases/$phase_label-after/obi-metrics.delta" take 1
  done

  background_process_is_running "$PRIMARY_SECURITY_EXEC_PID" || {
    log_error "same-cgroup primary security probe exited before release"
    return 1
  }
  # Expanded by the container shell, not this process.
  # shellcheck disable=SC2016
  run_bounded 10 docker exec "$java_container" /bin/sh -ec '
    read -r name <"/proc/$1/comm"
    [ "$name" = security-probe ]
    kill -USR1 "$1"
  ' sh "$PRIMARY_SECURITY_NAMESPACE_PID"
  if wait_for_background_process "$PRIMARY_SECURITY_EXEC_PID" 15; then
    same_cgroup_exit=0
  else
    same_cgroup_exit=$?
  fi
  [[ "$same_cgroup_exit" == "0" ]] || {
    log_error "same-cgroup primary security probe exited with status $same_cgroup_exit"
    return 1
  }
  PRIMARY_SECURITY_EXEC_PID=""
  PRIMARY_SECURITY_NAMESPACE_PID=""
  if ! grep -Fq '"status":"passed","mode":"primary"' "$same_cgroup_output" || \
    ! grep -Eq '"attempts":[1-9][0-9]*' "$same_cgroup_output" || \
    ! grep -Fq '"name":"repeated-retrieval","outcome":"native-unsupported"' \
      "$same_cgroup_output"; then
    log_error "same-cgroup primary security probe did not emit bounded native-result evidence"
    return 1
  fi

  run_bounded 15 docker kill --signal SIGUSR1 \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER" >/dev/null
  sibling_exit="$(run_bounded 60 docker wait "$PRIMARY_SECURITY_SIBLING_CONTAINER")"
  [[ "$sibling_exit" == "0" ]] || {
    log_error "sibling security probe exited with status $sibling_exit"
    return 1
  }
  run_bounded 15 "${COMPOSE[@]}" logs --no-color security-probe >"$sibling_output"
  PRIMARY_SECURITY_SIBLING_CONTAINER=""
  if ! grep -Fq '"status":"passed","mode":"primary"' "$sibling_output" || \
    ! grep -Eq '"attempts":[1-9][0-9]*' "$sibling_output" || \
    ! grep -Fq '"name":"wrong-process-negotiation","outcome":"native-unsupported"' \
      "$sibling_output" || \
    ! grep -Fq '"name":"repeated-retrieval","outcome":"native-unsupported"' \
      "$sibling_output"; then
    log_error "sibling security probe did not emit honest native-result evidence"
    return 1
  fi

  run_bounded 10 docker exec "$java_container" \
    rm -f -- "$PRIMARY_SECURITY_PROBE_PATH" "$PRIMARY_SECURITY_PID_PATH"
  PRIMARY_SECURITY_JAVA_CONTAINER=""
  capture_java_diagnostics "security-primary-diagnostics-after"
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/security-primary-diagnostics-after/java-diagnostics.txt"

  previous_variant="$SCENARIO_VARIANT"
  SCENARIO_VARIANT="security-primary-recovery"
  if ! run_scenario basic false; then
    SCENARIO_VARIANT="$previous_variant"
    return 1
  fi
  SCENARIO_VARIANT="$previous_variant"
  printf '{"status":"passed","scenario":"security","mode":"primary","same_cgroup_probe":"%s","sibling_probe":"%s","cgroup_match":true,"unauthorized_classification":"metrics_verified","post_abuse_recovery":"passed","unix_only_cases":"not_applicable"}\n' \
    "$(basename -- "$same_cgroup_output")" \
    "$(basename -- "$sibling_output")" \
    >"$RESULT_DIR/scenario-security-status.json"
}

run_unix_permissive_directory_control() {
  local -r response_body="$RESULT_DIR/security-permissive-directory-response.json"
  local -r response_status="$RESULT_DIR/security-permissive-directory-response.status"
  local -r mode_evidence="$RESULT_DIR/security-permissive-directory-mode.txt"
  local -r obi_log="$RESULT_DIR/security-permissive-directory-obi.log"
  local failure_since=""
  local recovery_since=""

  log_info "proving the Unix bridge refuses a world-accessible socket directory"
  BRIDGE_RUNNING=false
  run_bounded 30 "${COMPOSE[@]}" stop --timeout 10 obi
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    chmod 0777 /var/run/obi
  UNIX_SECURITY_DIRECTORY_RELAXED=true
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    /bin/sh -ec 'ls -ld /var/run/obi' >"$mode_evidence"
  grep -Eq '^drwxrwxrwx' "$mode_evidence" || {
    log_error "could not prove the Unix socket directory was made world accessible"
    return 1
  }

  failure_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  run_bounded 60 "${COMPOSE[@]}" up --detach --no-deps --force-recreate obi
  wait_for_log \
    obi \
    "$UNIX_PERMISSION_REFUSAL_PATTERN" \
    "permissive Unix directory refusal" \
    "$failure_since"
  if run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    /bin/sh -ec 'test -S /var/run/obi/java-remote-parent.sock'; then
    log_error "Unix bridge created a socket in a permissive directory"
    return 1
  fi

  curl --fail --silent --show-error --max-time 10 \
    --header 'x-obi-demo-id: security-permissive-directory' \
    --output "$response_body" \
    --write-out '%{http_code}\n' \
    "http://127.0.0.1:18080/api/echo?close=1" >"$response_status"
  if [[ "$(<"$response_status")" != "200" ]] || \
    ! grep -Fq '"marker":"security-permissive-directory"' "$response_body"; then
    log_error "application traffic did not fail open while the Unix directory was rejected"
    return 1
  fi
  run_bounded 15 "${COMPOSE[@]}" logs --no-color --since "$failure_since" \
    obi >"$obi_log"

  run_bounded 30 "${COMPOSE[@]}" stop --timeout 10 obi
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    chmod 0750 /var/run/obi
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    /bin/sh -ec 'ls -ld /var/run/obi' >>"$mode_evidence"
  tail -n 1 "$mode_evidence" | grep -Eq '^drwxr-x---' || {
    log_error "could not prove the Unix socket directory permissions were restored"
    return 1
  }
  UNIX_SECURITY_DIRECTORY_RELAXED=false
  recovery_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  run_bounded 60 "${COMPOSE[@]}" up --detach --no-deps --force-recreate obi
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "post-permission Unix bridge recovery" \
    "$recovery_since"
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "post-permission Java bridge provider" \
    "$recovery_since"
  assert_selected_transport
  [[ "$SELECTED_TRANSPORT" == "unix" ]] || {
    log_error "post-permission recovery did not restore the Unix transport"
    return 1
  }
  wait_for_apache_instrumentation unix-permission-recovery
  BRIDGE_RUNNING=true
}

run_unix_security_control() {
  local -r abuse_output="$RESULT_DIR/security-abuse.json"
  local -r endpoint_output="$RESULT_DIR/security-endpoint.log"
  local -r security_logs="$RESULT_DIR/security-sanitized-logs.txt"
  local security_since=""
  local restart_since=""
  local probe_container=""
  local probe_exit=""
  local previous_variant=""
  local previous_metric_policy=""
  local run_number=0
  local phase_label=""

  [[ "$TRANSPORT" == "unix" && "$SELECTED_TRANSPORT" == "unix" ]] || {
    log_error "the security control requires the forced Unix transport"
    return 1
  }

  security_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  capture_java_diagnostics "security-before"
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/security-before/java-diagnostics.txt"

  SECURITY_PROBE_MODE="abuse-race"
  export SECURITY_PROBE_MODE
  log_info "starting bounded Unix abuse while legitimate exact-parent traffic remains active"
  run_bounded 60 \
    "${COMPOSE[@]}" up --detach --no-deps --force-recreate security-probe
  wait_for_log \
    security-probe \
    "security probe abuse race ready" \
    "Unix abuse race barrier"
  UNIX_SECURITY_RACE_CONTAINER="$(run_bounded 10 \
    "${COMPOSE[@]}" ps --all --quiet security-probe)"
  [[ -n "$UNIX_SECURITY_RACE_CONTAINER" ]] || {
    log_error "could not resolve the Unix abuse-race container"
    return 1
  }

  previous_variant="$SCENARIO_VARIANT"
  previous_metric_policy="$ALLOW_UNIX_SECURITY_METRICS"
  SCENARIO_VARIANT="security-unix-victim"
  ALLOW_UNIX_SECURITY_METRICS=true
  if ! run_scenario concurrency false metrics; then
    SCENARIO_VARIANT="$previous_variant"
    ALLOW_UNIX_SECURITY_METRICS="$previous_metric_policy"
    return 1
  fi
  SCENARIO_VARIANT="$previous_variant"
  ALLOW_UNIX_SECURITY_METRICS="$previous_metric_policy"

  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    phase_label="concurrency-security-unix-victim"
    if ((REPEAT_COUNT > 1)); then
      printf -v phase_label '%s-run-%02d' "$phase_label" "$run_number"
    fi
    assert_security_metric_delta \
      "$RESULT_DIR/phases/$phase_label-after/obi-metrics.delta" \
      take unauthorized unix 1
  done

  run_bounded 15 docker kill --signal SIGUSR1 \
    "$UNIX_SECURITY_RACE_CONTAINER" >/dev/null
  probe_exit="$(run_bounded 60 docker wait "$UNIX_SECURITY_RACE_CONTAINER")"
  [[ "$probe_exit" == "0" ]] || {
    log_error "Unix abuse-race probe exited with status $probe_exit"
    return 1
  }
  run_bounded 15 \
    "${COMPOSE[@]}" logs --no-color security-probe >"$abuse_output"
  UNIX_SECURITY_RACE_CONTAINER=""
  if ! grep -Fq '"status":"passed","mode":"abuse-race"' "$abuse_output" || \
    ! grep -Eq '"attempts":[1-9][0-9]*' "$abuse_output" || \
    ! grep -Fq '"name":"concurrent-repeated-unauthorized","outcome":"bounded"' \
      "$abuse_output"; then
    log_error "Unix abuse-race probe did not emit explicit bounded pass evidence"
    return 1
  fi

  SECURITY_PROBE_MODE="endpoint"
  export SECURITY_PROBE_MODE
  log_info "installing a bounded replacement endpoint around an OBI restart"
  run_bounded 60 \
    "${COMPOSE[@]}" up --detach --no-deps --force-recreate security-probe
  wait_for_log \
    security-probe \
    "security probe replacement ready" \
    "security endpoint replacement barrier"
  probe_container="$(run_bounded 10 "${COMPOSE[@]}" ps --all --quiet security-probe)"
  [[ -n "$probe_container" ]] || {
    log_error "could not resolve the security probe container"
    return 1
  }

  restart_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  BRIDGE_RUNNING=false
  run_bounded 60 "${COMPOSE[@]}" restart --timeout 10 obi
  wait_for_log \
    obi \
    "refusing to replace non-socket Java bridge path" \
    "replacement endpoint fail-closed restart" \
    "$restart_since"
  run_bounded 15 "${COMPOSE[@]}" kill --signal SIGUSR1 security-probe
  probe_exit="$(run_bounded 60 docker wait "$probe_container")"
  [[ "$probe_exit" == "0" ]] || {
    log_error "security endpoint probe exited with status $probe_exit"
    return 1
  }
  run_bounded 15 \
    "${COMPOSE[@]}" logs --no-color security-probe >"$endpoint_output"
  grep -Fq '"status":"passed","mode":"endpoint"' "$endpoint_output" || {
    log_error "security endpoint probe did not emit explicit pass evidence"
    return 1
  }

  wait_for_log \
    obi \
    "Java remote-parent fallback transport recovered" \
    "post-replacement Unix bridge recovery" \
    "$restart_since"
  BRIDGE_RUNNING=true
  SELECTED_TRANSPORT="unix"

  capture_java_diagnostics "security-after"
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/security-after/java-diagnostics.txt"
  run_bounded 15 \
    "${COMPOSE[@]}" logs --no-color --since "$security_since" \
      obi java-backend security-probe >"$security_logs"
  if grep -Fq 'OBI_SECURITY_PROBE_PAYLOAD_CANARY' \
    "$abuse_output" "$endpoint_output" "$security_logs" \
    "$RESULT_DIR/phases/security-before/java-diagnostics.txt" \
    "$RESULT_DIR/phases/security-after/java-diagnostics.txt"; then
    log_error "security diagnostics disclosed the probe payload canary"
    return 1
  fi

  run_unix_permissive_directory_control

  previous_variant="$SCENARIO_VARIANT"
  SCENARIO_VARIANT="security-recovery"
  if ! run_scenario basic false; then
    SCENARIO_VARIANT="$previous_variant"
    return 1
  fi
  SCENARIO_VARIANT="$previous_variant"
  printf '{"status":"passed","scenario":"security","mode":"unix","abuse_race":"%s","concurrent_victim":"passed","endpoint":"%s","permissive_directory":"refused","post_abuse_recovery":"passed","primary_only_cases":"not_applicable"}\n' \
    "$(basename -- "$abuse_output")" \
    "$(basename -- "$endpoint_output")" \
    >"$RESULT_DIR/scenario-security-status.json"
}

record_unsupported_scenario() {
  local -r name="$1"
  local -r reason="$2"

  [[ -n "$RESULT_DIR" && -d "$RESULT_DIR" ]] || {
    log_error "cannot record unsupported scenario without a result directory"
    return 1
  }
  printf '{"status":"unsupported","reason":"%s"}\n' "$reason" \
    >"$RESULT_DIR/scenario-$name-status.json"
}

run_security_control() {
  case "$SELECTED_TRANSPORT" in
    getsockopt)
      run_primary_security_control
      ;;
    unix)
      run_unix_security_control
      ;;
    *)
      log_error "security control cannot run with selected transport ${SELECTED_TRANSPORT:-unknown}"
      return 1
      ;;
  esac
}

run_disabled_control() {
  local recreate_since=""

  log_info "recreating Java and OBI with only the remote-parent bridge disabled"
  BRIDGE_RUNNING=false
  export BRIDGE_TRANSPORT=disabled
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  run_bounded 30 "${COMPOSE[@]}" config >"$RESULT_DIR/compose-disabled-control.yaml"
  recreate_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy obi
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "disabled-control external extension" \
    "$recreate_since"
  wait_for_log \
    java-backend \
    "OBI Java instrumentation ready" \
    "disabled-control Java instrumentation" \
    "$recreate_since"
  wait_for_apache_instrumentation disabled-control
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "disabled-control HTTPS path"
  assert_runtime_contract disabled
  run_scenario disabled
}

run_uninstrumented_control() {
  log_info "recreating the backend without OBI or any Java agent"
  capture_control_response "instrumented-control"
  BRIDGE_RUNNING=false
  export BRIDGE_TRANSPORT=disabled
  export EXTENSION_ENABLED=false
  export JAVA_TOOL_OPTIONS_VALUE=""
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE=""
  export OTEL_PROPAGATORS_VALUE="tracecontext,baggage"
  run_bounded 60 "${COMPOSE[@]}" stop --timeout 10 obi
  run_bounded 30 "${COMPOSE[@]}" config >"$RESULT_DIR/compose-uninstrumented-control.yaml"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "uninstrumented-control HTTPS path"
  assert_runtime_contract uninstrumented
  capture_control_response "uninstrumented-control"
  cmp \
    "$RESULT_DIR/instrumented-control-response.normalized.json" \
    "$RESULT_DIR/uninstrumented-control-response.normalized.json"
  cmp \
    "$RESULT_DIR/instrumented-control-response.status" \
    "$RESULT_DIR/uninstrumented-control-response.status"
  run_scenario uninstrumented
}

capture_control_response() {
  local -r label="$1"
  local -r body="$RESULT_DIR/$label-response.json"
  local -r status="$RESULT_DIR/$label-response.status"

  curl --fail --silent --show-error --max-time 10 \
    --header 'x-obi-demo-id: instrumentation-control' \
    --output "$body" \
    --write-out '%{http_code}\n' \
    "http://127.0.0.1:18080/api/echo" >"$status"
  [[ "$(<"$status")" == "200" ]] || {
    log_error "$label returned HTTP status $(<"$status")"
    return 1
  }
  normalize_control_response \
    "$body" \
    "$RESULT_DIR/$label-response.normalized.json"
}

normalize_control_response() {
  local -r input="$1"
  local -r output="$2"

  sed -E \
    -e 's/"backend_connection_id":[0-9]+/"backend_connection_id":0/' \
    -e 's/"backend_remote_port":[0-9]+/"backend_remote_port":0/' \
    "$input" >"$output"
}

execute_requested_scenarios() {
  local restart_since=""

  case "$SCENARIO" in
    all)
      run_scenario basic
      run_security_control
      run_scenario keepalive
      run_scenario pipelining
      run_scenario concurrency
      run_scenario connection-churn
      run_scenario fd-port-reuse
      run_scenario slow-body
      run_scenario tls-boundary
      run_scenario timeout-retry
      run_scenario pressure
      run_scenario handoff
      run_scenario virtual-thread
      run_scenario netty
      run_scenario dispatch
      run_scenario w3c
      run_w3c_match_control
      run_scenario obi-flags
      if [[ "$TRANSPORT" == "unix" ]]; then
        run_w3c_fault_control
      else
        record_unsupported_scenario w3c-fault "requires forced Unix transport"
      fi
      run_late_attach_control
      run_restart_during_traffic_control
      run_disabled_control
      run_extension_controls
      run_uninstrumented_control
      ;;
    fail-open)
      run_fail_open_control
      ;;
    w3c-only)
      run_w3c_only_control
      ;;
    restart)
      restart_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')"
      run_bounded 60 "${COMPOSE[@]}" restart --timeout 10 obi
      wait_for_log \
        obi \
        "Java remote parent bridge ready" \
        "restarted OBI remote-parent bridge" \
        "$restart_since"
      wait_for_log \
        java-backend \
        "OBI remote-parent provider ready" \
        "restarted Java bridge provider" \
        "$restart_since"
      BRIDGE_RUNNING=true
      assert_selected_transport
      wait_for_apache_instrumentation restart
      run_scenario restart
      ;;
    restart-fault)
      run_restart_during_traffic_control
      ;;
    w3c-match)
      run_w3c_match_control
      ;;
    w3c-fault)
      run_w3c_fault_control
      ;;
    security)
      run_security_control
      ;;
    uninstrumented)
      run_scenario uninstrumented
      ;;
    *)
      run_scenario "$SCENARIO"
      ;;
  esac
}

capture_environment() {
  {
    printf 'invocation=%s\n' "$RUN_INVOCATION"
    printf 'revision=%s\n' "$SOURCE_REVISION"
    printf 'dirty=%s\n' "$SOURCE_DIRTY"
    printf 'source_tree_sha256=%s\n' "$SOURCE_TREE_SHA256"
    printf 'tracked_patch_sha256=%s\n' "$SOURCE_TRACKED_PATCH_SHA256"
    printf 'patch_identity_sha256=%s\n' "$SOURCE_PATCH_SHA256"
    printf 'transport=%s\n' "$TRANSPORT"
    printf 'agent_distribution=%s\n' "$AGENT_DISTRIBUTION"
    printf 'tls_protocol=%s\n' "$TLS_PROTOCOL"
    printf 'scenario=%s\n' "$SCENARIO"
    printf 'request_count=%s\n' "$REQUEST_COUNT"
    printf 'repeat_count=%s\n' "$REPEAT_COUNT"
    printf 'scenario_seed=%s\n' "$SCENARIO_SEED"
    printf 'bridge_build_mode=%s\n' "$BRIDGE_BUILD_MODE"
    printf 'acceptance_evidence=%s\n' "$ACCEPTANCE_EVIDENCE"
    printf 'acceptance_evidence_reason=%s\n' "${ACCEPTANCE_EVIDENCE_REASON:-none}"
    printf 'compose_project=%s\n' "$PROJECT_NAME"
    printf 'command_timeout_seconds=%s\n' "$COMMAND_TIMEOUT_SECONDS"
    printf 'readiness_timeout_seconds=%s\n' "$READINESS_TIMEOUT_SECONDS"
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'openssl=%s\n' "$(openssl version)"
    printf 'docker=%s\n' "$(run_bounded 15 docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
    printf 'compose=%s\n' "$(run_bounded 15 docker compose version --short 2>/dev/null || true)"
  } >"$RESULT_DIR/environment.txt"
  install -m 0644 "$ARTIFACT_DIR/official-javaagent.json" "$RESULT_DIR/official-javaagent.json"
  install -m 0644 "$ARTIFACT_DIR/bridge-artifacts.json" "$RESULT_DIR/bridge-artifacts.json"
  install -m 0644 "$ARTIFACT_DIR/bridge-artifacts.sha256" "$RESULT_DIR/bridge-artifacts.sha256"
  install -m 0644 "$ARTIFACT_DIR/bridge-metadata.sha256" "$RESULT_DIR/bridge-metadata.sha256"
  install -m 0644 "$ARTIFACT_DIR/bridge-source-revision.txt" "$RESULT_DIR/bridge-source-revision.txt"
  install -m 0644 "$ARTIFACT_DIR/bridge-source-tree.sha256" "$RESULT_DIR/bridge-source-tree.sha256"
  install -m 0644 "$CERT_DIR/metadata.json" "$RESULT_DIR/certificates.json"
}

capture_host_topology() {
  local cgroup_filesystem="unavailable"
  local unprivileged_bpf="unavailable"

  if command -v stat >/dev/null 2>&1; then
    cgroup_filesystem="$(stat --file-system --format '%T' /sys/fs/cgroup 2>/dev/null || true)"
  fi
  if [[ -r /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
    unprivileged_bpf="$(</proc/sys/kernel/unprivileged_bpf_disabled)"
  fi
  {
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'cgroup_filesystem=%s\n' "$cgroup_filesystem"
    printf 'unprivileged_bpf_disabled=%s\n' "$unprivileged_bpf"
    if [[ -r /sys/kernel/btf/vmlinux ]]; then
      printf 'vmlinux_btf=readable\n'
    else
      printf 'vmlinux_btf=unavailable\n'
    fi
    printf '\n/proc/self/cgroup:\n'
    cat /proc/self/cgroup 2>&1 || true
    printf '\n/proc/mounts cgroup entries:\n'
    while IFS= read -r mount_entry; do
      if [[ "$mount_entry" == *" cgroup "* || "$mount_entry" == *" cgroup2 "* ]]; then
        printf '%s\n' "$mount_entry"
      fi
    done </proc/mounts
  } >"$RESULT_DIR/host-topology.txt"
}

capture_bpf_evidence() {
  if ! command -v bpftool >/dev/null 2>&1; then
    printf 'bpftool=unavailable\n' >"$RESULT_DIR/bpftool-feature-probe.txt"
    printf 'bpftool=unavailable\n' >"$RESULT_DIR/bpftool-programs.txt"
    printf 'bpftool=unavailable\n' >"$RESULT_DIR/bpftool-maps.txt"
    return 0
  fi

  capture_optional_command "$RESULT_DIR/bpftool-feature-probe.txt" 30 bpftool feature probe
  capture_optional_command "$RESULT_DIR/bpftool-programs.txt" 30 bpftool prog show
  capture_optional_command "$RESULT_DIR/bpftool-maps.txt" 30 bpftool map show
}

capture_apache_tls_runtime_evidence() {
  # shellcheck disable=SC2016 # The script expands only inside apache-proxy.
  run_logged_bounded "$RESULT_DIR/apache-openssl-version.txt" 30 \
    "${COMPOSE[@]}" exec --no-TTY apache-proxy /bin/sh -eu -c '
      module_path=/usr/local/apache2/modules/mod_ssl.so
      libssl_path=/usr/lib/libssl.so.3
      libcrypto_path=/usr/lib/libcrypto.so.3
      newline="
"

      fail() {
        printf "apache_tls_runtime_error=%s\n" "$1" >&2
        exit 1
      }

      httpd_version_output=
      if httpd_version_output="$(httpd -v 2>&1)"; then
        :
      else
        printf "%s\n" "$httpd_version_output" >&2
        fail httpd-version-command
      fi
      httpd_version_line=${httpd_version_output%%"$newline"*}
      case "$httpd_version_line" in
        "Server version: Apache/"?*) ;;
        *) fail httpd-version-invalid ;;
      esac
      apache_version=${httpd_version_line#"Server version: "}

      httpd_modules=
      if httpd_modules="$(httpd -M 2>&1)"; then
        :
      else
        printf "%s\n" "$httpd_modules" >&2
        fail httpd-modules-command
      fi
      case "
$httpd_modules
" in
        *"
 ssl_module (shared)
"*) ;;
        *) fail ssl-module-not-loaded ;;
      esac

      mod_ssl_scan=
      if mod_ssl_scan="$(scanelf -n -B -F "%n %F" "$module_path" 2>&1)"; then
        :
      else
        printf "%s\n" "$mod_ssl_scan" >&2
        fail mod-ssl-scan-command
      fi
      case "$mod_ssl_scan" in
        *" $module_path") ;;
        *) fail mod-ssl-path-mismatch ;;
      esac
      mod_ssl_needed=${mod_ssl_scan%" $module_path"}
      case "$mod_ssl_needed" in
        ""|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._,+-]*) fail mod-ssl-needed-invalid ;;
      esac
      case ",$mod_ssl_needed," in
        *,libssl.so.3,*) ;;
        *) fail mod-ssl-libssl-missing ;;
      esac
      case ",$mod_ssl_needed," in
        *,libcrypto.so.3,*) ;;
        *) fail mod-ssl-libcrypto-missing ;;
      esac

      libssl_owner_record=
      if libssl_owner_record="$(apk info --who-owns "$libssl_path" 2>&1)"; then
        :
      else
        printf "%s\n" "$libssl_owner_record" >&2
        fail libssl-owner-command
      fi
      case "$libssl_owner_record" in
        "$libssl_path is owned by libssl3-"*) ;;
        *) fail libssl-owner-invalid ;;
      esac
      libssl_owner="${libssl_owner_record#"$libssl_path is owned by "}"
      case "$libssl_owner" in
        *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-]*) fail libssl-owner-invalid ;;
      esac
      case "$libssl_owner" in
        libssl3-?*) ;;
        *) fail libssl-owner-invalid ;;
      esac

      libcrypto_owner_record=
      if libcrypto_owner_record="$(apk info --who-owns "$libcrypto_path" 2>&1)"; then
        :
      else
        printf "%s\n" "$libcrypto_owner_record" >&2
        fail libcrypto-owner-command
      fi
      case "$libcrypto_owner_record" in
        "$libcrypto_path is owned by libcrypto3-"*) ;;
        *) fail libcrypto-owner-invalid ;;
      esac
      libcrypto_owner="${libcrypto_owner_record#"$libcrypto_path is owned by "}"
      case "$libcrypto_owner" in
        *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-]*) fail libcrypto-owner-invalid ;;
      esac
      case "$libcrypto_owner" in
        libcrypto3-?*) ;;
        *) fail libcrypto-owner-invalid ;;
      esac

      printf "apache_version=%s\n" "$apache_version"
      printf "apache_ssl_module=ssl_module (shared)\n"
      printf "apache_mod_ssl_path=%s\n" "$module_path"
      printf "apache_mod_ssl_needed=%s\n" "$mod_ssl_needed"
      printf "openssl_libssl_path=%s\n" "$libssl_path"
      printf "openssl_libssl_owner=%s\n" "$libssl_owner"
      printf "openssl_libcrypto_path=%s\n" "$libcrypto_path"
      printf "openssl_libcrypto_owner=%s\n" "$libcrypto_owner"
    '
}

capture_runtime_evidence() {
  local container_ids_output=""
  local container_id=""
  local -a container_ids=()
  local -a image_references=(
    "httpd:2.4.68-alpine@sha256:1b766f17b84026429b7cb243317b142921b24432336e798bc881c43f45ed9567"
    "obi-apache-java-https-tracecheck:local"
    "obi-apache-java-https-backend:local"
    "obi-apache-java-https:local"
  )

  capture_host_topology
  capture_bpf_evidence
  capture_optional_command "$RESULT_DIR/compose-images.json" 30 \
    "${COMPOSE[@]}" images --format json

  container_ids_output="$(run_bounded 15 "${COMPOSE[@]}" ps --all --quiet 2>/dev/null || true)"
  while IFS= read -r container_id; do
    if [[ -n "$container_id" ]]; then
      container_ids+=("$container_id")
    fi
  done <<<"$container_ids_output"
  if [[ ${#container_ids[@]} -gt 0 ]]; then
    capture_optional_command "$RESULT_DIR/container-identities.txt" 30 \
      docker inspect \
      --format '{{json .Name}} {{json .Id}} {{json .Image}} {{json .Config.Image}} {{json .HostConfig.NetworkMode}} {{json .HostConfig.PidMode}}' \
      "${container_ids[@]}"
  else
    printf 'containers=unavailable\n' >"$RESULT_DIR/container-identities.txt"
  fi

  capture_optional_command "$RESULT_DIR/image-identities.txt" 30 \
    docker image inspect \
    --format '{{json .Id}} {{json .RepoTags}} {{json .RepoDigests}}' \
    "${image_references[@]}"
  capture_optional_command "$RESULT_DIR/java-version.txt" 30 \
    "${COMPOSE[@]}" exec --no-TTY java-backend java -version
  capture_optional_command "$RESULT_DIR/apache-version.txt" 30 \
    "${COMPOSE[@]}" exec --no-TTY apache-proxy httpd -v
  capture_apache_tls_runtime_evidence || return
  capture_optional_command "$RESULT_DIR/obi-startup.log" 30 \
    "${COMPOSE[@]}" logs --no-color --tail 2000 obi
  capture_optional_command "$RESULT_DIR/java-startup.log" 30 \
    "${COMPOSE[@]}" logs --no-color --tail 2000 java-backend
  capture_optional_command "$RESULT_DIR/apache-startup.log" 30 \
    "${COMPOSE[@]}" logs --no-color --tail 2000 apache-proxy
}

capture_metric_phase_evidence() {
  local -r phase="$1"
  local phase_dir=""

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
    log_error "refusing invalid metric evidence phase name: $phase"
    return 1
  }
  phase_dir="$RESULT_DIR/phases/$phase"
  mkdir -p -- "$phase_dir"
  fetch_obi_metrics "$phase_dir/obi-metrics.prom"
}

capture_phase_evidence() {
  local -r phase="$1"
  local phase_dir=""
  local service=""
  local container_id=""
  local container_pid=""
  local fd_count=""
  local -a phase_container_ids=()

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
    log_warn "refusing invalid evidence phase name: $phase"
    return 0
  }
  phase_dir="$RESULT_DIR/phases/$phase"
  mkdir -p -- "$phase_dir"

  if ! curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:18990/internal/metrics" >"$phase_dir/obi-metrics.prom" 2>"$phase_dir/obi-metrics.stderr"; then
    printf 'unavailable\n' >"$phase_dir/obi-metrics.prom"
  fi
  mapfile -t phase_container_ids < <(
    run_bounded 10 "${COMPOSE[@]}" ps --quiet 2>/dev/null | awk 'NF > 0'
  )
  if [[ ${#phase_container_ids[@]} -gt 0 ]]; then
    capture_optional_command "$phase_dir/container-stats.jsonl" 20 \
      docker stats --no-stream --format \
        '{{json .Name}} {{json .ID}} {{json .CPUPerc}} {{json .MemUsage}} {{json .PIDs}} {{json .NetIO}}' \
        "${phase_container_ids[@]}"
  else
    printf 'containers=unavailable\n' >"$phase_dir/container-stats.jsonl"
  fi

  for service in obi apache-proxy java-backend trace-receiver; do
    container_id="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet "$service" 2>/dev/null || true)"
    if [[ -z "$container_id" ]]; then
      printf 'container=unavailable\n' >"$phase_dir/$service-resources.txt"
      continue
    fi
    container_pid="$(run_bounded 10 docker inspect --format '{{.State.Pid}}' "$container_id" 2>/dev/null || true)"
    {
      printf 'container_id=%s\n' "$container_id"
      printf 'host_pid=%s\n' "$container_pid"
      if [[ "$container_pid" =~ ^[1-9][0-9]*$ && -r "/proc/$container_pid/status" ]]; then
        awk '/^(VmPeak|VmSize|VmRSS|VmData|VmStk|VmExe|VmLib|Threads):/ {print}' \
          "/proc/$container_pid/status"
        fd_count="$(find "/proc/$container_pid/fd" -mindepth 1 -maxdepth 1 -printf '.\n' 2>/dev/null | wc -l || true)"
        printf 'FDs:\t%s\n' "$fd_count"
      else
        printf 'proc_status=unavailable\n'
      fi
    } >"$phase_dir/$service-resources.txt"
    capture_optional_command "$phase_dir/$service-processes.txt" 15 \
      docker top "$container_id" -eo pid,ppid,nlwp,rss,vsz,comm
  done
}

capture_java_diagnostics() {
  local -r phase="$1"
  local -r phase_dir="$RESULT_DIR/phases/$phase"

  mkdir -p -- "$phase_dir"
  if ! curl --fail --silent --show-error --max-time 5 \
    --cacert "$CERT_DIR/ca.crt" \
    "https://127.0.0.1:18443/obi-diagnostics" \
    >"$phase_dir/java-diagnostics.txt" \
    2>"$phase_dir/java-diagnostics.stderr"; then
    printf 'unavailable\n' >"$phase_dir/java-diagnostics.txt"
  fi
}

write_metrics_delta() {
  local -r before="$1"
  local -r after="$2"
  local -r output="$3"
  local unsorted=""

  unsorted="$(mktemp "$RESULT_DIR/.metrics-delta.XXXXXX")"
  awk '
    function wanted(metric) {
      return metric ~ /^obi_java_remote_parent_operations_total/ ||
        metric ~ /^obi_bpf_map_(entries|max_entries)_total/
    }
    FNR == NR {
      if ($0 !~ /^#/ && NF == 2 && wanted($1)) {
        before[$1] = $2
      }
      next
    }
    $0 !~ /^#/ && NF == 2 && wanted($1) {
      previous = ($1 in before) ? before[$1] : 0
      printf "%s before=%s after=%s delta=%.17g\n", $1, previous, $2, $2 - previous
      seen[$1] = 1
    }
    END {
      for (metric in before) {
        if (!(metric in seen)) {
          printf "%s before=%s after=unavailable delta=unavailable\n", metric, before[metric]
        }
      }
    }
  ' "$before" "$after" >"$unsorted"
  sort -- "$unsorted" >"$output"
  rm -f -- "$unsorted"
}

metric_delta_operation_total() {
  local -r input="$1"
  local -r operation="$2"

  awk -v operation="$operation" '
    index($0, "operation=\"" operation "\"") && index($0, "status=\"valid\"") {
      for (field = 1; field <= NF; field++) {
        if ($field ~ /^delta=/) {
          sub(/^delta=/, "", $field)
          total += $field
        }
      }
    }
    END { printf "%.0f\n", total }
  ' "$input"
}

pressure_bridge_reconciliation() {
  local -r input="$1"
  local -r transport="$2"
  local -r expected_valid="$3"
  local -r expected_roots="$4"
  local -r expected_requests="$5"

  [[ -f "$input" && ! -L "$input" &&
    ( "$transport" == "getsockopt" || "$transport" == "unix" ) &&
    "$expected_valid" =~ ^(0|[1-9][0-9]*)$ &&
    "$expected_roots" =~ ^(0|[1-9][0-9]*)$ &&
    "$expected_requests" =~ ^(0|[1-9][0-9]*)$ ]] || return 1

  awk \
    -v selected="$transport" \
    -v wanted_valid="$expected_valid" \
    -v wanted_roots="$expected_roots" \
    -v wanted_requests="$expected_requests" '
    function label(line, name, value) {
      value = line
      sub("^.*" name "=\"", "", value)
      sub("\".*$", "", value)
      return value
    }
    function upstream_status(status) {
      return status == "missing" || status == "stale" || status == "ambiguous" ||
        status == "malformed" || status == "overload" || status == "segmented"
    }
    function retrieval_status(status) {
      return status == "missing" || status == "stale" || status == "unsupported" ||
        status == "malformed" || status == "version_mismatch" ||
        status == "ambiguous" || status == "unauthorized" ||
        status == "already_consumed" || status == "timeout" ||
        status == "overload" || status == "transport_error" || status == "disabled"
    }
    function unexpected(kind, line) {
      printf "unexpected pressure bridge %s: %s\n", kind, line > "/dev/stderr"
      failed = 1
    }
    /^obi_java_remote_parent_operations_total/ {
      operation = label($0, "operation")
      status = label($0, "status")
      transport = label($0, "transport")
      delta = ""
      delta_fields = 0
      for (field = 1; field <= NF; field++) {
        if ($field ~ /^delta=/) {
          delta = $field
          sub(/^delta=/, "", delta)
          delta_fields++
        }
      }
      if (delta_fields != 1 || delta !~ /^(0|[1-9][0-9]*)$/) {
        unexpected("metric delta", $0)
        next
      }
      if (operation == "inject" && transport == "tcp") {
        inject_total += delta
        if (status == "valid") {
          inject_valid += delta
        } else if (upstream_status(status)) {
          inject_fail += delta
          upstream_reason[status] += delta
        } else if (delta != 0) {
          unexpected("inject result", $0)
        }
        next
      }
      if (operation == "candidate" && transport == "tcp") {
        candidate_total += delta
        if (status == "valid") {
          candidate_valid += delta
        } else if (status == "ambiguous" || status == "malformed" || status == "overload") {
          candidate_fail += delta
          upstream_reason[status] += delta
        } else if (delta != 0) {
          unexpected("candidate result", $0)
        }
        next
      }
      if (operation == "stage" && transport == "tcp") {
        stage_total += delta
        if (status == "valid") {
          stage_valid += delta
        } else if (status == "ambiguous" || status == "malformed" || status == "overload") {
          stage_fail += delta
          upstream_reason[status] += delta
        } else if (delta != 0) {
          unexpected("stage result", $0)
        }
        next
      }
      if (operation == "take") {
        if (transport != selected) {
          if (delta != 0) {
            unexpected("non-selected retrieval result", $0)
          }
        } else {
          retrieval_total += delta
          if (status == "valid") {
            retrieval_valid += delta
          } else if (retrieval_status(status)) {
            retrieval_fail += delta
            retrieval_reason[status] += delta
          } else if (delta != 0) {
            unexpected("retrieval result", $0)
          }
        }
        next
      }
      if (operation == "handoff" && transport == "tcp") {
        if (status == "valid") {
          handoff_valid += delta
        } else if (delta != 0) {
          unexpected("handoff result", $0)
        }
        next
      }
      allowed = operation == "negotiate" && status == "missing" && transport == selected
      allowed = allowed || (operation == "cleanup" && status == "valid" && transport == "tcp")
      allowed = allowed || (operation == "report" && status == "valid" && transport == "tcp")
      if (delta != 0 && !allowed) {
        unexpected("operation result", $0)
      }
    }
    END {
      upstream_fail = inject_fail + candidate_fail + stage_fail
      if (inject_total != wanted_requests || inject_valid != candidate_total ||
          candidate_valid != stage_total || retrieval_valid != wanted_valid ||
          handoff_valid > retrieval_valid ||
          wanted_valid + wanted_roots != wanted_requests) {
        printf "pressure bridge pipeline mismatch: requests=%d inject=%d/%d candidate=%d/%d stage=%d/%d retrieval=%d/%d handoff=%d expected_valid=%d roots=%d\n",
          wanted_requests, inject_valid, inject_total, candidate_valid, candidate_total,
          stage_valid, stage_total, retrieval_valid, retrieval_total,
          handoff_valid, wanted_valid, wanted_roots > "/dev/stderr"
        failed = 1
      }
      if (selected == "getsockopt") {
        if (stage_valid != retrieval_total ||
            upstream_fail + retrieval_fail != wanted_roots) {
          printf "getsockopt pressure root mismatch: upstream_failures=%d retrieval_failures=%d roots=%d stage_valid=%d retrieval_total=%d\n",
            upstream_fail, retrieval_fail, wanted_roots, stage_valid, retrieval_total > "/dev/stderr"
          failed = 1
        }
      } else if (retrieval_total != wanted_requests || retrieval_fail != wanted_roots ||
                 upstream_fail > wanted_roots) {
        printf "unix pressure root mismatch: upstream_failures=%d retrieval_failures=%d roots=%d retrieval_total=%d requests=%d\n",
          upstream_fail, retrieval_fail, wanted_roots, retrieval_total,
          wanted_requests > "/dev/stderr"
        failed = 1
      }
      if (failed) {
        exit 1
      }
      printf "{\"transport\":\"%s\",\"phase_outcome_counts\":{\"inject\":%d,\"candidate\":%d,\"stage\":%d,\"retrieval\":%d},", selected, inject_total, candidate_total, stage_total, retrieval_total
      printf "\"auxiliary_outcome_counts\":{\"handoff\":%d},", handoff_valid
      printf "\"retrieval_valid_count\":%d,\"upstream_failure_count\":%d,\"retrieval_failure_count\":%d,", retrieval_valid, upstream_fail, retrieval_fail
      printf "\"upstream_failure_reason_counts\":{\"missing\":%d,\"stale\":%d,\"ambiguous\":%d,\"malformed\":%d,\"overload\":%d,\"segmented\":%d},", upstream_reason["missing"], upstream_reason["stale"], upstream_reason["ambiguous"], upstream_reason["malformed"], upstream_reason["overload"], upstream_reason["segmented"]
      printf "\"retrieval_failure_reason_counts\":{\"missing\":%d,\"stale\":%d,\"unsupported\":%d,\"malformed\":%d,\"version_mismatch\":%d,\"ambiguous\":%d,\"unauthorized\":%d,\"already_consumed\":%d,\"timeout\":%d,\"overload\":%d,\"transport_error\":%d,\"disabled\":%d}}\n", retrieval_reason["missing"], retrieval_reason["stale"], retrieval_reason["unsupported"], retrieval_reason["malformed"], retrieval_reason["version_mismatch"], retrieval_reason["ambiguous"], retrieval_reason["unauthorized"], retrieval_reason["already_consumed"], retrieval_reason["timeout"], retrieval_reason["overload"], retrieval_reason["transport_error"], retrieval_reason["disabled"]
    }
  ' "$input"
}

assert_bridge_metric_delta() {
  local -r input="$1"
  local -r transport="$2"
  local -r expected_takes="$3"
  local -r expected_discards="$4"
  local -r expected_missing="${5:-0}"

  awk \
    -v selected="$transport" \
    -v wanted_takes="$expected_takes" \
    -v wanted_discards="$expected_discards" \
    -v wanted_missing="$expected_missing" \
    -v allow_primary_security="$ALLOW_PRIMARY_SECURITY_METRICS" \
    -v allow_unix_security="$ALLOW_UNIX_SECURITY_METRICS" '
    function label(line, name, value) {
      value = line
      sub("^.*" name "=\"", "", value)
      sub("\".*$", "", value)
      return value
    }
    /^obi_java_remote_parent_operations_total/ {
      operation = label($0, "operation")
      status = label($0, "status")
      transport = label($0, "transport")
      delta = ""
      for (field = 1; field <= NF; field++) {
        if ($field ~ /^delta=/) {
          delta = $field
          sub(/^delta=/, "", delta)
        }
      }
      if (delta !~ /^-?[0-9]+$/ || delta < 0) {
        printf "invalid bridge metric delta: %s\n", $0 > "/dev/stderr"
        failed = 1
        next
      }
      if (operation == "take" || operation == "discard") {
        security_allowed = allow_primary_security == "true" &&
          operation == "take" && status == "unauthorized" &&
          transport == "getsockopt" && selected == "getsockopt"
        security_allowed = security_allowed || (allow_unix_security == "true" &&
          operation == "take" && status == "unauthorized" &&
          transport == "unix" && selected == "unix")
        if (transport == selected && status == "valid") {
          if (operation == "take") {
            takes += delta
          } else {
            discards += delta
          }
        } else if (transport == selected && operation == "take" && status == "missing") {
          missing += delta
        } else if (delta != 0 && !security_allowed) {
          printf "unexpected bridge retrieval result: %s\n", $0 > "/dev/stderr"
          failed = 1
        }
        next
      }
      if (transport == "tcp" && status == "valid") {
        if (operation == "candidate") {
          candidates += delta
        } else if (operation == "inject") {
          injections += delta
        } else if (operation == "stage") {
          stages += delta
        }
      }
      allowed = operation == "candidate" && transport == "tcp" && status == "valid"
      allowed = allowed || (operation == "inject" && transport == "tcp" && status == "valid")
      allowed = allowed || (operation == "stage" && transport == "tcp" && status == "valid")
      allowed = allowed || (operation == "negotiate" && status == "missing" && transport == selected)
      allowed = allowed || (allow_primary_security == "true" && operation == "negotiate" &&
        status == "unauthorized" && transport == "getsockopt" && selected == "getsockopt")
      allowed = allowed || (operation == "candidate" && status == "ambiguous" && transport == "tcp")
      allowed = allowed || (operation == "cleanup" && status == "valid" && transport == "tcp")
      allowed = allowed || (operation == "report" && status == "valid" && transport == "tcp")
      if (delta != 0 && !allowed) {
        printf "unexpected bridge operation result: %s\n", $0 > "/dev/stderr"
        failed = 1
      }
    }
    END {
      if (candidates != wanted_takes || injections != wanted_takes || stages != wanted_takes ||
          takes != wanted_takes || discards != wanted_discards || missing != wanted_missing) {
        printf "expected lifecycle=%d/%d/%d %s take/valid=%d discard/valid=%d take/missing=%d, got lifecycle=%d/%d/%d take=%d discard=%d missing=%d\n",
          wanted_takes, wanted_takes, wanted_takes, selected,
          wanted_takes, wanted_discards, wanted_missing,
          candidates, injections, stages, takes, discards, missing > "/dev/stderr"
        failed = 1
      }
      exit failed ? 1 : 0
    }
  ' "$input"
}

assert_primary_security_metric_delta() {
  local -r input="$1"
  local -r operation="$2"
  local -r minimum="$3"
  local -r maximum="${4:-}"

  assert_security_metric_delta \
    "$input" "$operation" unauthorized getsockopt "$minimum" "$maximum"
}

assert_security_metric_delta() {
  local -r input="$1"
  local -r operation="$2"
  local -r status="$3"
  local -r transport="$4"
  local -r minimum="$5"
  local -r maximum="${6:-}"

  awk \
    -v wanted_operation="$operation" \
    -v wanted_status="$status" \
    -v wanted_transport="$transport" \
    -v minimum="$minimum" \
    -v maximum="$maximum" '
    index($0, "operation=\"" wanted_operation "\"") &&
    index($0, "status=\"" wanted_status "\"") &&
    index($0, "transport=\"" wanted_transport "\"") {
      for (field = 1; field <= NF; field++) {
        if ($field ~ /^delta=/) {
          value = $field
          sub(/^delta=/, "", value)
          if (value !~ /^[0-9]+$/) {
            printf "invalid security metric delta: %s\n", $0 > "/dev/stderr"
            failed = 1
          } else {
            total += value
          }
        }
      }
    }
    END {
      if (total < minimum) {
        printf "expected %s/%s %s delta >= %d, got %d\n",
          wanted_operation, wanted_status, wanted_transport, minimum, total > "/dev/stderr"
        failed = 1
      }
      if (maximum != "" && total > maximum) {
        printf "expected %s/%s %s delta <= %d, got %d\n",
          wanted_operation, wanted_status, wanted_transport, maximum, total > "/dev/stderr"
        failed = 1
      }
      exit failed ? 1 : 0
    }
  ' "$input"
}

diagnostic_counter() {
  local -r input="$1"
  local -r wanted="$2"
  local snapshot=""
  local entry=""
  local name=""
  local encoded=""
  local -a entries=()

  IFS= read -r snapshot <"$input" || true
  IFS=',' read -r -a entries <<<"$snapshot"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    encoded="${entry#*=}"
    if [[ "$name" == "$wanted" && "$encoded" =~ ^[0-9a-z]+$ ]]; then
      printf '%d\n' "$((36#$encoded))"
      return 0
    fi
  done
  return 1
}

write_java_diagnostics_delta() {
  local -r before="$1"
  local -r after="$2"
  local -r output="$3"
  local name=""
  local before_value=""
  local after_value=""
  local -a names=(
    provider_reject provider_ver lookup_missing lookup_version lookup_error
    record_version invoke_error discard_standard extract_fields extract_invalid
    extract_error registration_fail take_sampled take_unsampled
  )
  local -a statuses=(
    unknown valid missing stale unsupported malformed version_mismatch ambiguous
    unauthorized already_consumed timeout overload transport_error disabled
  )
  local status=""

  for status in "${statuses[@]}"; do
    names+=("t_$status" "d_$status")
  done
  : >"$output"
  for name in "${names[@]}"; do
    before_value="$(diagnostic_counter "$before" "$name")" || return 1
    after_value="$(diagnostic_counter "$after" "$name")" || return 1
    ((after_value >= before_value)) || return 1
    printf '%s before=%d after=%d delta=%d\n' \
      "$name" "$before_value" "$after_value" "$((after_value - before_value))" \
      >>"$output"
  done
}

java_diagnostic_delta() {
  local -r input="$1"
  local -r wanted="$2"

  awk -v wanted="$wanted" -v maximum="$JAVA_DIAGNOSTIC_COUNTER_MAX" '
    $1 == wanted {
      for (field = 1; field <= NF; field++) {
        if ($field ~ /^delta=/) {
          sub(/^delta=/, "", $field)
          if ($field !~ /^(0|[1-9][0-9]*)$/ ||
              length($field) > length(maximum) ||
              (length($field) == length(maximum) && $field > maximum)) {
            invalid = 1
            exit
          }
          print $field
          found = 1
          exit
        }
      }
    }
    END { if (!found || invalid) exit 1 }
  ' "$input"
}

assert_java_diagnostics_delta_schema() {
  local -r input="$1"

  awk -v maximum="$JAVA_DIAGNOSTIC_COUNTER_MAX" '
    BEGIN {
      fixed_names = "provider_reject provider_ver lookup_missing lookup_version lookup_error "
      fixed_names = fixed_names "record_version invoke_error discard_standard extract_fields "
      fixed_names = fixed_names "extract_invalid extract_error registration_fail take_sampled "
      fixed_names = fixed_names "take_unsampled"
      fixed_count = split(fixed_names, fixed)
      for (position = 1; position <= fixed_count; position++) {
        expected[++expected_count] = fixed[position]
      }
      status_names = "unknown valid missing stale unsupported malformed version_mismatch "
      status_names = status_names "ambiguous unauthorized already_consumed timeout overload "
      status_names = status_names "transport_error disabled"
      status_count = split(status_names, statuses)
      for (position = 1; position <= status_count; position++) {
        expected[++expected_count] = "t_" statuses[position]
        expected[++expected_count] = "d_" statuses[position]
      }
    }
    function bounded(value) {
      return value ~ /^(0|[1-9][0-9]*)$/ &&
        length(value) <= length(maximum) &&
        (length(value) < length(maximum) || value <= maximum)
    }
    {
      if (NF != 4 || FNR > expected_count || $1 != expected[FNR]) {
        invalid = 1
        next
      }
      before = $2
      after = $3
      delta = $4
      if (sub(/^before=/, "", before) != 1 ||
          sub(/^after=/, "", after) != 1 ||
          sub(/^delta=/, "", delta) != 1 ||
          !bounded(before) || !bounded(after) || !bounded(delta) ||
          after + 0 < before + 0 ||
          delta + 0 != (after + 0) - (before + 0)) {
        invalid = 1
      }
    }
    END { if (invalid || FNR != expected_count) exit 1 }
  ' "$input"
}

assert_java_diagnostics_delta() {
  local -r input="$1"
  local -r expected_valid="$2"
  local -r expected_stale="$3"
  local -r expected_malformed="$4"
  local -r expected_missing="$5"
  local -r expected_sampled="$6"
  local -r expected_unsampled="$7"
  local -r expected_standard="$8"
  local -r expected_fault_status="${9:-}"
  local -r expected_fault_count="${10:-0}"
  local name=""
  local actual=""
  local expected=""
  local actual_missing=0
  local actual_already_consumed=0
  local expected_missing_fault=0
  local expected_already_consumed_fault=0
  local absence_missing=0
  local absence_already_consumed=0
  local -a failure_counters=(
    provider_reject provider_ver lookup_missing lookup_version lookup_error
    record_version invoke_error extract_fields extract_invalid extract_error
    registration_fail
  )

  if ! assert_java_diagnostics_delta_schema "$input"; then
    log_error "Java diagnostics delta did not contain the exact counter schema"
    return 1
  fi

  case "$expected_fault_status" in
    missing) expected_missing_fault="$expected_fault_count" ;;
    already_consumed) expected_already_consumed_fault="$expected_fault_count" ;;
  esac

  while IFS= read -r name; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    expected=0
    case "$name" in
      t_valid) expected="$expected_valid" ;;
      t_missing)
        actual_missing="$actual"
        continue
        ;;
      t_already_consumed)
        actual_already_consumed="$actual"
        continue
        ;;
      t_stale) expected="$expected_stale" ;;
      t_malformed) expected="$expected_malformed" ;;
      "t_$expected_fault_status") expected="$expected_fault_count" ;;
    esac
    if [[ "$actual" != "$expected" ]]; then
      log_error "Java diagnostics expected $name=$expected, got $actual"
      return 1
    fi
  done < <(awk '$1 ~ /^[td]_/ { print $1 }' "$input")

  if ((actual_missing < expected_missing_fault ||
    actual_already_consumed < expected_already_consumed_fault)); then
    log_error \
      "Java diagnostics did not report the expected attributable absence fault"
    return 1
  fi
  absence_missing="$((actual_missing - expected_missing_fault))"
  absence_already_consumed="$((actual_already_consumed - expected_already_consumed_fault))"
  if ((absence_missing + absence_already_consumed != expected_missing ||
    absence_already_consumed > 1)); then
    log_error \
      "Java diagnostics expected absence total=$expected_missing with at most one already-consumed lookup after attributable faults, got missing=$absence_missing already_consumed=$absence_already_consumed"
    return 1
  fi

  for name in "${failure_counters[@]}"; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    if [[ "$actual" != "0" ]]; then
      log_error "Java diagnostics reported unexpected $name=$actual"
      return 1
    fi
  done
  for name in take_sampled take_unsampled discard_standard; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    case "$name" in
      take_sampled) expected="$expected_sampled" ;;
      take_unsampled) expected="$expected_unsampled" ;;
      discard_standard) expected="$expected_standard" ;;
    esac
    if [[ "$actual" != "$expected" ]]; then
      log_error "Java diagnostics expected $name=$expected, got $actual"
      return 1
    fi
  done
}

assert_restart_fault_diagnostics() {
  local -r input="$1"
  local -r expected_requests="$2"
  local -r output="$3"
  local name=""
  local actual=""
  local take_total=0
  local discard_total=0
  local valid=0
  local diagnostics_eligible=0
  local failure_total=0
  local take_sampled=""
  local discard_standard=""
  local -a failure_counters=(
    provider_reject provider_ver lookup_missing lookup_version lookup_error
    record_version invoke_error extract_fields extract_invalid extract_error
    registration_fail
  )

  if ! assert_java_diagnostics_delta_schema "$input"; then
    log_error "restart fault Java diagnostics delta did not contain the exact counter schema"
    return 1
  fi

  while IFS= read -r name; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    if [[ "$name" == t_* ]]; then
      take_total="$((take_total + actual))"
      if [[ "$name" == "t_valid" ]]; then
        valid="$actual"
      elif [[ "$name" == "t_missing" || "$name" == "t_already_consumed" ]]; then
        diagnostics_eligible="$((diagnostics_eligible + actual))"
      fi
    else
      discard_total="$((discard_total + actual))"
    fi
  done < <(awk '$1 ~ /^[td]_/ { print $1 }' "$input")
  for name in "${failure_counters[@]}"; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    failure_total="$((failure_total + actual))"
  done
  take_sampled="$(java_diagnostic_delta "$input" take_sampled)" || return 1
  discard_standard="$(java_diagnostic_delta "$input" discard_standard)" || return 1

  if ((take_total != expected_requests + 1 || diagnostics_eligible == 0 ||
    valid < 2 || valid >= expected_requests)); then
    log_error \
      "restart fault expected $expected_requests workload takes plus one probe with conservatively provable valid and fail-open workload results, got total=$take_total valid=$valid diagnostics_eligible=$diagnostics_eligible"
    return 1
  fi
  if ((discard_total != 0)); then
    log_error "restart fault produced unexpected discard status count=$discard_total"
    return 1
  fi
  if ((failure_total > expected_requests || take_sampled > expected_requests || discard_standard > expected_requests)); then
    log_error "restart fault diagnostics exceeded the request bound"
    return 1
  fi
  {
    printf 'status=passed\n'
    printf 'requests=%d\n' "$expected_requests"
    printf 'observed_take_total=%d\n' "$take_total"
    printf 'observed_take_valid=%d\n' "$valid"
    printf 'workload_valid_min=%d\n' "$((valid - 1))"
    printf 'workload_valid_max=%d\n' "$valid"
    printf 'workload_fail_open_min=%d\n' "$((expected_requests - valid))"
    printf 'workload_fail_open_max=%d\n' "$((expected_requests - valid + 1))"
    printf 'failure_total=%d\n' "$failure_total"
    printf 'take_sampled=%d\n' "$take_sampled"
    printf 'discard_standard=%d\n' "$discard_standard"
  } >"$output"
}

capture_evidence() {
  if [[ "$STACK_STARTED" == "true" ]]; then
    capture_phase_evidence "final"
    capture_java_diagnostics "final"
  fi
  run_bounded 30 "${COMPOSE[@]}" ps --all >"$RESULT_DIR/compose-ps.txt" 2>&1 || true
  run_bounded 30 "${COMPOSE[@]}" logs --no-color --tail 10000 >"$RESULT_DIR/compose.log" 2>&1 || true
  curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:14318/snapshot" >"$RESULT_DIR/final-receiver-snapshot.json" 2>/dev/null || true
}

write_run_status() {
  local -r exit_status="$1"
  local failure_stage="${FAILURE_STAGE:-none}"
  local failure_line="${FAILURE_LINE:-0}"
  local status="failed"

  if ((exit_status == 0)) && [[ "$RUN_STATUS" == "passed" ]]; then
    status="passed"
  fi
  printf '{\n  "status": "%s",\n  "exit_status": %d,\n  "acceptance_evidence": %s,\n  "failure_stage": "%s",\n  "failure_line": %d,\n  "evidence_directory": "%s"\n}\n' \
    "$status" \
    "$exit_status" \
    "$ACCEPTANCE_EVIDENCE" \
    "$failure_stage" \
    "$failure_line" \
    "$RESULT_DIR" >"$RESULT_DIR/run-status.json"
}

cleanup_only() {
  log_info "stopping scoped Compose project $PROJECT_NAME"
  safe_compose_down
}

main() {
  printf -v RUN_INVOCATION '%q ' "$0" "$@"
  RUN_INVOCATION="${RUN_INVOCATION% }"
  install_traps
  RUN_STAGE="argument-validation"
  parse_args "$@"
  check_dependencies

  if [[ "$CLEANUP_ONLY" == "true" ]]; then
    cleanup_only
    return 0
  fi

  RUN_STAGE="runtime-preparation"
  prepare_directories
  RUN_STAGE="source-state"
  capture_source_state
  RUN_STAGE="certificates"
  prepare_certificates
  RUN_STAGE="official-agent"
  prepare_official_agent
  RUN_STAGE="bridge-artifacts"
  prepare_bridge_artifacts
  RUN_STAGE="compose-environment"
  export_compose_environment
  RUN_STAGE="environment-evidence"
  capture_environment
  start_stack
  RUN_STAGE="runtime-evidence"
  capture_runtime_evidence
  RUN_STAGE="scenarios"
  execute_requested_scenarios
  RUN_STATUS="passed"
  RUN_STAGE="complete"
  log_info "all requested assertions passed; evidence: $RESULT_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
