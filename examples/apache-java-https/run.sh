#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
# Start with inherited job control disabled. The relay enables it only around
# the guarded holder launch to create one private, identity-checked process
# group for flock and every worker descendant.
set +m

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
MAX_SHELL_INTEGER="9223372036854775807"
MAX_JSON_SAFE_INTEGER="9007199254740991"
MAX_UINT32_DECIMAL="4294967295"
MAX_UINT64_DECIMAL="18446744073709551615"
JAVA_DIAGNOSTIC_COUNTER_MAX="999999999"
TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES=16384
TERMINAL_JAVA_DIAGNOSTICS_MAX_LINES=1
TERMINAL_JAVA_DIAGNOSTICS_LOCK_TIMEOUT_SECONDS=5
OBI_METRIC_PAIR_MAX_BYTES=131072
OBI_TERMINAL_BOUNDARY_MAX_BYTES=155648
OBI_METRIC_BOUNDARY_INDEX_MAX_BYTES=4194304
OBI_METRIC_BOUNDARY_INDEX_MAX_BOUNDARIES=256
OBI_METRIC_BOUNDARY_INDEX_MAX_CAPTURES=4096
OBI_METRIC_BOUNDARY_INDEX_MAX_STATUS_REFERENCES=1024
OBI_METRIC_BOUNDARY_STATUS_MAX_BYTES=262144
OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES=536870912
OBI_PROCESS_IDENTITY_MAX_BYTES=2048
OBI_METRIC_PAIR_MAX_SERIES=792
OBI_METRIC_SNAPSHOT_MAX_BYTES=8388608
OBI_METRIC_SNAPSHOT_MAX_LINES=20000
BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS=35
JAVA_PROVIDER_RETRY_SETTLE_SECONDS=2
JAVA_DUPLICATE_SUPPRESSION_PRIME_INTERVAL_SECONDS=5
PRIMARY_W3C_STALE_RETRIEVAL_TTL="1ns"
UNIX_W3C_STALE_RETRIEVAL_TTL="1ns"
JAVA_ATTACH_FAILURE_QUIET_SAMPLES=15
OBI_COMPOSE_STOP_GRACE_SECONDS=30
OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS=60
# Compose may apply the stop grace once per service in reverse dependency
# order. The full five-service down path therefore needs a larger outer bound.
OBI_COMPOSE_MULTI_SERVICE_COMMAND_TIMEOUT_SECONDS=180
DELAYED_OTLP_SCHEDULE_DELAY_SECONDS=60
DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS="$((DELAYED_OTLP_SCHEDULE_DELAY_SECONDS * 1000))"
DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS=5
DELAYED_OTLP_PRE_EXPORT_SAFETY_SECONDS=1
DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS=70
DELAYED_OTLP_OBI_BATCH_TIMEOUT_SECONDS=15
DELAYED_OTLP_OBI_RETRY_MAX_ELAPSED_SECONDS=2
DELAYED_OTLP_OBI_EXPORT_TIMEOUT_SECONDS=5
DELAYED_OTLP_JAVA_RETRY_DISABLED=true
DELAYED_OTLP_CLOCK_QUANTIZATION_SECONDS=1
DELAYED_OTLP_BOUNDARY_POLL_SECONDS=1
DELAYED_OTLP_BOUNDARY_START_SLACK_SECONDS=1
DELAYED_OTLP_FETCH_KILL_GRACE_SECONDS=1
DELAYED_OTLP_NONCE_TIMEOUT_SECONDS=5
DELAYED_OTLP_POST_EXPORT_SETTLE_SECONDS="$((
  DELAYED_OTLP_OBI_BATCH_TIMEOUT_SECONDS +
    DELAYED_OTLP_OBI_RETRY_MAX_ELAPSED_SECONDS +
    DELAYED_OTLP_OBI_EXPORT_TIMEOUT_SECONDS +
    DELAYED_OTLP_CLOCK_QUANTIZATION_SECONDS
))"
DELAYED_OTLP_PRIME_MARKER_PREFIX="delayed-otlp-suppression-prime"
DELAYED_OTLP_PRIME_MARKER="$DELAYED_OTLP_PRIME_MARKER_PREFIX"
DELAYED_OTLP_JAVA_SERVER_SCOPE="io.opentelemetry.jetty-11.0"
HELPER_ATTACH_FAILURE_JAVA_TOOL_OPTIONS="-javaagent:/otel/official-javaagent.jar -XX:-EnableDynamicAgentLoading"
TRANSPORT_CONFIGURATION_MAX_BYTES=256
SCENARIO_RUN_TIMEOUT_SECONDS=120
PID_REUSE_CONTROLLER_TIMEOUT_SECONDS=150
PID_REUSE_CONTROLLER_INNER_TIMEOUT="120s"
PID_REUSE_RESULT_MAX_BYTES=4096
PID_REUSE_RESULT_MAX_LINES=1
PID_REUSE_STDERR_MAX_BYTES=65536
PID_REUSE_STDERR_MAX_LINES=512
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
RECEIVE_CURSOR_MAP_MAX_ENTRIES=10000
RECEIVE_CURSOR_MAP_RECOVERY_TIMEOUT_SECONDS=10
RECEIVE_CURSOR_MAP_RECOVERY_CONSECUTIVE_SAMPLES=2
RECEIVE_CURSOR_MAP_HELPER_TIMEOUT_SECONDS=60
RECEIVE_CURSOR_HELPER_STDOUT_MAX_BYTES=4096
RECEIVE_CURSOR_HELPER_STDOUT_MAX_LINES=1
RECEIVE_CURSOR_HELPER_STDERR_MAX_BYTES=65536
RECEIVE_CURSOR_HELPER_STDERR_MAX_LINES=512
PRESSURE_RESULT_MAX_BYTES=4096
PRESSURE_RESULT_MAX_LINES=1
SCENARIO_RECONCILIATION_MAX_BYTES=8388608
SCENARIO_RECONCILIATION_MAX_LINES=131072
# Sum explicit metric, readiness, Docker, release, and final-attempt overrun bounds.
SECURITY_PROBE_SCENARIO_BUDGET_SECONDS=232
SECURITY_PROBE_SAME_CGROUP_FIXED_BUDGET_SECONDS=193
SECURITY_PROBE_SIBLING_FIXED_BUDGET_SECONDS=408
PRIMARY_LIVE_FD_BARRIER_TIMEOUT_SECONDS=90
PRIMARY_LIVE_FD_PRE_RELEASE_DEADLINE_SECONDS=55
PRIMARY_LIVE_FD_BARRIER_READY_TIMEOUT_SECONDS=5
PRIMARY_LIVE_FD_PROBE_TIMEOUT_SECONDS=5
PRIMARY_LIVE_FD_METRICS_TIMEOUT_SECONDS=35
PRIMARY_LIVE_FD_METRIC_CAPTURE_TIMEOUT_SECONDS=5
PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS=5
PRIMARY_LIVE_FD_VICTIM_REQUEST_TIMEOUT_SECONDS=70
PRIMARY_LIVE_FD_VICTIM_SCENARIO_TIMEOUT_SECONDS=90
PRIMARY_LIVE_FD_VICTIM_STARTUP_BUDGET_SECONDS=30
PRIMARY_LIVE_FD_VICTIM_SUPERVISOR_SLACK_SECONDS=5
PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS="$((
  PRIMARY_LIVE_FD_VICTIM_SCENARIO_TIMEOUT_SECONDS +
  PRIMARY_LIVE_FD_VICTIM_STARTUP_BUDGET_SECONDS +
  PRIMARY_LIVE_FD_VICTIM_SUPERVISOR_SLACK_SECONDS
))"
PRIMARY_LIVE_FD_VICTIM_REAP_TIMEOUT_SECONDS=15
# The three duplicate-suppression readiness windows (preparation, explicit
# recovery, and EXIT recovery after a late failure) are accounted for
# separately because they follow READINESS_TIMEOUT_SECONDS.
PRIMARY_LIVE_FD_FIXED_BUDGET_SECONDS=200
GENERATION_FAULT_HELPER_TIMEOUT_SECONDS=60
GENERATION_FAULT_RELEASE_TIMEOUT_SECONDS=45
GENERATION_FAULT_READY_TIMEOUT_SECONDS=10
GENERATION_FAULT_TAKE_FENCE_TIMEOUT_SECONDS=4
GENERATION_FAULT_REAP_TIMEOUT_SECONDS=10
GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS=55
UNIX_GENERATION_BARRIER_TIMEOUT_SECONDS=25
UNIX_GENERATION_BARRIER_READY_TIMEOUT_SECONDS=5
UNIX_GENERATION_FAULT_TIMEOUT_SECONDS=30
UNIX_GENERATION_FAULT_TIMEOUT_MILLISECONDS=30000
UNIX_GENERATION_DEADLINE_SLACK_SECONDS=5
UNIX_GENERATION_BACKEND_HOLD_SECONDS=20
UNIX_GENERATION_PROXY_TIMEOUT_SECONDS=45
UNIX_GENERATION_SCENARIO_TIMEOUT_SECONDS=75
PERMANENT_ABSENCE_REGISTRATION_FAILURE_MAX=32
PERMANENT_ABSENCE_REMOTE_PARENT_LOG_MAX=64
PERMANENT_ABSENCE_LOG_MAX_BYTES=1048576
PERMANENT_ABSENCE_LOG_MAX_LINES=10000
PERMANENT_ABSENCE_LOG_CAPTURE_TIMEOUT_SECONDS=30
AUTO_UNAVAILABLE_CONFIGURATION_MAX_ATTEMPTS=8
AUTO_UNAVAILABLE_REGISTRATION_FAILURE_MAX=12
AUTO_UNAVAILABLE_TAKE_MIN=5
AUTO_UNAVAILABLE_TAKE_MAX=16
COMPOSE_LOG_MAX_BYTES=1048576
COMPOSE_LOG_MAX_LINES=10000
COMPOSE_LOG_CAPTURE_TIMEOUT_SECONDS=30
DIAGNOSTIC_NONDISCLOSURE_OBI_LOG_MAX_BYTES=2097152
DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_BYTES=16384
DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_LINES=256
DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_COUNT=128
DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_BYTES=16384
DIAGNOSTIC_NONDISCLOSURE_CANARY_SOURCE_MAX_BYTES=1048576
DIAGNOSTIC_NONDISCLOSURE_CANARY_SOURCE_MAX_LINES=10000
DIAGNOSTIC_NONDISCLOSURE_REPORT_MAX_BYTES=32768
DIAGNOSTIC_NONDISCLOSURE_TRACE_ID="d139f67e43a24c51b87e02d964af3501"
DIAGNOSTIC_NONDISCLOSURE_PARENT_SPAN_ID="a18c45067b29de03"
DIAGNOSTIC_NONDISCLOSURE_MARKER="issue39-nondisclosure-marker"
DIAGNOSTIC_NONDISCLOSURE_HEADER_CANARY="issue39privateheadervalue"
DIAGNOSTIC_NONDISCLOSURE_BODY_CANARY="issue39privatebodyvalue"
DIAGNOSTIC_NONDISCLOSURE_CREDENTIAL_CANARY="issue39syntheticcredential"
DIAGNOSTIC_NONDISCLOSURE_UNIX_PAYLOAD_CANARY="OBI_SECURITY_PROBE_PAYLOAD_CANARY"
DOCKER_SERVER_ID_MAX_BYTES=1024
PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS=300
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
UNIX_SECURITY_STATUS_SEPARATOR="__OBI_UNIX_SECURITY_STATUS_BOUNDARY_V1__"
RESTART_CONTROL_CONTAINER_DIR="/run/obi-demo/restart-control"
RESTART_SIGNAL_PRE_STOP_READY="pre-stop-ready"
RESTART_SIGNAL_STOPPED_TRAFFIC_COMPLETE="stopped-traffic-complete"
RESTART_SIGNAL_POST_RESTART_TRAFFIC_COMPLETE="post-restart-traffic-complete"
RESTART_RELEASE_OBI_STOPPED="obi-stopped"
RESTART_RELEASE_OBI_READY="obi-ready"
PRIMARY_FAULT_PRELOAD="/otel/libobi-java-remote-parent-fault.so"
PRIMARY_FAULT_CONTROL_DIRECTORY="/run/obi-demo/fault"
PRIMARY_FAULT_CONTROL_FILE="$PRIMARY_FAULT_CONTROL_DIRECTORY/java-remote-parent.mode"
readonly SCRIPT_DIR REPO_ROOT SCRIPT_NAME MAX_SHELL_INTEGER MAX_JSON_SAFE_INTEGER
readonly MAX_UINT32_DECIMAL
readonly MAX_UINT64_DECIMAL JAVA_DIAGNOSTIC_COUNTER_MAX
readonly TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES
readonly TERMINAL_JAVA_DIAGNOSTICS_MAX_LINES
readonly TERMINAL_JAVA_DIAGNOSTICS_LOCK_TIMEOUT_SECONDS
readonly OBI_METRIC_PAIR_MAX_BYTES OBI_TERMINAL_BOUNDARY_MAX_BYTES
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_BYTES
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_BOUNDARIES
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_CAPTURES
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_STATUS_REFERENCES
readonly OBI_METRIC_BOUNDARY_STATUS_MAX_BYTES
readonly OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES
readonly OBI_PROCESS_IDENTITY_MAX_BYTES OBI_METRIC_PAIR_MAX_SERIES
readonly OBI_METRIC_SNAPSHOT_MAX_BYTES OBI_METRIC_SNAPSHOT_MAX_LINES
readonly BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS SCENARIO_RUN_TIMEOUT_SECONDS
readonly PID_REUSE_CONTROLLER_TIMEOUT_SECONDS
readonly PID_REUSE_CONTROLLER_INNER_TIMEOUT
readonly PID_REUSE_RESULT_MAX_BYTES PID_REUSE_RESULT_MAX_LINES
readonly PID_REUSE_STDERR_MAX_BYTES PID_REUSE_STDERR_MAX_LINES
readonly JAVA_PROVIDER_RETRY_SETTLE_SECONDS
readonly JAVA_DUPLICATE_SUPPRESSION_PRIME_INTERVAL_SECONDS
readonly PRIMARY_W3C_STALE_RETRIEVAL_TTL UNIX_W3C_STALE_RETRIEVAL_TTL
readonly JAVA_ATTACH_FAILURE_QUIET_SAMPLES
readonly OBI_COMPOSE_STOP_GRACE_SECONDS
readonly OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS
readonly OBI_COMPOSE_MULTI_SERVICE_COMMAND_TIMEOUT_SECONDS
readonly DELAYED_OTLP_SCHEDULE_DELAY_SECONDS
readonly DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS
readonly DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS
readonly DELAYED_OTLP_PRE_EXPORT_SAFETY_SECONDS
readonly DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS
readonly DELAYED_OTLP_OBI_BATCH_TIMEOUT_SECONDS
readonly DELAYED_OTLP_OBI_RETRY_MAX_ELAPSED_SECONDS
readonly DELAYED_OTLP_OBI_EXPORT_TIMEOUT_SECONDS
readonly DELAYED_OTLP_JAVA_RETRY_DISABLED
readonly DELAYED_OTLP_CLOCK_QUANTIZATION_SECONDS
readonly DELAYED_OTLP_BOUNDARY_POLL_SECONDS
readonly DELAYED_OTLP_BOUNDARY_START_SLACK_SECONDS
readonly DELAYED_OTLP_FETCH_KILL_GRACE_SECONDS
readonly DELAYED_OTLP_NONCE_TIMEOUT_SECONDS
readonly DELAYED_OTLP_POST_EXPORT_SETTLE_SECONDS
readonly DELAYED_OTLP_PRIME_MARKER_PREFIX
readonly DELAYED_OTLP_JAVA_SERVER_SCOPE
readonly HELPER_ATTACH_FAILURE_JAVA_TOOL_OPTIONS
readonly TRANSPORT_CONFIGURATION_MAX_BYTES
readonly PRESSURE_STATE_TIMEOUT_SECONDS PRESSURE_MONITOR_METRICS_TIMEOUT_SECONDS
readonly PRESSURE_MONITOR_POLL_INTERVAL_SECONDS PRESSURE_MONITOR_COMPLETION_SLACK_SECONDS
readonly PRESSURE_MONITOR_COMPLETION_TIMEOUT_SECONDS
readonly PRESSURE_ENTRY_TTL_SECONDS
readonly PRESSURE_RECOVERY_TIMEOUT_SECONDS PRESSURE_RECOVERY_CONSECUTIVE_SAMPLES
readonly PRESSURE_HELPER_TIMEOUT_SECONDS PRESSURE_CLEANUP_MAX_ATTEMPTS
readonly PRESSURE_CLEANUP_DEADLINE_SECONDS PRESSURE_MAX_ENTRIES
readonly RECEIVE_CURSOR_MAP_MAX_ENTRIES
readonly RECEIVE_CURSOR_MAP_RECOVERY_TIMEOUT_SECONDS
readonly RECEIVE_CURSOR_MAP_RECOVERY_CONSECUTIVE_SAMPLES
readonly RECEIVE_CURSOR_MAP_HELPER_TIMEOUT_SECONDS
readonly RECEIVE_CURSOR_HELPER_STDOUT_MAX_BYTES
readonly RECEIVE_CURSOR_HELPER_STDOUT_MAX_LINES
readonly RECEIVE_CURSOR_HELPER_STDERR_MAX_BYTES
readonly RECEIVE_CURSOR_HELPER_STDERR_MAX_LINES
readonly PRESSURE_RESULT_MAX_BYTES PRESSURE_RESULT_MAX_LINES
readonly SCENARIO_RECONCILIATION_MAX_BYTES
readonly SCENARIO_RECONCILIATION_MAX_LINES
readonly SECURITY_PROBE_SCENARIO_BUDGET_SECONDS
readonly SECURITY_PROBE_SAME_CGROUP_FIXED_BUDGET_SECONDS
readonly SECURITY_PROBE_SIBLING_FIXED_BUDGET_SECONDS
readonly PRIMARY_LIVE_FD_BARRIER_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_PRE_RELEASE_DEADLINE_SECONDS
readonly PRIMARY_LIVE_FD_BARRIER_READY_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_PROBE_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_METRICS_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_METRIC_CAPTURE_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_VICTIM_REQUEST_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_VICTIM_SCENARIO_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_VICTIM_STARTUP_BUDGET_SECONDS
readonly PRIMARY_LIVE_FD_VICTIM_SUPERVISOR_SLACK_SECONDS
readonly PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_VICTIM_REAP_TIMEOUT_SECONDS
readonly PRIMARY_LIVE_FD_FIXED_BUDGET_SECONDS
readonly GENERATION_FAULT_HELPER_TIMEOUT_SECONDS GENERATION_FAULT_READY_TIMEOUT_SECONDS
readonly GENERATION_FAULT_RELEASE_TIMEOUT_SECONDS GENERATION_FAULT_REAP_TIMEOUT_SECONDS
readonly GENERATION_FAULT_TAKE_FENCE_TIMEOUT_SECONDS
readonly GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS
readonly UNIX_GENERATION_BARRIER_TIMEOUT_SECONDS
readonly UNIX_GENERATION_BARRIER_READY_TIMEOUT_SECONDS
readonly UNIX_GENERATION_FAULT_TIMEOUT_SECONDS
readonly UNIX_GENERATION_FAULT_TIMEOUT_MILLISECONDS
readonly UNIX_GENERATION_DEADLINE_SLACK_SECONDS
readonly UNIX_GENERATION_BACKEND_HOLD_SECONDS
readonly UNIX_GENERATION_PROXY_TIMEOUT_SECONDS
readonly UNIX_GENERATION_SCENARIO_TIMEOUT_SECONDS
readonly PERMANENT_ABSENCE_REGISTRATION_FAILURE_MAX
readonly PERMANENT_ABSENCE_REMOTE_PARENT_LOG_MAX
readonly PERMANENT_ABSENCE_LOG_MAX_BYTES PERMANENT_ABSENCE_LOG_MAX_LINES
readonly PERMANENT_ABSENCE_LOG_CAPTURE_TIMEOUT_SECONDS
readonly AUTO_UNAVAILABLE_CONFIGURATION_MAX_ATTEMPTS
readonly AUTO_UNAVAILABLE_REGISTRATION_FAILURE_MAX
readonly AUTO_UNAVAILABLE_TAKE_MIN AUTO_UNAVAILABLE_TAKE_MAX
readonly COMPOSE_LOG_MAX_BYTES COMPOSE_LOG_MAX_LINES
readonly COMPOSE_LOG_CAPTURE_TIMEOUT_SECONDS
readonly DIAGNOSTIC_NONDISCLOSURE_OBI_LOG_MAX_BYTES
readonly DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_BYTES
readonly DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_LINES
readonly DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_COUNT
readonly DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_BYTES
readonly DIAGNOSTIC_NONDISCLOSURE_CANARY_SOURCE_MAX_BYTES
readonly DIAGNOSTIC_NONDISCLOSURE_CANARY_SOURCE_MAX_LINES
readonly DIAGNOSTIC_NONDISCLOSURE_REPORT_MAX_BYTES
readonly DIAGNOSTIC_NONDISCLOSURE_TRACE_ID
readonly DIAGNOSTIC_NONDISCLOSURE_PARENT_SPAN_ID
readonly DIAGNOSTIC_NONDISCLOSURE_MARKER
readonly DIAGNOSTIC_NONDISCLOSURE_HEADER_CANARY
readonly DIAGNOSTIC_NONDISCLOSURE_BODY_CANARY
readonly DIAGNOSTIC_NONDISCLOSURE_CREDENTIAL_CANARY
readonly DIAGNOSTIC_NONDISCLOSURE_UNIX_PAYLOAD_CANARY
readonly DOCKER_SERVER_ID_MAX_BYTES
readonly PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS
readonly SECURITY_PROBE_TIMEOUT_SLACK_SECONDS
readonly MAX_SECURITY_PROBE_TIMEOUT_SECONDS PROJECT_NAMESPACE
readonly PROJECT_SENTINEL_LABEL PROJECT_SENTINEL_VALUE APACHE_EXPECTED_PROCESS_COUNT
readonly APACHE_HTTPS_HEALTH_ENDPOINT
readonly PRIMARY_SECURITY_PROBE_PATH PRIMARY_SECURITY_PID_PATH
readonly UNIX_PERMISSION_REFUSAL_PATTERN
readonly UNIX_SECURITY_STATUS_SEPARATOR
readonly RESTART_CONTROL_CONTAINER_DIR
readonly RESTART_SIGNAL_PRE_STOP_READY RESTART_SIGNAL_STOPPED_TRAFFIC_COMPLETE
readonly RESTART_SIGNAL_POST_RESTART_TRAFFIC_COMPLETE
readonly RESTART_RELEASE_OBI_STOPPED RESTART_RELEASE_OBI_READY
readonly PRIMARY_FAULT_PRELOAD PRIMARY_FAULT_CONTROL_DIRECTORY PRIMARY_FAULT_CONTROL_FILE

RUNTIME_DIR="$SCRIPT_DIR/.runtime"
ARTIFACT_DIR="$RUNTIME_DIR/artifacts"
CERT_DIR="$RUNTIME_DIR/certs"
RESULTS_ROOT="$RUNTIME_DIR/results"
SOURCE_SNAPSHOT_PARENT="/tmp"
readonly SOURCE_SNAPSHOT_PARENT
PROJECT_GUARD_ROOT="/tmp/obi-apache-java-https-project-guard-$EUID"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
PRIMARY_FAULT_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.primary-fault.yml"
PRIMARY_LIVE_FD_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.primary-live-fd.yml"
UNIX_GENERATION_FAULT_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.unix-generation-fault.yml"
PID_REUSE_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.pid-reuse.yml"
COMPOSE_PROJECT_DIRECTORY="$SCRIPT_DIR"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$PROJECT_NAMESPACE}"

TRANSPORT="getsockopt"
REMOTE_PARENT_TTL="30s"
REMOTE_PARENT_RETRIEVAL_TTL="0s"
AGENT_DISTRIBUTION="otel"
TLS_PROTOCOL="TLSv1.3"
OBI_LOG_LEVEL="info"
SCENARIO="all"
KEEP_RUNNING=false
SKIP_BRIDGE_BUILD=false
CLEANUP_ONLY=false
COMMAND_TIMEOUT_SECONDS=1200
READINESS_TIMEOUT_SECONDS=90
REQUEST_COUNT=0
REPEAT_COUNT=1
SCENARIO_SEED=1
BRIDGE_EXPORT_DIR=""
RESULT_DIR=""
SOURCE_SNAPSHOT_DIR=""
SOURCE_SNAPSHOT_SCRIPT_DIR=""
SOURCE_SNAPSHOT_WORK_DIR=""
STACK_STARTED=false
SOURCE_DIRTY=""
SOURCE_PATCH_SHA256=""
SOURCE_REVISION=""
SOURCE_TRACKED_PATCH_SHA256=""
SOURCE_TREE_SHA256=""
SOURCE_TREE_MANIFEST_SCHEMA=""
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
OBI_RUNNING=false
OBI_METRIC_BOUNDARY_ACTIVE_ID=""
OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD=""
OBI_METRIC_BOUNDARY_FROZEN_SHA256=""
MATCHING_BRIDGE_RUNNING=false
FAULT_BRIDGE_RUNNING=false
SELECTED_TRANSPORT=""
CONTEXT_PROPAGATION="tcp"
RUN_STATUS="failed"
RUN_STATUS_CREATED_IDENTITY=""
RUN_STATUS_PUBLISHED_DIGEST=""
RUN_STATUS_PUBLISHED_IDENTITY=""
RUN_STATUS_PUBLICATION_HANDLE=""
RUN_STATUS_PUBLICATION_OUTPUT=""
RUN_STATUS_PUBLICATION_STATE=""
PRESSURE_ACTIVE=false
PRESSURE_MAP_ID=""
PRESSURE_MAP_MAX_ENTRIES=""
PRESSURE_MAP_BASELINE_ENTRIES=""
PRESSURE_CAPACITY_REJECTED_ENTRIES=""
PRESSURE_VERIFIED_PRESENT_ENTRIES=""
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
RECEIVE_CURSOR_MAP_ID=""
RECEIVE_GUARD_MAP_ID=""
RECEIVE_CURSOR_MAP_BASELINE_ENTRIES=""
RECEIVE_GUARD_MAP_BASELINE_ENTRIES=""
RECEIVE_CURSOR_MAP_STATUS_JSON="null"
FAULT_MODE="alternating"
FAULT_REQUEST_COUNT=2
W3C_FAULT_DIAGNOSTICS_PREVIOUS=""
MATCHING_VALID_TAKES=1
SCENARIO_VARIANT=""
DELAYED_OTLP_PROVIDER_READY_SINCE=""
DIAGNOSTIC_NONDISCLOSURE_LOG_SINCE=""
DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR=""
DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP=""
DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP=""
# Base64 keeps the receiver's JSON string opaque and safe for shell comparison.
DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64=""
DELAYED_OTLP_RECEIVER_RESET_GENERATION=""
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
UNIX_SECURITY_SIBLING_CONTAINER=""
UNIX_SECURITY_ENDPOINT_CONTAINER=""
UNIX_SECURITY_EXEC_PID=""
UNIX_SECURITY_HOST_PROBE=""
UNIX_SECURITY_JAVA_CONTAINER=""
UNIX_SECURITY_NAMESPACE_PID=""
UNIX_SECURITY_PROBE_DIRECTORY=""
PRIMARY_FAULT_STACK_ACTIVE=false
PROJECT_GUARD_HELD=false
PROJECT_GUARD_CONTROL_DIR=""
PROJECT_GUARD_HANDOFF_SIGNAL_STATUS=0
PROJECT_GUARD_LOCK_IDENTITY=""
PROJECT_GUARD_PARENT_PID=""
PROJECT_GUARD_PENDING_SIGNAL=""
PROJECT_GUARD_FORWARDING_READY=false
PROJECT_GUARD_SUPERVISOR_PID=""
PROJECT_GUARD_SUPERVISOR_START_TIME=""
PROJECT_GUARD_STATUS_RELAY_PID=""
PROJECT_GUARD_STATUS_RELAY_START_TIME=""
PROJECT_GUARD_STATUS_HOLDER_PID=""
PROJECT_GUARD_STATUS_HOLDER_START_TIME=""
PROJECT_GUARD_PROCESS_STATE=""
PROJECT_GUARD_PROCESS_START_TIME=""
PROJECT_GUARD_LOADED_SUPERVISOR_START_TIME=""
PROJECT_GUARD_LOADED_HOLDER_START_TIME=""
PROJECT_GUARD_LOADED_HOLDER_STATUS=""
PROJECT_GUARD_FORMATTED_HOLDER_STATUS=""
PROJECT_GUARD_HOLDER_PUBLICATION_ATTEMPTED=false
PROJECT_GUARD_SIGNAL_RESET_EXECUTABLE="$(type -P env)"
PROJECT_DOCKER_SERVER_ID_SHA256=""
CLEANUP_ENTRY_ACTIVE=""
CLEANUP_ENTRY_STATUS=""
CLEANUP_SIGNAL_STATUS=0

declare -a COMPOSE=(
  docker compose --project-name "$PROJECT_NAME" \
    --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE"
)
declare -a PRIMARY_FAULT_COMPOSE=(
  docker compose --project-name "$PROJECT_NAME" \
    --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
    --file "$PRIMARY_FAULT_COMPOSE_FILE"
)
declare -a PRIMARY_LIVE_FD_COMPOSE=(
  docker compose --project-name "$PROJECT_NAME" \
    --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
    --file "$PRIMARY_FAULT_COMPOSE_FILE" --file "$PRIMARY_LIVE_FD_COMPOSE_FILE"
)
declare -a UNIX_GENERATION_FAULT_COMPOSE=(
  docker compose --project-name "$PROJECT_NAME" \
    --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
    --file "$PRIMARY_FAULT_COMPOSE_FILE" --file "$UNIX_GENERATION_FAULT_COMPOSE_FILE"
)
declare -a PID_REUSE_COMPOSE=(
  docker compose --project-name "$PROJECT_NAME" \
    --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
    --file "$PID_REUSE_COMPOSE_FILE"
)

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Build, run, and assert the client -> Apache -> HTTPS Java trace bridge demo.

Options:
  --transport MODE        getsockopt, unix, auto, or disabled.
                          Default: getsockopt
  --agent NAME            otel or splunk. Default: otel
  --tls VERSION           TLSv1.2 or TLSv1.3. Default: TLSv1.3
  --obi-log-level LEVEL   info or debug. Default: info. Debug is restricted
                          to the diagnostic-nondisclosure scenario.
  --scenario NAME         all, basic, keepalive, pipelining, concurrency,
                          connection-churn, fd-port-reuse, slow-body, tls-boundary,
                          coalesced-bridge, timeout-retry,
                          pressure, handoff, virtual-thread, netty, netty-server, dispatch,
                          w3c, w3c-match, obi-flags, w3c-fault, primary-w3c-fault,
                          primary-generation-mismatch, unix-generation-mismatch,
                          pid-reuse,
                          primary-w3c-stale, permanent-absence,
                          auto-unavailable,
                          unix-w3c-stale, w3c-only,
                          security, restart-fault, helper-attach-failure,
                          delayed-otlp-suppression, assertion-failure, fail-open,
                          diagnostic-nondisclosure,
                          restart, disabled, uninstrumented, benchmark-disabled,
                          or benchmark-uninstrumented.
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
boundaries, the live coalesced receive control, timeout/retry, pressure,
executor/virtual-thread/Netty handoff, inbound Netty TLS, async redispatch, W3C
precedence/match/flags/fault/no-state controls, the primary stale-record control,
the primary malformed-response control,
auto selection with both primary and fallback unavailable,
late attach, OBI restart during
traffic, helper attach failure, bounded primary or fallback transport abuse
controls, delayed first-OTLP suppression, Unix endpoint replacement when that transport is selected,
bridge/extension-disabled, extension-absent, and uninstrumented controls.
It deliberately excludes the assertion-failure control, which is a
non-acceptance run that exits after a passing basic scenario.
Evidence is retained under:
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
      --obi-log-level)
        require_value "$1" "$#"
        OBI_LOG_LEVEL="$2"
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
        CLEANUP_ENTRY_ACTIVE=true
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
  case "$OBI_LOG_LEVEL" in
    info|debug)
      ;;
    *)
      die "OBI log level must be info or debug"
      ;;
  esac
  case "$SCENARIO" in
    all|basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff|virtual-thread|netty|netty-server|dispatch|w3c|w3c-match|obi-flags|w3c-fault|primary-w3c-fault|primary-generation-mismatch|unix-generation-mismatch|pid-reuse|primary-w3c-stale|unix-w3c-stale|w3c-only|security|restart-fault|helper-attach-failure|delayed-otlp-suppression|assertion-failure|fail-open|permanent-absence|auto-unavailable|diagnostic-nondisclosure|restart|disabled|uninstrumented|benchmark-disabled|benchmark-uninstrumented)
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
  case "$SCENARIO" in
    disabled|uninstrumented|benchmark-disabled|benchmark-uninstrumented)
      [[ "$TRANSPORT" == "disabled" ]] || {
        die "the $SCENARIO scenario requires --transport disabled"
      }
      ;;
  esac
  if [[ "$TRANSPORT" == "disabled" ]]; then
    case "$SCENARIO" in
      disabled|uninstrumented|benchmark-disabled|benchmark-uninstrumented)
        ;;
      *)
        die "--transport disabled may only run a disabled or uninstrumented control"
        ;;
    esac
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
  if [[ "$OBI_LOG_LEVEL" == "debug" && \
    "$SCENARIO" != "diagnostic-nondisclosure" ]]; then
    die "OBI debug logging is restricted to the diagnostic-nondisclosure scenario"
  fi
  if [[ "$SCENARIO" == "diagnostic-nondisclosure" ]]; then
    [[ "$TRANSPORT" == "getsockopt" || "$TRANSPORT" == "unix" ]] || {
      die "the diagnostic-nondisclosure scenario requires forced getsockopt or Unix transport"
    }
    [[ "$TLS_PROTOCOL" == "TLSv1.3" ]] || {
      die "the diagnostic-nondisclosure scenario requires TLSv1.3"
    }
    [[ "$REQUEST_COUNT" == "0" ]] || {
      die "the diagnostic-nondisclosure scenario does not accept a custom request count"
    }
    [[ "$REPEAT_COUNT" == "1" ]] || {
      die "the diagnostic-nondisclosure scenario requires exactly one run"
    }
    [[ "$SKIP_BRIDGE_BUILD" == "false" ]] || {
      die "the diagnostic-nondisclosure scenario requires a fresh bridge build"
    }
    [[ "$KEEP_RUNNING" == "false" ]] || {
      die "the diagnostic-nondisclosure scenario cannot leave diagnostic logging running"
    }
  fi
  if [[ "$SCENARIO" == "w3c-fault" && "$TRANSPORT" != "unix" ]]; then
    die "the w3c-fault scenario requires --transport unix"
  fi
  if [[ "$SCENARIO" == "w3c-fault" && "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "2" ]]; then
    die "the w3c-fault scenario requires exactly two requests"
  fi
  if [[ "$SCENARIO" == "primary-w3c-stale" && "$TRANSPORT" != "getsockopt" ]]; then
    die "the primary-w3c-stale scenario requires --transport getsockopt"
  fi
  if [[ "$SCENARIO" == "primary-generation-mismatch" && \
    "$TRANSPORT" != "getsockopt" ]]; then
    die "the primary-generation-mismatch scenario requires --transport getsockopt"
  fi
  if [[ "$SCENARIO" == "primary-generation-mismatch" && \
    "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "1" ]]; then
    die "the primary-generation-mismatch scenario requires exactly one request"
  fi
  if [[ "$SCENARIO" == "unix-generation-mismatch" && \
    "$TRANSPORT" != "unix" ]]; then
    die "the unix-generation-mismatch scenario requires --transport unix"
  fi
  if [[ "$SCENARIO" == "unix-generation-mismatch" && \
    "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "1" ]]; then
    die "the unix-generation-mismatch scenario requires exactly one request"
  fi
  if [[ "$SCENARIO" == "pid-reuse" && \
    "$TRANSPORT" != "getsockopt" && "$TRANSPORT" != "unix" ]]; then
    die "the pid-reuse scenario requires forced getsockopt or Unix transport"
  fi
  if [[ "$SCENARIO" == "pid-reuse" && "$REQUEST_COUNT" != "0" ]]; then
    die "the pid-reuse scenario does not accept a custom request count"
  fi
  if [[ "$SCENARIO" == "pid-reuse" && "$REPEAT_COUNT" != "1" ]]; then
    die "the pid-reuse scenario requires exactly one lifecycle pair"
  fi
  if [[ "$SCENARIO" == "auto-unavailable" && "$TRANSPORT" != "auto" ]]; then
    die "the auto-unavailable scenario requires --transport auto"
  fi
  if [[ "$SCENARIO" == "auto-unavailable" && \
    "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "1" ]]; then
    die "the auto-unavailable scenario requires exactly one request"
  fi
  if [[ "$SCENARIO" == "primary-w3c-stale" && "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "1" ]]; then
    die "the primary-w3c-stale scenario requires exactly one request"
  fi
  if [[ "$SCENARIO" == "unix-w3c-stale" && "$TRANSPORT" != "unix" ]]; then
    die "the unix-w3c-stale scenario requires --transport unix"
  fi
  if [[ "$SCENARIO" == "unix-w3c-stale" && "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "1" ]]; then
    die "the unix-w3c-stale scenario requires exactly one request"
  fi
  if [[ "$SCENARIO" == "primary-w3c-fault" && "$TRANSPORT" != "getsockopt" ]]; then
    die "the primary-w3c-fault scenario requires --transport getsockopt"
  fi
  if [[ "$SCENARIO" == "primary-w3c-fault" && "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" != "1" ]]; then
    die "the primary-w3c-fault scenario requires exactly one request"
  fi
  if [[ ( "$SCENARIO" == "keepalive" || "$SCENARIO" == "pipelining" ) &&
    "$REQUEST_COUNT" != "0" && "$REQUEST_COUNT" -lt 3 ]]; then
    die "the $SCENARIO scenario requires at least three requests"
  fi
  if [[ "$SCENARIO" == "concurrency" && "$REQUEST_COUNT" != "0" ]] &&
    ((REQUEST_COUNT < 2 || REQUEST_COUNT > 64)); then
    die "the concurrency scenario requires between two and 64 requests"
  fi
  if [[ "$SCENARIO" == "fd-port-reuse" && "$REQUEST_COUNT" == "1" ]]; then
    die "the fd-port-reuse scenario requires at least two requests"
  fi
  if [[ "$SCENARIO" == "tls-boundary" && "$REQUEST_COUNT" != "0" && \
    "$REQUEST_COUNT" != "3" ]]; then
    die "the tls-boundary scenario requires exactly three requests"
  fi
  if [[ "$SCENARIO" == "coalesced-bridge" && "$REQUEST_COUNT" != "0" && \
    "$REQUEST_COUNT" != "2" ]]; then
    die "the coalesced-bridge scenario requires exactly two requests"
  fi
  if [[ "$SCENARIO" == "assertion-failure" ]]; then
    mark_non_acceptance "deliberate-assertion-failure"
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
  CLEANUP_ENTRY_ACTIVE=true
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

sanitize_git_environment() {
  local git_variable=""

  # Git's repository-selection and temporary-config environment variables can
  # redirect an otherwise explicit `git -C "$REPO_ROOT"` invocation away from
  # the physical checkout that Docker would otherwise read. The demo's source
  # identity is always derived from its own checkout, never caller state.
  unset \
    GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_CEILING_DIRECTORIES \
    GIT_COMMON_DIR \
    GIT_CONFIG \
    GIT_CONFIG_COUNT \
    GIT_CONFIG_GLOBAL \
    GIT_CONFIG_NOSYSTEM \
    GIT_CONFIG_PARAMETERS \
    GIT_CONFIG_SYSTEM \
    GIT_DIR \
    GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_DIFF_OPTS \
    GIT_EXTERNAL_DIFF \
    GIT_GLOB_PATHSPECS \
    GIT_ICASE_PATHSPECS \
    GIT_INDEX_FILE \
    GIT_LITERAL_PATHSPECS \
    GIT_NAMESPACE \
    GIT_NOGLOB_PATHSPECS \
    GIT_OBJECT_DIRECTORY \
    GIT_OPTIONAL_LOCKS \
    GIT_REPLACE_REF_BASE \
    GIT_WORK_TREE \
    TAR_OPTIONS
  for git_variable in "${!GIT_CONFIG_KEY_@}" "${!GIT_CONFIG_VALUE_@}"; do
    [[ -n "$git_variable" ]] || continue
    unset "$git_variable"
  done
  export GIT_NO_REPLACE_OBJECTS=1
}

sha256_file() {
  local digest=""

  [[ -f "$1" && ! -L "$1" ]] || return 1
  digest="$(sha256sum <"$1")" || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

check_dependencies() {
  local -a missing=()
  local command_name=""
  for command_name in awk cmp cp curl cut docker env find flock git grep head id install jq ln mktemp mv openssl readlink realpath rmdir sed sha256sum sort stat tail tar tee timeout wc; do
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
  run_bounded "$OBI_COMPOSE_MULTI_SERVICE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" --profile '*' \
    down --volumes --remove-orphans \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" || return
  verify_compose_project_absent
}

project_guard_lock_path() {
  (( ${#PROJECT_NAME} <= 63 )) || return 1
  [[ "$PROJECT_NAME" == "$PROJECT_NAMESPACE" || \
    "$PROJECT_NAME" =~ ^${PROJECT_NAMESPACE}-[a-z0-9]([a-z0-9_-]*[a-z0-9])?$ ]] || \
    return 1
  printf '%s/%s.lock\n' "$PROJECT_GUARD_ROOT" "$PROJECT_NAME"
}

permanent_absence_global_marker_path() {
  project_guard_lock_path >/dev/null || return 1
  printf '%s/%s.permanent-absence-recovery-required\n' \
    "$PROJECT_GUARD_ROOT" "$PROJECT_NAME"
}

assert_project_guard_root_path() {
  [[ "$PROJECT_GUARD_ROOT" == \
    "/tmp/obi-apache-java-https-project-guard-$EUID" ]]
}

assert_private_project_guard_directory() {
  local -r directory="$1"
  local metadata=""
  local extra=""

  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  (cd -P -- "$directory" && [[ "$PWD" == "$directory" ]]) || return 1
  stat --format='%u:%a' -- "$directory" |
    {
      IFS= read -r metadata &&
        ! IFS= read -r extra &&
        [[ "$metadata" == "$EUID:700" ]]
    }
}

prepare_project_guard_root() {
  assert_project_guard_root_path || {
    log_error "project guard path is outside the fixed host-shared namespace"
    return 1
  }
  assert_source_snapshot_parent_is_trusted /tmp
  if [[ ! -e "$PROJECT_GUARD_ROOT" && ! -L "$PROJECT_GUARD_ROOT" ]]; then
    if (umask 077; mkdir -- "$PROJECT_GUARD_ROOT") 2>/dev/null; then
      :
    elif [[ ! -e "$PROJECT_GUARD_ROOT" && ! -L "$PROJECT_GUARD_ROOT" ]]; then
      log_error "could not create the host-shared project guard directory"
      return 1
    fi
  fi
  assert_private_project_guard_directory "$PROJECT_GUARD_ROOT" || {
    log_error "host-shared project guard directory metadata is untrusted"
    return 1
  }
}

assert_private_project_guard_lock() {
  local -r lock_file="$1"
  local metadata=""
  local extra=""

  [[ -f "$lock_file" && ! -L "$lock_file" ]] || return 1
  stat --format='%u:%a:%h:%s' -- "$lock_file" |
    {
      IFS= read -r metadata &&
        ! IFS= read -r extra &&
        [[ "$metadata" == "$EUID:600:1:0" ]]
    }
}

assert_private_project_guard_control_directory() {
  local -r directory="$1"

  [[ "$directory" == "$PROJECT_GUARD_ROOT"/.terminal-handoff.?????? ]] || \
    return 1
  assert_private_project_guard_directory "$directory"
}

project_guard_control_file_matches() {
  local -r path="$1"
  local -r expected="$2"
  local metadata=""
  local content=""
  local extra=""

  [[ -n "$PROJECT_GUARD_CONTROL_DIR" && \
    ( "$path" == "$PROJECT_GUARD_CONTROL_DIR/ready" || \
      "$path" == "$PROJECT_GUARD_CONTROL_DIR/decision" || \
      "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor" || \
      "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted" || \
      "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" || \
      "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched-accepted" || \
      "$path" == "$PROJECT_GUARD_CONTROL_DIR/holder-status" ) && \
    -f "$path" && ! -L "$path" ]] || return 1
  stat --format='%u:%a:%h:%s' -- "$path" |
    {
      IFS= read -r metadata &&
        ! IFS= read -r extra &&
        [[ "$metadata" == "$EUID:600:1:$((${#expected} + 1))" ]]
    } || return 1
  IFS= read -r content <"$path" || return 1
  [[ "$content" == "$expected" ]]
}

publish_project_guard_control_file() {
  local -r path="$1"
  local -r content="$2"
  local temporary=""
  local temporary_content=""
  local metadata=""
  local extra=""
  local status=0

  assert_private_project_guard_control_directory \
    "$PROJECT_GUARD_CONTROL_DIR" || return 1
  [[ "$path" == "$PROJECT_GUARD_CONTROL_DIR/ready" || \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/decision" || \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor" || \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted" || \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" || \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched-accepted" || \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/holder-status" ]] || \
    return 1
  [[ ! -e "$path" && ! -L "$path" ]] || return 1
  temporary="$path.publication"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] || return 1
  if (umask 077; set -o noclobber; \
      printf '%s\n' "$content" >"$temporary") 2>/dev/null && \
    stat --format='%u:%a:%h:%s' -- "$temporary" | \
      {
        IFS= read -r metadata &&
          ! IFS= read -r extra &&
          [[ "$metadata" == "$EUID:600:1:$((${#content} + 1))" ]]
      } && \
    IFS= read -r temporary_content <"$temporary" && \
    [[ "$temporary_content" == "$content" ]] && \
    [[ ! -e "$path" && ! -L "$path" ]] && \
    env --ignore-signal=HUP,INT,TERM \
      mv --no-target-directory -- "$temporary" "$path"; then
    temporary=""
  else
    status=$?
    rm -f -- "$temporary" || true
    return "$((status == 0 ? 1 : status))"
  fi
  return 0
}

complete_project_guard_terminal_handoff() {
  local -r ready_file="$PROJECT_GUARD_CONTROL_DIR/ready"
  local -r decision_file="$PROJECT_GUARD_CONTROL_DIR/decision"
  local sleep_status=0
  local -i attempt=0

  PROJECT_GUARD_HANDOFF_SIGNAL_STATUS=0
  publish_project_guard_control_file "$ready_file" ready || return $?
  for ((attempt = 0; attempt < PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS; attempt++)); do
    if [[ -e "$decision_file" || -L "$decision_file" ]]; then
      if project_guard_control_file_matches "$decision_file" commit; then
        return 0
      fi
      if project_guard_control_file_matches "$decision_file" signal:129; then
        PROJECT_GUARD_HANDOFF_SIGNAL_STATUS=129
        return 0
      fi
      if project_guard_control_file_matches "$decision_file" signal:130; then
        PROJECT_GUARD_HANDOFF_SIGNAL_STATUS=130
        return 0
      fi
      return 1
    fi
    if sleep 0.05; then
      :
    else
      sleep_status=$?
      [[ "$CLEANUP_SIGNAL_STATUS" -ne 0 ]] || return "$sleep_status"
    fi
  done
  remove_project_guard_control_directory "$PROJECT_GUARD_CONTROL_DIR" || true
  return 1
}

publish_project_guard_terminal_decision() {
  local decision=commit
  local publication_status=0
  local -i attempt=0

  # This is the signal-aware relay's terminal commit point. A signal handled
  # before this trap update remains in PROJECT_GUARD_PENDING_SIGNAL and is
  # handed to the worker. Later direct relay signals are intentionally ignored;
  # process-group signals still reach the worker until its own commit point.
  trap '' HUP INT TERM
  case "$PROJECT_GUARD_PENDING_SIGNAL" in
    "") ;;
    HUP) decision=signal:129 ;;
    INT|TERM) decision=signal:130 ;;
    *) return 1 ;;
  esac
  if publish_project_guard_control_file \
    "$PROJECT_GUARD_CONTROL_DIR/decision" "$decision"; then
    :
  else
    publication_status=$?
    for attempt in 1 2 3; do
      if project_guard_control_file_matches \
        "$PROJECT_GUARD_CONTROL_DIR/decision" "$decision"; then
        publication_status=0
        break
      fi
    done
    ((publication_status == 0)) || return "$publication_status"
  fi
  PROJECT_GUARD_PENDING_SIGNAL=""
}

remove_project_guard_control_directory() {
  local -r directory="$1"

  [[ "$directory" == "$PROJECT_GUARD_ROOT"/.terminal-handoff.?????? ]] || \
    return 1
  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    return 0
  fi
  assert_private_project_guard_control_directory "$directory" || return 1
  rm -f -- \
    "$directory/ready" "$directory/decision" "$directory/supervisor" \
    "$directory/supervisor-accepted" "$directory/supervisor-launched" \
    "$directory/supervisor-launched-accepted" "$directory/holder-status" \
    "$directory/ready.publication" "$directory/decision.publication" \
    "$directory/supervisor.publication" \
    "$directory/supervisor-accepted.publication" \
    "$directory/supervisor-launched.publication" \
    "$directory/supervisor-launched-accepted.publication" \
    "$directory/holder-status.publication" || \
    return 1
  rmdir -- "$directory"
}

resolve_docker_server_identity() {
  local server_id_file=""
  local server_id=""
  local digest=""
  local size=""
  local pipeline_status=0

  server_id_file="$(mktemp "$PROJECT_GUARD_ROOT/.docker-server-id.XXXXXX")" || return 1
  if run_bounded 15 docker info --format '{{json .ID}}' |
    (
      LC_ALL=C head -c "$((DOCKER_SERVER_ID_MAX_BYTES + 1))" \
        >"$server_id_file" || exit $?
      cat >/dev/null
    ); then
    :
  else
    pipeline_status=$?
  fi
  size="$(stat --format='%s' -- "$server_id_file")" || {
    pipeline_status=$?
    rm -f -- "$server_id_file" || true
    return "$pipeline_status"
  }
  if ((pipeline_status != 0 || size > DOCKER_SERVER_ID_MAX_BYTES)); then
    rm -f -- "$server_id_file" || true
    return "$((pipeline_status == 0 ? 1 : pipeline_status))"
  fi
  server_id="$(jq -ser '
    if length == 1 and (.[0] | type == "string") and
      (.[0] | length) >= 8 and (.[0] | length) <= 256 and
      (.[0] | test("^[A-Za-z0-9:_-]+$"))
    then .[0]
    else empty
    end
  ' "$server_id_file")" || {
    pipeline_status=$?
    rm -f -- "$server_id_file" || true
    return "$pipeline_status"
  }
  rm -f -- "$server_id_file" || return 1
  [[ -n "$server_id" ]] || return 1
  digest="$(printf '%s' "$server_id" | sha256sum)" || return 1
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

project_guard_signal_reset_executable() {
  [[ "$PROJECT_GUARD_SIGNAL_RESET_EXECUTABLE" == /* ]] || return 1
  printf '%s\n' "$PROJECT_GUARD_SIGNAL_RESET_EXECUTABLE"
}

project_guard_child_signal_state() {
  local -r child_pid="$1"
  local -r parent_pid="$2"
  local -r signal_name="$3"
  local key=""
  local value=""
  local extra=""
  local observed_parent=""
  local ignored_hex=""
  local ignored_low=""
  local -i parent_entries=0
  local -i ignored_entries=0
  local -i ignored_signals=0
  local -i signal_mask=0

  [[ "$child_pid" =~ ^[1-9][0-9]*$ && \
    "$parent_pid" =~ ^[1-9][0-9]*$ && \
    -r "/proc/$child_pid/status" ]] || return 2
  while read -r key value extra; do
    case "$key" in
      PPid:)
        ((parent_entries += 1))
        observed_parent="$value"
        ;;
      SigIgn:)
        ((ignored_entries += 1))
        ignored_hex="${value,,}"
        ;;
    esac
  done <"/proc/$child_pid/status" 2>/dev/null || return 2
  [[ "$parent_entries" -eq 1 && "$ignored_entries" -eq 1 && \
    "$observed_parent" == "$parent_pid" && \
    "$ignored_hex" =~ ^[0-9a-f]{16}$ ]] || return 2
  case "$signal_name" in
    HUP) signal_mask=1 ;;
    INT) signal_mask=2 ;;
    TERM) signal_mask=16384 ;;
    *) return 2 ;;
  esac
  ignored_low="${ignored_hex: -8}"
  ignored_signals=$((16#$ignored_low))
  if (( (ignored_signals & signal_mask) == 0 )); then
    return 0
  fi
  [[ "$PROJECT_GUARD_SIGNAL_RESET_EXECUTABLE" == /* && \
    "/proc/$child_pid/exe" -ef \
      "$PROJECT_GUARD_SIGNAL_RESET_EXECUTABLE" ]] || return 2
  return 1
}

load_project_guard_process_stat_identity() {
  local -r process_pid="$1"
  local process_stat=""
  local state_fields=""
  local -a fields=()

  PROJECT_GUARD_PROCESS_STATE=""
  PROJECT_GUARD_PROCESS_START_TIME=""

  [[ "$process_pid" =~ ^[1-9][0-9]*$ && \
    -r "/proc/$process_pid/stat" ]] || return 1
  if ! { IFS= read -r process_stat <"/proc/$process_pid/stat"; } \
    2>/dev/null; then
    return 1
  fi
  state_fields="${process_stat##*) }"
  [[ "$state_fields" != "$process_stat" ]] || return 1
  read -r -a fields <<<"$state_fields"
  ((${#fields[@]} >= 20)) || return 1
  PROJECT_GUARD_PROCESS_STATE="${fields[0]}"
  PROJECT_GUARD_PROCESS_START_TIME="${fields[19]}"
  [[ "$PROJECT_GUARD_PROCESS_STATE" =~ ^[A-Zt]$ && \
    "$PROJECT_GUARD_PROCESS_START_TIME" =~ ^[0-9]+$ ]]
}

project_guard_process_stat_identity() {
  load_project_guard_process_stat_identity "$1" || return 1
  printf '%s %s\n' \
    "$PROJECT_GUARD_PROCESS_STATE" "$PROJECT_GUARD_PROCESS_START_TIME"
}

project_guard_process_start_time() {
  local -r process_pid="$1"

  load_project_guard_process_stat_identity "$process_pid" || return 1
  printf '%s\n' "$PROJECT_GUARD_PROCESS_START_TIME"
}

publish_project_guard_supervisor_identity() {
  local -r supervisor_pid="$BASHPID"
  local supervisor_start_time=""

  load_project_guard_process_stat_identity "$supervisor_pid" || return 1
  supervisor_start_time="$PROJECT_GUARD_PROCESS_START_TIME"
  publish_project_guard_control_file \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" \
    "supervisor:$supervisor_pid:$supervisor_start_time"
}

wait_for_project_guard_supervisor_acceptance() {
  local -r supervisor_pid="$1"
  local -r supervisor_start_time="$2"
  local -r acceptance_file="$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted"
  local -r expected="supervisor-accepted:$supervisor_pid:$supervisor_start_time"
  local -i attempt=0

  [[ "$supervisor_pid" =~ ^[1-9][0-9]*$ && \
    "$supervisor_start_time" =~ ^[0-9]+$ ]] || return 1
  for ((attempt = 0; attempt < PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS; attempt++)); do
    if [[ -e "$acceptance_file" || -L "$acceptance_file" ]]; then
      project_guard_control_file_matches "$acceptance_file" "$expected"
      return $?
    fi
    sleep 0.05 || true
  done
  return 1
}

complete_project_guard_supervisor_identity_handoff() {
  local -r supervisor_pid="$BASHPID"
  local supervisor_start_time=""

  load_project_guard_process_stat_identity "$supervisor_pid" || return 1
  supervisor_start_time="$PROJECT_GUARD_PROCESS_START_TIME"
  publish_project_guard_control_file \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" \
    "supervisor:$supervisor_pid:$supervisor_start_time" || return $?
  wait_for_project_guard_supervisor_acceptance \
    "$supervisor_pid" "$supervisor_start_time"
}

load_project_guard_supervisor_identity() {
  local -r path="$1"
  local -r expected_pid="$2"
  local owner=""
  local mode=""
  local links=""
  local size=""
  local extra=""
  local content=""
  local supervisor_pid=""
  local supervisor_start_time=""

  [[ "$expected_pid" =~ ^[1-9][0-9]*$ && \
    -n "$PROJECT_GUARD_CONTROL_DIR" && \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor" && \
    -f "$path" && ! -L "$path" ]] || return 1
  stat --format='%u:%a:%h:%s' -- "$path" |
    {
      IFS=: read -r owner mode links size extra &&
        ! IFS= read -r &&
        [[ "$owner" == "$EUID" && "$mode" == 600 && \
          "$links" == 1 && "$size" =~ ^[1-9][0-9]?$ && \
          -z "$extra" ]] &&
        ((10#$size <= 64))
    } || return 1
  IFS= read -r content <"$path" || return 1
  ((${#content} < 64)) || return 1
  stat --format='%u:%a:%h:%s' -- "$path" |
    {
      IFS= read -r size &&
        ! IFS= read -r &&
        [[ "$size" == "$EUID:600:1:$(( ${#content} + 1 ))" ]]
    } || return 1
  [[ "$content" =~ ^supervisor:([1-9][0-9]*):([0-9]+)$ ]] || return 1
  supervisor_pid="${BASH_REMATCH[1]}"
  supervisor_start_time="${BASH_REMATCH[2]}"
  [[ "$supervisor_pid" == "$expected_pid" ]] || return 1
  PROJECT_GUARD_LOADED_SUPERVISOR_START_TIME="$supervisor_start_time"
}

read_project_guard_supervisor_identity() {
  load_project_guard_supervisor_identity "$1" "$2" || return 1
  printf '%s\n' "$PROJECT_GUARD_LOADED_SUPERVISOR_START_TIME"
}

publish_project_guard_supervisor_acceptance() {
  local -r supervisor_pid="$1"
  local -r supervisor_start_time="$2"

  [[ "$PROJECT_GUARD_SUPERVISOR_PID" == "$supervisor_pid" && \
    "$PROJECT_GUARD_SUPERVISOR_START_TIME" == "$supervisor_start_time" ]] || \
    return 1
  project_guard_supervisor_identity_matches \
    "$supervisor_pid" "$supervisor_start_time" || return 1
  publish_project_guard_control_file \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted" \
    "supervisor-accepted:$supervisor_pid:$supervisor_start_time"
}

publish_project_guard_supervisor_launched() {
  local -r supervisor_pid="$1"
  local -r holder_pid="$2"
  local supervisor_start_time=""
  local holder_start_time=""
  local expected_acceptance=""

  load_project_guard_supervisor_identity \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" "$supervisor_pid" || return 1
  supervisor_start_time="$PROJECT_GUARD_LOADED_SUPERVISOR_START_TIME"
  project_guard_supervisor_identity_matches \
    "$supervisor_pid" "$supervisor_start_time" || return 1
  expected_acceptance="supervisor-accepted:$supervisor_pid:$supervisor_start_time"
  project_guard_control_file_matches \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted" \
    "$expected_acceptance" || return 1
  load_project_guard_process_stat_identity "$holder_pid" || return 1
  holder_start_time="$PROJECT_GUARD_PROCESS_START_TIME"
  project_guard_supervisor_identity_matches \
    "$holder_pid" "$holder_start_time" || return 1
  publish_project_guard_control_file \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" \
    "supervisor-launched:$supervisor_pid:$supervisor_start_time:$holder_pid:$holder_start_time"
}

load_project_guard_supervisor_launch() {
  local -r path="$1"
  local -r expected_supervisor_pid="$2"
  local -r expected_supervisor_start_time="$3"
  local -r expected_holder_pid="$4"
  local owner=""
  local mode=""
  local links=""
  local size=""
  local extra=""
  local content=""
  local supervisor_pid=""
  local supervisor_start_time=""
  local holder_pid=""
  local holder_start_time=""

  [[ "$expected_supervisor_pid" =~ ^[1-9][0-9]*$ && \
    "$expected_supervisor_start_time" =~ ^[0-9]+$ && \
    "$expected_holder_pid" =~ ^[1-9][0-9]*$ && \
    -n "$PROJECT_GUARD_CONTROL_DIR" && \
    "$path" == "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" && \
    -f "$path" && ! -L "$path" ]] || return 1
  stat --format='%u:%a:%h:%s' -- "$path" |
    {
      IFS=: read -r owner mode links size extra &&
        ! IFS= read -r &&
        [[ "$owner" == "$EUID" && "$mode" == 600 && \
          "$links" == 1 && "$size" =~ ^[1-9][0-9]{1,2}$ && \
          -z "$extra" ]] &&
        ((10#$size <= 192))
    } || return 1
  IFS= read -r content <"$path" || return 1
  ((${#content} < 192)) || return 1
  stat --format='%u:%a:%h:%s' -- "$path" |
    {
      IFS= read -r size &&
        ! IFS= read -r &&
        [[ "$size" == "$EUID:600:1:$(( ${#content} + 1 ))" ]]
    } || return 1
  [[ "$content" =~ ^supervisor-launched:([1-9][0-9]*):([0-9]+):([1-9][0-9]*):([0-9]+)$ ]] || \
    return 1
  supervisor_pid="${BASH_REMATCH[1]}"
  supervisor_start_time="${BASH_REMATCH[2]}"
  holder_pid="${BASH_REMATCH[3]}"
  holder_start_time="${BASH_REMATCH[4]}"
  [[ "$supervisor_pid" == "$expected_supervisor_pid" && \
    "$supervisor_start_time" == "$expected_supervisor_start_time" && \
    "$holder_pid" == "$expected_holder_pid" ]] || return 1
  project_guard_supervisor_identity_matches \
    "$supervisor_pid" "$supervisor_start_time" || return 1
  project_guard_supervisor_identity_matches \
    "$holder_pid" "$holder_start_time" || return 1
  PROJECT_GUARD_LOADED_HOLDER_START_TIME="$holder_start_time"
}

read_project_guard_supervisor_launch() {
  load_project_guard_supervisor_launch "$@" || return 1
  printf '%s\n' "$PROJECT_GUARD_LOADED_HOLDER_START_TIME"
}

publish_project_guard_supervisor_launch_acceptance() {
  local -r supervisor_pid="$1"
  local -r supervisor_start_time="$2"
  local -r holder_pid="$3"
  local -r holder_start_time="$4"

  project_guard_supervisor_identity_matches \
    "$supervisor_pid" "$supervisor_start_time" || return 1
  project_guard_supervisor_identity_matches \
    "$holder_pid" "$holder_start_time" || return 1
  load_project_guard_supervisor_launch \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" \
    "$supervisor_pid" "$supervisor_start_time" "$holder_pid" || return 1
  [[ "$PROJECT_GUARD_LOADED_HOLDER_START_TIME" == \
    "$holder_start_time" ]] || return 1
  publish_project_guard_control_file \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched-accepted" \
    "supervisor-launched-accepted:$supervisor_pid:$supervisor_start_time:$holder_pid:$holder_start_time"
}

wait_for_project_guard_supervisor_launch_acceptance() {
  local -r supervisor_pid="$1"
  local -r holder_pid="$2"
  local supervisor_start_time=""
  local holder_start_time=""
  local expected=""
  local -i attempt=0

  load_project_guard_supervisor_identity \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" "$supervisor_pid" || return 1
  supervisor_start_time="$PROJECT_GUARD_LOADED_SUPERVISOR_START_TIME"
  load_project_guard_process_stat_identity "$holder_pid" || return 1
  holder_start_time="$PROJECT_GUARD_PROCESS_START_TIME"
  expected="supervisor-launched-accepted:$supervisor_pid:$supervisor_start_time:$holder_pid:$holder_start_time"
  for ((attempt = 0; attempt < PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS; attempt++)); do
    if [[ -e "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched-accepted" || \
      -L "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched-accepted" ]]; then
      project_guard_control_file_matches \
        "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched-accepted" \
        "$expected" || return 1
      project_guard_supervisor_identity_matches \
        "$supervisor_pid" "$supervisor_start_time" || return 1
      project_guard_supervisor_identity_matches \
        "$holder_pid" "$holder_start_time"
      return $?
    fi
    sleep 0.05 || return $?
  done
  return 1
}

format_project_guard_holder_status_payload() {
  local -r relay_pid="$1"
  local -r relay_start_time="$2"
  local -r holder_pid="$3"
  local -r holder_start_time="$4"
  local -r exit_status="$5"

  [[ "$relay_pid" =~ ^[1-9][0-9]*$ && \
    "$relay_start_time" =~ ^[0-9]+$ && \
    "$holder_pid" =~ ^[1-9][0-9]*$ && \
    "$holder_start_time" =~ ^[0-9]+$ && \
    "$exit_status" =~ ^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]] || \
    return 1
  printf -v PROJECT_GUARD_FORMATTED_HOLDER_STATUS \
    'holder-status:%s:%s:%s:%s:%s' \
    "$relay_pid" "$relay_start_time" \
    "$holder_pid" "$holder_start_time" "$exit_status"
}

project_guard_holder_status_payload() {
  format_project_guard_holder_status_payload "$@" || return 1
  printf '%s\n' "$PROJECT_GUARD_FORMATTED_HOLDER_STATUS"
}

load_project_guard_holder_status() {
  local -r relay_pid="$1"
  local -r relay_start_time="$2"
  local -r holder_pid="$3"
  local -r expected_holder_start_time="${4:-}"
  local content=""
  local recorded_relay_pid=""
  local recorded_relay_start_time=""
  local recorded_holder_pid=""
  local recorded_holder_start_time=""
  local exit_status=""
  local expected=""

  [[ -f "$PROJECT_GUARD_CONTROL_DIR/holder-status" && \
    ! -L "$PROJECT_GUARD_CONTROL_DIR/holder-status" ]] || return 1
  IFS= read -r content <"$PROJECT_GUARD_CONTROL_DIR/holder-status" || return 1
  [[ "$content" =~ ^holder-status:([1-9][0-9]*):([0-9]+):([1-9][0-9]*):([0-9]+):([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]] || \
    return 1
  recorded_relay_pid="${BASH_REMATCH[1]}"
  recorded_relay_start_time="${BASH_REMATCH[2]}"
  recorded_holder_pid="${BASH_REMATCH[3]}"
  recorded_holder_start_time="${BASH_REMATCH[4]}"
  exit_status="${BASH_REMATCH[5]}"
  [[ "$recorded_relay_pid" == "$relay_pid" && \
    "$recorded_relay_start_time" == "$relay_start_time" && \
    "$recorded_holder_pid" == "$holder_pid" ]] || return 1
  if [[ -n "$expected_holder_start_time" ]]; then
    [[ "$recorded_holder_start_time" == "$expected_holder_start_time" ]] || \
      return 1
  fi
  format_project_guard_holder_status_payload \
    "$relay_pid" "$relay_start_time" \
    "$holder_pid" "$recorded_holder_start_time" "$exit_status" || return 1
  expected="$PROJECT_GUARD_FORMATTED_HOLDER_STATUS"
  project_guard_control_file_matches \
    "$PROJECT_GUARD_CONTROL_DIR/holder-status" "$expected" || return 1
  PROJECT_GUARD_LOADED_HOLDER_START_TIME="$recorded_holder_start_time"
  PROJECT_GUARD_LOADED_HOLDER_STATUS="$exit_status"
}

read_project_guard_holder_status() {
  load_project_guard_holder_status "$@" || return 1
  printf '%s %s\n' \
    "$PROJECT_GUARD_LOADED_HOLDER_START_TIME" \
    "$PROJECT_GUARD_LOADED_HOLDER_STATUS"
}

publish_project_guard_holder_status() {
  local -r exit_status="$1"
  local supervisor_expected=""
  local supervisor_acceptance_expected=""
  local status_payload=""

  PROJECT_GUARD_HOLDER_PUBLICATION_ATTEMPTED=false

  format_project_guard_holder_status_payload \
    "$PROJECT_GUARD_STATUS_RELAY_PID" \
    "$PROJECT_GUARD_STATUS_RELAY_START_TIME" \
    "$PROJECT_GUARD_STATUS_HOLDER_PID" \
    "$PROJECT_GUARD_STATUS_HOLDER_START_TIME" \
    "$exit_status" || return 1
  status_payload="$PROJECT_GUARD_FORMATTED_HOLDER_STATUS"
  supervisor_expected="supervisor:$PROJECT_GUARD_STATUS_RELAY_PID:$PROJECT_GUARD_STATUS_RELAY_START_TIME"
  supervisor_acceptance_expected="supervisor-accepted:$PROJECT_GUARD_STATUS_RELAY_PID:$PROJECT_GUARD_STATUS_RELAY_START_TIME"

  project_guard_control_file_matches \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" "$supervisor_expected" || return 1
  project_guard_control_file_matches \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted" \
    "$supervisor_acceptance_expected" || return 1
  project_guard_supervisor_identity_matches \
    "$PROJECT_GUARD_STATUS_RELAY_PID" \
    "$PROJECT_GUARD_STATUS_RELAY_START_TIME" || return 1
  project_guard_supervisor_identity_matches \
    "$PROJECT_GUARD_STATUS_HOLDER_PID" \
    "$PROJECT_GUARD_STATUS_HOLDER_START_TIME" || return 1
  [[ ! -e "$PROJECT_GUARD_CONTROL_DIR/holder-status" &&
    ! -L "$PROJECT_GUARD_CONTROL_DIR/holder-status" ]] || return 1
  PROJECT_GUARD_HOLDER_PUBLICATION_ATTEMPTED=true
  publish_project_guard_control_file \
    "$PROJECT_GUARD_CONTROL_DIR/holder-status" "$status_payload"
}

publish_project_guard_holder_status_with_retries() {
  local -r exit_status="$1"
  local publication_status=1
  local expected=""
  local -i attempt=0

  format_project_guard_holder_status_payload \
    "$PROJECT_GUARD_STATUS_RELAY_PID" \
    "$PROJECT_GUARD_STATUS_RELAY_START_TIME" \
    "$PROJECT_GUARD_STATUS_HOLDER_PID" \
    "$PROJECT_GUARD_STATUS_HOLDER_START_TIME" \
    "$exit_status" || return 1
  expected="$PROJECT_GUARD_FORMATTED_HOLDER_STATUS"

  for ((attempt = 0; attempt < 3; attempt++)); do
    if publish_project_guard_holder_status "$exit_status"; then
      return 0
    else
      publication_status=$?
    fi
    if [[ "$PROJECT_GUARD_HOLDER_PUBLICATION_ATTEMPTED" == true &&
      ( -e "$PROJECT_GUARD_CONTROL_DIR/holder-status" ||
        -L "$PROJECT_GUARD_CONTROL_DIR/holder-status" ) ]]; then
      # The immutable authority path was absent immediately before this
      # worker's atomic publication attempt. Under the serialized cooperative
      # guard protocol, its appearance is the terminal commit even if the
      # publishing command or this optional diagnostic read reports an error.
      project_guard_control_file_matches \
        "$PROJECT_GUARD_CONTROL_DIR/holder-status" "$expected" || true
      return 0
    fi
    if [[ -e "$PROJECT_GUARD_CONTROL_DIR/holder-status" || \
      -L "$PROJECT_GUARD_CONTROL_DIR/holder-status" ]]; then
      if project_guard_control_file_matches \
        "$PROJECT_GUARD_CONTROL_DIR/holder-status" "$expected"; then
        return 0
      fi
      break
    fi
    sleep 0.01 || true
  done
  return "$((publication_status == 0 ? 1 : publication_status))"
}

project_guard_supervisor_identity_matches() {
  local -r supervisor_pid="$1"
  local -r expected_start_time="$2"

  [[ "$supervisor_pid" =~ ^[1-9][0-9]*$ && \
    "$expected_start_time" =~ ^[0-9]+$ ]] || return 1
  load_project_guard_process_stat_identity "$supervisor_pid" || return 1
  [[ "$PROJECT_GUARD_PROCESS_START_TIME" == "$expected_start_time" ]]
}

project_guard_supervisor_is_running() {
  local -r supervisor_pid="$1"
  local -r expected_start_time="${2:-$PROJECT_GUARD_SUPERVISOR_START_TIME}"

  [[ "$expected_start_time" =~ ^[0-9]+$ ]] || return 1
  load_project_guard_process_stat_identity "$supervisor_pid" || return 1
  [[ "$PROJECT_GUARD_PROCESS_START_TIME" == "$expected_start_time" && \
    "$PROJECT_GUARD_PROCESS_STATE" != Z && \
    "$PROJECT_GUARD_PROCESS_STATE" != X ]]
}

record_project_guard_pending_signal() {
  local -r requested_signal="$1"

  [[ "$requested_signal" == HUP || "$requested_signal" == INT || \
    "$requested_signal" == TERM ]] || return 1
  [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]] || \
    PROJECT_GUARD_PENDING_SIGNAL="$requested_signal"
}

record_project_guard_hup() {
  [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]] || \
    PROJECT_GUARD_PENDING_SIGNAL=HUP
}

record_project_guard_int() {
  [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]] || \
    PROJECT_GUARD_PENDING_SIGNAL=INT
}

record_project_guard_term() {
  [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]] || \
    PROJECT_GUARD_PENDING_SIGNAL=TERM
}

forward_project_guard_signal() {
  local -r requested_signal="$1"
  local supervisor_pid=""
  local supervisor_start_time=""
  local signal_name=""
  local children=""
  local child=""
  local child_start_time=""
  local current_child_start_time=""
  local signal_state=0
  local -i attempt=0
  local -a child_pids=()

  record_project_guard_pending_signal "$requested_signal" || return 1
  signal_name="$PROJECT_GUARD_PENDING_SIGNAL"
  [[ "$PROJECT_GUARD_FORWARDING_READY" == true ]] || return 0
  supervisor_pid="$PROJECT_GUARD_SUPERVISOR_PID"
  supervisor_start_time="$PROJECT_GUARD_SUPERVISOR_START_TIME"
  if [[ ! "$supervisor_pid" =~ ^[1-9][0-9]*$ && \
    -z "$supervisor_start_time" ]]; then
    return 0
  fi
  project_guard_supervisor_identity_matches \
    "$supervisor_pid" "$supervisor_start_time" || return 1
  for ((attempt = 0; attempt < 100; attempt++)); do
    project_guard_supervisor_identity_matches \
      "$supervisor_pid" "$supervisor_start_time" || return 1
    children=""
    child_pids=()
    if [[ -r "/proc/$supervisor_pid/task/$supervisor_pid/children" ]]; then
      if ! { IFS= read -r children \
        <"/proc/$supervisor_pid/task/$supervisor_pid/children"; } \
        2>/dev/null && [[ -z "$children" ]]; then
        children=""
      fi
      read -r -a child_pids <<<"$children"
      if ((${#child_pids[@]} == 1)); then
        child="${child_pids[0]}"
        if load_project_guard_process_stat_identity "$child"; then
          child_start_time="$PROJECT_GUARD_PROCESS_START_TIME"
        else
          child_start_time=""
        fi
        if [[ -n "$child_start_time" ]] && \
          project_guard_child_signal_state \
            "$child" "$supervisor_pid" "$signal_name" && \
          project_guard_supervisor_identity_matches \
            "$supervisor_pid" "$supervisor_start_time" && \
          load_project_guard_process_stat_identity "$child" && \
          current_child_start_time="$PROJECT_GUARD_PROCESS_START_TIME" && \
          [[ "$current_child_start_time" == "$child_start_time" ]] && \
          project_guard_child_signal_state \
            "$child" "$supervisor_pid" "$signal_name"; then
          if kill -s "$signal_name" "$child" 2>/dev/null; then
            PROJECT_GUARD_PENDING_SIGNAL=""
            return 0
          fi
        fi
      fi
    fi
    if ! project_guard_supervisor_is_running \
      "$supervisor_pid" "$supervisor_start_time"; then
      return 1
    fi
    sleep 0.01 || return $?
  done
  project_guard_supervisor_identity_matches \
    "$supervisor_pid" "$supervisor_start_time" || return 1
  children=""
  child_pids=()
  if [[ -r "/proc/$supervisor_pid/task/$supervisor_pid/children" ]]; then
    if ! { IFS= read -r children \
      <"/proc/$supervisor_pid/task/$supervisor_pid/children"; } \
      2>/dev/null && [[ -z "$children" ]]; then
      children=""
    fi
    read -r -a child_pids <<<"$children"
  fi
  if ((${#child_pids[@]} == 1)); then
    child="${child_pids[0]}"
    if load_project_guard_process_stat_identity "$child"; then
      child_start_time="$PROJECT_GUARD_PROCESS_START_TIME"
    else
      child_start_time=""
    fi
    if [[ -z "$child_start_time" ]]; then
      signal_state=2
    elif project_guard_child_signal_state \
      "$child" "$supervisor_pid" "$signal_name"; then
      if project_guard_supervisor_identity_matches \
          "$supervisor_pid" "$supervisor_start_time" && \
        load_project_guard_process_stat_identity "$child" && \
        current_child_start_time="$PROJECT_GUARD_PROCESS_START_TIME" && \
        [[ "$current_child_start_time" == "$child_start_time" ]] && \
        project_guard_child_signal_state \
          "$child" "$supervisor_pid" "$signal_name" && \
        kill -s "$signal_name" "$child" 2>/dev/null; then
        PROJECT_GUARD_PENDING_SIGNAL=""
        return 0
      fi
    else
      signal_state=$?
    fi
    if ((signal_state == 1)); then
      # Only GNU env can still be in the inherited-ignore launch stage. Kill
      # that exact child and let flock retain the lock until it is reaped.
      if project_guard_supervisor_identity_matches \
          "$supervisor_pid" "$supervisor_start_time" && \
        load_project_guard_process_stat_identity "$child" && \
        current_child_start_time="$PROJECT_GUARD_PROCESS_START_TIME" && \
        [[ "$current_child_start_time" == "$child_start_time" ]]; then
        if project_guard_child_signal_state \
          "$child" "$supervisor_pid" "$signal_name"; then
          signal_state=0
        else
          signal_state=$?
        fi
      else
        signal_state=2
      fi
      if ((signal_state == 1)) && kill -KILL "$child" 2>/dev/null; then
        PROJECT_GUARD_PENDING_SIGNAL=""
        return 0
      fi
    elif ((signal_state == 2)); then
      log_error \
        "could not prove the guarded child identity while forwarding $signal_name"
    fi
  else
    log_error \
      "could not identify one guarded child while forwarding $signal_name"
  fi
  return 1
}

wait_for_project_guard_holder() {
  local -r holder_pid="$1"
  local -r lock_file="$2"
  local -r relay_pid="$3"
  local -r relay_start_time="$4"
  local holder_start_time="${5:-}"
  local -r launch_accepted="${6:-false}"
  local holder_status=0
  local wait_probe_pid=""
  local recorded_holder_start_time=""
  local published_status=""
  local observed_signal=""
  local unanchored_state=""
  local unanchored_start_time=""
  local unanchored_extra=""
  local lock_protocol_failed=false
  local status_protocol_failed=false

  [[ "$holder_pid" =~ ^[1-9][0-9]*$ && \
    "$relay_pid" =~ ^[1-9][0-9]*$ && \
    "$relay_start_time" =~ ^[0-9]+$ ]] || return 1
  [[ "$launch_accepted" == true || "$launch_accepted" == false ]] || \
    return 1
  assert_private_project_guard_lock "$lock_file" || lock_protocol_failed=true
  [[ -z "$holder_start_time" || "$holder_start_time" =~ ^[0-9]+$ ]] || \
    return 1
  while :; do
    [[ -n "$observed_signal" ]] || observed_signal="$PROJECT_GUARD_PENDING_SIGNAL"
    if [[ -z "$holder_start_time" ]]; then
      if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]]; then
        trap '' HUP INT TERM
      fi
      # Before the worker self-publishes its holder start time, no numeric PID
      # is safe to signal or bind. Never call wait while this child is live:
      # a signal can interrupt that wait and make Bash cache a synthetic
      # 129/130/143 in place of the eventual child status. Poll until the
      # unreaped child is terminal (or /proc is definitely absent), then make
      # that fixed child result the pre-acceptance terminal boundary.
      if load_project_guard_process_stat_identity "$holder_pid"; then
        unanchored_state="$PROJECT_GUARD_PROCESS_STATE"
        unanchored_start_time="$PROJECT_GUARD_PROCESS_START_TIME"
        unanchored_extra=""
        if [[ -n "$unanchored_state" && -z "$unanchored_extra" && \
          "$unanchored_start_time" =~ ^[0-9]+$ && \
          "$unanchored_state" != Z && "$unanchored_state" != X ]]; then
          sleep 0.01 || true
          continue
        fi
      elif [[ -e "/proc/$holder_pid" ]]; then
        sleep 0.01 || true
        continue
      fi
      trap '' HUP INT TERM
      if wait "$holder_pid"; then
        holder_status=0
      else
        holder_status=$?
      fi
      [[ "$lock_protocol_failed" == false ]] || return 1
      # A successful pre-acceptance exit cannot prove the worker's terminal
      # protocol, and 255 is Bash's ambiguous lost-status result.
      if ((holder_status > 0 && holder_status < 255)); then
        return "$holder_status"
      fi
      return 1
    fi
    if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]]; then
      # The relay records the first cooperative cancellation. Disarm its
      # handlers from ordinary control flow before a child-table wait so a
      # repeated signal cannot make that exact wait look like a holder exit.
      trap '' HUP INT TERM
    fi
    if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" && \
      -n "$holder_start_time" && \
      "$holder_start_time" =~ ^[0-9]+$ ]]; then
      PROJECT_GUARD_SUPERVISOR_PID="$holder_pid"
      PROJECT_GUARD_SUPERVISOR_START_TIME="$holder_start_time"
      PROJECT_GUARD_FORWARDING_READY=true
      forward_project_guard_signal "$PROJECT_GUARD_PENDING_SIGNAL" || true
    fi
    if project_guard_supervisor_is_running "$holder_pid" "$holder_start_time"; then
      wait_probe_pid=""
      sleep 0.01 &
      wait_probe_pid=$!
      wait -n "$holder_pid" "$wait_probe_pid" 2>/dev/null || true
      wait "$wait_probe_pid" 2>/dev/null || true
      [[ -n "$observed_signal" ]] || \
        observed_signal="$PROJECT_GUARD_PENDING_SIGNAL"
      if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]]; then
        PROJECT_GUARD_SUPERVISOR_PID="$holder_pid"
        PROJECT_GUARD_SUPERVISOR_START_TIME="$holder_start_time"
        PROJECT_GUARD_FORWARDING_READY=true
        forward_project_guard_signal "$PROJECT_GUARD_PENDING_SIGNAL" || true
      fi
      continue
    fi

    # The worker has crossed its terminal boundary before the holder becomes
    # non-running. Ignore later relay-directed signals before reaping and
    # validating the immutable terminal record, so post-commit cancellation
    # cannot interrupt Bash while it expands that record.
    trap '' HUP INT TERM
    if wait "$holder_pid"; then
      holder_status=0
    else
      holder_status=$?
    fi
    [[ -n "$observed_signal" ]] || observed_signal="$PROJECT_GUARD_PENDING_SIGNAL"

    if [[ -e "$PROJECT_GUARD_CONTROL_DIR/holder-status" || \
      -L "$PROJECT_GUARD_CONTROL_DIR/holder-status" ]]; then
      if load_project_guard_holder_status \
          "$relay_pid" "$relay_start_time" \
          "$holder_pid" "$holder_start_time"; then
        recorded_holder_start_time="$PROJECT_GUARD_LOADED_HOLDER_START_TIME"
        published_status="$PROJECT_GUARD_LOADED_HOLDER_STATUS"
        if [[ "$recorded_holder_start_time" =~ ^[0-9]+$ && \
          "$published_status" =~ ^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
          holder_start_time="$recorded_holder_start_time"
          # The authenticated worker publishes before it exits. The anchored
          # holder becoming non-running is therefore the PID-reuse-safe
          # terminal condition; never consult Bash's stale job table here.
          if ! project_guard_supervisor_is_running \
            "$holder_pid" "$holder_start_time"; then
            [[ "$lock_protocol_failed" == false && \
              "$status_protocol_failed" == false ]] || return 1
            return "$published_status"
          fi
        else
          status_protocol_failed=true
        fi
      else
        status_protocol_failed=true
      fi
    fi

    # A completed child-table wait reaps the exact holder even when an
    # authenticated status record was already available. This is deliberately
    # after status validation so stale Bash job metadata cannot become status
    # authority.
    if [[ "$holder_status" -eq 255 ]]; then
      holder_status=1
    fi

    if [[ -n "$holder_start_time" ]] && \
      ! project_guard_supervisor_is_running "$holder_pid" "$holder_start_time"; then
      [[ "$lock_protocol_failed" == false ]] || return 1
      [[ "$status_protocol_failed" == false ]] || return 1
      [[ "$launch_accepted" == false ]] || return 1
      # An accepted worker may not exit without its exact terminal-status
      # record. A worker killed before it could initialize that protocol can
      # only report the relay's already-recorded cancellation; every other
      # missing, malformed, or unpublished state fails closed.
      case "${observed_signal:-$PROJECT_GUARD_PENDING_SIGNAL}" in
        HUP) return 129 ;;
        INT|TERM) return 130 ;;
        *)
          # Before the recursive worker initializes its authenticated status
          # protocol, the child-table-bound wait result is the only terminal
          # authority (notably flock's conflict status 75). Bash uses 255 for
          # the lost-status/phantom-job race, so never accept that ambiguous
          # value or an unexplained success without a published record.
          if ((holder_status > 0 && holder_status < 255)); then
            return "$holder_status"
          fi
          return 1
          ;;
      esac
    fi

    sleep 0.01 || true
  done
}

run_project_guard_relay() {
  local -r lock_file="$1"
  shift
  local -r relay_pid="$BASHPID"
  local relay_start_time=""
  local holder_pid=""
  local holder_start_time=""
  local holder_state=""
  local holder_observed_start=""
  local holder_extra=""
  local holder_status=0
  local launch_ready=false
  local launch_accepted=false
  local launch_signal=""
  local decision_sent=false
  local -i attempt=0

  publish_project_guard_supervisor_identity || return $?
  load_project_guard_supervisor_identity \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" "$relay_pid" || return 1
  relay_start_time="$PROJECT_GUARD_LOADED_SUPERVISOR_START_TIME"
  PROJECT_GUARD_SUPERVISOR_PID="$relay_pid"
  PROJECT_GUARD_SUPERVISOR_START_TIME="$relay_start_time"
  project_guard_supervisor_identity_matches \
    "$relay_pid" "$relay_start_time" || return 1
  publish_project_guard_supervisor_acceptance \
    "$relay_pid" "$relay_start_time" || return $?

  set -m
  env --ignore-signal=HUP,INT,TERM \
    flock --exclusive --nonblock --close --conflict-exit-code 75 \
      "$lock_file" \
      env --default-signal=HUP,INT,TERM \
        bash -c '
          set -Eeuo pipefail
          relay_pid="$1"
          control_dir="$2"
          runner="$3"
          shift 3
          exec env \
            OBI_DEMO_PROJECT_GUARD_ACTIVE=1 \
            OBI_DEMO_PROJECT_GUARD_CONTROL_DIR="$control_dir" \
            OBI_DEMO_PROJECT_GUARD_SUPERVISOR_PID="$relay_pid" \
            OBI_DEMO_PROJECT_GUARD_PARENT_PID="$PPID" \
            "$runner" "$@"
        ' bash "$relay_pid" "$PROJECT_GUARD_CONTROL_DIR" \
          "$SCRIPT_DIR/$SCRIPT_NAME" "$@" &
  holder_pid=$!
  set +m
  [[ "$-" != *m* ]] || return 1

  for ((attempt = 0; attempt < PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS; attempt++)); do
    if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" && \
      "$holder_observed_start" =~ ^[0-9]+$ ]]; then
      [[ -n "$launch_signal" ]] || \
        launch_signal="$PROJECT_GUARD_PENDING_SIGNAL"
      PROJECT_GUARD_SUPERVISOR_PID="$holder_pid"
      PROJECT_GUARD_SUPERVISOR_START_TIME="$holder_observed_start"
      PROJECT_GUARD_FORWARDING_READY=true
      forward_project_guard_signal "$PROJECT_GUARD_PENDING_SIGNAL" || true
    fi
    load_project_guard_process_stat_identity "$holder_pid" || break
    holder_state="$PROJECT_GUARD_PROCESS_STATE"
    holder_observed_start="$PROJECT_GUARD_PROCESS_START_TIME"
    holder_extra=""
    [[ -n "$holder_state" && -z "$holder_extra" && \
      "$holder_observed_start" =~ ^[0-9]+$ && \
      "$holder_state" != Z && "$holder_state" != X ]] || break
    if [[ -e "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" || \
      -L "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" ]]; then
      if load_project_guard_supervisor_launch \
        "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" \
        "$relay_pid" "$relay_start_time" "$holder_pid"; then
        holder_start_time="$PROJECT_GUARD_LOADED_HOLDER_START_TIME"
      else
        holder_start_time=""
      fi
      [[ -n "$holder_start_time" ]] && launch_ready=true
      break
    fi
    sleep 0.05 || true
  done
  if [[ "$launch_ready" != true ]]; then
    [[ -n "$launch_signal" ]] || launch_signal="$PROJECT_GUARD_PENDING_SIGNAL"
    # A rejected launch still enters the worker's ordinary cleanup path. Let
    # that trusted worker finish its terminal handoff and publish the exact
    # holder status before reaping it; otherwise the worker and relay would
    # wait on each other after a malformed launch record.
    for ((attempt = 0; attempt < PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS; attempt++)); do
      if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" && \
        "$holder_observed_start" =~ ^[0-9]+$ ]]; then
        [[ -n "$launch_signal" ]] || \
          launch_signal="$PROJECT_GUARD_PENDING_SIGNAL"
        PROJECT_GUARD_SUPERVISOR_PID="$holder_pid"
        PROJECT_GUARD_SUPERVISOR_START_TIME="$holder_observed_start"
        PROJECT_GUARD_FORWARDING_READY=true
        forward_project_guard_signal "$PROJECT_GUARD_PENDING_SIGNAL" || true
      fi
      if project_guard_control_file_matches \
        "$PROJECT_GUARD_CONTROL_DIR/ready" ready; then
        if publish_project_guard_terminal_decision; then
          decision_sent=true
        fi
        break
      fi
      if [[ "$holder_observed_start" =~ ^[0-9]+$ ]] && \
        ! project_guard_supervisor_is_running \
          "$holder_pid" "$holder_observed_start"; then
        break
      fi
      sleep 0.05 || true
    done
    if [[ "$holder_observed_start" =~ ^[0-9]+$ ]] && \
      project_guard_supervisor_is_running \
        "$holder_pid" "$holder_observed_start"; then
      [[ -n "$launch_signal" ]] || launch_signal=TERM
      PROJECT_GUARD_SUPERVISOR_PID="$holder_pid"
      PROJECT_GUARD_SUPERVISOR_START_TIME="$holder_observed_start"
      PROJECT_GUARD_FORWARDING_READY=true
      PROJECT_GUARD_PENDING_SIGNAL=TERM
      forward_project_guard_signal TERM || true
    fi
    if wait_for_project_guard_holder \
      "$holder_pid" "$lock_file" "$relay_pid" "$relay_start_time" \
      "$holder_observed_start" false; then
      holder_status=0
    else
      holder_status=$?
    fi
    # A process-group TERM can reach the recursive worker after GNU env has
    # restored default dispositions but before run.sh installs its own traps.
    # That pre-acceptance path cannot mutate Docker, yet Bash reports the raw
    # signal status 143. Normalize only this exact matching cancellation to
    # the runner's canonical TERM status; preserve every unrelated failure.
    if [[ "$launch_signal" == TERM && \
      "$holder_status" -eq 143 ]]; then
      holder_status=130
    elif [[ "$launch_signal" == HUP && \
      "$holder_status" -eq 129 ]]; then
      holder_status=129
    elif [[ "$launch_signal" == INT && \
      "$holder_status" -eq 130 ]]; then
      holder_status=130
    fi
    ((holder_status != 0)) || holder_status=1
    return "$holder_status"
  fi

  PROJECT_GUARD_SUPERVISOR_PID="$holder_pid"
  PROJECT_GUARD_SUPERVISOR_START_TIME="$holder_start_time"
  PROJECT_GUARD_FORWARDING_READY=true
  if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]]; then
    [[ -n "$launch_signal" ]] || \
      launch_signal="$PROJECT_GUARD_PENDING_SIGNAL"
    forward_project_guard_signal "$PROJECT_GUARD_PENDING_SIGNAL" || true
  fi
  if [[ -z "$launch_signal" && -z "$PROJECT_GUARD_PENDING_SIGNAL" ]]; then
    # The atomic acceptance publication may become visible even when its
    # command reports an error. From this attempt onward, require the
    # authenticated holder status and never fall back to the child-table
    # status of a worker that may already be mutating guarded state.
    launch_accepted=true
    if publish_project_guard_supervisor_launch_acceptance \
      "$relay_pid" "$relay_start_time" \
      "$holder_pid" "$holder_start_time"; then
      :
    else
      log_error "could not acknowledge the guarded worker launch"
    fi
  fi
  while project_guard_supervisor_is_running \
    "$holder_pid" "$holder_start_time"; do
    if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]]; then
      forward_project_guard_signal "$PROJECT_GUARD_PENDING_SIGNAL" || true
    fi
    # Once launch acceptance is published, the worker may be mutating Docker
    # or running the permanent-absence recovery. Keep the relay and flock
    # alive until that worker publishes its authenticated terminal status;
    # killing only one process group could release the lock while a nested
    # GNU timeout group or daemon mutation is still active.
    if [[ "$decision_sent" != true ]] && \
      project_guard_control_file_matches \
        "$PROJECT_GUARD_CONTROL_DIR/ready" ready; then
      if publish_project_guard_terminal_decision; then
        decision_sent=true
      else
        log_error "could not publish the project guard terminal decision"
      fi
    fi
    sleep 0.05 || true
  done
  PROJECT_GUARD_FORWARDING_READY=false
  PROJECT_GUARD_SUPERVISOR_PID=""
  PROJECT_GUARD_SUPERVISOR_START_TIME=""
  if wait_for_project_guard_holder \
    "$holder_pid" "$lock_file" \
    "$relay_pid" "$relay_start_time" "$holder_start_time" \
    "$launch_accepted"; then
    holder_status=0
  else
    holder_status=$?
  fi
  if [[ "$decision_sent" != true && "$holder_status" -eq 0 ]]; then
    log_error "guarded runner exited without the terminal status handoff"
    holder_status=1
  fi
  return "$holder_status"
}

enter_project_guard() {
  local lock_file=""
  local lock_identity=""
  local control_dir=""
  local guard_parent=""
  local parent_executable=""
  local supervisor_pid=""
  local supervisor_start_time=""
  local holder_start_time=""
  local relay_status=0

  [[ "$PROJECT_GUARD_HELD" == "false" ]] || {
    log_error "project guard was already acquired"
    return 1
  }
  prepare_project_guard_root || return $?
  lock_file="$(project_guard_lock_path)" || return $?
  if [[ ! -e "$lock_file" && ! -L "$lock_file" ]]; then
    if (umask 077; set -o noclobber; : >"$lock_file") 2>/dev/null; then
      :
    elif [[ ! -e "$lock_file" && ! -L "$lock_file" ]]; then
      log_error "could not create the persistent project guard lock"
      return 1
    fi
  fi
  assert_private_project_guard_lock "$lock_file" || {
    log_error "persistent project guard lock metadata is untrusted"
    return 1
  }
  lock_identity="$(stat --format='%d:%i' -- "$lock_file")" || return 1
  if [[ "${OBI_DEMO_PROJECT_GUARD_ACTIVE:-}" != 1 ]]; then
    control_dir="$(umask 077; mktemp -d \
      "$PROJECT_GUARD_ROOT/.terminal-handoff.XXXXXX")" || return 1
    assert_private_project_guard_control_directory "$control_dir" || {
      rmdir -- "$control_dir" 2>/dev/null || true
      log_error "project guard terminal handoff directory is untrusted"
      return 1
    }
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    set +m
    [[ "$-" != *m* ]] || {
      log_error "could not disable Bash job control for the project guard"
      return 1
    }
    PROJECT_GUARD_PENDING_SIGNAL=""
    PROJECT_GUARD_FORWARDING_READY=false
    PROJECT_GUARD_SUPERVISOR_PID=""
    PROJECT_GUARD_SUPERVISOR_START_TIME=""
    PROJECT_GUARD_STATUS_RELAY_PID=""
    PROJECT_GUARD_STATUS_RELAY_START_TIME=""
    PROJECT_GUARD_STATUS_HOLDER_PID=""
    PROJECT_GUARD_STATUS_HOLDER_START_TIME=""
    # Signal actions are pre-parsed, record-only handlers. Keep the armed relay
    # call graph free of command substitutions: Bash 5.2 can corrupt its parser
    # state when it dispatches even a simple trap across that boundary.
    trap record_project_guard_hup HUP
    trap record_project_guard_int INT
    trap record_project_guard_term TERM
    if run_project_guard_relay "$lock_file" "$@"; then
      relay_status=0
    else
      relay_status=$?
    fi
    remove_project_guard_control_directory "$control_dir" || \
      log_warn "could not remove the project guard terminal handoff directory"
    trap - ERR EXIT
    trap '' HUP INT TERM
    PROJECT_GUARD_PENDING_SIGNAL=""
    PROJECT_GUARD_SUPERVISOR_PID=""
    PROJECT_GUARD_SUPERVISOR_START_TIME=""
    PROJECT_GUARD_STATUS_RELAY_PID=""
    PROJECT_GUARD_STATUS_RELAY_START_TIME=""
    PROJECT_GUARD_STATUS_HOLDER_PID=""
    PROJECT_GUARD_STATUS_HOLDER_START_TIME=""
    PROJECT_GUARD_CONTROL_DIR=""
    if ((relay_status == 75)); then
      log_error "project guard is already held for $PROJECT_NAME"
    fi
    exit "$relay_status"
  fi
  guard_parent="${OBI_DEMO_PROJECT_GUARD_PARENT_PID:-}"
  supervisor_pid="${OBI_DEMO_PROJECT_GUARD_SUPERVISOR_PID:-}"
  control_dir="${OBI_DEMO_PROJECT_GUARD_CONTROL_DIR:-}"
  unset OBI_DEMO_PROJECT_GUARD_ACTIVE OBI_DEMO_PROJECT_GUARD_CONTROL_DIR \
    OBI_DEMO_PROJECT_GUARD_PARENT_PID OBI_DEMO_PROJECT_GUARD_SUPERVISOR_PID
  [[ "$guard_parent" =~ ^[1-9][0-9]*$ && "$guard_parent" == "$PPID" ]] || {
    log_error "project guard parent identity is invalid"
    return 1
  }
  parent_executable="$(readlink -f -- "/proc/$guard_parent/exe")" || return 1
  [[ "${parent_executable##*/}" == flock ]] || {
    log_error "project guard is not owned by the expected flock supervisor"
    return 1
  }
  assert_private_project_guard_control_directory "$control_dir" || {
    log_error "project guard terminal handoff directory is untrusted"
    return 1
  }
  PROJECT_GUARD_CONTROL_DIR="$control_dir"
  PROJECT_GUARD_LOCK_IDENTITY="$lock_identity"
  PROJECT_GUARD_PARENT_PID="$guard_parent"
  PROJECT_GUARD_HELD=true
  assert_project_guard_held || {
    log_error "project guard lock was not held by its supervisor"
    return 1
  }
  supervisor_start_time="$(read_project_guard_supervisor_identity \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" "$supervisor_pid")" || {
    log_error "project guard relay identity is invalid"
    return 1
  }
  holder_start_time="$(project_guard_process_start_time "$guard_parent")" || {
    log_error "project guard holder identity is invalid"
    return 1
  }
  PROJECT_GUARD_STATUS_RELAY_PID="$supervisor_pid"
  PROJECT_GUARD_STATUS_RELAY_START_TIME="$supervisor_start_time"
  PROJECT_GUARD_STATUS_HOLDER_PID="$guard_parent"
  PROJECT_GUARD_STATUS_HOLDER_START_TIME="$holder_start_time"
  publish_project_guard_supervisor_launched \
    "$supervisor_pid" "$guard_parent" || {
    log_error "could not publish guarded runner launch readiness"
    return 1
  }
  holder_start_time="$(read_project_guard_supervisor_launch \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" \
    "$supervisor_pid" "$supervisor_start_time" "$guard_parent")" || {
    log_error "guarded runner launch identity is invalid"
    return 1
  }
  wait_for_project_guard_supervisor_launch_acceptance \
    "$supervisor_pid" "$guard_parent" || {
    log_error "guarded runner launch was not acknowledged"
    return 1
  }
  PROJECT_DOCKER_SERVER_ID_SHA256="$(resolve_docker_server_identity)" || {
    log_error "could not bind the project guard to the Docker server"
    PROJECT_GUARD_HELD=false
    PROJECT_GUARD_LOCK_IDENTITY=""
    PROJECT_GUARD_PARENT_PID=""
    return 1
  }
}

assert_project_guard_held() {
  local lock_file=""
  local path_identity=""
  local parent_executable=""

  [[ "$PROJECT_GUARD_HELD" == "true" && \
    "$PROJECT_GUARD_PARENT_PID" =~ ^[1-9][0-9]*$ && \
    "$PROJECT_GUARD_PARENT_PID" == "$PPID" && \
    "$PROJECT_GUARD_LOCK_IDENTITY" =~ ^[0-9]+:[0-9]+$ ]] || return 1
  lock_file="$(project_guard_lock_path)" || return 1
  assert_private_project_guard_directory "$PROJECT_GUARD_ROOT" || return 1
  assert_private_project_guard_lock "$lock_file" || return 1
  path_identity="$(stat --format='%d:%i' -- "$lock_file")" || return 1
  [[ "$path_identity" == "$PROJECT_GUARD_LOCK_IDENTITY" ]] || return 1
  parent_executable="$(readlink -f -- "/proc/$PROJECT_GUARD_PARENT_PID/exe")" || return 1
  [[ "${parent_executable##*/}" == flock ]] || return 1
  if flock --exclusive --nonblock "$lock_file" true >/dev/null 2>&1; then
    return 1
  fi
}

assert_project_docker_identity_unchanged() {
  local current=""

  assert_project_guard_held || return 1
  [[ "$PROJECT_DOCKER_SERVER_ID_SHA256" =~ ^[0-9a-f]{64}$ ]] || return 1
  current="$(resolve_docker_server_identity)" || return 1
  [[ "$current" == "$PROJECT_DOCKER_SERVER_ID_SHA256" ]] || {
    log_error "Docker server identity changed while project $PROJECT_NAME was guarded"
    return 1
  }
}

release_project_guard() {
  PROJECT_GUARD_HELD=false
  PROJECT_GUARD_LOCK_IDENTITY=""
  PROJECT_GUARD_PARENT_PID=""
  PROJECT_GUARD_PENDING_SIGNAL=""
  PROJECT_GUARD_FORWARDING_READY=false
  PROJECT_GUARD_SUPERVISOR_PID=""
  PROJECT_GUARD_SUPERVISOR_START_TIME=""
  PROJECT_DOCKER_SERVER_ID_SHA256=""
}

on_error() {
  local -r line="$1"
  local -r status="$2"
  local -r command="$3"

  CLEANUP_ENTRY_ACTIVE=true
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
  if [[ -n "$UNIX_SECURITY_JAVA_CONTAINER" && \
    "$UNIX_SECURITY_NAMESPACE_PID" =~ ^[1-9][0-9]*$ ]]; then
    # Expanded by the container shell, not this process.
    # shellcheck disable=SC2016
    run_bounded 10 docker exec "$UNIX_SECURITY_JAVA_CONTAINER" \
      /bin/sh -ec '
        if read -r name <"/proc/$1/comm" && [ "$name" = security-probe ]; then
          kill -TERM "$1" 2>/dev/null || true
        fi
      ' sh \
      "$UNIX_SECURITY_NAMESPACE_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$UNIX_SECURITY_EXEC_PID" =~ ^[1-9][0-9]*$ ]]; then
    if kill -0 "$UNIX_SECURITY_EXEC_PID" 2>/dev/null; then
      kill -TERM "$UNIX_SECURITY_EXEC_PID" 2>/dev/null || true
    fi
    wait "$UNIX_SECURITY_EXEC_PID" 2>/dev/null || true
  fi
  if [[ -n "$UNIX_SECURITY_SIBLING_CONTAINER" ]]; then
    run_bounded 10 docker kill "$UNIX_SECURITY_SIBLING_CONTAINER" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$UNIX_SECURITY_ENDPOINT_CONTAINER" ]]; then
    run_bounded 10 docker kill "$UNIX_SECURITY_ENDPOINT_CONTAINER" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$UNIX_SECURITY_JAVA_CONTAINER" && \
    "$UNIX_SECURITY_PROBE_DIRECTORY" =~ ^/tmp/obi-unix-security\.[[:alnum:]]{6,}$ ]]; then
    run_bounded 10 docker exec "$UNIX_SECURITY_JAVA_CONTAINER" \
      rm -rf -- "$UNIX_SECURITY_PROBE_DIRECTORY" >/dev/null 2>&1 || true
  fi
  if [[ -n "$UNIX_SECURITY_HOST_PROBE" ]]; then
    rm -f -- "$UNIX_SECURITY_HOST_PROBE" || true
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
  UNIX_SECURITY_SIBLING_CONTAINER=""
  UNIX_SECURITY_ENDPOINT_CONTAINER=""
  UNIX_SECURITY_EXEC_PID=""
  UNIX_SECURITY_HOST_PROBE=""
  UNIX_SECURITY_JAVA_CONTAINER=""
  UNIX_SECURITY_NAMESPACE_PID=""
  UNIX_SECURITY_PROBE_DIRECTORY=""
}

record_cleanup_signal() {
  local -r signal_name="$1"

  ((CLEANUP_SIGNAL_STATUS == 0)) || return 0
  case "$signal_name" in
    HUP) CLEANUP_SIGNAL_STATUS=129 ;;
    INT|TERM) CLEANUP_SIGNAL_STATUS=130 ;;
    *) return 1 ;;
  esac
}

record_cleanup_hup() {
  record_cleanup_signal HUP
}

record_cleanup_int() {
  record_cleanup_signal INT
}

record_cleanup_term() {
  record_cleanup_signal TERM
}

cleanup() {
  local -r status="${1:-$?}"
  local final_status="$status"
  local cleanup_status=0
  local force_stack_shutdown=false
  local global_permanent_absence_marker=""
  local primary_fault_recovery_marker=""
  local primary_fault_recovery_stage=""
  local publication_succeeded=false
  local holder_status_authorized=false
  local holder_status_before=0
  CLEANUP_ENTRY_ACTIVE=true
  trap record_cleanup_hup HUP
  trap record_cleanup_int INT
  trap record_cleanup_term TERM
  trap - ERR EXIT
  set +e

  if ((status != 0)) && [[ -z "$FAILURE_STAGE" ]]; then
    record_failure "$RUN_STAGE" 0 "$status" "exit"
  fi
  if [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
    for primary_fault_recovery_marker in \
      "$RESULT_DIR/primary-w3c-fault-recovery-required" \
      "$RESULT_DIR/primary-generation-mismatch-recovery-required" \
      "$RESULT_DIR/unix-generation-mismatch-recovery-required" \
      "$RESULT_DIR/permanent-absence-recovery-required" \
      "$RESULT_DIR/primary-live-fd-security-recovery-required"; do
      if [[ -e "$primary_fault_recovery_marker" || -L "$primary_fault_recovery_marker" ]]; then
        primary_fault_recovery_stage="${primary_fault_recovery_marker##*/}"
        primary_fault_recovery_stage="${primary_fault_recovery_stage%-recovery-required}"
        force_stack_shutdown=true
        PRIMARY_FAULT_STACK_ACTIVE=true
        log_error "$primary_fault_recovery_stage recovery is incomplete; refusing to leave the fault stack running"
        if ((final_status == 0)); then
          final_status=1
          record_failure \
            "$primary_fault_recovery_stage-recovery" 0 1 "incomplete primary fault recovery"
        fi
      fi
    done
  fi
  if [[ "$PROJECT_GUARD_HELD" == "true" ]]; then
    global_permanent_absence_marker="$(permanent_absence_global_marker_path)" || true
    if [[ -n "$global_permanent_absence_marker" && \
      ( -e "$global_permanent_absence_marker" || \
        -L "$global_permanent_absence_marker" ) ]]; then
      force_stack_shutdown=true
      PRIMARY_FAULT_STACK_ACTIVE=true
      if ((final_status == 0)); then
        final_status=1
        record_failure \
          "permanent-absence-recovery" 0 1 \
          "incomplete host-shared permanent-absence recovery"
      fi
    fi
  fi

  if cleanup_diagnostic_nondisclosure_request_directory; then
    :
  else
    cleanup_status=$?
    log_error "could not remove private diagnostic nondisclosure request inputs"
    if ((final_status == 0)); then
      ((cleanup_status != 0)) || cleanup_status=1
      final_status="$cleanup_status"
      record_failure \
        "temporary-cleanup" 0 "$cleanup_status" \
        "cleanup_diagnostic_nondisclosure_request_directory"
    fi
  fi

  if ((final_status != 0)) && \
    [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
    if seal_terminal_java_diagnostics; then
      :
    else
      cleanup_status=$?
      log_error "could not seal Java bridge diagnostics before cleanup recovery"
    fi
  fi

  if [[ "$PRESSURE_ACTIVE" == "true" ]]; then
    cleanup_map_pressure_with_retries || true
  fi
  if cleanup_delayed_otlp_receiver_temporaries; then
    :
  else
    cleanup_status=$?
    log_error "could not remove delayed OTLP receiver temporary evidence"
    if ((final_status == 0)); then
      final_status="$cleanup_status"
      record_failure \
        "temporary-cleanup" 0 "$cleanup_status" \
        "cleanup_delayed_otlp_receiver_temporaries"
    fi
  fi
  cleanup_security_processes
  if [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
    capture_evidence
  fi
  if [[ "$FAULT_BRIDGE_RUNNING" == "true" ]]; then
    log_warn "stopping the transient W3C fault bridge"
    if ! stop_w3c_fault_bridge; then
      log_error "could not stop the transient W3C fault bridge"
    fi
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
  if [[ "$STACK_STARTED" == "true" && \
    ( "$KEEP_RUNNING" == "false" || "$force_stack_shutdown" == "true" ) ]]; then
    log_info "stopping scoped Compose project $PROJECT_NAME"
    if assert_permanent_absence_marker_matches_current_docker && \
      invalidate_project_transport_evidence; then
      BRIDGE_RUNNING=false
      if safe_compose_down >/dev/null 2>&1; then
        OBI_RUNNING=false
        if clear_pending_permanent_absence_recovery; then
          :
        else
          cleanup_status=$?
          log_error "could not clear verified permanent-absence recovery state"
          if ((final_status == 0)); then
            final_status="$cleanup_status"
            record_failure \
              "compose-cleanup" 0 "$cleanup_status" \
              "clear_pending_permanent_absence_recovery"
          fi
        fi
      else
        cleanup_status=$?
        log_error "Compose project cleanup was refused or failed"
        if ((final_status == 0)); then
          final_status="$cleanup_status"
          record_failure "compose-cleanup" 0 "$cleanup_status" "safe_compose_down"
        fi
      fi
    else
      cleanup_status=$?
      log_error "project guard or transport state could not be validated before cleanup"
      if ((final_status == 0)); then
        ((cleanup_status != 0)) || cleanup_status=1
        final_status="$cleanup_status"
        record_failure \
          "compose-cleanup" 0 "$cleanup_status" \
          "invalidate_project_transport_evidence"
      fi
    fi
  elif [[ "$STACK_STARTED" == "true" ]]; then
    log_warn "leaving Compose project $PROJECT_NAME running by request"
  fi
  cleanup_source_snapshot_work_directory
  if [[ -n "${SOURCE_SNAPSHOT_DIR:-}" && \
    "$SOURCE_SNAPSHOT_DIR" == "$SOURCE_SNAPSHOT_PARENT"/obi-source-snapshot.* && \
    -d "$SOURCE_SNAPSHOT_DIR" && ! -L "$SOURCE_SNAPSHOT_DIR" ]]; then
    if unseal_source_snapshot; then
      rm -rf -- "$SOURCE_SNAPSHOT_DIR"
      SOURCE_SNAPSHOT_DIR=""
      SOURCE_SNAPSHOT_SCRIPT_DIR=""
    else
      log_error "could not unseal the private source snapshot for cleanup"
    fi
  fi
  if release_project_guard; then
    :
  else
    cleanup_status=$?
    log_error "could not release the host-shared project guard"
    if ((final_status == 0)); then
      final_status="$cleanup_status"
    fi
  fi
  if [[ -n "$PROJECT_GUARD_CONTROL_DIR" ]]; then
    if complete_project_guard_terminal_handoff; then
      if ((final_status == 0 && CLEANUP_SIGNAL_STATUS == 0 && \
        PROJECT_GUARD_HANDOFF_SIGNAL_STATUS != 0)); then
        final_status="$PROJECT_GUARD_HANDOFF_SIGNAL_STATUS"
        record_failure \
          "signal" 0 "$final_status" "supervisor cancellation before commit"
      fi
    else
      cleanup_status=$?
      log_error "project guard terminal status handoff failed"
      if ((final_status == 0)); then
        final_status="$cleanup_status"
        record_failure \
          "project-guard-handoff" 0 "$cleanup_status" \
          "complete_project_guard_terminal_handoff"
      fi
    fi
  fi
  # This is the terminal commit boundary. Signals received before it are
  # reflected in the canonical status below; signals received after it are
  # deliberately ignored so the retained status and process exit cannot
  # diverge while the bounded final publication completes.
  trap '' HUP INT TERM
  if ((status == 0 && CLEANUP_SIGNAL_STATUS != 0)); then
    final_status="$CLEANUP_SIGNAL_STATUS"
    if [[ -n "$FAILURE_STAGE" && "$FAILURE_STAGE" != signal ]]; then
      FAILURE_STAGE=""
      FAILURE_LINE=""
      FAILURE_STATUS=""
      FAILURE_COMMAND=""
    fi
    record_failure "signal" 0 "$final_status" "cleanup interrupted"
  fi
  if [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
    if publish_owned_run_status "$final_status"; then
      publication_succeeded=true
      holder_status_authorized=true
    else
      cleanup_status=$?
      log_error "could not publish and commit the final run status"
      if ((final_status == 0)); then
        ((cleanup_status != 0)) || cleanup_status=1
        final_status="$cleanup_status"
        record_failure \
          "evidence-publication" 0 "$cleanup_status" \
          "publish_owned_run_status"
      fi
      publication_succeeded=false
      holder_status_authorized=false
      if publish_owned_run_status "$final_status"; then
        publication_succeeded=true
        holder_status_authorized=true
      else
        cleanup_status=$?
        log_error "could not publish and commit the failed final run status"
      fi
    fi
  elif [[ -z "${RESULT_DIR:-}" ]]; then
    holder_status_authorized=true
  fi

  if [[ "$holder_status_authorized" == true &&
    "$PROJECT_GUARD_STATUS_RELAY_PID" =~ ^[1-9][0-9]*$ ]]; then
    if publish_project_guard_holder_status_with_retries "$final_status"; then
      if [[ "$publication_succeeded" == true ]]; then
        log_info "retained run evidence: $RESULT_DIR"
      fi
    else
      cleanup_status=$?
      log_error "could not publish the guarded runner terminal status"
      holder_status_before="$final_status"
      if ((final_status == 0)); then
        ((cleanup_status != 0)) || cleanup_status=1
        final_status="$cleanup_status"
        record_failure \
          "project-guard-status" 0 "$final_status" \
          "publish_project_guard_holder_status: original_status=$holder_status_before"
      fi
      if ((holder_status_before != final_status)) &&
        [[ -n "${RESULT_DIR:-}" && -d "$RESULT_DIR" ]]; then
        publication_succeeded=false
        holder_status_authorized=false
        if publish_owned_run_status "$final_status"; then
          publication_succeeded=true
          holder_status_authorized=true
        else
          log_error "could not replace the committed run status after holder failure"
        fi
      fi
      if [[ "$holder_status_authorized" == true ]] &&
        publish_project_guard_holder_status_with_retries "$final_status"; then
        if [[ "$publication_succeeded" == true ]]; then
          log_info "retained run evidence: $RESULT_DIR"
        fi
      else
        log_error "could not publish the final guarded runner terminal status"
      fi
    fi
  elif [[ "$publication_succeeded" == true ]]; then
    log_info "retained run evidence: $RESULT_DIR"
  fi

  exit "$final_status"
}

run_signal_hup() {
  record_cleanup_signal HUP
  if [[ "$CLEANUP_ENTRY_ACTIVE" != true ]]; then
    CLEANUP_ENTRY_ACTIVE=true
    record_failure "signal" 0 129 "HUP"
    exit 129
  fi
}

run_signal_int() {
  record_cleanup_signal INT
  if [[ "$CLEANUP_ENTRY_ACTIVE" != true ]]; then
    CLEANUP_ENTRY_ACTIVE=true
    record_failure "signal" 0 130 "INT"
    exit 130
  fi
}

run_signal_term() {
  record_cleanup_signal TERM
  if [[ "$CLEANUP_ENTRY_ACTIVE" != true ]]; then
    CLEANUP_ENTRY_ACTIVE=true
    record_failure "signal" 0 130 "TERM"
    exit 130
  fi
}

install_run_signal_traps() {
  trap run_signal_hup HUP
  trap run_signal_int INT
  trap run_signal_term TERM
}

cleanup_from_exit_trap() {
  local -r entry_status="$?"

  # Runtime signal handlers set CLEANUP_ENTRY_ACTIVE before requesting exit,
  # so a signal at cleanup entry is already record-only. Keep this wrapper's
  # trap source literal and parse-stable; nested dynamically expanded trap
  # strings can be torn when Bash dispatches a signal during reparsing.
  CLEANUP_ENTRY_STATUS="${CLEANUP_ENTRY_STATUS:-$entry_status}"
  CLEANUP_ENTRY_ACTIVE=true
  trap record_cleanup_hup HUP
  trap record_cleanup_int INT
  trap record_cleanup_term TERM
  cleanup "$CLEANUP_ENTRY_STATUS"
}

install_traps() {
  trap 'on_error "$LINENO" "$?" "$BASH_COMMAND"' ERR
  trap cleanup_from_exit_trap EXIT
  install_run_signal_traps
}

prepare_directories() {
  local run_id=""
  local candidate_result_dir=""
  local creation_status=0

  prepare_runtime_directory "$RUNTIME_DIR"
  prepare_runtime_directory "$ARTIFACT_DIR"
  prepare_runtime_directory "$CERT_DIR"
  prepare_runtime_directory "$RESULTS_ROOT"
  run_id="$(date -u +'%Y%m%dT%H%M%SZ')-$$"
  candidate_result_dir="$RESULTS_ROOT/$run_id"
  if RESULT_DIR="$(
    mkdir -- "$candidate_result_dir" || exit $?
    printf '%s\n' "$candidate_result_dir"
  )"; then
    return 0
  else
    creation_status=$?
  fi
  RESULT_DIR=""
  return "$creation_status"
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

assert_source_snapshot_parent_is_trusted() {
  local -r snapshot_parent="${1:-$SOURCE_SNAPSHOT_PARENT}"
  local root_physical=""
  local parent_physical=""
  local root_owner=""
  local root_mode=""
  local parent_owner=""
  local parent_mode=""
  local -i root_mode_bits=0
  local -i parent_mode_bits=0

  [[ "$snapshot_parent" == /* ]] || {
    die "source snapshot parent must be an absolute directory"
  }
  [[ -d / && ! -L / ]] || {
    die "source snapshot root is not a regular directory"
  }
  root_physical="$(cd -- / && pwd -P)" || {
    die "could not resolve the source snapshot filesystem root"
  }
  [[ "$root_physical" == / ]] || {
    die "source snapshot filesystem root must be physical"
  }
  root_owner="$(stat --format=%u -- /)" || {
    die "could not inspect the source snapshot filesystem root owner"
  }
  root_mode="$(stat --format=%a -- /)" || {
    die "could not inspect the source snapshot filesystem root mode"
  }
  [[ "$root_owner" == 0 && "$root_mode" =~ ^[0-7]{3,4}$ ]] || {
    die "source snapshot filesystem root ownership or mode is invalid"
  }
  root_mode_bits=$((8#$root_mode))
  (( (root_mode_bits & 0022) == 0 )) || {
    die "source snapshot filesystem root must not be group or world writable"
  }

  [[ -d "$snapshot_parent" && ! -L "$snapshot_parent" ]] || {
    die "source snapshot parent is not a regular directory"
  }
  parent_physical="$(cd -- "$snapshot_parent" && pwd -P)" || {
    die "could not resolve the source snapshot parent"
  }
  [[ "$parent_physical" == "$snapshot_parent" ]] || {
    die "source snapshot parent must be a physical directory"
  }
  parent_owner="$(stat --format=%u -- "$snapshot_parent")" || {
    die "could not inspect the source snapshot parent owner"
  }
  parent_mode="$(stat --format=%a -- "$snapshot_parent")" || {
    die "could not inspect the source snapshot parent mode"
  }
  [[ "$parent_owner" == 0 && "$parent_mode" =~ ^[0-7]{3,4}$ ]] || {
    die "source snapshot parent ownership or mode is invalid"
  }
  parent_mode_bits=$((8#$parent_mode))
  (( (parent_mode_bits & 01000) != 0 && (parent_mode_bits & 0002) != 0 )) || {
    die "source snapshot parent must be root-owned, sticky, and world writable"
  }
}

assert_source_snapshot_root_has_mode() {
  local -r expected_mode="$1"
  local snapshot_physical=""
  local owner=""
  local mode=""

  [[ -d "$SOURCE_SNAPSHOT_DIR" && ! -L "$SOURCE_SNAPSHOT_DIR" ]] || {
    die "source snapshot is not a regular directory"
  }
  snapshot_physical="$(cd -- "$SOURCE_SNAPSHOT_DIR" && pwd -P)" || {
    die "could not resolve the source snapshot directory"
  }
  [[ "$snapshot_physical" == "$SOURCE_SNAPSHOT_DIR" ]] || {
    die "source snapshot must be a physical directory"
  }
  owner="$(stat --format=%u -- "$SOURCE_SNAPSHOT_DIR")" || {
    die "could not inspect the source snapshot owner"
  }
  mode="$(stat --format=%a -- "$SOURCE_SNAPSHOT_DIR")" || {
    die "could not inspect the source snapshot mode"
  }
  [[ "$expected_mode" =~ ^[0-7]{3,4}$ && "$owner" == "$EUID" && \
    "$mode" == "$expected_mode" ]] || {
    die "source snapshot ownership or mode is invalid"
  }
}

assert_source_snapshot_root_is_private() {
  assert_source_snapshot_parent_is_trusted
  assert_source_snapshot_root_has_mode 700
}

assert_sealed_source_snapshot_is_private() {
  assert_source_snapshot_parent_is_trusted
  assert_source_snapshot_root_has_mode 500
}

assert_source_snapshot_work_directory_is_private() {
  local work_physical=""
  local owner=""
  local mode=""

  assert_source_snapshot_parent_is_trusted
  [[ "$SOURCE_SNAPSHOT_WORK_DIR" == "$SOURCE_SNAPSHOT_PARENT"/obi-source-snapshot-work.* && \
    -d "$SOURCE_SNAPSHOT_WORK_DIR" && ! -L "$SOURCE_SNAPSHOT_WORK_DIR" ]] || {
    die "source snapshot work directory is unsafe"
  }
  work_physical="$(cd -- "$SOURCE_SNAPSHOT_WORK_DIR" && pwd -P)" || {
    die "could not resolve the source snapshot work directory"
  }
  [[ "$work_physical" == "$SOURCE_SNAPSHOT_WORK_DIR" ]] || {
    die "source snapshot work directory must be physical"
  }
  owner="$(stat --format=%u -- "$SOURCE_SNAPSHOT_WORK_DIR")" || {
    die "could not inspect the source snapshot work directory owner"
  }
  mode="$(stat --format=%a -- "$SOURCE_SNAPSHOT_WORK_DIR")" || {
    die "could not inspect the source snapshot work directory mode"
  }
  [[ "$owner" == "$EUID" && "$mode" == 700 ]] || {
    die "source snapshot work directory ownership or mode is invalid"
  }
}

ensure_source_snapshot_work_directory() {
  if [[ -n "$SOURCE_SNAPSHOT_WORK_DIR" ]]; then
    assert_source_snapshot_work_directory_is_private
    return 0
  fi
  assert_source_snapshot_parent_is_trusted
  SOURCE_SNAPSHOT_WORK_DIR="$(
    mktemp -d "$SOURCE_SNAPSHOT_PARENT/obi-source-snapshot-work.XXXXXX"
  )" || {
    die "could not create the private source snapshot work directory"
  }
  assert_source_snapshot_work_directory_is_private
}

cleanup_source_snapshot_work_directory() {
  if [[ -n "${SOURCE_SNAPSHOT_WORK_DIR:-}" && \
    "$SOURCE_SNAPSHOT_WORK_DIR" == "$SOURCE_SNAPSHOT_PARENT"/obi-source-snapshot-work.* && \
    -d "$SOURCE_SNAPSHOT_WORK_DIR" && ! -L "$SOURCE_SNAPSHOT_WORK_DIR" ]]; then
    rm -rf -- "$SOURCE_SNAPSHOT_WORK_DIR"
  fi
  SOURCE_SNAPSHOT_WORK_DIR=""
  BRIDGE_EXPORT_DIR=""
}

assert_bridge_export_directory_is_private() {
  local export_physical=""
  local owner=""
  local mode=""

  assert_source_snapshot_work_directory_is_private
  [[ "$BRIDGE_EXPORT_DIR" == "$SOURCE_SNAPSHOT_WORK_DIR"/bridge-export.* && \
    -d "$BRIDGE_EXPORT_DIR" && ! -L "$BRIDGE_EXPORT_DIR" ]] || {
    die "bridge export directory is unsafe"
  }
  export_physical="$(cd -- "$BRIDGE_EXPORT_DIR" && pwd -P)" || {
    die "could not resolve the bridge export directory"
  }
  [[ "$export_physical" == "$BRIDGE_EXPORT_DIR" ]] || {
    die "bridge export directory must be physical"
  }
  owner="$(stat --format=%u -- "$BRIDGE_EXPORT_DIR")" || {
    die "could not inspect the bridge export directory owner"
  }
  mode="$(stat --format=%a -- "$BRIDGE_EXPORT_DIR")" || {
    die "could not inspect the bridge export directory mode"
  }
  [[ "$owner" == "$EUID" && "$mode" == 700 ]] || {
    die "bridge export directory ownership or mode is invalid"
  }
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

capture_clean_source_tree_manifest() {
  local -r output="$1"
  local entries=""
  local manifest=""
  local entry=""
  local metadata=""
  local path=""
  local mode=""
  local object_id=""
  local marker=""

  ensure_source_snapshot_work_directory
  entries="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-tree-v2.entries.XXXXXX")" || {
    die "could not prepare clean source Git-tree entries"
  }
  manifest="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-tree-v2.manifest.XXXXXX")" || {
    die "could not prepare clean source Git-tree manifest"
  }
  git -C "$REPO_ROOT" ls-tree -r -z --full-tree "$SOURCE_REVISION" >"$entries" || {
    die "could not enumerate the clean source Git tree"
  }
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    is_safe_git_tree_path "$path" || {
      die "clean source Git tree has an unsafe path"
    }
    case "$mode" in
      100644) marker='-' ;;
      100755) marker='x' ;;
      120000) marker='l' ;;
      160000) marker='g' ;;
      *) die "unsupported clean source Git-tree mode: $mode" ;;
    esac
    [[ "$object_id" =~ ^[0-9a-f]{40}$ ]] || {
      die "clean source Git tree has an invalid object identifier"
    }
    LC_ALL=C printf '%s %s %q\n' "$object_id" "$marker" "$path"
  done <"$entries" >"$manifest"
  mv -f -- "$manifest" "$output"
  rm -f -- "$entries"
}

capture_dirty_source_tree_manifest() {
  local -r output="$1"
  local executable=""
  local object_id=""
  local path=""

  (
    cd -- "$REPO_ROOT"
    while IFS= read -r -d '' path; do
      is_safe_git_tree_path "$path" || {
        printf '%s\n' "source working tree has an unsafe path" >&2
        exit 1
      }
      if [[ ! -f "$path" && ! -L "$path" ]]; then
        continue
      fi
      if [[ -L "$path" ]]; then
        object_id="$(readlink -z -- "$path" | head -c -1 | git hash-object --stdin)"
      else
        object_id="$(git hash-object -- "$path")"
      fi
      executable="-"
      if [[ -x "$path" ]]; then
        executable="x"
      fi
      printf '%s %s %q\n' "$object_id" "$executable" "$path"
    done < <(git ls-files --cached --others --exclude-standard -z | sort -z)
  ) >"$output"
}

assert_source_gitlink_is_pinned() {
  local -r gitlink_directory="$1"
  local -r expected_revision="$2"
  local gitlink_root=""
  local gitlink_physical=""
  local gitlink_revision=""

  [[ "$expected_revision" =~ ^[0-9a-f]{40}$ ]] || {
    die "source gitlink has an invalid revision"
  }
  [[ -d "$gitlink_directory" && ! -L "$gitlink_directory" ]] || {
    die "source gitlink is not an initialized regular directory"
  }
  gitlink_physical="$(cd -- "$gitlink_directory" && pwd -P)" || {
    die "could not resolve source gitlink directory"
  }
  gitlink_root="$(git -C "$gitlink_directory" rev-parse --show-toplevel)" || {
    die "could not resolve source gitlink worktree root"
  }
  gitlink_root="$(cd -- "$gitlink_root" && pwd -P)" || {
    die "could not resolve source gitlink worktree root physically"
  }
  [[ "$gitlink_root" == "$gitlink_physical" ]] || {
    die "source gitlink directory is not its own Git worktree"
  }
  gitlink_revision="$(git -C "$gitlink_directory" rev-parse HEAD)" || {
    die "could not resolve source gitlink revision"
  }
  [[ "$gitlink_revision" == "$expected_revision" ]] || {
    die "source gitlink revision differs from its recorded Git tree"
  }
}

assert_source_repository_index_is_fully_observed() {
  local -r repository="$1"
  local -r depth="$2"
  local index_flags=""
  local gitlinks=""
  local repository_root=""
  local repository_physical=""
  local entry=""
  local flag=""
  local metadata=""
  local mode=""
  local object_id=""
  local stage=""
  local path=""
  local gitlink_directory=""

  ((depth <= 16)) || die "source gitlink nesting exceeds the snapshot limit"
  ensure_source_snapshot_work_directory
  index_flags="$SOURCE_SNAPSHOT_WORK_DIR/.source-index-flags-$depth"
  gitlinks="$SOURCE_SNAPSHOT_WORK_DIR/.source-gitlinks-$depth"
  repository_physical="$(cd -- "$repository" && pwd -P)" || {
    die "could not resolve source repository directory"
  }
  repository_root="$(git -C "$repository" rev-parse --show-toplevel)" || {
    die "could not resolve source repository root"
  }
  repository_root="$(cd -- "$repository_root" && pwd -P)" || {
    die "could not resolve source repository root physically"
  }
  [[ "$repository_root" == "$repository_physical" ]] || {
    die "source gitlink directory is not its own Git worktree"
  }

  git -C "$repository" ls-files -v -z >"$index_flags" || {
    die "could not inspect source index flags"
  }
  while IFS= read -r -d '' entry; do
    flag="${entry:0:1}"
    case "$flag" in
      [a-z]|S)
        die "source index has assume-unchanged or skip-worktree entries"
        ;;
    esac
  done <"$index_flags"
  git -C "$repository" ls-files --stage -z >"$gitlinks" || {
    die "could not inspect source gitlinks"
  }
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    metadata="${metadata#* }"
    object_id="${metadata%% *}"
    stage="${metadata##* }"
    is_safe_git_tree_path "$path" || {
      die "source index has an unsafe path"
    }
    [[ "$stage" == 0 ]] || {
      die "source index has unresolved entries"
    }
    [[ "$mode" == 160000 ]] || continue
    gitlink_directory="$repository/$path"
    [[ "$object_id" =~ ^[0-9a-f]{40}$ ]] || {
      die "source gitlink has an invalid revision"
    }
    assert_source_gitlink_is_pinned "$gitlink_directory" "$object_id"
    assert_source_repository_index_is_fully_observed \
      "$gitlink_directory" "$((depth + 1))"
  done <"$gitlinks"
  rm -f -- "$index_flags" "$gitlinks"
}

assert_source_index_is_fully_observed() {
  ensure_source_snapshot_work_directory
  assert_source_repository_index_is_fully_observed "$REPO_ROOT" 0
}

assert_clean_source_checkout_is_stable() {
  local current_revision=""
  local current_status=""

  [[ "${SOURCE_DIRTY:-}" == false ]] || return 0
  sanitize_git_environment
  assert_source_index_is_fully_observed
  current_revision="$(git -C "$REPO_ROOT" rev-parse HEAD)" || {
    die "could not resolve the captured source revision"
  }
  [[ "$current_revision" == "$SOURCE_REVISION" ]] || {
    die "source revision changed after capture"
  }
  if ! git -C "$REPO_ROOT" diff --quiet --no-ext-diff "$SOURCE_REVISION" --; then
    die "source working tree changed after capture"
  fi
  if ! git -C "$REPO_ROOT" diff --cached --quiet --no-ext-diff "$SOURCE_REVISION" --; then
    die "source index changed after capture"
  fi
  current_status="$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all \
    --ignore-submodules=none)" || {
    die "could not inspect the captured source checkout"
  }
  [[ -z "$current_status" ]] || {
    die "source checkout became dirty after capture"
  }
}

capture_source_state() {
  local source_status=""
  local source_status_sha256=""
  local source_tree_manifest=""
  local source_tree_manifest_sha256=""

  sanitize_git_environment
  ensure_source_snapshot_work_directory
  source_status="$SOURCE_SNAPSHOT_WORK_DIR/git-status.txt"
  source_tree_manifest="$SOURCE_SNAPSHOT_WORK_DIR/source-tree.manifest"
  SOURCE_REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  assert_source_index_is_fully_observed
  git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all \
    --ignore-submodules=none >"$source_status"
  SOURCE_TRACKED_PATCH_SHA256="$(git -C "$REPO_ROOT" diff --binary --no-ext-diff HEAD | sha256sum)"
  SOURCE_TRACKED_PATCH_SHA256="${SOURCE_TRACKED_PATCH_SHA256%% *}"

  SOURCE_DIRTY=false
  if [[ -s "$source_status" ]]; then
    SOURCE_DIRTY=true
    mark_non_acceptance "dirty-source-tree"
  fi
  if [[ "$SOURCE_DIRTY" == false ]]; then
    SOURCE_TREE_MANIFEST_SCHEMA=git-tree-v2
    capture_clean_source_tree_manifest "$source_tree_manifest"
  else
    SOURCE_TREE_MANIFEST_SCHEMA=worktree-v1
    capture_dirty_source_tree_manifest "$source_tree_manifest"
  fi

  source_status_sha256="$(sha256_file "$source_status")" || {
    die "could not checksum the source-status evidence"
  }
  source_tree_manifest_sha256="$(sha256_file "$source_tree_manifest")" || {
    die "could not checksum the source-tree manifest"
  }
  SOURCE_TREE_SHA256="$source_tree_manifest_sha256"
  SOURCE_PATCH_SHA256="$({
    printf '%s\n' \
      "$source_status_sha256" \
      "$source_tree_manifest_sha256" \
      "$SOURCE_TRACKED_PATCH_SHA256"
  } | sha256sum)" || {
    die "could not checksum the source patch identity"
  }
  SOURCE_PATCH_SHA256="${SOURCE_PATCH_SHA256%% *}"
  [[ "$SOURCE_PATCH_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    die "source patch identity checksum is invalid"
  }
  assert_clean_source_checkout_is_stable

  install -m 0644 "$source_status" "$RESULT_DIR/git-status.txt" || {
    die "could not publish source status evidence"
  }
  install -m 0644 "$source_tree_manifest" "$RESULT_DIR/source-tree.manifest" || {
    die "could not publish source-tree evidence"
  }

  {
    printf 'revision=%s\n' "$SOURCE_REVISION"
    printf 'dirty=%s\n' "$SOURCE_DIRTY"
    printf 'source_tree_sha256=%s\n' "$SOURCE_TREE_SHA256"
    printf 'source_tree_manifest_schema=%s\n' "$SOURCE_TREE_MANIFEST_SCHEMA"
    printf 'tracked_patch_sha256=%s\n' "$SOURCE_TRACKED_PATCH_SHA256"
    printf 'patch_identity_sha256=%s\n' "$SOURCE_PATCH_SHA256"
  } >"$RESULT_DIR/source-state.txt"
}

materialize_source_tree_snapshot() {
  local -r repository="$1"
  local -r revision="$2"
  local -r destination="$3"
  local -r depth="$4"
  local entries=""
  local entry=""
  local metadata=""
  local mode=""
  local object_id=""
  local path=""
  local source_gitlink=""
  local snapshot_gitlink=""
  local snapshot_parent=""
  local destination_entry=""

  ((depth <= 16)) || die "source gitlink nesting exceeds the snapshot limit"
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || {
    die "source snapshot has an invalid Git revision"
  }
  [[ -d "$destination" && ! -L "$destination" ]] || {
    die "source snapshot destination is not a regular directory"
  }
  ensure_source_snapshot_work_directory
  destination_entry="$(find -- "$destination" -mindepth 1 -print -quit)" || {
    die "could not inspect the source snapshot destination"
  }
  [[ -z "$destination_entry" ]] || {
    die "source snapshot destination is not empty"
  }
  git -C "$repository" cat-file -e "${revision}^{commit}" || {
    die "source snapshot revision is unavailable"
  }
  if ! git -C "$repository" archive --format=tar "$revision" |
    (
      cd -- "$destination" || exit 1
      exec tar --extract --file=- --no-same-owner --same-permissions
    ); then
    die "could not materialize the pinned source Git tree"
  fi

  entries="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-snapshot-gitlinks-$depth.XXXXXX")" || {
    die "could not prepare source snapshot gitlink evidence"
  }
  git -C "$repository" ls-tree -r -z --full-tree "$revision" >"$entries" || {
    die "could not enumerate source snapshot gitlinks"
  }
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    is_safe_git_tree_path "$path" || {
      die "source snapshot Git tree has an unsafe path"
    }
    [[ "$mode" == 160000 ]] || continue
    source_gitlink="$repository/$path"
    snapshot_gitlink="$destination/$path"
    assert_source_gitlink_is_pinned "$source_gitlink" "$object_id"
    if [[ -e "$snapshot_gitlink" || -L "$snapshot_gitlink" ]]; then
      [[ -d "$snapshot_gitlink" && ! -L "$snapshot_gitlink" ]] || {
        die "source snapshot has a non-directory Gitlink placeholder"
      }
      rmdir -- "$snapshot_gitlink" || {
        die "source snapshot Gitlink placeholder is not empty"
      }
    fi
    snapshot_parent="${snapshot_gitlink%/*}"
    mkdir -p -- "$snapshot_parent"
    mkdir -- "$snapshot_gitlink"
    materialize_source_tree_snapshot \
      "$source_gitlink" "$object_id" "$snapshot_gitlink" "$((depth + 1))"
  done <"$entries"
  rm -f -- "$entries"
}

assert_materialized_source_tree_matches_revision() {
  local -r repository="$1"
  local -r revision="$2"
  local -r destination="$3"
  local -r depth="${4:-0}"
  local entries=""
  local entry=""
  local metadata=""
  local mode=""
  local object_id=""
  local path=""
  local snapshot_path=""
  local actual_object_id=""
  local expected_mode=""
  local actual_mode=""
  local expected_paths=""
  local expected_paths_sorted=""
  local snapshot_paths=""
  local snapshot_paths_filtered=""
  local snapshot_paths_sorted=""
  local actual_path=""
  local parent_path=""
  local gitlink_path=""
  local skip_gitlink_descendant=false
  local -a gitlink_paths=()

  ((depth <= 16)) || die "source gitlink nesting exceeds the snapshot limit"
  ensure_source_snapshot_work_directory
  entries="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-snapshot-tree-$depth.XXXXXX")" || {
    die "could not prepare source snapshot validation"
  }
  expected_paths="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-snapshot-expected-$depth.XXXXXX")" || {
    die "could not prepare expected source snapshot paths"
  }
  expected_paths_sorted="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-snapshot-expected-sorted-$depth.XXXXXX")" || {
    die "could not prepare sorted expected source snapshot paths"
  }
  snapshot_paths="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-snapshot-actual-$depth.XXXXXX")" || {
    die "could not prepare actual source snapshot paths"
  }
  snapshot_paths_filtered="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-snapshot-actual-filtered-$depth.XXXXXX")" || {
    die "could not prepare filtered source snapshot paths"
  }
  snapshot_paths_sorted="$(mktemp "$SOURCE_SNAPSHOT_WORK_DIR/.source-snapshot-actual-sorted-$depth.XXXXXX")" || {
    die "could not prepare sorted actual source snapshot paths"
  }
  git -C "$repository" ls-tree -r -z --full-tree "$revision" >"$entries" || {
    die "could not enumerate the pinned source Git tree"
  }
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    is_safe_git_tree_path "$path" || {
      die "source snapshot validation has an unsafe Git-tree path"
    }
    snapshot_path="$destination/$path"
    printf '%s\0' "$path" >>"$expected_paths"
    parent_path="$path"
    while [[ "$parent_path" == */* ]]; do
      parent_path="${parent_path%/*}"
      printf '%s\0' "$parent_path" >>"$expected_paths"
    done
    case "$mode" in
      100644|100755)
        [[ -f "$snapshot_path" && ! -L "$snapshot_path" ]] || {
          die "source snapshot lacks a regular Git-tree file"
        }
        if [[ "$mode" == 100755 ]]; then
          expected_mode=755
        else
          expected_mode=644
        fi
        chmod "$expected_mode" -- "$snapshot_path" || {
          die "could not normalize source snapshot file mode"
        }
        actual_object_id="$(git -C "$repository" hash-object --stdin <"$snapshot_path")" || {
          die "could not hash a source snapshot file"
        }
        actual_mode="$(stat --format=%a -- "$snapshot_path")" || {
          die "could not inspect a source snapshot file mode"
        }
        [[ "$actual_object_id" == "$object_id" && "$actual_mode" == "$expected_mode" ]] || {
          die "source snapshot does not match the pinned Git tree"
        }
        ;;
      120000)
        [[ -L "$snapshot_path" ]] || {
          die "source snapshot lacks a symbolic-link Git-tree entry"
        }
        actual_object_id="$(
          readlink -z -- "$snapshot_path" |
            head -c -1 |
            git -C "$repository" hash-object --stdin
        )" || {
          die "could not hash a source snapshot symbolic link"
        }
        [[ "$actual_object_id" == "$object_id" ]] || {
          die "source snapshot symbolic link does not match the pinned Git tree"
        }
        ;;
      160000)
        [[ -d "$snapshot_path" && ! -L "$snapshot_path" ]] || {
          die "source snapshot lacks a materialized Gitlink"
        }
        gitlink_paths+=("$path")
        assert_source_gitlink_is_pinned "$repository/$path" "$object_id"
        assert_materialized_source_tree_matches_revision \
          "$repository/$path" "$object_id" "$snapshot_path" "$((depth + 1))"
        ;;
      *)
        die "source snapshot has an unsupported Git-tree mode"
        ;;
    esac
  done <"$entries"
  LC_ALL=C sort -z -u "$expected_paths" >"$expected_paths_sorted" || {
    die "could not sort expected source snapshot paths"
  }
  find -- "$destination" -mindepth 1 -print0 >"$snapshot_paths" || {
    die "could not enumerate actual source snapshot paths"
  }
  while IFS= read -r -d '' actual_path; do
    actual_path="${actual_path#"$destination"/}"
    skip_gitlink_descendant=false
    for gitlink_path in "${gitlink_paths[@]}"; do
      if [[ "$actual_path" == "$gitlink_path/"* ]]; then
        skip_gitlink_descendant=true
        break
      fi
    done
    [[ "$skip_gitlink_descendant" == false ]] || continue
    printf '%s\0' "$actual_path"
  done <"$snapshot_paths" >"$snapshot_paths_filtered" || {
    die "could not filter actual source snapshot paths"
  }
  LC_ALL=C sort -z -u "$snapshot_paths_filtered" >"$snapshot_paths_sorted" || {
    die "could not sort actual source snapshot paths"
  }
  cmp -s "$expected_paths_sorted" "$snapshot_paths_sorted" || {
    die "source snapshot contains unexpected Git-tree entries"
  }
  rm -f -- \
    "$entries" \
    "$expected_paths" \
    "$expected_paths_sorted" \
    "$snapshot_paths" \
    "$snapshot_paths_filtered" \
    "$snapshot_paths_sorted"
}

prepare_source_snapshot() {
  local snapshot_compose_file=""
  local snapshot_fault_compose_file=""
  local snapshot_live_fd_compose_file=""
  local snapshot_unix_generation_fault_compose_file=""
  local snapshot_pid_reuse_compose_file=""
  local source_artifact_dir="$ARTIFACT_DIR"
  local artifact_file=""
  local -a reusable_bridge_artifact_files=(
    obi-java-agent.jar
    obi-otel-extension.jar
    bridge-artifacts.json
    bridge-artifacts.sha256
    bridge-metadata.sha256
    bridge-source-revision.txt
    bridge-source-tree.sha256
  )

  [[ "$SOURCE_DIRTY" == false ]] || return 0
  sanitize_git_environment
  assert_clean_source_checkout_is_stable
  ensure_source_snapshot_work_directory
  assert_source_snapshot_parent_is_trusted
  if [[ "$SKIP_BRIDGE_BUILD" == "true" ]]; then
    bridge_artifacts_are_valid || {
      die "--skip-bridge-build requires checksum-verified bridge artifacts built from the current source tree"
    }
  fi
  SOURCE_SNAPSHOT_DIR="$(mktemp -d "$SOURCE_SNAPSHOT_PARENT/obi-source-snapshot.XXXXXX")" || {
    die "could not create the private source snapshot"
  }
  assert_source_snapshot_root_is_private
  materialize_source_tree_snapshot \
    "$REPO_ROOT" "$SOURCE_REVISION" "$SOURCE_SNAPSHOT_DIR" 0
  find "$SOURCE_SNAPSHOT_DIR" -mindepth 1 -type d -exec chmod 0755 -- {} + || {
    die "could not normalize source snapshot directory modes"
  }
  assert_materialized_source_tree_matches_revision \
    "$REPO_ROOT" "$SOURCE_REVISION" "$SOURCE_SNAPSHOT_DIR"

  SOURCE_SNAPSHOT_SCRIPT_DIR="$SOURCE_SNAPSHOT_DIR/examples/apache-java-https"
  [[ -d "$SOURCE_SNAPSHOT_SCRIPT_DIR" && ! -L "$SOURCE_SNAPSHOT_SCRIPT_DIR" ]] || {
    die "source snapshot lacks the Apache Java HTTPS demo"
  }
  snapshot_compose_file="$SOURCE_SNAPSHOT_SCRIPT_DIR/docker-compose.yml"
  snapshot_fault_compose_file="$SOURCE_SNAPSHOT_SCRIPT_DIR/docker-compose.primary-fault.yml"
  snapshot_live_fd_compose_file="$SOURCE_SNAPSHOT_SCRIPT_DIR/docker-compose.primary-live-fd.yml"
  snapshot_unix_generation_fault_compose_file="$SOURCE_SNAPSHOT_SCRIPT_DIR/docker-compose.unix-generation-fault.yml"
  snapshot_pid_reuse_compose_file="$SOURCE_SNAPSHOT_SCRIPT_DIR/docker-compose.pid-reuse.yml"
  [[ -f "$snapshot_compose_file" && ! -L "$snapshot_compose_file" && \
    -f "$snapshot_fault_compose_file" && ! -L "$snapshot_fault_compose_file" && \
    -f "$snapshot_live_fd_compose_file" && ! -L "$snapshot_live_fd_compose_file" && \
    -f "$snapshot_unix_generation_fault_compose_file" && \
    ! -L "$snapshot_unix_generation_fault_compose_file" && \
    -f "$snapshot_pid_reuse_compose_file" && \
    ! -L "$snapshot_pid_reuse_compose_file" ]] || {
    die "source snapshot lacks the demo Compose configuration"
  }

  ARTIFACT_DIR="$SOURCE_SNAPSHOT_SCRIPT_DIR/.runtime/artifacts"
  CERT_DIR="$SOURCE_SNAPSHOT_SCRIPT_DIR/.runtime/certs"
  prepare_runtime_directory "$ARTIFACT_DIR"
  prepare_runtime_directory "$CERT_DIR"
  if [[ "$SKIP_BRIDGE_BUILD" == "true" ]]; then
    for artifact_file in "${reusable_bridge_artifact_files[@]}"; do
      install -m 0644 "$source_artifact_dir/$artifact_file" "$ARTIFACT_DIR/$artifact_file"
    done
  fi
  COMPOSE_FILE="$snapshot_compose_file"
  PRIMARY_FAULT_COMPOSE_FILE="$snapshot_fault_compose_file"
  PRIMARY_LIVE_FD_COMPOSE_FILE="$snapshot_live_fd_compose_file"
  UNIX_GENERATION_FAULT_COMPOSE_FILE="$snapshot_unix_generation_fault_compose_file"
  PID_REUSE_COMPOSE_FILE="$snapshot_pid_reuse_compose_file"
  COMPOSE_PROJECT_DIRECTORY="$SOURCE_SNAPSHOT_SCRIPT_DIR"
  COMPOSE=(
    docker compose --project-name "$PROJECT_NAME" \
      --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE"
  )
  PRIMARY_FAULT_COMPOSE=(
    docker compose --project-name "$PROJECT_NAME" \
      --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
      --file "$PRIMARY_FAULT_COMPOSE_FILE"
  )
  PRIMARY_LIVE_FD_COMPOSE=(
    docker compose --project-name "$PROJECT_NAME" \
      --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
      --file "$PRIMARY_FAULT_COMPOSE_FILE" --file "$PRIMARY_LIVE_FD_COMPOSE_FILE"
  )
  UNIX_GENERATION_FAULT_COMPOSE=(
    docker compose --project-name "$PROJECT_NAME" \
      --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
      --file "$PRIMARY_FAULT_COMPOSE_FILE" --file "$UNIX_GENERATION_FAULT_COMPOSE_FILE"
  )
  PID_REUSE_COMPOSE=(
    docker compose --project-name "$PROJECT_NAME" \
      --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
      --file "$PID_REUSE_COMPOSE_FILE"
  )
  assert_clean_source_checkout_is_stable
}

seal_source_snapshot() {
  [[ -n "$SOURCE_SNAPSHOT_DIR" ]] || return 0
  [[ "$SOURCE_SNAPSHOT_DIR" == "$SOURCE_SNAPSHOT_PARENT"/obi-source-snapshot.* && \
    -d "$SOURCE_SNAPSHOT_DIR" && ! -L "$SOURCE_SNAPSHOT_DIR" ]] || {
    die "source snapshot path is unsafe"
  }
  assert_source_snapshot_root_is_private
  find "$SOURCE_SNAPSHOT_DIR" -type f -exec chmod a-w -- {} + || {
    die "could not seal source snapshot files"
  }
  find "$SOURCE_SNAPSHOT_DIR" -type d -exec chmod a-w -- {} + || {
    die "could not seal source snapshot directories"
  }
  assert_sealed_source_snapshot_is_private
}

unseal_source_snapshot() {
  [[ -n "${SOURCE_SNAPSHOT_DIR:-}" ]] || return 0
  [[ "$SOURCE_SNAPSHOT_DIR" == "$SOURCE_SNAPSHOT_PARENT"/obi-source-snapshot.* && \
    -d "$SOURCE_SNAPSHOT_DIR" && ! -L "$SOURCE_SNAPSHOT_DIR" ]] || return 1
  find "$SOURCE_SNAPSHOT_DIR" -type d -exec chmod u+rwx -- {} +
}

prepare_certificates() {
  local certificate_generator="$SCRIPT_DIR/certs/generate.sh"

  if [[ -n "$SOURCE_SNAPSHOT_SCRIPT_DIR" ]]; then
    assert_source_snapshot_root_is_private
    certificate_generator="$SOURCE_SNAPSHOT_SCRIPT_DIR/certs/generate.sh"
  fi
  log_info "preparing runtime test CA"
  "$certificate_generator" --output "$CERT_DIR"
}

prepare_official_agent() {
  local agent_downloader="$SCRIPT_DIR/scripts/download-agent.sh"

  if [[ -n "$SOURCE_SNAPSHOT_SCRIPT_DIR" ]]; then
    assert_source_snapshot_root_is_private
    agent_downloader="$SOURCE_SNAPSHOT_SCRIPT_DIR/scripts/download-agent.sh"
  fi
  log_info "preparing official $AGENT_DISTRIBUTION Java agent"
  "$agent_downloader" \
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
  [[ "$(sha256_file "$ARTIFACT_DIR/obi-java-agent.jar")" == "$actual_helper_sha" ]] || return 1
  [[ "$(sha256_file "$ARTIFACT_DIR/obi-otel-extension.jar")" == "$actual_extension_sha" ]] || return 1

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

  helper_sha="$(sha256_file "$ARTIFACT_DIR/obi-java-agent.jar")" || return 1
  extension_sha="$(sha256_file "$ARTIFACT_DIR/obi-otel-extension.jar")" || return 1
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
  local build_context="$REPO_ROOT"
  local dockerfile="$REPO_ROOT/javaagent.Dockerfile"

  assert_clean_source_checkout_is_stable
  if [[ -n "$SOURCE_SNAPSHOT_DIR" ]]; then
    assert_source_snapshot_root_is_private
    build_context="$SOURCE_SNAPSHOT_DIR"
    dockerfile="$SOURCE_SNAPSHOT_DIR/javaagent.Dockerfile"
  fi
  [[ -f "$dockerfile" && ! -L "$dockerfile" && \
    -d "$build_context" && ! -L "$build_context" ]] || {
    die "pinned source snapshot lacks the Java bridge build inputs"
  }
  if [[ "$SKIP_BRIDGE_BUILD" == "true" ]]; then
    bridge_artifacts_are_valid || {
      die "--skip-bridge-build requires checksum-verified bridge artifacts built from the current source tree"
    }
    BRIDGE_BUILD_MODE="reused-local-cache"
    mark_non_acceptance "reused-bridge-artifacts"
    log_info "reusing checksum-verified bridge artifacts for source tree $SOURCE_TREE_SHA256"
    return 0
  fi

  ensure_source_snapshot_work_directory
  BRIDGE_EXPORT_DIR="$(mktemp -d "$SOURCE_SNAPSHOT_WORK_DIR/bridge-export.XXXXXX")" || {
    die "could not create the private bridge export directory"
  }
  assert_bridge_export_directory_is_private
  export_dir="$BRIDGE_EXPORT_DIR/export"
  mkdir -p -- "$export_dir"
  log_info "building OBI Java helper and external extension"
  RUN_STAGE="bridge-build"
  if [[ -n "$SOURCE_SNAPSHOT_DIR" ]]; then
    assert_source_snapshot_root_is_private
  fi
  assert_bridge_export_directory_is_private
  run_logged_bounded "$RESULT_DIR/bridge-build.log" "$COMMAND_TIMEOUT_SECONDS" \
    docker build \
      --file "$dockerfile" \
      --target export \
      --output "type=local,dest=$export_dir" \
      "$build_context" || return

  assert_clean_source_checkout_is_stable
  assert_bridge_export_directory_is_private
  [[ -s "$export_dir/obi-java-agent.jar" ]] || die "Java build did not export obi-java-agent.jar"
  [[ -s "$export_dir/obi-otel-extension.jar" ]] || die "Java build did not export obi-otel-extension.jar"
  install -m 0644 "$export_dir/obi-java-agent.jar" "$BRIDGE_EXPORT_DIR/obi-java-agent.jar.ready"
  install -m 0644 "$export_dir/obi-otel-extension.jar" "$BRIDGE_EXPORT_DIR/obi-otel-extension.jar.ready"
  mv -fT -- "$BRIDGE_EXPORT_DIR/obi-java-agent.jar.ready" "$ARTIFACT_DIR/obi-java-agent.jar"
  mv -fT -- "$BRIDGE_EXPORT_DIR/obi-otel-extension.jar.ready" "$ARTIFACT_DIR/obi-otel-extension.jar"
  write_bridge_metadata

  rm -rf -- "$BRIDGE_EXPORT_DIR"
  BRIDGE_EXPORT_DIR=""
}

configure_security_probe_timeouts() {
  local -i repeat_seconds=$((
    REPEAT_COUNT * SECURITY_PROBE_SCENARIO_BUDGET_SECONDS
  ))
  # Three readiness windows belong to the primary probe controls and three to
  # the live-descriptor stack's preparation and two possible recovery checks.
  local -i maximum_readiness=$((
    (MAX_SECURITY_PROBE_TIMEOUT_SECONDS - repeat_seconds -
      SECURITY_PROBE_SAME_CGROUP_FIXED_BUDGET_SECONDS -
      SECURITY_PROBE_SIBLING_FIXED_BUDGET_SECONDS - PRIMARY_LIVE_FD_FIXED_BUDGET_SECONDS -
      SECURITY_PROBE_TIMEOUT_SLACK_SECONDS) / 6
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

uses_uninstrumented_runtime() {
  [[ "$SCENARIO" == "uninstrumented" || \
    "$SCENARIO" == "benchmark-uninstrumented" ]]
}

export_compose_environment() {
  if [[ -n "$SOURCE_SNAPSHOT_DIR" ]]; then
    assert_sealed_source_snapshot_is_private
  fi
  SECURITY_PROBE_TIMEOUT="60s"
  PRIMARY_SECURITY_SAME_CGROUP_TIMEOUT="60s"
  if [[ "$SCENARIO" == "all" || "$SCENARIO" == "security" ]]; then
    configure_security_probe_timeouts
  else
    export SECURITY_PROBE_TIMEOUT
  fi
  export BRIDGE_TRANSPORT="$TRANSPORT"
  export OBI_LOG_LEVEL
  export REMOTE_PARENT_TTL
  export REMOTE_PARENT_RETRIEVAL_TTL
  export BACKEND_TLS_PROTOCOL="$TLS_PROTOCOL"
  CONTEXT_PROPAGATION="tcp"
  export CONTEXT_PROPAGATION
  if uses_uninstrumented_runtime; then
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
  export OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE=false
  if [[ "$SCENARIO" == "delayed-otlp-suppression" ]]; then
    export OTEL_BSP_SCHEDULE_DELAY_VALUE="$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS"
    export OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE="$DELAYED_OTLP_JAVA_RETRY_DISABLED"
  fi
  if [[ "$SCENARIO" == "pid-reuse" ]]; then
    COMPOSE=("${PID_REUSE_COMPOSE[@]}")
  fi
}

pid_reuse_compose_model_has_contract() {
  local -r input="$1"

  jq -e -s '
    length == 1 and
    (.[0] | type == "object") and
    (.[0].services["socket-init"] as $init |
      ($init.user == "0:0") and
      ($init.network_mode == "none") and
      (($init.privileged // false) == false) and
      ($init.read_only == true) and
      (($init.cap_drop | map(sub("^CAP_"; "")) | sort) == ["ALL"]) and
      (($init.cap_add | map(sub("^CAP_"; "")) | sort) ==
        ["CHOWN", "DAC_READ_SEARCH"]) and
      (($init.security_opt | sort) == ["no-new-privileges:true"]) and
      ($init.entrypoint == ["/bin/sh", "-ec"]) and
      (($init.command | length) == 1) and
      (($init.command[0] | split("\n")) == [
        "umask 077",
        "chown 0:65534 /var/run/obi",
        "chmod 0750 /var/run/obi",
        "test -f /run/obi-demo/pid-reuse-keystore-source/server.p12",
        "test ! -L /run/obi-demo/pid-reuse-keystore-source/server.p12",
        "test -s /run/obi-demo/pid-reuse-keystore-source/server.p12",
        "stat -c \u0027%a:%h:%F\u0027 /run/obi-demo/pid-reuse-keystore-source/server.p12 | grep -Ex \u0027(400|600):1:regular file\u0027 >/dev/null",
        "chown 0:0 /run/obi-demo/pid-reuse-keystore",
        "chmod 0700 /run/obi-demo/pid-reuse-keystore",
        "test ! -e /run/obi-demo/pid-reuse-keystore/server.p12",
        "test ! -L /run/obi-demo/pid-reuse-keystore/server.p12",
        "set -C",
        "cat /run/obi-demo/pid-reuse-keystore-source/server.p12 > /run/obi-demo/pid-reuse-keystore/server.p12",
        "chmod 0600 /run/obi-demo/pid-reuse-keystore/server.p12",
        "stat -c \u0027%u:%g:%a:%h:%F\u0027 /run/obi-demo/pid-reuse-keystore/server.p12 | grep -Fx \u00270:0:600:1:regular file\u0027 >/dev/null",
        "test -s /run/obi-demo/pid-reuse-keystore/server.p12",
        "cmp -s /run/obi-demo/pid-reuse-keystore-source/server.p12 /run/obi-demo/pid-reuse-keystore/server.p12",
        ""
      ]) and
      (($init.volumes | length) == 3) and
      ([$init.volumes[] |
        select(.type == "volume" and
          .source == "java-remote-parent-socket" and
          .target == "/var/run/obi" and
          ((.read_only // false) == false))] | length == 1) and
      ([$init.volumes[] |
        select(.type == "bind" and
          (.source | endswith("/.runtime/certs/server.p12")) and
          .target == "/run/obi-demo/pid-reuse-keystore-source/server.p12" and
          .read_only == true and
          .bind.create_host_path == false)] | length == 1) and
      ([$init.volumes[] |
        select(.type == "volume" and
          .source == "pid-reuse-keystore" and
          .target == "/run/obi-demo/pid-reuse-keystore" and
          ((.read_only // false) == false))] | length == 1)) and
    (.[0].services["java-backend"] as $java |
      ($java.user == "0:0") and
      (($java.privileged // false) == false) and
      (($java.pid // "") == "") and
      (($java.cap_drop | map(sub("^CAP_"; "")) | sort) == ["ALL"]) and
      (($java.cap_add | map(sub("^CAP_"; "")) | sort) ==
        ["CHECKPOINT_RESTORE", "SETPCAP"]) and
      (($java.security_opt | sort) ==
        ["apparmor=unconfined", "no-new-privileges:true", "systempaths=unconfined"]) and
      ($java.entrypoint == [
        "/otel/pid-reuse-supervisor",
        "--control-dir", "/run/obi-demo/pid-reuse",
        "--target-pid", "4242",
        "--socket-fd", "198",
        "--", "java", "-jar", "/app/backend.jar"
      ]) and
      ($java.environment.TLS_KEYSTORE_PATH ==
        "/run/obi-demo/pid-reuse-keystore/server.p12") and
      (($java.volumes | length) == 4) and
      ([$java.volumes[] |
        select(.type == "bind" and
          (.source | endswith("/.runtime/certs/server.p12")) and
          .target == "/run/obi-demo/certs/server.p12" and
          .read_only == true)] | length == 1) and
      ([$java.volumes[] |
        select(.type == "volume" and
          .source == "java-remote-parent-socket" and
          .target == "/var/run/obi" and
          ((.read_only // false) == false))] | length == 1) and
      ([$java.volumes[] |
        select(.type == "volume" and
          .source == "pid-reuse-control" and
          .target == "/run/obi-demo/pid-reuse" and
          ((.read_only // false) == false))] | length == 1) and
      ([$java.volumes[] |
        select(.type == "volume" and
          .source == "pid-reuse-keystore" and
          .target == "/run/obi-demo/pid-reuse-keystore" and
          .read_only == true)] | length == 1)) and
    (.[0].services["pid-reuse"] as $controller |
      ($controller.user == "0:0") and
      ($controller.network_mode == "none") and
      ($controller.privileged == true) and
      ($controller.read_only == true) and
      ($controller.entrypoint == ["/pid-reuse"]) and
      ($controller.profiles == ["tools"]) and
      (($controller.cap_add // []) == []) and
      (($controller.cap_drop // []) == []) and
      (($controller.volumes | length) == 1) and
      ($controller.volumes[0].type == "volume") and
      ($controller.volumes[0].source == "pid-reuse-control") and
      ($controller.volumes[0].target == "/control") and
      (($controller.volumes[0].read_only // false) == false)) and
    ((.[0].volumes | keys | sort) ==
      ["java-remote-parent-socket", "pid-reuse-control", "pid-reuse-keystore"]) and
    (.[0].volumes["pid-reuse-control"] | type == "object") and
    (.[0].volumes["pid-reuse-keystore"] as $keystore |
      ($keystore | type == "object") and
      ($keystore.labels["io.opentelemetry.obi.apache-java-https.owner"] ==
        "acceptance-demo-v1"))
  ' "$input" >/dev/null
}

assert_pid_reuse_compose_contract() {
  local -r output="$RESULT_DIR/compose-pid-reuse.json"

  run_bounded 30 "${COMPOSE[@]}" --profile tools \
    config --format json >"$output" || return $?
  bounded_evidence_file "$output" 1048576 20000 || {
    log_error "PID reuse resolved Compose model exceeded its evidence bounds"
    return 1
  }
  pid_reuse_compose_model_has_contract "$output" || {
    log_error "PID reuse resolved Compose model violates its exact topology contract"
    return 1
  }
}

pid_reuse_result_has_contract() {
  local -r input="$1"
  local -r transport="$2"

  [[ "$transport" == "getsockopt" || "$transport" == "unix" ]] || return 1
  bounded_evidence_file \
    "$input" "$PID_REUSE_RESULT_MAX_BYTES" "$PID_REUSE_RESULT_MAX_LINES" || return 1
  jq -e -s --arg transport "$transport" '
    length == 1 and
    (.[0] |
      type == "object" and
      ((keys | sort) == ([
        "a_reaped_before_b",
        "authorization_maps_agree",
        "different_lifetime",
        "injected_residue_preserved",
        "injected_residue_rejected",
        "jvm_a_privileges_dropped",
        "jvm_b_privileges_dropped",
        "negative_status",
        "normal_cleanup",
        "obi_capabilities_distinct",
        "obi_capabilities_nonzero",
        "private_artifacts_removed",
        "private_pid_namespace",
        "recovery_parent_exact",
        "recovery_status",
        "residue",
        "same_namespace_inode",
        "same_numeric_pid",
        "same_numeric_tid",
        "same_primary_socket",
        "schema",
        "status",
        "transport",
        "w3c_fail_open"
      ] | sort)) and
      .schema == "obi-pid-reuse-public-v1" and
      .status == "passed" and
      .transport == $transport and
      .private_pid_namespace == true and
      .same_namespace_inode == true and
      .same_numeric_pid == true and
      .same_numeric_tid == true and
      .a_reaped_before_b == true and
      .different_lifetime == true and
      .obi_capabilities_nonzero == true and
      .obi_capabilities_distinct == true and
      .authorization_maps_agree == true and
      .jvm_a_privileges_dropped == true and
      .jvm_b_privileges_dropped == true and
      .normal_cleanup == "completed" and
      .residue == "injected_after_a_reap" and
      .same_primary_socket == true and
      .negative_status == (if $transport == "getsockopt" then "unsupported" else "ambiguous" end) and
      .injected_residue_rejected == true and
      .injected_residue_preserved == true and
      .w3c_fail_open == true and
      .recovery_status == "valid" and
      .recovery_parent_exact == true and
      .private_artifacts_removed == true)
  ' "$input" >/dev/null
}

pid_reuse_java_sandbox_has_contract() {
  local -r apparmor_profile="$1"
  local -r security_options="$2"
  local -r masked_paths="$3"
  local -r readonly_paths="$4"

  [[ -z "$apparmor_profile" || "$apparmor_profile" == "unconfined" ]] || return 1
  jq -e '
    type == "array" and
    (length == (unique | length)) and
    ([.[] | select(. == "no-new-privileges:true")] | length == 1) and
    all(.[];
      . == "no-new-privileges:true" or
      . == "systempaths=unconfined" or
      . == "apparmor=unconfined")
  ' <<<"$security_options" >/dev/null || return 1
  jq -e 'type == "array" and length == 0' <<<"$masked_paths" >/dev/null || return 1
  jq -e 'type == "array" and length == 0' <<<"$readonly_paths" >/dev/null
}

run_pid_reuse_controller() {
  local -r output="$RESULT_DIR/pid-reuse-controller.json"
  local -r stderr_output="$RESULT_DIR/pid-reuse-controller.stderr.log"
  local command_status=0

  log_info "running real numeric PID/TID reuse control for forced $TRANSPORT transport"
  run_bounded "$PID_REUSE_CONTROLLER_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" run --rm --no-deps --no-TTY pid-reuse \
      --control-dir /control \
      --transport "$TRANSPORT" \
      --timeout "$PID_REUSE_CONTROLLER_INNER_TIMEOUT" \
      >"$output" 2>"$stderr_output" || command_status=$?
  bounded_evidence_file \
    "$output" "$PID_REUSE_RESULT_MAX_BYTES" "$PID_REUSE_RESULT_MAX_LINES" || {
    log_error "PID reuse controller stdout violated its evidence bounds"
    return 1
  }
  bounded_evidence_file \
    "$stderr_output" "$PID_REUSE_STDERR_MAX_BYTES" "$PID_REUSE_STDERR_MAX_LINES" || {
    log_error "PID reuse controller stderr violated its evidence bounds"
    return 1
  }
  if [[ -s "$stderr_output" ]]; then
    sed -n 'p' "$stderr_output" >&2 || return $?
    log_error "PID reuse controller produced unexpected stderr"
    return 1
  fi
  ((command_status == 0)) || return "$command_status"
  pid_reuse_result_has_contract "$output" "$TRANSPORT" || {
    log_error "PID reuse controller result violates the closed public schema"
    return 1
  }
}

pid_reuse_supervisor_pid_namespace_depth_from_snapshot() {
  local -r status_snapshot="$1"
  local -r raw_host_pid="$2"
  local host_pid=""

  host_pid="$(
    bounded_decimal "$raw_host_pid" "$MAX_UINT32_DECIMAL" false
  )" || return $?
  [[ "$host_pid" == "$raw_host_pid" ]] || return 1
  LC_ALL=C awk \
    -v expected_host_pid="$host_pid" \
    -v maximum_pid="$MAX_UINT32_DECIMAL" '
    function valid_pid(value) {
      return value ~ /^[1-9][0-9]*$/ &&
        (length(value) < length(maximum_pid) ||
          (length(value) == length(maximum_pid) &&
            ("p" value) <= ("p" maximum_pid)))
    }
    function same_pid(left, right) {
      return ("p" left) == ("p" right)
    }
    $1 == "Pid:" {
      pid_count++
      if (NF != 2 || !valid_pid($2) ||
        !same_pid($2, expected_host_pid)) {
        invalid = 1
      }
      next
    }
    $1 == "Tgid:" {
      tgid_count++
      if (NF != 2 || !valid_pid($2) ||
        !same_pid($2, expected_host_pid)) {
        invalid = 1
      }
      next
    }
    $1 == "NSpid:" {
      nspid_count++
      nspid_depth = NF - 1
      if (NF < 3 || !same_pid($2, expected_host_pid) ||
        !same_pid($NF, "1")) {
        invalid = 1
      }
      for (field = 2; field <= NF; field++) {
        if (!valid_pid($field)) {
          invalid = 1
        }
        nspid[field - 1] = $field
      }
      next
    }
    $1 == "NStgid:" {
      nstgid_count++
      nstgid_depth = NF - 1
      if (NF < 3 || !same_pid($2, expected_host_pid) ||
        !same_pid($NF, "1")) {
        invalid = 1
      }
      for (field = 2; field <= NF; field++) {
        if (!valid_pid($field)) {
          invalid = 1
        }
        nstgid[field - 1] = $field
      }
      next
    }
    END {
      if (invalid || pid_count != 1 || tgid_count != 1 ||
        nspid_count != 1 || nstgid_count != 1 || nspid_depth < 2 ||
        nstgid_depth != nspid_depth) {
        exit 1
      }
      for (field = 1; field <= nspid_depth; field++) {
        if (!same_pid(nspid[field], nstgid[field])) {
          exit 1
        }
      }
      print nspid_depth
    }
  ' <<<"$status_snapshot"
}

pid_reuse_running_container_state_identity_from_snapshot() {
  local -r state_snapshot="$1"

  jq -er '
    if type == "object" and
      .Status == "running" and
      .Running == true and
      .Paused == false and
      .Restarting == false and
      .Dead == false and
      (.Pid |
        type == "number" and . == floor and . >= 1 and . <= 4294967295) and
      (.StartedAt |
        type == "string" and length > 0 and
        . != "0001-01-01T00:00:00Z")
    then
      "\(.Pid)\t\(.StartedAt)"
    else
      empty
    end
  ' <<<"$state_snapshot"
}

pid_reuse_supervisor_namespace_attestation_from_snapshots() {
  local -r runtime_state_before="$1"
  local -r status_snapshot="$2"
  local -r runtime_state_after="$3"
  local runtime_identity_before=""
  local runtime_identity_after=""
  local host_pid=""
  local pid_namespace_depth=""

  runtime_identity_before="$(
    pid_reuse_running_container_state_identity_from_snapshot \
      "$runtime_state_before"
  )" || return 10
  runtime_identity_after="$(
    pid_reuse_running_container_state_identity_from_snapshot \
      "$runtime_state_after"
  )" || return 11
  [[ "$runtime_identity_after" == "$runtime_identity_before" ]] || return 12
  host_pid="${runtime_identity_before%%$'\t'*}"
  pid_namespace_depth="$(
    pid_reuse_supervisor_pid_namespace_depth_from_snapshot \
      "$status_snapshot" "$host_pid"
  )" || return 13
  printf '%s\t%s\n' "$host_pid" "$pid_namespace_depth"
}

pid_reuse_runtime_keystore_has_contract() {
  local -r input="$1"

  jq -e '
    length == 2 and
    (.[0] as $init | .[1] as $java |
      ($init.State.Status == "exited") and
      ($init.State.Running == false) and
      ($init.State.Paused == false) and
      ($init.State.Restarting == false) and
      ($init.State.OOMKilled == false) and
      ($init.State.Dead == false) and
      ($init.State.ExitCode == 0) and
      ($init.State.Error == "") and
      ($init.Config.User == "0:0") and
      ($init.HostConfig.NetworkMode == "none") and
      ($init.HostConfig.Privileged == false) and
      ($init.HostConfig.ReadonlyRootfs == true) and
      (($init.HostConfig.CapDrop | map(sub("^CAP_"; "")) | sort) == ["ALL"]) and
      (($init.HostConfig.CapAdd | map(sub("^CAP_"; "")) | sort) ==
        ["CHOWN", "DAC_READ_SEARCH"]) and
      (($init.HostConfig.SecurityOpt | sort) == ["no-new-privileges:true"]) and
      (($init.Mounts | length) == 3) and
      ([$init.Mounts[] |
        select(.Type == "volume" and
          .Destination == "/var/run/obi" and
          .RW == true)] | length == 1) and
      ([$init.Mounts[] |
        select(.Type == "bind" and
          (.Source | endswith("/.runtime/certs/server.p12")) and
          .Destination == "/run/obi-demo/pid-reuse-keystore-source/server.p12" and
          .RW == false)] | length == 1) and
      ([$init.Mounts[] |
        select(.Type == "volume" and
          .Destination == "/run/obi-demo/pid-reuse-keystore" and
          .RW == true)] as $init_keystore |
        ($init_keystore | length) == 1 and
        ($init_keystore[0].Name | type == "string" and length > 0) and
        (($java.Mounts | length) == 4) and
        ([$java.Mounts[] |
          select(.Type == "bind" and
            (.Source | endswith("/.runtime/certs/server.p12")) and
            .Destination == "/run/obi-demo/certs/server.p12" and
            .RW == false)] | length == 1) and
        ([$java.Mounts[] |
          select(.Type == "volume" and
            .Destination == "/var/run/obi" and
            .RW == true)] | length == 1) and
        ([$java.Mounts[] |
          select(.Type == "volume" and
            .Destination == "/run/obi-demo/pid-reuse" and
            .RW == true)] | length == 1) and
        ([ $java.Config.Env[] |
          select(startswith("TLS_KEYSTORE_PATH=")) ] ==
          ["TLS_KEYSTORE_PATH=/run/obi-demo/pid-reuse-keystore/server.p12"]) and
        ([$java.Mounts[] |
          select(.Type == "volume" and
            .Destination == "/run/obi-demo/pid-reuse-keystore" and
            .RW == false)] as $java_keystore |
          ($java_keystore | length) == 1 and
          $java_keystore[0].Name == $init_keystore[0].Name)))
  ' "$input" >/dev/null
}

assert_pid_reuse_runtime_contract() {
  local java_container=""
  local socket_init_container=""
  local runtime_keystore_evidence="$RESULT_DIR/pid-reuse-keystore-runtime.json"
  local privileged=""
  local pid_mode=""
  local user=""
  local cap_drop=""
  local cap_add=""
  local apparmor_profile=""
  local security_options=""
  local masked_paths=""
  local readonly_paths=""
  local entrypoint=""
  local mounts=""
  local runtime_state_before=""
  local runtime_state_after=""
  local runtime_identity_before=""
  local namespace_attestation=""
  local namespace_attestation_status=0
  local host_pid=""
  local status_snapshot=""
  local pid_namespace_depth=""

  socket_init_container="$(run_bounded 10 \
    "${COMPOSE[@]}" ps --all --quiet socket-init)" || return $?
  java_container="$(run_bounded 10 \
    "${COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$socket_init_container" && -n "$java_container" ]] || {
    log_error "PID reuse keystore initializer or Java supervisor is absent before the controller"
    return 1
  }
  run_bounded 10 docker inspect \
    "$socket_init_container" "$java_container" >"$runtime_keystore_evidence" || return $?
  bounded_evidence_file "$runtime_keystore_evidence" 1048576 20000 || {
    log_error "PID reuse runtime keystore evidence exceeded its bounds"
    return 1
  }
  pid_reuse_runtime_keystore_has_contract "$runtime_keystore_evidence" || {
    log_error "PID reuse runtime did not realize the private one-run keystore contract"
    return 1
  }
  privileged="$(run_bounded 10 docker inspect \
    --format '{{.HostConfig.Privileged}}' "$java_container")" || return $?
  pid_mode="$(run_bounded 10 docker inspect \
    --format '{{.HostConfig.PidMode}}' "$java_container")" || return $?
  user="$(run_bounded 10 docker inspect \
    --format '{{.Config.User}}' "$java_container")" || return $?
  cap_drop="$(run_bounded 10 docker inspect \
    --format '{{json .HostConfig.CapDrop}}' "$java_container")" || return $?
  cap_add="$(run_bounded 10 docker inspect \
    --format '{{json .HostConfig.CapAdd}}' "$java_container")" || return $?
  apparmor_profile="$(run_bounded 10 docker inspect \
    --format '{{.AppArmorProfile}}' "$java_container")" || return $?
  security_options="$(run_bounded 10 docker inspect \
    --format '{{json .HostConfig.SecurityOpt}}' "$java_container")" || return $?
  masked_paths="$(run_bounded 10 docker inspect \
    --format '{{json .HostConfig.MaskedPaths}}' "$java_container")" || return $?
  readonly_paths="$(run_bounded 10 docker inspect \
    --format '{{json .HostConfig.ReadonlyPaths}}' "$java_container")" || return $?
  entrypoint="$(run_bounded 10 docker inspect \
    --format '{{json .Config.Entrypoint}}' "$java_container")" || return $?
  mounts="$(run_bounded 10 docker inspect \
    --format '{{json .Mounts}}' "$java_container")" || return $?

  [[ "$privileged" == "false" && -z "$pid_mode" && "$user" == "0:0" && \
    -n "$java_container" ]] || {
    log_error "PID reuse Java runtime lost its unprivileged private-PID topology"
    return 1
  }
  jq -e 'map(sub("^CAP_"; "")) | sort == ["ALL"]' \
    <<<"$cap_drop" >/dev/null || return 1
  jq -e 'map(sub("^CAP_"; "")) | sort == ["CHECKPOINT_RESTORE", "SETPCAP"]' \
    <<<"$cap_add" >/dev/null || return 1
  pid_reuse_java_sandbox_has_contract \
    "$apparmor_profile" "$security_options" "$masked_paths" "$readonly_paths" || {
    log_error "PID reuse Java runtime cannot access namespace-local ns_last_pid safely"
    return 1
  }
  jq -e '. == [
    "/otel/pid-reuse-supervisor",
    "--control-dir", "/run/obi-demo/pid-reuse",
    "--target-pid", "4242",
    "--socket-fd", "198",
    "--", "java", "-jar", "/app/backend.jar"
  ]' <<<"$entrypoint" >/dev/null || return 1
  jq -e '
    [.[] | select(.Type == "volume" and
      .Destination == "/run/obi-demo/pid-reuse" and .RW == true)] | length == 1
  ' <<<"$mounts" >/dev/null || return 1
  # NSpid is ordered from the namespace that mounted this host procfs into
  # successively nested namespaces. A matching first value, at least one inner
  # value, and a final value of 1 prove the live supervisor topology without a
  # ptrace-gated /proc/<pid>/ns/pid dereference.
  if ! runtime_state_before="$(run_bounded 10 docker inspect \
    --format '{{json .State}}' "$java_container")"; then
    log_error "could not inspect PID reuse Java supervisor state before namespace attestation"
    return 1
  fi
  runtime_identity_before="$(
    pid_reuse_running_container_state_identity_from_snapshot \
      "$runtime_state_before"
  )" || {
    log_error "PID reuse Java supervisor was not running, unpaused, unrestarting, and live before namespace attestation"
    return 1
  }
  host_pid="${runtime_identity_before%%$'\t'*}"
  status_snapshot="$(<"/proc/$host_pid/status")" || {
    log_error "could not read host proc status for PID reuse Java supervisor (host PID $host_pid)"
    return 1
  }
  if ! runtime_state_after="$(run_bounded 10 docker inspect \
    --format '{{json .State}}' "$java_container")"; then
    log_error "could not inspect PID reuse Java supervisor state after namespace attestation"
    return 1
  fi
  namespace_attestation="$(
    pid_reuse_supervisor_namespace_attestation_from_snapshots \
      "$runtime_state_before" "$status_snapshot" "$runtime_state_after"
  )" || namespace_attestation_status=$?
  case "$namespace_attestation_status" in
    0)
      ;;
    10)
      log_error "PID reuse Java supervisor state became invalid before namespace attestation"
      return 1
      ;;
    11)
      log_error "PID reuse Java supervisor was not running, unpaused, unrestarting, and live after namespace attestation"
      return 1
      ;;
    12)
      log_error "PID reuse Java supervisor changed Docker PID or start identity during namespace attestation"
      return 1
      ;;
    13)
      log_error "PID reuse supervisor status did not contain singular matching Pid/Tgid and identical multi-level NSpid/NStgid records ending in PID 1"
      return 1
      ;;
    *)
      log_error "PID reuse supervisor namespace attestation failed unexpectedly (status $namespace_attestation_status)"
      return 1
      ;;
  esac
  host_pid="${namespace_attestation%%$'\t'*}"
  pid_namespace_depth="${namespace_attestation#*$'\t'}"
  log_info "PID reuse supervisor namespace attestation: Docker host PID $host_pid maps through $pid_namespace_depth PID namespaces to inner PID 1"
}

start_stack() {
  local start_status=0
  local controller_status=0
  local startup_since=""
  local runtime_contract_mode="$SCENARIO"
  local -a recreate_arguments=()

  assert_project_docker_identity_unchanged || return $?
  assert_clean_source_checkout_is_stable
  assert_no_pending_permanent_absence_recovery || return $?
  # These controls replace the normal Java runtime only after startup.
  case "$runtime_contract_mode" in
    primary-w3c-fault|primary-generation-mismatch|unix-generation-mismatch|pid-reuse|permanent-absence|auto-unavailable)
      runtime_contract_mode="basic"
      ;;
    benchmark-disabled)
      runtime_contract_mode="disabled"
      ;;
    benchmark-uninstrumented)
      runtime_contract_mode="uninstrumented"
      ;;
  esac

  RUN_STAGE="compose-ownership"
  verify_compose_project_ownership || {
    die "reserved Compose project ownership could not be verified"
  }
  if [[ "$SCENARIO" == "pid-reuse" ]]; then
    verify_compose_project_absent || {
      log_error "PID reuse requires a fresh Compose project; run --cleanup-only first"
      return 1
    }
  fi
  log_info "validating resolved Compose configuration"
  RUN_STAGE="compose-configuration"
  if [[ -n "$SOURCE_SNAPSHOT_DIR" ]]; then
    assert_sealed_source_snapshot_is_private
  fi
  run_bounded 30 "${COMPOSE[@]}" config --quiet || return $?
  run_bounded 30 \
    "${COMPOSE[@]}" config >"$RESULT_DIR/compose-resolved.yaml" || return $?
  if [[ "$SCENARIO" == "pid-reuse" ]]; then
    assert_pid_reuse_compose_contract || return $?
  fi

  invalidate_project_transport_evidence || return $?
  log_info "building and starting the demo stack"
  RUN_STAGE="compose-build-start"
  if [[ -n "$SOURCE_SNAPSHOT_DIR" ]]; then
    assert_sealed_source_snapshot_is_private
  fi
  startup_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  if [[ "$SCENARIO" == "delayed-otlp-suppression" ]]; then
    DELAYED_OTLP_PROVIDER_READY_SINCE="$startup_since"
  fi
  if [[ "$SCENARIO" == "diagnostic-nondisclosure" ]]; then
    DIAGNOSTIC_NONDISCLOSURE_LOG_SINCE="$startup_since"
  fi
  STACK_STARTED=true
  if [[ "$SCENARIO" == "delayed-otlp-suppression" ]]; then
    recreate_arguments=(--force-recreate)
  fi
  if uses_uninstrumented_runtime; then
    run_logged_bounded "$RESULT_DIR/compose-up.log" "$COMMAND_TIMEOUT_SECONDS" \
      "${COMPOSE[@]}" up --build --detach \
        --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" \
        "${recreate_arguments[@]}" \
        trace-receiver java-backend coalesced-source apache-proxy || start_status=$?
  else
    run_logged_bounded "$RESULT_DIR/compose-up.log" "$COMMAND_TIMEOUT_SECONDS" \
      "${COMPOSE[@]}" up --build --detach \
        --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" \
        "${recreate_arguments[@]}" \
        trace-receiver java-backend coalesced-source apache-proxy obi || start_status=$?
  fi
  if ((start_status != 0)); then
    return "$start_status"
  fi
  if ! uses_uninstrumented_runtime; then
    OBI_RUNNING=true
    if [[ "$TRANSPORT" != "disabled" ]]; then
      BRIDGE_RUNNING=true
    fi
  fi

  RUN_STAGE="readiness"
  wait_for_http "http://127.0.0.1:14318/healthz" "trace receiver" || return $?
  if [[ "$TRANSPORT" != "disabled" ]]; then
    wait_for_log \
      obi \
      "Java remote parent bridge ready" \
      "OBI remote-parent bridge" \
      "$startup_since" || return $?
    if [[ "$SCENARIO" == "pid-reuse" ]]; then
      assert_pid_reuse_runtime_contract || return $?
      plan_obi_metric_pair_capture pid-reuse-controller-window || return $?
      capture_phase_evidence pid-reuse-controller-before || return $?
      if run_pid_reuse_controller; then
        capture_phase_evidence pid-reuse-controller-after || return $?
        record_obi_metric_pair \
          pid-reuse-controller-window pid-reuse-controller-before \
          pid-reuse-controller-after same_process "" >/dev/null || return $?
        attach_obi_artifact_capture \
          pid-reuse-controller pid-reuse-controller.json || return $?
      else
        controller_status=$?
        if [[ -f "$RESULT_DIR/pid-reuse-controller.json" &&
          ! -L "$RESULT_DIR/pid-reuse-controller.json" ]]; then
          attach_obi_artifact_capture \
            pid-reuse-controller pid-reuse-controller.json || return $?
        fi
        return "$controller_status"
      fi
    fi
    wait_for_log \
      java-backend \
      "OBI remote-parent propagator enabled" \
      "external OTel extension" \
      "$startup_since" || return $?
    wait_for_log \
      java-backend \
      "Jetty HTTPS backend ready on 127.0.0.1:18443" \
      "Jetty HTTPS backend" \
      "$startup_since" || return $?
    wait_for_log \
      java-backend \
      "Netty HTTPS backend ready on 127.0.0.1:18444" \
      "Netty HTTPS backend" \
      "$startup_since" || return $?
    wait_for_log \
      java-backend \
      "TLS boundary split HTTPS backend ready on 127.0.0.1:18445" \
      "TLS boundary split HTTPS backend" \
      "$startup_since" || return $?
    wait_for_log \
      java-backend \
      "TLS boundary coalesced HTTPS backend ready on 127.0.0.1:18446" \
      "TLS boundary coalesced HTTPS backend" \
      "$startup_since" || return $?
  elif ! uses_uninstrumented_runtime; then
    wait_for_log \
      java-backend \
      "OBI remote-parent propagator enabled" \
      "external OTel extension" \
      "$startup_since" || return $?
  fi
  if ! uses_uninstrumented_runtime; then
    wait_for_log \
      java-backend \
      "OBI Java instrumentation ready" \
      "injected Java instrumentation" \
      "$startup_since" || return $?
    wait_for_apache_instrumentation startup || return $?
  fi
  if [[ "$SCENARIO" == "delayed-otlp-suppression" ]]; then
    wait_for_log \
      apache-proxy \
      "resuming normal operations" \
      "Apache HTTP proxy" \
      "$startup_since" || return $?
    return 0
  fi
  wait_for_http \
    "http://127.0.0.1:18081/healthz" \
    "live coalesced-request source" || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "verified Apache-to-Jetty HTTPS path" || return $?
  if [[ "$TRANSPORT" != "disabled" ]]; then
    # A provider registration attempted before the bridge is ready is retried
    # when Java next handles TLS traffic. Use the bounded health request as that
    # activation probe, then require the provider and selected transport.
    wait_for_log \
      java-backend \
      "OBI remote-parent provider ready" \
      "injected Java helper" \
      "$startup_since" || return $?
    assert_selected_transport || return $?
  fi
  assert_apache_denies_java_diagnostics || return $?
  assert_runtime_contract "$runtime_contract_mode" || return $?
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
  metrics="$(mktemp "$RESULT_DIR/.apache-readiness.XXXXXX")" || return $?
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
        install -m 0644 \
          "$metrics" "$RESULT_DIR/apache-instrumentation-$label.prom" || return $?
        {
          printf 'expected_processes=%d\n' "$APACHE_EXPECTED_PROCESS_COUNT"
          printf 'observed_processes=%s\n' "$process_count"
          printf 'instrumented_processes=%s\n' "$instrumented_count"
        } >"$RESULT_DIR/apache-instrumentation-$label.txt" || return $?
        rm -f -- "$metrics" || return $?
        log_info "all $APACHE_EXPECTED_PROCESS_COUNT Apache processes are instrumented"
        return 0
      fi
    else
      consecutive_matches=0
    fi
    if ((SECONDS < deadline)); then
      sleep 1 || return $?
    fi
  done
  rm -f -- "$metrics" || return $?
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
  metrics="$(mktemp "$RESULT_DIR/.apache-drain.XXXXXX")" || return $?
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
        install -m 0644 \
          "$metrics" "$RESULT_DIR/apache-instrumentation-drain-$label.prom" || return $?
        {
          printf 'expected_instrumented_processes=0\n'
          printf 'instrumented_processes=%s\n' "$instrumented_count"
        } >"$RESULT_DIR/apache-instrumentation-drain-$label.txt" || return $?
        rm -f -- "$metrics" || return $?
        log_info "Apache instrumentation drained before $label replacement"
        return 0
      fi
    else
      consecutive_matches=0
    fi
    if ((SECONDS < deadline)); then
      sleep 1 || return $?
    fi
  done
  rm -f -- "$metrics" || return $?
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
      if logs="$(run_bounded 10 \
        "${COMPOSE[@]}" logs --no-color --since "$since" "$service" 2>/dev/null)"; then
        :
      else
        logs=""
      fi
    else
      if logs="$(run_bounded 10 \
        "${COMPOSE[@]}" logs --no-color --tail 200 "$service" 2>/dev/null)"; then
        :
      else
        logs=""
      fi
    fi
    if [[ "$logs" == *"$pattern"* ]]; then
      log_info "$description is ready"
      return 0
    fi
    sleep 1 || return $?
  done
  log_error "timed out waiting for $description log: $pattern"
  return 1
}

assert_apache_denies_java_diagnostics() {
  local path=""
  local method=""
  local status=""
  local -a method_arguments=()
  local -a paths=(
    /obi-diagnostics
    /obi-diagnostics/
    /obi-diagnostics/child
    '/obi-diagnostics?probe=1'
    '/obi-diagnostics;matrix=1'
    /obi-diagnostics%3Bmatrix=1
    /obi-transport-configuration
    /obi-transport-configuration/
    /obi-transport-configuration/child
    '/obi-transport-configuration?probe=1'
    '/obi-transport-configuration;matrix=1'
    /obi-transport-configuration%3Bmatrix=1
  )

  for path in "${paths[@]}"; do
    for method in GET HEAD OPTIONS POST; do
      if [[ "$method" == "HEAD" ]]; then
        method_arguments=(--head)
      else
        method_arguments=(--request "$method")
      fi
      if status="$(curl --silent --show-error --max-time 5 --path-as-is \
        "${method_arguments[@]}" \
        --output /dev/null \
        --write-out '%{http_code}' \
        "http://127.0.0.1:18080$path")"; then
        :
      else
        log_error "Apache $method denial probe failed for $path"
        return 1
      fi
      [[ "$status" == "403" ]] || {
        log_error "Apache exposed $path to $method with status $status"
        return 1
      }
    done
  done
}

is_canonical_uint8() {
  local -r value="$1"

  [[ "$value" =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((10#$value <= 255))
}

transport_configuration_values() {
  local -r configuration="$1"
  local version=""
  local status=""
  local requested=""
  local selected=""
  local attempted=""
  local getsockopt=""
  local unix=""
  local value=""

  if [[ "$configuration" =~ ^version=([0-9]+),status=([0-9]+),requested=([0-9]+),selected=([0-9]+),attempted=([0-9]+),getsockopt=([0-9]+),unix=([0-9]+)$ ]]; then
    version="${BASH_REMATCH[1]}"
    status="${BASH_REMATCH[2]}"
    requested="${BASH_REMATCH[3]}"
    selected="${BASH_REMATCH[4]}"
    attempted="${BASH_REMATCH[5]}"
    getsockopt="${BASH_REMATCH[6]}"
    unix="${BASH_REMATCH[7]}"
  else
    return 1
  fi
  for value in "$version" "$status" "$requested" "$selected" "$attempted" "$getsockopt" "$unix"; do
    is_canonical_uint8 "$value" || return 1
  done

  printf '%s %s %s %s %s %s %s\n' \
    "$version" "$status" "$requested" "$selected" "$attempted" "$getsockopt" "$unix"
}

transport_configuration_from_file() {
  local -r configuration_file="$1"
  local configuration=""
  local -i byte_count=0
  local -i line_count=0

  [[ -f "$configuration_file" && ! -L "$configuration_file" ]] || return 1
  byte_count="$(LC_ALL=C wc -c <"$configuration_file")" || return 1
  line_count="$(LC_ALL=C wc -l <"$configuration_file")" || return 1
  ((byte_count > 0 &&
    byte_count <= TRANSPORT_CONFIGURATION_MAX_BYTES &&
    line_count == 1)) || return 1
  IFS= read -r configuration <"$configuration_file" || return 1
  ((${#configuration} + 1 == byte_count)) || return 1
  transport_configuration_values "$configuration" >/dev/null || return 1
  printf '%s\n' "$configuration"
}

selected_transport_from_configuration() {
  local -r configuration="$1"
  local -r expected="$2"
  local values=""
  local version=""
  local status=""
  local requested=""
  local selected=""
  local attempted=""
  local getsockopt=""
  local unix=""

  values="$(transport_configuration_values "$configuration")" || return 1
  read -r version status requested selected attempted getsockopt unix <<<"$values"
  ((version == 2 && status == 1 && attempted <= 3 && getsockopt <= 13 && unix <= 13)) ||
    return 1

  case "$expected" in
    auto) ((requested == 0)) || return 1 ;;
    getsockopt) ((requested == 1)) || return 1 ;;
    unix) ((requested == 2)) || return 1 ;;
    *) return 1 ;;
  esac

  case "$selected" in
    1)
      [[ "$expected" != "unix" ]] || return 1
      ((attempted == 1 && getsockopt == 1 && unix == 0)) || return 1
      printf 'getsockopt\n'
      ;;
    2)
      [[ "$expected" != "getsockopt" ]] || return 1
      ((unix == 1)) || return 1
      if [[ "$expected" == "unix" ]]; then
        ((attempted == 2 && getsockopt == 0)) || return 1
      else
        ((attempted == 3)) || return 1
        case "$getsockopt" in
          4|5|8|10|11|12) ;;
          *) return 1 ;;
        esac
      fi
      printf 'unix\n'
      ;;
    *) return 1 ;;
  esac
}

auto_transports_unavailable_from_configuration() {
  local -r configuration="$1"
  local values=""
  local version=""
  local status=""
  local requested=""
  local selected=""
  local attempted=""
  local getsockopt=""
  local unix=""

  values="$(transport_configuration_values "$configuration")" || return 1
  read -r version status requested selected attempted getsockopt unix <<<"$values"
  ((version == 2 && requested == 0 && selected == 255 && attempted == 3 &&
    status == unix)) || return 1
  case "$getsockopt" in
    4|5|8|10|11|12) ;;
    *) return 1 ;;
  esac
  case "$unix" in
    3|4|5|6|7|8|9|10|11|12|13) ;;
    *) return 1 ;;
  esac
}

wait_for_auto_transports_unavailable_configuration() {
  local -r output="$1"
  local -r attempts_output="$RESULT_DIR/auto-unavailable-transport-attempts.txt"
  local candidate=""
  local configuration=""
  local -i attempt=0

  [[ "$output" == "$RESULT_DIR/java-auto-unavailable-transport-configuration.txt" &&
    ! -e "$output" && ! -L "$output" &&
    ! -e "$attempts_output" && ! -L "$attempts_output" ]] || return 1
  candidate="$(mktemp "$RESULT_DIR/.java-auto-unavailable-transport.XXXXXX")" || return $?
  : >"$attempts_output" || return $?
  for ((attempt = 1; attempt <= AUTO_UNAVAILABLE_CONFIGURATION_MAX_ATTEMPTS; attempt++)); do
    if curl --fail --silent --show-error --max-time 5 \
      --max-filesize "$TRANSPORT_CONFIGURATION_MAX_BYTES" \
      --cacert "$CERT_DIR/ca.crt" \
      "https://127.0.0.1:18443/obi-transport-configuration" \
      --output "$candidate" 2>/dev/null &&
      configuration="$(transport_configuration_from_file "$candidate")"; then
      printf 'attempt=%d %s\n' "$attempt" "$configuration" >>"$attempts_output" || return $?
      if auto_transports_unavailable_from_configuration "$configuration"; then
        install -m 0644 "$candidate" "$output" || return $?
        rm -f -- "$candidate" || return $?
        return 0
      fi
    else
      printf 'attempt=%d unavailable\n' "$attempt" >>"$attempts_output" || return $?
    fi
    if ((attempt < AUTO_UNAVAILABLE_CONFIGURATION_MAX_ATTEMPTS)); then
      sleep 1 || return $?
    fi
  done
  rm -f -- "$candidate" || return $?
  log_error "auto transport did not report both primary and fallback unavailable"
  return 1
}

invalidate_selected_transport() {
  if [[ -n "${RESULT_DIR:-}" ]]; then
    rm -f -- "$RESULT_DIR/java-transport-configuration.txt" || return $?
  fi
  SELECTED_TRANSPORT=""
}

result_evidence_matches_project() {
  local -r environment="$1"

  awk -v project="$PROJECT_NAME" '
    index($0, "compose_project=") == 1 {
      entries += 1
      if ($0 == "compose_project=" project) {
        matches += 1
      }
    }
    END {
      if (entries != 1) {
        exit 2
      }
      exit matches == 1 ? 0 : 1
    }
  ' "$environment"
}

assert_no_pending_permanent_absence_recovery() {
  local marker=""
  local recorded_docker_identity=""

  assert_project_docker_identity_unchanged || return $?
  marker="$(permanent_absence_global_marker_path)" || return $?
  [[ -e "$marker" || -L "$marker" ]] || return 0
  recorded_docker_identity="$(read_permanent_absence_global_marker)" || {
    log_error "host-shared permanent-absence recovery marker is untrusted: $marker"
    return 1
  }
  if [[ "$recorded_docker_identity" != "$PROJECT_DOCKER_SERVER_ID_SHA256" ]]; then
    log_error "pending permanent-absence recovery belongs to a different Docker server"
  else
    log_error "pending permanent-absence recovery requires --cleanup-only before this project can start: $marker"
  fi
  return 1
}

permanent_absence_global_marker_payload() {
  local -r docker_identity="$1"

  [[ "$docker_identity" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' \
    'schema=permanent-absence-recovery-v1' \
    "project=$PROJECT_NAME" \
    "sentinel=$PROJECT_SENTINEL_VALUE" \
    "docker_server_id_sha256=$docker_identity"
}

read_permanent_absence_global_marker() {
  local marker=""
  local marker_metadata=""
  local recorded_docker_identity=""
  local -a marker_lines=()

  assert_project_guard_held || return 1
  marker="$(permanent_absence_global_marker_path)" || return 1
  [[ -f "$marker" && ! -L "$marker" && -r "$marker" ]] || return 1
  marker_metadata="$(stat --format='%u:%a:%h:%s' -- "$marker")" || return 1
  [[ "$marker_metadata" =~ ^${EUID}:600:1:([1-9][0-9]{0,2})$ ]] || return 1
  mapfile -t marker_lines <"$marker" || return 1
  [[ ${#marker_lines[@]} -eq 4 && \
    "${marker_lines[0]}" == 'schema=permanent-absence-recovery-v1' && \
    "${marker_lines[1]}" == "project=$PROJECT_NAME" && \
    "${marker_lines[2]}" == "sentinel=$PROJECT_SENTINEL_VALUE" && \
    "${marker_lines[3]}" =~ ^docker_server_id_sha256=([0-9a-f]{64})$ ]] || return 1
  recorded_docker_identity="${BASH_REMATCH[1]}"
  cmp -s -- "$marker" \
    <(permanent_absence_global_marker_payload "$recorded_docker_identity") || return 1
  printf '%s\n' "$recorded_docker_identity"
}

create_permanent_absence_global_marker() {
  local marker=""
  local recorded_docker_identity=""

  assert_project_docker_identity_unchanged || return $?
  marker="$(permanent_absence_global_marker_path)" || return $?
  [[ ! -e "$marker" && ! -L "$marker" ]] || {
    log_error "permanent-absence recovery marker already exists: $marker"
    return 1
  }
  if ! (umask 077; set -o noclobber; \
    permanent_absence_global_marker_payload \
      "$PROJECT_DOCKER_SERVER_ID_SHA256" >"$marker") 2>/dev/null; then
    log_error "could not atomically create the host-shared recovery marker"
    return 1
  fi
  recorded_docker_identity="$(read_permanent_absence_global_marker)" || return 1
  [[ "$recorded_docker_identity" == "$PROJECT_DOCKER_SERVER_ID_SHA256" ]]
}

assert_permanent_absence_marker_matches_current_docker() {
  local marker=""
  local recorded_docker_identity=""

  assert_project_docker_identity_unchanged || return $?
  marker="$(permanent_absence_global_marker_path)" || return 1
  [[ -e "$marker" || -L "$marker" ]] || return 0
  recorded_docker_identity="$(read_permanent_absence_global_marker)" || {
    log_error "permanent-absence recovery marker is untrusted"
    return 1
  }
  [[ "$recorded_docker_identity" == "$PROJECT_DOCKER_SERVER_ID_SHA256" ]] || {
    log_error "permanent-absence recovery marker belongs to a different Docker server"
    return 1
  }
}

clear_pending_permanent_absence_recovery() {
  local marker=""
  local recorded_docker_identity=""

  assert_project_guard_held || return 1
  marker="$(permanent_absence_global_marker_path)" || return 1
  [[ -e "$marker" || -L "$marker" ]] || return 0
  recorded_docker_identity="$(read_permanent_absence_global_marker)" || {
    log_error "refusing to remove an untrusted host-shared recovery marker"
    return 1
  }
  assert_project_docker_identity_unchanged || return $?
  [[ "$recorded_docker_identity" == "$PROJECT_DOCKER_SERVER_ID_SHA256" ]] || {
    log_error "refusing to clear recovery state from a different Docker server"
    return 1
  }
  rm -f -- "$marker" || return $?
  [[ ! -e "$marker" && ! -L "$marker" ]]
}

invalidate_project_transport_evidence() {
  local result_directory=""
  local environment=""
  local transport_configuration=""
  local match_status=0

  if [[ -e "$RESULTS_ROOT" || -L "$RESULTS_ROOT" ]]; then
    if [[ -L "$RESULTS_ROOT" || ! -d "$RESULTS_ROOT" ]]; then
      log_error "results root is not a regular directory: $RESULTS_ROOT"
      return 1
    fi
    if [[ ! -r "$RESULTS_ROOT" || ! -x "$RESULTS_ROOT" ]]; then
      log_error "results root cannot be enumerated safely: $RESULTS_ROOT"
      return 1
    fi

    for result_directory in \
      "$RESULTS_ROOT"/* \
      "$RESULTS_ROOT"/.[!.]* \
      "$RESULTS_ROOT"/..?*; do
      [[ -e "$result_directory" || -L "$result_directory" ]] || continue
      [[ -d "$result_directory" && ! -L "$result_directory" ]] || continue
      if [[ ! -r "$result_directory" || ! -x "$result_directory" ]]; then
        log_error "result directory cannot be inspected safely: $result_directory"
        return 1
      fi
      transport_configuration="$result_directory/java-transport-configuration.txt"
      [[ -e "$transport_configuration" || -L "$transport_configuration" ]] || continue
      environment="$result_directory/environment.txt"
      if [[ ! -f "$environment" || -L "$environment" || ! -r "$environment" ]]; then
        log_error "current transport evidence has no trustworthy project identity: $result_directory"
        return 1
      fi
      if result_evidence_matches_project "$environment"; then
        :
      else
        match_status=$?
        if ((match_status == 1)); then
          continue
        fi
        log_error "could not inspect result environment safely: $environment"
        return "$match_status"
      fi
      rm -f -- "$transport_configuration" || return $?
    done
  fi

  if [[ -n "${RESULT_DIR:-}" ]]; then
    invalidate_selected_transport || return $?
  else
    SELECTED_TRANSPORT=""
  fi
}

assert_selected_transport() {
  local -r expected="${1:-$TRANSPORT}"
  local -r configuration_file="$RESULT_DIR/java-transport-configuration.txt"
  local -r selected_configuration_file="$RESULT_DIR/java-selected-transport-configuration.txt"
  local configuration=""
  local publication_status=0
  local selected_configuration_temporary=""
  local selected=""

  invalidate_selected_transport || return $?
  if ! curl --fail --silent --show-error --max-time 5 \
    --max-filesize "$TRANSPORT_CONFIGURATION_MAX_BYTES" \
    --cacert "$CERT_DIR/ca.crt" \
    "https://127.0.0.1:18443/obi-transport-configuration" \
    --output "$configuration_file" 2>/dev/null; then
    rm -f -- "$configuration_file"
    log_error "failed to read the $expected Java transport configuration"
    return 1
  fi
  if ! configuration="$(transport_configuration_from_file "$configuration_file")"; then
    rm -f -- "$configuration_file"
    log_error "received a malformed $expected Java transport configuration"
    return 1
  fi
  if ! selected="$(selected_transport_from_configuration "$configuration" "$expected")"; then
    log_error "received an unsuccessful $expected Java transport configuration"
    return 1
  fi
  selected_configuration_temporary="$(
    mktemp "$RESULT_DIR/.java-selected-transport-configuration.XXXXXX"
  )" || return $?
  if install -m 0644 "$configuration_file" "$selected_configuration_temporary"; then
    :
  else
    publication_status=$?
    rm -f -- "$selected_configuration_temporary" || true
    log_error "failed to retain the selected Java transport configuration"
    return "$publication_status"
  fi
  if mv -fT -- "$selected_configuration_temporary" "$selected_configuration_file"; then
    :
  else
    publication_status=$?
    rm -f -- "$selected_configuration_temporary" || true
    log_error "failed to publish the selected Java transport configuration"
    return "$publication_status"
  fi
  SELECTED_TRANSPORT="$selected"
  bind_selected_transport_to_obi_metric_boundary_index "$selected" || return $?
  return 0
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

environment_line_prefix_count() {
  local -r environment="$1"
  local -r prefix="$2"
  local line=""
  local -i count=0

  while IFS= read -r line; do
    if [[ "$line" == "$prefix"* ]]; then
      ((count += 1))
    fi
  done <<<"$environment"
  printf '%d\n' "$count"
}

assert_primary_fault_runtime_contract() {
  local -r java_container="$1"
  local -r java_environment="$2"
  local preload_count=""
  local control_file_count=""

  preload_count="$(environment_line_prefix_count "$java_environment" "LD_PRELOAD=")" || return $?
  control_file_count="$(environment_line_prefix_count \
    "$java_environment" "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE=")" || return $?
  [[ "$preload_count" == "1" && "$control_file_count" == "1" ]] || {
    log_error "primary fault runtime must expose exactly one preload and control-file setting"
    return 1
  }
  environment_has_line "$java_environment" "LD_PRELOAD=$PRIMARY_FAULT_PRELOAD" || {
    log_error "primary fault runtime did not use the fixed preload library"
    return 1
  }
  environment_has_line \
    "$java_environment" \
    "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE=$PRIMARY_FAULT_CONTROL_FILE" || {
    log_error "primary fault runtime did not use the fixed control-file path"
    return 1
  }
  # shellcheck disable=SC2016 # The fixed paths are positional parameters in the Java container.
  run_bounded 10 docker exec "$java_container" /bin/sh -ec '
    set -eu
    directory=$1
    control_file=$2
    [ "$(id -u)" = 0 ]
    [ -d "$directory" ] && [ ! -L "$directory" ]
    [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
    [ ! -e "$control_file" ] && [ ! -L "$control_file" ]
  ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE"
}

assert_obi_remote_parent_timeout() {
  local -r expected="$1"
  local obi_container=""
  local environment=""
  local count=""

  obi_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi)" || return $?
  [[ -n "$obi_container" ]] || return 1
  environment="$(run_bounded 10 docker inspect \
    --format '{{range .Config.Env}}{{println .}}{{end}}' "$obi_container")" || return $?
  count="$(environment_line_prefix_count \
    "$environment" "OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT=")" || return $?
  [[ "$count" == 1 ]] && environment_has_line \
    "$environment" "OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT=$expected"
}

assert_unix_generation_mismatch_runtime_contract() {
  local -r output="$1"
  local obi_container=""
  local environment=""
  local transport_count=""
  local timeout_count=""

  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  obi_container="$(run_bounded 10 "${UNIX_GENERATION_FAULT_COMPOSE[@]}" ps --quiet obi)" || return $?
  [[ -n "$obi_container" ]] || return 1
  environment="$(run_bounded 10 docker inspect \
    --format '{{range .Config.Env}}{{println .}}{{end}}' "$obi_container")" || return $?
  transport_count="$(environment_line_prefix_count \
    "$environment" "OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=")" || return $?
  timeout_count="$(environment_line_prefix_count \
    "$environment" "OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT=")" || return $?
  [[ "$transport_count" == 1 && "$timeout_count" == 1 ]] || return 1
  environment_has_line "$environment" \
    "OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=unix" || return 1
  environment_has_line "$environment" \
    "OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT=30s" || return 1
  printf 'status=passed\ntransport=unix\ntimeout=30s\n' >"$output"
}

assert_unix_generation_deadlines() {
  ((UNIX_GENERATION_BARRIER_READY_TIMEOUT_SECONDS +
      GENERATION_FAULT_READY_TIMEOUT_SECONDS +
      UNIX_GENERATION_DEADLINE_SLACK_SECONDS <
      UNIX_GENERATION_BARRIER_TIMEOUT_SECONDS &&
    UNIX_GENERATION_BARRIER_TIMEOUT_SECONDS <
      UNIX_GENERATION_FAULT_TIMEOUT_SECONDS &&
    UNIX_GENERATION_BARRIER_READY_TIMEOUT_SECONDS +
      GENERATION_FAULT_READY_TIMEOUT_SECONDS +
      UNIX_GENERATION_BACKEND_HOLD_SECONDS +
      UNIX_GENERATION_DEADLINE_SLACK_SECONDS <
      UNIX_GENERATION_PROXY_TIMEOUT_SECONDS &&
    UNIX_GENERATION_PROXY_TIMEOUT_SECONDS <
      GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS &&
    GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS <
      UNIX_GENERATION_SCENARIO_TIMEOUT_SECONDS &&
    GENERATION_FAULT_TAKE_FENCE_TIMEOUT_SECONDS +
      GENERATION_FAULT_REAP_TIMEOUT_SECONDS +
      UNIX_GENERATION_DEADLINE_SLACK_SECONDS <
      UNIX_GENERATION_BACKEND_HOLD_SECONDS &&
    GENERATION_FAULT_RELEASE_TIMEOUT_SECONDS <
      GENERATION_FAULT_HELPER_TIMEOUT_SECONDS &&
    UNIX_GENERATION_FAULT_TIMEOUT_MILLISECONDS ==
      UNIX_GENERATION_FAULT_TIMEOUT_SECONDS * 1000))
}

assert_primary_live_fd_security_runtime_topology() {
  local -r java_container="$1"
  local privileged=""
  local pid_mode=""
  local cap_add=""
  local security_options=""

  privileged="$(run_bounded 10 docker inspect --format '{{.HostConfig.Privileged}}' \
    "$java_container")" || return $?
  pid_mode="$(run_bounded 10 docker inspect --format '{{.HostConfig.PidMode}}' \
    "$java_container")" || return $?
  cap_add="$(run_bounded 10 docker inspect --format '{{json .HostConfig.CapAdd}}' \
    "$java_container")" || return $?
  security_options="$(run_bounded 10 docker inspect \
    --format '{{json .HostConfig.SecurityOpt}}' "$java_container")" || return $?

  [[ "$privileged" == "false" && -z "$pid_mode" ]] || {
    log_error "primary live-descriptor security runtime must stay unprivileged with a private PID namespace"
    return 1
  }
  jq -e '
    type == "array" and length == 1 and
    (.[0] == "SYS_PTRACE" or .[0] == "CAP_SYS_PTRACE")
  ' <<<"$cap_add" >/dev/null || {
    log_error "primary live-descriptor security runtime must grant exactly CAP_SYS_PTRACE"
    return 1
  }
  jq -e '. == null or (type == "array" and length == 0)' \
    <<<"$security_options" >/dev/null || {
    log_error "primary live-descriptor security runtime must retain Docker's default seccomp profile"
    return 1
  }
}

assert_normal_runtime_has_no_primary_fault_environment() {
  local -r java_environment="$1"
  local preload_count=""
  local control_file_count=""

  preload_count="$(environment_line_prefix_count "$java_environment" "LD_PRELOAD=")" || return $?
  control_file_count="$(environment_line_prefix_count \
    "$java_environment" "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE=")" || return $?
  [[ "$preload_count" == "0" && "$control_file_count" == "0" ]] || {
    log_error "normal Java runtime unexpectedly retained a primary fault setting"
    return 1
  }
}

host_vmlinux_btf_readable() {
  [[ -r /sys/kernel/btf/vmlinux ]]
}

assert_runtime_contract() {
  local -r mode="${1:-$SCENARIO}"
  local -r suppression_already_observed="${2:-false}"
  local -r output="$RESULT_DIR/runtime-assertions-$mode.txt"
  local java_container=""
  local java_environment=""
  local obi_container=""
  local obi_identity=""
  local obi_environment=""
  local bridge_transport_count=""
  local java_agent="absent"
  local java_otlp_retry="not-configured"
  local dynamic_agent_loading="not-configured"
  local extension="absent"
  local bridge_transport="not-applicable"
  local live_fd_security_topology="not-applicable"

  [[ "$suppression_already_observed" == "false" || \
    "$suppression_already_observed" == "true" ]] || {
    log_error "duplicate suppression readiness state must be true or false"
    return 1
  }

  java_container="$(run_bounded 10 \
    "${COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$java_container" ]] || {
    log_error "Java backend container identity is unavailable"
    return 1
  }
  java_environment="$(run_bounded 10 docker inspect \
    --format '{{range .Config.Env}}{{println .}}{{end}}' \
    "$java_container")" || return $?
  if environment_has_line \
    "$java_environment" \
    "JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar"; then
    java_agent="official"
    dynamic_agent_loading="enabled"
  elif environment_has_line \
    "$java_environment" \
    "JAVA_TOOL_OPTIONS=$HELPER_ATTACH_FAILURE_JAVA_TOOL_OPTIONS"; then
    java_agent="official"
    dynamic_agent_loading="disabled"
  fi
  if environment_has_line \
    "$java_environment" \
    "OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar"; then
    extension="invalid"
    if environment_has_line "$java_environment" "OTEL_OBI_REMOTE_PARENT_ENABLED=true"; then
      extension="enabled"
    elif environment_has_line "$java_environment" "OTEL_OBI_REMOTE_PARENT_ENABLED=false"; then
      extension="disabled"
    fi
  fi
  if [[ "$mode" == "delayed-otlp-suppression" ]] && ! environment_has_line \
    "$java_environment" \
    "OTEL_BSP_SCHEDULE_DELAY=$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS"; then
    log_error "delayed OTLP control did not configure the expected Java export delay"
    return 1
  fi
  if environment_has_line \
    "$java_environment" \
    "OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED=true"; then
    java_otlp_retry="disabled"
  elif environment_has_line \
    "$java_environment" \
    "OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED=false"; then
    java_otlp_retry="enabled"
  fi
  if [[ "$mode" == "delayed-otlp-suppression" && "$java_otlp_retry" != "disabled" ]]; then
    log_error "delayed OTLP control did not disable Java OTLP retries"
    return 1
  fi

  if [[ "$mode" == "primary-w3c-fault" || \
    "$mode" == "primary-generation-mismatch" || \
    "$mode" == "unix-generation-mismatch" || \
    "$mode" == "primary-live-fd-security" ]]; then
    assert_primary_fault_runtime_contract "$java_container" "$java_environment" || return $?
  else
    assert_normal_runtime_has_no_primary_fault_environment "$java_environment" || return $?
  fi
  if [[ "$mode" == "primary-live-fd-security" ]]; then
    assert_primary_live_fd_security_runtime_topology "$java_container" || return $?
    live_fd_security_topology="private-pid-sys-ptrace"
  fi

  if [[ "$mode" == "uninstrumented" ]]; then
    [[ "$java_agent" == "absent" && "$extension" == "absent" ]] || {
      log_error "uninstrumented control unexpectedly configured Java instrumentation"
      return 1
    }
    obi_container="$(
      run_bounded 10 "${COMPOSE[@]}" ps --quiet obi 2>/dev/null
    )" || return $?
    [[ -z "$obi_container" ]] || {
      log_error "uninstrumented control unexpectedly started OBI"
      return 1
    }
  elif [[ "$mode" == "obi-absent" || "$mode" == "permanent-absence" || \
    "$mode" == "auto-unavailable" ]]; then
    [[ "$java_agent" == "official" && "$dynamic_agent_loading" == "enabled" &&
      "$extension" == "enabled" ]] || {
      log_error "OBI-absent control requires the official agent and enabled extension"
      return 1
    }
    obi_container="$(
      run_bounded 10 "${COMPOSE[@]}" ps --quiet obi 2>/dev/null
    )" || return $?
    [[ -z "$obi_container" ]] || {
      log_error "OBI-absent control unexpectedly started OBI"
      return 1
    }
  elif [[ "$mode" == "extension-absent" || "$mode" == "extension-disabled" ]]; then
    [[ "$java_agent" == "official" && "$dynamic_agent_loading" == "enabled" ]] || {
      log_error "$mode control requires the official Java agent"
      return 1
    }
    [[ "$extension" == "${mode#extension-}" ]] || {
      log_error "$mode control has extension state $extension"
      return 1
    }
    obi_container="$(
      run_bounded 10 "${COMPOSE[@]}" ps --quiet obi 2>/dev/null
    )" || return $?
    [[ -z "$obi_container" ]] || {
      log_error "$mode control unexpectedly started OBI"
      return 1
    }
  elif [[ "$mode" == "disabled" ]]; then
    [[ "$java_agent" == "official" && "$dynamic_agent_loading" == "enabled" &&
      "$extension" == "enabled" ]] || {
      log_error "disabled control requires the official Java agent and enabled extension"
      return 1
    }
    obi_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi)" || return $?
    [[ -n "$obi_container" ]] || {
      log_error "disabled control requires an OBI container"
      return 1
    }
    obi_identity="$(run_bounded 10 docker inspect \
      --format '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}}' \
      "$obi_container")" || return $?
    [[ "$obi_identity" == "true host" ]] || {
      log_error "OBI runtime must be privileged with the host PID namespace, got: $obi_identity"
      return 1
    }
    obi_environment="$(run_bounded 10 docker inspect \
      --format '{{range .Config.Env}}{{println .}}{{end}}' \
      "$obi_container")" || return $?
    bridge_transport_count="$(environment_line_prefix_count \
      "$obi_environment" \
      "OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=")" || return $?
    [[ "$bridge_transport_count" == "1" ]] || {
      log_error "disabled control requires exactly one OBI remote-parent transport setting"
      return 1
    }
    environment_has_line \
      "$obi_environment" \
      "OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=disabled" || {
      log_error "disabled control did not configure the OBI remote-parent transport as disabled"
      return 1
    }
    host_vmlinux_btf_readable || {
      log_error "host vmlinux BTF is not readable"
      return 1
    }
    bridge_transport="disabled"
    if [[ "$suppression_already_observed" == "false" ]]; then
      wait_for_java_duplicate_suppression \
        "$RESULT_DIR/duplicate-suppression-$mode.prom" || return $?
    fi
  elif [[ "$mode" == "helper-attach-fault" ]]; then
    [[ "$java_agent" == "official" && "$dynamic_agent_loading" == "disabled" &&
      "$extension" == "enabled" ]] || {
      log_error "helper attach failure control requires the exact dynamic-loading-disabled official agent and enabled extension"
      return 1
    }
    obi_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi)" || return $?
    [[ -n "$obi_container" ]] || {
      log_error "OBI container identity is unavailable"
      return 1
    }
    obi_identity="$(run_bounded 10 docker inspect \
      --format '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}}' \
      "$obi_container")" || return $?
    [[ "$obi_identity" == "true host" ]] || {
      log_error "OBI runtime must be privileged with the host PID namespace, got: $obi_identity"
      return 1
    }
    host_vmlinux_btf_readable || {
      log_error "host vmlinux BTF is not readable"
      return 1
    }
  else
    [[ "$java_agent" == "official" && "$dynamic_agent_loading" == "enabled" &&
      "$extension" == "enabled" ]] || {
      log_error "Java runtime does not have the expected official agent and extension opt-in"
      return 1
    }
    obi_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi)" || return $?
    [[ -n "$obi_container" ]] || {
      log_error "OBI container identity is unavailable"
      return 1
    }
    obi_identity="$(run_bounded 10 docker inspect \
      --format '{{.HostConfig.Privileged}} {{.HostConfig.PidMode}}' \
      "$obi_container")" || return $?
    [[ "$obi_identity" == "true host" ]] || {
      log_error "OBI runtime must be privileged with the host PID namespace, got: $obi_identity"
      return 1
    }
    host_vmlinux_btf_readable || {
      log_error "host vmlinux BTF is not readable"
      return 1
    }
    if [[ "$suppression_already_observed" == "false" ]]; then
      wait_for_java_duplicate_suppression \
        "$RESULT_DIR/duplicate-suppression-$mode.prom" || return $?
    fi
  fi

  {
    printf 'status=passed\n'
    printf 'java_container=%s\n' "$java_container"
    printf 'java_agent=%s\n' "$java_agent"
    printf 'java_otlp_retry=%s\n' "$java_otlp_retry"
    printf 'dynamic_agent_loading=%s\n' "$dynamic_agent_loading"
    printf 'extension=%s\n' "$extension"
    printf 'obi_container=%s\n' "${obi_container:-absent}"
    printf 'obi_privileged_pid_mode=%s\n' "${obi_identity:-absent}"
    printf 'bridge_transport=%s\n' "$bridge_transport"
    printf 'live_fd_security_topology=%s\n' "$live_fd_security_topology"
    printf 'vmlinux_btf=%s\n' "$(host_vmlinux_btf_readable && printf readable || printf unavailable)"
  } >"$output" || return $?
}

wait_for_java_duplicate_suppression() {
  local -r output="$1"
  local -r timeout_seconds="${2:-$READINESS_TIMEOUT_SECONDS}"

  wait_for_java_duplicate_suppression_with_policy \
    "$output" \
    "$timeout_seconds" \
    "$JAVA_DUPLICATE_SUPPRESSION_PRIME_INTERVAL_SECONDS"
}

wait_for_java_duplicate_suppression_without_prime() {
  local -r output="$1"
  local -r timeout_seconds="${2:-$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS}"

  wait_for_java_duplicate_suppression_with_policy \
    "$output" "$timeout_seconds" 0
}

wait_for_java_duplicate_suppression_with_policy() {
  local -r output="$1"
  local timeout_seconds=""
  local prime_interval_seconds=""
  local metrics=""
  local last_metrics=""
  local -i elapsed=0
  local -i fetch_timeout=0
  local last_metrics_ready=false
  local -i next_prime_at=0
  local -i remaining=0
  local -i request_timeout=0
  local -i started_at="$SECONDS"
  local status=0
  local suppression_present=false

  timeout_seconds="$(bounded_decimal "$2" "$MAX_SHELL_INTEGER" false)" || return 1
  prime_interval_seconds="$(bounded_decimal "$3" "$MAX_SHELL_INTEGER" true)" || return 1
  metrics="$(mktemp "$RESULT_DIR/.duplicate-suppression.XXXXXX")" || return $?
  last_metrics="$(mktemp "$RESULT_DIR/.duplicate-suppression-last.XXXXXX")" || {
    status=$?
    rm -f -- "$metrics" || true
    return "$status"
  }
  while ((SECONDS - started_at < timeout_seconds)); do
    elapsed="$((SECONDS - started_at))"
    remaining="$((timeout_seconds - elapsed))"
    if ((prime_interval_seconds > 0 && elapsed >= next_prime_at)); then
      request_timeout="$remaining"
      ((request_timeout <= 10)) || request_timeout=10
      if run_bounded "$request_timeout" curl --fail --silent --show-error \
        --max-time "$request_timeout" \
        "$APACHE_HTTPS_HEALTH_ENDPOINT" >/dev/null; then
        next_prime_at="$((elapsed + prime_interval_seconds))"
      else
        status=$?
        if [[ "$last_metrics_ready" == "true" ]]; then
          # Preserve the last complete scrape for the primary prime failure.
          # Publication failure is secondary and must not replace its status.
          install -m 0644 "$last_metrics" "$output" || true
        fi
        rm -f -- "$metrics" "$last_metrics" || true
        return "$status"
      fi
    fi
    elapsed="$((SECONDS - started_at))"
    remaining="$((timeout_seconds - elapsed))"
    ((remaining > 0)) || break
    fetch_timeout="$remaining"
    ((fetch_timeout <= 5)) || fetch_timeout=5
    if fetch_obi_metrics "$metrics" "$fetch_timeout" 2>/dev/null; then
      if install -m 0600 "$metrics" "$last_metrics"; then
        last_metrics_ready=true
      else
        status=$?
        rm -f -- "$metrics" "$last_metrics" || true
        return "$status"
      fi
    fi
    # A scrape that finishes on or after the deadline remains useful failure
    # evidence, but must not turn an expired readiness window into success.
    ((SECONDS - started_at < timeout_seconds)) || break
    suppression_present=false
    if [[ "$last_metrics_ready" == "true" ]] && \
      java_duplicate_suppression_present "$last_metrics"; then
      suppression_present=true
    fi
    # Predicate evaluation is part of the same wall-clock transaction on both
    # its true and false paths.
    ((SECONDS - started_at < timeout_seconds)) || break
    if [[ "$suppression_present" == "true" ]]; then
      if install -m 0644 "$last_metrics" "$output"; then
        :
      else
        status=$?
        rm -f -- "$metrics" "$last_metrics" || true
        return "$status"
      fi
      # Evidence publication is part of the bounded readiness transaction.
      ((SECONDS - started_at < timeout_seconds)) || {
        rm -f -- "$metrics" "$last_metrics" || true
        log_error "OBI did not report Java duplicate-trace suppression"
        return 1
      }
      rm -f -- "$metrics" "$last_metrics" || return $?
      return 0
    fi
    if sleep 1; then
      :
    else
      status=$?
      rm -f -- "$metrics" "$last_metrics" || true
      return "$status"
    fi
  done
  if [[ "$last_metrics_ready" == "true" ]]; then
    if install -m 0644 "$last_metrics" "$output"; then
      :
    else
      status=$?
      rm -f -- "$metrics" "$last_metrics" || true
      return "$status"
    fi
  fi
  rm -f -- "$metrics" "$last_metrics" || return $?
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

assert_java_duplicate_suppression_absent() {
  local -r output="$1"
  local metrics=""
  local status=0

  metrics="$(mktemp "$RESULT_DIR/.duplicate-suppression.XXXXXX")" || return $?
  if fetch_obi_metrics "$metrics"; then
    :
  else
    status=$?
    rm -f -- "$metrics" || true
    return "$status"
  fi
  if java_duplicate_suppression_present "$metrics"; then
    rm -f -- "$metrics" || true
    log_error "OBI reported Java duplicate-trace suppression before delayed export readiness"
    return 1
  fi
  if install -m 0644 "$metrics" "$output"; then
    :
  else
    status=$?
    rm -f -- "$metrics" || true
    return "$status"
  fi
  rm -f -- "$metrics" || return $?
}

delayed_otlp_run_nonce() {
  local nonce=""

  nonce="$(run_bounded "$DELAYED_OTLP_NONCE_TIMEOUT_SECONDS" openssl rand -hex 16)" ||
    return $?
  [[ "$nonce" =~ ^[[:xdigit:]]{32}$ ]] || return 1
  printf '%s\n' "${nonce,,}"
}

initialize_delayed_otlp_run_identity() {
  local nonce=""
  local marker=""

  nonce="$(delayed_otlp_run_nonce)" || return $?
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || return 1
  marker="$DELAYED_OTLP_PRIME_MARKER_PREFIX-$nonce"
  ((${#marker} <= 128)) || return 1

  DELAYED_OTLP_PRIME_MARKER="$marker"
  DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64=""
  DELAYED_OTLP_RECEIVER_RESET_GENERATION=""
}

delayed_otlp_receiver_snapshot_is_single_object() {
  local -r snapshot="$1"

  jq -e -s 'length == 1 and (.[0] | type == "object")' \
    "$snapshot" >/dev/null
}

delayed_otlp_receiver_snapshot_continuity() {
  local -r snapshot="$1"

  delayed_otlp_receiver_snapshot_is_single_object "$snapshot" || return $?
  jq -er --argjson maximum "$MAX_JSON_SAFE_INTEGER" '
    if
      (.receiver_instance_id | type == "string") and
      ((.receiver_instance_id | length) >= 1) and
      (.reset_generation | type == "number") and
      .reset_generation >= 0 and
      .reset_generation <= $maximum and
      .reset_generation == (.reset_generation | floor)
    then
      [(.receiver_instance_id | @base64),
        (.reset_generation | floor | tostring)] | @tsv
    else
      error("invalid receiver continuity")
    end
  ' "$snapshot"
}

capture_delayed_otlp_receiver_continuity() {
  local -r snapshot="$1"
  local continuity=""
  local receiver_instance_id=""
  local reset_generation=""
  local extra=""

  [[ -z "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" &&
    -z "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" ]] || return 1
  continuity="$(delayed_otlp_receiver_snapshot_continuity "$snapshot")" || return $?
  IFS=$'\t' read -r receiver_instance_id reset_generation extra <<<"$continuity" ||
    return $?
  [[ -n "$receiver_instance_id" && -n "$reset_generation" && -z "$extra" ]] ||
    return 1

  DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64="$receiver_instance_id"
  DELAYED_OTLP_RECEIVER_RESET_GENERATION="$reset_generation"
}

delayed_otlp_receiver_snapshot_has_expected_continuity() {
  local -r snapshot="$1"
  local continuity=""
  local receiver_instance_id=""
  local reset_generation=""
  local extra=""

  [[ -n "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" &&
    -n "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" ]] || return 1
  continuity="$(delayed_otlp_receiver_snapshot_continuity "$snapshot")" || return $?
  IFS=$'\t' read -r receiver_instance_id reset_generation extra <<<"$continuity" ||
    return $?
  [[ -z "$extra" &&
    "$receiver_instance_id" == "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" &&
    "$reset_generation" == "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" ]]
}

fetch_delayed_otlp_receiver_snapshot() {
  local -r output="$1"
  local -r timeout_seconds="${2:-10}"

  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 1
  timeout --signal=TERM \
    --kill-after="${DELAYED_OTLP_FETCH_KILL_GRACE_SECONDS}s" \
    "${timeout_seconds}s" curl --fail --silent --show-error \
    --get --data-urlencode "marker=$DELAYED_OTLP_PRIME_MARKER" \
    --output "$output" \
    "http://127.0.0.1:14318/snapshot"
}

create_delayed_otlp_receiver_snapshot_temp() {
  local -r template="$1"
  local status=0

  [[ -n "$template" && -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]] || return 1
  if DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP="$(mktemp "$template")"; then
    return 0
  else
    status=$?
    DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP=""
    return "$status"
  fi
}

create_delayed_otlp_receiver_publication_temp() {
  local -r template="$1"
  local status=0

  [[ -n "$template" && -z "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" ]] || return 1
  if DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP="$(mktemp "$template")"; then
    return 0
  else
    status=$?
    DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP=""
    return "$status"
  fi
}

discard_delayed_otlp_receiver_snapshot_temp() {
  local -r temporary="$1"
  local status=0

  [[ -n "$temporary" ]] || return 0
  if rm -f -- "$temporary"; then
    if [[ "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" == "$temporary" ]]; then
      DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP=""
    fi
    return 0
  else
    status=$?
    return "$status"
  fi
}

discard_delayed_otlp_receiver_publication_temp() {
  local -r temporary="$1"
  local status=0

  [[ -n "$temporary" ]] || return 0
  if rm -f -- "$temporary"; then
    if [[ "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" == "$temporary" ]]; then
      DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP=""
    fi
    return 0
  else
    status=$?
    return "$status"
  fi
}

cleanup_delayed_otlp_receiver_temporaries() {
  local status=0
  local cleanup_status=0

  if [[ -n "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]]; then
    if discard_delayed_otlp_receiver_snapshot_temp \
      "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP"; then
      :
    else
      cleanup_status=$?
      if ((status == 0)); then
        status="$cleanup_status"
      fi
    fi
  fi
  if [[ -n "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" ]]; then
    if discard_delayed_otlp_receiver_publication_temp \
      "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP"; then
      :
    else
      cleanup_status=$?
      if ((status == 0)); then
        status="$cleanup_status"
      fi
    fi
  fi
  return "$status"
}

cleanup_diagnostic_nondisclosure_request_directory() {
  local -r directory="${DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR:-}"
  local metadata=""
  local cleanup_status=0

  [[ -n "$directory" ]] || return 0
  [[ -n "${RESULT_DIR:-}" &&
    "$directory" == "$RESULT_DIR"/.diagnostic-nondisclosure-request.* ]] || return 1
  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR=""
    return 0
  fi
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  metadata="$(stat --format='%u:%a' -- "$directory")" || return $?
  [[ "$metadata" == "$EUID:700" ]] || return 1
  if rm -f -- \
    "$directory/request.headers" \
    "$directory/request.body" \
    "$directory/response.headers" \
    "$directory/response.json" \
    "$directory/response.status" \
    "$directory/canaries.txt" \
    "$directory/canaries.unsorted" \
    "$directory/.java-endpoint.capture" \
    "$directory/parsed-metrics.txt" \
    "$directory/parsed-metrics.unsorted" \
    "$directory/report.candidate" \
    "$directory/diagnostic-nondisclosure-java-endpoint.txt" \
    "$directory/diagnostic-nondisclosure-java-header.txt" \
    "$directory/diagnostic-nondisclosure-java-transport-configuration.txt" \
    "$directory/diagnostic-nondisclosure-obi-metrics.prom" \
    "$directory/diagnostic-nondisclosure-obi.log" \
    "$directory/diagnostic-nondisclosure-java.log" \
    "$directory/.obi.log.capture" \
    "$directory/.java-backend.log.capture" \
    "$directory/obi.log.candidate" \
    "$directory/java-backend.log.candidate" \
    "$directory/unix-probe.json" &&
    rmdir -- "$directory"; then
    DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR=""
    return 0
  else
    cleanup_status=$?
  fi
  return "$cleanup_status"
}

delayed_otlp_receiver_snapshot_progress() {
  local -r snapshot="$1"

  delayed_otlp_receiver_snapshot_is_single_object "$snapshot" || return $?
  jq -er --arg marker "$DELAYED_OTLP_PRIME_MARKER" \
    --arg scope "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    --argjson maximum "$MAX_JSON_SAFE_INTEGER" '
    if
      (.received_batches | type == "number") and
      (.received_spans | type == "number") and
      (.dropped_spans | type == "number") and
      (.dropped_count_spans | type == "number") and
      (.dropped_value_limit_spans | type == "number") and
      (.dropped_retained_limit_spans | type == "number") and
      .received_batches >= 0 and
      .received_spans >= 0 and
      .received_batches <= $maximum and
      .received_spans <= $maximum and
      .received_batches == (.received_batches | floor) and
      .received_spans == (.received_spans | floor) and
      .dropped_spans == 0 and
      .dropped_count_spans == 0 and
      .dropped_value_limit_spans == 0 and
      .dropped_retained_limit_spans == 0 and
      ((has("omitted_related_spans") | not) or
        ((.omitted_related_spans | type == "number") and
          .omitted_related_spans == 0)) and
      ((has("ambiguous_related_spans") | not) or
        ((.ambiguous_related_spans | type == "number") and
          .ambiguous_related_spans == 0)) and
      (.spans | type == "array")
    then
      ([.spans[] |
        select(
          .service_name == "java-backend" and
          .kind == "SERVER" and
          .scope_name != $scope and
          .attributes["http.request.header.x-obi-demo-id"] == $marker
        )] | length) as $pre_detection_servers |
      [.received_batches, .received_spans, $pre_detection_servers] | @tsv
    else
      error("invalid delayed OTLP receiver progress")
    end
  ' "$snapshot"
}

publish_delayed_otlp_receiver_snapshot() {
  local -r snapshot="$1"
  local -r output="$2"
  local output_directory=""
  local output_name=""
  local temporary=""
  local status=0

  output_directory="$(dirname -- "$output")" || return $?
  output_name="$(basename -- "$output")" || return $?
  create_delayed_otlp_receiver_publication_temp \
    "$output_directory/.${output_name}.XXXXXX" || return $?
  temporary="$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP"
  if install -m 0644 "$snapshot" "$temporary"; then
    :
  else
    status=$?
    discard_delayed_otlp_receiver_publication_temp "$temporary" || true
    return "$status"
  fi
  if mv -f -- "$temporary" "$output"; then
    DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP=""
    return 0
  else
    status=$?
    discard_delayed_otlp_receiver_publication_temp "$temporary" || true
    return "$status"
  fi
}

retain_delayed_otlp_receiver_failure() {
  local -r snapshot="$1"
  local -r output="$2"
  local -r message="$3"

  publish_delayed_otlp_receiver_snapshot "$snapshot" "$output" || return $?
  log_error "$message"
  return 1
}

delayed_otlp_receiver_snapshot_is_empty() {
  local -r snapshot="$1"

  delayed_otlp_receiver_snapshot_is_single_object "$snapshot" || return $?
  jq -e --arg marker "$DELAYED_OTLP_PRIME_MARKER" '
    .marker == $marker and
    .received_batches == 0 and
    .received_spans == 0 and
    (.spans | type == "array" and length == 0)
  ' "$snapshot" >/dev/null
}

delayed_otlp_receiver_snapshot_has_java_export() {
  local -r snapshot="$1"

  delayed_otlp_receiver_snapshot_is_single_object "$snapshot" || return $?
  jq -e --arg marker "$DELAYED_OTLP_PRIME_MARKER" \
    --arg scope "$DELAYED_OTLP_JAVA_SERVER_SCOPE" '
    .marker == $marker and
    .received_batches > 0 and
    .received_spans > 0 and
    (.spans | type == "array") and
    ([.spans[] |
      select(
        .service_name == "java-backend" and
        .kind == "SERVER" and
        .attributes["http.request.header.x-obi-demo-id"] == $marker
      )] as $java_servers |
      ([$java_servers[] | select(.scope_name == $scope)] as $java_sdk_servers |
        ([$java_servers[] | select(.scope_name != $scope)] as $pre_detection_servers |
          (($java_servers | length) >= 1) and
          (($java_servers | length) <= 2) and
          (($java_sdk_servers | length) == 1) and
          (($pre_detection_servers | length) <= 1) and
          ($pre_detection_servers | all(.[];
            (.scope_name == null or .scope_name == "") and
            (.received_unix_milli | type == "number") and
            (.received_unix_milli > 0)
          )) and
          ($java_sdk_servers[0].received_unix_milli | type == "number") and
          ($java_sdk_servers[0].received_unix_milli > 0))))
  ' "$snapshot" >/dev/null
}

delayed_otlp_receiver_snapshot_has_java_export_before_deadline() {
  local -r snapshot="$1"
  local -r earliest_export_millisecond="$2"

  [[ "$earliest_export_millisecond" =~ ^[0-9]+$ ]] || return 1
  delayed_otlp_receiver_snapshot_is_single_object "$snapshot" || return $?
  jq -e --arg marker "$DELAYED_OTLP_PRIME_MARKER" \
    --arg scope "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    --argjson earliest_export_millisecond "$earliest_export_millisecond" '
    .marker == $marker and
    (.spans | type == "array") and
    ([.spans[] |
      select(
        .service_name == "java-backend" and
        .kind == "SERVER" and
        .scope_name == $scope and
        .attributes["http.request.header.x-obi-demo-id"] == $marker and
        (.received_unix_milli | type == "number") and
        .received_unix_milli < $earliest_export_millisecond
      )] | length > 0)
  ' "$snapshot" >/dev/null
}

delayed_otlp_receiver_snapshot_has_java_export_at_or_after_deadline() {
  local -r snapshot="$1"
  local -r earliest_export_millisecond="$2"

  [[ "$earliest_export_millisecond" =~ ^[0-9]+$ ]] || return 1
  delayed_otlp_receiver_snapshot_is_single_object "$snapshot" || return $?
  # The collector can receive a pre-detection OBI span in a later OTLP batch.
  # Classify that span by its lifetime while keeping the SDK receipt gate strict.
  delayed_otlp_receiver_snapshot_has_java_export "$snapshot" || return 1
  jq -e --arg marker "$DELAYED_OTLP_PRIME_MARKER" \
    --arg scope "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    --argjson earliest_export_millisecond "$earliest_export_millisecond" '
    [.spans[] |
      select(
        .service_name == "java-backend" and
        .kind == "SERVER" and
        .attributes["http.request.header.x-obi-demo-id"] == $marker
      )] as $java_servers |
    [$java_servers[] | select(.scope_name == $scope)] as $java_sdk_servers |
    [$java_servers[] | select(.scope_name != $scope)] as $pre_detection_servers |
    ($java_sdk_servers[0].received_unix_milli >= $earliest_export_millisecond) and
    ($pre_detection_servers | all(.[];
      (.start_unix_nano | type == "number") and
      (.end_unix_nano | type == "number") and
      .start_unix_nano > 0 and
      .end_unix_nano >= .start_unix_nano and
      .end_unix_nano < ($earliest_export_millisecond * 1000000)
    ))
  ' "$snapshot" >/dev/null
}

assert_delayed_otlp_receiver_empty() {
  local -r output="$1"
  local snapshot=""
  local status=0
  local cleanup_status=0

  create_delayed_otlp_receiver_snapshot_temp \
    "$RESULT_DIR/.delayed-otlp-receiver.XXXXXX" || return $?
  snapshot="$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP"
  if fetch_delayed_otlp_receiver_snapshot "$snapshot"; then
    :
  else
    status=$?
    discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
    return "$status"
  fi
  if ! capture_delayed_otlp_receiver_continuity "$snapshot"; then
    status=0
    retain_delayed_otlp_receiver_failure \
      "$snapshot" "$output" \
      "trace receiver did not expose a fresh valid continuity token" || status=$?
    discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
    return "$status"
  fi
  if ! delayed_otlp_receiver_snapshot_is_empty "$snapshot"; then
    status=0
    retain_delayed_otlp_receiver_failure \
      "$snapshot" "$output" \
      "trace receiver accepted an OTLP export before delayed export readiness" || status=$?
    discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
    return "$status"
  fi
  publish_delayed_otlp_receiver_snapshot "$snapshot" "$output" || status=$?
  if discard_delayed_otlp_receiver_snapshot_temp "$snapshot"; then
    :
  else
    cleanup_status=$?
    if ((status == 0)); then
      status="$cleanup_status"
    fi
  fi
  return "$status"
}

delayed_otlp_receiver_snapshot_has_no_java_export() {
  local -r snapshot="$1"

  delayed_otlp_receiver_snapshot_is_single_object "$snapshot" || return $?
  jq -e --arg marker "$DELAYED_OTLP_PRIME_MARKER" \
    --arg scope "$DELAYED_OTLP_JAVA_SERVER_SCOPE" '
      .marker == $marker and
      (.spans | type == "array") and
      ([.spans[] |
        select(
          .service_name == "java-backend" and
          .kind == "SERVER" and
          .scope_name == $scope and
          .attributes["http.request.header.x-obi-demo-id"] == $marker
        )] | length == 0)
    ' "$snapshot" >/dev/null
}

assert_delayed_otlp_receiver_has_no_java_export() {
  local -r output="$1"
  local snapshot=""
  local status=0
  local cleanup_status=0

  create_delayed_otlp_receiver_snapshot_temp \
    "$RESULT_DIR/.delayed-otlp-receiver.XXXXXX" || return $?
  snapshot="$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP"
  if fetch_delayed_otlp_receiver_snapshot "$snapshot"; then
    :
  else
    status=$?
    discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
    return "$status"
  fi
  if ! delayed_otlp_receiver_snapshot_has_expected_continuity "$snapshot"; then
    status=0
    retain_delayed_otlp_receiver_failure \
      "$snapshot" "$output" \
      "trace receiver continuity changed before delayed export readiness" || status=$?
    discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
    return "$status"
  fi
  if ! delayed_otlp_receiver_snapshot_has_no_java_export "$snapshot"; then
    status=0
    retain_delayed_otlp_receiver_failure \
      "$snapshot" "$output" \
      "trace receiver accepted the delayed Java OTLP export before readiness" || status=$?
    discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
    return "$status"
  fi
  publish_delayed_otlp_receiver_snapshot "$snapshot" "$output" || status=$?
  if discard_delayed_otlp_receiver_snapshot_temp "$snapshot"; then
    :
  else
    cleanup_status=$?
    if ((status == 0)); then
      status="$cleanup_status"
    fi
  fi
  return "$status"
}

wait_for_delayed_otlp_receiver_export() {
  local -r output="$1"
  local -r timeout_seconds="${2:-$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS}"
  local -r earliest_export_millisecond="${3:-}"
  local -r early_output="${4:-$output}"
  local -r unexpected_output="${5:-$output}"
  local -r settle_seconds="${6:-$DELAYED_OTLP_POST_EXPORT_SETTLE_SECONDS}"
  local snapshot=""
  local snapshot_progress=""
  local command_timeout=""
  local phase="discovery"
  local -i current_batches=0
  local -i current_spans=0
  local -i current_pre_detection=0
  local -i previous_batches=-1
  local -i previous_spans=-1
  local -i previous_pre_detection=0
  local -i phase_deadline=0
  local status=0
  local boundary_polled=false
  local poll_is_boundary=false
  local snapshot_fetched=false

  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$earliest_export_millisecond" =~ ^[0-9]+$ ]] || return 1
  [[ "$settle_seconds" =~ ^[1-9][0-9]*$ ]] || return 1
  create_delayed_otlp_receiver_snapshot_temp \
    "$RESULT_DIR/.delayed-otlp-receiver.XXXXXX" || return $?
  snapshot="$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP"
  phase_deadline="$((SECONDS + timeout_seconds))"

  while :; do
    poll_is_boundary=false
    if ((SECONDS < phase_deadline)); then
      command_timeout="$(remaining_timeout_seconds "$phase_deadline" 10)" || {
        discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
        return 1
      }
    elif [[ "$boundary_polled" == "false" ]] &&
      ((SECONDS <= phase_deadline + DELAYED_OTLP_BOUNDARY_START_SLACK_SECONDS)); then
      # One one-second fetch samples the inclusive deadline without opening an
      # unbounded command overrun.
      command_timeout="$DELAYED_OTLP_BOUNDARY_POLL_SECONDS"
      boundary_polled=true
      poll_is_boundary=true
    else
      break
    fi

    if fetch_delayed_otlp_receiver_snapshot "$snapshot" "$command_timeout"; then
      snapshot_fetched=true
    else
      status=$?
      discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
      return "$status"
    fi

    if delayed_otlp_receiver_snapshot_has_expected_continuity "$snapshot" &&
      snapshot_progress="$(delayed_otlp_receiver_snapshot_progress "$snapshot")" &&
      IFS=$'\t' read -r current_batches current_spans current_pre_detection \
        <<<"$snapshot_progress" &&
      [[ "$current_batches" =~ ^[0-9]+$ && "$current_spans" =~ ^[0-9]+$ &&
        "$current_pre_detection" =~ ^[0-9]+$ ]] &&
      ((previous_batches < 0 ||
        (current_batches >= previous_batches &&
          current_spans >= previous_spans &&
          current_pre_detection >= previous_pre_detection))); then
      previous_batches="$current_batches"
      previous_spans="$current_spans"
      previous_pre_detection="$current_pre_detection"
    else
      status=0
      retain_delayed_otlp_receiver_failure \
        "$snapshot" "$unexpected_output" \
        "trace receiver continuity changed, or its delayed snapshot regressed or was malformed" ||
        status=$?
      discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
      return "$status"
    fi

    if delayed_otlp_receiver_snapshot_has_java_export_before_deadline \
      "$snapshot" "$earliest_export_millisecond"; then
      status=0
      retain_delayed_otlp_receiver_failure \
        "$snapshot" "$early_output" \
        "trace receiver accepted the delayed Java OTLP export before its configured deadline" || \
        status=$?
      discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
      return "$status"
    elif delayed_otlp_receiver_snapshot_has_java_export_at_or_after_deadline \
      "$snapshot" "$earliest_export_millisecond"; then
      if [[ "$phase" == "discovery" ]]; then
        phase="settlement"
        phase_deadline="$((SECONDS + settle_seconds))"
        boundary_polled=false
      elif [[ "$poll_is_boundary" == "true" ]]; then
        if publish_delayed_otlp_receiver_snapshot "$snapshot" "$output"; then
          :
        else
          status=$?
          discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
          return "$status"
        fi
        discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || return $?
        return 0
      fi
    elif delayed_otlp_receiver_snapshot_has_no_java_export "$snapshot" &&
      [[ "$phase" == "discovery" ]]; then
      if [[ "$poll_is_boundary" == "true" ]]; then
        status=0
        retain_delayed_otlp_receiver_failure \
          "$snapshot" "$unexpected_output" \
          "trace receiver did not retain the delayed Java OTLP export" || status=$?
        discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
        return "$status"
      fi
    else
      status=0
      retain_delayed_otlp_receiver_failure \
        "$snapshot" "$unexpected_output" \
        "trace receiver retained an unexpected delayed Java server span" || status=$?
      discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
      return "$status"
    fi

    if ((SECONDS < phase_deadline)); then
      if sleep 1; then
        :
      else
        status=$?
        discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
        return "$status"
      fi
    fi
  done

  if [[ "$snapshot_fetched" == "true" ]]; then
    status=0
    retain_delayed_otlp_receiver_failure \
      "$snapshot" "$unexpected_output" \
      "trace receiver missed the bounded delayed OTLP final poll" || status=$?
    discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || true
    return "$status"
  fi
  discard_delayed_otlp_receiver_snapshot_temp "$snapshot" || return $?
  log_error "trace receiver did not complete delayed Java OTLP validation"
  return 1
}

java_backend_started_millisecond() {
  local java_container=""
  local started_at=""
  local millisecond=""

  java_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$java_container" ]] || return 1
  started_at="$(run_bounded 10 docker inspect --format '{{.State.StartedAt}}' "$java_container")" ||
    return $?
  [[ "$started_at" == *Z ]] || return 1
  millisecond="$(date -u --date="$started_at" +%s%3N)" || return $?
  [[ "$millisecond" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$millisecond"
}

delayed_otlp_earliest_export_millisecond() {
  local java_started_millisecond=""

  java_started_millisecond="$(java_backend_started_millisecond)" || return $?
  printf '%s\n' "$((java_started_millisecond + DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS))"
}

assert_delayed_otlp_pre_export_window() {
  local -r output="$1"
  local -r expected_earliest_export_millisecond="${2:-}"
  local java_started_millisecond=""
  local current_millisecond=""
  local -i earliest_export_millisecond=0

  java_started_millisecond="$(java_backend_started_millisecond)" || return $?
  current_millisecond="$(date -u +%s%3N)" || return $?
  [[ "$current_millisecond" =~ ^[0-9]+$ ]] || return 1
  if [[ -n "$expected_earliest_export_millisecond" ]]; then
    [[ "$expected_earliest_export_millisecond" =~ ^[0-9]+$ ]] || return 1
    [[ "$expected_earliest_export_millisecond" == \
      "$((java_started_millisecond + DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS))" ]] || {
      log_error "Java backend generation changed before delayed OTLP observation"
      return 1
    }
    earliest_export_millisecond="$expected_earliest_export_millisecond"
  else
    earliest_export_millisecond="$((java_started_millisecond + DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS))"
  fi
  if ((current_millisecond +
    (DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS + DELAYED_OTLP_PRE_EXPORT_SAFETY_SECONDS) * 1000 >=
    earliest_export_millisecond)); then
    log_error "cold Java startup did not leave the required delayed OTLP observation window"
    return 1
  fi
  {
    printf 'java_started_millisecond=%s\n' "$java_started_millisecond"
    printf 'prime_millisecond=%s\n' "$current_millisecond"
    printf 'earliest_export_millisecond=%s\n' "$earliest_export_millisecond"
    printf 'schedule_delay_milliseconds=%s\n' "$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS"
    printf 'pre_export_wait_seconds=%s\n' "$DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS"
    printf 'pre_export_safety_seconds=%s\n' "$DELAYED_OTLP_PRE_EXPORT_SAFETY_SECONDS"
  } >"$output" || return $?
}

obi_metric_output_parent_is_contained() {
  local -r output="$1"
  local parent=""
  local result_physical=""
  local parent_physical=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    "$output" == "$RESULT_DIR"/* && "$output" != *$'\n'* ]] || return 1
  parent="${output%/*}"
  [[ -d "$parent" && ! -L "$parent" ]] || return 1
  result_physical="$(realpath -e -- "$RESULT_DIR")" || return 1
  parent_physical="$(realpath -e -- "$parent")" || return 1
  [[ "$parent_physical" == "$result_physical" ||
    "$parent_physical" == "$result_physical"/* ]]
}

capture_obi_metrics_candidate() {
  local -r candidate="$1"
  local -r timeout_seconds="$2"
  local size=""
  local capture_status=0

  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ &&
    -f "$candidate" && ! -L "$candidate" ]] || return 1
  if curl --fail --silent --show-error --max-time "$timeout_seconds" \
    "http://127.0.0.1:18990/internal/metrics" |
    (
      LC_ALL=C head -c "$((OBI_METRIC_SNAPSHOT_MAX_BYTES + 1))" \
        >"$candidate" || exit $?
      cat >/dev/null
    ); then
    :
  else
    capture_status=$?
    return "$capture_status"
  fi
  size="$(stat -Lc '%s' -- "$candidate")" || return 1
  ((size > 0 && size <= OBI_METRIC_SNAPSHOT_MAX_BYTES)) || return 1
  bounded_evidence_file \
    "$candidate" \
    "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
    "$OBI_METRIC_SNAPSHOT_MAX_LINES"
}

fetch_obi_metrics() {
  local -r output="$1"
  local -r timeout_seconds="${2:-5}"
  local parent=""
  local candidate=""
  local capture_status=0

  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ &&
    ! -L "$output" && ( ! -e "$output" || -f "$output" ) ]] || return 1
  obi_metric_output_parent_is_contained "$output" || return 1
  parent="${output%/*}"
  candidate="$(mktemp "$parent/.obi-metrics.XXXXXX")" || return $?
  if capture_obi_metrics_candidate "$candidate" "$timeout_seconds" &&
    chmod 0644 -- "$candidate" && mv -fT -- "$candidate" "$output"; then
    return 0
  else
    capture_status=$?
  fi
  rm -f -- "$candidate" || true
  return "$capture_status"
}

java_attach_error_total() {
  local -r metrics="$1"
  local metric=""
  local labels=""
  local raw_value=""
  local extra=""
  local value=""
  local found=false

  while read -r metric raw_value extra; do
    [[ "$metric" == 'obi_instrumentation_errors_total{'*'}' ]] || continue
    labels="${metric#*\{}"
    labels="${labels%\}}"
    if [[ "$labels" == 'error_type="attaching_java_agent",process_name="java"' ||
      "$labels" == 'process_name="java",error_type="attaching_java_agent"' ]]; then
      [[ "$found" == "false" && -z "$extra" ]] || return 1
      value="$(bounded_decimal "$raw_value" "$MAX_SHELL_INTEGER" true)" || return 1
      found=true
    elif [[ "$labels" == *'error_type="attaching_java_agent"'* &&
      "$labels" == *'process_name="java"'* ]]; then
      return 1
    fi
  done <"$metrics"

  if [[ "$found" == "true" ]]; then
    printf '%s\n' "$value"
  else
    printf 'absent\n'
  fi
}

wait_for_java_attach_error_total() {
  local -r expected="$1"
  local -r baseline="$2"
  local -r output="$3"
  local -r description="$4"
  local -r required_samples="${5:-$JAVA_ATTACH_FAILURE_QUIET_SAMPLES}"
  local -r samples_output="${output%.prom}-samples.log"
  local candidate=""
  local state=""
  local baseline_value=""
  local observed=false
  local -i stable_samples=0
  local -i started_at="$SECONDS"

  bounded_decimal "$expected" "$MAX_SHELL_INTEGER" true >/dev/null || return 1
  bounded_decimal "$required_samples" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  if [[ "$baseline" == "absent" ]]; then
    baseline_value=0
  else
    baseline_value="$(bounded_decimal "$baseline" "$MAX_SHELL_INTEGER" true)" || return 1
  fi
  ((expected >= baseline_value && expected - baseline_value <= 1)) || return 1

  candidate="$(mktemp "$RESULT_DIR/.java-attach-errors.XXXXXX")" || return $?
  : >"$samples_output" || return $?
  while ((SECONDS - started_at < READINESS_TIMEOUT_SECONDS)); do
    if ! fetch_obi_metrics "$candidate" 2>/dev/null; then
      printf '%(%Y-%m-%dT%H:%M:%SZ)T unavailable\n' -1 \
        >>"$samples_output" || return $?
      stable_samples=0
      sleep 1 || return $?
      continue
    fi
    if ! state="$(java_attach_error_total "$candidate")"; then
      rm -f -- "$candidate"
      log_error "$description produced a malformed or duplicate attach-error metric"
      return 1
    fi
    printf '%(%Y-%m-%dT%H:%M:%SZ)T %s\n' -1 "$state" \
      >>"$samples_output" || return $?

    if [[ "$state" == "absent" ]]; then
      if [[ "$baseline" != "absent" || "$observed" == "true" || "$expected" == "0" ]]; then
        rm -f -- "$candidate"
        log_error "$description attach-error metric disappeared or reset"
        return 1
      fi
      stable_samples=0
    elif ((state > expected || state < baseline_value)); then
      rm -f -- "$candidate"
      log_error "$description attach-error metric escaped the expected range baseline=$baseline_value expected=$expected observed=$state"
      return 1
    elif ((state == expected)); then
      observed=true
      ((stable_samples += 1))
      if ((stable_samples >= required_samples)); then
        install -m 0644 "$candidate" "$output" || return $?
        rm -f -- "$candidate" || return $?
        return 0
      fi
    elif [[ "$observed" == "true" ]]; then
      rm -f -- "$candidate"
      log_error "$description attach-error metric reset after reaching $expected"
      return 1
    fi
    sleep 1 || return $?
  done
  rm -f -- "$candidate" || return $?
  log_error "timed out waiting for $description attach-error total=$expected"
  return 1
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
      if (line !~ /operation="take"/) {
        return 0
      }
      if (allow_primary_security == "true" &&
          line ~ /status="unauthorized"/ && line ~ /transport="getsockopt"/) {
        return 1
      }
      return allow_unix_security == "true" &&
        line ~ /status="(unauthorized|timeout|overload)"/ && line ~ /transport="unix"/
    }
  ' "$metrics" | LC_ALL=C sort | sha256sum | awk '{print $1}'
}

wait_for_bridge_metrics_quiescent() {
  local -r minimum_success="$1"
  local -r minimum_stage="$2"
  local -r output="$3"
  local -r description="$4"
  local -r timeout_seconds="${5:-$BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS}"
  local candidate=""
  local fingerprint=""
  local previous_fingerprint=""
  local report=""
  local stage=""
  local success=""
  local metrics_timeout=""
  local -i deadline=0
  local -i previous_report=-1

  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  candidate="$(mktemp "$RESULT_DIR/.bridge-metrics.XXXXXX")" || return $?
  deadline="$((SECONDS + timeout_seconds))"
  while ((SECONDS < deadline)); do
    metrics_timeout="$(remaining_timeout_seconds "$deadline" 5)" || break
    if fetch_obi_metrics "$candidate" "$metrics_timeout" 2>/dev/null; then
      success="$(bridge_success_total "$candidate")" || return $?
      stage="$(bridge_stage_total "$candidate")" || return $?
      report="$(bridge_report_total "$candidate")" || return $?
      fingerprint="$(bridge_metric_fingerprint "$candidate")" || return $?
      if [[ "$success" =~ ^[0-9]+$ && "$stage" =~ ^[0-9]+$ &&
        "$report" =~ ^[0-9]+$ ]] && ((report > previous_report)); then
        if [[ -n "$previous_fingerprint" && "$fingerprint" == "$previous_fingerprint" ]] &&
          ((success >= minimum_success && stage >= minimum_stage)); then
          install -m 0644 "$candidate" "$output" || return $?
          rm -f -- "$candidate" || return $?
          return 0
        fi
        previous_report="$report"
        previous_fingerprint="$fingerprint"
      fi
    fi
    if ((SECONDS < deadline)); then
      sleep 1 || return $?
    fi
  done
  rm -f -- "$candidate" || return $?
  log_error "timed out waiting for $description (minimum success=$minimum_success stage=$minimum_stage, last success=${success:-unavailable} stage=${stage:-unavailable} report=${report:-unavailable})"
  return 1
}

wait_for_bridge_take_attempts_quiescent() {
  local -r expected_attempts="$1"
  local -r expected_stage="$2"
  local -r output="$3"
  local -r description="$4"
  local -r timeout_seconds="${5:-$BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS}"
  local candidate=""
  local fingerprint=""
  local previous_fingerprint=""
  local report=""
  local stage=""
  local attempts=""
  local metrics_timeout=""
  local -i deadline=0
  local -i previous_report=-1

  bounded_decimal "$expected_attempts" "$MAX_SHELL_INTEGER" true >/dev/null || return 1
  bounded_decimal "$expected_stage" "$MAX_SHELL_INTEGER" true >/dev/null || return 1
  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  candidate="$(mktemp "$RESULT_DIR/.bridge-take-fence.XXXXXX")" || return $?
  deadline="$((SECONDS + timeout_seconds))"
  while ((SECONDS < deadline)); do
    metrics_timeout="$(remaining_timeout_seconds "$deadline" 5)" || break
    if fetch_obi_metrics "$candidate" "$metrics_timeout" 2>/dev/null; then
      attempts="$(bridge_take_attempt_total "$candidate")" || {
        rm -f -- "$candidate"
        return 1
      }
      stage="$(bridge_stage_total "$candidate")" || {
        rm -f -- "$candidate"
        return 1
      }
      report="$(bridge_report_total "$candidate")" || {
        rm -f -- "$candidate"
        return 1
      }
      fingerprint="$(bridge_metric_fingerprint "$candidate")" || {
        rm -f -- "$candidate"
        return 1
      }
      if [[ ! "$attempts" =~ ^[0-9]+$ || ! "$stage" =~ ^[0-9]+$ || \
        ! "$report" =~ ^[0-9]+$ ]] || \
        ((attempts > expected_attempts || stage > expected_stage)); then
        rm -f -- "$candidate"
        log_error "$description escaped its exact take fence (take=${attempts:-invalid}/$expected_attempts stage=${stage:-invalid}/$expected_stage)"
        return 1
      fi
      if ((report > previous_report)); then
        if [[ -n "$previous_fingerprint" && \
          "$fingerprint" == "$previous_fingerprint" && \
          "$attempts" == "$expected_attempts" && "$stage" == "$expected_stage" ]]; then
          install -m 0644 "$candidate" "$output" || return $?
          rm -f -- "$candidate" || return $?
          return 0
        fi
        previous_report="$report"
        previous_fingerprint="$fingerprint"
      fi
    fi
    if ((SECONDS < deadline)); then
      sleep 1 || return $?
    fi
  done
  rm -f -- "$candidate" || return $?
  log_error "timed out waiting for $description (exact take=$expected_attempts stage=$expected_stage, last take=${attempts:-unavailable} stage=${stage:-unavailable} report=${report:-unavailable})"
  return 1
}

wait_for_primary_security_metrics_quiescent() {
  local -r output="$1"
  local -r description="$2"
  local -r timeout_seconds="${3:-$BRIDGE_METRIC_QUIESCENCE_TIMEOUT_SECONDS}"
  local -r previous_policy="$ALLOW_PRIMARY_SECURITY_METRICS"
  local wait_status=0

  ALLOW_PRIMARY_SECURITY_METRICS=true
  if wait_for_bridge_metrics_quiescent \
    0 0 "$output" "$description" "$timeout_seconds"; then
    wait_status=0
  else
    wait_status=$?
  fi
  ALLOW_PRIMARY_SECURITY_METRICS="$previous_policy"
  return "$wait_status"
}

wait_for_unix_security_metrics_quiescent() {
  local -r output="$1"
  local -r description="$2"
  local -r previous_policy="$ALLOW_UNIX_SECURITY_METRICS"
  local wait_status=0

  ALLOW_UNIX_SECURITY_METRICS=true
  if wait_for_bridge_metrics_quiescent 0 0 "$output" "$description"; then
    wait_status=0
  else
    wait_status=$?
  fi
  ALLOW_UNIX_SECURITY_METRICS="$previous_policy"
  return "$wait_status"
}

flush_bridge_metric_boundary() {
  local -r label="$1"
  local -r expected_success_increment="${2:-1}"
  local -r expected_stage_increment="${3:-1}"
  local -r diagnostics_output="${4:-}"
  local current=""
  local response_headers=""
  local health_endpoint="$APACHE_HTTPS_HEALTH_ENDPOINT"
  local before_stage=""
  local before_success=""

  [[ "$BRIDGE_RUNNING" == "true" ]] || return 0
  if [[ -n "$diagnostics_output" && \
    ( -e "$diagnostics_output" || -L "$diagnostics_output" ) ]]; then
    log_error "refusing to overwrite bridge-boundary diagnostics: $diagnostics_output"
    return 1
  fi
  bounded_decimal \
    "$expected_success_increment" "$MAX_SHELL_INTEGER" true >/dev/null || return 1
  bounded_decimal \
    "$expected_stage_increment" "$MAX_SHELL_INTEGER" true >/dev/null || return 1
  current="$(mktemp "$RESULT_DIR/.bridge-boundary.XXXXXX")" || return 1
  if ! fetch_obi_metrics "$current"; then
    rm -f -- "$current"
    return 1
  fi
  before_success="$(bridge_success_total "$current")" || {
    rm -f -- "$current"
    return 1
  }
  before_stage="$(bridge_stage_total "$current")" || {
    rm -f -- "$current"
    return 1
  }
  bounded_decimal "$before_success" "$MAX_SHELL_INTEGER" true >/dev/null || {
    rm -f -- "$current"
    return 1
  }
  bounded_decimal "$before_stage" "$MAX_SHELL_INTEGER" true >/dev/null || {
    rm -f -- "$current"
    return 1
  }
  ((before_success <= MAX_SHELL_INTEGER - expected_success_increment &&
    before_stage <= MAX_SHELL_INTEGER - expected_stage_increment)) || {
    rm -f -- "$current"
    return 1
  }
  if [[ -n "$diagnostics_output" ]]; then
    response_headers="$(mktemp "$RESULT_DIR/.bridge-boundary-headers.XXXXXX")" || {
      rm -f -- "$current"
      return 1
    }
    health_endpoint="${health_endpoint}&bridge_diagnostics=1"
    if ! curl --fail --silent --show-error --max-time 5 \
      --dump-header "$response_headers" \
      "$health_endpoint" >/dev/null; then
      rm -f -- "$current" "$response_headers"
      return 1
    fi
    if ! extract_java_diagnostics_header "$response_headers" "$diagnostics_output"; then
      rm -f -- "$current" "$response_headers"
      log_error "bridge-boundary response did not contain one valid Java diagnostics header"
      return 1
    fi
    rm -f -- "$response_headers" || {
      rm -f -- "$current"
      return 1
    }
  elif ! curl --fail --silent --show-error --max-time 5 \
    "$health_endpoint" >/dev/null; then
    rm -f -- "$current"
    return 1
  fi
  rm -f -- "$current" || return $?
  wait_for_bridge_metrics_quiescent \
    "$((before_success + expected_success_increment))" \
    "$((before_stage + expected_stage_increment))" \
    "$RESULT_DIR/metrics-boundary-$label.prom" \
    "$label pre-scenario bridge metric boundary"
}

is_w3c_stale_scenario() {
  case "$1" in
    primary-w3c-stale|unix-w3c-stale)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

scenario_uses_in_band_java_diagnostics() {
  case "$1" in
    coalesced-bridge|timeout-retry)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

scenario_request_count() {
  local -r name="$1"

  if [[ "$name" == "w3c-fault" ]]; then
    printf '%d\n' "$FAULT_REQUEST_COUNT"
    return
  fi
  if [[ "$name" == "primary-w3c-fault" ]]; then
    printf '1\n'
    return
  fi
  if [[ "$name" == "tls-boundary" ]]; then
    printf '3\n'
    return
  fi
  if [[ "$name" == "coalesced-bridge" ]]; then
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
    handoff|virtual-thread|netty|netty-server|dispatch)
      printf '4\n'
      ;;
    w3c|obi-flags|w3c-fault)
      printf '2\n'
      ;;
    primary-w3c-stale|unix-w3c-stale)
      printf '1\n'
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

  # Coalesced and timeout controls return their terminal snapshot in-band.
  # They must not add a diagnostic self-probe after the measured workload.
  if [[ "$name" == "coalesced-bridge" || "$name" == "timeout-retry" ]]; then
    printf '0\n'
    return
  fi
  # Forced stale controls take their terminal snapshot from the marked
  # workload response, so they do not issue the ordinary diagnostic self probe.
  if [[ "$name" != "w3c-fault" && "$diagnostics_enabled" == "true" ]] &&
    ! is_w3c_stale_scenario "$name"; then
    count=1
  fi
  printf '%d\n' "$count"
}

scenario_bridge_missing_count() {
  local -r name="$1"
  local -r transport="$2"

	printf '0\n'
}

concurrency_overlap_reconciliation() {
	local -r input="$1"
	local expected="$2"

	bounded_evidence_file \
		"$input" \
		"$SCENARIO_RECONCILIATION_MAX_BYTES" \
		"$SCENARIO_RECONCILIATION_MAX_LINES" || return 1
	expected="$(bounded_decimal "$expected" 64 false)" || return 1
	((expected >= 2)) || return 1
	jq -ce --argjson expected "$expected" '
		def positive_integer:
			type == "number" and floor == . and . >= 1 and . <= 9007199254740991;
		. as $result |
		if
			$result.status == "passed" and
			$result.scenario == "concurrency" and
			$result.request_count == $expected and
			($result.connection_evidence | type == "object") and
			($result.cases | type == "array" and length == $expected)
		then
			$result.connection_evidence as $e |
			($result.cases | map(.request)) as $requests |
			($result.cases | map(.response)) as $responses |
			($requests | map(.concurrency_batch)) as $request_batches |
			($request_batches[0]) as $batch |
			($responses | map(.backend_worker_id)) as $workers |
			($responses | map(.backend_connection_id)) as $connections |
			($responses | map(.concurrency_arrival)) as $arrivals |
			($responses | map(.concurrency_release)) as $releases |
			if
				$e.frontend_connections == $expected and
				$e.frontend_protocol == "HTTP/1.1" and
				$e.distinct_backend_workers == $expected and
				$e.distinct_concurrency_arrivals == $expected and
				$e.concurrency_participants == $expected and
				$e.concurrency_max_active == $expected and
				($e.concurrency_release | positive_integer) and
				($batch | type == "string" and test("^c[0-9a-f]{16}$")) and
				($request_batches | unique | length == 1) and
				all($requests[];
					type == "object" and
					.concurrency_batch == $batch and
					.concurrency_expected == $expected) and
				($workers | all(.[]; positive_integer)) and
				($workers | unique | length == $expected) and
				($connections | all(.[]; positive_integer)) and
				($connections | unique | length >= 2) and
				($arrivals | all(.[]; positive_integer)) and
				($arrivals | sort == [range(1; $expected + 1)]) and
				($releases | all(.[]; . == $e.concurrency_release)) and
				all($responses[];
					type == "object" and
					.concurrency_batch == $batch and
					.concurrency_participants == $expected and
					.concurrency_max_active == $expected)
			then $e else error("invalid concurrency overlap evidence") end
		else error("missing concurrency overlap evidence") end
	' "$input"
}

coalesced_bridge_reconciliation() {
  local -r input="$1"

  bounded_evidence_file \
    "$input" \
    "$SCENARIO_RECONCILIATION_MAX_BYTES" \
    "$SCENARIO_RECONCILIATION_MAX_LINES" || return 1
  jq -ce '
    def count: type == "number" and floor == . and . >= 0 and . <= 2;
    def positive_bytes: type == "number" and floor == . and . >= 1 and . <= 8192;
    . as $result |
    if
      $result.status == "passed" and
      $result.scenario == "coalesced-bridge" and
      $result.request_count == 2 and
      ($result.coalesced_bridge_correlation | type == "object")
    then
      $result.coalesced_bridge_correlation as $correlation |
      if
        ($correlation.exact_hit_count | count) and
        ($correlation.explicit_root_count | count) and
        ($correlation.wrong_parent_count | count) and
        ($correlation.unresolved_count | count) and
		$correlation.outcome == "receive_ambiguous" and
		$correlation.exact_hit_count == 0 and
		$correlation.explicit_root_count == 2 and
        $correlation.wrong_parent_count == 0 and
        $correlation.unresolved_count == 0 and
		$correlation.source_client_operations == 1 and
		$correlation.source_client_marker == "absent" and
		$correlation.apache_trigger_chain_proven == true and
		$correlation.source_operation_chain_proven == true and
		($correlation.source_plaintext_write_bytes | positive_bytes) and
		$correlation.tls_read_delta == 1 and
		$correlation.tls_bytes_delta == $correlation.source_plaintext_write_bytes and
		$correlation.take_missing_delta == 2 and
		$correlation.discard_total_delta == 1 and
		$correlation.discard_ambiguous_delta == 1
      then $correlation else error("invalid coalesced bridge correlation") end
    else error("missing coalesced bridge correlation") end
  ' "$input"
}

tls_boundary_reconciliation() {
  local -r input="$1"

  bounded_evidence_file \
    "$input" \
    "$SCENARIO_RECONCILIATION_MAX_BYTES" \
    "$SCENARIO_RECONCILIATION_MAX_LINES" || return 1
  jq -sce '
    def count: type == "number" and floor == . and . >= 0 and . <= 3;
    def positive_bytes:
      type == "number" and floor == . and . >= 1 and . <= 73728;
    def positive_bounded:
      type == "number" and floor == . and . >= 1 and . <= 32;
    def trace_id:
      type == "string" and
      test("^[0-9a-f]{32}$") and . != "00000000000000000000000000000000";
    def span_id:
      type == "string" and
      test("^[0-9a-f]{16}$") and . != "0000000000000000";
    def marker($index):
      type == "string" and
      test("^tls-boundary-0" + ($index | tostring) + "-[0-9a-f]{16}$");
    def common_row($index; $mode; $sequence; $phase; $shape):
      type == "object" and
      (.marker | marker($index)) and
      .mode == $mode and
      .sequence == $sequence and
      .evidence_phase == $phase and
      .delivery_shape == $shape and
      (.trace_id | trace_id) and
      (.apache_client_span_id | span_id) and
      (.java_server_span_id | span_id) and
      (.java_parent_span_id | span_id) and
      .java_parent_span_id == .apache_client_span_id and
      .java_server_span_id != .apache_client_span_id and
      .exact_parent == true and
      .same_request_evidence == true and
      (.request_bytes | positive_bytes) and
      (.tls_application_record_count | positive_bounded) and
      .tls_application_record_count >= 2 and
      (.decrypted_callback_count | positive_bounded) and
      .decrypted_callback_count >= 2 and
      .decrypted_callback_count == .tls_application_record_count and
      (.header_decrypted_callback_count | positive_bounded) and
      .header_decrypted_callback_count >= 2 and
      .header_decrypted_callback_count <= .decrypted_callback_count and
      (.parser_callback_count | positive_bounded) and
      (.parser_bytes | positive_bytes) and
      .parser_bytes == .request_bytes;
    if length != 1 then error("expected exactly one TLS boundary result") else .[0] end |
    . as $result |
    if
      $result.status == "passed" and
      $result.scenario == "tls-boundary" and
      $result.request_count == 3 and
      ($result.tls_boundary_correlation | type == "object")
    then
      $result.tls_boundary_correlation as $correlation |
      if
        ($correlation.exact_parent_count | count) and
        ($correlation.wrong_parent_count | count) and
        ($correlation.unresolved_count | count) and
        ($correlation.same_request_evidence_count | count) and
        $correlation.exact_parent_count == 3 and
        $correlation.wrong_parent_count == 0 and
        $correlation.unresolved_count == 0 and
        $correlation.same_request_evidence_count == 3 and
        ($correlation.requests | type == "array" and length == 3) and
        ($correlation.requests |
          map([
            .trace_id + "/" + .apache_client_span_id,
            .trace_id + "/" + .java_server_span_id
          ]) | add | unique | length == 6) and
        ($correlation.requests[0] |
          common_row(0; "split"; 1; "final"; "split") and
          .parser_callback_count == .decrypted_callback_count) and
        ($correlation.requests[1] |
          common_row(1; "coalesced"; 1; "partial"; "serialized_proxy_fallback") and
          .parser_callback_count == 1) and
        ($correlation.requests[2] |
          common_row(2; "coalesced"; 2; "final"; "serialized_proxy_fallback") and
          .parser_callback_count == 1)
      then $correlation else error("invalid TLS boundary correlation") end
    else error("missing TLS boundary correlation") end
  ' "$input"
}

timeout_cancellation_reconciliation() {
  local -r input="$1"

  bounded_evidence_file \
    "$input" \
    "$SCENARIO_RECONCILIATION_MAX_BYTES" \
    "$SCENARIO_RECONCILIATION_MAX_LINES" || return 1
  jq -ce '
    def fixed_reason:
      . == "missing" or . == "stale" or . == "unsupported" or
      . == "malformed" or . == "version_mismatch" or . == "ambiguous" or
      . == "unauthorized" or . == "already_consumed" or . == "timeout" or
      . == "overload" or . == "transport_error" or . == "disabled";
    . as $result |
    if
      $result.status == "passed" and
      $result.scenario == "timeout-retry" and
      ($result.faults | type == "array" and length == 1) and
      ($result.faults[0] | type == "object") and
      $result.faults[0].kind == "client-timeout" and
      $result.faults[0].outcome == "deadline-exceeded-as-expected" and
      ($result.faults[0].marker | type == "string" and test("^timeout-retry-cancelled-[0-9]+$")) and
      ($result.faults[0].parent_outcome == "exact" or
       $result.faults[0].parent_outcome == "missing" or
       $result.faults[0].parent_outcome == "reason_coded_drop") and
      ($result.faults[0].drop_reasons | type == "array" and all(.[]; type == "string" and fixed_reason)) and
      (($result.faults[0].parent_outcome == "reason_coded_drop" and
        ($result.faults[0].drop_reasons | length == 1)) or
       (($result.faults[0].parent_outcome == "exact" or
         $result.faults[0].parent_outcome == "missing") and
        ($result.faults[0].drop_reasons | length == 0)))
    then $result.faults[0] else error("invalid timeout cancellation reconciliation") end
  ' "$input"
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

bounded_evidence_file() {
  local -r input="$1"
  local -r maximum_bytes="$2"
  local -r maximum_lines="$3"
  local size=""

  [[ -f "$input" && ! -L "$input" ]] || return 1
  bounded_decimal "$maximum_bytes" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  bounded_decimal "$maximum_lines" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  size="$(stat -c '%s' -- "$input")" || return 1
  bounded_decimal "$size" "$maximum_bytes" true >/dev/null || return 1
  LC_ALL=C awk -v maximum="$maximum_lines" '
    NR > maximum { exit 1 }
  ' "$input"
}

retain_bounded_evidence_prefix() {
  local -r input="$1"
  local -r maximum_bytes="$2"
  local bounded=""
  local status=0

  [[ -f "$input" && ! -L "$input" ]] || return 1
  bounded_decimal "$maximum_bytes" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  bounded="$(mktemp "$input.bounded.XXXXXX")" || return 1
  if LC_ALL=C head -c "$maximum_bytes" -- "$input" >"$bounded" && \
    chmod 0644 "$bounded" && mv -f -- "$bounded" "$input"; then
    return 0
  else
    status=$?
  fi
  rm -f -- "$bounded" || true
  return "$status"
}

retain_bounded_evidence_limits() {
  local -r input="$1"
  local -r maximum_bytes="$2"
  local -r maximum_lines="$3"
  local line_bounded=""
  local bounded=""
  local status=0

  [[ -f "$input" && ! -L "$input" ]] || return 1
  bounded_decimal "$maximum_bytes" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  bounded_decimal "$maximum_lines" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  line_bounded="$(mktemp "$input.lines.XXXXXX")" || return 1
  bounded="$(mktemp "$input.bounded.XXXXXX")" || {
    status=$?
    rm -f -- "$line_bounded" || true
    return "$status"
  }
  if LC_ALL=C head -n "$maximum_lines" -- "$input" >"$line_bounded" && \
    LC_ALL=C head -c "$maximum_bytes" -- "$line_bounded" >"$bounded" && \
    chmod 0644 "$bounded" && mv -f -- "$bounded" "$input"; then
    rm -f -- "$line_bounded" || return $?
    return 0
  else
    status=$?
  fi
  rm -f -- "$line_bounded" "$bounded" || true
  return "$status"
}

pressure_result_record() {
  local -r input="$1"
  local -a records=()

  bounded_evidence_file \
    "$input" "$PRESSURE_RESULT_MAX_BYTES" "$PRESSURE_RESULT_MAX_LINES" || return 1
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
      pattern='^\{"status":"passed","mode":"prepare","map_id":'"$decimal"',"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":'"$decimal"',"process_map_id":'"$decimal"',"process_pid":'"$decimal"',"process_namespace":'"$decimal"',"token_base":'"$decimal"',"touched":0\}$'
      ;;
    fill)
      pattern='^\{"status":"passed","mode":"fill","map_id":'"$decimal"',"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":'"$decimal"',"process_map_id":'"$decimal"',"process_pid":'"$decimal"',"process_namespace":'"$decimal"',"token_base":'"$decimal"',"touched":'"$decimal"',"capacity_rejected_entries":'"$decimal"',"verified_present_entries":'"$decimal"'\}$'
      ;;
    cleanup)
      pattern='^\{"status":"passed","mode":"cleanup","map_id":'"$decimal"',"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":'"$decimal"',"process_map_id":0,"process_pid":'"$decimal"',"process_namespace":'"$decimal"',"token_base":'"$decimal"',"touched":'"$decimal"',"cleanup_verified":true,"verified_absent_entries":'"$decimal"'\}$'
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

run_receive_cursor_map_helper() {
  local -r output="$1"
  local -r stderr_output="$2"
  local -r timeout_seconds="$3"
  local command_status=0
  local evidence_status=0
  local replay_status=0
  shift 3

  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || {
    log_error "receive-cursor map helper timeout must be a positive integer"
    return 2
  }
  if run_bounded "$timeout_seconds" \
    "${COMPOSE[@]}" run --rm --no-deps --no-TTY map-state \
      "$@" >"$output" 2>"$stderr_output"; then
    command_status=0
  else
    command_status=$?
  fi
  if ! bounded_evidence_file \
    "$output" \
    "$RECEIVE_CURSOR_HELPER_STDOUT_MAX_BYTES" \
    "$RECEIVE_CURSOR_HELPER_STDOUT_MAX_LINES"; then
    log_error "receive-cursor map helper stdout exceeded its evidence bounds"
    retain_bounded_evidence_prefix \
      "$output" "$RECEIVE_CURSOR_HELPER_STDOUT_MAX_BYTES" || return 1
    evidence_status=1
  fi
  if ! bounded_evidence_file \
    "$stderr_output" \
    "$RECEIVE_CURSOR_HELPER_STDERR_MAX_BYTES" \
    "$RECEIVE_CURSOR_HELPER_STDERR_MAX_LINES"; then
    log_error "receive-cursor map helper stderr exceeded its evidence bounds"
    retain_bounded_evidence_prefix \
      "$stderr_output" "$RECEIVE_CURSOR_HELPER_STDERR_MAX_BYTES" || return 1
    evidence_status=1
  fi
  if ((evidence_status != 0)); then
    if ((command_status != 0)); then
      return "$command_status"
    fi
    return "$evidence_status"
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

receive_cursor_map_result_has_contract() {
  local -r input="$1"
  local -r decimal='(0|[1-9][0-9]*)'
  local record=""
  local pattern=""

  record="$(pressure_result_record "$input")" || return 1
  pattern='^\{"status":"passed","cursor_map_id":'"$decimal"',"cursor_map_name":"jrp_recv_cur","cursor_kernel_name":"jrp_recv_cur","cursor_map_type":"Hash","cursor_key_size":8,"cursor_value_size":56,"cursor_max_entries":10000,"cursor_entries":'"$decimal"',"guard_map_id":'"$decimal"',"guard_map_name":"jrp_recv_guard","guard_kernel_name":"jrp_recv_guard","guard_map_type":"Hash","guard_key_size":8,"guard_value_size":56,"guard_max_entries":10000,"guard_entries":'"$decimal"'\}$'
  [[ "$record" =~ $pattern ]]
}

record_receive_cursor_map_status() {
  local -r label="$1"
  local -r status="$2"
  local -r reason="$3"
  local cursor_final_entries="$4"
  local guard_final_entries="$5"
  local -r attempts="$6"
  local -r status_output="$RESULT_DIR/receive-cursor-map-$label-status.json"
  local cursor_final_json="null"
  local guard_final_json="null"

  if [[ -n "$cursor_final_entries" ]]; then
    cursor_final_entries="$(bounded_decimal \
      "$cursor_final_entries" "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" true)" || return 1
    cursor_final_json="$cursor_final_entries"
  fi
  if [[ -n "$guard_final_entries" ]]; then
    guard_final_entries="$(bounded_decimal \
      "$guard_final_entries" "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" true)" || return 1
    guard_final_json="$guard_final_entries"
  fi
  bounded_decimal "$attempts" "$MAX_SHELL_INTEGER" true >/dev/null || return 1
  [[ "$status" == "passed" || "$status" == "failed" ]] || return 1
  [[ "$reason" =~ ^[a-z-]+$ ]] || return 1
  RECEIVE_CURSOR_MAP_STATUS_JSON="$(printf \
    '{"status":"%s","reason":"%s","cursor_map_id":%s,"guard_map_id":%s,"cursor_baseline_entries":%s,"guard_baseline_entries":%s,"cursor_final_entries":%s,"guard_final_entries":%s,"required_consecutive_samples":%d,"attempts":%s,"before":"receive-cursor-map-%s-before.json","after":"receive-cursor-map-%s-after.json","samples":"receive-cursor-map-%s-recovery-samples.log"}' \
    "$status" \
    "$reason" \
    "${RECEIVE_CURSOR_MAP_ID:-0}" \
    "${RECEIVE_GUARD_MAP_ID:-0}" \
    "${RECEIVE_CURSOR_MAP_BASELINE_ENTRIES:-0}" \
    "${RECEIVE_GUARD_MAP_BASELINE_ENTRIES:-0}" \
    "$cursor_final_json" \
    "$guard_final_json" \
    "$RECEIVE_CURSOR_MAP_RECOVERY_CONSECUTIVE_SAMPLES" \
    "$attempts" \
    "$label" \
    "$label" \
    "$label")" || return 1
  printf '%s\n' "$RECEIVE_CURSOR_MAP_STATUS_JSON" >"$status_output"
}

capture_receive_cursor_map_baseline() {
  local -r label="$1"
  local -r output="$RESULT_DIR/receive-cursor-map-$label-before.json"
  local -r stderr_output="$RESULT_DIR/receive-cursor-map-$label-before.stderr.log"
  local cursor_map_id=""
  local guard_map_id=""
  local cursor_max_entries=""
  local guard_max_entries=""
  local cursor_entries=""
  local guard_entries=""

  RECEIVE_CURSOR_MAP_ID=""
  RECEIVE_GUARD_MAP_ID=""
  RECEIVE_CURSOR_MAP_BASELINE_ENTRIES=""
  RECEIVE_GUARD_MAP_BASELINE_ENTRIES=""
  RECEIVE_CURSOR_MAP_STATUS_JSON="null"
  if ! run_receive_cursor_map_helper \
    "$output" \
    "$stderr_output" \
    "$RECEIVE_CURSOR_MAP_HELPER_TIMEOUT_SECONDS"; then
    record_receive_cursor_map_status "$label" failed baseline-command "" "" 0 || true
    return 1
  fi
  if ! receive_cursor_map_result_has_contract "$output"; then
    log_error "receive-cursor map baseline does not match the exact evidence contract"
    record_receive_cursor_map_status "$label" failed baseline-contract "" "" 0 || true
    return 1
  fi
  if ! cursor_map_id="$(pressure_result_bounded_uint \
    "$output" cursor_map_id "$MAX_UINT32_DECIMAL" false)" || \
    ! guard_map_id="$(pressure_result_bounded_uint \
      "$output" guard_map_id "$MAX_UINT32_DECIMAL" false)" || \
    ! cursor_max_entries="$(pressure_result_bounded_uint \
      "$output" cursor_max_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" false)" || \
    ! guard_max_entries="$(pressure_result_bounded_uint \
      "$output" guard_max_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" false)" || \
    ! cursor_entries="$(pressure_result_bounded_uint \
      "$output" cursor_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" true)" || \
    ! guard_entries="$(pressure_result_bounded_uint \
      "$output" guard_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" true)"; then
    log_error "receive coordination-map baseline contains invalid bounded fields"
    record_receive_cursor_map_status "$label" failed baseline-fields "" "" 0 || true
    return 1
  fi
  if [[ "$cursor_map_id" == "$guard_map_id" || \
    "$cursor_max_entries" != "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" || \
    "$guard_max_entries" != "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" ]]; then
    log_error "receive coordination-map baseline reported an unexpected identity or capacity"
    record_receive_cursor_map_status "$label" failed baseline-identity "" "" 0 || true
    return 1
  fi
  RECEIVE_CURSOR_MAP_ID="$cursor_map_id"
  RECEIVE_GUARD_MAP_ID="$guard_map_id"
  RECEIVE_CURSOR_MAP_BASELINE_ENTRIES="$cursor_entries"
  RECEIVE_GUARD_MAP_BASELINE_ENTRIES="$guard_entries"
  if ! record_receive_cursor_map_status \
    "$label" failed recovery-pending "" "" 0; then
    log_error "could not persist the receive coordination-map recovery gate"
    return 1
  fi
}

wait_for_receive_cursor_map_recovery() {
  local -r label="$1"
  local -r samples_log="$RESULT_DIR/receive-cursor-map-$label-recovery-samples.log"
  local -r canonical_after="$RESULT_DIR/receive-cursor-map-$label-after.json"
  local output=""
  local stderr_output=""
  local cursor_map_id=""
  local guard_map_id=""
  local cursor_max_entries=""
  local guard_max_entries=""
  local cursor_entries=""
  local guard_entries=""
  local helper_timeout=""
  local matched=false
  local -i attempts=0
  local -i consecutive_matches=0
  local -i deadline=0

  if ! bounded_decimal \
    "$RECEIVE_CURSOR_MAP_ID" "$MAX_UINT32_DECIMAL" false >/dev/null || \
    ! bounded_decimal \
      "$RECEIVE_GUARD_MAP_ID" "$MAX_UINT32_DECIMAL" false >/dev/null || \
    ! bounded_decimal \
      "$RECEIVE_CURSOR_MAP_BASELINE_ENTRIES" \
      "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" \
      true >/dev/null || \
    ! bounded_decimal \
      "$RECEIVE_GUARD_MAP_BASELINE_ENTRIES" \
      "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" \
      true >/dev/null; then
    log_error "receive coordination-map recovery has no exact baseline identity"
    record_receive_cursor_map_status "$label" failed missing-baseline "" "" 0 || true
    return 1
  fi
  : >"$samples_log" || return 1
  deadline="$((SECONDS + RECEIVE_CURSOR_MAP_RECOVERY_TIMEOUT_SECONDS))"
  while ((SECONDS < deadline)); do
    ((attempts += 1))
    printf -v output \
      '%s/receive-cursor-map-%s-recovery-attempt-%02d.json' \
      "$RESULT_DIR" "$label" "$attempts"
    printf -v stderr_output \
      '%s/receive-cursor-map-%s-recovery-attempt-%02d.stderr.log' \
      "$RESULT_DIR" "$label" "$attempts"
    cursor_map_id=""
    guard_map_id=""
    cursor_max_entries=""
    guard_max_entries=""
    cursor_entries=""
    guard_entries=""
    helper_timeout="$(remaining_timeout_seconds \
      "$deadline" "$RECEIVE_CURSOR_MAP_HELPER_TIMEOUT_SECONDS")" || break
    matched=false
    if run_receive_cursor_map_helper \
      "$output" \
      "$stderr_output" \
      "$helper_timeout" \
      --cursor-map-id "$RECEIVE_CURSOR_MAP_ID" \
      --guard-map-id "$RECEIVE_GUARD_MAP_ID" \
      --expected-max-entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" && \
      receive_cursor_map_result_has_contract "$output"; then
      cursor_map_id="$(pressure_result_bounded_uint \
        "$output" cursor_map_id "$MAX_UINT32_DECIMAL" false)" || cursor_map_id=""
      guard_map_id="$(pressure_result_bounded_uint \
        "$output" guard_map_id "$MAX_UINT32_DECIMAL" false)" || guard_map_id=""
      cursor_max_entries="$(pressure_result_bounded_uint \
        "$output" cursor_max_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" false)" || \
        cursor_max_entries=""
      guard_max_entries="$(pressure_result_bounded_uint \
        "$output" guard_max_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" false)" || \
        guard_max_entries=""
      cursor_entries="$(pressure_result_bounded_uint \
        "$output" cursor_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" true)" || \
        cursor_entries=""
      guard_entries="$(pressure_result_bounded_uint \
        "$output" guard_entries "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" true)" || \
        guard_entries=""
      if [[ "$cursor_map_id" == "$RECEIVE_CURSOR_MAP_ID" && \
        "$guard_map_id" == "$RECEIVE_GUARD_MAP_ID" && \
        "$cursor_max_entries" == "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" && \
        "$guard_max_entries" == "$RECEIVE_CURSOR_MAP_MAX_ENTRIES" && \
        -n "$cursor_entries" && -n "$guard_entries" ]] && \
        ((cursor_entries == RECEIVE_CURSOR_MAP_BASELINE_ENTRIES &&
          guard_entries == RECEIVE_GUARD_MAP_BASELINE_ENTRIES)); then
        matched=true
      fi
    fi
    if [[ "$matched" == "true" ]]; then
      ((consecutive_matches += 1))
    else
      consecutive_matches=0
    fi
    printf 'attempt=%d observed_at=%(%Y-%m-%dT%H:%M:%SZ)T cursor_map_id=%s cursor_entries=%s guard_map_id=%s guard_entries=%s matched=%s consecutive=%d\n' \
      "$attempts" \
      -1 \
      "${cursor_map_id:-unavailable}" \
      "${cursor_entries:-unavailable}" \
      "${guard_map_id:-unavailable}" \
      "${guard_entries:-unavailable}" \
      "$matched" \
      "$consecutive_matches" >>"$samples_log" || return 1
    if ((consecutive_matches >= RECEIVE_CURSOR_MAP_RECOVERY_CONSECUTIVE_SAMPLES)); then
      if ! install -m 0644 "$output" "$canonical_after"; then
        record_receive_cursor_map_status \
          "$label" failed artifact-write "$cursor_entries" "$guard_entries" "$attempts" || true
        return 1
      fi
      record_receive_cursor_map_status \
        "$label" passed steady-baseline "$cursor_entries" "$guard_entries" "$attempts"
      return $?
    fi
    if ((SECONDS < deadline)); then
      sleep 1
    fi
  done
  log_error "receive coordination maps did not return to their steady baselines, cursor_map_id=$RECEIVE_CURSOR_MAP_ID cursor_baseline=$RECEIVE_CURSOR_MAP_BASELINE_ENTRIES cursor_actual=${cursor_entries:-unavailable} guard_map_id=$RECEIVE_GUARD_MAP_ID guard_baseline=$RECEIVE_GUARD_MAP_BASELINE_ENTRIES guard_actual=${guard_entries:-unavailable} attempts=$attempts"
  record_receive_cursor_map_status \
    "$label" failed recovery-timeout "$cursor_entries" "$guard_entries" "$attempts" || true
  return 1
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

resolve_map_pressure_java_identity() {
  local java_container=""
  local inspection_before=""
  local inspection_after=""
  local inspected_container=""
  local host_pid=""
  local started_at=""
  local identity=""
  local process_pid=""
  local process_namespace=""
  local extra=""

  java_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$java_container" ]] || {
    log_error "Java backend container identity is unavailable for map pressure"
    return 1
  }
  inspection_before="$(run_bounded 10 docker inspect \
    --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$java_container")" || return $?
  read -r inspected_container host_pid started_at extra <<<"$inspection_before" || return $?
  [[ "$inspected_container" == "$java_container" && "$host_pid" =~ ^[1-9][0-9]*$ && \
    -n "$started_at" && "$started_at" != "0001-01-01T00:00:00Z" && -z "$extra" ]] || return 1
  identity="$(resolve_container_process_namespace_identity "$java_container")" || return $?
  read -r process_pid process_namespace extra <<<"$identity" || return $?
  [[ -z "$extra" ]] || return 1
  inspection_after="$(run_bounded 10 docker inspect \
    --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$java_container")" || return $?
  [[ "$inspection_after" == "$inspection_before" ]] || {
    log_error "the controlled JVM changed while resolving map-pressure identity"
    return 1
  }
  printf '%s %s %s %s %s\n' \
    "$inspected_container" \
    "$host_pid" \
    "$started_at" \
    "$process_pid" \
    "$process_namespace"
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
  local fill_capacity_rejected=""
  local fill_verified_present=""
  local prepare_status=0
  local fill_status=0
  local start_status=0
  local java_identity=""
  local java_container_id=""
  local java_host_pid=""
  local java_started_at=""
  local java_process_pid=""
  local java_process_namespace=""
  local confirmed_java_identity=""
  local inspection_extra=""

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
  PRESSURE_CAPACITY_REJECTED_ENTRIES=""
  PRESSURE_VERIFIED_PRESENT_ENTRIES=""
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
  java_identity="$(resolve_map_pressure_java_identity)" || return $?
  read -r \
    java_container_id \
    java_host_pid \
    java_started_at \
    java_process_pid \
    java_process_namespace \
    inspection_extra <<<"$java_identity" || return $?
  [[ "$java_container_id" =~ ^[a-f0-9]{64}$ && \
    "$java_host_pid" =~ ^[1-9][0-9]*$ && \
    -n "$java_started_at" && \
    "$java_process_pid" =~ ^[1-9][0-9]*$ && \
    "$java_process_namespace" =~ ^[1-9][0-9]*$ && \
    -z "$inspection_extra" ]] || return 1
  prepare_output="$RESULT_DIR/map-pressure-$label-prepare.json"
  prepare_stderr="$RESULT_DIR/map-pressure-$label-prepare.stderr.log"
  if run_map_pressure_helper \
    "$prepare_output" \
    "$prepare_stderr" \
    "$PRESSURE_HELPER_TIMEOUT_SECONDS" \
    --process-pid "$java_process_pid" \
    --process-namespace "$java_process_namespace" \
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
  confirmed_java_identity="$(resolve_map_pressure_java_identity)" || return $?
  [[ "$confirmed_java_identity" == "$java_identity" ]] || {
    log_error "the controlled JVM changed during map-pressure preparation"
    return 1
  }
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
    "$prepare_map_id")" || {
    log_error "pre-fill handoff-claim occupancy is unavailable for the prepared map"
    return 1
  }
  baseline_map_id="${resolved%% *}"
  baseline_entries="${resolved#* }"
  baseline_entries="$(bounded_decimal \
    "$baseline_entries" "$PRESSURE_MAX_ENTRIES" true)" || {
    log_error "pre-fill handoff-claim occupancy is invalid"
    return 1
  }

  if [[ "$baseline_map_id" != "$prepare_map_id" ]] || \
    [[ "$prepare_process_pid" != "$java_process_pid" ]] || \
    [[ "$prepare_process_namespace" != "$java_process_namespace" ]] || \
    ((baseline_entries >= prepare_max_entries)); then
    log_error "map-pressure prepare did not preserve the scoped map identity and capacity"
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
    "$fill_output" touched "$PRESSURE_MAP_MAX_ENTRIES" false)" || fill_touched=""
  fill_capacity_rejected="$(pressure_result_bounded_uint \
    "$fill_output" capacity_rejected_entries 1 false)" || \
    fill_capacity_rejected=""
  fill_verified_present="$(pressure_result_bounded_uint \
    "$fill_output" verified_present_entries "$PRESSURE_MAX_ENTRIES" false)" || \
    fill_verified_present=""
  if [[ "$fill_map_id" != "$PRESSURE_MAP_ID" || \
    "$fill_max_entries" != "$PRESSURE_MAP_MAX_ENTRIES" || \
    "$fill_process_map_id" != "$PRESSURE_PROCESS_MAP_ID" || \
    "$fill_process_pid" != "$PRESSURE_PROCESS_PID" || \
    "$fill_process_namespace" != "$PRESSURE_PROCESS_NAMESPACE" || \
    "$fill_token_base" != "$PRESSURE_TOKEN_BASE" || \
    "$fill_capacity_rejected" != "1" || \
    "$fill_verified_present" != "$fill_touched" ]] || \
    ((fill_touched == 0 || fill_touched > PRESSURE_MAP_MAX_ENTRIES)); then
    log_error "map-pressure fill did not echo its prepared identity or prove non-evicting capacity rejection"
    cleanup_map_pressure_with_retries || true
    return 1
  fi
  PRESSURE_TOUCHED_ENTRIES="$fill_touched"
  PRESSURE_CAPACITY_REJECTED_ENTRIES="$fill_capacity_rejected"
  PRESSURE_VERIFIED_PRESENT_ENTRIES="$fill_verified_present"
  log_info "map pressure armed map_id=$PRESSURE_MAP_ID baseline=$PRESSURE_MAP_BASELINE_ENTRIES max_entries=$PRESSURE_MAP_MAX_ENTRIES touched=$PRESSURE_TOUCHED_ENTRIES capacity_rejected=$PRESSURE_CAPACITY_REJECTED_ENTRIES verified_present=$PRESSURE_VERIFIED_PRESENT_ENTRIES"

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
      "$cleanup_output" touched "$PRESSURE_MAP_MAX_ENTRIES" true)" || \
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
      { [[ -z "$PRESSURE_TOUCHED_ENTRIES" ]] || \
        ((cleanup_touched <= PRESSURE_TOUCHED_ENTRIES)); }; then
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
  local -r retrieval_mode="${5:-normal}"
  local -r assertion_mode="${6:-}"
  local run_number=0
  local label=""
  local output=""
  local stderr_output=""
  local before_phase=""
  local after_phase=""
  local before_diagnostics=""
  local after_diagnostics=""
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
  local expected_bridge_lifecycle=0
  local expected_bridge_stage=0
  local expected_bridge_missing=0
  local expected_bridge_stale=0
  local expected_bridge_handoffs=0
  local include_ambiguous_candidates=false
  local expected_java_missing=0
  local pressure_hits=0
  local pressure_roots=0
  local pressure_wrong=0
  local pressure_unresolved=0
  local pressure_trace_json="null"
  local pressure_bridge_json="null"
  local pressure_java_json="null"
  local pressure_status_json="null"
  local scenario_reconciliation_json="null"
  local receive_cursor_map_status_json="null"
  local pressure_unix_already_consumed_reconciled=false
  local coalesced_outcome=""
  local timeout_parent_outcome=""
  local timeout_drop_reason=""
  local diagnostic_valid_takes=0
  local expected_fault_status=""
  local expected_fault_count=0
  local fault_diagnostics_after=""
  local fault_diagnostics_delta=""
  local before_diagnostics_status_json="null"
  local after_diagnostics_status_json="null"
  local obi_metric_evidence_json="null"
  local obi_metric_pair_reference=""
  local obi_metric_boundary_id=""
  local obi_metric_boundary_ids_json="[]"
  local owns_obi_metric_boundary=false
  local bridge_was_running=false
  local obi_was_running=false
  local controlled_bridge_was_running=false
  local fixture_status=0
  local scenario_status=0
  local metric_status=0
  local status_name="passed"
  local -a request_arguments=()
  local -a scenario_arguments=()

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
  [[ "$retrieval_mode" == "normal" || "$retrieval_mode" == "helper-unavailable" ]] || {
    log_error "scenario retrieval mode must be normal or helper-unavailable"
    return 1
  }
  [[ -z "$assertion_mode" || "$assertion_mode" == "disabled" || \
    "$assertion_mode" == "uninstrumented" ]] || {
    log_error "scenario assertion mode must be disabled or uninstrumented"
    return 1
  }
  if [[ -n "$assertion_mode" && "$name" != "concurrency" ]]; then
    log_error "an explicit assertion mode requires the concurrency workload"
    return 1
  fi
  if [[ "$fixture_mode" == "matching" && \
    ( "$name" != "w3c-match" || "$diagnostics_enabled" != "true" ) ]]; then
    log_error "the matching fixture requires the diagnostic w3c-match scenario"
    return 1
  fi
  if [[ "$retrieval_mode" == "helper-unavailable" && \
    ( "$fixture_mode" != "none" || "$diagnostics_enabled" != "false" ||
    ( "$name" != "helper-attach-failure" && "$name" != "w3c" ) ) ]]; then
    log_error "helper-unavailable retrieval requires a non-diagnostic helper-attach-failure or w3c scenario"
    return 1
  fi
  baseline_bridge_missing="$(
    scenario_bridge_missing_count "$name" "$SELECTED_TRANSPORT"
  )" || return $?
  baseline_java_missing="$(
    scenario_java_missing_count "$name" "$diagnostics_enabled"
  )" || return $?
  expected_requests="$(scenario_bridge_take_count "$name")" || return $?
  if [[ "$retrieval_mode" == "helper-unavailable" ]]; then
    expected_requests=1
    request_arguments=(--requests 1)
  elif [[ "$name" == "w3c-fault" ]]; then
    request_arguments=(
      --requests "$FAULT_REQUEST_COUNT"
      --fault-mode "$FAULT_MODE"
    )
  elif [[ "$name" == "tls-boundary" ]]; then
    request_arguments=(--requests 3)
  elif (( REQUEST_COUNT > 0 )); then
    request_arguments=(--requests "$REQUEST_COUNT")
  fi
  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    controlled_bridge_was_running=false
    scenario_status=0
    metric_status=0
    status_name="passed"
    expected_bridge_valid="$expected_requests"
    expected_bridge_lifecycle="$expected_requests"
    expected_bridge_stage="$expected_requests"
    expected_bridge_stale=0
    expected_bridge_handoffs=0
    if [[ "$name" == "tls-boundary" && \
      "$SELECTED_TRANSPORT" == "getsockopt" ]]; then
      expected_bridge_handoffs="$expected_requests"
    fi
    include_ambiguous_candidates=false
    if [[ "$retrieval_mode" == "helper-unavailable" ]]; then
      expected_bridge_valid=0
      expected_bridge_stage=0
      include_ambiguous_candidates=true
    fi
    if is_w3c_stale_scenario "$name"; then
      expected_bridge_valid=0
      expected_bridge_stale="$expected_requests"
    fi
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
    scenario_reconciliation_json="null"
    receive_cursor_map_status_json="null"
    pressure_unix_already_consumed_reconciled=false
    coalesced_outcome=""
    timeout_parent_outcome=""
    timeout_drop_reason=""
    diagnostic_valid_takes=0
    before_diagnostics_status_json="null"
    after_diagnostics_status_json="null"
    obi_metric_evidence_json="null"
    obi_metric_pair_reference=""
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
    obi_metric_boundary_id=""
    obi_metric_boundary_ids_json="[]"
    owns_obi_metric_boundary=false
    if obi_metric_boundary_index_is_initialized; then
      if obi_metric_boundary_id="$(active_obi_metric_boundary_id 2>/dev/null)"; then
        :
      else
        obi_metric_boundary_id="$label"
        begin_obi_metric_boundary "$obi_metric_boundary_id" || return $?
        owns_obi_metric_boundary=true
      fi
      obi_metric_boundary_ids_json="$(jq -cn \
        --arg boundary_id "$obi_metric_boundary_id" '[$boundary_id]')" || return 1
      if [[ "$OBI_RUNNING" == true ]]; then
        plan_obi_metric_pair_capture "$label" || return $?
      fi
    fi
    output="$RESULT_DIR/scenario-$label.json"
    stderr_output="$RESULT_DIR/scenario-$label.stderr.log"
    before_phase="$label-before"
    after_phase="$label-after"
    before_diagnostics="$RESULT_DIR/phases/$before_phase/java-diagnostics.txt"
    after_diagnostics="$RESULT_DIR/phases/$after_phase/java-diagnostics.txt"
    if [[ "$OBI_RUNNING" == false ]] &&
      obi_metric_pair_reference="$(
        active_stopped_obi_metric_pair_reference 2>/dev/null
      )" && [[ -n "$obi_metric_pair_reference" ]]; then
      if ! obi_metric_evidence_json="$(
        obi_metric_pair_evidence_json_from_reference "$obi_metric_pair_reference"
      )"; then
        log_error "could not retain the stopped OBI metric boundary in $label status"
        obi_metric_evidence_json="null"
        metric_status=1
      fi
    fi

    log_info "running $label scenario"
    if [[ "$fixture_mode" == "matching" ]]; then
      if start_matching_bridge "$label" "$expected_requests"; then
        controlled_bridge_was_running=true
      else
        fixture_status=$?
        scenario_status="$fixture_status"
      fi
    fi
    if [[ "$retrieval_mode" == "helper-unavailable" ]]; then
      if ! flush_bridge_metric_boundary "$label" 0 0; then
        metric_status=1
      fi
    elif is_w3c_stale_scenario "$name"; then
      if [[ "$diagnostics_enabled" == "true" ]] &&
        ! mkdir -p -- "$RESULT_DIR/phases/$before_phase"; then
        metric_status=1
      elif [[ "$diagnostics_enabled" == "true" ]] &&
        ! flush_bridge_metric_boundary "$label" 0 1 "$before_diagnostics"; then
        metric_status=1
      elif [[ "$diagnostics_enabled" == "false" ]] &&
        ! flush_bridge_metric_boundary "$label" 0 1; then
        metric_status=1
      fi
    elif ! flush_bridge_metric_boundary "$label"; then
      metric_status=1
    fi
    if [[ "$name" != "w3c-fault" && "$diagnostics_enabled" == "true" ]]; then
      if ! is_w3c_stale_scenario "$name" &&
        ! capture_java_diagnostics "$before_phase"; then
        metric_status=1
      fi
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
    elif ! capture_phase_evidence "$before_phase"; then
      metric_status=1
    fi
    if [[ "$name" == "tls-boundary" || "$name" == "coalesced-bridge" ]] && \
      ! capture_receive_cursor_map_baseline "$label"; then
      metric_status=1
    fi
    bridge_was_running="$BRIDGE_RUNNING"
    obi_was_running="$OBI_RUNNING"
    if [[ "$bridge_was_running" == "true" ]]; then
      before_success="$(bridge_success_total \
        "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
      before_stage="$(bridge_stage_total \
        "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
    fi
    if [[ "$name" == "pressure" ]]; then
      if start_map_pressure \
        "$label" \
        "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
        "$expected_requests"; then
        if ! capture_phase_evidence "$label-pressured"; then
          metric_status=1
        fi
      else
        scenario_status=$?
      fi
    fi
    if ((scenario_status == 0)); then
      scenario_arguments=(
        --scenario "$name"
        --expected-tls "$TLS_PROTOCOL"
        --seed "$SCENARIO_SEED"
        "${request_arguments[@]}"
        --timeout 75s
      )
      if scenario_uses_in_band_java_diagnostics "$name"; then
        if assert_sanitized_java_diagnostics "$before_diagnostics"; then
          scenario_arguments+=(
            --java-diagnostics-before "$(<"$before_diagnostics")"
          )
        else
          log_error "$label has no valid Java diagnostics baseline"
          scenario_status=1
        fi
      fi
      if [[ -n "$assertion_mode" ]]; then
        scenario_arguments+=(--assertion-mode "$assertion_mode")
      fi
      if ((scenario_status == 0)) && run_bounded "$SCENARIO_RUN_TIMEOUT_SECONDS" \
        "${COMPOSE[@]}" run --rm --no-deps --no-TTY scenario \
          "${scenario_arguments[@]}" \
          2> >(tee "$stderr_output" >&2) | tee "$output"; then
        scenario_status=0
      else
        scenario_status=$?
      fi
    fi
    if scenario_uses_in_band_java_diagnostics "$name"; then
      if ! mkdir -p -- "$RESULT_DIR/phases/$after_phase"; then
        metric_status=1
      elif ! extract_java_diagnostics_after "$output" "$after_diagnostics"; then
        log_error "could not extract in-band Java diagnostics for $label"
        metric_status=1
      elif ! write_java_diagnostics_delta \
        "$before_diagnostics" \
        "$after_diagnostics" \
        "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"; then
        log_error "could not compute in-band Java diagnostics for $label"
        metric_status=1
      else
        diagnostic_valid_takes="$(java_diagnostic_delta \
          "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" t_valid)" || {
          diagnostic_valid_takes=""
          metric_status=1
        }
      fi
    fi
	if ((scenario_status == 0)) && [[ "$name" == "concurrency" ]]; then
		if ! scenario_reconciliation_json="$(concurrency_overlap_reconciliation \
			"$output" "$expected_requests")"; then
			log_error "concurrency result did not retain exact worker and arrival evidence"
			scenario_reconciliation_json="null"
			scenario_status=1
		fi
	elif ((scenario_status == 0)) && [[ "$name" == "tls-boundary" ]]; then
		if ! scenario_reconciliation_json="$(tls_boundary_reconciliation "$output")"; then
			log_error "TLS boundary result did not bind exact parents to same-request record evidence"
			scenario_reconciliation_json="null"
			scenario_status=1
		fi
	elif ((scenario_status == 0)) && [[ "$name" == "coalesced-bridge" ]]; then
      if scenario_reconciliation_json="$(coalesced_bridge_reconciliation "$output")"; then
        coalesced_outcome="$(jq -er '.outcome' <<<"$scenario_reconciliation_json")" || {
          coalesced_outcome=""
          metric_status=1
        }
      else
		log_error "coalesced receive control did not prove one fail-closed ambiguity outcome"
        scenario_reconciliation_json="null"
        scenario_status=1
      fi
      case "$coalesced_outcome" in
		receive_ambiguous)
          expected_bridge_valid=0
          expected_bridge_stage=0
          ;;
      esac
    elif ((scenario_status == 0)) && [[ "$name" == "timeout-retry" ]]; then
      if scenario_reconciliation_json="$(timeout_cancellation_reconciliation "$output")"; then
        timeout_parent_outcome="$(jq -er '.parent_outcome' \
          <<<"$scenario_reconciliation_json")" || {
          timeout_parent_outcome=""
          metric_status=1
        }
        if [[ "$timeout_parent_outcome" == "reason_coded_drop" ]]; then
          timeout_drop_reason="$(jq -er \
            '.drop_reasons | if length == 1 then .[0] else error("expected one drop reason") end' \
            <<<"$scenario_reconciliation_json")" || {
            timeout_drop_reason=""
            metric_status=1
          }
        fi
      else
        log_error "timeout result did not retain one bounded cancellation outcome"
        scenario_reconciliation_json="null"
        scenario_status=1
      fi
      if [[ "$diagnostic_valid_takes" =~ ^[12]$ ]]; then
        expected_bridge_valid="$diagnostic_valid_takes"
        expected_bridge_stage="$diagnostic_valid_takes"
      else
        log_error "timeout result did not report one or two valid Java takes"
        metric_status=1
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
    if [[ ( "$name" == "tls-boundary" || "$name" == "coalesced-bridge" ) && \
      -n "$RECEIVE_CURSOR_MAP_ID" ]] && \
      ! wait_for_receive_cursor_map_recovery "$label"; then
      metric_status=1
    fi
    if [[ "$retrieval_mode" == "normal" ]] && ! is_w3c_stale_scenario "$name"; then
      case "$name" in
        coalesced-bridge)
		  # Go crypto/tls does not use the request-owned exact-prewrite path.
		  # This negative control therefore requires a zero native bridge
		  # lifecycle and a reason-coded ambiguity at the Java receive boundary.
          expected_bridge_lifecycle=0
          ;;
        timeout-retry)
          expected_bridge_lifecycle=2
          ;;
        *)
          expected_bridge_lifecycle="$expected_bridge_valid"
          expected_bridge_stage="$expected_bridge_valid"
          ;;
      esac
    fi
    if [[ "$bridge_was_running" == "true" ]]; then
      expected_success="$((before_success + expected_bridge_valid))"
      expected_stage="$((before_stage + expected_bridge_stage))"
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
    elif ! capture_phase_evidence "$after_phase"; then
      metric_status=1
    fi
    if [[ "$name" != "w3c-fault" && "$diagnostics_enabled" == "true" ]]; then
      if is_w3c_stale_scenario "$name" &&
        ! extract_java_diagnostics_after "$output" "$after_diagnostics"; then
        log_error "could not extract in-band Java diagnostics for $label"
        metric_status=1
      elif scenario_uses_in_band_java_diagnostics "$name" &&
        ! assert_sanitized_java_diagnostics "$after_diagnostics"; then
        log_error "in-band Java diagnostics became unavailable for $label"
        metric_status=1
      elif ! is_w3c_stale_scenario "$name" &&
        ! scenario_uses_in_band_java_diagnostics "$name" &&
        ! capture_java_diagnostics "$after_phase"; then
        metric_status=1
      fi
    fi
    if [[ "$name" == "w3c-fault" ]]; then
      fault_diagnostics_after="$RESULT_DIR/phases/$after_phase/java-diagnostics.txt"
      fault_diagnostics_delta="$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"
      if [[ -z "$W3C_FAULT_DIAGNOSTICS_PREVIOUS" ]]; then
        log_error "W3C fault diagnostics baseline is unavailable for $label"
        metric_status=1
      elif ! extract_fault_diagnostics_after "$output" "$fault_diagnostics_after"; then
        log_error "could not extract terminal W3C fault diagnostics for $label"
        metric_status=1
      elif ! write_java_diagnostics_delta \
        "$W3C_FAULT_DIAGNOSTICS_PREVIOUS" \
        "$fault_diagnostics_after" \
        "$fault_diagnostics_delta"; then
        log_error "could not compute chained W3C fault diagnostics for $label"
        metric_status=1
      elif ! assert_w3c_fault_diagnostics_delta \
        "$fault_diagnostics_delta" \
        "$FAULT_MODE" \
        "$FAULT_REQUEST_COUNT"; then
        log_error "W3C fault diagnostics were not exactly attributable for $label"
        metric_status=1
      else
        W3C_FAULT_DIAGNOSTICS_PREVIOUS="$fault_diagnostics_after"
      fi
    fi
    if [[ -f "$RESULT_DIR/phases/$before_phase/obi-identity.json" &&
      ! -L "$RESULT_DIR/phases/$before_phase/obi-identity.json" &&
      -f "$RESULT_DIR/phases/$after_phase/obi-identity.json" &&
      ! -L "$RESULT_DIR/phases/$after_phase/obi-identity.json" ]]; then
      if ! obi_metric_pair_reference="$(record_obi_metric_pair \
        "$label" "$before_phase" "$after_phase" same_process "$after_phase")"; then
        log_error "could not retain the bounded OBI metric pair for $label"
        metric_status=1
      elif ! obi_metric_evidence_json="$(
        obi_metric_pair_evidence_json_from_reference "$obi_metric_pair_reference"
      )"; then
        log_error "could not bind the bounded OBI metric pair into $label status"
        obi_metric_evidence_json="null"
        metric_status=1
      fi
    elif [[ "$obi_was_running" == true ]]; then
      log_error "could not bind the $label metric snapshots to one OBI process"
      metric_status=1
    fi
    if ! write_metrics_delta \
      "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
      "$RESULT_DIR/phases/$after_phase/obi-metrics.prom" \
      "$RESULT_DIR/phases/$after_phase/obi-metrics.delta"; then
      metric_status=1
    fi
    if [[ "$bridge_was_running" == "true" ]]; then
      if [[ "$name" == "coalesced-bridge" && -n "$coalesced_outcome" ]]; then
        if ! assert_coalesced_bridge_metric_delta \
          "$RESULT_DIR/phases/$after_phase/obi-metrics.delta" \
          "$SELECTED_TRANSPORT" \
          "$coalesced_outcome"; then
          metric_status=1
        fi
      elif [[ "$name" == "timeout-retry" && -n "$timeout_parent_outcome" ]]; then
        if ! assert_timeout_cancellation_metric_delta \
          "$RESULT_DIR/phases/$after_phase/obi-metrics.delta" \
          "$SELECTED_TRANSPORT" \
          "$timeout_parent_outcome" \
          "$diagnostic_valid_takes" \
          "$timeout_drop_reason"; then
          metric_status=1
        fi
      elif [[ "$name" == "pressure" && -n "$pressure_hits" &&
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
        if [[ "$SELECTED_TRANSPORT" == "unix" && "$pressure_roots" != "0" ]] && \
          pressure_unix_already_consumed_roots_are_reconciled \
            "$pressure_bridge_json" "$pressure_roots"; then
          pressure_unix_already_consumed_reconciled=true
        fi
      elif ! assert_bridge_metric_delta \
        "$RESULT_DIR/phases/$after_phase/obi-metrics.delta" \
        "$SELECTED_TRANSPORT" \
        "$expected_bridge_valid" \
        0 \
        "$expected_bridge_missing" \
        "$expected_bridge_lifecycle" \
        "$expected_bridge_stage" \
        "$include_ambiguous_candidates" \
        "$expected_bridge_stale" \
        "$expected_bridge_handoffs"; then
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
          primary-w3c-stale|unix-w3c-stale)
            expected_stale="$expected_requests"
            ;;
        esac
        if [[ "$name" == "coalesced-bridge" ]]; then
          if ! assert_coalesced_bridge_diagnostics_delta \
            "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" \
            "$coalesced_outcome"; then
            metric_status=1
          fi
        elif [[ "$name" == "timeout-retry" ]]; then
          if ! assert_timeout_cancellation_diagnostics_delta \
            "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" \
            "$scenario_reconciliation_json"; then
            metric_status=1
          fi
        elif [[ "$name" == "pressure" && \
          "$pressure_unix_already_consumed_reconciled" == "true" ]]; then
          if ! assert_pressure_unix_already_consumed_diagnostics_delta \
            "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" \
            "$expected_valid" \
            "$baseline_java_missing" \
            "$expected_sampled" \
            "$expected_unsampled" \
            "$expected_standard" \
            "$pressure_roots"; then
            metric_status=1
          fi
        elif ! assert_java_diagnostics_delta \
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
    if [[ "$diagnostics_enabled" == "true" ]]; then
      if ! before_diagnostics_status_json="$(
        java_diagnostics_phase_evidence_json "$before_phase"
      )"; then
        log_error "could not retain valid before-phase Java diagnostics for $label"
        before_diagnostics_status_json="null"
        metric_status=1
      fi
      if ! after_diagnostics_status_json="$(
        java_diagnostics_phase_evidence_json "$after_phase"
      )"; then
        log_error "could not retain valid after-phase Java diagnostics for $label"
        after_diagnostics_status_json="null"
        metric_status=1
      fi
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
    if [[ "$name" == "tls-boundary" || "$name" == "coalesced-bridge" ]]; then
      receive_cursor_map_status_json="$RECEIVE_CURSOR_MAP_STATUS_JSON"
    fi
    if ! printf '{\n  "status": "%s",\n  "scenario": "%s",\n  "exit_status": %d,\n  "metric_status": %d,\n  "pressure_correlation": %s,\n  "scenario_reconciliation": %s,\n  "receive_coordination_maps": %s,\n  "java_diagnostics": {"before": %s, "after": %s},\n  "obi_metric_evidence": %s,\n  "obi_metric_boundary_ids": %s,\n  "result": "%s",\n  "stderr": "%s",\n  "before_phase": "%s",\n  "after_phase": "%s"\n}\n' \
      "$status_name" \
      "$name" \
      "$scenario_status" \
      "$metric_status" \
      "$pressure_status_json" \
      "$scenario_reconciliation_json" \
      "$receive_cursor_map_status_json" \
      "$before_diagnostics_status_json" \
      "$after_diagnostics_status_json" \
      "$obi_metric_evidence_json" \
      "$obi_metric_boundary_ids_json" \
      "$(basename -- "$output")" \
      "$(basename -- "$stderr_output")" \
      "phases/$before_phase" \
      "phases/$after_phase" >"$RESULT_DIR/scenario-$label-status.json"; then
      return 1
    fi
    bind_status_to_active_obi_metric_boundary \
      "scenario-$label-status.json" || return $?
    log_info "$label status=$status_name evidence=$RESULT_DIR/scenario-$label-status.json"
    if ((scenario_status != 0)); then
      return "$scenario_status"
    fi
    if ((metric_status != 0)); then
      return "$metric_status"
    fi
    if [[ "$owns_obi_metric_boundary" == true ]]; then
      complete_obi_metric_boundary "$obi_metric_boundary_id" || return $?
    fi
    if [[ "$name" == "w3c-fault" ]] && ((run_number < REPEAT_COUNT)); then
      sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return 1
    fi
  done
}

run_deliberate_assertion_failure_control() {
  local -r label="assertion-failure"
  local -r result="$RESULT_DIR/scenario-$label.json"
  local java_bridge_diagnostics=""
  local obi_metric_boundary_ids="[]"

  run_scenario basic || return $?
  RUN_STAGE="deliberate-assertion-failure"
  seal_terminal_java_diagnostics || return $?
  java_bridge_diagnostics="$(terminal_java_diagnostics_json)" || return $?
  obi_metric_boundary_ids="$(completed_obi_metric_boundary_ids_json)" || return $?
  if ! printf '{"status":"failed","scenario":"assertion-failure","reason":"deliberate assertion failure requested","expected_exit_status":2}\n' \
    >"$result"; then
    return 1
  fi
  if ! jq -cn \
    --arg result "$(basename -- "$result")" \
    --arg java_bridge_diagnostics_reference 'terminal-java-diagnostics.json' \
    --argjson java_bridge_diagnostics "$java_bridge_diagnostics" \
    --argjson obi_metric_boundary_ids "$obi_metric_boundary_ids" '
      {
        status: "failed",
        scenario: "assertion-failure",
        exit_status: 2,
        metric_status: 0,
        result: $result,
        failure_context: "failure-context.txt",
        obi_metric_boundary_ids: $obi_metric_boundary_ids,
        java_bridge_diagnostics_reference: $java_bridge_diagnostics_reference,
        java_bridge_diagnostics: $java_bridge_diagnostics
      }
    ' >"$RESULT_DIR/scenario-$label-status.json"; then
    return 1
  fi
  log_info "basic scenario passed; recording the requested deliberate assertion failure"
  die "deliberate assertion failure requested"
}

stop_obi_for_no_state_control() {
  local -r label="$1"
  local -r diagnostics_output="${2:-}"
  local stopped_metric_pair_reference=""
  local stop_status=0

  plan_obi_metric_pair_capture "$label-obi-stopped" || return $?
  if ! flush_bridge_metric_boundary "$label" 1 1 "$diagnostics_output"; then
    log_error "could not establish the $label pre-stop bridge boundary"
    return 1
  fi
  if [[ -n "$diagnostics_output" && \
    ( ! -f "$diagnostics_output" || -L "$diagnostics_output" ) ]]; then
    log_error "$label pre-stop Java diagnostics snapshot is unavailable"
    return 1
  fi
  if ! capture_phase_evidence "$label-obi-running"; then
    log_error "could not capture the $label pre-stop evidence"
    return 1
  fi
  log_info "stopping OBI for the $label control"
  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  if run_bounded "$OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" stop --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi; then
    OBI_RUNNING=false
  else
    stop_status=$?
    log_error "could not stop OBI for the $label control"
    return "$stop_status"
  fi
  capture_obi_stopped_attestation \
    "$label-obi-stopped" \
    "phases/$label-obi-running/obi-identity.json" || return $?
  if ! capture_java_diagnostics "$label-obi-stopped" ||
    ! java_diagnostics_reference_evidence_json \
      "phases/$label-obi-stopped/java-diagnostics.txt" >/dev/null; then
    log_error "could not capture valid $label post-stop Java diagnostics"
    return 1
  fi
  stopped_metric_pair_reference="$(record_obi_metric_pair \
    "$label-obi-stopped" \
    "$label-obi-running" \
    "$label-obi-stopped" \
    same_process \
    "$label-obi-stopped")" || return $?
  obi_metric_pair_evidence_json_from_reference \
    "$stopped_metric_pair_reference" >/dev/null
}

run_fail_open_control() {
  stop_obi_for_no_state_control "fail-open" || return $?
  run_scenario fail-open
}

run_w3c_only_control() {
  stop_obi_for_no_state_control "w3c-only" || return $?
  run_scenario w3c-only
}

run_late_attach_recovery_sequence() {
  local -r attach_since="$1"
  local apache_since=""
  local scenario_status=0

  [[ -n "$attach_since" ]] || return 1
  log_info "starting OBI and requiring late helper attach without a JVM restart"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || return $?
  OBI_RUNNING=true
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "late-attach OBI remote-parent bridge" \
    "$attach_since" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "late-attached Java helper" \
    "$attach_since" || return $?
  wait_for_log \
    java-backend \
    "OBI Java instrumentation ready" \
    "late-attached Java instrumentation" \
    "$attach_since" || return $?
  BRIDGE_RUNNING=true
  assert_selected_transport || return $?
  log_info "recycling Apache connections created before late attach"
  run_bounded 60 \
    "${COMPOSE[@]}" stop --timeout 10 apache-proxy || return $?
  wait_for_apache_instrumentation_drain late-attach || return $?
  apache_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      --no-deps apache-proxy || return $?
  wait_for_log \
    obi \
    "cmd=/usr/local/apache2/bin/httpd" \
    "late-attach Apache instrumentation" \
    "$apache_since" || return $?
  wait_for_apache_instrumentation late-attach || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "late-attach recovered HTTPS path" || return $?
  wait_for_java_duplicate_suppression \
    "$RESULT_DIR/duplicate-suppression-late-attach-recovery.prom" || return $?
  SCENARIO_VARIANT="late-attach-recovery"
  if run_scenario restart; then
    SCENARIO_VARIANT=""
  else
    scenario_status=$?
    SCENARIO_VARIANT=""
    return "$scenario_status"
  fi
}

run_late_attach_control() {
  local attach_since=""
  local recovery_boundary_status=0
  local recovery_status=0
  local terminal_diagnostics_status=0

  stop_obi_for_no_state_control "late-attach" || return $?
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  log_info "recreating the JVM while OBI is absent"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "OBI-absent HTTPS path" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "OBI-absent external extension" || return $?
  assert_runtime_contract obi-absent || return $?

  SCENARIO_VARIANT="obi-absent"
  run_scenario fail-open
  run_scenario w3c-only
  SCENARIO_VARIANT=""

  attach_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  if capture_terminal_java_diagnostics_recovery_boundary; then
    :
  else
    recovery_boundary_status=$?
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
  fi
  if run_late_attach_recovery_sequence "$attach_since"; then
    recovery_status=0
  else
    recovery_status=$?
  fi
  if ((recovery_boundary_status != 0)); then
    return "$recovery_boundary_status"
  fi
  if ((recovery_status != 0)); then
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
    return "$recovery_status"
  fi
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  clear_terminal_java_diagnostics_recovery_boundary || return $?
  return "$terminal_diagnostics_status"
}

assert_compose_service_stopped() {
  local -r service="$1"
  local -r boundary="${2:-permanent-absence boundary}"
  local running=""

  [[ "$service" =~ ^[a-z][a-z0-9-]{0,63}$ ]] || return 1
  [[ "$boundary" =~ ^[a-z0-9][-a-z0-9\ ]{0,95}$ ]] || return 1
  running="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet "$service" 2>/dev/null)" || return $?
  [[ -z "$running" ]] || {
    log_error "$service remained running across the $boundary"
    return 1
  }
}

stop_permanent_absence_jvm() {
  assert_project_docker_identity_unchanged || return $?
  run_bounded 60 "${COMPOSE[@]}" stop --timeout 10 \
    apache-proxy java-backend || return $?
  assert_compose_service_stopped apache-proxy || return $?
  assert_compose_service_stopped java-backend
}

assert_runtime_identity_unchanged() {
  local -r before="$1"
  local -r after="$2"
  local -r description="${3:-controlled requests}"

  [[ -f "$before" && ! -L "$before" && -f "$after" && ! -L "$after" ]] || return 1
  runtime_identity_field "$before" container_id >/dev/null || return 1
  runtime_identity_field "$before" host_pid >/dev/null || return 1
  runtime_identity_field "$before" started_at >/dev/null || return 1
  runtime_identity_field "$after" container_id >/dev/null || return 1
  runtime_identity_field "$after" host_pid >/dev/null || return 1
  runtime_identity_field "$after" started_at >/dev/null || return 1
  cmp -s -- "$before" "$after" || {
    log_error "the $description did not remain in one JVM lifetime"
    return 1
  }
}

assert_permanent_absence_logs_are_bounded() {
  local -r input="$1"

  bounded_evidence_file \
    "$input" \
    "$PERMANENT_ABSENCE_LOG_MAX_BYTES" \
    "$PERMANENT_ABSENCE_LOG_MAX_LINES" || return 1
  LC_ALL=C awk \
    -v maximum="$PERMANENT_ABSENCE_REMOTE_PARENT_LOG_MAX" '
    index($0, "OBI remote-parent") {
      remote_parent_lines++
      if (length($0) > 1024) {
        overlong = 1
      }
    }
    index($0, "OBI remote-parent propagator enabled") {
      propagator_enabled++
    }
    index($0, "OBI remote-parent provider ready") {
      provider_ready++
    }
    index($0, "OBI Java instrumentation ready") {
      instrumentation_ready++
    }
    END {
      exit remote_parent_lines <= maximum && !overlong &&
        propagator_enabled >= 1 && provider_ready == 0 &&
        instrumentation_ready == 0 ? 0 : 1
    }
  ' "$input" || {
    log_error "permanent-absence Java diagnostics were unbounded or reported false readiness"
    return 1
  }
}

capture_bounded_permanent_absence_logs() {
  local -r service="$1"
  local -r since="$2"
  local -r output="$3"
  local temporary=""
  local size=""
  local pipeline_status=0
  local overflow=false

  [[ "$service" =~ ^[a-z][a-z0-9-]{0,63}$ && ! -L "$output" ]] || return 1
  temporary="$(mktemp "$output.capture.XXXXXX")" || return $?
  if run_bounded "$PERMANENT_ABSENCE_LOG_CAPTURE_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" logs --no-color --since "$since" "$service" |
    (
      LC_ALL=C head -c "$((PERMANENT_ABSENCE_LOG_MAX_BYTES + 1))" \
        >"$temporary" || exit $?
      cat >/dev/null
    ); then
    :
  else
    pipeline_status=$?
  fi
  size="$(stat -c '%s' -- "$temporary")" || {
    pipeline_status=$?
    rm -f -- "$temporary" || true
    return "$pipeline_status"
  }
  if ((size > PERMANENT_ABSENCE_LOG_MAX_BYTES)) || \
    ! bounded_evidence_file \
      "$temporary" \
      "$PERMANENT_ABSENCE_LOG_MAX_BYTES" \
      "$PERMANENT_ABSENCE_LOG_MAX_LINES"; then
    overflow=true
    retain_bounded_evidence_limits \
      "$temporary" \
      "$PERMANENT_ABSENCE_LOG_MAX_BYTES" \
      "$PERMANENT_ABSENCE_LOG_MAX_LINES" || {
      pipeline_status=$?
      rm -f -- "$temporary" || true
      return "$pipeline_status"
    }
  fi
  if chmod 0644 "$temporary" && mv -fT -- "$temporary" "$output"; then
    :
  else
    pipeline_status=$?
    rm -f -- "$temporary" || true
    return "$pipeline_status"
  fi
  if ((pipeline_status != 0)); then
    log_error "could not capture the complete permanent-absence Java log stream"
    return "$pipeline_status"
  fi
  if [[ "$overflow" == "true" ]]; then
    log_error "permanent-absence Java logs exceeded the retained bounds"
    return 1
  fi
}

wait_for_bounded_permanent_absence_log() {
  local -r service="$1"
  local -r pattern="$2"
  local -r description="$3"
  local -r since="$4"
  local -r failure_snapshot="$RESULT_DIR/permanent-absence-readiness.log"
  local snapshot=""
  local -i deadline=0
  local capture_status=0
  local sleep_status=0

  [[ -n "$pattern" && -n "$since" && \
    ! -e "$failure_snapshot" && ! -L "$failure_snapshot" ]] || return 1
  snapshot="$(mktemp "$RESULT_DIR/.permanent-absence-readiness.XXXXXX")" || return $?
  deadline=$((SECONDS + READINESS_TIMEOUT_SECONDS))
  while ((SECONDS < deadline)); do
    if capture_bounded_permanent_absence_logs \
      "$service" "$since" "$snapshot"; then
      :
    else
      capture_status=$?
      mv -fT -- "$snapshot" "$failure_snapshot" || return $?
      return "$capture_status"
    fi
    if ! bounded_evidence_file \
      "$snapshot" \
      "$PERMANENT_ABSENCE_LOG_MAX_BYTES" \
      "$PERMANENT_ABSENCE_LOG_MAX_LINES"; then
      mv -fT -- "$snapshot" "$failure_snapshot" || return $?
      log_error "permanent-absence readiness logs exceeded their fixed bounds"
      return 1
    fi
    if grep -Fq -- "$pattern" "$snapshot"; then
      rm -f -- "$snapshot" || return $?
      log_info "$description is ready"
      return 0
    fi
    if ((SECONDS < deadline)); then
      sleep 1 || {
        sleep_status=$?
        rm -f -- "$snapshot" || true
        return "$sleep_status"
      }
    fi
  done
  mv -fT -- "$snapshot" "$failure_snapshot" || return $?
  log_error "timed out waiting for $description log: $pattern"
  return 1
}

run_permanent_absence_control() (
  local -r original_variant="$SCENARIO_VARIANT"
  local -r original_transport="$TRANSPORT"
  local -r original_propagation="${CONTEXT_PROPAGATION:-tcp}"
  local -r recovery_marker="$RESULT_DIR/permanent-absence-recovery-required"
  local -r timeline="$RESULT_DIR/permanent-absence-lifetime.txt"
  local -r identity_before="$RESULT_DIR/permanent-absence-java-before.txt"
  local -r identity_after="$RESULT_DIR/permanent-absence-java-after.txt"
  local -r logs="$RESULT_DIR/permanent-absence-java.log"
  local -r diagnostics="$RESULT_DIR/phases/permanent-absence/java-diagnostics.txt"
  local absence_since=""
  local registration_failures=""
  local restore_required=false
  local absence_jvm_may_be_running=false
  local safe_to_restore=true
  local restore_status=0
  local restore_entry_status=""

  complete_permanent_absence_recovery() {
    assert_project_docker_identity_unchanged || return $?
    recreate_instrumented_stack \
      "$original_propagation" "post-permanent absence recovery" \
      "$original_transport" true false base || return $?
    SCENARIO_VARIANT="permanent-absence-recovery"
    run_scenario basic || return $?
    clear_pending_permanent_absence_recovery || return $?
    rm -f -- "$recovery_marker" || return $?
  }

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  restore_permanent_absence_stack() {
    local -r status="${1:-$?}"
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    arm_permanent_absence_record_only_traps
    seal_terminal_java_diagnostics
    terminal_diagnostics_status=$?
    if [[ "$absence_jvm_may_be_running" == "true" ]]; then
      if stop_permanent_absence_jvm; then
        absence_jvm_may_be_running=false
      else
        restore_status=$?
        safe_to_restore=false
        log_error "refusing to start OBI while the permanent-absence JVM may still be running"
      fi
    fi
    if [[ "$restore_required" == "true" && "$safe_to_restore" == "true" ]]; then
      complete_permanent_absence_recovery
      restore_status=$?
    fi
    SCENARIO_VARIANT="$original_variant"
    # Recovery is complete at this boundary. Preserve every earlier signal,
    # then ignore later arrivals so this subshell's status cannot diverge from
    # the recovery decision returned to the guarded runner.
    trap '' HUP INT TERM
    if ((status == 0 && CLEANUP_SIGNAL_STATUS != 0)); then
      exit "$CLEANUP_SIGNAL_STATUS"
    fi
    if ((status == 0 && restore_status != 0)); then
      exit "$restore_status"
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  arm_permanent_absence_record_only_traps() {
    # The first update closes the re-entry window in one builtin. Subsequent
    # updates preserve the exact first signal without dynamically reparsing a
    # nested trap program during recovery.
    trap record_cleanup_term HUP INT TERM
    trap record_cleanup_hup HUP
    trap record_cleanup_int INT
    trap record_cleanup_term TERM
  }

  permanent_absence_signal_hup() {
    arm_permanent_absence_record_only_traps
    record_cleanup_signal HUP
    restore_permanent_absence_stack 129
  }

  permanent_absence_signal_int() {
    arm_permanent_absence_record_only_traps
    record_cleanup_signal INT
    restore_permanent_absence_stack 130
  }

  permanent_absence_signal_term() {
    arm_permanent_absence_record_only_traps
    record_cleanup_signal TERM
    restore_permanent_absence_stack 130
  }

  permanent_absence_exit() {
    local -r entry_status="$?"

    restore_entry_status="${restore_entry_status:-$entry_status}"
    arm_permanent_absence_record_only_traps
    restore_permanent_absence_stack "$restore_entry_status"
  }

  CLEANUP_SIGNAL_STATUS=0
  trap permanent_absence_exit EXIT
  trap permanent_absence_signal_hup HUP
  trap permanent_absence_signal_int INT
  trap permanent_absence_signal_term TERM
  assert_project_docker_identity_unchanged || return $?
  [[ "$original_transport" == "getsockopt" || "$original_transport" == "unix" || \
    "$original_transport" == "auto" ]] || return 1
  [[ ! -e "$recovery_marker" && ! -L "$recovery_marker" && \
    ! -e "$timeline" && ! -L "$timeline" ]] || return 1
  create_permanent_absence_global_marker || return $?
  if ! (umask 077; printf 'recovery_required\n' >"$recovery_marker"); then
    clear_pending_permanent_absence_recovery || true
    return 1
  fi
  restore_required=true

  assert_project_docker_identity_unchanged || return $?
  SCENARIO_VARIANT="permanent-absence-baseline"
  run_disabled_control || return $?
  SCENARIO_VARIANT="$original_variant"
  capture_control_response permanent-absence-disabled || return $?
  printf 'disabled_baseline=captured\n' >"$timeline" || return $?

  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  assert_project_docker_identity_unchanged || return $?
  run_bounded "$OBI_COMPOSE_MULTI_SERVICE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" stop --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" \
    apache-proxy java-backend obi || return $?
  OBI_RUNNING=false
  assert_compose_service_stopped apache-proxy || return $?
  assert_compose_service_stopped java-backend || return $?
  assert_compose_service_stopped obi || return $?
  printf 'obi=stopped-before-jvm-start\n' >>"$timeline" || return $?

  export BRIDGE_TRANSPORT="$original_transport"
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  absence_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  absence_jvm_may_be_running=true
  assert_project_docker_identity_unchanged || return $?
  run_bounded 120 "${COMPOSE[@]}" up --detach --force-recreate \
    java-backend apache-proxy || return $?
  assert_compose_service_stopped obi || return $?
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "permanent-absence HTTPS path" || return $?
  wait_for_bounded_permanent_absence_log \
    java-backend "OBI remote-parent propagator enabled" \
    "permanent-absence external extension" "$absence_since" || return $?
  assert_runtime_contract permanent-absence || return $?
  capture_service_runtime_identity java-backend "$identity_before" || return $?
  printf 'jvm=started-with-obi-absent\n' >>"$timeline" || return $?

  capture_control_response permanent-absence || return $?
  cmp -s -- \
    "$RESULT_DIR/permanent-absence-disabled-response.normalized.json" \
    "$RESULT_DIR/permanent-absence-response.normalized.json" || return $?
  cmp -s -- \
    "$RESULT_DIR/permanent-absence-disabled-response.status" \
    "$RESULT_DIR/permanent-absence-response.status" || return $?
  SCENARIO_VARIANT="permanent-absence"
  run_scenario fail-open || return $?
  run_scenario w3c-only || return $?
  capture_java_diagnostics permanent-absence || return $?
  assert_sanitized_java_diagnostics "$diagnostics" || return $?
  registration_failures="$(diagnostic_counter "$diagnostics" registration_fail)" || return $?
  ((registration_failures >= 1 && \
    registration_failures <= PERMANENT_ABSENCE_REGISTRATION_FAILURE_MAX)) || {
    log_error "permanent-absence provider registration retries were not bounded"
    return 1
  }
  capture_service_runtime_identity java-backend "$identity_after" || return $?
  assert_runtime_identity_unchanged "$identity_before" "$identity_after" || return $?
  assert_compose_service_stopped obi || return $?
  printf 'requests=completed-in-one-jvm\nobi=absent-at-final-checkpoint\n' \
    >>"$timeline" || return $?

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  stop_permanent_absence_jvm || return $?
  absence_jvm_may_be_running=false
  capture_bounded_permanent_absence_logs \
    java-backend "$absence_since" "$logs" || return $?
  assert_permanent_absence_logs_are_bounded "$logs" || return $?
  printf 'jvm=stopped-before-obi-recovery\n' >>"$timeline" || return $?
  complete_permanent_absence_recovery || return $?
  restore_required=false
  SCENARIO_VARIANT="$original_variant"
  printf '{"status":"passed","scenario":"permanent-absence","obi_started_during_jvm_lifetime":false,"single_jvm_lifetime":true,"disabled_baseline_equivalent":true,"fail_open":"passed","w3c_precedence":"passed","diagnostics":"bounded","post_absence_recovery":"passed"}\n' \
    >"$RESULT_DIR/scenario-permanent-absence-status.json"
  crosslink_and_bind_active_obi_metric_boundary_status \
    scenario-permanent-absence-status.json || return $?

  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
)

run_auto_unavailable_control() (
  # This lifecycle proof deliberately contributes one fail-open and one W3C
  # request per repeat. A custom all-suite request count must not turn this
  # bounded control into an unrelated bulk workload.
  local -r REQUEST_COUNT=1
  local -r original_variant="$SCENARIO_VARIANT"
  local -r original_propagation="${CONTEXT_PROPAGATION:-tcp}"
  local -r before_phase="auto-unavailable-before"
  local -r after_phase="auto-unavailable-after"
  local -r before_diagnostics="$RESULT_DIR/phases/$before_phase/java-diagnostics.txt"
  local -r stopped_diagnostics="$RESULT_DIR/phases/auto-unavailable-obi-stopped/java-diagnostics.txt"
  local -r diagnostics_delta="$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"
  local -r transport_configuration="$RESULT_DIR/java-auto-unavailable-transport-configuration.txt"
  local -r identity_before="$RESULT_DIR/auto-unavailable-java-before.txt"
  local -r identity_fault="$RESULT_DIR/auto-unavailable-java-fault.txt"
  local -r identity_recovery="$RESULT_DIR/auto-unavailable-java-recovery.txt"
  local restart_since=""
  local restore_required=false
  local restore_status=0

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  restore_auto_unavailable_stack() {
    local -r status="$?"
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    seal_terminal_java_diagnostics
    terminal_diagnostics_status=$?
    if [[ "$restore_required" == "true" ]]; then
      (
        set -Eeuo pipefail
        recreate_instrumented_stack \
          "$original_propagation" "auto-unavailable cleanup" auto
      )
      restore_status=$?
    fi
    SCENARIO_VARIANT="$original_variant"
    if ((status == 0 && restore_status != 0)); then
      exit "$restore_status"
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  trap restore_auto_unavailable_stack EXIT
  [[ "$TRANSPORT" == "auto" &&
    ( "$SELECTED_TRANSPORT" == "getsockopt" || "$SELECTED_TRANSPORT" == "unix" ) &&
    "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "the auto-unavailable control requires a healthy auto-selected bridge"
    return 1
  }
  restore_required=true

  SCENARIO_VARIANT="auto-unavailable-baseline"
  run_disabled_control || return $?
  SCENARIO_VARIANT="$original_variant"
  capture_control_response auto-unavailable-disabled || return $?
  recreate_instrumented_stack \
    "$original_propagation" "auto-unavailable preparation" auto || return $?
  assert_runtime_contract basic true || return $?
  capture_service_runtime_identity java-backend "$identity_before" || return $?
  mkdir -p -- "$RESULT_DIR/phases/$before_phase" || return $?
  stop_obi_for_no_state_control auto-unavailable "$before_diagnostics" || return $?
  assert_runtime_contract auto-unavailable || return $?

  capture_control_response auto-unavailable || return $?
  cmp -s -- \
    "$RESULT_DIR/auto-unavailable-disabled-response.normalized.json" \
    "$RESULT_DIR/auto-unavailable-response.normalized.json" || return $?
  cmp -s -- \
    "$RESULT_DIR/auto-unavailable-disabled-response.status" \
    "$RESULT_DIR/auto-unavailable-response.status" || return $?

  sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return $?
  SCENARIO_VARIANT="auto-unavailable"
  run_scenario fail-open false || return $?
  wait_for_auto_transports_unavailable_configuration \
    "$transport_configuration" || return $?
  run_scenario w3c-only false || return $?
  capture_java_diagnostics "$after_phase" || return $?
  write_java_diagnostics_delta \
    "$stopped_diagnostics" \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" \
    "$diagnostics_delta" || return $?
  assert_auto_unavailable_diagnostics_delta "$diagnostics_delta" || return $?
  capture_service_runtime_identity java-backend "$identity_fault" || return $?
  assert_runtime_identity_unchanged \
    "$identity_before" "$identity_fault" "auto-unavailable requests" || return $?
  assert_compose_service_stopped obi "auto-unavailable boundary" || return $?

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  restart_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || return $?
  OBI_RUNNING=true
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "auto-unavailable OBI recovery" \
    "$restart_since" || return $?
  sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return $?
  BRIDGE_RUNNING=true
  wait_for_apache_instrumentation auto-unavailable-recovery || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "auto-unavailable Java provider recovery" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "auto-unavailable Java provider recovery" \
    "$restart_since" || return $?
  assert_selected_transport auto || return $?
  wait_for_java_duplicate_suppression \
    "$RESULT_DIR/duplicate-suppression-auto-unavailable-recovery.prom" || return $?
  assert_runtime_contract basic true || return $?
  capture_service_runtime_identity java-backend "$identity_recovery" || return $?
  assert_runtime_identity_unchanged \
    "$identity_before" "$identity_recovery" "auto-unavailable recovery" || return $?
  SCENARIO_VARIANT="auto-unavailable-recovery"
  run_scenario basic || return $?
  SCENARIO_VARIANT="$original_variant"
  restore_required=false
  printf '{"status":"passed","scenario":"auto-unavailable","requested_transport":"auto","attempted_transports":["getsockopt","unix"],"selected_transport":"none","disabled_baseline_equivalent":true,"fail_open":"passed","w3c_precedence":"passed","single_jvm_lifetime":true,"retry_storm":"absent","post_fault_recovery":"passed"}\n' \
    >"$RESULT_DIR/scenario-auto-unavailable-status.json"
  crosslink_and_bind_active_obi_metric_boundary_status \
    scenario-auto-unavailable-status.json || return $?

  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
)

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
  local timestamp=""

  if [[ -L "$events" || ( -e "$events" && ! -f "$events" ) ]]; then
    log_error "restart control event target is not a regular file: $events"
    return 1
  fi
  timestamp="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  printf '%s %s\n' "$timestamp" "$event" >>"$events" || return $?
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
  local obi_metric_pair_reference=""
  local obi_metric_evidence_json="null"

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  cleanup_restart_traffic() {
    local -r status="$?"
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    if ((status != 0)); then
      seal_terminal_java_diagnostics
      terminal_diagnostics_status=$?
    fi
    if [[ -n "$scenario_pid" ]]; then
      if kill -0 "$scenario_pid" 2>/dev/null; then
        kill -TERM "$scenario_pid" 2>/dev/null || true
      fi
      wait "$scenario_pid" 2>/dev/null || true
      scenario_pid=""
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  trap cleanup_restart_traffic EXIT

  [[ "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "restart-during-traffic control requires a running bridge"
    return 1
  }
  plan_obi_metric_pair_capture "$label" || return $?
  prepare_restart_control_directory "$control_dir" || return $?
  log_info "running valid-W3C traffic while OBI restarts"
  capture_phase_evidence "$before_phase" || return $?
  capture_java_diagnostics "$before_phase" || return $?
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

  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  run_bounded "$OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" stop --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || \
    return $?
  OBI_RUNNING=false
  publish_restart_control_release \
    "$control_dir" \
    "$RESTART_RELEASE_OBI_STOPPED" || return $?
  wait_for_restart_control_signal \
    "$control_dir" \
    "$RESTART_SIGNAL_STOPPED_TRAFFIC_COMPLETE" \
    "traffic while OBI was stopped" \
    "$scenario_pid" || return $?
  restart_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || return $?
  OBI_RUNNING=true
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "OBI bridge restarted during traffic" \
    "$restart_since" || return $?
  sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return $?
  BRIDGE_RUNNING=true
  wait_for_apache_instrumentation restart-fault-recovery || return $?
  wait_for_java_duplicate_suppression \
    "$RESULT_DIR/duplicate-suppression-restart-fault-recovery.prom" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "Java bridge reconfigured before restart traffic resumes" \
    "$restart_since" || return $?
  assert_selected_transport || return $?
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
  capture_phase_evidence "$after_phase" || return $?
  capture_java_diagnostics "$after_phase" || return $?
  obi_metric_pair_reference="$(record_obi_metric_pair \
    "$label" "$before_phase" "$after_phase" process_replaced "$after_phase")" ||
    return $?
  obi_metric_evidence_json="$(
    obi_metric_pair_evidence_json_from_reference "$obi_metric_pair_reference"
  )" || return $?
  write_java_diagnostics_delta \
    "$RESULT_DIR/phases/$before_phase/java-diagnostics.txt" \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" || return $?
  assert_restart_fault_diagnostics \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.delta" \
    32 \
    3 \
    "$RESULT_DIR/restart-fault-diagnostics.txt" || return $?
  jq -c \
    --arg result "$(basename -- "$output")" \
    --arg after_phase "phases/$after_phase" '
      {
        status: "passed",
        scenario: "restart-fault",
        result: $result,
        after_phase: $after_phase,
        restart_control: "restart-control/events.log",
        obi_metric_evidence: .
      }
    ' <<<"$obi_metric_evidence_json" \
    >"$RESULT_DIR/scenario-$label-status.json" || return $?
  crosslink_and_bind_active_obi_metric_boundary_status \
    "scenario-$label-status.json" || return $?

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  SCENARIO_VARIANT="restart-recovery"
  run_scenario restart
  SCENARIO_VARIANT=""
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
)

run_extension_controls() {
  local disabled_since=""

  stop_obi_for_no_state_control "extension-controls" || return $?
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"

  log_info "recreating the backend with the external extension absent"
  export EXTENSION_ENABLED=false
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE=""
  export OTEL_PROPAGATORS_VALUE="tracecontext,baggage"
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "extension-absent HTTPS path" || return $?
  assert_runtime_contract extension-absent || return $?
  SCENARIO_VARIANT="extension-absent"
  run_scenario w3c-only

  log_info "recreating the backend with the external extension disabled"
  export EXTENSION_ENABLED=false
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  disabled_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "extension-disabled HTTPS path" || return $?
  assert_runtime_contract extension-disabled || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator disabled by configuration" \
    "disabled external extension" \
    "$disabled_since" || return $?
  SCENARIO_VARIANT="extension-disabled"
  run_scenario w3c-only
  SCENARIO_VARIANT=""
}

recreate_instrumented_stack() {
  local -r propagation="$1"
  local -r label="$2"
  local -r transport="${3:-$TRANSPORT}"
  local -r verify_java_traffic="${4:-true}"
  local -r fresh_trace_receiver="${5:-false}"
  local -r compose_flavor="${6:-base}"
  local recreate_since=""
  local -a services=(java-backend apache-proxy obi)
  local -a compose_command=()

  [[ "$verify_java_traffic" == "true" || "$verify_java_traffic" == "false" ]] || {
    log_error "Java traffic verification mode must be true or false"
    return 1
  }
  [[ "$fresh_trace_receiver" == "true" || "$fresh_trace_receiver" == "false" ]] || {
    log_error "trace receiver recreation mode must be true or false"
    return 1
  }
  case "$compose_flavor" in
    base)
      compose_command=("${COMPOSE[@]}")
      ;;
    primary-fault)
      compose_command=("${PRIMARY_FAULT_COMPOSE[@]}")
      ;;
    primary-live-fd)
      compose_command=("${PRIMARY_LIVE_FD_COMPOSE[@]}")
      ;;
    unix-generation-fault)
      compose_command=("${UNIX_GENERATION_FAULT_COMPOSE[@]}")
      ;;
    *)
      log_error "unsupported instrumented-stack Compose flavor: $compose_flavor"
      return 1
      ;;
  esac
  if [[ "$fresh_trace_receiver" == "true" ]]; then
    services=(trace-receiver "${services[@]}")
  fi

  CONTEXT_PROPAGATION="$propagation"
  export CONTEXT_PROPAGATION
  BRIDGE_TRANSPORT="$transport"
  export BRIDGE_TRANSPORT
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  recreate_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  if [[ "$verify_java_traffic" == "false" ]]; then
    DELAYED_OTLP_PROVIDER_READY_SINCE="$recreate_since"
  fi
  log_info "recreating the instrumented stack for $label propagation=$propagation flavor=$compose_flavor"
  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  if [[ "$compose_flavor" == "primary-fault" || \
    "$compose_flavor" == "primary-live-fd" || \
    "$compose_flavor" == "unix-generation-fault" ]]; then
    run_bounded 30 "${compose_command[@]}" config --quiet || return $?
    run_bounded 30 "${compose_command[@]}" config \
      >"$RESULT_DIR/compose-${compose_flavor}-resolved.yaml" || return $?
  fi
  run_bounded 180 \
    "${compose_command[@]}" up --detach \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" --force-recreate \
      "${services[@]}" || return $?
  OBI_RUNNING=true
  if [[ "$fresh_trace_receiver" == "true" ]]; then
    wait_for_http "http://127.0.0.1:14318/healthz" \
      "$label trace receiver" || return $?
  fi
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "$label OBI remote-parent bridge" \
    "$recreate_since" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "$label external OTel extension" \
    "$recreate_since" || return $?
  wait_for_log \
    java-backend \
    "OBI Java instrumentation ready" \
    "$label injected Java instrumentation" \
    "$recreate_since" || return $?
  wait_for_log \
    java-backend \
    "Jetty HTTPS backend ready on 127.0.0.1:18443" \
    "$label Jetty HTTPS backend" \
    "$recreate_since" || return $?
  wait_for_log \
    java-backend \
    "Netty HTTPS backend ready on 127.0.0.1:18444" \
    "$label Netty HTTPS backend" \
    "$recreate_since" || return $?
  wait_for_log \
    java-backend \
    "TLS boundary split HTTPS backend ready on 127.0.0.1:18445" \
    "$label TLS boundary split HTTPS backend" \
    "$recreate_since" || return $?
  wait_for_log \
    java-backend \
    "TLS boundary coalesced HTTPS backend ready on 127.0.0.1:18446" \
    "$label TLS boundary coalesced HTTPS backend" \
    "$recreate_since" || return $?
  BRIDGE_RUNNING=true
  wait_for_apache_instrumentation recreate-instrumented || return $?
  if [[ "$verify_java_traffic" == "false" ]]; then
    wait_for_log \
      apache-proxy \
      "resuming normal operations" \
      "$label Apache HTTP proxy" \
      "$recreate_since" || return $?
    return 0
  fi
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "$label HTTPS path" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "$label injected Java helper" \
    "$recreate_since" || return $?
  assert_selected_transport "$transport" || return $?
  wait_for_java_duplicate_suppression \
    "$RESULT_DIR/duplicate-suppression-${label// /-}.prom" || return $?
}

run_delayed_otlp_suppression_sequence() {
  local scenario_status=0
  local earliest_export_millisecond=""
  local -r provider_ready_since="$DELAYED_OTLP_PROVIDER_READY_SINCE"
  local -r before_phase="delayed-otlp-prime-before"
  local -r after_phase="delayed-otlp-suppression-after"

  [[ -n "$provider_ready_since" ]] || {
    log_error "delayed OTLP provider-readiness cursor is unavailable"
    return 1
  }

  initialize_delayed_otlp_run_identity || return $?
  plan_obi_metric_pair_capture delayed-otlp-prime-suppression || return $?
  capture_phase_evidence "$before_phase" || return $?
  earliest_export_millisecond="$(delayed_otlp_earliest_export_millisecond)" || return $?
  assert_delayed_otlp_receiver_empty \
    "$RESULT_DIR/delayed-otlp-receiver-before-request.json" || return $?
  assert_java_duplicate_suppression_absent \
    "$RESULT_DIR/duplicate-suppression-delayed-otlp-before-request.prom" || return $?
  # Registration can race bridge attachment. Let the provider's bounded retry interval expire,
  # then use the one intentional prime request to activate recovery without adding another span.
  sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return $?
  run_bounded 10 curl --fail --silent --show-error \
    --header "x-obi-demo-id: $DELAYED_OTLP_PRIME_MARKER" \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" >/dev/null || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "delayed-otlp-suppression injected Java helper" \
    "$provider_ready_since" || return $?
  assert_delayed_otlp_pre_export_window \
    "$RESULT_DIR/delayed-otlp-window.txt" \
    "$earliest_export_millisecond" || return $?
  sleep "$DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS" || return $?
  assert_delayed_otlp_receiver_has_no_java_export \
    "$RESULT_DIR/delayed-otlp-receiver-before-export.json" || return $?
  assert_java_duplicate_suppression_absent \
    "$RESULT_DIR/duplicate-suppression-delayed-otlp-before-export.prom" || return $?
  wait_for_java_duplicate_suppression_without_prime \
    "$RESULT_DIR/duplicate-suppression-delayed-otlp-ready.prom" \
    "$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS" || return $?
  wait_for_delayed_otlp_receiver_export \
    "$RESULT_DIR/delayed-otlp-receiver-ready.json" \
    "$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS" \
    "$earliest_export_millisecond" \
    "$RESULT_DIR/delayed-otlp-receiver-early.json" \
    "$RESULT_DIR/delayed-otlp-receiver-unexpected.json" \
    "$DELAYED_OTLP_POST_EXPORT_SETTLE_SECONDS" || return $?
  capture_phase_evidence "$after_phase" || return $?
  record_obi_metric_pair \
    delayed-otlp-prime-suppression "$before_phase" "$after_phase" \
    same_process "$after_phase" >/dev/null || return $?
  assert_selected_transport || return $?
  assert_runtime_contract delayed-otlp-suppression true || return $?
  SCENARIO_VARIANT="delayed-otlp-suppression"
  if run_scenario basic; then
    SCENARIO_VARIANT=""
  else
    scenario_status=$?
    SCENARIO_VARIANT=""
    return "$scenario_status"
  fi
}

run_delayed_otlp_suppression_control() {
  local schedule_delay_previous=""
  local schedule_delay_was_set=false
  local java_retry_disabled_previous=""
  local java_retry_disabled_was_set=false
  local control_status=0
  local recovery_boundary_status=0
  local recovery_status=0
  local terminal_diagnostics_status=0

  if [[ "$SCENARIO" == "all" ]]; then
    if [[ -v OTEL_BSP_SCHEDULE_DELAY_VALUE ]]; then
      schedule_delay_was_set=true
      schedule_delay_previous="$OTEL_BSP_SCHEDULE_DELAY_VALUE"
    fi
    if [[ -v OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE ]]; then
      java_retry_disabled_was_set=true
      java_retry_disabled_previous="$OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE"
    fi
    export OTEL_BSP_SCHEDULE_DELAY_VALUE="$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS"
    export OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE="$DELAYED_OTLP_JAVA_RETRY_DISABLED"
    if recreate_instrumented_stack \
      tcp "delayed-otlp-suppression startup" "$TRANSPORT" false true; then
      :
    else
      control_status=$?
    fi
  fi

  if ((control_status == 0)); then
    if run_delayed_otlp_suppression_sequence; then
      :
    else
      control_status=$?
    fi
  fi
  if ((control_status != 0)); then
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
  fi

  if [[ "$SCENARIO" == "all" ]]; then
    if [[ "$schedule_delay_was_set" == "true" ]]; then
      export OTEL_BSP_SCHEDULE_DELAY_VALUE="$schedule_delay_previous"
    else
      unset OTEL_BSP_SCHEDULE_DELAY_VALUE
    fi
    if [[ "$java_retry_disabled_was_set" == "true" ]]; then
      export OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE="$java_retry_disabled_previous"
    else
      unset OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE
    fi
    if ((control_status != 0)); then
      log_warn "restoring the standard instrumented stack after delayed OTLP control failure"
      recreate_instrumented_stack \
        tcp "post-delayed-otlp suppression recovery" || true
      return "$control_status"
    fi
    if capture_terminal_java_diagnostics_recovery_boundary; then
      :
    else
      recovery_boundary_status=$?
      if seal_terminal_java_diagnostics; then
        :
      else
        terminal_diagnostics_status=$?
      fi
    fi
    if recreate_instrumented_stack \
      tcp "post-delayed-otlp suppression restoration"; then
      recovery_status=0
    else
      recovery_status=$?
    fi
    if ((recovery_boundary_status != 0)); then
      return "$recovery_boundary_status"
    fi
    if ((recovery_status != 0)); then
      if seal_terminal_java_diagnostics; then
        :
      else
        terminal_diagnostics_status=$?
      fi
      return "$recovery_status"
    fi
    commit_terminal_java_diagnostics_recovery_boundary || return $?
    clear_terminal_java_diagnostics_recovery_boundary || return $?
  fi
  if ((control_status == 0 && terminal_diagnostics_status != 0)); then
    return "$terminal_diagnostics_status"
  fi
  return "$control_status"
}

capture_service_runtime_identity() {
  local -r service="$1"
  local -r output="$2"
  local container_id=""
  local inspected_id=""
  local host_pid=""
  local started_at=""
  local extra=""
  local inspection=""

  container_id="$(
    run_bounded 10 "${COMPOSE[@]}" ps --quiet "$service"
  )" || return $?
  [[ -n "$container_id" ]] || {
    log_error "$service container identity is unavailable"
    return 1
  }
  inspection="$(run_bounded 10 docker inspect \
    --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' \
    "$container_id")" || return $?
  read -r inspected_id host_pid started_at extra <<<"$inspection" || return $?
  [[ "$inspected_id" == "$container_id" && "$host_pid" =~ ^[1-9][0-9]*$ &&
    -n "$started_at" && "$started_at" != "0001-01-01T00:00:00Z" &&
    -z "$extra" ]] || {
    log_error "$service runtime identity is invalid"
    return 1
  }
  {
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$host_pid"
    printf 'started_at=%s\n' "$started_at"
  } >"$output" || return $?
}

runtime_identity_field() {
  local -r identity="$1"
  local -r name="$2"
  local value=""
  local -i matches=0
  local line=""

  while IFS= read -r line; do
    if [[ "$line" == "$name="* ]]; then
      value="${line#*=}"
      ((matches += 1))
    fi
  done <"$identity"
  [[ "$matches" == "1" && -n "$value" ]] || return 1
  printf '%s\n' "$value"
}

assert_runtime_identity_replaced() {
  local -r before="$1"
  local -r after="$2"
  local before_container=""
  local before_started=""
  local after_container=""
  local after_started=""

  before_container="$(runtime_identity_field "$before" container_id)" || return 1
  before_started="$(runtime_identity_field "$before" started_at)" || return 1
  after_container="$(runtime_identity_field "$after" container_id)" || return 1
  after_started="$(runtime_identity_field "$after" started_at)" || return 1
  [[ "$before_container" != "$after_container" && "$before_started" != "$after_started" ]] || {
    log_error "Java recovery did not replace the failed JVM generation"
    return 1
  }
}

capture_service_logs_since() {
  local -r service="$1"
  local -r since="$2"
  local -r output="$3"

  run_bounded 30 \
    "${COMPOSE[@]}" logs --no-color --since "$since" "$service" >"$output"
}

assert_log_message_count() {
  local -r input="$1"
  local -r message="$2"
  local -r expected="$3"
  local count=""

  count="$(awk -v message="$message" \
    'index($0, message) != 0 { count++ } END { print count + 0 }' "$input")"
  [[ "$count" == "$expected" ]] || {
    log_error "expected $expected log lines containing '$message', got $count"
    return 1
  }
}

assert_log_message_for_pid_count() {
  local -r input="$1"
  local -r message="$2"
  local -r host_pid="$3"
  local -r expected="$4"
  local count=""

  bounded_decimal "$host_pid" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  count="$(awk -v message="$message" -v pid="$host_pid" \
    'index($0, message) != 0 &&
      $0 ~ ("(^|[[:space:]])pid=" pid "([^0-9]|$)") { count++ }
    END { print count + 0 }' \
    "$input")"
  [[ "$count" == "$expected" ]] || {
    log_error "expected $expected log lines containing '$message' for pid=$host_pid, got $count"
    return 1
  }
}

next_scenario_seed() {
  local -r current="$1"

  bounded_decimal "$current" "$MAX_SHELL_INTEGER" true >/dev/null || return 1
  if [[ "$current" == "$MAX_SHELL_INTEGER" ]]; then
    printf '0\n'
  else
    printf '%d\n' "$((current + 1))"
  fi
}

next_java_attach_error_total() {
  local -r baseline="$1"
  local current=0

  if [[ "$baseline" != "absent" ]]; then
    current="$(bounded_decimal "$baseline" "$MAX_SHELL_INTEGER" true)" || return 1
  fi
  ((current < MAX_SHELL_INTEGER)) || return 1
  printf '%d\n' "$((current + 1))"
}

recover_helper_attach_failure_stack() {
  local -r propagation="$1"
  local -r label="$2"
  local -r transport="$3"
  local recovery_since=""

  CONTEXT_PROPAGATION="$propagation"
  export CONTEXT_PROPAGATION
  BRIDGE_TRANSPORT="$transport"
  export BRIDGE_TRANSPORT
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  recovery_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  log_info "replacing the failed JVM for $label propagation=$propagation"
  invalidate_selected_transport || return $?
  run_bounded 180 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "$label injected Java helper" \
    "$recovery_since" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "$label external OTel extension" \
    "$recovery_since" || return $?
  wait_for_log \
    java-backend \
    "OBI Java instrumentation ready" \
    "$label injected Java instrumentation" \
    "$recovery_since" || return $?
  wait_for_log \
    java-backend \
    "Jetty HTTPS backend ready on 127.0.0.1:18443" \
    "$label Jetty HTTPS backend" \
    "$recovery_since" || return $?
  wait_for_log \
    java-backend \
    "Netty HTTPS backend ready on 127.0.0.1:18444" \
    "$label Netty HTTPS backend" \
    "$recovery_since" || return $?
  wait_for_log \
    java-backend \
    "TLS boundary split HTTPS backend ready on 127.0.0.1:18445" \
    "$label TLS boundary split HTTPS backend" \
    "$recovery_since" || return $?
  wait_for_log \
    java-backend \
    "TLS boundary coalesced HTTPS backend ready on 127.0.0.1:18446" \
    "$label TLS boundary coalesced HTTPS backend" \
    "$recovery_since" || return $?
  BRIDGE_RUNNING=true
  assert_selected_transport "$transport" || return $?
  wait_for_apache_instrumentation "$label" || return $?
  wait_for_http "$APACHE_HTTPS_HEALTH_ENDPOINT" "$label HTTPS path" || return $?
}

run_helper_attach_failure_control() (
  local -r original_transport="$TRANSPORT"
  local -r original_propagation="$CONTEXT_PROPAGATION"
  local -r original_seed="$SCENARIO_SEED"
  local alternate_seed=""
  local attach_baseline=""
  local expected_attach_total=""
  local failed_java_pid=""
  local fault_since=""
  local restore_required=false
  local unexpected_log_status=0
  local -r obi_log="$RESULT_DIR/helper-attach-failure-obi.log"
  local -r java_log="$RESULT_DIR/helper-attach-failure-java.log"
  local -r baseline_metrics="$RESULT_DIR/helper-attach-failure-metrics-before.prom"
  local -r fault_metrics="$RESULT_DIR/helper-attach-failure-metrics-after.prom"
  local -r quiet_metrics="$RESULT_DIR/helper-attach-failure-metrics-quiet.prom"
  local -r recovery_metrics="$RESULT_DIR/helper-attach-failure-metrics-recovery.prom"
  local -r before_phase="helper-attach-failure-before"
  local -r after_phase="helper-attach-failure-after"
  local -r obi_identity_before="$RESULT_DIR/helper-attach-failure-obi-before.txt"
  local -r obi_identity_fault="$RESULT_DIR/helper-attach-failure-obi-fault.txt"
  local -r obi_identity_recovery="$RESULT_DIR/helper-attach-failure-obi-recovery.txt"
  local -r java_identity_fault="$RESULT_DIR/helper-attach-failure-java-fault.txt"
  local -r java_identity_after="$RESULT_DIR/helper-attach-failure-java-after-traffic.txt"
  local -r java_identity_recovery="$RESULT_DIR/helper-attach-failure-java-recovery.txt"

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  restore_helper_attach_failure_stack() {
    local -r status="$?"
    local restore_status=0
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    seal_terminal_java_diagnostics
    terminal_diagnostics_status=$?
    if [[ "$restore_required" == "true" ]]; then
      log_warn \
        "restoring the normal instrumented stack after helper attach failure control" || true
      (
        set -Eeuo pipefail
        recreate_instrumented_stack \
          "$original_propagation" \
          "helper attach failure cleanup" \
          "$original_transport"
      )
      restore_status=$?
      if ((restore_status != 0)); then
        log_error \
          "could not restore the instrumented stack after helper attach failure control" || true
      fi
    fi
    if ((status == 0 && restore_status != 0)); then
      exit "$restore_status"
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  trap restore_helper_attach_failure_stack EXIT
  [[ "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "helper attach failure control requires a healthy running bridge"
    return 1
  }
  alternate_seed="$(next_scenario_seed "$original_seed")" || return $?

  restore_required=true
  SCENARIO_VARIANT="helper-attach-bridge-disabled"
  SCENARIO_SEED="$alternate_seed"
  run_disabled_control || return $?
  capture_control_response "helper-attach-bridge-disabled" || return $?
  SCENARIO_VARIANT=""

  recreate_instrumented_stack \
    "$original_propagation" \
    "helper attach failure preparation" \
    "$original_transport" || return $?
  plan_obi_metric_pair_capture helper-attach-rejection || return $?
  capture_phase_evidence "$before_phase" || return $?
  capture_service_runtime_identity obi "$obi_identity_before" || return $?
  fetch_obi_metrics "$baseline_metrics" || return $?
  attach_baseline="$(java_attach_error_total "$baseline_metrics")" || {
    log_error "helper attach failure baseline metric is malformed"
    return 1
  }
  expected_attach_total="$(next_java_attach_error_total "$attach_baseline")" || {
    log_error "helper attach failure baseline metric cannot be incremented"
    return 1
  }

  export BRIDGE_TRANSPORT="$original_transport"
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="$HELPER_ATTACH_FAILURE_JAVA_TOOL_OPTIONS"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  invalidate_selected_transport || return $?
  run_bounded 30 "${COMPOSE[@]}" config \
    >"$RESULT_DIR/compose-helper-attach-failure.yaml" || return $?
  fault_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  log_info "replacing the JVM with dynamic agent loading disabled"
  run_bounded 180 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "helper attach failure external OTel extension" \
    "$fault_since" || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "helper attach failure HTTPS path" || return $?
  capture_service_runtime_identity \
    java-backend "$java_identity_fault" || return $?
  failed_java_pid="$(runtime_identity_field \
    "$java_identity_fault" host_pid)" || return $?

  wait_for_log \
    obi \
    "couldn't attach OpenTelemetry eBPF Java Agent" \
    "rejected dynamic Java helper attach" \
    "$fault_since" || return $?
  wait_for_log \
    obi \
    "unable to attach java agent to process, Java TLS telemetry will not work" \
    "attributed Java helper attach failure" \
    "$fault_since" || return $?
  wait_for_java_attach_error_total \
    "$expected_attach_total" \
    "$attach_baseline" \
    "$fault_metrics" \
    "helper attach failure" || return $?
  write_metrics_delta \
    "$baseline_metrics" \
    "$fault_metrics" \
    "$RESULT_DIR/helper-attach-failure-metrics.delta" || return $?
  capture_phase_evidence "$after_phase" || return $?
  record_obi_metric_pair \
    helper-attach-rejection "$before_phase" "$after_phase" same_process "" \
    >/dev/null || return $?

  capture_service_runtime_identity obi "$obi_identity_fault" || return $?
  cmp -- "$obi_identity_before" "$obi_identity_fault" || return $?
  BRIDGE_RUNNING=true
  wait_for_apache_instrumentation helper-attach-failure || return $?
  capture_service_logs_since obi "$fault_since" "$obi_log" || return $?
  capture_service_logs_since \
    java-backend "$fault_since" "$java_log" || return $?
  assert_runtime_contract helper-attach-fault || return $?

  capture_control_response "helper-attach-failure" || return $?
  cmp \
    "$RESULT_DIR/helper-attach-bridge-disabled-response.normalized.json" \
    "$RESULT_DIR/helper-attach-failure-response.normalized.json" || return $?
  cmp \
    "$RESULT_DIR/helper-attach-bridge-disabled-response.status" \
    "$RESULT_DIR/helper-attach-failure-response.status" || return $?

  SCENARIO_VARIANT="helper-unavailable"
  run_scenario \
    helper-attach-failure false full none helper-unavailable
  run_scenario w3c false full none helper-unavailable
  SCENARIO_VARIANT=""
  capture_service_runtime_identity \
    java-backend "$java_identity_after" || return $?
  cmp -- "$java_identity_fault" "$java_identity_after" || return $?
  wait_for_java_attach_error_total \
    "$expected_attach_total" \
    "$expected_attach_total" \
    "$quiet_metrics" \
    "helper attach failure quiet window" \
    3 || return $?

  capture_service_logs_since obi "$fault_since" "$obi_log" || return $?
  capture_service_logs_since \
    java-backend "$fault_since" "$java_log" || return $?
  assert_log_message_count \
    "$obi_log" \
    "injecting OpenTelemetry eBPF instrumentation for Java process" \
    1 || return $?
  assert_log_message_count \
    "$obi_log" \
    "couldn't attach OpenTelemetry eBPF Java Agent" \
    1 || return $?
  assert_log_message_count \
    "$obi_log" \
    "unable to attach java agent to process, Java TLS telemetry will not work" \
    1 || return $?
  assert_log_message_for_pid_count \
    "$obi_log" \
    "injecting OpenTelemetry eBPF instrumentation for Java process" \
    "$failed_java_pid" \
    1 || return $?
  assert_log_message_for_pid_count \
    "$obi_log" \
    "couldn't attach OpenTelemetry eBPF Java Agent" \
    "$failed_java_pid" \
    1 || return $?
  assert_log_message_for_pid_count \
    "$obi_log" \
    "unable to attach java agent to process, Java TLS telemetry will not work" \
    "$failed_java_pid" \
    1 || return $?
  assert_log_message_count \
    "$java_log" \
    "OBI remote-parent propagator enabled" \
    1 || return $?
  assert_log_message_count \
    "$java_log" "OBI remote-parent compatibility " 1 || return $?
  grep -F "OBI remote-parent compatibility " "$java_log" |
    grep -Fq "supported=true" || return $?
  if grep -Eq \
    'OBI remote-parent (provider ready|transport configuration)|OBI Java instrumentation ready' \
    "$java_log"; then
    log_error "helper attach failure JVM unexpectedly loaded the injected helper"
    return 1
  else
    unexpected_log_status=$?
  fi
  if ((unexpected_log_status != 1)); then
    log_error "could not verify that the failed JVM omitted helper readiness logs"
    return "$unexpected_log_status"
  fi
  grep -Fq "reason=bridge_lookup_missing" "$java_log" || return $?

  curl --fail --silent --show-error --max-time 5 \
    --cacert "$CERT_DIR/ca.crt" \
    "https://127.0.0.1:18443/obi-diagnostics" \
    >"$RESULT_DIR/helper-attach-failure-java-diagnostics.txt" || return $?
  cmp -s \
    "$RESULT_DIR/helper-attach-failure-java-diagnostics.txt" \
    <(printf 'unavailable\n') || {
    log_error "helper attach failure diagnostics did not report unavailable"
    return 1
  }
  capture_terminal_java_diagnostics_recovery_boundary || return $?
  recover_helper_attach_failure_stack \
    "$original_propagation" \
    "helper-attach-recovery" \
    "$original_transport" || return $?
  restore_required=false
  capture_service_runtime_identity \
    java-backend "$java_identity_recovery" || return $?
  assert_runtime_identity_replaced \
    "$java_identity_fault" "$java_identity_recovery" || return $?
  capture_service_runtime_identity obi "$obi_identity_recovery" || return $?
  cmp -- "$obi_identity_before" "$obi_identity_recovery" || return $?
  wait_for_java_attach_error_total \
    "$expected_attach_total" \
    "$expected_attach_total" \
    "$recovery_metrics" \
    "helper attach recovery" \
    3 || return $?
  capture_java_diagnostics helper-attach-recovery || return $?
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/helper-attach-recovery/java-diagnostics.txt" || return $?
  capture_control_response "helper-attach-recovery" || return $?
  cmp \
    "$RESULT_DIR/helper-attach-bridge-disabled-response.normalized.json" \
    "$RESULT_DIR/helper-attach-recovery-response.normalized.json" || return $?
  cmp \
    "$RESULT_DIR/helper-attach-bridge-disabled-response.status" \
    "$RESULT_DIR/helper-attach-recovery-response.status" || return $?

  SCENARIO_VARIANT="helper-attach-recovery"
  run_scenario basic
  SCENARIO_VARIANT=""
  SCENARIO_SEED="$original_seed"

  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
  return 0
)

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
  local recovery_boundary_status=0
  local recovery_status=0
  local terminal_diagnostics_status=0

  if [[ "$SELECTED_TRANSPORT" != "unix" ]]; then
    recreate_instrumented_stack \
      "tcp" "matching W3C and OBI preparation" unix || return $?
  fi
  stop_obi_for_no_state_control "w3c-match" || return $?
  run_scenario w3c-match true full matching || return $?
  if [[ "$SCENARIO" == "all" || "$KEEP_RUNNING" == "true" ]]; then
    if capture_terminal_java_diagnostics_recovery_boundary; then
      :
    else
      recovery_boundary_status=$?
      if seal_terminal_java_diagnostics; then
        :
      else
        terminal_diagnostics_status=$?
      fi
    fi
    if recreate_instrumented_stack \
      "tcp" "post-match bridge restoration" "$original_transport"; then
      recovery_status=0
    else
      recovery_status=$?
    fi
    if ((recovery_boundary_status != 0)); then
      return "$recovery_boundary_status"
    fi
    if ((recovery_status != 0)); then
      if seal_terminal_java_diagnostics; then
        :
      else
        terminal_diagnostics_status=$?
      fi
      return "$recovery_status"
    fi
    commit_terminal_java_diagnostics_recovery_boundary || return $?
    clear_terminal_java_diagnostics_recovery_boundary || return $?
  fi
  return "$terminal_diagnostics_status"
}

capture_w3c_fault_bridge_log() {
  local -r fault_log="$1"
  local capture_status=0

  if run_bounded 15 \
    "${COMPOSE[@]}" logs --no-color bridge-fault >"$fault_log"; then
    return 0
  else
    capture_status=$?
  fi
  log_error "could not capture the W3C fault bridge log"
  return "$capture_status"
}

stop_w3c_fault_bridge() {
  local stop_status=0

  [[ "$FAULT_BRIDGE_RUNNING" == "true" ]] || return 0
  if run_bounded 30 "${COMPOSE[@]}" stop --timeout 5 bridge-fault; then
    FAULT_BRIDGE_RUNNING=false
    return 0
  else
    stop_status=$?
  fi
  return "$stop_status"
}

abort_w3c_fault_mode() {
  local -r primary_status="$1"
  local -r fault_log="$2"
  local -r capture_log="$3"
  local cleanup_status=0
  local terminal_diagnostics_status=0

  if seal_terminal_java_diagnostics; then
    :
  else
    terminal_diagnostics_status=$?
  fi

  if [[ "$capture_log" == "true" ]] && \
    ! capture_w3c_fault_bridge_log "$fault_log"; then
    cleanup_status=1
  fi
  if ! stop_w3c_fault_bridge; then
    log_error "could not stop the W3C fault bridge after a mode failure"
    cleanup_status=1
  fi
  if ((primary_status != 0)); then
    return "$primary_status"
  fi
  if ((cleanup_status == 0 && terminal_diagnostics_status != 0)); then
    return "$terminal_diagnostics_status"
  fi
  return "$cleanup_status"
}

run_w3c_fault_control() {
  local -r diagnostics_baseline="$RESULT_DIR/phases/w3c-fault-pre-stop/java-diagnostics.txt"
  local -r stopped_diagnostics="$RESULT_DIR/phases/w3c-fault-obi-stopped/java-diagnostics.txt"
  local fault_log=""
  local expected_requests=""
  local stale=""
  local malformed=""
  local observed=""
  local control_status=0
  local recovery_boundary_status=0
  local recovery_status=0
  local terminal_diagnostics_status=0
  local -a fault_modes=(
    alternating timeout disconnect overload truncated bad-magic bad-size
    version-mismatch zero-trace-id zero-span-id
  )

  [[ "$TRANSPORT" == "unix" && "$SELECTED_TRANSPORT" == "unix" ]] || {
    log_error "the W3C malformed/stale control requires the forced Unix transport"
    return 1
  }
  W3C_FAULT_DIAGNOSTICS_PREVIOUS=""
  ensure_java_diagnostics_phase_directory w3c-fault-pre-stop || return $?
  if ! stop_obi_for_no_state_control "w3c-fault" "$diagnostics_baseline"; then
    return 1
  fi
  # The required post-stop diagnostics probe is itself instrumented. Start the
  # fault-mode chain after that probe so every delta remains attributable only
  # to its controlled responder request.
  W3C_FAULT_DIAGNOSTICS_PREVIOUS="$stopped_diagnostics"
  for FAULT_MODE in "${fault_modes[@]}"; do
    FAULT_REQUEST_COUNT=1
    if [[ "$FAULT_MODE" == "alternating" ]]; then
      FAULT_REQUEST_COUNT=2
    fi
    export FAULT_MODE
    fault_log="$RESULT_DIR/w3c-fault-$FAULT_MODE-bridge.log"
    log_info "starting bounded Unix fault responder mode=$FAULT_MODE"
    FAULT_BRIDGE_RUNNING=true
    if run_bounded 60 \
      "${COMPOSE[@]}" up --detach --no-deps --force-recreate bridge-fault; then
      :
    else
      control_status=$?
      abort_w3c_fault_mode "$control_status" "$fault_log" true || return $?
      return 1
    fi
    if wait_for_log \
      bridge-fault \
      "mode=$FAULT_MODE" \
      "Unix fault responder mode=$FAULT_MODE"; then
      :
    else
      control_status=$?
      abort_w3c_fault_mode "$control_status" "$fault_log" true || return $?
      return 1
    fi
    if run_scenario w3c-fault; then
      :
    else
      control_status=$?
      abort_w3c_fault_mode "$control_status" "$fault_log" true || return $?
      return 1
    fi
    if capture_w3c_fault_bridge_log "$fault_log"; then
      :
    else
      control_status=$?
      abort_w3c_fault_mode "$control_status" "$fault_log" false || return $?
      return 1
    fi
    expected_requests="$(scenario_request_count w3c-fault)"
    expected_requests="$((expected_requests * REPEAT_COUNT))"
    if [[ "$FAULT_MODE" == "alternating" ]]; then
      stale="$(awk '/operation=take status=stale/ { count++ } END { print count + 0 }' "$fault_log")"
      malformed="$(awk '/operation=take status=malformed/ { count++ } END { print count + 0 }' "$fault_log")"
      if [[ "$stale" != "$(((expected_requests + 1) / 2))" || \
        "$malformed" != "$((expected_requests / 2))" ]]; then
        log_error "fault responder expected stale=$(((expected_requests + 1) / 2)) malformed=$((expected_requests / 2)), got stale=$stale malformed=$malformed"
        abort_w3c_fault_mode 1 "$fault_log" false || return $?
        return 1
      fi
    else
      observed="$(awk -v wanted="$FAULT_MODE" \
        '$0 ~ ("operation=take status=" wanted) { count++ } END { print count + 0 }' \
        "$fault_log")"
      if [[ "$observed" != "$expected_requests" ]]; then
        log_error "fault responder mode=$FAULT_MODE expected requests=$expected_requests, got $observed"
        abort_w3c_fault_mode 1 "$fault_log" false || return $?
        return 1
      fi
    fi
    if ! sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS"; then
      abort_w3c_fault_mode 1 "$fault_log" false || return $?
      return 1
    fi
  done
  stop_w3c_fault_bridge || return $?
  FAULT_MODE="alternating"
  FAULT_REQUEST_COUNT=2
  W3C_FAULT_DIAGNOSTICS_PREVIOUS=""
  export FAULT_MODE
  if capture_terminal_java_diagnostics_recovery_boundary; then
    :
  else
    recovery_boundary_status=$?
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
  fi
  if recreate_instrumented_stack "tcp" "post-fault bridge recovery"; then
    recovery_status=0
  else
    recovery_status=$?
  fi
  if ((recovery_boundary_status != 0)); then
    return "$recovery_boundary_status"
  fi
  if ((recovery_status != 0)); then
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
    return "$recovery_status"
  fi
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  clear_terminal_java_diagnostics_recovery_boundary || return $?
  return "$terminal_diagnostics_status"
}

run_primary_w3c_stale_control() {
  local -r original_retrieval_ttl="$REMOTE_PARENT_RETRIEVAL_TTL"
  local control_status=0
  local recovery_boundary_status=0
  local recovery_status=0
  local terminal_diagnostics_status=0

  [[ "$TRANSPORT" == "getsockopt" && "$SELECTED_TRANSPORT" == "getsockopt" ]] || {
    log_error "the primary W3C stale control requires forced getsockopt transport"
    return 1
  }

  log_info "recreating the forced primary bridge with retrieval TTL=$PRIMARY_W3C_STALE_RETRIEVAL_TTL"
  REMOTE_PARENT_RETRIEVAL_TTL="$PRIMARY_W3C_STALE_RETRIEVAL_TTL"
  export REMOTE_PARENT_RETRIEVAL_TTL
  if recreate_instrumented_stack "tcp" "primary W3C stale preparation" getsockopt; then
    if run_scenario primary-w3c-stale; then
      :
    else
      control_status=$?
    fi
  else
    control_status=$?
  fi
  if ((control_status != 0)); then
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
  elif capture_terminal_java_diagnostics_recovery_boundary; then
    :
  else
    recovery_boundary_status=$?
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
  fi

  REMOTE_PARENT_RETRIEVAL_TTL="$original_retrieval_ttl"
  export REMOTE_PARENT_RETRIEVAL_TTL
  if recreate_instrumented_stack "tcp" "post-primary W3C stale recovery" getsockopt; then
    if SCENARIO_VARIANT="primary-w3c-stale-recovery" run_scenario basic; then
      :
    else
      recovery_status=$?
    fi
  else
    recovery_status=$?
  fi

  if ((control_status != 0)); then
    return "$control_status"
  fi
  if ((recovery_boundary_status != 0)); then
    return "$recovery_boundary_status"
  fi
  if ((recovery_status != 0)); then
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
    return "$recovery_status"
  fi
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  clear_terminal_java_diagnostics_recovery_boundary || return $?
  return "$terminal_diagnostics_status"
}

run_unix_w3c_stale_control() {
  local -r original_retrieval_ttl="$REMOTE_PARENT_RETRIEVAL_TTL"
  local control_status=0
  local recovery_boundary_status=0
  local recovery_status=0
  local terminal_diagnostics_status=0

  [[ "$TRANSPORT" == "unix" && "$SELECTED_TRANSPORT" == "unix" ]] || {
    log_error "the Unix W3C stale control requires forced Unix transport"
    return 1
  }

  log_info "recreating the forced Unix bridge with retrieval TTL=$UNIX_W3C_STALE_RETRIEVAL_TTL"
  REMOTE_PARENT_RETRIEVAL_TTL="$UNIX_W3C_STALE_RETRIEVAL_TTL"
  export REMOTE_PARENT_RETRIEVAL_TTL
  if recreate_instrumented_stack "tcp" "Unix W3C stale preparation" unix; then
    if run_scenario unix-w3c-stale; then
      :
    else
      control_status=$?
    fi
  else
    control_status=$?
  fi
  if ((control_status != 0)); then
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
  elif capture_terminal_java_diagnostics_recovery_boundary; then
    :
  else
    recovery_boundary_status=$?
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
  fi

  REMOTE_PARENT_RETRIEVAL_TTL="$original_retrieval_ttl"
  export REMOTE_PARENT_RETRIEVAL_TTL
  if recreate_instrumented_stack "tcp" "post-Unix W3C stale recovery" unix; then
    if SCENARIO_VARIANT="unix-w3c-stale-recovery" run_scenario basic; then
      :
    else
      recovery_status=$?
    fi
  else
    recovery_status=$?
  fi

  if ((control_status != 0)); then
    return "$control_status"
  fi
  if ((recovery_boundary_status != 0)); then
    return "$recovery_boundary_status"
  fi
  if ((recovery_status != 0)); then
    if seal_terminal_java_diagnostics; then
      :
    else
      terminal_diagnostics_status=$?
    fi
    return "$recovery_status"
  fi
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  clear_terminal_java_diagnostics_recovery_boundary || return $?
  return "$terminal_diagnostics_status"
}

primary_w3c_fault_expected_java_status() {
  local -r mode="$1"

  case "$mode" in
    version-mismatch)
      printf 'version_mismatch\n'
      ;;
    bad-size|zero-trace-id|zero-span-id)
      printf 'malformed\n'
      ;;
    generation-mismatch)
      printf 'missing\n'
      ;;
    *)
      return 1
      ;;
  esac
}

arm_primary_w3c_fault_control() {
  local -r mode="$1"
  local -r output="$2"

  primary_w3c_fault_expected_java_status "$mode" >/dev/null || {
    log_error "unsupported primary W3C fault mode: $mode"
    return 1
  }
  [[ "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]] || {
    log_error "cannot arm the primary W3C fault control outside its fault stack"
    return 1
  }
  [[ ! -e "$output" && ! -L "$output" ]] || {
    log_error "refusing to overwrite primary W3C fault evidence: $output"
    return 1
  }

  # shellcheck disable=SC2016 # The control values are positional parameters in the Java container.
  run_bounded 15 "${PRIMARY_FAULT_COMPOSE[@]}" exec --no-TTY --user 0:0 \
    java-backend /bin/sh -ec '
      set -eu
      directory=$1
      control_file=$2
      mode=$3

      case "$mode" in
        version-mismatch|bad-size|zero-trace-id|zero-span-id) ;;
        *) exit 64 ;;
      esac
      [ "$control_file" = "$directory/java-remote-parent.mode" ]
      [ "$(id -u)" = 0 ]
      [ -d "$directory" ] && [ ! -L "$directory" ]
      [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
      [ ! -e "$control_file" ] && [ ! -L "$control_file" ]

      umask 077
      temporary=$(mktemp "$directory/.java-remote-parent.mode.XXXXXX")
      cleanup() {
        [ -z "${temporary:-}" ] || rm -f -- "$temporary"
      }
      trap cleanup EXIT HUP INT TERM
      printf "%s\\n" "$mode" >"$temporary"
      chmod 0600 -- "$temporary"
      [ -f "$temporary" ] && [ ! -L "$temporary" ]
      [ "$(stat -c "%u:%g:%a:%h" "$temporary")" = "0:0:600:1" ]
      mv -T -- "$temporary" "$control_file"
      temporary=
      trap - EXIT HUP INT TERM
      [ -f "$control_file" ] && [ ! -L "$control_file" ]
      [ "$(stat -c "%u:%g:%a:%h" "$control_file")" = "0:0:600:1" ]
      [ "$(cat "$control_file")" = "$mode" ]
      printf "phase=armed\nmode=%s\nmetadata=%s\nsize=%s\n" \
        "$mode" "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" \
        "$(stat -c "%s" "$control_file")"
    ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE" "$mode" \
    >"$output"
}

consume_primary_w3c_fault_control() {
  local -r output="$1"

  [[ "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]] || {
    log_error "cannot inspect the primary W3C fault control outside its fault stack"
    return 1
  }
  [[ ! -e "$output" && ! -L "$output" ]] || {
    log_error "refusing to overwrite primary W3C fault evidence: $output"
    return 1
  }

  # shellcheck disable=SC2016 # The control values are positional parameters in the Java container.
  run_bounded 15 "${PRIMARY_FAULT_COMPOSE[@]}" exec --no-TTY --user 0:0 \
    java-backend /bin/sh -ec '
      set -eu
      directory=$1
      control_file=$2

      [ "$control_file" = "$directory/java-remote-parent.mode" ]
      [ "$(id -u)" = 0 ]
      [ -d "$directory" ] && [ ! -L "$directory" ]
      [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
      [ -f "$control_file" ] && [ ! -L "$control_file" ]
      [ "$(stat -c "%u:%g:%a:%h" "$control_file")" = "0:0:600:1" ]
      [ ! -s "$control_file" ]
      printf "phase=consumed\nmetadata=%s\nsize=%s\n" \
        "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" \
        "$(stat -c "%s" "$control_file")"
      rm -f -- "$control_file"
      [ ! -e "$control_file" ] && [ ! -L "$control_file" ]
    ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE" \
    >"$output"
}

primary_live_fd_descriptor() {
  local -r raw="$1"
  local normalized=""

  normalized="$(bounded_decimal "$raw" "2147483647" true)" || return 1
  [[ "$normalized" == "$raw" ]] || return 1
  printf '%s\n' "$normalized"
}

arm_java_fault_control() {
  local -r output="$1"
  local -r stack="$2"
  local -r mode="$3"
  local -a compose_command=()

  case "$stack" in
    primary-live-fd)
      compose_command=("${PRIMARY_LIVE_FD_COMPOSE[@]}")
      ;;
    primary-fault)
      compose_command=("${PRIMARY_FAULT_COMPOSE[@]}")
      ;;
    unix-generation-fault)
      compose_command=("${UNIX_GENERATION_FAULT_COMPOSE[@]}")
      ;;
    *)
      return 1
      ;;
  esac
  [[ "$mode" == "live-fd-barrier" || \
    "$mode" == "unix-generation-barrier" ]] || return 1

  [[ "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]] || {
    log_error "cannot arm the primary live-descriptor barrier outside its fault stack"
    return 1
  }
  [[ ! -e "$output" && ! -L "$output" ]] || {
    log_error "refusing to overwrite primary live-descriptor barrier evidence: $output"
    return 1
  }

  # shellcheck disable=SC2016 # The fixed paths are positional parameters in the Java container.
  run_bounded 15 "${compose_command[@]}" exec --no-TTY --user 0:0 \
    java-backend /bin/sh -ec '
      set -eu
      directory=$1
      control_file=$2
      mode=$3

      [ "$control_file" = "$directory/java-remote-parent.mode" ]
      [ "$(id -u)" = 0 ]
      [ -d "$directory" ] && [ ! -L "$directory" ]
      [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
      [ ! -e "$control_file" ] && [ ! -L "$control_file" ]

      umask 077
      temporary=$(mktemp "$directory/.java-remote-parent.mode.XXXXXX")
      cleanup() {
        [ -z "${temporary:-}" ] || rm -f -- "$temporary"
      }
      trap cleanup EXIT HUP INT TERM
      printf "%s\\n" "$mode" >"$temporary"
      chmod 0600 -- "$temporary"
      [ -f "$temporary" ] && [ ! -L "$temporary" ]
      [ "$(stat -c "%u:%g:%a:%h" "$temporary")" = "0:0:600:1" ]
      mv -T -- "$temporary" "$control_file"
      temporary=
      trap - EXIT HUP INT TERM
      [ -f "$control_file" ] && [ ! -L "$control_file" ]
      [ "$(stat -c "%u:%g:%a:%h" "$control_file")" = "0:0:600:1" ]
      [ "$(cat "$control_file")" = "$mode" ]
      printf "phase=armed\\nmetadata=%s\\nsize=%s\\n" \
        "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" \
        "$(stat -c "%s" "$control_file")"
    ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE" "$mode" \
    >"$output"
}

arm_primary_live_fd_barrier() {
  arm_java_fault_control "$1" "${2:-primary-live-fd}" live-fd-barrier
}

arm_unix_generation_barrier() {
  arm_java_fault_control "$1" unix-generation-fault unix-generation-barrier
}

read_java_fault_control() {
  local -r java_container="$1"

  [[ "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]] || return 1
  [[ -n "$java_container" ]] || return 1

  # shellcheck disable=SC2016 # The fixed paths are positional parameters in the Java container.
  run_bounded 5 docker exec --user 0:0 "$java_container" /bin/sh -ec '
    set -eu
    directory=$1
    control_file=$2
    value=
    size=

    [ "$control_file" = "$directory/java-remote-parent.mode" ]
    [ "$(id -u)" = 0 ]
    [ -d "$directory" ] && [ ! -L "$directory" ]
    [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
    [ -f "$control_file" ] && [ ! -L "$control_file" ]
    [ "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" = "0:0:600:1:regular file" ]
    size="$(stat -c "%s" "$control_file")"
    case "$size" in
      ""|*[!0-9]*) exit 65 ;;
    esac
    [ "$size" -lt 96 ] || exit 65
    if IFS= read -r value <"$control_file"; then
      printf "%s\\n" "$value"
    fi
  ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE"
}

read_primary_live_fd_barrier() {
  read_java_fault_control "$1"
}

read_unix_generation_barrier() {
  read_java_fault_control "$1"
}

wait_for_unix_generation_barrier_ready() {
  local -r java_container="$1"
  local -r victim_pid="$2"
  local value=""
  local -i started_at="$SECONDS"

  while ((SECONDS - started_at < UNIX_GENERATION_BARRIER_READY_TIMEOUT_SECONDS)); do
    value="$(read_unix_generation_barrier "$java_container")" || return $?
    case "$value" in
      ""|unix-generation-barrier) ;;
      ready:unix-generation) return 0 ;;
      *)
        log_error "Unix generation barrier returned an unexpected state"
        return 1
        ;;
    esac
    background_process_is_running "$victim_pid" || {
      log_error "Unix generation victim exited before reaching its barrier"
      return 1
    }
    sleep 0.1
  done
  log_error "timed out waiting for the Unix generation barrier"
  return 1
}

release_unix_generation_barrier() {
  local -r java_container="$1"
  local -r output="$2"
  local -r timeout_seconds="${3:-$PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS}"

  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  [[ "$PRIMARY_FAULT_STACK_ACTIVE" == "true" && \
    ! -e "$output" && ! -L "$output" ]] || return 1
  # shellcheck disable=SC2016 # Fixed trusted paths are positional parameters.
  run_bounded "$timeout_seconds" docker exec --user 0:0 "$java_container" /bin/sh -ec '
    set -eu
    directory=$1
    control_file=$2
    [ "$control_file" = "$directory/java-remote-parent.mode" ]
    [ "$(id -u)" = 0 ]
    [ -d "$directory" ] && [ ! -L "$directory" ]
    [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
    [ -f "$control_file" ] && [ ! -L "$control_file" ]
    [ "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" = "0:0:600:1:regular file" ]
    [ "$(cat "$control_file")" = ready:unix-generation ]
    before="$(stat -c "%d:%i:%u:%g:%a:%h" "$control_file")"
    printf "release:unix-generation\\n" >"$control_file"
    after="$(stat -c "%d:%i:%u:%g:%a:%h" "$control_file")"
    [ "$before" = "$after" ]
    printf "phase=released\\nmetadata=%s\\nsize=%s\\n" \
      "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" \
      "$(stat -c "%s" "$control_file")"
  ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE" >"$output"
}

wait_for_primary_live_fd_barrier_ready() {
  local -r java_container="$1"
  local -r victim_pid="$2"
  local value=""
  local descriptor=""
  local -i started_at="$SECONDS"

  while ((SECONDS - started_at < PRIMARY_LIVE_FD_BARRIER_READY_TIMEOUT_SECONDS)); do
    value="$(read_primary_live_fd_barrier "$java_container")" || {
      log_error "could not read the primary live-descriptor barrier"
      return 1
    }
    case "$value" in
      ""|live-fd-barrier)
        ;;
      ready:*)
        [[ "$value" =~ ^ready:([0-9]+):task=missing:thread=missing$ ]] || {
          log_error "primary live-descriptor barrier did not prove both same-FD execution misses"
          return 1
        }
        descriptor="$(primary_live_fd_descriptor "${BASH_REMATCH[1]}")" || {
          log_error "primary live-descriptor barrier returned an invalid descriptor"
          return 1
        }
        printf '%s\n' "$descriptor"
        return 0
        ;;
      *)
        log_error "primary live-descriptor barrier returned an unexpected state"
        return 1
        ;;
    esac
    if ! background_process_is_running "$victim_pid"; then
      log_error "primary live-descriptor victim exited before reaching its barrier"
      return 1
    fi
    sleep 0.1
  done
  log_error "timed out waiting for the primary live-descriptor barrier"
  return 1
}

primary_live_fd_remaining_timeout() {
  local -r deadline="$1"
  local -r maximum="$2"
  local -r reserve="$3"
  local -i remaining=0

  [[ "$deadline" =~ ^[1-9][0-9]*$ && "$maximum" =~ ^[1-9][0-9]*$ && \
    "$reserve" =~ ^[0-9]+$ ]] || return 1
  ((remaining = deadline - SECONDS, remaining > reserve)) || return 1
  ((remaining -= reserve))
  if ((remaining > maximum)); then
    remaining="$maximum"
  fi
  printf '%d\n' "$remaining"
}

run_primary_live_fd_probe() {
  local -r java_container="$1"
  local -r descriptor="$2"
  local -r timeout_seconds="$3"
  local -r output="$4"

  primary_live_fd_descriptor "$descriptor" >/dev/null || return 1
  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  [[ -n "$java_container" && -f "$output" && ! -L "$output" && ! -s "$output" ]] || return 1

  # The cgroup comparison and preload clearing occur in the exact root process
  # that execs the probe, so an adjacent diagnostic process cannot certify it.
  # shellcheck disable=SC2016 # Fixed values are positional parameters in the Java container.
  run_bounded "$timeout_seconds" docker exec --user 0:0 "$java_container" \
    env -u LD_PRELOAD -u OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE /bin/sh -ec '
      set -eu
      probe_path=$1
      descriptor=$2
      probe_timeout=$3
      process_name=
      self_cgroup=
      pid_one_cgroup=

      case "$descriptor" in
        ""|*[!0-9]*) exit 64 ;;
      esac
      case "$probe_timeout" in
        ""|*[!0-9]*) exit 64 ;;
      esac
      [ "$(id -u)" = 0 ]
      [ -r /proc/1/comm ]
      IFS= read -r process_name </proc/1/comm
      [ "$process_name" = java ]
      self_cgroup="$(cat /proc/self/cgroup)"
      pid_one_cgroup="$(cat /proc/1/cgroup)"
      [ -n "$self_cgroup" ] && [ "$self_cgroup" = "$pid_one_cgroup" ]
      [ -f "$probe_path" ] && [ ! -L "$probe_path" ] && [ -x "$probe_path" ]
      exec "$probe_path" --mode primary-live-fd --fd "$descriptor" \
        --timeout "${probe_timeout}s"
    ' sh "$PRIMARY_SECURITY_PROBE_PATH" "$descriptor" "$timeout_seconds" \
    >"$output"
}

assert_primary_live_fd_probe_output() {
  local -r input="$1"

  [[ -s "$input" && -f "$input" && ! -L "$input" ]] || return 1
  [[ "$(wc -l <"$input")" == "1" ]] || return 1
  jq -e '
    type == "object" and
    ((keys | sort) == ["attempts", "cases", "mode", "status"]) and
    .status == "unverified" and
    .mode == "primary-live-fd" and
    .attempts == 1 and
    (.cases | type == "array" and length == 4 and
      all(.[]; try (
        type == "object" and
        ((keys | sort) == ["name", "outcome"]) and
        (.name | type == "string") and
        (.outcome | type == "string")
      ) catch false)) and
    ([.cases[] | select(.name == "pidfd-duplicate" and .outcome == "opened")] | length == 1) and
    ([.cases[] | select(.name == "standard-option" and .outcome == "preserved")] | length == 1) and
    ([.cases[] | select(.name == "wrong-process-negotiation" and .outcome == "native-unsupported")] | length == 1) and
    ([.cases[] | select(.name == "duplicated-fd-take" and .outcome == "native-unsupported")] | length == 1)
  ' "$input" >/dev/null
}

assert_primary_live_fd_probe_unsupported_output() {
  local -r input="$1"

  [[ -s "$input" && -f "$input" && ! -L "$input" ]] || return 1
  [[ "$(wc -l <"$input")" == "1" ]] || return 1
  jq -e '
    type == "object" and
    ((keys | sort) == ["cases", "mode", "status"]) and
    .status == "unsupported" and
    .mode == "primary-live-fd" and
    (.cases | type == "array" and length == 1 and
      all(.[]; try (
        type == "object" and
        ((keys | sort) == ["name", "outcome"]) and
        .name == "pidfd-duplicate" and
        .outcome == "unavailable"
      ) catch false))
  ' "$input" >/dev/null
}

release_primary_live_fd_barrier() {
  local -r java_container="$1"
  local -r descriptor="$2"
  local -r output="$3"
  local -r timeout_seconds="${4:-$PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS}"

  primary_live_fd_descriptor "$descriptor" >/dev/null || return 1
  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  [[ "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]] || {
    log_error "cannot release the primary live-descriptor barrier outside its fault stack"
    return 1
  }
  [[ ! -e "$output" && ! -L "$output" ]] || {
    log_error "refusing to overwrite primary live-descriptor release evidence: $output"
    return 1
  }

  # shellcheck disable=SC2016 # The fixed paths and validated descriptor are positional parameters.
  run_bounded "$timeout_seconds" docker exec --user 0:0 "$java_container" /bin/sh -ec '
    set -eu
    directory=$1
    control_file=$2
    descriptor=$3
    before=
    after=

    case "$descriptor" in
      ""|*[!0-9]*) exit 64 ;;
    esac
    [ "$control_file" = "$directory/java-remote-parent.mode" ]
    [ "$(id -u)" = 0 ]
    [ -d "$directory" ] && [ ! -L "$directory" ]
    [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
    [ -f "$control_file" ] && [ ! -L "$control_file" ]
    [ "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" = "0:0:600:1:regular file" ]
    [ "$(cat "$control_file")" = "ready:$descriptor:task=missing:thread=missing" ]
    before="$(stat -c "%d:%i:%u:%g:%a:%h" "$control_file")"
    printf "release:%s\\n" "$descriptor" >"$control_file"
    after="$(stat -c "%d:%i:%u:%g:%a:%h" "$control_file")"
    [ "$before" = "$after" ]
    printf "phase=released\\nmetadata=%s\\nsize=%s\\n" \
      "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" \
      "$(stat -c "%s" "$control_file")"
  ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE" "$descriptor" \
    >"$output"
}

consume_java_fault_control() {
  local -r output="$1"
  local -r stack="$2"
  local -a compose_command=()

  case "$stack" in
    primary-live-fd)
      compose_command=("${PRIMARY_LIVE_FD_COMPOSE[@]}")
      ;;
    primary-fault)
      compose_command=("${PRIMARY_FAULT_COMPOSE[@]}")
      ;;
    unix-generation-fault)
      compose_command=("${UNIX_GENERATION_FAULT_COMPOSE[@]}")
      ;;
    *)
      return 1
      ;;
  esac

  [[ "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]] || {
    log_error "cannot consume the primary live-descriptor barrier outside its fault stack"
    return 1
  }
  [[ ! -e "$output" && ! -L "$output" ]] || {
    log_error "refusing to overwrite primary live-descriptor consumption evidence: $output"
    return 1
  }

  # The initial -f test establishes the regular-file type. %F changes from
  # "regular file" to "regular empty file" when the trusted shim truncates
  # this exact inode, so ownership, mode, and link count are the stable
  # post-consumption metadata contract.
  # shellcheck disable=SC2016 # The fixed paths are positional parameters in the Java container.
  run_bounded 10 "${compose_command[@]}" exec --no-TTY --user 0:0 \
    java-backend /bin/sh -ec '
      set -eu
      directory=$1
      control_file=$2
      [ "$control_file" = "$directory/java-remote-parent.mode" ]
      [ "$(id -u)" = 0 ]
      [ -d "$directory" ] && [ ! -L "$directory" ]
      [ "$(stat -c "%u:%g:%a:%F" "$directory")" = "0:0:700:directory" ]
      [ -f "$control_file" ] && [ ! -L "$control_file" ]
      [ "$(stat -c "%u:%g:%a:%h" "$control_file")" = "0:0:600:1" ]
      [ ! -s "$control_file" ]
      printf "phase=consumed\\nmetadata=%s\\nsize=%s\\n" \
        "$(stat -c "%u:%g:%a:%h:%F" "$control_file")" \
        "$(stat -c "%s" "$control_file")"
      rm -f -- "$control_file"
      [ ! -e "$control_file" ] && [ ! -L "$control_file" ]
    ' sh "$PRIMARY_FAULT_CONTROL_DIRECTORY" "$PRIMARY_FAULT_CONTROL_FILE" \
    >"$output"
}

consume_primary_live_fd_barrier() {
  consume_java_fault_control "$1" "${2:-primary-live-fd}"
}

consume_unix_generation_barrier() {
  consume_java_fault_control "$1" unix-generation-fault
}

run_primary_w3c_fault_scenario() {
  local -r mode="$1"
  local run_number=0
  local label=""
  local output=""
  local stderr_output=""
  local before_phase=""
  local after_phase=""
  local before_diagnostics=""
  local after_diagnostics=""
  local diagnostics_delta=""
  local before_success=0
  local before_stage=0
  local expected_success=0
  local expected_stage=0
  local baseline_snapshot=""
  local arm_evidence=""
  local consumption_evidence=""
  local scenario_status=0
  local metric_status=0
  local status_name="passed"
  local control_armed=false

  primary_w3c_fault_expected_java_status "$mode" >/dev/null || {
    log_error "unsupported primary W3C fault mode: $mode"
    return 1
  }
  [[ "$BRIDGE_RUNNING" == "true" && "$SELECTED_TRANSPORT" == "getsockopt" && \
    "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]] || {
    log_error "primary W3C fault scenario requires the running forced primary fault stack"
    return 1
  }

  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    label="primary-w3c-fault-$mode"
    if ((REPEAT_COUNT > 1)); then
      printf -v label '%s-run-%02d' "$label" "$run_number"
    fi
    output="$RESULT_DIR/scenario-$label.json"
    stderr_output="$RESULT_DIR/scenario-$label.stderr.log"
    before_phase="$label-before"
    after_phase="$label-after"
    before_diagnostics="$RESULT_DIR/phases/$before_phase/java-diagnostics.txt"
    after_diagnostics="$RESULT_DIR/phases/$after_phase/java-diagnostics.txt"
    diagnostics_delta="$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"
    arm_evidence="$RESULT_DIR/primary-w3c-fault-$mode-run-$run_number-armed.txt"
    consumption_evidence="$RESULT_DIR/primary-w3c-fault-$mode-run-$run_number-consumed.txt"
    scenario_status=0
    metric_status=0
    status_name="passed"
    control_armed=false

    plan_obi_metric_pair_capture "$label" || return $?
    log_info "running $label scenario"
    mkdir -p -- "$RESULT_DIR/phases/$before_phase"
    if ! flush_bridge_metric_boundary "$label" 1 1 "$before_diagnostics"; then
      metric_status=1
    elif ! assert_sanitized_java_diagnostics "$before_diagnostics"; then
      log_error "primary W3C fault diagnostics baseline is invalid for $label"
      metric_status=1
    else
      baseline_snapshot="$(<"$before_diagnostics")"
    fi
    if ! capture_phase_evidence "$before_phase"; then
      metric_status=1
    fi
    before_success="$(bridge_success_total \
      "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
    before_stage="$(bridge_stage_total \
      "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
    if ((metric_status == 0)); then
      if arm_primary_w3c_fault_control "$mode" "$arm_evidence"; then
        control_armed=true
      else
        metric_status=1
      fi
    fi
    if [[ "$control_armed" == "true" ]]; then
      if run_bounded "$SCENARIO_RUN_TIMEOUT_SECONDS" \
        "${COMPOSE[@]}" run --rm --no-deps --no-TTY scenario \
          --scenario primary-w3c-fault \
          --expected-tls "$TLS_PROTOCOL" \
          --seed "$SCENARIO_SEED" \
          --requests 1 \
          --fault-mode "$mode" \
          --java-diagnostics-before "$baseline_snapshot" \
          --timeout 75s 2> >(tee "$stderr_output" >&2) | tee "$output"; then
        :
      else
        scenario_status=$?
      fi
      if ! consume_primary_w3c_fault_control "$consumption_evidence"; then
        log_error "primary W3C fault control was not consumed exactly once for $label"
        metric_status=1
      fi
    fi
    expected_success="$((before_success + 1))"
    expected_stage="$((before_stage + 1))"
    if ! wait_for_bridge_metrics_quiescent \
      "$expected_success" \
      "$expected_stage" \
      "$RESULT_DIR/metrics-after-$label.prom" \
      "$label scenario-attributable bridge operations"; then
      metric_status=1
    fi
    if ! capture_phase_evidence "$after_phase"; then
      metric_status=1
    fi
    if ! extract_fault_diagnostics_after "$output" "$after_diagnostics"; then
      log_error "could not extract primary W3C fault diagnostics for $label"
      metric_status=1
    elif ! write_java_diagnostics_delta \
      "$before_diagnostics" \
      "$after_diagnostics" \
      "$diagnostics_delta"; then
      log_error "could not compute primary W3C fault diagnostics for $label"
      metric_status=1
    elif ! assert_w3c_fault_diagnostics_delta "$diagnostics_delta" "$mode" 1; then
      log_error "primary W3C fault diagnostics were not exactly attributable for $label"
      metric_status=1
    fi
    if ! write_metrics_delta \
      "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
      "$RESULT_DIR/phases/$after_phase/obi-metrics.prom" \
      "$RESULT_DIR/phases/$after_phase/obi-metrics.delta"; then
      metric_status=1
    elif ! assert_bridge_metric_delta \
      "$RESULT_DIR/phases/$after_phase/obi-metrics.delta" \
      getsockopt 1 0 0 1 1 false 0; then
      metric_status=1
    fi
    if ! record_obi_metric_pair \
      "$label" "$before_phase" "$after_phase" same_process "$after_phase" \
      >/dev/null; then
      log_error "could not retain the primary W3C fault metric pair for $label"
      metric_status=1
    fi
    if ((scenario_status != 0 || metric_status != 0)); then
      status_name="failed"
    fi
    if ! printf '{\n  "status": "%s",\n  "scenario": "primary-w3c-fault",\n  "fault_mode": "%s",\n  "exit_status": %d,\n  "metric_status": %d,\n  "result": "%s",\n  "stderr": "%s",\n  "after_phase": "%s",\n  "fault_control_arm": "%s",\n  "fault_control_consumption": "%s"\n}\n' \
      "$status_name" \
      "$mode" \
      "$scenario_status" \
      "$metric_status" \
      "$(basename -- "$output")" \
      "$(basename -- "$stderr_output")" \
      "phases/$after_phase" \
      "$(basename -- "$arm_evidence")" \
      "$(basename -- "$consumption_evidence")" \
      >"$RESULT_DIR/scenario-$label-status.json"; then
      return 1
    fi
    crosslink_and_bind_active_obi_metric_boundary_status \
      "scenario-$label-status.json" || return $?
    log_info "$label status=$status_name evidence=$RESULT_DIR/scenario-$label-status.json"
    if ((scenario_status != 0)); then
      return "$scenario_status"
    fi
    if ((metric_status != 0)); then
      return "$metric_status"
    fi
  done
}

run_primary_w3c_fault_control() (
  local -r original_variant="$SCENARIO_VARIANT"
  local -r recovery_marker="$RESULT_DIR/primary-w3c-fault-recovery-required"
  local restore_required=false

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  restore_primary_w3c_fault_stack() {
    local -r status="$?"
    local restore_status=0
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    seal_terminal_java_diagnostics
    terminal_diagnostics_status=$?
    if [[ "$restore_required" == "true" ]]; then
      log_warn "restoring the normal instrumented stack after primary W3C fault control" || true
      (
        set -Eeuo pipefail
        recreate_instrumented_stack \
          tcp "post-primary W3C fault recovery" getsockopt true false base
        assert_runtime_contract basic true
      )
      restore_status=$?
      if ((restore_status == 0)); then
        if rm -f -- "$recovery_marker"; then
          PRIMARY_FAULT_STACK_ACTIVE=false
        else
          restore_status=$?
          log_error "could not clear the primary W3C fault recovery marker" || true
        fi
      else
        log_error "could not restore the instrumented stack after primary W3C fault control" || true
      fi
    fi
    SCENARIO_VARIANT="$original_variant"
    if ((status == 0 && restore_status != 0)); then
      exit "$restore_status"
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  trap restore_primary_w3c_fault_stack EXIT
  [[ "$TRANSPORT" == "getsockopt" && "$SELECTED_TRANSPORT" == "getsockopt" && \
    "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "the primary W3C fault control requires a healthy forced getsockopt bridge"
    return 1
  }
  [[ ! -e "$recovery_marker" && ! -L "$recovery_marker" ]] || {
    log_error "primary W3C fault recovery marker already exists: $recovery_marker"
    return 1
  }
  if ! (umask 077; printf 'recovery_required\n' >"$recovery_marker"); then
    log_error "could not create the primary W3C fault recovery marker"
    return 1
  fi

  restore_required=true
  PRIMARY_FAULT_STACK_ACTIVE=true
  recreate_instrumented_stack \
    tcp "primary W3C fault preparation" getsockopt true false primary-fault || return $?
  assert_runtime_contract primary-w3c-fault true || return $?

  for FAULT_MODE in version-mismatch bad-size zero-trace-id zero-span-id; do
    run_primary_w3c_fault_scenario "$FAULT_MODE" || return $?
  done
  FAULT_MODE="alternating"

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  recreate_instrumented_stack \
    tcp "post-primary W3C fault recovery" getsockopt true false base || return $?
  assert_runtime_contract basic true || return $?
  rm -f -- "$recovery_marker" || return $?
  PRIMARY_FAULT_STACK_ACTIVE=false
  restore_required=false
  SCENARIO_VARIANT="primary-w3c-fault-recovery"
  run_scenario basic
  SCENARIO_VARIANT="$original_variant"

  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
)

run_primary_live_fd_security_recovery_scenario() {
  local -r original_variant="$1"
  local scenario_status=0

  SCENARIO_VARIANT="security-primary-live-fd-recovery"
  if run_scenario basic; then
    scenario_status=0
  else
    scenario_status=$?
  fi
  SCENARIO_VARIANT="$original_variant"
  return "$scenario_status"
}

process_namespace_identity_from_snapshot() {
  local -r status_snapshot="$1"
  local -r expected_process_pid="$2"
  local process_pid=""
  local process_namespace=""

  bounded_decimal "$expected_process_pid" "$MAX_UINT32_DECIMAL" false >/dev/null || return 1
  read -r process_pid process_namespace < <(
    LC_ALL=C awk -v expected_process_pid="$expected_process_pid" '
      $1 == "Tgid:" {
        tgid_count++
        if (NF != 2 || $2 !~ /^[1-9][0-9]*$/ || $2 != expected_process_pid) {
          invalid = 1
        }
        next
      }
      $1 == "NSpid:" {
        nspid_count++
        if (NF < 2 || $NF != expected_process_pid) {
          invalid = 1
        }
        for (field = 2; field <= NF; field++) {
          if ($field !~ /^[1-9][0-9]*$/) {
            invalid = 1
          }
        }
        process_pid = $NF
        next
      }
      $1 == "PidNamespace:" {
        pid_namespace_count++
        pid_namespace = $2
        if (NF != 2 || pid_namespace !~ /^pid:\[[1-9][0-9]*\]$/) {
          invalid = 1
        }
        next
      }
      $1 == "ChildPidNamespace:" {
        child_namespace_count++
        child_namespace = $2
        if (NF != 2 || child_namespace !~ /^pid:\[[1-9][0-9]*\]$/) {
          invalid = 1
        }
        next
      }
      $1 == "Comm:" {
        comm_count++
        if (NF != 2 || $2 != "java") {
          invalid = 1
        }
        next
      }
      NF != 0 {
        invalid = 1
      }
      END {
        if (invalid || tgid_count != 1 || nspid_count != 1 ||
          pid_namespace_count != 1 || child_namespace_count != 1 ||
          comm_count != 1 || process_pid == "" ||
          pid_namespace != child_namespace) {
          exit 1
        }
        sub(/^pid:\[/, "", pid_namespace)
        sub(/\]$/, "", pid_namespace)
        print process_pid, pid_namespace
      }
    ' <<<"$status_snapshot"
  ) || return $?
  process_pid="$(bounded_decimal "$process_pid" "$MAX_UINT32_DECIMAL" false)" || return $?
  process_namespace="$(
    bounded_decimal "$process_namespace" "$MAX_UINT32_DECIMAL" false
  )" || return $?
  printf '%s %s\n' "$process_pid" "$process_namespace"
}

resolve_container_process_namespace_identity() {
  local -r container="$1"
  local status_snapshot=""

  [[ "$container" =~ ^[a-f0-9]{64}$ ]] || return 1
  # Read through the controlled container's private procfs. Host-side namespace
  # symlink dereferences are ptrace-gated for ordinary Docker-group operators.
  # shellcheck disable=SC2016 # The fixed proc paths are evaluated in the container.
  status_snapshot="$(run_bounded 10 docker exec "$container" /bin/sh -ec '
    set -eu
    LC_ALL=C awk '\''$1 == "Tgid:" || $1 == "NSpid:" { print }'\'' /proc/1/status
    printf "PidNamespace:\t%s\n" "$(readlink /proc/1/ns/pid)"
    printf "ChildPidNamespace:\t%s\n" "$(readlink /proc/1/ns/pid_for_children)"
    printf "Comm:\t%s\n" "$(cat /proc/1/comm)"
  ')" || return $?
  process_namespace_identity_from_snapshot "$status_snapshot" 1
}

wait_for_generation_fault_armed() {
  local -r directory="$1"
  local -r helper_pid="$2"
  local -r expected_owner="$3"
  local -r armed="$directory/armed"
  local -i started_at="$SECONDS"
  local metadata=""

  [[ "$directory" == "$RESULT_DIR/generation-fault-control" && \
    "$helper_pid" =~ ^[1-9][0-9]*$ && "$expected_owner" =~ ^[0-9]+$ ]] || return 1
  while ((SECONDS - started_at < GENERATION_FAULT_READY_TIMEOUT_SECONDS)); do
    if [[ -f "$armed" && ! -L "$armed" ]]; then
      metadata="$(stat -c '%u:%g:%a:%h:%s' -- "$armed")" || return $?
      [[ "$metadata" =~ ^([0-9]+):([0-9]+):600:1:6$ && \
        "${BASH_REMATCH[1]}" == "$expected_owner" && \
        "$(<"$armed")" == "armed" ]] || {
        log_error "generation mismatch helper published an invalid armed record"
        return 1
      }
      return 0
    fi
    if ! background_process_is_running "$helper_pid"; then
      log_error "generation mismatch helper exited before mutation was armed"
      return 1
    fi
    sleep 0.1
  done
  log_error "timed out waiting for the generation mismatch mutation"
  return 1
}

publish_generation_fault_release() {
  local -r directory="$1"
  local -r expected_owner="$2"
  local -r release="$directory/release"
  local temporary=""

  [[ "$directory" == "$RESULT_DIR/generation-fault-control" && \
    "$expected_owner" == "$(id -u)" && -d "$directory" && ! -L "$directory" && \
    ! -e "$release" && ! -L "$release" ]] || return 1
  temporary="$(mktemp "$directory/.release.XXXXXX")" || return $?
  if ! printf 'release\n' >"$temporary" || ! chmod 0600 -- "$temporary" || \
    [[ "$(stat -c '%u:%a:%h:%s' -- "$temporary")" != "$expected_owner:600:1:8" ]] || \
    ! mv -T -- "$temporary" "$release"; then
    rm -f -- "$temporary" || true
    return 1
  fi
  [[ -f "$release" && ! -L "$release" && "$(<"$release")" == "release" ]]
}

assert_generation_fault_helper_output() {
  local -r output="$1"
  local -r stderr_output="$2"

  bounded_evidence_file "$output" 512 1 || return 1
  bounded_evidence_file "$stderr_output" 4096 64 || return 1
  [[ ! -s "$stderr_output" ]] || return 1
  jq -e '
    type == "object" and
    ((keys | sort) == ["mode", "mutated", "restored", "status"]) and
    .status == "passed" and
    .mode == "generation-mismatch" and
    .mutated == true and
    .restored == true
  ' "$output" >/dev/null
}

run_primary_generation_mismatch_control() (
  local -r original_variant="$SCENARIO_VARIANT"
  local -r recovery_marker="$RESULT_DIR/primary-generation-mismatch-recovery-required"
  local -r control_directory="$RESULT_DIR/generation-fault-control"
  local -r before_phase="primary-generation-mismatch-before"
  local -r after_phase="primary-generation-mismatch-after"
  local -r arm_evidence="$RESULT_DIR/primary-generation-mismatch-barrier-armed.txt"
  local -r release_evidence="$RESULT_DIR/primary-generation-mismatch-barrier-released.txt"
  local -r consumption_evidence="$RESULT_DIR/primary-generation-mismatch-barrier-consumed.txt"
  local -r victim_output="$RESULT_DIR/scenario-primary-generation-mismatch.json"
  local -r victim_stderr="$RESULT_DIR/scenario-primary-generation-mismatch.stderr.log"
  local -r helper_output="$RESULT_DIR/generation-mismatch-helper.json"
  local -r helper_stderr="$RESULT_DIR/generation-mismatch-helper.stderr.log"
  local -r diagnostics_delta="$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"
  local -r metric_delta="$RESULT_DIR/phases/$after_phase/obi-metrics.delta"
  local restore_required=false
  local barrier_released=false
  local helper_release_published=false
  local java_container=""
  local java_host_pid=""
  local java_inspection_before=""
  local java_inspection_after=""
  local java_process_identity=""
  local java_process_pid=""
  local java_process_namespace=""
  local inspected_container=""
  local inspected_started_at=""
  local inspection_extra=""
  local control_owner=""
  local descriptor=""
  local victim_pid=""
  local helper_pid=""
  local before_stage=""
  local before_take_attempts=""
  local baseline_snapshot=""
  local restore_status=0

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  restore_primary_generation_mismatch_stack() {
    local -r status="$?"
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    seal_terminal_java_diagnostics
    terminal_diagnostics_status=$?
    if [[ "$barrier_released" == "false" && -n "$descriptor" && -n "$java_container" ]]; then
      release_primary_live_fd_barrier \
        "$java_container" "$descriptor" \
        "$RESULT_DIR/primary-generation-mismatch-emergency-barrier-release.txt" 5 || true
      barrier_released=true
    fi
    if [[ "$helper_release_published" == "false" && -n "$control_owner" && \
      -d "$control_directory" ]]; then
      publish_generation_fault_release "$control_directory" "$control_owner" || true
      helper_release_published=true
    fi
    if [[ "$helper_pid" =~ ^[1-9][0-9]*$ ]]; then
      if ! wait_for_background_process "$helper_pid" "$GENERATION_FAULT_REAP_TIMEOUT_SECONDS"; then
        if background_process_is_running "$helper_pid"; then
          kill -TERM "$helper_pid" 2>/dev/null || true
        fi
        wait "$helper_pid" 2>/dev/null || true
      fi
      helper_pid=""
    fi
    if [[ "$victim_pid" =~ ^[1-9][0-9]*$ ]]; then
      if background_process_is_running "$victim_pid"; then
        kill -TERM "$victim_pid" 2>/dev/null || true
      fi
      wait "$victim_pid" 2>/dev/null || true
      victim_pid=""
    fi
    rm -f -- "$control_directory/armed" "$control_directory/release" \
      "$control_directory"/.release.* 2>/dev/null || true
    rmdir -- "$control_directory" 2>/dev/null || true
    if [[ "$restore_required" == "true" ]]; then
      (
        set -Eeuo pipefail
        recreate_instrumented_stack \
          tcp "post-primary generation mismatch recovery" getsockopt true false base
        assert_runtime_contract basic true
      )
      restore_status=$?
      if ((restore_status == 0)); then
        rm -f -- "$recovery_marker" || restore_status=$?
        PRIMARY_FAULT_STACK_ACTIVE=false
      fi
    fi
    SCENARIO_VARIANT="$original_variant"
    if ((status == 0 && restore_status != 0)); then
      exit "$restore_status"
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  trap restore_primary_generation_mismatch_stack EXIT
  [[ "$TRANSPORT" == "getsockopt" && "$SELECTED_TRANSPORT" == "getsockopt" && \
    "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "the generation mismatch control requires a healthy forced getsockopt bridge"
    return 1
  }
  [[ ! -e "$recovery_marker" && ! -L "$recovery_marker" && \
    ! -e "$control_directory" && ! -L "$control_directory" ]] || return 1
  plan_obi_metric_pair_capture primary-generation-mismatch-fault || return $?
  (umask 077; printf 'recovery_required\n' >"$recovery_marker") || return $?
  install -d -m 0700 -- "$control_directory" || return $?
  control_owner="$(id -u)" || return $?

  restore_required=true
  PRIMARY_FAULT_STACK_ACTIVE=true
  recreate_instrumented_stack \
    tcp "primary generation mismatch preparation" getsockopt true false primary-fault || return $?
  assert_runtime_contract primary-generation-mismatch true || return $?
  java_container="$(run_bounded 10 "${PRIMARY_FAULT_COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$java_container" ]] || return 1
  java_inspection_before="$(run_bounded 10 docker inspect \
    --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$java_container")" || return $?
  read -r inspected_container java_host_pid inspected_started_at inspection_extra \
    <<<"$java_inspection_before" || return $?
  [[ "$inspected_container" == "$java_container" && -n "$inspected_started_at" && \
    "$inspected_started_at" != "0001-01-01T00:00:00Z" && -z "$inspection_extra" ]] || return 1
  java_host_pid="$(bounded_decimal "$java_host_pid" "$MAX_UINT32_DECIMAL" false)" || return $?
  java_process_identity="$(
    resolve_container_process_namespace_identity "$java_container"
  )" || return $?
  read -r java_process_pid java_process_namespace inspection_extra \
    <<<"$java_process_identity" || return $?
  [[ -z "$inspection_extra" ]] || return 1
  java_inspection_after="$(run_bounded 10 docker inspect \
    --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$java_container")" || return $?
  [[ "$java_inspection_after" == "$java_inspection_before" ]] || {
    log_error "the controlled JVM changed while resolving its PID namespace identity"
    return 1
  }

  mkdir -p -- "$RESULT_DIR/phases/$before_phase"
  flush_bridge_metric_boundary \
    primary-generation-mismatch 1 1 \
    "$RESULT_DIR/phases/$before_phase/java-diagnostics.txt" || return $?
  capture_phase_evidence "$before_phase" || return $?
  before_stage="$(bridge_stage_total \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
  before_take_attempts="$(bridge_take_attempt_total \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
  ((before_take_attempts <= MAX_SHELL_INTEGER - 4)) || return 1
  baseline_snapshot="$(<"$RESULT_DIR/phases/$before_phase/java-diagnostics.txt")"

  arm_primary_live_fd_barrier "$arm_evidence" primary-fault || return $?
  timeout --signal=TERM --kill-after=10s \
    "${PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS}s" \
    "${PRIMARY_FAULT_COMPOSE[@]}" run --rm --no-deps --no-TTY scenario \
      --scenario primary-w3c-fault \
      --expected-tls "$TLS_PROTOCOL" \
      --seed "$SCENARIO_SEED" \
      --requests 1 \
      --fault-mode generation-mismatch \
      --java-diagnostics-before "$baseline_snapshot" \
      --timeout 75s \
      --request-timeout "${GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS}s" \
      </dev/null >"$victim_output" 2>"$victim_stderr" &
  victim_pid=$!
  descriptor="$(wait_for_primary_live_fd_barrier_ready "$java_container" "$victim_pid")" || return $?

  GENERATION_FAULT_CONTROL_SOURCE="$control_directory" \
    timeout --signal=TERM --kill-after=5s \
      "${GENERATION_FAULT_HELPER_TIMEOUT_SECONDS}s" \
      "${PRIMARY_FAULT_COMPOSE[@]}" run --rm --no-deps --no-TTY generation-fault \
        --process-pid "$java_process_pid" \
        --process-namespace "$java_process_namespace" \
        --control-dir /control \
        --control-owner "$control_owner" \
        --timeout "${GENERATION_FAULT_RELEASE_TIMEOUT_SECONDS}s" \
        </dev/null >"$helper_output" 2>"$helper_stderr" &
  helper_pid=$!
  wait_for_generation_fault_armed \
    "$control_directory" "$helper_pid" "$control_owner" || return $?
  ALLOW_PRIMARY_SECURITY_METRICS=true

  release_primary_live_fd_barrier \
    "$java_container" "$descriptor" "$release_evidence" || return $?
  barrier_released=true
  # The request's bounded post-extraction delay keeps the accepted connection
  # alive while this exact attempt fence proves the unauthorized-socket
  # preflight, both same-FD probes, and the generation-mismatched victim take
  # ran before restoration.
  wait_for_bridge_take_attempts_quiescent \
    "$((before_take_attempts + 4))" "$((before_stage + 1))" \
    "$RESULT_DIR/metrics-primary-generation-mismatch-take.prom" \
    "primary generation mismatch take" \
    "$GENERATION_FAULT_TAKE_FENCE_TIMEOUT_SECONDS" || return $?
  publish_generation_fault_release "$control_directory" "$control_owner" || return $?
  helper_release_published=true
  wait_for_background_process "$helper_pid" "$GENERATION_FAULT_REAP_TIMEOUT_SECONDS" || return $?
  helper_pid=""
  assert_generation_fault_helper_output "$helper_output" "$helper_stderr" || return $?

  wait_for_background_process "$victim_pid" "$PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS" || return $?
  victim_pid=""
  consume_primary_live_fd_barrier "$consumption_evidence" primary-fault || return $?
  capture_phase_evidence "$after_phase" || return $?
  extract_fault_diagnostics_after \
    "$victim_output" "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" || return $?
  write_java_diagnostics_delta \
    "$RESULT_DIR/phases/$before_phase/java-diagnostics.txt" \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" \
    "$diagnostics_delta" || return $?
  assert_w3c_fault_diagnostics_delta \
    "$diagnostics_delta" generation-mismatch 1 || return $?
  write_metrics_delta \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
    "$RESULT_DIR/phases/$after_phase/obi-metrics.prom" \
    "$metric_delta" || return $?
  assert_security_metric_delta \
    "$metric_delta" take missing getsockopt 3 3 || return $?
  assert_primary_security_metric_delta "$metric_delta" take 1 1 || return $?
  assert_bridge_metric_delta \
    "$metric_delta" getsockopt 0 0 3 1 1 false 0 || return $?
  record_obi_metric_pair \
    primary-generation-mismatch-fault "$before_phase" "$after_phase" \
    same_process "$after_phase" >/dev/null || return $?

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  recreate_instrumented_stack \
    tcp "post-primary generation mismatch recovery" getsockopt true false base || return $?
  assert_runtime_contract basic true || return $?
  rm -f -- "$recovery_marker" || return $?
  PRIMARY_FAULT_STACK_ACTIVE=false
  restore_required=false
  rm -f -- "$control_directory/armed" "$control_directory/release" || return $?
  rmdir -- "$control_directory" || return $?
  SCENARIO_VARIANT="primary-generation-mismatch-recovery"
  run_scenario basic || return $?
  SCENARIO_VARIANT="$original_variant"
  printf '{"status":"passed","scenario":"primary-generation-mismatch","live_owner_mutation":"verified","take_status":"missing","w3c_precedence":"passed","same_fd_execution_guards":"missing","exact_restore":"verified","post_fault_recovery":"passed","before_phase":"phases/%s","after_phase":"phases/%s"}\n' \
    "$before_phase" "$after_phase" \
    >"$RESULT_DIR/scenario-primary-generation-mismatch-status.json"
  crosslink_and_bind_active_obi_metric_boundary_status \
    scenario-primary-generation-mismatch-status.json || return $?

  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
)

run_unix_generation_mismatch_control() (
  local -r original_variant="$SCENARIO_VARIANT"
  local -r recovery_marker="$RESULT_DIR/unix-generation-mismatch-recovery-required"
  local -r control_directory="$RESULT_DIR/generation-fault-control"
  local -r before_phase="unix-generation-mismatch-before"
  local -r after_phase="unix-generation-mismatch-after"
  local -r arm_evidence="$RESULT_DIR/unix-generation-mismatch-barrier-armed.txt"
  local -r release_evidence="$RESULT_DIR/unix-generation-mismatch-barrier-released.txt"
  local -r consumption_evidence="$RESULT_DIR/unix-generation-mismatch-barrier-consumed.txt"
  local -r runtime_evidence="$RESULT_DIR/unix-generation-mismatch-runtime.txt"
  local -r victim_output="$RESULT_DIR/scenario-unix-generation-mismatch.json"
  local -r victim_stderr="$RESULT_DIR/scenario-unix-generation-mismatch.stderr.log"
  local -r helper_output="$RESULT_DIR/generation-mismatch-helper.json"
  local -r helper_stderr="$RESULT_DIR/generation-mismatch-helper.stderr.log"
  local -r diagnostics_delta="$RESULT_DIR/phases/$after_phase/java-diagnostics.delta"
  local -r metric_delta="$RESULT_DIR/phases/$after_phase/obi-metrics.delta"
  local restore_required=false
  local barrier_ready=false
  local barrier_released=false
  local helper_release_published=false
  local java_container=""
  local java_host_pid=""
  local java_inspection_before=""
  local java_inspection_after=""
  local java_process_identity=""
  local java_process_pid=""
  local java_process_namespace=""
  local inspected_container=""
  local inspected_started_at=""
  local inspection_extra=""
  local control_owner=""
  local victim_pid=""
  local helper_pid=""
  local before_stage=""
  local before_take_attempts=""
  local baseline_snapshot=""
  local restore_status=0

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  restore_unix_generation_mismatch_stack() {
    local -r status="$?"
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    seal_terminal_java_diagnostics
    terminal_diagnostics_status=$?
    if [[ "$barrier_ready" == "true" && "$barrier_released" == "false" && \
      -n "$java_container" ]]; then
      release_unix_generation_barrier "$java_container" \
        "$RESULT_DIR/unix-generation-mismatch-emergency-barrier-release.txt" 5 || true
      barrier_released=true
    fi
    if [[ "$helper_release_published" == "false" && -n "$control_owner" && \
      -d "$control_directory" ]]; then
      publish_generation_fault_release "$control_directory" "$control_owner" || true
      helper_release_published=true
    fi
    if [[ "$helper_pid" =~ ^[1-9][0-9]*$ ]]; then
      if ! wait_for_background_process "$helper_pid" "$GENERATION_FAULT_REAP_TIMEOUT_SECONDS"; then
        if background_process_is_running "$helper_pid"; then
          kill -TERM "$helper_pid" 2>/dev/null || true
        fi
        wait "$helper_pid" 2>/dev/null || true
      fi
      helper_pid=""
    fi
    if [[ "$victim_pid" =~ ^[1-9][0-9]*$ ]]; then
      if background_process_is_running "$victim_pid"; then
        kill -TERM "$victim_pid" 2>/dev/null || true
      fi
      wait "$victim_pid" 2>/dev/null || true
      victim_pid=""
    fi
    rm -f -- "$control_directory/armed" "$control_directory/release" \
      "$control_directory"/.release.* 2>/dev/null || true
    rmdir -- "$control_directory" 2>/dev/null || true
    if [[ "$restore_required" == "true" ]]; then
      (
        set -Eeuo pipefail
        recreate_instrumented_stack \
          tcp "post-Unix generation mismatch recovery" unix true false base
        assert_runtime_contract basic true
        assert_obi_remote_parent_timeout 50ms
      )
      restore_status=$?
      if ((restore_status == 0)); then
        rm -f -- "$recovery_marker" || restore_status=$?
        PRIMARY_FAULT_STACK_ACTIVE=false
      fi
    fi
    SCENARIO_VARIANT="$original_variant"
    if ((status == 0 && restore_status != 0)); then
      exit "$restore_status"
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  trap restore_unix_generation_mismatch_stack EXIT
  assert_unix_generation_deadlines || return $?
  [[ "$TRANSPORT" == "unix" && "$SELECTED_TRANSPORT" == "unix" && \
    "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "the Unix generation mismatch control requires a healthy forced Unix bridge"
    return 1
  }
  [[ ! -e "$recovery_marker" && ! -L "$recovery_marker" && \
    ! -e "$control_directory" && ! -L "$control_directory" ]] || return 1
  plan_obi_metric_pair_capture unix-generation-mismatch-fault || return $?
  (umask 077; printf 'recovery_required\n' >"$recovery_marker") || return $?
  install -d -m 0700 -- "$control_directory" || return $?
  control_owner="$(id -u)" || return $?

  restore_required=true
  PRIMARY_FAULT_STACK_ACTIVE=true
  recreate_instrumented_stack \
    tcp "Unix generation mismatch preparation" unix true false unix-generation-fault || return $?
  assert_runtime_contract unix-generation-mismatch true || return $?
  assert_unix_generation_mismatch_runtime_contract "$runtime_evidence" || return $?
  java_container="$(run_bounded 10 "${UNIX_GENERATION_FAULT_COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$java_container" ]] || return 1
  java_inspection_before="$(run_bounded 10 docker inspect \
    --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$java_container")" || return $?
  read -r inspected_container java_host_pid inspected_started_at inspection_extra \
    <<<"$java_inspection_before" || return $?
  [[ "$inspected_container" == "$java_container" && -n "$inspected_started_at" && \
    "$inspected_started_at" != "0001-01-01T00:00:00Z" && -z "$inspection_extra" ]] || return 1
  java_host_pid="$(bounded_decimal "$java_host_pid" "$MAX_UINT32_DECIMAL" false)" || return $?
  java_process_identity="$(
    resolve_container_process_namespace_identity "$java_container"
  )" || return $?
  read -r java_process_pid java_process_namespace inspection_extra \
    <<<"$java_process_identity" || return $?
  [[ -z "$inspection_extra" ]] || return 1
  java_inspection_after="$(run_bounded 10 docker inspect \
    --format '{{.Id}} {{.State.Pid}} {{.State.StartedAt}}' "$java_container")" || return $?
  [[ "$java_inspection_after" == "$java_inspection_before" ]] || return 1

  mkdir -p -- "$RESULT_DIR/phases/$before_phase"
  flush_bridge_metric_boundary unix-generation-mismatch 1 1 \
    "$RESULT_DIR/phases/$before_phase/java-diagnostics.txt" || return $?
  capture_phase_evidence "$before_phase" || return $?
  before_stage="$(bridge_stage_total \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
  before_take_attempts="$(bridge_take_attempt_total \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
  ((before_take_attempts <= MAX_SHELL_INTEGER - 1 && \
    before_stage <= MAX_SHELL_INTEGER - 1)) || return 1
  baseline_snapshot="$(<"$RESULT_DIR/phases/$before_phase/java-diagnostics.txt")"

  arm_unix_generation_barrier "$arm_evidence" || return $?
  timeout --signal=TERM --kill-after=10s \
    "${PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS}s" \
    "${UNIX_GENERATION_FAULT_COMPOSE[@]}" run --rm --no-deps --no-TTY scenario \
      --scenario unix-generation-mismatch \
      --expected-tls "$TLS_PROTOCOL" \
      --seed "$SCENARIO_SEED" \
      --requests 1 \
      --fault-mode generation-mismatch \
      --java-diagnostics-before "$baseline_snapshot" \
      --timeout "${UNIX_GENERATION_SCENARIO_TIMEOUT_SECONDS}s" \
      --request-timeout "${GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS}s" \
      </dev/null >"$victim_output" 2>"$victim_stderr" &
  victim_pid=$!
  wait_for_unix_generation_barrier_ready "$java_container" "$victim_pid" || return $?
  barrier_ready=true

  GENERATION_FAULT_CONTROL_SOURCE="$control_directory" \
    timeout --signal=TERM --kill-after=5s \
      "${GENERATION_FAULT_HELPER_TIMEOUT_SECONDS}s" \
      "${UNIX_GENERATION_FAULT_COMPOSE[@]}" run --rm --no-deps --no-TTY generation-fault \
        --process-pid "$java_process_pid" \
        --process-namespace "$java_process_namespace" \
        --control-dir /control \
        --control-owner "$control_owner" \
        --timeout "${GENERATION_FAULT_RELEASE_TIMEOUT_SECONDS}s" \
        </dev/null >"$helper_output" 2>"$helper_stderr" &
  helper_pid=$!
  wait_for_generation_fault_armed \
    "$control_directory" "$helper_pid" "$control_owner" || return $?
  release_unix_generation_barrier "$java_container" "$release_evidence" || return $?
  barrier_released=true
  wait_for_bridge_take_attempts_quiescent \
    "$((before_take_attempts + 1))" "$((before_stage + 1))" \
    "$RESULT_DIR/metrics-unix-generation-mismatch-take.prom" \
    "Unix generation mismatch take" \
    "$GENERATION_FAULT_TAKE_FENCE_TIMEOUT_SECONDS" || return $?
  publish_generation_fault_release "$control_directory" "$control_owner" || return $?
  helper_release_published=true
  wait_for_background_process "$helper_pid" "$GENERATION_FAULT_REAP_TIMEOUT_SECONDS" || return $?
  helper_pid=""
  assert_generation_fault_helper_output "$helper_output" "$helper_stderr" || return $?
  wait_for_background_process "$victim_pid" "$PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS" || return $?
  victim_pid=""
  consume_unix_generation_barrier "$consumption_evidence" || return $?
  capture_phase_evidence "$after_phase" || return $?
  extract_fault_diagnostics_after \
    "$victim_output" "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" || return $?
  write_java_diagnostics_delta \
    "$RESULT_DIR/phases/$before_phase/java-diagnostics.txt" \
    "$RESULT_DIR/phases/$after_phase/java-diagnostics.txt" \
    "$diagnostics_delta" || return $?
  assert_unix_generation_mismatch_diagnostics_delta \
    "$diagnostics_delta" 1 || return $?
  write_metrics_delta \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
    "$RESULT_DIR/phases/$after_phase/obi-metrics.prom" \
    "$metric_delta" || return $?
  assert_security_metric_delta \
    "$metric_delta" take already_consumed unix 1 1 || return $?
  assert_bridge_metric_delta \
    "$metric_delta" unix 0 0 0 1 1 false 0 0 1 || return $?
  record_obi_metric_pair \
    unix-generation-mismatch-fault "$before_phase" "$after_phase" \
    same_process "$after_phase" >/dev/null || return $?

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  recreate_instrumented_stack \
    tcp "post-Unix generation mismatch recovery" unix true false base || return $?
  assert_runtime_contract basic true || return $?
  assert_obi_remote_parent_timeout 50ms || return $?
  rm -f -- "$recovery_marker" || return $?
  PRIMARY_FAULT_STACK_ACTIVE=false
  restore_required=false
  rm -f -- "$control_directory/armed" "$control_directory/release" || return $?
  rmdir -- "$control_directory" || return $?
  SCENARIO_VARIANT="unix-generation-mismatch-recovery"
  run_scenario basic || return $?
  SCENARIO_VARIANT="$original_variant"
  printf '%s\n' \
    '{"status":"passed","scenario":"unix-generation-mismatch","transport":"unix","live_owner_mutation":"verified","barrier":"pre-send","bridge_timeout_ms":30000,"take_status":"already_consumed","wrong_parent_count":0,"w3c_precedence":"passed","exact_restore":"verified","post_fault_recovery":"passed","before_phase":"phases/unix-generation-mismatch-before","after_phase":"phases/unix-generation-mismatch-after"}' \
    >"$RESULT_DIR/scenario-unix-generation-mismatch-status.json"
  crosslink_and_bind_active_obi_metric_boundary_status \
    scenario-unix-generation-mismatch-status.json || return $?

  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
)

run_primary_live_fd_security_control() (
  local -r probe_source="$1"
  local -r original_variant="$SCENARIO_VARIANT"
  local -r recovery_marker="$RESULT_DIR/primary-live-fd-security-recovery-required"
  local -r before_phase="security-primary-live-fd-before"
  local -r probe_phase="security-primary-live-fd-probe"
  local -r after_phase="security-primary-live-fd-after"
  local -r arm_evidence="$RESULT_DIR/primary-live-fd-security-armed.txt"
  local -r release_evidence="$RESULT_DIR/primary-live-fd-security-released.txt"
  local -r consumption_evidence="$RESULT_DIR/primary-live-fd-security-consumed.txt"
  local -r probe_output="$RESULT_DIR/security-primary-live-fd.log"
  local -r victim_output="$RESULT_DIR/scenario-security-primary-live-fd-victim.json"
  local -r victim_stderr="$RESULT_DIR/scenario-security-primary-live-fd-victim.stderr.log"
  local -r probe_delta="$RESULT_DIR/phases/$probe_phase/obi-metrics.delta"
  local -r full_delta="$RESULT_DIR/phases/$after_phase/obi-metrics.delta"
  local restore_required=false
  local java_container=""
  local descriptor=""
  local victim_pid=""
  local before_success=""
  local before_stage=""
  local probe_candidate=""
  local victim_exit=0
  local restore_status=0
  local probe_timeout=""
  local metrics_timeout=""
  local capture_timeout=""
  local release_timeout=""
  local -i pre_release_deadline=0

  # shellcheck disable=SC2329 # Invoked by the EXIT trap below.
  restore_primary_live_fd_security_stack() {
    local -r status="$?"
    local terminal_diagnostics_status=0

    trap - EXIT
    set +e
    seal_terminal_java_diagnostics
    terminal_diagnostics_status=$?
    if [[ -n "$probe_candidate" ]]; then
      rm -f -- "$probe_candidate" || true
      probe_candidate=""
    fi
    if [[ "$victim_pid" =~ ^[1-9][0-9]*$ ]]; then
      if background_process_is_running "$victim_pid"; then
        kill -TERM "$victim_pid" 2>/dev/null || true
      fi
      if ! wait_for_background_process \
        "$victim_pid" "$PRIMARY_LIVE_FD_VICTIM_REAP_TIMEOUT_SECONDS"; then
        if background_process_is_running "$victim_pid"; then
          kill -KILL "$victim_pid" 2>/dev/null || true
        fi
        wait "$victim_pid" 2>/dev/null || true
      fi
      victim_pid=""
    fi
    if [[ "$restore_required" == "true" ]]; then
      log_warn "restoring the normal instrumented stack after primary live-descriptor security control" || true
      (
        set -Eeuo pipefail
        recreate_instrumented_stack \
          tcp "post-primary live-descriptor security recovery" getsockopt true false base
        assert_runtime_contract basic true
      )
      restore_status=$?
      if ((restore_status == 0)); then
        if rm -f -- "$recovery_marker"; then
          PRIMARY_FAULT_STACK_ACTIVE=false
        else
          restore_status=$?
          log_error "could not clear the primary live-descriptor recovery marker" || true
        fi
      else
        log_error "could not restore the instrumented stack after primary live-descriptor security control" || true
      fi
    fi
    SCENARIO_VARIANT="$original_variant"
    if ((status == 0 && restore_status != 0)); then
      exit "$restore_status"
    fi
    if ((status == 0 && terminal_diagnostics_status != 0)); then
      exit "$terminal_diagnostics_status"
    fi
    exit "$status"
  }

  trap restore_primary_live_fd_security_stack EXIT
  ((PRIMARY_LIVE_FD_PRE_RELEASE_DEADLINE_SECONDS +
    PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS <
    PRIMARY_LIVE_FD_BARRIER_TIMEOUT_SECONDS)) || {
    log_error "primary live-descriptor barrier cannot retain its release window"
    return 1
  }
  [[ -s "$probe_source" && -f "$probe_source" && ! -L "$probe_source" ]] || {
    log_error "primary live-descriptor security probe source is unavailable"
    return 1
  }
  [[ ! -e "$probe_output" && ! -L "$probe_output" ]] || {
    log_error "refusing to overwrite primary live-descriptor probe evidence: $probe_output"
    return 1
  }
  [[ "$TRANSPORT" == "getsockopt" && "$SELECTED_TRANSPORT" == "getsockopt" && \
    "$BRIDGE_RUNNING" == "true" ]] || {
    log_error "the primary live-descriptor security control requires a healthy forced getsockopt bridge"
    return 1
  }
  [[ ! -e "$recovery_marker" && ! -L "$recovery_marker" ]] || {
    log_error "primary live-descriptor recovery marker already exists: $recovery_marker"
    return 1
  }
  plan_obi_metric_pair_capture primary-live-fd-probe || return $?
  plan_obi_metric_pair_capture primary-live-fd-full || return $?
  if ! (umask 077; printf 'recovery_required\n' >"$recovery_marker"); then
    log_error "could not create the primary live-descriptor recovery marker"
    return 1
  fi

  restore_required=true
  PRIMARY_FAULT_STACK_ACTIVE=true
  recreate_instrumented_stack \
    tcp "primary live-descriptor security preparation" getsockopt true false primary-live-fd || return $?
  assert_runtime_contract primary-live-fd-security true || return $?
  java_container="$(run_bounded 10 "${PRIMARY_LIVE_FD_COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$java_container" ]] || {
    log_error "could not resolve the Java container for the primary live-descriptor security control"
    return 1
  }
  run_bounded 10 docker exec --user 0:0 "$java_container" \
    rm -f -- "$PRIMARY_SECURITY_PROBE_PATH" || return $?
  run_bounded 15 docker cp "$probe_source" \
    "$java_container:$PRIMARY_SECURITY_PROBE_PATH" || return $?
  run_bounded 10 docker exec --user 0:0 "$java_container" \
    chmod 0755 "$PRIMARY_SECURITY_PROBE_PATH" || return $?

  wait_for_primary_security_metrics_quiescent \
    "$RESULT_DIR/metrics-security-primary-live-fd-before.prom" \
    "primary live-descriptor security baseline" || return $?
  capture_metric_phase_evidence "$before_phase" || return $?
  before_success="$(bridge_success_total \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?
  before_stage="$(bridge_stage_total \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom")" || return $?

  arm_primary_live_fd_barrier "$arm_evidence" || return $?
  # Background the timeout supervisor itself, not a Bash function wrapper, so
  # the EXIT trap can terminate and reap the complete victim process tree.
  timeout --signal=TERM --kill-after=10s \
    "${PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS}s" \
    "${PRIMARY_LIVE_FD_COMPOSE[@]}" run --rm --no-deps --no-TTY scenario \
    --scenario basic \
    --expected-tls "$TLS_PROTOCOL" \
    --seed "$SCENARIO_SEED" \
    --requests 1 \
    --timeout "${PRIMARY_LIVE_FD_VICTIM_SCENARIO_TIMEOUT_SECONDS}s" \
    --request-timeout "${PRIMARY_LIVE_FD_VICTIM_REQUEST_TIMEOUT_SECONDS}s" \
    </dev/null >"$victim_output" 2>"$victim_stderr" &
  victim_pid=$!
  descriptor="$(wait_for_primary_live_fd_barrier_ready "$java_container" "$victim_pid")" || return $?
  background_process_is_running "$victim_pid" || {
    log_error "primary live-descriptor victim exited before the security probe"
    return 1
  }
  pre_release_deadline="$((SECONDS + PRIMARY_LIVE_FD_PRE_RELEASE_DEADLINE_SECONDS))"
  probe_timeout="$(primary_live_fd_remaining_timeout \
    "$pre_release_deadline" \
    "$PRIMARY_LIVE_FD_PROBE_TIMEOUT_SECONDS" \
    "$((PRIMARY_LIVE_FD_METRICS_TIMEOUT_SECONDS + \
      PRIMARY_LIVE_FD_METRIC_CAPTURE_TIMEOUT_SECONDS + \
      PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS))")" || {
    log_error "primary live-descriptor proof did not retain enough time for release"
    return 1
  }
  probe_candidate="$(mktemp "$RESULT_DIR/.security-primary-live-fd.XXXXXX")" || return $?
  if ! run_primary_live_fd_probe \
    "$java_container" "$descriptor" "$probe_timeout" "$probe_candidate"; then
    rm -f -- "$probe_candidate" || true
    probe_candidate=""
    log_error "primary live-descriptor security probe failed"
    return 1
  fi
  if assert_primary_live_fd_probe_unsupported_output "$probe_candidate"; then
    install -m 0644 "$probe_candidate" "$probe_output" || return $?
    rm -f -- "$probe_candidate" || return $?
    probe_candidate=""
    release_timeout="$(primary_live_fd_remaining_timeout \
      "$pre_release_deadline" "$PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS" 0)" || {
      log_error "primary live-descriptor unsupported probe exhausted its release budget"
      return 1
    }
    [[ "$release_timeout" == "$PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS" ]] || {
      log_error "primary live-descriptor unsupported probe did not retain the full release budget"
      return 1
    }
    release_primary_live_fd_barrier \
      "$java_container" "$descriptor" "$release_evidence" "$release_timeout" || return $?
    if wait_for_background_process \
      "$victim_pid" "$PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS"; then
      victim_exit=0
      victim_pid=""
    else
      victim_exit=$?
    fi
    [[ "$victim_exit" == "0" ]] || {
      log_error "primary live-descriptor victim failed while releasing an unsupported probe"
      return "$victim_exit"
    }
    consume_primary_live_fd_barrier "$consumption_evidence" || return $?
    printf '{"status":"unsupported","scenario":"primary-live-fd-security","reason":"pidfd-duplicate-unavailable","probe":"%s","attacker_identity":"root","attacker_cgroup":"pid1-verified-preexec"}\n' \
      "$(basename -- "$probe_output")" \
      >"$RESULT_DIR/scenario-primary-live-fd-security-status.json" || return $?
    crosslink_and_bind_active_obi_metric_boundary_status \
      scenario-primary-live-fd-security-status.json || return $?
    if ! run_bounded 10 docker exec --user 0:0 "$java_container" \
      rm -f -- "$PRIMARY_SECURITY_PROBE_PATH"; then
      log_error "could not remove the primary live-descriptor security probe after an unsupported result"
      return 1
    fi
    log_error "primary live-descriptor security probe is unsupported in this topology"
    return 1
  fi
  assert_primary_live_fd_probe_output "$probe_candidate" || {
    rm -f -- "$probe_candidate" || true
    probe_candidate=""
    log_error "primary live-descriptor security probe did not emit the expected unverified observation"
    return 1
  }
  install -m 0644 "$probe_candidate" "$probe_output" || return $?
  rm -f -- "$probe_candidate" || return $?
  probe_candidate=""

  metrics_timeout="$(primary_live_fd_remaining_timeout \
    "$pre_release_deadline" \
    "$PRIMARY_LIVE_FD_METRICS_TIMEOUT_SECONDS" \
    "$((PRIMARY_LIVE_FD_METRIC_CAPTURE_TIMEOUT_SECONDS + \
      PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS))")" || {
    log_error "primary live-descriptor proof did not retain enough time for its metric fence"
    return 1
  }
  wait_for_primary_security_metrics_quiescent \
    "$RESULT_DIR/metrics-security-primary-live-fd-probe.prom" \
    "primary live-descriptor security probe" "$metrics_timeout" || return $?
  capture_timeout="$(primary_live_fd_remaining_timeout \
    "$pre_release_deadline" \
    "$PRIMARY_LIVE_FD_METRIC_CAPTURE_TIMEOUT_SECONDS" \
    "$PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS")" || {
    log_error "primary live-descriptor proof did not retain enough time for metric evidence"
    return 1
  }
  capture_metric_phase_evidence "$probe_phase" "$capture_timeout" || return $?
  write_metrics_delta \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
    "$RESULT_DIR/phases/$probe_phase/obi-metrics.prom" \
    "$probe_delta" || return $?
  assert_primary_security_metric_delta "$probe_delta" negotiate 1 1 || return $?
  # The same-JVM decoy and the root PID 1-cgroup duplicated descriptor are
  # unauthorized. The held accepted socket also rejects one task-source lookup
  # on the request thread and one direct lookup from a different native thread
  # as missing, before the legitimate request-thread take is released.
  assert_primary_security_metric_delta "$probe_delta" take 2 2 || return $?
  assert_security_metric_delta \
    "$probe_delta" take missing getsockopt 2 2 || return $?
  (
    ALLOW_PRIMARY_SECURITY_METRICS=true
    # The victim has reached its Java getsockopt barrier, so its one inbound
    # context is staged before release. Only retrieval must remain denied.
    assert_bridge_metric_delta "$probe_delta" getsockopt 0 0 2 1 1 false 0
  ) || {
    log_error "primary live-descriptor security probe produced a valid bridge retrieval"
    return 1
  }
  record_obi_metric_pair \
    primary-live-fd-probe "$before_phase" "$probe_phase" same_process "" \
    >/dev/null || return $?

  release_timeout="$(primary_live_fd_remaining_timeout \
    "$pre_release_deadline" "$PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS" 0)" || {
    log_error "primary live-descriptor proof exhausted its release budget"
    return 1
  }
  [[ "$release_timeout" == "$PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS" ]] || {
    log_error "primary live-descriptor proof did not retain the full release budget"
    return 1
  }
  release_primary_live_fd_barrier \
    "$java_container" "$descriptor" "$release_evidence" "$release_timeout" || return $?
  if wait_for_background_process \
    "$victim_pid" "$PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS"; then
    victim_exit=0
    victim_pid=""
  else
    victim_exit=$?
  fi
  [[ "$victim_exit" == "0" ]] || {
    log_error "primary live-descriptor victim did not retain its exact parent"
    return "$victim_exit"
  }
  consume_primary_live_fd_barrier "$consumption_evidence" || return $?
  run_bounded 10 docker exec --user 0:0 "$java_container" \
    rm -f -- "$PRIMARY_SECURITY_PROBE_PATH" || return $?

  (
    ALLOW_PRIMARY_SECURITY_METRICS=true
    wait_for_bridge_metrics_quiescent \
      "$((before_success + 1))" \
      "$((before_stage + 1))" \
      "$RESULT_DIR/metrics-security-primary-live-fd-after.prom" \
      "primary live-descriptor legitimate victim"
  ) || return $?
  capture_metric_phase_evidence "$after_phase" || return $?
  write_metrics_delta \
    "$RESULT_DIR/phases/$before_phase/obi-metrics.prom" \
    "$RESULT_DIR/phases/$after_phase/obi-metrics.prom" \
    "$full_delta" || return $?
  assert_primary_security_metric_delta "$full_delta" negotiate 1 1 || return $?
  assert_primary_security_metric_delta "$full_delta" take 2 2 || return $?
  assert_security_metric_delta \
    "$full_delta" take missing getsockopt 2 2 || return $?
  (
    ALLOW_PRIMARY_SECURITY_METRICS=true
    assert_bridge_metric_delta "$full_delta" getsockopt 1 0 2 1 1 false 0
  ) || {
    log_error "primary live-descriptor security metrics did not preserve one legitimate retrieval"
    return 1
  }
  record_obi_metric_pair \
    primary-live-fd-full "$before_phase" "$after_phase" same_process "" \
    >/dev/null || return $?

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  recreate_instrumented_stack \
    tcp "post-primary live-descriptor security recovery" getsockopt true false base || return $?
  assert_runtime_contract basic true || return $?
  rm -f -- "$recovery_marker" || return $?
  PRIMARY_FAULT_STACK_ACTIVE=false
  restore_required=false
  run_primary_live_fd_security_recovery_scenario "$original_variant" || return $?
  printf '{"status":"passed","scenario":"primary-live-fd-security","probe":"%s","probe_status":"unverified","probe_verification":"metrics_verified","wrong_live_socket":"metrics_verified","duplicated_fd_wrong_process":"metrics_verified","wrong_current_tid_same_fd":"metrics_verified","wrong_logical_execution_same_fd":"metrics_verified","attacker_identity":"root","attacker_cgroup":"pid1-verified-preexec","legitimate_victim":"passed","post_abuse_recovery":"passed","before_phase":"phases/%s","probe_phase":"phases/%s","after_phase":"phases/%s"}\n' \
    "$(basename -- "$probe_output")" \
    "$before_phase" \
    "$probe_phase" \
    "$after_phase" \
    >"$RESULT_DIR/scenario-primary-live-fd-security-status.json" || return $?
  crosslink_and_bind_active_obi_metric_boundary_status \
    scenario-primary-live-fd-security-status.json || return $?

  commit_terminal_java_diagnostics_recovery_boundary || return $?
  trap - EXIT
  clear_terminal_java_diagnostics_recovery_boundary || return $?
)

validate_java_diagnostics_snapshot_hardlink_payload() {
  local -r observed_payload="$1"
  local -r expected_payload="$3"

  [[ "$expected_payload" == __any__ ||
    "$observed_payload" == "$expected_payload" ]] || return 1
  assert_sanitized_java_diagnostics_snapshot "$observed_payload"
}

extract_java_diagnostics_header_unlocked() {
  local -r headers="$1"
  local -r output="$2"
  local reference=""
  local phase=""
  local phase_dir=""
  local snapshot=""

  [[ -f "$headers" && ! -L "$headers" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false ]] || return 1
  reference="${output#"$RESULT_DIR/"}"
  [[ "$reference" != "$output" ]] || return 1
  phase="$(java_diagnostics_reference_phase "$reference")" || return 1
  phase_dir="$RESULT_DIR/phases/$phase"
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  snapshot="$(awk '
    {
      line = $0
      sub(/\r$/, "", line)
      separator = index(line, ":")
      if (separator == 0) {
        next
      }
      name = substr(line, 1, separator - 1)
      if (tolower(name) != "x-obi-java-diagnostics") {
        next
      }
      matches++
      value = substr(line, separator + 1)
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      selected = value
    }
    END {
      if (matches != 1 || selected == "") {
        exit 1
      }
      print selected
    }
  ' "$headers")" || return 1
  assert_sanitized_java_diagnostics_snapshot "$snapshot" || return 1
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  publish_terminal_owned_hardlink_payload \
    "$output" "$phase_dir/.java-diagnostics-header" \
    '^\.java-diagnostics-header\.[A-Za-z0-9]{6}$' \
    '^\.(java-diagnostics-header|terminal-diagnostics)\.[A-Za-z0-9]{6}$' \
    644 "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" "$snapshot" \
    validate_java_diagnostics_snapshot_hardlink_payload true \
    "$phase_dir/.java-diagnostics-header" \
    "$phase_dir/.terminal-diagnostics" || return $?
  record_last_java_diagnostics_reference_unlocked "$reference"
}

extract_java_diagnostics_header() {
  with_terminal_java_diagnostics_lock \
    extract_java_diagnostics_header_unlocked "$@"
}

extract_terminal_diagnostics_after_unlocked() {
  local -r input="$1"
  local -r output="$2"
  local -r field="$3"
  local reference=""
  local phase=""
  local phase_dir=""
  local snapshot=""

  case "$field" in
    fault_diagnostics_after|java_diagnostics_after) ;;
    *) return 1 ;;
  esac
  [[ -f "$input" && ! -L "$input" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false ]] || return 1
  reference="${output#"$RESULT_DIR/"}"
  [[ "$reference" != "$output" ]] || return 1
  phase="$(java_diagnostics_reference_phase "$reference")" || return 1
  phase_dir="$RESULT_DIR/phases/$phase"
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  snapshot="$(awk -v field="$field" '
    index($0, "\"" field "\"") {
      matches++
      line = $0
      pattern = "^[[:space:]]*\"" field "\"[[:space:]]*:[[:space:]]*\"[0-9a-z_=,]+\"[[:space:]]*,?[[:space:]]*$"
      if (line !~ pattern) {
        invalid = 1
        next
      }
      prefix = "^[[:space:]]*\"" field "\"[[:space:]]*:[[:space:]]*\""
      sub(prefix, "", line)
      sub(/"[[:space:]]*,?[[:space:]]*$/, "", line)
      selected = line
    }
    END {
      if (invalid || matches != 1 || selected == "") {
        exit 1
      }
      print selected
    }
  ' "$input")" || return 1
  assert_sanitized_java_diagnostics_snapshot "$snapshot" || return 1
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  publish_terminal_owned_hardlink_payload \
    "$output" "$phase_dir/.terminal-diagnostics" \
    '^\.terminal-diagnostics\.[A-Za-z0-9]{6}$' \
    '^\.(java-diagnostics-header|terminal-diagnostics)\.[A-Za-z0-9]{6}$' \
    644 "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" "$snapshot" \
    validate_java_diagnostics_snapshot_hardlink_payload true \
    "$phase_dir/.java-diagnostics-header" \
    "$phase_dir/.terminal-diagnostics" || return $?
  record_last_java_diagnostics_reference_unlocked "$reference"
}

extract_terminal_diagnostics_after() {
  with_terminal_java_diagnostics_lock \
    extract_terminal_diagnostics_after_unlocked "$@"
}

extract_fault_diagnostics_after() {
  extract_terminal_diagnostics_after "$1" "$2" fault_diagnostics_after
}

extract_java_diagnostics_after() {
  extract_terminal_diagnostics_after "$1" "$2" java_diagnostics_after
}

read_bounded_single_line_regular_file() {
  local -r input="$1"
  local -r maximum_bytes="$2"
  local descriptor=""
  local descriptor_path=""
  local path_identity=""
  local descriptor_identity=""
  local links=""
  local size=""
  local digest=""
  local reconstructed_digest=""
  local -a lines=()
  local LC_ALL=C

  [[ "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    -f "$input" && ! -L "$input" ]] || return 1
  path_identity="$(stat -Lc '%d:%i' -- "$input")" || return 1
  exec {descriptor}<"$input" || return $?
  descriptor_path="/proc/self/fd/$descriptor"
  if [[ ! -f "$descriptor_path" ]] ||
    ! descriptor_identity="$(stat -Lc '%d:%i' -- "$descriptor_path")" ||
    [[ -L "$input" ]] ||
    [[ "$(stat -Lc '%d:%i' -- "$input")" != "$path_identity" ]] ||
    [[ "$descriptor_identity" != "$path_identity" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  links="$(stat -Lc '%h' -- "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  size="$(stat -Lc '%s' -- "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  if [[ "$links" != 1 ]] || ((size == 0 || size > maximum_bytes)); then
    exec {descriptor}<&-
    return 1
  fi
  digest="$(sha256sum "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  digest="${digest%% *}"
  mapfile -t lines <"$descriptor_path" || {
    exec {descriptor}<&-
    return 1
  }
  exec {descriptor}<&-
  (( ${#lines[@]} == 1 )) || return 1
  if ((size == ${#lines[0]})); then
    reconstructed_digest="$(printf '%s' "${lines[0]}" | sha256sum)" || return 1
  elif ((size == ${#lines[0]} + 1)); then
    reconstructed_digest="$(printf '%s\n' "${lines[0]}" | sha256sum)" || return 1
  else
    return 1
  fi
  reconstructed_digest="${reconstructed_digest%% *}"
  [[ "$reconstructed_digest" == "$digest" ]] || return 1
  printf '%s\n' "${lines[0]}"
}

read_bounded_single_line_owned_regular_file() {
  local -r input="$1"
  local -r maximum_bytes="$2"
  local -r expected_mode="$3"
  local -r expected_links="$4"
  local descriptor=""
  local descriptor_path=""
  local path_identity=""
  local descriptor_identity=""
  local size=""
  local digest=""
  local reconstructed_digest=""
  local -a lines=()
  local LC_ALL=C

  [[ "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$expected_mode" =~ ^(600|644)$ && "$expected_links" =~ ^[12]$ &&
    -f "$input" && ! -L "$input" ]] || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$input")" || return 1
  [[ "$path_identity" == *":$(id -u):$expected_mode:$expected_links" ]] ||
    return 1
  exec {descriptor}<"$input" || return $?
  descriptor_path="/proc/self/fd/$descriptor"
  if [[ ! -f "$descriptor_path" ]] ||
    ! descriptor_identity="$(
      stat -Lc '%d:%i:%u:%a:%h' -- "$descriptor_path"
    )" ||
    [[ "$descriptor_identity" != "$path_identity" ]] ||
    [[ -L "$input" ]] ||
    [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$input")" != "$path_identity" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  size="$(stat -Lc '%s' -- "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  if ((size == 0 || size > maximum_bytes)); then
    exec {descriptor}<&-
    return 1
  fi
  digest="$(sha256sum "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  digest="${digest%% *}"
  mapfile -t lines <"$descriptor_path" || {
    exec {descriptor}<&-
    return 1
  }
  if [[ -L "$input" ||
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$input")" != \
      "$path_identity:$size" ||
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$descriptor_path")" != \
      "$descriptor_identity:$size" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  exec {descriptor}<&-
  (( ${#lines[@]} == 1 )) || return 1
  if ((size == ${#lines[0]})); then
    reconstructed_digest="$(printf '%s' "${lines[0]}" | sha256sum)" ||
      return 1
  elif ((size == ${#lines[0]} + 1)); then
    reconstructed_digest="$(printf '%s\n' "${lines[0]}" | sha256sum)" ||
      return 1
  else
    return 1
  fi
  reconstructed_digest="${reconstructed_digest%% *}"
  [[ "$reconstructed_digest" == "$digest" ]] || return 1
  printf '%s\n' "${lines[0]}"
}

canonical_uint64_string() {
  local -r canonical_value="$1"
  local -r output_name="${2:-}"
  local LC_ALL=C

  (($# == 1 || $# == 2)) || return 1
  [[ "$canonical_value" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  # Equal-width canonical decimal strings compare safely without arithmetic.
  # shellcheck disable=SC2071
  if (( ${#canonical_value} > ${#MAX_UINT64_DECIMAL} )) ||
    { (( ${#canonical_value} == ${#MAX_UINT64_DECIMAL} )) &&
      [[ "$canonical_value" > "$MAX_UINT64_DECIMAL" ]]; }; then
    return 1
  fi
  if (($# == 2)); then
    [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || return 1
    printf -v "$output_name" '%s' "$canonical_value"
  else
    printf '%s\n' "$canonical_value"
  fi
}

uint64_string_compare() {
  local left=""
  local right=""
  local comparison_result=""
  local -r output_name="${3:-}"

  (($# == 2 || $# == 3)) || return 1
  canonical_uint64_string "$1" left || return 1
  canonical_uint64_string "$2" right || return 1
  # Equal-width canonical decimal strings compare safely without arithmetic.
  # shellcheck disable=SC2071
  if (( ${#left} < ${#right} )); then
    comparison_result=-1
  elif (( ${#left} > ${#right} )); then
    comparison_result=1
  elif [[ "$left" == "$right" ]]; then
    comparison_result=0
  elif [[ "$left" < "$right" ]]; then
    comparison_result=-1
  else
    comparison_result=1
  fi
  if (($# == 3)); then
    [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || return 1
    printf -v "$output_name" '%s' "$comparison_result"
  else
    printf '%s\n' "$comparison_result"
  fi
}

uint64_string_subtract() {
  local minuend=""
  local subtrahend=""
  local comparison=""
  local result=""
  local digit=""
  local -i minuend_index=0
  local -i subtrahend_index=0
  local -i minuend_digit=0
  local -i subtrahend_digit=0
  local -i borrow=0
  local -i difference=0
  local -r output_name="${3:-}"

  (($# == 2 || $# == 3)) || return 1
  canonical_uint64_string "$1" minuend || return 1
  canonical_uint64_string "$2" subtrahend || return 1
  uint64_string_compare "$minuend" "$subtrahend" comparison || return 1
  [[ "$comparison" != -1 ]] || return 1
  minuend_index=$((${#minuend} - 1))
  subtrahend_index=$((${#subtrahend} - 1))
  while ((minuend_index >= 0)); do
    minuend_digit=$((10#${minuend:minuend_index:1} - borrow))
    subtrahend_digit=0
    if ((subtrahend_index >= 0)); then
      subtrahend_digit=$((10#${subtrahend:subtrahend_index:1}))
    fi
    if ((minuend_digit < subtrahend_digit)); then
      minuend_digit=$((minuend_digit + 10))
      borrow=1
    else
      borrow=0
    fi
    difference=$((minuend_digit - subtrahend_digit))
    printf -v digit '%d' "$difference"
    result="$digit$result"
    minuend_index=$((minuend_index - 1))
    subtrahend_index=$((subtrahend_index - 1))
  done
  ((borrow == 0)) || return 1
  while (( ${#result} > 1 )) && [[ "$result" == 0* ]]; do
    result="${result#0}"
  done
  canonical_uint64_string "$result" result || return 1
  if (($# == 3)); then
    [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || return 1
    printf -v "$output_name" '%s' "$result"
  else
    printf '%s\n' "$result"
  fi
}

obi_metric_phase_reference() {
  local -r phase="$1"
  local -r name="$2"

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  case "$name" in
    identity) printf 'phases/%s/obi-identity.json\n' "$phase" ;;
    metrics) printf 'phases/%s/obi-metrics.prom\n' "$phase" ;;
    *) return 1 ;;
  esac
}

validate_obi_process_identity_payload_structure() {
  local -r payload="$1"
  local state=""
  local container_id=""
  local host_pid=""
  local exit_code=""
  local metrics_reference=""
  local metrics_sha256=""

  state="$(jq -er '.state' <<<"$payload")" || return 1
  case "$state" in
    running)
      jq -e '
        keys == [
          "container_id", "host_pid", "metrics_reference", "metrics_sha256",
          "schema", "started_at", "state"
        ] and
        .schema == "obi-process-identity-v1" and
        .state == "running" and
        ([.container_id, .host_pid, .metrics_reference, .metrics_sha256,
          .started_at][] | type == "string")
      ' <<<"$payload" >/dev/null || return 1
      ;;
    obi_stopped)
      jq -e '
        keys == [
          "container_id", "exit_code", "finished_at", "host_pid", "schema",
          "started_at", "state"
        ] and
        .schema == "obi-process-identity-v1" and
        .state == "obi_stopped" and
        ([.container_id, .exit_code, .finished_at, .host_pid, .started_at][] |
          type == "string")
      ' <<<"$payload" >/dev/null || return 1
      ;;
    *) return 1 ;;
  esac
  container_id="$(jq -er '.container_id' <<<"$payload")" || return 1
  host_pid="$(jq -er '.host_pid' <<<"$payload")" || return 1
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  canonical_uint64_string "$host_pid" >/dev/null || return 1
  if [[ "$state" == running && "$host_pid" == 0 ]]; then
    return 1
  fi
  [[ "$(jq -er '.started_at' <<<"$payload")" =~ ^[0-9TZ:.-]{20,64}$ ]] ||
    return 1
  if [[ "$state" == obi_stopped ]]; then
    exit_code="$(jq -er '.exit_code' <<<"$payload")" || return 1
    canonical_uint64_string "$exit_code" >/dev/null || return 1
    [[ "$(jq -er '.finished_at' <<<"$payload")" =~ ^[0-9TZ:.-]{20,64}$ ]] ||
      return 1
  else
    metrics_reference="$(jq -er '.metrics_reference' <<<"$payload")" || return 1
    metrics_sha256="$(jq -er '.metrics_sha256' <<<"$payload")" || return 1
    [[ "$metrics_reference" =~ ^phases/[a-z0-9][a-z0-9-]{0,63}/obi-metrics\.prom$ &&
      "$metrics_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  fi
  printf '%s\n' "$payload"
}

validate_obi_process_identity_payload() {
  local -r payload="$1"
  local state=""
  local metrics_reference=""
  local metrics_sha256=""
  local metrics=""
  local observed_sha256=""

  validate_obi_process_identity_payload_structure "$payload" >/dev/null ||
    return 1
  state="$(jq -er '.state' <<<"$payload")" || return 1
  if [[ "$state" == running ]]; then
    metrics_reference="$(jq -er '.metrics_reference' <<<"$payload")" || return 1
    metrics_sha256="$(jq -er '.metrics_sha256' <<<"$payload")" || return 1
    metrics="$RESULT_DIR/$metrics_reference"
    [[ -f "$metrics" && ! -L "$metrics" ]] || return 1
    obi_metric_output_parent_is_contained "$metrics" || return 1
    bounded_evidence_file \
      "$metrics" "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
      "$OBI_METRIC_SNAPSHOT_MAX_LINES" || return 1
    observed_sha256="$(sha256sum "$metrics")" || return 1
    observed_sha256="${observed_sha256%% *}"
    [[ "$observed_sha256" == "$metrics_sha256" ]] || return 1
  fi
  printf '%s\n' "$payload"
}

obi_process_identity_payload_from_reference() {
  local -r reference="$1"
  local -r output_name="${2:-}"
  local phase=""
  local input=""
  local payload=""

  (($# == 1 || $# == 2)) || return 1
  [[ -z "$output_name" || "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] ||
    return 1
  [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-identity\.json$ ]] ||
    return 1
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true ]]; then
    if [[ -n "${OBI_METRIC_BOUNDARY_IDENTITY_PAYLOAD_CACHE[$reference]+present}" ]]; then
      if [[ -n "$output_name" ]]; then
        printf -v "$output_name" '%s' \
          "${OBI_METRIC_BOUNDARY_IDENTITY_PAYLOAD_CACHE[$reference]}"
      else
        printf '%s\n' "${OBI_METRIC_BOUNDARY_IDENTITY_PAYLOAD_CACHE[$reference]}"
      fi
      return 0
    fi
  fi
  phase="${BASH_REMATCH[1]}"
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  input="$RESULT_DIR/$reference"
  payload="$(read_bounded_single_line_regular_file \
    "$input" "$OBI_PROCESS_IDENTITY_MAX_BYTES")" || return 1
  validate_obi_process_identity_payload "$payload" >/dev/null || return 1
  if [[ "$(jq -er '.state' <<<"$payload")" == running ]]; then
    [[ "$(jq -er '.metrics_reference' <<<"$payload")" == \
      "$(obi_metric_phase_reference "$phase" metrics)" ]] || return 1
  fi
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true ]]; then
    OBI_METRIC_BOUNDARY_IDENTITY_PAYLOAD_CACHE["$reference"]="$payload"
  fi
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$payload"
  else
    printf '%s\n' "$payload"
  fi
}

normalize_owned_phase_publication_handle() {
  local -r output="$1"
  local -r handle_prefix="$2"
  local -r expected_digest="$3"
  local -r preserve_h2="${4:-false}"
  local handle=""
  local handle_name=""
  local output_identity=""
  local handle_identity=""
  local handle_device=""
  local handle_inode=""
  local handle_owner=""
  local handle_mode=""
  local handle_links=""
  local observed_digest=""
  local observed_payload=""
  local path=""
  local -a handles=()

  (($# == 3 || $# == 4)) || return 1
  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "$expected_digest" =~ ^[0-9a-f]{64}$ &&
    ( "$preserve_h2" == true || "$preserve_h2" == false ) &&
    "${handle_prefix%/*}" == "${output%/*}" &&
    "${handle_prefix##*/}" =~ ^\.obi-(identity|metrics-unavailable)$ ]] ||
    return 1
  obi_metric_output_parent_is_contained "$output" || return 1
  for path in "$handle_prefix".*; do
    if [[ -e "$path" || -L "$path" ]]; then
      handles+=("$path")
      ((${#handles[@]} <= 1)) || return 1
    fi
  done
  ((${#handles[@]} <= 1)) || return 1
  if [[ ! -e "$output" && ! -L "$output" ]]; then
    ((${#handles[@]} == 1)) || return 0
    handle="${handles[0]}"
    handle_name="${handle##*/}"
    [[ "$handle_name" =~ \
      ^\.obi-(identity|metrics-unavailable)\.[A-Za-z0-9]{6}$ &&
      -f "$handle" && ! -L "$handle" ]] || return 1
    handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" || return 1
    IFS=: read -r handle_device handle_inode handle_owner handle_mode \
      handle_links <<<"$handle_identity"
    [[ -n "$handle_device" && -n "$handle_inode" &&
      "$handle_owner" == "$(id -u)" &&
      ( "$handle_mode" == 600 || "$handle_mode" == 644 ) &&
      "$handle_links" == 1 ]] || return 1
    remove_terminal_owned_private_path "$handle" "$handle_identity"
    return $?
  fi
  [[ -f "$output" && ! -L "$output" ]] || return 1
  output_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$output")" || return 1
  if ((${#handles[@]} == 0)); then
    [[ "$output_identity" == *":$(id -u):644:1" ]] || return 1
    observed_digest="$(sha256sum "$output")" || return 1
    observed_digest="${observed_digest%% *}"
    [[ "$observed_digest" == "$expected_digest" ]]
    return $?
  fi
  handle="${handles[0]}"
  handle_name="${handle##*/}"
  [[ "$handle_name" =~ ^\.obi-(identity|metrics-unavailable)\.[A-Za-z0-9]{6}$ &&
    -f "$handle" && ! -L "$handle" ]] ||
    return 1
  handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" || return 1
  IFS=: read -r handle_device handle_inode handle_owner handle_mode \
    handle_links <<<"$handle_identity"
  [[ -n "$handle_device" && -n "$handle_inode" &&
    "$handle_owner" == "$(id -u)" ]] || return 1
  if [[ "$handle_links" == 1 ]]; then
    [[ "$handle_mode" =~ ^(600|644)$ &&
      "$output_identity" == *":$(id -u):644:1" &&
      ! "$handle" -ef "$output" ]] || return 1
    remove_terminal_owned_private_path "$handle" "$handle_identity" || return $?
    observed_digest="$(sha256sum "$output")" || return 1
    observed_digest="${observed_digest%% *}"
    [[ "$observed_digest" == "$expected_digest" ]]
    return $?
  fi
  [[ "$handle_links" == 2 && "$handle_mode" == 644 &&
    "$output_identity" == "$handle_identity" &&
    "$output_identity" == *":$(id -u):644:2" ]] || return 1
  observed_digest="$(sha256sum "$output")" || return 1
  observed_digest="${observed_digest%% *}"
  case "$handle_name" in
    .obi-identity.*)
      observed_payload="$(read_bounded_single_line_owned_regular_file \
        "$output" "$OBI_PROCESS_IDENTITY_MAX_BYTES" 644 2)" || return 1
      validate_obi_process_identity_payload "$observed_payload" >/dev/null ||
        return 1
      ;;
    .obi-metrics-unavailable.*)
      observed_payload="$(read_bounded_single_line_owned_regular_file \
        "$output" 64 644 2)" || return 1
      [[ "$observed_payload" == unavailable ]] || return 1
      ;;
    *) return 1 ;;
  esac
  [[ "$observed_digest" == "$expected_digest" ]] || return 1
  if [[ "$preserve_h2" == true ]]; then
    return 2
  fi
  remove_terminal_owned_hardlink_handle \
    "$handle" "$output" "$output_identity" || return $?
  observed_digest="$(sha256sum "$output")" || return 1
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$expected_digest" ]]
}

obi_process_identity_publication_matches() {
  local -r phase="$1"
  local -r expected_payload="$2"
  local reference=""
  local output=""
  local observed_payload=""

  reference="$(obi_metric_phase_reference "$phase" identity)" || return 1
  output="$RESULT_DIR/$reference"
  [[ -f "$output" && ! -L "$output" &&
    "$(stat -Lc '%u:%a:%h' -- "$output")" == "$(id -u):644:1" ]] ||
    return 1
  observed_payload="$(
    obi_process_identity_payload_from_reference "$reference"
  )" || return 1
  [[ "$observed_payload" == "$expected_payload" ]]
}

obi_phase_live_family_is_exclusive() {
  local -r phase="$1"
  local -r phase_dir="$RESULT_DIR/phases/$phase"
  local path=""

  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  for path in "$phase_dir"/.obi-metrics-unavailable.*; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
}

obi_phase_unavailable_family_is_exclusive() {
  local -r phase="$1"
  local -r phase_dir="$RESULT_DIR/phases/$phase"
  local path=""

  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  [[ ! -e "$phase_dir/obi-identity.json" &&
    ! -L "$phase_dir/obi-identity.json" ]] || return 1
  for path in \
    "$phase_dir"/.obi-identity.* \
    "$phase_dir"/.obi-metrics.* \
    "$phase_dir"/.obi-metrics-parsed.*; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
}

obi_phase_stopped_family_is_exclusive() {
  local -r phase="$1"
  local -r phase_dir="$RESULT_DIR/phases/$phase"
  local path=""

  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  [[ ! -e "$phase_dir/obi-metrics.prom" &&
    ! -L "$phase_dir/obi-metrics.prom" ]] || return 1
  for path in \
    "$phase_dir"/.obi-metrics.* \
    "$phase_dir"/.obi-metrics-unavailable.* \
    "$phase_dir"/.obi-metrics-parsed.*; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
}

publish_obi_process_identity_payload_unlocked() {
  local -r phase="$1"
  local -r payload="$2"
  local reference=""
  local output=""
  local candidate=""
  local candidate_identity=""
  local candidate_private_identity=""
  local candidate_digest=""
  local expected_digest=""
  local boundary_index_payload=""
  local identity_state=""
  local publication_status=0
  local identity_published=false

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false ]] || return 1
  ensure_java_diagnostics_phase_directory "$phase" || return 1
  reference="$(obi_metric_phase_reference "$phase" identity)" || return 1
  output="$RESULT_DIR/$reference"
  validate_obi_process_identity_payload "$payload" >/dev/null || return 1
  identity_state="$(jq -er '.state' <<<"$payload")" || return 1
  # Running identities are committed only by the paired metrics+identity
  # publisher. This direct path is deliberately limited to the stopped family,
  # where the preplanned pair intent closes the publication-to-attach window.
  [[ "$identity_state" == obi_stopped ]] || return 1
  obi_phase_stopped_family_is_exclusive "$phase" || return 1
  if obi_metric_boundary_index_is_initialized; then
    boundary_index_payload="$(obi_metric_boundary_index_payload)" || return 1
    if [[ "$identity_state" == obi_stopped ]]; then
      jq -e --arg capture_id "$phase" '
        [.boundaries[] | select(.state == "active")] as $active |
        ($active | length) == 1 and
        ([$active[0].captures[] | select(.kind == "pair")] | last) as $latest |
        $latest.id == $capture_id and $latest.state == "planned"
      ' <<<"$boundary_index_payload" >/dev/null || return 1
    fi
  elif ! obi_metric_boundary_journal_paths_are_cleanly_absent; then
    return 1
  fi
  expected_digest="$(printf '%s\n' "$payload" | sha256sum)" || return 1
  expected_digest="${expected_digest%% *}"
  normalize_owned_phase_publication_handle \
    "$output" "$RESULT_DIR/phases/$phase/.obi-identity" "$expected_digest" ||
    return $?
  if [[ -e "$output" || -L "$output" ]]; then
    if obi_process_identity_publication_matches "$phase" "$payload"; then
      return 0
    fi
    normalize_owned_phase_publication_handle \
      "$output" "$RESULT_DIR/phases/$phase/.obi-identity" "$expected_digest" ||
      return 1
    obi_process_identity_publication_matches "$phase" "$payload"
    return $?
  fi
  candidate="$(mktemp "$RESULT_DIR/phases/$phase/.obi-identity.XXXXXX")" ||
    return $?
  candidate_private_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
    return 1
  [[ "$candidate_private_identity" == *":$(id -u):600:1" ]] || return 1
  if printf '%s\n' "$payload" >"$candidate" && chmod 0644 -- "$candidate"; then
    :
  else
    publication_status=$?
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_private_identity" || return 1
    return "$publication_status"
  fi
  candidate_identity="$(stat -Lc '%d:%i:%u:%a' -- "$candidate")" || return 1
  candidate_digest="$(sha256sum "$candidate")" || return 1
  candidate_digest="${candidate_digest%% *}"
  if ln -T -- "$candidate" "$output"; then
    identity_published=true
  else
    publication_status=$?
    if [[ -f "$output" && ! -L "$output" && "$candidate" -ef "$output" ]] &&
      obi_owned_publication_matches \
        "$output" "$candidate_identity" "$candidate_digest" 2; then
      identity_published=true
    fi
  fi
  if [[ "$identity_published" != true ]]; then
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_identity:1" || return 1
    if obi_process_identity_publication_matches "$phase" "$payload"; then
      return 0
    fi
    return "$publication_status"
  fi
  if ! obi_owned_publication_matches \
    "$output" "$candidate_identity" "$candidate_digest" 2; then
    if [[ -f "$output" && ! -L "$output" && "$candidate" -ef "$output" ]]; then
      remove_terminal_owned_hardlink_handle \
        "$output" "$candidate" "$candidate_identity:2" || return 1
    fi
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_identity:1" || return 1
    return 1
  fi
  remove_terminal_owned_hardlink_handle \
    "$candidate" "$output" "$candidate_identity:2" || return $?
  obi_owned_publication_matches \
    "$output" "$candidate_identity" "$candidate_digest" 1 || return 1
  obi_process_identity_publication_matches "$phase" "$payload"
}

publish_obi_process_identity_payload() {
  with_terminal_java_diagnostics_lock \
    publish_obi_process_identity_payload_unlocked "$@"
}

current_obi_running_observation_payload() {
  local container_id=""
  local inspection=""
  local inspected_id=""
  local host_pid=""
  local started_at=""
  local running=""
  local extra=""
  local payload=""

  container_id="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet obi)" || return $?
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  inspection="$(run_bounded 10 docker inspect --format \
    '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}}' \
    "$container_id")" || return $?
  read -r inspected_id host_pid started_at running extra <<<"$inspection"
  [[ -z "$extra" && "$inspected_id" == "$container_id" &&
    "$running" == true ]] || return 1
  canonical_uint64_string "$host_pid" >/dev/null || return 1
  [[ "$host_pid" != 0 ]] || return 1
  payload="$(jq -cSn \
    --arg container_id "$container_id" \
    --arg host_pid "$host_pid" \
    --arg started_at "$started_at" '
      {
        schema: "obi-process-observation-v1",
        state: "running",
        container_id: $container_id,
        host_pid: $host_pid,
        started_at: $started_at
      }
    ')" || return 1
  jq -e '
    keys == ["container_id", "host_pid", "schema", "started_at", "state"] and
    .schema == "obi-process-observation-v1" and
    .state == "running" and
    (.container_id | type == "string") and
    (.host_pid | type == "string") and
    (.started_at | type == "string")
  ' <<<"$payload" >/dev/null || return 1
  [[ "$(jq -er '.container_id' <<<"$payload")" =~ ^[0-9a-f]{64}$ ]] ||
    return 1
  [[ "$(jq -er '.host_pid' <<<"$payload")" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$(jq -er '.started_at' <<<"$payload")" =~ ^[0-9TZ:.-]{20,64}$ ]] ||
    return 1
  printf '%s\n' "$payload"
}

normalize_owned_obi_h1_scratch_family() {
  local -r directory="$1"
  local -r prefix="$2"
  local -r basename_pattern="$3"
  local candidate=""
  local basename=""
  local identity=""
  local path=""
  local -a candidates=()

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    -d "$directory" && ! -L "$directory" &&
    "${prefix%/*}" == "$directory" ]] || return 1
  for path in "$prefix".*; do
    if [[ -e "$path" || -L "$path" ]]; then
      candidates+=("$path")
      ((${#candidates[@]} <= 1)) || return 1
    fi
  done
  ((${#candidates[@]} == 1)) || return 0
  candidate="${candidates[0]}"
  basename="${candidate##*/}"
  [[ "$basename" =~ $basename_pattern &&
    -f "$candidate" && ! -L "$candidate" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" || return 1
  [[ "$identity" == *":$(id -u):600:1" ||
    "$identity" == *":$(id -u):644:1" ]] || return 1
  remove_terminal_owned_private_path "$candidate" "$identity"
}

normalize_owned_obi_metric_phase_scratch_residue() {
  local -r phase="$1"
  local -r phase_dir="$RESULT_DIR/phases/$phase"

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  normalize_owned_obi_h1_scratch_family \
    "$phase_dir" "$phase_dir/.obi-metrics-parsed" \
    '^\.obi-metrics-parsed\.[A-Za-z0-9]{6}$'
}

normalize_owned_obi_metric_phase_capture() {
  local -r phase="$1"
  local -r preserve_h2="${2:-false}"
  local phase_dir=""
  local metrics_output=""
  local identity_output=""
  local metrics_handle=""
  local identity_handle=""
  local path=""
  local name=""
  local metrics_identity=""
  local identity_identity=""
  local metrics_digest=""
  local identity_payload=""
  local identity_size=""
  local handle_identity=""
  local output_present=false
  local identity_present=false
  local -a handles=()
  local -a identity_lines=()

  (($# == 1 || $# == 2)) || return 1
  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    ( "$preserve_h2" == true || "$preserve_h2" == false ) &&
    "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  phase_dir="$RESULT_DIR/phases/$phase"
  metrics_output="$phase_dir/obi-metrics.prom"
  identity_output="$phase_dir/obi-identity.json"
  [[ ! -L "$metrics_output" && ! -L "$identity_output" ]] || return 1
  [[ -f "$metrics_output" ]] && output_present=true
  [[ -f "$identity_output" ]] && identity_present=true
  for path in "$phase_dir"/.obi-*; do
    if [[ -e "$path" || -L "$path" ]]; then
      handles+=("$path")
    fi
  done
  ((${#handles[@]} <= 2)) || return 1
  for path in "${handles[@]}"; do
    name="${path##*/}"
    case "$name" in
      .obi-metrics.??????)
        [[ "$name" =~ ^\.obi-metrics\.[A-Za-z0-9]{6}$ &&
          -z "$metrics_handle" ]] || return 1
        metrics_handle="$path"
        ;;
      .obi-identity.??????)
        [[ "$name" =~ ^\.obi-identity\.[A-Za-z0-9]{6}$ &&
          -z "$identity_handle" ]] || return 1
        identity_handle="$path"
        ;;
      *) return 1 ;;
    esac
  done
  if [[ "$output_present" != true || "$identity_present" != true ]]; then
    if [[ "$output_present" == true ]]; then
      [[ -n "$metrics_handle" && -f "$metrics_handle" &&
        ! -L "$metrics_handle" && "$metrics_handle" -ef "$metrics_output" ]] ||
        return 1
      handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$metrics_handle")" ||
        return 1
      [[ "$handle_identity" == *":$(id -u):644:2" ]] || return 1
      remove_terminal_owned_hardlink_handle \
        "$metrics_output" "$metrics_handle" "$handle_identity" || return $?
    fi
    if [[ -n "$metrics_handle" ]]; then
      handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$metrics_handle")" ||
        return 1
      remove_terminal_owned_private_path \
        "$metrics_handle" "$handle_identity" || return $?
    fi
    if [[ "$identity_present" == true ]]; then
      [[ -n "$identity_handle" && -f "$identity_handle" &&
        ! -L "$identity_handle" && "$identity_handle" -ef "$identity_output" ]] ||
        return 1
      handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$identity_handle")" ||
        return 1
      [[ "$handle_identity" == *":$(id -u):644:2" ]] || return 1
      remove_terminal_owned_hardlink_handle \
        "$identity_output" "$identity_handle" "$handle_identity" || return $?
    fi
    if [[ -n "$identity_handle" ]]; then
      handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$identity_handle")" ||
        return 1
      remove_terminal_owned_private_path \
        "$identity_handle" "$handle_identity" || return $?
    fi
    [[ ! -e "$metrics_output" && ! -L "$metrics_output" &&
      ! -e "$identity_output" && ! -L "$identity_output" ]]
    return $?
  fi
  metrics_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$metrics_output")" ||
    return 1
  identity_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$identity_output")" ||
    return 1
  if [[ -n "$metrics_handle" ]]; then
    handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$metrics_handle")" ||
      return 1
    if [[ "$handle_identity" == *":$(id -u):644:1" &&
      "$metrics_identity" == *":$(id -u):644:1" &&
      ! "$metrics_handle" -ef "$metrics_output" ]]; then
      remove_terminal_owned_private_path \
        "$metrics_handle" "$handle_identity" || return $?
      metrics_handle=""
    else
      [[ -f "$metrics_handle" && ! -L "$metrics_handle" &&
        "$metrics_handle" -ef "$metrics_output" &&
        "$handle_identity" == "$metrics_identity" &&
        "$metrics_identity" == *":$(id -u):644:2" ]] || return 1
    fi
  else
    [[ "$metrics_identity" == *":$(id -u):644:1" ]] || return 1
  fi
  if [[ -n "$identity_handle" ]]; then
    handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$identity_handle")" ||
      return 1
    if [[ "$handle_identity" == *":$(id -u):644:1" &&
      "$identity_identity" == *":$(id -u):644:1" &&
      ! "$identity_handle" -ef "$identity_output" ]]; then
      remove_terminal_owned_private_path \
        "$identity_handle" "$handle_identity" || return $?
      identity_handle=""
    else
      [[ -f "$identity_handle" && ! -L "$identity_handle" &&
        "$identity_handle" -ef "$identity_output" &&
        "$handle_identity" == "$identity_identity" &&
        "$identity_identity" == *":$(id -u):644:2" ]] || return 1
    fi
  else
    [[ "$identity_identity" == *":$(id -u):644:1" ]] || return 1
  fi
  bounded_evidence_file \
    "$metrics_output" "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
    "$OBI_METRIC_SNAPSHOT_MAX_LINES" || return 1
  metrics_digest="$(sha256sum "$metrics_output")" || return 1
  metrics_digest="${metrics_digest%% *}"
  identity_size="$(stat -Lc '%s' -- "$identity_output")" || return 1
  ((identity_size > 0 && identity_size <= OBI_PROCESS_IDENTITY_MAX_BYTES)) ||
    return 1
  mapfile -t identity_lines <"$identity_output" || return 1
  ((${#identity_lines[@]} == 1)) || return 1
  identity_payload="${identity_lines[0]}"
  [[ "$identity_size" == "${#identity_payload}" ||
    "$identity_size" == "$(( ${#identity_payload} + 1 ))" ]] || return 1
  validate_obi_process_identity_payload "$identity_payload" >/dev/null || return 1
  [[ "$(jq -er '.state' <<<"$identity_payload")" == running &&
    "$(jq -er '.metrics_reference' <<<"$identity_payload")" == \
      "phases/$phase/obi-metrics.prom" &&
    "$(jq -er '.metrics_sha256' <<<"$identity_payload")" == \
      "$metrics_digest" ]] || return 1
  obi_phase_live_family_is_exclusive "$phase" || return 1
  if [[ "$preserve_h2" == true &&
    ( -n "$identity_handle" || -n "$metrics_handle" ) ]]; then
    return 2
  fi
  if [[ -n "$identity_handle" ]]; then
    remove_terminal_owned_hardlink_handle \
      "$identity_handle" "$identity_output" "$identity_identity" || return $?
  fi
  if [[ -n "$metrics_handle" ]]; then
    remove_terminal_owned_hardlink_handle \
      "$metrics_handle" "$metrics_output" "$metrics_identity" || return $?
  fi
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$metrics_output")" == \
      "${metrics_identity%:*}:1" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$identity_output")" == \
      "${identity_identity%:*}:1" ]] || return 1
  obi_process_identity_payload_from_reference \
    "phases/$phase/obi-identity.json" >/dev/null
}

with_obi_metric_capture_stage_lock() (
  local -r parent="${RESULT_DIR%/*}"
  local -r lock="$parent/.obi-metric-capture.lock"
  local lock_fd=""
  local path_identity=""
  local descriptor_identity=""
  local command_status=0
  local lock_status=0
  local parent_physical=""
  local result_physical=""
  local device=""
  local inode=""
  local links=""
  local owner=""
  local mode=""
  local normalization_status=0

  [[ "$RESULT_DIR" == /* && -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    -d "$parent" && ! -L "$parent" &&
    ! -L "$lock" && ( ! -e "$lock" || -f "$lock" ) ]] || return 1
  parent_physical="$(realpath -e -- "$parent")" || return 1
  result_physical="$(realpath -e -- "$RESULT_DIR")" || return 1
  [[ "${result_physical%/*}" == "$parent_physical" ]] || return 1
  umask 077
  exec {lock_fd}>>"$lock" || return $?
  path_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- "$lock")" || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- \
    "/proc/self/fd/$lock_fd")" || return 1
  IFS=: read -r device inode links owner mode <<<"$path_identity"
  [[ ! -L "$lock" && "$path_identity" == "$descriptor_identity" &&
    -n "$device" && -n "$inode" && "$links" == 1 &&
    "$owner" == "$(id -u)" && "$mode" == 600 ]] || return 1
  flock -x -w "$TERMINAL_JAVA_DIAGNOSTICS_LOCK_TIMEOUT_SECONDS" \
    "$lock_fd" || return $?
  path_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- "$lock")" || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- \
    "/proc/self/fd/$lock_fd")" || return 1
  IFS=: read -r device inode links owner mode <<<"$path_identity"
  [[ ! -L "$lock" && "$path_identity" == "$descriptor_identity" &&
    -n "$device" && -n "$inode" && "$links" == 1 &&
    "$owner" == "$(id -u)" && "$mode" == 600 ]] || return 1
  local OBI_METRIC_CAPTURE_STAGE_LOCK_HELD_BY_CALLER=true
  if normalize_obi_metric_capture_stage_residue; then
    if "$@"; then
      command_status=0
    else
      command_status=$?
    fi
  else
    command_status=$?
  fi
  if normalize_obi_metric_capture_stage_residue; then
    :
  else
    normalization_status=$?
    ((command_status == 0)) && command_status="$normalization_status"
  fi
  if flock -u "$lock_fd"; then
    :
  else
    lock_status=$?
  fi
  exec {lock_fd}>&-
  if ((command_status != 0)); then
    return "$command_status"
  fi
  return "$lock_status"
)

normalize_obi_metric_capture_stage_residue() {
  local -r parent="${RESULT_DIR%/*}"
  local stage=""
  local path=""
  local name=""
  local seen_raw=false
  local seen_parsed=false
  local seen_unsorted=false
  local identity=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local -a stages=()

  [[ "${OBI_METRIC_CAPTURE_STAGE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "$RESULT_DIR" == /* && -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    -d "$parent" && ! -L "$parent" ]] || return 1
  for path in "$parent"/.obi-metric-capture-stage.*; do
    [[ -e "$path" || -L "$path" ]] || continue
    stages+=("$path")
  done
  ((${#stages[@]} <= 1)) || return 1
  ((${#stages[@]} == 1)) || return 0
  stage="${stages[0]}"
  [[ "${stage%/*}" == "$parent" &&
    "${stage##*/}" =~ ^\.obi-metric-capture-stage\.[A-Za-z0-9]{6}$ &&
    -d "$stage" && ! -L "$stage" ]] || return 1
  IFS=$'\t' read -r device inode owner mode links <<<"$(
    stat -Lc $'%d\t%i\t%u\t%a\t%h' -- "$stage"
  )" || return 1
  [[ -n "$device" && -n "$inode" && "$owner" == "$(id -u)" &&
    "$mode" == 700 && "$links" == 2 ]] || return 1
  for path in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
    [[ -e "$path" || -L "$path" ]] || continue
    name="${path##*/}"
    [[ -f "$path" && ! -L "$path" ]] || return 1
    identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$path")" || return 1
    IFS=: read -r device inode owner mode links <<<"$identity"
    [[ -n "$device" && -n "$inode" && "$owner" == "$(id -u)" &&
      "$mode" == 600 && "$links" == 1 ]] || return 1
    case "$name" in
      metrics.raw)
        [[ "$seen_raw" == false ]] || return 1
        seen_raw=true
        ;;
      metrics.parsed)
        [[ "$seen_parsed" == false ]] || return 1
        seen_parsed=true
        ;;
      metrics.unsorted)
        [[ "$seen_unsorted" == false ]] || return 1
        seen_unsorted=true
        ;;
      *) return 1 ;;
    esac
  done
  cleanup_obi_metric_capture_stage \
    "$stage" "$stage/metrics.raw" "$stage/metrics.parsed" \
    "$stage/metrics.unsorted"
}

obi_metric_capture_stage_paths_are_cleanly_absent() {
  local -r parent="${RESULT_DIR%/*}"
  local path=""

  [[ "$RESULT_DIR" == /* && -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    -d "$parent" && ! -L "$parent" ]] || return 1
  for path in "$parent"/.obi-metric-capture-stage.*; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
}

create_obi_metric_capture_stage() {
  local -r output_name="$1"
  local -r parent="${RESULT_DIR%/*}"
  local candidate_stage=""
  local stage_identity=""
  local parent_physical=""
  local result_physical=""
  local create_status=0
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local attempt=0

  [[ "${OBI_METRIC_CAPTURE_STAGE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ &&
    "$RESULT_DIR" == /* && -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    -d "$parent" && ! -L "$parent" ]] || return 1
  parent_physical="$(realpath -e -- "$parent")" || return 1
  result_physical="$(realpath -e -- "$RESULT_DIR")" || return 1
  [[ "${result_physical%/*}" == "$parent_physical" ]] || return 1
  umask 077
  if candidate_stage="$(mktemp -d \
    "$parent/.obi-metric-capture-stage.XXXXXX")"; then
    create_status=0
  else
    create_status=$?
  fi
  if [[ -n "$candidate_stage" && "${candidate_stage%/*}" == "$parent" &&
    "${candidate_stage##*/}" =~ \
      ^\.obi-metric-capture-stage\.[A-Za-z0-9]{6}$ ]]; then
    printf -v "$output_name" '%s' "$candidate_stage"
  fi
  ((create_status == 0)) || return "$create_status"
  for attempt in 1 2 3; do
    stage_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
      "$candidate_stage")" && break
    stage_identity=""
  done
  IFS=: read -r device inode owner mode links <<<"$stage_identity"
  if [[ "${candidate_stage%/*}" != "$parent" ||
    ! "${candidate_stage##*/}" =~ \
      ^\.obi-metric-capture-stage\.[A-Za-z0-9]{6}$ ||
    ! -d "$candidate_stage" || -L "$candidate_stage" ||
    -z "$device" || -z "$inode" || "$owner" != "$(id -u)" ||
    "$mode" != 700 || "$links" != 2 ]]; then
    return 1
  fi
  [[ -n "${!output_name}" ]] || printf -v "$output_name" '%s' "$candidate_stage"
}

cleanup_obi_metric_capture_stage() {
  local -r stage="$1"
  local -r parent="${RESULT_DIR%/*}"
  local stage_identity=""
  local file=""
  local identity=""
  local current_identity=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local cleanup_status=0
  local file_status=0
  local removal_status=1
  local attempt=0
  local -a files=()
  local -a identities=()

  [[ "${OBI_METRIC_CAPTURE_STAGE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${stage%/*}" == "$parent" &&
    "${stage##*/}" =~ ^\.obi-metric-capture-stage\.[A-Za-z0-9]{6}$ &&
    -d "$stage" && ! -L "$stage" ]] || return 1
  stage_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$stage")" || return 1
  IFS=: read -r device inode owner mode links <<<"$stage_identity"
  [[ -n "$device" && -n "$inode" && "$owner" == "$(id -u)" &&
    "$mode" == 700 && "$links" == 2 ]] || return 1
  for file in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
    [[ -e "$file" || -L "$file" ]] || continue
    [[ "${file%/*}" == "$stage" ]] || return 1
    [[ -f "$file" && ! -L "$file" ]] || return 1
    case "${file##*/}" in
      metrics.raw|metrics.parsed|metrics.unsorted) ;;
      *) return 1 ;;
    esac
    identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$file")" || return 1
    IFS=: read -r device inode owner mode links <<<"$identity"
    [[ -n "$device" && -n "$inode" && "$owner" == "$(id -u)" &&
      "$mode" == 600 && "$links" == 1 ]] || return 1
    files+=("$file")
    identities+=("$identity")
  done
  for attempt in "${!files[@]}"; do
    file="${files[$attempt]}"
    identity="${identities[$attempt]}"
    if remove_terminal_owned_private_path "$file" "$identity"; then
      :
    else
      file_status=$?
      ((cleanup_status == 0)) && cleanup_status="$file_status"
    fi
  done
  ((cleanup_status == 0)) || return "$cleanup_status"
  for attempt in 1 2 3; do
    [[ -d "$stage" && ! -L "$stage" ]] || return 1
    current_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$stage")" || return 1
    [[ "$current_identity" == "$stage_identity" ]] || return 1
    if rmdir -- "$stage"; then
      removal_status=0
    else
      removal_status=$?
    fi
    [[ ! -e "$stage" && ! -L "$stage" ]] && return 0
  done
  return "$removal_status"
}

finalize_obi_metric_phase_publication_unlocked() {
  local -r phase="$1"
  local -r journal_mode="$2"
  local -r identity_digest="$3"
  local -r metrics_handle="$4"
  local -r metrics_identity="$5"
  local -r identity_handle="$6"
  local -r identity_identity="$7"
  local -r metrics_output="$RESULT_DIR/phases/$phase/obi-metrics.prom"
  local -r identity_output="$RESULT_DIR/phases/$phase/obi-identity.json"
  local attachment_state=""
  local attach_status=0

  (($# == 7)) || return 1
  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    ( "$journal_mode" == initialized || "$journal_mode" == legacy ) &&
    "$identity_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ -z "$metrics_handle" ||
    "$metrics_identity" == *":$(id -u):644:2" ]] || return 1
  [[ -z "$identity_handle" ||
    "$identity_identity" == *":$(id -u):644:2" ]] || return 1
  obi_phase_live_family_is_exclusive "$phase" || return 1
  if [[ "$journal_mode" == initialized ]]; then
    if attach_obi_metric_phase_capture_unlocked "$phase" "$identity_digest"; then
      attach_status=0
    else
      attach_status=$?
    fi
    attachment_state="$(obi_phase_capture_attachment_state_unlocked \
      "$phase" phase "$identity_digest")" || return 1
  else
    attachment_state=legacy
  fi
  case "$attachment_state" in
    captured|no_active|legacy)
      if [[ -n "$identity_handle" ]]; then
        remove_terminal_owned_hardlink_handle \
          "$identity_handle" "$identity_output" "$identity_identity" ||
          return $?
      fi
      if [[ -n "$metrics_handle" ]]; then
        remove_terminal_owned_hardlink_handle \
          "$metrics_handle" "$metrics_output" "$metrics_identity" ||
          return $?
      fi
      ;;
    not_captured)
      # Roll back only while both h2 handles still prove ownership of the two
      # canonicals. A partial/ambiguous state is preserved for the next
      # lock-held retry or the pre-freeze normalizer.
      [[ -n "$identity_handle" && -n "$metrics_handle" ]] || {
        ((attach_status != 0)) && return "$attach_status"
        return 1
      }
      remove_terminal_owned_hardlink_handle \
        "$identity_output" "$identity_handle" "$identity_identity" ||
        return $?
      remove_terminal_owned_private_path \
        "$identity_handle" "${identity_identity%:2}:1" || return $?
      remove_terminal_owned_hardlink_handle \
        "$metrics_output" "$metrics_handle" "$metrics_identity" ||
        return $?
      remove_terminal_owned_private_path \
        "$metrics_handle" "${metrics_identity%:2}:1" || return $?
      ((attach_status != 0)) && return "$attach_status"
      return 1
      ;;
    *) return 1 ;;
  esac
  obi_process_identity_payload_from_reference \
    "phases/$phase/obi-identity.json" >/dev/null || return 1
  obi_phase_live_family_is_exclusive "$phase" || return 1
  ((attach_status == 0)) || [[ "$attachment_state" == captured ]]
}

finalize_obi_unavailable_phase_publication_unlocked() {
  local -r phase="$1"
  local -r journal_mode="$2"
  local -r digest="$3"
  local -r handle="$4"
  local -r handle_identity="$5"
  local -r output="$RESULT_DIR/phases/$phase/obi-metrics.prom"
  local attachment_state=""
  local attach_status=0

  (($# == 5)) || return 1
  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    ( "$journal_mode" == initialized || "$journal_mode" == legacy ) &&
    "$digest" =~ ^[0-9a-f]{64}$ &&
    ( -z "$handle" || "$handle_identity" == *":$(id -u):644:2" ) ]] ||
    return 1
  obi_phase_unavailable_family_is_exclusive "$phase" || return 1
  if [[ "$journal_mode" == initialized ]]; then
    if attach_obi_unavailable_phase_capture_unlocked "$phase" "$digest"; then
      attach_status=0
    else
      attach_status=$?
    fi
    attachment_state="$(obi_phase_capture_attachment_state_unlocked \
      "$phase" unavailable "$digest")" || return 1
  else
    attachment_state=legacy
  fi
  case "$attachment_state" in
    captured|no_active|legacy)
      if [[ -n "$handle" ]]; then
        remove_terminal_owned_hardlink_handle \
          "$handle" "$output" "$handle_identity" || return $?
      fi
      ;;
    not_captured)
      [[ -n "$handle" ]] || {
        ((attach_status != 0)) && return "$attach_status"
        return 1
      }
      remove_terminal_owned_hardlink_handle \
        "$output" "$handle" "$handle_identity" || return $?
      remove_terminal_owned_private_path \
        "$handle" "${handle_identity%:2}:1" || return $?
      ((attach_status != 0)) && return "$attach_status"
      return 1
      ;;
    *) return 1 ;;
  esac
  obi_metrics_unavailable_phase_is_valid "$phase" || return 1
  obi_phase_unavailable_family_is_exclusive "$phase" || return 1
  ((attach_status == 0)) || [[ "$attachment_state" == captured ]]
}

capture_bounded_obi_metric_phase_publication_unlocked() {
  local -r phase="$1"
  local -r staged_metrics="$2"
  local -r identity_payload="$3"
  local phase_dir="$RESULT_DIR/phases/$phase"
  local metrics_reference="phases/$phase/obi-metrics.prom"
  local identity_reference="phases/$phase/obi-identity.json"
  local metrics_output="$RESULT_DIR/$metrics_reference"
  local identity_output="$RESULT_DIR/$identity_reference"
  local metrics_candidate=""
  local identity_candidate=""
  local metrics_candidate_identity=""
  local identity_candidate_identity=""
  local metrics_digest=""
  local identity_digest=""
  local journal_mode=""
  local normalization_status=0
  local path=""
  local publication_status=0
  local metrics_link_status=1
  local identity_link_status=1
  local attempt=0

  [[ "${OBI_METRIC_CAPTURE_STAGE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false &&
    "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    -f "$staged_metrics" && ! -L "$staged_metrics" ]] || return 1
  ensure_java_diagnostics_phase_directory "$phase" || return 1
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  bounded_evidence_file "$staged_metrics" "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
    "$OBI_METRIC_SNAPSHOT_MAX_LINES" || return 1
  metrics_digest="$(sha256sum "$staged_metrics")" || return 1
  metrics_digest="${metrics_digest%% *}"
  validate_obi_process_identity_payload_structure \
    "$identity_payload" >/dev/null || return 1
  [[ "$(jq -er '.state' <<<"$identity_payload")" == running &&
    "$(jq -er '.metrics_reference' <<<"$identity_payload")" == \
      "$metrics_reference" &&
    "$(jq -er '.metrics_sha256' <<<"$identity_payload")" == \
      "$metrics_digest" ]] || return 1
  obi_phase_live_family_is_exclusive "$phase" || return 1
  if obi_metric_boundary_index_is_initialized; then
    journal_mode=initialized
  elif obi_metric_boundary_journal_paths_are_cleanly_absent; then
    journal_mode=legacy
  else
    return 1
  fi
  normalize_owned_obi_metric_phase_scratch_residue "$phase" || return $?
  if normalize_owned_obi_metric_phase_capture "$phase" true; then
    normalization_status=0
  else
    normalization_status=$?
    ((normalization_status == 2)) || return "$normalization_status"
  fi
  if ((normalization_status == 2)); then
    for path in "$phase_dir"/.obi-*; do
      [[ -e "$path" || -L "$path" ]] || continue
      case "${path##*/}" in
        .obi-metrics.??????)
          [[ -z "$metrics_candidate" ]] || return 1
          metrics_candidate="$path"
          metrics_candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
            "$path")" || return 1
          ;;
        .obi-identity.??????)
          [[ -z "$identity_candidate" ]] || return 1
          identity_candidate="$path"
          identity_candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
            "$path")" || return 1
          ;;
        *) return 1 ;;
      esac
    done
  fi
  if [[ -e "$metrics_output" || -L "$metrics_output" ||
    -e "$identity_output" || -L "$identity_output" ]]; then
    [[ -f "$metrics_output" && ! -L "$metrics_output" &&
      -f "$identity_output" && ! -L "$identity_output" ]] || return 1
    obi_process_identity_payload_from_reference "$identity_reference" >/dev/null ||
      return 1
    [[ "$(sha256sum "$metrics_output" | awk '{print $1}')" == \
        "$metrics_digest" &&
      "$(read_bounded_single_line_regular_file \
        "$identity_output" "$OBI_PROCESS_IDENTITY_MAX_BYTES")" == \
        "$identity_payload" ]] || return 1
    identity_digest="$(sha256sum "$identity_output")" || return 1
    identity_digest="${identity_digest%% *}"
    finalize_obi_metric_phase_publication_unlocked \
      "$phase" "$journal_mode" "$identity_digest" \
      "$metrics_candidate" "$metrics_candidate_identity" \
      "$identity_candidate" "$identity_candidate_identity"
    return $?
  fi
  metrics_candidate="$(mktemp "$phase_dir/.obi-metrics.XXXXXX")" || return $?
  identity_candidate="$(mktemp "$phase_dir/.obi-identity.XXXXXX")" || {
    publication_status=$?
    normalize_owned_obi_metric_phase_capture "$phase" || return 1
    return "$publication_status"
  }
  if cp -- "$staged_metrics" "$metrics_candidate" &&
    chmod 0644 -- "$metrics_candidate" &&
    printf '%s\n' "$identity_payload" >"$identity_candidate" &&
    chmod 0644 -- "$identity_candidate"; then
    :
  else
    publication_status=$?
    normalize_owned_obi_metric_phase_capture "$phase" || return 1
    return "$publication_status"
  fi
  metrics_candidate_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "$metrics_candidate")" || return 1
  identity_candidate_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "$identity_candidate")" || return 1
  identity_digest="$(sha256sum "$identity_candidate")" || return 1
  identity_digest="${identity_digest%% *}"
  for attempt in 1 2 3; do
    if ln -T -- "$metrics_candidate" "$metrics_output"; then
      metrics_link_status=1
      break
    else
      metrics_link_status=$?
    fi
    [[ ! -e "$metrics_output" && ! -L "$metrics_output" ]] || break
  done
  if ! obi_owned_publication_matches "$metrics_output" \
    "$metrics_candidate_identity" "$metrics_digest" 2; then
    if normalize_owned_obi_metric_phase_capture "$phase" true; then
      :
    else
      normalization_status=$?
      ((normalization_status == 2)) || return 1
    fi
    return "$metrics_link_status"
  fi
  for attempt in 1 2 3; do
    if ln -T -- "$identity_candidate" "$identity_output"; then
      identity_link_status=1
      break
    else
      identity_link_status=$?
    fi
    [[ ! -e "$identity_output" && ! -L "$identity_output" ]] || break
  done
  if ! obi_owned_publication_matches "$identity_output" \
    "$identity_candidate_identity" "$identity_digest" 2; then
    if normalize_owned_obi_metric_phase_capture "$phase" true; then
      :
    else
      normalization_status=$?
      ((normalization_status == 2)) || return 1
    fi
    return "$identity_link_status"
  fi
  metrics_candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "$metrics_candidate")" || return 1
  identity_candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "$identity_candidate")" || return 1
  finalize_obi_metric_phase_publication_unlocked \
    "$phase" "$journal_mode" "$identity_digest" \
    "$metrics_candidate" "$metrics_candidate_identity" \
    "$identity_candidate" "$identity_candidate_identity"
}

recover_obi_metric_phase_capture_unlocked() {
  local -r phase="$1"
  local -r phase_dir="$RESULT_DIR/phases/$phase"
  local -r metrics_output="$phase_dir/obi-metrics.prom"
  local -r identity_output="$phase_dir/obi-identity.json"
  local metrics_handle=""
  local identity_handle=""
  local metrics_handle_identity=""
  local identity_handle_identity=""
  local identity_payload=""
  local identity_digest=""
  local identity_owner=""
  local identity_mode=""
  local identity_links=""
  local journal_mode=""
  local attachment_state=""
  local normalization_status=0
  local path=""

  [[ "${OBI_METRIC_CAPTURE_STAGE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false &&
    "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  if [[ ! -e "$phase_dir" && ! -L "$phase_dir" ]]; then
    return 2
  fi
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  normalize_owned_obi_metric_phase_scratch_residue "$phase" || return $?
  if normalize_owned_obi_metric_phase_capture "$phase" true; then
    normalization_status=0
  else
    normalization_status=$?
    ((normalization_status == 2)) || return "$normalization_status"
  fi
  if [[ ! -e "$metrics_output" && ! -L "$metrics_output" &&
    ! -e "$identity_output" && ! -L "$identity_output" ]]; then
    return 2
  fi
  [[ -f "$metrics_output" && ! -L "$metrics_output" &&
    -f "$identity_output" && ! -L "$identity_output" ]] || return 1
  if ((normalization_status == 2)); then
    IFS=: read -r identity_owner identity_mode identity_links <<<"$(
      stat -Lc '%u:%a:%h' -- "$identity_output"
    )" || return 1
    [[ "$identity_owner" == "$(id -u)" && "$identity_mode" == 644 &&
      ( "$identity_links" == 1 || "$identity_links" == 2 ) ]] || return 1
    identity_payload="$(read_bounded_single_line_owned_regular_file \
      "$identity_output" "$OBI_PROCESS_IDENTITY_MAX_BYTES" \
      644 "$identity_links")" || return 1
    validate_obi_process_identity_payload "$identity_payload" >/dev/null ||
      return 1
  else
    identity_payload="$(obi_process_identity_payload_from_reference \
      "phases/$phase/obi-identity.json")" || return 1
  fi
  [[ "$(jq -er '.state' <<<"$identity_payload")" == running &&
    "$(jq -er '.metrics_reference' <<<"$identity_payload")" == \
      "phases/$phase/obi-metrics.prom" ]] || return 1
  identity_digest="$(sha256sum "$identity_output")" || return 1
  identity_digest="${identity_digest%% *}"
  [[ "$identity_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  obi_phase_live_family_is_exclusive "$phase" || return 1
  if obi_metric_boundary_index_is_initialized; then
    journal_mode=initialized
  elif obi_metric_boundary_journal_paths_are_cleanly_absent; then
    journal_mode=legacy
  else
    return 1
  fi
  if ((normalization_status == 2)); then
    for path in "$phase_dir"/.obi-*; do
      [[ -e "$path" || -L "$path" ]] || continue
      case "${path##*/}" in
        .obi-metrics.??????)
          [[ -z "$metrics_handle" &&
            "${path##*/}" =~ ^\.obi-metrics\.[A-Za-z0-9]{6}$ ]] || return 1
          metrics_handle="$path"
          metrics_handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
            "$path")" || return 1
          ;;
        .obi-identity.??????)
          [[ -z "$identity_handle" &&
            "${path##*/}" =~ ^\.obi-identity\.[A-Za-z0-9]{6}$ ]] || return 1
          identity_handle="$path"
          identity_handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
            "$path")" || return 1
          ;;
        *) return 1 ;;
      esac
    done
    [[ -n "$metrics_handle" || -n "$identity_handle" ]] || return 1
    finalize_obi_metric_phase_publication_unlocked \
      "$phase" "$journal_mode" "$identity_digest" \
      "$metrics_handle" "$metrics_handle_identity" \
      "$identity_handle" "$identity_handle_identity"
    return $?
  fi
  if [[ "$journal_mode" == initialized ]]; then
    attachment_state="$(obi_phase_capture_attachment_state_unlocked \
      "$phase" phase "$identity_digest")" || return 1
    [[ "$attachment_state" == captured || "$attachment_state" == no_active ]] ||
      return 1
  fi
  normalize_owned_obi_metric_phase_capture "$phase" || return $?
  obi_phase_live_family_is_exclusive "$phase" || return 1
  return 0
}

capture_bounded_obi_metric_phase_unlocked() {
  local -r phase="$1"
  local -r timeout_seconds="${2:-5}"
  local stage=""
  local staged_metrics=""
  local staged_parsed=""
  local staged_unsorted=""
  local observation_before=""
  local observation_after=""
  local metrics_digest=""
  local identity_payload=""
  local recovery_status=0
  local capture_status=0
  local cleanup_status=0

  [[ "${OBI_METRIC_CAPTURE_STAGE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 1
  normalize_obi_metric_capture_stage_residue || return $?
  obi_metric_boundary_publication_is_frozen && return 1
  if with_terminal_java_diagnostics_lock \
    recover_obi_metric_phase_capture_unlocked "$phase"; then
    return 0
  else
    recovery_status=$?
  fi
  ((recovery_status == 2)) || return "$recovery_status"
  if create_obi_metric_capture_stage stage; then
    staged_metrics="$stage/metrics.raw"
    staged_parsed="$stage/metrics.parsed"
    staged_unsorted="$stage/metrics.unsorted"
  else
    capture_status=$?
  fi
  if ((capture_status == 0)); then
    if (umask 077 && : >"$staged_metrics" && : >"$staged_parsed" &&
      : >"$staged_unsorted"); then
      :
    else
      capture_status=$?
      ((capture_status != 0)) || capture_status=1
    fi
  fi
  if ((capture_status == 0)); then
    observation_before="$(current_obi_running_observation_payload)" ||
      capture_status=$?
  fi
  if ((capture_status == 0)); then
    capture_obi_metrics_candidate "$staged_metrics" "$timeout_seconds" ||
      capture_status=$?
  fi
  if ((capture_status == 0)); then
    parse_obi_metric_snapshot \
      "$staged_metrics" "$staged_parsed" "$staged_unsorted" ||
      capture_status=$?
  fi
  if ((capture_status == 0)); then
    observation_after="$(current_obi_running_observation_payload)" ||
      capture_status=$?
  fi
  if ((capture_status == 0)) && [[ "$observation_after" != "$observation_before" ]]; then
    capture_status=1
  fi
  if ((capture_status == 0)); then
    metrics_digest="$(sha256sum "$staged_metrics")" || capture_status=$?
    metrics_digest="${metrics_digest%% *}"
  fi
  if ((capture_status == 0)); then
    identity_payload="$(jq -cS \
      --arg metrics_reference "phases/$phase/obi-metrics.prom" \
      --arg metrics_sha256 "$metrics_digest" '
        .schema = "obi-process-identity-v1" |
        . + {
          metrics_reference: $metrics_reference,
          metrics_sha256: $metrics_sha256
        }
      ' <<<"$observation_before")" || capture_status=$?
  fi
  if ((capture_status == 0)); then
    with_terminal_java_diagnostics_lock \
      capture_bounded_obi_metric_phase_publication_unlocked \
      "$phase" "$staged_metrics" "$identity_payload" || capture_status=$?
  fi
  if [[ -n "$stage" && ( -e "$stage" || -L "$stage" ) ]]; then
    cleanup_obi_metric_capture_stage \
      "$stage" "$stage/metrics.raw" "$stage/metrics.parsed" \
      "$stage/metrics.unsorted" || cleanup_status=$?
  fi
  ((cleanup_status == 0)) || return "$cleanup_status"
  return "$capture_status"
}

capture_bounded_obi_metric_phase() {
  with_obi_metric_capture_stage_lock \
    capture_bounded_obi_metric_phase_unlocked "$@"
}

obi_metrics_unavailable_phase_is_valid() {
  local -r phase="$1"
  local reference=""
  local output=""
  local payload=""

  reference="$(obi_metric_phase_reference "$phase" metrics)" || return 1
  output="$RESULT_DIR/$reference"
  [[ -f "$output" && ! -L "$output" &&
    "$(stat -Lc '%u:%a:%h' -- "$output")" == "$(id -u):644:1" ]] ||
    return 1
  payload="$(read_bounded_single_line_regular_file "$output" 64)" || return 1
  [[ "$payload" == unavailable ]]
}

publish_obi_metrics_unavailable_phase_unlocked() {
  local -r phase="$1"
  local phase_dir=""
  local reference=""
  local output=""
  local candidate=""
  local candidate_identity=""
  local candidate_private_identity=""
  local candidate_digest=""
  local expected_digest=""
  local journal_mode=""
  local normalization_status=0
  local publication_status=1
  local attempt=0

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false ]] || return 1
  ensure_java_diagnostics_phase_directory "$phase" || return 1
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  phase_dir="$RESULT_DIR/phases/$phase"
  reference="$(obi_metric_phase_reference "$phase" metrics)" || return 1
  output="$RESULT_DIR/$reference"
  expected_digest="$(printf 'unavailable\n' | sha256sum)" || return 1
  expected_digest="${expected_digest%% *}"
  obi_phase_unavailable_family_is_exclusive "$phase" || return 1
  if obi_metric_boundary_index_is_initialized; then
    journal_mode=initialized
  elif obi_metric_boundary_journal_paths_are_cleanly_absent; then
    journal_mode=legacy
  else
    return 1
  fi
  if normalize_owned_phase_publication_handle \
    "$output" "$phase_dir/.obi-metrics-unavailable" "$expected_digest" \
    true; then
    normalization_status=0
  else
    normalization_status=$?
    ((normalization_status == 2)) || return "$normalization_status"
  fi
  if ((normalization_status == 2)); then
    for candidate in "$phase_dir"/.obi-metrics-unavailable.*; do
      [[ -e "$candidate" || -L "$candidate" ]] || continue
      [[ "${candidate##*/}" =~ \
        ^\.obi-metrics-unavailable\.[A-Za-z0-9]{6}$ ]] || return 1
      candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
        return 1
    done
    [[ -n "$candidate" && "$candidate_identity" == \
      *":$(id -u):644:2" ]] || return 1
  fi
  if [[ -e "$output" || -L "$output" ]]; then
    if obi_metrics_unavailable_phase_is_valid "$phase"; then
      finalize_obi_unavailable_phase_publication_unlocked \
        "$phase" "$journal_mode" "$expected_digest" \
        "$candidate" "$candidate_identity"
      return $?
    fi
    normalize_owned_phase_publication_handle \
      "$output" "$phase_dir/.obi-metrics-unavailable" "$expected_digest" ||
      return 1
    obi_metrics_unavailable_phase_is_valid "$phase" || return 1
    finalize_obi_unavailable_phase_publication_unlocked \
      "$phase" "$journal_mode" "$expected_digest" "" ""
    return $?
  fi
  candidate="$(mktemp "$phase_dir/.obi-metrics-unavailable.XXXXXX")" || return $?
  candidate_private_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
    return 1
  [[ "$candidate_private_identity" == *":$(id -u):600:1" ]] || return 1
  if ! printf 'unavailable\n' >"$candidate" || ! chmod 0644 -- "$candidate"; then
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_private_identity" || return 1
    return 1
  fi
  candidate_identity="$(stat -Lc '%d:%i:%u:%a' -- "$candidate")" || {
    publication_status=$?
    if [[ -n "$candidate_identity" ]]; then
      remove_terminal_owned_private_path \
        "$candidate" "$candidate_identity:1" || return 1
    fi
    return "$publication_status"
  }
  candidate_digest="$(sha256sum "$candidate")" || {
    publication_status=$?
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_identity:1" || return 1
    return "$publication_status"
  }
  candidate_digest="${candidate_digest%% *}"
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  for attempt in 1 2 3; do
    if ln -T -- "$candidate" "$output"; then
      publication_status=1
      break
    else
      publication_status=$?
    fi
    [[ ! -e "$output" && ! -L "$output" ]] || break
  done
  if ! obi_owned_publication_matches \
    "$output" "$candidate_identity" "$candidate_digest" 2; then
    if [[ -f "$output" && ! -L "$output" && "$candidate" -ef "$output" ]]; then
      remove_terminal_owned_hardlink_handle \
        "$output" "$candidate" "$candidate_identity:2" || return 1
    fi
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_identity:1" || return 1
    return "$publication_status"
  fi
  candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
    return 1
  finalize_obi_unavailable_phase_publication_unlocked \
    "$phase" "$journal_mode" "$candidate_digest" \
    "$candidate" "$candidate_identity"
}

publish_obi_metrics_unavailable_phase() {
  with_terminal_java_diagnostics_lock \
    publish_obi_metrics_unavailable_phase_unlocked "$@"
}

capture_obi_stopped_attestation() {
  local -r phase="$1"
  local -r before_identity_reference="$2"
  local before_payload=""
  local container_id=""
  local started_at=""
  local inspection=""
  local inspected_id=""
  local host_pid=""
  local inspected_started_at=""
  local running=""
  local finished_at=""
  local exit_code=""
  local extra=""
  local payload=""

  assert_compose_service_stopped obi "$phase stopped-metric boundary" || return $?
  before_payload="$(
    obi_process_identity_payload_from_reference "$before_identity_reference"
  )" || return 1
  [[ "$(jq -er '.state' <<<"$before_payload")" == running ]] || return 1
  container_id="$(jq -er '.container_id' <<<"$before_payload")" || return 1
  started_at="$(jq -er '.started_at' <<<"$before_payload")" || return 1
  inspection="$(run_bounded 10 docker inspect --format \
    '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}} {{.State.FinishedAt}} {{.State.ExitCode}}' \
    "$container_id")" || return $?
  read -r inspected_id host_pid inspected_started_at running finished_at exit_code extra \
    <<<"$inspection"
  [[ -z "$extra" && "$inspected_id" == "$container_id" &&
    "$inspected_started_at" == "$started_at" && "$running" == false ]] ||
    return 1
  canonical_uint64_string "$host_pid" >/dev/null || return 1
  canonical_uint64_string "$exit_code" >/dev/null || return 1
  payload="$(jq -cn \
    --arg container_id "$container_id" \
    --arg host_pid "$host_pid" \
    --arg started_at "$started_at" \
    --arg finished_at "$finished_at" \
    --arg exit_code "$exit_code" '
      {
        schema: "obi-process-identity-v1",
        state: "obi_stopped",
        container_id: $container_id,
        host_pid: $host_pid,
        started_at: $started_at,
        finished_at: $finished_at,
        exit_code: $exit_code
      }
    ')" || return 1
  publish_obi_process_identity_payload "$phase" "$payload"
}

obi_metric_label_value_is_allowed() {
  local -r kind="$1"
  local -r value="$2"

  case "$kind:$value" in
    transport:tcp|transport:getsockopt|transport:unix|transport:disabled|\
    operation:stage|operation:candidate|operation:handoff|operation:inject|\
    operation:take|operation:discard|operation:negotiate|\
    operation:availability|operation:cleanup|operation:evict|operation:report|\
    status:unknown|status:valid|status:missing|status:stale|\
    status:unsupported|status:malformed|status:version_mismatch|\
    status:ambiguous|status:unauthorized|status:already_consumed|\
    status:timeout|status:overload|status:transport_error|status:disabled|\
    status:segmented|status:load_denied|status:permission_denied|\
    status:verifier_rejected)
      return 0
      ;;
  esac
  return 1
}

parse_obi_metric_snapshot() {
  local -r input="$1"
  local -r output="$2"
  local -r supplied_unsorted="${3:-}"
  local line=""
  local metric=""
  local raw_value=""
  local extra=""
  local labels=""
  local entry=""
  local label_name=""
  local label_value=""
  local transport=""
  local operation=""
  local status=""
  local error_type=""
  local process_name=""
  local value=""
  local key=""
  local unsorted=""
  local attach_value=0
  local attach_present=false
  local -a label_entries=()
  declare -A seen_series=()
  declare -A seen_labels=()

  [[ $# -le 3 && -f "$input" && ! -L "$input" && ! -L "$output" ]] ||
    return 1
  if [[ -n "$supplied_unsorted" ]]; then
    [[ "${supplied_unsorted%/*}" == "${output%/*}" &&
      -f "$supplied_unsorted" && ! -L "$supplied_unsorted" ]] || return 1
    unsorted="$supplied_unsorted"
    : >"$unsorted" || return $?
  else
    unsorted="$(mktemp "$RESULT_DIR/.obi-metric-snapshot.XXXXXX")" || return $?
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" != *$'\r'* ]] || {
      rm -f -- "$unsorted"
      return 1
    }
    [[ -n "$line" && "$line" != \#* ]] || continue
    metric=""
    raw_value=""
    extra=""
    read -r metric raw_value extra <<<"$line"
    if [[ "$metric" == obi_java_remote_parent_operations_total* ]]; then
      [[ -z "$extra" &&
        "$metric" == 'obi_java_remote_parent_operations_total{'*'}' ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      labels="${metric#*\{}"
      labels="${labels%\}}"
      IFS=',' read -r -a label_entries <<<"$labels"
      (( ${#label_entries[@]} == 3 )) || {
        rm -f -- "$unsorted"
        return 1
      }
      transport=""
      operation=""
      status=""
      seen_labels=()
      for entry in "${label_entries[@]}"; do
        [[ "$entry" =~ ^(operation|status|transport)=\"([a-z_]+)\"$ ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        label_name="${BASH_REMATCH[1]}"
        label_value="${BASH_REMATCH[2]}"
        [[ -z "${seen_labels[$label_name]:-}" ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        seen_labels["$label_name"]=1
        obi_metric_label_value_is_allowed "$label_name" "$label_value" || {
          rm -f -- "$unsorted"
          return 1
        }
        case "$label_name" in
          transport) transport="$label_value" ;;
          operation) operation="$label_value" ;;
          status) status="$label_value" ;;
        esac
      done
      [[ -n "$transport" && -n "$operation" && -n "$status" ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      canonical_uint64_string "$raw_value" value || {
        rm -f -- "$unsorted"
        return 1
      }
      key="$transport|$operation|$status"
      [[ -z "${seen_series[$key]:-}" ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      seen_series["$key"]=1
      if (( ${#seen_series[@]} > OBI_METRIC_PAIR_MAX_SERIES )); then
        rm -f -- "$unsorted"
        return 1
      fi
      printf 'series\t%s\t%s\t%s\t%s\n' \
        "$transport" "$operation" "$status" "$value" >>"$unsorted" || {
        rm -f -- "$unsorted"
        return 1
      }
      continue
    fi
    if [[ "$metric" == obi_instrumentation_errors_total* &&
      "$metric" == *'attaching_java_agent'* ]]; then
      [[ -z "$extra" &&
        "$metric" == 'obi_instrumentation_errors_total{'*'}' ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      labels="${metric#*\{}"
      labels="${labels%\}}"
      IFS=',' read -r -a label_entries <<<"$labels"
      (( ${#label_entries[@]} == 2 )) || {
        rm -f -- "$unsorted"
        return 1
      }
      error_type=""
      process_name=""
      seen_labels=()
      for entry in "${label_entries[@]}"; do
        [[ "$entry" =~ ^(error_type|process_name)=\"([a-z_]+)\"$ ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        label_name="${BASH_REMATCH[1]}"
        label_value="${BASH_REMATCH[2]}"
        [[ -z "${seen_labels[$label_name]:-}" ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        seen_labels["$label_name"]=1
        case "$label_name" in
          error_type) error_type="$label_value" ;;
          process_name) process_name="$label_value" ;;
        esac
      done
      [[ "$error_type" == attaching_java_agent ]] || continue
      [[ "$process_name" == java ]] || continue
      [[ "$attach_present" == false ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      canonical_uint64_string "$raw_value" attach_value || {
        rm -f -- "$unsorted"
        return 1
      }
      attach_present=true
    fi
  done <"$input"
  if LC_ALL=C sort -- "$unsorted" >"$output" &&
    printf 'attach\t%s\t%s\n' "$attach_present" "$attach_value" >>"$output";
  then
    rm -f -- "$unsorted" || return 1
    return 0
  fi
  rm -f -- "$unsorted" "$output" || true
  return 1
}

obi_parsed_metric_snapshot() {
  local -r input="$1"
  local -r output_name="$2"
  local reference=""
  local parsed_output=""
  local parsed_payload=""

  (($# == 2)) || return 1
  [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ &&
    "$input" == "$RESULT_DIR"/phases/*/obi-metrics.prom ]] || return 1
  reference="${input#"$RESULT_DIR/"}"
  [[ "$reference" =~ ^phases/[a-z0-9][a-z0-9-]{0,63}/obi-metrics\.prom$ ]] ||
    return 1
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true &&
    -n "${OBI_METRIC_BOUNDARY_PARSED_METRICS_CACHE[$reference]+present}" ]]; then
    printf -v "$output_name" '%s' \
      "${OBI_METRIC_BOUNDARY_PARSED_METRICS_CACHE[$reference]}"
    return 0
  fi
  parsed_output="$(mktemp "$RESULT_DIR/.obi-metric-parsed.XXXXXX")" || return $?
  if parse_obi_metric_snapshot "$input" "$parsed_output" &&
    parsed_payload="$(<"$parsed_output")" && rm -f -- "$parsed_output"; then
    :
  else
    rm -f -- "$parsed_output" || true
    return 1
  fi
  [[ -n "$parsed_payload" ]] || return 1
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true ]]; then
    OBI_METRIC_BOUNDARY_PARSED_METRICS_CACHE["$reference"]="$parsed_payload"
  fi
  printf -v "$output_name" '%s' "$parsed_payload"
}

validate_obi_metric_pair_payload_structure() {
  local -r payload="$1"
  local boundary=""
  local continuity=""
  local before_state=""
  local after_state=""
  local before_reference=""
  local after_reference=""
  local before_identity=""
  local after_identity=""
  local before_identity_key=""
  local after_identity_key=""
  local transport=""
  local operation=""
  local status=""
  local before=""
  local after=""
  local delta=""
  local expected_delta=""
  local key=""
  local previous_key=""
  local attach_before=""
  local attach_after=""
  local attach_delta=""
  local -i series_count=0
  local -i observed_series=0
  local LC_ALL=C

  jq -e '
    keys == [
      "after", "before", "boundary", "continuity", "java_attach_errors",
      "schema", "series"
    ] and
    .schema == "obi-java-remote-parent-metric-pair-v1" and
    (.boundary | type == "string") and
    (.continuity == "same_process" or .continuity == "process_replaced") and
    (.before | keys == ["identity_reference", "state"]) and
    (.after | keys == ["identity_reference", "state"]) and
    (.before.state == "running") and
    (.after.state == "running" or .after.state == "obi_stopped") and
    ([.before.identity_reference, .after.identity_reference][] |
      type == "string") and
    (.series | type == "array") and
    all(.series[];
      keys == ["after", "before", "delta", "operation", "status", "transport"] and
      ([.transport, .operation, .status, .before][] | type == "string") and
      (.after == null or (.after | type == "string")) and
      (.delta == null or (.delta | type == "string"))) and
    (.java_attach_errors | keys == ["after", "before", "delta"]) and
    (.java_attach_errors.before | type == "string") and
    (.java_attach_errors.after == null or
      (.java_attach_errors.after | type == "string")) and
    (.java_attach_errors.delta == null or
      (.java_attach_errors.delta | type == "string"))
  ' <<<"$payload" >/dev/null || return 1
  boundary="$(jq -er '.boundary' <<<"$payload")" || return 1
  continuity="$(jq -er '.continuity' <<<"$payload")" || return 1
  before_state="$(jq -er '.before.state' <<<"$payload")" || return 1
  after_state="$(jq -er '.after.state' <<<"$payload")" || return 1
  before_reference="$(jq -er '.before.identity_reference' <<<"$payload")" ||
    return 1
  after_reference="$(jq -er '.after.identity_reference' <<<"$payload")" ||
    return 1
  [[ "$boundary" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  [[ "$before_reference" != "$after_reference" ]] || return 1
  obi_process_identity_payload_from_reference \
    "$before_reference" before_identity || return 1
  obi_process_identity_payload_from_reference \
    "$after_reference" after_identity || return 1
  [[ "$(jq -er '.state' <<<"$before_identity")" == "$before_state" &&
    "$(jq -er '.state' <<<"$after_identity")" == "$after_state" ]] || return 1
  before_identity_key="$(jq -r '[.container_id, .started_at] | join(":")' \
    <<<"$before_identity")" || return 1
  after_identity_key="$(jq -r '[.container_id, .started_at] | join(":")' \
    <<<"$after_identity")" || return 1
  if [[ "$after_state" == obi_stopped ]]; then
    [[ "$continuity" == same_process &&
      "$before_identity_key" == "$after_identity_key" ]] || return 1
  elif [[ "$continuity" == same_process ]]; then
    [[ "$before_identity_key" == "$after_identity_key" ]] || return 1
  else
    [[ "$before_identity_key" != "$after_identity_key" ]] || return 1
  fi
  series_count="$(jq -er '.series | length' <<<"$payload")" || return 1
  ((series_count <= OBI_METRIC_PAIR_MAX_SERIES)) || return 1
  while IFS=$'\t' read -r \
    transport operation status before after delta; do
    ((observed_series += 1))
    [[ -n "$transport" && -n "$operation" && -n "$status" ]] || return 1
    obi_metric_label_value_is_allowed transport "$transport" || return 1
    obi_metric_label_value_is_allowed operation "$operation" || return 1
    obi_metric_label_value_is_allowed status "$status" || return 1
    key="$transport|$operation|$status"
    # Canonical allowlisted tuple keys are intentionally compared lexically.
    # shellcheck disable=SC2071
    [[ -z "$previous_key" || "$key" > "$previous_key" ]] || return 1
    previous_key="$key"
    canonical_uint64_string "$before" >/dev/null || return 1
    if [[ "$after_state" == obi_stopped ]]; then
      [[ "$after" == null && "$delta" == null ]] || return 1
    elif [[ "$continuity" == process_replaced ]]; then
      canonical_uint64_string "$after" >/dev/null || return 1
      [[ "$delta" == null ]] || return 1
    else
      canonical_uint64_string "$after" >/dev/null || return 1
      uint64_string_subtract "$after" "$before" expected_delta || return 1
      [[ "$delta" == "$expected_delta" ]] || return 1
    fi
  done < <(jq -r '
    .series[] |
    [.transport, .operation, .status, .before,
      (if .after == null then "null" else .after end),
      (if .delta == null then "null" else .delta end)] | @tsv
  ' <<<"$payload")
  ((observed_series == series_count)) || return 1
  attach_before="$(jq -er '.java_attach_errors.before' <<<"$payload")" || return 1
  attach_after="$(jq -r '
    .java_attach_errors.after |
    if . == null then "null" elif type == "string" then . else error("invalid") end
  ' <<<"$payload")" || return 1
  attach_delta="$(jq -r '
    .java_attach_errors.delta |
    if . == null then "null" elif type == "string" then . else error("invalid") end
  ' <<<"$payload")" || return 1
  canonical_uint64_string "$attach_before" >/dev/null || return 1
  if [[ "$after_state" == obi_stopped ]]; then
    [[ "$attach_after" == null && "$attach_delta" == null ]] || return 1
  elif [[ "$continuity" == process_replaced ]]; then
    canonical_uint64_string "$attach_after" >/dev/null || return 1
    [[ "$attach_delta" == null ]] || return 1
  else
    canonical_uint64_string "$attach_after" >/dev/null || return 1
    uint64_string_subtract \
      "$attach_after" "$attach_before" expected_delta || return 1
    [[ "$attach_delta" == "$expected_delta" ]] || return 1
  fi
  if ((series_count == 0)); then
    [[ "$attach_before" != 0 ||
      ( "$attach_after" != null && "$attach_after" != 0 ) ]] || return 1
  fi
  printf '%s\n' "$payload"
}

validate_obi_metric_pair_payload() {
  local -r payload="$1"
  local boundary=""
  local continuity=""
  local before_reference=""
  local after_reference=""
  local before_phase=""
  local after_phase=""
  local expected_payload=""

  validate_obi_metric_pair_payload_structure "$payload" >/dev/null || return 1
  boundary="$(jq -er '.boundary' <<<"$payload")" || return 1
  continuity="$(jq -er '.continuity' <<<"$payload")" || return 1
  before_reference="$(jq -er '.before.identity_reference' <<<"$payload")" ||
    return 1
  after_reference="$(jq -er '.after.identity_reference' <<<"$payload")" ||
    return 1
  [[ "$before_reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-identity\.json$ ]] ||
    return 1
  before_phase="${BASH_REMATCH[1]}"
  [[ "$after_reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-identity\.json$ ]] ||
    return 1
  after_phase="${BASH_REMATCH[1]}"
  derive_obi_metric_pair_payload \
    "$boundary" "$before_phase" "$after_phase" "$continuity" \
    expected_payload || return 1
  [[ "$payload" == "$expected_payload" ]] || return 1
  printf '%s\n' "$payload"
}

derive_obi_metric_pair_payload() {
  local -r boundary="$1"
  local -r before_phase="$2"
  local -r after_phase="$3"
  local -r continuity="$4"
  local -r output_name="${5:-}"
  local before_identity_reference=""
  local after_identity_reference=""
  local before_identity=""
  local after_identity=""
  local after_state=""
  local before_metrics=""
  local after_metrics=""
  local before_parsed=""
  local after_parsed=""
  local series_tsv=""
  local union_unsorted=""
  local union_sorted=""
  local build_status=0
  local payload=""
  local record_type=""
  local transport=""
  local operation=""
  local status=""
  local value=""
  local key=""
  local before=""
  local after=""
  local delta=""
  local attach_before=0
  local attach_after=0
  local attach_delta=""
  local attach_before_present=false
  local attach_after_present=false
  local -a keys=()
  declare -A before_values=()
  declare -A after_values=()
  declare -A union=()

  (($# == 4 || $# == 5)) || return 1
  [[ -z "$output_name" || "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] ||
    return 1
  [[ "$boundary" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    ( "$continuity" == same_process || "$continuity" == process_replaced ) ]] ||
    return 1
  before_identity_reference="$(
    obi_metric_phase_reference "$before_phase" identity
  )" || return 1
  after_identity_reference="$(
    obi_metric_phase_reference "$after_phase" identity
  )" || return 1
  [[ "$before_identity_reference" != "$after_identity_reference" ]] || return 1
  obi_process_identity_payload_from_reference \
    "$before_identity_reference" before_identity || return 1
  obi_process_identity_payload_from_reference \
    "$after_identity_reference" after_identity || return 1
  [[ "$(jq -er '.state' <<<"$before_identity")" == running ]] || return 1
  after_state="$(jq -er '.state' <<<"$after_identity")" || return 1
  before_metrics="$RESULT_DIR/$(obi_metric_phase_reference "$before_phase" metrics)" ||
    return 1
  after_metrics="$RESULT_DIR/$(obi_metric_phase_reference "$after_phase" metrics)" ||
    return 1
  obi_parsed_metric_snapshot "$before_metrics" before_parsed || return 1
  series_tsv="$(mktemp "$RESULT_DIR/.obi-metric-series.XXXXXX")" || return $?
  while IFS=$'\t' read -r record_type transport operation status value; do
    if [[ "$record_type" == series ]]; then
      key="$transport|$operation|$status"
      before_values["$key"]="$value"
      union["$key"]=1
    elif [[ "$record_type" == attach ]]; then
      attach_before_present="$transport"
      attach_before="$operation"
    else
      rm -f -- "$series_tsv"
      return 1
    fi
  done <<<"$before_parsed"
  if [[ "$after_state" == running ]]; then
    if ! obi_parsed_metric_snapshot "$after_metrics" after_parsed; then
      rm -f -- "$series_tsv"
      return 1
    fi
    while IFS=$'\t' read -r record_type transport operation status value; do
      if [[ "$record_type" == series ]]; then
        key="$transport|$operation|$status"
        after_values["$key"]="$value"
        union["$key"]=1
      elif [[ "$record_type" == attach ]]; then
        attach_after_present="$transport"
        attach_after="$operation"
      else
        rm -f -- "$series_tsv"
        return 1
      fi
    done <<<"$after_parsed"
  else
    [[ "$after_state" == obi_stopped && "$continuity" == same_process &&
      ! -e "$after_metrics" && ! -L "$after_metrics" ]] || {
      rm -f -- "$series_tsv"
      return 1
    }
  fi
  if (( ${#union[@]} > 0 )); then
    union_unsorted="$(mktemp "$RESULT_DIR/.obi-metric-union-unsorted.XXXXXX")" || {
      rm -f -- "$series_tsv"
      return 1
    }
    union_sorted="$(mktemp "$RESULT_DIR/.obi-metric-union-sorted.XXXXXX")" || {
      rm -f -- "$series_tsv" "$union_unsorted"
      return 1
    }
    if printf '%s\n' "${!union[@]}" >"$union_unsorted" &&
      LC_ALL=C sort -- "$union_unsorted" >"$union_sorted" &&
      mapfile -t keys <"$union_sorted"; then
      :
    else
      build_status=$?
      rm -f -- "$series_tsv" "$union_unsorted" "$union_sorted" || true
      return "$build_status"
    fi
    rm -f -- "$union_unsorted" "$union_sorted" || {
      rm -f -- "$series_tsv" || true
      return 1
    }
  fi
  (( ${#keys[@]} <= OBI_METRIC_PAIR_MAX_SERIES )) || {
    rm -f -- "$series_tsv"
    return 1
  }
  for key in "${keys[@]}"; do
    IFS='|' read -r transport operation status <<<"$key"
    before="${before_values[$key]:-0}"
    if [[ "$after_state" == obi_stopped ]]; then
      printf '%s\t%s\t%s\t%s\tnull\tnull\n' \
        "$transport" "$operation" "$status" "$before" >>"$series_tsv" || {
        rm -f -- "$series_tsv" || true
        return 1
      }
      continue
    fi
    after="${after_values[$key]:-0}"
    if [[ "$continuity" == same_process ]]; then
      if [[ -n "${before_values[$key]+present}" &&
        -z "${after_values[$key]+present}" ]]; then
        rm -f -- "$series_tsv"
        return 1
      fi
      uint64_string_subtract "$after" "$before" delta || {
        rm -f -- "$series_tsv"
        return 1
      }
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$transport" "$operation" "$status" "$before" "$after" "$delta" \
        >>"$series_tsv" || {
        rm -f -- "$series_tsv" || true
        return 1
      }
    else
      printf '%s\t%s\t%s\t%s\t%s\tnull\n' \
        "$transport" "$operation" "$status" "$before" "$after" \
        >>"$series_tsv" || {
        rm -f -- "$series_tsv" || true
        return 1
      }
    fi
  done
  if [[ "$after_state" == obi_stopped ]]; then
    attach_after=0
    attach_delta=null
  elif [[ "$continuity" == process_replaced ]]; then
    attach_delta=null
  else
    if [[ "$attach_before_present" == true && "$attach_after_present" != true ]]; then
      rm -f -- "$series_tsv"
      return 1
    fi
    uint64_string_subtract "$attach_after" "$attach_before" attach_delta || {
      rm -f -- "$series_tsv"
      return 1
    }
  fi
  if payload="$(jq -Rcn \
    --arg boundary "$boundary" \
    --arg continuity "$continuity" \
    --arg before_reference "$before_identity_reference" \
    --arg after_reference "$after_identity_reference" \
    --arg after_state "$after_state" \
    --arg attach_before "$attach_before" \
    --arg attach_after "$attach_after" \
    --arg attach_delta "$attach_delta" '
      {
        schema: "obi-java-remote-parent-metric-pair-v1",
        boundary: $boundary,
        continuity: $continuity,
        before: {state: "running", identity_reference: $before_reference},
        after: {state: $after_state, identity_reference: $after_reference},
        series: [inputs | split("\t") |
          {
            transport: .[0],
            operation: .[1],
            status: .[2],
            before: .[3],
            after: (if .[4] == "null" then null else .[4] end),
            delta: (if .[5] == "null" then null else .[5] end)
          }
        ],
        java_attach_errors: {
          before: $attach_before,
          after: (if $after_state == "obi_stopped" then null else $attach_after end),
          delta: (if $attach_delta == "null" then null else $attach_delta end)
        }
      }
    ' <"$series_tsv")"; then
    :
  else
    build_status=$?
    rm -f -- "$series_tsv" || true
    return "$build_status"
  fi
  rm -f -- "$series_tsv" || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$payload"
  else
    printf '%s\n' "$payload"
  fi
}

build_obi_metric_pair_payload() {
  local payload=""
  local build_status=0

  (($# == 4)) || return 1
  if payload="$(derive_obi_metric_pair_payload "$@")"; then
    :
  else
    build_status=$?
    return "$build_status"
  fi
  validate_obi_metric_pair_payload_structure "$payload"
}

ensure_obi_metric_pair_directory() {
  local -r directory="$RESULT_DIR/obi-metric-pairs"
  local result_physical=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || return 1
  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    mkdir -- "$directory" || return $?
  fi
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  result_physical="$(realpath -e -- "$RESULT_DIR")" || return 1
  [[ "$(realpath -e -- "$directory")" == "$result_physical/obi-metric-pairs" ]]
}

remove_obi_owned_pair_publication_handle() {
  local -r handle="$1"
  local -r canonical="$2"
  local shared_identity=""
  local removal_status=0
  local attempt=0

  [[ -f "$handle" && ! -L "$handle" &&
    -f "$canonical" && ! -L "$canonical" && "$handle" -ef "$canonical" ]] ||
    return 1
  shared_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" || return 1
  [[ "$shared_identity" == *":$(id -u):644:2" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" == "$shared_identity" ]] ||
    return 1
  for attempt in 1 2 3; do
    if rm -f -- "$handle"; then
      removal_status=0
      break
    else
      removal_status=$?
    fi
    [[ ! -e "$handle" && ! -L "$handle" ]] && break
    [[ -f "$handle" && ! -L "$handle" && "$handle" -ef "$canonical" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" == "$shared_identity" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" == "$shared_identity" ]] ||
      return 1
  done
  [[ ! -e "$handle" && ! -L "$handle" ]] || return "$removal_status"
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" == \
    "${shared_identity%:2}:1" ]]
}

remove_obi_owned_pair_orphan_publication() {
  local -r handle="$1"
  local -r canonical="$2"
  local shared_identity=""
  local device=""
  local inode=""
  local owner=""
  local removal_status=0
  local attempt=0

  [[ -f "$handle" && ! -L "$handle" &&
    -f "$canonical" && ! -L "$canonical" && "$handle" -ef "$canonical" ]] ||
    return 1
  shared_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" || return 1
  [[ "$shared_identity" == *":$(id -u):644:2" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" == "$shared_identity" ]] ||
    return 1
  for attempt in 1 2 3; do
    if rm -f -- "$canonical"; then
      removal_status=0
      break
    else
      removal_status=$?
    fi
    [[ ! -e "$canonical" && ! -L "$canonical" ]] && break
    [[ -f "$handle" && ! -L "$handle" && "$handle" -ef "$canonical" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" == "$shared_identity" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" == "$shared_identity" ]] ||
      return 1
  done
  [[ ! -e "$canonical" && ! -L "$canonical" ]] || return "$removal_status"
  IFS=: read -r device inode owner _ <<<"${shared_identity%:2}"
  [[ -n "$device" && -n "$inode" && -n "$owner" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" == \
      "$device:$inode:$owner:644:1" ]] || return 1
  remove_obi_owned_private_path_by_inode "$handle" "$device:$inode:$owner"
}

normalize_obi_metric_pair_candidate_residue() {
  local -r expected_canonical="${1:-}"
  local -r directory="$RESULT_DIR/obi-metric-pairs"
  local candidate=""
  local candidate_name=""
  local canonical=""
  local canonical_reference=""
  local journal_payload=""
  local journal_state=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local -a candidates=()
  local -a matching_canonicals=()

  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    return 0
  fi
  ensure_obi_metric_pair_directory || return 1
  for candidate in "$directory"/.pair.*; do
    [[ -e "$candidate" || -L "$candidate" ]] && candidates+=("$candidate")
  done
  ((${#candidates[@]} <= 1)) || return 1
  ((${#candidates[@]} == 1)) || return 0
  candidate="${candidates[0]}"
  candidate_name="${candidate##*/}"
  [[ "$candidate_name" =~ ^\.pair\.[A-Za-z0-9]{6}$ &&
    -f "$candidate" && ! -L "$candidate" ]] || return 1
  IFS=$'\t' read -r device inode owner mode links <<<"$(
    stat -Lc $'%d\t%i\t%u\t%a\t%h' -- "$candidate"
  )" || return 1
  [[ -n "$device" && -n "$inode" && "$owner" == "$(id -u)" &&
    ( "$mode" == 600 || "$mode" == 644 ) ]] || return 1
  if [[ "$links" == 1 ]]; then
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$device:$inode:$owner"
    return $?
  fi
  [[ "$links" == 2 && "$mode" == 644 ]] || return 1
  if [[ -n "$expected_canonical" ]]; then
    [[ "$expected_canonical" == "$directory"/*.json &&
      -f "$expected_canonical" && ! -L "$expected_canonical" &&
      "$candidate" -ef "$expected_canonical" ]] || return 1
    canonical="$expected_canonical"
  else
    for canonical in "$directory"/*.json; do
      if [[ -f "$canonical" && ! -L "$canonical" &&
        "$candidate" -ef "$canonical" ]]; then
        matching_canonicals+=("$canonical")
      fi
    done
    ((${#matching_canonicals[@]} == 1)) || return 1
    canonical="${matching_canonicals[0]}"
  fi
  [[ "${canonical##*/}" =~ ^[a-z0-9][a-z0-9-]{0,63}\.json$ ]] || return 1
  if obi_metric_boundary_index_is_initialized; then
    journal_payload="$(obi_metric_boundary_index_payload)" || return 1
    canonical_reference="${canonical#"$RESULT_DIR/"}"
    journal_state="$(jq -r --arg reference "$canonical_reference" \
      --arg capture_id "${canonical##*/}" '
        ($capture_id | sub("\\.json$"; "")) as $id |
        [.boundaries[].captures[] | select(.kind == "pair") |
          if .state == "captured" and .pair_reference == $reference then
            "captured"
          elif .state == "planned" and .id == $id then "planned"
          else empty end] |
        if length == 1 then .[0] else "unknown" end
      ' <<<"$journal_payload")" || return 1
  else
    journal_state=captured
  fi
  case "$journal_state" in
    captured)
      remove_obi_owned_pair_publication_handle "$candidate" "$canonical"
      ;;
    planned)
      remove_obi_owned_pair_orphan_publication "$candidate" "$canonical"
      ;;
    *) return 1 ;;
  esac
}

validate_obi_metric_pair_directory_closure() {
  local -r index_payload="$1"
  local -r directory="$RESULT_DIR/obi-metric-pairs"
  local expected_manifest=""
  local observed_manifest=""
  local entry=""

  expected_manifest="$(jq -r '
    [.boundaries[].captures[] |
      select(.kind == "pair" and .state == "captured") |
      .pair_reference] | unique | .[]
  ' <<<"$index_payload")" || return 1
  if [[ ! -e "$directory" && ! -L "$directory" ]]; then
    [[ -z "$expected_manifest" ]]
    return $?
  fi
  ensure_obi_metric_pair_directory || return 1
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    [[ -f "$entry" && ! -L "$entry" &&
      "${entry##*/}" =~ ^[a-z0-9][a-z0-9-]{0,63}\.json$ ]] || return 1
  done
  observed_manifest="$(find "$directory" -mindepth 1 -maxdepth 1 \
    -type f -printf 'obi-metric-pairs/%f\n' | LC_ALL=C sort -u)" || return 1
  expected_manifest="$(LC_ALL=C sort -u <<<"$expected_manifest")" || return 1
  [[ "$observed_manifest" == "$expected_manifest" ]]
}

obi_metric_pair_payload_from_reference() {
  local -r reference="$1"
  local -r output_name="${2:-}"
  local input=""
  local payload=""
  local boundary=""

  (($# == 1 || $# == 2)) || return 1
  [[ -z "$output_name" || "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] ||
    return 1
  [[ "$reference" =~ ^obi-metric-pairs/([a-z0-9][a-z0-9-]{0,63})\.json$ ]] ||
    return 1
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true ]]; then
    if [[ -n "${OBI_METRIC_BOUNDARY_PAIR_PAYLOAD_CACHE[$reference]+present}" ]]; then
      if [[ -n "$output_name" ]]; then
        printf -v "$output_name" '%s' \
          "${OBI_METRIC_BOUNDARY_PAIR_PAYLOAD_CACHE[$reference]}"
      else
        printf '%s\n' "${OBI_METRIC_BOUNDARY_PAIR_PAYLOAD_CACHE[$reference]}"
      fi
      return 0
    fi
  fi
  boundary="${BASH_REMATCH[1]}"
  ensure_obi_metric_pair_directory || return 1
  input="$RESULT_DIR/$reference"
  payload="$(read_bounded_single_line_regular_file \
    "$input" "$OBI_METRIC_PAIR_MAX_BYTES")" || return 1
  [[ "$(jq -er '.boundary' <<<"$payload")" == "$boundary" ]] ||
    return 1
  validate_obi_metric_pair_payload "$payload" >/dev/null || return 1
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true ]]; then
    OBI_METRIC_BOUNDARY_PAIR_PAYLOAD_CACHE["$reference"]="$payload"
  fi
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$payload"
  else
    printf '%s\n' "$payload"
  fi
}

obi_metric_pair_evidence_json_from_reference() {
  local -r reference="$1"
  local payload=""

  payload="$(obi_metric_pair_payload_from_reference "$reference")" || return 1
  jq -c --arg reference "$reference" '
    {reference: $reference, pair: .}
  ' <<<"$payload"
}

java_diagnostics_payload_for_terminal_boundary_phase() {
  local -r phase="$1"
  local reference=""
  local input=""
  local evidence=""
  local payload=""

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  reference="phases/$phase/java-diagnostics.txt"
  input="$RESULT_DIR/$reference"
  if [[ ! -e "$input" && ! -L "$input" ]]; then
    printf 'null\n'
    return 0
  fi
  [[ -f "$input" && ! -L "$input" ]] || return 1
  evidence="$(java_diagnostics_reference_evidence_json "$reference")" || return 1
  payload="$(jq -cn \
    --arg phase "$phase" \
    --argjson evidence "$evidence" '
      $evidence + {
        schema: "obi-java-bridge-terminal-diagnostics-v1",
        sealed: false,
        available: true,
        phase: $phase
      }
    ')" || return 1
  validate_last_java_diagnostics_payload "$payload"
}

obi_owned_publication_matches() {
  local -r path="$1"
  local -r expected_identity="$2"
  local -r expected_digest="$3"
  local -r expected_links="$4"
  local observed_digest=""

  [[ -f "$path" && ! -L "$path" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$path")" == "$expected_identity" &&
    "$(stat -Lc '%h' -- "$path")" == "$expected_links" ]] || return 1
  observed_digest="$(sha256sum "$path")" || return 1
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$expected_digest" ]]
}

remove_obi_owned_private_file() {
  local -r path="$1"
  local -r expected_identity="$2"
  local -r expected_digest="$3"
  local removal_status=0
  local attempt=0

  for attempt in 1 2 3; do
    if [[ ! -e "$path" && ! -L "$path" ]]; then
      return 0
    fi
    obi_owned_publication_matches \
      "$path" "$expected_identity" "$expected_digest" 1 || return 1
    if rm -f -- "$path"; then
      [[ ! -e "$path" && ! -L "$path" ]] && return 0
      removal_status=1
    else
      removal_status=$?
      [[ ! -e "$path" && ! -L "$path" ]] && return 0
    fi
  done
  return "$removal_status"
}

remove_obi_owned_private_path_by_inode() {
  local -r path="$1"
  local -r expected_inode="$2"
  local removal_status=0
  local attempt=0

  for attempt in 1 2 3; do
    [[ -e "$path" || -L "$path" ]] || return 0
    [[ -f "$path" && ! -L "$path" &&
      "$(stat -Lc '%d:%i:%u:%h' -- "$path")" == "$expected_inode:1" ]] ||
      return 1
    if rm -f -- "$path"; then
      [[ ! -e "$path" && ! -L "$path" ]] && return 0
      removal_status=1
    else
      removal_status=$?
      [[ ! -e "$path" && ! -L "$path" ]] && return 0
    fi
  done
  return "$removal_status"
}

normalize_obi_owned_private_candidate_residue() {
  local -r prefix="$1"
  local -r basename_pattern="$2"
  local -r allowed_mode_pattern="$3"
  local -r excluded_canonical="${4:-}"
  local path=""
  local basename=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local -a candidates=()

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${prefix%/*}" == "$RESULT_DIR" &&
    ( -z "$excluded_canonical" ||
      "$excluded_canonical" == "$prefix.freeze" ) ]] || return 1
  for path in "$prefix".*; do
    [[ -n "$excluded_canonical" && "$path" == "$excluded_canonical" ]] &&
      continue
    [[ -e "$path" || -L "$path" ]] && candidates+=("$path")
  done
  ((${#candidates[@]} <= 1)) || return 1
  ((${#candidates[@]} == 1)) || return 0
  path="${candidates[0]}"
  basename="${path##*/}"
  [[ "$basename" =~ $basename_pattern && -f "$path" && ! -L "$path" ]] ||
    return 1
  IFS=$'\t' read -r device inode owner mode links <<<"$(
    stat -Lc $'%d\t%i\t%u\t%a\t%h' -- "$path"
  )" || return 1
  [[ -n "$device" && -n "$inode" && "$owner" == "$(id -u)" &&
    "$mode" =~ $allowed_mode_pattern && "$links" == 1 ]] || return 1
  remove_obi_owned_private_path_by_inode \
    "$path" "$device:$inode:$owner"
}

remove_terminal_owned_hardlink_handle() {
  local -r handle="$1"
  local -r canonical="$2"
  local -r expected_identity="$3"
  local removal_status=1
  local attempt=0
  local expected_device=""
  local expected_inode=""
  local expected_owner=""
  local expected_mode=""
  local expected_links=""

  IFS=: read -r expected_device expected_inode expected_owner \
    expected_mode expected_links <<<"$expected_identity"
  [[ -n "$expected_device" && -n "$expected_inode" &&
    "$expected_owner" == "$(id -u)" &&
    ( "$expected_mode" == 600 || "$expected_mode" == 644 ) &&
    "$expected_links" == 2 ]] || return 1
  for attempt in 1 2 3; do
    [[ -f "$handle" && ! -L "$handle" &&
      -f "$canonical" && ! -L "$canonical" &&
      "$handle" -ef "$canonical" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" == \
        "$expected_identity" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" == \
        "$expected_identity" ]] || return 1
    if rm -f -- "$handle"; then
      removal_status=0
    else
      removal_status=$?
    fi
    if [[ ! -e "$handle" && ! -L "$handle" ]]; then
      [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" == \
        "${expected_identity%:2}:1" ]] || return 1
      return 0
    fi
  done
  return "$removal_status"
}

remove_terminal_owned_private_path() {
  local -r path="$1"
  local -r expected_identity="$2"
  local removal_status=1
  local attempt=0
  local expected_device=""
  local expected_inode=""
  local expected_owner=""
  local expected_mode=""
  local expected_links=""

  IFS=: read -r expected_device expected_inode expected_owner \
    expected_mode expected_links <<<"$expected_identity"
  [[ -n "$expected_device" && -n "$expected_inode" &&
    "$expected_owner" == "$(id -u)" &&
    ( "$expected_mode" == 600 || "$expected_mode" == 644 ) &&
    "$expected_links" == 1 ]] || return 1
  for attempt in 1 2 3; do
    [[ -f "$path" && ! -L "$path" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$path")" == \
        "$expected_identity" ]] || return 1
    if rm -f -- "$path"; then
      removal_status=0
    else
      removal_status=$?
    fi
    [[ ! -e "$path" && ! -L "$path" ]] && return 0
  done
  return "$removal_status"
}

remove_terminal_owned_private_candidate() {
  local -r path="$1"
  local -r expected_inode="$2"
  local -r allowed_mode_pattern="$3"
  local identity=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""

  identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$path")" || return 1
  IFS=: read -r device inode owner mode links <<<"$identity"
  [[ "$device:$inode:$owner" == "$expected_inode" &&
    "$owner" == "$(id -u)" && "$mode" =~ $allowed_mode_pattern &&
    "$links" == 1 ]] || return 1
  remove_terminal_owned_private_path "$path" "$identity"
}

normalize_terminal_owned_hardlink_family() {
  local -r canonical="$1"
  local -r canonical_mode="$2"
  local -r maximum_bytes="$3"
  local -r allow_h1_cleanup="$4"
  local -r expected_payload="$5"
  local -r payload_validator="$6"
  local -r candidate_basename_pattern="$7"
  shift 7
  local canonical_directory="${canonical%/*}"
  local result_physical=""
  local canonical_directory_physical=""
  local canonical_identity=""
  local canonical_device=""
  local canonical_inode=""
  local canonical_owner=""
  local canonical_observed_mode=""
  local canonical_links=""
  local canonical_payload=""
  local candidate=""
  local candidate_basename=""
  local candidate_identity=""
  local candidate_device=""
  local candidate_inode=""
  local candidate_owner=""
  local candidate_mode=""
  local candidate_links=""
  local candidate_prefix=""
  local path=""
  local -a candidates=()

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    -d "$canonical_directory" && ! -L "$canonical_directory" &&
    "$canonical_mode" =~ ^(600|644)$ &&
    "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    ( "$allow_h1_cleanup" == true || "$allow_h1_cleanup" == false ) &&
    "$payload_validator" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ &&
    $# -ge 1 ]] || return 1
  if [[ "$allow_h1_cleanup" == true ]]; then
    [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true ||
      "${TERMINAL_TRANSITION_PUBLICATION_LOCK_HELD_BY_CALLER:-false}" == \
        true ]] || return 1
  fi
  result_physical="$(realpath -e -- "$RESULT_DIR")" || return 1
  canonical_directory_physical="$(
    realpath -e -- "$canonical_directory"
  )" || return 1
  [[ "$canonical_directory_physical" == "$result_physical" ||
    "$canonical_directory_physical" == "$result_physical"/* ]] || return 1
  for candidate_prefix in "$@"; do
    [[ "${candidate_prefix%/*}" == "${canonical%/*}" ]] || return 1
    for path in "$candidate_prefix".*; do
      if [[ ( -e "$path" || -L "$path" ) && "$path" != "$canonical" ]]; then
        candidates+=("$path")
        ((${#candidates[@]} <= 1)) || return 1
      fi
    done
  done
  ((${#candidates[@]} <= 1)) || return 1
  if ((${#candidates[@]} == 1)); then
    candidate="${candidates[0]}"
    candidate_basename="${candidate##*/}"
    [[ "$candidate_basename" =~ $candidate_basename_pattern &&
      -f "$candidate" && ! -L "$candidate" ]] || return 1
    candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
      return 1
    IFS=: read -r \
      candidate_device candidate_inode candidate_owner candidate_mode \
      candidate_links <<<"$candidate_identity"
    [[ -n "$candidate_device" && -n "$candidate_inode" &&
      "$candidate_owner" == "$(id -u)" &&
      "$candidate_links" =~ ^[12]$ ]] || return 1
    if [[ "$candidate_links" == 1 ]]; then
      if [[ "$canonical_mode" == 644 ]]; then
        [[ "$candidate_mode" == 600 || "$candidate_mode" == 644 ]] ||
          return 1
      else
        [[ "$candidate_mode" == 600 ]] || return 1
      fi
    else
      [[ "$candidate_mode" == "$canonical_mode" ]] || return 1
    fi
  fi
  if [[ ! -e "$canonical" && ! -L "$canonical" ]]; then
    if [[ -z "$candidate" ]]; then
      return 0
    fi
    [[ "$allow_h1_cleanup" == true && "$candidate_links" == 1 ]] ||
      return 1
    remove_terminal_owned_private_path "$candidate" "$candidate_identity"
    return $?
  fi
  [[ -f "$canonical" && ! -L "$canonical" ]] || return 1
  canonical_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$canonical")" ||
    return 1
  IFS=: read -r \
    canonical_device canonical_inode canonical_owner canonical_observed_mode \
    canonical_links <<<"$canonical_identity"
  [[ -n "$canonical_device" && -n "$canonical_inode" &&
    "$canonical_owner" == "$(id -u)" &&
    "$canonical_observed_mode" == "$canonical_mode" ]] || return 1
  case "$canonical_links" in
    1|2) ;;
    *) return 1 ;;
  esac
  canonical_payload="$(read_bounded_single_line_owned_regular_file \
    "$canonical" "$maximum_bytes" "$canonical_mode" \
    "$canonical_links")" || return 1
  "$payload_validator" \
    "$canonical_payload" "$candidate_basename" __any__ \
    "$candidate_links" || return 1
  if [[ -z "$candidate" ]]; then
    [[ "$canonical_links" == 1 ]] || return 1
    "$payload_validator" "$canonical_payload" "" "$expected_payload" ""
    return $?
  fi
  if [[ "$candidate_links" == 2 ]]; then
    [[ "$canonical_links" == 2 &&
      "$candidate" -ef "$canonical" &&
      "$candidate_identity" == "$canonical_identity" ]] || return 1
    remove_terminal_owned_hardlink_handle \
      "$candidate" "$canonical" "$canonical_identity" || return $?
  else
    [[ "$canonical_links" == 1 &&
      "$allow_h1_cleanup" == true && ! "$candidate" -ef "$canonical" ]] ||
      return 1
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_identity" || return $?
  fi
  canonical_payload="$(read_bounded_single_line_owned_regular_file \
    "$canonical" "$maximum_bytes" "$canonical_mode" 1)" || return 1
  "$payload_validator" "$canonical_payload" "" "$expected_payload" ""
}

publish_terminal_owned_hardlink_payload() {
  local -r canonical="$1"
  local -r candidate_prefix="$2"
  local -r own_basename_pattern="$3"
  local -r family_basename_pattern="$4"
  local -r canonical_mode="$5"
  local -r maximum_bytes="$6"
  local -r payload="$7"
  local -r payload_validator="$8"
  local -r allow_h1_cleanup="$9"
  shift 9
  local candidate=""
  local candidate_basename=""
  local candidate_cleanup_mode_pattern='^600$'
  local candidate_inode=""
  local candidate_device=""
  local candidate_inode_number=""
  local candidate_owner=""
  local candidate_payload=""
  local publication_status=1
  local normalization_status=1
  local cleanup_status=0
  local attempt=0

  if [[ "$canonical_mode" == 644 ]]; then
    candidate_cleanup_mode_pattern='^(600|644)$'
  fi

  normalize_terminal_owned_hardlink_family \
    "$canonical" "$canonical_mode" "$maximum_bytes" "$allow_h1_cleanup" \
    "$payload" "$payload_validator" "$family_basename_pattern" "$@" ||
    return $?
  if [[ -e "$canonical" || -L "$canonical" ]]; then
    return 0
  fi
  if candidate="$(mktemp "$candidate_prefix.XXXXXX")"; then
    :
  else
    publication_status=$?
    normalize_terminal_owned_hardlink_family \
      "$canonical" "$canonical_mode" "$maximum_bytes" "$allow_h1_cleanup" \
      "$payload" "$payload_validator" "$family_basename_pattern" "$@" ||
      return 1
    return "$publication_status"
  fi
  candidate_basename="${candidate##*/}"
  [[ "${candidate%/*}" == "${canonical%/*}" &&
    "$candidate_basename" =~ $own_basename_pattern &&
    -f "$candidate" && ! -L "$candidate" ]] || return 1
  for attempt in 1 2 3; do
    candidate_inode="$(stat -Lc '%d:%i:%u' -- "$candidate")" && break
    candidate_inode=""
  done
  IFS=: read -r candidate_device candidate_inode_number candidate_owner \
    <<<"$candidate_inode"
  [[ -n "$candidate_device" && -n "$candidate_inode_number" &&
    "$candidate_owner" == "$(id -u)" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" == \
      "$candidate_inode:600:1" ]] || return 1
  if printf '%s\n' "$payload" >"$candidate" &&
    chmod "0$canonical_mode" -- "$candidate"; then
    :
  else
    publication_status=$?
    remove_terminal_owned_private_candidate \
      "$candidate" "$candidate_inode" "$candidate_cleanup_mode_pattern" ||
      return 1
    return "$publication_status"
  fi
  candidate_payload="$(read_bounded_single_line_owned_regular_file \
    "$candidate" "$maximum_bytes" "$canonical_mode" 1)" || {
      remove_terminal_owned_private_candidate \
        "$candidate" "$candidate_inode" "^$canonical_mode$" || return 1
      return 1
    }
  "$payload_validator" \
    "$candidate_payload" "$candidate_basename" "$payload" 1 || {
    remove_terminal_owned_private_candidate \
      "$candidate" "$candidate_inode" "^$canonical_mode$" || return 1
    return 1
  }
  for attempt in 1 2 3; do
    if ln -T -- "$candidate" "$canonical"; then
      publication_status=1
      break
    else
      publication_status=$?
    fi
    [[ ! -e "$canonical" && ! -L "$canonical" ]] || break
    [[ -f "$candidate" && ! -L "$candidate" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" == \
        "$candidate_inode:$canonical_mode:1" ]] || return 1
  done
  if normalize_terminal_owned_hardlink_family \
    "$canonical" "$canonical_mode" "$maximum_bytes" "$allow_h1_cleanup" \
    "$payload" "$payload_validator" "$family_basename_pattern" "$@"; then
    normalization_status=0
    [[ -e "$canonical" && ! -L "$canonical" ]] && return 0
  else
    normalization_status=$?
  fi
  if [[ -f "$candidate" && ! -L "$candidate" &&
    "$(stat -Lc '%d:%i:%u:%h' -- "$candidate")" == "$candidate_inode:1" ]]; then
    if remove_terminal_owned_private_candidate \
      "$candidate" "$candidate_inode" "$candidate_cleanup_mode_pattern"; then
      :
    else
      cleanup_status=$?
      return "$cleanup_status"
    fi
  fi
  if ((normalization_status != 0)); then
    return "$normalization_status"
  fi
  return "$publication_status"
}

obi_metric_boundary_publication_is_frozen() {
  local -r index_freeze="$RESULT_DIR/.obi-metric-boundary-index.freeze"
  local -r java_transition="$RESULT_DIR/.terminal-java-diagnostics.freeze"
  local -r java_terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local -r metric_terminal="$RESULT_DIR/terminal-obi-metrics.json"

  [[ -e "$index_freeze" || -L "$index_freeze" ||
    -e "$java_transition" || -L "$java_transition" ||
    -e "$java_terminal" || -L "$java_terminal" ||
    -e "$metric_terminal" || -L "$metric_terminal" ]]
}

obi_metric_boundary_index_path() {
  printf '%s/obi-metric-boundary-index.json\n' "$RESULT_DIR"
}

obi_metric_boundary_index_is_initialized() {
  local index=""

  [[ -n "${RESULT_DIR:-}" ]] || return 1
  index="$(obi_metric_boundary_index_path)" || return 1
  [[ -f "$index" && ! -L "$index" ]]
}

obi_metric_boundary_journal_paths_are_cleanly_absent() {
  local -r index="$RESULT_DIR/obi-metric-boundary-index.json"
  local -r freeze="$RESULT_DIR/.obi-metric-boundary-index.freeze"
  local path=""

  [[ ! -e "$index" && ! -L "$index" &&
    ! -e "$freeze" && ! -L "$freeze" ]] || return 1
  for path in \
    "$RESULT_DIR"/.obi-metric-boundary-plan.* \
    "$RESULT_DIR"/.obi-metric-boundary-index.* \
    "$RESULT_DIR"/.obi-metric-boundary-index-backup.* \
    "$RESULT_DIR"/.obi-metric-boundary-index-restore.* \
    "$RESULT_DIR"/.obi-metric-boundary-index-freeze.*; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
}

read_bounded_single_line_regular_file_without_hashing() {
  local -r input="$1"
  local -r maximum_bytes="$2"
  local descriptor=""
  local descriptor_path=""
  local path_identity=""
  local descriptor_identity=""
  local links=""
  local size=""
  local -a lines=()
  local LC_ALL=C

  [[ "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    -f "$input" && ! -L "$input" ]] || return 1
  path_identity="$(stat -Lc '%d:%i' -- "$input")" || return 1
  exec {descriptor}<"$input" || return $?
  descriptor_path="/proc/self/fd/$descriptor"
  if [[ ! -f "$descriptor_path" ]] ||
    ! descriptor_identity="$(stat -Lc '%d:%i' -- "$descriptor_path")" ||
    [[ "$descriptor_identity" != "$path_identity" ]] ||
    [[ -L "$input" ]] ||
    [[ "$(stat -Lc '%d:%i' -- "$input")" != "$path_identity" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  links="$(stat -Lc '%h' -- "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  size="$(stat -Lc '%s' -- "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  if [[ "$links" != 1 ]] || ((size == 0 || size > maximum_bytes)); then
    exec {descriptor}<&-
    return 1
  fi
  mapfile -t lines <"$descriptor_path" || {
    exec {descriptor}<&-
    return 1
  }
  if [[ -L "$input" ||
    "$(stat -Lc '%d:%i:%s:%h' -- "$input")" != \
      "$path_identity:$size:1" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  exec {descriptor}<&-
  (( ${#lines[@]} == 1 )) || return 1
  if ((size != ${#lines[0]} && size != ${#lines[0]} + 1)); then
    return 1
  fi
  printf '%s\n' "${lines[0]}"
}

add_obi_metric_boundary_budget_reference() {
  local -r reference="$1"
  local -r reference_kind="$2"
  local -n seen_map_ref="$3"
  local -n bytes_total_ref="$4"
  local maximum_bytes=""
  local path=""
  local descriptor=""
  local descriptor_path=""
  local path_identity=""
  local descriptor_identity=""
  local links=""
  local size=""

  case "$reference_kind" in
    identity)
      [[ "$reference" =~ ^phases/[a-z0-9][a-z0-9-]{0,63}/obi-identity\.json$ ]] ||
        return 1
      maximum_bytes="$OBI_PROCESS_IDENTITY_MAX_BYTES"
      ;;
    metrics)
      [[ "$reference" =~ ^phases/[a-z0-9][a-z0-9-]{0,63}/obi-metrics\.prom$ ]] ||
        return 1
      maximum_bytes="$OBI_METRIC_SNAPSHOT_MAX_BYTES"
      ;;
    java)
      [[ "$reference" =~ ^phases/[a-z0-9][a-z0-9-]{0,63}/java-diagnostics\.txt$ ]] ||
        return 1
      maximum_bytes="$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES"
      ;;
    pair)
      [[ "$reference" =~ ^obi-metric-pairs/[a-z0-9][a-z0-9-]{0,63}\.json$ ]] ||
        return 1
      maximum_bytes="$OBI_METRIC_PAIR_MAX_BYTES"
      ;;
    status)
      [[ "$reference" =~ ^scenario-[a-z0-9][a-z0-9-]{0,95}-status\.json$ ]] ||
        return 1
      maximum_bytes="$OBI_METRIC_BOUNDARY_STATUS_MAX_BYTES"
      ;;
    artifact)
      [[ "$reference" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || return 1
      maximum_bytes="$OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES"
      ;;
    *) return 1 ;;
  esac
  if [[ -n "${seen_map_ref[$reference]+present}" ]]; then
    [[ "${seen_map_ref[$reference]}" == "$reference_kind" ]] || return 1
    return 0
  fi
  path="$RESULT_DIR/$reference"
  [[ -f "$path" && ! -L "$path" ]] || return 1
  path_identity="$(stat -Lc '%d:%i' -- "$path")" || return 1
  exec {descriptor}<"$path" || return $?
  descriptor_path="/proc/self/fd/$descriptor"
  if [[ ! -f "$descriptor_path" ]] ||
    ! descriptor_identity="$(stat -Lc '%d:%i' -- "$descriptor_path")" ||
    [[ "$descriptor_identity" != "$path_identity" ]] ||
    [[ -L "$path" ]] ||
    [[ "$(stat -Lc '%d:%i' -- "$path")" != "$path_identity" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  links="$(stat -Lc '%h' -- "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  size="$(stat -Lc '%s' -- "$descriptor_path")" || {
    exec {descriptor}<&-
    return 1
  }
  if [[ "$reference_kind" == artifact ]]; then
    size="$(bounded_decimal "$size" "$maximum_bytes" true)" || {
      exec {descriptor}<&-
      return 1
    }
  else
    size="$(bounded_decimal "$size" "$maximum_bytes" false)" || {
      exec {descriptor}<&-
      return 1
    }
  fi
  if [[ "$links" != 1 || -L "$path" ||
    "$(stat -Lc '%d:%i:%s:%h' -- "$path")" != \
      "$path_identity:$size:1" ]]; then
    exec {descriptor}<&-
    return 1
  fi
  exec {descriptor}<&-
  if ((size > OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES - bytes_total_ref)); then
    log_error "retained boundary evidence exceeds the 536870912-byte safety ceiling; unrelated Prometheus cardinality may trigger this limit"
    return 1
  fi
  bytes_total_ref=$((bytes_total_ref + size))
  seen_map_ref["$reference"]="$reference_kind"
}

validate_obi_metric_boundary_referenced_byte_budget() {
  local -r payload="$1"
  local boundary_id=""
  local capture_id=""
  local kind=""
  local capture_state=""
  local reference=""
  local java_reference=""
  local pair_payload=""
  local pair_identity_manifest=""
  local identity_payload=""
  local identity_state=""
  local metrics_reference=""
  local capture_budget_manifest=""
  local status_budget_manifest=""
  local expected_budget_capture_count=""
  local expected_budget_status_count=""
  local -i budget_capture_count=0
  local -i budget_status_count=0
  local -i pair_identity_count=0
  # Updated by add_obi_metric_boundary_budget_reference through its nameref.
  # shellcheck disable=SC2034
  local -i referenced_bytes=0
  # Updated by add_obi_metric_boundary_budget_reference through its nameref.
  # shellcheck disable=SC2034
  local -A seen_references=()
  local -a pair_references=()
  local -a identity_references=()

  capture_budget_manifest="$(jq -r '
    .boundaries[] as $boundary |
    $boundary.captures[] |
    [
      $boundary.id, .id, .kind, .state,
      (if .kind == "phase" then .identity_reference
       elif .kind == "pair" then (.pair_reference // "__null__")
       else .reference end),
      (.java_reference // "__null__")
    ] | @tsv
  ' <<<"$payload")" || return 1
  expected_budget_capture_count="$(jq -er \
    '[.boundaries[].captures[]] | length' <<<"$payload")" || return 1
  while IFS=$'\t' read -r \
    boundary_id capture_id kind capture_state reference java_reference; do
    [[ -n "$boundary_id" ]] || continue
    ((budget_capture_count += 1))
    case "$kind:$capture_state" in
      phase:captured)
        add_obi_metric_boundary_budget_reference \
          "$reference" identity seen_references referenced_bytes || return 1
        identity_references+=("$reference")
        ;;
      java:captured)
        add_obi_metric_boundary_budget_reference \
          "$reference" java seen_references referenced_bytes || return 1
        ;;
      artifact:captured)
        add_obi_metric_boundary_budget_reference \
          "$reference" artifact seen_references referenced_bytes || return 1
        ;;
      unavailable:captured)
        add_obi_metric_boundary_budget_reference \
          "$reference" metrics seen_references referenced_bytes || return 1
        ;;
      pair:captured)
        add_obi_metric_boundary_budget_reference \
          "$reference" pair seen_references referenced_bytes || return 1
        pair_references+=("$reference")
        if [[ "$java_reference" != __null__ ]]; then
          add_obi_metric_boundary_budget_reference \
            "$java_reference" java seen_references referenced_bytes || return 1
        fi
        ;;
      pair:planned) ;;
      *) return 1 ;;
    esac
  done <<<"$capture_budget_manifest"
  ((budget_capture_count == expected_budget_capture_count)) || return 1
  status_budget_manifest="$(jq -r '
    .boundaries[] as $boundary |
    $boundary.status_references[] |
    [$boundary.id, .reference] | @tsv
  ' <<<"$payload")" || return 1
  expected_budget_status_count="$(jq -er \
    '[.boundaries[].status_references[]] | length' <<<"$payload")" || return 1
  while IFS=$'\t' read -r boundary_id reference; do
    [[ -n "$boundary_id" ]] || continue
    ((budget_status_count += 1))
    add_obi_metric_boundary_budget_reference \
      "$reference" status seen_references referenced_bytes || return 1
  done <<<"$status_budget_manifest"
  ((budget_status_count == expected_budget_status_count)) || return 1

  for reference in "${pair_references[@]}"; do
    pair_payload="$(read_bounded_single_line_regular_file_without_hashing \
      "$RESULT_DIR/$reference" "$OBI_METRIC_PAIR_MAX_BYTES")" || return 1
    pair_identity_manifest="$(jq -er '
      if (.before.identity_reference | type) == "string" and
        (.after.identity_reference | type) == "string"
      then .before.identity_reference, .after.identity_reference
      else error("invalid pair identity references") end
    ' <<<"$pair_payload")" || return 1
    pair_identity_count=0
    while IFS= read -r metrics_reference; do
      [[ -n "$metrics_reference" ]] || return 1
      ((pair_identity_count += 1))
      add_obi_metric_boundary_budget_reference \
        "$metrics_reference" identity seen_references referenced_bytes || return 1
      identity_references+=("$metrics_reference")
    done <<<"$pair_identity_manifest"
    ((pair_identity_count == 2)) || return 1
  done
  for reference in "${identity_references[@]}"; do
    identity_payload="$(read_bounded_single_line_regular_file_without_hashing \
      "$RESULT_DIR/$reference" "$OBI_PROCESS_IDENTITY_MAX_BYTES")" || return 1
    identity_state="$(jq -er '.state' <<<"$identity_payload")" || return 1
    case "$identity_state" in
      running)
        metrics_reference="$(jq -er '.metrics_reference' \
          <<<"$identity_payload")" || return 1
        add_obi_metric_boundary_budget_reference \
          "$metrics_reference" metrics seen_references referenced_bytes || return 1
        ;;
      obi_stopped) ;;
      *) return 1 ;;
    esac
  done
}

validate_obi_metric_boundary_index_payload() {
  local -r payload="$1"
  local -r validation_scope="${2:-full}"
  local canonical=""
  local kind=""
  local boundary_id=""
  local capture_id=""
  local reference=""
  local expected_digest=""
  local observed_digest=""
  local capture_state=""
  local java_reference=""
  local java_digest=""
  local unavailable_phase=""
  local capture_phase=""
  # Populated by the semantic loader helpers through their output-variable name.
  # shellcheck disable=SC2034
  local semantic_payload=""
  local capture_manifest=""
  local status_manifest=""
  local expected_capture_count=""
  local expected_status_count=""
  local -i capture_count=0
  local -i status_count=0
  local OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE=true
  local -A observed_reference_digests=()
  local -A OBI_METRIC_BOUNDARY_IDENTITY_PAYLOAD_CACHE=()
  local -A OBI_METRIC_BOUNDARY_PAIR_PAYLOAD_CACHE=()
  local -A OBI_METRIC_BOUNDARY_JAVA_EVIDENCE_CACHE=()
  local -A OBI_METRIC_BOUNDARY_PARSED_METRICS_CACHE=()

  canonical="$(
    jq -ceS \
      --argjson maximum_boundaries "$OBI_METRIC_BOUNDARY_INDEX_MAX_BOUNDARIES" \
      --argjson maximum_captures "$OBI_METRIC_BOUNDARY_INDEX_MAX_CAPTURES" \
      --argjson maximum_statuses "$OBI_METRIC_BOUNDARY_INDEX_MAX_STATUS_REFERENCES" '
      def valid_shape:
        keys == ["boundaries", "schema", "selection"] and
      .schema == "obi-metric-boundary-index-v1" and
      (.selection | keys == [
        "repeat_count", "requested_transport", "scenario", "selected_transport"
      ]) and
      (.selection.scenario | type == "string") and
      (.selection.requested_transport == "auto" or
        .selection.requested_transport == "getsockopt" or
        .selection.requested_transport == "unix" or
        .selection.requested_transport == "disabled") and
      (.selection.selected_transport == null or
        .selection.selected_transport == "getsockopt" or
        .selection.selected_transport == "unix") and
      (if .selection.requested_transport == "getsockopt" then
        (.selection.selected_transport == null or
          .selection.selected_transport == "getsockopt")
       elif .selection.requested_transport == "unix" then
        (.selection.selected_transport == null or
          .selection.selected_transport == "unix")
       elif .selection.requested_transport == "disabled" then
        .selection.selected_transport == null
       else true end) and
      (.selection.repeat_count | type == "number" and
        floor == . and . >= 1 and . <= 10) and
      (.boundaries | type == "array" and length >= 1 and
        length <= $maximum_boundaries) and
      ([.boundaries[].id] | length == (unique | length)) and
      ([.boundaries[].ordinal] | length == (unique | length)) and
      ([.boundaries[].captures[] |
        select(.kind == "pair" and .state == "captured") |
        .pair_reference] | length == (unique | length)) and
      ([.boundaries[] | select(.state == "active")] | length <= 1) and
      ([.boundaries[].captures[]] | length <= $maximum_captures) and
      ([.boundaries[].status_references[]] | length <= $maximum_statuses) and
      (.boundaries | to_entries | all(.[];
        .value.ordinal == (.key + 1))) and
      all(.boundaries[];
        keys == [
          "captures", "id", "not_applicable_reason", "ordinal", "state",
          "status_references"
        ] and
        (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$")) and
        (.ordinal | type == "number" and floor == . and . >= 1) and
        (.state == "planned" or .state == "active" or
          .state == "complete" or .state == "not_applicable") and
        (.captures | type == "array") and
        (.status_references | type == "array") and
        ([.captures[].id] | length == (unique | length)) and
        ([.status_references[].reference] | length == (unique | length)) and
        (if .state == "planned" then
          .captures == [] and .status_references == [] and
          .not_applicable_reason == null
        elif .state == "active" then
          .not_applicable_reason == null
        elif .state == "complete" then
          (.captures | length) > 0 and
          all(.captures[]; .state == "captured") and
          (any(.captures[]; .kind == "pair") or
            all(.captures[]; .kind == "unavailable")) and
          (.status_references | length) > 0 and
          .not_applicable_reason == null
        else
          .captures == [] and (.status_references | length) == 1 and
          (.not_applicable_reason | type == "string" and length >= 1 and
            length <= 160)
        end) and
        all(.status_references[];
          keys == ["reference", "sha256"] and
          (.reference | type == "string" and
            test("^scenario-[a-z0-9][a-z0-9-]{0,95}-status\\.json$")) and
          (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) and
        all(.captures[];
          (.kind == "phase" and .state == "captured" and
            keys == ["id", "identity_reference", "identity_sha256", "kind", "state"] and
            (.identity_reference | type == "string") and
            (.identity_sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "java" and .state == "captured" and
            keys == ["id", "kind", "reference", "sha256", "state"] and
            (.reference | type == "string") and
            (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "artifact" and .state == "captured" and
            keys == ["id", "kind", "reference", "sha256", "state"] and
            (.reference | type == "string") and
            (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "unavailable" and .state == "captured" and
            keys == ["id", "kind", "reason", "reference", "sha256", "state"] and
            .reason == "obi_process_not_running" and
            (.reference | type == "string") and
            (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "pair" and
            keys == [
              "id", "java_reference", "java_sha256", "kind", "pair_reference",
              "pair_sha256", "state"
            ] and
            (.state == "planned" or .state == "captured") and
            (.id | type == "string" and
              test("^[a-z0-9][a-z0-9-]{0,63}$")) and
            (if .state == "planned" then
              .pair_reference == null and .pair_sha256 == null and
              .java_reference == null and .java_sha256 == null
            else
              (.pair_reference | type == "string") and
              (.pair_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
              ((.java_reference == null and .java_sha256 == null) or
                ((.java_reference | type == "string") and
                  (.java_sha256 | type == "string" and test("^[0-9a-f]{64}$"))))
            end)) and
          (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$"))
        )
      );
      def valid_order:
        [.boundaries[].state] as $states |
        ($states | length) as $count |
        all(range(0; $count); . as $index |
          if ($states[$index] == "complete" or
            $states[$index] == "not_applicable") then
            all(range(0; $index); . as $prior |
              $states[$prior] == "complete" or
              $states[$prior] == "not_applicable")
          elif $states[$index] == "active" then
            all(range(0; $index); . as $prior |
              $states[$prior] == "complete" or
              $states[$prior] == "not_applicable") and
            all(range($index + 1; $count); . as $later |
              $states[$later] == "planned")
          else
            all(range($index + 1; $count); . as $later |
              $states[$later] == "planned")
          end) and
        all(.boundaries[];
          ([.captures[] | select(.kind == "pair") | .state]) as $pair_states |
          all(range(0; ($pair_states | length)); . as $index |
            if $pair_states[$index] == "planned" then
              all(range($index + 1; ($pair_states | length)); . as $later |
                $pair_states[$later] == "planned")
            else true end));
      if valid_shape and valid_order then
        .
      else
        error("invalid OBI metric boundary index structure")
      end
    ' <<<"$payload"
  )" || return 1
  [[ "$payload" == "$canonical" ]] || return 1

  [[ "$validation_scope" == full || "$validation_scope" == structure ]] ||
    return 1
  if [[ "$validation_scope" == structure ]]; then
    return 0
  fi

  validate_obi_metric_boundary_referenced_byte_budget "$payload" || return 1

  capture_manifest="$(jq -r '
    .boundaries[] as $boundary |
    $boundary.captures[] |
    [
      $boundary.id, .id, .kind, .state,
      (if .kind == "phase" then .identity_reference
       elif .kind == "pair" then (.pair_reference // "__null__")
       else .reference end),
      (if .kind == "phase" then .identity_sha256
       elif .kind == "pair" then (.pair_sha256 // "__null__")
       else .sha256 end),
      (.java_reference // "__null__"), (.java_sha256 // "__null__")
    ] | @tsv
  ' <<<"$payload")" || return 1
  expected_capture_count="$(jq -er '[.boundaries[].captures[]] | length' \
    <<<"$payload")" || return 1

  while IFS=$'\t' read -r \
    boundary_id capture_id kind capture_state reference expected_digest \
    java_reference java_digest; do
    [[ -n "$boundary_id" ]] || continue
    ((capture_count += 1))
    case "$kind:$capture_state" in
      pair:planned)
        continue
        ;;
      phase:captured)
        [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-identity\.json$ ]] ||
          return 1
        capture_phase="${BASH_REMATCH[1]}"
        [[ "$capture_id" == "$capture_phase" ]] || return 1
        obi_process_identity_payload_from_reference \
          "$reference" semantic_payload || return 1
        ;;
      java:captured)
        [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/java-diagnostics\.txt$ ]] ||
          return 1
        capture_phase="${BASH_REMATCH[1]}"
        [[ "$capture_id" == "java-$capture_phase" ]] || return 1
        java_diagnostics_reference_evidence_json \
          "$reference" semantic_payload || return 1
        ;;
      artifact:captured)
        [[ "$reference" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ &&
          -f "$RESULT_DIR/$reference" && ! -L "$RESULT_DIR/$reference" ]] || return 1
        ;;
      unavailable:captured)
        [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-metrics\.prom$ ]] ||
          return 1
        unavailable_phase="${BASH_REMATCH[1]}"
        [[ "$capture_id" == "$unavailable_phase" ]] || return 1
        [[ ! -e "$RESULT_DIR/phases/$unavailable_phase/obi-identity.json" &&
          ! -L "$RESULT_DIR/phases/$unavailable_phase/obi-identity.json" ]] ||
          return 1
        obi_metrics_unavailable_phase_is_valid "$unavailable_phase" || return 1
        ;;
      pair:captured)
        [[ "$reference" == "obi-metric-pairs/$capture_id.json" ]] || return 1
        obi_metric_pair_payload_from_reference \
          "$reference" semantic_payload || return 1
        if [[ "$java_reference" != __null__ ]]; then
          java_diagnostics_reference_evidence_json \
            "$java_reference" semantic_payload || return 1
          observed_digest="$(sha256sum "$RESULT_DIR/$java_reference")" || return 1
          observed_digest="${observed_digest%% *}"
          [[ "$observed_digest" == "$java_digest" ]] || return 1
        fi
        ;;
      *) return 1 ;;
    esac
    if [[ -n "${observed_reference_digests[$reference]+present}" ]]; then
      [[ "${observed_reference_digests[$reference]}" == "$expected_digest" ]] ||
        return 1
    else
      observed_digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
      observed_digest="${observed_digest%% *}"
      [[ "$observed_digest" == "$expected_digest" ]] || return 1
      observed_reference_digests["$reference"]="$observed_digest"
    fi
  done <<<"$capture_manifest"
  ((capture_count == expected_capture_count)) || return 1
  status_manifest="$(jq -r '
    .boundaries[] as $boundary |
    $boundary.status_references[] |
    [$boundary.id, .reference, .sha256] | @tsv
  ' <<<"$payload")" || return 1
  expected_status_count="$(jq -er \
    '[.boundaries[].status_references[]] | length' <<<"$payload")" || return 1
  while IFS=$'\t' read -r boundary_id reference expected_digest; do
    [[ -n "$boundary_id" ]] || continue
    ((status_count += 1))
    [[ -f "$RESULT_DIR/$reference" && ! -L "$RESULT_DIR/$reference" &&
      "$(stat -Lc '%s' -- "$RESULT_DIR/$reference")" -le \
        "$OBI_METRIC_BOUNDARY_STATUS_MAX_BYTES" ]] || return 1
    if [[ -n "${observed_reference_digests[$reference]+present}" ]]; then
      [[ "${observed_reference_digests[$reference]}" == "$expected_digest" ]] ||
        return 1
    else
      observed_digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
      observed_digest="${observed_digest%% *}"
      [[ "$observed_digest" == "$expected_digest" ]] || return 1
      observed_reference_digests["$reference"]="$observed_digest"
    fi
    jq -e --arg boundary_id "$boundary_id" '
      (.obi_metric_boundary_ids | type == "array" and length >= 1) and
      ([.obi_metric_boundary_ids[]] | length == (unique | length)) and
      all(.obi_metric_boundary_ids[];
        type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$")) and
      (.obi_metric_boundary_ids | index($boundary_id)) != null
    ' "$RESULT_DIR/$reference" >/dev/null || return 1
  done <<<"$status_manifest"
  validate_obi_metric_pair_directory_closure "$payload" || return 1
  ((capture_count == expected_capture_count &&
    status_count == expected_status_count &&
    capture_count <= OBI_METRIC_BOUNDARY_INDEX_MAX_CAPTURES &&
    status_count <= OBI_METRIC_BOUNDARY_INDEX_MAX_STATUS_REFERENCES))
}

obi_metric_boundary_index_payload() {
  local -r validation_scope="${1:-structure}"
  local index=""
  local authority=""
  local authority_device=""
  local authority_inode=""
  local authority_owner=""
  local authority_mode=""
  local authority_links=""
  local payload=""

  index="$(obi_metric_boundary_index_path)" || return 1
  [[ -f "$index" && ! -L "$index" ]] || return 1
  authority="$(stat -Lc '%d:%i:%u:%a:%h' -- "$index")" || return 1
  IFS=: read -r authority_device authority_inode authority_owner \
    authority_mode authority_links <<<"$authority"
  [[ -n "$authority_device" && -n "$authority_inode" &&
    "$authority_owner" == "$(id -u)" && "$authority_mode" == 644 &&
    "$authority_links" == 1 ]] || return 1
  payload="$(read_bounded_single_line_regular_file \
    "$index" "$OBI_METRIC_BOUNDARY_INDEX_MAX_BYTES")" || return 1
  [[ ! -L "$index" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$index")" == "$authority" ]] ||
    return 1
  validate_obi_metric_boundary_index_payload \
    "$payload" "$validation_scope" >/dev/null || return 1
  printf '%s\n' "$payload"
}

publish_obi_metric_boundary_index_payload_unlocked() {
  local -r payload="$1"
  local -r expected_old_payload="${2:-}"
  local -r index="$(obi_metric_boundary_index_path)"
  local candidate=""
  local candidate_name=""
  local candidate_inode=""
  local candidate_identity=""
  local candidate_digest=""
  local old_identity=""
  local old_digest=""
  local observed_payload=""
  local publication_status=0
  local old_index_existed=false
  local installed=false
  local attempt=0

  (($# == 1 || $# == 2)) || return 1
  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "$TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN" == false &&
    -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    ! -L "$index" && ( ! -e "$index" || -f "$index" ) ]] || return 1
  normalize_obi_owned_private_candidate_residue \
    "$RESULT_DIR/.obi-metric-boundary-index" \
    '^\.obi-metric-boundary-index\.[A-Za-z0-9]{6}$' '^(600|644)$' || return 1
  validate_obi_metric_boundary_index_payload "$payload" structure >/dev/null ||
    return 1
  if [[ -e "$index" ]]; then
    observed_payload="$(read_bounded_single_line_regular_file_without_hashing \
      "$index" "$OBI_METRIC_BOUNDARY_INDEX_MAX_BYTES")" || return 1
    old_identity="$(stat -Lc '%d:%i:%u:%a' -- "$index")" || return 1
    [[ "$old_identity" == *":$(id -u):644" ]] || return 1
    old_digest="$(sha256sum "$index")" || return 1
    old_digest="${old_digest%% *}"
    obi_owned_publication_matches \
      "$index" "$old_identity" "$old_digest" 1 || return 1
    # A previous call can install the requested payload and then lose a
    # transient post-install stat/read. Treat that exact, fully validated
    # canonical state as the committed transition so a cooperative retry is
    # idempotent rather than requiring the no-longer-current predecessor.
    [[ "$observed_payload" != "$payload" ]] || return 0
    (($# == 2)) || return 1
    [[ "$observed_payload" == "$expected_old_payload" ]] || return 1
    old_index_existed=true
  elif (($# == 2)); then
    return 1
  fi
  if candidate="$(mktemp "$RESULT_DIR/.obi-metric-boundary-index.XXXXXX")"; then
    :
  else
    publication_status=$?
    candidate_name="${candidate##*/}"
    if [[ "${candidate%/*}" != "$RESULT_DIR" ||
      ! "$candidate_name" =~ ^\.obi-metric-boundary-index\.[A-Za-z0-9]{6}$ ||
      ! -f "$candidate" || -L "$candidate" ]]; then
      return "$publication_status"
    fi
  fi
  for attempt in 1 2 3; do
    candidate_inode="$(stat -Lc '%d:%i:%u' -- "$candidate")" && break
  done
  [[ -n "$candidate_inode" && "$candidate_inode" == *":$(id -u)" &&
    "$(stat -Lc '%d:%i:%u:%h' -- "$candidate")" == "$candidate_inode:1" ]] ||
    return 1
  if printf '%s\n' "$payload" >"$candidate" && chmod 0644 -- "$candidate"; then
    :
  else
    publication_status=$?
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || return 1
    return "$publication_status"
  fi
  candidate_identity="$(stat -Lc '%d:%i:%u:%a' -- "$candidate")" || {
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || true
    return 1
  }
  [[ "$candidate_identity" == "$candidate_inode:644" ]] || {
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || true
    return 1
  }
  candidate_digest="$(sha256sum "$candidate")" || {
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || true
    return 1
  }
  candidate_digest="${candidate_digest%% *}"
  observed_payload="$(read_bounded_single_line_regular_file_without_hashing \
    "$candidate" "$OBI_METRIC_BOUNDARY_INDEX_MAX_BYTES")" || {
    remove_obi_owned_private_file \
      "$candidate" "$candidate_identity" "$candidate_digest" || true
    return 1
  }
  [[ "$observed_payload" == "$payload" ]] || {
    remove_obi_owned_private_file \
      "$candidate" "$candidate_identity" "$candidate_digest" || true
    return 1
  }
  if [[ "$old_index_existed" == true ]]; then
    obi_owned_publication_matches \
      "$index" "$old_identity" "$old_digest" 1 || {
      remove_obi_owned_private_file \
        "$candidate" "$candidate_identity" "$candidate_digest" || return 1
      return 1
    }
  elif [[ -e "$index" || -L "$index" ]]; then
    remove_obi_owned_private_file \
      "$candidate" "$candidate_identity" "$candidate_digest" || return 1
    return 1
  fi
  if mv -fT -- "$candidate" "$index"; then
    publication_status=0
  else
    publication_status=$?
  fi
  if obi_owned_publication_matches \
    "$index" "$candidate_identity" "$candidate_digest" 1; then
    installed=true
  fi
  if [[ "$installed" == true ]]; then
    return 0
  fi
  if [[ "$old_index_existed" == true ]]; then
    obi_owned_publication_matches \
      "$index" "$old_identity" "$old_digest" 1 || return 1
  else
    [[ ! -e "$index" && ! -L "$index" ]] || return 1
  fi
  remove_obi_owned_private_file \
    "$candidate" "$candidate_identity" "$candidate_digest" || return 1
  ((publication_status != 0)) || publication_status=1
  return "$publication_status"
}

emit_repeated_obi_metric_boundary_ids() {
  local -r base="$1"
  local run_number=0

  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    if ((REPEAT_COUNT == 1)); then
      printf '%s\n' "$base"
    else
      printf '%s-run-%02d\n' "$base" "$run_number"
    fi
  done
}

planned_obi_metric_boundary_ids() {
  local name=""
  local -a direct_after_controls=(
    keepalive pipelining concurrency connection-churn fd-port-reuse
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff
    virtual-thread netty netty-server dispatch w3c
  )

  if [[ "$SCENARIO" == all ]]; then
    emit_repeated_obi_metric_boundary_ids basic
    printf '%s\n' delayed-otlp-suppression security
    for name in "${direct_after_controls[@]}"; do
      emit_repeated_obi_metric_boundary_ids "$name"
    done
    printf 'w3c-match\n'
    emit_repeated_obi_metric_boundary_ids obi-flags
    printf '%s\n' \
      primary-w3c-stale primary-generation-mismatch primary-w3c-fault \
      unix-w3c-stale unix-generation-mismatch w3c-fault \
      permanent-absence auto-unavailable late-attach restart-during-traffic \
      helper-attach-failure disabled extension-controls uninstrumented
    return 0
  fi
  case "$SCENARIO" in
    assertion-failure) emit_repeated_obi_metric_boundary_ids basic ;;
    restart-fault) printf 'restart-during-traffic\n' ;;
    benchmark-disabled|benchmark-uninstrumented|pid-reuse|restart)
      printf '%s\n' "$SCENARIO"
      ;;
    fail-open|w3c-only|w3c-match|w3c-fault|primary-w3c-stale|unix-w3c-stale|\
    primary-w3c-fault|primary-generation-mismatch|unix-generation-mismatch|\
    permanent-absence|auto-unavailable|security|delayed-otlp-suppression|\
    helper-attach-failure)
      printf '%s\n' "$SCENARIO"
      ;;
    *) emit_repeated_obi_metric_boundary_ids "$SCENARIO" ;;
  esac
}

initialize_obi_metric_boundary_index_unlocked() {
  local -r index="$(obi_metric_boundary_index_path)"
  local plan=""
  local plan_inode=""
  local payload=""
  local initialize_status=0

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" && ! -L "$index" &&
    ( ! -e "$index" || -f "$index" ) ]] || return 1
  normalize_owned_obi_h1_scratch_family \
    "$RESULT_DIR" "$RESULT_DIR/.obi-metric-boundary-plan" \
    '^\.obi-metric-boundary-plan\.[A-Za-z0-9]{6}$' || return $?
  plan="$(mktemp "$RESULT_DIR/.obi-metric-boundary-plan.XXXXXX")" || return $?
  plan_inode="$(stat -Lc '%d:%i:%u' -- "$plan")" || return 1
  [[ "$plan_inode" == *":$(id -u)" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$plan")" == \
      "$plan_inode:600:1" ]] || return 1
  if planned_obi_metric_boundary_ids >"$plan"; then
    :
  else
    initialize_status=$?
    remove_obi_owned_private_path_by_inode \
      "$plan" "$plan_inode" || return $?
    return "$initialize_status"
  fi
  payload="$(jq -Rcn \
    --arg scenario "$SCENARIO" \
    --arg requested_transport "$TRANSPORT" \
    --argjson repeat_count "$REPEAT_COUNT" '
      [inputs | select(length > 0)] as $ids |
      {
        schema: "obi-metric-boundary-index-v1",
        selection: {
          scenario: $scenario,
          requested_transport: $requested_transport,
          selected_transport: null,
          repeat_count: $repeat_count
        },
        boundaries: ($ids | to_entries | map({
          id: .value,
          ordinal: (.key + 1),
          state: "planned",
          captures: [],
          status_references: [],
          not_applicable_reason: null
        }))
      }
    ' <"$plan")" || initialize_status=$?
  remove_obi_owned_private_path_by_inode \
    "$plan" "$plan_inode" || return $?
  ((initialize_status == 0)) || return "$initialize_status"
  payload="$(jq -cS . <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$payload"
}

initialize_obi_metric_boundary_index() {
  with_terminal_java_diagnostics_lock initialize_obi_metric_boundary_index_unlocked
}

bind_selected_transport_to_obi_metric_boundary_index_unlocked() {
  local -r selected_transport="$1"
  local payload=""
  local updated=""

  [[ "$selected_transport" == getsockopt || "$selected_transport" == unix ]] ||
    return 1
  payload="$(obi_metric_boundary_index_payload)" || return 1
  if [[ "$(jq -r '.selection.selected_transport // empty' <<<"$payload")" != "" ]]; then
    return 0
  fi
  updated="$(jq -cS --arg selected_transport "$selected_transport" '
    if .selection.selected_transport == null then
      .selection.selected_transport = $selected_transport
    else .
    end
  ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

bind_selected_transport_to_obi_metric_boundary_index() {
  local -r selected_transport="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    bind_selected_transport_to_obi_metric_boundary_index_unlocked \
      "$selected_transport"
}

active_obi_metric_boundary_id() {
  local payload=""

  obi_metric_boundary_index_is_initialized || return 1
  payload="$(obi_metric_boundary_index_payload)" || return 1
  jq -er '
    [.boundaries[] | select(.state == "active") | .id] |
    if length == 1 then .[0] else error("no unique active boundary") end
  ' <<<"$payload"
}

begin_obi_metric_boundary_unlocked() {
  local -r boundary_id="$1"
  local payload=""
  local updated=""

  [[ "$boundary_id" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  payload="$(obi_metric_boundary_index_payload)" || return 1
  updated="$(jq -cS --arg boundary_id "$boundary_id" '
    ([.boundaries[] | select(.state == "active") | .id]) as $active |
    if $active == [$boundary_id] then .
    elif ($active | length) != 0 then error("another boundary is active")
    elif ([.boundaries[] | select(.state == "planned")][0].id // null) !=
      $boundary_id then error("boundary is not the earliest planned entry")
    else .boundaries |= map(
      if .id == $boundary_id then .state = "active" else . end)
    end
  ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

begin_obi_metric_boundary() {
  local -r boundary_id="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    begin_obi_metric_boundary_unlocked "$boundary_id" || return $?
  OBI_METRIC_BOUNDARY_ACTIVE_ID="$boundary_id"
}

plan_obi_metric_pair_capture_unlocked() {
  local -r capture_id="$1"
  local payload=""
  local updated=""

  payload="$(obi_metric_boundary_index_payload)" || return 1
  updated="$(jq -cS --arg capture_id "$capture_id" '
    ([.boundaries[] | select(.state == "active")]) as $active |
    if ($active | length) != 1 then error("no unique active boundary")
    elif any($active[0].captures[]; .id == $capture_id) then
      if any($active[0].captures[];
        .id == $capture_id and .kind == "pair") then .
      else error("capture id collision") end
    else
      .boundaries |= map(
        if .state == "active" then
          .captures += [{
            id: $capture_id,
            kind: "pair",
            state: "planned",
            pair_reference: null,
            pair_sha256: null,
            java_reference: null,
            java_sha256: null
          }]
        else . end)
    end
  ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

plan_obi_metric_pair_capture() {
  local -r capture_id="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    plan_obi_metric_pair_capture_unlocked "$capture_id"
}

attach_obi_metric_phase_capture_unlocked() {
  local -r phase="$1"
  local -r reference="phases/$phase/obi-identity.json"
  local digest="${2:-}"
  local payload=""
  local updated=""

  payload="$(obi_metric_boundary_index_payload)" || return 1
  case "$(jq -r '[.boundaries[] | select(.state == "active")] | length' \
    <<<"$payload")" in
    0) return 0 ;;
    1) ;;
    *) return 1 ;;
  esac
  if [[ -n "$digest" ]]; then
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  else
    obi_process_identity_payload_from_reference "$reference" >/dev/null || return 1
    digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
    digest="${digest%% *}"
  fi
  updated="$(jq -cS \
    --arg capture_id "$phase" --arg reference "$reference" --arg digest "$digest" '
      ([.boundaries[] | select(.state == "active")]) as $active |
      if ($active | length) == 0 then .
      elif ($active | length) != 1 then error("no unique active boundary")
      elif any($active[0].captures[]; .id == $capture_id) then
        if any($active[0].captures[];
          .id == $capture_id and .kind == "phase" and
          .identity_reference == $reference and .identity_sha256 == $digest)
        then . else error("phase capture collision") end
      else
        .boundaries |= map(
          if .state == "active" then
            .captures += [{
              id: $capture_id,
              kind: "phase",
              state: "captured",
              identity_reference: $reference,
              identity_sha256: $digest
            }]
          else . end)
      end
    ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

attach_obi_metric_phase_capture() {
  local -r phase="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    attach_obi_metric_phase_capture_unlocked "$phase"
}

attach_obi_unavailable_phase_capture_unlocked() {
  local -r phase="$1"
  local -r reference="phases/$phase/obi-metrics.prom"
  local digest="${2:-}"
  local payload=""
  local updated=""

  payload="$(obi_metric_boundary_index_payload)" || return 1
  case "$(jq -r '[.boundaries[] | select(.state == "active")] | length' \
    <<<"$payload")" in
    0) return 0 ;;
    1) ;;
    *) return 1 ;;
  esac
  obi_metrics_unavailable_phase_is_valid "$phase" || return 1
  [[ ! -e "$RESULT_DIR/phases/$phase/obi-identity.json" &&
    ! -L "$RESULT_DIR/phases/$phase/obi-identity.json" ]] || return 1
  if [[ -n "$digest" ]]; then
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  else
    digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
    digest="${digest%% *}"
  fi
  updated="$(jq -cS \
    --arg capture_id "$phase" --arg reference "$reference" \
    --arg digest "$digest" '
      ([.boundaries[] | select(.state == "active")]) as $active |
      if ($active | length) == 0 then .
      elif ($active | length) != 1 then error("no unique active boundary")
      elif any($active[0].captures[]; .id == $capture_id) then
        if any($active[0].captures[];
          .id == $capture_id and .kind == "unavailable" and
          .reason == "obi_process_not_running" and
          .reference == $reference and .sha256 == $digest)
        then . else error("unavailable capture collision") end
      else
        .boundaries |= map(
          if .state == "active" then
            .captures += [{
              id: $capture_id,
              kind: "unavailable",
              state: "captured",
              reason: "obi_process_not_running",
              reference: $reference,
              sha256: $digest
            }]
          else . end)
      end
    ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

obi_phase_capture_attachment_state_unlocked() {
  local -r phase="$1"
  local -r kind="$2"
  local -r digest="$3"
  local payload=""
  local active_count=""
  local matches=""

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    ( "$kind" == phase || "$kind" == unavailable ) &&
    "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  payload="$(obi_metric_boundary_index_payload)" || return 1
  active_count="$(jq -r \
    '[.boundaries[] | select(.state == "active")] | length' \
    <<<"$payload")" || return 1
  case "$active_count" in
    0)
      printf 'no_active\n'
      return 0
      ;;
    1) ;;
    *) return 1 ;;
  esac
  if [[ "$kind" == phase ]]; then
    matches="$(jq -r --arg capture_id "$phase" \
      --arg reference "phases/$phase/obi-identity.json" \
      --arg digest "$digest" '
        [.boundaries[] | select(.state == "active") | .captures[] |
          select(.id == $capture_id and .kind == "phase" and
            .state == "captured" and .identity_reference == $reference and
            .identity_sha256 == $digest)] | length
      ' <<<"$payload")" || return 1
  else
    matches="$(jq -r --arg capture_id "$phase" \
      --arg reference "phases/$phase/obi-metrics.prom" \
      --arg digest "$digest" '
        [.boundaries[] | select(.state == "active") | .captures[] |
          select(.id == $capture_id and .kind == "unavailable" and
            .state == "captured" and .reason == "obi_process_not_running" and
            .reference == $reference and .sha256 == $digest)] | length
      ' <<<"$payload")" || return 1
  fi
  case "$matches" in
    1) printf 'captured\n' ;;
    0) printf 'not_captured\n' ;;
    *) return 1 ;;
  esac
}

attach_obi_unavailable_phase_capture() {
  local -r phase="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    attach_obi_unavailable_phase_capture_unlocked "$phase"
}

attach_obi_java_capture_unlocked() {
  local -r phase="$1"
  local -r reference="phases/$phase/java-diagnostics.txt"
  local digest=""
  local payload=""
  local updated=""

  payload="$(obi_metric_boundary_index_payload)" || return 1
  case "$(jq -r '[.boundaries[] | select(.state == "active")] | length' \
    <<<"$payload")" in
    0) return 0 ;;
    1) ;;
    *) return 1 ;;
  esac
  java_diagnostics_reference_evidence_json "$reference" >/dev/null || return 1
  digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
  digest="${digest%% *}"
  updated="$(jq -cS \
    --arg capture_id "java-$phase" --arg reference "$reference" \
    --arg digest "$digest" '
      ([.boundaries[] | select(.state == "active")]) as $active |
      if ($active | length) == 0 then .
      elif ($active | length) != 1 then error("no unique active boundary")
      elif any($active[0].captures[]; .id == $capture_id) then
        if any($active[0].captures[];
          .id == $capture_id and .kind == "java" and
          .reference == $reference and .sha256 == $digest)
        then . else error("Java capture collision") end
      else
        .boundaries |= map(
          if .state == "active" then
            .captures += [{
              id: $capture_id,
              kind: "java",
              state: "captured",
              reference: $reference,
              sha256: $digest
            }]
          else . end)
      end
    ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

attach_obi_java_capture() {
  local -r phase="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock attach_obi_java_capture_unlocked "$phase"
}

attach_obi_artifact_capture_unlocked() {
  local -r capture_id="$1"
  local -r reference="$2"
  local digest=""
  local payload=""
  local updated=""

  [[ "$capture_id" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    "$reference" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ &&
    -f "$RESULT_DIR/$reference" && ! -L "$RESULT_DIR/$reference" ]] || return 1
  digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
  digest="${digest%% *}"
  payload="$(obi_metric_boundary_index_payload)" || return 1
  updated="$(jq -cS \
    --arg capture_id "$capture_id" --arg reference "$reference" \
    --arg digest "$digest" '
      ([.boundaries[] | select(.state == "active")]) as $active |
      if ($active | length) != 1 then error("no unique active boundary")
      elif any($active[0].captures[]; .id == $capture_id) then
        if any($active[0].captures[];
          .id == $capture_id and .kind == "artifact" and
          .reference == $reference and .sha256 == $digest)
        then . else error("artifact capture collision") end
      else
        .boundaries |= map(
          if .state == "active" then
            .captures += [{
              id: $capture_id,
              kind: "artifact",
              state: "captured",
              reference: $reference,
              sha256: $digest
            }]
          else . end)
      end
    ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

attach_obi_artifact_capture() {
  local -r capture_id="$1"
  local -r reference="$2"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    attach_obi_artifact_capture_unlocked "$capture_id" "$reference"
}

attach_obi_metric_pair_capture_unlocked() {
  local -r capture_id="$1"
  local -r pair_reference="$2"
  local -r java_phase="$3"
  local -r admitted_pair_payload="${4:-}"
  local -r admitted_pair_digest="${5:-}"
  local pair_digest=""
  local java_reference="null"
  local java_digest="null"
  local payload=""
  local updated=""

  (($# == 3 || $# == 5)) || return 1
  if (($# == 5)); then
    [[ "$TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN" == false &&
      "$admitted_pair_digest" =~ ^[0-9a-f]{64}$ &&
      "$(jq -er '.boundary' <<<"$admitted_pair_payload")" == "$capture_id" ]] ||
      return 1
    validate_obi_metric_pair_payload "$admitted_pair_payload" >/dev/null ||
      return 1
    pair_digest="$admitted_pair_digest"
  else
    obi_metric_pair_payload_from_reference "$pair_reference" >/dev/null || return 1
    pair_digest="$(sha256sum "$RESULT_DIR/$pair_reference")" || return 1
    pair_digest="${pair_digest%% *}"
  fi
  if [[ -n "$java_phase" &&
    -e "$RESULT_DIR/phases/$java_phase/java-diagnostics.txt" ]]; then
    java_reference="phases/$java_phase/java-diagnostics.txt"
    java_diagnostics_reference_evidence_json "$java_reference" >/dev/null || return 1
    java_digest="$(sha256sum "$RESULT_DIR/$java_reference")" || return 1
    java_digest="${java_digest%% *}"
  fi
  payload="$(obi_metric_boundary_index_payload)" || return 1
  updated="$(jq -cS \
    --arg capture_id "$capture_id" \
    --arg pair_reference "$pair_reference" --arg pair_digest "$pair_digest" \
    --arg java_reference "$java_reference" --arg java_digest "$java_digest" '
      def nullable($value): if $value == "null" then null else $value end;
      ([.boundaries[] | select(.state == "active")]) as $active |
      if ($active | length) != 1 then error("no unique active boundary")
      elif any($active[0].captures[];
        .id == $capture_id and .kind == "pair" and .state == "captured") then
        if any($active[0].captures[];
          .id == $capture_id and .kind == "pair" and .state == "captured" and
          .pair_reference == $pair_reference and .pair_sha256 == $pair_digest and
          .java_reference == nullable($java_reference) and
          .java_sha256 == nullable($java_digest))
        then . else error("captured pair collision") end
      elif ([ $active[0].captures[] |
        select(.kind == "pair" and .state == "planned") ][0].id // null) !=
        $capture_id then error("pair capture is not the earliest planned pair")
      else
        .boundaries |= map(
          if .state == "active" then
            .captures |= map(
              if .id == $capture_id and .kind == "pair" then
                .state = "captured" |
                .pair_reference = $pair_reference |
                .pair_sha256 = $pair_digest |
                .java_reference = nullable($java_reference) |
                .java_sha256 = nullable($java_digest)
              else . end)
          else . end)
      end
    ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

obi_metric_pair_capture_commit_state() {
  local -r capture_id="$1"
  local -r pair_reference="$2"
  local -r pair_digest="$3"
  local -r java_reference="$4"
  local -r java_digest="$5"
  local payload=""

  payload="$(obi_metric_boundary_index_payload)" || return 1
  jq -er \
    --arg capture_id "$capture_id" \
    --arg pair_reference "$pair_reference" --arg pair_digest "$pair_digest" \
    --arg java_reference "$java_reference" --arg java_digest "$java_digest" '
      def nullable($value): if $value == "null" then null else $value end;
      [.boundaries[] | select(.state == "active") | .captures[] |
        select(.id == $capture_id and .kind == "pair")] as $matches |
      if ($matches | length) != 1 then error("ambiguous pair capture")
      elif $matches[0].state == "planned" and
        $matches[0].pair_reference == null and
        $matches[0].pair_sha256 == null and
        $matches[0].java_reference == null and
        $matches[0].java_sha256 == null then "planned"
      elif $matches[0].state == "captured" and
        $matches[0].pair_reference == $pair_reference and
        $matches[0].pair_sha256 == $pair_digest and
        $matches[0].java_reference == nullable($java_reference) and
        $matches[0].java_sha256 == nullable($java_digest) then "captured"
      else error("pair capture collision") end
    ' <<<"$payload"
}

obi_metric_boundary_ids_json() {
  local boundary_id=""

  if boundary_id="$(active_obi_metric_boundary_id 2>/dev/null)"; then
    jq -cn --arg boundary_id "$boundary_id" '[$boundary_id]'
  else
    printf '[]\n'
  fi
}

completed_obi_metric_boundary_ids_json() {
  local payload=""

  obi_metric_boundary_index_is_initialized || {
    printf '[]\n'
    return 0
  }
  payload="$(obi_metric_boundary_index_payload)" || return 1
  jq -ce '
    [.boundaries[] | select(.state == "complete") | .id] as $completed |
    if ($completed | length) >= 1 and
      all(.boundaries[]; .state == "complete")
    then $completed else error("journal is not wholly complete") end
  ' <<<"$payload"
}

bind_status_to_active_obi_metric_boundary_unlocked() {
  local -r reference="$1"
  local boundary_id=""
  local digest=""
  local payload=""
  local updated=""

  [[ "$reference" =~ ^scenario-[a-z0-9][a-z0-9-]{0,95}-status\.json$ &&
    -f "$RESULT_DIR/$reference" && ! -L "$RESULT_DIR/$reference" ]] || return 1
  digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
  digest="${digest%% *}"
  payload="$(obi_metric_boundary_index_payload)" || return 1
  boundary_id="$(jq -er '
    [.boundaries[] | select(.state == "active") | .id] |
    if length == 1 then .[0] else error("no unique active boundary") end
  ' <<<"$payload")" || return 1
  jq -e --arg boundary_id "$boundary_id" '
    .obi_metric_boundary_ids == [$boundary_id]
  ' "$RESULT_DIR/$reference" >/dev/null || return 1
  updated="$(jq -cS \
    --arg boundary_id "$boundary_id" --arg reference "$reference" \
    --arg digest "$digest" '
      .boundaries |= map(
        if .id == $boundary_id and .state == "active" then
          if any(.status_references[]; .reference == $reference) then
            if any(.status_references[];
              .reference == $reference and .sha256 == $digest)
            then . else error("status reference collision") end
          else .status_references += [{reference: $reference, sha256: $digest}] end
        else . end)
    ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

bind_status_to_active_obi_metric_boundary() {
  local -r reference="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    bind_status_to_active_obi_metric_boundary_unlocked "$reference"
}

crosslink_and_bind_active_obi_metric_boundary_status() {
  local -r reference="$1"
  local boundary_id=""
  local candidate=""
  local update_status=0

  obi_metric_boundary_index_is_initialized || return 0
  boundary_id="$(active_obi_metric_boundary_id)" || return 1
  [[ "$reference" =~ ^scenario-[a-z0-9][a-z0-9-]{0,95}-status\.json$ &&
    -f "$RESULT_DIR/$reference" && ! -L "$RESULT_DIR/$reference" ]] || return 1
  candidate="$(mktemp "$RESULT_DIR/.scenario-status-crosslink.XXXXXX")" || return $?
  if jq -c --arg boundary_id "$boundary_id" '
    . + {obi_metric_boundary_ids: [$boundary_id]}
  ' "$RESULT_DIR/$reference" >"$candidate" &&
    chmod 0644 -- "$candidate" && mv -fT -- "$candidate" "$RESULT_DIR/$reference";
  then
    :
  else
    update_status=$?
    rm -f -- "$candidate" || true
    return "$update_status"
  fi
  bind_status_to_active_obi_metric_boundary "$reference"
}

complete_obi_metric_boundary_unlocked() {
  local -r boundary_id="$1"
  local payload=""
  local updated=""

  payload="$(obi_metric_boundary_index_payload)" || return 1
  updated="$(jq -cS --arg boundary_id "$boundary_id" '
    if ([.boundaries[] | select(
      .id == $boundary_id and .state == "active" and
      (.captures | length) > 0 and all(.captures[]; .state == "captured") and
      (any(.captures[]; .kind == "pair") or
        all(.captures[]; .kind == "unavailable")) and
      (.status_references | length) > 0)] | length) != 1
    then error("active boundary is incomplete")
    else .boundaries |= map(
      if .id == $boundary_id then .state = "complete" else . end)
    end
  ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

complete_obi_metric_boundary() {
  local -r boundary_id="$1"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    complete_obi_metric_boundary_unlocked "$boundary_id" || return $?
  if [[ "$OBI_METRIC_BOUNDARY_ACTIVE_ID" == "$boundary_id" ]]; then
    OBI_METRIC_BOUNDARY_ACTIVE_ID=""
  fi
}

mark_obi_metric_boundary_not_applicable_unlocked() {
  local -r boundary_id="$1"
  local -r reason="$2"
  local -r reference="$3"
  local digest=""
  local payload=""
  local updated=""

  [[ ${#reason} -ge 1 && ${#reason} -le 160 &&
    "$reference" == "scenario-$boundary_id-status.json" &&
    -f "$RESULT_DIR/$reference" && ! -L "$RESULT_DIR/$reference" ]] || return 1
  jq -e --arg boundary_id "$boundary_id" '
    .obi_metric_boundary_ids == [$boundary_id] and .status == "not_applicable"
  ' "$RESULT_DIR/$reference" >/dev/null || return 1
  digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
  digest="${digest%% *}"
  payload="$(obi_metric_boundary_index_payload)" || return 1
  updated="$(jq -cS \
    --arg boundary_id "$boundary_id" --arg reason "$reason" \
    --arg reference "$reference" --arg digest "$digest" '
      if ([.boundaries[] | select(
        .id == $boundary_id and .state == "planned")] | length) != 1
      then error("boundary is not uniquely planned")
      else .boundaries |= map(
        if .id == $boundary_id then
          .state = "not_applicable" |
          .not_applicable_reason = $reason |
          .status_references = [{reference: $reference, sha256: $digest}]
        else . end)
      end
    ' <<<"$payload")" || return 1
  publish_obi_metric_boundary_index_payload_unlocked "$updated" "$payload"
}

mark_obi_metric_boundary_not_applicable() {
  local -r boundary_id="$1"
  local -r reason="$2"
  local -r reference="$3"

  obi_metric_boundary_index_is_initialized || return 0
  with_terminal_java_diagnostics_lock \
    mark_obi_metric_boundary_not_applicable_unlocked \
      "$boundary_id" "$reason" "$reference" || return $?
  if [[ "$OBI_METRIC_BOUNDARY_ACTIVE_ID" == "$boundary_id" ]]; then
    OBI_METRIC_BOUNDARY_ACTIVE_ID=""
  fi
}

active_stopped_obi_metric_pair_reference() {
  local payload=""
  local pair_state=""
  local reference=""
  local expected_digest=""
  local observed_digest=""

  obi_metric_boundary_index_is_initialized || return 1
  payload="$(obi_metric_boundary_index_payload)" || return 1
  pair_state="$(jq -r '
    .boundaries[] | select(.state == "active") | .captures[] |
    select(.kind == "pair") | .state
  ' <<<"$payload" | tail -n 1)" || return 1
  if [[ -z "$pair_state" || "$pair_state" == planned ]]; then
    printf '\n'
    return 0
  fi
  [[ "$pair_state" == captured ]] || return 1
  IFS=$'\t' read -r reference expected_digest <<<"$(jq -er '
    [.boundaries[] | select(.state == "active") | .captures[] |
      select(.kind == "pair")][-1] |
    [.pair_reference, .pair_sha256] | @tsv
  ' <<<"$payload")" || return 1
  observed_digest="$(sha256sum "$RESULT_DIR/$reference")" || return 1
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$expected_digest" ]] || return 1
  if [[ "$(jq -er '.after.state' \
    <<<"$(obi_metric_pair_payload_from_reference "$reference")")" == \
    obi_stopped ]]; then
    printf '%s\n' "$reference"
  else
    printf '\n'
  fi
}

record_obi_metric_pair_unlocked() {
  local -r boundary="$1"
  local -r metric_payload="$2"
  local -r java_phase="$3"
  local -r metric_reference="obi-metric-pairs/$boundary.json"
  local -r pair_output="$RESULT_DIR/$metric_reference"
  local -r java_terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local -r metric_terminal="$RESULT_DIR/terminal-obi-metrics.json"
  local existing_pair=""
  local pair_candidate=""
  local pair_candidate_name=""
  local pair_inode=""
  local pair_identity=""
  local pair_digest=""
  local expected_java_reference="null"
  local expected_java_digest="null"
  local durable_capture_state=""
  local size=""
  local publication_status=0
  local attach_status=0
  local pair_created=false
  local pair_published=false
  local attempt=0

  [[ "$boundary" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    "$TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN" == false &&
    -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    ! -e "$java_terminal" && ! -L "$java_terminal" &&
    ! -e "$metric_terminal" && ! -L "$metric_terminal" ]] || return 1
  ensure_obi_metric_pair_directory || return 1
  normalize_obi_metric_pair_candidate_residue "$pair_output" || return 1
  validate_obi_metric_pair_payload "$metric_payload" >/dev/null || return 1
  [[ "$(jq -er '.boundary' <<<"$metric_payload")" == "$boundary" ]] || return 1
  if [[ -e "$pair_output" || -L "$pair_output" ]]; then
    existing_pair="$(obi_metric_pair_payload_from_reference "$metric_reference")" ||
      return 1
    [[ "$existing_pair" == "$metric_payload" ]] || return 1
    pair_digest="$(sha256sum "$pair_output")" || return 1
    pair_digest="${pair_digest%% *}"
  else
    if pair_candidate="$(mktemp \
      "$RESULT_DIR/obi-metric-pairs/.pair.XXXXXX")"; then
      :
    else
      publication_status=$?
      pair_candidate_name="${pair_candidate##*/}"
      if [[ "${pair_candidate%/*}" != "$RESULT_DIR/obi-metric-pairs" ||
        ! "$pair_candidate_name" =~ ^\.pair\.[A-Za-z0-9]{6}$ ||
        ! -f "$pair_candidate" || -L "$pair_candidate" ]]; then
        return "$publication_status"
      fi
      for attempt in 1 2 3; do
        pair_inode="$(stat -Lc '%d:%i:%u' -- "$pair_candidate")" && break
      done
      [[ -n "$pair_inode" ]] || return "$publication_status"
      remove_obi_owned_private_path_by_inode \
        "$pair_candidate" "$pair_inode" || return 1
      return "$publication_status"
    fi
    pair_candidate_name="${pair_candidate##*/}"
    [[ "${pair_candidate%/*}" == "$RESULT_DIR/obi-metric-pairs" &&
      "$pair_candidate_name" =~ ^\.pair\.[A-Za-z0-9]{6}$ &&
      -f "$pair_candidate" && ! -L "$pair_candidate" ]] || return 1
    for attempt in 1 2 3; do
      pair_inode="$(stat -Lc '%d:%i:%u' -- "$pair_candidate")" && break
    done
    [[ -n "$pair_inode" &&
      "$(stat -Lc '%d:%i:%u:%h' -- "$pair_candidate")" == "$pair_inode:1" ]] ||
      return 1
    if printf '%s\n' "$metric_payload" >"$pair_candidate" &&
      chmod 0644 -- "$pair_candidate"; then
      :
    else
      publication_status=$?
      remove_obi_owned_private_path_by_inode \
        "$pair_candidate" "$pair_inode" || return 1
      return "$publication_status"
    fi
    size=""
    for attempt in 1 2 3; do
      size="$(stat -Lc '%s' -- "$pair_candidate")" && break
    done
    if ! size="$(bounded_decimal "$size" "$OBI_METRIC_PAIR_MAX_BYTES" false)";
    then
      remove_obi_owned_private_path_by_inode \
        "$pair_candidate" "$pair_inode" || return 1
      return 1
    fi
    pair_identity=""
    for attempt in 1 2 3; do
      pair_identity="$(stat -Lc '%d:%i:%u:%a' -- "$pair_candidate")" && break
    done
    if [[ "$pair_identity" != "$pair_inode:644" ]]; then
      remove_obi_owned_private_path_by_inode \
        "$pair_candidate" "$pair_inode" || return 1
      return 1
    fi
    pair_digest=""
    for attempt in 1 2 3; do
      if pair_digest="$(sha256sum "$pair_candidate")"; then
        break
      fi
      pair_digest=""
    done
    if [[ -z "$pair_digest" ]]; then
      remove_obi_owned_private_path_by_inode \
        "$pair_candidate" "$pair_inode" || return 1
      return 1
    fi
    pair_digest="${pair_digest%% *}"
    if ln -T -- "$pair_candidate" "$pair_output"; then
      pair_published=true
    else
      publication_status=$?
      for attempt in 1 2 3; do
        if obi_owned_publication_matches \
          "$pair_output" "$pair_identity" "$pair_digest" 2; then
          pair_published=true
          break
        fi
      done
      if [[ "$pair_published" != true ]]; then
        remove_obi_owned_private_file \
          "$pair_candidate" "$pair_identity" "$pair_digest" || return 1
        return "$publication_status"
      fi
    fi
    for attempt in 1 2 3; do
      obi_owned_publication_matches \
        "$pair_output" "$pair_identity" "$pair_digest" 2 && break
    done
    obi_owned_publication_matches \
      "$pair_output" "$pair_identity" "$pair_digest" 2 || return 1
    pair_created=true
  fi
  if [[ -n "$java_phase" &&
    -e "$RESULT_DIR/phases/$java_phase/java-diagnostics.txt" ]]; then
    expected_java_reference="phases/$java_phase/java-diagnostics.txt"
    java_diagnostics_reference_evidence_json \
      "$expected_java_reference" >/dev/null || return 1
    expected_java_digest="$(sha256sum \
      "$RESULT_DIR/$expected_java_reference")" || return 1
    expected_java_digest="${expected_java_digest%% *}"
  fi
  if obi_metric_boundary_index_is_initialized; then
    if [[ "$pair_created" == true ]]; then
      if attach_obi_metric_pair_capture_unlocked \
        "$boundary" "$metric_reference" "$java_phase" \
        "$metric_payload" "$pair_digest"; then
        attach_status=0
      else
        attach_status=$?
      fi
    elif attach_obi_metric_pair_capture_unlocked \
      "$boundary" "$metric_reference" "$java_phase"; then
      attach_status=0
    else
      attach_status=$?
    fi
    durable_capture_state="$(obi_metric_pair_capture_commit_state \
      "$boundary" "$metric_reference" "$pair_digest" \
      "$expected_java_reference" "$expected_java_digest")" ||
      durable_capture_state=ambiguous
    if [[ "$durable_capture_state" == captured ]]; then
      if [[ "$pair_created" == true ]]; then
        remove_obi_owned_pair_publication_handle \
          "$pair_candidate" "$pair_output" || return 1
      fi
      attach_status=0
    elif [[ "$durable_capture_state" == planned ]]; then
      if [[ "$pair_created" == true ]]; then
        remove_obi_owned_pair_orphan_publication \
          "$pair_candidate" "$pair_output" || return 1
      fi
      ((attach_status != 0)) || attach_status=1
      return "$attach_status"
    else
      # Preserve the exact h2 ownership proof when the durable index cannot be
      # classified. A retry or terminal freeze can resolve it from disk.
      return 1
    fi
  elif [[ "$pair_created" == true ]]; then
    remove_obi_owned_pair_publication_handle \
      "$pair_candidate" "$pair_output" || return 1
  fi
  printf '%s\n' "$metric_reference"
}

record_obi_metric_pair() {
  local -r boundary="$1"
  local -r before_phase="$2"
  local -r after_phase="$3"
  local -r continuity="$4"
  local -r java_phase="${5:-$after_phase}"
  local payload=""
  local record_status=0

  (($# >= 4 && $# <= 5)) || return 1
  plan_obi_metric_pair_capture "$boundary" || return $?
  if payload="$(build_obi_metric_pair_payload \
    "$boundary" "$before_phase" "$after_phase" "$continuity")"; then
    :
  else
    record_status=$?
    return "$record_status"
  fi
  if with_terminal_java_diagnostics_lock \
    record_obi_metric_pair_unlocked "$boundary" "$payload" "$java_phase"; then
    return 0
  else
    record_status=$?
  fi
  return "$record_status"
}

assert_sanitized_java_diagnostics_snapshot() {
  local -r snapshot="$1"
  local entry=""
  local name=""
  local value=""
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
  local decoded=0
  local index=0

  IFS=',' read -r -a entries <<<"$snapshot"
  if (( ${#entries[@]} != ${#expected_names[@]} )); then
    log_error "Java diagnostics did not contain the exact fixed counter schema"
    return 1
  fi
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^[a-z_]+=(0|[1-9a-z][0-9a-z]*)$ ]] || {
      log_error "Java diagnostics contained a non-counter field"
      return 1
    }
    name="${entry%%=*}"
    value="${entry#*=}"
    if [[ "$name" != "${expected_names[$index]}" ]] || (( ${#value} > 6 )); then
      log_error "Java diagnostics contained an unknown, reordered, or unbounded counter"
      return 1
    fi
    decoded="$((36#$value))"
    if ((decoded >= JAVA_DIAGNOSTIC_COUNTER_MAX)); then
      log_error "Java diagnostics contained an out-of-range or saturated counter"
      return 1
    fi
    ((index += 1))
  done
}

assert_sanitized_java_diagnostics() {
  local -r input="$1"
  local snapshot=""

  snapshot="$(read_bounded_single_line_regular_file \
    "$input" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES")" || {
    log_error "Java diagnostics did not contain exactly one bounded snapshot"
    return 1
  }
  assert_sanitized_java_diagnostics_snapshot "$snapshot"
}

java_diagnostics_phase_directory_is_safe() {
  local -r phase="$1"
  local -r phases_root="$RESULT_DIR/phases"
  local -r phase_dir="$phases_root/$phase"
  local result_physical=""

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    -d "$phases_root" && ! -L "$phases_root" &&
    -d "$phase_dir" && ! -L "$phase_dir" ]] || return 1
  result_physical="$(realpath -e -- "$RESULT_DIR")" || return 1
  [[ "$(realpath -e -- "$phases_root")" == "$result_physical/phases" &&
    "$(realpath -e -- "$phase_dir")" == "$result_physical/phases/$phase" ]]
}

ensure_java_diagnostics_phase_directory() {
  local -r phase="$1"
  local -r phases_root="$RESULT_DIR/phases"
  local -r phase_dir="$phases_root/$phase"

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    -d "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || return 1
  if [[ ! -e "$phases_root" && ! -L "$phases_root" ]]; then
    mkdir -- "$phases_root" || return $?
  fi
  [[ -d "$phases_root" && ! -L "$phases_root" ]] || return 1
  if [[ ! -e "$phase_dir" && ! -L "$phase_dir" ]]; then
    mkdir -- "$phase_dir" || return $?
  fi
  java_diagnostics_phase_directory_is_safe "$phase"
}

java_diagnostics_reference_phase() {
  local -r reference="$1"

  [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/java-diagnostics\.txt$ ]] ||
    return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

java_diagnostics_reference_evidence_json() {
  local -r reference="$1"
  local -r output_name="${2:-}"
  local phase=""
  local input=""
  local snapshot=""
  local evidence=""

  (($# == 1 || $# == 2)) || return 1
  [[ -z "$output_name" || "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] ||
    return 1
  phase="$(java_diagnostics_reference_phase "$reference")" || return 1
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true ]]; then
    if [[ -n "${OBI_METRIC_BOUNDARY_JAVA_EVIDENCE_CACHE[$reference]+present}" ]]; then
      if [[ -n "$output_name" ]]; then
        printf -v "$output_name" '%s' \
          "${OBI_METRIC_BOUNDARY_JAVA_EVIDENCE_CACHE[$reference]}"
      else
        printf '%s\n' "${OBI_METRIC_BOUNDARY_JAVA_EVIDENCE_CACHE[$reference]}"
      fi
      return 0
    fi
  fi
  input="$RESULT_DIR/$reference"
  java_diagnostics_phase_directory_is_safe "$phase" || return 1
  snapshot="$(read_bounded_single_line_regular_file \
    "$input" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES")" || return 1
  assert_sanitized_java_diagnostics_snapshot "$snapshot" || return $?
  evidence="$(jq -cn \
    --arg reference "$reference" \
    --arg snapshot "$snapshot" '
      {
        reference: $reference,
        snapshot: $snapshot,
        counters: (
          $snapshot
          | split(",")
          | map(split("=") | {(.[0]): .[1]})
          | add
        )
      }
    ')" || return 1
  if [[ "${OBI_METRIC_BOUNDARY_FULL_VALIDATION_CACHE_ACTIVE:-false}" == true ]]; then
    OBI_METRIC_BOUNDARY_JAVA_EVIDENCE_CACHE["$reference"]="$evidence"
  fi
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$evidence"
  else
    printf '%s\n' "$evidence"
  fi
}

java_diagnostics_phase_evidence_json() {
  local -r phase="$1"
  local -r reference="phases/$phase/java-diagnostics.txt"
  local -r input="$RESULT_DIR/$reference"

  if [[ ! -e "$input" && ! -L "$input" ]]; then
    printf 'null\n'
    return 0
  fi
  java_diagnostics_reference_evidence_json "$reference"
}

with_terminal_java_diagnostics_transition_publication_lock() (
  local -r lock="$RESULT_DIR/.terminal-java-diagnostics-transition.lock"
  local lock_fd=""
  local path_identity=""
  local descriptor_identity=""
  local lock_status=0
  local command_status=0
  local lock_device=""
  local lock_inode=""
  local lock_links=""
  local lock_owner=""
  local lock_mode=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    ! -L "$lock" && ( ! -e "$lock" || -f "$lock" ) ]] || return 1
  umask 077
  exec {lock_fd}>>"$lock" || return $?
  path_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- "$lock")" || return 1
  descriptor_identity="$(
    stat -Lc '%d:%i:%h:%u:%a' -- "/proc/self/fd/$lock_fd"
  )" || return 1
  IFS=: read -r lock_device lock_inode lock_links lock_owner lock_mode \
    <<<"$path_identity"
  [[ ! -L "$lock" && "$path_identity" == "$descriptor_identity" &&
    -n "$lock_device" && -n "$lock_inode" && "$lock_links" == 1 &&
    "$lock_owner" == "$(id -u)" && "$lock_mode" == 600 ]] || return 1
  flock -x -w "$TERMINAL_JAVA_DIAGNOSTICS_LOCK_TIMEOUT_SECONDS" \
    "$lock_fd" || return $?
  path_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- "$lock")" || return 1
  descriptor_identity="$(
    stat -Lc '%d:%i:%h:%u:%a' -- "/proc/self/fd/$lock_fd"
  )" || return 1
  IFS=: read -r lock_device lock_inode lock_links lock_owner lock_mode \
    <<<"$path_identity"
  [[ ! -L "$lock" && "$path_identity" == "$descriptor_identity" &&
    -n "$lock_device" && -n "$lock_inode" && "$lock_links" == 1 &&
    "$lock_owner" == "$(id -u)" && "$lock_mode" == 600 ]] || return 1
  local TERMINAL_TRANSITION_PUBLICATION_LOCK_HELD_BY_CALLER=true
  if "$@"; then
    command_status=0
  else
    command_status=$?
  fi
  if flock -u "$lock_fd"; then
    :
  else
    lock_status=$?
  fi
  exec {lock_fd}>&-
  if ((command_status != 0)); then
    return "$command_status"
  fi
  return "$lock_status"
)

with_terminal_java_diagnostics_lock() (
  local -r lock="$RESULT_DIR/.terminal-java-diagnostics.lock"
  local lock_fd=""
  local path_identity=""
  local descriptor_identity=""
  local lock_status=0
  local command_status=0
  local TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN=""
  local lock_device=""
  local lock_inode=""
  local lock_links=""
  local lock_owner=""
  local lock_mode=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    ! -L "$lock" && ( ! -e "$lock" || -f "$lock" ) ]] || return 1
  umask 077
  exec {lock_fd}>>"$lock" || return $?
  path_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- "$lock")" || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- "/proc/self/fd/$lock_fd")" ||
    return 1
  IFS=: read -r lock_device lock_inode lock_links lock_owner lock_mode \
    <<<"$path_identity"
  [[ ! -L "$lock" && "$path_identity" == "$descriptor_identity" &&
    -n "$lock_device" && -n "$lock_inode" && "$lock_links" == 1 &&
    "$lock_owner" == "$(id -u)" && "$lock_mode" == 600 ]] || return 1
  flock -x -w "$TERMINAL_JAVA_DIAGNOSTICS_LOCK_TIMEOUT_SECONDS" \
    "$lock_fd" || return $?
  path_identity="$(stat -Lc '%d:%i:%h:%u:%a' -- "$lock")" || return 1
  descriptor_identity="$(
    stat -Lc '%d:%i:%h:%u:%a' -- "/proc/self/fd/$lock_fd"
  )" || return 1
  IFS=: read -r lock_device lock_inode lock_links lock_owner lock_mode \
    <<<"$path_identity"
  [[ ! -L "$lock" && "$path_identity" == "$descriptor_identity" &&
    -n "$lock_device" && -n "$lock_inode" && "$lock_links" == 1 &&
    "$lock_owner" == "$(id -u)" && "$lock_mode" == 600 ]] || return 1
  local TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER=true
  if obi_metric_boundary_publication_is_frozen; then
    TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN=true
  else
    TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN=false
  fi
  if "$@"; then
    command_status=0
  else
    command_status=$?
  fi
  if flock -u "$lock_fd"; then
    :
  else
    lock_status=$?
  fi
  exec {lock_fd}>&-
  if ((command_status != 0)); then
    return "$command_status"
  fi
  return "$lock_status"
)

last_java_diagnostics_payload_is_exact() {
  local -r last="$RESULT_DIR/.last-valid-java-diagnostics.json"
  local -r expected_payload="$1"
  local observed_payload=""

  observed_payload="$(read_bounded_single_line_owned_regular_file \
    "$last" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" 644 1)" || return 1
  validate_last_java_diagnostics_payload_structure \
    "$observed_payload" >/dev/null ||
    return 1
  [[ "$expected_payload" == __any__ ||
    "$observed_payload" == "$expected_payload" ]]
}

normalize_last_java_diagnostics_candidate_residue() {
  local -r expected_payload="$1"
  local -r last="$RESULT_DIR/.last-valid-java-diagnostics.json"
  local candidate=""
  local candidate_identity=""
  local candidate_device=""
  local candidate_inode=""
  local candidate_owner=""
  local candidate_mode=""
  local candidate_links=""
  local path=""
  local -a candidates=()

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true ]] || return 1
  for path in "$RESULT_DIR"/.last-valid-java-diagnostics.*; do
    if [[ ( -e "$path" || -L "$path" ) && "$path" != "$last" ]]; then
      candidates+=("$path")
      ((${#candidates[@]} <= 1)) || return 1
    fi
  done
  ((${#candidates[@]} <= 1)) || return 1
  if [[ -e "$last" || -L "$last" ]]; then
    last_java_diagnostics_payload_is_exact __any__ || return 1
  fi
  if ((${#candidates[@]} == 0)); then
    return 0
  fi
  candidate="${candidates[0]}"
  [[ "${candidate##*/}" =~ \
      ^\.last-valid-java-diagnostics\.[A-Za-z0-9]{6}$ &&
    -f "$candidate" && ! -L "$candidate" ]] || return 1
  candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
    return 1
  IFS=: read -r \
    candidate_device candidate_inode candidate_owner candidate_mode \
    candidate_links <<<"$candidate_identity"
  [[ -n "$candidate_device" && -n "$candidate_inode" &&
    "$candidate_owner" == "$(id -u)" &&
    ( "$candidate_mode" == 600 || "$candidate_mode" == 644 ) &&
    "$candidate_links" == 1 ]] || return 1
  remove_terminal_owned_private_path \
    "$candidate" "$candidate_identity" || return $?
  if [[ -e "$last" || -L "$last" ]]; then
    last_java_diagnostics_payload_is_exact "$expected_payload"
    return $?
  fi
  return 0
}

normalize_terminal_java_phase_and_last_candidates_before_freeze() {
  local -r phases_root="$RESULT_DIR/phases"
  local phase_dir=""
  local phase=""
  local path=""
  local has_candidate=false

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true ]] || return 1
  normalize_diagnostic_nondisclosure_report_candidate_before_freeze || return $?
  normalize_legacy_terminal_java_diagnostics_candidate_residue || return $?
  normalize_last_java_diagnostics_candidate_residue __any__ || return $?
  if [[ ! -e "$phases_root" && ! -L "$phases_root" ]]; then
    return 0
  fi
  [[ -d "$phases_root" && ! -L "$phases_root" ]] || return 1
  for phase_dir in "$phases_root"/*; do
    [[ -e "$phase_dir" || -L "$phase_dir" ]] || continue
    phase="${phase_dir##*/}"
    [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
      -d "$phase_dir" && ! -L "$phase_dir" ]] || return 1
    has_candidate=false
    for path in \
      "$phase_dir"/.java-diagnostics-header.* \
      "$phase_dir"/.terminal-diagnostics.*; do
      if [[ -e "$path" || -L "$path" ]]; then
        has_candidate=true
        break
      fi
    done
    [[ "$has_candidate" == true ]] || continue
    java_diagnostics_phase_directory_is_safe "$phase" || return 1
    normalize_terminal_owned_hardlink_family \
      "$phase_dir/java-diagnostics.txt" 644 \
      "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" true __any__ \
      validate_java_diagnostics_snapshot_hardlink_payload \
      '^\.(java-diagnostics-header|terminal-diagnostics)\.[A-Za-z0-9]{6}$' \
      "$phase_dir/.java-diagnostics-header" \
      "$phase_dir/.terminal-diagnostics" || return $?
  done
}

normalize_diagnostic_nondisclosure_report_candidate_before_freeze() {
  local -r canonical="$RESULT_DIR/scenario-diagnostic-nondisclosure-status.json"
  local path=""
  local present=false

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true ]] || return 1
  if [[ -e "$canonical" || -L "$canonical" ]]; then
    present=true
  fi
  for path in "$RESULT_DIR"/.diagnostic-nondisclosure-report.*; do
    if [[ -e "$path" || -L "$path" ]]; then
      present=true
      break
    fi
  done
  [[ "$present" == true ]] || return 0
  normalize_terminal_owned_hardlink_family \
    "$canonical" 644 "$DIAGNOSTIC_NONDISCLOSURE_REPORT_MAX_BYTES" true \
    __any__ validate_diagnostic_nondisclosure_status_hardlink_payload \
    '^\.diagnostic-nondisclosure-report\.[A-Za-z0-9]{6}$' \
    "$RESULT_DIR/.diagnostic-nondisclosure-report"
}

normalize_obi_phase_publication_candidates_before_freeze() {
  local -r phases_root="$RESULT_DIR/phases"
  local phase_dir=""
  local phase=""
  local path=""
  local identity_output=""
  local metrics_output=""
  local identity_payload=""
  local identity_digest=""
  local identity_links=""
  local unavailable_digest=""
  local journal_mode=""
  local normalization_status=0
  local metrics_handle=""
  local identity_handle=""
  local unavailable_handle=""
  local metrics_handle_identity=""
  local identity_handle_identity=""
  local unavailable_handle_identity=""
  local has_identity_candidate=false
  local has_metrics_candidate=false
  local has_unavailable_candidate=false

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true ]] || return 1
  normalize_owned_obi_h1_scratch_family \
    "$RESULT_DIR" "$RESULT_DIR/.obi-metric-boundary-plan" \
    '^\.obi-metric-boundary-plan\.[A-Za-z0-9]{6}$' || return $?
  normalize_obi_owned_private_candidate_residue \
    "$RESULT_DIR/.obi-metric-boundary-index" \
    '^\.obi-metric-boundary-index\.[A-Za-z0-9]{6}$' '^(600|644)$' \
    "$RESULT_DIR/.obi-metric-boundary-index.freeze" ||
    return $?
  if obi_metric_boundary_index_is_initialized; then
    journal_mode=initialized
  elif obi_metric_boundary_journal_paths_are_cleanly_absent; then
    journal_mode=legacy
  else
    return 1
  fi
  normalize_owned_obi_h1_scratch_family \
    "$RESULT_DIR" "$RESULT_DIR/.obi-metric-snapshot" \
    '^\.obi-metric-snapshot\.[A-Za-z0-9]{6}$' || return $?
  normalize_owned_obi_h1_scratch_family \
    "$RESULT_DIR" "$RESULT_DIR/.obi-metric-parsed" \
    '^\.obi-metric-parsed\.[A-Za-z0-9]{6}$' || return $?
  if [[ ! -e "$phases_root" && ! -L "$phases_root" ]]; then
    return 0
  fi
  [[ -d "$phases_root" && ! -L "$phases_root" ]] || return 1
  unavailable_digest="$(printf 'unavailable\n' | sha256sum)" || return 1
  unavailable_digest="${unavailable_digest%% *}"
  for phase_dir in "$phases_root"/*; do
    [[ -e "$phase_dir" || -L "$phase_dir" ]] || continue
    phase="${phase_dir##*/}"
    [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
      -d "$phase_dir" && ! -L "$phase_dir" ]] || return 1
    java_diagnostics_phase_directory_is_safe "$phase" || return 1
    normalize_owned_obi_metric_phase_scratch_residue "$phase" || return $?
    has_identity_candidate=false
    has_metrics_candidate=false
    has_unavailable_candidate=false
    metrics_handle=""
    identity_handle=""
    unavailable_handle=""
    metrics_handle_identity=""
    identity_handle_identity=""
    unavailable_handle_identity=""
    for path in "$phase_dir"/.obi-*; do
      [[ -e "$path" || -L "$path" ]] || continue
      case "${path##*/}" in
        .obi-identity.*)
          [[ "${path##*/}" =~ ^\.obi-identity\.[A-Za-z0-9]{6}$ ]] ||
            return 1
          has_identity_candidate=true
          identity_handle="$path"
          ;;
        .obi-metrics.*)
          [[ "${path##*/}" =~ ^\.obi-metrics\.[A-Za-z0-9]{6}$ ]] ||
            return 1
          has_metrics_candidate=true
          metrics_handle="$path"
          ;;
        .obi-metrics-unavailable.*)
          [[ "${path##*/}" =~ \
            ^\.obi-metrics-unavailable\.[A-Za-z0-9]{6}$ ]] || return 1
          has_unavailable_candidate=true
          unavailable_handle="$path"
          ;;
        *) return 1 ;;
      esac
    done
    if [[ "$has_unavailable_candidate" == true ]]; then
      if normalize_owned_phase_publication_handle \
        "$phase_dir/obi-metrics.prom" \
        "$phase_dir/.obi-metrics-unavailable" "$unavailable_digest" true;
      then
        normalization_status=0
      else
        normalization_status=$?
      fi
      case "$normalization_status" in
        0) ;;
        2)
          unavailable_handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
            "$unavailable_handle")" || return 1
          finalize_obi_unavailable_phase_publication_unlocked \
            "$phase" "$journal_mode" "$unavailable_digest" \
            "$unavailable_handle" "$unavailable_handle_identity" || return $?
          ;;
        *) return "$normalization_status" ;;
      esac
    fi
    [[ "$has_identity_candidate" == true ||
      "$has_metrics_candidate" == true ]] || continue
    identity_output="$phase_dir/obi-identity.json"
    metrics_output="$phase_dir/obi-metrics.prom"
    if [[ -f "$identity_output" && ! -L "$identity_output" &&
      ! -e "$metrics_output" && ! -L "$metrics_output" ]]; then
      identity_links="$(stat -Lc '%h' -- "$identity_output")" || return 1
      [[ "$identity_links" =~ ^[12]$ ]] || return 1
      identity_payload="$(read_bounded_single_line_owned_regular_file \
        "$identity_output" "$OBI_PROCESS_IDENTITY_MAX_BYTES" 644 \
        "$identity_links")" || return 1
      validate_obi_process_identity_payload "$identity_payload" >/dev/null ||
        return 1
      if [[ "$(jq -er '.state' <<<"$identity_payload")" == obi_stopped ]]; then
        identity_digest="$(sha256sum "$identity_output")" || return 1
        identity_digest="${identity_digest%% *}"
        normalize_owned_phase_publication_handle \
          "$identity_output" "$phase_dir/.obi-identity" "$identity_digest" ||
          return $?
        continue
      fi
    fi
    if normalize_owned_obi_metric_phase_capture "$phase" true; then
      normalization_status=0
    else
      normalization_status=$?
    fi
    case "$normalization_status" in
      0) ;;
      2)
        identity_digest="$(sha256sum "$identity_output")" || return 1
        identity_digest="${identity_digest%% *}"
        metrics_handle=""
        identity_handle=""
        for path in "$phase_dir"/.obi-*; do
          [[ -e "$path" || -L "$path" ]] || continue
          case "${path##*/}" in
            .obi-metrics.??????) metrics_handle="$path" ;;
            .obi-identity.??????) identity_handle="$path" ;;
            *) return 1 ;;
          esac
        done
        if [[ -n "$metrics_handle" ]]; then
          metrics_handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
            "$metrics_handle")" || return 1
        fi
        if [[ -n "$identity_handle" ]]; then
          identity_handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
            "$identity_handle")" || return 1
        fi
        finalize_obi_metric_phase_publication_unlocked \
          "$phase" "$journal_mode" "$identity_digest" \
          "$metrics_handle" "$metrics_handle_identity" \
          "$identity_handle" "$identity_handle_identity" || return $?
        ;;
      *) return "$normalization_status" ;;
    esac
  done
}

publish_last_java_diagnostics_payload_unlocked() {
  local -r payload="$1"
  local -r last="$RESULT_DIR/.last-valid-java-diagnostics.json"
  local candidate=""
  local candidate_inode=""
  local candidate_device=""
  local candidate_inode_number=""
  local candidate_owner=""
  local publication_status=1
  local attempt=0

  normalize_last_java_diagnostics_candidate_residue __any__ || return $?
  if [[ -e "$last" || -L "$last" ]] &&
    last_java_diagnostics_payload_is_exact "$payload"; then
    return 0
  fi
  if candidate="$(mktemp "$RESULT_DIR/.last-valid-java-diagnostics.XXXXXX")"; then
    :
  else
    publication_status=$?
    normalize_last_java_diagnostics_candidate_residue __any__ || return 1
    return "$publication_status"
  fi
  [[ "${candidate%/*}" == "$RESULT_DIR" &&
    "${candidate##*/}" =~ \
      ^\.last-valid-java-diagnostics\.[A-Za-z0-9]{6}$ &&
    -f "$candidate" && ! -L "$candidate" ]] || return 1
  for attempt in 1 2 3; do
    candidate_inode="$(stat -Lc '%d:%i:%u' -- "$candidate")" && break
    candidate_inode=""
  done
  IFS=: read -r candidate_device candidate_inode_number candidate_owner \
    <<<"$candidate_inode"
  [[ -n "$candidate_device" && -n "$candidate_inode_number" &&
    "$candidate_owner" == "$(id -u)" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" == \
      "$candidate_inode:600:1" ]] || return 1
  if printf '%s\n' "$payload" >"$candidate" &&
    chmod 0644 -- "$candidate"; then
    :
  else
    publication_status=$?
    remove_terminal_owned_private_candidate \
      "$candidate" "$candidate_inode" '^(600|644)$' || return 1
    return "$publication_status"
  fi
  [[ "$(read_bounded_single_line_owned_regular_file \
      "$candidate" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" 644 1)" == \
      "$payload" ]] &&
    validate_last_java_diagnostics_payload_structure "$payload" >/dev/null || {
      remove_terminal_owned_private_candidate \
        "$candidate" "$candidate_inode" '^644$' || return 1
      return 1
    }
  if mv -fT -- "$candidate" "$last"; then
    # A successful rename is provisional until the exact canonical path is
    # re-read with its expected ownership, mode, link count, and payload.
    publication_status=1
  else
    publication_status=$?
  fi
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    remove_terminal_owned_private_candidate \
      "$candidate" "$candidate_inode" '^(600|644)$' || return 1
  fi
  if last_java_diagnostics_payload_is_exact "$payload"; then
    return 0
  fi
  return "$publication_status"
}

record_last_java_diagnostics_reference_unlocked() {
  local -r reference="$1"
  local -r last="$RESULT_DIR/.last-valid-java-diagnostics.json"
  local -r terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local phase=""
  local evidence=""
  local payload=""

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "$TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN" == false &&
    -d "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || return 1
  if [[ -e "$terminal" || -L "$terminal" ]]; then
    terminal_java_diagnostics_json >/dev/null
    return $?
  fi
  [[ ! -L "$last" && ( ! -e "$last" || -f "$last" ) ]] || return 1
  phase="$(java_diagnostics_reference_phase "$reference")" || return 1
  evidence="$(java_diagnostics_reference_evidence_json "$reference")" || return 1
  payload="$(jq -cn \
    --arg schema 'obi-java-bridge-terminal-diagnostics-v1' \
    --arg phase "$phase" \
    --argjson evidence "$evidence" '
      $evidence + {
        schema: $schema,
        sealed: false,
        available: true,
        phase: $phase
      }
    ')" || return 1
  publish_last_java_diagnostics_payload_unlocked "$payload"
}

record_last_java_diagnostics_reference() {
  with_terminal_java_diagnostics_lock \
    record_last_java_diagnostics_reference_unlocked "$@"
}

record_last_java_diagnostics_phase() {
  local -r phase="$1"

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  record_last_java_diagnostics_reference \
    "phases/$phase/java-diagnostics.txt"
}

validate_last_java_diagnostics_payload_structure() {
  local -r payload="$1"
  local reference=""
  local phase=""
  local snapshot=""

  jq -e '
    keys == [
      "available", "counters", "phase", "reference", "schema", "sealed", "snapshot"
    ] and
    .schema == "obi-java-bridge-terminal-diagnostics-v1" and
    .sealed == false and
    .available == true and
    (.phase | type == "string") and
    (.reference | type == "string") and
    (.snapshot | type == "string") and
    (.counters | type == "object")
  ' <<<"$payload" >/dev/null || return 1
  reference="$(jq -er '.reference' <<<"$payload")" || return 1
  phase="$(java_diagnostics_reference_phase "$reference")" || return 1
  [[ "$(jq -er '.phase' <<<"$payload")" == "$phase" ]] || return 1
  snapshot="$(jq -er '.snapshot' <<<"$payload")" || return 1
  assert_sanitized_java_diagnostics_snapshot "$snapshot" || return $?
  jq -e --arg snapshot "$snapshot" '
    .counters == (
      $snapshot | split(",") |
      map(split("=") | {(.[0]): .[1]}) | add)
  ' <<<"$payload" >/dev/null || return 1
  printf '%s\n' "$payload"
}

validate_last_java_diagnostics_payload() {
  local -r payload="$1"
  local reference=""
  local expected=""

  validate_last_java_diagnostics_payload_structure "$payload" >/dev/null ||
    return 1
  reference="$(jq -er '.reference' <<<"$payload")" || return 1
  expected="$(java_diagnostics_reference_evidence_json "$reference")" || return 1
  jq -e --argjson expected "$expected" '
    .reference == $expected.reference and
    .snapshot == $expected.snapshot and
    .counters == $expected.counters
  ' <<<"$payload" >/dev/null || return 1
  printf '%s\n' "$payload"
}

validate_last_java_diagnostics_json() {
  local -r input="$1"
  local payload=""

  payload="$(read_bounded_single_line_regular_file \
    "$input" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES")" || return 1
  validate_last_java_diagnostics_payload "$payload"
}

validate_terminal_java_diagnostics_recovery_envelope() {
  local -r envelope="$1"
  local payload=""
  local metric_pair=""

  jq -e '
    keys == ["obi_metric_pair", "payload", "schema", "state"] and
    .schema == "obi-terminal-evidence-recovery-v2" and
    .state == "pending" and
    (.payload == null or (.payload | type == "object")) and
    .obi_metric_pair == null
  ' <<<"$envelope" >/dev/null || return 1
  payload="$(jq -c '.payload' <<<"$envelope")" || return 1
  metric_pair="$(jq -c '.obi_metric_pair' <<<"$envelope")" || return 1
  [[ "$metric_pair" == null ]] || return 1
  if [[ "$payload" == "null" ]]; then
    :
  else
    validate_last_java_diagnostics_payload_structure \
      "$payload" >/dev/null || return 1
  fi
  printf '%s\n' "$envelope"
}

validate_terminal_java_diagnostics_recovery_hardlink_payload() {
  local -r observed_payload="$1"
  local -r expected_payload="$3"

  validate_terminal_java_diagnostics_recovery_envelope \
    "$observed_payload" >/dev/null || return 1
  [[ "$expected_payload" == __any__ ||
    "$observed_payload" == "$expected_payload" ]]
}

normalize_terminal_java_diagnostics_recovery_boundary_residue() {
  local -r expected_payload="${1:-__any__}"
  local allow_h1_cleanup=false

  if [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true ]]; then
    allow_h1_cleanup=true
  fi
  normalize_terminal_owned_hardlink_family \
    "$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json" 600 \
    "$OBI_TERMINAL_BOUNDARY_MAX_BYTES" "$allow_h1_cleanup" \
    "$expected_payload" \
    validate_terminal_java_diagnostics_recovery_hardlink_payload \
    '^\.terminal-java-diagnostics-recovery-boundary\.[A-Za-z0-9]{6}$' \
    "$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary"
}

terminal_java_diagnostics_recovery_boundary_payload() {
  local -r boundary="$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json"
  local envelope=""
  local payload=""

  normalize_terminal_java_diagnostics_recovery_boundary_residue || return $?
  envelope="$(read_bounded_single_line_regular_file \
    "$boundary" "$OBI_TERMINAL_BOUNDARY_MAX_BYTES")" || return 1
  validate_terminal_java_diagnostics_recovery_envelope \
    "$envelope" >/dev/null || return 1
  payload="$(jq -c '.payload' <<<"$envelope")" || return 1
  printf '%s\n' "$payload"
}

terminal_obi_metric_recovery_boundary_payload() {
  local -r boundary="$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json"
  local envelope=""
  local metric_pair=""

  envelope="$(read_bounded_single_line_regular_file \
    "$boundary" "$OBI_TERMINAL_BOUNDARY_MAX_BYTES")" || return 1
  terminal_java_diagnostics_recovery_boundary_payload >/dev/null || return 1
  metric_pair="$(jq -c '.obi_metric_pair' <<<"$envelope")" || return 1
  printf '%s\n' "$metric_pair"
}

terminal_java_diagnostics_recovery_commit_is_valid() {
  with_terminal_java_diagnostics_transition_publication_lock \
    terminal_java_diagnostics_recovery_commit_is_valid_unlocked
}

validate_terminal_java_diagnostics_transition_payload() {
  local -r payload="$1"
  local -r boundary="$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json"
  local boundary_digest=""
  local expected_boundary_digest=""

  if [[ "$payload" == terminal-java-diagnostics-frozen-v1 ]]; then
    printf 'frozen\n'
    return 0
  fi
  [[ "$payload" =~ ^terminal-java-diagnostics-recovery-committed-v1:([0-9a-f]{64})$ ]] ||
    return 1
  expected_boundary_digest="${BASH_REMATCH[1]}"
  if [[ -e "$boundary" || -L "$boundary" ]]; then
    terminal_java_diagnostics_recovery_boundary_payload >/dev/null || return $?
    boundary_digest="$(sha256sum "$boundary")" || return $?
    boundary_digest="${boundary_digest%% *}"
    [[ "$boundary_digest" == "$expected_boundary_digest" ]] || return 1
  fi
  printf 'committed\n'
}

validate_terminal_java_diagnostics_transition_hardlink_payload() {
  local -r observed_payload="$1"
  local -r candidate_basename="$2"
  local -r expected_payload="$3"
  local -r candidate_links="$4"
  local state=""

  state="$(
    validate_terminal_java_diagnostics_transition_payload "$observed_payload"
  )" || return 1
  if [[ "$candidate_links" == 2 ]]; then
    if [[ "$state" == frozen ]]; then
      [[ "$candidate_basename" =~ \
        ^\.terminal-java-diagnostics-freeze\.[A-Za-z0-9]{6}$ ]] || return 1
    else
      [[ "$candidate_basename" =~ \
        ^\.terminal-java-diagnostics-recovery-commit\.[A-Za-z0-9]{6}$ ]] ||
        return 1
    fi
  fi
  [[ "$expected_payload" == __any__ ||
    "$observed_payload" == "$expected_payload" ]]
}

# shellcheck disable=SC2120 # Tests also exercise exact-payload normalization.
normalize_terminal_java_diagnostics_transition_residue_unlocked() {
  local -r expected_payload="${1:-__any__}"

  [[ "${TERMINAL_TRANSITION_PUBLICATION_LOCK_HELD_BY_CALLER:-false}" == true ]] ||
    return 1
  normalize_terminal_owned_hardlink_family \
    "$RESULT_DIR/.terminal-java-diagnostics.freeze" 600 160 true \
    "$expected_payload" \
    validate_terminal_java_diagnostics_transition_hardlink_payload \
    '^\.terminal-java-diagnostics-(freeze|recovery-commit)\.[A-Za-z0-9]{6}$' \
    "$RESULT_DIR/.terminal-java-diagnostics-freeze" \
    "$RESULT_DIR/.terminal-java-diagnostics-recovery-commit"
}

terminal_java_diagnostics_transition_state_unlocked() {
  local -r transition="$RESULT_DIR/.terminal-java-diagnostics.freeze"
  local payload=""

  normalize_terminal_java_diagnostics_transition_residue_unlocked || return $?
  payload="$(read_bounded_single_line_regular_file "$transition" 160)" || return 1
  validate_terminal_java_diagnostics_transition_payload "$payload"
}

terminal_java_diagnostics_transition_state() {
  with_terminal_java_diagnostics_transition_publication_lock \
    terminal_java_diagnostics_transition_state_unlocked
}

terminal_java_diagnostics_recovery_commit_is_valid_unlocked() {
  [[ "$(terminal_java_diagnostics_transition_state_unlocked)" == committed ]]
}

terminal_java_diagnostics_transition_is_valid() {
  terminal_java_diagnostics_transition_state >/dev/null
}

capture_terminal_java_diagnostics_recovery_boundary_unlocked() {
  local -r terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local -r metric_terminal="$RESULT_DIR/terminal-obi-metrics.json"
  local -r freeze="$RESULT_DIR/.terminal-java-diagnostics.freeze"
  local -r last="$RESULT_DIR/.last-valid-java-diagnostics.json"
  local -r boundary="$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json"
  local payload="null"
  local metric_pair="null"
  local envelope=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    ! -e "$terminal" && ! -L "$terminal" &&
    ! -e "$metric_terminal" && ! -L "$metric_terminal" &&
    ! -e "$freeze" && ! -L "$freeze" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false ]] || return 1
  if [[ -e "$last" || -L "$last" ]]; then
    payload="$(validate_last_java_diagnostics_json "$last")" || return 1
  fi
  envelope="$(jq -cn \
    --argjson payload "$payload" \
    --argjson metric_pair "$metric_pair" '
    {
      schema: "obi-terminal-evidence-recovery-v2",
      state: "pending",
      payload: $payload,
      obi_metric_pair: $metric_pair
    }
  ')" || return 1
  normalize_terminal_java_diagnostics_recovery_boundary_residue __any__ ||
    return $?
  if [[ -e "$boundary" || -L "$boundary" ]]; then
    terminal_java_diagnostics_recovery_boundary_payload >/dev/null || return 1
    terminal_obi_metric_recovery_boundary_payload >/dev/null
    return $?
  fi
  publish_terminal_owned_hardlink_payload \
    "$boundary" \
    "$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary" \
    '^\.terminal-java-diagnostics-recovery-boundary\.[A-Za-z0-9]{6}$' \
    '^\.terminal-java-diagnostics-recovery-boundary\.[A-Za-z0-9]{6}$' \
    600 "$OBI_TERMINAL_BOUNDARY_MAX_BYTES" "$envelope" \
    validate_terminal_java_diagnostics_recovery_hardlink_payload true \
    "$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary" || return $?
  terminal_java_diagnostics_recovery_boundary_payload >/dev/null || return 1
  terminal_obi_metric_recovery_boundary_payload >/dev/null
}

capture_terminal_java_diagnostics_recovery_boundary() {
  with_terminal_java_diagnostics_lock \
    capture_terminal_java_diagnostics_recovery_boundary_unlocked
}

commit_terminal_java_diagnostics_recovery_boundary_publication_unlocked() {
  local -r terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local -r metric_terminal="$RESULT_DIR/terminal-obi-metrics.json"
  local -r freeze="$RESULT_DIR/.terminal-java-diagnostics.freeze"
  local -r boundary="$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json"
  local boundary_digest=""
  local payload=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    ! -e "$terminal" && ! -L "$terminal" &&
    ! -e "$metric_terminal" && ! -L "$metric_terminal" &&
    -e "$boundary" && ! -L "$boundary" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    ( "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false ||
      ( "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == true &&
        -e "$freeze" && ! -L "$freeze" ) ) &&
    "${TERMINAL_TRANSITION_PUBLICATION_LOCK_HELD_BY_CALLER:-false}" == true ]] ||
    return 1
  terminal_java_diagnostics_recovery_boundary_payload >/dev/null || return $?
  boundary_digest="$(sha256sum "$boundary")" || return $?
  boundary_digest="${boundary_digest%% *}"
  payload="terminal-java-diagnostics-recovery-committed-v1:$boundary_digest"
  publish_terminal_owned_hardlink_payload \
    "$freeze" "$RESULT_DIR/.terminal-java-diagnostics-recovery-commit" \
    '^\.terminal-java-diagnostics-recovery-commit\.[A-Za-z0-9]{6}$' \
    '^\.terminal-java-diagnostics-(freeze|recovery-commit)\.[A-Za-z0-9]{6}$' \
    600 160 "$payload" \
    validate_terminal_java_diagnostics_transition_hardlink_payload true \
    "$RESULT_DIR/.terminal-java-diagnostics-freeze" \
    "$RESULT_DIR/.terminal-java-diagnostics-recovery-commit" || return $?
  terminal_java_diagnostics_recovery_commit_is_valid_unlocked
}

commit_terminal_java_diagnostics_recovery_boundary_unlocked() {
  with_terminal_java_diagnostics_transition_publication_lock \
    commit_terminal_java_diagnostics_recovery_boundary_publication_unlocked
}

commit_terminal_java_diagnostics_recovery_boundary() {
  with_terminal_java_diagnostics_lock \
    commit_terminal_java_diagnostics_recovery_boundary_unlocked
}

clear_terminal_java_diagnostics_recovery_boundary_publication_unlocked() {
  local -r boundary="$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json"
  local -r transition="$RESULT_DIR/.terminal-java-diagnostics.freeze"

  local boundary_identity=""
  local transition_identity=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_TRANSITION_PUBLICATION_LOCK_HELD_BY_CALLER:-false}" == true ]] ||
    return 1
  normalize_terminal_java_diagnostics_recovery_boundary_residue __any__ ||
    return $?
  normalize_terminal_java_diagnostics_transition_residue_unlocked || return $?
  if [[ ! -e "$boundary" && ! -L "$boundary" &&
    ! -e "$transition" && ! -L "$transition" ]]; then
    return 0
  fi
  [[ -e "$transition" && ! -L "$transition" ]] || return 1
  terminal_java_diagnostics_recovery_commit_is_valid_unlocked || return $?
  if [[ -e "$boundary" || -L "$boundary" ]]; then
    terminal_java_diagnostics_recovery_boundary_payload >/dev/null || return $?
    boundary_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$boundary")" ||
      return 1
    remove_terminal_owned_private_path \
      "$boundary" "$boundary_identity" || return $?
  fi
  transition_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$transition")" ||
    return 1
  remove_terminal_owned_private_path \
    "$transition" "$transition_identity" || return $?
  [[ ! -e "$boundary" && ! -L "$boundary" &&
    ! -e "$transition" && ! -L "$transition" ]]
}

clear_terminal_java_diagnostics_recovery_boundary_unlocked() {
  with_terminal_java_diagnostics_transition_publication_lock \
    clear_terminal_java_diagnostics_recovery_boundary_publication_unlocked
}

clear_terminal_java_diagnostics_recovery_boundary() {
  with_terminal_java_diagnostics_lock \
    clear_terminal_java_diagnostics_recovery_boundary_unlocked
}

validate_terminal_java_diagnostics_payload() {
  local -r payload="$1"
  local reference=""
  local phase=""
  local expected=""

  if jq -e '
    keys == ["available", "reason", "schema", "sealed"] and
    .schema == "obi-java-bridge-terminal-diagnostics-v1" and
    .sealed == true and
    .available == false and
    .reason == "no-valid-snapshot-before-terminal-boundary"
  ' <<<"$payload" >/dev/null; then
    printf '%s\n' "$payload"
    return 0
  fi
  jq -e '
    keys == [
      "available", "counters", "phase", "reference", "schema", "sealed", "snapshot"
    ] and
    .schema == "obi-java-bridge-terminal-diagnostics-v1" and
    .sealed == true and
    .available == true and
    (.phase | type == "string") and
    (.reference | type == "string") and
    (.snapshot | type == "string") and
    (.counters | type == "object")
  ' <<<"$payload" >/dev/null || return 1
  reference="$(jq -er '.reference' <<<"$payload")" || return 1
  phase="$(java_diagnostics_reference_phase "$reference")" || return 1
  [[ "$(jq -er '.phase' <<<"$payload")" == "$phase" ]] || return 1
  expected="$(java_diagnostics_reference_evidence_json "$reference")" || return 1
  jq -e --argjson expected "$expected" '
    .reference == $expected.reference and
    .snapshot == $expected.snapshot and
    .counters == $expected.counters
  ' <<<"$payload" >/dev/null || return 1
  printf '%s\n' "$payload"
}

validate_terminal_java_diagnostics_hardlink_payload() {
  local -r observed_payload="$1"
  local -r expected_payload="$3"

  validate_terminal_java_diagnostics_payload "$observed_payload" >/dev/null ||
    return 1
  [[ "$expected_payload" == __any__ ||
    "$observed_payload" == "$expected_payload" ]]
}

normalize_legacy_terminal_java_diagnostics_candidate_residue() {
  local -r terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local candidate=""
  local name=""
  local path=""
  local candidate_identity=""
  local terminal_identity=""
  local payload=""
  local candidate_device=""
  local candidate_inode=""
  local candidate_owner=""
  local candidate_mode=""
  local candidate_links=""
  local -a candidates=()

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    -d "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || return 1
  for path in "$RESULT_DIR"/.terminal-java-diagnostics.*; do
    [[ -e "$path" || -L "$path" ]] || continue
    name="${path##*/}"
    case "$name" in
      .terminal-java-diagnostics.lock|\
      .terminal-java-diagnostics-transition.lock|\
      .terminal-java-diagnostics.freeze|\
      .terminal-java-diagnostics-recovery-boundary.json)
        ;;
      .terminal-java-diagnostics.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9])
        [[ "$name" =~ ^\.terminal-java-diagnostics\.[A-Za-z0-9]{6}$ ]] ||
          return 1
        candidates+=("$path")
        ;;
      .terminal-java-diagnostics-output.*)
        [[ "$name" =~ \
          ^\.terminal-java-diagnostics-output\.[A-Za-z0-9]{6}$ ]] ||
          return 1
        ;;
      .terminal-java-diagnostics-freeze.*)
        [[ "$name" =~ \
          ^\.terminal-java-diagnostics-freeze\.[A-Za-z0-9]{6}$ ]] ||
          return 1
        ;;
      .terminal-java-diagnostics-recovery-commit.*)
        [[ "$name" =~ \
          ^\.terminal-java-diagnostics-recovery-commit\.[A-Za-z0-9]{6}$ ]] ||
          return 1
        ;;
      .terminal-java-diagnostics-recovery-boundary.*)
        [[ "$name" =~ \
          ^\.terminal-java-diagnostics-recovery-boundary\.[A-Za-z0-9]{6}$ ]] ||
          return 1
        ;;
      *) return 1 ;;
    esac
  done
  ((${#candidates[@]} <= 1)) || return 1
  ((${#candidates[@]} == 1)) || return 0
  candidate="${candidates[0]}"
  [[ -f "$candidate" && ! -L "$candidate" ]] || return 1
  candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
    return 1
  IFS=: read -r candidate_device candidate_inode candidate_owner \
    candidate_mode candidate_links <<<"$candidate_identity"
  [[ -n "$candidate_device" && -n "$candidate_inode" &&
    "$candidate_owner" == "$(id -u)" ]] || return 1
  if [[ ( "$candidate_mode" == 600 || "$candidate_mode" == 644 ) &&
    "$candidate_links" == 1 ]]; then
    remove_terminal_owned_private_path \
      "$candidate" "$candidate_identity"
    return $?
  fi
  [[ "$candidate_mode" == 644 && "$candidate_links" == 2 &&
    -f "$terminal" && ! -L "$terminal" && "$candidate" -ef "$terminal" ]] ||
    return 1
  terminal_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$terminal")" ||
    return 1
  [[ "$terminal_identity" == "$candidate_identity" ]] || return 1
  payload="$(read_bounded_single_line_owned_regular_file \
    "$terminal" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" 644 2)" || return 1
  validate_terminal_java_diagnostics_payload "$payload" >/dev/null ||
    return 1
  remove_terminal_owned_hardlink_handle \
    "$candidate" "$terminal" "$terminal_identity"
}

normalize_terminal_java_diagnostics_residue() {
  local -r expected_payload="$1"
  local allow_h1_cleanup=false

  if [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == true ]]; then
    allow_h1_cleanup=true
  fi
  normalize_legacy_terminal_java_diagnostics_candidate_residue || return $?
  normalize_terminal_owned_hardlink_family \
    "$RESULT_DIR/terminal-java-diagnostics.json" 644 \
    "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" "$allow_h1_cleanup" \
    "$expected_payload" validate_terminal_java_diagnostics_hardlink_payload \
    '^\.terminal-java-diagnostics-output\.[A-Za-z0-9]{6}$' \
    "$RESULT_DIR/.terminal-java-diagnostics-output"
}

terminal_java_diagnostics_json() {
  local -r terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local payload=""

  payload="$(read_bounded_single_line_regular_file \
    "$terminal" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES")" || return 1
  validate_terminal_java_diagnostics_payload "$payload"
}

terminal_java_diagnostics_payload_from_frozen_index() {
  local index_payload=""
  local active_boundary_id=""
  local reference=""
  local phase=""
  local evidence=""

  if obi_metric_boundary_journal_paths_are_cleanly_absent; then
    printf 'null\n'
    return 0
  fi
  obi_metric_boundary_index_freeze_payload >/dev/null || return 1
  if [[ -n "$OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD" ]]; then
    index_payload="$OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD"
  else
    index_payload="$(obi_metric_boundary_index_payload full)" || return 1
  fi
  active_boundary_id="$(jq -r '
    [.boundaries[] | select(.state == "active") | .id] |
    if length == 0 then "" elif length == 1 then .[0]
    else error("multiple active boundaries") end
  ' <<<"$index_payload")" || return 1
  if [[ -z "$active_boundary_id" ]]; then
    # Java-only recovery remains independent of metric attribution. Returning
    # null permits the existing last-valid Java checkpoint, but the v2 metric
    # terminal below still records no-active-boundary and can never reuse a
    # completed boundary's pair.
    printf 'null\n'
    return 0
  fi
  reference="$(jq -r --arg boundary_id "$active_boundary_id" '
    [.boundaries[] | select(.id == $boundary_id) | .captures][0] as $captures |
    [$captures | to_entries[] | select(.value.kind == "pair")] as $pairs |
    if ($pairs | length) == 0 then
      [$captures[] | select(.kind == "java" and .state == "captured") |
        .reference] | if length == 0 then "" else .[-1] end
    elif $pairs[-1].value.state == "captured" then
      ($pairs[-1].value.java_reference // "")
    else
      [$captures | to_entries[] |
        select(.key > $pairs[-1].key and .value.kind == "java" and
          .value.state == "captured") | .value.reference] |
      if length == 0 then "" else .[-1] end
    end
  ' <<<"$index_payload")" || return 1
  if [[ -z "$reference" ]]; then
    jq -cnS '
      {
        schema: "obi-java-bridge-terminal-diagnostics-v1",
        sealed: true,
        available: false,
        reason: "no-valid-snapshot-before-terminal-boundary"
      }
    '
    return $?
  fi
  phase="$(java_diagnostics_reference_phase "$reference")" || return 1
  evidence="$(java_diagnostics_reference_evidence_json "$reference")" || return 1
  jq -cnS --arg phase "$phase" --argjson evidence "$evidence" '
    $evidence + {
      schema: "obi-java-bridge-terminal-diagnostics-v1",
      sealed: true,
      available: true,
      phase: $phase
    }
  '
}

terminal_obi_metrics_payload_from_frozen_index() {
  local freeze_payload=""
  local index_payload=""
  local index_digest=""
  local active_boundary_id=""
  local pair_state=""
  local pair_reference=""
  local pair=""

  if obi_metric_boundary_journal_paths_are_cleanly_absent; then
    jq -cnS '
      {
        schema: "obi-java-remote-parent-terminal-metrics-v1",
        sealed: true,
        available: false,
        reason: "no-valid-pair-before-terminal-boundary"
      }
    '
    return $?
  fi
  freeze_payload="$(obi_metric_boundary_index_freeze_payload)" || return 1
  index_digest="${freeze_payload##*:}"
  if [[ -n "$OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD" ]]; then
    index_payload="$OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD"
  else
    index_payload="$(obi_metric_boundary_index_payload full)" || return 1
  fi
  active_boundary_id="$(jq -r '
    [.boundaries[] | select(.state == "active") | .id] |
    if length == 0 then "" elif length == 1 then .[0]
    else error("multiple active boundaries") end
  ' <<<"$index_payload")" || return 1
  if [[ -z "$active_boundary_id" ]]; then
    jq -cnS \
      --arg index_reference 'obi-metric-boundary-index.json' \
      --arg index_digest "$index_digest" '
        {
          schema: "obi-java-remote-parent-terminal-metrics-v2",
          sealed: true,
          available: false,
          reason: "no-active-boundary",
          active_boundary_id: null,
          boundary_index_reference: $index_reference,
          boundary_index_sha256: $index_digest
        }
      '
    return $?
  fi
  pair_state="$(jq -r --arg boundary_id "$active_boundary_id" '
    [.boundaries[] | select(.id == $boundary_id) | .captures[] |
      select(.kind == "pair") | .state] |
    if length == 0 then "none" else .[-1] end
  ' <<<"$index_payload")" || return 1
  if [[ "$pair_state" != captured ]]; then
    jq -cnS \
      --arg active_boundary_id "$active_boundary_id" \
      --arg index_reference 'obi-metric-boundary-index.json' \
      --arg index_digest "$index_digest" '
        {
          schema: "obi-java-remote-parent-terminal-metrics-v2",
          sealed: true,
          available: false,
          reason: "active-boundary-incomplete",
          active_boundary_id: $active_boundary_id,
          boundary_index_reference: $index_reference,
          boundary_index_sha256: $index_digest
        }
      '
    return $?
  fi
  pair_reference="$(jq -er --arg boundary_id "$active_boundary_id" '
    [.boundaries[] | select(.id == $boundary_id) | .captures[] |
      select(.kind == "pair")][-1].pair_reference
  ' <<<"$index_payload")" || return 1
  pair="$(obi_metric_pair_payload_from_reference "$pair_reference")" || return 1
  jq -cnS \
    --arg active_boundary_id "$active_boundary_id" \
    --arg index_reference 'obi-metric-boundary-index.json' \
    --arg index_digest "$index_digest" \
    --arg pair_reference "$pair_reference" \
    --argjson pair "$pair" '
      {
        schema: "obi-java-remote-parent-terminal-metrics-v2",
        sealed: true,
        available: true,
        active_boundary_id: $active_boundary_id,
        boundary_index_reference: $index_reference,
        boundary_index_sha256: $index_digest,
        pair_reference: $pair_reference,
        pair: $pair
      }
    '
}

validate_terminal_obi_metrics_payload() {
  local -r payload="$1"
  local pair_reference=""
  local expected_pair=""

  if jq -e '
    .schema == "obi-java-remote-parent-terminal-metrics-v2"
  ' <<<"$payload" >/dev/null; then
    if jq -e '
      keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "reason", "schema", "sealed"
      ] and
      .schema == "obi-java-remote-parent-terminal-metrics-v2" and
      .sealed == true and .available == false and
      (.active_boundary_id == null or
        (.active_boundary_id | type == "string" and
          test("^[a-z0-9][a-z0-9-]{0,63}$"))) and
      ((.reason == "no-active-boundary" and .active_boundary_id == null) or
        (.reason == "active-boundary-incomplete" and
          (.active_boundary_id | type == "string"))) and
      .boundary_index_reference == "obi-metric-boundary-index.json" and
      (.boundary_index_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
    ' <<<"$payload" >/dev/null; then
      [[ "$payload" == "$(terminal_obi_metrics_payload_from_frozen_index)" ]] ||
        return 1
      printf '%s\n' "$payload"
      return 0
    fi
    jq -e '
      keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "pair", "pair_reference", "schema", "sealed"
      ] and
      .schema == "obi-java-remote-parent-terminal-metrics-v2" and
      .sealed == true and .available == true and
      (.active_boundary_id | type == "string" and
        test("^[a-z0-9][a-z0-9-]{0,63}$")) and
      .boundary_index_reference == "obi-metric-boundary-index.json" and
      (.boundary_index_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.pair_reference | type == "string") and (.pair | type == "object")
    ' <<<"$payload" >/dev/null || return 1
    [[ "$payload" == "$(terminal_obi_metrics_payload_from_frozen_index)" ]] ||
      return 1
    printf '%s\n' "$payload"
    return 0
  fi
  # Legacy v1 terminals are readable only for pre-journal evidence. A current
  # run with an initialized journal must bind the frozen index through v2.
  obi_metric_boundary_journal_paths_are_cleanly_absent || return 1
  if jq -e '
    keys == ["available", "reason", "schema", "sealed"] and
    .schema == "obi-java-remote-parent-terminal-metrics-v1" and
    .sealed == true and
    .available == false and
    .reason == "no-valid-pair-before-terminal-boundary"
  ' <<<"$payload" >/dev/null; then
    printf '%s\n' "$payload"
    return 0
  fi
  jq -e '
    keys == ["available", "pair", "pair_reference", "schema", "sealed"] and
    .schema == "obi-java-remote-parent-terminal-metrics-v1" and
    .sealed == true and
    .available == true and
    (.pair_reference | type == "string") and
    (.pair | type == "object")
  ' <<<"$payload" >/dev/null || return 1
  pair_reference="$(jq -er '.pair_reference' <<<"$payload")" || return 1
  expected_pair="$(obi_metric_pair_payload_from_reference "$pair_reference")" ||
    return 1
  jq -e --argjson expected_pair "$expected_pair" \
    '.pair == $expected_pair' <<<"$payload" >/dev/null || return 1
  validate_obi_metric_pair_payload "$expected_pair" >/dev/null || return 1
  printf '%s\n' "$payload"
}

validate_terminal_obi_metrics_hardlink_payload() {
  local -r observed_payload="$1"
  local -r expected_payload="$3"

  validate_terminal_obi_metrics_payload "$observed_payload" >/dev/null ||
    return 1
  [[ "$expected_payload" == __any__ ||
    "$observed_payload" == "$expected_payload" ]]
}

normalize_terminal_obi_metrics_residue() {
  local -r expected_payload="$1"
  local allow_h1_cleanup=false

  if [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == true ]]; then
    allow_h1_cleanup=true
  fi
  normalize_terminal_owned_hardlink_family \
    "$RESULT_DIR/terminal-obi-metrics.json" 644 "$OBI_METRIC_PAIR_MAX_BYTES" \
    "$allow_h1_cleanup" "$expected_payload" \
    validate_terminal_obi_metrics_hardlink_payload \
    '^\.terminal-obi-metrics\.[A-Za-z0-9]{6}$' \
    "$RESULT_DIR/.terminal-obi-metrics"
}

terminal_obi_metrics_json() {
  local -r terminal="$RESULT_DIR/terminal-obi-metrics.json"
  local payload=""

  payload="$(read_bounded_single_line_regular_file \
    "$terminal" "$OBI_METRIC_PAIR_MAX_BYTES")" || return 1
  validate_terminal_obi_metrics_payload "$payload"
}

seal_terminal_obi_metrics_unlocked() {
  local -r terminal="$RESULT_DIR/terminal-obi-metrics.json"
  local payload=""

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == true ]] || return 1
  payload="$(terminal_obi_metrics_payload_from_frozen_index)" || return 1
  publish_terminal_owned_hardlink_payload \
    "$terminal" "$RESULT_DIR/.terminal-obi-metrics" \
    '^\.terminal-obi-metrics\.[A-Za-z0-9]{6}$' \
    '^\.terminal-obi-metrics\.[A-Za-z0-9]{6}$' \
    644 "$OBI_METRIC_PAIR_MAX_BYTES" "$payload" \
    validate_terminal_obi_metrics_hardlink_payload true \
    "$RESULT_DIR/.terminal-obi-metrics" || return $?
  [[ "$(terminal_obi_metrics_json)" == "$payload" ]]
}

obi_metric_boundary_index_freeze_payload() {
  local -r freeze="$RESULT_DIR/.obi-metric-boundary-index.freeze"
  local -r index="$RESULT_DIR/obi-metric-boundary-index.json"
  local payload=""
  local expected_digest=""
  local observed_digest=""
  local path=""

  for path in "$RESULT_DIR"/.obi-metric-boundary-index-freeze.*; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
  [[ -f "$freeze" && ! -L "$freeze" &&
    "$(stat -Lc '%u:%a:%h' -- "$freeze")" == "$(id -u):600:1" ]] ||
    return 1
  [[ -f "$index" && ! -L "$index" &&
    "$(stat -Lc '%u:%a:%h' -- "$index")" == "$(id -u):644:1" ]] ||
    return 1
  payload="$(read_bounded_single_line_regular_file "$freeze" 160)" || return 1
  [[ "$payload" =~ ^obi-metric-boundary-index-frozen-v1:([0-9a-f]{64})$ ]] ||
    return 1
  expected_digest="${BASH_REMATCH[1]}"
  observed_digest="$(sha256sum "$(obi_metric_boundary_index_path)")" || return 1
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$expected_digest" ]] || return 1
  if [[ -z "$OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD" ||
    "$OBI_METRIC_BOUNDARY_FROZEN_SHA256" != "$expected_digest" ]]; then
    OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD="$(
      obi_metric_boundary_index_payload full
    )" || return 1
    OBI_METRIC_BOUNDARY_FROZEN_SHA256="$expected_digest"
  fi
  printf '%s\n' "$payload"
}

normalize_obi_metric_boundary_index_freeze_owned_handle() {
  local -r freeze="$RESULT_DIR/.obi-metric-boundary-index.freeze"
  local handle=""
  local path=""
  local freeze_identity=""
  local handle_identity=""
  local removal_status=0
  local attempt=0
  local -a handles=()

  [[ -f "$freeze" && ! -L "$freeze" ]] || return 1
  for path in "$RESULT_DIR"/.obi-metric-boundary-index-freeze.*; do
    [[ -e "$path" || -L "$path" ]] && handles+=("$path")
  done
  ((${#handles[@]} == 1)) || return 1
  handle="${handles[0]}"
  [[ -f "$handle" && ! -L "$handle" && "$handle" -ef "$freeze" ]] ||
    return 1
  freeze_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$freeze")" || return 1
  handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" || return 1
  [[ "$freeze_identity" == "$handle_identity" &&
    "$freeze_identity" == *":$(id -u):600:2" ]] || return 1
  for attempt in 1 2 3; do
    if rm -f -- "$handle"; then
      removal_status=0
      break
    else
      removal_status=$?
    fi
    [[ ! -e "$handle" && ! -L "$handle" ]] && break
    [[ -f "$handle" && ! -L "$handle" && "$handle" -ef "$freeze" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$handle")" == "$freeze_identity" ]] ||
      return 1
  done
  [[ ! -e "$handle" && ! -L "$handle" ]] || return "$removal_status"
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$freeze")" == \
    "${freeze_identity%:2}:1" ]] || return 1
  obi_metric_boundary_index_freeze_payload >/dev/null
}

freeze_obi_metric_boundary_index_unlocked() {
  local -r freeze="$RESULT_DIR/.obi-metric-boundary-index.freeze"
  local index=""
  local index_payload=""
  local digest=""
  local candidate=""
  local candidate_name=""
  local candidate_inode=""
  local candidate_identity=""
  local candidate_digest=""
  local freeze_published=false
  local publication_status=0
  local path=""
  local attempt=0

  index="$(obi_metric_boundary_index_path)" || return 1
  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true ]] || return 1
  obi_metric_capture_stage_paths_are_cleanly_absent || return 1
  normalize_obi_phase_publication_candidates_before_freeze || return $?
  normalize_terminal_java_phase_and_last_candidates_before_freeze || return $?
  # Initialization owns this scratch family under the same journal lock.  It
  # must be normalized before deciding whether the journal is cleanly absent;
  # otherwise an interrupted first plan write can permanently block the
  # deterministic pre-index failure seal.
  normalize_obi_owned_private_candidate_residue \
    "$RESULT_DIR/.obi-metric-boundary-plan" \
    '^\.obi-metric-boundary-plan\.[A-Za-z0-9]{6}$' '^600$' || return $?
  if [[ ! -e "$index" && ! -L "$index" &&
    ! -e "$freeze" && ! -L "$freeze" ]]; then
    # A clean pre-index failure still needs deterministic Java/metric terminal
    # evidence and run-status-v2. Normalize the sole publisher candidate that
    # an interrupted initialization may own, then refuse every other partial
    # journal shape instead of downgrading it to legacy evidence.
    normalize_obi_owned_private_candidate_residue \
      "$RESULT_DIR/.obi-metric-boundary-index" \
      '^\.obi-metric-boundary-index\.[A-Za-z0-9]{6}$' '^(600|644)$' ||
      return 1
    obi_metric_boundary_journal_paths_are_cleanly_absent
    return $?
  fi
  if [[ -e "$freeze" || -L "$freeze" ]]; then
    if obi_metric_boundary_index_freeze_payload >/dev/null; then
      return 0
    fi
    if normalize_obi_metric_boundary_index_freeze_owned_handle; then
      return 0
    fi
    normalize_obi_owned_private_candidate_residue \
      "$RESULT_DIR/.obi-metric-boundary-index-freeze" \
      '^\.obi-metric-boundary-index-freeze\.[A-Za-z0-9]{6}$' '^600$' ||
      return 1
    obi_metric_boundary_index_freeze_payload >/dev/null
    return $?
  fi
  normalize_obi_owned_private_candidate_residue \
    "$RESULT_DIR/.obi-metric-boundary-index-freeze" \
    '^\.obi-metric-boundary-index-freeze\.[A-Za-z0-9]{6}$' '^600$' ||
    return 1
  terminal_java_diagnostics_transition_is_valid || return 1
  # A mutation admitted before the freeze intent can fail before installation
  # and leave its exact private candidate behind. The stable canonical index is
  # still the pre-mutation version, so normalize that owned h1 residue before
  # taking the frozen snapshot.
  normalize_obi_owned_private_candidate_residue \
    "$RESULT_DIR/.obi-metric-boundary-index" \
    '^\.obi-metric-boundary-index\.[A-Za-z0-9]{6}$' '^(600|644)$' || return 1
  normalize_obi_metric_pair_candidate_residue || return 1
  for path in \
    "$RESULT_DIR"/.obi-metric-boundary-index.* \
    "$RESULT_DIR"/.obi-metric-boundary-index-backup.* \
    "$RESULT_DIR"/.obi-metric-boundary-index-restore.* \
    "$RESULT_DIR"/.obi-metric-boundary-index-freeze.*; do
    if [[ ( -e "$path" || -L "$path" ) && "$path" != "$freeze" ]]; then
      return 1
    fi
  done
  [[ -f "$index" && ! -L "$index" &&
    "$(stat -Lc '%u:%a:%h' -- "$index")" == "$(id -u):644:1" ]] ||
    return 1
  index_payload="$(obi_metric_boundary_index_payload full)" || return 1
  digest="$(sha256sum "$index")" || return 1
  digest="${digest%% *}"
  OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD="$index_payload"
  OBI_METRIC_BOUNDARY_FROZEN_SHA256="$digest"
  if candidate="$(mktemp \
    "$RESULT_DIR/.obi-metric-boundary-index-freeze.XXXXXX")"; then
    :
  else
    publication_status=$?
    candidate_name="${candidate##*/}"
    if [[ "${candidate%/*}" != "$RESULT_DIR" ||
      ! "$candidate_name" =~ ^\.obi-metric-boundary-index-freeze\.[A-Za-z0-9]{6}$ ||
      ! -f "$candidate" || -L "$candidate" ]]; then
      return "$publication_status"
    fi
    for attempt in 1 2 3; do
      candidate_inode="$(stat -Lc '%d:%i:%u' -- "$candidate")" && break
    done
    [[ -n "$candidate_inode" ]] || return "$publication_status"
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || return 1
    return "$publication_status"
  fi
  candidate_name="${candidate##*/}"
  [[ "${candidate%/*}" == "$RESULT_DIR" &&
    "$candidate_name" =~ ^\.obi-metric-boundary-index-freeze\.[A-Za-z0-9]{6}$ &&
    -f "$candidate" && ! -L "$candidate" ]] || return 1
  for attempt in 1 2 3; do
    candidate_inode="$(stat -Lc '%d:%i:%u' -- "$candidate")" && break
  done
  [[ -n "$candidate_inode" &&
    "$(stat -Lc '%d:%i:%u:%h' -- "$candidate")" == "$candidate_inode:1" ]] ||
    return 1
  if printf 'obi-metric-boundary-index-frozen-v1:%s\n' "$digest" >"$candidate" &&
    chmod 0600 -- "$candidate"; then
    :
  else
    publication_status=$?
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || return 1
    return "$publication_status"
  fi
  candidate_identity=""
  for attempt in 1 2 3; do
    candidate_identity="$(stat -Lc '%d:%i:%u:%a' -- "$candidate")" && break
  done
  if [[ "$candidate_identity" != "$candidate_inode:600" ]]; then
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || return 1
    return 1
  fi
  candidate_digest=""
  for attempt in 1 2 3; do
    if candidate_digest="$(sha256sum "$candidate")"; then
      break
    fi
    candidate_digest=""
  done
  if [[ -z "$candidate_digest" ]]; then
    remove_obi_owned_private_path_by_inode \
      "$candidate" "$candidate_inode" || return 1
    return 1
  fi
  candidate_digest="${candidate_digest%% *}"
  if ln -T -- "$candidate" "$freeze"; then
    freeze_published=true
  else
    publication_status=$?
    if [[ -f "$freeze" && ! -L "$freeze" && "$candidate" -ef "$freeze" ]] &&
      obi_owned_publication_matches \
        "$freeze" "$candidate_identity" "$candidate_digest" 2; then
      freeze_published=true
    fi
  fi
  if [[ "$freeze_published" == false ]]; then
    remove_obi_owned_private_file \
      "$candidate" "$candidate_identity" "$candidate_digest" || return 1
    return "$publication_status"
  fi
  for attempt in 1 2 3; do
    obi_owned_publication_matches \
      "$freeze" "$candidate_identity" "$candidate_digest" 2 && break
  done
  obi_owned_publication_matches \
    "$freeze" "$candidate_identity" "$candidate_digest" 2 || return 1
  for attempt in 1 2 3; do
    if rm -f -- "$candidate"; then
      publication_status=0
      break
    else
      publication_status=$?
    fi
    [[ ! -e "$candidate" && ! -L "$candidate" ]] && break
    obi_owned_publication_matches \
      "$freeze" "$candidate_identity" "$candidate_digest" 2 || return 1
  done
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    return "$publication_status"
  fi
  obi_owned_publication_matches \
    "$freeze" "$candidate_identity" "$candidate_digest" 1 || return 1
  obi_metric_boundary_index_freeze_payload >/dev/null
}

terminal_java_diagnostics_freeze_is_valid_unlocked() {
  [[ "$(terminal_java_diagnostics_transition_state_unlocked)" == frozen ]]
}

terminal_java_diagnostics_freeze_is_valid() {
  with_terminal_java_diagnostics_transition_publication_lock \
    terminal_java_diagnostics_freeze_is_valid_unlocked
}

freeze_terminal_java_diagnostics_publication_unlocked() {
  local -r freeze="$RESULT_DIR/.terminal-java-diagnostics.freeze"
  local -r payload="terminal-java-diagnostics-frozen-v1"

  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    "${TERMINAL_TRANSITION_PUBLICATION_LOCK_HELD_BY_CALLER:-false}" == true ]] ||
    return 1
  normalize_terminal_java_diagnostics_transition_residue_unlocked || return $?
  if [[ -e "$freeze" || -L "$freeze" ]]; then
    return 0
  fi
  publish_terminal_owned_hardlink_payload \
    "$freeze" "$RESULT_DIR/.terminal-java-diagnostics-freeze" \
    '^\.terminal-java-diagnostics-freeze\.[A-Za-z0-9]{6}$' \
    '^\.terminal-java-diagnostics-(freeze|recovery-commit)\.[A-Za-z0-9]{6}$' \
    600 160 "$payload" \
    validate_terminal_java_diagnostics_transition_hardlink_payload true \
    "$RESULT_DIR/.terminal-java-diagnostics-freeze" \
    "$RESULT_DIR/.terminal-java-diagnostics-recovery-commit"
}

freeze_terminal_java_diagnostics_unlocked() {
  with_terminal_java_diagnostics_transition_publication_lock \
    freeze_terminal_java_diagnostics_publication_unlocked
}

freeze_terminal_java_diagnostics() {
  # Publish the freeze before waiting for the advisory lock. If an earlier
  # record currently owns the lock, it is linearized before this boundary and
  # the lock wait drains it. If the bounded wait fails, the durable freeze still
  # prevents recovery from publishing a later snapshot as the failed boundary.
  freeze_terminal_java_diagnostics_unlocked || return $?
  with_obi_metric_capture_stage_lock \
    normalize_obi_metric_capture_stage_residue || return $?
  with_terminal_java_diagnostics_lock \
    freeze_terminal_evidence_indexes_unlocked
}

freeze_terminal_evidence_indexes_unlocked() {
  freeze_terminal_java_diagnostics_unlocked || return $?
  freeze_obi_metric_boundary_index_unlocked
}

seal_terminal_java_diagnostics_unlocked() {
  local -r terminal="$RESULT_DIR/terminal-java-diagnostics.json"
  local -r last="$RESULT_DIR/.last-valid-java-diagnostics.json"
  local recovery_boundary="${1:-}"
  local boundary_is_explicit=false
  local journal_boundary_payload=""
  local payload=""

  (($# <= 2)) || return 1
  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == true ]] || return 1
  journal_boundary_payload="$(
    terminal_java_diagnostics_payload_from_frozen_index
  )" || return 1
  if [[ "$journal_boundary_payload" != null ]]; then
    recovery_boundary="$journal_boundary_payload"
    boundary_is_explicit=true
  elif (($# >= 1)); then
    boundary_is_explicit=true
  fi
  freeze_terminal_java_diagnostics_unlocked || return $?
  if [[ "$boundary_is_explicit" == true &&
    "$journal_boundary_payload" != null ]]; then
    payload="$journal_boundary_payload"
  elif [[ "$boundary_is_explicit" == true && "$recovery_boundary" != null ]]; then
    payload="$(validate_last_java_diagnostics_payload_structure \
      "$recovery_boundary")" ||
      return 1
    payload="$(jq -c '.sealed = true' <<<"$payload")" || return 1
  elif [[ "$boundary_is_explicit" == true ]]; then
    payload="$(jq -cn '
      {
        schema: "obi-java-bridge-terminal-diagnostics-v1",
        sealed: true,
        available: false,
        reason: "no-valid-snapshot-before-terminal-boundary"
      }
    ')" || return 1
  elif [[ -e "$last" || -L "$last" ]]; then
    payload="$(validate_last_java_diagnostics_json "$last")" || return 1
    payload="$(jq -c '.sealed = true' <<<"$payload")" || return 1
  else
    payload="$(jq -cn '
      {
        schema: "obi-java-bridge-terminal-diagnostics-v1",
        sealed: true,
        available: false,
        reason: "no-valid-snapshot-before-terminal-boundary"
      }
    ')" || return 1
  fi
  publish_terminal_owned_hardlink_payload \
    "$terminal" "$RESULT_DIR/.terminal-java-diagnostics-output" \
    '^\.terminal-java-diagnostics-output\.[A-Za-z0-9]{6}$' \
    '^\.terminal-java-diagnostics-output\.[A-Za-z0-9]{6}$' \
    644 "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" "$payload" \
    validate_terminal_java_diagnostics_hardlink_payload true \
    "$RESULT_DIR/.terminal-java-diagnostics-output" || return $?
  [[ "$(terminal_java_diagnostics_json)" == "$payload" ]] || return 1
  seal_terminal_obi_metrics_unlocked
}

seal_terminal_java_diagnostics_from_recovery_state_unlocked() {
  local -r boundary="$RESULT_DIR/.terminal-java-diagnostics-recovery-boundary.json"
  local transition_state=""
  local recovery_boundary=""
  local metric_recovery_boundary=""

  normalize_terminal_java_diagnostics_recovery_boundary_residue __any__ ||
    return $?
  transition_state="$(terminal_java_diagnostics_transition_state)" || return $?
  if [[ "$transition_state" == "committed" ]]; then
    terminal_java_diagnostics_recovery_commit_is_valid || return $?
    seal_terminal_java_diagnostics_unlocked
    return $?
  fi
  if [[ -e "$boundary" || -L "$boundary" ]]; then
    recovery_boundary="$(
      terminal_java_diagnostics_recovery_boundary_payload
    )" || return $?
    metric_recovery_boundary="$(
      terminal_obi_metric_recovery_boundary_payload
    )" || return $?
    seal_terminal_java_diagnostics_unlocked \
      "$recovery_boundary" "$metric_recovery_boundary"
    return $?
  fi
  seal_terminal_java_diagnostics_unlocked
}

seal_terminal_evidence_from_recovery_state_unlocked() {
  freeze_terminal_java_diagnostics_unlocked || return $?
  freeze_obi_metric_boundary_index_unlocked || return $?
  seal_terminal_java_diagnostics_from_recovery_state_unlocked
}

seal_terminal_java_diagnostics() {
  # The freeze must survive a bounded lock-acquisition failure. Records check
  # it both before validation and immediately before publication, while the
  # lock orders any record that was already in flight ahead of this seal.
  freeze_terminal_java_diagnostics_unlocked || return $?
  with_obi_metric_capture_stage_lock \
    normalize_obi_metric_capture_stage_residue || return $?
  with_terminal_java_diagnostics_lock \
    seal_terminal_evidence_from_recovery_state_unlocked
}

background_process_is_running() {
  local -r process_pid="$1"
  local state=""

  [[ "$process_pid" =~ ^[1-9][0-9]*$ && -r "/proc/$process_pid/stat" ]] || return 1
  state="$(sed -E 's/^[0-9]+ \(.*\) ([A-Z]) .*/\1/' "/proc/$process_pid/stat" 2>/dev/null)" || return 1
  [[ "$state" =~ ^[A-Z]$ && "$state" != "Z" ]]
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

wait_for_unix_security_namespace_pid() {
  local -r java_container="$1"
  local -r pid_path="$2"
  local candidate=""
  local -i started_at="$SECONDS"

  [[ "$pid_path" =~ ^/tmp/obi-unix-security\.[[:alnum:]]{6,}/security-probe\.pid$ ]] || {
    log_error "refusing an unsafe Unix security probe PID path"
    return 1
  }
  while ((SECONDS - started_at < READINESS_TIMEOUT_SECONDS)); do
    candidate="$(run_bounded 5 docker exec "$java_container" \
      cat -- "$pid_path" 2>/dev/null || true)"
    if [[ "$candidate" =~ ^[1-9][0-9]*$ ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    sleep 0.1
  done
  log_error "timed out waiting for the same-cgroup Unix security probe PID"
  return 1
}

assert_unix_security_cgroup_identity() {
  local -r java_cgroup="$1"
  local -r probe_cgroup="$2"
  local -r probe_status="$3"

  [[ -n "$java_cgroup" && -n "$probe_cgroup" && -n "$probe_status" ]] || {
    log_error "Unix same-cgroup security identity evidence was empty"
    return 1
  }
  [[ "$java_cgroup" == "$probe_cgroup" ]] || {
    log_error "Unix security probe did not share the Java container cgroup"
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
    $1 == "CapEff:" {
      found_cap_eff = 1
      if (NF != 2 || $2 != "0000000000000000") {
        failed = 1
      }
    }
    END {
      exit failed || !found_uid || !found_gid || !found_cap_eff ? 1 : 0
    }
  ' <<<"$probe_status" || {
    log_error "Unix security probe did not run as capability-free 65534:65534"
    return 1
  }
}

assert_unix_security_pid_namespace_identity() {
  local -r status_snapshot="$1"
  local -r probe_pid="$2"

  [[ "$probe_pid" =~ ^[1-9][0-9]*$ && "$probe_pid" != "1" ]] || return 1
  awk \
    -v separator="$UNIX_SECURITY_STATUS_SEPARATOR" \
    -v expected_probe_pid="$probe_pid" '
    function valid_namespace_pid(value) {
      return value ~ /^[1-9][0-9]*$/
    }
    function same_namespace_pid(left, right, character_index) {
      if (length(left) != length(right)) {
        return 0
      }
      for (character_index = 1; character_index <= length(left); character_index++) {
        if (substr(left, character_index, 1) != substr(right, character_index, 1)) {
          return 0
        }
      }
      return 1
    }
    $0 == separator {
      section++
      if (section > 2) {
        invalid = 1
      }
      next
    }
    section == 0 || section > 2 {
      invalid = 1
      next
    }
    section == 1 && $1 == "Pid:" {
      java_pid_count++
      if (NF != 2 || !valid_namespace_pid($2) || $2 != "1") {
        invalid = 1
      }
      next
    }
    section == 1 && $1 == "NSpid:" {
      java_nspid_count++
      if (NF != 2 || !valid_namespace_pid($2) || $2 != "1") {
        invalid = 1
      }
      next
    }
    section == 2 && $1 == "Pid:" {
      probe_pid_count++
      if (NF != 2 || !valid_namespace_pid($2) ||
        !same_namespace_pid($2, expected_probe_pid)) {
        invalid = 1
      }
      next
    }
    section == 2 && $1 == "NSpid:" {
      probe_nspid_count++
      if (NF != 2 || !valid_namespace_pid($2) ||
        !same_namespace_pid($2, expected_probe_pid)) {
        invalid = 1
      }
      next
    }
    END {
      exit invalid || section != 2 || java_pid_count != 1 ||
        java_nspid_count != 1 || probe_pid_count != 1 ||
        probe_nspid_count != 1 ? 1 : 0
    }
  ' <<<"$status_snapshot"
}

capture_unix_security_pid_namespace_status() {
  local -r java_container="$1"
  local -r probe_pid="$2"

  [[ "$probe_pid" =~ ^[1-9][0-9]*$ && "$probe_pid" != "1" ]] || return 1
  # The namespace link for an unprivileged peer is ptrace-gated on hardened
  # kernels. Validate both statuses from Java's private /proc view instead;
  # a sibling is invisible and a child namespace has an additional NSpid value.
  # Suppress proc-race diagnostics because they include the transient PID.
  # Expanded by the container shell, not this process.
  # shellcheck disable=SC2016
  run_bounded 10 docker exec "$java_container" /bin/sh -ec '
    set -eu
    case "$1" in
      ""|*[!0-9]*|0|1) exit 1 ;;
    esac
    process_name="$(cat /proc/1/comm 2>/dev/null)"
    thread_name="$(cat /proc/1/task/1/comm 2>/dev/null)"
    probe_name="$(cat "/proc/$1/comm" 2>/dev/null)"
    [ "$process_name" = java ]
    [ "$thread_name" = java ]
    [ "$probe_name" = security-probe ]
    printf "%s\\n" "$2"
    cat /proc/1/status 2>/dev/null
    printf "%s\\n" "$2"
    cat "/proc/$1/status" 2>/dev/null
  ' sh "$probe_pid" "$UNIX_SECURITY_STATUS_SEPARATOR" 2>/dev/null
}

assert_unix_sibling_security_options() {
  local -r security_options="$1"

  jq -e '
    type == "array" and
    length == 1 and
    .[0] == "no-new-privileges:true"
  ' <<<"$security_options" >/dev/null
}

assert_unix_sibling_tmpfs() {
  local -r tmpfs="$1"

  jq -e '
    . == null or
    (type == "object" and length == 0)
  ' <<<"$tmpfs" >/dev/null
}

assert_unix_sibling_security_topology() {
  local -r java_container="$1"
  local -r sibling_container="$2"
  local -r output="$3"
  local user=""
  local network_mode=""
  local pid_mode=""
  local java_pid_mode=""
  local read_only_rootfs=""
  local privileged=""
  local cap_drop=""
  local cap_add=""
  local security_options=""
  local mounts=""
  local tmpfs=""
  local java_host_pid=""
  local sibling_host_pid=""
  local java_cgroup=""
  local sibling_cgroup=""
  local java_pid_namespace=""
  local sibling_pid_namespace=""
  local pid_namespace_evidence=""

  user="$(run_bounded 10 docker inspect --format '{{.Config.User}}' \
    "$sibling_container")" || return $?
  network_mode="$(run_bounded 10 docker inspect --format '{{.HostConfig.NetworkMode}}' \
    "$sibling_container")" || return $?
  pid_mode="$(run_bounded 10 docker inspect --format '{{.HostConfig.PidMode}}' \
    "$sibling_container")" || return $?
  java_pid_mode="$(run_bounded 10 docker inspect --format '{{.HostConfig.PidMode}}' \
    "$java_container")" || return $?
  read_only_rootfs="$(run_bounded 10 docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' \
    "$sibling_container")" || return $?
  privileged="$(run_bounded 10 docker inspect --format '{{.HostConfig.Privileged}}' \
    "$sibling_container")" || return $?
  cap_drop="$(run_bounded 10 docker inspect --format '{{json .HostConfig.CapDrop}}' \
    "$sibling_container")" || return $?
  cap_add="$(run_bounded 10 docker inspect --format '{{json .HostConfig.CapAdd}}' \
    "$sibling_container")" || return $?
  security_options="$(run_bounded 10 docker inspect \
    --format '{{json .HostConfig.SecurityOpt}}' "$sibling_container")" || return $?
  mounts="$(run_bounded 10 docker inspect --format '{{json .Mounts}}' \
    "$sibling_container")" || return $?
  tmpfs="$(run_bounded 10 docker inspect --format '{{json .HostConfig.Tmpfs}}' \
    "$sibling_container")" || return $?
  [[ "$user" == "65534:65534" && "$network_mode" == "none" && -z "$pid_mode" && \
    -z "$java_pid_mode" && \
    "$read_only_rootfs" == "true" && "$privileged" == "false" && \
    "$cap_drop" == *'"ALL"'* && \
    ( "$cap_add" == "null" || "$cap_add" == "[]" ) ]] || {
    log_error "Unix sibling security probe did not preserve its least-privilege topology"
    return 1
  }
  assert_unix_sibling_security_options "$security_options" || {
    log_error "Unix sibling security probe did not retain exactly no-new-privileges:true"
    return 1
  }
  assert_unix_sibling_tmpfs "$tmpfs" || {
    log_error "Unix sibling security probe unexpectedly configured writable tmpfs storage"
    return 1
  }
  jq -e '
    type == "array" and length == 1 and
    .[0].Type == "volume" and
    .[0].Destination == "/var/run/obi" and
    .[0].RW == false
  ' <<<"$mounts" >/dev/null || {
    log_error "Unix sibling security probe did not have exactly one read-only socket volume"
    return 1
  }

  java_host_pid="$(run_bounded 10 docker inspect --format '{{.State.Pid}}' \
    "$java_container")" || return $?
  sibling_host_pid="$(run_bounded 10 docker inspect --format '{{.State.Pid}}' \
    "$sibling_container")" || return $?
  if [[ ! "$java_host_pid" =~ ^[1-9][0-9]*$ || \
    ! "$sibling_host_pid" =~ ^[1-9][0-9]*$ || \
    ! -r "/proc/$java_host_pid/cgroup" || ! -r "/proc/$sibling_host_pid/cgroup" ]]; then
    log_error "could not resolve host topology for the Java and Unix sibling containers"
    return 1
  fi
  java_cgroup="$(<"/proc/$java_host_pid/cgroup")"
  sibling_cgroup="$(<"/proc/$sibling_host_pid/cgroup")"
  [[ "$java_cgroup" != "$sibling_cgroup" ]] || {
    log_error "Unix sibling security probe unexpectedly shared the Java container cgroup"
    return 1
  }
  java_pid_namespace="$(readlink "/proc/$java_host_pid/ns/pid" 2>/dev/null || true)"
  sibling_pid_namespace="$(readlink "/proc/$sibling_host_pid/ns/pid" 2>/dev/null || true)"
  if [[ -n "$java_pid_namespace" || -n "$sibling_pid_namespace" ]]; then
    [[ -n "$java_pid_namespace" && -n "$sibling_pid_namespace" && \
      "$java_pid_namespace" != "$sibling_pid_namespace" ]] || {
      log_error "Unix sibling security probe did not remain in a distinct host-observed PID namespace"
      return 1
    }
    pid_namespace_evidence="host-proc"
  else
    # Docker's empty PidMode is the engine's private-namespace contract. Some
    # hardened hosts intentionally deny host-side /proc/<pid>/ns dereferences.
    pid_namespace_evidence="docker-private"
  fi

  {
    printf 'peer_user=65534:65534\n'
    printf 'network_mode=none\n'
    printf 'pid_namespace_shared=false\n'
    printf 'pid_namespace_evidence=%s\n' "$pid_namespace_evidence"
    printf 'cgroup_match=false\n'
    printf 'readonly_rootfs=true\n'
    printf 'privileged=false\n'
    printf 'cap_drop_all=true\n'
    printf 'cap_add_empty=true\n'
    printf 'no_new_privileges=true\n'
    printf 'tmpfs_empty=true\n'
    printf 'mount_count=1\n'
    printf 'socket_mount_type=volume\n'
    printf 'socket_mount_writable=false\n'
  } >"$output"
}

assert_unix_abuse_race_output() {
  local -r output="$1"
  local -r require_live_java_forgery="${2:-}"
  local result=""

  [[ "$require_live_java_forgery" == "true" || \
    "$require_live_java_forgery" == "false" ]] || {
    log_error "Unix abuse-race result requires an explicit live-Java-forgery policy"
    return 1
  }
  result="$(grep -E '^\{"status":' "$output" || true)"
  [[ "$(wc -l <<<"$result")" == "1" ]] || {
    log_error "Unix security probe did not emit exactly one result record"
    return 1
  }
  jq -e --argjson require_live_java_forgery "$require_live_java_forgery" '
    .status == "passed" and .mode == "abuse-race" and
    (.attempts | type == "number" and . >= 1) and
    (.cases | type == "array") and
    (
      (
        [
          {"name":"peer-identity","outcome":"unauthorized"},
          {"name":"forged-identity","outcome":"unauthorized"}
        ] +
        (if $require_live_java_forgery then
          [{"name":"forged-live-java-tid","outcome":"unauthorized"}]
        else
          []
        end) +
        [
          {"name":"malformed","outcome":"malformed"},
          {"name":"truncated","outcome":"malformed"},
          {"name":"version-mismatch","outcome":"version_mismatch"},
          {"name":"oversized","outcome":"unauthorized"},
          {"name":"repeated-frame","outcome":"unauthorized"},
          {"name":"repeated-unauthorized","outcome":"bounded"},
          {"name":"high-rate-admission","outcome":"overload-and-recovery"},
          {"name":"concurrent-repeated-unauthorized","outcome":"bounded"}
        ]
      ) as $expected |
      .cases == $expected
    )
  ' <<<"$result" >/dev/null || {
    log_error "Unix abuse-race probe did not emit the exact bounded denial cases"
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
  local -r same_cgroup_delta="$RESULT_DIR/phases/security-primary-probe-ready/obi-metrics.delta"
  local host_probe=""
  local java_container=""
  local java_host_pid=""
  local sibling_host_pid=""
  local same_cgroup_exit=0
  local sibling_exit=""
  local network_mode=""
  local pid_mode=""
  local cgroup_comparison_status=0
  local run_number=0
  local phase_label=""

  [[ "$SELECTED_TRANSPORT" == "getsockopt" ]] || {
    log_error "the primary security control requires the selected getsockopt transport"
    return 1
  }
  plan_obi_metric_pair_capture security-primary-sibling || return $?
  plan_obi_metric_pair_capture security-primary-same-cgroup || return $?

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
  else
    cgroup_comparison_status=$?
  fi
  if ((cgroup_comparison_status != 1)); then
    log_error "could not compare Java and sibling container cgroups"
    return "$cgroup_comparison_status"
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
  assert_primary_security_metric_delta "$sibling_delta" negotiate 1 1
  assert_primary_security_metric_delta "$sibling_delta" take 5
  record_obi_metric_pair \
    security-primary-sibling security-primary-before \
    security-primary-sibling-ready same_process "" >/dev/null || return $?

  host_probe="$(mktemp "$RESULT_DIR/.security-primary-probe.XXXXXX")"
  PRIMARY_SECURITY_HOST_PROBE="$host_probe"
  run_bounded 15 docker cp \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER:/security-probe" "$host_probe"

  run_bounded 15 docker kill --signal SIGUSR1 \
    "$PRIMARY_SECURITY_SIBLING_CONTAINER" >/dev/null
  sibling_exit="$(run_bounded 60 docker wait "$PRIMARY_SECURITY_SIBLING_CONTAINER")"
  [[ "$sibling_exit" == "0" ]] || {
    log_error "sibling security probe exited with status $sibling_exit"
    return 1
  }
  run_bounded 15 "${COMPOSE[@]}" logs --no-color security-probe >"$sibling_output"
  PRIMARY_SECURITY_SIBLING_CONTAINER=""
  if ! grep -Fq '"status":"unverified","mode":"primary"' "$sibling_output" || \
    ! grep -Eq '"attempts":[1-9][0-9]*' "$sibling_output" || \
    ! grep -Fq '"name":"wrong-process-negotiation","outcome":"native-unsupported"' \
      "$sibling_output" || \
    ! grep -Fq '"name":"repeated-retrieval","outcome":"native-unsupported"' \
      "$sibling_output"; then
    log_error "sibling security probe did not emit honest native-result evidence"
    return 1
  fi
  if ! wait_for_primary_security_metrics_quiescent \
    "$RESULT_DIR/metrics-security-primary-sibling-complete.prom" \
    "sibling-container security probe completion"; then
    return 1
  fi
  if ! capture_metric_phase_evidence "security-primary-sibling-complete"; then
    return 1
  fi

  PRIMARY_SECURITY_JAVA_CONTAINER="$java_container"
  run_bounded 10 docker exec "$java_container" \
    rm -f -- "$PRIMARY_SECURITY_PROBE_PATH" "$PRIMARY_SECURITY_PID_PATH"
  run_bounded 15 docker cp "$host_probe" \
    "$java_container:$PRIMARY_SECURITY_PROBE_PATH"
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
    "$RESULT_DIR/phases/security-primary-sibling-complete/obi-metrics.prom" \
    "$RESULT_DIR/phases/security-primary-probe-ready/obi-metrics.prom" \
    "$same_cgroup_delta"
  assert_primary_security_metric_delta "$same_cgroup_delta" negotiate 1 1
  assert_primary_security_metric_delta "$same_cgroup_delta" take 5
  record_obi_metric_pair \
    security-primary-same-cgroup security-primary-sibling-complete \
    security-primary-probe-ready same_process "" >/dev/null || return $?

  (
    SCENARIO_VARIANT="security-primary-victim"
    ALLOW_PRIMARY_SECURITY_METRICS=true
    run_scenario concurrency false metrics
  )

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
  if ! grep -Fq '"status":"unverified","mode":"primary"' "$same_cgroup_output" || \
    ! grep -Eq '"attempts":[1-9][0-9]*' "$same_cgroup_output" || \
    ! grep -Fq '"name":"repeated-retrieval","outcome":"native-unsupported"' \
      "$same_cgroup_output"; then
    log_error "same-cgroup primary security probe did not emit bounded native-result evidence"
    return 1
  fi

  run_bounded 10 docker exec "$java_container" \
    rm -f -- "$PRIMARY_SECURITY_PROBE_PATH" "$PRIMARY_SECURITY_PID_PATH"
  PRIMARY_SECURITY_JAVA_CONTAINER=""
  capture_java_diagnostics "security-primary-diagnostics-after"
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/security-primary-diagnostics-after/java-diagnostics.txt"

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  (
    SCENARIO_VARIANT="security-primary-recovery"
    run_scenario basic false
  )
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  clear_terminal_java_diagnostics_recovery_boundary || return $?
  # Keep this as a simple command: a conditional call would suppress errexit
  # inside the nested fault-control subshell.
  run_primary_live_fd_security_control "$host_probe"
  rm -f -- "$host_probe" || return $?
  host_probe=""
  PRIMARY_SECURITY_HOST_PROBE=""
  printf '{"status":"passed","scenario":"security","mode":"primary","same_cgroup_probe":"%s","sibling_probe":"%s","live_descriptor_probe":"metrics_verified","live_descriptor_topology":"pid1-cgroup-verified-preexec","probe_status":"unverified","probe_verification":"metrics_verified","cgroup_match":true,"unauthorized_classification":"metrics_verified","post_abuse_recovery":"passed","unix_only_cases":"not_applicable"}\n' \
    "$(basename -- "$same_cgroup_output")" \
    "$(basename -- "$sibling_output")" \
    >"$RESULT_DIR/scenario-security-status.json"
  crosslink_and_bind_active_obi_metric_boundary_status \
    scenario-security-status.json || return $?
}

run_unix_permissive_directory_control() {
  local -r response_body="$RESULT_DIR/security-permissive-directory-response.json"
  local -r response_status="$RESULT_DIR/security-permissive-directory-response.status"
  local -r mode_evidence="$RESULT_DIR/security-permissive-directory-mode.txt"
  local -r obi_log="$RESULT_DIR/security-permissive-directory-obi.log"
  local failure_since=""
  local recovery_since=""
  local socket_status=0

  plan_obi_metric_pair_capture security-unix-permissive-refusal || return $?
  plan_obi_metric_pair_capture security-unix-permissive-recovery || return $?
  capture_phase_evidence security-unix-permissive-before || return $?
  log_info "proving the Unix bridge refuses a world-accessible socket directory"
  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  run_bounded "$OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" stop --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || \
    return $?
  OBI_RUNNING=false
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    chmod 0777 /var/run/obi || return $?
  UNIX_SECURITY_DIRECTORY_RELAXED=true
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    /bin/sh -ec 'ls -ld /var/run/obi' >"$mode_evidence" || return $?
  grep -Eq '^drwxrwxrwx' "$mode_evidence" || {
    log_error "could not prove the Unix socket directory was made world accessible"
    return 1
  }

  failure_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  run_bounded 60 \
    "${COMPOSE[@]}" up --detach \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" \
      --no-deps --force-recreate obi || return $?
  OBI_RUNNING=true
  wait_for_log \
    obi \
    "$UNIX_PERMISSION_REFUSAL_PATTERN" \
    "permissive Unix directory refusal" \
    "$failure_since" || return $?
  if run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    /bin/sh -ec 'test -S /var/run/obi/java-remote-parent.sock'; then
    log_error "Unix bridge created a socket in a permissive directory"
    return 1
  else
    socket_status=$?
  fi
  if ((socket_status != 1)); then
    log_error "could not verify Unix bridge socket absence in the permissive directory"
    return "$socket_status"
  fi

  curl --fail --silent --show-error --max-time 10 \
    --header 'x-obi-demo-id: security-permissive-directory' \
    --output "$response_body" \
    --write-out '%{http_code}\n' \
    "http://127.0.0.1:18080/api/echo?close=1" \
    >"$response_status" || return $?
  if [[ "$(<"$response_status")" != "200" ]] || \
    ! grep -Fq '"marker":"security-permissive-directory"' "$response_body"; then
    log_error "application traffic did not fail open while the Unix directory was rejected"
    return 1
  fi
  run_bounded 15 "${COMPOSE[@]}" logs --no-color --since "$failure_since" \
    obi >"$obi_log" || return $?
  capture_phase_evidence security-unix-permissive-fault || return $?
  record_obi_metric_pair \
    security-unix-permissive-refusal security-unix-permissive-before \
    security-unix-permissive-fault process_replaced "" >/dev/null || return $?

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  run_bounded "$OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" stop --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || \
    return $?
  OBI_RUNNING=false
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    chmod 0750 /var/run/obi || return $?
  run_bounded 10 "${COMPOSE[@]}" exec --no-TTY java-backend \
    /bin/sh -ec 'ls -ld /var/run/obi' >>"$mode_evidence" || return $?
  tail -n 1 "$mode_evidence" | grep -Eq '^drwxr-x---' || {
    log_error "could not prove the Unix socket directory permissions were restored"
    return 1
  }
  UNIX_SECURITY_DIRECTORY_RELAXED=false
  recovery_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  run_bounded 60 \
    "${COMPOSE[@]}" up --detach \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" \
      --no-deps --force-recreate obi || return $?
  OBI_RUNNING=true
  wait_for_log \
    obi \
    "Java remote parent bridge ready" \
    "post-permission Unix bridge recovery" \
    "$recovery_since" || return $?
  BRIDGE_RUNNING=true
  wait_for_apache_instrumentation unix-permission-recovery || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "post-permission Java provider probe" || return $?
  sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return $?
  wait_for_java_duplicate_suppression \
    "$RESULT_DIR/duplicate-suppression-unix-permission-recovery.prom" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "post-permission Java bridge provider" \
    "$recovery_since" || return $?
  assert_selected_transport || return $?
  [[ "$SELECTED_TRANSPORT" == "unix" ]] || {
    log_error "post-permission recovery did not restore the Unix transport"
    return 1
  }
  BRIDGE_RUNNING=true
  capture_phase_evidence security-unix-permissive-after || return $?
  record_obi_metric_pair \
    security-unix-permissive-recovery security-unix-permissive-fault \
    security-unix-permissive-after process_replaced "" >/dev/null || return $?
}

run_unix_sibling_security_control() {
  local -r java_container="$1"
  local -r output="$RESULT_DIR/security-unix-sibling.log"
  local -r topology="$RESULT_DIR/security-unix-sibling-topology.txt"
  local -r before_metrics="$RESULT_DIR/metrics-security-unix-sibling-before.prom"
  local -r after_metrics="$RESULT_DIR/metrics-security-unix-sibling-complete.prom"
  local -r metric_delta="$RESULT_DIR/metrics-security-unix-sibling.delta"
  local host_probe=""
  local probe_exit=""
  local running=""
  local scenario_status=0
  local inspect_status=0
  local release_status=0
  local wait_status=0
  local log_status=0
  local output_status=0
  local metric_status=0
  local current_metric_status=0
  local probe_window_valid=true
  local run_number=0
  local phase_label=""

  if ! wait_for_unix_security_metrics_quiescent \
    "$before_metrics" \
    "Unix sibling security probe baseline"; then
    return 1
  fi
  log_info "starting an isolated non-root Unix abuse race"
  run_bounded 60 \
    "${COMPOSE[@]}" up --detach --no-deps --force-recreate \
    security-unix-sibling-probe || return $?
  UNIX_SECURITY_SIBLING_CONTAINER="$(run_bounded 10 \
    "${COMPOSE[@]}" ps --all --quiet security-unix-sibling-probe)"
  [[ -n "$UNIX_SECURITY_SIBLING_CONTAINER" ]] || {
    log_error "could not resolve the Unix sibling abuse-race container"
    return 1
  }
  wait_for_log \
    security-unix-sibling-probe \
    "security probe abuse race ready" \
    "Unix sibling abuse race barrier" || return $?
  assert_unix_sibling_security_topology \
    "$java_container" "$UNIX_SECURITY_SIBLING_CONTAINER" "$topology" || return $?

  host_probe="$(mktemp "$RESULT_DIR/.security-unix-probe.XXXXXX")" || return $?
  UNIX_SECURITY_HOST_PROBE="$host_probe"
  run_bounded 15 docker cp \
    "$UNIX_SECURITY_SIBLING_CONTAINER:/security-probe" "$host_probe" || return $?

  if running="$(run_bounded 10 docker inspect --format '{{.State.Running}}' \
    "$UNIX_SECURITY_SIBLING_CONTAINER")"; then
    :
  else
    inspect_status=$?
    probe_window_valid=false
    scenario_status=1
    log_error "could not inspect the Unix sibling security probe before the victim scenario"
  fi
  if [[ "$running" != "true" ]]; then
    probe_window_valid=false
    scenario_status=1
    log_error "Unix sibling security probe exited before the victim scenario"
  fi

  if [[ "$probe_window_valid" == "true" ]]; then
    if (
      SCENARIO_VARIANT="security-unix-sibling-victim"
      ALLOW_UNIX_SECURITY_METRICS=true
      run_scenario concurrency false metrics
    ); then
      scenario_status=0
    else
      scenario_status=$?
    fi
  fi

  if running="$(run_bounded 10 docker inspect --format '{{.State.Running}}' \
    "$UNIX_SECURITY_SIBLING_CONTAINER")"; then
    inspect_status=0
  else
    inspect_status=$?
    probe_window_valid=false
    log_error "could not inspect the Unix sibling security probe after the victim scenario"
  fi
  if [[ "$running" != "true" ]]; then
    probe_window_valid=false
    log_error "Unix sibling security probe exited before release"
  elif run_bounded 15 docker kill --signal SIGUSR1 \
    "$UNIX_SECURITY_SIBLING_CONTAINER" >/dev/null; then
    release_status=0
  else
    release_status=$?
    probe_window_valid=false
    log_error "could not release the Unix sibling security probe"
  fi
  if probe_exit="$(run_bounded 60 docker wait "$UNIX_SECURITY_SIBLING_CONTAINER")"; then
    wait_status=0
  else
    wait_status=$?
    probe_window_valid=false
    log_error "could not reap the Unix sibling security probe"
  fi
  if [[ "$probe_exit" != "0" ]]; then
    probe_window_valid=false
    log_error "Unix sibling security probe exited with status $probe_exit"
  fi
  if run_bounded 15 docker logs "$UNIX_SECURITY_SIBLING_CONTAINER" >"$output"; then
    log_status=0
  else
    log_status=$?
    probe_window_valid=false
    log_error "could not capture the Unix sibling security probe logs"
  fi
  if ((wait_status == 0)); then
    UNIX_SECURITY_SIBLING_CONTAINER=""
  fi
  if assert_unix_abuse_race_output "$output" false; then
    output_status=0
  else
    output_status=$?
    probe_window_valid=false
  fi
  if [[ "$probe_window_valid" != "true" || \
    "$inspect_status" != "0" || "$release_status" != "0" || \
    "$wait_status" != "0" || "$log_status" != "0" || \
    "$output_status" != "0" ]]; then
    return 1
  fi

  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    phase_label="concurrency-security-unix-sibling-victim"
    if ((REPEAT_COUNT > 1)); then
      printf -v phase_label '%s-run-%02d' "$phase_label" "$run_number"
    fi
    if assert_security_metric_delta \
      "$RESULT_DIR/phases/$phase_label-after/obi-metrics.delta" \
      take unauthorized unix 1; then
      :
    else
      current_metric_status=$?
      if ((metric_status == 0)); then
        metric_status=$current_metric_status
      fi
    fi
  done
  if ((metric_status != 0)); then
    return "$metric_status"
  fi
  if ((scenario_status != 0)); then
    return "$scenario_status"
  fi

  if ! wait_for_unix_security_metrics_quiescent \
    "$after_metrics" \
    "Unix sibling security probe completion"; then
    return 1
  fi
  write_metrics_delta "$before_metrics" "$after_metrics" "$metric_delta" || return $?
  assert_security_metric_delta "$metric_delta" take unauthorized unix 1
}

run_unix_same_cgroup_security_control() {
  local -r java_container="$1"
  local -r output="$RESULT_DIR/security-unix-same-cgroup.log"
  local -r identity="$RESULT_DIR/security-unix-same-cgroup-identity.txt"
  local -r before_metrics="$RESULT_DIR/metrics-security-unix-same-cgroup-before.prom"
  local -r after_metrics="$RESULT_DIR/metrics-security-unix-same-cgroup-complete.prom"
  local -r metric_delta="$RESULT_DIR/metrics-security-unix-same-cgroup.delta"
  local probe_directory=""
  local probe_path=""
  local pid_path=""
  local java_pid_mode=""
  local java_live_tid=""
  local pid_namespace_status=""
  local java_cgroup=""
  local probe_cgroup=""
  local probe_status=""
  local probe_exit=0
  local scenario_status=0
  local release_status=0
  local wait_status=0
  local output_status=0
  local remove_status=0
  local metric_status=0
  local current_metric_status=0
  local probe_window_valid=true
  local run_number=0
  local phase_label=""

  [[ -n "$UNIX_SECURITY_HOST_PROBE" && -f "$UNIX_SECURITY_HOST_PROBE" ]] || {
    log_error "the Unix same-cgroup control requires the retained sibling probe binary"
    return 1
  }
  if ! wait_for_unix_security_metrics_quiescent \
    "$before_metrics" \
    "Unix same-cgroup security probe baseline"; then
    return 1
  fi

  UNIX_SECURITY_JAVA_CONTAINER="$java_container"
  java_pid_mode="$(run_bounded 10 docker inspect --format '{{.HostConfig.PidMode}}' \
    "$java_container")" || return $?
  [[ -z "$java_pid_mode" ]] || {
    log_error "Java backend did not retain a private PID namespace for the Unix same-cgroup control"
    return 1
  }
  # Expanded by the container shell, not this process.
  # shellcheck disable=SC2016
  run_bounded 10 docker exec "$java_container" /bin/sh -ec '
    set -eu
    [ -d /proc/1/task/1 ]
    [ -r /proc/1/comm ]
    [ -r /proc/1/task/1/comm ]
    read -r process_name </proc/1/comm
    read -r thread_name </proc/1/task/1/comm
    [ "$process_name" = java ]
    [ "$thread_name" = java ]
  ' || return $?
  java_live_tid=1
  probe_directory="$(run_bounded 10 docker exec "$java_container" /bin/sh -ec '
    set -eu
    umask 077
    directory="$(mktemp -d /tmp/obi-unix-security.XXXXXX)"
    chown 65534:65534 "$directory"
    printf "%s\\n" "$directory"
  ')" || return $?
  [[ "$probe_directory" =~ ^/tmp/obi-unix-security\.[[:alnum:]]{6,}$ ]] || {
    log_error "Java container returned an unsafe Unix security probe directory"
    return 1
  }
  UNIX_SECURITY_PROBE_DIRECTORY="$probe_directory"
  probe_path="$probe_directory/security-probe"
  pid_path="$probe_directory/security-probe.pid"
  run_bounded 15 docker cp "$UNIX_SECURITY_HOST_PROBE" \
    "$java_container:$probe_path" || return $?
  rm -f -- "$UNIX_SECURITY_HOST_PROBE" || return $?
  UNIX_SECURITY_HOST_PROBE=""
  run_bounded 10 docker exec "$java_container" chmod 0755 "$probe_path" || return $?

  : >"$output"
  docker exec --user 65534:65534 "$java_container" /bin/sh -ec '
    umask 077
    printf "%s\n" "$$" >"$1"
    exec "$2" --socket "$3" --mode abuse-race --timeout "$4" --forged-tid "$5"
  ' sh "$pid_path" "$probe_path" /var/run/obi/java-remote-parent.sock \
    "$SECURITY_PROBE_TIMEOUT" "$java_live_tid" >"$output" 2>&1 &
  UNIX_SECURITY_EXEC_PID=$!
  wait_for_background_log \
    "$UNIX_SECURITY_EXEC_PID" \
    "$output" \
    "security probe abuse race ready" \
    "same-cgroup Unix abuse race" || return $?
  UNIX_SECURITY_NAMESPACE_PID="$(wait_for_unix_security_namespace_pid \
    "$java_container" "$pid_path")" || return $?
  [[ "$UNIX_SECURITY_NAMESPACE_PID" != "$java_live_tid" ]] || {
    log_error "Unix same-cgroup security probe reused the Java live-thread identity"
    return 1
  }
  if ! pid_namespace_status="$(capture_unix_security_pid_namespace_status \
    "$java_container" "$UNIX_SECURITY_NAMESPACE_PID")"; then
    log_error "Unix same-cgroup security probe did not present a shared private PID namespace"
    return 1
  fi
  if ! assert_unix_security_pid_namespace_identity \
    "$pid_namespace_status" "$UNIX_SECURITY_NAMESPACE_PID"; then
    log_error "Unix same-cgroup security probe did not share the Java PID namespace"
    return 1
  fi

  java_cgroup="$(run_bounded 10 docker exec "$java_container" cat /proc/1/cgroup)" || return $?
  probe_cgroup="$(run_bounded 10 docker exec "$java_container" \
    cat "/proc/$UNIX_SECURITY_NAMESPACE_PID/cgroup" 2>/dev/null)" || return $?
  probe_status="$(run_bounded 10 docker exec "$java_container" \
    cat "/proc/$UNIX_SECURITY_NAMESPACE_PID/status" 2>/dev/null)" || return $?
  assert_unix_security_cgroup_identity \
    "$java_cgroup" "$probe_cgroup" "$probe_status" || return $?
  {
    printf 'peer_user=65534:65534\n'
    printf 'cgroup_match=true\n'
    printf 'capability_free=true\n'
    printf 'pid_namespace_shared=true\n'
    printf 'pid_namespace_evidence=status-nspid-depth\n'
    awk '/^(Uid|Gid|CapEff):/ { print }' <<<"$probe_status"
  } >"$identity"

  if ! background_process_is_running "$UNIX_SECURITY_EXEC_PID"; then
    probe_window_valid=false
    scenario_status=1
    log_error "Unix same-cgroup security probe exited before the victim scenario"
  fi

  if [[ "$probe_window_valid" == "true" ]]; then
    if (
      SCENARIO_VARIANT="security-unix-same-cgroup-victim"
      ALLOW_UNIX_SECURITY_METRICS=true
      run_scenario concurrency false metrics
    ); then
      scenario_status=0
    else
      scenario_status=$?
    fi
  fi

  if ! background_process_is_running "$UNIX_SECURITY_EXEC_PID"; then
    probe_window_valid=false
    log_error "Unix same-cgroup security probe exited before release"
  else
    # Expanded by the container shell, not this process.
    # shellcheck disable=SC2016
    if run_bounded 10 docker exec "$java_container" /bin/sh -ec '
      set -eu
      name="$(cat "/proc/$1/comm" 2>/dev/null)"
      [ "$name" = security-probe ]
      kill -USR1 "$1"
    ' sh "$UNIX_SECURITY_NAMESPACE_PID" 2>/dev/null; then
      release_status=0
    else
      release_status=$?
      probe_window_valid=false
      log_error "could not release the Unix same-cgroup security probe"
    fi
  fi
  if wait_for_background_process "$UNIX_SECURITY_EXEC_PID" 15; then
    probe_exit=0
    wait_status=0
  else
    probe_exit=$?
    wait_status=$probe_exit
  fi
  # Only timeout leaves the child potentially live and therefore reserved for cleanup.
  if ((wait_status != 124)); then
    UNIX_SECURITY_EXEC_PID=""
    UNIX_SECURITY_NAMESPACE_PID=""
  fi
  if ((probe_exit != 0)); then
    probe_window_valid=false
    log_error "Unix same-cgroup security probe exited with status $probe_exit"
  fi
  if assert_unix_abuse_race_output "$output" true; then
    output_status=0
  else
    output_status=$?
    probe_window_valid=false
  fi

  if [[ -z "$UNIX_SECURITY_EXEC_PID" ]]; then
    if run_bounded 10 docker exec "$java_container" \
      rm -rf -- "$probe_directory"; then
      remove_status=0
      UNIX_SECURITY_PROBE_DIRECTORY=""
      UNIX_SECURITY_JAVA_CONTAINER=""
    else
      remove_status=$?
      probe_window_valid=false
      log_error "could not remove the Unix same-cgroup security probe directory"
    fi
  fi
  if [[ "$probe_window_valid" != "true" || \
    "$release_status" != "0" || "$wait_status" != "0" || \
    "$output_status" != "0" || "$remove_status" != "0" ]]; then
    return 1
  fi

  for ((run_number = 1; run_number <= REPEAT_COUNT; run_number++)); do
    phase_label="concurrency-security-unix-same-cgroup-victim"
    if ((REPEAT_COUNT > 1)); then
      printf -v phase_label '%s-run-%02d' "$phase_label" "$run_number"
    fi
    if assert_security_metric_delta \
      "$RESULT_DIR/phases/$phase_label-after/obi-metrics.delta" \
      take unauthorized unix 1; then
      :
    else
      current_metric_status=$?
      if ((metric_status == 0)); then
        metric_status=$current_metric_status
      fi
    fi
  done
  if ((metric_status != 0)); then
    return "$metric_status"
  fi
  if ((scenario_status != 0)); then
    return "$scenario_status"
  fi

  if ! wait_for_unix_security_metrics_quiescent \
    "$after_metrics" \
    "Unix same-cgroup security probe completion"; then
    return 1
  fi
  write_metrics_delta "$before_metrics" "$after_metrics" "$metric_delta" || return $?
  assert_security_metric_delta "$metric_delta" take unauthorized unix 1 || return $?
}

run_unix_peer_security_controls() {
  local java_container=""

  java_container="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet java-backend)" || return $?
  [[ -n "$java_container" ]] || {
    log_error "could not resolve the Java backend container for Unix security controls"
    return 1
  }
  run_unix_sibling_security_control "$java_container" || return $?
  run_unix_same_cgroup_security_control "$java_container"
}

run_unix_security_control() {
  local -r endpoint_output="$RESULT_DIR/security-endpoint.log"
  local -r security_logs="$RESULT_DIR/security-sanitized-logs.txt"
  local security_since=""
  local restart_since=""
  local probe_exit=""
  local canary_status=0

  [[ "$TRANSPORT" == "unix" && "$SELECTED_TRANSPORT" == "unix" ]] || {
    log_error "the security control requires the forced Unix transport"
    return 1
  }

  security_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  capture_java_diagnostics "security-before"
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/security-before/java-diagnostics.txt"

  run_unix_peer_security_controls || return $?

  plan_obi_metric_pair_capture security-unix-endpoint-refusal || return $?
  plan_obi_metric_pair_capture security-unix-endpoint-recovery || return $?
  capture_phase_evidence security-unix-endpoint-before || return $?
  SECURITY_PROBE_MODE="endpoint"
  export SECURITY_PROBE_MODE
  log_info "installing a bounded replacement endpoint around an OBI restart"
  run_bounded 60 \
    "${COMPOSE[@]}" up --detach --no-deps --force-recreate security-probe
  wait_for_log \
    security-probe \
    "security probe replacement ready" \
    "security endpoint replacement barrier"
  UNIX_SECURITY_ENDPOINT_CONTAINER="$(run_bounded 10 \
    "${COMPOSE[@]}" ps --all --quiet security-probe)"
  [[ -n "$UNIX_SECURITY_ENDPOINT_CONTAINER" ]] || {
    log_error "could not resolve the security probe container"
    return 1
  }

  restart_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  run_bounded "$OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" restart --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || \
    return $?
  OBI_RUNNING=true
  wait_for_log \
    obi \
    "refusing to replace non-socket Java bridge path" \
    "replacement endpoint fail-closed restart" \
    "$restart_since" || return $?
  capture_phase_evidence security-unix-endpoint-fault || return $?
  record_obi_metric_pair \
    security-unix-endpoint-refusal security-unix-endpoint-before \
    security-unix-endpoint-fault process_replaced "" >/dev/null || return $?
  run_bounded 15 \
    "${COMPOSE[@]}" kill --signal SIGUSR1 security-probe || return $?
  probe_exit="$(run_bounded 60 docker wait "$UNIX_SECURITY_ENDPOINT_CONTAINER")"
  [[ "$probe_exit" == "0" ]] || {
    log_error "security endpoint probe exited with status $probe_exit"
    return 1
  }
  run_bounded 15 docker logs "$UNIX_SECURITY_ENDPOINT_CONTAINER" \
    >"$endpoint_output" || return $?
  UNIX_SECURITY_ENDPOINT_CONTAINER=""
  grep -Fq '"status":"passed","mode":"endpoint"' "$endpoint_output" || {
    log_error "security endpoint probe did not emit explicit pass evidence"
    return 1
  }

  capture_terminal_java_diagnostics_recovery_boundary || return $?
  wait_for_log \
    obi \
    "Java remote-parent fallback transport recovered" \
    "post-replacement Unix bridge recovery" \
    "$restart_since" || return $?
  BRIDGE_RUNNING=true
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "post-replacement Java provider probe" || return $?
  sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "post-replacement Java provider reconfiguration" || return $?
  wait_for_log \
    java-backend \
    "OBI remote-parent provider ready" \
    "post-replacement Java bridge provider" \
    "$restart_since" || return $?
  assert_selected_transport unix || return $?
  capture_phase_evidence security-unix-endpoint-after || return $?
  record_obi_metric_pair \
    security-unix-endpoint-recovery security-unix-endpoint-fault \
    security-unix-endpoint-after same_process "" >/dev/null || return $?

  capture_java_diagnostics "security-after"
  assert_sanitized_java_diagnostics \
    "$RESULT_DIR/phases/security-after/java-diagnostics.txt"
  run_bounded 15 \
    "${COMPOSE[@]}" logs --no-color --since "$security_since" \
      obi java-backend security-probe security-unix-sibling-probe >"$security_logs"
  if grep -Fq 'OBI_SECURITY_PROBE_PAYLOAD_CANARY' \
    "$RESULT_DIR/security-unix-sibling.log" \
    "$RESULT_DIR/security-unix-same-cgroup.log" \
    "$endpoint_output" "$security_logs" \
    "$RESULT_DIR/phases/security-before/java-diagnostics.txt" \
    "$RESULT_DIR/phases/security-after/java-diagnostics.txt"; then
    log_error "security diagnostics disclosed the probe payload canary"
    return 1
  else
    canary_status=$?
  fi
  if ((canary_status != 1)); then
    log_error "could not verify that security diagnostics excluded the probe payload canary"
    return "$canary_status"
  fi
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  clear_terminal_java_diagnostics_recovery_boundary || return $?

  run_unix_permissive_directory_control || return $?

  (
    SCENARIO_VARIANT="security-recovery"
    run_scenario basic false
  )
  printf '{"status":"passed","scenario":"security","mode":"unix","sibling_probe":"%s","sibling_topology":"%s","same_cgroup_probe":"%s","same_cgroup_identity":"%s","sibling_cgroup_match":false,"same_cgroup_match":true,"peer_uid_gid":"65534:65534","concurrent_sibling_victim":"passed","concurrent_same_cgroup_victim":"passed","endpoint":"%s","permissive_directory":"refused","post_abuse_recovery":"passed","primary_only_cases":"not_applicable"}\n' \
    "$(basename -- "$RESULT_DIR/security-unix-sibling.log")" \
    "$(basename -- "$RESULT_DIR/security-unix-sibling-topology.txt")" \
    "$(basename -- "$RESULT_DIR/security-unix-same-cgroup.log")" \
    "$(basename -- "$RESULT_DIR/security-unix-same-cgroup-identity.txt")" \
    "$(basename -- "$endpoint_output")" \
    >"$RESULT_DIR/scenario-security-status.json"
  crosslink_and_bind_active_obi_metric_boundary_status \
    scenario-security-status.json || return $?
  commit_terminal_java_diagnostics_recovery_boundary || return $?
  clear_terminal_java_diagnostics_recovery_boundary || return $?
}

record_unsupported_scenario() {
  local -r name="$1"
  local -r reason="$2"
  local -r reference="scenario-$name-status.json"

  [[ -n "$RESULT_DIR" && -d "$RESULT_DIR" ]] || {
    log_error "cannot record unsupported scenario without a result directory"
    return 1
  }
  if obi_metric_boundary_index_is_initialized; then
    jq -cn --arg name "$name" --arg reason "$reason" '
      {
        status: "not_applicable",
        scenario: $name,
        reason: $reason,
        obi_metric_boundary_ids: [$name]
      }
    ' >"$RESULT_DIR/$reference" || return $?
    mark_obi_metric_boundary_not_applicable \
      "$name" "$reason" "$reference"
  else
    printf '{"status":"unsupported","reason":"%s"}\n' "$reason" \
      >"$RESULT_DIR/$reference"
  fi
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
  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  export BRIDGE_TRANSPORT=disabled
  export EXTENSION_ENABLED=true
  export JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE="/otel/obi-otel-extension.jar"
  export OTEL_PROPAGATORS_VALUE="obi,tracecontext,baggage"
  run_bounded 30 \
    "${COMPOSE[@]}" config >"$RESULT_DIR/compose-disabled-control.yaml" || return $?
  recreate_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach \
      --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" --force-recreate \
      java-backend apache-proxy obi || return $?
  OBI_RUNNING=true
  wait_for_log \
    java-backend \
    "OBI remote-parent propagator enabled" \
    "disabled-control external extension" \
    "$recreate_since" || return $?
  wait_for_log \
    java-backend \
    "OBI Java instrumentation ready" \
    "disabled-control Java instrumentation" \
    "$recreate_since" || return $?
  wait_for_apache_instrumentation disabled-control || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "disabled-control HTTPS path" || return $?
  assert_runtime_contract disabled || return $?
  run_scenario disabled
}

run_uninstrumented_control() {
  log_info "recreating the backend without OBI or any Java agent"
  capture_control_response "instrumented-control" || return $?
  invalidate_selected_transport || return $?
  BRIDGE_RUNNING=false
  export BRIDGE_TRANSPORT=disabled
  export EXTENSION_ENABLED=false
  export JAVA_TOOL_OPTIONS_VALUE=""
  export OTEL_JAVAAGENT_EXTENSIONS_VALUE=""
  export OTEL_PROPAGATORS_VALUE="tracecontext,baggage"
  run_bounded "$OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" stop --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || \
    return $?
  OBI_RUNNING=false
  run_bounded 30 \
    "${COMPOSE[@]}" config >"$RESULT_DIR/compose-uninstrumented-control.yaml" || return $?
  run_bounded 120 \
    "${COMPOSE[@]}" up --detach --force-recreate \
      java-backend apache-proxy || return $?
  wait_for_http \
    "$APACHE_HTTPS_HEALTH_ENDPOINT" \
    "uninstrumented-control HTTPS path" || return $?
  assert_runtime_contract uninstrumented || return $?
  capture_control_response "uninstrumented-control" || return $?
  cmp \
    "$RESULT_DIR/instrumented-control-response.normalized.json" \
    "$RESULT_DIR/uninstrumented-control-response.normalized.json" || return $?
  cmp \
    "$RESULT_DIR/instrumented-control-response.status" \
    "$RESULT_DIR/uninstrumented-control-response.status" || return $?
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
    "http://127.0.0.1:18080/api/echo" >"$status" || return $?
  [[ "$(<"$status")" == "200" ]] || {
    log_error "$label returned HTTP status $(<"$status")"
    return 1
  }
  normalize_control_response \
    "$body" \
    "$RESULT_DIR/$label-response.normalized.json" || return $?
}

normalize_control_response() {
  local -r input="$1"
  local -r output="$2"

  sed -E \
    -e 's/"backend_connection_id":[0-9]+/"backend_connection_id":0/' \
    -e 's/"backend_remote_port":[0-9]+/"backend_remote_port":0/' \
    -e 's/"backend_socket_fd":-?[0-9]+/"backend_socket_fd":0/' \
    -e 's/"tls_read_events":-?[0-9]+/"tls_read_events":0/' \
    -e 's/"tls_read_bytes":-?[0-9]+/"tls_read_bytes":0/' \
    "$input" >"$output"
}

diagnostic_nondisclosure_container_id() {
  local -r service="$1"
  local container_id=""

  case "$service" in
    obi|java-backend) ;;
    *) return 1 ;;
  esac
  container_id="$(run_bounded 10 "${COMPOSE[@]}" ps --quiet "$service")" || return $?
  [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$container_id"
}

assert_diagnostic_nondisclosure_runtime_configuration() {
  local -r obi_container_id="$1"
  local runtime_environment=""

  [[ "$obi_container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  runtime_environment="$(run_bounded 10 docker inspect \
    --format '{{json .Config.Env}}' "$obi_container_id")" || return $?
  jq -e \
    --arg log_level "$OBI_LOG_LEVEL" '
      type == "array" and
      ([.[] | select(startswith("OTEL_EBPF_LOG_LEVEL="))] ==
        ["OTEL_EBPF_LOG_LEVEL=" + $log_level]) and
      ([.[] | select(startswith("OTEL_EBPF_BPF_DEBUG="))] ==
        ["OTEL_EBPF_BPF_DEBUG=false"]) and
      ([.[] | select(startswith("OTEL_EBPF_PROTOCOL_DEBUG_PRINT="))] ==
        ["OTEL_EBPF_PROTOCOL_DEBUG_PRINT=false"])
    ' <<<"$runtime_environment" >/dev/null
}

create_diagnostic_nondisclosure_request_directory() {
  local metadata=""

  [[ -z "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" &&
    -d "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || return 1
  DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR="$(umask 077; mktemp -d \
    "$RESULT_DIR/.diagnostic-nondisclosure-request.XXXXXX")" || return $?
  metadata="$(stat --format='%u:%a' -- \
    "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR")" || return $?
  [[ "$metadata" == "$EUID:700" ]]
}

validate_diagnostic_nondisclosure_canary_source() {
  local -r input="$1"

  bounded_evidence_file \
    "$input" \
    "$DIAGNOSTIC_NONDISCLOSURE_CANARY_SOURCE_MAX_BYTES" \
    "$DIAGNOSTIC_NONDISCLOSURE_CANARY_SOURCE_MAX_LINES" || return 1
  jq -ces '
    def canary:
      type == "string" and length >= 1 and length <= 128 and
      test("^[A-Za-z0-9._:-]+$");
    length == 1 and
    (.[0] | type == "object" and
      .status == "passed" and .scenario == "w3c" and
      (.cases | type == "array" and length > 0) and
      all(.cases[];
        type == "object" and
        (.request | type == "object") and
        (.request.marker | canary) and
        ((.request.w3c_trace_id? // "") |
          . == "" or canary) and
        ((.request.w3c_parent_span_id? // "") |
          . == "" or canary) and
        (.trace | type == "object") and
        (.trace.spans | type == "array") and
        ((.trace.related_spans? // []) | type == "array") and
        all((.trace.spans + (.trace.related_spans? // []))[];
          type == "object" and
          (.trace_id | canary) and
          (.span_id | canary) and
          ((.parent_span_id? // "") | . == "" or canary))))
  ' "$input" >/dev/null
}

diagnostic_nondisclosure_canary_source_sha256() {
  local -r input="$1"
  local first_digest=""
  local second_digest=""

  validate_diagnostic_nondisclosure_canary_source "$input" || return $?
  first_digest="$(sha256_file "$input")" || return $?
  validate_diagnostic_nondisclosure_canary_source "$input" || return $?
  second_digest="$(sha256_file "$input")" || return $?
  [[ "$first_digest" == "$second_digest" ]] || return 1
  printf '%s\n' "$first_digest"
}

write_diagnostic_nondisclosure_canaries() {
  local -r scenario_result="$1"
  local -r expected_source_sha256="$2"
  local -r output="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/canaries.txt"
  local -r candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/canaries.unsorted"
  local count=""
  local observed_source_sha256=""
  local size=""

  [[ "$expected_source_sha256" =~ ^[0-9a-f]{64}$ &&
    -f "$scenario_result" && ! -L "$scenario_result" &&
    -d "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" &&
    ! -L "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" ]] || return 1
  [[ ! -e "$candidate" && ! -L "$candidate" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  observed_source_sha256="$(sha256sum <"$scenario_result")" || return $?
  observed_source_sha256="${observed_source_sha256%% *}"
  [[ "$observed_source_sha256" =~ ^[0-9a-f]{64}$ &&
    "$observed_source_sha256" == "$expected_source_sha256" ]] || return 1
  if {
    printf '%s\n' \
      "$DIAGNOSTIC_NONDISCLOSURE_TRACE_ID" \
      "$DIAGNOSTIC_NONDISCLOSURE_PARENT_SPAN_ID" \
      "$DIAGNOSTIC_NONDISCLOSURE_MARKER" \
      "$DIAGNOSTIC_NONDISCLOSURE_HEADER_CANARY" \
      "$DIAGNOSTIC_NONDISCLOSURE_BODY_CANARY" \
      "$DIAGNOSTIC_NONDISCLOSURE_CREDENTIAL_CANARY" || exit $?
    if [[ "$SELECTED_TRANSPORT" == "unix" ]]; then
      printf '%s\n' "$DIAGNOSTIC_NONDISCLOSURE_UNIX_PAYLOAD_CANARY" || exit $?
    fi
    jq -er '
      if .status == "passed" and .scenario == "w3c" and
        (.cases | type == "array" and length > 0)
      then
        .cases[] |
        .request.marker,
        (.request.w3c_trace_id // empty),
        (.request.w3c_parent_span_id // empty),
        (.trace.spans[]? |
          .trace_id, .span_id, (.parent_span_id // empty)),
        (.trace.related_spans[]? |
          .trace_id, .span_id, (.parent_span_id // empty))
      else error("invalid W3C scenario evidence") end
    ' "$scenario_result" || exit $?
  } | LC_ALL=C sort -u >"$candidate"; then
    :
  else
    count=$?
    rm -f -- "$candidate" || true
    return "$count"
  fi
  count="$(LC_ALL=C awk '
    length($0) < 1 || length($0) > 128 ||
    $0 !~ /^[A-Za-z0-9._:-]+$/ { exit 2 }
    seen[$0]++ { exit 3 }
    END { print NR }
  ' "$candidate")" || {
    count=$?
    rm -f -- "$candidate" || true
    return "$count"
  }
  size="$(stat -c '%s' -- "$candidate")" || {
    count=$?
    rm -f -- "$candidate" || true
    return "$count"
  }
  bounded_decimal \
    "$count" "$DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_COUNT" false >/dev/null || {
    rm -f -- "$candidate" || true
    return 1
  }
  bounded_decimal \
    "$size" "$DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_BYTES" false >/dev/null || {
    rm -f -- "$candidate" || true
    return 1
  }
  if chmod 0600 -- "$candidate" && mv -T -- "$candidate" "$output"; then
    :
  else
    count=$?
    rm -f -- "$candidate" || true
    return "$count"
  fi
  observed_source_sha256="$(sha256sum <"$scenario_result")" || {
    count=$?
    rm -f -- "$output" || true
    return "$count"
  }
  observed_source_sha256="${observed_source_sha256%% *}"
  [[ "$observed_source_sha256" =~ ^[0-9a-f]{64}$ &&
    "$observed_source_sha256" == "$expected_source_sha256" ]] || {
    rm -f -- "$output" || true
    return 1
  }
}

assert_diagnostic_nondisclosure_surface_has_no_canary() {
  local -r surface="$1"
  local -r canaries="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/canaries.txt"
  local grep_status=0

  [[ -f "$surface" && ! -L "$surface" &&
    -f "$canaries" && ! -L "$canaries" ]] || return 1
  if LC_ALL=C grep --fixed-strings --file="$canaries" -- "$surface" \
    >/dev/null; then
    return 1
  else
    grep_status=$?
  fi
  [[ "$grep_status" == 1 ]]
}

perform_diagnostic_nondisclosure_request() {
  local -r request_directory="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR"
  local -r request_headers="$request_directory/request.headers"
  local -r request_body="$request_directory/request.body"
  local -r response_headers="$request_directory/response.headers"
  local -r response_body="$request_directory/response.json"
  local -r response_status="$request_directory/response.status"
  local -r diagnostics_phase="diagnostic-nondisclosure-header"
  local -r diagnostics_output="$RESULT_DIR/phases/$diagnostics_phase/java-diagnostics.txt"
  local metadata=""
  local request_status=0
  local grep_status=0
  local sensitive=""

  [[ -d "$request_directory" && ! -L "$request_directory" ]] || return 1
  if (umask 077
    printf '%s\n' \
      "traceparent: 00-$DIAGNOSTIC_NONDISCLOSURE_TRACE_ID-$DIAGNOSTIC_NONDISCLOSURE_PARENT_SPAN_ID-01" \
      "x-obi-demo-id: $DIAGNOSTIC_NONDISCLOSURE_MARKER" \
      "x-obi-private-canary: $DIAGNOSTIC_NONDISCLOSURE_HEADER_CANARY" \
      "Authorization: Bearer $DIAGNOSTIC_NONDISCLOSURE_CREDENTIAL_CANARY" \
      >"$request_headers" || exit $?
    printf '%s\n' "$DIAGNOSTIC_NONDISCLOSURE_BODY_CANARY" \
      >"$request_body" || exit $?
  ); then
    :
  else
    return $?
  fi
  metadata="$(stat --format='%u:%a:%h' -- \
    "$request_headers" "$request_body")" || return $?
  [[ "$metadata" == "$EUID:600:1"$'\n'"$EUID:600:1" ]] || return 1
  ensure_java_diagnostics_phase_directory "$diagnostics_phase" || return $?
  if curl --fail --silent --show-error --max-time 10 \
    --max-filesize "$DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_BYTES" \
    --header "@$request_headers" \
    --data-binary "@$request_body" \
    --dump-header "$response_headers" \
    --output "$response_body" \
    --write-out '%{http_code}\n' \
    "http://127.0.0.1:18080/api/echo?bridge_diagnostics=1&close=1" \
    >"$response_status"; then
    :
  else
    request_status=$?
    return "$request_status"
  fi
  bounded_evidence_file \
    "$response_headers" "$DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_BYTES" \
    "$DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_LINES" || return 1
  bounded_evidence_file \
    "$response_body" "$DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_BYTES" 1 || return 1
  [[ "$(<"$response_status")" == 200 ]] || return 1
  jq -e -s --arg marker "$DIAGNOSTIC_NONDISCLOSURE_MARKER" '
    length == 1 and
    (.[0] | keys == [
      "backend_connection_id", "backend_remote_port", "backend_socket_fd",
      "marker", "protocol", "secure", "tls_cipher", "tls_protocol",
      "tls_read_bytes", "tls_read_events"
    ]) and
    .[0].marker == $marker and .[0].secure == true and
    .[0].protocol == "HTTP/1.1" and .[0].tls_protocol == "TLSv1.3"
  ' "$response_body" >/dev/null || return 1
  for sensitive in \
    "$DIAGNOSTIC_NONDISCLOSURE_TRACE_ID" \
    "$DIAGNOSTIC_NONDISCLOSURE_PARENT_SPAN_ID" \
    "$DIAGNOSTIC_NONDISCLOSURE_HEADER_CANARY" \
    "$DIAGNOSTIC_NONDISCLOSURE_BODY_CANARY" \
    "$DIAGNOSTIC_NONDISCLOSURE_CREDENTIAL_CANARY" \
    "$DIAGNOSTIC_NONDISCLOSURE_UNIX_PAYLOAD_CANARY"; do
    if LC_ALL=C grep --fixed-strings -- "$sensitive" "$response_body" \
      >/dev/null; then
      return 1
    else
      grep_status=$?
    fi
    [[ "$grep_status" == 1 ]] || return "$grep_status"
  done
  assert_diagnostic_nondisclosure_surface_has_no_canary "$response_headers" ||
    return $?
  extract_java_diagnostics_header "$response_headers" "$diagnostics_output" || return $?
  assert_sanitized_java_diagnostics "$diagnostics_output" || return $?
  assert_diagnostic_nondisclosure_surface_has_no_canary "$diagnostics_output" ||
    return $?
  attach_obi_java_capture "$diagnostics_phase" || return $?
  rm -f -- \
    "$request_headers" "$request_body" "$response_headers" \
    "$response_body" "$response_status"
}

capture_diagnostic_nondisclosure_java_endpoint() {
  local -r output="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/.java-endpoint.capture"
  local metadata=""
  local size=""
  local capture_status=0

  [[ -d "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" &&
    ! -L "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" &&
    -f "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/canaries.txt" &&
    ! -L "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/canaries.txt" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  (umask 077; : >"$output") || return $?
  metadata="$(stat --format='%u:%a:%h' -- "$output")" || return $?
  [[ "$metadata" == "$EUID:600:1" ]] || return 1
  if curl --fail --silent --show-error --max-time 5 \
    --max-filesize "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" \
    --cacert "$CERT_DIR/ca.crt" \
    "https://127.0.0.1:18443/obi-diagnostics" 2>/dev/null |
    (
      LC_ALL=C head -c "$((TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES + 1))" \
        >"$output" || exit $?
      cat >/dev/null
    ); then
    :
  else
    capture_status=$?
    return "$capture_status"
  fi
  size="$(stat -Lc '%s' -- "$output")" || return $?
  ((size > 0 && size <= TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES)) || return 1
  bounded_evidence_file \
    "$output" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" \
    "$TERMINAL_JAVA_DIAGNOSTICS_MAX_LINES" || return 1
  [[ "$(stat --format='%u:%a:%h' -- "$output")" == "$EUID:600:1" ]] ||
    return 1
  assert_sanitized_java_diagnostics "$output" || return $?
  assert_diagnostic_nondisclosure_surface_has_no_canary "$output"
}

run_diagnostic_nondisclosure_unix_probe() {
  local -r output="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/unix-probe.json"
  local SECURITY_PROBE_MODE="abuse"

  [[ "$SELECTED_TRANSPORT" == "unix" ]] || return 0
  export SECURITY_PROBE_MODE
  run_bounded "$((SECURITY_PROBE_TIMEOUT_SLACK_SECONDS + 60))" \
    "${COMPOSE[@]}" run --rm --no-deps --no-TTY \
      --env SECURITY_PROBE_MODE=abuse security-probe \
    >"$output" || return $?
  bounded_evidence_file \
    "$output" "$DIAGNOSTIC_NONDISCLOSURE_RESPONSE_MAX_BYTES" 1 || return 1
  jq -e -s '
    length == 1 and
    (.[0] | keys == ["cases", "mode", "status"]) and
    .[0].status == "passed" and .[0].mode == "abuse" and
    (.[0].cases == [
      {"name":"peer-identity","outcome":"unauthorized"},
      {"name":"forged-identity","outcome":"unauthorized"},
      {"name":"malformed","outcome":"malformed"},
      {"name":"truncated","outcome":"malformed"},
      {"name":"version-mismatch","outcome":"version_mismatch"},
      {"name":"oversized","outcome":"unauthorized"},
      {"name":"repeated-frame","outcome":"unauthorized"},
      {"name":"repeated-unauthorized","outcome":"bounded"},
      {"name":"high-rate-admission","outcome":"overload-and-recovery"}
    ])
  ' "$output" >/dev/null
}

capture_diagnostic_nondisclosure_service_log() {
  local -r service="$1"
  local -r expected_container_id="$2"
  local -r since="$3"
  local -r until="$4"
  local -r output="$5"
  local observed_container_id=""
  local candidate=""
  local candidate_metadata=""
  local size=""
  local capture_status=0
  local expected_output=""
  local maximum_bytes=""

  case "$service" in
    obi)
      expected_output="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/diagnostic-nondisclosure-obi.log"
      maximum_bytes="$DIAGNOSTIC_NONDISCLOSURE_OBI_LOG_MAX_BYTES"
      ;;
    java-backend)
      expected_output="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/diagnostic-nondisclosure-java.log"
      maximum_bytes="$COMPOSE_LOG_MAX_BYTES"
      ;;
    *) return 1 ;;
  esac
  [[ "$expected_container_id" =~ ^[0-9a-f]{64}$ &&
    "$since" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$ &&
    "$until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$ &&
    "$since" < "$until" &&
    "$output" == "$expected_output" && ! -e "$output" && ! -L "$output" &&
    -d "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" &&
    ! -L "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" ]] || return 1
  observed_container_id="$(diagnostic_nondisclosure_container_id "$service")" || return $?
  [[ "$observed_container_id" == "$expected_container_id" ]] || return 1
  candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/.$service.log.capture"
  [[ ! -e "$candidate" && ! -L "$candidate" ]] || return 1
  (umask 077; : >"$candidate") || return $?
  candidate_metadata="$(stat --format='%u:%a:%h' -- "$candidate")" || return $?
  [[ "$candidate_metadata" == "$EUID:600:1" ]] || return 1
  if run_bounded "$COMPOSE_LOG_CAPTURE_TIMEOUT_SECONDS" \
    docker logs --timestamps \
      --since "$since" --until "$until" "$expected_container_id" 2>&1 |
    (
      LC_ALL=C head -c "$((maximum_bytes + 1))" \
        >"$candidate" || exit $?
      cat >/dev/null
    ); then
    :
  else
    capture_status=$?
    rm -f -- "$candidate" || return 1
    return "$capture_status"
  fi
  size="$(stat -c '%s' -- "$candidate")" || {
    capture_status=$?
    rm -f -- "$candidate" || return 1
    return "$capture_status"
  }
  if ((size < 1 || size > maximum_bytes)) ||
    ! bounded_evidence_file "$candidate" "$maximum_bytes" "$COMPOSE_LOG_MAX_LINES";
  then
    rm -f -- "$candidate" || return 1
    return 1
  fi
  observed_container_id="$(diagnostic_nondisclosure_container_id "$service")" || {
    capture_status=$?
    rm -f -- "$candidate" || return 1
    return "$capture_status"
  }
  [[ "$observed_container_id" == "$expected_container_id" ]] || {
    rm -f -- "$candidate" || return 1
    return 1
  }
  if mv -T -- "$candidate" "$output"; then
    return 0
  else
    capture_status=$?
  fi
  rm -f -- "$candidate" || return 1
  return "$capture_status"
}

assert_diagnostic_nondisclosure_obi_log_policy() {
  local -r input="$1"

  [[ -f "$input" && ! -L "$input" &&
    ( "$OBI_LOG_LEVEL" == info || "$OBI_LOG_LEVEL" == debug ) &&
    ( "$SELECTED_TRANSPORT" == getsockopt ||
      "$SELECTED_TRANSPORT" == unix ) ]] || return 1
  bounded_evidence_file \
    "$input" "$DIAGNOSTIC_NONDISCLOSURE_OBI_LOG_MAX_BYTES" \
    "$COMPOSE_LOG_MAX_LINES" || return 1
  LC_ALL=C awk \
    -v level="$OBI_LOG_LEVEL" -v transport="$SELECTED_TRANSPORT" '
    length($0) > 16384 { invalid = 1 }
    index($0, "msg=\"Java remote parent bridge ready details\"") {
      details++
      if (index($0, "transport=" transport) == 0 ||
          index($0, "socket_path=") == 0) invalid = 1
    }
    index($0, "msg=\"Java remote parent bridge ready\"") &&
      index($0, "msg=\"Java remote parent bridge ready details\"") == 0 {
      ready++
      if (index($0, "transport=" transport) == 0) invalid = 1
    }
    {
      if (index($0, "traceID=") != 0 ||
          index($0, "spanID=") != 0 ||
          index($0, " conn=") != 0 ||
          index($0, " buf=") != 0 ||
          index($0, " request=") != 0 ||
          index($0, " response=") != 0 ||
          index($0, " reqErr=") != 0 ||
          index($0, " respErr=") != 0) invalid = 1
      if (level == "info" &&
          (index($0, " level=DEBUG ") != 0 ||
           index($0, "socket_path=") != 0 ||
           index($0, " error=") != 0)) invalid = 1
    }
    END {
      if (ready != 1 ||
          (level == "info" && details != 0) ||
          (level == "debug" && details != 1)) invalid = 1
      exit invalid ? 1 : 0
    }
  ' "$input"
}

assert_diagnostic_nondisclosure_java_log_policy() {
  local -r input="$1"

  [[ -f "$input" && ! -L "$input" ]] || return 1
  bounded_evidence_file \
    "$input" "$COMPOSE_LOG_MAX_BYTES" "$COMPOSE_LOG_MAX_LINES" || return 1
  LC_ALL=C awk '
    length($0) > 16384 { invalid = 1 }
    index($0, "OBI remote-parent provider ready") { provider_ready++ }
    index($0, "OBI remote-parent propagator enabled") { propagator_ready++ }
    index($0, "Jetty HTTPS backend ready on 127.0.0.1:18443") {
      jetty_ready++
    }
    index($0, "OBI remote-parent diagnostics reason=") {
      message = $0
      sub(/^.*OBI remote-parent diagnostics reason=/, "", message)
      if (message !~ /^[a-z][a-z0-9_]{0,31} count=(0|[1-9][0-9]{0,8})$/) {
        invalid = 1
      }
    }
    END {
      if (provider_ready < 1 || propagator_ready != 1 || jetty_ready != 1) {
        invalid = 1
      }
      exit invalid ? 1 : 0
    }
  ' "$input"
}

diagnostic_nondisclosure_surface_json() {
  local -r name="$1"
  local -r reference="$2"
  local -r maximum_bytes="$3"
  local -r maximum_lines="$4"
  local -r input="${5:-$RESULT_DIR/$reference}"
  local -r expected_mode="${6:-644}"
  local metadata=""
  local size=""
  local line_count=""
  local digest=""

  [[ "$name" =~ ^[a-z][a-z_]{0,47}$ &&
    "$reference" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ &&
    ( "$expected_mode" == 600 || "$expected_mode" == 644 ) ]] || return 1
  bounded_evidence_file "$input" "$maximum_bytes" "$maximum_lines" || return 1
  metadata="$(stat --format='%u:%a:%h' -- "$input")" || return $?
  [[ "$metadata" == "$EUID:$expected_mode:1" ]] || return 1
  assert_diagnostic_nondisclosure_surface_has_no_canary "$input" || return $?
  size="$(stat -c '%s' -- "$input")" || return $?
  line_count="$(LC_ALL=C wc -l <"$input")" || return $?
  digest="$(sha256sum "$input")" || return $?
  digest="${digest%% *}"
  jq -cnS \
    --arg name "$name" --arg reference "$reference" --arg sha256 "$digest" \
    --argjson size_bytes "$size" --argjson line_count "$line_count" '
      {
        canary_match_count: 0,
        line_count: $line_count,
        name: $name,
        reference: $reference,
        schema_valid: true,
        sha256: $sha256,
        size_bytes: $size_bytes
      }
    '
}

validate_diagnostic_nondisclosure_status_payload_intrinsic() {
  local -r payload="$1"
  local canonical=""

  canonical="$(jq -ceS \
    --argjson java_max_bytes "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" \
    --argjson metrics_max_bytes "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
    --argjson metrics_max_lines "$OBI_METRIC_SNAPSHOT_MAX_LINES" \
    --argjson obi_log_max_bytes \
      "$DIAGNOSTIC_NONDISCLOSURE_OBI_LOG_MAX_BYTES" \
    --argjson log_max_bytes "$COMPOSE_LOG_MAX_BYTES" \
    --argjson log_max_lines "$COMPOSE_LOG_MAX_LINES" \
    --argjson transport_max_bytes "$TRANSPORT_CONFIGURATION_MAX_BYTES" '
      . as $report |
      if (keys == [
        "agent_distribution", "canary_bytes", "canary_count", "canary_source",
        "debug_controls", "obi_log_level", "obi_metric_boundary_ids",
        "policy", "scenario", "schema", "selected_transport", "status",
        "surfaces", "tls_protocol", "window"
      ] and
      .schema == "obi-diagnostic-nondisclosure-v1" and
      .status == "passed" and .scenario == "diagnostic-nondisclosure" and
      (.agent_distribution == "otel" or .agent_distribution == "splunk") and
      (.selected_transport == "getsockopt" or .selected_transport == "unix") and
      (.obi_log_level == "info" or .obi_log_level == "debug") and
      .tls_protocol == "TLSv1.3" and
      .obi_metric_boundary_ids == ["diagnostic-nondisclosure"] and
      (.canary_source | keys == ["reference", "sha256"]) and
      .canary_source.reference == "scenario-w3c.json" and
      (.canary_source.sha256 | type == "string" and
        test("^[0-9a-f]{64}$")) and
      (.canary_count | type == "number" and floor == . and . >= 6 and . <= 128) and
      (.canary_bytes | type == "number" and floor == . and . >= 1 and . <= 16384) and
      (.debug_controls | keys == ["bpf_debug", "protocol_debug"]) and
      .debug_controls.bpf_debug == false and
      .debug_controls.protocol_debug == false and
      (.policy | keys == [
        "log_capture_complete", "no_canary_matches",
        "runtime_configuration_attested", "surface_schemas_valid"
      ]) and all(.policy[]; . == true) and
      (.window | keys == ["since", "until"]) and
      (.window.since | type == "string" and
        test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9}Z$")) and
      (.window.until | type == "string" and
        test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9}Z$")) and
      .window.since < .window.until and
      (.surfaces | type == "array" and length == 6) and
      ([.surfaces[].name] == [
        "java_endpoint", "java_header", "java_transport_configuration",
        "obi_metrics", "obi_log", "java_log"
      ]) and
      ([.surfaces[].reference] == [
        "diagnostic-nondisclosure-java-endpoint.txt",
        "diagnostic-nondisclosure-java-header.txt",
        "diagnostic-nondisclosure-java-transport-configuration.txt",
        "diagnostic-nondisclosure-obi-metrics.prom",
        "diagnostic-nondisclosure-obi.log",
        "diagnostic-nondisclosure-java.log"
      ]) and
      all(.surfaces[];
        keys == [
          "canary_match_count", "line_count", "name", "reference",
          "schema_valid", "sha256", "size_bytes"
        ] and .canary_match_count == 0 and .schema_valid == true and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.size_bytes | type == "number" and floor == . and . >= 1) and
        (.line_count | type == "number" and floor == . and . >= 1) and
        (if .name == "java_endpoint" or .name == "java_header" then
          .size_bytes <= $java_max_bytes and .line_count == 1
         elif .name == "java_transport_configuration" then
          .size_bytes <= $transport_max_bytes and .line_count == 1
         elif .name == "obi_metrics" then
          .size_bytes <= $metrics_max_bytes and
          .line_count <= $metrics_max_lines
         elif .name == "obi_log" then
          .size_bytes <= $obi_log_max_bytes and
          .line_count <= $log_max_lines
         else
          .size_bytes <= $log_max_bytes and .line_count <= $log_max_lines
         end))
      ) then $report else error("invalid diagnostic nondisclosure status") end
    ' <<<"$payload")" || return 1
  [[ "$payload" == "$canonical" ]]
}

validate_diagnostic_nondisclosure_status_payload() {
  local -r payload="$1"
  local canary_source_sha256=""

  validate_diagnostic_nondisclosure_status_payload_intrinsic "$payload" ||
    return $?
  canary_source_sha256="$(diagnostic_nondisclosure_canary_source_sha256 \
    "$RESULT_DIR/scenario-w3c.json")" || return $?
  jq -e \
    --arg agent "$AGENT_DISTRIBUTION" \
    --arg transport "$SELECTED_TRANSPORT" \
    --arg log_level "$OBI_LOG_LEVEL" \
    --arg canary_source_sha256 "$canary_source_sha256" '
      .agent_distribution == $agent and
      .selected_transport == $transport and
      .obi_log_level == $log_level and
      .canary_source.sha256 == $canary_source_sha256
    ' <<<"$payload" >/dev/null
}

validate_diagnostic_nondisclosure_status() {
  local -r input="$1"
  local payload=""

  payload="$(read_bounded_single_line_regular_file \
    "$input" "$DIAGNOSTIC_NONDISCLOSURE_REPORT_MAX_BYTES")" || return 1
  validate_diagnostic_nondisclosure_status_payload "$payload"
}

validate_diagnostic_nondisclosure_status_hardlink_payload() {
  local -r observed_payload="$1"
  local -r expected_payload="$3"

  if [[ "$expected_payload" == __any__ ]]; then
    validate_diagnostic_nondisclosure_status_payload_intrinsic \
      "$observed_payload"
  else
    [[ "$observed_payload" == "$expected_payload" ]] || return 1
    validate_diagnostic_nondisclosure_status_payload "$observed_payload"
  fi
}

publish_diagnostic_nondisclosure_status_unlocked() {
  local -r payload="$1"
  local -r output="$RESULT_DIR/scenario-diagnostic-nondisclosure-status.json"

  [[ "${TERMINAL_EVIDENCE_LOCK_HELD_BY_CALLER:-false}" == true &&
    "${TERMINAL_EVIDENCE_LOCK_ENTRY_FROZEN:-}" == false ]] || return 1
  publish_terminal_owned_hardlink_payload \
    "$output" "$RESULT_DIR/.diagnostic-nondisclosure-report" \
    '^\.diagnostic-nondisclosure-report\.[A-Za-z0-9]{6}$' \
    '^\.diagnostic-nondisclosure-report\.[A-Za-z0-9]{6}$' \
    644 "$DIAGNOSTIC_NONDISCLOSURE_REPORT_MAX_BYTES" "$payload" \
    validate_diagnostic_nondisclosure_status_hardlink_payload true \
    "$RESULT_DIR/.diagnostic-nondisclosure-report"
}

build_diagnostic_nondisclosure_status_payload() {
  local -r surfaces="$1"
  local -r canary_count="$2"
  local -r canary_bytes="$3"
  local -r since="$4"
  local -r until="$5"
  local -r canary_source_sha256="$6"
  local payload=""

  payload="$(jq -cnS \
    --arg agent_distribution "$AGENT_DISTRIBUTION" \
    --arg selected_transport "$SELECTED_TRANSPORT" \
    --arg obi_log_level "$OBI_LOG_LEVEL" \
    --arg canary_source_sha256 "$canary_source_sha256" \
    --arg since "$since" --arg until "$until" \
    --argjson canary_count "$canary_count" \
    --argjson canary_bytes "$canary_bytes" \
    --argjson surfaces "$surfaces" '
      {
        agent_distribution: $agent_distribution,
        canary_bytes: $canary_bytes,
        canary_count: $canary_count,
        canary_source: {
          reference: "scenario-w3c.json",
          sha256: $canary_source_sha256
        },
        debug_controls: {bpf_debug: false, protocol_debug: false},
        obi_log_level: $obi_log_level,
        obi_metric_boundary_ids: ["diagnostic-nondisclosure"],
        policy: {
          log_capture_complete: true,
          no_canary_matches: true,
          runtime_configuration_attested: true,
          surface_schemas_valid: true
        },
        scenario: "diagnostic-nondisclosure",
        schema: "obi-diagnostic-nondisclosure-v1",
        selected_transport: $selected_transport,
        status: "passed",
        surfaces: $surfaces,
        tls_protocol: "TLSv1.3",
        window: {since: $since, until: $until}
      }
    ')" || return 1
  validate_diagnostic_nondisclosure_status_payload "$payload" || return 1
  printf '%s\n' "$payload"
}

publish_diagnostic_nondisclosure_status() {
  local payload=""

  payload="$(build_diagnostic_nondisclosure_status_payload "$@")" || return $?
  with_terminal_java_diagnostics_lock \
    publish_diagnostic_nondisclosure_status_unlocked "$payload"
}

stage_diagnostic_nondisclosure_surface() {
  local -r input="$1"
  local -r reference="$2"
  local -r output="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$reference"
  local metadata=""

  [[ -f "$input" && ! -L "$input" &&
    "$reference" =~ ^diagnostic-nondisclosure-[a-z0-9._-]{1,96}$ &&
    -d "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" &&
    ! -L "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR" &&
    ! -e "$output" && ! -L "$output" ]] ||
    return 1
  install -m 0600 -- "$input" "$output" || return $?
  metadata="$(stat --format='%u:%a:%h' -- "$output")" || return $?
  [[ "$metadata" == "$EUID:600:1" ]] || return 1
  cmp -s -- "$input" "$output"
}

remove_diagnostic_nondisclosure_surface_handle() {
  local -r input="$1"
  local -r output="$2"
  local -r input_identity="$3"
  local cleanup_status=1
  local attempt=0

  for attempt in 1 2 3; do
    [[ -f "$input" && ! -L "$input" &&
      -f "$output" && ! -L "$output" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$input")" == \
        "$input_identity:644:2" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$output")" == \
        "$input_identity:644:2" ]] || return 1
    if rm -f -- "$input"; then
      cleanup_status=0
    else
      cleanup_status=$?
    fi
    if [[ ! -e "$input" && ! -L "$input" ]]; then
      [[ -f "$output" && ! -L "$output" &&
        "$(stat -Lc '%d:%i:%u:%a:%h' -- "$output")" == \
          "$input_identity:644:1" ]] || return 1
      return 0
    fi
    [[ "$cleanup_status" != 0 ]] || cleanup_status=1
  done
  return "$cleanup_status"
}

publish_diagnostic_nondisclosure_surface() {
  local -r reference="$1"
  local -r expected_digest="$2"
  local -r input="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$reference"
  local -r output="$RESULT_DIR/$reference"
  local input_identity=""
  local observed_digest=""
  local publication_status=0
  local attempt=0
  local published=false

  [[ "$reference" =~ ^diagnostic-nondisclosure-[a-z0-9._-]{1,96}$ &&
    "$expected_digest" =~ ^[0-9a-f]{64}$ &&
    -f "$input" && ! -L "$input" &&
    "$(stat --format='%u:%a:%h' -- "$input")" == "$EUID:600:1" &&
    ! -e "$output" && ! -L "$output" ]] || return 1
  observed_digest="$(sha256sum "$input")" || return $?
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$expected_digest" ]] || return 1
  input_identity="$(stat -Lc '%d:%i:%u' -- "$input")" || return $?
  chmod 0644 -- "$input" || return $?
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$input")" == \
    "$input_identity:644:1" ]] || return 1
  if ln -T -- "$input" "$output"; then
    publication_status=0
  else
    publication_status=$?
  fi
  for attempt in 1 2 3; do
    if [[ -f "$input" && ! -L "$input" &&
      -f "$output" && ! -L "$output" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$input")" == \
        "$input_identity:644:2" &&
      "$(stat -Lc '%d:%i:%u:%a:%h' -- "$output")" == \
        "$input_identity:644:2" ]]; then
      published=true
      break
    fi
  done
  if [[ "$published" == true ]]; then
    remove_diagnostic_nondisclosure_surface_handle \
      "$input" "$output" "$input_identity" || return $?
    observed_digest="$(sha256sum "$output")" || return $?
    observed_digest="${observed_digest%% *}"
    [[ "$observed_digest" == "$expected_digest" ]] || return 1
    return 0
  fi
  ((publication_status != 0)) || publication_status=1
  return "$publication_status"
}

run_diagnostic_nondisclosure_control() {
  local -r scenario_result="$RESULT_DIR/scenario-w3c.json"
  local -r header_phase="diagnostic-nondisclosure-header"
  local -r endpoint_reference="diagnostic-nondisclosure-java-endpoint.txt"
  local -r header_reference="diagnostic-nondisclosure-java-header.txt"
  local -r transport_reference="diagnostic-nondisclosure-java-transport-configuration.txt"
  local -r metrics_reference="diagnostic-nondisclosure-obi-metrics.prom"
  local -r obi_log_reference="diagnostic-nondisclosure-obi.log"
  local -r java_log_reference="diagnostic-nondisclosure-java.log"
  local -r status_reference="scenario-diagnostic-nondisclosure-status.json"
  local -r parsed_metrics_name="parsed-metrics.txt"
  local -r parsed_unsorted_name="parsed-metrics.unsorted"
  local obi_container_id=""
  local java_container_id=""
  local until=""
  local canary_count=""
  local canary_bytes=""
  local canary_source_sha256=""
  local parsed_metrics=""
  local parsed_unsorted=""
  local surface=""
  local reference=""
  local expected_digest=""
  local endpoint_capture=""
  local endpoint_candidate=""
  local header_candidate=""
  local transport_candidate=""
  local metrics_candidate=""
  local obi_log_candidate=""
  local java_log_candidate=""
  local surfaces=""
  local -i surface_index=0
  local -a surface_json=()
  local -a artifact_bindings=(
    "diagnostic-java-endpoint:$endpoint_reference"
    "diagnostic-java-header:$header_reference"
    "diagnostic-java-transport:$transport_reference"
    "diagnostic-obi-metrics:$metrics_reference"
    "diagnostic-obi-log:$obi_log_reference"
    "diagnostic-java-log:$java_log_reference"
  )

  [[ "$SCENARIO" == diagnostic-nondisclosure &&
    "$TLS_PROTOCOL" == TLSv1.3 && "$KEEP_RUNNING" == false &&
    ( "$OBI_LOG_LEVEL" == info || "$OBI_LOG_LEVEL" == debug ) &&
    ( "$SELECTED_TRANSPORT" == getsockopt ||
      "$SELECTED_TRANSPORT" == unix ) &&
    "$TRANSPORT" == "$SELECTED_TRANSPORT" &&
    ! -e "$RESULT_DIR/compose.log" && ! -L "$RESULT_DIR/compose.log" &&
    ! -e "$RESULT_DIR/phases/final" && ! -L "$RESULT_DIR/phases/final" &&
    "$DIAGNOSTIC_NONDISCLOSURE_LOG_SINCE" =~ \
      ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$ ]] ||
    return 1

  obi_container_id="$(diagnostic_nondisclosure_container_id obi)" || return $?
  java_container_id="$(diagnostic_nondisclosure_container_id java-backend)" ||
    return $?
  assert_diagnostic_nondisclosure_runtime_configuration "$obi_container_id" ||
    return $?

  run_scenario w3c || return $?
  canary_source_sha256="$(diagnostic_nondisclosure_canary_source_sha256 \
    "$scenario_result")" || return $?
  create_diagnostic_nondisclosure_request_directory || return $?
  endpoint_capture="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/.java-endpoint.capture"
  endpoint_candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$endpoint_reference"
  header_candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$header_reference"
  transport_candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$transport_reference"
  metrics_candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$metrics_reference"
  obi_log_candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$obi_log_reference"
  java_log_candidate="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$java_log_reference"
  write_diagnostic_nondisclosure_canaries \
    "$scenario_result" "$canary_source_sha256" || return $?
  perform_diagnostic_nondisclosure_request || return $?
  run_diagnostic_nondisclosure_unix_probe || return $?
  capture_diagnostic_nondisclosure_java_endpoint || return $?
  stage_diagnostic_nondisclosure_surface \
    "$endpoint_capture" "$endpoint_reference" || return $?
  stage_diagnostic_nondisclosure_surface \
    "$RESULT_DIR/phases/$header_phase/java-diagnostics.txt" \
    "$header_reference" || return $?
  stage_diagnostic_nondisclosure_surface \
    "$RESULT_DIR/java-selected-transport-configuration.txt" \
    "$transport_reference" || return $?
  [[ "$(selected_transport_from_configuration \
    "$(transport_configuration_from_file "$transport_candidate")" \
    "$TRANSPORT")" == "$SELECTED_TRANSPORT" ]] || return 1

  (umask 077; : >"$metrics_candidate") || return $?
  [[ "$(stat --format='%u:%a:%h' -- "$metrics_candidate")" == \
    "$EUID:600:1" ]] || return 1
  capture_obi_metrics_candidate "$metrics_candidate" 5 || return $?
  parsed_metrics="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$parsed_metrics_name"
  parsed_unsorted="$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/$parsed_unsorted_name"
  (umask 077; : >"$parsed_metrics" && : >"$parsed_unsorted") || return $?
  parse_obi_metric_snapshot \
    "$metrics_candidate" "$parsed_metrics" "$parsed_unsorted" ||
    return $?
  LC_ALL=C awk -v transport="$SELECTED_TRANSPORT" '
    $1 == "series" && $2 == transport && $3 == "availability" &&
    $4 == "valid" && $5 ~ /^(0|[1-9][0-9]*)$/ && $5 + 0 >= 1 {
      valid++
    }
    END { exit valid == 1 ? 0 : 1 }
  ' "$parsed_metrics" || return 1

  until="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
  capture_diagnostic_nondisclosure_service_log \
    obi "$obi_container_id" "$DIAGNOSTIC_NONDISCLOSURE_LOG_SINCE" "$until" \
    "$obi_log_candidate" || return $?
  capture_diagnostic_nondisclosure_service_log \
    java-backend "$java_container_id" \
    "$DIAGNOSTIC_NONDISCLOSURE_LOG_SINCE" "$until" \
    "$java_log_candidate" || return $?
  [[ "$(diagnostic_nondisclosure_container_id obi)" == "$obi_container_id" &&
    "$(diagnostic_nondisclosure_container_id java-backend)" == \
      "$java_container_id" ]] || return 1

  assert_sanitized_java_diagnostics "$endpoint_candidate" || return $?
  assert_sanitized_java_diagnostics "$header_candidate" || return $?
  assert_diagnostic_nondisclosure_obi_log_policy \
    "$obi_log_candidate" || return $?
  assert_diagnostic_nondisclosure_java_log_policy \
    "$java_log_candidate" || return $?

  surface_json+=("$(diagnostic_nondisclosure_surface_json \
    java_endpoint "$endpoint_reference" \
    "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" \
    "$TERMINAL_JAVA_DIAGNOSTICS_MAX_LINES" "$endpoint_candidate" 600)") ||
    return $?
  surface_json+=("$(diagnostic_nondisclosure_surface_json \
    java_header "$header_reference" \
    "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" \
    "$TERMINAL_JAVA_DIAGNOSTICS_MAX_LINES" "$header_candidate" 600)") ||
    return $?
  surface_json+=("$(diagnostic_nondisclosure_surface_json \
    java_transport_configuration "$transport_reference" \
    "$TRANSPORT_CONFIGURATION_MAX_BYTES" 1 "$transport_candidate" 600)") ||
    return $?
  surface_json+=("$(diagnostic_nondisclosure_surface_json \
    obi_metrics "$metrics_reference" \
    "$OBI_METRIC_SNAPSHOT_MAX_BYTES" "$OBI_METRIC_SNAPSHOT_MAX_LINES" \
    "$metrics_candidate" 600)") ||
    return $?
  surface_json+=("$(diagnostic_nondisclosure_surface_json \
    obi_log "$obi_log_reference" \
    "$DIAGNOSTIC_NONDISCLOSURE_OBI_LOG_MAX_BYTES" \
    "$COMPOSE_LOG_MAX_LINES" \
    "$obi_log_candidate" 600)") || return $?
  surface_json+=("$(diagnostic_nondisclosure_surface_json \
    java_log "$java_log_reference" \
    "$COMPOSE_LOG_MAX_BYTES" "$COMPOSE_LOG_MAX_LINES" \
    "$java_log_candidate" 600)") || return $?
  surfaces="$(printf '%s\n' "${surface_json[@]}" | jq -ces '.')" || return 1
  [[ "$(jq -r 'length' <<<"$surfaces")" == 6 ]] || return 1
  canary_count="$(LC_ALL=C wc -l \
    <"$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/canaries.txt")" || return $?
  canary_bytes="$(stat -c '%s' -- \
    "$DIAGNOSTIC_NONDISCLOSURE_REQUEST_DIR/canaries.txt")" || return $?
  bounded_decimal \
    "$canary_count" "$DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_COUNT" false \
    >/dev/null || return 1
  bounded_decimal \
    "$canary_bytes" "$DIAGNOSTIC_NONDISCLOSURE_CANARY_MAX_BYTES" false \
    >/dev/null || return 1

  for surface_index in "${!artifact_bindings[@]}"; do
    surface="${artifact_bindings[$surface_index]}"
    reference="${surface#*:}"
    expected_digest="$(jq -er '.sha256' \
      <<<"${surface_json[$surface_index]}")" || return $?
    publish_diagnostic_nondisclosure_surface \
      "$reference" "$expected_digest" || return $?
  done
  cleanup_diagnostic_nondisclosure_request_directory || return $?
  publish_diagnostic_nondisclosure_status \
    "$surfaces" "$canary_count" "$canary_bytes" \
    "$DIAGNOSTIC_NONDISCLOSURE_LOG_SINCE" "$until" \
    "$canary_source_sha256" || return $?
  validate_diagnostic_nondisclosure_status "$RESULT_DIR/$status_reference" ||
    return $?
  for surface in "${artifact_bindings[@]}"; do
    attach_obi_artifact_capture "${surface%%:*}" "${surface#*:}" || return $?
  done
  bind_status_to_active_obi_metric_boundary "$status_reference"
}

run_obi_metric_control_boundary() {
  local -r boundary_id="$1"
  local control_status=0
  shift

  if ! obi_metric_boundary_index_is_initialized; then
    "$@"
    return $?
  fi
  if ! active_obi_metric_boundary_id >/dev/null 2>&1; then
    begin_obi_metric_boundary "$boundary_id" || return $?
  else
    [[ "$(active_obi_metric_boundary_id)" == "$boundary_id" ]] || return 1
  fi
  if "$@"; then
    :
  else
    control_status=$?
    return "$control_status"
  fi
  complete_obi_metric_boundary "$boundary_id"
}

execute_requested_scenarios() {
  local restart_since=""

  case "$SCENARIO" in
    all)
      run_scenario basic
      run_obi_metric_control_boundary \
        delayed-otlp-suppression run_delayed_otlp_suppression_control
      run_obi_metric_control_boundary security run_security_control
      run_scenario keepalive
      run_scenario pipelining
      run_scenario concurrency
      run_scenario connection-churn
      run_scenario fd-port-reuse
      run_scenario slow-body
      run_scenario tls-boundary
      run_scenario coalesced-bridge
      run_scenario timeout-retry
      run_scenario pressure
      run_scenario handoff
      run_scenario virtual-thread
      run_scenario netty
      run_scenario netty-server
      run_scenario dispatch
      run_scenario w3c
      run_obi_metric_control_boundary w3c-match run_w3c_match_control
      run_scenario obi-flags
      if [[ "$TRANSPORT" == "getsockopt" && "$SELECTED_TRANSPORT" == "getsockopt" ]]; then
        run_obi_metric_control_boundary \
          primary-w3c-stale run_primary_w3c_stale_control
        run_obi_metric_control_boundary \
          primary-generation-mismatch run_primary_generation_mismatch_control
        run_obi_metric_control_boundary \
          primary-w3c-fault run_primary_w3c_fault_control
      else
        record_unsupported_scenario \
          primary-w3c-stale "requires forced getsockopt transport"
        record_unsupported_scenario \
          primary-generation-mismatch "requires forced getsockopt transport"
        record_unsupported_scenario \
          primary-w3c-fault "requires forced getsockopt transport"
      fi
      if [[ "$TRANSPORT" == "unix" && "$SELECTED_TRANSPORT" == "unix" ]]; then
        run_obi_metric_control_boundary \
          unix-w3c-stale run_unix_w3c_stale_control
        run_obi_metric_control_boundary \
          unix-generation-mismatch run_unix_generation_mismatch_control
        run_obi_metric_control_boundary w3c-fault run_w3c_fault_control
      else
        record_unsupported_scenario \
          unix-w3c-stale "requires forced Unix transport"
        record_unsupported_scenario \
          unix-generation-mismatch "requires forced Unix transport"
        record_unsupported_scenario \
          w3c-fault "requires forced Unix transport"
      fi
      run_obi_metric_control_boundary \
        permanent-absence run_permanent_absence_control
      if [[ "$TRANSPORT" == "auto" ]]; then
        run_obi_metric_control_boundary \
          auto-unavailable run_auto_unavailable_control
      else
        record_unsupported_scenario \
          auto-unavailable "requires auto transport selection"
      fi
      run_obi_metric_control_boundary late-attach run_late_attach_control
      run_obi_metric_control_boundary \
        restart-during-traffic run_restart_during_traffic_control
      run_obi_metric_control_boundary \
        helper-attach-failure run_helper_attach_failure_control
      run_obi_metric_control_boundary disabled run_disabled_control
      run_obi_metric_control_boundary extension-controls run_extension_controls
      run_obi_metric_control_boundary uninstrumented run_uninstrumented_control
      ;;
    fail-open)
      run_obi_metric_control_boundary fail-open run_fail_open_control
      ;;
    w3c-only)
      run_obi_metric_control_boundary w3c-only run_w3c_only_control
      ;;
    restart)
      begin_obi_metric_boundary restart || return $?
      plan_obi_metric_pair_capture restart-process-replaced || return $?
      capture_phase_evidence restart-obi-before || return $?
      restart_since="$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" || return $?
      invalidate_selected_transport || return $?
      BRIDGE_RUNNING=false
      run_bounded "$OBI_COMPOSE_COMMAND_TIMEOUT_SECONDS" \
        "${COMPOSE[@]}" restart \
          --timeout "$OBI_COMPOSE_STOP_GRACE_SECONDS" obi || return $?
      OBI_RUNNING=true
      wait_for_log \
        obi \
        "Java remote parent bridge ready" \
        "restarted OBI remote-parent bridge" \
        "$restart_since" || return $?
      BRIDGE_RUNNING=true
      wait_for_apache_instrumentation restart || return $?
      wait_for_http \
        "$APACHE_HTTPS_HEALTH_ENDPOINT" \
        "restarted Java provider probe" || return $?
      sleep "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" || return $?
      wait_for_java_duplicate_suppression \
        "$RESULT_DIR/duplicate-suppression-restart.prom" || return $?
      wait_for_log \
        java-backend \
        "OBI remote-parent provider ready" \
        "restarted Java bridge provider" \
        "$restart_since" || return $?
      assert_selected_transport || return $?
      capture_phase_evidence restart-obi-after || return $?
      record_obi_metric_pair \
        restart-process-replaced restart-obi-before restart-obi-after \
        process_replaced restart-obi-after >/dev/null || return $?
      run_scenario restart
      complete_obi_metric_boundary restart
      ;;
    restart-fault)
      run_obi_metric_control_boundary \
        restart-during-traffic run_restart_during_traffic_control
      ;;
    helper-attach-failure)
      run_obi_metric_control_boundary \
        helper-attach-failure run_helper_attach_failure_control
      ;;
    delayed-otlp-suppression)
      run_obi_metric_control_boundary \
        delayed-otlp-suppression run_delayed_otlp_suppression_control
      ;;
    assertion-failure)
      run_deliberate_assertion_failure_control
      ;;
    w3c-match)
      run_obi_metric_control_boundary w3c-match run_w3c_match_control
      ;;
    w3c-fault)
      run_obi_metric_control_boundary w3c-fault run_w3c_fault_control
      ;;
    primary-w3c-stale)
      run_obi_metric_control_boundary \
        primary-w3c-stale run_primary_w3c_stale_control
      ;;
    unix-w3c-stale)
      run_obi_metric_control_boundary unix-w3c-stale run_unix_w3c_stale_control
      ;;
    unix-generation-mismatch)
      run_obi_metric_control_boundary \
        unix-generation-mismatch run_unix_generation_mismatch_control
      ;;
    pid-reuse)
      attach_obi_artifact_capture \
        pid-reuse-controller pid-reuse-controller.json || return $?
      SCENARIO_VARIANT="pid-reuse-recovery"
      run_scenario basic
      SCENARIO_VARIANT=""
      complete_obi_metric_boundary pid-reuse
      ;;
    primary-w3c-fault)
      run_obi_metric_control_boundary \
        primary-w3c-fault run_primary_w3c_fault_control
      ;;
    primary-generation-mismatch)
      run_obi_metric_control_boundary \
        primary-generation-mismatch run_primary_generation_mismatch_control
      ;;
    permanent-absence)
      run_obi_metric_control_boundary \
        permanent-absence run_permanent_absence_control
      ;;
    auto-unavailable)
      run_obi_metric_control_boundary \
        auto-unavailable run_auto_unavailable_control
      ;;
    security)
      run_obi_metric_control_boundary security run_security_control
      ;;
    diagnostic-nondisclosure)
      run_obi_metric_control_boundary \
        diagnostic-nondisclosure run_diagnostic_nondisclosure_control
      ;;
    benchmark-disabled)
      begin_obi_metric_boundary benchmark-disabled || return $?
      run_scenario concurrency true full none normal disabled
      complete_obi_metric_boundary benchmark-disabled
      ;;
    benchmark-uninstrumented)
      begin_obi_metric_boundary benchmark-uninstrumented || return $?
      run_scenario concurrency true full none normal uninstrumented
      complete_obi_metric_boundary benchmark-uninstrumented
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
    printf 'source_tree_manifest_schema=%s\n' "$SOURCE_TREE_MANIFEST_SCHEMA"
    printf 'tracked_patch_sha256=%s\n' "$SOURCE_TRACKED_PATCH_SHA256"
    printf 'patch_identity_sha256=%s\n' "$SOURCE_PATCH_SHA256"
    printf 'transport=%s\n' "$TRANSPORT"
    printf 'agent_distribution=%s\n' "$AGENT_DISTRIBUTION"
    printf 'tls_protocol=%s\n' "$TLS_PROTOCOL"
    printf 'obi_log_level=%s\n' "$OBI_LOG_LEVEL"
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
  local -r timeout_seconds="${2:-5}"

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
    log_error "refusing invalid metric evidence phase name: $phase"
    return 1
  }
  bounded_decimal "$timeout_seconds" "$MAX_SHELL_INTEGER" false >/dev/null || return 1
  capture_bounded_obi_metric_phase "$phase" "$timeout_seconds"
}

capture_phase_evidence() {
  local -r phase="$1"
  local phase_dir=""
  local service=""
  local container_id=""
  local container_pid=""
  local fd_count=""
  local metric_capture_status=0
  local stopped_attestation_status=0
  local live_metric_capture=false
  local unavailable_metric_capture=false
  local -a phase_container_ids=()

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
    log_warn "refusing invalid evidence phase name: $phase"
    return 0
  }
  phase_dir="$RESULT_DIR/phases/$phase"
  ensure_java_diagnostics_phase_directory "$phase" || return $?

  if [[ "$OBI_RUNNING" == true ||
    ( ! -e "$RESULT_DIR/obi-metric-boundary-index.json" &&
      "$BRIDGE_RUNNING" == true ) ]] &&
    capture_bounded_obi_metric_phase "$phase" 5; then
    live_metric_capture=true
  else
    metric_capture_status=$?
    if assert_compose_service_stopped obi "$phase metric-evidence boundary"; then
      if ! publish_obi_metrics_unavailable_phase "$phase"; then
        log_warn "could not publish the attested unavailable $phase OBI metrics"
        return 1
      fi
      unavailable_metric_capture=true
    else
      stopped_attestation_status=$?
      log_warn "could not capture bounded process-fenced $phase OBI metrics"
      if ((metric_capture_status != 0)); then
        return "$metric_capture_status"
      fi
      return "$stopped_attestation_status"
    fi
  fi
  [[ "$live_metric_capture" == true ||
    "$unavailable_metric_capture" == true ]] || return 1
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

  for service in obi apache-proxy java-backend coalesced-source trace-receiver; do
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
  local -r output="$phase_dir/java-diagnostics.txt"
  local -r stderr_output="$phase_dir/java-diagnostics.stderr"
  local candidate=""
  local stderr_candidate=""
  local size=""
  local capture_status=0
  local validation_status=0
  local publish_unavailable=false

  ensure_java_diagnostics_phase_directory "$phase" || return $?
  [[ ! -L "$output" && ( ! -e "$output" || -f "$output" ) &&
    ! -L "$stderr_output" &&
    ( ! -e "$stderr_output" || -f "$stderr_output" ) ]] || return 1
  candidate="$(mktemp "$phase_dir/.java-diagnostics.XXXXXX")" || return $?
  stderr_candidate="$(mktemp "$phase_dir/.java-diagnostics-stderr.XXXXXX")" || {
    capture_status=$?
    rm -f -- "$candidate" || true
    return "$capture_status"
  }
  if curl --fail --silent --show-error --max-time 5 \
    --cacert "$CERT_DIR/ca.crt" \
    "https://127.0.0.1:18443/obi-diagnostics" \
    2>"$stderr_candidate" |
    (
      LC_ALL=C head -c "$((TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES + 1))" \
        >"$candidate" || exit $?
      cat >/dev/null
    ); then
    :
  else
    capture_status=$?
    publish_unavailable=true
  fi
  if chmod 0644 -- "$stderr_candidate" &&
    mv -fT -- "$stderr_candidate" "$stderr_output"; then
    :
  else
    validation_status=$?
    rm -f -- "$candidate" "$stderr_candidate" || true
    return "$validation_status"
  fi
  if ((capture_status == 0)); then
    size="$(stat -c '%s' -- "$candidate")" || {
      validation_status=$?
      rm -f -- "$candidate" || true
      return "$validation_status"
    }
    if ((size > TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES)) ||
      ! bounded_evidence_file \
        "$candidate" \
        "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" \
        "$TERMINAL_JAVA_DIAGNOSTICS_MAX_LINES" ||
      ! assert_sanitized_java_diagnostics "$candidate"; then
      validation_status=1
      publish_unavailable=true
    fi
  fi
  if [[ "$publish_unavailable" == "true" ]]; then
    if printf 'unavailable\n' >"$candidate"; then
      :
    else
      validation_status=$?
      rm -f -- "$candidate" || true
      return "$validation_status"
    fi
  fi
  if chmod 0644 -- "$candidate" &&
    mv -fT -- "$candidate" "$output"; then
    :
  else
    validation_status=$?
    rm -f -- "$candidate" || true
    return "$validation_status"
  fi
  if ((capture_status != 0)); then
    return 0
  fi
  if ((validation_status != 0)); then
    return "$validation_status"
  fi
  record_last_java_diagnostics_phase "$phase" || return $?
  attach_obi_java_capture "$phase"
}

write_metrics_delta() {
  local -r before="$1"
  local -r after="$2"
  local -r output="$3"
  local unsorted=""

  unsorted="$(mktemp "$RESULT_DIR/.metrics-delta.XXXXXX")" || return $?
  awk '
    function wanted(metric) {
      return metric ~ /^obi_java_remote_parent_operations_total/ ||
        metric ~ /^obi_instrumentation_errors_total/ ||
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
  ' "$before" "$after" >"$unsorted" || return $?
  sort -- "$unsorted" >"$output" || return $?
  rm -f -- "$unsorted" || return $?
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
          (selected != "getsockopt" && handoff_valid != 0) ||
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

pressure_unix_already_consumed_roots_are_reconciled() {
  local -r reconciliation="$1"
  local -r expected_roots="$2"

  [[ "$expected_roots" =~ ^[1-9][0-9]*$ ]] || return 1
  jq -e -s --argjson expected_roots "$expected_roots" '
    length == 1 and
    (.[0] |
      .transport == "unix" and
      .retrieval_failure_count == $expected_roots and
      (.retrieval_failure_reason_counts | type == "object") and
      .retrieval_failure_reason_counts.already_consumed == $expected_roots and
      ([.retrieval_failure_reason_counts | to_entries[] |
        select(.key != "already_consumed" and .value != 0)] | length == 0)
    )
  ' <<<"$reconciliation" >/dev/null
}

assert_pressure_unix_already_consumed_diagnostics_delta() {
  local -r input="$1"
  local -r expected_valid="$2"
  local -r expected_missing="$3"
  local -r expected_sampled="$4"
  local -r expected_unsampled="$5"
  local -r expected_standard="$6"
  local -r expected_roots="$7"
  local actual_missing=""
  local actual_already_consumed=""

  [[ "$expected_roots" =~ ^[1-9][0-9]*$ ]] || return 1
  assert_java_diagnostics_delta \
    "$input" \
    "$expected_valid" \
    0 \
    0 \
    "$expected_missing" \
    "$expected_sampled" \
    "$expected_unsampled" \
    "$expected_standard" \
    already_consumed \
    "$expected_roots" || return $?

  actual_missing="$(java_diagnostic_delta "$input" t_missing)" || return $?
  actual_already_consumed="$(
    java_diagnostic_delta "$input" t_already_consumed
  )" || return $?
  if [[ "$actual_missing" != "$expected_missing" || \
    "$actual_already_consumed" != "$expected_roots" ]]; then
    log_error \
      "pressure diagnostics expected missing=$expected_missing already_consumed=$expected_roots, got missing=$actual_missing already_consumed=$actual_already_consumed"
    return 1
  fi
}

assert_bridge_metric_delta() {
  (( $# >= 4 && $# <= 11 )) || return 1
  local -r input="$1"
  local -r transport="$2"
  local -r expected_takes="$3"
  local -r expected_discards="$4"
  local -r expected_missing="${5:-0}"
  local -r expected_upstream="${6:-$expected_takes}"
  local -r expected_stage="${7:-$expected_upstream}"
  local -r include_ambiguous_candidates="${8:-false}"
  local -r expected_stale="${9:-0}"
  local -r expected_handoffs="${10:-0}"
  local -r expected_already_consumed="${11:-0}"

  [[ "$transport" == "getsockopt" || "$transport" == "unix" ]] || return 1
  [[ "$include_ambiguous_candidates" == "true" || \
    "$include_ambiguous_candidates" == "false" ]] || return 1
  bounded_decimal \
    "$expected_handoffs" 1000 true >/dev/null || return 1
  bounded_decimal \
    "$expected_already_consumed" 1000 true >/dev/null || return 1
  [[ "$transport" == "getsockopt" || "$expected_handoffs" == "0" ]] || return 1

  awk \
    -v selected="$transport" \
    -v wanted_takes="$expected_takes" \
    -v wanted_discards="$expected_discards" \
    -v wanted_missing="$expected_missing" \
    -v wanted_upstream="$expected_upstream" \
    -v wanted_stage="$expected_stage" \
    -v wanted_stale="$expected_stale" \
    -v wanted_handoffs="$expected_handoffs" \
    -v wanted_already_consumed="$expected_already_consumed" \
    -v include_ambiguous_candidates="$include_ambiguous_candidates" \
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
      delta_fields = 0
      for (field = 1; field <= NF; field++) {
        if ($field ~ /^delta=/) {
          delta = $field
          sub(/^delta=/, "", delta)
          delta_fields++
        }
      }
      if (delta_fields != 1 || delta !~ /^-?[0-9]+$/ || delta < 0) {
        printf "invalid bridge metric delta: %s\n", $0 > "/dev/stderr"
        failed = 1
        next
      }
      if (operation == "take" || operation == "discard") {
        security_allowed = allow_primary_security == "true" &&
          operation == "take" && status == "unauthorized" &&
          transport == "getsockopt" && selected == "getsockopt"
        security_allowed = security_allowed || (allow_unix_security == "true" &&
          operation == "take" && status ~ /^(unauthorized|timeout|overload)$/ &&
          transport == "unix" && selected == "unix")
        if (transport == selected && status == "valid") {
          if (operation == "take") {
            takes += delta
          } else {
            discards += delta
          }
        } else if (transport == selected && operation == "take" && status == "missing") {
          missing += delta
        } else if (transport == selected && operation == "take" && status == "stale") {
          stale += delta
        } else if (transport == selected && operation == "take" && status == "already_consumed") {
          already_consumed += delta
        } else if (delta != 0 && !security_allowed) {
          printf "unexpected bridge retrieval result: %s\n", $0 > "/dev/stderr"
          failed = 1
        }
        next
      }
      if (index($1, "operation=\"handoff\"") != 0) {
        handoff_rows++
        if ($1 == "obi_java_remote_parent_operations_total{operation=\"handoff\",status=\"valid\",transport=\"tcp\"}" &&
            delta ~ /^(0|[1-9][0-9]*)$/ && length(delta) <= 4 && delta + 0 <= 1000) {
          handoffs += delta
        } else if (delta != 0) {
          printf "unexpected bridge handoff result: %s\n", $0 > "/dev/stderr"
          failed = 1
        } else {
          printf "malformed bridge handoff result: %s\n", $0 > "/dev/stderr"
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
      if (operation == "candidate" && status == "ambiguous" && transport == "tcp") {
        ambiguous_candidates += delta
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
      candidate_total = candidates
      if (include_ambiguous_candidates == "true") {
        candidate_total += ambiguous_candidates
      }
      if (candidate_total != wanted_upstream || injections != wanted_upstream ||
          stages != wanted_stage ||
          takes != wanted_takes || discards != wanted_discards || missing != wanted_missing ||
          stale != wanted_stale || already_consumed != wanted_already_consumed ||
          handoffs != wanted_handoffs || handoffs > takes ||
          handoff_rows > 1) {
        printf "expected lifecycle=%d/%d/%d %s take/valid=%d discard/valid=%d take/missing=%d take/stale=%d take/already_consumed=%d handoff/tcp/valid=%d, got candidate-valid=%d candidate-ambiguous=%d inject=%d stage=%d take=%d discard=%d missing=%d stale=%d already_consumed=%d handoff=%d\n",
          wanted_upstream, wanted_upstream, wanted_stage, selected,
          wanted_takes, wanted_discards, wanted_missing, wanted_stale,
          wanted_already_consumed, wanted_handoffs,
          candidates, ambiguous_candidates, injections, stages, takes, discards, missing,
          stale, already_consumed, handoffs > "/dev/stderr"
        failed = 1
      }
      exit failed ? 1 : 0
    }
  ' "$input"
}

assert_coalesced_bridge_metric_delta() {
  local -r input="$1"
  local -r transport="$2"
  local -r outcome="$3"

  [[ -f "$input" && ! -L "$input" && \
    ( "$transport" == "getsockopt" || "$transport" == "unix" ) && \
	"$outcome" == "receive_ambiguous" ]] || return 1

  awk \
	-v selected="$transport" '
    function decimal_sum(left, right, left_index, right_index, carry, total, output) {
      left_index = length(left)
      right_index = length(right)
      carry = 0
      output = ""
      while (left_index > 0 || right_index > 0 || carry > 0) {
        total = carry
        if (left_index > 0) total += substr(left, left_index--, 1)
        if (right_index > 0) total += substr(right, right_index--, 1)
        output = (total % 10) output
        carry = int(total / 10)
      }
      return output == "" ? "0" : output
    }
    function label(line, name, value) {
      value = line
      sub("^.*" name "=\"", "", value)
      sub("\".*$", "", value)
      return value
    }
    function fail(kind, line) {
      printf "unexpected coalesced bridge %s: %s\n", kind, line > "/dev/stderr"
      failed = 1
    }
    /^obi_java_remote_parent_operations_total/ {
	  if ($0 !~ /^obi_java_remote_parent_operations_total\{operation="[a-z_]+",status="[a-z_]+",transport="(tcp|getsockopt|unix)"\} before=(0|[1-9][0-9]*) after=(0|[1-9][0-9]*) delta=(0|[1-9][0-9]*)$/) {
		fail("metric schema", $0)
		next
	  }
      operation = label($0, "operation")
      status = label($0, "status")
      transport = label($0, "transport")
	  before = $2
	  after = $3
	  delta = $NF
	  sub(/^before=/, "", before)
	  sub(/^after=/, "", after)
	  sub(/^delta=/, "", delta)
	  if ("x" decimal_sum(before, delta) != "x" after) {
		fail("metric arithmetic", $0)
		next
	  }
	  key = operation SUBSEP status SUBSEP transport
	  if (seen[key]++) fail("duplicate metric", $0)
	  lifecycle = operation == "candidate" || operation == "inject" ||
		operation == "stage" || operation == "take" ||
		operation == "discard" || operation == "handoff"
	  if (lifecycle) {
		if (delta != 0) fail("nonzero lifecycle", $0)
		next
	  }
      allowed = operation == "negotiate" && status == "missing" && transport == selected
      allowed = allowed || (operation == "cleanup" && status == "valid" && transport == "tcp")
      allowed = allowed || (operation == "report" && status == "valid" && transport == "tcp")
	  if (operation == "report" && status == "valid" && transport == "tcp") {
		report_rows++
		report_delta = delta
	  }
      if (delta != 0 && !allowed) fail("operation result", $0)
    }
	END {
	  if (report_rows != 1 || report_delta + 0 <= 0) {
		fail("missing positive report fence", "report/valid/tcp")
	  }
	  exit failed ? 1 : 0
	}
  ' "$input"
}

assert_timeout_cancellation_metric_delta() {
  local -r input="$1"
  local -r transport="$2"
  local -r outcome="$3"
  local -r expected_valid="$4"
  local -r reason="${5:-}"
  local minimum_discards=0

  [[ -f "$input" && ! -L "$input" && \
    ( "$transport" == "getsockopt" || "$transport" == "unix" ) ]] || return 1
  case "$outcome" in
    exact)
      [[ "$expected_valid" == "2" && -z "$reason" ]] || return 1
      ;;
    missing)
      [[ ( "$expected_valid" == "1" || "$expected_valid" == "2" ) && \
        -z "$reason" ]] || return 1
      ;;
    reason_coded_drop)
      [[ "$expected_valid" == "1" ]] || return 1
      case "$reason" in
        stale|unsupported|ambiguous)
          minimum_discards=0
          ;;
        missing|malformed|version_mismatch|unauthorized|already_consumed|timeout|overload|transport_error|disabled)
          minimum_discards=1
          ;;
        *) return 1 ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac

  awk \
    -v selected="$transport" \
    -v wanted_outcome="$outcome" \
    -v wanted_valid="$expected_valid" \
    -v wanted_reason="$reason" \
    -v minimum_discards="$minimum_discards" '
    function label(line, name, value) {
      value = line
      sub("^.*" name "=\"", "", value)
      sub("\".*$", "", value)
      return value
    }
    function fail(kind, line) {
      printf "unexpected timeout cancellation %s: %s\n", kind, line > "/dev/stderr"
      failed = 1
    }
    /^obi_java_remote_parent_operations_total/ {
      operation = label($0, "operation")
      status = label($0, "status")
      transport = label($0, "transport")
      delta = ""
      fields = 0
      for (field = 1; field <= NF; field++) {
        if ($field ~ /^delta=/) {
          delta = $field
          sub(/^delta=/, "", delta)
          fields++
        }
      }
      if (fields != 1 || delta !~ /^(0|[1-9][0-9]*)$/) {
        fail("metric delta", $0)
        next
      }
      if (operation == "take" || operation == "discard") {
        if (transport != selected) {
          if (delta != 0) fail("non-selected retrieval", $0)
        } else if (operation == "take") {
          if (status == "valid") take_valid += delta
          else if (delta != 0) fail("take result", $0)
        } else {
          discard_total += delta
          if (wanted_outcome == "reason_coded_drop" && status == wanted_reason) {
            reason_discard += delta
          } else if (delta != 0) {
            fail("discard result", $0)
          }
        }
        next
      }
      if (transport == "tcp" && operation == "candidate") {
        candidate_total += delta
        if (status == "valid") candidate_valid += delta
        else if (delta != 0) fail("candidate result", $0)
        next
      }
      if (transport == "tcp" && operation == "inject") {
        inject_total += delta
        if (status == "valid") inject_valid += delta
        else if (delta != 0) fail("inject result", $0)
        next
      }
      if (transport == "tcp" && operation == "stage") {
        stage_total += delta
        if (status == "valid") stage_valid += delta
        else if (delta != 0) fail("stage result", $0)
        next
      }
      if (index($1, "operation=\"handoff\"") != 0) {
        handoff_rows++
        if ($1 == "obi_java_remote_parent_operations_total{operation=\"handoff\",status=\"valid\",transport=\"tcp\"}" &&
            delta ~ /^(0|[1-9][0-9]*)$/ && length(delta) <= 1 && delta + 0 <= 2) {
          handoff_valid += delta
        } else if (delta != 0) {
          fail("handoff result", $0)
        } else {
          fail("malformed handoff result", $0)
        }
        next
      }
      allowed = operation == "negotiate" && status == "missing" && transport == selected
      allowed = allowed || (operation == "cleanup" && status == "valid" && transport == "tcp")
      allowed = allowed || (operation == "report" && status == "valid" && transport == "tcp")
      if (delta != 0 && !allowed) fail("operation result", $0)
    }
    END {
      maximum_discards = wanted_outcome == "reason_coded_drop" ? 1 : 0
      if (candidate_valid != 2 || candidate_total != 2 ||
          inject_valid != 2 || inject_total != 2 ||
          stage_valid != wanted_valid || stage_total != wanted_valid ||
          take_valid != wanted_valid || discard_total < minimum_discards ||
          discard_total > maximum_discards || reason_discard != discard_total ||
          handoff_valid > take_valid || handoff_rows > 1 ||
          (selected != "getsockopt" && handoff_valid != 0)) {
        printf "timeout cancellation metric mismatch: outcome=%s reason=%s candidate=%d/%d inject=%d/%d stage=%d/%d take=%d discard=%d reason-discard=%d handoff=%d\n",
          wanted_outcome, wanted_reason, candidate_valid, candidate_total,
          inject_valid, inject_total, stage_valid, stage_total, take_valid,
          discard_total, reason_discard, handoff_valid > "/dev/stderr"
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
  local before_snapshot=""
  local after_snapshot=""
  local before_encoded=""
  local after_encoded=""
  local -a before_entries=()
  local -a after_entries=()
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
  local index=0

  assert_sanitized_java_diagnostics "$before" || return 1
  assert_sanitized_java_diagnostics "$after" || return 1
  IFS= read -r before_snapshot <"$before"
  IFS= read -r after_snapshot <"$after"
  IFS=',' read -r -a before_entries <<<"$before_snapshot"
  IFS=',' read -r -a after_entries <<<"$after_snapshot"
  for ((index = 0; index < ${#before_entries[@]}; index++)); do
    before_encoded="${before_entries[$index]#*=}"
    after_encoded="${after_entries[$index]#*=}"
    ((36#$after_encoded >= 36#$before_encoded)) || return 1
  done
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

assert_w3c_fault_diagnostics_delta() {
  local -r input="$1"
  local -r fault_mode="$2"
  local -r expected_requests="$3"
  local expected_stale=0
  local expected_malformed=0
  local expected_fault_status=""
  local expected_fault_count=0

  bounded_decimal "$expected_requests" 1000 false >/dev/null || return 1
  case "$fault_mode" in
    alternating)
      expected_stale="$(((expected_requests + 1) / 2))"
      expected_malformed="$((expected_requests / 2))"
      ;;
    timeout)
      expected_fault_status=timeout
      expected_fault_count="$expected_requests"
      ;;
    disconnect|truncated)
      expected_fault_status=transport_error
      expected_fault_count="$expected_requests"
      ;;
    overload)
      expected_fault_status=overload
      expected_fault_count="$expected_requests"
      ;;
    bad-magic|bad-size|zero-trace-id|zero-span-id)
      expected_malformed="$expected_requests"
      ;;
    version-mismatch)
      expected_fault_status=version_mismatch
      expected_fault_count="$expected_requests"
      ;;
    generation-mismatch)
      expected_fault_status=missing
      expected_fault_count="$expected_requests"
      ;;
    *)
      return 1
      ;;
  esac
  assert_java_diagnostics_delta \
    "$input" \
    0 \
    "$expected_stale" \
    "$expected_malformed" \
    0 \
    0 \
    0 \
    0 \
    "$expected_fault_status" \
    "$expected_fault_count"
}

assert_unix_generation_mismatch_diagnostics_delta() {
  local -r input="$1"
  local -r expected_requests="$2"

  bounded_decimal "$expected_requests" 1000 false >/dev/null || return 1
  assert_java_diagnostics_delta \
    "$input" 0 0 0 0 0 0 0 already_consumed "$expected_requests"
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

assert_one_reason_coded_discard_diagnostics_delta() {
  local -r input="$1"
  local -r expected_valid="$2"
  local -r reason="$3"
  local name=""
  local actual=""
  local expected=""
  local -a failure_counters=(
    provider_reject provider_ver lookup_missing lookup_version lookup_error
    record_version invoke_error extract_fields extract_invalid extract_error
    registration_fail
  )

  case "$reason" in
    missing|stale|unsupported|malformed|version_mismatch|ambiguous|unauthorized|already_consumed|timeout|overload|transport_error|disabled)
      ;;
    *)
      return 1
      ;;
  esac
  if ! assert_java_diagnostics_delta_schema "$input"; then
    log_error "reason-coded Java diagnostics delta did not contain the exact counter schema"
    return 1
  fi
  while IFS= read -r name; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    expected=0
    if [[ "$name" == "t_valid" ]]; then
      expected="$expected_valid"
    elif [[ "$name" == "d_$reason" ]]; then
      expected=1
    fi
    if [[ "$actual" != "$expected" ]]; then
      log_error "reason-coded Java diagnostics expected $name=$expected, got $actual"
      return 1
    fi
  done < <(awk '$1 ~ /^[td]_/ { print $1 }' "$input")
  for name in "${failure_counters[@]}"; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    [[ "$actual" == "0" ]] || {
      log_error "reason-coded Java diagnostics reported unexpected $name=$actual"
      return 1
    }
  done
  [[ "$(java_diagnostic_delta "$input" take_sampled)" == "$expected_valid" && \
    "$(java_diagnostic_delta "$input" take_unsampled)" == "0" && \
    "$(java_diagnostic_delta "$input" discard_standard)" == "0" ]] || {
    log_error "reason-coded Java diagnostics changed flags or standard-parent precedence"
    return 1
  }
}

assert_coalesced_bridge_diagnostics_delta() {
  local -r input="$1"
  local -r outcome="$2"
	local name=""
	local actual=""
	local expected=""
	local -a failure_counters=(
	  provider_reject provider_ver lookup_missing lookup_version lookup_error
	  record_version invoke_error extract_fields extract_invalid extract_error
	  registration_fail
	)

	[[ "$outcome" == "receive_ambiguous" ]] || return 1
	assert_java_diagnostics_delta_schema "$input" || return 1
	while IFS= read -r name; do
	  actual="$(java_diagnostic_delta "$input" "$name")" || return 1
	  expected=0
	  if [[ "$name" == "t_missing" ]]; then
		expected=2
	  elif [[ "$name" == "d_ambiguous" ]]; then
		expected=1
	  fi
	  [[ "$actual" == "$expected" ]] || {
		log_error "coalesced receive diagnostics expected $name=$expected, got $actual"
		return 1
	  }
	done < <(awk '$1 ~ /^[td]_/ { print $1 }' "$input")
	for name in "${failure_counters[@]}"; do
	  [[ "$(java_diagnostic_delta "$input" "$name")" == "0" ]] || return 1
	done
	[[ "$(java_diagnostic_delta "$input" take_sampled)" == "0" && \
	  "$(java_diagnostic_delta "$input" take_unsampled)" == "0" && \
	  "$(java_diagnostic_delta "$input" discard_standard)" == "0" ]]
}

assert_timeout_cancellation_diagnostics_delta() {
  local -r input="$1"
  local -r reconciliation="$2"
  local outcome=""
  local valid=""
  local reason=""

  outcome="$(jq -er '.parent_outcome' <<<"$reconciliation")" || return 1
  valid="$(java_diagnostic_delta "$input" t_valid)" || return 1
  case "$outcome" in
    exact)
      [[ "$valid" == "2" ]] || {
        log_error "exact canceled request expected two valid Java takes, got $valid"
        return 1
      }
      assert_java_diagnostics_delta "$input" 2 0 0 0 2 0 0 "" 0
      ;;
    missing)
      [[ "$valid" == "1" || "$valid" == "2" ]] || {
        log_error "missing canceled request expected one or two valid Java takes, got $valid"
        return 1
      }
      assert_java_diagnostics_delta "$input" "$valid" 0 0 0 "$valid" 0 0 "" 0
      ;;
    reason_coded_drop)
      [[ "$valid" == "1" ]] || {
        log_error "reason-coded canceled request expected one valid retry take, got $valid"
        return 1
      }
      reason="$(jq -er '.drop_reasons | if length == 1 then .[0] else error("expected one drop reason") end' \
        <<<"$reconciliation")" || return 1
      assert_one_reason_coded_discard_diagnostics_delta "$input" 1 "$reason"
      ;;
    *)
      return 1
      ;;
  esac
}

assert_auto_unavailable_diagnostics_delta() {
  local -r input="$1"
  local name=""
  local actual=""
  local take_total=0
  local transport_failure_total=0
  local registration_failures=""
  local -i repeat_increment=0
  local -i take_minimum=0
  local -i take_maximum=0
  local -i registration_maximum=0
  local -a fixed_failures=(
    provider_reject provider_ver lookup_missing lookup_version lookup_error
    record_version invoke_error extract_fields extract_invalid extract_error
  )

  assert_java_diagnostics_delta_schema "$input" || return 1
  bounded_decimal "$REPEAT_COUNT" 10 false >/dev/null || return 1
  repeat_increment=$((2 * (REPEAT_COUNT - 1)))
  take_minimum=$((AUTO_UNAVAILABLE_TAKE_MIN + repeat_increment))
  take_maximum=$((AUTO_UNAVAILABLE_TAKE_MAX + repeat_increment))
  registration_maximum=$((
    AUTO_UNAVAILABLE_REGISTRATION_FAILURE_MAX + repeat_increment
  ))
  while IFS= read -r name; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    if [[ "$name" == t_* ]]; then
      take_total="$((take_total + actual))"
      case "$name" in
        t_missing|t_already_consumed)
          ;;
        t_unsupported|t_unauthorized|t_timeout|t_overload|t_transport_error)
          transport_failure_total="$((transport_failure_total + actual))"
          ;;
        *)
          ((actual == 0)) || {
            log_error "auto-unavailable diagnostics reported unexpected $name=$actual"
            return 1
          }
          ;;
      esac
    elif ((actual != 0)); then
      log_error "auto-unavailable diagnostics reported unexpected $name=$actual"
      return 1
    fi
  done < <(awk '$1 ~ /^[td]_/ { print $1 }' "$input")

  ((take_total >= take_minimum &&
    take_total <= take_maximum &&
    transport_failure_total >= 1)) || {
    log_error "auto-unavailable diagnostics did not retain a bounded attributable transport failure"
    return 1
  }
  registration_failures="$(java_diagnostic_delta "$input" registration_fail)" || return 1
  ((registration_failures >= 1 &&
    registration_failures <= registration_maximum &&
    registration_failures <= take_total)) || {
    log_error "auto-unavailable transport registration retries were unbounded or absent"
    return 1
  }
  for name in "${fixed_failures[@]}" take_sampled take_unsampled discard_standard; do
    actual="$(java_diagnostic_delta "$input" "$name")" || return 1
    ((actual == 0)) || {
      log_error "auto-unavailable diagnostics reported unexpected $name=$actual"
      return 1
    }
  done
}

assert_restart_fault_diagnostics() {
  local -r input="$1"
  local -r expected_requests="$2"
  local -r expected_non_workload_takes="$3"
  local -r output="$4"
  local name=""
  local actual=""
  local take_total=0
  local discard_total=0
  local valid=0
  local diagnostics_eligible=0
  local failure_total=0
  local take_sampled=""
  local take_unsampled=""
  local discard_standard=""
  local workload_valid_min=0
  local workload_valid_max=0
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
  take_unsampled="$(java_diagnostic_delta "$input" take_unsampled)" || return 1
  discard_standard="$(java_diagnostic_delta "$input" discard_standard)" || return 1

  if ((take_total != expected_requests + expected_non_workload_takes ||
    diagnostics_eligible == 0 ||
    valid <= expected_non_workload_takes ||
    valid >= expected_requests)); then
    log_error \
      "restart fault expected $expected_requests workload takes plus $expected_non_workload_takes probes with conservatively provable valid and fail-open workload results, got total=$take_total valid=$valid diagnostics_eligible=$diagnostics_eligible"
    return 1
  fi
  if ((discard_total != 0)); then
    log_error "restart fault produced unexpected discard status count=$discard_total"
    return 1
  fi
  if ((failure_total > expected_requests + expected_non_workload_takes)); then
    log_error "restart fault diagnostics exceeded the failure request bound"
    return 1
  fi
  if ((take_sampled + take_unsampled != valid)); then
    log_error \
      "restart fault diagnostics reported sampled totals inconsistent with valid takes"
    return 1
  fi
  workload_valid_min="$((valid - expected_non_workload_takes))"
  workload_valid_max="$valid"
  if ((discard_standard < workload_valid_min ||
    discard_standard > workload_valid_max)); then
    log_error \
      "restart fault diagnostics reported standard discards outside the valid workload bounds"
    return 1
  fi
  {
    printf 'status=passed\n'
    printf 'requests=%d\n' "$expected_requests"
    printf 'non_workload_takes=%d\n' "$expected_non_workload_takes"
    printf 'observed_take_total=%d\n' "$take_total"
    printf 'observed_take_valid=%d\n' "$valid"
    printf 'workload_valid_min=%d\n' "$workload_valid_min"
    printf 'workload_valid_max=%d\n' "$workload_valid_max"
    printf 'workload_fail_open_min=%d\n' "$((expected_requests - valid))"
    printf 'workload_fail_open_max=%d\n' \
      "$((expected_requests - valid + expected_non_workload_takes))"
    printf 'failure_total=%d\n' "$failure_total"
    printf 'take_sampled=%d\n' "$take_sampled"
    printf 'take_unsampled=%d\n' "$take_unsampled"
    printf 'discard_standard=%d\n' "$discard_standard"
  } >"$output"
}

capture_final_java_diagnostics() {
  if [[ "$FAULT_BRIDGE_RUNNING" == "true" || \
    "$PRIMARY_FAULT_STACK_ACTIVE" == "true" ]]; then
    log_warn "skipping final Java diagnostics while a fault bridge is active"
    return 0
  fi
  capture_java_diagnostics "final"
}

capture_bounded_compose_logs() {
  local -r output="$1"
  local temporary=""
  local size=""
  local capture_status=0
  local overflow=false

  [[ -n "$output" && ! -L "$output" ]] || return 1
  temporary="$(mktemp "$output.capture.XXXXXX")" || return $?
  if run_bounded "$COMPOSE_LOG_CAPTURE_TIMEOUT_SECONDS" \
    "${COMPOSE[@]}" logs --no-color --tail "$COMPOSE_LOG_MAX_LINES" 2>&1 |
    (
      LC_ALL=C head -c "$((COMPOSE_LOG_MAX_BYTES + 1))" \
        >"$temporary" || exit $?
      cat >/dev/null
    ); then
    :
  else
    capture_status=$?
  fi
  size="$(stat -c '%s' -- "$temporary")" || {
    capture_status=$?
    rm -f -- "$temporary" || true
    return "$capture_status"
  }
  if ((size > COMPOSE_LOG_MAX_BYTES)) || \
    ! bounded_evidence_file \
      "$temporary" "$COMPOSE_LOG_MAX_BYTES" "$COMPOSE_LOG_MAX_LINES"; then
    overflow=true
    retain_bounded_evidence_limits \
      "$temporary" "$COMPOSE_LOG_MAX_BYTES" "$COMPOSE_LOG_MAX_LINES" || {
      capture_status=$?
      rm -f -- "$temporary" || true
      return "$capture_status"
    }
  fi
  if chmod 0644 "$temporary" && mv -fT -- "$temporary" "$output"; then
    :
  else
    capture_status=$?
    rm -f -- "$temporary" || true
    return "$capture_status"
  fi
  if ((capture_status != 0)); then
    log_error "could not capture the complete Compose log stream"
    return "$capture_status"
  fi
  if [[ "$overflow" == "true" ]]; then
    log_error "Compose logs exceeded the retained bounds"
    return 1
  fi
  if ! bounded_evidence_file \
    "$output" "$COMPOSE_LOG_MAX_BYTES" "$COMPOSE_LOG_MAX_LINES"; then
    log_error "Compose logs exceeded the retained line bound"
    return 1
  fi
}

capture_evidence() {
  if [[ "$STACK_STARTED" == "true" ]]; then
    if [[ "$SCENARIO" != diagnostic-nondisclosure ]]; then
      capture_phase_evidence "final"
    fi
    capture_final_java_diagnostics
  fi
  run_bounded 30 "${COMPOSE[@]}" ps --all >"$RESULT_DIR/compose-ps.txt" 2>&1 || true
  if [[ "$SCENARIO" != diagnostic-nondisclosure ]]; then
    capture_bounded_compose_logs "$RESULT_DIR/compose.log" || true
  fi
  curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:14318/snapshot" >"$RESULT_DIR/final-receiver-snapshot.json" 2>/dev/null || true
}

clear_published_run_status_ownership() {
  RUN_STATUS_CREATED_IDENTITY=""
  RUN_STATUS_PUBLISHED_IDENTITY=""
  RUN_STATUS_PUBLISHED_DIGEST=""
  RUN_STATUS_PUBLICATION_HANDLE=""
  RUN_STATUS_PUBLICATION_OUTPUT=""
  RUN_STATUS_PUBLICATION_STATE=""
}

acquire_run_status_created_identity() {
  local -r output="$RESULT_DIR/run-status.json"
  local identity=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local output_identity=""
  local attempt=0

  [[ -z "$RUN_STATUS_CREATED_IDENTITY" &&
    "$RUN_STATUS_PUBLICATION_STATE" == created &&
    "$RUN_STATUS_PUBLICATION_OUTPUT" == "$output" &&
    "${RUN_STATUS_PUBLICATION_HANDLE%/*}" == "$RESULT_DIR" &&
    "${RUN_STATUS_PUBLICATION_HANDLE##*/}" =~ \
      ^\.run-status\.[A-Za-z0-9]{6}$ ]] || return 1
  for attempt in 1 2 3; do
    identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
      "$RUN_STATUS_PUBLICATION_HANDLE")" && break
    identity=""
  done
  IFS=: read -r device inode owner mode links <<<"$identity"
  [[ -n "$device" && -n "$inode" && "$owner" == "$(id -u)" &&
    ( "$mode" == 600 || "$mode" == 644 ) &&
    ( "$links" == 1 || "$links" == 2 ) &&
    -f "$RUN_STATUS_PUBLICATION_HANDLE" &&
    ! -L "$RUN_STATUS_PUBLICATION_HANDLE" ]] || return 1
  if [[ "$links" == 1 ]]; then
    [[ ! -e "$output" && ! -L "$output" ]] || return 1
  else
    [[ "$mode" == 644 && -f "$output" && ! -L "$output" &&
      "$RUN_STATUS_PUBLICATION_HANDLE" -ef "$output" ]] || return 1
    output_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$output")" || return 1
    [[ "$output_identity" == "$identity" ]] || return 1
  fi
  RUN_STATUS_CREATED_IDENTITY="$device:$inode:$owner"
}

classify_owned_run_status_publication() {
  local -r output_name="$1"
  local -r output="$RESULT_DIR/run-status.json"
  local handle_present=false
  local output_present=false
  local handle_identity=""
  local output_identity=""
  local handle_digest=""
  local output_digest=""
  local created_device=""
  local created_inode=""
  local created_owner=""
  local handle_device=""
  local handle_inode=""
  local handle_owner=""
  local handle_mode=""
  local handle_links=""
  local output_device=""
  local output_inode=""
  local output_owner=""
  local output_mode=""
  local output_links=""
  local classified_topology=""

  [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ &&
    "$RUN_STATUS_PUBLICATION_OUTPUT" == "$output" &&
    "${RUN_STATUS_PUBLICATION_HANDLE%/*}" == "$RESULT_DIR" &&
    "${RUN_STATUS_PUBLICATION_HANDLE##*/}" =~ \
      ^\.run-status\.[A-Za-z0-9]{6}$ &&
    "$RUN_STATUS_PUBLICATION_STATE" =~ \
      ^(created|prepared|validated|committed)$ ]] || return 1
  if [[ -z "$RUN_STATUS_CREATED_IDENTITY" ]]; then
    acquire_run_status_created_identity || return $?
  fi
  IFS=: read -r created_device created_inode created_owner \
    <<<"$RUN_STATUS_CREATED_IDENTITY"
  [[ -n "$created_device" && -n "$created_inode" &&
    "$created_owner" == "$(id -u)" ]] || return 1
  if [[ -e "$RUN_STATUS_PUBLICATION_HANDLE" ||
    -L "$RUN_STATUS_PUBLICATION_HANDLE" ]]; then
    [[ -f "$RUN_STATUS_PUBLICATION_HANDLE" &&
      ! -L "$RUN_STATUS_PUBLICATION_HANDLE" ]] || return 1
    handle_present=true
    handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
      "$RUN_STATUS_PUBLICATION_HANDLE")" || return 1
    IFS=: read -r handle_device handle_inode handle_owner handle_mode \
      handle_links <<<"$handle_identity"
    [[ "$handle_device:$handle_inode:$handle_owner" == \
      "$RUN_STATUS_CREATED_IDENTITY" ]] || return 1
  fi
  if [[ -e "$output" || -L "$output" ]]; then
    [[ -f "$output" && ! -L "$output" ]] || return 1
    output_present=true
    output_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$output")" || return 1
    IFS=: read -r output_device output_inode output_owner output_mode \
      output_links <<<"$output_identity"
    [[ "$output_device:$output_inode:$output_owner" == \
      "$RUN_STATUS_CREATED_IDENTITY" ]] || return 1
  fi
  if [[ "$handle_present" == false && "$output_present" == false ]]; then
    classified_topology=absent
  elif [[ "$handle_present" == true && "$output_present" == false ]]; then
    [[ "$handle_owner" == "$(id -u)" && "$handle_links" == 1 &&
      ( "$handle_mode" == 600 || "$handle_mode" == 644 ) ]] || return 1
    if [[ -n "$RUN_STATUS_PUBLISHED_IDENTITY" ||
      -n "$RUN_STATUS_PUBLISHED_DIGEST" ]]; then
      [[ "$RUN_STATUS_PUBLISHED_IDENTITY" == \
          "$handle_device:$handle_inode:$handle_owner:644" &&
        "$handle_mode" == 644 &&
        "$RUN_STATUS_PUBLISHED_DIGEST" =~ ^[0-9a-f]{64}$ ]] || return 1
      handle_digest="$(sha256sum "$RUN_STATUS_PUBLICATION_HANDLE")" ||
        return 1
      handle_digest="${handle_digest%% *}"
      [[ "$handle_digest" == "$RUN_STATUS_PUBLISHED_DIGEST" ]] || return 1
    fi
    classified_topology=private_h1
  elif [[ "$handle_present" == true && "$output_present" == true ]]; then
    [[ -n "$RUN_STATUS_PUBLISHED_IDENTITY" &&
      "$RUN_STATUS_PUBLISHED_DIGEST" =~ ^[0-9a-f]{64}$ &&
      "$RUN_STATUS_PUBLICATION_HANDLE" -ef "$output" &&
      "$handle_identity" == "$output_identity" &&
      "$handle_identity" == "$RUN_STATUS_PUBLISHED_IDENTITY:2" &&
      "$handle_owner" == "$(id -u)" && "$handle_mode" == 644 &&
      "$handle_links" == 2 && "$output_links" == 2 ]] || return 1
    handle_digest="$(sha256sum "$RUN_STATUS_PUBLICATION_HANDLE")" || return 1
    handle_digest="${handle_digest%% *}"
    output_digest="$(sha256sum "$output")" || return 1
    output_digest="${output_digest%% *}"
    [[ "$handle_digest" == "$RUN_STATUS_PUBLISHED_DIGEST" &&
      "$output_digest" == "$RUN_STATUS_PUBLISHED_DIGEST" ]] || return 1
    classified_topology=published_h2
  else
    [[ -n "$RUN_STATUS_PUBLISHED_IDENTITY" &&
      "$RUN_STATUS_PUBLISHED_DIGEST" =~ ^[0-9a-f]{64}$ &&
      "$output_identity" == "$RUN_STATUS_PUBLISHED_IDENTITY:1" &&
      "$output_owner" == "$(id -u)" && "$output_mode" == 644 &&
      "$output_links" == 1 ]] || return 1
    output_digest="$(sha256sum "$output")" || return 1
    output_digest="${output_digest%% *}"
    [[ "$output_digest" == "$RUN_STATUS_PUBLISHED_DIGEST" ]] || return 1
    classified_topology=committed_h1
  fi
  printf -v "$output_name" '%s' "$classified_topology"
}

reconcile_owned_run_status_publication() {
  local -r output_name="$1"
  local observed_topology=""
  local attempt=0

  [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || return 1
  for attempt in 1 2 3; do
    if classify_owned_run_status_publication observed_topology; then
      printf -v "$output_name" '%s' "$observed_topology"
      return 0
    fi
  done
  return 1
}

remove_terminal_owned_run_status_for_rewrite() {
  local -r output="$RESULT_DIR/run-status.json"
  local topology=""
  local handle_identity=""

  reconcile_owned_run_status_publication topology || return 1
  case "$topology" in
    absent)
      clear_published_run_status_ownership
      return 0
      ;;
    published_h2)
      remove_terminal_owned_hardlink_handle \
        "$output" "$RUN_STATUS_PUBLICATION_HANDLE" \
        "$RUN_STATUS_PUBLISHED_IDENTITY:2" || return $?
      ;;
    committed_h1)
      remove_terminal_owned_private_path \
        "$output" "$RUN_STATUS_PUBLISHED_IDENTITY:1" || return $?
      ;;
    private_h1) ;;
    *) return 1 ;;
  esac
  reconcile_owned_run_status_publication topology || return 1
  if [[ "$topology" == private_h1 ]]; then
    handle_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
      "$RUN_STATUS_PUBLICATION_HANDLE")" || return 1
    remove_terminal_owned_private_path \
      "$RUN_STATUS_PUBLICATION_HANDLE" "$handle_identity" || return $?
    reconcile_owned_run_status_publication topology || return 1
  fi
  [[ "$topology" == absent ]] || return 1
  clear_published_run_status_ownership
}

remove_published_run_status() {
  remove_terminal_owned_run_status_for_rewrite
}

commit_published_run_status() {
  local topology=""

  [[ "$RUN_STATUS_PUBLICATION_STATE" =~ ^(validated|committed)$ ]] ||
    return 1
  reconcile_owned_run_status_publication topology || return 1
  case "$topology" in
    published_h2)
      remove_terminal_owned_hardlink_handle \
        "$RUN_STATUS_PUBLICATION_HANDLE" "$RUN_STATUS_PUBLICATION_OUTPUT" \
        "$RUN_STATUS_PUBLISHED_IDENTITY:2" || return $?
      reconcile_owned_run_status_publication topology || return 1
      ;;
    committed_h1) ;;
    *) return 1 ;;
  esac
  [[ "$topology" == committed_h1 ]] || return 1
  RUN_STATUS_PUBLICATION_STATE=committed
}

publish_owned_run_status() {
  local -r exit_status="$1"
  local publication_status=0
  local cleanup_status=0

  if [[ -n "$RUN_STATUS_PUBLICATION_STATE" ||
    -n "$RUN_STATUS_CREATED_IDENTITY" ||
    -n "$RUN_STATUS_PUBLICATION_HANDLE" ]]; then
    remove_terminal_owned_run_status_for_rewrite || return $?
  fi
  if write_run_status "$exit_status"; then
    :
  else
    publication_status=$?
    if [[ -n "$RUN_STATUS_PUBLICATION_STATE" ||
      -n "$RUN_STATUS_CREATED_IDENTITY" ||
      -n "$RUN_STATUS_PUBLICATION_HANDLE" ]]; then
      remove_terminal_owned_run_status_for_rewrite || cleanup_status=$?
      ((cleanup_status == 0)) || return "$cleanup_status"
    fi
    return "$publication_status"
  fi
  commit_published_run_status
}

write_run_status() {
  local -r exit_status="$1"
  local -r output="$RESULT_DIR/run-status.json"
  local failure_stage="${FAILURE_STAGE:-none}"
  local failure_line="${FAILURE_LINE:-0}"
  local -r acceptance_evidence_reason="${ACCEPTANCE_EVIDENCE_REASON:-none}"
  local status="failed"
  local java_bridge_diagnostics=""
  local obi_metric_evidence=""
  local boundary_index_payload=""
  local boundary_index_digest=""
  local boundary_index_freeze=""
  local run_status_schema="obi-apache-java-https-run-status-v3"
  local candidate=""
  local candidate_created_identity=""
  local candidate_identity=""
  local candidate_digest=""
  local candidate_device=""
  local candidate_inode=""
  local candidate_owner=""
  local candidate_mode=""
  local candidate_links=""
  local topology=""
  local create_status=0
  local cleanup_status=0
  local publication_status=0
  local attempt=0

  if ((exit_status == 0)) && [[ "$RUN_STATUS" == "passed" ]]; then
    status="passed"
  fi
  seal_terminal_java_diagnostics || return $?
  if obi_metric_boundary_journal_paths_are_cleanly_absent; then
    # This branch is only for failures before journal initialization. A passed
    # current run must always prove closed v3 journal coverage.
    [[ "$status" != passed ]] || return 1
    run_status_schema="obi-apache-java-https-run-status-v2"
  else
    boundary_index_freeze="$(read_bounded_single_line_regular_file \
      "$RESULT_DIR/.obi-metric-boundary-index.freeze" 160)" || return 1
    [[ "$boundary_index_freeze" =~ \
      ^obi-metric-boundary-index-frozen-v1:([0-9a-f]{64})$ ]] || return 1
    boundary_index_digest="${BASH_REMATCH[1]}"
    [[ "$(sha256sum "$(obi_metric_boundary_index_path)" | awk '{print $1}')" == \
      "$boundary_index_digest" ]] || return 1
    boundary_index_payload="$(obi_metric_boundary_index_payload full)" || return 1
    OBI_METRIC_BOUNDARY_FROZEN_PAYLOAD="$boundary_index_payload"
    OBI_METRIC_BOUNDARY_FROZEN_SHA256="$boundary_index_digest"
  fi
  java_bridge_diagnostics="$(terminal_java_diagnostics_json)" || return $?
  obi_metric_evidence="$(terminal_obi_metrics_json)" || return $?
  if [[ "$status" == passed ]]; then
    jq -e '
      all(.boundaries[];
        .state == "complete" or .state == "not_applicable")
    ' <<<"$boundary_index_payload" >/dev/null || return 1
  fi
  [[ -d "$RESULT_DIR" && ! -L "$RESULT_DIR" &&
    ! -e "$output" && ! -L "$output" &&
    -z "$RUN_STATUS_CREATED_IDENTITY" &&
    -z "$RUN_STATUS_PUBLISHED_IDENTITY" &&
    -z "$RUN_STATUS_PUBLISHED_DIGEST" &&
    -z "$RUN_STATUS_PUBLICATION_HANDLE" &&
    -z "$RUN_STATUS_PUBLICATION_OUTPUT" &&
    -z "$RUN_STATUS_PUBLICATION_STATE" ]] || return 1
  if candidate="$(mktemp "$RESULT_DIR/.run-status.XXXXXX")"; then
    create_status=0
  else
    create_status=$?
  fi
  if [[ "${candidate%/*}" != "$RESULT_DIR" ||
    ! "${candidate##*/}" =~ ^\.run-status\.[A-Za-z0-9]{6}$ ||
    ! -f "$candidate" || -L "$candidate" ]]; then
    ((create_status != 0)) && return "$create_status"
    return 1
  fi
  # Register the exact private pathname before the first fallible metadata
  # read.  If that read is transiently unavailable, the next cooperative
  # reconciliation can acquire its inode token without losing the candidate.
  RUN_STATUS_PUBLICATION_HANDLE="$candidate"
  RUN_STATUS_PUBLICATION_OUTPUT="$output"
  RUN_STATUS_PUBLICATION_STATE=created
  for attempt in 1 2 3; do
    candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" &&
      break
    candidate_identity=""
  done
  IFS=: read -r candidate_device candidate_inode candidate_owner \
    candidate_mode candidate_links <<<"$candidate_identity"
  if [[ -z "$candidate_device" || -z "$candidate_inode" ||
    "$candidate_owner" != "$(id -u)" || "$candidate_mode" != 600 ||
    "$candidate_links" != 1 ]]; then
    ((create_status != 0)) && return "$create_status"
    return 1
  fi
  candidate_created_identity="$candidate_device:$candidate_inode:$candidate_owner"
  RUN_STATUS_CREATED_IDENTITY="$candidate_created_identity"
  if ((create_status != 0)); then
    remove_terminal_owned_run_status_for_rewrite || cleanup_status=$?
    ((cleanup_status == 0)) || return "$cleanup_status"
    return "$create_status"
  fi
  if jq -n \
    --arg schema "$run_status_schema" \
    --arg status "$status" \
    --argjson exit_status "$exit_status" \
    --argjson acceptance_evidence "$ACCEPTANCE_EVIDENCE" \
    --arg acceptance_evidence_reason "$acceptance_evidence_reason" \
    --arg failure_stage "$failure_stage" \
    --argjson failure_line "$failure_line" \
    --arg evidence_directory "$RESULT_DIR" \
    --arg java_bridge_diagnostics_reference 'terminal-java-diagnostics.json' \
    --argjson java_bridge_diagnostics "$java_bridge_diagnostics" \
    --arg obi_metric_evidence_reference 'terminal-obi-metrics.json' \
    --argjson obi_metric_evidence "$obi_metric_evidence" \
    --arg obi_metric_boundary_index_reference 'obi-metric-boundary-index.json' \
    --arg obi_metric_boundary_index_sha256 "$boundary_index_digest" \
    '({
      schema: $schema,
      status: $status,
      exit_status: $exit_status,
      acceptance_evidence: $acceptance_evidence,
      acceptance_evidence_reason: $acceptance_evidence_reason,
      failure_stage: $failure_stage,
      failure_line: $failure_line,
      evidence_directory: $evidence_directory,
      java_bridge_diagnostics_reference: $java_bridge_diagnostics_reference,
      java_bridge_diagnostics: $java_bridge_diagnostics,
      obi_metric_evidence_reference: $obi_metric_evidence_reference,
      obi_metric_evidence: $obi_metric_evidence
    } + if $schema == "obi-apache-java-https-run-status-v3" then {
      obi_metric_boundary_index_reference: $obi_metric_boundary_index_reference,
      obi_metric_boundary_index_sha256: $obi_metric_boundary_index_sha256
    } else {} end)' >"$candidate" && chmod 0644 -- "$candidate"; then
    :
  else
    publication_status=$?
    remove_terminal_owned_run_status_for_rewrite || cleanup_status=$?
    ((cleanup_status == 0)) || return "$cleanup_status"
    return "$publication_status"
  fi
  for attempt in 1 2 3; do
    candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" &&
      break
    candidate_identity=""
  done
  IFS=: read -r candidate_device candidate_inode candidate_owner \
    candidate_mode candidate_links <<<"$candidate_identity"
  if [[ "$candidate_device:$candidate_inode:$candidate_owner" != \
      "$candidate_created_identity" || "$candidate_mode" != 644 ||
    "$candidate_links" != 1 ]]; then
    remove_terminal_owned_run_status_for_rewrite || cleanup_status=$?
    ((cleanup_status == 0)) || return "$cleanup_status"
    return 1
  fi
  if candidate_digest="$(sha256sum "$candidate")"; then
    :
  else
    publication_status=$?
    remove_terminal_owned_run_status_for_rewrite || cleanup_status=$?
    ((cleanup_status == 0)) || return "$cleanup_status"
    return "$publication_status"
  fi
  candidate_digest="${candidate_digest%% *}"
  if [[ ! "$candidate_digest" =~ ^[0-9a-f]{64}$ ]]; then
    remove_terminal_owned_run_status_for_rewrite || cleanup_status=$?
    ((cleanup_status == 0)) || return "$cleanup_status"
    return 1
  fi
  RUN_STATUS_PUBLISHED_IDENTITY="${candidate_identity%:1}"
  RUN_STATUS_PUBLISHED_DIGEST="$candidate_digest"
  RUN_STATUS_PUBLICATION_STATE=prepared
  publication_status=1
  for attempt in 1 2 3; do
    if ln -T -- "$candidate" "$output"; then
      publication_status=1
      break
    else
      publication_status=$?
    fi
    [[ ! -e "$output" && ! -L "$output" ]] || break
  done
  if ! reconcile_owned_run_status_publication topology; then
    return "$publication_status"
  fi
  [[ "$topology" == published_h2 ]] || return "$publication_status"
  RUN_STATUS_PUBLICATION_STATE=validated
}

cleanup_only() {
  # Cleanup must use the superset model so resources declared only by an
  # optional scenario overlay (notably the private PID-reuse keystore volume)
  # cannot survive a later base-model cleanup.
  COMPOSE=("${PID_REUSE_COMPOSE[@]}")
  assert_permanent_absence_marker_matches_current_docker || return $?
  invalidate_project_transport_evidence || return $?
  BRIDGE_RUNNING=false
  log_info "stopping scoped Compose project $PROJECT_NAME"
  safe_compose_down || return $?
  OBI_RUNNING=false
  clear_pending_permanent_absence_recovery
}

run_demo() {
  local recursive_guard_launch=false

  printf -v RUN_INVOCATION '%q ' "$0" "$@"
  RUN_INVOCATION="${RUN_INVOCATION% }"
  install_traps
  RUN_STAGE="argument-validation"
  parse_args "$@"
  if [[ "${OBI_DEMO_PROJECT_GUARD_ACTIVE:-}" == 1 ]]; then
    recursive_guard_launch=true
  else
    check_dependencies
  fi
  RUN_STAGE="project-guard"
  enter_project_guard "$@" || return $?
  # The outer relay already checked dependencies. Delay the recursive check
  # until after launch acceptance so the pre-acceptance process group cannot
  # contain GNU timeout's independently grouped descendants when it is
  # cancelled and reaped.
  if [[ "$recursive_guard_launch" == true ]]; then
    check_dependencies
  fi

  if [[ "$CLEANUP_ONLY" == "true" ]]; then
    cleanup_only || return $?
    return 0
  fi
  assert_no_pending_permanent_absence_recovery || return $?

  RUN_STAGE="runtime-preparation"
  prepare_directories
  initialize_obi_metric_boundary_index || return $?
  RUN_STAGE="source-state"
  capture_source_state
  RUN_STAGE="source-snapshot"
  prepare_source_snapshot
  RUN_STAGE="certificates"
  prepare_certificates
  RUN_STAGE="official-agent"
  prepare_official_agent
  RUN_STAGE="bridge-artifacts"
  prepare_bridge_artifacts
  RUN_STAGE="source-snapshot-seal"
  seal_source_snapshot
  RUN_STAGE="compose-environment"
  export_compose_environment
  RUN_STAGE="environment-evidence"
  capture_environment
  assert_clean_source_checkout_is_stable
  if [[ "$SCENARIO" == "pid-reuse" ]]; then
    begin_obi_metric_boundary pid-reuse || return $?
  fi
  start_stack
  RUN_STAGE="scenarios"
  if [[ "$SCENARIO" == "delayed-otlp-suppression" ]]; then
    execute_requested_scenarios
    RUN_STAGE="runtime-evidence"
    capture_runtime_evidence
  else
    RUN_STAGE="runtime-evidence"
    capture_runtime_evidence
    RUN_STAGE="scenarios"
    execute_requested_scenarios
  fi
  assert_clean_source_checkout_is_stable
  RUN_STATUS="passed"
  RUN_STAGE="complete"
  log_info "all requested assertions passed; evidence: $RESULT_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  run_demo "$@"
  CLEANUP_ENTRY_ACTIVE=true
fi
