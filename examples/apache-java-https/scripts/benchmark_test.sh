#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

TEST_SOURCE="${BASH_SOURCE[0]}"
TEST_SOURCE="$(cd -- "$(dirname -- "$TEST_SOURCE")" && pwd -P)/$(basename -- "$TEST_SOURCE")"
if [[ -L "$TEST_SOURCE" ]]; then
  TEST_SOURCE="$(readlink -f -- "$TEST_SOURCE")"
fi
TEST_SCRIPT_DIR="$(cd -- "$(dirname -- "$TEST_SOURCE")" && pwd -P)"
readonly TEST_SOURCE TEST_SCRIPT_DIR
readonly FAKE_PREFLIGHT_REQUESTS=16
readonly FAKE_PRESSURE_MAP_MAX_ENTRIES=10000
readonly FAKE_REQUEST_LIMIT=1000000
readonly FAKE_SUSTAINED_LOAD_SEED=0
readonly FAKE_WORKLOAD_BASE_URL="http://127.0.0.1:18080"
readonly FAKE_WORKLOAD_PATH="/api/echo?delay_ms=150"
readonly FAKE_WORKLOAD_CONNECTION_MODE="close"
readonly FAKE_DIRECT_JAVA_WORKLOAD_BASE_URL="https://127.0.0.1:18443"
readonly FAKE_DIRECT_JAVA_WORKLOAD_CA_FILE="/benchmark-ca.crt"
readonly FAKE_REQUEST_TIMEOUT_SECONDS=10
readonly VALID_PROCESS_TREE_CAP_ARGS=(
  --process-tree-fd-absolute-max 4096
  --process-tree-task-absolute-max 2048
  --process-tree-rss-bytes-absolute-max 1073741824
  --process-tree-fd-recovery-delta-max 0
  --process-tree-task-recovery-delta-max 0
  --process-tree-rss-bytes-recovery-delta-max 0
)
readonly FAKE_JAVA_DIAGNOSTIC_COUNTER_NAMES=(
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

fake_java_diagnostics_snapshot() {
  local -r discard_standard="$1"
  local -r take_valid="$2"
  local -r discard_valid="${3:-0}"
  local -r take_missing="${4:-0}"
  local counter=""
  local -a entries=()

  for counter in "${FAKE_JAVA_DIAGNOSTIC_COUNTER_NAMES[@]}"; do
    case "$counter" in
      discard_standard) entries+=("$counter=$discard_standard") ;;
      t_valid) entries+=("$counter=$take_valid") ;;
      d_valid) entries+=("$counter=$discard_valid") ;;
      t_missing) entries+=("$counter=$take_missing") ;;
      *) entries+=("$counter=0") ;;
    esac
  done
  (IFS=,; printf '%s\n' "${entries[*]}")
}

fake_diagnostics_increment() {
  local -r discard_increment="$1"
  local -r take_valid_increment="$2"
  local -r take_missing_increment="${3:-0}"
  local discard_standard=""
  local take_valid=""
  local take_missing=""
  local extra=""

  [[ -n "${FAKE_DIAGNOSTICS_FILE:-}" && -f "$FAKE_DIAGNOSTICS_FILE" ]] || return 64
  read -r discard_standard take_valid take_missing extra <"$FAKE_DIAGNOSTICS_FILE" || return 64
  [[ "$discard_standard" =~ ^[0-9]+$ && "$take_valid" =~ ^[0-9]+$ &&
    "$take_missing" =~ ^[0-9]+$ && -z "$extra" ]] || return 64
  printf '%s %s %s\n' \
    "$((discard_standard + discard_increment))" \
    "$((take_valid + take_valid_increment))" \
    "$((take_missing + take_missing_increment))" \
    >"$FAKE_DIAGNOSTICS_FILE"
}

fake_java_runtime_snapshot() {
  local load_count=0

  if [[ -n "${FAKE_JAVA_MEASUREMENT_STATE_FILE:-}" &&
    -f "$FAKE_JAVA_MEASUREMENT_STATE_FILE" ]]; then
    load_count="$(<"$FAKE_JAVA_MEASUREMENT_STATE_FILE")"
    if [[ "$load_count" == pre ]]; then
      load_count=0
    fi
  fi
  [[ "$load_count" =~ ^[0-9]+$ ]] || return 64
  jq -cn --argjson load_count "$load_count" '{
    schema_version: 1,
    target_pid: 1,
    runtime_pid: 1,
    jvm_start_epoch_millis: 1770000000000,
    direct_buffer: {
      count: (2 + $load_count),
      memory_used_bytes: (200 + 100 * $load_count),
      total_capacity_bytes: (200 + 100 * $load_count)
    }
  }'
}

fake_jfr_summary() {
  local size=""
  local digest=""

  [[ -n "${FAKE_JFR_FILE:-}" && -f "$FAKE_JFR_FILE" &&
    ! -L "$FAKE_JFR_FILE" ]] || return 64
  size="$(stat --format '%s' -- "$FAKE_JFR_FILE")" || return 64
  digest="$(sha256sum -- "$FAKE_JFR_FILE")" || return 64
  digest="${digest%% *}"
  jq -cn --argjson size "$size" --arg digest "$digest" '{
    schema_version: 1,
    file_size_bytes: $size,
    raw_sha256: $digest,
    snapshot_semantics: "single_source_descriptor_bounded_private_copy",
    total_records: 7,
    allocation_sample: {records: 5, weight_bytes: 500},
    java_monitor_enter: {records: 1, duration_nanos: 20000000},
    thread_park: {records: 1, duration_nanos: 30000000},
    data_loss: {records: 0, bytes: 0}
  }'
}

fake_bootstrap_jfr_discard() {
  local size=""
  local digest=""

  [[ -n "${FAKE_BOOTSTRAP_JFR_FILE:-}" &&
    -f "$FAKE_BOOTSTRAP_JFR_FILE" && ! -L "$FAKE_BOOTSTRAP_JFR_FILE" ]] || return 64
  size="$(stat --format '%s' -- "$FAKE_BOOTSTRAP_JFR_FILE")" || return 64
  digest="$(sha256sum -- "$FAKE_BOOTSTRAP_JFR_FILE")" || return 64
  digest="${digest%% *}"
  [[ "$size" =~ ^[1-9][0-9]*$ && "$size" -le 33554432 ]] || return 64
  command rm -f -- "$FAKE_BOOTSTRAP_JFR_FILE" || return 64
  [[ ! -e "$FAKE_BOOTSTRAP_JFR_FILE" && ! -L "$FAKE_BOOTSTRAP_JFR_FILE" ]] || return 64
  jq -cn --argjson size "$size" --arg digest "$digest" '{
    schema_version: 1,
    status: "discarded",
    size_bytes: $size,
    sha256: $digest,
    discard_semantics: "atomic_move_then_descriptor_bounded_delete"
  }'
}

fake_jfr_formatted_size() {
  local -r file="$1"
  local size=""

  [[ -f "$file" && ! -L "$file" ]] || return 64
  size="$(stat --format '%s' -- "$file")" || return 64
  if ((size == 1)); then
    printf '1 byte\n'
  elif ((size < 1024)); then
    printf '%s bytes\n' "$size"
  elif ((size < 1024 * 1024)); then
    awk -v bytes="$size" 'BEGIN { printf "%.1f kB\n", bytes / 1024 }'
  else
    awk -v bytes="$size" 'BEGIN { printf "%.1f MB\n", bytes / 1048576 }'
  fi
}

fake_java_measurement_increment() {
  local load_count=""

  [[ -n "${FAKE_JAVA_MEASUREMENT_STATE_FILE:-}" &&
    -f "$FAKE_JAVA_MEASUREMENT_STATE_FILE" ]] || return 64
  load_count="$(<"$FAKE_JAVA_MEASUREMENT_STATE_FILE")"
  [[ "$load_count" == pre ]] && return 0
  [[ "$load_count" =~ ^[0-9]+$ ]] || return 64
  printf '%s\n' "$((load_count + 1))" >"$FAKE_JAVA_MEASUREMENT_STATE_FILE"
}

fake_bpf_metrics_increment() {
  local -r report_increment="$1"
  local -r candidate_increment="${2:-0}"
  local -r inject_increment="${3:-0}"
  local -r stage_increment="${4:-0}"
  local -r handoff_increment="${5:-0}"
  local -r take_increment="${6:-0}"
  local -r discard_increment="${7:-0}"
  local -r negotiate_missing_increment="${8:-0}"
  local -r program_executions_increment="${9:-0}"
  local -r program_runtime_nanos_increment="${10:-0}"
  local -r program_collection_passes_increment="${11:-0}"
  local report=""
  local candidate=""
  local inject=""
  local stage=""
  local handoff=""
  local take=""
  local discard=""
  local negotiate_missing=""
  local program_executions=""
  local program_runtime_nanos=""
  local program_collection_passes=""
  local extra=""

  [[ -n "${FAKE_BPF_METRICS_FILE:-}" && -f "$FAKE_BPF_METRICS_FILE" ]] || return 64
  read -r report candidate inject stage handoff take discard negotiate_missing \
    program_executions program_runtime_nanos program_collection_passes extra \
    <"$FAKE_BPF_METRICS_FILE" || return 64
  [[ "$report" =~ ^[0-9]+$ && "$candidate" =~ ^[0-9]+$ && "$inject" =~ ^[0-9]+$ &&
    "$stage" =~ ^[0-9]+$ && "$handoff" =~ ^[0-9]+$ && "$take" =~ ^[0-9]+$ &&
    "$discard" =~ ^[0-9]+$ && "$negotiate_missing" =~ ^[0-9]+$ &&
    "$program_executions" =~ ^[0-9]+$ && "$program_runtime_nanos" =~ ^[0-9]+$ &&
    "$program_collection_passes" =~ ^[0-9]+$ &&
    -z "$extra" ]] || return 64
  printf '%s %s %s %s %s %s %s %s %s %s %s\n' \
    "$((report + report_increment))" \
    "$((candidate + candidate_increment))" \
    "$((inject + inject_increment))" \
    "$((stage + stage_increment))" \
    "$((handoff + handoff_increment))" \
    "$((take + take_increment))" \
    "$((discard + discard_increment))" \
    "$((negotiate_missing + negotiate_missing_increment))" \
    "$((program_executions + program_executions_increment))" \
    "$((program_runtime_nanos + program_runtime_nanos_increment))" \
    "$((program_collection_passes + program_collection_passes_increment))" \
    >"$FAKE_BPF_METRICS_FILE"
}

fake_bpf_metrics_snapshot() {
  local report=""
  local candidate=""
  local inject=""
  local stage=""
  local handoff=""
  local take=""
  local discard=""
  local negotiate_missing=""
  local program_executions=""
  local program_runtime_nanos=""
  local program_collection_passes=""
  local program_runtime_seconds=""
  local extra=""
  local map_entries=1
  local map_max_entries=10000
  local project=""

  [[ -n "${FAKE_BPF_METRICS_FILE:-}" && -f "$FAKE_BPF_METRICS_FILE" ]] || return 64
  read -r report candidate inject stage handoff take discard negotiate_missing \
    program_executions program_runtime_nanos program_collection_passes extra \
    <"$FAKE_BPF_METRICS_FILE" || return 64
  [[ "$report" =~ ^[0-9]+$ && "$candidate" =~ ^[0-9]+$ && "$inject" =~ ^[0-9]+$ &&
    "$stage" =~ ^[0-9]+$ && "$handoff" =~ ^[0-9]+$ && "$take" =~ ^[0-9]+$ &&
    "$discard" =~ ^[0-9]+$ && "$negotiate_missing" =~ ^[0-9]+$ &&
    "$program_executions" =~ ^[0-9]+$ && "$program_runtime_nanos" =~ ^[0-9]+$ &&
    "$program_collection_passes" =~ ^[0-9]+$ &&
    -z "$extra" ]] || return 64
  printf -v program_runtime_seconds '%d.%09d' \
    "$((program_runtime_nanos / 1000000000))" "$((program_runtime_nanos % 1000000000))"
  if [[ -n "${FAKE_COMPOSE_PROJECT_FILE:-}" &&
    -f "$FAKE_COMPOSE_PROJECT_FILE" ]]; then
    project="$(<"$FAKE_COMPOSE_PROJECT_FILE")"
    if [[ "$project" == *-bridge-disabled ]]; then
      map_entries=0
      map_max_entries=1
    fi
  fi
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}'" $map_entries" \
    'obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}'" $map_max_entries" \
    "obi_bpf_probe_executions_total{probe_id=\"71\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_setsockopt\"} $program_executions" \
    "obi_bpf_probe_latency_seconds_total{probe_id=\"71\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_setsockopt\"} $program_runtime_seconds" \
    "obi_bpf_probe_collection_passes_total{probe_id=\"71\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_setsockopt\"} $program_collection_passes" \
    "obi_bpf_probe_executions_total{probe_id=\"72\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt\"} $program_executions" \
    "obi_bpf_probe_latency_seconds_total{probe_id=\"72\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt\"} $program_runtime_seconds" \
    "obi_bpf_probe_collection_passes_total{probe_id=\"72\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt\"} $program_collection_passes" \
    "obi_bpf_probe_executions_total{probe_id=\"73\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_direct_take\"} $program_executions" \
    "obi_bpf_probe_latency_seconds_total{probe_id=\"73\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_direct_take\"} $program_runtime_seconds" \
    "obi_bpf_probe_collection_passes_total{probe_id=\"73\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_direct_take\"} $program_collection_passes" \
    "obi_bpf_probe_executions_total{probe_id=\"74\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_direct_discard\"} $program_executions" \
    "obi_bpf_probe_latency_seconds_total{probe_id=\"74\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_direct_discard\"} $program_runtime_seconds" \
    "obi_bpf_probe_collection_passes_total{probe_id=\"74\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_direct_discard\"} $program_collection_passes" \
    "obi_bpf_probe_executions_total{probe_id=\"75\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_task_take\"} $program_executions" \
    "obi_bpf_probe_latency_seconds_total{probe_id=\"75\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_task_take\"} $program_runtime_seconds" \
    "obi_bpf_probe_collection_passes_total{probe_id=\"75\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_task_take\"} $program_collection_passes" \
    "obi_bpf_probe_executions_total{probe_id=\"76\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_task_discard\"} $program_executions" \
    "obi_bpf_probe_latency_seconds_total{probe_id=\"76\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_task_discard\"} $program_runtime_seconds" \
    "obi_bpf_probe_collection_passes_total{probe_id=\"76\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_task_discard\"} $program_collection_passes" \
    "obi_bpf_probe_executions_total{probe_id=\"77\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_health\"} $program_executions" \
    "obi_bpf_probe_latency_seconds_total{probe_id=\"77\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_health\"} $program_runtime_seconds" \
    "obi_bpf_probe_collection_passes_total{probe_id=\"77\",probe_type=\"CGroupSockopt\",probe_name=\"obi_java_remote_parent_getsockopt_health\"} $program_collection_passes" \
    'obi_bpf_probe_executions_total{probe_id="99",probe_type="CGroupSockopt",probe_name="foreign_fixture"} 999' \
    'obi_bpf_probe_latency_seconds_total{probe_id="99",probe_type="CGroupSockopt",probe_name="foreign_fixture"} 0.999' \
    'obi_bpf_probe_collection_passes_total{probe_id="99",probe_type="CGroupSockopt",probe_name="foreign_fixture"} 999' \
    "obi_java_remote_parent_operations_total{operation=\"candidate\",status=\"valid\",transport=\"tcp\"} $candidate" \
    "obi_java_remote_parent_operations_total{operation=\"handoff\",status=\"valid\",transport=\"tcp\"} $handoff" \
    "obi_java_remote_parent_operations_total{operation=\"inject\",status=\"valid\",transport=\"tcp\"} $inject" \
    "obi_java_remote_parent_operations_total{operation=\"negotiate\",status=\"missing\",transport=\"getsockopt\"} $negotiate_missing" \
    "obi_java_remote_parent_operations_total{operation=\"report\",status=\"valid\",transport=\"tcp\"} $report" \
    "obi_java_remote_parent_operations_total{operation=\"stage\",status=\"valid\",transport=\"tcp\"} $stage" \
    "obi_java_remote_parent_operations_total{operation=\"take\",status=\"valid\",transport=\"getsockopt\"} $take" \
    "obi_java_remote_parent_operations_total{operation=\"discard\",status=\"valid\",transport=\"getsockopt\"} $discard"
}

fake_decimal_to_base36() {
  local -r decimal="$1"
  local value="$decimal"
  local remainder=0
  local encoded=""
  local -r digits="0123456789abcdefghijklmnopqrstuvwxyz"

  [[ "$value" =~ ^[0-9]+$ ]] || return 64
  if ((value == 0)); then
    printf '0\n'
    return 0
  fi
  while ((value > 0)); do
    remainder=$((value % 36))
    encoded="${digits:remainder:1}${encoded}"
    value=$((value / 36))
  done
  printf '%s\n' "$encoded"
}

write_runner_environment() {
  local -r output="$1"
  local -r transport="$2"
  local -r agent="$3"
  local -r tls="$4"
  local -r scenario="$5"
  local -r requests="$6"
  local -r repetitions="$7"
  local -r seed="$8"
  local -r project="$9"

  {
    printf 'transport=%s\n' "$transport"
    printf 'agent_distribution=%s\n' "$agent"
    printf 'tls_protocol=%s\n' "$tls"
    printf 'scenario=%s\n' "$scenario"
    printf 'request_count=%s\n' "$requests"
    printf 'repeat_count=%s\n' "$repetitions"
    printf 'scenario_seed=%s\n' "$seed"
    printf 'compose_project=%s\n' "$project"
  } >"$output"
}

fake_w3c_sentinel_result() {
  local -r requests="$1"
  local -r seed="$2"
  local -r tls="$3"

  jq -n \
    --arg tls "$tls" \
    --argjson requests "$requests" \
    --argjson seed "$seed" '
      {
        status: "passed",
        scenario: "w3c",
        request_count: $requests,
        seed: $seed,
        cases: [range(0; $requests) as $index |
          ("w3c-" + ($index | tostring)) as $marker |
          if $index % 2 == 0 then
            {
              request: {
                marker: $marker,
                endpoint: "/api/echo",
                w3c_trace_id: "00000000000000000000000000000001",
                w3c_parent_span_id: "0000000000000001",
                w3c_trace_flags: "01",
                w3c_case: "conflicting-valid-w3c-and-obi"
              },
              response: {marker: $marker, tls_protocol: $tls},
              trace: {
                marker: $marker,
                dropped_spans: 0,
                spans: [
                  {
                    trace_id: "00000000000000000000000000000001",
                    span_id: "0000000000000002",
                    parent_span_id: "0000000000000001",
                    flags: 1,
                    service_name: "apache-proxy",
                    kind: "SERVER",
                    attributes: {
                      "http.request.header.x-obi-demo-id": $marker,
                      "url.path": "/api/echo"
                    }
                  },
                  {
                    trace_id: "00000000000000000000000000000001",
                    span_id: "0000000000000003",
                    parent_span_id: "0000000000000002",
                    flags: 1,
                    service_name: "apache-proxy",
                    kind: "CLIENT",
                    attributes: {
                      "http.request.header.x-obi-demo-id": $marker,
                      "url.full": "https://localhost:18443/api/echo"
                    }
                  },
                  {
                    trace_id: "00000000000000000000000000000001",
                    span_id: "0000000000000004",
                    parent_span_id: "0000000000000001",
                    flags: 769,
                    service_name: "java-backend",
                    kind: "SERVER",
                    attributes: {
                      "http.request.header.x-obi-demo-id": $marker,
                      "http.route": "/api/echo"
                    }
                  }
                ]
              }
            }
          else
            {
              request: {
                marker: $marker,
                endpoint: "/api/echo",
                w3c_case: "malformed-w3c-valid-obi",
                invalid_w3c: true
              },
              response: {marker: $marker, tls_protocol: $tls},
              trace: {
                marker: $marker,
                dropped_spans: 0,
                spans: [
                  {
                    trace_id: "00000000000000000000000000000005",
                    span_id: "0000000000000006",
                    flags: 1,
                    service_name: "apache-proxy",
                    kind: "SERVER",
                    attributes: {
                      "http.request.header.x-obi-demo-id": $marker,
                      "url.path": "/api/echo"
                    }
                  },
                  {
                    trace_id: "00000000000000000000000000000005",
                    span_id: "0000000000000007",
                    parent_span_id: "0000000000000006",
                    flags: 1,
                    service_name: "apache-proxy",
                    kind: "CLIENT",
                    attributes: {
                      "http.request.header.x-obi-demo-id": $marker,
                      "url.full": "https://localhost:18443/api/echo?close=1"
                    }
                  },
                  {
                    trace_id: "00000000000000000000000000000005",
                    span_id: "0000000000000008",
                    parent_span_id: "0000000000000007",
                    flags: 769,
                    service_name: "java-backend",
                    kind: "SERVER",
                    attributes: {
                      "http.request.header.x-obi-demo-id": $marker,
                      "http.route": "/api/echo"
                    }
                  }
                ]
              }
            }
          end
        ]
      }
    '
}

write_pressure_map_metrics_fixture() {
  local -r output="$1"
  local -r map_entries_count="$2"
  local -r max_entries="${3:-$FAKE_PRESSURE_MAP_MAX_ENTRIES}"

  {
    printf '%s %s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}' \
      "$map_entries_count"
    printf '%s %s\n' \
      'obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}' \
      "$max_entries"
  } >"$output"
}

write_pressure_contract_artifacts_fixture() {
  local -r runner="$1"
  local -r max_entries="$2"
  local -r project="${3:-obi-test-pressure}"
  local -r tls="${4:-TLSv1.3}"
  local -r seed="${5:-20260721}"
  local -r content_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local -r session="0123456789abcdef0123456789abcdef"
  local -r container_id="cdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdef"
  local -r result="$runner/scenario-pressure.json"
  local -r status="$runner/scenario-pressure-status.json"
  local -r inspections="$runner/map-pressure-pressure-container-inspections.json"
  local owner_gid=""
  local ready_sha256=""
  local release_sha256=""
  local fill_sha256=""
  local verify_sha256=""
  local result_sha256=""
  local status_sha256=""
  local inspections_sha256=""
  local inspections_size=""

  [[ "$max_entries" =~ ^[1-9][0-9]*$ &&
    "$project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ &&
    "$tls" =~ ^TLSv1\.[23]$ && "$seed" =~ ^(0|[1-9][0-9]*)$ &&
    -f "$result" && -f "$status" ]] || return 1
  owner_gid="$(id -g)" || return 1
  [[ "$owner_gid" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  jq '.pressure_correlation = {
    request_count: 128, exact_hit_count: 126, explicit_root_count: 1,
    w3c_parent_count: 1, wrong_parent_count: 0, unresolved_count: 0
  }' "$result" >"$result.tmp" || return 1
  mv -T -- "$result.tmp" "$result" || return 1
  jq '.pressure_correlation = {
    trace: {request_count: 128, exact_hit_count: 126, explicit_root_count: 1,
      w3c_parent_count: 1, wrong_parent_count: 0, unresolved_count: 0},
    bridge: {
      transport: "getsockopt",
      retrieval_valid_count: 127,
      attributable_failure_count: 1,
      w3c_masked_valid_count: 1,
      handoff_admission_outcome_counts: {
        overload: 5, ambiguous: 0, maximum: 1152
      }
    },
    java_reconciliation_target: {
      take_valid_count: 127, take_sampled_count: 127,
      take_unsampled_count: 0, discard_standard_count: 1,
      attributable_absence_count: 1, diagnostic_self_miss_count: 1
    },
    barrier_reference: "map-pressure-pressure-barrier-status.json"
  }' "$status" >"$status.tmp" || return 1
  mv -T -- "$status.tmp" "$status" || return 1

  jq -cn --argjson max_entries "$max_entries" '
    {status: "passed", mode: "prepare", map_id: 41,
     map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
     map_type: "Hash", max_entries: $max_entries, process_map_id: 42,
     process_pid: 43, process_namespace: 44, token_base: 1,
     synthetic_pid: 0, synthetic_namespace: 0, touched: 0}
  ' >"$runner/map-pressure-pressure-prepare.json" || return 1
  jq -cn --argjson max_entries "$max_entries" \
    --arg content_sha256 "$content_sha256" '
    {status: "passed", mode: "fill", map_id: 41,
     map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
     map_type: "Hash", max_entries: $max_entries, process_map_id: 42,
     process_pid: 43, process_namespace: 44, token_base: 1,
     synthetic_pid: 0, synthetic_namespace: 0, touched: $max_entries,
     capacity_rejected_entries: 1, verified_present_entries: $max_entries,
     content_sha256: $content_sha256, verified_absent_entries: 1}
  ' >"$runner/map-pressure-pressure-fill.json" || return 1
  jq -cn --argjson max_entries "$max_entries" \
    --arg content_sha256 "$content_sha256" '
    {status: "passed", mode: "verify", map_id: 41,
     map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
     map_type: "Hash", max_entries: $max_entries, process_map_id: 42,
     process_pid: 43, process_namespace: 44, token_base: 1,
     synthetic_pid: 0, synthetic_namespace: 0, touched: 0,
     verified_present_entries: $max_entries, content_sha256: $content_sha256,
     verified_absent_entries: 1}
  ' >"$runner/map-pressure-pressure-verify.json" || return 1
  jq -cn --argjson max_entries "$max_entries" '
    {status: "passed", mode: "cleanup", map_id: 41,
     map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
     map_type: "Hash", max_entries: $max_entries, process_map_id: 0,
     process_pid: 43, process_namespace: 44, token_base: 1,
     synthetic_pid: 0, synthetic_namespace: 0, touched: $max_entries,
     cleanup_verified: true, verified_absent_entries: ($max_entries + 1)}
  ' >"$runner/map-pressure-pressure-cleanup.json" || return 1
  : >"$runner/map-pressure-pressure-prepare.stderr.log"
  : >"$runner/map-pressure-pressure-fill.stderr.log"
  : >"$runner/map-pressure-pressure-verify.stderr.log"
  : >"$runner/map-pressure-pressure-cleanup.stderr.log"

  printf 'pressure-ready-v1:%s\n' "$session" \
    >"$runner/map-pressure-pressure-barrier-ready.txt"
  printf 'pressure-release-v1:%s\n' "$session" \
    >"$runner/map-pressure-pressure-barrier-release.txt"
  jq -cS -n --arg project "$project" --arg tls "$tls" --arg seed "$seed" \
    --arg session "$session" --arg container_id "$container_id" \
    --arg user "$EUID:$owner_gid" --argjson requests 128 '
    {
      running: {
        config: {
          cmd: ["--scenario", "pressure", "--expected-tls", $tls,
            "--seed", $seed, "--requests", ($requests | tostring),
            "--timeout", "75s", "--pressure-control-dir",
            "/run/obi-demo/pressure-control", "--pressure-control-session",
            $session, "--pressure-control-timeout", "255s"],
          entrypoint: ["/trace-scenario"], path: "/trace-scenario", user: $user
        },
        identity: {
          id: $container_id, image_id: ("sha256:" + ("b" * 64)),
          image_reference: "obi-apache-java-https-tracecheck:local",
          name: ("/" + $project + "-pressure-scenario-" + ($session[0:12]))
        },
        labels: {oneoff: "True", owner: "acceptance-demo-v1",
          project: $project, service: "scenario"},
        mount: {destination: "/run/obi-demo/pressure-control", rw: true,
          source_leaf: (".pressure-control." + $session), type: "bind"},
        runtime: {attach_stdin: false, network_mode: "host", open_stdin: false,
          pid_mode: "", privileged: false, restart_policy: "none",
          stdin_once: false, tty: false},
        state: {dead: false, error: "", exit_code: 0,
          finished_at: "0001-01-01T00:00:00Z", host_pid: 4242,
          oom_killed: false, restart_count: 0, running: true,
          started_at: "2026-08-17T00:00:00.000000001Z", status: "running"}
      },
      scenario_label: "pressure",
      schema: "pressure-scenario-container-inspections-v1",
      session: $session,
      status: "passed",
      terminal: {
        config: {
          cmd: ["--scenario", "pressure", "--expected-tls", $tls,
            "--seed", $seed, "--requests", ($requests | tostring),
            "--timeout", "75s", "--pressure-control-dir",
            "/run/obi-demo/pressure-control", "--pressure-control-session",
            $session, "--pressure-control-timeout", "255s"],
          entrypoint: ["/trace-scenario"], path: "/trace-scenario", user: $user
        },
        identity: {
          id: $container_id, image_id: ("sha256:" + ("b" * 64)),
          image_reference: "obi-apache-java-https-tracecheck:local",
          name: ("/" + $project + "-pressure-scenario-" + ($session[0:12]))
        },
        labels: {oneoff: "True", owner: "acceptance-demo-v1",
          project: $project, service: "scenario"},
        mount: {destination: "/run/obi-demo/pressure-control", rw: true,
          source_leaf: (".pressure-control." + $session), type: "bind"},
        runtime: {attach_stdin: false, network_mode: "host", open_stdin: false,
          pid_mode: "", privileged: false, restart_policy: "none",
          stdin_once: false, tty: false},
        state: {dead: false, error: "", exit_code: 0,
          finished_at: "2026-08-17T00:00:01.000000001Z", host_pid: 0,
          oom_killed: false, restart_count: 0, running: false,
          started_at: "2026-08-17T00:00:00.000000001Z", status: "exited"}
      },
      wait_exit_code: 0
    }
  ' >"$inspections" || return 1
  chmod 0600 -- "$inspections" || return 1
  mkdir -p -- "$runner/phases/pressure-before"
  write_pressure_map_metrics_fixture \
    "$runner/phases/pressure-before/obi-metrics.prom" 0 "$max_entries"
  write_pressure_map_metrics_fixture \
    "$runner/map-pressure-pressure-recovered-sample-01.prom" 0 "$max_entries"
  write_pressure_map_metrics_fixture \
    "$runner/map-pressure-pressure-recovered-sample-02.prom" 0 "$max_entries"
  command cp -- "$runner/map-pressure-pressure-recovered-sample-02.prom" \
    "$runner/map-pressure-pressure-recovered.prom"
  {
    printf 'attempt=1 observed_at=2026-08-10T00:00:00Z entries=0 matched=true consecutive=1\n'
    printf 'attempt=2 observed_at=2026-08-10T00:00:01Z entries=0 matched=true consecutive=2\n'
  } >"$runner/map-pressure-pressure-recovered-samples.log"

  ready_sha256="$(sha256sum <"$runner/map-pressure-pressure-barrier-ready.txt")" || return 1
  release_sha256="$(sha256sum <"$runner/map-pressure-pressure-barrier-release.txt")" || return 1
  fill_sha256="$(sha256sum <"$runner/map-pressure-pressure-fill.json")" || return 1
  verify_sha256="$(sha256sum <"$runner/map-pressure-pressure-verify.json")" || return 1
  result_sha256="$(sha256sum <"$result")" || return 1
  inspections_sha256="$(sha256sum <"$inspections")" || return 1
  inspections_size="$(stat -Lc '%s' -- "$inspections")" || return 1
  ready_sha256="${ready_sha256%% *}"
  release_sha256="${release_sha256%% *}"
  fill_sha256="${fill_sha256%% *}"
  verify_sha256="${verify_sha256%% *}"
  result_sha256="${result_sha256%% *}"
  inspections_sha256="${inspections_sha256%% *}"
  jq --arg inspections_sha256 "$inspections_sha256" \
    --argjson inspections_size "$inspections_size" '
    .pressure_correlation.container_inspections = {
      reference: "map-pressure-pressure-container-inspections.json",
      sha256: $inspections_sha256,
      size_bytes: $inspections_size
    }
  ' "$status" >"$status.tmp" || return 1
  mv -T -- "$status.tmp" "$status" || return 1
  status_sha256="$(sha256sum <"$status")" || return 1
  status_sha256="${status_sha256%% *}"
  jq -cS -n --arg session "$session" --argjson max_entries "$max_entries" \
    --arg content_sha256 "$content_sha256" --arg ready_sha256 "$ready_sha256" \
    --arg release_sha256 "$release_sha256" --arg fill_sha256 "$fill_sha256" \
    --arg verify_sha256 "$verify_sha256" --arg result_sha256 "$result_sha256" \
    --arg status_sha256 "$status_sha256" \
    --arg inspections_sha256 "$inspections_sha256" \
    --argjson inspections_size "$inspections_size" --arg user "$EUID:$owner_gid" \
    --arg container_id "$container_id" '
    {
      schema: "pressure-traffic-barrier-v2", status: "passed",
      scenario_label: "pressure", session: $session,
      sequence: ["scenario_ready", "capacity_fill_verified",
        "release_published", "scenario_reaped",
        "post_traffic_content_verified"],
      control: {
        ready_reference: "map-pressure-pressure-barrier-ready.txt",
        ready_sha256: $ready_sha256,
        release_reference: "map-pressure-pressure-barrier-release.txt",
        release_sha256: $release_sha256
      },
      container: {
        id: $container_id, host_pid: "4242",
        started_at: "2026-08-17T00:00:00.000000001Z", user: $user
      },
      container_inspections: {
        reference: "map-pressure-pressure-container-inspections.json",
        sha256: $inspections_sha256, size_bytes: $inspections_size
      },
      fill: {
        reference: "map-pressure-pressure-fill.json", sha256: $fill_sha256,
        map_id: "41", baseline_entries: 0, synthetic_pid: 0,
        synthetic_namespace: 0, max_entries: $max_entries,
        touched: $max_entries, verified_present_entries: $max_entries,
        verified_absent_entries: 1, content_sha256: $content_sha256,
        capacity_rejected_entries: 1
      },
      verification: {
        reference: "map-pressure-pressure-verify.json", sha256: $verify_sha256,
        map_id: "41", synthetic_pid: 0, synthetic_namespace: 0,
        verified_present_entries: $max_entries, verified_absent_entries: 1,
        content_sha256: $content_sha256
      },
      traffic: {
        result_reference: "scenario-pressure.json", result_sha256: $result_sha256,
        status_reference: "scenario-pressure-status.json",
        status_sha256: $status_sha256, request_count: 128,
        exact_hit_count: 126, explicit_root_count: 1, w3c_parent_count: 1,
        retrieval_valid_count: 127, attributable_failure_count: 1,
        w3c_masked_valid_count: 1,
        java_reconciliation_target: {
          take_valid_count: 127, take_sampled_count: 127,
          take_unsampled_count: 0, discard_standard_count: 1,
          attributable_absence_count: 1, diagnostic_self_miss_count: 1
        },
        handoff_admission_overload_count: 5,
        handoff_admission_ambiguous_count: 0,
        handoff_admission_maximum_count: 1152,
        wrong_parent_count: 0, unresolved_count: 0
      }
    }
  ' >"$runner/map-pressure-pressure-barrier-status.json"
}

refresh_pressure_contract_barrier_digests() {
  local -r runner="$1"
  local -r result="$runner/scenario-pressure.json"
  local -r status="$runner/scenario-pressure-status.json"
  local -r barrier="$runner/map-pressure-pressure-barrier-status.json"
  local result_sha256=""
  local status_sha256=""

  [[ -f "$result" && ! -L "$result" &&
    -f "$status" && ! -L "$status" &&
    -f "$barrier" && ! -L "$barrier" ]] || return 1
  result_sha256="$(sha256sum <"$result")" || return 1
  status_sha256="$(sha256sum <"$status")" || return 1
  result_sha256="${result_sha256%% *}"
  status_sha256="${status_sha256%% *}"
  jq -cS --arg result_sha256 "$result_sha256" \
    --arg status_sha256 "$status_sha256" '
      .traffic.result_sha256 = $result_sha256 |
      .traffic.status_sha256 = $status_sha256
    ' "$barrier" >"$barrier.tmp" || return 1
  mv -T -- "$barrier.tmp" "$barrier"
}

fake_write_runner_artifacts() {
  local -r result_directory="$1"
  local -r transport="$2"
  local -r agent="$3"
  local -r tls="$4"
  local -r scenario="$5"
  local -r assertion_mode="$6"
  local -r selected_transport="$7"
  local -r project="$8"
  local -r requested_requests="${9:-$FAKE_PREFLIGHT_REQUESTS}"
  local assertion_scenario="concurrency"
  local measurement_scenario="$scenario"
  local measurement_requests="$requested_requests"
  local bounded_path=false
  local ca_fingerprint=""
  local source_revision="${FAKE_GIT_REVISION:-0123456789012345678901234567890123456789}"
  local source_tree_sha256=""
  local tracked_patch_sha256=""
  local patch_identity_sha256=""
  local pressure_max_entries="${FAKE_PRESSURE_MAP_MAX_ENTRIES_OVERRIDE:-$FAKE_PRESSURE_MAP_MAX_ENTRIES}"
  local index=0

  case "$scenario" in
    w3c) assertion_scenario=w3c ;;
    primary-w3c-stale|unix-w3c-stale)
      assertion_scenario="$scenario"
      bounded_path=true
      ;;
    w3c-fault)
      assertion_scenario='w3c-fault-timeout'
      measurement_requests=1
      bounded_path=true
      ;;
    pressure)
      assertion_scenario=pressure
      bounded_path=true
      ;;
  esac
  mkdir -p -- \
    "$result_directory/phases/$assertion_scenario-before" \
    "$result_directory/phases/$assertion_scenario-after"
  jq -n --arg result_directory "$result_directory" \
    '{status: "passed", exit_status: 0, evidence_directory: $result_directory}' \
    >"$result_directory/run-status.json"
  write_runner_environment \
    "$result_directory/environment.txt" "$transport" "$agent" "$tls" "$scenario" \
    "$requested_requests" 1 "$SEED" "$project"
  if [[ -n "${FAKE_SOURCE_TREE_MANIFEST:-}" ]]; then
    [[ -f "$FAKE_SOURCE_TREE_MANIFEST" && ! -L "$FAKE_SOURCE_TREE_MANIFEST" ]] || return 64
    command cp -- "$FAKE_SOURCE_TREE_MANIFEST" "$result_directory/source-tree.manifest"
  else
    printf 'fake-source-tree\n' >"$result_directory/source-tree.manifest"
  fi
  : >"$result_directory/git-status.txt"
  source_tree_sha256="$(sha256sum -- \
    "$result_directory/source-tree.manifest")" || return 64
  source_tree_sha256="${source_tree_sha256%% *}"
  tracked_patch_sha256="$(printf '' | sha256sum)" || return 64
  tracked_patch_sha256="${tracked_patch_sha256%% *}"
  patch_identity_sha256="$({
    sha256sum -- "$result_directory/git-status.txt"
    sha256sum -- "$result_directory/source-tree.manifest"
    printf '%s\n' "$tracked_patch_sha256"
  } | sha256sum)" || return 64
  patch_identity_sha256="${patch_identity_sha256%% *}"
  {
    printf 'revision=%s\n' "$source_revision"
    printf 'dirty=false\n'
    printf 'source_tree_sha256=%s\n' "$source_tree_sha256"
    printf 'source_tree_manifest_schema=git-tree-v2\n'
    printf 'tracked_patch_sha256=%s\n' "$tracked_patch_sha256"
    printf 'patch_identity_sha256=%s\n' "$patch_identity_sha256"
  } >"$result_directory/source-state.txt"
  {
    printf 'revision=%s\n' "$source_revision"
    printf 'dirty=false\n'
    printf 'source_tree_sha256=%s\n' "$source_tree_sha256"
    printf 'source_tree_manifest_schema=git-tree-v2\n'
    printf 'tracked_patch_sha256=%s\n' "$tracked_patch_sha256"
    printf 'patch_identity_sha256=%s\n' "$patch_identity_sha256"
  } >>"$result_directory/environment.txt"
  printf '{"distribution":"otel","checksum":"fake"}\n' >"$result_directory/official-javaagent.json"
  printf '{"obi_java_agent_sha256":"fake"}\n' >"$result_directory/bridge-artifacts.json"
  printf 'fake  obi-java-agent.jar\n' >"$result_directory/bridge-artifacts.sha256"
  printf 'fake  bridge-artifacts.json\n' >"$result_directory/bridge-metadata.sha256"
  printf 'fake\n' >"$result_directory/bridge-source-revision.txt"
  printf 'fake\n' >"$result_directory/bridge-source-tree.sha256"
  if [[ -n "${FAKE_CA_FILE:-}" && -f "$FAKE_CA_FILE" ]]; then
    ca_fingerprint="$(
      openssl x509 -noout -fingerprint -sha256 -in "$FAKE_CA_FILE"
    )" || return 64
    ca_fingerprint="${ca_fingerprint#*=}"
    jq -n --arg ca_sha256 "$ca_fingerprint" '{ca_sha256: $ca_sha256}' \
      >"$result_directory/certificates.json"
  else
    printf '{"certificate":"test-only"}\n' >"$result_directory/certificates.json"
  fi
  printf 'services: {}\n' >"$result_directory/compose-resolved.yaml"
  printf 'compose up\n' >"$result_directory/compose-up.log"
  printf 'NAME STATUS\n' >"$result_directory/compose-ps.txt"
  printf 'compose logs\n' >"$result_directory/compose.log"
  printf '[]\n' >"$result_directory/compose-images.json"
  printf 'container-identities\n' >"$result_directory/container-identities.txt"
  printf 'image-identities\n' >"$result_directory/image-identities.txt"
  printf 'host-topology\n' >"$result_directory/host-topology.txt"
  printf 'bpftool=unavailable\n' >"$result_directory/bpftool-feature-probe.txt"
  printf 'bpftool=unavailable\n' >"$result_directory/bpftool-programs.txt"
  printf 'bpftool=unavailable\n' >"$result_directory/bpftool-maps.txt"
  printf 'java version "fake"\n' >"$result_directory/java-version.txt"
  printf 'Server version: Apache/fake\n' >"$result_directory/apache-version.txt"
  printf 'OpenSSL fake\n' >"$result_directory/apache-openssl-version.txt"
  printf 'obi startup\n' >"$result_directory/obi-startup.log"
  printf 'java startup\n' >"$result_directory/java-startup.log"
  printf 'apache startup\n' >"$result_directory/apache-startup.log"
  printf '{"snapshot":"fake"}\n' >"$result_directory/final-receiver-snapshot.json"
  if [[ "$transport" != disabled ]]; then
    printf 'selected_transport=%s\n' "$selected_transport" \
      >"$result_directory/java-transport-configuration.txt"
    printf 'selected_transport=%s\n' "$selected_transport" \
      >"$result_directory/java-selected-transport-configuration.txt"
  fi
  if [[ "$bounded_path" == true ]]; then
    jq -n --arg scenario "$measurement_scenario" \
      --arg tls "${FAKE_TLS_PROTOCOL:-TLSv1.3}" \
      --argjson requests "$measurement_requests" '
        {status: "passed", scenario: $scenario, request_count: $requests,
         traffic_elapsed_nanos: 1000, throughput_per_second: 1,
         latency: {p50_nanos: 1, p95_nanos: 2, p99_nanos: 3},
         cases: [range(0; $requests) |
           {latency_nanos: 1, request: {}, response: {tls_protocol: $tls}, trace: {}}]}
      ' >"$result_directory/scenario-$assertion_scenario.json"
    jq -n --arg scenario "$measurement_scenario" \
      --arg result "scenario-$assertion_scenario.json" '
        {status: "passed", scenario: $scenario, exit_status: 0,
         metric_status: 0, result: $result}
      ' >"$result_directory/scenario-$assertion_scenario-status.json"
    printf 'scenario stderr\n' \
      >"$result_directory/scenario-$assertion_scenario.stderr.log"
    if [[ "$scenario" == primary-w3c-stale || "$scenario" == unix-w3c-stale ]]; then
      jq -n '
        {status: "passed", scenario: "basic", request_count: 1,
         traffic_elapsed_nanos: 1000, throughput_per_second: 1,
         latency: {p50_nanos: 1, p95_nanos: 2, p99_nanos: 3},
         cases: [{latency_nanos: 1, request: {}, response: {}, trace: {}}]}
      ' >"$result_directory/scenario-basic-$assertion_scenario-recovery.json"
      jq -n --arg result "scenario-basic-$assertion_scenario-recovery.json" '
        {status: "passed", scenario: "basic", exit_status: 0,
         metric_status: 0, result: $result}
      ' >"$result_directory/scenario-basic-$assertion_scenario-recovery-status.json"
      : >"$result_directory/scenario-basic-$assertion_scenario-recovery.stderr.log"
    elif [[ "$scenario" == w3c-fault ]]; then
      : >"$result_directory/w3c-fault-timeout-bridge.log"
    elif [[ "$scenario" == pressure ]]; then
      write_pressure_contract_artifacts_fixture \
        "$result_directory" "$pressure_max_entries" "$project" "$tls" "$SEED"
    fi
  elif [[ "$assertion_scenario" == w3c ]]; then
    fake_w3c_sentinel_result \
      "$FAKE_PREFLIGHT_REQUESTS" "${SEED:-1}" "${FAKE_TLS_PROTOCOL:-TLSv1.3}" \
      >"$result_directory/scenario-w3c.json"
    jq -n '
      {
        status: "passed",
        scenario: "w3c",
        exit_status: 0,
        metric_status: 0,
        result: "scenario-w3c.json",
        after_phase: "phases/w3c-after"
      }
    ' >"$result_directory/scenario-w3c-status.json"
    printf 'scenario stderr\n' >"$result_directory/scenario-w3c.stderr.log"
  else
    jq -n \
      --arg assertion_mode "$assertion_mode" \
      --arg tls "${FAKE_TLS_PROTOCOL:-TLSv1.3}" \
      --argjson requests "$requested_requests" \
      --argjson seed "${SEED:-1}" \
      '{
        status: "passed",
        scenario: "concurrency",
        assertion_mode: $assertion_mode,
        request_count: $requests,
        seed: $seed,
        traffic_elapsed_nanos: 1000000,
        throughput_per_second: $requests,
        latency: {p50_nanos: 100, p95_nanos: 200, p99_nanos: 300},
        cases: [range(0; $requests) | {
          request: {},
          response: {tls_protocol: $tls},
          latency_nanos: 100,
          trace: {}
        }]
      }' >"$result_directory/scenario-concurrency.json"
    jq -n '{status: "passed", scenario: "concurrency", exit_status: 0,
      metric_status: 0, result: "scenario-concurrency.json"}' \
      >"$result_directory/scenario-concurrency-status.json"
    printf 'scenario stderr\n' >"$result_directory/scenario-concurrency.stderr.log"
  fi
  for index in before after; do
    if [[ "$scenario" == pressure && "$index" == before ]]; then
      write_pressure_map_metrics_fixture \
        "$result_directory/phases/$assertion_scenario-$index/obi-metrics.prom" \
        0 "$pressure_max_entries"
    else
      printf 'obi_java_remote_parent_operations_total 0\n' \
        >"$result_directory/phases/$assertion_scenario-$index/obi-metrics.prom"
    fi
    printf 'java-diagnostics\n' \
      >"$result_directory/phases/$assertion_scenario-$index/java-diagnostics.txt"
  done
  if [[ "$assertion_scenario" == w3c ]]; then
    printf 'discard_standard before=4 after=12 delta=8\n' \
      >"$result_directory/phases/w3c-after/java-diagnostics.delta"
  else
    for index in \
      unknown valid missing stale unsupported malformed version_mismatch ambiguous \
      unauthorized already_consumed timeout overload transport_error disabled; do
      if [[ "$bounded_path" == true ]]; then
        local bounded_delta=0
        case "$scenario:$index" in
          primary-w3c-stale:stale|unix-w3c-stale:stale|w3c-fault:timeout)
            bounded_delta=1
            ;;
          pressure:valid) bounded_delta=127 ;;
          pressure:missing) bounded_delta=2 ;;
        esac
        printf 't_%s before=0 after=%s delta=%s\n' \
          "$index" "$bounded_delta" "$bounded_delta"
      elif [[ "$index" == valid ]]; then
        printf 't_%s before=0 after=%s delta=%s\n' \
          "$index" "$requested_requests" "$requested_requests"
      elif [[ "$index" == missing ]]; then
        printf 't_%s before=0 after=1 delta=1\n' "$index"
      else
        printf 't_%s before=0 after=0 delta=0\n' "$index"
      fi
    done >"$result_directory/phases/$assertion_scenario-after/java-diagnostics.delta"
  fi
}

fake_runner() {
  local cleanup_only=false
  local transport=""
  local scenario=""
  local requests=""
  local seed=""
  local agent=""
  local tls=""
  local keep=false
  local assertion_mode="bridge"
  local selected_transport=""
  local result_directory=""
  local project="${COMPOSE_PROJECT_NAME:-}"

  while (($# > 0)); do
    case "$1" in
      --cleanup-only)
        cleanup_only=true
        shift
        ;;
      --transport)
        transport="$2"
        shift 2
        ;;
      --scenario)
        scenario="$2"
        shift 2
        ;;
      --requests)
        requests="$2"
        shift 2
        ;;
      --seed)
        seed="$2"
        shift 2
        ;;
      --keep)
        keep=true
        shift
        ;;
      --agent)
        agent="$2"
        shift 2
        ;;
      --tls)
        tls="$2"
        shift 2
        ;;
      --command-timeout|--readiness-timeout)
        shift 2
        ;;
      *)
        printf 'unexpected fake runner argument: %s\n' "$1" >&2
        return 64
        ;;
    esac
  done
  if [[ "$cleanup_only" == "true" ]]; then
    printf 'cleanup %s\n' "$project" >>"$FAKE_EVENTS"
    return 0
  fi
  [[ "$project" =~ ^obi-apache-java-https-b-[0-9]+-[0-9]+-[a-z0-9-]+$ &&
    "$requests" =~ ^[0-9]+$ && "$keep" == "true" && -n "$seed" &&
    ("$agent" == otel || "$agent" == splunk) && ("$tls" == TLSv1.2 || "$tls" == TLSv1.3) ]] || {
    printf 'invalid fake runner invocation\n' >&2
    return 64
  }
  if [[ -n "${FAKE_COMPOSE_PROJECT_FILE:-}" ]]; then
    local project_temporary=""
    project_temporary="$(mktemp -- "${FAKE_COMPOSE_PROJECT_FILE}.tmp.XXXXXX")" || return 64
    printf '%s\n' "$project" >"$project_temporary" || {
      rm -f -- "$project_temporary"
      return 64
    }
    mv -f -- "$project_temporary" "$FAKE_COMPOSE_PROJECT_FILE" || {
      rm -f -- "$project_temporary"
      return 64
    }
  fi
  case "$scenario" in
    benchmark-uninstrumented)
      [[ "$transport" == disabled ]] || return 64
      assertion_mode="uninstrumented"
      selected_transport="disabled"
      ;;
    benchmark-disabled)
      [[ "$transport" == disabled ]] || return 64
      assertion_mode="disabled"
      selected_transport="disabled"
      ;;
    concurrency)
      [[ "$transport" == getsockopt || "$transport" == unix ]] || return 64
      assertion_mode="bridge"
      selected_transport="$transport"
      ;;
    w3c)
      [[ "$transport" == getsockopt && "$requests" == "$FAKE_PREFLIGHT_REQUESTS" ]] || return 64
      assertion_mode="bridge"
      selected_transport="$transport"
      ;;
    primary-w3c-stale)
      [[ "$transport" == getsockopt && "$requests" == 1 ]] || return 64
      selected_transport=getsockopt
      ;;
    unix-w3c-stale)
      [[ "$transport" == unix && "$requests" == 1 ]] || return 64
      selected_transport=unix
      ;;
    w3c-fault)
      [[ "$transport" == unix && "$requests" == 2 ]] || return 64
      selected_transport=unix
      ;;
    pressure)
      [[ "$transport" == getsockopt && "$requests" == 128 ]] || return 64
      selected_transport=getsockopt
      ;;
    *)
      return 64
      ;;
  esac
  case "$scenario" in
    primary-w3c-stale|unix-w3c-stale|w3c-fault|pressure)
      [[ "${JAVA_IMAGE_TARGET:-}" == runtime &&
        "${JAVA_BACKEND_IMAGE:-}" == obi-apache-java-https-backend:local &&
        -z "${JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX:-}" ]] || return 64
      printf 'java-runtime default %s\n' "$scenario" >>"$FAKE_RUNNER_LOG"
      ;;
    *)
      [[ "${JAVA_IMAGE_TARGET:-}" == benchmark-runtime &&
        "${JAVA_BACKEND_IMAGE:-}" == \
          obi-apache-java-https-backend-benchmark:local &&
        "${JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX:-}" == \
          ' -XX:NativeMemoryTracking=summary -XX:StartFlightRecording=name=obi-benchmark-bootstrap,settings=/otel/obi-benchmark.jfc,filename=/tmp/obi-benchmark-bootstrap.jfr,disk=true,dumponexit=false,duration=3600s,maxsize=32m' &&
        -n "${FAKE_BOOTSTRAP_JFR_FILE:-}" ]] || return 64
      printf 'FLR-fake-bounded-bootstrap-recording\n' >"$FAKE_BOOTSTRAP_JFR_FILE"
      printf 'java-runtime benchmark %s\n' "$scenario" >>"$FAKE_RUNNER_LOG"
      ;;
  esac
  [[ -n "${FAKE_JAVA_MEASUREMENT_STATE_FILE:-}" ]] || return 64
  printf 'pre\n' >"$FAKE_JAVA_MEASUREMENT_STATE_FILE"
  result_directory="$FAKE_RESULTS_ROOT/$project"
  SEED="$seed"
  fake_write_runner_artifacts \
    "$result_directory" "$transport" "$agent" "$tls" "$scenario" "$assertion_mode" \
    "$selected_transport" "$project" "$requests"
  printf 'start %s %s %s\n' "$project" "$transport" "$scenario" >>"$FAKE_RUNNER_LOG"
  printf 'start %s %s %s\n' "$project" "$transport" "$scenario" >>"$FAKE_EVENTS"
  printf '[fake] INFO: retained run evidence: %s\n' "$result_directory" >&2
}

fake_benchmark_result() {
  local base_url=""
  local duration=""
  local concurrency=""
  local request_limit=""
  local seed=""
  local path=""
  local connection_mode=""
  local ca_file=""
  local w3c="unset"

  while (($# > 0)); do
    case "$1" in
      --duration)
        duration="${2%s}"
        shift 2
        ;;
      --concurrency)
        concurrency="$2"
        shift 2
        ;;
      --request-limit)
        request_limit="$2"
        shift 2
        ;;
      --seed)
        seed="$2"
        shift 2
        ;;
      --path)
        path="$2"
        shift 2
        ;;
      --base-url)
        base_url="$2"
        shift 2
        ;;
      --ca-file)
        ca_file="$2"
        shift 2
        ;;
      --connection-mode)
        connection_mode="$2"
        shift 2
        ;;
      --w3c=false|--w3c=true)
        w3c="${1#--w3c=}"
        shift
        ;;
      --request-timeout)
        shift 2
        ;;
      *)
        printf 'unexpected fake benchmark argument: %s\n' "$1" >&2
        return 64
        ;;
    esac
  done
  [[ "$duration" =~ ^[0-9]+$ && "$concurrency" =~ ^[0-9]+$ &&
    "$request_limit" == "$FAKE_REQUEST_LIMIT" && "$seed" == "$FAKE_SUSTAINED_LOAD_SEED" &&
    "$path" == "$FAKE_WORKLOAD_PATH" && "$connection_mode" == "$FAKE_WORKLOAD_CONNECTION_MODE" &&
    ( "$w3c" == false || "$w3c" == true ) ]] || return 64
  case "$base_url" in
    "$FAKE_WORKLOAD_BASE_URL")
      [[ -z "$ca_file" ]] || return 64
      ;;
    "$FAKE_DIRECT_JAVA_WORKLOAD_BASE_URL")
      [[ "$ca_file" == "$FAKE_DIRECT_JAVA_WORKLOAD_CA_FILE" && "$w3c" == false ]] || return 64
      fake_diagnostics_increment 0 0 4 || return $?
      fake_bpf_metrics_increment 4 || return $?
      printf '%s\n' direct-java-workload >>"$FAKE_EVENTS"
      ;;
    *) return 64 ;;
  esac
  if [[ "$w3c" == true ]]; then
    fake_diagnostics_increment 4 4 || return $?
  fi
  fake_java_measurement_increment || return $?
  fake_bpf_metrics_increment 0 0 0 0 0 0 0 0 4 4000 || return $?
  printf 'benchmark duration=%s concurrency=%s\n' "$duration" "$concurrency" >>"$FAKE_DOCKER_LOG"
  # Keep the exact client identity live through the cgroup-only midpoint and
  # its post-capture liveness check. The fake clock advances independently.
  /bin/sleep 1
  jq -n \
    --arg base_url "$base_url" \
    --arg path "$path" \
    --arg connection_mode "$connection_mode" \
    --argjson duration_nanos "$((duration * 1000000000))" \
    --argjson timeout_nanos "$((FAKE_REQUEST_TIMEOUT_SECONDS * 1000000000))" \
    --argjson concurrency "$concurrency" \
    --argjson request_limit "$request_limit" \
    --argjson seed "$seed" \
    --argjson w3c "$w3c" '
      {
        status: "passed",
        started_at: "2026-08-20T00:00:00.000000001Z",
        finished_at: "2026-08-20T00:00:02.000000001Z",
        base_url: $base_url,
        path: $path,
        connection_mode: $connection_mode,
        tls_verification: (if ($base_url | startswith("https://")) then "verified_ca_file" else "not_applicable" end),
        w3c: $w3c,
        seed: $seed,
        requested_duration_nanos: $duration_nanos,
        request_timeout_nanos: $timeout_nanos,
        concurrency: $concurrency,
        request_limit: $request_limit,
        request_limit_reached: false,
        canceled: false,
        successful_requests: 4,
        failed_requests: 0,
        traffic_elapsed_nanos: $duration_nanos,
        throughput_per_second: (4 * 1000000000 / $duration_nanos),
        latency: {
          p50_nanos: 1,
          p95_nanos: 1,
          p99_nanos: 1,
          histogram_encoding: "sorted_rle_nanos_v1",
          histogram: [{nanos: 1, count: 4}]
        }
      }
    '
}

fake_sentinel_result() {
  local assertion_mode="bridge"
  local scenario=""
  local requests=""
  local seed=""
  local index=0

  while (($# > 0)); do
    case "$1" in
      --scenario)
        scenario="$2"
        shift 2
        ;;
      --requests)
        requests="$2"
        shift 2
        ;;
      --seed)
        seed="$2"
        shift 2
        ;;
      --expected-tls|--timeout)
        shift 2
        ;;
      --assertion-mode)
        assertion_mode="$2"
        shift 2
        ;;
      *)
        printf 'unexpected fake sentinel argument: %s\n' "$1" >&2
        return 64
        ;;
    esac
  done
  [[ "$requests" == "$FAKE_PREFLIGHT_REQUESTS" && "$seed" =~ ^[0-9]+$ ]] || return 64
  case "$scenario" in
    concurrency)
      printf 'sentinel assertion=%s\n' "$assertion_mode" >>"$FAKE_DOCKER_LOG"
      ;;
    w3c)
      [[ "$assertion_mode" == bridge ]] || return 64
      printf 'sentinel w3c-discard\n' >>"$FAKE_DOCKER_LOG"
      fake_diagnostics_increment \
        "$(( (FAKE_PREFLIGHT_REQUESTS + 1) / 2 ))" \
        "$FAKE_PREFLIGHT_REQUESTS" || return $?
      fake_w3c_sentinel_result "$requests" "$seed" "${FAKE_TLS_PROTOCOL:-TLSv1.3}"
      return 0
      ;;
    *)
      return 64
      ;;
  esac
  jq -n \
    --arg assertion_mode "$assertion_mode" \
    --arg tls "${FAKE_TLS_PROTOCOL:-TLSv1.3}" \
    --argjson requests "$requests" \
    --argjson seed "$seed" '
      {
        status: "passed",
        scenario: "concurrency",
        assertion_mode: $assertion_mode,
        request_count: $requests,
        seed: $seed,
        cases: [range(0; $requests) | {response: {tls_protocol: $tls}}]
      }
    '
}

fake_docker() {
  local format=""
  local project=""
  local project_temporary=""
  local service=""
  local argument=""
  local -a arguments=("$@")

  printf 'docker' >>"$FAKE_DOCKER_LOG"
  for argument in "${arguments[@]}"; do
    printf ' %q' "$argument" >>"$FAKE_DOCKER_LOG"
  done
  printf '\n' >>"$FAKE_DOCKER_LOG"
  if [[ "${1:-}" == context && "${2:-}" == show && $# == 2 ]]; then
    if [[ -n "${FAKE_DOCKER_CONTEXT_SHOW_COUNT_FILE:-}" ]]; then
      local context_show_count=0
      if [[ -f "$FAKE_DOCKER_CONTEXT_SHOW_COUNT_FILE" ]]; then
        context_show_count="$(<"$FAKE_DOCKER_CONTEXT_SHOW_COUNT_FILE")"
      fi
      [[ "$context_show_count" =~ ^[0-9]+$ ]] || return 64
      ((context_show_count += 1))
      printf '%s\n' "$context_show_count" >"$FAKE_DOCKER_CONTEXT_SHOW_COUNT_FILE"
      if [[ -n "${FAKE_DOCKER_CONTEXT_FAIL_AFTER:-}" &&
        "$context_show_count" -gt "$FAKE_DOCKER_CONTEXT_FAIL_AFTER" ]]; then
        return 70
      fi
    fi
    printf '%s\n' "${FAKE_DOCKER_CONTEXT:-default}"
    return 0
  fi
  if [[ "${1:-}" == context && "${2:-}" == inspect &&
    "${3:-}" == "${FAKE_DOCKER_CONTEXT:-default}" &&
    "${4:-}" == --format && $# == 5 ]]; then
    printf '"%s"\n' "${FAKE_DOCKER_ENDPOINT:-unix:///var/run/docker.sock}"
    return 0
  fi
  if [[ "${1:-}" == compose && "${2:-}" == --project-name ]]; then
    project="${3:-}"
    [[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ &&
      -n "${FAKE_COMPOSE_PROJECT_FILE:-}" ]] || return 64
    project_temporary="$(mktemp -- "${FAKE_COMPOSE_PROJECT_FILE}.tmp.XXXXXX")" || return 64
    printf '%s\n' "$project" >"$project_temporary" || {
      rm -f -- "$project_temporary"
      return 64
    }
    mv -f -- "$project_temporary" "$FAKE_COMPOSE_PROJECT_FILE" || {
      rm -f -- "$project_temporary"
      return 64
    }
  fi
  if [[ "${1:-}" == compose && "${2:-}" == version ]]; then
    printf 'Docker Compose version v2.fake\n'
    return 0
  fi
  if [[ "${1:-}" == stats ]]; then
    printf '"fake" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "0.01%%" "1MiB / 1GiB" "1" "0B / 0B"\n'
    return 0
  fi
  if [[ "${1:-}" == image && "${2:-}" == inspect ]]; then
    printf '[{"Id":"sha256:fixture"}]\n'
    return 0
  fi
  if [[ "${1:-}" == run ]]; then
    local mount=""
    local mount_source=""
    while (($# > 0)); do
      case "$1" in
        --mount)
          mount="$2"
          shift 2
          ;;
        --entrypoint)
          if [[ "$2" == java ]]; then
            printf 'openjdk version "fixture"\n'
            return 0
          fi
          shift 2
          ;;
        *) shift ;;
      esac
    done
    mount_source="${mount#*src=}"
    mount_source="${mount_source%%,dst=*}"
    [[ "$mount_source" == /* && "$mount_source" != "$mount" ]] || return 64
    mkdir -p -- "$mount_source/linux"
    printf '/* fixture jni.h */\n' >"$mount_source/jni.h"
    printf '/* fixture jni_md.h */\n' >"$mount_source/linux/jni_md.h"
    return 0
  fi
  if [[ "${1:-}" == exec ]]; then
    [[ "${2:-}" == "$FAKE_CONTAINER_ID" ]] || return 64
    if [[ "${3:-}" == env ]]; then
      [[ "${4:-}" == -i && "${5:-}" == HOME=/tmp &&
        "${6:-}" == LANG=C && "${7:-}" == LC_ALL=C &&
        "${8:-}" == PATH=/opt/java/openjdk/bin:/usr/bin:/bin &&
        "${9:-}" == TZ=UTC && $# -ge 10 ]] || return 64
      set -- "${arguments[@]:0:2}" "${arguments[@]:9}"
    fi
    if [[ "${3:-}" == /usr/bin/test && $# == 5 ]]; then
      case "${4:-} ${5:-}" in
        '-x /opt/java/openjdk/bin/java'|'-x /opt/java/openjdk/bin/jcmd'|\
        '-x /usr/bin/sha256sum'|'-x /usr/bin/stat')
          return 0
          ;;
        '-f /otel/obi-benchmark-runtime-snapshot.jar')
          [[ -n "${FAKE_RUNTIME_HELPER_JAR_FILE:-}" &&
            -f "$FAKE_RUNTIME_HELPER_JAR_FILE" &&
            ! -L "$FAKE_RUNTIME_HELPER_JAR_FILE" ]]
          return $?
          ;;
        '-f /otel/benchmark-source/RuntimeSnapshot.java')
          [[ -n "${FAKE_RUNTIME_HELPER_SOURCE_FILE:-}" &&
            -f "$FAKE_RUNTIME_HELPER_SOURCE_FILE" &&
            ! -L "$FAKE_RUNTIME_HELPER_SOURCE_FILE" ]]
          return $?
          ;;
        '-f /otel/obi-benchmark.jfc')
          [[ -n "${FAKE_RUNTIME_JFR_SETTINGS_FILE:-}" &&
            -f "$FAKE_RUNTIME_JFR_SETTINGS_FILE" &&
            ! -L "$FAKE_RUNTIME_JFR_SETTINGS_FILE" ]]
          return $?
          ;;
        *) return 64 ;;
      esac
    fi
    if [[ "${3:-}" == /usr/bin/sha256sum && "${4:-}" == -- && $# == 7 &&
      "${5:-}" == /otel/obi-benchmark-runtime-snapshot.jar &&
      "${6:-}" == /otel/benchmark-source/RuntimeSnapshot.java &&
      "${7:-}" == /otel/obi-benchmark.jfc ]]; then
      local digest=""
      digest="$(sha256sum -- "$FAKE_RUNTIME_HELPER_JAR_FILE")" || return 64
      printf '%s  %s\n' "${digest%% *}" "$5"
      digest="$(sha256sum -- "$FAKE_RUNTIME_HELPER_SOURCE_FILE")" || return 64
      printf '%s  %s\n' "${digest%% *}" "$6"
      digest="$(sha256sum -- "$FAKE_RUNTIME_JFR_SETTINGS_FILE")" || return 64
      printf '%s  %s\n' "${digest%% *}" "$7"
      return 0
    fi
    if [[ "${3:-}" == /usr/bin/stat && "${4:-}" == --format=%s &&
      "${5:-}" == -- && $# == 8 &&
      "${6:-}" == /otel/obi-benchmark-runtime-snapshot.jar &&
      "${7:-}" == /otel/benchmark-source/RuntimeSnapshot.java &&
      "${8:-}" == /otel/obi-benchmark.jfc ]]; then
      stat --format '%s' -- "$FAKE_RUNTIME_HELPER_JAR_FILE" \
        "$FAKE_RUNTIME_HELPER_SOURCE_FILE" "$FAKE_RUNTIME_JFR_SETTINGS_FILE"
      return $?
    fi
    if [[ "${3:-}" == cat && "${4:-}" == /run/obi-demo/certs/ca.crt && $# == 4 &&
      -n "${FAKE_CA_FILE:-}" && -f "$FAKE_CA_FILE" ]]; then
      command cat -- "$FAKE_CA_FILE"
      return 0
    fi
    if [[ "${3:-}" == java && "$*" == *' runtime-snapshot 1' ]]; then
      fake_java_runtime_snapshot
      return $?
    fi
    if [[ "${3:-}" == java && "$*" == *' jfr-snapshot /tmp/obi-benchmark-measurement.jfr '* ]]; then
      fake_jfr_summary >&2 || return $?
      command cat -- "$FAKE_JFR_FILE"
      return $?
    fi
    if [[ "${3:-}" == java && "$*" == *' discard-bootstrap-jfr 33554432' ]]; then
      fake_bootstrap_jfr_discard
      return $?
    fi
    if [[ "${3:-}" == jcmd && "${4:-}" == 1 ]]; then
      case "${5:-} ${6:-}" in
        'JFR.stop name=obi-benchmark-bootstrap')
          [[ -n "${FAKE_BOOTSTRAP_JFR_FILE:-}" &&
            -f "$FAKE_BOOTSTRAP_JFR_FILE" ]] || return 64
          local fake_formatted_size=""
          fake_formatted_size="$(fake_jfr_formatted_size \
            "$FAKE_BOOTSTRAP_JFR_FILE")" || return 64
          printf '%s\n' \
            '1:' \
            "Stopped recording \"obi-benchmark-bootstrap\", ${fake_formatted_size} written to:" \
            '' \
            '/tmp/obi-benchmark-bootstrap.jfr'
          return 0
          ;;
        'JFR.stop name=obi-benchmark-measurement')
          local fake_formatted_size=""
          fake_formatted_size="$(fake_jfr_formatted_size "$FAKE_JFR_FILE")" || return 64
          printf '%s\n' \
            '1:' \
            "Stopped recording \"obi-benchmark-measurement\", ${fake_formatted_size} written to:" \
            '' \
            '/tmp/obi-benchmark-measurement.jfr'
          return 0
          ;;
        'JFR.start name=obi-benchmark-measurement')
          [[ -n "${FAKE_JAVA_MEASUREMENT_STATE_FILE:-}" ]] || return 64
          printf '0\n' >"$FAKE_JAVA_MEASUREMENT_STATE_FILE"
          printf '%s\n' \
            '1:' \
            'Started recording 2. The result will be written to:' \
            '' \
            '/tmp/obi-benchmark-measurement.jfr'
          return 0
          ;;
        'VM.native_memory baseline')
          printf '1:\nBaseline taken\n'
          return 0
          ;;
        'VM.native_memory summary.diff')
          local fake_load_count=""
          fake_load_count="$(<"$FAKE_JAVA_MEASUREMENT_STATE_FILE")"
          if [[ "$fake_load_count" == pre ]]; then
            printf '%s\n' \
              '1:' 'Native Memory Tracking:' \
              'Total: reserved=1000100 +100, committed=500050 +50'
          elif [[ "$fake_load_count" =~ ^[0-9]+$ ]]; then
            printf '%s\n' \
              '1:' 'Native Memory Tracking:' \
              "Total: reserved=$((1000000 + 1000 * fake_load_count)) +$((1000 * fake_load_count)), committed=$((500000 + 500 * fake_load_count)) +$((500 * fake_load_count))"
          else
            return 64
          fi
          return 0
          ;;
        'VM.native_memory summary')
          local fake_load_count=""
          fake_load_count="$(<"$FAKE_JAVA_MEASUREMENT_STATE_FILE")"
          [[ "$fake_load_count" =~ ^[0-9]+$ ]] || return 64
          printf '%s\n' \
            '1:' 'Native Memory Tracking:' \
            "Total: reserved=$((1000000 + 1000 * fake_load_count)), committed=$((500000 + 500 * fake_load_count))"
          return 0
          ;;
      esac
    fi
    return 64
  fi
  if [[ "${1:-}" == inspect ]]; then
    while (($# > 0)); do
      if [[ "$1" == --format ]]; then
        format="$2"
        shift 2
      else
        shift
      fi
    done
    if [[ -n "$format" ]]; then
      [[ -n "${FAKE_COMPOSE_PROJECT_FILE:-}" &&
        -f "$FAKE_COMPOSE_PROJECT_FILE" ]] || return 64
      project="$(<"$FAKE_COMPOSE_PROJECT_FILE")"
      [[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 64
      printf '%s %s %s %s %s\n' \
        "$FAKE_CONTAINER_ID" \
        sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
        "$FAKE_PID" "$project" "acceptance-demo-v1"
    else
      printf '[{"Id":"%s"}]\n' "$FAKE_CONTAINER_ID"
    fi
    return 0
  fi
  [[ "${1:-}" == compose ]] || return 64
  while (($# > 0)); do
    case "$1" in
      --project-name|--file)
        shift 2
        ;;
      ps)
        shift
        [[ "${1:-}" == --quiet ]] && shift
        service="${1:-}"
        if [[ -n "$service" ]]; then
          printf '%s\n' "$FAKE_CONTAINER_ID"
        else
          printf '%s\n' "$FAKE_CONTAINER_ID"
        fi
        return 0
        ;;
      run)
        shift
        while [[ "${1:-}" == --rm || "${1:-}" == --no-deps || "${1:-}" == --no-TTY ]]; do
          shift
        done
        service="$1"
        shift
        case "$service" in
          benchmark)
            fake_benchmark_result "$@"
            return $?
            ;;
          scenario)
            fake_sentinel_result "$@"
            return $?
            ;;
          *)
            return 64
            ;;
        esac
        ;;
      down)
        printf 'raw compose down is forbidden\n' >&2
        return 64
        ;;
      *)
        shift
        ;;
    esac
  done
  return 64
}

fake_curl() {
  local argument=""
  local project=""

  for argument in "$@"; do
    case "$argument" in
      http://127.0.0.1:18990/internal/metrics)
        printf '%s\n' obi-metrics >>"$FAKE_EVENTS"
        # Model both independent periodic collectors. Each completed fake scrape has a
        # new Java bridge report and a new per-program collection pass.
        fake_bpf_metrics_increment 1 0 0 0 0 0 0 0 0 0 1 || return $?
        if [[ -n "${FAKE_COMPOSE_PROJECT_FILE:-}" &&
          -f "$FAKE_COMPOSE_PROJECT_FILE" ]]; then
          project="$(<"$FAKE_COMPOSE_PROJECT_FILE")"
        fi
        if [[ "$project" == *-bridge-disabled || "$project" == *-unix-hit ]]; then
          fake_bpf_metrics_snapshot | awk '!/^obi_bpf_probe_/'
        else
          fake_bpf_metrics_snapshot
        fi
        return 0
        ;;
      https://127.0.0.1:18443/obi-diagnostics)
        printf '%s\n' java-diagnostics >>"$FAKE_EVENTS"
        [[ -n "${FAKE_DIAGNOSTICS_FILE:-}" && -f "$FAKE_DIAGNOSTICS_FILE" ]] || return 64
        fake_diagnostics_increment 0 0 1 || return $?
        fake_bpf_metrics_increment 1 || return $?
        read -r discard_standard take_valid take_missing extra <"$FAKE_DIAGNOSTICS_FILE" || return 64
        [[ "$discard_standard" =~ ^[0-9]+$ && "$take_valid" =~ ^[0-9]+$ &&
          "$take_missing" =~ ^[0-9]+$ && -z "$extra" ]] || return 64
        fake_java_diagnostics_snapshot \
          "$(fake_decimal_to_base36 "$discard_standard")" \
          "$(fake_decimal_to_base36 "$take_valid")" \
          0 \
          "$(fake_decimal_to_base36 "$take_missing")"
        return 0
        ;;
    esac
  done
  return 64
}

fake_git() {
  if [[ "${*: -1}" == HEAD ]]; then
    printf '%s\n' "${FAKE_GIT_REVISION:-0123456789012345678901234567890123456789}"
    return 0
  fi
  return 64
}

case "$(basename -- "$0")" in
  docker)
    fake_docker "$@"
    exit $?
    ;;
  curl)
    fake_curl "$@"
    exit $?
    ;;
  git)
    fake_git "$@"
    exit $?
    ;;
  run.sh)
    fake_runner "$@"
    exit $?
    ;;
  sleep)
    if [[ -n "${FAKE_CLOCK_FILE:-}" && -f "$FAKE_CLOCK_FILE" &&
      "${1:-}" =~ ^[1-9][0-9]*$ ]]; then
      read -r fake_wall fake_monotonic fake_extra <"$FAKE_CLOCK_FILE" || exit 64
      [[ "$fake_wall" =~ ^[1-9][0-9]*$ &&
        "$fake_monotonic" =~ ^(0|[1-9][0-9]*)$ && -z "$fake_extra" ]] || exit 64
      printf '%s %s\n' \
        "$((fake_wall + $1))" "$((fake_monotonic + $1 * 1000))" \
        >"$FAKE_CLOCK_FILE"
    elif [[ "${1:-}" == 0.1 ]]; then
      /bin/sleep 0.1
    fi
    exit 0
    ;;
esac

# shellcheck source=benchmark.sh
# shellcheck disable=SC1091 # Resolved from TEST_SCRIPT_DIR at runtime.
source "$TEST_SCRIPT_DIR/benchmark.sh"

TEST_TMP_DIR=""
FAKE_CA_FILE=""

create_unix_socket_fixture() {
  local -r socket_path="$1"

  [[ "$socket_path" == /* && ! -e "$socket_path" && ! -L "$socket_path" ]] || return 1
  python3 - "$socket_path" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(sys.argv[1])
sock.close()
PY
  [[ -S "$socket_path" && ! -L "$socket_path" ]]
}

run_benchmark_with_fake_bound_proc() {
  local -r script="$1"
  shift

  bash -c '
    set -Eeuo pipefail
    source "$1"
    shift
    capture_service_identity() {
      local -r service="$1"
      local -r output="$2"
      {
        printf "service=%s\n" "$service"
        printf "container_id=%s\n" "$FAKE_CONTAINER_ID"
        printf "image_id=sha256:%064d\n" 0
        printf "host_pid=%s\n" "$FAKE_PID"
        printf "proc_start_time=123456\n"
        printf "proc_cgroup_sha256=%064d\n" 0
        printf "proc_cgroup_container_binding=%s\n" \
          "$PROC_CGROUP_CONTAINER_BINDING"
        printf "project=%s\n" "$ACTIVE_PROJECT"
        printf "owner_sentinel=%s\n" "$PROJECT_SENTINEL_VALUE"
      } >"$output"
    }
    clock_pair_values() {
      local wall=""
      local monotonic=""
      local extra=""

      read -r wall monotonic extra <"$FAKE_CLOCK_FILE" || return 1
      [[ "$wall" =~ ^[1-9][0-9]*$ &&
        "$monotonic" =~ ^(0|[1-9][0-9]*)$ && -z "$extra" ]] || return 1
      printf "%s %s\n" "$wall" "$monotonic"
    }
    capture_proc_snapshot() {
      local -r identity_file="$1"
      local -r output="$2"
      local container_id=""
      local host_pid=""
      container_id="$(identity_field "$identity_file" container_id)" || return 1
      host_pid="$(identity_field "$identity_file" host_pid)" || return 1
      {
        printf "status=available\n"
        printf "container_id=%s\n" "$container_id"
        printf "host_pid=%s\n" "$host_pid"
        printf "proc_start_time=123456\n"
        printf "proc_cgroup_sha256=%064d\n" 0
        printf "proc_cgroup_container_binding=%s\n" \
          "$PROC_CGROUP_CONTAINER_BINDING"
        printf "VmPeak:\t2048 kB\n"
        printf "VmSize:\t2048 kB\n"
        printf "VmRSS:\t1024 kB\n"
        printf "VmData:\t512 kB\n"
        printf "VmStk:\t128 kB\n"
        printf "VmExe:\t64 kB\n"
        printf "VmLib:\t256 kB\n"
        printf "Threads:\t4\n"
        printf "fd_count=8\n"
        printf "task_count=4\n"
        printf "stat=fixture-process-stat\n"
      } >"$output"
    }
    capture_bound_cgroup_v2_snapshot() {
      local -r identity_file="$1"
      local -r output="$2"
      local -r timing="$3"
      local -r cell="$4"
      local -r service="$5"
      local -r repetition="${6:-}"
      local repetition_json=null
      local usage_1=3000
      local usage_2=3001
      local path=""
      local path_sha256=""
      local container_id=""
      local host_pid=""

      container_id="$(identity_field "$identity_file" container_id)" || return 1
      host_pid="$(identity_field "$identity_file" host_pid)" || return 1
      path="/docker/$container_id"
      path_sha256="$(printf %s "$path" | sha256sum)" || return 1
      path_sha256="${path_sha256%% *}"
      case "$timing" in
        cpu_measurement_baseline)
          usage_1=1000
          usage_2=1001
          ;;
        cpu_measurement_end)
          usage_1=2001
          usage_2=2002
          ;;
        scheduled_repetition_midpoint)
          [[ "$repetition" =~ ^[1-5]$ ]] || return 1
          repetition_json="$repetition"
          ;;
        *)
          [[ -z "$repetition" ]] || return 1
          ;;
      esac
      jq -n --arg cell "$cell" --arg service "$service" --arg timing "$timing" \
        --argjson repetition "$repetition_json" --arg container_id "$container_id" \
        --arg cgroup_path "$path" --arg cgroup_path_sha256 "$path_sha256" \
        --argjson host_pid "$host_pid" --argjson usage_1 "$usage_1" \
        --argjson usage_2 "$usage_2" '\''
        def process: {
          pid: $host_pid, proc_start_time: 123456,
          proc_cgroup_sha256: ("0" * 64),
          proc_cgroup_container_binding: "full_container_id_at_non_hex_boundaries",
          fd_roster_sha256: ("1" * 64), task_roster_sha256: ("2" * 64),
          fd_count: 8, task_count: 4, status_threads: 4, rss_bytes: 1048576
        };
        def pass($ordinal; $usage): {
          ordinal: $ordinal, roster_sha256: ("3" * 64), processes: [process],
          totals: {process_count: 1, fd_count: 8, task_count: 4,
            status_threads: 4, rss_bytes: 1048576},
          cpu_stat: {usage_usec: $usage, user_usec: ($usage - 400), system_usec: 400}
        };
        {
          schema_version: 1, kind: "bound-container-cgroup-v2-snapshot",
          status: "available", cell: $cell, service: $service, timing: $timing,
          repetition: $repetition, identity_source: ($service + "-identity.txt"),
          identity: {
            container_id: $container_id, root_host_pid: $host_pid,
            root_proc_start_time: 123456, proc_cgroup_sha256: ("0" * 64),
            proc_cgroup_container_binding: "full_container_id_at_non_hex_boundaries",
            cgroup_path: $cgroup_path, cgroup_path_sha256: $cgroup_path_sha256,
            cgroup_root_device: 1, cgroup_root_inode: 1,
            cgroup_device: 1, cgroup_inode: 2,
            cgroup_hierarchy_sha256: ("f" * 64), cgroup_version: 2,
            cgroup_type: "domain", filesystem_type: "cgroup2fs", leaf: true,
            nr_descendants: 0, nr_dying_descendants: 0
          },
          roster: [{pid: $host_pid, proc_start_time: 123456,
            proc_cgroup_sha256: ("0" * 64),
            proc_cgroup_container_binding: "full_container_id_at_non_hex_boundaries"}],
          passes: [pass(1; $usage_1), pass(2; $usage_2)],
          envelope: {
            process_count: {min: 1, max: 1}, fd_count: {min: 8, max: 8},
            task_count: {min: 4, max: 4}, status_threads: {min: 4, max: 4},
            rss_bytes: {min: 1048576, max: 1048576},
            cpu_usage_usec: {min: $usage_1, max: $usage_2},
            cpu_user_usec: {min: ($usage_1 - 400), max: ($usage_2 - 400)},
            cpu_system_usec: {min: 400, max: 400}
          },
          collection: {
            authority: "compose_identity_plus_fd_anchored_cgroup2_root_leaf_and_stable_hierarchy",
            roster_stability: "two_identical_sorted_pid_start_cgroup_rosters",
            resource_values: "two_pass_conservative_envelope",
            cgroup2_leaf_domain_required: true
          }
        }
      '\'' >"$output"
    }
    capture_bpf_fd_ownership() {
      local -r identity_file="$1"
      local -r output="$2"
      local container_id=""
      local host_pid=""
      container_id="$(identity_field "$identity_file" container_id)" || return 1
      host_pid="$(identity_field "$identity_file" host_pid)" || return 1
      {
        printf "status=available\n"
        printf "container_id=%s\n" "$container_id"
        printf "host_pid=%s\n" "$host_pid"
        printf "proc_start_time=123456\n"
        printf "proc_cgroup_sha256=%064d\n" 0
        printf "proc_cgroup_container_binding=%s\n" \
          "$PROC_CGROUP_CONTAINER_BINDING"
        printf "fd=4 map_id=41\n"
        printf "fd=5 prog_id=71\n"
        printf "fd=6 map_id=41\n"
        printf "fd=7 prog_id=72\n"
        printf "fd=8 prog_id=73\n"
        printf "fd=9 prog_id=74\n"
        printf "fd=10 prog_id=75\n"
        printf "fd=11 prog_id=76\n"
        printf "fd=12 prog_id=77\n"
      } >"$output"
    }
    trap '\''on_exit "$?"'\'' EXIT
    trap '\''exit 130'\'' INT TERM
    main "$@"
  ' benchmark-fake-proc "$script" "$@"
}

cleanup_test() {
  if [[ "${KEEP_TEST_TMP:-false}" != "true" && -n "$TEST_TMP_DIR" && -d "$TEST_TMP_DIR" ]]; then
    rm -rf -- "$TEST_TMP_DIR"
  fi
}

trap cleanup_test EXIT

prepare_fake_ca() {
  local private_key=""

  FAKE_CA_FILE="$TEST_TMP_DIR/fake-benchmark-ca.crt"
  private_key="$TEST_TMP_DIR/fake-benchmark-ca.key"
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 1 \
    -set_serial 1 \
    -subj '/CN=OBI benchmark harness test CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$private_key" \
    -out "$FAKE_CA_FILE" >/dev/null 2>&1
  chmod 0600 -- "$private_key" "$FAKE_CA_FILE"
  export FAKE_CA_FILE
}

# shellcheck disable=SC2034 # These globals are consumed by sourced benchmark.sh functions.
reset_options() {
  OUTPUT_DIR=""
  OUTPUT_PARENT=""
  OUTPUT_DIR_IDENTITY=""
  AGENT=otel
  TLS_PROTOCOL=TLSv1.3
  WARMUP_SECONDS=10
  DURATION_SECONDS=30
  CONCURRENCY=16
  REPETITIONS=5
  SEED=20260721
  CELLS_MODE=core
  PROCESS_TREE_FD_ABSOLUTE_MAX=""
  PROCESS_TREE_TASK_ABSOLUTE_MAX=""
  PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX=""
  PROCESS_TREE_FD_RECOVERY_DELTA_MAX=""
  PROCESS_TREE_TASK_RECOVERY_DELTA_MAX=""
  PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX=""
  RUN_TOKEN=1234567890-12345
  SHOW_HELP=false
  OUTPUT_READY=false
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
  TERMINAL_NATIVE_SIGNAL_TEST_HOOK=none
  HARNESS_STATUS=failed
  STARTED_AT=""
  ACTIVE_PROJECT=""
  ACTIVE_CELL_DIR=""
  BENCHMARK_PID=""
  BENCHMARK_IDENTITY=""
  BENCHMARK_OUTPUT=""
  BENCHMARK_DURATION_SECONDS=""
  BENCHMARK_CELL_DIR=""
  BENCHMARK_OUTPUT_PARENT_IDENTITY=""
  JAVA_MEASUREMENT_PARTIAL=""
  JAVA_MEASUREMENT_CELL_DIR=""
  JAVA_MEASUREMENT_PARENT_IDENTITY=""
  JAVA_MEASUREMENT_ROOT_IDENTITY=""
  JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS=""
  JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256=""
  JAVA_MEASUREMENT_STARTED_AT=""
  JAVA_MEASUREMENT_STOP_INITIATED_AT=""
  HARNESS_INVOCATION=""
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
  CELL_MEASUREMENT_REQUESTS="$PREFLIGHT_REQUESTS"
  CELL_RESULT_LABEL=""
  CELL_PATH_CLASSIFICATION=""
  CELL_EXPECTED_JAVA_STATUS=""
  CELL_EXTRA_RUNNER_FILES=()
  COMPOSE=()
  unset BENCHMARK_CA_SOURCE JAVA_IMAGE_TARGET JAVA_BACKEND_IMAGE \
    JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX
}

set_valid_process_tree_caps() {
  PROCESS_TREE_FD_ABSOLUTE_MAX=4096
  PROCESS_TREE_TASK_ABSOLUTE_MAX=2048
  PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX=1073741824
  PROCESS_TREE_FD_RECOVERY_DELTA_MAX=0
  PROCESS_TREE_TASK_RECOVERY_DELTA_MAX=0
  PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX=0
}

write_valid_in_progress_manifest_fixture() {
  [[ -n "$OUTPUT_DIR" && -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || return 1
  OUTPUT_DIR_IDENTITY="$(stat --format '%d:%i:%u:%g:%a' -- \
    "$OUTPUT_DIR")" || return 1
  set_valid_process_tree_caps
  # shellcheck disable=SC2034 # Consumed dynamically by manifest_json.
  STARTED_AT=2026-08-21T00:00:00Z
  write_manifest || return 1
  validate_manifest_schema "$OUTPUT_DIR/manifest.in-progress.json"
}

expect_parse_failure() {
  if (
    reset_options
    parse_args "$@" "${VALID_PROCESS_TREE_CAP_ARGS[@]}"
  ) >/dev/null 2>&1; then
    printf 'accepted invalid arguments: %q\n' "$*" >&2
    return 1
  fi
}

expect_exact_parse_failure() {
  if (
    reset_options
    parse_args "$@"
  ) >/dev/null 2>&1; then
    printf 'accepted invalid exact arguments: %q\n' "$*" >&2
    return 1
  fi
}

expect_cap_value_parse_failure() {
  local -r target_flag="$1"
  local -r replacement="$2"
  local argument=""
  local replace_next=false
  local replaced=false
  local -a arguments=(--output "$TEST_TMP_DIR/parse-output")

  for argument in "${VALID_PROCESS_TREE_CAP_ARGS[@]}"; do
    if [[ "$replace_next" == true ]]; then
      arguments+=("$replacement")
      replace_next=false
      replaced=true
    elif [[ "$argument" == "$target_flag" ]]; then
      arguments+=("$argument")
      replace_next=true
    else
      arguments+=("$argument")
    fi
  done
  [[ "$replaced" == true && "$replace_next" == false ]] || return 1
  expect_exact_parse_failure "${arguments[@]}"
}

test_java_bridge_program_allowlist_matches_source() {
  local -r source="$REPO_ROOT/bpf/javabridge/javabridge.c"
  local name=""
  local names_json="[]"

  [[ -f "$source" && ! -L "$source" &&
    "${#JAVA_BRIDGE_CGROUP_SOCKOPT_PROGRAM_NAMES[@]}" == 7 ]] || return 1
  names_json="$(jq -cn '$ARGS.positional' --args \
    "${JAVA_BRIDGE_CGROUP_SOCKOPT_PROGRAM_NAMES[@]}")" || return 1
  jq -e 'length == 7 and (unique | length) == 7' \
    <<<"$names_json" >/dev/null || return 1
  for name in "${JAVA_BRIDGE_CGROUP_SOCKOPT_PROGRAM_NAMES[@]}"; do
    [[ "$(grep -Ec "^int ${name}\\(struct bpf_sockopt \\*ctx\\) \\{$" "$source")" == 1 ]] || {
      printf 'Java bridge program allowlist drifted from source definition: %s\n' \
        "$name" >&2
      return 1
    }
  done
}

test_parser_defaults_and_boundaries() {
  local -r output="$TEST_TMP_DIR/parse-output"
  local -r seed_error="$TEST_TMP_DIR/seed-error.txt"

  [[ "$METRICS_SETTLE_SECONDS" == 1 &&
    "$(grep -Fc 'sleep "$METRICS_SETTLE_SECONDS"' "$TEST_SCRIPT_DIR/benchmark.sh")" -ge 1 ]] || {
    printf 'metrics settle constant disappeared from its source-coupled call sites\n' >&2
    return 1
  }

  (
    reset_options
    parse_args --output "$output" "${VALID_PROCESS_TREE_CAP_ARGS[@]}"
    [[ "$OUTPUT_DIR" == "$output" && "$AGENT" == otel && "$TLS_PROTOCOL" == TLSv1.3 &&
      "$WARMUP_SECONDS" == 10 && "$DURATION_SECONDS" == 30 && "$CONCURRENCY" == 16 &&
      "$REPETITIONS" == 5 && "$SEED" == 20260721 && "$CELLS_MODE" == core &&
      "$PROCESS_TREE_FD_ABSOLUTE_MAX" == 4096 &&
      "$PROCESS_TREE_TASK_ABSOLUTE_MAX" == 2048 &&
      "$PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX" == 1073741824 &&
      "$PROCESS_TREE_FD_RECOVERY_DELTA_MAX" == 0 &&
      "$PROCESS_TREE_TASK_RECOVERY_DELTA_MAX" == 0 &&
      "$PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX" == 0 ]]
  ) || {
    printf 'default benchmark options changed unexpectedly\n' >&2
    return 1
  }

  (
    reset_options
    parse_args --output "$output" --cells complete "${VALID_PROCESS_TREE_CAP_ARGS[@]}"
    [[ "$CELLS_MODE" == complete ]]
  ) || {
    printf 'complete benchmark cell set was rejected\n' >&2
    return 1
  }

  (
    reset_options
    parse_args --output "$output" --warmup-seconds 2 --duration-seconds 600 \
      --concurrency 1 --repetitions 5 --seed 9007199254740991 --cells core \
      --process-tree-fd-absolute-max 9007199254740991 \
      --process-tree-task-absolute-max 9007199254740991 \
      --process-tree-rss-bytes-absolute-max 9007199254740991 \
      --process-tree-fd-recovery-delta-max 9007199254740991 \
      --process-tree-task-recovery-delta-max 9007199254740991 \
      --process-tree-rss-bytes-recovery-delta-max 9007199254740991
    [[ "$WARMUP_SECONDS" == 2 && "$DURATION_SECONDS" == 600 && "$CONCURRENCY" == 1 &&
      "$REPETITIONS" == 5 && "$SEED" == 9007199254740991 ]]
  ) || {
    printf 'valid benchmark boundaries were rejected\n' >&2
    return 1
  }

  expect_parse_failure --output "$output" --warmup-seconds 1
  expect_parse_failure --output "$output" --duration-seconds 601
  expect_parse_failure --output "$output" --duration-seconds -1
  expect_parse_failure --output "$output" --concurrency 0
  expect_parse_failure --output "$output" --concurrency 257
  expect_parse_failure --output "$output" --repetitions 4
  expect_parse_failure --output "$output" --repetitions 6
  expect_parse_failure --output "$output" --repetitions 10
  expect_parse_failure --output "$output" --repetitions 11
  expect_parse_failure --output "$output" --seed -1
  expect_parse_failure --output "$output" --seed 9007199254740992
  expect_parse_failure --output "$output" --seed 9223372036854775808
  if (
    reset_options
    parse_args --output "$output" --seed 9007199254740992 \
      "${VALID_PROCESS_TREE_CAP_ARGS[@]}"
  ) >/dev/null 2>"$seed_error" ||
    ! grep -Fxq \
      '[ERROR] --seed must be a non-negative integer no greater than 9007199254740991' \
      <(sed -E 's/^\[[^]]+\] INFO:/[INFO]/; s/^\[[^]]+\] ERROR:/[ERROR]/' "$seed_error"); then
    printf 'seed overflow error did not state the JSON-safe exact bound\n' >&2
    return 1
  fi
  expect_parse_failure --output "$output" --duration-seconds 600 --concurrency 256
  expect_parse_failure --output "$output" --cells getsockopt-miss
  expect_parse_failure --output "$output" --agent invalid
  expect_parse_failure --output "$output" --tls invalid
  expect_parse_failure --output "$output" --unknown
  expect_parse_failure --output
  expect_parse_failure --agent otel
  expect_parse_failure --output "$output" --output "$TEST_TMP_DIR/second-output"

  local flag=""
  local value=""
  local -a absolute_flags=(
    --process-tree-fd-absolute-max
    --process-tree-task-absolute-max
    --process-tree-rss-bytes-absolute-max
  )
  local -a recovery_flags=(
    --process-tree-fd-recovery-delta-max
    --process-tree-task-recovery-delta-max
    --process-tree-rss-bytes-recovery-delta-max
  )
  for flag in "${absolute_flags[@]}"; do
    expect_cap_value_parse_failure "$flag" 0
  done
  for flag in "${absolute_flags[@]}" "${recovery_flags[@]}"; do
    for value in -1 1.0 1e3 +1 9007199254740992; do
      expect_cap_value_parse_failure "$flag" "$value"
    done
  done
  for flag in "${VALID_PROCESS_TREE_CAP_ARGS[@]}"; do
    [[ "$flag" == --process-tree-* ]] || continue
    local -a without_flag=()
    local skip_next=false
    local argument=""
    for argument in "${VALID_PROCESS_TREE_CAP_ARGS[@]}"; do
      if [[ "$skip_next" == true ]]; then
        skip_next=false
      elif [[ "$argument" == "$flag" ]]; then
        skip_next=true
      else
        without_flag+=("$argument")
      fi
    done
    expect_exact_parse_failure --output "$output" "${without_flag[@]}"
    expect_exact_parse_failure --output "$output" \
      "${VALID_PROCESS_TREE_CAP_ARGS[@]}" "$flag" 1
  done
}

test_lifecycle_tool_paths_must_be_absolute_regular() {
  local ps_path=""
  local sleep_path=""

  ps_path="$(builtin type -P ps)"
  sleep_path="$(builtin type -P sleep)"
  is_absolute_regular_executable "$ps_path" &&
    is_absolute_regular_executable "$sleep_path" || {
    printf 'system lifecycle tools were not resolved to absolute regular executables\n' >&2
    return 1
  }
  if is_absolute_regular_executable ./ps || is_absolute_regular_executable /; then
    printf 'relative or non-regular lifecycle tool path was accepted\n' >&2
    return 1
  fi
}

test_lifecycle_tool_resolution_rejects_relative_paths() (
  reset_options
  type() {
    case "$1:$2" in
      -P:ps)
        printf './relative-ps\n'
        ;;
      -P:sleep)
        printf './relative-sleep\n'
        ;;
      *)
        builtin type "$@"
        ;;
    esac
  }
  resolve_lifecycle_tools
  if is_absolute_regular_executable "$PS_COMMAND" ||
    is_absolute_regular_executable "$SLEEP_COMMAND"; then
    printf 'lifecycle resolver accepted relative executable paths\n' >&2
    return 1
  fi
  [[ "$PS_COMMAND" == ./relative-ps && "$SLEEP_COMMAND" == ./relative-sleep ]] || {
    printf 'lifecycle resolver did not inspect the relative candidate paths\n' >&2
    return 1
  }
)

test_dependency_check_reports_only_invalid_lifecycle_tool() (
  local -r output="$TEST_TMP_DIR/lifecycle-tool-dependency-error.log"
  local -r ps_path="$(builtin type -P ps)"

  reset_options
  command() {
    if [[ "$1" == -v ]]; then
      return 0
    fi
    builtin command "$@"
  }
  type() {
    case "$1:$2" in
      -P:ps)
        printf '%s\n' "$ps_path"
        ;;
      -P:sleep)
        printf './relative-sleep\n'
        ;;
      *)
        builtin type "$@"
        ;;
    esac
  }
  if check_dependencies >"$output" 2>&1; then
    printf 'dependency check accepted a relative lifecycle tool path\n' >&2
    return 1
  fi
  grep -Fq 'missing required commands: sleep' "$output" &&
    ! grep -Fq 'missing required commands: ps sleep' "$output" || {
    printf 'dependency check did not report only the invalid lifecycle tool\n' >&2
    return 1
  }
)

test_dependency_check_reports_invalid_lifecycle_tool_under_errexit() {
  local -r output="$TEST_TMP_DIR/lifecycle-tool-errexit-error.log"
  local -r ps_path="$(builtin type -P ps)"
  local status=0

  set +e
  bash -Eeuo pipefail -c '
    source "$1"
    valid_ps_path="$2"
    command() {
      if [[ "$1" == -v ]]; then
        return 0
      fi
      builtin command "$@"
    }
    type() {
      case "$1:$2" in
        -P:ps)
          printf "%s\\n" "$valid_ps_path"
          ;;
        -P:sleep)
          printf "./relative-sleep\\n"
          ;;
        *)
          builtin type "$@"
          ;;
      esac
    }
    check_dependencies
  ' bash "$TEST_SCRIPT_DIR/benchmark.sh" "$ps_path" >"$output" 2>&1
  status=$?
  set -e
  [[ "$status" != 0 ]] && grep -Fq 'missing required commands: sleep' "$output" &&
    ! grep -Fq 'missing required commands: ps sleep' "$output" || {
    printf 'strict dependency check did not report only the invalid lifecycle tool\n' >&2
    return 1
  }
}

test_docker_daemon_locality_is_verified_before_execution() (
  local -r fake_bin="$TEST_TMP_DIR/docker-locality-bin"
  local -r docker_log="$TEST_TMP_DIR/docker-locality.log"
  local -r output="$TEST_TMP_DIR/docker-locality-output"
  local -r socket_path="$TEST_TMP_DIR/docker-locality.sock"
  local -r socket_symlink="$TEST_TMP_DIR/docker-locality-symlink.sock"
  local -r compose_project="$TEST_TMP_DIR/docker-locality-project.txt"
  local -r identity="$TEST_TMP_DIR/docker-locality-colliding-pid.txt"

  mkdir -p -- "$fake_bin" "$output"
  create_unix_socket_fixture "$socket_path"
  ln -s -- "$TEST_SOURCE" "$fake_bin/docker"
  : >"$docker_log"
  reset_options
  resolve_benchmark_identity_tools
  PATH="$fake_bin:$PATH"
  FAKE_DOCKER_LOG="$docker_log"
  unset DOCKER_HOST DOCKER_CONTEXT
  FAKE_DOCKER_CONTEXT=default
  FAKE_DOCKER_ENDPOINT="unix://$socket_path"
  FAKE_COMPOSE_PROJECT_FILE="$compose_project"
  FAKE_CONTAINER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  FAKE_PID="$$"
  export PATH FAKE_DOCKER_LOG FAKE_DOCKER_CONTEXT FAKE_DOCKER_ENDPOINT \
    FAKE_COMPOSE_PROJECT_FILE FAKE_CONTAINER_ID FAKE_PID
  resolve_docker_daemon_locality || {
    printf 'verified local Docker endpoint was rejected\n' >&2
    return 1
  }
  OUTPUT_DIR="$output"
  OUTPUT_READY=true
  write_docker_daemon_provenance
  validate_docker_daemon_provenance "$output/docker-daemon.json" || return 1
  jq -e --arg endpoint "unix://$socket_path" --arg socket_path "$socket_path" '
    .status == "verified_local_unix_socket_endpoint_only" and
    .kind == "docker-endpoint-evidence" and .active_context == "default" and
    .active_endpoint == $endpoint and .socket_path == $socket_path and
    .endpoint_transport == "unix" and
    .socket_evidence == "existing_non_symlink_unix_socket" and
    .daemon_process_locality == "not_established_by_unix_socket_endpoint" and
    .container_process_binding == "required_separately_for_each_process_sample" and
    (.socket_device | type == "number") and (.socket_inode | type == "number") and
    .verified_before_container_execution == true
  ' "$output/docker-daemon.json" >/dev/null || return 1

  FAKE_DOCKER_ENDPOINT="unix://$TEST_TMP_DIR/nonexistent-docker.sock"
  if resolve_docker_daemon_locality >/dev/null 2>&1; then
    printf 'Docker locality accepted a nonexistent Unix socket endpoint\n' >&2
    return 1
  fi
  ln -s -- "$socket_path" "$socket_symlink"
  FAKE_DOCKER_ENDPOINT="unix://$socket_symlink"
  if resolve_docker_daemon_locality >/dev/null 2>&1; then
    printf 'Docker locality accepted a symlink Unix socket endpoint\n' >&2
    return 1
  fi

  DOCKER_HOST=tcp://remote.example.invalid:2376
  if resolve_docker_daemon_locality >/dev/null 2>&1; then
    printf 'Docker locality accepted DOCKER_HOST remote control\n' >&2
    return 1
  fi
  unset DOCKER_HOST
  DOCKER_HOST=""
  export DOCKER_HOST
  if resolve_docker_daemon_locality >/dev/null 2>&1; then
    printf 'Docker locality accepted an inherited empty DOCKER_HOST override\n' >&2
    return 1
  fi
  unset DOCKER_HOST
  FAKE_DOCKER_CONTEXT=remote
  FAKE_DOCKER_ENDPOINT=ssh://operator@remote.example.invalid
  if resolve_docker_daemon_locality >/dev/null 2>&1; then
    printf 'Docker locality accepted a remote SSH context endpoint\n' >&2
    return 1
  fi
  FAKE_DOCKER_ENDPOINT=tcp://127.0.0.1:2375
  if resolve_docker_daemon_locality >/dev/null 2>&1; then
    printf 'Docker locality accepted a TCP daemon endpoint\n' >&2
    return 1
  fi
  FAKE_DOCKER_ENDPOINT="unix://$socket_path"
  DOCKER_CONTEXT=other
  export DOCKER_CONTEXT
  if resolve_docker_daemon_locality >/dev/null 2>&1; then
    printf 'Docker locality accepted a mismatched active context override\n' >&2
    return 1
  fi
  unset DOCKER_CONTEXT
  printf 'fixture\n' >"$compose_project"
  ACTIVE_PROJECT=fixture
  COMPOSE=(docker compose --project-name fixture --file "$COMPOSE_FILE")
  if capture_service_identity java-backend "$identity" >/dev/null 2>&1; then
    printf 'container identity accepted a colliding local PID without exact cgroup binding\n' >&2
    return 1
  fi
)

test_manifest_bootstrap_survives_second_locality_query_failure() (
  local -r fake_root="$TEST_TMP_DIR/locality-failure-root"
  local -r fake_example="$fake_root/examples/apache-java-https"
  local -r fake_bin="$TEST_TMP_DIR/locality-failure-bin"
  local -r output_parent="$TEST_TMP_DIR/locality-failure-output"
  local -r output="$output_parent/artifacts"
  local -r docker_log="$TEST_TMP_DIR/locality-failure-docker.log"
  local -r context_count="$TEST_TMP_DIR/locality-failure-context-count.txt"
  local -r socket_path="$TEST_TMP_DIR/locality-failure.sock"
  local status=0

  mkdir -p -- "$fake_example/scripts" "$fake_example/.runtime" \
    "$fake_bin" "$output_parent"
  chmod 0755 -- "$fake_example/.runtime"
  install --mode=0755 "$TEST_SCRIPT_DIR/benchmark.sh" \
    "$fake_example/scripts/benchmark.sh"
  ln -s -- "$TEST_SOURCE" "$fake_example/run.sh"
  printf 'services: {}\n' >"$fake_example/docker-compose.yml"
  ln -s -- "$TEST_SOURCE" "$fake_bin/docker"
  : >"$docker_log"
  create_unix_socket_fixture "$socket_path"
  set +e
  PATH="$fake_bin:$PATH" \
    FAKE_DOCKER_CONTEXT=default \
    FAKE_DOCKER_ENDPOINT="unix://$socket_path" \
    FAKE_DOCKER_LOG="$docker_log" \
    FAKE_DOCKER_CONTEXT_SHOW_COUNT_FILE="$context_count" \
    FAKE_DOCKER_CONTEXT_FAIL_AFTER=1 \
    "$fake_example/scripts/benchmark.sh" --output "$output" \
      --warmup-seconds 2 --duration-seconds 2 --concurrency 1 \
      --repetitions 5 --seed 17 \
      "${VALID_PROCESS_TREE_CAP_ARGS[@]}" >/dev/null 2>&1
  status=$?
  set -e
  [[ "$status" != 0 && -f "$context_count" &&
    "$(<"$context_count")" == 2 ]] || {
    printf 'second Docker locality query did not fail at the intended boundary\n' >&2
    return 1
  }
  jq -e '
    .status == "failed" and .docker_daemon == {
      status: "requested_but_unavailable", path: null
    } and .application_source == {
      status: "requested_but_unavailable", path: null
    }
  ' "$output/summary.json" >/dev/null || {
    printf 'early provenance failure did not retain a failed terminal summary\n' >&2
    return 1
  }
  jq -e '.status == "failed" and .docker_endpoint_evidence == "docker-daemon.json"' \
    "$output/manifest.json" >/dev/null || {
    printf 'early provenance failure did not terminate its bootstrap manifest\n' >&2
    return 1
  }
)

test_benchmark_documentation_binds_partial_status_to_mralias_issue() (
  local -r document="$TEST_SCRIPT_DIR/../BENCHMARK.md"
  local -r issue_link='[MrAlias/opentelemetry-ebpf-instrumentation issue #37](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/issues/37)'
  local flattened=""
  local result_cap_mib=0
  local jfr_cap_mib=0
  local -a issue_lines=()

  [[ "$(grep -Fc -- "$issue_link" "$document")" == 1 ]] || {
    printf 'benchmark documentation does not identify the exact MrAlias fork issue once\n' >&2
    return 1
  }
  mapfile -t issue_lines < <(grep -F -- '#37' "$document")
  [[ "${#issue_lines[@]}" == 1 && "${issue_lines[0]}" == "$issue_link." ]] || {
    printf 'benchmark documentation contains an ambiguous issue #37 reference\n' >&2
    return 1
  }
  flattened="$(tr '\n' ' ' <"$document")" || return 1
  [[ "$flattened" == *"The retained benchmark evidence remains partial and does not close the open $issue_link."* ]] || {
    printf 'benchmark documentation does not keep the fork issue explicitly partial and open\n' >&2
    return 1
  }
  ((MAX_BENCHMARK_RESULT_BYTES % (1024 * 1024) == 0)) || return 1
  result_cap_mib="$((MAX_BENCHMARK_RESULT_BYTES / 1024 / 1024))"
  [[ "$flattened" == *"and to $result_cap_mib MiB before publication"* ]] || {
    printf 'benchmark documentation drifted from the enforced result byte cap\n' >&2
    return 1
  }
  ((MAX_JFR_BYTES % (1024 * 1024) == 0)) || return 1
  jfr_cap_mib="$((MAX_JFR_BYTES / 1024 / 1024))"
  [[ "$flattened" == *"limited to $jfr_cap_mib MiB and $JAVA_JFR_MAX_DURATION_SECONDS seconds"* &&
    "$flattened" == *"normalization stops at 600,000 records"* &&
    "$flattened" == *"may exceed $MAX_JAVA_EVIDENCE_FILES entries"* ]] || {
    printf 'benchmark documentation drifted from Java evidence bounds\n' >&2
    return 1
  }
)

test_proc_snapshot_requires_container_starttime_and_cgroup_identity() (
  local -r fixture="$TEST_TMP_DIR/proc-identity"
  local -r proc_root="$fixture/proc"
  local -r pid=4242
  local -r container_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local -r wrong_container_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  local -r identity="$fixture/identity.txt"
  local -r snapshot="$fixture/snapshot.txt"
  local current=""
  local start_time=""
  local cgroup_sha256=""
  local binding=""
  local field=0

  mkdir -p -- "$proc_root/$pid/fd" "$proc_root/$pid/task"
  touch -- "$proc_root/$pid/fd/3" "$proc_root/$pid/task/$pid"
  {
    printf '%s (fixture process) S' "$pid"
    for ((field = 1; field <= 18; field++)); do
      printf ' 1'
    done
    printf ' 777\n'
  } >"$proc_root/$pid/stat"
  printf 'Name:\tfixture\nThreads:\t1\n' >"$proc_root/$pid/status"
  printf '0::/system.slice/docker-%s.scope\n' "$container_id" \
    >"$proc_root/$pid/cgroup"
  reset_options
  resolve_benchmark_identity_tools
  current="$(proc_identity_from_root "$proc_root" "$pid" "$container_id")" || {
    printf 'could not capture the copied proc identity fixture\n' >&2
    return 1
  }
  read -r start_time cgroup_sha256 binding <<<"$current" || return 1
  [[ "$binding" == "$PROC_CGROUP_CONTAINER_BINDING" ]] || return 1
  {
    printf 'service=fixture\n'
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$pid"
    printf 'proc_start_time=%s\n' "$start_time"
    printf 'proc_cgroup_sha256=%s\n' "$cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' "$binding"
    printf 'project=fixture\n'
    printf 'owner_sentinel=acceptance-demo-v1\n'
  } >"$identity"
  capture_proc_snapshot_from_root "$identity" "$snapshot" "$proc_root"
  grep -Fxq status=available "$snapshot" &&
    grep -Fxq "proc_start_time=$start_time" "$snapshot" &&
    grep -Fxq "proc_cgroup_sha256=$cgroup_sha256" "$snapshot" &&
    grep -Fxq "proc_cgroup_container_binding=$PROC_CGROUP_CONTAINER_BINDING" \
      "$snapshot" || {
    printf 'matching local process identity did not produce an available sample\n' >&2
    return 1
  }
  sed -i "s/^proc_start_time=.*/proc_start_time=$((start_time + 1))/" "$identity"
  capture_proc_snapshot_from_root "$identity" "$snapshot" "$proc_root"
  grep -Fxq status=unavailable "$snapshot" || {
    printf 'process snapshot accepted a reused PID start-time mismatch\n' >&2
    return 1
  }
  sed -i "s/^proc_start_time=.*/proc_start_time=$start_time/" "$identity"
  sed -i 's/^proc_cgroup_sha256=.*/proc_cgroup_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/' \
    "$identity"
  capture_proc_snapshot_from_root "$identity" "$snapshot" "$proc_root"
  grep -Fxq status=unavailable "$snapshot" || {
    printf 'process snapshot accepted an unrelated cgroup identity\n' >&2
    return 1
  }
  sed -i "s/^proc_cgroup_sha256=.*/proc_cgroup_sha256=$cgroup_sha256/" "$identity"

  printf '0::/system.slice/no-container.scope\n' >"$proc_root/$pid/cgroup"
  if proc_identity_from_root "$proc_root" "$pid" "$container_id" >/dev/null 2>&1; then
    printf 'proc identity accepted a cgroup without a container ID\n' >&2
    return 1
  fi
  printf '0::/system.slice/docker-%s.scope\n' "$wrong_container_id" \
    >"$proc_root/$pid/cgroup"
  if proc_identity_from_root "$proc_root" "$pid" "$container_id" >/dev/null 2>&1; then
    printf 'proc identity accepted the wrong full container ID\n' >&2
    return 1
  fi
  printf '0::/system.slice/docker-%s.scope\n' "${container_id:0:63}" \
    >"$proc_root/$pid/cgroup"
  if proc_identity_from_root "$proc_root" "$pid" "$container_id" >/dev/null 2>&1; then
    printf 'proc identity accepted a prefix-only container ID\n' >&2
    return 1
  fi
  {
    printf '0::/system.slice/docker-%s.scope/' "$container_id"
    head -c "$MAX_PROC_CGROUP_BYTES" /dev/zero | tr '\0' x
  } >"$proc_root/$pid/cgroup"
  if proc_identity_from_root "$proc_root" "$pid" "$container_id" >/dev/null 2>&1; then
    printf 'proc identity accepted an oversized cgroup file\n' >&2
    return 1
  fi

  printf '0::/system.slice/docker-%s.scope\n' "$container_id" \
    >"$proc_root/$pid/cgroup"
  current="$(proc_identity_from_root "$proc_root" "$pid" "$container_id")" || return 1
  read -r start_time cgroup_sha256 binding <<<"$current" || return 1
  sed -i "s/^proc_cgroup_sha256=.*/proc_cgroup_sha256=$cgroup_sha256/" "$identity"
  printf '0::/alternate/docker-%s.scope\n' "$container_id" \
    >"$proc_root/$pid/cgroup"
  capture_proc_snapshot_from_root "$identity" "$snapshot" "$proc_root"
  grep -Fxq status=unavailable "$snapshot" || {
    printf 'process snapshot accepted cgroup identity drift\n' >&2
    return 1
  }
)

test_bpf_fd_ownership_requires_bound_stable_proc_identity() (
  local -r fixture="$TEST_TMP_DIR/bpf-fd-ownership"
  local -r proc_root="$fixture/proc"
  local -r pid=4343
  local -r container_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local -r identity="$fixture/identity.txt"
  local -r ownership="$fixture/ownership.txt"
  local current=""
  local start_time=""
  local cgroup_sha256=""
  local binding=""
  local field=0

  mkdir -p -- "$proc_root/$pid/fd" "$proc_root/$pid/fdinfo" "$proc_root/$pid/task"
  touch -- "$proc_root/$pid/task/$pid"
  for field in 3 4 5 6; do
    ln -s -- /dev/null "$proc_root/$pid/fd/$field"
  done
  {
    printf '%s (fixture process) S' "$pid"
    for ((field = 1; field <= 18; field++)); do
      printf ' 1'
    done
    printf ' 888\n'
  } >"$proc_root/$pid/stat"
  printf 'Name:\tfixture\nThreads:\t1\n' >"$proc_root/$pid/status"
  printf '0::/system.slice/docker-%s.scope\n' "$container_id" \
    >"$proc_root/$pid/cgroup"
  printf 'pos:\t0\nflags:\t0100000\n' >"$proc_root/$pid/fdinfo/3"
  printf 'pos:\t0\nflags:\t02000002\nmap_id:\t41\n' >"$proc_root/$pid/fdinfo/4"
  printf 'pos:\t0\nflags:\t02000002\nprog_id:\t71\n' >"$proc_root/$pid/fdinfo/5"
  printf 'pos:\t0\nflags:\t02000002\nmap_id:\t41\n' >"$proc_root/$pid/fdinfo/6"
  reset_options
  resolve_benchmark_identity_tools
  current="$(proc_identity_from_root "$proc_root" "$pid" "$container_id")" || return 1
  read -r start_time cgroup_sha256 binding <<<"$current" || return 1
  {
    printf 'service=obi\n'
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$pid"
    printf 'proc_start_time=%s\n' "$start_time"
    printf 'proc_cgroup_sha256=%s\n' "$cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' "$binding"
    printf 'project=fixture\n'
    printf 'owner_sentinel=acceptance-demo-v1\n'
  } >"$identity"
  capture_bpf_fd_ownership_from_root "$identity" "$ownership" "$proc_root"
  jq -e '
    .container_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
    .host_pid == 4343 and .proc_start_time == 888 and
    .proc_cgroup_container_binding == "full_container_id_at_non_hex_boundaries" and
    .descriptors == [
      {fd: 4, kind: "map_id", id: 41},
      {fd: 5, kind: "prog_id", id: 71},
      {fd: 6, kind: "map_id", id: 41}
    ] and .map_ids == [41] and .program_ids == [71]
  ' < <(bpf_fd_ownership_json "$ownership") >/dev/null || {
    printf 'exact bound BPF FD ownership did not normalize canonically\n' >&2
    return 1
  }

  rm -f -- "$proc_root/$pid/fd/6"
  capture_bpf_fd_ownership_from_root "$identity" "$ownership" "$proc_root"
  grep -Fxq 'status=unavailable' "$ownership" || {
    printf 'BPF FD ownership accepted an fdinfo entry without a matching FD\n' >&2
    return 1
  }
  ln -s -- /dev/null "$proc_root/$pid/fd/6"
  ln -s -- /dev/null "$proc_root/$pid/fd/7"
  capture_bpf_fd_ownership_from_root "$identity" "$ownership" "$proc_root"
  grep -Fxq 'status=unavailable' "$ownership" || {
    printf 'BPF FD ownership accepted an FD without matching fdinfo\n' >&2
    return 1
  }
  rm -f -- "$proc_root/$pid/fd/7"

  local mutation_done=false
  head() {
    local -r path="${*: -1}"

    command head "$@" || return 1
    if [[ "$mutation_done" == false && "$path" == "$proc_root/$pid/fdinfo/4" ]]; then
      printf 'pos:\t0\nflags:\t02000002\nmap_id:\t42\n' >"$proc_root/$pid/fdinfo/4"
      printf 'pos:\t0\nflags:\t02000002\nprog_id:\t72\n' >"$proc_root/$pid/fdinfo/5"
      mutation_done=true
    fi
  }
  capture_bpf_fd_ownership_from_root "$identity" "$ownership" "$proc_root"
  grep -Fxq 'status=unavailable' "$ownership" || {
    printf 'BPF FD ownership accepted a hybrid intra-capture descriptor roster\n' >&2
    return 1
  }
  unset -f head
  printf 'pos:\t0\nflags:\t02000002\nmap_id:\t41\n' >"$proc_root/$pid/fdinfo/4"
  printf 'pos:\t0\nflags:\t02000002\nprog_id:\t71\n' >"$proc_root/$pid/fdinfo/5"

  printf 'pos:\t0\nmap_id:\t41\nmap_id:\t42\n' >"$proc_root/$pid/fdinfo/4"
  capture_bpf_fd_ownership_from_root "$identity" "$ownership" "$proc_root"
  grep -Fxq 'status=unavailable' "$ownership" || {
    printf 'duplicate BPF FD identity was accepted\n' >&2
    return 1
  }
  printf 'pos:\t0\nmap_id:\t41\n' >"$proc_root/$pid/fdinfo/4"
  sed -i "s/^proc_start_time=.*/proc_start_time=$((start_time + 1))/" "$identity"
  capture_bpf_fd_ownership_from_root "$identity" "$ownership" "$proc_root"
  grep -Fxq 'status=unavailable' "$ownership" || {
    printf 'BPF FD ownership accepted PID start-time drift\n' >&2
    return 1
  }
)

test_make_compiler_resolution_honors_and_pins_inherited_cc() (
  local -r compiler_directory="$TEST_TMP_DIR/compiler-resolution"
  local -r inherited_compiler="$compiler_directory/inherited-cc"
  local -r expanded_command="$compiler_directory/expanded-build-command.txt"
  local -r hostile_marker="$compiler_directory/hostile-resolution.marker"
  local -r hostile_stderr="$compiler_directory/hostile-resolution.stderr"
  local default_compiler=""
  local inherited_compiler_canonical=""
  local trusted_cc=""
  local trusted_true=""
  local hostile_staging=""
  local compiler_definition=""
  local staging_definition=""
  local flag=""

  reset_options
  mkdir -- "$compiler_directory"
  install -m 0755 /bin/true "$inherited_compiler"
  printf '$(shell /usr/bin/touch %s)\nCC = /bin/false\nCFLAGS = -DINJECTED\n' \
    "$compiler_directory/makefiles-marker" >"$compiler_directory/injected.mk"
  export MAKEFILES="$compiler_directory/injected.mk"
  export MAKEFLAGS='CFLAGS=-DMAKEFLAGS_INJECTED'
  export GNUMAKEFLAGS='CFLAGS=-DGNUMAKEFLAGS_INJECTED'
  export MFLAGS='CFLAGS=-DMFLAGS_INJECTED'
  export MAKEOVERRIDES='CFLAGS'
  CC="$inherited_compiler"
  export CC
  resolve_native_benchmark_compiler || {
    printf 'inherited CC could not be resolved through Makefile.jni\n' >&2
    return 1
  }
  inherited_compiler_canonical="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "$inherited_compiler")" || return 1
  [[ "$NATIVE_BENCHMARK_COMPILER" == "$inherited_compiler_canonical" &&
    "$NATIVE_BENCHMARK_COMPILER_SELECTION" == inherited_CC &&
    ! -e "$compiler_directory/makefiles-marker" ]] || {
    printf 'inherited CC was not retained as the compiler selected by Make\n' >&2
    return 1
  }
  {
    printf '%s' "$NATIVE_BENCHMARK_COMPILER"
    for flag in "${NATIVE_BENCHMARK_COMPILE_FLAGS[@]}"; do
      printf ' %s' "$flag"
    done
    printf ' %s' \
      'src/main/c/io_opentelemetry_obi_java_jni.c' \
      'src/test/c/remote_parent_jni_benchmark.c'
    for flag in "${NATIVE_BENCHMARK_LINK_FLAGS[@]}"; do
      printf ' %s' "$flag"
    done
    printf ' -o /tmp/remote_parent_jni_benchmark\n'
    printf '/tmp/remote_parent_jni_benchmark 10000\n'
  } >"$expanded_command"
  validate_native_expanded_build_command \
    "$expanded_command" "$NATIVE_BENCHMARK_COMPILER" || {
    printf 'expanded Make command did not prove the pinned compiler and flags\n' >&2
    return 1
  }
  sed 's/ -DOBI_JNI_TESTING//' "$expanded_command" >"$expanded_command.invalid"
  if validate_native_expanded_build_command \
    "$expanded_command.invalid" "$NATIVE_BENCHMARK_COMPILER"; then
    printf 'expanded Make validator accepted a missing production benchmark flag\n' >&2
    return 1
  fi

  CC='cc -fno-omit-frame-pointer'
  if resolve_native_benchmark_compiler >/dev/null 2>&1; then
    printf 'compiler resolver accepted an ambiguous CC command with arguments\n' >&2
    return 1
  fi
  CC="\$(shell /usr/bin/touch $compiler_directory/cc-marker)"
  if resolve_native_benchmark_compiler >/dev/null 2>&1 ||
    [[ -e "$compiler_directory/cc-marker" ]]; then
    printf 'compiler resolver evaluated Make syntax from inherited CC\n' >&2
    return 1
  fi

  unset CC
  resolve_native_benchmark_compiler || {
    printf 'Makefile.jni default compiler could not be resolved\n' >&2
    return 1
  }
  resolve_trusted_native_tool cc || return 1
  default_compiler="$TRUSTED_NATIVE_TOOL_RESULT"
  [[ "$NATIVE_BENCHMARK_COMPILER" == "$default_compiler" &&
    "$NATIVE_BENCHMARK_COMPILER_SELECTION" == make_default ]] || {
    printf 'compiler resolver did not use the actual Make default CC\n' >&2
    return 1
  }

  resolve_trusted_native_tool cc || return 1
  trusted_cc="$TRUSTED_NATIVE_TOOL_RESULT"
  resolve_trusted_native_tool true || return 1
  trusted_true="$TRUSTED_NATIVE_TOOL_RESULT"
  (
    local configured_test_compiler=""
    local staging_canonical=""

    query_clean_native_benchmark_compiler() {
      # shellcheck disable=SC2317 # Isolated resolver seam; avoids unrelated utilities.
      builtin printf '%s\n' "$configured_test_compiler"
    }
    type() { : >"$hostile_marker"; return 93; }
    readlink() { : >"$hostile_marker"; return 93; }
    function /usr/bin/readlink() { : >"$hostile_marker"; return 93; }
    function /bin/readlink() { : >"$hostile_marker"; return 93; }
    function /usr/bin/cc() { : >"$hostile_marker"; return 93; }
    function /bin/cc() { : >"$hostile_marker"; return 93; }
    function /usr/bin/true() { : >"$hostile_marker"; return 93; }
    function /bin/true() { : >"$hostile_marker"; return 93; }
    export -f type readlink
    export LD_AUDIT="$compiler_directory/missing-audit.so"
    export LD_LIBRARY_PATH="$compiler_directory/missing-loader"
    export LD_PRELOAD="$compiler_directory/missing-preload.so"

    configured_test_compiler="$trusted_true"
    CC="$trusted_true"
    export CC
    resolve_native_benchmark_compiler || return 1
    [[ "$NATIVE_BENCHMARK_COMPILER" == "$trusted_true" &&
      "$NATIVE_BENCHMARK_COMPILER_SELECTION" == inherited_CC ]] || return 1

    configured_test_compiler=cc
    CC=cc
    export CC
    resolve_native_benchmark_compiler || return 1
    [[ "$NATIVE_BENCHMARK_COMPILER" == "$trusted_cc" &&
      "$NATIVE_BENCHMARK_COMPILER_SELECTION" == inherited_CC ]] || return 1

    unset CC
    resolve_native_benchmark_compiler || return 1
    [[ "$NATIVE_BENCHMARK_COMPILER" == "$trusted_cc" &&
      "$NATIVE_BENCHMARK_COMPILER_SELECTION" == make_default ]] || return 1

    unset LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD
    hostile_staging="$(create_native_build_staging_directory)" || return 1
    export LD_AUDIT="$compiler_directory/missing-audit.so"
    export LD_LIBRARY_PATH="$compiler_directory/missing-loader"
    export LD_PRELOAD="$compiler_directory/missing-preload.so"
    staging_canonical="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "$hostile_staging")" || return 1
    [[ "$staging_canonical" == "$hostile_staging" ]] || return 1
    unset LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD
    cleanup_native_build_staging_directory "$hostile_staging" || return 1
  ) 2>"$hostile_stderr" || {
    printf 'compiler or staging resolution accepted shell/loader poisoning\n' >&2
    return 1
  }
  [[ ! -e "$hostile_marker" && ! -L "$hostile_marker" &&
    ! -s "$hostile_stderr" ]] || {
    printf 'compiler or staging resolver invoked poisoned type/readlink/loader state\n' >&2
    return 1
  }
  compiler_definition="$(declare -f resolve_native_benchmark_compiler)" || return 1
  staging_definition="$(declare -f create_native_build_staging_directory)" || return 1
  [[ "$compiler_definition" != *'type -P'* &&
    "$compiler_definition" != *'readlink -f'* &&
    "$compiler_definition" == *'resolve_trusted_native_tool "$configured_compiler"'* &&
    "$compiler_definition" == *'"$NATIVE_BENCHMARK_READLINK_COMMAND" -f'* &&
    "$staging_definition" != *'readlink -f'* &&
    "$staging_definition" == *'"$NATIVE_BENCHMARK_READLINK_COMMAND" -f'* ]] || {
    printf 'compiler or staging canonicalization lost its authenticated resolver\n' >&2
    return 1
  }
)

test_trusted_native_tool_resolution_is_function_and_loader_immune() (
  local -r fixture="$TEST_TMP_DIR/native-tool-resolution"
  local -r shadow_marker="$fixture/shadow.marker"
  local -r resolver_stderr="$fixture/resolver.stderr"
  local tool=""
  local -ar tool_names=(env git make perl readlink sha256sum timeout true)
  local -A expected_tools=()

  mkdir -- "$fixture"
  for tool in "${tool_names[@]}"; do
    resolve_trusted_native_tool "$tool" || return 1
    expected_tools["$tool"]="$TRUSTED_NATIVE_TOOL_RESULT"
  done
  resolve_native_benchmark_tools || return 1
  (
    printf() { : >"$shadow_marker"; return 93; }
    function /usr/bin/printf() { : >"$shadow_marker"; return 93; }
    command() { : >"$shadow_marker"; return 93; }
    builtin() { : >"$shadow_marker"; return 93; }
    type() { : >"$shadow_marker"; return 93; }
    readlink() { : >"$shadow_marker"; return 93; }
    function /usr/bin/readlink() { : >"$shadow_marker"; return 93; }
    # Deliberately uncalled: POSIX special-builtin lookup must bypass it.
    # shellcheck disable=SC2120
    exec() {
      (($# == 0)) && return 0
      : >"$shadow_marker"
      return 93
    }
    env() { : >"$shadow_marker"; return 93; }
    export -f printf command builtin type readlink exec env
    export LD_AUDIT="$fixture/missing-audit.so"
    export LD_LIBRARY_PATH="$fixture/missing-loader"
    export LD_PRELOAD="$fixture/missing-preload.so"
    for tool in "${tool_names[@]}"; do
      resolve_trusted_native_tool "$tool" || return 1
      [[ "$TRUSTED_NATIVE_TOOL_RESULT" == "${expected_tools[$tool]}" ]] || return 1
    done
    resolve_native_benchmark_tools || return 1
    [[ "$NATIVE_BENCHMARK_ENV_COMMAND" == "${expected_tools[env]}" &&
      "$NATIVE_BENCHMARK_GIT_COMMAND" == "${expected_tools[git]}" &&
      "$NATIVE_BENCHMARK_MAKE_COMMAND" == "${expected_tools[make]}" &&
      "$NATIVE_BENCHMARK_PERL_COMMAND" == "${expected_tools[perl]}" &&
      "$NATIVE_BENCHMARK_READLINK_COMMAND" == "${expected_tools[readlink]}" &&
      "$NATIVE_BENCHMARK_SHA256_COMMAND" == "${expected_tools[sha256sum]}" &&
      "$NATIVE_BENCHMARK_TIMEOUT_COMMAND" == "${expected_tools[timeout]}" ]] || return 1
    run_native_clean_environment "${expected_tools[true]}"
  ) 2>"$resolver_stderr" || {
    printf 'trusted native tool resolution accepted function or loader poisoning\n' >&2
    return 1
  }
  [[ ! -e "$shadow_marker" && ! -L "$shadow_marker" &&
    ! -s "$resolver_stderr" ]] || {
    printf 'trusted native resolver invoked a callable formatter or poisoned loader\n' >&2
    return 1
  }
)

test_native_make_environment_and_staging_are_hermetic() (
  local -r fixture="$TEST_TMP_DIR/native-hermetic"
  local -r compiler="$fixture/compiler"
  local -r compiler_log="$fixture/compiler.log"
  local -r runtime_log="$fixture/runtime.log"
  local -r marker="$fixture/makefiles-marker"
  local -r output_marker="$fixture/output-path-marker"
  local -r build_command="$fixture/build-command.txt"
  local -r clean_exec_shadow_marker="$fixture/clean-exec-shadow-marker"
  local -r clean_exec_stderr="$fixture/clean-exec.stderr"
  local staging=""
  local hostile_output=""
  local native_true=""
  local -a make_arguments=()

  mkdir -- "$fixture"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'if [[ "${1:-}" == --version ]]; then printf "fixture compiler\\n"; exit 0; fi' \
    "printf 'args=' >$(printf '%q' "$compiler_log")" \
    "printf '%q ' \"\$@\" >>$(printf '%q' "$compiler_log")" \
    "printf '\\n' >>$(printf '%q' "$compiler_log")" \
    "/usr/bin/env | /usr/bin/sort >>$(printf '%q' "$compiler_log")" \
    'output=""' \
    'while (($# > 0)); do if [[ "$1" == -o ]]; then output="$2"; shift 2; else shift; fi; done' \
    '[[ "$output" == /* ]]' \
    "printf '%s\\n' '#!/bin/sh' $(printf '%q' "/usr/bin/env | /usr/bin/sort >$runtime_log") 'exit 0' >\"\$output\"" \
    '/usr/bin/chmod 0700 -- "$output"' \
    >"$compiler"
  chmod 0700 -- "$compiler"
  {
    printf 'CFLAGS = -DFIXED\n'
    printf 'all:\n'
    printf '\t$(CC) $(CFLAGS) -o $(BUILD_DIR)/artifact\n'
    printf '\t$(BUILD_DIR)/artifact\n'
  } >"$fixture/Makefile"
  printf '$(shell /usr/bin/touch %s)\nCFLAGS = -DINJECTED\n' "$marker" \
    >"$fixture/injected.mk"
  resolve_native_benchmark_tools
  resolve_trusted_native_tool true || return 1
  native_true="$TRUSTED_NATIVE_TOOL_RESULT"
  (
    command() {
      printf 'command shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    builtin() {
      printf 'builtin shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    type() {
      printf 'type shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    unset() {
      printf 'unset shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    # Deliberately uncalled: POSIX special-builtin lookup must bypass it.
    # shellcheck disable=SC2120
    exec() {
      (($# == 0)) && return 0
      printf 'exec shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    env() {
      printf 'env shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    function /usr/bin/env() {
      printf 'absolute env shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    function /usr/bin/readlink() {
      printf 'absolute readlink shadow invoked\n' >"$clean_exec_shadow_marker"
      return 93
    }
    export -f command builtin type unset exec env
    resolve_trusted_native_tool true || return 1
    [[ "$TRUSTED_NATIVE_TOOL_RESULT" == "$native_true" ]] || return 1
    LD_AUDIT="$fixture/missing-audit.so" \
      LD_LIBRARY_PATH="$fixture/missing-loader" \
      LD_PRELOAD="$fixture/missing-preload.so" \
      run_native_clean_environment "$native_true"
  ) 2>"$clean_exec_stderr" || {
    printf 'native clean execution accepted a shadowed exec transition\n' >&2
    return 1
  }
  [[ ! -e "$clean_exec_shadow_marker" && ! -L "$clean_exec_shadow_marker" &&
    ! -s "$clean_exec_stderr" ]] || {
    printf 'native clean execution exposed a function or loader poison\n' >&2
    return 1
  }
  staging="$(create_native_build_staging_directory)" || return 1
  hostile_output="$fixture/\$(shell /usr/bin/touch $output_marker)"
  OUTPUT_DIR="$hostile_output"
  make_arguments=(
    --no-print-directory --directory "$fixture" --file Makefile all
    "CC=$compiler" "BUILD_DIR=$staging"
  )
  write_native_make_build_command \
    "$build_command" 15 "${make_arguments[@]}" || return 1
  export MAKEFILES="$fixture/injected.mk"
  export MAKEFLAGS='CFLAGS=-DMAKEFLAGS_INJECTED'
  export GNUMAKEFLAGS='CFLAGS=-DGNUMAKEFLAGS_INJECTED'
  export MFLAGS='CFLAGS=-DMFLAGS_INJECTED'
  export MAKEOVERRIDES='CFLAGS'
  export CPATH="$fixture/hostile-cpath"
  export C_INCLUDE_PATH="$fixture/hostile-include"
  export GCC_EXEC_PREFIX="$fixture/hostile-gcc"
  export COMPILER_PATH="$fixture/hostile-compiler-path"
  export LIBRARY_PATH="$fixture/hostile-library"
  export LD_AUDIT="$fixture/hostile-audit.so"
  export LD_LIBRARY_PATH="$fixture/hostile-loader"
  export LD_PRELOAD="$fixture/hostile-preload.so"
  run_native_bounded 15 "$NATIVE_BENCHMARK_MAKE_COMMAND" \
    "${make_arguments[@]}" || return 1
  unset MAKEFILES MAKEFLAGS GNUMAKEFLAGS MFLAGS MAKEOVERRIDES CPATH \
    C_INCLUDE_PATH GCC_EXEC_PREFIX COMPILER_PATH LIBRARY_PATH \
    LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD
  [[ -x "$staging/artifact" && -s "$runtime_log" &&
    ! -e "$marker" && ! -e "$output_marker" ]] || {
    printf 'hostile Make or output-path input affected the staged build\n' >&2
    return 1
  }
  grep -Fq -- '-DFIXED' "$compiler_log" &&
    ! grep -Fq -- 'INJECTED' "$compiler_log" &&
    ! grep -Eq '^(CPATH|C_INCLUDE_PATH|GCC_EXEC_PREFIX|COMPILER_PATH|LIBRARY_PATH|LD_AUDIT|LD_LIBRARY_PATH|LD_PRELOAD)=' \
      "$compiler_log" &&
    ! grep -Eq '^(CPATH|C_INCLUDE_PATH|GCC_EXEC_PREFIX|COMPILER_PATH|LIBRARY_PATH|LD_AUDIT|LD_LIBRARY_PATH|LD_PRELOAD)=' \
      "$runtime_log" || {
    printf 'native compiler or benchmark inherited an uncontrolled environment\n' >&2
    return 1
  }
  grep -Fq -- "( POSIXLY_CORRECT=1; [[ -o posix ]] || exit 1; exec -c $NATIVE_BENCHMARK_ENV_COMMAND -i" "$build_command" &&
    grep -Fq -- "$NATIVE_BENCHMARK_ENV_COMMAND -i" "$build_command" &&
    grep -Fq -- "PATH=/usr/bin:/bin" "$build_command" &&
    grep -Fq -- "$NATIVE_BENCHMARK_MAKE_COMMAND" "$build_command" &&
    ! grep -Fq -- "$hostile_output" "$build_command" || {
    printf 'recorded native build command did not match the sanitized invocation\n' >&2
    return 1
  }
  cleanup_native_build_staging_directory "$staging"
  [[ ! -e "$staging" ]]
)

test_native_source_state_rejects_dirty_and_mutating_inputs() (
  local -r repository="$TEST_TMP_DIR/native-source-repository"
  local -r evidence="$TEST_TMP_DIR/native-source-evidence"
  local -r filtered_path="${NATIVE_BENCHMARK_SOURCE_PATHS[2]}"
  local -r filter="$TEST_TMP_DIR/native-source-clean-filter"
  local filtered_blob=""
  local head_blob=""
  local path=""

  mkdir -p -- "$repository" "$evidence"
  for path in "${NATIVE_BENCHMARK_SOURCE_PATHS[@]}"; do
    mkdir -p -- "$repository/${path%/*}"
    printf 'fixture %s\n' "$path" >"$repository/$path"
  done
  git -C "$repository" init --quiet
  git -C "$repository" config user.email benchmark@example.invalid
  git -C "$repository" config user.name 'Benchmark Test'
  git -C "$repository" config commit.gpgsign false
  git -C "$repository" add -- "${NATIVE_BENCHMARK_SOURCE_PATHS[@]}"
  git -C "$repository" commit --quiet -m fixture
  capture_native_source_snapshot "$repository" "$evidence/source-state-before.json" || {
    printf 'clean native source snapshot was rejected\n' >&2
    return 1
  }
  printf 'mutated\n' >>"$repository/${NATIVE_BENCHMARK_SOURCE_PATHS[2]}"
  if capture_native_source_snapshot "$repository" "$evidence/dirty.json"; then
    printf 'dirty native source was accepted\n' >&2
    return 1
  fi
  printf 'fixture %s\n' "$filtered_path" >"$repository/$filtered_path"
  printf '%s\n' \
    '#!/bin/sh' \
    "printf '%s\\n' $(printf '%q' "fixture $filtered_path")" >"$filter"
  chmod 0700 -- "$filter"
  printf '%s filter=mask-dirty-native-source\n' "$filtered_path" \
    >"$repository/.gitattributes"
  git -C "$repository" config filter.mask-dirty-native-source.clean "$filter"
  git -C "$repository" config filter.mask-dirty-native-source.required true
  printf 'dirty content hidden by a Git clean filter\n' >"$repository/$filtered_path"
  head_blob="$(git -C "$repository" rev-parse "HEAD:$filtered_path")" || return 1
  filtered_blob="$(git -C "$repository" hash-object \
    --path="$filtered_path" -- "$repository/$filtered_path")" || return 1
  [[ "$filtered_blob" == "$head_blob" ]] || {
    printf 'dirty-source filter fixture did not mask the working-tree mutation\n' >&2
    return 1
  }
  if capture_native_source_snapshot "$repository" "$evidence/filtered-dirty.json"; then
    printf 'native source identity trusted a Git clean filter over raw bytes\n' >&2
    return 1
  fi
  rm -f -- "$repository/.gitattributes"
  git -C "$repository" config --unset filter.mask-dirty-native-source.clean
  git -C "$repository" config --unset filter.mask-dirty-native-source.required
  printf 'fixture %s\n' "$filtered_path" >"$repository/$filtered_path"
  capture_native_source_snapshot "$repository" "$evidence/source-state-after.json" || return 1
  finalize_native_source_state \
    "$evidence/source-state-before.json" "$evidence/source-state-after.json" \
    "$evidence/source-state.json" || return 1
  validate_native_source_state_schema "$evidence/source-state.json" || return 1
  printf 'mutated during build\n' >>"$repository/${NATIVE_BENCHMARK_SOURCE_PATHS[3]}"
  if capture_native_source_snapshot "$repository" "$evidence/mutated-after.json"; then
    printf 'native source mutation between captures was accepted\n' >&2
    return 1
  fi
)

test_output_directory_is_absolute_fresh_private() {
  local -r private_output="$TEST_TMP_DIR/new output; literal-dollar\$"
  local -r existing_directory="$TEST_TMP_DIR/existing"
  local -r existing_file="$TEST_TMP_DIR/existing-file"
  local -r symlink_target="$TEST_TMP_DIR/symlink-target"
  local -r symlink_parent="$TEST_TMP_DIR/symlink-parent"
  local -r insecure_parent="$TEST_TMP_DIR/insecure-parent"
  local -r repository_output="$REPO_ROOT/benchmark-artifacts-forbidden"

  (
    reset_options
    OUTPUT_DIR="$private_output"
    prepare_output_directory
    [[ -d "$OUTPUT_DIR" && "$(stat --format '%a' -- "$OUTPUT_DIR")" == 700 ]]
  ) || {
    printf 'fresh private output directory was not created\n' >&2
    return 1
  }
  mkdir -- "$existing_directory" "$symlink_target" "$insecure_parent"
  chmod 0755 -- "$insecure_parent"
  printf 'sentinel\n' >"$existing_file"
  ln -s -- "$symlink_target" "$symlink_parent"
  if (
    reset_options
    OUTPUT_DIR=relative-output
    prepare_output_directory
  ) >/dev/null 2>&1; then
    printf 'accepted a relative output directory\n' >&2
    return 1
  fi
  if (
    reset_options
    OUTPUT_DIR="$insecure_parent/output"
    prepare_output_directory
  ) >/dev/null 2>&1; then
    printf 'accepted a shared output parent\n' >&2
    return 1
  fi
  if (
    reset_options
    OUTPUT_DIR="$existing_directory"
    prepare_output_directory
  ) >/dev/null 2>&1; then
    printf 'accepted an existing output directory\n' >&2
    return 1
  fi
  if (
    reset_options
    OUTPUT_DIR="$existing_file"
    prepare_output_directory
  ) >/dev/null 2>&1; then
    printf 'accepted an existing output file\n' >&2
    return 1
  fi
  if (
    reset_options
    OUTPUT_DIR="$symlink_parent/output"
    prepare_output_directory
  ) >/dev/null 2>&1; then
    printf 'accepted a symbolic-link output parent\n' >&2
    return 1
  fi
  if (
    reset_options
    OUTPUT_DIR="$repository_output"
    prepare_output_directory
  ) >/dev/null 2>&1; then
    printf 'accepted an output directory inside the repository\n' >&2
    return 1
  fi
  [[ "$(<"$existing_file")" == sentinel ]] || {
    printf 'output validation modified an existing file\n' >&2
    return 1
  }
}

test_core_cell_mapping_is_exact() {
  local cell=""
  local expected=""

  while IFS='|' read -r cell expected; do
    (
      reset_options
      cell_spec "$cell"
      [[ "$CELL_SLUG|$CELL_TRANSPORT|$CELL_SCENARIO|$CELL_ASSERTION_MODE|$CELL_REQUIRES_OBI|$CELL_SELECTED_TRANSPORT|$CELL_SENTINEL_SCENARIO|$CELL_SUSTAINED_W3C|$CELL_EXPECTED_STANDARD_PARENT_DISCARDS|$CELL_EXPECTED_W3C_VALID_TAKES|$CELL_WORKLOAD_BASE_URL|$CELL_WORKLOAD_PATH|$CELL_WORKLOAD_CONNECTION_MODE|$CELL_WORKLOAD_CA_FILE|$CELL_EXPECTED_TLS_VERIFICATION|$CELL_UPSTREAM_HANDOFF|$CELL_HELPER_IDLE" == "$expected" ]]
    ) || {
      printf 'incorrect core cell mapping for %s\n' "$cell" >&2
      return 1
    }
  done <<'EOF'
uninstrumented|uninstrumented|disabled|benchmark-uninstrumented|uninstrumented|false|disabled|concurrency|false|0|0|http://127.0.0.1:18080|/api/echo?delay_ms=150|close||not_applicable|apache_proxy|false
bridge-disabled|bridge-disabled|disabled|benchmark-disabled|disabled|true|disabled|concurrency|false|0|0|http://127.0.0.1:18080|/api/echo?delay_ms=150|close||not_applicable|apache_proxy|false
getsockopt-hit|getsockopt-hit|getsockopt|concurrency||true|getsockopt|concurrency|false|0|0|http://127.0.0.1:18080|/api/echo?delay_ms=150|close||not_applicable|apache_proxy|false
unix-hit|unix-hit|unix|concurrency||true|unix|concurrency|false|0|0|http://127.0.0.1:18080|/api/echo?delay_ms=150|close||not_applicable|apache_proxy|false
getsockopt-w3c|getsockopt-w3c|getsockopt|w3c||true|getsockopt|w3c|true|8|16|http://127.0.0.1:18080|/api/echo?delay_ms=150|close||not_applicable|apache_proxy|false
getsockopt-helper-idle|getsockopt-helper-idle|getsockopt|concurrency||true|getsockopt|concurrency|false|0|0|https://127.0.0.1:18443|/api/echo?delay_ms=150|close|/benchmark-ca.crt|verified_ca_file|none|true
EOF
}

test_bounded_path_cell_mapping_is_exact() {
  local cell=""
  local expected=""

  while IFS='|' read -r cell expected; do
    (
      reset_options
      cell_spec "$cell"
      [[ "$CELL_SLUG|$CELL_TRANSPORT|$CELL_SCENARIO|$CELL_PREFLIGHT_REQUESTS|$CELL_MEASUREMENT_REQUESTS|$CELL_RESULT_LABEL|$CELL_PATH_CLASSIFICATION|$CELL_EXPECTED_JAVA_STATUS|$CELL_BOUNDED_PATH" == "$expected" ]]
    ) || {
      printf 'incorrect bounded path cell mapping for %s\n' "$cell" >&2
      return 1
    }
  done <<'EOF'
getsockopt-stale|getsockopt-stale|getsockopt|primary-w3c-stale|1|1|primary-w3c-stale|failure|stale|true
unix-stale|unix-stale|unix|unix-w3c-stale|1|1|unix-w3c-stale|failure|stale|true
unix-timeout|unix-timeout|unix|w3c-fault|2|1|w3c-fault-timeout|failure|timeout|true
getsockopt-pressure|getsockopt-pressure|getsockopt|pressure|128|128|pressure|pressure|mixed|true
EOF

  (
    local observed=""
    local expected=""

    reset_options
    cell_spec getsockopt-pressure
    observed="$(printf '%s\n' "${CELL_EXTRA_RUNNER_FILES[@]}")"
    expected="$(sed 's/^ *//' <<'EOF'
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
EOF
    )"
    [[ "$observed" == "$expected" ]]
  ) || {
    printf 'pressure retained runner artifact roster is not exact\n' >&2
    return 1
  }

  (
    reset_options
    cell_spec getsockopt-helper-idle
    [[ "$CELL_PATH_CLASSIFICATION" == "" &&
      "$CELL_EXPECTED_JAVA_STATUS" == "" &&
      "$CELL_BOUNDED_PATH" == false ]]
  ) || {
    printf 'helper-idle was relabelled as a lookup miss\n' >&2
    return 1
  }
}

test_core_mode_does_not_publish_complete_only_path_observations() (
  local -r calls="$TEST_TMP_DIR/core-path-observation.calls"

  write_path_observation() {
    printf '%s\n' "$1" >>"$calls"
  }
  reset_options
  cell_spec getsockopt-hit
  CELLS_MODE=core
  write_core_hit_path_observation_if_requested /fixture/getsockopt-hit
  [[ ! -e "$calls" ]] || {
    printf 'core mode published a complete-only hit path observation\n' >&2
    return 1
  }
  CELLS_MODE=complete
  write_core_hit_path_observation_if_requested /fixture/getsockopt-hit
  [[ "$(<"$calls")" == /fixture/getsockopt-hit ]] || return 1
  cell_spec getsockopt-w3c
  write_core_hit_path_observation_if_requested /fixture/getsockopt-w3c
  [[ "$(wc -l <"$calls")" == 1 ]]
)

write_path_observation_fixture() {
  local -r output="$1"
  local -r cell="${2:-getsockopt-stale}"
  local -r pressure_max_entries="${3:-$FAKE_PRESSURE_MAP_MAX_ENTRIES}"
  local transport=""
  local classification=""
  local java_status=""
  local label=""
  local requested=0
  local observed=0
  local valid=0
  local missing=0
  local stale=0
  local timeout_count=0
  local pressure="null"

  case "$cell" in
    getsockopt-hit)
      transport=getsockopt; classification=hit; java_status=valid
      label=concurrency; requested=16; observed=16; valid=16; missing=1
      ;;
    unix-hit)
      transport=unix; classification=hit; java_status=valid
      label=concurrency; requested=16; observed=16; valid=16; missing=1
      ;;
    getsockopt-stale)
      transport=getsockopt; classification=failure; java_status=stale
      label=primary-w3c-stale; requested=1; observed=1; stale=1
      ;;
    unix-stale)
      transport=unix; classification=failure; java_status=stale
      label=unix-w3c-stale; requested=1; observed=1; stale=1
      ;;
    unix-timeout)
      transport=unix; classification=failure; java_status=timeout
      label='w3c-fault-timeout'; requested=2; observed=1; timeout_count=1
      ;;
    getsockopt-pressure)
      transport=getsockopt; classification=pressure; java_status=mixed
      label=pressure; requested=128; observed=128; valid=127; missing=2
      [[ "$pressure_max_entries" =~ ^[1-9][0-9]*$ ]] || return 1
      pressure="$(jq -cn --argjson max_entries "$pressure_max_entries" '
        {
          bounded: true,
          pressure_contract_version: 2,
          barrier_schema: "pressure-traffic-barrier-v2",
          barrier_sequence: ["scenario_ready", "capacity_fill_verified",
            "release_published", "scenario_reaped",
            "post_traffic_content_verified"],
          exact_hit_count: 126,
          explicit_root_count: 1,
          w3c_parent_count: 1,
          wrong_parent_count: 0,
          unresolved_count: 0,
          retrieval_valid_count: 127,
          attributable_failure_count: 1,
          w3c_masked_valid_count: 1,
          take_valid_count: 127,
          take_sampled_count: 127,
          take_unsampled_count: 0,
          discard_standard_count: 1,
          attributable_absence_count: 1,
          diagnostic_self_miss_count: 1,
          handoff_admission_overload_count: 5,
          handoff_admission_ambiguous_count: 0,
          handoff_admission_maximum_count: 1152,
          map_name: "java_remote_parent_handoff_claims",
          map_type: "Hash",
          map_id: 41,
          kernel_map_name: "java_remote_par",
          kernel_map_type: "hash",
          max_entries: $max_entries,
          synthetic_pid: 0,
          synthetic_namespace: 0,
          touched_entries: $max_entries,
          capacity_rejected_entries: 1,
          fill_verified_present_entries: $max_entries,
          fill_verified_absent_entries: 1,
          content_sha256: ("a" * 64),
          post_traffic_verified_present_entries: $max_entries,
          post_traffic_verified_absent_entries: 1,
          post_traffic_content_sha256: ("a" * 64),
          post_traffic_content_verified: true,
          cleanup_verified: true,
          cleanup_verified_absent_entries: ($max_entries + 1),
          occupancy_before_fill: 0,
          occupancy_recovery_samples: [0, 0],
          occupancy_recovered: 0,
          recovery_log_attempts: 2,
          recovery_samples: 2
        }
      ')" || return 1
      ;;
    *) return 1 ;;
  esac
  jq -n \
    --arg cell "$cell" --arg transport "$transport" \
    --arg classification "$classification" --arg java_status "$java_status" \
    --arg label "$label" --argjson requested "$requested" \
    --argjson observed "$observed" --argjson valid "$valid" \
    --argjson missing "$missing" --argjson stale "$stale" \
    --argjson timeout "$timeout_count" --argjson pressure "$pressure" '
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
        runner_requested_requests: $requested,
        observed_requests: $observed,
        result_status: "passed"
      },
      java_diagnostic_status_deltas: {
        unknown: 0, valid: $valid, missing: $missing, stale: $stale, unsupported: 0,
        malformed: 0, version_mismatch: 0, ambiguous: 0, unauthorized: 0,
        already_consumed: 0, timeout: $timeout, overload: 0, transport_error: 0,
        disabled: 0
      },
      performance_metrics: {
        status: "not_evaluated_from_bounded_observation",
        reason: "one correctness execution is not a benchmark"
      },
      pressure: $pressure,
      source: {
        result: ("preflight/runner/scenario-" + $label + ".json"),
        status: ("preflight/runner/scenario-" + $label + "-status.json"),
        java_diagnostics_delta: ("preflight/runner/phases/" + $label + "-after/java-diagnostics.delta")
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
  ' >"$output"
}

test_bounded_paths_are_correctness_observations_not_performance_samples() {
  local -r observation="$TEST_TMP_DIR/path-observation.json"
  local -r invalid="$TEST_TMP_DIR/path-observation-invalid.json"
  local filter=""
  local label=""

  pressure_mutation_must_fail() {
    local -r mutation_filter="$1"
    local -r mutation_label="$2"

    jq "$mutation_filter" "$observation" >"$invalid" || return 1
    if validate_path_observation_schema "$invalid"; then
      printf 'pressure path observation accepted %s\n' "$mutation_label" >&2
      return 1
    fi
  }

  write_path_observation_fixture "$observation"
  validate_path_observation_schema "$observation" || {
    printf 'valid bounded correctness observation was rejected\n' >&2
    return 1
  }
  jq -e '
    .observation.mode == "bounded_correctness_observed_once" and
    .observation.runner_execution_count == 1 and
    .observation.observed_requests == 1 and
    .performance_metrics.status == "not_evaluated_from_bounded_observation" and
    (has("end_to_end") | not) and
    ([paths(scalars) as $path | $path[-1]] |
      index("throughput_per_second") == null and
      index("latency_p50_nanos") == null and
      index("latency_p95_nanos") == null and
      index("latency_p99_nanos") == null)
  ' "$observation" >/dev/null || {
    printf 'bounded path observation retained benchmark-like statistics\n' >&2
    return 1
  }

  jq '.end_to_end = {throughput_per_second: 1, latency_p99_nanos: 1}' \
    "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'bounded path schema accepted injected performance statistics\n' >&2
    return 1
  fi
  jq '.observation.mode = "measured"' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'bounded path schema accepted a benchmark-like coverage label\n' >&2
    return 1
  fi
  jq '.cell = "unix-stale"' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'path schema accepted a mismatched cell/transport/source contract\n' >&2
    return 1
  fi
  jq '.pressure = {}' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'path schema accepted pressure evidence on a stale cell\n' >&2
    return 1
  fi
  write_path_observation_fixture "$observation" getsockopt-pressure
  validate_path_observation_schema "$observation" || {
    printf 'exact pressure observation was rejected\n' >&2
    return 1
  }
  jq -e '
    .pressure.pressure_contract_version == 2 and
    .pressure.barrier_schema == "pressure-traffic-barrier-v2" and
    .pressure.exact_hit_count == 126 and
    .pressure.explicit_root_count == 1 and
    .pressure.w3c_parent_count == 1 and
    .pressure.retrieval_valid_count == 127 and
    .pressure.attributable_failure_count == 1 and
    .pressure.w3c_masked_valid_count == 1 and
    .pressure.take_valid_count == 127 and
    .pressure.take_sampled_count == 127 and
    .pressure.take_unsampled_count == 0 and
    .pressure.discard_standard_count == 1 and
    .pressure.attributable_absence_count == 1 and
    .pressure.diagnostic_self_miss_count == 1
  ' "$observation" >/dev/null || return 1
  jq '.observation.runner_requested_requests = 127' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'pressure observation accepted the wrong request count\n' >&2
    return 1
  fi
  while IFS='|' read -r label filter; do
    pressure_mutation_must_fail "$filter" "$label" || return 1
  done <<'EOF'
contract version 1|.pressure.pressure_contract_version = 1
barrier schema v1|.pressure.barrier_schema = "pressure-traffic-barrier-v1"
missing W3C field|del(.pressure.w3c_parent_count)
extra pressure field|.pressure.untrusted_count = 0
W=0|.pressure.w3c_parent_count = 0
W=2|.pressure.w3c_parent_count = 2
R=0|.pressure.explicit_root_count = 0
H+R+W!=N|.pressure.exact_hit_count = 125
wrong parent|.pressure.wrong_parent_count = 1
unresolved parent|.pressure.unresolved_count = 1
V<H|.pressure.retrieval_valid_count = 125
V>H+W|.pressure.retrieval_valid_count = 128
F<R|.pressure.attributable_failure_count = 0
F>R+W|.pressure.attributable_failure_count = 3
V+F!=N|.pressure.retrieval_valid_count = 126
M!=V-H|.pressure.w3c_masked_valid_count = 0
M outside 0..1|.pressure.w3c_masked_valid_count = 2
take_valid!=V|.pressure.take_valid_count = 126
take_sampled!=V|.pressure.take_sampled_count = 126
take_unsampled!=0|.pressure.take_unsampled_count = 1
discard_standard!=M|.pressure.discard_standard_count = 0
attributable_absence!=F|.pressure.attributable_absence_count = 2
diagnostic_self_miss!=1|.pressure.diagnostic_self_miss_count = 0
EOF
  jq 'del(.pressure.recovery_samples)' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'pressure observation accepted incomplete recovery evidence\n' >&2
    return 1
  fi
  jq '.pressure = null' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'pressure cell accepted missing pressure evidence\n' >&2
    return 1
  fi
}

test_pressure_recovery_evidence_parses_canonical_samples_and_log() (
  local -r root="$TEST_TMP_DIR/pressure-recovery-evidence"
  local -r observation="$root/path-observation.json"
  local -r runner="$root/preflight/runner"
  local -r sample_one="$runner/map-pressure-pressure-recovered-sample-01.prom"
  local -r sample_two="$runner/map-pressure-pressure-recovered-sample-02.prom"
  local -r recovered="$runner/map-pressure-pressure-recovered.prom"
  local -r log="$runner/map-pressure-pressure-recovered-samples.log"
  local -r baseline="$runner/phases/pressure-before/obi-metrics.prom"
  local -r fill="$runner/map-pressure-pressure-fill.json"
  local -r verify="$runner/map-pressure-pressure-verify.json"
  local -r inspections="$runner/map-pressure-pressure-container-inspections.json"
  local -r barrier="$runner/map-pressure-pressure-barrier-status.json"
  local -r status="$runner/scenario-pressure-status.json"
  local -r invalid_observation="$root/path-observation.invalid.json"
  local canonical_pressure=""
  local inspections_sha256=""
  local inspections_size=""
  local status_sha256=""

  mkdir -p -- "$root"
  write_path_observation_fixture "$observation" getsockopt-pressure
  materialize_path_observation_sources "$observation"
  validate_pressure_cell_artifacts "$runner" canonical_pressure || {
    printf 'production-shaped pressure recovery evidence was rejected\n' >&2
    return 1
  }
  jq -e '
    .map_id == 41 and .kernel_map_name == "java_remote_par" and
    .kernel_map_type == "hash" and .max_entries == 10000 and
    .occupancy_before_fill == 0 and .recovery_samples == 2 and
    .occupancy_recovery_samples == [0, 0] and .occupancy_recovered == 0 and
    .recovery_log_attempts == 2
  ' <<<"$canonical_pressure" >/dev/null || return 1
  jq -e --argjson canonical "$canonical_pressure" '.pressure == $canonical' \
    "$observation" >/dev/null || {
    printf 'pressure fixture diverged from the canonical raw evidence builder\n' >&2
    return 1
  }
  validate_path_observation_source_artifacts "$observation" || return 1

  mv -T -- "$inspections" "$inspections.missing" || return 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted a missing container inspection artifact\n' >&2
    return 1
  fi
  mv -T -- "$inspections.missing" "$inspections" || return 1

  chmod 0644 -- "$inspections" || return 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted public container inspection permissions\n' >&2
    return 1
  fi
  chmod 0600 -- "$inspections" || return 1

  command cp -- "$inspections" "$inspections.valid" || return 1
  command cp -- "$status" "$status.valid" || return 1
  command cp -- "$barrier" "$barrier.valid" || return 1
  jq -cS '.terminal.state.running = true' "$inspections" \
    >"$inspections.tmp" || return 1
  mv -T -- "$inspections.tmp" "$inspections" || return 1
  chmod 0600 -- "$inspections" || return 1
  inspections_sha256="$(sha256sum <"$inspections")" || return 1
  inspections_sha256="${inspections_sha256%% *}"
  inspections_size="$(stat -Lc '%s' -- "$inspections")" || return 1
  jq --arg sha256 "$inspections_sha256" --argjson size "$inspections_size" '
    .pressure_correlation.container_inspections.sha256 = $sha256 |
    .pressure_correlation.container_inspections.size_bytes = $size
  ' "$status" >"$status.tmp" || return 1
  mv -T -- "$status.tmp" "$status" || return 1
  status_sha256="$(sha256sum <"$status")" || return 1
  status_sha256="${status_sha256%% *}"
  jq -cS --arg inspections_sha256 "$inspections_sha256" \
    --argjson inspections_size "$inspections_size" \
    --arg status_sha256 "$status_sha256" '
    .container_inspections.sha256 = $inspections_sha256 |
    .container_inspections.size_bytes = $inspections_size |
    .traffic.status_sha256 = $status_sha256
  ' "$barrier" >"$barrier.tmp" || return 1
  mv -T -- "$barrier.tmp" "$barrier" || return 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted an impossible terminal inspection state\n' >&2
    return 1
  fi
  mv -T -- "$inspections.valid" "$inspections" || return 1
  mv -T -- "$status.valid" "$status" || return 1
  mv -T -- "$barrier.valid" "$barrier" || return 1

  command cp -- "$barrier" "$barrier.valid" || return 1
  jq -cS '.container_inspections.sha256 = ("f" * 64)' \
    "$barrier" >"$barrier.tmp" || return 1
  mv -T -- "$barrier.tmp" "$barrier" || return 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted a stale barrier inspection descriptor\n' >&2
    return 1
  fi
  mv -T -- "$barrier.valid" "$barrier" || return 1

  command cp -- "$status" "$status.valid" || return 1
  command cp -- "$barrier" "$barrier.valid" || return 1
  jq '.pressure_correlation.container_inspections.sha256 = ("f" * 64)' \
    "$status" >"$status.tmp" || return 1
  mv -T -- "$status.tmp" "$status" || return 1
  status_sha256="$(sha256sum <"$status")" || return 1
  status_sha256="${status_sha256%% *}"
  jq -cS --arg status_sha256 "$status_sha256" \
    '.traffic.status_sha256 = $status_sha256' "$barrier" \
    >"$barrier.tmp" || return 1
  mv -T -- "$barrier.tmp" "$barrier" || return 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted an unbound status inspection descriptor\n' >&2
    return 1
  fi
  mv -T -- "$status.valid" "$status" || return 1
  mv -T -- "$barrier.valid" "$barrier" || return 1

  jq '.pressure.content_sha256 = ("b" * 64) |
    .pressure.post_traffic_content_sha256 = ("b" * 64)' \
    "$observation" >"$invalid_observation"
  validate_path_observation_schema "$invalid_observation" || return 1
  if validate_path_observation_source_artifacts "$invalid_observation"; then
    printf 'pressure source validation accepted a stale derived content digest\n' >&2
    return 1
  fi

  command cp -- "$fill" "$fill.valid"
  jq '.touched = 1 | .verified_present_entries = 1' "$fill" >"$fill.tmp"
  mv -T -- "$fill.tmp" "$fill"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted a partial rather than exact full-map fill\n' >&2
    return 1
  fi
  mv -T -- "$fill.valid" "$fill"

  command cp -- "$verify" "$verify.valid"
  jq '.content_sha256 = ("b" * 64)' "$verify" >"$verify.tmp"
  mv -T -- "$verify.tmp" "$verify"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted changed post-traffic map content\n' >&2
    return 1
  fi
  mv -T -- "$verify.valid" "$verify"

  command cp -- "$sample_one" "$sample_one.valid"
  printf 'garbage\n' >"$sample_one"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted garbage recovery metrics\n' >&2
    return 1
  fi
  mv -T -- "$sample_one.valid" "$sample_one"

  command cp -- "$log" "$log.valid"
  {
    printf 'attempt=1 observed_at=2026-08-10T00:00:00Z entries=1 matched=false consecutive=0\n'
    printf 'attempt=2 observed_at=2026-08-10T00:00:01Z entries=0 matched=true consecutive=1\n'
  } >"$log"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted a log/sample occupancy mismatch\n' >&2
    return 1
  fi
  mv -T -- "$log.valid" "$log"

  command cp -- "$recovered" "$recovered.valid"
  write_pressure_map_metrics_fixture "$recovered" 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted a canonical/sample recovery mismatch\n' >&2
    return 1
  fi
  mv -T -- "$recovered.valid" "$recovered"

  command cp -- "$sample_two" \
    "$runner/map-pressure-pressure-recovered-sample-03.prom"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted the wrong canonical recovery sample count\n' >&2
    return 1
  fi
  rm -f -- "$runner/map-pressure-pressure-recovered-sample-03.prom"

  command cp -- "$baseline" "$baseline.valid"
  write_pressure_map_metrics_fixture "$baseline" 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted a nonempty pre-fill baseline\n' >&2
    return 1
  fi
  mv -T -- "$baseline.valid" "$baseline"
)

test_pressure_capacity_is_live_bounded_and_exactly_reconciled() (
  local capacity=0
  local root=""
  local observation=""
  local invalid_observation=""
  local runner=""
  local baseline=""
  local cleanup=""

  for capacity in 20000 50000; do
    root="$TEST_TMP_DIR/pressure-capacity-$capacity"
    observation="$root/path-observation.json"
    runner="$root/preflight/runner"
    mkdir -p -- "$root"
    write_path_observation_fixture "$observation" getsockopt-pressure "$capacity"
    validate_path_observation_schema "$observation" || {
      printf 'pressure schema rejected supported live capacity %s\n' "$capacity" >&2
      return 1
    }
    materialize_path_observation_sources "$observation"
    validate_pressure_cell_artifacts "$runner" || {
      printf 'pressure artifacts rejected supported live capacity %s\n' "$capacity" >&2
      return 1
    }
    validate_path_observation_source_artifacts "$observation" || {
      printf 'pressure source reconciliation rejected live capacity %s\n' "$capacity" >&2
      return 1
    }
  done

  root="$TEST_TMP_DIR/pressure-capacity-over-limit"
  observation="$root/path-observation.json"
  runner="$root/preflight/runner"
  mkdir -p -- "$root"
  write_path_observation_fixture "$observation" getsockopt-pressure 50001
  if validate_path_observation_schema "$observation"; then
    printf 'pressure schema accepted capacity above the supported ceiling\n' >&2
    return 1
  fi
  materialize_path_observation_sources "$observation"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure artifacts accepted capacity above the supported ceiling\n' >&2
    return 1
  fi

  root="$TEST_TMP_DIR/pressure-capacity-reconciliation"
  observation="$root/path-observation.json"
  invalid_observation="$root/path-observation.invalid.json"
  runner="$root/preflight/runner"
  baseline="$runner/phases/pressure-before/obi-metrics.prom"
  cleanup="$runner/map-pressure-pressure-cleanup.json"
  mkdir -p -- "$root"
  write_path_observation_fixture "$observation" getsockopt-pressure
  materialize_path_observation_sources "$observation"

  write_path_observation_fixture "$invalid_observation" getsockopt-pressure 20000
  validate_path_observation_schema "$invalid_observation" || {
    printf 'pressure schema hard-coded the default live capacity\n' >&2
    return 1
  }
  if validate_path_observation_source_artifacts "$invalid_observation"; then
    printf 'pressure source reconciliation accepted a different in-range capacity\n' >&2
    return 1
  fi

  command cp -- "$baseline" "$baseline.valid"
  write_pressure_map_metrics_fixture "$baseline" 0 20000
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure artifacts accepted a metric capacity mismatch\n' >&2
    return 1
  fi
  mv -T -- "$baseline.valid" "$baseline"

  command cp -- "$cleanup" "$cleanup.valid"
  jq '.max_entries = 9999 | .verified_absent_entries = 10000' \
    "$cleanup" >"$cleanup.tmp"
  mv -T -- "$cleanup.tmp" "$cleanup"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure artifacts accepted a cleanup capacity mismatch\n' >&2
    return 1
  fi
  mv -T -- "$cleanup.valid" "$cleanup"
)

test_pressure_contract_v2_raw_artifacts_are_exact_and_cross_bound() (
  local -r root="$TEST_TMP_DIR/pressure-contract-v2-raw"
  local -r observation="$root/path-observation.json"
  local -r runner="$root/preflight/runner"
  local -r result="$runner/scenario-pressure.json"
  local -r status="$runner/scenario-pressure-status.json"
  local -r barrier="$runner/map-pressure-pressure-barrier-status.json"
  local target=""
  local filter=""
  local index=0
  local label=""
  local accepted=false
  local canonical=""
  local -a mutations=(
    result 'result trace missing N' 'del(.pressure_correlation.request_count)'
    result 'result trace N mismatch' '.pressure_correlation.request_count = 127'
    barrier 'barrier schema v1' '.schema = "pressure-traffic-barrier-v1"'
    barrier 'barrier N mismatch' '.traffic.request_count = 127'
    barrier 'barrier H+R+W mismatch' '.traffic.exact_hit_count = 125'
    barrier 'barrier R=0' '.traffic.explicit_root_count = 0'
    barrier 'barrier W=0' '.traffic.w3c_parent_count = 0'
    barrier 'barrier V<H' '.traffic.retrieval_valid_count = 125'
    barrier 'barrier V>H+W' '.traffic.retrieval_valid_count = 128'
    barrier 'barrier F<R' '.traffic.attributable_failure_count = 0'
    barrier 'barrier F>R+W' '.traffic.attributable_failure_count = 3'
    barrier 'barrier V+F!=N' '.traffic.retrieval_valid_count = 126'
    barrier 'barrier M!=V-H' '.traffic.w3c_masked_valid_count = 0'
    barrier 'barrier M outside 0..1' '.traffic.w3c_masked_valid_count = 2'
    barrier 'barrier take_valid!=V' '.traffic.java_reconciliation_target.take_valid_count = 126'
    barrier 'barrier take_sampled!=V' '.traffic.java_reconciliation_target.take_sampled_count = 126'
    barrier 'barrier take_unsampled!=0' '.traffic.java_reconciliation_target.take_unsampled_count = 1'
    barrier 'barrier discard_standard!=M' '.traffic.java_reconciliation_target.discard_standard_count = 0'
    barrier 'barrier attributable_absence!=F' '.traffic.java_reconciliation_target.attributable_absence_count = 2'
    barrier 'barrier diagnostic_self_miss!=1' '.traffic.java_reconciliation_target.diagnostic_self_miss_count = 0'
    barrier 'barrier Java target extra key' '.traffic.java_reconciliation_target.extra = 0'
    status 'status trace missing N' 'del(.pressure_correlation.trace.request_count)'
    status 'status trace extra key' '.pressure_correlation.trace.extra = 0'
    status 'status bridge extra key' '.pressure_correlation.bridge.untrusted_extra = 0'
    status 'status bridge M mismatch' '.pressure_correlation.bridge.w3c_masked_valid_count = 0'
    status 'status Java target mismatch' '.pressure_correlation.java_reconciliation_target.take_sampled_count = 126'
  )

  restore_raw_fixture() {
    mv -T -- "$result.mutation-base" "$result"
    mv -T -- "$status.mutation-base" "$status"
    mv -T -- "$barrier.mutation-base" "$barrier"
  }

  raw_mutation_must_fail() {
    local -r mutation_target="$1"
    local -r mutation_filter="$2"
    local -r mutation_label="$3"
    local mutation_file=""
    local path_accepted=false

    command cp -- "$result" "$result.mutation-base" || return 1
    command cp -- "$status" "$status.mutation-base" || return 1
    command cp -- "$barrier" "$barrier.mutation-base" || return 1
    case "$mutation_target" in
      result) mutation_file="$result" ;;
      status) mutation_file="$status" ;;
      barrier) mutation_file="$barrier" ;;
      *) restore_raw_fixture; return 1 ;;
    esac
    jq -cS "$mutation_filter" "$mutation_file.mutation-base" \
      >"$mutation_file" || {
      restore_raw_fixture
      return 1
    }
    refresh_pressure_contract_barrier_digests "$runner" || {
      restore_raw_fixture
      return 1
    }
    accepted=false
    if validate_pressure_cell_artifacts "$runner"; then
      accepted=true
    fi
    if validate_path_observation_source_artifacts "$observation"; then
      path_accepted=true
    fi
    restore_raw_fixture || return 1
    if [[ "$accepted" == true || "$path_accepted" == true ]]; then
      printf 'pressure raw/path contract accepted %s\n' \
        "$mutation_label" >&2
      return 1
    fi
  }

  mkdir -p -- "$root"
  write_path_observation_fixture "$observation" getsockopt-pressure
  materialize_path_observation_sources "$observation"
  validate_pressure_cell_artifacts "$runner" || {
    printf 'valid pressure v2 raw fixture was rejected\n' >&2
    return 1
  }

  for ((index = 0; index < ${#mutations[@]}; index += 3)); do
    target="${mutations[index]}"
    label="${mutations[index + 1]}"
    filter="${mutations[index + 2]}"
    raw_mutation_must_fail "$target" "$filter" "$label" || return 1
  done

  # A valid alternative H/R/V/F split remains internally coherent, but a
  # result-only rewrite must not cross the status or barrier authority seams.
  raw_mutation_must_fail result '
    .pressure_correlation.exact_hit_count = 125 |
    .pressure_correlation.explicit_root_count = 2
  ' 'result/status trace cross-binding mismatch' || return 1

  command cp -- "$result" "$result.mutation-base"
  command cp -- "$status" "$status.mutation-base"
  command cp -- "$barrier" "$barrier.mutation-base"
  jq -cS '
    .pressure_correlation.exact_hit_count = 125 |
    .pressure_correlation.explicit_root_count = 2
  ' "$result.mutation-base" >"$result" || return 1
  jq -cS '
    .pressure_correlation.trace.exact_hit_count = 125 |
    .pressure_correlation.trace.explicit_root_count = 2 |
    .pressure_correlation.bridge.retrieval_valid_count = 126 |
    .pressure_correlation.bridge.attributable_failure_count = 2 |
    .pressure_correlation.java_reconciliation_target.take_valid_count = 126 |
    .pressure_correlation.java_reconciliation_target.take_sampled_count = 126 |
    .pressure_correlation.java_reconciliation_target.attributable_absence_count = 2
  ' "$status.mutation-base" >"$status" || return 1
  refresh_pressure_contract_barrier_digests "$runner" || return 1
  accepted=false
  if validate_pressure_cell_artifacts "$runner"; then accepted=true; fi
  restore_raw_fixture || return 1
  if [[ "$accepted" == true ]]; then
    printf 'pressure raw contract accepted a coherent status/result split not bound to the barrier\n' >&2
    return 1
  fi

  # Conversely, an internally coherent alternate barrier must not override
  # the independently retained result and status contract.
  raw_mutation_must_fail barrier '
    .traffic.exact_hit_count = 125 |
    .traffic.explicit_root_count = 2 |
    .traffic.retrieval_valid_count = 126 |
    .traffic.attributable_failure_count = 2 |
    .traffic.java_reconciliation_target.take_valid_count = 126 |
    .traffic.java_reconciliation_target.take_sampled_count = 126 |
    .traffic.java_reconciliation_target.attributable_absence_count = 2
  ' 'coherent barrier/status/result cross-binding mismatch' || return 1

  # The other permitted W3C branch (V=H, F=R+W, M=0) is accepted when all
  # independently retained authorities agree.
  command cp -- "$result" "$result.mutation-base"
  command cp -- "$status" "$status.mutation-base"
  command cp -- "$barrier" "$barrier.mutation-base"
  jq -cS '
    .pressure_correlation.bridge.retrieval_valid_count = 126 |
    .pressure_correlation.bridge.attributable_failure_count = 2 |
    .pressure_correlation.bridge.w3c_masked_valid_count = 0 |
    .pressure_correlation.java_reconciliation_target.take_valid_count = 126 |
    .pressure_correlation.java_reconciliation_target.take_sampled_count = 126 |
    .pressure_correlation.java_reconciliation_target.discard_standard_count = 0 |
    .pressure_correlation.java_reconciliation_target.attributable_absence_count = 2
  ' "$status.mutation-base" >"$status" || return 1
  refresh_pressure_contract_barrier_digests "$runner" || return 1
  jq -cS '
    .traffic.retrieval_valid_count = 126 |
    .traffic.attributable_failure_count = 2 |
    .traffic.w3c_masked_valid_count = 0 |
    .traffic.java_reconciliation_target.take_valid_count = 126 |
    .traffic.java_reconciliation_target.take_sampled_count = 126 |
    .traffic.java_reconciliation_target.discard_standard_count = 0 |
    .traffic.java_reconciliation_target.attributable_absence_count = 2
  ' "$barrier" >"$barrier.tmp" || return 1
  mv -T -- "$barrier.tmp" "$barrier"
  validate_pressure_cell_artifacts "$runner" canonical || {
    restore_raw_fixture
    printf 'pressure raw contract rejected the valid M=0 W3C branch\n' >&2
    return 1
  }
  jq -e '
    .retrieval_valid_count == 126 and .attributable_failure_count == 2 and
    .w3c_masked_valid_count == 0 and .take_sampled_count == 126 and
    .discard_standard_count == 0 and .attributable_absence_count == 2
  ' <<<"$canonical" >/dev/null || {
    restore_raw_fixture
    return 1
  }
  restore_raw_fixture || return 1

  # Admission overload is separately bounded pressure evidence. It may vary
  # without changing H/R/W, V/F/M, or the Java target.
  command cp -- "$result" "$result.mutation-base"
  command cp -- "$status" "$status.mutation-base"
  command cp -- "$barrier" "$barrier.mutation-base"
  jq -cS '
    .pressure_correlation.bridge.handoff_admission_outcome_counts.overload = 6
  ' "$status.mutation-base" >"$status" || return 1
  refresh_pressure_contract_barrier_digests "$runner" || return 1
  jq -cS '.traffic.handoff_admission_overload_count = 6' \
    "$barrier" >"$barrier.tmp" || return 1
  mv -T -- "$barrier.tmp" "$barrier"
  validate_pressure_cell_artifacts "$runner" canonical || {
    restore_raw_fixture
    printf 'pressure raw contract coupled admission overload to W3C attribution\n' >&2
    return 1
  }
  jq -e '
    .handoff_admission_overload_count == 6 and
    .retrieval_valid_count == 127 and .attributable_failure_count == 1 and
    .w3c_masked_valid_count == 1
  ' <<<"$canonical" >/dev/null || {
    restore_raw_fixture
    return 1
  }
  restore_raw_fixture
)

test_pressure_consumer_source_preserves_full_hash_contract_literals() {
  local -r source="$TEST_SCRIPT_DIR/benchmark.sh"

  # These are intentional literal jq fragments in the production source.
  # shellcheck disable=SC2016
  [[ "$(grep -Fc -- 'E2BIG proxy' "$source")" == 1 &&
    "$(grep -Fc -- 'non-evicting HASH' "$source")" == 1 &&
    "$(grep -Fc -- '.map_type == "Hash"' "$source")" -ge 2 &&
    "$(grep -Fc -- '.capacity_rejected_entries == 1' "$source")" -ge 3 &&
    "$(grep -Fc -- '.content_sha256 == $fill.content_sha256' "$source")" -ge 2 &&
    "$(grep -Fc -- '.post_traffic_content_sha256 == .content_sha256' "$source")" == 1 ]] || {
    printf 'pressure consumer source lost the literal full non-evicting HASH/E2BIG/digest contract\n' >&2
    return 1
  }
}

test_lookup_coverage_uses_observed_once_vocabulary() {
  local -r root="$TEST_TMP_DIR/lookup-coverage"
  local -r summary="$root/lookup-paths.json"
  local -r invalid="$root/lookup-paths-invalid.json"

  write_lookup_path_summary_fixture "$summary"
  validate_lookup_path_summary_schema "$summary" || {
    printf 'observed-once lookup coverage vocabulary was rejected\n' >&2
    return 1
  }
  command cp -- "$root/docker-daemon.json" "$root/docker-daemon.json.valid"
  printf '{}\n' >"$root/docker-daemon.json"
  if validate_lookup_path_summary_schema "$summary"; then
    printf 'lookup coverage accepted invalid local-daemon provenance\n' >&2
    return 1
  fi
  mv -T -- "$root/docker-daemon.json.valid" "$root/docker-daemon.json"
  command cp -- "$root/application-source-identity.json" \
    "$root/application-source-identity.json.valid"
  printf '{}\n' >"$root/application-source-identity.json"
  if validate_lookup_path_summary_schema "$summary"; then
    printf 'lookup coverage accepted invalid all-cell source provenance\n' >&2
    return 1
  fi
  mv -T -- "$root/application-source-identity.json.valid" \
    "$root/application-source-identity.json"
  jq '.coverage.getsockopt.stale_failure = "measured"' "$summary" >"$invalid"
  if validate_lookup_path_summary_schema "$invalid"; then
    printf 'lookup coverage accepted a benchmark-like label for one correctness run\n' >&2
    return 1
  fi
  jq '.paths[0].observation = {
    schema_version: 1, kind: "java-remote-parent-path-correctness-observation",
    cell: "getsockopt-hit", observation: {mode: "bounded_correctness_observed_once"}
  }' "$summary" >"$invalid"
  if validate_lookup_path_summary_schema "$invalid"; then
    printf 'lookup coverage accepted a partial embedded path stub\n' >&2
    return 1
  fi
  jq '.native_lookup_benchmark.benchmark = {
    schema_version: 1, kind: "native-jni-lookup-benchmark",
    status: "passed", series: [0,1,2,3,4,5]
  }' "$summary" >"$invalid"
  if validate_lookup_path_summary_schema "$invalid"; then
    printf 'lookup coverage accepted a partial embedded native stub\n' >&2
    return 1
  fi
  mv -- "$root/cells/getsockopt-hit/preflight/runner/environment.txt" \
    "$root/cells/getsockopt-hit/preflight/runner/environment.txt.missing"
  if validate_lookup_path_summary_schema "$summary"; then
    printf 'lookup coverage accepted a broken embedded artifact link\n' >&2
    return 1
  fi
  mv -- "$root/cells/getsockopt-hit/preflight/runner/environment.txt.missing" \
    "$root/cells/getsockopt-hit/preflight/runner/environment.txt"
  jq '.pressure_correlation.java_reconciliation_target.take_valid_count = 126' \
    "$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json" \
    >"$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json.invalid"
  mv -- "$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json" \
    "$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json.valid"
  mv -- "$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json.invalid" \
    "$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json"
  if validate_lookup_path_summary_schema "$summary"; then
    printf 'lookup coverage accepted an unreconciled 128-request pressure trace\n' >&2
    return 1
  fi
  mv -- "$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json.valid" \
    "$root/cells/getsockopt-pressure/preflight/runner/scenario-pressure-status.json"
}

write_application_runner_source_fixture() {
  local -r runner_directory="$1"
  local -r revision="$2"
  local -r marker_or_manifest="${3:-application-source-fixture}"
  local tree_sha256=""
  local tracked_patch_sha256=""
  local patch_identity_sha256=""

  mkdir -p -- "$runner_directory"
  if [[ -f "$marker_or_manifest" && ! -L "$marker_or_manifest" ]]; then
    command cp -- "$marker_or_manifest" "$runner_directory/source-tree.manifest"
  else
    printf '%s\n' "$marker_or_manifest" >"$runner_directory/source-tree.manifest"
  fi
  : >"$runner_directory/git-status.txt"
  tree_sha256="$(sha256sum -- "$runner_directory/source-tree.manifest")" || return 1
  tree_sha256="${tree_sha256%% *}"
  tracked_patch_sha256="$(printf '' | sha256sum)" || return 1
  tracked_patch_sha256="${tracked_patch_sha256%% *}"
  patch_identity_sha256="$({
    sha256sum -- "$runner_directory/git-status.txt"
    sha256sum -- "$runner_directory/source-tree.manifest"
    printf '%s\n' "$tracked_patch_sha256"
  } | sha256sum)" || return 1
  patch_identity_sha256="${patch_identity_sha256%% *}"
  {
    printf 'revision=%s\n' "$revision"
    printf 'dirty=false\n'
    printf 'source_tree_sha256=%s\n' "$tree_sha256"
    printf 'source_tree_manifest_schema=git-tree-v2\n'
    printf 'tracked_patch_sha256=%s\n' "$tracked_patch_sha256"
    printf 'patch_identity_sha256=%s\n' "$patch_identity_sha256"
  } >"$runner_directory/source-state.txt"
  command cp -- "$runner_directory/source-state.txt" "$runner_directory/environment.txt"
}

write_application_source_identity_artifact_fixture() {
  local -r root="$1"
  local -r mode="$2"
  local -r revision="$3"
  local -r repository="${4:-$REPO_ROOT}"
  local -r canonical_manifest="$root/.canonical-source-tree.manifest"
  local cell=""
  local runner_directory=""
  local canonical_identity=""
  local tree_sha256=""
  local tracked_patch_sha256=""
  local runner_patch_identity=""
  local native_source_state="null"
  local cells_json=""
  local git_tree=""
  local -a cells=("${CORE_CELLS[@]}")

  if [[ "$mode" == complete ]]; then
    cells+=("${BOUNDED_PATH_CELLS[@]}")
    native_source_state='"native-jni/source-state.json"'
  fi
  git_tree="$(git -C "$repository" rev-parse "$revision^{tree}")" || return 1
  write_git_tree_manifest_for_tree \
    "$repository" "$git_tree" "$canonical_manifest" || return 1
  for cell in "${cells[@]}"; do
    runner_directory="$root/cells/$cell/preflight/runner"
    write_application_runner_source_fixture \
      "$runner_directory" "$revision" "$canonical_manifest"
  done
  rm -f -- "$canonical_manifest" || return 1
  runner_directory="$root/cells/${cells[0]}/preflight/runner"
  canonical_identity="$(canonical_application_patch_identity "$runner_directory")" || return 1
  tree_sha256="$(runner_environment_value \
    "$runner_directory/source-state.txt" source_tree_sha256)" || return 1
  tracked_patch_sha256="$(runner_environment_value \
    "$runner_directory/source-state.txt" tracked_patch_sha256)" || return 1
  cells_json="$({
    for cell in "${cells[@]}"; do
      runner_patch_identity="$(runner_environment_value \
        "$root/cells/$cell/preflight/runner/source-state.txt" \
        patch_identity_sha256)" || return 1
      jq -cn --arg cell "$cell" --arg identity "$runner_patch_identity" '
        {
          cell: $cell,
          source_state: ("cells/" + $cell + "/preflight/runner/source-state.txt"),
          source_tree_manifest: ("cells/" + $cell + "/preflight/runner/source-tree.manifest"),
          git_status: ("cells/" + $cell + "/preflight/runner/git-status.txt"),
          runner_environment: ("cells/" + $cell + "/preflight/runner/environment.txt"),
          runner_patch_identity_sha256: $identity
        }
      '
    done
  } | jq -s .)" || return 1
  printf 'git_revision=%s\n' "$revision" >"$root/host-environment.txt"
  jq -n --arg mode "$mode" --arg revision "$revision" \
    --arg tree_sha256 "$tree_sha256" --arg tracked_patch "$tracked_patch_sha256" \
    --arg canonical "$canonical_identity" --arg git_tree "$git_tree" \
    --argjson cells "$cells_json" \
    --argjson native_source_state "$native_source_state" '
      {
        schema_version: 1,
        kind: "benchmark-application-source-identity",
        status: "clean_and_stable_across_all_requested_cells",
        cells_mode: $mode,
        revision: $revision,
        git_tree: $git_tree,
        source_tree_sha256: $tree_sha256,
        source_tree_manifest_schema: "git-tree-v2",
        tracked_patch_sha256: $tracked_patch,
        canonical_patch_identity_sha256: $canonical,
        host_environment: "host-environment.txt",
        native_source_state: $native_source_state,
        cells: $cells
      }
    ' >"$root/application-source-identity.json"
  validate_application_source_identity_schema \
    "$root/application-source-identity.json" "$repository" false
}

prepare_application_source_identity_fixture() {
  local -r repository="$1"
  local -r output="$2"
  local -r mode="$3"
  local revision=""
  local git_tree=""
  local canonical_manifest=""
  local cell=""
  local -a cells=("${CORE_CELLS[@]}")

  mkdir -p -- "$repository" "$output/cells"
  printf 'tracked application source\n' >"$repository/application.txt"
  git -C "$repository" init --quiet
  git -C "$repository" config user.email benchmark@example.invalid
  git -C "$repository" config user.name 'Benchmark Test'
  git -C "$repository" config commit.gpgsign false
  git -C "$repository" add -- application.txt
  git -C "$repository" commit --quiet -m fixture
  revision="$(git -C "$repository" rev-parse HEAD)" || return 1
  git_tree="$(git -C "$repository" rev-parse "$revision^{tree}")" || return 1
  canonical_manifest="$output/.canonical-source-tree.manifest"
  resolve_benchmark_identity_tools
  write_git_tree_manifest_for_tree \
    "$repository" "$git_tree" "$canonical_manifest" || return 1
  if [[ "$mode" == complete ]]; then
    cells+=("${BOUNDED_PATH_CELLS[@]}")
  fi
  for cell in "${cells[@]}"; do
    write_application_runner_source_fixture \
      "$output/cells/$cell/preflight/runner" "$revision" "$canonical_manifest"
  done
  rm -f -- "$canonical_manifest" || return 1
  printf 'git_revision=%s\n' "$revision" >"$output/host-environment.txt"
  if [[ "$mode" == complete ]]; then
    mkdir -p -- "$output/native-jni"
    write_native_source_state_fixture "$output/native-jni" "$revision"
  fi
  OUTPUT_DIR="$output"
  OUTPUT_READY=true
  CELLS_MODE="$mode"
  write_application_source_identity "$repository"
  validate_application_source_identity_schema \
    "$output/application-source-identity.json" "$repository"
}

test_application_source_identity_is_exact_across_core_and_complete_cells() (
  local -r core_repository="$TEST_TMP_DIR/application-source-core-repository"
  local -r core_output="$TEST_TMP_DIR/application-source-core-output"
  local -r complete_repository="$TEST_TMP_DIR/application-source-complete-repository"
  local -r complete_output="$TEST_TMP_DIR/application-source-complete-output"
  local -r alternate_revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local revision=""

  reset_options
  resolve_benchmark_identity_tools
  prepare_application_source_identity_fixture "$core_repository" "$core_output" core
  revision="$(jq -er '.revision' "$core_output/application-source-identity.json")" || return 1
  jq -e '
    .status == "clean_and_stable_across_all_requested_cells" and
    .cells_mode == "core" and (.cells | length) == 6 and
    ([.cells[].cell] == [
      "uninstrumented", "bridge-disabled", "getsockopt-hit", "unix-hit",
      "getsockopt-w3c", "getsockopt-helper-idle"
    ])
  ' "$core_output/application-source-identity.json" >/dev/null || return 1

  sed -i 's/^dirty=false$/dirty=true/' \
    "$core_output/cells/bridge-disabled/preflight/runner/source-state.txt"
  if validate_application_source_identity_schema \
    "$core_output/application-source-identity.json" "$core_repository"; then
    printf 'core source identity accepted a dirty bridge-disabled cell\n' >&2
    return 1
  fi
  write_application_runner_source_fixture \
    "$core_output/cells/bridge-disabled/preflight/runner" "$revision" \
    "$core_output/cells/uninstrumented/preflight/runner/source-tree.manifest"
  write_application_runner_source_fixture \
    "$core_output/cells/getsockopt-w3c/preflight/runner" "$alternate_revision" \
    "$core_output/cells/uninstrumented/preflight/runner/source-tree.manifest"
  if validate_application_source_identity_schema \
    "$core_output/application-source-identity.json" "$core_repository"; then
    printf 'core source identity accepted per-cell revision drift\n' >&2
    return 1
  fi
  write_application_runner_source_fixture \
    "$core_output/cells/getsockopt-w3c/preflight/runner" "$revision" tree-drift
  if validate_application_source_identity_schema \
    "$core_output/application-source-identity.json" "$core_repository"; then
    printf 'core source identity accepted per-cell tree drift\n' >&2
    return 1
  fi

  reset_options
  resolve_native_benchmark_tools
  prepare_application_source_identity_fixture \
    "$complete_repository" "$complete_output" complete
  revision="$(jq -er '.revision' \
    "$complete_output/application-source-identity.json")" || return 1
  jq -e '.cells_mode == "complete" and (.cells | length) == 10 and
    ([.cells[].cell][-4:] == [
      "getsockopt-stale", "unix-stale", "unix-timeout", "getsockopt-pressure"
    ])' "$complete_output/application-source-identity.json" >/dev/null || return 1
  sed -i 's/^patch_identity_sha256=.*/patch_identity_sha256=0000000000000000000000000000000000000000000000000000000000000000/' \
    "$complete_output/cells/getsockopt-pressure/preflight/runner/source-state.txt"
  if validate_application_source_identity_schema \
    "$complete_output/application-source-identity.json" "$complete_repository"; then
    printf 'complete source identity accepted bounded-cell patch drift\n' >&2
    return 1
  fi
  write_application_runner_source_fixture \
    "$complete_output/cells/getsockopt-pressure/preflight/runner" "$revision" \
    "$complete_output/cells/uninstrumented/preflight/runner/source-tree.manifest"
  printf 'live checkout mutation\n' >>"$complete_repository/application.txt"
  if validate_application_source_identity_schema \
    "$complete_output/application-source-identity.json" "$complete_repository"; then
    printf 'complete source identity accepted live checkout mutation\n' >&2
    return 1
  fi
)

test_application_source_identity_rejects_coordinated_manifest_forgery() (
  local -r repository="$TEST_TMP_DIR/application-source-forgery-repository"
  local -r output="$TEST_TMP_DIR/application-source-forgery-output"
  local -r artifact="$output/application-source-identity.json"
  local revision=""
  local cell=""
  local runner_directory=""
  local tree_sha256=""
  local canonical_identity=""
  local runner_identity=""
  local identities_json=""
  local -a identities=()

  reset_options
  resolve_benchmark_identity_tools
  prepare_application_source_identity_fixture "$repository" "$output" core
  revision="$(jq -er '.revision' "$artifact")" || return 1
  for cell in "${CORE_CELLS[@]}"; do
    runner_directory="$output/cells/$cell/preflight/runner"
    write_application_runner_source_fixture \
      "$runner_directory" "$revision" coordinated-forged-manifest
    runner_identity="$(runner_environment_value \
      "$runner_directory/source-state.txt" patch_identity_sha256)" || return 1
    identities+=("$(jq -cn --arg cell "$cell" --arg identity "$runner_identity" \
      '{cell: $cell, identity: $identity}')") || return 1
  done
  runner_directory="$output/cells/${CORE_CELLS[0]}/preflight/runner"
  tree_sha256="$(runner_environment_value \
    "$runner_directory/source-state.txt" source_tree_sha256)" || return 1
  canonical_identity="$(canonical_application_patch_identity "$runner_directory")" || return 1
  identities_json="$(printf '%s\n' "${identities[@]}" | jq -s .)" || return 1
  jq --arg tree_sha256 "$tree_sha256" --arg canonical "$canonical_identity" \
    --argjson identities "$identities_json" '
      .source_tree_sha256 = $tree_sha256 |
      .canonical_patch_identity_sha256 = $canonical |
      .cells |= map(. as $cell |
        .runner_patch_identity_sha256 =
          ($identities[] | select(.cell == $cell.cell) | .identity))
    ' "$artifact" >"$artifact.tmp"
  mv -T -- "$artifact.tmp" "$artifact"
  if validate_application_source_identity_schema "$artifact" "$repository"; then
    printf 'application source identity accepted a coordinated manifest forgery unrelated to its recorded Git tree\n' >&2
    return 1
  fi
)

write_native_jni_fixture() {
  local -r output="$1"

  {
    printf '%s\n' 'benchmark=obi_java_remote_parent_native getsockopt_backend=deterministic_syscall_shim'
    printf '%s\n' 'transport=getsockopt outcome=hit warmup_iterations=1000 iterations=10000 elapsed_ns=100000 ns_per_op=10.00 p50_ns=10 p95_ns=20 p99_ns=30 ops_per_second=100000000.00 status=1 checksum=10000'
    printf '%s\n' 'transport=getsockopt outcome=miss warmup_iterations=1000 iterations=10000 elapsed_ns=110000 ns_per_op=11.00 p50_ns=11 p95_ns=21 p99_ns=31 ops_per_second=90909090.91 status=2 checksum=20000'
    printf '%s\n' 'transport=getsockopt outcome=failure warmup_iterations=1000 iterations=10000 elapsed_ns=120000 ns_per_op=12.00 p50_ns=12 p95_ns=22 p99_ns=32 ops_per_second=83333333.33 status=12 checksum=120000'
    printf '%s\n' 'transport=unix outcome=hit warmup_iterations=1000 iterations=10000 elapsed_ns=200000 ns_per_op=20.00 p50_ns=20 p95_ns=30 p99_ns=40 ops_per_second=50000000.00 status=1 checksum=10000'
    printf '%s\n' 'transport=unix outcome=miss warmup_iterations=1000 iterations=10000 elapsed_ns=210000 ns_per_op=21.00 p50_ns=21 p95_ns=31 p99_ns=41 ops_per_second=47619047.62 status=2 checksum=20000'
    printf '%s\n' 'transport=unix outcome=failure warmup_iterations=1000 iterations=10000 elapsed_ns=220000 ns_per_op=22.00 p50_ns=22 p95_ns=32 p99_ns=42 ops_per_second=45454545.45 status=12 checksum=120000'
  } >"$output"
}

write_compiler_provenance_fixture() {
  local -r output="$1"
  local compiler=""
  local compiler_sha256=""

  compiler="$(readlink -f -- "$(type -P cc)")" || return 1
  compiler_sha256="$(sha256sum -- "$compiler")" || return 1
  compiler_sha256="${compiler_sha256%% *}"
  jq -n --arg compiler "$compiler" --arg compiler_sha256 "$compiler_sha256" '
    {
      canonical_path: $compiler,
      executable_sha256: $compiler_sha256,
      selection: "make_default",
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
      compile_flags: [
        "-fPIC", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter",
        "-pthread", "-DOBI_JNI_TESTING"
      ],
      link_flags: ["-pthread"],
      build_command: "build-command.txt",
      expanded_build_command: "expanded-build-command.txt"
    }
  ' >"$output"
}

write_native_source_state_fixture() {
  local -r directory="$1"
  local -r revision="$2"
  local paths_json=""
  local identity=""
  local path=""
  local -a entries=()

  for path in "${NATIVE_BENCHMARK_SOURCE_PATHS[@]}"; do
    entries+=("$(jq -cn --arg path "$path" '
      {path: $path, mode: "100644",
       head_blob: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
       index_blob: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
       working_blob: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
       working_sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
    ')") || return 1
  done
  paths_json="$(printf '%s\n' "${entries[@]}" | jq -s .)" || return 1
  identity="$(jq -cnS --arg revision "$revision" --argjson paths "$paths_json" \
    '{revision: $revision, paths: $paths}' | sha256sum)" || return 1
  identity="${identity%% *}"
  jq -n --arg revision "$revision" --arg identity "$identity" \
    --argjson paths "$paths_json" '
      {schema_version: 1, kind: "native-jni-source-snapshot", status: "clean",
       revision: $revision, paths: $paths, content_identity: $identity}
    ' >"$directory/source-state-before.json"
  cp -- "$directory/source-state-before.json" "$directory/source-state-after.json"
  finalize_native_source_state \
    "$directory/source-state-before.json" "$directory/source-state-after.json" \
    "$directory/source-state.json"
  validate_native_source_state_schema "$directory/source-state.json"
}

write_normalized_native_jni_artifact_fixture() {
  local -r output="$1"
  local -r source_revision="${2:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
  local -r fixture_directory="${output%/*}"
  local -r raw="$fixture_directory/raw.txt"
  local -r compiler_provenance="$fixture_directory/compiler-provenance.json"
  local -r header_image="maven:test@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  local binary_sha256=""
  local compiler=""

  mkdir -p -- "$fixture_directory/build" "${fixture_directory%/*}"
  write_native_jni_fixture "$raw"
  printf 'native fixture binary\n' >"$fixture_directory/build/remote_parent_jni_benchmark"
  chmod 0700 -- "$fixture_directory/build/remote_parent_jni_benchmark"
  binary_sha256="$(sha256sum -- \
    "$fixture_directory/build/remote_parent_jni_benchmark")" || return 1
  binary_sha256="${binary_sha256%% *}"
  printf 'host fixture\n' >"${fixture_directory%/*}/host-environment.txt"
  : >"$fixture_directory/raw.stderr.log"
  printf 'fixture compiler version\n' >"$fixture_directory/compiler-version.txt"
  resolve_native_benchmark_tools || return 1
  write_native_make_build_command "$fixture_directory/build-command.txt" 15 \
    --silent --directory /tmp/native-source --file Makefile.jni benchmark \
    CC=/usr/bin/cc BUILD_DIR=/tmp/native-build JAVA_HOME=/tmp/native-jdk \
    BENCHMARK_ITERATIONS=10000 || return 1
  compiler="$(readlink -f -- "$(type -P cc)")" || return 1
  {
    printf '%s' "$compiler"
    printf ' %s' "${NATIVE_BENCHMARK_COMPILE_FLAGS[@]}"
    printf ' %s' -I/tmp/native-jdk/include -I/tmp/native-jdk/include/linux \
      src/main/c/io_opentelemetry_obi_java_jni.c \
      src/test/c/remote_parent_jni_benchmark.c
    printf ' %s' "${NATIVE_BENCHMARK_LINK_FLAGS[@]}"
    printf ' -o /tmp/remote_parent_jni_benchmark\n'
  } >"$fixture_directory/expanded-build-command.txt"
  printf '/tmp/remote_parent_jni_benchmark 10000\n' \
    >>"$fixture_directory/expanded-build-command.txt"
  printf 'fixture java version\n' >"$fixture_directory/java-version.txt"
  jq -n '{}' >"$fixture_directory/jdk-image.json"
  write_native_source_state_fixture "$fixture_directory" "$source_revision"
  write_compiler_provenance_fixture "$compiler_provenance"
  normalize_native_jni_benchmark \
    "$raw" "$binary_sha256" "$source_revision" "$header_image" \
    "$compiler_provenance" "$fixture_directory/source-state.json" "$output"
  validate_native_jni_benchmark_schema "$output"
}

materialize_path_observation_sources() {
  local -r observation="$1"
  local -r cell_directory="${observation%/*}"
  local cell=""
  local scenario=""
  local label=""
  local requests=0
  local result_file=""
  local status_file=""
  local diagnostics_file=""
  local status=""
  local value=0
  local pressure_max_entries=0
  local -r pressure_project="obi-test-pressure"
  local -a statuses=(
    unknown valid missing stale unsupported malformed version_mismatch ambiguous
    unauthorized already_consumed timeout overload transport_error disabled
  )

  cell="$(jq -er '.cell' "$observation")" || return 1
  case "$cell" in
    getsockopt-hit|unix-hit) scenario=concurrency; label=concurrency; requests=16 ;;
    getsockopt-stale) scenario=primary-w3c-stale; label=primary-w3c-stale; requests=1 ;;
    unix-stale) scenario=unix-w3c-stale; label=unix-w3c-stale; requests=1 ;;
    unix-timeout) scenario='w3c-fault'; label='w3c-fault-timeout'; requests=1 ;;
    getsockopt-pressure) scenario=pressure; label=pressure; requests=128 ;;
    *) return 1 ;;
  esac
  result_file="$cell_directory/preflight/runner/scenario-$label.json"
  status_file="$cell_directory/preflight/runner/scenario-$label-status.json"
  diagnostics_file="$cell_directory/preflight/runner/phases/$label-after/java-diagnostics.delta"
  mkdir -p -- "${diagnostics_file%/*}"
  jq -n --arg scenario "$scenario" --argjson requests "$requests" '
    {status: "passed", scenario: $scenario, request_count: $requests,
     traffic_elapsed_nanos: 1000, throughput_per_second: 1,
     latency: {p50_nanos: 1, p95_nanos: 2, p99_nanos: 3},
     cases: [range(0; $requests) |
       {latency_nanos: 1, request: {}, response: {}, trace: {}}]}
  ' >"$result_file"
  if [[ "$cell" == "getsockopt-pressure" ]]; then
    pressure_max_entries="$(jq -er '.pressure.max_entries' "$observation")" || return 1
    [[ "$pressure_max_entries" =~ ^[1-9][0-9]*$ ]] || return 1
    jq -n '
      {status: "passed", scenario: "pressure", exit_status: 0, metric_status: 0,
       result: "scenario-pressure.json"}
    ' >"$status_file"
    write_pressure_contract_artifacts_fixture \
      "$cell_directory/preflight/runner" "$pressure_max_entries" \
      "$pressure_project" "$TLS_PROTOCOL" "$SEED"
  else
    jq -n --arg scenario "$scenario" --arg result "scenario-$label.json" '
      {status: "passed", scenario: $scenario, exit_status: 0,
       metric_status: 0, result: $result}
    ' >"$status_file"
  fi
  for status in "${statuses[@]}"; do
    value="$(jq -er --arg status "$status" \
      '.java_diagnostic_status_deltas[$status]' "$observation")" || return 1
    printf 't_%s before=0 after=%s delta=%s\n' "$status" "$value" "$value"
  done >"$diagnostics_file"
  jq -n '{}' >"$cell_directory/preflight/runner/provenance.json"
  if [[ ! -e "$cell_directory/preflight/runner/source-state.txt" &&
    ! -L "$cell_directory/preflight/runner/source-state.txt" &&
    ! -e "$cell_directory/preflight/runner/environment.txt" &&
    ! -L "$cell_directory/preflight/runner/environment.txt" ]]; then
    write_application_runner_source_fixture \
      "$cell_directory/preflight/runner" bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  else
    [[ -f "$cell_directory/preflight/runner/source-state.txt" &&
      ! -L "$cell_directory/preflight/runner/source-state.txt" &&
      -f "$cell_directory/preflight/runner/environment.txt" &&
      ! -L "$cell_directory/preflight/runner/environment.txt" ]] || return 1
  fi
  if [[ "$cell" == getsockopt-pressure ]]; then
    {
      printf 'compose_project=%s\n' "$pressure_project"
      printf 'tls_protocol=%s\n' "$TLS_PROTOCOL"
      printf 'scenario_seed=%s\n' "$SEED"
    } >>"$cell_directory/preflight/runner/environment.txt"
  fi
}

write_lookup_path_summary_fixture() {
  local -r output="$1"
  local -r root="${output%/*}"
  local cell=""
  local paths_json=""
  local revision=""

  mkdir -p -- "$root"
  revision="$(git -C "$REPO_ROOT" rev-parse HEAD)" || return 1
  if [[ ! -f "$root/native-jni/benchmark.json" ]]; then
    write_normalized_native_jni_artifact_fixture \
      "$root/native-jni/benchmark.json" "$revision"
  fi
  write_application_source_identity_artifact_fixture \
    "$root" complete "$revision" "$REPO_ROOT"
  paths_json="$({
    for cell in "${PATH_OBSERVATION_CELLS[@]}"; do
      mkdir -p -- "$root/cells/$cell"
      write_path_observation_fixture "$root/cells/$cell/path-observation.json" "$cell"
      materialize_path_observation_sources "$root/cells/$cell/path-observation.json"
      jq -cn --arg source_artifact "cells/$cell/path-observation.json" \
        --arg link_base "cells/$cell/" \
        --slurpfile observation "$root/cells/$cell/path-observation.json" '
          {source_artifact: $source_artifact, link_base: $link_base,
           observation: $observation[0]}
      '
    done
  } | jq -s .)" || return 1
  jq -n '
    {
      schema_version: 2,
      kind: "docker-endpoint-evidence",
      status: "verified_local_unix_socket_endpoint_only",
      active_context: "default",
      active_endpoint: "unix:///var/run/docker.sock",
      endpoint_transport: "unix",
      socket_path: "/var/run/docker.sock",
      socket_device: 1,
      socket_inode: 1,
      socket_evidence: "existing_non_symlink_unix_socket",
      daemon_process_locality: "not_established_by_unix_socket_endpoint",
      container_process_binding: "required_separately_for_each_process_sample",
      docker_host_environment: "unset",
      docker_context_environment: "unset",
      verified_before_container_execution: true
    }
  ' >"$root/docker-daemon.json"
  jq -n --argjson paths "$paths_json" \
    --slurpfile native "$root/native-jni/benchmark.json" '
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
      native_lookup_benchmark: {
        source_artifact: "native-jni/benchmark.json",
        link_base: "native-jni/",
        benchmark: $native[0]
      },
      paths: $paths,
      coverage: {
        getsockopt: {
          hit: "correctness_observed_once", miss: "blocked",
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
        {dimension: "application_state_map_miss", status: "blocked", reason: "fixture absent"},
        {dimension: "in_jvm_java_to_native_transition_latency_percentiles", status: "blocked", reason: "diagnostic absent"}
      ]
    }
  ' >"$output"
  validate_lookup_path_summary_schema "$output"
}

test_native_jni_benchmark_normalization_is_strict() {
  local -r native_directory="$TEST_TMP_DIR/native-normalization/native-jni"
  local -r fixture="$native_directory/raw.txt"
  local -r invalid_fixture="$native_directory/native-jni-invalid.txt"
  local -r artifact="$native_directory/benchmark.json"
  local -r invalid_artifact="$native_directory/native-jni-benchmark-invalid.json"
  local -r compiler_provenance="$native_directory/compiler-provenance.json"
  local -r source_revision="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  local -r header_image="maven:test@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  local binary_sha256=""
  local compiler=""

  write_normalized_native_jni_artifact_fixture "$artifact" || {
    printf 'valid native JNI benchmark fixture was rejected\n' >&2
    return 1
  }
  binary_sha256="$(jq -er '.provenance.binary_sha256' "$artifact")" || return 1
  compiler="$(readlink -f -- "$(type -P cc)")" || return 1
  jq -e --arg compiler "$compiler" '
    [.series[] | [.transport, .outcome, .latency_p50_nanos,
      .latency_p95_nanos, .latency_p99_nanos]] == [
      ["getsockopt", "hit", 10, 20, 30],
      ["getsockopt", "miss", 11, 21, 31],
      ["getsockopt", "failure", 12, 22, 32],
      ["unix", "hit", 20, 30, 40],
      ["unix", "miss", 21, 31, 41],
      ["unix", "failure", 22, 32, 42]
    ] and
    .provenance.compiler.canonical_path == $compiler and
    .provenance.compiler.pinned_for_make == true and
    .provenance.compiler.compile_flags == [
      "-fPIC", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter",
      "-pthread", "-DOBI_JNI_TESTING"
    ] and
    .provenance.compiler.link_flags == ["-pthread"]
  ' "$artifact" >/dev/null || {
    printf 'native JNI benchmark lost ordered hit/miss/failure percentiles\n' >&2
    return 1
  }

  sed 's/outcome=miss warmup_iterations=1000 iterations=10000 elapsed_ns=110000/outcome=hit warmup_iterations=1000 iterations=10000 elapsed_ns=110000/' \
    "$fixture" >"$invalid_fixture"
  if normalize_native_jni_benchmark \
    "$invalid_fixture" "$binary_sha256" "$source_revision" "$header_image" \
    "$compiler_provenance" "$native_directory/source-state.json" \
    "$invalid_artifact"; then
    printf 'native JNI normalization accepted an out-of-contract series\n' >&2
    return 1
  fi

  jq '.series[0].latency_p95_nanos = 5' "$artifact" >"$invalid_artifact"
  if validate_native_jni_benchmark_schema "$invalid_artifact"; then
    printf 'native JNI schema accepted non-monotonic percentiles\n' >&2
    return 1
  fi

  jq '.provenance.compiler.canonical_path = "cc"' "$artifact" >"$invalid_artifact"
  if validate_native_jni_benchmark_schema "$invalid_artifact"; then
    printf 'native JNI schema accepted a non-canonical compiler path\n' >&2
    return 1
  fi
}

test_complete_manifest_links_bounded_artifacts_and_scopes() {
  # shellcheck disable=SC2034 # Consumed dynamically by the sourced harness.
  local OUTPUT_DIR=""
  local CELLS_MODE=""
  local STARTED_AT=""
  local HARNESS_INVOCATION=""
  local compact=""
  local mutated_json=""
  local -r duplicate_manifest="$TEST_TMP_DIR/manifest-duplicate.json"
  local -r oversized_manifest="$TEST_TMP_DIR/manifest-oversized.json"

  reset_options
  set_valid_process_tree_caps
  OUTPUT_DIR="$TEST_TMP_DIR/complete-manifest"
  CELLS_MODE=complete
  # shellcheck disable=SC2034 # Consumed dynamically by write_manifest.
  STARTED_AT=2026-08-10T00:00:00Z
  # shellcheck disable=SC2034 # Consumed dynamically by write_manifest.
  HARNESS_INVOCATION='benchmark.sh --cells complete --process-tree-fd-absolute-max 4096 --process-tree-task-absolute-max 2048 --process-tree-rss-bytes-absolute-max 1073741824 --process-tree-fd-recovery-delta-max 0 --process-tree-task-recovery-delta-max 0 --process-tree-rss-bytes-recovery-delta-max 0'
  mkdir -- "$OUTPUT_DIR"
  write_manifest
  validate_manifest_schema "$OUTPUT_DIR/manifest.in-progress.json" || return 1
  compact="$(jq -c . "$OUTPUT_DIR/manifest.in-progress.json")" || return 1
  mutated_json="${compact/\"schema_version\":4/\"schema_version\":4,\"schema_version\":4}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$duplicate_manifest"
  if validate_manifest_schema "$duplicate_manifest"; then
    printf 'manifest validator accepted a duplicate top-level key\n' >&2
    return 1
  fi
  mutated_json="${compact/\"correctness_preflight\":{\"postload_sentinel\":true/\"correctness_preflight\":{\"postload_sentinel\":true,\"postload_sentinel\":true}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$duplicate_manifest"
  if validate_manifest_schema "$duplicate_manifest"; then
    printf 'manifest validator accepted a duplicate nested key\n' >&2
    return 1
  fi
  head -c "$((MAX_MANIFEST_BYTES + 1))" /dev/zero | tr '\0' x \
    >"$oversized_manifest"
  if validate_manifest_schema "$oversized_manifest"; then
    printf 'manifest validator accepted an artifact above its byte cap\n' >&2
    return 1
  fi
  rm -f -- "$duplicate_manifest" "$oversized_manifest"
  jq -e '
    .schema_version == 4 and .cells_mode == "complete" and
    (.invocation | contains("--process-tree-fd-absolute-max 4096") and
      contains("--process-tree-task-absolute-max 2048") and
      contains("--process-tree-rss-bytes-absolute-max 1073741824") and
      contains("--process-tree-fd-recovery-delta-max 0") and
      contains("--process-tree-task-recovery-delta-max 0") and
      contains("--process-tree-rss-bytes-recovery-delta-max 0")) and
    .bounded_path_observations.requested == true and
    .bounded_path_observations.cells == [
      "getsockopt-stale", "unix-stale", "unix-timeout", "getsockopt-pressure"
    ] and
    .bounded_path_observations.native_jni_lookup == {
      status: "requested", iterations_per_series: 10000,
      artifact: "native-jni/benchmark.json"
    } and
    .bounded_path_observations.normalized_summary == "lookup-paths.json" and
    .bounded_path_observations.application_state_map_miss.status == "blocked" and
    .unavailable_dimensions.jni_lookup_latency_percentiles == "native_fixture_requested" and
    .unavailable_dimensions.application_cpu_rss_fd_threads ==
      "cgroup_v2_process_tree_cpu_rss_fd_task_gates_requested" and
    .unavailable_dimensions.primary_cgroupsockopt_program_cpu == "not_collected" and
    .unavailable_dimensions.java_native_memory ==
      "nmt_summary_indicator_requested_not_evaluated_as_acceptance_gate" and
    .unavailable_dimensions.java_direct_memory ==
      "direct_buffer_pool_indicator_requested_not_evaluated_as_acceptance_gate" and
    .process_tree_resource_evidence == {
      artifacts: "cells/*/{resources-before,cpu-measurement-baseline,measurements/rep-*-midpoint,cpu-measurement-end,resources-after-load,resources-idle-recovery-01,resources-idle-recovery-02}/*-cgroup-v2.json",
      services: ["obi", "java-backend"],
      scope: "complete_leaf_cgroup_v2_process_tree",
      sampling: "stable_two_pass_roster_and_conservative_resource_envelope",
      recovery_schedule: "cells/*/recovery-schedule.json"
    } and
    .dedicated_application_cpu_evidence == {
      artifacts: "cells/*/cpu-measurement-{baseline,end}/*-cgroup-v2.json",
      baseline_cell: "bridge-disabled",
      comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
      dimensions: ["obi", "java_backend", "combined"],
      metric: "cgroup_v2_cpu_stat_usage_usec_per_successful_request",
      maximum_regression_percent: 10,
      arithmetic: "exact_unsigned_decimal_cross_multiplication",
      primary_cgroupsockopt_program_cpu: "not_collected"
    } and
    .predeclared_poc_gates.repetitions.required == 5 and
    .predeclared_poc_gates.repetitions.population_variability == {
      formula: "sqrt(sum((x-mean)^2)/N)/mean*100",
      divisor: "population_N",
      metrics: ["throughput_per_second", "p99_latency_nanos"],
      required_cells: [
        "uninstrumented", "bridge-disabled", "getsockopt-hit", "unix-hit",
        "getsockopt-w3c", "getsockopt-helper-idle"
      ],
      maximum_cv_percent: 10
    } and
    .predeclared_poc_gates.steady_state_application == {
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
      population_cv_max_percent: 10
    } and
    .predeclared_poc_gates.sampled_jfr_allocation == {
      baseline_cell: "bridge-disabled",
      comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
      metric: "sampled_allocation_weight_bytes_per_successful_request",
      regression_allowance:
        "max(baseline_bytes_per_successful_request*percent/100,minimum_bytes_per_successful_request)",
      maximum_regression_percent: 10,
      minimum_allowance_bytes_per_successful_request: 1024,
      classification: "exploratory_sampled_indicator_not_exact_allocation",
      exact_allocation: false,
      acceptance_evidence: false
    } and
    .java_runtime_indicator_evidence.sampled_allocation_gate == {
      artifact: "poc-gates.json",
      baseline_cell: "bridge-disabled",
      comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
      metric: "sampled_allocation_weight_bytes_per_successful_request",
      maximum_regression_percent: 10,
      minimum_allowance_bytes_per_successful_request: 1024,
      classification: "exploratory_sampled_indicator_not_exact_allocation",
      acceptance_evidence: false
    } and
    .predeclared_poc_gates.bounded_growth.unavailable_samples_fail_closed == true and
    .predeclared_poc_gates.bounded_growth.process_tree == {
      services: ["obi", "java-backend"],
      absolute_caps: {fd_count: 4096, task_count: 2048, rss_bytes: 1073741824},
      recovery_delta_caps: {fd_count: 0, task_count: 0, rss_bytes: 0},
      boundaries: [
        "before", "cpu_measurement_baseline", "rep_01_midpoint",
        "rep_02_midpoint", "rep_03_midpoint", "rep_04_midpoint",
        "rep_05_midpoint", "cpu_measurement_end", "after_load",
        "idle_recovery_01", "idle_recovery_02"
      ],
      recovery: {interval_seconds: 30, required_consecutive_samples: 2},
      unavailable_samples_fail_closed: true
    } and
    .predeclared_poc_gates.bounded_growth.cpu_per_successful_request == {
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
    } and
    .predeclared_poc_gates.bounded_growth.java_bridge_map_evaluation == {
      status: "evaluated_when_exact_ownership_receipts_are_complete",
      metric_scope: "exact_obi_process_open_bpf_map_ids",
      ownership_attribution: true,
      required_ownership_samples: true,
      bridge_disabled_project_map_configured_max_entries: 1,
      completion_requirement:
        "stable_exact_obi_process_bpf_fd_rosters_bracketing_each_metrics_scrape"
    } and
    .predeclared_poc_gates.issue_acceptance_complete == false and
    .unavailable_dimensions.jfr_nmt_allocation_native_direct_memory ==
      "bounded_indicators_requested" and
    .unavailable_dimensions.bpf_lock_contention == "not_collected" and
    .unavailable_dimensions.bpf_map_evictions ==
      "not_applicable_non_evicting_hash_pressure"
  ' "$OUTPUT_DIR/manifest.in-progress.json" >/dev/null
}

write_valid_benchmark_result() {
  local -r output="$1"
  local -r duration_seconds="$2"
  local -r successful_requests="${3:-1}"
  local -r failed_requests="${4:-0}"
  local -r traffic_elapsed_nanos="${5:-$((duration_seconds * 1000000000))}"
  local throughput_per_second="${6:-}"
  local -r p50_nanos="${7:-1}"
  local -r p95_nanos="${8:-$p50_nanos}"
  local -r p99_nanos="${9:-$p50_nanos}"

  [[ "$p50_nanos" == "$p95_nanos" && "$p50_nanos" == "$p99_nanos" ]] || return 1
  if [[ -z "$throughput_per_second" ]]; then
    throughput_per_second="$(jq -cn \
      --argjson successful_requests "$successful_requests" \
      --argjson traffic_elapsed_nanos "$traffic_elapsed_nanos" \
      '$successful_requests * 1000000000 / $traffic_elapsed_nanos')" || return 1
  fi

  jq -n \
    --arg base_url "$CELL_WORKLOAD_BASE_URL" \
    --arg path "$CELL_WORKLOAD_PATH" \
    --arg connection_mode "$CELL_WORKLOAD_CONNECTION_MODE" \
    --arg tls_verification "$CELL_EXPECTED_TLS_VERIFICATION" \
    --argjson duration_nanos "$((duration_seconds * 1000000000))" \
    --argjson timeout_nanos "$((REQUEST_TIMEOUT_SECONDS * 1000000000))" \
    --argjson concurrency "$CONCURRENCY" \
    --argjson request_limit "$REQUEST_LIMIT" \
    --argjson seed "$SUSTAINED_LOAD_SEED" \
    --argjson w3c "$CELL_SUSTAINED_W3C" \
    --argjson successful_requests "$successful_requests" \
    --argjson failed_requests "$failed_requests" \
    --argjson traffic_elapsed_nanos "$traffic_elapsed_nanos" \
    --argjson throughput_per_second "$throughput_per_second" \
    --argjson p50_nanos "$p50_nanos" \
    --argjson p95_nanos "$p95_nanos" \
    --argjson p99_nanos "$p99_nanos" '
      {
        status: "passed", base_url: $base_url, path: $path,
        started_at: "2026-08-20T00:00:00.000000001Z",
        finished_at: "2026-08-20T00:00:02.000000001Z",
        connection_mode: $connection_mode, tls_verification: $tls_verification,
        w3c: $w3c, seed: $seed,
        requested_duration_nanos: $duration_nanos,
        request_timeout_nanos: $timeout_nanos, concurrency: $concurrency,
        request_limit: $request_limit, request_limit_reached: false,
        canceled: false, successful_requests: $successful_requests, failed_requests: $failed_requests,
        traffic_elapsed_nanos: $traffic_elapsed_nanos, throughput_per_second: $throughput_per_second,
        latency: {
          p50_nanos: $p50_nanos,
          p95_nanos: $p95_nanos,
          p99_nanos: $p99_nanos,
          histogram_encoding: "sorted_rle_nanos_v1",
          histogram: [{nanos: $p50_nanos, count: $successful_requests}]
        }
      }
    ' >"$output"
}

write_variance_fixture_cell() {
  local -r cell="$1"
  local -r successful_requests="${2:-$DURATION_SECONDS}"
  local -r failed_requests="${3:-0}"
  local -r traffic_elapsed_nanos="${4:-$((DURATION_SECONDS * 1000000000))}"
  local -r throughput_per_second="${5:-1}"
  local -r p50_nanos="${6:-1}"
  local -r p95_nanos="${7:-1}"
  local -r p99_nanos="${8:-1}"
  local -r cell_dir="$OUTPUT_DIR/cells/$cell"
  local repetition=0
  local repetition_label=""

  cell_spec "$cell" || return 1
  mkdir -p -- "$cell_dir/measurements" "$cell_dir/preflight"
  jq -n --arg cell "$cell" '
    {status: "passed", cell: $cell, reason: null,
     completed_at: "2026-08-10T00:00:00Z"}
  ' >"$cell_dir/status.json"
  jq -n --arg cell "$cell" '{cell: $cell}' >"$cell_dir/preflight/contract.json"
  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    printf -v repetition_label 'rep-%02d' "$repetition"
    write_valid_benchmark_result \
      "$cell_dir/measurements/$repetition_label.json" \
      "$DURATION_SECONDS" \
      "$successful_requests" \
      "$failed_requests" \
      "$traffic_elapsed_nanos" \
      "$throughput_per_second" \
      "$p50_nanos" \
      "$p95_nanos" \
      "$p99_nanos"
  done
}

write_sampled_allocation_fixture() {
  local -r cell="$1"
  local -r sampled_weight_bytes="${2:-2000000}"
  local -r cell_dir="$OUTPUT_DIR/cells/$cell"
  local -r evidence="$cell_dir/java-measurement/evidence.json"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local sample_records=5
  local evidence_sha256=""

  [[ "$sampled_weight_bytes" =~ ^[0-9]+$ ]] || return 1
  if ((sampled_weight_bytes == 0)); then
    sample_records=0
  fi
  mkdir -p -- "$cell_dir/java-measurement"
  jq -n \
    --arg cell "$cell" \
    --argjson sample_records "$sample_records" \
    --argjson sampled_weight_bytes "$sampled_weight_bytes" '
      {
        status: "complete",
        acceptance_evidence: false,
        cell: $cell,
        jfr: {
          status: "available",
          whole_window_retention_attested: false,
          allocation_sample: {
            records: $sample_records,
            weight_bytes: $sampled_weight_bytes
          }
        },
        interpretation: {
          allocation_sample_weight_is_not_an_exact_allocation_count: true
        }
      }
    ' >"$evidence" || return 1
  evidence_sha256="$(sha256_regular_file "$evidence")" || return 1
  jq -n \
    --arg cell "$cell" \
    --arg evidence_sha256 "$evidence_sha256" '
      {
        cell: $cell,
        evidence_sha256: $evidence_sha256,
        tree_manifest_sha256:
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    ' >"$receipt"
}

validate_sampled_allocation_fixture_seal() {
  local -r cell_dir="$1"
  local -r cell="${cell_dir##*/}"
  local -r evidence="$cell_dir/java-measurement/evidence.json"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local expected_raw_value_count=""
  local observed_raw_value_count=""
  local canonical=""

  [[ -f "$evidence" && ! -L "$evidence" &&
    -f "$receipt" && ! -L "$receipt" ]] || return 1
  canonical="$(jq -c . "$evidence")" || return 1
  expected_raw_value_count="$(jq --stream -n '
    reduce inputs as $event (0;
      if ($event | length) == 2 then . + 1 else . end)
  ' <<<"$canonical")" || return 1
  observed_raw_value_count="$(raw_json_value_count "$evidence")" || return 1
  [[ "$observed_raw_value_count" == "$expected_raw_value_count" ]] || return 1
  jq -se --arg cell "$cell" '
    length == 1 and (.[0] |
      (keys) == ["acceptance_evidence", "cell", "interpretation", "jfr", "status"] and
      .status == "complete" and .acceptance_evidence == false and .cell == $cell and
      (.jfr | (keys) == [
        "allocation_sample", "status", "whole_window_retention_attested"
      ] and .status == "available" and .whole_window_retention_attested == false and
        (.allocation_sample | (keys) == ["records", "weight_bytes"] and
          (.records | type == "number" and isfinite and floor == . and . >= 0) and
          (.weight_bytes | type == "number" and isfinite and floor == . and . >= 0) and
          ((.records == 0 and .weight_bytes == 0) or
            (.records > 0 and .weight_bytes > 0)))) and
      .interpretation == {
        allocation_sample_weight_is_not_an_exact_allocation_count: true
      })
  ' "$evidence" >/dev/null || return 1
  canonical="$(jq -c . "$receipt")" || return 1
  expected_raw_value_count="$(jq --stream -n '
    reduce inputs as $event (0;
      if ($event | length) == 2 then . + 1 else . end)
  ' <<<"$canonical")" || return 1
  observed_raw_value_count="$(raw_json_value_count "$receipt")" || return 1
  [[ "$observed_raw_value_count" == "$expected_raw_value_count" ]] || return 1
  jq -se \
    --arg cell "$cell" \
    --arg evidence_sha256 "$(sha256_regular_file "$evidence")" '
      length == 1 and (.[0] |
        (keys) == ["cell", "evidence_sha256", "tree_manifest_sha256"] and
        .cell == $cell and .evidence_sha256 == $evidence_sha256 and
        (.tree_manifest_sha256 | test("^[0-9a-f]{64}$")))
  ' "$receipt" >/dev/null
}

sampled_allocation_fixture_bundle() {
  local -r cell_dir="$1"
  local -r cell="${cell_dir##*/}"
  local -r evidence="$cell_dir/java-measurement/evidence.json"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local evidence_value=""
  local receipt_value=""
  local evidence_sha256=""
  local receipt_sha256=""

  validate_sampled_allocation_fixture_seal "$cell_dir" || return 1
  evidence_sha256="$(sha256_regular_file "$evidence")" || return 1
  receipt_sha256="$(sha256_regular_file "$receipt")" || return 1
  evidence_value="$(jq -c --arg attestation \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa '
      . + {runtime_artifacts: {attestation_sha256: $attestation}}
    ' "$evidence")" || return 1
  receipt_value="$(jq -c . "$receipt")" || return 1
  jq -cn --argjson evidence "$evidence_value" \
    --argjson receipt "$receipt_value" \
    --arg evidence_sha256 "$evidence_sha256" \
    --arg receipt_sha256 "$receipt_sha256" \
    --arg tree_manifest_sha256 \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa '
      {
        evidence: $evidence,
        receipt: $receipt,
        evidence_sha256: $evidence_sha256,
        receipt_sha256: $receipt_sha256,
        tree_manifest_sha256: $tree_manifest_sha256
      }
    '
}

validate_sampled_allocation_fixture_with_bundle() {
  local -r cell_dir="$1"
  local -r output_name="${2:-}"
  local fixture_payload=""

  fixture_payload="$(sampled_allocation_fixture_bundle "$cell_dir")" || return 1
  if [[ -n "$output_name" ]]; then
    printf -v "$output_name" '%s' "$fixture_payload"
  fi
}

prepare_variance_fixture() {
  local -r output="$1"
  local cell=""

  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Consumed by write_variance_summary from the sourced harness.
  OUTPUT_READY=true
  mkdir -p -- "$OUTPUT_DIR/cells"
  for cell in "${CORE_CELLS[@]}"; do
    write_variance_fixture_cell "$cell"
  done
}

write_proc_growth_fixture() {
  local -r output="$1"
  local -r pid="$2"
  local -r fds="$3"
  local -r threads="$4"
  local -r container_id="${5:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
  local -r start_time="${6:-$((pid * 10))}"
  local -r cgroup_sha256="${7:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"

  {
    printf 'status=available\n'
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$pid"
    printf 'proc_start_time=%s\n' "$start_time"
    printf 'proc_cgroup_sha256=%s\n' "$cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' "$PROC_CGROUP_CONTAINER_BINDING"
    printf 'fd_count=%s\n' "$fds"
    printf 'task_count=%s\n' "$threads"
  } >"$output"
}

write_java_map_growth_fixture() {
  local -r output="$1"
  local -r map_entries_count="$2"
  local -r maximum="$3"

  {
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}'" $map_entries_count"
    printf '%s\n' \
      'obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}'" $maximum"
  } >"$output"
}

write_bpf_fd_ownership_fixture() {
  local -r output="$1"
  local -r map_id="${2:-41}"
  local -r program_id="${3:-71}"
  local -r container_id="${4:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
  local -r host_pid="${5:-101}"
  local -r start_time="${6:-1010}"
  local -r cgroup_sha256="${7:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"

  {
    printf 'status=available\n'
    printf 'container_id=%s\n' "$container_id"
    printf 'host_pid=%s\n' "$host_pid"
    printf 'proc_start_time=%s\n' "$start_time"
    printf 'proc_cgroup_sha256=%s\n' "$cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' "$PROC_CGROUP_CONTAINER_BINDING"
    printf 'fd=4 map_id=%s\n' "$map_id"
    printf 'fd=5 prog_id=%s\n' "$program_id"
    printf 'fd=6 map_id=%s\n' "$map_id"
  } >"$output"
}

write_proc_stat_fixture() {
  local -r output="$1"
  local -r pid="$2"
  local -r start_time="$3"

  printf '%s (fixture process) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 %s 0\n' \
    "$pid" "$start_time" >"$output"
}

prepare_bound_cgroup_v2_fixture() {
  local -r fixture="$1"
  local -r container_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local -r cgroup_path="/docker/$container_id"
  local -r proc_root="$fixture/proc"
  local -r cgroup_root="$fixture/cgroup"
  local -r cgroup_directory="$cgroup_root$cgroup_path"
  local cgroup_sha256=""

  mkdir -p -- "$proc_root/101/fd" "$proc_root/101/task/101" \
    "$proc_root/101/task/102" "$proc_root/202/fd" "$proc_root/202/task/202" \
    "$cgroup_directory"
  ln -s -- /dev/null "$proc_root/101/fd/0"
  ln -s -- /dev/null "$proc_root/101/fd/1"
  ln -s -- /dev/null "$proc_root/202/fd/0"
  write_proc_stat_fixture "$proc_root/101/stat" 101 1010
  write_proc_stat_fixture "$proc_root/202/stat" 202 2020
  printf '0::%s\n' "$cgroup_path" >"$proc_root/101/cgroup"
  cp -- "$proc_root/101/cgroup" "$proc_root/202/cgroup"
  {
    printf 'Name:\troot\n'
    printf 'VmRSS:\t100 kB\n'
    printf 'Threads:\t2\n'
  } >"$proc_root/101/status"
  {
    printf 'Name:\tchild\n'
    printf 'VmRSS:\t50 kB\n'
    printf 'Threads:\t1\n'
  } >"$proc_root/202/status"
  printf 'cpu memory\n' >"$cgroup_root/cgroup.controllers"
  printf 'domain\n' >"$cgroup_directory/cgroup.type"
  printf 'nr_descendants 0\nnr_dying_descendants 0\n' \
    >"$cgroup_directory/cgroup.stat"
  printf '202\n101\n' >"$cgroup_directory/cgroup.procs"
  printf 'usage_usec 1000\nuser_usec 600\nsystem_usec 400\n' \
    >"$cgroup_directory/cpu.stat"
  cgroup_sha256="$(sha256_regular_file "$proc_root/101/cgroup")" || return 1
  {
    printf 'service=java-backend\n'
    printf 'container_id=%s\n' "$container_id"
    printf 'image_id=sha256:%064d\n' 0
    printf 'host_pid=101\n'
    printf 'proc_start_time=1010\n'
    printf 'proc_cgroup_sha256=%s\n' "$cgroup_sha256"
    printf 'proc_cgroup_container_binding=%s\n' \
      "$PROC_CGROUP_CONTAINER_BINDING"
    printf 'project=fixture\n'
    printf 'owner_sentinel=fixture\n'
  } >"$fixture/java-backend-identity.txt"
}

expect_bound_cgroup_fixture_unavailable() {
  local -r fixture="$1"
  local -r label="$2"
  local -r output="$fixture/$label.json"

  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  capture_bound_cgroup_v2_snapshot_from_roots \
    "$fixture/java-backend-identity.txt" "$output" before \
    "$fixture/proc" "$fixture/cgroup" fixture java-backend || return 1
  jq -e '
    .schema_version == 1 and
    .kind == "bound-container-cgroup-v2-snapshot" and
    .status == "unavailable" and
    .reason == "authority_or_two_pass_snapshot_unavailable"
  ' "$output" >/dev/null || {
    printf 'cgroup-v2 mutation was not retained as unavailable: %s\n' "$label" >&2
    return 1
  }
  [[ -z "$(find "$fixture" -maxdepth 1 \
    \( -name '.cgroup-snapshot.*' -o -name '.cgroup-v2.json.*' \) -print -quit)" ]] || {
    printf 'cgroup-v2 mutation leaked a private temporary: %s\n' "$label" >&2
    return 1
  }
}

expect_bound_cgroup_duplicate_rejected() {
  local -r source="$1"
  local -r label="$2"
  local -r needle="$3"
  local -r duplicate="$4"
  local -r mutated="${source%/*}/duplicate-$label.json"
  local compact=""
  local mutated_json=""

  [[ -f "$source" && ! -L "$source" && ! -e "$mutated" && ! -L "$mutated" ]] ||
    return 1
  compact="$(jq -cS . "$source")" || return 1
  mutated_json="${compact/"$needle"/"$duplicate"}"
  [[ "$mutated_json" != "$compact" ]] || {
    printf 'duplicate-key mutation needle was absent: %s\n' "$label" >&2
    return 1
  }
  printf '%s\n' "$mutated_json" >"$mutated" || return 1
  if validate_bound_cgroup_v2_snapshot_schema "$mutated"; then
    printf 'cgroup-v2 schema accepted a duplicate key: %s\n' "$label" >&2
    return 1
  fi
  rm -f -- "$mutated"
}

test_bound_cgroup_v2_process_tree_is_complete_bounded_and_fail_closed() (
  local -r fixture="$TEST_TMP_DIR/bound-cgroup-v2"
  local -r output="$fixture/available.json"
  local -r cgroup_directory="$fixture/cgroup/docker/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local -r container_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local original_definition=""

  mkdir -- "$fixture"
  prepare_bound_cgroup_v2_fixture "$fixture"

  # A regular temporary filesystem with a lookalike cgroup.controllers file is
  # not a cgroup-v2 mount. This exercises the production statfs proof before
  # enabling the explicit hermetic seam below.
  expect_bound_cgroup_fixture_unavailable "$fixture" statfs-lookalike
  expect_bound_cgroup_duplicate_rejected \
    "$fixture/statfs-lookalike.json" unavailable-top-level \
    '"status":"unavailable"' \
    '"status":"unavailable","status":"unavailable"'
  cgroup_root_is_cgroup2() {
    [[ "$1" == "$fixture/cgroup" || "$1" =~ ^/proc/self/fd/[0-9]+$ ]]
  }

  capture_bound_cgroup_v2_snapshot_from_roots \
    "$fixture/java-backend-identity.txt" "$output" before \
    "$fixture/proc" "$fixture/cgroup" fixture java-backend
  validate_bound_cgroup_v2_snapshot_schema "$output"
  jq -e '
    .status == "available" and .cell == "fixture" and
    .service == "java-backend" and .timing == "before" and
    .identity.filesystem_type == "cgroup2fs" and
    .identity.cgroup_type == "domain" and .identity.leaf == true and
    .identity.cgroup_root_device == .identity.cgroup_device and
    (.identity.cgroup_root_inode > 0) and
    (.identity.cgroup_hierarchy_sha256 | test("^[0-9a-f]{64}$")) and
    .identity.nr_descendants == 0 and .identity.nr_dying_descendants == 0 and
    [.roster[].pid] == [101, 202] and
    all(.passes[];
      .totals == {process_count: 2, fd_count: 3, task_count: 3,
        status_threads: 3, rss_bytes: 153600} and
      .cpu_stat == {usage_usec: 1000, user_usec: 600, system_usec: 400}) and
    .envelope.fd_count == {min: 3, max: 3} and
    .envelope.task_count == {min: 3, max: 3} and
    .envelope.rss_bytes == {min: 153600, max: 153600}
  ' "$output" >/dev/null || {
    printf 'valid full-tree cgroup-v2 fixture was not aggregated exactly\n' >&2
    return 1
  }

  expect_bound_cgroup_duplicate_rejected "$output" available-top-level \
    '"status":"available"' '"status":"available","status":"available"'
  expect_bound_cgroup_duplicate_rejected "$output" identity \
    "\"container_id\":\"$container_id\"" \
    "\"container_id\":\"$container_id\",\"container_id\":\"$container_id\""
  expect_bound_cgroup_duplicate_rejected "$output" authority-roster-row \
    '"roster":[{"pid":101' '"roster":[{"pid":101,"pid":101'
  expect_bound_cgroup_duplicate_rejected "$output" pass \
    '"passes":[{"cpu_stat":' '"passes":[{"cpu_stat":{},"cpu_stat":'
  expect_bound_cgroup_duplicate_rejected "$output" process \
    '"processes":[{"fd_count":2' '"processes":[{"fd_count":2,"fd_count":2'
  expect_bound_cgroup_duplicate_rejected "$output" totals \
    '"totals":{"fd_count":3' \
    '"totals":{"fd_count":3,"fd_count":3'
  expect_bound_cgroup_duplicate_rejected "$output" cpu-stat \
    '"cpu_stat":{"system_usec":400' \
    '"cpu_stat":{"system_usec":400,"system_usec":400'
  expect_bound_cgroup_duplicate_rejected "$output" envelope \
    '"envelope":{"cpu_system_usec":{"max":400,"min":400}' \
    '"envelope":{"cpu_system_usec":{"max":400,"min":400},"cpu_system_usec":{"max":400,"min":400}'
  expect_bound_cgroup_duplicate_rejected "$output" envelope-pair \
    '"fd_count":{"max":3,"min":3}' \
    '"fd_count":{"max":3,"max":3,"min":3}'
  expect_bound_cgroup_duplicate_rejected "$output" collection \
    '"collection":{"authority":"compose_identity_plus_fd_anchored_cgroup2_root_leaf_and_stable_hierarchy"' \
    '"collection":{"authority":"compose_identity_plus_fd_anchored_cgroup2_root_leaf_and_stable_hierarchy","authority":"compose_identity_plus_fd_anchored_cgroup2_root_leaf_and_stable_hierarchy"'

  head -c "$((MAX_BOUND_CGROUP_V2_SNAPSHOT_BYTES + 1))" /dev/zero | tr '\0' x \
    >"$fixture/oversized-snapshot.json"
  if validate_bound_cgroup_v2_snapshot_schema "$fixture/oversized-snapshot.json"; then
    printf 'cgroup-v2 schema accepted a snapshot above its derived byte cap\n' >&2
    return 1
  fi
  rm -f -- "$fixture/oversized-snapshot.json"

  (
    local statfs_checks=0
    cgroup_root_is_cgroup2() {
      ((statfs_checks += 1))
      [[ "$1" == "$fixture/cgroup" || "$1" =~ ^/proc/self/fd/[0-9]+$ ]] || return 1
      ((statfs_checks <= 3))
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" statfs-end-drift
  )

  (
    stat() {
      local target="${*: -1}"
      local identity=""
      local device=""
      local inode=""
      local extra=""

      if [[ "$target" =~ ^/proc/self/fd/[0-9]+$ &&
        "$(readlink -- "$target")" == "$cgroup_directory" &&
        "$*" == *"--format %d %i"* ]]; then
        identity="$(command stat -L --format '%d %i' -- "$target")" || return 1
        read -r device inode extra <<<"$identity" || return 1
        [[ -z "$extra" ]] || return 1
        printf '%s %s\n' "$((device + 1))" "$inode"
      else
        command stat "$@"
      fi
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" root-leaf-device-discontinuity
  )

  original_definition="$(declare -f parse_cgroup_v2_path_from_root)" || return 1
  (
    local -r path_reads_file="$fixture/path-reads.txt"
    local path_reads=0
    printf '0\n' >"$path_reads_file"
    eval "${original_definition/parse_cgroup_v2_path_from_root/parse_cgroup_v2_path_from_root_original}"
    parse_cgroup_v2_path_from_root() {
      read -r path_reads <"$path_reads_file" || return 1
      ((path_reads += 1))
      printf '%s\n' "$path_reads" >"$path_reads_file" || return 1
      if [[ "$path_reads" == 2 ]]; then
        printf '/docker/%s/changed\n' "$container_id"
      else
        parse_cgroup_v2_path_from_root_original "$@"
      fi
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" cgroup-path-end-drift
    rm -f -- "$path_reads_file"
  )

  original_definition="$(declare -f capture_process_tree_pass_from_root)" || return 1
  (
    local process_passes=0
    local -r original_leaf="$cgroup_directory.original"
    restore_leaf_path() {
      if [[ -d "$original_leaf" && ! -L "$original_leaf" ]]; then
        [[ ! -e "$cgroup_directory" || -d "$cgroup_directory" ]] || return 1
        if [[ -d "$cgroup_directory" ]]; then
          rmdir -- "$cgroup_directory" || return 1
        fi
        mv -- "$original_leaf" "$cgroup_directory"
      fi
    }
    trap restore_leaf_path EXIT
    eval "${original_definition/capture_process_tree_pass_from_root/capture_process_tree_pass_from_root_original}"
    capture_process_tree_pass_from_root() {
      capture_process_tree_pass_from_root_original "$@" || return 1
      ((process_passes += 1))
      if [[ "$process_passes" == 1 ]]; then
        mv -- "$cgroup_directory" "$original_leaf" || return 1
        mkdir -- "$cgroup_directory" || return 1
      fi
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" cgroup-leaf-path-replacement
  )

  original_definition="$(declare -f capture_process_tree_pass_from_root)" || return 1
  (
    local process_passes=0
    local -r cgroup_root="$fixture/cgroup"
    local -r original_root="$fixture/cgroup.original"
    restore_root_path() {
      if [[ -d "$original_root" && ! -L "$original_root" ]]; then
        if [[ -d "$cgroup_root" ]]; then
          rm -f -- "$cgroup_root/cgroup.controllers"
          rmdir -- "$cgroup_root/docker/$container_id" \
            "$cgroup_root/docker" "$cgroup_root" || return 1
        fi
        mv -- "$original_root" "$cgroup_root"
      fi
    }
    trap restore_root_path EXIT
    eval "${original_definition/capture_process_tree_pass_from_root/capture_process_tree_pass_from_root_original}"
    capture_process_tree_pass_from_root() {
      capture_process_tree_pass_from_root_original "$@" || return 1
      ((process_passes += 1))
      if [[ "$process_passes" == 1 ]]; then
        mv -- "$cgroup_root" "$original_root" || return 1
        mkdir -p -- "$cgroup_root/docker/$container_id" || return 1
        : >"$cgroup_root/cgroup.controllers"
      fi
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" cgroup-root-path-replacement
  )

  original_definition="$(declare -f cgroup_leaf_stat_values)" || return 1
  (
    local leaf_checks=0
    local values=""
    eval "${original_definition/cgroup_leaf_stat_values/cgroup_leaf_stat_values_original}"
    cgroup_leaf_stat_values() {
      values="$(cgroup_leaf_stat_values_original "$@")" || return 1
      ((leaf_checks += 1))
      if [[ "$leaf_checks" == 1 ]]; then
        printf 'nr_descendants 1\nnr_dying_descendants 0\n' \
          >"$cgroup_directory/cgroup.stat"
      fi
      printf '%s\n' "$values"
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" descendant-end-drift
  )
  printf 'nr_descendants 0\nnr_dying_descendants 0\n' \
    >"$cgroup_directory/cgroup.stat"

  head -c "$((MAX_CGROUP_STAT_BYTES + 1))" /dev/zero | tr '\0' x \
    >"$cgroup_directory/cgroup.stat"
  expect_bound_cgroup_fixture_unavailable "$fixture" oversized-cgroup-stat
  printf 'nr_descendants 0\nnr_dying_descendants 0\n' \
    >"$cgroup_directory/cgroup.stat"

  printf 'nr_descendants 1\nnr_dying_descendants 0\n' \
    >"$cgroup_directory/cgroup.stat"
  expect_bound_cgroup_fixture_unavailable "$fixture" live-descendant
  printf 'nr_descendants 0\nnr_dying_descendants 1\n' \
    >"$cgroup_directory/cgroup.stat"
  expect_bound_cgroup_fixture_unavailable "$fixture" dying-descendant
  printf 'nr_descendants 0\nnr_dying_descendants 0\n' \
    >"$cgroup_directory/cgroup.stat"

  printf 'usage_usec 1002\nuser_usec 600\nsystem_usec 400\n' \
    >"$cgroup_directory/cpu.stat"
  expect_bound_cgroup_fixture_unavailable "$fixture" cpu-rounding-gap
  printf 'usage_usec 1000\nusage_usec 1000\nuser_usec 600\nsystem_usec 400\n' \
    >"$cgroup_directory/cpu.stat"
  expect_bound_cgroup_fixture_unavailable "$fixture" duplicate-cpu-counter
  printf 'usage_usec 1000\nuser_usec 600\nsystem_usec 400\n' \
    >"$cgroup_directory/cpu.stat"

  printf '202\n101\n101\n' >"$cgroup_directory/cgroup.procs"
  expect_bound_cgroup_fixture_unavailable "$fixture" duplicate-process
  printf '202\nnot-a-pid\n101\n' >"$cgroup_directory/cgroup.procs"
  expect_bound_cgroup_fixture_unavailable "$fixture" malformed-process
  printf '202\n101\n' >"$cgroup_directory/cgroup.procs"

  printf 'VmRSS:\t100 kB\nVmRSS:\t100 kB\nThreads:\t2\n' \
    >"$fixture/proc/101/status"
  expect_bound_cgroup_fixture_unavailable "$fixture" duplicate-rss
  printf 'VmRSS:\t100 bytes\nThreads:\t2\n' >"$fixture/proc/101/status"
  expect_bound_cgroup_fixture_unavailable "$fixture" bad-rss-unit
  printf 'VmRSS:\t100 kB\nThreads:\t1\n' >"$fixture/proc/101/status"
  expect_bound_cgroup_fixture_unavailable "$fixture" task-thread-mismatch
  printf 'VmRSS:\t100 kB\nThreads:\t2\n' >"$fixture/proc/101/status"

  rm -f -- "$fixture/proc/101/fd/1"
  : >"$fixture/proc/101/fd/1"
  expect_bound_cgroup_fixture_unavailable "$fixture" non-symlink-fd-entry
  rm -f -- "$fixture/proc/101/fd/1"
  ln -s -- /dev/null "$fixture/proc/101/fd/1"

  original_definition="$(declare -f capture_cgroup_procs_roster)" || return 1
  (
    local roster_calls=0
    eval "${original_definition/capture_cgroup_procs_roster/capture_cgroup_procs_roster_original}"
    capture_cgroup_procs_roster() {
      capture_cgroup_procs_roster_original "$@" || return 1
      ((roster_calls += 1))
      if [[ "$roster_calls" == 1 ]]; then
        printf '101\n' >"$cgroup_directory/cgroup.procs"
      fi
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" process-roster-pass-drift
  )
  printf '202\n101\n' >"$cgroup_directory/cgroup.procs"

  original_definition="$(declare -f capture_process_tree_pass_from_root)" || return 1
  (
    local process_passes=0
    local -r dynamic_output="$fixture/dynamic-resource-envelope.json"
    eval "${original_definition/capture_process_tree_pass_from_root/capture_process_tree_pass_from_root_original}"
    capture_process_tree_pass_from_root() {
      capture_process_tree_pass_from_root_original "$@" || return 1
      ((process_passes += 1))
      if [[ "$process_passes" == 1 ]]; then
        ln -s -- /dev/null "$fixture/proc/101/fd/2"
        mkdir -- "$fixture/proc/101/task/103"
        printf 'VmRSS:\t101 kB\nThreads:\t3\n' >"$fixture/proc/101/status"
      fi
    }
    capture_bound_cgroup_v2_snapshot_from_roots \
      "$fixture/java-backend-identity.txt" "$dynamic_output" before \
      "$fixture/proc" "$fixture/cgroup" fixture java-backend || return 1
    jq -e '
      .status == "available" and
      [.passes[].totals.fd_count] == [3, 4] and
      [.passes[].totals.task_count] == [3, 4] and
      [.passes[].totals.rss_bytes] == [153600, 154624] and
      .passes[0].roster_sha256 == .passes[1].roster_sha256 and
      .passes[0].processes[0].fd_roster_sha256 !=
        .passes[1].processes[0].fd_roster_sha256 and
      .passes[0].processes[0].task_roster_sha256 !=
        .passes[1].processes[0].task_roster_sha256 and
      .envelope.fd_count == {min: 3, max: 4} and
      .envelope.task_count == {min: 3, max: 4} and
      .envelope.rss_bytes == {min: 153600, max: 154624} and
      [.roster[].pid] == [101, 202]
    ' "$dynamic_output" >/dev/null || {
      printf 'dynamic FD values were not retained as a two-pass envelope\n' >&2
      return 1
    }
  )
  rm -f -- "$fixture/proc/101/fd/2"
  rmdir -- "$fixture/proc/101/task/103"
  printf 'VmRSS:\t100 kB\nThreads:\t2\n' >"$fixture/proc/101/status"

  original_definition="$(declare -f capture_process_tree_pass_from_root)" || return 1
  (
    local process_passes=0
    eval "${original_definition/capture_process_tree_pass_from_root/capture_process_tree_pass_from_root_original}"
    capture_process_tree_pass_from_root() {
      capture_process_tree_pass_from_root_original "$@" || return 1
      ((process_passes += 1))
      if [[ "$process_passes" == 1 ]]; then
        write_proc_stat_fixture "$fixture/proc/202/stat" 202 3030
      fi
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" pid-start-pass-drift
  )
  write_proc_stat_fixture "$fixture/proc/202/stat" 202 2020

  original_definition="$(declare -f capture_process_tree_pass_from_root)" || return 1
  (
    local process_passes=0
    eval "${original_definition/capture_process_tree_pass_from_root/capture_process_tree_pass_from_root_original}"
    capture_process_tree_pass_from_root() {
      capture_process_tree_pass_from_root_original "$@" || return 1
      ((process_passes += 1))
      if [[ "$process_passes" == 1 ]]; then
        printf '0::/docker/%s/child\n' \
          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
          >"$fixture/proc/202/cgroup"
      fi
    }
    expect_bound_cgroup_fixture_unavailable "$fixture" pid-cgroup-pass-drift
  )
  cp -- "$fixture/proc/101/cgroup" "$fixture/proc/202/cgroup"

  (
    cut() { return 73; }
    expect_bound_cgroup_fixture_unavailable "$fixture" cut-projection-failure
  )
  [[ -z "$(find "$fixture" -maxdepth 2 \
    \( -name '.benchmark-status.*' -o -name '.numeric-directory-roster.*' \) \
    -print -quit)" ]] || {
    printf 'late process-tree failure leaked scratch artifacts\n' >&2
    return 1
  }
)

write_bound_cgroup_v2_snapshot_fixture() {
  local -r output="$1"
  local -r cell="$2"
  local -r service="$3"
  local -r timing="$4"
  local -r repetition_raw="$5"
  local -r fd_1="$6"
  local -r fd_2="$7"
  local -r task_1="$8"
  local -r task_2="$9"
  local -r rss_1="${10}"
  local -r rss_2="${11}"
  local -r usage_1="${12}"
  local -r usage_2="${13}"
  local -r cgroup_inode="${14:-2}"
  local -r container_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local -r cgroup_path="/docker/$container_id"
  local repetition_json=null
  local cgroup_path_sha256=""

  if [[ "$timing" == scheduled_repetition_midpoint ]]; then
    repetition_json="$repetition_raw"
  else
    [[ -z "$repetition_raw" ]] || return 1
  fi
  cgroup_path_sha256="$(printf '%s' "$cgroup_path" | sha256sum)" || return 1
  cgroup_path_sha256="${cgroup_path_sha256%% *}"
  jq -n --arg cell "$cell" --arg service "$service" --arg timing "$timing" \
    --argjson repetition "$repetition_json" --arg container_id "$container_id" \
    --arg cgroup_path "$cgroup_path" --arg cgroup_path_sha256 "$cgroup_path_sha256" \
    --argjson fd_1 "$fd_1" --argjson fd_2 "$fd_2" \
    --argjson task_1 "$task_1" --argjson task_2 "$task_2" \
    --argjson rss_1 "$rss_1" --argjson rss_2 "$rss_2" \
    --argjson usage_1 "$usage_1" --argjson usage_2 "$usage_2" \
    --argjson cgroup_inode "$cgroup_inode" '
      def process($fd; $task; $rss): {
        pid: 101, proc_start_time: 1010,
        proc_cgroup_sha256: ("b" * 64),
        proc_cgroup_container_binding: "full_container_id_at_non_hex_boundaries",
        fd_roster_sha256: ("c" * 64), task_roster_sha256: ("d" * 64),
        fd_count: $fd, task_count: $task, status_threads: $task, rss_bytes: $rss
      };
      def pass($ordinal; $fd; $task; $rss; $usage): {
        ordinal: $ordinal, roster_sha256: ("e" * 64),
        processes: [process($fd; $task; $rss)],
        totals: {process_count: 1, fd_count: $fd, task_count: $task,
          status_threads: $task, rss_bytes: $rss},
        cpu_stat: {usage_usec: $usage, user_usec: ($usage - 1), system_usec: 1}
      };
      def pair($left; $right): {
        min: ([$left, $right] | min), max: ([$left, $right] | max)
      };
      (pass(1; $fd_1; $task_1; $rss_1; $usage_1)) as $pass_1 |
      (pass(2; $fd_2; $task_2; $rss_2; $usage_2)) as $pass_2 |
      {
        schema_version: 1, kind: "bound-container-cgroup-v2-snapshot",
        status: "available", cell: $cell, service: $service, timing: $timing,
        repetition: $repetition, identity_source: ($service + "-identity.txt"),
        identity: {
          container_id: $container_id, root_host_pid: 101,
          root_proc_start_time: 1010, proc_cgroup_sha256: ("b" * 64),
          proc_cgroup_container_binding: "full_container_id_at_non_hex_boundaries",
          cgroup_path: $cgroup_path, cgroup_path_sha256: $cgroup_path_sha256,
          cgroup_root_device: 1, cgroup_root_inode: 1,
          cgroup_device: 1, cgroup_inode: $cgroup_inode,
          cgroup_hierarchy_sha256: ("f" * 64), cgroup_version: 2,
          cgroup_type: "domain", filesystem_type: "cgroup2fs", leaf: true,
          nr_descendants: 0, nr_dying_descendants: 0
        },
        roster: [{pid: 101, proc_start_time: 1010,
          proc_cgroup_sha256: ("b" * 64),
          proc_cgroup_container_binding: "full_container_id_at_non_hex_boundaries"}],
        passes: [$pass_1, $pass_2],
        envelope: {
          process_count: {min: 1, max: 1}, fd_count: pair($fd_1; $fd_2),
          task_count: pair($task_1; $task_2),
          status_threads: pair($task_1; $task_2), rss_bytes: pair($rss_1; $rss_2),
          cpu_usage_usec: pair($usage_1; $usage_2),
          cpu_user_usec: pair($usage_1 - 1; $usage_2 - 1),
          cpu_system_usec: {min: 1, max: 1}
        },
        collection: {
          authority: "compose_identity_plus_fd_anchored_cgroup2_root_leaf_and_stable_hierarchy",
          roster_stability: "two_identical_sorted_pid_start_cgroup_rosters",
          resource_values: "two_pass_conservative_envelope",
          cgroup2_leaf_domain_required: true
        }
      }
    ' >"$output" || return 1
  validate_bound_cgroup_v2_snapshot_schema "$output"
}

write_bound_service_identity_fixture() {
  local -r output="$1"
  local -r service="$2"

  {
    printf 'service=%s\n' "$service"
    printf 'container_id=%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    printf 'image_id=sha256:%s\n' 0000000000000000000000000000000000000000000000000000000000000000
    printf 'host_pid=101\n'
    printf 'proc_start_time=1010\n'
    printf 'proc_cgroup_sha256=%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    printf 'proc_cgroup_container_binding=%s\n' "$PROC_CGROUP_CONTAINER_BINDING"
    printf 'project=fixture\n'
    printf 'owner_sentinel=fixture\n'
  } >"$output"
}

write_cpu_measurement_boundary_fixture() {
  local -r directory="$1"
  local -r cell="$2"
  local -r timing="$3"
  local -r services_json="$4"
  local service=""

  jq -n --arg cell "$cell" --arg timing "$timing" --argjson services "$services_json" '{
    schema_version: 1,
    kind: "authoritative-application-cgroup-v2-boundary",
    timing: $timing,
    cell: $cell,
    services: $services,
    capture: {
      started: {wall_epoch_seconds: 1000, monotonic_milliseconds: 1000000},
      ended: {wall_epoch_seconds: 1001, monotonic_milliseconds: 1001000}
    },
    authority: {
      cpu_stat: "authoritative",
      process_tree_fd_task_rss: "authoritative",
      primary_cgroupsockopt_program_cpu: "not_collected"
    }
  }' >"$directory/snapshot.json"
  while IFS= read -r service; do
    write_bound_service_identity_fixture "$directory/$service-identity.txt" "$service"
  done < <(jq -r '.[]' <<<"$services_json")
}

write_resource_boundary_fixture() {
  local -r directory="$1"
  local -r cell="$2"
  local -r timing="$3"
  local -r started_wall="$4"
  local -r started_monotonic="$5"
  local -r ended_wall="$6"
  local -r ended_monotonic="$7"
  local diagnostics='{"status":"requested"}'

  if [[ "$timing" == idle_recovery_01 || "$timing" == idle_recovery_02 ]]; then
    diagnostics='{"status":"not_collected","reason":"excluded_from_ordered_idle_recovery_window"}'
  fi
  jq -n --arg cell "$cell" --arg timing "$timing" \
    --argjson started_wall "$started_wall" \
    --argjson started_monotonic "$started_monotonic" \
    --argjson ended_wall "$ended_wall" \
    --argjson ended_monotonic "$ended_monotonic" \
    --argjson diagnostics "$diagnostics" '{
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
      authority: {classification: "resource_boundary",
        process_tree_cgroup_v2: "collected"},
      java_diagnostics: $diagnostics
    }' >"$directory/snapshot.json"
}

write_scheduled_midpoint_boundary_fixture() {
  local -r directory="$1"
  local -r cell="$2"
  local -r repetition="$3"
  local -r services_json="$4"
  local parent_identity=""
  local directory_identity=""
  local artifacts_json=""
  local repetition_label=""
  local service=""
  local -a artifacts=()

  printf -v repetition_label 'rep-%02d' "$repetition"
  parent_identity="$(stat --format '%d:%i:%u:%a' -- "${directory%/*}")" || return 1
  directory_identity="$(stat --format '%d:%i:%u:%a' -- "$directory")" || return 1
  while IFS= read -r service; do
    write_bound_service_identity_fixture "$directory/$service-identity.txt" "$service"
    artifacts+=("$(jq -cn --arg service "$service" '{
      service: $service,
      identity_source: ($service + "-identity.txt"),
      cgroup_snapshot: ($service + "-cgroup-v2.json")
    }')") || return 1
  done < <(jq -r '.[]' <<<"$services_json")
  artifacts_json="$(printf '%s\n' "${artifacts[@]}" | jq -s .)" || return 1
  jq -n --arg cell "$cell" --arg parent_identity "$parent_identity" \
    --arg directory_identity "$directory_identity" \
    --arg output_source "cells/$cell/measurements/$repetition_label-midpoint" \
    --arg result_source "cells/$cell/measurements/$repetition_label.json" \
    --argjson repetition "$repetition" --argjson artifacts "$artifacts_json" '{
      schema_version: 1,
      kind: "scheduled-cgroup-v2-midpoint-receipt",
      status: "available",
      cell: $cell,
      repetition: $repetition,
      benchmark_duration_seconds: 2,
      scheduled_seconds_after_confirmed_launch: 1,
      output_source: $output_source,
      measurement_parent_identity: $parent_identity,
      published_directory_identity: $directory_identity,
      benchmark: {pid: 4242, identity: "4242 4242 1010", result_source: $result_source},
      clocks: {
        confirmed_launch: {wall_epoch_seconds: 1000, monotonic_milliseconds: 1000000},
        sleep_started: {wall_epoch_seconds: 1000, monotonic_milliseconds: 1000000},
        sleep_ended: {wall_epoch_seconds: 1001, monotonic_milliseconds: 1001000},
        capture_started: {wall_epoch_seconds: 1001, monotonic_milliseconds: 1001000},
        capture_ended: {wall_epoch_seconds: 1001, monotonic_milliseconds: 1001000}
      },
      elapsed: {
        sleep_wall_seconds: 1,
        sleep_monotonic_milliseconds: 1000,
        confirmed_launch_to_sleep_end_wall_seconds: 1,
        confirmed_launch_to_sleep_end_monotonic_milliseconds: 1000
      },
      scope: {
        cgroup_v2_process_tree: {status: "collected"},
        docker_inspect: {status: "not_collected", reason: "excluded_from_measured_window"},
        container_stats: {status: "not_collected", reason: "excluded_from_measured_window"},
        obi_metrics: {status: "not_collected", reason: "zero_in_window_scrapes_required"},
        java_diagnostics: {status: "not_collected", reason: "excluded_from_measured_window"}
      },
      artifacts: $artifacts
    }' >"$directory/midpoint-receipt.json" || return 1
  jq -n --arg cell "$cell" --argjson repetition "$repetition" \
    --argjson services "$services_json" '{
      schema_version: 1,
      kind: "scheduled-cgroup-v2-midpoint-boundary",
      status: "available",
      cell: $cell,
      repetition: $repetition,
      timing: "scheduled_repetition_midpoint",
      receipt: "midpoint-receipt.json",
      metrics: {status: "not_collected", reason: "zero_in_window_scrapes_required"},
      java_diagnostics: {status: "not_collected", reason: "excluded_from_measured_window"},
      services: $services
    }' >"$directory/snapshot.json"
}

write_process_tree_observation_fixture() {
  local -r fixture="$1"
  local -r cell="fixture-cell"
  local -r service="java-backend"
  local repetition=0

  mkdir -p -- "$fixture/midpoints"
  write_bound_cgroup_v2_snapshot_fixture \
    "$fixture/before.json" "$cell" "$service" before '' 3 3 3 3 153600 153600 1000 1001
  write_bound_cgroup_v2_snapshot_fixture \
    "$fixture/baseline.json" "$cell" "$service" cpu_measurement_baseline '' \
    3 3 3 3 153600 153600 1100 1101
  write_bound_cgroup_v2_snapshot_fixture \
    "$fixture/end.json" "$cell" "$service" cpu_measurement_end '' 3 3 3 3 153600 153600 1200 1201
  write_bound_cgroup_v2_snapshot_fixture \
    "$fixture/after.json" "$cell" "$service" after '' 3 3 3 3 153600 153600 1300 1301
  write_bound_cgroup_v2_snapshot_fixture \
    "$fixture/recovery-01.json" "$cell" "$service" idle_recovery_01 '' \
    3 3 3 3 153600 153600 1400 1401
  write_bound_cgroup_v2_snapshot_fixture \
    "$fixture/recovery-02.json" "$cell" "$service" idle_recovery_02 '' \
    3 3 3 3 153600 153600 1500 1501
  for ((repetition = 1; repetition <= 5; repetition++)); do
    write_bound_cgroup_v2_snapshot_fixture \
      "$fixture/midpoints/$repetition.json" "$cell" "$service" \
      scheduled_repetition_midpoint "$repetition" 3 3 3 3 153600 153600 \
      "$((1100 + repetition * 10))" "$((1101 + repetition * 10))"
  done
  jq -n --arg cell "$cell" '{
    schema_version: 1, kind: "ordered-idle-recovery-schedule", status: "complete",
    cell: $cell, required_consecutive_samples: 2,
    load_activity_between_samples: false,
    started: {wall_epoch_seconds: 1000, monotonic_milliseconds: 1000000},
    samples: [
      {
        ordinal: 1, idle_interval_seconds: 30, ordering: "after_postload_sentinel",
        sleep: {
          started: {wall_epoch_seconds: 1000, monotonic_milliseconds: 1000000},
          ended: {wall_epoch_seconds: 1030, monotonic_milliseconds: 1030000},
          elapsed_wall_seconds: 30, elapsed_monotonic_milliseconds: 30000
        },
        capture: {
          started: {wall_epoch_seconds: 1030, monotonic_milliseconds: 1030000},
          ended: {wall_epoch_seconds: 1031, monotonic_milliseconds: 1031000},
          resource_snapshot: "resources-idle-recovery-01"
        }
      },
      {
        ordinal: 2, idle_interval_seconds: 30,
        ordering: "after_recovery_01_without_intervening_workload",
        sleep: {
          started: {wall_epoch_seconds: 1031, monotonic_milliseconds: 1031000},
          ended: {wall_epoch_seconds: 1061, monotonic_milliseconds: 1061000},
          elapsed_wall_seconds: 30, elapsed_monotonic_milliseconds: 30000
        },
        capture: {
          started: {wall_epoch_seconds: 1061, monotonic_milliseconds: 1061000},
          ended: {wall_epoch_seconds: 1062, monotonic_milliseconds: 1062000},
          resource_snapshot: "resources-idle-recovery-02"
        }
      }
    ],
    completed: {wall_epoch_seconds: 1062, monotonic_milliseconds: 1062000}
  }' >"$fixture/recovery-schedule.json"
}

process_tree_fixture_observation() {
  local -r fixture="$1"

  process_tree_resource_observation fixture-cell java-backend \
    "$fixture/before.json" "$fixture/baseline.json" "$fixture/end.json" \
    "$fixture/after.json" "$fixture/recovery-01.json" "$fixture/recovery-02.json" \
    "$fixture/recovery-schedule.json" "$fixture/midpoints/1.json" \
    "$fixture/midpoints/2.json" "$fixture/midpoints/3.json" \
    "$fixture/midpoints/4.json" "$fixture/midpoints/5.json"
}

test_process_tree_caps_cover_every_boundary_and_both_recoveries() (
  local -r fixture="$TEST_TMP_DIR/process-tree-observation"
  local observation=""
  local target=""
  local timing=""
  local repetition=""
  local -a boundary_files=(
    before.json baseline.json midpoints/1.json midpoints/2.json midpoints/3.json
    midpoints/4.json midpoints/5.json end.json after.json recovery-01.json recovery-02.json
  )

  mkdir -- "$fixture"
  write_process_tree_observation_fixture "$fixture"
  PROCESS_TREE_FD_ABSOLUTE_MAX=3
  PROCESS_TREE_TASK_ABSOLUTE_MAX=3
  PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX=153600
  PROCESS_TREE_FD_RECOVERY_DELTA_MAX=0
  PROCESS_TREE_TASK_RECOVERY_DELTA_MAX=0
  PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX=0
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '
    .status == "complete" and .result == "passed" and
    (.absolute.fd_count.samples | keys | length) == 11 and
    all([.absolute[], .recovery[]][]; .result == "passed") and
    .recovery.fd_count.before_min == 3 and
    .sources.repetition_midpoints == [
      "cells/fixture-cell/measurements/rep-01-midpoint/java-backend-cgroup-v2.json",
      "cells/fixture-cell/measurements/rep-02-midpoint/java-backend-cgroup-v2.json",
      "cells/fixture-cell/measurements/rep-03-midpoint/java-backend-cgroup-v2.json",
      "cells/fixture-cell/measurements/rep-04-midpoint/java-backend-cgroup-v2.json",
      "cells/fixture-cell/measurements/rep-05-midpoint/java-backend-cgroup-v2.json"
    ]
  ' <<<"$observation" >/dev/null || {
    printf 'equal full-boundary process-tree caps did not pass\n' >&2
    return 1
  }

  for target in "${boundary_files[@]}"; do
    timing="$(jq -er '.timing' "$fixture/$target")" || return 1
    repetition="$(jq -er 'if .repetition == null then "" else (.repetition | tostring) end' \
      "$fixture/$target")" || return 1
    rm -f -- "$fixture/$target"
    write_bound_cgroup_v2_snapshot_fixture "$fixture/$target" fixture-cell java-backend \
      "$timing" "$repetition" 3 4 3 3 153600 153600 2000 2001
    observation="$(process_tree_fixture_observation "$fixture")"
    jq -e '.status == "complete" and .result == "failed" and
      .absolute.fd_count.result == "failed"' <<<"$observation" >/dev/null || {
      printf 'absolute FD cap omitted required boundary: %s\n' "$target" >&2
      return 1
    }
    rm -f -- "$fixture/$target"
    write_bound_cgroup_v2_snapshot_fixture "$fixture/$target" fixture-cell java-backend \
      "$timing" "$repetition" 3 3 3 3 153600 153600 2000 2001
  done

  rm -f -- "$fixture/midpoints/3.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/midpoints/3.json" \
    fixture-cell java-backend scheduled_repetition_midpoint 3 \
    3 3 3 4 153600 153600 2000 2001
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "complete" and .result == "failed" and
    .absolute.task_count.result == "failed"' <<<"$observation" >/dev/null || return 1
  rm -f -- "$fixture/midpoints/3.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/midpoints/3.json" \
    fixture-cell java-backend scheduled_repetition_midpoint 3 \
    3 3 3 3 153600 153601 2000 2001
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "complete" and .result == "failed" and
    .absolute.rss_bytes.result == "failed"' <<<"$observation" >/dev/null || return 1
  rm -f -- "$fixture/midpoints/3.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/midpoints/3.json" \
    fixture-cell java-backend scheduled_repetition_midpoint 3 \
    3 3 3 3 153600 153600 2000 2001

  PROCESS_TREE_FD_ABSOLUTE_MAX=10
  PROCESS_TREE_FD_RECOVERY_DELTA_MAX=1
  rm -f -- "$fixture/recovery-01.json" "$fixture/recovery-02.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-01.json" \
    fixture-cell java-backend idle_recovery_01 '' 3 4 3 3 153600 153600 2100 2101
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-02.json" \
    fixture-cell java-backend idle_recovery_02 '' 3 4 3 3 153600 153600 2200 2201
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.result == "passed" and .recovery.fd_count.delta_01 == 1 and
    .recovery.fd_count.delta_02 == 1' <<<"$observation" >/dev/null || {
    printf 'recovery cap equality did not pass conservatively\n' >&2
    return 1
  }
  rm -f -- "$fixture/recovery-01.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-01.json" \
    fixture-cell java-backend idle_recovery_01 '' 3 5 3 3 153600 153600 2100 2101
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.result == "failed" and .recovery.fd_count.result == "failed" and
    .recovery.fd_count.delta_01 == 2 and .recovery.fd_count.delta_02 == 1' \
    <<<"$observation" >/dev/null || {
    printf 'recovery-2 pass hid recovery-1 failure\n' >&2
    return 1
  }
  PROCESS_TREE_FD_RECOVERY_DELTA_MAX=0
  PROCESS_TREE_TASK_ABSOLUTE_MAX=10
  PROCESS_TREE_TASK_RECOVERY_DELTA_MAX=1
  rm -f -- "$fixture/recovery-01.json" "$fixture/recovery-02.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-01.json" \
    fixture-cell java-backend idle_recovery_01 '' 3 3 3 4 153600 153600 2100 2101
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-02.json" \
    fixture-cell java-backend idle_recovery_02 '' 3 3 3 4 153600 153600 2200 2201
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.result == "passed" and .recovery.task_count.delta_01 == 1 and
    .recovery.task_count.delta_02 == 1' <<<"$observation" >/dev/null || return 1
  rm -f -- "$fixture/recovery-02.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-02.json" \
    fixture-cell java-backend idle_recovery_02 '' 3 3 3 5 153600 153600 2200 2201
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.result == "failed" and .recovery.task_count.delta_02 == 2' \
    <<<"$observation" >/dev/null || return 1

  PROCESS_TREE_TASK_RECOVERY_DELTA_MAX=0
  PROCESS_TREE_RSS_BYTES_ABSOLUTE_MAX=200000
  PROCESS_TREE_RSS_BYTES_RECOVERY_DELTA_MAX=1
  rm -f -- "$fixture/recovery-01.json" "$fixture/recovery-02.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-01.json" \
    fixture-cell java-backend idle_recovery_01 '' 3 3 3 3 153600 153601 2100 2101
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-02.json" \
    fixture-cell java-backend idle_recovery_02 '' 3 3 3 3 153600 153601 2200 2201
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.result == "passed" and .recovery.rss_bytes.delta_01 == 1 and
    .recovery.rss_bytes.delta_02 == 1' <<<"$observation" >/dev/null || return 1
  rm -f -- "$fixture/recovery-01.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/recovery-01.json" \
    fixture-cell java-backend idle_recovery_01 '' 3 3 3 3 153600 153602 2100 2101
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.result == "failed" and .recovery.rss_bytes.delta_01 == 2 and
    .recovery.rss_bytes.delta_02 == 1' <<<"$observation" >/dev/null || return 1

  mv -- "$fixture/midpoints/5.json" "$fixture/midpoints/5.missing"
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$observation" >/dev/null || {
    printf 'missing fifth midpoint was evaluated\n' >&2
    return 1
  }
  mv -- "$fixture/midpoints/5.missing" "$fixture/midpoints/5.json"
  jq '.repetition = 4' "$fixture/midpoints/5.json" >"$fixture/midpoints/5.invalid"
  mv -T -- "$fixture/midpoints/5.invalid" "$fixture/midpoints/5.json"
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$observation" >/dev/null || {
    printf 'duplicated midpoint ordinal was evaluated\n' >&2
    return 1
  }
  rm -f -- "$fixture/midpoints/5.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/midpoints/5.json" \
    fixture-cell java-backend scheduled_repetition_midpoint 5 \
    3 3 3 3 153600 153600 2300 2301
  mv -- "$fixture/midpoints/5.json" "$fixture/midpoints/5.valid"
  printf '{"schema_version":1' >"$fixture/midpoints/5.json"
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$observation" >/dev/null || {
    printf 'malformed fifth midpoint source was evaluated\n' >&2
    return 1
  }
  mv -T -- "$fixture/midpoints/5.valid" "$fixture/midpoints/5.json"
  jq '.identity.cgroup_inode = 99' "$fixture/after.json" >"$fixture/after.invalid"
  mv -T -- "$fixture/after.invalid" "$fixture/after.json"
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$observation" >/dev/null || {
    printf 'cgroup-directory identity drift was evaluated\n' >&2
    return 1
  }
  rm -f -- "$fixture/after.json"
  write_bound_cgroup_v2_snapshot_fixture "$fixture/after.json" \
    fixture-cell java-backend after '' 3 3 3 3 153600 153600 2400 2401
  mv -- "$fixture/after.json" "$fixture/after.valid"
  printf '[]' >"$fixture/after.json"
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$observation" >/dev/null || {
    printf 'malformed non-midpoint cgroup source was evaluated\n' >&2
    return 1
  }
  mv -T -- "$fixture/after.valid" "$fixture/after.json"

  cp -- "$fixture/recovery-schedule.json" "$fixture/recovery-schedule.valid"
  jq '.samples[0].idle_interval_seconds = 29' "$fixture/recovery-schedule.json" \
    >"$fixture/recovery-schedule.invalid"
  mv -T -- "$fixture/recovery-schedule.invalid" "$fixture/recovery-schedule.json"
  observation="$(process_tree_fixture_observation "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$observation" >/dev/null || {
    printf 'wrong recovery interval was evaluated\n' >&2
    return 1
  }
  mv -T -- "$fixture/recovery-schedule.valid" "$fixture/recovery-schedule.json"
  mv -- "$fixture/recovery-schedule.json" "$fixture/recovery-schedule.missing"
  if observation="$(process_tree_fixture_observation "$fixture")"; then
    printf 'missing recovery schedule did not fail artifact construction\n' >&2
    return 1
  fi
  mv -- "$fixture/recovery-schedule.missing" "$fixture/recovery-schedule.json"
)

prepare_application_cpu_fixture() {
  local -r fixture="$1"
  local cell=""
  local service=""
  local repetition=0
  local end_usage_1=0
  local end_usage_2=0
  local -a cells=(bridge-disabled getsockopt-hit unix-hit getsockopt-w3c)

  DURATION_SECONDS=2
  CONCURRENCY=1
  REPETITIONS=5
  for cell in "${cells[@]}"; do
    cell_spec "$cell" || return 1
    mkdir -p -- "$fixture/cells/$cell/measurements" \
      "$fixture/cells/$cell/cpu-measurement-baseline" \
      "$fixture/cells/$cell/cpu-measurement-end"
    for ((repetition = 1; repetition <= 5; repetition++)); do
      write_valid_benchmark_result \
        "$fixture/cells/$cell/measurements/rep-0$repetition.json" 2 10
    done
    if [[ "$cell" == bridge-disabled ]]; then
      end_usage_1=2001
      end_usage_2=2002
    else
      end_usage_1=2101
      end_usage_2=2102
    fi
    for service in obi java-backend; do
      write_bound_cgroup_v2_snapshot_fixture \
        "$fixture/cells/$cell/cpu-measurement-baseline/$service-cgroup-v2.json" \
        "$cell" "$service" cpu_measurement_baseline '' \
        3 3 3 3 153600 153600 1000 1001
      write_bound_cgroup_v2_snapshot_fixture \
        "$fixture/cells/$cell/cpu-measurement-end/$service-cgroup-v2.json" \
        "$cell" "$service" cpu_measurement_end '' \
        3 3 3 3 153600 153600 "$end_usage_1" "$end_usage_2"
    done
    write_cpu_measurement_boundary_fixture \
      "$fixture/cells/$cell/cpu-measurement-baseline" "$cell" \
      cpu_measurement_baseline '["obi","java-backend"]'
    write_cpu_measurement_boundary_fixture \
      "$fixture/cells/$cell/cpu-measurement-end" "$cell" \
      cpu_measurement_end '["obi","java-backend"]'
  done
}

test_application_cpu_gate_uses_exact_service_and_combined_cross_products() (
  local -r fixture="$TEST_TMP_DIR/application-cpu"
  local -r anchor_resource="$fixture/anchor-resource"
  local -r anchor_midpoint="$fixture/anchor-midpoint"
  local -r hit_baseline="$fixture/cells/getsockopt-hit/cpu-measurement-baseline/obi-cgroup-v2.json"
  local -r hit_end="$fixture/cells/getsockopt-hit/cpu-measurement-end/obi-cgroup-v2.json"
  local -r hit_baseline_boundary="$fixture/cells/getsockopt-hit/cpu-measurement-baseline/snapshot.json"
  local compact=""
  local gate=""
  local held_midpoint_receipt=""
  local held_midpoint_identity=""
  local held_midpoint_size=""
  local held_midpoint_digest=""
  # shellcheck disable=SC2034 # Filled through the midpoint bundle output seam.
  local midpoint_bundle=""
  local resource_bundle=""
  local large_delta=4503599627370496
  local mutated_json=""

  mkdir -- "$fixture"
  prepare_application_cpu_fixture "$fixture"
  assert_boundary_directory_path_swap_is_descriptor_anchored \
    "$fixture/cells/getsockopt-hit/cpu-measurement-baseline" \
    validated_cpu_measurement_boundary_bundle \
    "$fixture/cells/getsockopt-hit/cpu-measurement-baseline" \
    getsockopt-hit cpu_measurement_baseline
  mkdir -- "$anchor_resource" "$anchor_midpoint"
  write_resource_boundary_fixture \
    "$anchor_resource" bridge-disabled before 100 100000 101 101000
  write_bound_service_identity_fixture \
    "$anchor_resource/obi-identity.txt" obi
  write_bound_cgroup_v2_snapshot_fixture \
    "$anchor_resource/obi-cgroup-v2.json" bridge-disabled obi \
    before '' 3 3 3 3 153600 153600 1000 1001
  write_bound_service_identity_fixture \
    "$anchor_resource/java-backend-identity.txt" java-backend
  write_bound_cgroup_v2_snapshot_fixture \
    "$anchor_resource/java-backend-cgroup-v2.json" bridge-disabled java-backend \
    before '' 3 3 3 3 153600 153600 1000 1001
  assert_boundary_directory_path_swap_is_descriptor_anchored \
    "$anchor_resource" validated_resource_cgroup_boundary_bundle \
    "$anchor_resource" bridge-disabled before
  mv -- "$anchor_resource/obi-cgroup-v2.json" \
    "$anchor_resource/obi-cgroup-v2.missing"
  resource_bundle="$(validated_resource_cgroup_boundary_bundle \
    "$anchor_resource" bridge-disabled before)" || {
    printf 'resource boundary rejected missing snapshot with valid OBI identity\n' >&2
    return 1
  }
  jq -e '.snapshots.obi.status == "unavailable"' \
    <<<"$resource_bundle" >/dev/null || return 1
  mv -- "$anchor_resource/obi-cgroup-v2.missing" \
    "$anchor_resource/obi-cgroup-v2.json"
  mv -- "$anchor_resource/obi-identity.txt" \
    "$anchor_resource/obi-identity.missing"
  if validated_resource_cgroup_boundary_bundle \
    "$anchor_resource" bridge-disabled before >/dev/null 2>&1; then
    printf 'bridge-disabled resource boundary accepted a missing OBI identity\n' >&2
    return 1
  fi
  mv -- "$anchor_resource/obi-identity.missing" \
    "$anchor_resource/obi-identity.txt"
  write_bound_service_identity_fixture \
    "$anchor_midpoint/obi-identity.txt" obi
  write_bound_cgroup_v2_snapshot_fixture \
    "$anchor_midpoint/obi-cgroup-v2.json" bridge-disabled obi \
    scheduled_repetition_midpoint 1 3 3 3 3 153600 153600 1000 1001
  write_bound_service_identity_fixture \
    "$anchor_midpoint/java-backend-identity.txt" java-backend
  write_bound_cgroup_v2_snapshot_fixture \
    "$anchor_midpoint/java-backend-cgroup-v2.json" bridge-disabled java-backend \
    scheduled_repetition_midpoint 1 3 3 3 3 153600 153600 1000 1001
  write_scheduled_midpoint_boundary_fixture \
    "$anchor_midpoint" bridge-disabled 1 '["obi","java-backend"]'
  assert_boundary_directory_path_swap_is_descriptor_anchored \
    "$anchor_midpoint" validated_scheduled_midpoint_boundary_bundle \
    "$anchor_midpoint" bridge-disabled 1
  bounded_duplicate_free_json_image \
    "$anchor_midpoint/midpoint-receipt.json" "$MAX_MIDPOINT_RECEIPT_BYTES" \
    held_midpoint_receipt held_midpoint_identity held_midpoint_size \
    held_midpoint_digest || return 1
  [[ "$held_midpoint_identity" == *:* &&
    "$held_midpoint_size" =~ ^[1-9][0-9]*$ &&
    "$held_midpoint_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  validate_scheduled_midpoint_boundary \
    "$anchor_midpoint" bridge-disabled 1 midpoint_bundle \
    "$held_midpoint_receipt" || return 1
  jq '.benchmark.pid = 4243 | .benchmark.identity = "4243 4243 1011"' \
    "$anchor_midpoint/midpoint-receipt.json" \
    >"$anchor_midpoint/midpoint-receipt.json.mutated" || return 1
  mv -T -- "$anchor_midpoint/midpoint-receipt.json.mutated" \
    "$anchor_midpoint/midpoint-receipt.json" || return 1
  if validate_scheduled_midpoint_boundary \
    "$anchor_midpoint" bridge-disabled 1 midpoint_bundle \
    "$held_midpoint_receipt" >/dev/null 2>&1; then
    printf 'midpoint final validation accepted a different valid receipt than its producer held\n' >&2
    return 1
  fi
  cp -- "$hit_baseline_boundary" "$hit_baseline_boundary.valid"
  compact="$(jq -c . "$hit_baseline_boundary")" || return 1
  mutated_json="${compact/\"authority\":{\"cpu_stat\":\"authoritative\"/\"authority\":{\"cpu_stat\":\"authoritative\",\"cpu_stat\":\"authoritative\"}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$hit_baseline_boundary"
  if validate_cpu_measurement_boundary \
    "${hit_baseline_boundary%/*}" getsockopt-hit cpu_measurement_baseline; then
    printf 'CPU boundary accepted a duplicate nested authority key\n' >&2
    return 1
  fi
  mv -T -- "$hit_baseline_boundary.valid" "$hit_baseline_boundary"
  cp -- "$hit_baseline_boundary" "$hit_baseline_boundary.valid"
  jq '.cell = "unix-hit"' "$hit_baseline_boundary" >"$hit_baseline_boundary.invalid"
  mv -T -- "$hit_baseline_boundary.invalid" "$hit_baseline_boundary"
  if validate_cpu_measurement_boundary \
    "${hit_baseline_boundary%/*}" getsockopt-hit cpu_measurement_baseline; then
    printf 'CPU boundary accepted a mismatched cell binding\n' >&2
    return 1
  fi
  mv -T -- "$hit_baseline_boundary.valid" "$hit_baseline_boundary"
  cp -- "$hit_baseline_boundary" "$hit_baseline_boundary.valid"
  head -c "$((MAX_BOUNDARY_SNAPSHOT_BYTES + 1))" /dev/zero | tr '\0' x \
    >"$hit_baseline_boundary"
  if validate_cpu_measurement_boundary \
    "${hit_baseline_boundary%/*}" getsockopt-hit cpu_measurement_baseline; then
    printf 'CPU boundary accepted an artifact above its byte cap\n' >&2
    return 1
  fi
  mv -T -- "$hit_baseline_boundary.valid" "$hit_baseline_boundary"
  validate_cpu_measurement_boundary \
    "${hit_baseline_boundary%/*}" getsockopt-hit cpu_measurement_baseline
  # Leave a deliberately incompatible contract active: each CPU observation
  # must bind its own cell before validating that cell's repetitions.
  cell_spec getsockopt-w3c
  gate="$(application_cpu_gate "$fixture")"
  [[ "$CELL_SLUG" == getsockopt-w3c ]] || {
    printf 'application CPU gate leaked a per-cell workload contract\n' >&2
    return 1
  }
  jq -e '
    .status == "complete" and .result == "passed" and
    .baseline_cell == "bridge-disabled" and
    .comparison_cells == ["getsockopt-hit", "unix-hit", "getsockopt-w3c"] and
    .dimensions == ["obi", "java_backend", "combined"] and
    (.observations | length) == 4 and (.comparisons | length) == 9 and
    all(.observations[].services[];
      .usage_usec_per_successful_request == {
        numerator_usage_usec: .delta_usage_usec,
        denominator_successful_requests: .successful_requests
      } and
      .cpu_stat.usage_usec.delta == .delta_usage_usec and
      .cpu_stat.user_usec.delta >= 0 and .cpu_stat.system_usec.delta >= 0) and
    all(.comparisons[];
      .result == "passed" and .maximum_regression_percent == 10 and
      .exact_cross_products.candidate_cpu_times_baseline_requests_times_100 ==
        .exact_cross_products.baseline_cpu_times_candidate_requests_times_110) and
    .excluded_cells == {
      uninstrumented: "no_official_agent",
      getsockopt_helper_idle:
        "direct_java_workload_is_not_comparable_to_the_apache_baseline"
    } and .primary_cgroupsockopt_program_cpu == "not_collected"
  ' <<<"$gate" >/dev/null || {
    printf 'exact 10-percent OBI/Java/combined CPU boundary did not pass\n' >&2
    return 1
  }

  rm -f -- "$hit_end"
  write_bound_cgroup_v2_snapshot_fixture "$hit_end" getsockopt-hit obi \
    cpu_measurement_end '' 3 3 3 3 153600 153600 2102 2103
  gate="$(application_cpu_gate "$fixture")"
  jq -e '
    .status == "complete" and .result == "failed" and
    ([.comparisons[] | select(.cell == "getsockopt-hit" and .result == "failed") |
      .dimension] | sort) == ["combined", "obi"] and
    (.comparisons[] | select(.cell == "getsockopt-hit" and .dimension == "java_backend") |
      .result == "passed")
  ' <<<"$gate" >/dev/null || {
    printf 'one-usec CPU regression above 10 percent did not fail exact dimensions\n' >&2
    return 1
  }

  rm -f -- "$hit_end"
  write_bound_cgroup_v2_snapshot_fixture "$hit_end" getsockopt-hit obi \
    cpu_measurement_end '' 3 3 3 3 153600 153600 1000 1001
  gate="$(application_cpu_gate "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated" and
    (.observations[] | select(.cell == "getsockopt-hit" and .service == "obi") |
      .reason == "dedicated_cpu_counter_reset_overlap_or_authority_drift")' \
    <<<"$gate" >/dev/null || {
    printf 'CPU reset/overlap was evaluated\n' >&2
    return 1
  }

  rm -f -- "$hit_end"
  write_bound_cgroup_v2_snapshot_fixture "$hit_end" getsockopt-hit obi \
    cpu_measurement_end '' 3 3 3 3 153600 153600 2101 2102
  jq '
    .passes[0].cpu_stat = {usage_usec: 2101, user_usec: 900, system_usec: 1201} |
    .passes[1].cpu_stat = {usage_usec: 2102, user_usec: 901, system_usec: 1201} |
    .envelope.cpu_user_usec = {min: 900, max: 901} |
    .envelope.cpu_system_usec = {min: 1201, max: 1201}
  ' "$hit_end" >"$hit_end.invalid"
  mv -T -- "$hit_end.invalid" "$hit_end"
  validate_bound_cgroup_v2_snapshot_schema "$hit_end" || return 1
  gate="$(application_cpu_gate "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated" and
    (.observations[] | select(.cell == "getsockopt-hit" and .service == "obi") |
      .reason == "dedicated_cpu_counter_reset_overlap_or_authority_drift")' \
    <<<"$gate" >/dev/null || {
    printf 'CPU user counter reset was evaluated from monotonic usage\n' >&2
    return 1
  }

  rm -f -- "$hit_end"
  write_bound_cgroup_v2_snapshot_fixture "$hit_end" getsockopt-hit obi \
    cpu_measurement_end '' 3 3 3 3 153600 153600 2101 2102
  jq '
    .passes[0].cpu_stat = {usage_usec: 1000, user_usec: 500, system_usec: 500} |
    .passes[1].cpu_stat = {usage_usec: 1001, user_usec: 501, system_usec: 500} |
    .envelope.cpu_user_usec = {min: 500, max: 501} |
    .envelope.cpu_system_usec = {min: 500, max: 500}
  ' "$hit_baseline" >"$hit_baseline.invalid"
  mv -T -- "$hit_baseline.invalid" "$hit_baseline"
  validate_bound_cgroup_v2_snapshot_schema "$hit_baseline" || return 1
  gate="$(application_cpu_gate "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated" and
    (.observations[] | select(.cell == "getsockopt-hit" and .service == "obi") |
      .reason == "dedicated_cpu_counter_reset_overlap_or_authority_drift")' \
    <<<"$gate" >/dev/null || {
    printf 'CPU system counter reset was evaluated from monotonic usage\n' >&2
    return 1
  }
  rm -f -- "$hit_baseline"
  write_bound_cgroup_v2_snapshot_fixture "$hit_baseline" getsockopt-hit obi \
    cpu_measurement_baseline '' 3 3 3 3 153600 153600 1000 1001

  rm -f -- "$hit_end"
  write_bound_cgroup_v2_snapshot_fixture "$hit_end" getsockopt-hit obi \
    cpu_measurement_end '' 3 3 3 3 153600 153600 2101 2102 99
  gate="$(application_cpu_gate "$fixture")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$gate" >/dev/null || {
    printf 'CPU cgroup authority drift was evaluated\n' >&2
    return 1
  }

  rm -f -- "$hit_end" \
    "$fixture/cells/getsockopt-hit/cpu-measurement-end/java-backend-cgroup-v2.json"
  write_bound_cgroup_v2_snapshot_fixture "$hit_end" getsockopt-hit obi \
    cpu_measurement_end '' 3 3 3 3 153600 153600 \
    "$((large_delta + 1001))" "$((large_delta + 1002))"
  write_bound_cgroup_v2_snapshot_fixture \
    "$fixture/cells/getsockopt-hit/cpu-measurement-end/java-backend-cgroup-v2.json" \
    getsockopt-hit java-backend cpu_measurement_end '' 3 3 3 3 153600 153600 \
    "$((large_delta + 1001))" "$((large_delta + 1002))"
  if application_cpu_gate "$fixture" >/dev/null 2>&1; then
    printf 'combined CPU delta above the JSON-safe exact bound was accepted\n' >&2
    return 1
  fi

  [[ "$(decimal_multiply 9007199254740991 110)" == 990791918021509010 &&
    "$(decimal_multiply 990791918021509010 9007199254740991)" == \
      8924260225606733004952954522828910 ]] || {
    printf 'unsigned decimal CPU cross multiplication lost precision\n' >&2
    return 1
  }
)

prepare_poc_gate_fixture() {
  local -r output="$1"
  local cell=""
  local service=""
  local cell_dir=""
  local pid=100
  local obi_pid=""
  local repetition=0
  local repetition_label=""
  local timing=""
  local directory=""
  local services_json=""
  local -a services=()
  local -a process_tree_services=()

  OUTPUT_DIR="$output"
  OUTPUT_READY=true
  REPETITIONS=5
  DURATION_SECONDS=2
  CONCURRENCY=1
  set_valid_process_tree_caps
  mkdir -p -- "$OUTPUT_DIR/cells"
  OUTPUT_DIR_IDENTITY="$(stat --format '%d:%i:%u:%g:%a' -- \
    "$OUTPUT_DIR")" || return 1
  for cell in "${CORE_CELLS[@]}"; do
    obi_pid=""
    write_variance_fixture_cell "$cell" 200 0 2000000000 100 100 100 100
    cell_spec "$cell" || return 1
    cell_dir="$OUTPUT_DIR/cells/$cell"
    mkdir -- "$cell_dir/resources-before" \
      "$cell_dir/cpu-measurement-baseline" \
      "$cell_dir/cpu-measurement-end" \
      "$cell_dir/resources-after-load" \
      "$cell_dir/resources-idle-recovery-01" \
      "$cell_dir/resources-idle-recovery-02"
    services=(trace-receiver apache-proxy java-backend)
    process_tree_services=(java-backend)
    if [[ "$CELL_REQUIRES_OBI" == true ]]; then
      services+=(obi)
      process_tree_services=(obi java-backend)
    fi
    services_json="$(jq -cn '$ARGS.positional' --args "${process_tree_services[@]}")" || return 1
    write_resource_boundary_fixture \
      "$cell_dir/resources-before" "$cell" before 900 900000 901 901000
    write_resource_boundary_fixture \
      "$cell_dir/resources-after-load" "$cell" after 990 990000 991 991000
    write_resource_boundary_fixture \
      "$cell_dir/resources-idle-recovery-01" "$cell" idle_recovery_01 \
      1030 1030000 1031 1031000
    write_resource_boundary_fixture \
      "$cell_dir/resources-idle-recovery-02" "$cell" idle_recovery_02 \
      1061 1061000 1062 1062000
    for service in "${services[@]}"; do
      write_proc_growth_fixture \
        "$cell_dir/resources-before/$service-proc.txt" "$pid" 20 8
      write_proc_growth_fixture \
        "$cell_dir/resources-idle-recovery-02/$service-proc.txt" "$pid" 20 8
      if [[ "$service" == "obi" ]]; then
        obi_pid="$pid"
      fi
      ((pid += 1))
    done
    if [[ "$CELL_REQUIRES_OBI" == true ]]; then
      [[ "$obi_pid" =~ ^[1-9][0-9]*$ ]] || return 1
      write_bpf_fd_ownership_fixture \
        "$cell_dir/resources-before/obi-bpf-fd-ownership.txt" 41 71 \
        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        "$obi_pid" "$((obi_pid * 10))"
      write_bpf_fd_ownership_fixture \
        "$cell_dir/resources-idle-recovery-02/obi-bpf-fd-ownership.txt" 41 71 \
        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        "$obi_pid" "$((obi_pid * 10))"
      if [[ "$cell" == "bridge-disabled" ]]; then
        write_java_map_growth_fixture "$cell_dir/resources-before/obi-metrics.prom" 0 1
        write_java_map_growth_fixture "$cell_dir/resources-idle-recovery-02/obi-metrics.prom" 0 1
      else
        write_java_map_growth_fixture "$cell_dir/resources-before/obi-metrics.prom" 2 10000
        write_java_map_growth_fixture "$cell_dir/resources-idle-recovery-02/obi-metrics.prom" 1 10000
      fi
    fi
    for service in "${process_tree_services[@]}"; do
      for directory in resources-before resources-after-load \
        resources-idle-recovery-01 resources-idle-recovery-02; do
        case "$directory" in
          resources-before) timing=before ;;
          resources-after-load) timing=after ;;
          resources-idle-recovery-01) timing=idle_recovery_01 ;;
          resources-idle-recovery-02) timing=idle_recovery_02 ;;
        esac
        write_bound_service_identity_fixture \
          "$cell_dir/$directory/$service-identity.txt" "$service"
        write_bound_cgroup_v2_snapshot_fixture \
          "$cell_dir/$directory/$service-cgroup-v2.json" "$cell" "$service" \
          "$timing" '' 8 8 4 4 1048576 1048576 3000 3001
      done
      write_bound_cgroup_v2_snapshot_fixture \
        "$cell_dir/cpu-measurement-baseline/$service-cgroup-v2.json" \
        "$cell" "$service" cpu_measurement_baseline '' \
        8 8 4 4 1048576 1048576 1000 1001
      write_bound_cgroup_v2_snapshot_fixture \
        "$cell_dir/cpu-measurement-end/$service-cgroup-v2.json" \
        "$cell" "$service" cpu_measurement_end '' \
        8 8 4 4 1048576 1048576 2001 2002
      for ((repetition = 1; repetition <= 5; repetition++)); do
        printf -v repetition_label 'rep-%02d' "$repetition"
        mkdir -p -- "$cell_dir/measurements/$repetition_label-midpoint"
        write_bound_cgroup_v2_snapshot_fixture \
          "$cell_dir/measurements/$repetition_label-midpoint/$service-cgroup-v2.json" \
          "$cell" "$service" scheduled_repetition_midpoint "$repetition" \
          8 8 4 4 1048576 1048576 3000 3001
      done
    done
    write_cpu_measurement_boundary_fixture \
      "$cell_dir/cpu-measurement-baseline" "$cell" \
      cpu_measurement_baseline "$services_json"
    write_cpu_measurement_boundary_fixture \
      "$cell_dir/cpu-measurement-end" "$cell" cpu_measurement_end "$services_json"
    for ((repetition = 1; repetition <= 5; repetition++)); do
      printf -v repetition_label 'rep-%02d' "$repetition"
      write_scheduled_midpoint_boundary_fixture \
        "$cell_dir/measurements/$repetition_label-midpoint" \
        "$cell" "$repetition" "$services_json"
    done
    jq -n --arg cell "$cell" '{
      schema_version: 1, kind: "ordered-idle-recovery-schedule", status: "complete",
      cell: $cell, required_consecutive_samples: 2,
      load_activity_between_samples: false,
      started: {wall_epoch_seconds: 1000, monotonic_milliseconds: 1000000},
      samples: [
        {
          ordinal: 1, idle_interval_seconds: 30, ordering: "after_postload_sentinel",
          sleep: {
            started: {wall_epoch_seconds: 1000, monotonic_milliseconds: 1000000},
            ended: {wall_epoch_seconds: 1030, monotonic_milliseconds: 1030000},
            elapsed_wall_seconds: 30, elapsed_monotonic_milliseconds: 30000
          },
          capture: {
            started: {wall_epoch_seconds: 1030, monotonic_milliseconds: 1030000},
            ended: {wall_epoch_seconds: 1031, monotonic_milliseconds: 1031000},
            resource_snapshot: "resources-idle-recovery-01"
          }
        },
        {
          ordinal: 2, idle_interval_seconds: 30,
          ordering: "after_recovery_01_without_intervening_workload",
          sleep: {
            started: {wall_epoch_seconds: 1031, monotonic_milliseconds: 1031000},
            ended: {wall_epoch_seconds: 1061, monotonic_milliseconds: 1061000},
            elapsed_wall_seconds: 30, elapsed_monotonic_milliseconds: 30000
          },
          capture: {
            started: {wall_epoch_seconds: 1061, monotonic_milliseconds: 1061000},
            ended: {wall_epoch_seconds: 1062, monotonic_milliseconds: 1062000},
            resource_snapshot: "resources-idle-recovery-02"
          }
        }
      ],
      completed: {wall_epoch_seconds: 1062, monotonic_milliseconds: 1062000}
    }' >"$cell_dir/recovery-schedule.json"
    # The held Java runtime roster is exact across all six core cells even
    # though the sampled-allocation comparison itself uses only four.
    write_sampled_allocation_fixture "$cell"
  done
  write_variance_summary
  # shellcheck disable=SC2034 # Consumed dynamically by manifest_json.
  STARTED_AT=2026-08-21T00:00:00Z
  write_manifest
}

test_application_resource_gates_project_unavailable_cgroup_snapshots() (
  local -r fixture="$TEST_TMP_DIR/application-resource-unavailable"
  local -r resource_directory="$fixture/cells/getsockopt-hit/resources-before"
  local -r resource_snapshot="$resource_directory/obi-cgroup-v2.json"
  local -r resource_identity="$resource_directory/obi-identity.txt"
  local -r cpu_directory="$fixture/cells/getsockopt-hit/cpu-measurement-baseline"
  local -r cpu_snapshot="$cpu_directory/obi-cgroup-v2.json"
  local gate=""
  local bundle=""
  local unavailable_value=""

  reset_options
  prepare_poc_gate_fixture "$fixture"
  unavailable_value="$(unavailable_bound_cgroup_v2_snapshot_json_value \
    getsockopt-hit obi before)" || return 1

  cp -- "$resource_snapshot" "$resource_snapshot.valid"
  printf '%s\n' "$unavailable_value" >"$resource_snapshot.unavailable"
  mv -T -- "$resource_snapshot.unavailable" "$resource_snapshot"
  gate="$(application_resource_gates "$fixture" 2>/dev/null)" || {
    printf 'canonical resource gates aborted on unavailable cgroup with valid identity\n' >&2
    return 1
  }
  jq -e '.process_tree.status == "partial" and
    .process_tree.result == "not_evaluated" and
    .application_cpu.status == "complete"' <<<"$gate" >/dev/null || {
    printf 'unavailable resource cgroup did not project partial/not_evaluated\n' >&2
    return 1
  }
  mv -T -- "$resource_snapshot.valid" "$resource_snapshot"

  mv -- "$resource_snapshot" "$resource_snapshot.missing"
  gate="$(application_resource_gates "$fixture" 2>/dev/null)" || {
    printf 'canonical resource gates aborted on a missing cgroup snapshot\n' >&2
    return 1
  }
  jq -e '.process_tree.status == "partial" and
    .process_tree.result == "not_evaluated"' <<<"$gate" >/dev/null || {
    printf 'missing resource cgroup did not project partial/not_evaluated\n' >&2
    return 1
  }
  mv -- "$resource_snapshot.missing" "$resource_snapshot"

  cp -- "$resource_snapshot" "$resource_snapshot.valid"
  printf '{"schema_version":1' >"$resource_snapshot"
  gate="$(application_resource_gates "$fixture" 2>/dev/null)" || {
    printf 'canonical resource gates aborted on a malformed cgroup snapshot\n' >&2
    return 1
  }
  jq -e '.process_tree.status == "partial" and
    .process_tree.result == "not_evaluated"' <<<"$gate" >/dev/null || {
    printf 'malformed resource cgroup did not project partial/not_evaluated\n' >&2
    return 1
  }
  mv -T -- "$resource_snapshot.valid" "$resource_snapshot"

  unavailable_value="$(unavailable_bound_cgroup_v2_snapshot_json_value \
    getsockopt-hit obi cpu_measurement_baseline)" || return 1
  cp -- "$cpu_snapshot" "$cpu_snapshot.valid"
  printf '%s\n' "$unavailable_value" >"$cpu_snapshot.unavailable"
  mv -T -- "$cpu_snapshot.unavailable" "$cpu_snapshot"
  validate_cpu_measurement_boundary "$cpu_directory" getsockopt-hit \
    cpu_measurement_baseline bundle || {
    printf 'CPU boundary rejected unavailable cgroup with valid identity\n' >&2
    return 1
  }
  jq -e '.snapshots.obi.status == "unavailable"' <<<"$bundle" >/dev/null || return 1
  mv -T -- "$cpu_snapshot.valid" "$cpu_snapshot"

  cp -- "$resource_snapshot" "$resource_snapshot.valid"
  cp -- "$resource_identity" "$resource_identity.valid"
  unavailable_value="$(unavailable_bound_cgroup_v2_snapshot_json_value \
    getsockopt-hit obi before)" || return 1
  printf '%s\n' "$unavailable_value" >"$resource_snapshot.unavailable"
  mv -T -- "$resource_snapshot.unavailable" "$resource_snapshot"
  printf 'status=unavailable\n' >"$resource_identity"
  validated_resource_cgroup_boundary_bundle \
    "$resource_directory" getsockopt-hit before >/dev/null || {
    printf 'resource boundary rejected exact unavailable identity sentinel\n' >&2
    return 1
  }
  printf 'status=unavailable' >"$resource_identity"
  if validated_resource_cgroup_boundary_bundle \
    "$resource_directory" getsockopt-hit before >/dev/null 2>&1; then
    printf 'resource boundary accepted unavailable identity without final newline\n' >&2
    return 1
  fi
  printf 'status=unavailable\nextra' >"$resource_identity"
  if validated_resource_cgroup_boundary_bundle \
    "$resource_directory" getsockopt-hit before >/dev/null 2>&1; then
    printf 'resource boundary accepted unavailable identity with extra bytes\n' >&2
    return 1
  fi
  printf 'status=invalid\n' >"$resource_identity"
  if validated_resource_cgroup_boundary_bundle \
    "$resource_directory" getsockopt-hit before >/dev/null 2>&1; then
    printf 'resource boundary accepted malformed identity for unavailable cgroup\n' >&2
    return 1
  fi
  mv -T -- "$resource_identity.valid" "$resource_identity"
  mv -T -- "$resource_snapshot.valid" "$resource_snapshot"
)

publish_held_poc_gate_fixture() {
  local manifest_value=""

  [[ -n "$POC_GATE_HELD_VALUE" &&
    "$POC_GATE_HELD_SIZE" == "${#POC_GATE_HELD_VALUE}" &&
    "$POC_GATE_HELD_SHA256" == "$(json_value_sha256 "$POC_GATE_HELD_VALUE")" ]] || return 1
  manifest_value="$(manifest_json failed)" || return 1
  manifest_value="$(printf '%s' "$manifest_value" | jq -ceS .)" || return 1
  publish_exact_json_value "$OUTPUT_DIR/manifest.json" \
    "$manifest_value" "$MAX_MANIFEST_BYTES" || return 1
  publish_exact_json_value "$OUTPUT_DIR/poc-gates.json" \
    "$POC_GATE_HELD_VALUE" "$MAX_POC_GATE_BYTES" || return 1
  validate_poc_gate_schema "$OUTPUT_DIR/poc-gates.json"
}

write_valid_sentinel() {
  local -r output="$1"
  local -r assertion_mode="$2"

  jq -n \
    --arg assertion_mode "$assertion_mode" \
    --arg tls "$TLS_PROTOCOL" \
    --argjson requests "$PREFLIGHT_REQUESTS" \
    --argjson seed "$SEED" '
      {
        status: "passed", scenario: "concurrency", assertion_mode: $assertion_mode,
        request_count: $requests, seed: $seed,
        cases: [range(0; $requests) | {response: {tls_protocol: $tls}}]
      }
    ' >"$output"
}

write_valid_w3c_sentinel() {
  local -r output="$1"

  fake_w3c_sentinel_result "$PREFLIGHT_REQUESTS" "$SEED" "$TLS_PROTOCOL" >"$output"
}

write_valid_java_diagnostics_snapshot() {
  local -r output="$1"
  local -r discard_standard="$2"
  local -r take_valid="$3"
  local -r discard_valid="${4:-0}"
  local -r take_missing="${5:-0}"

  fake_java_diagnostics_snapshot \
    "$discard_standard" "$take_valid" "$discard_valid" "$take_missing" >"$output"
}

test_json_validators_require_one_document() {
  local -r benchmark_result="$TEST_TMP_DIR/benchmark-result.json"
  local -r sentinel_result="$TEST_TMP_DIR/sentinel-result.json"
  local -r w3c_sentinel_result="$TEST_TMP_DIR/w3c-sentinel-result.json"
  local -r under_run_result="$TEST_TMP_DIR/under-run-result.json"
  local -r overrun_result="$TEST_TMP_DIR/overrun-result.json"
  local -r drained_result="$TEST_TMP_DIR/drained-result.json"
  local -r non_numeric_metric_result="$TEST_TMP_DIR/non-numeric-metric-result.json"
  local -r fractional_metric_result="$TEST_TMP_DIR/fractional-metric-result.json"
  local -r histogram_result="$TEST_TMP_DIR/histogram-result.json"
  local -r invalid_histogram_result="$TEST_TMP_DIR/invalid-histogram-result.json"
  local -r invalid_benchmark_result="$TEST_TMP_DIR/invalid-benchmark-result.json"
  local -r oversized_result="$TEST_TMP_DIR/oversized-benchmark-result.json"
  local -r truncated_result="$TEST_TMP_DIR/truncated-benchmark-result.json"
  local mutation=""

  reset_options
  cell_spec getsockopt-hit
  write_valid_benchmark_result "$benchmark_result" 2
  validate_benchmark_result "$benchmark_result" 2 || {
    printf 'valid benchmark result was rejected\n' >&2
    return 1
  }
  jq '
    .successful_requests = 4 |
    .throughput_per_second = 2 |
    .latency = {
      p50_nanos: 1,
      p95_nanos: 3,
      p99_nanos: 3,
      histogram_encoding: "sorted_rle_nanos_v1",
      histogram: [
        {nanos: 1, count: 2},
        {nanos: 2, count: 1},
        {nanos: 3, count: 1}
      ]
    }
  ' "$benchmark_result" >"$histogram_result"
  validate_benchmark_result "$histogram_result" 2 || {
    printf 'benchmark validator rejected a recomputable sorted RLE histogram\n' >&2
    return 1
  }
  for mutation in top_schema run_schema timestamp_epoch timestamp_offset \
    timestamp_noncanonical timestamp_invalid timestamp_order throughput; do
    case "$mutation" in
      top_schema)
        jq '.unexpected = true' "$histogram_result" >"$invalid_benchmark_result"
        ;;
      run_schema)
        jq '.latency.histogram[1].unexpected = true' \
          "$histogram_result" >"$invalid_benchmark_result"
        ;;
      timestamp_epoch)
        jq '.started_at = "1970-01-01T00:00:00Z"' \
          "$histogram_result" >"$invalid_benchmark_result"
        ;;
      timestamp_offset)
        jq '.started_at = "2026-08-20T00:00:00+00:00"' \
          "$histogram_result" >"$invalid_benchmark_result"
        ;;
      timestamp_noncanonical)
        jq '.started_at = "2026-08-20T00:00:00.000000010Z"' \
          "$histogram_result" >"$invalid_benchmark_result"
        ;;
      timestamp_invalid)
        jq '.started_at = "2026-02-30T00:00:00Z"' \
          "$histogram_result" >"$invalid_benchmark_result"
        ;;
      timestamp_order)
        jq '.started_at = "2026-08-20T00:00:03Z"' \
          "$histogram_result" >"$invalid_benchmark_result"
        ;;
      throughput)
        jq '.throughput_per_second += 0.000001' \
          "$histogram_result" >"$invalid_benchmark_result"
        ;;
    esac
    if validate_benchmark_result "$invalid_benchmark_result" 2 >/dev/null 2>&1; then
      printf 'benchmark validator accepted invalid %s evidence\n' "$mutation" >&2
      return 1
    fi
  done
  jq '.seed = 9007199254740992' \
    "$histogram_result" >"$invalid_benchmark_result"
  if validate_benchmark_result \
    "$invalid_benchmark_result" 2 9007199254740992 >/dev/null 2>&1; then
    printf 'benchmark validator accepted an inexact JSON integer seed\n' >&2
    return 1
  fi
  for mutation in top latency histogram_runs; do
    case "$mutation" in
      top)
        awk '
          {print}
          !duplicated && /"status": "passed",/ {print; duplicated = 1}
          END {if (!duplicated) exit 1}
        ' "$histogram_result" >"$invalid_benchmark_result"
        ;;
      latency)
        awk '
          {print}
          !duplicated && /"p50_nanos": 1,/ {print; duplicated = 1}
          END {if (!duplicated) exit 1}
        ' "$histogram_result" >"$invalid_benchmark_result"
        ;;
      histogram_runs)
        awk '
          {print}
          /"count":/ {print; duplicated += 1}
          END {if (duplicated != 3) exit 1}
        ' "$histogram_result" >"$invalid_benchmark_result"
        ;;
    esac
    if validate_benchmark_result "$invalid_benchmark_result" 2 >/dev/null 2>&1; then
      printf 'benchmark validator accepted duplicate %s object keys\n' "$mutation" >&2
      return 1
    fi
  done
  for mutation in count order percentile schema range; do
    case "$mutation" in
      count) jq '.latency.histogram[0].count = 1' "$histogram_result" >"$invalid_histogram_result" ;;
      order) jq '.latency.histogram |= [.[1], .[0], .[2]]' "$histogram_result" >"$invalid_histogram_result" ;;
      percentile) jq '.latency.p95_nanos = 2' "$histogram_result" >"$invalid_histogram_result" ;;
      schema) jq '.latency.unbounded_samples = []' "$histogram_result" >"$invalid_histogram_result" ;;
      range)
        jq --argjson too_large "$(((2 + MEASUREMENT_OVERRUN_TOLERANCE_SECONDS) * 1000000000 + 1))" '
          .latency.histogram[2].nanos = $too_large |
          .latency.p95_nanos = $too_large |
          .latency.p99_nanos = $too_large
        ' "$histogram_result" >"$invalid_histogram_result"
        ;;
    esac
    if validate_benchmark_result "$invalid_histogram_result" 2 >/dev/null 2>&1; then
      printf 'benchmark validator accepted invalid histogram %s evidence\n' "$mutation" >&2
      return 1
    fi
  done
  head -c 100 "$histogram_result" >"$truncated_result"
  if validate_benchmark_result "$truncated_result" 2 >/dev/null 2>&1; then
    printf 'benchmark validator accepted a truncated client result\n' >&2
    return 1
  fi
  cp -- "$histogram_result" "$oversized_result"
  truncate -s "$((MAX_BENCHMARK_RESULT_BYTES + 1))" "$oversized_result"
  if validate_benchmark_result "$oversized_result" 2 >/dev/null 2>&1; then
    printf 'benchmark validator accepted an oversized client result\n' >&2
    return 1
  fi
  write_valid_benchmark_result "$drained_result" 2 1 0 3000000000
  validate_benchmark_result "$drained_result" 2 || {
    printf 'valid benchmark result with bounded in-flight drain was rejected\n' >&2
    return 1
  }
  jq --argjson elapsed_nanos 1999999999 \
    '.traffic_elapsed_nanos = $elapsed_nanos' "$benchmark_result" >"$under_run_result"
  if validate_benchmark_result "$under_run_result" 2 >/dev/null 2>&1; then
    printf 'benchmark validator accepted a result shorter than its requested duration\n' >&2
    return 1
  fi
  jq --argjson elapsed_nanos "$((
    (2 + MEASUREMENT_OVERRUN_TOLERANCE_SECONDS) * 1000000000 + 1
  ))" '.traffic_elapsed_nanos = $elapsed_nanos' "$benchmark_result" >"$overrun_result"
  if validate_benchmark_result "$overrun_result" 2 >/dev/null 2>&1; then
    printf 'benchmark validator accepted an overrun beyond its bounded drain tolerance\n' >&2
    return 1
  fi
  jq '
    .throughput_per_second = "x" |
    .latency = {p50_nanos: "x", p95_nanos: "y", p99_nanos: "z"}
  ' "$benchmark_result" >"$non_numeric_metric_result"
  if validate_benchmark_result "$non_numeric_metric_result" 2 >/dev/null 2>&1; then
    printf 'benchmark validator accepted non-numeric throughput or latency metrics\n' >&2
    return 1
  fi
  jq '
    .traffic_elapsed_nanos = 2000000000.5 |
    .latency = {p50_nanos: 1.5, p95_nanos: 1.5, p99_nanos: 1.5}
  ' "$benchmark_result" >"$fractional_metric_result"
  if validate_benchmark_result "$fractional_metric_result" 2 >/dev/null 2>&1; then
    printf 'benchmark validator accepted fractional nanosecond metrics\n' >&2
    return 1
  fi
  printf '\n' >>"$benchmark_result"
  write_valid_benchmark_result "$TEST_TMP_DIR/second-document.json" 2
  awk '1' "$TEST_TMP_DIR/second-document.json" >>"$benchmark_result"
  if validate_benchmark_result "$benchmark_result" 2 >/dev/null 2>&1; then
    printf 'benchmark validator accepted multiple JSON documents\n' >&2
    return 1
  fi
  write_valid_sentinel "$sentinel_result" bridge
  validate_concurrency_sentinel "$sentinel_result" "" || {
    printf 'valid bridge sentinel was rejected\n' >&2
    return 1
  }
  if validate_concurrency_sentinel "$sentinel_result" disabled >/dev/null 2>&1; then
    printf 'sentinel validator accepted the wrong assertion mode\n' >&2
    return 1
  fi
  (
    reset_options
    cell_spec getsockopt-w3c
    write_valid_benchmark_result "$benchmark_result" 2
    validate_benchmark_result "$benchmark_result" 2 || {
      printf 'valid W3C benchmark result was rejected\n' >&2
      return 1
    }
    write_valid_w3c_sentinel "$w3c_sentinel_result"
    validate_w3c_sentinel "$w3c_sentinel_result" || {
      printf 'valid W3C sentinel was rejected\n' >&2
      return 1
    }
    jq '
      .cases[0].trace.spans[2].parent_span_id = "0000000000000002"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.invalid"
    if validate_w3c_sentinel "$w3c_sentinel_result.invalid" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a Java span with the wrong W3C parent\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans += [.cases[0].trace.spans[2]]
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.duplicate-java"
    if validate_w3c_sentinel "$w3c_sentinel_result.duplicate-java" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted duplicate Java server spans\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans[2].flags = 1
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.local-parent"
    if validate_w3c_sentinel "$w3c_sentinel_result.local-parent" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a Java span without remote-parent flags\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans[0].flags = 0
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.apache-local-parent"
    if validate_w3c_sentinel "$w3c_sentinel_result.apache-local-parent" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted an Apache span with the wrong W3C flags\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.dropped_spans = 1
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.dropped-spans"
    if validate_w3c_sentinel "$w3c_sentinel_result.dropped-spans" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a trace with dropped spans\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans[0].attributes["http.request.header.x_obi_demo_id"] = "other-marker"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.conflicting-marker-alias"
    if validate_w3c_sentinel "$w3c_sentinel_result.conflicting-marker-alias" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted conflicting marker aliases\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans[1].parent_span_id = "00000000000000ff"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.disconnected-apache-client"
    if validate_w3c_sentinel "$w3c_sentinel_result.disconnected-apache-client" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a disconnected Apache client span\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans[0].span_id = .cases[0].request.w3c_parent_span_id |
      .cases[0].trace.spans[0].parent_span_id = .cases[0].request.w3c_parent_span_id |
      .cases[0].trace.spans[1].parent_span_id = .cases[0].request.w3c_parent_span_id
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.apache-parent-cycle"
    if validate_w3c_sentinel "$w3c_sentinel_result.apache-parent-cycle" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted an Apache ancestor parent cycle\n' >&2
      return 1
    fi
    jq '
      .cases[0].request.w3c_trace_id += "\n" |
      .cases[0].request.w3c_parent_span_id += "\n" |
      .cases[0].trace.spans[] |= (
        .trace_id += "\n" |
        .span_id += "\n" |
        if has("parent_span_id") then .parent_span_id += "\n" else . end
      )
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.trailing-newline-identifiers"
    if validate_w3c_sentinel "$w3c_sentinel_result.trailing-newline-identifiers" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted identifiers with trailing newlines\n' >&2
      return 1
    fi
    jq '
      .cases[0].request.marker += "\n" |
      .cases[0].response.marker += "\n" |
      .cases[0].trace.marker += "\n" |
      .cases[0].trace.spans[].attributes["http.request.header.x-obi-demo-id"] += "\n"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.trailing-newline-marker"
    if validate_w3c_sentinel "$w3c_sentinel_result.trailing-newline-marker" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a marker with a trailing newline\n' >&2
      return 1
    fi
    jq '
      .cases[1].trace.spans[0].parent_span_id = "0000000000000000\n"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.trailing-newline-root"
    if validate_w3c_sentinel "$w3c_sentinel_result.trailing-newline-root" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a malformed-W3C root with a trailing newline\n' >&2
      return 1
    fi
    jq '
      .cases[0].request.invalid_w3c = true
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.valid-marked-invalid"
    if validate_w3c_sentinel "$w3c_sentinel_result.valid-marked-invalid" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a valid W3C case marked invalid\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans[0].attributes["url.path"] = "/unexpected"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.unexpected-endpoint"
    if validate_w3c_sentinel "$w3c_sentinel_result.unexpected-endpoint" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted an Apache span for the wrong endpoint\n' >&2
      return 1
    fi
    jq '
      .cases[0].trace.spans[1].attributes["url.full"] = "https://localhost:18443/api/echo#bad%zz"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.fragment-endpoint"
    if validate_w3c_sentinel "$w3c_sentinel_result.fragment-endpoint" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted an endpoint attribute with a fragment\n' >&2
      return 1
    fi
    jq '
      .cases[1].trace.spans[2].parent_span_id = "0000000000000006"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.fallback-wrong-parent"
    if validate_w3c_sentinel "$w3c_sentinel_result.fallback-wrong-parent" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a malformed-W3C fallback unrelated to Apache\n' >&2
      return 1
    fi
    jq '
      .cases[1].trace.spans[0].parent_span_id = "00000000000000ff"
    ' "$w3c_sentinel_result" >"$w3c_sentinel_result.fallback-external-parent"
    if validate_w3c_sentinel "$w3c_sentinel_result.fallback-external-parent" >/dev/null 2>&1; then
      printf 'W3C sentinel validator accepted a malformed-W3C Apache server with an external parent\n' >&2
      return 1
    fi
  )
  (
    reset_options
    cell_spec getsockopt-helper-idle
    write_valid_benchmark_result "$benchmark_result" 2
    validate_benchmark_result "$benchmark_result" 2 || {
      printf 'valid direct-Java HTTPS benchmark result was rejected\n' >&2
      return 1
    }
    jq '.tls_verification = "not_applicable"' "$benchmark_result" >"$benchmark_result.tls"
    if validate_benchmark_result "$benchmark_result.tls" 2 >/dev/null 2>&1; then
      printf 'helper-idle validator accepted an unverified HTTPS result\n' >&2
      return 1
    fi
    jq '.base_url = "http://127.0.0.1:18080"' "$benchmark_result" >"$benchmark_result.http"
    if validate_benchmark_result "$benchmark_result.http" 2 >/dev/null 2>&1; then
      printf 'helper-idle validator accepted an Apache workload result\n' >&2
      return 1
    fi
  )
}

test_variance_summary_records_ordered_per_cell_statistics() (
  local -r output="$TEST_TMP_DIR/variance-summary"
  local -r mutated="$TEST_TMP_DIR/variance-summary-mutated.json"
  local canonical=""
  local compact=""
  local mutated_json=""
  local repetition=0
  local repetition_label=""
  local -a successful_requests=(100 20 80 40 60)
  local -a throughput_per_second=(50 10 40 20 30)
  local -a p50_nanos=(5 1 4 2 3)
  local -a p95_nanos=(5 1 4 2 3)
  local -a p99_nanos=(5 1 4 2 3)

  reset_options
  DURATION_SECONDS=2
  REPETITIONS=5
  prepare_variance_fixture "$output"
  cell_spec getsockopt-hit
  for ((repetition = 1; repetition <= REPETITIONS; repetition++)); do
    printf -v repetition_label 'rep-%02d' "$repetition"
    write_valid_benchmark_result \
      "$output/cells/getsockopt-hit/measurements/$repetition_label.json" \
      "$DURATION_SECONDS" \
      "${successful_requests[repetition - 1]}" \
      0 \
      2000000000 \
      "${throughput_per_second[repetition - 1]}" \
      "${p50_nanos[repetition - 1]}" \
      "${p95_nanos[repetition - 1]}" \
      "${p99_nanos[repetition - 1]}"
  done
  jq -n --arg timing scheduled_repetition_midpoint --arg status unavailable \
    '{timing: $timing, repetition: 1,
      scheduled_seconds_after_confirmed_launch: 1,
      status: $status, reason: "load_client_not_live_at_scheduled_midpoint"}' \
    >"$output/cells/getsockopt-hit/measurements/rep-01-midpoint.json"
  write_variance_summary || {
    printf 'variance summary rejected valid fixture data\n' >&2
    return 1
  }
  jq -e '
    .schema_version == 2 and
    .kind == "application-performance-repetition-summary" and
    .status == "complete" and
    .acceptance_evidence == false and
    .manifest == "manifest.json" and
    .aggregation.sample_unit == "one completed sustained-client repetition" and
    .aggregation.population_variability == {
      formula: "sqrt(sum((x-mean)^2)/N)/mean*100",
      divisor: "population_N",
      required_sample_count: 5,
      positive_finite_mean_required: true,
      metrics: ["throughput_per_second", "p99_latency_nanos"]
    } and
    .aggregation.cross_cell_aggregation == false and
    .aggregation.per_request_latency_aggregation == false and
    (.cells | map(.cell)) == [
      "uninstrumented",
      "bridge-disabled",
      "getsockopt-hit",
      "unix-hit",
      "getsockopt-w3c",
      "getsockopt-helper-idle"
    ]
  ' "$output/variance.json" >/dev/null || {
    printf 'variance summary did not retain its descriptive per-cell contract\n' >&2
    return 1
  }
  jq -e '
    (.cells[] | select(.cell == "getsockopt-hit")) as $cell |
    $cell.contract == "cells/getsockopt-hit/preflight/contract.json" and
    $cell.expected_sample_count == 5 and
    $cell.valid_sample_count == 5 and
    ($cell.samples | map({repetition, source})) == [
      {repetition: 1, source: "cells/getsockopt-hit/measurements/rep-01.json"},
      {repetition: 2, source: "cells/getsockopt-hit/measurements/rep-02.json"},
      {repetition: 3, source: "cells/getsockopt-hit/measurements/rep-03.json"},
      {repetition: 4, source: "cells/getsockopt-hit/measurements/rep-04.json"},
      {repetition: 5, source: "cells/getsockopt-hit/measurements/rep-05.json"}
    ] and
    $cell.statistics.successful_requests == {min: 20, median: 60, max: 100} and
    $cell.statistics.failed_requests == {min: 0, median: 0, max: 0} and
    $cell.statistics.traffic_elapsed_nanos == {min: 2000000000, median: 2000000000, max: 2000000000} and
    ($cell.statistics.throughput_per_second |
      .min == 10 and .median == 30 and .max == 50 and
      .population_variability == {
        sample_count: 5, sum: 150, mean: 30,
        squared_deviation_sum: 1000, population_variance: 200,
        population_standard_deviation: (200 | sqrt),
        coefficient_of_variation_percent: ((200 | sqrt) / 30 * 100)
      }) and
    $cell.statistics.latency.p50_nanos == {min: 1, median: 3, max: 5} and
    $cell.statistics.latency.p95_nanos == {min: 1, median: 3, max: 5} and
    ($cell.statistics.latency.p99_nanos |
      .min == 1 and .median == 3 and .max == 5 and
      .population_variability == {
        sample_count: 5, sum: 15, mean: 3,
        squared_deviation_sum: 10, population_variance: 2,
        population_standard_deviation: (2 | sqrt),
        coefficient_of_variation_percent: ((2 | sqrt) / 3 * 100)
      }) and
    (.cells[] | select(.cell == "unix-hit").statistics.throughput_per_second |
      .min == 1 and .median == 1 and .max == 1 and
      .population_variability.coefficient_of_variation_percent == 0)
  ' "$output/variance.json" >/dev/null || {
    printf 'variance summary did not preserve ordered samples or numeric per-cell statistics\n' >&2
    return 1
  }
  canonical="$(variance_summary_json "$output")" || return 1
  jq -e --argjson canonical "$canonical" '. == $canonical' \
    "$output/variance.json" >/dev/null || {
    printf 'variance writer diverged from its canonical source builder\n' >&2
    return 1
  }
  jq '(.cells[] | select(.cell == "getsockopt-hit") |
    .statistics.throughput_per_second.median) = 34' \
    "$output/variance.json" >"$mutated"
  if validate_variance_summary_schema "$mutated"; then
    printf 'variance validator accepted a mutated derived statistic\n' >&2
    return 1
  fi
  jq '(.cells[] | select(.cell == "getsockopt-hit") |
    .statistics.throughput_per_second.population_variability.coefficient_of_variation_percent) = 0' \
    "$output/variance.json" >"$mutated"
  if validate_variance_summary_schema "$mutated"; then
    printf 'variance validator accepted a mutated population CV\n' >&2
    return 1
  fi
  compact="$(jq -c . "$output/variance.json")" || return 1
  mutated_json="${compact/\"schema_version\":2/\"schema_version\":2,\"schema_version\":2}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$mutated"
  if validate_variance_summary_schema "$mutated"; then
    printf 'variance validator accepted a duplicate schema key\n' >&2
    return 1
  fi
  jq '.throughput_per_second = 61' \
    "$output/cells/getsockopt-hit/measurements/rep-01.json" \
    >"$output/cells/getsockopt-hit/measurements/rep-01.json.tmp"
  mv -T -- "$output/cells/getsockopt-hit/measurements/rep-01.json.tmp" \
    "$output/cells/getsockopt-hit/measurements/rep-01.json"
  if validate_variance_summary_schema "$output/variance.json"; then
    printf 'variance validator accepted an artifact stale against a raw repetition\n' >&2
    return 1
  fi
)

test_variance_summary_rejects_invalid_repetition_sets() (
  local mode=""
  local output=""
  local measurement_dir=""

  for mode in configured_count missing extra multi_document symlink; do
    reset_options
    DURATION_SECONDS=2
    REPETITIONS=5
    output="$TEST_TMP_DIR/variance-invalid-$mode"
    prepare_variance_fixture "$output"
    measurement_dir="$output/cells/getsockopt-hit/measurements"
    case "$mode" in
      configured_count)
        REPETITIONS=6
        write_variance_fixture_cell getsockopt-hit
        ;;
      missing)
        rm -f -- "$measurement_dir/rep-05.json"
        ;;
      extra)
        cell_spec getsockopt-hit
        write_valid_benchmark_result "$measurement_dir/rep-06.json" "$DURATION_SECONDS"
        ;;
      multi_document)
        printf '\n{}\n' >>"$measurement_dir/rep-01.json"
        ;;
      symlink)
        rm -f -- "$measurement_dir/rep-01.json"
        ln -s -- rep-02.json "$measurement_dir/rep-01.json"
        ;;
    esac
    if write_variance_summary >/dev/null 2>&1; then
      printf 'variance summary accepted a %s repetition set\n' "$mode" >&2
      return 1
    fi
    [[ ! -e "$output/variance.json" && ! -L "$output/variance.json" ]] || {
      printf 'variance summary published an artifact for a %s repetition set\n' "$mode" >&2
      return 1
    }
  done
)

rewrite_cell_performance_fixture() {
  local -r cell="$1"
  local -r throughput="$2"
  local -r p99="$3"
  local result=""
  local temporary=""

  for result in "$OUTPUT_DIR/cells/$cell/measurements"/rep-[0-9][0-9].json; do
    temporary="$result.tmp"
    jq --argjson throughput "$throughput" --argjson p99 "$p99" '
      .throughput_per_second = $throughput |
      .successful_requests = ($throughput * .traffic_elapsed_nanos / 1000000000) |
      .latency.p50_nanos = $p99 |
      .latency.p95_nanos = $p99 |
      .latency.p99_nanos = $p99 |
      .latency.histogram = [{nanos: $p99, count: .successful_requests}]
    ' "$result" >"$temporary" || return 1
    mv -T -- "$temporary" "$result" || return 1
  done
  rm -f -- "$OUTPUT_DIR/variance.json"
  write_variance_summary
}

rewrite_cell_population_cv_fixture() {
  local -r cell="$1"
  local -r mode="$2"
  local -r duration_seconds="${3:-2}"
  local repetition=0
  local repetition_label=""
  local throughput=""
  local result=""
  local -a values=()

  case "$mode" in
    boundary) values=(85 95 100 105 115) ;;
    failure) values=(84 95 100 105 116) ;;
    *) return 1 ;;
  esac
  cell_spec "$cell" || return 1
  for ((repetition = 1; repetition <= REQUIRED_REPETITIONS; repetition++)); do
    printf -v repetition_label 'rep-%02d' "$repetition"
    result="$OUTPUT_DIR/cells/$cell/measurements/$repetition_label.json"
    throughput="${values[repetition - 1]}"
    write_valid_benchmark_result \
      "$result" "$duration_seconds" "$((throughput * duration_seconds))" 0 \
      "$((duration_seconds * 1000000000))" "$throughput" \
      "$throughput" "$throughput" "$throughput"
  done
  rm -f -- "$OUTPUT_DIR/variance.json" "$OUTPUT_DIR/poc-gates.json"
  write_variance_summary
}

test_resource_growth_observations_fail_closed() (
  local -r fixture="$TEST_TMP_DIR/resource-growth"
  local process_json=""
  local map_json=""

  mkdir -- "$fixture"
  write_proc_growth_fixture "$fixture/proc-before.txt" 101 20 8
  write_proc_growth_fixture "$fixture/proc-recovery.txt" 101 19 7
  process_json="$(process_growth_observation \
    test-cell java-backend "$fixture/proc-before.txt" "$fixture/proc-recovery.txt")"
  jq -e '
    .status == "complete" and .result == "passed" and
    (.container_id | test("^[0-9a-f]{64}$")) and
    .host_pid == 101 and .proc_start_time == 1010 and
    (.proc_cgroup_sha256 | test("^[0-9a-f]{64}$")) and
    .proc_cgroup_container_binding == "full_container_id_at_non_hex_boundaries" and
    .fd.delta == -1 and .threads.delta == -1
  ' <<<"$process_json" >/dev/null || {
    printf 'complete non-growing process samples did not pass\n' >&2
    return 1
  }

  write_proc_growth_fixture "$fixture/proc-recovery.txt" 101 19 7 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1011
  process_json="$(process_growth_observation \
    test-cell java-backend "$fixture/proc-before.txt" "$fixture/proc-recovery.txt")"
  jq -e '.status == "partial" and .result == "not_evaluated" and
    .reason == "service_container_or_process_identity_changed_between_required_samples"' \
    <<<"$process_json" >/dev/null || {
    printf 'PID start-time reuse was not rejected from process growth evidence\n' >&2
    return 1
  }

  write_proc_growth_fixture "$fixture/proc-recovery.txt" 101 19 7 \
    cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 1010
  process_json="$(process_growth_observation \
    test-cell java-backend "$fixture/proc-before.txt" "$fixture/proc-recovery.txt")"
  jq -e '.status == "partial" and .result == "not_evaluated" and
    .reason == "service_container_or_process_identity_changed_between_required_samples"' \
    <<<"$process_json" >/dev/null || {
    printf 'unrelated container identity was not rejected from process growth evidence\n' >&2
    return 1
  }

  write_proc_growth_fixture "$fixture/proc-recovery.txt" 101 19 7 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1010 \
    dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  process_json="$(process_growth_observation \
    test-cell java-backend "$fixture/proc-before.txt" "$fixture/proc-recovery.txt")"
  jq -e '.status == "partial" and .result == "not_evaluated" and
    .reason == "service_container_or_process_identity_changed_between_required_samples"' \
    <<<"$process_json" >/dev/null || {
    printf 'cgroup identity drift was not rejected from process growth evidence\n' >&2
    return 1
  }

  printf 'status=unavailable\n' >"$fixture/proc-recovery.txt"
  process_json="$(process_growth_observation \
    test-cell java-backend "$fixture/proc-before.txt" "$fixture/proc-recovery.txt")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$process_json" >/dev/null || {
    printf 'unavailable process sample was misrepresented as complete\n' >&2
    return 1
  }

  write_java_map_growth_fixture "$fixture/map-before.prom" 2 10000
  write_java_map_growth_fixture "$fixture/map-recovery.prom" 1 10000
  write_proc_growth_fixture "$fixture/obi-proc-before.txt" 101 20 8
  write_proc_growth_fixture "$fixture/obi-proc-recovery.txt" 101 19 7
  write_bpf_fd_ownership_fixture "$fixture/map-before-owner.txt"
  write_bpf_fd_ownership_fixture "$fixture/map-recovery-owner.txt"
  map_json="$(java_bridge_map_growth_observation \
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom" \
    "$fixture/map-before-owner.txt" "$fixture/map-recovery-owner.txt" \
    "$fixture/obi-proc-before.txt" "$fixture/obi-proc-recovery.txt")"
  jq -e '
    .status == "complete" and .result == "passed" and
    .data_status == "complete" and
    .descriptive_result == "stable_or_decreased" and
    .scope == "exact_obi_process_open_bpf_map_ids" and
    .ownership_attribution == true and
    .ownership.descriptors == [
      {fd: 4, kind: "map_id", id: 41},
      {fd: 5, kind: "prog_id", id: 71},
      {fd: 6, kind: "map_id", id: 41}
    ] and
    .ownership.map_ids == [41] and .ownership.program_ids == [71] and
    .maps == [{
      map_id: 41, map_name: "java_remote_par", map_type: "hash",
      before_entries: 2, idle_recovery_entries: 1, delta: -1,
      maximum_delta: 0, max_entries: 10000
    }]
  ' <<<"$map_json" >/dev/null || {
    printf 'stable exact-owner Java map samples did not pass the bounded growth gate\n' >&2
    return 1
  }

  write_bpf_fd_ownership_fixture \
    "$fixture/map-before-owner.txt" 42 71
  map_json="$(java_bridge_map_growth_observation \
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom" \
    "$fixture/map-before-owner.txt" "$fixture/map-recovery-owner.txt" \
    "$fixture/obi-proc-before.txt" "$fixture/obi-proc-recovery.txt")"
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .data_status == "ambiguous" and
    .ownership_attribution == false
  ' <<<"$map_json" >/dev/null || {
    printf 'map samples outside the exact owned roster were allowed to pass\n' >&2
    return 1
  }
  write_bpf_fd_ownership_fixture "$fixture/map-before-owner.txt"

  write_bpf_fd_ownership_fixture \
    "$fixture/map-before-owner.txt" 41 71 \
    cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 102 1020 \
    dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  write_bpf_fd_ownership_fixture \
    "$fixture/map-recovery-owner.txt" 41 71 \
    cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 102 1020 \
    dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  map_json="$(java_bridge_map_growth_observation \
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom" \
    "$fixture/map-before-owner.txt" "$fixture/map-recovery-owner.txt" \
    "$fixture/obi-proc-before.txt" "$fixture/obi-proc-recovery.txt")"
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .data_status == "ambiguous" and .ownership_attribution == false and
    .reason == "owned_java_bridge_map_series_or_bpf_fd_roster_changed_or_was_duplicate_or_incomplete"
  ' <<<"$map_json" >/dev/null || {
    printf 'coordinated foreign BPF ownership was not rejected against the bound OBI process\n' >&2
    return 1
  }
  write_bpf_fd_ownership_fixture "$fixture/map-before-owner.txt"
  write_bpf_fd_ownership_fixture "$fixture/map-recovery-owner.txt"

  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 1' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 1' \
    'obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 10000' \
    >"$fixture/map-recovery.prom"
  map_json="$(java_bridge_map_growth_observation \
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom" \
    "$fixture/map-before-owner.txt" "$fixture/map-recovery-owner.txt" \
    "$fixture/obi-proc-before.txt" "$fixture/obi-proc-recovery.txt")"
  jq -e '.status == "partial" and .result == "not_evaluated"' \
    <<<"$map_json" >/dev/null || {
    printf 'duplicate Java map sample was misrepresented as complete\n' >&2
    return 1
  }

  {
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 1' \
      'obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 10000' \
      'obi_bpf_map_entries_total{map_id="42",map_name="java_remote_par",map_type="hash"} 0' \
      'obi_bpf_map_max_entries_total{map_id="42",map_name="java_remote_par",map_type="hash"} 1'
  } >"$fixture/map-recovery.prom"
  map_json="$(java_bridge_map_growth_observation \
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom" \
    "$fixture/map-before-owner.txt" "$fixture/map-recovery-owner.txt" \
    "$fixture/obi-proc-before.txt" "$fixture/obi-proc-recovery.txt")"
  jq -e '
    .status == "complete" and .result == "passed" and
    .data_status == "complete" and
    .descriptive_result == "stable_or_decreased" and
    .scope == "exact_obi_process_open_bpf_map_ids" and
    .ownership_attribution == true and
    [.maps[].map_id] == [41]
  ' <<<"$map_json" >/dev/null || {
    printf 'an unrelated host-global Java map series contaminated the exact owned gate\n' >&2
    return 1
  }
)

test_predeclared_poc_gate_stays_partial_and_evaluates_supported_dimensions() (
  local -r stable_output="$TEST_TMP_DIR/poc-gate-stable"
  local -r partial_output="$TEST_TMP_DIR/poc-gate-partial"
  local -r map_partial_output="$TEST_TMP_DIR/poc-gate-map-partial"
  local -r resource_failure_output="$TEST_TMP_DIR/poc-gate-resource-failure"
  local -r correctness_failure_output="$TEST_TMP_DIR/poc-gate-correctness-failure"
  local -r boundary_output="$TEST_TMP_DIR/poc-gate-boundary"
  local -r performance_failure_output="$TEST_TMP_DIR/poc-gate-performance-failure"
  local -r cv_boundary_output="$TEST_TMP_DIR/poc-gate-cv-boundary"
  local -r cv_failure_output="$TEST_TMP_DIR/poc-gate-cv-failure"
  local -r allocation_boundary_output="$TEST_TMP_DIR/poc-gate-allocation-boundary"
  local -r allocation_failure_output="$TEST_TMP_DIR/poc-gate-allocation-failure"
  local -r allocation_percentage_boundary_output="$TEST_TMP_DIR/poc-gate-allocation-percentage-boundary"
  local -r allocation_percentage_failure_output="$TEST_TMP_DIR/poc-gate-allocation-percentage-failure"
  local -r allocation_zero_output="$TEST_TMP_DIR/poc-gate-allocation-zero"
  local -r allocation_reset_output="$TEST_TMP_DIR/poc-gate-allocation-reset"
  local -r allocation_malformed_output="$TEST_TMP_DIR/poc-gate-allocation-malformed"
  local -r allocation_missing_receipt_output="$TEST_TMP_DIR/poc-gate-allocation-missing-receipt"
  local -r mutated_gate="$TEST_TMP_DIR/poc-gate-mutated.json"
  local -r canonical_gate="$TEST_TMP_DIR/poc-gate-canonical.json"
  local -r stable_evidence="$stable_output/cells/getsockopt-hit/java-measurement/evidence.json"
  local -r stable_evidence_backup="$TEST_TMP_DIR/poc-gate-stable-evidence.json"
  local compact=""
  local mutated_json=""
  local result=""
  local production_writer_definition=""

  # Unit fixtures retain the same evidence/receipt binding consumed by the
  # production gate. The full hermetic run below exercises the production
  # whole-tree validator; this focused test substitutes only its expensive
  # tree walk so arithmetic and source-staleness mutations stay deterministic.
  validate_published_java_measurement() {
    # shellcheck disable=SC2317 # Dynamically called by the sourced gate builder.
    validate_sampled_allocation_fixture_with_bundle "$1" "${2:-}"
  }
  production_writer_definition="$(declare -f write_poc_gate_summary)" || return 1
  eval "${production_writer_definition/write_poc_gate_summary/production_write_poc_gate_summary}"
  # shellcheck disable=SC2120 # Test wrapper deliberately forwards optional dynamic arguments.
  write_poc_gate_summary() {
    production_write_poc_gate_summary "$@" || return 1
    publish_held_poc_gate_fixture
  }

  reset_options
  prepare_poc_gate_fixture "$stable_output"
  write_poc_gate_summary
  validate_poc_gate_schema "$stable_output/poc-gates.json" || {
    printf 'partial PoC fixture with complete descriptive samples was rejected\n' >&2
    return 1
  }
  validate_supported_poc_dimensions_pass "$stable_output/poc-gates.json" || {
    printf 'passing supported dimensions with complete descriptive samples was rejected\n' >&2
    return 1
  }
  poc_gate_summary_json "$stable_output" >"$canonical_gate" || return 1
  jq -se 'length == 2 and .[0] == .[1]' \
    "$stable_output/poc-gates.json" "$canonical_gate" >/dev/null || {
    printf 'PoC writer diverged from its canonical source builder\n' >&2
    return 1
  }
  jq '
    .performance.comparisons[0].throughput_per_second.candidate_median = 1 |
    .performance.comparisons[0].p99_latency_nanos.candidate_median = 1000
  ' "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted candidate metrics inconsistent with retained regressions\n' >&2
    return 1
  fi
  jq '
    (.sampled_allocation.comparisons[] | select(.cell == "getsockopt-hit")) |= (
      .allowed_regression_bytes_per_successful_request = 2048 |
      .maximum_candidate_bytes_per_successful_request = 4048
    )
  ' "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted coordinated forged sampled-allocation derivations\n' >&2
    return 1
  fi
  jq '.thresholds.process_tree.absolute.fd_count += 1' \
    "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted a threshold drift from the frozen CLI cap\n' >&2
    return 1
  fi
  jq '.resources.process_tree.thresholds.recovery_delta.rss_bytes += 1' \
    "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted a projected recovery-cap drift\n' >&2
    return 1
  fi
  jq '.manifest_binding.predeclared_poc_gates_sha256 = ("0" * 64)' \
    "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted a forged manifest gate-declaration binding\n' >&2
    return 1
  fi
  jq '.resources.application_cpu.comparisons[0].exact_cross_products.candidate_cpu_times_baseline_requests_times_100 = "0"' \
    "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted a forged exact CPU cross-product\n' >&2
    return 1
  fi
  compact="$(jq -c . "$stable_output/poc-gates.json")" || return 1
  mutated_json="${compact/\"schema_version\":3/\"schema_version\":3,\"schema_version\":3}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted a duplicate top-level schema key\n' >&2
    return 1
  fi
  jq '
    .correctness.cells[0].status = "failed" |
    .correctness.cells[0].reason = "forged" |
    .correctness.observed_failures = 1 |
    .correctness.result = "failed" |
    .result = "failed"
  ' "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted a coordinated correctness-count forgery\n' >&2
    return 1
  fi
  jq '
    .resources.java_bridge_map_observations[0].ownership.host_pid += 1
  ' "$stable_output/poc-gates.json" >"$mutated_gate"
  if validate_poc_gate_schema "$mutated_gate"; then
    printf 'PoC validator accepted map ownership not bound to the cell OBI process\n' >&2
    return 1
  fi
  jq -e '
    .schema_version == 3 and
    .status == "partial" and .result == "not_evaluated" and
    .correctness.observed_failures == 0 and
    .correctness.status == "complete" and .correctness.result == "passed" and
    .performance.required_repetitions == 5 and
    .performance.status == "complete" and .performance.result == "passed" and
    .performance.population_variability.status == "complete" and
    .performance.population_variability.result == "passed" and
    .performance.population_variability.maximum_coefficient_of_variation_percent == 10 and
    all(.performance.population_variability.cells[];
      .result == "passed" and
      .throughput_per_second.sample_count == 5 and
      .throughput_per_second.coefficient_of_variation_percent == 0 and
      .p99_latency_nanos.sample_count == 5 and
      .p99_latency_nanos.coefficient_of_variation_percent == 0) and
    all(.performance.comparisons[];
      .throughput_per_second.regression_percent == 0 and
      .p99_latency_nanos.regression_percent == 0 and
      .result == "passed") and
    .sampled_allocation.status == "complete" and
    .sampled_allocation.result == "passed" and
    .sampled_allocation.classification ==
      "exploratory_sampled_indicator_not_exact_allocation" and
    .sampled_allocation.exact_allocation == false and
    .sampled_allocation.acceptance_evidence == false and
    .sampled_allocation.baseline == {
      cell: "bridge-disabled", sampled_allocation_records: 5,
      sampled_allocation_weight_bytes: 2000000, successful_requests: 1000,
      sampled_allocation_weight_bytes_per_successful_request: 2000
    } and
    all(.sampled_allocation.comparisons[];
      .baseline_sampled_allocation_weight_bytes_per_successful_request == 2000 and
      .candidate_sampled_allocation_weight_bytes_per_successful_request == 2000 and
      .percentage_allowance_bytes_per_successful_request == 200 and
      .minimum_allowance_bytes_per_successful_request == 1024 and
      .allowed_regression_bytes_per_successful_request == 1024 and
      .maximum_candidate_bytes_per_successful_request == 3024 and
      .observed_regression_bytes_per_successful_request == 0 and
      .result == "passed") and
    .performance.excluded_cells.getsockopt_helper_idle ==
      "direct_java_workload_is_not_comparable_to_the_apache_baseline" and
    .thresholds.process_tree == {
      absolute: {fd_count: 4096, task_count: 2048, rss_bytes: 1073741824},
      recovery_delta: {fd_count: 0, task_count: 0, rss_bytes: 0}
    } and
    .thresholds.application_cpu_regression_max_percent == 10 and
    .resources.status == "complete" and .resources.result == "passed" and
    .resources.process_dimension == {status: "complete", result: "passed"} and
    .resources.map_dimension == {
      status: "complete",
      result: "passed",
      reason: null,
      descriptive_data_status: "complete"
    } and
    .resources.map_sampling_scope == {
      metric_scope: "exact_obi_process_open_bpf_map_ids",
      ownership_attribution: true,
      descriptive_interpretation:
        "stable_or_decreased_applies_only_to_exact_obi_owned_java_remote_parent_maps",
      evaluation_policy:
        "require_stable_exact_obi_process_bpf_fd_rosters_bracketing_each_metrics_scrape"
    } and
    .resources.java_bridge_map_observations[0].cell == "bridge-disabled" and
    .resources.java_bridge_map_observations[0].status == "complete" and
    .resources.java_bridge_map_observations[0].result == "passed" and
    .resources.java_bridge_map_observations[0].data_status == "complete" and
    .resources.java_bridge_map_observations[0].descriptive_result == "stable_or_decreased" and
    .resources.java_bridge_map_observations[0].maps == [{
      map_id: 41, map_name: "java_remote_par", map_type: "hash",
      before_entries: 0, idle_recovery_entries: 0, delta: 0,
      maximum_delta: 0, max_entries: 1
    }] and
    all(.resources.java_bridge_map_observations[];
      .scope == "exact_obi_process_open_bpf_map_ids" and
      .ownership_attribution == true and
      .process_sources == {
        before: ("cells/" + .cell + "/resources-before/obi-proc.txt"),
        idle_recovery: ("cells/" + .cell + "/resources-idle-recovery-02/obi-proc.txt")
      } and
      .ownership.descriptors == [
        {fd: 4, kind: "map_id", id: 41},
        {fd: 5, kind: "prog_id", id: 71},
        {fd: 6, kind: "map_id", id: 41}
      ] and
      .ownership.map_ids == [41] and .ownership.program_ids == [71] and
      .status == "complete" and .result == "passed") and
    .resources.process_tree.status == "complete" and
    .resources.process_tree.result == "passed" and
    .resources.process_tree.scope == "complete_leaf_cgroup_v2_process_tree" and
    .resources.process_tree.boundaries == [
      "before", "cpu_measurement_baseline", "rep_01_midpoint", "rep_02_midpoint",
      "rep_03_midpoint", "rep_04_midpoint", "rep_05_midpoint", "cpu_measurement_end",
      "after_load", "idle_recovery_01", "idle_recovery_02"
    ] and
    (.resources.process_tree.observations | length) == 11 and
    all(.resources.process_tree.observations[];
      .status == "complete" and .result == "passed" and
      .sources.recovery_schedule == ("cells/" + .cell + "/recovery-schedule.json")) and
    .resources.application_cpu.status == "complete" and
    .resources.application_cpu.result == "passed" and
    .resources.application_cpu.primary_cgroupsockopt_program_cpu == "not_collected" and
    (.resources.application_cpu.observations | length) == 4 and
    (.resources.application_cpu.comparisons | length) == 9 and
    all(.resources.application_cpu.comparisons[]; .result == "passed") and
    .issue_acceptance_complete == false and
    .unmeasured_dimensions == {
      exact_java_allocation:
        "sampled_jfr_weight_evaluated_as_exploratory_indicator_only_exact_allocation_not_collected",
      nmt_native_and_direct_memory:
        "bounded_indicators_retained_not_evaluated_as_acceptance_gate",
      primary_cgroupsockopt_program_cpu: "not_collected",
      bpf_lock_contention: "not_collected"
    }
  ' "$stable_output/poc-gates.json" >/dev/null || {
    printf 'partial PoC gate omitted evaluated subsets or explicit acceptance gaps\n' >&2
    return 1
  }

  reset_options
  prepare_poc_gate_fixture "$partial_output"
  printf 'status=unavailable\n' \
    >"$partial_output/cells/unix-hit/resources-idle-recovery-02/java-backend-proc.txt"
  write_poc_gate_summary
  validate_poc_gate_schema "$partial_output/poc-gates.json" || {
    printf 'partial PoC gate did not retain a valid fail-closed artifact\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass "$partial_output/poc-gates.json"; then
    printf 'supported PoC dimensions passed with an unavailable process sample\n' >&2
    return 1
  fi
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .resources.status == "partial" and .resources.result == "not_evaluated" and
    .resources.process_dimension == {status: "partial", result: "not_evaluated"}
  ' "$partial_output/poc-gates.json" >/dev/null || {
    printf 'unavailable resource sample was claimed as collected or evaluated\n' >&2
    return 1
  }

  reset_options
  prepare_poc_gate_fixture "$map_partial_output"
  printf '# required java_remote_par series unavailable\n' \
    >"$map_partial_output/cells/bridge-disabled/resources-idle-recovery-02/obi-metrics.prom"
  write_poc_gate_summary
  validate_poc_gate_schema "$map_partial_output/poc-gates.json" || {
    printf 'partial PoC gate rejected an honest unavailable map sample\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass "$map_partial_output/poc-gates.json"; then
    printf 'supported PoC dimensions passed without required descriptive map data\n' >&2
    return 1
  fi
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .resources.map_dimension == {
      status: "partial",
      result: "not_evaluated",
      reason: "stable_exact_obi_bpf_fd_ownership_is_required_for_every_map_sample",
      descriptive_data_status: "unavailable"
    } and
    (.resources.java_bridge_map_observations[] |
      select(.cell == "bridge-disabled") |
      .data_status == "unavailable" and
      .descriptive_result == "not_available")
  ' "$map_partial_output/poc-gates.json" >/dev/null || {
    printf 'unavailable Java map data was claimed as collected\n' >&2
    return 1
  }

  reset_options
  prepare_poc_gate_fixture "$resource_failure_output"
  write_proc_growth_fixture \
    "$resource_failure_output/cells/getsockopt-hit/resources-idle-recovery-02/java-backend-proc.txt" \
    109 21 8
  write_poc_gate_summary
  validate_poc_gate_schema "$resource_failure_output/poc-gates.json" || {
    printf 'partial PoC artifact rejected an evaluated process-growth failure\n' >&2
    return 1
  }
  jq -e '
    .status == "partial" and .result == "failed" and
    .resources.status == "complete" and .resources.result == "failed" and
    .resources.process_dimension == {status: "complete", result: "failed"} and
    (.resources.process_observations[] |
      select(.cell == "getsockopt-hit" and .service == "java-backend") |
      .status == "complete" and .result == "failed" and .fd.delta == 1)
  ' "$resource_failure_output/poc-gates.json" >/dev/null || {
    printf 'bounded process growth failure was not retained within the partial PoC gate\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass "$resource_failure_output/poc-gates.json"; then
    printf 'supported PoC dimensions passed despite positive FD growth\n' >&2
    return 1
  fi

  reset_options
  prepare_poc_gate_fixture "$correctness_failure_output"
  jq '.status = "failed" | .reason = "fixture_correctness_failure"' \
    "$correctness_failure_output/cells/unix-hit/status.json" \
    >"$correctness_failure_output/cells/unix-hit/status.json.tmp"
  mv -T -- \
    "$correctness_failure_output/cells/unix-hit/status.json.tmp" \
    "$correctness_failure_output/cells/unix-hit/status.json"
  write_poc_gate_summary
  validate_poc_gate_schema "$correctness_failure_output/poc-gates.json" || {
    printf 'partial PoC artifact rejected a known correctness failure\n' >&2
    return 1
  }
  jq -e '
    .status == "partial" and .result == "failed" and
    .correctness.status == "complete" and
    .correctness.result == "failed" and
    .correctness.observed_failures == 1 and
    .resources.status == "complete" and .resources.result == "passed" and
    .resources.process_dimension == {status: "complete", result: "passed"} and
    .resources.process_tree.status == "complete" and
    .resources.process_tree.result == "passed" and
    .resources.application_cpu.status == "complete" and
    .resources.application_cpu.result == "passed"
  ' "$correctness_failure_output/poc-gates.json" >/dev/null || {
    printf 'known correctness failure did not propagate through the partial PoC gate\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass \
    "$correctness_failure_output/poc-gates.json"; then
    printf 'supported PoC dimensions passed despite a correctness failure\n' >&2
    return 1
  fi

  reset_options
  prepare_poc_gate_fixture "$boundary_output"
  rewrite_cell_performance_fixture getsockopt-hit 90 110
  for result in obi java-backend; do
    write_bound_cgroup_v2_snapshot_fixture \
      "$boundary_output/cells/getsockopt-hit/cpu-measurement-end/$result-cgroup-v2.json" \
      getsockopt-hit "$result" cpu_measurement_end '' \
      8 8 4 4 1048576 1048576 1901 1902
  done
  write_poc_gate_summary
  validate_poc_gate_schema "$boundary_output/poc-gates.json" || {
    printf 'exact ten-percent performance regression boundary invalidated the partial artifact\n' >&2
    return 1
  }
  validate_supported_poc_dimensions_pass "$boundary_output/poc-gates.json" || {
    printf 'exact ten-percent supported performance boundary did not pass\n' >&2
    return 1
  }
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .performance.status == "complete" and .performance.result == "passed" and
    (.performance.comparisons[] | select(.cell == "getsockopt-hit") |
      .throughput_per_second.regression_percent == 10 and
      .p99_latency_nanos.regression_percent == 10 and .result == "passed")
  ' "$boundary_output/poc-gates.json" >/dev/null || {
    printf 'exact ten-percent performance boundary was not retained\n' >&2
    return 1
  }

  reset_options
  prepare_poc_gate_fixture "$performance_failure_output"
  rewrite_cell_performance_fixture getsockopt-hit 89 111
  write_poc_gate_summary
  result="$performance_failure_output/poc-gates.json"
  validate_poc_gate_schema "$result" || {
    printf 'partial PoC artifact rejected an evaluated performance failure\n' >&2
    return 1
  }
  jq -e '
    .status == "partial" and .result == "failed" and
    .performance.result == "failed" and
    (.performance.comparisons[] | select(.cell == "getsockopt-hit") |
      .throughput_per_second.regression_percent == 11 and
      .p99_latency_nanos.regression_percent == 11 and
      .result == "failed")
  ' "$result" >/dev/null || {
    printf 'greater-than-ten-percent performance regression did not fail\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass "$result"; then
    printf 'supported PoC dimensions passed despite a performance regression\n' >&2
    return 1
  fi

  reset_options
  prepare_poc_gate_fixture "$cv_boundary_output"
  rewrite_cell_population_cv_fixture getsockopt-hit boundary
  write_poc_gate_summary
  validate_supported_poc_dimensions_pass "$cv_boundary_output/poc-gates.json" || {
    printf 'exact ten-percent population CV boundary did not pass\n' >&2
    return 1
  }
  jq -e '
    (.performance.population_variability.cells[] |
      select(.cell == "getsockopt-hit")) as $cell |
    $cell.result == "passed" and
    $cell.throughput_per_second.coefficient_of_variation_percent == 10 and
    $cell.p99_latency_nanos.coefficient_of_variation_percent == 10 and
    $cell.throughput_per_second.squared_deviation_sum == 500 and
    $cell.p99_latency_nanos.squared_deviation_sum == 500
  ' "$cv_boundary_output/poc-gates.json" >/dev/null || {
    printf 'population CV boundary omitted its recomputable fields\n' >&2
    return 1
  }

  reset_options
  prepare_poc_gate_fixture "$cv_failure_output"
  rewrite_cell_population_cv_fixture getsockopt-hit failure
  write_poc_gate_summary
  jq -e '
    .status == "partial" and .result == "failed" and
    .performance.result == "failed" and
    .performance.population_variability.result == "failed" and
    (.performance.population_variability.cells[] |
      select(.cell == "getsockopt-hit") |
      .result == "failed" and
      .throughput_per_second.coefficient_of_variation_percent > 10 and
      .p99_latency_nanos.coefficient_of_variation_percent > 10)
  ' "$cv_failure_output/poc-gates.json" >/dev/null || {
    printf 'greater-than-ten-percent population CV did not fail\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass "$cv_failure_output/poc-gates.json"; then
    printf 'supported PoC dimensions passed despite excessive population CV\n' >&2
    return 1
  fi

  reset_options
  prepare_poc_gate_fixture "$allocation_boundary_output"
  write_sampled_allocation_fixture getsockopt-hit 3024000
  rm -f -- "$allocation_boundary_output/poc-gates.json"
  write_poc_gate_summary
  validate_supported_poc_dimensions_pass \
    "$allocation_boundary_output/poc-gates.json" || {
    printf 'sampled-allocation minimum-allowance boundary did not pass\n' >&2
    return 1
  }
  jq -e '
    (.sampled_allocation.comparisons[] | select(.cell == "getsockopt-hit")) |
    .candidate_sampled_allocation_weight_bytes_per_successful_request == 3024 and
    .observed_regression_bytes_per_successful_request == 1024 and
    .allowed_regression_bytes_per_successful_request == 1024 and
    .result == "passed"
  ' "$allocation_boundary_output/poc-gates.json" >/dev/null || return 1

  reset_options
  prepare_poc_gate_fixture "$allocation_failure_output"
  write_sampled_allocation_fixture getsockopt-hit 3024001
  rm -f -- "$allocation_failure_output/poc-gates.json"
  write_poc_gate_summary
  jq -e '
    .status == "partial" and .result == "failed" and
    .sampled_allocation.status == "complete" and
    .sampled_allocation.result == "failed" and
    (.sampled_allocation.comparisons[] | select(.cell == "getsockopt-hit") |
      .observed_regression_bytes_per_successful_request >
        .allowed_regression_bytes_per_successful_request and
      .result == "failed")
  ' "$allocation_failure_output/poc-gates.json" >/dev/null || {
    printf 'sampled-allocation over-boundary regression did not fail\n' >&2
    return 1
  }

  reset_options
  prepare_poc_gate_fixture "$allocation_percentage_boundary_output"
  write_sampled_allocation_fixture bridge-disabled 20000000
  write_sampled_allocation_fixture getsockopt-hit 22000000
  rm -f -- "$allocation_percentage_boundary_output/poc-gates.json"
  write_poc_gate_summary
  validate_supported_poc_dimensions_pass \
    "$allocation_percentage_boundary_output/poc-gates.json" || {
    printf 'sampled-allocation ten-percent allowance boundary did not pass\n' >&2
    return 1
  }
  jq -e '
    (.sampled_allocation.comparisons[] | select(.cell == "getsockopt-hit")) |
    .baseline_sampled_allocation_weight_bytes_per_successful_request == 20000 and
    .candidate_sampled_allocation_weight_bytes_per_successful_request == 22000 and
    .percentage_allowance_bytes_per_successful_request == 2000 and
    .allowed_regression_bytes_per_successful_request == 2000 and
    .observed_regression_bytes_per_successful_request == 2000 and
    .result == "passed"
  ' "$allocation_percentage_boundary_output/poc-gates.json" >/dev/null || return 1

  reset_options
  prepare_poc_gate_fixture "$allocation_percentage_failure_output"
  write_sampled_allocation_fixture bridge-disabled 20000000
  write_sampled_allocation_fixture getsockopt-hit 22000001
  rm -f -- "$allocation_percentage_failure_output/poc-gates.json"
  write_poc_gate_summary
  jq -e '
    .status == "partial" and .result == "failed" and
    .sampled_allocation.status == "complete" and
    .sampled_allocation.result == "failed" and
    (.sampled_allocation.comparisons[] | select(.cell == "getsockopt-hit") |
      .percentage_allowance_bytes_per_successful_request == 2000 and
      .allowed_regression_bytes_per_successful_request == 2000 and
      .observed_regression_bytes_per_successful_request > 2000 and
      .result == "failed")
  ' "$allocation_percentage_failure_output/poc-gates.json" >/dev/null || {
    printf 'sampled-allocation over-ten-percent boundary did not fail\n' >&2
    return 1
  }

  reset_options
  prepare_poc_gate_fixture "$allocation_zero_output"
  for result in bridge-disabled getsockopt-hit unix-hit getsockopt-w3c; do
    write_sampled_allocation_fixture "$result" 0
  done
  rm -f -- "$allocation_zero_output/poc-gates.json"
  write_poc_gate_summary
  validate_supported_poc_dimensions_pass "$allocation_zero_output/poc-gates.json" || {
    printf 'zero-record sampled-allocation observations did not pass safely\n' >&2
    return 1
  }
  jq -e '
    .sampled_allocation.baseline.sampled_allocation_records == 0 and
    .sampled_allocation.baseline.sampled_allocation_weight_bytes_per_successful_request == 0 and
    all(.sampled_allocation.comparisons[];
      .percentage_allowance_bytes_per_successful_request == 0 and
      .allowed_regression_bytes_per_successful_request == 1024 and
      .result == "passed")
  ' "$allocation_zero_output/poc-gates.json" >/dev/null || return 1

  reset_options
  prepare_poc_gate_fixture "$allocation_reset_output"
  for result in getsockopt-hit unix-hit getsockopt-w3c; do
    write_sampled_allocation_fixture "$result" 0
  done
  rm -f -- "$allocation_reset_output/poc-gates.json"
  write_poc_gate_summary
  validate_supported_poc_dimensions_pass "$allocation_reset_output/poc-gates.json" || {
    printf 'independent lower/reset sampled weight was treated as a regression\n' >&2
    return 1
  }
  jq -e 'all(.sampled_allocation.comparisons[];
    .candidate_sampled_allocation_weight_bytes_per_successful_request == 0 and
    .observed_regression_bytes_per_successful_request == 0 and
    .result == "passed")' \
    "$allocation_reset_output/poc-gates.json" >/dev/null || return 1

  reset_options
  prepare_poc_gate_fixture "$allocation_malformed_output"
  jq '.jfr.allocation_sample.weight_bytes = "malformed"' \
    "$allocation_malformed_output/cells/getsockopt-hit/java-measurement/evidence.json" \
    >"$mutated_gate"
  mv -T -- "$mutated_gate" \
    "$allocation_malformed_output/cells/getsockopt-hit/java-measurement/evidence.json"
  rm -f -- "$allocation_malformed_output/poc-gates.json"
  write_poc_gate_summary
  validate_poc_gate_schema "$allocation_malformed_output/poc-gates.json" || return 1
  jq -e '
    .sampled_allocation.status == "partial" and
    .sampled_allocation.result == "not_evaluated" and
    (.sampled_allocation.observations[] | select(.cell == "getsockopt-hit") |
      .status == "not_available")
  ' "$allocation_malformed_output/poc-gates.json" >/dev/null || {
    printf 'malformed sampled-allocation evidence was not failed closed\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass \
    "$allocation_malformed_output/poc-gates.json"; then
    printf 'supported PoC dimensions passed malformed sampled-allocation evidence\n' >&2
    return 1
  fi

  reset_options
  prepare_poc_gate_fixture "$allocation_missing_receipt_output"
  rm -f -- \
    "$allocation_missing_receipt_output/cells/getsockopt-hit/java-measurement-publication.json" \
    "$allocation_missing_receipt_output/poc-gates.json"
  write_poc_gate_summary
  validate_poc_gate_schema \
    "$allocation_missing_receipt_output/poc-gates.json" || return 1
  jq -e '
    .sampled_allocation.status == "partial" and
    .sampled_allocation.result == "not_evaluated" and
    (.sampled_allocation.observations[] | select(.cell == "getsockopt-hit") |
      .status == "not_available" and
      .reason == "sealed_java_measurement_evidence_unavailable_or_invalid")
  ' "$allocation_missing_receipt_output/poc-gates.json" >/dev/null || {
    printf 'missing sampled-allocation publication receipt did not fail closed\n' >&2
    return 1
  }
  if validate_supported_poc_dimensions_pass \
    "$allocation_missing_receipt_output/poc-gates.json"; then
    printf 'supported PoC dimensions passed missing sampled-allocation publication receipt\n' >&2
    return 1
  fi

  validate_poc_gate_schema "$stable_output/poc-gates.json" || {
    printf 'stable PoC source precontrol failed before Java evidence mutation\n' >&2
    return 1
  }
  cp -p -- "$stable_evidence" "$stable_evidence_backup" || return 1
  jq '.jfr.allocation_sample.weight_bytes += 1' \
    "$stable_evidence" \
    >"$mutated_gate"
  mv -T -- "$mutated_gate" \
    "$stable_evidence"
  if validate_poc_gate_schema "$stable_output/poc-gates.json"; then
    printf 'PoC validator accepted stale sampled-allocation source evidence\n' >&2
    return 1
  fi
  mv -T -- "$stable_evidence_backup" "$stable_evidence" || return 1
  validate_poc_gate_schema "$stable_output/poc-gates.json" || {
    printf 'stable PoC source did not recover after Java evidence restoration\n' >&2
    return 1
  }

  prepare_poc_gate_fixture "$TEST_TMP_DIR/poc-gate-allocation-duplicate-source"
  compact="$(jq -c . \
    "$OUTPUT_DIR/cells/getsockopt-hit/java-measurement/evidence.json")" || return 1
  mutated_json="${compact/\"cell\":\"getsockopt-hit\"/\"cell\":\"getsockopt-hit\",\"cell\":\"getsockopt-hit\"}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" \
    >"$OUTPUT_DIR/cells/getsockopt-hit/java-measurement/evidence.json"
  write_poc_gate_summary
  jq -e '.sampled_allocation.status == "partial" and
    (.sampled_allocation.observations[] | select(.cell == "getsockopt-hit") |
      .status == "not_available")' "$OUTPUT_DIR/poc-gates.json" >/dev/null || {
    printf 'duplicate sampled-allocation evidence key did not fail closed\n' >&2
    return 1
  }

  validate_poc_gate_schema "$stable_output/poc-gates.json" || {
    printf 'stable PoC source precontrol failed before cell status mutation\n' >&2
    return 1
  }
  jq '.completed_at = "2026-08-10T00:00:01Z"' \
    "$stable_output/cells/unix-hit/status.json" \
    >"$stable_output/cells/unix-hit/status.json.tmp"
  mv -T -- "$stable_output/cells/unix-hit/status.json.tmp" \
    "$stable_output/cells/unix-hit/status.json"
  if validate_poc_gate_schema "$stable_output/poc-gates.json"; then
    printf 'PoC validator accepted an artifact stale against a retained cell status\n' >&2
    return 1
  fi
)

test_terminal_poc_publication_revalidates_sampled_allocation_receipts() (
  local -r allocation_receipt_stable_failed_output="$TEST_TMP_DIR/poc-gate-allocation-receipt-stable-failed"
  local -r allocation_receipt_stable_passed_output="$TEST_TMP_DIR/poc-gate-allocation-receipt-stable-passed"
  local -r allocation_receipt_drift_failed_output="$TEST_TMP_DIR/poc-gate-allocation-receipt-drift-failed"
  local -r allocation_receipt_drift_passed_output="$TEST_TMP_DIR/poc-gate-allocation-receipt-drift-passed"
  local -r allocation_post_entry_status_drift_output="$TEST_TMP_DIR/poc-gate-allocation-post-entry-status-drift"
  local -r allocation_manifest_visibility_drift_output="$TEST_TMP_DIR/poc-gate-allocation-manifest-visibility-drift"
  local -r terminal_malformed_ack_output="$TEST_TMP_DIR/terminal-malformed-manifest-ack"
  local -r terminal_timeout_ack_output="$TEST_TMP_DIR/terminal-timeout-manifest-ack"
  local cell=""
  local production_commit_definition=""
  local production_writer_definition=""
  local terminal_commit_test_mode="normal"
  local terminal_commit_test_path=""
  local terminal_commit_test_marker=""
  local terminal_commit_test_reaped_pid=""
  local terminal_status_drift_output=""
  local terminal_status_drift_fired=false

  # Keep the focused fixture's simulated tree digest authoritative, and expose
  # the same aggregate runtime attestation field as the production bundle.
  validate_published_java_measurement() {
    # shellcheck disable=SC2317 # Dynamically called by the sourced summary builder.
    local -r cell_dir="$1"
    local -r output_name="${2:-}"
    local -r receipt="$cell_dir/java-measurement-publication.json"
    local fixture_bundle=""

    [[ "$(jq -er '.tree_manifest_sha256' "$receipt")" == \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]] || return 1
    validate_sampled_allocation_fixture_with_bundle \
      "$cell_dir" fixture_bundle || return 1
    fixture_bundle="$(printf '%s' "$fixture_bundle" | jq -c '
      .runtime_artifact_attestation_sha256 =
        .evidence.runtime_artifacts.attestation_sha256
    ')" || return 1
    if [[ -n "$output_name" ]]; then
      printf -v "$output_name" '%s' "$fixture_bundle"
    fi
  }
  production_writer_definition="$(declare -f write_poc_gate_summary)" || return 1
  eval "${production_writer_definition/write_poc_gate_summary/production_write_poc_gate_summary}"
  production_commit_definition="$(declare -f terminal_publication_commit)" || return 1
  eval "${production_commit_definition/terminal_publication_commit/production_terminal_publication_commit}"

  terminal_publication_commit() {
    # shellcheck disable=SC2317 # Test-only native commit acknowledgement seam.
    local helper_pid="$TERMINAL_SOURCE_HELPER_PID"
    local helper_executable=""
    local response=""
    local wait_status=0

    if [[ "$terminal_commit_test_mode" == normal ]]; then
      production_terminal_publication_commit
      return
    fi
    [[ "$TERMINAL_SOURCE_SESSION_PREPARED" == true &&
      "$TERMINAL_PUBLICATION_STARTED" == false &&
      "$helper_pid" =~ ^[1-9][0-9]*$ ]] || return 1
    helper_executable="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "/proc/$helper_pid/exe")" || return 1
    [[ "$helper_executable" == "$NATIVE_BENCHMARK_PERL_COMMAND" ]] || return 1
    json_publication_absence_ready "$OUTPUT_DIR/poc-gates.json" || return 1
    json_publication_absence_ready "$OUTPUT_DIR/manifest.json" || return 1
    json_publication_absence_ready "$OUTPUT_DIR/summary.json" || return 1
    TERMINAL_PUBLICATION_STARTED=true
    printf 'K:COMMIT\n' >&"$TERMINAL_SOURCE_RECORD_FD" || return 1
    IFS= read -r response <&"$TERMINAL_SOURCE_RESPONSE_FD" || return 1
    [[ "$response" == M:LINKED ]] || return 1
    case "$terminal_commit_test_mode" in
      source-drift)
        printf 'terminal source changed after manifest acknowledgement\n' \
          >"$terminal_commit_test_path" || return 1
        printf 'mutated\n' >"$terminal_commit_test_marker" || return 1
        printf 'M:CONTINUE\n' >&"$TERMINAL_SOURCE_RECORD_FD" || return 1
        ;;
      malformed-ack)
        printf 'M:MALFORMED\n' >&"$TERMINAL_SOURCE_RECORD_FD" || return 1
        ;;
      timeout-ack)
        kill -ALRM "$helper_pid" || return 1
        ;;
      *) return 1 ;;
    esac
    exec {TERMINAL_SOURCE_RECORD_FD}>&- || true
    exec {TERMINAL_SOURCE_RESPONSE_FD}<&- || true
    if wait "$helper_pid"; then
      wait_status=0
    else
      wait_status=$?
    fi
    terminal_commit_test_reaped_pid="$helper_pid"
    terminal_publication_session_clear
    ((wait_status == 0))
  }

  validate_docker_daemon_provenance() {
    # shellcheck disable=SC2317 # Test-only terminal-summary dependency.
    local -r artifact="$1"
    local -r output_name="${2:-}"
    local status_file=""
    local temporary=""
    local artifact_value=""

    [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
    bounded_duplicate_free_json_value \
      "$artifact" "$MAX_BOUNDARY_SNAPSHOT_BYTES" artifact_value || return 1
    if [[ -n "$terminal_status_drift_output" &&
      "$artifact" == "$terminal_status_drift_output/docker-daemon.json" ]]; then
      status_file="$terminal_status_drift_output/cells/unix-hit/status.json"
      temporary="$status_file.tmp"
      jq '.completed_at = "2026-08-21T00:00:00Z"' \
        "$status_file" >"$temporary" || return 1
      mv -T -- "$temporary" "$status_file" || return 1
      terminal_status_drift_fired=true
    fi
    if [[ -n "$output_name" ]]; then
      printf -v "$output_name" '%s' \
        '{"status":"verified_local_unix_socket_endpoint_only"}'
    fi
  }
  validate_application_source_identity_schema() {
    # shellcheck disable=SC2317 # Test-only terminal-summary dependency.
    local -r artifact="$1"
    local -r output_name="${4:-}"
    local artifact_value=""
    local checkout=""
    local revision=""
    local git_tree=""
    local cell=""
    local manifest_value=""
    local reference_manifest_value=""
    local source_tree_sha256=""
    local source_value=""

    [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
    bounded_duplicate_free_json_value "$artifact" \
      "$MAX_APPLICATION_SOURCE_IDENTITY_BYTES" artifact_value || return 1
    checkout="${artifact%/*}/checkout-fixture"
    revision="$(git -C "$checkout" rev-parse HEAD)" || return 1
    git_tree="$(git -C "$checkout" rev-parse 'HEAD^{tree}')" || return 1
    for cell in "${CORE_CELLS[@]}"; do
      capture_bounded_regular_file_value \
        "${artifact%/*}/cells/$cell/preflight/runner/source-tree.manifest" \
        "$MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES" manifest_value || return 1
      if [[ -z "$reference_manifest_value" ]]; then
        reference_manifest_value="$manifest_value"
      else
        [[ "$manifest_value" == "$reference_manifest_value" ]] || return 1
      fi
    done
    source_tree_sha256="$(json_value_sha256 "$reference_manifest_value")" || return 1
    terminal_record_git_checkout_authority \
      "$checkout" "$revision" "$git_tree" "$source_tree_sha256" || return 1
    if [[ -n "$output_name" ]]; then
      source_value="$(jq -cn \
        --arg revision "$revision" --arg git_tree "$git_tree" \
        --arg source_tree_sha256 "$source_tree_sha256" \
        '{cells_mode:"core",revision:$revision,git_tree:$git_tree,
          source_tree_sha256:$source_tree_sha256}')" || return 1
      printf -v "$output_name" '%s' "$source_value"
    fi
  }
  validate_exact_owned_cgroup_sockopt_runtime() {
    # shellcheck disable=SC2317 # Test-only terminal-summary dependency.
    local -r artifact="$1"
    local -r output_name="${2:-}"

    [[ -f "$artifact" && ! -L "$artifact" ]] || return 1
    if [[ -n "$output_name" ]]; then
      printf -v "$output_name" '%s' '{"status":"complete"}'
    fi
  }
  prepare_terminal_allocation_fixture() {
    # shellcheck disable=SC2317 # Called below within this test subshell.
    local -r output="$1"
    local -r requested_status="$2"
    local cell=""

    reset_options
    prepare_poc_gate_fixture "$output" || return 1
    if [[ "$requested_status" == failed ]]; then
      rewrite_cell_performance_fixture getsockopt-hit 100 111 || return 1
    else
      printf '{}\n' >"$output/docker-daemon.json" || return 1
      printf '{}\n' >"$output/application-source-identity.json" || return 1
      mkdir -- "$output/checkout-fixture" || return 1
      git -c init.defaultBranch=main -C "$output/checkout-fixture" init -q || return 1
      git -C "$output/checkout-fixture" config user.email test@example.invalid || return 1
      git -C "$output/checkout-fixture" config user.name Test || return 1
      printf 'terminal source\n' >"$output/checkout-fixture/tracked.txt" || return 1
      git -C "$output/checkout-fixture" add tracked.txt || return 1
      GIT_AUTHOR_DATE=2001-01-01T00:00:00Z \
        GIT_COMMITTER_DATE=2001-01-01T00:00:00Z \
        git -c commit.gpgsign=false -C "$output/checkout-fixture" \
          commit -qm initial || return 1
      write_git_tree_manifest_for_tree "$output/checkout-fixture" \
        "$(git -C "$output/checkout-fixture" rev-parse 'HEAD^{tree}')" \
        "$output/source-tree.manifest" || return 1
      for cell in "${CORE_CELLS[@]}"; do
        mkdir -p -- "$output/cells/$cell/preflight/runner" || return 1
        command cp -- "$output/source-tree.manifest" \
          "$output/cells/$cell/preflight/runner/source-tree.manifest" || return 1
        printf '{}\n' >"$output/cells/$cell/bpf-program-runtime.json" || return 1
      done
    fi
    production_write_poc_gate_summary
  }
  mutate_terminal_allocation_receipt() {
    # shellcheck disable=SC2317 # Called below within this test subshell.
    local -r output="$1"
    local -r receipt="$output/cells/getsockopt-hit/java-measurement-publication.json"
    local -r temporary="$receipt.tmp"

    jq '.tree_manifest_sha256 =
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
      "$receipt" >"$temporary" || return 1
    mv -T -- "$temporary" "$receipt"
  }

  prepare_terminal_ack_failure_fixture() {
    # shellcheck disable=SC2317 # Called below within this test subshell.
    local -r output="$1"

    reset_options
    OUTPUT_DIR="$output"
    # shellcheck disable=SC2034 # Consumed by write_summary from the sourced harness.
    OUTPUT_READY=true
    mkdir -p -- "$output/cells" || return 1
    write_valid_in_progress_manifest_fixture
  }

  prepare_terminal_allocation_fixture \
    "$allocation_receipt_stable_failed_output" failed
  write_summary failed || {
    printf 'stable failed summary could not publish its terminal PoC transaction\n' >&2
    return 1
  }
  [[ -f "$allocation_receipt_stable_failed_output/poc-gates.json" &&
    -f "$allocation_receipt_stable_failed_output/manifest.json" &&
    -f "$allocation_receipt_stable_failed_output/summary.json" ]] || {
    printf 'stable failed summary omitted a terminal PoC transaction leaf\n' >&2
    return 1
  }
  validate_summary_artifact_receipts \
    "$allocation_receipt_stable_failed_output/summary.json" \
    "$allocation_receipt_stable_failed_output" || return 1

  prepare_terminal_allocation_fixture \
    "$allocation_receipt_stable_passed_output" passed
  write_summary passed || {
    printf 'stable passed summary could not publish its terminal PoC transaction\n' >&2
    return 1
  }
  [[ -f "$allocation_receipt_stable_passed_output/poc-gates.json" &&
    -f "$allocation_receipt_stable_passed_output/manifest.json" &&
    -f "$allocation_receipt_stable_passed_output/summary.json" ]] || {
    printf 'stable passed summary omitted a terminal PoC transaction leaf\n' >&2
    return 1
  }
  validate_summary_artifact_receipts \
    "$allocation_receipt_stable_passed_output/summary.json" \
    "$allocation_receipt_stable_passed_output" || return 1

  prepare_terminal_allocation_fixture \
    "$allocation_post_entry_status_drift_output" passed
  terminal_status_drift_output="$allocation_post_entry_status_drift_output"
  terminal_status_drift_fired=false
  if write_summary passed >/dev/null 2>&1; then
    printf 'passed summary accepted status drift after entry PoC revalidation\n' >&2
    return 1
  fi
  [[ "$terminal_status_drift_fired" == true &&
    "$(jq -er '.completed_at' \
      "$allocation_post_entry_status_drift_output/cells/unix-hit/status.json")" == \
      2026-08-21T00:00:00Z ]] || {
    printf 'post-entry status-drift hook did not reach the terminal validation window\n' >&2
    return 1
  }
  if validate_poc_gate_json_value_against_root \
    "$POC_GATE_HELD_VALUE" "$allocation_post_entry_status_drift_output" \
    >/dev/null 2>&1; then
    printf 'no-override PoC validation accepted post-entry cell-status drift\n' >&2
    return 1
  fi
  [[ ! -e "$allocation_post_entry_status_drift_output/poc-gates.json" &&
    ! -L "$allocation_post_entry_status_drift_output/poc-gates.json" &&
    ! -e "$allocation_post_entry_status_drift_output/manifest.json" &&
    ! -L "$allocation_post_entry_status_drift_output/manifest.json" &&
    ! -e "$allocation_post_entry_status_drift_output/summary.json" &&
    ! -L "$allocation_post_entry_status_drift_output/summary.json" ]] || {
    printf 'passed summary linked a terminal leaf after post-entry source drift\n' >&2
    return 1
  }
  terminal_status_drift_output=""
  terminal_status_drift_fired=false

  # The native commit helper acknowledges manifest.json through its anonymous
  # protocol before its final complete G sweep. Mutating the checkout before
  # that acknowledgement is continued deterministically exercises the final
  # authority boundary without relying on process scheduling or path polling.
  prepare_terminal_allocation_fixture \
    "$allocation_manifest_visibility_drift_output" passed
  terminal_commit_test_mode="source-drift"
  terminal_commit_test_path="$allocation_manifest_visibility_drift_output/checkout-fixture/tracked.txt"
  terminal_commit_test_marker="$allocation_manifest_visibility_drift_output/visibility-mutator.marker"
  terminal_commit_test_reaped_pid=""
  if write_summary passed >/dev/null 2>&1; then
    printf 'terminal helper accepted checkout drift after manifest visibility\n' >&2
    return 1
  fi
  [[ -f "$allocation_manifest_visibility_drift_output/visibility-mutator.marker" &&
    -f "$allocation_manifest_visibility_drift_output/manifest.json" &&
    ! -e "$allocation_manifest_visibility_drift_output/summary.json" &&
    ! -L "$allocation_manifest_visibility_drift_output/summary.json" &&
    "$terminal_commit_test_reaped_pid" =~ ^[1-9][0-9]*$ &&
    ! -e "/proc/$terminal_commit_test_reaped_pid" &&
    -z "$TERMINAL_SOURCE_HELPER_PID" ]] || {
    printf 'manifest-visibility source drift missed the final G sweep boundary\n' >&2
    return 1
  }
  terminal_commit_test_mode=normal
  terminal_commit_test_path=""
  terminal_commit_test_marker=""
  terminal_commit_test_reaped_pid=""

  # Missing or malformed acknowledgement cannot advance the native commit
  # beyond its already-linked terminal manifest. Injected SIGALRM exercises
  # the same bounded timeout handler without adding a minute to this selector.
  for terminal_commit_test_mode in malformed-ack timeout-ack; do
    if [[ "$terminal_commit_test_mode" == malformed-ack ]]; then
      OUTPUT_DIR="$terminal_malformed_ack_output"
    else
      OUTPUT_DIR="$terminal_timeout_ack_output"
    fi
    prepare_terminal_ack_failure_fixture "$OUTPUT_DIR" || return 1
    terminal_commit_test_reaped_pid=""
    if write_summary failed >/dev/null 2>&1; then
      printf 'terminal helper accepted %s at the manifest acknowledgement\n' \
        "$terminal_commit_test_mode" >&2
      return 1
    fi
    [[ -f "$OUTPUT_DIR/manifest.json" && ! -L "$OUTPUT_DIR/manifest.json" &&
      ! -e "$OUTPUT_DIR/poc-gates.json" && ! -L "$OUTPUT_DIR/poc-gates.json" &&
      ! -e "$OUTPUT_DIR/summary.json" && ! -L "$OUTPUT_DIR/summary.json" &&
      "$terminal_commit_test_reaped_pid" =~ ^[1-9][0-9]*$ &&
      ! -e "/proc/$terminal_commit_test_reaped_pid" &&
      -z "$TERMINAL_SOURCE_HELPER_PID" ]] || {
      printf 'terminal %s did not retain only an honest manifest residue and reap\n' \
        "$terminal_commit_test_mode" >&2
      return 1
    }
  done
  terminal_commit_test_mode=normal
  OUTPUT_DIR="$allocation_manifest_visibility_drift_output"

  prepare_terminal_allocation_fixture \
    "$allocation_receipt_drift_failed_output" failed
  mutate_terminal_allocation_receipt \
    "$allocation_receipt_drift_failed_output"
  if validate_poc_gate_json_value_against_root \
    "$POC_GATE_HELD_VALUE" "$allocation_receipt_drift_failed_output" \
    >/dev/null 2>&1; then
    printf 'no-override PoC validation accepted failed-run receipt drift\n' >&2
    return 1
  fi
  if write_summary failed >/dev/null 2>&1; then
    printf 'failed summary accepted terminal sampled-allocation receipt drift\n' >&2
    return 1
  fi
  [[ ! -e "$allocation_receipt_drift_failed_output/poc-gates.json" &&
    ! -L "$allocation_receipt_drift_failed_output/poc-gates.json" &&
    ! -e "$allocation_receipt_drift_failed_output/manifest.json" &&
    ! -L "$allocation_receipt_drift_failed_output/manifest.json" &&
    ! -e "$allocation_receipt_drift_failed_output/summary.json" &&
    ! -L "$allocation_receipt_drift_failed_output/summary.json" ]] || {
    printf 'failed summary linked a terminal leaf after sampled-allocation receipt drift\n' >&2
    return 1
  }

  prepare_terminal_allocation_fixture \
    "$allocation_receipt_drift_passed_output" passed
  mutate_terminal_allocation_receipt \
    "$allocation_receipt_drift_passed_output"
  if validate_poc_gate_json_value_against_root \
    "$POC_GATE_HELD_VALUE" "$allocation_receipt_drift_passed_output" \
    >/dev/null 2>&1; then
    printf 'no-override PoC validation accepted passed-run receipt drift\n' >&2
    return 1
  fi
  if write_summary passed >/dev/null 2>&1; then
    printf 'passed summary accepted terminal sampled-allocation receipt drift\n' >&2
    return 1
  fi
  [[ ! -e "$allocation_receipt_drift_passed_output/poc-gates.json" &&
    ! -L "$allocation_receipt_drift_passed_output/poc-gates.json" &&
    ! -e "$allocation_receipt_drift_passed_output/manifest.json" &&
    ! -L "$allocation_receipt_drift_passed_output/manifest.json" &&
    ! -e "$allocation_receipt_drift_passed_output/summary.json" &&
    ! -L "$allocation_receipt_drift_passed_output/summary.json" ]] || {
    printf 'passed summary linked a terminal leaf after sampled-allocation receipt drift\n' >&2
    return 1
  }
)

test_summary_resource_scope_is_independent_of_nonresource_failures() (
  local -r performance_output="$TEST_TMP_DIR/summary-performance-only-failure"
  local -r correctness_output="$TEST_TMP_DIR/summary-correctness-only-failure"
  local -r process_output="$TEST_TMP_DIR/summary-process-growth-failure"
  local -r summary_backup="$TEST_TMP_DIR/summary-cross-binding.valid.json"
  local -r summary_mutated="$TEST_TMP_DIR/summary-cross-binding.mutated.json"

  reset_options
  prepare_poc_gate_fixture "$performance_output"
  rewrite_cell_performance_fixture getsockopt-hit 100 111
  write_poc_gate_summary
  write_summary failed

  reset_options
  prepare_poc_gate_fixture "$correctness_output"
  jq '.status = "failed" | .reason = "fixture_correctness_failure"' \
    "$correctness_output/cells/unix-hit/status.json" \
    >"$correctness_output/cells/unix-hit/status.json.tmp"
  mv -T -- "$correctness_output/cells/unix-hit/status.json.tmp" \
    "$correctness_output/cells/unix-hit/status.json"
  write_poc_gate_summary
  write_summary failed

  reset_options
  prepare_poc_gate_fixture "$process_output"
  write_proc_growth_fixture \
    "$process_output/cells/getsockopt-hit/resources-idle-recovery-02/java-backend-proc.txt" \
    109 21 8
  write_poc_gate_summary
  write_summary failed

  jq -e '
    .performance.result == "failed" and
    .correctness.result == "passed" and
    .resources.status == "complete" and .resources.result == "passed" and
    .resources.process_dimension == {status: "complete", result: "passed"} and
    (.resources.process_tree | .status == "complete" and .result == "passed") and
    (.resources.application_cpu | .status == "complete" and .result == "passed")
  ' "$performance_output/poc-gates.json" >/dev/null || {
    printf 'performance-only fixture did not isolate its gate failure\n' >&2
    return 1
  }
  jq -e '
    .performance.result == "passed" and
    .correctness.result == "failed" and
    .resources.status == "complete" and .resources.result == "passed" and
    .resources.process_dimension == {status: "complete", result: "passed"} and
    (.resources.process_tree | .status == "complete" and .result == "passed") and
    (.resources.application_cpu | .status == "complete" and .result == "passed")
  ' "$correctness_output/poc-gates.json" >/dev/null || {
    printf 'correctness-only fixture did not isolate its gate failure\n' >&2
    return 1
  }
  jq -se '
    length == 2 and all(.[0:2][];
      .status == "failed" and .poc_gates.result == "failed" and
      (.measurement_scope.application_fd_threads_and_java_bridge_map_growth |
        .status == "complete" and .result == "passed" and
        .process_fd_threads == {status: "complete", result: "passed"} and
        .java_bridge_map == {
          status: "complete",
          result: "passed",
          reason: null,
          descriptive_data_status: "complete"
        } and
        (.full_cgroup_v2_process_tree_fd_task_rss |
          .status == "complete" and .result == "passed") and
        (.application_cpu_per_successful_request |
          .status == "complete" and .result == "passed")))
  ' "$performance_output/summary.json" "$correctness_output/summary.json" \
    >/dev/null || {
    printf 'summary misattributed a nonresource failure to resource growth\n' >&2
    return 1
  }
  jq -e '
    .status == "failed" and .poc_gates.result == "failed" and
    (.measurement_scope.application_fd_threads_and_java_bridge_map_growth |
      .status == "complete" and .result == "failed" and
      .process_fd_threads == {status: "complete", result: "failed"} and
      .java_bridge_map == {
        status: "complete",
        result: "passed",
        reason: null,
        descriptive_data_status: "complete"
      } and
      (.full_cgroup_v2_process_tree_fd_task_rss |
        .status == "complete" and .result == "passed") and
      (.application_cpu_per_successful_request |
        .status == "complete" and .result == "passed"))
  ' "$process_output/summary.json" >/dev/null || {
    printf 'summary did not attribute an evaluated process-growth failure to resources\n' >&2
    return 1
  }
  validate_summary_artifact_receipts \
    "$performance_output/summary.json" "$performance_output" || return 1
  cp -p -- "$performance_output/summary.json" "$summary_backup" || return 1
  jq -cS '.status = "passed"' "$summary_backup" >"$summary_mutated" || return 1
  mv -T -- "$summary_mutated" "$performance_output/summary.json" || return 1
  if validate_summary_artifact_receipts \
    "$performance_output/summary.json" "$performance_output" >/dev/null 2>&1; then
    printf 'summary validator accepted status drift from terminal manifest\n' >&2
    return 1
  fi
  cp -p -- "$summary_backup" "$performance_output/summary.json" || return 1
  jq -cS '.poc_gates.result = "not_evaluated"' \
    "$summary_backup" >"$summary_mutated" || return 1
  mv -T -- "$summary_mutated" "$performance_output/summary.json" || return 1
  if validate_summary_artifact_receipts \
    "$performance_output/summary.json" "$performance_output" >/dev/null 2>&1; then
    printf 'summary validator accepted a PoC result drift with intact receipts\n' >&2
    return 1
  fi
  cp -p -- "$summary_backup" "$performance_output/summary.json" || return 1
  jq -cS '.cells[0].completed_at = "2026-08-21T00:00:01Z"' \
    "$summary_backup" >"$summary_mutated" || return 1
  mv -T -- "$summary_mutated" "$performance_output/summary.json" || return 1
  if validate_summary_artifact_receipts \
    "$performance_output/summary.json" "$performance_output" >/dev/null 2>&1; then
    printf 'summary validator accepted cell-status drift from retained PoC\n' >&2
    return 1
  fi
  cp -p -- "$summary_backup" "$performance_output/summary.json" || return 1
  jq -cS '.measurement_scope.primary_cgroupsockopt_program_cpu = "collected"' \
    "$summary_backup" >"$summary_mutated" || return 1
  mv -T -- "$summary_mutated" "$performance_output/summary.json" || return 1
  if validate_summary_artifact_receipts \
    "$performance_output/summary.json" "$performance_output" >/dev/null 2>&1; then
    printf 'summary validator accepted forbidden primary-program CPU collection drift\n' >&2
    return 1
  fi
  cp -p -- "$summary_backup" "$performance_output/summary.json" || return 1
)

test_failed_complete_summary_reports_requested_artifact_state() (
  local -r unavailable_output="$TEST_TMP_DIR/failed-complete-artifacts-unavailable"
  local -r available_output="$TEST_TMP_DIR/failed-complete-artifacts-available"
  local revision=""

  reset_options
  OUTPUT_DIR="$unavailable_output"
  OUTPUT_READY=true
  CELLS_MODE=complete
  mkdir -p -- "$OUTPUT_DIR/cells"
  write_valid_in_progress_manifest_fixture
  write_summary failed
  jq -e '
    .status == "failed" and
    .lookup_paths == {status: "requested_but_unavailable", path: null} and
    .native_jni_lookup == {status: "requested_but_unavailable", path: null} and
    .measurement_scope.pressure_map_occupancy_and_capacity_rejection ==
      "requested_but_unavailable"
  ' "$OUTPUT_DIR/summary.json" >/dev/null || {
    printf 'failed complete summary relabelled requested artifacts as not requested\n' >&2
    return 1
  }

  reset_options
  OUTPUT_DIR="$available_output"
  OUTPUT_READY=true
  CELLS_MODE=complete
  mkdir -p -- "$OUTPUT_DIR/cells"
  write_valid_in_progress_manifest_fixture
  revision="$(git -C "$REPO_ROOT" rev-parse HEAD)" || return 1
  write_normalized_native_jni_artifact_fixture \
    "$OUTPUT_DIR/native-jni/benchmark.json" "$revision"
  write_lookup_path_summary_fixture "$OUTPUT_DIR/lookup-paths.json"
  write_summary failed
  jq -e '
    .status == "failed" and
    .lookup_paths == {status: "available", path: "lookup-paths.json"} and
    .native_jni_lookup == {status: "available", path: "native-jni/benchmark.json"} and
    .measurement_scope.pressure_map_occupancy_and_capacity_rejection ==
      "bounded_correctness_observed_once"
  ' "$OUTPUT_DIR/summary.json" >/dev/null || {
    printf 'failed complete summary did not link valid retained artifacts\n' >&2
    return 1
  }
  [[ -f "$OUTPUT_DIR/lookup-paths.json" &&
    -f "$OUTPUT_DIR/native-jni/benchmark.json" ]] || {
    printf 'failed complete summary removed valid retained artifacts\n' >&2
    return 1
  }
)

test_summary_rejects_invalid_variance_after_failure() (
  local -r output="$TEST_TMP_DIR/failed-variance-summary"

  reset_options
  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Consumed by write_summary from the sourced harness.
  OUTPUT_READY=true
  mkdir -p -- "$output/cells"
  write_valid_in_progress_manifest_fixture
  if write_summary passed >/dev/null 2>&1; then
    printf 'passed summary accepted a missing variance artifact\n' >&2
    return 1
  fi
  jq -n '{status: "complete"}' >"$output/variance.json"
  if write_summary failed >/dev/null 2>&1; then
    printf 'failed summary downgraded a capturable invalid variance artifact\n' >&2
    return 1
  fi
  [[ -f "$output/variance.json" && ! -L "$output/variance.json" &&
    ! -e "$output/poc-gates.json" && ! -L "$output/poc-gates.json" &&
    ! -e "$output/manifest.json" && ! -L "$output/manifest.json" &&
    ! -e "$output/summary.json" && ! -L "$output/summary.json" ]] || {
    printf 'failed summary changed state after invalid variance rejection\n' >&2
    return 1
  }
)

test_failed_summary_refuses_unremovable_variance() (
  local -r output="$TEST_TMP_DIR/unremovable-variance-summary"

  reset_options
  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Consumed by write_summary from the sourced harness.
  OUTPUT_READY=true
  mkdir -p -- "$output/variance.json"
  if write_summary failed >/dev/null 2>&1; then
    printf 'failed summary accepted an unremovable variance artifact\n' >&2
    return 1
  fi
  [[ -d "$output/variance.json" && ! -e "$output/summary.json" ]] || {
    printf 'failed summary changed state after variance cleanup failed\n' >&2
    return 1
  }
)

test_on_exit_rewrites_failed_summary_after_passed_summary_error() {
  local -r calls="$TEST_TMP_DIR/on-exit-summary-calls.txt"
  local on_exit_status=0

  if (
    reset_options
    # shellcheck disable=SC2034 # Consumed by on_exit from the sourced harness.
    HARNESS_STATUS=passed
    write_summary() {
      printf '%s\n' "$1" >>"$calls"
      [[ "$1" == "failed" ]]
    }
    on_exit 0
  ); then
    printf 'on_exit accepted a failed passed-summary finalization\n' >&2
    return 1
  else
    on_exit_status=$?
  fi
  [[ "$on_exit_status" == 1 && "$(<"$calls")" == $'passed\nfailed' ]] || {
    printf 'on_exit did not rewrite the summary after passed finalization failed\n' >&2
    return 1
  }
}

test_summary_rejects_manifest_render_failure() (
  local -r output="$TEST_TMP_DIR/manifest-render-failure"

  reset_options
  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Consumed by write_summary from the sourced harness.
  OUTPUT_READY=true
  mkdir -p -- "$output/cells"
  write_valid_in_progress_manifest_fixture
  manifest_json() {
    # shellcheck disable=SC2317 # Dynamically called by sourced write_summary.
    return 1
  }
  if write_summary failed >/dev/null 2>&1; then
    printf 'summary accepted a failed manifest render\n' >&2
    return 1
  fi
  command jq -e '.status == "in_progress"' \
    "$output/manifest.in-progress.json" >/dev/null || {
    printf 'summary changed the manifest after its render failed\n' >&2
    return 1
  }
  [[ ! -e "$output/summary.json" && ! -L "$output/summary.json" &&
    -z "$(find "$output" -maxdepth 1 \
      \( -name '.summary.json.*' -o -name '.manifest.json.*' \) -print -quit)" ]] || {
    printf 'summary retained an artifact after its manifest render failed\n' >&2
    return 1
  }
)

test_summary_publishes_completion_marker_last() (
  local -r output="$TEST_TMP_DIR/summary-publication-order"

  reset_options
  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Consumed by write_summary from the sourced harness.
  OUTPUT_READY=true
  mkdir -p -- "$output/cells"
  write_valid_in_progress_manifest_fixture
  json_publication_target_ready() {
    case "$1" in
      "$output/manifest.json")
        command jq -e '.status == "in_progress"' \
          "$output/manifest.in-progress.json" >/dev/null || return 1
        [[ ! -e "$output/summary.json" && ! -L "$output/summary.json" ]] || return 1
        ;;
      "$output/summary.json")
        command jq -e '.status == "failed"' "$output/manifest.json" >/dev/null || return 1
        ;;
    esac
  }
  write_summary failed || {
    printf 'summary did not publish its completion marker last\n' >&2
    return 1
  }
  command jq -e '.status == "failed"' "$output/summary.json" >/dev/null &&
    command jq -e '.status == "failed"' "$output/manifest.json" >/dev/null || {
    printf 'summary did not retain matching terminal artifacts\n' >&2
    return 1
  }
)

test_terminal_source_authority_protocol_is_bounded_and_held() (
  local -r protocol_root="$TEST_TMP_DIR/terminal-source-authority"
  local definition=""
  local manifest_value='{"predeclared_poc_gates":{"fixture":true}}'
  local manifest_predeclared=""
  local manifest_digest=""
  local poc_value=""
  local mutation=""
  local rejected_helper_pid=""

  prepare_terminal_protocol_output() {
    # shellcheck disable=SC2317 # Called by the isolated protocol fixtures below.
    local -r output="$1"

    reset_options
    mkdir --mode=0700 -- "$output" || return 1
    chmod 0700 -- "$output" || return 1
    OUTPUT_DIR="$output"
    # shellcheck disable=SC2034 # Consumed dynamically by the sourced helper.
    OUTPUT_DIR_IDENTITY="$(stat --format '%d:%i:%u:%g:%a' -- \
      "$OUTPUT_DIR")" || return 1
    OUTPUT_READY=true
  }

  run_terminal_protocol_capability_fixture() (
    local -r output="$protocol_root/capability"
    local -r exec_shadow_marker="$protocol_root/capability-exec-shadow.marker"
    local helper_executable=""
    local helper_pid=""

    prepare_terminal_protocol_output "$output"
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    ulimit -n "$MIN_TERMINAL_SOURCE_NOFILE_LIMIT"
    # Deliberately uncalled: the coprocess must use POSIX special-builtin exec.
    # shellcheck disable=SC2120
    exec() {
      (($# == 0)) && return 0
      : >"$exec_shadow_marker"
      return 93
    }
    export -f exec
    terminal_publication_session_begin || return 1
    unset -f exec
    helper_pid="$TERMINAL_SOURCE_HELPER_PID"
    helper_executable="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "/proc/$helper_pid/exe")" || return 1
    [[ "$helper_executable" == "$NATIVE_BENCHMARK_PERL_COMMAND" &&
      ! -e "$exec_shadow_marker" && ! -L "$exec_shadow_marker" ]] || {
      printf 'terminal coprocess PID did not name the native Perl authority\n' >&2
      return 1
    }
    if compgen -G "$output/.obi-terminal-linkat-probe-*" >/dev/null; then
      printf 'terminal capability check retained its private linkat probe\n' >&2
      return 1
    fi
    terminal_publication_session_abort || return 1
    trap - EXIT
    [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == false &&
      -z "$TERMINAL_SOURCE_HELPER_PID" ]]
  )

  run_terminal_protocol_low_nofile_fixture() (
    local -r output="$protocol_root/low-nofile"

    prepare_terminal_protocol_output "$output"
    ulimit -n "$((MIN_TERMINAL_SOURCE_NOFILE_LIMIT - 1))"
    if terminal_publication_session_begin >/dev/null 2>&1; then
      printf 'terminal source helper accepted RLIMIT_NOFILE below its bound\n' >&2
      terminal_publication_session_abort || true
      return 1
    fi
    [[ "$TERMINAL_SOURCE_SESSION_ACTIVE" == false &&
      -z "$TERMINAL_SOURCE_HELPER_PID" ]]
  )

  run_terminal_protocol_leaf_limit_fixture() (
    local -r requested_count="$1"
    local -r expect_success="$2"
    local -r output="$protocol_root/leaves-$requested_count"
    local leaf=""
    local leaf_value=""
    local record_status=0
    local index=0

    prepare_terminal_protocol_output "$output"
    mkdir -- "$output/leaves"
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    for ((index = 1; index <= requested_count; index++)); do
      printf -v leaf '%s/leaves/leaf-%04d.txt' "$output" "$index"
      printf 'x' >"$leaf" || return 1
      capture_bounded_regular_file_value "$leaf" 1 leaf_value || {
        record_status=$?
        break
      }
      [[ "$leaf_value" == x ]] || return 1
    done
    if [[ "$expect_success" == true ]]; then
      ((record_status == 0)) || return 1
      terminal_publication_freeze_sources || return 1
      printf '%s' "$TERMINAL_SOURCE_ROSTER_VALUE" | jq -e \
        --argjson expected "$MAX_TERMINAL_SOURCE_LEAVES" '
        (.leaves | length) == $expected and
        (.negatives | length) == 0 and (.trees | length) == 0 and
        (.checkouts | length) == 0
      ' >/dev/null || return 1
    elif ((record_status == 0)) &&
      terminal_publication_freeze_sources >/dev/null 2>&1; then
      printf 'terminal helper accepted more than %s source leaves\n' \
        "$MAX_TERMINAL_SOURCE_LEAVES" >&2
      return 1
    fi
    terminal_publication_session_abort || return 1
    trap - EXIT
  )

  run_terminal_protocol_negative_limit_fixture() (
    local -r requested_count="$1"
    local -r expect_success="$2"
    local -r output="$protocol_root/negatives-$requested_count"
    local missing=""
    local record_status=0
    local index=0

    prepare_terminal_protocol_output "$output"
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    for ((index = 1; index <= requested_count; index++)); do
      printf -v missing '%s/missing-%04d.txt' "$output" "$index"
      terminal_record_source_negative "$missing" 1 absent || {
        record_status=$?
        break
      }
    done
    if [[ "$expect_success" == true ]]; then
      ((record_status == 0)) || return 1
      terminal_publication_freeze_sources || return 1
      printf '%s' "$TERMINAL_SOURCE_ROSTER_VALUE" | jq -e \
        --argjson expected "$MAX_TERMINAL_SOURCE_NEGATIVES" '
        (.negatives | length) == $expected and
        all(.negatives[]; .state == "absent")
      ' >/dev/null || return 1
    elif ((record_status == 0)) &&
      terminal_publication_freeze_sources >/dev/null 2>&1; then
      printf 'terminal helper accepted more than %s negative sources\n' \
        "$MAX_TERMINAL_SOURCE_NEGATIVES" >&2
      return 1
    fi
    terminal_publication_session_abort || return 1
    trap - EXIT
  )

  run_terminal_protocol_conflicting_repeat_fixture() (
    local -r output="$protocol_root/conflicting-repeat"
    local -r leaf="$output/source.txt"
    local leaf_value=""

    prepare_terminal_protocol_output "$output"
    printf 'x' >"$leaf"
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    capture_bounded_regular_file_value "$leaf" 1 leaf_value || return 1
    printf 'y' >"$leaf"
    capture_bounded_regular_file_value "$leaf" 1 leaf_value
    terminal_publication_freeze_sources
  )

  run_terminal_protocol_directory_swap_fixture() (
    local -r output="$protocol_root/directory-swap"
    local -r source_directory="$output/source"
    local -r saved_directory="$output/source.saved"
    local leaf_value=""

    prepare_terminal_protocol_output "$output"
    mkdir -- "$source_directory"
    printf 'x' >"$source_directory/value.txt"
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    capture_bounded_regular_file_value \
      "$source_directory/value.txt" 1 leaf_value || return 1
    mv -- "$source_directory" "$saved_directory" || return 1
    mkdir -- "$source_directory"
    printf 'x' >"$source_directory/value.txt"
    if terminal_publication_freeze_sources >/dev/null 2>&1; then
      printf 'terminal helper accepted a source-directory namespace swap\n' >&2
      return 1
    fi
    terminal_publication_session_abort || return 1
    trap - EXIT
  )

  run_terminal_protocol_missing_intermediate_fixture() (
    local -r mutation="$1"
    local -r output="$protocol_root/missing-intermediate-$mutation"
    local -r existing_parent="$output/existing"
    local -r missing_parent="$existing_parent/missing"
    local -r missing_leaf="$missing_parent/status.json"
    local -r saved_parent="$output/existing.saved"

    prepare_terminal_protocol_output "$output"
    mkdir -- "$existing_parent"
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    terminal_record_source_negative "$missing_leaf" 1 absent || return 1
    case "$mutation" in
      stable)
        terminal_publication_freeze_sources || return 1
        printf '%s' "$TERMINAL_SOURCE_ROSTER_VALUE" | jq -e '
          .negatives == [{
            root: "output",
            path: "existing/missing/status.json",
            maximum_bytes: 1,
            state: "absent",
            missing_path: "existing/missing",
            identity: null,
            size_bytes: null
          }]
        ' >/dev/null || return 1
        terminal_publication_session_abort || return 1
        trap - EXIT
        ;;
      create)
        mkdir -- "$missing_parent" || return 1
        terminal_publication_freeze_sources
        ;;
      swap)
        mv -- "$existing_parent" "$saved_parent" || return 1
        mkdir -- "$existing_parent" || return 1
        terminal_publication_freeze_sources
        ;;
      drift)
        rmdir -- "$existing_parent" || return 1
        terminal_publication_freeze_sources
        ;;
      *)
        return 1
        ;;
    esac
  )

  run_terminal_pressure_selector_fixture() (
    local -r include_extra="$1"
    local -r output="$protocol_root/pressure-selector-$include_extra"
    local -r runner="$output/preflight/runner"

    prepare_terminal_protocol_output "$output"
    mkdir -p -- "$runner"
    printf 'sample-01\n' \
      >"$runner/map-pressure-pressure-recovered-sample-01.prom"
    printf 'sample-02\n' \
      >"$runner/map-pressure-pressure-recovered-sample-02.prom"
    if [[ "$include_extra" == true ]]; then
      printf 'sample-03\n' \
        >"$runner/map-pressure-pressure-recovered-sample-03.prom"
    fi
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    terminal_record_directory_selector \
      "$runner" pressure-recovery-sample-prom || return 1
    terminal_publication_freeze_sources || return 1
    printf '%s' "$TERMINAL_SOURCE_ROSTER_VALUE" | jq -e '
      .directory_selectors == [{
        root: "output",
        path: "preflight/runner",
        selector: "pressure-recovery-sample-prom",
        identity: .directory_selectors[0].identity,
        names: [
          "map-pressure-pressure-recovered-sample-01.prom",
          "map-pressure-pressure-recovered-sample-02.prom"
        ]
      }]
    ' >/dev/null || return 1
    terminal_publication_session_abort || return 1
    trap - EXIT
  )

  run_terminal_git_checkout_fixture() (
    local -r mutation="$1"
    local -r output="$protocol_root/git-checkout-$mutation"
    local -r checkout="$output/checkout"
    local -r helper_pid_receipt="$protocol_root/git-checkout-$mutation.helper-pid"
    local revision=""
    local git_tree=""
    local manifest_value=""
    local manifest_digest=""
    local cell=""
    local runner_manifest_value=""
    local timestamp_reference="$output/tracked.timestamp"

    prepare_terminal_protocol_output "$output"
    mkdir -- "$checkout"
    git -c init.defaultBranch=main -C "$checkout" init -q
    git -C "$checkout" config user.email test@example.invalid
    git -C "$checkout" config user.name Test
    printf 'one\n' >"$checkout/tracked.txt"
    printf 'hostile name\n' >"$checkout/"$'line\nbreak\tname.txt'
    printf 'ignored-*.bin\n' >"$checkout/.gitignore"
    printf 'ignored\n' >"$checkout/ignored-one.bin"
    ln -s -- tracked.txt "$checkout/tracked-link"
    git -C "$checkout" add tracked.txt tracked-link .gitignore \
      "$checkout/"$'line\nbreak\tname.txt'
    GIT_AUTHOR_DATE=2001-01-01T00:00:00Z \
      GIT_COMMITTER_DATE=2001-01-01T00:00:00Z \
      git -c commit.gpgsign=false -C "$checkout" commit -qm initial
    revision="$(git -C "$checkout" rev-parse HEAD)" || return 1
    git_tree="$(git -C "$checkout" rev-parse 'HEAD^{tree}')" || return 1
    write_git_tree_manifest_for_tree \
      "$checkout" "$git_tree" "$output/source-tree.manifest" || return 1
    command cp -p -- "$checkout/tracked.txt" "$timestamp_reference" || return 1
    for cell in "${CORE_CELLS[@]}"; do
      mkdir -p -- "$output/cells/$cell/preflight/runner" || return 1
      command cp -- "$output/source-tree.manifest" \
        "$output/cells/$cell/preflight/runner/source-tree.manifest" || return 1
    done
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    for cell in "${CORE_CELLS[@]}"; do
      capture_bounded_regular_file_value \
        "$output/cells/$cell/preflight/runner/source-tree.manifest" \
        "$MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES" runner_manifest_value || return 1
      if [[ -z "$manifest_value" ]]; then
        manifest_value="$runner_manifest_value"
      else
        [[ "$runner_manifest_value" == "$manifest_value" ]] || return 1
      fi
    done
    manifest_digest="$(validate_recorded_git_tree_manifest_value \
      "$checkout" "$revision" "$git_tree" "$manifest_value")" || return 1
    [[ "$manifest_digest" == "$(json_value_sha256 "$manifest_value")" ]] || return 1
    if [[ "$mutation" == worktree-config ]]; then
      git -C "$checkout" config ExTeNsIoNs.WoRkTrEeCoNfIg true || return 1
      git -C "$checkout" config --worktree filter.hostile.clean /bin/false || return 1
      git -C "$checkout" config --worktree include.path /dev/null || return 1
      git -C "$checkout" config --worktree core.fileMode false || return 1
      printf '%s\n' "$TERMINAL_SOURCE_HELPER_PID" >"$helper_pid_receipt" || return 1
      terminal_record_git_checkout_authority \
        "$checkout" "$revision" "$git_tree" "$manifest_digest" || return 1
    elif [[ "$mutation" == manifest-crossbind ]]; then
      terminal_record_git_checkout_authority \
        "$checkout" "$revision" "$git_tree" \
        bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb || return 1
    else
      terminal_record_git_checkout_authority \
        "$checkout" "$revision" "$git_tree" "$manifest_digest" || return 1
    fi
    case "$mutation" in
      stable)
        terminal_publication_freeze_sources || return 1
        printf '%s' "$TERMINAL_SOURCE_ROSTER_VALUE" | jq -e \
          --arg revision "$revision" --arg git_tree "$git_tree" \
          --arg manifest_digest "$manifest_digest" \
          --argjson maximum_entries "$MAX_TERMINAL_GIT_INDEX_ENTRIES" '
            (.checkouts | length) == 1 and
            (.checkouts[0] |
              .checkout_kind == "git-clean-checkout-v1" and
              .revision == $revision and .git_tree == $git_tree and
              .index_entry_count == 4 and .tracked_entry_count == 4 and
              .index_entry_count <= $maximum_entries and
              .source_tree_sha256 == $manifest_digest and
              .ignored_entry_count == 1 and
              (.ignored_roster_sha256 | test("^[0-9a-f]{64}$")) and
              (.filesystem_roster_sha256 | test("^[0-9a-f]{64}$")) and
              (.stage_sha256 | test("^[0-9a-f]{64}$")) and
              (.index_flags_sha256 | test("^[0-9a-f]{64}$")) and
              (.transcript_sha256 | test("^[0-9a-f]{64}$"))) and
            (.trees | length) == 0
          ' >/dev/null || return 1
        terminal_publication_session_abort || return 1
        trap - EXIT
        ;;
      worktree)
        printf 'two\n' >"$checkout/tracked.txt"
        terminal_publication_freeze_sources
        ;;
      index-stat-cache)
        printf 'two\n' >"$checkout/tracked.txt"
        touch -r "$timestamp_reference" -- "$checkout/tracked.txt"
        terminal_publication_freeze_sources
        ;;
      symlink-target)
        ln -snf -- wronged.txt "$checkout/tracked-link"
        terminal_publication_freeze_sources
        ;;
      untracked)
        printf 'foreign\n' >"$checkout/untracked.txt"
        terminal_publication_freeze_sources
        ;;
      index)
        printf 'two\n' >"$checkout/tracked.txt"
        git -C "$checkout" add tracked.txt
        terminal_publication_freeze_sources
        ;;
      config)
        git -C "$checkout" config filter.hostile.clean /bin/true
        terminal_publication_freeze_sources
        ;;
      worktree-config)
        terminal_publication_freeze_sources
        ;;
      ignored-new)
        printf 'ignored\n' >"$checkout/ignored-two.bin"
        terminal_publication_freeze_sources
        ;;
      ignored-type)
        mv -- "$checkout/ignored-one.bin" "$output/ignored.saved"
        ln -s -- ../ignored.saved "$checkout/ignored-one.bin"
        terminal_publication_freeze_sources
        ;;
      manifest-drift)
        printf 'forged manifest\n' \
          >"$output/cells/unix-hit/preflight/runner/source-tree.manifest"
        terminal_publication_freeze_sources
        ;;
      manifest-crossbind)
        terminal_publication_freeze_sources
        ;;
      commit-switch)
        printf 'two\n' >"$checkout/tracked.txt"
        git -C "$checkout" add tracked.txt
        GIT_AUTHOR_DATE=2001-01-01T00:00:01Z \
          GIT_COMMITTER_DATE=2001-01-01T00:00:01Z \
          git -c commit.gpgsign=false -C "$checkout" commit -qm second
        terminal_publication_freeze_sources
        ;;
      *) return 1 ;;
    esac
  )

  run_terminal_git_record_shape_fixture() (
    local -r output="$protocol_root/git-record-shape"

    prepare_terminal_protocol_output "$output"
    trap 'terminal_publication_session_abort >/dev/null 2>&1 || true' EXIT
    terminal_publication_session_begin || return 1
    terminal_publication_write_source_record G \
      $'repository/.\tgit-clean-checkout-v1\t0000000000000000000000000000000000000000\t0000000000000000000000000000000000000000\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\textra' || return 1
    terminal_publication_freeze_sources
  )

  mkdir -- "$protocol_root"
  [[ "$MAX_TERMINAL_SOURCE_LEAVES" == 640 &&
    "$MAX_TERMINAL_SOURCE_CHECKOUTS" == 1 &&
    "$MAX_TERMINAL_SOURCE_NEGATIVES" == 128 &&
    "$MAX_TERMINAL_SOURCE_HELD_FDS" == 896 &&
    "$MIN_TERMINAL_SOURCE_NOFILE_LIMIT" == 1024 ]] || {
    printf 'terminal source authority constants drifted from the audited bounds\n' >&2
    return 1
  }
  run_terminal_protocol_low_nofile_fixture
  run_terminal_protocol_capability_fixture
  run_terminal_protocol_leaf_limit_fixture \
    "$MAX_TERMINAL_SOURCE_LEAVES" true
  run_terminal_protocol_leaf_limit_fixture \
    "$((MAX_TERMINAL_SOURCE_LEAVES + 1))" false
  run_terminal_protocol_negative_limit_fixture \
    "$MAX_TERMINAL_SOURCE_NEGATIVES" true
  run_terminal_protocol_negative_limit_fixture \
    "$((MAX_TERMINAL_SOURCE_NEGATIVES + 1))" false
  if run_terminal_protocol_conflicting_repeat_fixture >/dev/null 2>&1; then
    printf 'terminal helper accepted conflicting duplicate source receipts\n' >&2
    return 1
  fi
  run_terminal_protocol_directory_swap_fixture
  run_terminal_protocol_missing_intermediate_fixture stable
  for mutation in create swap drift; do
    if run_terminal_protocol_missing_intermediate_fixture \
      "$mutation" >/dev/null 2>&1; then
      printf 'terminal helper accepted missing-intermediate %s drift\n' \
        "$mutation" >&2
      return 1
    fi
  done
  run_terminal_pressure_selector_fixture false
  if run_terminal_pressure_selector_fixture true >/dev/null 2>&1; then
    printf 'terminal pressure selector accepted an extra recovery sample\n' >&2
    return 1
  fi
  run_terminal_git_checkout_fixture stable
  for mutation in worktree index-stat-cache symlink-target untracked index \
    config worktree-config ignored-new ignored-type manifest-drift manifest-crossbind \
    commit-switch; do
    if run_terminal_git_checkout_fixture "$mutation" >/dev/null 2>&1; then
      printf 'terminal Git checkout authority accepted %s drift\n' \
        "$mutation" >&2
      return 1
    fi
    if [[ "$mutation" == worktree-config ]]; then
      rejected_helper_pid="$(<"$protocol_root/git-checkout-worktree-config.helper-pid")" || return 1
      [[ "$rejected_helper_pid" =~ ^[1-9][0-9]*$ &&
        ! -e "/proc/$rejected_helper_pid" &&
        ! -e "$protocol_root/git-checkout-worktree-config/poc-gates.json" &&
        ! -e "$protocol_root/git-checkout-worktree-config/manifest.json" &&
        ! -e "$protocol_root/git-checkout-worktree-config/summary.json" ]] || {
        printf 'worktreeConfig rejection retained a helper or terminal leaf\n' >&2
        return 1
      }
    fi
  done
  if run_terminal_git_record_shape_fixture >/dev/null 2>&1; then
    printf 'terminal helper accepted a cross-kind/extra-field G record\n' >&2
    return 1
  fi

  definition="$(declare -f poc_gate_summary_json)" || return 1
  [[ "$definition" == *'local -r supplied_manifest_value='* &&
    "$definition" == *'manifest_json_value="$supplied_manifest_value"'* ]] || {
    printf 'PoC renderer lost its held-manifest input seam\n' >&2
    return 1
  }
  manifest_predeclared="$(printf '%s' "$manifest_value" | jq -ceS \
    '.predeclared_poc_gates')" || return 1
  manifest_digest="$(json_value_sha256 "$manifest_predeclared")" || return 1
  poc_value="$(jq -cn --arg digest "$manifest_digest" '{
    manifest_binding: {predeclared_poc_gates_sha256: $digest}
  }')" || return 1
  (
    validate_poc_gate_shape_json_value() { :; }
    validate_manifest_json_value() { [[ "$1" == "$manifest_value" ]]; }
    poc_gate_summary_json() {
      [[ "$1" == "$protocol_root" && "$2" == "$manifest_value" ]] || return 1
      printf '%s' "$poc_value"
    }
    validate_poc_gate_json_value_against_root \
      "$poc_value" "$protocol_root" "$manifest_value"
  ) || {
    printf 'terminal PoC regeneration did not consume the supplied held manifest\n' >&2
    return 1
  }
)

process_blocked_signal_mask() {
  local -r pid="$1"
  local line=""
  local value=""
  local extra=""
  local count=0

  [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/status" ]] || return 1
  while IFS= read -r line; do
    [[ "$line" == SigBlk:* ]] || continue
    ((count += 1))
    read -r value extra <<<"${line#*:}" || return 1
    [[ "$value" =~ ^[0-9A-Fa-f]{16}$ && -z "$extra" ]] || return 1
  done <"/proc/$pid/status"
  ((count == 1)) || return 1
  printf '%s' "$value"
}

run_terminal_native_inherited_blocked_alarm_fixture() (
  local -r output="$TEST_TMP_DIR/terminal-native-inherited-blocked-alarm"
  local -r handled_signal_mask_hex=6007
  local -r alarm_signal_mask_hex=2000
  local -r unrelated_signal_mask_hex=200
  local helper_pid=""
  local helper_executable=""
  local launcher_pid=""
  local launcher_mask=""
  local helper_mask=""
  local response=""
  local wait_status=0
  local attempt=0

  [[ "${BENCHMARK_TEST_INHERITED_BLOCKED_ALARM:-}" == true ]] || return 1
  launcher_pid="$BASHPID"
  launcher_mask="$(process_blocked_signal_mask "$launcher_pid")" || return 1
  (( (16#$launcher_mask & 16#$alarm_signal_mask_hex) != 0 &&
    (16#$launcher_mask & 16#$unrelated_signal_mask_hex) != 0 )) || {
    printf 'blocked-ALRM fixture launcher lost its inherited signal mask\n' >&2
    return 1
  }

  cleanup_inherited_alarm_fixture() {
    # shellcheck disable=SC2317 # EXIT cleanup for a deliberately interrupted helper.
    if [[ "$helper_pid" =~ ^[1-9][0-9]*$ && -e "/proc/$helper_pid" ]]; then
      kill -KILL "$helper_pid" 2>/dev/null || true
    fi
    if [[ "$TERMINAL_SOURCE_RECORD_FD" =~ ^[1-9][0-9]*$ ]]; then
      exec {TERMINAL_SOURCE_RECORD_FD}>&- || true
    fi
    if [[ "$TERMINAL_SOURCE_RESPONSE_FD" =~ ^[1-9][0-9]*$ ]]; then
      exec {TERMINAL_SOURCE_RESPONSE_FD}<&- || true
    fi
    [[ "$helper_pid" =~ ^[1-9][0-9]*$ ]] && wait "$helper_pid" 2>/dev/null || true
    terminal_publication_session_clear
  }

  mkdir -- "$output" || return 1
  reset_options
  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Read through dynamic scope by the session starter.
  OUTPUT_DIR_IDENTITY="$(stat --format '%d:%i:%u:%g:%a' -- "$output")" || return 1
  OUTPUT_READY=true
  trap cleanup_inherited_alarm_fixture EXIT
  ulimit -n "$MIN_TERMINAL_SOURCE_NOFILE_LIMIT"
  terminal_publication_session_begin || return 1
  helper_pid="$TERMINAL_SOURCE_HELPER_PID"
  helper_executable="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "/proc/$helper_pid/exe")" || return 1
  [[ "$helper_executable" == "$NATIVE_BENCHMARK_PERL_COMMAND" &&
    -e "/proc/$BASHPID/fd/$TERMINAL_SOURCE_RECORD_FD" ]] || return 1

  helper_mask="$(process_blocked_signal_mask "$helper_pid")" || return 1
  (( (16#$helper_mask & 16#$handled_signal_mask_hex) == 0 )) || {
    printf 'terminal Perl helper retained a blocked handled signal: %s\n' \
      "$helper_mask" >&2
    return 1
  }
  (( (16#$helper_mask & 16#$unrelated_signal_mask_hex) != 0 )) || {
    printf 'terminal Perl helper cleared the inherited unrelated signal bit\n' >&2
    return 1
  }
  kill -ALRM "$helper_pid" || return 1
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ ! -e "/proc/$helper_pid" ]] && break
    "$SLEEP_COMMAND" 0.01 || return 1
  done
  [[ ! -e "/proc/$helper_pid" ]] || {
    printf 'terminal Perl helper ignored inherited-blocked SIGALRM normalization\n' >&2
    return 1
  }
  if wait "$helper_pid"; then
    wait_status=0
  else
    wait_status=$?
  fi
  ((wait_status != 0)) || return 1
  if IFS= read -r -t 1 response <&"$TERMINAL_SOURCE_RESPONSE_FD"; then
    printf 'terminated blocked-ALRM helper retained a response: %s\n' \
      "$response" >&2
    return 1
  fi
  [[ ! -e "$output/poc-gates.json" && ! -e "$output/manifest.json" &&
    ! -e "$output/summary.json" &&
    -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
    printf 'blocked-ALRM helper left a terminal leaf or capability-probe residue\n' >&2
    return 1
  }
  exec {TERMINAL_SOURCE_RECORD_FD}>&- || return 1
  exec {TERMINAL_SOURCE_RESPONSE_FD}<&- || return 1
  terminal_publication_session_clear
  trap - EXIT
)

test_terminal_native_perl_normalizes_inherited_blocked_alarm() (
  local bash_executable=""
  local shell_pid=""

  resolve_benchmark_identity_tools || return 1
  shell_pid="$BASHPID"
  bash_executable="$(run_native_clean_environment \
    "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "/proc/$shell_pid/exe")" || return 1
  is_absolute_regular_executable "$bash_executable" || return 1
  run_native_clean_environment "$NATIVE_BENCHMARK_PERL_COMMAND" -T \
    -MPOSIX=SIG_BLOCK,SIGALRM,SIGUSR1,sigprocmask -e '
      my ($bash, $test) = @ARGV;
      for ($bash, $test) {
        defined($_) && /\A(\/(?:[^\/\0\r\n]+\/)*[^\/\0\r\n]+)\z/ or exit 126;
        $_ = $1;
      }
      my $blocked = POSIX::SigSet->new(SIGALRM, SIGUSR1);
      defined(sigprocmask(SIG_BLOCK, $blocked)) or exit 126;
      %ENV = (PATH => q{/usr/bin:/bin}, LC_ALL => q{C});
      $ENV{BENCHMARK_TEST_ONLY} = q{terminal-native-inherited-alarm};
      $ENV{BENCHMARK_TEST_INHERITED_BLOCKED_ALARM} = q{true};
      exec {$bash} $bash, $test or exit 127;
    ' -- "$bash_executable" "$TEST_SOURCE"
)

test_terminal_native_perl_reaps_active_git_child_on_signal() (
  local -r signal_root="$TEST_TMP_DIR/terminal-native-signal"

  run_terminal_native_signal_fixture() (
    local -r capture_kind="$1"
    local -r signal_point="$2"
    local -r signal_name="$3"
    local -r output="$signal_root/$capture_kind-$signal_point-${signal_name,,}"
    local -r checkout="$output/checkout"
    local helper_pid=""
    local helper_executable=""
    local child_pid=""
    local revision=""
    local git_tree=""
    local manifest_value=""
    local manifest_digest=""
    local runner_manifest_value=""
    local locator=""
    local payload=""
    local response=""
    local marker_prefix=""
    local marker_kind=""
    local observed_capture_kind=""
    local observed_signal_point=""
    local observed_signal_name=""
    local marker_extra=""
    local wait_status=0
    local index=0
    local attempt=0
    local cell=""

    cleanup_signal_fixture() {
      # shellcheck disable=SC2317 # EXIT cleanup for a deliberately interrupted helper.
      if [[ "$child_pid" =~ ^[1-9][0-9]*$ && -e "/proc/$child_pid" ]]; then
        kill -KILL "$child_pid" 2>/dev/null || true
      fi
      if [[ "$helper_pid" =~ ^[1-9][0-9]*$ && -e "/proc/$helper_pid" ]]; then
        kill -KILL "$helper_pid" 2>/dev/null || true
      fi
      if [[ "$TERMINAL_SOURCE_RECORD_FD" =~ ^[1-9][0-9]*$ ]]; then
        exec {TERMINAL_SOURCE_RECORD_FD}>&- || true
      fi
      if [[ "$TERMINAL_SOURCE_RESPONSE_FD" =~ ^[1-9][0-9]*$ ]]; then
        exec {TERMINAL_SOURCE_RESPONSE_FD}<&- || true
      fi
      [[ "$helper_pid" =~ ^[1-9][0-9]*$ ]] && wait "$helper_pid" 2>/dev/null || true
      terminal_publication_session_clear
    }

    mkdir -p -- "$output" "$checkout" || return 1
    reset_options
    OUTPUT_DIR="$output"
    # shellcheck disable=SC2034 # Read through dynamic scope by the session starter.
    OUTPUT_DIR_IDENTITY="$(stat --format '%d:%i:%u:%g:%a' -- "$output")" || return 1
    OUTPUT_READY=true
    # shellcheck disable=SC2034 # Read through dynamic scope by the session starter.
    TERMINAL_NATIVE_SIGNAL_TEST_HOOK="$capture_kind:$signal_point:$signal_name"
    git -c init.defaultBranch=main -C "$checkout" init -q || return 1
    git -C "$checkout" config user.email test@example.invalid || return 1
    git -C "$checkout" config user.name Test || return 1
    for ((index = 1; index <= 256; index++)); do
      printf 'tracked %04d\n' "$index" >"$checkout/tracked-$index.txt" || return 1
    done
    git -C "$checkout" add . || return 1
    GIT_AUTHOR_DATE=2001-01-01T00:00:00Z \
      GIT_COMMITTER_DATE=2001-01-01T00:00:00Z \
      git -c commit.gpgsign=false -C "$checkout" commit -qm initial || return 1
    revision="$(git -C "$checkout" rev-parse HEAD)" || return 1
    git_tree="$(git -C "$checkout" rev-parse 'HEAD^{tree}')" || return 1
    write_git_tree_manifest_for_tree \
      "$checkout" "$git_tree" "$output/source-tree.manifest" || return 1
    for cell in "${CORE_CELLS[@]}"; do
      mkdir -p -- "$output/cells/$cell/preflight/runner" || return 1
      command cp -- "$output/source-tree.manifest" \
        "$output/cells/$cell/preflight/runner/source-tree.manifest" || return 1
    done

    trap cleanup_signal_fixture EXIT
    ulimit -n "$MIN_TERMINAL_SOURCE_NOFILE_LIMIT"
    terminal_publication_session_begin || return 1
    helper_pid="$TERMINAL_SOURCE_HELPER_PID"
    helper_executable="$(run_native_clean_environment \
      "$NATIVE_BENCHMARK_READLINK_COMMAND" -f -- "/proc/$helper_pid/exe")" || return 1
    [[ "$helper_executable" == "$NATIVE_BENCHMARK_PERL_COMMAND" ]] || return 1
    for cell in "${CORE_CELLS[@]}"; do
      capture_bounded_regular_file_value \
        "$output/cells/$cell/preflight/runner/source-tree.manifest" \
        "$MAX_RUNNER_SOURCE_TREE_MANIFEST_BYTES" runner_manifest_value || return 1
      if [[ -z "$manifest_value" ]]; then
        manifest_value="$runner_manifest_value"
      else
        [[ "$runner_manifest_value" == "$manifest_value" ]] || return 1
      fi
    done
    manifest_digest="$(validate_recorded_git_tree_manifest_value \
      "$checkout" "$revision" "$git_tree" "$manifest_value")" || return 1
    locator="$(terminal_source_locator "$checkout")" || return 1
    printf -v payload '%s\t%s\t%s\t%s\t%s' \
      "$locator" git-clean-checkout-v1 "$revision" "$git_tree" "$manifest_digest"

    terminal_publication_write_source_record G "$payload" || return 1
    IFS= read -r -t 60 response <&"$TERMINAL_SOURCE_RESPONSE_FD" || {
      printf 'terminal Perl helper emitted no deterministic %s/%s hook for %s\n' \
        "$capture_kind" "$signal_point" "$signal_name" >&2
      return 1
    }
    IFS=: read -r marker_prefix marker_kind observed_capture_kind \
      observed_signal_point child_pid observed_signal_name marker_extra \
      <<<"$response"
    [[ "$marker_prefix" == X && "$marker_kind" == GIT-SIGNAL &&
      "$observed_capture_kind" == "$capture_kind" &&
      "$observed_signal_point" == "$signal_point" &&
      "$observed_signal_name" == "$signal_name" && -z "$marker_extra" &&
      "$child_pid" =~ ^[1-9][0-9]*$ ]] || {
      printf 'terminal Perl helper emitted a malformed signal hook: %s\n' \
        "$response" >&2
      return 1
    }
    for ((attempt = 0; attempt < 500; attempt++)); do
      [[ ! -e "/proc/$helper_pid" ]] && break
      "$SLEEP_COMMAND" 0.01 || return 1
    done
    [[ ! -e "/proc/$helper_pid" ]] || {
      printf 'terminal Perl helper ignored %s at %s/%s\n' \
        "$signal_name" "$capture_kind" "$signal_point" >&2
      return 1
    }
    if wait "$helper_pid"; then
      wait_status=0
    else
      wait_status=$?
    fi
    ((wait_status != 0)) || return 1
    [[ ! -e "/proc/$child_pid" ]] || {
      printf 'terminal Perl helper orphaned Git child %s after %s at %s/%s\n' \
        "$child_pid" "$signal_name" "$capture_kind" "$signal_point" >&2
      return 1
    }
    [[ ! -e "$output/poc-gates.json" &&
      ! -e "$output/manifest.json" && ! -e "$output/summary.json" ]] || {
      printf 'interrupted terminal helper published a terminal leaf at %s/%s\n' \
        "$capture_kind" "$signal_point" >&2
      return 1
    }
    if IFS= read -r -t 1 response <&"$TERMINAL_SOURCE_RESPONSE_FD"; then
      printf 'interrupted terminal helper retained a response-pipe record: %s\n' \
        "$response" >&2
      return 1
    fi
    exec {TERMINAL_SOURCE_RECORD_FD}>&- || return 1
    exec {TERMINAL_SOURCE_RESPONSE_FD}<&- || return 1
    terminal_publication_session_clear
    trap - EXIT
  )

  mkdir -- "$signal_root"
  run_terminal_native_signal_fixture capture pre-registration TERM
  run_terminal_native_signal_fixture capture post-wait ALRM
  run_terminal_native_signal_fixture capture-with-input pre-registration ALRM
  run_terminal_native_signal_fixture capture-with-input post-wait TERM
  # These exact children close their capture pipe and stop while still live.
  # The WNOHANG poll must restore an ALRM-deliverable mask between polls so the
  # native deadline handler can synchronously kill and reap both variants.
  run_terminal_native_signal_fixture capture stopped-after-eof ALRM
  run_terminal_native_signal_fixture capture-with-input stopped-after-eof ALRM
  test_terminal_native_perl_normalizes_inherited_blocked_alarm
)

test_publish_once_json_images_and_terminal_receipts_fail_closed() (
  local -r publication_root="$TEST_TMP_DIR/publish-once-json"
  local -r canonical_value='{"schema_version":1,"status":"available"}'
  local -r foreign_value='{"schema_version":1,"status":"foreign"}'
  local -r duplicate_value='{"schema_version":1,"status":"available","status":"available"}'
  local output=""
  local saved=""
  local frame=""
  local decoded=""
  local identity=""
  local digest=""
  local summary_root=""
  local summary_value=""
  local temporary=""

  mkdir -- "$publication_root"
  output="$publication_root/exact.json"
  json_publication_absence_ready() {
    local -r parent="${1%/*}"
    local -r name="${1##*/}"

    [[ -z "$(find "$parent" -mindepth 1 -maxdepth 1 \
      -name ".$name.*" -print -quit)" ]]
  }
  publish_exact_json_value "$output" "$canonical_value" 4096 || return 1
  [[ "$(<"$output")" == "$canonical_value" &&
    -z "$(find "$publication_root" -mindepth 1 -maxdepth 1 \
      -name '.exact.json.*' -print -quit)" ]] || {
    printf 'anonymous JSON publication exposed a candidate pathname\n' >&2
    return 1
  }
  json_publication_absence_ready() { :; }
  if publish_exact_json_value "$output" "$foreign_value" 4096 >/dev/null 2>&1; then
    printf 'publish-once JSON writer replaced an existing terminal leaf\n' >&2
    return 1
  fi
  [[ "$(<"$output")" == "$canonical_value" ]] || {
    printf 'failed replacement changed a published terminal leaf\n' >&2
    return 1
  }

  output="$publication_root/foreign-race.json"
  json_publication_absence_ready() {
    printf '%s' "$foreign_value" >"$1"
  }
  if publish_exact_json_value "$output" "$canonical_value" 4096 >/dev/null 2>&1; then
    printf 'publish-once JSON writer accepted a foreign absent-target race\n' >&2
    return 1
  fi
  [[ "$(<"$output")" == "$foreign_value" ]] || {
    printf 'absent-target race changed or removed the foreign leaf\n' >&2
    return 1
  }
  json_publication_absence_ready() { :; }

  output="$publication_root/post-link-content.json"
  json_publication_target_ready() {
    printf '%s' "$duplicate_value" >"$1"
  }
  if publish_exact_json_value "$output" "$canonical_value" 4096 >/dev/null 2>&1; then
    printf 'publisher accepted same-inode post-link content mutation\n' >&2
    return 1
  fi
  [[ "$(<"$output")" == "$duplicate_value" ]] || {
    printf 'publisher cleaned or rewrote a post-link mutated target\n' >&2
    return 1
  }
  if validate_bounded_duplicate_free_json "$output" 4096 >/dev/null 2>&1; then
    printf 'fresh validation accepted retained post-link duplicate keys\n' >&2
    return 1
  fi

  output="$publication_root/post-link-path-swap.json"
  saved="$publication_root/post-link-path-swap.original"
  json_publication_target_ready() {
    mv -- "$1" "$saved" || return 1
    printf '%s' "$foreign_value" >"$1"
  }
  if publish_exact_json_value "$output" "$canonical_value" 4096 >/dev/null 2>&1; then
    printf 'publisher accepted a post-link target path swap\n' >&2
    return 1
  fi
  [[ "$(<"$output")" == "$foreign_value" &&
    "$(<"$saved")" == "$canonical_value" ]] || {
    printf 'publisher removed an inode after a post-link path swap\n' >&2
    return 1
  }
  json_publication_target_ready() { :; }

  printf '%s' "$canonical_value" >"$publication_root/framed.json"
  frame="$(capture_bounded_regular_file_image \
    "$publication_root/framed.json" 4096)" || return 1
  decode_bounded_regular_file_image "$frame" 4096 decoded identity digest || return 1
  [[ "$decoded" == "$canonical_value" && "$digest" == "$(json_value_sha256 "$decoded")" ]] || return 1
  if decode_bounded_regular_file_image "${frame}x" 4096 \
    decoded identity digest >/dev/null 2>&1; then
    printf 'held-image frame accepted trailing bytes\n' >&2
    return 1
  fi
  printf '{"a":1}\0{"b":2}' >"$publication_root/nul.json"
  if capture_bounded_regular_file_image \
    "$publication_root/nul.json" 4096 >/dev/null 2>&1; then
    printf 'held-image capture accepted a NUL byte\n' >&2
    return 1
  fi
  printf '{"a":1}{"b":2}' >"$publication_root/multiple.json"
  if validate_bounded_duplicate_free_json \
    "$publication_root/multiple.json" 4096 >/dev/null 2>&1; then
    printf 'held-image validation accepted multiple JSON documents\n' >&2
    return 1
  fi
  output="$publication_root/publisher-multiple.json"
  if publish_exact_json_value \
    "$output" $'{"a":1}\n{"b":2}' 4096 >/dev/null 2>&1; then
    printf 'publish-once writer accepted multiple JSON documents\n' >&2
    return 1
  fi
  [[ ! -e "$output" && ! -L "$output" ]] || {
    printf 'multiple-document rejection exposed a terminal leaf\n' >&2
    return 1
  }

  reset_options
  summary_root="$publication_root/summary-receipts"
  OUTPUT_DIR="$summary_root"
  OUTPUT_READY=true
  mkdir -p -- "$summary_root/cells"
  write_valid_in_progress_manifest_fixture
  write_summary failed || return 1
  validate_summary_artifact_receipts \
    "$summary_root/summary.json" "$summary_root" || return 1
  jq -e '
    (.artifact_receipts | keys) == ["manifest", "poc_gates"] and
    (.artifact_receipts.manifest | keys) == ["path", "sha256", "size_bytes"] and
    .artifact_receipts.poc_gates == {
      path: null, sha256: null, size_bytes: null, status: "not_available"
    } and
    .poc_gates == {status: "not_available", path: null, result: null} and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth == {
      status: "not_available", result: null, process_fd_threads: null,
      java_bridge_map: null, full_cgroup_v2_process_tree_fd_task_rss: null,
      application_cpu_per_successful_request: null
    }
  ' "$summary_root/summary.json" >/dev/null || return 1
  cp -- "$summary_root/summary.json" "$summary_root/summary.valid.json"
  temporary="$summary_root/summary.forged-poc.json"
  jq -cS '.poc_gates = {
    status: "partial", path: "poc-gates.json", result: "not_evaluated"
  }' "$summary_root/summary.json" >"$temporary" || return 1
  mv -T -- "$temporary" "$summary_root/summary.json" || return 1
  summary_value="$(bounded_duplicate_free_json_value \
    "$summary_root/summary.json" "$MAX_SUMMARY_BYTES")" || return 1
  validate_summary_json_value "$summary_value" failed || {
    printf 'no-PoC summary mutation was not independently schema-valid\n' >&2
    return 1
  }
  if validate_summary_artifact_receipts \
    "$summary_root/summary.json" "$summary_root" >/dev/null 2>&1; then
    printf 'not-available PoC receipt accepted a partial nested PoC claim\n' >&2
    return 1
  fi
  mv -T -- "$summary_root/summary.valid.json" "$summary_root/summary.json"

  cp -- "$summary_root/summary.json" "$summary_root/summary.valid.json"
  temporary="$summary_root/summary.forged-resources.json"
  jq -cS '.measurement_scope.application_fd_threads_and_java_bridge_map_growth = {
    status: "partial", result: "not_evaluated", process_fd_threads: {},
    java_bridge_map: {}, full_cgroup_v2_process_tree_fd_task_rss: {},
    application_cpu_per_successful_request: {}
  }' "$summary_root/summary.json" >"$temporary" || return 1
  mv -T -- "$temporary" "$summary_root/summary.json" || return 1
  summary_value="$(bounded_duplicate_free_json_value \
    "$summary_root/summary.json" "$MAX_SUMMARY_BYTES")" || return 1
  validate_summary_json_value "$summary_value" failed || {
    printf 'no-PoC resource mutation was not independently schema-valid\n' >&2
    return 1
  }
  if validate_summary_artifact_receipts \
    "$summary_root/summary.json" "$summary_root" >/dev/null 2>&1; then
    printf 'not-available PoC receipt accepted a nested resource claim\n' >&2
    return 1
  fi
  mv -T -- "$summary_root/summary.valid.json" "$summary_root/summary.json"

  temporary="$summary_root/summary.receipt-drift.json"
  jq -cS '.artifact_receipts.manifest.sha256 = ("0" * 64)' \
    "$summary_root/summary.json" >"$temporary" || return 1
  mv -T -- "$temporary" "$summary_root/summary.json" || return 1
  if validate_summary_artifact_receipts \
    "$summary_root/summary.json" "$summary_root" >/dev/null 2>&1; then
    printf 'terminal summary accepted independent receipt drift\n' >&2
    return 1
  fi
)

assert_held_json_projection_survives_source_mutation() (
  local -r mode="$1"
  local -r target="$2"
  local -r maximum_bytes="$3"
  local -r label="$4"
  local -r expected_outcome="$5"
  shift 5
  local -r backup="$target.held-image-backup"
  local -r swapped="$target.held-image-swapped"
  local -r marker="$target.held-image-mutated"
  local command_status=0
  local original_definition=""
  local terminal_root=""

  cp -p -- "$target" "$backup" || return 1
  cleanup_held_image_mutation() {
    if [[ -e "$target" || -L "$target" ]]; then
      command unlink -- "$target" || return 1
    fi
    if [[ -e "$swapped" || -L "$swapped" ]]; then
      command unlink -- "$swapped" || return 1
    fi
    mv -- "$backup" "$target" || return 1
    command unlink -- "$marker" 2>/dev/null || true
  }
  trap cleanup_held_image_mutation EXIT
  original_definition="$(declare -f capture_bounded_regular_file_image)" || return 1
  eval "${original_definition/capture_bounded_regular_file_image/original_capture_bounded_regular_file_image}"
  capture_bounded_regular_file_image() {
    local captured_frame=""

    captured_frame="$(original_capture_bounded_regular_file_image "$@")" || return 1
    if [[ "$1" == "$target" && ! -e "$marker" ]]; then
      : >"$marker" || return 1
      case "$mode" in
        same-inode)
          printf '%s' '{"status":"available","status":"available"}' >"$target" || return 1
          ;;
        path-swap)
          mv -- "$target" "$swapped" || return 1
          printf '%s' '{"status":"available","status":"available"}' >"$target" || return 1
          ;;
        *) return 1 ;;
      esac
    fi
    printf '%s' "$captured_frame"
  }
  if "$@" >/dev/null; then
    command_status=0
  else
    command_status=$?
  fi
  case "$expected_outcome" in
    survive)
      ((command_status == 0)) || {
        printf 'held JSON projection reopened a mutated %s source: %s\n' \
          "$mode" "$label" >&2
        return 1
      }
      ;;
    reject-terminal)
      ((command_status != 0)) || {
        printf 'terminal summary accepted mutated %s source authority\n' \
          "$mode" >&2
        return 1
      }
      [[ -e "$marker" ]] || {
        printf 'terminal summary %s mutation hook did not fire\n' "$mode" >&2
        return 1
      }
      terminal_root="${target%/*}"
      [[ ! -e "$terminal_root/poc-gates.json" &&
        ! -L "$terminal_root/poc-gates.json" &&
        ! -e "$terminal_root/manifest.json" &&
        ! -L "$terminal_root/manifest.json" &&
        ! -e "$terminal_root/summary.json" &&
        ! -L "$terminal_root/summary.json" ]] || {
        printf 'terminal summary linked a leaf after %s source mutation\n' \
          "$mode" >&2
        return 1
      }
      ;;
    *)
      return 1
      ;;
  esac
  if validate_bounded_duplicate_free_json \
    "$target" "$maximum_bytes" >/dev/null 2>&1; then
    printf 'fresh validation accepted mutated %s source: %s\n' \
      "$mode" "$label" >&2
    return 1
  fi
)

assert_boundary_directory_path_swap_is_descriptor_anchored() (
  local -r target_directory="$1"
  shift
  local -r saved_directory="$target_directory.namespace-anchor-saved"
  local -r replacement_directory="$target_directory.namespace-anchor-replacement"
  local -r marker="$target_directory.namespace-anchor-mutated"
  local original_definition=""
  local expected_inodes=""
  local observed_bundle=""
  local cgroup_artifact=""
  local service=""
  local temporary=""
  local -a inode_rows=()

  cp -a -- "$target_directory" "$replacement_directory" || return 1
  for cgroup_artifact in "$target_directory"/*-cgroup-v2.json; do
    [[ -f "$cgroup_artifact" && ! -L "$cgroup_artifact" ]] || continue
    service="${cgroup_artifact##*/}"
    service="${service%-cgroup-v2.json}"
    inode_rows+=("$(jq -cn --arg service "$service" \
      --argjson inode "$(jq -er '.identity.cgroup_inode' "$cgroup_artifact")" \
      '{key: $service, value: $inode}')") || return 1
    cgroup_artifact="$replacement_directory/${cgroup_artifact##*/}"
    temporary="$cgroup_artifact.mutated"
    jq '.identity.cgroup_inode += 1000' "$cgroup_artifact" >"$temporary" || return 1
    mv -T -- "$temporary" "$cgroup_artifact" || return 1
  done
  expected_inodes="$(printf '%s\n' "${inode_rows[@]}" | jq -cs 'from_entries')" || return 1
  [[ "$(printf '%s' "$expected_inodes" | jq -er 'length')" -gt 0 ]] || return 1
  cleanup_boundary_directory_path_swap() {
    if [[ -d "$saved_directory" && ! -L "$saved_directory" ]]; then
      [[ -d "$target_directory" && ! -L "$target_directory" &&
        ! -e "$replacement_directory" && ! -L "$replacement_directory" ]] || return 1
      mv -- "$target_directory" "$replacement_directory" || return 1
      mv -- "$saved_directory" "$target_directory" || return 1
    fi
    command unlink -- "$marker" 2>/dev/null || true
  }
  trap cleanup_boundary_directory_path_swap EXIT
  original_definition="$(declare -f capture_bounded_regular_file_image)" || return 1
  eval "${original_definition/capture_bounded_regular_file_image/original_capture_bounded_regular_file_image}"
  capture_bounded_regular_file_image() {
    local captured_frame=""

    captured_frame="$(original_capture_bounded_regular_file_image "$@")" || return 1
    if [[ "$1" == */snapshot.json && ! -e "$marker" ]]; then
      printf 'replacement-installed\n' >"$marker" || return 1
      mv -- "$target_directory" "$saved_directory" || return 1
      mv -- "$replacement_directory" "$target_directory" || return 1
    elif [[ "$1" == */*-cgroup-v2.json && -f "$marker" &&
      "$(<"$marker")" == replacement-installed ]]; then
      mv -- "$target_directory" "$replacement_directory" || return 1
      mv -- "$saved_directory" "$target_directory" || return 1
      printf 'original-restored\n' >"$marker" || return 1
    fi
    printf '%s' "$captured_frame"
  }
  observed_bundle="$("$@")" || {
    printf 'descriptor-anchored boundary rejected its original held directory\n' >&2
    return 1
  }
  [[ "$(<"$marker")" == original-restored ]] || {
    printf 'boundary directory path-swap/restore mutation hook did not complete\n' >&2
    return 1
  }
  printf '%s\n%s' "$observed_bundle" "$expected_inodes" | jq -es '
    length == 2 and
    (.[0].snapshots | with_entries(.value = .value.identity.cgroup_inode)) == .[1]
  ' >/dev/null || {
    printf 'boundary bundle mixed a replacement-directory child into the held namespace\n' >&2
    return 1
  }
)

validate_supported_poc_held_image_fixture() {
  local -r artifact="$1"
  local artifact_value=""

  artifact_value="$(bounded_poc_gate_json_value "$artifact")" || return 1
  validate_supported_poc_dimensions_json_value "$artifact_value"
}

test_held_json_images_close_all_four_source_aba_chains() (
  local mode=""
  local output=""
  local boundary=""

  validate_published_java_measurement() {
    # shellcheck disable=SC2317 # Dynamically called by the sourced gate builder.
    validate_sampled_allocation_fixture_with_bundle "$1" "${2:-}"
  }

  for mode in same-inode path-swap; do
    output="$TEST_TMP_DIR/held-resource-$mode"
    mkdir -- "$output"
    boundary="$output/snapshot.json"
    write_resource_boundary_fixture \
      "$output" fixture before 100 100000 101 101000
    assert_held_json_projection_survives_source_mutation \
      "$mode" "$boundary" "$MAX_BOUNDARY_SNAPSHOT_BYTES" \
      resource-boundary survive validate_resource_snapshot_boundary \
      "$boundary" fixture before

    reset_options
    output="$TEST_TMP_DIR/held-manifest-$mode"
    OUTPUT_DIR="$output"
    OUTPUT_READY=true
    mkdir -- "$output"
    write_valid_in_progress_manifest_fixture
    assert_held_json_projection_survives_source_mutation \
      "$mode" "$output/manifest.in-progress.json" "$MAX_MANIFEST_BYTES" \
      manifest survive validate_manifest_schema \
      "$output/manifest.in-progress.json"

    reset_options
    output="$TEST_TMP_DIR/held-poc-$mode"
    prepare_poc_gate_fixture "$output"
    write_poc_gate_summary
    publish_held_poc_gate_fixture
    assert_held_json_projection_survives_source_mutation \
      "$mode" "$output/poc-gates.json" "$MAX_POC_GATE_BYTES" \
      supported-poc survive validate_supported_poc_held_image_fixture \
      "$output/poc-gates.json"

    reset_options
    output="$TEST_TMP_DIR/held-summary-$mode"
    OUTPUT_DIR="$output"
    OUTPUT_READY=true
    mkdir -p -- "$output/cells"
    write_valid_in_progress_manifest_fixture
    assert_held_json_projection_survives_source_mutation \
      "$mode" "$output/manifest.in-progress.json" "$MAX_MANIFEST_BYTES" \
      summary reject-terminal write_summary failed
  done
)

test_on_exit_does_not_replace_partial_terminal_publication() {
  local -r output="$TEST_TMP_DIR/on-exit-partial-terminal"
  local -r calls="$output/calls.txt"
  local exit_status=0

  mkdir -- "$output"
  if (
    reset_options
    OUTPUT_DIR="$output"
    OUTPUT_READY=true
    # shellcheck disable=SC2034 # Consumed dynamically by the sourced exit handler.
    HARNESS_STATUS=passed
    release_lock() { :; }
    write_summary() {
      printf '%s\n' "$1" >>"$calls"
      if [[ "$1" == passed ]]; then
        # shellcheck disable=SC2034 # Simulates the sourced terminal publication latch.
        TERMINAL_PUBLICATION_STARTED=true
        printf '%s' '{"terminal":"poc"}' >"$OUTPUT_DIR/poc-gates.json"
        printf '%s' '{"terminal":"manifest"}' >"$OUTPUT_DIR/manifest.json"
        printf '%s' '{"terminal":"summary"}' >"$OUTPUT_DIR/summary.json"
        command unlink -- "$OUTPUT_DIR/poc-gates.json" || return 1
        command unlink -- "$OUTPUT_DIR/manifest.json" || return 1
        command unlink -- "$OUTPUT_DIR/summary.json" || return 1
        return 1
      fi
      return 0
    }
    on_exit 0
  ); then
    printf 'on_exit accepted a partial terminal publication\n' >&2
    return 1
  else
    exit_status=$?
  fi
  [[ "$exit_status" == 1 && "$(<"$calls")" == passed &&
    ! -e "$output/poc-gates.json" && ! -L "$output/poc-gates.json" &&
    ! -e "$output/manifest.json" && ! -L "$output/manifest.json" &&
    ! -e "$output/summary.json" && ! -L "$output/summary.json" ]] || {
    printf 'on_exit retried after published terminal leaves were unlinked\n' >&2
    return 1
  }
}

test_w3c_discard_diagnostics_require_exact_delta() {
  local -r before="$TEST_TMP_DIR/w3c-diagnostics-before.txt"
  local -r after="$TEST_TMP_DIR/w3c-diagnostics-after.txt"
  local -r output="$TEST_TMP_DIR/w3c-diagnostics.json"
  local -r runner_delta="$TEST_TMP_DIR/w3c-runner-diagnostics.delta"
  local -r oversized="$TEST_TMP_DIR/w3c-diagnostics-oversized.txt"

  (
    reset_options
    cell_spec getsockopt-w3c
    write_valid_java_diagnostics_snapshot "$before" z z
    if [[ "$(tr ',' '\n' <"$before" | wc -l)" != 54 ]] ||
      ! grep -Fq 'tls_bytes=0,framework_depth=0,framework_cycle=0,framework_late=0,transport_missing=0' \
        "$before"; then
      printf 'diagnostic fixture does not match the exact 54-field production schema\n' >&2
      return 1
    fi
    write_valid_java_diagnostics_snapshot "$after" 17 17
    validate_java_diagnostics_counter_deltas \
      "$before" "$after" "$output" discard_standard 8 t_valid 8 d_valid 0 || {
      printf 'valid base36 W3C precedence diagnostic delta was rejected\n' >&2
      return 1
    }
    jq -e '
      .counters == [
        {counter: "discard_standard", before_base36: "z", after_base36: "17", observed_delta: 8, expected_delta: 8},
        {counter: "t_valid", before_base36: "z", after_base36: "17", observed_delta: 8, expected_delta: 8},
        {counter: "d_valid", before_base36: "0", after_base36: "0", observed_delta: 0, expected_delta: 0}
      ]
    ' "$output" >/dev/null || {
      printf 'W3C precedence diagnostic evidence did not retain the exact delta\n' >&2
      return 1
    }
    write_valid_java_diagnostics_snapshot "$after" 18 17
    if validate_java_diagnostics_counter_deltas \
      "$before" "$after" "$output" discard_standard 8 t_valid 8 d_valid 0 >/dev/null 2>&1; then
      printf 'W3C precedence diagnostic validator accepted the wrong discard delta\n' >&2
      return 1
    fi
    write_valid_java_diagnostics_snapshot "$after" 17 1f
    validate_standard_parent_discard_diagnostics "$before" "$after" "$output" || {
      printf 'valid post-load W3C precedence diagnostic delta was rejected\n' >&2
      return 1
    }
    jq -e '
      .counters == [
        {counter: "discard_standard", before_base36: "z", after_base36: "17", observed_delta: 8, expected_delta: 8},
        {counter: "t_valid", before_base36: "z", after_base36: "1f", observed_delta: 16, expected_delta: 16},
        {counter: "d_valid", before_base36: "0", after_base36: "0", observed_delta: 0, expected_delta: 0}
      ]
    ' "$output" >/dev/null || {
      printf 'post-load W3C precedence diagnostic evidence did not retain its exact deltas\n' >&2
      return 1
    }
    write_valid_java_diagnostics_snapshot "$after" 17 1e
    if validate_standard_parent_discard_diagnostics "$before" "$after" "$output" >/dev/null 2>&1; then
      printf 'W3C precedence diagnostic validator accepted the wrong valid-take delta\n' >&2
      return 1
    fi
    write_valid_java_diagnostics_snapshot "$after" 17 1f 1
    if validate_standard_parent_discard_diagnostics "$before" "$after" "$output" >/dev/null 2>&1; then
      printf 'W3C precedence diagnostic validator accepted a valid discard result\n' >&2
      return 1
    fi
    printf 'discard_standard=z\n' >"$before"
    if validate_java_diagnostics_snapshot "$before" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted a truncated counter snapshot\n' >&2
      return 1
    fi
    write_valid_java_diagnostics_snapshot "$before" z z
    sed 's/^cfg_on=/unknown=/' "$before" >"$before.unknown"
    if validate_java_diagnostics_snapshot "$before.unknown" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted an unknown counter name\n' >&2
      return 1
    fi
    awk -F, 'BEGIN {OFS=","} {first=$1; $1=$2; $2=first; print}' "$before" >"$before.reordered"
    if validate_java_diagnostics_snapshot "$before.reordered" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted reordered counters\n' >&2
      return 1
    fi
    sed 's/framework_depth=0,framework_cycle=0/framework_cycle=0,framework_depth=0/' \
      "$before" >"$before.framework-reordered"
    if validate_java_diagnostics_snapshot "$before.framework-reordered" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted reordered framework reason counters\n' >&2
      return 1
    fi
    sed 's/framework_cycle=0/framework_depth=0/' \
      "$before" >"$before.framework-duplicate"
    if validate_java_diagnostics_snapshot "$before.framework-duplicate" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted a duplicate framework reason counter\n' >&2
      return 1
    fi
    printf '%s,%s\n' "$(<"$before")" "discard_standard=0" >"$before.duplicate"
    if validate_java_diagnostics_snapshot "$before.duplicate" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted a duplicate counter\n' >&2
      return 1
    fi
    sed 's/discard_standard=z/discard_standard=gjdgxs/' "$before" >"$before.out-of-range"
    if validate_java_diagnostics_snapshot "$before.out-of-range" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted an out-of-range counter\n' >&2
      return 1
    fi
    head -c "$((MAX_JAVA_DIAGNOSTICS_SNAPSHOT_BYTES + 1))" /dev/zero >"$oversized"
    if validate_java_diagnostics_snapshot "$oversized" >/dev/null 2>&1; then
      printf 'diagnostic validator accepted an oversized snapshot\n' >&2
      return 1
    fi
    printf 'discard_standard before=4 after=12 delta=8\n' >"$runner_delta"
    validate_runner_standard_parent_discards "$runner_delta" || {
      printf 'valid runner W3C discard delta was rejected\n' >&2
      return 1
    }
    printf 'discard_standard before=12 after=4 delta=8\n' >"$runner_delta"
    if validate_runner_standard_parent_discards "$runner_delta" >/dev/null 2>&1; then
      printf 'runner W3C discard validator accepted an inconsistent delta\n' >&2
      return 1
    fi
  )
}

test_helper_idle_java_diagnostics_require_exact_correction() (
  local -r before="$TEST_TMP_DIR/helper-idle-java-before.txt"
  local -r after="$TEST_TMP_DIR/helper-idle-java-after.txt"
  local -r output="$TEST_TMP_DIR/helper-idle-java-deltas.json"
  local -r maximum_successful_requests="$MAX_HELPER_IDLE_WORKLOAD_SUCCESSFUL_REQUESTS"
  local -r maximum_raw_t_missing="$((maximum_successful_requests + 1))"
  local -r maximum_raw_t_missing_base36="$(fake_decimal_to_base36 "$maximum_raw_t_missing")"

  reset_options
  cell_spec getsockopt-helper-idle
  write_valid_java_diagnostics_snapshot "$before" 0 0 0 0
  # `p` is base36 for 25: 24 direct-Java requests plus the after-diagnostics
  # request, whose own server instrumentation is included in that snapshot.
  write_valid_java_diagnostics_snapshot "$after" 0 0 0 p
  validate_helper_idle_java_diagnostics "$before" "$after" "$output" 24 || {
    printf 'helper-idle diagnostics rejected the exact raw N+1 correction\n' >&2
    return 1
  }
  jq -e '
    .semantic == "direct_java_no_upstream_handoff_not_state_map_miss_proof" and
    .workload_successful_requests == 24 and
    .diagnostic_after_probe_t_missing == 1 and
    .raw_java_t_missing_delta == 25 and
    .corrected_workload_t_missing == 24 and
    .correction == {
      reason: "the_after_obi_diagnostics_request_is_itself_server_instrumented",
      raw_t_missing_expected: 25,
      corrected_workload_t_missing_expected: 24
    } and
    ([.raw_counters[] | select(.counter == "t_missing")] == [
      {counter: "t_missing", before_base36: "0", after_base36: "p", observed_delta: 25, expected_delta: 25}
    ])
  ' "$output" >/dev/null || {
    printf 'helper-idle diagnostics omitted its exact correction evidence\n' >&2
    return 1
  }
  rm -f -- "$output"
  write_valid_java_diagnostics_snapshot "$after" 0 0 0 "$maximum_raw_t_missing_base36"
  validate_helper_idle_java_diagnostics \
    "$before" "$after" "$output" "$maximum_successful_requests" || {
    printf 'helper-idle diagnostics rejected the maximum aggregate workload correction\n' >&2
    return 1
  }
  rm -f -- "$output"
  write_valid_java_diagnostics_snapshot "$after" 0 0 0 \
    "$(fake_decimal_to_base36 "$((maximum_raw_t_missing + 1))")"
  if validate_helper_idle_java_diagnostics \
    "$before" "$after" "$output" "$maximum_successful_requests" >/dev/null 2>&1; then
    printf 'helper-idle diagnostics accepted a raw delta above the aggregate workload bound\n' >&2
    return 1
  fi
  write_valid_java_diagnostics_snapshot "$after" 0 0 0 o
  if validate_helper_idle_java_diagnostics "$before" "$after" "$output" 24 >/dev/null 2>&1; then
    printf 'helper-idle diagnostics accepted raw N instead of N+1\n' >&2
    return 1
  fi
  write_valid_java_diagnostics_snapshot "$after" 0 1 0 p
  if validate_helper_idle_java_diagnostics "$before" "$after" "$output" 24 >/dev/null 2>&1; then
    printf 'helper-idle diagnostics accepted a native valid take\n' >&2
    return 1
  fi
  write_valid_java_diagnostics_snapshot "$after" 0 0 1 p
  if validate_helper_idle_java_diagnostics "$before" "$after" "$output" 24 >/dev/null 2>&1; then
    printf 'helper-idle diagnostics accepted a native valid discard\n' >&2
    return 1
  fi
  write_valid_java_diagnostics_snapshot "$after" 0 0 0 p
  sed 's/provider_reject=0/provider_reject=1/' "$after" >"$after.provider-reject"
  if validate_helper_idle_java_diagnostics \
    "$before" "$after.provider-reject" "$output" 24 >/dev/null 2>&1; then
    printf 'helper-idle diagnostics accepted a provider failure\n' >&2
    return 1
  fi
)

test_diagnostics_suppression_is_scheduled_midpoint_only() (
  local -r non_helper_snapshot="$TEST_TMP_DIR/non-helper-not-collected"
  local -r wrong_timing_snapshot="$TEST_TMP_DIR/helper-wrong-timing-not-collected"

  reset_options
  cell_spec getsockopt-hit
  if capture_resource_snapshot "$non_helper_snapshot" unsynchronized_midpoint not_collected; then
    printf 'resource snapshot accepted the obsolete unsynchronized midpoint timing\n' >&2
    return 1
  fi
  [[ ! -e "$non_helper_snapshot" ]] || {
    printf 'resource snapshot created artifacts after rejecting non-helper diagnostics suppression\n' >&2
    return 1
  }

  cell_spec getsockopt-helper-idle
  if capture_resource_snapshot "$wrong_timing_snapshot" before not_collected; then
    printf 'resource snapshot allowed diagnostics suppression outside a protected boundary\n' >&2
    return 1
  fi
  [[ ! -e "$wrong_timing_snapshot" ]] || {
    printf 'resource snapshot created artifacts after rejecting an invalid helper timing\n' >&2
    return 1
  }
)

test_scheduled_midpoint_failure_cleanup_and_post_capture_liveness() (
  local -r output="$TEST_TMP_DIR/midpoint-lifecycle"
  local -r cell_dir="$output/cells/getsockopt-hit"
  local -r boundary_dir="$output/bound-midpoint"
  local -r clock_file="$output/clocks.txt"
  local -r outside="$output/outside.txt"
  local -r outside_directory="$output/outside-directory"
  local -r receipt="$output/receipt.json"
  local aborts=0
  local waits=0
  local liveness_checks=0
  local compact=""
  local mutated_json=""
  local mutation=""
  local original_measurements=""
  local publication_bundle=""
  local publication_final=""
  local publication_partial=""
  local unavailable_output=""
  local unavailable_parent_identity=""
  local unavailable_partial_identity=""
  local unavailable_foreign_target="$output/unavailable-midpoint-foreign-target"
  local poison_directory="$output/perl-poison"
  local poison_marker="$output/perl-poison-loaded"
  local service=""

  reset_options
  OUTPUT_DIR="$output"
  DURATION_SECONDS=2
  REPETITIONS=5
  cell_spec getsockopt-hit
  mkdir -p -- "$cell_dir/measurements"
  ACTIVE_CELL_DIR="$cell_dir"
  activate_benchmark() {
    local -r result="$cell_dir/measurements/rep-01.json"
    BENCHMARK_PID=4242
    BENCHMARK_IDENTITY='4242 4242 1010'
    BENCHMARK_OUTPUT="$result"
    BENCHMARK_DURATION_SECONDS=2
    BENCHMARK_CELL_DIR="$cell_dir"
    BENCHMARK_OUTPUT_PARENT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- \
      "$cell_dir/measurements")"
    # shellcheck disable=SC2034 # Consumed dynamically by the midpoint transaction.
    BENCHMARK_CONFIRMED_WALL_EPOCH_SECONDS=1000 \
      BENCHMARK_CONFIRMED_MONOTONIC_MILLISECONDS=1000000
  }
  launch_benchmark_client() {
    [[ "$1" == "$cell_dir/measurements/rep-01.json" && "$2" == 2 ]] || return 1
    activate_benchmark
  }
  abort_active_benchmark() {
    ((aborts += 1))
    clear_active_benchmark
  }
  wait_for_active_benchmark() {
    ((waits += 1))
  }
  benchmark_job_is_running() { return 0; }
  benchmark_identity_matches_leader() { return 0; }
  clock_pair_values() {
    local value=""
    local temporary=""
    [[ -s "$clock_file" ]] || return 1
    value="$(head -n 1 -- "$clock_file")" || return 1
    temporary="${clock_file}.next"
    tail -n +2 -- "$clock_file" >"$temporary" || return 1
    mv -T -- "$temporary" "$clock_file" || return 1
    printf '%s\n' "$value"
  }

  : >"$clock_file"
  SLEEP_COMMAND=/bin/true
  if run_measurement_rep "$cell_dir" 1 >/dev/null 2>&1; then
    printf 'measurement accepted a late midpoint-transaction clock failure\n' >&2
    return 1
  fi
  [[ "$aborts" == 1 && "$waits" == 0 && -z "$BENCHMARK_PID" ]] || {
    printf 'midpoint begin failure did not abort/reap before wait\n' >&2
    return 1
  }
  [[ ! -e "$cell_dir/measurements/.rep-01-midpoint.partial" ]] || {
    printf 'midpoint begin failure leaked its active transaction\n' >&2
    return 1
  }

  printf '1000 1000000\n' >"$clock_file"
  SLEEP_COMMAND=/bin/false
  if run_measurement_rep "$cell_dir" 1 >/dev/null 2>&1; then
    printf 'measurement accepted an interrupted midpoint sleep\n' >&2
    return 1
  fi
  [[ "$aborts" == 2 && "$waits" == 0 && -z "$BENCHMARK_PID" ]] || {
    printf 'midpoint sleep failure did not abort/reap before wait\n' >&2
    return 1
  }
  [[ ! -e "$cell_dir/measurements/.rep-01-midpoint.partial" ]] || return 1

  printf '1000 1000000\n1001 1001000\n' >"$clock_file"
  SLEEP_COMMAND=/bin/true
  capture_scheduled_midpoint_cgroups() { return 71; }
  if run_measurement_rep "$cell_dir" 1 >/dev/null 2>&1; then
    printf 'measurement accepted a failed midpoint capture\n' >&2
    return 1
  fi
  [[ "$aborts" == 3 && "$waits" == 0 && -z "$BENCHMARK_PID" ]] || {
    printf 'midpoint capture failure did not abort/reap before wait\n' >&2
    return 1
  }
  [[ ! -e "$cell_dir/measurements/.rep-01-midpoint.partial" ]] || {
    printf 'failed cgroup-only midpoint capture leaked its private transaction\n' >&2
    return 1
  }

  printf '1000 1000000\n1001 1001000\n1001 1001000\n' >"$clock_file"
  benchmark_job_is_running() {
    ((liveness_checks += 1))
    ((liveness_checks == 1))
  }
  capture_scheduled_midpoint_cgroups() { return 0; }
  activate_benchmark
  capture_scheduled_repetition_midpoint "$cell_dir" 1
  jq -e '.status == "unavailable" and
    .reason == "load_client_exited_during_scheduled_midpoint_capture" and
    .kind == "scheduled-cgroup-v2-midpoint-receipt" and .repetition == 1 and
    .benchmark_duration_seconds == 2 and
    .benchmark == {pid: 4242, identity: "4242 4242 1010",
      result_source: "cells/getsockopt-hit/measurements/rep-01.json"} and
    .scheduled_seconds_after_confirmed_launch == 1 and
    .scope.cgroup_v2_process_tree.status == "not_collected" and
    .scope.obi_metrics == {status: "not_collected", reason: "zero_in_window_scrapes_required"}' \
    "$cell_dir/measurements/rep-01-midpoint.json" >/dev/null || {
    printf 'post-capture early exit did not retain the bounded unavailable receipt\n' >&2
    return 1
  }
  [[ ! -e "$cell_dir/measurements/rep-01-midpoint" &&
    ! -e "$cell_dir/measurements/.rep-01-midpoint.partial" ]] || {
    printf 'post-capture early exit retained an accepted or partial midpoint\n' >&2
    return 1
  }

  rm -f -- "$cell_dir/measurements/rep-01-midpoint.json"

  # The receipt schema binds every active transaction field and both clocks.
  activate_benchmark
  printf '1000 1000000\n' >"$clock_file"
  begin_scheduled_midpoint_transaction "$cell_dir" 1
  # shellcheck disable=SC2034 # Consumed dynamically by the receipt renderer.
  MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS=1001 \
    MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS=1001000 \
    MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS=1001 \
    MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS=1001000 \
    MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS=1001 \
    MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS=1001000
  scheduled_midpoint_receipt_json available >"$receipt"
  validate_scheduled_midpoint_receipt_schema \
    "$receipt" getsockopt-hit 1 available \
    "$MIDPOINT_PARENT_IDENTITY" "$MIDPOINT_PARTIAL_IDENTITY"
  for mutation in \
    '.cell = "unix-hit"' '.repetition = 2' '.benchmark_duration_seconds = 3' \
    '.measurement_parent_identity = "1:1:0:700"' \
    '.benchmark.result_source = "cells/getsockopt-hit/measurements/rep-02.json"' \
    '.clocks.sleep_ended.monotonic_milliseconds = 1000999' \
    '.elapsed.sleep_monotonic_milliseconds = 999'; do
    jq "$mutation" "$receipt" >"$receipt.invalid"
    if validate_scheduled_midpoint_receipt_schema \
      "$receipt.invalid" getsockopt-hit 1 available \
      "$MIDPOINT_PARENT_IDENTITY" "$MIDPOINT_PARTIAL_IDENTITY"; then
      printf 'midpoint receipt accepted identity/timing drift: %s\n' "$mutation" >&2
      return 1
    fi
  done
  rm -f -- "$receipt.invalid"

  # A symlink child is never followed or unlinked under an ambiguous cleanup.
  printf 'outside\n' >"$outside"
  ln -s -- "$outside" "$MIDPOINT_PARTIAL/snapshot.json"
  if discard_scheduled_midpoint_partial; then
    printf 'midpoint cleanup accepted a replacement symlink\n' >&2
    return 1
  fi
  [[ "$(<"$outside")" == outside && -L "$MIDPOINT_PARTIAL/snapshot.json" ]] || return 1
  rm -f -- "$MIDPOINT_PARTIAL/snapshot.json"
  discard_scheduled_midpoint_partial

  # Replacing the transaction directory itself is equally ambiguous. Cleanup
  # refuses the replacement and never follows it into an outside directory.
  activate_benchmark
  printf '1000 1000000\n' >"$clock_file"
  begin_scheduled_midpoint_transaction "$cell_dir" 1
  mkdir -- "$outside_directory"
  printf 'outside-directory\n' >"$outside_directory/sentinel"
  mv -- "$MIDPOINT_PARTIAL" "$MIDPOINT_PARTIAL.original"
  ln -s -- "$outside_directory" "$MIDPOINT_PARTIAL"
  if discard_scheduled_midpoint_partial; then
    printf 'midpoint cleanup accepted a replaced transaction directory\n' >&2
    return 1
  fi
  [[ "$(<"$outside_directory/sentinel")" == outside-directory &&
    -L "$MIDPOINT_PARTIAL" && -d "$MIDPOINT_PARTIAL.original" ]] || return 1
  rm -f -- "$MIDPOINT_PARTIAL"
  mv -- "$MIDPOINT_PARTIAL.original" "$MIDPOINT_PARTIAL"
  discard_scheduled_midpoint_partial

  # Parent replacement is refused and the original transaction remains intact.
  activate_benchmark
  printf '1000 1000000\n' >"$clock_file"
  begin_scheduled_midpoint_transaction "$cell_dir" 1
  original_measurements="$cell_dir/measurements.original"
  mv -- "$cell_dir/measurements" "$original_measurements"
  mkdir -- "$cell_dir/measurements"
  if discard_scheduled_midpoint_partial; then
    printf 'midpoint cleanup accepted a replaced output parent\n' >&2
    return 1
  fi
  [[ -d "$original_measurements/.rep-01-midpoint.partial" ]] || return 1
  rmdir -- "$cell_dir/measurements"
  mv -- "$original_measurements" "$cell_dir/measurements"
  discard_scheduled_midpoint_partial

  # The EXIT handler invokes the same exact cleanup authority.
  activate_benchmark
  printf '1000 1000000\n' >"$clock_file"
  begin_scheduled_midpoint_transaction "$cell_dir" 1
  OUTPUT_READY=false
  abort_active_benchmark() { clear_active_benchmark; }
  if (on_exit 73); then
    printf 'midpoint EXIT cleanup changed the primary failure to success\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/measurements/.rep-01-midpoint.partial" ]] || {
    printf 'EXIT cleanup retained the exact active midpoint partial\n' >&2
    return 1
  }
  clear_active_midpoint_transaction
  clear_active_benchmark

  # Both halves of a published midpoint are independently byte-bounded and
  # duplicate-aware before their cross-file bindings are evaluated.
  mkdir -- "$boundary_dir"
  write_scheduled_midpoint_boundary_fixture \
    "$boundary_dir" getsockopt-hit 1 '["java-backend"]'
  write_bound_cgroup_v2_snapshot_fixture \
    "$boundary_dir/java-backend-cgroup-v2.json" getsockopt-hit java-backend \
    scheduled_repetition_midpoint 1 3 3 3 3 153600 153600 1100 1101
  validate_scheduled_midpoint_boundary "$boundary_dir" getsockopt-hit 1
  cp -- "$boundary_dir/midpoint-receipt.json" "$boundary_dir/midpoint-receipt.valid"
  compact="$(jq -c . "$boundary_dir/midpoint-receipt.json")" || return 1
  mutated_json="${compact/\"benchmark\":{\"pid\":4242/\"benchmark\":{\"pid\":4242,\"pid\":4242}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$boundary_dir/midpoint-receipt.json"
  if validate_scheduled_midpoint_boundary "$boundary_dir" getsockopt-hit 1; then
    printf 'midpoint validator accepted a duplicate nested receipt key\n' >&2
    return 1
  fi
  mv -T -- "$boundary_dir/midpoint-receipt.valid" \
    "$boundary_dir/midpoint-receipt.json"
  cp -- "$boundary_dir/snapshot.json" "$boundary_dir/snapshot.valid"
  compact="$(jq -c . "$boundary_dir/snapshot.json")" || return 1
  mutated_json="${compact/\"metrics\":{\"status\":\"not_collected\"/\"metrics\":{\"status\":\"not_collected\",\"status\":\"not_collected\"}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$boundary_dir/snapshot.json"
  if validate_scheduled_midpoint_boundary "$boundary_dir" getsockopt-hit 1; then
    printf 'midpoint validator accepted a duplicate nested boundary key\n' >&2
    return 1
  fi
  mv -T -- "$boundary_dir/snapshot.valid" "$boundary_dir/snapshot.json"
  cp -- "$boundary_dir/midpoint-receipt.json" "$boundary_dir/midpoint-receipt.valid"
  head -c "$((MAX_MIDPOINT_RECEIPT_BYTES + 1))" /dev/zero | tr '\0' x \
    >"$boundary_dir/midpoint-receipt.json"
  if validate_scheduled_midpoint_boundary "$boundary_dir" getsockopt-hit 1; then
    printf 'midpoint validator accepted a receipt above its byte cap\n' >&2
    return 1
  fi
  mv -T -- "$boundary_dir/midpoint-receipt.valid" \
    "$boundary_dir/midpoint-receipt.json"
  cp -- "$boundary_dir/snapshot.json" "$boundary_dir/snapshot.valid"
  head -c "$((MAX_BOUNDARY_SNAPSHOT_BYTES + 1))" /dev/zero | tr '\0' x \
    >"$boundary_dir/snapshot.json"
  if validate_scheduled_midpoint_boundary "$boundary_dir" getsockopt-hit 1; then
    printf 'midpoint validator accepted a boundary above its byte cap\n' >&2
    return 1
  fi
  mv -T -- "$boundary_dir/snapshot.valid" "$boundary_dir/snapshot.json"
  validate_scheduled_midpoint_boundary "$boundary_dir" getsockopt-hit 1

  prepare_midpoint_publication_fixture() {
    activate_benchmark
    printf '1000 1000000\n' >"$clock_file"
    begin_scheduled_midpoint_transaction "$cell_dir" 1 || return 1
    publication_partial="$MIDPOINT_PARTIAL"
    publication_final="$MIDPOINT_FINAL"
    write_scheduled_midpoint_boundary_fixture \
      "$publication_partial" getsockopt-hit 1 '["obi","java-backend"]' || return 1
    for service in obi java-backend; do
      write_bound_cgroup_v2_snapshot_fixture \
        "$publication_partial/$service-cgroup-v2.json" getsockopt-hit "$service" \
        scheduled_repetition_midpoint 1 3 3 3 3 153600 153600 1100 1101 || return 1
    done
    validate_scheduled_midpoint_boundary \
      "$publication_partial" getsockopt-hit 1 publication_bundle || return 1
    printf '%s' "$publication_bundle" | jq -e '
      (.publication_leaves | map(.name)) == [
        "java-backend-cgroup-v2.json", "java-backend-identity.txt",
        "midpoint-receipt.json", "obi-cgroup-v2.json", "obi-identity.txt",
        "snapshot.json"
      ] and all(.publication_leaves[]; . as $leaf |
        ($leaf.size_bytes | type == "number" and . > 0) and
        ($leaf.maximum_bytes | type == "number") and
        $leaf.maximum_bytes >= $leaf.size_bytes and
        ($leaf.identity | test("^[0-9]+:[1-9][0-9]*:[0-9]+:[1-9][0-9]*:[0-9]+:[0-9]+:[0-9]+:[1-9][0-9]*$")) and
        ($leaf.sha256 | test("^[0-9a-f]{64}$")))
    ' >/dev/null
  }
  prepare_unavailable_midpoint_fixture() {
    activate_benchmark
    printf '1000 1000000\n' >"$clock_file"
    begin_scheduled_midpoint_transaction "$cell_dir" 1 || return 1
    # shellcheck disable=SC2034 # Consumed dynamically by the receipt renderer.
    MIDPOINT_SLEEP_ENDED_WALL_EPOCH_SECONDS=1001 \
      MIDPOINT_SLEEP_ENDED_MONOTONIC_MILLISECONDS=1001000 \
      MIDPOINT_CAPTURE_STARTED_WALL_EPOCH_SECONDS=1001 \
      MIDPOINT_CAPTURE_STARTED_MONOTONIC_MILLISECONDS=1001000 \
      MIDPOINT_CAPTURE_ENDED_WALL_EPOCH_SECONDS=1001 \
      MIDPOINT_CAPTURE_ENDED_MONOTONIC_MILLISECONDS=1001000
    unavailable_output="$MIDPOINT_FINAL.json"
    unavailable_parent_identity="$MIDPOINT_PARENT_IDENTITY"
    unavailable_partial_identity="$MIDPOINT_PARTIAL_IDENTITY"
  }
  remove_published_midpoint_fixture() {
    local path=""
    for path in snapshot.json midpoint-receipt.json \
      obi-identity.txt obi-cgroup-v2.json \
      java-backend-identity.txt java-backend-cgroup-v2.json; do
      rm -f -- "$publication_final/$path" || return 1
    done
    rmdir -- "$publication_final"
  }

  # Stable publication is one isolated absolute-Perl transaction. Shell
  # function and module-path poisoning cannot impersonate its FD protocol.
  prepare_midpoint_publication_fixture
  resolve_trusted_native_tool env || return 1
  NATIVE_BENCHMARK_ENV_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  # shellcheck disable=SC2034 # Consumed dynamically by the sourced native publisher.
  resolve_trusted_native_tool perl || return 1
  NATIVE_BENCHMARK_PERL_COMMAND="$TRUSTED_NATIVE_TOOL_RESULT"
  mkdir -p -- "$poison_directory/Digest"
  printf 'BEGIN { open(my $fh, ">", q{%s}) or die; print {$fh} "loaded"; close($fh) or die; } die "poisoned Digest::SHA loaded";\n' \
    "$poison_marker" >"$poison_directory/Digest/SHA.pm"
  export PERL5LIB="$poison_directory"
  export PERL5OPT='-MDigest::SHA'
  env() { return 91; }
  perl() { return 92; }
  publish_scheduled_midpoint_directory "$publication_bundle" || {
    printf 'isolated midpoint helper rejected a stable held roster\n' >&2
    return 1
  }
  unset -f env perl
  unset PERL5LIB PERL5OPT
  [[ -d "$publication_final" && ! -L "$publication_final" &&
    ! -e "$publication_partial" && ! -L "$publication_partial" &&
    ! -e "$poison_marker" ]] || {
    printf 'stable midpoint publication did not produce only the exact final directory\n' >&2
    return 1
  }
  validate_scheduled_midpoint_boundary "$publication_final" getsockopt-hit 1
  clear_active_midpoint_transaction
  clear_active_benchmark
  remove_published_midpoint_fixture

  # Reproduce the old final-check gap: mutate an otherwise schema-valid receipt
  # after held validation. The helper must reject the changed inode/digest and
  # the exact producer-owned partial remains safely cleanable.
  prepare_midpoint_publication_fixture
  scheduled_midpoint_publication_ready() {
    local -r partial="$1"
    local mutated="$partial/midpoint-receipt.mutated"
    jq '.clocks.capture_ended = {
      wall_epoch_seconds: 1002, monotonic_milliseconds: 1002000
    }' "$partial/midpoint-receipt.json" >"$mutated" || return 1
    mv -T -- "$mutated" "$partial/midpoint-receipt.json"
  }
  if publish_scheduled_midpoint_directory "$publication_bundle"; then
    printf 'midpoint helper accepted final-check receipt replacement\n' >&2
    return 1
  fi
  [[ ! -e "$publication_final" && ! -L "$publication_final" &&
    -d "$publication_partial" ]] || return 1
  validate_scheduled_midpoint_boundary "$publication_partial" getsockopt-hit 1
  discard_scheduled_midpoint_partial
  [[ ! -e "$publication_partial" && ! -L "$publication_partial" ]] || return 1
  clear_active_benchmark

  # A destination created after the Bash check is never replaced or removed.
  # Cleanup uses only the creation-bound partial authority.
  prepare_midpoint_publication_fixture
  scheduled_midpoint_publication_ready() {
    local -r final="$2"
    mkdir --mode=0700 -- "$final" || return 1
    printf 'foreign\n' >"$final/sentinel"
  }
  if publish_scheduled_midpoint_directory "$publication_bundle"; then
    printf 'midpoint helper replaced a concurrently-created final directory\n' >&2
    return 1
  fi
  [[ "$(<"$publication_final/sentinel")" == foreign &&
    -d "$publication_partial" ]] || return 1
  discard_scheduled_midpoint_partial allow_foreign_final
  [[ ! -e "$publication_partial" && ! -L "$publication_partial" &&
    "$(<"$publication_final/sentinel")" == foreign ]] || {
    printf 'midpoint failure cleanup touched a foreign final directory\n' >&2
    return 1
  }
  rm -f -- "$publication_final/sentinel"
  rmdir -- "$publication_final"
  clear_active_benchmark

  # An unavailable receipt is also a held publish-once image. Its anonymous
  # inode is linked only to an absent name after the exact partial is cleaned.
  json_publication_absence_ready() { :; }
  prepare_unavailable_midpoint_fixture
  write_unavailable_scheduled_midpoint_receipt \
    load_client_not_live_at_scheduled_midpoint || {
    printf 'stable unavailable midpoint receipt was not published once\n' >&2
    return 1
  }
  validate_scheduled_midpoint_receipt_schema "$unavailable_output" \
    getsockopt-hit 1 unavailable "$unavailable_parent_identity" \
    "$unavailable_partial_identity"
  [[ "$MIDPOINT_ACTIVE" == false &&
    ! -e "$cell_dir/measurements/.rep-01-midpoint.partial" &&
    -f "$unavailable_output" && ! -L "$unavailable_output" &&
    -z "$(find "$cell_dir/measurements" -mindepth 1 -maxdepth 1 \
      -name '.rep-01-midpoint.json.*' -print -quit)" ]] || {
    printf 'stable unavailable publication retained a partial or named candidate\n' >&2
    return 1
  }
  clear_active_benchmark
  rm -f -- "$unavailable_output"

  # A foreign regular file, symlink, or directory created in the old final
  # check-to-move gap is never replaced or removed. Only the authenticated
  # producer-owned partial may be cleaned before the atomic absent-name link.
  for mutation in regular symlink directory; do
    json_publication_absence_ready() {
      [[ "$1" == "$unavailable_output" ]] || return 1
      case "$mutation" in
        regular)
          printf 'FOREIGN-SENTINEL\n' >"$1"
          ;;
        symlink)
          printf 'FOREIGN-SYMLINK-TARGET\n' >"$unavailable_foreign_target" || return 1
          ln -s -- "$unavailable_foreign_target" "$1"
          ;;
        directory)
          mkdir --mode=0700 -- "$1" || return 1
          printf 'FOREIGN-DIRECTORY-SENTINEL\n' >"$1/sentinel"
          ;;
        *) return 1 ;;
      esac
    }
    prepare_unavailable_midpoint_fixture
    if write_unavailable_scheduled_midpoint_receipt \
      load_client_not_live_at_scheduled_midpoint >/dev/null 2>&1; then
      printf 'unavailable midpoint replaced a foreign %s final leaf\n' \
        "$mutation" >&2
      return 1
    fi
    [[ "$MIDPOINT_ACTIVE" == false &&
      ! -e "$cell_dir/measurements/.rep-01-midpoint.partial" &&
      ! -L "$cell_dir/measurements/.rep-01-midpoint.partial" ]] || {
      printf 'unavailable midpoint race did not clean only its exact partial: %s\n' \
        "$mutation" >&2
      return 1
    }
    case "$mutation" in
      regular)
        [[ -f "$unavailable_output" && ! -L "$unavailable_output" &&
          "$(<"$unavailable_output")" == FOREIGN-SENTINEL ]] || return 1
        rm -f -- "$unavailable_output"
        ;;
      symlink)
        [[ -L "$unavailable_output" &&
          "$(readlink -- "$unavailable_output")" == "$unavailable_foreign_target" &&
          "$(<"$unavailable_foreign_target")" == FOREIGN-SYMLINK-TARGET ]] || return 1
        rm -f -- "$unavailable_output" "$unavailable_foreign_target"
        ;;
      directory)
        [[ -d "$unavailable_output" && ! -L "$unavailable_output" &&
          "$(<"$unavailable_output/sentinel")" == FOREIGN-DIRECTORY-SENTINEL ]] || return 1
        rm -f -- "$unavailable_output/sentinel"
        rmdir -- "$unavailable_output"
        ;;
    esac
    clear_active_benchmark
  done
  json_publication_absence_ready() { :; }
)

test_ordered_idle_recovery_is_exactly_two_serial_thirty_second_samples() (
  local -r fixture="$TEST_TMP_DIR/ordered-idle-recovery"
  local -r sleep_command="$fixture/fake-sleep"
  local -r events="$fixture/events.log"
  local -r clock_state="$fixture/clock.txt"
  local compact=""
  local mutated_json=""
  local mutation=""

  mkdir -- "$fixture"
  export RECOVERY_TEST_EVENTS="$events"
  SLEEP_COMMAND="$sleep_command"
  CELL_SLUG='fixture-cell'
  printf '1000 1000000\n' >"$clock_state"
  clock_pair_values() { command cat -- "$clock_state"; }
  # Bash invokes the configured path, so make that path a script which updates
  # the shared clock state rather than overriding the harness function.
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -Eeuo pipefail\n'
    printf 'read -r wall monotonic <"$RECOVERY_TEST_CLOCK"\n'
    printf 'printf "sleep %%s\\n" "$1" >>"$RECOVERY_TEST_EVENTS"\n'
    printf 'printf "%%s %%s\\n" "$((wall + $1))" "$((monotonic + $1 * 1000))" >"$RECOVERY_TEST_CLOCK"\n'
  } >"$sleep_command"
  chmod 0700 -- "$sleep_command"
  export RECOVERY_TEST_CLOCK="$clock_state"
  capture_resource_snapshot() {
    local wall="" monotonic="" extra=""
    printf 'capture %s\n' "$2" >>"$events"
    mkdir -- "$1"
    read -r wall monotonic extra <"$clock_state"
    [[ -z "$extra" ]] || return 1
    jq -n --arg cell "$CELL_SLUG" --arg timing "$2" \
      --argjson wall "$wall" --argjson monotonic "$monotonic" '{
        schema_version: 1, kind: "program-and-resource-diagnostic-snapshot",
        cell: $cell, timing: $timing,
        capture: {
          started: {wall_epoch_seconds: $wall, monotonic_milliseconds: $monotonic},
          ended: {wall_epoch_seconds: ($wall + 1),
            monotonic_milliseconds: ($monotonic + 1000)}
        },
        authority: {classification: "resource_boundary", process_tree_cgroup_v2: "collected"},
        java_diagnostics: {status: "not_collected", reason: "excluded_from_ordered_idle_recovery_window"}
      }' >"$1/snapshot.json"
    printf '%s %s\n' "$((wall + 1))" "$((monotonic + 1000))" >"$clock_state"
  }
  capture_ordered_idle_recovery "$fixture"
  diff -u <(printf '%s\n' \
    'sleep 30' 'capture idle_recovery_01' \
    'sleep 30' 'capture idle_recovery_02') "$events" || {
    printf 'idle recovery was not two serial 30-second samples\n' >&2
    return 1
  }
  validate_recovery_schedule_schema "$fixture/recovery-schedule.json"
  jq -e '.required_consecutive_samples == 2 and
    .load_activity_between_samples == false and
    [.samples[].ordinal] == [1, 2] and
    all(.samples[]; .idle_interval_seconds == 30 and
      .sleep.elapsed_wall_seconds == 30 and
      .sleep.elapsed_monotonic_milliseconds == 30000)' \
    "$fixture/recovery-schedule.json" >/dev/null
  cp -- "$fixture/recovery-schedule.json" "$fixture/recovery-schedule.valid"
  compact="$(jq -c . "$fixture/recovery-schedule.json")" || return 1
  mutated_json="${compact/\"elapsed_wall_seconds\":30/\"elapsed_wall_seconds\":30,\"elapsed_wall_seconds\":30}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" >"$fixture/recovery-schedule.json"
  if validate_recovery_schedule_schema "$fixture/recovery-schedule.json"; then
    printf 'ordered recovery accepted a duplicate nested schedule key\n' >&2
    return 1
  fi
  mv -T -- "$fixture/recovery-schedule.valid" "$fixture/recovery-schedule.json"
  cp -- "$fixture/recovery-schedule.json" "$fixture/recovery-schedule.valid"
  head -c "$((MAX_RECOVERY_SCHEDULE_BYTES + 1))" /dev/zero | tr '\0' x \
    >"$fixture/recovery-schedule.json"
  if validate_recovery_schedule_schema "$fixture/recovery-schedule.json"; then
    printf 'ordered recovery accepted a schedule above its byte cap\n' >&2
    return 1
  fi
  mv -T -- "$fixture/recovery-schedule.valid" "$fixture/recovery-schedule.json"

  cp -- "$fixture/resources-idle-recovery-01/snapshot.json" \
    "$fixture/resources-idle-recovery-01/snapshot.valid"
  compact="$(jq -c . "$fixture/resources-idle-recovery-01/snapshot.json")" || return 1
  mutated_json="${compact/\"authority\":{\"classification\":\"resource_boundary\"/\"authority\":{\"classification\":\"resource_boundary\",\"classification\":\"resource_boundary\"}"
  [[ "$mutated_json" != "$compact" ]] || return 1
  printf '%s\n' "$mutated_json" \
    >"$fixture/resources-idle-recovery-01/snapshot.json"
  if validate_recovery_schedule_schema "$fixture/recovery-schedule.json"; then
    printf 'ordered recovery accepted a duplicate nested boundary key\n' >&2
    return 1
  fi
  mv -T -- "$fixture/resources-idle-recovery-01/snapshot.valid" \
    "$fixture/resources-idle-recovery-01/snapshot.json"
  validate_recovery_schedule_schema "$fixture/recovery-schedule.json"
  for mutation in \
    '.samples[0].sleep.elapsed_wall_seconds = 0' \
    '.samples[0].sleep.ended.monotonic_milliseconds = 1029999' \
    '.samples[1].sleep.started.monotonic_milliseconds = 1030999' \
    '.samples |= reverse' \
    '.samples[1].sleep.ended.wall_epoch_seconds = 1000'; do
    jq "$mutation" "$fixture/recovery-schedule.json" >"$fixture/recovery.invalid"
    if validate_recovery_schedule_schema "$fixture/recovery.invalid"; then
      printf 'ordered recovery accepted short/rollback/order drift: %s\n' "$mutation" >&2
      return 1
    fi
  done
)

test_helper_idle_bpf_metrics_require_constrained_deltas() (
  local -r before="$TEST_TMP_DIR/helper-idle-bpf-before.prom"
  local -r after="$TEST_TMP_DIR/helper-idle-bpf-after.prom"
  local -r unavailable="$TEST_TMP_DIR/helper-idle-bpf-unavailable.prom"
  local -r duplicate="$TEST_TMP_DIR/helper-idle-bpf-duplicate.prom"
  local -r before_zero="$TEST_TMP_DIR/helper-idle-bpf-before-zero.prom"
  local -r after_zero="$TEST_TMP_DIR/helper-idle-bpf-after-zero.prom"
  local -r churn_before="$TEST_TMP_DIR/helper-idle-bpf-churn-before.prom"
  local -r churn_after="$TEST_TMP_DIR/helper-idle-bpf-churn-after.prom"
  local -r safe_counter="$TEST_TMP_DIR/helper-idle-bpf-safe-counter.prom"
  local -r unsafe_counter="$TEST_TMP_DIR/helper-idle-bpf-unsafe-counter.prom"
  local -r output="$TEST_TMP_DIR/helper-idle-bpf-deltas.json"
  local -r state="$TEST_TMP_DIR/helper-idle-bpf-state.txt"
  local mutation=""
  local transport=""
  local operation=""
  local report=""
  local candidate=""
  local inject=""
  local stage=""
  local handoff=""
  local take=""
  local discard=""
  local negotiate_missing=""

  reset_options
  cell_spec getsockopt-helper-idle
  export FAKE_BPF_METRICS_FILE="$state"
  printf '5 0 0 0 0 0 0 1 0 0 0\n' >"$state"
  fake_bpf_metrics_snapshot >"$before"
  printf '13 0 0 0 0 0 0 9 0 0 0\n' >"$state"
  fake_bpf_metrics_snapshot >"$after"
  helper_idle_metric_delta_json "$before" "$after" "$output" || {
    printf 'helper-idle BPF metrics rejected a no-handoff direct-Java window\n' >&2
    return 1
  }
  jq -e '
    .semantic == "direct_java_no_upstream_handoff_not_state_map_miss_proof" and
    .report_watermark == {
      operation: "report", status: "valid", transport: "tcp",
      before: 5, after: 13, observed_delta: 8
    } and
    (.constrained_zero_deltas | map({category, operation, transport, expected_delta}) == [
      {category: "tcp-candidate", operation: "candidate", transport: "tcp", expected_delta: 0},
      {category: "tcp-inject", operation: "inject", transport: "tcp", expected_delta: 0},
      {category: "tcp-stage", operation: "stage", transport: "tcp", expected_delta: 0},
      {category: "tcp-handoff", operation: "handoff", transport: "tcp", expected_delta: 0},
      {category: "tcp-handoff_admission", operation: "handoff_admission", transport: "tcp", expected_delta: 0},
      {category: "getsockopt-take", operation: "take", transport: "getsockopt", expected_delta: 0},
      {category: "getsockopt-discard", operation: "discard", transport: "getsockopt", expected_delta: 0}
    ]) and
    (.constrained_zero_deltas | all(.observed_delta == 0 and .expected_delta == 0)) and
    (.constrained_zero_deltas[] |
      select(.operation == "handoff_admission") |
      .before_series == 0 and .after_series == 0) and
    .informative_getsockopt_negotiate_missing == {
      before_series: 1, after_series: 1, before: 1, after: 9, observed_delta: 8,
      interpretation: "informative_only_not_a_retrieval_outcome_reconciliation"
    }
  ' "$output" >/dev/null || {
    printf 'helper-idle BPF metrics lost the report and informative-negotiation distinction\n' >&2
    return 1
  }
  rm -f -- "$output"
  cp -- "$before" "$before_zero"
  cp -- "$after" "$after_zero"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="handoff_admission",status="ambiguous",transport="tcp"} 0' \
    'obi_java_remote_parent_operations_total{operation="handoff_admission",status="overload",transport="tcp"} 0' \
    >>"$before_zero"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="handoff_admission",status="ambiguous",transport="tcp"} 0' \
    'obi_java_remote_parent_operations_total{operation="handoff_admission",status="overload",transport="tcp"} 0' \
    >>"$after_zero"
  helper_idle_metric_delta_json "$before_zero" "$after_zero" "$output" || {
    printf 'helper-idle BPF metrics rejected explicit zero admission rows\n' >&2
    return 1
  }
  rm -f -- "$output"
  printf 'status=unavailable\n' >"$unavailable"
  if helper_idle_metric_delta_json "$unavailable" "$after" "$output" >/dev/null 2>&1; then
    printf 'helper-idle BPF metrics accepted an unavailable scrape\n' >&2
    return 1
  fi
  for mutation in \
    'tcp candidate 13 1 0 0 0 0 0 9' \
    'tcp inject 13 0 1 0 0 0 0 9' \
    'tcp stage 13 0 0 1 0 0 0 9' \
    'tcp handoff 13 0 0 0 1 0 0 9' \
    'getsockopt take 13 0 0 0 0 1 0 9' \
    'getsockopt discard 13 0 0 0 0 0 1 9'; do
    read -r transport operation report candidate inject stage handoff take discard negotiate_missing \
      <<<"$mutation"
    printf '%s %s %s %s %s %s %s %s 0 0 0\n' \
      "$report" "$candidate" "$inject" "$stage" "$handoff" "$take" "$discard" \
      "$negotiate_missing" >"$state"
    fake_bpf_metrics_snapshot >"$after"
    if helper_idle_metric_delta_json "$before" "$after" "$output" >/dev/null 2>&1; then
      printf 'helper-idle BPF metrics accepted %s/%s activity\n' "$transport" "$operation" >&2
      return 1
    fi
  done
  printf '13 0 0 0 0 0 0 9 0 0 0\n' >"$state"
  fake_bpf_metrics_snapshot >"$after"
  for mutation in ambiguous overload; do
    cp -- "$after" "$after.$mutation"
    printf '%s\n' \
      "obi_java_remote_parent_operations_total{operation=\"handoff_admission\",status=\"$mutation\",transport=\"tcp\"} 1" \
      >>"$after.$mutation"
    if helper_idle_metric_delta_json \
      "$before" "$after.$mutation" "$output" >/dev/null 2>&1; then
      printf 'helper-idle BPF metrics accepted handoff admission %s activity\n' \
        "$mutation" >&2
      return 1
    fi
  done
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} 10' \
    'obi_java_remote_parent_operations_total{operation="negotiate",status="missing",transport="getsockopt"} 0' \
    'obi_java_remote_parent_operations_total{operation="report",status="valid",transport="tcp"} 5' \
    >"$churn_before"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="ambiguous",transport="tcp"} 10' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} 0' \
    'obi_java_remote_parent_operations_total{operation="negotiate",status="missing",transport="getsockopt"} 0' \
    'obi_java_remote_parent_operations_total{operation="report",status="valid",transport="tcp"} 6' \
    >"$churn_after"
  if helper_idle_metric_delta_json "$churn_before" "$churn_after" "$output" >/dev/null 2>&1; then
    printf 'helper-idle BPF metrics accepted a reset or status-series churn hidden by an aggregate\n' >&2
    return 1
  fi
  printf '13 0 0 0 0 0 0 9 0 0 0\n' >"$state"
  fake_bpf_metrics_snapshot >"$after"
  cp -- "$after" "$duplicate"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} 0' \
    >>"$duplicate"
  if helper_idle_metric_delta_json "$before" "$duplicate" "$output" >/dev/null 2>&1; then
    printf 'helper-idle BPF metrics accepted duplicate label sets\n' >&2
    return 1
  fi
  sed \
    's/{operation="report",status="valid",transport="tcp"} 13$/{operation="report",status="valid",transport="tcp"} 9007199254740991/' \
    "$after" >"$safe_counter"
  [[ "$(helper_idle_report_value "$safe_counter")" == 9007199254740991 ]] || {
    printf 'helper-idle BPF metrics rejected the largest exact JSON integer counter\n' >&2
    return 1
  }
  sed \
    's/{operation="report",status="valid",transport="tcp"} 13$/{operation="report",status="valid",transport="tcp"} 9007199254740992/' \
    "$after" >"$unsafe_counter"
  if helper_idle_report_value "$unsafe_counter" >/dev/null 2>&1; then
    printf 'helper-idle BPF metrics accepted an inexact JSON integer counter\n' >&2
    return 1
  fi
)

test_obi_metrics_capture_cleans_partial_after_stat_failure() (
  local -r output="$TEST_TMP_DIR/obi-metrics-stat-failure.prom"

  reset_options
  CELL_REQUIRES_OBI=true
  run_bounded() {
    printf '%s\n' '# fake OBI metrics payload'
  }
  stat() {
    return 1
  }

  capture_obi_metrics "$output" || {
    printf 'OBI metrics capture did not fail closed after stat failure\n' >&2
    return 1
  }
  grep -Fxq 'status=unavailable' "$output" || {
    printf 'OBI metrics capture did not publish unavailable status after stat failure\n' >&2
    return 1
  }
  [[ ! -e "$output.partial" && ! -L "$output.partial" ]] || {
    printf 'OBI metrics capture retained a partial file after stat failure\n' >&2
    return 1
  }
)

test_helper_idle_bpf_fence_requires_two_post_boundary_passes() (
  local -r observed="$TEST_TMP_DIR/helper-idle-observed.prom"
  local -r output="$TEST_TMP_DIR/helper-idle-causal.prom"
  local -r fence="$TEST_TMP_DIR/helper-idle-causal.json"
  local -r delta="$TEST_TMP_DIR/helper-idle-causal-delta.json"
  local -r state="$TEST_TMP_DIR/helper-idle-causal-state.txt"
  local captures=0
  local candidate_result=""

  reset_options
  cell_spec getsockopt-helper-idle
  export FAKE_BPF_METRICS_FILE="$state"
  printf '10 0 0 0 0 0 0 0 0 0 0\n' >"$state"
  fake_bpf_metrics_snapshot >"$observed"
  capture_obi_metrics() {
    local -r capture="$1"

    ((captures += 1))
    case "$captures" in
      # The first post-boundary pass is a delayed prior report. The direct
      # workload's candidate only arrives in the following stats pass.
      1) printf '11 0 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      2) printf '12 4 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      3) printf '13 4 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      4) printf '14 4 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      *)
        printf 'unexpected helper-idle fence metric capture: %s\n' "$captures" >&2
        return 1
        ;;
    esac
    fake_bpf_metrics_snapshot >"$capture"
  }

  wait_for_helper_idle_two_pass_fence \
    "$observed" "$output" "$fence" "delayed helper-idle workload" || {
    printf 'helper-idle BPF fence rejected a stable delayed-publication sequence\n' >&2
    return 1
  }
  candidate_result="$(helper_idle_metric_total "$output" candidate tcp)" || return 1
  [[ "$candidate_result" == "1 4" ]] || {
    printf 'helper-idle BPF fence retained the stale pre-workload counter snapshot\n' >&2
    return 1
  }
  jq -e '
    .initial_report == 10 and
    .first_post_boundary_report == 11 and
    .second_post_boundary_report == 12 and
    .observed_delta == 2 and
    .fence == {
      required_serial_post_boundary_report_passes: 2,
      report_is_published_after_each_successful_java_bridge_stats_pass: true
    }
  ' "$fence" >/dev/null || {
    printf 'helper-idle BPF fence omitted its two-pass causal evidence\n' >&2
    return 1
  }
  if helper_idle_metric_delta_json "$observed" "$output" "$delta" >/dev/null 2>&1; then
    printf 'helper-idle BPF fence let delayed lifecycle activity appear as a zero delta\n' >&2
    return 1
  fi
)

test_helper_idle_sustained_rejects_delayed_post_workload_lifecycle() (
  local -r cell_dir="$TEST_TMP_DIR/helper-idle-delayed-lifecycle"
  local -r state="$TEST_TMP_DIR/helper-idle-delayed-lifecycle-state.txt"
  local metrics_captures=0
  local diagnostics_captures=0
  local measurement_repetitions=0
  local java_measurement_begins=0
  local java_measurement_stops=0
  local java_measurement_finishes=0
  local run_status=0
  local candidate_result=""

  reset_options
  cell_spec getsockopt-helper-idle
  WARMUP_SECONDS=2
  DURATION_SECONDS=2
  REPETITIONS=5
  export FAKE_BPF_METRICS_FILE="$state"
  mkdir -p -- "$cell_dir/measurements"
  capture_java_diagnostics() {
    local -r output="$1"

    ((diagnostics_captures += 1))
    case "$diagnostics_captures" in
      1) write_valid_java_diagnostics_snapshot "$output" 0 0 0 0 ;;
      2) write_valid_java_diagnostics_snapshot "$output" 0 0 0 p ;;
      *)
        printf 'unexpected delayed-lifecycle Java diagnostic capture: %s\n' \
          "$diagnostics_captures" >&2
        return 1
        ;;
    esac
  }
  capture_obi_metrics() {
    local -r output="$1"

    ((metrics_captures += 1))
    case "$metrics_captures" in
      # pre seed, then the serial stale/fresh report passes
      1) printf '10 0 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      2) printf '11 0 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      3) printf '12 0 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      # post seed, then a delayed pre-window pass followed by the pass that
      # actually publishes the direct-workload candidate.
      4) printf '12 0 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      5) printf '13 0 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      6) printf '14 1 0 0 0 0 0 0 0 0 0\n' >"$state" ;;
      *)
        printf 'unexpected delayed-lifecycle BPF metric capture: %s\n' \
          "$metrics_captures" >&2
        return 1
        ;;
    esac
    fake_bpf_metrics_snapshot >"$output"
  }
  run_benchmark_client() {
    write_valid_benchmark_result "$1" "$2" 4
  }
  capture_resource_snapshot() {
    [[ "$2" == program_metrics_baseline || "$2" == program_metrics_end ]] || return 1
    mkdir -- "$1"
  }
  capture_cpu_measurement_snapshot() {
    [[ "$2" == cpu_measurement_baseline || "$2" == cpu_measurement_end ]] || return 1
    mkdir -- "$1"
  }
  java_measurement_facilities_available() {
    [[ "$1" == "$cell_dir" ]]
  }
  begin_java_measurement() {
    [[ "$1" == "$cell_dir" ]] || return 1
    ((java_measurement_begins += 1))
  }
  stop_java_measurement() {
    [[ "$1" == "$cell_dir" && "$java_measurement_begins" == 1 ]] || return 1
    ((java_measurement_stops += 1))
  }
  finish_java_measurement() {
    [[ "$1" == "$cell_dir" && "$java_measurement_stops" == 1 ]] || return 1
    ((java_measurement_finishes += 1))
  }
  run_helper_idle_measurement_rep() {
    local -r measurement_cell_dir="$1"
    local -r repetition="$2"
    local label=""

    ((measurement_repetitions += 1))
    printf -v label 'rep-%02d' "$repetition"
    write_valid_benchmark_result \
      "$measurement_cell_dir/measurements/$label.json" "$DURATION_SECONDS" 4
  }

  if run_helper_idle_sustained "$cell_dir"; then
    printf 'helper-idle sustained run accepted delayed post-workload lifecycle activity\n' >&2
    return 1
  else
    run_status=$?
  fi
  [[ "$run_status" != 0 && "$metrics_captures" == 6 && "$diagnostics_captures" == 2 &&
    "$measurement_repetitions" == 5 && "$java_measurement_begins" == 1 &&
    "$java_measurement_stops" == 1 && "$java_measurement_finishes" == 1 ]] || {
    printf 'helper-idle sustained delayed-publication control did not consume both boundary fences\n' >&2
    return 1
  }
  [[ "$(helper_idle_report_value "$cell_dir/sustained-helper-idle/obi-metrics-before.prom")" == 12 &&
    "$(helper_idle_report_value "$cell_dir/sustained-helper-idle/obi-metrics-after.prom")" == 14 ]] || {
    printf 'helper-idle sustained control did not retain second-pass BPF fence snapshots\n' >&2
    return 1
  }
  candidate_result="$(helper_idle_metric_total \
    "$cell_dir/sustained-helper-idle/obi-metrics-after.prom" candidate tcp)" || return 1
  [[ "$candidate_result" == "1 1" ]] || {
    printf 'helper-idle sustained control lost delayed candidate evidence before rejection\n' >&2
    return 1
  }
)

test_runner_environment_contract_is_exact() {
  local -r result_directory="$TEST_TMP_DIR/runner-environment"
  local -r environment_file="$result_directory/environment.txt"
  local -r project="obi-apache-java-https-b-1234567890-12345-getsockopt-hit"

  mkdir -- "$result_directory"
  reset_options
  AGENT=splunk
  TLS_PROTOCOL=TLSv1.2
  SEED=17
  # shellcheck disable=SC2034 # Consumed by sourced validate_runner_environment.
  ACTIVE_PROJECT="$project"
  cell_spec getsockopt-hit
  write_runner_environment "$environment_file" getsockopt splunk TLSv1.2 concurrency \
    "$PREFLIGHT_REQUESTS" 1 17 "$project"
  validate_runner_environment "$result_directory" || {
    printf 'valid runner environment contract was rejected\n' >&2
    return 1
  }
  awk '
    $0 == "agent_distribution=splunk" { print "agent_distribution=otel"; next }
    { print }
  ' "$environment_file" >"$environment_file.next"
  mv -- "$environment_file.next" "$environment_file"
  if validate_runner_environment "$result_directory" >/dev/null 2>&1; then
    printf 'runner environment validator accepted the wrong agent distribution\n' >&2
    return 1
  fi
  write_runner_environment "$environment_file" getsockopt splunk TLSv1.2 concurrency \
    "$PREFLIGHT_REQUESTS" 1 17 "$project"
  printf 'compose_project=unrelated-project\n' >>"$environment_file"
  if validate_runner_environment "$result_directory" >/dev/null 2>&1; then
    printf 'runner environment validator accepted duplicate compose-project entries\n' >&2
    return 1
  fi
}

test_failed_measurement_clears_reaped_pid() {
  local -r cell_dir="$TEST_TMP_DIR/failed-measurement"
  local status=0

  mkdir -p -- "$cell_dir/measurements"
  set +e
  bash -Eeuo pipefail -c '
    source "$1"
    verify_pid_cleared() {
      local status=$?

      if [[ -n "$BENCHMARK_PID" ]]; then
        exit 97
      fi
      exit "$status"
    }
    start_benchmark_client() {
      return 7
    }
    sleep() {
      :
    }
    kill() {
      return 1
    }
    DURATION_SECONDS=2
    ACTIVE_CELL_DIR="$2"
    trap verify_pid_cleared EXIT
    run_measurement_rep "$2" 1
  ' bash "$TEST_SCRIPT_DIR/benchmark.sh" "$cell_dir"
  status=$?
  set -e
  [[ "$status" == 7 ]] || {
    printf 'failed measurement left a stale load-client PID for cleanup\n' >&2
    return 1
  }
}

test_invalid_benchmark_result_is_not_published_or_retained() (
  local -r cell_dir="$TEST_TMP_DIR/unpublishable-benchmark-result"
  local -r output="$cell_dir/warmup.json"
  local mutation=""

  reset_options
  cell_spec getsockopt-hit
  mkdir -p -- "$cell_dir/measurements"
  ACTIVE_CELL_DIR="$cell_dir"
  terminate_active_benchmark() {
    clear_active_benchmark
  }
  for mutation in truncated oversized; do
    case "$mutation" in
      truncated)
        printf '{"status":"passed"' >"${output}.partial"
        ;;
      oversized)
        write_valid_benchmark_result "${output}.partial" 2
        truncate -s "$((MAX_BENCHMARK_RESULT_BYTES + 1))" "${output}.partial"
        ;;
    esac
    (exit 0) &
    BENCHMARK_PID=$!
    # shellcheck disable=SC2034 # Consumed by sourced wait_for_active_benchmark.
    BENCHMARK_OUTPUT="$output"
    # shellcheck disable=SC2034 # Consumed by sourced wait_for_active_benchmark.
    BENCHMARK_DURATION_SECONDS=2
    # shellcheck disable=SC2034 # Consumed by sourced wait_for_active_benchmark.
    BENCHMARK_CELL_DIR="$cell_dir"
    # shellcheck disable=SC2034 # Consumed by sourced wait_for_active_benchmark.
    BENCHMARK_OUTPUT_PARENT_IDENTITY="$(benchmark_output_parent_identity "$output")"
    if wait_for_active_benchmark >/dev/null 2>&1; then
      printf 'benchmark lifecycle published an invalid %s result\n' "$mutation" >&2
      return 1
    fi
    if [[ -e "$output" || -L "$output" ||
      -e "${output}.partial" || -L "${output}.partial" ]]; then
      printf 'benchmark lifecycle retained an invalid %s result or partial\n' "$mutation" >&2
      return 1
    fi
  done
  start_benchmark_client() {
    printf '{"status":"passed"' >"${1}.partial"
    return 7
  }
  if launch_benchmark_client "$output" 2 >/dev/null 2>&1; then
    printf 'benchmark lifecycle accepted a failed client launch\n' >&2
    return 1
  fi
  if [[ -e "$output" || -L "$output" ||
    -e "${output}.partial" || -L "${output}.partial" ]]; then
    printf 'benchmark lifecycle retained a failed-launch result or partial\n' >&2
    return 1
  fi
)

test_benchmark_abort_discard_is_exact_and_fail_closed() (
  local -r cell_dir="$TEST_TMP_DIR/benchmark-abort-cell"
  local -r outside_output="$TEST_TMP_DIR/benchmark-abort-outside.json"
  local -r outside_target="$TEST_TMP_DIR/benchmark-abort-symlink-target.txt"
  local output="$cell_dir/warmup.json"
  local reaps=0

  reset_options
  cell_spec getsockopt-hit
  REPETITIONS=5
  mkdir -p -- "$cell_dir/measurements"
  ACTIVE_CELL_DIR="$cell_dir"
  terminate_active_benchmark() {
    ((reaps += 1))
    clear_active_benchmark
  }
  arm_test_benchmark_abort() {
    local -r armed_output="$1"

    BENCHMARK_PID=4242
    BENCHMARK_IDENTITY='4242 4242 1'
    BENCHMARK_OUTPUT="$armed_output"
    BENCHMARK_DURATION_SECONDS=2
    BENCHMARK_CELL_DIR="$cell_dir"
    BENCHMARK_OUTPUT_PARENT_IDENTITY="$(benchmark_output_parent_identity "$armed_output")"
  }

  printf '%s\n' unpublished >"$output.partial"
  arm_test_benchmark_abort "$output"
  abort_active_benchmark || {
    printf 'benchmark abort rejected an exact allowlisted partial\n' >&2
    return 1
  }
  [[ "$reaps" == 1 && -z "$BENCHMARK_PID" && -z "$BENCHMARK_OUTPUT" &&
    ! -e "$output" && ! -L "$output" &&
    ! -e "$output.partial" && ! -L "$output.partial" ]] || {
    printf 'benchmark abort did not snapshot before global clear or remove the exact partial\n' >&2
    return 1
  }

  printf '%s\n' preserve-me >"$outside_target"
  ln -s -- "$outside_target" "$output.partial"
  arm_test_benchmark_abort "$output"
  abort_active_benchmark || {
    printf 'benchmark abort rejected an allowlisted final-component symlink\n' >&2
    return 1
  }
  [[ ! -e "$output.partial" && ! -L "$output.partial" &&
    "$(<"$outside_target")" == preserve-me ]] || {
    printf 'benchmark abort followed a partial symlink or retained the link\n' >&2
    return 1
  }

  printf '%s\n' outside-sentinel >"$outside_output.partial"
  arm_test_benchmark_abort "$outside_output"
  if abort_active_benchmark >/dev/null 2>&1; then
    printf 'benchmark abort accepted an output outside the active cell\n' >&2
    return 1
  fi
  [[ "$(<"$outside_output.partial")" == outside-sentinel ]] || {
    printf 'benchmark abort changed an outside sentinel\n' >&2
    return 1
  }

  output="$cell_dir/measurements/rep-00.json"
  printf '%s\n' malformed-sentinel >"$output.partial"
  arm_test_benchmark_abort "$output"
  if abort_active_benchmark >/dev/null 2>&1; then
    printf 'benchmark abort accepted a malformed repetition output\n' >&2
    return 1
  fi
  [[ "$(<"$output.partial")" == malformed-sentinel ]] || {
    printf 'benchmark abort changed a malformed-path sentinel\n' >&2
    return 1
  }
  rm -f -- "$output.partial"

  output="$cell_dir/warmup.json"
  mkdir -- "$output.partial"
  arm_test_benchmark_abort "$output"
  if abort_active_benchmark >/dev/null 2>&1; then
    printf 'benchmark abort accepted a directory at the partial path\n' >&2
    return 1
  fi
  [[ -d "$output.partial" && ! -L "$output.partial" ]] || {
    printf 'benchmark abort changed a refused partial directory\n' >&2
    return 1
  }
  rmdir -- "$output.partial"

  printf '%s\n' identity-sentinel >"$output.partial"
  arm_test_benchmark_abort "$output"
  BENCHMARK_OUTPUT_PARENT_IDENTITY='0:0:0:000'
  if abort_active_benchmark >/dev/null 2>&1; then
    printf 'benchmark abort accepted output-parent identity drift\n' >&2
    return 1
  fi
  [[ "$(<"$output.partial")" == identity-sentinel ]] || {
    printf 'benchmark abort changed a parent-identity-drift sentinel\n' >&2
    return 1
  }
  rm -f -- "$output.partial"

  output="$cell_dir/measurements/rep-01.json"
  write_valid_benchmark_result "$output.partial" 2
  (exit 0) &
  BENCHMARK_PID=$!
  BENCHMARK_IDENTITY=""
  BENCHMARK_OUTPUT="$output"
  # shellcheck disable=SC2034 # Consumed by sourced wait_for_active_benchmark.
  BENCHMARK_DURATION_SECONDS=2
  # shellcheck disable=SC2034 # Consumed by sourced wait_for_active_benchmark.
  BENCHMARK_CELL_DIR="$cell_dir"
  # shellcheck disable=SC2034 # Consumed by sourced wait_for_active_benchmark.
  BENCHMARK_OUTPUT_PARENT_IDENTITY="$(benchmark_output_parent_identity "$output")"
  wait_for_active_benchmark || {
    printf 'benchmark wait rejected a valid atomically publishable result\n' >&2
    return 1
  }
  [[ -f "$output" && ! -L "$output" &&
    ! -e "$output.partial" && ! -L "$output.partial" ]] &&
    validate_benchmark_result "$output" 2 || {
    printf 'benchmark wait did not preserve successful validate-and-move publication\n' >&2
    return 1
  }
)

test_interrupted_measurement_reaps_client_tree() (
  local -r cell_dir="$TEST_TMP_DIR/interrupted-measurement"
  local -r output="$cell_dir/warmup.json"
  local -r child_pid_file="$TEST_TMP_DIR/interrupted-measurement-child.pid"
  local child_pid=""
  local process_group=""
  local session=""
  local start_time=""
  local attempt=0

  reset_options
  mkdir -p -- "$cell_dir/measurements"
  # shellcheck disable=SC2034 # Consumed by sourced launch_benchmark_client.
  ACTIVE_CELL_DIR="$cell_dir"
  export BENCHMARK_TEST_CHILD_PID_FILE="$child_pid_file"
  # shellcheck disable=SC2034 # Consumed by sourced start_benchmark_client.
  COMPOSE=(
    bash -c '
      /bin/sleep 120 &
      child_pid=$!
      printf "%s\\n" "$child_pid" >"$BENCHMARK_TEST_CHILD_PID_FILE"
      wait "$child_pid"
    ' benchmark-client
  )
  cleanup_interrupted_measurement() {
    abort_active_benchmark || true
    if [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$child_pid" 2>/dev/null; then
      kill -TERM "$child_pid" 2>/dev/null || true
      wait "$child_pid" 2>/dev/null || true
    fi
  }
  trap cleanup_interrupted_measurement EXIT

  launch_benchmark_client "$output" 60 || {
    printf 'measurement client did not start its dedicated session\n' >&2
    return 1
  }
  read -r process_group session start_time <<<"$BENCHMARK_IDENTITY"
  [[ "$process_group" == "$BENCHMARK_PID" && "$session" == "$BENCHMARK_PID" &&
    "$start_time" =~ ^[1-9][0-9]*$ ]] || {
    printf 'measurement client did not become its own session and process-group leader\n' >&2
    return 1
  }
  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -s "$child_pid_file" ]]; then
      break
    fi
    /bin/sleep 0.1
  done
  [[ -s "$child_pid_file" ]] || {
    printf 'interrupted measurement did not start its controlled client child\n' >&2
    return 1
  }
  child_pid="$(<"$child_pid_file")"
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] || {
    printf 'interrupted measurement did not expose its controlled client child PID\n' >&2
    return 1
  }
  abort_active_benchmark
  for ((attempt = 0; attempt < 50; attempt++)); do
    if ! kill -0 "$child_pid" 2>/dev/null; then
      child_pid=""
      break
    fi
    /bin/sleep 0.1
  done
  [[ -z "$child_pid" ]] || {
    printf 'interrupted measurement left its controlled client child running\n' >&2
    return 1
  }
  [[ ! -e "$output" && ! -L "$output" &&
    ! -e "$output.partial" && ! -L "$output.partial" ]] || {
    printf 'interrupted measurement retained a final or partial client result\n' >&2
    return 1
  }
)

test_wait_reaps_client_group_after_leader_exit() (
  local -r cell_dir="$TEST_TMP_DIR/leader-exit"
  local -r output="$cell_dir/warmup.json"
  local -r child_pid_file="$TEST_TMP_DIR/leader-exit-child.pid"
  local child_pid=""
  local wait_status=0
  local attempt=0

  reset_options
  mkdir -p -- "$cell_dir/measurements"
  # shellcheck disable=SC2034 # Consumed by sourced launch_benchmark_client.
  ACTIVE_CELL_DIR="$cell_dir"
  export BENCHMARK_TEST_CHILD_PID_FILE="$child_pid_file"
  # shellcheck disable=SC2034 # Consumed by sourced start_benchmark_client.
  COMPOSE=(
    bash -c '
      /bin/sleep 120 &
      child_pid=$!
      printf "%s\\n" "$child_pid" >"$BENCHMARK_TEST_CHILD_PID_FILE"
      wait "$child_pid"
    ' benchmark-client
  )
  cleanup_leader_exit() {
    terminate_active_benchmark || true
    if [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$child_pid" 2>/dev/null; then
      kill -TERM "$child_pid" 2>/dev/null || true
    fi
  }
  trap cleanup_leader_exit EXIT

  launch_benchmark_client "$output" 60 || {
    printf 'leader-exit client did not start its dedicated session\n' >&2
    return 1
  }
  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -s "$child_pid_file" ]]; then
      child_pid="$(<"$child_pid_file")"
      break
    fi
    /bin/sleep 0.1
  done
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$child_pid" 2>/dev/null || {
    printf 'leader-exit client did not expose its controlled child PID\n' >&2
    return 1
  }
  kill -KILL "$BENCHMARK_PID"
  if wait_for_active_benchmark 2>/dev/null; then
    printf 'killed session leader unexpectedly reported a successful wait\n' >&2
    return 1
  else
    wait_status=$?
  fi
  [[ "$wait_status" != 0 ]] || {
    printf 'killed session leader did not preserve its failed wait status\n' >&2
    return 1
  }
  for ((attempt = 0; attempt < 50; attempt++)); do
    if ! kill -0 "$child_pid" 2>/dev/null; then
      child_pid=""
      break
    fi
    /bin/sleep 0.1
  done
  [[ -z "$child_pid" ]] || {
    printf 'failed wait left a child after its session leader exited\n' >&2
    return 1
  }
)

test_failed_identity_capture_reaps_client_group() (
  local -r output="$TEST_TMP_DIR/early-leader-exit.json"
  local -r child_pid_file="$TEST_TMP_DIR/early-leader-exit-child.pid"
  local child_pid=""
  local capture_status=0
  local attempt=0

  reset_options
  export BENCHMARK_TEST_CHILD_PID_FILE="$child_pid_file"
  # shellcheck disable=SC2034 # Consumed by sourced start_benchmark_client.
  COMPOSE=(
    bash -c '
      /bin/sleep 120 &
      child_pid=$!
      printf "%s\\n" "$child_pid" >"$BENCHMARK_TEST_CHILD_PID_FILE"
    ' benchmark-client
  )
  cleanup_early_leader_exit() {
    terminate_active_benchmark || true
    if [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$child_pid" 2>/dev/null; then
      kill -TERM "$child_pid" 2>/dev/null || true
    fi
  }
  trap cleanup_early_leader_exit EXIT

  start_benchmark_client "$output" 60 &
  BENCHMARK_PID=$!
  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -s "$child_pid_file" ]]; then
      child_pid="$(<"$child_pid_file")"
      break
    fi
    /bin/sleep 0.1
  done
  [[ "$child_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$child_pid" 2>/dev/null || {
    printf 'early-exit client did not expose its controlled child PID\n' >&2
    return 1
  }
  for ((attempt = 0; attempt < 50; attempt++)); do
    if ! benchmark_job_is_running "$BENCHMARK_PID"; then
      break
    fi
    /bin/sleep 0.1
  done
  if benchmark_job_is_running "$BENCHMARK_PID"; then
    printf 'early-exit client did not finish before identity capture\n' >&2
    return 1
  fi
  record_active_benchmark_identity || capture_status=$?
  [[ "$capture_status" != 0 ]] || {
    printf 'early-exit client unexpectedly completed identity capture\n' >&2
    return 1
  }
  for ((attempt = 0; attempt < 50; attempt++)); do
    if ! kill -0 "$child_pid" 2>/dev/null; then
      child_pid=""
      break
    fi
    /bin/sleep 0.1
  done
  [[ -z "$child_pid" ]] || {
    printf 'failed identity capture left a client child running\n' >&2
    return 1
  }
)

test_stale_client_identity_never_signals_unrelated_process() (
  local -r pid_file="$TEST_TMP_DIR/unrelated-session.pid"
  local unrelated_pid=""
  local identity=""
  local process_group=""
  local session=""
  local start_time=""
  local attempt=0

  reset_options
  cleanup_unrelated_process() {
    if [[ "$unrelated_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$unrelated_pid" 2>/dev/null; then
      kill -TERM -- "-$unrelated_pid" 2>/dev/null || kill -TERM "$unrelated_pid" 2>/dev/null || true
      for ((attempt = 0; attempt < 50; attempt++)); do
        if ! kill -0 "$unrelated_pid" 2>/dev/null; then
          return
        fi
        /bin/sleep 0.1
      done
      kill -KILL -- "-$unrelated_pid" 2>/dev/null || kill -KILL "$unrelated_pid" 2>/dev/null || true
    fi
  }
  trap cleanup_unrelated_process EXIT

  bash -c 'setsid -- /bin/sleep 120 >/dev/null 2>&1 & printf "%s\\n" "$!" >"$1"' bash "$pid_file"
  for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ -s "$pid_file" ]]; then
      unrelated_pid="$(<"$pid_file")"
      if [[ "$unrelated_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$unrelated_pid" 2>/dev/null; then
        break
      fi
    fi
    /bin/sleep 0.1
  done
  [[ "$unrelated_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$unrelated_pid" 2>/dev/null || {
    printf 'test setup did not leave an unrelated live session leader\n' >&2
    return 1
  }
  identity="$(benchmark_process_identity "$unrelated_pid")" || {
    printf 'test setup did not expose unrelated process identity\n' >&2
    return 1
  }
  BENCHMARK_PID="$unrelated_pid"
  read -r process_group session start_time <<<"$identity"
  BENCHMARK_IDENTITY="$process_group $session $((start_time + 1))"
  if benchmark_job_is_running "$BENCHMARK_PID"; then
    printf 'unrelated session was unexpectedly registered as the harness job\n' >&2
    return 1
  fi
  terminate_active_benchmark
  [[ -z "$BENCHMARK_PID" && -z "$BENCHMARK_IDENTITY" ]] || {
    printf 'stale client identity was not cleared\n' >&2
    return 1
  }
  kill -0 "$unrelated_pid" 2>/dev/null || {
    printf 'stale client identity signalled an unrelated process\n' >&2
    return 1
  }
)

test_pending_identity_never_signals_mismatched_live_job() (
  local unrelated_pid=""
  local identity=""
  local start_time=""

  reset_options
  cleanup_pending_job() {
    if [[ "$unrelated_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$unrelated_pid" 2>/dev/null; then
      kill -TERM "$unrelated_pid" 2>/dev/null || true
      wait "$unrelated_pid" 2>/dev/null || true
    fi
  }
  trap cleanup_pending_job EXIT

  /bin/sleep 120 &
  unrelated_pid=$!
  identity="$(benchmark_process_identity "$unrelated_pid")" || {
    printf 'test setup did not expose a pending job identity\n' >&2
    return 1
  }
  read -r _ _ start_time <<<"$identity"
  BENCHMARK_PID="$unrelated_pid"
  BENCHMARK_IDENTITY="pending $((start_time + 1))"
  if terminate_active_benchmark; then
    printf 'mismatched pending identity unexpectedly reported safe termination\n' >&2
    return 1
  fi
  kill -0 "$unrelated_pid" 2>/dev/null || {
    printf 'mismatched pending identity signalled a live unrelated job\n' >&2
    return 1
  }
)

test_pending_identity_rejects_reused_session_promotion() (
  local capture_status=0

  reset_options
  BENCHMARK_PID=4242
  BENCHMARK_IDENTITY="pending 101"
  benchmark_process_identity() {
    printf '%s %s %s\n' "$BENCHMARK_PID" "$BENCHMARK_PID" 202
  }
  benchmark_job_is_running() {
    return 0
  }
  if record_active_benchmark_identity; then
    printf 'mismatched pending identity promoted a reused session leader\n' >&2
    return 1
  else
    capture_status=$?
  fi
  [[ "$capture_status" != 0 && "$BENCHMARK_IDENTITY" == "pending 101" ]] || {
    printf 'reused session promotion did not preserve the original pending identity\n' >&2
    return 1
  }
)

test_missing_runner_provenance_is_rejected() {
  local -r result_directory="$TEST_TMP_DIR/missing-runner-provenance"
  local -r cell_dir="$TEST_TMP_DIR/missing-runner-provenance-cell"
  local -r project="obi-apache-java-https-b-1234567890-12345-uninstrumented"

  mkdir -p -- "$cell_dir/preflight"
  reset_options
  cell_spec uninstrumented
  fake_write_runner_artifacts \
    "$result_directory" disabled otel TLSv1.3 benchmark-uninstrumented uninstrumented disabled "$project"
  mv -- "$result_directory/compose-images.json" "$TEST_TMP_DIR/omitted-compose-images.json"
  if retain_runner_artifacts "$result_directory" "$cell_dir" >/dev/null 2>&1; then
    printf 'runner artifact retention accepted missing Compose image provenance\n' >&2
    return 1
  fi
}

test_benchmark_ca_rejects_untrusted_inputs() (
  local -r result_directory="$TEST_TMP_DIR/benchmark-ca-rejection-result"
  local -r cell_dir="$TEST_TMP_DIR/benchmark-ca-rejection-cell"
  local -r noncanonical="$TEST_TMP_DIR/noncanonical-benchmark-ca.crt"
  local -r oversized="$TEST_TMP_DIR/oversized-benchmark-ca.crt"
  local -r bad_signature="$TEST_TMP_DIR/bad-signature-benchmark-ca.crt"
  local -r ambient_ca_directory="$TEST_TMP_DIR/ambient-benchmark-ca-directory"
  local -r intermediate="$TEST_TMP_DIR/intermediate-benchmark-ca.crt"
  local -r intermediate_csr="$TEST_TMP_DIR/intermediate-benchmark-ca.csr"
  local -r intermediate_extensions="$TEST_TMP_DIR/intermediate-benchmark-ca-extensions.cnf"
  local -r intermediate_key="$TEST_TMP_DIR/intermediate-benchmark-ca.key"
  local -r non_ca="$TEST_TMP_DIR/non-ca-benchmark-certificate.crt"
  local -r non_ca_key="$TEST_TMP_DIR/non-ca-benchmark-certificate.key"
  local -r oversized_metadata="$TEST_TMP_DIR/oversized-benchmark-ca-metadata.json"
  local -r multiple_metadata="$TEST_TMP_DIR/multiple-benchmark-ca-metadata.json"
  local -r suppressed_stderr="$TEST_TMP_DIR/benchmark-ca-suppressed.stderr"
  local actual_fingerprint=""
  local ambient_ca_hash=""
  local emit_hostile_stderr=true
  local source_certificate="$FAKE_CA_FILE"

  reset_options
  mkdir -p -- "$result_directory" "$cell_dir/preflight"
  printf '%s\n' \
    '{"ca_sha256":"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"}' \
    >"$result_directory/certificates.json"
  capture_service_identity() {
    local -r service="$1"
    local -r output="$2"

    [[ "$service" == apache-proxy ]] || return 64
    {
      printf 'service=apache-proxy\n'
      printf 'container_id=%064d\n' 0
      printf 'host_pid=1\n'
      printf 'project=test-project\n'
      printf 'owner_sentinel=acceptance-demo-v1\n'
    } >"$output"
  }
  run_bounded() {
    if [[ "$emit_hostile_stderr" == true ]]; then
      head -c 32768 /dev/zero | tr '\0' x >&2
    fi
    command cat -- "$source_certificate"
  }
  if prepare_benchmark_ca "$result_directory" "$cell_dir" 2>"$suppressed_stderr"; then
    printf 'benchmark CA accepted a mismatched retained fingerprint\n' >&2
    return 1
  fi
  [[ ! -s "$suppressed_stderr" ]] || {
    printf 'benchmark CA retrieval leaked hostile container stderr\n' >&2
    return 1
  }
  emit_hostile_stderr=false
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'benchmark CA mismatch published an artifact\n' >&2
    return 1
  }

  command cp -- "$FAKE_CA_FILE" "$noncanonical"
  printf '%s\n' 'trailing payload' >>"$noncanonical"
  source_certificate="$noncanonical"
  actual_fingerprint="$(
    openssl x509 -noout -fingerprint -sha256 -in "$FAKE_CA_FILE"
  )" || return 1
  actual_fingerprint="${actual_fingerprint#*=}"
  jq -n --arg ca_sha256 "$actual_fingerprint" '{ca_sha256: $ca_sha256}' \
    >"$result_directory/certificates.json"
  if prepare_benchmark_ca "$result_directory" "$cell_dir"; then
    printf 'benchmark CA accepted trailing non-certificate data\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'noncanonical benchmark CA published an artifact\n' >&2
    return 1
  }

  {
    command cat -- "$FAKE_CA_FILE"
    head -c "$MAX_BENCHMARK_CA_CERTIFICATE_BYTES" /dev/zero | tr '\0' x
  } >"$oversized"
  source_certificate="$oversized"
  if prepare_benchmark_ca "$result_directory" "$cell_dir"; then
    printf 'benchmark CA accepted an oversized source\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'oversized benchmark CA published an artifact\n' >&2
    return 1
  }

  openssl x509 -in "$FAKE_CA_FILE" -badsig -out "$bad_signature" 2>/dev/null
  source_certificate="$bad_signature"
  actual_fingerprint="$(
    openssl x509 -noout -fingerprint -sha256 -in "$source_certificate"
  )" || return 1
  actual_fingerprint="${actual_fingerprint#*=}"
  jq -n --arg ca_sha256 "$actual_fingerprint" '{ca_sha256: $ca_sha256}' \
    >"$result_directory/certificates.json"
  if prepare_benchmark_ca "$result_directory" "$cell_dir"; then
    printf 'benchmark CA accepted an invalid self-signature\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'bad-signature benchmark CA published an artifact\n' >&2
    return 1
  }

  mkdir --mode=0700 -- "$ambient_ca_directory"
  ambient_ca_hash="$(
    openssl x509 -subject_hash -noout -in "$FAKE_CA_FILE"
  )" || return 1
  [[ "$ambient_ca_hash" =~ ^[0-9a-fA-F]+$ ]] || return 1
  ln -s -- "$FAKE_CA_FILE" "$ambient_ca_directory/$ambient_ca_hash.0"
  openssl req \
    -new \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -subj '/CN=OBI benchmark harness intermediate test CA' \
    -keyout "$intermediate_key" \
    -out "$intermediate_csr" >/dev/null 2>&1
  printf '%s\n' \
    '[benchmark_intermediate]' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid,issuer' \
    >"$intermediate_extensions"
  openssl x509 \
    -req \
    -sha256 \
    -days 1 \
    -set_serial 3 \
    -in "$intermediate_csr" \
    -CA "$FAKE_CA_FILE" \
    -CAkey "$TEST_TMP_DIR/fake-benchmark-ca.key" \
    -extfile "$intermediate_extensions" \
    -extensions benchmark_intermediate \
    -out "$intermediate" >/dev/null 2>&1
  chmod 0600 -- \
    "$intermediate" "$intermediate_csr" "$intermediate_extensions" "$intermediate_key"
  SSL_CERT_DIR="$ambient_ca_directory" \
    openssl verify -check_ss_sig -CAfile "$intermediate" "$intermediate" \
      >/dev/null 2>&1 || {
    printf 'ambient CA fixture did not reproduce the non-isolated trust chain\n' >&2
    return 1
  }
  source_certificate="$intermediate"
  actual_fingerprint="$(
    openssl x509 -noout -fingerprint -sha256 -in "$source_certificate"
  )" || return 1
  actual_fingerprint="${actual_fingerprint#*=}"
  jq -n --arg ca_sha256 "$actual_fingerprint" '{ca_sha256: $ca_sha256}' \
    >"$result_directory/certificates.json"
  if SSL_CERT_DIR="$ambient_ca_directory" \
    prepare_benchmark_ca "$result_directory" "$cell_dir"; then
    printf 'benchmark CA accepted an ambiently chained intermediate\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'ambiently chained intermediate published a benchmark CA artifact\n' >&2
    return 1
  }

  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 1 \
    -set_serial 2 \
    -subj '/CN=OBI benchmark harness non-CA test certificate' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -keyout "$non_ca_key" \
    -out "$non_ca" >/dev/null 2>&1
  chmod 0600 -- "$non_ca_key" "$non_ca"
  source_certificate="$non_ca"
  actual_fingerprint="$(
    openssl x509 -noout -fingerprint -sha256 -in "$source_certificate"
  )" || return 1
  actual_fingerprint="${actual_fingerprint#*=}"
  jq -n --arg ca_sha256 "$actual_fingerprint" '{ca_sha256: $ca_sha256}' \
    >"$result_directory/certificates.json"
  if prepare_benchmark_ca "$result_directory" "$cell_dir"; then
    printf 'benchmark CA accepted a CA:FALSE trust object\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'non-CA benchmark certificate published an artifact\n' >&2
    return 1
  }

  source_certificate="$FAKE_CA_FILE"
  actual_fingerprint="$(
    openssl x509 -noout -fingerprint -sha256 -in "$source_certificate"
  )" || return 1
  actual_fingerprint="${actual_fingerprint#*=}"
  {
    printf '{"ca_sha256":"%s","padding":"' "$actual_fingerprint"
    head -c "$MAX_BENCHMARK_CA_METADATA_BYTES" /dev/zero | tr '\0' x
    printf '"}\n'
  } >"$oversized_metadata"
  command cp -- "$oversized_metadata" "$result_directory/certificates.json"
  if prepare_benchmark_ca "$result_directory" "$cell_dir"; then
    printf 'benchmark CA accepted oversized retained metadata\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'oversized benchmark CA metadata published an artifact\n' >&2
    return 1
  }

  jq -n --arg ca_sha256 "$actual_fingerprint" '{ca_sha256: $ca_sha256}' \
    >"$multiple_metadata"
  jq -n --arg ca_sha256 "$actual_fingerprint" '{ca_sha256: $ca_sha256}' \
    >>"$multiple_metadata"
  command cp -- "$multiple_metadata" "$result_directory/certificates.json"
  if prepare_benchmark_ca "$result_directory" "$cell_dir"; then
    printf 'benchmark CA accepted multiple retained metadata documents\n' >&2
    return 1
  fi
  [[ ! -e "$cell_dir/preflight/benchmark-ca.crt" &&
    ! -e "$cell_dir/preflight/benchmark-ca.json" &&
    ! -e "$cell_dir/preflight/benchmark-ca-source-identity.txt" ]] || {
    printf 'multiple benchmark CA metadata documents published an artifact\n' >&2
    return 1
  }
  [[ -z "$(find "$cell_dir/preflight" -mindepth 1 -maxdepth 1 \
    -name '.benchmark-ca-*' -print -quit)" ]] || {
    printf 'rejected benchmark CA input left a hidden temporary artifact\n' >&2
    return 1
  }
)

assert_java_measurement_mutation_rejected() {
  local -r source="$1"
  local -r mutation="$2"
  local -r kind="$3"
  local artifact=""
  local compact=""
  local mutated=""
  local temporary=""

  [[ -d "$source" && ! -L "$source" && ! -e "$mutation" && ! -L "$mutation" ]] || return 1
  cp -a -- "$source" "$mutation" || return 1
  artifact="$mutation/evidence.json"
  case "$kind" in
    duplicate-top)
      compact="$(jq -c . "$artifact")" || return 1
      mutated="$(sed \
        's/"acceptance_evidence":false/"acceptance_evidence":false,"acceptance_evidence":false/' \
        <<<"$compact")" || return 1
      [[ "$mutated" != "$compact" ]] || return 1
      printf '%s\n' "$mutated" >"$artifact"
      ;;
    duplicate-nested)
      compact="$(jq -c . "$artifact")" || return 1
      mutated="$(sed \
        's/"allocation_sample":{"records":5/"allocation_sample":{"records":5,"records":5/' \
        <<<"$compact")" || return 1
      [[ "$mutated" != "$compact" ]] || return 1
      printf '%s\n' "$mutated" >"$artifact"
      ;;
    unexpected-key)
      temporary="$(mktemp "$mutation/.evidence.XXXXXX")" || return 1
      jq '.unexpected = 1' "$artifact" >"$temporary" &&
        mv -T -- "$temporary" "$artifact" || return 1
      ;;
    missing-key)
      temporary="$(mktemp "$mutation/.evidence.XXXXXX")" || return 1
      jq 'del(.jfr.raw_sha256)' "$artifact" >"$temporary" &&
        mv -T -- "$temporary" "$artifact" || return 1
      ;;
    epoch-timestamp)
      temporary="$(mktemp "$mutation/.evidence.XXXXXX")" || return 1
      jq '.measurement_window.started_at = "1970-01-01T00:00:00Z"' \
        "$artifact" >"$temporary" && mv -T -- "$temporary" "$artifact" || return 1
      ;;
    reversed-timestamps)
      temporary="$(mktemp "$mutation/.evidence.XXXXXX")" || return 1
      jq '.measurement_window.started_at = "2026-08-20T00:00:02Z" |
          .measurement_window.stop_initiated_at = "2026-08-20T00:00:01Z"' \
        "$artifact" >"$temporary" && mv -T -- "$temporary" "$artifact" || return 1
      ;;
    runtime-identity-drift)
      temporary="$(mktemp "$mutation/.runtime.XXXXXX")" || return 1
      jq '.jvm_start_epoch_millis += 1' \
        "$mutation/operations/05-runtime-baseline/runtime-after.json" \
        >"$temporary" && mv -T -- "$temporary" \
          "$mutation/operations/05-runtime-baseline/runtime-after.json" || return 1
      ;;
    duplicate-runtime-key)
      artifact="$mutation/operations/05-runtime-baseline/runtime-after.json"
      compact="$(jq -c . "$artifact")" || return 1
      mutated="$(sed \
        's/"direct_buffer":{"count":2/"direct_buffer":{"count":2,"count":2/' \
        <<<"$compact")" || return 1
      [[ "$mutated" != "$compact" ]] || return 1
      printf '%s\n' "$mutated" >"$artifact"
      ;;
    duplicate-jfr-key)
      artifact="$mutation/operations/08-jfr-summary/output"
      compact="$(jq -c . "$artifact")" || return 1
      mutated="$(sed \
        's/"data_loss":{"records":0/"data_loss":{"records":0,"records":0/' \
        <<<"$compact")" || return 1
      [[ "$mutated" != "$compact" ]] || return 1
      printf '%s\n' "$mutated" >"$artifact"
      ;;
    snapshot-semantics-changed)
      artifact="$mutation/operations/08-jfr-summary/output"
      temporary="$(mktemp "$mutation/.jfr-summary.XXXXXX")" || return 1
      jq '.snapshot_semantics = "path_reopen"' "$artifact" >"$temporary" &&
        mv -T -- "$temporary" "$artifact" || return 1
      ;;
    runtime-image-substitution)
      artifact="$mutation/runtime-artifacts.json"
      temporary="$(mktemp "$mutation/.runtime-artifacts.XXXXXX")" || return 1
      jq '.image_id = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
        "$artifact" >"$temporary" && mv -T -- "$temporary" "$artifact" || return 1
      ;;
    runtime-helper-substitution)
      artifact="$mutation/runtime-artifacts.json"
      temporary="$(mktemp "$mutation/.runtime-artifacts.XXXXXX")" || return 1
      jq '.helper_jar.sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
        "$artifact" >"$temporary" && mv -T -- "$temporary" "$artifact" || return 1
      ;;
    runtime-helper-source-substitution)
      artifact="$mutation/runtime-artifacts.json"
      temporary="$(mktemp "$mutation/.runtime-artifacts.XXXXXX")" || return 1
      jq '.helper_source.sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
        "$artifact" >"$temporary" && mv -T -- "$temporary" "$artifact" || return 1
      ;;
    runtime-jfc-substitution)
      artifact="$mutation/runtime-artifacts.json"
      temporary="$(mktemp "$mutation/.runtime-artifacts.XXXXXX")" || return 1
      jq '.jfr_settings.sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
        "$artifact" >"$temporary" && mv -T -- "$temporary" "$artifact" || return 1
      ;;
    runtime-artifact-missing)
      rm -f -- "$mutation/runtime-artifacts.json"
      ;;
    retention-overclaim)
      temporary="$(mktemp "$mutation/.evidence.XXXXXX")" || return 1
      jq '.jfr.whole_window_retention_attested = true' "$artifact" >"$temporary" &&
        mv -T -- "$temporary" "$artifact" || return 1
      ;;
    stop-size-mismatch)
      sed -i \
        '2cStopped recording "obi-benchmark-measurement", 32.0 MB written to:' \
        "$mutation/operations/07-jfr-stop/output"
      ;;
    bootstrap-discard-semantics)
      artifact="$mutation/operations/02-bootstrap-discard/output"
      temporary="$(mktemp "$mutation/.bootstrap-discard.XXXXXX")" || return 1
      jq '.discard_semantics = "path_delete"' "$artifact" >"$temporary" &&
        mv -T -- "$temporary" "$artifact" || return 1
      ;;
    negative-nmt-delta)
      sed -i 's/ +5000, committed=/ -1, committed=/' \
        "$mutation/operations/11-nmt-postload-diff/output"
      ;;
    bootstrap-alternate-path)
      sed -i 's#/tmp/obi-benchmark-bootstrap.jfr#/tmp/alternate-bootstrap.jfr#' \
        "$mutation/operations/01-bootstrap-stop/output"
      ;;
    measurement-stop-extra-line)
      printf 'unexpected\n' >>"$mutation/operations/07-jfr-stop/output"
      ;;
    bootstrap-discard-missing)
      rm -f -- "$mutation/operations/02-bootstrap-discard/output"
      ;;
    nmt-baseline-old-wording)
      sed -i 's/Baseline taken/Baseline succeeded/' \
        "$mutation/operations/03-nmt-baseline/output"
      ;;
    raw-jfr-drift)
      printf 'unexpected\n' >>"$mutation/measurement.jfr"
      ;;
    raw-jfr-oversized)
      head -c "$((MAX_JFR_BYTES + 1))" /dev/zero >"$mutation/measurement.jfr"
      ;;
    missing-raw-jfr)
      rm -f -- "$mutation/measurement.jfr"
      ;;
    operations-foreign-file)
      printf 'foreign\n' >"$mutation/operations/foreign-file"
      chmod 0600 -- "$mutation/operations/foreign-file"
      ;;
    operations-foreign-symlink)
      ln -s -- ../identity.txt "$mutation/operations/foreign-symlink"
      ;;
    operations-foreign-directory)
      mkdir -- "$mutation/operations/foreign-directory"
      chmod 0700 -- "$mutation/operations/foreign-directory"
      ;;
    operations-foreign-special)
      mkfifo -m 0600 -- "$mutation/operations/foreign-fifo"
      ;;
    *) return 1 ;;
  esac
  chmod 0600 -- "$artifact" 2>/dev/null || true
  if validate_java_measurement_evidence "$mutation/evidence.json" >/dev/null 2>&1; then
    printf 'Java measurement validator accepted mutation: %s\n' "$kind" >&2
    return 1
  fi
}

assert_java_direct_buffer_reclamation_is_retained() {
  local -r source="$1"
  local -r reclamation="$2"
  local snapshot=""
  local temporary=""
  local cell=""
  local started_at=""
  local stop_initiated_at=""

  [[ -d "$source" && ! -L "$source" &&
    ! -e "$reclamation" && ! -L "$reclamation" ]] || return 1
  cp -a -- "$source" "$reclamation" || return 1
  for snapshot in \
    "$reclamation/operations/12-runtime-postload/runtime-before.json" \
    "$reclamation/operations/12-runtime-postload/runtime-after.json"; do
    temporary="$(mktemp "$reclamation/.runtime.XXXXXX")" || return 1
    jq '.direct_buffer = {
      count: 1, memory_used_bytes: 100, total_capacity_bytes: 100
    }' "$snapshot" >"$temporary" &&
      mv -T -- "$temporary" "$snapshot" || return 1
  done
  cell="$(jq -er '.cell' "$reclamation/evidence.json")" || return 1
  started_at="$(jq -er '.measurement_window.started_at' \
    "$reclamation/evidence.json")" || return 1
  stop_initiated_at="$(jq -er '.measurement_window.stop_initiated_at' \
    "$reclamation/evidence.json")" || return 1
  # shellcheck disable=SC2034 # Consumed by the sourced evidence renderer/validator.
  JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS="$(jq -er \
    '.process_binding.java_runtime_start_epoch_millis' \
    "$reclamation/evidence.json")" || return 1
  temporary="$(mktemp "$reclamation/.evidence.XXXXXX")" || return 1
  java_measurement_evidence_json \
    "$reclamation" "$cell" "$started_at" "$stop_initiated_at" \
    >"$temporary" && mv -T -- "$temporary" \
      "$reclamation/evidence.json" || return 1
  validate_java_measurement_evidence "$reclamation/evidence.json" || return 1
  jq -e '.direct_buffer.signed_delta == {
    count: -1, memory_used_bytes: -100, total_capacity_bytes: -100
  }' "$reclamation/evidence.json" >/dev/null
}

test_java_measurement_partial_cleanup_is_identity_safe() (
  local -r output="$TEST_TMP_DIR/java-partial-cleanup-output"
  local -r cell_dir="$output/cells/getsockopt-hit"
  local -r partial="$cell_dir/.java-measurement.partial"
  local -r outside="$TEST_TMP_DIR/java-partial-outside"
  local -r sentinel="$TEST_TMP_DIR/java-partial-sentinel.txt"
  local -r cap_cell_dir="$output/cells/unix-hit"
  local -r cap_partial="$cap_cell_dir/.java-measurement.partial"
  local -r bounded_output_dir="$TEST_TMP_DIR/java-bounded-output"
  local parent_identity=""
  local root_identity=""
  local index=0

  reset_options
  OUTPUT_DIR="$output"
  CELL_SLUG=getsockopt-hit
  mkdir -p -- "$partial/nested" "$outside"
  chmod 0700 -- "$output" "$output/cells" "$cell_dir" "$partial" "$partial/nested" "$outside"
  printf 'preserve\n' >"$sentinel"
  printf 'partial\n' >"$partial/nested/output"
  ln -s -- "$sentinel" "$partial/nested/untrusted-link"
  parent_identity="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")" || return 1
  root_identity="$(stat --format '%d:%i:%u:%a' -- "$partial")" || return 1
  # shellcheck disable=SC2034 # Consumed by discard_active_java_measurement in sourced benchmark.sh.
  JAVA_MEASUREMENT_PARTIAL="$partial"
  JAVA_MEASUREMENT_CELL_DIR="$cell_dir"
  # shellcheck disable=SC2034 # Consumed by discard_active_java_measurement in sourced benchmark.sh.
  JAVA_MEASUREMENT_PARENT_IDENTITY="$parent_identity"
  # shellcheck disable=SC2034 # Consumed by discard_active_java_measurement in sourced benchmark.sh.
  JAVA_MEASUREMENT_ROOT_IDENTITY="$root_identity"
  discard_active_java_measurement || return 1
  [[ ! -e "$partial" && ! -L "$partial" &&
    "$(<"$sentinel")" == preserve &&
    -z "$JAVA_MEASUREMENT_PARTIAL" && -z "$JAVA_MEASUREMENT_CELL_DIR" ]] || {
    printf 'Java partial cleanup followed a symlink or retained active globals\n' >&2
    return 1
  }

  printf 'outside\n' >"$outside/output"
  if discard_java_measurement_partial \
    "$outside" "$cell_dir" "$parent_identity" \
    "$(stat --format '%d:%i:%u:%a' -- "$outside")"; then
    printf 'Java partial cleanup accepted an outside path\n' >&2
    return 1
  fi
  [[ "$(<"$outside/output")" == outside ]] || return 1

  mkdir -- "$partial"
  chmod 0700 -- "$partial"
  root_identity="$(stat --format '%d:%i:%u:%a' -- "$partial")" || return 1
  mkdir -- "$cell_dir/java-measurement"
  if discard_java_measurement_partial \
    "$partial" "$cell_dir" "$parent_identity" "$root_identity"; then
    printf 'Java partial cleanup accepted an existing final directory\n' >&2
    return 1
  fi
  [[ -d "$partial" && -d "$cell_dir/java-measurement" ]] || return 1

  mkdir -p -- "$cap_partial" "$bounded_output_dir"
  chmod 0700 -- "$cap_cell_dir" "$cap_partial" "$bounded_output_dir"
  for ((index = 0; index <= MAX_JAVA_EVIDENCE_FILES; index++)); do
    printf 'bounded\n' >"$cap_partial/entry-$index"
  done
  parent_identity="$(stat --format '%d:%i:%u:%a' -- "$cap_cell_dir")" || return 1
  root_identity="$(stat --format '%d:%i:%u:%a' -- "$cap_partial")" || return 1
  if discard_java_measurement_partial \
    "$cap_partial" "$cap_cell_dir" "$parent_identity" "$root_identity"; then
    printf 'Java partial cleanup accepted an over-cap evidence tree\n' >&2
    return 1
  fi
  [[ -f "$cap_partial/entry-$MAX_JAVA_EVIDENCE_FILES" ]] || return 1

  if capture_bounded_private_output \
    "$bounded_output_dir/oversized" 16 5 head -c 17 /dev/zero; then
    printf 'bounded Java tool capture accepted oversized output\n' >&2
    return 1
  fi
  [[ ! -e "$bounded_output_dir/oversized" &&
    -z "$(find "$bounded_output_dir" -mindepth 1 -print -quit)" ]] || return 1

  capture_bounded_private_streams \
    "$bounded_output_dir/raw" 16 \
    "$bounded_output_dir/summary" 16 5 \
    bash -c 'printf raw; printf summary >&2' || return 1
  [[ "$(<"$bounded_output_dir/raw")" == raw &&
    "$(<"$bounded_output_dir/summary")" == summary ]] || return 1
  rm -f -- "$bounded_output_dir/raw" "$bounded_output_dir/summary"

  if capture_bounded_private_streams \
    "$bounded_output_dir/raw-too-large" 16 \
    "$bounded_output_dir/summary-for-raw" 16 5 \
    bash -c 'head -c 17 /dev/zero; printf summary >&2'; then
    printf 'bounded Java dual-stream capture accepted oversized raw output\n' >&2
    return 1
  fi
  [[ -z "$(find "$bounded_output_dir" -mindepth 1 -print -quit)" ]] || return 1

  if capture_bounded_private_streams \
    "$bounded_output_dir/raw-for-summary" 16 \
    "$bounded_output_dir/summary-too-large" 16 5 \
    bash -c 'printf raw; head -c 17 /dev/zero >&2'; then
    printf 'bounded Java dual-stream capture accepted oversized summary output\n' >&2
    return 1
  fi
  [[ -z "$(find "$bounded_output_dir" -mindepth 1 -print -quit)" ]] || return 1
)

test_java_benchmark_tooling_is_opt_in_and_payload_bounded() {
  local -r compose_file="$EXAMPLE_DIR/docker-compose.yml"
  local -r dockerfile="$EXAMPLE_DIR/java/Dockerfile"
  local -r jfc="$EXAMPLE_DIR/java/benchmark/obi-benchmark.jfc"
  local -a event_names=()

  mapfile -t event_names < <(
    sed -n 's/.*<event name="\([^"]*\)">.*/\1/p' "$jfc"
  )

  [[ "$(grep -Fc 'target: ${JAVA_IMAGE_TARGET:-runtime}' "$compose_file")" == 1 &&
    "$(grep -Fc 'image: ${JAVA_BACKEND_IMAGE:-obi-apache-java-https-backend:local}' \
      "$compose_file")" == 1 &&
    "$(grep -Fc '${JAVA_BENCHMARK_TOOL_OPTIONS_SUFFIX:-}' "$compose_file")" == 1 &&
    "$(grep -Fc 'COPY java/benchmark/RuntimeSnapshot.java /otel/benchmark-source/RuntimeSnapshot.java' \
      "$dockerfile")" == 1 &&
    "$(grep -Fc 'FROM runtime-base AS runtime' "$dockerfile")" == 1 &&
    "$(tail -n 1 "$dockerfile")" == 'FROM runtime-base AS runtime' &&
    "${event_names[*]}" == \
      'jdk.ObjectAllocationSample jdk.JavaMonitorEnter jdk.ThreadPark jdk.DataLoss' &&
    "$(grep -Fc '<setting name="stackTrace">false</setting>' "$jfc")" == 3 &&
    "$(grep -Fc '<setting name="stackTrace">true</setting>' "$jfc")" == 0 &&
    "$(grep -Ec '<event name="jdk\.(InitialSystemProperty|InitialEnvironmentVariable|ExecutionSample|NativeMethodSample|OldObjectSample)"' "$jfc" || true)" == 0 ]] || {
    printf 'benchmark JVM tooling is not opt-in, JRE-default, and payload-bounded\n' >&2
    return 1
  }
}

test_runtime_snapshot_source_and_jfc_are_exact_authorities() (
  local -r source="$EXAMPLE_DIR/java/benchmark/RuntimeSnapshot.java"
  local -r jfc="$EXAMPLE_DIR/java/benchmark/obi-benchmark.jfc"
  local -r source_mutation="$TEST_TMP_DIR/RuntimeSnapshot-mutated.java"
  local -r jfc_mutation="$TEST_TMP_DIR/obi-benchmark-mutated.jfc"

  validate_benchmark_runtime_source "$source" || return 1
  validate_benchmark_jfr_settings_source "$jfc" || return 1
  grep -Fq 'new RecordingFile(snapshot.descriptorPath())' "$source" &&
    grep -Fq 'FileChannel.open(source, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))' \
      "$source" &&
    grep -Fq 'readBoundedDescriptor(sourceDescriptor, sourceDescriptorPath, maximumBytes)' \
      "$source" &&
    grep -Fq 'streamRaw(System.out)' "$source" &&
    grep -Fq 'System.err.printf(' "$source" &&
    grep -Fq 'failure.addSuppressed(exception)' "$source" &&
    grep -Fq 'descriptor.close();' "$source" &&
    grep -Fq 'readBoundedDescriptor(descriptor, descriptorPath, maximumBytes)' "$source" &&
    ! grep -Fq 'exec cat "$JAVA_MEASUREMENT_JFR_CONTAINER_PATH"' \
      "$TEST_SCRIPT_DIR/benchmark.sh" || {
    printf 'JFR normalization/raw retention is not bound to one held descriptor\n' >&2
    return 1
  }
  cp -- "$source" "$source_mutation"
  sed -i 's/snapshot.descriptorPath()/snapshot.file()/g' "$source_mutation"
  if validate_benchmark_runtime_source "$source_mutation" >/dev/null 2>&1; then
    printf 'runtime helper source authority accepted a path-reopen mutation\n' >&2
    return 1
  fi
  cp -- "$jfc" "$jfc_mutation"
  sed -i 's/<setting name="stackTrace">false/<setting name="stackTrace">true/' \
    "$jfc_mutation"
  if validate_benchmark_jfr_settings_source "$jfc_mutation" >/dev/null 2>&1; then
    printf 'JFC source authority accepted a payload-expansion mutation\n' >&2
    return 1
  fi
)

test_java_tree_traversal_and_publication_identity_fail_closed() (
  local -r output="$TEST_TMP_DIR/java-tree-identity-output"
  local -r cell_dir="$output/cells/getsockopt-hit"
  local -r partial="$cell_dir/.java-measurement.partial"
  local -r final="$cell_dir/java-measurement"
  local -r listing="$cell_dir/listing"
  local old_partial="$cell_dir/old-partial"

  reset_options
  OUTPUT_DIR="$output"
  CELL_SLUG=getsockopt-hit
  mkdir -p -- "$partial/operations"
  chmod 0700 -- "$output" "$output/cells" "$cell_dir" "$partial" "$partial/operations"
  printf 'fixture\n' >"$partial/fixture"
  JAVA_MEASUREMENT_CELL_DIR="$cell_dir"
  JAVA_MEASUREMENT_PARTIAL="$partial"
  JAVA_MEASUREMENT_PARENT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")"
  JAVA_MEASUREMENT_ROOT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- "$partial")"
  java_measurement_root_identity_matches "$partial" partial || return 1
  capture_stable_java_listing "$partial" all "$listing" || return 1
  rm -f -- "$listing"

  find() { return 70; }
  if capture_stable_java_listing "$partial" all "$listing" >/dev/null 2>&1; then
    printf 'Java tree traversal hid an injected find failure\n' >&2
    return 1
  fi
  unset -f find
  [[ ! -e "$listing" && ! -L "$listing" ]] || return 1
  sort() { return 71; }
  if capture_stable_java_listing "$partial" all "$listing" >/dev/null 2>&1; then
    printf 'Java tree traversal hid an injected sort failure\n' >&2
    return 1
  fi
  unset -f sort
  [[ ! -e "$listing" && ! -L "$listing" ]] || return 1

  chmod 0750 -- "$cell_dir"
  if java_measurement_root_identity_matches "$partial" partial >/dev/null 2>&1; then
    printf 'Java measurement accepted parent identity drift\n' >&2
    return 1
  fi
  chmod 0700 -- "$cell_dir"
  # shellcheck disable=SC2034 # Consumed by the sourced root identity validator.
  JAVA_MEASUREMENT_PARENT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")"
  mv -- "$partial" "$old_partial"
  mkdir --mode=0700 -- "$partial"
  if java_measurement_root_identity_matches "$partial" partial >/dev/null 2>&1; then
    printf 'Java measurement accepted root inode substitution\n' >&2
    return 1
  fi
  rmdir -- "$partial"
  mv -- "$old_partial" "$partial"
  # shellcheck disable=SC2034 # Consumed by the sourced root identity validator.
  JAVA_MEASUREMENT_ROOT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- "$partial")"
  mv -T -- "$partial" "$final"
  java_measurement_root_identity_matches "$final" published || return 1
  chmod 0750 -- "$final"
  if java_measurement_root_identity_matches "$final" published >/dev/null 2>&1; then
    printf 'Java measurement accepted post-publication root identity drift\n' >&2
    return 1
  fi
)

test_java_publication_substitution_is_quarantined() (
  local -r output="$TEST_TMP_DIR/java-publication-substitution-output"
  local -r cell_dir="$output/cells/getsockopt-hit"
  local -r partial="$cell_dir/.java-measurement.partial"
  local -r final="$cell_dir/java-measurement"
  local -r expected_saved="$cell_dir/expected-root"
  local -r rejected="$cell_dir/.java-measurement.rejected"

  reset_options
  OUTPUT_DIR="$output"
  CELL_SLUG=getsockopt-hit
  mkdir -p -- "$partial"
  chmod 0700 -- "$output" "$output/cells" "$cell_dir" "$partial"
  printf 'expected\n' >"$partial/expected"
  JAVA_MEASUREMENT_CELL_DIR="$cell_dir"
  JAVA_MEASUREMENT_PARTIAL="$partial"
  JAVA_MEASUREMENT_PARENT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- "$cell_dir")"
  JAVA_MEASUREMENT_ROOT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- "$partial")"
  mv() {
    local -r source="${*: -2:1}"
    local -r destination="${*: -1}"

    if [[ "$source" == "$partial" && "$destination" == "$final" ]]; then
      command mv -T -- "$partial" "$expected_saved" || return 1
      mkdir --mode=0700 -- "$partial" || return 1
      printf 'untrusted replacement\n' >"$partial/untrusted" || return 1
    fi
    command mv "$@"
  }
  if publish_java_measurement_tree "$partial" "$final"; then
    printf 'Java publication accepted a last-window root substitution\n' >&2
    return 1
  fi
  unset -f mv
  [[ -f "$final/untrusted" && -f "$expected_saved/expected" &&
    ! -e "$cell_dir/java-measurement-publication.json" ]] || return 1
  quarantine_failed_java_measurement_publication "$cell_dir" || return 1
  [[ ! -e "$final" && ! -L "$final" &&
    ! -e "$cell_dir/java-measurement-publication.json" &&
    -f "$rejected/untrusted" ]] || return 1
  if validate_published_java_measurement "$cell_dir" >/dev/null 2>&1; then
    printf 'collector accepted quarantined unsealed Java evidence\n' >&2
    return 1
  fi
)

test_java_measurement_failure_classification_is_exact() (
  local -r output="$TEST_TMP_DIR/java-classification-output"
  local -r cell_dir="$output/cells/getsockopt-hit"
  local begin_calls=0
  local facility_status=1
  local begin_status=0

  reset_options
  OUTPUT_DIR="$output"
  CELL_SLUG=getsockopt-hit
  mkdir -p -- "$cell_dir"
  java_measurement_facilities_available() { return "$facility_status"; }
  begin_java_measurement() { ((begin_calls += 1)); return "$begin_status"; }
  if begin_java_measurement_with_classification "$cell_dir"; then
    return 1
  fi
  [[ "$begin_calls" == 0 ]] || return 1
  jq -e '.status == "unavailable" and
    .classification == "infrastructure_unavailable" and
    .stage == "post_warmup_preflight"' \
    "$cell_dir/java-measurement-status.json" >/dev/null || return 1
  rm -f -- "$cell_dir/java-measurement-status.json"

  facility_status=0
  begin_status=65
  if begin_java_measurement_with_classification "$cell_dir"; then
    return 1
  fi
  [[ "$begin_calls" == 1 ]] || return 1
  jq -e '.status == "failed" and
    .classification == "measurement_contract_failed" and
    .stage == "post_warmup_baseline"' \
    "$cell_dir/java-measurement-status.json" >/dev/null || return 1
  rm -f -- "$cell_dir/java-measurement-status.json"
  if write_java_measurement_status \
    "$cell_dir" post_load_stop product_unsupported >/dev/null 2>&1; then
    printf 'Java status writer accepted a fabricated unsupported classification\n' >&2
    return 1
  fi
)

assert_java_publication_receipt_mutations_rejected() {
  local -r output="$1"
  local -r cell_dir="$output/cells/getsockopt-hit"
  local -r receipt="$cell_dir/java-measurement-publication.json"
  local -r backup="$TEST_TMP_DIR/java-measurement-publication.backup.json"
  local compact=""
  local mutated=""
  local temporary=""
  local tree_entry=""
  local expected_file="$cell_dir/java-measurement/operations/03-nmt-baseline/output"
  local expected_backup="$TEST_TMP_DIR/java-measurement-expected-file.backup"
  local kind=""
  local -a tree_mutations=(regular symlink directory special)

  validate_published_java_measurement "$cell_dir" || return 1
  cp -- "$receipt" "$backup" || return 1
  rm -f -- "$receipt"
  if validate_published_java_measurement "$cell_dir" >/dev/null 2>&1; then
    printf 'collector accepted Java evidence without its publication receipt\n' >&2
    return 1
  fi
  cp -- "$backup" "$receipt" && chmod 0600 -- "$receipt" || return 1

  temporary="$(mktemp "$cell_dir/.publication.XXXXXX")" || return 1
  jq '.root_identity = "1:1:1:700"' "$receipt" >"$temporary" &&
    mv -T -- "$temporary" "$receipt" || return 1
  if validate_published_java_measurement "$cell_dir" >/dev/null 2>&1; then
    printf 'collector accepted a cross-root Java publication receipt\n' >&2
    return 1
  fi
  cp -- "$backup" "$receipt" && chmod 0600 -- "$receipt" || return 1

  compact="$(jq -c . "$receipt")" || return 1
  mutated="${compact/\"status\":\"sealed\"/\"status\":\"sealed\",\"status\":\"sealed\"}"
  [[ "$mutated" != "$compact" ]] || return 1
  printf '%s\n' "$mutated" >"$receipt"
  if validate_published_java_measurement "$cell_dir" >/dev/null 2>&1; then
    printf 'collector accepted a duplicate-key Java publication receipt\n' >&2
    return 1
  fi
  cp -- "$backup" "$receipt" && chmod 0600 -- "$receipt" || return 1

  temporary="$(mktemp "$cell_dir/.publication.XXXXXX")" || return 1
  jq '.tree_manifest_sha256 =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
    "$receipt" >"$temporary" && mv -T -- "$temporary" "$receipt" || return 1
  if validate_published_java_measurement "$cell_dir" >/dev/null 2>&1; then
    printf 'collector accepted a stale Java tree-manifest digest\n' >&2
    return 1
  fi
  cp -- "$backup" "$receipt" && chmod 0600 -- "$receipt" || return 1

  for kind in "${tree_mutations[@]}"; do
    tree_entry="$cell_dir/java-measurement/operations/foreign-$kind"
    case "$kind" in
      regular)
        printf 'foreign\n' >"$tree_entry" && chmod 0600 -- "$tree_entry" || return 1
        ;;
      symlink)
        ln -s -- ../identity.txt "$tree_entry" || return 1
        ;;
      directory)
        mkdir -- "$tree_entry" && chmod 0700 -- "$tree_entry" || return 1
        ;;
      special)
        mkfifo -m 0600 -- "$tree_entry" || return 1
        ;;
      *) return 1 ;;
    esac
    if validate_published_java_measurement "$cell_dir" >/dev/null 2>&1; then
      printf 'collector accepted a post-publication Java %s entry\n' "$kind" >&2
      return 1
    fi
    if [[ "$kind" == directory ]]; then
      rmdir -- "$tree_entry" || return 1
    else
      rm -f -- "$tree_entry" || return 1
    fi
    validate_published_java_measurement "$cell_dir" || return 1
  done

  cp -- "$expected_file" "$expected_backup" || return 1
  printf 'post-publication mutation\n' >>"$expected_file"
  if validate_published_java_measurement "$cell_dir" >/dev/null 2>&1; then
    printf 'collector accepted a changed expected Java evidence file\n' >&2
    return 1
  fi
  cp -- "$expected_backup" "$expected_file" && chmod 0600 -- "$expected_file" || return 1
  validate_published_java_measurement "$cell_dir" || return 1

  # The writer must reject both roster and expected-content drift before a
  # receipt exists; it may not bless the mutation by hashing the changed tree.
  JAVA_MEASUREMENT_CELL_DIR="$cell_dir"
  JAVA_MEASUREMENT_PARTIAL="$cell_dir/.java-measurement.partial"
  JAVA_MEASUREMENT_PARENT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- \
    "$cell_dir")" || return 1
  JAVA_MEASUREMENT_ROOT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- \
    "$cell_dir/java-measurement")" || return 1
  JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256="$(jq -er \
    '.runtime_artifacts.attestation_sha256' \
    "$cell_dir/java-measurement/evidence.json")" || return 1
  CELL_SLUG=getsockopt-hit
  rm -f -- "$receipt"
  tree_entry="$cell_dir/java-measurement/operations/foreign-before-receipt"
  printf 'foreign\n' >"$tree_entry" && chmod 0600 -- "$tree_entry" || return 1
  if write_java_measurement_publication_receipt "$cell_dir" >/dev/null 2>&1; then
    printf 'receipt writer accepted a foreign pre-receipt Java entry\n' >&2
    return 1
  fi
  [[ ! -e "$receipt" && ! -L "$receipt" ]] || return 1
  rm -f -- "$tree_entry"
  cp -- "$backup" "$receipt" && chmod 0600 -- "$receipt" || return 1
  validate_published_java_measurement "$cell_dir" || return 1

  rm -f -- "$receipt"
  printf 'pre-receipt mutation\n' >>"$expected_file"
  if write_java_measurement_publication_receipt "$cell_dir" >/dev/null 2>&1; then
    printf 'receipt writer accepted changed expected Java evidence\n' >&2
    return 1
  fi
  [[ ! -e "$receipt" && ! -L "$receipt" ]] || return 1
  cp -- "$expected_backup" "$expected_file" && chmod 0600 -- "$expected_file" || return 1
  cp -- "$backup" "$receipt" && chmod 0600 -- "$receipt" || return 1
  clear_active_java_measurement
  validate_published_java_measurement "$cell_dir"
}

assert_mixed_java_runtime_artifact_identity_rejected() {
  local -r output="$1"
  local -r root="$output/cells/getsockopt-hit/java-measurement"
  local artifact="$root/runtime-artifacts.json"
  local evidence="$root/evidence.json"
  local temporary=""
  local cell=""
  local started_at=""
  local stopped_at=""

  temporary="$(mktemp "$root/.runtime-artifacts.XXXXXX")" || return 1
  jq '.helper_jar.sha256 =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"' \
    "$artifact" >"$temporary" && mv -T -- "$temporary" "$artifact" || return 1
  cell="$(jq -er '.cell' "$evidence")" || return 1
  started_at="$(jq -er '.measurement_window.started_at' "$evidence")" || return 1
  stopped_at="$(jq -er '.measurement_window.stop_initiated_at' "$evidence")" || return 1
  # shellcheck disable=SC2034 # Consumed by the sourced evidence renderer.
  JAVA_MEASUREMENT_JVM_START_EPOCH_MILLIS="$(jq -er \
    '.process_binding.java_runtime_start_epoch_millis' "$evidence")" || return 1
  temporary="$(mktemp "$root/.evidence.XXXXXX")" || return 1
  java_measurement_evidence_json "$root" "$cell" "$started_at" "$stopped_at" \
    >"$temporary" && mv -T -- "$temporary" "$evidence" || return 1
  validate_java_measurement_evidence "$evidence" || return 1
  JAVA_MEASUREMENT_CELL_DIR="${root%/*}"
  JAVA_MEASUREMENT_PARTIAL="$JAVA_MEASUREMENT_CELL_DIR/.java-measurement.partial"
  # shellcheck disable=SC2034 # Consumed by the sourced publication writer.
  JAVA_MEASUREMENT_PARENT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- \
    "$JAVA_MEASUREMENT_CELL_DIR")" || return 1
  # shellcheck disable=SC2034 # Consumed by the sourced publication writer.
  JAVA_MEASUREMENT_ROOT_IDENTITY="$(stat --format '%d:%i:%u:%a' -- "$root")" || return 1
  # shellcheck disable=SC2034 # Consumed by the sourced publication writer.
  JAVA_MEASUREMENT_RUNTIME_ARTIFACT_SHA256="$(jq -er \
    '.runtime_artifacts.attestation_sha256' "$evidence")" || return 1
  CELL_SLUG="$cell"
  rm -f -- "$JAVA_MEASUREMENT_CELL_DIR/java-measurement-publication.json"
  write_java_measurement_publication_receipt "$JAVA_MEASUREMENT_CELL_DIR" || return 1
  validate_published_java_measurement "$JAVA_MEASUREMENT_CELL_DIR" || return 1
  clear_active_java_measurement
  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Consumed by the sourced summary writer.
  OUTPUT_READY=true
  CELLS_MODE=core
  if write_summary passed >/dev/null 2>&1; then
    printf 'summary accepted mixed per-cell runtime helper identities\n' >&2
    return 1
  fi
}

test_main_uses_runner_cleanup_and_retains_core_artifacts() {
  local -r fake_root="$TEST_TMP_DIR/fake-root"
  local -r fake_example="$fake_root/examples/apache-java-https"
  local -r fake_bin="$TEST_TMP_DIR/fake-bin"
  local -r output_parent="$TEST_TMP_DIR/fake-output-parent"
  local -r output="$output_parent/artifacts"
  local -r runner_log="$TEST_TMP_DIR/fake-runner.log"
  local -r docker_log="$TEST_TMP_DIR/fake-docker.log"
  local -r events="$TEST_TMP_DIR/fake-events.log"
  local -r diagnostics="$TEST_TMP_DIR/fake-diagnostics.txt"
  local -r bpf_metrics="$TEST_TMP_DIR/fake-bpf-metrics.txt"
  local -r compose_project="$TEST_TMP_DIR/fake-compose-project.txt"
  local -r results_root="$fake_example/.runtime/results"
  local -r helper_events="$TEST_TMP_DIR/helper-idle-events.log"
  local -r expected_helper_events="$TEST_TMP_DIR/helper-idle-events.expected"
  local -r docker_socket="$TEST_TMP_DIR/fake-docker.sock"
  local -r source_tree_manifest="$TEST_TMP_DIR/fake-source-tree.manifest"
  local -r java_measurement_state="$TEST_TMP_DIR/fake-java-measurement-state.txt"
  local -r clock_file="$TEST_TMP_DIR/fake-clock.txt"
  local -r bootstrap_jfr_file="$TEST_TMP_DIR/fake-bootstrap.jfr"
  local -r jfr_file="$TEST_TMP_DIR/fake-measurement.jfr"
  local -r runtime_helper_jar="$fake_example/java/benchmark/fake-helper.jar"
  local -r mutation_root="$TEST_TMP_DIR/java-measurement-mutations"
  local -a java_mutations=(
    duplicate-top duplicate-nested unexpected-key missing-key epoch-timestamp
    reversed-timestamps runtime-identity-drift duplicate-runtime-key
    duplicate-jfr-key negative-nmt-delta raw-jfr-drift raw-jfr-oversized
    missing-raw-jfr bootstrap-alternate-path measurement-stop-extra-line
    bootstrap-discard-missing bootstrap-discard-semantics nmt-baseline-old-wording
    snapshot-semantics-changed runtime-image-substitution
    runtime-helper-substitution runtime-helper-source-substitution
    runtime-jfc-substitution runtime-artifact-missing retention-overclaim
    stop-size-mismatch operations-foreign-file operations-foreign-symlink
    operations-foreign-directory operations-foreign-special
  )
  local cell=""
  local boundary=""
  local command_name=""
  local request=0
  local revision=""
  local git_tree=""

  mkdir -p -- "$fake_example/scripts" "$fake_example/java/benchmark" \
    "$fake_bin" "$output_parent" "$fake_example/.runtime"
  chmod 0755 -- "$fake_example/.runtime"
  install --mode=0755 "$TEST_SCRIPT_DIR/benchmark.sh" "$fake_example/scripts/benchmark.sh"
  install --mode=0644 "$TEST_SCRIPT_DIR/../java/benchmark/RuntimeSnapshot.java" \
    "$fake_example/java/benchmark/RuntimeSnapshot.java"
  install --mode=0644 "$TEST_SCRIPT_DIR/../java/benchmark/obi-benchmark.jfc" \
    "$fake_example/java/benchmark/obi-benchmark.jfc"
  printf 'fake deterministic helper jar\n' >"$runtime_helper_jar"
  ln -s -- "$TEST_SOURCE" "$fake_example/run.sh"
  printf 'services: {}\n' >"$fake_example/docker-compose.yml"
  printf 'examples/apache-java-https/.runtime/\n' >"$fake_root/.gitignore"
  git -C "$fake_root" init --quiet
  git -C "$fake_root" config user.email benchmark@example.invalid
  git -C "$fake_root" config user.name 'Benchmark Test'
  git -C "$fake_root" config commit.gpgsign false
  git -C "$fake_root" add -- .
  git -C "$fake_root" commit --quiet -m fixture
  revision="$(git -C "$fake_root" rev-parse HEAD)" || return 1
  git_tree="$(git -C "$fake_root" rev-parse "$revision^{tree}")" || return 1
  resolve_benchmark_identity_tools
  write_git_tree_manifest_for_tree \
    "$fake_root" "$git_tree" "$source_tree_manifest" || return 1
  create_unix_socket_fixture "$docker_socket"
  for command_name in docker curl sleep git; do
    ln -s -- "$TEST_SOURCE" "$fake_bin/$command_name"
  done
  printf '0 0 0\n' >"$diagnostics"
  printf '0 0 0 0 0 0 0 0 0 0 0\n' >"$bpf_metrics"
  printf 'pre\n' >"$java_measurement_state"
  printf '1000 1000000\n' >"$clock_file"
  printf 'FLR-fake-bounded-private-recording\n' >"$jfr_file"
  if ! PATH="$fake_bin:$PATH" \
    FAKE_CONTAINER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    FAKE_BPF_METRICS_FILE="$bpf_metrics" \
    FAKE_COMPOSE_PROJECT_FILE="$compose_project" \
    FAKE_DOCKER_LOG="$docker_log" \
    FAKE_DIAGNOSTICS_FILE="$diagnostics" \
    FAKE_DOCKER_ENDPOINT="unix://$docker_socket" \
    FAKE_EVENTS="$events" \
    FAKE_GIT_REVISION="$revision" \
    FAKE_BOOTSTRAP_JFR_FILE="$bootstrap_jfr_file" \
    FAKE_CLOCK_FILE="$clock_file" \
    FAKE_JAVA_MEASUREMENT_STATE_FILE="$java_measurement_state" \
    FAKE_JFR_FILE="$jfr_file" \
    FAKE_RUNTIME_HELPER_JAR_FILE="$runtime_helper_jar" \
    FAKE_RUNTIME_HELPER_SOURCE_FILE="$fake_example/java/benchmark/RuntimeSnapshot.java" \
    FAKE_RUNTIME_JFR_SETTINGS_FILE="$fake_example/java/benchmark/obi-benchmark.jfc" \
    FAKE_PID="$$" \
    FAKE_RESULTS_ROOT="$results_root" \
    FAKE_RUNNER_LOG="$runner_log" \
    FAKE_SOURCE_TREE_MANIFEST="$source_tree_manifest" \
    FAKE_TLS_PROTOCOL=TLSv1.2 \
    run_benchmark_with_fake_bound_proc "$fake_example/scripts/benchmark.sh" \
      --output "$output" \
      --agent splunk \
      --tls TLSv1.2 \
      --warmup-seconds 2 \
      --duration-seconds 2 \
      --concurrency 1 \
      --repetitions 5 \
      --seed 17 \
      "${VALID_PROCESS_TREE_CAP_ARGS[@]}"; then
    printf 'hermetic benchmark harness run failed\n' >&2
    return 1
  fi
  OUTPUT_DIR="$output"
  DURATION_SECONDS=2
  CONCURRENCY=1
  REPETITIONS=5
  jq -e '
    .status == "passed" and
    .acceptance_evidence == false and
    (.cells | length == 6) and
    all(.cells[]; .status == "passed") and
    .variance == {status: "available", path: "variance.json"} and
    .docker_daemon == {status: "verified_local_unix_socket_endpoint_only", path: "docker-daemon.json"} and
    (.application_source |
      .status == "clean_and_stable" and
      .path == "application-source-identity.json" and
      (.revision | test("^[0-9a-f]{40}$")) and
      (.git_tree | test("^[0-9a-f]{40}$")) and
      (.source_tree_sha256 | test("^[0-9a-f]{64}$"))) and
    .source_authority.checkouts[0].source_tree_sha256 ==
      .application_source.source_tree_sha256 and
    .poc_gates == {
      status: "partial", path: "poc-gates.json", result: "not_evaluated"
    } and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth == {
      status: "complete",
      result: "passed",
      process_fd_threads: {status: "complete", result: "passed"},
      java_bridge_map: {
        status: "complete",
        result: "passed",
        reason: null,
        descriptive_data_status: "complete"
      },
      full_cgroup_v2_process_tree_fd_task_rss: .measurement_scope.application_fd_threads_and_java_bridge_map_growth.full_cgroup_v2_process_tree_fd_task_rss,
      application_cpu_per_successful_request: .measurement_scope.application_fd_threads_and_java_bridge_map_growth.application_cpu_per_successful_request
    } and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth.full_cgroup_v2_process_tree_fd_task_rss.status == "complete" and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth.full_cgroup_v2_process_tree_fd_task_rss.result == "passed" and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth.application_cpu_per_successful_request.status == "complete" and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth.application_cpu_per_successful_request.result == "passed" and
    .measurement_scope.nmt_and_direct_memory_recovery_drift ==
      "bounded_indicators_retained_not_evaluated_as_acceptance_gates" and
    .measurement_scope.primary_cgroupsockopt_program_cpu == "not_collected" and
    .measurement_scope.exact_owned_cgroupsockopt_program_counters == {
      status: "available",
      artifact: "cells/*/bpf-program-runtime.json",
      retained_cell_artifacts: 6,
      expected_cell_artifacts: 6,
      metric: "kernel_reported_program_execution_count_and_cumulative_run_time_deltas",
      acceptance_evidence: false
    } and
    (.measurement_scope.jfr_nmt_allocation_native_direct_memory |
      .status == "available" and
      .artifact == "cells/*/java-measurement/evidence.json" and
      .retained_cell_artifacts == 6 and .expected_cell_artifacts == 6 and
      (.runtime_artifact_attestation_sha256 | test("^[0-9a-f]{64}$")) and
      .indicators == [
          "sampled_allocation_weight", "monitor_enter_duration",
          "thread_park_duration", "nmt_committed_and_reserved",
          "direct_buffer_pool"
        ] and
      .acceptance_evidence == false) and
    (.notes | any(contains("passed summary status means the harness completed successfully")))
  ' "$output/summary.json" >/dev/null || {
    printf 'hermetic run misrepresented harness completion as a completed PoC gate\n' >&2
    return 1
  }
  validate_application_source_identity_schema \
    "$output/application-source-identity.json" "$fake_root" || return 1
  jq -e '.cells_mode == "core" and (.cells | length) == 6 and
    (.canonical_patch_identity_sha256 | test("^[0-9a-f]{64}$"))' \
    "$output/application-source-identity.json" >/dev/null || return 1
  jq -e '.status == "verified_local_unix_socket_endpoint_only" and
    .socket_evidence == "existing_non_symlink_unix_socket" and
    .daemon_process_locality == "not_established_by_unix_socket_endpoint"' \
    "$output/docker-daemon.json" >/dev/null || return 1
  grep -Eq '^container_id=[0-9a-f]{64}$' \
    "$output/cells/getsockopt-hit/resources-before/java-backend-proc.txt" &&
    grep -Eq '^proc_start_time=[1-9][0-9]*$' \
      "$output/cells/getsockopt-hit/resources-before/java-backend-proc.txt" &&
    grep -Eq '^proc_cgroup_sha256=[0-9a-f]{64}$' \
      "$output/cells/getsockopt-hit/resources-before/java-backend-proc.txt" &&
    grep -Fxq 'proc_cgroup_container_binding=full_container_id_at_non_hex_boundaries' \
      "$output/cells/getsockopt-hit/resources-before/java-backend-proc.txt" || {
    printf 'hermetic run omitted bound container/process identity evidence\n' >&2
    return 1
  }
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .issue_acceptance_complete == false and
    .performance.population_variability.status == "complete" and
    .performance.population_variability.result == "passed" and
    all(.performance.population_variability.cells[];
      .throughput_per_second.coefficient_of_variation_percent == 0 and
      .p99_latency_nanos.coefficient_of_variation_percent == 0 and
      .result == "passed") and
    .sampled_allocation.status == "complete" and
    .sampled_allocation.result == "passed" and
    .sampled_allocation.classification ==
      "exploratory_sampled_indicator_not_exact_allocation" and
    .sampled_allocation.exact_allocation == false and
    all(.sampled_allocation.observations[];
      .status == "complete" and
      .sampled_allocation_records == 5 and
      .sampled_allocation_weight_bytes == 500 and
      .successful_requests == 20 and
      .sampled_allocation_weight_bytes_per_successful_request == 25) and
    all(.sampled_allocation.comparisons[]; .result == "passed") and
    .resources.map_dimension.status == "complete" and
    .resources.map_dimension.result == "passed" and
    .resources.status == "complete" and .resources.result == "passed" and
    .resources.process_tree.status == "complete" and
    .resources.process_tree.result == "passed" and
    (.resources.process_tree.observations | length) == 11 and
    all(.resources.process_tree.observations[];
      .status == "complete" and .result == "passed") and
    .resources.application_cpu.status == "complete" and
    .resources.application_cpu.result == "passed" and
    (.resources.application_cpu.observations | length) == 4 and
    (.resources.application_cpu.comparisons | length) == 9 and
    all(.resources.application_cpu.comparisons[]; .result == "passed") and
    .resources.application_cpu.primary_cgroupsockopt_program_cpu == "not_collected" and
    .resources.map_sampling_scope.ownership_attribution == true and
    (.resources.java_bridge_map_observations[] |
      select(.cell == "bridge-disabled") |
      .data_status == "complete" and
      .descriptive_result == "stable_or_decreased" and
      .maps == [{
        map_id: 41, map_name: "java_remote_par", map_type: "hash",
        before_entries: 0, idle_recovery_entries: 0, delta: 0,
        maximum_delta: 0, max_entries: 1
      }]) and
    all(.resources.java_bridge_map_observations[];
      .status == "complete" and .result == "passed" and
      .scope == "exact_obi_process_open_bpf_map_ids" and
      .ownership_attribution == true)
  ' "$output/poc-gates.json" >/dev/null || {
    printf 'hermetic run did not bind Java map samples to the exact OBI process\n' >&2
    return 1
  }
  for cell in uninstrumented bridge-disabled getsockopt-hit unix-hit getsockopt-w3c getsockopt-helper-idle; do
    [[ -f "$output/cells/$cell/cpu-measurement-baseline/snapshot.json" &&
      -f "$output/cells/$cell/cpu-measurement-end/snapshot.json" &&
      -f "$output/cells/$cell/program-metrics-baseline/snapshot.json" &&
      -f "$output/cells/$cell/program-metrics-end/snapshot.json" &&
      -f "$output/cells/$cell/recovery-schedule.json" &&
      -f "$output/cells/$cell/bpf-program-runtime.json" &&
      -f "$output/cells/$cell/java-measurement/evidence.json" &&
      -f "$output/cells/$cell/java-measurement-publication.json" &&
      -f "$output/cells/$cell/java-measurement/measurement.jfr" ]] || {
      printf 'hermetic run omitted measurement-boundary artifacts for %s\n' "$cell" >&2
      return 1
    }
    validate_cpu_measurement_boundary \
      "$output/cells/$cell/cpu-measurement-baseline" \
      "$cell" cpu_measurement_baseline || return 1
    validate_cpu_measurement_boundary \
      "$output/cells/$cell/cpu-measurement-end" \
      "$cell" cpu_measurement_end || return 1
    validate_resource_snapshot_boundary \
      "$output/cells/$cell/program-metrics-baseline/snapshot.json" \
      "$cell" program_metrics_baseline || return 1
    validate_resource_snapshot_boundary \
      "$output/cells/$cell/program-metrics-end/snapshot.json" \
      "$cell" program_metrics_end || return 1
    [[ -z "$(find "$output/cells/$cell/program-metrics-baseline" \
      "$output/cells/$cell/program-metrics-end" -mindepth 1 -maxdepth 1 \
      -name '*-cgroup-v2.json' -print -quit)" ]] || {
      printf 'diagnostic program-metrics boundary retained authoritative cgroup evidence\n' >&2
      return 1
    }
    validate_recovery_schedule_schema \
      "$output/cells/$cell/recovery-schedule.json" || return 1
    for repetition_label in rep-01 rep-02 rep-03 rep-04 rep-05; do
      validate_scheduled_midpoint_boundary \
        "$output/cells/$cell/measurements/$repetition_label-midpoint" \
        "$cell" "${repetition_label#rep-0}" || return 1
    done
    validate_java_measurement_evidence \
      "$output/cells/$cell/java-measurement/evidence.json" || return 1
    validate_published_java_measurement \
      "$output/cells/$cell" || return 1
    jq -e '
      (has("target_pid") | not) and
      (has("jvm_start_epoch_millis") | not)
    ' "$output/cells/$cell/java-measurement/operations/08-jfr-summary/output" \
      >/dev/null || {
      printf 'JFR summary echoed unrecorded caller identity for %s\n' "$cell" >&2
      return 1
    }
    jq -e '
      .status == "complete" and .acceptance_evidence == false and
      .interpretation.acceptance_evidence == false and
      .interpretation.jfr_retention_may_be_a_bounded_tail_if_the_size_limit_was_reached == true and
      (.runtime_artifacts.attestation_sha256 | test("^[0-9a-f]{64}$")) and
      .runtime_artifacts.configured_image_tag ==
        "obi-apache-java-https-backend-benchmark:local" and
      .jfr.raw_private_diagnostic_input == true and
      .jfr.snapshot_semantics ==
        "single_source_descriptor_bounded_private_copy" and
      .jfr.retention_scope ==
        "bounded_tail_may_exclude_earliest_events_if_maximum_size_is_reached" and
      .jfr.whole_window_retention_attested == false and
      .jfr.stop_reported_size_reconciled == true and
      .jfr.allocation_sample == {records: 5, weight_bytes: 500} and
      .jfr.data_loss == {records: 0, bytes: 0} and
      .nmt.baseline == {reserved_bytes: 1000000, committed_bytes: 500000} and
      .nmt.non_negative_delta == {
        reserved_bytes: 5000, committed_bytes: 2500
      } and
      .direct_buffer.signed_delta == {
        count: 5, memory_used_bytes: 500, total_capacity_bytes: 500
      }
    ' "$output/cells/$cell/java-measurement/evidence.json" >/dev/null || return 1
    if grep -Eqi \
      'class_name|className|stackTrace|stack_frame|jvmArguments|systemProperties|request_marker|source_path' \
      "$output/cells/$cell/java-measurement/evidence.json"; then
      printf 'normalized Java evidence disclosed a prohibited payload field\n' >&2
      return 1
    fi
    jq -e '
      .java_diagnostics == {
        status: "not_collected",
        reason: "excluded_from_exact_sustained_measurement_counter_window"
      }
    ' "$output/cells/$cell/program-metrics-baseline/snapshot.json" \
      "$output/cells/$cell/program-metrics-end/snapshot.json" >/dev/null || return 1
    for repetition_label in rep-01 rep-02 rep-03 rep-04 rep-05; do
      jq -e '
        .latency.histogram_encoding == "sorted_rle_nanos_v1" and
        .latency.histogram == [{nanos: 1, count: 4}]
      ' "$output/cells/$cell/measurements/$repetition_label.json" >/dev/null || return 1
    done
  done
  for cell in uninstrumented bridge-disabled unix-hit; do
    jq -e '
      .status == "not_applicable" and .acceptance_evidence == false and
      .scope == "exact_obi_process_open_java_bridge_cgroup_sockopt_program_ids" and
      .programs == []
    ' "$output/cells/$cell/bpf-program-runtime.json" >/dev/null || return 1
    for boundary in program-metrics-baseline program-metrics-end; do
      if [[ "$cell" == uninstrumented ]]; then
        jq -e '. == {
          status: "not_applicable", reason: "cell_has_no_obi_process"
        }' "$output/cells/$cell/$boundary/obi-metrics-fence.json" >/dev/null || return 1
      else
        jq -e '. == {
          status: "not_applicable",
          reason: "selected_transport_does_not_use_cgroup_sockopt_bridge"
        }' "$output/cells/$cell/$boundary/obi-metrics-fence.json" >/dev/null || return 1
        if grep -q '^obi_bpf_probe_' \
          "$output/cells/$cell/$boundary/obi-metrics.prom"; then
          printf 'non-getsockopt cell %s unexpectedly required program metric series\n' \
            "$cell" >&2
          return 1
        fi
      fi
    done
  done
  # Recompute production artifacts with the same sustained workload contract used
  # by the independently executed fake harness.
  for cell in getsockopt-hit getsockopt-w3c getsockopt-helper-idle; do
    cell_spec "$cell" || return 1
    validate_exact_owned_cgroup_sockopt_runtime \
      "$output/cells/$cell/bpf-program-runtime.json" || return 1
    validate_bpf_probe_collection_fence \
      "$output/cells/$cell/program-metrics-baseline/obi-metrics-fence.json" || return 1
    validate_bpf_probe_collection_fence \
      "$output/cells/$cell/program-metrics-end/obi-metrics-fence.json" || return 1
    jq -e '
      .confirmation == {
        required_marker_advances_per_program: 2,
        separate_scrape_started_after_fence_response: true,
        retained_confirmation_scrape: true
      } and
      all(.programs[];
        (.observed_fence_collection_passes - .initial_collection_passes) >= 2 and
        .confirmation_collection_passes >= .observed_fence_collection_passes)
    ' "$output/cells/$cell/program-metrics-baseline/obi-metrics-fence.json" \
      "$output/cells/$cell/program-metrics-end/obi-metrics-fence.json" \
      >/dev/null || return 1
    jq -e '
      .status == "complete" and .acceptance_evidence == false and
      .scope == "exact_obi_process_open_java_bridge_cgroup_sockopt_program_ids" and
      .successful_requests == 20 and
      (.programs | length) == 7 and
      ([.programs[].program_id] == [71, 72, 73, 74, 75, 76, 77]) and
      all(.programs[];
        .probe_type == "CGroupSockopt" and
        .delta.executions == 20 and
        .delta.runtime_nanoseconds == 20000 and
        .delta.collection_passes > 0) and
      .totals.executions == 140 and .totals.runtime_nanoseconds == 140000
    ' "$output/cells/$cell/bpf-program-runtime.json" >/dev/null || return 1
  done
  cell_spec getsockopt-hit || return 1
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom" \
    "$TEST_TMP_DIR/owned-runtime-end.prom"
  printf '%s\n' \
    'obi_bpf_probe_executions_total{probe_id="71",probe_type="CGroupSockopt",probe_name="obi_java_remote_parent_setsockopt"} 24' \
    >>"$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted a duplicate probe series\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end.prom" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom" \
    "$TEST_TMP_DIR/owned-runtime-end.prom"
  printf '%s\n' \
    'obi_bpf_probe_collection_passes_total{probe_id="71",probe_type="CGroupSockopt",probe_name="obi_java_remote_parent_setsockopt"} 26' \
    >>"$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted a duplicate collection marker series\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end.prom" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom" \
    "$TEST_TMP_DIR/owned-runtime-end.prom"
  grep -Fv \
    'obi_bpf_probe_collection_passes_total{probe_id="77",probe_type="CGroupSockopt",probe_name="obi_java_remote_parent_getsockopt_health"}' \
    "$TEST_TMP_DIR/owned-runtime-end.prom" \
    >"$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted a missing collection marker series\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end.prom" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom" \
    "$TEST_TMP_DIR/owned-runtime-end.prom"
  sed '/obi_bpf_probe_collection_passes_total{probe_id="71"/ s/ [0-9][0-9]*$/ 0/' \
    "$TEST_TMP_DIR/owned-runtime-end.prom" \
    >"$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted a reset collection marker\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end.prom" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom" \
    "$TEST_TMP_DIR/owned-runtime-end.prom"
  sed '/obi_bpf_probe_executions_total{probe_id="71"/ s/ [0-9][0-9]*$/ 0/' \
    "$TEST_TMP_DIR/owned-runtime-end.prom" \
    >"$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted a reset probe counter\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end.prom" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom" \
    "$TEST_TMP_DIR/owned-runtime-end.prom"
  head -c 100 "$TEST_TMP_DIR/owned-runtime-end.prom" \
    >"$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted a truncated probe scrape\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end.prom" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics.prom"
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-bpf-fd-ownership.txt" \
    "$TEST_TMP_DIR/owned-runtime-end.txt"
  sed 's/^fd=12 prog_id=77$/fd=12 prog_id=78/' \
    "$TEST_TMP_DIR/owned-runtime-end.txt" \
    >"$output/cells/getsockopt-hit/program-metrics-end/obi-bpf-fd-ownership.txt"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted an ownership roster drift\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end.txt" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-bpf-fd-ownership.txt"
  cp -- "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics-fence.json" \
    "$TEST_TMP_DIR/owned-runtime-end-fence.json"
  jq '.programs[0].confirmation_collection_passes += 1' \
    "$TEST_TMP_DIR/owned-runtime-end-fence.json" \
    >"$output/cells/getsockopt-hit/program-metrics-end/obi-metrics-fence.json"
  if validate_exact_owned_cgroup_sockopt_runtime \
    "$output/cells/getsockopt-hit/bpf-program-runtime.json" >/dev/null 2>&1; then
    printf 'owned runtime validator accepted collection-fence identity drift\n' >&2
    return 1
  fi
  mv -T -- "$TEST_TMP_DIR/owned-runtime-end-fence.json" \
    "$output/cells/getsockopt-hit/program-metrics-end/obi-metrics-fence.json"
  jq -e '
    .schema_version == 2 and
    .kind == "application-performance-repetition-summary" and
    .status == "complete" and
    .acceptance_evidence == false and
    .aggregation.cross_cell_aggregation == false and
    .aggregation.per_request_latency_aggregation == false and
    (.cells | map(.cell)) == [
      "uninstrumented",
      "bridge-disabled",
      "getsockopt-hit",
      "unix-hit",
      "getsockopt-w3c",
      "getsockopt-helper-idle"
    ] and
    all(.cells[];
      .expected_sample_count == 5 and
      .valid_sample_count == 5 and
      (.samples | map(.repetition)) == [1, 2, 3, 4, 5] and
      all(.samples[];
        (.source | test("^cells/(uninstrumented|bridge-disabled|getsockopt-hit|unix-hit|getsockopt-w3c|getsockopt-helper-idle)/measurements/rep-0[1-5]\\.json$")) and
        .successful_requests == 4 and
        .failed_requests == 0 and
        .traffic_elapsed_nanos == 2000000000 and
        .throughput_per_second == 2 and
        .latency == {p50_nanos: 1, p95_nanos: 1, p99_nanos: 1}
      ) and
      .statistics.successful_requests == {min: 4, median: 4, max: 4} and
      .statistics.failed_requests == {min: 0, median: 0, max: 0} and
      .statistics.traffic_elapsed_nanos == {min: 2000000000, median: 2000000000, max: 2000000000} and
      (.statistics.throughput_per_second |
        .min == 2 and .median == 2 and .max == 2 and
        .population_variability == {
          sample_count: 5, sum: 10, mean: 2, squared_deviation_sum: 0,
          population_variance: 0, population_standard_deviation: 0,
          coefficient_of_variation_percent: 0
        }) and
      .statistics.latency.p50_nanos == {min: 1, median: 1, max: 1} and
      .statistics.latency.p95_nanos == {min: 1, median: 1, max: 1} and
      (.statistics.latency.p99_nanos |
        .min == 1 and .median == 1 and .max == 1 and
        .population_variability == {
          sample_count: 5, sum: 5, mean: 1, squared_deviation_sum: 0,
          population_variance: 0, population_standard_deviation: 0,
          coefficient_of_variation_percent: 0
        })
    )
  ' "$output/variance.json" >/dev/null || {
    printf 'hermetic run did not retain complete per-cell repetition variance\n' >&2
    return 1
  }
  [[ "$(grep -Fc cleanup "$events")" == 6 ]] || {
    printf 'hermetic run did not clean each core cell through the runner\n' >&2
    return 1
  }
  [[ -f "$fake_example/.runtime/benchmark.lock" &&
    "$(stat --format '%a' -- "$fake_example/.runtime")" == 700 ]] || {
    printf 'hermetic run did not safely secure its runtime lock\n' >&2
    return 1
  }
  jq -e '.requests == 16' \
    "$output/cells/getsockopt-hit/preflight/contract.json" >/dev/null || {
    printf 'hermetic run did not retain the fixed bounded preflight request count\n' >&2
    return 1
  }
  for cell in uninstrumented bridge-disabled getsockopt-hit unix-hit getsockopt-w3c getsockopt-helper-idle; do
    [[ -f "$output/cells/$cell/preflight/benchmark-ca.crt" &&
      "$(stat --format '%a' -- "$output/cells/$cell/preflight/benchmark-ca.crt")" == 444 &&
      -f "$output/cells/$cell/preflight/benchmark-ca-source-identity.txt" &&
      "$(stat --format '%a' -- "$output/cells/$cell/preflight/benchmark-ca-source-identity.txt")" == 400 ]] || {
      printf 'benchmark cell %s omitted its private verified CA copy\n' "$cell" >&2
      return 1
    }
    jq -e '
      .source_service == "apache-proxy" and
      .source_path == "/run/obi-demo/certs/ca.crt" and
      .source_identity == "benchmark-ca-source-identity.txt" and
      (.source_container_id | test("^[0-9a-f]{64}$")) and
      .expected_sha256_fingerprint == .observed_sha256_fingerprint and
      .size_bytes > 0 and
      .assertion == {
        source_container_identity_verified: true,
        recorded_fingerprint_matched: true,
        canonical_single_pem_certificate: true,
        private_key_or_keystore_copied: false
      }
    ' "$output/cells/$cell/preflight/benchmark-ca.json" >/dev/null || {
      printf 'benchmark cell %s omitted exact CA provenance\n' "$cell" >&2
      return 1
    }
    grep -Fxq 'service=apache-proxy' \
      "$output/cells/$cell/preflight/benchmark-ca-source-identity.txt" || {
      printf 'benchmark cell %s omitted its verified CA source identity\n' "$cell" >&2
      return 1
    }
  done
  jq -e '.status == "passed" and .requests == 16' \
    "$output/cells/unix-hit/postload-sentinel/status.json" >/dev/null || {
    printf 'hermetic run did not retain the post-load sentinel\n' >&2
    return 1
  }
  [[ -f "$output/cells/getsockopt-hit/preflight/runner/phases/concurrency-after/obi-metrics.prom" ]] || {
    printf 'hermetic run did not retain runner phase evidence\n' >&2
    return 1
  }
  jq -e '
    .sustained_w3c == true and
    .sentinel_scenario == "w3c" and
    .expected_standard_parent_discards == 8 and
    .expected_w3c_valid_takes == 16
  ' "$output/cells/getsockopt-w3c/preflight/contract.json" >/dev/null || {
    printf 'W3C benchmark cell did not retain its traffic and discard contract\n' >&2
    return 1
  }
  [[ -f "$output/cells/getsockopt-w3c/preflight/runner/phases/w3c-after/java-diagnostics.delta" ]] || {
    printf 'W3C benchmark preflight did not retain standard-parent discard diagnostics\n' >&2
    return 1
  }
  jq -e '
    .scenario == "w3c" and
    .expected_standard_parent_discards == 8
  ' "$output/cells/getsockopt-w3c/postload-sentinel/status.json" >/dev/null || {
    printf 'W3C benchmark post-load sentinel did not retain its assertion contract\n' >&2
    return 1
  }
  jq -e '
    (.counters | map({counter, observed_delta, expected_delta})) == [
      {counter: "discard_standard", observed_delta: 8, expected_delta: 8},
      {counter: "t_valid", observed_delta: 16, expected_delta: 16},
      {counter: "d_valid", observed_delta: 0, expected_delta: 0}
    ]
  ' \
    "$output/cells/getsockopt-w3c/postload-sentinel/standard-parent-discard-diagnostics.json" \
    >/dev/null || {
    printf 'W3C benchmark post-load sentinel did not retain the exact discard delta\n' >&2
    return 1
  }
  jq -e '
    (.counters | map({counter, observed_delta, expected_delta})) == [
      {counter: "discard_standard", observed_delta: 24, expected_delta: 24},
      {counter: "t_valid", observed_delta: 24, expected_delta: 24},
      {counter: "d_valid", observed_delta: 0, expected_delta: 0}
    ]
  ' "$output/cells/getsockopt-w3c/sustained-w3c/java-diagnostics-deltas.json" >/dev/null || {
    printf 'W3C benchmark workload did not retain exact precedence deltas\n' >&2
    return 1
  }
  jq -e '
    .transport == "getsockopt" and
    .scenario == "concurrency" and
    .selected_transport == "getsockopt" and
    .sentinel_scenario == "concurrency" and
    .helper_idle_direct_java == true and
    .state_map_absence_proof == false and
    .workload == {
      base_url: "https://127.0.0.1:18443",
      path: "/api/echo?delay_ms=150",
      connection_mode: "close",
      ca_file: "/benchmark-ca.crt",
      tls_verification: "verified_ca_file",
      upstream_handoff: "none"
    }
  ' "$output/cells/getsockopt-helper-idle/preflight/contract.json" >/dev/null || {
    printf 'helper-idle benchmark cell did not retain the direct-Java HTTPS contract\n' >&2
    return 1
  }
  jq -e '
    .workload_successful_requests == 24 and
    .diagnostic_after_probe_t_missing == 1 and
    .raw_java_t_missing_delta == 25 and
    .corrected_workload_t_missing == 24 and
    .correction.corrected_workload_t_missing_expected == 24 and
    (.raw_counters | any(.counter == "t_missing" and .observed_delta == 25 and .expected_delta == 25)) and
    (.raw_counters | all(.[] | select(.counter != "t_missing"); .observed_delta == 0 and .expected_delta == 0))
  ' "$output/cells/getsockopt-helper-idle/sustained-helper-idle/java-diagnostics-deltas.json" \
    >/dev/null || {
    printf 'helper-idle Java diagnostics did not retain exact raw and corrected missing accounting\n' >&2
    return 1
  }
  jq -e '
    .semantic == "direct_java_no_upstream_handoff_not_state_map_miss_proof" and
    .report_watermark.observed_delta > 0 and
    (.constrained_zero_deltas | map({category, operation, transport, expected_delta}) == [
      {category: "tcp-candidate", operation: "candidate", transport: "tcp", expected_delta: 0},
      {category: "tcp-inject", operation: "inject", transport: "tcp", expected_delta: 0},
      {category: "tcp-stage", operation: "stage", transport: "tcp", expected_delta: 0},
      {category: "tcp-handoff", operation: "handoff", transport: "tcp", expected_delta: 0},
      {category: "tcp-handoff_admission", operation: "handoff_admission", transport: "tcp", expected_delta: 0},
      {category: "getsockopt-take", operation: "take", transport: "getsockopt", expected_delta: 0},
      {category: "getsockopt-discard", operation: "discard", transport: "getsockopt", expected_delta: 0}
    ]) and
    (.constrained_zero_deltas | all(.observed_delta == 0 and .expected_delta == 0)) and
    .assertion == {
      tcp_upstream_candidate_inject_stage_handoff_and_admission_delta_zero: true,
      getsockopt_take_discard_delta_zero: true
    }
  ' "$output/cells/getsockopt-helper-idle/sustained-helper-idle/obi-metrics-deltas.json" \
    >/dev/null || {
    printf 'helper-idle BPF metrics did not retain constrained no-handoff evidence\n' >&2
    return 1
  }
  jq -e '
    .semantic == "direct_java_no_upstream_handoff_not_state_map_miss_proof" and
    .workload_successful_requests == 24 and
    .workload.upstream_handoff == "none" and
    .java == {
      raw_t_missing_delta: 25,
      diagnostic_after_probe_t_missing: 1,
      corrected_workload_t_missing: 24,
      exact_workload_reconciliation: true
    } and
    (.caveat | contains("does not prove a java_remote_parent_state map absence"))
  ' "$output/cells/getsockopt-helper-idle/sustained-helper-idle/reconciliation.json" \
    >/dev/null || {
    printf 'helper-idle reconciliation overstated or lost its direct-Java caveat\n' >&2
    return 1
  }
  jq -e '
    .metric == "obi_java_remote_parent_operations_total" and
    .operation == "report" and .status == "valid" and .transport == "tcp" and
    .initial_report >= 0 and
    .first_post_boundary_report > .initial_report and
    .second_post_boundary_report > .first_post_boundary_report and
    .observed_delta > 0 and
    .fence == {
      required_serial_post_boundary_report_passes: 2,
      report_is_published_after_each_successful_java_bridge_stats_pass: true
    }
  ' "$output/cells/getsockopt-helper-idle/sustained-helper-idle/metrics-watermark-before.json" \
    "$output/cells/getsockopt-helper-idle/sustained-helper-idle/metrics-watermark-after.json" \
    >/dev/null || {
    printf 'helper-idle did not retain two-pass causal BPF fences around its exact window\n' >&2
    return 1
  }
  for ((request = 1; request <= 5; request++)); do
    printf -v repetition_label 'rep-%02d' "$request"
    jq -e --argjson repetition "$request" '
      .kind == "scheduled-cgroup-v2-midpoint-boundary" and
      .timing == "scheduled_repetition_midpoint" and .repetition == $repetition and
      .metrics == {
        status: "not_collected", reason: "zero_in_window_scrapes_required"
      } and
      .java_diagnostics == {
        status: "not_collected",
        reason: "excluded_from_measured_window"
      }
    ' "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/snapshot.json" \
      >/dev/null || {
      printf 'helper-idle midpoint %s did not retain cgroup-only provenance\n' \
        "$repetition_label" >&2
      return 1
    }
    jq -e '
      .scope == {
        cgroup_v2_process_tree: {status: "collected"},
        docker_inspect: {status: "not_collected", reason: "excluded_from_measured_window"},
        container_stats: {status: "not_collected", reason: "excluded_from_measured_window"},
        obi_metrics: {status: "not_collected", reason: "zero_in_window_scrapes_required"},
        java_diagnostics: {status: "not_collected", reason: "excluded_from_measured_window"}
      }
    ' "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/midpoint-receipt.json" \
      >/dev/null || return 1
    [[ -f "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/obi-cgroup-v2.json" &&
      -f "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-cgroup-v2.json" &&
      ! -e "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-proc.txt" &&
      ! -e "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/container-stats.jsonl" &&
      ! -e "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/obi-metrics.prom" &&
      ! -e "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-diagnostics.txt" ]] || {
      printf 'helper-idle midpoint %s retained non-cgroup in-window evidence\n' \
        "$repetition_label" >&2
      return 1
    }
  done
  awk '
    $1 == "start" && $2 ~ /-helper-idle$/ && $3 == "getsockopt" && $4 == "concurrency" {
      collect = 1
      next
    }
    collect && $1 == "cleanup" { exit }
    collect { print }
  ' "$events" >"$helper_events"
  {
    printf '%s\n' obi-metrics java-diagnostics java-diagnostics obi-metrics obi-metrics obi-metrics
    printf '%s\n' direct-java-workload
    printf '%s\n' obi-metrics obi-metrics obi-metrics obi-metrics
    for ((request = 0; request < 5; request++)); do
      printf '%s\n' direct-java-workload
    done
    printf '%s\n' obi-metrics obi-metrics obi-metrics obi-metrics obi-metrics obi-metrics \
      obi-metrics \
      java-diagnostics obi-metrics java-diagnostics \
      obi-metrics obi-metrics
  } >"$expected_helper_events"
  cmp -s -- "$expected_helper_events" "$helper_events" || {
    printf 'helper-idle added an in-window diagnostic probe or reordered its BPF/resource fences\n' >&2
    return 1
  }
  grep -Fq 'getsockopt concurrency' "$runner_log" || {
    printf 'helper-idle preflight did not retain active forced-getsockopt concurrency coverage\n' >&2
    return 1
  }
  jq -e '
    (.retained_files | index("compose-images.json")) and
    (.retained_files | index("host-topology.txt")) and
    (.retained_files | index("apache-openssl-version.txt")) and
    (.retained_files | index("obi-startup.log"))
  ' "$output/cells/getsockopt-hit/preflight/runner/provenance.json" >/dev/null || {
    printf 'hermetic run omitted required runner provenance artifacts\n' >&2
    return 1
  }
  jq -e '.transport_configuration_artifacts == "not_applicable"' \
    "$output/cells/bridge-disabled/preflight/runner/provenance.json" >/dev/null || {
    printf 'disabled control did not mark transport configuration artifacts not applicable\n' >&2
    return 1
  }
  jq -e '.unavailable_dimensions.jni_lookup_latency_percentiles == "not_collected"' \
    "$output/manifest.json" >/dev/null || {
    printf 'manifest misrepresented unavailable benchmark dimensions\n' >&2
    return 1
  }
  jq -e '.workload.traffic_elapsed_overrun_tolerance_seconds == 2' \
    "$output/manifest.json" >/dev/null || {
    printf 'manifest omitted the bounded measurement drain tolerance\n' >&2
    return 1
  }
  jq -e '.schema_version == 4 and
    (.invocation | contains("--process-tree-fd-absolute-max 4096") and
      contains("--process-tree-task-absolute-max 2048") and
      contains("--process-tree-rss-bytes-absolute-max 1073741824") and
      contains("--process-tree-fd-recovery-delta-max 0") and
      contains("--process-tree-task-recovery-delta-max 0") and
      contains("--process-tree-rss-bytes-recovery-delta-max 0")) and
    .measurement_boundary_resource_evidence ==
      "cells/*/cpu-measurement-{baseline,end}/snapshot.json" and
    .program_metrics_diagnostic_evidence ==
      "cells/*/program-metrics-{baseline,end}/snapshot.json" and
    .process_tree_resource_evidence == {
      artifacts: "cells/*/{resources-before,cpu-measurement-baseline,measurements/rep-*-midpoint,cpu-measurement-end,resources-after-load,resources-idle-recovery-01,resources-idle-recovery-02}/*-cgroup-v2.json",
      services: ["obi", "java-backend"],
      scope: "complete_leaf_cgroup_v2_process_tree",
      sampling: "stable_two_pass_roster_and_conservative_resource_envelope",
      recovery_schedule: "cells/*/recovery-schedule.json"
    } and
    .dedicated_application_cpu_evidence == {
      artifacts: "cells/*/cpu-measurement-{baseline,end}/*-cgroup-v2.json",
      baseline_cell: "bridge-disabled",
      comparison_cells: ["getsockopt-hit", "unix-hit", "getsockopt-w3c"],
      dimensions: ["obi", "java_backend", "combined"],
      metric: "cgroup_v2_cpu_stat_usage_usec_per_successful_request",
      maximum_regression_percent: 10,
      arithmetic: "exact_unsigned_decimal_cross_multiplication",
      primary_cgroupsockopt_program_cpu: "not_collected"
    } and
    .exact_owned_cgroup_sockopt_program_evidence == {
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
    } and
    .workload.w3c_headers == false and
    .workload.w3c_headers_by_cell == {
      "uninstrumented": false,
      "bridge-disabled": false,
      "getsockopt-hit": false,
      "unix-hit": false,
      "getsockopt-w3c": true,
      "getsockopt-helper-idle": false
    } and
    .workload.w3c_discard_cells == ["getsockopt-w3c"] and
    .workload.by_cell["getsockopt-helper-idle"] == {
      base_url: "https://127.0.0.1:18443",
      path: "/api/echo?delay_ms=150",
      connection_mode: "close",
      ca_file: "/benchmark-ca.crt",
      tls_verification: "verified_ca_file",
      upstream_handoff: "none",
      w3c_headers: false,
      helper_idle_direct_java: true,
      state_map_absence_proof: false
    }' \
    "$output/manifest.json" >/dev/null || {
    printf 'manifest omitted the authoritative cell-specific W3C traffic contract\n' >&2
    return 1
  }
  jq -e '.invocation | contains("--agent splunk")' "$output/manifest.json" >/dev/null || {
    printf 'manifest omitted the shell-escaped benchmark invocation\n' >&2
    return 1
  }
  grep -Fq -- '--w3c=false' "$docker_log" &&
    grep -Fq -- '--w3c=true' "$docker_log" &&
    grep -Fq -- '--connection-mode close' "$docker_log" &&
    grep -Fq -- '--seed 0' "$docker_log" || {
    printf 'hermetic run did not preserve the controlled sustained client contract\n' >&2
    return 1
  }
  [[ "$(grep -Fc -- '--base-url https://127.0.0.1:18443' "$docker_log")" == 6 &&
    "$(grep -Fc -- '--ca-file /benchmark-ca.crt' "$docker_log")" == 6 &&
    "$(grep -Fc -- '--ca-file' "$docker_log")" == 6 ]] || {
    printf 'helper-idle did not confine verified-CA direct HTTPS arguments to its six client runs\n' >&2
    return 1
  }
  [[ "$(grep -Fc -- 'exec aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa cat /run/obi-demo/certs/ca.crt' "$docker_log")" == 6 ]] || {
    printf 'hermetic run did not retrieve one verified public CA per cell\n' >&2
    return 1
  }
  [[ "$(grep -Fc 'java-runtime benchmark ' "$runner_log")" == 6 ]] || {
    printf 'core cells did not exclusively select the benchmark JDK runtime\n' >&2
    return 1
  }
  [[ ! -e "$bootstrap_jfr_file" && ! -L "$bootstrap_jfr_file" ]] || {
    printf 'core cells left the bounded bootstrap JFR behind\n' >&2
    return 1
  }
  mkdir -- "$mutation_root"
  for boundary in "${java_mutations[@]}"; do
    assert_java_measurement_mutation_rejected \
      "$output/cells/getsockopt-hit/java-measurement" \
      "$mutation_root/$boundary" "$boundary" || return 1
  done
  assert_java_direct_buffer_reclamation_is_retained \
    "$output/cells/getsockopt-hit/java-measurement" \
    "$mutation_root/direct-reclamation-retained" || return 1
  assert_java_publication_receipt_mutations_rejected "$output" || return 1
  assert_mixed_java_runtime_artifact_identity_rejected "$output" || return 1
  ! grep -Fq down "$docker_log" || {
    printf 'hermetic run issued a raw Compose down\n' >&2
    return 1
  }
}

test_complete_mode_fake_run_publishes_resolvable_bounded_evidence() {
  local -r fake_root="$TEST_TMP_DIR/fake-complete-root"
  local -r fake_example="$fake_root/examples/apache-java-https"
  local -r agent_directory="$fake_root/pkg/internal/java/agent"
  local -r fake_bin="$TEST_TMP_DIR/fake-complete-bin"
  local -r output_parent="$TEST_TMP_DIR/fake-complete-output"
  local -r output_name='artifacts-$(shell printf INJECTED >&2)'
  local -r output="$output_parent/$output_name"
  local -r runner_log="$TEST_TMP_DIR/fake-complete-runner.log"
  local -r docker_log="$TEST_TMP_DIR/fake-complete-docker.log"
  local -r events="$TEST_TMP_DIR/fake-complete-events.log"
  local -r diagnostics="$TEST_TMP_DIR/fake-complete-diagnostics.txt"
  local -r bpf_metrics="$TEST_TMP_DIR/fake-complete-bpf-metrics.txt"
  local -r compose_project="$TEST_TMP_DIR/fake-complete-compose-project.txt"
  local -r results_root="$fake_example/.runtime/results"
  local -r compiler="$TEST_TMP_DIR/fake-native-compiler"
  local -r compiler_log="$TEST_TMP_DIR/fake-native-compiler.log"
  local -r binary_template="$TEST_TMP_DIR/fake-native-binary"
  local -r runtime_log="$TEST_TMP_DIR/fake-native-runtime.log"
  local -r docker_socket="$TEST_TMP_DIR/fake-complete-docker.sock"
  local -r source_tree_manifest="$TEST_TMP_DIR/fake-complete-source-tree.manifest"
  local -r java_measurement_state="$TEST_TMP_DIR/fake-complete-java-measurement-state.txt"
  local -r clock_file="$TEST_TMP_DIR/fake-complete-clock.txt"
  local -r bootstrap_jfr_file="$TEST_TMP_DIR/fake-complete-bootstrap.jfr"
  local -r jfr_file="$TEST_TMP_DIR/fake-complete-measurement.jfr"
  local -r runtime_helper_jar="$fake_example/java/benchmark/fake-helper.jar"
  # Exercise publication with a supported capacity that differs from the default fixture.
  local -r pressure_max_entries="${FAKE_PRESSURE_MAP_MAX_ENTRIES_OVERRIDE:-20000}"
  local revision=""
  local git_tree=""
  local command_name=""

  mkdir -p -- "$fake_example/scripts" "$fake_example/java/benchmark" \
    "$agent_directory/src/main/c" "$agent_directory/src/test/c" \
    "$fake_bin" "$output_parent" "$fake_example/.runtime"
  chmod 0755 -- "$fake_example/.runtime"
  install --mode=0755 "$TEST_SCRIPT_DIR/benchmark.sh" "$fake_example/scripts/benchmark.sh"
  install --mode=0644 "$TEST_SCRIPT_DIR/../java/benchmark/RuntimeSnapshot.java" \
    "$fake_example/java/benchmark/RuntimeSnapshot.java"
  install --mode=0644 "$TEST_SCRIPT_DIR/../java/benchmark/obi-benchmark.jfc" \
    "$fake_example/java/benchmark/obi-benchmark.jfc"
  printf 'fake deterministic helper jar\n' >"$runtime_helper_jar"
  ln -s -- "$TEST_SOURCE" "$fake_example/run.sh"
  printf 'services: {}\n' >"$fake_example/docker-compose.yml"
  printf '%s\n' \
    'FROM maven:fixture@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc AS builder' \
    >"$fake_example/java/Dockerfile"
  {
    printf 'CC ?= cc\n'
    printf 'CFLAGS = -fPIC -O2 -Wall -Wextra -Wno-unused-parameter -pthread\n'
    printf 'LDFLAGS = -pthread\n'
    printf 'BENCHMARK_TARGET = $(BUILD_DIR)/remote_parent_jni_benchmark\n'
    printf '.PHONY: benchmark\n'
    printf 'benchmark: CFLAGS += -DOBI_JNI_TESTING\n'
    printf 'benchmark:\n'
    printf '\t$(CC) $(CFLAGS) -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux src/main/c/io_opentelemetry_obi_java_jni.c src/test/c/remote_parent_jni_benchmark.c $(LDFLAGS) -o $(BENCHMARK_TARGET)\n'
    printf '\t$(BENCHMARK_TARGET) $(BENCHMARK_ITERATIONS)\n'
  } >"$agent_directory/Makefile.jni"
  printf '/* fixture production source */\n' \
    >"$agent_directory/src/main/c/io_opentelemetry_obi_java_jni.c"
  printf '/* fixture benchmark source */\n' \
    >"$agent_directory/src/test/c/remote_parent_jni_benchmark.c"
  printf 'examples/apache-java-https/.runtime/\n' >"$fake_root/.gitignore"
  {
    printf '#!/bin/sh\n'
    printf '/usr/bin/env | /usr/bin/sort >%q\n' "$runtime_log"
    printf 'printf "%%s\\n" %q\n' \
      'benchmark=obi_java_remote_parent_native getsockopt_backend=deterministic_syscall_shim'
    printf 'printf "%%s\\n" %q\n' \
      'transport=getsockopt outcome=hit warmup_iterations=1000 iterations=10000 elapsed_ns=100000 ns_per_op=10.00 p50_ns=10 p95_ns=20 p99_ns=30 ops_per_second=100000000.00 status=1 checksum=10000'
    printf 'printf "%%s\\n" %q\n' \
      'transport=getsockopt outcome=miss warmup_iterations=1000 iterations=10000 elapsed_ns=110000 ns_per_op=11.00 p50_ns=11 p95_ns=21 p99_ns=31 ops_per_second=90909090.91 status=2 checksum=20000'
    printf 'printf "%%s\\n" %q\n' \
      'transport=getsockopt outcome=failure warmup_iterations=1000 iterations=10000 elapsed_ns=120000 ns_per_op=12.00 p50_ns=12 p95_ns=22 p99_ns=32 ops_per_second=83333333.33 status=12 checksum=120000'
    printf 'printf "%%s\\n" %q\n' \
      'transport=unix outcome=hit warmup_iterations=1000 iterations=10000 elapsed_ns=200000 ns_per_op=20.00 p50_ns=20 p95_ns=30 p99_ns=40 ops_per_second=50000000.00 status=1 checksum=10000'
    printf 'printf "%%s\\n" %q\n' \
      'transport=unix outcome=miss warmup_iterations=1000 iterations=10000 elapsed_ns=210000 ns_per_op=21.00 p50_ns=21 p95_ns=31 p99_ns=41 ops_per_second=47619047.62 status=2 checksum=20000'
    printf 'printf "%%s\\n" %q\n' \
      'transport=unix outcome=failure warmup_iterations=1000 iterations=10000 elapsed_ns=220000 ns_per_op=22.00 p50_ns=22 p95_ns=32 p99_ns=42 ops_per_second=45454545.45 status=12 checksum=120000'
  } >"$binary_template"
  chmod 0700 -- "$binary_template"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'if [[ "${1:-}" == --version ]]; then printf "fixture compiler\\n"; exit 0; fi' \
    "printf 'args=' >$(printf '%q' "$compiler_log")" \
    "printf '%q ' \"\$@\" >>$(printf '%q' "$compiler_log")" \
    "printf '\\n' >>$(printf '%q' "$compiler_log")" \
    "/usr/bin/env | /usr/bin/sort >>$(printf '%q' "$compiler_log")" \
    'output=""' \
    'while (($# > 0)); do if [[ "$1" == -o ]]; then output="$2"; shift 2; else shift; fi; done' \
    '[[ "$output" == /* ]]' \
    "/usr/bin/install -m 0700 -- $(printf '%q' "$binary_template") \"\$output\"" \
    >"$compiler"
  chmod 0700 -- "$compiler"
  git -C "$fake_root" init --quiet
  git -C "$fake_root" config user.email benchmark@example.invalid
  git -C "$fake_root" config user.name 'Benchmark Test'
  git -C "$fake_root" config commit.gpgsign false
  git -C "$fake_root" add -- .
  git -C "$fake_root" commit --quiet -m fixture
  revision="$(git -C "$fake_root" rev-parse HEAD)" || return 1
  git_tree="$(git -C "$fake_root" rev-parse "$revision^{tree}")" || return 1
  resolve_benchmark_identity_tools
  write_git_tree_manifest_for_tree \
    "$fake_root" "$git_tree" "$source_tree_manifest" || return 1
  create_unix_socket_fixture "$docker_socket"
  for command_name in docker curl sleep git; do
    ln -s -- "$TEST_SOURCE" "$fake_bin/$command_name"
  done
  printf '0 0 0\n' >"$diagnostics"
  printf '0 0 0 0 0 0 0 0 0 0 0\n' >"$bpf_metrics"
  printf 'pre\n' >"$java_measurement_state"
  printf '1000 1000000\n' >"$clock_file"
  printf 'FLR-fake-bounded-private-recording\n' >"$jfr_file"
  if ! PATH="$fake_bin:$PATH" \
    CC="$compiler" \
    MAKEFILES="$TEST_TMP_DIR/nonexistent-hostile.mk" \
    MAKEFLAGS='CFLAGS=-DINJECTED' \
    GNUMAKEFLAGS='CFLAGS=-DGNU_INJECTED' \
    CPATH="$TEST_TMP_DIR/hostile-cpath" \
    C_INCLUDE_PATH="$TEST_TMP_DIR/hostile-include" \
    COMPILER_PATH="$TEST_TMP_DIR/hostile-compiler-path" \
    GCC_EXEC_PREFIX="$TEST_TMP_DIR/hostile-gcc-prefix" \
    LIBRARY_PATH="$TEST_TMP_DIR/hostile-library-path" \
    FAKE_CONTAINER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    FAKE_BPF_METRICS_FILE="$bpf_metrics" \
    FAKE_COMPOSE_PROJECT_FILE="$compose_project" \
    FAKE_DOCKER_LOG="$docker_log" \
    FAKE_DIAGNOSTICS_FILE="$diagnostics" \
    FAKE_DOCKER_ENDPOINT="unix://$docker_socket" \
    FAKE_EVENTS="$events" \
    FAKE_GIT_REVISION="$revision" \
    FAKE_BOOTSTRAP_JFR_FILE="$bootstrap_jfr_file" \
    FAKE_CLOCK_FILE="$clock_file" \
    FAKE_JAVA_MEASUREMENT_STATE_FILE="$java_measurement_state" \
    FAKE_JFR_FILE="$jfr_file" \
    FAKE_RUNTIME_HELPER_JAR_FILE="$runtime_helper_jar" \
    FAKE_RUNTIME_HELPER_SOURCE_FILE="$fake_example/java/benchmark/RuntimeSnapshot.java" \
    FAKE_RUNTIME_JFR_SETTINGS_FILE="$fake_example/java/benchmark/obi-benchmark.jfc" \
    FAKE_PRESSURE_MAP_MAX_ENTRIES_OVERRIDE="$pressure_max_entries" \
    FAKE_PID="$$" \
    FAKE_RESULTS_ROOT="$results_root" \
    FAKE_RUNNER_LOG="$runner_log" \
    FAKE_SOURCE_TREE_MANIFEST="$source_tree_manifest" \
    FAKE_TLS_PROTOCOL=TLSv1.2 \
    run_benchmark_with_fake_bound_proc "$fake_example/scripts/benchmark.sh" \
      --output "$output" --agent splunk --tls TLSv1.2 \
      --warmup-seconds 2 --duration-seconds 2 --concurrency 1 \
      --repetitions 5 --seed 17 --cells complete \
      "${VALID_PROCESS_TREE_CAP_ARGS[@]}"; then
    printf 'fake complete-mode benchmark run failed\n' >&2
    return 1
  fi
  jq -e '
    .status == "passed" and .acceptance_evidence == false and
    (.bounded_path_cells | map(.cell)) == [
      "getsockopt-stale", "unix-stale", "unix-timeout", "getsockopt-pressure"
    ] and all(.bounded_path_cells[]; .status == "passed") and
    .lookup_paths == {status: "available", path: "lookup-paths.json"} and
    .native_jni_lookup == {status: "available", path: "native-jni/benchmark.json"} and
    .docker_daemon == {status: "verified_local_unix_socket_endpoint_only", path: "docker-daemon.json"} and
    (.application_source |
      .status == "clean_and_stable" and
      .path == "application-source-identity.json" and
      (.revision | test("^[0-9a-f]{40}$")) and
      (.git_tree | test("^[0-9a-f]{40}$")) and
      (.source_tree_sha256 | test("^[0-9a-f]{64}$"))) and
    .source_authority.checkouts[0].source_tree_sha256 ==
      .application_source.source_tree_sha256 and
    .measurement_scope.pressure_map_occupancy_and_capacity_rejection ==
      "bounded_correctness_observed_once" and
    .measurement_scope.jfr_nmt_allocation_native_direct_memory.status == "available" and
    .measurement_scope.jfr_nmt_allocation_native_direct_memory.retained_cell_artifacts == 6 and
    .measurement_scope.jfr_nmt_allocation_native_direct_memory.acceptance_evidence == false
  ' "$output/summary.json" >/dev/null || {
    printf 'complete fake run did not publish bounded evidence honestly\n' >&2
    return 1
  }
  validate_lookup_path_summary_schema \
    "$output/lookup-paths.json" "$fake_root" || return 1
  [[ -f "$output/cells/getsockopt-pressure/preflight/runner/map-pressure-pressure-container-inspections.json" &&
    ! -L "$output/cells/getsockopt-pressure/preflight/runner/map-pressure-pressure-container-inspections.json" &&
    "$(stat -Lc '%a' -- "$output/cells/getsockopt-pressure/preflight/runner/map-pressure-pressure-container-inspections.json")" == 600 ]] || {
    printf 'complete fake run did not privately retain the exact pressure container inspection artifact\n' >&2
    return 1
  }
  jq -e '
    .retained_files |
    index("map-pressure-pressure-container-inspections.json") != null
  ' "$output/cells/getsockopt-pressure/preflight/runner/provenance.json" \
    >/dev/null || {
    printf 'pressure runner provenance omitted the private inspection artifact\n' >&2
    return 1
  }
  if grep -Eq \
    'map-pressure-pressure-container-inspections\.json|0123456789abcdef0123456789abcdef|\.pressure-control\.0123456789abcdef0123456789abcdef|cdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdefcdef' \
    "$output/lookup-paths.json" \
    "$output/cells/getsockopt-pressure/path-observation.json"; then
    printf 'normalized pressure observations disclosed private container inspection data\n' >&2
    return 1
  fi
  validate_native_jni_benchmark_schema "$output/native-jni/benchmark.json" || return 1
  validate_application_source_identity_schema \
    "$output/application-source-identity.json" "$fake_root" || return 1
  jq -e '.cells_mode == "complete" and (.cells | length) == 10 and
    (.cells | map(.cell))[-4:] == [
      "getsockopt-stale", "unix-stale", "unix-timeout", "getsockopt-pressure"
    ]' "$output/application-source-identity.json" >/dev/null || return 1
  jq -e \
    --argjson pressure_max_entries "$pressure_max_entries" '
    (.paths | length) == 6 and
    all(.paths[];
      (.source_artifact | test("^cells/[^/]+/path-observation\\.json$")) and
      (.link_base | test("^cells/[^/]+/$")) and
      .observation.observation.mode == "bounded_correctness_observed_once") and
    .native_lookup_benchmark.source_artifact == "native-jni/benchmark.json" and
    .provenance == {
      application_source_identity: "application-source-identity.json",
      capture_scope: "single_harness_run_with_verified_unix_socket_and_per_sample_container_process_binding",
      docker_daemon: "docker-daemon.json",
      host_environment: "host-environment.txt"
    } and
    (.paths[] | select(.observation.cell == "getsockopt-pressure") |
      .observation.pressure |
      .map_id == 41 and .kernel_map_name == "java_remote_par" and
      .pressure_contract_version == 2 and
      .barrier_schema == "pressure-traffic-barrier-v2" and
      .exact_hit_count == 126 and .explicit_root_count == 1 and
      .w3c_parent_count == 1 and .retrieval_valid_count == 127 and
      .attributable_failure_count == 1 and .w3c_masked_valid_count == 1 and
      .take_valid_count == 127 and .take_sampled_count == 127 and
      .take_unsampled_count == 0 and .discard_standard_count == 1 and
      .attributable_absence_count == 1 and .diagnostic_self_miss_count == 1 and
      .synthetic_pid == 0 and
      .synthetic_namespace == 0 and .occupancy_before_fill == 0 and
      .touched_entries == $pressure_max_entries and
      .fill_verified_present_entries == $pressure_max_entries and
      .post_traffic_verified_present_entries == $pressure_max_entries and
      .content_sha256 == .post_traffic_content_sha256 and
      .handoff_admission_overload_count == 5 and
      .handoff_admission_ambiguous_count == 0 and
      .handoff_admission_maximum_count == 1152 and
      .occupancy_recovery_samples == [0, 0] and .occupancy_recovered == 0 and
      .recovery_samples == 2 and .recovery_log_attempts == 2)
  ' "$output/lookup-paths.json" >/dev/null || return 1
  jq -e '.status == "clean_and_stable" and
    .captures == {before: "source-state-before.json", after: "source-state-after.json"}' \
    "$output/native-jni/source-state.json" >/dev/null || return 1
  [[ "$(grep -Fc cleanup "$events")" == 10 &&
    -f "$output/cells/getsockopt-hit/path-observation.json" &&
    -f "$output/cells/unix-hit/path-observation.json" &&
    ! -e "$agent_directory/INJECTED" ]] || return 1
  [[ "$(grep -Fc 'java-runtime benchmark ' "$runner_log")" == 6 &&
    "$(grep -Fc 'java-runtime default ' "$runner_log")" == 4 ]] || {
    printf 'complete mode did not confine benchmark JVM tooling to core cells\n' >&2
    return 1
  }
  [[ ! -e "$bootstrap_jfr_file" && ! -L "$bootstrap_jfr_file" ]] || {
    printf 'complete mode left the bounded bootstrap JFR behind\n' >&2
    return 1
  }
  ! grep -R -Fq -- 'CFLAGS=-DINJECTED' "$output/native-jni" &&
    ! grep -R -Fq -- 'printf INJECTED' "$output/native-jni" &&
    grep -Fq -- '-DOBI_JNI_TESTING' "$compiler_log" &&
    ! grep -Eq '^(CPATH|C_INCLUDE_PATH|COMPILER_PATH|GCC_EXEC_PREFIX|LIBRARY_PATH|LD_LIBRARY_PATH|LD_PRELOAD)=' \
      "$compiler_log" &&
    ! grep -Eq '^(CPATH|C_INCLUDE_PATH|COMPILER_PATH|GCC_EXEC_PREFIX|LIBRARY_PATH|LD_LIBRARY_PATH|LD_PRELOAD)=' \
      "$runtime_log" &&
    ! grep -Fq -- INJECTED "$runtime_log" || {
    printf 'complete fake run leaked hostile path or compiler environment input\n' >&2
    return 1
  }
}

main() {
  TEST_TMP_DIR="$(mktemp -d)"
  prepare_fake_ca
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "terminal-native-inherited-alarm" ]]; then
    run_terminal_native_inherited_blocked_alarm_fixture
    printf 'benchmark.sh inherited blocked-ALRM normalization test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "terminal-native-signal" ]]; then
    test_terminal_native_perl_reaps_active_git_child_on_signal
    printf 'benchmark.sh terminal native Git signal-mask test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "pressure-contract-v2" ]]; then
    test_bounded_paths_are_correctness_observations_not_performance_samples
    test_pressure_recovery_evidence_parses_canonical_samples_and_log
    test_pressure_capacity_is_live_bounded_and_exactly_reconciled
    test_pressure_contract_v2_raw_artifacts_are_exact_and_cross_bound
    test_pressure_consumer_source_preserves_full_hash_contract_literals
    printf 'benchmark.sh pressure contract v2 consumer tests passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "terminal-source-authority" ]]; then
    test_trusted_native_tool_resolution_is_function_and_loader_immune
    test_make_compiler_resolution_honors_and_pins_inherited_cc
    test_terminal_source_authority_protocol_is_bounded_and_held
    test_terminal_native_perl_reaps_active_git_child_on_signal
    test_pressure_recovery_evidence_parses_canonical_samples_and_log
    test_pressure_capacity_is_live_bounded_and_exactly_reconciled
    printf 'benchmark.sh terminal source authority protocol test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "midpoint-publication" ]]; then
    test_scheduled_midpoint_failure_cleanup_and_post_capture_liveness
    printf 'benchmark.sh coherent midpoint publication test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "cpu-resources" ]]; then
    test_bound_cgroup_v2_process_tree_is_complete_bounded_and_fail_closed
    test_process_tree_caps_cover_every_boundary_and_both_recoveries
    test_application_cpu_gate_uses_exact_service_and_combined_cross_products
    test_application_resource_gates_project_unavailable_cgroup_snapshots
    test_diagnostics_suppression_is_scheduled_midpoint_only
    test_scheduled_midpoint_failure_cleanup_and_post_capture_liveness
    test_ordered_idle_recovery_is_exactly_two_serial_thirty_second_samples
    test_publish_once_json_images_and_terminal_receipts_fail_closed
    test_held_json_images_close_all_four_source_aba_chains
    test_on_exit_does_not_replace_partial_terminal_publication
    printf '%s\n' \
      'benchmark.sh CPU/resource tests passed: cgroup-v2 tree; boundary/recovery caps; exact CPU; diagnostics suppression; midpoint lifecycle; ordered recovery; held JSON; publish-once receipts'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "json-publication" ]]; then
    test_terminal_source_authority_protocol_is_bounded_and_held
    test_summary_publishes_completion_marker_last
    test_publish_once_json_images_and_terminal_receipts_fail_closed
    test_held_json_images_close_all_four_source_aba_chains
    test_on_exit_does_not_replace_partial_terminal_publication
    printf 'benchmark.sh immutable JSON publication tests passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "core-mode" ]]; then
    test_java_benchmark_tooling_is_opt_in_and_payload_bounded
    test_runtime_snapshot_source_and_jfc_are_exact_authorities
    test_java_tree_traversal_and_publication_identity_fail_closed
    test_java_publication_substitution_is_quarantined
    test_java_measurement_failure_classification_is_exact
    test_java_measurement_partial_cleanup_is_identity_safe
    test_helper_idle_sustained_rejects_delayed_post_workload_lifecycle
    test_main_uses_runner_cleanup_and_retains_core_artifacts
    printf 'benchmark.sh core-mode test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "benchmark-repairs" ]]; then
    test_java_benchmark_tooling_is_opt_in_and_payload_bounded
    test_runtime_snapshot_source_and_jfc_are_exact_authorities
    test_java_tree_traversal_and_publication_identity_fail_closed
    test_java_publication_substitution_is_quarantined
    test_java_measurement_failure_classification_is_exact
    printf 'benchmark.sh focused repair tests passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "complete-mode" ]]; then
    test_complete_mode_fake_run_publishes_resolvable_bounded_evidence
    printf 'benchmark.sh complete-mode test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "terminal-poc-receipt" ]]; then
    test_terminal_source_authority_protocol_is_bounded_and_held
    test_terminal_poc_publication_revalidates_sampled_allocation_receipts
    printf 'benchmark.sh terminal PoC receipt revalidation test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "benchmark-variability" ]]; then
    test_complete_manifest_links_bounded_artifacts_and_scopes
    test_variance_summary_records_ordered_per_cell_statistics
    test_variance_summary_rejects_invalid_repetition_sets
    test_predeclared_poc_gate_stays_partial_and_evaluates_supported_dimensions
    test_terminal_poc_publication_revalidates_sampled_allocation_receipts
    printf 'benchmark.sh variability and sampled-allocation tests passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "council-repairs" ]]; then
    test_java_bridge_program_allowlist_matches_source
    test_docker_daemon_locality_is_verified_before_execution
    test_manifest_bootstrap_survives_second_locality_query_failure
    test_benchmark_documentation_binds_partial_status_to_mralias_issue
    test_proc_snapshot_requires_container_starttime_and_cgroup_identity
    test_bounded_path_cell_mapping_is_exact
    test_pressure_recovery_evidence_parses_canonical_samples_and_log
    test_pressure_capacity_is_live_bounded_and_exactly_reconciled
    test_application_source_identity_is_exact_across_core_and_complete_cells
    test_application_source_identity_rejects_coordinated_manifest_forgery
    test_variance_summary_records_ordered_per_cell_statistics
    test_variance_summary_rejects_invalid_repetition_sets
    test_predeclared_poc_gate_stays_partial_and_evaluates_supported_dimensions
    test_terminal_poc_publication_revalidates_sampled_allocation_receipts
    printf 'benchmark.sh council repair tests passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "resource-ownership" ]]; then
    test_java_bridge_program_allowlist_matches_source
    test_bpf_fd_ownership_requires_bound_stable_proc_identity
    test_resource_growth_observations_fail_closed
    test_obi_metrics_capture_cleans_partial_after_stat_failure
    printf 'benchmark.sh resource ownership tests passed\n'
    return 0
  fi
  test_parser_defaults_and_boundaries
  test_trusted_native_tool_resolution_is_function_and_loader_immune
  test_terminal_source_authority_protocol_is_bounded_and_held
  test_terminal_native_perl_reaps_active_git_child_on_signal
  test_java_benchmark_tooling_is_opt_in_and_payload_bounded
  test_runtime_snapshot_source_and_jfc_are_exact_authorities
  test_java_tree_traversal_and_publication_identity_fail_closed
  test_java_publication_substitution_is_quarantined
  test_java_measurement_failure_classification_is_exact
  test_java_bridge_program_allowlist_matches_source
  test_lifecycle_tool_paths_must_be_absolute_regular
  test_lifecycle_tool_resolution_rejects_relative_paths
  test_dependency_check_reports_only_invalid_lifecycle_tool
  test_dependency_check_reports_invalid_lifecycle_tool_under_errexit
  test_docker_daemon_locality_is_verified_before_execution
  test_manifest_bootstrap_survives_second_locality_query_failure
  test_benchmark_documentation_binds_partial_status_to_mralias_issue
  test_proc_snapshot_requires_container_starttime_and_cgroup_identity
  test_bpf_fd_ownership_requires_bound_stable_proc_identity
  test_make_compiler_resolution_honors_and_pins_inherited_cc
  test_native_make_environment_and_staging_are_hermetic
  test_native_source_state_rejects_dirty_and_mutating_inputs
  test_output_directory_is_absolute_fresh_private
  test_core_cell_mapping_is_exact
  test_bounded_path_cell_mapping_is_exact
  test_core_mode_does_not_publish_complete_only_path_observations
  test_bounded_paths_are_correctness_observations_not_performance_samples
  test_pressure_recovery_evidence_parses_canonical_samples_and_log
  test_pressure_capacity_is_live_bounded_and_exactly_reconciled
  test_pressure_contract_v2_raw_artifacts_are_exact_and_cross_bound
  test_pressure_consumer_source_preserves_full_hash_contract_literals
  test_lookup_coverage_uses_observed_once_vocabulary
  test_application_source_identity_is_exact_across_core_and_complete_cells
  test_application_source_identity_rejects_coordinated_manifest_forgery
  test_native_jni_benchmark_normalization_is_strict
  test_complete_manifest_links_bounded_artifacts_and_scopes
  test_json_validators_require_one_document
  test_variance_summary_records_ordered_per_cell_statistics
  test_variance_summary_rejects_invalid_repetition_sets
  test_resource_growth_observations_fail_closed
  test_bound_cgroup_v2_process_tree_is_complete_bounded_and_fail_closed
  test_process_tree_caps_cover_every_boundary_and_both_recoveries
  test_application_cpu_gate_uses_exact_service_and_combined_cross_products
  test_application_resource_gates_project_unavailable_cgroup_snapshots
  test_predeclared_poc_gate_stays_partial_and_evaluates_supported_dimensions
  test_terminal_poc_publication_revalidates_sampled_allocation_receipts
  test_summary_resource_scope_is_independent_of_nonresource_failures
  test_failed_complete_summary_reports_requested_artifact_state
  test_summary_rejects_invalid_variance_after_failure
  test_failed_summary_refuses_unremovable_variance
  test_on_exit_rewrites_failed_summary_after_passed_summary_error
  test_summary_rejects_manifest_render_failure
  test_summary_publishes_completion_marker_last
  test_publish_once_json_images_and_terminal_receipts_fail_closed
  test_held_json_images_close_all_four_source_aba_chains
  test_on_exit_does_not_replace_partial_terminal_publication
  test_w3c_discard_diagnostics_require_exact_delta
  test_helper_idle_java_diagnostics_require_exact_correction
  test_diagnostics_suppression_is_scheduled_midpoint_only
  test_scheduled_midpoint_failure_cleanup_and_post_capture_liveness
  test_ordered_idle_recovery_is_exactly_two_serial_thirty_second_samples
  test_helper_idle_bpf_metrics_require_constrained_deltas
  test_obi_metrics_capture_cleans_partial_after_stat_failure
  test_helper_idle_bpf_fence_requires_two_post_boundary_passes
  test_helper_idle_sustained_rejects_delayed_post_workload_lifecycle
  test_runner_environment_contract_is_exact
  test_failed_measurement_clears_reaped_pid
  test_invalid_benchmark_result_is_not_published_or_retained
  test_benchmark_abort_discard_is_exact_and_fail_closed
  test_java_measurement_partial_cleanup_is_identity_safe
  test_interrupted_measurement_reaps_client_tree
  test_wait_reaps_client_group_after_leader_exit
  test_failed_identity_capture_reaps_client_group
  test_stale_client_identity_never_signals_unrelated_process
  test_pending_identity_never_signals_mismatched_live_job
  test_pending_identity_rejects_reused_session_promotion
  test_missing_runner_provenance_is_rejected
  test_benchmark_ca_rejects_untrusted_inputs
  test_main_uses_runner_cleanup_and_retains_core_artifacts
  test_complete_mode_fake_run_publishes_resolvable_bounded_evidence
  printf 'benchmark.sh tests passed\n'
}

main "$@"
