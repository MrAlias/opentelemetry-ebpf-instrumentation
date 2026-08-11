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
readonly FAKE_REQUEST_LIMIT=1000000
readonly FAKE_SUSTAINED_LOAD_SEED=0
readonly FAKE_WORKLOAD_BASE_URL="http://127.0.0.1:18080"
readonly FAKE_WORKLOAD_PATH="/api/echo?delay_ms=150"
readonly FAKE_WORKLOAD_CONNECTION_MODE="close"
readonly FAKE_DIRECT_JAVA_WORKLOAD_BASE_URL="https://127.0.0.1:18443"
readonly FAKE_DIRECT_JAVA_WORKLOAD_CA_FILE="/benchmark-ca.crt"
readonly FAKE_REQUEST_TIMEOUT_SECONDS=10
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

fake_bpf_metrics_increment() {
  local -r report_increment="$1"
  local -r candidate_increment="${2:-0}"
  local -r inject_increment="${3:-0}"
  local -r stage_increment="${4:-0}"
  local -r handoff_increment="${5:-0}"
  local -r take_increment="${6:-0}"
  local -r discard_increment="${7:-0}"
  local -r negotiate_missing_increment="${8:-0}"
  local report=""
  local candidate=""
  local inject=""
  local stage=""
  local handoff=""
  local take=""
  local discard=""
  local negotiate_missing=""
  local extra=""

  [[ -n "${FAKE_BPF_METRICS_FILE:-}" && -f "$FAKE_BPF_METRICS_FILE" ]] || return 64
  read -r report candidate inject stage handoff take discard negotiate_missing extra <"$FAKE_BPF_METRICS_FILE" || return 64
  [[ "$report" =~ ^[0-9]+$ && "$candidate" =~ ^[0-9]+$ && "$inject" =~ ^[0-9]+$ &&
    "$stage" =~ ^[0-9]+$ && "$handoff" =~ ^[0-9]+$ && "$take" =~ ^[0-9]+$ &&
    "$discard" =~ ^[0-9]+$ && "$negotiate_missing" =~ ^[0-9]+$ && -z "$extra" ]] || return 64
  printf '%s %s %s %s %s %s %s %s\n' \
    "$((report + report_increment))" \
    "$((candidate + candidate_increment))" \
    "$((inject + inject_increment))" \
    "$((stage + stage_increment))" \
    "$((handoff + handoff_increment))" \
    "$((take + take_increment))" \
    "$((discard + discard_increment))" \
    "$((negotiate_missing + negotiate_missing_increment))" \
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
  local extra=""
  local map_entries=1
  local map_max_entries=10000
  local project=""

  [[ -n "${FAKE_BPF_METRICS_FILE:-}" && -f "$FAKE_BPF_METRICS_FILE" ]] || return 64
  read -r report candidate inject stage handoff take discard negotiate_missing extra <"$FAKE_BPF_METRICS_FILE" || return 64
  [[ "$report" =~ ^[0-9]+$ && "$candidate" =~ ^[0-9]+$ && "$inject" =~ ^[0-9]+$ &&
    "$stage" =~ ^[0-9]+$ && "$handoff" =~ ^[0-9]+$ && "$take" =~ ^[0-9]+$ &&
    "$discard" =~ ^[0-9]+$ && "$negotiate_missing" =~ ^[0-9]+$ && -z "$extra" ]] || return 64
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
  local -r max_entries="${3:-50000}"

  {
    printf '%s %s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}' \
      "$map_entries_count"
    printf '%s %s\n' \
      'obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"}' \
      "$max_entries"
  } >"$output"
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
      jq '.pressure_correlation = {
        exact_hit_count: 127, explicit_root_count: 1,
        wrong_parent_count: 0, unresolved_count: 0
      }' "$result_directory/scenario-pressure.json" \
        >"$result_directory/scenario-pressure.json.tmp"
      mv -T -- "$result_directory/scenario-pressure.json.tmp" \
        "$result_directory/scenario-pressure.json"
      jq '.pressure_correlation = {
        trace: {exact_hit_count: 127, explicit_root_count: 1,
          wrong_parent_count: 0, unresolved_count: 0},
        bridge: {transport: "getsockopt"},
        java_reconciliation_target: {take_valid_count: 127,
          attributable_absence_count: 1, diagnostic_self_miss_count: 1}
      }' "$result_directory/scenario-pressure-status.json" \
        >"$result_directory/scenario-pressure-status.json.tmp"
      mv -T -- "$result_directory/scenario-pressure-status.json.tmp" \
        "$result_directory/scenario-pressure-status.json"
      jq -n '
        {status: "passed", mode: "fill",
         map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
         map_type: "Hash", map_id: 41, max_entries: 50000, touched: 49999,
         capacity_rejected_entries: 1, verified_present_entries: 49999,
         process_map_id: 42, process_pid: 43, process_namespace: 44, token_base: 1}
      ' >"$result_directory/map-pressure-pressure-fill.json"
      jq -n '
        {status: "passed", mode: "cleanup", map_id: 41,
         map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
         map_type: "Hash", max_entries: 50000, process_map_id: 0,
         process_pid: 43, process_namespace: 44, token_base: 1,
         cleanup_verified: true, verified_absent_entries: 50001, touched: 0}
      ' >"$result_directory/map-pressure-pressure-cleanup.json"
      write_pressure_map_metrics_fixture \
        "$result_directory/phases/pressure-before/obi-metrics.prom" 1
      write_pressure_map_metrics_fixture \
        "$result_directory/map-pressure-pressure-pressured.prom" 50000
      write_pressure_map_metrics_fixture \
        "$result_directory/map-pressure-pressure-traffic-complete.prom" 49999
      write_pressure_map_metrics_fixture \
        "$result_directory/map-pressure-pressure-recovered-sample-01.prom" 1
      write_pressure_map_metrics_fixture \
        "$result_directory/map-pressure-pressure-recovered-sample-02.prom" 1
      command cp -- "$result_directory/map-pressure-pressure-recovered-sample-02.prom" \
        "$result_directory/map-pressure-pressure-recovered.prom"
      {
        printf 'attempt=1 observed_at=2026-08-10T00:00:00Z entries=1 matched=true consecutive=1\n'
        printf 'attempt=2 observed_at=2026-08-10T00:00:01Z entries=1 matched=true consecutive=2\n'
      } >"$result_directory/map-pressure-pressure-recovered-samples.log"
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
        "$result_directory/phases/$assertion_scenario-$index/obi-metrics.prom" 1
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
  printf 'benchmark duration=%s concurrency=%s\n' "$duration" "$concurrency" >>"$FAKE_DOCKER_LOG"
  # Give the harness enough real time to verify the dedicated client session.
  /bin/sleep 0.2
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
        throughput_per_second: 4,
        latency: {p50_nanos: 1, p95_nanos: 2, p99_nanos: 3}
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
    [[ "${2:-}" == "$FAKE_CONTAINER_ID" && "${3:-}" == cat &&
      "${4:-}" == /run/obi-demo/certs/ca.crt && $# == 4 &&
      -n "${FAKE_CA_FILE:-}" && -f "$FAKE_CA_FILE" ]] || return 64
    command cat -- "$FAKE_CA_FILE"
    return 0
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
      printf '%s %s %s %s\n' \
        "$FAKE_CONTAINER_ID" "$FAKE_PID" "$project" "acceptance-demo-v1"
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

  for argument in "$@"; do
    case "$argument" in
      http://127.0.0.1:18990/internal/metrics)
        printf '%s\n' obi-metrics >>"$FAKE_EVENTS"
        # Model the periodic BPF stats reader: every completed fake scrape has
        # a new report marker after the counters it published.
        fake_bpf_metrics_increment 1 || return $?
        fake_bpf_metrics_snapshot
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
    if [[ "${1:-}" == 0.1 ]]; then
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
        printf "host_pid=%s\n" "$FAKE_PID"
        printf "proc_start_time=123456\n"
        printf "proc_cgroup_sha256=%064d\n" 0
        printf "proc_cgroup_container_binding=%s\n" \
          "$PROC_CGROUP_CONTAINER_BINDING"
        printf "project=%s\n" "$ACTIVE_PROJECT"
        printf "owner_sentinel=%s\n" "$PROJECT_SENTINEL_VALUE"
      } >"$output"
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
  AGENT=otel
  TLS_PROTOCOL=TLSv1.3
  WARMUP_SECONDS=10
  DURATION_SECONDS=30
  CONCURRENCY=16
  REPETITIONS=5
  SEED=20260721
  CELLS_MODE=core
  RUN_TOKEN=1234567890-12345
  SHOW_HELP=false
  OUTPUT_READY=false
  HARNESS_STATUS=failed
  STARTED_AT=""
  ACTIVE_PROJECT=""
  ACTIVE_CELL_DIR=""
  BENCHMARK_PID=""
  BENCHMARK_IDENTITY=""
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
  unset BENCHMARK_CA_SOURCE
}

expect_parse_failure() {
  if (
    reset_options
    parse_args "$@"
  ) >/dev/null 2>&1; then
    printf 'accepted invalid arguments: %q\n' "$*" >&2
    return 1
  fi
}

test_parser_defaults_and_boundaries() {
  local -r output="$TEST_TMP_DIR/parse-output"

  (
    reset_options
    parse_args --output "$output"
    [[ "$OUTPUT_DIR" == "$output" && "$AGENT" == otel && "$TLS_PROTOCOL" == TLSv1.3 &&
      "$WARMUP_SECONDS" == 10 && "$DURATION_SECONDS" == 30 && "$CONCURRENCY" == 16 &&
      "$REPETITIONS" == 5 && "$SEED" == 20260721 && "$CELLS_MODE" == core ]]
  ) || {
    printf 'default benchmark options changed unexpectedly\n' >&2
    return 1
  }

  (
    reset_options
    parse_args --output "$output" --cells complete
    [[ "$CELLS_MODE" == complete ]]
  ) || {
    printf 'complete benchmark cell set was rejected\n' >&2
    return 1
  }

  (
    reset_options
    parse_args --output "$output" --warmup-seconds 2 --duration-seconds 600 \
      --concurrency 1 --repetitions 5 --seed 0 --cells core
    [[ "$WARMUP_SECONDS" == 2 && "$DURATION_SECONDS" == 600 && "$CONCURRENCY" == 1 &&
      "$REPETITIONS" == 5 && "$SEED" == 0 ]]
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
  expect_parse_failure --output "$output" --seed 9223372036854775808
  expect_parse_failure --output "$output" --duration-seconds 600 --concurrency 256
  expect_parse_failure --output "$output" --cells getsockopt-miss
  expect_parse_failure --output "$output" --agent invalid
  expect_parse_failure --output "$output" --tls invalid
  expect_parse_failure --output "$output" --unknown
  expect_parse_failure --output
  expect_parse_failure --agent otel
  expect_parse_failure --output "$output" --output "$TEST_TMP_DIR/second-output"
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
      --repetitions 5 --seed 17 >/dev/null 2>&1
  status=$?
  set -e
  [[ "$status" != 0 && "$(<"$context_count")" == 2 ]] || {
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

test_make_compiler_resolution_honors_and_pins_inherited_cc() (
  local -r compiler_directory="$TEST_TMP_DIR/compiler-resolution"
  local -r inherited_compiler="$compiler_directory/inherited-cc"
  local -r expanded_command="$compiler_directory/expanded-build-command.txt"
  local default_compiler=""
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
  [[ "$NATIVE_BENCHMARK_COMPILER" == "$(readlink -f -- "$inherited_compiler")" &&
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
  default_compiler="$(readlink -f -- "$(type -P cc)")" || return 1
  [[ "$NATIVE_BENCHMARK_COMPILER" == "$default_compiler" &&
    "$NATIVE_BENCHMARK_COMPILER_SELECTION" == make_default ]] || {
    printf 'compiler resolver did not use the actual Make default CC\n' >&2
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
  local staging=""
  local hostile_output=""
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
  grep -Fq -- "( exec -c $NATIVE_BENCHMARK_ENV_COMMAND -i" "$build_command" &&
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
      pressure='{
        "bounded":true,"exact_hit_count":127,"explicit_root_count":1,
        "wrong_parent_count":0,"unresolved_count":0,"take_valid_count":127,
        "attributable_absence_count":1,
        "map_name":"java_remote_parent_handoff_claims","map_type":"Hash",
        "map_id":41,"kernel_map_name":"java_remote_par","kernel_map_type":"hash",
        "max_entries":50000,"touched_entries":49999,"capacity_rejected_entries":1,
        "verified_present_entries":49999,"cleanup_verified":true,
        "verified_absent_entries":50001,"occupancy_before_fill":1,
        "occupancy_pressured":50000,"occupancy_traffic_complete":49999,
        "occupancy_recovery_samples":[1,1],"occupancy_recovered":1,
        "recovery_log_attempts":2,"recovery_samples":2
      }'
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
  jq '.observation.runner_requested_requests = 127' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'pressure observation accepted the wrong request count\n' >&2
    return 1
  fi
  jq '.pressure.take_valid_count = 126' "$observation" >"$invalid"
  if validate_path_observation_schema "$invalid"; then
    printf 'pressure observation accepted incomplete Java reconciliation\n' >&2
    return 1
  fi
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
  local -r pressured="$runner/map-pressure-pressure-pressured.prom"
  local -r fill="$runner/map-pressure-pressure-fill.json"
  local -r invalid_observation="$root/path-observation.invalid.json"
  local evidence=""
  local canonical_pressure=""

  mkdir -p -- "$root"
  write_path_observation_fixture "$observation" getsockopt-pressure
  materialize_path_observation_sources "$observation"
  evidence="$(pressure_recovery_evidence_json "$runner")" || {
    printf 'production-shaped pressure recovery evidence was rejected\n' >&2
    return 1
  }
  jq -e '
    .map_id == 41 and .kernel_map_name == "java_remote_par" and
    .map_type == "hash" and .max_entries == 50000 and
    .baseline_entries == 1 and .pressured_entries == 50000 and
    .traffic_complete_entries == 49999 and
    .recovery_sample_count == 2 and .recovery_sample_entries == [1, 1] and
    .recovered_entries == 1 and .recovery_log_attempts == 2
  ' <<<"$evidence" >/dev/null || return 1
  validate_pressure_cell_artifacts "$runner" || return 1
  canonical_pressure="$(canonical_pressure_observation_json "$runner")" || return 1
  jq -e --argjson canonical "$canonical_pressure" '.pressure == $canonical' \
    "$observation" >/dev/null || {
    printf 'pressure fixture diverged from the canonical raw evidence builder\n' >&2
    return 1
  }
  validate_path_observation_source_artifacts "$observation" || return 1
  jq '.pressure.occupancy_pressured = 49999' "$observation" >"$invalid_observation"
  validate_path_observation_schema "$invalid_observation" || return 1
  if validate_path_observation_source_artifacts "$invalid_observation"; then
    printf 'pressure source validation accepted a stale derived occupancy\n' >&2
    return 1
  fi

  command cp -- "$fill" "$fill.valid"
  jq '.touched = 1 | .verified_present_entries = 1' "$fill" >"$fill.tmp"
  mv -T -- "$fill.tmp" "$fill"
  validate_pressure_cell_artifacts "$runner" || {
    printf 'production-valid mutated fill fixture was rejected before reconciliation\n' >&2
    return 1
  }
  if validate_path_observation_source_artifacts "$observation"; then
    printf 'pressure source validation accepted stale touched-entry evidence\n' >&2
    return 1
  fi
  mv -T -- "$fill.valid" "$fill"

  command cp -- "$pressured" "$pressured.occupancy-valid"
  write_pressure_map_metrics_fixture "$pressured" 2
  validate_pressure_cell_artifacts "$runner" || {
    printf 'production-valid mutated pressure occupancy was rejected before reconciliation\n' >&2
    return 1
  }
  if validate_path_observation_source_artifacts "$observation"; then
    printf 'pressure source validation accepted stale pressured occupancy evidence\n' >&2
    return 1
  fi
  mv -T -- "$pressured.occupancy-valid" "$pressured"

  command cp -- "$sample_one" "$sample_one.valid"
  printf 'garbage\n' >"$sample_one"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted garbage recovery metrics\n' >&2
    return 1
  fi
  mv -T -- "$sample_one.valid" "$sample_one"

  command cp -- "$log" "$log.valid"
  {
    printf 'attempt=1 observed_at=2026-08-10T00:00:00Z entries=2 matched=true consecutive=1\n'
    printf 'attempt=2 observed_at=2026-08-10T00:00:01Z entries=1 matched=true consecutive=2\n'
  } >"$log"
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted a log/sample occupancy mismatch\n' >&2
    return 1
  fi
  mv -T -- "$log.valid" "$log"

  command cp -- "$recovered" "$recovered.valid"
  write_pressure_map_metrics_fixture "$recovered" 0
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

  command cp -- "$pressured" "$pressured.valid"
  write_pressure_map_metrics_fixture "$pressured" 1
  if validate_pressure_cell_artifacts "$runner"; then
    printf 'pressure validation accepted missing pressured occupancy\n' >&2
    return 1
  fi
  mv -T -- "$pressured.valid" "$pressured"
)

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
    jq '.pressure_correlation = {
      exact_hit_count: 127, explicit_root_count: 1,
      wrong_parent_count: 0, unresolved_count: 0
    }' "$result_file" >"$result_file.tmp"
    mv -T -- "$result_file.tmp" "$result_file"
    jq -n '
      {status: "passed", scenario: "pressure", exit_status: 0, metric_status: 0,
       result: "scenario-pressure.json",
       pressure_correlation: {
         trace: {exact_hit_count: 127, explicit_root_count: 1,
           wrong_parent_count: 0, unresolved_count: 0},
         bridge: {transport: "getsockopt"},
         java_reconciliation_target: {take_valid_count: 127,
           attributable_absence_count: 1, diagnostic_self_miss_count: 1}
       }}
    ' >"$status_file"
    jq -n '
      {status: "passed", mode: "fill",
       map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
       map_type: "Hash", map_id: 41, max_entries: 50000, touched: 49999,
       capacity_rejected_entries: 1, verified_present_entries: 49999,
       process_map_id: 42, process_pid: 43, process_namespace: 44, token_base: 1}
    ' >"$cell_directory/preflight/runner/map-pressure-pressure-fill.json"
    jq -n '
      {status: "passed", mode: "cleanup", map_id: 41,
       map_name: "java_remote_parent_handoff_claims", kernel_name: "java_remote_par",
       map_type: "Hash", max_entries: 50000, process_map_id: 0,
       process_pid: 43, process_namespace: 44, token_base: 1,
       cleanup_verified: true, verified_absent_entries: 50001, touched: 0}
    ' >"$cell_directory/preflight/runner/map-pressure-pressure-cleanup.json"
    mkdir -p -- "$cell_directory/preflight/runner/phases/pressure-before"
    write_pressure_map_metrics_fixture \
      "$cell_directory/preflight/runner/phases/pressure-before/obi-metrics.prom" 1
    write_pressure_map_metrics_fixture \
      "$cell_directory/preflight/runner/map-pressure-pressure-pressured.prom" 50000
    write_pressure_map_metrics_fixture \
      "$cell_directory/preflight/runner/map-pressure-pressure-traffic-complete.prom" 49999
    write_pressure_map_metrics_fixture \
      "$cell_directory/preflight/runner/map-pressure-pressure-recovered-sample-01.prom" 1
    write_pressure_map_metrics_fixture \
      "$cell_directory/preflight/runner/map-pressure-pressure-recovered-sample-02.prom" 1
    command cp -- \
      "$cell_directory/preflight/runner/map-pressure-pressure-recovered-sample-02.prom" \
      "$cell_directory/preflight/runner/map-pressure-pressure-recovered.prom"
    {
      printf 'attempt=1 observed_at=2026-08-10T00:00:00Z entries=1 matched=true consecutive=1\n'
      printf 'attempt=2 observed_at=2026-08-10T00:00:01Z entries=1 matched=true consecutive=2\n'
    } >"$cell_directory/preflight/runner/map-pressure-pressure-recovered-samples.log"
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
  write_application_runner_source_fixture \
    "$cell_directory/preflight/runner" bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
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
  write_application_source_identity_artifact_fixture \
    "$root" complete "$revision" "$REPO_ROOT"
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

  reset_options
  OUTPUT_DIR="$TEST_TMP_DIR/complete-manifest"
  CELLS_MODE=complete
  # shellcheck disable=SC2034 # Consumed dynamically by write_manifest.
  STARTED_AT=2026-08-10T00:00:00Z
  # shellcheck disable=SC2034 # Consumed dynamically by write_manifest.
  HARNESS_INVOCATION='benchmark.sh --cells complete'
  mkdir -- "$OUTPUT_DIR"
  write_manifest
  jq -e '
    .cells_mode == "complete" and
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
      "requested_for_bounded_growth_gate" and
    .predeclared_poc_gates.repetitions.required == 5 and
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
      p99_latency_regression_max_percent: 10
    } and
    .predeclared_poc_gates.bounded_growth.unavailable_samples_fail_closed == true and
    .predeclared_poc_gates.bounded_growth.java_bridge_map_evaluation == {
      status: "partial_not_evaluated",
      metric_scope: "host_global_java_remote_par_superset",
      ownership_attribution: false,
      required_descriptive_samples: true,
      bridge_disabled_project_map_configured_max_entries: 1,
      completion_requirement: "project_ownership_attribution_or_clean_host_proof"
    } and
    .predeclared_poc_gates.issue_acceptance_complete == false and
    .unavailable_dimensions.jfr_nmt_allocation_native_direct_memory == "not_collected" and
    .unavailable_dimensions.bpf_lock_contention == "not_collected" and
    .unavailable_dimensions.bpf_map_evictions ==
      "not_applicable_non_evicting_hash_pressure"
  ' "$OUTPUT_DIR/manifest.json" >/dev/null
}

write_valid_benchmark_result() {
  local -r output="$1"
  local -r duration_seconds="$2"
  local -r successful_requests="${3:-1}"
  local -r failed_requests="${4:-0}"
  local -r traffic_elapsed_nanos="${5:-$((duration_seconds * 1000000000))}"
  local -r throughput_per_second="${6:-1}"
  local -r p50_nanos="${7:-1}"
  local -r p95_nanos="${8:-1}"
  local -r p99_nanos="${9:-1}"

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
        connection_mode: $connection_mode, tls_verification: $tls_verification,
        w3c: $w3c, seed: $seed,
        requested_duration_nanos: $duration_nanos,
        request_timeout_nanos: $timeout_nanos, concurrency: $concurrency,
        request_limit: $request_limit, request_limit_reached: false,
        canceled: false, successful_requests: $successful_requests, failed_requests: $failed_requests,
        traffic_elapsed_nanos: $traffic_elapsed_nanos, throughput_per_second: $throughput_per_second,
        latency: {p50_nanos: $p50_nanos, p95_nanos: $p95_nanos, p99_nanos: $p99_nanos}
      }
    ' >"$output"
}

write_variance_fixture_cell() {
  local -r cell="$1"
  local -r successful_requests="${2:-1}"
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

prepare_poc_gate_fixture() {
  local -r output="$1"
  local cell=""
  local service=""
  local cell_dir=""
  local pid=100
  local -a services=()

  OUTPUT_DIR="$output"
  OUTPUT_READY=true
  REPETITIONS=5
  DURATION_SECONDS=2
  CONCURRENCY=1
  mkdir -p -- "$OUTPUT_DIR/cells"
  for cell in "${CORE_CELLS[@]}"; do
    write_variance_fixture_cell "$cell" 10 0 2000000000 100 50 90 100
    cell_spec "$cell" || return 1
    cell_dir="$OUTPUT_DIR/cells/$cell"
    mkdir -- "$cell_dir/resources-before" "$cell_dir/resources-idle-recovery"
    services=(trace-receiver apache-proxy java-backend)
    if [[ "$CELL_REQUIRES_OBI" == true ]]; then
      services+=(obi)
    fi
    for service in "${services[@]}"; do
      write_proc_growth_fixture \
        "$cell_dir/resources-before/$service-proc.txt" "$pid" 20 8
      write_proc_growth_fixture \
        "$cell_dir/resources-idle-recovery/$service-proc.txt" "$pid" 20 8
      ((pid += 1))
    done
    if [[ "$CELL_REQUIRES_OBI" == true ]]; then
      if [[ "$cell" == "bridge-disabled" ]]; then
        write_java_map_growth_fixture "$cell_dir/resources-before/obi-metrics.prom" 0 1
        write_java_map_growth_fixture "$cell_dir/resources-idle-recovery/obi-metrics.prom" 0 1
      else
        write_java_map_growth_fixture "$cell_dir/resources-before/obi-metrics.prom" 2 10000
        write_java_map_growth_fixture "$cell_dir/resources-idle-recovery/obi-metrics.prom" 1 10000
      fi
    fi
  done
  write_variance_summary
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

  reset_options
  cell_spec getsockopt-hit
  write_valid_benchmark_result "$benchmark_result" 2
  validate_benchmark_result "$benchmark_result" 2 || {
    printf 'valid benchmark result was rejected\n' >&2
    return 1
  }
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
  local repetition=0
  local repetition_label=""
  local -a successful_requests=(6 1 5 2 4 3)
  local -a throughput_per_second=(60 10 50 20 40 30)
  local -a p50_nanos=(6 1 5 2 4 3)
  local -a p95_nanos=(60 10 50 20 40 30)
  local -a p99_nanos=(600 100 500 200 400 300)

  reset_options
  DURATION_SECONDS=2
  REPETITIONS=6
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
  jq -n --arg timing unsynchronized_midpoint --arg status unavailable \
    '{timing: $timing, status: $status, reason: "load_client_exited_before_sample"}' \
    >"$output/cells/getsockopt-hit/measurements/rep-01-midpoint.json"
  write_variance_summary || {
    printf 'variance summary rejected valid fixture data\n' >&2
    return 1
  }
  jq -e '
    .schema_version == 1 and
    .kind == "application-performance-repetition-summary" and
    .status == "complete" and
    .acceptance_evidence == false and
    .manifest == "manifest.json" and
    .aggregation.sample_unit == "one completed sustained-client repetition" and
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
    $cell.expected_sample_count == 6 and
    $cell.valid_sample_count == 6 and
    ($cell.samples | map({repetition, source})) == [
      {repetition: 1, source: "cells/getsockopt-hit/measurements/rep-01.json"},
      {repetition: 2, source: "cells/getsockopt-hit/measurements/rep-02.json"},
      {repetition: 3, source: "cells/getsockopt-hit/measurements/rep-03.json"},
      {repetition: 4, source: "cells/getsockopt-hit/measurements/rep-04.json"},
      {repetition: 5, source: "cells/getsockopt-hit/measurements/rep-05.json"},
      {repetition: 6, source: "cells/getsockopt-hit/measurements/rep-06.json"}
    ] and
    $cell.statistics.successful_requests == {min: 1, median: 3.5, max: 6} and
    $cell.statistics.failed_requests == {min: 0, median: 0, max: 0} and
    $cell.statistics.traffic_elapsed_nanos == {min: 2000000000, median: 2000000000, max: 2000000000} and
    $cell.statistics.throughput_per_second == {min: 10, median: 35, max: 60} and
    $cell.statistics.latency.p50_nanos == {min: 1, median: 3.5, max: 6} and
    $cell.statistics.latency.p95_nanos == {min: 10, median: 35, max: 60} and
    $cell.statistics.latency.p99_nanos == {min: 100, median: 350, max: 600} and
    (.cells[] | select(.cell == "unix-hit").statistics.throughput_per_second) ==
      {min: 1, median: 1, max: 1}
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

  for mode in missing extra multi_document symlink; do
    reset_options
    DURATION_SECONDS=2
    REPETITIONS=5
    output="$TEST_TMP_DIR/variance-invalid-$mode"
    prepare_variance_fixture "$output"
    measurement_dir="$output/cells/getsockopt-hit/measurements"
    case "$mode" in
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
      .latency.p99_nanos = $p99
    ' "$result" >"$temporary" || return 1
    mv -T -- "$temporary" "$result" || return 1
  done
  rm -f -- "$OUTPUT_DIR/variance.json"
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
  map_json="$(java_bridge_map_growth_observation \
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom")"
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .data_status == "complete" and
    .descriptive_result == "stable_or_decreased" and
    .scope == "host_global_java_remote_par_superset" and
    .ownership_attribution == false and
    .maps == [{
      map_id: 41, map_name: "java_remote_par", map_type: "hash",
      before_entries: 2, idle_recovery_entries: 1, delta: -1,
      maximum_delta: 0, max_entries: 10000
    }]
  ' <<<"$map_json" >/dev/null || {
    printf 'stable foreign-only Java map samples were treated as attributable gate evidence\n' >&2
    return 1
  }

  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 1' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 1' \
    'obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 10000' \
    >"$fixture/map-recovery.prom"
  map_json="$(java_bridge_map_growth_observation \
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom")"
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
    test-cell "$fixture/map-before.prom" "$fixture/map-recovery.prom")"
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .data_status == "ambiguous" and
    .descriptive_result == "series_set_changed_or_was_duplicate" and
    .scope == "host_global_java_remote_par_superset" and
    .ownership_attribution == false
  ' <<<"$map_json" >/dev/null || {
    printf 'foreign or newly visible Java map series did not prevent a pass\n' >&2
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
  local -r mutated_gate="$TEST_TMP_DIR/poc-gate-mutated.json"
  local canonical_gate=""
  local result=""

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
  canonical_gate="$(poc_gate_summary_json "$stable_output")" || return 1
  jq -e --argjson canonical "$canonical_gate" '. == $canonical' \
    "$stable_output/poc-gates.json" >/dev/null || {
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
  jq -e '
    .status == "partial" and .result == "not_evaluated" and
    .correctness.observed_failures == 0 and
    .correctness.status == "complete" and .correctness.result == "passed" and
    .performance.required_repetitions == 5 and
    .performance.status == "complete" and .performance.result == "passed" and
    all(.performance.comparisons[];
      .throughput_per_second.regression_percent == 0 and
      .p99_latency_nanos.regression_percent == 0 and
      .result == "passed") and
    .performance.excluded_cells.getsockopt_helper_idle ==
      "direct_java_workload_is_not_comparable_to_the_apache_baseline" and
    .resources.status == "partial" and .resources.result == "not_evaluated" and
    .resources.process_dimension == {status: "complete", result: "passed"} and
    .resources.map_dimension == {
      status: "partial",
      result: "not_evaluated",
      reason: "host_global_metrics_do_not_attribute_visible_java_remote_par_series_to_this_demo_project",
      descriptive_data_status: "complete"
    } and
    .resources.map_sampling_scope == {
      metric_scope: "host_global_java_remote_par_superset",
      ownership_attribution: false,
      descriptive_interpretation: "stable_or_decreased_applies_to_every_visible_java_remote_par_series",
      evaluation_policy: "not_evaluated_without_project_ownership_attribution_or_clean_host_proof"
    } and
    .resources.java_bridge_map_observations[0].cell == "bridge-disabled" and
    .resources.java_bridge_map_observations[0].status == "partial" and
    .resources.java_bridge_map_observations[0].result == "not_evaluated" and
    .resources.java_bridge_map_observations[0].data_status == "complete" and
    .resources.java_bridge_map_observations[0].descriptive_result == "stable_or_decreased" and
    .resources.java_bridge_map_observations[0].maps == [{
      map_id: 41, map_name: "java_remote_par", map_type: "hash",
      before_entries: 0, idle_recovery_entries: 0, delta: 0,
      maximum_delta: 0, max_entries: 1
    }] and
    all(.resources.java_bridge_map_observations[];
      .scope == "host_global_java_remote_par_superset" and
      .ownership_attribution == false and
      .status == "partial" and .result == "not_evaluated") and
    .issue_acceptance_complete == false and
    .unmeasured_dimensions == {
      jfr_nmt_allocation_native_direct_memory: "not_collected",
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
    >"$partial_output/cells/unix-hit/resources-idle-recovery/java-backend-proc.txt"
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
    >"$map_partial_output/cells/bridge-disabled/resources-idle-recovery/obi-metrics.prom"
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
      reason: "host_global_metrics_do_not_attribute_visible_java_remote_par_series_to_this_demo_project",
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
    "$resource_failure_output/cells/getsockopt-hit/resources-idle-recovery/java-backend-proc.txt" \
    109 21 8
  write_poc_gate_summary
  validate_poc_gate_schema "$resource_failure_output/poc-gates.json" || {
    printf 'partial PoC artifact rejected an evaluated process-growth failure\n' >&2
    return 1
  }
  jq -e '
    .status == "partial" and .result == "failed" and
    .resources.status == "partial" and .resources.result == "failed" and
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
    .resources.result == "not_evaluated"
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

test_summary_resource_scope_is_independent_of_nonresource_failures() (
  local -r performance_output="$TEST_TMP_DIR/summary-performance-only-failure"
  local -r correctness_output="$TEST_TMP_DIR/summary-correctness-only-failure"
  local -r process_output="$TEST_TMP_DIR/summary-process-growth-failure"

  reset_options
  prepare_poc_gate_fixture "$performance_output"
  rewrite_cell_performance_fixture getsockopt-hit 89 111
  write_poc_gate_summary
  jq -n '{status: "in_progress"}' >"$performance_output/manifest.json"
  write_summary failed

  reset_options
  prepare_poc_gate_fixture "$correctness_output"
  jq '.status = "failed" | .reason = "fixture_correctness_failure"' \
    "$correctness_output/cells/unix-hit/status.json" \
    >"$correctness_output/cells/unix-hit/status.json.tmp"
  mv -T -- "$correctness_output/cells/unix-hit/status.json.tmp" \
    "$correctness_output/cells/unix-hit/status.json"
  write_poc_gate_summary
  jq -n '{status: "in_progress"}' >"$correctness_output/manifest.json"
  write_summary failed

  reset_options
  prepare_poc_gate_fixture "$process_output"
  write_proc_growth_fixture \
    "$process_output/cells/getsockopt-hit/resources-idle-recovery/java-backend-proc.txt" \
    109 21 8
  write_poc_gate_summary
  jq -n '{status: "in_progress"}' >"$process_output/manifest.json"
  write_summary failed

  jq -e '
    .performance.result == "failed" and
    .correctness.result == "passed" and
    .resources.result == "not_evaluated" and
    .resources.process_dimension == {status: "complete", result: "passed"}
  ' "$performance_output/poc-gates.json" >/dev/null || {
    printf 'performance-only fixture did not isolate its gate failure\n' >&2
    return 1
  }
  jq -e '
    .performance.result == "passed" and
    .correctness.result == "failed" and
    .resources.result == "not_evaluated" and
    .resources.process_dimension == {status: "complete", result: "passed"}
  ' "$correctness_output/poc-gates.json" >/dev/null || {
    printf 'correctness-only fixture did not isolate its gate failure\n' >&2
    return 1
  }
  jq -se '
    length == 2 and all(.[0:2][];
      .status == "failed" and .poc_gates.result == "failed" and
      .measurement_scope.application_fd_threads_and_java_bridge_map_growth == {
        status: "partial",
        result: "not_evaluated",
        process_fd_threads: {status: "complete", result: "passed"},
        java_bridge_map: {
          status: "partial",
          result: "not_evaluated",
          reason: "host_global_metrics_do_not_attribute_visible_java_remote_par_series_to_this_demo_project",
          descriptive_data_status: "complete"
        }
      })
  ' "$performance_output/summary.json" "$correctness_output/summary.json" \
    >/dev/null || {
    printf 'summary misattributed a nonresource failure to resource growth\n' >&2
    return 1
  }
  jq -e '
    .status == "failed" and .poc_gates.result == "failed" and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth == {
      status: "partial",
      result: "failed",
      process_fd_threads: {status: "complete", result: "failed"},
      java_bridge_map: {
        status: "partial",
        result: "not_evaluated",
        reason: "host_global_metrics_do_not_attribute_visible_java_remote_par_series_to_this_demo_project",
        descriptive_data_status: "complete"
      }
    }
  ' "$process_output/summary.json" >/dev/null || {
    printf 'summary did not attribute an evaluated process-growth failure to resources\n' >&2
    return 1
  }
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
  jq -n '{status: "in_progress"}' >"$OUTPUT_DIR/manifest.json"
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
  jq -n '{status: "in_progress"}' >"$OUTPUT_DIR/manifest.json"
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

test_summary_marks_unavailable_variance_after_failure() (
  local -r output="$TEST_TMP_DIR/failed-variance-summary"

  reset_options
  OUTPUT_DIR="$output"
  # shellcheck disable=SC2034 # Consumed by write_summary from the sourced harness.
  OUTPUT_READY=true
  mkdir -p -- "$output/cells"
  jq -n '{status: "in_progress"}' >"$output/manifest.json"
  if write_summary passed >/dev/null 2>&1; then
    printf 'passed summary accepted a missing variance artifact\n' >&2
    return 1
  fi
  jq -n '{status: "complete"}' >"$output/variance.json"
  write_summary failed || {
    printf 'failed summary could not record unavailable variance\n' >&2
    return 1
  }
  jq -e '
    .status == "failed" and
    .acceptance_evidence == false and
    .variance == {status: "not_available", path: null}
  ' "$output/summary.json" >/dev/null || {
    printf 'failed summary misrepresented unavailable variance\n' >&2
    return 1
  }
  [[ ! -e "$output/variance.json" && ! -L "$output/variance.json" ]] || {
    printf 'failed summary retained a completed variance artifact\n' >&2
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
  command jq -n '{status: "in_progress"}' >"$output/manifest.json"
  jq() {
    if [[ "${1:-}" == "--arg" && "${2:-}" == "status" ]]; then
      return 1
    fi
    command jq "$@"
  }
  if write_summary failed >/dev/null 2>&1; then
    printf 'summary accepted a failed manifest render\n' >&2
    return 1
  fi
  command jq -e '.status == "in_progress"' "$output/manifest.json" >/dev/null || {
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
  command jq -n '{status: "in_progress"}' >"$output/manifest.json"
  mv() {
    case "${4:-}" in
      "$output/summary.json")
        command jq -e '.status == "in_progress"' "$output/manifest.json" >/dev/null || return 1
        ;;
      "$output/manifest.json")
        [[ -f "$output/summary.json" && ! -L "$output/summary.json" ]] || return 1
        ;;
    esac
    command mv "$@"
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

test_helper_idle_diagnostics_suppression_is_midpoint_only() (
  local -r non_helper_snapshot="$TEST_TMP_DIR/non-helper-not-collected"
  local -r wrong_timing_snapshot="$TEST_TMP_DIR/helper-wrong-timing-not-collected"

  reset_options
  cell_spec getsockopt-hit
  if capture_resource_snapshot "$non_helper_snapshot" unsynchronized_midpoint not_collected; then
    printf 'resource snapshot allowed diagnostics suppression outside the helper-idle control\n' >&2
    return 1
  fi
  [[ ! -e "$non_helper_snapshot" ]] || {
    printf 'resource snapshot created artifacts after rejecting non-helper diagnostics suppression\n' >&2
    return 1
  }

  cell_spec getsockopt-helper-idle
  if capture_resource_snapshot "$wrong_timing_snapshot" before not_collected; then
    printf 'resource snapshot allowed diagnostics suppression outside the helper midpoint\n' >&2
    return 1
  fi
  [[ ! -e "$wrong_timing_snapshot" ]] || {
    printf 'resource snapshot created artifacts after rejecting an invalid helper timing\n' >&2
    return 1
  }
)

test_helper_idle_bpf_metrics_require_constrained_deltas() (
  local -r before="$TEST_TMP_DIR/helper-idle-bpf-before.prom"
  local -r after="$TEST_TMP_DIR/helper-idle-bpf-after.prom"
  local -r unavailable="$TEST_TMP_DIR/helper-idle-bpf-unavailable.prom"
  local -r duplicate="$TEST_TMP_DIR/helper-idle-bpf-duplicate.prom"
  local -r churn_before="$TEST_TMP_DIR/helper-idle-bpf-churn-before.prom"
  local -r churn_after="$TEST_TMP_DIR/helper-idle-bpf-churn-after.prom"
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
  printf '5 0 0 0 0 0 0 1\n' >"$state"
  fake_bpf_metrics_snapshot >"$before"
  printf '13 0 0 0 0 0 0 9\n' >"$state"
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
      {category: "getsockopt-take", operation: "take", transport: "getsockopt", expected_delta: 0},
      {category: "getsockopt-discard", operation: "discard", transport: "getsockopt", expected_delta: 0}
    ]) and
    (.constrained_zero_deltas | all(.observed_delta == 0 and .expected_delta == 0)) and
    .informative_getsockopt_negotiate_missing == {
      before_series: 1, after_series: 1, before: 1, after: 9, observed_delta: 8,
      interpretation: "informative_only_not_a_retrieval_outcome_reconciliation"
    }
  ' "$output" >/dev/null || {
    printf 'helper-idle BPF metrics lost the report and informative-negotiation distinction\n' >&2
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
    printf '%s %s %s %s %s %s %s %s\n' \
      "$report" "$candidate" "$inject" "$stage" "$handoff" "$take" "$discard" \
      "$negotiate_missing" >"$state"
    fake_bpf_metrics_snapshot >"$after"
    if helper_idle_metric_delta_json "$before" "$after" "$output" >/dev/null 2>&1; then
      printf 'helper-idle BPF metrics accepted %s/%s activity\n' "$transport" "$operation" >&2
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
  printf '13 0 0 0 0 0 0 9\n' >"$state"
  fake_bpf_metrics_snapshot >"$after"
  cp -- "$after" "$duplicate"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} 0' \
    >>"$duplicate"
  if helper_idle_metric_delta_json "$before" "$duplicate" "$output" >/dev/null 2>&1; then
    printf 'helper-idle BPF metrics accepted duplicate label sets\n' >&2
    return 1
  fi
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
  printf '10 0 0 0 0 0 0 0\n' >"$state"
  fake_bpf_metrics_snapshot >"$observed"
  capture_obi_metrics() {
    local -r capture="$1"

    ((captures += 1))
    case "$captures" in
      # The first post-boundary pass is a delayed prior report. The direct
      # workload's candidate only arrives in the following stats pass.
      1) printf '11 0 0 0 0 0 0 0\n' >"$state" ;;
      2) printf '12 4 0 0 0 0 0 0\n' >"$state" ;;
      3) printf '13 4 0 0 0 0 0 0\n' >"$state" ;;
      4) printf '14 4 0 0 0 0 0 0\n' >"$state" ;;
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
      report_is_published_after_each_successful_bpf_counter_pass: true
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
      1) printf '10 0 0 0 0 0 0 0\n' >"$state" ;;
      2) printf '11 0 0 0 0 0 0 0\n' >"$state" ;;
      3) printf '12 0 0 0 0 0 0 0\n' >"$state" ;;
      # post seed, then a delayed pre-window pass followed by the pass that
      # actually publishes the direct-workload candidate.
      4) printf '12 0 0 0 0 0 0 0\n' >"$state" ;;
      5) printf '13 0 0 0 0 0 0 0\n' >"$state" ;;
      6) printf '14 1 0 0 0 0 0 0\n' >"$state" ;;
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
    "$measurement_repetitions" == 5 ]] || {
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

test_interrupted_measurement_reaps_client_tree() (
  local -r output="$TEST_TMP_DIR/interrupted-measurement.json"
  local -r child_pid_file="$TEST_TMP_DIR/interrupted-measurement-child.pid"
  local child_pid=""
  local process_group=""
  local session=""
  local start_time=""
  local attempt=0

  reset_options
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
    terminate_active_benchmark || true
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
  terminate_active_benchmark
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
)

test_wait_reaps_client_group_after_leader_exit() (
  local -r output="$TEST_TMP_DIR/leader-exit.json"
  local -r child_pid_file="$TEST_TMP_DIR/leader-exit-child.pid"
  local child_pid=""
  local wait_status=0
  local attempt=0

  reset_options
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
  local cell=""
  local command_name=""
  local request=0
  local revision=""
  local git_tree=""

  mkdir -p -- "$fake_example/scripts" "$fake_bin" "$output_parent" "$fake_example/.runtime"
  chmod 0755 -- "$fake_example/.runtime"
  install --mode=0755 "$TEST_SCRIPT_DIR/benchmark.sh" "$fake_example/scripts/benchmark.sh"
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
  printf '0 0 0 0 0 0 0 0\n' >"$bpf_metrics"
  if ! PATH="$fake_bin:$PATH" \
    FAKE_CONTAINER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    FAKE_BPF_METRICS_FILE="$bpf_metrics" \
    FAKE_COMPOSE_PROJECT_FILE="$compose_project" \
    FAKE_DOCKER_LOG="$docker_log" \
    FAKE_DIAGNOSTICS_FILE="$diagnostics" \
    FAKE_DOCKER_ENDPOINT="unix://$docker_socket" \
    FAKE_EVENTS="$events" \
    FAKE_GIT_REVISION="$revision" \
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
      --seed 17; then
    printf 'hermetic benchmark harness run failed\n' >&2
    return 1
  fi
  jq -e '
    .status == "passed" and
    .acceptance_evidence == false and
    (.cells | length == 6) and
    all(.cells[]; .status == "passed") and
    .variance == {status: "available", path: "variance.json"} and
    .docker_daemon == {status: "verified_local_unix_socket_endpoint_only", path: "docker-daemon.json"} and
    .application_source == {status: "clean_and_stable", path: "application-source-identity.json"} and
    .poc_gates == {
      status: "partial", path: "poc-gates.json", result: "not_evaluated"
    } and
    .measurement_scope.application_fd_threads_and_java_bridge_map_growth == {
      status: "partial",
      result: "not_evaluated",
      process_fd_threads: {status: "complete", result: "passed"},
      java_bridge_map: {
        status: "partial",
        result: "not_evaluated",
        reason: "host_global_metrics_do_not_attribute_visible_java_remote_par_series_to_this_demo_project",
        descriptive_data_status: "complete"
      }
    } and
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
    .resources.map_dimension.status == "partial" and
    .resources.map_dimension.result == "not_evaluated" and
    .resources.map_sampling_scope.ownership_attribution == false and
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
      .status == "partial" and .result == "not_evaluated")
  ' "$output/poc-gates.json" >/dev/null || {
    printf 'hermetic run allowed host-global map samples to complete the PoC gate\n' >&2
    return 1
  }
  jq -e '
    .schema_version == 1 and
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
        .throughput_per_second == 4 and
        .latency == {p50_nanos: 1, p95_nanos: 2, p99_nanos: 3}
      ) and
      .statistics.successful_requests == {min: 4, median: 4, max: 4} and
      .statistics.failed_requests == {min: 0, median: 0, max: 0} and
      .statistics.traffic_elapsed_nanos == {min: 2000000000, median: 2000000000, max: 2000000000} and
      .statistics.throughput_per_second == {min: 4, median: 4, max: 4} and
      .statistics.latency.p50_nanos == {min: 1, median: 1, max: 1} and
      .statistics.latency.p95_nanos == {min: 2, median: 2, max: 2} and
      .statistics.latency.p99_nanos == {min: 3, median: 3, max: 3}
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
      {category: "getsockopt-take", operation: "take", transport: "getsockopt", expected_delta: 0},
      {category: "getsockopt-discard", operation: "discard", transport: "getsockopt", expected_delta: 0}
    ]) and
    (.constrained_zero_deltas | all(.observed_delta == 0 and .expected_delta == 0)) and
    .assertion == {
      tcp_upstream_candidate_inject_stage_handoff_delta_zero: true,
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
      report_is_published_after_each_successful_bpf_counter_pass: true
    }
  ' "$output/cells/getsockopt-helper-idle/sustained-helper-idle/metrics-watermark-before.json" \
    "$output/cells/getsockopt-helper-idle/sustained-helper-idle/metrics-watermark-after.json" \
    >/dev/null || {
    printf 'helper-idle did not retain two-pass causal BPF fences around its exact window\n' >&2
    return 1
  }
  for ((request = 1; request <= 5; request++)); do
    printf -v repetition_label 'rep-%02d' "$request"
    jq -e '
      .timing == "unsynchronized_midpoint" and
      .java_diagnostics == {
        status: "not_collected",
        reason: "would_mutate_exact_helper_idle_java_diagnostics_window"
      }
    ' "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/snapshot.json" \
      >/dev/null || {
      printf 'helper-idle midpoint %s did not retain diagnostics-free resource-sampling provenance\n' \
        "$repetition_label" >&2
      return 1
    }
    [[ -f "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-proc.txt" &&
      -f "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/container-stats.jsonl" &&
      -s "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/obi-metrics.prom" &&
      ! -e "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-diagnostics.txt" ]] || {
      printf 'helper-idle midpoint %s did not retain diagnostics-free resource evidence\n' \
        "$repetition_label" >&2
      return 1
    }
    grep -Eq '^VmRSS:' \
      "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-proc.txt" &&
      grep -Eq '^Threads:' \
        "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-proc.txt" &&
      grep -Eq '^fd_count=' \
        "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-proc.txt" &&
      grep -Eq '^task_count=' \
        "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-proc.txt" &&
      grep -Eq '^stat=' \
        "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/java-backend-proc.txt" || {
      printf 'helper-idle midpoint %s omitted Java CPU/RSS/thread/FD process fields\n' \
        "$repetition_label" >&2
      return 1
    }
    grep -Fq '"fake"' \
      "$output/cells/getsockopt-helper-idle/measurements/$repetition_label-midpoint/container-stats.jsonl" || {
      printf 'helper-idle midpoint %s omitted container resource statistics\n' \
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
    for ((request = 0; request < 5; request++)); do
      printf '%s\n' direct-java-workload
      printf '%s\n' obi-metrics
    done
    printf '%s\n' obi-metrics obi-metrics obi-metrics java-diagnostics obi-metrics java-diagnostics \
      obi-metrics java-diagnostics
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
  jq -e '.schema_version == 2 and
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
  local revision=""
  local git_tree=""
  local command_name=""

  mkdir -p -- "$fake_example/scripts" "$fake_example/java" \
    "$agent_directory/src/main/c" "$agent_directory/src/test/c" \
    "$fake_bin" "$output_parent" "$fake_example/.runtime"
  chmod 0755 -- "$fake_example/.runtime"
  install --mode=0755 "$TEST_SCRIPT_DIR/benchmark.sh" "$fake_example/scripts/benchmark.sh"
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
  printf '0 0 0 0 0 0 0 0\n' >"$bpf_metrics"
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
    FAKE_PID="$$" \
    FAKE_RESULTS_ROOT="$results_root" \
    FAKE_RUNNER_LOG="$runner_log" \
    FAKE_SOURCE_TREE_MANIFEST="$source_tree_manifest" \
    FAKE_TLS_PROTOCOL=TLSv1.2 \
    run_benchmark_with_fake_bound_proc "$fake_example/scripts/benchmark.sh" \
      --output "$output" --agent splunk --tls TLSv1.2 \
      --warmup-seconds 2 --duration-seconds 2 --concurrency 1 \
      --repetitions 5 --seed 17 --cells complete; then
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
    .application_source == {status: "clean_and_stable", path: "application-source-identity.json"} and
    .measurement_scope.pressure_map_occupancy_and_capacity_rejection ==
      "bounded_correctness_observed_once"
  ' "$output/summary.json" >/dev/null || {
    printf 'complete fake run did not publish bounded evidence honestly\n' >&2
    return 1
  }
  validate_lookup_path_summary_schema \
    "$output/lookup-paths.json" "$fake_root" || return 1
  validate_native_jni_benchmark_schema "$output/native-jni/benchmark.json" || return 1
  validate_application_source_identity_schema \
    "$output/application-source-identity.json" "$fake_root" || return 1
  jq -e '.cells_mode == "complete" and (.cells | length) == 10 and
    (.cells | map(.cell))[-4:] == [
      "getsockopt-stale", "unix-stale", "unix-timeout", "getsockopt-pressure"
    ]' "$output/application-source-identity.json" >/dev/null || return 1
  jq -e '
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
      .occupancy_before_fill == 1 and .occupancy_pressured == 50000 and
      .occupancy_traffic_complete == 49999 and
      .occupancy_recovery_samples == [1, 1] and .occupancy_recovered == 1 and
      .recovery_samples == 2 and .recovery_log_attempts == 2)
  ' "$output/lookup-paths.json" >/dev/null || return 1
  jq -e '.status == "clean_and_stable" and
    .captures == {before: "source-state-before.json", after: "source-state-after.json"}' \
    "$output/native-jni/source-state.json" >/dev/null || return 1
  [[ "$(grep -Fc cleanup "$events")" == 10 &&
    -f "$output/cells/getsockopt-hit/path-observation.json" &&
    -f "$output/cells/unix-hit/path-observation.json" &&
    ! -e "$agent_directory/INJECTED" ]] || return 1
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
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "core-mode" ]]; then
    test_main_uses_runner_cleanup_and_retains_core_artifacts
    printf 'benchmark.sh core-mode test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "complete-mode" ]]; then
    test_complete_mode_fake_run_publishes_resolvable_bounded_evidence
    printf 'benchmark.sh complete-mode test passed\n'
    return 0
  fi
  if [[ "${BENCHMARK_TEST_ONLY:-}" == "council-repairs" ]]; then
    test_docker_daemon_locality_is_verified_before_execution
    test_manifest_bootstrap_survives_second_locality_query_failure
    test_benchmark_documentation_binds_partial_status_to_mralias_issue
    test_proc_snapshot_requires_container_starttime_and_cgroup_identity
    test_pressure_recovery_evidence_parses_canonical_samples_and_log
    test_application_source_identity_is_exact_across_core_and_complete_cells
    test_application_source_identity_rejects_coordinated_manifest_forgery
    test_variance_summary_records_ordered_per_cell_statistics
    test_variance_summary_rejects_invalid_repetition_sets
    test_predeclared_poc_gate_stays_partial_and_evaluates_supported_dimensions
    printf 'benchmark.sh council repair tests passed\n'
    return 0
  fi
  test_parser_defaults_and_boundaries
  test_lifecycle_tool_paths_must_be_absolute_regular
  test_lifecycle_tool_resolution_rejects_relative_paths
  test_dependency_check_reports_only_invalid_lifecycle_tool
  test_dependency_check_reports_invalid_lifecycle_tool_under_errexit
  test_docker_daemon_locality_is_verified_before_execution
  test_manifest_bootstrap_survives_second_locality_query_failure
  test_benchmark_documentation_binds_partial_status_to_mralias_issue
  test_proc_snapshot_requires_container_starttime_and_cgroup_identity
  test_make_compiler_resolution_honors_and_pins_inherited_cc
  test_native_make_environment_and_staging_are_hermetic
  test_native_source_state_rejects_dirty_and_mutating_inputs
  test_output_directory_is_absolute_fresh_private
  test_core_cell_mapping_is_exact
  test_bounded_path_cell_mapping_is_exact
  test_core_mode_does_not_publish_complete_only_path_observations
  test_bounded_paths_are_correctness_observations_not_performance_samples
  test_pressure_recovery_evidence_parses_canonical_samples_and_log
  test_lookup_coverage_uses_observed_once_vocabulary
  test_application_source_identity_is_exact_across_core_and_complete_cells
  test_application_source_identity_rejects_coordinated_manifest_forgery
  test_native_jni_benchmark_normalization_is_strict
  test_complete_manifest_links_bounded_artifacts_and_scopes
  test_json_validators_require_one_document
  test_variance_summary_records_ordered_per_cell_statistics
  test_variance_summary_rejects_invalid_repetition_sets
  test_resource_growth_observations_fail_closed
  test_predeclared_poc_gate_stays_partial_and_evaluates_supported_dimensions
  test_summary_resource_scope_is_independent_of_nonresource_failures
  test_failed_complete_summary_reports_requested_artifact_state
  test_summary_marks_unavailable_variance_after_failure
  test_failed_summary_refuses_unremovable_variance
  test_on_exit_rewrites_failed_summary_after_passed_summary_error
  test_summary_rejects_manifest_render_failure
  test_summary_publishes_completion_marker_last
  test_w3c_discard_diagnostics_require_exact_delta
  test_helper_idle_java_diagnostics_require_exact_correction
  test_helper_idle_diagnostics_suppression_is_midpoint_only
  test_helper_idle_bpf_metrics_require_constrained_deltas
  test_helper_idle_bpf_fence_requires_two_post_boundary_passes
  test_helper_idle_sustained_rejects_delayed_post_workload_lifecycle
  test_runner_environment_contract_is_exact
  test_failed_measurement_clears_reaped_pid
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
