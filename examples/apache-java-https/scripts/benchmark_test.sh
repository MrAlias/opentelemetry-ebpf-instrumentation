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

  [[ -n "${FAKE_BPF_METRICS_FILE:-}" && -f "$FAKE_BPF_METRICS_FILE" ]] || return 64
  read -r report candidate inject stage handoff take discard negotiate_missing extra <"$FAKE_BPF_METRICS_FILE" || return 64
  [[ "$report" =~ ^[0-9]+$ && "$candidate" =~ ^[0-9]+$ && "$inject" =~ ^[0-9]+$ &&
    "$stage" =~ ^[0-9]+$ && "$handoff" =~ ^[0-9]+$ && "$take" =~ ^[0-9]+$ &&
    "$discard" =~ ^[0-9]+$ && "$negotiate_missing" =~ ^[0-9]+$ && -z "$extra" ]] || return 64
  printf '%s\n' \
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

fake_write_runner_artifacts() {
  local -r result_directory="$1"
  local -r transport="$2"
  local -r agent="$3"
  local -r tls="$4"
  local -r scenario="$5"
  local -r assertion_mode="$6"
  local -r selected_transport="$7"
  local -r project="$8"
  local assertion_scenario="concurrency"
  local index=0

  if [[ "$scenario" == w3c ]]; then
    assertion_scenario=w3c
  fi
  mkdir -p -- \
    "$result_directory/phases/$assertion_scenario-before" \
    "$result_directory/phases/$assertion_scenario-after"
  jq -n --arg result_directory "$result_directory" \
    '{status: "passed", exit_status: 0, evidence_directory: $result_directory}' \
    >"$result_directory/run-status.json"
  write_runner_environment \
    "$result_directory/environment.txt" "$transport" "$agent" "$tls" "$scenario" \
    "$FAKE_PREFLIGHT_REQUESTS" 1 "$SEED" "$project"
  printf 'revision=fake\n' >"$result_directory/source-state.txt"
  printf 'fake-source-tree\n' >"$result_directory/source-tree.manifest"
  printf 'fake-git-status\n' >"$result_directory/git-status.txt"
  printf '{"distribution":"otel","checksum":"fake"}\n' >"$result_directory/official-javaagent.json"
  printf '{"obi_java_agent_sha256":"fake"}\n' >"$result_directory/bridge-artifacts.json"
  printf 'fake  obi-java-agent.jar\n' >"$result_directory/bridge-artifacts.sha256"
  printf 'fake  bridge-artifacts.json\n' >"$result_directory/bridge-metadata.sha256"
  printf 'fake\n' >"$result_directory/bridge-source-revision.txt"
  printf 'fake\n' >"$result_directory/bridge-source-tree.sha256"
  printf '{"certificate":"test-only"}\n' >"$result_directory/certificates.json"
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
  if [[ "$assertion_scenario" == w3c ]]; then
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
      --argjson requests "$FAKE_PREFLIGHT_REQUESTS" \
      --argjson seed "${SEED:-1}" \
      '{
        status: "passed",
        scenario: "concurrency",
        assertion_mode: $assertion_mode,
        request_count: $requests,
        seed: $seed,
        cases: [range(0; $requests) | {response: {tls_protocol: $tls}}]
      }' >"$result_directory/scenario-concurrency.json"
    jq -n '{status: "passed", scenario: "concurrency"}' \
      >"$result_directory/scenario-concurrency-status.json"
    printf 'scenario stderr\n' >"$result_directory/scenario-concurrency.stderr.log"
  fi
  for index in before after; do
    printf 'obi_java_remote_parent_operations_total 0\n' \
      >"$result_directory/phases/$assertion_scenario-$index/obi-metrics.prom"
    printf 'java-diagnostics\n' \
      >"$result_directory/phases/$assertion_scenario-$index/java-diagnostics.txt"
  done
  if [[ "$assertion_scenario" == w3c ]]; then
    printf 'discard_standard before=4 after=12 delta=8\n' \
      >"$result_directory/phases/w3c-after/java-diagnostics.delta"
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
    "$requests" == "$FAKE_PREFLIGHT_REQUESTS" && "$keep" == "true" && -n "$seed" &&
    ("$agent" == otel || "$agent" == splunk) && ("$tls" == TLSv1.2 || "$tls" == TLSv1.3) ]] || {
    printf 'invalid fake runner invocation\n' >&2
    return 64
  }
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
      [[ "$transport" == getsockopt ]] || return 64
      assertion_mode="bridge"
      selected_transport="$transport"
      ;;
    *)
      return 64
      ;;
  esac
  result_directory="$FAKE_RESULTS_ROOT/$project"
  SEED="$seed"
  fake_write_runner_artifacts \
    "$result_directory" "$transport" "$agent" "$tls" "$scenario" "$assertion_mode" \
    "$selected_transport" "$project"
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
    printf '0123456789012345678901234567890123456789\n'
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

cleanup_test() {
  if [[ "${KEEP_TEST_TMP:-false}" != "true" && -n "$TEST_TMP_DIR" && -d "$TEST_TMP_DIR" ]]; then
    rm -rf -- "$TEST_TMP_DIR"
  fi
}

trap cleanup_test EXIT

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
  COMPOSE=()
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
      "$REPETITIONS" == 5 && "$SEED" == 20260721 ]]
  ) || {
    printf 'default benchmark options changed unexpectedly\n' >&2
    return 1
  }

  (
    reset_options
    parse_args --output "$output" --warmup-seconds 2 --duration-seconds 600 \
      --concurrency 1 --repetitions 10 --seed 0 --cells core
    [[ "$WARMUP_SECONDS" == 2 && "$DURATION_SECONDS" == 600 && "$CONCURRENCY" == 1 &&
      "$REPETITIONS" == 10 && "$SEED" == 0 ]]
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
  jq -n --arg cell "$cell" '{status: "passed", cell: $cell}' >"$cell_dir/status.json"
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
  local -r non_numeric_metric_result="$TEST_TMP_DIR/non-numeric-metric-result.json"
  local -r fractional_metric_result="$TEST_TMP_DIR/fractional-metric-result.json"

  reset_options
  cell_spec getsockopt-hit
  write_valid_benchmark_result "$benchmark_result" 2
  validate_benchmark_result "$benchmark_result" 2 || {
    printf 'valid benchmark result was rejected\n' >&2
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
    .kind == "descriptive-repetition-summary" and
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
  local command_name=""
  local request=0

  mkdir -p -- "$fake_example/scripts" "$fake_bin" "$output_parent" "$fake_example/.runtime"
  chmod 0755 -- "$fake_example/.runtime"
  install --mode=0755 "$TEST_SCRIPT_DIR/benchmark.sh" "$fake_example/scripts/benchmark.sh"
  ln -s -- "$TEST_SOURCE" "$fake_example/run.sh"
  printf 'services: {}\n' >"$fake_example/docker-compose.yml"
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
    FAKE_EVENTS="$events" \
    FAKE_PID="$$" \
    FAKE_RESULTS_ROOT="$results_root" \
    FAKE_RUNNER_LOG="$runner_log" \
    FAKE_TLS_PROTOCOL=TLSv1.2 \
    "$fake_example/scripts/benchmark.sh" \
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
    .variance == {status: "available", path: "variance.json"}
  ' "$output/summary.json" >/dev/null || {
    printf 'hermetic run did not retain six passing core summaries\n' >&2
    return 1
  }
  jq -e '
    .schema_version == 1 and
    .kind == "descriptive-repetition-summary" and
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
  ! grep -Fq down "$docker_log" || {
    printf 'hermetic run issued a raw Compose down\n' >&2
    return 1
  }
}

main() {
  TEST_TMP_DIR="$(mktemp -d)"
  test_parser_defaults_and_boundaries
  test_lifecycle_tool_paths_must_be_absolute_regular
  test_lifecycle_tool_resolution_rejects_relative_paths
  test_dependency_check_reports_only_invalid_lifecycle_tool
  test_dependency_check_reports_invalid_lifecycle_tool_under_errexit
  test_output_directory_is_absolute_fresh_private
  test_core_cell_mapping_is_exact
  test_json_validators_require_one_document
  test_variance_summary_records_ordered_per_cell_statistics
  test_variance_summary_rejects_invalid_repetition_sets
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
  test_main_uses_runner_cleanup_and_retains_core_artifacts
  printf 'benchmark.sh tests passed\n'
}

main "$@"
