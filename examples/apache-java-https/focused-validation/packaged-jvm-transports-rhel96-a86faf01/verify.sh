#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

readonly script_name="${BASH_SOURCE[0]##*/}"
bundle_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly bundle_dir

on_error() {
  local -r line="$1"
  printf '%s: command failed at line %s\n' "$script_name" "$line" >&2
}

trap 'on_error "$LINENO"' ERR

die() {
  printf '%s: %s\n' "$script_name" "$*" >&2
  exit 1
}

check_dependencies() {
  local -a required=(awk cmp jq sha256sum)
  local -a missing=()
  local command_name=''

  for command_name in "${required[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done

  if (( ${#missing[@]} != 0 )); then
    die "missing required commands: ${missing[*]}"
  fi
}

verify_exact_files() {
  local -a expected=(
    README.md
    SANITIZATION.md
    SHA256SUMS
    benchmark-summary.json
    run-identity.json
    verify.sh
  )
  local -a actual=()
  local index=0
  local retained_file=''

  shopt -s dotglob nullglob
  actual=("$bundle_dir"/*)
  shopt -u dotglob nullglob

  (( ${#actual[@]} == ${#expected[@]} )) ||
    die 'bundle must contain exactly the six declared files'

  for index in "${!expected[@]}"; do
    [[ "${actual[$index]##*/}" == "${expected[$index]}" ]] ||
      die 'bundle contains an unexpected, missing, or out-of-order file'
  done

  for retained_file in "${expected[@]}"; do
    [[ -f "$bundle_dir/$retained_file" && ! -L "$bundle_dir/$retained_file" ]] ||
      die "retained evidence file must be a regular non-symlink: $retained_file"
  done
}

verify_manifest() {
  local -a expected=(
    README.md
    SANITIZATION.md
    benchmark-summary.json
    run-identity.json
    verify.sh
  )
  local -a actual=()
  local manifest_output=''
  local index=0

  if ! manifest_output="$(
    awk '
      NF != 2 ||
      length($1) != 64 ||
      $1 !~ /^[0-9a-f]+$/ ||
      $2 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ ||
      substr($0, 65, 2) != "  " ||
      substr($0, 67) != $2 {
        exit 2
      }
      {
        count += 1
        print $2
      }
      END {
        if (count != 5) {
          exit 2
        }
      }
    ' SHA256SUMS
  )"; then
    die 'SHA256SUMS contains an invalid, missing, or extra entry'
  fi

  mapfile -t actual <<<"$manifest_output"
  (( ${#actual[@]} == ${#expected[@]} )) ||
    die 'SHA256SUMS must contain exactly five entries'

  for index in "${!expected[@]}"; do
    [[ "${actual[$index]}" == "${expected[$index]}" ]] ||
      die 'SHA256SUMS must contain the exact ordered evidence file set once'
  done

  sha256sum --check --strict SHA256SUMS
}

verify_canonical_json() {
  local json_file=''

  for json_file in benchmark-summary.json run-identity.json; do
    jq --exit-status --slurp 'length == 1' -- "$json_file" >/dev/null ||
      die "JSON evidence must contain exactly one valid document: $json_file"
    cmp --silent -- "$json_file" <(jq --compact-output --sort-keys . -- "$json_file") ||
      die "JSON evidence must be canonical and contain no duplicate keys: $json_file"
  done
}

verify_frozen_json_identity() {
  local summary_identity=''
  local run_identity=''
  local -r expected_summary_identity='e87081f44153bd5c72834df4c1548df19a3a8302233b342c2f699411f7ad9c9a  benchmark-summary.json'
  local -r expected_run_identity='2459c635f7edfb2cce307a7ea31e84ca4a5000ad136538ba5c7ad291f715e75d  run-identity.json'

  summary_identity="$(sha256sum -- benchmark-summary.json)"
  [[ "$summary_identity" == "$expected_summary_identity" ]] ||
    die 'benchmark summary byte identity does not match the retained schema-v2 projection'

  run_identity="$(sha256sum -- run-identity.json)"
  [[ "$run_identity" == "$expected_run_identity" ]] ||
    die 'run identity byte identity does not match the retained provenance'
}

verify_identity_contract() {
  jq --exit-status '
    . == {
      "format": 1,
      "kind": "focused-rhel96-packaged-jvm-transports-schema-v2",
      "provenance": {
        "artifact_name": "java-remote-parent-rhel9.6-kernel-sockopt-31839215163",
        "github_artifact_id": 9233961250,
        "repository": "MrAlias/opentelemetry-ebpf-instrumentation",
        "workflow": {
          "conclusion": "success",
          "path": ".github/workflows/java_remote_parent_rhel.yml",
          "run_attempt": 1,
          "run_id": 31839215163,
          "run_url": "https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31839215163"
        }
      },
      "raw_evidence": {
        "github_archive": {
          "retained_in_repository": false,
          "sha256": "d0c39375633205f0d556727d16d810005611028ca4beecd99eda2150c49d4455",
          "size_bytes": 36207445,
          "source_name": "java-remote-parent-rhel9.6-kernel-sockopt-31839215163"
        },
        "packaged_benchmark": {
          "retained_in_repository": false,
          "schema_version": 2,
          "sha256": "794d16ab745d8b7cd0d0a413ac6b17d78fe017e16dce9e9695441de18c89ba21",
          "size_bytes": 371859,
          "source_filename": "benchmark.json"
        }
      },
      "result": {
        "benchmark": "passed",
        "ci_compiled_crosslink_validator": "passed",
        "ci_compiled_decoder": "passed",
        "sanitized_bundle": "passed"
      },
      "scope": {
        "acceptance_evidence": false,
        "advances_issues": [11, 18, 20, 37],
        "closes_issues": [],
        "evidence_class": "focused_non_acceptance",
        "execution_environment": "github_actions_digest_pinned_rhel96_kernel_vm",
        "limitations": [
          "not_rhel_userspace_compatibility",
          "not_apache_application_acceptance",
          "no_application_request_or_throughput",
          "no_process_or_native_resource_growth",
          "no_run_to_run_variance",
          "no_native_sanitizers",
          "revisionless_boundary_identity_only_topology"
        ],
        "public_ci_locator_available": true
      },
      "source": {
        "clean": true,
        "patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "repository": "MrAlias/opentelemetry-ebpf-instrumentation",
        "revision": "a86faf0170d237df66055d22e1f316ff693d890a",
        "status_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "summary_file": "benchmark-summary.json",
      "validation": {
        "cleanup": {
          "authorized_process_keys_absent": true,
          "bpf_resources_closed": true,
          "derivation": "successful benchmark publication gate",
          "direct_hierarchy_chains_empty": true,
          "effective_chains_empty": true,
          "intended_program_ids_absent": true,
          "process_incarnation_keys_absent": true
        },
        "compiled_crosslink_validator": {
          "ci_result": "passed",
          "test": "TestValidatePackagedJVMBenchmarkArtifactCICrosslinks"
        },
        "compiled_decoder": {
          "ci_result": "passed",
          "loads_bpf": false,
          "test": "TestValidatePackagedJVMBenchmarkArtifactFile"
        },
        "projection": {
          "allocation_control_samples_retained": 28672,
          "allocation_samples_retained": 28672,
          "latency_samples_retained": 28672,
          "raw_schema_version": 2,
          "series_retained": 14
        },
        "raw_archive_matches_github_metadata": true,
        "raw_artifact_matches_declared_identity": true,
        "raw_projection_recomputed": true
      }
    }
  ' run-identity.json >/dev/null ||
    die 'run identity does not match the retained claim contract'
}

verify_summary_contract() {
  jq --exit-status '
    def exact_keys($expected):
      keys == $expected;
    def integer:
      type == "number" and . == floor;
    def nonnegative_integer:
      integer and . >= 0;
    def program_keys:
      exact_keys(["name", "program_type", "tag"]);
    def nearest_rank($samples; $percent):
      ($samples | sort) as $sorted |
      ($sorted | length) as $count |
      $sorted[((($count * $percent / 100) | ceil) - 1)];
    def retained_summary($samples; $total; $p50; $p95; $p99; $positive):
      ($samples | length) == 2048 and
      all($samples[]; nonnegative_integer and (if $positive then . > 0 else true end)) and
      ($samples | add) == $total and
      nearest_rank($samples; 50) == $p50 and
      nearest_rank($samples; 95) == $p95 and
      nearest_rank($samples; 99) == $p99;
    def status_name:
      if .expected_status == 1 then "valid"
      elif .expected_status == 2 then "missing"
      elif .expected_status == 3 then "stale"
      elif .expected_status == 10 then "timeout"
      else "invalid"
      end;
    def selected_status_count:
      if .expected_status == 1 then .status_counts.valid
      elif .expected_status == 2 then .status_counts.missing
      elif .expected_status == 3 then .status_counts.stale
      elif .expected_status == 10 then .status_counts.timeout
      else -1
      end;
    def status_consistent:
      (.status_counts | exact_keys([
        "already_consumed", "ambiguous", "disabled", "malformed", "missing",
        "overload", "stale", "timeout", "transport_error", "unauthorized",
        "unknown", "unsupported", "valid", "version_mismatch"
      ])) and
      all(.status_counts[]; nonnegative_integer) and
      (.status_counts | [.[]] | add) == 2176 and
      selected_status_count == 2176;
    def calls_consistent:
      (.call_counts | exact_keys([
        "expected_bridge_calls", "expected_java_calls", "expected_native_calls",
        "expected_primary_bpf_calls", "expected_timeout_full_requests",
        "expected_unix_server_requests", "observed_bridge_calls",
        "observed_java_calls", "observed_native_calls", "observed_primary_bpf_calls",
        "observed_timeout_full_requests", "observed_unix_server_requests",
        "primary_bpf_status", "primary_bpf_status_after", "primary_bpf_status_before",
        "unix_server_status", "unix_server_status_after", "unix_server_status_before"
      ])) and
      (.scope == "bridge_provider_jni") as $provider |
      (.transport == "getsockopt") as $primary |
      (.transport == "unix") as $unix |
      (.outcome == "timeout") as $timeout |
      .call_counts.expected_java_calls == 2176 and
      .call_counts.observed_java_calls == 2176 and
      .call_counts.expected_native_calls == 2176 and
      .call_counts.observed_native_calls == 2176 and
      .call_counts.expected_bridge_calls == (if $provider then 2176 else 0 end) and
      .call_counts.observed_bridge_calls == .call_counts.expected_bridge_calls and
      .call_counts.expected_primary_bpf_calls == (if $primary then 2176 else 0 end) and
      .call_counts.observed_primary_bpf_calls == .call_counts.expected_primary_bpf_calls and
      .call_counts.expected_unix_server_requests ==
        (if $unix and ($timeout | not) then 2176 else 0 end) and
      .call_counts.observed_unix_server_requests == .call_counts.expected_unix_server_requests and
      .call_counts.expected_timeout_full_requests == (if $timeout then 2176 else 0 end) and
      .call_counts.observed_timeout_full_requests == .call_counts.expected_timeout_full_requests and
      (if $primary then
        .call_counts.primary_bpf_status == status_name and
        (.call_counts.primary_bpf_status_before | nonnegative_integer) and
        (.call_counts.primary_bpf_status_after | nonnegative_integer) and
        .call_counts.primary_bpf_status_after >= .call_counts.primary_bpf_status_before and
        (.call_counts.primary_bpf_status_after - .call_counts.primary_bpf_status_before) == 2176
      else
        .call_counts.primary_bpf_status == "not_applicable" and
        .call_counts.primary_bpf_status_before == 0 and
        .call_counts.primary_bpf_status_after == 0
      end) and
      (if $unix then
        .call_counts.unix_server_status == status_name and
        (.call_counts.unix_server_status_before | nonnegative_integer) and
        (.call_counts.unix_server_status_after | nonnegative_integer) and
        .call_counts.unix_server_status_after >= .call_counts.unix_server_status_before and
        (.call_counts.unix_server_status_after - .call_counts.unix_server_status_before) == 2176
      else
        .call_counts.unix_server_status == "not_applicable" and
        .call_counts.unix_server_status_before == 0 and
        .call_counts.unix_server_status_after == 0
      end);
    def gate_consistent:
      (.latency_gate | exact_keys(["kind", "p50_min_ns", "p99_max_ns", "passed"])) and
      (if .transport == "getsockopt" then
        .latency_gate.kind == "p99_lt" and
        .latency_gate.p50_min_ns == 0 and
        .latency_gate.p99_max_ns == 1000000 and
        .latency_gate.passed == (.p99_ns < 1000000)
      elif .outcome == "timeout" then
        .latency_gate.kind == "p50_gte_p99_lte" and
        .latency_gate.p50_min_ns == 50000000 and
        .latency_gate.p99_max_ns == 100000000 and
        .latency_gate.passed == (.p50_ns >= 50000000 and .p99_ns <= 100000000)
      else
        .latency_gate.kind == "p99_lt" and
        .latency_gate.p50_min_ns == 0 and
        .latency_gate.p99_max_ns == 50000000 and
        .latency_gate.passed == (.p99_ns < 50000000)
      end);
    def series_consistent:
      exact_keys([
        "allocation", "call_counts", "correct", "expected_status", "latency_gate",
        "outcome", "p50_ns", "p95_ns", "p99_ns", "samples_ns", "scope",
        "status_counts", "total_timed_ns", "transport"
      ]) and
      (.scope == "raw_jni" or .scope == "bridge_provider_jni") and
      (.transport == "getsockopt" or .transport == "unix") and
      retained_summary(.samples_ns; .total_timed_ns; .p50_ns; .p95_ns; .p99_ns; true) and
      (.allocation | exact_keys([
        "control", "control_p50_bytes", "control_p95_bytes", "control_p99_bytes",
        "control_samples_bytes", "control_total_bytes", "method", "p50_bytes",
        "p95_bytes", "p99_bytes", "samples_bytes", "total_bytes"
      ])) and
      .allocation.method == "com.sun.management.ThreadMXBean.getThreadAllocatedBytes" and
      .allocation.control == "paired consecutive counter reads on the same worker" and
      retained_summary(
        .allocation.samples_bytes; .allocation.total_bytes; .allocation.p50_bytes;
        .allocation.p95_bytes; .allocation.p99_bytes; false
      ) and
      retained_summary(
        .allocation.control_samples_bytes; .allocation.control_total_bytes;
        .allocation.control_p50_bytes; .allocation.control_p95_bytes;
        .allocation.control_p99_bytes; false
      ) and
      status_consistent and calls_consistent and .correct == true and gate_consistent;

    exact_keys([
      "benchmark", "format", "inputs", "raw_archive_sha256", "raw_artifact_sha256",
      "raw_schema_version", "result", "run_identity_file", "runtime", "scope", "series",
      "setup", "source_revision", "topology", "transport_attribution"
    ]) and
    .benchmark == "java_remote_parent_packaged_jvm_transport" and
    .format == 1 and
    .raw_schema_version == 2 and
    .raw_archive_sha256 == "d0c39375633205f0d556727d16d810005611028ca4beecd99eda2150c49d4455" and
    .raw_artifact_sha256 == "794d16ab745d8b7cd0d0a413ac6b17d78fe017e16dce9e9695441de18c89ba21" and
    .result == "passed" and
    .run_identity_file == "run-identity.json" and
    .source_revision == "a86faf0170d237df66055d22e1f316ff693d890a" and
    .inputs == {
      "agent_artifact": {
        "sha256": "6d1a456fdac1c29b4b1e7cc6eaff02f8c353c9181c368e960aec1e24fb27cc61",
        "size_bytes": 4559094
      },
      "go_toolchain": "go1.26.3",
      "sockops_bpf": {
        "sha256": "9113f2e269ec536e0be693da4906cb29571dced8564d4fd4cb2553b830d7343e",
        "size_bytes": 978584
      },
      "sockopt_bpf": {
        "sha256": "5920e506a80857541b0a95a5f5b19e91d438b37ed740312b94e965833190364e",
        "size_bytes": 798320
      },
      "test_binary": {
        "sha256": "4e597a33264f7611809a0ed127b720ae588d65e10248d29456b8373b5b6911ca",
        "size_bytes": 74864647
      }
    } and
    .runtime == {
      "architecture": "amd64",
      "bpf_descriptors": 0,
      "cgroup": {"hierarchy_depth": 2, "mode": "v2"},
      "cpu_model": "AMD EPYC 9V74 80-Core Processor",
      "java": {
        "capabilities": "all_zero",
        "distribution": "Oracle OpenJDK (Alpine package)",
        "executable_sha256": "af2a90f0fb3ac07fce3a4c9990405890f7c5353d7c926e6e7644f796b831e00f",
        "feature": 21,
        "identity": "unprivileged child",
        "no_new_privileges": true,
        "package": "openjdk21-jre-headless-21.0.12_p8-r0",
        "version": "21.0.12+8-alpine-r0"
      },
      "kernel": {
        "config_sha256": "ad5594081ce812d0db0e094bb5b02020232c49dcb59f1cca013b23c3ab6d17bc",
        "family": "5.14",
        "image_sha256": "6f0fb81f341995adae2bf17970a7b640236a0d4a3c7d89b267fdbfdd2d8afc1e",
        "lvh_digest": "sha256:ae4ce64faec9c87b702a89ca48bba9e8798861d199942bd8ebddf1937ee098ad",
        "lvh_tag": "rhel9.6-20260720.023802",
        "release": "5.14.0",
        "target": "RHEL 9.6"
      },
      "logical_cpus": 2,
      "memory_total_bytes": 8323371008,
      "userspace": "Alpine Linux 3.23.4"
    } and
    .scope == {
      "acceptance_evidence": false,
      "evidence_class": "focused_non_acceptance",
      "excludes": [
        "application_request", "instrumentation", "throughput", "application_throughput",
        "process_cpu", "rss_growth", "native_memory_growth", "direct_memory_growth",
        "fd_growth", "thread_growth", "map_growth", "run_to_run_variance", "native_sanitizers"
      ],
      "harness": "packaged_agent_java_concurrent_transport",
      "measures": [
        "packaged_agent", "java_workers", "raw_jni", "bridge_provider", "jni",
        "kernel_getsockopt", "cgroup_bpf", "unix_server", "thread_allocated_bytes"
      ]
    } and
    (.setup | exact_keys([
      "agent_artifact_binding", "agent_options", "allocation_control",
      "allocation_measurement", "batch_synchronization", "concurrency",
      "environment_keys", "environment_policy", "jvm_arguments", "measurement_batches",
      "primary_miss_control", "provider_timed_call", "raw_timed_call", "response_storage",
      "retained_calls_per_series", "retrieval_ttl_ns", "stale_age_ns",
      "total_calls_per_series", "unix_max_concurrent", "unix_miss_control",
      "unix_server_identity", "unix_socket_group_identity", "unix_timeout_deadline_ns",
      "warmup_batches"
    ])) and
    .setup.warmup_batches == 16 and
    .setup.measurement_batches == 256 and
    .setup.concurrency == 8 and
    .setup.retained_calls_per_series == 2048 and
    .setup.total_calls_per_series == 2176 and
    .setup.unix_timeout_deadline_ns == 50000000 and
    .setup.retrieval_ttl_ns == 30000000000 and
    .setup.stale_age_ns == 31000000000 and
    .setup.unix_max_concurrent == 32 and
    .setup.agent_options == "remoteParentTransport=disabled" and
    .setup.environment_keys == ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ"] and
    .setup.environment_policy ==
      "fixed minimal child environment; no inherited loader or implicit-JVM controls" and
    .setup.unix_server_identity == "privileged root-owned server" and
    .setup.unix_socket_group_identity == "Java child primary group" and
    (.series | length) == 14 and
    (.series | map([.scope, .transport, .outcome, .expected_status])) == [
      ["raw_jni", "getsockopt", "miss", 2],
      ["raw_jni", "getsockopt", "hit", 1],
      ["raw_jni", "getsockopt", "stale", 3],
      ["bridge_provider_jni", "getsockopt", "miss", 2],
      ["bridge_provider_jni", "getsockopt", "hit", 1],
      ["bridge_provider_jni", "getsockopt", "stale", 3],
      ["raw_jni", "unix", "miss", 2],
      ["raw_jni", "unix", "hit", 1],
      ["raw_jni", "unix", "stale", 3],
      ["bridge_provider_jni", "unix", "miss", 2],
      ["bridge_provider_jni", "unix", "hit", 1],
      ["bridge_provider_jni", "unix", "stale", 3],
      ["raw_jni", "unix", "timeout", 10],
      ["bridge_provider_jni", "unix", "timeout", 10]
    ] and
    all(.series[]; series_consistent) and
    (.series | map(.samples_ns | length) | add) == 28672 and
    (.series | map(.allocation.samples_bytes | length) | add) == 28672 and
    (.series | map(.allocation.control_samples_bytes | length) | add) == 28672 and
    (.series | map(.total_timed_ns) | add) == 221976716987 and
    (.series | map(.allocation.total_bytes) | add) == 3894776 and
    (.series | map(.allocation.control_total_bytes) | add) == 0 and
    (.series | map(.call_counts.observed_java_calls) | add) == 30464 and
    (.series | map(.call_counts.observed_native_calls) | add) == 30464 and
    (.series | map(.call_counts.observed_bridge_calls) | add) == 15232 and
    (.series | map(.call_counts.observed_primary_bpf_calls) | add) == 13056 and
    (.series | map(.call_counts.observed_unix_server_requests) | add) == 13056 and
    (.series | map(.call_counts.observed_timeout_full_requests) | add) == 4352 and
    (.topology | exact_keys([
      "chains", "effective_query", "exclusive_topology_premise", "hierarchy_depth",
      "post_run_cleanup", "pre_attach_chains_empty", "stability_checks",
      "stability_evidence", "stability_mode"
    ])) and
    (.topology | del(.chains)) == {
      "effective_query": {"flag": "BPF_F_QUERY_EFFECTIVE", "flags": 1},
      "exclusive_topology_premise": "operator_controlled_no_concurrent_cgroup_bpf_mutation",
      "hierarchy_depth": 2,
      "post_run_cleanup": {
        "direct_hierarchy_chains_empty": true,
        "effective_chains_empty": true,
        "intended_program_ids_absent": true
      },
      "pre_attach_chains_empty": true,
      "stability_checks": {
        "expected_batches": 3808,
        "expected_primary_calls": 13056,
        "observed_post_batch_snapshots": 3808,
        "observed_pre_batch_snapshots": 3808,
        "query_errors": 0,
        "topology_mismatches": 0
      },
      "stability_evidence":
        "exact boundary identities unchanged; attach-detach completed between queries cannot be excluded",
      "stability_mode": "boundary_identity_only"
    } and
    .topology.stability_checks.expected_batches ==
      ((.series | length) * (.setup.warmup_batches + .setup.measurement_batches)) and
    .topology.stability_checks.expected_primary_calls ==
      (([.series[] | select(.transport == "getsockopt")] | length) * .setup.total_calls_per_series) and
    (.topology.chains | length) == 3 and
    all(.topology.chains[];
      exact_keys(["attach_type", "direct_hierarchy", "effective_post_attach", "intended_program"]) and
      (.intended_program | program_keys) and
      (.effective_post_attach |
        exact_keys(["program_count", "programs", "revision", "revision_supported"])) and
      .effective_post_attach.program_count == 1 and
      (.effective_post_attach.programs | length) == 1 and
      (.effective_post_attach.programs[0] | program_keys) and
      .effective_post_attach.programs[0] == .intended_program and
      .effective_post_attach.revision == 0 and
      .effective_post_attach.revision_supported == false and
      (.direct_hierarchy | length) == 2 and
      all(.direct_hierarchy[];
        exact_keys(["level", "program_count", "programs", "revision", "revision_supported", "role"]) and
        .revision == 0 and
        .revision_supported == false and
        all(.programs[]; program_keys)) and
      (.direct_hierarchy | map(.level)) == [0, 1] and
      (.direct_hierarchy | map(.role)) == ["root", "target"] and
      (.direct_hierarchy | map(.program_count)) == [0, 1] and
      (.direct_hierarchy | map(.programs | length)) == [0, 1] and
      .direct_hierarchy[1].programs[0] == .intended_program) and
    (.topology.chains | map(.attach_type)) == [
      "CGroupGetsockopt", "CGroupSetsockopt", "CGroupSockOps"
    ] and
    (.topology.chains | map(.intended_program)) == [
      {"name": "obi_java_remote_parent_getsockopt", "program_type": "CGroupSockopt", "tag": "ac77d58abf02d07c"},
      {"name": "obi_java_remote_parent_setsockopt", "program_type": "CGroupSockopt", "tag": "f2764727e43225a4"},
      {"name": "obi_sockmap_tracker", "program_type": "SockOps", "tag": "08eb6e4d1a509638"}
    ] and
    .topology.hierarchy_depth == .runtime.cgroup.hierarchy_depth and
    .transport_attribution == {
      "unix": {
        "handler": "javabridge.NewMapHandler over the benchmark BPF maps",
        "observer": "ServerOptions.Observe exactly one NEGOTIATE/MISSING configuration and exact TAKE status counters",
        "server": "javabridge.NewServer production authenticated Unix server in an identity-bound temporary child removed and proven absent per series",
        "socket_path_retained": false,
        "timeout_fixture": "production Unix server handler waits for the request deadline and returns TIMEOUT after a complete authenticated request"
      }
    }
  ' benchmark-summary.json >/dev/null ||
    die 'benchmark summary does not match or recompute to the strict schema-v2 projection contract'
}

verify_crosslinks() {
  jq --exit-status --null-input \
    --slurpfile identity run-identity.json \
    --slurpfile summary benchmark-summary.json '
      ($identity | length) == 1 and
      ($summary | length) == 1 and
      $identity[0].source.revision == $summary[0].source_revision and
      $identity[0].raw_evidence.github_archive.sha256 == $summary[0].raw_archive_sha256 and
      $identity[0].raw_evidence.packaged_benchmark.sha256 == $summary[0].raw_artifact_sha256 and
      $identity[0].raw_evidence.packaged_benchmark.schema_version == $summary[0].raw_schema_version and
      $identity[0].summary_file == "benchmark-summary.json" and
      $summary[0].run_identity_file == "run-identity.json" and
      $identity[0].result.benchmark == $summary[0].result and
      $identity[0].scope.evidence_class == $summary[0].scope.evidence_class and
      $identity[0].scope.acceptance_evidence == $summary[0].scope.acceptance_evidence and
      $identity[0].validation.projection.series_retained == ($summary[0].series | length) and
      $identity[0].validation.projection.latency_samples_retained ==
        ($summary[0].series | map(.samples_ns | length) | add) and
      $identity[0].validation.projection.allocation_samples_retained ==
        ($summary[0].series | map(.allocation.samples_bytes | length) | add) and
      $identity[0].validation.projection.allocation_control_samples_retained ==
        ($summary[0].series | map(.allocation.control_samples_bytes | length) | add) and
      $identity[0].validation.cleanup.direct_hierarchy_chains_empty ==
        $summary[0].topology.post_run_cleanup.direct_hierarchy_chains_empty and
      $identity[0].validation.cleanup.effective_chains_empty ==
        $summary[0].topology.post_run_cleanup.effective_chains_empty and
      $identity[0].validation.cleanup.intended_program_ids_absent ==
        $summary[0].topology.post_run_cleanup.intended_program_ids_absent
    ' >/dev/null ||
    die 'retained JSON cross-links do not agree'
}

verify_sanitization_contract() {
  jq --exit-status --slurp '
    def forbidden_key:
      . == "created_at" or
      . == "timestamp" or
      . == "timestamps" or
      . == "device" or
      . == "inode" or
      . == "id" or
      . == "ids" or
      . == "program_id" or
      . == "program_ids" or
      . == "target_cgroup" or
      . == "cgroup_path" or
      . == "cgroup_hierarchy" or
      . == "java_executable" or
      . == "java_uid" or
      . == "java_gid" or
      . == "unix_server_uid" or
      . == "unix_socket_gid" or
      . == "uid" or
      . == "gid" or
      . == "username" or
      . == "hostname";
    [.. | objects | keys[] | select(forbidden_key)] | length == 0
  ' benchmark-summary.json run-identity.json >/dev/null ||
    die 'retained JSON contains a forbidden operational key'

  jq --exit-status --slurp '
    [
      .. | strings |
      select(
        test("^/") or
        test("/(?:build|proc|sys|tmp)/") or
        test("/sys/fs/cgroup") or
        test("openrc\\.startup") or
        test("session-[0-9]+\\.scope") or
        test("user-[0-9]+\\.slice") or
        test("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:")
      )
    ] | length == 0
  ' benchmark-summary.json run-identity.json >/dev/null ||
    die 'retained JSON contains a forbidden operational string'

  jq --exit-status '
    (.inputs.test_binary | keys) == ["sha256", "size_bytes"] and
    (.inputs.agent_artifact | keys) == ["sha256", "size_bytes"] and
    .setup.environment_keys == ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ"] and
    (.setup | has("environment") | not) and
    all(.topology.chains[].intended_program; has("id") | not) and
    all(.topology.chains[].effective_post_attach.programs[]; has("id") | not) and
    all(.topology.chains[].direct_hierarchy[].programs[]; has("id") | not)
  ' benchmark-summary.json >/dev/null ||
    die 'retained JSON does not implement the declared normalization contract'
}

main() {
  (( $# == 0 )) || die 'this verifier accepts no arguments'
  check_dependencies
  cd -- "$bundle_dir"
  verify_exact_files
  verify_manifest
  verify_canonical_json
  verify_frozen_json_identity
  verify_identity_contract
  verify_summary_contract
  verify_crosslinks
  verify_sanitization_contract
  printf 'RHEL 9.6 packaged-JVM schema-v2 transport focused evidence verified\n'
}

main "$@"
