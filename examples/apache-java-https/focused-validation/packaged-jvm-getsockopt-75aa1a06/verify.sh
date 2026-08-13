#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

readonly script_name="${BASH_SOURCE[0]##*/}"
bundle_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly bundle_dir

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
    cmp --silent -- "$json_file" <(jq --sort-keys --indent 2 . -- "$json_file") ||
      die "JSON evidence must be canonical and contain no duplicate keys: $json_file"
  done
}

verify_identity() {
  jq --exit-status '
    . == {
      "format": 1,
      "kind": "focused-packaged-jvm-getsockopt",
      "raw_artifact": {
        "retained": false,
        "sha256": "ad9f0cd2b2d33dc0402821eb87b3de9e0c23750a423cba262246964841e9b7a5",
        "size_bytes": 9837,
        "source_filename": "packaged-jvm-getsockopt.json"
      },
      "result": {
        "benchmark": "passed",
        "compiled_decoder": "passed",
        "sanitized_bundle": "passed"
      },
      "scope": {
        "acceptance_evidence": false,
        "advances_issues": [11, 20, 37],
        "closes_issues": [],
        "evidence_class": "focused_non_acceptance",
        "execution_environment": "local_upstream_host",
        "limitations": [
          "no_public_ci_locator",
          "not_rhel9_matrix_evidence",
          "not_apache_application_acceptance",
          "no_allocations_or_resource_growth",
          "no_concurrency_or_run_to_run_variance"
        ],
        "public_ci_locator_available": false,
        "public_ci_locator_reason": "execution was a local upstream-host run"
      },
      "source": {
        "clean": true,
        "patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "repository": "MrAlias/opentelemetry-ebpf-instrumentation",
        "revision": "75aa1a06afad7777cfc67b0632ae8f3402f40264",
        "status_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "summary_file": "benchmark-summary.json",
      "validation": {
        "compiled_decoder": {
          "loads_bpf": false,
          "result": "passed",
          "test": "TestValidatePackagedJVMBenchmarkArtifactFile"
        },
        "post_run_topology": {
          "direct_hierarchy_chains_empty": true,
          "effective_chains_empty": true,
          "intended_program_ids_absent": true
        },
        "raw_artifact_matches_declared_identity": true
      }
    }
  ' run-identity.json >/dev/null || die 'run identity does not match the retained claim contract'
}

verify_summary_contract() {
  local summary_sha256=''

  summary_sha256="$(sha256sum -- benchmark-summary.json)"
  [[ "$summary_sha256" == '0359af19c394b15b62f5d3bbe546e875254e72eed22d1a2bc2d1348daec39a35  benchmark-summary.json' ]] ||
    die 'benchmark summary byte identity does not match the retained sample arrays'

  jq --exit-status '
    def exact_keys($expected): keys == $expected;
    def program_keys:
      exact_keys(["name", "program_type", "tag"]);
    def nearest_rank($samples; $percent):
      ($samples | sort) as $sorted |
      ($sorted | length) as $count |
      $sorted[((($count * $percent / 100) | ceil) - 1)];
    def series_consistent:
      (.samples_ns | length) == .sample_count and
      (.samples_ns | add) == .total_timed_ns and
      (.samples_ns | min) == .min_ns and
      (.samples_ns | max) == .max_ns and
      nearest_rank(.samples_ns; 50) == .p50_ns and
      nearest_rank(.samples_ns; 95) == .p95_ns and
      nearest_rank(.samples_ns; 99) == .p99_ns and
      all(.samples_ns[]; type == "number" and . >= 0 and . == floor) and
      .missing + .valid == .sample_count and
      .latency_gate.passed == (.p99_ns < .latency_gate.p99_max_ns);

    . as $summary |
    exact_keys([
      "benchmark",
      "format",
      "inputs",
      "raw_artifact_sha256",
      "result",
      "run_identity_file",
      "runtime",
      "scope",
      "series",
      "setup",
      "source_revision",
      "topology"
    ]) and
    .benchmark == "java_remote_parent_packaged_jvm_getsockopt" and
    .format == 1 and
    .raw_artifact_sha256 == "ad9f0cd2b2d33dc0402821eb87b3de9e0c23750a423cba262246964841e9b7a5" and
    .result == "passed" and
    .run_identity_file == "run-identity.json" and
    .source_revision == "75aa1a06afad7777cfc67b0632ae8f3402f40264" and
    .inputs == {
      "agent_artifact": {
        "sha256": "040088653332dbadcf0d3b7ed8c3f5e141d2b0d39c05b4e50a8d5b7412101ade",
        "size_bytes": 4549438
      },
      "go_toolchain": "go1.26.5",
      "sockops_bpf": {
        "sha256": "9113f2e269ec536e0be693da4906cb29571dced8564d4fd4cb2553b830d7343e",
        "size_bytes": 978584
      },
      "sockopt_bpf": {
        "sha256": "5920e506a80857541b0a95a5f5b19e91d438b37ed740312b94e965833190364e",
        "size_bytes": 798320
      },
      "test_binary": {
        "sha256": "5892686c13ce413e2c9698c65783eacc6a6d70f3f85275e14a54ef155ee78c8d",
        "size_bytes": 74493606
      }
    } and
    .runtime == {
      "architecture": "amd64",
      "bpf_descriptors": 0,
      "cgroup": {"hierarchy_depth": 4, "mode": "v2"},
      "cpu_model": "Intel(R) Xeon(R) Platinum 8223CL CPU @ 3.00GHz",
      "java": {
        "capabilities": "all_zero",
        "distribution": "Eclipse Temurin",
        "feature": 21,
        "no_new_privileges": true,
        "version": "21.0.11+10 LTS"
      },
      "kernel_release": "7.0.0-1010-aws",
      "logical_cpus": 36,
      "memory_total_bytes": 74243411968
    } and
    .scope == {
      "evidence_class": "focused_non_acceptance",
      "excludes": [
        "application_request",
        "instrumentation",
        "provider_selection",
        "record_decode",
        "unix_transport",
        "throughput",
        "allocations",
        "resource_growth",
        "concurrency",
        "run_to_run_variance"
      ],
      "harness": "packaged_agent_java_jni_cgroup_getsockopt",
      "measures": [
        "packaged_agent",
        "java_native_call",
        "jni",
        "kernel_getsockopt",
        "cgroup_bpf"
      ]
    } and
    .setup == {
      "agent_artifact_binding": "opened read-only fd 3; fstat and SHA-256 before and after execution",
      "agent_options": "remoteParentTransport=disabled",
      "concurrency": 1,
      "environment_keys": ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ"],
      "environment_policy": "fixed minimal child environment; no inherited loader or implicit-JVM controls",
      "jvm_arguments": [
        "-javaagent:<agent-artifact-fd>=remoteParentTransport=disabled",
        "-cp",
        "<agent-artifact-fd>",
        "io.opentelemetry.obi.java.probe.RemoteParentGetsockoptBenchmarkProbe"
      ],
      "measurement_iterations": 256,
      "miss_control": "assert exact negotiated process, incarnation, connection, namespace, and generation; delete only java_remote_parent_state; retain and exactly assert owner and generation index; preserve generation; restore state; run full cleanup",
      "response_storage": "one reused 64-byte Java byte array",
      "timed_call": "System.nanoTime around BootstrapNative.takeRemoteParent(fd,reused_byte_array)",
      "warmup_iterations": 16
    } and
    (.series | length) == 2 and
    all(.series[];
      exact_keys([
        "correct",
        "errors",
        "expected_status",
        "latency_gate",
        "max_ns",
        "min_ns",
        "missing",
        "outcome",
        "p50_ns",
        "p95_ns",
        "p99_ns",
        "sample_count",
        "samples_ns",
        "total_timed_ns",
        "valid",
        "warmup_iterations"
      ]) and
      (.latency_gate | exact_keys(["kind", "p99_max_ns", "passed"])) and
      series_consistent) and
    (.series | map(del(.samples_ns))) == [
      {
        "correct": true,
        "errors": 0,
        "expected_status": 2,
        "latency_gate": {"kind": "p99_lt", "p99_max_ns": 1000000, "passed": true},
        "max_ns": 27450,
        "min_ns": 4092,
        "missing": 256,
        "outcome": "miss",
        "p50_ns": 7379,
        "p95_ns": 8387,
        "p99_ns": 19997,
        "sample_count": 256,
        "total_timed_ns": 1840801,
        "valid": 0,
        "warmup_iterations": 16
      },
      {
        "correct": true,
        "errors": 0,
        "expected_status": 1,
        "latency_gate": {"kind": "p99_lt", "p99_max_ns": 1000000, "passed": true},
        "max_ns": 35211,
        "min_ns": 11261,
        "missing": 0,
        "outcome": "hit",
        "p50_ns": 16131,
        "p95_ns": 17825,
        "p99_ns": 25049,
        "sample_count": 256,
        "total_timed_ns": 4034635,
        "valid": 256,
        "warmup_iterations": 16
      }
    ] and
    (.series | map(.sample_count) | add) == 512 and
    (.series | map(.errors) | add) == 0 and
    (.series | map(.missing) | add) == 256 and
    (.series | map(.valid) | add) == 256 and
    (.topology | exact_keys([
      "chains",
      "direct_revision_support_complete",
      "effective_query",
      "exclusive_topology_premise",
      "hierarchy_depth",
      "post_run_cleanup",
      "pre_attach_chains_empty",
      "stability_checks",
      "stability_evidence",
      "stability_mode"
    ])) and
    (.topology | del(.chains)) == {
      "direct_revision_support_complete": true,
      "effective_query": {"flag": "BPF_F_QUERY_EFFECTIVE", "flags": 1},
      "exclusive_topology_premise": "not_required_all_direct_queries_revision_supported",
      "hierarchy_depth": 4,
      "post_run_cleanup": {
        "direct_hierarchy_chains_empty": true,
        "effective_chains_empty": true,
        "intended_program_ids_absent": true
      },
      "pre_attach_chains_empty": true,
      "stability_checks": {
        "expected_calls": 544,
        "observed_post_call_snapshots": 544,
        "observed_pre_call_snapshots": 544,
        "query_errors": 0,
        "topology_mismatches": 0
      },
      "stability_evidence": "exact boundary identities and supported direct revisions unchanged",
      "stability_mode": "revision_and_identity"
    } and
    (.topology.stability_checks.expected_calls ==
      (2 * (.setup.warmup_iterations + .setup.measurement_iterations))) and
    (.topology.chains | length) == 3 and
    all(.topology.chains[];
      exact_keys(["attach_type", "direct_hierarchy", "effective_post_attach", "intended_program"]) and
      (.intended_program | program_keys) and
      (.effective_post_attach |
        exact_keys(["program_count", "programs", "revision", "revision_supported"])) and
      (.effective_post_attach.programs | length) == 1 and
      (.effective_post_attach.programs[0] | program_keys) and
      .effective_post_attach.program_count == 1 and
      .effective_post_attach.programs[0] == .intended_program and
      .effective_post_attach.revision == 0 and
      .effective_post_attach.revision_supported == false and
      (.direct_hierarchy | length) == 4 and
      all(.direct_hierarchy[];
        exact_keys(["level", "program_count", "programs", "revision", "revision_supported", "role"]) and
        all(.programs[]; program_keys)) and
      (.direct_hierarchy | map(.level)) == [0, 1, 2, 3] and
      (.direct_hierarchy | map(.role)) == ["root", "ancestor", "ancestor", "target"] and
      (.direct_hierarchy | map(.program_count)) == [0, 0, 0, 1] and
      (.direct_hierarchy | map(.programs | length)) == [0, 0, 0, 1] and
      (.direct_hierarchy | map(.revision_supported)) == [true, true, true, true] and
      .direct_hierarchy[3].programs[0] == .intended_program) and
    (.topology.chains | map(.attach_type)) == [
      "CGroupGetsockopt",
      "CGroupSetsockopt",
      "CGroupSockOps"
    ] and
    (.topology.chains | map(.intended_program)) == [
      {
        "name": "obi_java_remote_parent_getsockopt",
        "program_type": "CGroupSockopt",
        "tag": "f5c83ed89a83d051"
      },
      {
        "name": "obi_java_remote_parent_setsockopt",
        "program_type": "CGroupSockopt",
        "tag": "07e7d372fca30520"
      },
      {
        "name": "obi_sockmap_tracker",
        "program_type": "SockOps",
        "tag": "d5d05b785d357692"
      }
    ] and
    (.topology.chains | map(.direct_hierarchy | map(.revision))) == [
      [201, 1, 1, 2],
      [201, 1, 1, 2],
      [421, 1, 1, 2]
    ] and
    $summary.topology.hierarchy_depth == $summary.runtime.cgroup.hierarchy_depth
  ' benchmark-summary.json >/dev/null || die 'benchmark summary does not match or recompute to the retained claim contract'
}

verify_crosslinks() {
  jq --exit-status --null-input \
    --slurpfile identity run-identity.json \
    --slurpfile summary benchmark-summary.json '
      ($identity | length) == 1 and
      ($summary | length) == 1 and
      $identity[0].source.revision == $summary[0].source_revision and
      $identity[0].raw_artifact.sha256 == $summary[0].raw_artifact_sha256 and
      $identity[0].summary_file == "benchmark-summary.json" and
      $summary[0].run_identity_file == "run-identity.json" and
      $identity[0].result.benchmark == $summary[0].result and
      $identity[0].scope.evidence_class == $summary[0].scope.evidence_class and
      $identity[0].validation.post_run_topology == $summary[0].topology.post_run_cleanup
    ' >/dev/null || die 'retained JSON cross-links do not agree'
}

verify_no_operational_identifiers() {
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
        test("/sys/fs/cgroup") or
        test("session-[0-9]+\\.scope") or
        test("user-[0-9]+\\.slice") or
        test("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:")
      )
    ] | length == 0
  ' benchmark-summary.json run-identity.json >/dev/null ||
    die 'retained JSON contains a forbidden operational string'
}

main() {
  (( $# == 0 )) || die 'this verifier accepts no arguments'
  check_dependencies
  cd -- "$bundle_dir"
  verify_exact_files
  verify_manifest
  verify_canonical_json
  verify_identity
  verify_summary_contract
  verify_crosslinks
  verify_no_operational_identifiers
  printf 'packaged-JVM getsockopt focused evidence verified\n'
}

main "$@"
