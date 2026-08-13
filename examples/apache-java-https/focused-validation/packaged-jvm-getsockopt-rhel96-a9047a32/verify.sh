#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

readonly script_name="${BASH_SOURCE[0]##*/}"
bundle_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly bundle_dir
temporary_dir=''

cleanup() {
  if [[ -n "${temporary_dir:-}" && -d "$temporary_dir" ]]; then
    rm -rf -- "$temporary_dir"
  fi
}

on_error() {
  local -r line="$1"
  printf '%s: command failed at line %s\n' "$script_name" "$line" >&2
}

trap 'on_error "$LINENO"' ERR
trap cleanup EXIT

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

verify_frozen_json_identity() {
  local summary_identity=''
  local run_identity=''
  local -r expected_summary_identity='a8e0b85bb76812399c18503a15d074305fa6276b6d358fccde56373dccaef82e  benchmark-summary.json'
  local -r expected_run_identity='22c0db64a86015d5ddaf55baa23147f34da96473e7e11a2cd9f462bd7be76db5  run-identity.json'

  summary_identity="$(sha256sum -- benchmark-summary.json)"
  [[ "$summary_identity" == "$expected_summary_identity" ]] ||
    die 'benchmark summary byte identity does not match the retained samples'

  run_identity="$(sha256sum -- run-identity.json)"
  [[ "$run_identity" == "$expected_run_identity" ]] ||
    die 'run identity byte identity does not match the retained provenance'
}

verify_identity_contract() {
  jq --exit-status '
    . == {
      "format": 1,
      "kind": "focused-rhel96-packaged-jvm-getsockopt",
      "provenance": {
        "artifact_name": "java-remote-parent-rhel9.6-kernel-sockopt-31741417915",
        "repository": "MrAlias/opentelemetry-ebpf-instrumentation",
        "workflow": {
          "conclusion": "success",
          "path": ".github/workflows/java_remote_parent_rhel.yml",
          "run_attempt": 1,
          "run_url": "https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31741417915"
        }
      },
      "raw_evidence": {
        "github_archive": {
          "retained_in_repository": false,
          "sha256": "f8dc199c64a518dd0e6c957cc9f78259aa14e0ae420b0d6d3061144ba6fff367",
          "size_bytes": 35934009,
          "source_name": "java-remote-parent-rhel9.6-kernel-sockopt-31741417915"
        },
        "packaged_benchmark": {
          "retained_in_repository": false,
          "sha256": "8cc7c5b1815878d7ebb51b42eabdb48a08f27ff78f185d084d8d5dc281e82e17",
          "size_bytes": 8761,
          "source_filename": "benchmark.json"
        }
      },
      "result": {
        "benchmark": "passed",
        "ci_compiled_crosslink_validator": "passed",
        "ci_compiled_decoder": "passed",
        "independent_compiled_decoder": "passed",
        "sanitized_bundle": "passed"
      },
      "scope": {
        "acceptance_evidence": false,
        "advances_issues": [11, 20, 37],
        "closes_issues": [],
        "evidence_class": "focused_non_acceptance",
        "execution_environment": "github_actions_digest_pinned_rhel96_kernel_vm",
        "limitations": [
          "not_rhel_userspace_compatibility",
          "not_apache_application_acceptance",
          "no_provider_selection_or_record_decode",
          "no_unix_fallback",
          "no_throughput_or_sustained_load",
          "no_allocations_or_resource_growth",
          "no_concurrency_or_run_to_run_variance",
          "revisionless_boundary_identity_only_topology"
        ],
        "public_ci_locator_available": true
      },
      "source": {
        "clean": true,
        "patch_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "repository": "MrAlias/opentelemetry-ebpf-instrumentation",
        "revision": "a9047a32788e545b0c24a17e620708b488120a74",
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
          "independent_result": "passed",
          "loads_bpf": false,
          "test": "TestValidatePackagedJVMBenchmarkArtifactFile"
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
      all(.samples_ns[]; type == "number" and . > 0 and . == floor) and
      .missing + .valid + .errors == .sample_count and
      .errors == 0 and
      .latency_gate.passed == (.p99_ns < .latency_gate.p99_max_ns);

    exact_keys([
      "benchmark",
      "format",
      "inputs",
      "raw_archive_sha256",
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
    .raw_archive_sha256 == "f8dc199c64a518dd0e6c957cc9f78259aa14e0ae420b0d6d3061144ba6fff367" and
    .raw_artifact_sha256 == "8cc7c5b1815878d7ebb51b42eabdb48a08f27ff78f185d084d8d5dc281e82e17" and
    .result == "passed" and
    .run_identity_file == "run-identity.json" and
    .source_revision == "a9047a32788e545b0c24a17e620708b488120a74" and
    .inputs == {
      "agent_artifact": {
        "sha256": "a5eced7a6428ef8dafd10dbce0e41074039cee1d448c4f26a780d965ea806a6d",
        "size_bytes": 4548942
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
        "sha256": "f98ee4a574eec9fd5d080e80c1476de1a1f5ed0f8279871560a8d2c886f18437",
        "size_bytes": 74421574
      }
    } and
    .runtime == {
      "architecture": "amd64",
      "bpf_descriptors": 0,
      "cgroup": {"hierarchy_depth": 2, "mode": "v2"},
      "cpu_model": "AMD EPYC 7763 64-Core Processor",
      "java": {
        "capabilities": "all_zero",
        "distribution": "Oracle OpenJDK (Alpine package)",
        "executable_sha256": "af2a90f0fb3ac07fce3a4c9990405890f7c5353d7c926e6e7644f796b831e00f",
        "feature": 21,
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
      .latency_gate.kind == "p99_lt" and
      .latency_gate.p99_max_ns == 1000000 and
      .correct == true and
      series_consistent) and
    (.series | map(del(.samples_ns))) == [
      {
        "correct": true,
        "errors": 0,
        "expected_status": 2,
        "latency_gate": {"kind": "p99_lt", "p99_max_ns": 1000000, "passed": true},
        "max_ns": 46998,
        "min_ns": 6312,
        "missing": 256,
        "outcome": "miss",
        "p50_ns": 7003,
        "p95_ns": 8024,
        "p99_ns": 29034,
        "sample_count": 256,
        "total_timed_ns": 1924099,
        "valid": 0,
        "warmup_iterations": 16
      },
      {
        "correct": true,
        "errors": 0,
        "expected_status": 1,
        "latency_gate": {"kind": "p99_lt", "p99_max_ns": 1000000, "passed": true},
        "max_ns": 72315,
        "min_ns": 16130,
        "missing": 0,
        "outcome": "hit",
        "p50_ns": 18164,
        "p95_ns": 36608,
        "p99_ns": 61183,
        "sample_count": 256,
        "total_timed_ns": 5147901,
        "valid": 256,
        "warmup_iterations": 16
      }
    ] and
    (.series | map(.sample_count) | add) == 512 and
    (.series | map(.total_timed_ns) | add) == 7072000 and
    (.series | map(.warmup_iterations) | add) == 32 and
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
      "direct_revision_support_complete": false,
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
        "expected_calls": 544,
        "observed_post_call_snapshots": 544,
        "observed_pre_call_snapshots": 544,
        "query_errors": 0,
        "topology_mismatches": 0
      },
      "stability_evidence": "exact boundary identities unchanged; attach-detach completed between queries cannot be excluded",
      "stability_mode": "boundary_identity_only"
    } and
    .topology.stability_checks.expected_calls ==
      (2 * (.setup.warmup_iterations + .setup.measurement_iterations)) and
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
      "CGroupGetsockopt",
      "CGroupSetsockopt",
      "CGroupSockOps"
    ] and
    (.topology.chains | map(.intended_program)) == [
      {
        "name": "obi_java_remote_parent_getsockopt",
        "program_type": "CGroupSockopt",
        "tag": "ac77d58abf02d07c"
      },
      {
        "name": "obi_java_remote_parent_setsockopt",
        "program_type": "CGroupSockopt",
        "tag": "f2764727e43225a4"
      },
      {
        "name": "obi_sockmap_tracker",
        "program_type": "SockOps",
        "tag": "08eb6e4d1a509638"
      }
    ] and
    .topology.hierarchy_depth == .runtime.cgroup.hierarchy_depth
  ' benchmark-summary.json >/dev/null ||
    die 'benchmark summary does not match or recompute to the retained claim contract'
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
      $identity[0].summary_file == "benchmark-summary.json" and
      $summary[0].run_identity_file == "run-identity.json" and
      $identity[0].result.benchmark == $summary[0].result and
      $identity[0].scope.evidence_class == $summary[0].scope.evidence_class and
      $identity[0].validation.cleanup.direct_hierarchy_chains_empty ==
        $summary[0].topology.post_run_cleanup.direct_hierarchy_chains_empty and
      $identity[0].validation.cleanup.effective_chains_empty ==
        $summary[0].topology.post_run_cleanup.effective_chains_empty and
      $identity[0].validation.cleanup.intended_program_ids_absent ==
        $summary[0].topology.post_run_cleanup.intended_program_ids_absent
    ' >/dev/null ||
    die 'retained JSON cross-links do not agree'
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
        test("/(?:build|proc|sys|tmp)/") or
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
  verify_frozen_json_identity
  verify_identity_contract
  verify_summary_contract
  verify_crosslinks
  verify_no_operational_identifiers
  printf 'RHEL 9.6 packaged-JVM getsockopt focused evidence verified\n'
}

main "$@"
