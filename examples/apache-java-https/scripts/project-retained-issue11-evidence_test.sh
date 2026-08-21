#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECTOR="$SCRIPT_DIRECTORY/project-retained-issue11-evidence.sh"
readonly SCRIPT_DIRECTORY PROJECTOR

TEST_ROOT=''

cleanup_test() {
  if [[ -n "$TEST_ROOT" && -d "$TEST_ROOT" && ! -L "$TEST_ROOT" &&
    "$TEST_ROOT" == /tmp/obi-issue11-project-test.* ]]; then
    chmod -R u+rwX -- "$TEST_ROOT" >/dev/null 2>&1 || true
    find -- "$TEST_ROOT" -xdev -depth -delete >/dev/null 2>&1 || true
  fi
}
trap cleanup_test EXIT HUP INT TERM

fail() {
  printf 'project-retained-issue11-evidence_test.sh: %s\n' "$*" >&2
  return 1
}

expect_reject() {
  local -r label="$1"
  shift
  if ("$@") >/dev/null 2>&1; then fail "accepted mutation: $label"; fi
}

write_pass_log() {
  local -r output="$1"
  shift
  local test_name=''
  : >"$output"
  for test_name in "$@"; do
    printf -- '--- PASS: %s (0.01s)\n' "$test_name" >>"$output"
  done
}

write_transport_benchmark() {
  local -r output="$1"
  jq -n '{schema_version:2,benchmark:"java_remote_parent_transport",
    provenance:{harness:"go_privileged_transport_provider",
      measures:["transport","provider"],excludes:["java","jni"]},
    series:[
      {transport:"getsockopt",outcome:"miss",warmup_rounds:16,measurement_rounds:512,samples:4096,concurrency:8,errors:0,correct:true,latency_gate:{kind:"p99_lt",p50_min_ns:0,p99_max_ns:1000000,passed:true}},
      {transport:"getsockopt",outcome:"hit",warmup_rounds:16,measurement_rounds:512,samples:4096,concurrency:8,errors:0,correct:true,latency_gate:{kind:"p99_lt",p50_min_ns:0,p99_max_ns:1000000,passed:true}},
      {transport:"getsockopt",outcome:"one_shot",warmup_rounds:16,measurement_rounds:512,samples:4096,concurrency:8,errors:0,correct:true,latency_gate:{kind:"correctness_only",p50_min_ns:0,p99_max_ns:0,passed:true}},
      {transport:"unix",outcome:"miss",warmup_rounds:8,measurement_rounds:128,samples:1024,concurrency:8,errors:0,correct:true,latency_gate:{kind:"p99_lt",p50_min_ns:0,p99_max_ns:50000000,passed:true}},
      {transport:"unix",outcome:"hit",warmup_rounds:8,measurement_rounds:128,samples:1024,concurrency:8,errors:0,correct:true,latency_gate:{kind:"p99_lt",p50_min_ns:0,p99_max_ns:50000000,passed:true}},
      {transport:"unix",outcome:"timeout",warmup_rounds:8,measurement_rounds:128,samples:1024,concurrency:8,errors:0,correct:true,latency_gate:{kind:"p50_gte_p99_lte",p50_min_ns:50000000,p99_max_ns:100000000,passed:true}}]}' >"$output"
}

write_packaged_benchmark() {
  local -r output="$1"
  local -r revision="$2"
  local empty_sha=''
  empty_sha="$(printf '' | sha256sum)"; empty_sha="${empty_sha%% *}"
  jq -n --arg revision "$revision" --arg empty "$empty_sha" '
    def series($scope;$transport;$outcome):
      {scope:$scope,transport:$transport,outcome:$outcome,
        correct:true,latency_gate:{passed:true}};
    def statuses($calls):
      {unknown:0,valid:$calls,missing:0,stale:0,unsupported:0,malformed:0,
        version_mismatch:0,ambiguous:0,unauthorized:0,already_consumed:0,
        timeout:0,overload:0,transport_error:0,disabled:0};
    def calls($calls;$before):
      {expected_java_calls:$calls,observed_java_calls:$calls,
        expected_native_calls:$calls,observed_native_calls:$calls,
        expected_bridge_calls:0,observed_bridge_calls:0,
        expected_primary_bpf_calls:$calls,observed_primary_bpf_calls:$calls,
        primary_bpf_status:"valid",primary_bpf_status_before:$before,
        primary_bpf_status_after:($before+$calls),
        expected_unix_server_requests:0,observed_unix_server_requests:0,
        unix_server_status:"not_applicable",unix_server_status_before:0,
        unix_server_status_after:0,expected_timeout_full_requests:0,
        observed_timeout_full_requests:0};
    def lookup_series($concurrency;$latency;$before):
      ($concurrency * 256) as $retained |
      ($concurrency * 272) as $calls |
      {scope:"raw_jni",transport:"getsockopt",outcome:"hit",expected_status:1,
        samples_ns:[range(0;$retained)|$latency],
        total_timed_ns:($retained*$latency),p50_ns:$latency,p95_ns:$latency,
        p99_ns:$latency,status_counts:statuses($calls),
        call_counts:calls($calls;$before),
        allocation:{method:"com.sun.management.ThreadMXBean.getThreadAllocatedBytes",
          control:"paired consecutive counter reads on the same worker",
          samples_bytes:[range(0;$retained)|64],
          control_samples_bytes:[range(0;$retained)|0],
          total_bytes:($retained*64),p50_bytes:64,p95_bytes:64,p99_bytes:64,
          control_total_bytes:0,control_p50_bytes:0,control_p95_bytes:0,
          control_p99_bytes:0},correct:true,
        latency_gate:{kind:"p99_lt",p50_min_ns:0,p99_max_ns:1000000,
          passed:true}};
    lookup_series(1;80000;0) as $lookup1 |
    lookup_series(8;100000;272) as $lookup8 |
    {schema_version:3,benchmark:"java_remote_parent_packaged_jvm_transport",
      provenance:{harness:"packaged_agent_java_concurrent_transport",
        measures:["packaged_agent","java_workers","raw_jni","bridge_provider",
          "jni","kernel_getsockopt","cgroup_bpf","unix_server",
          "thread_allocated_bytes","indirect_lookup_contention_indicator"],
        excludes:["application_request","instrumentation","throughput",
          "application_throughput","process_cpu","rss_growth",
          "native_memory_growth","direct_memory_growth","fd_growth",
          "thread_growth","map_growth","run_to_run_variance",
          "native_sanitizers","exact_bpf_lock_wait"],
        unix:{socket_path_retained:false},cgroup_bpf:{pre_attach_chains_empty:true,
          cgroup_hierarchy:["/","/target"],
          chains:[{attach_type:"CGroupGetsockopt"},{attach_type:"CGroupSetsockopt"},
            {attach_type:"CGroupSockOps"}],
          stability_mode:"boundary_identity_only",stability_checks:{expected_batches:4080,
            expected_primary_calls:13328,observed_pre_batch_snapshots:4080,
            observed_post_batch_snapshots:4080,query_errors:0,
            topology_mismatches:0}}},
      source:{revision:$revision,dirty:false,status_sha256:$empty,patch_sha256:$empty},
      runtime:{architecture:"amd64",cgroup_mode:"v2",
        java_version:"openjdk version 21.0.12",no_new_privileges:true},
      setup:{warmup_batches:16,measurement_batches:256,concurrency:8,
        retained_calls_per_series:2048,total_calls_per_series:2176},
      lookup_contention_indicator:{kind:"indirect_lookup_contention_indicator",
        only_varied_dimension:"java_worker_count",comparison_control:
          "fresh packaged-agent JVM; raw JNI getsockopt hit is the first retained series after identical fixture setup and per-series warmup; measurement batches, timed call, response storage, and host are controlled; Java worker count is the only intentionally varied benchmark dimension",
        interpretation:
          "end-to-end lookup latency comparison is an indirect lookup-contention indicator; it does not measure exact BPF lock wait",
        exact_bpf_lock_wait_measured:false,concurrency_1:$lookup1,
        concurrency_8:$lookup8,relative_p99_gate:{
          kind:"concurrency_8_p99_lte_2x_concurrency_1",p99_multiplier:2,
          concurrency_1_p99_ns:80000,concurrency_8_p99_ns:100000,
          concurrency_8_p99_max_ns:160000,passed:true}},
      series:[
        $lookup8,
        series("raw_jni";"getsockopt";"miss"),
        series("raw_jni";"getsockopt";"stale"),
        series("bridge_provider_jni";"getsockopt";"miss"),
        series("bridge_provider_jni";"getsockopt";"hit"),
        series("bridge_provider_jni";"getsockopt";"stale"),
        series("raw_jni";"unix";"miss"),series("raw_jni";"unix";"hit"),
        series("raw_jni";"unix";"stale"),
        series("bridge_provider_jni";"unix";"miss"),
        series("bridge_provider_jni";"unix";"hit"),
        series("bridge_provider_jni";"unix";"stale"),
        series("raw_jni";"unix";"timeout"),
        series("bridge_provider_jni";"unix";"timeout")]}' >"$output"
}

write_buildinfo() {
  local -r output="$1"
  local -r kernel="$2"
  local -r config="$3"
  local config_sha=''
  config_sha="$(sha256sum <"$config")"; config_sha="${config_sha%% *}"
  jq -n --arg kernel "$kernel" --arg tag "$kernel-fixture" \
    --arg digest "sha256:$(printf '%064d' 1)" --arg config "$config_sha" \
    '{kernel_id:$kernel,lvh_tag:$tag,lvh_digest:$digest,target_arch:"amd64",
      config_sha256:$config}' >"$output"
}

write_raw_cell() {
  local -r root="$1"
  local -r kernel="$2"
  local -r revision="$3"
  mkdir -p -- "$root/transport-benchmark" "$root/packaged-jvm-benchmark"
  printf '%s\n' "$revision" >"$root/source-commit.txt"
  printf 'kernel_id=%s\nlvh_tag=%s-fixture\ndigest=sha256:%064d\n' \
    "$kernel" "$kernel" 1 >"$root/kernel-source.properties"
  printf '%s\n' \
    'probe=bpftool_feature_probe_kernel_full' \
    'status=probe_complete' \
    'reason=compatible' \
    'final_support_decision=selected_go_runtime_feature_probes_and_non_skipping_tests' \
    'version_inference=disabled' >"$root/kernel-feature.properties"
  printf '%s\n' \
    TestRecordCorpus TestRecordGoldenVector TestRecordRejectsInvalidFraming \
    TestRecordDoesNotMarshalUnknownStatus \
    TestRecordRejectsFutureLargerRecordInVersionOne TestVersionMismatchIsTyped \
    TestValidRemoteParentRejectsZeroIDs TestRequestGoldenVector \
    TestRequestSourceIsExplicitOnTheWire TestSampledAndUnsampledRoundTrip \
    >"$root/abi-selected-tests.txt"
  write_pass_log "$root/abi-tests.log" \
    TestRecordCorpus TestRecordGoldenVector TestRecordRejectsInvalidFraming \
    TestRecordDoesNotMarshalUnknownStatus \
    TestRecordRejectsFutureLargerRecordInVersionOne TestVersionMismatchIsTyped \
    TestValidRemoteParentRejectsZeroIDs TestRequestGoldenVector \
    TestRequestSourceIsExplicitOnTheWire TestSampledAndUnsampledRoundTrip
  printf -- '%s\n' \
    '    --- PASS: TestRecordCorpus/empty-parent (0.00s)' \
    '    --- PASS: TestRequestGoldenVector/version-one (0.00s)' \
    >>"$root/abi-tests.log"
  write_pass_log "$root/production-verifier-profiles.log" \
    TestBPFVerifierProductionProfiles \
    TestBPFVerifierProductionProfiles/generictracer/apache-java-https \
    TestBPFVerifierProductionProfiles/tpinjector/java-remote-parent
  write_pass_log "$root/privileged-tests.log" \
    TestJavaRemoteParentPrimarySocketAuthority \
    TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook \
    TestJavaRemoteParentPrimaryJVMFaults \
    TestJavaRemoteParentPrimaryJVMDirectSSLSocket \
    TestJavaRemoteParentGenericJVMDirectSSLSocket \
    TestJavaRemoteParentNestedCgroupLifecycle \
    TestJavaRemoteParentCgroupLinkProcessDeathCleanup \
    TestJavaRemoteParentCgroupPartialAttachRollback \
    TestJavaRemoteParentBridgeLoadRequiresPrivileges
  printf -- '%s\n' \
    '    --- PASS: TestJavaRemoteParentPrimaryJVMFaults/close-before-read (0.00s)' \
    '    --- PASS: TestJavaRemoteParentPrimaryJVMFaults/timeout (0.00s)' \
    >>"$root/privileged-tests.log"
  write_pass_log "$root/packaged-jvm-benchmark-validation.log" \
    TestValidatePackagedJVMBenchmarkArtifactFile \
    TestValidatePackagedJVMBenchmarkArtifactCICrosslinks
  printf '%s\n' \
    'format_version=1' \
    'matrix_revision=java-remote-parent-kernel-v1' \
    "kernel_id=$kernel" \
    'architecture=amd64' \
    'repository=fixture/repository' \
    'workflow_ref=fixture/workflow' \
    'run_id=123' \
    'run_attempt=1' \
    'status_scope=packaged_jvm_transport_preflight' \
    'status=pass' \
    'support_decision=runtime_feature_probes_and_required_non_skipping_tests' \
    'version_inference=disabled' >"$root/matrix-cell.properties"
  write_transport_benchmark "$root/transport-benchmark/benchmark.json"
  write_packaged_benchmark "$root/packaged-jvm-benchmark/benchmark.json" \
    "$revision"
}

expect_packaged_mutation_reject() {
  local -r label="$1"
  local -r slug="$2"
  local -r revision="$3"
  local -r mutation="$4"
  local -r buildinfo="$5"
  local -r config="$6"
  local -r raw="$TEST_ROOT/raw-packaged-$slug"
  local -r benchmark="$raw/packaged-jvm-benchmark/benchmark.json"
  write_raw_cell "$raw" 5.10-lts "$revision"
  jq "$mutation" "$benchmark" >"$raw/benchmark.tmp"
  mv -- "$raw/benchmark.tmp" "$benchmark"
  expect_reject "$label" "$PROJECTOR" cell-v1 "$raw" "$buildinfo" "$config" \
    "$TEST_ROOT/cell-packaged-$slug"
}

project_cell() {
  local -r kernel="$1"
  local -r revision="$2"
  local -r output="$3"
  local raw="$TEST_ROOT/raw-$kernel-${output##*/}"
  local buildinfo="$TEST_ROOT/$kernel.buildinfo"
  local config="$TEST_ROOT/$kernel.config"
  write_raw_cell "$raw" "$kernel" "$revision"
  printf 'CONFIG_BPF=y\n' >"$config"
  write_buildinfo "$buildinfo" "$kernel" "$config"
  "$PROJECTOR" cell-v1 "$raw" "$buildinfo" "$config" "$output" >/dev/null
}

rehash_cell() {
  local -r cell="$1"
  (CDPATH='' cd -- "$cell" &&
    sha256sum README.md SANITIZATION.md cell.json verify.sh >SHA256SUMS)
}

matrix_seed_from_json() {
  local -r matrix="$1"
  local -a rows=()
  mapfile -t rows < <(jq -cS '.cells[]' "$matrix" |
    while IFS= read -r cell; do printf '%s\n' "$cell" | sha256sum; done)
  printf '%s\n' issue11-kernel-matrix-v1 "${rows[@]}" | sha256sum |
    awk '{print $1}'
}

test_cell_projection_and_mutations() {
  local revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local cell="$TEST_ROOT/cell-good"
  local contention_cell=''
  local contention_identity_payload=''
  local contention_evidence_id=''
  project_cell 5.10-lts "$revision" "$cell" || fail 'valid cell did not project'
  (CDPATH='' cd / && bash "$cell/verify.sh" >/dev/null) ||
    fail 'valid cell verifier failed'
  jq -e '
    .benchmarks.packaged_jvm.schema_version == 3 and
    .benchmarks.packaged_jvm.lookup_contention_indicator.kind ==
      "indirect_lookup_contention_indicator" and
    .benchmarks.packaged_jvm.lookup_contention_indicator.exact_bpf_lock_wait_measured == false and
    .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_1.concurrency == 1 and
    .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_8.concurrency == 8 and
    .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_1.primary_bpf_status_before == 0 and
    .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_1.primary_bpf_status_after == 272 and
    .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_8.primary_bpf_status_before == 272 and
    .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_8.primary_bpf_status_after == 2448 and
    .benchmarks.packaged_jvm.lookup_contention_indicator.relative_p99_gate.passed == true and
    .benchmarks.packaged_jvm.topology.expected_batches == 4080 and
    .benchmarks.packaged_jvm.topology.expected_primary_calls == 13328
  ' "$cell/cell.json" >/dev/null || fail 'v3 contention summary was not retained'
  if grep -Eqi -- '(/tmp/|/home/|/proc/|samples_ns|samples_bytes|"program_id"[[:space:]]*:)' \
    "$cell/cell.json"; then
    fail 'cell leaked private material'
  fi

  contention_cell="$TEST_ROOT/cell-contention-mutation"
  cp -a -- "$cell" "$contention_cell"
  chmod -R u+w -- "$contention_cell"
  jq -cS \
    '.benchmarks.packaged_jvm.lookup_contention_indicator.relative_p99_gate.passed=false' \
    "$contention_cell/cell.json" >"$contention_cell/cell.tmp"
  mv -- "$contention_cell/cell.tmp" "$contention_cell/cell.json"
  contention_identity_payload="$(jq -cS \
    '{source_revision:.source.revision,kernel_id:.kernel.id,
      lvh_digest:.kernel.lvh_digest,buildinfo_sha256:.kernel.buildinfo_sha256,
      config_sha256:.kernel.config_sha256,raw_commitment,tests,
      transport:.benchmarks.transport,packaged_jvm:.benchmarks.packaged_jvm}' \
    "$contention_cell/cell.json")"
  contention_evidence_id="$(printf '%s\n' issue11-kernel-cell-v1 \
    "$contention_identity_payload" | sha256sum)"
  contention_evidence_id="${contention_evidence_id%% *}"
  jq -cS --arg evidence_id "$contention_evidence_id" '.evidence_id=$evidence_id' \
    "$contention_cell/cell.json" >"$contention_cell/cell.tmp"
  mv -- "$contention_cell/cell.tmp" "$contention_cell/cell.json"
  rehash_cell "$contention_cell"
  expect_reject 'rederived projected contention gate weakening' \
    bash "$contention_cell/verify.sh"

  jq -cS \
    '.benchmarks.packaged_jvm.lookup_contention_indicator.relative_p99_gate.passed=true |
      .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_8.primary_bpf_status_before += 1 |
      .benchmarks.packaged_jvm.lookup_contention_indicator.concurrency_8.primary_bpf_status_after += 1' \
    "$contention_cell/cell.json" >"$contention_cell/cell.tmp"
  mv -- "$contention_cell/cell.tmp" "$contention_cell/cell.json"
  contention_identity_payload="$(jq -cS \
    '{source_revision:.source.revision,kernel_id:.kernel.id,
      lvh_digest:.kernel.lvh_digest,buildinfo_sha256:.kernel.buildinfo_sha256,
      config_sha256:.kernel.config_sha256,raw_commitment,tests,
      transport:.benchmarks.transport,packaged_jvm:.benchmarks.packaged_jvm}' \
    "$contention_cell/cell.json")"
  contention_evidence_id="$(printf '%s\n' issue11-kernel-cell-v1 \
    "$contention_identity_payload" | sha256sum)"
  contention_evidence_id="${contention_evidence_id%% *}"
  jq -cS --arg evidence_id "$contention_evidence_id" '.evidence_id=$evidence_id' \
    "$contention_cell/cell.json" >"$contention_cell/cell.tmp"
  mv -- "$contention_cell/cell.tmp" "$contention_cell/cell.json"
  rehash_cell "$contention_cell"
  expect_reject 'rederived projected contention counter gap' \
    bash "$contention_cell/verify.sh"

  chmod -R u+w -- "$cell"
  jq -cS '.coverage.issue_11.state="closed"|.coverage.issue_11.closes=[11]' \
    "$cell/cell.json" >"$cell/cell.tmp"
  mv -- "$cell/cell.tmp" "$cell/cell.json"
  rehash_cell "$cell"
  expect_reject '#11 overclaim' bash "$cell/verify.sh"

  local raw="$TEST_ROOT/raw-special"
  write_raw_cell "$raw" 5.10-lts "$revision"
  ln -s -- source-commit.txt "$raw/link"
  printf 'CONFIG_BPF=y\n' >"$TEST_ROOT/special.config"
  write_buildinfo "$TEST_ROOT/special.buildinfo" 5.10-lts \
    "$TEST_ROOT/special.config"
  expect_reject 'raw symlink' "$PROJECTOR" cell-v1 "$raw" \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config" \
    "$TEST_ROOT/cell-special"

  raw="$TEST_ROOT/raw-failed"
  write_raw_cell "$raw" 5.10-lts "$revision"
  sed -i 's/status=probe_complete/status=unsupported/' \
    "$raw/kernel-feature.properties"
  expect_reject 'unsupported runtime probe' "$PROJECTOR" cell-v1 "$raw" \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config" \
    "$TEST_ROOT/cell-failed"

  raw="$TEST_ROOT/raw-skipped"
  write_raw_cell "$raw" 5.10-lts "$revision"
  printf -- '%s\n' '--- SKIP: TestJavaRemoteParentPrimarySocketAuthority (0.01s)' \
    >>"$raw/privileged-tests.log"
  expect_reject 'skipped privileged roster' "$PROJECTOR" cell-v1 "$raw" \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config" \
    "$TEST_ROOT/cell-skipped"

  raw="$TEST_ROOT/raw-duplicate-json"
  write_raw_cell "$raw" 5.10-lts "$revision"
  sed -i '0,/"schema_version": 3/s//"schema_version": 3, "schema_version": 3/' \
    "$raw/packaged-jvm-benchmark/benchmark.json"
  expect_reject 'duplicate raw benchmark JSON key' "$PROJECTOR" cell-v1 \
    "$raw" "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config" \
    "$TEST_ROOT/cell-duplicate-json"

  raw="$TEST_ROOT/raw-source-mismatch"
  write_raw_cell "$raw" 5.10-lts "$revision"
  jq '.source.revision="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    "$raw/packaged-jvm-benchmark/benchmark.json" >"$raw/benchmark.tmp"
  mv -- "$raw/benchmark.tmp" "$raw/packaged-jvm-benchmark/benchmark.json"
  expect_reject 'packaged benchmark source mismatch' "$PROJECTOR" cell-v1 \
    "$raw" "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config" \
    "$TEST_ROOT/cell-source-mismatch"

  expect_packaged_mutation_reject 'raw packaged schema v2' schema-v2 "$revision" \
    '.schema_version=2' "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'missing contention indicator' missing-indicator \
    "$revision" 'del(.lookup_contention_indicator)' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'exact BPF lock-wait claim' exact-lock-claim \
    "$revision" '.lookup_contention_indicator.exact_bpf_lock_wait_measured=true' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'contention comparison drift' comparison-drift \
    "$revision" '.lookup_contention_indicator.only_varied_dimension="worker_count_and_fixture"' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'contention c1 p99 summary forgery' c1-p99 \
    "$revision" '.lookup_contention_indicator.concurrency_1.p99_ns += 1' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'contention c8 canonical-copy forgery' c8-copy \
    "$revision" '.series[0].allocation.p99_bytes += 1' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'packaged series order drift' series-order \
    "$revision" '.series[1:3] |= reverse' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'contention relative-gate forgery' relative-gate \
    "$revision" \
    '.lookup_contention_indicator.relative_p99_gate.concurrency_8_p99_max_ns += 1' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'failed contention relative gate' failed-relative \
    "$revision" \
    '.lookup_contention_indicator.concurrency_1.samples_ns |= map(40000) | .lookup_contention_indicator.concurrency_1.total_timed_ns=10240000 | .lookup_contention_indicator.concurrency_1.p50_ns=40000 | .lookup_contention_indicator.concurrency_1.p95_ns=40000 | .lookup_contention_indicator.concurrency_1.p99_ns=40000 | .lookup_contention_indicator.relative_p99_gate.concurrency_1_p99_ns=40000 | .lookup_contention_indicator.relative_p99_gate.concurrency_8_p99_max_ns=80000 | .lookup_contention_indicator.relative_p99_gate.passed=false' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'coordinated contention status forgery' status-roster \
    "$revision" \
    '.lookup_contention_indicator.concurrency_1.status_counts.forged_positive=1 | .lookup_contention_indicator.concurrency_1.status_counts.forged_negative=-1' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
  expect_packaged_mutation_reject 'intervening primary lookup counter gap' counter-gap \
    "$revision" \
    '.lookup_contention_indicator.concurrency_8.call_counts.primary_bpf_status_before += 1 | .lookup_contention_indicator.concurrency_8.call_counts.primary_bpf_status_after += 1 | .series[0].call_counts.primary_bpf_status_before += 1 | .series[0].call_counts.primary_bpf_status_after += 1' \
    "$TEST_ROOT/special.buildinfo" "$TEST_ROOT/special.config"
}

test_matrix_projection_and_mixing() {
  local revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local kernel=''
  local -a kernels=(5.10-lts 5.15-lts 6.1-lts 6.6-lts 6.12-lts rhel9.6)
  local -a cells=()
  local cell=''
  for kernel in "${kernels[@]}"; do
    cell="$TEST_ROOT/matrix-cell-$kernel"
    project_cell "$kernel" "$revision" "$cell"
    cells+=("$cell")
  done
  local name=''
  name="$("$PROJECTOR" matrix-name-v1 "${cells[@]}")" ||
    fail 'matrix name derivation failed'
  local output="$TEST_ROOT/$name"
  "$PROJECTOR" matrix-v1 "${cells[@]}" "$output" >/dev/null ||
    fail 'complete matrix did not project'
  (CDPATH='' cd / && bash "$output/verify.sh" >/dev/null) ||
    fail 'complete matrix did not verify'
  jq -e '.status == "passed_bounded_scope" and
    .coverage.issue_11 == {state:"open",advances:[11],closes:[]} and
    (.cells|length)==6' "$output/matrix.json" >/dev/null ||
    fail 'matrix closure semantics changed'
  expect_reject 'incomplete five-cell matrix' "$PROJECTOR" matrix-v1 \
    "${cells[0]}" "${cells[1]}" "${cells[2]}" "${cells[3]}" "${cells[4]}" \
    "$TEST_ROOT/incomplete"

  local trusted_cell="$TEST_ROOT/trusted-cell-backup"
  local canary="$TEST_ROOT/untrusted-cell-verifier-ran"
  cp -a -- "${cells[0]}" "$trusted_cell"
  chmod -R u+w -- "${cells[0]}"
  printf '%s\n' '#!/usr/bin/env bash' \
    "printf pwned >$(printf '%q' "$canary")" >"${cells[0]}/verify.sh"
  rehash_cell "${cells[0]}"
  expect_reject 'artifact-controlled cell verifier' \
    "$PROJECTOR" matrix-name-v1 "${cells[@]}"
  [[ ! -e "$canary" ]] || fail 'artifact-controlled cell verifier executed'
  mv -- "${cells[0]}" "$TEST_ROOT/untrusted-cell"
  mv -- "$trusted_cell" "${cells[0]}"

  chmod -R u+w -- "${cells[5]}"
  jq -cS '.source.revision="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    "${cells[5]}/cell.json" >"${cells[5]}/cell.tmp"
  mv -- "${cells[5]}/cell.tmp" "${cells[5]}/cell.json"
  rehash_cell "${cells[5]}"
  expect_reject 'mixed-source matrix' "$PROJECTOR" matrix-name-v1 "${cells[@]}"

  chmod -R u+w -- "${cells[0]}"
  jq -cS '.private_binary="UFJJVkFURQ=="' "${cells[0]}/cell.json" \
    >"${cells[0]}/cell.tmp"
  mv -- "${cells[0]}/cell.tmp" "${cells[0]}/cell.json"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"${cells[0]}/verify.sh"
  rehash_cell "${cells[0]}"
  expect_reject 'self-verifying private cell smuggle' \
    "$PROJECTOR" matrix-name-v1 "${cells[@]}"

  local trusted_matrix="$TEST_ROOT/trusted-matrix-backup"
  local mutated_seed=''
  local mutated_matrix=''
  cp -a -- "$output" "$trusted_matrix"
  chmod -R u+w -- "$output"
  jq -cS '.cells[0].privacy.logs_retained=true' "$output/matrix.json" \
    >"$output/matrix.tmp"
  mv -- "$output/matrix.tmp" "$output/matrix.json"
  mutated_seed="$(matrix_seed_from_json "$output/matrix.json")"
  jq -cS --arg seed "$mutated_seed" '.evidence_id=$seed' \
    "$output/matrix.json" >"$output/matrix.tmp"
  mv -- "$output/matrix.tmp" "$output/matrix.json"
  (CDPATH='' cd -- "$output" &&
    sha256sum README.md SANITIZATION.md matrix.json verify.sh >SHA256SUMS)
  mutated_matrix="$TEST_ROOT/issue11-kernel-matrix-${revision:0:12}-${mutated_seed:0:12}"
  mv -- "$output" "$mutated_matrix"
  expect_reject 'embedded cell privacy weakening with rederived matrix identity' \
    bash "$mutated_matrix/verify.sh"
  mv -- "$trusted_matrix" "$output"

  chmod -R u+w -- "$output"
  jq -cS '.evidence_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    "$output/matrix.json" >"$output/matrix.tmp"
  mv -- "$output/matrix.tmp" "$output/matrix.json"
  (CDPATH='' cd -- "$output" &&
    sha256sum README.md SANITIZATION.md matrix.json verify.sh >SHA256SUMS)
  expect_reject 'arbitrary matrix evidence identity' bash "$output/verify.sh"
}

test_workflow_contracts() {
  local acceptance="$SCRIPT_DIRECTORY/../../../.github/workflows/java_remote_parent_acceptance_claims.yml"
  local rhel="$SCRIPT_DIRECTORY/../../../.github/workflows/java_remote_parent_rhel.yml"
  grep -Fq -- 'fail-fast: false' "$acceptance" || fail 'profile matrix lost fail-fast false'
  grep -Fq -- 'timeout-minutes: 180' "$acceptance" || fail 'profile timeout is absent'
  [[ "$(grep -Fc -- 'retention-days: 90' "$rhel")" -ge 2 ]] ||
    fail 'safe #11 cell/matrix 90-day retention is absent'
  grep -Fq -- 'retention-days: 14' "$rhel" ||
    fail 'raw diagnostic 14-day retention is absent'
  grep -Fq -- 'description: "Exact lowercase 40-hex Git commit to validate"' \
    "$rhel" || fail 'dispatch input is not restricted to an immutable commit'
  # These single-quoted patterns are literal workflow source contracts.
  # shellcheck disable=SC2016
  [[ "$(grep -Fc -- 'ref: ${{ inputs.ref || github.sha }}' "$rhel")" == 2 &&
    "$(grep -Fc -- '[[ "$SELECTED_REVISION" =~ ^[0-9a-f]{40}$ ]]' "$rhel")" == 2 &&
    "$(grep -Fc -- '[[ "$(git rev-parse --verify '\''HEAD^{commit}'\'')" == "$SELECTED_REVISION" ]]' \
      "$rhel")" == 2 &&
    "$(grep -Fc -- '[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]]' \
      "$rhel")" == 2 ]] || fail 'validate and aggregate jobs lost exact source binding'
  # This single-quoted pattern is a literal workflow source contract.
  # shellcheck disable=SC2016
  grep -Fq -- 'campaign_output="$(readlink -f -- "$CAMPAIGN_OUTPUT")"' "$rhel" ||
    fail 'workflow passes a relative raw cell path to the safe projector'
}

main() {
  TEST_ROOT="$(mktemp -d /tmp/obi-issue11-project-test.XXXXXX)"
  chmod 0700 -- "$TEST_ROOT"
  test_cell_projection_and_mutations
  test_matrix_projection_and_mixing
  test_workflow_contracts
  printf 'issue #11 bounded projection mutation tests passed\n'
}

main
