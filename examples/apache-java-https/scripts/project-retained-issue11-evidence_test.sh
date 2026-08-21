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
    {schema_version:2,benchmark:"java_remote_parent_packaged_jvm_transport",
      provenance:{harness:"packaged_agent_java_jni_cgroup_getsockopt",
        unix:{socket_path_retained:false},cgroup_bpf:{pre_attach_chains_empty:true,
          cgroup_hierarchy:["/","/target"],
          chains:[{attach_type:"CGroupGetsockopt"},{attach_type:"CGroupSetsockopt"},
            {attach_type:"CGroupSockOps"}],
          stability_mode:"boundary_identity_only",stability_checks:{expected_batches:10,
            observed_pre_batch_snapshots:10,observed_post_batch_snapshots:10,
            query_errors:0,topology_mismatches:0}}},
      source:{revision:$revision,dirty:false,status_sha256:$empty,patch_sha256:$empty},
      runtime:{architecture:"amd64",cgroup_mode:"v2",
        java_version:"openjdk version 21.0.12",no_new_privileges:true},
      setup:{warmup_batches:16,measurement_batches:256,concurrency:8,
        retained_calls_per_series:2048,total_calls_per_series:2176},
      series:[
        series("raw_jni";"getsockopt";"miss"),
        series("raw_jni";"getsockopt";"hit"),
        series("raw_jni";"getsockopt";"stale"),
        series("bridge_provider_jni";"getsockopt";"miss"),
        series("bridge_provider_jni";"getsockopt";"hit"),
        series("bridge_provider_jni";"getsockopt";"stale"),
        series("raw_jni";"unix";"miss"),series("raw_jni";"unix";"hit"),
        series("raw_jni";"unix";"stale"),series("raw_jni";"unix";"timeout"),
        series("bridge_provider_jni";"unix";"miss"),
        series("bridge_provider_jni";"unix";"hit"),
        series("bridge_provider_jni";"unix";"stale"),
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
  project_cell 5.10-lts "$revision" "$cell" || fail 'valid cell did not project'
  (CDPATH='' cd / && bash "$cell/verify.sh" >/dev/null) ||
    fail 'valid cell verifier failed'
  if grep -Eqi -- '(/tmp/|/home/|/proc/|samples_ns|samples_bytes|"program_id"[[:space:]]*:)' \
    "$cell/cell.json"; then
    fail 'cell leaked private material'
  fi
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
  sed -i '0,/"schema_version": 2/s//"schema_version": 2, "schema_version": 2/' \
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
  [[ "$(grep -Fc -- 'ref: ${{ inputs.ref || github.sha }}' "$rhel")" == 2 &&
    "$(grep -Fc -- '[[ "$SELECTED_REVISION" =~ ^[0-9a-f]{40}$ ]]' "$rhel")" == 2 &&
    "$(grep -Fc -- '[[ "$(git rev-parse --verify '\''HEAD^{commit}'\'')" == "$SELECTED_REVISION" ]]' \
      "$rhel")" == 2 &&
    "$(grep -Fc -- '[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]]' \
      "$rhel")" == 2 ]] || fail 'validate and aggregate jobs lost exact source binding'
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
