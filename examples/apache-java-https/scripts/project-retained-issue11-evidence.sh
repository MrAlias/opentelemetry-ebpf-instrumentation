#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
readonly SCRIPT_NAME

readonly MAX_RAW_FILES=4096
readonly MAX_RAW_BYTES=536870912
readonly MAX_TEXT_BYTES=8388608
readonly -a KERNEL_ORDER=(
  5.10-lts 5.15-lts 6.1-lts 6.6-lts 6.12-lts rhel9.6
)
readonly -a ABI_TESTS=(
  TestRecordCorpus TestRecordGoldenVector TestRecordRejectsInvalidFraming
  TestRecordDoesNotMarshalUnknownStatus
  TestRecordRejectsFutureLargerRecordInVersionOne TestVersionMismatchIsTyped
  TestValidRemoteParentRejectsZeroIDs TestRequestGoldenVector
  TestRequestSourceIsExplicitOnTheWire TestSampledAndUnsampledRoundTrip
)
readonly -a VERIFIER_TESTS=(
  TestBPFVerifierProductionProfiles
  TestBPFVerifierProductionProfiles/generictracer/apache-java-https
  TestBPFVerifierProductionProfiles/tpinjector/java-remote-parent
)
readonly -a PRIVILEGED_TESTS=(
  TestJavaRemoteParentPrimarySocketAuthority
  TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook
  TestJavaRemoteParentPrimaryJVMFaults
  TestJavaRemoteParentPrimaryJVMDirectSSLSocket
  TestJavaRemoteParentGenericJVMDirectSSLSocket
  TestJavaRemoteParentNestedCgroupLifecycle
  TestJavaRemoteParentCgroupLinkProcessDeathCleanup
  TestJavaRemoteParentCgroupPartialAttachRollback
  TestJavaRemoteParentBridgeLoadRequiresPrivileges
)
# Consumed by name through assert_log_roster's nameref.
# shellcheck disable=SC2034
readonly -a COMPILED_VALIDATOR_TESTS=(
  TestValidatePackagedJVMBenchmarkArtifactFile
  TestValidatePackagedJVMBenchmarkArtifactCICrosslinks
)

WORK_DIRECTORY=''
WORK_IDENTITY=''
CANDIDATE_DIRECTORY=''
CANDIDATE_IDENTITY=''
OUTPUT_DIRECTORY=''
OUTPUT_PARENT=''

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME cell-v1 RAW_DIR BUILDINFO CONFIG ABS_OUTPUT" \
    "       $SCRIPT_NAME matrix-name-v1 CELL_5.10 CELL_5.15 CELL_6.1 CELL_6.6 CELL_6.12 CELL_RHEL9.6" \
    "       $SCRIPT_NAME matrix-v1 CELL_5.10 CELL_5.15 CELL_6.1 CELL_6.6 CELL_6.12 CELL_RHEL9.6 ABS_OUTPUT"
}

die() {
  printf '%s: ERROR: %s\n' "$SCRIPT_NAME" "$*" >&2
  return 1
}

is_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

is_safe_leaf() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
    "$1" != . && "$1" != .. ]]
}

property_value() {
  local -r file="$1"
  local -r key="$2"
  awk -F= -v key="$key" '
    $1 == key {count++; value = substr($0, length(key) + 2)}
    END {if (count != 1 || value == "") exit 1; print value}
  ' "$file"
}

safe_regular() {
  local -r file="$1"
  local -r maximum="$2"
  local size=''
  [[ -f "$file" && ! -L "$file" ]] || return 1
  size="$(stat -Lc '%s' -- "$file")" || return 1
  [[ "$size" =~ ^[1-9][0-9]*$ && "$size" -le "$maximum" ]]
}

validate_json_object() {
  local -r file="$1"
  safe_regular "$file" "$MAX_TEXT_BYTES" || return 1
  python3 - "$file" <<'PY'
import json
import sys

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result

with open(sys.argv[1], "rb") as source:
    value = json.load(source, object_pairs_hook=unique)
if not isinstance(value, dict):
    raise ValueError("top-level JSON value must be an object")
PY
}

validate_buildinfo() {
  local -r file="$1"
  local -r kernel_id="$2"
  local -r lvh_tag="$3"
  local -r lvh_digest="$4"
  local -r config_sha256="$5"
  validate_json_object "$file" || return 1
  jq -e --arg kernel "$kernel_id" --arg tag "$lvh_tag" \
    --arg digest "$lvh_digest" --arg config "$config_sha256" '
    .kernel_id == $kernel and .lvh_tag == $tag and .lvh_digest == $digest and
    .target_arch == "amd64" and .config_sha256 == $config
  ' "$file" >/dev/null
}

validate_output() {
  OUTPUT_DIRECTORY="$1"
  [[ "$OUTPUT_DIRECTORY" == /* && ! -e "$OUTPUT_DIRECTORY" &&
    ! -L "$OUTPUT_DIRECTORY" ]] || return 1
  is_safe_leaf "${OUTPUT_DIRECTORY##*/}" || return 1
  OUTPUT_PARENT="${OUTPUT_DIRECTORY%/*}"
  [[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" &&
    "$(readlink -f -- "$OUTPUT_PARENT")" == "$OUTPUT_PARENT" &&
    "$(stat -Lc '%u:%a' -- "$OUTPUT_PARENT")" == "$EUID:700" ]] || return 1
}

cleanup_owned() {
  local -r path="$1"
  local -r identity="$2"
  [[ -n "$path" && -n "$identity" && -d "$path" && ! -L "$path" &&
    "$(stat -Lc '%d:%i:%u' -- "$path")" == "$identity" ]] || return 1
  case "$path" in
    /tmp/obi-issue11-project.*|"$OUTPUT_PARENT"/.issue11-project.*|\
      "$OUTPUT_DIRECTORY") ;;
    *) return 1 ;;
  esac
  chmod -R u+rwX -- "$path" >/dev/null 2>&1 || return 1
  find -- "$path" -xdev -depth -delete
}

cleanup() {
  local original_status="$?"
  local cleanup_status=0
  trap - EXIT HUP INT TERM
  if [[ -n "$CANDIDATE_DIRECTORY" && -e "$CANDIDATE_DIRECTORY" ]]; then
    cleanup_owned "$CANDIDATE_DIRECTORY" "$CANDIDATE_IDENTITY" ||
      cleanup_status=1
  fi
  if [[ -n "$WORK_DIRECTORY" && -e "$WORK_DIRECTORY" ]]; then
    cleanup_owned "$WORK_DIRECTORY" "$WORK_IDENTITY" || cleanup_status=1
  fi
  if ((original_status == 0 && cleanup_status != 0)); then exit 1; fi
  exit "$original_status"
}
trap cleanup EXIT HUP INT TERM

raw_manifest_commitment() {
  local -r raw="$1"
  local manifest="$WORK_DIRECTORY/raw.manifest"
  local relative=''
  local count=0
  local bytes=0
  local size=''
  local digest=''
  local commitment=''

  [[ "$raw" == /* && -d "$raw" && ! -L "$raw" &&
    "$(readlink -f -- "$raw")" == "$raw" ]] || return 1
  [[ -z "$(find -- "$raw" -xdev -mindepth 1 ! -type f ! -type d \
    -print -quit)" ]] || return 1
  : >"$manifest"
  while IFS= read -r -d '' relative; do
    relative="${relative#./}"
    [[ -n "$relative" && "$relative" != *$'\n'* &&
      "$relative" != *$'\t'* ]] || return 1
    size="$(stat -Lc '%s' -- "$raw/$relative")" || return 1
    [[ "$size" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    digest="$(sha256sum <"$raw/$relative")" || return 1
    digest="${digest%% *}"
    printf '%s  %s\n' "$digest" "$relative" >>"$manifest" || return 1
    ((count += 1))
    ((bytes += size))
    ((count <= MAX_RAW_FILES && bytes <= MAX_RAW_BYTES)) || return 1
  done < <(CDPATH='' cd -- "$raw" && find . -xdev -type f -print0 |
    LC_ALL=C sort -z)
  ((count > 0 && bytes > 0)) || return 1
  commitment="$(sha256sum <"$manifest")" || return 1
  commitment="${commitment%% *}"
  jq -cn --arg sha256 "$commitment" --argjson files "$count" \
    --argjson bytes "$bytes" '{algorithm:"sha256",file_count:$files,
      total_bytes:$bytes,sha256:$sha256,raw_retained:false,
      paths_retained:false}'
}

assert_log_roster() {
  local -r file="$1"
  local -r array_name="$2"
  local -r include_subtests="${3:-false}"
  local -n expected_tests="$array_name"
  local observed=''
  local expected=''
  [[ "$include_subtests" == true || "$include_subtests" == false ]] || return 1
  safe_regular "$file" "$MAX_TEXT_BYTES" || return 1
  ! grep -Eq -- '^[[:space:]]*--- (SKIP|FAIL):' "$file" || return 1
  observed="$(awk -v include_subtests="$include_subtests" '
    /^--- PASS: / || (include_subtests == "true" && /^[[:space:]]+--- PASS: /) {
      line = $0
      sub(/^[[:space:]]*--- PASS: /, "", line)
      sub(/ \([^)]*\)$/, "", line)
      print line
    }
  ' "$file" | LC_ALL=C sort)" || return 1
  expected="$(printf '%s\n' "${expected_tests[@]}" | LC_ALL=C sort)" ||
    return 1
  [[ "$observed" == "$expected" ]]
}

validate_abi_roster() {
  local -r selected="$1"
  local -r log="$2"
  local observed=''
  local expected=''
  safe_regular "$selected" 65536 || return 1
  observed="$(LC_ALL=C sort -- "$selected")" || return 1
  expected="$(printf '%s\n' "${ABI_TESTS[@]}" | LC_ALL=C sort)" || return 1
  [[ "$observed" == "$expected" ]] || return 1
  assert_log_roster "$log" ABI_TESTS false
}

validate_transport_benchmark() {
  local -r file="$1"
  validate_json_object "$file" || return 1
  jq -e '
    .schema_version == 2 and .benchmark == "java_remote_parent_transport" and
    .provenance.harness == "go_privileged_transport_provider" and
    .provenance.measures == ["transport","provider"] and
    .provenance.excludes == ["java","jni"] and
    (.series | type == "array" and length == 6) and
    [.series[] | [.transport,.outcome]] == [
      ["getsockopt","miss"],["getsockopt","hit"],
      ["getsockopt","one_shot"],["unix","miss"],["unix","hit"],
      ["unix","timeout"]] and
    all(.series[]; .correct == true and .errors == 0 and
      .latency_gate.passed == true)
  ' "$file" >/dev/null
}

validate_packaged_benchmark() {
  local -r file="$1"
  local -r source_revision="$2"
  local -r source_status_sha256="$3"
  validate_json_object "$file" || return 1
  jq -e --arg source "$source_revision" --arg status "$source_status_sha256" '
    .schema_version == 2 and
    .benchmark == "java_remote_parent_packaged_jvm_transport" and
    .provenance.harness == "packaged_agent_java_jni_cgroup_getsockopt" and
    .source == {revision:$source,dirty:false,status_sha256:$status,
      patch_sha256:$status} and
    .runtime.architecture == "amd64" and .runtime.cgroup_mode == "v2" and
    (.runtime.java_version | test("(^|[^0-9])21([^0-9]|$)")) and
    .runtime.no_new_privileges == true and
    .provenance.unix.socket_path_retained == false and
    .provenance.cgroup_bpf.pre_attach_chains_empty == true and
    (.provenance.cgroup_bpf.chains | type == "array" and length == 3) and
    .provenance.cgroup_bpf.stability_checks.query_errors == 0 and
    .provenance.cgroup_bpf.stability_checks.topology_mismatches == 0 and
    (.series | type == "array" and length == 14) and
    ([.series[].scope] | unique | sort) ==
      ["bridge_provider_jni","raw_jni"] and
    ([.series[].transport] | unique | sort) == ["getsockopt","unix"] and
    ([.series[].outcome] | unique | sort) == ["hit","miss","stale","timeout"] and
    all(.series[]; .correct == true and .latency_gate.passed == true)
  ' "$file" >/dev/null
}

validate_matrix_cell_gate() {
  local -r file="$1"
  local -r kernel_id="$2"
  safe_regular "$file" 65536 || return 1
  [[ "$(property_value "$file" format_version)" == 1 &&
    "$(property_value "$file" matrix_revision)" == java-remote-parent-kernel-v1 &&
    "$(property_value "$file" kernel_id)" == "$kernel_id" &&
    "$(property_value "$file" architecture)" == amd64 &&
    "$(property_value "$file" status_scope)" == packaged_jvm_transport_preflight &&
    "$(property_value "$file" status)" == pass &&
    "$(property_value "$file" support_decision)" == runtime_feature_probes_and_required_non_skipping_tests &&
    "$(property_value "$file" version_inference)" == disabled ]]
}

test_summary_json() {
  jq -cn --argjson abi "$(printf '%s\n' "${ABI_TESTS[@]}" | jq -R . | jq -sc .)" \
    --argjson verifier "$(printf '%s\n' "${VERIFIER_TESTS[@]}" | jq -R . | jq -sc .)" \
    --argjson privileged "$(printf '%s\n' "${PRIVILEGED_TESTS[@]}" | jq -R . | jq -sc .)" \
    '{abi:{status:"passed",selected:($abi|length),passed:($abi|length),
      failed:0,skipped:0,roster:$abi},production_verifier:{status:"passed",
      selected:($verifier|length),passed:($verifier|length),failed:0,skipped:0,
      roster:$verifier},privileged:{status:"passed",selected:($privileged|length),
      passed:($privileged|length),failed:0,skipped:0,roster:$privileged}}'
}

transport_summary_json() {
  local -r file="$1"
  jq -cS '{status:"passed",schema_version,benchmark,
    series:[.series[] | {transport,outcome,warmup_rounds,measurement_rounds,
      samples,concurrency,correct,gate:.latency_gate}]}' "$file"
}

packaged_summary_json() {
  local -r file="$1"
  jq -cS '{status:"passed",schema_version,benchmark,
    series_count:(.series|length),scopes:([.series[].scope]|unique),
    transports:([.series[].transport]|unique),
    outcomes:([.series[].outcome]|unique),
    setup:{warmup_batches:.setup.warmup_batches,
      measurement_batches:.setup.measurement_batches,
      concurrency:.setup.concurrency,
      retained_calls_per_series:.setup.retained_calls_per_series,
      total_calls_per_series:.setup.total_calls_per_series},
    topology:{pre_attach_chains_empty:.provenance.cgroup_bpf.pre_attach_chains_empty,
      attached_chain_count:(.provenance.cgroup_bpf.chains|length),
      hierarchy_depth:(.provenance.cgroup_bpf.cgroup_hierarchy|length),
      attach_types:([.provenance.cgroup_bpf.chains[].attach_type]|sort),
      stability_mode:.provenance.cgroup_bpf.stability_mode,
      expected_batches:.provenance.cgroup_bpf.stability_checks.expected_batches,
      observed_pre_batch_snapshots:.provenance.cgroup_bpf.stability_checks.observed_pre_batch_snapshots,
      observed_post_batch_snapshots:.provenance.cgroup_bpf.stability_checks.observed_post_batch_snapshots,
      query_errors:.provenance.cgroup_bpf.stability_checks.query_errors,
      topology_mismatches:.provenance.cgroup_bpf.stability_checks.topology_mismatches},
    cleanup:{socket_path_retained:.provenance.unix.socket_path_retained,
      vm_workspace_cleanup_gate_passed:true,
      compiled_artifact_and_crosslink_validators_passed:true,
      raw_samples_retained:false,program_ids_retained:false},
    gates:{correct:(all(.series[];.correct == true)),
      latency:(all(.series[];.latency_gate.passed == true))}}' "$file"
}

emit_cell_verifier() {
  cat <<'VERIFY'
#!/usr/bin/env bash
set -Eeuo pipefail
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'README.md\tf\nSANITIZATION.md\tf\nSHA256SUMS\tf\ncell.json\tf\nverify.sh\tf'
[[ "$(find -H "$root" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)" == "$expected" ]]
[[ "$(awk 'END {print NR + 0}' "$root/SHA256SUMS")" == 4 ]]
(CDPATH='' cd -- "$root" && sha256sum --check --strict SHA256SUMS >/dev/null)
cmp -s -- "$root/cell.json" <(jq -cS . "$root/cell.json")
jq -e '
  keys == ["benchmarks","coverage","evidence_class","evidence_id","kernel",
    "privacy","raw_commitment","runtime","schema","source","status","tests"] and
  .schema == "obi-issue11-kernel-cell-v1" and .status == "passed" and
  .evidence_class == "focused_non_acceptance" and
  .coverage == {issue_11:{state:"open",advances:[11],closes:[]}} and
  (.source | keys == ["clean","revision","status_sha256"] and
    (.revision | test("^[0-9a-f]{40}$")) and .clean == true and
    (.status_sha256 | test("^[0-9a-f]{64}$"))) and
  (.kernel | keys == ["buildinfo_sha256","config_sha256","id","lvh_digest",
    "lvh_tag","runtime_feature_probe"]) and
  (.kernel.id | test("^(5\\.10-lts|5\\.15-lts|6\\.1-lts|6\\.6-lts|6\\.12-lts|rhel9\\.6)$")) and
  (.kernel.lvh_digest | test("^sha256:[0-9a-f]{64}$")) and
  (.kernel.config_sha256 | test("^[0-9a-f]{64}$")) and
  (.kernel.buildinfo_sha256 | test("^[0-9a-f]{64}$")) and
  .runtime == {architecture:"amd64",cgroup:"unified-v2",
    java_feature_version:21,packaged_jvm:true} and
  .tests.abi.selected == 10 and .tests.production_verifier.selected == 3 and
  .tests.privileged.selected == 9 and
  .benchmarks.transport.status == "passed" and
  .benchmarks.packaged_jvm.status == "passed" and
  .benchmarks.packaged_jvm.topology.attached_chain_count == 3 and
  .benchmarks.packaged_jvm.topology.attach_types ==
    ["CGroupGetsockopt","CGroupSetsockopt","CGroupSockOps"] and
  .benchmarks.packaged_jvm.cleanup.vm_workspace_cleanup_gate_passed == true and
  .benchmarks.packaged_jvm.cleanup.compiled_artifact_and_crosslink_validators_passed == true and
  .benchmarks.packaged_jvm.cleanup.raw_samples_retained == false and
  .benchmarks.packaged_jvm.cleanup.program_ids_retained == false and
  .privacy == {logs_retained:false,paths_retained:false,pids_retained:false,
    binaries_retained:false,raw_samples_retained:false,raw_identifiers_retained:false} and
  (.raw_commitment | keys == ["algorithm","file_count","paths_retained",
    "raw_retained","sha256","total_bytes"] and .algorithm == "sha256" and
    (.sha256 | test("^[0-9a-f]{64}$")) and .file_count >= 1 and .total_bytes >= 1 and
    .raw_retained == false and .paths_retained == false)
' "$root/cell.json" >/dev/null
identity_payload="$(jq -cS '{source_revision:.source.revision,kernel_id:.kernel.id,
  lvh_digest:.kernel.lvh_digest,buildinfo_sha256:.kernel.buildinfo_sha256,
  config_sha256:.kernel.config_sha256,raw_commitment,tests,
  transport:.benchmarks.transport,packaged_jvm:.benchmarks.packaged_jvm}' \
  "$root/cell.json")"
expected_evidence_id="$(printf '%s\n' issue11-kernel-cell-v1 \
  "$identity_payload" | sha256sum)"
expected_evidence_id="${expected_evidence_id%% *}"
[[ "$(jq -er '.evidence_id' "$root/cell.json")" == "$expected_evidence_id" ]]
if grep -Eqi -- '(/tmp/|/home/|/proc/|"(pid|process_id|host_pid|thread_id|trace_id|span_id|program_id|program_ids|binary|binaries)"[[:space:]]*:|\.log"|samples_ns|samples_bytes)' "$root/cell.json"; then
  printf '%s\n' 'private path, identifier, log, binary, or raw sample leaked' >&2
  exit 1
fi
printf 'bounded issue #11 kernel cell internally consistent: %s\n' "$(jq -er '.evidence_id' "$root/cell.json")"
VERIFY
}

write_cell_verifier() {
  local -r output="$1"
  emit_cell_verifier >"$output" || return 1
  chmod 0444 -- "$output"
}

write_cell() {
  local -r raw="$1"
  local -r buildinfo="$2"
  local -r config="$3"
  local source=''
  local source_status=''
  local kernel_id=''
  local lvh_tag=''
  local lvh_digest=''
  local feature_probe=''
  local feature_status=''
  local feature_reason=''
  local buildinfo_sha=''
  local config_sha=''
  local raw_commitment=''
  local tests=''
  local transport=''
  local packaged=''
  local identity_payload=''
  local evidence_id=''
  local file=''
  local transport_file="$raw/transport-benchmark/benchmark.json"
  local packaged_file="$raw/packaged-jvm-benchmark/benchmark.json"

  safe_regular "$raw/source-commit.txt" 128 || return 1
  source="$(<"$raw/source-commit.txt")"
  [[ "$source" =~ ^[0-9a-f]{40}$ ]] || return 1
  source_status="$(printf '' | sha256sum)"
  source_status="${source_status%% *}"
  kernel_id="$(property_value "$raw/kernel-source.properties" kernel_id)" ||
    return 1
  lvh_tag="$(property_value "$raw/kernel-source.properties" lvh_tag)" || return 1
  lvh_digest="$(property_value "$raw/kernel-source.properties" digest)" || return 1
  [[ "$kernel_id" =~ ^(5\.10-lts|5\.15-lts|6\.1-lts|6\.6-lts|6\.12-lts|rhel9\.6)$ &&
    "$lvh_tag" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ &&
    "$lvh_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  feature_probe="$(property_value "$raw/kernel-feature.properties" probe)" || return 1
  feature_status="$(property_value "$raw/kernel-feature.properties" status)" || return 1
  feature_reason="$(property_value "$raw/kernel-feature.properties" reason)" || return 1
  [[ "$feature_probe" == bpftool_feature_probe_kernel_full &&
    "$feature_status" == probe_complete && "$feature_reason" == compatible ]] ||
    return 1
  safe_regular "$buildinfo" 1048576 || return 1
  safe_regular "$config" 4194304 || return 1
  buildinfo_sha="$(sha256sum <"$buildinfo")"; buildinfo_sha="${buildinfo_sha%% *}"
  config_sha="$(sha256sum <"$config")"; config_sha="${config_sha%% *}"
  validate_buildinfo "$buildinfo" "$kernel_id" "$lvh_tag" "$lvh_digest" \
    "$config_sha" || return 1
  validate_abi_roster "$raw/abi-selected-tests.txt" "$raw/abi-tests.log" || return 1
  assert_log_roster "$raw/production-verifier-profiles.log" VERIFIER_TESTS true || return 1
  assert_log_roster "$raw/privileged-tests.log" PRIVILEGED_TESTS false || return 1
  assert_log_roster "$raw/packaged-jvm-benchmark-validation.log" \
    COMPILED_VALIDATOR_TESTS false || return 1
  validate_matrix_cell_gate "$raw/matrix-cell.properties" "$kernel_id" ||
    return 1
  validate_transport_benchmark "$transport_file" || return 1
  validate_packaged_benchmark "$packaged_file" "$source" "$source_status" ||
    return 1
  raw_commitment="$(raw_manifest_commitment "$raw")" || return 1
  tests="$(test_summary_json)" || return 1
  transport="$(transport_summary_json "$transport_file")" || return 1
  packaged="$(packaged_summary_json "$packaged_file")" || return 1
  identity_payload="$(jq -cS -n --arg source "$source" \
    --arg kernel "$kernel_id" --arg digest "$lvh_digest" \
    --arg buildinfo "$buildinfo_sha" --arg config "$config_sha" \
    --argjson raw "$raw_commitment" --argjson tests "$tests" \
    --argjson transport "$transport" --argjson packaged "$packaged" \
    '{source_revision:$source,kernel_id:$kernel,lvh_digest:$digest,
      buildinfo_sha256:$buildinfo,config_sha256:$config,raw_commitment:$raw,
      tests:$tests,transport:$transport,packaged_jvm:$packaged}')" || return 1
  evidence_id="$(printf '%s\n' issue11-kernel-cell-v1 "$identity_payload" | \
    sha256sum)"
  evidence_id="${evidence_id%% *}"

  CANDIDATE_DIRECTORY="$(mktemp -d "$OUTPUT_PARENT/.issue11-project.XXXXXX")"
  CANDIDATE_DIRECTORY="$(CDPATH='' cd -- "$CANDIDATE_DIRECTORY" && pwd -P)"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")"
  jq -cS -n --arg evidence_id "$evidence_id" --arg source "$source" \
    --arg source_status "$source_status" --arg kernel_id "$kernel_id" \
    --arg lvh_tag "$lvh_tag" --arg lvh_digest "$lvh_digest" \
    --arg buildinfo_sha "$buildinfo_sha" --arg config_sha "$config_sha" \
    --arg feature_probe "$feature_probe" --arg feature_status "$feature_status" \
    --arg feature_reason "$feature_reason" --argjson raw "$raw_commitment" \
    --argjson tests "$tests" --argjson transport "$transport" \
    --argjson packaged "$packaged" '
    {schema:"obi-issue11-kernel-cell-v1",status:"passed",
      evidence_class:"focused_non_acceptance",evidence_id:$evidence_id,
      coverage:{issue_11:{state:"open",advances:[11],closes:[]}},
      source:{revision:$source,clean:true,status_sha256:$source_status},
      kernel:{id:$kernel_id,lvh_tag:$lvh_tag,lvh_digest:$lvh_digest,
        config_sha256:$config_sha,buildinfo_sha256:$buildinfo_sha,
        runtime_feature_probe:{probe:$feature_probe,status:$feature_status,
          reason:$feature_reason,final_support_decision:
            "selected_go_runtime_feature_probes_and_non_skipping_tests",
          version_inference:"disabled"}},
      runtime:{architecture:"amd64",cgroup:"unified-v2",
        java_feature_version:21,packaged_jvm:true},tests:$tests,
      benchmarks:{transport:$transport,packaged_jvm:$packaged},
      raw_commitment:$raw,
      privacy:{logs_retained:false,paths_retained:false,pids_retained:false,
        binaries_retained:false,raw_samples_retained:false,
        raw_identifiers_retained:false}}
  ' >"$CANDIDATE_DIRECTORY/cell.json" || return 1
  printf '%s\n' '# Issue #11 bounded kernel cell' '' \
    'This focused, non-acceptance projection advances issue #11 but does not close it.' \
    'It retains bounded summaries and a raw-input commitment only.' \
    >"$CANDIDATE_DIRECTORY/README.md"
  printf '%s\n' '# Sanitization' '' \
    'Raw paths, process/thread IDs, logs, binaries, samples, and BPF program IDs are excluded.' \
    >"$CANDIDATE_DIRECTORY/SANITIZATION.md"
  write_cell_verifier "$CANDIDATE_DIRECTORY/verify.sh"
  (CDPATH='' cd -- "$CANDIDATE_DIRECTORY" &&
    for file in README.md SANITIZATION.md cell.json verify.sh; do sha256sum "$file"; done) \
    >"$CANDIDATE_DIRECTORY/SHA256SUMS"
  find -- "$CANDIDATE_DIRECTORY" -type f -exec chmod 0444 -- {} +
  find -- "$CANDIDATE_DIRECTORY" -depth -type d -exec chmod 0555 -- {} +
  mv -T -- "$CANDIDATE_DIRECTORY" "$OUTPUT_DIRECTORY" || return 1
  CANDIDATE_DIRECTORY="$OUTPUT_DIRECTORY"
  (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null) ||
    return 1
  CANDIDATE_DIRECTORY=''; CANDIDATE_IDENTITY=''
}

validate_cell_json() {
  local -r file="$1"
  local abi=''
  local verifier=''
  local privileged=''
  local identity_payload=''
  local expected_evidence_id=''
  local empty_sha=''

  cmp -s -- "$file" <(jq -cS . "$file") || return 1
  abi="$(printf '%s\n' "${ABI_TESTS[@]}" | jq -R . | jq -sc .)" || return 1
  verifier="$(printf '%s\n' "${VERIFIER_TESTS[@]}" | jq -R . | jq -sc .)" ||
    return 1
  privileged="$(printf '%s\n' "${PRIVILEGED_TESTS[@]}" | jq -R . | jq -sc .)" ||
    return 1
  empty_sha="$(printf '' | sha256sum)"; empty_sha="${empty_sha%% *}"
  jq -e --arg empty "$empty_sha" --argjson abi "$abi" \
    --argjson verifier "$verifier" --argjson privileged "$privileged" '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def result($count;$roster):
      keys == ["failed","passed","roster","selected","skipped","status"] and
      .status == "passed" and .selected == $count and .passed == $count and
      .failed == 0 and .skipped == 0 and .roster == $roster;
    keys == ["benchmarks","coverage","evidence_class","evidence_id","kernel",
      "privacy","raw_commitment","runtime","schema","source","status","tests"] and
    .schema == "obi-issue11-kernel-cell-v1" and .status == "passed" and
    .evidence_class == "focused_non_acceptance" and (.evidence_id | sha256) and
    .coverage == {issue_11:{state:"open",advances:[11],closes:[]}} and
    (.source | keys == ["clean","revision","status_sha256"] and
      (.revision | test("^[0-9a-f]{40}$")) and .clean == true and
      .status_sha256 == $empty) and
    (.kernel | keys == ["buildinfo_sha256","config_sha256","id","lvh_digest",
      "lvh_tag","runtime_feature_probe"] and
      (.id | test("^(5\\.10-lts|5\\.15-lts|6\\.1-lts|6\\.6-lts|6\\.12-lts|rhel9\\.6)$")) and
      (.lvh_tag | test("^[a-z0-9][a-z0-9._-]{0,127}$")) and
      (.lvh_digest | test("^sha256:[0-9a-f]{64}$")) and
      (.config_sha256 | sha256) and (.buildinfo_sha256 | sha256) and
      .runtime_feature_probe == {
        probe:"bpftool_feature_probe_kernel_full",status:"probe_complete",
        reason:"compatible",
        final_support_decision:
          "selected_go_runtime_feature_probes_and_non_skipping_tests",
        version_inference:"disabled"}) and
    .runtime == {architecture:"amd64",cgroup:"unified-v2",
      java_feature_version:21,packaged_jvm:true} and
    (.tests | keys == ["abi","privileged","production_verifier"] and
      (.abi | result(10;$abi)) and
      (.production_verifier | result(3;$verifier)) and
      (.privileged | result(9;$privileged))) and
    (.benchmarks | keys == ["packaged_jvm","transport"]) and
    (.benchmarks.transport |
      keys == ["benchmark","schema_version","series","status"] and
      .status == "passed" and .schema_version == 2 and
      .benchmark == "java_remote_parent_transport" and
      [.series[] | [.transport,.outcome]] == [
        ["getsockopt","miss"],["getsockopt","hit"],
        ["getsockopt","one_shot"],["unix","miss"],
        ["unix","hit"],["unix","timeout"]] and
      all(.series[];
        keys == ["concurrency","correct","gate","measurement_rounds","outcome",
          "samples","transport","warmup_rounds"] and .correct == true and
        (.gate | keys == ["kind","p50_min_ns","p99_max_ns","passed"] and
          .passed == true))) and
    (.benchmarks.packaged_jvm |
      keys == ["benchmark","cleanup","gates","outcomes","schema_version","scopes",
        "series_count","setup","status","topology","transports"] and
      .status == "passed" and .schema_version == 2 and
      .benchmark == "java_remote_parent_packaged_jvm_transport" and
      .series_count == 14 and .scopes == ["bridge_provider_jni","raw_jni"] and
      .transports == ["getsockopt","unix"] and
      .outcomes == ["hit","miss","stale","timeout"] and
      (.setup | keys == ["concurrency","measurement_batches",
        "retained_calls_per_series","total_calls_per_series","warmup_batches"] and
        all(.[]; type == "number" and . >= 1)) and
      (.topology | keys == ["attach_types","attached_chain_count","expected_batches",
        "hierarchy_depth","observed_post_batch_snapshots",
        "observed_pre_batch_snapshots","pre_attach_chains_empty","query_errors",
        "stability_mode","topology_mismatches"] and
        .pre_attach_chains_empty == true) and
      .topology.attached_chain_count == 3 and .topology.hierarchy_depth >= 1 and
      .topology.attach_types ==
        ["CGroupGetsockopt","CGroupSetsockopt","CGroupSockOps"] and
      .topology.stability_mode == "boundary_identity_only" and
      .topology.expected_batches >= 1 and
      .topology.observed_pre_batch_snapshots == .topology.expected_batches and
      .topology.observed_post_batch_snapshots == .topology.expected_batches and
      .topology.query_errors == 0 and .topology.topology_mismatches == 0 and
      .cleanup == {compiled_artifact_and_crosslink_validators_passed:true,
        program_ids_retained:false,raw_samples_retained:false,
        socket_path_retained:false,vm_workspace_cleanup_gate_passed:true} and
      .gates == {correct:true,latency:true}) and
    (.raw_commitment | keys == ["algorithm","file_count","paths_retained",
      "raw_retained","sha256","total_bytes"] and .algorithm == "sha256" and
      (.sha256 | sha256) and .file_count >= 1 and .total_bytes >= 1 and
      .raw_retained == false and .paths_retained == false) and
    .privacy == {logs_retained:false,paths_retained:false,pids_retained:false,
      binaries_retained:false,raw_samples_retained:false,
      raw_identifiers_retained:false}
  ' "$file" >/dev/null || return 1
  identity_payload="$(jq -cS '{source_revision:.source.revision,
    kernel_id:.kernel.id,lvh_digest:.kernel.lvh_digest,
    buildinfo_sha256:.kernel.buildinfo_sha256,
    config_sha256:.kernel.config_sha256,raw_commitment,tests,
    transport:.benchmarks.transport,packaged_jvm:.benchmarks.packaged_jvm}' \
    "$file")" || return 1
  expected_evidence_id="$(printf '%s\n' issue11-kernel-cell-v1 \
    "$identity_payload" | sha256sum)" || return 1
  expected_evidence_id="${expected_evidence_id%% *}"
  [[ "$(jq -er '.evidence_id' "$file")" == "$expected_evidence_id" ]] || return 1
  ! grep -Eqi -- '(/tmp/|/home/|/proc/|"(pid|process_id|host_pid|thread_id|trace_id|span_id|program_id|program_ids|binary|binaries)"[[:space:]]*:|\.log"|samples_ns|samples_bytes)' \
    "$file"
}

validate_cell() {
  local -r cell="$1"
  [[ "$cell" == /* && -d "$cell" && ! -L "$cell" &&
    "$(readlink -f -- "$cell")" == "$cell" ]] || return 1
  local expected=$'README.md\tf\nSANITIZATION.md\tf\nSHA256SUMS\tf\ncell.json\tf\nverify.sh\tf'
  [[ "$(find -- "$cell" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' |
    LC_ALL=C sort)" == "$expected" ]] || return 1
  [[ "$(awk 'END {print NR + 0}' "$cell/SHA256SUMS")" == 4 ]] || return 1
  (CDPATH='' cd -- "$cell" && sha256sum --check --strict SHA256SUMS >/dev/null) ||
    return 1
  cmp -s -- "$cell/verify.sh" <(emit_cell_verifier) || return 1
  validate_cell_json "$cell/cell.json" || return 1
}

matrix_seed() {
  local cell=''
  local -a cells=("$@")
  local -a rows=()
  for cell in "${cells[@]}"; do
    validate_cell "$cell" || return 1
    rows+=("$(sha256sum <"$cell/cell.json")")
  done
  printf '%s\n' issue11-kernel-matrix-v1 "${rows[@]}" | sha256sum |
    awk '{print $1}'
}

matrix_name() {
  local -a cells=("$@")
  local seed=''
  local source=''
  local observed_source=''
  local observed_kernel=''
  local index=0
  [[ "${#cells[@]}" == 6 ]] || return 1
  for index in "${!cells[@]}"; do
    validate_cell "${cells[index]}" || return 1
    observed_source="$(jq -er '.source.revision' \
      "${cells[index]}/cell.json")" || return 1
    observed_kernel="$(jq -er '.kernel.id' "${cells[index]}/cell.json")" ||
      return 1
    [[ "$observed_kernel" == "${KERNEL_ORDER[index]}" ]] || return 1
    if ((index == 0)); then source="$observed_source"; fi
    [[ "$observed_source" == "$source" ]] || return 1
  done
  seed="$(matrix_seed "${cells[@]}")" || return 1
  printf 'issue11-kernel-matrix-%s-%s\n' "${source:0:12}" "${seed:0:12}"
}

write_matrix_verifier() {
  local -r output="$1"
  cat >"$output" <<'VERIFY'
#!/usr/bin/env bash
set -Eeuo pipefail
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'README.md\tf\nSANITIZATION.md\tf\nSHA256SUMS\tf\nmatrix.json\tf\nverify.sh\tf'
[[ "$(find -H "$root" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)" == "$expected" ]]
[[ "$(awk 'END {print NR + 0}' "$root/SHA256SUMS")" == 4 ]]
(CDPATH='' cd -- "$root" && sha256sum --check --strict SHA256SUMS >/dev/null)
cmp -s -- "$root/matrix.json" <(jq -cS . "$root/matrix.json")
jq -e '
  keys == ["bounded_scope","cells","coverage","evidence_class","evidence_id",
    "explicitly_uncovered","privacy","schema","status"] and
  .schema == "obi-issue11-kernel-matrix-v1" and
  .status == "passed_bounded_scope" and
  .evidence_class == "focused_non_acceptance" and
  .coverage == {issue_11:{state:"open",advances:[11],closes:[]}} and
  [.cells[].kernel.id] == ["5.10-lts","5.15-lts","6.1-lts","6.6-lts","6.12-lts","rhel9.6"] and
  (.cells | length == 6) and
  ([.cells[].source.revision] | unique | length) == 1 and
  all(.cells[];
    keys == ["benchmarks","coverage","evidence_class","evidence_id","kernel",
      "privacy","raw_commitment","runtime","schema","source","status","tests"] and
    .schema == "obi-issue11-kernel-cell-v1" and .status == "passed" and
    .coverage == {issue_11:{state:"open",advances:[11],closes:[]}}) and
  .bounded_scope == {architecture:"amd64",cgroup:"unified-v2",
    java_feature_version:21,packaged_jvm:true} and
  .explicitly_uncovered == ["rhel8","arm64","cgroup-v1-hybrid",
    "namespaces","delegated-cgroups","nested-production"] and
  .privacy == {logs_retained:false,paths_retained:false,pids_retained:false,
    binaries_retained:false,raw_samples_retained:false,raw_identifiers_retained:false}
' "$root/matrix.json" >/dev/null
empty_sha="$(printf '' | sha256sum)"; empty_sha="${empty_sha%% *}"
abi='["TestRecordCorpus","TestRecordGoldenVector","TestRecordRejectsInvalidFraming","TestRecordDoesNotMarshalUnknownStatus","TestRecordRejectsFutureLargerRecordInVersionOne","TestVersionMismatchIsTyped","TestValidRemoteParentRejectsZeroIDs","TestRequestGoldenVector","TestRequestSourceIsExplicitOnTheWire","TestSampledAndUnsampledRoundTrip"]'
production='["TestBPFVerifierProductionProfiles","TestBPFVerifierProductionProfiles/generictracer/apache-java-https","TestBPFVerifierProductionProfiles/tpinjector/java-remote-parent"]'
privileged='["TestJavaRemoteParentPrimarySocketAuthority","TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook","TestJavaRemoteParentPrimaryJVMFaults","TestJavaRemoteParentPrimaryJVMDirectSSLSocket","TestJavaRemoteParentGenericJVMDirectSSLSocket","TestJavaRemoteParentNestedCgroupLifecycle","TestJavaRemoteParentCgroupLinkProcessDeathCleanup","TestJavaRemoteParentCgroupPartialAttachRollback","TestJavaRemoteParentBridgeLoadRequiresPrivileges"]'
jq -e --arg empty "$empty_sha" --argjson abi "$abi" \
  --argjson production "$production" --argjson privileged "$privileged" '
  def sha256: type == "string" and test("^[0-9a-f]{64}$");
  def result($count;$roster):
    keys == ["failed","passed","roster","selected","skipped","status"] and
    .status == "passed" and .selected == $count and .passed == $count and
    .failed == 0 and .skipped == 0 and .roster == $roster;
  all(.cells[];
    keys == ["benchmarks","coverage","evidence_class","evidence_id","kernel",
      "privacy","raw_commitment","runtime","schema","source","status","tests"] and
    .schema == "obi-issue11-kernel-cell-v1" and .status == "passed" and
    .evidence_class == "focused_non_acceptance" and (.evidence_id | sha256) and
    .coverage == {issue_11:{state:"open",advances:[11],closes:[]}} and
    (.source | keys == ["clean","revision","status_sha256"] and
      (.revision | test("^[0-9a-f]{40}$")) and .clean == true and
      .status_sha256 == $empty) and
    (.kernel | keys == ["buildinfo_sha256","config_sha256","id","lvh_digest",
      "lvh_tag","runtime_feature_probe"] and
      (.id | test("^(5\\.10-lts|5\\.15-lts|6\\.1-lts|6\\.6-lts|6\\.12-lts|rhel9\\.6)$")) and
      (.lvh_tag | test("^[a-z0-9][a-z0-9._-]{0,127}$")) and
      (.lvh_digest | test("^sha256:[0-9a-f]{64}$")) and
      (.config_sha256 | sha256) and (.buildinfo_sha256 | sha256) and
      .runtime_feature_probe == {
        probe:"bpftool_feature_probe_kernel_full",status:"probe_complete",
        reason:"compatible",
        final_support_decision:
          "selected_go_runtime_feature_probes_and_non_skipping_tests",
        version_inference:"disabled"}) and
    .runtime == {architecture:"amd64",cgroup:"unified-v2",
      java_feature_version:21,packaged_jvm:true} and
    (.tests | keys == ["abi","privileged","production_verifier"] and
      (.abi | result(10;$abi)) and
      (.production_verifier | result(3;$production)) and
      (.privileged | result(9;$privileged))) and
    (.benchmarks | keys == ["packaged_jvm","transport"]) and
    (.benchmarks.transport |
      keys == ["benchmark","schema_version","series","status"] and
      .status == "passed" and .schema_version == 2 and
      .benchmark == "java_remote_parent_transport" and
      [.series[] | [.transport,.outcome]] == [
        ["getsockopt","miss"],["getsockopt","hit"],
        ["getsockopt","one_shot"],["unix","miss"],
        ["unix","hit"],["unix","timeout"]] and
      all(.series[];
        keys == ["concurrency","correct","gate","measurement_rounds","outcome",
          "samples","transport","warmup_rounds"] and .correct == true and
        (.gate | keys == ["kind","p50_min_ns","p99_max_ns","passed"] and
          .passed == true))) and
    (.benchmarks.packaged_jvm |
      keys == ["benchmark","cleanup","gates","outcomes","schema_version","scopes",
        "series_count","setup","status","topology","transports"] and
      .status == "passed" and .schema_version == 2 and
      .benchmark == "java_remote_parent_packaged_jvm_transport" and
      .series_count == 14 and .scopes == ["bridge_provider_jni","raw_jni"] and
      .transports == ["getsockopt","unix"] and
      .outcomes == ["hit","miss","stale","timeout"] and
      (.setup | keys == ["concurrency","measurement_batches",
        "retained_calls_per_series","total_calls_per_series","warmup_batches"] and
        all(.[]; type == "number" and . >= 1)) and
      (.topology | keys == ["attach_types","attached_chain_count","expected_batches",
        "hierarchy_depth","observed_post_batch_snapshots",
        "observed_pre_batch_snapshots","pre_attach_chains_empty","query_errors",
        "stability_mode","topology_mismatches"] and
        .pre_attach_chains_empty == true) and
      .topology.attached_chain_count == 3 and .topology.hierarchy_depth >= 1 and
      .topology.attach_types ==
        ["CGroupGetsockopt","CGroupSetsockopt","CGroupSockOps"] and
      .topology.stability_mode == "boundary_identity_only" and
      .topology.expected_batches >= 1 and
      .topology.observed_pre_batch_snapshots == .topology.expected_batches and
      .topology.observed_post_batch_snapshots == .topology.expected_batches and
      .topology.query_errors == 0 and .topology.topology_mismatches == 0 and
      .cleanup == {compiled_artifact_and_crosslink_validators_passed:true,
        program_ids_retained:false,raw_samples_retained:false,
        socket_path_retained:false,vm_workspace_cleanup_gate_passed:true} and
      .gates == {correct:true,latency:true}) and
    (.raw_commitment | keys == ["algorithm","file_count","paths_retained",
      "raw_retained","sha256","total_bytes"] and .algorithm == "sha256" and
      (.sha256 | sha256) and .file_count >= 1 and .total_bytes >= 1 and
      .raw_retained == false and .paths_retained == false) and
    .privacy == {logs_retained:false,paths_retained:false,pids_retained:false,
      binaries_retained:false,raw_samples_retained:false,
      raw_identifiers_retained:false})
' "$root/matrix.json" >/dev/null
while IFS= read -r cell; do
  identity_payload="$(jq -cS '{source_revision:.source.revision,
    kernel_id:.kernel.id,lvh_digest:.kernel.lvh_digest,
    buildinfo_sha256:.kernel.buildinfo_sha256,
    config_sha256:.kernel.config_sha256,raw_commitment,tests,
    transport:.benchmarks.transport,packaged_jvm:.benchmarks.packaged_jvm}' \
    <<<"$cell")"
  expected_cell_id="$(printf '%s\n' issue11-kernel-cell-v1 \
    "$identity_payload" | sha256sum)"
  expected_cell_id="${expected_cell_id%% *}"
  [[ "$(jq -er '.evidence_id' <<<"$cell")" == "$expected_cell_id" ]]
done < <(jq -cS '.cells[]' "$root/matrix.json")
mapfile -t cell_digests < <(jq -cS '.cells[]' "$root/matrix.json" | while IFS= read -r cell; do
  printf '%s\n' "$cell" | sha256sum
done)
[[ "${#cell_digests[@]}" == 6 ]]
expected_evidence_id="$(printf '%s\n' issue11-kernel-matrix-v1 "${cell_digests[@]}" | sha256sum)"
expected_evidence_id="${expected_evidence_id%% *}"
[[ "$(jq -er '.evidence_id' "$root/matrix.json")" == "$expected_evidence_id" ]]
source_revision="$(jq -er '.cells[0].source.revision' "$root/matrix.json")"
[[ "${root##*/}" == "issue11-kernel-matrix-${source_revision:0:12}-${expected_evidence_id:0:12}" ]]
if grep -Eqi -- '(/tmp/|/home/|/proc/|"(pid|process_id|host_pid|thread_id|trace_id|span_id|program_id|program_ids|binary|binaries)"[[:space:]]*:|samples_ns|samples_bytes)' "$root/matrix.json"; then
  printf '%s\n' 'private material leaked into issue #11 matrix' >&2
  exit 1
fi
printf 'bounded issue #11 kernel matrix internally consistent: %s\n' "$(jq -er '.evidence_id' "$root/matrix.json")"
VERIFY
  chmod 0444 -- "$output"
}

write_matrix() {
  local -a cells=("$@")
  local output="${cells[-1]}"
  unset 'cells[-1]'
  local expected_kernel=''
  local observed_kernel=''
  local source=''
  local observed_source=''
  local seed=''
  local expected_name=''
  local cell=''
  local file=''
  local -a cell_json=()
  local index=0

  validate_output "$output" || return 1
  for index in "${!cells[@]}"; do
    cell="${cells[index]}"
    validate_cell "$cell" || return 1
    observed_kernel="$(jq -er '.kernel.id' "$cell/cell.json")" || return 1
    expected_kernel="${KERNEL_ORDER[index]}"
    [[ "$observed_kernel" == "$expected_kernel" ]] || return 1
    observed_source="$(jq -er '.source.revision' "$cell/cell.json")" || return 1
    if ((index == 0)); then source="$observed_source"; fi
    [[ "$observed_source" == "$source" ]] || return 1
    cell_json+=("$(jq -cS . "$cell/cell.json")")
  done
  seed="$(matrix_seed "${cells[@]}")" || return 1
  expected_name="issue11-kernel-matrix-${source:0:12}-${seed:0:12}"
  [[ "${output##*/}" == "$expected_name" ]] || return 1
  CANDIDATE_DIRECTORY="$(mktemp -d "$OUTPUT_PARENT/.issue11-project.XXXXXX")"
  CANDIDATE_DIRECTORY="$(CDPATH='' cd -- "$CANDIDATE_DIRECTORY" && pwd -P)"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")"
  printf '%s\n' "${cell_json[@]}" | jq -cS -s --arg evidence_id "$seed" '
    {schema:"obi-issue11-kernel-matrix-v1",status:"passed_bounded_scope",
      evidence_class:"focused_non_acceptance",evidence_id:$evidence_id,
      coverage:{issue_11:{state:"open",advances:[11],closes:[]}},cells:.,
      bounded_scope:{architecture:"amd64",cgroup:"unified-v2",
        java_feature_version:21,packaged_jvm:true},
      explicitly_uncovered:["rhel8","arm64","cgroup-v1-hybrid",
        "namespaces","delegated-cgroups","nested-production"],
      privacy:{logs_retained:false,paths_retained:false,pids_retained:false,
        binaries_retained:false,raw_samples_retained:false,
        raw_identifiers_retained:false}}
  ' >"$CANDIDATE_DIRECTORY/matrix.json"
  printf '%s\n' '# Issue #11 bounded kernel matrix' '' \
    'Six digest-pinned amd64, unified-cgroup-v2, Java 21 packaged-JVM cells passed.' \
    'This focused projection advances issue #11 and explicitly does not close it.' \
    >"$CANDIDATE_DIRECTORY/README.md"
  printf '%s\n' '# Sanitization' '' \
    'Only safe cell summaries and commitments are retained; raw diagnostics remain separate.' \
    >"$CANDIDATE_DIRECTORY/SANITIZATION.md"
  write_matrix_verifier "$CANDIDATE_DIRECTORY/verify.sh"
  (CDPATH='' cd -- "$CANDIDATE_DIRECTORY" &&
    for file in README.md SANITIZATION.md matrix.json verify.sh; do sha256sum "$file"; done) \
    >"$CANDIDATE_DIRECTORY/SHA256SUMS"
  find -- "$CANDIDATE_DIRECTORY" -type f -exec chmod 0444 -- {} +
  find -- "$CANDIDATE_DIRECTORY" -depth -type d -exec chmod 0555 -- {} +
  mv -T -- "$CANDIDATE_DIRECTORY" "$OUTPUT_DIRECTORY" || return 1
  CANDIDATE_DIRECTORY="$OUTPUT_DIRECTORY"
  (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null) ||
    return 1
  CANDIDATE_DIRECTORY=''; CANDIDATE_IDENTITY=''
}

cell_mode() {
  local -r raw="$1"
  local -r buildinfo="$2"
  local -r config="$3"
  local -r output="$4"
  command -v python3 >/dev/null 2>&1 ||
    die 'python3 is required for duplicate-key-safe JSON validation' || return 1
  validate_output "$output" || die 'unsafe cell output' || return 1
  WORK_DIRECTORY="$(mktemp -d /tmp/obi-issue11-project.XXXXXX)"
  WORK_DIRECTORY="$(CDPATH='' cd -- "$WORK_DIRECTORY" && pwd -P)"
  WORK_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$WORK_DIRECTORY")"
  write_cell "$raw" "$buildinfo" "$config" ||
    die 'raw kernel cell failed bounded projection' || return 1
  printf 'bounded issue #11 cell projected: %s\n' "$OUTPUT_DIRECTORY"
}

main() {
  case "${1:-}" in
    cell-v1)
      [[ $# == 5 ]] || { usage >&2; return 2; }
      cell_mode "$2" "$3" "$4" "$5"
      ;;
    matrix-name-v1)
      [[ $# == 7 ]] || { usage >&2; return 2; }
      matrix_name "$2" "$3" "$4" "$5" "$6" "$7"
      ;;
    matrix-v1)
      [[ $# == 8 ]] || { usage >&2; return 2; }
      write_matrix "$2" "$3" "$4" "$5" "$6" "$7" "$8"
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage >&2
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
