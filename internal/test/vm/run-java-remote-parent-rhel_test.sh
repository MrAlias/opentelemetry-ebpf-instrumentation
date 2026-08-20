#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR="$script_dir"
unset script_dir

# SCRIPT_DIR is resolved above; ShellCheck cannot follow this dynamic path.
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/run-java-remote-parent-rhel.sh"

TEST_TMP_DIR=""
readonly TEST_TMP_PARENT="${TMPDIR:-/tmp}"
declare -a TEST_FILES=()
declare -a TEST_DIRS=()

test_fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local path=""
    local index=0

    for path in "${TEST_FILES[@]}"; do
        unlink -- "$path" 2>/dev/null || true
    done
    for ((index = ${#TEST_DIRS[@]} - 1; index >= 0; index--)); do
        rmdir -- "${TEST_DIRS[index]}" 2>/dev/null || true
    done
}

track_fixture() {
    local -r path="$1"

    TEST_FILES+=("$path")
}

write_series() {
    local -r transport="$1"
    local -r outcome="$2"
    local -r warmup_rounds="$3"
    local -r measurement_rounds="$4"
    local -r samples="$5"
    local -r p50_ns="$6"
    local -r p95_ns="$7"
    local -r p99_ns="$8"
    local -r valid="$9"
    local -r missing="${10}"
    local -r already_consumed="${11}"
    local -r timeout="${12}"
    local -r gate_kind="${13}"
    local -r p50_min_ns="${14}"
    local -r p99_max_ns="${15}"
    local -r passed="${16}"
    local -r batch_elapsed_ns="$((samples * 1000000))"

    printf '%s' "{\"transport\":\"${transport}\",\"outcome\":\"${outcome}\","
    printf '%s' "\"warmup_rounds\":${warmup_rounds},\"measurement_rounds\":${measurement_rounds},"
    printf '%s' "\"samples\":${samples},\"concurrency\":8,\"batch_elapsed_ns\":${batch_elapsed_ns},"
    printf '%s' "\"p50_ns\":${p50_ns},\"p95_ns\":${p95_ns},\"p99_ns\":${p99_ns},"
    printf '%s' '"operations_per_second":1000,'
    printf '%s' "\"valid\":${valid},\"missing\":${missing},"
    printf '%s' "\"already_consumed\":${already_consumed},\"timeout\":${timeout},"
    printf '%s' '"errors":0,"correct":true,"latency_gate":{'
    printf '%s' "\"kind\":\"${gate_kind}\",\"p50_min_ns\":${p50_min_ns},"
    printf '%s' "\"p99_max_ns\":${p99_max_ns},\"passed\":${passed}}}"
}

write_artifact() {
    local -r path="$1"
    local -r getsockopt_miss_p99="$2"
    local -r getsockopt_miss_passed="$3"
    local -r timeout_p50="$4"
    local -r timeout_p99="$5"
    local -r timeout_passed="$6"
    local -r duplicate_series="$7"

    track_fixture "$path"
    {
        printf '%s' '{"schema_version":2,"benchmark":"java_remote_parent_transport",'
        printf '%s' '"provenance":{"harness":"go_privileged_transport_provider",'
        printf '%s' '"measures":["transport","provider"],"excludes":["java","jni"]},'
        printf '%s' '"unix_timeout_deadline_ns":50000000,"series":['
        write_series \
            getsockopt miss 16 512 4096 100000 500000 "$getsockopt_miss_p99" \
            0 4096 0 0 p99_lt 0 1000000 "$getsockopt_miss_passed"
        printf ','
        write_series \
            getsockopt hit 16 512 4096 100000 500000 999999 \
            4096 0 0 0 p99_lt 0 1000000 true
        printf ','
        write_series \
            getsockopt one_shot 16 512 4096 100000 500000 999999 \
            512 1792 1792 0 correctness_only 0 0 true
        printf ','
        write_series \
            unix miss 8 128 1024 1000000 10000000 49999999 \
            0 1024 0 0 p99_lt 0 50000000 true
        printf ','
        write_series \
            unix hit 8 128 1024 1000000 10000000 49999999 \
            1024 0 0 0 p99_lt 0 50000000 true
        printf ','
        write_series \
            unix timeout 8 128 1024 "$timeout_p50" 75000000 "$timeout_p99" \
            0 0 0 1024 p50_gte_p99_lte 50000000 100000000 "$timeout_passed"
        if [[ "$duplicate_series" == true ]]; then
            printf ','
            write_series \
                getsockopt miss 16 512 4096 100000 500000 "$getsockopt_miss_p99" \
                0 4096 0 0 p99_lt 0 1000000 "$getsockopt_miss_passed"
        fi
        printf '%s\n' ']}'
    } > "$path"
    chmod 600 -- "$path"
}

write_mutated_fixture() {
    local -r path="$1"
    local -r source_file="$2"
    local -r expression="$3"

    track_fixture "$path"
    sed -e "$expression" "$source_file" > "$path"
    chmod 600 -- "$path"
}

assert_artifact_accepted() {
    local -r description="$1"
    local -r path="$2"

    require_transport_benchmark_artifact "$path" || \
        test_fail "validator rejected ${description}"
}

assert_artifact_rejected() {
    local -r description="$1"
    local -r path="$2"

    if (require_transport_benchmark_artifact "$path" >/dev/null 2>&1); then
        test_fail "validator accepted ${description}"
    fi
}

assert_all_gates_pass() {
    local -r description="$1"
    local -r path="$2"

    transport_benchmark_artifact_gates_pass "$path" || \
        test_fail "validator reported a failed gate for ${description}"
}

assert_failed_gate_retained() {
    local -r description="$1"
    local -r path="$2"

    assert_artifact_accepted "$description" "$path"
    if transport_benchmark_artifact_gates_pass "$path"; then
        test_fail "validator reported all gates passed for ${description}"
    fi
}

write_verifier_log() {
    local -r path="$1"
    local -r include_generic="$2"
    local -r include_sockopt="$3"
    local -r top_level_result="$4"

    track_fixture "$path"
    {
        printf '%s\n' "=== RUN   ${VERIFIER_TEST_NAME}"
        if [[ "$include_generic" == true ]]; then
            printf '%s\n' "--- PASS: ${VERIFIER_GENERIC_PROFILE} (0.01s)"
        fi
        if [[ "$include_sockopt" == true ]]; then
            printf '%s\n' "--- PASS: ${VERIFIER_SOCKOPT_PROFILE} (0.01s)"
        fi
        printf '%s\n' "--- ${top_level_result}: ${VERIFIER_TEST_NAME} (0.02s)"
    } > "$path"
    chmod 600 -- "$path"
}

assert_verifier_log_accepted() {
    local -r description="$1"
    local -r path="$2"

    require_production_verifier_profiles_passed "$path" || \
        test_fail "verifier validator rejected ${description}"
}

assert_verifier_log_rejected() {
    local -r description="$1"
    local -r path="$2"

    if (require_production_verifier_profiles_passed "$path" >/dev/null 2>&1); then
        test_fail "verifier validator accepted ${description}"
    fi
}

test_production_verifier_profile_validation() {
    local -r valid="${TEST_TMP_DIR}/verifier-valid.log"
    local -r missing_generic="${TEST_TMP_DIR}/verifier-missing-generic.log"
    local -r missing_sockopt="${TEST_TMP_DIR}/verifier-missing-sockopt.log"
    local -r skipped="${TEST_TMP_DIR}/verifier-skipped.log"
    local -r spoofed="${TEST_TMP_DIR}/verifier-spoofed.log"

    write_verifier_log "$valid" true true PASS
    assert_verifier_log_accepted 'complete production profiles' "$valid"

    write_verifier_log "$missing_generic" false true PASS
    assert_verifier_log_rejected 'missing generic Java profile' "$missing_generic"

    write_verifier_log "$missing_sockopt" true false PASS
    assert_verifier_log_rejected 'missing cgroup sockopt profile' "$missing_sockopt"

    write_verifier_log "$skipped" true true SKIP
    assert_verifier_log_rejected 'skipped production profile test' "$skipped"

    write_mutated_fixture \
        "$spoofed" "$valid" 's/^--- PASS:/log prefix --- PASS:/'
    assert_verifier_log_rejected 'prefixed PASS substrings' "$spoofed"
}

test_deterministic_artifact_path() {
    local -r artifact_dir="${TEST_TMP_DIR}/deterministic-artifact"
    local artifact_path=""
    local expected_path=""

    artifact_path="$(create_transport_benchmark_artifact_path "$artifact_dir")" || \
        test_fail 'failed to create the deterministic artifact path'
    TEST_DIRS+=("$artifact_dir")
    expected_path="$(cd -L -- "$artifact_dir" && pwd -L)/benchmark.json"
    [[ "$artifact_path" == "$expected_path" ]] || \
        test_fail 'deterministic artifact path was not canonical'
    if (create_transport_benchmark_artifact_path "$artifact_dir" >/dev/null 2>&1); then
        test_fail 'deterministic artifact path allowed reuse'
    fi
}

test_relative_artifact_path_resolution() {
    local -r artifact_name=relative-artifact
    local -r artifact_dir="${TEST_TMP_DIR}/${artifact_name}"
    local artifact_path=""
    local expected_path=""

    artifact_path="$(
        cd -- "$TEST_TMP_DIR"
        create_transport_benchmark_artifact_path "$artifact_name"
    )" || test_fail 'failed to create the relative artifact path'
    TEST_DIRS+=("$artifact_dir")
    expected_path="$(cd -L -- "$artifact_dir" && pwd -L)/benchmark.json"
    [[ "$artifact_path" == /* ]] || \
        test_fail 'relative artifact path was not made absolute'
    [[ "$artifact_path" == "$expected_path" ]] || \
        test_fail 'relative artifact path was not resolved from the invoking directory'
    track_fixture "$artifact_path"
    (
        cd -- "${SCRIPT_DIR}/../../../pkg/internal/ebpf/tpinjector"
        : > "$artifact_path"
    ) || test_fail 'artifact path changed under the Go package working directory'
    [[ -f "$artifact_path" ]] || \
        test_fail 'consumer did not publish through the resolved artifact path'
}

test_artifact_path_preserves_symlinks() {
    local absolute_test_dir=""
    local target_dir=""
    local link_path=""
    local artifact_dir=""
    local artifact_path=""

    absolute_test_dir="$(cd -L -- "$TEST_TMP_DIR" && pwd -L)"
    target_dir="${absolute_test_dir}/artifact-target"
    link_path="${absolute_test_dir}/artifact-link"
    artifact_dir="${link_path}/transport-benchmark"

    mkdir -m 700 -- "$target_dir"
    TEST_DIRS+=("$target_dir")
    ln -s -- "$(basename -- "$target_dir")" "$link_path"
    track_fixture "$link_path"
    artifact_path="$(create_transport_benchmark_artifact_path "$artifact_dir")" || \
        test_fail 'failed to create an artifact directory beneath a symlink'
    TEST_DIRS+=("${target_dir}/transport-benchmark")
    [[ "$artifact_path" == "${artifact_dir}/benchmark.json" ]] || \
        test_fail 'artifact path resolution concealed a symlink component'
    [[ "$artifact_path" != "${target_dir}/transport-benchmark/benchmark.json" ]] || \
        test_fail 'artifact path resolution returned the physical symlink target'
}

test_relative_agent_path_resolution() {
    local -r fixture="${TEST_TMP_DIR}/obi-java-agent.jar"
    local expected=""
    local resolved=""

    track_fixture "$fixture"
    : > "$fixture"
    expected="$(realpath "$fixture")"
    resolved="$(
        cd -- "$TEST_TMP_PARENT"
        resolve_existing_path "$(basename -- "$TEST_TMP_DIR")/$(basename -- "$fixture")"
    )"
    [[ "$resolved" == "$expected" ]] || \
        test_fail 'relative Java agent path did not resolve from the invoking directory'
}

require_rhel_workflow_vm_contract() {
    local -r workflow="$1"
    local mktemp_line=""
    local launch_line=""
    local chown_line=""
    local cleanup_line=""
    local rethrow_line=""

    grep -Fq -- "vm_workdir=\"\$(mktemp -d -- \"\$RUNNER_TEMP/java-remote-parent-kernel-vm.XXXXXX\")\"" \
        "$workflow" || return 1
    grep -Fq -- "WORKDIR=\"\$vm_workdir\"" "$workflow" || return 1
    ! grep -Fq -- "WORKDIR=\"\$(pwd)\"" "$workflow" || return 1
    grep -Fq -- "runner_uid=\"\$(id -u)\"" "$workflow" || return 1
    grep -Fq -- "runner_gid=\"\$(id -g)\"" "$workflow" || return 1
    grep -Fq -- "sudo chown -R -- \"\$runner_uid:\$runner_gid\" testoutput" "$workflow" || return 1
    grep -Fq -- "exit \"\$launch_status\"" "$workflow" || return 1
    grep -Fq -- "rm -rf -- \"\$vm_workdir\"" "$workflow" || return 1
    grep -Fq -- 'timeout-minutes: 60' "$workflow" || return 1
    grep -Fq -- 'TestPackagedJVMBenchmarkArtifactV2StrictContract' "$workflow" || return 1
    grep -Fq -- 'TestPackagedJVMBenchmarkArtifactV2RejectsSemanticMutations' "$workflow" || return 1
    grep -Fq -- 'TestDecodePackagedJVMBenchmarkArtifactV2RejectsStructuralMutations' "$workflow" || return 1
    grep -Fq -- "JAVA_REMOTE_PARENT_KERNEL_ID=\"\$OBI_VM_KERNEL_ID\"" \
        "$workflow" || return 1
    grep -Fq -- 'support_decision=runtime_feature_probes_and_required_non_skipping_tests' \
        "$workflow" || return 1
    grep -Fq -- 'version_inference=disabled' "$workflow" || return 1
    grep -Fq -- 'cell_status=unsupported' "$workflow" || return 1
    grep -Fq -- 'workflow_ref=%s' "$workflow" || return 1
    grep -Fq -- 'run_attempt=%s' "$workflow" || return 1
    for kernel_id in 5.10-lts 5.15-lts 6.1-lts 6.6-lts 6.12-lts rhel9.6; do
        [[ "$(grep -Fxc -- "          - ${kernel_id}" "$workflow")" == 1 ]] || return 1
    done
    ! grep -Eq -- '^[[:space:]]+- rhel8[.]' "$workflow" || return 1
    mktemp_line="$(grep -Fn -- "vm_workdir=\"\$(mktemp -d --" "$workflow" | cut -d: -f1)"
    launch_line="$(grep -Fn -- 'sudo make -C internal/test/vm' "$workflow" | cut -d: -f1)"
    chown_line="$(grep -Fn -- "sudo chown -R -- \"\$runner_uid:\$runner_gid\" testoutput" "$workflow" | cut -d: -f1)"
    cleanup_line="$(grep -Fn -- "rm -rf -- \"\$vm_workdir\"" "$workflow" | cut -d: -f1)"
    rethrow_line="$(grep -Fn -- "exit \"\$launch_status\"" "$workflow" | cut -d: -f1)"
    [[ "$mktemp_line" =~ ^[1-9][0-9]*$ && "$launch_line" =~ ^[1-9][0-9]*$ && \
        "$chown_line" =~ ^[1-9][0-9]*$ && "$cleanup_line" =~ ^[1-9][0-9]*$ && \
        "$rethrow_line" =~ ^[1-9][0-9]*$ && \
        mktemp_line -lt launch_line && launch_line -lt chown_line && \
        chown_line -lt cleanup_line && cleanup_line -lt rethrow_line ]]
}

require_rhel_vm_image_contract() {
    local -r dockerfile="$1"

    grep -Eq -- '^[[:space:]]+setpriv$' "$dockerfile" || return 1
    ! grep -Eq -- '^[[:space:]]+(busybox|util-linux-misc)$' "$dockerfile" || return 1
    grep -Fq -- 'chown 65534:65534 /overlay/upper' "$dockerfile" || return 1
    grep -Fq -- 'export GOCACHE=/overlay/gocache' "$dockerfile" || return 1
    grep -Fq -- 'export TMPDIR=/overlay/tmp' "$dockerfile" || return 1
    ! grep -Fq -- 'export GOCACHE=/build/' "$dockerfile" || return 1
    ! grep -Fq -- 'export TMPDIR=/build/' "$dockerfile" || return 1
    ! grep -Fq -- 'safe.directory' "$dockerfile" || return 1
    grep -Fq -- "if [ \"\$target\" = \"run-java-remote-parent-rhel-kernel-sockopt-vm\" ]; then" \
        "$dockerfile" || return 1
    grep -Fq -- 'bash internal/test/vm/run-java-remote-parent-rhel.sh' "$dockerfile" || return 1
    grep -Fq -- "kernel_id) kernel_id=\"\$v\" ;;" "$dockerfile" || return 1
    grep -Fq -- "OBI_VM_KERNEL_ID=\"\$kernel_id\"" "$dockerfile" || return 1
    grep -Fq -- "''|*[!a-z0-9._-]*)" "$dockerfile" || return 1
    ! grep -Fq -- "cd /build && make \$target" "$dockerfile" || return 1
}

require_kernel_makefile_contract() {
    local -r makefile="$1"

    grep -Fq -- 'export JAVA_REMOTE_PARENT_KERNEL_ID' "$makefile" || return 1
    grep -Fq -- "case \"\$\${JAVA_REMOTE_PARENT_KERNEL_ID}\" in" \
        "$makefile" || return 1
    grep -Fq -- "\"\$\${JAVA_REMOTE_PARENT_KERNEL_ID}\" \\" \
        "$makefile" || return 1
    ! grep -Fq -- "case \"\$(JAVA_REMOTE_PARENT_KERNEL_ID)\" in" \
        "$makefile" || return 1
}

test_rhel_ci_is_private_and_preserves_launch_status() {
    local -r workflow="${SCRIPT_DIR}/../../../.github/workflows/java_remote_parent_rhel.yml"
    local -r valid="${TEST_TMP_DIR}/workflow-valid.yml"
    local -r repo_workdir="${TEST_TMP_DIR}/workflow-repo-workdir.yml"
    local -r missing_chown="${TEST_TMP_DIR}/workflow-missing-chown.yml"
    local -r masked_status="${TEST_TMP_DIR}/workflow-masked-status.yml"
    local -r missing_cleanup="${TEST_TMP_DIR}/workflow-missing-cleanup.yml"

    track_fixture "$valid"
    cp -- "$workflow" "$valid"
    require_rhel_workflow_vm_contract "$valid" || \
        test_fail 'RHEL workflow lost its private VM/status-recovery contract'
    write_mutated_fixture "$repo_workdir" "$valid" \
        "s/WORKDIR=\"\$vm_workdir\"/WORKDIR=\"\$(pwd)\"/"
    write_mutated_fixture "$missing_chown" "$valid" \
        "/sudo chown -R -- \"\$runner_uid:\$runner_gid\" testoutput/d"
    write_mutated_fixture "$masked_status" "$valid" \
        "s/exit \"\$launch_status\"/exit \"\$ownership_status\"/"
    write_mutated_fixture "$missing_cleanup" "$valid" \
        "/rm -rf -- \"\$vm_workdir\"/d"
    for mutation in "$repo_workdir" "$missing_chown" "$masked_status" "$missing_cleanup"; do
        if require_rhel_workflow_vm_contract "$mutation" >/dev/null 2>&1; then
            test_fail "RHEL workflow validator accepted mutation: ${mutation}"
        fi
    done
}

test_kernel_campaign_identity_is_bounded() {
    local collect_function=""
    local feature_function=""
    local main_function=""
    local output=""
    local mkdir_line=""
    local validate_line=""

    output="$(
        OBI_VM_KERNEL_ID=6.12-lts bash -c '
            source "$1"
            validate_campaign_identity
            printf "%s\n" "$OUTPUT_DIR"
        ' bash "${SCRIPT_DIR}/run-java-remote-parent-rhel.sh"
    )" || test_fail 'valid upstream kernel campaign identity was rejected'
    [[ "$output" == 'testoutput/java-remote-parent-6.12-lts-kernel-sockopt' ]] || \
        test_fail 'kernel campaign output was not derived from its validated identity'

    for invalid in '' '../escape' 'RHEL9.6' 'rhel9/6' 'rhel9 6' \
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
        if OBI_VM_KERNEL_ID="$invalid" bash -c '
            source "$1"
            validate_campaign_identity
        ' bash "${SCRIPT_DIR}/run-java-remote-parent-rhel.sh" >/dev/null 2>&1; then
            test_fail "kernel campaign accepted invalid identity: ${invalid:-empty}"
        fi
    done
    if OBI_VM_EXPECTED_ARCHITECTURE=aarch64 bash -c '
        source "$1"
        validate_campaign_identity
    ' bash "${SCRIPT_DIR}/run-java-remote-parent-rhel.sh" >/dev/null 2>&1; then
        test_fail 'x86-only nested VM campaign accepted an arm64 architecture'
    fi

    collect_function="$(declare -f collect_kernel_evidence)"
    feature_function="$(declare -f write_kernel_feature_status)"
    main_function="$(declare -f main)"
    validate_line="$(awk '/validate_campaign_identity/ { print NR; exit }' \
        <<<"$main_function")"
    mkdir_line="$(awk '/mkdir -p --/ { print NR; exit }' <<<"$main_function")"
    [[ "$collect_function" == *'bpftool feature probe kernel full'* && \
        "$collect_function" == *'write_kernel_feature_status unsupported'* && \
        "$collect_function" == *'write_kernel_feature_status untested'* && \
        "$collect_function" == *'write_kernel_feature_status probe_complete compatible'* && \
        "$collect_function" != *'5.14.'* && \
        "$feature_function" == *'version_inference=disabled'* && \
        "$feature_function" == *'final_support_decision=selected_go_runtime_feature_probes_and_non_skipping_tests'* && \
        "$validate_line" =~ ^[1-9][0-9]*$ && \
        "$mkdir_line" =~ ^[1-9][0-9]*$ && \
        validate_line -lt mkdir_line ]] || \
        test_fail 'kernel campaign lost bounded identity or runtime feature-probe ordering'
}

require_java_provider_workflow_contract() {
    local -r workflow="$1"
    local provider_job=""
    local required=""

    provider_job="$(awk '
        /^  production-provider-runtime:/ { selected = 1 }
        selected { print }
    ' "$workflow")" || return 1
    [[ -n "$provider_job" ]] || return 1
    grep -Fq -- 'runner: ubuntu-latest' <<<"$provider_job" || return 1
    grep -Fq -- 'runner: ubuntu-24.04-arm' <<<"$provider_job" || return 1
    grep -Fq -- 'test-java: [8, 11, 17, 21]' <<<"$provider_job" || return 1
    grep -Fq -- 'jni-entry: native/linux-amd64/libobijni.so' \
        <<<"$provider_job" || return 1
    grep -Fq -- 'jni-entry: native/linux-aarch64/libobijni.so' \
        <<<"$provider_job" || return 1
    grep -Fq -- 'sudo bpftool feature probe kernel full' \
        <<<"$provider_job" || return 1
    grep -Fq -- 'version_inference=disabled' <<<"$provider_job" || return 1
    grep -Fq -- 'final_support_decision=selected_go_runtime_feature_probes_and_non_skipping_tests' \
        <<<"$provider_job" || return 1
    grep -Fq -- '-test.count=3' <<<"$provider_job" || return 1
    grep -Fq -- 'resource-growth.properties' <<<"$provider_job" || return 1
    grep -Fq -- "residual-\${kind}.json" <<<"$provider_job" || return 1
    grep -Fq -- 'if (( new_after > 0 ))' <<<"$provider_job" || return 1
    for required in \
        TestJavaRemoteParentPrimaryJVMFaults \
        TestJavaRemoteParentPrimaryJVMDirectSSLSocket \
        TestJavaRemoteParentGenericJVMDirectSSLSocket \
        TestJavaRemoteParentNestedCgroupLifecycle \
        TestJavaRemoteParentCgroupLinkProcessDeathCleanup \
        TestJavaRemoteParentCgroupPartialAttachRollback; do
        grep -Fq -- "$required" <<<"$provider_job" || return 1
    done
    for required in pass fail unsupported untested; do
        grep -Eq -- "(cell_status|runtime_classification)=${required}([[:space:]]|$)" \
            <<<"$provider_job" || return 1
    done
    grep -Fq -- 'status_scope=production_bpf_jni_provider_runtime' \
        <<<"$provider_job" || return 1
    grep -Fq -- 'workflow_ref=%s' <<<"$provider_job" || return 1
    grep -Fq -- 'run_attempt=%s' <<<"$provider_job" || return 1
}

test_java_provider_workflow_matrix_contract() {
    local -r workflow="${SCRIPT_DIR}/../../../.github/workflows/java-agent.yml"
    local -r valid="${TEST_TMP_DIR}/java-agent-workflow-valid.yml"
    local -r missing_arm="${TEST_TMP_DIR}/java-agent-workflow-missing-arm.yml"
    local -r missing_resource_gate="${TEST_TMP_DIR}/java-agent-workflow-missing-resource.yml"
    local -r version_inferred="${TEST_TMP_DIR}/java-agent-workflow-version-inferred.yml"

    track_fixture "$valid"
    cp -- "$workflow" "$valid"
    require_java_provider_workflow_contract "$valid" || \
        test_fail 'Java provider workflow lost its native production matrix contract'
    write_mutated_fixture "$missing_arm" "$valid" \
        '/jni-entry: native\/linux-aarch64\/libobijni[.]so/d'
    write_mutated_fixture "$missing_resource_gate" "$valid" \
        '/if (( new_after > 0 ))/d'
    write_mutated_fixture "$version_inferred" "$valid" \
        's/version_inference=disabled/version_inference=kernel_release/'
    for mutation in "$missing_arm" "$missing_resource_gate" "$version_inferred"; do
        if require_java_provider_workflow_contract "$mutation" >/dev/null 2>&1; then
            test_fail "Java provider workflow validator accepted mutation: ${mutation}"
        fi
    done
}

test_rhel_vm_installs_setpriv_without_dirtying_source() {
    local -r dockerfile="${SCRIPT_DIR}/Dockerfile"
    local -r valid="${TEST_TMP_DIR}/Dockerfile.valid"
    local -r missing_setpriv="${TEST_TMP_DIR}/Dockerfile.missing-setpriv"
    local -r busybox_fallback="${TEST_TMP_DIR}/Dockerfile.busybox-fallback"
    local -r util_linux_misc_fallback="${TEST_TMP_DIR}/Dockerfile.util-linux-misc-fallback"
    local -r root_owned_source="${TEST_TMP_DIR}/Dockerfile.root-owned-source"
    local -r repository_cache="${TEST_TMP_DIR}/Dockerfile.repository-cache"
    local -r global_source_trust="${TEST_TMP_DIR}/Dockerfile.global-source-trust"
    local -r root_make_source_git="${TEST_TMP_DIR}/Dockerfile.root-make-source-git"

    track_fixture "$valid"
    cp -- "$dockerfile" "$valid"
    require_rhel_vm_image_contract "$valid" || \
        test_fail 'RHEL VM image lost setpriv or private build storage'
    write_mutated_fixture "$missing_setpriv" "$valid" '/^[[:space:]]*setpriv$/d'
    write_mutated_fixture "$busybox_fallback" "$valid" \
        's/^[[:space:]]*setpriv$/    busybox/'
    write_mutated_fixture "$util_linux_misc_fallback" "$valid" \
        's/^[[:space:]]*setpriv$/    util-linux-misc/'
    write_mutated_fixture "$root_owned_source" "$valid" \
        '/chown 65534:65534 \/overlay\/upper/d'
    write_mutated_fixture "$repository_cache" "$valid" \
        's|export GOCACHE=/overlay/gocache|export GOCACHE=/build/gocache|'
    write_mutated_fixture "$global_source_trust" "$valid" \
        's|echo "--- mount state ---"|git config --global --add safe.directory /build\
echo "--- mount state ---"|'
    write_mutated_fixture "$root_make_source_git" "$valid" \
        "s|bash internal/test/vm/run-java-remote-parent-rhel.sh|make \"\$target\" TEST_PATTERN=\"\$test_pattern\" RUN_NUMBER=\"\$run_number\"|"
    for mutation in \
        "$missing_setpriv" \
        "$busybox_fallback" \
        "$util_linux_misc_fallback" \
        "$root_owned_source" \
        "$repository_cache" \
        "$global_source_trust" \
        "$root_make_source_git"; do
        if require_rhel_vm_image_contract "$mutation" >/dev/null 2>&1; then
            test_fail "RHEL VM image validator accepted mutation: ${mutation}"
        fi
    done
}

test_kernel_makefile_handoff_is_bounded() {
    local -r makefile="${SCRIPT_DIR}/Makefile"
    local -r valid="${TEST_TMP_DIR}/Makefile.valid"
    local -r missing_export="${TEST_TMP_DIR}/Makefile.missing-export"
    local -r direct_expansion="${TEST_TMP_DIR}/Makefile.direct-expansion"

    track_fixture "$valid"
    cp -- "$makefile" "$valid"
    require_kernel_makefile_contract "$valid" || \
        test_fail 'VM Makefile lost its bounded kernel-ID environment handoff'
    write_mutated_fixture "$missing_export" "$valid" \
        '/^export JAVA_REMOTE_PARENT_KERNEL_ID$/d'
    write_mutated_fixture "$direct_expansion" "$valid" \
        "s/\$\${JAVA_REMOTE_PARENT_KERNEL_ID}/\$(JAVA_REMOTE_PARENT_KERNEL_ID)/g"
    for mutation in "$missing_export" "$direct_expansion"; do
        if require_kernel_makefile_contract "$mutation" >/dev/null 2>&1; then
            test_fail "VM Makefile validator accepted mutation: ${mutation}"
        fi
    done
}

test_packaged_jvm_source_git_contract() {
    local -a command=()
    local -a status_command=()
    local -a expected=(
        /bin/setpriv
        --reuid=65534
        --regid=65534
        --clear-groups
        --no-new-privs
        --inh-caps=-all
        --ambient-caps=-all
        --bounding-set=-all
        --
        /usr/bin/env
        -i
        HOME=/nonexistent
        LANG=C
        LC_ALL=C
        PATH=/usr/bin:/bin
        /usr/bin/git
        -c
        safe.directory=/build
        -C
        /build
        rev-parse
        --verify
        'HEAD^{commit}'
    )
    local -a expected_status=(
        /bin/setpriv
        --reuid=65534
        --regid=65534
        --clear-groups
        --no-new-privs
        --inh-caps=-all
        --ambient-caps=-all
        --bounding-set=-all
        --
        /usr/bin/env
        -i
        HOME=/nonexistent
        LANG=C
        LC_ALL=C
        PATH=/usr/bin:/bin
        /usr/bin/git
        -c
        safe.directory=/build
        -C
        /build
        status
        --porcelain=v1
        --untracked-files=all
    )
    local index=0
    local rendered_command=""
    local source_git_function=""

    validate_packaged_jvm_source_identity /build 65534:65534 || \
        test_fail 'exact packaged JVM source identity was rejected'
    for mutation in \
        '/workspace 65534:65534' \
        '/build/.. 65534:65534' \
        '/build 0:0' \
        '/build 65534:0' \
        '/build 0:65534' \
        '/build 65533:65534' \
        '/build 65534:65533'; do
        # The mutation fixtures contain no whitespace in either field.
        read -r path owner <<<"$mutation"
        if validate_packaged_jvm_source_identity "$path" "$owner"; then
            test_fail "packaged JVM source identity accepted mutation: ${mutation}"
        fi
    done

    build_packaged_jvm_source_git_command \
        command /bin/setpriv /usr/bin/git /build 65534:65534 \
        rev-parse --verify 'HEAD^{commit}' || \
        test_fail 'failed to build exact packaged JVM source Git command'
    [[ ${#command[@]} -eq ${#expected[@]} ]] || \
        test_fail 'packaged JVM source Git argv length changed'
    for ((index = 0; index < ${#expected[@]}; index++)); do
        [[ "${command[index]}" == "${expected[index]}" ]] || \
            test_fail "packaged JVM source Git argv changed at index ${index}"
    done
    rendered_command="$(write_packaged_jvm_command_argv source_revision_argv "${command[@]}")"
    [[ "$rendered_command" == 'source_revision_argv= /bin/setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- /usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin /usr/bin/git -c safe.directory=/build -C /build rev-parse --verify HEAD\^\{commit\}' ]] || \
        test_fail 'packaged JVM source revision argv recording changed'
    build_packaged_jvm_source_git_command \
        status_command /bin/setpriv /usr/bin/git /build 65534:65534 \
        status --porcelain=v1 --untracked-files=all || \
        test_fail 'failed to build exact packaged JVM source status command'
    [[ ${#status_command[@]} -eq ${#expected_status[@]} ]] || \
        test_fail 'packaged JVM source status Git argv length changed'
    for ((index = 0; index < ${#expected_status[@]}; index++)); do
        [[ "${status_command[index]}" == "${expected_status[index]}" ]] || \
            test_fail "packaged JVM source status Git argv changed at index ${index}"
    done
    rendered_command="$(write_packaged_jvm_command_argv source_status_argv "${status_command[@]}")"
    [[ "$rendered_command" == 'source_status_argv= /bin/setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- /usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin /usr/bin/git -c safe.directory=/build -C /build status --porcelain=v1 --untracked-files=all' ]] || \
        test_fail 'packaged JVM source status argv recording changed'

    source_git_function="$(declare -f build_packaged_jvm_source_git_command)"
    for required in \
        '/usr/bin/env -i' \
        "\"\${PACKAGED_JVM_SOURCE_GIT_ENVIRONMENT[@]}\"" \
        "-c \"safe.directory=\$source_path\"" \
        "-C \"\$source_path\""; do
        [[ "$source_git_function" == *"$required"* ]] || \
            test_fail "packaged JVM source Git command lost contract: ${required}"
    done
    for forbidden in \
        'safe.directory=*' \
        'git config --global' \
        'HOME=/root'; do
        [[ "$source_git_function" != *"$forbidden"* ]] || \
            test_fail "packaged JVM source Git command added forbidden trust/environment: ${forbidden}"
    done

    for mutation in \
        '/usr/bin/setpriv /usr/bin/git /build 65534:65534' \
        '/bin/setpriv /bin/git /build 65534:65534' \
        '/bin/setpriv /usr/bin/git /workspace 65534:65534' \
        '/bin/setpriv /usr/bin/git /build 0:0'; do
        read -r setpriv git path owner <<<"$mutation"
        if build_packaged_jvm_source_git_command \
            command "$setpriv" "$git" "$path" "$owner" rev-parse HEAD; then
            test_fail "packaged JVM source Git command accepted mutation: ${mutation}"
        fi
    done
}

test_packaged_jvm_setpriv_identity_contract() {
    local -r valid_owner='/bin/setpriv is owned by setpriv-2.41.4-r0'
    local -r valid_version='setpriv from util-linux 2.41.4'
    local valid_help=""
    local mutated_help=""
    local option=""

    valid_help="$(printf '%s\n' "${PACKAGED_JVM_SETPRIV_OPTIONS[@]}")"
    validate_packaged_jvm_setpriv_identity \
        /bin/setpriv "$valid_owner" "$valid_version" "$valid_help" || \
        test_fail 'valid Alpine util-linux setpriv identity was rejected'

    if validate_packaged_jvm_setpriv_identity \
        /bin/busybox "$valid_owner" "$valid_version" "$valid_help"; then
        test_fail 'non-canonical setpriv path was accepted'
    fi
    if validate_packaged_jvm_setpriv_identity \
        /bin/setpriv '/bin/setpriv is owned by busybox-1.37.0-r30' \
        "$valid_version" "$valid_help"; then
        test_fail 'BusyBox-owned setpriv fallback was accepted'
    fi
    if validate_packaged_jvm_setpriv_identity \
        /bin/setpriv "$valid_owner" 'BusyBox v1.37.0' "$valid_help"; then
        test_fail 'non-util-linux setpriv version was accepted'
    fi
    if validate_packaged_jvm_setpriv_identity \
        /bin/setpriv '/bin/setpriv is owned by util-linux-misc-2.41.4-r0' \
        "$valid_version" "$valid_help"; then
        test_fail 'util-linux-misc setpriv fallback was accepted'
    fi
    for option in "${PACKAGED_JVM_SETPRIV_OPTIONS[@]}"; do
        mutated_help="${valid_help/"$option"/--unsupported-option}"
        if validate_packaged_jvm_setpriv_identity \
            /bin/setpriv "$valid_owner" "$valid_version" "$mutated_help"; then
            test_fail "setpriv identity accepted missing option: ${option}"
        fi
    done
}

test_packaged_jvm_runner_contract() {
    local build_function=""
    local benchmark_function=""
    local source_git_function=""
    local validation_function=""
    local main_function=""
    local transport_line=""
    local packaged_line=""
    local validate_line=""
    local gate_line=""
    local status_line=""
    local test_binary_crosslink_line=""
    local test_binary_execution_line=""
    local test_binary_identity_line=""
    local test_binary_literal_count=""
    local test_binary_resolve_line=""

    build_function="$(declare -f build_packaged_jvm_benchmark_test_binary)"
    benchmark_function="$(declare -f run_packaged_jvm_benchmark)"
    source_git_function="$(declare -f build_packaged_jvm_source_git_command)"
    validation_function="$(declare -f require_packaged_jvm_benchmark_artifact)"
    main_function="$(declare -f main)"
    [[ "$PACKAGED_JVM_BENCHMARK_TEST_PATTERN" == \
        '^TestJavaRemoteParentPackagedJVMTransportBenchmark$' && \
        "$PACKAGED_JVM_BENCHMARK_TEST_NAME" == \
        'TestJavaRemoteParentPackagedJVMTransportBenchmark' ]] || \
        test_fail 'packaged JVM runner does not select the generalized transport benchmark'
    [[ "$build_function" == *'go test -c -tags=privileged_tests'* && \
        "$build_function" == *'umask 077'* && \
        "$benchmark_function" == *'PATH=/usr/local/go/bin:/usr/bin:/bin command -v setpriv'* && \
        "$benchmark_function" == *"apk info --who-owns \"\$PACKAGED_JVM_SETPRIV_PATH\""* && \
        "$benchmark_function" == *'validate_packaged_jvm_setpriv_identity'* && \
        "$benchmark_function" == *"validate_packaged_jvm_source_identity \"\$source_path\" \"\$source_owner\""* && \
        "$benchmark_function" == *'build_packaged_jvm_source_git_command'* && \
        "$benchmark_function" == *"source_revision=\"\$(\"\${source_revision_command[@]}\")\""* && \
        "$benchmark_function" == *"source_status=\"\$(\"\${source_status_command[@]}\")\""* && \
        "$benchmark_function" == *"test_binary_path=\"\$(resolve_existing_path \"\$OUTPUT_DIR/packaged-jvm-benchmark.test\")\""* && \
        "$benchmark_function" == *'write_packaged_jvm_command_argv source_revision_argv'* && \
        "$benchmark_function" == *'write_packaged_jvm_command_argv source_status_argv'* && \
        "$benchmark_function" != *"source_revision=\"\$(git "* && \
        "$benchmark_function" != *"source_status=\"\$(git "* && \
        "$benchmark_function" == *"\"\$setpriv_path\" --version"* && \
        "$benchmark_function" == *'apk info -e openjdk21-jre-headless setpriv'* && \
        "$benchmark_function" == *'benchmark_environment=("HOME=/root" "LANG=C" "LC_ALL=C" "PATH=/usr/local/go/bin:/usr/bin:/bin" "TMPDIR=/tmp" "TZ=UTC"'* && \
        "$benchmark_function" == *"OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_EXCLUSIVE_CGROUP_BPF=\$PACKAGED_JVM_EXCLUSIVE_CGROUP_BPF_PREMISE"* && \
        "$benchmark_function" == *"env -i \"\${benchmark_environment[@]}\""* && \
        "$benchmark_function" == *'packaged-jvm-benchmark-root-environment.txt'* && \
        "$benchmark_function" == *'userspace=Alpine Linux'* && \
        "$benchmark_function" == *'kernel_input=LVH digest-pinned %s artifact'* && \
        "$benchmark_function" == *"\"\$KERNEL_ID\""* && \
        "$validation_function" == *'VALIDATE_CI_CROSSLINKS=1'* && \
        "$source_git_function" == *'--no-new-privs'* && \
        "$source_git_function" == *'--inh-caps=-all'* && \
        "$source_git_function" == *'--ambient-caps=-all'* && \
        "$source_git_function" == *'--bounding-set=-all'* && \
        "$source_git_function" == *'/usr/bin/env -i'* && \
        "$source_git_function" == *"\"\${PACKAGED_JVM_SOURCE_GIT_ENVIRONMENT[@]}\""* && \
        "$source_git_function" == *"safe.directory=\$source_path"* && \
        "$source_git_function" == *"-C \"\$source_path\""* ]] || \
        test_fail 'packaged JVM benchmark lost compile, environment, or identity contracts'

    test_binary_literal_count="$(
        grep -Fo -- 'packaged-jvm-benchmark.test' <<<"$benchmark_function" | wc -l
    )" || test_fail 'packaged JVM benchmark lost its test binary path'
    [[ "$test_binary_literal_count" -eq 1 ]] || \
        test_fail 'packaged JVM benchmark reused a raw test binary path after resolution'
    test_binary_resolve_line="$(awk \
        '/test_binary_path=.*resolve_existing_path/ { print NR; exit }' \
        <<<"$benchmark_function")"
    test_binary_identity_line="$(awk \
        '/sha256sum .*test_binary_path/ { print NR; exit }' \
        <<<"$benchmark_function")"
    test_binary_execution_line="$(awk \
        '/env -i .*test_binary_path/ { print NR; exit }' \
        <<<"$benchmark_function")"
    test_binary_crosslink_line="$(awk \
        '/require_packaged_jvm_benchmark_artifact .*test_binary_path/ { print NR; exit }' \
        <<<"$benchmark_function")"
    [[ "$test_binary_resolve_line" =~ ^[1-9][0-9]*$ && \
        "$test_binary_identity_line" =~ ^[1-9][0-9]*$ && \
        "$test_binary_execution_line" =~ ^[1-9][0-9]*$ && \
        "$test_binary_crosslink_line" =~ ^[1-9][0-9]*$ && \
        test_binary_resolve_line -lt test_binary_identity_line && \
        test_binary_identity_line -lt test_binary_execution_line && \
        test_binary_execution_line -lt test_binary_crosslink_line ]] || \
        test_fail 'packaged JVM benchmark did not resolve its test binary before every provenance use'

    transport_line="$(awk '/run_transport_benchmark/ { line = NR } END { print line }' <<<"$main_function")"
    packaged_line="$(awk '/run_packaged_jvm_benchmark/ { line = NR } END { print line }' <<<"$main_function")"
    [[ "$transport_line" =~ ^[1-9][0-9]*$ && "$packaged_line" =~ ^[1-9][0-9]*$ && \
        transport_line -lt packaged_line ]] || \
        test_fail 'packaged JVM benchmark is not the final benchmark run'

    validate_line="$(awk '/require_packaged_jvm_benchmark_artifact/ { print NR; exit }' <<<"$benchmark_function")"
    gate_line="$(awk '/packaged_jvm_benchmark_artifact_gates_pass/ { print NR; exit }' <<<"$benchmark_function")"
    status_line="$(awk '/test_status == 0/ { line = NR } END { print line }' <<<"$benchmark_function")"
    [[ "$validate_line" =~ ^[1-9][0-9]*$ && "$gate_line" =~ ^[1-9][0-9]*$ && \
        "$status_line" =~ ^[1-9][0-9]*$ && \
        validate_line -lt gate_line && gate_line -lt status_line ]] || \
        test_fail 'packaged JVM artifact is not validated before latency/test failure propagation'

    if (require_packaged_jvm_benchmark_artifact \
        "${TEST_TMP_DIR}/absent-packaged-jvm.json" \
        "${TEST_TMP_DIR}/absent-validation.log" \
        /missing/agent /missing/test 0123456789abcdef0123456789abcdef01234567 \
        5.14.0-test /usr/bin/java /missing/sockopt.o /missing/sockops.o \
        >/dev/null 2>&1); then
        test_fail 'packaged JVM validator accepted an absent artifact'
    fi
}

run_tests() {
    local -r valid="${TEST_TMP_DIR}/valid.json"
    local -r strict_getsockopt_failure="${TEST_TMP_DIR}/strict-getsockopt-failure.json"
    local -r inclusive_timeout="${TEST_TMP_DIR}/inclusive-timeout.json"
    local -r timeout_lower_failure="${TEST_TMP_DIR}/timeout-lower-failure.json"
    local -r timeout_upper_failure="${TEST_TMP_DIR}/timeout-upper-failure.json"
    local -r inconsistent_gate="${TEST_TMP_DIR}/inconsistent-gate.json"
    local -r wrong_counts="${TEST_TMP_DIR}/wrong-counts.json"
    local -r duplicate="${TEST_TMP_DIR}/duplicate.json"
    local -r truncated="${TEST_TMP_DIR}/truncated.json"
    local -r multiline="${TEST_TMP_DIR}/multiline.json"
    local -r malformed_number="${TEST_TMP_DIR}/malformed-number.json"
    local -r impossible_batch="${TEST_TMP_DIR}/impossible-batch.json"
    local -r inconsistent_throughput="${TEST_TMP_DIR}/inconsistent-throughput.json"

    write_artifact "$valid" 999999 true 50000000 100000000 true false
    assert_artifact_accepted 'valid boundary artifact' "$valid"
    assert_all_gates_pass 'valid boundary artifact' "$valid"

    write_artifact \
        "$strict_getsockopt_failure" 1000000 false 50000000 100000000 true false
    assert_failed_gate_retained 'strict getsockopt p99 boundary' "$strict_getsockopt_failure"

    write_artifact "$inclusive_timeout" 999999 true 50000000 100000000 true false
    assert_artifact_accepted 'inclusive timeout boundaries' "$inclusive_timeout"
    assert_all_gates_pass 'inclusive timeout boundaries' "$inclusive_timeout"

    write_artifact \
        "$timeout_lower_failure" 999999 true 49999999 100000000 false false
    assert_failed_gate_retained 'timeout p50 lower boundary' "$timeout_lower_failure"
    write_artifact \
        "$timeout_upper_failure" 999999 true 50000000 100000001 false false
    assert_failed_gate_retained 'timeout p99 upper boundary' "$timeout_upper_failure"

    write_artifact "$inconsistent_gate" 1000000 true 50000000 100000000 true false
    assert_artifact_rejected 'inconsistent gate result' "$inconsistent_gate"

    write_mutated_fixture "$wrong_counts" "$valid" \
        's/"missing":4096/"missing":4095/'
    assert_artifact_rejected 'wrong status counts' "$wrong_counts"

    write_artifact "$duplicate" 999999 true 50000000 100000000 true true
    assert_artifact_rejected 'duplicate series' "$duplicate"

    write_mutated_fixture "$truncated" "$valid" 's/]}/]/'
    assert_artifact_rejected 'truncated JSON' "$truncated"
    write_mutated_fixture "$multiline" "$valid" \
        's/,"unix_timeout_deadline_ns"/,\
"unix_timeout_deadline_ns"/'
    assert_artifact_rejected 'multiline JSON' "$multiline"
    write_mutated_fixture "$malformed_number" "$valid" \
        '0,/"p99_ns":999999/s//"p99_ns":0999999/'
    assert_artifact_rejected 'malformed numeric field' "$malformed_number"
    write_mutated_fixture "$impossible_batch" "$valid" \
        '0,/"batch_elapsed_ns":4096000000/s//"batch_elapsed_ns":1/'
    assert_artifact_rejected 'impossible batch elapsed time' "$impossible_batch"
    write_mutated_fixture "$inconsistent_throughput" "$valid" \
        '0,/"operations_per_second":1000/s//"operations_per_second":999/'
    assert_artifact_rejected 'inconsistent throughput' "$inconsistent_throughput"

    test_production_verifier_profile_validation
    test_deterministic_artifact_path
    test_relative_artifact_path_resolution
    test_artifact_path_preserves_symlinks
    test_relative_agent_path_resolution
    test_rhel_ci_is_private_and_preserves_launch_status
    test_kernel_campaign_identity_is_bounded
    test_java_provider_workflow_matrix_contract
    test_rhel_vm_installs_setpriv_without_dirtying_source
    test_kernel_makefile_handoff_is_bounded
    test_packaged_jvm_source_git_contract
    test_packaged_jvm_setpriv_identity_contract
    test_packaged_jvm_runner_contract
    printf '%s\n' 'Kernel compatibility verifier and transport benchmark validator tests passed'
}

if (($# != 0)); then
    test_fail 'this test accepts no arguments'
fi
[[ -d "$TEST_TMP_PARENT" && -w "$TEST_TMP_PARENT" ]] || \
    test_fail "temporary directory is unavailable: ${TEST_TMP_PARENT}"
TEST_TMP_DIR="$(mktemp -d -- "${TEST_TMP_PARENT}/java-remote-parent-rhel-test.XXXXXX")"
TEST_DIRS+=("$TEST_TMP_DIR")
trap cleanup EXIT
run_tests
