#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly OUTPUT_DIR="${TEST_OUTPUT:-testoutput}/java-remote-parent-rhel9.6-kernel-sockopt"
readonly JAVA_AGENT_PATH="${OUTPUT_DIR}/java-artifacts/obi-java-agent.jar"
readonly JAVA_AGENT_CHECKSUM="${OUTPUT_DIR}/java-agent.sha256"
readonly VERIFIER_TEST_PATTERN='^TestBPFVerifierProductionProfiles$'
readonly VERIFIER_TEST_NAME='TestBPFVerifierProductionProfiles'
readonly VERIFIER_GENERIC_PROFILE='TestBPFVerifierProductionProfiles/generictracer/apache-java-https'
readonly VERIFIER_SOCKOPT_PROFILE='TestBPFVerifierProductionProfiles/tpinjector/java-remote-parent'
readonly PRIVILEGED_TEST_PATTERN='^(TestJavaRemoteParentPrimarySocketAuthority|TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook|TestJavaRemoteParentPrimaryJVMFaults|TestJavaRemoteParentPrimaryJVMDirectSSLSocket|TestJavaRemoteParentGenericJVMDirectSSLSocket|TestJavaRemoteParentNestedCgroupLifecycle|TestJavaRemoteParentCgroupLinkProcessDeathCleanup|TestJavaRemoteParentCgroupPartialAttachRollback|TestJavaRemoteParentBridgeLoadRequiresPrivileges)$'
readonly BENCHMARK_TEST_PATTERN='^TestJavaRemoteParentTransportBenchmark$'
readonly PACKAGED_JVM_BENCHMARK_TEST_PATTERN='^TestJavaRemoteParentPackagedJVMGetsockoptBenchmark$'
readonly PACKAGED_JVM_BENCHMARK_TEST_NAME='TestJavaRemoteParentPackagedJVMGetsockoptBenchmark'
readonly PACKAGED_JVM_ARTIFACT_VALIDATOR_PATTERN='^(TestValidatePackagedJVMBenchmarkArtifactFile|TestValidatePackagedJVMBenchmarkArtifactCICrosslinks)$'
readonly PACKAGED_JVM_ARTIFACT_VALIDATOR_NAME='TestValidatePackagedJVMBenchmarkArtifactFile'
readonly PACKAGED_JVM_ARTIFACT_CROSSLINK_VALIDATOR_NAME='TestValidatePackagedJVMBenchmarkArtifactCICrosslinks'
readonly PACKAGED_JVM_EXCLUSIVE_CGROUP_BPF_PREMISE='operator_controlled_no_concurrent_cgroup_bpf_mutation'
readonly PACKAGED_JVM_SETPRIV_PATH='/bin/setpriv'
readonly -a PACKAGED_JVM_SETPRIV_OPTIONS=(
    --reuid
    --regid
    --clear-groups
    --no-new-privs
    --inh-caps
    --ambient-caps
    --bounding-set
)

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

resolve_existing_path() {
    local -r path="$1"
    local resolved=""

    resolved="$(realpath "$path")" || \
        fail "failed to resolve path: ${path}"
    printf '%s\n' "$resolved"
}

validate_packaged_jvm_setpriv_identity() {
    local -r path="$1"
    local -r package_owner="$2"
    local -r version="$3"
    local -r help="$4"
    local option=""

    [[ "$path" == "$PACKAGED_JVM_SETPRIV_PATH" ]] || return 1
    [[ "$package_owner" =~ ^/bin/setpriv[[:space:]]is[[:space:]]owned[[:space:]]by[[:space:]]setpriv-[0-9][0-9A-Za-z._+~-]*-r[0-9]+$ ]] || return 1
    [[ "$version" =~ ^setpriv[[:space:]]from[[:space:]]util-linux[[:space:]][0-9]+([.][0-9]+){1,2}$ ]] || return 1
    for option in "${PACKAGED_JVM_SETPRIV_OPTIONS[@]}"; do
        grep -Fq -- "$option" <<<"$help" || return 1
    done
}

require_test_passed() {
    local -r output_file="$1"
    local -r test_name="$2"

    if grep -Eq -- '^[[:space:]]*--- SKIP:' "$output_file"; then
        fail "a required test skipped; see ${output_file}"
    fi
    if ! grep -Eq -- "^[[:space:]]*--- PASS: ${test_name} \\(" "$output_file"; then
        fail "${test_name} did not report PASS; see ${output_file}"
    fi
}

require_production_verifier_profiles_passed() {
    local -r output_file="$1"

    require_test_passed "$output_file" "$VERIFIER_TEST_NAME"
    require_test_passed "$output_file" "$VERIFIER_GENERIC_PROFILE"
    require_test_passed "$output_file" "$VERIFIER_SOCKOPT_PROFILE"
}

require_private_benchmark_path() {
    local -r path="$1"
    local -r path_type="$2"
    local -r mode="$3"
    local path_identity=""

    path_identity="$(stat -c '%F:%u:%a' -- "$path")" || \
        fail "cannot stat transport benchmark path: ${path}"
    [[ "$path_identity" == "${path_type}:${EUID}:${mode}" ]] || \
        fail "transport benchmark path is not private: ${path}"
}

transport_benchmark_series_pattern() {
    local -r transport="$1"
    local -r outcome="$2"
    local -r warmup_rounds="$3"
    local -r measurement_rounds="$4"
    local -r samples="$5"
    local -r gate_kind="$6"
    local -r p50_min_ns="$7"
    local -r p99_max_ns="$8"
    local -r positive_integer='[1-9][0-9]{0,15}'
    local -r non_negative_integer='(0|[1-9][0-9]{0,15})'
    local -r positive_number='([1-9][0-9]*(\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)([eE][+-]?[0-9]{1,2})?'
    local series_pattern="\\{\"transport\":\"${transport}\",\"outcome\":\"${outcome}\","

    series_pattern+="\"warmup_rounds\":${warmup_rounds},"
    series_pattern+="\"measurement_rounds\":${measurement_rounds},"
    series_pattern+="\"samples\":${samples},\"concurrency\":8,"
    series_pattern+="\"batch_elapsed_ns\":${positive_integer},"
    series_pattern+="\"p50_ns\":${positive_integer},"
    series_pattern+="\"p95_ns\":${positive_integer},"
    series_pattern+="\"p99_ns\":${positive_integer},"
    series_pattern+="\"operations_per_second\":${positive_number},"
    series_pattern+="\"valid\":${non_negative_integer},"
    series_pattern+="\"missing\":${non_negative_integer},"
    series_pattern+="\"already_consumed\":${non_negative_integer},"
    series_pattern+="\"timeout\":${non_negative_integer},"
    series_pattern+="\"errors\":0,\"correct\":true,"
    series_pattern+="\"latency_gate\":\\{\"kind\":\"${gate_kind}\","
    series_pattern+="\"p50_min_ns\":${p50_min_ns},"
    series_pattern+="\"p99_max_ns\":${p99_max_ns},\"passed\":(true|false)\\}\\}"

    printf '%s' "$series_pattern"
}

transport_benchmark_integer_field() {
    local -r series_json="$1"
    local -r field="$2"

    if [[ "$series_json" =~ \"${field}\":([0-9]+) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

transport_benchmark_boolean_field() {
    local -r series_json="$1"
    local -r field="$2"

    if [[ "$series_json" =~ \"${field}\":(true|false) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

transport_benchmark_number_field() {
    local -r series_json="$1"
    local -r field="$2"
    local -r positive_number='([1-9][0-9]*(\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)([eE][+-]?[0-9]{1,2})?'

    if [[ "$series_json" =~ \"${field}\":(${positive_number}) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

require_transport_benchmark_series() {
    local -r artifact_file="$1"
    local -r transport="$2"
    local -r outcome="$3"
    local -r warmup_rounds="$4"
    local -r measurement_rounds="$5"
    local -r samples="$6"
    local -r gate_kind="$7"
    local -r p50_min_ns="$8"
    local -r p99_max_ns="$9"
    local series_pattern=""
    local series_json=""
    local p50_ns=""
    local p95_ns=""
    local p99_ns=""
    local batch_elapsed_ns=""
    local operations_per_second=""
    local valid=""
    local missing=""
    local already_consumed=""
    local timeout=""
    local gate_passed=""
    local expected_gate_passed=false

    series_pattern="$(transport_benchmark_series_pattern \
        "$transport" "$outcome" "$warmup_rounds" "$measurement_rounds" \
        "$samples" "$gate_kind" "$p50_min_ns" "$p99_max_ns")" || \
        fail "cannot construct ${transport}/${outcome} benchmark validation"
    series_json="$(grep -Eo -- "$series_pattern" "$artifact_file")" || \
        fail "transport benchmark artifact lacks a valid ${transport}/${outcome} series: ${artifact_file}"

    batch_elapsed_ns="$(transport_benchmark_integer_field "$series_json" batch_elapsed_ns)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} batch elapsed time: ${artifact_file}"
    p50_ns="$(transport_benchmark_integer_field "$series_json" p50_ns)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} p50: ${artifact_file}"
    p95_ns="$(transport_benchmark_integer_field "$series_json" p95_ns)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} p95: ${artifact_file}"
    p99_ns="$(transport_benchmark_integer_field "$series_json" p99_ns)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} p99: ${artifact_file}"
    operations_per_second="$(transport_benchmark_number_field "$series_json" operations_per_second)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} throughput: ${artifact_file}"
    valid="$(transport_benchmark_integer_field "$series_json" valid)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} valid count: ${artifact_file}"
    missing="$(transport_benchmark_integer_field "$series_json" missing)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} missing count: ${artifact_file}"
    already_consumed="$(transport_benchmark_integer_field "$series_json" already_consumed)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} consumed count: ${artifact_file}"
    timeout="$(transport_benchmark_integer_field "$series_json" timeout)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} timeout count: ${artifact_file}"
    gate_passed="$(transport_benchmark_boolean_field "$series_json" passed)" || \
        fail "transport benchmark artifact lacks ${transport}/${outcome} gate result: ${artifact_file}"

    (( p50_ns <= p95_ns && p95_ns <= p99_ns )) || \
        fail "transport benchmark artifact has non-monotonic ${transport}/${outcome} percentiles: ${artifact_file}"
    (( batch_elapsed_ns >= p99_ns )) || \
        fail "transport benchmark artifact has impossible ${transport}/${outcome} batch elapsed time: ${artifact_file}"
    awk \
        -v observed="$operations_per_second" \
        -v sample_count="$samples" \
        -v elapsed_ns="$batch_elapsed_ns" \
        'BEGIN {
            expected = sample_count * 1000000000 / elapsed_ns
            difference = observed - expected
            if (difference < 0) {
                difference = -difference
            }
            exit !(observed > 0 && expected > 0 && difference / expected <= 1e-12)
        }' || \
        fail "transport benchmark artifact has inconsistent ${transport}/${outcome} throughput: ${artifact_file}"
    (( valid + missing + already_consumed + timeout == samples )) || \
        fail "transport benchmark artifact has inconsistent ${transport}/${outcome} status counts: ${artifact_file}"

    case "${transport}/${outcome}" in
        getsockopt/miss|unix/miss)
            (( valid == 0 && missing == samples && already_consumed == 0 && timeout == 0 )) || \
                fail "transport benchmark artifact has incorrect ${transport}/${outcome} outcomes: ${artifact_file}"
            ;;
        getsockopt/hit|unix/hit)
            (( valid == samples && missing == 0 && already_consumed == 0 && timeout == 0 )) || \
                fail "transport benchmark artifact has incorrect ${transport}/${outcome} outcomes: ${artifact_file}"
            ;;
        getsockopt/one_shot)
            (( valid == measurement_rounds && missing + already_consumed == samples - valid && timeout == 0 )) || \
                fail "transport benchmark artifact has incorrect ${transport}/${outcome} outcomes: ${artifact_file}"
            ;;
        unix/timeout)
            (( valid == 0 && missing == 0 && already_consumed == 0 && timeout == samples )) || \
                fail "transport benchmark artifact has incorrect ${transport}/${outcome} outcomes: ${artifact_file}"
            ;;
        *)
            fail "unknown transport benchmark series: ${transport}/${outcome}"
            ;;
    esac

    case "$gate_kind" in
        p99_lt)
            (( p50_min_ns == 0 )) || \
                fail "transport benchmark artifact has an invalid ${transport}/${outcome} p99 gate: ${artifact_file}"
            if (( p99_ns < p99_max_ns )); then
                expected_gate_passed=true
            fi
            ;;
        p50_gte_p99_lte)
            if (( p50_ns >= p50_min_ns && p99_ns <= p99_max_ns )); then
                expected_gate_passed=true
            fi
            ;;
        correctness_only)
            (( p50_min_ns == 0 && p99_max_ns == 0 )) || \
                fail "transport benchmark artifact has an invalid ${transport}/${outcome} correctness gate: ${artifact_file}"
            expected_gate_passed=true
            ;;
        *)
            fail "unknown transport benchmark gate: ${gate_kind}"
            ;;
    esac
    [[ "$gate_passed" == "$expected_gate_passed" ]] || \
        fail "transport benchmark artifact has an inconsistent ${transport}/${outcome} gate result: ${artifact_file}"
}

require_transport_benchmark_artifact() {
    local -r artifact_file="$1"
    local artifact_bytes=""
    local artifact_lines=""
    local artifact_pattern='^\{"schema_version":2,"benchmark":"java_remote_parent_transport",'
    local getsockopt_miss_pattern=""
    local getsockopt_hit_pattern=""
    local getsockopt_one_shot_pattern=""
    local unix_miss_pattern=""
    local unix_hit_pattern=""
    local unix_timeout_pattern=""

    command -v awk >/dev/null 2>&1 || fail 'awk is unavailable'
    require_private_benchmark_path "$artifact_file" 'regular file' 600
    [[ -s "$artifact_file" ]] || \
        fail "transport benchmark artifact is missing or invalid: ${artifact_file}"
    artifact_bytes="$(stat -c '%s' -- "$artifact_file")" || \
        fail "cannot read transport benchmark artifact size: ${artifact_file}"
    (( artifact_bytes > 0 && artifact_bytes <= 65536 )) || \
        fail "transport benchmark artifact has an invalid size: ${artifact_file}"
    artifact_lines="$(wc -l < "$artifact_file")" || \
        fail "cannot read transport benchmark artifact lines: ${artifact_file}"
    [[ "$artifact_lines" -eq 1 ]] || \
        fail "transport benchmark artifact must be one newline-terminated JSON record: ${artifact_file}"

    getsockopt_miss_pattern="$(transport_benchmark_series_pattern \
        getsockopt miss 16 512 4096 p99_lt 0 1000000)" || \
        fail 'cannot construct getsockopt/miss benchmark validation'
    getsockopt_hit_pattern="$(transport_benchmark_series_pattern \
        getsockopt hit 16 512 4096 p99_lt 0 1000000)" || \
        fail 'cannot construct getsockopt/hit benchmark validation'
    getsockopt_one_shot_pattern="$(transport_benchmark_series_pattern \
        getsockopt one_shot 16 512 4096 correctness_only 0 0)" || \
        fail 'cannot construct getsockopt/one_shot benchmark validation'
    unix_miss_pattern="$(transport_benchmark_series_pattern \
        unix miss 8 128 1024 p99_lt 0 50000000)" || \
        fail 'cannot construct unix/miss benchmark validation'
    unix_hit_pattern="$(transport_benchmark_series_pattern \
        unix hit 8 128 1024 p99_lt 0 50000000)" || \
        fail 'cannot construct unix/hit benchmark validation'
    unix_timeout_pattern="$(transport_benchmark_series_pattern \
        unix timeout 8 128 1024 p50_gte_p99_lte 50000000 100000000)" || \
        fail 'cannot construct unix/timeout benchmark validation'

    artifact_pattern+='"provenance":\{"harness":"go_privileged_transport_provider",'
    artifact_pattern+='"measures":\["transport","provider"\],'
    artifact_pattern+='"excludes":\["java","jni"\]\},'
    artifact_pattern+='"unix_timeout_deadline_ns":50000000,"series":\['
    artifact_pattern+="${getsockopt_miss_pattern},${getsockopt_hit_pattern},"
    artifact_pattern+="${getsockopt_one_shot_pattern},${unix_miss_pattern},"
    artifact_pattern+="${unix_hit_pattern},${unix_timeout_pattern}\]\}$"
    grep -Eq -- "$artifact_pattern" "$artifact_file" || \
        fail "transport benchmark artifact has an invalid schema-v2 structure: ${artifact_file}"

    require_transport_benchmark_series \
        "$artifact_file" getsockopt miss 16 512 4096 p99_lt 0 1000000
    require_transport_benchmark_series \
        "$artifact_file" getsockopt hit 16 512 4096 p99_lt 0 1000000
    require_transport_benchmark_series \
        "$artifact_file" getsockopt one_shot 16 512 4096 correctness_only 0 0
    require_transport_benchmark_series \
        "$artifact_file" unix miss 8 128 1024 p99_lt 0 50000000
    require_transport_benchmark_series \
        "$artifact_file" unix hit 8 128 1024 p99_lt 0 50000000
    require_transport_benchmark_series \
        "$artifact_file" unix timeout 8 128 1024 p50_gte_p99_lte 50000000 100000000
}

transport_benchmark_artifact_gates_pass() {
    local -r artifact_file="$1"

    ! grep -Fq -- '"passed":false' "$artifact_file"
}

packaged_jvm_benchmark_artifact_gates_pass() {
    local -r artifact_file="$1"

    ! grep -Fq -- '"passed":false' "$artifact_file"
}

require_packaged_jvm_benchmark_artifact() {
    local -r artifact_file="$1"
    local -r output_file="$2"
    local -r agent_path="$3"
    local -r test_binary="$4"
    local -r source_revision="$5"
    local -r kernel_release="$6"
    local -r java_path="$7"
    local -r sockopt_bpf_path="$8"
    local -r sockops_bpf_path="$9"

    require_private_benchmark_path "$artifact_file" 'regular file' 600
    [[ -s "$artifact_file" ]] || \
        fail "packaged JVM benchmark artifact is missing: ${artifact_file}"
    OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_ARTIFACT="$artifact_file" \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_CI_CROSSLINKS=1 \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_AGENT="$agent_path" \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_TEST_BINARY="$test_binary" \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_REVISION="$source_revision" \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_KERNEL="$kernel_release" \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_JAVA="$java_path" \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_SOCKOPT_BPF="$sockopt_bpf_path" \
        OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_SOCKOPS_BPF="$sockops_bpf_path" \
        "$OUTPUT_DIR/packaged-jvm-benchmark.test" \
            -test.v \
            -test.run "$PACKAGED_JVM_ARTIFACT_VALIDATOR_PATTERN" \
            2>&1 | tee "$output_file"
    require_test_passed "$output_file" "$PACKAGED_JVM_ARTIFACT_VALIDATOR_NAME"
    require_test_passed "$output_file" "$PACKAGED_JVM_ARTIFACT_CROSSLINK_VALIDATOR_NAME"
}

create_transport_benchmark_artifact_path() {
    local -r artifact_dir="$1"
    local absolute_artifact_dir=""

    if [[ -e "$artifact_dir" || -L "$artifact_dir" ]]; then
        fail "transport benchmark artifact directory already exists: ${artifact_dir}"
    fi
    mkdir -m 700 -- "$artifact_dir" || \
        fail "failed to create transport benchmark artifact directory: ${artifact_dir}"
    require_private_benchmark_path "$artifact_dir" directory 700
    # Go test changes to the package directory. Keep logical symlinks visible so
    # the artifact writer can still reject them with O_NOFOLLOW.
    absolute_artifact_dir="$(
        unset CDPATH
        cd -L -- "$artifact_dir" && pwd -L
    )" || \
        fail "failed to resolve transport benchmark artifact directory: ${artifact_dir}"
    printf '%s\n' "${absolute_artifact_dir}/benchmark.json"
}

require_java_agent() {
    [[ -s "$JAVA_AGENT_PATH" ]] || fail "Java bridge agent artifact is unavailable at ${JAVA_AGENT_PATH}"
    [[ -s "$JAVA_AGENT_CHECKSUM" ]] || fail "Java bridge agent checksum is unavailable at ${JAVA_AGENT_CHECKSUM}"
    command -v java >/dev/null 2>&1 || fail 'Java runtime is unavailable'
    command -v realpath >/dev/null 2>&1 || fail 'realpath is unavailable'

    java -version 2>&1 | tee "$OUTPUT_DIR/java-version.txt"
    sha256sum -c "$JAVA_AGENT_CHECKSUM" | tee "$OUTPUT_DIR/java-agent-verified.txt"
    sha256sum "$JAVA_AGENT_PATH" | tee "$OUTPUT_DIR/java-agent-vm.sha256"
}

build_packaged_jvm_benchmark_test_binary() {
    local -r test_binary="$OUTPUT_DIR/packaged-jvm-benchmark.test"

    [[ ! -e "$test_binary" && ! -L "$test_binary" ]] || \
        fail "refusing to replace packaged JVM benchmark test binary: ${test_binary}"
    (
        umask 077
        go test \
            -c \
            -tags=privileged_tests \
            -o "$test_binary" \
            ./pkg/internal/ebpf/tpinjector
    )
    require_private_benchmark_path "$test_binary" 'regular file' 700
}

collect_kernel_evidence() {
    local -r btf_file=/sys/kernel/btf/vmlinux
    local kernel_release=""

    (( EUID == 0 )) || fail 'VM validation must run as root'
    kernel_release="$(uname -r)"
    [[ "$kernel_release" == 5.14.* ]] || \
        fail "expected the RHEL 9 5.14 kernel family, got ${kernel_release}"
    [[ "$(uname -m)" == x86_64 ]] || fail 'expected x86_64 architecture'
    [[ -r /sys/fs/cgroup/cgroup.controllers ]] || \
        fail 'unified cgroup v2 is unavailable'
    [[ -s "$btf_file" ]] || fail "kernel BTF is unavailable at ${btf_file}"
    command -v bpftool >/dev/null 2>&1 || fail 'bpftool is unavailable'

    {
        printf '%s\n' '=== uname ==='
        uname -a
        printf 'release=%s\narchitecture=%s\n' "$kernel_release" "$(uname -m)"
        id
    } 2>&1 | tee "$OUTPUT_DIR/uname.txt"

    {
        printf '%s\n' '=== /proc/self/cgroup ==='
        cat /proc/self/cgroup
        printf '%s\n' '=== cgroup mounts ==='
        mount | grep -- 'cgroup'
        printf '%s\n' '=== cgroup v2 controllers ==='
        cat /sys/fs/cgroup/cgroup.controllers
    } 2>&1 | tee "$OUTPUT_DIR/cgroup.txt"

    {
        printf 'path=%s\n' "$btf_file"
        printf 'bytes='
        wc -c < "$btf_file"
        sha256sum "$btf_file"
    } 2>&1 | tee "$OUTPUT_DIR/btf.txt"

    {
        bpftool version
        bpftool feature probe kernel full
    } 2>&1 | tee "$OUTPUT_DIR/bpftool-feature.txt"
}

run_production_verifier_profiles() {
    local -r output_file="$OUTPUT_DIR/production-verifier-profiles.log"

    go test \
        -count=1 \
        -timeout=20m \
        -v \
        -tags=bpf_verifier_tests \
        -run "$VERIFIER_TEST_PATTERN" \
        ./pkg/internal/ebpf/verifier/... 2>&1 | tee "$output_file"

    require_production_verifier_profiles_passed "$output_file"
}

run_sockopt_authority_tests() {
    local -r output_file="$OUTPUT_DIR/privileged-tests.log"
    local java_agent_path=""

    java_agent_path="$(resolve_existing_path "$JAVA_AGENT_PATH")"

    OBI_JAVA_REMOTE_PARENT_AGENT_JAR="$java_agent_path" \
    OBI_REQUIRE_CGROUP_TOPOLOGY=1 go test \
        -count=1 \
        -timeout=10m \
        -v \
        -tags=privileged_tests \
        -run "$PRIVILEGED_TEST_PATTERN" \
        ./pkg/internal/ebpf/tpinjector 2>&1 | tee "$output_file"

    require_test_passed "$output_file" \
        TestJavaRemoteParentPrimarySocketAuthority
    require_test_passed "$output_file" \
        TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook
    require_test_passed "$output_file" \
        TestJavaRemoteParentPrimaryJVMFaults
    require_test_passed "$output_file" \
        TestJavaRemoteParentPrimaryJVMDirectSSLSocket
    require_test_passed "$output_file" \
        TestJavaRemoteParentGenericJVMDirectSSLSocket
    require_test_passed "$output_file" \
        TestJavaRemoteParentNestedCgroupLifecycle
    require_test_passed "$output_file" \
        TestJavaRemoteParentCgroupLinkProcessDeathCleanup
    require_test_passed "$output_file" \
        TestJavaRemoteParentCgroupPartialAttachRollback
    require_test_passed "$output_file" \
        TestJavaRemoteParentBridgeLoadRequiresPrivileges
}

run_transport_benchmark() {
    local -r output_file="$OUTPUT_DIR/transport-benchmark.log"
    local -r artifact_dir="$OUTPUT_DIR/transport-benchmark"
    local artifact_file=""
    local test_status=0

    artifact_file="$(create_transport_benchmark_artifact_path "$artifact_dir")" || \
        fail 'failed to prepare transport benchmark artifact path'

    if OBI_JAVA_REMOTE_PARENT_BENCHMARK=1 \
        OBI_JAVA_REMOTE_PARENT_BENCHMARK_ARTIFACT="$artifact_file" go test \
            -count=1 \
            -timeout=10m \
            -v \
            -tags=privileged_tests \
            -run "$BENCHMARK_TEST_PATTERN" \
            ./pkg/internal/ebpf/tpinjector 2>&1 | tee "$output_file"; then
        test_status=0
    else
        test_status=$?
    fi

    require_transport_benchmark_artifact "$artifact_file"
    grep -F -- 'bridge_benchmark ' "$output_file" \
        | tee "$OUTPUT_DIR/benchmark-results.txt"
    transport_benchmark_artifact_gates_pass "$artifact_file" || \
        fail "transport benchmark artifact records a failed latency gate: ${artifact_file}"
    (( test_status == 0 )) || \
        fail "transport benchmark test failed with status ${test_status}; see ${output_file}"
    require_test_passed "$output_file" \
        TestJavaRemoteParentTransportBenchmark
}

run_packaged_jvm_benchmark() {
    local -r output_file="$OUTPUT_DIR/packaged-jvm-benchmark.log"
    local -r validation_output="$OUTPUT_DIR/packaged-jvm-benchmark-validation.log"
    local -r artifact_dir="$OUTPUT_DIR/packaged-jvm-benchmark"
    local -r identity_file="$OUTPUT_DIR/packaged-jvm-benchmark-identities.txt"
    local artifact_file=""
    local agent_path=""
    local java_path=""
    local setpriv_help=""
    local setpriv_lookup=""
    local setpriv_owner=""
    local setpriv_path=""
    local setpriv_version=""
    local sockopt_bpf_path=""
    local sockops_bpf_path=""
    local source_revision=""
    local kernel_release=""
    local test_status=0
    local -a benchmark_environment=()

    command -v java >/dev/null 2>&1 || fail 'Java runtime is unavailable'
    agent_path="$(resolve_existing_path "$JAVA_AGENT_PATH")" || \
        fail 'failed to resolve the packaged JVM agent artifact'
    java_path="$(resolve_existing_path "$(command -v java)")" || \
        fail 'failed to resolve the packaged Java runtime'
    [[ -x "$PACKAGED_JVM_SETPRIV_PATH" ]] || \
        fail "packaged JVM benchmark setpriv is unavailable: ${PACKAGED_JVM_SETPRIV_PATH}"
    setpriv_path="$(resolve_existing_path "$PACKAGED_JVM_SETPRIV_PATH")" || \
        fail 'failed to resolve packaged JVM benchmark setpriv'
    setpriv_lookup="$(PATH=/usr/local/go/bin:/usr/bin:/bin command -v setpriv)" || \
        fail 'setpriv is unavailable in the packaged JVM benchmark environment'
    setpriv_lookup="$(resolve_existing_path "$setpriv_lookup")" || \
        fail 'failed to resolve setpriv from the packaged JVM benchmark environment'
    [[ "$setpriv_lookup" == "$setpriv_path" ]] || \
        fail "packaged JVM benchmark resolves an unexpected setpriv: ${setpriv_lookup}"
    setpriv_owner="$(apk info --who-owns "$PACKAGED_JVM_SETPRIV_PATH")" || \
        fail 'failed to establish the packaged JVM benchmark setpriv package owner'
    setpriv_version="$(LC_ALL=C "$setpriv_path" --version 2>&1)" || \
        fail 'packaged JVM benchmark setpriv does not support --version'
    setpriv_help="$(LC_ALL=C "$setpriv_path" --help 2>&1)" || \
        fail 'failed to inspect packaged JVM benchmark setpriv options'
    validate_packaged_jvm_setpriv_identity \
        "$setpriv_path" "$setpriv_owner" "$setpriv_version" "$setpriv_help" || \
        fail 'packaged JVM benchmark requires Alpine setpriv from util-linux with every privilege-drop option'
    sockopt_bpf_path="$(resolve_existing_path \
        pkg/internal/ebpf/tpinjector/bpfjavaremoteparent_x86_bpfel.o)" || \
        fail 'failed to resolve the generated sockopt BPF artifact'
    sockops_bpf_path="$(resolve_existing_path \
        pkg/internal/ebpf/tpinjector/bpf_x86_bpfel.o)" || \
        fail 'failed to resolve the generated sockops BPF artifact'
    source_revision="$(git rev-parse HEAD)" || \
        fail 'failed to resolve the packaged JVM benchmark source revision'
    [[ "$source_revision" =~ ^[0-9a-f]{40}$ ]] || \
        fail 'packaged JVM benchmark source revision is invalid'
    [[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || \
        fail 'packaged JVM benchmark requires a clean source tree'
    kernel_release="$(uname -r)" || fail 'failed to resolve the VM kernel release'
    artifact_file="$(create_transport_benchmark_artifact_path "$artifact_dir")" || \
        fail 'failed to prepare the packaged JVM benchmark artifact path'
    benchmark_environment=(
        "HOME=/root"
        "LANG=C"
        "LC_ALL=C"
        "PATH=/usr/local/go/bin:/usr/bin:/bin"
        "TMPDIR=/tmp"
        "TZ=UTC"
        "OBI_JAVA_REMOTE_PARENT_AGENT_JAR=$agent_path"
        "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK=1"
        "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_ARTIFACT=$artifact_file"
        "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_EXCLUSIVE_CGROUP_BPF=$PACKAGED_JVM_EXCLUSIVE_CGROUP_BPF_PREMISE"
    )

    {
        printf 'userspace=Alpine Linux\n'
        printf 'kernel_input=RHEL 9.6 LVH pinned artifact\n'
        printf 'kernel_release=%s\nsource_revision=%s\n' \
            "$kernel_release" "$source_revision"
        printf 'java=%s\nsetpriv=%s\nagent=%s\nsockopt_bpf=%s\nsockops_bpf=%s\n' \
            "$java_path" "$setpriv_path" "$agent_path" \
            "$sockopt_bpf_path" "$sockops_bpf_path"
        printf 'setpriv_package_owner=%s\nsetpriv_required_options=%s\n' \
            "$setpriv_owner" "${PACKAGED_JVM_SETPRIV_OPTIONS[*]}"
        printf 'exclusive_cgroup_bpf_premise=%s\n' \
            "$PACKAGED_JVM_EXCLUSIVE_CGROUP_BPF_PREMISE"
        "$java_path" -version 2>&1
        cat /etc/os-release
        go version
        git --version
        "$setpriv_path" --version
        apk info -e openjdk21-jre-headless setpriv
        apk info -a openjdk21-jre-headless setpriv
        sha256sum "$java_path" "$setpriv_path" "$agent_path" \
            "$sockopt_bpf_path" "$sockops_bpf_path" \
            "$OUTPUT_DIR/packaged-jvm-benchmark.test"
    } > "$identity_file"
    sha256sum "$identity_file" | tee "$OUTPUT_DIR/packaged-jvm-benchmark-identities.sha256"
    env -i "${benchmark_environment[@]}" env | LC_ALL=C sort \
        > "$OUTPUT_DIR/packaged-jvm-benchmark-root-environment.txt"
    sha256sum "$OUTPUT_DIR/packaged-jvm-benchmark-root-environment.txt" | \
        tee "$OUTPUT_DIR/packaged-jvm-benchmark-root-environment.sha256"

    if env -i "${benchmark_environment[@]}" \
        "$OUTPUT_DIR/packaged-jvm-benchmark.test" \
            -test.v \
            -test.timeout=10m \
            -test.run "$PACKAGED_JVM_BENCHMARK_TEST_PATTERN" \
            2>&1 | tee "$output_file"; then
        test_status=0
    else
        test_status=$?
    fi

    # The benchmark publishes a structurally valid artifact before applying
    # the latency gate. Validate and retain it even when the test reports a
    # failed gate, then preserve the original test status.
    require_packaged_jvm_benchmark_artifact \
        "$artifact_file" \
        "$validation_output" \
        "$agent_path" \
        "$OUTPUT_DIR/packaged-jvm-benchmark.test" \
        "$source_revision" \
        "$kernel_release" \
        "$java_path" \
        "$sockopt_bpf_path" \
        "$sockops_bpf_path"
    sha256sum "$artifact_file" | tee "$OUTPUT_DIR/packaged-jvm-benchmark.sha256"
    packaged_jvm_benchmark_artifact_gates_pass "$artifact_file" || \
        fail "packaged JVM benchmark artifact records a failed latency gate: ${artifact_file}"
    (( test_status == 0 )) || \
        fail "packaged JVM benchmark test failed with status ${test_status}; see ${output_file}"
    require_test_passed "$output_file" "$PACKAGED_JVM_BENCHMARK_TEST_NAME"
}

main() {
    mkdir -p -- "$OUTPUT_DIR"
    collect_kernel_evidence
    require_java_agent
    build_packaged_jvm_benchmark_test_binary
    run_production_verifier_profiles
    run_sockopt_authority_tests
    run_transport_benchmark
    # Run last so earlier probes cannot perturb the packaged latency evidence.
    run_packaged_jvm_benchmark
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
