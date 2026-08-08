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
readonly PRIVILEGED_TEST_PATTERN='^(TestJavaRemoteParentPrimarySocketAuthority|TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook|TestJavaRemoteParentPrimaryJVMFaults|TestJavaRemoteParentPrimaryJVMDirectSSLSocket|TestJavaRemoteParentNestedCgroupLifecycle|TestJavaRemoteParentCgroupLinkProcessDeathCleanup|TestJavaRemoteParentCgroupPartialAttachRollback|TestJavaRemoteParentBridgeLoadRequiresPrivileges)$'
readonly BENCHMARK_TEST_PATTERN='^TestJavaRemoteParentTransportBenchmark$'

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

create_transport_benchmark_artifact_path() {
    local -r artifact_dir="$1"

    if [[ -e "$artifact_dir" || -L "$artifact_dir" ]]; then
        fail "transport benchmark artifact directory already exists: ${artifact_dir}"
    fi
    mkdir -m 700 -- "$artifact_dir" || \
        fail "failed to create transport benchmark artifact directory: ${artifact_dir}"
    require_private_benchmark_path "$artifact_dir" directory 700
    printf '%s\n' "${artifact_dir}/benchmark.json"
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

main() {
    mkdir -p -- "$OUTPUT_DIR"
    collect_kernel_evidence
    require_java_agent
    run_production_verifier_profiles
    run_sockopt_authority_tests
    run_transport_benchmark
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
