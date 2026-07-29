#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly OUTPUT_DIR="${TEST_OUTPUT:-testoutput}/java-remote-parent-rhel9.6-kernel-sockopt"
readonly JAVA_AGENT_PATH="${OUTPUT_DIR}/java-artifacts/obi-java-agent.jar"
readonly JAVA_AGENT_CHECKSUM="${OUTPUT_DIR}/java-agent.sha256"
readonly PRIVILEGED_TEST_PATTERN='^(TestJavaRemoteParentPrimarySocketAuthority|TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook|TestJavaRemoteParentPrimaryJVMFaults|TestJavaRemoteParentNestedCgroupLifecycle|TestJavaRemoteParentCgroupLinkProcessDeathCleanup|TestJavaRemoteParentCgroupPartialAttachRollback|TestJavaRemoteParentBridgeLoadRequiresPrivileges)$'
readonly BENCHMARK_TEST_PATTERN='^TestJavaRemoteParentTransportBenchmark$'

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_test_passed() {
    local -r output_file="$1"
    local -r test_name="$2"

    if grep -Eq -- '^[[:space:]]*--- SKIP:' "$output_file"; then
        fail "a required test skipped; see ${output_file}"
    fi
    if ! grep -Fq -- "--- PASS: ${test_name} " "$output_file"; then
        fail "${test_name} did not report PASS; see ${output_file}"
    fi
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

require_transport_benchmark_series() {
    local -r artifact_file="$1"
    local -r transport="$2"
    local -r outcome="$3"
    local -r samples="$4"
    local -r positive_integer='[1-9][0-9]*'
    local -r non_negative_integer='[0-9]+'
    local -r non_negative_number='[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?'
    local series_pattern="\\{\"transport\":\"${transport}\",\"outcome\":\"${outcome}\","

    series_pattern+="\"warmup_rounds\":${positive_integer},"
    series_pattern+="\"measurement_rounds\":${positive_integer},"
    series_pattern+="\"samples\":${samples},\"concurrency\":8,"
    series_pattern+="\"batch_elapsed_ns\":${positive_integer},"
    series_pattern+="\"p50_ns\":${positive_integer},"
    series_pattern+="\"p95_ns\":${positive_integer},"
    series_pattern+="\"p99_ns\":${positive_integer},"
    series_pattern+="\"operations_per_second\":${non_negative_number},"
    series_pattern+="\"valid\":${non_negative_integer},"
    series_pattern+="\"missing\":${non_negative_integer},"
    series_pattern+="\"already_consumed\":${non_negative_integer},"
    series_pattern+="\"errors\":0,\"correct\":true\\}"

    if ! grep -Eq -- "$series_pattern" "$artifact_file"; then
        fail "transport benchmark artifact lacks a valid ${transport}/${outcome} series: ${artifact_file}"
    fi
}

require_transport_benchmark_artifact() {
    local -r artifact_file="$1"
    local transport_count=""

    require_private_benchmark_path "$artifact_file" 'regular file' 600
    [[ -s "$artifact_file" ]] || \
        fail "transport benchmark artifact is missing or invalid: ${artifact_file}"
    grep -Fq -- '"schema_version":1,"benchmark":"java_remote_parent_transport","series":[' "$artifact_file" || \
        fail "transport benchmark artifact has an invalid root: ${artifact_file}"

    transport_count="$(grep -o -- '"transport":' "$artifact_file" | wc -l || true)"
    [[ "$transport_count" -eq 5 ]] || \
        fail "transport benchmark artifact has an unexpected series count: ${artifact_file}"

    require_transport_benchmark_series "$artifact_file" getsockopt miss 4096
    require_transport_benchmark_series "$artifact_file" getsockopt hit 4096
    require_transport_benchmark_series "$artifact_file" getsockopt one_shot 4096
    require_transport_benchmark_series "$artifact_file" unix miss 1024
    require_transport_benchmark_series "$artifact_file" unix hit 1024
}

require_java_agent() {
    [[ -s "$JAVA_AGENT_PATH" ]] || fail "Java bridge agent artifact is unavailable at ${JAVA_AGENT_PATH}"
    [[ -s "$JAVA_AGENT_CHECKSUM" ]] || fail "Java bridge agent checksum is unavailable at ${JAVA_AGENT_CHECKSUM}"
    command -v java >/dev/null 2>&1 || fail 'Java runtime is unavailable'

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

run_sockopt_authority_tests() {
    local -r output_file="$OUTPUT_DIR/privileged-tests.log"

    OBI_JAVA_REMOTE_PARENT_AGENT_JAR="$JAVA_AGENT_PATH" \
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
    local artifact_dir=""

    artifact_dir="$(mktemp -d -- "${OUTPUT_DIR}/transport-benchmark.XXXXXX")" || \
        fail 'failed to create transport benchmark artifact directory'
    require_private_benchmark_path "$artifact_dir" directory 700
    local -r artifact_file="${artifact_dir}/benchmark.json"

    OBI_JAVA_REMOTE_PARENT_BENCHMARK=1 \
    OBI_JAVA_REMOTE_PARENT_BENCHMARK_ARTIFACT="$artifact_file" go test \
        -count=1 \
        -timeout=10m \
        -v \
        -tags=privileged_tests \
        -run "$BENCHMARK_TEST_PATTERN" \
        ./pkg/internal/ebpf/tpinjector 2>&1 | tee "$output_file"

    require_test_passed "$output_file" \
        TestJavaRemoteParentTransportBenchmark
    require_transport_benchmark_artifact "$artifact_file"
    grep -F -- 'bridge_benchmark ' "$output_file" \
        | tee "$OUTPUT_DIR/benchmark-results.txt"
}

main() {
    mkdir -p -- "$OUTPUT_DIR"
    collect_kernel_evidence
    require_java_agent
    run_sockopt_authority_tests
    run_transport_benchmark
}

main "$@"
