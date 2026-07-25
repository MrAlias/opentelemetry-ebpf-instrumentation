#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly OUTPUT_DIR="${TEST_OUTPUT:-testoutput}/java-remote-parent-rhel9.6-kernel-sockopt"
readonly PRIVILEGED_TEST_PATTERN='^(TestJavaRemoteParentPrimarySocketAuthority|TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook|TestJavaRemoteParentNestedCgroupLifecycle|TestJavaRemoteParentCgroupLinkProcessDeathCleanup|TestJavaRemoteParentCgroupPartialAttachRollback|TestJavaRemoteParentBridgeLoadRequiresPrivileges)$'
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

    OBI_JAVA_REMOTE_PARENT_BENCHMARK=1 go test \
        -count=1 \
        -timeout=10m \
        -v \
        -tags=privileged_tests \
        -run "$BENCHMARK_TEST_PATTERN" \
        ./pkg/internal/ebpf/tpinjector 2>&1 | tee "$output_file"

    require_test_passed "$output_file" \
        TestJavaRemoteParentTransportBenchmark
    grep -F -- 'bridge_benchmark ' "$output_file" \
        | tee "$OUTPUT_DIR/benchmark-results.txt"
}

main() {
    mkdir -p -- "$OUTPUT_DIR"
    collect_kernel_evidence
    run_sockopt_authority_tests
    run_transport_benchmark
}

main "$@"
