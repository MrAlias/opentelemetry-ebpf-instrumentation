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
    printf '%s\n' 'RHEL verifier and transport benchmark validator tests passed'
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
