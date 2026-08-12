#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# This harness intentionally overrides sourced run.sh globals and functions in isolated subshells.
# shellcheck disable=SC2016,SC2030,SC2031,SC2034,SC2317,SC2329

set -Eeuo pipefail

TEST_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TEST_SCRIPT_DIR

# shellcheck source=../run.sh
# shellcheck disable=SC1091 # Resolved from BASH_SOURCE at runtime.
source "$TEST_SCRIPT_DIR/../run.sh"

TEST_TMP_DIR=""

cleanup_test() {
  if [[ -n "${TEST_TMP_DIR:-}" && -d "$TEST_TMP_DIR" ]]; then
    rm -rf -- "$TEST_TMP_DIR"
  fi
}

trap cleanup_test EXIT

expect_invalid_project_name() {
  local -r project_name="$1"
  if (
    PROJECT_NAME="$project_name"
    parse_args --cleanup-only
  ) >/dev/null 2>&1; then
    printf 'accepted invalid Compose project name: %s\n' "$project_name" >&2
    return 1
  fi
}

print_concurrency_result_fixture() {
  local -r request_count="$1"
  local -r assertion_mode="${2:-bridge}"

  jq -cn \
    --argjson request_count "$request_count" \
    --arg assertion_mode "$assertion_mode" '
      {
        status: "passed",
        scenario: "concurrency",
        assertion_mode: $assertion_mode,
        request_count: $request_count,
        connection_evidence: {
          frontend_connections: $request_count,
          frontend_protocol: "HTTP/1.1",
          distinct_backend_workers: $request_count,
          distinct_concurrency_arrivals: $request_count,
          concurrency_participants: $request_count,
          concurrency_max_active: $request_count,
          concurrency_release: 7
        },
        cases: [
          range(0; $request_count) as $index |
          {
            request: {
              concurrency_batch: "c0000000000000007",
              concurrency_expected: $request_count
            },
            response: {
              backend_worker_id: ($index + 11),
              backend_connection_id: (($index % 2) + 1),
              concurrency_batch: "c0000000000000007",
              concurrency_participants: $request_count,
              concurrency_max_active: $request_count,
              concurrency_arrival: ($index + 1),
              concurrency_release: 7
            }
          }
        ]
      }
    '
}

test_project_name_validation() {
  local overlong_name=""

  printf -v overlong_name '%064d' 0
  expect_invalid_project_name "Uppercase"
  expect_invalid_project_name "trailing-"
  expect_invalid_project_name "contains.dot"
  expect_invalid_project_name "$overlong_name"

  PROJECT_NAME="obi-apache-java-https-test_1"
  parse_args --cleanup-only

  expect_invalid_project_name "obi-demo_1"
}

test_compose_cleanup_requires_ownership_sentinel() {
  local -r fake_bin="$TEST_TMP_DIR/fake-docker-bin"
  local -r docker_log="$TEST_TMP_DIR/fake-docker.log"
  local -r docker_down_marker="$TEST_TMP_DIR/fake-docker-down"
  local -r fake_docker="$fake_bin/docker"

  mkdir -p -- "$fake_bin"
  cat >"$fake_docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$1 $2" in
  "container ls") [[ -e "$FAKE_DOCKER_DOWN_MARKER" ]] || printf 'demo-container\n' ;;
  "volume ls") [[ -e "$FAKE_DOCKER_DOWN_MARKER" ]] || printf 'demo-volume\n' ;;
  "network ls") [[ -e "$FAKE_DOCKER_DOWN_MARKER" ]] || printf 'demo-network\n' ;;
  "container inspect"|"volume inspect"|"network inspect")
    if [[ "$FAKE_DOCKER_MODE" == "foreign" && "$1" == "container" ]]; then
      printf 'someone-else\n'
    else
      printf 'acceptance-demo-v1\n'
    fi
    ;;
  "compose --project-name")
    [[ "$*" == *" --profile * down --volumes --remove-orphans --timeout 10" ]] || {
      printf 'cleanup omitted all Compose profiles: %s\n' "$*" >&2
      exit 65
    }
    if [[ "$FAKE_DOCKER_MODE" != "leftover" ]]; then
      : >"$FAKE_DOCKER_DOWN_MARKER"
    fi
    ;;
  *) printf 'unexpected fake Docker arguments: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
  chmod 0755 "$fake_docker"

  (
    export PATH="$fake_bin:$PATH"
    export FAKE_DOCKER_LOG="$docker_log"
    export FAKE_DOCKER_DOWN_MARKER="$docker_down_marker"
    export FAKE_DOCKER_MODE=owned
    PROJECT_NAME="obi-apache-java-https-test"
    # shellcheck disable=SC2153 # Sourced run.sh declares this global fixture path.
    COMPOSE=(
      docker compose --project-name "$PROJECT_NAME" \
        --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE"
    )
    safe_compose_down
  )
  grep -Fq 'compose --project-name obi-apache-java-https-test' "$docker_log" || {
    printf 'verified cleanup did not invoke Compose down\n' >&2
    return 1
  }
  grep -Fq 'container ls --all --quiet' "$docker_log" || {
    printf 'ownership verification omitted stopped project containers\n' >&2
    return 1
  }
  grep -Fq ' --profile * down --volumes --remove-orphans --timeout 10' "$docker_log" || {
    printf 'cleanup did not activate every Compose profile\n' >&2
    return 1
  }

  : >"$docker_log"
  rm -f -- "$docker_down_marker"
  if (
    export PATH="$fake_bin:$PATH"
    export FAKE_DOCKER_LOG="$docker_log"
    export FAKE_DOCKER_DOWN_MARKER="$docker_down_marker"
    export FAKE_DOCKER_MODE=foreign
    PROJECT_NAME="obi-apache-java-https-test"
    COMPOSE=(
      docker compose --project-name "$PROJECT_NAME" \
        --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE"
    )
    safe_compose_down
  ) >/dev/null 2>&1; then
    printf 'cleanup accepted a foreign resource in the reserved project namespace\n' >&2
    return 1
  fi
  if grep -Fq 'compose --project-name' "$docker_log"; then
    printf 'cleanup invoked Compose down after ownership verification failed\n' >&2
    return 1
  fi

  : >"$docker_log"
  rm -f -- "$docker_down_marker"
  if (
    export PATH="$fake_bin:$PATH"
    export FAKE_DOCKER_LOG="$docker_log"
    export FAKE_DOCKER_DOWN_MARKER="$docker_down_marker"
    export FAKE_DOCKER_MODE=leftover
    PROJECT_NAME="obi-apache-java-https-test"
    COMPOSE=(
      docker compose --project-name "$PROJECT_NAME" \
        --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE"
    )
    safe_compose_down
  ) >/dev/null 2>&1; then
    printf 'cleanup accepted project resources left behind by Compose\n' >&2
    return 1
  fi
}

test_successful_cleanup_invalidates_current_transport_before_down() {
  local -r results_root="$TEST_TMP_DIR/cleanup-success-results"
  local -r result_dir="$results_root/current"
  local -r prior_result="$results_root/prior"
  local -r foreign_result="$results_root/foreign"
  local -r down_marker="$result_dir/down"
  local -r receiver_snapshot_temp="$result_dir/.delayed-otlp-receiver.signal"
  local -r receiver_publication_temp="$result_dir/.delayed-ready.json.signal"

  mkdir -p -- "$result_dir" "$prior_result" "$foreign_result"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$result_dir/environment.txt"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$prior_result/environment.txt"
  printf 'compose_project=another-project\n' \
    >"$foreign_result/environment.txt"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  printf 'prior-current\n' >"$prior_result/java-transport-configuration.txt"
  printf 'prior-retained\n' >"$prior_result/java-selected-transport-configuration.txt"
  printf 'foreign-current\n' >"$foreign_result/java-transport-configuration.txt"
  printf 'foreign-retained\n' >"$foreign_result/java-selected-transport-configuration.txt"
  printf 'snapshot\n' >"$receiver_snapshot_temp"
  printf 'publication\n' >"$receiver_publication_temp"
  (
    PRESSURE_ACTIVE=false
    RESULTS_ROOT="$results_root"
    RESULT_DIR="$result_dir"
    PROJECT_NAME="obi-apache-java-https-test"
    STACK_STARTED=true
    KEEP_RUNNING=false
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    MATCHING_BRIDGE_RUNNING=false
    TMP_DIR=""
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP="$receiver_snapshot_temp"
    DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP="$receiver_publication_temp"
    assert_permanent_absence_marker_matches_current_docker() { :; }
    clear_pending_permanent_absence_recovery() { :; }
    cleanup_security_processes() { :; }
    capture_evidence() {
      [[ -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" &&
        -z "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" &&
        ! -e "$receiver_snapshot_temp" &&
        ! -e "$receiver_publication_temp" ]]
    }
    safe_compose_down() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
        -e "$RESULT_DIR/java-selected-transport-configuration.txt" &&
        ! -e "$prior_result/java-transport-configuration.txt" &&
        -e "$prior_result/java-selected-transport-configuration.txt" &&
        -e "$foreign_result/java-transport-configuration.txt" ]] || return 19
      : >"$down_marker"
    }

    cleanup
  ) >/dev/null 2>&1 || {
    printf 'successful cleanup did not invalidate current transport state\n' >&2
    return 1
  }
  [[ -e "$down_marker" &&
    ! -e "$receiver_snapshot_temp" &&
    ! -e "$receiver_publication_temp" &&
    ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" &&
    ! -e "$prior_result/java-transport-configuration.txt" &&
    "$(<"$prior_result/java-selected-transport-configuration.txt")" == \
      "prior-retained" &&
    "$(<"$foreign_result/java-transport-configuration.txt")" == \
      "foreign-current" ]] || {
    printf 'successful cleanup retained stale current-generation selection evidence\n' >&2
    return 1
  }
}

test_delayed_otlp_temporary_cleanup_preserves_failure() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-temporary-cleanup-failure"
  local -r receiver_snapshot_temp="$result_dir/.delayed-otlp-receiver.failure"
  local -r receiver_publication_temp="$result_dir/.delayed-ready.json.failure"
  local cleanup_status=0
  local full_cleanup_status=0

  mkdir -- "$result_dir"
  printf 'snapshot\n' >"$receiver_snapshot_temp"
  printf 'publication\n' >"$receiver_publication_temp"
  if (
    DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP="$receiver_snapshot_temp"
    DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP="$receiver_publication_temp"
    rm() {
      if [[ "$3" == "$receiver_snapshot_temp" ]]; then
        return 47
      fi
      return 53
    }

    cleanup_delayed_otlp_receiver_temporaries
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP temporary cleanup ignored removal failure\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == "47" && -e "$receiver_snapshot_temp" &&
    -e "$receiver_publication_temp" ]] || {
    printf 'delayed OTLP temporary cleanup did not preserve its first failure\n' >&2
    return 1
  }

  if (
    PRESSURE_ACTIVE=false
    STACK_STARTED=false
    FAULT_BRIDGE_RUNNING=false
    MATCHING_BRIDGE_RUNNING=false
    RESULT_DIR="$result_dir"
    RUN_STAGE="temporary-cleanup-test"
    RUN_STATUS=passed
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP="$receiver_snapshot_temp"
    DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP="$receiver_publication_temp"
    cleanup_security_processes() { :; }
    capture_evidence() { :; }
    write_run_status() { :; }
    cleanup_source_snapshot_work_directory() { :; }
    rm() {
      if [[ "$3" == "$receiver_snapshot_temp" ]]; then
        return 47
      fi
      return 53
    }

    cleanup
  ) >/dev/null 2>&1; then
    printf 'full cleanup ignored delayed OTLP temporary removal failure\n' >&2
    return 1
  else
    full_cleanup_status=$?
  fi
  [[ "$full_cleanup_status" == "47" && -e "$receiver_snapshot_temp" &&
    -e "$receiver_publication_temp" ]] || {
    printf 'full cleanup did not preserve its first temporary failure\n' >&2
    return 1
  }
}

test_cleanup_refuses_down_when_transport_invalidation_fails() {
  local -r result_dir="$TEST_TMP_DIR/cleanup-invalidation-failure-result"
  local -r down_marker="$result_dir/down"
  local cleanup_status=0

  mkdir -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  if (
    PRESSURE_ACTIVE=false
    RESULTS_ROOT="$TEST_TMP_DIR/cleanup-invalidation-failure-results"
    RESULT_DIR="$result_dir"
    STACK_STARTED=true
    KEEP_RUNNING=false
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    MATCHING_BRIDGE_RUNNING=false
    TMP_DIR=""
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    assert_permanent_absence_marker_matches_current_docker() { :; }
    cleanup_security_processes() { :; }
    capture_evidence() { :; }
    invalidate_selected_transport() { return 29; }
    safe_compose_down() { : >"$down_marker"; }

    cleanup
  ) >/dev/null 2>&1; then
    printf 'cleanup ignored transport invalidation failure\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == "29" &&
    ! -e "$down_marker" &&
    "$(<"$result_dir/java-transport-configuration.txt")" == "current" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'cleanup mutated the stack after transport invalidation failed\n' >&2
    return 1
  }
  grep -Fq '"exit_status": 29' "$result_dir/run-status.json" || {
    printf 'transport invalidation failure was absent from run-status.json\n' >&2
    return 1
  }
  grep -Fq '"failure_stage": "compose-cleanup"' "$result_dir/run-status.json" || {
    printf 'transport invalidation failure omitted its cleanup stage\n' >&2
    return 1
  }
}

test_cleanup_failure_changes_successful_run_status() {
  local -r result_dir="$TEST_TMP_DIR/cleanup-failure-result"
  local cleanup_status=0

  mkdir -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  if (
    PRESSURE_ACTIVE=false
    RESULTS_ROOT="$TEST_TMP_DIR/cleanup-failure-results"
    RESULT_DIR="$result_dir"
    STACK_STARTED=true
    KEEP_RUNNING=false
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    MATCHING_BRIDGE_RUNNING=false
    TMP_DIR=""
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    assert_permanent_absence_marker_matches_current_docker() { :; }
    cleanup_security_processes() { :; }
    capture_evidence() { :; }
    safe_compose_down() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
        -e "$RESULT_DIR/java-selected-transport-configuration.txt" ]] || return 19
      return 23
    }

    cleanup
  ) >/dev/null 2>&1; then
    printf 'cleanup failure preserved a successful process exit\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == "23" ]] || {
    printf 'cleanup failure returned status %s instead of 23\n' "$cleanup_status" >&2
    return 1
  }
  [[ ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'cleanup retained stale current-generation selection evidence\n' >&2
    return 1
  }
  grep -Fq '"status": "failed"' "$result_dir/run-status.json" || {
    printf 'cleanup failure retained a passed run status\n' >&2
    return 1
  }
  grep -Fq '"exit_status": 23' "$result_dir/run-status.json" || {
    printf 'cleanup failure status was absent from run-status.json\n' >&2
    return 1
  }
  grep -Fq '"failure_stage": "compose-cleanup"' "$result_dir/run-status.json" || {
    printf 'cleanup failure stage was absent from run-status.json\n' >&2
    return 1
  }
}

test_primary_fault_recovery_marker_forces_cleanup_with_keep() {
  local -r result_dir="$TEST_TMP_DIR/primary-fault-recovery-marker"
  local -r down_marker="$result_dir/down"
  local cleanup_status=0

  mkdir -p -- "$result_dir"
  printf 'recovery_required\n' >"$result_dir/primary-w3c-fault-recovery-required"
  if (
    RESULT_DIR="$result_dir"
    STACK_STARTED=true
    KEEP_RUNNING=true
    BRIDGE_RUNNING=true
    PRIMARY_FAULT_STACK_ACTIVE=false
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    assert_permanent_absence_marker_matches_current_docker() { :; }
    clear_pending_permanent_absence_recovery() { :; }
    cleanup_security_processes() {
      :
    }
    capture_evidence() {
      [[ "$PRIMARY_FAULT_STACK_ACTIVE" == true ]]
    }
    invalidate_project_transport_evidence() {
      :
    }
    safe_compose_down() {
      [[ "$BRIDGE_RUNNING" == false ]] || return 1
      : >"$down_marker"
    }

    cleanup
  ) >/dev/null 2>&1; then
    printf 'primary fault recovery marker left a kept stack running\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == 1 && -e "$down_marker" ]] || {
    printf 'primary fault recovery marker did not force a failed cleanup\n' >&2
    return 1
  }
  grep -Fq '"failure_stage": "primary-w3c-fault-recovery"' \
    "$result_dir/run-status.json" || {
    printf 'primary fault recovery marker omitted its failure evidence\n' >&2
    return 1
  }
}

test_primary_live_fd_recovery_marker_forces_cleanup_with_keep() {
  local -r result_dir="$TEST_TMP_DIR/primary-live-fd-recovery-marker"
  local -r down_marker="$result_dir/down"
  local cleanup_status=0

  mkdir -p -- "$result_dir"
  printf 'recovery_required\n' >"$result_dir/primary-live-fd-security-recovery-required"
  if (
    RESULT_DIR="$result_dir"
    STACK_STARTED=true
    KEEP_RUNNING=true
    BRIDGE_RUNNING=true
    PRIMARY_FAULT_STACK_ACTIVE=false
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    assert_permanent_absence_marker_matches_current_docker() { :; }
    clear_pending_permanent_absence_recovery() { :; }
    cleanup_security_processes() {
      :
    }
    capture_evidence() {
      [[ "$PRIMARY_FAULT_STACK_ACTIVE" == true ]]
    }
    invalidate_project_transport_evidence() {
      :
    }
    safe_compose_down() {
      [[ "$BRIDGE_RUNNING" == false ]] || return 1
      : >"$down_marker"
    }

    cleanup
  ) >/dev/null 2>&1; then
    printf 'primary live-descriptor recovery marker left a kept stack running\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == 1 && -e "$down_marker" ]] || {
    printf 'primary live-descriptor recovery marker did not force a failed cleanup\n' >&2
    return 1
  }
  grep -Fq '"failure_stage": "primary-live-fd-security-recovery"' \
    "$result_dir/run-status.json" || {
    printf 'primary live-descriptor recovery marker omitted its failure evidence\n' >&2
    return 1
  }
}

test_run_status_publication_failure_changes_successful_exit() {
  local -r result_dir="$TEST_TMP_DIR/run-status-publication-failure"
  local -r cleanup_log="$result_dir/cleanup.log"
  local -r first_write="$result_dir/first-write"
  local cleanup_status=0

  mkdir -p -- "$result_dir"
  if (
    PRESSURE_ACTIVE=false
    FAULT_BRIDGE_RUNNING=false
    MATCHING_BRIDGE_RUNNING=false
    STACK_STARTED=false
    RESULT_DIR="$result_dir"
    TMP_DIR=""
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    FAILURE_STAGE=""
    FAILURE_LINE=""
    capture_evidence() { :; }
    cleanup_security_processes() { :; }
    eval "$(declare -f write_run_status | \
      sed '1s/^write_run_status /write_run_status_original /')"
    write_run_status() {
      if [[ ! -e "$first_write" ]]; then
        write_run_status_original "$@" || return $?
        : >"$first_write"
        return 29
      fi
      return 79
    }

    cleanup
  ) >"$cleanup_log" 2>&1; then
    printf 'run-status publication failure preserved a successful exit\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == "29" ]] || {
    printf 'run-status publication returned %s instead of 29\n' \
      "$cleanup_status" >&2
    return 1
  }
  if grep -Fq 'retained run evidence' "$cleanup_log"; then
    printf 'cleanup claimed evidence retention after run-status publication failed\n' >&2
    return 1
  fi
  [[ -e "$first_write" ]] || {
    printf 'run-status failure test did not publish its initial passing status\n' >&2
    return 1
  }
  if [[ -e "$result_dir/run-status.json" || -L "$result_dir/run-status.json" ]]; then
    printf 'cleanup retained a stale passing status after failed retry\n' >&2
    return 1
  fi
}

test_cleanup_only_invalidates_matching_project_evidence_before_down() {
  local -r results_root="$TEST_TMP_DIR/cleanup-only-results"
  local -r matching_result="$results_root/matching"
  local -r foreign_result="$results_root/foreign"
  local -r ambiguous_result="$results_root/ambiguous"
  local -r nested_result="$results_root/parent/nested"
  local -r symlink_target="$TEST_TMP_DIR/cleanup-only-symlink-target"
  local -r down_marker="$TEST_TMP_DIR/cleanup-only-down"

  mkdir -p -- \
    "$matching_result" \
    "$foreign_result" \
    "$ambiguous_result" \
    "$nested_result" \
    "$symlink_target"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$matching_result/environment.txt"
  printf 'compose_project=another-project\n' \
    >"$foreign_result/environment.txt"
  printf '%s\n' \
    'compose_project=obi-apache-java-https-test' \
    'compose_project=another-project' \
    >"$ambiguous_result/environment.txt"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$nested_result/environment.txt"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$symlink_target/environment.txt"
  ln -s -- "$symlink_target" "$results_root/symlink"
  for result in \
    "$matching_result" \
    "$foreign_result" \
    "$nested_result" \
    "$symlink_target"; do
    printf 'current\n' >"$result/java-transport-configuration.txt"
    printf 'retained\n' >"$result/java-selected-transport-configuration.txt"
  done
  printf 'retained\n' \
    >"$ambiguous_result/java-selected-transport-configuration.txt"
  (umask 077; printf 'recovery_required\n' \
    >"$matching_result/permanent-absence-recovery-required")
  (umask 077; printf 'recovery_required\n' \
    >"$foreign_result/permanent-absence-recovery-required")

  (
    RESULTS_ROOT="$results_root"
    RESULT_DIR=""
    PROJECT_NAME="obi-apache-java-https-test"
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=unix
    assert_permanent_absence_marker_matches_current_docker() { :; }
    clear_pending_permanent_absence_recovery() { :; }
    safe_compose_down() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$matching_result/java-transport-configuration.txt" &&
        -e "$matching_result/java-selected-transport-configuration.txt" &&
        -e "$foreign_result/java-transport-configuration.txt" &&
        -e "$matching_result/permanent-absence-recovery-required" &&
        -e "$foreign_result/permanent-absence-recovery-required" &&
        ! -e "$ambiguous_result/java-transport-configuration.txt" &&
        -e "$nested_result/java-transport-configuration.txt" &&
        -e "$symlink_target/java-transport-configuration.txt" ]] || return 31
      : >"$down_marker"
    }

    cleanup_only
  ) || {
    printf 'cleanup-only did not invalidate matching project evidence\n' >&2
    return 1
  }
  [[ -e "$down_marker" &&
    ! -e "$matching_result/java-transport-configuration.txt" &&
    "$(<"$matching_result/java-selected-transport-configuration.txt")" == "retained" &&
    "$(<"$foreign_result/java-transport-configuration.txt")" == "current" &&
    "$(<"$matching_result/permanent-absence-recovery-required")" == \
      "recovery_required" &&
    "$(<"$foreign_result/permanent-absence-recovery-required")" == \
      "recovery_required" &&
    "$(<"$ambiguous_result/java-selected-transport-configuration.txt")" == "retained" &&
    "$(<"$nested_result/java-transport-configuration.txt")" == "current" &&
    "$(<"$symlink_target/java-transport-configuration.txt")" == "current" ]] || {
    printf 'cleanup-only invalidated evidence outside the exact project scope\n' >&2
    return 1
  }
}

test_cleanup_only_refuses_untrusted_current_evidence_identity() {
  local mode=""
  local results_root=""
  local result_dir=""
  local down_marker=""
  local expected_status=0
  local cleanup_status=0

  for mode in missing ambiguous duplicate opaque; do
    results_root="$TEST_TMP_DIR/cleanup-only-untrusted-$mode"
    result_dir="$results_root/result"
    down_marker="$results_root/down"
    mkdir -p -- "$result_dir"
    case "$mode" in
      missing)
        expected_status=1
        ;;
      ambiguous)
        expected_status=2
        printf '%s\n' \
          'compose_project=obi-apache-java-https-test' \
          'compose_project=another-project' \
          >"$result_dir/environment.txt"
        ;;
      duplicate)
        expected_status=2
        printf '%s\n' \
          'compose_project=obi-apache-java-https-test' \
          'compose_project=obi-apache-java-https-test' \
          >"$result_dir/environment.txt"
        ;;
      opaque)
        expected_status=1
        printf 'compose_project=obi-apache-java-https-test\n' \
          >"$result_dir/environment.txt"
        ;;
    esac
    printf 'current\n' >"$result_dir/java-transport-configuration.txt"
    printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
    if [[ "$mode" == "opaque" ]]; then
      chmod 000 -- "$result_dir"
    fi

    if (
      RESULTS_ROOT="$results_root"
      RESULT_DIR=""
      PROJECT_NAME="obi-apache-java-https-test"
      BRIDGE_RUNNING=true
      SELECTED_TRANSPORT=unix
      assert_permanent_absence_marker_matches_current_docker() { :; }
      safe_compose_down() {
        : >"$down_marker"
      }

      cleanup_only
    ) >/dev/null 2>&1; then
      printf 'cleanup-only accepted %s current evidence identity\n' "$mode" >&2
      return 1
    else
      cleanup_status=$?
    fi
    if [[ "$mode" == "opaque" ]]; then
      chmod 0700 -- "$result_dir"
    fi
    [[ "$cleanup_status" == "$expected_status" &&
      ! -e "$down_marker" &&
      "$(<"$result_dir/java-transport-configuration.txt")" == "current" &&
      "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
      printf 'cleanup-only mutated state after %s identity failure\n' "$mode" >&2
      return 1
    }
  done
}

test_cleanup_only_refuses_down_when_project_evidence_invalidation_fails() {
  local -r results_root="$TEST_TMP_DIR/cleanup-only-failure-results"
  local -r result_dir="$results_root/matching"
  local -r down_marker="$TEST_TMP_DIR/cleanup-only-failure-down"
  local cleanup_status=0

  mkdir -p -- "$result_dir"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$result_dir/environment.txt"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"

  if (
    RESULTS_ROOT="$results_root"
    RESULT_DIR=""
    PROJECT_NAME="obi-apache-java-https-test"
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=unix
    assert_permanent_absence_marker_matches_current_docker() { :; }
    rm() {
      return 29
    }
    safe_compose_down() {
      : >"$down_marker"
    }

    if cleanup_only; then
      return 1
    else
      cleanup_status=$?
    fi
    [[ "$cleanup_status" == "29" &&
      "$BRIDGE_RUNNING" == "true" &&
      "$SELECTED_TRANSPORT" == "unix" ]] || return 1
    return "$cleanup_status"
  ) >/dev/null 2>&1; then
    printf 'cleanup-only ignored project evidence invalidation failure\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == "29" &&
    ! -e "$down_marker" &&
    "$(<"$result_dir/java-transport-configuration.txt")" == "current" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'cleanup-only mutated Compose after evidence invalidation failed\n' >&2
    return 1
  }
}

test_cleanup_only_fails_closed_on_project_matcher_error() {
  local -r results_root="$TEST_TMP_DIR/cleanup-only-matcher-results"
  local -r result_dir="$results_root/matching"
  local -r down_marker="$TEST_TMP_DIR/cleanup-only-matcher-down"
  local cleanup_status=0

  mkdir -p -- "$result_dir"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$result_dir/environment.txt"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"

  if (
    RESULTS_ROOT="$results_root"
    RESULT_DIR=""
    PROJECT_NAME="obi-apache-java-https-test"
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=unix
    assert_permanent_absence_marker_matches_current_docker() { :; }
    result_evidence_matches_project() {
      return 42
    }
    safe_compose_down() {
      : >"$down_marker"
    }

    cleanup_only
  ) >/dev/null 2>&1; then
    printf 'cleanup-only treated a matcher error as an unrelated project\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == "42" &&
    ! -e "$down_marker" &&
    "$(<"$result_dir/java-transport-configuration.txt")" == "current" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'cleanup-only continued after project matcher failure\n' >&2
    return 1
  }
}

test_main_propagates_cleanup_only_failure() {
  local cleanup_status=0

  if (
    install_traps() { :; }
    parse_args() { CLEANUP_ONLY=true; }
    check_dependencies() { :; }
    enter_project_guard() { :; }
    cleanup_only() { return 29; }

    run_demo --cleanup-only
  ) >/dev/null 2>&1; then
    printf 'main ignored cleanup-only failure\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == "29" ]] || {
    printf 'main returned %s instead of cleanup-only status 29\n' \
      "$cleanup_status" >&2
    return 1
  }
}

test_acceptance_requires_fresh_bridge_build() {
  if (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    SKIP_BRIDGE_BUILD=false
    parse_args --scenario all --skip-bridge-build
  ) >/dev/null 2>&1; then
    printf 'accepted cached bridge artifacts for the full acceptance suite\n' >&2
    return 1
  fi
}

test_custom_all_request_count_is_non_acceptance() {
  (
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --scenario all --requests 1
    [[ "$ACCEPTANCE_EVIDENCE" == "false" ]]
    [[ "$ACCEPTANCE_EVIDENCE_REASON" == "custom-request-count" ]]
  ) || {
    printf 'custom all-suite request count was treated as acceptance evidence\n' >&2
    return 1
  }
}

test_numeric_options_reject_overflow() {
  local -r overflow="18446744073709551616"
  local option=""

  for option in --requests --repeat --seed --command-timeout --readiness-timeout; do
    if (
      SCENARIO=all
      parse_args "$option" "$overflow"
    ) >/dev/null 2>&1; then
      printf 'accepted overflowing numeric option %s\n' "$option" >&2
      return 1
    fi
  done

  (
    SCENARIO=all
    parse_args --repeat 0002 --seed 0000
    [[ "$REPEAT_COUNT" == "2" && "$SCENARIO_SEED" == "0" ]]
  ) || {
    printf 'bounded numeric options were not normalized to decimal\n' >&2
    return 1
  }
}

test_transport_configuration_parser_is_exact() {
  local expected=""
  local configuration=""
  local selected=""

  while IFS='|' read -r expected configuration selected; do
    [[ "$(selected_transport_from_configuration "$configuration" "$expected")" == "$selected" ]] || {
      printf 'rejected valid %s transport configuration: %s\n' "$expected" "$configuration" >&2
      return 1
    }
  done <<'EOF'
getsockopt|version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0|getsockopt
auto|version=2,status=1,requested=0,selected=1,attempted=1,getsockopt=1,unix=0|getsockopt
unix|version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=1|unix
auto|version=2,status=1,requested=0,selected=2,attempted=3,getsockopt=4,unix=1|unix
EOF

  while IFS='|' read -r expected configuration; do
    if selected_transport_from_configuration "$configuration" "$expected" >/dev/null; then
      printf 'accepted invalid %s transport configuration: %s\n' "$expected" "$configuration" >&2
      return 1
    fi
  done <<'EOF'
auto|version=1,status=1,requested=0,selected=255,attempted=0,getsockopt=0,unix=0
auto|version=2,status=6,requested=0,selected=255,attempted=0,getsockopt=0,unix=0
auto|version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0
auto|version=2,status=1,requested=0,selected=2,attempted=3,getsockopt=1,unix=1
getsockopt|version=2,status=1,requested=1,selected=2,attempted=2,getsockopt=0,unix=1
unix|version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=01
unix|version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=1,extra=0
unix|status=1,version=2,requested=2,selected=2,attempted=2,getsockopt=0,unix=1
EOF
}

test_selected_transport_uses_java_diagnostics() {
  local -r result_dir="$TEST_TMP_DIR/java-transport-configuration"
  local -r curl_attempts="$result_dir/curl-attempts"
  local -r successful_configuration="version=2,status=1,requested=0,selected=2,attempted=3,getsockopt=4,unix=1"
  local -r replacement_configuration="version=2,status=1,requested=0,selected=1,attempted=1,getsockopt=1,unix=0"

  mkdir -p -- "$result_dir/certs"
  (
    local publication_status=0

    RESULT_DIR="$result_dir"
    CERT_DIR="$result_dir/certs"
    TRANSPORT=auto
    SELECTED_TRANSPORT=""
    CURL_MODE=success
    INSTALL_MODE=success
    TRANSPORT_CONFIGURATION_RESPONSE="$successful_configuration"
    curl() {
      local -i attempt_count=0

      [[ "$*" == \
        "--fail --silent --show-error --max-time 5 --max-filesize $TRANSPORT_CONFIGURATION_MAX_BYTES --cacert $CERT_DIR/ca.crt https://127.0.0.1:18443/obi-transport-configuration --output $RESULT_DIR/java-transport-configuration.txt" ]] ||
        return 64
      if [[ "$CURL_MODE" == "transient" ]]; then
        printf 'attempt\n' >>"$curl_attempts"
        attempt_count="$(wc -l <"$curl_attempts")"
        if ((attempt_count == 1)); then
          [[ -z "$SELECTED_TRANSPORT" &&
            ! -e "$RESULT_DIR/java-transport-configuration.txt" ]] || return 65
          return 7
        fi
      fi
      case "$CURL_MODE" in
        nul)
          printf '%s\n\0' "$TRANSPORT_CONFIGURATION_RESPONSE" \
            >"$RESULT_DIR/java-transport-configuration.txt"
          ;;
        oversized)
          printf '%0300d\n' 0 >"$RESULT_DIR/java-transport-configuration.txt"
          return 63
          ;;
        oversized-raw)
          printf '%0300d\n' 0 >"$RESULT_DIR/java-transport-configuration.txt"
          ;;
        crlf)
          printf '%s\r\n' "$TRANSPORT_CONFIGURATION_RESPONSE" \
            >"$RESULT_DIR/java-transport-configuration.txt"
          ;;
        no-final-newline)
          printf '%s' "$TRANSPORT_CONFIGURATION_RESPONSE" \
            >"$RESULT_DIR/java-transport-configuration.txt"
          ;;
        trailing-nonblank)
          printf '%s\nunexpected\n' "$TRANSPORT_CONFIGURATION_RESPONSE" \
            >"$RESULT_DIR/java-transport-configuration.txt"
          ;;
        trailing-blank)
          printf '%s\n\n' "$TRANSPORT_CONFIGURATION_RESPONSE" \
            >"$RESULT_DIR/java-transport-configuration.txt"
          ;;
        *)
          printf '%s\n' "$TRANSPORT_CONFIGURATION_RESPONSE" \
            >"$RESULT_DIR/java-transport-configuration.txt"
          ;;
      esac
    }
    install() {
      if [[ "$INSTALL_MODE" == "failure" ]]; then
        : >"${@: -1}"
        return 29
      fi
      command install "$@"
    }

    assert_selected_transport auto
    [[ "$SELECTED_TRANSPORT" == "unix" ]]
    [[ "$(<"$RESULT_DIR/java-transport-configuration.txt")" == "$successful_configuration" ]]
    [[ "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == \
      "$successful_configuration" ]]

    TRANSPORT_CONFIGURATION_RESPONSE="$replacement_configuration"
    INSTALL_MODE=failure
    if assert_selected_transport auto >/dev/null 2>&1; then
      printf 'readiness ignored retained transport publication failure\n' >&2
      return 1
    else
      publication_status=$?
    fi
    [[ "$publication_status" == "29" ]] || return 1
    [[ -z "$SELECTED_TRANSPORT" &&
      "$(<"$RESULT_DIR/java-transport-configuration.txt")" == \
        "$replacement_configuration" &&
      "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == \
        "$successful_configuration" ]] || return 1
    if compgen -G \
      "$RESULT_DIR/.java-selected-transport-configuration.*" >/dev/null; then
      printf 'readiness left a failed retained transport temporary file\n' >&2
      return 1
    fi
    INSTALL_MODE=success
    TRANSPORT_CONFIGURATION_RESPONSE="$successful_configuration"

    CURL_MODE=transient
    rm -f -- "$curl_attempts"
    if assert_selected_transport auto >/dev/null 2>&1; then
      printf 'readiness retried a failed transport request with unaccounted side effects\n' >&2
      return 1
    fi
    [[ -z "$SELECTED_TRANSPORT" &&
      ! -e "$RESULT_DIR/java-transport-configuration.txt" ]]
    [[ "$(wc -l <"$curl_attempts")" == "1" ]]
    [[ "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == \
      "$successful_configuration" ]]

    assert_selected_transport auto
    [[ "$SELECTED_TRANSPORT" == "unix" ]]
    [[ "$(wc -l <"$curl_attempts")" == "2" ]]

    CURL_MODE=success
    TRANSPORT_CONFIGURATION_RESPONSE="version=2,status=12,requested=0,selected=255,attempted=3,getsockopt=4,unix=12"
    if assert_selected_transport auto >/dev/null 2>&1; then
      printf 'readiness accepted a failed Java transport configuration\n' >&2
      return 1
    fi
    [[ -z "$SELECTED_TRANSPORT" ]]
    [[ "$(<"$RESULT_DIR/java-transport-configuration.txt")" == \
      "version=2,status=12,requested=0,selected=255,attempted=3,getsockopt=4,unix=12" ]]
    [[ "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == \
      "$successful_configuration" ]]

    TRANSPORT_CONFIGURATION_RESPONSE="application log OBI remote-parent transport configuration version=2,status=1,requested=0,selected=1,attempted=1,getsockopt=1,unix=0"
    if assert_selected_transport auto >/dev/null 2>&1; then
      printf 'readiness accepted an application-forged transport configuration\n' >&2
      return 1
    fi
    [[ -z "$SELECTED_TRANSPORT" && ! -e "$RESULT_DIR/java-transport-configuration.txt" ]]

    TRANSPORT_CONFIGURATION_RESPONSE="$successful_configuration"
    for CURL_MODE in \
      nul oversized oversized-raw crlf no-final-newline trailing-blank trailing-nonblank; do
      if assert_selected_transport auto >/dev/null 2>&1; then
        printf 'readiness accepted a %s Java transport response\n' "$CURL_MODE" >&2
        return 1
      fi
      [[ -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" ]] || return 1
    done
    [[ "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == \
      "$successful_configuration" ]]
  ) || {
    printf 'readiness did not use the direct Java transport configuration\n' >&2
    return 1
  }
}

test_transport_configuration_file_size_boundary_is_exact() {
  local -r configuration_file="$TEST_TMP_DIR/transport-configuration-size.txt"

  (
    transport_configuration_values() {
      return 0
    }

    printf '%0254d\n' 0 >"$configuration_file"
    transport_configuration_from_file "$configuration_file" >/dev/null
    [[ "$(wc -c <"$configuration_file")" == "255" ]]

    printf '%0255d\n' 0 >"$configuration_file"
    transport_configuration_from_file "$configuration_file" >/dev/null
    [[ "$(wc -c <"$configuration_file")" == "$TRANSPORT_CONFIGURATION_MAX_BYTES" ]]

    printf '%0256d\n' 0 >"$configuration_file"
    if transport_configuration_from_file "$configuration_file" >/dev/null 2>&1; then
      printf 'transport configuration accepted more than %d bytes\n' \
        "$TRANSPORT_CONFIGURATION_MAX_BYTES" >&2
      return 1
    fi
    [[ "$(wc -c <"$configuration_file")" == "257" ]]
  ) || {
    printf 'transport configuration byte boundary was not exact\n' >&2
    return 1
  }
}

test_control_modes_are_distinct() {
  (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport disabled --scenario disabled
    [[ "$TRANSPORT" == "disabled" && "$SCENARIO" == "disabled" ]]
  ) || {
    printf 'rejected the bridge-disabled control\n' >&2
    return 1
  }
  (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport disabled --scenario uninstrumented
    [[ "$TRANSPORT" == "disabled" && "$SCENARIO" == "uninstrumented" ]]
  ) || {
    printf 'rejected the uninstrumented control\n' >&2
    return 1
  }
  (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport disabled --scenario benchmark-disabled
    [[ "$TRANSPORT" == "disabled" && "$SCENARIO" == "benchmark-disabled" ]]
  ) || {
    printf 'rejected the comparable bridge-disabled benchmark control\n' >&2
    return 1
  }
  (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport disabled --scenario benchmark-uninstrumented
    [[ "$TRANSPORT" == "disabled" && "$SCENARIO" == "benchmark-uninstrumented" ]]
  ) || {
    printf 'rejected the comparable uninstrumented benchmark control\n' >&2
    return 1
  }
  (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport getsockopt --scenario delayed-otlp-suppression
    [[ "$TRANSPORT" == "getsockopt" && "$SCENARIO" == "delayed-otlp-suppression" ]]
  ) || {
    printf 'rejected the delayed OTLP suppression control\n' >&2
    return 1
  }
  (
    SCENARIO="delayed-otlp-suppression"
    unset OTEL_BSP_SCHEDULE_DELAY_VALUE
    export_compose_environment
    [[ "$OTEL_BSP_SCHEDULE_DELAY_VALUE" == \
      "$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS" &&
      "$OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE" == \
        "$DELAYED_OTLP_JAVA_RETRY_DISABLED" ]]
  ) || {
    printf 'delayed OTLP suppression did not configure bounded Java export\n' >&2
    return 1
  }
  if (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport getsockopt --scenario uninstrumented
  ) >/dev/null 2>&1; then
    printf 'accepted an uninstrumented control with an enabled transport\n' >&2
    return 1
  fi
  if (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport getsockopt --scenario benchmark-uninstrumented
  ) >/dev/null 2>&1; then
    printf 'accepted an uninstrumented benchmark control with an enabled transport\n' >&2
    return 1
  fi
}

test_benchmark_controls_use_shared_concurrency_workload() {
  local -r disabled_arguments="$TEST_TMP_DIR/benchmark-disabled-arguments"
  local -r uninstrumented_arguments="$TEST_TMP_DIR/benchmark-uninstrumented-arguments"

  (
    SCENARIO="benchmark-disabled"
    run_scenario() {
      printf '%s\n' "$*" >"$disabled_arguments"
    }
    execute_requested_scenarios
  ) || {
    printf 'benchmark-disabled control could not dispatch its workload\n' >&2
    return 1
  }
  [[ "$(<"$disabled_arguments")" == \
    "concurrency true full none normal disabled" ]] || {
    printf 'benchmark-disabled control did not retain the disabled concurrency assertion\n' >&2
    return 1
  }

  (
    SCENARIO="benchmark-uninstrumented"
    run_scenario() {
      printf '%s\n' "$*" >"$uninstrumented_arguments"
    }
    execute_requested_scenarios
  ) || {
    printf 'benchmark-uninstrumented control could not dispatch its workload\n' >&2
    return 1
  }
  [[ "$(<"$uninstrumented_arguments")" == \
    "concurrency true full none normal uninstrumented" ]] || {
    printf 'benchmark-uninstrumented control did not retain the uninstrumented concurrency assertion\n' >&2
    return 1
  }
}

test_benchmark_controls_configure_their_runtime() {
  (
    SCENARIO="benchmark-disabled"
    export_compose_environment
    [[ "$EXTENSION_ENABLED" == "true" &&
      "$JAVA_TOOL_OPTIONS_VALUE" == "-javaagent:/otel/official-javaagent.jar" &&
      "$OTEL_JAVAAGENT_EXTENSIONS_VALUE" == "/otel/obi-otel-extension.jar" &&
      "$OTEL_PROPAGATORS_VALUE" == "obi,tracecontext,baggage" ]]
  ) || {
    printf 'benchmark-disabled control did not retain the instrumented runtime\n' >&2
    return 1
  }
  (
    SCENARIO="benchmark-uninstrumented"
    export_compose_environment
    [[ "$EXTENSION_ENABLED" == "false" &&
      -z "$JAVA_TOOL_OPTIONS_VALUE" &&
      -z "$OTEL_JAVAAGENT_EXTENSIONS_VALUE" &&
      "$OTEL_PROPAGATORS_VALUE" == "tracecontext,baggage" ]] &&
      uses_uninstrumented_runtime
  ) || {
    printf 'benchmark-uninstrumented control did not omit instrumentation\n' >&2
    return 1
  }
}

test_benchmark_startup_selects_runtime_contract() {
  local -r disabled_dir="$TEST_TMP_DIR/benchmark-disabled-startup"
  local -r uninstrumented_dir="$TEST_TMP_DIR/benchmark-uninstrumented-startup"

  mkdir -p -- "$disabled_dir" "$uninstrumented_dir"
  (
    RESULT_DIR="$disabled_dir"
    SCENARIO="benchmark-disabled"
    TRANSPORT=disabled
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() { :; }
    invalidate_project_transport_evidence() { :; }
    run_bounded() { :; }
    run_logged_bounded() { printf '%s\n' "$*" >"$disabled_dir/compose"; }
    date() { printf 'startup-cursor\n'; }
    wait_for_http() { :; }
    wait_for_log() { :; }
    wait_for_apache_instrumentation() { :; }
    assert_apache_denies_java_diagnostics() { :; }
    assert_runtime_contract() { printf '%s\n' "$1" >"$disabled_dir/runtime"; }

    start_stack
  ) || {
    printf 'benchmark-disabled startup failed\n' >&2
    return 1
  }
  [[ "$(<"$disabled_dir/compose")" == *"trace-receiver java-backend coalesced-source apache-proxy obi"* &&
    "$(<"$disabled_dir/runtime")" == "disabled" ]] || {
    printf 'benchmark-disabled startup did not retain the disabled runtime\n' >&2
    return 1
  }

  (
    RESULT_DIR="$uninstrumented_dir"
    SCENARIO="benchmark-uninstrumented"
    TRANSPORT=disabled
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() { :; }
    invalidate_project_transport_evidence() { :; }
    run_bounded() { :; }
    run_logged_bounded() { printf '%s\n' "$*" >"$uninstrumented_dir/compose"; }
    date() { printf 'startup-cursor\n'; }
    wait_for_http() { :; }
    wait_for_log() { return 1; }
    wait_for_apache_instrumentation() { return 1; }
    assert_apache_denies_java_diagnostics() { :; }
    assert_runtime_contract() { printf '%s\n' "$1" >"$uninstrumented_dir/runtime"; }

    start_stack
  ) || {
    printf 'benchmark-uninstrumented startup failed\n' >&2
    return 1
  }
  [[ "$(<"$uninstrumented_dir/compose")" == *"trace-receiver java-backend coalesced-source apache-proxy"* &&
    "$(<"$uninstrumented_dir/compose")" != *" apache-proxy obi"* &&
    "$(<"$uninstrumented_dir/runtime")" == "uninstrumented" ]] || {
    printf 'benchmark-uninstrumented startup did not omit OBI\n' >&2
    return 1
  }
}

test_benchmark_control_passes_assertion_mode_to_tracecheck() {
  local assertion_mode=""
  local invocation=""

  for assertion_mode in disabled uninstrumented; do
    invocation="$TEST_TMP_DIR/benchmark-tracecheck-$assertion_mode-invocation"
    (
      RESULT_DIR="$TEST_TMP_DIR/benchmark-tracecheck-$assertion_mode"
      mkdir -- "$RESULT_DIR"
      COMPOSE=(docker compose)
      REPEAT_COUNT=1
      REQUEST_COUNT=16
      BRIDGE_RUNNING=false
      SELECTED_TRANSPORT=""
      scenario_bridge_missing_count() { printf '0\n'; }
      scenario_java_missing_count() { printf '0\n'; }
      scenario_bridge_take_count() { printf '16\n'; }
      flush_bridge_metric_boundary() { :; }
      capture_java_diagnostics() { :; }
      capture_phase_evidence() { :; }
      write_metrics_delta() { :; }
      run_bounded() {
        printf '%q ' "$@" >"$invocation"
        print_concurrency_result_fixture "$REQUEST_COUNT" "$assertion_mode"
      }

      run_scenario concurrency true full none normal "$assertion_mode"
    ) || {
      printf 'benchmark %s control could not run its tracecheck assertion\n' \
        "$assertion_mode" >&2
      return 1
    }
    grep -Fq -- '--scenario concurrency' "$invocation" || return 1
    grep -Fq -- '--requests 16' "$invocation" || return 1
    grep -Fq -- "--assertion-mode $assertion_mode" "$invocation" || return 1
  done
}

test_benchmark_controls_are_bounded() {
  if (parse_args --scenario concurrency --requests 1001) >/dev/null 2>&1; then
    printf 'accepted an unbounded request count\n' >&2
    return 1
  fi
  if (parse_args --scenario concurrency --repeat 11) >/dev/null 2>&1; then
    printf 'accepted an unbounded repetition count\n' >&2
    return 1
  fi
  if (parse_args --scenario concurrency --seed invalid) >/dev/null 2>&1; then
    printf 'accepted a non-numeric scenario seed\n' >&2
    return 1
  fi
  if (parse_args --scenario concurrency --requests 1) >/dev/null 2>&1; then
    printf 'accepted a concurrency fixture with fewer than two participants\n' >&2
    return 1
  fi
  if (parse_args --scenario concurrency --requests 65) >/dev/null 2>&1; then
    printf 'accepted a concurrency fixture with more than 64 participants\n' >&2
    return 1
  fi
  for request_count in 2 64; do
    (
      SCENARIO=all
      REQUEST_COUNT=0
      parse_args --scenario concurrency --requests "$request_count"
      [[ "$REQUEST_COUNT" == "$request_count" ]]
    ) || {
      printf 'rejected bounded concurrency participant count: %s\n' "$request_count" >&2
      return 1
    }
  done
  if (parse_args --scenario keepalive --requests 2) >/dev/null 2>&1; then
    printf 'accepted keepalive without two pre-terminal requests\n' >&2
    return 1
  fi
  if (parse_args --scenario pipelining --requests 2) >/dev/null 2>&1; then
    printf 'accepted a pipeline without two pre-terminal requests\n' >&2
    return 1
  fi
  if (parse_args --scenario fd-port-reuse --requests 1) >/dev/null 2>&1; then
    printf 'accepted a reuse scenario with fewer than two connections\n' >&2
    return 1
  fi
}

test_all_suite_includes_every_scenario() {
  local -r actual="$TEST_TMP_DIR/all-scenarios.txt"
  local -r expected=$'basic\nbasic\nsecurity\nkeepalive\npipelining\nconcurrency\nconnection-churn\nfd-port-reuse\nslow-body\ntls-boundary\ncoalesced-bridge\ntimeout-retry\npressure\nhandoff\nvirtual-thread\nnetty\nnetty-server\ndispatch\nw3c\nw3c-match\nobi-flags\nprimary-w3c-stale\nbasic\nprimary-generation-mismatch\nbasic\nprimary-w3c-fault\nprimary-w3c-fault\nprimary-w3c-fault\nprimary-w3c-fault\nbasic\npermanent-absence\nbasic\nfail-open\nw3c-only\nrestart\nrestart-fault\nhelper-attach-failure\ndisabled\nw3c-only\nw3c-only\nuninstrumented'

  (
    SCENARIO=all
    SELECTED_TRANSPORT=getsockopt
    run_scenario() {
      printf '%s\n' "$1" >>"$actual"
    }
    run_late_attach_control() {
      run_scenario fail-open
      run_scenario w3c-only
      run_scenario restart
    }
    run_w3c_match_control() {
      run_scenario w3c-match
    }
    run_primary_w3c_stale_control() {
      run_scenario primary-w3c-stale
      run_scenario basic
    }
    run_primary_generation_mismatch_control() {
      run_scenario primary-generation-mismatch
      run_scenario basic
    }
    run_primary_w3c_fault_control() {
      run_scenario primary-w3c-fault
      run_scenario primary-w3c-fault
      run_scenario primary-w3c-fault
      run_scenario primary-w3c-fault
      run_scenario basic
    }
    run_permanent_absence_control() {
      run_scenario permanent-absence
      run_scenario basic
    }
    record_unsupported_scenario() {
      return 0
    }
    run_primary_security_control() {
      run_scenario security
    }
    run_delayed_otlp_suppression_control() {
      run_scenario basic
    }
    run_disabled_control() {
      run_scenario disabled
    }
    run_restart_during_traffic_control() {
      run_scenario restart-fault
    }
    run_helper_attach_failure_control() {
      run_scenario helper-attach-failure
    }
    run_extension_controls() {
      run_scenario w3c-only
      run_scenario w3c-only
    }
    run_uninstrumented_control() {
      run_scenario uninstrumented
    }
    execute_requested_scenarios
  )

  [[ "$(<"$actual")" == "$expected" ]] || {
    printf 'all suite scenario coverage changed:\n%s\n' "$(<"$actual")" >&2
    return 1
  }
}

test_unix_all_suite_includes_fault_control() {
  local -r actual="$TEST_TMP_DIR/unix-all-scenarios.txt"

  (
    SCENARIO=all
    TRANSPORT=unix
    SELECTED_TRANSPORT=unix
    run_scenario() {
      printf '%s\n' "$1" >>"$actual"
    }
    run_w3c_match_control() {
      run_scenario w3c-match
    }
    record_unsupported_scenario() {
      return 0
    }
    run_unix_w3c_stale_control() {
      run_scenario unix-w3c-stale
      run_scenario basic
    }
    run_w3c_fault_control() {
      run_scenario w3c-fault
    }
    run_permanent_absence_control() {
      run_scenario permanent-absence
      run_scenario basic
    }
    run_unix_security_control() {
      run_scenario security
    }
    run_delayed_otlp_suppression_control() {
      run_scenario basic
    }
    run_late_attach_control() {
      run_scenario fail-open
      run_scenario w3c-only
      run_scenario restart
    }
    run_disabled_control() {
      run_scenario disabled
    }
    run_restart_during_traffic_control() {
      run_scenario restart-fault
    }
    run_helper_attach_failure_control() {
      run_scenario helper-attach-failure
    }
    run_extension_controls() {
      run_scenario w3c-only
      run_scenario w3c-only
    }
    run_uninstrumented_control() {
      run_scenario uninstrumented
    }
    execute_requested_scenarios
  )

  [[ "$(<"$actual")" == *$'basic\nbasic\nsecurity\nkeepalive'* && \
    "$(<"$actual")" == *$'obi-flags\nunix-w3c-stale\nbasic\nw3c-fault\npermanent-absence\nbasic\nfail-open'* &&
    "$(<"$actual")" == *$'restart\nrestart-fault\nhelper-attach-failure'* ]] || {
    printf 'Unix all suite omitted the security or bounded W3C fault control\n' >&2
    return 1
  }
}

test_run_demo_preserves_strict_scenario_execution() {
  local -r first_observed="$TEST_TMP_DIR/run-demo-first-scenario"
  local -r nested_observed="$TEST_TMP_DIR/run-demo-nested-scenario"
  local demo_status=0

  set +e
  (
    set -Eeuo pipefail
    install_traps() { :; }
    parse_args() {
      CLEANUP_ONLY=false
      SCENARIO=all
      TRANSPORT=getsockopt
    }
    check_dependencies() { :; }
    enter_project_guard() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    prepare_directories() { :; }
    capture_source_state() { :; }
    prepare_certificates() { :; }
    prepare_official_agent() { :; }
    prepare_bridge_artifacts() { :; }
    export_compose_environment() { :; }
    capture_environment() { :; }
    start_stack() { :; }
    capture_runtime_evidence() { :; }
    run_scenario() {
      printf 'scenario:%s:%s\n' "$1" "$RUN_STATUS" >>"$first_observed"
      [[ "$1" != "basic" ]] || return 17
    }
    run_security_control() {
      printf 'continued-security\n' >>"$first_observed"
    }

    RUN_STATUS=failed
    run_demo
    printf 'continued-main:%s\n' "$RUN_STATUS" >>"$first_observed"
  )
  demo_status=$?
  set -e
  [[ "$demo_status" == "17" &&
    "$(<"$first_observed")" == "scenario:basic:failed" ]] || {
    printf 'run_demo continued after the first scenario failed\n' >&2
    return 1
  }

  set +e
  (
    set -Eeuo pipefail
    install_traps() { :; }
    parse_args() {
      CLEANUP_ONLY=false
      SCENARIO=all
      TRANSPORT=getsockopt
    }
    check_dependencies() { :; }
    enter_project_guard() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    prepare_directories() { :; }
    capture_source_state() { :; }
    prepare_certificates() { :; }
    prepare_official_agent() { :; }
    prepare_bridge_artifacts() { :; }
    export_compose_environment() { :; }
    capture_environment() { :; }
    start_stack() { :; }
    capture_runtime_evidence() { :; }
    run_scenario() {
      printf 'scenario:%s\n' "$1" >>"$nested_observed"
    }
    run_delayed_otlp_suppression_control() { :; }
    injected_security_failure() {
      return 23
    }
    run_primary_security_control() {
      printf 'security-entered\n' >>"$nested_observed"
      injected_security_failure
      printf 'security-continued\n' >>"$nested_observed"
    }

    RUN_STATUS=failed
    SELECTED_TRANSPORT=getsockopt
    run_demo
    printf 'continued-main:%s\n' "$RUN_STATUS" >>"$nested_observed"
  )
  demo_status=$?
  set -e
  [[ "$demo_status" == "23" &&
    "$(<"$nested_observed")" == $'scenario:basic\nsecurity-entered' ]] || {
    printf 'run_demo suppressed a nested scenario failure\n' >&2
    return 1
  }
}

test_delayed_otlp_run_demo_defers_runtime_evidence() {
  local -r observed="$TEST_TMP_DIR/delayed-otlp-run-demo-order"

  (
    set -Eeuo pipefail
    install_traps() { :; }
    parse_args() {
      CLEANUP_ONLY=false
      SCENARIO=delayed-otlp-suppression
      TRANSPORT=getsockopt
    }
    check_dependencies() { :; }
    enter_project_guard() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    prepare_directories() { :; }
    capture_source_state() { :; }
    prepare_certificates() { :; }
    prepare_official_agent() { :; }
    prepare_bridge_artifacts() { :; }
    export_compose_environment() { :; }
    capture_environment() { :; }
    start_stack() {
      printf 'stack\n' >>"$observed"
    }
    execute_requested_scenarios() {
      printf 'control\n' >>"$observed"
    }
    capture_runtime_evidence() {
      printf 'runtime-evidence\n' >>"$observed"
    }

    RUN_STATUS=failed
    run_demo
    [[ "$RUN_STATUS" == "passed" ]]
  ) || {
    printf 'delayed OTLP run demo did not complete in the expected order\n' >&2
    return 1
  }

  [[ "$(<"$observed")" == $'stack\ncontrol\nruntime-evidence' ]] || {
    printf 'delayed OTLP runtime evidence ran before the controlled request\n' >&2
    return 1
  }
}

test_helper_attach_failure_dispatch_and_seed_are_exact() {
  local -r actual="$TEST_TMP_DIR/helper-attach-dispatch.txt"

  (
    SCENARIO=helper-attach-failure
    run_helper_attach_failure_control() {
      printf 'helper-attach-failure\n' >"$actual"
    }
    run_scenario() {
      printf 'unexpected:%s\n' "$1" >"$actual"
      return 1
    }
    execute_requested_scenarios
  )
  [[ "$(<"$actual")" == "helper-attach-failure" ]] || {
    printf 'standalone helper attach failure scenario used the wrong dispatch\n' >&2
    return 1
  }
  [[ "$(next_scenario_seed 41)" == "42" &&
    "$(next_scenario_seed "$MAX_SHELL_INTEGER")" == "0" ]] || {
    printf 'helper attach failure alternate seed is not bounded and distinct\n' >&2
    return 1
  }
  if next_scenario_seed invalid >/dev/null 2>&1; then
    printf 'helper attach failure seed accepted malformed input\n' >&2
    return 1
  fi
  (
    parse_args --transport getsockopt --scenario helper-attach-failure
  ) || {
    printf 'helper attach failure scenario rejected an enabled transport\n' >&2
    return 1
  }
  if (
    parse_args --transport disabled --scenario helper-attach-failure
  ) >/dev/null 2>&1; then
    printf 'helper attach failure scenario accepted the disabled transport\n' >&2
    return 1
  fi
}

test_w3c_fault_requires_forced_unix() {
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    parse_args --scenario w3c-fault
  ) >/dev/null 2>&1; then
    printf 'accepted W3C fault control without forced Unix transport\n' >&2
    return 1
  fi
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    parse_args --transport unix --scenario w3c-fault --requests 3
  ) >/dev/null 2>&1; then
    printf 'accepted an invalid W3C fault request count\n' >&2
    return 1
  fi
}

test_primary_w3c_stale_requires_forced_primary() {
  (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport getsockopt --scenario primary-w3c-stale --requests 1
    [[ "$TRANSPORT" == "getsockopt" && "$SCENARIO" == "primary-w3c-stale" && \
      "$REQUEST_COUNT" == "1" ]]
  ) || {
    printf 'rejected the forced-primary stale control\n' >&2
    return 1
  }
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport unix --scenario primary-w3c-stale
  ) >/dev/null 2>&1; then
    printf 'accepted the primary stale control without forced getsockopt\n' >&2
    return 1
  fi
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport getsockopt --scenario primary-w3c-stale --requests 2
  ) >/dev/null 2>&1; then
    printf 'accepted the primary stale control with multiple requests\n' >&2
    return 1
  fi
}

test_primary_generation_mismatch_requires_one_forced_primary() {
  (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args \
      --transport getsockopt --scenario primary-generation-mismatch --requests 1
    [[ "$TRANSPORT" == "getsockopt" && \
      "$SCENARIO" == "primary-generation-mismatch" && "$REQUEST_COUNT" == "1" ]]
  ) || {
    printf 'rejected the forced-primary generation mismatch control\n' >&2
    return 1
  }
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport unix --scenario primary-generation-mismatch
  ) >/dev/null 2>&1; then
    printf 'accepted generation mismatch without forced getsockopt\n' >&2
    return 1
  fi
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args \
      --transport getsockopt --scenario primary-generation-mismatch --requests 2
  ) >/dev/null 2>&1; then
    printf 'accepted generation mismatch with multiple requests\n' >&2
    return 1
  fi
}

test_unix_w3c_stale_requires_forced_unix() {
  (
    TRANSPORT=unix
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport unix --scenario unix-w3c-stale --requests 1
    [[ "$TRANSPORT" == "unix" && "$SCENARIO" == "unix-w3c-stale" && \
      "$REQUEST_COUNT" == "1" ]]
  ) || {
    printf 'rejected the forced-Unix stale control\n' >&2
    return 1
  }
  if (
    TRANSPORT=unix
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport getsockopt --scenario unix-w3c-stale
  ) >/dev/null 2>&1; then
    printf 'accepted the Unix stale control without forced Unix transport\n' >&2
    return 1
  fi
  if (
    TRANSPORT=unix
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport unix --scenario unix-w3c-stale --requests 2
  ) >/dev/null 2>&1; then
    printf 'accepted the Unix stale control with multiple requests\n' >&2
    return 1
  fi
}

test_primary_w3c_fault_requires_forced_primary() {
  (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport getsockopt --scenario primary-w3c-fault --requests 1
    [[ "$TRANSPORT" == "getsockopt" && "$SCENARIO" == "primary-w3c-fault" && \
      "$REQUEST_COUNT" == "1" ]]
  ) || {
    printf 'rejected the forced-primary malformed-response control\n' >&2
    return 1
  }
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport unix --scenario primary-w3c-fault
  ) >/dev/null 2>&1; then
    printf 'accepted the primary malformed-response control without forced getsockopt\n' >&2
    return 1
  fi
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --transport getsockopt --scenario primary-w3c-fault --requests 2
  ) >/dev/null 2>&1; then
    printf 'accepted the primary malformed-response control with multiple requests\n' >&2
    return 1
  fi
}

test_primary_w3c_fault_modes_are_exact() {
  [[ "$(primary_w3c_fault_expected_java_status version-mismatch)" == version_mismatch ]]
  [[ "$(primary_w3c_fault_expected_java_status bad-size)" == malformed ]]
  [[ "$(primary_w3c_fault_expected_java_status zero-trace-id)" == malformed ]]
  [[ "$(primary_w3c_fault_expected_java_status zero-span-id)" == malformed ]]
  if primary_w3c_fault_expected_java_status alternating >/dev/null 2>&1; then
    printf 'accepted a Unix-only W3C fault mode for the primary fault shim\n' >&2
    return 1
  fi
}

test_primary_w3c_fault_control_scripts_publish_and_consume_exactly() {
  local -r result_dir="$TEST_TMP_DIR/primary-fault-control-scripts"
  local -r private_directory="$result_dir/fault"
  local -r control_file="$private_directory/java-remote-parent.mode"
  local -r fake_bin="$result_dir/bin"
  local -r arm_evidence="$result_dir/armed.txt"
  local -r bad_size_arm_evidence="$result_dir/bad-size-armed.txt"
  local -r consumption_evidence="$result_dir/consumed.txt"
  local -r bad_size_consumption_evidence="$result_dir/bad-size-consumed.txt"
  local -r expected_arm=$'phase=armed\nmode=version-mismatch\nmetadata=0:0:600:1:regular file\nsize=17'
  local -r expected_bad_size_arm=$'phase=armed\nmode=bad-size\nmetadata=0:0:600:1:regular file\nsize=9'
  local -r expected_consumption=$'phase=consumed\nmetadata=0:0:600:1:regular empty file\nsize=0'

  mkdir -p -- "$private_directory" "$fake_bin"
  chmod 0700 -- "$private_directory"
  cat >"$fake_bin/id" <<'EOF'
#!/usr/bin/env bash
printf '0\n'
EOF
  cat >"$fake_bin/stat" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

case "$2" in
  '%u:%g:%a:%F') printf '0:0:700:directory\n' ;;
  '%u:%g:%a:%h') printf '0:0:600:1\n' ;;
  '%u:%g:%a:%h:%F')
    if [[ -s "$3" ]]; then
      printf '0:0:600:1:regular file\n'
    else
      printf '0:0:600:1:regular empty file\n'
    fi
    ;;
  '%s') wc -c <"$3" ;;
  *) exit 64 ;;
esac
EOF
  chmod 0755 -- "$fake_bin/id" "$fake_bin/stat"

  (
    PRIMARY_FAULT_STACK_ACTIVE=true
    PRIMARY_FAULT_COMPOSE=(test-compose)
    run_bounded() {
      local -a bounded_command=("$@")
      local -a shell_command=()
      local script_index=-1
      local index=0

      for index in "${!bounded_command[@]}"; do
        if [[ "${bounded_command[$index]}" == -ec ]]; then
          script_index="$index"
          break
        fi
      done
      ((script_index >= 0)) || return 1

      shell_command=(
        /bin/sh -ec "${bounded_command[$((script_index + 1))]}" sh
        "$private_directory" "$control_file"
      )
      case "$(( ${#bounded_command[@]} - script_index ))" in
        5)
          ;;
        6)
          case "${bounded_command[$((script_index + 5))]}" in
            version-mismatch|bad-size)
              shell_command+=("${bounded_command[$((script_index + 5))]}")
              ;;
            *) return 1 ;;
          esac
          ;;
        *) return 1 ;;
      esac

      PATH="$fake_bin:$PATH" "${shell_command[@]}"
    }

    arm_primary_w3c_fault_control version-mismatch "$arm_evidence"
    [[ "$(<"$arm_evidence")" == "$expected_arm" && \
      "$(<"$control_file")" == version-mismatch ]]

    : >"$control_file"
    consume_primary_w3c_fault_control "$consumption_evidence"
    [[ "$(<"$consumption_evidence")" == "$expected_consumption" && \
      ! -e "$control_file" && ! -L "$control_file" ]]

    arm_primary_w3c_fault_control bad-size "$bad_size_arm_evidence"
    [[ "$(<"$bad_size_arm_evidence")" == "$expected_bad_size_arm" && \
      "$(<"$control_file")" == bad-size ]]

    : >"$control_file"
    consume_primary_w3c_fault_control "$bad_size_consumption_evidence"
    [[ "$(<"$bad_size_consumption_evidence")" == "$expected_consumption" && \
      ! -e "$control_file" && ! -L "$control_file" ]]
  ) || {
    printf 'primary fault control scripts did not publish and consume exact evidence\n' >&2
    return 1
  }
}

test_primary_w3c_stale_control_restores_the_normal_ttls() {
  local -r observed="$TEST_TMP_DIR/primary-w3c-stale-control.calls"

  (
    TRANSPORT=getsockopt
    SELECTED_TRANSPORT=getsockopt
    REMOTE_PARENT_TTL=30s
    REMOTE_PARENT_RETRIEVAL_TTL=0s
    SCENARIO_VARIANT=existing-variant
    : >"$observed"
    recreate_instrumented_stack() {
      printf 'recreate:%s:%s:retention_ttl=%s:retrieval_ttl=%s\n' \
        "$2" "$3" "$REMOTE_PARENT_TTL" "$REMOTE_PARENT_RETRIEVAL_TTL" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:%s:retention_ttl=%s:retrieval_ttl=%s\n' \
        "$1" "$SCENARIO_VARIANT" "$REMOTE_PARENT_TTL" "$REMOTE_PARENT_RETRIEVAL_TTL" >>"$observed"
    }

    run_primary_w3c_stale_control
    [[ "$REMOTE_PARENT_TTL" == "30s" && "$REMOTE_PARENT_RETRIEVAL_TTL" == "0s" && \
      "$SCENARIO_VARIANT" == "existing-variant" ]]
  ) || {
    printf 'primary stale control did not restore its caller state\n' >&2
    return 1
  }

  local -r expected=$'recreate:primary W3C stale preparation:getsockopt:retention_ttl=30s:retrieval_ttl=1ns\nscenario:primary-w3c-stale:existing-variant:retention_ttl=30s:retrieval_ttl=1ns\nrecreate:post-primary W3C stale recovery:getsockopt:retention_ttl=30s:retrieval_ttl=0s\nscenario:basic:primary-w3c-stale-recovery:retention_ttl=30s:retrieval_ttl=0s'
  [[ "$(<"$observed")" == "$expected" ]] || {
    printf 'primary stale control lifecycle changed:\n%s\n' "$(<"$observed")" >&2
    return 1
  }
}

test_unix_w3c_stale_control_restores_the_normal_ttls() {
  local -r observed="$TEST_TMP_DIR/unix-w3c-stale-control.calls"

  (
    TRANSPORT=unix
    SELECTED_TRANSPORT=unix
    REMOTE_PARENT_TTL=30s
    REMOTE_PARENT_RETRIEVAL_TTL=0s
    SCENARIO_VARIANT=existing-variant
    : >"$observed"
    recreate_instrumented_stack() {
      printf 'recreate:%s:%s:retention_ttl=%s:retrieval_ttl=%s\n' \
        "$2" "$3" "$REMOTE_PARENT_TTL" "$REMOTE_PARENT_RETRIEVAL_TTL" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:%s:retention_ttl=%s:retrieval_ttl=%s\n' \
        "$1" "$SCENARIO_VARIANT" "$REMOTE_PARENT_TTL" "$REMOTE_PARENT_RETRIEVAL_TTL" >>"$observed"
    }

    run_unix_w3c_stale_control
    [[ "$REMOTE_PARENT_TTL" == "30s" && "$REMOTE_PARENT_RETRIEVAL_TTL" == "0s" && \
      "$SCENARIO_VARIANT" == "existing-variant" ]]
  ) || {
    printf 'Unix stale control did not restore its caller state\n' >&2
    return 1
  }

  local -r expected=$'recreate:Unix W3C stale preparation:unix:retention_ttl=30s:retrieval_ttl=1ns\nscenario:unix-w3c-stale:existing-variant:retention_ttl=30s:retrieval_ttl=1ns\nrecreate:post-Unix W3C stale recovery:unix:retention_ttl=30s:retrieval_ttl=0s\nscenario:basic:unix-w3c-stale-recovery:retention_ttl=30s:retrieval_ttl=0s'
  [[ "$(<"$observed")" == "$expected" ]] || {
    printf 'Unix stale control lifecycle changed:\n%s\n' "$(<"$observed")" >&2
    return 1
  }
}

test_unix_w3c_stale_control_recovers_after_a_failed_stale_assertion() {
  local -r observed="$TEST_TMP_DIR/unix-w3c-stale-failure-recovery.calls"
  local control_status=0

  (
    TRANSPORT=unix
    SELECTED_TRANSPORT=unix
    REMOTE_PARENT_TTL=30s
    REMOTE_PARENT_RETRIEVAL_TTL=0s
    : >"$observed"
    recreate_instrumented_stack() {
      printf 'recreate:%s:%s:retrieval_ttl=%s\n' \
        "$2" "$3" "$REMOTE_PARENT_RETRIEVAL_TTL" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:retrieval_ttl=%s\n' \
        "$1" "$REMOTE_PARENT_RETRIEVAL_TTL" >>"$observed"
      [[ "$1" != "unix-w3c-stale" ]]
    }

    if run_unix_w3c_stale_control; then
      return 1
    else
      control_status=$?
    fi
    [[ "$control_status" == "1" && "$REMOTE_PARENT_TTL" == "30s" && \
      "$REMOTE_PARENT_RETRIEVAL_TTL" == "0s" ]]
  ) || {
    printf 'Unix stale control did not recover after a failed stale assertion\n' >&2
    return 1
  }

  local -r expected=$'recreate:Unix W3C stale preparation:unix:retrieval_ttl=1ns\nscenario:unix-w3c-stale:retrieval_ttl=1ns\nrecreate:post-Unix W3C stale recovery:unix:retrieval_ttl=0s\nscenario:basic:retrieval_ttl=0s'
  [[ "$(<"$observed")" == "$expected" ]] || {
    printf 'Unix stale failure recovery changed:\n%s\n' "$(<"$observed")" >&2
    return 1
  }
}

test_w3c_stale_scenarios_use_in_band_diagnostics() {
  local scenario=""
  local transport=""
  local calls=""
  local index=0
  local -a scenarios=(primary-w3c-stale unix-w3c-stale)
  local -a transports=(getsockopt unix)

  for index in "${!scenarios[@]}"; do
    scenario="${scenarios[$index]}"
    transport="${transports[$index]}"
    calls="$TEST_TMP_DIR/$scenario-scenario.calls"

    (
      RESULT_DIR="$TEST_TMP_DIR/$scenario-scenario"
      mkdir -p -- "$RESULT_DIR"
      : >"$calls"
      BRIDGE_RUNNING=true
      COMPOSE=(docker compose)
      REPEAT_COUNT=1
      REQUEST_COUNT=0
      SCENARIO_SEED=1
      SCENARIO_VARIANT=""
      SELECTED_TRANSPORT="$transport"
      TLS_PROTOCOL=TLSv1.3
      flush_bridge_metric_boundary() {
        printf 'boundary:%s:%s:%s:%s\n' \
          "$1" "${2:-1}" "${3:-1}" "${4:-}" >>"$calls"
        mkdir -p -- "$(dirname -- "$4")"
        write_diagnostics_fixture "$4" 0 0 0 0 0 0
      }
      capture_java_diagnostics() {
        printf 'unexpected-direct-diagnostics:%s\n' "$1" >>"$calls"
        return 1
      }
      capture_phase_evidence() {
        printf 'evidence:%s\n' "$1" >>"$calls"
        mkdir -p -- "$RESULT_DIR/phases/$1"
        printf 'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="%s"} 10\n' \
          "$transport" >"$RESULT_DIR/phases/$1/obi-metrics.prom"
        printf '%s\n' \
          'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 20' \
          >>"$RESULT_DIR/phases/$1/obi-metrics.prom"
      }
      run_bounded() {
        printf 'scenario\n' >>"$calls"
        write_diagnostics_fixture "$RESULT_DIR/in-band-diagnostics.txt" 0 1 0 0 0 0
        printf '{\n  "status": "passed",\n  "java_diagnostics_after": "%s"\n}\n' \
          "$(<"$RESULT_DIR/in-band-diagnostics.txt")"
      }
      wait_for_bridge_metrics_quiescent() {
        printf 'wait:%s:%s\n' "$1" "$2" >>"$calls"
      }
      write_metrics_delta() { : >"$3"; }
      assert_bridge_metric_delta() {
        printf 'bridge:%s:%s:%s:%s:%s:%s:%s:%s\n' \
          "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" >>"$calls"
        [[ "$2" == "$transport" && "$3" == "0" && "$4" == "0" && \
          "$5" == "0" && "$6" == "1" && "$7" == "1" && \
          "$8" == "false" && "$9" == "1" ]]
      }
      write_java_diagnostics_delta() { : >"$3"; }
      assert_java_diagnostics_delta() {
        printf 'java:%s:%s:%s:%s:%s:%s:%s\n' \
          "$2" "$3" "$4" "$5" "$6" "$7" "$8" >>"$calls"
        [[ "$2" == "0" && "$3" == "1" && "$4" == "0" && \
          "$5" == "0" && "$6" == "0" && "$7" == "0" && "$8" == "0" ]]
      }

      run_scenario "$scenario" >/dev/null
    ) || {
      printf '%s stale scenario did not use its in-band diagnostics snapshot\n' "$transport" >&2
      return 1
    }

    grep -Fqx \
      "boundary:$scenario:0:1:$TEST_TMP_DIR/$scenario-scenario/phases/$scenario-before/java-diagnostics.txt" \
      "$calls" || return 1
    grep -Fqx 'wait:10:21' "$calls" || return 1
    grep -Fqx "bridge:$transport:0:0:0:1:1:false:1" "$calls" || return 1
    grep -Fqx 'java:0:1:0:0:0:0:0' "$calls" || return 1
    if grep -Fq 'unexpected-direct-diagnostics:' "$calls"; then
      printf '%s stale scenario issued a direct diagnostics probe\n' "$transport" >&2
      return 1
    fi
  done
}

test_primary_w3c_fault_recreation_uses_the_overlay_only() {
  local -r result_dir="$TEST_TMP_DIR/primary-fault-recreate"
  local -r observed="$result_dir/observed"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(base-compose)
    PRIMARY_FAULT_COMPOSE=(fault-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    date() {
      printf 'primary-fault-cursor\n'
    }
    invalidate_selected_transport() {
      SELECTED_TRANSPORT=""
    }
    run_bounded() {
      printf 'bounded:%s\n' "$*" >>"$observed"
    }
    wait_for_log() {
      printf 'log:%s\n' "$3" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport:%s\n' "$1" >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    wait_for_java_duplicate_suppression() {
      printf 'suppression:%s\n' "$(basename -- "$1")" >>"$observed"
    }

    recreate_instrumented_stack \
      tcp primary-fault-overlay getsockopt true false primary-fault
    [[ "${COMPOSE[*]}" == "base-compose" && \
      "${PRIMARY_FAULT_COMPOSE[*]}" == "fault-compose" ]]
  ) || {
    printf 'primary fault recreation did not use its overlay\n' >&2
    return 1
  }

  grep -Fqx 'bounded:30 fault-compose config --quiet' "$observed"
  grep -Fqx 'bounded:30 fault-compose config' "$observed"
  grep -Fqx \
    'bounded:180 fault-compose up --detach --force-recreate java-backend apache-proxy obi' \
    "$observed"
  if grep -Fq 'base-compose up' "$observed"; then
    printf 'primary fault recreation used the base Compose command for its JVM\n' >&2
    return 1
  fi
}

test_primary_w3c_fault_scenario_arms_after_the_baseline() {
  local -r result_dir="$TEST_TMP_DIR/primary-fault-scenario"
  local -r observed="$result_dir/observed"
  local baseline_count=0

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    PRIMARY_FAULT_STACK_ACTIVE=true
    COMPOSE=(base-compose)
    PRIMARY_FAULT_COMPOSE=(fault-compose)
    REPEAT_COUNT=2
    SCENARIO_SEED=19
    TLS_PROTOCOL=TLSv1.3
    : >"$observed"
    flush_bridge_metric_boundary() {
      local -r diagnostics="$4"

      ((baseline_count += 1))
      printf 'boundary:%s:%s:%s\n' "$1" "$2" "$3" >>"$observed"
      mkdir -p -- "$(dirname -- "$diagnostics")"
      write_diagnostics_fixture \
        "$diagnostics" 0 0 0 0 0 0 version_mismatch "$((baseline_count - 1))"
    }
    capture_phase_evidence() {
      printf 'evidence:%s\n' "$1" >>"$observed"
      mkdir -p -- "$RESULT_DIR/phases/$1"
      if [[ "$1" == *-before ]]; then
        printf '%s\n' \
          'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 10' \
          'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 20' \
          >"$RESULT_DIR/phases/$1/obi-metrics.prom"
      else
        printf '%s\n' \
          'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 11' \
          'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 21' \
          >"$RESULT_DIR/phases/$1/obi-metrics.prom"
      fi
    }
    arm_primary_w3c_fault_control() {
      [[ -s "$RESULT_DIR/phases/primary-w3c-fault-version-mismatch-run-$(printf '%02d' "$baseline_count")-before/java-diagnostics.txt" ]] || return 1
      printf 'arm:%s:%s\n' "$1" "$(basename -- "$2")" >>"$observed"
      printf 'phase=armed\n' >"$2"
    }
    consume_primary_w3c_fault_control() {
      printf 'consume:%s\n' "$(basename -- "$1")" >>"$observed"
      printf 'phase=consumed\n' >"$1"
    }
    run_bounded() {
      local diagnostics_before=""
      local argument=""
      local version_mismatch_count=""

      for argument in "$@"; do
        if [[ "$argument" == cfg_on=* ]]; then
          diagnostics_before="$argument"
        fi
      done
      [[ "$diagnostics_before" == \
        "$(<"$RESULT_DIR/phases/primary-w3c-fault-version-mismatch-run-$(printf '%02d' "$baseline_count")-before/java-diagnostics.txt")" ]] || return 1
      version_mismatch_count="$(sed -n 's/.*t_version_mismatch=\([0-9][0-9]*\).*/\1/p' \
        <<<"$diagnostics_before")"
      [[ "$version_mismatch_count" =~ ^[0-9]+$ ]] || return 1
      printf 'scenario:%s\n' "$*" >>"$observed"
      write_diagnostics_fixture \
        "$RESULT_DIR/after-$baseline_count.txt" 0 0 0 0 0 0 version_mismatch \
        "$((version_mismatch_count + 1))"
      printf '{\n  "status": "passed",\n  "fault_diagnostics_after": "%s"\n}\n' \
        "$(<"$RESULT_DIR/after-$baseline_count.txt")"
    }
    wait_for_bridge_metrics_quiescent() {
      printf 'wait:%s:%s\n' "$1" "$2" >>"$observed"
    }
    write_metrics_delta() {
      : >"$3"
    }
    assert_bridge_metric_delta() {
      printf 'bridge:%s:%s:%s:%s:%s:%s:%s:%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" >>"$observed"
      [[ "$2" == getsockopt && "$3" == 1 && "$4" == 0 && "$5" == 0 && \
        "$6" == 1 && "$7" == 1 && "$8" == false && "$9" == 0 ]]
    }
    capture_java_diagnostics() {
      printf 'unexpected-direct-diagnostics:%s\n' "$1" >>"$observed"
      return 1
    }

    run_primary_w3c_fault_scenario version-mismatch
  ) || {
    printf 'primary fault scenario did not preserve its one-shot lifecycle\n' >&2
    return 1
  }

  [[ "$(grep -c '^boundary:' "$observed")" == 2 && \
    "$(grep -c '^arm:' "$observed")" == 2 && \
    "$(grep -c '^consume:' "$observed")" == 2 && \
    "$(grep -c '^scenario:' "$observed")" == 2 ]] || {
    printf 'primary fault scenario did not arm and consume every repeated request\n' >&2
    return 1
  }
  if grep -q '^unexpected-direct-diagnostics:' "$observed"; then
    printf 'primary fault scenario performed a direct Java diagnostics request after arming\n' >&2
    return 1
  fi
  awk '
    /^boundary:/ { boundary++ }
    /^arm:/ {
      arm++
      if (boundary != arm) invalid = 1
    }
    /^scenario:/ {
      scenario++
      if (arm != scenario) invalid = 1
    }
    /^consume:/ {
      consume++
      if (scenario != consume) invalid = 1
    }
    END { exit invalid || boundary != 2 || arm != 2 || scenario != 2 || consume != 2 ? 1 : 0 }
  ' "$observed" || {
    printf 'primary fault scenario did not order boundary, arm, request, and consumption\n' >&2
    return 1
  }
  grep -Fqx 'bridge:getsockopt:1:0:0:1:1:false:0' "$observed"
  grep -Fq -- '--scenario primary-w3c-fault' "$observed"
  grep -Fq -- '--fault-mode version-mismatch' "$observed"
  [[ -s "$result_dir/scenario-primary-w3c-fault-version-mismatch-run-01-status.json" && \
    -s "$result_dir/scenario-primary-w3c-fault-version-mismatch-run-02-status.json" ]] || {
    printf 'primary fault scenario did not retain per-request evidence\n' >&2
    return 1
  }
}

test_primary_w3c_fault_control_restores_the_base_stack() {
  run_case() (
    local -r mode="$1"
    local -r expected_status="$2"
    local -r expected_primary_fault_stack_active="$3"
    local -r result_dir="$TEST_TMP_DIR/primary-fault-control-$mode"
    local -r observed="$result_dir/observed"
    local status=0

    mkdir -p -- "$result_dir"
    RESULT_DIR="$result_dir"
    TRANSPORT=getsockopt
    SELECTED_TRANSPORT=getsockopt
    BRIDGE_RUNNING=true
    KEEP_RUNNING=true
    SCENARIO_VARIANT=existing-variant
    PRIMARY_FAULT_STACK_ACTIVE=false
    : >"$observed"
    recreate_instrumented_stack() {
      printf 'recreate:%s:%s:%s:%s\n' "$2" "$3" "$4" "$6" >>"$observed"
    }
    assert_runtime_contract() {
      printf 'runtime:%s:%s\n' "$1" "$2" >>"$observed"
      [[ "$mode" != recovery-contract-failure || "$1" != basic ]] || return 23
    }
    run_primary_w3c_fault_scenario() {
      printf 'fault:%s\n' "$1" >>"$observed"
      [[ "$mode" != failure || "$1" != version-mismatch ]] || return 17
    }
    run_scenario() {
      printf 'scenario:%s:%s\n' "$1" "$SCENARIO_VARIANT" >>"$observed"
    }

    if run_primary_w3c_fault_control; then
      status=0
    else
      status=$?
    fi
    [[ "$status" == "$expected_status" && \
      "$PRIMARY_FAULT_STACK_ACTIVE" == "$expected_primary_fault_stack_active" && \
      "$SCENARIO_VARIANT" == existing-variant ]] || return 1
    if [[ "$mode" == recovery-contract-failure ]]; then
      [[ -e "$result_dir/primary-w3c-fault-recovery-required" ]] || return 1
    else
      [[ ! -e "$result_dir/primary-w3c-fault-recovery-required" ]] || return 1
    fi
  ) || {
    printf 'primary fault control did not preserve its status and caller state\n' >&2
    return 1
  }

  run_case success 0 false
  run_case failure 17 false
  run_case recovery-contract-failure 23 false

  local -r success="$TEST_TMP_DIR/primary-fault-control-success/observed"
  local -r failure="$TEST_TMP_DIR/primary-fault-control-failure/observed"
  local -r recovery_contract_failure="$TEST_TMP_DIR/primary-fault-control-recovery-contract-failure/observed"

  grep -Fqx 'recreate:primary W3C fault preparation:getsockopt:true:primary-fault' "$success"
  grep -Fqx 'runtime:primary-w3c-fault:true' "$success"
  grep -Fqx 'fault:version-mismatch' "$success"
  grep -Fqx 'fault:bad-size' "$success"
  grep -Fqx 'fault:zero-trace-id' "$success"
  grep -Fqx 'fault:zero-span-id' "$success"
  grep -Fqx 'recreate:post-primary W3C fault recovery:getsockopt:true:base' "$success"
  grep -Fqx 'runtime:basic:true' "$success"
  grep -Fqx 'scenario:basic:primary-w3c-fault-recovery' "$success"
  grep -Fqx 'recreate:post-primary W3C fault recovery:getsockopt:true:base' "$failure"
  grep -Fqx 'runtime:basic:true' "$failure"
  if grep -q '^scenario:basic:' "$failure"; then
    printf 'failed primary fault control ran its post-recovery traffic\n' >&2
    return 1
  fi
  [[ "$(grep -c '^recreate:post-primary W3C fault recovery:getsockopt:true:base$' \
    "$recovery_contract_failure")" == 2 && \
    "$(grep -c '^runtime:basic:true$' "$recovery_contract_failure")" == 2 ]] || {
    printf 'failed primary fault recovery cleared its marker without a clean runtime contract\n' >&2
    return 1
  }
}

test_security_accepts_enabled_transports() {
  local transport=""

  for transport in getsockopt unix auto; do
    (
      TRANSPORT=getsockopt
      SCENARIO=all
      parse_args --transport "$transport" --scenario security
      [[ "$TRANSPORT" == "$transport" && "$SCENARIO" == "security" ]]
    ) || {
      printf 'rejected the security control for %s transport\n' "$transport" >&2
      return 1
    }
  done
  if (
    TRANSPORT=getsockopt
    SCENARIO=all
    parse_args --transport disabled --scenario security
  ) >/dev/null 2>&1; then
    printf 'accepted the security control with disabled transport\n' >&2
    return 1
  fi
}

test_tls_boundary_requires_split_and_coalesced_pair() {
  (
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --scenario tls-boundary --requests 3
    [[ "$SCENARIO" == "tls-boundary" && "$REQUEST_COUNT" == "3" ]]
  ) || {
    printf 'rejected the exact split-plus-coalesced-pair TLS boundary scenario\n' >&2
    return 1
  }
  if (
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --scenario tls-boundary --requests 2
  ) >/dev/null 2>&1; then
    printf 'accepted a TLS boundary run without the complete coalesced pair\n' >&2
    return 1
  fi
}

test_coalesced_bridge_requires_exact_live_pair() {
  (
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --scenario coalesced-bridge --requests 2
    [[ "$SCENARIO" == "coalesced-bridge" && "$REQUEST_COUNT" == "2" && \
      "$(scenario_request_count coalesced-bridge)" == "2" ]]
  ) || {
    printf 'rejected the exact two-boundary coalesced bridge control\n' >&2
    return 1
  }
  if (
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --scenario coalesced-bridge --requests 1
  ) >/dev/null 2>&1; then
    printf 'accepted a coalesced bridge control without two boundaries\n' >&2
    return 1
  fi
}

test_tls_boundary_receive_cursor_map_evidence_is_exact_and_steady() {
  local -r result_dir="$TEST_TMP_DIR/tls-boundary-receive-cursor-map"
  local -r helper_calls="$result_dir/helper.calls"

  mkdir -p -- "$result_dir"
  (
    local helper_call_count=0

    RESULT_DIR="$result_dir"
    RECEIVE_CURSOR_MAP_ID=""
    RECEIVE_GUARD_MAP_ID=""
    RECEIVE_CURSOR_MAP_BASELINE_ENTRIES=""
    RECEIVE_GUARD_MAP_BASELINE_ENTRIES=""
    RECEIVE_CURSOR_MAP_STATUS_JSON="null"
    run_receive_cursor_map_helper() {
      local -r output="$1"
      local -r stderr_output="$2"
      local cursor_map_id=41
      local guard_map_id=42
      local cursor_max_entries=10000
      local guard_max_entries=10000
      local cursor_entries=0
      local guard_entries=0
      shift 3

      ((helper_call_count += 1))
      printf 'call=%d args=%s\n' "$helper_call_count" "$*" >>"$helper_calls"
      : >"$stderr_output"
      case "$helper_call_count" in
        1)
          cursor_entries=2
          guard_entries=2
          ;;
        2)
          cursor_entries=2
          guard_entries=2
          ;;
        3)
          cursor_map_id=43
          cursor_entries=2
          guard_entries=2
          ;;
        4)
          cursor_max_entries=9999
          cursor_entries=2
          guard_entries=2
          ;;
        5)
          cursor_entries=2
          guard_entries=1
          ;;
        *)
          cursor_entries=2
          guard_entries=2
          ;;
      esac
      printf '{"status":"passed","cursor_map_id":%d,"cursor_map_name":"jrp_recv_cur","cursor_kernel_name":"jrp_recv_cur","cursor_map_type":"Hash","cursor_key_size":8,"cursor_value_size":56,"cursor_max_entries":%d,"cursor_entries":%d,"guard_map_id":%d,"guard_map_name":"jrp_recv_guard","guard_kernel_name":"jrp_recv_guard","guard_map_type":"Hash","guard_key_size":8,"guard_value_size":56,"guard_max_entries":%d,"guard_entries":%d}\n' \
        "$cursor_map_id" "$cursor_max_entries" "$cursor_entries" \
        "$guard_map_id" "$guard_max_entries" "$guard_entries" >"$output"
    }
    sleep() { : "$@"; }

    capture_receive_cursor_map_baseline tls-boundary >/dev/null
    [[ "$RECEIVE_CURSOR_MAP_ID" == "41" && \
      "$RECEIVE_GUARD_MAP_ID" == "42" && \
      "$RECEIVE_CURSOR_MAP_BASELINE_ENTRIES" == "2" && \
      "$RECEIVE_GUARD_MAP_BASELINE_ENTRIES" == "2" ]]
    wait_for_receive_cursor_map_recovery tls-boundary >/dev/null
    [[ "$helper_call_count" == "7" ]]
    [[ -f "$result_dir/receive-cursor-map-tls-boundary-before.json" && \
      -f "$result_dir/receive-cursor-map-tls-boundary-after.json" && \
      -f "$result_dir/receive-cursor-map-tls-boundary-recovery-samples.log" && \
      -f "$result_dir/receive-cursor-map-tls-boundary-status.json" ]]
    [[ "$(grep -c 'matched=true' \
      "$result_dir/receive-cursor-map-tls-boundary-recovery-samples.log")" == "3" ]]
    grep -F 'attempt=1 ' \
      "$result_dir/receive-cursor-map-tls-boundary-recovery-samples.log" | \
      grep -Fq 'cursor_map_id=41 cursor_entries=2 guard_map_id=42 guard_entries=2 matched=true consecutive=1'
    grep -F 'attempt=2 ' \
      "$result_dir/receive-cursor-map-tls-boundary-recovery-samples.log" | \
      grep -Fq 'cursor_map_id=43 cursor_entries=2 guard_map_id=42 guard_entries=2 matched=false consecutive=0'
    grep -F 'attempt=3 ' \
      "$result_dir/receive-cursor-map-tls-boundary-recovery-samples.log" | \
      grep -Fq 'cursor_map_id=41 cursor_entries=2 guard_map_id=42 guard_entries=2 matched=false consecutive=0'
    grep -Fq '"status":"passed","reason":"steady-baseline"' \
      "$result_dir/receive-cursor-map-tls-boundary-status.json"
    grep -Fq '"cursor_baseline_entries":2,"guard_baseline_entries":2,"cursor_final_entries":2,"guard_final_entries":2' \
      "$result_dir/receive-cursor-map-tls-boundary-status.json"
    grep -Fq '"required_consecutive_samples":2,"attempts":6' \
      "$result_dir/receive-cursor-map-tls-boundary-status.json"
  ) || {
    printf 'TLS-boundary receive-cursor map evidence did not require exact steady recovery\n' >&2
    return 1
  }

  grep -Fqx 'call=1 args=' "$helper_calls"
  [[ "$(grep -c \
    'args=--cursor-map-id 41 --guard-map-id 42 --expected-max-entries 10000' \
    "$helper_calls")" == "6" ]]

  (
    RESULT_DIR="$TEST_TMP_DIR/tls-boundary-receive-cursor-map-missing-baseline"
    mkdir -p -- "$RESULT_DIR"
    RECEIVE_CURSOR_MAP_ID=""
    RECEIVE_GUARD_MAP_ID=""
    RECEIVE_CURSOR_MAP_BASELINE_ENTRIES=""
    RECEIVE_GUARD_MAP_BASELINE_ENTRIES=""
    RECEIVE_CURSOR_MAP_STATUS_JSON="null"
    if wait_for_receive_cursor_map_recovery tls-boundary >/dev/null 2>&1; then
      return 1
    fi
    grep -Fq '"status":"failed","reason":"missing-baseline"' \
      "$RESULT_DIR/receive-cursor-map-tls-boundary-status.json"
  ) || {
    printf 'receive coordination-map recovery accepted a missing baseline\n' >&2
    return 1
  }

  local -r malformed="$result_dir/malformed.json"
  printf '%s\n' \
    '{"status":"passed","cursor_map_id":41,"cursor_map_name":"jrp_recv_cur","cursor_kernel_name":"jrp_recv_cur","cursor_map_type":"Hash","cursor_key_size":8,"cursor_value_size":56,"cursor_max_entries":10000,"cursor_entries":0,"guard_map_id":42,"guard_map_name":"jrp_recv_guard","guard_kernel_name":"jrp_recv_guard","guard_map_type":"Hash","guard_key_size":8,"guard_value_size":55,"guard_max_entries":10000,"guard_entries":0}' \
    >"$malformed"
  if receive_cursor_map_result_has_contract "$malformed"; then
    printf 'receive coordination-map evidence accepted the wrong guard layout\n' >&2
    return 1
  fi
}

test_receive_cursor_map_helper_bounds_evidence_before_replay() {
  run_limit_case() (
    local -r mode="$1"
    local -r result_dir="$TEST_TMP_DIR/receive-cursor-helper-bound-$mode"
    local -r output="$result_dir/output.json"
    local -r stderr_output="$result_dir/stderr.log"
    local -r replay_stdout="$result_dir/replay.stdout"
    local -r replay_stderr="$result_dir/replay.stderr"
    local output_size=0
    local stderr_size=0

    mkdir -p -- "$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      case "$mode" in
        stdout-bytes)
          awk -v count="$((RECEIVE_CURSOR_HELPER_STDOUT_MAX_BYTES + 1))" \
            'BEGIN { for (position = 0; position < count; position++) printf "x" }'
          ;;
        stdout-lines)
          printf '{}\n{}\n'
          ;;
        stderr-bytes)
          printf '{}\n'
          awk -v count="$((RECEIVE_CURSOR_HELPER_STDERR_MAX_BYTES + 1))" \
            'BEGIN { for (position = 0; position < count; position++) printf "x" > "/dev/stderr" }'
          ;;
        *)
          return 2
          ;;
      esac
    }

    if run_receive_cursor_map_helper \
      "$output" "$stderr_output" 1 >"$replay_stdout" 2>"$replay_stderr"; then
      return 1
    fi
    output_size="$(stat -c '%s' -- "$output")"
    stderr_size="$(stat -c '%s' -- "$stderr_output")"
    ((output_size <= RECEIVE_CURSOR_HELPER_STDOUT_MAX_BYTES))
    ((stderr_size <= RECEIVE_CURSOR_HELPER_STDERR_MAX_BYTES))
    [[ ! -s "$replay_stdout" ]]
    grep -Fq 'exceeded its evidence bounds' "$replay_stderr"
  )

  local mode=""
  for mode in stdout-bytes stdout-lines stderr-bytes; do
    run_limit_case "$mode" || {
      printf 'receive-cursor helper replay was not bounded for %s\n' "$mode" >&2
      return 1
    }
  done

  local -r oversized_record="$TEST_TMP_DIR/oversized-pressure-result.json"
  awk -v count="$((PRESSURE_RESULT_MAX_BYTES + 1))" \
    'BEGIN { for (position = 0; position < count; position++) printf "x" }' \
    >"$oversized_record"
  if pressure_result_record "$oversized_record" >/dev/null 2>&1; then
    printf 'pressure result parser accepted oversized evidence\n' >&2
    return 1
  fi
}

test_w3c_match_uses_controlled_unix_fixture() {
  run_control_case() (
    local -r scenario="$1"
    local -r keep_running="$2"
    local -r observed="$3"

    SCENARIO="$scenario"
    KEEP_RUNNING="$keep_running"
    TRANSPORT=getsockopt
    SELECTED_TRANSPORT=getsockopt
    BRIDGE_RUNNING=true
    export_compose_environment
    printf 'propagation:%s\n' "$CONTEXT_PROPAGATION" >>"$observed"
    recreate_instrumented_stack() {
      SELECTED_TRANSPORT="$3"
      BRIDGE_RUNNING=true
      printf 'recreate:%s:%s:%s\n' "$1" "$2" "$3" >>"$observed"
    }
    stop_obi_for_no_state_control() {
      BRIDGE_RUNNING=false
      printf 'stop:%s\n' "$1" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:%s:%s:%s\n' "$1" "$2" "$3" "$4" >>"$observed"
    }

    run_w3c_match_control
  )

  local -r expected="$TEST_TMP_DIR/w3c-match-control.expected"
  local observed=""

  printf '%s\n' \
    'propagation:tcp' \
    'recreate:tcp:matching W3C and OBI preparation:unix' \
    'stop:w3c-match' \
    'scenario:w3c-match:true:full:matching' \
    'recreate:tcp:post-match bridge restoration:getsockopt' >"$expected"
  for observed in \
    "$TEST_TMP_DIR/w3c-match-control-all.observed" \
    "$TEST_TMP_DIR/w3c-match-control-keep.observed"; do
    if [[ "$observed" == *-all.observed ]]; then
      run_control_case all false "$observed"
    else
      run_control_case w3c-match true "$observed"
    fi
    cmp -s -- "$expected" "$observed" || {
      printf 'W3C match fixture lifecycle changed for %s\n' "$observed" >&2
      diff -u -- "$expected" "$observed" >&2 || true
      return 1
    }
  done
}

test_matching_bridge_sequence_is_exact() {
  local -r fixture_log="$TEST_TMP_DIR/matching-bridge.log"

  printf '%s\n' \
    'bridge-fault | fault bridge operation=negotiate status=missing take_count=0' \
    'bridge-fault | fault bridge operation=take status=missing take_count=1' \
    'bridge-fault | fault bridge operation=take status=valid take_count=2' \
    'bridge-fault | fault bridge operation=take status=valid take_count=3' \
    'bridge-fault | fault bridge operation=take status=missing take_count=4' \
    >"$fixture_log"
  matching_bridge_sequence_is_exact "$fixture_log" 2 || {
    printf 'matching bridge rejected its exact bounded sequence\n' >&2
    return 1
  }

  sed -i 's/status=valid take_count=3/status=missing take_count=3/' "$fixture_log"
  if matching_bridge_sequence_is_exact "$fixture_log" 2; then
    printf 'matching bridge accepted an out-of-order response\n' >&2
    return 1
  fi
}

test_matching_bridge_start_failure_is_cleaned_up() {
  local -r call_log="$TEST_TMP_DIR/matching-bridge-start-failure.calls"

  (
    local start_status=0

    BRIDGE_RUNNING=false
    MATCHING_BRIDGE_RUNNING=false
    COMPOSE=(docker compose)
    RESULT_DIR="$TEST_TMP_DIR/matching-bridge-start-failure"
    mkdir -p -- "$RESULT_DIR"
    run_bounded() {
      printf '%s\n' "$*" >>"$call_log"
      if [[ "$*" == *' up '* ]]; then
        return 42
      fi
    }

    if start_matching_bridge w3c-match 1; then
      return 1
    else
      start_status=$?
    fi
    [[ "$start_status" == "42" ]] || return 1
    [[ "$MATCHING_BRIDGE_RUNNING" == "false" ]] || return 1
    [[ "$FAULT_MODE" == "alternating" && "$MATCHING_VALID_TAKES" == "1" ]] || return 1
  ) || {
    printf 'matching bridge partial startup was not cleaned up\n' >&2
    return 1
  }

  [[ "$(<"$call_log")" == $'60 docker compose up --detach --no-deps --force-recreate bridge-fault\n30 docker compose stop --timeout 5 bridge-fault' ]] || {
    printf 'matching bridge startup failure did not issue a bounded stop\n' >&2
    return 1
  }
}

test_cleanup_stops_matching_bridge_when_stack_is_kept() {
  local -r call_log="$TEST_TMP_DIR/matching-bridge-exit-cleanup.calls"

  (
    PRESSURE_ACTIVE=false
    RESULT_DIR=""
    STACK_STARTED=true
    KEEP_RUNNING=true
    MATCHING_BRIDGE_RUNNING=true
    TMP_DIR=""
    COMPOSE=(docker compose)
    cleanup_security_processes() { :; }
    run_bounded() {
      printf '%s\n' "$*" >>"$call_log"
    }
    safe_compose_down() {
      printf 'unexpected compose down\n' >>"$call_log"
      return 1
    }

    cleanup
  ) || {
    printf 'exit cleanup failed while retaining the main stack\n' >&2
    return 1
  }

  [[ "$(<"$call_log")" == '30 docker compose stop --timeout 5 bridge-fault' ]] || {
    printf 'exit cleanup did not stop only the transient matching bridge\n' >&2
    return 1
  }
}

test_runtime_directory_rejects_symlink() {
  mkdir -p -- "$TEST_TMP_DIR/runtime-real"
  ln -s -- "$TEST_TMP_DIR/runtime-real" "$TEST_TMP_DIR/runtime-link"
  if (prepare_runtime_directory "$TEST_TMP_DIR/runtime-link") >/dev/null 2>&1; then
    printf 'accepted a symlink runtime directory\n' >&2
    return 1
  fi
}

test_bridge_artifact_metadata() {
  local valid_tree_sha=""
  local victim=""

  RESULT_DIR="$TEST_TMP_DIR/results"
  ARTIFACT_DIR="$TEST_TMP_DIR/artifacts"
  mkdir -p -- "$RESULT_DIR" "$ARTIFACT_DIR"
  capture_source_state

  printf 'helper jar fixture\n' >"$ARTIFACT_DIR/obi-java-agent.jar"
  printf 'extension jar fixture\n' >"$ARTIFACT_DIR/obi-otel-extension.jar"
  write_bridge_metadata
  bridge_artifacts_are_valid || {
    printf 'rejected valid bridge artifact metadata\n' >&2
    return 1
  }

  printf 'tampered\n' >>"$ARTIFACT_DIR/obi-java-agent.jar"
  if bridge_artifacts_are_valid; then
    printf 'accepted a bridge artifact with a mismatched checksum\n' >&2
    return 1
  fi

  printf 'helper jar fixture\n' >"$ARTIFACT_DIR/obi-java-agent.jar"
  write_bridge_metadata
  printf 'tampered metadata\n' >>"$ARTIFACT_DIR/bridge-source-revision.txt"
  if bridge_artifacts_are_valid; then
    printf 'accepted tampered bridge artifact metadata\n' >&2
    return 1
  fi

  write_bridge_metadata
  valid_tree_sha="$SOURCE_TREE_SHA256"
  SOURCE_TREE_SHA256="$(printf '0%.0s' {1..64})"
  if bridge_artifacts_are_valid; then
    printf 'accepted bridge artifacts from a different source tree\n' >&2
    return 1
  fi
  SOURCE_TREE_SHA256="$valid_tree_sha"

  victim="$TEST_TMP_DIR/metadata-symlink-victim"
  printf 'do not overwrite\n' >"$victim"
  rm -f -- "$ARTIFACT_DIR/bridge-source-revision.txt"
  ln -s -- "$victim" "$ARTIFACT_DIR/bridge-source-revision.txt"
  write_bridge_metadata
  [[ "$(<"$victim")" == "do not overwrite" ]] || {
    printf 'bridge metadata publication followed a stale symlink\n' >&2
    return 1
  }
  [[ -f "$ARTIFACT_DIR/bridge-source-revision.txt" && \
    ! -L "$ARTIFACT_DIR/bridge-source-revision.txt" ]] || {
    printf 'bridge metadata publication did not replace a stale symlink\n' >&2
    return 1
  }
}

test_agent_download_rejects_symlink_output() {
  local -r download_script="$TEST_SCRIPT_DIR/download-agent.sh"
  local -r download_root="$TEST_TMP_DIR/agent-download"

  mkdir -p -- "$download_root/real-artifacts"
  ln -s -- "$download_root/real-artifacts" "$download_root/artifacts"
  if "$download_script" --distribution otel --output "$download_root/artifacts" >/dev/null 2>&1; then
    printf 'agent downloader accepted a symlink output directory\n' >&2
    return 1
  fi
}

test_metrics_delta_reports_counters_and_map_occupancy() {
  local before="$TEST_TMP_DIR/metrics-before.prom"
  local after="$TEST_TMP_DIR/metrics-after.prom"
  local delta="$TEST_TMP_DIR/metrics.delta"
  local delta_status=0

  cat >"$before" <<'EOF'
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 2
obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 7
EOF
  cat >"$after" <<'EOF'
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 5
obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 1
obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 1
EOF
  RESULT_DIR="$TEST_TMP_DIR"
  write_metrics_delta "$before" "$after" "$delta"

  [[ "$(<"$delta")" == *'status="valid"'*'delta=3'* ]] || {
    printf 'metrics delta omitted the reason-coded counter change\n' >&2
    return 1
  }
  [[ "$(<"$delta")" == *'map_name="java_remote_parent_state"'*'delta=-6'* ]] || {
    printf 'metrics delta omitted the map occupancy change\n' >&2
    return 1
  }
  [[ "$(<"$delta")" == *'error_type="attaching_java_agent"'*'delta=1'* ]] || {
    printf 'metrics delta omitted the Java attach-error counter change\n' >&2
    return 1
  }

  if (
    sort() { return 29; }
    write_metrics_delta "$before" "$after" "$delta.failed"
  ) >/dev/null 2>&1; then
    printf 'metrics delta ignored sort failure\n' >&2
    return 1
  else
    delta_status=$?
  fi
  [[ "$delta_status" == "29" ]] || {
    printf 'metrics delta returned %s instead of sort status 29\n' "$delta_status" >&2
    return 1
  }
}

test_java_attach_error_metric_is_exact_unique() {
  local -r metrics="$TEST_TMP_DIR/java-attach-errors.prom"

  cat >"$metrics" <<'EOF'
obi_instrumentation_errors_total{error_type="other",process_name="java"} 9
obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="python"} 8
obi_instrumentation_errors_total_extra{error_type="attaching_java_agent",process_name="java"} 7
EOF
  [[ "$(java_attach_error_total "$metrics")" == "absent" ]] || {
    printf 'attach-error parser did not distinguish an absent exact series\n' >&2
    return 1
  }

  printf '%s\n' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 3' \
    >>"$metrics"
  [[ "$(java_attach_error_total "$metrics")" == "3" ]] || {
    printf 'attach-error parser rejected the exact series\n' >&2
    return 1
  }

  printf '%s\n' \
    'obi_instrumentation_errors_total{process_name="java",error_type="attaching_java_agent"} 3' \
    >>"$metrics"
  if java_attach_error_total "$metrics" >/dev/null 2>&1; then
    printf 'attach-error parser accepted duplicate target series\n' >&2
    return 1
  fi

  for invalid in \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java",extra="x"} 1' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} -1' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 1.5' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} NaN' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 9223372036854775808' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 1 extra'; do
    printf '%s\n' "$invalid" >"$metrics"
    if java_attach_error_total "$metrics" >/dev/null 2>&1; then
      printf 'attach-error parser accepted malformed target: %s\n' "$invalid" >&2
      return 1
    fi
  done
}

test_java_attach_error_wait_requires_exact_stability() {
  (
    local -i fetches=0
    RESULT_DIR="$TEST_TMP_DIR/java-attach-wait-success"
    READINESS_TIMEOUT_SECONDS=5
    mkdir -p -- "$RESULT_DIR"
    fetch_obi_metrics() {
      ((fetches += 1))
      if ((fetches == 1)); then
        printf '# absent\n' >"$1"
      else
        printf '%s\n' \
          'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 1' \
          >"$1"
      fi
    }
    sleep() {
      :
    }

    wait_for_java_attach_error_total \
      1 absent "$RESULT_DIR/stable.prom" "test attach failure" 3
    [[ "$fetches" == "4" && "$(java_attach_error_total "$RESULT_DIR/stable.prom")" == "1" ]]
    [[ "$(wc -l <"$RESULT_DIR/stable-samples.log")" == "4" ]]
  ) || {
    printf 'attach-error wait did not require absent-to-one stability\n' >&2
    return 1
  }

  (
    local -i fetches=0
    RESULT_DIR="$TEST_TMP_DIR/java-attach-wait-gap"
    READINESS_TIMEOUT_SECONDS=5
    mkdir -p -- "$RESULT_DIR"
    fetch_obi_metrics() {
      ((fetches += 1))
      if ((fetches == 2)); then
        return 1
      fi
      printf '%s\n' \
        'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 1' \
        >"$1"
    }
    sleep() {
      :
    }

    wait_for_java_attach_error_total \
      1 1 "$RESULT_DIR/stable.prom" "gapped attach metric" 2
    [[ "$fetches" == "4" ]]
  ) || {
    printf 'attach-error wait counted non-consecutive successful scrapes\n' >&2
    return 1
  }

  run_failure_case() (
    local -r first="$1"
    local -r second="$2"
    local -r baseline="$3"
    local -r expected="$4"
    local -i fetches=0
    RESULT_DIR="$TEST_TMP_DIR/java-attach-wait-failure-$first-$second"
    READINESS_TIMEOUT_SECONDS=5
    mkdir -p -- "$RESULT_DIR"
    fetch_obi_metrics() {
      local state=""

      ((fetches += 1))
      if ((fetches == 1)); then
        state="$first"
      else
        state="$second"
      fi
      if [[ "$state" == "absent" ]]; then
        printf '# absent\n' >"$1"
      elif [[ "$state" == "duplicate" ]]; then
        printf '%s\n' \
          'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 1' \
          'obi_instrumentation_errors_total{process_name="java",error_type="attaching_java_agent"} 1' \
          >"$1"
      else
        printf 'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} %s\n' \
          "$state" >"$1"
      fi
    }
    sleep() {
      :
    }
    ! wait_for_java_attach_error_total \
      "$expected" "$baseline" "$RESULT_DIR/rejected.prom" "rejected attach metric" 2
  )

  run_failure_case 1 absent absent 1 || {
    printf 'attach-error wait accepted disappearance after observation\n' >&2
    return 1
  }
  run_failure_case 2 2 absent 1 || {
    printf 'attach-error wait accepted an overshoot\n' >&2
    return 1
  }
  run_failure_case 2 1 1 2 || {
    printf 'attach-error wait accepted a reset after observation\n' >&2
    return 1
  }
  run_failure_case duplicate duplicate absent 1 || {
    printf 'attach-error wait accepted duplicate target series\n' >&2
    return 1
  }
}

test_log_pid_count_requires_an_exact_numeric_token() {
  local -r log="$TEST_TMP_DIR/exact-pid.log"
  local -r message="unable to attach java agent"

  printf '%s\n' \
    "level=WARN msg=\"$message\" pid=42420" \
    "level=WARN msg=\"$message\" pid=4242 component=test" \
    >"$log"
  assert_log_message_for_pid_count "$log" "$message" 4242 1 || {
    printf 'log PID matcher did not accept the exact numeric token\n' >&2
    return 1
  }
  if assert_log_message_for_pid_count "$log" "$message" 424 1 >/dev/null 2>&1; then
    printf 'log PID matcher accepted a numeric prefix\n' >&2
    return 1
  fi
  if assert_log_message_for_pid_count "$log" "$message" invalid 0 >/dev/null 2>&1; then
    printf 'log PID matcher accepted a malformed PID\n' >&2
    return 1
  fi
}

test_helper_unavailable_metric_boundary_preserves_counters() {
  (
    local -r observed="$TEST_TMP_DIR/helper-boundary-observed"
    RESULT_DIR="$TEST_TMP_DIR/helper-boundary"
    BRIDGE_RUNNING=true
    mkdir -p -- "$RESULT_DIR"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 5' \
        'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 7' \
        >"$1"
    }
    curl() {
      :
    }
    wait_for_bridge_metrics_quiescent() {
      printf '%s %s\n' "$1" "$2" >>"$observed"
    }

    flush_bridge_metric_boundary normal
    flush_bridge_metric_boundary helper 0 0
    [[ "$(<"$observed")" == $'6 8\n5 7' ]]
    ! flush_bridge_metric_boundary invalid -1 1
  ) || {
    printf 'helper-unavailable metric boundary did not preserve success and stage\n' >&2
    return 1
  }
}

test_metric_boundary_helpers_are_reason_coded() {
  local metrics="$TEST_TMP_DIR/bridge-metrics.prom"
  local fingerprint=""
  local pressure=""

  cat >"$metrics" <<'EOF'
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 2
obi_java_remote_parent_operations_total{operation="discard",status="valid",transport="unix"} 3
obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} 99
obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="getsockopt"} 11
obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="unix"} 12
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 99
obi_java_remote_parent_operations_total{operation="report",status="valid",transport="tcp"} 7
obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7
obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 10000
obi_avoided_services{otel_metric_overflow="false",service_name="java-backend",service_namespace="apache-java-https",telemetry_type="traces"} 1
EOF

  [[ "$(bridge_success_total "$metrics")" == "5" ]] || {
    printf 'bridge success total included a non-success or non-transport counter\n' >&2
    return 1
  }
  [[ "$(bridge_stage_total "$metrics")" == "99" ]] || {
    printf 'bridge stage total did not isolate the valid stage counter\n' >&2
    return 1
  }
  [[ "$(bridge_report_total "$metrics")" == "7" ]] || {
    printf 'bridge report total did not isolate the completed publication marker\n' >&2
    return 1
  }
  fingerprint="$(bridge_metric_fingerprint "$metrics")"
  sed -i 's/operation="report",status="valid",transport="tcp"} 7/operation="report",status="valid",transport="tcp"} 8/' "$metrics"
  [[ "$(bridge_metric_fingerprint "$metrics")" == "$fingerprint" ]] || {
    printf 'bridge fingerprint included the report generation\n' >&2
    return 1
  }
  ALLOW_PRIMARY_SECURITY_METRICS=true
  fingerprint="$(bridge_metric_fingerprint "$metrics")"
  sed -i 's/status="unauthorized",transport="getsockopt"} 11/status="unauthorized",transport="getsockopt"} 13/' "$metrics"
  [[ "$(bridge_metric_fingerprint "$metrics")" == "$fingerprint" ]] || {
    printf 'bridge fingerprint included allowed primary-security noise\n' >&2
    return 1
  }
  ALLOW_PRIMARY_SECURITY_METRICS=false
  ALLOW_UNIX_SECURITY_METRICS=true
  fingerprint="$(bridge_metric_fingerprint "$metrics")"
  sed -i 's/status="unauthorized",transport="unix"} 12/status="unauthorized",transport="unix"} 14/' "$metrics"
  [[ "$(bridge_metric_fingerprint "$metrics")" == "$fingerprint" ]] || {
    printf 'bridge fingerprint included allowed Unix-security noise\n' >&2
    return 1
  }
  ALLOW_UNIX_SECURITY_METRICS=false
  pressure="$(pressure_map_metric \
    "$metrics" \
    obi_bpf_map_max_entries_total)"
  [[ "$pressure" == "41 10000" ]] || {
    printf 'could not resolve pressure map metadata: %s\n' "$pressure" >&2
    return 1
  }
  java_duplicate_suppression_present "$metrics" || {
    printf 'could not prove Java duplicate trace suppression\n' >&2
    return 1
  }
}

test_duplicate_suppression_wait_primes_java_export() {
  local -r result_dir="$TEST_TMP_DIR/duplicate-suppression-wait"
  local -r observed="$result_dir/observed"
  local -r metrics="$result_dir/suppression.prom"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    run_bounded() {
      printf '%s\n' "$*" >>"$observed"
    }
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_avoided_services{service_name="java-backend",service_namespace="apache-java-https",telemetry_type="traces"} 1' \
        >"$1"
    }

    wait_for_java_duplicate_suppression "$metrics"
  ) || {
    printf 'duplicate suppression readiness did not become ready\n' >&2
    return 1
  }
  grep -Fq "10 curl --fail --silent --show-error $APACHE_HTTPS_HEALTH_ENDPOINT" \
    "$observed" || {
    printf 'duplicate suppression readiness did not prime a Java export\n' >&2
    return 1
  }
  java_duplicate_suppression_present "$metrics"

  local failure_status=0
  if (
    RESULT_DIR="$result_dir"
    run_bounded() { return 23; }

    wait_for_java_duplicate_suppression "$result_dir/prime-failure.prom"
  ) >/dev/null 2>&1; then
    printf 'duplicate suppression ignored Java export prime failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "23" ]] || return 1

  if (
    RESULT_DIR="$result_dir"
    run_bounded() { return 0; }
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_avoided_services{service_name="java-backend",service_namespace="apache-java-https",telemetry_type="traces"} 1' \
        >"$1"
    }
    install() { return 29; }

    wait_for_java_duplicate_suppression "$result_dir/install-failure.prom"
  ) >/dev/null 2>&1; then
    printf 'duplicate suppression ignored evidence install failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "29" &&
    ! -e "$result_dir/install-failure.prom" ]] || return 1

  if (
    RESULT_DIR="$result_dir"
    run_bounded() { return 0; }
    fetch_obi_metrics() { return 1; }
    sleep() { return 31; }

    wait_for_java_duplicate_suppression "$result_dir/sleep-failure.prom"
  ) >/dev/null 2>&1; then
    printf 'duplicate suppression ignored retry sleep failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "31" &&
    ! -e "$result_dir/sleep-failure.prom" ]] || return 1
}

test_duplicate_suppression_absence_requires_a_clean_metric_snapshot() {
  local -r result_dir="$TEST_TMP_DIR/duplicate-suppression-absence"
  local -r output="$result_dir/absent.prom"
  local failure_status=0

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    fetch_obi_metrics() {
      printf '# no Java duplicate suppression\n' >"$1"
    }

    assert_java_duplicate_suppression_absent "$output"
  ) || {
    printf 'duplicate suppression absence rejected an empty metric state\n' >&2
    return 1
  }
  [[ "$(<"$output")" == '# no Java duplicate suppression' ]] || return 1

  if (
    RESULT_DIR="$result_dir"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_avoided_services{service_name="java-backend",service_namespace="apache-java-https",telemetry_type="traces"} 1' \
        >"$1"
    }

    assert_java_duplicate_suppression_absent "$result_dir/present.prom"
  ) >/dev/null 2>&1; then
    printf 'duplicate suppression absence accepted a positive metric\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/present.prom" ]] || return 1

  if (
    RESULT_DIR="$result_dir"
    fetch_obi_metrics() { return 23; }

    assert_java_duplicate_suppression_absent "$result_dir/fetch-failure.prom"
  ) >/dev/null 2>&1; then
    printf 'duplicate suppression absence ignored a metrics fetch failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "23" && ! -e "$result_dir/fetch-failure.prom" ]] || return 1

  if (
    RESULT_DIR="$result_dir"
    fetch_obi_metrics() {
      printf '# no Java duplicate suppression\n' >"$1"
    }
    install() { return 29; }

    assert_java_duplicate_suppression_absent "$result_dir/install-failure.prom"
  ) >/dev/null 2>&1; then
    printf 'duplicate suppression absence ignored an evidence publication failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "29" && ! -e "$result_dir/install-failure.prom" ]] || return 1
}

test_delayed_otlp_window_requires_a_fresh_generation() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-window"
  local -r output="$result_dir/window.txt"
  local current_millisecond=""
  local failure_status=0
  local -i expected_current=0

  mkdir -p -- "$result_dir"
  expected_current="$((
    100000 + DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS -
      (DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS + DELAYED_OTLP_PRE_EXPORT_SAFETY_SECONDS) * 1000 - 1
  ))"
  (
    java_backend_started_millisecond() { printf '100000\n'; }
    date() { printf '%s\n' "$expected_current"; }

    assert_delayed_otlp_pre_export_window "$output"
  ) || {
    printf 'delayed OTLP window rejected a fresh Java generation\n' >&2
    return 1
  }
  current_millisecond="$expected_current"
  grep -Fqx 'java_started_millisecond=100000' "$output"
  grep -Fqx "prime_millisecond=$current_millisecond" "$output"
  grep -Fqx "earliest_export_millisecond=$((100000 + DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS))" "$output"
  grep -Fqx "schedule_delay_milliseconds=$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS" "$output"
  grep -Fqx "pre_export_wait_seconds=$DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS" "$output"
  grep -Fqx "pre_export_safety_seconds=$DELAYED_OTLP_PRE_EXPORT_SAFETY_SECONDS" "$output"

  if (
    java_backend_started_millisecond() { printf '100000\n'; }
    date() {
      printf '%s\n' "$((
        100000 + DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS -
          (DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS + DELAYED_OTLP_PRE_EXPORT_SAFETY_SECONDS) * 1000
      ))"
    }

    assert_delayed_otlp_pre_export_window "$result_dir/expired-window.txt"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP window accepted an export deadline boundary\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/expired-window.txt" ]] || return 1
}

test_delayed_otlp_settlement_covers_pinned_obi_delivery_bound() {
  ((DELAYED_OTLP_POST_EXPORT_SETTLE_SECONDS ==
    DELAYED_OTLP_OBI_BATCH_TIMEOUT_SECONDS +
      DELAYED_OTLP_OBI_RETRY_MAX_ELAPSED_SECONDS +
      DELAYED_OTLP_OBI_EXPORT_TIMEOUT_SECONDS +
      DELAYED_OTLP_CLOCK_QUANTIZATION_SECONDS)) || return 1
  ((DELAYED_OTLP_CLOCK_QUANTIZATION_SECONDS == 1)) || return 1
  grep -Fqx \
    "  batch_timeout: ${DELAYED_OTLP_OBI_BATCH_TIMEOUT_SECONDS}s" \
    "$TEST_SCRIPT_DIR/../configs/obi.yaml" || return $?
  grep -Fqx \
    "  export_timeout: ${DELAYED_OTLP_OBI_EXPORT_TIMEOUT_SECONDS}s" \
    "$TEST_SCRIPT_DIR/../configs/obi.yaml" || return $?
  grep -Fqx '  backoff_initial_interval: 100ms' \
    "$TEST_SCRIPT_DIR/../configs/obi.yaml" || return $?
  grep -Fqx '  backoff_max_interval: 1s' \
    "$TEST_SCRIPT_DIR/../configs/obi.yaml" || return $?
  grep -Fqx \
    "  backoff_max_elapsed_time: ${DELAYED_OTLP_OBI_RETRY_MAX_ELAPSED_SECONDS}s" \
    "$TEST_SCRIPT_DIR/../configs/obi.yaml" || return $?
  grep -Fqx '      OTEL_BSP_EXPORT_TIMEOUT: "5000"' \
    "$TEST_SCRIPT_DIR/../docker-compose.yml" || return $?
  grep -Fqx \
    '      OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED: "${OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE:-false}"' \
    "$TEST_SCRIPT_DIR/../docker-compose.yml"
}

test_delayed_otlp_snapshot_fetch_wrapper_is_exact_and_bounded() (
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-fetch-wrapper"
  local -r fake_bin="$result_dir/bin"
  local -r fake_timeout="$fake_bin/timeout"
  local -r fake_curl="$fake_bin/curl"
  local -r timeout_argument_log="$result_dir/timeout-arguments"
  local -r argument_log="$result_dir/curl-arguments"
  local -r output="$result_dir/snapshot.json"
  local -r partial_output="$result_dir/partial.json"
  local -r term_file="$result_dir/curl-term"
  local -r pid_file="$result_dir/curl-pid"
  local -a actual_timeout_arguments=()
  local -a actual_arguments=()
  local -a expected_timeout_arguments=(
    --signal=TERM
    "--kill-after=${DELAYED_OTLP_FETCH_KILL_GRACE_SECONDS}s"
    2s
    curl
    --fail
    --silent
    --show-error
    --get
    --data-urlencode
    "marker=$DELAYED_OTLP_PRIME_MARKER"
    --output
    "$output"
    http://127.0.0.1:14318/snapshot
  )
  local -a expected_arguments=(
    --fail
    --silent
    --show-error
    --get
    --data-urlencode
    "marker=$DELAYED_OTLP_PRIME_MARKER"
    --output
    "$output"
    http://127.0.0.1:14318/snapshot
  )
  local -i argument_index=0
  local real_timeout=""
  local timeout_version=""
  local curl_pid=""
  local process_state=""
  local status=0

  mkdir -p -- "$fake_bin"
  real_timeout="$(command -v timeout)" || return $?
  [[ "$real_timeout" == /* && -x "$real_timeout" ]] || return 1
  timeout_version="$("$real_timeout" --version 2>/dev/null)" || return $?
  [[ "$timeout_version" == *"GNU coreutils"* ]] || return 1
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    ': "${FAKE_TIMEOUT_ARGV_FILE:?}" "${REAL_TIMEOUT:?}"' \
    'printf "%s\0" "$@" >"$FAKE_TIMEOUT_ARGV_FILE"' \
    'exec "$REAL_TIMEOUT" "$@"' >"$fake_timeout"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    ': "${FAKE_CURL_ARGV_FILE:?}" "${FAKE_CURL_MODE:?}"' \
    'printf "%s\0" "$@" >"$FAKE_CURL_ARGV_FILE"' \
    'output=""' \
    'previous=""' \
    'for argument in "$@"; do' \
    '  if [[ "$previous" == "--output" ]]; then output="$argument"; fi' \
    '  previous="$argument"' \
    'done' \
    '[[ -n "$output" ]] || exit 91' \
    'case "$FAKE_CURL_MODE" in' \
    '  success)' \
    '    printf "%s\n" "$FAKE_CURL_PAYLOAD" >"$output"' \
    '    ;;' \
    '  ignore-term)' \
    '    printf "%s\n" partial >"$output"' \
    '    on_term() { printf "%s\n" term >"$FAKE_CURL_TERM_FILE"; }' \
    '    trap on_term TERM' \
    '    printf "%s\n" "$BASHPID" >"$FAKE_CURL_PID_FILE"' \
    '    SECONDS=0' \
    '    while ((SECONDS < 10)); do sleep 1 || :; done' \
    '    exit 99' \
    '    ;;' \
    '  *) exit 92 ;;' \
    'esac' >"$fake_curl"
  chmod 0755 "$fake_timeout" "$fake_curl"

  export REAL_TIMEOUT="$real_timeout"
  export PATH="$fake_bin:$PATH"
  export FAKE_TIMEOUT_ARGV_FILE="$timeout_argument_log"
  export FAKE_CURL_ARGV_FILE="$argument_log"
  export FAKE_CURL_MODE=success
  export FAKE_CURL_PAYLOAD='{"status":"ok"}'
  fetch_delayed_otlp_receiver_snapshot "$output" 2 || return $?
  [[ "$(<"$output")" == "$FAKE_CURL_PAYLOAD" ]] || return 1
  mapfile -d '' -t actual_timeout_arguments <"$timeout_argument_log"
  mapfile -d '' -t actual_arguments <"$argument_log"
  ((${#actual_timeout_arguments[@]} == ${#expected_timeout_arguments[@]})) ||
    return 1
  for argument_index in "${!expected_timeout_arguments[@]}"; do
    [[ "${actual_timeout_arguments[$argument_index]}" == \
      "${expected_timeout_arguments[$argument_index]}" ]] || return 1
  done
  ((${#actual_arguments[@]} == ${#expected_arguments[@]})) || return 1
  for argument_index in "${!expected_arguments[@]}"; do
    [[ "${actual_arguments[$argument_index]}" == \
      "${expected_arguments[$argument_index]}" ]] || return 1
  done

  export FAKE_CURL_MODE=ignore-term
  export FAKE_CURL_TERM_FILE="$term_file"
  export FAKE_CURL_PID_FILE="$pid_file"
  expected_timeout_arguments[2]=1s
  expected_timeout_arguments[11]="$partial_output"
  expected_arguments[7]="$partial_output"
  if (fetch_delayed_otlp_receiver_snapshot "$partial_output" 1) \
    >/dev/null 2>&1; then
    printf 'delayed OTLP fetch wrapper did not terminate a TERM-ignoring curl\n' >&2
    return 1
  else
    status=$?
  fi
  mapfile -d '' -t actual_timeout_arguments <"$timeout_argument_log"
  mapfile -d '' -t actual_arguments <"$argument_log"
  [[ "$status" == "137" && "$(<"$partial_output")" == "partial" &&
    "$(<"$term_file")" == "term" ]] || return 1
  ((${#actual_timeout_arguments[@]} == ${#expected_timeout_arguments[@]})) ||
    return 1
  for argument_index in "${!expected_timeout_arguments[@]}"; do
    [[ "${actual_timeout_arguments[$argument_index]}" == \
      "${expected_timeout_arguments[$argument_index]}" ]] || return 1
  done
  ((${#actual_arguments[@]} == ${#expected_arguments[@]})) || return 1
  for argument_index in "${!expected_arguments[@]}"; do
    [[ "${actual_arguments[$argument_index]}" == \
      "${expected_arguments[$argument_index]}" ]] || return 1
  done

  curl_pid="$(<"$pid_file")"
  [[ "$curl_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  if kill -0 "$curl_pid" 2>/dev/null; then
    process_state="$(
      awk '$1 == "State:" { print $2; exit }' \
        "/proc/$curl_pid/status" 2>/dev/null || true
    )"
    [[ "$process_state" == "Z" ]] || return 1
  fi
)

test_delayed_otlp_run_identity_and_receiver_continuity() (
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-continuity"
  local -r nonce_counter="$result_dir/nonce-counter"
  local -r baseline="$result_dir/baseline.json"
  local -r reset="$result_dir/reset.json"
  local -r restarted="$result_dir/restarted.json"
  local -r malformed="$result_dir/malformed.json"
  local -r progress="$result_dir/progress.json"
  local -r receiver_instance_id="ABCDEFGHIJKLMNOPQRSTUVWX23"
  local -r next_receiver_instance_id="ZYXWVUTSRQPONMLKJIHGFEDC32"
  local -r reset_generation=7
  local expected_instance_id_base64=""
  local first_marker=""
  local second_marker=""
  local progress_output=""
  local invalid_filter=""
  local DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64="stale-instance"
  local DELAYED_OTLP_RECEIVER_RESET_GENERATION="99"
  local DELAYED_OTLP_PRIME_MARKER="$DELAYED_OTLP_PRIME_MARKER_PREFIX"

  mkdir -p -- "$result_dir"
  printf '0\n' >"$nonce_counter"
  delayed_otlp_run_nonce() {
    local counter=""

    counter="$(<"$nonce_counter")" || return $?
    case "$counter" in
      0) printf '00000000000000000000000000000001\n' ;;
      1) printf '00000000000000000000000000000002\n' ;;
      *) return 1 ;;
    esac
    printf '%s\n' "$((counter + 1))" >"$nonce_counter"
  }

  initialize_delayed_otlp_run_identity || return $?
  first_marker="$DELAYED_OTLP_PRIME_MARKER"
  [[ "$first_marker" == \
      "$DELAYED_OTLP_PRIME_MARKER_PREFIX-00000000000000000000000000000001" &&
    -z "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" &&
    -z "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" ]] || return 1

  DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64="stale-instance"
  DELAYED_OTLP_RECEIVER_RESET_GENERATION="100"
  initialize_delayed_otlp_run_identity || return $?
  second_marker="$DELAYED_OTLP_PRIME_MARKER"
  [[ "$second_marker" == \
      "$DELAYED_OTLP_PRIME_MARKER_PREFIX-00000000000000000000000000000002" &&
    "$second_marker" != "$first_marker" && ${#second_marker} -le 128 &&
    -z "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" &&
    -z "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" ]] || return 1

  delayed_otlp_run_nonce() { printf 'not-a-valid-nonce\n'; }
  if initialize_delayed_otlp_run_identity; then
    printf 'delayed OTLP run identity accepted a malformed nonce\n' >&2
    return 1
  fi
  [[ "$DELAYED_OTLP_PRIME_MARKER" == "$second_marker" &&
    -z "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" &&
    -z "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" ]] || return 1

  jq -cn \
    --arg marker "$DELAYED_OTLP_PRIME_MARKER" \
    --arg receiver_instance_id "$receiver_instance_id" \
    --argjson reset_generation "$reset_generation" '
      {
        receiver_instance_id: $receiver_instance_id,
        reset_generation: $reset_generation,
        marker: $marker,
        received_batches: 0,
        received_spans: 0,
        spans: []
      }
    ' >"$baseline"
  jq -c '.reset_generation += 1' "$baseline" >"$reset"
  jq -c --arg receiver_instance_id "$next_receiver_instance_id" \
    '.receiver_instance_id = $receiver_instance_id' "$baseline" >"$restarted"
  jq -c '.reset_generation = 9007199254740992' "$baseline" >"$malformed"

  jq -c --arg marker "$first_marker" '.marker = $marker' \
    "$baseline" >"$progress"
  if delayed_otlp_receiver_snapshot_is_empty "$progress"; then
    printf 'delayed OTLP receiver accepted an earlier run marker\n' >&2
    return 1
  fi

  capture_delayed_otlp_receiver_continuity "$baseline" || return $?
  expected_instance_id_base64="$(jq -nr --arg value "$receiver_instance_id" \
    '$value | @base64')" || return $?
  [[ "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" == \
      "$expected_instance_id_base64" &&
    "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" == "$reset_generation" ]] || return 1
  delayed_otlp_receiver_snapshot_has_expected_continuity "$baseline" || return $?
  if capture_delayed_otlp_receiver_continuity "$reset"; then
    printf 'delayed OTLP receiver continuity was silently recaptured\n' >&2
    return 1
  fi
  if delayed_otlp_receiver_snapshot_has_expected_continuity "$reset"; then
    printf 'delayed OTLP receiver accepted a reset generation change\n' >&2
    return 1
  fi
  if delayed_otlp_receiver_snapshot_has_expected_continuity "$restarted"; then
    printf 'delayed OTLP receiver accepted an instance change\n' >&2
    return 1
  fi
  if delayed_otlp_receiver_snapshot_has_expected_continuity "$malformed" 2>/dev/null; then
    printf 'delayed OTLP receiver accepted an inexact JSON generation\n' >&2
    return 1
  fi

  for invalid_filter in \
    'del(.receiver_instance_id)' \
    '.receiver_instance_id = ""' \
    'del(.reset_generation)' \
    '.reset_generation = 1.5' \
    '.reset_generation = "7"'; do
    jq -c "$invalid_filter" "$baseline" >"$malformed"
    if delayed_otlp_receiver_snapshot_has_expected_continuity \
      "$malformed" 2>/dev/null; then
      printf 'delayed OTLP receiver accepted malformed continuity: %s\n' \
        "$invalid_filter" >&2
      return 1
    fi
  done

  jq -cn \
    --arg marker "$DELAYED_OTLP_PRIME_MARKER" \
    --argjson maximum "$MAX_JSON_SAFE_INTEGER" '
      {
        marker: $marker,
        received_batches: $maximum,
        received_spans: $maximum,
        dropped_spans: 0,
        dropped_count_spans: 0,
        dropped_value_limit_spans: 0,
        dropped_retained_limit_spans: 0,
        spans: []
      }
    ' >"$progress"
  progress_output="$(delayed_otlp_receiver_snapshot_progress "$progress")" || return $?
  [[ "$progress_output" == \
    $MAX_JSON_SAFE_INTEGER$'\t'$MAX_JSON_SAFE_INTEGER$'\t0' ]] || return 1
  for invalid_filter in \
    '.received_batches = 9007199254740992' \
    '.received_spans = 9.007199254740992e15' \
    '.received_batches = -1' \
    '.received_spans = 1.5' \
    '.received_batches = "1"'; do
    jq -c "$invalid_filter" "$progress" >"$malformed"
    if delayed_otlp_receiver_snapshot_progress "$malformed" >/dev/null 2>&1; then
      printf 'delayed OTLP receiver accepted an inexact counter: %s\n' \
        "$invalid_filter" >&2
      return 1
    fi
  done
)

test_delayed_otlp_pre_export_evidence_is_atomic() (
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-pre-export-atomic"
  local -r baseline="$result_dir/baseline.json"
  local -r multi_document="$result_dir/multi-document.json"
  local -r reset="$result_dir/reset.json"
  local -r malformed="$result_dir/malformed.json"
  local -r output="$result_dir/before-request.json"
  local -r missing_output="$result_dir/missing-before-request.json"
  local -r reset_output="$result_dir/before-export-reset.json"
  local -r malformed_output="$result_dir/before-request-malformed.json"
  local -r multi_baseline_output="$result_dir/before-request-multi.json"
  local -r multi_pre_export_output="$result_dir/before-export-multi.json"
  local DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64=""
  local DELAYED_OTLP_RECEIVER_RESET_GENERATION=""
  local failure_status=0

  mkdir -p -- "$result_dir"
  RESULT_DIR="$result_dir"
  jq -cn \
    --arg marker "$DELAYED_OTLP_PRIME_MARKER" '
      {
        receiver_instance_id: "ABCDEFGHIJKLMNOPQRSTUVWX23",
        reset_generation: 7,
        marker: $marker,
        received_batches: 0,
        received_spans: 0,
        spans: []
      }
    ' >"$baseline"
  jq -c '.' "$baseline" "$baseline" >"$multi_document"
  jq -c '.reset_generation += 1' "$baseline" >"$reset"
  printf '{"receiver_instance_id":' >"$malformed"
  printf 'existing\n' >"$output"
  fetch_delayed_otlp_receiver_snapshot() {
    [[ "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" == "$1" ]] || return 1
    printf 'partial\n' >"$1"
    return 23
  }
  if assert_delayed_otlp_receiver_empty "$output" >/dev/null 2>&1; then
    printf 'delayed OTLP baseline ignored a partial fetch failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "23" && "$(<"$output")" == "existing" &&
    -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]] || return 1

  if assert_delayed_otlp_receiver_empty "$missing_output" >/dev/null 2>&1; then
    printf 'delayed OTLP missing baseline ignored a partial fetch failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "23" && ! -e "$missing_output" &&
    -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]] || return 1

  fetch_delayed_otlp_receiver_snapshot() {
    install -m 0644 "$multi_document" "$1"
  }
  log_error() { :; }
  if assert_delayed_otlp_receiver_empty "$multi_baseline_output"; then
    printf 'delayed OTLP baseline accepted a multi-document snapshot\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    -z "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" &&
    -z "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" &&
    -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]] || return 1
  cmp -s -- "$multi_document" "$multi_baseline_output" || return 1

  fetch_delayed_otlp_receiver_snapshot() {
    install -m 0644 "$baseline" "$1"
  }
  assert_delayed_otlp_receiver_empty "$output" || return $?
  [[ "$(<"$output")" == "$(<"$baseline")" &&
    "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" == \
      "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYMjM=" &&
    "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" == "7" &&
    -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]] || return 1

  fetch_delayed_otlp_receiver_snapshot() {
    install -m 0644 "$multi_document" "$1"
  }
  if assert_delayed_otlp_receiver_has_no_java_export \
    "$multi_pre_export_output"; then
    printf 'delayed OTLP pre-export check accepted a multi-document snapshot\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    "$DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64" == \
      "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYMjM=" &&
    "$DELAYED_OTLP_RECEIVER_RESET_GENERATION" == "7" &&
    -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]] || return 1
  cmp -s -- "$multi_document" "$multi_pre_export_output" || return 1

  fetch_delayed_otlp_receiver_snapshot() {
    install -m 0644 "$reset" "$1"
  }
  if assert_delayed_otlp_receiver_has_no_java_export "$reset_output"; then
    printf 'delayed OTLP pre-export evidence accepted a reset\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    "$(<"$reset_output")" == "$(<"$reset")" &&
    -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]] || return 1

  DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64=""
  DELAYED_OTLP_RECEIVER_RESET_GENERATION=""
  fetch_delayed_otlp_receiver_snapshot() {
    install -m 0644 "$malformed" "$1"
  }
  if assert_delayed_otlp_receiver_empty "$malformed_output" >/dev/null 2>&1; then
    printf 'delayed OTLP baseline accepted malformed JSON\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    "$(<"$malformed_output")" == "$(<"$malformed")" &&
    -z "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" ]]
)

test_delayed_otlp_receiver_snapshots_prove_export_boundary() {
  local -r snapshot="$TEST_TMP_DIR/delayed-otlp-receiver.json"
  local -r duplicate_snapshot="$TEST_TMP_DIR/delayed-otlp-receiver-duplicate.json"

  printf '{"marker":"%s","received_batches":0,"received_spans":0,"spans":[]}' \
    "$DELAYED_OTLP_PRIME_MARKER" >"$snapshot"
  delayed_otlp_receiver_snapshot_is_empty "$snapshot" || {
    printf 'delayed OTLP receiver rejected an empty startup snapshot\n' >&2
    return 1
  }
  if delayed_otlp_receiver_snapshot_has_java_export "$snapshot"; then
    printf 'delayed OTLP receiver treated an empty snapshot as a Java export\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":1,"received_spans":2,"spans":[{"service_name":"apache","kind":"CLIENT","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"}},{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000}]}' >"$snapshot"
  delayed_otlp_receiver_snapshot_has_java_export "$snapshot" || {
    printf 'delayed OTLP receiver rejected the marked Java server export\n' >&2
    return 1
  }
  if delayed_otlp_receiver_snapshot_has_no_java_export "$snapshot"; then
    printf 'delayed OTLP receiver missed the marked Java SDK export\n' >&2
    return 1
  fi
  if delayed_otlp_receiver_snapshot_is_empty "$snapshot"; then
    printf 'delayed OTLP receiver accepted an early export snapshot\n' >&2
    return 1
  fi
  delayed_otlp_receiver_snapshot_has_java_export_before_deadline "$snapshot" 101001 || {
    printf 'delayed OTLP receiver missed an early receipt timestamp\n' >&2
    return 1
  }
  delayed_otlp_receiver_snapshot_has_java_export_at_or_after_deadline "$snapshot" 101000 || {
    printf 'delayed OTLP receiver rejected a receipt timestamp at its deadline\n' >&2
    return 1
  }
  jq -c '
    .received_batches = 2 |
    .received_spans = 2 |
    .spans += [(.spans[1] | .trace_id = "00112233445566778899aabbccddeeff" |
      .span_id = "0011223344556677")]
  ' "$snapshot" >"$duplicate_snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export "$duplicate_snapshot"; then
    printf 'delayed OTLP receiver accepted duplicate Java SDK exports\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":1,"received_spans":1,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"}}]}' >"$snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export "$snapshot"; then
    printf 'delayed OTLP receiver accepted a Java server without a receipt timestamp\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":4,"spans":[{"service_name":"apache","kind":"CLIENT","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"}}]}' >"$snapshot"
  if ! delayed_otlp_receiver_snapshot_has_no_java_export "$snapshot"; then
    printf 'Apache-only delayed OTLP snapshot unexpectedly had a Java SDK export\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":1,"received_spans":1,"spans":[{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"other-request"}}]}' >"$snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export "$snapshot"; then
    printf 'delayed OTLP receiver accepted a Java export from another request\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":1,"received_spans":1,"spans":[{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"}}]}' >"$snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export "$snapshot"; then
    printf 'delayed OTLP receiver accepted an unscoped Java server span\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000},{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"start_unix_nano":100998000000,"end_unix_nano":100999000000,"received_unix_milli":101001}]}' >"$snapshot"
  delayed_otlp_receiver_snapshot_has_java_export "$snapshot" || {
    printf 'delayed OTLP receiver rejected the expected pre-detection OBI Java span\n' >&2
    return 1
  }
  delayed_otlp_receiver_snapshot_has_java_export_at_or_after_deadline "$snapshot" 101000 || {
    printf 'delayed OTLP receiver rejected a pre-deadline OBI span delivered after the SDK batch\n' >&2
    return 1
  }

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000},{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101001}]}' >"$snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export_at_or_after_deadline "$snapshot" 101000; then
    printf 'delayed OTLP receiver accepted a pre-detection OBI span without its lifetime\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":3,"received_spans":3,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000},{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":100999},{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":100998}]}' >"$snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export "$snapshot"; then
    printf 'delayed OTLP receiver accepted duplicate pre-detection OBI Java spans\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000},{"service_name":"java-backend","scope_name":"other.java.instrumentation","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":100999}]}' >"$snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export "$snapshot"; then
    printf 'delayed OTLP receiver accepted a Java server from another scope\n' >&2
    return 1
  fi

  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000},{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"start_unix_nano":100999000000,"end_unix_nano":101000000000,"received_unix_milli":101001}]}' >"$snapshot"
  if delayed_otlp_receiver_snapshot_has_java_export_at_or_after_deadline "$snapshot" 101000; then
    printf 'delayed OTLP receiver accepted an OBI Java span completed at the export boundary\n' >&2
    return 1
  fi
}

test_delayed_otlp_receiver_wait_enforces_export_deadline() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-receiver-deadline"
  local -r empty_fixture="$result_dir/java-export-empty.json"
  local -r early_fixture="$result_dir/java-export-early.json"
  local -r sdk_fixture="$result_dir/java-export-sdk.json"
  local -r obi_first_fixture="$result_dir/java-export-obi-first.json"
  local -r advanced_sdk_fixture="$result_dir/java-export-sdk-advanced.json"
  local -r ready_fixture="$result_dir/java-export-ready.json"
  local -r unexpected_fixture="$result_dir/java-export-unexpected.json"
  local -r duplicate_fixture="$result_dir/java-export-duplicate.json"
  local -r dropped_receiver_fixture="$result_dir/java-export-receiver-drop.json"
  local -r omitted_receiver_fixture="$result_dir/java-export-receiver-omission.json"
  local -r counter_regression_fixture="$result_dir/java-export-counter-regression.json"
  local -r dropped_obi_fixture="$result_dir/java-export-dropped-obi.json"
  local -r reset_fixture="$result_dir/java-export-reset.json"
  local -r restart_fixture="$result_dir/java-export-restart.json"
  local -r malformed_fixture="$result_dir/java-export-malformed.json"
  local -r multi_discovery_fixture="$result_dir/java-export-multi-discovery.json"
  local -r multi_settlement_fixture="$result_dir/java-export-multi-settlement.json"
  local -r multi_final_fixture="$result_dir/java-export-multi-final.json"
  local -r simulated_phase_seconds=100
  local -r receiver_instance_id="ABCDEFGHIJKLMNOPQRSTUVWX23"
  local -r next_receiver_instance_id="ZYXWVUTSRQPONMLKJIHGFEDC32"
  local -r reset_generation=7
  local DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64=""
  local DELAYED_OTLP_RECEIVER_RESET_GENERATION="$reset_generation"
  local metadata_fixture=""
  local metadata_name=""
  local normalized_fixture=""
  local receiver_fixture=""
  local failure_status=0

  mkdir -p -- "$result_dir"
  DELAYED_OTLP_RECEIVER_INSTANCE_ID_BASE64="$(
    jq -nr --arg value "$receiver_instance_id" '$value | @base64'
  )" || return $?
  printf '{"marker":"%s","received_batches":0,"received_spans":0,"spans":[]}' \
    "$DELAYED_OTLP_PRIME_MARKER" >"$empty_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":1,"received_spans":1,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":100999}]}' >"$early_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":1,"received_spans":1,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000}]}' >"$sdk_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":1,"received_spans":1,"spans":[{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"start_unix_nano":100998000000,"end_unix_nano":100999000000,"received_unix_milli":101001}]}' \
    >"$obi_first_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000}]}' >"$advanced_sdk_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000},{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"start_unix_nano":100998000000,"end_unix_nano":100999000000,"received_unix_milli":101001}]}' >"$ready_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000},{"service_name":"java-backend","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"start_unix_nano":100999000000,"end_unix_nano":101000000000,"received_unix_milli":101001}]}' >"$unexpected_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":3,"received_spans":3,"ambiguous_related_spans":1,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000}]}' >"$duplicate_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"dropped_spans":1,"dropped_value_limit_spans":1,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000}]}' >"$dropped_receiver_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":2,"received_spans":2,"omitted_related_spans":1,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000}]}' >"$omitted_receiver_fixture"
  command cp -- "$sdk_fixture" "$counter_regression_fixture"
  printf '%s' \
    '{"marker":"' "$DELAYED_OTLP_PRIME_MARKER" \
    '","received_batches":3,"received_spans":3,"spans":[{"service_name":"java-backend","scope_name":"' \
    "$DELAYED_OTLP_JAVA_SERVER_SCOPE" \
    '","kind":"SERVER","attributes":{"http.request.header.x-obi-demo-id":"' \
    "$DELAYED_OTLP_PRIME_MARKER" \
    '"},"received_unix_milli":101000}]}' >"$dropped_obi_fixture"

  for receiver_fixture in \
    "$empty_fixture" \
    "$early_fixture" \
    "$sdk_fixture" \
    "$obi_first_fixture" \
    "$advanced_sdk_fixture" \
    "$ready_fixture" \
    "$unexpected_fixture" \
    "$duplicate_fixture" \
    "$dropped_receiver_fixture" \
    "$omitted_receiver_fixture" \
    "$counter_regression_fixture" \
    "$dropped_obi_fixture"; do
    normalized_fixture="$receiver_fixture.normalized"
    jq -c \
      --arg receiver_instance_id "$receiver_instance_id" \
      --argjson reset_generation "$reset_generation" '
      . + {
        receiver_instance_id: $receiver_instance_id,
        reset_generation: $reset_generation,
        dropped_spans: (.dropped_spans // 0),
        dropped_count_spans: (.dropped_count_spans // 0),
        dropped_value_limit_spans: (.dropped_value_limit_spans // 0),
        dropped_retained_limit_spans: (.dropped_retained_limit_spans // 0)
      }
    ' "$receiver_fixture" >"$normalized_fixture"
    command mv -f -- "$normalized_fixture" "$receiver_fixture"
  done
  jq -c '.reset_generation += 1' "$sdk_fixture" >"$reset_fixture"
  jq -c --arg receiver_instance_id "$next_receiver_instance_id" \
    '.receiver_instance_id = $receiver_instance_id' \
    "$empty_fixture" >"$restart_fixture"
  printf '{"receiver_instance_id":' >"$malformed_fixture"
  jq -c '.' "$empty_fixture" "$sdk_fixture" >"$multi_discovery_fixture"
  jq -c '.' "$ready_fixture" "$ready_fixture" >"$multi_settlement_fixture"
  jq -c '.' "$advanced_sdk_fixture" "$sdk_fixture" >"$multi_final_fixture"

  if (
    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      install -m 0644 "$early_fixture" "$1"
    }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/ready-early.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/early.json" "$result_dir/unexpected-early.json" \
      "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted an export before its deadline\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/ready-early.json" &&
    ! -e "$result_dir/unexpected-early.json" &&
    "$(<"$result_dir/early.json")" == "$(<"$early_fixture")" ]] || {
    printf 'delayed OTLP receiver did not retain the early export evidence\n' >&2
    return 1
  }

  (
    local -i fetch_calls=0
    local -i sleep_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      [[ "$DELAYED_OTLP_RECEIVER_SNAPSHOT_TEMP" == "$1" ]] || return 1
      case "$fetch_calls" in
        1)
          [[ "$2" == "10" ]] || return 1
          install -m 0644 "$empty_fixture" "$1"
          ;;
        2)
          [[ "$2" == "1" ]] || return 1
          install -m 0644 "$sdk_fixture" "$1"
          ;;
        3)
          [[ "$2" == "1" ]] || return 1
          install -m 0644 "$ready_fixture" "$1"
          ;;
        *) return 1 ;;
      esac
    }
    sleep() {
      ((sleep_calls += 1))
      SECONDS="$((SECONDS + simulated_phase_seconds))"
    }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/ready-boundary.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/early-boundary.json" \
      "$result_dir/unexpected-boundary.json" "$simulated_phase_seconds"
    [[ "$fetch_calls" == "3" && "$sleep_calls" == "2" ]]
  ) || {
    printf 'delayed OTLP receiver missed a boundary export or final settlement poll\n' >&2
    return 1
  }
  [[ "$(<"$result_dir/ready-boundary.json")" == "$(<"$ready_fixture")" &&
    ! -e "$result_dir/early-boundary.json" &&
    ! -e "$result_dir/unexpected-boundary.json" ]] || return 1

  (
    local -i fetch_calls=0
    local -i sleep_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$obi_first_fixture" "$1" ;;
        2 | 3) install -m 0644 "$ready_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() {
      ((sleep_calls += 1))
      if ((sleep_calls == 1)); then
        SECONDS="$((SECONDS + 1))"
      else
        SECONDS="$((SECONDS + simulated_phase_seconds))"
      fi
    }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/obi-first-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/obi-first-early.json" \
      "$result_dir/obi-first-unexpected.json" "$simulated_phase_seconds"
    [[ "$fetch_calls" == "3" && "$sleep_calls" == "2" ]]
  ) || {
    printf 'delayed OTLP receiver rejected OBI-before-SDK batch order\n' >&2
    return 1
  }
  [[ "$(<"$result_dir/obi-first-ready.json")" == "$(<"$ready_fixture")" &&
    ! -e "$result_dir/obi-first-early.json" &&
    ! -e "$result_dir/obi-first-unexpected.json" ]] || return 1

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      [[ "$fetch_calls" == "1" && "$2" == "10" ]] || return 91
      install -m 0644 "$multi_discovery_fixture" "$1"
    }
    sleep() { return 47; }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/multi-discovery-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/multi-discovery-early.json" \
      "$result_dir/multi-discovery-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a multi-document discovery snapshot\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    ! -e "$result_dir/multi-discovery-ready.json" &&
    ! -e "$result_dir/multi-discovery-early.json" ]] || return 1
  cmp -s -- "$multi_discovery_fixture" \
    "$result_dir/multi-discovery-unexpected.json" || return 1

  if (
    local -i fetch_calls=0
    local -i sleep_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      [[ "$2" == "10" ]] || return 91
      case "$fetch_calls" in
        1) install -m 0644 "$sdk_fixture" "$1" ;;
        2) install -m 0644 "$multi_settlement_fixture" "$1" ;;
        *) return 91 ;;
      esac
    }
    sleep() {
      ((sleep_calls += 1))
      if [[ "$sleep_calls" == "1" ]]; then
        SECONDS="$((SECONDS + 1))"
      else
        return 47
      fi
    }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/multi-settlement-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/multi-settlement-early.json" \
      "$result_dir/multi-settlement-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a multi-document settlement snapshot\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    ! -e "$result_dir/multi-settlement-ready.json" &&
    ! -e "$result_dir/multi-settlement-early.json" ]] || return 1
  cmp -s -- "$multi_settlement_fixture" \
    "$result_dir/multi-settlement-unexpected.json" || return 1

  if (
    local -i fetch_calls=0
    local -i sleep_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1)
          [[ "$2" == "10" ]] || return 91
          install -m 0644 "$sdk_fixture" "$1"
          ;;
        2)
          [[ "$2" == "1" ]] || return 91
          install -m 0644 "$multi_final_fixture" "$1"
          ;;
        *) return 91 ;;
      esac
    }
    sleep() {
      ((sleep_calls += 1))
      [[ "$sleep_calls" == "1" ]] || return 47
      SECONDS="$((SECONDS + simulated_phase_seconds))"
    }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/multi-final-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/multi-final-early.json" \
      "$result_dir/multi-final-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a multi-document final snapshot\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    ! -e "$result_dir/multi-final-ready.json" &&
    ! -e "$result_dir/multi-final-early.json" ]] || return 1
  cmp -s -- "$multi_final_fixture" \
    "$result_dir/multi-final-unexpected.json" || return 1

  if (
    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      install -m 0644 "$restart_fixture" "$1"
    }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/restart-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/restart-early.json" "$result_dir/restart-unexpected.json" \
      "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a restarted discovery snapshot\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/restart-ready.json" &&
    ! -e "$result_dir/restart-early.json" &&
    "$(<"$result_dir/restart-unexpected.json")" == \
      "$(<"$restart_fixture")" ]] || {
    printf 'delayed OTLP receiver did not retain restart evidence\n' >&2
    return 1
  }

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$sdk_fixture" "$1" ;;
        2) install -m 0644 "$reset_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/reset-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/reset-early.json" "$result_dir/reset-unexpected.json" \
      "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a reset during settlement\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/reset-ready.json" &&
    ! -e "$result_dir/reset-early.json" &&
    "$(<"$result_dir/reset-unexpected.json")" == "$(<"$reset_fixture")" ]] || {
    printf 'delayed OTLP receiver did not retain reset evidence\n' >&2
    return 1
  }

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$sdk_fixture" "$1" ;;
        2) install -m 0644 "$malformed_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/malformed-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/malformed-early.json" \
      "$result_dir/malformed-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted malformed settlement JSON\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/malformed-ready.json" &&
    ! -e "$result_dir/malformed-early.json" &&
    "$(<"$result_dir/malformed-unexpected.json")" == \
      "$(<"$malformed_fixture")" ]] || return 1

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      install -m 0644 "$empty_fixture" "$1"
    }
    sleep() {
      SECONDS="$((
        SECONDS + simulated_phase_seconds +
          DELAYED_OTLP_BOUNDARY_START_SLACK_SECONDS + 1
      ))"
    }
    log_error() { :; }

    if wait_for_delayed_otlp_receiver_export \
      "$result_dir/overshoot-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/overshoot-early.json" "$result_dir/overshoot-unexpected.json" \
      "$simulated_phase_seconds"; then
      return 1
    fi
    [[ "$fetch_calls" == "1" ]]
  ) >/dev/null 2>&1; then
    :
  else
    printf 'delayed OTLP receiver reopened an expired final-poll deadline\n' >&2
    return 1
  fi
  [[ ! -e "$result_dir/overshoot-ready.json" &&
    ! -e "$result_dir/overshoot-early.json" &&
    "$(<"$result_dir/overshoot-unexpected.json")" == \
      "$(<"$empty_fixture")" ]] || return 1

  if (
    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() { return 19; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/discovery-fetch.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/discovery-fetch-early.json" \
      "$result_dir/discovery-fetch-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored a discovery fetch failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "19" && ! -e "$result_dir/discovery-fetch.json" &&
    ! -e "$result_dir/discovery-fetch-early.json" &&
    ! -e "$result_dir/discovery-fetch-unexpected.json" ]] || return 1

  if (
    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      install -m 0644 "$empty_fixture" "$1"
    }
    sleep() { return 21; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/discovery-sleep.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/discovery-sleep-early.json" \
      "$result_dir/discovery-sleep-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored a discovery sleep failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "21" && ! -e "$result_dir/discovery-sleep.json" &&
    ! -e "$result_dir/discovery-sleep-early.json" &&
    ! -e "$result_dir/discovery-sleep-unexpected.json" ]] || return 1

  (
    local -i fetch_calls=0
    local -i sleep_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1)
          [[ "$2" == "3" ]] || return 1
          install -m 0644 "$empty_fixture" "$1" || return $?
          SECONDS="$((SECONDS + 3))"
          ;;
        2)
          [[ "$2" == "1" ]] || return 1
          install -m 0644 "$empty_fixture" "$1"
          ;;
        *) return 1 ;;
      esac
    }
    sleep() { ((sleep_calls += 1)); }
    log_error() { :; }

    if wait_for_delayed_otlp_receiver_export \
      "$result_dir/discovery-deadline.json" 3 101000 \
      "$result_dir/discovery-deadline-early.json" \
      "$result_dir/discovery-deadline-unexpected.json" 1; then
      return 1
    fi
    [[ "$fetch_calls" == "2" && "$sleep_calls" == "0" ]] && ((SECONDS >= 3))
  ) || {
    printf 'delayed OTLP receiver did not cap discovery fetch by its deadline\n' >&2
    return 1
  }
  [[ ! -e "$result_dir/discovery-deadline.json" &&
    ! -e "$result_dir/discovery-deadline-early.json" &&
    "$(<"$result_dir/discovery-deadline-unexpected.json")" == \
      "$(<"$empty_fixture")" ]] || {
    printf 'delayed OTLP receiver did not retain missing-export evidence\n' >&2
    return 1
  }

  (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$sdk_fixture" "$1" ;;
        2) install -m 0644 "$ready_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() {
      SECONDS="$((
        SECONDS + simulated_phase_seconds +
          DELAYED_OTLP_BOUNDARY_START_SLACK_SECONDS
      ))"
    }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/early-success.json" "$result_dir/unexpected-success.json" \
      "$simulated_phase_seconds"
    [[ "$fetch_calls" == "2" ]]
  ) || {
    printf 'delayed OTLP receiver rejected a valid later OBI batch\n' >&2
    return 1
  }
  [[ "$(<"$result_dir/ready.json")" == "$(<"$ready_fixture")" &&
    ! -e "$result_dir/early-success.json" &&
    ! -e "$result_dir/unexpected-success.json" ]] || {
    printf 'delayed OTLP receiver did not retain the deadline-ready snapshot\n' >&2
    return 1
  }

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$sdk_fixture" "$1" ;;
        2) install -m 0644 "$early_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/ready-settlement-early.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/settlement-early.json" \
      "$result_dir/unexpected-settlement-early.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a later early SDK export\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    ! -e "$result_dir/ready-settlement-early.json" &&
    ! -e "$result_dir/unexpected-settlement-early.json" &&
    "$(<"$result_dir/settlement-early.json")" == "$(<"$early_fixture")" ]] || {
    printf 'delayed OTLP receiver did not retain settlement early evidence\n' >&2
    return 1
  }

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) command cp -- "$sdk_fixture" "$1" ;;
        2) command cp -- "$early_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    install() {
      [[ "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" == "$4" ]] || return 42
      printf 'partial\n' >"$4"
      return 43
    }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/early-install-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/early-install-failure.json" \
      "$result_dir/early-install-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored settlement early publication failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "43" &&
    ! -e "$result_dir/early-install-ready.json" &&
    ! -e "$result_dir/early-install-failure.json" &&
    ! -e "$result_dir/early-install-unexpected.json" &&
    -z "$(find "$result_dir" -maxdepth 1 \
      -name '.early-install-failure.json.*' -print -quit)" ]] || return 1

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$sdk_fixture" "$1" ;;
        2) install -m 0644 "$unexpected_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/ready-unexpected.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/early-unexpected.json" "$result_dir/unexpected.json" \
      "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a post-boundary OBI span\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/ready-unexpected.json" &&
    ! -e "$result_dir/early-unexpected.json" &&
    "$(<"$result_dir/unexpected.json")" == "$(<"$unexpected_fixture")" ]] || {
    printf 'delayed OTLP receiver did not retain the unexpected span evidence\n' >&2
    return 1
  }

  for metadata_name in ambiguous dropped omitted; do
    case "$metadata_name" in
      ambiguous) metadata_fixture="$duplicate_fixture" ;;
      dropped) metadata_fixture="$dropped_receiver_fixture" ;;
      omitted) metadata_fixture="$omitted_receiver_fixture" ;;
      *) return 1 ;;
    esac
    failure_status=0
    if (
      local -i fetch_calls=0

      RESULT_DIR="$result_dir"
      SECONDS=0
      fetch_delayed_otlp_receiver_snapshot() {
        ((fetch_calls += 1))
        case "$fetch_calls" in
          1) install -m 0644 "$sdk_fixture" "$1" ;;
          2) install -m 0644 "$metadata_fixture" "$1" ;;
          *) return 1 ;;
        esac
      }
      sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
      log_error() { :; }

      wait_for_delayed_otlp_receiver_export \
        "$result_dir/ready-$metadata_name.json" \
        "$simulated_phase_seconds" 101000 \
        "$result_dir/early-$metadata_name.json" \
        "$result_dir/$metadata_name.json" "$simulated_phase_seconds"
    ) >/dev/null 2>&1; then
      printf 'delayed OTLP receiver accepted %s receiver metadata\n' \
        "$metadata_name" >&2
      return 1
    else
      failure_status=$?
    fi
    [[ "$failure_status" == "1" &&
      ! -e "$result_dir/ready-$metadata_name.json" &&
      ! -e "$result_dir/early-$metadata_name.json" &&
      "$(<"$result_dir/$metadata_name.json")" == \
        "$(<"$metadata_fixture")" ]] || {
      printf 'delayed OTLP receiver did not retain %s metadata evidence\n' \
        "$metadata_name" >&2
      return 1
    }
  done

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$advanced_sdk_fixture" "$1" ;;
        2) install -m 0644 "$counter_regression_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/ready-counter-regression.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/early-counter-regression.json" \
      "$result_dir/counter-regression.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted decreasing cumulative counters\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" &&
    ! -e "$result_dir/ready-counter-regression.json" &&
    ! -e "$result_dir/early-counter-regression.json" &&
    "$(<"$result_dir/counter-regression.json")" == \
      "$(<"$counter_regression_fixture")" ]] || return 1

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$ready_fixture" "$1" ;;
        2) install -m 0644 "$dropped_obi_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    log_error() { :; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/ready-dropped-obi.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/early-dropped-obi.json" "$result_dir/dropped-obi.json" \
      "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver accepted a disappearing startup OBI span\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "1" && ! -e "$result_dir/ready-dropped-obi.json" &&
    ! -e "$result_dir/early-dropped-obi.json" &&
    "$(<"$result_dir/dropped-obi.json")" == "$(<"$dropped_obi_fixture")" ]] || {
    printf 'delayed OTLP receiver did not retain cumulative regression evidence\n' >&2
    return 1
  }

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) command cp -- "$sdk_fixture" "$1" ;;
        2) command cp -- "$unexpected_fixture" "$1" ;;
        *) return 1 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    install() {
      [[ "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" == "$4" ]] || return 28
      printf 'partial\n' >"$4"
      return 29
    }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/unexpected-install-ready.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/unexpected-install-early.json" \
      "$result_dir/unexpected-install.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored an unexpected-evidence publication failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "29" &&
    ! -e "$result_dir/unexpected-install-ready.json" &&
    ! -e "$result_dir/unexpected-install-early.json" &&
    ! -e "$result_dir/unexpected-install.json" &&
    -z "$(find "$result_dir" -maxdepth 1 \
      -name '.unexpected-install.json.*' -print -quit)" ]] || {
    printf 'delayed OTLP receiver did not fail closed on unexpected-evidence publication\n' >&2
    return 1
  }

  if (
    local -i fetch_calls=0

    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      ((fetch_calls += 1))
      case "$fetch_calls" in
        1) install -m 0644 "$sdk_fixture" "$1" ;;
        *) return 23 ;;
      esac
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/fetch-failure.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/fetch-early.json" "$result_dir/fetch-unexpected.json" \
      "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored a settlement snapshot fetch failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "23" && ! -e "$result_dir/fetch-failure.json" &&
    ! -e "$result_dir/fetch-early.json" &&
    ! -e "$result_dir/fetch-unexpected.json" ]] || {
    printf 'delayed OTLP receiver did not fail closed on a settlement snapshot gap\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      command cp -- "$sdk_fixture" "$1"
    }
    sleep() { SECONDS="$((SECONDS + simulated_phase_seconds))"; }
    install() {
      [[ "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" == "$4" ]] || return 30
      printf 'partial\n' >"$4"
      return 31
    }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/final-install-failure.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/final-install-early.json" \
      "$result_dir/final-install-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored final evidence publication failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "31" &&
    ! -e "$result_dir/final-install-failure.json" &&
    ! -e "$result_dir/final-install-early.json" &&
    ! -e "$result_dir/final-install-unexpected.json" &&
    -z "$(find "$result_dir" -maxdepth 1 \
      -name '.final-install-failure.json.*' -print -quit)" ]] || {
    printf 'delayed OTLP receiver did not fail closed on final evidence publication\n' >&2
    return 1
  }

  printf 'existing\n' >"$result_dir/final-move-failure.json"
  if (
    mv() {
      [[ "$DELAYED_OTLP_RECEIVER_PUBLICATION_TEMP" == "$3" ]] || return 40
      return 41
    }

    publish_delayed_otlp_receiver_snapshot \
      "$sdk_fixture" "$result_dir/final-move-failure.json"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored final evidence move failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "41" &&
    "$(<"$result_dir/final-move-failure.json")" == "existing" &&
    -z "$(find "$result_dir" -maxdepth 1 \
      -name '.final-move-failure.json.*' -print -quit)" ]] || {
    printf 'delayed OTLP receiver did not preserve atomic output on move failure\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$result_dir"
    SECONDS=0
    fetch_delayed_otlp_receiver_snapshot() {
      install -m 0644 "$sdk_fixture" "$1"
    }
    sleep() { return 37; }

    wait_for_delayed_otlp_receiver_export \
      "$result_dir/settle-sleep-failure.json" "$simulated_phase_seconds" 101000 \
      "$result_dir/settle-sleep-early.json" \
      "$result_dir/settle-sleep-unexpected.json" "$simulated_phase_seconds"
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP receiver ignored settlement sleep failure\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "37" &&
    ! -e "$result_dir/settle-sleep-failure.json" &&
    ! -e "$result_dir/settle-sleep-early.json" &&
    ! -e "$result_dir/settle-sleep-unexpected.json" ]] || {
    printf 'delayed OTLP receiver did not preserve settlement sleep failure\n' >&2
    return 1
  }
}

test_delayed_otlp_suppression_control_has_one_pre_export_request() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-suppression"
  local -r observed="$result_dir/observed"
  local -r expected="$result_dir/expected"

  mkdir -p -- "$result_dir"
  (
    local -i absence_calls=0
    local -i request_calls=0
    local -i receiver_empty_calls=0
    local -i sleep_calls=0

    RESULT_DIR="$result_dir"
    SCENARIO=delayed-otlp-suppression
    TRANSPORT=getsockopt
    SCENARIO_VARIANT=""
    DELAYED_OTLP_PROVIDER_READY_SINCE="provider-cursor"
    delayed_otlp_earliest_export_millisecond() {
      printf '900000\n'
    }
    delayed_otlp_run_nonce() {
      printf '00000000000000000000000000000003\n'
    }
    assert_delayed_otlp_receiver_empty() {
      case "$receiver_empty_calls" in
        0) [[ "$request_calls" == "0" && "$absence_calls" == "0" ]] || return 1 ;;
        *) return 1 ;;
      esac
      printf 'receiver-empty:%s\n' "${1##*/}" >>"$observed"
      ((receiver_empty_calls += 1))
    }
    assert_delayed_otlp_receiver_has_no_java_export() {
      [[ "$request_calls" == "1" && "$absence_calls" == "1" &&
        "$receiver_empty_calls" == "1" ]] || return 1
      printf 'receiver-no-java:%s\n' "${1##*/}" >>"$observed"
    }
    assert_java_duplicate_suppression_absent() {
      case "$absence_calls" in
        0) [[ "$request_calls" == "0" ]] || return 1 ;;
        1) [[ "$request_calls" == "1" ]] || return 1 ;;
        *) return 1 ;;
      esac
      printf 'absent:%s\n' "${1##*/}" >>"$observed"
      ((absence_calls += 1))
    }
    assert_delayed_otlp_pre_export_window() {
      [[ "$request_calls" == "1" && "$absence_calls" == "1" &&
        "$2" == "900000" ]] || return 1
      printf 'window:%s\n' "${1##*/}" >>"$observed"
    }
    run_bounded() {
      [[ "$1" == "10" && "$2" == "curl" &&
        "$*" == *"$APACHE_HTTPS_HEALTH_ENDPOINT"* &&
        "$*" == *"x-obi-demo-id: $DELAYED_OTLP_PRIME_MARKER"* ]] || return 1
      ((request_calls += 1))
      [[ "$request_calls" == "1" ]] || return 1
      printf 'prime\n' >>"$observed"
    }
    sleep() {
      case "$sleep_calls" in
        0)
          [[ "$1" == "$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" &&
            "$request_calls" == "0" && "$absence_calls" == "1" &&
            "$receiver_empty_calls" == "1" ]] || return 1
          ;;
        1)
          [[ "$1" == "$DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS" &&
            "$request_calls" == "1" && "$absence_calls" == "1" &&
            "$receiver_empty_calls" == "1" ]] || return 1
          ;;
        *) return 1 ;;
      esac
      printf 'sleep:%s\n' "$1" >>"$observed"
      ((sleep_calls += 1))
    }
    wait_for_log() {
      [[ "$1" == "java-backend" &&
        "$2" == "OBI remote-parent provider ready" &&
        "$3" == "delayed-otlp-suppression injected Java helper" &&
        "$4" == "provider-cursor" && "$request_calls" == "1" ]] || return 1
      printf 'provider-ready\n' >>"$observed"
    }
    wait_for_delayed_otlp_receiver_export() {
      [[ "$request_calls" == "1" && "$absence_calls" == "2" &&
        "$receiver_empty_calls" == "1" && "$2" == \
          "$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS" && "$3" == "900000" &&
        "${4##*/}" == "delayed-otlp-receiver-early.json" &&
        "${5##*/}" == "delayed-otlp-receiver-unexpected.json" &&
        "$6" == "$DELAYED_OTLP_POST_EXPORT_SETTLE_SECONDS" ]] || return 1
      printf 'receiver-ready:%s\n' "${1##*/}" >>"$observed"
    }
    wait_for_java_duplicate_suppression_without_prime() {
      [[ "$request_calls" == "1" && "$absence_calls" == "2" &&
        "$receiver_empty_calls" == "1" &&
        "$2" == "$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS" ]] || return 1
      printf 'ready:%s\n' "${1##*/}" >>"$observed"
    }
    assert_selected_transport() {
      [[ "$request_calls" == "1" && "$absence_calls" == "2" ]] || return 1
      printf 'transport\n' >>"$observed"
    }
    assert_runtime_contract() {
      [[ "$1" == "delayed-otlp-suppression" && "$2" == "true" &&
        "$request_calls" == "1" ]] || return 1
      printf 'runtime\n' >>"$observed"
    }
    recreate_instrumented_stack() {
      return 1
    }
    run_scenario() {
      [[ "$1" == "basic" && "$SCENARIO_VARIANT" == "delayed-otlp-suppression" &&
        "$request_calls" == "1" ]] || return 1
      printf 'scenario:%s:%s\n' "$1" "$SCENARIO_VARIANT" >>"$observed"
    }

    execute_requested_scenarios
    [[ "$request_calls" == "1" && "$absence_calls" == "2" &&
      "$receiver_empty_calls" == "1" && "$sleep_calls" == "2" &&
      -z "$SCENARIO_VARIANT" ]]
  ) || {
    printf 'delayed OTLP suppression control did not preserve its request boundary\n' >&2
    return 1
  }

  printf '%s\n' \
    'receiver-empty:delayed-otlp-receiver-before-request.json' \
    'absent:duplicate-suppression-delayed-otlp-before-request.prom' \
    "sleep:$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" \
    'prime' \
    'provider-ready' \
    'window:delayed-otlp-window.txt' \
    "sleep:$DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS" \
    'receiver-no-java:delayed-otlp-receiver-before-export.json' \
    'absent:duplicate-suppression-delayed-otlp-before-export.prom' \
    'ready:duplicate-suppression-delayed-otlp-ready.prom' \
    'receiver-ready:delayed-otlp-receiver-ready.json' \
    'transport' \
    'runtime' \
    'scenario:basic:delayed-otlp-suppression' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'delayed OTLP suppression sequence changed:\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_delayed_otlp_suppression_control_restores_schedule_delay() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-restoration"
  local -r observed="$result_dir/observed"
  local -r expected="$result_dir/expected"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    SCENARIO=all
    TRANSPORT=getsockopt
    SCENARIO_VARIANT=""
    DELAYED_OTLP_PROVIDER_READY_SINCE="provider-cursor"
    export OTEL_BSP_SCHEDULE_DELAY_VALUE=750
    export OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE=false
    delayed_otlp_earliest_export_millisecond() {
      printf '900000\n'
    }
    delayed_otlp_run_nonce() {
      printf '00000000000000000000000000000004\n'
    }
    recreate_instrumented_stack() {
      printf 'recreate:%s:%s:%s:%s:%s:%s:%s\n' \
        "$1" "$2" "${3:-}" "${4:-}" "${5:-}" \
        "$OTEL_BSP_SCHEDULE_DELAY_VALUE" \
        "$OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE" >>"$observed"
    }
    assert_delayed_otlp_receiver_empty() {
      printf 'receiver-empty:%s\n' "${1##*/}" >>"$observed"
    }
    assert_delayed_otlp_receiver_has_no_java_export() {
      printf 'receiver-no-java:%s\n' "${1##*/}" >>"$observed"
    }
    assert_java_duplicate_suppression_absent() {
      printf 'absent:%s\n' "${1##*/}" >>"$observed"
    }
    assert_delayed_otlp_pre_export_window() {
      [[ "$2" == "900000" ]] || return 1
      printf 'window:%s\n' "${1##*/}" >>"$observed"
    }
    run_bounded() {
      [[ "$1" == "10" && "$2" == "curl" &&
        "$*" == *"$APACHE_HTTPS_HEALTH_ENDPOINT"* ]] || return 1
      printf 'prime\n' >>"$observed"
    }
    wait_for_log() {
      [[ "$1" == "java-backend" &&
        "$2" == "OBI remote-parent provider ready" &&
        "$3" == "delayed-otlp-suppression injected Java helper" &&
        "$4" == "provider-cursor" ]] || return 1
      printf 'provider-ready\n' >>"$observed"
    }
    sleep() {
      printf 'sleep:%s\n' "$1" >>"$observed"
    }
    wait_for_delayed_otlp_receiver_export() {
      [[ "$2" == "$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS" &&
        "$3" == "900000" &&
        "${4##*/}" == "delayed-otlp-receiver-early.json" &&
        "${5##*/}" == "delayed-otlp-receiver-unexpected.json" &&
        "$6" == "$DELAYED_OTLP_POST_EXPORT_SETTLE_SECONDS" ]] || return 1
      printf 'receiver-ready:%s\n' "${1##*/}" >>"$observed"
    }
    wait_for_java_duplicate_suppression_without_prime() {
      [[ "$2" == "$DELAYED_OTLP_SUPPRESSION_TIMEOUT_SECONDS" ]] || return 1
      printf 'ready:%s\n' "${1##*/}" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    assert_runtime_contract() {
      [[ "$1" == "delayed-otlp-suppression" && "$2" == "true" ]] || return 1
      printf 'runtime\n' >>"$observed"
    }
    run_scenario() {
      [[ "$1" == "basic" && "$SCENARIO_VARIANT" == "delayed-otlp-suppression" ]] || return 1
      printf 'scenario\n' >>"$observed"
    }

    run_delayed_otlp_suppression_control
    [[ "$OTEL_BSP_SCHEDULE_DELAY_VALUE" == "750" &&
      "$OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE" == "false" &&
      -z "$SCENARIO_VARIANT" ]]
  ) || {
    printf 'delayed OTLP suppression did not restore the prior schedule delay\n' >&2
    return 1
  }

  printf '%s\n' \
    "recreate:tcp:delayed-otlp-suppression startup:getsockopt:false:true:$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS:true" \
    'receiver-empty:delayed-otlp-receiver-before-request.json' \
    'absent:duplicate-suppression-delayed-otlp-before-request.prom' \
    "sleep:$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" \
    'prime' \
    'provider-ready' \
    'window:delayed-otlp-window.txt' \
    "sleep:$DELAYED_OTLP_PRE_EXPORT_WAIT_SECONDS" \
    'receiver-no-java:delayed-otlp-receiver-before-export.json' \
    'absent:duplicate-suppression-delayed-otlp-before-export.prom' \
    'ready:duplicate-suppression-delayed-otlp-ready.prom' \
    'receiver-ready:delayed-otlp-receiver-ready.json' \
    'transport' \
    'runtime' \
    'scenario' \
    'recreate:tcp:post-delayed-otlp suppression restoration::::750:false' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'delayed OTLP schedule-delay restoration changed:\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_delayed_otlp_suppression_recovers_after_startup_failure() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-recovery"
  local -r observed="$result_dir/observed"
  local failure_status=0

  mkdir -p -- "$result_dir"
  if (
    local -i recreate_calls=0

    RESULT_DIR="$result_dir"
    SCENARIO=all
    TRANSPORT=getsockopt
    export OTEL_BSP_SCHEDULE_DELAY_VALUE=750
    export OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE=false
    recreate_instrumented_stack() {
      ((recreate_calls += 1))
      printf 'recreate:%s:%s:%s:%s:%s:%s\n' \
        "$2" "${4:-true}" "${5:-false}" \
        "$OTEL_BSP_SCHEDULE_DELAY_VALUE" \
        "$OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE" \
        "$recreate_calls" >>"$observed"
      if [[ "$recreate_calls" == "1" ]]; then
        return 47
      fi
    }
    run_delayed_otlp_suppression_sequence() {
      printf 'sequence\n' >>"$observed"
      return 1
    }

    run_delayed_otlp_suppression_control
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP startup failure unexpectedly passed\n' >&2
    return 1
  else
    failure_status=$?
  fi
  [[ "$failure_status" == "47" &&
    "$(<"$observed")" == $"recreate:delayed-otlp-suppression startup:false:true:$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS:true:1"$'\nrecreate:post-delayed-otlp suppression recovery:true:false:750:false:2' ]] || {
    printf 'delayed OTLP startup failure did not restore the standard stack\n' >&2
    return 1
  }
}

test_pressure_map_metric_requires_exact_unique_series() {
  local -r metrics="$TEST_TMP_DIR/pressure-map-metric.prom"

  printf '%s\n' \
    'obi_bpf_map_entries_total_shadow{map_id="41",map_name="java_remote_par",map_type="hash"} 9' \
    >"$metrics"
  if pressure_map_metric "$metrics" obi_bpf_map_entries_total 41 >/dev/null; then
    printf 'pressure-map resolver accepted a prefixed metric name\n' >&2
    return 1
  fi

  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
    >>"$metrics"
  [[ "$(pressure_map_metric "$metrics" obi_bpf_map_entries_total 41)" == "41 7" ]]

  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 8' \
    >>"$metrics"
  if pressure_map_metric "$metrics" obi_bpf_map_entries_total 41 >/dev/null; then
    printf 'pressure-map resolver accepted duplicate exact-map series\n' >&2
    return 1
  fi
}

test_bridge_metric_wait_requires_quiescent_report() {
  (
    local -i fetches=0
    RESULT_DIR="$TEST_TMP_DIR/bridge-metric-wait"
    mkdir -p -- "$RESULT_DIR"
    ALLOW_PRIMARY_SECURITY_METRICS=true
    fetch_obi_metrics() {
      ((fetches += 1))
      printf '%s\n' \
        "obi_java_remote_parent_operations_total{operation=\"take\",status=\"valid\",transport=\"unix\"} $((fetches >= 2 ? 1 : 0))" \
        "obi_java_remote_parent_operations_total{operation=\"take\",status=\"unauthorized\",transport=\"getsockopt\"} $fetches" \
        "obi_java_remote_parent_operations_total{operation=\"stage\",status=\"valid\",transport=\"tcp\"} $((fetches >= 2 ? 1 : 0))" \
        "obi_java_remote_parent_operations_total{operation=\"inject\",status=\"ambiguous\",transport=\"tcp\"} $((fetches >= 2 ? 1 : 0))" \
        "obi_java_remote_parent_operations_total{operation=\"report\",status=\"valid\",transport=\"tcp\"} $((fetches == 1 ? 5 : fetches < 4 ? 6 : 7))" \
        >"$1"
    }
    sleep() {
      :
    }

    wait_for_bridge_metrics_quiescent \
      1 1 "$RESULT_DIR/settled.prom" "delayed reporter quiescence"

    [[ "$fetches" -eq 4 ]] || {
      printf 'bridge wait returned before a stable completed report: fetches=%d\n' "$fetches" >&2
      return 1
    }
    [[ "$(bridge_stage_total "$RESULT_DIR/settled.prom")" == "1" ]] || {
      printf 'bridge wait did not retain the completed reporter snapshot\n' >&2
      return 1
    }
  )

  local publication_status=0
  if (
    local -i fetches=0
    RESULT_DIR="$TEST_TMP_DIR/bridge-metric-publication-failure"
    mkdir -p -- "$RESULT_DIR"
    fetch_obi_metrics() {
      ((fetches += 1))
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="unix"} 1' \
        'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 1' \
        "obi_java_remote_parent_operations_total{operation=\"report\",status=\"valid\",transport=\"tcp\"} $fetches" \
        >"$1"
    }
    sleep() { :; }
    install() { return 29; }

    wait_for_bridge_metrics_quiescent \
      1 1 "$RESULT_DIR/settled.prom" "publication failure"
  ) >/dev/null 2>&1; then
    printf 'bridge metric wait ignored evidence publication failure\n' >&2
    return 1
  else
    publication_status=$?
  fi
  [[ "$publication_status" == "29" ]] || {
    printf 'bridge metric publication returned %s instead of 29\n' \
      "$publication_status" >&2
    return 1
  }
}

test_security_probe_window_covers_metric_fences() {
  (
    local -i configured_same_cgroup=0
    local -i configured_sibling=0
    local -i required_same_cgroup=0
    local -i required_sibling=0
    local -i readiness_timeout=0
    local -i repeat_count=0

    while read -r readiness_timeout repeat_count; do
      READINESS_TIMEOUT_SECONDS="$readiness_timeout"
      REPEAT_COUNT="$repeat_count"
      configure_security_probe_timeouts
      configured_same_cgroup="${PRIMARY_SECURITY_SAME_CGROUP_TIMEOUT%s}"
      configured_sibling="${SECURITY_PROBE_TIMEOUT%s}"
      required_same_cgroup=$((
        (2 * readiness_timeout) + 193 + (repeat_count * 232)
      ))
      required_sibling=$((required_same_cgroup + readiness_timeout + 408))
      ((configured_same_cgroup > required_same_cgroup)) || return 1
      ((configured_sibling > required_sibling)) || return 1
      ((configured_sibling > configured_same_cgroup)) || return 1
      ((configured_sibling <= MAX_SECURITY_PROBE_TIMEOUT_SECONDS)) || return 1
    done <<'EOF'
90 1
120 1
90 10
119 10
EOF
    if (
      READINESS_TIMEOUT_SECONDS="$MAX_SHELL_INTEGER"
      REPEAT_COUNT=1
      configure_security_probe_timeouts
    ) >/dev/null 2>&1; then
      return 1
    fi
    if (
      READINESS_TIMEOUT_SECONDS=120
      REPEAT_COUNT=10
      configure_security_probe_timeouts
    ) >/dev/null 2>&1; then
      return 1
    fi
    READINESS_TIMEOUT_SECONDS=120
    REPEAT_COUNT=10
    SCENARIO=basic
    TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    export_compose_environment
    [[ "$PRIMARY_SECURITY_SAME_CGROUP_TIMEOUT" == "60s" &&
      "$SECURITY_PROBE_TIMEOUT" == "60s" ]] || return 1
    [[ "${PRIMARY_SECURITY_PROBE_PATH##*/}" == "security-probe" ]] || return 1
  ) || {
    printf 'security probe deadlines did not cover both bounded lifetimes\n' >&2
    return 1
  }
}

test_primary_security_quiescence_restores_policy() {
  (
    local observed_policy=""
    local wait_status=0

    ALLOW_PRIMARY_SECURITY_METRICS=false
    wait_for_bridge_metrics_quiescent() {
      observed_policy="$ALLOW_PRIMARY_SECURITY_METRICS"
      return 23
    }
    if wait_for_primary_security_metrics_quiescent \
      "$TEST_TMP_DIR/security-settled.prom" "security publication"; then
      printf 'primary security quiescence ignored the underlying wait failure\n' >&2
      return 1
    else
      wait_status=$?
    fi
    [[ "$wait_status" -eq 23 && "$observed_policy" == "true" && \
      "$ALLOW_PRIMARY_SECURITY_METRICS" == "false" ]] || {
      printf 'primary security quiescence did not scope and restore its policy\n' >&2
      return 1
    }
  )
}

test_bridge_take_attempt_total_is_transport_scoped() {
  local -r metrics="$TEST_TMP_DIR/bridge-take-attempts.prom"
  local -r previous_transport="$SELECTED_TRANSPORT"
  local zero_total=""

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 5' \
    'obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} 2' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="unix"} 11' \
    'obi_java_remote_parent_operations_total_extra{operation="take",status="valid",transport="getsockopt"} 99' \
    'obi_java_remote_parent_operations_total{operation="discard",status="valid",transport="getsockopt"} 13' \
    >"$metrics"

  SELECTED_TRANSPORT=getsockopt
  [[ "$(bridge_take_attempt_total "$metrics")" == "7" ]]
  SELECTED_TRANSPORT=unix
  [[ "$(bridge_take_attempt_total "$metrics")" == "11" ]]
  SELECTED_TRANSPORT=auto
  if bridge_take_attempt_total "$metrics" >/dev/null; then
    SELECTED_TRANSPORT="$previous_transport"
    printf 'bridge take attempts accepted an unresolved transport\n' >&2
    return 1
  fi

  SELECTED_TRANSPORT=getsockopt
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} invalid' \
    >>"$metrics"
  if bridge_take_attempt_total "$metrics" >/dev/null; then
    SELECTED_TRANSPORT="$previous_transport"
    printf 'bridge take attempts accepted a malformed counter\n' >&2
    return 1
  fi

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 0' \
    >"$metrics"
  zero_total="$(bridge_take_attempt_total "$metrics")"
  [[ "$zero_total" == "0" ]]

  printf '%s\n' \
    "obi_java_remote_parent_operations_total{operation=\"take\",status=\"valid\",transport=\"getsockopt\"} $MAX_SHELL_INTEGER" \
    'obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} 1' \
    >"$metrics"
  if bridge_take_attempt_total "$metrics" >/dev/null; then
    SELECTED_TRANSPORT="$previous_transport"
    printf 'bridge take attempts accepted a counter sum outside the bounded range\n' >&2
    return 1
  fi
  SELECTED_TRANSPORT="$previous_transport"
}

test_bridge_inject_attempt_total_is_reason_agnostic() {
  local -r metrics="$TEST_TMP_DIR/bridge-inject-attempts.prom"

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} 4' \
    'obi_java_remote_parent_operations_total{operation="inject",status="ambiguous",transport="tcp"} 1' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 99' \
    >"$metrics"
  [[ "$(bridge_inject_attempt_total "$metrics")" == "5" ]] || {
    printf 'bridge inject attempts did not retain reason-coded failures\n' >&2
    return 1
  }

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} invalid' \
    >>"$metrics"
  if bridge_inject_attempt_total "$metrics" >/dev/null 2>&1; then
    printf 'bridge inject attempts accepted a malformed counter\n' >&2
    return 1
  fi
}

test_pressure_monitor_uses_prefill_baseline() {
  local -i required_completion_timeout="$((
    (PRESSURE_MONITOR_METRICS_TIMEOUT_SECONDS * 2) +
    PRESSURE_MONITOR_POLL_INTERVAL_SECONDS +
    PRESSURE_MONITOR_COMPLETION_SLACK_SECONDS
  ))"

  if ((PRESSURE_MONITOR_COMPLETION_SLACK_SECONDS <= 0 ||
    PRESSURE_MONITOR_COMPLETION_TIMEOUT_SECONDS < required_completion_timeout)); then
    printf 'pressure monitor completion timeout does not cover the next bounded sample\n' >&2
    return 1
  fi

  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-failure"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_INJECT_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    : >"$PRESSURE_MONITOR_OUTPUT"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' >"$1"
    }
    if (monitor_map_pressure); then
      printf 'pressure monitor accepted occupancy at the pre-fill baseline\n' >&2
      return 1
    fi
    grep -Fq 'status=failed reason=occupancy map_id=41 baseline=7 max_entries=10 actual=7' \
      "$PRESSURE_MONITOR_OUTPUT"
  )

  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-overflow"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_INJECT_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    : >"$PRESSURE_MONITOR_OUTPUT"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 18446744073709551625' >"$1"
    }
    if (monitor_map_pressure); then
      printf 'pressure monitor accepted an overflowing occupancy value\n' >&2
      return 1
    fi
    grep -Fq 'actual=18446744073709551625' "$PRESSURE_MONITOR_OUTPUT"
  )

  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-traffic-overshoot"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_INJECT_TARGET=5
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    : >"$PRESSURE_MONITOR_OUTPUT"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 9' \
        'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} 6' >"$1"
    }
    if monitor_map_pressure; then
      printf 'pressure monitor accepted more inject outcomes than requests\n' >&2
      return 1
    fi
    grep -Fq 'reason=traffic-count operation=inject transport=tcp actual=6 target=5' \
      "$PRESSURE_MONITOR_OUTPUT"
  )

  (
    local fetch_calls=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-report-only"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_INJECT_TARGET=5
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    : >"$PRESSURE_MONITOR_OUTPUT"
    fetch_obi_metrics() {
      fetch_calls="$((fetch_calls + 1))"
      if ((fetch_calls < 3)); then
        printf '%s\n' \
          'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 9' \
          'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} 4' \
          "obi_java_remote_parent_operations_total{operation=\"report\",status=\"valid\",transport=\"tcp\"} $fetch_calls" >"$1"
      else
        printf '%s\n' \
          'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
          'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} 4' \
          'obi_java_remote_parent_operations_total{operation="report",status="valid",transport="tcp"} 3' >"$1"
      fi
    }
    if monitor_map_pressure; then
      printf 'pressure monitor treated report growth as traffic completion\n' >&2
      return 1
    fi
    if grep -q '^status=traffic-complete ' "$PRESSURE_MONITOR_OUTPUT"; then
      printf 'pressure monitor published terminal evidence before inject completion\n' >&2
      return 1
    fi
    grep -Fq 'status=failed reason=occupancy' "$PRESSURE_MONITOR_OUTPUT"
  )

  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-success"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_LABEL="pressure-test"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_INJECT_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 9' \
        'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} 4' \
        'obi_java_remote_parent_operations_total{operation="inject",status="ambiguous",transport="tcp"} 1' >"$1"
    }
    start_map_pressure_monitor
    local monitor_pid="$PRESSURE_MONITOR_PID"
    stop_map_pressure_monitor
    if kill -0 "$monitor_pid" 2>/dev/null; then
      printf 'pressure monitor was not terminated and reaped\n' >&2
      return 1
    fi
    grep -Fq 'status=pressured ' "$PRESSURE_MONITOR_OUTPUT"
    grep -Fq 'status=traffic-complete ' "$PRESSURE_MONITOR_OUTPUT"
    [[ -f "$PRESSURE_MONITOR_FINAL_OUTPUT" ]]
  )

  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-incomplete"
    mkdir -p -- "$RESULT_DIR"
    true &
    PRESSURE_MONITOR_PID=$!
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    PRESSURE_MONITOR_FINAL_OUTPUT="$RESULT_DIR/terminal.prom"
    printf '%s\n' \
      'status=pressured observed_at=2026-01-01T00:00:00Z map_id=41 baseline=7 max_entries=10 entries=9' \
      >"$PRESSURE_MONITOR_OUTPUT"
    if stop_map_pressure_monitor; then
      printf 'pressure monitor accepted evidence without bridge-traffic completion\n' >&2
      return 1
    fi
  )

  (
    local fetch_calls=0
    local fixture_inject_total=4

    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-stop-race"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_LABEL="pressure-test"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_INJECT_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    fetch_obi_metrics() {
      fetch_calls="$((fetch_calls + 1))"
      if ((fetch_calls > 1)); then
        fixture_inject_total=5
      fi
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 9' \
        "obi_java_remote_parent_operations_total{operation=\"inject\",status=\"valid\",transport=\"tcp\"} $fixture_inject_total" >"$1"
    }
    start_map_pressure_monitor
    stop_map_pressure_monitor
    grep -Fq 'status=traffic-complete ' "$PRESSURE_MONITOR_OUTPUT"
    [[ -f "$PRESSURE_MONITOR_FINAL_OUTPUT" ]]
  )
}

pressure_prepare_result() {
  local -r token_base="$1"

  printf '{"status":"passed","mode":"prepare","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":%s,"touched":0}\n' \
    "$token_base"
}

pressure_fill_result() {
  local -r token_base="$1"

  printf '{"status":"passed","mode":"fill","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":%s,"touched":10,"capacity_rejected_entries":1,"verified_present_entries":10}\n' \
    "$token_base"
}

pressure_cleanup_result() {
  local -r token_base="$1"

  printf '{"status":"passed","mode":"cleanup","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10,"process_map_id":0,"process_pid":101,"process_namespace":202,"token_base":%s,"touched":10,"cleanup_verified":true,"verified_absent_entries":11}\n' \
    "$token_base"
}

pressure_state_result() {
  local -r comparison="$1"
  local -r output="$2"
  local -r required_matches="${4:-1}"
  local sample_output=""
  local -i index=0

  printf 'comparison=%s output=%s\n' "$comparison" "$output" >"$output"
  if ((required_matches > 1)); then
    for ((index = 1; index <= required_matches; index++)); do
      printf -v sample_output '%s-sample-%02d.prom' "${output%.prom}" "$index"
      printf 'comparison=%s sample=%d\n' "$comparison" "$index" >"$sample_output"
    done
    printf 'comparison=%s matches=%d\n' \
      "$comparison" "$required_matches" >"${output%.prom}-samples.log"
  fi
}

test_pressure_state_uses_baseline_and_retains_steady_recovery() {
  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-state"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    sleep() {
      return 0
    }
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 8' >"$1"
    }
    wait_for_pressure_map_state pressured "$RESULT_DIR/pressured.prom" 1 1 1
    grep -Fq '} 8' "$RESULT_DIR/pressured.prom"
  )

  (
    local fetch_count=0
    local entries=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-recovery"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=2
    sleep() {
      return 0
    }
    fetch_obi_metrics() {
      ((fetch_count += 1))
      case "$fetch_count" in
        1) entries=3 ;;
        2) entries=2 ;;
        3) entries=3 ;;
        *) entries=2 ;;
      esac
      printf 'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash",sample="%d"} %s\n' \
        "$fetch_count" "$entries" >"$1"
    }
    wait_for_pressure_map_state recovered "$RESULT_DIR/recovered.prom" 5 2 5
    [[ "$fetch_count" -eq 5 ]] || {
      printf 'steady recovery did not require consecutive baseline samples\n' >&2
      return 1
    }
    grep -Fq '} 2' "$RESULT_DIR/recovered.prom"
    grep -Fq 'sample="4"' "$RESULT_DIR/recovered-sample-01.prom"
    grep -Fq 'sample="5"' "$RESULT_DIR/recovered-sample-02.prom"
    grep -Eq '^attempt=3 .* matched=false consecutive=0$' \
      "$RESULT_DIR/recovered-samples.log"
  )
}

test_pressure_state_has_attempt_and_wall_clock_bounds() {
  (
    local fetch_count=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-attempt-bound"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=2
    sleep() {
      return 0
    }
    fetch_obi_metrics() {
      ((fetch_count += 1))
      return 1
    }
    if wait_for_pressure_map_state \
      recovered "$RESULT_DIR/recovered.prom" 60 2 3 >/dev/null 2>&1; then
      printf 'pressure state ignored its attempt cap\n' >&2
      return 1
    fi
    [[ "$fetch_count" -eq 3 ]] || {
      printf 'pressure state attempt cap used %d fetches, wanted 3\n' "$fetch_count" >&2
      return 1
    }
  )

  (
    local -i started=0
    local -i elapsed=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-deadline-bound"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=2
    fetch_obi_metrics() {
      command sleep "$2"
      return 1
    }
    started="$SECONDS"
    if wait_for_pressure_map_state \
      recovered "$RESULT_DIR/recovered.prom" 2 2 10 >/dev/null 2>&1; then
      printf 'pressure deadline accepted unavailable metrics\n' >&2
      return 1
    fi
    elapsed="$((SECONDS - started))"
    ((elapsed >= 2 && elapsed <= 3)) || {
      printf 'pressure deadline elapsed %d seconds, wanted 2-3\n' "$elapsed" >&2
      return 1
    }
  )
}

test_pressure_state_fails_closed_on_evidence_write_error() {
  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-evidence-write"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=2
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 3' >"$1"
    }
    install() {
      return 1
    }
    if wait_for_pressure_map_state \
      pressured "$RESULT_DIR/pressured.prom" 1 1 1 >/dev/null 2>&1; then
      printf 'pressure state accepted a failed evidence install\n' >&2
      return 1
    fi
  )
}

test_map_pressure_prepare_fill_cleanup_transaction() {
  (
    local -r token_base="18446744073709551605"
    local -r command_log="$TEST_TMP_DIR/pressure-transaction.commands"
    local -r state_log="$TEST_TMP_DIR/pressure-transaction.states"

    RESULT_DIR="$TEST_TMP_DIR/pressure-transaction"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} 3' \
      >"$RESULT_DIR/before.prom"
    SELECTED_TRANSPORT=getsockopt
    run_bounded() {
      printf '%s\n' "$*" >>"$command_log"
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result "$token_base" ;;
        *' --mode cleanup '*) pressure_cleanup_result "$token_base" ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      printf '%s\n' "$*" >>"$state_log"
      pressure_state_result "$@"
    }
    start_map_pressure_monitor() {
      return 0
    }

    SELECTED_TRANSPORT=getsockopt
    start_map_pressure pressure-test "$RESULT_DIR/before.prom" 5 >/dev/null
    [[ "$PRESSURE_INJECT_TARGET" == "8" ]] || return 1
    [[ "$PRESSURE_ACTIVE" == "true" && \
      "$PRESSURE_MAP_BASELINE_ENTRIES" == "7" && \
      "$PRESSURE_PROCESS_MAP_ID" == "42" && \
      "$PRESSURE_TOKEN_BASE" == "$token_base" && \
      "$PRESSURE_TOUCHED_ENTRIES" == "10" && \
      "$PRESSURE_CAPACITY_REJECTED_ENTRIES" == "1" && \
      "$PRESSURE_VERIFIED_PRESENT_ENTRIES" == "10" ]] || {
      printf 'map-pressure start did not retain its prepared identity and fill evidence\n' >&2
      return 1
    }
    cleanup_map_pressure >/dev/null
    [[ "$PRESSURE_ACTIVE" == "false" ]] || {
      printf 'verified map-pressure cleanup did not clear active state\n' >&2
      return 1
    }
    [[ "$(wc -l <"$command_log")" -eq 3 ]]
    sed -n '1p' "$command_log" | grep -Fq -- '--mode prepare'
    sed -n '2p' "$command_log" | grep -Fq -- \
      "--map-id 41 --expected-max-entries 10 --expected-process-map-id 42 --process-pid 101 --process-namespace 202 --token-base $token_base --seed 1 --mode fill"
    sed -n '3p' "$command_log" | grep -Fq -- \
      "--map-id 41 --expected-max-entries 10 --process-pid 101 --process-namespace 202 --token-base $token_base --seed 1 --mode cleanup"
    grep -Fq 'pressured ' "$state_log"
    grep -Fq 'recovered ' "$state_log"
    [[ -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.json" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.stderr.log" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup.json" ]]
    grep -Fq 'validation_status=passed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
    grep -Fq 'recovery_status=passed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
  )
}

test_map_pressure_pre_mutation_failures_do_not_fill() {
  (
    local -r command_log="$TEST_TMP_DIR/pressure-bad-prepare.commands"

    RESULT_DIR="$TEST_TMP_DIR/pressure-bad-prepare"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    : >"$RESULT_DIR/before.prom"
    run_bounded() {
      printf '%s\n' "$*" >>"$command_log"
      pressure_prepare_result 700
      pressure_prepare_result 701
    }

    SELECTED_TRANSPORT=getsockopt
    if start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null 2>&1; then
      printf 'map-pressure start accepted duplicate prepare records\n' >&2
      return 1
    fi
    [[ "$PRESSURE_ACTIVE" == "false" && "$(wc -l <"$command_log")" -eq 1 ]]
    if grep -Fq -- '--mode fill' "$command_log" || \
      grep -Fq -- '--mode cleanup' "$command_log"; then
      printf 'map-pressure mutated state after invalid prepare evidence\n' >&2
      return 1
    fi
  )

  (
    local -r command_log="$TEST_TMP_DIR/pressure-missing-baseline.commands"

    RESULT_DIR="$TEST_TMP_DIR/pressure-missing-baseline"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="99",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      printf '%s\n' "$*" >>"$command_log"
      pressure_prepare_result 700
    }

    SELECTED_TRANSPORT=getsockopt
    if start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null 2>&1; then
      printf 'map-pressure start accepted a missing exact-map baseline\n' >&2
      return 1
    fi
    [[ "$PRESSURE_ACTIVE" == "false" && "$(wc -l <"$command_log")" -eq 1 ]]
    if grep -Fq -- '--mode fill' "$command_log" || \
      grep -Fq -- '--mode cleanup' "$command_log"; then
      printf 'map-pressure mutated state without an exact-map baseline\n' >&2
      return 1
    fi
  )
}

test_map_pressure_fill_failure_uses_prepared_cleanup_identity() {
  (
    local -r token_base="18446744073709551605"
    local -r command_log="$TEST_TMP_DIR/pressure-fill-failure.commands"
    local start_status=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-fill-failure"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      printf '%s\n' "$*" >>"$command_log"
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) printf 'fill interrupted\n' >&2; return 23 ;;
        *' --mode cleanup '*) pressure_cleanup_result "$token_base" ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      pressure_state_result "$@"
    }

    SELECTED_TRANSPORT=getsockopt
    if start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null 2>&1; then
      printf 'map-pressure start accepted a failed fill command\n' >&2
      return 1
    else
      start_status=$?
    fi
    [[ "$start_status" -eq 23 && "$PRESSURE_ACTIVE" == "false" ]]
    sed -n '3p' "$command_log" | grep -Fq -- \
      "--map-id 41 --expected-max-entries 10 --process-pid 101 --process-namespace 202 --token-base $token_base --seed 1 --mode cleanup"
    grep -Fq 'fill interrupted' "$RESULT_DIR/map-pressure-pressure-test-fill.stderr.log"
  )

  (
    local -r token_base="18446744073709551605"
    local -r command_log="$TEST_TMP_DIR/pressure-fill-mismatch.commands"

    RESULT_DIR="$TEST_TMP_DIR/pressure-fill-mismatch"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      printf '%s\n' "$*" >>"$command_log"
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result 700 ;;
        *' --mode cleanup '*) pressure_cleanup_result "$token_base" ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      pressure_state_result "$@"
    }

    SELECTED_TRANSPORT=getsockopt
    if start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null 2>&1; then
      printf 'map-pressure start accepted mismatched fill identity\n' >&2
      return 1
    fi
    [[ "$PRESSURE_ACTIVE" == "false" && "$(wc -l <"$command_log")" -eq 3 ]]
  )
}

test_map_pressure_cleanup_retries_keep_immutable_artifacts() {
  (
    local -r token_base="18446744073709551605"
    local cleanup_calls=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-cleanup-retry"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result "$token_base" ;;
        *' --mode cleanup '*)
          ((cleanup_calls += 1))
          case "$cleanup_calls" in
            1)
              printf 'transient cleanup failure\n' >&2
              return 23
              ;;
            2)
              pressure_cleanup_result 700
              ;;
            *)
              pressure_cleanup_result "$token_base"
              ;;
          esac
          ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      pressure_state_result "$@"
    }
    start_map_pressure_monitor() {
      return 0
    }

    SELECTED_TRANSPORT=getsockopt
    start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null
    cleanup_map_pressure_with_retries >/dev/null 2>&1
    [[ "$PRESSURE_ACTIVE" == "false" && "$PRESSURE_CLEANUP_ATTEMPT" -eq 3 ]]
    grep -Fq 'command_status=23' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
    grep -Fq 'validation_status=not-run' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
    grep -Fq '"token_base":700' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-02.json"
    grep -Fq 'validation_status=failed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-02.status"
    grep -Fq "\"token_base\":$token_base" \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-03.json"
    grep -Fq 'validation_status=passed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-03.status"
    grep -Fq "\"token_base\":$token_base" \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup.json"
  )

  (
    local helper_called=false

    RESULT_DIR="$TEST_TMP_DIR/pressure-cleanup-exhausted"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_ACTIVE=true
    PRESSURE_CLEANUP_ATTEMPT="$PRESSURE_CLEANUP_MAX_ATTEMPTS"
    PRESSURE_MONITOR_PID=""
    run_map_pressure_helper() {
      helper_called=true
    }
    if cleanup_map_pressure_with_retries >/dev/null 2>&1; then
      printf 'map-pressure cleanup exceeded its attempt cap\n' >&2
      return 1
    fi
    [[ "$helper_called" == "false" && "$PRESSURE_ACTIVE" == "true" ]]
  )

  (
    local -r token_base="700"
    local recovery_calls=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-cleanup-recovery-failure"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result "$token_base" ;;
        *' --mode cleanup '*) pressure_cleanup_result "$token_base" ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      if [[ "$1" == "recovered" ]]; then
        ((recovery_calls += 1))
        pressure_state_result "$@"
        if ((recovery_calls == 1)); then
          return 37
        fi
        return 0
      fi
      pressure_state_result "$@"
    }
    start_map_pressure_monitor() {
      return 0
    }

    SELECTED_TRANSPORT=getsockopt
    start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null
    cleanup_map_pressure_with_retries >/dev/null 2>&1
    [[ "$PRESSURE_ACTIVE" == "false" && "$PRESSURE_CLEANUP_ATTEMPT" -eq 2 ]]
    grep -Fq 'command_status=0' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
    grep -Fq 'validation_status=passed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
    grep -Fq 'recovery_status=failed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
    [[ -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01-recovered-sample-01.prom" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01-recovered-sample-02.prom" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01-recovered-samples.log" ]]
    grep -Fq 'recovery_status=passed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-02.status"
    grep -Fq 'cleanup-attempt-02-recovered.prom' \
      "$RESULT_DIR/map-pressure-pressure-test-recovered.prom"
  )

  (
    local -r token_base="700"
    local cleanup_status=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-cleanup-recovery-exhausted"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result "$token_base" ;;
        *' --mode cleanup '*) pressure_cleanup_result "$token_base" ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      pressure_state_result "$@"
      if [[ "$1" == "recovered" ]]; then
        return 37
      fi
    }
    start_map_pressure_monitor() {
      return 0
    }

    SELECTED_TRANSPORT=getsockopt
    start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null
    if cleanup_map_pressure_with_retries >/dev/null 2>&1; then
      printf 'map-pressure cleanup accepted exhausted recovery failures\n' >&2
      return 1
    else
      cleanup_status=$?
    fi
    [[ "$cleanup_status" -eq 37 && \
      "$PRESSURE_ACTIVE" == "true" && \
      "$PRESSURE_CLEANUP_ATTEMPT" -eq "$PRESSURE_CLEANUP_MAX_ATTEMPTS" ]]
    [[ -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-03.json" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-03.status" ]]
    [[ ! -e "$RESULT_DIR/map-pressure-pressure-test-cleanup.json" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-cleanup.stderr.log" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-sample-01.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-sample-02.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-samples.log" ]]
  )

  (
    local -r token_base="700"
    local cleanup_calls=0
    local cleanup_status=0

    RESULT_DIR="$TEST_TMP_DIR/pressure-cleanup-monitor-failure"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result "$token_base" ;;
        *' --mode cleanup '*)
          ((cleanup_calls += 1))
          if ((cleanup_calls == 1)); then
            return 23
          fi
          pressure_cleanup_result "$token_base"
          ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      pressure_state_result "$@"
    }
    start_map_pressure_monitor() {
      return 0
    }
    stop_map_pressure_monitor() {
      PRESSURE_MONITOR_PID=""
      return 29
    }

    SELECTED_TRANSPORT=getsockopt
    start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null
    PRESSURE_MONITOR_PID=123
    if cleanup_map_pressure_with_retries >/dev/null 2>&1; then
      printf 'map-pressure cleanup erased a monitor failure during retry\n' >&2
      return 1
    else
      cleanup_status=$?
    fi
    [[ "$cleanup_status" -eq 29 && \
      "$PRESSURE_MONITOR_STATUS" -eq 29 && \
      "$PRESSURE_ACTIVE" == "false" && \
      "$PRESSURE_CLEANUP_ATTEMPT" -eq 2 ]]
    grep -Fq 'monitor_status=29' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-02.status"
  )
}

test_map_pressure_result_contract_is_single_record_and_exact() {
  local -r output="$TEST_TMP_DIR/pressure-result.json"

  pressure_prepare_result 700 >"$output"
  pressure_result_has_contract "$output" prepare
  [[ "$(pressure_result_uint "$output" token_base)" == "700" ]]

  pressure_prepare_result 700 >>"$output"
  if pressure_result_has_contract "$output" prepare; then
    printf 'map-pressure contract accepted duplicate records\n' >&2
    return 1
  fi

  pressure_prepare_result 700 >"$output"
  sed -i 's/"status":"passed"/"status":"failed"/' "$output"
  if pressure_result_has_contract "$output" prepare; then
    printf 'map-pressure contract accepted failed status\n' >&2
    return 1
  fi

  pressure_prepare_result 700 >"$output"
  sed -i 's/"kernel_name":"java_remote_par"/"kernel_name":"wrong"/' "$output"
  if pressure_result_has_contract "$output" prepare; then
    printf 'map-pressure contract accepted wrong static map identity\n' >&2
    return 1
  fi
}

test_map_pressure_helper_capture_preserves_status_and_streams() {
  (
    local -r output="$TEST_TMP_DIR/pressure-helper.stdout"
    local -r stderr_output="$TEST_TMP_DIR/pressure-helper.stderr"
    local helper_status=0

    RESULT_DIR="$TEST_TMP_DIR"
    COMPOSE=(fake-compose)
    run_bounded() {
      printf 'complete stdout\n'
      printf 'complete stderr\n' >&2
      return 23
    }
    if run_map_pressure_helper \
      "$output" "$stderr_output" 5 --mode prepare >/dev/null 2>&1; then
      printf 'map-pressure helper capture lost the command failure\n' >&2
      return 1
    else
      helper_status=$?
    fi
    [[ "$helper_status" -eq 23 ]]
    [[ "$(<"$output")" == "complete stdout" ]]
    [[ "$(<"$stderr_output")" == "complete stderr" ]]
  )

  (
    local -r call_marker="$TEST_TMP_DIR/pressure-helper-open.called"
    local helper_status=0

    RESULT_DIR="$TEST_TMP_DIR"
    COMPOSE=(fake-compose)
    run_bounded() {
      : >"$call_marker"
    }
    if run_map_pressure_helper \
      "$TEST_TMP_DIR/missing/stdout" \
      "$TEST_TMP_DIR/missing/stderr" \
      5 \
      --mode prepare >/dev/null 2>&1; then
      printf 'map-pressure helper ignored a capture-open failure\n' >&2
      return 1
    else
      helper_status=$?
    fi
    ((helper_status != 0))
    [[ ! -e "$call_marker" ]]
  )
}

test_map_pressure_canonical_promotion_rolls_back_partial_files() {
  (
    local -r token_base="700"
    local destination=""

    RESULT_DIR="$TEST_TMP_DIR/pressure-cleanup-promotion-failure"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result "$token_base" ;;
        *' --mode cleanup '*) pressure_cleanup_result "$token_base" ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      pressure_state_result "$@"
    }
    start_map_pressure_monitor() {
      return 0
    }
    install() {
      destination="${!#}"
      if [[ "$destination" == "$RESULT_DIR/map-pressure-pressure-test-cleanup.stderr.log" ]]; then
        printf 'partial\n' >"$destination"
        return 1
      fi
      command install "$@"
    }

    SELECTED_TRANSPORT=getsockopt
    start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null
    if cleanup_map_pressure >/dev/null 2>&1; then
      printf 'map-pressure cleanup accepted a partial canonical promotion\n' >&2
      return 1
    fi
    [[ "$PRESSURE_ACTIVE" == "true" ]]
    [[ ! -e "$RESULT_DIR/map-pressure-pressure-test-cleanup.json" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-cleanup.stderr.log" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-sample-01.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-sample-02.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-samples.log" ]]
    [[ -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.json" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status" ]]
  )

  (
    local -r token_base="700"
    local destination=""

    RESULT_DIR="$TEST_TMP_DIR/pressure-recovery-promotion-failure"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    SCENARIO_SEED=1
    printf '%s\n' \
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 7' \
      >"$RESULT_DIR/before.prom"
    run_bounded() {
      case " $* " in
        *' --mode prepare '*) pressure_prepare_result "$token_base" ;;
        *' --mode fill '*) pressure_fill_result "$token_base" ;;
        *' --mode cleanup '*) pressure_cleanup_result "$token_base" ;;
        *) return 64 ;;
      esac
    }
    wait_for_pressure_map_state() {
      pressure_state_result "$@"
    }
    start_map_pressure_monitor() {
      return 0
    }
    install() {
      destination="${!#}"
      if [[ "$destination" == "$RESULT_DIR/map-pressure-pressure-test-recovered-sample-02.prom" ]]; then
        printf 'partial\n' >"$destination"
        return 1
      fi
      command install "$@"
    }

    SELECTED_TRANSPORT=getsockopt
    start_map_pressure pressure-test "$RESULT_DIR/before.prom" 1 >/dev/null
    if cleanup_map_pressure >/dev/null 2>&1; then
      printf 'map-pressure cleanup accepted a partial recovery promotion\n' >&2
      return 1
    fi
    [[ "$PRESSURE_ACTIVE" == "true" ]]
    [[ ! -e "$RESULT_DIR/map-pressure-pressure-test-cleanup.json" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-cleanup.stderr.log" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-sample-01.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-sample-02.prom" && \
      ! -e "$RESULT_DIR/map-pressure-pressure-test-recovered-samples.log" ]]
    [[ -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01-recovered.prom" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01-recovered-sample-01.prom" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01-recovered-sample-02.prom" && \
      -f "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01-recovered-samples.log" ]]
    grep -Fq 'recovery_status=failed' \
      "$RESULT_DIR/map-pressure-pressure-test-cleanup-attempt-01.status"
  )
}

test_bridge_take_count_includes_cancelled_request() {
  REQUEST_COUNT=0
  [[ "$(scenario_bridge_take_count basic)" == "1" ]] || {
    printf 'basic bridge take count did not match its request count\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_take_count keepalive)" == "10" ]] || {
    printf 'keepalive bridge take count did not retain its acceptance default\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_take_count timeout-retry)" == "2" ]] || {
    printf 'timeout/retry bridge take count omitted the cancelled request\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_take_count coalesced-bridge)" == "2" && \
    "$(scenario_java_missing_count coalesced-bridge true)" == "0" && \
    "$(scenario_java_missing_count timeout-retry true)" == "0" ]] || {
    printf 'in-band controls retained a diagnostic self-probe\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count basic getsockopt)" == "0" &&
    "$(scenario_java_missing_count basic true)" == "1" ]] || {
    printf 'getsockopt diagnostics miss expectations were conflated\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count basic unix)" == "0" &&
    "$(scenario_java_missing_count basic true)" == "1" ]] || {
    printf 'Unix metric baseline did not exclude the before-diagnostics lookup\n' >&2
    return 1
  }
  [[ "$(scenario_java_missing_count primary-w3c-stale true)" == "0" &&
    "$(scenario_java_missing_count unix-w3c-stale true)" == "0" ]] || {
    printf 'stale diagnostics accounting did not suppress the direct self lookup\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count tls-boundary getsockopt)" == "0" &&
    "$(scenario_java_missing_count tls-boundary true)" == "1" ]] || {
    printf 'getsockopt TLS-boundary miss expectations included nested fixture traffic\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count tls-boundary unix)" == "0" &&
    "$(scenario_java_missing_count tls-boundary true)" == "1" ]] || {
    printf 'Unix TLS-boundary miss expectations included nested fixture traffic\n' >&2
    return 1
  }
}

test_pressure_scenario_counts_are_unique_and_bounded() {
  local -r result="$TEST_TMP_DIR/pressure-scenario-result.json"

  cat >"$result" <<'EOF'
{
  "pressure_correlation": {
    "exact_hit_count": 127,
    "explicit_root_count": 1,
    "wrong_parent_count": 0,
    "unresolved_count": 0
  }
}
EOF
  [[ "$(pressure_scenario_count "$result" exact_hit_count)" == "127" &&
    "$(pressure_scenario_count "$result" explicit_root_count)" == "1" &&
    "$(pressure_scenario_count "$result" wrong_parent_count)" == "0" &&
    "$(pressure_scenario_count "$result" unresolved_count)" == "0" ]] || {
    printf 'pressure scenario result counts were not parsed exactly\n' >&2
    return 1
  }
  if pressure_scenario_count "$result" absent_count >/dev/null 2>&1; then
    printf 'pressure scenario result accepted a missing count\n' >&2
    return 1
  fi
  sed -i 's/"unresolved_count": 0/"unresolved_count": 1.0/' "$result"
  if pressure_scenario_count "$result" unresolved_count >/dev/null 2>&1; then
    printf 'pressure scenario result accepted a nondecimal count\n' >&2
    return 1
  fi
  sed -i 's/"unresolved_count": 1.0/"unresolved_count": 0/' "$result"

  printf '  "explicit_root_count": 1,\n' >>"$result"
  if pressure_scenario_count "$result" explicit_root_count >/dev/null 2>&1; then
    printf 'pressure scenario result accepted a duplicate count\n' >&2
    return 1
  fi
  sed -i '$d' "$result"
  sed -i 's/"wrong_parent_count": 0/"wrong_parent_count": -1/' "$result"
  if pressure_scenario_count "$result" wrong_parent_count >/dev/null 2>&1; then
    printf 'pressure scenario result accepted a negative count\n' >&2
    return 1
  fi
  sed -i 's/"wrong_parent_count": -1/"wrong_parent_count": 129/' "$result"
  if pressure_scenario_count "$result" wrong_parent_count 128 >/dev/null 2>&1; then
    printf 'pressure scenario result accepted a count above the request bound\n' >&2
    return 1
  fi
}

test_concurrency_overlap_reconciliation_is_exact() {
  local -r result="$TEST_TMP_DIR/concurrency-reconciliation.json"
  local -r mutated="$TEST_TMP_DIR/concurrency-reconciliation-mutated.json"

  printf '%s\n' \
    '{"status":"passed","scenario":"concurrency","request_count":4,"connection_evidence":{"frontend_connections":4,"frontend_protocol":"HTTP/1.1","distinct_backend_workers":4,"distinct_concurrency_arrivals":4,"concurrency_participants":4,"concurrency_max_active":4,"concurrency_release":7},"cases":[{"request":{"concurrency_batch":"c0000000000000007","concurrency_expected":4},"response":{"backend_worker_id":11,"backend_connection_id":1,"concurrency_batch":"c0000000000000007","concurrency_participants":4,"concurrency_max_active":4,"concurrency_arrival":1,"concurrency_release":7}},{"request":{"concurrency_batch":"c0000000000000007","concurrency_expected":4},"response":{"backend_worker_id":12,"backend_connection_id":2,"concurrency_batch":"c0000000000000007","concurrency_participants":4,"concurrency_max_active":4,"concurrency_arrival":2,"concurrency_release":7}},{"request":{"concurrency_batch":"c0000000000000007","concurrency_expected":4},"response":{"backend_worker_id":13,"backend_connection_id":3,"concurrency_batch":"c0000000000000007","concurrency_participants":4,"concurrency_max_active":4,"concurrency_arrival":3,"concurrency_release":7}},{"request":{"concurrency_batch":"c0000000000000007","concurrency_expected":4},"response":{"backend_worker_id":14,"backend_connection_id":4,"concurrency_batch":"c0000000000000007","concurrency_participants":4,"concurrency_max_active":4,"concurrency_arrival":4,"concurrency_release":7}}]}' \
    >"$result"
  [[ "$(concurrency_overlap_reconciliation "$result" 4 | \
    jq -r '.distinct_concurrency_arrivals')" == "4" ]] || return 1
  if concurrency_overlap_reconciliation "$result" 3 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted the wrong request count\n' >&2
    return 1
  fi

  jq 'del(.connection_evidence.distinct_concurrency_arrivals)' \
    "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted missing distinct arrivals\n' >&2
    return 1
  fi
  jq '.connection_evidence.distinct_concurrency_arrivals = "4"' \
    "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted string distinct arrivals\n' >&2
    return 1
  fi
  jq '.connection_evidence.distinct_concurrency_arrivals = 0' \
    "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted zero distinct arrivals\n' >&2
    return 1
  fi
  jq '.connection_evidence.distinct_concurrency_arrivals = 3' \
    "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a missing distinct arrival\n' >&2
    return 1
  fi
  jq 'del(.cases[0].request.concurrency_batch)' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a missing request batch\n' >&2
    return 1
  fi
  jq '.cases[0].request.concurrency_batch = "c0000000000000008"' \
    "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted mismatched request batches\n' >&2
    return 1
  fi
  jq '.cases[0].request.concurrency_expected = 3' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a wrong request barrier size\n' >&2
    return 1
  fi
  jq 'del(.cases[0].response.concurrency_batch)' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a missing response batch\n' >&2
    return 1
  fi
  jq '.cases[0].response.concurrency_batch = "c0000000000000008"' \
    "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a response from another batch\n' >&2
    return 1
  fi
  jq 'del(.cases[0].response)' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a missing response object\n' >&2
    return 1
  fi
  jq '.cases[3].response.backend_worker_id = 11' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a repeated worker\n' >&2
    return 1
  fi
  jq '.cases[3].response.concurrency_arrival = 3' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a duplicate arrival\n' >&2
    return 1
  fi
  jq '.cases[3].response.concurrency_release = 8' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted a mismatched release\n' >&2
    return 1
  fi
  jq '.cases[3].response.concurrency_participants = 3' "$result" >"$mutated"
  if concurrency_overlap_reconciliation "$mutated" 4 >/dev/null 2>&1; then
    printf 'concurrency reconciliation accepted incomplete participation\n' >&2
    return 1
  fi
}

test_reason_coded_scenario_reconciliation_is_exact() {
  local -r coalesced="$TEST_TMP_DIR/coalesced-reconciliation.json"
  local -r mutated="$TEST_TMP_DIR/reason-coded-reconciliation-mutated.json"
  local -r timeout="$TEST_TMP_DIR/timeout-reconciliation.json"

  printf '%s\n' \
    '{"status":"passed","scenario":"coalesced-bridge","request_count":2,"coalesced_bridge_correlation":{"outcome":"supported_exact","exact_hit_count":2,"explicit_root_count":0,"wrong_parent_count":0,"unresolved_count":0,"source_client_candidates":2,"trigger_chain_proven":true,"discard_total_delta":0,"discard_ambiguous_delta":0}}' \
    >"$coalesced"
  [[ "$(coalesced_bridge_reconciliation "$coalesced" | jq -r '.outcome')" == \
    "supported_exact" ]] || return 1
  jq 'del(.coalesced_bridge_correlation.discard_total_delta)' \
    "$coalesced" >"$mutated"
  if coalesced_bridge_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'coalesced reconciliation accepted a missing total discard count\n' >&2
    return 1
  fi
  jq '.coalesced_bridge_correlation.discard_total_delta = null' \
    "$coalesced" >"$mutated"
  if coalesced_bridge_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'coalesced reconciliation accepted a null total discard count\n' >&2
    return 1
  fi
  jq '.coalesced_bridge_correlation.discard_total_delta = "0"' \
    "$coalesced" >"$mutated"
  if coalesced_bridge_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'coalesced reconciliation accepted a string total discard count\n' >&2
    return 1
  fi
  jq '.coalesced_bridge_correlation.discard_total_delta = 2' \
    "$coalesced" >"$mutated"
  if coalesced_bridge_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'coalesced reconciliation accepted two total discards\n' >&2
    return 1
  fi
  sed -i 's/"source_client_candidates":2/"source_client_candidates":1/' "$coalesced"
  if coalesced_bridge_reconciliation "$coalesced" >/dev/null 2>&1; then
    printf 'coalesced exact reconciliation accepted one source candidate for two parents\n' >&2
    return 1
  fi
  sed -i 's/"source_client_candidates":1/"source_client_candidates":2/' "$coalesced"
  sed -i 's/"discard_total_delta":0/"discard_total_delta":1/' "$coalesced"
  if coalesced_bridge_reconciliation "$coalesced" >/dev/null 2>&1; then
    printf 'coalesced exact reconciliation accepted an unexpected discard\n' >&2
    return 1
  fi
  sed -i 's/"discard_total_delta":1/"discard_total_delta":0/' "$coalesced"
  sed -i \
    -e 's/"outcome":"supported_exact"/"outcome":"ambiguous_drop"/' \
    -e 's/"exact_hit_count":2/"exact_hit_count":0/' \
    -e 's/"explicit_root_count":0/"explicit_root_count":2/' \
    -e 's/"discard_total_delta":0/"discard_total_delta":1/' \
    -e 's/"discard_ambiguous_delta":0/"discard_ambiguous_delta":1/' \
    "$coalesced"
  [[ "$(coalesced_bridge_reconciliation "$coalesced" | jq -r '.outcome')" == \
    "ambiguous_drop" ]] || return 1
  sed -i 's/"source_client_candidates":2/"source_client_candidates":1/' "$coalesced"
  if coalesced_bridge_reconciliation "$coalesced" >/dev/null 2>&1; then
    printf 'coalesced ambiguous reconciliation accepted one source candidate\n' >&2
    return 1
  fi
  sed -i 's/"source_client_candidates":1/"source_client_candidates":2/' "$coalesced"
  sed -i 's/"discard_total_delta":1/"discard_total_delta":0/' "$coalesced"
  if coalesced_bridge_reconciliation "$coalesced" >/dev/null 2>&1; then
    printf 'coalesced ambiguous reconciliation accepted zero total discards\n' >&2
    return 1
  fi
  sed -i 's/"discard_total_delta":0/"discard_total_delta":1/' "$coalesced"
  sed -i 's/"wrong_parent_count":0/"wrong_parent_count":1/' "$coalesced"
  if coalesced_bridge_reconciliation "$coalesced" >/dev/null 2>&1; then
    printf 'coalesced reconciliation accepted a wrong parent\n' >&2
    return 1
  fi

  printf '%s\n' \
    '{"status":"passed","scenario":"timeout-retry","faults":[{"kind":"client-timeout","outcome":"deadline-exceeded-as-expected","marker":"timeout-retry-cancelled-42","parent_outcome":"exact","drop_reasons":[]}]}' \
    >"$timeout"
  [[ "$(timeout_cancellation_reconciliation "$timeout" | jq -r '.parent_outcome')" == \
    "exact" ]] || return 1
  jq 'del(.faults[0].drop_reasons)' "$timeout" >"$mutated"
  if timeout_cancellation_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'timeout reconciliation accepted missing drop reasons\n' >&2
    return 1
  fi
  jq '.faults[0].drop_reasons = null' "$timeout" >"$mutated"
  if timeout_cancellation_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'timeout reconciliation accepted null drop reasons\n' >&2
    return 1
  fi
  jq '.faults[0].drop_reasons = {}' "$timeout" >"$mutated"
  if timeout_cancellation_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'timeout reconciliation accepted object drop reasons\n' >&2
    return 1
  fi
  jq '.faults[0].drop_reasons = ["valid"]' "$timeout" >"$mutated"
  if timeout_cancellation_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'timeout reconciliation accepted a non-failure drop reason\n' >&2
    return 1
  fi
  jq '.faults[0].drop_reasons = ["timeout", "timeout"]' \
    "$timeout" >"$mutated"
  if timeout_cancellation_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'timeout reconciliation accepted two identical drop reasons\n' >&2
    return 1
  fi
  jq '.faults[0].parent_outcome = "missing" | .faults[0].drop_reasons = ["timeout"]' \
    "$timeout" >"$mutated"
  if timeout_cancellation_reconciliation "$mutated" >/dev/null 2>&1; then
    printf 'timeout missing-parent reconciliation accepted a drop reason\n' >&2
    return 1
  fi
  sed -i 's/"drop_reasons":\[\]/"drop_reasons":["ambiguous"]/' "$timeout"
  if timeout_cancellation_reconciliation "$timeout" >/dev/null 2>&1; then
    printf 'timeout exact reconciliation accepted an unrelated discard reason\n' >&2
    return 1
  fi
  sed -i 's/"drop_reasons":\["ambiguous"\]/"drop_reasons":[]/' "$timeout"
  sed -i \
    -e 's/"parent_outcome":"exact"/"parent_outcome":"reason_coded_drop"/' \
    -e 's/"drop_reasons":\[\]/"drop_reasons":["ambiguous"]/' \
    "$timeout"
  [[ "$(timeout_cancellation_reconciliation "$timeout" | jq -r '.drop_reasons[0]')" == \
    "ambiguous" ]] || return 1
  sed -i 's/"ambiguous"/"ambiguous","missing"/' "$timeout"
  if timeout_cancellation_reconciliation "$timeout" >/dev/null 2>&1; then
    printf 'timeout reconciliation accepted multiple drop reasons\n' >&2
    return 1
  fi
  sed -i \
    -e 's/"parent_outcome":"reason_coded_drop"/"parent_outcome":"wrong_parent"/' \
    -e 's/"drop_reasons":\["ambiguous","missing"\]/"drop_reasons":[]/' \
    "$timeout"
  if timeout_cancellation_reconciliation "$timeout" >/dev/null 2>&1; then
    printf 'timeout reconciliation accepted a wrong parent\n' >&2
    return 1
  fi
}

test_bridge_metric_delta_requires_exact_one_shot_results() {
  local -r delta="$TEST_TMP_DIR/w3c-metrics.delta"
  local -r helper_delta="$TEST_TMP_DIR/helper-attach-metrics.delta"

  cat >"$delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="report",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="candidate",status="ambiguous",transport="tcp"} before=1 after=3 delta=2
obi_java_remote_parent_operations_total{operation="cleanup",status="valid",transport="tcp"} before=0 after=16 delta=16
obi_java_remote_parent_operations_total{operation="negotiate",status="missing",transport="getsockopt"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="discard",status="valid",transport="getsockopt"} before=1 after=1 delta=0
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} before=0 after=0 delta=0
obi_java_remote_parent_operations_total{operation="take",status="stale",transport="getsockopt"} before=0 after=0 delta=0
EOF
  assert_bridge_metric_delta "$delta" getsockopt 2 0 || {
    printf 'bridge metric delta rejected exact one-shot results\n' >&2
    return 1
  }
  sed -i 's/operation="inject",status="valid",transport="tcp"} before=3 after=5 delta=2/operation="inject",status="valid",transport="tcp"} before=3 after=6 delta=3/' "$delta"
  if assert_bridge_metric_delta "$delta" getsockopt 2 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted a duplicate injection\n' >&2
    return 1
  fi
  sed -i 's/operation="inject",status="valid",transport="tcp"} before=3 after=6 delta=3/operation="inject",status="valid",transport="tcp"} before=3 after=5 delta=2/' "$delta"
  sed -i 's/status="missing",transport="getsockopt"} before=0 after=0 delta=0/status="missing",transport="getsockopt"} before=0 after=1 delta=1/' "$delta"
  if assert_bridge_metric_delta "$delta" getsockopt 2 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted an unexpected lookup result\n' >&2
    return 1
  fi
  assert_bridge_metric_delta "$delta" getsockopt 2 0 1 || {
    printf 'bridge metric delta rejected the exact diagnostics self-probe miss\n' >&2
    return 1
  }

  sed -i 's/status="missing",transport="getsockopt"} before=0 after=1 delta=1/status="missing",transport="getsockopt"} before=0 after=0 delta=0/' "$delta"
  sed -i 's/status="stale",transport="getsockopt"} before=0 after=0 delta=0/status="stale",transport="getsockopt"} before=0 after=1 delta=1/' "$delta"
  if assert_bridge_metric_delta "$delta" getsockopt 2 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted an unexpected stale lookup\n' >&2
    return 1
  fi
  assert_bridge_metric_delta "$delta" getsockopt 2 0 0 2 2 false 1 || {
    printf 'bridge metric delta rejected an exact stale lookup\n' >&2
    return 1
  }
  sed -i 's/status="stale",transport="getsockopt"} before=0 after=1 delta=1/status="stale",transport="getsockopt"} before=0 after=0 delta=0/' "$delta"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="inject",status="ambiguous",transport="tcp"} before=0 after=1 delta=1' \
    >>"$delta"
  if assert_bridge_metric_delta "$delta" getsockopt 2 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted an ambiguous injection\n' >&2
    return 1
  fi
  sed -i '/operation="inject",status="ambiguous",transport="tcp"/d' "$delta"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="overload",transport="tcp"} before=0 after=1 delta=1' \
    >>"$delta"
  if assert_bridge_metric_delta "$delta" getsockopt 2 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted candidate overload\n' >&2
    return 1
  fi

  cat >"$helper_delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=3 after=4 delta=1
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=3 after=4 delta=1
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=3 after=3 delta=0
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="unix"} before=3 after=3 delta=0
obi_java_remote_parent_operations_total{operation="discard",status="valid",transport="unix"} before=1 after=1 delta=0
EOF
  assert_bridge_metric_delta "$helper_delta" unix 0 0 0 1 0 || {
    printf 'bridge metric delta rejected upstream injection without a Java helper\n' >&2
    return 1
  }
  sed -i 's/operation="candidate",status="valid",transport="tcp"} before=3 after=4 delta=1/operation="candidate",status="ambiguous",transport="tcp"} before=3 after=4 delta=1/' \
    "$helper_delta"
  if assert_bridge_metric_delta "$helper_delta" unix 0 0 0 1 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted an ambiguous candidate without helper-unavailable mode\n' >&2
    return 1
  fi
  assert_bridge_metric_delta "$helper_delta" unix 0 0 0 1 0 true || {
    printf 'bridge metric delta rejected an ambiguous helper-unavailable candidate\n' >&2
    return 1
  }
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=4 after=5 delta=1' \
    >>"$helper_delta"
  if assert_bridge_metric_delta "$helper_delta" unix 0 0 0 1 0 true >/dev/null 2>&1; then
    printf 'bridge metric delta accepted duplicate helper-unavailable candidates\n' >&2
    return 1
  fi
  sed -i '/operation="candidate",status="valid",transport="tcp"} before=4 after=5 delta=1/d' \
    "$helper_delta"
  sed -i 's/operation="candidate",status="ambiguous",transport="tcp"} before=3 after=4 delta=1/operation="candidate",status="valid",transport="tcp"} before=3 after=4 delta=1/' \
    "$helper_delta"
  sed -i 's/operation="stage",status="valid",transport="tcp"} before=3 after=3 delta=0/operation="stage",status="valid",transport="tcp"} before=3 after=4 delta=1/' \
    "$helper_delta"
  if assert_bridge_metric_delta "$helper_delta" unix 0 0 0 1 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted helper-unavailable staging\n' >&2
    return 1
  fi
  sed -i 's/operation="stage",status="valid",transport="tcp"} before=3 after=4 delta=1/operation="stage",status="valid",transport="tcp"} before=3 after=3 delta=0/' \
    "$helper_delta"
  sed -i 's/operation="take",status="valid",transport="unix"} before=3 after=3 delta=0/operation="take",status="valid",transport="unix"} before=3 after=4 delta=1/' \
    "$helper_delta"
  if assert_bridge_metric_delta "$helper_delta" unix 0 0 0 1 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted a Java take without a helper\n' >&2
    return 1
  fi
}

test_coalesced_bridge_metrics_follow_explicit_outcome() {
  local -r delta="$TEST_TMP_DIR/coalesced-bridge.delta"

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=0 after=2 delta=2' \
    'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=0 after=2 delta=2' \
    'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=0 after=2 delta=2' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=0 after=2 delta=2' \
    >"$delta"
  assert_coalesced_bridge_metric_delta "$delta" getsockopt supported_exact || {
    printf 'coalesced bridge metrics rejected the explicit exact outcome\n' >&2
    return 1
  }

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=0 after=1 delta=1' \
    'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=0 after=1 delta=1' \
    'obi_java_remote_parent_operations_total{operation="inject",status="ambiguous",transport="tcp"} before=0 after=1 delta=1' \
    'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=0 after=0 delta=0' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=0 after=0 delta=0' \
    >"$delta"
  assert_coalesced_bridge_metric_delta "$delta" getsockopt ambiguous_drop || {
    printf 'coalesced bridge metrics rejected the explicit ambiguous outcome\n' >&2
    return 1
  }
  sed -i \
    's/operation="take",status="valid",transport="getsockopt"} before=0 after=0 delta=0/operation="take",status="valid",transport="getsockopt"} before=0 after=1 delta=1/' \
    "$delta"
  if assert_coalesced_bridge_metric_delta \
    "$delta" getsockopt ambiguous_drop >/dev/null 2>&1; then
    printf 'coalesced ambiguous metrics accepted a valid Java take\n' >&2
    return 1
  fi
}

test_timeout_cancellation_metrics_follow_explicit_outcome() {
  local -r delta="$TEST_TMP_DIR/timeout-cancellation.delta"
  local local_reason=""

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=0 after=2 delta=2' \
    'obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=0 after=2 delta=2' \
    'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=0 after=2 delta=2' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=0 after=2 delta=2' \
    >"$delta"
  assert_timeout_cancellation_metric_delta \
    "$delta" getsockopt exact 2 || {
    printf 'timeout cancellation metrics rejected the exact parent outcome\n' >&2
    return 1
  }

  sed -i \
    -e 's/operation="stage",status="valid",transport="tcp"} before=0 after=2 delta=2/operation="stage",status="valid",transport="tcp"} before=0 after=1 delta=1/' \
    -e 's/operation="take",status="valid",transport="getsockopt"} before=0 after=2 delta=2/operation="take",status="valid",transport="getsockopt"} before=0 after=1 delta=1/' \
    "$delta"
  assert_timeout_cancellation_metric_delta \
    "$delta" getsockopt missing 1 || {
    printf 'timeout cancellation metrics rejected the missing parent outcome\n' >&2
    return 1
  }
  for local_reason in ambiguous unsupported stale; do
    assert_timeout_cancellation_metric_delta \
      "$delta" getsockopt reason_coded_drop 1 "$local_reason" || {
      printf 'timeout cancellation metrics rejected local %s without a BPF discard\n' \
        "$local_reason" >&2
      return 1
    }
  done
  if assert_timeout_cancellation_metric_delta \
    "$delta" getsockopt reason_coded_drop 1 timeout >/dev/null 2>&1; then
    printf 'timeout cancellation metrics accepted a native-only reason without a BPF discard\n' >&2
    return 1
  fi

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="discard",status="ambiguous",transport="getsockopt"} before=0 after=1 delta=1' \
    >>"$delta"
  assert_timeout_cancellation_metric_delta \
    "$delta" getsockopt reason_coded_drop 1 ambiguous || {
    printf 'timeout cancellation metrics rejected the reason-coded discard\n' >&2
    return 1
  }
  if assert_timeout_cancellation_metric_delta \
    "$delta" getsockopt reason_coded_drop 1 stale >/dev/null 2>&1; then
    printf 'timeout cancellation metrics accepted the wrong discard reason\n' >&2
    return 1
  fi
  if assert_timeout_cancellation_metric_delta \
    "$delta" getsockopt missing 1 >/dev/null 2>&1; then
    printf 'timeout cancellation metrics accepted a discard for a missing parent\n' >&2
    return 1
  fi
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="discard",status="timeout",transport="getsockopt"} before=0 after=1 delta=1' \
    >>"$delta"
  if assert_timeout_cancellation_metric_delta \
    "$delta" getsockopt reason_coded_drop 1 ambiguous >/dev/null 2>&1; then
    printf 'timeout cancellation metrics accepted two discard outcomes\n' >&2
    return 1
  fi
}

test_pressure_bridge_reconciliation_preserves_failure_reasons() {
  local -r getsockopt_delta="$TEST_TMP_DIR/pressure-getsockopt.delta"
  local -r stage_delta="$TEST_TMP_DIR/pressure-stage.delta"
  local -r take_delta="$TEST_TMP_DIR/pressure-take.delta"
  local -r unix_delta="$TEST_TMP_DIR/pressure-unix.delta"
  local reconciliation=""

  cat >"$getsockopt_delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=2 after=3 delta=1
obi_java_remote_parent_operations_total{operation="inject",status="ambiguous",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=2 after=3 delta=1
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=2 after=3 delta=1
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=2 after=3 delta=1
obi_java_remote_parent_operations_total{operation="handoff",status="valid",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} before=0 after=0 delta=0
obi_java_remote_parent_operations_total{operation="negotiate",status="missing",transport="getsockopt"} before=7 after=11 delta=4
obi_java_remote_parent_operations_total{operation="cleanup",status="valid",transport="tcp"} before=0 after=9 delta=9
obi_java_remote_parent_operations_total{operation="report",status="valid",transport="tcp"} before=3 after=7 delta=4
EOF
  reconciliation="$(pressure_bridge_reconciliation \
    "$getsockopt_delta" getsockopt 1 1 2)" || {
    printf 'pressure bridge rejected the observed getsockopt injection-drop shape\n' >&2
    return 1
  }
  [[ "$reconciliation" == *'"upstream_failure_count":1'* &&
    "$reconciliation" == *'"retrieval_failure_count":0'* &&
    "$reconciliation" == *'"auxiliary_outcome_counts":{"handoff":1}'* &&
    "$reconciliation" == *'"ambiguous":1'* ]] || {
    printf 'pressure bridge did not preserve the injection failure reason and handoff count\n' >&2
    return 1
  }

  sed -i 's/operation="handoff",status="valid",transport="tcp"} before=0 after=1 delta=1/operation="handoff",status="valid",transport="tcp"} before=0 after=2 delta=2/' \
    "$getsockopt_delta"
  if pressure_bridge_reconciliation \
    "$getsockopt_delta" getsockopt 1 1 2 >/dev/null 2>&1; then
    printf 'pressure bridge accepted more task handoffs than valid retrievals\n' >&2
    return 1
  fi
  sed -i 's/operation="handoff",status="valid",transport="tcp"} before=0 after=2 delta=2/operation="handoff",status="valid",transport="tcp"} before=0 after=1 delta=1/' \
    "$getsockopt_delta"

  sed -i 's/operation="inject",status="ambiguous",transport="tcp"} before=0 after=1 delta=1/operation="inject",status="ambiguous",transport="tcp"} before=0 after=0 delta=0/' \
    "$getsockopt_delta"
  if pressure_bridge_reconciliation \
    "$getsockopt_delta" getsockopt 1 1 2 >/dev/null 2>&1; then
    printf 'pressure bridge accepted an unreported root\n' >&2
    return 1
  fi

  cat >"$stage_delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=0 after=2 delta=2
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=0 after=2 delta=2
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="stage",status="overload",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=0 after=1 delta=1
EOF
  pressure_bridge_reconciliation "$stage_delta" getsockopt 1 1 2 >/dev/null || {
    printf 'pressure bridge rejected a reason-coded stage failure\n' >&2
    return 1
  }

  cat >"$take_delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=0 after=2 delta=2
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=0 after=2 delta=2
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=0 after=2 delta=2
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="take",status="stale",transport="getsockopt"} before=0 after=1 delta=1
EOF
  pressure_bridge_reconciliation "$take_delta" getsockopt 1 1 2 >/dev/null || {
    printf 'pressure bridge rejected a reason-coded retrieval failure\n' >&2
    return 1
  }

  cat >"$unix_delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="inject",status="ambiguous",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="unix"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="take",status="missing",transport="unix"} before=0 after=1 delta=1
EOF
  reconciliation="$(pressure_bridge_reconciliation "$unix_delta" unix 1 1 2)" || {
    printf 'pressure bridge rejected Unix retrieval after an upstream drop\n' >&2
    return 1
  }
  [[ "$reconciliation" == *'"upstream_failure_count":1'* &&
    "$reconciliation" == *'"retrieval_failure_count":1'* ]] || {
    printf 'pressure bridge hid overlapping Unix upstream and retrieval reasons\n' >&2
    return 1
  }
}

test_primary_security_metrics_are_explicitly_scoped() {
  local -r delta="$TEST_TMP_DIR/primary-security-metrics.delta"
  local -r sibling_delta="$TEST_TMP_DIR/primary-security-sibling-metrics.delta"

  cat >"$delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="negotiate",status="missing",transport="getsockopt"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="negotiate",status="unauthorized",transport="getsockopt"} before=0 after=1 delta=1
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="getsockopt"} before=4 after=12 delta=8
EOF
  if (
    ALLOW_PRIMARY_SECURITY_METRICS=false
    assert_bridge_metric_delta "$delta" getsockopt 2 0
  ) >/dev/null 2>&1; then
    printf 'bridge metrics accepted abuse traffic without the scoped policy\n' >&2
    return 1
  fi
  (
    ALLOW_PRIMARY_SECURITY_METRICS=true
    assert_bridge_metric_delta "$delta" getsockopt 2 0
  ) || {
    printf 'bridge metrics rejected explicitly scoped primary abuse traffic\n' >&2
    return 1
  }
  assert_primary_security_metric_delta "$delta" negotiate 1
  assert_primary_security_metric_delta "$delta" take 8
  if assert_primary_security_metric_delta "$delta" take 9 >/dev/null 2>&1; then
    printf 'primary security metrics accepted an unmet minimum\n' >&2
    return 1
  fi

  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=3 after=5 delta=2' \
    >"$sibling_delta"
  assert_primary_security_metric_delta "$sibling_delta" negotiate 0 0
  assert_primary_security_metric_delta "$sibling_delta" take 0 0
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="negotiate",status="unauthorized",transport="getsockopt"} before=0 after=1 delta=1' \
    'obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="getsockopt"} before=0 after=5 delta=5' \
    >>"$sibling_delta"
  assert_primary_security_metric_delta "$sibling_delta" negotiate 1 1
  assert_primary_security_metric_delta "$sibling_delta" take 5
  if assert_primary_security_metric_delta "$sibling_delta" take 6 >/dev/null 2>&1; then
    printf 'sibling security control accepted an unmet take requirement\n' >&2
    return 1
  fi
}

test_primary_security_identity_requires_same_cgroup_and_nonroot_user() {
  local -r java_cgroup="$TEST_TMP_DIR/primary-java.cgroup"
  local -r probe_cgroup="$TEST_TMP_DIR/primary-probe.cgroup"
  local -r probe_status="$TEST_TMP_DIR/primary-probe.status"

  printf '0::/demo/java\n' >"$java_cgroup"
  printf '0::/demo/java\n' >"$probe_cgroup"
  cat >"$probe_status" <<'EOF'
Name:	security-probe
Uid:	65534	65534	65534	65534
Gid:	65534	65534	65534	65534
EOF
  assert_primary_security_cgroup_identity \
    "$java_cgroup" "$probe_cgroup" "$probe_status"

  printf '0::/demo/sibling\n' >"$probe_cgroup"
  if assert_primary_security_cgroup_identity \
    "$java_cgroup" "$probe_cgroup" "$probe_status" >/dev/null 2>&1; then
    printf 'primary security identity accepted a sibling cgroup\n' >&2
    return 1
  fi

  printf '0::/demo/java\n' >"$probe_cgroup"
  sed -i 's/65534/0/g' "$probe_status"
  if assert_primary_security_cgroup_identity \
    "$java_cgroup" "$probe_cgroup" "$probe_status" >/dev/null 2>&1; then
    printf 'primary security identity accepted a root probe\n' >&2
    return 1
  fi
}

test_primary_security_probe_is_not_self_certifying() {
  local primary_control=""
  local unverified_checks=""
  local sibling_release_line=""
  local sibling_completion_line=""
  local same_cgroup_start_line=""
  local same_cgroup_delta_line=""

  primary_control="$(declare -f run_primary_security_control)"
  unverified_checks="$(grep -Fc '"status":"unverified","mode":"primary"' \
    <<<"$primary_control" || true)"
  [[ "$unverified_checks" == "2" ]] || {
    printf 'primary security control did not require both raw probes to be unverified\n' >&2
    return 1
  }
  [[ "$primary_control" != *'"status":"passed","mode":"primary"'* ]] || {
    printf 'primary security control treated raw probe output as proof\n' >&2
    return 1
  }
  [[ "$primary_control" == *'"probe_status":"unverified"'* && \
    "$primary_control" == *'"probe_verification":"metrics_verified"'* ]] || {
    printf 'primary security result did not distinguish observation from verification\n' >&2
    return 1
  }
  [[ "$primary_control" == *'assert_primary_security_metric_delta "$sibling_delta" negotiate 1 1'* && \
    "$primary_control" == *'assert_primary_security_metric_delta "$sibling_delta" take 5'* && \
    "$primary_control" == *'"$RESULT_DIR/phases/security-primary-sibling-complete/obi-metrics.prom"'* && \
    "$primary_control" == *'assert_primary_security_metric_delta "$same_cgroup_delta" negotiate 1 1'* && \
    "$primary_control" == *'assert_primary_security_metric_delta "$same_cgroup_delta" take 5'* ]] || {
    printf 'primary security control did not retain per-topology enforcement evidence\n' >&2
    return 1
  }
  sibling_release_line="$(awk '/docker kill --signal SIGUSR1/ { print NR; exit }' \
    <<<"$primary_control")"
  sibling_completion_line="$(awk '/capture_metric_phase_evidence "security-primary-sibling-complete"/ { print NR; exit }' \
    <<<"$primary_control")"
  same_cgroup_start_line="$(awk '/docker exec --user 65534:65534/ { print NR; exit }' \
    <<<"$primary_control")"
  same_cgroup_delta_line="$(awk '/assert_primary_security_metric_delta "\$same_cgroup_delta" negotiate 1 1/ { print NR; exit }' \
    <<<"$primary_control")"
  [[ "$sibling_release_line" =~ ^[1-9][0-9]*$ && \
    "$sibling_completion_line" =~ ^[1-9][0-9]*$ && \
    "$same_cgroup_start_line" =~ ^[1-9][0-9]*$ && \
    "$same_cgroup_delta_line" =~ ^[1-9][0-9]*$ && \
    sibling_release_line -lt sibling_completion_line && \
    sibling_completion_line -lt same_cgroup_start_line && \
    same_cgroup_start_line -lt same_cgroup_delta_line ]] || {
    printf 'primary security probes did not use isolated metric windows\n' >&2
    return 1
  }
}

test_generation_fault_protocol_and_output_are_exact() {
  local -r result_dir="$TEST_TMP_DIR/generation-fault-protocol"
  local -r control_dir="$result_dir/generation-fault-control"
  local -r armed="$control_dir/armed"
  local -r output="$result_dir/helper.json"
  local -r stderr_output="$result_dir/helper.stderr"
  local owner=""

  install -d -m 0700 -- "$control_dir"
  owner="$(id -u)" || return $?
  printf 'armed\n' >"$armed"
  chmod 0600 -- "$armed"
  (
    RESULT_DIR="$result_dir"
    wait_for_generation_fault_armed "$control_dir" "$$" "$owner"
  ) || {
    printf 'generation fault rejected its exact armed record\n' >&2
    return 1
  }
  chmod 0644 -- "$armed"
  if (
    RESULT_DIR="$result_dir"
    wait_for_generation_fault_armed "$control_dir" "$$" "$owner"
  ) >/dev/null 2>&1; then
    printf 'generation fault accepted a permissive armed record\n' >&2
    return 1
  fi
  chmod 0600 -- "$armed"

  (
    RESULT_DIR="$result_dir"
    publish_generation_fault_release "$control_dir" "$owner"
  ) || {
    printf 'generation fault could not publish its exact release record\n' >&2
    return 1
  }
  [[ "$(stat -c '%u:%a:%h:%s' -- "$control_dir/release")" == \
    "$owner:600:1:8" && "$(<"$control_dir/release")" == release ]] || {
    printf 'generation fault release metadata changed\n' >&2
    return 1
  }

  printf '%s\n' \
    '{"status":"passed","mode":"generation-mismatch","mutated":true,"restored":true}' \
    >"$output"
  : >"$stderr_output"
  assert_generation_fault_helper_output "$output" "$stderr_output" || {
    printf 'generation fault rejected its fixed helper output\n' >&2
    return 1
  }
  printf '%s\n' \
    '{"status":"passed","mode":"generation-mismatch","mutated":true,"restored":true,"generation":7}' \
    >"$output"
  if assert_generation_fault_helper_output "$output" "$stderr_output" \
    >/dev/null 2>&1; then
    printf 'generation fault helper output disclosed an extra field\n' >&2
    return 1
  fi
}

test_generation_process_identity_is_namespace_qualified() {
  local -r valid_status=$'Tgid:\t1\nNSpid:\t123\t1\nPidNamespace:\tpid:[4026532999]\nChildPidNamespace:\tpid:[4026532999]\nComm:\tjava\n'
  local identity=""
  local invalid_status=""
  local control=""
  local resolver=""

  identity="$(
    process_namespace_identity_from_snapshot "$valid_status" 1
  )" || return $?
  [[ "$identity" == "1 4026532999" ]] || {
    printf 'generation identity did not select the namespace-qualified JVM PID\n' >&2
    return 1
  }

  for invalid_status in \
    $'Tgid:\t2\nNSpid:\t123\t1\nPidNamespace:\tpid:[4026532999]\nChildPidNamespace:\tpid:[4026532999]\nComm:\tjava\n' \
    $'Tgid:\t1\nNSpid:\t123\t2\nPidNamespace:\tpid:[4026532999]\nChildPidNamespace:\tpid:[4026532999]\nComm:\tjava\n' \
    $'Tgid:\t1\nNSpid:\t123\t1\nNSpid:\t123\t1\nPidNamespace:\tpid:[4026532999]\nChildPidNamespace:\tpid:[4026532999]\nComm:\tjava\n' \
    $'Tgid:\t1\nNSpid:\t123\t1\nPidNamespace:\tpid:[4026532999]\nChildPidNamespace:\tpid:[4026533000]\nComm:\tjava\n' \
    $'Tgid:\t1\nNSpid:\t123\t1\nPidNamespace:\tpid:[4026532999]\nChildPidNamespace:\tpid:[4026532999]\nComm:\tnot-java\n'; do
    if process_namespace_identity_from_snapshot "$invalid_status" 1 \
      >/dev/null 2>&1; then
      printf 'generation identity accepted an invalid proc status snapshot\n' >&2
      return 1
    fi
  done
  if process_namespace_identity_from_snapshot \
    "${valid_status/pid:\[4026532999\]/pid:[0]}" 1 >/dev/null 2>&1 || \
    process_namespace_identity_from_snapshot \
      "${valid_status//4026532999/4294967296}" 1 >/dev/null 2>&1; then
    printf 'generation identity accepted an invalid namespace inode\n' >&2
    return 1
  fi

  control="$(declare -f run_primary_generation_mismatch_control)" || return $?
  resolver="$(declare -f resolve_container_process_namespace_identity)" || return $?
  [[ "$control" == *'resolve_container_process_namespace_identity "$java_container"'* && \
    "$control" == *'"$java_inspection_after" == "$java_inspection_before"'* && \
    "$control" == *'--process-pid "$java_process_pid"'* && \
    "$control" == *'--process-namespace "$java_process_namespace"'* && \
    "$control" != *'/proc/$java_host_pid/'* && \
    "$resolver" == *'docker exec "$container"'* && \
    "$resolver" == *'/proc/1/ns/pid)'* && \
    "$resolver" == *'/proc/1/ns/pid_for_children)'* ]] || {
    printf 'generation helper invocation lost its exact namespace-qualified identity\n' >&2
    return 1
  }
}

test_generation_mismatch_mutation_spans_the_victim_take() {
  local -ri backend_hold_milliseconds=20000
  local -ri proxy_timeout_seconds=45
  local -ri proxy_slack_seconds=5
  local control=""
  local armed_line=""
  local release_barrier_line=""
  local take_fence_line=""
  local restore_release_line=""
  local helper_reap_line=""
  local helper_verify_line=""
  local victim_reap_line=""
  local consume_line=""

  control="$(declare -f run_primary_generation_mismatch_control)" || return $?
  armed_line="$(awk '/wait_for_generation_fault_armed/ { line = NR } END { print line }' \
    <<<"$control")"
  release_barrier_line="$(awk '/release_primary_live_fd_barrier/ { line = NR } END { print line }' \
    <<<"$control")"
  take_fence_line="$(awk '/wait_for_bridge_take_attempts_quiescent/ { line = NR } END { print line }' \
    <<<"$control")"
  restore_release_line="$(awk '/publish_generation_fault_release/ { line = NR } END { print line }' \
    <<<"$control")"
  helper_reap_line="$(awk '/wait_for_background_process "\$helper_pid"/ { line = NR } END { print line }' \
    <<<"$control")"
  helper_verify_line="$(awk '/assert_generation_fault_helper_output/ { line = NR } END { print line }' \
    <<<"$control")"
  victim_reap_line="$(awk '/wait_for_background_process "\$victim_pid"/ { line = NR } END { print line }' \
    <<<"$control")"
  consume_line="$(awk '/consume_primary_live_fd_barrier/ { line = NR } END { print line }' \
    <<<"$control")"

  [[ "$armed_line" =~ ^[1-9][0-9]*$ && \
    "$release_barrier_line" =~ ^[1-9][0-9]*$ && \
    "$take_fence_line" =~ ^[1-9][0-9]*$ && \
    "$restore_release_line" =~ ^[1-9][0-9]*$ && \
    "$helper_reap_line" =~ ^[1-9][0-9]*$ && \
    "$helper_verify_line" =~ ^[1-9][0-9]*$ && \
    "$victim_reap_line" =~ ^[1-9][0-9]*$ && \
    "$consume_line" =~ ^[1-9][0-9]*$ && \
    armed_line -lt release_barrier_line && \
    release_barrier_line -lt take_fence_line && \
    take_fence_line -lt restore_release_line && \
    restore_release_line -lt helper_reap_line && \
    helper_reap_line -lt helper_verify_line && \
    helper_verify_line -lt victim_reap_line && \
    victim_reap_line -lt consume_line ]] || {
    printf 'generation mutation no longer spans the exact victim take and restore fence\n' >&2
    return 1
  }
  [[ "$control" == *'consume_primary_live_fd_barrier "$consumption_evidence" primary-fault'* && \
    "$control" == *'ALLOW_PRIMARY_SECURITY_METRICS=true'* && \
    "$control" == *'MAX_SHELL_INTEGER - 4'* && \
    "$control" == *'"$((before_take_attempts + 4))"'* && \
    "$control" == *'assert_security_metric_delta'* && \
    "$control" == *'"$metric_delta" take missing getsockopt 3 3'* ]] || {
    printf 'generation mismatch lost its fault-stack or bounded missing evidence\n' >&2
    return 1
  }
  ((GENERATION_FAULT_TAKE_FENCE_TIMEOUT_SECONDS * 1000 + \
      GENERATION_FAULT_REAP_TIMEOUT_SECONDS * 1000 + \
      proxy_slack_seconds * 1000 < \
      backend_hold_milliseconds && \
    PRIMARY_LIVE_FD_BARRIER_READY_TIMEOUT_SECONDS + \
      GENERATION_FAULT_READY_TIMEOUT_SECONDS + \
      backend_hold_milliseconds / 1000 + \
      proxy_slack_seconds < \
      proxy_timeout_seconds && \
    proxy_timeout_seconds < \
      GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS && \
    GENERATION_FAULT_REQUEST_TIMEOUT_SECONDS < 75 && \
    GENERATION_FAULT_RELEASE_TIMEOUT_SECONDS < \
      GENERATION_FAULT_HELPER_TIMEOUT_SECONDS)) || {
    printf 'generation mismatch deadlines no longer preserve restore slack\n' >&2
    return 1
  }
  grep -Fq 'requests[i].Endpoint = "/api/generation-fence"' \
    "$TEST_SCRIPT_DIR/../tracecheck/cmd/scenario/main.go" || {
    printf 'generation mismatch request lost its dedicated backend endpoint\n' >&2
    return 1
  }
  grep -Fq 'requests[i].GenerationFenceHoldMillis = 20_000' \
    "$TEST_SCRIPT_DIR/../tracecheck/cmd/scenario/main.go" || {
    printf 'generation mismatch request lost its bounded backend hold\n' >&2
    return 1
  }
  grep -Fq 'static final int MAX_GENERATION_FENCE_HOLD_MILLIS = 20_000;' \
    "$TEST_SCRIPT_DIR/../java/src/main/java/io/opentelemetry/obi/examples/ApacheJavaHttpsBackend.java" || {
    printf 'generation mismatch backend hold no longer matches the request contract\n' >&2
    return 1
  }
  local -r apache_config="$TEST_SCRIPT_DIR/../apache/httpd.conf"
  local generation_route_line=""
  local default_route_line=""
  generation_route_line="$(grep -Fn \
    'ProxyPass "/api/generation-fence" "https://localhost:18443/api/generation-fence" connectiontimeout=3 timeout=45' \
    "$apache_config" | cut -d: -f1)" || return $?
  default_route_line="$(grep -Fn \
    'ProxyPass "/" "https://localhost:18443/" connectiontimeout=3 timeout=10' \
    "$apache_config" | cut -d: -f1)" || return $?
  [[ "$generation_route_line" =~ ^[1-9][0-9]*$ && \
    "$default_route_line" =~ ^[1-9][0-9]*$ && \
    generation_route_line -lt default_route_line ]] || {
    printf 'generation mismatch route lost its dedicated ordered proxy timeout\n' >&2
    return 1
  }
}

test_generation_take_fence_waits_for_the_fourth_attempt() {
  local -r result_dir="$TEST_TMP_DIR/generation-take-fence"
  local -r output="$result_dir/take-fence.prom"
  local -r overshoot_output="$result_dir/take-fence-overshoot.prom"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    SELECTED_TRANSPORT=getsockopt
    ALLOW_PRIMARY_SECURITY_METRICS=false
    ALLOW_UNIX_SECURITY_METRICS=false
    local -i fetches=0
    fetch_obi_metrics() {
      local -r destination="$1"
      local missing=2

      ((fetches += 1))
      if ((fetches >= 2)); then
        missing=3
      fi
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 7' \
        "obi_java_remote_parent_operations_total{operation=\"take\",status=\"missing\",transport=\"getsockopt\"} $missing" \
        'obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="getsockopt"} 1' \
        'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 11' \
        "obi_java_remote_parent_operations_total{operation=\"report\",status=\"valid\",transport=\"tcp\"} $fetches" \
        >"$destination"
    }
    sleep() { :; }

    wait_for_bridge_take_attempts_quiescent \
      11 11 "$output" "generation victim take" 5
    [[ "$fetches" == 3 && "$(bridge_take_attempt_total "$output")" == 11 ]]
  ) || {
    printf 'generation take fence passed before observing the victim attempt\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$result_dir"
    SELECTED_TRANSPORT=getsockopt
    ALLOW_PRIMARY_SECURITY_METRICS=false
    ALLOW_UNIX_SECURITY_METRICS=false
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 7' \
        'obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} 4' \
        'obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="getsockopt"} 1' \
        'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 11' \
        'obi_java_remote_parent_operations_total{operation="report",status="valid",transport="tcp"} 1' \
        >"$1"
    }
    sleep() { :; }
    wait_for_bridge_take_attempts_quiescent \
      11 11 "$overshoot_output" "generation victim take" 5
  ) >/dev/null 2>&1; then
    printf 'generation take fence accepted an overshot attempt count\n' >&2
    return 1
  fi
}

test_primary_live_fd_descriptor_is_exact_and_bounded() {
  local descriptor=""

  descriptor="$(primary_live_fd_descriptor 0)" || return $?
  [[ "$descriptor" == "0" ]] || return 1
  descriptor="$(primary_live_fd_descriptor 2147483647)" || return $?
  [[ "$descriptor" == "2147483647" ]] || return 1
  for descriptor in '' -1 00 0001 2147483648 99999999999; do
    if primary_live_fd_descriptor "$descriptor" >/dev/null 2>&1; then
      printf 'primary live-descriptor parser accepted an unsafe descriptor: %s\n' \
        "${descriptor:-empty}" >&2
      return 1
    fi
  done
}

test_primary_live_fd_probe_result_is_exact() {
  local -r good="$TEST_TMP_DIR/primary-live-fd-good.json"
  local -r unsupported="$TEST_TMP_DIR/primary-live-fd-unsupported.json"
  local -r extra="$TEST_TMP_DIR/primary-live-fd-extra.json"
  local -r nested_extra="$TEST_TMP_DIR/primary-live-fd-nested-extra.json"
  local -r unsupported_extra="$TEST_TMP_DIR/primary-live-fd-unsupported-extra.json"
  local -r valid="$TEST_TMP_DIR/primary-live-fd-valid.json"

  cat >"$good" <<'EOF'
{"status":"unverified","mode":"primary-live-fd","attempts":1,"cases":[{"name":"pidfd-duplicate","outcome":"opened"},{"name":"standard-option","outcome":"preserved"},{"name":"wrong-process-negotiation","outcome":"native-unsupported"},{"name":"duplicated-fd-take","outcome":"native-unsupported"}]}
EOF
  assert_primary_live_fd_probe_output "$good" || {
    printf 'primary live-descriptor result rejected the exact denial observation\n' >&2
    return 1
  }

  cat >"$unsupported" <<'EOF'
{"status":"unsupported","mode":"primary-live-fd","cases":[{"name":"pidfd-duplicate","outcome":"unavailable"}]}
EOF
  assert_primary_live_fd_probe_unsupported_output "$unsupported" || {
    printf 'primary live-descriptor unsupported result rejected its exact schema\n' >&2
    return 1
  }
  if assert_primary_live_fd_probe_output "$unsupported" >/dev/null 2>&1; then
    printf 'primary live-descriptor result accepted an unsupported probe\n' >&2
    return 1
  fi

  cat >"$extra" <<'EOF'
{"status":"unverified","mode":"primary-live-fd","attempts":1,"descriptor":7,"cases":[{"name":"pidfd-duplicate","outcome":"opened"},{"name":"standard-option","outcome":"preserved"},{"name":"wrong-process-negotiation","outcome":"native-unsupported"},{"name":"duplicated-fd-take","outcome":"native-unsupported"}]}
EOF
  if assert_primary_live_fd_probe_output "$extra" >/dev/null 2>&1; then
    printf 'primary live-descriptor result accepted an unsafe extra field\n' >&2
    return 1
  fi

  cat >"$nested_extra" <<'EOF'
{"status":"unverified","mode":"primary-live-fd","attempts":1,"cases":[{"name":"pidfd-duplicate","outcome":"opened","descriptor":7},{"name":"standard-option","outcome":"preserved"},{"name":"wrong-process-negotiation","outcome":"native-unsupported"},{"name":"duplicated-fd-take","outcome":"native-unsupported"}]}
EOF
  if assert_primary_live_fd_probe_output "$nested_extra" >/dev/null 2>&1; then
    printf 'primary live-descriptor result accepted a nested unsafe field\n' >&2
    return 1
  fi

  cat >"$unsupported_extra" <<'EOF'
{"status":"unsupported","mode":"primary-live-fd","cases":[{"name":"pidfd-duplicate","outcome":"unavailable","descriptor":7}]}
EOF
  if assert_primary_live_fd_probe_unsupported_output "$unsupported_extra" >/dev/null 2>&1; then
    printf 'primary live-descriptor unsupported result accepted a nested unsafe field\n' >&2
    return 1
  fi

  cat >"$valid" <<'EOF'
{"status":"unverified","mode":"primary-live-fd","attempts":1,"cases":[{"name":"pidfd-duplicate","outcome":"opened"},{"name":"standard-option","outcome":"preserved"},{"name":"wrong-process-negotiation","outcome":"native-unsupported"},{"name":"duplicated-fd-take","outcome":"valid"}]}
EOF
  if assert_primary_live_fd_probe_output "$valid" >/dev/null 2>&1; then
    printf 'primary live-descriptor result accepted a valid attacker retrieval\n' >&2
    return 1
  fi
}

test_primary_live_fd_barrier_consumption_accepts_empty_inode() {
  local -r result_dir="$TEST_TMP_DIR/primary-live-fd-barrier-consumption"
  local -r private_directory="$result_dir/fault"
  local -r control_file="$private_directory/java-remote-parent.mode"
  local -r fake_bin="$result_dir/bin"
  local -r evidence="$result_dir/consumed.txt"
  local -r nonempty_evidence="$result_dir/nonempty.txt"
  local -r expected=$'phase=consumed\nmetadata=0:0:600:1:regular empty file\nsize=0'

  mkdir -p -- "$private_directory" "$fake_bin"
  chmod 0700 -- "$private_directory"
  cat >"$fake_bin/id" <<'EOF'
#!/usr/bin/env bash
printf '0\n'
EOF
  cat >"$fake_bin/stat" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

case "$2" in
  '%u:%g:%a:%F') printf '0:0:700:directory\n' ;;
  '%u:%g:%a:%h') printf '0:0:600:1\n' ;;
  '%u:%g:%a:%h:%F')
    if [[ -s "$3" ]]; then
      printf '0:0:600:1:regular file\n'
    else
      printf '0:0:600:1:regular empty file\n'
    fi
    ;;
  '%s') wc -c <"$3" ;;
  *) exit 64 ;;
esac
EOF
  chmod 0755 -- "$fake_bin/id" "$fake_bin/stat"

  (
    PRIMARY_FAULT_STACK_ACTIVE=true
    PRIMARY_FAULT_COMPOSE=(test-compose)
    run_bounded() {
      local -a bounded_command=("$@")
      local script_index=-1
      local index=0

      [[ "${bounded_command[0]}" == 10 ]] || return 1
      for index in "${!bounded_command[@]}"; do
        if [[ "${bounded_command[$index]}" == -ec ]]; then
          script_index="$index"
          break
        fi
      done
      ((script_index >= 0)) || return 1
      PATH="$fake_bin:$PATH" /bin/sh -ec \
        "${bounded_command[$((script_index + 1))]}" \
        sh "$private_directory" "$control_file"
    }

    : >"$control_file"
    consume_primary_live_fd_barrier "$evidence"
    [[ "$(<"$evidence")" == "$expected" && \
      ! -e "$control_file" && ! -L "$control_file" ]]
    printf 'release:124\n' >"$control_file"
    if consume_primary_live_fd_barrier "$nonempty_evidence"; then
      return 1
    fi
    [[ "$(<"$control_file")" == release:124 && -s "$control_file" ]]
  ) || {
    printf 'primary live-descriptor barrier rejected the trusted empty inode\n' >&2
    return 1
  }
}

test_primary_live_fd_control_uses_exact_barrier_protocol() {
  local control=""
  local arm=""
  local release=""
  local consume=""
  local waiter=""
  local probe_runner=""
  local recovery_scenario=""
  local primary_control=""
  local runtime_contract=""
  local arm_line=""
  local victim_line=""
  local ready_line=""
  local probe_line=""
  local probe_delta_line=""
  local release_line=""
  local victim_wait_line=""
  local unsupported_status_line=""
  local unsupported_cleanup_line=""

  control="$(declare -f run_primary_live_fd_security_control)"
  arm="$(declare -f arm_primary_live_fd_barrier)"
  release="$(declare -f release_primary_live_fd_barrier)"
  consume="$(declare -f consume_primary_live_fd_barrier)"
  waiter="$(declare -f wait_for_primary_live_fd_barrier_ready)"
  probe_runner="$(declare -f run_primary_live_fd_probe)"
  recovery_scenario="$(declare -f run_primary_live_fd_security_recovery_scenario)"
  primary_control="$(declare -f run_primary_security_control)"
  runtime_contract="$(declare -f assert_runtime_contract)"
  [[ "$control" == *'primary-live-fd'* && \
    "$control" == *'PRIMARY_LIVE_FD_COMPOSE'* && \
    "$control" != *'PRIMARY_FAULT_COMPOSE'* && \
    "$arm" == *'PRIMARY_LIVE_FD_COMPOSE'* && \
    "$consume" == *'PRIMARY_LIVE_FD_COMPOSE'* && \
    "$control" == *'arm_primary_live_fd_barrier'* && \
    "$control" == *'wait_for_primary_live_fd_barrier_ready'* && \
    "$waiter" == *'^ready:([0-9]+):task=missing:thread=missing$'* && \
    "$control" == *'run_primary_live_fd_probe'* && \
    "$control" == *'timeout --signal=TERM --kill-after=10s'* && \
    "$control" == *'--request-timeout "${PRIMARY_LIVE_FD_VICTIM_REQUEST_TIMEOUT_SECONDS}s"'* && \
    "$control" == *'primary_live_fd_remaining_timeout'* && \
    "$control" == *'assert_primary_security_metric_delta "$probe_delta" negotiate 1 1'* && \
    "$control" == *'assert_primary_security_metric_delta "$probe_delta" take 2 2'* && \
    "$control" == *'assert_primary_security_metric_delta "$full_delta" take 2 2'* && \
    "$control" == *'"$probe_delta" take missing getsockopt 2 2'* && \
    "$control" == *'"$full_delta" take missing getsockopt 2 2'* && \
    "$control" == *'assert_bridge_metric_delta "$probe_delta" getsockopt 0 0 2 1 1 false 0'* && \
    "$control" == *'assert_bridge_metric_delta "$full_delta" getsockopt 1 0 2 1 1 false 0'* ]] || {
    printf 'primary live-descriptor control omitted its exact barrier or metric gates\n' >&2
    return 1
  }
  [[ "$control" != *'run_bounded "$PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS"'* && \
    "$control" != *'/proc/1/fd'* && "$control" != *'--pid'* && \
    "$control" != *'capture_java_diagnostics'* ]] || {
    printf 'primary live-descriptor control used an unsafe fallback or post-arm diagnostic\n' >&2
    return 1
  }
  [[ "$release" == *'"ready:$descriptor:task=missing:thread=missing"'* && \
    "$release" != *'"ready:$descriptor" ]'* && \
    "$release" == *'printf "release:%s\\n" "$descriptor" >"$control_file"'* && \
    "$release" != *'flock '* && "$release" != *'mv '* ]] || {
    printf 'primary live-descriptor release was not an in-place non-locking write\n' >&2
    return 1
  }
  [[ "$release" == *'before="$(stat -c "%d:%i:%u:%g:%a:%h" "$control_file")"'* && \
    "$release" == *'after="$(stat -c "%d:%i:%u:%g:%a:%h" "$control_file")"'* && \
    "$release" != *'%d:%i:%u:%g:%a:%h:%F'* && \
    "$consume" == *'$(stat -c "%u:%g:%a:%h" "$control_file")" = "0:0:600:1"'* && \
    "$consume" != *'$(stat -c "%u:%g:%a:%h:%F" "$control_file")" = "0:0:600:1:regular file"'* && \
    "$consume" != *'flock '* && "$consume" != *'mv '* ]] || {
    printf 'primary live-descriptor empty-inode metadata contract is unsafe\n' >&2
    return 1
  }
  [[ "$probe_runner" == *'env -u LD_PRELOAD -u OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE /bin/sh -ec'* && \
    "$probe_runner" == *'self_cgroup="$(cat /proc/self/cgroup)"'* && \
    "$probe_runner" == *'pid_one_cgroup="$(cat /proc/1/cgroup)"'* && \
    "$probe_runner" == *'[ "$self_cgroup" = "$pid_one_cgroup" ]'* && \
    "$probe_runner" == *'exec "$probe_path" --mode primary-live-fd'* && \
    "$probe_runner" != *'/proc/1/fd'* && "$probe_runner" != *'--pid'* ]] || {
    printf 'primary live-descriptor probe did not verify its pre-exec root topology\n' >&2
    return 1
  }
  [[ "$primary_control" == *'run_primary_live_fd_security_control "$host_probe"'* && \
    "$primary_control" != *'run_primary_live_fd_security_control "$host_probe" ||'* && \
    "$primary_control" == *'"live_descriptor_probe":"metrics_verified"'* && \
    "$primary_control" == *'"live_descriptor_topology":"pid1-cgroup-verified-preexec"'* && \
    "$control" == *'"wrong_live_socket":"metrics_verified"'* && \
    "$control" == *'"duplicated_fd_wrong_process":"metrics_verified"'* && \
    "$control" == *'"wrong_current_tid_same_fd":"metrics_verified"'* && \
    "$control" == *'"wrong_logical_execution_same_fd":"metrics_verified"'* && \
    "$recovery_scenario" == *'run_scenario basic'* && \
    "$recovery_scenario" == *'return "$scenario_status"'* && \
    "$runtime_contract" == *'primary-live-fd-security'* ]] || {
    printf 'primary security control did not retain the live-descriptor evidence path\n' >&2
    return 1
  }
  awk '
    /^[[:space:]]*if wait_for_background_process/ {
      waiting = 1
      succeeded = 0
      next
    }
    waiting && /victim_exit=0/ {
      succeeded = 1
      next
    }
    waiting && succeeded && /victim_pid=""/ {
      cleared_after_reap++
      waiting = 0
      next
    }
    waiting && /\[\[ "\$victim_exit" == "0" \]\]/ {
      missing_reap_clear++
      waiting = 0
    }
    END { exit !(cleared_after_reap == 2 && missing_reap_clear == 0) }
  ' <<<"$control" || {
    printf 'primary live-descriptor control loses a timed-out victim before trap cleanup\n' >&2
    return 1
  }

  arm_line="$(awk '/arm_primary_live_fd_barrier/ { print NR; exit }' <<<"$control")"
  victim_line="$(awk '/run --rm --no-deps --no-TTY scenario/ { print NR; exit }' <<<"$control")"
  ready_line="$(awk '/wait_for_primary_live_fd_barrier_ready/ { print NR; exit }' <<<"$control")"
  probe_line="$(awk '/run_primary_live_fd_probe/ { print NR; exit }' <<<"$control")"
  probe_delta_line="$(awk '/assert_primary_security_metric_delta "\$probe_delta" negotiate 1 1/ { print NR; exit }' <<<"$control")"
  release_line="$(awk '/release_primary_live_fd_barrier/ { line = NR } END { print line }' <<<"$control")"
  victim_wait_line="$(awk -v release_line="$release_line" \
    'NR > release_line && /wait_for_background_process/ { print NR; exit }' <<<"$control")"
  unsupported_status_line="$(awk '/"status":"unsupported"/ { print NR; exit }' <<<"$control")"
  unsupported_cleanup_line="$(awk -v status_line="$unsupported_status_line" \
    'NR > status_line && /rm -f -- "\$PRIMARY_SECURITY_PROBE_PATH"/ { print NR; exit }' <<<"$control")"
  [[ "$arm_line" =~ ^[1-9][0-9]*$ && "$victim_line" =~ ^[1-9][0-9]*$ && \
    "$ready_line" =~ ^[1-9][0-9]*$ && "$probe_line" =~ ^[1-9][0-9]*$ && \
    "$probe_delta_line" =~ ^[1-9][0-9]*$ && "$release_line" =~ ^[1-9][0-9]*$ && \
    "$victim_wait_line" =~ ^[1-9][0-9]*$ && \
    "$unsupported_status_line" =~ ^[1-9][0-9]*$ && \
    "$unsupported_cleanup_line" =~ ^[1-9][0-9]*$ && \
    arm_line -lt victim_line && victim_line -lt ready_line && \
    ready_line -lt probe_line && probe_line -lt probe_delta_line && \
    probe_delta_line -lt release_line && release_line -lt victim_wait_line && \
    unsupported_status_line -lt unsupported_cleanup_line ]] || {
    printf 'primary live-descriptor control did not sequence barrier, denial, release, and victim evidence\n' >&2
    return 1
  }
}

test_primary_live_fd_barrier_budget_is_consistent() {
  local -r shim_source="$REPO_ROOT/examples/apache-java-https/java/fault/getsockopt_fault_shim.c"
  local barrier_millis=""

  barrier_millis="$(sed -nE \
    's/^[[:space:]]*java_remote_parent_live_fd_barrier_timeout_millis = ([0-9]+),$/\1/p' \
    "$shim_source")" || return $?
  [[ "$barrier_millis" =~ ^[1-9][0-9]*$ && \
    "$barrier_millis" == "$((PRIMARY_LIVE_FD_BARRIER_TIMEOUT_SECONDS * 1000))" ]] || {
    printf 'primary live-descriptor shim and runner barrier deadlines diverged\n' >&2
    return 1
  }
  ((PRIMARY_LIVE_FD_PROBE_TIMEOUT_SECONDS +
    PRIMARY_LIVE_FD_METRICS_TIMEOUT_SECONDS +
    PRIMARY_LIVE_FD_METRIC_CAPTURE_TIMEOUT_SECONDS +
    PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS <
    PRIMARY_LIVE_FD_PRE_RELEASE_DEADLINE_SECONDS)) || {
    printf 'primary live-descriptor pre-release work exceeds its deadline\n' >&2
    return 1
  }
  ((PRIMARY_LIVE_FD_PRE_RELEASE_DEADLINE_SECONDS +
    PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS <
    PRIMARY_LIVE_FD_BARRIER_TIMEOUT_SECONDS)) || {
    printf 'primary live-descriptor release budget reaches the shim deadline\n' >&2
    return 1
  }
  ((PRIMARY_LIVE_FD_VICTIM_REQUEST_TIMEOUT_SECONDS >
    PRIMARY_LIVE_FD_PRE_RELEASE_DEADLINE_SECONDS +
      PRIMARY_LIVE_FD_RELEASE_TIMEOUT_SECONDS &&
    PRIMARY_LIVE_FD_VICTIM_SCENARIO_TIMEOUT_SECONDS >
      PRIMARY_LIVE_FD_VICTIM_REQUEST_TIMEOUT_SECONDS &&
    PRIMARY_LIVE_FD_VICTIM_TIMEOUT_SECONDS ==
      PRIMARY_LIVE_FD_VICTIM_SCENARIO_TIMEOUT_SECONDS +
        PRIMARY_LIVE_FD_VICTIM_STARTUP_BUDGET_SECONDS +
        PRIMARY_LIVE_FD_VICTIM_SUPERVISOR_SLACK_SECONDS)) || {
    printf 'primary live-descriptor victim timeouts do not cover the release path\n' >&2
    return 1
  }
}

test_primary_live_fd_recovery_scenario_propagates_failure() {
  local status=0

  (
    SCENARIO_VARIANT=original
    run_scenario() {
      [[ "$1" == basic && "$SCENARIO_VARIANT" == security-primary-live-fd-recovery ]] || return 1
      return 47
    }

    if run_primary_live_fd_security_recovery_scenario "$SCENARIO_VARIANT"; then
      return 1
    else
      status=$?
    fi
    [[ "$status" == 47 && "$SCENARIO_VARIANT" == original ]]
  ) || {
    printf 'primary live-descriptor recovery scenario failure did not propagate\n' >&2
    return 1
  }
}

test_primary_live_fd_control_restores_the_base_stack() {
  local -r result_dir="$TEST_TMP_DIR/primary-live-fd-recovery"
  local -r probe_source="$result_dir/security-probe"
  local -r observed="$result_dir/observed"
  local control_status=0

  mkdir -p -- "$result_dir"
  printf 'probe\n' >"$probe_source"
  (
    RESULT_DIR="$result_dir"
    TRANSPORT=getsockopt
    SELECTED_TRANSPORT=getsockopt
    BRIDGE_RUNNING=true
    PRIMARY_FAULT_STACK_ACTIVE=false
    SCENARIO_VARIANT=original
    : >"$observed"
    recreate_instrumented_stack() {
      printf 'recreate:%s:%s\n' "$2" "$6" >>"$observed"
    }
    assert_runtime_contract() {
      printf 'contract:%s\n' "$1" >>"$observed"
      [[ "$1" != primary-live-fd-security ]]
    }

    if run_primary_live_fd_security_control "$probe_source"; then
      return 1
    else
      control_status=$?
    fi
    [[ "$control_status" == "1" && ! -e "$result_dir/primary-live-fd-security-recovery-required" && \
      "$SCENARIO_VARIANT" == original ]]
  ) || {
    printf 'primary live-descriptor control did not restore after fault-stack validation failure\n' >&2
    return 1
  }
  local -r expected=$'recreate:primary live-descriptor security preparation:primary-live-fd\ncontract:primary-live-fd-security\nrecreate:post-primary live-descriptor security recovery:base\ncontract:basic'
  [[ "$(<"$observed")" == "$expected" ]] || {
    printf 'primary live-descriptor recovery changed:\n%s\n' "$(<"$observed")" >&2
    return 1
  }
}

test_unix_security_metrics_require_explicit_race_scope() {
  local -r delta="$TEST_TMP_DIR/unix-security-race-metrics.delta"

  cat >"$delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="unix"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="unix"} before=4 after=12 delta=8
EOF
  if (
    ALLOW_UNIX_SECURITY_METRICS=false
    assert_bridge_metric_delta "$delta" unix 2 0
  ) >/dev/null 2>&1; then
    printf 'bridge metrics accepted Unix abuse without the scoped race policy\n' >&2
    return 1
  fi
  (
    ALLOW_UNIX_SECURITY_METRICS=true
    assert_bridge_metric_delta "$delta" unix 2 0
  ) || {
    printf 'bridge metrics rejected explicitly scoped Unix abuse traffic\n' >&2
    return 1
  }
  assert_security_metric_delta "$delta" take unauthorized unix 8 8
}

test_unix_security_provider_wait_uses_restart_cursor() {
  local unix_control=""

  unix_control="$(declare -f run_unix_security_control)"
  [[ "$unix_control" != *'provider_since'* ]] || {
    printf 'Unix security control captured the provider log cursor after restart recovery\n' >&2
    return 1
  }
  grep -Fq \
    'post-replacement Java bridge provider" "$restart_since" || return $?' \
    <<<"$unix_control" || {
    printf 'Unix security control did not scope provider readiness to the restart\n' >&2
    return 1
  }
}

test_unix_security_quiescence_restores_policy() {
  (
    local observed_policy=""
    local wait_status=0

    ALLOW_UNIX_SECURITY_METRICS=false
    wait_for_bridge_metrics_quiescent() {
      observed_policy="$ALLOW_UNIX_SECURITY_METRICS"
      return 23
    }
    if wait_for_unix_security_metrics_quiescent \
      "$TEST_TMP_DIR/unix-security-settled.prom" "security publication"; then
      printf 'Unix security quiescence ignored the underlying wait failure\n' >&2
      return 1
    else
      wait_status=$?
    fi
    [[ "$wait_status" -eq 23 && "$observed_policy" == "true" && \
      "$ALLOW_UNIX_SECURITY_METRICS" == "false" ]] || {
      printf 'Unix security quiescence did not scope and restore its policy\n' >&2
      return 1
    }
  )
}

test_background_process_polling_handles_proc_race_quietly() {
  local -r fake_bin="$TEST_TMP_DIR/background-process-fake-bin"
  local -r fake_sed="$fake_bin/sed"
  local -r output="$TEST_TMP_DIR/background-process-race.log"

  mkdir -p -- "$fake_bin"
  cat >"$fake_sed" <<'EOF'
#!/usr/bin/env bash
printf 'simulated /proc race\n' >&2
exit 1
EOF
  chmod 0755 "$fake_sed"

  if (
    PATH="$fake_bin:$PATH"
    background_process_is_running "$$"
  ) >"$output" 2>&1; then
    printf 'background process poll accepted a failed proc read\n' >&2
    return 1
  fi
  [[ ! -s "$output" ]] || {
    printf 'background process poll leaked a failed proc-read diagnostic\n' >&2
    return 1
  }
}

test_unix_security_identity_requires_same_cgroup_nonroot_capabilityfree() {
  local -r same_cgroup=$'0::/demo/java\n'
  local -r sibling_cgroup=$'0::/demo/sibling\n'
  local -r valid_status=$'Name:\tsecurity-probe\nUid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\nCapEff:\t0000000000000000\n'
  local -r root_status=$'Name:\tsecurity-probe\nUid:\t0\t0\t0\t0\nGid:\t65534\t65534\t65534\t65534\nCapEff:\t0000000000000000\n'
  local -r capability_status=$'Name:\tsecurity-probe\nUid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\nCapEff:\t0000000000000001\n'

  assert_unix_security_cgroup_identity \
    "$same_cgroup" "$same_cgroup" "$valid_status"
  if assert_unix_security_cgroup_identity \
    "$same_cgroup" "$sibling_cgroup" "$valid_status" >/dev/null 2>&1; then
    printf 'Unix security identity accepted a sibling cgroup\n' >&2
    return 1
  fi
  if assert_unix_security_cgroup_identity \
    "$same_cgroup" "$same_cgroup" "$root_status" >/dev/null 2>&1; then
    printf 'Unix security identity accepted a root peer\n' >&2
    return 1
  fi
  if assert_unix_security_cgroup_identity \
    "$same_cgroup" "$same_cgroup" "$capability_status" >/dev/null 2>&1; then
    printf 'Unix security identity accepted an effective capability\n' >&2
    return 1
  fi
}

test_unix_security_pid_namespace_identity_requires_exact_single_layer() {
  local valid_snapshot=""
  local child_java_snapshot=""
  local child_probe_snapshot=""
  local invalid_java_pid_snapshot=""
  local probe_pid_mismatch_snapshot=""
  local missing_nspid_snapshot=""
  local duplicate_nspid_snapshot=""
  local malformed_nspid_snapshot=""
  local missing_probe_nspid_snapshot=""
  local duplicate_probe_nspid_snapshot=""
  local malformed_probe_nspid_snapshot=""
  local huge_pid_mismatch_snapshot=""
  local output="$TEST_TMP_DIR/unix-security-pid-namespace.log"
  local snapshot=""

  printf -v valid_snapshot '%s\nPid:\t1\nNSpid:\t1\n%s\nPid:\t42\nNSpid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  assert_unix_security_pid_namespace_identity "$valid_snapshot" 42 >"$output" 2>&1
  [[ ! -s "$output" ]] || {
    printf 'Unix PID namespace identity validator emitted raw status data\n' >&2
    return 1
  }

  printf -v child_java_snapshot '%s\nPid:\t1\nNSpid:\t1\t1\n%s\nPid:\t42\nNSpid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v child_probe_snapshot '%s\nPid:\t1\nNSpid:\t1\n%s\nPid:\t42\nNSpid:\t42\t7\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v invalid_java_pid_snapshot '%s\nPid:\t7\nNSpid:\t1\n%s\nPid:\t42\nNSpid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v probe_pid_mismatch_snapshot '%s\nPid:\t1\nNSpid:\t1\n%s\nPid:\t7\nNSpid:\t7\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v missing_nspid_snapshot '%s\nPid:\t1\n%s\nPid:\t42\nNSpid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v duplicate_nspid_snapshot '%s\nPid:\t1\nNSpid:\t1\nNSpid:\t1\n%s\nPid:\t42\nNSpid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v malformed_nspid_snapshot '%s\nPid:\t1\nNSpid:\tinvalid\n%s\nPid:\t42\nNSpid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v missing_probe_nspid_snapshot '%s\nPid:\t1\nNSpid:\t1\n%s\nPid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v duplicate_probe_nspid_snapshot '%s\nPid:\t1\nNSpid:\t1\n%s\nPid:\t42\nNSpid:\t42\nNSpid:\t42\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v malformed_probe_nspid_snapshot '%s\nPid:\t1\nNSpid:\t1\n%s\nPid:\t42\nNSpid:\tinvalid\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  printf -v huge_pid_mismatch_snapshot '%s\nPid:\t1\nNSpid:\t1\n%s\nPid:\t9007199254740992\nNSpid:\t9007199254740992\n' \
    "$UNIX_SECURITY_STATUS_SEPARATOR" "$UNIX_SECURITY_STATUS_SEPARATOR"
  for snapshot in \
    "$child_java_snapshot" \
    "$child_probe_snapshot" \
    "$invalid_java_pid_snapshot" \
    "$probe_pid_mismatch_snapshot" \
    "$missing_nspid_snapshot" \
    "$duplicate_nspid_snapshot" \
    "$malformed_nspid_snapshot" \
    "$missing_probe_nspid_snapshot" \
    "$duplicate_probe_nspid_snapshot" \
    "$malformed_probe_nspid_snapshot"; do
    if assert_unix_security_pid_namespace_identity "$snapshot" 42 >/dev/null 2>&1; then
      printf 'Unix PID namespace identity accepted an invalid status snapshot\n' >&2
      return 1
    fi
  done
  if assert_unix_security_pid_namespace_identity \
    "$huge_pid_mismatch_snapshot" 9007199254740993 >/dev/null 2>&1; then
    printf 'Unix PID namespace identity accepted an imprecise large PID match\n' >&2
    return 1
  fi
  if assert_unix_security_pid_namespace_identity "$valid_snapshot" 1 >/dev/null 2>&1; then
    printf 'Unix PID namespace identity accepted the Java live thread as an attacker PID\n' >&2
    return 1
  fi
}

test_unix_security_pid_namespace_capture_redacts_proc_races() {
  local original_run_bounded=""
  local output=""

  original_run_bounded="$(declare -f run_bounded)"
  run_bounded() {
    printf 'cat: /proc/987654321/comm: No such file or directory\n' >&2
    return 1
  }
  if output="$(capture_unix_security_pid_namespace_status java-container 42 2>&1)"; then
    eval "$original_run_bounded"
    printf 'Unix PID namespace capture unexpectedly succeeded after a proc race\n' >&2
    return 1
  fi
  eval "$original_run_bounded"
  [[ -z "$output" && "$output" != *987654321* ]] || {
    printf 'Unix PID namespace capture leaked a proc-race identity\n' >&2
    return 1
  }
}

test_unix_sibling_security_options_require_exact_nnp() {
  local security_options=""

  assert_unix_sibling_security_options '["no-new-privileges:true"]'
  for security_options in \
    '["no-new-privileges:true","no-new-privileges:false"]' \
    '["no-new-privileges:false"]' \
    '["no-new-privileges:true","seccomp=unconfined"]' \
    '[]' \
    'null'; do
    if assert_unix_sibling_security_options "$security_options" >/dev/null 2>&1; then
      printf 'Unix sibling security options accepted %s\n' "$security_options" >&2
      return 1
    fi
  done
}

test_unix_sibling_tmpfs_requires_empty_configuration() {
  local tmpfs=""

  assert_unix_sibling_tmpfs 'null'
  assert_unix_sibling_tmpfs '{}'
  for tmpfs in '{"tmp":""}' '{"tmp":"rw,size=16m"}' '[]'; do
    if assert_unix_sibling_tmpfs "$tmpfs" >/dev/null 2>&1; then
      printf 'Unix sibling tmpfs policy accepted %s\n' "$tmpfs" >&2
      return 1
    fi
  done
}

test_unix_abuse_race_result_requires_every_case() {
  local -r output="$TEST_TMP_DIR/unix-abuse-race-result.log"

  printf '%s\n' \
    'security probe abuse race ready' \
    '{"status":"passed","mode":"abuse-race","attempts":1,"cases":[{"name":"peer-identity","outcome":"unauthorized"},{"name":"forged-identity","outcome":"unauthorized"},{"name":"malformed","outcome":"malformed"},{"name":"truncated","outcome":"malformed"},{"name":"version-mismatch","outcome":"version_mismatch"},{"name":"oversized","outcome":"unauthorized"},{"name":"repeated-frame","outcome":"unauthorized"},{"name":"repeated-unauthorized","outcome":"bounded"},{"name":"high-rate-admission","outcome":"overload-and-recovery"},{"name":"concurrent-repeated-unauthorized","outcome":"bounded"}]}' \
    >"$output"
  assert_unix_abuse_race_output "$output" false
  if assert_unix_abuse_race_output "$output" >/dev/null 2>&1; then
    printf 'Unix abuse-race result accepted a missing live-Java-forgery policy\n' >&2
    return 1
  fi
  if assert_unix_abuse_race_output "$output" true >/dev/null 2>&1; then
    printf 'Unix abuse-race result accepted a missing live-Java forgery case\n' >&2
    return 1
  fi
  printf '%s\n' \
    '{"status":"passed","mode":"abuse-race","attempts":1,"cases":[{"name":"peer-identity","outcome":"unauthorized"},{"name":"forged-identity","outcome":"unauthorized"},{"name":"forged-live-java-tid","outcome":"unauthorized"},{"name":"malformed","outcome":"malformed"},{"name":"truncated","outcome":"malformed"},{"name":"version-mismatch","outcome":"version_mismatch"},{"name":"oversized","outcome":"unauthorized"},{"name":"repeated-frame","outcome":"unauthorized"},{"name":"repeated-unauthorized","outcome":"bounded"},{"name":"high-rate-admission","outcome":"overload-and-recovery"},{"name":"concurrent-repeated-unauthorized","outcome":"bounded"}]}' \
    >"$output"
  assert_unix_abuse_race_output "$output" true
  if assert_unix_abuse_race_output "$output" false >/dev/null 2>&1; then
    printf 'Unix abuse-race result accepted a live-Java forgery outside its control\n' >&2
    return 1
  fi
  if assert_unix_abuse_race_output "$output" invalid >/dev/null 2>&1; then
    printf 'Unix abuse-race result accepted an invalid live-Java-forgery policy\n' >&2
    return 1
  fi
  printf '%s\n' \
    '{"status":"passed","mode":"abuse-race","attempts":1,"cases":[]}' \
    >"$output"
  if assert_unix_abuse_race_output "$output" false >/dev/null 2>&1; then
    printf 'Unix abuse-race result accepted an incomplete case set\n' >&2
    return 1
  fi
}

test_unix_security_controls_use_isolated_topology_windows() {
  local unix_control=""
  local peer_controls=""
  local sibling_control=""
  local same_cgroup_control=""
  local pid_namespace_capture=""
  local cleanup_control=""
  local sibling_topology=""
  local peer_start_line=""
  local endpoint_start_line=""
  local sibling_baseline_line=""
  local sibling_start_line=""
  local sibling_release_line=""
  local sibling_completion_line=""
  local same_cgroup_baseline_line=""
  local same_cgroup_java_tid_line=""
  local same_cgroup_start_line=""

  unix_control="$(declare -f run_unix_security_control)"
  peer_controls="$(declare -f run_unix_peer_security_controls)"
  sibling_control="$(declare -f run_unix_sibling_security_control)"
  same_cgroup_control="$(declare -f run_unix_same_cgroup_security_control)"
  pid_namespace_capture="$(declare -f capture_unix_security_pid_namespace_status)"
  cleanup_control="$(declare -f cleanup_security_processes)"
  sibling_topology="$(declare -f assert_unix_sibling_security_topology)"

  peer_start_line="$(awk '/run_unix_peer_security_controls/ { print NR; exit }' \
    <<<"$unix_control")"
  endpoint_start_line="$(awk '/SECURITY_PROBE_MODE="endpoint"/ { print NR; exit }' \
    <<<"$unix_control")"
  sibling_baseline_line="$(awk '/Unix sibling security probe baseline/ { print NR; exit }' \
    <<<"$sibling_control")"
  sibling_start_line="$(awk '/security-unix-sibling-probe/ { print NR; exit }' \
    <<<"$sibling_control")"
  sibling_release_line="$(awk '/docker kill --signal SIGUSR1/ { print NR; exit }' \
    <<<"$sibling_control")"
  sibling_completion_line="$(awk '/Unix sibling security probe completion/ { print NR; exit }' \
    <<<"$sibling_control")"
  same_cgroup_baseline_line="$(awk '/Unix same-cgroup security probe baseline/ { print NR; exit }' \
    <<<"$same_cgroup_control")"
  same_cgroup_java_tid_line="$(awk '/java_live_tid=1/ { print NR; exit }' \
    <<<"$same_cgroup_control")"
  same_cgroup_start_line="$(awk '/docker exec --user 65534:65534/ { print NR; exit }' \
    <<<"$same_cgroup_control")"
  [[ "$peer_start_line" =~ ^[1-9][0-9]*$ && \
    "$endpoint_start_line" =~ ^[1-9][0-9]*$ && \
    peer_start_line -lt endpoint_start_line && \
    "$sibling_baseline_line" =~ ^[1-9][0-9]*$ && \
    "$sibling_start_line" =~ ^[1-9][0-9]*$ && \
    "$sibling_release_line" =~ ^[1-9][0-9]*$ && \
    "$sibling_completion_line" =~ ^[1-9][0-9]*$ && \
    "$same_cgroup_baseline_line" =~ ^[1-9][0-9]*$ && \
    "$same_cgroup_java_tid_line" =~ ^[1-9][0-9]*$ && \
    "$same_cgroup_start_line" =~ ^[1-9][0-9]*$ && \
    sibling_baseline_line -lt sibling_start_line && \
    sibling_start_line -lt sibling_release_line && \
    sibling_release_line -lt sibling_completion_line && \
    same_cgroup_baseline_line -lt same_cgroup_java_tid_line && \
    same_cgroup_java_tid_line -lt same_cgroup_start_line ]] || {
    printf 'Unix security controls do not preserve isolated attacker windows\n' >&2
    return 1
  }
  [[ "$peer_controls" == *'run_unix_sibling_security_control "$java_container"'* && \
    "$peer_controls" == *'run_unix_same_cgroup_security_control "$java_container"'* && \
    "$sibling_control" == *'security-unix-sibling-probe'* && \
    "$sibling_control" != *'--force-recreate security-probe'* && \
    "$sibling_control" == *'assert_unix_sibling_security_topology'* && \
    "$sibling_control" == *'security-unix-sibling-victim'* && \
    "$sibling_control" == *'assert_unix_abuse_race_output "$output" false'* && \
    "$sibling_control" != *'--forged-tid'* && \
    "$same_cgroup_control" == *'docker exec --user 65534:65534'* && \
    "$same_cgroup_control" == *'HostConfig.PidMode'* && \
    "$same_cgroup_control" == *'/proc/1/task/1/comm'* && \
    "$same_cgroup_control" == *'[ "$process_name" = java ]'* && \
    "$same_cgroup_control" == *'[ "$thread_name" = java ]'* && \
    "$same_cgroup_control" == *'--forged-tid "$5"'* && \
    "$same_cgroup_control" == *'"$UNIX_SECURITY_NAMESPACE_PID" != "$java_live_tid"'* && \
    "$same_cgroup_control" == *'capture_unix_security_pid_namespace_status'* && \
    "$same_cgroup_control" == *'assert_unix_security_pid_namespace_identity'* && \
    "$same_cgroup_control" == *'cat "/proc/$UNIX_SECURITY_NAMESPACE_PID/cgroup" 2> /dev/null'* && \
    "$same_cgroup_control" == *'cat "/proc/$UNIX_SECURITY_NAMESPACE_PID/status" 2> /dev/null'* && \
    "$pid_namespace_capture" == *'case "$1" in'* && \
    "$pid_namespace_capture" == *'""|*[!0-9]*|0|1)'* && \
    "$pid_namespace_capture" == *'[ "$probe_name" = security-probe ]'* && \
    "$pid_namespace_capture" == *'cat "/proc/$1/comm" 2>/dev/null'* && \
    "$pid_namespace_capture" == *'cat /proc/1/status 2>/dev/null'* && \
    "$pid_namespace_capture" == *'cat "/proc/$1/status" 2>/dev/null'* && \
    "$pid_namespace_capture" == *'2> /dev/null'* && \
    "$same_cgroup_control" == *'pid_namespace_shared=true'* && \
    "$same_cgroup_control" == *'pid_namespace_evidence=status-nspid-depth'* && \
    "$same_cgroup_control" != *'/ns/pid'* && \
    "$same_cgroup_control" == *'assert_unix_security_cgroup_identity'* && \
    "$same_cgroup_control" == *'security-unix-same-cgroup-victim'* && \
    "$same_cgroup_control" == *'assert_unix_abuse_race_output "$output" true'* && \
    "$sibling_topology" == *'HostConfig.Privileged'* && \
    "$sibling_topology" == *'json .HostConfig.CapAdd'* && \
    "$sibling_topology" == *'assert_unix_sibling_security_options'* && \
    "$sibling_topology" == *'assert_unix_sibling_tmpfs'* && \
    "$sibling_topology" == *'"$privileged" == "false"'* && \
    "$sibling_topology" == *'( "$cap_add" == "null" || "$cap_add" == "[]" )'* && \
    "$sibling_topology" == *'json .Mounts'* && \
    "$sibling_topology" == *'json .HostConfig.Tmpfs'* && \
    "$sibling_topology" == *'length == 1'* && \
    "$sibling_topology" == *'.[0].Type == "volume"'* && \
    "$sibling_topology" == *'.[0].Destination == "/var/run/obi"'* && \
    "$sibling_topology" == *'.[0].RW == false'* && \
    "$cleanup_control" == *'UNIX_SECURITY_SIBLING_CONTAINER'* && \
    "$cleanup_control" == *'UNIX_SECURITY_ENDPOINT_CONTAINER'* && \
    "$cleanup_control" == *'UNIX_SECURITY_PROBE_DIRECTORY'* && \
    "$cleanup_control" == *'"/proc/$1/comm"'* ]] || {
    printf 'Unix security controls lost topology, identity, or cleanup fencing\n' >&2
    return 1
  }
}

test_permissive_unix_directory_control_refuses_and_restores() {
  local -r result_dir="$TEST_TMP_DIR/permissive-directory-control"
  local -r observed="$result_dir/observed"
  local -r provider_ready="$result_dir/provider-ready"
  local -r date_calls="$result_dir/date-calls"

  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=unix
    UNIX_SECURITY_DIRECTORY_RELAXED=false
    directory_mode=0750
    run_bounded() {
      shift
      case " $* " in
        *" stop --timeout 10 obi "*)
          [[ "$BRIDGE_RUNNING" == "false" &&
            -z "$SELECTED_TRANSPORT" &&
            ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
            -e "$RESULT_DIR/java-selected-transport-configuration.txt" ]] ||
            return 31
          ;;
        *" chmod 0777 /var/run/obi "*)
          directory_mode=0777
          ;;
        *" chmod 0750 /var/run/obi "*)
          directory_mode=0750
          ;;
        *" ls -ld /var/run/obi "*)
          if [[ "$directory_mode" == "0777" ]]; then
            printf 'drwxrwxrwx 2 root root 40 Jul 22 00:00 /var/run/obi\n'
          else
            printf 'drwxr-x--- 2 root root 40 Jul 22 00:00 /var/run/obi\n'
          fi
          ;;
        *" test -S /var/run/obi/java-remote-parent.sock "*)
          return 1
          ;;
        *" up --detach --no-deps --force-recreate obi "*)
          if [[ "$directory_mode" == "0750" ]]; then
            : >"$provider_ready"
            printf 'provider-ready\n' >>"$observed"
          fi
          ;;
        *" logs --no-color "*)
          if [[ "$directory_mode" == "0777" ]]; then
            printf 'java bridge socket ancestor is writable without the sticky bit\n'
          else
            printf 'Java remote parent bridge ready\n'
          fi
          ;;
      esac
      printf '%s\n' "$*" >>"$observed"
    }
    assert_selected_transport() {
      SELECTED_TRANSPORT=unix
      printf 'transport\n' >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    sleep() {
      printf 'sleep:%s\n' "$1" >>"$observed"
    }
    wait_for_log() {
      if [[ "$3" == "post-permission Java bridge provider" ]]; then
        [[ -f "$provider_ready" && "$4" == "security-recovery-cursor" ]] || return 1
      fi
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    wait_for_java_duplicate_suppression() {
      [[ -f "$provider_ready" ]] || return 1
      printf 'suppression:%s\n' "$(basename -- "$1")" >>"$observed"
      : >"$1"
    }
    date() {
      local -i call_count=0

      printf 'call\n' >>"$date_calls"
      call_count="$(wc -l <"$date_calls")"
      case "$call_count" in
        1)
          printf 'cursor:security-failure\n' >>"$observed"
          printf 'security-failure-cursor\n'
          ;;
        2)
          printf 'cursor:security-recovery\n' >>"$observed"
          printf 'security-recovery-cursor\n'
          ;;
        *) return 1 ;;
      esac
    }
    curl() {
      local output=""
      while (($# > 0)); do
        if [[ "$1" == "--output" ]]; then
          output="$2"
          shift 2
          continue
        fi
        shift
      done
      printf '{"marker":"security-permissive-directory"}\n' >"$output"
      printf '200\n'
    }

    run_unix_permissive_directory_control || return 1
    [[ "$directory_mode" == "0750" ]] || return 1
    [[ "$UNIX_SECURITY_DIRECTORY_RELAXED" == "false" ]] || return 1
    [[ "$BRIDGE_RUNNING" == "true" ]] || return 1
  ) || {
    printf 'permissive Unix directory control did not refuse and restore safely\n' >&2
    return 1
  }
  grep -Fq "$UNIX_PERMISSION_REFUSAL_PATTERN" \
    "$result_dir/security-permissive-directory-obi.log"
  grep -Fq 'logs --no-color --since security-failure-cursor obi' "$observed"
  awk '
    /up --detach --no-deps --force-recreate obi/ { recovery = NR }
    $0 == "cursor:security-recovery" { recovery_cursor = NR }
    $0 == "log:post-permission Unix bridge recovery:security-recovery-cursor" {
      bridge = NR
    }
    $0 == "provider-ready" { provider_ready = NR }
    $0 == "http:post-permission Java provider probe" { probe = NR }
    $0 ~ /^sleep:[0-9]+$/ { settle = NR }
    $0 == "transport" { transport = NR }
    $0 == "log:post-permission Java bridge provider:security-recovery-cursor" {
      provider = NR
    }
    $0 == "apache:unix-permission-recovery" { readiness = NR }
    $0 == "suppression:duplicate-suppression-unix-permission-recovery.prom" {
      suppression = NR
    }
    END {
      exit recovery > 0 && recovery_cursor > 0 &&
        provider_ready > recovery_cursor && provider_ready < recovery &&
        bridge > recovery && readiness > bridge &&
        probe > readiness && settle > probe && suppression > settle &&
        provider > suppression && transport > provider ? 0 : 1
    }
  ' "$observed" || {
    printf 'Unix permission recovery resumed before duplicate suppression readiness\n' >&2
    return 1
  }
  grep -Fqx "sleep:$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" "$observed"
  [[ ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'Unix permission control retained stale current transport evidence\n' >&2
    return 1
  }
}

test_permissive_unix_directory_rejects_socket_probe_error() {
  local -r result_dir="$TEST_TMP_DIR/permissive-directory-probe-error"
  local control_status=0

  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=unix
    UNIX_SECURITY_DIRECTORY_RELAXED=false
    date() { printf 'probe-error-cursor\n'; }
    wait_for_log() { return 0; }
    run_bounded() {
      case " $* " in
        *" ls -ld /var/run/obi "*)
          printf 'drwxrwxrwx 2 root root 40 Jul 22 00:00 /var/run/obi\n'
          ;;
        *" test -S /var/run/obi/java-remote-parent.sock "*)
          return 42
          ;;
      esac
    }

    run_unix_permissive_directory_control
  ) >/dev/null 2>&1; then
    printf 'Unix permission control treated a failed socket probe as absence\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == "42" &&
    ! -e "$result_dir/security-permissive-directory-response.json" ]] || {
    printf 'Unix permission control continued after socket probe failure\n' >&2
    return 1
  }
}

test_unix_endpoint_restart_invalidates_before_stack_mutation() {
  local -r success_dir="$TEST_TMP_DIR/unix-endpoint-invalidation"
  local -r failure_dir="$TEST_TMP_DIR/unix-endpoint-invalidation-failure"
  local -r success_marker="$success_dir/restart"
  local -r failure_marker="$failure_dir/restart"
  local control_status=0

  run_unix_endpoint_probe() (
    local -r result_dir="$1"
    local -r mutation_marker="$2"
    local -r invalidation_failure="$3"
    local -r date_calls="$result_dir/date-calls"

    RESULT_DIR="$result_dir"
    TRANSPORT=unix
    SELECTED_TRANSPORT=unix
    BRIDGE_RUNNING=true
    COMPOSE=(test-compose)
    REPEAT_COUNT=1
    SCENARIO_VARIANT=""
    ALLOW_UNIX_SECURITY_METRICS=false
    UNIX_SECURITY_ENDPOINT_CONTAINER=""
    mkdir -p -- "$RESULT_DIR"
    printf 'current\n' >"$RESULT_DIR/java-transport-configuration.txt"
    printf 'retained\n' >"$RESULT_DIR/java-selected-transport-configuration.txt"
    if [[ "$invalidation_failure" == "true" ]]; then
      rm() { return 29; }
    fi
    date() {
      local call_count=0

      printf 'call\n' >>"$date_calls"
      call_count="$(wc -l <"$date_calls")"
      printf 'cursor-%s\n' "$call_count"
    }
    capture_java_diagnostics() { return 0; }
    assert_sanitized_java_diagnostics() { return 0; }
    assert_security_metric_delta() { return 0; }
    run_unix_peer_security_controls() { return 0; }
    wait_for_log() { return 0; }
    run_scenario() { return 0; }
    run_bounded() {
      case " $* " in
        *" ps --all --quiet security-probe "*)
          printf 'security-probe-container\n'
          ;;
        *" docker wait security-probe-container "*)
          printf '0\n'
          ;;
        *" logs --no-color security-probe "*)
          printf '%s\n' \
            '{"status":"passed","mode":"abuse-race","attempts":1,"name":"concurrent-repeated-unauthorized","outcome":"bounded"}'
          ;;
        *" restart --timeout 10 obi "*)
          [[ "$BRIDGE_RUNNING" == "false" &&
            -z "$SELECTED_TRANSPORT" &&
            ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
            "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == "retained" ]] ||
            return 31
          : >"$mutation_marker"
          return 41
          ;;
      esac
    }

    run_unix_security_control
  )

  if run_unix_endpoint_probe "$success_dir" "$success_marker" false \
    >/dev/null 2>&1; then
    printf 'Unix endpoint control ignored the restart-boundary failure\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == "41" &&
    -e "$success_marker" &&
    ! -e "$success_dir/java-transport-configuration.txt" &&
    "$(<"$success_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'Unix endpoint control restarted before transport invalidation\n' >&2
    return 1
  }

  if run_unix_endpoint_probe "$failure_dir" "$failure_marker" true \
    >/dev/null 2>&1; then
    printf 'Unix endpoint control ignored transport invalidation failure\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == "29" &&
    ! -e "$failure_marker" &&
    "$(<"$failure_dir/java-transport-configuration.txt")" == "current" &&
    "$(<"$failure_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'Unix endpoint control mutated the stack after invalidation failed\n' >&2
    return 1
  }
}

write_diagnostics_fixture() {
  local -r output="$1"
  local -r valid="$2"
  local -r stale="$3"
  local -r malformed="$4"
  local -r sampled="$5"
  local -r unsampled="$6"
  local -r standard="$7"
  local -r fault_status="${8:-}"
  local -r fault_count="${9:-0}"
  local snapshot="cfg_on=0,cfg_off=0,provider_ok=0,provider_reject=0,provider_ver=0,extension_reg=0,lookup_ready=0,lookup_missing=0,lookup_version=0,lookup_error=0,record_version=0,invoke_error=0,discard_standard=$standard,extract_fields=0,extract_invalid=0,extract_error=0,registration_ok=0,registration_fail=0,take_sampled=$sampled,take_unsampled=$unsampled,tls_reads=0,tls_bytes=0,framework_depth=0,framework_cycle=0,framework_late=0,transport_missing=0"
  local status=""
  local value=0

  for status in unknown valid missing stale unsupported malformed version_mismatch ambiguous unauthorized already_consumed timeout overload transport_error disabled; do
    value=0
    case "$status" in
      valid) value="$valid" ;;
      stale) value="$stale" ;;
      malformed) value="$malformed" ;;
      "$fault_status") value="$fault_count" ;;
    esac
    snapshot+=",t_$status=$value,d_$status=0"
  done
  printf '%s\n' "$snapshot" >"$output"
}

test_java_diagnostics_schema_is_exact() {
  local -r snapshot="$TEST_TMP_DIR/java-diagnostics-schema.txt"
  local required_field=""
  local invalid_value=""

  write_diagnostics_fixture "$snapshot" 0 0 0 0 0 0
  assert_sanitized_java_diagnostics "$snapshot"

  for required_field in framework_depth framework_cycle framework_late transport_missing; do
    write_diagnostics_fixture "$snapshot" 0 0 0 0 0 0
    sed -i "s/$required_field=0/${required_field}_renamed=0/" "$snapshot"
    if assert_sanitized_java_diagnostics "$snapshot" >/dev/null 2>&1; then
      printf 'Java diagnostics accepted missing required field=%s\n' \
        "$required_field" >&2
      return 1
    fi
  done

  write_diagnostics_fixture "$snapshot" 0 0 0 0 0 0
  sed -i 's/cfg_on=0/secret=0/' "$snapshot"
  if assert_sanitized_java_diagnostics "$snapshot" >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an unknown fixed-shape field\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$snapshot" 0 0 0 0 0 0
  sed -i 's/$/,request_id=0/' "$snapshot"
  if assert_sanitized_java_diagnostics "$snapshot" >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an appended side-channel field\n' >&2
    return 1
  fi

  for invalid_value in 00 A gjdgxr gjdgxs unavailable; do
    write_diagnostics_fixture "$snapshot" 0 0 0 0 0 0
    sed -i "s/cfg_on=0/cfg_on=$invalid_value/" "$snapshot"
    if assert_sanitized_java_diagnostics "$snapshot" >/dev/null 2>&1; then
      printf 'Java diagnostics accepted noncanonical or saturated value=%s\n' \
        "$invalid_value" >&2
      return 1
    fi
  done

  write_diagnostics_fixture "$snapshot" 0 0 0 0 0 0
  printf 'unexpected=0\n' >>"$snapshot"
  if assert_sanitized_java_diagnostics "$snapshot" >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an additional snapshot line\n' >&2
    return 1
  fi
}

test_java_diagnostics_delta_is_exact() {
  local -r before="$TEST_TMP_DIR/java-before.txt"
  local -r after="$TEST_TMP_DIR/java-after.txt"
  local -r delta="$TEST_TMP_DIR/java.delta"
  local invalid_delta=""

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 2 0 0 1 1 1 missing 1
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 || {
    printf 'Java diagnostics rejected exact expected deltas\n' >&2
    return 1
  }

  sed -i '/^d_disabled /d' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an omitted delta record\n' >&2
    return 1
  fi

  write_java_diagnostics_delta "$before" "$after" "$delta"
  sed -i '/^t_valid /p' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted a duplicate delta record\n' >&2
    return 1
  fi

  write_java_diagnostics_delta "$before" "$after" "$delta"
  sed -i 's/^d_disabled /d_unexpected /' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an unknown delta record\n' >&2
    return 1
  fi

  write_java_diagnostics_delta "$before" "$after" "$delta"
  sed -i 's/t_missing before=0/t_missing before=invalid/' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted a malformed counter value\n' >&2
    return 1
  fi

  write_java_diagnostics_delta "$before" "$after" "$delta"
  sed -i 's/t_missing before=0 after=1 delta=1/t_missing before=0 after=2 delta=1/' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an inconsistent counter delta\n' >&2
    return 1
  fi

  for invalid_delta in expected_missing 1+0 -1 01 1000000000; do
    write_java_diagnostics_delta "$before" "$after" "$delta"
    sed -i \
      "s/t_missing before=0 after=1 delta=1/t_missing before=0 after=1 delta=$invalid_delta/" \
      "$delta"
    if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
      printf 'Java diagnostics accepted non-canonical delta=%s\n' "$invalid_delta" >&2
      return 1
    fi
  done
  write_java_diagnostics_delta "$before" "$after" "$delta"

  sed -i \
    -e 's/t_missing before=0 after=1 delta=1/t_missing before=0 after=0 delta=0/' \
    -e 's/t_already_consumed before=0 after=0 delta=0/t_already_consumed before=0 after=1 delta=1/' \
    "$delta"
  assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 || {
    printf 'Java diagnostics rejected an already-consumed self lookup\n' >&2
    return 1
  }

  sed -i 's/t_missing before=0 after=0 delta=0/t_missing before=0 after=1 delta=1/' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an additional absence lookup\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" 2 0 0 1 1 1 missing 4
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_java_diagnostics_delta "$delta" 2 0 0 4 1 1 1 || {
    printf 'Java diagnostics rejected exact TLS-boundary misses\n' >&2
    return 1
  }
  sed -i \
    -e 's/t_missing before=0 after=4 delta=4/t_missing before=0 after=3 delta=3/' \
    -e 's/t_already_consumed before=0 after=0 delta=0/t_already_consumed before=0 after=1 delta=1/' \
    "$delta"
  assert_java_diagnostics_delta "$delta" 2 0 0 4 1 1 1 || {
    printf 'Java diagnostics rejected a TLS-boundary self lookup on a consumed task\n' >&2
    return 1
  }
  sed -i \
    -e 's/t_missing before=0 after=3 delta=3/t_missing before=0 after=2 delta=2/' \
    -e 's/t_already_consumed before=0 after=1 delta=1/t_already_consumed before=0 after=2 delta=2/' \
    "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 4 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics allowed self lookup tolerance to hide a TLS-boundary miss\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" 2 0 0 1 1 1 missing 1
  write_java_diagnostics_delta "$before" "$after" "$delta"

  sed -i 's/d_missing before=0 after=0 delta=0/d_missing before=0 after=1 delta=1/' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an unexpected duplicate result\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" 2 0 0 1 1 1
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics omitted the expected self-observed lookup\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 0 0 0 0 0 0 already_consumed 1
  sed -i 's/,t_missing=0/,t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_java_diagnostics_delta "$delta" 0 0 0 1 0 0 0 already_consumed 1 || {
    printf 'Java diagnostics rejected an attributable already-consumed fault\n' >&2
    return 1
  }

  write_diagnostics_fixture "$after" 0 0 0 0 0 0 transport_error 1
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_java_diagnostics_delta "$delta" 0 0 0 0 0 0 0 transport_error 1 || {
    printf 'Java diagnostics rejected an attributable fault status\n' >&2
    return 1
  }
}

test_reason_coded_control_diagnostics_are_exact() {
  local -r before="$TEST_TMP_DIR/reason-coded-before.txt"
  local -r after="$TEST_TMP_DIR/reason-coded-after.txt"
  local -r delta="$TEST_TMP_DIR/reason-coded.delta"
  local reconciliation=""

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 2 0 0 2 0 0
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_coalesced_bridge_diagnostics_delta "$delta" supported_exact || return 1

  write_diagnostics_fixture "$after" 0 0 0 0 0 0
  sed -i 's/d_ambiguous=0/d_ambiguous=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_coalesced_bridge_diagnostics_delta "$delta" ambiguous_drop || return 1
  sed -i 's/d_missing before=0 after=0 delta=0/d_missing before=0 after=1 delta=1/' \
    "$delta"
  if assert_coalesced_bridge_diagnostics_delta \
    "$delta" ambiguous_drop >/dev/null 2>&1; then
    printf 'coalesced diagnostics accepted a second discard reason\n' >&2
    return 1
  fi

  reconciliation='{"parent_outcome":"exact","drop_reasons":[]}'
  write_diagnostics_fixture "$after" 2 0 0 2 0 0
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_timeout_cancellation_diagnostics_delta "$delta" "$reconciliation" || return 1

  reconciliation='{"parent_outcome":"missing","drop_reasons":[]}'
  write_diagnostics_fixture "$after" 1 0 0 1 0 0
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_timeout_cancellation_diagnostics_delta "$delta" "$reconciliation" || return 1

  reconciliation='{"parent_outcome":"reason_coded_drop","drop_reasons":["timeout"]}'
  sed -i 's/d_timeout=0/d_timeout=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_timeout_cancellation_diagnostics_delta "$delta" "$reconciliation" || return 1
  sed -i 's/take_sampled before=0 after=1 delta=1/take_sampled before=0 after=0 delta=0/' \
    "$delta"
  if assert_timeout_cancellation_diagnostics_delta \
    "$delta" "$reconciliation" >/dev/null 2>&1; then
    printf 'timeout diagnostics accepted changed trace flags\n' >&2
    return 1
  fi
}

test_pressure_unix_already_consumed_diagnostics_are_exact() {
  local -r before="$TEST_TMP_DIR/pressure-unix-before.txt"
  local -r after="$TEST_TMP_DIR/pressure-unix-after.txt"
  local -r delta="$TEST_TMP_DIR/pressure-unix.delta"
  local bridge_json='{"transport":"unix","retrieval_failure_count":2,"retrieval_failure_reason_counts":{"missing":0,"stale":0,"unsupported":0,"malformed":0,"version_mismatch":0,"ambiguous":0,"unauthorized":0,"already_consumed":2,"timeout":0,"overload":0,"transport_error":0,"disabled":0}}'

  pressure_unix_already_consumed_roots_are_reconciled "$bridge_json" 2 || {
    printf 'pressure reconciliation rejected exact Unix already-consumed roots\n' >&2
    return 1
  }
  if pressure_unix_already_consumed_roots_are_reconciled \
    "${bridge_json/\"already_consumed\":2/\"already_consumed\":1}" 2; then
    printf 'pressure reconciliation accepted a mismatched Unix already-consumed count\n' >&2
    return 1
  fi
  if pressure_unix_already_consumed_roots_are_reconciled \
    "${bridge_json/\"missing\":0/\"missing\":1}" 2; then
    printf 'pressure reconciliation accepted an additional Unix retrieval failure reason\n' >&2
    return 1
  fi
  if pressure_unix_already_consumed_roots_are_reconciled \
    $'null\n'"$bridge_json" 2; then
    printf 'pressure reconciliation accepted multiple reconciliation documents\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 3i 0 0 3i 0 0 already_consumed 2
  sed -i 's/,t_missing=0/,t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"

  if assert_java_diagnostics_delta "$delta" 126 0 0 3 126 0 0 \
    >/dev/null 2>&1; then
    printf 'generic diagnostics validation accepted multiple un-attributed already-consumed results\n' >&2
    return 1
  fi
  assert_pressure_unix_already_consumed_diagnostics_delta \
    "$delta" 126 1 126 0 0 2 || {
    printf 'pressure diagnostics rejected exact Unix already-consumed roots\n' >&2
    return 1
  }

  sed -i \
    's/t_already_consumed before=0 after=2 delta=2/t_already_consumed before=0 after=3 delta=3/' \
    "$delta"
  if assert_pressure_unix_already_consumed_diagnostics_delta \
    "$delta" 126 1 126 0 0 2 >/dev/null 2>&1; then
    printf 'pressure diagnostics accepted an extra already-consumed result\n' >&2
    return 1
  fi

  write_java_diagnostics_delta "$before" "$after" "$delta"
  sed -i \
    's/t_missing before=0 after=1 delta=1/t_missing before=0 after=2 delta=2/' \
    "$delta"
  if assert_pressure_unix_already_consumed_diagnostics_delta \
    "$delta" 126 1 126 0 0 2 >/dev/null 2>&1; then
    printf 'pressure diagnostics accepted an extra missing result\n' >&2
    return 1
  fi
}

test_java_diagnostics_header_is_exact_and_piggybacked() {
  local -r result_dir="$TEST_TMP_DIR/java-diagnostics-boundary"
  local -r calls="$result_dir/curl.calls"
  local -r expected="$result_dir/expected.txt"
  local -r output="$result_dir/baseline.txt"
  local headers=""
  local invalid_output=""
  local snapshot=""

  mkdir -p -- "$result_dir"
  write_diagnostics_fixture "$expected" 1 0 0 1 0 0
  snapshot="$(<"$expected")"
  (
    RESULT_DIR="$result_dir"
    BRIDGE_RUNNING=true
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 5' \
        'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 7' \
        >"$1"
    }
    curl() {
      local header_output=""
      local argument=""

      printf '%s\n' "$*" >>"$calls"
      while (( $# > 0 )); do
        argument="$1"
        shift
        if [[ "$argument" == "--dump-header" ]]; then
          (( $# > 0 )) || return 1
          header_output="$1"
          shift
        fi
      done
      [[ -n "$header_output" ]] || return 1
      printf 'HTTP/1.1 200 OK\r\nX-OBI-Java-Diagnostics: %s\r\n\r\n' \
        "$snapshot" >"$header_output"
    }
    wait_for_bridge_metrics_quiescent() {
      [[ "$1" == "6" && "$2" == "8" ]]
    }

    flush_bridge_metric_boundary fault-baseline 1 1 "$output"
  ) || {
    printf 'diagnostics baseline was not captured on the metric-boundary request\n' >&2
    return 1
  }

  cmp -s -- "$expected" "$output" || {
    printf 'metric-boundary diagnostics header was not persisted exactly\n' >&2
    return 1
  }
  [[ "$(wc -l <"$calls")" == "1" ]] || {
    printf 'diagnostics baseline issued more than one health request\n' >&2
    return 1
  }
  grep -Fq \
    "$APACHE_HTTPS_HEALTH_ENDPOINT&bridge_diagnostics=1" "$calls" || {
    printf 'diagnostics baseline did not opt in on the existing health request\n' >&2
    return 1
  }
  if grep -Fq '/obi-diagnostics' "$calls"; then
    printf 'diagnostics baseline used the direct diagnostics endpoint\n' >&2
    return 1
  fi

  headers="$result_dir/headers.txt"
  printf 'HTTP/1.1 200 OK\r\n\r\n' >"$headers"
  invalid_output="$result_dir/missing.txt"
  if extract_java_diagnostics_header "$headers" "$invalid_output" >/dev/null 2>&1; then
    printf 'diagnostics baseline accepted a missing response header\n' >&2
    return 1
  fi
  printf 'X-OBI-Java-Diagnostics: %s\r\nX-OBI-Java-Diagnostics: %s\r\n' \
    "$snapshot" "$snapshot" >"$headers"
  invalid_output="$result_dir/duplicate.txt"
  if extract_java_diagnostics_header "$headers" "$invalid_output" >/dev/null 2>&1; then
    printf 'diagnostics baseline accepted duplicate response headers\n' >&2
    return 1
  fi
  printf 'X-OBI-Java-Diagnostics: unavailable\r\n' >"$headers"
  invalid_output="$result_dir/unavailable.txt"
  if extract_java_diagnostics_header "$headers" "$invalid_output" >/dev/null 2>&1; then
    printf 'diagnostics baseline accepted unavailable response diagnostics\n' >&2
    return 1
  fi

  printf 'X-OBI-Java-Diagnostics: %s\r\n' "$snapshot" >"$headers"
  invalid_output="$result_dir/existing.txt"
  printf 'sentinel\n' >"$invalid_output"
  if extract_java_diagnostics_header "$headers" "$invalid_output" >/dev/null 2>&1 ||
    [[ "$(<"$invalid_output")" != "sentinel" ]]; then
    printf 'diagnostics baseline overwrote an existing artifact\n' >&2
    return 1
  fi
  invalid_output="$result_dir/symlink.txt"
  ln -s -- "$expected" "$invalid_output"
  if extract_java_diagnostics_header "$headers" "$invalid_output" >/dev/null 2>&1 ||
    [[ ! -L "$invalid_output" ]]; then
    printf 'diagnostics baseline followed or replaced a symlink artifact\n' >&2
    return 1
  fi
}

test_pre_stop_diagnostics_failure_does_not_stop_obi() {
  local -r calls="$TEST_TMP_DIR/pre-stop-diagnostics.calls"
  local -r baseline="$TEST_TMP_DIR/pre-stop-diagnostics.txt"
  local -r result_dir="$TEST_TMP_DIR/pre-stop-diagnostics-result"
  local -r invalidation_stop="$result_dir/invalidation-stop"

  (
    BRIDGE_RUNNING=true
    flush_bridge_metric_boundary() {
      return 1
    }
    capture_phase_evidence() {
      printf 'evidence:%s\n' "$1" >>"$calls"
    }
    run_bounded() {
      printf 'stop:%s\n' "$*" >>"$calls"
    }

    if stop_obi_for_no_state_control w3c-fault "$baseline" >/dev/null 2>&1; then
      return 1
    fi
    [[ "$BRIDGE_RUNNING" == "true" ]]
  ) || {
    printf 'OBI stop proceeded after the diagnostics boundary failed\n' >&2
    return 1
  }
  [[ ! -e "$calls" ]] || {
    printf 'OBI stop side effects ran after the diagnostics boundary failed\n' >&2
    return 1
  }

  (
    BRIDGE_RUNNING=true
    flush_bridge_metric_boundary() {
      return 0
    }
    capture_phase_evidence() {
      printf 'evidence:%s\n' "$1" >>"$calls"
    }
    run_bounded() {
      printf 'stop:%s\n' "$*" >>"$calls"
    }

    if stop_obi_for_no_state_control w3c-fault "$baseline" >/dev/null 2>&1; then
      return 1
    fi
    [[ "$BRIDGE_RUNNING" == "true" ]]
  ) || {
    printf 'OBI stop accepted a missing diagnostics baseline artifact\n' >&2
    return 1
  }
  [[ ! -e "$calls" ]] || {
    printf 'OBI stop side effects ran without a diagnostics baseline artifact\n' >&2
    return 1
  }

  write_diagnostics_fixture "$baseline" 0 0 0 0 0 0
  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  if (
    local stop_status=0

    RESULT_DIR="$result_dir"
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    COMPOSE=(docker compose)
    flush_bridge_metric_boundary() {
      return 0
    }
    capture_phase_evidence() {
      printf 'evidence:%s\n' "$1" >>"$calls"
    }
    run_bounded() {
      printf 'stop:%s\n' "$*" >>"$calls"
      return 23
    }

    if stop_obi_for_no_state_control w3c-fault "$baseline" >/dev/null 2>&1; then
      return 1
    else
      stop_status=$?
    fi
    [[ "$stop_status" == "23" &&
      "$BRIDGE_RUNNING" == "false" &&
      -z "$SELECTED_TRANSPORT" &&
      ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
      -e "$RESULT_DIR/java-selected-transport-configuration.txt" ]]
  ); then
    :
  else
    printf 'OBI stop failure retained stale current-generation bridge state\n' >&2
    return 1
  fi
  grep -Fqx 'evidence:w3c-fault-obi-running' "$calls"
  grep -Fq 'stop:60 docker compose stop --timeout 10 obi' "$calls"

  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  if (
    local stop_status=0

    RESULT_DIR="$result_dir"
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    COMPOSE=(docker compose)
    flush_bridge_metric_boundary() {
      return 0
    }
    capture_phase_evidence() {
      return 0
    }
    rm() {
      return 29
    }
    run_bounded() {
      : >"$invalidation_stop"
    }

    if stop_obi_for_no_state_control w3c-fault "$baseline" >/dev/null 2>&1; then
      return 1
    else
      stop_status=$?
    fi
    [[ "$stop_status" == "29" &&
      "$BRIDGE_RUNNING" == "true" &&
      "$SELECTED_TRANSPORT" == "getsockopt" &&
      "$(<"$RESULT_DIR/java-transport-configuration.txt")" == "current" &&
      "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == "retained" ]]
  ); then
    :
  else
    printf 'OBI stop ignored current transport invalidation failure\n' >&2
    return 1
  fi
  [[ ! -e "$invalidation_stop" ]] || {
    printf 'OBI stop mutated Compose after transport invalidation failed\n' >&2
    return 1
  }
}

test_fault_diagnostics_result_is_single_sanitized_snapshot() {
  local -r expected="$TEST_TMP_DIR/fault-result-expected.txt"
  local -r result="$TEST_TMP_DIR/fault-result.json"
  local output=""
  local snapshot=""
  local malformed=""

  write_diagnostics_fixture "$expected" 0 1 1 0 0 0
  snapshot="$(<"$expected")"
  printf '{\n  "status": "passed",\n  "fault_diagnostics_after": "%s"\n}\n' \
    "$snapshot" >"$result"
  output="$TEST_TMP_DIR/fault-result-valid.txt"
  extract_fault_diagnostics_after "$result" "$output"
  cmp -s -- "$expected" "$output" || {
    printf 'fault result did not preserve its terminal diagnostics snapshot\n' >&2
    return 1
  }

  printf '{\n  "status": "passed"\n}\n' >"$result"
  output="$TEST_TMP_DIR/fault-result-missing.txt"
  if extract_fault_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'fault result accepted missing terminal diagnostics\n' >&2
    return 1
  fi
  printf '{\n  "fault_diagnostics_after": "%s",\n  "fault_diagnostics_after": "%s"\n}\n' \
    "$snapshot" "$snapshot" >"$result"
  output="$TEST_TMP_DIR/fault-result-duplicate.txt"
  if extract_fault_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'fault result accepted duplicate terminal diagnostics\n' >&2
    return 1
  fi
  printf '{\n  "fault_diagnostics_after": "unavailable"\n}\n' >"$result"
  output="$TEST_TMP_DIR/fault-result-unavailable.txt"
  if extract_fault_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'fault result accepted unavailable terminal diagnostics\n' >&2
    return 1
  fi
  malformed="${snapshot/cfg_on=0/cfg_on=00}"
  printf '{\n  "fault_diagnostics_after": "%s"\n}\n' "$malformed" >"$result"
  output="$TEST_TMP_DIR/fault-result-malformed.txt"
  if extract_fault_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'fault result accepted malformed terminal diagnostics\n' >&2
    return 1
  fi
}

test_java_diagnostics_result_is_single_sanitized_snapshot() {
  local -r expected="$TEST_TMP_DIR/java-result-expected.txt"
  local -r result="$TEST_TMP_DIR/java-result.json"
  local output=""
  local snapshot=""
  local malformed=""

  write_diagnostics_fixture "$expected" 0 1 0 0 0 0
  snapshot="$(<"$expected")"
  printf '{\n  "status": "passed",\n  "java_diagnostics_after": "%s"\n}\n' \
    "$snapshot" >"$result"
  output="$TEST_TMP_DIR/java-result-valid.txt"
  extract_java_diagnostics_after "$result" "$output"
  cmp -s -- "$expected" "$output" || {
    printf 'stale result did not preserve its terminal diagnostics snapshot\n' >&2
    return 1
  }

  printf '{\n  "status": "passed"\n}\n' >"$result"
  output="$TEST_TMP_DIR/java-result-missing.txt"
  if extract_java_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'stale result accepted missing terminal diagnostics\n' >&2
    return 1
  fi
  printf '{\n  "java_diagnostics_after": "%s",\n  "java_diagnostics_after": "%s"\n}\n' \
    "$snapshot" "$snapshot" >"$result"
  output="$TEST_TMP_DIR/java-result-duplicate.txt"
  if extract_java_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'stale result accepted duplicate terminal diagnostics\n' >&2
    return 1
  fi
  printf '{\n  "java_diagnostics_after": "unavailable"\n}\n' >"$result"
  output="$TEST_TMP_DIR/java-result-unavailable.txt"
  if extract_java_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'stale result accepted unavailable terminal diagnostics\n' >&2
    return 1
  fi
  malformed="${snapshot/cfg_on=0/cfg_on=00}"
  printf '{\n  "java_diagnostics_after": "%s"\n}\n' "$malformed" >"$result"
  output="$TEST_TMP_DIR/java-result-malformed.txt"
  if extract_java_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'stale result accepted malformed terminal diagnostics\n' >&2
    return 1
  fi
  printf '{\n  "java_diagnostics_after": "%s"\n}\n' "$snapshot" >"$result"
  output="$TEST_TMP_DIR/java-result-symlink.txt"
  ln -s -- "$expected" "$output"
  if extract_java_diagnostics_after "$result" "$output" >/dev/null 2>&1; then
    printf 'stale result overwrote a diagnostics symlink\n' >&2
    return 1
  fi
}

test_w3c_fault_diagnostics_mappings_are_exact() {
  local -r before="$TEST_TMP_DIR/w3c-fault-before.txt"
  local -r after="$TEST_TMP_DIR/w3c-fault-after.txt"
  local -r delta="$TEST_TMP_DIR/w3c-fault.delta"
  local mode=""
  local status=""
  local request_count=""
  local stale=0
  local malformed=0
  local -a cases=(
    "alternating stale-malformed 2"
    "timeout timeout 1"
    "disconnect transport_error 1"
    "overload overload 1"
    "truncated transport_error 1"
    "bad-magic malformed 1"
    "bad-size malformed 1"
    "version-mismatch version_mismatch 1"
    "zero-trace-id malformed 1"
    "zero-span-id malformed 1"
  )
  local test_case=""

  for test_case in "${cases[@]}"; do
    read -r mode status request_count <<<"$test_case"
    stale=0
    malformed=0
    write_diagnostics_fixture "$before" 0 0 0 0 0 0
    case "$status" in
      stale-malformed)
        stale=1
        malformed=1
        write_diagnostics_fixture "$after" 0 "$stale" "$malformed" 0 0 0
        ;;
      malformed)
        write_diagnostics_fixture "$after" 0 0 "$request_count" 0 0 0
        ;;
      *)
        write_diagnostics_fixture "$after" 0 0 0 0 0 0 "$status" "$request_count"
        ;;
    esac
    write_java_diagnostics_delta "$before" "$after" "$delta"
    assert_w3c_fault_diagnostics_delta "$delta" "$mode" "$request_count" || {
      printf 'W3C fault diagnostics rejected exact mapping mode=%s status=%s\n' \
        "$mode" "$status" >&2
      return 1
    }
  done

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 0 0 0 0 0 0 timeout 1
  sed -i 's/lookup_error=0/lookup_error=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_w3c_fault_diagnostics_delta "$delta" timeout 1 >/dev/null 2>&1; then
    printf 'W3C fault diagnostics accepted an unexpected counter delta\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$before" 0 0 0 0 0 0 timeout 1
  write_diagnostics_fixture "$after" 0 0 0 0 0 0
  if write_java_diagnostics_delta "$before" "$after" "$delta" >/dev/null 2>&1; then
    printf 'W3C fault diagnostics accepted a nonmonotonic counter\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 0 0 0 0 0 0
  sed -i 's/cfg_on=0/cfg_on=1/' "$before"
  if write_java_diagnostics_delta "$before" "$after" "$delta" >/dev/null 2>&1; then
    printf 'W3C fault diagnostics accepted a nonmonotonic lifecycle counter\n' >&2
    return 1
  fi
}

test_fault_scenario_chains_in_band_diagnostics_without_direct_probe() {
  local -r diagnostics_calls="$TEST_TMP_DIR/fault-diagnostics.calls"
  local -r scenario_calls="$TEST_TMP_DIR/fault-scenario.calls"
  local -r scenario_count="$TEST_TMP_DIR/fault-scenario.count"
  local -r baseline="$TEST_TMP_DIR/fault-baseline.txt"
  local -r after_one="$TEST_TMP_DIR/fault-after-one.txt"
  local -r after_two="$TEST_TMP_DIR/fault-after-two.txt"
  local snapshot_one=""
  local snapshot_two=""

  write_diagnostics_fixture "$baseline" 0 0 0 0 0 0
  write_diagnostics_fixture "$after_one" 0 1 1 0 0 0
  write_diagnostics_fixture "$after_two" 0 2 2 0 0 0
  snapshot_one="$(<"$after_one")"
  snapshot_two="$(<"$after_two")"

  (
    RESULT_DIR="$TEST_TMP_DIR/fault-scenario"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=false
    COMPOSE=(docker compose)
    FAULT_MODE=alternating
    FAULT_REQUEST_COUNT=2
    W3C_FAULT_DIAGNOSTICS_PREVIOUS="$baseline"
    REPEAT_COUNT=2
    REQUEST_COUNT=0
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=unix
    TLS_PROTOCOL=TLSv1.3
    : >"$scenario_count"
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    capture_java_diagnostics() {
      printf '%s\n' "$1" >>"$diagnostics_calls"
      return 1
    }
    flush_bridge_metric_boundary() {
      return 0
    }
    run_bounded() {
      local count=0

      printf '%s\n' "$*" >>"$scenario_calls"
      count="$(<"$scenario_count")"
      count="$((count + 1))"
      printf '%s\n' "$count" >"$scenario_count"
      if [[ "$count" == "1" ]]; then
        printf '{\n  "status": "passed",\n  "fault_diagnostics_after": "%s"\n}\n' \
          "$snapshot_one"
      else
        printf '{\n  "status": "passed",\n  "fault_diagnostics_after": "%s"\n}\n' \
          "$snapshot_two"
      fi
    }
    sleep() {
      printf 'sleep:%s\n' "$1" >>"$scenario_calls"
    }

    run_scenario w3c-fault >/dev/null
    [[ "$W3C_FAULT_DIAGNOSTICS_PREVIOUS" == \
      "$RESULT_DIR/phases/w3c-fault-alternating-run-02-after/java-diagnostics.txt" ]]
  ) || {
    printf 'fault scenario did not chain response-bound diagnostics\n' >&2
    return 1
  }

  if [[ -e "$diagnostics_calls" ]]; then
    printf 'fault scenario used a direct Java diagnostics probe\n' >&2
    return 1
  fi
  [[ "$(grep -c -- '--fault-mode alternating' "$scenario_calls")" == "2" ]] || {
    printf 'fault scenario did not pass its strict fault mode on every run\n' >&2
    return 1
  }
  if grep -Fq '/obi-diagnostics' "$scenario_calls"; then
    printf 'fault scenario command used the direct diagnostics endpoint\n' >&2
    return 1
  fi
  grep -Fqx \
    't_stale before=0 after=1 delta=1' \
    "$TEST_TMP_DIR/fault-scenario/phases/w3c-fault-alternating-run-01-after/java-diagnostics.delta"
  grep -Fqx \
    't_stale before=1 after=2 delta=1' \
    "$TEST_TMP_DIR/fault-scenario/phases/w3c-fault-alternating-run-02-after/java-diagnostics.delta"
  ((JAVA_PROVIDER_RETRY_SETTLE_SECONDS >= 2)) || {
    printf 'Java provider retry settle interval is below two seconds\n' >&2
    return 1
  }
  grep -Fqx \
    "sleep:$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" "$scenario_calls" || {
    printf 'repeated fault runs did not wait for the provider retry interval\n' >&2
    return 1
  }
}

test_fault_scenario_failure_retains_in_band_diagnostics() {
  local -r result_dir="$TEST_TMP_DIR/fault-scenario-failure"
  local -r baseline="$TEST_TMP_DIR/fault-failure-baseline.txt"
  local -r after="$TEST_TMP_DIR/fault-failure-after.txt"
  local -r diagnostics_calls="$TEST_TMP_DIR/fault-failure-diagnostics.calls"
  local -r scenario_calls="$TEST_TMP_DIR/fault-failure-scenario.calls"
  local snapshot=""

  write_diagnostics_fixture "$baseline" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 0 0 0 0 0 0 timeout 1
  snapshot="$(<"$after")"
  (
    local scenario_status=0

    RESULT_DIR="$result_dir"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=false
    COMPOSE=(docker compose)
    FAULT_MODE=timeout
    FAULT_REQUEST_COUNT=1
    W3C_FAULT_DIAGNOSTICS_PREVIOUS="$baseline"
    REPEAT_COUNT=1
    REQUEST_COUNT=0
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=unix
    TLS_PROTOCOL=TLSv1.3
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    capture_java_diagnostics() {
      printf '%s\n' "$1" >>"$diagnostics_calls"
      return 1
    }
    flush_bridge_metric_boundary() {
      return 0
    }
    run_bounded() {
      printf '%s\n' "$*" >>"$scenario_calls"
      printf '{\n  "status": "failed",\n  "fault_diagnostics_after": "%s"\n}\n' \
        "$snapshot"
      return 17
    }

    if run_scenario w3c-fault >/dev/null; then
      return 1
    else
      scenario_status=$?
    fi
    [[ "$scenario_status" == "17" ]]
    [[ "$W3C_FAULT_DIAGNOSTICS_PREVIOUS" == \
      "$RESULT_DIR/phases/w3c-fault-timeout-after/java-diagnostics.txt" ]]
  ) || {
    printf 'fault scenario failure did not retain its in-band diagnostics\n' >&2
    return 1
  }

  [[ ! -e "$diagnostics_calls" ]] || {
    printf 'failed fault scenario used a direct Java diagnostics probe\n' >&2
    return 1
  }
  grep -Fq -- '--fault-mode timeout' "$scenario_calls"
  grep -Fqx \
    't_timeout before=0 after=1 delta=1' \
    "$result_dir/phases/w3c-fault-timeout-after/java-diagnostics.delta"
  grep -Fq '"exit_status": 17' "$result_dir/scenario-w3c-fault-timeout-status.json"
  grep -Fq '"metric_status": 0' "$result_dir/scenario-w3c-fault-timeout-status.json"
}

test_w3c_fault_control_preserves_scenario_failure_in_conditional() {
  local -r result_dir="$TEST_TMP_DIR/fault-control-scenario-failure"
  local -r calls="$result_dir/calls"
  local control_status=0

  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    TRANSPORT=unix
    SELECTED_TRANSPORT=unix
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    FAULT_BRIDGE_RUNNING=false
    stop_obi_for_no_state_control() {
      printf 'stop-obi:%s:%s\n' "$1" "$2" >>"$calls"
    }
    run_bounded() {
      printf 'bounded:%s\n' "$*" >>"$calls"
    }
    wait_for_log() {
      printf 'wait:%s\n' "$*" >>"$calls"
    }
    run_scenario() {
      printf 'scenario:%s:%s\n' "$1" "$FAULT_MODE" >>"$calls"
      return 17
    }
    sleep() {
      printf 'unexpected-sleep:%s\n' "$1" >>"$calls"
      return 1
    }
    recreate_instrumented_stack() {
      printf 'unexpected-recreate:%s\n' "$*" >>"$calls"
      return 1
    }

    if run_w3c_fault_control; then
      return 1
    else
      control_status=$?
    fi
    printf 'fault-bridge-running:%s\n' "$FAULT_BRIDGE_RUNNING" >>"$calls"
    return "$control_status"
  ); then
    printf 'W3C fault control masked a scenario failure in a conditional\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == "17" ]] || {
    printf 'W3C fault control returned %s instead of scenario status 17\n' \
      "$control_status" >&2
    return 1
  }
  [[ "$(grep -c '^scenario:' "$calls")" == "1" ]] || {
    printf 'W3C fault control continued after its scenario failed\n' >&2
    return 1
  }
  if grep -Eq '^unexpected-(sleep|recreate):' "$calls"; then
    printf 'W3C fault control ran post-failure operations\n' >&2
    return 1
  fi
  grep -Fq \
    'bounded:15 docker compose logs --no-color bridge-fault' "$calls" || {
    printf 'W3C fault control did not capture the failed responder log\n' >&2
    return 1
  }
  grep -Fq \
    'bounded:30 docker compose stop --timeout 5 bridge-fault' "$calls" || {
    printf 'W3C fault control did not stop the failed responder\n' >&2
    return 1
  }
  grep -Fqx 'fault-bridge-running:false' "$calls" || {
    printf 'W3C fault control retained an active responder marker\n' >&2
    return 1
  }
  [[ -f "$result_dir/w3c-fault-alternating-bridge.log" ]] || {
    printf 'W3C fault control omitted the failed responder artifact\n' >&2
    return 1
  }
}

test_final_java_diagnostics_skip_active_fault_bridge() {
  local -r calls="$TEST_TMP_DIR/final-java-diagnostics.calls"

  (
    FAULT_BRIDGE_RUNNING=true
    PRIMARY_FAULT_STACK_ACTIVE=false
    log_warn() {
      :
    }
    capture_java_diagnostics() {
      printf '%s\n' "$1" >>"$calls"
    }

    capture_final_java_diagnostics
    FAULT_BRIDGE_RUNNING=false
    capture_final_java_diagnostics
    PRIMARY_FAULT_STACK_ACTIVE=true
    capture_final_java_diagnostics
    PRIMARY_FAULT_STACK_ACTIVE=false
    capture_final_java_diagnostics
  )
  [[ "$(<"$calls")" == $'final\nfinal' ]] || {
    printf 'final evidence probed Java while a fault control was active\n' >&2
    return 1
  }
}

test_helper_unavailable_scenario_injects_without_staging_or_retrieval() {
  local -r calls="$TEST_TMP_DIR/helper-unavailable-scenario.calls"

  (
    RESULT_DIR="$TEST_TMP_DIR/helper-unavailable-scenario"
    BRIDGE_RUNNING=true
    COMPOSE=(test-compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=99
    SCENARIO_SEED=7
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=unix
    TLS_PROTOCOL=TLSv1.3
    mkdir -p -- "$RESULT_DIR"
    : >"$calls"
    flush_bridge_metric_boundary() {
      printf 'boundary:%s:%s:%s\n' "$1" "${2:-1}" "${3:-1}" >>"$calls"
    }
    capture_java_diagnostics() {
      printf 'unexpected-diagnostics:%s\n' "$1" >>"$calls"
      return 1
    }
    capture_phase_evidence() {
      printf 'evidence:%s\n' "$1" >>"$calls"
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="unix"} 4' \
        'obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 7' \
        >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    run_bounded() {
      printf 'scenario:%s\n' "$*" >>"$calls"
      printf '{"status":"passed"}\n'
    }
    wait_for_bridge_metrics_quiescent() {
      printf 'wait:%s:%s\n' "$1" "$2" >>"$calls"
    }
    write_metrics_delta() {
      : >"$3"
    }
    assert_bridge_metric_delta() {
      printf 'assert:%s:%s:%s:%s:%s:%s:%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" "$8" >>"$calls"
    }

    run_scenario helper-attach-failure false full none helper-unavailable >/dev/null
  ) || {
    printf 'helper-unavailable scenario orchestration failed\n' >&2
    return 1
  }

  grep -Fqx 'boundary:helper-attach-failure:0:0' "$calls"
  grep -Fq 'scenario:' "$calls"
  grep -Fq -- '--scenario helper-attach-failure' "$calls"
  grep -Fq -- '--requests 1' "$calls"
  grep -Fqx 'wait:4:7' "$calls"
  grep -Fqx 'assert:unix:0:0:0:1:0:true' "$calls"
  if grep -Fq 'unexpected-diagnostics' "$calls"; then
    printf 'helper-unavailable scenario attempted Java helper diagnostics\n' >&2
    return 1
  fi
}

test_scenario_fences_metrics_around_diagnostics() {
  run_accounting_case() (
    local -r name="$1"
    local -r requests="$2"
    local -r wanted_valid="$3"
    local -r wanted_missing="$4"
    local -r wanted_sampled="$5"
    local -r wanted_unsampled="$6"
    local -r wanted_standard="$7"
    local -r wanted_request_argument="$8"
    local -r call_log="$TEST_TMP_DIR/scenario-$name.calls"
    local boundary_ran=false
    local expected_requests=0
    local expected_calls_file="$RESULT_DIR/expected.calls"

    RESULT_DIR="$TEST_TMP_DIR/scenario-$name"
    mkdir -p -- "$RESULT_DIR"
    : >"$call_log"
    BRIDGE_RUNNING=true
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT="$requests"
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    capture_java_diagnostics() {
      printf 'diagnostics:%s\n' "$1" >>"$call_log"
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'fixture\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    flush_bridge_metric_boundary() {
      boundary_ran=true
      printf 'boundary:%s\n' "$1" >>"$call_log"
    }
    capture_phase_evidence() {
      printf 'evidence:%s\n' "$1" >>"$call_log"
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    capture_receive_cursor_map_baseline() {
      printf 'cursor-map-before:%s\n' "$1" >>"$call_log"
      RECEIVE_CURSOR_MAP_ID=41
      RECEIVE_GUARD_MAP_ID=42
      RECEIVE_CURSOR_MAP_BASELINE_ENTRIES=0
      RECEIVE_GUARD_MAP_BASELINE_ENTRIES=0
      RECEIVE_CURSOR_MAP_STATUS_JSON="null"
    }
    wait_for_receive_cursor_map_recovery() {
      printf 'cursor-map-after:%s\n' "$1" >>"$call_log"
      RECEIVE_CURSOR_MAP_STATUS_JSON='{"status":"passed"}'
    }
    run_bounded() {
      local request_argument=default
      while (( $# > 0 )); do
        if [[ "$1" == "--requests" ]]; then
          if (( $# < 2 )); then
            return 1
          fi
          request_argument="$2"
          shift 2
          continue
        fi
        shift
      done
      printf 'scenario:%s\n' "$request_argument" >>"$call_log"
      printf '{"status":"passed"}\n'
    }
    wait_for_bridge_metrics_quiescent() {
      printf 'wait:%s:%s\n' "$1" "$2" >>"$call_log"
    }
    assert_bridge_metric_delta() {
      return 0
    }
    write_java_diagnostics_delta() {
      : >"$3"
    }
    assert_java_diagnostics_delta() {
      [[ "$boundary_ran" == "true" &&
        "$2" == "$wanted_valid" && "$3" == "0" && "$4" == "0" &&
        "$5" == "$wanted_missing" && "$6" == "$wanted_sampled" &&
        "$7" == "$wanted_unsampled" && "$8" == "$wanted_standard" &&
        "${9:-}" == "" && "${10:-0}" == "0" ]]
    }

    run_scenario "$name" >/dev/null || return $?

    expected_requests="$(scenario_bridge_take_count "$name")"
    {
      printf 'boundary:%s\n' "$name"
      printf 'diagnostics:%s-before\n' "$name"
      printf 'wait:0:0\n'
      printf 'evidence:%s-before\n' "$name"
      if [[ "$name" == "tls-boundary" ]]; then
        printf 'cursor-map-before:%s\n' "$name"
      fi
      printf 'scenario:%s\n' "$wanted_request_argument"
      if [[ "$name" == "tls-boundary" ]]; then
        printf 'cursor-map-after:%s\n' "$name"
      fi
      printf 'wait:%d:%d\n' "$expected_requests" "$expected_requests"
      printf 'evidence:%s-after\n' "$name"
      printf 'diagnostics:%s-after\n' "$name"
    } >"$expected_calls_file"
    cmp -s -- "$expected_calls_file" "$call_log"
  )

  run_accounting_case basic 1 1 1 1 0 0 1 || {
    printf 'basic scenario did not fence metrics around diagnostics\n' >&2
    return 1
  }
  run_accounting_case keepalive 0 10 1 10 0 0 default || {
    printf 'keepalive scenario did not account for all acceptance requests\n' >&2
    return 1
  }
  run_accounting_case keepalive 7 7 1 7 0 0 7 || {
    printf 'targeted keepalive request count was not forwarded and accounted\n' >&2
    return 1
  }
  run_accounting_case tls-boundary 0 3 1 3 0 0 3 || {
    printf 'TLS-boundary scenario did not fence metrics around diagnostics\n' >&2
    return 1
  }
  run_accounting_case obi-flags 4 4 1 2 2 0 4 || {
    printf 'OBI-flags scenario did not preserve sampled and unsampled takes\n' >&2
    return 1
  }
}

test_pressure_scenario_reconciles_roots_with_bridge_and_java_counts() {
  local -r call_log="$TEST_TMP_DIR/scenario-pressure-accounting.calls"
  local -r result_dir="$TEST_TMP_DIR/scenario-pressure-accounting"

  (
    RESULT_DIR="$result_dir"
    mkdir -p -- "$RESULT_DIR"
    : >"$call_log"
    BRIDGE_RUNNING=true
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=10
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    PRESSURE_ACTIVE=false
    flush_bridge_metric_boundary() { :; }
    capture_java_diagnostics() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'fixture\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    start_map_pressure() {
      [[ "$1" == "pressure" && "$3" == "10" ]] || return 1
      PRESSURE_ACTIVE=true
    }
    cleanup_map_pressure_with_retries() {
      PRESSURE_ACTIVE=false
    }
    run_bounded() {
      cat <<'EOF'
{
  "status": "passed",
  "pressure_correlation": {
    "exact_hit_count": 7,
    "explicit_root_count": 3,
    "wrong_parent_count": 0,
    "unresolved_count": 0
  }
}
EOF
    }
    wait_for_bridge_metrics_quiescent() {
      printf 'wait:%s:%s\n' "$1" "$2" >>"$call_log"
    }
    write_metrics_delta() {
      : >"$3"
    }
    pressure_bridge_reconciliation() {
      printf 'bridge:%s:%s:%s:%s\n' "$2" "$3" "$4" "$5" >>"$call_log"
      [[ "$2" == "getsockopt" && "$3" == "7" && "$4" == "3" && "$5" == "10" ]] || \
        return 1
      printf '%s\n' \
        '{"transport":"getsockopt","retrieval_valid_count":7,"upstream_failure_count":3,"retrieval_failure_count":0,"upstream_failure_reason_counts":{"ambiguous":3}}'
    }
    write_java_diagnostics_delta() {
      : >"$3"
    }
    assert_java_diagnostics_delta() {
      printf 'java:%s:%s:%s:%s:%s:%s:%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" "$8" >>"$call_log"
      [[ "$2" == "7" && "$3" == "0" && "$4" == "0" && "$5" == "4" &&
        "$6" == "7" && "$7" == "0" && "$8" == "0" ]]
    }

    run_scenario pressure >/dev/null
    [[ "$PRESSURE_ACTIVE" == "false" ]]
    [[ "$(<"$call_log")" == $'wait:0:0\nwait:7:7\nbridge:getsockopt:7:3:10\njava:7:0:0:4:7:0:0' ]]
  ) || {
    printf 'pressure scenario did not reconcile explicit roots across evidence layers\n' >&2
    return 1
  }
  grep -Fq '"retrieval_valid_count":7' \
    "$result_dir/scenario-pressure-status.json" || return 1
  grep -Fq '"attributable_absence_count":3' \
    "$result_dir/scenario-pressure-status.json" || return 1
}

test_pressure_unix_scenario_uses_strict_already_consumed_reconciliation() {
  local -r call_log="$TEST_TMP_DIR/scenario-pressure-unix-accounting.calls"
  local -r result_dir="$TEST_TMP_DIR/scenario-pressure-unix-accounting"

  (
    RESULT_DIR="$result_dir"
    mkdir -p -- "$RESULT_DIR"
    : >"$call_log"
    BRIDGE_RUNNING=true
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=128
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=unix
    TLS_PROTOCOL=TLSv1.2
    PRESSURE_ACTIVE=false
    scenario_bridge_missing_count() { printf '0\n'; }
    scenario_java_missing_count() { printf '1\n'; }
    scenario_bridge_take_count() { printf '128\n'; }
    flush_bridge_metric_boundary() { :; }
    capture_java_diagnostics() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'fixture\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    start_map_pressure() {
      [[ "$1" == "pressure" && "$3" == "128" ]] || return 1
      PRESSURE_ACTIVE=true
    }
    cleanup_map_pressure_with_retries() {
      PRESSURE_ACTIVE=false
    }
    run_bounded() {
      cat <<'EOF'
{
  "status": "passed",
  "pressure_correlation": {
    "exact_hit_count": 126,
    "explicit_root_count": 2,
    "wrong_parent_count": 0,
    "unresolved_count": 0
  }
}
EOF
    }
    wait_for_bridge_metrics_quiescent() { :; }
    write_metrics_delta() { : >"$3"; }
    pressure_bridge_reconciliation() {
      printf '%s\n' '{"transport":"unix","retrieval_valid_count":126,"retrieval_failure_count":2,"retrieval_failure_reason_counts":{"missing":0,"stale":0,"unsupported":0,"malformed":0,"version_mismatch":0,"ambiguous":0,"unauthorized":0,"already_consumed":2,"timeout":0,"overload":0,"transport_error":0,"disabled":0}}'
    }
    write_java_diagnostics_delta() { : >"$3"; }
    assert_pressure_unix_already_consumed_diagnostics_delta() {
      printf 'strict:%s:%s:%s:%s:%s:%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" >>"$call_log"
      [[ "$2" == "126" && "$3" == "1" && "$4" == "126" && \
        "$5" == "0" && "$6" == "0" && "$7" == "2" ]]
    }
    assert_java_diagnostics_delta() {
      printf 'generic\n' >>"$call_log"
      return 1
    }

    run_scenario pressure >/dev/null
    [[ "$PRESSURE_ACTIVE" == "false" ]]
  ) || {
    printf 'Unix pressure scenario did not use strict already-consumed reconciliation\n' >&2
    return 1
  }
  grep -Fqx 'strict:126:1:126:0:0:2' "$call_log"
  if grep -Fqx 'generic' "$call_log"; then
    printf 'Unix pressure scenario used generic diagnostics instead of strict reconciliation\n' >&2
    return 1
  fi
}

test_pressure_failure_retains_wrong_parent_counts_and_cleans_up() {
  local -r result_dir="$TEST_TMP_DIR/scenario-pressure-wrong-parent"
  local scenario_status=0

  if (
    RESULT_DIR="$result_dir"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=true
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=10
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    PRESSURE_ACTIVE=false
    flush_bridge_metric_boundary() { :; }
    capture_java_diagnostics() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'fixture\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    start_map_pressure() {
      PRESSURE_ACTIVE=true
    }
    cleanup_map_pressure_with_retries() {
      PRESSURE_ACTIVE=false
    }
    run_bounded() {
      cat <<'EOF'
{
  "status": "failed",
  "pressure_correlation": {
    "exact_hit_count": 7,
    "explicit_root_count": 2,
    "wrong_parent_count": 1,
    "unresolved_count": 0
  }
}
EOF
      return 17
    }
    wait_for_bridge_metrics_quiescent() { :; }
    write_metrics_delta() { : >"$3"; }
    pressure_bridge_reconciliation() {
      printf '%s\n' \
        '{"transport":"getsockopt","retrieval_valid_count":8,"upstream_failure_count":2,"retrieval_failure_count":0}'
    }
    write_java_diagnostics_delta() { : >"$3"; }
    assert_java_diagnostics_delta() { :; }

    if run_scenario pressure >/dev/null; then
      return 1
    else
      scenario_status=$?
    fi
    [[ "$scenario_status" == "17" && "$PRESSURE_ACTIVE" == "false" ]]
  ); then
    :
  else
    printf 'pressure wrong-parent failure did not retain status or clean up\n' >&2
    return 1
  fi
  grep -Fq '"exit_status": 17' "$result_dir/scenario-pressure-status.json" || {
    printf 'pressure wrong-parent command status was not retained\n' >&2
    return 1
  }
  grep -Fq '"wrong_parent_count":1' "$result_dir/scenario-pressure-status.json" || {
    printf 'pressure wrong-parent count was not retained\n' >&2
    return 1
  }
}

test_pressure_empty_result_fails_closed_and_cleans_up() {
  local -r result_dir="$TEST_TMP_DIR/scenario-pressure-empty"
  local scenario_status=0

  (
    RESULT_DIR="$result_dir"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=false
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=2
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    PRESSURE_ACTIVE=false
    flush_bridge_metric_boundary() { :; }
    capture_java_diagnostics() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'fixture\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    start_map_pressure() {
      PRESSURE_ACTIVE=true
    }
    cleanup_map_pressure_with_retries() {
      PRESSURE_ACTIVE=false
    }
    run_bounded() { :; }
    write_metrics_delta() { : >"$3"; }

    if run_scenario pressure >/dev/null 2>&1; then
      return 1
    else
      scenario_status=$?
    fi
    [[ "$scenario_status" == "1" && "$PRESSURE_ACTIVE" == "false" ]]
  ) || {
    printf 'pressure scenario accepted empty result evidence or skipped cleanup\n' >&2
    return 1
  }
  grep -Fq '"status": "failed"' "$result_dir/scenario-pressure-status.json"
  grep -Fq '"pressure_correlation": null' "$result_dir/scenario-pressure-status.json"
}

test_scenario_controls_matching_fixture_lifecycle() {
  run_fixture_case() (
    local -r command_status="$1"
    local -r call_log="$2"
    local -r fixture_start_status="${3:-0}"
    local expected_status="$command_status"
    local observed_status=0
    local request_argument=default

    RESULT_DIR="$TEST_TMP_DIR/matching-fixture-$command_status"
    mkdir -p -- "$RESULT_DIR"
    : >"$call_log"
    BRIDGE_RUNNING=false
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=3
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=unix
    TLS_PROTOCOL=TLSv1.3
    start_matching_bridge() {
      [[ "$BRIDGE_RUNNING" == "false" && "$1" == "w3c-match" && "$2" == "3" ]] || return 1
      printf 'start:%s:%s\n' "$1" "$2" >>"$call_log"
      return "$fixture_start_status"
    }
    stop_matching_bridge() {
      printf 'stop:%s:%s\n' "$1" "$2" >>"$call_log"
    }
    flush_bridge_metric_boundary() {
      printf 'boundary:%s\n' "$1" >>"$call_log"
    }
    capture_java_diagnostics() {
      printf 'diagnostics:%s\n' "$1" >>"$call_log"
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'fixture\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    capture_phase_evidence() {
      printf 'evidence:%s\n' "$1" >>"$call_log"
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    run_bounded() {
      request_argument=default
      while (($# > 0)); do
        if [[ "$1" == "--requests" ]]; then
          request_argument="$2"
          shift 2
          continue
        fi
        shift
      done
      printf 'scenario:%s\n' "$request_argument" >>"$call_log"
      if ((command_status != 0)); then
        return "$command_status"
      fi
      printf '{"status":"passed"}\n'
    }
    wait_for_bridge_metrics_quiescent() {
      printf 'unexpected bridge wait\n' >>"$call_log"
      return 1
    }
    assert_bridge_metric_delta() {
      printf 'unexpected bridge assertion\n' >>"$call_log"
      return 1
    }
    write_java_diagnostics_delta() {
      : >"$3"
    }
    assert_java_diagnostics_delta() {
      printf 'java:%s:%s:%s:%s:%s:%s:%s:%s:%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$7" "$8" "${9:-none}" "${10:-0}" \
        >>"$call_log"
      [[ "$2" == "3" && "$3" == "0" && "$4" == "0" && "$5" == "1" && \
        "$6" == "3" && "$7" == "0" && "$8" == "3" && \
        "${9:-}" == "" && "${10:-0}" == "0" ]]
    }

    if run_scenario w3c-match true full matching >/dev/null; then
      observed_status=0
    else
      observed_status=$?
    fi
    if ((fixture_start_status != 0)); then
      expected_status="$fixture_start_status"
    fi
    [[ "$observed_status" == "$expected_status" ]]
  )

  local -r success_log="$TEST_TMP_DIR/matching-fixture-success.calls"
  local -r failure_log="$TEST_TMP_DIR/matching-fixture-failure.calls"
  local -r start_failure_log="$TEST_TMP_DIR/matching-fixture-start-failure.calls"

  run_fixture_case 0 "$success_log" || {
    printf 'controlled matching fixture success path failed\n' >&2
    return 1
  }
  [[ "$(<"$success_log")" == $'start:w3c-match:3\nboundary:w3c-match\ndiagnostics:w3c-match-before\nevidence:w3c-match-before\nscenario:3\nevidence:w3c-match-after\ndiagnostics:w3c-match-after\njava:3:0:0:1:3:0:3:none:0\nstop:w3c-match:3' ]] || {
    printf 'controlled matching fixture was not fenced around diagnostics\n' >&2
    return 1
  }

  run_fixture_case 17 "$failure_log" || {
    printf 'controlled matching fixture failure path changed status\n' >&2
    return 1
  }
  [[ "$(tail -n 1 "$failure_log")" == "stop:w3c-match:3" ]] || {
    printf 'controlled matching fixture leaked after scenario failure\n' >&2
    return 1
  }

  run_fixture_case 0 "$start_failure_log" 42 || {
    printf 'controlled matching fixture flattened its startup status\n' >&2
    return 1
  }
  if grep -Eq '^(scenario|stop):' "$start_failure_log"; then
    printf 'controlled matching fixture ran traffic or normal stop after startup failure\n' >&2
    return 1
  fi
}

test_scenario_supports_metrics_only_security_evidence() {
  local -r call_log="$TEST_TMP_DIR/scenario-metrics-only.calls"

  (
    RESULT_DIR="$TEST_TMP_DIR/scenario-metrics-only"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=true
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=0
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    flush_bridge_metric_boundary() {
      return 0
    }
    capture_phase_evidence() {
      return 99
    }
    capture_metric_phase_evidence() {
      printf 'metrics:%s\n' "$1" >>"$call_log"
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    run_bounded() {
      printf 'scenario\n' >>"$call_log"
      printf '{"status":"passed"}\n'
    }
    wait_for_bridge_metrics_quiescent() {
      printf 'wait:%s:%s\n' "$1" "$2" >>"$call_log"
    }
    assert_bridge_metric_delta() {
      printf 'assert\n' >>"$call_log"
    }

    run_scenario basic false metrics >/dev/null
    [[ "$(<"$call_log")" == \
      $'metrics:basic-before\nscenario\nwait:1:1\nmetrics:basic-after\nassert' ]]
  ) || {
    printf 'metrics-only security scenario skipped attribution or used slow evidence\n' >&2
    return 1
  }

  (
    RESULT_DIR="$TEST_TMP_DIR/scenario-metrics-only-failure"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=true
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=0
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    flush_bridge_metric_boundary() {
      return 0
    }
    capture_metric_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      : >"$RESULT_DIR/phases/$1/obi-metrics.prom"
      return 1
    }
    run_bounded() {
      printf '{"status":"passed"}\n'
    }
    wait_for_bridge_metrics_quiescent() {
      return 0
    }
    assert_bridge_metric_delta() {
      return 0
    }

    if run_scenario basic false metrics >/dev/null; then
      return 1
    fi
    grep -Fq '"metric_status": 1' "$RESULT_DIR/scenario-basic-status.json"
  ) || {
    printf 'metrics-only evidence failure did not fail the scenario\n' >&2
    return 1
  }
}

test_security_controls_select_metrics_only_evidence() {
  local primary_control=""
  local unix_sibling_control=""
  local unix_same_cgroup_control=""

  primary_control="$(declare -f run_primary_security_control)"
  unix_sibling_control="$(declare -f run_unix_sibling_security_control)"
  unix_same_cgroup_control="$(declare -f run_unix_same_cgroup_security_control)"
  [[ "$primary_control" == *'run_scenario concurrency false metrics'* &&
    "$unix_sibling_control" == *'run_scenario concurrency false metrics'* &&
    "$unix_same_cgroup_control" == *'run_scenario concurrency false metrics'* ]] || {
    printf 'a concurrent security control selected full phase evidence\n' >&2
    return 1
  }
}

test_scenario_records_metric_boundary_failure() {
  (
    local scenario_status=0

    RESULT_DIR="$TEST_TMP_DIR/scenario-boundary-failure"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=true
    COMPOSE=(docker compose)
    REPEAT_COUNT=1
    REQUEST_COUNT=0
    SCENARIO_SEED=1
    SCENARIO_VARIANT=""
    SELECTED_TRANSPORT=getsockopt
    TLS_PROTOCOL=TLSv1.3
    flush_bridge_metric_boundary() {
      return 1
    }
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    run_bounded() {
      printf '{"status":"passed"}\n'
    }
    wait_for_bridge_metrics_quiescent() {
      return 0
    }
    assert_bridge_metric_delta() {
      return 0
    }

    if run_scenario basic false >/dev/null; then
      printf 'scenario ignored a failed metric boundary\n' >&2
      return 1
    else
      scenario_status=$?
    fi
    [[ "$scenario_status" -eq 1 ]] || {
      printf 'metric-boundary failure returned %d, expected 1\n' "$scenario_status" >&2
      return 1
    }
    grep -Fq '"metric_status": 1' "$RESULT_DIR/scenario-basic-status.json" || {
      printf 'scenario did not retain its metric-boundary failure\n' >&2
      return 1
    }
  )
}

test_bridge_metric_boundary_fails_closed_on_fetch_failure() {
  local -r result_dir="$TEST_TMP_DIR/bridge-boundary-fetch-failure"
  local -r unexpected="$result_dir/unexpected"
  local boundary_status=0

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    BRIDGE_RUNNING=true
    fetch_obi_metrics() {
      return 23
    }
    bridge_success_total() {
      : >"$unexpected"
      printf '0\n'
    }
    bridge_stage_total() {
      : >"$unexpected"
      printf '0\n'
    }

    if flush_bridge_metric_boundary test; then
      return 1
    else
      boundary_status=$?
    fi
    [[ "$boundary_status" -eq 1 ]]
  ) || {
    printf 'bridge metric boundary did not fail closed on fetch failure\n' >&2
    return 1
  }
  [[ ! -e "$unexpected" ]] || {
    printf 'bridge metric boundary parsed a failed metric fetch\n' >&2
    return 1
  }
  if compgen -G "$result_dir/.bridge-boundary.*" >/dev/null; then
    printf 'bridge metric boundary retained a failed fetch temporary file\n' >&2
    return 1
  fi
}

test_scenario_records_required_evidence_failures() {
  local failure_point=""

  for failure_point in before after delta; do
    if ! (
      local scenario_status=0

      RESULT_DIR="$TEST_TMP_DIR/scenario-evidence-failure-$failure_point"
      mkdir -p -- "$RESULT_DIR"
      BRIDGE_RUNNING=true
      COMPOSE=(docker compose)
      REPEAT_COUNT=1
      REQUEST_COUNT=0
      SCENARIO_SEED=1
      SCENARIO_VARIANT=""
      SELECTED_TRANSPORT=getsockopt
      TLS_PROTOCOL=TLSv1.3
      flush_bridge_metric_boundary() {
        return 0
      }
      capture_phase_evidence() {
        mkdir -p -- "$RESULT_DIR/phases/$1"
        printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
        case "$failure_point:$1" in
          before:basic-before|after:basic-after)
            return 23
            ;;
        esac
      }
      run_bounded() {
        printf '{"status":"passed"}\n'
      }
      wait_for_bridge_metrics_quiescent() {
        return 0
      }
      write_metrics_delta() {
        if [[ "$failure_point" == "delta" ]]; then
          return 23
        fi
        : >"$3"
      }
      assert_bridge_metric_delta() {
        return 0
      }

      if run_scenario basic false >/dev/null; then
        return 1
      else
        scenario_status=$?
      fi
      [[ "$scenario_status" -eq 1 ]] || return 1
      grep -Fq \
        '"metric_status": 1' "$RESULT_DIR/scenario-basic-status.json"
    ); then
      printf 'scenario masked the required %s evidence failure\n' \
        "$failure_point" >&2
      return 1
    fi
  done
}

test_java_diagnostics_parser_uses_base36() {
  local -r snapshot="$TEST_TMP_DIR/java-base36.txt"

  printf 'take_sampled=z\n' >"$snapshot"
  [[ "$(diagnostic_counter "$snapshot" take_sampled)" == "35" ]] || {
    printf 'Java diagnostics parser did not decode the bounded base36 counter\n' >&2
    return 1
  }
}

test_restart_fault_diagnostics_require_overlap() {
  local -r before="$TEST_TMP_DIR/restart-java-before.txt"
  local -r after="$TEST_TMP_DIR/restart-java-after.txt"
  local -r delta="$TEST_TMP_DIR/restart-java.delta"
  local -r result="$TEST_TMP_DIR/restart-java-result.txt"

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" k 0 0 k 0 k timeout c
  sed -i 's/,t_missing=0/,t_missing=3/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_restart_fault_diagnostics "$delta" 32 3 "$result"
  grep -Fqx 'non_workload_takes=3' "$result"
  grep -Fqx 'observed_take_total=35' "$result"
  grep -Fqx 'workload_valid_min=17' "$result"
  grep -Fqx 'workload_valid_max=20' "$result"
  grep -Fqx 'workload_fail_open_min=12' "$result"
  grep -Fqx 'workload_fail_open_max=15' "$result"

  write_diagnostics_fixture "$after" k 0 0 j 0 k timeout c
  sed -i 's/,t_missing=0/,t_missing=3/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted sampled totals below valid takes\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" k 0 0 k 0 g timeout c
  sed -i 's/,t_missing=0/,t_missing=3/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted standard discards below valid workload bounds\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" k 0 0 k 0 l timeout c
  sed -i 's/,t_missing=0/,t_missing=3/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted standard discards above valid workload bounds\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" k 0 0 k 0 i timeout c
  sed -i 's/t_already_consumed=0/t_already_consumed=3/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_restart_fault_diagnostics "$delta" 32 3 "$result" || {
    printf 'restart diagnostics rejected an already-consumed self lookup\n' >&2
    return 1
  }
  grep -Fqx 'observed_take_total=35' "$result"
  grep -Fqx 'workload_valid_min=17' "$result"
  grep -Fqx 'workload_valid_max=20' "$result"
  grep -Fqx 'workload_fail_open_min=12' "$result"
  grep -Fqx 'workload_fail_open_max=15' "$result"

  sed -i 's/,t_missing=0/,t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted an additional take result\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" k 0 0 k 0 k timeout f
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted a run without a diagnostics-eligible result\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" 6 0 0 6 0 6 timeout l
  sed -i 's/,t_missing=0/,t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  sed -i '/^t_valid /p' "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted duplicate rows that forged the take total\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" 1 0 0 1 0 0 missing x
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted an attribution-ambiguous single valid result\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" w 0 0 w 0 w
  sed -i 's/,t_missing=0/,t_missing=3/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 3 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted a run without an observed bridge fault\n' >&2
    return 1
  fi
}

test_apache_tls_runtime_evidence_is_required() {
  local -r fake_bin="$TEST_TMP_DIR/apache-tls-runtime-bin"
  local -r fake_compose="$fake_bin/fake-compose"
  local -r fake_httpd="$fake_bin/httpd"
  local -r fake_scanelf="$fake_bin/scanelf"
  local -r fake_apk="$fake_bin/apk"
  local -r successful_result="$TEST_TMP_DIR/apache-tls-runtime-success"
  local -a failure_modes=(
    httpd-version-fail
    httpd-version-invalid
    httpd-version-empty
    httpd-modules-fail
    no-ssl-module
    near-ssl-module
    scanelf-fail
    wrong-scanelf-path
    malformed-needed
    missing-libssl
    missing-libcrypto
    apk-fail-libssl
    apk-invalid-libssl
    apk-empty-libssl
    apk-fail-libcrypto
    apk-invalid-libcrypto
    apk-multiline-libcrypto
  )
  local mode=""
  local expected_error=""
  local failure_result=""
  local evidence=""

  mkdir -p -- "$fake_bin" "$successful_result"
  cat >"$fake_compose" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$#" -eq 7 && "$1" == "exec" && "$2" == "--no-TTY" && "$3" == "apache-proxy" &&
  "$4" == "/bin/sh" && "$5" == "-eu" && "$6" == "-c" && -n "$7" ]] || exit 64
shift 3
exec "$@"
EOF
  cat >"$fake_httpd" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$#" -eq 1 ]] || exit 64
case "$1:$FAKE_TLS_MODE" in
  -v:httpd-version-fail) printf 'injected httpd version failure\n' >&2; exit 16 ;;
  -v:httpd-version-invalid) printf 'unexpected version output\n' ;;
  -v:httpd-version-empty) printf 'Server version: Apache/\n' ;;
  -v:*) printf 'Server version: Apache/2.4.68 (Unix)\nServer built: test fixture\n' ;;
  -M:httpd-modules-fail) printf 'injected httpd module failure\n' >&2; exit 17 ;;
  -M:no-ssl-module) printf 'Loaded Modules:\n core_module (static)\n' ;;
  -M:near-ssl-module) printf 'Loaded Modules:\n not_ssl_module (shared)\n' ;;
  -M:*) printf 'Loaded Modules:\n ssl_module (shared)\n' ;;
  *) exit 64 ;;
esac
EOF
  cat >"$fake_scanelf" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$#" -eq 5 && "$1" == "-n" && "$2" == "-B" && "$3" == "-F" &&
  "$4" == "%n %F" && "$5" == "/usr/local/apache2/modules/mod_ssl.so" ]] || exit 64
case "$FAKE_TLS_MODE" in
  scanelf-fail) printf 'injected scanelf failure\n' >&2; exit 18 ;;
  wrong-scanelf-path) printf 'libssl.so.3,libcrypto.so.3 /tmp/not-mod-ssl.so\n' ;;
  malformed-needed) printf 'libssl.so.3,libcrypto.so.3 forged /usr/local/apache2/modules/mod_ssl.so\n' ;;
  missing-libssl) printf 'libcrypto.so.3,libc.musl-x86_64.so.1 /usr/local/apache2/modules/mod_ssl.so\n' ;;
  missing-libcrypto) printf 'libssl.so.3,libc.musl-x86_64.so.1 /usr/local/apache2/modules/mod_ssl.so\n' ;;
  *) printf 'libssl.so.3,libcrypto.so.3,libc.musl-x86_64.so.1 /usr/local/apache2/modules/mod_ssl.so\n' ;;
esac
EOF
  cat >"$fake_apk" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$#" -eq 3 && "$1" == "info" && "$2" == "--who-owns" ]] || exit 64
case "$3:$FAKE_TLS_MODE" in
  /usr/lib/libssl.so.3:apk-fail-libssl) printf 'injected libssl owner failure\n' >&2; exit 19 ;;
  /usr/lib/libssl.so.3:apk-invalid-libssl) printf '/usr/lib/libssl.so.3 is owned by unexpected-1.0-r0\n' ;;
  /usr/lib/libssl.so.3:apk-empty-libssl) printf '/usr/lib/libssl.so.3 is owned by libssl3-\n' ;;
  /usr/lib/libssl.so.3:*) printf '/usr/lib/libssl.so.3 is owned by libssl3-3.5.7-r0\n' ;;
  /usr/lib/libcrypto.so.3:apk-fail-libcrypto) printf 'injected libcrypto owner failure\n' >&2; exit 20 ;;
  /usr/lib/libcrypto.so.3:apk-invalid-libcrypto) printf '/usr/lib/libcrypto.so.3 is owned by unexpected-1.0-r0\n' ;;
  /usr/lib/libcrypto.so.3:apk-multiline-libcrypto) printf '/usr/lib/libcrypto.so.3 is owned by libcrypto3-3.5.7-r0\nforged\n' ;;
  /usr/lib/libcrypto.so.3:*) printf '/usr/lib/libcrypto.so.3 is owned by libcrypto3-3.5.7-r0\n' ;;
  *) exit 64 ;;
esac
EOF
  chmod 0755 "$fake_compose" "$fake_httpd" "$fake_scanelf" "$fake_apk"

  (
    export PATH="$fake_bin:$PATH"
    export FAKE_TLS_MODE=success
    RESULT_DIR="$successful_result"
    RUN_STAGE=runtime-evidence
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    COMPOSE=("$fake_compose")
    capture_apache_tls_runtime_evidence >/dev/null
  ) || {
    printf 'valid Apache TLS runtime evidence was rejected\n' >&2
    return 1
  }

  evidence="$successful_result/apache-openssl-version.txt"
  grep -Fqx 'apache_version=Apache/2.4.68 (Unix)' "$evidence"
  [[ "$(grep -Fxc 'apache_ssl_module=ssl_module (shared)' "$evidence")" -eq 1 ]]
  grep -Fqx 'apache_mod_ssl_path=/usr/local/apache2/modules/mod_ssl.so' "$evidence"
  grep -Fqx 'apache_mod_ssl_needed=libssl.so.3,libcrypto.so.3,libc.musl-x86_64.so.1' "$evidence"
  grep -Fqx 'openssl_libssl_path=/usr/lib/libssl.so.3' "$evidence"
  grep -Fqx 'openssl_libssl_owner=libssl3-3.5.7-r0' "$evidence"
  grep -Fqx 'openssl_libcrypto_path=/usr/lib/libcrypto.so.3' "$evidence"
  grep -Fqx 'openssl_libcrypto_owner=libcrypto3-3.5.7-r0' "$evidence"
  grep -Fqx 'exit_status=0' "$evidence"
  grep -Fqx 'capture_exit_status=0' "$evidence"

  for mode in "${failure_modes[@]}"; do
    failure_result="$TEST_TMP_DIR/apache-tls-runtime-$mode"
    mkdir -p -- "$failure_result"
    case "$mode" in
      httpd-version-fail) expected_error=httpd-version-command ;;
      httpd-version-invalid) expected_error=httpd-version-invalid ;;
      httpd-version-empty) expected_error=httpd-version-invalid ;;
      httpd-modules-fail) expected_error=httpd-modules-command ;;
      no-ssl-module) expected_error=ssl-module-not-loaded ;;
      near-ssl-module) expected_error=ssl-module-not-loaded ;;
      scanelf-fail) expected_error=mod-ssl-scan-command ;;
      wrong-scanelf-path) expected_error=mod-ssl-path-mismatch ;;
      malformed-needed) expected_error=mod-ssl-needed-invalid ;;
      missing-libssl) expected_error=mod-ssl-libssl-missing ;;
      missing-libcrypto) expected_error=mod-ssl-libcrypto-missing ;;
      apk-fail-libssl) expected_error=libssl-owner-command ;;
      apk-invalid-libssl) expected_error=libssl-owner-invalid ;;
      apk-empty-libssl) expected_error=libssl-owner-invalid ;;
      apk-fail-libcrypto) expected_error=libcrypto-owner-command ;;
      apk-invalid-libcrypto) expected_error=libcrypto-owner-invalid ;;
      apk-multiline-libcrypto) expected_error=libcrypto-owner-invalid ;;
    esac

    if (
      export PATH="$fake_bin:$PATH"
      export FAKE_TLS_MODE="$mode"
      RESULT_DIR="$failure_result"
      RUN_STAGE=runtime-evidence
      FAILURE_STAGE=""
      FAILURE_LINE=""
      FAILURE_STATUS=""
      FAILURE_COMMAND=""
      COMPOSE=("$fake_compose")
      capture_apache_tls_runtime_evidence >/dev/null 2>&1
    ); then
      printf 'invalid Apache TLS runtime evidence passed: %s\n' "$mode" >&2
      return 1
    fi

    evidence="$failure_result/apache-openssl-version.txt"
    grep -Fqx "apache_tls_runtime_error=$expected_error" "$evidence" || return 1
    grep -Eq '^exit_status=[1-9][0-9]*$' "$evidence" || return 1
    grep -Fqx 'capture_exit_status=0' "$evidence" || return 1
    if grep -Eq '^apache_ssl_module=' "$evidence"; then
      printf 'failed Apache TLS evidence emitted canonical success records: %s\n' "$mode" >&2
      return 1
    fi
  done

  (
    local status=0

    RESULT_DIR="$TEST_TMP_DIR/apache-tls-runtime-propagation"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=(fake-compose)
    capture_host_topology() { return 0; }
    capture_bpf_evidence() { return 0; }
    capture_optional_command() { return 0; }
    run_bounded() { return 0; }
    capture_apache_tls_runtime_evidence() { return 37; }

    if capture_runtime_evidence; then
      printf 'Apache TLS runtime evidence failure was suppressed\n' >&2
      return 1
    else
      status=$?
    fi
    [[ "$status" -eq 37 ]]
  ) || return 1
}

test_bounded_commands_close_stdin() {
  local -r probe="$TEST_TMP_DIR/stdin-probe"
  local -r stderr_output="$TEST_TMP_DIR/stdin-probe.stderr"
  local output=""
  local status=0

  cat >"$probe" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if IFS= read -r unexpected; then
  printf 'unexpected stdin: %s\n' "$unexpected" >&2
  exit 64
fi
printf 'stdout-evidence\n'
printf 'stderr-evidence\n' >&2
exit "${STDIN_PROBE_STATUS:-0}"
EOF
  chmod 0755 "$probe"

  if output="$(
    printf 'must-not-reach-bounded-command\n' |
      run_bounded 5 env STDIN_PROBE_STATUS=23 "$probe" 2>"$stderr_output"
  )"; then
    printf 'bounded command exit status was suppressed\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" -eq 23 ]] || {
    printf 'bounded command returned %d, expected 23\n' "$status" >&2
    return 1
  }
  [[ "$output" == "stdout-evidence" ]] || {
    printf 'bounded command stdout was not preserved\n' >&2
    return 1
  }
  grep -Fqx 'stderr-evidence' "$stderr_output" || {
    printf 'bounded command stderr was not preserved\n' >&2
    return 1
  }
}

test_optional_evidence_closes_stdin() {
  local -r probe="$TEST_TMP_DIR/optional-stdin-probe"
  local -r evidence="$TEST_TMP_DIR/optional-stdin-evidence.txt"

  cat >"$probe" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if IFS= read -r unexpected; then
  printf 'unexpected stdin: %s\n' "$unexpected" >&2
  exit 64
fi
printf 'stdout-evidence\n'
printf 'stderr-evidence\n' >&2
exit 23
EOF
  chmod 0755 "$probe"

  printf 'must-not-reach-optional-command\n' |
    capture_optional_command "$evidence" 5 "$probe"
  grep -Fqx 'stdout-evidence' "$evidence"
  grep -Fqx 'stderr-evidence' "$evidence"
  grep -Fqx 'exit_status=23' "$evidence"
}

test_compose_commands_close_stdin() {
  local -r runner="$TEST_SCRIPT_DIR/../run.sh"
  local logical_commands=""
  local command=""
  local prefix=""
  local -a compose_commands=()

  logical_commands="$(awk '
    {
      sub(/[[:space:]]+$/, "")
      if (continuing) {
        logical = logical " " $0
      } else {
        logical = $0
      }
      if (logical ~ /\\$/) {
        sub(/\\$/, "", logical)
        continuing = 1
        next
      }
      print logical
      continuing = 0
    }
    END {
      if (continuing) {
        print logical
      }
    }
  ' "$runner")"
  mapfile -t compose_commands < <(
    grep -E '"\$\{COMPOSE\[@\]\}" (exec|run)' <<<"$logical_commands" || true
  )
  ((${#compose_commands[@]} > 0)) || {
    printf 'no Compose exec/run commands were audited\n' >&2
    return 1
  }

  for command in "${compose_commands[@]}"; do
    prefix="${command%%\"\$\{COMPOSE\[@\]\}\"*}"
    if [[ "$prefix" =~ (^|[[:space:]])(run_bounded|run_logged_bounded|capture_optional_command)[[:space:]] ]]; then
      continue
    fi
    if [[ "$prefix" =~ (^|[[:space:]])timeout[[:space:]] && "$command" == *"</dev/null"* ]]; then
      continue
    fi
    printf 'Compose command can retain stdin: %s\n' "$command" >&2
    return 1
  done
}

test_pipeline_dependencies_are_declared() {
  local definition=""

  definition="$(declare -f check_dependencies)"
  [[ "$definition" == *" jq "* && "$definition" == *" mv "* && \
    "$definition" == *" tee "* && "$definition" == *" tar "* && \
    "$definition" == *" head "* && "$definition" == *" readlink "* && \
    "$definition" == *" rmdir "* && "$definition" == *" stat "* ]] || {
    printf 'runner dependency check omitted a required evidence or snapshot command\n' >&2
    return 1
  }
}

test_runtime_environment_line_matching() {
  local -r environment=$'OTEL_OBI_REMOTE_PARENT_ENABLED=true\nJAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar'

  environment_has_line \
    "$environment" \
    "JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar" || {
    printf 'runtime contract missed the final environment entry\n' >&2
    return 1
  }
  if environment_has_line "$environment" "JAVA_TOOL_OPTIONS="; then
    printf 'runtime contract accepted a partial environment entry\n' >&2
    return 1
  fi
}

test_primary_fault_runtime_contract_is_exact_and_base_is_clean() {
  local -r result_dir="$TEST_TMP_DIR/primary-fault-runtime"
  local runtime_environment=""
  local -i primary_exec_calls=0

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      case "$*" in
        *"test-compose ps --quiet java-backend")
          printf 'java-container\n'
          ;;
        *"docker inspect --format "*" java-container")
          printf '%s\n' "$runtime_environment"
          ;;
        *"docker exec java-container /bin/sh -ec "*)
          ((primary_exec_calls += 1))
          ;;
        *"test-compose ps --quiet obi")
          printf 'obi-container\n'
          ;;
        *"docker inspect --format "*" obi-container")
          printf 'true host\n'
          ;;
        *)
          return 1
          ;;
      esac
    }
    wait_for_java_duplicate_suppression() {
      return 1
    }
    log_error() {
      :
    }

    runtime_environment="$(printf '%s\n' \
      'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar' \
      'OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar' \
      'OTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      "LD_PRELOAD=$PRIMARY_FAULT_PRELOAD" \
      "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE=$PRIMARY_FAULT_CONTROL_FILE")"
    assert_runtime_contract primary-w3c-fault true || {
      printf 'primary fault runtime rejected its exact fixed environment\n' >&2
      return 1
    }
    [[ "$primary_exec_calls" == 1 ]] || {
      printf 'primary fault runtime did not inspect its private control tmpfs\n' >&2
      return 1
    }

    runtime_environment="$(printf '%s\n' \
      'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar' \
      'OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar' \
      'OTEL_OBI_REMOTE_PARENT_ENABLED=true')"
    assert_runtime_contract basic true || {
      printf 'normal recovered runtime rejected its clean environment\n' >&2
      return 1
    }

    for runtime_environment in \
      "$(printf '%s\n' \
        'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar' \
        'OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar' \
        'OTEL_OBI_REMOTE_PARENT_ENABLED=true' \
        "LD_PRELOAD=$PRIMARY_FAULT_PRELOAD")" \
      "$(printf '%s\n' \
        'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar' \
        'OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar' \
        'OTEL_OBI_REMOTE_PARENT_ENABLED=true' \
        "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE=$PRIMARY_FAULT_CONTROL_FILE")" \
      "$(printf '%s\n' \
        'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar' \
        'OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar' \
        'OTEL_OBI_REMOTE_PARENT_ENABLED=true' \
        "LD_PRELOAD=$PRIMARY_FAULT_PRELOAD" \
        'LD_PRELOAD=/tmp/other.so' \
        "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE=$PRIMARY_FAULT_CONTROL_FILE")"; do
      if assert_runtime_contract primary-w3c-fault true >/dev/null 2>&1; then
        printf 'primary fault runtime accepted an invalid preload/control environment\n' >&2
        return 1
      fi
    done

    runtime_environment="$(printf '%s\n' \
      'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar' \
      'OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar' \
      'OTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      "LD_PRELOAD=$PRIMARY_FAULT_PRELOAD")"
    if assert_runtime_contract basic true >/dev/null 2>&1; then
      printf 'normal recovered runtime accepted a retained preload\n' >&2
      return 1
    fi
  )
}

test_primary_live_fd_runtime_topology_is_exact() {
  local mock_privileged=false
  local mock_pid_mode=""
  local mock_cap_add='["SYS_PTRACE"]'
  local mock_security_options=null

  (
    run_bounded() {
      case "$*" in
        *'HostConfig.Privileged'*) printf '%s\n' "$mock_privileged" ;;
        *'HostConfig.PidMode'*) printf '%s\n' "$mock_pid_mode" ;;
        *'HostConfig.CapAdd'*) printf '%s\n' "$mock_cap_add" ;;
        *'HostConfig.SecurityOpt'*) printf '%s\n' "$mock_security_options" ;;
        *) return 1 ;;
      esac
    }
    log_error() { :; }

    assert_primary_live_fd_security_runtime_topology java-container || {
      printf 'primary live-descriptor runtime rejected its exact least-privilege topology\n' >&2
      return 1
    }

    mock_cap_add='["CAP_SYS_PTRACE"]'
    assert_primary_live_fd_security_runtime_topology java-container || {
      printf 'primary live-descriptor runtime rejected Docker capability normalization\n' >&2
      return 1
    }

    for mock_cap_add in '["SYS_PTRACE","NET_ADMIN"]' '[]' null; do
      if assert_primary_live_fd_security_runtime_topology java-container >/dev/null 2>&1; then
        printf 'primary live-descriptor runtime accepted capability topology %s\n' "$mock_cap_add" >&2
        return 1
      fi
    done
    mock_cap_add='["SYS_PTRACE"]'

    mock_security_options='["seccomp=unconfined"]'
    if assert_primary_live_fd_security_runtime_topology java-container >/dev/null 2>&1; then
      printf 'primary live-descriptor runtime accepted a custom seccomp override\n' >&2
      return 1
    fi
    mock_security_options=null

    mock_privileged=true
    if assert_primary_live_fd_security_runtime_topology java-container >/dev/null 2>&1; then
      printf 'primary live-descriptor runtime accepted privileged mode\n' >&2
      return 1
    fi
    mock_privileged=false
    mock_pid_mode=host
    if assert_primary_live_fd_security_runtime_topology java-container >/dev/null 2>&1; then
      printf 'primary live-descriptor runtime accepted a shared PID namespace\n' >&2
      return 1
    fi
  )
}

test_extension_disabled_runtime_requires_explicit_false() {
  local -r result_dir="$TEST_TMP_DIR/extension-disabled-runtime"
  local runtime_environment=""

  mkdir -p -- "$result_dir"
  (
    local obi_status=0

    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      case "$*" in
        *"test-compose ps --quiet java-backend")
          printf 'java-container\n'
          ;;
        *"docker inspect --format "*" java-container")
          printf '%s\n' "$runtime_environment"
          ;;
        *"test-compose ps --quiet obi")
          return "$obi_status"
          ;;
        *)
          return 1
          ;;
      esac
    }
    log_error() {
      return 0
    }

    runtime_environment=$'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar'
    if assert_runtime_contract extension-disabled; then
      printf 'extension-disabled contract accepted a missing false setting\n' >&2
      return 1
    fi

    runtime_environment+=$'\nOTEL_OBI_REMOTE_PARENT_ENABLED=disabled'
    if assert_runtime_contract extension-disabled; then
      printf 'extension-disabled contract accepted a malformed false setting\n' >&2
      return 1
    fi

    runtime_environment=$'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=false'
    assert_runtime_contract extension-disabled || {
      printf 'extension-disabled contract rejected the exact false setting\n' >&2
      return 1
    }

    obi_status=42
    if assert_runtime_contract extension-disabled; then
      printf 'extension-disabled contract treated failed OBI enumeration as absence\n' >&2
      return 1
    fi
  )
}

test_disabled_runtime_requires_explicit_transport_disable() {
  local -r result_dir="$TEST_TMP_DIR/disabled-runtime"
  # Keep mock values distinct from assert_runtime_contract's dynamically scoped
  # local variables. Bash function mocks resolve names dynamically.
  local mock_java_environment=""
  local mock_obi_environment=""
  local btf_readable=true

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      case "$*" in
        *"test-compose ps --quiet java-backend")
          printf 'java-container\n'
          ;;
        *"docker inspect --format "*" java-container")
          printf '%s\n' "$mock_java_environment"
          ;;
        *"test-compose ps --quiet obi")
          printf 'obi-container\n'
          ;;
        *"range .Config.Env"*" obi-container")
          printf '%s\n' "$mock_obi_environment"
          ;;
        *"docker inspect --format "*" obi-container")
          printf 'true host\n'
          ;;
        *)
          return 1
          ;;
      esac
    }
    wait_for_java_duplicate_suppression() { :; }
    log_error() { :; }
    host_vmlinux_btf_readable() { [[ "$btf_readable" == "true" ]]; }

    mock_java_environment=$'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true'
    mock_obi_environment='OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=disabled'
    assert_runtime_contract disabled || {
      printf 'disabled runtime rejected the exact disabled transport\n' >&2
      return 1
    }
    grep -Fqx 'bridge_transport=disabled' \
      "$result_dir/runtime-assertions-disabled.txt"
    grep -Fqx 'vmlinux_btf=readable' \
      "$result_dir/runtime-assertions-disabled.txt"

    btf_readable=false
    if assert_runtime_contract disabled >/dev/null 2>&1; then
      printf 'disabled runtime accepted unreadable vmlinux BTF\n' >&2
      return 1
    fi
    btf_readable=true

    for mock_obi_environment in \
      'OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=getsockopt' \
      'OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=unix' \
      $'OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=disabled\nOTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=getsockopt' \
      $'OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=disabled\nOTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT=disabled' \
      ''; do
      if assert_runtime_contract disabled >/dev/null 2>&1; then
        printf 'disabled runtime accepted a non-disabled OBI transport\n' >&2
        return 1
      fi
    done
  )
}

test_helper_attach_runtime_requires_exact_dynamic_disable() {
  local -r result_dir="$TEST_TMP_DIR/helper-attach-runtime"
  local runtime_environment=""

  mkdir -p -- "$result_dir"
  (
    local -i duplicate_suppression_calls=0

    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      case "$*" in
        *"test-compose ps --quiet java-backend")
          printf 'java-container\n'
          ;;
        *"docker inspect --format "*" java-container")
          printf '%s\n' "$runtime_environment"
          ;;
        *"test-compose ps --quiet obi")
          printf 'obi-container\n'
          ;;
        *"docker inspect --format "*" obi-container")
          printf 'true host\n'
          ;;
        *)
          return 1
          ;;
      esac
    }
    wait_for_java_duplicate_suppression() {
      ((duplicate_suppression_calls += 1))
      : >"$1"
    }
    log_error() {
      return 0
    }

    runtime_environment=$'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar -XX:-EnableDynamicAgentLoading\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true'
    assert_runtime_contract helper-attach-fault || {
      printf 'helper attach contract rejected the exact dynamic-loading-disabled runtime\n' >&2
      return 1
    }
    [[ "$duplicate_suppression_calls" == "0" ]] || {
      printf 'helper attach fault contract required an injected-helper metric\n' >&2
      return 1
    }
    grep -Fqx 'java_agent=official' \
      "$result_dir/runtime-assertions-helper-attach-fault.txt"
    grep -Fqx 'dynamic_agent_loading=disabled' \
      "$result_dir/runtime-assertions-helper-attach-fault.txt"
    grep -Fqx 'extension=enabled' \
      "$result_dir/runtime-assertions-helper-attach-fault.txt"

    runtime_environment=$'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true'
    SCENARIO=helper-attach-failure
    assert_runtime_contract || {
      printf 'helper attach scenario rejected its initial healthy runtime\n' >&2
      return 1
    }
    [[ "$duplicate_suppression_calls" == "1" ]] || {
      printf 'healthy helper attach contract skipped duplicate suppression\n' >&2
      return 1
    }

    for runtime_environment in \
      $'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      $'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar -XX:+EnableDynamicAgentLoading\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      $'JAVA_TOOL_OPTIONS=-XX:-EnableDynamicAgentLoading -javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      $'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar -XX:-EnableDynamicAgentLoading -Xmx256m\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      $'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar -XX:-EnableDynamicAgentLoading\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=false'; do
      if assert_runtime_contract helper-attach-fault >/dev/null 2>&1; then
        printf 'helper attach contract accepted a non-exact runtime: %s\n' \
          "$runtime_environment" >&2
        return 1
      fi
    done
  )
}

test_delayed_otlp_runtime_requires_bounded_export_contract() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-runtime"
  local runtime_environment=""

  mkdir -p -- "$result_dir"
  (
    local -i duplicate_suppression_calls=0

    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      case "$*" in
        *"test-compose ps --quiet java-backend")
          printf 'java-container\n'
          ;;
        *"docker inspect --format "*" java-container")
          printf '%s\n' "$runtime_environment"
          ;;
        *"test-compose ps --quiet obi")
          printf 'obi-container\n'
          ;;
        *"docker inspect --format "*" obi-container")
          printf 'true host\n'
          ;;
        *)
          return 1
          ;;
      esac
    }
    wait_for_java_duplicate_suppression() {
      ((duplicate_suppression_calls += 1))
      return 1
    }
    log_error() { :; }

    runtime_environment="$(printf '%s\n' \
      'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar' \
      'OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar' \
      'OTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      "OTEL_BSP_SCHEDULE_DELAY=$DELAYED_OTLP_SCHEDULE_DELAY_MILLISECONDS" \
      'OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED=true')"
    assert_runtime_contract delayed-otlp-suppression true || {
      printf 'delayed OTLP runtime rejected the exact export delay\n' >&2
      return 1
    }
    [[ "$duplicate_suppression_calls" == "0" ]] || {
      printf 'delayed OTLP runtime added a second suppression prime\n' >&2
      return 1
    }
    grep -Fqx 'status=passed' \
      "$result_dir/runtime-assertions-delayed-otlp-suppression.txt"
    grep -Fqx 'java_otlp_retry=disabled' \
      "$result_dir/runtime-assertions-delayed-otlp-suppression.txt"

    for runtime_environment in \
      $'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true' \
      $'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true\nOTEL_BSP_SCHEDULE_DELAY=100\nOTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED=true' \
      $'JAVA_TOOL_OPTIONS=-javaagent:/otel/official-javaagent.jar\nOTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar\nOTEL_OBI_REMOTE_PARENT_ENABLED=true\nOTEL_BSP_SCHEDULE_DELAY=60000\nOTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED=false'; do
      if assert_runtime_contract delayed-otlp-suppression true >/dev/null 2>&1; then
        printf 'delayed OTLP runtime accepted an unbounded Java export contract\n' >&2
        return 1
      fi
    done
  )
}

test_start_stack_invalidates_project_evidence_before_compose_up() {
  local -r results_root="$TEST_TMP_DIR/start-stack-invalidation"
  local -r result_dir="$results_root/current"
  local -r prior_result="$results_root/prior"
  local -r foreign_result="$results_root/foreign"
  local -r observed="$results_root/observed"
  local -r failure_root="$TEST_TMP_DIR/start-stack-invalidation-failure"
  local -r failure_result="$failure_root/current"
  local -r failure_observed="$failure_root/observed"
  local start_status=0

  mkdir -p -- "$result_dir" "$prior_result" "$foreign_result"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$result_dir/environment.txt"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$prior_result/environment.txt"
  printf 'compose_project=another-project\n' \
    >"$foreign_result/environment.txt"
  for result in "$result_dir" "$prior_result" "$foreign_result"; do
    printf 'current\n' >"$result/java-transport-configuration.txt"
    printf 'retained\n' >"$result/java-selected-transport-configuration.txt"
  done

  if (
    RESULTS_ROOT="$results_root"
    RESULT_DIR="$result_dir"
    PROJECT_NAME="obi-apache-java-https-test"
    SCENARIO=basic
    TRANSPORT=getsockopt
    SELECTED_TRANSPORT=unix
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMMAND_TIMEOUT_SECONDS=5
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() { return 0; }
    run_bounded() { return 0; }
    date() {
      printf 'cursor\n' >>"$observed"
      printf 'startup-cursor\n'
    }
    run_logged_bounded() {
      [[ -z "$SELECTED_TRANSPORT" &&
        ! -e "$result_dir/java-transport-configuration.txt" &&
        ! -e "$prior_result/java-transport-configuration.txt" &&
        "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" &&
        "$(<"$prior_result/java-selected-transport-configuration.txt")" == "retained" &&
        "$(<"$foreign_result/java-transport-configuration.txt")" == "current" &&
        "$(<"$foreign_result/java-selected-transport-configuration.txt")" == "retained" ]] ||
        return 31
      printf 'compose-up\n' >>"$observed"
      return 41
    }

    start_stack
  ) >/dev/null 2>&1; then
    printf 'startup ignored the injected Compose-up boundary failure\n' >&2
    return 1
  else
    start_status=$?
  fi
  [[ "$start_status" == "41" &&
    "$(<"$observed")" == $'cursor\ncompose-up' ]] || {
    printf 'startup did not invalidate project evidence before Compose up\n' >&2
    return 1
  }

  mkdir -p -- "$failure_result"
  printf 'compose_project=obi-apache-java-https-test\n' \
    >"$failure_result/environment.txt"
  printf 'current\n' >"$failure_result/java-transport-configuration.txt"
  printf 'retained\n' >"$failure_result/java-selected-transport-configuration.txt"
  if (
    RESULTS_ROOT="$failure_root"
    RESULT_DIR="$failure_result"
    PROJECT_NAME="obi-apache-java-https-test"
    SCENARIO=basic
    TRANSPORT=getsockopt
    SELECTED_TRANSPORT=unix
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMMAND_TIMEOUT_SECONDS=5
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() { return 0; }
    run_bounded() { return 0; }
    rm() { return 29; }
    date() {
      printf 'cursor\n' >>"$failure_observed"
      printf 'startup-cursor\n'
    }
    run_logged_bounded() {
      printf 'compose-up\n' >>"$failure_observed"
    }

    start_stack
  ) >/dev/null 2>&1; then
    printf 'startup ignored project evidence invalidation failure\n' >&2
    return 1
  else
    start_status=$?
  fi
  [[ "$start_status" == "29" &&
    ! -e "$failure_observed" &&
    "$(<"$failure_result/java-transport-configuration.txt")" == "current" &&
    "$(<"$failure_result/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'startup mutated the stack after evidence invalidation failed\n' >&2
    return 1
  }
}

test_primary_w3c_fault_startup_uses_normal_runtime_contract() {
  local -r result_dir="$TEST_TMP_DIR/primary-fault-startup"
  local -r observed="$result_dir/observed"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    SCENARIO=primary-w3c-fault
    TRANSPORT=getsockopt
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() { return 0; }
    invalidate_project_transport_evidence() { return 0; }
    run_bounded() { return 0; }
    run_logged_bounded() { return 0; }
    date() { printf 'startup-cursor\n'; }
    wait_for_http() { return 0; }
    wait_for_log() { return 0; }
    assert_selected_transport() { return 0; }
    wait_for_apache_instrumentation() { return 0; }
    assert_apache_denies_java_diagnostics() { return 0; }
    assert_runtime_contract() {
      [[ "$#" == 1 && "$1" == basic ]] || return 1
      printf '%s\n' "$1" >"$observed"
    }

    start_stack
  ) || {
    printf 'primary fault startup did not validate the normal runtime\n' >&2
    return 1
  }
  [[ "$(<"$observed")" == basic ]] || {
    printf 'primary fault startup selected the overlay runtime contract\n' >&2
    return 1
  }
}

test_instrumented_readiness_precedes_https_traffic() {
  local -r result_dir="$TEST_TMP_DIR/readiness-order"
  local -r observed="$result_dir/observed"
  local -r expected="$result_dir/expected"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    SCENARIO=basic
    TRANSPORT=getsockopt
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() {
      return 0
    }
    run_bounded() {
      return 0
    }
    run_logged_bounded() {
      printf 'compose:up\n' >>"$observed"
      return 0
    }
    date() {
      printf 'cursor:startup\n' >>"$observed"
      printf 'startup-cursor\n'
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    wait_for_log() {
      [[ "${4:-}" == "startup-cursor" ]] || return 1
      printf 'log:%s\n' "$3" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    assert_runtime_contract() {
      printf 'runtime\n' >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    assert_apache_denies_java_diagnostics() {
      printf 'diagnostic-denials\n' >>"$observed"
    }

    start_stack
  ) || {
    printf 'instrumented readiness-order probe failed\n' >&2
    return 1
  }

  printf '%s\n' \
    'cursor:startup' \
    'compose:up' \
    'http:trace receiver' \
    'log:OBI remote-parent bridge' \
    'log:external OTel extension' \
    'log:Jetty HTTPS backend' \
    'log:Netty HTTPS backend' \
    'log:TLS boundary split HTTPS backend' \
    'log:TLS boundary coalesced HTTPS backend' \
    'log:injected Java instrumentation' \
    'apache:startup' \
    'http:live coalesced-request source' \
    'http:verified Apache-to-Jetty HTTPS path' \
    'log:injected Java helper' \
    'transport' \
    'diagnostic-denials' \
    'runtime' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'instrumented HTTPS traffic ran before bridge readiness\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }

  local denial_status=0
  if (
    RESULT_DIR="$result_dir"
    SCENARIO=basic
    TRANSPORT=getsockopt
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() { return 0; }
    run_bounded() { return 0; }
    run_logged_bounded() { return 0; }
    date() { printf 'startup-cursor\n'; }
    wait_for_http() { return 0; }
    wait_for_log() { return 0; }
    assert_selected_transport() { return 0; }
    wait_for_apache_instrumentation() { return 0; }
    assert_apache_denies_java_diagnostics() { return 37; }
    assert_runtime_contract() {
      : >"$result_dir/runtime-after-denial-failure"
    }

    start_stack
  ) >/dev/null 2>&1; then
    printf 'startup ignored Apache diagnostic denial failure\n' >&2
    return 1
  else
    denial_status=$?
  fi
  [[ "$denial_status" == "37" &&
    ! -e "$result_dir/runtime-after-denial-failure" ]] || {
    printf 'startup mutated runtime evidence after diagnostic denial failure\n' >&2
    return 1
  }
}

test_delayed_otlp_startup_avoids_java_traffic() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-startup"
  local -r observed="$result_dir/observed"
  local -r expected="$result_dir/expected"

  mkdir -p -- "$result_dir/results"
  (
    RESULT_DIR="$result_dir"
    RESULTS_ROOT="$result_dir/results"
    PROJECT_NAME="obi-apache-java-https-test"
    SCENARIO=delayed-otlp-suppression
    TRANSPORT=getsockopt
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() {
      return 0
    }
    run_bounded() {
      return 0
    }
    run_logged_bounded() {
      [[ "$*" == *"up --build --detach --force-recreate trace-receiver java-backend coalesced-source apache-proxy obi"* ]] ||
        return 1
      printf 'compose:up\n' >>"$observed"
    }
    date() {
      printf 'cursor:startup\n' >>"$observed"
      printf 'startup-cursor\n'
    }
    wait_for_http() {
      [[ "$2" == "trace receiver" ]] || return 1
      printf 'http:%s\n' "$2" >>"$observed"
    }
    wait_for_log() {
      [[ "${4:-}" == "startup-cursor" ]] || return 1
      printf 'log:%s\n' "$3" >>"$observed"
    }
    assert_selected_transport() {
      return 1
    }
    assert_runtime_contract() {
      return 1
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    assert_apache_denies_java_diagnostics() {
      return 1
    }

    start_stack
    [[ "$STACK_STARTED" == "true" && "$BRIDGE_RUNNING" == "true" &&
      "$DELAYED_OTLP_PROVIDER_READY_SINCE" == "startup-cursor" ]]
  ) || {
    printf 'delayed OTLP startup generated Java traffic before its control\n' >&2
    return 1
  }

  printf '%s\n' \
    'cursor:startup' \
    'compose:up' \
    'http:trace receiver' \
    'log:OBI remote-parent bridge' \
    'log:external OTel extension' \
    'log:Jetty HTTPS backend' \
    'log:Netty HTTPS backend' \
    'log:TLS boundary split HTTPS backend' \
    'log:TLS boundary coalesced HTTPS backend' \
    'log:injected Java instrumentation' \
    'apache:startup' \
    'log:Apache HTTP proxy' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'delayed OTLP startup order changed:\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_delayed_otlp_recreate_avoids_java_traffic() {
  local -r result_dir="$TEST_TMP_DIR/delayed-otlp-recreate"
  local -r observed="$result_dir/observed"
  local -r expected="$result_dir/expected"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=unix
    date() {
      printf 'recreate-cursor\n'
    }
    run_bounded() {
      [[ "$BRIDGE_RUNNING" == "false" && -z "$SELECTED_TRANSPORT" ]] || return 1
      printf 'compose:%s\n' "$*" >>"$observed"
    }
    wait_for_log() {
      [[ "${4:-}" == "recreate-cursor" ]] || return 1
      printf 'log:%s\n' "$3" >>"$observed"
    }
    assert_selected_transport() {
      return 1
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    wait_for_http() {
      [[ "$2" == "delayed-otlp-suppression trace receiver" ]] || return 1
      printf 'http:%s\n' "$2" >>"$observed"
    }
    wait_for_java_duplicate_suppression() {
      return 1
    }

    DELAYED_OTLP_PROVIDER_READY_SINCE=""
    recreate_instrumented_stack tcp delayed-otlp-suppression getsockopt false true
    [[ "$BRIDGE_RUNNING" == "true" && -z "$SELECTED_TRANSPORT" &&
      "$DELAYED_OTLP_PROVIDER_READY_SINCE" == "recreate-cursor" ]]
  ) || {
    printf 'delayed OTLP recreation generated Java traffic before its control\n' >&2
    return 1
  }

  printf '%s\n' \
    'compose:180 test-compose up --detach --force-recreate trace-receiver java-backend apache-proxy obi' \
    'http:delayed-otlp-suppression trace receiver' \
    'log:delayed-otlp-suppression OBI remote-parent bridge' \
    'log:delayed-otlp-suppression external OTel extension' \
    'log:delayed-otlp-suppression injected Java instrumentation' \
    'log:delayed-otlp-suppression Jetty HTTPS backend' \
    'log:delayed-otlp-suppression Netty HTTPS backend' \
    'log:delayed-otlp-suppression TLS boundary split HTTPS backend' \
    'log:delayed-otlp-suppression TLS boundary coalesced HTTPS backend' \
    'apache:recreate-instrumented' \
    'log:delayed-otlp-suppression Apache HTTP proxy' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'delayed OTLP recreation order changed:\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }

  if (
    RESULT_DIR="$result_dir"
    recreate_instrumented_stack tcp invalid getsockopt false invalid
  ) >/dev/null 2>&1; then
    printf 'delayed OTLP recreation accepted an invalid traffic mode\n' >&2
    return 1
  fi
}

test_apache_readiness_requires_the_full_pool() {
  local -r result_dir="$TEST_TMP_DIR/apache-readiness"
  local publication_status=0

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=4
    local -i metric_calls=0
    apache_process_count() {
      printf '%d\n' "$APACHE_EXPECTED_PROCESS_COUNT"
    }
    fetch_obi_metrics() {
      ((metric_calls += 1))
      if ((metric_calls == 1)); then
        printf 'obi_instrumented_processes{process_name="httpd"} 8\n' >"$1"
      else
        printf 'obi_instrumented_processes{process_name="httpd"} 9\n' >"$1"
      fi
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }

    wait_for_apache_instrumentation test || return 1
    ((metric_calls == 3)) || return 1
    grep -Fqx 'expected_processes=9' \
      "$RESULT_DIR/apache-instrumentation-test.txt" || return 1
    grep -Fqx 'observed_processes=9' "$RESULT_DIR/apache-instrumentation-test.txt" || return 1
    grep -Fqx 'instrumented_processes=9' \
      "$RESULT_DIR/apache-instrumentation-test.txt" || return 1
  ) || {
    printf 'Apache readiness did not require two full-pool observations\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=2
    apache_process_count() {
      printf '8\n'
    }
    fetch_obi_metrics() {
      printf 'obi_instrumented_processes{process_name="httpd"} 8\n' >"$1"
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }

    wait_for_apache_instrumentation incomplete
  ) >/dev/null 2>&1; then
    printf 'Apache readiness accepted an undersized process pool\n' >&2
    return 1
  fi

  if (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=3
    SECONDS=0
    apache_process_count() {
      printf '%d\n' "$APACHE_EXPECTED_PROCESS_COUNT"
    }
    fetch_obi_metrics() {
      printf 'obi_instrumented_processes{process_name="httpd"} 9\n' >"$1"
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }
    install() { return 29; }

    wait_for_apache_instrumentation publication
  ) >/dev/null 2>&1; then
    printf 'Apache readiness ignored evidence publication failure\n' >&2
    return 1
  else
    publication_status=$?
  fi
  [[ "$publication_status" == "29" ]] || {
    printf 'Apache readiness publication returned %s instead of 29\n' \
      "$publication_status" >&2
    return 1
  }
}

test_apache_instrumented_process_metric_is_exact() {
  local -r metrics="$TEST_TMP_DIR/apache-instrumented-processes.prom"

  printf 'obi_instrumented_processes{process_name="httpd"} 9\n' >"$metrics"
  [[ "$(instrumented_apache_process_count "$metrics")" == "9" ]] || {
    printf 'Apache process metric rejected one exact integer series\n' >&2
    return 1
  }

  printf 'obi_instrumented_processes{process_name="httpd"} 9.4\n' >"$metrics"
  if instrumented_apache_process_count "$metrics" >/dev/null 2>&1; then
    printf 'Apache process metric rounded a fractional value\n' >&2
    return 1
  fi

  printf 'obi_instrumented_processes{process_name="httpd"} NaN\n' >"$metrics"
  if instrumented_apache_process_count "$metrics" >/dev/null 2>&1; then
    printf 'Apache process metric accepted a malformed value\n' >&2
    return 1
  fi

  printf '%s\n' \
    'obi_instrumented_processes{process_name="httpd"} 4' \
    'obi_instrumented_processes{process_name="httpd",source="duplicate"} 5' \
    >"$metrics"
  if instrumented_apache_process_count "$metrics" >/dev/null 2>&1; then
    printf 'Apache process metric accepted duplicate matching series\n' >&2
    return 1
  fi

  printf 'obi_instrumented_processes{process_name="java"} 1\n' >"$metrics"
  if instrumented_apache_process_count "$metrics" >/dev/null 2>&1; then
    printf 'Apache process metric accepted a missing httpd series\n' >&2
    return 1
  fi
}

test_apache_readiness_uses_elapsed_deadline() {
  local -r result_dir="$TEST_TMP_DIR/apache-readiness-deadline"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=2
    SECONDS=0
    local -i metric_calls=0
    local -i sleep_calls=0
    apache_process_count() {
      printf '%d\n' "$APACHE_EXPECTED_PROCESS_COUNT"
    }
    fetch_obi_metrics() {
      ((metric_calls += 1))
      printf 'obi_instrumented_processes{process_name="httpd"} 9\n' >"$1"
      SECONDS="$((SECONDS + READINESS_TIMEOUT_SECONDS))"
    }
    sleep() {
      ((sleep_calls += 1))
    }

    if wait_for_apache_instrumentation deadline >/dev/null 2>&1; then
      printf 'Apache readiness accepted one sample after its deadline\n' >&2
      return 1
    fi
    ((metric_calls == 1)) || return 1
    ((sleep_calls == 0)) || return 1
  ) || {
    printf 'Apache readiness did not enforce an elapsed-time deadline\n' >&2
    return 1
  }
}

test_apache_instrumentation_drain_is_a_generation_boundary() {
  local -r result_dir="$TEST_TMP_DIR/apache-instrumentation-drain"
  local publication_status=0

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=5
    SECONDS=0
    local -i metric_calls=0
    fetch_obi_metrics() {
      ((metric_calls += 1))
      if ((metric_calls == 1)); then
        printf 'obi_instrumented_processes{process_name="httpd"} 9\n' >"$1"
      else
        printf 'obi_instrumented_processes{process_name="httpd"} 0\n' >"$1"
      fi
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }

    wait_for_apache_instrumentation_drain test || return 1
    ((metric_calls == 3)) || return 1
    grep -Fqx 'expected_instrumented_processes=0' \
      "$RESULT_DIR/apache-instrumentation-drain-test.txt" || return 1
    grep -Fqx 'instrumented_processes=0' \
      "$RESULT_DIR/apache-instrumentation-drain-test.txt" || return 1
  ) || {
    printf 'Apache instrumentation drain did not require a stable zero boundary\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=2
    SECONDS=0
    fetch_obi_metrics() {
      printf 'obi_instrumented_processes{process_name="httpd"} 9\n' >"$1"
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }

    wait_for_apache_instrumentation_drain stale
  ) >/dev/null 2>&1; then
    printf 'Apache instrumentation drain accepted a stale old generation\n' >&2
    return 1
  fi

  if (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=3
    SECONDS=0
    fetch_obi_metrics() {
      printf 'obi_instrumented_processes{process_name="httpd"} 0\n' >"$1"
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }
    install() { return 29; }

    wait_for_apache_instrumentation_drain publication
  ) >/dev/null 2>&1; then
    printf 'Apache drain ignored evidence publication failure\n' >&2
    return 1
  else
    publication_status=$?
  fi
  [[ "$publication_status" == "29" ]] || {
    printf 'Apache drain publication returned %s instead of 29\n' \
      "$publication_status" >&2
    return 1
  }
}

test_apache_process_count_uses_docker_compatible_columns() {
  local -r calls="$TEST_TMP_DIR/apache-process-count.calls"

  (
    COMPOSE=(docker compose)
    run_bounded() {
      printf '%s\n' "$*" >>"$calls"
      if [[ "$2 $3 $4 $5" == "docker compose ps --quiet" ]]; then
        printf '0123456789abcdef\n'
      elif [[ "$2 $3 $5 $6" == "docker top -eo pid,comm" ]]; then
        printf 'PID COMMAND\n'
        printf '101 httpd\n'
        printf '102 httpd\n'
        printf '103 java\n'
      else
        return 64
      fi
    }

    [[ "$(apache_process_count "$((SECONDS + 60))")" == "2" ]] || return 1
    grep -Fqx '10 docker top 0123456789abcdef -eo pid,comm' "$calls" || return 1
  ) || {
    printf 'Apache process count did not request Docker-compatible PID and command columns\n' >&2
    return 1
  }
}

test_apache_readiness_rejects_failed_process_inspection() {
  local -r result_dir="$TEST_TMP_DIR/apache-process-inspection-failure"

  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    READINESS_TIMEOUT_SECONDS=2
    SECONDS=0
    COMPOSE=(docker compose)
    run_bounded() {
      local pid=0

      if [[ "$2 $3 $4 $5" == "docker compose ps --quiet" ]]; then
        printf '0123456789abcdef\n'
      elif [[ "$2 $3 $5 $6" == "docker top -eo pid,comm" ]]; then
        printf 'PID COMMAND\n'
        for pid in {101..109}; do
          printf '%d httpd\n' "$pid"
        done
        return 42
      else
        return 64
      fi
    }
    fetch_obi_metrics() {
      printf 'obi_instrumented_processes{process_name="httpd"} 9\n' >"$1"
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }

    wait_for_apache_instrumentation failed-inspection
  ) >/dev/null 2>&1; then
    printf 'Apache readiness accepted rows from a failed Docker process inspection\n' >&2
    return 1
  fi
}

test_apache_pool_bounds_pressure() {
  local -r apache_config="$TEST_SCRIPT_DIR/../apache/httpd.conf"
  local -i server_limit=0
  local -i start_servers=0
  local -i threads_per_child=0
  local -i max_request_workers=0
  local -i min_spare_threads=0
  local -i max_spare_threads=0
  local -i max_connections_per_child=0
  local -i pressure_requests=0

  server_limit="$(awk '$1 == "ServerLimit" { print $2 }' "$apache_config")"
  start_servers="$(awk '$1 == "StartServers" { print $2 }' "$apache_config")"
  threads_per_child="$(awk '$1 == "ThreadsPerChild" { print $2 }' "$apache_config")"
  max_request_workers="$(awk '$1 == "MaxRequestWorkers" { print $2 }' "$apache_config")"
  min_spare_threads="$(awk '$1 == "MinSpareThreads" { print $2 }' "$apache_config")"
  max_spare_threads="$(awk '$1 == "MaxSpareThreads" { print $2 }' "$apache_config")"
  max_connections_per_child="$(awk '$1 == "MaxConnectionsPerChild" { print $2 }' "$apache_config")"
  pressure_requests="$(scenario_request_count pressure)"

  ((start_servers == server_limit))
  ((APACHE_EXPECTED_PROCESS_COUNT == start_servers + 1))
  ((start_servers * threads_per_child == max_request_workers))
  ((max_request_workers > pressure_requests))
  ((min_spare_threads <= max_request_workers - pressure_requests))
  ((max_spare_threads == max_request_workers))
  ((max_connections_per_child == 0))
}

test_https_health_probes_close_the_backend_connection() {
  [[ "$APACHE_HTTPS_HEALTH_ENDPOINT" == *'?close=1' ]] || {
    printf 'HTTPS health probes can retain a backend connection\n' >&2
    return 1
  }
  if grep -Fq '"http://127.0.0.1:18080/healthz"' "$TEST_SCRIPT_DIR/../run.sh"; then
    printf 'a measured-path health probe bypasses the closing endpoint\n' >&2
    return 1
  fi
}

test_recreated_stack_readiness_uses_log_cursor() {
  local -r observed="$TEST_TMP_DIR/recreate-readiness.observed"
  local -r expected="$TEST_TMP_DIR/recreate-readiness.expected"
  local -r result_dir="$TEST_TMP_DIR/recreate-readiness-result"

  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=unix
    date() {
      printf 'recreate-cursor\n'
    }
    run_bounded() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
        -e "$RESULT_DIR/java-selected-transport-configuration.txt" ]] || return 31
      printf 'compose:%s\n' "$*" >>"$observed"
    }
    wait_for_log() {
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport:%s:%s\n' "$1" "$BRIDGE_TRANSPORT" >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    wait_for_java_duplicate_suppression() {
      printf 'suppression:%s\n' "$(basename -- "$1")" >>"$observed"
    }

    recreate_instrumented_stack tcp restoration unix
  ) || {
    printf 'recreated stack readiness-order probe failed\n' >&2
    return 1
  }
  [[ ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'recreated stack retained stale current-generation selection evidence\n' >&2
    return 1
  }

  printf '%s\n' \
    'compose:180 test-compose up --detach --force-recreate java-backend apache-proxy obi' \
    'log:restoration OBI remote-parent bridge:recreate-cursor' \
    'log:restoration external OTel extension:recreate-cursor' \
    'log:restoration injected Java instrumentation:recreate-cursor' \
    'log:restoration Jetty HTTPS backend:recreate-cursor' \
    'log:restoration Netty HTTPS backend:recreate-cursor' \
    'log:restoration TLS boundary split HTTPS backend:recreate-cursor' \
    'log:restoration TLS boundary coalesced HTTPS backend:recreate-cursor' \
    'apache:recreate-instrumented' \
    'http:restoration HTTPS path' \
    'log:restoration injected Java helper:recreate-cursor' \
    'transport:unix:unix' \
    'suppression:duplicate-suppression-restoration.prom' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'recreated stack used stale readiness evidence\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_disabled_control_waits_for_instrumentation() {
  local -r result_dir="$TEST_TMP_DIR/disabled-readiness"
  local -r observed="$result_dir/observed"
  local -r expected="$result_dir/expected"
  local -r failure_marker="$result_dir/failure-mutation"
  local control_status=0

  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    date() {
      printf 'disabled-cursor\n'
    }
    run_bounded() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
        "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == "retained" ]] ||
        return 31
      printf 'compose:%s\n' "$*" >>"$observed"
    }
    wait_for_log() {
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    assert_runtime_contract() {
      printf 'runtime:%s\n' "$1" >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s\n' "$1" >>"$observed"
    }

    run_disabled_control
  ) || {
    printf 'disabled-control readiness-order probe failed\n' >&2
    return 1
  }
  [[ ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'disabled control retained stale current transport evidence\n' >&2
    return 1
  }

  printf '%s\n' \
    'compose:30 test-compose config' \
    'compose:120 test-compose up --detach --force-recreate java-backend apache-proxy obi' \
    'log:disabled-control external extension:disabled-cursor' \
    'log:disabled-control Java instrumentation:disabled-cursor' \
    'apache:disabled-control' \
    'http:disabled-control HTTPS path' \
    'runtime:disabled' \
    'scenario:disabled' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'disabled control used stale instrumentation readiness\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }

  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    rm() { return 29; }
    run_bounded() {
      : >"$failure_marker"
    }

    run_disabled_control
  ) >/dev/null 2>&1; then
    printf 'disabled control ignored transport invalidation failure\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == "29" &&
    ! -e "$failure_marker" &&
    "$(<"$result_dir/java-transport-configuration.txt")" == "current" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'disabled control mutated the stack after invalidation failed\n' >&2
    return 1
  }
}

test_uninstrumented_control_invalidates_before_stack_mutation() {
  local -r result_dir="$TEST_TMP_DIR/uninstrumented-invalidation"
  local -r mutation_marker="$result_dir/mutation"
  local -r failure_marker="$result_dir/failure-mutation"
  local control_status=0

  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    capture_control_response() { return 0; }
    run_bounded() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
        "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == "retained" ]] ||
        return 31
      : >"$mutation_marker"
      return 41
    }

    run_uninstrumented_control
  ) >/dev/null 2>&1; then
    printf 'uninstrumented control ignored the mutation-boundary failure\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == "41" &&
    -e "$mutation_marker" &&
    ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'uninstrumented control did not invalidate before stopping OBI\n' >&2
    return 1
  }

  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    capture_control_response() { return 0; }
    rm() { return 29; }
    run_bounded() {
      : >"$failure_marker"
    }

    run_uninstrumented_control
  ) >/dev/null 2>&1; then
    printf 'uninstrumented control ignored transport invalidation failure\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == "29" &&
    ! -e "$failure_marker" &&
    "$(<"$result_dir/java-transport-configuration.txt")" == "current" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'uninstrumented control mutated the stack after invalidation failed\n' >&2
    return 1
  }
}

test_standalone_restart_invalidates_before_stack_mutation() {
  local -r result_dir="$TEST_TMP_DIR/restart-invalidation"
  local -r mutation_marker="$result_dir/mutation"
  local -r failure_marker="$result_dir/failure-mutation"
  local -r cursor_failure_marker="$result_dir/cursor-failure-mutation"
  local -r readiness_observed="$result_dir/readiness-failure"
  local restart_status=0

  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  if (
    RESULT_DIR="$result_dir"
    SCENARIO=restart
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    date() { printf 'restart-cursor\n'; }
    run_bounded() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
        "$(<"$RESULT_DIR/java-selected-transport-configuration.txt")" == "retained" ]] ||
        return 31
      : >"$mutation_marker"
      return 41
    }

    execute_requested_scenarios
  ) >/dev/null 2>&1; then
    printf 'standalone restart ignored the mutation-boundary failure\n' >&2
    return 1
  else
    restart_status=$?
  fi
  [[ "$restart_status" == "41" &&
    -e "$mutation_marker" &&
    ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'standalone restart did not invalidate before restarting OBI\n' >&2
    return 1
  }

  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  if (
    RESULT_DIR="$result_dir"
    SCENARIO=restart
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    date() { printf 'restart-cursor\n'; }
    rm() { return 29; }
    run_bounded() {
      : >"$failure_marker"
    }

    execute_requested_scenarios
  ) >/dev/null 2>&1; then
    printf 'standalone restart ignored transport invalidation failure\n' >&2
    return 1
  else
    restart_status=$?
  fi
  [[ "$restart_status" == "29" &&
    ! -e "$failure_marker" &&
    "$(<"$result_dir/java-transport-configuration.txt")" == "current" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'standalone restart mutated the stack after invalidation failed\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$result_dir"
    SCENARIO=restart
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    date() { return 42; }
    invalidate_selected_transport() {
      : >"$cursor_failure_marker"
    }
    run_bounded() {
      : >"$cursor_failure_marker"
    }

    execute_requested_scenarios
  ) >/dev/null 2>&1; then
    printf 'standalone restart ignored log-cursor failure\n' >&2
    return 1
  else
    restart_status=$?
  fi
  [[ "$restart_status" == "42" && ! -e "$cursor_failure_marker" ]] || {
    printf 'standalone restart mutated state after log-cursor failure\n' >&2
    return 1
  }

  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  if (
    RESULT_DIR="$result_dir"
    SCENARIO=restart
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    date() { printf 'restart-cursor\n'; }
    run_bounded() {
      printf 'restart\n' >>"$readiness_observed"
    }
    wait_for_log() {
      printf 'wait\n' >>"$readiness_observed"
      return 43
    }
    wait_for_apache_instrumentation() {
      printf 'continued-apache\n' >>"$readiness_observed"
    }
    wait_for_http() {
      printf 'continued-http\n' >>"$readiness_observed"
    }
    sleep() {
      printf 'continued-sleep\n' >>"$readiness_observed"
    }
    wait_for_java_duplicate_suppression() {
      printf 'continued-suppression\n' >>"$readiness_observed"
    }
    assert_selected_transport() {
      printf 'continued-transport\n' >>"$readiness_observed"
    }
    run_scenario() {
      printf 'continued-scenario\n' >>"$readiness_observed"
    }

    execute_requested_scenarios
  ) >/dev/null 2>&1; then
    printf 'standalone restart ignored post-restart readiness failure\n' >&2
    return 1
  else
    restart_status=$?
  fi
  [[ "$restart_status" == "43" &&
    "$(<"$readiness_observed")" == $'restart\nwait' ]] || {
    printf 'standalone restart continued after readiness failure\n' >&2
    return 1
  }
}

test_extension_disabled_control_uses_configuration_log() {
  local -r observed="$TEST_TMP_DIR/extension-disabled.observed"
  local -r expected="$TEST_TMP_DIR/extension-disabled.expected"

  (
    COMPOSE=(test-compose)
    date() {
      printf 'cursor\n' >>"$observed"
      printf 'extension-disabled-cursor\n'
    }
    stop_obi_for_no_state_control() {
      printf 'stop-obi:%s\n' "$1" >>"$observed"
    }
    run_bounded() {
      printf 'compose:%s:extension=%s:enabled=%s:propagators=%s\n' \
        "$*" \
        "$OTEL_JAVAAGENT_EXTENSIONS_VALUE" \
        "$EXTENSION_ENABLED" \
        "$OTEL_PROPAGATORS_VALUE" >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    assert_runtime_contract() {
      printf 'runtime:%s\n' "$1" >>"$observed"
    }
    wait_for_log() {
      printf 'log:%s:%s:%s\n' "$2" "$3" "${4:-}" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:%s\n' "$SCENARIO_VARIANT" "$1" >>"$observed"
    }

    run_extension_controls
  ) || {
    printf 'extension-disabled lifecycle probe failed\n' >&2
    return 1
  }

  printf '%s\n' \
    'stop-obi:extension-controls' \
    'compose:120 test-compose up --detach --force-recreate java-backend apache-proxy:extension=:enabled=false:propagators=tracecontext,baggage' \
    'http:extension-absent HTTPS path' \
    'runtime:extension-absent' \
    'scenario:extension-absent:w3c-only' \
    'cursor' \
    'compose:120 test-compose up --detach --force-recreate java-backend apache-proxy:extension=/otel/obi-otel-extension.jar:enabled=false:propagators=obi,tracecontext,baggage' \
    'http:extension-disabled HTTPS path' \
    'runtime:extension-disabled' \
    'log:OBI remote-parent propagator disabled by configuration:disabled external extension:extension-disabled-cursor' \
    'scenario:extension-disabled:w3c-only' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'extension-disabled control used the wrong lifecycle predicate\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_permanent_absence_requires_a_full_jvm_lifetime_boundary() {
  local control=""
  local global_marker_line=""
  local disabled_line=""
  local obi_stop_line=""
  local java_start_line=""
  local identity_before_line=""
  local fail_open_line=""
  local w3c_line=""
  local registration_line=""
  local logs_line=""
  local identity_after_line=""
  local final_obi_check_line=""
  local java_stop_line=""
  local recovery_line=""
  local recovery_helper_line=""
  local recovery_basic_line=""
  local global_marker_clear_line=""
  local local_marker_clear_line=""
  local status_line=""

  control="$(declare -f run_permanent_absence_control)" || return $?
  global_marker_line="$(awk '/create_permanent_absence_global_marker/ { line = NR } END { print line }' <<<"$control")"
  disabled_line="$(awk '/run_disabled_control/ { line = NR } END { print line }' <<<"$control")"
  obi_stop_line="$(awk '/apache-proxy java-backend obi/ { line = NR } END { print line }' <<<"$control")"
  java_start_line="$(awk '/java-backend apache-proxy/ { line = NR } END { print line }' <<<"$control")"
  identity_before_line="$(awk '/capture_service_runtime_identity java-backend "\$identity_before"/ { line = NR } END { print line }' <<<"$control")"
  fail_open_line="$(awk '/run_scenario fail-open/ { line = NR } END { print line }' <<<"$control")"
  w3c_line="$(awk '/run_scenario w3c-only/ { line = NR } END { print line }' <<<"$control")"
  registration_line="$(awk '/diagnostic_counter .* registration_fail/ { line = NR } END { print line }' <<<"$control")"
  logs_line="$(awk '/assert_permanent_absence_logs_are_bounded/ { line = NR } END { print line }' <<<"$control")"
  identity_after_line="$(awk '/capture_service_runtime_identity java-backend "\$identity_after"/ { line = NR } END { print line }' <<<"$control")"
  final_obi_check_line="$(awk '/assert_compose_service_stopped obi/ { line = NR } END { print line }' <<<"$control")"
  java_stop_line="$(awk '/stop_permanent_absence_jvm/ { line = NR } END { print line }' <<<"$control")"
  recovery_line="$(awk '/complete_permanent_absence_recovery \|\| return/ { line = NR } END { print line }' <<<"$control")"
  recovery_helper_line="$(awk '/recreate_instrumented_stack .*post-permanent absence recovery/ { print NR; exit }' <<<"$control")"
  recovery_basic_line="$(awk '/run_scenario basic/ { print NR; exit }' <<<"$control")"
  global_marker_clear_line="$(awk '/clear_pending_permanent_absence_recovery/ { print NR; exit }' <<<"$control")"
  local_marker_clear_line="$(awk '/rm -f -- "\$recovery_marker"/ { print NR; exit }' <<<"$control")"
  status_line="$(awk '/scenario-permanent-absence-status.json/ { line = NR } END { print line }' <<<"$control")"

  [[ "$global_marker_line" =~ ^[1-9][0-9]*$ && \
    "$disabled_line" =~ ^[1-9][0-9]*$ && \
    "$obi_stop_line" =~ ^[1-9][0-9]*$ && \
    "$java_start_line" =~ ^[1-9][0-9]*$ && \
    "$identity_before_line" =~ ^[1-9][0-9]*$ && \
    "$fail_open_line" =~ ^[1-9][0-9]*$ && \
    "$w3c_line" =~ ^[1-9][0-9]*$ && \
    "$registration_line" =~ ^[1-9][0-9]*$ && \
    "$logs_line" =~ ^[1-9][0-9]*$ && \
    "$identity_after_line" =~ ^[1-9][0-9]*$ && \
    "$final_obi_check_line" =~ ^[1-9][0-9]*$ && \
    "$java_stop_line" =~ ^[1-9][0-9]*$ && \
    "$recovery_line" =~ ^[1-9][0-9]*$ && \
    "$recovery_helper_line" =~ ^[1-9][0-9]*$ && \
    "$recovery_basic_line" =~ ^[1-9][0-9]*$ && \
    "$global_marker_clear_line" =~ ^[1-9][0-9]*$ && \
    "$local_marker_clear_line" =~ ^[1-9][0-9]*$ && \
    "$status_line" =~ ^[1-9][0-9]*$ && \
    global_marker_line -lt disabled_line && \
    disabled_line -lt obi_stop_line && \
    obi_stop_line -lt java_start_line && \
    java_start_line -lt identity_before_line && \
    identity_before_line -lt fail_open_line && \
    fail_open_line -lt w3c_line && \
    w3c_line -lt registration_line && \
    registration_line -lt logs_line && \
    registration_line -lt identity_after_line && \
    identity_after_line -lt final_obi_check_line && \
    final_obi_check_line -lt java_stop_line && \
    java_stop_line -lt logs_line && \
    logs_line -lt recovery_line && \
    recovery_line -lt status_line && \
    recovery_helper_line -lt recovery_basic_line && \
    recovery_basic_line -lt global_marker_clear_line && \
    global_marker_clear_line -lt local_marker_clear_line ]] || {
    printf 'permanent-absence control no longer fences absence, evidence, and recovery ordering\n' >&2
    return 1
  }
  [[ "$control" == *'"obi_started_during_jvm_lifetime":false'* && \
    "$control" == *'"disabled_baseline_equivalent":true'* && \
    "$control" == *'"post_absence_recovery":"passed"'* && \
    "$control" == *'registration_failures >= 1'* && \
    "$control" == *'registration_failures <= PERMANENT_ABSENCE_REGISTRATION_FAILURE_MAX'* && \
    "$control" == *'assert_runtime_identity_unchanged'* && \
    "$control" == *'capture_bounded_permanent_absence_logs'* && \
    "$control" == *'wait_for_bounded_permanent_absence_log'* && \
    "$control" == *'assert_permanent_absence_logs_are_bounded'* ]] || {
    printf 'permanent-absence control lost its baseline, bounded, identity, or recovery evidence\n' >&2
    return 1
  }
  local transport=""
  for transport in getsockopt unix auto; do
    (
      TRANSPORT=auto
      SCENARIO=all
      parse_args --transport "$transport" --scenario permanent-absence
      [[ "$TRANSPORT" == "$transport" && "$SCENARIO" == permanent-absence ]]
    ) || {
      printf 'permanent-absence scenario rejected enabled transport %s\n' \
        "$transport" >&2
      return 1
    }
  done
  if (parse_args --transport disabled --scenario permanent-absence) \
    >/dev/null 2>&1; then
    printf 'permanent-absence scenario accepted disabled transport\n' >&2
    return 1
  fi
}

test_permanent_absence_startup_uses_normal_runtime_contract() {
  local -r result_dir="$TEST_TMP_DIR/permanent-absence-startup"

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    SCENARIO=permanent-absence
    TRANSPORT=getsockopt
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    verify_compose_project_ownership() { :; }
    invalidate_project_transport_evidence() { :; }
    run_bounded() { :; }
    run_logged_bounded() { printf '%s\n' "$*" >"$result_dir/compose"; }
    date() { printf 'startup-cursor\n'; }
    wait_for_http() { :; }
    wait_for_log() { :; }
    wait_for_apache_instrumentation() { :; }
    assert_selected_transport() { :; }
    assert_apache_denies_java_diagnostics() { :; }
    assert_runtime_contract() { printf '%s\n' "$1" >"$result_dir/runtime"; }

    start_stack
  ) || {
    printf 'permanent-absence normal startup failed before control dispatch\n' >&2
    return 1
  }
  [[ "$(<"$result_dir/compose")" == \
      *"trace-receiver java-backend coalesced-source apache-proxy obi"* &&
    "$(<"$result_dir/runtime")" == "basic" ]] || {
    printf 'permanent-absence startup did not retain the normal OBI runtime\n' >&2
    return 1
  }
}

test_permanent_absence_startup_refuses_prior_run_recovery() {
  local -r guard_root="$TEST_TMP_DIR/permanent-absence-shared-guard"
  local -r worktree_b_results="$TEST_TMP_DIR/permanent-absence-worktree-b-results"
  local -r project=obi-apache-java-https-test
  local -r foreign_project=obi-apache-java-https-foreign
  local -r docker_identity=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local -r marker="$guard_root/$project.permanent-absence-recovery-required"
  local -r mutation="$worktree_b_results/compose-up"

  mkdir -m 0700 -- "$guard_root"
  mkdir -p -- "$worktree_b_results"
  (
    PROJECT_NAME="$project"
    umask 077
    permanent_absence_global_marker_payload "$docker_identity" >"$marker"
  )
  if (
    RESULTS_ROOT="$worktree_b_results"
    RESULT_DIR="$worktree_b_results"
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_identity"
    SCENARIO=permanent-absence
    TRANSPORT=getsockopt
    COMPOSE=(test-compose)
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    assert_clean_source_checkout_is_stable() { :; }
    run_logged_bounded() { : >"$mutation"; }

    start_stack
  ) >/dev/null 2>&1; then
    printf 'permanent-absence startup ignored a prior run recovery marker\n' >&2
    return 1
  fi
  [[ ! -e "$mutation" && ! -L "$mutation" ]] || {
    printf 'permanent-absence startup mutated Compose across a worktree recovery fence\n' >&2
    return 1
  }

  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$foreign_project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_identity"
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery
  ) || {
    printf 'permanent-absence startup rejected a foreign project marker\n' >&2
    return 1
  }
  printf 'corrupt\n' >"$marker"
  chmod 0600 -- "$marker"
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_identity"
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    assert_no_pending_permanent_absence_recovery
  ) >/dev/null 2>&1; then
    printf 'permanent-absence startup trusted a malformed host-shared marker\n' >&2
    return 1
  fi
}

test_permanent_absence_project_guard_is_host_shared() {
  local -r guard_root="$TEST_TMP_DIR/permanent-absence-project-guard"
  local -r project=obi-apache-java-https-lock-test
  local -r other_project=obi-apache-java-https-other-lock-test
  local -r lock_file="$guard_root/$project.lock"
  local -r other_lock="$guard_root/$other_project.lock"
  local -r ready="$guard_root/ready"
  local -r release="$guard_root/release"
  local -r observed="$guard_root/observed"
  local -r signal_ready="$guard_root/signal-ready"
  local -r signal_child_ready="$guard_root/signal-child-ready"
  local -r signal_release="$guard_root/signal-release"
  local -r signal_observed="$guard_root/signal-observed"
  local -r group_child="$guard_root/group-child"
  local -r group_outer="$guard_root/group-outer"
  local -r group_outer_ready="$guard_root/group-outer-ready"
  local -r group_child_ready="$guard_root/group-child-ready"
  local -r group_trap_started="$guard_root/group-trap-started"
  local -r group_repeated_signal="$guard_root/group-repeated-signal"
  local -r group_observed="$guard_root/group-observed"
  local -r group_supervisor="$guard_root/group-supervisor"
  local -r reset_wrapper="$guard_root/reset-wrapper"
  local -r reset_ready="$guard_root/reset-ready"
  local -r reset_release="$guard_root/reset-release"
  local -r reset_pass="$guard_root/reset-pass"
  local -r reused_parent_ready="$guard_root/reused-parent-ready"
  local -r reused_parent_release="$guard_root/reused-parent-release"
  local -r reused_child_file="$guard_root/reused-child"
  local guard_pid=""
  local reset_forward_pid=""
  local reset_holder_pid=""
  local reused_parent_pid=""
  local reused_child_pid=""
  local reused_parent_start_time=""
  local group_mode=""
  local group_signal=""
  local group_outer_pid=""
  local group_supervisor_pid=""
  local group_target_pid=""
  local reset_children=""
  local reset_child_pid=""
  local reset_extra_child=""
  local group_status=0
  local reset_status=0
  local expected_group_status=0
  local expected_signal_status=0
  local signal_name=""
  local signal_status=0
  local -i attempt=0
  local definition=""
  local armed_relay_definition=""
  local armed_relay_without_arithmetic=""
  local monitor_disable_line=""
  local supervisor_identity_line=""

  mkdir -m 0700 -- "$guard_root"
  (umask 077; : >"$lock_file"; : >"$other_lock")
  assert_private_project_guard_directory "$guard_root" || return 1
  assert_private_project_guard_lock "$lock_file" || return 1
  definition="$({
    declare -f enter_project_guard
    declare -f run_project_guard_relay
    declare -f wait_for_project_guard_holder
    declare -f publish_project_guard_supervisor_launched
  })" || return 1
  armed_relay_definition="$({
    declare -f run_project_guard_relay
    declare -f wait_for_project_guard_holder
    declare -f forward_project_guard_signal
    declare -f record_project_guard_pending_signal
    declare -f record_project_guard_hup
    declare -f record_project_guard_int
    declare -f record_project_guard_term
    declare -f project_guard_supervisor_is_running
    declare -f project_guard_supervisor_identity_matches
    declare -f load_project_guard_process_stat_identity
    declare -f project_guard_child_signal_state
    declare -f assert_private_project_guard_lock
    declare -f assert_private_project_guard_directory
    declare -f assert_private_project_guard_control_directory
    declare -f project_guard_control_file_matches
    declare -f publish_project_guard_control_file
    declare -f remove_project_guard_control_directory
    declare -f publish_project_guard_supervisor_identity
    declare -f publish_project_guard_supervisor_acceptance
    declare -f load_project_guard_supervisor_identity
    declare -f load_project_guard_supervisor_launch
    declare -f publish_project_guard_supervisor_launch_acceptance
    declare -f publish_project_guard_terminal_decision
    declare -f load_project_guard_holder_status
    declare -f format_project_guard_holder_status_payload
  })" || return 1
  armed_relay_without_arithmetic="$(sed 's/\$((/ARITHMETIC(/g' \
    <<<"$armed_relay_definition")" || return 1
  monitor_disable_line="$(awk '/set \+m;/ { print NR; exit }' <<<"$definition")"
  supervisor_identity_line="$(awk \
    '/run_project_guard_relay/ { print NR; exit }' \
    <<<"$definition")"
  [[ "$definition" != *setsid* && \
    "$definition" == *'set -m'* && \
    "$definition" != *'kill -KILL -- "-$holder_pid"'* && \
    "$definition" == *'--exclusive --nonblock --close'* && \
    "$definition" == *'env --default-signal=HUP,INT,TERM'* && \
    "$definition" == *'read_project_guard_supervisor_identity'* && \
    "$definition" == *'supervisor-launched:$supervisor_pid:$supervisor_start_time'* && \
    "$definition" == *'PROJECT_GUARD_FORWARDING_READY=true'* && \
    "$definition" == *'trap record_project_guard_hup HUP'* && \
    "$definition" != *'trap "" HUP INT TERM'* && \
    "$definition" == *'wait_for_project_guard_holder "$holder_pid"'* && \
    "$definition" == *'publish_project_guard_terminal_decision'* && \
    "$armed_relay_without_arithmetic" != *'$('* && \
    "$armed_relay_definition" != *'`'* && \
    "$armed_relay_definition" != *'<('* && \
    "$armed_relay_definition" != *'>('* && \
    "$monitor_disable_line" =~ ^[1-9][0-9]*$ && \
    "$supervisor_identity_line" =~ ^[1-9][0-9]*$ && \
    monitor_disable_line -lt supervisor_identity_line ]] || {
    printf 'project guard no longer keeps one signal-aware relay\n' >&2
    return 1
  }

  flock --exclusive --nonblock --close "$lock_file" \
    bash -c '
      set -Eeuo pipefail
      source "$1"
      PROJECT_GUARD_ROOT=$2
      PROJECT_NAME=$3
      PROJECT_GUARD_HELD=true
      PROJECT_GUARD_PARENT_PID=$PPID
      PROJECT_GUARD_LOCK_IDENTITY=$(stat --format="%d:%i" -- "$4")
      assert_project_guard_held
      (assert_project_guard_held)
      printf "guarded\n" >"$5"
      : >"$6"
      while [[ ! -e "$7" ]]; do sleep 0.01; done
    ' bash "$TEST_SCRIPT_DIR/../run.sh" "$guard_root" "$project" \
      "$lock_file" "$observed" "$ready" "$release" &
  guard_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$ready" ]] && break
    sleep 0.01
  done
  [[ -e "$ready" && "$(<"$observed")" == guarded ]] || {
    kill -TERM "$guard_pid" 2>/dev/null || true
    wait "$guard_pid" 2>/dev/null || true
    printf 'project guard supervisor did not publish readiness\n' >&2
    return 1
  }
  if flock --exclusive --nonblock "$lock_file" true; then
    printf 'a second worktree acquired the same project lock\n' >&2
    return 1
  fi
  flock --exclusive --nonblock "$other_lock" true || {
    printf 'a distinct project suffix shared the wrong lock\n' >&2
    return 1
  }
  : >"$release"
  wait "$guard_pid" || return $?
  flock --exclusive --nonblock "$lock_file" true || {
    printf 'project lock was not released after guarded runner exit\n' >&2
    return 1
  }
  (
    PROJECT_GUARD_PENDING_SIGNAL=""
    PROJECT_GUARD_SUPERVISOR_PID=""
    PROJECT_GUARD_SUPERVISOR_START_TIME=""
    forward_project_guard_signal HUP
    forward_project_guard_signal TERM
    [[ "$PROJECT_GUARD_PENDING_SIGNAL" == HUP ]]
  ) || {
    printf 'project guard lost or reordered a signal before supervisor publication\n' >&2
    return 1
  }
  if ! (
    sleep 10 &
    PROJECT_GUARD_SUPERVISOR_PID=$!
    PROJECT_GUARD_SUPERVISOR_START_TIME="$(project_guard_process_start_time \
      "$PROJECT_GUARD_SUPERVISOR_PID")"
    PROJECT_GUARD_FORWARDING_READY=true
    PROJECT_GUARD_PENDING_SIGNAL=""
    set +e
    forward_project_guard_signal TERM >/dev/null 2>&1
    signal_status=$?
    set -e
    [[ "$signal_status" == 1 && "$PROJECT_GUARD_PENDING_SIGNAL" == TERM ]] && \
      project_guard_supervisor_is_running "$PROJECT_GUARD_SUPERVISOR_PID" || \
      exit 1
    kill -KILL "$PROJECT_GUARD_SUPERVISOR_PID" 2>/dev/null || true
    for ((attempt = 0; attempt < 500; attempt++)); do
      if ! project_guard_supervisor_is_running \
        "$PROJECT_GUARD_SUPERVISOR_PID"; then
        break
      fi
      sleep 0.01
    done
    if project_guard_supervisor_is_running "$PROJECT_GUARD_SUPERVISOR_PID"; then
      exit 1
    fi
    wait "$PROJECT_GUARD_SUPERVISOR_PID" 2>/dev/null || true
    [[ "$PROJECT_GUARD_PENDING_SIGNAL" == TERM ]]
  ); then
    printf 'project guard discarded an unverified signal-delivery request\n' >&2
    return 1
  fi

  bash -c '
    set -Eeuo pipefail
    sleep 30 &
    child_pid=$!
    cleanup_child() {
      kill -TERM "$child_pid" 2>/dev/null || true
      wait "$child_pid" 2>/dev/null || true
    }
    trap cleanup_child EXIT
    printf "%s\n" "$child_pid" >"$1"
    : >"$2"
    while [[ ! -e "$3" ]]; do sleep 0.01; done
  ' bash "$reused_child_file" "$reused_parent_ready" \
    "$reused_parent_release" &
  reused_parent_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$reused_parent_ready" && -e "$reused_child_file" ]] && break
    sleep 0.01
  done
  [[ -e "$reused_parent_ready" && -e "$reused_child_file" ]] || return 1
  reused_child_pid="$(<"$reused_child_file")"
  reused_parent_start_time="$(project_guard_process_start_time \
    "$reused_parent_pid")" || return 1
  PROJECT_GUARD_SUPERVISOR_PID="$reused_parent_pid"
  PROJECT_GUARD_SUPERVISOR_START_TIME="$((reused_parent_start_time + 1))"
  PROJECT_GUARD_FORWARDING_READY=true
  PROJECT_GUARD_PENDING_SIGNAL=""
  if forward_project_guard_signal TERM >/dev/null 2>&1; then
    : >"$reused_parent_release"
    wait "$reused_parent_pid" 2>/dev/null || true
    printf 'project guard trusted a reused supervisor PID identity\n' >&2
    return 1
  fi
  [[ "$PROJECT_GUARD_PENDING_SIGNAL" == TERM && \
    -e "/proc/$reused_parent_pid" && -e "/proc/$reused_child_pid" ]] || {
    : >"$reused_parent_release"
    wait "$reused_parent_pid" 2>/dev/null || true
    printf 'project guard killed through an unverified supervisor PID identity\n' >&2
    return 1
  }
  : >"$reused_parent_release"
  wait "$reused_parent_pid" || return $?
  PROJECT_GUARD_PENDING_SIGNAL=""
  PROJECT_GUARD_FORWARDING_READY=false
  PROJECT_GUARD_SUPERVISOR_PID=""
  PROJECT_GUARD_SUPERVISOR_START_TIME=""

  for signal_name in HUP INT TERM; do
    rm -f -- "$signal_ready" "$signal_child_ready" \
      "$signal_release" "$signal_observed"
    env --ignore-signal=HUP,INT,TERM \
      flock --exclusive --nonblock --close "$lock_file" \
      env --default-signal=HUP,INT,TERM bash -c '
        set -Eeuo pipefail
        handle_signal() {
          local -r signal_name="$1"
          local -r signal_status="$2"
          local -r lock_file="$3"
          local -r observed="$4"
          if flock --exclusive --nonblock "$lock_file" true; then
            printf "%s:released-too-early\n" "$signal_name" >"$observed"
          else
            printf "%s:held-through-trap\n" "$signal_name" >"$observed"
          fi
          exit "$signal_status"
        }
        trap '\''handle_signal HUP 129 "$1" "$3"'\'' HUP
        trap '\''handle_signal INT 130 "$1" "$3"'\'' INT
        trap '\''handle_signal TERM 130 "$1" "$3"'\'' TERM
        : >"$2"
        bash -c '\''
          : >"$1"
          while [[ ! -e "$2" ]]; do sleep 0.01; done
        '\'' bash "$4" "$5"
      ' bash "$lock_file" "$signal_ready" "$signal_observed" \
        "$signal_child_ready" "$signal_release" &
    PROJECT_GUARD_SUPERVISOR_PID=$!
    PROJECT_GUARD_SUPERVISOR_START_TIME="$(project_guard_process_start_time \
      "$PROJECT_GUARD_SUPERVISOR_PID")" || return 1
    PROJECT_GUARD_FORWARDING_READY=true
    PROJECT_GUARD_PENDING_SIGNAL=""
    for ((attempt = 0; attempt < 500; attempt++)); do
      [[ -e "$signal_ready" && -e "$signal_child_ready" ]] && break
      sleep 0.01
    done
    if [[ ! -e "$signal_ready" || ! -e "$signal_child_ready" ]]; then
      : >"$signal_release"
      wait "$PROJECT_GUARD_SUPERVISOR_PID" 2>/dev/null || true
      printf 'guarded worker did not publish %s child readiness\n' \
        "$signal_name" >&2
      return 1
    fi
    forward_project_guard_signal "$signal_name"
    sleep 0.05
    if [[ -e "$signal_observed" ]] || \
      flock --exclusive --nonblock "$lock_file" true; then
      : >"$signal_release"
      wait "$PROJECT_GUARD_SUPERVISOR_PID" 2>/dev/null || true
      printf 'project guard released before deferred %s recovery\n' \
        "$signal_name" >&2
      return 1
    fi
    : >"$signal_release"
    if wait "$PROJECT_GUARD_SUPERVISOR_PID"; then
      signal_status=0
    else
      signal_status=$?
    fi
    case "$signal_name" in
      HUP) expected_signal_status=129 ;;
      INT|TERM) expected_signal_status=130 ;;
      *) return 1 ;;
    esac
    PROJECT_GUARD_SUPERVISOR_PID=""
    PROJECT_GUARD_SUPERVISOR_START_TIME=""
    PROJECT_GUARD_FORWARDING_READY=false
    PROJECT_GUARD_PENDING_SIGNAL=""
    [[ "$signal_status" == "$expected_signal_status" && \
      "$(<"$signal_observed")" == \
        "$signal_name:held-through-trap" ]] || {
      printf 'project guard released before %s recovery completed\n' \
        "$signal_name" >&2
      return 1
    }
    flock --exclusive --nonblock "$lock_file" true || {
      printf 'project guard remained locked after %s recovery\n' \
        "$signal_name" >&2
      return 1
    }
  done

  cat >"$group_child" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
readonly lock_file="$1"
readonly ready="$2"
readonly trap_started="$3"
readonly observed="$4"
readonly repeated_signal="$5"
readonly wait_fifo="$ready.wait"
# Keep this adversarial private-process-group fixture inside Bash builtins.
# Group-signalling a Bash process and its fork-before-exec child can corrupt
# Bash's SIGCHLD bookkeeping; production cancellation targets only the
# authenticated worker PID, which the preceding HUP/INT/TERM matrix covers
# while that worker has a live external foreground child.
handle_repeated_signal() {
  : >"$repeated_signal"
}
handle_signal() {
  local -r signal_name="$1"
  local -r signal_status="$2"
  trap handle_repeated_signal HUP INT TERM
  : >"$trap_started"
  read -r -t 0.3 _ <&9 || true
  if [[ -e "$repeated_signal" ]]; then
    read -r -t 0.3 _ <&9 || true
  fi
  if flock --exclusive --nonblock "$lock_file" true; then
    printf "%s:released-before-child-trap\n" "$signal_name" >"$observed"
  else
    printf "%s:held-through-child-trap\n" "$signal_name" >"$observed"
  fi
  exit "$signal_status"
}
trap 'handle_signal INT 130' INT
trap 'handle_signal HUP 129' HUP
trap 'handle_signal TERM 143' TERM
mkfifo -- "$wait_fifo"
exec 9<>"$wait_fifo"
rm -f -- "$wait_fifo"
: >"$ready"
while :; do read -r _ <&9 || true; done
EOF
  cat >"$group_outer" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$1"
readonly lock_file="$2"
readonly child_script="$3"
readonly child_ready="$4"
readonly trap_started="$5"
readonly observed="$6"
readonly outer_ready="$7"
readonly supervisor_file="$8"
readonly repeated_signal="$9"
local_status=0
trap 'forward_project_guard_signal HUP' HUP
trap 'forward_project_guard_signal INT' INT
trap 'forward_project_guard_signal TERM' TERM
set -m
[[ "$-" == *m* ]] || exit 91
set +m
[[ "$-" != *m* ]] || exit 92
(
  exec setsid env --ignore-signal=HUP,INT,TERM \
    flock --exclusive --nonblock --close --conflict-exit-code 75 \
    "$lock_file" env --default-signal=HUP,INT,TERM \
      "$child_script" "$lock_file" "$child_ready" "$trap_started" \
        "$observed" "$repeated_signal"
) &
PROJECT_GUARD_SUPERVISOR_PID=$!
PROJECT_GUARD_SUPERVISOR_START_TIME=$(project_guard_process_start_time \
  "$PROJECT_GUARD_SUPERVISOR_PID")
PROJECT_GUARD_FORWARDING_READY=true
printf '%s\n' "$PROJECT_GUARD_SUPERVISOR_PID" >"$supervisor_file"
: >"$outer_ready"
while :; do
  if wait "$PROJECT_GUARD_SUPERVISOR_PID"; then
    local_status=0
  else
    local_status=$?
  fi
  if ! kill -0 "$PROJECT_GUARD_SUPERVISOR_PID" 2>/dev/null; then
    break
  fi
done
exit "$local_status"
EOF
  chmod 0700 -- "$group_child" "$group_outer"
  for group_mode in \
    outer-HUP outer-TERM outer-INT \
    inner-HUP inner-TERM inner-INT; do
    group_signal="${group_mode##*-}"
    rm -f -- \
      "$group_outer_ready" "$group_child_ready" \
      "$group_trap_started" "$group_repeated_signal" \
      "$group_observed" "$group_supervisor"
    setsid env --default-signal=HUP,INT,TERM "$group_outer" \
      "$TEST_SCRIPT_DIR/../run.sh" "$lock_file" "$group_child" \
      "$group_child_ready" "$group_trap_started" "$group_observed" \
      "$group_outer_ready" "$group_supervisor" "$group_repeated_signal" &
    group_outer_pid=$!
    for ((attempt = 0; attempt < 500; attempt++)); do
      [[ -e "$group_outer_ready" && -e "$group_child_ready" && \
        -e "$group_supervisor" ]] && break
      sleep 0.01
    done
    if [[ ! -e "$group_outer_ready" || ! -e "$group_child_ready" || \
      ! -e "$group_supervisor" ]]; then
      kill -TERM -- "-$group_outer_pid" 2>/dev/null || true
      wait "$group_outer_pid" 2>/dev/null || true
      printf 'isolated project guard did not publish %s readiness\n' "$group_mode" >&2
      return 1
    fi
    group_supervisor_pid="$(<"$group_supervisor")"
    [[ "$group_supervisor_pid" =~ ^[1-9][0-9]*$ ]] || return 1
    if [[ "$group_mode" == inner-* ]]; then
      group_target_pid="$group_supervisor_pid"
    else
      group_target_pid="$group_outer_pid"
    fi
    kill -s "$group_signal" -- "-$group_target_pid" || return $?
    for ((attempt = 0; attempt < 500; attempt++)); do
      [[ -e "$group_trap_started" ]] && break
      sleep 0.01
    done
    if [[ ! -e "$group_trap_started" ]]; then
      kill -TERM -- "-$group_outer_pid" 2>/dev/null || true
      wait "$group_outer_pid" 2>/dev/null || true
      printf 'process-group %s did not reach the guarded child\n' \
        "$group_mode" >&2
      return 1
    fi
    if flock --exclusive --nonblock "$lock_file" true; then
      wait "$group_outer_pid" 2>/dev/null || true
      printf 'process-group %s released the lock during child recovery\n' \
        "$group_mode" >&2
      return 1
    fi
    if [[ "$group_mode" == outer-TERM ]]; then
      kill -TERM -- "-$group_outer_pid" || return $?
      if flock --exclusive --nonblock "$lock_file" true; then
        wait "$group_outer_pid" 2>/dev/null || true
        printf 'repeated TERM released the lock during child recovery\n' >&2
        return 1
      fi
    fi
    if wait "$group_outer_pid"; then
      group_status=0
    else
      group_status=$?
    fi
    case "$group_signal" in
      HUP) expected_group_status=129 ;;
      INT) expected_group_status=130 ;;
      TERM) expected_group_status=143 ;;
      *) return 1 ;;
    esac
    [[ "$group_status" == "$expected_group_status" && \
      "$(<"$group_observed")" == "$group_signal:held-through-child-trap" && \
      ( "$group_mode" != outer-TERM || -e "$group_repeated_signal" ) ]] || {
      printf 'isolated project guard did not retain the lock through %s recovery\n' \
        "$group_mode" >&2
      return 1
    }
    flock --exclusive --nonblock "$lock_file" true || {
      printf 'isolated project guard retained the lock after %s recovery\n' \
        "$group_mode" >&2
      return 1
    }
  done

  cat >"$reset_wrapper" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
readonly inherited_ready="$1"
readonly release="$2"
readonly pass="$3"
: >"$inherited_ready"
while [[ ! -e "$release" ]]; do sleep 0.01; done
: >"$pass"
EOF
  chmod 0700 -- "$reset_wrapper"
  env --ignore-signal=HUP,INT,TERM \
    flock --exclusive --nonblock --close "$lock_file" \
      "$reset_wrapper" "$reset_ready" "$reset_release" "$reset_pass" \
      >/dev/null 2>&1 &
  reset_holder_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$reset_ready" ]] && break
    sleep 0.01
  done
  [[ -e "$reset_ready" ]] || {
    kill -KILL "$reset_holder_pid" 2>/dev/null || true
    wait "$reset_holder_pid" 2>/dev/null || true
    printf 'ignored-signal guard child did not publish readiness\n' >&2
    return 1
  }
  reset_children="$(<"/proc/$reset_holder_pid/task/$reset_holder_pid/children")" || \
    return $?
  read -r reset_child_pid reset_extra_child <<<"$reset_children"
  [[ "$reset_child_pid" =~ ^[1-9][0-9]*$ && \
    -z "$reset_extra_child" ]] || return 1
  if project_guard_child_signal_state \
    "$reset_child_pid" "$reset_holder_pid" TERM; then
    printf 'project guard treated an ignored Bash child as signal-ready\n' >&2
    return 1
  else
    reset_status=$?
  fi
  [[ "$reset_status" == 2 ]] || {
    printf 'project guard mistook an ignored Bash child for the env launch stage\n' >&2
    return 1
  }
  if (
    PROJECT_GUARD_SIGNAL_RESET_EXECUTABLE="$(readlink -f -- \
      "/proc/$reset_child_pid/exe")"
    project_guard_child_signal_state \
      "$reset_child_pid" "$reset_holder_pid" TERM
  ); then
    printf 'pre-reset guard child did not retain inherited SIG_IGN\n' >&2
    return 1
  else
    reset_status=$?
  fi
  [[ "$reset_status" == 1 ]] || return 1
  PROJECT_GUARD_SUPERVISOR_PID="$reset_holder_pid"
  PROJECT_GUARD_SUPERVISOR_START_TIME="$(project_guard_process_start_time \
    "$reset_holder_pid")" || return 1
  PROJECT_GUARD_FORWARDING_READY=true
  (
    PROJECT_GUARD_SIGNAL_RESET_EXECUTABLE="$(readlink -f -- \
      "/proc/$reset_child_pid/exe")"
    forward_project_guard_signal TERM
  ) &
  reset_forward_pid=$!
  for ((attempt = 0; attempt < 50; attempt++)); do
    kill -0 "$reset_forward_pid" 2>/dev/null || break
    sleep 0.01
  done
  if ! kill -0 "$reset_forward_pid" 2>/dev/null || \
    flock --exclusive --nonblock "$lock_file" true; then
    kill -KILL "$reset_holder_pid" "$reset_forward_pid" 2>/dev/null || true
    wait "$reset_holder_pid" "$reset_forward_pid" 2>/dev/null || true
    printf 'project guard discarded TERM or unlocked in the pre-reset window\n' >&2
    return 1
  fi
  for ((attempt = 0; attempt < 500; attempt++)); do
    kill -0 "$reset_forward_pid" 2>/dev/null || break
    sleep 0.01
  done
  if kill -0 "$reset_forward_pid" 2>/dev/null; then
    kill -KILL "$reset_holder_pid" "$reset_forward_pid" 2>/dev/null || true
    wait "$reset_holder_pid" "$reset_forward_pid" 2>/dev/null || true
    printf 'project guard signal forwarder exceeded its fixed retry bound\n' >&2
    return 1
  fi
  wait "$reset_forward_pid" || return $?
  : >"$reset_release"
  if wait "$reset_holder_pid"; then
    reset_status=0
  else
    reset_status=$?
  fi
  PROJECT_GUARD_SUPERVISOR_PID=""
  PROJECT_GUARD_SUPERVISOR_START_TIME=""
  PROJECT_GUARD_FORWARDING_READY=false
  [[ "$reset_status" == 137 && ! -e "$reset_pass" && \
    ! -e "/proc/$reset_child_pid" && \
    ! -e "/proc/$reset_holder_pid" ]] || {
    printf 'project guard discarded TERM before its child reset the signal\n' >&2
    return 1
  }
  flock --exclusive --nonblock "$lock_file" true || {
    printf 'project guard remained locked after the reset-race trap exited\n' >&2
    return 1
  }

  chmod 0644 -- "$lock_file"
  if assert_private_project_guard_lock "$lock_file"; then
    printf 'project guard accepted a permissive lock file\n' >&2
    return 1
  fi
  chmod 0600 -- "$lock_file"
  ln -- "$lock_file" "$guard_root/hardlink.lock"
  if assert_private_project_guard_lock "$lock_file"; then
    printf 'project guard accepted a multiply linked lock file\n' >&2
    return 1
  fi
  mkdir -m 0755 -- "$guard_root/permissive-directory"
  if assert_private_project_guard_directory "$guard_root/permissive-directory"; then
    printf 'project guard accepted a non-0700 parent directory\n' >&2
    return 1
  fi
}

test_project_guard_terminal_handoff_is_status_truthful() {
  local -r guard_root="$TEST_TMP_DIR/project-guard-terminal-handoff"
  local -r pre_ack_worker="$TEST_TMP_DIR/project-guard-pre-ack-worker"
  local -r pre_ack_guarded="$TEST_TMP_DIR/project-guard-pre-ack-guarded"
  local -r pre_ack_outer="$TEST_TMP_DIR/project-guard-pre-ack-outer"
  local -r pre_ack_lock="$TEST_TMP_DIR/project-guard-pre-ack.lock"
  local -r pre_ack_ready="$TEST_TMP_DIR/project-guard-pre-ack-ready"
  local -r pre_ack_release="$TEST_TMP_DIR/project-guard-pre-ack-release"
  local -r pre_ack_mutation="$TEST_TMP_DIR/project-guard-pre-ack-mutation"
  local -r pre_ack_supervisor="$TEST_TMP_DIR/project-guard-pre-ack-supervisor"
  local -r pre_ack_pending="$TEST_TMP_DIR/project-guard-pre-ack-pending"
  local -r pre_ack_status="$TEST_TMP_DIR/project-guard-pre-ack-status"
  local mode=""
  local control_dir=""
  local observed=""
  local release=""
  local worker_pid=""
  local pre_ack_outer_pid=""
  local pre_ack_supervisor_pid=""
  local worker_status=0
  local supervisor_start_time=""
  local handoff_definition=""
  local publication_definition=""
  local existence_line=""
  local validation_line=""
  local -i attempt=0

  mkdir -m 0700 -- "$guard_root"
  handoff_definition="$(declare -f complete_project_guard_terminal_handoff)" || \
    return 1
  publication_definition="$(declare -f publish_project_guard_control_file)" || \
    return 1
  existence_line="$(awk '/\[\[ -e "\$decision_file"/ { print NR; exit }' \
    <<<"$handoff_definition")"
  validation_line="$(awk '/project_guard_control_file_matches "\$decision_file" commit/ { print NR; exit }' \
    <<<"$handoff_definition")"
  [[ "$existence_line" =~ ^[1-9][0-9]*$ && \
    "$validation_line" =~ ^[1-9][0-9]*$ && \
    existence_line -lt validation_line && \
    "$publication_definition" != *project_guard_control_file_matches* ]] || {
    printf 'project guard handoff lost its atomic publication boundary\n' >&2
    return 1
  }

  cat >"$pre_ack_worker" <<'EOF'
#!/usr/bin/env bash
PROJECT_GUARD_PENDING_SIGNAL=""
trap record_project_guard_hup HUP
trap record_project_guard_int INT
trap record_project_guard_term TERM
set -Eeuo pipefail
source "$1"
PROJECT_GUARD_ROOT="$2"
PROJECT_GUARD_CONTROL_DIR="$3"
complete_project_guard_supervisor_identity_handoff
relay_pid="$BASHPID"
relay_start_time="$(read_project_guard_supervisor_identity \
  "$PROJECT_GUARD_CONTROL_DIR/supervisor" "$relay_pid")"
launch_signal=""
env --ignore-signal=HUP,INT,TERM \
  flock --exclusive --nonblock --close "$4" \
    env --default-signal=HUP,INT,TERM \
      "$5" "$1" "$PROJECT_GUARD_ROOT" "$PROJECT_GUARD_CONTROL_DIR" \
        "$relay_pid" "$6" &
holder_pid=$!
for ((attempt = 0; attempt < 500; attempt++)); do
  if [[ -e "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" ]]; then
    holder_start_time="$(read_project_guard_supervisor_launch \
      "$PROJECT_GUARD_CONTROL_DIR/supervisor-launched" \
      "$relay_pid" "$relay_start_time" "$holder_pid")"
    PROJECT_GUARD_SUPERVISOR_PID="$holder_pid"
    PROJECT_GUARD_SUPERVISOR_START_TIME="$holder_start_time"
    PROJECT_GUARD_FORWARDING_READY=true
    break
  fi
  sleep 0.01 || true
done
[[ "$PROJECT_GUARD_FORWARDING_READY" == true ]]
if [[ -n "$PROJECT_GUARD_PENDING_SIGNAL" ]]; then
  launch_signal="$PROJECT_GUARD_PENDING_SIGNAL"
  forward_project_guard_signal "$PROJECT_GUARD_PENDING_SIGNAL"
fi
[[ -z "$PROJECT_GUARD_PENDING_SIGNAL" ]]
if [[ -z "$launch_signal" ]]; then
  publish_project_guard_supervisor_launch_acceptance \
    "$relay_pid" "$relay_start_time" "$holder_pid" "$holder_start_time"
fi
if wait "$holder_pid"; then
  exit 0
else
  exit $?
fi
EOF
  cat >"$pre_ack_guarded" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$1"
PROJECT_GUARD_ROOT="$2"
PROJECT_GUARD_CONTROL_DIR="$3"
readonly relay_pid="$4"
readonly observed="$5"
handle_pre_ack_term() {
  printf 'canonical-130\n' >"$observed"
  exit 130
}
trap handle_pre_ack_term TERM
publish_project_guard_supervisor_launched "$relay_pid" "$PPID"
wait_for_project_guard_supervisor_launch_acceptance "$relay_pid" "$PPID"
while :; do sleep 0.01; done
EOF
  cat >"$pre_ack_outer" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$1"
PROJECT_GUARD_ROOT="$2"
PROJECT_GUARD_CONTROL_DIR="$3"
readonly worker_script="$4"
readonly guarded_script="$5"
readonly lock_file="$6"
readonly ready="$7"
readonly release="$8"
readonly mutation="$9"
readonly supervisor_file="${10}"
readonly pending_file="${11}"
readonly status_file="${12}"
local_status=0
PROJECT_GUARD_PENDING_SIGNAL=""
PROJECT_GUARD_FORWARDING_READY=false
forward_pre_ack_hup() { forward_project_guard_signal HUP || true; }
forward_pre_ack_int() { forward_project_guard_signal INT || true; }
forward_pre_ack_term() { forward_project_guard_signal TERM || true; }
trap forward_pre_ack_hup HUP
trap forward_pre_ack_int INT
trap forward_pre_ack_term TERM
set -m
: | env --default-signal=HUP,INT,TERM setsid \
  "$worker_script" "$1" "$PROJECT_GUARD_ROOT" \
    "$PROJECT_GUARD_CONTROL_DIR" "$lock_file" "$guarded_script" "$mutation" &
PROJECT_GUARD_SUPERVISOR_PID=$!
set +m
for ((attempt = 0; attempt < 500; attempt++)); do
  [[ -e "$PROJECT_GUARD_CONTROL_DIR/supervisor" ]] && break
  sleep 0.01 || true
done
PROJECT_GUARD_SUPERVISOR_START_TIME="$({
  read_project_guard_supervisor_identity \
    "$PROJECT_GUARD_CONTROL_DIR/supervisor" \
    "$PROJECT_GUARD_SUPERVISOR_PID"
})"
printf '%s\n' "$PROJECT_GUARD_SUPERVISOR_PID" >"$supervisor_file"
: >"$ready"
while [[ ! -e "$release" ]]; do sleep 0.01 || true; done
publish_project_guard_supervisor_acceptance \
  "$PROJECT_GUARD_SUPERVISOR_PID" \
  "$PROJECT_GUARD_SUPERVISOR_START_TIME"
PROJECT_GUARD_FORWARDING_READY=true
if wait "$PROJECT_GUARD_SUPERVISOR_PID"; then
  local_status=0
else
  local_status=$?
fi
printf '%s\n' "$PROJECT_GUARD_PENDING_SIGNAL" >"$pending_file"
printf '%s\n' "$local_status" >"$status_file"
EOF
  chmod 0700 -- "$pre_ack_worker" "$pre_ack_guarded" "$pre_ack_outer"
  (umask 077; : >"$pre_ack_lock")
  control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
    return 1
  setsid "$pre_ack_outer" "$TEST_SCRIPT_DIR/../run.sh" "$guard_root" \
    "$control_dir" "$pre_ack_worker" "$pre_ack_guarded" "$pre_ack_lock" \
    "$pre_ack_ready" "$pre_ack_release" "$pre_ack_mutation" \
    "$pre_ack_supervisor" "$pre_ack_pending" "$pre_ack_status" &
  pre_ack_outer_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$pre_ack_ready" && -e "$pre_ack_supervisor" ]] && break
    sleep 0.01
  done
  if [[ ! -e "$pre_ack_ready" || ! -e "$pre_ack_supervisor" ]]; then
    kill -KILL -- "-$pre_ack_outer_pid" 2>/dev/null || true
    wait "$pre_ack_outer_pid" 2>/dev/null || true
    printf 'isolated pre-ack supervisor did not publish readiness\n' >&2
    return 1
  fi
  pre_ack_supervisor_pid="$(<"$pre_ack_supervisor")"
  [[ "$pre_ack_supervisor_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -TERM -- "-$pre_ack_supervisor_pid" || return $?
  sleep 0.1
  [[ -e "/proc/$pre_ack_supervisor_pid" && \
    ! -e "$pre_ack_mutation" ]] || {
    : >"$pre_ack_release"
    wait "$pre_ack_outer_pid" 2>/dev/null || true
    printf 'process-group TERM killed or advanced the pre-ack supervisor\n' >&2
    return 1
  }
  : >"$pre_ack_release"
  wait "$pre_ack_outer_pid" || return $?
  [[ "$(<"$pre_ack_mutation")" == canonical-130 && \
    "$(<"$pre_ack_pending")" == "" && \
    "$(<"$pre_ack_status")" == 130 ]] || {
    printf 'isolated pre-ack TERM did not reach the guarded worker canonically\n' >&2
    return 1
  }
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    remove_project_guard_control_directory "$control_dir"
  ) || return $?

  control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
    return 1
  observed="$guard_root/supervisor-accepted-observed"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    complete_project_guard_supervisor_identity_handoff
    : >"$observed"
  ) &
  worker_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$control_dir/supervisor" ]] && break
    sleep 0.01
  done
  [[ -e "$control_dir/supervisor" ]] || return 1
  supervisor_start_time="$({
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    read_project_guard_supervisor_identity \
      "$control_dir/supervisor" "$worker_pid"
  })" || return 1
  [[ "$supervisor_start_time" =~ ^[0-9]+$ ]] || return 1
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    PROJECT_GUARD_SUPERVISOR_PID="$worker_pid"
    PROJECT_GUARD_SUPERVISOR_START_TIME="$supervisor_start_time"
    PROJECT_GUARD_FORWARDING_READY=false
    PROJECT_GUARD_PENDING_SIGNAL=""
    forward_project_guard_signal TERM
    [[ "$PROJECT_GUARD_PENDING_SIGNAL" == TERM ]] || exit 1
    project_guard_supervisor_is_running \
      "$worker_pid" "$supervisor_start_time" || exit 1
    publish_project_guard_supervisor_acceptance \
      "$worker_pid" "$supervisor_start_time"
  ) || return $?
  wait "$worker_pid" || return $?
  [[ -e "$observed" ]] || {
    printf 'project guard supervisor proceeded without a valid parent acceptance\n' >&2
    return 1
  }
  rm -f -- "$observed"
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    read_project_guard_supervisor_identity \
      "$control_dir/supervisor" "$((worker_pid + 1))"
  ) >/dev/null 2>&1; then
    printf 'project guard accepted a supervisor token for another PID\n' >&2
    return 1
  fi
  chmod 0644 -- "$control_dir/supervisor"
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    read_project_guard_supervisor_identity \
      "$control_dir/supervisor" "$worker_pid"
  ) >/dev/null 2>&1; then
    printf 'project guard accepted a permissive supervisor token\n' >&2
    return 1
  fi
  chmod 0600 -- "$control_dir/supervisor"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    remove_project_guard_control_directory "$control_dir"
  ) || return $?

  control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
    return 1
  observed="$guard_root/unaccepted-supervisor-mutation"
  release="$guard_root/release-delayed-supervisor"
  rm -f -- "$observed" "$release"
  (
    while [[ ! -e "$release" ]]; do sleep 0.01; done
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    sleep() { :; }
    complete_project_guard_supervisor_identity_handoff
    : >"$observed"
  ) &
  worker_pid=$!
  for ((attempt = 0; attempt < 20; attempt++)); do
    [[ ! -e "$control_dir/supervisor" && \
      ! -L "$control_dir/supervisor" ]] || return 1
    sleep 0.01
  done
  : >"$release"
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  [[ "$worker_status" != 0 && ! -e "$observed" && \
    -f "$control_dir/supervisor" && \
    ! -e "$control_dir/supervisor-accepted" && \
    ! -L "$control_dir/supervisor-accepted" ]] || {
    printf 'delayed supervisor proceeded after the parent abandoned its handshake\n' >&2
    return 1
  }
  rm -f -- "$release"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    remove_project_guard_control_directory "$control_dir"
  ) || return $?

  control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
    return 1
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    project_guard_control_file_matches() { return 97; }
    publish_project_guard_control_file "$control_dir/decision" commit
  ) || {
    printf 'project guard treated post-rename readback as publication failure\n' >&2
    return 1
  }
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    project_guard_control_file_matches "$control_dir/decision" commit
    remove_project_guard_control_directory "$control_dir"
  ) || return $?

  control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
    return 1
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    decision_checks=0
    eval "$(declare -f project_guard_control_file_matches | \
      sed '1s/^project_guard_control_file_matches /project_guard_control_file_matches_original /')"
    project_guard_control_file_matches() {
      if [[ "$1" == "$PROJECT_GUARD_CONTROL_DIR/decision" ]]; then
        ((decision_checks += 1))
        if ((decision_checks == 3)) && [[ ! -e "$1" && ! -L "$1" ]]; then
          printf 'commit\n' >"$PROJECT_GUARD_CONTROL_DIR/race-publication"
          chmod 0600 -- "$PROJECT_GUARD_CONTROL_DIR/race-publication"
          mv --no-target-directory -- \
            "$PROJECT_GUARD_CONTROL_DIR/race-publication" "$1"
          return 1
        fi
      fi
      project_guard_control_file_matches_original "$@"
    }
    sleep() {
      : "$@"
      if [[ ! -e "$PROJECT_GUARD_CONTROL_DIR/decision" && \
        ! -L "$PROJECT_GUARD_CONTROL_DIR/decision" ]]; then
        printf 'commit\n' >"$PROJECT_GUARD_CONTROL_DIR/race-publication"
        chmod 0600 -- "$PROJECT_GUARD_CONTROL_DIR/race-publication"
        mv --no-target-directory -- \
          "$PROJECT_GUARD_CONTROL_DIR/race-publication" \
          "$PROJECT_GUARD_CONTROL_DIR/decision"
      fi
    }
    complete_project_guard_terminal_handoff
  ) || {
    printf 'project guard rejected a decision at the existence boundary\n' >&2
    return 1
  }
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    remove_project_guard_control_directory "$control_dir"
  ) || return $?

  for mode in commit HUP TERM; do
    control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
      return 1
    observed="$control_dir/observed"
    (
      PROJECT_GUARD_ROOT="$guard_root"
      PROJECT_GUARD_CONTROL_DIR="$control_dir"
      PROJECT_GUARD_HANDOFF_SIGNAL_STATUS=0
      complete_project_guard_terminal_handoff
      printf '%s\n' "$PROJECT_GUARD_HANDOFF_SIGNAL_STATUS" >"$observed"
    ) &
    worker_pid=$!
    for ((attempt = 0; attempt < 500; attempt++)); do
      if (
        PROJECT_GUARD_ROOT="$guard_root"
        PROJECT_GUARD_CONTROL_DIR="$control_dir"
        project_guard_control_file_matches "$control_dir/ready" ready
      ); then
        break
      fi
      sleep 0.01
    done
    if ! (
      PROJECT_GUARD_ROOT="$guard_root"
      PROJECT_GUARD_CONTROL_DIR="$control_dir"
      project_guard_control_file_matches "$control_dir/ready" ready
    ); then
      kill -KILL "$worker_pid" 2>/dev/null || true
      wait "$worker_pid" 2>/dev/null || true
      printf 'project guard worker did not publish terminal readiness\n' >&2
      return 1
    fi
    (
      PROJECT_GUARD_ROOT="$guard_root"
      PROJECT_GUARD_CONTROL_DIR="$control_dir"
      PROJECT_GUARD_PENDING_SIGNAL=""
      if [[ "$mode" != commit ]]; then
        PROJECT_GUARD_PENDING_SIGNAL="$mode"
      fi
      publish_project_guard_terminal_decision
    ) || return $?
    wait "$worker_pid" || return $?
    case "$mode" in
      commit) [[ "$(<"$observed")" == 0 ]] || return 1 ;;
      HUP) [[ "$(<"$observed")" == 129 ]] || return 1 ;;
      TERM) [[ "$(<"$observed")" == 130 ]] || return 1 ;;
      *) return 1 ;;
    esac
    rm -f -- "$observed"
    (
      PROJECT_GUARD_ROOT="$guard_root"
      PROJECT_GUARD_CONTROL_DIR="$control_dir"
      remove_project_guard_control_directory "$control_dir"
    ) || return $?
  done

  control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
    return 1
  observed="$guard_root/timeout-observed"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    if complete_project_guard_terminal_handoff; then
      printf 'accepted\n' >"$observed"
    else
      printf 'rejected\n' >"$observed"
    fi
  ) &
  worker_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$control_dir/ready" ]] && break
    sleep 0.01
  done
  [[ -e "$control_dir/ready" ]] || return 1
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    publish_project_guard_control_file "$control_dir/decision" corrupt
  ) || return $?
  wait "$worker_pid" || return $?
  [[ "$(<"$observed")" == rejected ]] || {
    printf 'project guard accepted a malformed terminal decision\n' >&2
    return 1
  }
  rm -f -- "$observed" "$control_dir/decision"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    remove_project_guard_control_directory "$control_dir"
  )

  control_dir="$(mktemp -d "$guard_root/.terminal-handoff.XXXXXX")" || \
    return 1
  observed="$guard_root/timeout-observed"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    sleep() { :; }
    if complete_project_guard_terminal_handoff; then
      printf 'accepted\n' >"$observed"
    else
      printf 'timed-out\n' >"$observed"
    fi
  ) || return $?
  [[ "$(<"$observed")" == timed-out && \
    ! -e "$control_dir" && ! -L "$control_dir" ]] || {
    printf 'project guard accepted or retained a missing terminal decision\n' >&2
    return 1
  }
  rm -f -- "$observed"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_GUARD_CONTROL_DIR="$control_dir"
    remove_project_guard_control_directory "$control_dir"
  )
}

test_project_guard_terminal_handoff_wraps_real_runner() {
  local -r fake_bin="$TEST_TMP_DIR/project-guard-runner-bin"
  local -r docker_log="$TEST_TMP_DIR/project-guard-runner-docker.log"
  local -r block_ready="$TEST_TMP_DIR/project-guard-runner-block-ready"
  local -r block_release="$TEST_TMP_DIR/project-guard-runner-block-release"
  local -r failed_launch_lock="$TEST_TMP_DIR/project-guard-failed-launch.lock"
  local -r failed_launch_ready="$TEST_TMP_DIR/project-guard-failed-launch-ready"
  local -r failed_launch_release="$TEST_TMP_DIR/project-guard-failed-launch-release"
  local -r failed_launch_status="$TEST_TMP_DIR/project-guard-failed-launch-status"
  local -r failed_launch_pending="$TEST_TMP_DIR/project-guard-failed-launch-pending"
  local -r failed_launch_observed="$TEST_TMP_DIR/project-guard-failed-launch-observed"
  local -r early_exit_lock="$TEST_TMP_DIR/project-guard-early-exit.lock"
  local -r early_wait_ready="$TEST_TMP_DIR/project-guard-early-wait.ready"
  local -r early_wait_release="$TEST_TMP_DIR/project-guard-early-wait.release"
  local -r early_wait_status_file="$TEST_TMP_DIR/project-guard-early-wait.status"
  local -r early_wait_pending_file="$TEST_TMP_DIR/project-guard-early-wait.pending"
  local -r early_wait_observed="$TEST_TMP_DIR/project-guard-early-wait.observed"
  local -r early_wait_escaped="$TEST_TMP_DIR/project-guard-early-wait.escaped"
  local -r malformed_launch_project="obi-apache-java-https-handoff-failed-$BASHPID"
  local -r malformed_launch_lock="/tmp/obi-apache-java-https-project-guard-$EUID/$malformed_launch_project.lock"
  local -r malformed_launch_status="$TEST_TMP_DIR/project-guard-malformed-launch-status"
  local -r pretrap_project="obi-apache-java-https-handoff-pretrap-$BASHPID"
  local -r pretrap_lock="/tmp/obi-apache-java-https-project-guard-$EUID/$pretrap_project.lock"
  local -r pretrap_ready="$TEST_TMP_DIR/project-guard-pretrap-ready"
  local -r pretrap_direct_ready="$TEST_TMP_DIR/project-guard-pretrap-direct-ready"
  local -r pretrap_runner="$(cd -- "$TEST_SCRIPT_DIR/.." && pwd -P)/run.sh"
  local -r project="obi-apache-java-https-handoff-$BASHPID"
  local -r lock_file="/tmp/obi-apache-java-https-project-guard-$EUID/$project.lock"
  local failed_launch_waiter=""
  local early_exit_holder=""
  local early_exit_state=""
  local early_exit_status=0
  local early_terminal_code=""
  local early_terminal_holder=""
  local early_terminal_probe=""
  local early_terminal_status_file=""
  local early_terminal_pending_file=""
  local early_wait_sender=""
  local failed_launch_control=""
  local exit_race_control=""
  local exit_race_lock=""
  local exit_race_ready=""
  local exit_race_release=""
  local exit_race_status=""
  local exit_race_waits=""
  local exit_race_holder_file=""
  local exit_race_probe=""
  local stale_wait_control=""
  local stale_wait_lock=""
  local stale_wait_release=""
  local stale_wait_holder=""
  local stale_wait_holder_pid=""
  local stale_wait_relay_pid=""
  local stale_wait_relay_start=""
  local stale_wait_holder_start=""
  local stale_wait_status=0
  local holder_status_original=""
  local holder_status_mutation=""
  local accepted_control=""
  local accepted_lock="$TEST_TMP_DIR/project-guard-accepted.lock"
  local accepted_ready="$TEST_TMP_DIR/project-guard-accepted.ready"
  local accepted_release="$TEST_TMP_DIR/project-guard-accepted.release"
  local accepted_pids="$TEST_TMP_DIR/project-guard-accepted.pids"
  local accepted_holder_file="$TEST_TMP_DIR/project-guard-accepted.holder"
  local accepted_status="$TEST_TMP_DIR/project-guard-accepted.status"
  local accepted_probe=""
  local accepted_holder=""
  local accepted_timeout=""
  local accepted_leaf=""
  local accepted_timeout_start=""
  local accepted_leaf_start=""
  local accepted_timeout_stat=""
  local accepted_timeout_fields=""
  local accepted_timeout_pgid=""
  local accepted_extra=""
  local accepted_missing_control=""
  local accepted_missing_lock="$TEST_TMP_DIR/project-guard-accepted-missing.lock"
  local accepted_missing_release="$TEST_TMP_DIR/project-guard-accepted-missing.release"
  local accepted_missing_holder=""
  local accepted_missing_start=""
  local accepted_missing_status=0
  local accepted_missing_mode=""
  local protocol_latch_control=""
  local protocol_latch_lock="$TEST_TMP_DIR/project-guard-protocol-latch.lock"
  local protocol_latch_release="$TEST_TMP_DIR/project-guard-protocol-latch.release"
  local protocol_latch_read_count="$TEST_TMP_DIR/project-guard-protocol-latch.read-count"
  local protocol_latch_live_count="$TEST_TMP_DIR/project-guard-protocol-latch.live-count"
  local protocol_latch_status=0
  local failed_signal=""
  local malformed_launch_control=""
  local malformed_launch_relay=""
  local relay_definition=""
  local accepted_definition=""
  local demo_definition=""
  local accepted_latch_line=""
  local accepted_forward_line=""
  local accepted_publish_line=""
  local demo_guard_line=""
  local demo_recursive_line=""
  local demo_dependency_lines=""
  local demo_order_file="$TEST_TMP_DIR/project-guard-recursive-dependency-order"
  local reap_calls=""
  local real_bash=""
  local runner_pid=""
  local runner_status=0
  local failed_launch_escaped=false
  local malformed_launch_escaped=false
  local -i attempt=0
  local -i exit_race_poll=0

  mkdir -p -- "$fake_bin"
  cat >"$fake_bin/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"$PROJECT_GUARD_TEST_DOCKER_LOG"
if [[ "${1:-}" == info ]]; then
  printf '"project-guard-test-daemon"\n'
fi
if [[ -n "${PROJECT_GUARD_TEST_BLOCK_READY:-}" && "$*" == *" down "* ]]; then
  : >"$PROJECT_GUARD_TEST_BLOCK_READY"
  while [[ ! -e "$PROJECT_GUARD_TEST_BLOCK_RELEASE" ]]; do sleep 0.01; done
fi
EOF
  chmod 0700 -- "$fake_bin/docker"
  if ! COMPOSE_PROJECT_NAME="$project" \
    PROJECT_GUARD_TEST_DOCKER_LOG="$docker_log" \
    PATH="$fake_bin:$PATH" \
    bash "$TEST_SCRIPT_DIR/../run.sh" --cleanup-only; then
    printf 'real runner failed its project guard terminal handoff\n' >&2
    return 1
  fi
  [[ -s "$docker_log" && -f "$lock_file" ]] || {
    printf 'real runner skipped guarded cleanup-only execution\n' >&2
    return 1
  }
  flock --exclusive --nonblock "$lock_file" true || {
    printf 'real runner retained the project lock after terminal handoff\n' >&2
    return 1
  }
  COMPOSE_PROJECT_NAME="$project" \
    PROJECT_GUARD_TEST_DOCKER_LOG="$docker_log" \
    PROJECT_GUARD_TEST_BLOCK_READY="$block_ready" \
    PROJECT_GUARD_TEST_BLOCK_RELEASE="$block_release" \
    PATH="$fake_bin:$PATH" \
    bash "$TEST_SCRIPT_DIR/../run.sh" --cleanup-only &
  runner_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$block_ready" ]] && break
    sleep 0.01
  done
  if [[ ! -e "$block_ready" ]]; then
    kill -KILL "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true
    printf 'real guarded runner did not reach its blocking mutation\n' >&2
    return 1
  fi
  kill -TERM "$runner_pid" || return $?
  : >"$block_release"
  if wait "$runner_pid"; then
    runner_status=0
  else
    runner_status=$?
  fi
  [[ "$runner_status" == 130 ]] || {
    printf 'real guarded runner lost TERM at terminal handoff: %s\n' \
      "$runner_status" >&2
    return 1
  }
  flock --exclusive --nonblock "$lock_file" true || {
    printf 'interrupted runner retained the project lock after handoff\n' >&2
    return 1
  }
  rm -f -- "$lock_file"

  relay_definition="$(declare -f run_project_guard_relay)" || return 1
  reap_calls="$(grep -F -c \
    'wait_for_project_guard_holder "$holder_pid"' \
    <<<"$relay_definition")" || return 1
  [[ "$reap_calls" == 2 ]] || {
    printf 'project guard launch failure bypassed its interruption-safe reap\n' >&2
    return 1
  }
  accepted_definition="$(awk '
    /PROJECT_GUARD_SUPERVISOR_START_TIME="\$holder_start_time"/ { accepted = 1 }
    accepted { print }
    /"\$launch_accepted"/ { exit }
  ' <<<"$relay_definition")" || return 1
  accepted_latch_line="$(awk \
    '/launch_signal="\$PROJECT_GUARD_PENDING_SIGNAL"/ { print NR; exit }' \
    <<<"$accepted_definition")"
  accepted_forward_line="$(awk \
    '/forward_project_guard_signal "\$PROJECT_GUARD_PENDING_SIGNAL"/ { print NR; exit }' \
    <<<"$accepted_definition")"
  accepted_publish_line="$(awk \
    '/publish_project_guard_supervisor_launch_acceptance/ { print NR; exit }' \
    <<<"$accepted_definition")"
  [[ "$accepted_definition" == *'publish_project_guard_supervisor_launch_acceptance'* && \
    "$accepted_definition" == *'launch_accepted=true'* && \
    "$accepted_definition" == *'"$launch_accepted"'* && \
    "$accepted_definition" != *'PROJECT_GUARD_HANDOFF_MAX_ATTEMPTS'* && \
    "$accepted_definition" != *'kill -KILL -- "-$holder_pid"'* && \
    "$accepted_latch_line" =~ ^[1-9][0-9]*$ && \
    "$accepted_forward_line" =~ ^[1-9][0-9]*$ && \
    "$accepted_publish_line" =~ ^[1-9][0-9]*$ && \
    accepted_latch_line -lt accepted_forward_line && \
    accepted_forward_line -lt accepted_publish_line ]] || {
    printf 'accepted project guard launch reused the pre-launch kill boundary\n' >&2
    return 1
  }
  demo_definition="$(declare -f run_demo)" || return 1
  demo_guard_line="$(awk '/enter_project_guard "\$@"/ { print NR; exit }' \
    <<<"$demo_definition")"
  demo_recursive_line="$(awk \
    '/if \[\[ "\$recursive_guard_launch" == true \]\]/ { print NR; exit }' \
    <<<"$demo_definition")"
  demo_dependency_lines="$(awk '/^[[:space:]]*check_dependencies;?$/ { print NR }' \
    <<<"$demo_definition")"
  [[ "$demo_definition" == *'recursive_guard_launch=true'* && \
    "$demo_definition" == *'enter_project_guard "$@"'* && \
    "$demo_definition" == *'if [[ "$recursive_guard_launch" == true ]]'* && \
    "$demo_guard_line" =~ ^[1-9][0-9]*$ && \
    "$demo_recursive_line" =~ ^[1-9][0-9]*$ && \
    "$(wc -l <<<"$demo_dependency_lines")" == 2 && \
    "$(tail -n 1 <<<"$demo_dependency_lines")" -gt "$demo_guard_line" && \
    "$demo_recursive_line" -gt "$demo_guard_line" ]] || {
    printf 'recursive dependency checks no longer follow guard acceptance\n' >&2
    return 1
  }
  (
    OBI_DEMO_PROJECT_GUARD_ACTIVE=1
    CLEANUP_ONLY=true
    install_traps() { :; }
    parse_args() { :; }
    enter_project_guard() { printf 'guard\n' >>"$demo_order_file"; }
    check_dependencies() { printf 'dependencies\n' >>"$demo_order_file"; }
    cleanup_only() { printf 'cleanup\n' >>"$demo_order_file"; }
    run_demo --cleanup-only
  ) || return $?
  [[ "$(<"$demo_order_file")" == $'guard\ndependencies\ncleanup' ]] || {
    printf 'recursive runner did not check dependencies after guard acceptance\n' >&2
    return 1
  }
  (umask 077; : >"$early_exit_lock")
  for failed_signal in HUP INT TERM; do
    bash -c 'exit 75' &
    early_exit_holder=$!
    while [[ -r "/proc/$early_exit_holder/stat" ]]; do
      read -r early_exit_state _ <<<"$(project_guard_process_stat_identity \
        "$early_exit_holder" 2>/dev/null || true)"
      [[ "$early_exit_state" == Z || "$early_exit_state" == X ]] && break
      sleep 0.001
    done
    PROJECT_GUARD_PENDING_SIGNAL="$failed_signal"
    PROJECT_GUARD_FORWARDING_READY=false
    if wait_for_project_guard_holder \
      "$early_exit_holder" "$early_exit_lock" \
      "$BASHPID" "$(project_guard_process_start_time "$BASHPID")" \
      "" false; then
      early_exit_status=0
    else
      early_exit_status=$?
    fi
    [[ "$early_exit_status" == 75 && \
      "$PROJECT_GUARD_PENDING_SIGNAL" == "$failed_signal" ]] || {
      printf 'early guard exit lost status under pending %s: %s\n' \
        "$failed_signal" "$early_exit_status" >&2
      return 1
    }
  done
  for early_terminal_code in 0 255; do
    early_terminal_status_file="$TEST_TMP_DIR/project-guard-early-$early_terminal_code.status"
    early_terminal_pending_file="$TEST_TMP_DIR/project-guard-early-$early_terminal_code.pending"
    (
      PROJECT_GUARD_PENDING_SIGNAL=TERM
      PROJECT_GUARD_FORWARDING_READY=false
      bash -c 'exit "$1"' bash "$early_terminal_code" &
      early_terminal_holder=$!
      while [[ -r "/proc/$early_terminal_holder/stat" ]]; do
        read -r early_exit_state _ <<<"$(project_guard_process_stat_identity \
          "$early_terminal_holder" 2>/dev/null || true)"
        [[ "$early_exit_state" == Z || "$early_exit_state" == X ]] && break
        sleep 0.001
      done
      if wait_for_project_guard_holder \
        "$early_terminal_holder" "$early_exit_lock" \
        "$BASHPID" "$(project_guard_process_start_time "$BASHPID")" \
        "" false; then
        early_exit_status=0
      else
        early_exit_status=$?
      fi
      printf '%s\n' "$early_exit_status" >"$early_terminal_status_file"
      printf '%s\n' "$PROJECT_GUARD_PENDING_SIGNAL" \
        >"$early_terminal_pending_file"
    ) &
    early_terminal_probe=$!
    for ((attempt = 0; attempt < 300; attempt++)); do
      kill -0 "$early_terminal_probe" 2>/dev/null || break
      sleep 0.01
    done
    if kill -0 "$early_terminal_probe" 2>/dev/null; then
      kill -KILL "$early_terminal_probe" 2>/dev/null || true
      wait "$early_terminal_probe" 2>/dev/null || true
      printf 'project guard livelocked on no-anchor status %s\n' \
        "$early_terminal_code" >&2
      return 1
    fi
    wait "$early_terminal_probe" || return $?
    [[ "$(<"$early_terminal_status_file")" == 1 && \
      "$(<"$early_terminal_pending_file")" == TERM ]] || {
      printf 'project guard trusted ambiguous no-anchor status %s: %s\n' \
        "$early_terminal_code" "$(<"$early_terminal_status_file")" >&2
      return 1
    }
    rm -f -- "$early_terminal_status_file" "$early_terminal_pending_file"
  done
  PROJECT_GUARD_PENDING_SIGNAL=""
  (
    relay_pid="$BASHPID"
    relay_start_time="$(project_guard_process_start_time "$relay_pid")"
    PROJECT_GUARD_PENDING_SIGNAL=""
    PROJECT_GUARD_FORWARDING_READY=false
    record_early_wait_term() {
      printf 'TERM\n' >"$early_wait_observed"
      record_project_guard_pending_signal TERM || true
    }
    trap record_early_wait_term TERM
    flock --exclusive --nonblock --close "$early_exit_lock" \
      bash -c '
        : >"$1"
        while [[ ! -e "$2" ]]; do sleep 0.01; done
        exit 41
      ' bash "$early_wait_ready" "$early_wait_release" &
    early_exit_holder=$!
    (
      while [[ ! -e "$early_wait_ready" ]]; do sleep 0.001; done
      kill -TERM "$relay_pid"
      sleep 0.005
      kill -TERM "$relay_pid"
      sleep 0.1
      if flock --exclusive --nonblock "$early_exit_lock" true; then
        : >"$early_wait_escaped"
      fi
      : >"$early_wait_release"
    ) &
    early_wait_sender=$!
    if wait_for_project_guard_holder \
      "$early_exit_holder" "$early_exit_lock" \
      "$relay_pid" "$relay_start_time" "" false; then
      early_exit_status=0
    else
      early_exit_status=$?
    fi
    wait "$early_wait_sender" 2>/dev/null || true
    printf '%s\n' "$early_exit_status" >"$early_wait_status_file"
    printf '%s\n' "$PROJECT_GUARD_PENDING_SIGNAL" \
      >"$early_wait_pending_file"
  ) || {
    printf 'project guard interrupted-wait fixture failed before observation\n' >&2
    return 1
  }
  [[ "$(<"$early_wait_status_file")" == 41 && \
    "$(<"$early_wait_observed")" == TERM && \
    ( -z "$(<"$early_wait_pending_file")" || \
      "$(<"$early_wait_pending_file")" == TERM ) && \
    ! -e "$early_wait_escaped" ]] || {
    printf 'project guard confused an interrupted wait with holder exit status=%s observed=%s pending=%s escaped=%s\n' \
      "$(<"$early_wait_status_file")" \
      "$(<"$early_wait_observed")" \
      "$(<"$early_wait_pending_file")" \
      "$([[ -e "$early_wait_escaped" ]] && printf yes || printf no)" >&2
    return 1
  }
  flock --exclusive --nonblock "$early_exit_lock" true || {
    printf 'project guard retained its lock after interrupted-wait reap\n' >&2
    return 1
  }
  rm -f -- "$early_exit_lock"
  rm -f -- "$early_wait_ready" "$early_wait_release" \
    "$early_wait_status_file" "$early_wait_pending_file" \
    "$early_wait_observed" "$early_wait_escaped"
  for failed_signal in HUP INT TERM; do
    rm -f -- "$failed_launch_ready" "$failed_launch_release" \
      "$failed_launch_status" "$failed_launch_pending" \
      "$failed_launch_observed"
    failed_launch_escaped=false
    (umask 077; : >"$failed_launch_lock")
    failed_launch_control="$(mktemp -d \
      "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
      return 1
    (
      relay_pid="$BASHPID"
      relay_start_time="$(project_guard_process_start_time "$relay_pid")"
      PROJECT_GUARD_CONTROL_DIR="$failed_launch_control"
      publish_project_guard_control_file \
        "$PROJECT_GUARD_CONTROL_DIR/supervisor" \
        "supervisor:$relay_pid:$relay_start_time"
      publish_project_guard_control_file \
        "$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted" \
        "supervisor-accepted:$relay_pid:$relay_start_time"
      PROJECT_GUARD_PENDING_SIGNAL=""
      PROJECT_GUARD_TEST_OBSERVED_SIGNAL=""
      PROJECT_GUARD_FORWARDING_READY=false
      record_failed_launch_signal() {
        local -r signal_name="$1"

        [[ -n "$PROJECT_GUARD_TEST_OBSERVED_SIGNAL" ]] || \
          PROJECT_GUARD_TEST_OBSERVED_SIGNAL="$signal_name"
        printf '%s\n' "$PROJECT_GUARD_TEST_OBSERVED_SIGNAL" \
          >"$failed_launch_observed"
        record_project_guard_pending_signal "$signal_name" || true
      }
      record_failed_launch_hup() { record_failed_launch_signal HUP; }
      record_failed_launch_int() { record_failed_launch_signal INT; }
      record_failed_launch_term() { record_failed_launch_signal TERM; }
      trap record_failed_launch_hup HUP
      trap record_failed_launch_int INT
      trap record_failed_launch_term TERM
      env --ignore-signal=HUP,INT,TERM \
        flock --exclusive --nonblock --close "$failed_launch_lock" \
          bash -c '
            set -Eeuo pipefail
            : >"$1"
            while [[ ! -e "$2" ]]; do sleep 0.01; done
            exit 41
          ' bash "$failed_launch_ready" "$failed_launch_release" &
      holder_pid=$!
      holder_start_time="$(project_guard_process_start_time "$holder_pid")"
      PROJECT_GUARD_STATUS_RELAY_PID="$relay_pid"
      PROJECT_GUARD_STATUS_RELAY_START_TIME="$relay_start_time"
      PROJECT_GUARD_STATUS_HOLDER_PID="$holder_pid"
      PROJECT_GUARD_STATUS_HOLDER_START_TIME="$holder_start_time"
      publish_project_guard_holder_status 41
      if wait_for_project_guard_holder \
        "$holder_pid" "$failed_launch_lock" \
        "$relay_pid" "$relay_start_time" "$holder_start_time"; then
        holder_status=0
      else
        holder_status=$?
      fi
      printf '%s\n' "$holder_status" >"$failed_launch_status"
      printf '%s\n' "$PROJECT_GUARD_PENDING_SIGNAL" \
        >"$failed_launch_pending"
    ) &
    failed_launch_waiter=$!
    for ((attempt = 0; attempt < 500; attempt++)); do
      [[ -e "$failed_launch_ready" ]] && break
      sleep 0.01
    done
    if [[ ! -e "$failed_launch_ready" ]]; then
      failed_launch_escaped=true
    else
      if ! kill -s "$failed_signal" "$failed_launch_waiter"; then
        failed_launch_escaped=true
      else
        if [[ "$failed_signal" == TERM ]] && \
          ! kill -TERM "$failed_launch_waiter"; then
          failed_launch_escaped=true
        fi
        for ((attempt = 0; attempt < 500; attempt++)); do
          [[ -s "$failed_launch_observed" ]] && break
          sleep 0.01
        done
        [[ -s "$failed_launch_observed" ]] || \
          failed_launch_escaped=true
        if ! kill -0 "$failed_launch_waiter" 2>/dev/null || \
          flock --exclusive --nonblock "$failed_launch_lock" true; then
          failed_launch_escaped=true
        fi
      fi
    fi
    : >"$failed_launch_release"
    wait "$failed_launch_waiter" || return $?
    [[ "$failed_launch_escaped" == false && \
      "$(<"$failed_launch_status")" == 41 && \
      "$(<"$failed_launch_observed")" == "$failed_signal" && \
      ( -z "$(<"$failed_launch_pending")" || \
        "$(<"$failed_launch_pending")" == "$failed_signal" ) ]] || {
      printf 'project guard returned before reaping its rejected launch signal=%s escaped=%s status=%s observed=%s pending=%s\n' \
        "$failed_signal" "$failed_launch_escaped" \
        "$(<"$failed_launch_status")" \
        "$(<"$failed_launch_observed")" \
        "$(<"$failed_launch_pending")" >&2
      return 1
    }
    flock --exclusive --nonblock "$failed_launch_lock" true || {
      printf 'rejected project guard launch retained its lock after reap\n' >&2
      return 1
    }
    rm -f -- "$failed_launch_lock"
    (
      PROJECT_GUARD_CONTROL_DIR="$failed_launch_control"
      remove_project_guard_control_directory "$failed_launch_control"
    ) || return $?
  done
  rm -f -- "$failed_launch_ready" "$failed_launch_release" \
    "$failed_launch_status" "$failed_launch_pending" \
    "$failed_launch_observed"

  # Bash can retain a phantom RUNNING job after TERM interrupts wait exactly
  # as the holder exits. The authenticated terminal-status record, not `jobs`,
  # must close that race and preserve the worker's arbitrary status.
  for ((attempt = 0; attempt < 50; attempt++)); do
    exit_race_control="$(mktemp -d \
      "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
      return 1
    exit_race_lock="$TEST_TMP_DIR/project-guard-exit-race-$attempt.lock"
    exit_race_ready="$TEST_TMP_DIR/project-guard-exit-race-$attempt.ready"
    exit_race_release="$TEST_TMP_DIR/project-guard-exit-race-$attempt.release"
    exit_race_status="$TEST_TMP_DIR/project-guard-exit-race-$attempt.status"
    exit_race_waits="$TEST_TMP_DIR/project-guard-exit-race-$attempt.waits"
    exit_race_holder_file="$TEST_TMP_DIR/project-guard-exit-race-$attempt.holder"
    (umask 077; : >"$exit_race_lock")
    (
      PROJECT_GUARD_CONTROL_DIR="$exit_race_control"
      relay_pid="$BASHPID"
      relay_start_time="$(project_guard_process_start_time "$relay_pid")"
      publish_project_guard_control_file \
        "$PROJECT_GUARD_CONTROL_DIR/supervisor" \
        "supervisor:$relay_pid:$relay_start_time"
      publish_project_guard_control_file \
        "$PROJECT_GUARD_CONTROL_DIR/supervisor-accepted" \
        "supervisor-accepted:$relay_pid:$relay_start_time"
      PROJECT_GUARD_PENDING_SIGNAL=""
      PROJECT_GUARD_FORWARDING_READY=false
      trap record_project_guard_term TERM
      env --ignore-signal=HUP,INT,TERM \
        flock --exclusive --nonblock --close "$exit_race_lock" \
          bash -c '
            set -Eeuo pipefail
            : >"$1"
            while [[ ! -e "$2" ]]; do sleep 0.001; done
            sleep 0.003
            exit 41
          ' bash "$exit_race_ready" "$exit_race_release" &
      holder_pid=$!
      printf '%s\n' "$holder_pid" >"$exit_race_holder_file"
      holder_start_time="$(project_guard_process_start_time "$holder_pid")"
      PROJECT_GUARD_STATUS_RELAY_PID="$relay_pid"
      PROJECT_GUARD_STATUS_RELAY_START_TIME="$relay_start_time"
      PROJECT_GUARD_STATUS_HOLDER_PID="$holder_pid"
      PROJECT_GUARD_STATUS_HOLDER_START_TIME="$holder_start_time"
      publish_project_guard_holder_status 41
      : >"$exit_race_release"
      if ((attempt == 0)); then
        wait() {
          printf '%s:%s\n' "$#" "$*" >>"$exit_race_waits"
          builtin wait "$@"
        }
      fi
      (sleep 0.004; kill -TERM "$relay_pid" 2>/dev/null || true) &
      sender_pid=$!
      if wait_for_project_guard_holder \
        "$holder_pid" "$exit_race_lock" \
        "$relay_pid" "$relay_start_time" "$holder_start_time"; then
        holder_status=0
      else
        holder_status=$?
      fi
      wait "$sender_pid" 2>/dev/null || true
      printf '%s\n' "$holder_status" >"$exit_race_status"
      remove_project_guard_control_directory "$exit_race_control"
    ) &
    exit_race_probe=$!
    for ((exit_race_poll = 0; exit_race_poll < 200; exit_race_poll++)); do
      kill -0 "$exit_race_probe" 2>/dev/null || break
      sleep 0.01
    done
    if kill -0 "$exit_race_probe" 2>/dev/null; then
      kill -KILL "$exit_race_probe" 2>/dev/null || true
      wait "$exit_race_probe" 2>/dev/null || true
      printf 'project guard livelocked after an interrupted terminal wait\n' >&2
      return 1
    fi
    wait "$exit_race_probe" || return $?
    [[ "$(<"$exit_race_status")" == 41 ]] || {
      printf 'project guard lost the authenticated exit-race status\n' >&2
      return 1
    }
    if ((attempt == 0)) && \
      ! grep -Fxq -- "1:$(<"$exit_race_holder_file")" \
        "$exit_race_waits"; then
      printf 'project guard did not child-table reap the exact holder\n' >&2
      return 1
    fi
    flock --exclusive --nonblock "$exit_race_lock" true || {
      printf 'project guard exit-race probe retained its lock\n' >&2
      return 1
    }
    rm -f -- "$exit_race_lock" "$exit_race_ready" \
      "$exit_race_release" "$exit_race_status" \
      "$exit_race_waits" "$exit_race_holder_file"
  done

  stale_wait_control="$(mktemp -d \
    "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
    return 1
  stale_wait_lock="$TEST_TMP_DIR/project-guard-stale-wait.lock"
  stale_wait_release="$TEST_TMP_DIR/project-guard-stale-wait.release"
  (umask 077; : >"$stale_wait_lock")
  PROJECT_GUARD_CONTROL_DIR="$stale_wait_control"
  stale_wait_relay_pid="$BASHPID"
  stale_wait_relay_start="$(project_guard_process_start_time \
    "$stale_wait_relay_pid")"
  publish_project_guard_control_file \
    "$stale_wait_control/supervisor" \
    "supervisor:$stale_wait_relay_pid:$stale_wait_relay_start"
  publish_project_guard_control_file \
    "$stale_wait_control/supervisor-accepted" \
    "supervisor-accepted:$stale_wait_relay_pid:$stale_wait_relay_start"
  env --ignore-signal=HUP,INT,TERM \
    flock --exclusive --nonblock --close "$stale_wait_lock" \
      bash -c '
        while [[ ! -e "$1" ]]; do sleep 0.01; done
        exit 41
      ' bash "$stale_wait_release" &
  stale_wait_holder=$!
  stale_wait_holder_start="$(project_guard_process_start_time \
    "$stale_wait_holder")"
  PROJECT_GUARD_STATUS_RELAY_PID="$stale_wait_relay_pid"
  PROJECT_GUARD_STATUS_RELAY_START_TIME="$stale_wait_relay_start"
  PROJECT_GUARD_STATUS_HOLDER_PID="$stale_wait_holder"
  PROJECT_GUARD_STATUS_HOLDER_START_TIME="$stale_wait_holder_start"
  publish_project_guard_holder_status 41
  if (
    wait() { return 255; }
    project_guard_supervisor_is_running() { return 1; }
    wait_for_project_guard_holder \
      "$stale_wait_holder" "$stale_wait_lock" \
      "$stale_wait_relay_pid" "$stale_wait_relay_start" \
      "$stale_wait_holder_start"
  ); then
    stale_wait_status=0
  else
    stale_wait_status=$?
  fi
  : >"$stale_wait_release"
  wait "$stale_wait_holder" 2>/dev/null || true
  [[ "$stale_wait_status" == 41 ]] || {
    printf 'project guard trusted a phantom Bash job over terminal status\n' >&2
    return 1
  }
  remove_project_guard_control_directory "$stale_wait_control" || return $?
  rm -f -- "$stale_wait_lock" "$stale_wait_release"
  PROJECT_GUARD_CONTROL_DIR=""
  PROJECT_GUARD_STATUS_RELAY_PID=""
  PROJECT_GUARD_STATUS_RELAY_START_TIME=""
  PROJECT_GUARD_STATUS_HOLDER_PID=""
  PROJECT_GUARD_STATUS_HOLDER_START_TIME=""

  # The terminal record is private protocol input, not a hint: every byte,
  # metadata field, and bound process identity must be exact.
  stale_wait_control="$(mktemp -d \
    "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
    return 1
  PROJECT_GUARD_CONTROL_DIR="$stale_wait_control"
  stale_wait_relay_pid="$BASHPID"
  stale_wait_relay_start="$(project_guard_process_start_time \
    "$stale_wait_relay_pid")"
  stale_wait_holder_pid="$stale_wait_relay_pid"
  stale_wait_holder_start="$stale_wait_relay_start"
  holder_status_original="$(project_guard_holder_status_payload \
    "$stale_wait_relay_pid" "$stale_wait_relay_start" \
    "$stale_wait_holder_pid" "$stale_wait_holder_start" 41)" || return 1
  publish_project_guard_control_file \
    "$stale_wait_control/holder-status" "$holder_status_original" || return $?
  [[ "$(read_project_guard_holder_status \
    "$stale_wait_relay_pid" "$stale_wait_relay_start" \
    "$stale_wait_holder_pid" "$stale_wait_holder_start")" == \
    "$stale_wait_holder_start 41" ]] || return 1
  for holder_status_mutation in \
    "holder-status:$stale_wait_relay_pid:$stale_wait_relay_start:$stale_wait_holder_pid:$stale_wait_holder_start:041" \
    "holder-status:$((stale_wait_relay_pid + 1)):$stale_wait_relay_start:$stale_wait_holder_pid:$stale_wait_holder_start:41" \
    "holder-status:$stale_wait_relay_pid:$((stale_wait_relay_start + 1)):$stale_wait_holder_pid:$stale_wait_holder_start:41" \
    "holder-status:$stale_wait_relay_pid:$stale_wait_relay_start:$((stale_wait_holder_pid + 1)):$stale_wait_holder_start:41" \
    "holder-status:$stale_wait_relay_pid:$stale_wait_relay_start:$stale_wait_holder_pid:$((stale_wait_holder_start + 1)):41"; do
    printf '%s\n' "$holder_status_mutation" >"$stale_wait_control/holder-status"
    if read_project_guard_holder_status \
      "$stale_wait_relay_pid" "$stale_wait_relay_start" \
      "$stale_wait_holder_pid" "$stale_wait_holder_start" \
      >/dev/null 2>&1; then
      printf 'project guard accepted a mutated terminal status record\n' >&2
      return 1
    fi
  done
  printf '%s\n' "$holder_status_original" >"$stale_wait_control/holder-status"
  chmod 0644 -- "$stale_wait_control/holder-status"
  if read_project_guard_holder_status \
    "$stale_wait_relay_pid" "$stale_wait_relay_start" \
    "$stale_wait_holder_pid" "$stale_wait_holder_start" \
    >/dev/null 2>&1; then
    printf 'project guard accepted public terminal status metadata\n' >&2
    return 1
  fi
  chmod 0600 -- "$stale_wait_control/holder-status"
  ln "$stale_wait_control/holder-status" \
    "$stale_wait_control/holder-status-link" || return $?
  if read_project_guard_holder_status \
    "$stale_wait_relay_pid" "$stale_wait_relay_start" \
    "$stale_wait_holder_pid" "$stale_wait_holder_start" \
    >/dev/null 2>&1; then
    printf 'project guard accepted hard-linked terminal status evidence\n' >&2
    return 1
  fi
  rm -f -- "$stale_wait_control/holder-status-link"
  remove_project_guard_control_directory "$stale_wait_control" || return $?
  PROJECT_GUARD_CONTROL_DIR=""

  # Once malformed terminal protocol input is observed, a later valid-looking
  # replacement cannot repair that invocation. Exercise the exact latch even
  # across two liveness observations so a fast-path status return cannot skip
  # the earlier failure.
  protocol_latch_control="$(mktemp -d \
    "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
    return 1
  (umask 077; : >"$protocol_latch_lock")
  printf 'corrupt\n' >"$protocol_latch_control/holder-status"
  chmod 0600 -- "$protocol_latch_control/holder-status"
  printf '0\n' >"$protocol_latch_read_count"
  printf '0\n' >"$protocol_latch_live_count"
  (
    PROJECT_GUARD_CONTROL_DIR="$protocol_latch_control"
    relay_pid="$BASHPID"
    relay_start_time="$(project_guard_process_start_time "$relay_pid")"
    bash -c 'while [[ ! -e "$1" ]]; do sleep 0.01; done; exit 41' \
      bash "$protocol_latch_release" &
    holder_pid=$!
    holder_start_time="$(project_guard_process_start_time "$holder_pid")"
    : >"$protocol_latch_release"
    project_guard_supervisor_is_running() {
      local count=""
      count="$(<"$protocol_latch_live_count")"
      printf '%s\n' "$((count + 1))" >"$protocol_latch_live_count"
      # First top-level probe: terminal. First post-read probe: appear live so
      # the loop observes the replacement. Every later probe: terminal.
      [[ "$count" -eq 1 ]]
    }
    load_project_guard_holder_status() {
      local count=""
      count="$(<"$protocol_latch_read_count")"
      printf '%s\n' "$((count + 1))" >"$protocol_latch_read_count"
      if [[ "$count" -eq 0 ]]; then
        return 1
      fi
      PROJECT_GUARD_LOADED_HOLDER_START_TIME="$holder_start_time"
      PROJECT_GUARD_LOADED_HOLDER_STATUS=41
    }
    if wait_for_project_guard_holder \
      "$holder_pid" "$protocol_latch_lock" \
      "$relay_pid" "$relay_start_time" "$holder_start_time" false; then
      protocol_status=0
    else
      protocol_status=$?
    fi
    [[ "$protocol_status" -eq 1 ]]
  ) || {
    printf 'project guard repaired a latched malformed terminal status\n' >&2
    return 1
  }
  (
    PROJECT_GUARD_CONTROL_DIR="$protocol_latch_control"
    remove_project_guard_control_directory "$protocol_latch_control"
  ) || return $?
  rm -f -- "$protocol_latch_lock" "$protocol_latch_release" \
    "$protocol_latch_read_count" "$protocol_latch_live_count"

  # An accepted worker can legitimately spend longer than the launch
  # handshake in cleanup and can run commands below GNU timeout's distinct
  # process group. Cancellation must retain the relay and flock until that
  # worker publishes and exits; killing the holder group would orphan timeout
  # and its command while making the project lock acquirable.
  accepted_control="$(mktemp -d \
    "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
    return 1
  (umask 077; : >"$accepted_lock")
  (
    PROJECT_GUARD_CONTROL_DIR="$accepted_control"
    relay_pid="$BASHPID"
    relay_start_time="$(project_guard_process_start_time "$relay_pid")"
    publish_project_guard_control_file \
      "$accepted_control/supervisor" \
      "supervisor:$relay_pid:$relay_start_time"
    publish_project_guard_control_file \
      "$accepted_control/supervisor-accepted" \
      "supervisor-accepted:$relay_pid:$relay_start_time"
    set -m
    env --ignore-signal=HUP,INT,TERM \
      flock --exclusive --nonblock --close "$accepted_lock" \
        env --default-signal=HUP,INT,TERM bash -c '
          trap ":" TERM
          timeout --signal=TERM --kill-after=1s 30s \
            bash -c '\''
              printf "%s %s\n" "$PPID" "$$" >"$1"
              : >"$2"
              while [[ ! -e "$3" ]]; do sleep 0.01; done
            '\'' bash "$1" "$2" "$3"
          exit 41
        ' bash "$accepted_pids" "$accepted_ready" "$accepted_release" &
    holder_pid=$!
    set +m
    printf '%s\n' "$holder_pid" >"$accepted_holder_file"
    holder_start_time="$(project_guard_process_start_time "$holder_pid")"
    PROJECT_GUARD_STATUS_RELAY_PID="$relay_pid"
    PROJECT_GUARD_STATUS_RELAY_START_TIME="$relay_start_time"
    PROJECT_GUARD_STATUS_HOLDER_PID="$holder_pid"
    PROJECT_GUARD_STATUS_HOLDER_START_TIME="$holder_start_time"
    publish_project_guard_holder_status 41
    PROJECT_GUARD_PENDING_SIGNAL=TERM
    PROJECT_GUARD_FORWARDING_READY=false
    sleep() {
      if [[ "${1:-}" == 0.01 ]]; then
        command sleep 0.001
      else
        command sleep "$@"
      fi
    }
    if wait_for_project_guard_holder \
      "$holder_pid" "$accepted_lock" \
      "$relay_pid" "$relay_start_time" "$holder_start_time" true; then
      holder_status=0
    else
      holder_status=$?
    fi
    printf '%s\n' "$holder_status" >"$accepted_status"
    remove_project_guard_control_directory "$accepted_control"
  ) &
  accepted_probe=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$accepted_ready" && -s "$accepted_holder_file" && \
      -s "$accepted_pids" ]] && break
    sleep 0.01
  done
  if [[ ! -e "$accepted_ready" || ! -s "$accepted_holder_file" || \
    ! -s "$accepted_pids" ]]; then
    : >"$accepted_release"
    kill -KILL "$accepted_probe" 2>/dev/null || true
    wait "$accepted_probe" 2>/dev/null || true
    printf 'accepted project guard fixture did not become ready\n' >&2
    return 1
  fi
  accepted_holder="$(<"$accepted_holder_file")"
  read -r accepted_timeout accepted_leaf accepted_extra <"$accepted_pids"
  [[ "$accepted_holder" =~ ^[1-9][0-9]*$ && \
    "$accepted_timeout" =~ ^[1-9][0-9]*$ && \
    "$accepted_leaf" =~ ^[1-9][0-9]*$ && -z "$accepted_extra" ]] || return 1
  accepted_timeout_start="$(project_guard_process_start_time \
    "$accepted_timeout")" || return 1
  accepted_leaf_start="$(project_guard_process_start_time \
    "$accepted_leaf")" || return 1
  accepted_timeout_stat="$(<"/proc/$accepted_timeout/stat")" || return 1
  accepted_timeout_fields="${accepted_timeout_stat##*) }"
  read -r -a accepted_timeout_fields <<<"$accepted_timeout_fields"
  accepted_timeout_pgid="${accepted_timeout_fields[2]:-}"
  [[ "$accepted_timeout_pgid" == "$accepted_timeout" && \
    "$accepted_timeout_pgid" != "$accepted_holder" ]] || {
    : >"$accepted_release"
    wait "$accepted_probe" 2>/dev/null || true
    printf 'accepted fixture did not create a nested timeout process group\n' >&2
    return 1
  }
  # The helper's old 300-iteration cancellation budget is compressed to well
  # below this delay. It must still be alive with the lock held afterward.
  sleep 1
  if ! kill -0 "$accepted_probe" 2>/dev/null || \
    flock --exclusive --nonblock "$accepted_lock" true || \
    ! project_guard_supervisor_identity_matches \
      "$accepted_timeout" "$accepted_timeout_start" || \
    ! project_guard_supervisor_identity_matches \
      "$accepted_leaf" "$accepted_leaf_start"; then
    : >"$accepted_release"
    wait "$accepted_probe" 2>/dev/null || true
    printf 'accepted project guard released before its worker lifetime ended\n' >&2
    return 1
  fi
  : >"$accepted_release"
  wait "$accepted_probe" || return $?
  [[ "$(<"$accepted_status")" == 41 ]] || {
    printf 'accepted project guard lost its authenticated terminal status\n' >&2
    return 1
  }
  for ((attempt = 0; attempt < 500; attempt++)); do
    if ! project_guard_supervisor_identity_matches \
        "$accepted_timeout" "$accepted_timeout_start" && \
      ! project_guard_supervisor_identity_matches \
        "$accepted_leaf" "$accepted_leaf_start"; then
      break
    fi
    sleep 0.01
  done
  if project_guard_supervisor_identity_matches \
      "$accepted_timeout" "$accepted_timeout_start" || \
    project_guard_supervisor_identity_matches \
      "$accepted_leaf" "$accepted_leaf_start" || \
    ! flock --exclusive --nonblock "$accepted_lock" true; then
    printf 'accepted project guard retained a descendant or project lock\n' >&2
    return 1
  fi
  rm -f -- "$accepted_lock" "$accepted_ready" "$accepted_release" \
    "$accepted_pids" "$accepted_holder_file" "$accepted_status"

  # Launch acceptance makes the worker's authenticated holder-status record
  # mandatory. Before acceptance, the exact child-table status remains the
  # authority for an early exit such as flock conflict.
  (umask 077; : >"$accepted_missing_lock")
  for accepted_missing_mode in true false; do
    accepted_missing_control="$(mktemp -d \
      "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
      return 1
    accepted_missing_release="$TEST_TMP_DIR/project-guard-accepted-missing-$accepted_missing_mode.release"
    rm -f -- "$accepted_missing_release"
    (
      PROJECT_GUARD_CONTROL_DIR="$accepted_missing_control"
      PROJECT_GUARD_PENDING_SIGNAL=""
      PROJECT_GUARD_FORWARDING_READY=false
      relay_pid="$BASHPID"
      relay_start_time="$(project_guard_process_start_time "$relay_pid")"
      flock --exclusive --nonblock --close "$accepted_missing_lock" \
        bash -c '
          while [[ ! -e "$1" ]]; do sleep 0.01; done
          exit 41
        ' bash "$accepted_missing_release" &
      accepted_missing_holder=$!
      accepted_missing_start="$(project_guard_process_start_time \
        "$accepted_missing_holder")"
      : >"$accepted_missing_release"
      if wait_for_project_guard_holder \
        "$accepted_missing_holder" "$accepted_missing_lock" \
        "$relay_pid" "$relay_start_time" "$accepted_missing_start" \
        "$accepted_missing_mode"; then
        accepted_missing_status=0
      else
        accepted_missing_status=$?
      fi
      remove_project_guard_control_directory "$accepted_missing_control"
      printf '%s\n' "$accepted_missing_status"
    ) >"$accepted_status" || return $?
    if [[ "$accepted_missing_mode" == true ]]; then
      [[ "$(<"$accepted_status")" == 1 ]] || {
        printf 'accepted worker exited without mandatory holder status: %s\n' \
          "$(<"$accepted_status")" >&2
        return 1
      }
    else
      [[ "$(<"$accepted_status")" == 41 ]] || {
        printf 'pre-acceptance exit lost its exact child status: %s\n' \
          "$(<"$accepted_status")" >&2
        return 1
      }
    fi
    flock --exclusive --nonblock "$accepted_missing_lock" true || {
      printf 'missing-status fixture retained the project lock\n' >&2
      return 1
    }
    rm -f -- "$accepted_missing_release" "$accepted_status"
  done
  rm -f -- "$accepted_missing_lock"

  real_bash="$(type -P bash)" || return 1
  [[ "$real_bash" == /* ]] || return 1
  {
    printf '#!%s\n' "$real_bash"
    cat <<'EOF'
set -Eeuo pipefail
if [[ "${1:-}" == "$PROJECT_GUARD_PRETRAP_RUNNER" ]]; then
  : >"$PROJECT_GUARD_PRETRAP_READY"
  while :; do sleep 0.01; done
fi
exec "$PROJECT_GUARD_REAL_BASH" "$@"
EOF
  } >"$fake_bin/bash"
  chmod 0700 -- "$fake_bin/bash"
  : >"$docker_log"
  setsid env --default-signal=HUP,INT,TERM \
    COMPOSE_PROJECT_NAME="$pretrap_project" \
    PROJECT_GUARD_TEST_DOCKER_LOG="$docker_log" \
    PROJECT_GUARD_PRETRAP_RUNNER="$pretrap_runner" \
    PROJECT_GUARD_PRETRAP_READY="$pretrap_ready" \
    PROJECT_GUARD_REAL_BASH="$real_bash" \
    PATH="$fake_bin:$PATH" \
    "$real_bash" "$pretrap_runner" --cleanup-only &
  runner_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$pretrap_ready" ]] && break
    sleep 0.01
  done
  if [[ ! -e "$pretrap_ready" ]]; then
    kill -KILL -- "-$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true
    printf 'real guarded worker did not expose its pre-trap launch boundary\n' >&2
    return 1
  fi
  kill -TERM -- "-$runner_pid" || return $?
  if wait "$runner_pid"; then
    runner_status=0
  else
    runner_status=$?
  fi
  [[ "$runner_status" == 130 ]] || {
    printf 'pre-trap process-group TERM was not canonical: %s\n' \
      "$runner_status" >&2
    return 1
  }
  flock --exclusive --nonblock "$pretrap_lock" true || {
    printf 'pre-trap process-group TERM retained the project lock\n' >&2
    return 1
  }
  [[ "$(<"$docker_log")" == 'compose version' ]] || {
    printf 'pre-trap process-group TERM reached a Compose mutation\n' >&2
    return 1
  }
  rm -f -- "$pretrap_lock" "$pretrap_ready" "$fake_bin/bash"

  {
    printf '#!%s\n' "$real_bash"
    cat <<'EOF'
set -Eeuo pipefail
if [[ "${1:-}" == "$PROJECT_GUARD_PRETRAP_RUNNER" ]]; then
  : >"$PROJECT_GUARD_PRETRAP_READY"
  while :; do sleep 0.01; done
fi
exec "$PROJECT_GUARD_REAL_BASH" "$@"
EOF
  } >"$fake_bin/bash"
  chmod 0700 -- "$fake_bin/bash"
  : >"$docker_log"
  COMPOSE_PROJECT_NAME="$pretrap_project" \
    PROJECT_GUARD_TEST_DOCKER_LOG="$docker_log" \
    PROJECT_GUARD_PRETRAP_RUNNER="$pretrap_runner" \
    PROJECT_GUARD_PRETRAP_READY="$pretrap_direct_ready" \
    PROJECT_GUARD_REAL_BASH="$real_bash" \
    PATH="$fake_bin:$PATH" \
    "$real_bash" "$pretrap_runner" --cleanup-only &
  runner_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$pretrap_direct_ready" ]] && break
    sleep 0.01
  done
  if [[ ! -e "$pretrap_direct_ready" ]]; then
    kill -KILL "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true
    printf 'direct guarded worker did not expose its pre-trap boundary\n' >&2
    return 1
  fi
  kill -TERM "$runner_pid" || return $?
  if wait "$runner_pid"; then
    runner_status=0
  else
    runner_status=$?
  fi
  [[ "$runner_status" == 130 ]] || {
    printf 'direct pre-trap TERM was not canonical: %s\n' \
      "$runner_status" >&2
    return 1
  }
  flock --exclusive --nonblock "$pretrap_lock" true || {
    printf 'direct pre-trap TERM retained the project lock\n' >&2
    return 1
  }
  [[ "$(<"$docker_log")" == 'compose version' ]] || {
    printf 'direct pre-trap TERM reached a Compose mutation\n' >&2
    return 1
  }
  rm -f -- "$pretrap_lock" "$pretrap_direct_ready" "$fake_bin/bash"

  malformed_launch_control="$(mktemp -d \
    "/tmp/obi-apache-java-https-project-guard-$EUID/.terminal-handoff.XXXXXX")" || \
    return 1
  (umask 077; : >"$malformed_launch_lock")
  printf 'corrupt\n' >"$malformed_launch_control/supervisor-launched"
  chmod 0600 -- "$malformed_launch_control/supervisor-launched"
  (
    export COMPOSE_PROJECT_NAME="$malformed_launch_project"
    export PROJECT_GUARD_TEST_DOCKER_LOG="$docker_log"
    export PATH="$fake_bin:$PATH"
    PROJECT_GUARD_CONTROL_DIR="$malformed_launch_control"
    PROJECT_GUARD_PENDING_SIGNAL=""
    PROJECT_GUARD_FORWARDING_READY=false
    PROJECT_GUARD_SUPERVISOR_PID=""
    PROJECT_GUARD_SUPERVISOR_START_TIME=""
    trap record_project_guard_hup HUP
    trap record_project_guard_int INT
    trap record_project_guard_term TERM
    if run_project_guard_relay "$malformed_launch_lock" --cleanup-only; then
      relay_status=0
    else
      relay_status=$?
    fi
    printf '%s\n' "$relay_status" >"$malformed_launch_status"
  ) &
  malformed_launch_relay=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$malformed_launch_control/ready" ]] && break
    sleep 0.01
  done
  if [[ ! -e "$malformed_launch_control/ready" ]]; then
    malformed_launch_escaped=true
  else
    kill -TERM "$malformed_launch_relay" || malformed_launch_escaped=true
    sleep 0.1
    if kill -0 "$malformed_launch_relay" 2>/dev/null; then
      if flock --exclusive --nonblock "$malformed_launch_lock" true || \
        [[ ! -d "$malformed_launch_control" ]]; then
        malformed_launch_escaped=true
      fi
    fi
  fi
  wait "$malformed_launch_relay" || return $?
  (
    PROJECT_GUARD_CONTROL_DIR="$malformed_launch_control"
    remove_project_guard_control_directory "$malformed_launch_control"
  ) || return $?
  [[ "$malformed_launch_escaped" == false && \
    "$(<"$malformed_launch_status")" == 1 && \
    ! -e "$malformed_launch_control" && \
    ! -L "$malformed_launch_control" ]] || {
    printf 'malformed guarded launch escaped before terminal cleanup\n' >&2
    return 1
  }
  flock --exclusive --nonblock "$malformed_launch_lock" true || {
    printf 'malformed guarded launch retained its project lock\n' >&2
    return 1
  }
  rm -f -- "$malformed_launch_lock" "$malformed_launch_status"
}

test_permanent_absence_global_marker_is_exact_and_daemon_bound() {
  local -r guard_root="$TEST_TMP_DIR/permanent-absence-global-marker"
  local -r project=obi-apache-java-https-marker-test
  local -r docker_a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local -r docker_b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  local -r marker="$guard_root/$project.permanent-absence-recovery-required"
  local metadata=""

  mkdir -m 0700 -- "$guard_root"
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_a"
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    create_permanent_absence_global_marker
  ) || return $?
  metadata="$(stat --format='%u:%a:%h' -- "$marker")" || return $?
  [[ "$metadata" == "$EUID:600:1" ]] || {
    printf 'global recovery marker metadata is not private: %s\n' "$metadata" >&2
    return 1
  }
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_a"
    assert_project_guard_held() { :; }
    [[ "$(read_permanent_absence_global_marker)" == "$docker_a" ]]
  ) || {
    printf 'global recovery marker content is not exact\n' >&2
    return 1
  }
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_b"
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    clear_pending_permanent_absence_recovery
  ) >/dev/null 2>&1; then
    printf 'cleanup cleared recovery state for a different Docker server\n' >&2
    return 1
  fi
  [[ -f "$marker" && ! -L "$marker" ]] || return 1
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_a"
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    clear_pending_permanent_absence_recovery
  ) || return $?
  [[ ! -e "$marker" && ! -L "$marker" ]] || {
    printf 'verified same-daemon cleanup retained the global marker\n' >&2
    return 1
  }

  (umask 077; printf 'corrupt\n' >"$marker")
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_a"
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    clear_pending_permanent_absence_recovery
  ) >/dev/null 2>&1; then
    printf 'cleanup removed a malformed global recovery marker\n' >&2
    return 1
  fi
  [[ -f "$marker" && "$(<"$marker")" == corrupt ]] || return 1
}

test_project_guard_docker_identity_capture_is_source_bounded() {
  local -r guard_root="$TEST_TMP_DIR/project-guard-docker-identity"
  local expected=""
  local observed=""
  local status=0

  mkdir -m 0700 -- "$guard_root"
  expected="$(printf '%s' 'SERVER_ID_1234' | sha256sum)" || return 1
  expected="${expected%% *}"
  observed="$({
    PROJECT_GUARD_ROOT="$guard_root"
    run_bounded() { printf '"SERVER_ID_1234"\n'; }
    resolve_docker_server_identity
  })" || return $?
  [[ "$observed" == "$expected" ]] || {
    printf 'project guard hashed the wrong bounded Docker server identity\n' >&2
    return 1
  }
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    run_bounded() {
      head -c "$((DOCKER_SERVER_ID_MAX_BYTES + 1))" /dev/zero | tr '\0' x
    }
    resolve_docker_server_identity
  ) >/dev/null 2>&1; then
    printf 'project guard accepted an oversized Docker identity response\n' >&2
    return 1
  fi
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    run_bounded() {
      printf '"SERVER_ID_1234"\n'
      return 77
    }
    resolve_docker_server_identity
  ) >/dev/null 2>&1; then
    printf 'project guard ignored a failed Docker identity producer\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" == 77 ]] || {
    printf 'project guard lost Docker identity producer status: %s\n' "$status" >&2
    return 1
  }
  if compgen -G "$guard_root/.docker-server-id.*" >/dev/null; then
    printf 'project guard retained a Docker identity temporary\n' >&2
    return 1
  fi
}

test_permanent_absence_cleanup_only_clears_after_verified_down() {
  local -r guard_root="$TEST_TMP_DIR/permanent-absence-cleanup-only"
  local -r project=obi-apache-java-https-cleanup-test
  local -r docker_identity=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  local -r marker="$guard_root/$project.permanent-absence-recovery-required"
  local -r observed="$guard_root/observed"

  mkdir -m 0700 -- "$guard_root"
  (
    PROJECT_NAME="$project"
    umask 077
    permanent_absence_global_marker_payload "$docker_identity" >"$marker"
  )
  if (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_identity"
    BRIDGE_RUNNING=true
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    invalidate_project_transport_evidence() { printf 'invalidate\n' >>"$observed"; }
    safe_compose_down() { printf 'down-failed\n' >>"$observed"; return 73; }
    cleanup_only
  ) >/dev/null 2>&1; then
    printf 'cleanup-only ignored a failed verified down\n' >&2
    return 1
  fi
  [[ -f "$marker" ]] || {
    printf 'cleanup-only cleared recovery state after a failed down\n' >&2
    return 1
  }
  (
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_identity"
    BRIDGE_RUNNING=true
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    invalidate_project_transport_evidence() { printf 'invalidate\n' >>"$observed"; }
    safe_compose_down() { printf 'down-verified\n' >>"$observed"; }
    cleanup_only
  ) || return $?
  [[ ! -e "$marker" && ! -L "$marker" && \
    "$(<"$observed")" == *'down-verified'* ]] || {
    printf 'cleanup-only did not clear state after verified project absence\n' >&2
    return 1
  }
}

test_permanent_absence_global_marker_forces_exit_cleanup() {
  local -r result_dir="$TEST_TMP_DIR/permanent-absence-global-cleanup-result"
  local -r guard_root="$TEST_TMP_DIR/permanent-absence-global-cleanup-guard"
  local -r project=obi-apache-java-https-global-cleanup-test
  local -r docker_identity=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  local -r marker="$guard_root/$project.permanent-absence-recovery-required"
  local -r down_marker="$result_dir/down"
  local cleanup_status=0

  mkdir -p -- "$result_dir"
  mkdir -m 0700 -- "$guard_root"
  (
    PROJECT_NAME="$project"
    umask 077
    permanent_absence_global_marker_payload "$docker_identity" >"$marker"
  )
  if (
    RESULT_DIR="$result_dir"
    PROJECT_GUARD_ROOT="$guard_root"
    PROJECT_NAME="$project"
    PROJECT_GUARD_HELD=true
    PROJECT_DOCKER_SERVER_ID_SHA256="$docker_identity"
    STACK_STARTED=true
    KEEP_RUNNING=true
    BRIDGE_RUNNING=true
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    assert_project_guard_held() { :; }
    assert_project_docker_identity_unchanged() { :; }
    cleanup_security_processes() { :; }
    cleanup_source_snapshot_work_directory() { :; }
    capture_evidence() { :; }
    invalidate_project_transport_evidence() { :; }
    safe_compose_down() { : >"$down_marker"; }

    cleanup
  ) >/dev/null 2>&1; then
    printf 'global recovery marker preserved a kept Compose stack\n' >&2
    return 1
  else
    cleanup_status=$?
  fi
  [[ "$cleanup_status" == 1 && -e "$down_marker" && \
    ! -e "$marker" && ! -L "$marker" ]] || {
    printf 'global-only recovery state did not force verified exit cleanup\n' >&2
    return 1
  }
}

test_cleanup_signal_status_matches_retained_evidence() {
  local -r root="$TEST_TMP_DIR/cleanup-signal-status"
  local -r entry_result="$root/entry-result"
  local -r entry_progress="$root/entry-progress"
  local -r failed_entry_result="$root/failed-entry-result"
  local -r failed_entry_progress="$root/failed-entry-progress"
  local -r runtime_signal_result="$root/runtime-signal-result"
  local -r runtime_signal_ready="$root/runtime-signal-ready"
  local -r runtime_signal_progress="$root/runtime-signal-progress"
  local -r capture_result="$root/capture-result"
  local -r capture_ready="$root/capture-ready"
  local -r capture_release="$root/capture-release"
  local -r group_cleanup_result="$root/group-cleanup-result"
  local -r group_cleanup_ready="$root/group-cleanup-ready"
  local -r holder_publication_result="$root/holder-publication-result"
  local -r holder_publication_calls="$root/holder-publication-calls"
  local -r publication_result="$root/publication-result"
  local -r publication_ready="$root/publication-ready"
  local -r publication_release="$root/publication-release"
  local -r post_publication_result="$root/post-publication-result"
  local -r post_publication_ready="$root/post-publication-ready"
  local -r post_publication_release="$root/post-publication-release"
  local worker_pid=""
  local worker_status=0
  local -i attempt=0

  mkdir -p -- \
    "$entry_result" \
    "$failed_entry_result" \
    "$runtime_signal_result" \
    "$capture_result" \
    "$group_cleanup_result" \
    "$holder_publication_result" \
    "$publication_result" \
    "$post_publication_result"
  if (
    RESULT_DIR="$entry_result"
    STACK_STARTED=false
    PROJECT_GUARD_HELD=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    CLEANUP_ENTRY_STATUS=""
    CLEANUP_SIGNAL_STATUS=0
    cleanup_entry_signal_sent=false
    signal_at_cleanup_trap_boundary() {
      if [[ "$cleanup_entry_signal_sent" == false ]]; then
        cleanup_entry_signal_sent=true
        trap - DEBUG
        kill -TERM "$BASHPID"
      fi
    }
    cleanup_security_processes() { :; }
    capture_evidence() { : >"$entry_progress"; }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    install_traps
    CLEANUP_ENTRY_ACTIVE=true
    set -T
    trap signal_at_cleanup_trap_boundary DEBUG
    exit 0
  ) >/dev/null 2>&1; then
    printf 'cleanup entry signal preserved a successful exit\n' >&2
    return 1
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 130 && -e "$entry_progress" ]] || {
    printf 'cleanup entry signal bypassed recovery: status=%s progress=%s\n' \
      "$worker_status" "$([[ -e "$entry_progress" ]] && printf yes || printf no)" >&2
    return 1
  }
  jq -e '
    .status == "failed" and .exit_status == 130 and
    .failure_stage == "signal"
  ' "$entry_result/run-status.json" >/dev/null || {
    printf 'cleanup entry signal did not retain failed status\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$failed_entry_result"
    STACK_STARTED=false
    PROJECT_GUARD_HELD=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    CLEANUP_ENTRY_ACTIVE=true
    CLEANUP_ENTRY_STATUS=""
    CLEANUP_SIGNAL_STATUS=0
    cleanup_entry_debug_count=0
    signal_during_failed_cleanup_entry() {
      ((cleanup_entry_debug_count += 1))
      if ((cleanup_entry_debug_count == 2)); then
        trap - DEBUG
        kill -TERM "$BASHPID"
      fi
    }
    cleanup_security_processes() { :; }
    capture_evidence() { : >"$failed_entry_progress"; }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    install_traps
    CLEANUP_ENTRY_ACTIVE=true
    set -T
    trap signal_during_failed_cleanup_entry DEBUG
    exit 42
  ) >/dev/null 2>&1; then
    printf 'failed cleanup entry unexpectedly returned success\n' >&2
    return 1
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 42 && -e "$failed_entry_progress" ]] || {
    printf 'cleanup entry signal replaced the prior failure: status=%s progress=%s\n' \
      "$worker_status" \
      "$([[ -e "$failed_entry_progress" ]] && printf yes || printf no)" >&2
    return 1
  }
  jq -e '
    .status == "failed" and .exit_status == 42
  ' "$failed_entry_result/run-status.json" >/dev/null || {
    printf 'cleanup entry signal did not preserve the prior failed status\n' >&2
    return 1
  }

  (
    RESULT_DIR="$runtime_signal_result"
    STACK_STARTED=false
    PROJECT_GUARD_HELD=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    CLEANUP_ENTRY_ACTIVE=""
    CLEANUP_ENTRY_STATUS=""
    CLEANUP_SIGNAL_STATUS=0
    cleanup_security_processes() { :; }
    capture_evidence() { : >"$runtime_signal_progress"; }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    install_traps
    : >"$runtime_signal_ready"
    while :; do sleep 0.1; done
  ) >/dev/null 2>&1 &
  worker_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$runtime_signal_ready" ]] && break
    sleep 0.01
  done
  [[ -e "$runtime_signal_ready" ]] || return 1
  kill -TERM "$worker_pid" || return $?
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 130 && -e "$runtime_signal_progress" ]] || {
    printf 'initial runtime TERM bypassed cleanup: status=%s progress=%s\n' \
      "$worker_status" \
      "$([[ -e "$runtime_signal_progress" ]] && printf yes || printf no)" >&2
    return 1
  }
  jq -e '
    .status == "failed" and .exit_status == 130 and
    .failure_stage == "signal"
  ' "$runtime_signal_result/run-status.json" >/dev/null || {
    printf 'initial runtime TERM did not retain failed status\n' >&2
    return 1
  }

  (
    RESULT_DIR="$capture_result"
    STACK_STARTED=false
    PROJECT_GUARD_HELD=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    CLEANUP_SIGNAL_STATUS=0
    trap record_cleanup_hup HUP
    trap record_cleanup_int INT
    trap record_cleanup_term TERM
    cleanup_security_processes() { :; }
    capture_evidence() {
      : >"$capture_ready"
      while [[ ! -e "$capture_release" ]]; do sleep 0.01; done
    }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    cleanup
  ) >/dev/null 2>&1 &
  worker_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$capture_ready" ]] && break
    sleep 0.01
  done
  [[ -e "$capture_ready" ]] || return 1
  kill -TERM "$worker_pid" || return $?
  kill -TERM "$worker_pid" || return $?
  : >"$capture_release"
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 130 ]] || {
    printf 'cleanup lost its repeated TERM status: %s\n' "$worker_status" >&2
    return 1
  }
  jq -e '
    .status == "failed" and .exit_status == 130 and
    .failure_stage == "signal"
  ' "$capture_result/run-status.json" >/dev/null || {
    printf 'cleanup retained a passing status after repeated TERM\n' >&2
    return 1
  }

  setsid env --default-signal=HUP,INT,TERM bash -c '
    set -Eeuo pipefail
    source "$1"
    RESULT_DIR=$2
    group_cleanup_ready=$3
    STACK_STARTED=true
    PROJECT_GUARD_HELD=false
    KEEP_RUNNING=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    CLEANUP_SIGNAL_STATUS=0
    trap record_cleanup_hup HUP
    trap record_cleanup_int INT
    trap record_cleanup_term TERM
    cleanup_security_processes() { :; }
    capture_evidence() { :; }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    assert_permanent_absence_marker_matches_current_docker() { :; }
    invalidate_project_transport_evidence() { :; }
    clear_pending_permanent_absence_recovery() { :; }
    safe_compose_down() {
      : >"$group_cleanup_ready"
      sleep 30
    }
    cleanup
  ' bash "$TEST_SCRIPT_DIR/../run.sh" \
    "$group_cleanup_result" "$group_cleanup_ready" \
    >/dev/null 2>&1 &
  worker_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$group_cleanup_ready" ]] && break
    sleep 0.01
  done
  [[ -e "$group_cleanup_ready" ]] || return 1
  kill -TERM -- "-$worker_pid" || return $?
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 130 ]] || {
    printf 'process-group TERM was not canonical during cleanup: %s\n' \
      "$worker_status" >&2
    return 1
  }
  jq -e '
    .status == "failed" and .exit_status == 130 and
    .failure_stage == "signal"
  ' "$group_cleanup_result/run-status.json" >/dev/null || {
    printf 'process-group TERM cleanup evidence was not canonical\n' >&2
    return 1
  }

  if (
    RESULT_DIR="$holder_publication_result"
    STACK_STARTED=false
    PROJECT_GUARD_HELD=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    PROJECT_GUARD_STATUS_RELAY_PID=1
    cleanup_security_processes() { :; }
    capture_evidence() { :; }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    publish_project_guard_holder_status_with_retries() {
      printf '%s\n' "$1" >>"$holder_publication_calls"
      [[ "$1" == 1 ]]
    }
    cleanup 0
  ) >/dev/null 2>&1; then
    printf 'cleanup preserved success after terminal-status publication failed\n' >&2
    return 1
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 1 && \
    "$(<"$holder_publication_calls")" == $'0\n1' ]] || {
    printf 'cleanup did not retry a canonical failed holder status\n' >&2
    return 1
  }
  jq -e '
    .status == "failed" and .exit_status == 1 and
    .failure_stage == "project-guard-status"
  ' "$holder_publication_result/run-status.json" >/dev/null || {
    printf 'holder-status publication failure diverged from run evidence\n' >&2
    return 1
  }

  (
    RESULT_DIR="$publication_result"
    STACK_STARTED=false
    PROJECT_GUARD_HELD=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    local_write_count=0
    eval "$(declare -f write_run_status | \
      sed '1s/^write_run_status /write_run_status_original /')"
    write_run_status() {
      ((local_write_count += 1))
      write_run_status_original "$@" || return $?
      if ((local_write_count == 1)); then
        : >"$publication_ready"
        while [[ ! -e "$publication_release" ]]; do sleep 0.01; done
      fi
    }
    cleanup_security_processes() { :; }
    capture_evidence() { :; }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    cleanup
  ) >/dev/null 2>&1 &
  worker_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$publication_ready" ]] && break
    sleep 0.01
  done
  [[ -e "$publication_ready" ]] || return 1
  kill -TERM "$worker_pid" || return $?
  : >"$publication_release"
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 0 ]] || {
    printf 'cleanup changed status after its terminal commit: %s\n' \
      "$worker_status" >&2
    return 1
  }
  jq -e '
    .status == "passed" and .exit_status == 0 and
    .failure_stage == "none"
  ' "$publication_result/run-status.json" >/dev/null || {
    printf 'cleanup status diverged after its terminal commit\n' >&2
    return 1
  }

  (
    RESULT_DIR="$post_publication_result"
    STACK_STARTED=false
    PROJECT_GUARD_HELD=false
    RUN_STATUS=passed
    RUN_STAGE=complete
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    log_info() {
      if [[ "$*" == retained\ run\ evidence:* ]]; then
        : >"$post_publication_ready"
        while [[ ! -e "$post_publication_release" ]]; do sleep 0.01; done
      fi
    }
    cleanup_security_processes() { :; }
    capture_evidence() { :; }
    cleanup_source_snapshot_work_directory() { :; }
    release_project_guard() { :; }
    cleanup
  ) >/dev/null 2>&1 &
  worker_pid=$!
  for ((attempt = 0; attempt < 500; attempt++)); do
    [[ -e "$post_publication_ready" ]] && break
    sleep 0.01
  done
  [[ -e "$post_publication_ready" ]] || return 1
  kill -TERM "$worker_pid" || return $?
  : >"$post_publication_release"
  if wait "$worker_pid"; then
    worker_status=0
  else
    worker_status=$?
  fi
  [[ "$worker_status" == 0 ]] || {
    printf 'cleanup changed status after published terminal commit: %s\n' \
      "$worker_status" >&2
    return 1
  }
  jq -e '
    .status == "passed" and .exit_status == 0 and
    .failure_stage == "none"
  ' "$post_publication_result/run-status.json" >/dev/null || {
    printf 'cleanup status diverged after terminal publication\n' >&2
    return 1
  }
}

test_permanent_absence_log_capture_is_source_bounded() {
  local -r result_dir="$TEST_TMP_DIR/permanent-absence-log-capture"
  local -r oversized="$result_dir/oversized.log"
  local -r small="$result_dir/small.log"
  local -r failed="$result_dir/failed.log"
  local size=""
  local status=0

  mkdir -p -- "$result_dir"
  if (
    COMPOSE=(test-compose)
    run_bounded() {
      head -c "$((PERMANENT_ABSENCE_LOG_MAX_BYTES + 4096))" /dev/zero |
        tr '\0' x
    }
    capture_bounded_permanent_absence_logs \
      java-backend test-cursor "$oversized"
  ) >/dev/null 2>&1; then
    printf 'permanent-absence accepted an oversized live log stream\n' >&2
    return 1
  fi
  size="$(stat -c '%s' -- "$oversized")" || return $?
  [[ "$size" == "$PERMANENT_ABSENCE_LOG_MAX_BYTES" && \
    -f "$oversized" && ! -L "$oversized" ]] || {
    printf 'permanent-absence retained an unbounded failure log: %s\n' "$size" >&2
    return 1
  }

  (
    COMPOSE=(test-compose)
    run_bounded() { printf 'OBI remote-parent propagator enabled\n'; }
    capture_bounded_permanent_absence_logs \
      java-backend test-cursor "$small"
  ) || {
    printf 'permanent-absence rejected a bounded live log stream\n' >&2
    return 1
  }
  [[ "$(<"$small")" == 'OBI remote-parent propagator enabled' ]] || return 1

  if (
    COMPOSE=(test-compose)
    run_bounded() {
      printf 'partial log\n'
      return 77
    }
    capture_bounded_permanent_absence_logs \
      java-backend test-cursor "$failed"
  ) >/dev/null 2>&1; then
    printf 'permanent-absence ignored a failed log producer\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" == 77 && "$(<"$failed")" == 'partial log' ]] || {
    printf 'permanent-absence lost a bounded producer failure: %s\n' "$status" >&2
    return 1
  }
}

test_cleanup_compose_log_capture_is_source_bounded() {
  local -r result_dir="$TEST_TMP_DIR/cleanup-compose-log-capture"
  local -r exact="$result_dir/exact.log"
  local -r oversized="$result_dir/oversized.log"
  local -r too_many_lines="$result_dir/too-many-lines.log"
  local -r failed="$result_dir/failed.log"
  local -r capture_marker="$result_dir/capture-marker"
  local size=""
  local status=0

  mkdir -p -- "$result_dir"
  (
    COMPOSE=(test-compose)
    run_bounded() {
      head -c "$COMPOSE_LOG_MAX_BYTES" /dev/zero | tr '\0' x
    }
    capture_bounded_compose_logs "$exact"
  ) || {
    printf 'cleanup rejected Compose logs at the exact byte bound\n' >&2
    return 1
  }
  size="$(stat -c '%s' -- "$exact")" || return $?
  [[ "$size" == "$COMPOSE_LOG_MAX_BYTES" ]] || return 1

  if (
    COMPOSE=(test-compose)
    run_bounded() {
      head -c "$((COMPOSE_LOG_MAX_BYTES + 1))" /dev/zero | tr '\0' x
    }
    capture_bounded_compose_logs "$oversized"
  ) >/dev/null 2>&1; then
    printf 'cleanup accepted a max-plus-one Compose log stream\n' >&2
    return 1
  fi
  size="$(stat -c '%s' -- "$oversized")" || return $?
  [[ "$size" == "$COMPOSE_LOG_MAX_BYTES" ]] || {
    printf 'cleanup retained %s oversized Compose log bytes\n' "$size" >&2
    return 1
  }

  if (
    COMPOSE=(test-compose)
    run_bounded() {
      awk -v count="$((COMPOSE_LOG_MAX_LINES + 1))" \
        'BEGIN { for (i = 0; i < count; i++) print "x" }'
    }
    capture_bounded_compose_logs "$too_many_lines"
  ) >/dev/null 2>&1; then
    printf 'cleanup accepted too many Compose log lines\n' >&2
    return 1
  fi
  bounded_evidence_file \
    "$too_many_lines" "$COMPOSE_LOG_MAX_BYTES" \
    "$COMPOSE_LOG_MAX_LINES" || {
    printf 'cleanup retained more than the bounded Compose log prefix\n' >&2
    return 1
  }
  [[ "$(wc -l <"$too_many_lines")" == "$COMPOSE_LOG_MAX_LINES" ]] || return 1

  if (
    COMPOSE=(test-compose)
    run_bounded() {
      printf 'partial Compose log\n'
      return 77
    }
    capture_bounded_compose_logs "$failed"
  ) >/dev/null 2>&1; then
    printf 'cleanup ignored a failed Compose log producer\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" == 77 && "$(<"$failed")" == 'partial Compose log' ]] || {
    printf 'cleanup lost a bounded Compose producer failure: %s\n' "$status" >&2
    return 1
  }

  (
    RESULT_DIR="$result_dir"
    STACK_STARTED=false
    COMPOSE=(test-compose)
    run_bounded() { :; }
    capture_bounded_compose_logs() { : >"$capture_marker"; return 71; }
    curl() { :; }
    capture_evidence
  ) || return $?
  [[ -e "$capture_marker" ]] || {
    printf 'generic cleanup bypassed the bounded Compose log collector\n' >&2
    return 1
  }
  if compgen -G "$result_dir/*.capture.*" >/dev/null; then
    printf 'cleanup retained a Compose log capture temporary\n' >&2
    return 1
  fi
}

test_permanent_absence_readiness_is_source_bounded() {
  local -r root="$TEST_TMP_DIR/permanent-absence-readiness"
  local -r pattern='OBI remote-parent propagator enabled'
  local result_dir=""
  local retained_size=""
  local status=0

  result_dir="$root/success"
  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      printf '%s' "$pattern"
      head -c "$((PERMANENT_ABSENCE_LOG_MAX_BYTES - ${#pattern}))" \
        /dev/zero | tr '\0' x
    }
    wait_for_bounded_permanent_absence_log \
      java-backend "$pattern" test-readiness test-cursor
  ) || {
    printf 'permanent-absence rejected a bounded readiness record\n' >&2
    return 1
  }
  [[ ! -e "$result_dir/permanent-absence-readiness.log" ]] || return 1

  result_dir="$root/overflow"
  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      printf '%s\n' "$pattern"
      head -c "$PERMANENT_ABSENCE_LOG_MAX_BYTES" /dev/zero | tr '\0' x
    }
    wait_for_bounded_permanent_absence_log \
      java-backend "$pattern" test-readiness test-cursor
  ) >/dev/null 2>&1; then
    printf 'permanent-absence readiness accepted a max-plus-one stream\n' >&2
    return 1
  fi
  retained_size="$(stat --format='%s' -- \
    "$result_dir/permanent-absence-readiness.log")" || return $?
  [[ "$retained_size" == "$PERMANENT_ABSENCE_LOG_MAX_BYTES" ]] || {
    printf 'permanent-absence readiness retained %s overflow bytes\n' \
      "$retained_size" >&2
    return 1
  }

  result_dir="$root/producer-failure"
  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      printf '%s\n' "$pattern"
      return 77
    }
    wait_for_bounded_permanent_absence_log \
      java-backend "$pattern" test-readiness test-cursor
  ) >/dev/null 2>&1; then
    printf 'permanent-absence readiness accepted a failed producer\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" == 77 && \
    "$(<"$result_dir/permanent-absence-readiness.log")" == "$pattern" ]] || {
    printf 'permanent-absence readiness lost a bounded producer failure\n' >&2
    return 1
  }

  result_dir="$root/line-overflow"
  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    run_bounded() {
      printf '%s\n' "$pattern"
      awk -v count="$PERMANENT_ABSENCE_LOG_MAX_LINES" \
        'BEGIN { for (i = 0; i < count; i++) print "x" }'
    }
    wait_for_bounded_permanent_absence_log \
      java-backend "$pattern" test-readiness test-cursor
  ) >/dev/null 2>&1; then
    printf 'permanent-absence readiness accepted too many log lines\n' >&2
    return 1
  fi
  bounded_evidence_file \
    "$result_dir/permanent-absence-readiness.log" \
    "$PERMANENT_ABSENCE_LOG_MAX_BYTES" \
    "$PERMANENT_ABSENCE_LOG_MAX_LINES" || return $?
  [[ "$(wc -l <"$result_dir/permanent-absence-readiness.log")" == \
    "$PERMANENT_ABSENCE_LOG_MAX_LINES" ]] || return 1

  result_dir="$root/timeout"
  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    READINESS_TIMEOUT_SECONDS=2
    SECONDS=0
    run_bounded() { printf 'not-ready\n'; }
    sleep() { SECONDS=$((SECONDS + 1)); }
    if wait_for_bounded_permanent_absence_log \
      java-backend "$pattern" test-readiness test-cursor; then
      exit 1
    fi
    [[ "$(<"$result_dir/permanent-absence-readiness.log")" == not-ready ]]
  ) >/dev/null 2>&1 || {
    printf 'permanent-absence readiness timeout was not bounded and retained\n' >&2
    return 1
  }

  result_dir="$root/sleep-failure"
  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    READINESS_TIMEOUT_SECONDS=2
    SECONDS=0
    run_bounded() { printf 'not-ready\n'; }
    sleep() { return 42; }
    wait_for_bounded_permanent_absence_log \
      java-backend "$pattern" test-readiness test-cursor
  ) >/dev/null 2>&1; then
    printf 'permanent-absence readiness ignored a failed poll delay\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" == 42 && \
    ! -e "$result_dir/permanent-absence-readiness.log" ]] || {
    printf 'permanent-absence readiness lost failed poll delay status: %s\n' \
      "$status" >&2
    return 1
  }
}

test_permanent_absence_failure_stops_the_jvm_before_recovery() {
  local -r result_dir="$TEST_TMP_DIR/permanent-absence-recovery"
  local -r observed="$result_dir/observed"
  local control_status=0
  local absent_start_line=""
  local failure_line=""
  local stop_line=""
  local recovery_line=""

  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    TRANSPORT=getsockopt
    CONTEXT_PROPAGATION=tcp
    SCENARIO_VARIANT=original
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    : >"$observed"
    assert_project_docker_identity_unchanged() { :; }
    create_permanent_absence_global_marker() { :; }
    clear_pending_permanent_absence_recovery() { :; }
    run_disabled_control() {
      printf 'disabled\n' >>"$observed"
    }
    capture_control_response() {
      printf 'response:%s\n' "$1" >>"$observed"
    }
    invalidate_selected_transport() {
      SELECTED_TRANSPORT=""
      printf 'invalidate\n' >>"$observed"
    }
    date() {
      printf 'absence-cursor\n'
    }
    run_bounded() {
      printf 'bounded:%s\n' "$*" >>"$observed"
      return 0
    }
    wait_for_http() {
      printf 'http\n' >>"$observed"
    }
    wait_for_bounded_permanent_absence_log() {
      printf 'log\n' >>"$observed"
    }
    assert_runtime_contract() {
      printf 'runtime:%s\n' "$1" >>"$observed"
      [[ "$1" != permanent-absence ]] || return 47
    }
    recreate_instrumented_stack() {
      printf 'recovery:%s\n' "$2" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s\n' "$1" >>"$observed"
    }

    run_permanent_absence_control
  ) >/dev/null 2>&1; then
    printf 'permanent-absence control ignored its runtime validation failure\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == 47 && \
    ! -e "$result_dir/permanent-absence-recovery-required" ]] || {
    printf 'permanent-absence failure did not complete its recovery transaction\n' >&2
    return 1
  }
  absent_start_line="$(awk '/up --detach --force-recreate java-backend apache-proxy/ { print NR; exit }' "$observed")"
  failure_line="$(awk '/runtime:permanent-absence/ { print NR; exit }' "$observed")"
  stop_line="$(awk '/stop --timeout 10 apache-proxy java-backend$/ { print NR; exit }' "$observed")"
  recovery_line="$(awk '/recovery:post-permanent absence recovery/ { print NR; exit }' "$observed")"
  [[ "$absent_start_line" =~ ^[1-9][0-9]*$ && \
    "$failure_line" =~ ^[1-9][0-9]*$ && \
    "$stop_line" =~ ^[1-9][0-9]*$ && \
    "$recovery_line" =~ ^[1-9][0-9]*$ && \
    absent_start_line -lt failure_line && failure_line -lt stop_line && \
    stop_line -lt recovery_line ]] || {
    printf 'permanent-absence failure started OBI before stopping the absence JVM\n' >&2
    return 1
  }
}

test_permanent_absence_identity_and_log_evidence_is_bounded() {
  local -r result_dir="$TEST_TMP_DIR/permanent-absence-evidence"
  local -r identity_before="$result_dir/identity-before.txt"
  local -r identity_after="$result_dir/identity-after.txt"
  local -r identity_link="$result_dir/identity-link.txt"
  local -r logs="$result_dir/java.log"
  local -i line_count=0

  mkdir -p -- "$result_dir"
  printf '%s\n' \
    'container_id=0123456789abcdef' \
    'host_pid=4242' \
    'started_at=2026-08-11T00:00:00Z' \
    >"$identity_before"
  printf '%s\n' \
    'container_id=0123456789abcdef' \
    'host_pid=4242' \
    'started_at=2026-08-11T00:00:00Z' \
    >"$identity_after"
  assert_runtime_identity_unchanged "$identity_before" "$identity_after" || {
    printf 'permanent-absence rejected one unchanged JVM identity\n' >&2
    return 1
  }

  printf '%s\n' \
    'container_id=0123456789abcdef' \
    'host_pid=4243' \
    'started_at=2026-08-11T00:00:00Z' \
    >"$identity_after"
  if assert_runtime_identity_unchanged "$identity_before" "$identity_after" \
    >/dev/null 2>&1; then
    printf 'permanent-absence accepted a replaced JVM identity\n' >&2
    return 1
  fi
  ln -s -- "$identity_before" "$identity_link"
  if assert_runtime_identity_unchanged "$identity_link" "$identity_before" \
    >/dev/null 2>&1; then
    printf 'permanent-absence accepted symlink identity evidence\n' >&2
    return 1
  fi

  printf 'OBI remote-parent propagator enabled\n' >"$logs"
  for ((line_count = 1;
    line_count < PERMANENT_ABSENCE_REMOTE_PARENT_LOG_MAX;
    line_count++)); do
    printf 'OBI remote-parent bridge unavailable retry=%d\n' "$line_count" \
      >>"$logs"
  done
  assert_permanent_absence_logs_are_bounded "$logs" || {
    printf 'permanent-absence rejected logs at the exact bound\n' >&2
    return 1
  }
  printf 'OBI remote-parent bridge unavailable retry=overflow\n' >>"$logs"
  if assert_permanent_absence_logs_are_bounded "$logs" >/dev/null 2>&1; then
    printf 'permanent-absence accepted logs beyond the fixed bound\n' >&2
    return 1
  fi

  printf 'OBI remote-parent propagator enabled\nOBI remote-parent ' >"$logs"
  for ((line_count = 0; line_count < 1025; line_count++)); do
    printf 'x' >>"$logs"
  done
  printf '\n' >>"$logs"
  if assert_permanent_absence_logs_are_bounded "$logs" >/dev/null 2>&1; then
    printf 'permanent-absence accepted an overlong diagnostic line\n' >&2
    return 1
  fi

  printf '%s\n' \
    'OBI remote-parent propagator enabled' \
    'OBI remote-parent provider ready' \
    >"$logs"
  if assert_permanent_absence_logs_are_bounded "$logs" >/dev/null 2>&1; then
    printf 'permanent-absence accepted false provider readiness\n' >&2
    return 1
  fi
  printf '%s\n' \
    'OBI remote-parent propagator enabled' \
    'OBI Java instrumentation ready' \
    >"$logs"
  if assert_permanent_absence_logs_are_bounded "$logs" >/dev/null 2>&1; then
    printf 'permanent-absence accepted false instrumentation readiness\n' >&2
    return 1
  fi
}

test_permanent_absence_refuses_recovery_if_jvm_stop_fails() {
  local -r result_dir="$TEST_TMP_DIR/permanent-absence-stop-failure"
  local -r observed="$result_dir/observed"
  local control_status=0
  local marker_metadata=""

  mkdir -p -- "$result_dir"
  if (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    TRANSPORT=getsockopt
    CONTEXT_PROPAGATION=tcp
    SCENARIO_VARIANT=original
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    : >"$observed"
    assert_project_docker_identity_unchanged() { :; }
    create_permanent_absence_global_marker() { :; }
    clear_pending_permanent_absence_recovery() { :; }
    run_disabled_control() { :; }
    capture_control_response() { :; }
    invalidate_selected_transport() { SELECTED_TRANSPORT=""; }
    date() { printf 'absence-cursor\n'; }
    run_bounded() {
      printf 'bounded:%s\n' "$*" >>"$observed"
      if [[ "$*" == \
        '60 test-compose stop --timeout 10 apache-proxy java-backend' ]]; then
        return 73
      fi
      return 0
    }
    wait_for_http() { :; }
    wait_for_bounded_permanent_absence_log() { :; }
    assert_runtime_contract() { return 47; }
    recreate_instrumented_stack() {
      printf 'recovery:%s\n' "$2" >>"$observed"
    }

    run_permanent_absence_control
  ) >/dev/null 2>&1; then
    printf 'permanent-absence ignored a runtime failure and failed JVM stop\n' >&2
    return 1
  else
    control_status=$?
  fi
  [[ "$control_status" == 47 && \
    -f "$result_dir/permanent-absence-recovery-required" && \
    ! -L "$result_dir/permanent-absence-recovery-required" ]] || {
    printf 'permanent-absence lost its original failure or recovery marker\n' >&2
    return 1
  }
  marker_metadata="$(stat -c '%u:%a:%h:%s' -- \
    "$result_dir/permanent-absence-recovery-required")" || return $?
  [[ "$marker_metadata" == "$(id -u):600:1:18" ]] || {
    printf 'permanent-absence recovery marker metadata changed: %s\n' \
      "$marker_metadata" >&2
    return 1
  }
  grep -Fxq \
    'bounded:60 test-compose stop --timeout 10 apache-proxy java-backend' \
    "$observed" || {
    printf 'permanent-absence did not attempt to stop the absence JVM\n' >&2
    return 1
  }
  if grep -Fq 'recovery:' "$observed"; then
    printf 'permanent-absence started OBI while the absence JVM might be running\n' >&2
    return 1
  fi
}

test_permanent_absence_refuses_jvm_stop_after_docker_drift() {
  local -r result_dir="$TEST_TMP_DIR/permanent-absence-docker-drift"
  local -r marker="$result_dir/permanent-absence-recovery-required"
  local -r mutation="$result_dir/compose-mutation"
  local status=0

  mkdir -p -- "$result_dir"
  (umask 077; printf 'recovery_required\n' >"$marker")
  if (
    COMPOSE=(test-compose)
    assert_project_docker_identity_unchanged() { return 88; }
    run_bounded() { printf '%s\n' "$*" >"$mutation"; }
    stop_permanent_absence_jvm
  ) >/dev/null 2>&1; then
    printf 'permanent-absence stopped a JVM after Docker identity drift\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" == 88 && -f "$marker" && ! -L "$marker" && \
    "$(<"$marker")" == recovery_required && \
    ! -e "$mutation" && ! -L "$mutation" ]] || {
    printf 'Docker identity drift mutated Compose or cleared recovery state\n' >&2
    return 1
  }
}

test_permanent_absence_refuses_stale_evidence_before_mutation() {
  local stale_name=""
  local result_dir=""
  local mutation=""

  for stale_name in \
    permanent-absence-recovery-required \
    permanent-absence-lifetime.txt; do
    result_dir="$TEST_TMP_DIR/permanent-absence-stale-$stale_name"
    mutation="$result_dir/mutated"
    mkdir -p -- "$result_dir"
    printf 'stale\n' >"$result_dir/$stale_name"
    if (
      RESULT_DIR="$result_dir"
      TRANSPORT=auto
      CONTEXT_PROPAGATION=tcp
      SCENARIO_VARIANT=original
      assert_project_docker_identity_unchanged() { :; }
      run_disabled_control() { : >"$mutation"; }
      run_permanent_absence_control
    ) >/dev/null 2>&1; then
      printf 'permanent-absence accepted stale evidence: %s\n' \
        "$stale_name" >&2
      return 1
    fi
    [[ ! -e "$mutation" && ! -L "$mutation" ]] || {
      printf 'permanent-absence mutated the stack after stale evidence: %s\n' \
        "$stale_name" >&2
      return 1
    }
  done
}

test_late_attach_recycles_only_apache_after_readiness() {
  local -r observed="$TEST_TMP_DIR/late-attach.observed"
  local -r expected="$TEST_TMP_DIR/late-attach.expected"

  (
    COMPOSE=(test-compose)
    date() {
      printf 'late-attach-cursor\n'
    }
    stop_obi_for_no_state_control() {
      BRIDGE_RUNNING=false
      printf 'stop-obi:%s\n' "$1" >>"$observed"
    }
    run_bounded() {
      printf 'compose:%s\n' "$*" >>"$observed"
    }
    wait_for_log() {
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    assert_runtime_contract() {
      printf 'runtime:%s\n' "$1" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    wait_for_apache_instrumentation_drain() {
      printf 'apache-drain:%s\n' "$1" >>"$observed"
    }
    wait_for_java_duplicate_suppression() {
      printf 'suppression:%s\n' "$(basename -- "$1")" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:%s\n' "$1" "$SCENARIO_VARIANT" >>"$observed"
    }

    run_late_attach_control
  ) || {
    printf 'late-attach readiness-order probe failed\n' >&2
    return 1
  }

  printf '%s\n' \
    'stop-obi:late-attach' \
    'compose:120 test-compose up --detach --force-recreate java-backend apache-proxy' \
    'http:OBI-absent HTTPS path' \
    'log:OBI-absent external extension:' \
    'runtime:obi-absent' \
    'scenario:fail-open:obi-absent' \
    'scenario:w3c-only:obi-absent' \
    'compose:120 test-compose up --detach obi' \
    'log:late-attach OBI remote-parent bridge:late-attach-cursor' \
    'log:late-attached Java helper:late-attach-cursor' \
    'log:late-attached Java instrumentation:late-attach-cursor' \
    'transport' \
    'compose:60 test-compose stop --timeout 10 apache-proxy' \
    'apache-drain:late-attach' \
    'compose:120 test-compose up --detach --force-recreate --no-deps apache-proxy' \
    'log:late-attach Apache instrumentation:late-attach-cursor' \
    'apache:late-attach' \
    'http:late-attach recovered HTTPS path' \
    'suppression:duplicate-suppression-late-attach-recovery.prom' \
    'scenario:restart:late-attach-recovery' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'late attach did not isolate the post-attach Apache pool\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_control_response_normalizes_connection_diagnostics() {
  local -r instrumented="$TEST_TMP_DIR/instrumented-control.json"
  local -r uninstrumented="$TEST_TMP_DIR/uninstrumented-control.json"
  local -r instrumented_normalized="$TEST_TMP_DIR/instrumented-control.normalized.json"
  local -r uninstrumented_normalized="$TEST_TMP_DIR/uninstrumented-control.normalized.json"

  printf '%s\n' \
    '{"marker":"instrumentation-control","backend_connection_id":17,"backend_remote_port":41000,"backend_socket_fd":21,"tls_read_events":7,"tls_read_bytes":4096,"tls_protocol":"TLSv1.3","secure":true}' \
    >"$instrumented"
  printf '%s\n' \
    '{"marker":"instrumentation-control","backend_connection_id":3,"backend_remote_port":42000,"backend_socket_fd":-1,"tls_read_events":-1,"tls_read_bytes":-1,"tls_protocol":"TLSv1.3","secure":true}' \
    >"$uninstrumented"

  normalize_control_response "$instrumented" "$instrumented_normalized"
  normalize_control_response "$uninstrumented" "$uninstrumented_normalized"
  cmp "$instrumented_normalized" "$uninstrumented_normalized" || {
    printf 'control response normalization retained recreated connection identity\n' >&2
    return 1
  }
  grep -Fq '"backend_connection_id":0' "$instrumented_normalized"
  grep -Fq '"backend_remote_port":0' "$instrumented_normalized"
  grep -Fq '"backend_socket_fd":0' "$instrumented_normalized"
  grep -Fq '"tls_read_events":0' "$instrumented_normalized"
  grep -Fq '"tls_read_bytes":0' "$instrumented_normalized"
  grep -Fq '"tls_protocol":"TLSv1.3"' "$instrumented_normalized"
}

test_required_read_failures_do_not_publish_evidence() {
  local -r response_dir="$TEST_TMP_DIR/control-response-read-failure"
  local -r identity_dir="$TEST_TMP_DIR/runtime-identity-read-failure"
  local -r normalize_marker="$response_dir/normalized"
  local -r inspect_marker="$identity_dir/inspected"
  local read_status=0

  mkdir -p -- "$response_dir" "$identity_dir"
  if (
    RESULT_DIR="$response_dir"
    curl() {
      local output=""

      while (($# > 0)); do
        if [[ "$1" == "--output" ]]; then
          output="$2"
          shift 2
          continue
        fi
        shift
      done
      printf '{"marker":"instrumentation-control"}\n' >"$output"
      printf '200\n'
      return 23
    }
    normalize_control_response() {
      : >"$normalize_marker"
    }

    capture_control_response read-failure
  ) >/dev/null 2>&1; then
    printf 'control response ignored a failed partial HTTP read\n' >&2
    return 1
  else
    read_status=$?
  fi
  [[ "$read_status" == "23" && ! -e "$normalize_marker" ]] || {
    printf 'control response published evidence after a failed read\n' >&2
    return 1
  }

  if (
    COMPOSE=(test-compose)
    run_bounded() {
      case " $* " in
        *" ps --quiet java-backend "*)
          printf 'java-container\n'
          return 23
          ;;
        *" docker inspect "*)
          : >"$inspect_marker"
          printf 'java-container 101 2026-07-27T00:00:00Z\n'
          ;;
      esac
    }

    capture_service_runtime_identity \
      java-backend "$identity_dir/identity.txt"
  ) >/dev/null 2>&1; then
    printf 'runtime identity ignored a failed container lookup\n' >&2
    return 1
  else
    read_status=$?
  fi
  [[ "$read_status" == "23" &&
    ! -e "$inspect_marker" &&
    ! -e "$identity_dir/identity.txt" ]] || {
    printf 'runtime identity published evidence after a failed lookup\n' >&2
    return 1
  }
}

test_helper_attach_failure_control_restores_and_preserves_status() {
  run_case() (
    local -r mode="$1"
    local -r expected_status="$2"
    local -r result_dir="$TEST_TMP_DIR/helper-attach-control-$mode"
    local -r observed="$result_dir/observed.log"
    local -i fault_probe_calls=0
    local status=0

    RESULT_DIR="$result_dir"
    CERT_DIR="$result_dir/certs"
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    TRANSPORT=getsockopt
    SELECTED_TRANSPORT=getsockopt
    CONTEXT_PROPAGATION=tcp
    SCENARIO_SEED=11
    SCENARIO_VARIANT=""
    TLS_PROTOCOL=TLSv1.3
    JAVA_TOOL_OPTIONS_VALUE="-javaagent:/otel/official-javaagent.jar"
    mkdir -p -- "$RESULT_DIR" "$CERT_DIR"
    printf 'stale-selection\n' >"$RESULT_DIR/java-transport-configuration.txt"
    : >"$observed"

    log_info() {
      printf 'info:%s\n' "$*" >>"$observed"
    }
    log_warn() {
      printf 'warn:%s\n' "$*" >>"$observed"
      [[ "$mode" != "failure" ]] || return 17
    }
    log_error() {
      printf 'error:%s\n' "$*" >>"$observed"
      [[ "$mode" != "failure" ]] || return 18
    }
    run_disabled_control() {
      printf 'disabled:%s:%s\n' "$SCENARIO_VARIANT" "$SCENARIO_SEED" >>"$observed"
    }
    recreate_instrumented_stack() {
      printf 'recreate:%s:%s:%s\n' "$1" "$2" "$3" >>"$observed"
      if [[ "$2" == "helper attach failure cleanup" && "$mode" == "failure" ]]; then
        return 29
      fi
    }
    capture_control_response() {
      printf 'response:%s\n' "$1" >>"$observed"
      printf '{"status":"ok"}\n' >"$RESULT_DIR/$1-response.json"
      printf '{"status":"ok"}\n' >"$RESULT_DIR/$1-response.normalized.json"
      printf '200\n' >"$RESULT_DIR/$1-response.status"
    }
    capture_service_runtime_identity() {
      local -r service="$1"
      local -r output="$2"
      local container_id="$service-fixed"
      local host_pid=4242
      local started_at="2026-07-24T18:00:00Z"

      if [[ "$service" == "java-backend" && "$output" == *"-recovery.txt" ]]; then
        container_id="java-recovered"
        host_pid=4343
        started_at="2026-07-24T18:01:00Z"
      elif [[ "$service" == "java-backend" ]]; then
        container_id="java-failed"
      fi
      printf 'identity:%s:%s\n' "$service" "$(basename -- "$output")" >>"$observed"
      printf 'container_id=%s\nhost_pid=%s\nstarted_at=%s\n' \
        "$container_id" "$host_pid" "$started_at" >"$output"
    }
    fetch_obi_metrics() {
      printf '# attach error absent\n' >"$1"
      printf 'metrics-before\n' >>"$observed"
    }
    run_bounded() {
      printf 'bounded:options=%s:%s\n' "$JAVA_TOOL_OPTIONS_VALUE" "$*" >>"$observed"
    }
    date() {
      printf 'helper-attach-cursor\n'
    }
    wait_for_log() {
      printf 'wait-log:%s:%s:%s\n' "$1" "$3" "${4:-}" >>"$observed"
    }
    wait_for_http() {
      printf 'wait-http:%s\n' "$2" >>"$observed"
    }
    wait_for_java_attach_error_total() {
      printf 'metric-wait:%s:%s:%s:%s\n' "$1" "$2" "$4" "${5:-}" >>"$observed"
      printf '%s\n' \
        "obi_instrumentation_errors_total{error_type=\"attaching_java_agent\",process_name=\"java\"} $1" \
        >"$3"
    }
    write_metrics_delta() {
      printf 'metric-delta\n' >>"$observed"
      : >"$3"
    }
    assert_selected_transport() {
      printf 'transport:%s\n' "${1:-}" >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:%s:%s:%s:%s:%s\n' \
        "$1" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "$SCENARIO_VARIANT" \
        >>"$observed"
      if [[ "$SCENARIO_VARIANT" == "helper-unavailable" ]]; then
        [[ -z "$SELECTED_TRANSPORT" &&
          ! -e "$RESULT_DIR/java-transport-configuration.txt" ]] || return 31
        printf 'fault-selection:absent\n' >>"$observed"
        ((fault_probe_calls += 1))
      fi
      if [[ "$mode" == "failure" && "$fault_probe_calls" == "2" ]]; then
        return 23
      fi
    }
    capture_service_logs_since() {
      printf 'logs:%s:%s\n' "$1" "$2" >>"$observed"
      if [[ "$1" == "obi" ]]; then
        printf '%s\n' \
          'level=INFO msg="injecting OpenTelemetry eBPF instrumentation for Java process" pid=4242' \
          "level=ERROR msg=\"couldn't attach OpenTelemetry eBPF Java Agent\" pid=4242" \
          "level=WARN msg=\"unable to attach java agent to process, Java TLS telemetry will not work\" pid=4242" \
          >"$3"
      else
        printf '%s\n' \
          'OBI remote-parent compatibility distribution=otel,supported=true' \
          'OBI remote-parent propagator enabled' \
          'reason=bridge_lookup_missing' \
          >"$3"
      fi
    }
    curl() {
      printf 'unavailable\n'
    }
    assert_runtime_contract() {
      printf 'runtime:%s\n' "$1" >>"$observed"
    }
    capture_java_diagnostics() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'diagnostics\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    assert_sanitized_java_diagnostics() {
      printf 'diagnostics-assert:%s\n' "$1" >>"$observed"
    }

    set +e
    (
      set -Eeuo pipefail
      run_helper_attach_failure_control
    )
    status=$?
    set -e
    [[ "$status" == "$expected_status" ]] || {
      printf 'helper attach control mode=%s returned %d, wanted %d\n' \
        "$mode" "$status" "$expected_status" >&2
      return 1
    }
    awk '
      /^runtime:helper-attach-fault$/ && !runtime { runtime = NR }
      /^logs:obi:helper-attach-cursor$/ && !obi_log { obi_log = NR }
      /^logs:java-backend:helper-attach-cursor$/ && !java_log { java_log = NR }
      /^scenario:helper-attach-failure:/ && !scenario { scenario = NR }
      END {
        exit !(runtime && obi_log && java_log && scenario &&
          runtime < scenario && obi_log < scenario && java_log < scenario)
      }
    ' "$observed" || {
      printf 'helper attach control did not preserve fault evidence before traffic\n' >&2
      return 1
    }
    [[ -s "$RESULT_DIR/helper-attach-failure-obi.log" &&
      -s "$RESULT_DIR/helper-attach-failure-java.log" ]] || {
      printf 'helper attach control did not retain the fault logs\n' >&2
      return 1
    }
    [[ "$(grep -c '^fault-selection:absent$' "$observed")" == "2" ]] || {
      printf 'helper attach control retained stale transport selection evidence\n' >&2
      return 1
    }

    if [[ "$mode" == "success" ]]; then
      [[ "$(grep -c '^transport:' "$observed")" == "1" ]]
      grep -Fqx 'transport:getsockopt' "$observed"
      grep -Fqx 'disabled:helper-attach-bridge-disabled:12' "$observed"
      grep -Fq \
        "bounded:options=$HELPER_ATTACH_FAILURE_JAVA_TOOL_OPTIONS:30 test-compose config" \
        "$observed"
      grep -Fq \
        "bounded:options=$HELPER_ATTACH_FAILURE_JAVA_TOOL_OPTIONS:180 test-compose up --detach --force-recreate java-backend apache-proxy" \
        "$observed"
      grep -Fqx \
        'scenario:helper-attach-failure:false:full:none:helper-unavailable:helper-unavailable' \
        "$observed"
      grep -Fqx \
        'scenario:w3c:false:full:none:helper-unavailable:helper-unavailable' \
        "$observed"
      [[ "$(grep -c ':helper-unavailable:helper-unavailable$' "$observed")" == "2" ]]
      grep -Fqx \
        'scenario:basic:::::helper-attach-recovery' \
        "$observed"
      grep -Fq \
        'bounded:options=-javaagent:/otel/official-javaagent.jar:180 test-compose up --detach --force-recreate java-backend apache-proxy' \
        "$observed"
      grep -Fqx 'apache:helper-attach-recovery' "$observed"
      if grep -Fq 'helper attach failure cleanup' "$observed"; then
        printf 'successful helper attach control ran EXIT restoration\n' >&2
        return 1
      fi
    else
      if grep -q '^transport:' "$observed"; then
        printf 'helper-unavailable phase required a Java-selected transport\n' >&2
        return 1
      fi
      [[ "$(grep -c ':helper-unavailable:helper-unavailable$' "$observed")" == "2" ]]
      grep -Fqx \
        'recreate:tcp:helper attach failure cleanup:getsockopt' \
        "$observed" || {
        printf 'failed helper attach control omitted cleanup restoration\n' >&2
        return 1
      }
      grep -Fq 'could not restore the instrumented stack' "$observed" || {
        printf 'restoration failure was not retained as evidence\n' >&2
        return 1
      }
    fi
  )

  run_case success 0
  run_case failure 23

  (
    local -r marker="$TEST_TMP_DIR/helper-attach-precondition-restored"
    local status=0

    BRIDGE_RUNNING=false
    TRANSPORT=getsockopt
    CONTEXT_PROPAGATION=tcp
    SCENARIO_SEED=1
    RESULT_DIR="$TEST_TMP_DIR/helper-attach-precondition"
    mkdir -p -- "$RESULT_DIR"
    log_error() {
      :
    }
    recreate_instrumented_stack() {
      : >"$marker"
    }
    set +e
    (
      set -Eeuo pipefail
      run_helper_attach_failure_control
    )
    status=$?
    set -e
    [[ "$status" == "1" && ! -e "$marker" ]] || {
      printf 'helper attach precondition failure mutated the Compose stack\n' >&2
      return 1
    }
  )
}

test_restart_readiness_uses_log_cursor() {
  local fake_compose="$TEST_TMP_DIR/fake-compose"

  printf '%s\n' \
    '#!/usr/bin/env sh' \
    'case " $* " in' \
    '  *" --since "*) printf "%s\n" "new bridge ready" ;;' \
    '  *) printf "%s\n" "old unrelated log" ;;' \
    'esac' >"$fake_compose"
  chmod 0755 "$fake_compose"

  (
    COMPOSE=("$fake_compose")
    READINESS_TIMEOUT_SECONDS=1
    wait_for_log obi "new bridge ready" restart "2026-07-21T00:00:00.000000000Z"
  ) >/dev/null 2>&1 || {
    printf 'restart readiness did not pass a post-restart log cursor\n' >&2
    return 1
  }
}

test_failed_log_read_cannot_satisfy_readiness() {
  if (
    COMPOSE=(test-compose)
    READINESS_TIMEOUT_SECONDS=1
    SECONDS=0
    run_bounded() {
      printf 'new bridge ready\n'
      return 42
    }
    sleep() {
      SECONDS="$((SECONDS + 1))"
    }

    wait_for_log obi "new bridge ready" restart "restart-cursor"
  ) >/dev/null 2>&1; then
    printf 'failed partial log read satisfied readiness\n' >&2
    return 1
  fi
}

test_standalone_restart_waits_for_apache_instrumentation() {
  local -r observed="$TEST_TMP_DIR/restart-readiness.observed"
  local -r expected="$TEST_TMP_DIR/restart-readiness.expected"
  local -r result_dir="$TEST_TMP_DIR/restart-readiness-result"
  local -r provider_ready="$result_dir/provider-ready"
  local -r date_calls="$result_dir/date-calls"

  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"
  (
    RESULT_DIR="$result_dir"
    SCENARIO=restart
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=true
    SELECTED_TRANSPORT=getsockopt
    date() {
      local -i call_count=0

      printf 'call\n' >>"$date_calls"
      call_count="$(wc -l <"$date_calls")"
      case "$call_count" in
        1)
          printf 'cursor:restart\n' >>"$observed"
          printf 'restart-cursor\n'
          ;;
        *) return 1 ;;
      esac
    }
    run_bounded() {
      [[ "$BRIDGE_RUNNING" == "false" &&
        -z "$SELECTED_TRANSPORT" &&
        ! -e "$RESULT_DIR/java-transport-configuration.txt" &&
        -e "$RESULT_DIR/java-selected-transport-configuration.txt" ]] || return 31
      printf 'compose:%s\n' "$*" >>"$observed"
      if [[ " $* " == *" restart --timeout 10 obi "* ]]; then
        : >"$provider_ready"
        printf 'provider-ready\n' >>"$observed"
      fi
    }
    wait_for_log() {
      if [[ "$3" == "restarted Java bridge provider" ]]; then
        [[ -f "$provider_ready" && "$4" == "restart-cursor" ]] || return 1
      fi
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    sleep() {
      printf 'sleep:%s\n' "$1" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    wait_for_java_duplicate_suppression() {
      [[ -f "$provider_ready" ]] || return 1
      printf 'suppression:%s\n' "$(basename -- "$1")" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s\n' "$1" >>"$observed"
    }

    execute_requested_scenarios
  ) || {
    printf 'standalone restart readiness-order probe failed\n' >&2
    return 1
  }
  [[ ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'standalone restart retained stale current-generation selection evidence\n' >&2
    return 1
  }

  printf '%s\n' \
    'cursor:restart' \
    'compose:60 test-compose restart --timeout 10 obi' \
    'provider-ready' \
    'log:restarted OBI remote-parent bridge:restart-cursor' \
    'apache:restart' \
    'http:restarted Java provider probe' \
    "sleep:$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" \
    'suppression:duplicate-suppression-restart.prom' \
    'log:restarted Java bridge provider:restart-cursor' \
    'transport' \
    'scenario:restart' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'standalone restart resumed before Apache instrumentation readiness\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_restart_fault_recovery_waits_for_apache_instrumentation() {
  local -r fake_compose="$TEST_TMP_DIR/restart-success-compose"
  local -r provider_ready="$TEST_TMP_DIR/restart-success.provider-ready"
  local -r observed="$TEST_TMP_DIR/restart-success.observed"
  local -r result_dir="$TEST_TMP_DIR/restart-success-result"
  local -r date_calls="$result_dir/date-calls"

  cat >"$fake_compose" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'compose:%s\n' "$*" >>"$RESTART_SUCCESS_OBSERVED"
case " $* " in
  *" stop --timeout 5 obi "*)
    [[ ! -e "$RESTART_SUCCESS_RESULT_DIR/java-transport-configuration.txt" ]]
    [[ "$(<"$RESTART_SUCCESS_RESULT_DIR/java-selected-transport-configuration.txt")" == "retained" ]]
    printf 'transport-invalidated\n' >>"$RESTART_SUCCESS_OBSERVED"
    ;;
  *" up --detach obi "*)
    : >"$RESTART_SUCCESS_PROVIDER_READY"
    printf 'provider-ready\n' >>"$RESTART_SUCCESS_OBSERVED"
    ;;
  *" scenario --scenario restart-fault "*)
    control="$RESTART_SUCCESS_CONTROL"
    printf 'traffic:before-stop\n' >>"$RESTART_SUCCESS_OBSERVED"
    printf 'pre-stop-ready\n' >"$control/.pre-stop-ready"
    mv -- "$control/.pre-stop-ready" "$control/pre-stop-ready"
    for _ in {1..500}; do
      [[ -f "$control/obi-stopped" ]] && break
      sleep 0.01
    done
    cmp -s -- "$control/obi-stopped" <(printf 'obi-stopped\n')
    printf 'traffic:obi-stopped\n' >>"$RESTART_SUCCESS_OBSERVED"
    printf 'stopped-traffic-complete\n' >"$control/.stopped-traffic-complete"
    mv -- "$control/.stopped-traffic-complete" "$control/stopped-traffic-complete"
    for _ in {1..500}; do
      [[ -f "$control/obi-ready" ]] && break
      sleep 0.01
    done
    cmp -s -- "$control/obi-ready" <(printf 'obi-ready\n')
    printf 'traffic:after-restart\n' >>"$RESTART_SUCCESS_OBSERVED"
    printf 'post-restart-traffic-complete\n' >"$control/.post-restart-traffic-complete"
    mv -- \
      "$control/.post-restart-traffic-complete" \
      "$control/post-restart-traffic-complete"
    printf '{}\n'
    ;;
esac
EOF
  chmod 0755 "$fake_compose"

  (
    export RESTART_SUCCESS_CONTROL="$result_dir/restart-control"
    export RESTART_SUCCESS_OBSERVED="$observed"
    export RESTART_SUCCESS_PROVIDER_READY="$provider_ready"
    export RESTART_SUCCESS_RESULT_DIR="$result_dir"
    RESULT_DIR="$result_dir"
    COMPOSE=("$fake_compose")
    BRIDGE_RUNNING=true
    READINESS_TIMEOUT_SECONDS=5
    SCENARIO_VARIANT=""
    SCENARIO_SEED=1
    TLS_PROTOCOL=TLSv1.3
    restart_log_cursor=""
    mkdir -p -- "$RESULT_DIR"
    printf 'current\n' >"$RESULT_DIR/java-transport-configuration.txt"
    printf 'retained\n' >"$RESULT_DIR/java-selected-transport-configuration.txt"
    record_restart_control_event() {
      printf 'event-timestamp %s\n' "$2" >>"$1/events.log"
    }
    date() {
      local -i call_count=0

      printf 'call\n' >>"$date_calls"
      call_count="$(wc -l <"$date_calls")"
      [[ "$call_count" == "1" ]] || return 1
      printf 'cursor:restart-success-cursor\n' >>"$observed"
      printf 'restart-success-cursor\n'
    }
    wait_for_log() {
      if [[ "$3" == "OBI bridge restarted during traffic" ]]; then
        restart_log_cursor="${4:-}"
      fi
      if [[ "$3" == "Java bridge reconfigured before restart traffic resumes" ]]; then
        [[ -f "$provider_ready" &&
          -n "$restart_log_cursor" &&
          "${4:-}" == "$restart_log_cursor" ]] || return 1
      fi
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    sleep() {
      printf 'sleep:%s\n' "$1" >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    wait_for_java_duplicate_suppression() {
      [[ -f "$provider_ready" ]] || return 1
      printf 'suppression:%s\n' "$(basename -- "$1")" >>"$observed"
    }
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'capture:%s\n' "$1" >>"$observed"
    }
    capture_java_diagnostics() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf 'fixture\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
      printf 'diagnostics:%s\n' "$1" >>"$observed"
    }
    write_java_diagnostics_delta() {
      : >"$3"
      printf 'delta\n' >>"$observed"
    }
    assert_restart_fault_diagnostics() {
      [[ "$1" == "$RESULT_DIR/phases/restart-fault-after/java-diagnostics.delta" &&
        "$2" == "32" &&
        "$3" == "3" &&
        "$4" == "$RESULT_DIR/restart-fault-diagnostics.txt" ]] || return 1
      printf 'diagnostics-assertion\n' >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s:%s\n' "$1" "$SCENARIO_VARIANT" >>"$observed"
    }

    run_restart_during_traffic_control
  ) || {
    printf 'restart-fault recovery readiness-order probe failed\n' >&2
    return 1
  }

  awk '
    $0 == "traffic:before-stop" { before = NR }
    $0 == "transport-invalidated" { invalidated = NR }
    $0 == "compose:stop --timeout 5 obi" { stopped = NR }
    $0 == "traffic:obi-stopped" { outage = NR }
    $0 == "compose:up --detach obi" { started = NR }
    $0 == "provider-ready" { provider_ready = NR }
    /^cursor:/ { cursor_line[substr($0, 8)] = NR }
    /^log:OBI bridge restarted during traffic:/ {
      bridge = NR
      restart_cursor = substr($0, length("log:OBI bridge restarted during traffic:") + 1)
    }
    $0 ~ /^sleep:[0-9]+$/ { settle = NR }
    /^log:Java bridge reconfigured before restart traffic resumes:/ {
      provider = NR
      provider_cursor = substr($0, length("log:Java bridge reconfigured before restart traffic resumes:") + 1)
    }
    $0 == "transport" { transport = NR }
    $0 == "apache:restart-fault-recovery" { readiness = NR }
    $0 == "traffic:after-restart" { recovered = NR }
    $0 == "capture:restart-fault-after" { capture = NR }
    $0 == "suppression:duplicate-suppression-restart-fault-recovery.prom" {
      suppression = NR
    }
    $0 == "scenario:restart:restart-recovery" { scenario = NR }
    END {
      exit before > 0 && stopped > before && invalidated > stopped &&
        outage > invalidated &&
        cursor_line[restart_cursor] > outage &&
        cursor_line[restart_cursor] < started &&
        started > outage && provider_ready > started && bridge > provider_ready &&
        settle > bridge && readiness > settle && suppression > readiness &&
        provider_cursor == restart_cursor &&
        provider > suppression && transport > provider &&
        recovered > transport && capture > recovered &&
        scenario > capture ? 0 : 1
    }
  ' "$observed" || {
    printf 'restart-fault recovery lifecycle was not causally ordered\n' >&2
    return 1
  }
  grep -Fqx "sleep:$JAVA_PROVIDER_RETRY_SETTLE_SECONDS" "$observed" || {
    printf 'restart-fault recovery skipped the Java provider retry interval\n' >&2
    return 1
  }
  [[ ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'restart-fault retained stale current transport evidence\n' >&2
    return 1
  }
  awk '
    $2 == "observed:pre-stop-ready" { pre = NR }
    $2 == "released:obi-stopped" { stopped = NR }
    $2 == "observed:stopped-traffic-complete" { outage = NR }
    $2 == "released:obi-ready" { ready = NR }
    $2 == "observed:post-restart-traffic-complete" { recovered = NR }
    END {
      exit pre > 0 && stopped > pre && outage > stopped &&
        ready > outage && recovered > ready ? 0 : 1
    }
  ' "$result_dir/restart-control/events.log" || {
    printf 'restart-fault control evidence omitted a lifecycle phase\n' >&2
    return 1
  }
}

test_restart_fault_rejects_traffic_ending_before_first_barrier() {
  local -r fake_compose="$TEST_TMP_DIR/restart-ended-compose"
  local -r observed="$TEST_TMP_DIR/restart-ended.observed"
  local status=0

  cat >"$fake_compose" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"$RESTART_ENDED_OBSERVED"
case " $* " in
  *" scenario --scenario restart-fault "*) printf '{}\n' ;;
esac
EOF
  chmod 0755 "$fake_compose"

  if (
    export RESTART_ENDED_OBSERVED="$observed"
    RESULT_DIR="$TEST_TMP_DIR/restart-ended-result"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=("$fake_compose")
    BRIDGE_RUNNING=true
    READINESS_TIMEOUT_SECONDS=2
    TLS_PROTOCOL=TLSv1.3
    SCENARIO_SEED=1
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
    }
    capture_java_diagnostics() {
      printf 'unavailable\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    run_restart_during_traffic_control
  ) >/dev/null 2>&1; then
    printf 'restart control accepted traffic that ended before its first barrier\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" -eq 1 ]] || {
    printf 'ended restart traffic returned %d, expected status 1\n' "$status" >&2
    return 1
  }
  if grep -Fq 'stop --timeout 5 obi' "$observed"; then
    printf 'restart control stopped OBI without active pre-stop traffic\n' >&2
    return 1
  fi
}

test_restart_failure_reaps_background_traffic() {
  local -r fake_compose="$TEST_TMP_DIR/restart-failure-compose"
  local -r traffic_pid_file="$TEST_TMP_DIR/restart-traffic.pid"
  local -r traffic_term_file="$TEST_TMP_DIR/restart-traffic.terminated"
  local -r result_dir="$TEST_TMP_DIR/restart-failure"
  local status=0
  local traffic_pid=""
  local -i elapsed=0

  cat >"$fake_compose" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case " $* " in
  *" scenario --scenario restart-fault "*)
    if IFS= read -r unexpected; then
      printf 'unexpected stdin: %s\n' "$unexpected" >&2
      exit 64
    fi
    printf '%d\n' "$$" >"$RESTART_TRAFFIC_PID_FILE"
    trap 'printf "terminated\n" >"$RESTART_TRAFFIC_TERM_FILE"; exit 0' TERM INT
    printf 'pre-stop-ready\n' >"$RESTART_FAILURE_CONTROL/.pre-stop-ready"
    mv -- \
      "$RESTART_FAILURE_CONTROL/.pre-stop-ready" \
      "$RESTART_FAILURE_CONTROL/pre-stop-ready"
    while true; do sleep 1; done
    ;;
  *" stop --timeout 5 obi "*) exit 23 ;;
  *) exit 0 ;;
esac
EOF
  chmod 0755 "$fake_compose"
  mkdir -p -- "$result_dir"
  printf 'current\n' >"$result_dir/java-transport-configuration.txt"
  printf 'retained\n' >"$result_dir/java-selected-transport-configuration.txt"

  if printf 'must-not-reach-restart-traffic\n' | (
    export RESTART_TRAFFIC_PID_FILE="$traffic_pid_file"
    export RESTART_TRAFFIC_TERM_FILE="$traffic_term_file"
    RESULT_DIR="$result_dir"
    export RESTART_FAILURE_CONTROL="$RESULT_DIR/restart-control"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=("$fake_compose")
    BRIDGE_RUNNING=true
    READINESS_TIMEOUT_SECONDS=5
    TLS_PROTOCOL=TLSv1.3
    SCENARIO_SEED=1
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    capture_java_diagnostics() {
      printf 'unavailable\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }
    run_restart_during_traffic_control
  ) >/dev/null 2>&1; then
    printf 'restart control ignored injected Compose stop failure\n' >&2
    return 1
  else
    status=$?
  fi
  [[ "$status" -eq 23 ]] || {
    printf 'restart control returned %d, expected injected status 23\n' "$status" >&2
    return 1
  }
  [[ ! -e "$result_dir/java-transport-configuration.txt" &&
    "$(<"$result_dir/java-selected-transport-configuration.txt")" == "retained" ]] || {
    printf 'failed restart retained stale current-generation selection evidence\n' >&2
    return 1
  }
  [[ -s "$traffic_pid_file" ]] || {
    printf 'restart control did not start background traffic\n' >&2
    return 1
  }
  traffic_pid="$(<"$traffic_pid_file")"
  while ((elapsed < 50)) && kill -0 "$traffic_pid" 2>/dev/null; do
    sleep 0.1
    ((elapsed += 1))
  done
  if kill -0 "$traffic_pid" 2>/dev/null; then
    printf 'restart control left background traffic process %s alive\n' "$traffic_pid" >&2
    return 1
  fi
  [[ -s "$traffic_term_file" ]] || {
    printf 'restart control did not terminate its background workload\n' >&2
    return 1
  }
}

test_scenario_failure_retains_after_evidence() {
  local fail_compose="$TEST_TMP_DIR/fail-compose"

  printf '%s\n' '#!/usr/bin/env sh' 'exit 17' >"$fail_compose"
  chmod 0755 "$fail_compose"

  (
    RESULT_DIR="$TEST_TMP_DIR/scenario-failure"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=("$fail_compose")
    BRIDGE_RUNNING=false
    REQUEST_COUNT=0
    REPEAT_COUNT=1
    capture_phase_evidence() {
      mkdir -p -- "$RESULT_DIR/phases/$1"
      printf '# empty\n' >"$RESULT_DIR/phases/$1/obi-metrics.prom"
    }
    capture_java_diagnostics() {
      printf 'unavailable\n' >"$RESULT_DIR/phases/$1/java-diagnostics.txt"
    }

    local scenario_status=0
    if run_scenario basic >/dev/null 2>&1; then
      printf 'failing scenario unexpectedly passed\n' >&2
      return 1
    else
      scenario_status=$?
    fi
    [[ "$scenario_status" -eq 17 ]] || {
      printf 'failing scenario returned %d, expected 17\n' "$scenario_status" >&2
      return 1
    }
    [[ -s "$RESULT_DIR/scenario-basic-status.json" ]] || {
      printf 'failing scenario omitted machine-readable status\n' >&2
      return 1
    }
    [[ -f "$RESULT_DIR/phases/basic-after/obi-metrics.delta" ]] || {
      printf 'failing scenario omitted after-phase metric delta\n' >&2
      return 1
    }
    if grep -q 'status="missing"' "$RESULT_DIR/phases/basic-after/obi-metrics.delta"; then
      printf 'diagnostic bridge lookup contaminated the scenario metric delta\n' >&2
      return 1
    fi
  )
}

test_start_failure_retains_command_boundary() {
  local -r fake_compose="$TEST_TMP_DIR/start-failure-compose"
  local -r result_dir="$TEST_TMP_DIR/start-failure-result"
  local status=0

  printf '%s\n' \
    '#!/usr/bin/env sh' \
    'set -eu' \
    'case "${1:-}" in' \
    '  config)' \
    '    if [ "${2:-}" = "--quiet" ]; then exit 0; fi' \
    '    printf "services: {}\n"' \
    '    ;;' \
    '  up)' \
    '    printf "compose-build-boundary-output\n"' \
    '    exit 37' \
    '    ;;' \
    '  *) exit 64 ;;' \
    'esac' >"$fake_compose"
  chmod 0755 "$fake_compose"

  (
    RESULT_DIR="$result_dir"
    RUN_STAGE="test"
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    COMPOSE=("$fake_compose")
    SCENARIO="basic"
    TRANSPORT="getsockopt"
    ACCEPTANCE_EVIDENCE=false
    ACCEPTANCE_EVIDENCE_REASON="custom-request-count"
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    mkdir -p -- "$RESULT_DIR" || return 1
    verify_compose_project_ownership() {
      return 0
    }
    assert_project_docker_identity_unchanged() {
      return 0
    }
    assert_no_pending_permanent_absence_recovery() {
      return 0
    }

    if start_stack; then
      printf 'failing Compose startup unexpectedly passed\n' >&2
      return 1
    else
      status=$?
    fi

    [[ "$status" -eq 37 ]] || {
      printf 'logged command returned %d, expected 37\n' "$status" >&2
      return 1
    }
    [[ "$STACK_STARTED" == "true" && "$BRIDGE_RUNNING" == "false" ]] || return 1
    grep -Fq 'compose-build-boundary-output' "$RESULT_DIR/compose-up.log" || return 1
    grep -Fq 'exit_status=37' "$RESULT_DIR/compose-up.log" || return 1
    grep -Fq 'capture_exit_status=0' "$RESULT_DIR/compose-up.log" || return 1
    grep -Fq 'stage=compose-build-start' "$RESULT_DIR/failure-context.txt" || return 1
    grep -Eq '^line=[1-9][0-9]*$' "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fq 'exit_status=37' "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fq "$fake_compose" "$RESULT_DIR/failure-context.txt" || return 1

    write_run_status "$status" || return 1
    grep -Fq '"failure_stage": "compose-build-start"' "$RESULT_DIR/run-status.json" || return 1
    jq -e '
      .acceptance_evidence == false and
      .acceptance_evidence_reason == "custom-request-count"
    ' "$RESULT_DIR/run-status.json" >/dev/null || return 1
  ) || {
    printf 'logged failure evidence was incomplete\n' >&2
    return 1
  }
}

test_pre_environment_failure_retains_acceptance_eligibility() {
  local -r result_dir="$TEST_TMP_DIR/pre-environment-failure-result"
  local status=0

  set +e
  (
    set -Eeuo pipefail
    RESULT_DIR=""
    TMP_DIR=""
    STACK_STARTED=false
    CLEANUP_ONLY=false
    RUN_STATUS=failed
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    check_dependencies() { :; }
    enter_project_guard() { :; }
    assert_no_pending_permanent_absence_recovery() { :; }
    prepare_directories() {
      RESULT_DIR="$result_dir"
      mkdir -p -- "$RESULT_DIR"
    }
    capture_source_state() { :; }
    prepare_certificates() { return 47; }
    capture_evidence() { :; }
    cleanup_security_processes() { :; }

    run_demo --scenario all --requests 1
  ) >/dev/null 2>&1
  status=$?
  set -e

  [[ "$status" -eq 47 ]] || {
    printf 'pre-environment failure returned %d, expected 47\n' "$status" >&2
    return 1
  }
  [[ ! -e "$result_dir/environment.txt" ]] || {
    printf 'pre-environment failure unexpectedly wrote environment evidence\n' >&2
    return 1
  }
  jq -e '
    .status == "failed" and
    .exit_status == 47 and
    .acceptance_evidence == false and
    .acceptance_evidence_reason == "custom-request-count" and
    .failure_stage == "certificates"
  ' "$result_dir/run-status.json" >/dev/null || {
    printf 'pre-environment failure omitted acceptance eligibility evidence\n' >&2
    return 1
  }
}

test_log_write_failure_is_not_ignored() {
  local -r result_dir="$TEST_TMP_DIR/log-write-failure"
  local expected_line=0
  local status=0

  (
    RESULT_DIR="$result_dir"
    RUN_STAGE="bridge-build"
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    mkdir -p -- "$RESULT_DIR" || return 1

    expected_line=$((LINENO + 1))
    if run_logged_bounded /dev/full 5 sh -c 'exit 0' 2>/dev/null; then
      printf 'unwritable evidence sink was ignored\n' >&2
      return 1
    else
      status=$?
    fi

    [[ "$status" -ne 0 ]] || return 1
    grep -Fq 'stage=bridge-build' "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fqx "line=$expected_line" "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fq 'command=write\ /dev/full' "$RESULT_DIR/failure-context.txt" || return 1
  ) || {
    printf 'log write failure did not fail closed\n' >&2
    return 1
  }
}

footer_faulting_tee() {
  local -r output="${!#}"

  command tee "$@" || return
  mv -- "$output" "$output.before-footer" || return
  ln -s /dev/full "$output" || return
  [[ -L "$output" && "$output" -ef /dev/full ]] || return 1
  printf 'ready\n' >"$RESULT_DIR/footer-fault-ready" || return
  return "${FOOTER_FAULT_STATUS:-0}"
}

test_footer_write_failure_preserves_first_failure() {
  local -r command_result_dir="$TEST_TMP_DIR/footer-command-failure"
  local -r capture_result_dir="$TEST_TMP_DIR/footer-capture-failure"

  (
    RESULT_DIR="$command_result_dir"
    RUN_STAGE="compose-build-start"
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    FOOTER_FAULT_STATUS=0
    mkdir -p -- "$RESULT_DIR" || return 1
    tee() {
      footer_faulting_tee "$@"
    }

    local expected_line=0
    local status=0
    expected_line=$((LINENO + 1))
    if run_logged_bounded "$RESULT_DIR/command.log" 5 sh -c 'exit 37' 2>/dev/null; then
      printf 'command and footer failures unexpectedly passed\n' >&2
      return 1
    else
      status=$?
    fi

    [[ "$status" -eq 37 ]] || return 1
    [[ -f "$RESULT_DIR/footer-fault-ready" ]] || return 1
    [[ -L "$RESULT_DIR/command.log" && "$RESULT_DIR/command.log" -ef /dev/full ]] || return 1
    grep -Fqx "line=$expected_line" "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fq 'exit_status=37' "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fq 'command=sh\ -c\ exit\\\ 37' "$RESULT_DIR/failure-context.txt" || return 1
  ) || {
    printf 'footer failure masked an earlier command failure\n' >&2
    return 1
  }

  (
    RESULT_DIR="$capture_result_dir"
    RUN_STAGE="bridge-build"
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    FOOTER_FAULT_STATUS=23
    mkdir -p -- "$RESULT_DIR" || return 1
    tee() {
      footer_faulting_tee "$@"
    }

    local expected_line=0
    local status=0
    expected_line=$((LINENO + 1))
    if run_logged_bounded "$RESULT_DIR/capture.log" 5 sh -c 'exit 0' 2>/dev/null; then
      printf 'capture and footer failures unexpectedly passed\n' >&2
      return 1
    else
      status=$?
    fi

    [[ "$status" -eq 23 ]] || return 1
    [[ -f "$RESULT_DIR/footer-fault-ready" ]] || return 1
    [[ -L "$RESULT_DIR/capture.log" && "$RESULT_DIR/capture.log" -ef /dev/full ]] || return 1
    grep -Fqx "line=$expected_line" "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fq 'exit_status=23' "$RESULT_DIR/failure-context.txt" || return 1
    grep -Fq 'command=tee\ -a\ ' "$RESULT_DIR/failure-context.txt" || return 1
  ) || {
    printf 'footer failure masked an earlier capture failure\n' >&2
    return 1
  }
}

test_error_logging_preserves_primary_status() {
  local -r result_dir="$TEST_TMP_DIR/error-log-failure"
  local status=0

  set +e
  (
    RESULT_DIR="$result_dir"
    RUN_STAGE="traffic"
    RUN_STATUS="failed"
    ACCEPTANCE_EVIDENCE=false
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    mkdir -p -- "$RESULT_DIR" || return 1
    trap 'status=$?; trap - ERR EXIT; write_run_status "$status"; exit "$status"' EXIT
    trap 'on_error "$LINENO" "$?" "$BASH_COMMAND"' ERR
    exec 2>&-
    set -e
    sh -c 'exit 37'
  )
  status=$?
  set -e

  if ((status == 0)); then
    printf 'closed error log unexpectedly passed\n' >&2
    return 1
  fi

  [[ "$status" -eq 37 ]] || return 1
  grep -Fq 'exit_status=37' "$result_dir/failure-context.txt" || return 1
  grep -Fq '"exit_status": 37' "$result_dir/run-status.json" || return 1
}

test_die_records_explicit_failure_boundary() {
  local -r result_dir="$TEST_TMP_DIR/die-failure"
  local expected_line=0
  local status=0

  set +e
  (
    RESULT_DIR="$result_dir"
    RUN_STAGE="argument-validation"
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    mkdir -p -- "$RESULT_DIR" || exit 1

    exec 2>&- || exit 1
    set -e
    printf '%d\n' "$((LINENO + 1))" >"$RESULT_DIR/expected-line.txt"
    die "injected explicit failure"
  ) >/dev/null 2>&1
  status=$?
  set -e

  if ((status == 0)); then
    printf 'explicit failure unexpectedly passed\n' >&2
    return 1
  fi

  expected_line="$(<"$result_dir/expected-line.txt")" || return 1
  [[ "$status" -eq 2 ]] || return 1
  grep -Fq "line=$expected_line" "$result_dir/failure-context.txt" || return 1
  grep -Fq 'exit_status=2' "$result_dir/failure-context.txt" || return 1
  grep -Fq 'command=die:\ injected\ explicit\ failure' "$result_dir/failure-context.txt" || return 1
}

test_assertion_failure_control_is_explicit() {
  local -r help_output="$TEST_TMP_DIR/assertion-failure-help.txt"
  local -r dispatch_output="$TEST_TMP_DIR/assertion-failure-dispatch.txt"

  usage >"$help_output"
  grep -Fq 'assertion-failure' "$help_output" || {
    printf 'help omitted the deliberate assertion failure control\n' >&2
    return 1
  }
  (
    TRANSPORT=getsockopt
    SCENARIO=all
    CLEANUP_ONLY=false
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    parse_args --scenario assertion-failure
    [[ "$SCENARIO" == "assertion-failure" && "$ACCEPTANCE_EVIDENCE" == "false" && \
      "$ACCEPTANCE_EVIDENCE_REASON" == \
        "deliberate-assertion-failure,targeted-scenario" ]]
  ) || {
    printf 'assertion failure control was not marked as non-acceptance evidence\n' >&2
    return 1
  }
  (
    SCENARIO=assertion-failure
    run_deliberate_assertion_failure_control() {
      printf 'assertion-failure\n' >"$dispatch_output"
    }
    execute_requested_scenarios
  ) || return 1
  [[ "$(<"$dispatch_output")" == "assertion-failure" ]] || {
    printf 'assertion failure scenario used the wrong dispatch\n' >&2
    return 1
  }
}

test_assertion_failure_control_retains_failure_evidence() {
  local -r result_dir="$TEST_TMP_DIR/assertion-failure"
  local status=0

  set +e
  (
    RESULT_DIR="$result_dir"
    RUN_STAGE="scenarios"
    FAILURE_STAGE=""
    FAILURE_LINE=""
    FAILURE_STATUS=""
    FAILURE_COMMAND=""
    mkdir -p -- "$RESULT_DIR" || exit 1
    run_scenario() {
      [[ "$1" == "basic" ]] || return 1
      : >"$RESULT_DIR/basic-passed"
    }

    run_deliberate_assertion_failure_control
  ) >/dev/null 2>&1
  status=$?
  set -e

  if ((status != 2)); then
    printf 'deliberate assertion failure returned %d, expected 2\n' "$status" >&2
    return 1
  fi
  [[ -e "$result_dir/basic-passed" ]] || {
    printf 'deliberate assertion failure did not first run the basic scenario\n' >&2
    return 1
  }
  grep -Fq '"expected_exit_status":2' "$result_dir/scenario-assertion-failure.json" || return 1
  grep -Fq '"failure_context":"failure-context.txt"' \
    "$result_dir/scenario-assertion-failure-status.json" || return 1
  grep -Fq 'stage=deliberate-assertion-failure' "$result_dir/failure-context.txt" || return 1
  grep -Fq 'command=die:\ deliberate\ assertion\ failure\ requested' \
    "$result_dir/failure-context.txt" || return 1
}

test_non_acceptance_reasons_are_recorded() {
  (
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    mark_non_acceptance dirty-source-tree
    mark_non_acceptance targeted-scenario
    [[ "$ACCEPTANCE_EVIDENCE" == "false" ]]
    [[ "$ACCEPTANCE_EVIDENCE_REASON" == "dirty-source-tree,targeted-scenario" ]]
  ) || {
    printf 'non-acceptance evidence reasons were not retained\n' >&2
    return 1
  }
}

test_retained_evidence_provenance_is_verified() {
  local -r verifier="$TEST_SCRIPT_DIR/verify-retained-evidence.sh"
  local -r evidence_root="$TEST_SCRIPT_DIR/../evidence"
  local -r source_bundle="$evidence_root/otel-getsockopt-tls13-c9d14356"
  local repository_root=""
  local -r fixture_repository="$TEST_TMP_DIR/retained-evidence-fixture-repository"
  local -r fixture_hooks_dir="$fixture_repository/controlled-hooks"
  local -r fixture_verifier="$fixture_repository/examples/apache-java-https/scripts/verify-retained-evidence.sh"
  local -r fixture_bundle="$fixture_repository/examples/apache-java-https/evidence/${source_bundle##*/}"
  local -r untracked_bundle="$TEST_TMP_DIR/untracked-retained-evidence/${source_bundle##*/}"
  local -r unsafe_bundle="$TEST_TMP_DIR/unsafe retained evidence"
  local -r option_tmp_parent="$TEST_TMP_DIR/retained-evidence-mktemp-option"
  local -r backslash_tmp="$TEST_TMP_DIR/retained-evidence\\temporary"
  local -r tmpdir_audit_bin="$TEST_TMP_DIR/retained-evidence-tmpdir-audit-bin"
  local -r tmpdir_audit_mktemp="$tmpdir_audit_bin/mktemp"
  local -r archive_race_bin="$TEST_TMP_DIR/retained-evidence-archive-race-bin"
  local -r archive_race_tmp="$TEST_TMP_DIR/retained-evidence-archive-race-tmp"
  local -r archive_race_workdir="$TEST_TMP_DIR/retained-evidence-archive-race-workdir"
  local -r archive_race_git="$archive_race_bin/git"
  local -r archive_race_mktemp="$archive_race_bin/mktemp"
  local -r archive_race_record="$archive_race_tmp/archive-directory"
  local -r replacement_index="$TEST_TMP_DIR/retained-evidence-replacement-index"
  local -r fixture_status_path="examples/apache-java-https/evidence/${source_bundle##*/}/run-status.json"
  local bundle=""
  local manifest_line=""
  local fabricated_tree_sha256=""
  local fixture_head=""
  local replacement_blob=""
  local replacement_tree=""
  local replacement_commit=""
  local real_git=""
  local real_mktemp=""

  commit_fixture_state() {
    local -r subject="$1"

    git -C "$fixture_repository" add -A -- examples/apache-java-https
    git -C "$fixture_repository" commit --quiet -m "$subject"
  }

  reset_fixture_bundle() {
    local -r subject="$1"

    [[ "$fixture_bundle" == "$fixture_repository/"* ]] || return 2
    if [[ -e "$fixture_bundle" || -L "$fixture_bundle" ]]; then
      rm -rf -- "$fixture_bundle"
    fi
    mkdir -p -- "${fixture_bundle%/*}"
    cp -a -- "$source_bundle" "$fixture_bundle"
    commit_fixture_state "$subject"
  }

  rewrite_bundle_checksums() {
    local -r bundle_directory="$1"
    local file=""

    (
      cd -- "$bundle_directory"
      while IFS= read -r file; do
        sha256sum "$file"
      done < <(find . -type f ! -path './SHA256SUMS' -printf '%p\n' | LC_ALL=C sort) >SHA256SUMS
    )
  }

  expect_invalid_bundle() {
    local -r verifier_path="$1"
    local -r bundle_directory="$2"
    local -r description="$3"

    if "$verifier_path" "$bundle_directory" >/dev/null 2>&1; then
      printf 'retained evidence verifier accepted %s\n' "$description" >&2
      return 1
    fi
  }

  commit_invalid_fixture() {
    local -r description="$1"

    commit_fixture_state "Test $description"
    expect_invalid_bundle "$fixture_verifier" "$fixture_bundle" "$description"
  }

  [[ -x "$verifier" ]] || {
    printf 'retained evidence verifier is not executable\n' >&2
    return 1
  }
  for bundle in "$evidence_root"/*; do
    [[ -d "$bundle" ]] || continue
    "$verifier" "$bundle" >/dev/null || return 1
  done

  mkdir -p -- "${untracked_bundle%/*}" "$unsafe_bundle" \
    "$option_tmp_parent/--help" "$backslash_tmp" "$tmpdir_audit_bin"
  cp -a -- "$source_bundle" "$untracked_bundle"
  expect_invalid_bundle "$verifier" "$untracked_bundle" "an untracked copied bundle"
  expect_invalid_bundle "$verifier" "$unsafe_bundle" "an unsafe evidence path"
  (
    cd -- "$option_tmp_parent"
    TMPDIR=--help "$verifier" "$source_bundle" >/dev/null
  ) || {
    printf 'retained evidence verifier did not handle an option-like TMPDIR\n' >&2
    return 1
  }
  TMPDIR="$backslash_tmp" "$verifier" "$source_bundle" >/dev/null || {
    printf 'retained evidence verifier did not handle a backslash TMPDIR\n' >&2
    return 1
  }
  real_mktemp="$(command -v mktemp)" || return 1
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'for argument in "$@"; do' \
    '  [[ "$argument" != *"$FORBIDDEN_TMPDIR"* ]] || exit 73' \
    'done' \
    'exec "$REAL_MKTEMP" "$@"' >"$tmpdir_audit_mktemp"
  chmod 0755 -- "$tmpdir_audit_mktemp"
  PATH="$tmpdir_audit_bin:$PATH" \
    REAL_MKTEMP="$real_mktemp" FORBIDDEN_TMPDIR="$backslash_tmp" TMPDIR="$backslash_tmp" \
    "$verifier" "$source_bundle" >/dev/null || {
    printf 'retained evidence verifier used caller-controlled TMPDIR\n' >&2
    return 1
  }
  real_git="$(command -v git)" || return 1
  mkdir -p -- "$archive_race_bin" "$archive_race_tmp" "$archive_race_workdir"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'for argument in "$@"; do' \
    '  if [[ "$argument" == archive ]]; then' \
    '    if [[ -s "$RACE_ARCHIVE_RECORD" ]]; then' \
    '      IFS= read -r archive_directory <"$RACE_ARCHIVE_RECORD"' \
    '      rmdir -- "$archive_directory"' \
    '    fi' \
    '    break' \
    '  fi' \
    'done' \
    'exec "$REAL_GIT" "$@"' >"$archive_race_git"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'result="$("$REAL_MKTEMP" "$@")"' \
    'case "$result" in' \
    '  /tmp/verify-retained-evidence.*/archive.*)' \
    '    printf "%s\\n" "$result" >"$RACE_ARCHIVE_RECORD"' \
    '    ;;' \
    'esac' \
    'printf "%s\\n" "$result"' >"$archive_race_mktemp"
  chmod 0755 -- "$archive_race_git" "$archive_race_mktemp"
  if (
    cd -- "$archive_race_workdir"
    PATH="$archive_race_bin:$PATH" \
      REAL_GIT="$real_git" REAL_MKTEMP="$real_mktemp" RACE_ARCHIVE_RECORD="$archive_race_record" \
      TMPDIR="$archive_race_tmp" \
      "$verifier" "$source_bundle"
  ) >/dev/null 2>&1; then
    printf 'retained evidence verifier continued after its archive destination disappeared\n' >&2
    return 1
  fi
  [[ ! -e "$archive_race_workdir/examples" && ! -L "$archive_race_workdir/examples" ]] || {
    printf 'retained evidence verifier wrote archive output outside its destination\n' >&2
    return 1
  }

  repository_root="$(git -C "$TEST_SCRIPT_DIR" rev-parse --show-toplevel)" || return 1
  git clone --shared --no-checkout --quiet "$repository_root" "$fixture_repository"
  git -C "$fixture_repository" read-tree --empty
  git -C "$fixture_repository" config user.email 'retained-evidence-test@example.invalid'
  git -C "$fixture_repository" config user.name 'Retained Evidence Test'
  git -C "$fixture_repository" config commit.gpgSign false
  mkdir -p -- "${fixture_verifier%/*}" "$fixture_hooks_dir"
  git -C "$fixture_repository" config core.hooksPath "$fixture_hooks_dir"
  cp -- "$verifier" "$fixture_verifier"
  chmod 0755 -- "$fixture_verifier"
  reset_fixture_bundle 'Add retained-evidence fixture'
  expect_invalid_bundle "$verifier" "$fixture_bundle" \
    "a bundle from a different Git checkout"
  "$fixture_verifier" "$fixture_bundle" >/dev/null || return 1
  fixture_head="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$fixture_repository" rev-parse HEAD)"
  replacement_blob="$(
    printf '{"status":"failed"}\n' |
      GIT_NO_REPLACE_OBJECTS=1 git -C "$fixture_repository" hash-object -w --stdin
  )"
  GIT_NO_REPLACE_OBJECTS=1 GIT_INDEX_FILE="$replacement_index" \
    git -C "$fixture_repository" read-tree "${fixture_head}^{tree}"
  GIT_NO_REPLACE_OBJECTS=1 GIT_INDEX_FILE="$replacement_index" \
    git -C "$fixture_repository" update-index --add \
      --cacheinfo "100644,$replacement_blob,$fixture_status_path"
  replacement_tree="$(
    GIT_NO_REPLACE_OBJECTS=1 GIT_INDEX_FILE="$replacement_index" \
      git -C "$fixture_repository" write-tree
  )"
  replacement_commit="$(
    printf 'replacement retained evidence fixture\n' |
      GIT_NO_REPLACE_OBJECTS=1 \
        git -C "$fixture_repository" commit-tree "$replacement_tree" -p "$fixture_head"
  )"
  GIT_NO_REPLACE_OBJECTS=1 \
    git -C "$fixture_repository" replace "$fixture_head" "$replacement_commit"
  env -u GIT_NO_REPLACE_OBJECTS "$fixture_verifier" "$fixture_bundle" >/dev/null || {
    printf 'retained evidence verifier trusted a local Git replacement ref\n' >&2
    return 1
  }
  GIT_NO_REPLACE_OBJECTS=1 git -C "$fixture_repository" replace -d "$fixture_head"
  GIT_DIR="$fixture_repository/.git" \
    GIT_WORK_TREE="$fixture_repository" \
    GIT_INDEX_FILE="$fixture_repository/.git/index" \
    "$verifier" "$source_bundle" >/dev/null || {
      printf 'retained evidence verifier trusted caller-selected Git state\n' >&2
      return 1
    }
  if GIT_DIR="$fixture_repository/.git" \
    GIT_WORK_TREE="$fixture_repository" \
    GIT_INDEX_FILE="$fixture_repository/.git/index" \
    "$verifier" "$fixture_bundle" >/dev/null 2>&1; then
    printf 'retained evidence verifier accepted a foreign bundle through Git environment redirection\n' >&2
    return 1
  fi
  jq '.status = "failed"' "$fixture_bundle/run-status.json" \
    >"$fixture_bundle/run-status.json.tmp"
  mv -- "$fixture_bundle/run-status.json.tmp" "$fixture_bundle/run-status.json"
  expect_invalid_bundle "$fixture_verifier" "$fixture_bundle" \
    "a modified supplied bundle"
  cp -a -- "$source_bundle/." "$fixture_bundle"
  "$fixture_verifier" "$fixture_bundle" >/dev/null || return 1
  : >"$fixture_bundle/untracked-working-tree-file"
  expect_invalid_bundle "$fixture_verifier" "$fixture_bundle" \
    "a supplied bundle with an extra working-tree file"
  rm -f -- "$fixture_bundle/untracked-working-tree-file"
  "$fixture_verifier" "$fixture_bundle" >/dev/null || return 1

  jq '.status = "failed"' "$fixture_bundle/run-status.json" \
    >"$fixture_bundle/run-status.json.tmp"
  mv -- "$fixture_bundle/run-status.json.tmp" "$fixture_bundle/run-status.json"
  commit_invalid_fixture "a checksum-corrupted bundle"

  reset_fixture_bundle 'Restore retained-evidence fixture after checksum test'
  : >"$fixture_bundle/unlisted.txt"
  commit_invalid_fixture "an unlisted bundle file"

  reset_fixture_bundle 'Restore retained-evidence fixture after file-set test'
  ln -s run-status.json "$fixture_bundle/linked-status.json"
  commit_invalid_fixture "a symbolic-link bundle file"

  reset_fixture_bundle 'Restore retained-evidence fixture after symlink test'
  jq '.status = "failed"' "$fixture_bundle/run-status.json" \
    >"$fixture_bundle/run-status.json.tmp"
  mv -- "$fixture_bundle/run-status.json.tmp" "$fixture_bundle/run-status.json"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a failed retained status"

  reset_fixture_bundle 'Restore retained-evidence fixture after status test'
  jq '.acceptance_evidence = false' "$fixture_bundle/run-status.json" \
    >"$fixture_bundle/run-status.json.tmp"
  mv -- "$fixture_bundle/run-status.json.tmp" "$fixture_bundle/run-status.json"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "an ineligible retained status"

  reset_fixture_bundle 'Restore retained-evidence fixture after eligibility test'
  jq '.evidence_id = "wrong-evidence-id"' "$fixture_bundle/run-status.json" \
    >"$fixture_bundle/run-status.json.tmp"
  mv -- "$fixture_bundle/run-status.json.tmp" "$fixture_bundle/run-status.json"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a mismatched evidence identifier"

  reset_fixture_bundle 'Restore retained-evidence fixture after identity test'
  jq '.evidence_directory = "/tmp/raw-result"' "$fixture_bundle/run-status.json" \
    >"$fixture_bundle/run-status.json.tmp"
  mv -- "$fixture_bundle/run-status.json.tmp" "$fixture_bundle/run-status.json"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a raw evidence directory"

  reset_fixture_bundle 'Restore retained-evidence fixture after raw-path test'
  awk '
    /^revision=/ {
      print "revision=0000000000000000000000000000000000000000"
      next
    }
    { print }
  ' "$fixture_bundle/environment.txt" >"$fixture_bundle/environment.txt.tmp"
  mv -- "$fixture_bundle/environment.txt.tmp" "$fixture_bundle/environment.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a mismatched source revision"

  reset_fixture_bundle 'Restore retained-evidence fixture after revision test'
  awk '
    /^dirty=/ { print "dirty=true"; next }
    { print }
  ' "$fixture_bundle/source-state.txt" >"$fixture_bundle/source-state.txt.tmp"
  mv -- "$fixture_bundle/source-state.txt.tmp" "$fixture_bundle/source-state.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a dirty source state"

  reset_fixture_bundle 'Restore retained-evidence fixture after dirty-state test'
  awk '
    /^scenario=/ { print "scenario=basic"; next }
    { print }
  ' "$fixture_bundle/environment.txt" >"$fixture_bundle/environment.txt.tmp"
  mv -- "$fixture_bundle/environment.txt.tmp" "$fixture_bundle/environment.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a targeted scenario"

  reset_fixture_bundle 'Restore retained-evidence fixture after scenario test'
  awk '
    /^request_count=/ { print "request_count=1"; next }
    { print }
  ' "$fixture_bundle/environment.txt" >"$fixture_bundle/environment.txt.tmp"
  mv -- "$fixture_bundle/environment.txt.tmp" "$fixture_bundle/environment.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a custom full-suite request count"

  reset_fixture_bundle 'Restore retained-evidence fixture after request-count test'
  awk '$0 !~ /^request_count=/' "$fixture_bundle/environment.txt" \
    >"$fixture_bundle/environment.txt.tmp"
  mv -- "$fixture_bundle/environment.txt.tmp" "$fixture_bundle/environment.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a current bundle without request-count evidence"

  reset_fixture_bundle 'Restore retained-evidence fixture after missing-count test'
  awk '
    /^bridge_build_mode=/ { print "bridge_build_mode=reused-local-cache"; next }
    { print }
  ' "$fixture_bundle/environment.txt" >"$fixture_bundle/environment.txt.tmp"
  mv -- "$fixture_bundle/environment.txt.tmp" "$fixture_bundle/environment.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a reused bridge build"

  reset_fixture_bundle 'Restore retained-evidence fixture after build-mode test'
  awk '
    /^acceptance_evidence_reason=/ {
      print "acceptance_evidence_reason=targeted-scenario"
      next
    }
    { print }
  ' "$fixture_bundle/environment.txt" >"$fixture_bundle/environment.txt.tmp"
  mv -- "$fixture_bundle/environment.txt.tmp" "$fixture_bundle/environment.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "an ineligible acceptance reason"

  reset_fixture_bundle 'Restore retained-evidence fixture after reason test'
  awk '
    NR == 1 {
      print "0000000000000000000000000000000000000000" substr($0, 41)
      next
    }
    { print }
  ' "$fixture_bundle/source-tree.manifest" >"$fixture_bundle/source-tree.manifest.tmp"
  mv -- "$fixture_bundle/source-tree.manifest.tmp" "$fixture_bundle/source-tree.manifest"
  fabricated_tree_sha256="$(sha256sum <"$fixture_bundle/source-tree.manifest")"
  fabricated_tree_sha256="${fabricated_tree_sha256%% *}"
  for bundle in "$fixture_bundle/environment.txt" "$fixture_bundle/source-state.txt"; do
    awk -v digest="$fabricated_tree_sha256" '
      /^source_tree_sha256=/ { print "source_tree_sha256=" digest; next }
      { print }
    ' "$bundle" >"$bundle.tmp"
    mv -- "$bundle.tmp" "$bundle"
  done
  printf '%s\n' "$fabricated_tree_sha256" >"$fixture_bundle/bridge-source-tree.sha256"
  jq --arg digest "$fabricated_tree_sha256" '.source_tree_sha256 = $digest' \
    "$fixture_bundle/bridge-artifacts.json" >"$fixture_bundle/bridge-artifacts.json.tmp"
  mv -- "$fixture_bundle/bridge-artifacts.json.tmp" "$fixture_bundle/bridge-artifacts.json"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "an internally re-checksummed fabricated source tree"

  reset_fixture_bundle 'Restore retained-evidence fixture after source-tree test'
  awk '
    /^tracked_patch_sha256=/ {
      print "tracked_patch_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      next
    }
    { print }
  ' "$fixture_bundle/source-state.txt" >"$fixture_bundle/source-state.txt.tmp"
  mv -- "$fixture_bundle/source-state.txt.tmp" "$fixture_bundle/source-state.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a source state with a tracked patch"

  reset_fixture_bundle 'Restore retained-evidence fixture after patch-state test'
  printf ' M tracked-file\n' >"$fixture_bundle/git-status.txt"
  rewrite_bundle_checksums "$fixture_bundle"
  commit_invalid_fixture "a nonempty retained git-status record"

  reset_fixture_bundle 'Restore retained-evidence fixture after git-status test'
  manifest_line="$(sed -n '1p' "$fixture_bundle/SHA256SUMS")" || return 1
  printf '%s\n' "$manifest_line" >>"$fixture_bundle/SHA256SUMS"
  commit_invalid_fixture "a duplicate checksum path"

  reset_fixture_bundle 'Restore retained-evidence fixture after duplicate-manifest test'
  manifest_line="$(sed -n '1p' "$fixture_bundle/SHA256SUMS")" || return 1
  printf '%s  ./../outside\n' "${manifest_line:0:64}" >>"$fixture_bundle/SHA256SUMS"
  commit_invalid_fixture "an unsafe checksum path"
}

capture_fixture_source_state() {
  local -r fixture_runner="$1"
  local -r result_directory="$2"
  local -r expectation="$3"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    result_directory=$2
    expectation=$3
    source "$fixture_runner"
    trap cleanup_source_snapshot_work_directory EXIT
    RESULT_DIR="$result_directory"
    SOURCE_DIRTY=""
    SOURCE_PATCH_SHA256=""
    SOURCE_REVISION=""
    SOURCE_TRACKED_PATCH_SHA256=""
    SOURCE_TREE_SHA256=""
    SOURCE_TREE_MANIFEST_SCHEMA=""
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    capture_source_state
    case "$expectation" in
      clean)
        [[ "$SOURCE_DIRTY" == false && "$SOURCE_TREE_MANIFEST_SCHEMA" == git-tree-v2 && \
          "$ACCEPTANCE_EVIDENCE" == true && -z "$ACCEPTANCE_EVIDENCE_REASON" ]]
        ;;
      dirty)
        [[ "$SOURCE_DIRTY" == true && "$SOURCE_TREE_MANIFEST_SCHEMA" == worktree-v1 && \
          "$ACCEPTANCE_EVIDENCE" == false && \
          "$ACCEPTANCE_EVIDENCE_REASON" == dirty-source-tree ]]
        ;;
      *) exit 64 ;;
    esac
  ' fixture-runner-child "$fixture_runner" "$result_directory" "$expectation"
}

materialize_fixture_source_snapshot() {
  local -r fixture_runner="$1"
  local -r result_directory="$2"
  local -r fixture_repository="$3"
  local -r source_revision="$4"
  local -r snapshot_directory="$5"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    result_directory=$2
    fixture_repository=$3
    source_revision=$4
    snapshot_directory=$5
    source "$fixture_runner"
    trap cleanup_source_snapshot_work_directory EXIT
    RESULT_DIR="$result_directory"
    materialize_source_tree_snapshot \
      "$fixture_repository" "$source_revision" "$snapshot_directory" 0
    find "$snapshot_directory" -mindepth 1 -type d -exec chmod 0755 -- {} +
    assert_materialized_source_tree_matches_revision \
      "$fixture_repository" "$source_revision" "$snapshot_directory"
  ' fixture-runner-child \
    "$fixture_runner" "$result_directory" "$fixture_repository" "$source_revision" \
    "$snapshot_directory"
}

materialize_fixture_source_snapshot_rejects_removed_destination() {
  local -r fixture_runner="$1"
  local -r result_directory="$2"
  local -r fixture_repository="$3"
  local -r source_revision="$4"
  local -r snapshot_directory="$5"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    result_directory=$2
    fixture_repository=$3
    source_revision=$4
    snapshot_directory=$5
    source "$fixture_runner"
    trap cleanup_source_snapshot_work_directory EXIT
    RESULT_DIR="$result_directory"
    cd -- "$result_directory"
    git() {
      local argument=""

      for argument in "$@"; do
        if [[ "$argument" == archive ]]; then
          rmdir -- "$snapshot_directory"
          break
        fi
      done
      command git "$@"
    }
    materialize_source_tree_snapshot \
      "$fixture_repository" "$source_revision" "$snapshot_directory" 0
  ' fixture-runner-child \
    "$fixture_runner" "$result_directory" "$fixture_repository" "$source_revision" \
    "$snapshot_directory"
}

assert_fixture_source_snapshot_matches() {
  local -r fixture_runner="$1"
  local -r result_directory="$2"
  local -r fixture_repository="$3"
  local -r source_revision="$4"
  local -r snapshot_directory="$5"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    result_directory=$2
    fixture_repository=$3
    source_revision=$4
    snapshot_directory=$5
    source "$fixture_runner"
    trap cleanup_source_snapshot_work_directory EXIT
    RESULT_DIR="$result_directory"
    assert_materialized_source_tree_matches_revision \
      "$fixture_repository" "$source_revision" "$snapshot_directory"
  ' fixture-runner-child \
    "$fixture_runner" "$result_directory" "$fixture_repository" "$source_revision" \
    "$snapshot_directory"
}

assert_fixture_source_checkout_stability() {
  local -r fixture_runner="$1"
  local -r result_directory="$2"
  local -r captured_revision="$3"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    result_directory=$2
    captured_revision=$3
    source "$fixture_runner"
    trap cleanup_source_snapshot_work_directory EXIT
    RESULT_DIR="$result_directory"
    SOURCE_DIRTY=false
    SOURCE_REVISION="$captured_revision"
    assert_clean_source_checkout_is_stable
  ' fixture-runner-child "$fixture_runner" "$result_directory" "$captured_revision"
}

prepare_fixture_source_snapshot() {
  local -r fixture_runner="$1"
  local -r runtime_directory="$2"
  local -r source_artifact_directory="$3"
  local -r capture_directory="$4"
  local -r expected_revision="$5"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    runtime_directory=$2
    source_artifact_directory=$3
    capture_directory=$4
    expected_revision=$5
    source "$fixture_runner"
    trap cleanup_source_snapshot_work_directory EXIT
    {
      RUNTIME_DIR="$runtime_directory"
      ARTIFACT_DIR="$source_artifact_directory"
      RESULT_DIR="$capture_directory"
      SOURCE_SNAPSHOT_DIR=""
      SOURCE_SNAPSHOT_SCRIPT_DIR=""
      SOURCE_DIRTY=""
      SOURCE_PATCH_SHA256=""
      SOURCE_REVISION=""
      SOURCE_TRACKED_PATCH_SHA256=""
      SOURCE_TREE_SHA256=""
      SOURCE_TREE_MANIFEST_SCHEMA=""
      ACCEPTANCE_EVIDENCE=true
      ACCEPTANCE_EVIDENCE_REASON=""
      SKIP_BRIDGE_BUILD=true
      BRIDGE_BUILD_MODE=fresh
      PROJECT_NAME=obi-apache-java-https-snapshot-test
      COMPOSE_FILE="$REPO_ROOT/examples/apache-java-https/docker-compose.yml"
      PRIMARY_FAULT_COMPOSE_FILE="$REPO_ROOT/examples/apache-java-https/docker-compose.primary-fault.yml"
      PRIMARY_LIVE_FD_COMPOSE_FILE="$REPO_ROOT/examples/apache-java-https/docker-compose.primary-live-fd.yml"
      COMPOSE_PROJECT_DIRECTORY="$REPO_ROOT/examples/apache-java-https"
      COMPOSE=(
        docker compose --project-name "$PROJECT_NAME" \
          --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE"
      )
      PRIMARY_FAULT_COMPOSE=(
        docker compose --project-name "$PROJECT_NAME" \
          --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
          --file "$PRIMARY_FAULT_COMPOSE_FILE"
      )
      PRIMARY_LIVE_FD_COMPOSE=(
        docker compose --project-name "$PROJECT_NAME" \
          --project-directory "$COMPOSE_PROJECT_DIRECTORY" --file "$COMPOSE_FILE" \
          --file "$PRIMARY_FAULT_COMPOSE_FILE" --file "$PRIMARY_LIVE_FD_COMPOSE_FILE"
      )

      unset GIT_NO_REPLACE_OBJECTS
      capture_source_state
      [[ "$SOURCE_DIRTY" == false && "$SOURCE_TREE_MANIFEST_SCHEMA" == git-tree-v2 && \
        "$SOURCE_REVISION" == "$expected_revision" ]]
      printf "cached Java bridge helper\\n" >"$ARTIFACT_DIR/obi-java-agent.jar"
      printf "cached Java bridge extension\\n" >"$ARTIFACT_DIR/obi-otel-extension.jar"
      write_bridge_metadata
      bridge_artifacts_are_valid
      prepare_source_snapshot
      bridge_artifacts_are_valid
      prepare_bridge_artifacts
      [[ -d "$SOURCE_SNAPSHOT_DIR" && ! -L "$SOURCE_SNAPSHOT_DIR" && \
        "$COMPOSE_FILE" == "$SOURCE_SNAPSHOT_DIR/examples/apache-java-https/docker-compose.yml" && \
        "$PRIMARY_FAULT_COMPOSE_FILE" == \
          "$SOURCE_SNAPSHOT_DIR/examples/apache-java-https/docker-compose.primary-fault.yml" && \
        "$PRIMARY_LIVE_FD_COMPOSE_FILE" == \
          "$SOURCE_SNAPSHOT_DIR/examples/apache-java-https/docker-compose.primary-live-fd.yml" && \
        "${COMPOSE[*]}" == *"--project-directory $SOURCE_SNAPSHOT_DIR/examples/apache-java-https"* && \
        ! -e "$SOURCE_SNAPSHOT_DIR/ignored-build-input" && \
        -L "$SOURCE_SNAPSHOT_DIR/link" && \
        "$(stat --format=%a -- "$SOURCE_SNAPSHOT_DIR/executable")" == 755 && \
        "$(<"$SOURCE_SNAPSHOT_DIR/source")" == "tracked source input" && \
        "$(stat --format=%a -- "$SOURCE_SNAPSHOT_DIR")" == 700 && \
        "$BRIDGE_BUILD_MODE" == reused-local-cache && \
        "$ACCEPTANCE_EVIDENCE" == false && \
        "$ACCEPTANCE_EVIDENCE_REASON" == reused-bridge-artifacts ]]
      seal_source_snapshot
      [[ "$(stat --format=%a -- "$SOURCE_SNAPSHOT_DIR/source")" == 444 && \
        "$(stat --format=%a -- "$SOURCE_SNAPSHOT_DIR/executable")" == 555 && \
        "$(stat --format=%a -- "$SOURCE_SNAPSHOT_DIR")" == 500 ]]
      unseal_source_snapshot
    } >&2
    printf "%s\\n" "$SOURCE_SNAPSHOT_DIR"
  ' fixture-runner-child \
    "$fixture_runner" "$runtime_directory" "$source_artifact_directory" "$capture_directory" \
    "$expected_revision"
}

assert_fixture_source_snapshot_parent_is_rejected() {
  local -r fixture_runner="$1"
  local -r candidate_parent="$2"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    candidate_parent=$2
    source "$fixture_runner"
    assert_source_snapshot_parent_is_trusted "$candidate_parent"
  ' fixture-runner-child "$fixture_runner" "$candidate_parent"
}

capture_fixture_source_with_redirected_git_environment() {
  local -r fixture_runner="$1"
  local -r result_directory="$2"
  local -r redirected_worktree="$3"
  local -r redirected_index="$4"

  bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    result_directory=$2
    redirected_worktree=$3
    redirected_index=$4
    source "$fixture_runner"
    trap cleanup_source_snapshot_work_directory EXIT
    RESULT_DIR="$result_directory"
    SOURCE_DIRTY=""
    SOURCE_PATCH_SHA256=""
    SOURCE_REVISION=""
    SOURCE_TRACKED_PATCH_SHA256=""
    SOURCE_TREE_SHA256=""
    SOURCE_TREE_MANIFEST_SCHEMA=""
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    export GIT_WORK_TREE="$redirected_worktree"
    export GIT_INDEX_FILE="$redirected_index"
    capture_source_state
    [[ "$SOURCE_DIRTY" == true && "$ACCEPTANCE_EVIDENCE" == false && \
      "$ACCEPTANCE_EVIDENCE_REASON" == dirty-source-tree ]]
  ' fixture-runner-child \
    "$fixture_runner" "$result_directory" "$redirected_worktree" "$redirected_index"
}

test_primary_wrong_live_socket_evidence_is_exact() {
  local -r bundle="$TEST_SCRIPT_DIR/../evidence/otel-getsockopt-tls13-b678ce1e"
  local -r summary="$bundle/security-primary-live-fd.json"
  local -r status="$bundle/scenario-primary-live-fd-security-status.json"

  jq -e '
    .status == "passed" and
    .transport == "getsockopt" and
    .controls.wrong_live_socket.status == "metrics_verified" and
    .controls.wrong_live_socket.actor == "the Java process" and
    .controls.duplicated_fd_wrong_process.status == "metrics_verified" and
    .metric_windows.probe_delta.take_valid == 0 and
    .metric_windows.probe_delta.take_unauthorized == 2 and
    .metric_windows.probe_delta.negotiate_unauthorized == 1 and
    .metric_windows.after_from_before_delta.take_valid == 1 and
    .metric_windows.after_from_before_delta.take_unauthorized == 2 and
    .legitimate_victim.status == "passed" and
    .post_abuse_recovery.status == "passed"
  ' "$summary" >/dev/null || {
    printf 'primary wrong-live-socket evidence lost its ordered metric contract\n' >&2
    return 1
  }
  jq -e '
    .status == "passed" and
    .probe_status == "unverified" and
    .probe_verification == "metrics_verified" and
    .wrong_live_socket == "metrics_verified" and
    .duplicated_fd_wrong_process == "metrics_verified" and
    .legitimate_victim == "passed" and
    .post_abuse_recovery == "passed"
  ' "$status" >/dev/null || {
    printf 'primary wrong-live-socket evidence lost its status boundary\n' >&2
    return 1
  }
}

test_retained_evidence_v2_git_tree_schema_is_verified() {
  local -r verifier="$TEST_SCRIPT_DIR/verify-retained-evidence.sh"
  local -r fixture_repository="$TEST_TMP_DIR/retained-evidence-v2-fixture"
  local -r fixture_hooks_dir="$fixture_repository/controlled-hooks"
  local -r nested_repository="$fixture_repository/gitlink"
  local -r capture_directory="$TEST_TMP_DIR/retained-evidence-v2-capture"
  local -r dirty_capture_directory="$TEST_TMP_DIR/retained-evidence-v2-dirty-capture"
  local -r index_flag_capture_directory="$TEST_TMP_DIR/retained-evidence-v2-index-flag-capture"
  local -r nested_index_flag_capture_directory="$TEST_TMP_DIR/retained-evidence-v2-nested-index-flag-capture"
  local -r snapshot_directory="$TEST_TMP_DIR/retained-evidence-v2-source-snapshot"
  local -r race_snapshot_directory="$TEST_TMP_DIR/retained-evidence-v2-raced-source-snapshot"
  local -r nonempty_snapshot_directory="$TEST_TMP_DIR/retained-evidence-v2-nonempty-source-snapshot"
  local -r evidence_id='synthetic-git-tree-v2'
  local -r bundle="$fixture_repository/examples/apache-java-https/evidence/$evidence_id"
  local -r fixture_runner="$fixture_repository/examples/apache-java-https/run.sh"
  local -r fixture_verifier="$fixture_repository/examples/apache-java-https/scripts/verify-retained-evidence.sh"
  local source_revision=""
  local source_tree_sha256=""

  write_bundle_checksums() {
    local file=""

    (
      cd -- "$bundle"
      while IFS= read -r file; do
        sha256sum "$file"
      done < <(find . -type f ! -path './SHA256SUMS' -printf '%p\n' | LC_ALL=C sort) >SHA256SUMS
    )
  }

  mkdir -p -- \
    "$fixture_repository" "$fixture_hooks_dir" "$capture_directory" "$dirty_capture_directory" \
    "$index_flag_capture_directory" "$nested_index_flag_capture_directory" \
    "$snapshot_directory" "$race_snapshot_directory" "$nonempty_snapshot_directory" \
    "${fixture_runner%/*}" \
    "$fixture_repository/nested"
  git init --quiet "$fixture_repository"
  git -C "$fixture_repository" config user.email 'retained-evidence-v2@example.invalid'
  git -C "$fixture_repository" config user.name 'Retained Evidence V2 Test'
  git -C "$fixture_repository" config commit.gpgSign false
  git -C "$fixture_repository" config core.hooksPath "$fixture_hooks_dir"
  cp -- "$TEST_SCRIPT_DIR/../run.sh" "$fixture_runner"
  chmod 0755 -- "$fixture_runner"
  printf 'regular source file\n' >"$fixture_repository/regular"
  printf 'executable source file\n' >"$fixture_repository/executable"
  chmod 0755 -- "$fixture_repository/executable"
  ln -s regular "$fixture_repository/link"
  ln -s $'regular\n' "$fixture_repository/link-with-newline-target"
  printf 'nested ordinary source file\n' >"$fixture_repository/nested/ordinary"
  git init --quiet "$nested_repository"
  git -C "$nested_repository" config user.email 'retained-evidence-v2@example.invalid'
  git -C "$nested_repository" config user.name 'Retained Evidence V2 Test'
  git -C "$nested_repository" config commit.gpgSign false
  git -C "$nested_repository" config core.hooksPath "$fixture_hooks_dir"
  printf 'nested source file\n' >"$nested_repository/nested"
  git -C "$nested_repository" add -- nested
  git -C "$nested_repository" commit --quiet -m 'Create nested gitlink source'
  git -C "$fixture_repository" add -- \
    regular executable link link-with-newline-target nested/ordinary gitlink \
    examples/apache-java-https/run.sh
  git -C "$fixture_repository" commit --quiet -m 'Create canonical source tree'

  capture_fixture_source_state "$fixture_runner" "$capture_directory" clean || {
    printf 'clean source capture did not produce a canonical Git-tree v2 manifest\n' >&2
    return 1
  }
  grep -Eq ' l link$' "$capture_directory/source-tree.manifest" || {
    printf 'canonical source manifest omitted the symbolic-link marker\n' >&2
    return 1
  }
  grep -Eq ' g gitlink$' "$capture_directory/source-tree.manifest" || {
    printf 'canonical source manifest omitted the gitlink marker\n' >&2
    return 1
  }
  grep -Eq ' - nested/ordinary$' "$capture_directory/source-tree.manifest" || {
    printf 'canonical source manifest omitted nested tracked content\n' >&2
    return 1
  }
  grep -Fqx 'source_tree_manifest_schema=git-tree-v2' \
    "$capture_directory/source-state.txt" || {
    printf 'clean source state omitted its Git-tree v2 schema\n' >&2
    return 1
  }
  source_revision="$(awk -F= '$1 == "revision" { print $2; exit }' "$capture_directory/source-state.txt")"
  materialize_fixture_source_snapshot \
    "$fixture_runner" "$capture_directory" "$fixture_repository" "$source_revision" \
    "$snapshot_directory" || {
    printf 'pinned source snapshot did not preserve the canonical Git tree and gitlink\n' >&2
    return 1
  }
  [[ "$(<"$snapshot_directory/gitlink/nested")" == "nested source file" && \
    "$(<"$snapshot_directory/nested/ordinary")" == "nested ordinary source file" && \
    ! -e "$snapshot_directory/gitlink/.git" && \
    -L "$snapshot_directory/link" && \
    -x "$snapshot_directory/executable" ]] || {
    printf 'pinned source snapshot omitted nested Git-tree content\n' >&2
    return 1
  }
  printf 'unexpected snapshot content\n' >"$snapshot_directory/unexpected"
  if assert_fixture_source_snapshot_matches \
    "$fixture_runner" "$capture_directory" "$fixture_repository" "$source_revision" \
    "$snapshot_directory" >/dev/null 2>&1; then
    printf 'source snapshot validation accepted an unexpected regular file\n' >&2
    return 1
  fi
  rm -f -- "$snapshot_directory/unexpected"
  if materialize_fixture_source_snapshot_rejects_removed_destination \
    "$fixture_runner" "$capture_directory" "$fixture_repository" "$source_revision" \
    "$race_snapshot_directory" >/dev/null 2>&1; then
    printf 'source snapshot extraction continued after its destination disappeared\n' >&2
    return 1
  fi
  [[ ! -e "$race_snapshot_directory" && ! -L "$race_snapshot_directory" ]] || {
    printf 'source snapshot extraction recreated a removed destination\n' >&2
    return 1
  }
  [[ ! -e "$capture_directory/regular" && ! -L "$capture_directory/regular" ]] || {
    printf 'source snapshot extraction wrote archive output outside its destination\n' >&2
    return 1
  }
  mkdir -p -- "$nonempty_snapshot_directory/gitlink"
  : >"$nonempty_snapshot_directory/gitlink/untrusted-placeholder-content"
  if materialize_fixture_source_snapshot \
    "$fixture_runner" "$capture_directory" "$fixture_repository" "$source_revision" \
    "$nonempty_snapshot_directory" >/dev/null 2>&1; then
    printf 'source snapshot accepted a nonempty Gitlink placeholder\n' >&2
    return 1
  fi
  printf 'corrupted nested snapshot source\n' >"$snapshot_directory/gitlink/nested"
  if assert_fixture_source_snapshot_matches \
    "$fixture_runner" "$capture_directory" "$fixture_repository" "$source_revision" \
    "$snapshot_directory" >/dev/null 2>&1; then
    printf 'source snapshot validation accepted a corrupted nested gitlink file\n' >&2
    return 1
  fi
  printf 'nested dirty source file\n' >"$nested_repository/nested"
  : >"$nested_repository/untracked"
  capture_fixture_source_state "$fixture_runner" "$dirty_capture_directory" dirty || {
    printf 'dirty gitlink source was not marked non-acceptance evidence\n' >&2
    return 1
  }
  [[ -s "$dirty_capture_directory/git-status.txt" ]] || {
    printf 'dirty gitlink source omitted its Git-status evidence\n' >&2
    return 1
  }
  printf 'nested source file\n' >"$nested_repository/nested"
  rm -f -- "$nested_repository/untracked"
  git -C "$nested_repository" update-index --assume-unchanged nested
  printf 'nested assume-unchanged dirty source file\n' >"$nested_repository/nested"
  if capture_fixture_source_state \
    "$fixture_runner" "$nested_index_flag_capture_directory" clean >/dev/null 2>&1; then
    printf 'source capture accepted a nested assume-unchanged source modification\n' >&2
    return 1
  fi
  printf 'nested source file\n' >"$nested_repository/nested"
  git -C "$nested_repository" update-index --no-assume-unchanged nested
  git -C "$nested_repository" update-index --no-skip-worktree nested
  git -C "$fixture_repository" update-index --assume-unchanged regular
  printf 'assume-unchanged dirty source file\n' >"$fixture_repository/regular"
  if capture_fixture_source_state \
    "$fixture_runner" "$index_flag_capture_directory" clean >/dev/null 2>&1; then
    printf 'source capture accepted an assume-unchanged source modification\n' >&2
    return 1
  fi
  printf 'regular source file\n' >"$fixture_repository/regular"
  git -C "$fixture_repository" update-index --no-assume-unchanged regular
  git -C "$fixture_repository" update-index --no-skip-worktree regular
  source_tree_sha256="$(awk -F= '$1 == "source_tree_sha256" { print $2; exit }' "$capture_directory/source-state.txt")"
  [[ "$source_revision" =~ ^[0-9a-f]{40}$ && \
    "$source_tree_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'clean source capture produced malformed Git-tree provenance\n' >&2
    return 1
  }

  mkdir -p -- "$bundle" "${fixture_verifier%/*}"
  cp -- "$verifier" "$fixture_verifier"
  chmod 0755 -- "$fixture_verifier"
  cp -- "$capture_directory/source-tree.manifest" "$bundle/source-tree.manifest"
  cp -- "$capture_directory/source-state.txt" "$bundle/source-state.txt"
  cp -- "$capture_directory/git-status.txt" "$bundle/git-status.txt"
  printf '%s\n' "$source_revision" >"$bundle/bridge-source-revision.txt"
  printf '%s\n' "$source_tree_sha256" >"$bundle/bridge-source-tree.sha256"
  printf '%s\n' \
    '{"status":"passed","exit_status":0,"acceptance_evidence":true,"acceptance_evidence_reason":"none","failure_stage":"none","failure_line":0,"evidence_id":"synthetic-git-tree-v2"}' \
    >"$bundle/run-status.json"
  printf '%s\n' \
    "{\"sanitized\":true,\"evidence_id\":\"$evidence_id\",\"source_revision\":\"$source_revision\"}" \
    >"$bundle/runtime-metadata.json"
  printf '%s\n' \
    "{\"source_revision\":\"$source_revision\",\"source_tree_sha256\":\"$source_tree_sha256\"}" \
    >"$bundle/bridge-artifacts.json"
  {
    printf 'invocation=synthetic-git-tree-v2\n'
    printf 'revision=%s\n' "$source_revision"
    printf 'dirty=false\n'
    printf 'source_tree_sha256=%s\n' "$source_tree_sha256"
    printf 'source_tree_manifest_schema=git-tree-v2\n'
    printf 'tracked_patch_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n'
    printf 'patch_identity_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n'
    printf 'transport=getsockopt\n'
    printf 'agent_distribution=otel\n'
    printf 'tls_protocol=TLSv1.3\n'
    printf 'scenario=all\n'
    printf 'request_count=0\n'
    printf 'repeat_count=1\n'
    printf 'scenario_seed=1\n'
    printf 'bridge_build_mode=fresh\n'
    printf 'acceptance_evidence=true\n'
    printf 'acceptance_evidence_reason=none\n'
  } >"$bundle/environment.txt"
  write_bundle_checksums
  git -C "$fixture_repository" add -A -- examples/apache-java-https
  git -C "$fixture_repository" commit --quiet -m 'Add canonical retained evidence fixture'
  [[ -z "$(git -C "$fixture_repository" status --porcelain=v1 --untracked-files=all)" ]] || {
    printf 'canonical retained evidence fixture is not clean\n' >&2
    return 1
  }
  "$fixture_verifier" "$bundle" >/dev/null || {
    printf 'retained evidence verifier rejected canonical Git-tree v2 evidence\n' >&2
    return 1
  }
  awk '
    /^source_tree_manifest_schema=/ {
      print "source_tree_manifest_schema=worktree-v1"
      next
    }
    { print }
  ' "$bundle/environment.txt" >"$bundle/environment.txt.tmp"
  mv -- "$bundle/environment.txt.tmp" "$bundle/environment.txt"
  write_bundle_checksums
  git -C "$fixture_repository" add -A -- examples/apache-java-https
  git -C "$fixture_repository" commit --quiet -m 'Corrupt canonical source-tree schema'
  if "$fixture_verifier" "$bundle" >/dev/null 2>&1; then
    printf 'retained evidence verifier accepted a noncanonical Git-tree schema\n' >&2
    return 1
  fi
}

test_source_gitlink_depth_is_bounded() {
  local -r source_repository="$TEST_TMP_DIR/source-gitlink-depth-fixture"
  local -r hooks_directory="$source_repository/controlled-hooks"
  local -r result_directory="$TEST_TMP_DIR/source-gitlink-depth-result"
  local -r fixture_runner="$source_repository/examples/apache-java-https/run.sh"
  local nested_directory="$source_repository"
  local child_name=""
  local -a gitlink_directories=()
  local -i depth=0

  mkdir -p -- "$source_repository" "$hooks_directory" "$result_directory" "${fixture_runner%/*}"
  git init --quiet "$source_repository"
  git -C "$source_repository" config user.email 'source-gitlink-depth@example.invalid'
  git -C "$source_repository" config user.name 'Source Gitlink Depth Test'
  git -C "$source_repository" config commit.gpgSign false
  git -C "$source_repository" config core.hooksPath "$hooks_directory"
  cp -- "$TEST_SCRIPT_DIR/../run.sh" "$fixture_runner"
  chmod 0755 -- "$fixture_runner"

  for ((depth = 0; depth <= 16; depth++)); do
    nested_directory+="/gitlink-$depth"
    gitlink_directories+=("$nested_directory")
  done
  for ((depth = 16; depth >= 0; depth--)); do
    nested_directory="${gitlink_directories[$depth]}"
    mkdir -p -- "$nested_directory"
    git init --quiet "$nested_directory"
    git -C "$nested_directory" config user.email 'source-gitlink-depth@example.invalid'
    git -C "$nested_directory" config user.name 'Source Gitlink Depth Test'
    git -C "$nested_directory" config commit.gpgSign false
    git -C "$nested_directory" config core.hooksPath "$hooks_directory"
    if ((depth == 16)); then
      printf 'nested leaf\n' >"$nested_directory/leaf"
      git -C "$nested_directory" add -- leaf
    else
      child_name="gitlink-$((depth + 1))"
      git -C "$nested_directory" add -- "$child_name"
    fi
    git -C "$nested_directory" commit --quiet -m "Create nested gitlink $depth"
  done
  git -C "$source_repository" add -- gitlink-0 examples/apache-java-https/run.sh
  git -C "$source_repository" commit --quiet -m 'Create bounded gitlink-depth source'

  if capture_fixture_source_state \
    "$fixture_runner" "$result_directory" clean >/dev/null 2>&1; then
    printf 'source capture accepted a gitlink chain beyond the nesting limit\n' >&2
    return 1
  fi
}

test_source_git_tree_path_validation_is_byte_safe() {
  local -a unsafe_paths=(
    ''
    '/absolute'
    'trailing/'
    'double//slash'
    '.'
    '..'
    'safe/./child'
    'safe/../child'
    $'safe\n/../child'
  )
  local -a safe_paths=(
    'regular'
    'nested/regular'
    $'newline\ncomponent/child'
  )
  local path=""

  for path in "${unsafe_paths[@]}"; do
    if is_safe_git_tree_path "$path"; then
      printf 'source Git-tree path validation accepted an unsafe path\n' >&2
      return 1
    fi
  done
  for path in "${safe_paths[@]}"; do
    if ! is_safe_git_tree_path "$path"; then
      printf 'source Git-tree path validation rejected a safe path\n' >&2
      return 1
    fi
  done
}

test_clean_source_checkout_stability_rejects_changed_revision() {
  local -r source_repository="$TEST_TMP_DIR/source-stability-fixture"
  local -r hooks_directory="$source_repository/controlled-hooks"
  local -r result_directory="$TEST_TMP_DIR/source-stability-result"
  local -r fixture_runner="$source_repository/examples/apache-java-https/run.sh"
  local captured_revision=""

  mkdir -p -- \
    "$source_repository" "$hooks_directory" "$result_directory" "${fixture_runner%/*}"
  git init --quiet "$source_repository"
  git -C "$source_repository" config user.email 'source-stability-test@example.invalid'
  git -C "$source_repository" config user.name 'Source Stability Test'
  git -C "$source_repository" config commit.gpgSign false
  git -C "$source_repository" config core.hooksPath "$hooks_directory"
  cp -- "$TEST_SCRIPT_DIR/../run.sh" "$fixture_runner"
  chmod 0755 -- "$fixture_runner"
  printf 'first source revision\n' >"$source_repository/source"
  git -C "$source_repository" add -- source examples/apache-java-https/run.sh
  git -C "$source_repository" commit --quiet -m 'Create first source revision'
  captured_revision="$(git -C "$source_repository" rev-parse HEAD)"
  printf 'second source revision\n' >"$source_repository/source"
  git -C "$source_repository" add -- source
  git -C "$source_repository" commit --quiet -m 'Create second source revision'
  if assert_fixture_source_checkout_stability \
    "$fixture_runner" "$result_directory" "$captured_revision" >/dev/null 2>&1; then
    printf 'source stability check accepted a changed source revision\n' >&2
    return 1
  fi
}

test_source_controls_and_bridge_export_use_private_work_directory() {
  local -r source_repository="$TEST_TMP_DIR/private-source-work-fixture"
  local -r hooks_directory="$source_repository/controlled-hooks"
  local -r fixture_runner="$source_repository/examples/apache-java-https/run.sh"
  local -r runtime_directory="$TEST_TMP_DIR/private-source-work-runtime"
  local -r source_artifact_directory="$TEST_TMP_DIR/private-source-work-artifacts"
  local -r result_directory="$TEST_TMP_DIR/private-source-work-result"
  local -r fake_bin="$TEST_TMP_DIR/private-source-work-fake-bin"
  local -r fake_docker="$fake_bin/docker"
  local -r fake_mktemp="$fake_bin/mktemp"
  local -r docker_destination_record="$TEST_TMP_DIR/private-source-work-destination"
  local -r control_canary="$TEST_TMP_DIR/private-source-work-canary"
  local real_mktemp=""
  local control_name=""
  local -a control_names=(
    .source-index-flags-0
    .source-gitlinks-0
    .source-tree-v2.entries
    .source-tree-v2.manifest
    .source-snapshot-gitlinks-0
    .source-snapshot-tree-0
    .source-snapshot-expected-0
    .source-snapshot-expected-sorted-0
    .source-snapshot-actual-0
    .source-snapshot-actual-filtered-0
    .source-snapshot-actual-sorted-0
  )

  mkdir -p -- \
    "$source_repository/examples/apache-java-https" "$hooks_directory" \
    "$runtime_directory" "$source_artifact_directory" "$result_directory" "$fake_bin"
  git init --quiet "$source_repository"
  git -C "$source_repository" config user.email 'private-source-work@example.invalid'
  git -C "$source_repository" config user.name 'Private Source Work Test'
  git -C "$source_repository" config commit.gpgSign false
  git -C "$source_repository" config core.hooksPath "$hooks_directory"
  cp -- "$TEST_SCRIPT_DIR/../run.sh" "$fixture_runner"
  chmod 0755 -- "$fixture_runner"
  printf 'tracked source input\n' >"$source_repository/source"
  printf 'services: {}\n' >"$source_repository/examples/apache-java-https/docker-compose.yml"
  printf 'services: {}\n' \
    >"$source_repository/examples/apache-java-https/docker-compose.primary-fault.yml"
  printf 'services: {}\n' \
    >"$source_repository/examples/apache-java-https/docker-compose.primary-live-fd.yml"
  printf 'FROM scratch\nCOPY . /source\n' >"$source_repository/javaagent.Dockerfile"
  git -C "$source_repository" add -- .
  git -C "$source_repository" commit --quiet -m 'Create private source-work fixture'

  real_mktemp="$(command -v mktemp)" || return 1
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'for argument in "$@"; do' \
    '  [[ "$argument" != *"$FORBIDDEN_RESULT_DIR"* ]] || exit 73' \
    'done' \
    'exec "$REAL_MKTEMP" "$@"' >"$fake_mktemp"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    '[[ "$1" == build ]] || exit 71' \
    'destination=""' \
    'for argument in "$@"; do' \
    '  case "$argument" in' \
    '    type=local,dest=*) destination="${argument#type=local,dest=}" ;;' \
    '  esac' \
    'done' \
    '[[ "$destination" == /tmp/obi-source-snapshot-work.*/bridge-export.*/export ]] || exit 72' \
    'printf "%s\\n" "$destination" >"$FAKE_DOCKER_DESTINATION_RECORD"' \
    'mkdir -p -- "$destination"' \
    'printf "agent\\n" >"$destination/obi-java-agent.jar"' \
    'printf "extension\\n" >"$destination/obi-otel-extension.jar"' >"$fake_docker"
  chmod 0755 -- "$fake_docker" "$fake_mktemp"

  printf 'unchanged\n' >"$control_canary"
  for control_name in "${control_names[@]}"; do
    ln -s -- "$control_canary" "$result_directory/$control_name"
  done
  chmod 0777 -- "$runtime_directory" "$result_directory"

  if ! bash -c '
    set -Eeuo pipefail
    fixture_runner=$1
    runtime_directory=$2
    source_artifact_directory=$3
    result_directory=$4
    fake_bin=$5
    real_mktemp=$6
    docker_destination_record=$7
    control_canary=$8
    control_names=(
      .source-index-flags-0
      .source-gitlinks-0
      .source-tree-v2.entries
      .source-tree-v2.manifest
      .source-snapshot-gitlinks-0
      .source-snapshot-tree-0
      .source-snapshot-expected-0
      .source-snapshot-expected-sorted-0
      .source-snapshot-actual-0
      .source-snapshot-actual-filtered-0
      .source-snapshot-actual-sorted-0
    )
    export PATH="$fake_bin:$PATH"
    export REAL_MKTEMP="$real_mktemp"
    export FORBIDDEN_RESULT_DIR="$result_directory"
    export FAKE_DOCKER_DESTINATION_RECORD="$docker_destination_record"
    source "$fixture_runner"
    cleanup_private_source_work_fixture() {
      cleanup_source_snapshot_work_directory
      if [[ -n "${SOURCE_SNAPSHOT_DIR:-}" && \
        "$SOURCE_SNAPSHOT_DIR" == /tmp/obi-source-snapshot.* && \
        -d "$SOURCE_SNAPSHOT_DIR" && ! -L "$SOURCE_SNAPSHOT_DIR" ]]; then
        rm -rf -- "$SOURCE_SNAPSHOT_DIR"
      fi
    }
    trap cleanup_private_source_work_fixture EXIT
    RUNTIME_DIR="$runtime_directory"
    ARTIFACT_DIR="$source_artifact_directory"
    RESULT_DIR="$result_directory"
    SOURCE_SNAPSHOT_DIR=""
    SOURCE_SNAPSHOT_SCRIPT_DIR=""
    SOURCE_SNAPSHOT_WORK_DIR=""
    BRIDGE_EXPORT_DIR=""
    SOURCE_DIRTY=""
    SOURCE_PATCH_SHA256=""
    SOURCE_REVISION=""
    SOURCE_TRACKED_PATCH_SHA256=""
    SOURCE_TREE_SHA256=""
    SOURCE_TREE_MANIFEST_SCHEMA=""
    SKIP_BRIDGE_BUILD=false
    BRIDGE_BUILD_MODE=fresh
    COMMAND_TIMEOUT_SECONDS=5

    capture_source_state
    [[ "$SOURCE_SNAPSHOT_WORK_DIR" == /tmp/obi-source-snapshot-work.* && \
      "$(stat --format=%a -- "$SOURCE_SNAPSHOT_WORK_DIR")" == 700 && \
      "$(stat --format=%a -- "$RUNTIME_DIR")" == 777 && \
      "$(stat --format=%a -- "$RESULT_DIR")" == 777 && \
      "$(<"$control_canary")" == unchanged ]]
    for control_name in "${control_names[@]}"; do
      [[ -L "$RESULT_DIR/$control_name" ]]
    done

    prepare_source_snapshot
    prepare_bridge_artifacts
    bridge_artifacts_are_valid
    [[ "$BRIDGE_BUILD_MODE" == fresh && -z "$BRIDGE_EXPORT_DIR" && \
      -s "$ARTIFACT_DIR/obi-java-agent.jar" && \
      -s "$ARTIFACT_DIR/obi-otel-extension.jar" ]]
    IFS= read -r exported_destination <"$FAKE_DOCKER_DESTINATION_RECORD"
    [[ "$exported_destination" == "$SOURCE_SNAPSHOT_WORK_DIR"/bridge-export.*/export && \
      "$(<"$control_canary")" == unchanged ]]
  ' private-source-work-child \
    "$fixture_runner" "$runtime_directory" "$source_artifact_directory" "$result_directory" \
    "$fake_bin" "$real_mktemp" "$docker_destination_record" "$control_canary"; then
    printf 'source controls or bridge export used an untrusted runtime/result directory\n' >&2
    return 1
  fi
}

test_clean_source_snapshot_uses_pinned_git_inputs() {
  local -r source_repository="$TEST_TMP_DIR/source-snapshot-fixture"
  local -r hooks_directory="$source_repository/controlled-hooks"
  local -r fixture_runner="$source_repository/examples/apache-java-https/run.sh"
  local -r runtime_directory="$TEST_TMP_DIR/source-snapshot\\runtime"
  local -r source_artifact_directory="$TEST_TMP_DIR/source-snapshot-artifacts"
  local -r capture_directory="$TEST_TMP_DIR/source-snapshot-capture"
  local -r redirected_capture_directory="$TEST_TMP_DIR/source-snapshot-redirected-capture"
  local -r redirected_worktree="$TEST_TMP_DIR/source-snapshot-redirected-worktree"
  local -r redirected_index="$TEST_TMP_DIR/source-snapshot-redirected-index"
  local -r replacement_index="$TEST_TMP_DIR/source-snapshot-replacement-index"
  local -r replacement_source="$TEST_TMP_DIR/source-snapshot-replacement-source"
  local expected_snapshot=""
  local hostile_runtime_snapshot=""
  local original_revision=""
  local replacement_blob=""
  local replacement_tree=""
  local replacement_commit=""

  mkdir -p -- \
    "$source_repository/examples/apache-java-https" "$hooks_directory" \
    "$runtime_directory" "$source_artifact_directory" "$capture_directory" "$redirected_capture_directory" \
    "$redirected_worktree"
  git init --quiet "$source_repository"
  git -C "$source_repository" config user.email 'source-snapshot-test@example.invalid'
  git -C "$source_repository" config user.name 'Source Snapshot Test'
  git -C "$source_repository" config commit.gpgSign false
  git -C "$source_repository" config core.hooksPath "$hooks_directory"
  cp -- "$TEST_SCRIPT_DIR/../run.sh" "$fixture_runner"
  chmod 0755 -- "$fixture_runner"
  printf 'tracked source input\n' >"$source_repository/source"
  printf 'tracked executable input\n' >"$source_repository/executable"
  chmod 0755 -- "$source_repository/executable"
  ln -s source "$source_repository/link"
  printf 'services: {}\n' >"$source_repository/examples/apache-java-https/docker-compose.yml"
  printf 'services: {}\n' \
    >"$source_repository/examples/apache-java-https/docker-compose.primary-fault.yml"
  printf 'services: {}\n' \
    >"$source_repository/examples/apache-java-https/docker-compose.primary-live-fd.yml"
  printf 'FROM scratch\nCOPY . /source\n' >"$source_repository/javaagent.Dockerfile"
  git -C "$source_repository" add -- .
  git -C "$source_repository" commit --quiet -m 'Create source snapshot fixture'
  printf '/ignored-build-input\n' >"$source_repository/.git/info/exclude"
  printf 'ignored Docker build input\n' >"$source_repository/ignored-build-input"
  git -C "$source_repository" config core.fileMode false
  chmod 0644 -- "$source_repository/executable"
  [[ -z "$(git -C "$source_repository" status --porcelain=v1 --untracked-files=all)" ]] || {
    printf 'fixture did not reproduce a Git-clean ignored/mode-only source mutation\n' >&2
    return 1
  }
  original_revision="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$source_repository" rev-parse HEAD)"
  printf 'replacement source input\n' >"$replacement_source"
  replacement_blob="$(
    GIT_NO_REPLACE_OBJECTS=1 \
      git -C "$source_repository" hash-object -w -- "$replacement_source"
  )"
  GIT_NO_REPLACE_OBJECTS=1 GIT_INDEX_FILE="$replacement_index" \
    git -C "$source_repository" read-tree "${original_revision}^{tree}"
  GIT_NO_REPLACE_OBJECTS=1 GIT_INDEX_FILE="$replacement_index" \
    git -C "$source_repository" update-index --add \
      --cacheinfo "100644,$replacement_blob,source"
  replacement_tree="$(
    GIT_NO_REPLACE_OBJECTS=1 GIT_INDEX_FILE="$replacement_index" \
      git -C "$source_repository" write-tree
  )"
  replacement_commit="$(
    printf 'replacement source snapshot fixture\n' |
      GIT_NO_REPLACE_OBJECTS=1 \
        git -C "$source_repository" commit-tree "$replacement_tree" -p "$original_revision"
  )"
  GIT_NO_REPLACE_OBJECTS=1 \
    git -C "$source_repository" replace "$original_revision" "$replacement_commit"

  if ! expected_snapshot="$(prepare_fixture_source_snapshot \
    "$fixture_runner" "$runtime_directory" "$source_artifact_directory" "$capture_directory" \
    "$original_revision")"; then
    printf 'clean source snapshot did not isolate pinned Git inputs\n' >&2
    return 1
  fi
  [[ "$expected_snapshot" == /tmp/obi-source-snapshot.* ]] || {
    printf 'clean source snapshot did not use the fixed private system staging directory\n' >&2
    return 1
  }
  if assert_fixture_source_snapshot_parent_is_rejected \
    "$fixture_runner" "$runtime_directory" >/dev/null 2>&1; then
    printf 'clean source snapshot accepted a non-root-owned staging parent\n' >&2
    return 1
  fi
  chmod 0777 -- "$runtime_directory"
  if ! hostile_runtime_snapshot="$(prepare_fixture_source_snapshot \
    "$fixture_runner" "$runtime_directory" "$source_artifact_directory" "$capture_directory" \
    "$original_revision")"; then
    printf 'clean source snapshot depended on the working tree runtime parent\n' >&2
    return 1
  fi
  [[ "$hostile_runtime_snapshot" == /tmp/obi-source-snapshot.* ]] || {
    printf 'clean source snapshot left the fixed private system staging directory\n' >&2
    return 1
  }
  chmod 0755 -- "$runtime_directory"
  rm -rf -- "$expected_snapshot" "$hostile_runtime_snapshot"

  printf 'dirty tracked source input\n' >"$source_repository/source"
  if ! capture_fixture_source_with_redirected_git_environment \
    "$fixture_runner" "$redirected_capture_directory" "$redirected_worktree" \
    "$redirected_index"; then
    printf 'source capture trusted a caller-provided Git worktree or index\n' >&2
    return 1
  fi
}

test_run_status_serializes_default_acceptance_reason() {
  local -r result_dir="$TEST_TMP_DIR/run-status-eligible"
  local -r hostile_result_dir="$TEST_TMP_DIR/run-status-hostile-reason"
  local -r hostile_reason=$'targeted-scenario "quote" \\ slash\nnewline'

  (
    RESULT_DIR="$result_dir"
    RUN_STATUS=passed
    ACCEPTANCE_EVIDENCE=true
    ACCEPTANCE_EVIDENCE_REASON=""
    FAILURE_STAGE=""
    FAILURE_LINE=""
    mkdir -p -- "$RESULT_DIR" || return 1

    write_run_status 0
    jq -e '
      .status == "passed" and
      .exit_status == 0 and
      .acceptance_evidence == true and
      .acceptance_evidence_reason == "none"
    ' "$RESULT_DIR/run-status.json" >/dev/null
  ) || {
    printf 'eligible run status omitted its explicit acceptance reason\n' >&2
    return 1
  }

  (
    RESULT_DIR="$hostile_result_dir"
    RUN_STATUS=failed
    ACCEPTANCE_EVIDENCE=false
    ACCEPTANCE_EVIDENCE_REASON="$hostile_reason"
    FAILURE_STAGE="scenario"
    FAILURE_LINE=42
    mkdir -p -- "$RESULT_DIR" || return 1

    write_run_status 17
    jq -e --arg expected_reason "$hostile_reason" '
      .status == "failed" and
      .exit_status == 17 and
      .acceptance_evidence == false and
      .acceptance_evidence_reason == $expected_reason
    ' "$RESULT_DIR/run-status.json" >/dev/null
  ) || {
    printf 'run status did not safely serialize an acceptance reason\n' >&2
    return 1
  }
}

test_release_source_uses_one_version_for_extension() {
  local dry_run=""

  dry_run="$(make --no-print-directory -n java-release-extension \
    RELEASE_VERSION=binary-version \
    JAVA_EXTENSION_RELEASE_VERSION=source-version \
    OCI_BIN=true)"
  [[ "$dry_run" == *'obi-otel-extension-source-version.jar'* ]] || {
    printf 'release source extension did not use the source release version\n' >&2
    return 1
  }
}

test_java_build_uses_isolated_gradle_home() {
  local dockerfile=""

  for dockerfile in \
    "$TEST_SCRIPT_DIR/../../../javaagent.Dockerfile" \
    "$TEST_SCRIPT_DIR/../../../Dockerfile"; do
    awk '
      $0 == "ENV GRADLE_USER_HOME=/tmp/obi-gradle-user-home" {
        gradle_home = NR
        next
      }
      gradle_home && !creates_private_home &&
          $0 ~ /^RUN install -d -m 0700 / &&
          $0 ~ /GRADLE_USER_HOME/ && $0 ~ /&&/ {
        creates_private_home = NR
        next
      }
      $0 == "    gradle build -x buildNativeLib-amd64 -x buildNativeLib-aarch64 -x nativeTest --no-daemon" &&
          creates_private_home && NR > creates_private_home {
        invokes_gradle = NR
      }
      END { exit gradle_home && creates_private_home && invokes_gradle ? 0 : 1 }
    ' "$dockerfile" || {
      printf 'Java build Dockerfile did not isolate its Gradle user home: %s\n' \
        "$dockerfile" >&2
      return 1
    }
  done
}

test_demo_diagnostics_are_loopback_only() {
  local -r apache_config="$TEST_SCRIPT_DIR/../apache/httpd.conf"
  local -r obi_config="$TEST_SCRIPT_DIR/../configs/obi.yaml"

  grep -Fqx 'Listen 127.0.0.1:18080' "$apache_config"
  awk '
    $0 == "<LocationMatch \"^/obi-(diagnostics|transport-configuration)\">" {
      blocks += 1
      in_block = 1
      next
    }
    /^<Location/ &&
    ($0 ~ /obi-diagnostics/ || $0 ~ /obi-transport-configuration/) {
      unexpected += 1
      next
    }
    in_block && $0 == "    Require all denied" {
      denials += 1
      next
    }
    in_block && $0 == "</LocationMatch>" {
      closes += 1
      in_block = 0
      next
    }
    in_block && $0 !~ /^[[:space:]]*$/ {
      unexpected += 1
    }
    END {
      exit blocks == 1 && denials == 1 && closes == 1 &&
        unexpected == 0 && !in_block ? 0 : 1
    }
  ' "$apache_config"
  grep -Fq 'address: 127.0.0.1' "$obi_config"
  grep -Fqx '  buffer_sizes:' "$obi_config"
  grep -Fqx '    http: 32768' "$obi_config"
  grep -Fqx '                - X-OBI-Demo-ID' "$obi_config"
}

test_apache_diagnostic_denial_matrix_is_exact() {
  local -r observed="$TEST_TMP_DIR/apache-diagnostic-denials"
  local exposed_path=""
  local method=""
  local path=""

  (
    curl() {
      local request_method=GET
      local request_path=""
      local path_as_is=false
      local status=403

      while (($# > 0)); do
        case "$1" in
          --path-as-is)
            path_as_is=true
            shift
            ;;
          --head)
            request_method=HEAD
            shift
            ;;
          --request)
            request_method="$2"
            shift 2
            ;;
          http://127.0.0.1:18080/*)
            request_path="${1#http://127.0.0.1:18080}"
            shift
            ;;
          --max-time|--output|--write-out)
            shift 2
            ;;
          *)
            shift
            ;;
        esac
      done
      [[ "$path_as_is" == "true" ]] || return 1
      printf '%s %s\n' "$request_method" "$request_path" >>"$observed"
      if [[ -n "$exposed_path" && "$request_path" == "$exposed_path" ]]; then
        status=200
      fi
      printf '%d' "$status"
    }

    assert_apache_denies_java_diagnostics
    [[ "$(wc -l <"$observed")" == "48" ]] || return 1
    for path in \
      /obi-diagnostics \
      /obi-diagnostics/ \
      /obi-diagnostics/child \
      '/obi-diagnostics?probe=1' \
      '/obi-diagnostics;matrix=1' \
      /obi-diagnostics%3Bmatrix=1 \
      /obi-transport-configuration \
      /obi-transport-configuration/ \
      /obi-transport-configuration/child \
      '/obi-transport-configuration?probe=1' \
      '/obi-transport-configuration;matrix=1' \
      /obi-transport-configuration%3Bmatrix=1; do
      for method in GET HEAD OPTIONS POST; do
        grep -Fqx "$method $path" "$observed" || return 1
      done
    done

    : >"$observed"
    exposed_path='/obi-transport-configuration;matrix=1'
    if assert_apache_denies_java_diagnostics >/dev/null 2>&1; then
      return 1
    fi
  ) || {
    printf 'Apache diagnostic denial matrix was incomplete\n' >&2
    return 1
  }
}

compatibility_matrix_revision() {
  local -r matrix="$1"

  awk '
    index($0, "Matrix revision:") != 0 {
      visible_declarations += 1
      if ($0 ~ /^Matrix revision: `[a-z0-9][a-z0-9-]*`\.$/) {
        visible_matches += 1
        visible_revision = $0
        sub(/^Matrix revision: `/, "", visible_revision)
        sub(/`\.$/, "", visible_revision)
      }
    }
    index($0, "obi-compatibility-matrix-revision:") != 0 {
      declarations += 1
      if ($0 ~ /^<!-- obi-compatibility-matrix-revision: [a-z0-9][a-z0-9-]* -->$/) {
        matches += 1
        revision = $0
        sub(/^<!-- obi-compatibility-matrix-revision: /, "", revision)
        sub(/ -->$/, "", revision)
      }
    }
    END {
      if (declarations != 1 || matches != 1 ||
        visible_declarations != 1 || visible_matches != 1 ||
        revision != visible_revision) {
        exit 1
      }
      print revision
    }
  ' "$matrix"
}

assert_compatibility_matrix_reference() {
  local -r document="$1"
  local -r revision="$2"

  awk -v revision="$revision" '
    index($0, "Matrix revision:") != 0 {
      visible_references += 1
      if ($0 == "Matrix revision: `" revision "`.") {
        visible_matches += 1
      }
    }
    index($0, "obi-compatibility-matrix-revision:") != 0 {
      references += 1
      if ($0 == "<!-- obi-compatibility-matrix-revision: " revision " -->") {
        matches += 1
      }
    }
    END {
      exit (references == 1 && matches == 1 &&
        visible_references == 1 && visible_matches == 1) ? 0 : 1
    }
  ' "$document"
}

test_compatibility_matrix_lists_deployment_modes() {
  local -r matrix="$TEST_SCRIPT_DIR/../COMPATIBILITY.md"
  local -r readme="$TEST_SCRIPT_DIR/../README.md"
  local -r final_result="$TEST_SCRIPT_DIR/../FINAL-RESULT.md"
  local -r invalid_matrix="$TEST_TMP_DIR/compatibility-matrix-revision-invalid.md"
  local -r duplicate_visible_matrix="$TEST_TMP_DIR/compatibility-matrix-visible-revision-duplicate.md"
  local -r duplicate_marker_reference="$TEST_TMP_DIR/compatibility-matrix-marker-reference-duplicate.md"
  local -r malformed_reference="$TEST_TMP_DIR/compatibility-matrix-revision-malformed.md"
  local -r suffix_reference="$TEST_TMP_DIR/compatibility-matrix-revision-suffix.md"
  local -r stale_reference="$TEST_TMP_DIR/compatibility-matrix-revision-stale.md"
  local matrix_revision=""
  local document=""
  local row=""
  local -a expected_rows=(
    '| RHEL 9 / kernel 5.14 | host process | unified v2 | untested | untested | untested |'
    '| RHEL 9 / kernel 5.14 | container process | unified v2 | untested | untested | untested |'
    '| upstream 5.10 | host process | unified v2 | untested | untested | untested |'
    '| upstream 5.10 | container process | unified v2 | untested | untested | untested |'
    '| upstream 5.15 | host process | unified v2 | untested | untested | untested |'
    '| upstream 5.15 | container process | unified v2 | untested | untested | untested |'
    '| upstream 6.1 | host process | unified v2 | untested | untested | untested |'
    '| upstream 6.1 | container process | unified v2 | untested | untested | untested |'
    '| upstream 6.6 | host process | unified v2 | untested | untested | untested |'
    '| upstream 6.6 | container process | unified v2 | untested | untested | untested |'
    '| upstream 6.12 | host process | unified v2 | untested | untested | untested |'
    '| upstream 6.12 | container process | unified v2 | untested | untested | untested |'
    '| RHEL 8 / 4.18 backport | host process | host default | untested | untested | untested |'
    '| RHEL 8 / 4.18 backport | container process | container default | untested | untested | untested |'
    '| supported kernel | host process | hybrid v1/v2 | untested | untested | untested |'
    '| supported kernel | container process | hybrid v1/v2 | untested | untested | untested |'
    '| supported kernel | host process | nested/delegated v2 | untested | untested | untested |'
    '| supported kernel | container process | nested/delegated v2 | untested | untested | untested |'
    '| supported kernel | container process | sibling containers | untested | untested | untested |'
  )

  matrix_revision="$(compatibility_matrix_revision "$matrix")" || return 1
  for document in "$readme" "$final_result"; do
    assert_compatibility_matrix_reference "$document" "$matrix_revision" || return 1
  done
  printf 'Matrix revision: `%s`.\n<!-- obi-compatibility-matrix-revision: %s -->\n  <!-- obi-compatibility-matrix-revision: %s-stale -->\n' \
    "$matrix_revision" "$matrix_revision" "$matrix_revision" >"$invalid_matrix"
  if compatibility_matrix_revision "$invalid_matrix" >/dev/null; then
    printf 'compatibility matrix accepted a stale revision declaration\n' >&2
    return 1
  fi
  printf 'Matrix revision: `%s`.\n  Matrix revision: `%s-stale`.\n<!-- obi-compatibility-matrix-revision: %s -->\n' \
    "$matrix_revision" "$matrix_revision" "$matrix_revision" >"$duplicate_visible_matrix"
  if compatibility_matrix_revision "$duplicate_visible_matrix" >/dev/null; then
    printf 'compatibility matrix accepted a duplicate visible revision declaration\n' >&2
    return 1
  fi
  printf 'Matrix revision: `%s`.stale\n<!-- obi-compatibility-matrix-revision: %s -->\n' \
    "$matrix_revision" "$matrix_revision" >"$suffix_reference"
  if assert_compatibility_matrix_reference "$suffix_reference" "$matrix_revision"; then
    printf 'compatibility matrix accepted a suffixed revision reference\n' >&2
    return 1
  fi
  printf 'Matrix revision: `%s`.\n<!-- obi-compatibility-matrix-revision: %s -->\nMatrix revision: `%s-stale`.\n' \
    "$matrix_revision" "$matrix_revision" "$matrix_revision" >"$stale_reference"
  if assert_compatibility_matrix_reference "$stale_reference" "$matrix_revision"; then
    printf 'compatibility matrix accepted a stale visible revision reference\n' >&2
    return 1
  fi
  printf 'Matrix revision: `%s`.\n<!-- obi-compatibility-matrix-revision: %s -->\n  <!-- obi-compatibility-matrix-revision: %s-stale -->\n' \
    "$matrix_revision" "$matrix_revision" "$matrix_revision" >"$duplicate_marker_reference"
  if assert_compatibility_matrix_reference "$duplicate_marker_reference" "$matrix_revision"; then
    printf 'compatibility matrix accepted an indented stale revision marker\n' >&2
    return 1
  fi
  printf 'Matrix revision: `%s`.\n<!-- obi-compatibility-matrix-revision: %s -->\n<!-- obi-compatibility-matrix-revision: %s-stale\n' \
    "$matrix_revision" "$matrix_revision" "$matrix_revision" >"$malformed_reference"
  if assert_compatibility_matrix_reference "$malformed_reference" "$matrix_revision"; then
    printf 'compatibility matrix accepted a malformed stale revision reference\n' >&2
    return 1
  fi
  grep -Fqx \
    '| Environment | Deployment mode | Cgroup topology | `getsockopt` | `unix` | `auto` |' \
    "$matrix" || return 1
  for row in "${expected_rows[@]}"; do
    grep -Fqx "$row" "$matrix" || return 1
  done
  awk '
    $0 == "| Environment | Deployment mode | Agent | Cgroup topology | TLS | `getsockopt` | `unix` | `auto` | Evidence |" {
      in_observed_table = 1
      valid = 1
      next
    }
    in_observed_table && $0 == "| --- | --- | --- | --- | --- | --- | --- | --- | --- |" {
      saw_delimiter = 1
      next
    }
    in_observed_table && $0 == "" {
      reached_end = 1
      exit
    }
    in_observed_table {
      if (!saw_delimiter || NF != 11 || $3 != " container process ") {
        valid = 0
        exit
      }
      rows += 1
    }
    END {
      exit in_observed_table && saw_delimiter && reached_end && valid != 0 && rows == 5 ? 0 : 1
    }
  ' FS='|' "$matrix"
}

test_demo_uses_only_explicit_tcp_context() {
  local -r obi_config="$TEST_SCRIPT_DIR/../configs/obi.yaml"

  grep -Fqx '  context_propagation: tcp' "$obi_config"
  grep -Fqx '  disable_black_box_cp: true' "$obi_config"
}

test_demo_java_attach_timeout_is_explicit() {
  local -r obi_config="$TEST_SCRIPT_DIR/../configs/obi.yaml"
  local -r compose_file="$TEST_SCRIPT_DIR/../docker-compose.yml"

  grep -Fqx '  attach_timeout: 30s' "$obi_config"
  ! grep -Fq 'OTEL_EBPF_JAVAAGENT_ATTACH_TIMEOUT:' "$compose_file"
}

compose_service_block() {
  local -r compose_file="$1"
  local -r service="$2"

  awk -v service="$service" '
    $0 == "  " service ":" { inside = 1 }
    inside && $0 ~ /^[^[:space:]#][^:]*:[[:space:]]*$/ { exit }
    inside && $0 ~ /^  [^[:space:]#].*:[[:space:]]*$/ &&
      $0 != "  " service ":" { exit }
    inside { print }
    END { exit inside ? 0 : 1 }
  ' "$compose_file"
}

benchmark_client_resolved_topology_is_least_privilege() {
  local -r compose_json="$1"
  local -r expected_ca_source="$2"

  jq -e -s --arg expected_ca_source "$expected_ca_source" '
    length == 1
    and (
      .[0].services.benchmark as $benchmark
      | ($benchmark | type == "object")
        and ($benchmark.user == "65532:65532")
        and ($benchmark.cap_drop == ["ALL"])
        and ($benchmark.read_only == true)
        and (($benchmark.privileged // false) == false)
        and (($benchmark.cap_add // []) == [])
        and (($benchmark.pid // "") == "")
        and (($benchmark.userns_mode // "") == "")
        and ($benchmark.security_opt == ["no-new-privileges:true"])
        and (($benchmark.volumes | length) == 1)
        and (
          $benchmark.volumes[0] as $volume
          | ($volume.type == "bind")
            and ($volume.source == $expected_ca_source)
            and ($volume.target == "/benchmark-ca.crt")
            and ($volume.read_only == true)
            and (($volume.bind.create_host_path? // false) == false)
            and (($volume.source | contains(".key")) | not)
            and (($volume.source | contains(".p12")) | not)
        )
      )
  ' "$compose_json" >/dev/null
}

primary_live_fd_resolved_topology_is_scoped() {
  local -r primary_fault_json="$1"
  local -r live_fd_json="$2"

  jq -e -s --slurpfile primary_fault "$primary_fault_json" '
    length == 1
    and ($primary_fault | length == 1)
    and (
      .[0] as $live_fd
      | $live_fd.services["java-backend"] as $backend
      | ($backend | type == "object")
        and ($backend.user == "0:0")
        and (($backend.privileged // false) == false)
        and (($backend.pid // "") == "")
        and (($backend.userns_mode // "") == "")
        and (($backend.security_opt // []) == [])
        and ($backend.cap_add == ["SYS_PTRACE"])
        and (
          ($live_fd | del(.services["java-backend"].cap_add)) == $primary_fault[0]
        )
    )
  ' "$live_fd_json" >/dev/null
}

primary_fault_resolved_topology_is_scoped() {
  local -r base_json="$1"
  local -r primary_fault_json="$2"

  jq -e -s --slurpfile base "$base_json" '
    def normalize_environment:
      if type == "array" then
        map(
          . as $entry
          | ($entry | index("=")) as $separator
          | {
              key: $entry[0:$separator],
              value: $entry[($separator + 1):]
            }
        )
        | from_entries
      else
        .
      end;
    def normalize_environments:
      .services |= with_entries(
        .value |= (
          if has("environment") then
            .environment |= normalize_environment
          else
            .
          end
        )
      );
    length == 1
    and ($base | length == 1)
    and (
      (.[0] | normalize_environments) as $primary_fault
      | ($base[0] | normalize_environments) as $base_model
      | $primary_fault.services["java-backend"] as $backend
      | ($backend | type == "object")
        and ($backend.user == "0:0")
        and ($backend.environment.LD_PRELOAD ==
          "/otel/libobi-java-remote-parent-fault.so")
        and ($backend.environment.OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE ==
          "/run/obi-demo/fault/java-remote-parent.mode")
        and ($backend.tmpfs == ["/run/obi-demo/fault:uid=0,gid=0,mode=0700"])
        and (
          (
            $primary_fault
            | del(
                .services["java-backend"].user,
                .services["java-backend"].environment.LD_PRELOAD,
                .services["java-backend"].environment.OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE,
                .services["java-backend"].tmpfs
              )
          ) == $base_model
        )
    )
  ' "$primary_fault_json" >/dev/null
}

assert_policy_rejection() {
  local -r accepted_message="$1"
  shift
  local status=0

  if "$@"; then
    status=0
  else
    status=$?
  fi
  case "$status" in
    0)
      printf '%s\n' "$accepted_message" >&2
      return 1
      ;;
    1)
      return 0
      ;;
    *)
      printf 'policy validator failed unexpectedly with status %d: %s\n' \
        "$status" "$accepted_message" >&2
      return "$status"
      ;;
  esac
}

assert_policy_acceptance() {
  local -r rejected_message="$1"
  shift
  local status=0

  if "$@"; then
    return 0
  else
    status=$?
  fi
  if [[ "$status" == "1" ]]; then
    printf '%s\n' "$rejected_message" >&2
    return 1
  fi
  printf 'policy validator failed unexpectedly with status %d: %s\n' \
    "$status" "$rejected_message" >&2
  return "$status"
}

assert_json_fixture_shape() {
  local -r fixture_file="$1"
  local -r fixture_filter="$2"
  local -r failure_message="$3"
  local status=0

  if jq -e "$fixture_filter" "$fixture_file" >/dev/null; then
    return 0
  else
    status=$?
  fi
  if [[ "$status" == "1" ]]; then
    printf '%s\n' "$failure_message" >&2
    return 1
  fi
  printf 'fixture validation failed unexpectedly with status %d: %s\n' \
    "$status" "$failure_message" >&2
  return "$status"
}

resolve_compose_model_without_interpolation() {
  local -r compose_json="$1"
  shift
  local -a compose_files=()
  local compose_file=""

  for compose_file in "$@"; do
    compose_files+=(--file "$compose_file")
  done
  if ! COMPOSE_PROFILES='*' docker compose \
    --project-name "$PROJECT_NAME" \
    --project-directory "$TEST_SCRIPT_DIR/.." "${compose_files[@]}" \
    config --format json --no-consistency --no-interpolate >"$compose_json"; then
    return 2
  fi
}

resolve_compose_fixture_without_interpolation() {
  local -r compose_file="$1"
  local -r compose_json="$2"

  resolve_compose_model_without_interpolation "$compose_json" "$compose_file"
}

resolve_compose_fixture() {
  local -r compose_file="$1"
  local -r compose_json="$2"

  if ! COMPOSE_PROFILES='*' docker compose \
    --project-name "$PROJECT_NAME" \
    --project-directory "$TEST_SCRIPT_DIR/.." --file "$compose_file" \
    config --format json >"$compose_json"; then
    return 2
  fi
}

compose_overlay_is_interpolation_free() {
  local -r compose_file="$1"
  local -r compose_json="$TEST_TMP_DIR/compose-overlay-interpolation-check.json"

  resolve_compose_fixture_without_interpolation \
    "$compose_file" "$compose_json" || return $?
  jq -e -s '
      length == 1
      and ([.[0] | .. | strings | select(contains("$"))] | length == 0)
      and ([.[0] | .. | objects | keys[] | select(contains("$"))] | length == 0)
    ' "$compose_json" >/dev/null
}

compose_source_model_build_arguments_are_allowlisted() {
  local -r compose_json="$1"
  local example_directory=""
  local repository_root=""

  example_directory="$(cd -- "$TEST_SCRIPT_DIR/.." && pwd -P)" || return 2
  repository_root="$(cd -- "$example_directory/../.." && pwd -P)" || return 2
  jq -e -s \
    --arg example_directory "$example_directory" \
    --arg repository_root "$repository_root" '
    def normalize_build_arguments:
      if type == "object" then
        to_entries
        | if all(
            .[];
            (.key | test("^[A-Za-z_][A-Za-z0-9_]*$"))
            and ((.value | type) == "string")
          ) then
            .
          else
            null
          end
      elif type == "array" then
        map(
          if type == "string"
            and test("^[A-Za-z_][A-Za-z0-9_]*=") then
            (index("=")) as $separator
            | {
                key: .[0:$separator],
                value: .[($separator + 1):]
              }
          else
            null
          end
        ) as $arguments
        | ($arguments | map(select(. != null) | .key)) as $keys
        | if ($arguments | all(. != null))
          and (($keys | length) == ($keys | unique | length)) then
            $arguments
          else
            null
          end
      else
        null
      end;
    def expected_obi_build_arguments:
      [
        {
          key: "RELEASE_REVISION",
          value: "local"
        },
        {
          key: "RELEASE_VERSION",
          value: "apache-java-https-demo"
        }
      ];
    def build_is_allowlisted($service; $build):
      if ($build | type) != "object" then
        false
      elif $service == "java-backend" then
        $build == {
          context: $example_directory,
          dockerfile: "java/Dockerfile"
        }
      elif $service == "obi" then
        (($build | keys) == ["args", "context", "dockerfile"])
        and ($build.context == $repository_root)
        and ($build.dockerfile == "Dockerfile")
        and (
          ($build.args | normalize_build_arguments) as $arguments
          | ($arguments != null)
            and (($arguments | sort_by([.key, .value]))
              == (expected_obi_build_arguments | sort_by([.key, .value])))
        )
      elif $service == "trace-receiver" then
        $build == {
          context: $repository_root,
          dockerfile: "examples/apache-java-https/tracecheck/Dockerfile"
        }
      else
        false
      end;
    length == 1
    and (.[0].services | type) == "object"
    and all(
      .[0].services | to_entries[];
      . as $service
      | if ($service.value | type) != "object" then
          false
        elif ($service.value | has("build")) then
          build_is_allowlisted($service.key; $service.value.build)
        else
          true
        end
    )
  ' "$compose_json" >/dev/null
}

compose_file_build_arguments_are_explicit() {
  local -r compose_file="$1"
  local -r compose_json="$TEST_TMP_DIR/compose-source-build-arguments.json"
  local compose_help=""
  local required_flag=""

  compose_help="$(LC_ALL=C docker compose config --help 2>&1)" || return 2
  for required_flag in \
    --no-consistency \
    --no-interpolate \
    --no-normalize; do
    if [[ ! "$compose_help" =~ (^|[[:space:]])${required_flag}([[:space:]]|$) ]]; then
      printf 'docker compose config lacks required flag: %s\n' \
        "$required_flag" >&2
      return 2
    fi
  done
  if ! COMPOSE_PROFILES='*' docker compose \
    --project-name "$PROJECT_NAME" \
    --project-directory "$TEST_SCRIPT_DIR/.." --file "$compose_file" \
    config --format json --no-consistency --no-interpolate \
    --no-normalize >"$compose_json"; then
    return 2
  fi
  compose_source_model_build_arguments_are_allowlisted "$compose_json"
}

compose_runtime_model_interpolation_is_allowlisted() {
  local -r compose_json="$1"
  local -r expected_project_name="$PROJECT_NAME"
  local example_directory=""
  local expected_benchmark_source=""
  local expected_generation_source=""
  local repository_root=""

  example_directory="$(cd -- "$TEST_SCRIPT_DIR/.." && pwd -P)" || return 2
  repository_root="$(cd -- "$example_directory/../.." && pwd -P)" || return 2
  expected_benchmark_source="$example_directory/\${BENCHMARK_CA_SOURCE:-./.runtime/certs/ca.crt}"
  expected_generation_source="$example_directory/\${GENERATION_FAULT_CONTROL_SOURCE:-./.runtime/generation-fault-control}"
  jq -e -s \
    --arg example_directory "$example_directory" \
    --arg expected_project_name "$expected_project_name" \
    --arg repository_root "$repository_root" \
    --arg expected_benchmark_source "$expected_benchmark_source" \
    --arg expected_generation_source "$expected_generation_source" '
    def environment_array_keys:
      map(
        . as $entry
        | ($entry | index("=")) as $separator
        | $entry[0:$separator]
      );
    def environments_are_explicit:
      (.services | type) == "object"
      and all(
        .services[];
        if type != "object" then
          false
        elif has("environment") then
          .environment as $environment
          | if ($environment | type) == "array" then
              all(
                $environment[];
                if type == "string" then
                  test("^[A-Za-z_][A-Za-z0-9_]*=")
                else
                  false
                end
              )
              and (
                ($environment | environment_array_keys | length) ==
                ($environment | environment_array_keys | unique | length)
              )
            elif ($environment | type) == "object" then
              all(
                $environment | to_entries[];
                (.key | test("^[A-Za-z_][A-Za-z0-9_]*$"))
                and ((.value | type) == "string")
              )
            else
              false
            end
        else
          true
        end
      );
    def expected_obi_build_arguments:
      [
        {
          key: "RELEASE_REVISION",
          value: "local"
        },
        {
          key: "RELEASE_VERSION",
          value: "apache-java-https-demo"
        }
      ];
    def normalize_build_arguments:
      if type == "object" then
        to_entries
        | if all(
            .[];
            (.key | test("^[A-Za-z_][A-Za-z0-9_]*$"))
            and ((.value | type) == "string")
          ) then
            .
          else
            null
          end
      elif type == "array" then
        map(
          if type == "string"
            and test("^[A-Za-z_][A-Za-z0-9_]*=") then
            (index("=")) as $separator
            | {
                key: .[0:$separator],
                value: .[($separator + 1):]
              }
          else
            null
          end
        ) as $arguments
        | ($arguments | map(select(. != null) | .key)) as $keys
        | if ($arguments | all(. != null))
          and (($keys | length) == ($keys | unique | length)) then
            $arguments
          else
            null
          end
      else
        null
      end;
    def build_is_allowlisted($service; $build):
      if ($build | type) != "object" then
        false
      elif $service == "java-backend" then
        $build == {
          context: $example_directory,
          dockerfile: "java/Dockerfile"
        }
      elif $service == "obi" then
        (($build | keys) == ["args", "context", "dockerfile"])
        and ($build.context == $repository_root)
        and ($build.dockerfile == "Dockerfile")
        and (
          ($build.args | normalize_build_arguments) as $arguments
          | ($arguments != null)
            and (($arguments | sort_by([.key, .value]))
              == (expected_obi_build_arguments | sort_by([.key, .value])))
        )
      elif $service == "trace-receiver" then
        $build == {
          context: $repository_root,
          dockerfile: "examples/apache-java-https/tracecheck/Dockerfile"
        }
      else
        false
      end;
    def build_inputs_are_explicit:
      all(
        .services | to_entries[];
        . as $service
        | if ($service.value | type) != "object" then
          false
        elif ($service.value | has("build")) then
          build_is_allowlisted($service.key; $service.value.build)
        else
          true
        end
      );
    def service_environment_files_are_absent:
      all(
        .services[];
        if type != "object" then
          false
        elif has("env_file") then
          ((.env_file | type) == "array") and ((.env_file | length) == 0)
        else
          true
        end
      );
    def dynamic_named_sources_are_absent:
      (((.secrets // {}) | type) == "object")
      and all(
        (.secrets // {})[];
        if type == "object" then
          (has("environment") | not)
          and (has("file") | not)
          and ((.external // false) == false)
        else
          false
        end
      )
      and (((.configs // {}) | type) == "object")
      and all(
        (.configs // {})[];
        if type == "object" then
          (has("environment") | not)
          and (has("file") | not)
          and ((.external // false) == false)
        else
          false
        end
      );
    def expected_mounts:
      [
        {
          service: "apache-proxy",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "\($example_directory)/apache/httpd.conf",
            target: "/usr/local/apache2/conf/httpd.conf",
            type: "bind"
          }
        },
        {
          service: "apache-proxy",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "\($example_directory)/.runtime/certs/ca.crt",
            target: "/run/obi-demo/certs/ca.crt",
            type: "bind"
          }
        },
        {
          service: "benchmark",
          volume: {
            bind: {create_host_path: false},
            read_only: true,
            source: $expected_benchmark_source,
            target: "/benchmark-ca.crt",
            type: "bind"
          }
        },
        {
          service: "bridge-fault",
          volume: {
            source: "java-remote-parent-socket",
            target: "/var/run/obi",
            type: "volume",
            volume: {}
          }
        },
        {
          service: "coalesced-source",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "\($example_directory)/.runtime/certs/ca.crt",
            target: "/run/obi-demo/certs/ca.crt",
            type: "bind"
          }
        },
        {
          service: "generation-fault",
          volume: {
            bind: {create_host_path: false},
            source: $expected_generation_source,
            target: "/control",
            type: "bind"
          }
        },
        {
          service: "java-backend",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "\($example_directory)/.runtime/certs/server.p12",
            target: "/run/obi-demo/certs/server.p12",
            type: "bind"
          }
        },
        {
          service: "java-backend",
          volume: {
            source: "java-remote-parent-socket",
            target: "/var/run/obi",
            type: "volume",
            volume: {}
          }
        },
        {
          service: "obi",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "\($example_directory)/configs/obi.yaml",
            target: "/config/obi.yaml",
            type: "bind"
          }
        },
        {
          service: "obi",
          volume: {
            source: "java-remote-parent-socket",
            target: "/var/run/obi",
            type: "volume",
            volume: {}
          }
        },
        {
          service: "obi",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "/sys/fs/cgroup",
            target: "/sys/fs/cgroup",
            type: "bind"
          }
        },
        {
          service: "obi",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "/sys/kernel/security",
            target: "/sys/kernel/security",
            type: "bind"
          }
        },
        {
          service: "obi",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "/sys/kernel/tracing",
            target: "/sys/kernel/tracing",
            type: "bind"
          }
        },
        {
          service: "obi",
          volume: {
            bind: {create_host_path: true},
            read_only: true,
            source: "/sys/kernel/debug",
            target: "/sys/kernel/debug",
            type: "bind"
          }
        },
        {
          service: "security-probe",
          volume: {
            source: "java-remote-parent-socket",
            target: "/var/run/obi",
            type: "volume",
            volume: {}
          }
        },
        {
          service: "security-unix-sibling-probe",
          volume: {
            read_only: true,
            source: "java-remote-parent-socket",
            target: "/var/run/obi",
            type: "volume",
            volume: {}
          }
        },
        {
          service: "socket-init",
          volume: {
            source: "java-remote-parent-socket",
            target: "/var/run/obi",
            type: "volume",
            volume: {}
          }
        }
      ];
    def mount_sort_key:
      [.service, .volume.type, .volume.target, .volume.source];
    def empty_attachment_field($field):
      if has($field) then
        (.[$field] == null)
        or (.[$field] == false)
        or (.[$field] == [])
        or (.[$field] == {})
      else
        true
      end;
    def discard_empty_topology_fields:
      with_entries(
        select(
          (.key == "service")
          or (
            (.value != null)
            and (.value != false)
            and (.value != "")
            and (.value != [])
            and (.value != {})
          )
        )
      );
    def discard_legacy_null_service_defaults:
      if .command? == null then del(.command) else . end
      | if .entrypoint? == null then del(.entrypoint) else . end;
    def discard_legacy_false_volume_default:
      if .external? == false then del(.external) else . end;
    def normalize_environment:
      if type == "array" then
        map(
          . as $entry
          | ($entry | index("=")) as $separator
          | {
              key: $entry[0:$separator],
              value: $entry[($separator + 1):]
            }
        )
        | from_entries
      else
        .
      end;
    def service_execution_topology:
      [
        .services | to_entries[] as $service
        | {
            service: $service.key,
            command: $service.value.command?,
            entrypoint: $service.value.entrypoint?,
            environment: (
              $service.value.environment? | normalize_environment
            )
          }
        | discard_empty_topology_fields
      ]
      | sort_by(.service);
    def expected_service_execution_topology:
      [
        {
          service: "apache-proxy",
          environment: {
            BACKEND_TLS_PROTOCOL: "${BACKEND_TLS_PROTOCOL:-TLSv1.3}"
          }
        },
        {
          service: "benchmark",
          entrypoint: ["/trace-benchmark"]
        },
        {
          service: "bridge-fault",
          entrypoint: [
            "/fault-bridge",
            "--socket",
            "/var/run/obi/java-remote-parent.sock",
            "--matching-valid-takes",
            "${MATCHING_VALID_TAKES:-1}"
          ],
          environment: {
            FAULT_MODE: "${FAULT_MODE:-alternating}"
          }
        },
        {
          service: "coalesced-source",
          entrypoint: ["/coalesced-source"],
          environment: {
            BACKEND_ADDRESS: "127.0.0.1:18444",
            BACKEND_TLS_PROTOCOL: "${BACKEND_TLS_PROTOCOL:-TLSv1.3}",
            CA_PATH: "/run/obi-demo/certs/ca.crt",
            LISTEN_ADDRESS: "127.0.0.1:18081"
          }
        },
        {
          service: "generation-fault",
          entrypoint: ["/generation-fault"]
        },
        {
          service: "java-backend",
          environment: {
            HTTPS_PORT: "18443",
            JAVA_TOOL_OPTIONS:
              "${JAVA_TOOL_OPTIONS_VALUE--javaagent:/otel/official-javaagent.jar}",
            LD_PRELOAD: "/otel/libobi-java-remote-parent-fault.so",
            NETTY_HTTPS_PORT: "18444",
            OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE:
              "/run/obi-demo/fault/java-remote-parent.mode",
            OTEL_BSP_EXPORT_TIMEOUT: "5000",
            OTEL_BSP_SCHEDULE_DELAY:
              "${OTEL_BSP_SCHEDULE_DELAY_VALUE:-100}",
            OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:14318",
            OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
            OTEL_INSTRUMENTATION_HTTP_SERVER_CAPTURE_REQUEST_HEADERS:
              "x-obi-demo-id",
            OTEL_JAVAAGENT_EXTENSIONS:
              "${OTEL_JAVAAGENT_EXTENSIONS_VALUE-/otel/obi-otel-extension.jar}",
            OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED:
              "${OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE:-false}",
            OTEL_LOGS_EXPORTER: "none",
            OTEL_METRICS_EXPORTER: "none",
            OTEL_OBI_REMOTE_PARENT_ENABLED: "${EXTENSION_ENABLED:-true}",
            OTEL_PROPAGATORS:
              "${OTEL_PROPAGATORS_VALUE:-obi,tracecontext,baggage}",
            OTEL_SERVICE_NAME: "java-backend",
            OTEL_TRACES_SAMPLER: "always_on",
            TLS_BOUNDARY_COALESCED_HTTPS_PORT: "18446",
            TLS_BOUNDARY_SPLIT_HTTPS_PORT: "18445",
            TLS_KEYSTORE_PASSWORD: "changeit",
            TLS_KEYSTORE_PATH: "/run/obi-demo/certs/server.p12",
            TLS_PROTOCOL: "${BACKEND_TLS_PROTOCOL:-TLSv1.3}",
            TLS_RECEIVE_BOUNDARY_FIXTURE_ENABLED: "1"
          }
        },
        {
          service: "map-pressure",
          entrypoint: ["/map-pressure"]
        },
        {
          service: "map-state",
          entrypoint: ["/map-state"]
        },
        {
          service: "obi",
          command: ["--config=/config/obi.yaml"],
          environment: {
            OTEL_EBPF_BPF_CONTEXT_PROPAGATION:
              "${CONTEXT_PROPAGATION:-tcp}",
            OTEL_EBPF_JAVA_REMOTE_PARENT_RETRIEVAL_TTL:
              "${REMOTE_PARENT_RETRIEVAL_TTL:-0s}",
            OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_GROUP_ID: "65534",
            OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_PATH:
              "/var/run/obi/java-remote-parent.sock",
            OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT: "50ms",
            OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT:
              "${BRIDGE_TRANSPORT:-getsockopt}",
            OTEL_EBPF_JAVA_REMOTE_PARENT_TTL:
              "${REMOTE_PARENT_TTL:-30s}"
          }
        },
        {
          service: "scenario",
          entrypoint: ["/trace-scenario"]
        },
        {
          service: "security-probe",
          entrypoint: [
            "/security-probe",
            "--socket",
            "/var/run/obi/java-remote-parent.sock",
            "--mode",
            "${SECURITY_PROBE_MODE:-abuse}",
            "--timeout",
            "${SECURITY_PROBE_TIMEOUT:-60s}"
          ]
        },
        {
          service: "security-unix-sibling-probe",
          entrypoint: [
            "/security-probe",
            "--socket",
            "/var/run/obi/java-remote-parent.sock",
            "--mode",
            "abuse-race",
            "--timeout",
            "${SECURITY_PROBE_TIMEOUT:-60s}"
          ]
        },
        {
          service: "socket-init",
          command: [
            "chown 0:65534 /var/run/obi && chmod 0750 /var/run/obi"
          ],
          entrypoint: ["/bin/sh", "-ec"]
        },
        {
          service: "trace-receiver",
          environment: {
            LISTEN_ADDRESS: "127.0.0.1:14318",
            MAX_RETAINED_BYTES: "67108864",
            MAX_SPANS: "10000",
            MAX_VALUE_BYTES: "4096"
          }
        }
      ];
    def service_security_topology:
      [
        .services | to_entries[] as $service
        | {
            service: $service.key,
            image: $service.value.image?,
            labels: $service.value.labels?,
            pull_policy: $service.value.pull_policy?,
            restart: $service.value.restart?,
            privileged: $service.value.privileged?,
            cap_add: $service.value.cap_add?,
            cap_drop: $service.value.cap_drop?,
            group_add: $service.value.group_add?,
            security_opt: $service.value.security_opt?,
            read_only: $service.value.read_only?,
            user: $service.value.user?,
            network_mode: $service.value.network_mode?,
            networks: $service.value.networks?,
            ports: $service.value.ports?,
            expose: $service.value.expose?,
            extra_hosts: $service.value.extra_hosts?,
            dns: $service.value.dns?,
            dns_search: $service.value.dns_search?,
            dns_opt: $service.value.dns_opt?,
            external_links: $service.value.external_links?,
            links: $service.value.links?,
            pid: $service.value.pid?,
            ipc: $service.value.ipc?,
            uts: $service.value.uts?,
            userns_mode: $service.value.userns_mode?,
            cgroup: $service.value.cgroup?,
            cgroup_parent: $service.value.cgroup_parent?,
            runtime: $service.value.runtime?,
            isolation: $service.value.isolation?,
            sysctls: $service.value.sysctls?,
            hostname: $service.value.hostname?,
            domainname: $service.value.domainname?,
            mac_address: $service.value.mac_address?
          }
        | discard_empty_topology_fields
      ]
      | sort_by(.service);
    def service_key_topology:
      [
        .services | to_entries[]
        | {
            service: .key,
            keys: (.value | discard_legacy_null_service_defaults | keys)
          }
      ]
      | sort_by(.service);
    def expected_service_key_topology:
      [
        {
          service: "apache-proxy",
          keys: [
            "depends_on", "environment", "image", "labels",
            "network_mode", "restart", "volumes"
          ]
        },
        {
          service: "benchmark",
          keys: [
            "cap_drop", "entrypoint", "image", "labels", "network_mode",
            "profiles", "read_only", "security_opt", "user", "volumes"
          ]
        },
        {
          service: "bridge-fault",
          keys: [
            "entrypoint", "environment", "image", "labels",
            "network_mode", "profiles", "user", "volumes"
          ]
        },
        {
          service: "coalesced-source",
          keys: [
            "depends_on", "entrypoint", "environment", "image", "labels",
            "network_mode", "restart", "volumes"
          ]
        },
        {
          service: "generation-fault",
          keys: [
            "entrypoint", "image", "labels", "network_mode", "privileged",
            "profiles", "read_only", "volumes"
          ]
        },
        {
          service: "java-backend",
          keys: [
            "build", "cap_add", "depends_on", "environment", "image",
            "labels", "network_mode", "restart", "tmpfs", "user",
            "volumes"
          ]
        },
        {
          service: "map-pressure",
          keys: [
            "entrypoint", "image", "labels", "network_mode", "privileged",
            "profiles"
          ]
        },
        {
          service: "map-state",
          keys: [
            "entrypoint", "image", "labels", "network_mode", "privileged",
            "profiles"
          ]
        },
        {
          service: "obi",
          keys: [
            "build", "command", "depends_on", "environment", "image",
            "labels", "network_mode", "pid", "privileged", "restart",
            "volumes"
          ]
        },
        {
          service: "scenario",
          keys: ["entrypoint", "image", "labels", "network_mode", "profiles"]
        },
        {
          service: "security-probe",
          keys: [
            "entrypoint", "image", "labels", "network_mode", "profiles",
            "user", "volumes"
          ]
        },
        {
          service: "security-unix-sibling-probe",
          keys: [
            "cap_drop", "entrypoint", "image", "labels", "network_mode",
            "profiles", "read_only", "security_opt", "user", "volumes"
          ]
        },
        {
          service: "socket-init",
          keys: [
            "command", "entrypoint", "image", "labels", "network_mode",
            "restart", "user", "volumes"
          ]
        },
        {
          service: "trace-receiver",
          keys: [
            "build", "environment", "image", "labels", "network_mode",
            "restart"
          ]
        }
      ];
    def dependency_topology:
      [
        .services | to_entries[]
        | select(.value.depends_on? != null)
        | {service: .key, depends_on: .value.depends_on}
      ]
      | sort_by(.service);
    def expected_dependency_topology:
      [
        {
          service: "apache-proxy",
          depends_on: {
            "coalesced-source": {
              condition: "service_started",
              required: true
            },
            "java-backend": {
              condition: "service_started",
              required: true
            }
          }
        },
        {
          service: "coalesced-source",
          depends_on: {
            "java-backend": {
              condition: "service_started",
              required: true
            }
          }
        },
        {
          service: "java-backend",
          depends_on: {
            "socket-init": {
              condition: "service_completed_successfully",
              required: true
            },
            "trace-receiver": {
              condition: "service_started",
              required: true
            }
          }
        },
        {
          service: "obi",
          depends_on: {
            "apache-proxy": {
              condition: "service_started",
              required: true
            },
            "java-backend": {
              condition: "service_started",
              required: true
            },
            "socket-init": {
              condition: "service_completed_successfully",
              required: true
            },
            "trace-receiver": {
              condition: "service_started",
              required: true
            }
          }
        }
      ];
    def ownership_labels:
      {
        "io.opentelemetry.obi.apache-java-https.owner":
          "acceptance-demo-v1"
      };
    def apache_image:
      "httpd:2.4.68-alpine@sha256:1b766f17b84026429b7cb243317b142921b24432336e798bc881c43f45ed9567";
    def tracecheck_image:
      "obi-apache-java-https-tracecheck:local";
    def expected_service_security_topology:
      [
        {
          service: "apache-proxy",
          image: apache_image,
          labels: ownership_labels,
          network_mode: "host",
          restart: "no"
        },
        {
          service: "benchmark",
          cap_drop: ["ALL"],
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "host",
          read_only: true,
          security_opt: ["no-new-privileges:true"],
          user: "65532:65532"
        },
        {
          service: "bridge-fault",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "none",
          user: "0:0"
        },
        {
          service: "coalesced-source",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "host",
          restart: "no"
        },
        {
          service: "generation-fault",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "none",
          privileged: true,
          read_only: true
        },
        {
          service: "java-backend",
          cap_add: ["SYS_PTRACE"],
          image: "obi-apache-java-https-backend:local",
          labels: ownership_labels,
          network_mode: "host",
          restart: "no",
          user: "0:0"
        },
        {
          service: "map-pressure",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "none",
          privileged: true
        },
        {
          service: "map-state",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "none",
          privileged: true
        },
        {
          service: "obi",
          image: "obi-apache-java-https:local",
          labels: ownership_labels,
          network_mode: "host",
          pid: "host",
          privileged: true,
          restart: "no"
        },
        {
          service: "scenario",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "host"
        },
        {
          service: "security-probe",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "none",
          user: "0:0"
        },
        {
          service: "security-unix-sibling-probe",
          cap_drop: ["ALL"],
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "none",
          read_only: true,
          security_opt: ["no-new-privileges:true"],
          user: "65534:65534"
        },
        {
          service: "socket-init",
          image: apache_image,
          labels: ownership_labels,
          network_mode: "none",
          restart: "no",
          user: "0:0"
        },
        {
          service: "trace-receiver",
          image: tracecheck_image,
          labels: ownership_labels,
          network_mode: "host",
          restart: "no"
        }
      ];
    def mount_topology_is_allowlisted:
      . as $model
      | [
          $model.services | to_entries[] as $service
          | ($service.value.volumes? // []) as $volumes
          | if ($volumes | type) == "array" then
              $volumes[]
              | if .type == "bind" then
                  .bind = (
                    (.bind // {}) + {
                      create_host_path: (.bind.create_host_path? // false)
                    }
                  )
                else
                  .
                end
              | {service: $service.key, volume: .}
            else
              empty
            end
        ]
        | sort_by(mount_sort_key) as $mounts
      | [
          $model.services | to_entries[] as $service
          | select(
              (($service.value.tmpfs? // []) | type) == "array"
              and (($service.value.tmpfs? // []) | length) > 0
            )
          | {service: $service.key, tmpfs: $service.value.tmpfs}
      ]
        | sort_by(.service) as $tmpfs
      | (expected_mounts | sort_by(mount_sort_key)) as $allowed_mounts
      | [
          {
            service: "java-backend",
            tmpfs: ["/run/obi-demo/fault:uid=0,gid=0,mode=0700"]
          }
        ] as $allowed_tmpfs
      | (
          all(
            $model.services[];
            (if has("volumes") then (.volumes | type) == "array" else true end)
            and (if has("tmpfs") then (.tmpfs | type) == "array" else true end)
            and empty_attachment_field("volumes_from")
            and empty_attachment_field("devices")
            and empty_attachment_field("device_cgroup_rules")
            and empty_attachment_field("gpus")
            and empty_attachment_field("blkio_config")
            and empty_attachment_field("secrets")
            and empty_attachment_field("configs")
            and empty_attachment_field("credential_spec")
            and empty_attachment_field("use_api_socket")
            and empty_attachment_field("develop")
            and empty_attachment_field("models")
            and empty_attachment_field("provider")
            and empty_attachment_field("label_file")
            and empty_attachment_field("post_start")
            and empty_attachment_field("pre_stop")
            and empty_attachment_field("deploy")
            and empty_attachment_field("scale")
            and empty_attachment_field("container_name")
            and empty_attachment_field("logging")
            and empty_attachment_field("pids_limit")
            and empty_attachment_field("shm_size")
            and empty_attachment_field("oom_kill_disable")
            and empty_attachment_field("oom_score_adj")
            and empty_attachment_field("ulimits")
            and empty_attachment_field("storage_opt")
            and empty_attachment_field("init")
            and empty_attachment_field("healthcheck")
          )
          and (($model.secrets // {}) == {})
          and (($model.configs // {}) == {})
          and (($model.models // {}) == {})
          and ($model.name == $expected_project_name)
          and (
            ($model.volumes // {})
            | with_entries(.value |= discard_legacy_false_volume_default)
          ) == {
              "java-remote-parent-socket": {
                labels: {
                  "io.opentelemetry.obi.apache-java-https.owner":
                    "acceptance-demo-v1"
                },
                name: "\($expected_project_name)_java-remote-parent-socket"
              }
            }
          and ($mounts == $allowed_mounts)
          and ($tmpfs == $allowed_tmpfs)
          and (($model | service_key_topology)
            == expected_service_key_topology)
          and (($model | dependency_topology)
            == expected_dependency_topology)
          and (($model | service_execution_topology)
            == expected_service_execution_topology)
          and (($model | service_security_topology)
            == expected_service_security_topology)
          and (
            [
              $model.services | to_entries[]
              | select((.value.profiles // []) != [])
              | {service: .key, profiles: .value.profiles}
            ]
            | sort_by(.service)
          ) == [
            {service: "benchmark", profiles: ["tools"]},
            {service: "bridge-fault", profiles: ["tools"]},
            {service: "generation-fault", profiles: ["tools"]},
            {service: "map-pressure", profiles: ["tools"]},
            {service: "map-state", profiles: ["tools"]},
            {service: "scenario", profiles: ["tools"]},
            {service: "security-probe", profiles: ["tools"]},
            {service: "security-unix-sibling-probe", profiles: ["tools"]}
          ]
          and (
            (($model.networks // {}) == {})
            or (($model.networks // {}) == {
              default: {
                labels: {
                  "io.opentelemetry.obi.apache-java-https.owner":
                    "acceptance-demo-v1"
                },
                name: "\($expected_project_name)_default"
              }
            })
          )
        );
    def normalize_environments:
      .services |= with_entries(
        .value |= (
          if has("environment") then
            .environment |= normalize_environment
          else
            .
          end
        )
      );
    def allowed_interpolations:
      [
        {
          path: ["services", "apache-proxy", "environment", "BACKEND_TLS_PROTOCOL"],
          value: "${BACKEND_TLS_PROTOCOL:-TLSv1.3}"
        },
        {
          path: ["services", "bridge-fault", "environment", "FAULT_MODE"],
          value: "${FAULT_MODE:-alternating}"
        },
        {
          path: ["services", "coalesced-source", "environment", "BACKEND_TLS_PROTOCOL"],
          value: "${BACKEND_TLS_PROTOCOL:-TLSv1.3}"
        },
        {
          path: ["services", "java-backend", "environment", "JAVA_TOOL_OPTIONS"],
          value: "${JAVA_TOOL_OPTIONS_VALUE--javaagent:/otel/official-javaagent.jar}"
        },
        {
          path: ["services", "java-backend", "environment", "OTEL_BSP_SCHEDULE_DELAY"],
          value: "${OTEL_BSP_SCHEDULE_DELAY_VALUE:-100}"
        },
        {
          path: ["services", "java-backend", "environment", "OTEL_JAVAAGENT_EXTENSIONS"],
          value: "${OTEL_JAVAAGENT_EXTENSIONS_VALUE-/otel/obi-otel-extension.jar}"
        },
        {
          path: ["services", "java-backend", "environment", "OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED"],
          value: "${OTEL_JAVA_EXPORTER_OTLP_RETRY_DISABLED_VALUE:-false}"
        },
        {
          path: ["services", "java-backend", "environment", "OTEL_OBI_REMOTE_PARENT_ENABLED"],
          value: "${EXTENSION_ENABLED:-true}"
        },
        {
          path: ["services", "java-backend", "environment", "OTEL_PROPAGATORS"],
          value: "${OTEL_PROPAGATORS_VALUE:-obi,tracecontext,baggage}"
        },
        {
          path: ["services", "java-backend", "environment", "TLS_PROTOCOL"],
          value: "${BACKEND_TLS_PROTOCOL:-TLSv1.3}"
        },
        {
          path: ["services", "obi", "environment", "OTEL_EBPF_BPF_CONTEXT_PROPAGATION"],
          value: "${CONTEXT_PROPAGATION:-tcp}"
        },
        {
          path: ["services", "obi", "environment", "OTEL_EBPF_JAVA_REMOTE_PARENT_RETRIEVAL_TTL"],
          value: "${REMOTE_PARENT_RETRIEVAL_TTL:-0s}"
        },
        {
          path: ["services", "obi", "environment", "OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT"],
          value: "${BRIDGE_TRANSPORT:-getsockopt}"
        },
        {
          path: ["services", "obi", "environment", "OTEL_EBPF_JAVA_REMOTE_PARENT_TTL"],
          value: "${REMOTE_PARENT_TTL:-30s}"
        },
        {
          path: ["services", "benchmark", "volumes", 0, "source"],
          value: $expected_benchmark_source
        },
        {
          path: ["services", "generation-fault", "volumes", 0, "source"],
          value: $expected_generation_source
        },
        {
          path: ["services", "bridge-fault", "entrypoint", 4],
          value: "${MATCHING_VALID_TAKES:-1}"
        },
        {
          path: ["services", "security-probe", "entrypoint", 4],
          value: "${SECURITY_PROBE_MODE:-abuse}"
        },
        {
          path: ["services", "security-probe", "entrypoint", 6],
          value: "${SECURITY_PROBE_TIMEOUT:-60s}"
        },
        {
          path: ["services", "security-unix-sibling-probe", "entrypoint", 6],
          value: "${SECURITY_PROBE_TIMEOUT:-60s}"
        }
      ];
    length == 1
    and (
      .[0] as $model
      | ($model | environments_are_explicit)
        and ($model | build_inputs_are_explicit)
        and ($model | service_environment_files_are_absent)
        and ($model | dynamic_named_sources_are_absent)
        and ($model | mount_topology_is_allowlisted)
        and ([$model | .. | objects | keys[] | select(contains("$"))] | length == 0)
        and (
          [
            ($model | normalize_environments)
            | paths(scalars) as $path
            | getpath($path) as $value
            | select(
                ([
                  $path[]
                  | strings
                  | select(contains("$"))
                ] | length) > 0
                or ([
                  $value
                  | strings
                  | select(contains("$"))
                ] | length) > 0
              )
            | {path: $path, value: $value} as $entry
            | select((allowed_interpolations | index($entry)) == null)
          ]
          | length == 0
        )
    )
  ' "$compose_json" >/dev/null
}

test_primary_live_fd_compose_topology_is_scoped() {
  local -r compose_file="$TEST_SCRIPT_DIR/../docker-compose.yml"
  local -r primary_fault_file="$TEST_SCRIPT_DIR/../docker-compose.primary-fault.yml"
  local -r live_fd_file="$TEST_SCRIPT_DIR/../docker-compose.primary-live-fd.yml"
  local -r base_resolved="$TEST_TMP_DIR/primary-live-fd-base-resolved.json"
  local -r primary_fault_resolved="$TEST_TMP_DIR/primary-live-fd-fault-resolved.json"
  local -r live_fd_resolved="$TEST_TMP_DIR/primary-live-fd-resolved.json"
  local -r custom_project_resolved="$TEST_TMP_DIR/primary-live-fd-custom-project.json"
  local -r expanded_live_fd_resolved="$TEST_TMP_DIR/primary-live-fd-expanded-resolved.json"
  local -r expanded_primary_fault_resolved="$TEST_TMP_DIR/primary-fault-expanded-resolved.json"
  local -r interpolated_live_fd_file="$TEST_TMP_DIR/primary-live-fd-interpolated.yml"
  local -r interpolated_live_fd_model="$TEST_TMP_DIR/primary-live-fd-interpolated-model.json"
  local -r interpolated_overlay_key_file="$TEST_TMP_DIR/primary-live-fd-interpolated-key.yml"
  local -r interpolated_overlay_key_model="$TEST_TMP_DIR/primary-live-fd-interpolated-key-model.json"
  local -r uninterpolated_live_fd_resolved="$TEST_TMP_DIR/primary-live-fd-uninterpolated-resolved.json"
  local -r interpolated_security_resolved="$TEST_TMP_DIR/primary-live-fd-interpolated-security.json"
  local -r interpolated_ipc_resolved="$TEST_TMP_DIR/primary-live-fd-interpolated-ipc.json"
  local -r interpolated_array_environment_resolved="$TEST_TMP_DIR/primary-live-fd-interpolated-array-environment.json"
  local -r interpolated_object_environment_resolved="$TEST_TMP_DIR/primary-live-fd-interpolated-object-environment.json"
  local -r interpolated_key_environment_resolved="$TEST_TMP_DIR/primary-live-fd-interpolated-key-environment.json"
  local -r inherited_environment_resolved="$TEST_TMP_DIR/primary-live-fd-inherited-environment.json"
  local -r multiline_environment_resolved="$TEST_TMP_DIR/primary-live-fd-multiline-environment.json"
  local -r inherited_build_arg_file="$TEST_TMP_DIR/primary-live-fd-inherited-build-arg.yml"
  local -r inherited_build_arg_resolved="$TEST_TMP_DIR/primary-live-fd-inherited-build-arg.json"
  local -r safe_list_build_arg_file="$TEST_TMP_DIR/primary-live-fd-safe-list-build-arg.yml"
  local -r safe_list_build_arg_resolved="$TEST_TMP_DIR/primary-live-fd-safe-list-build-arg.json"
  local -r duplicate_list_build_arg_resolved="$TEST_TMP_DIR/primary-live-fd-duplicate-list-build-arg.json"
  local -r host_build_context_resolved="$TEST_TMP_DIR/primary-live-fd-host-build-context.json"
  local -r forwarded_build_ssh_file="$TEST_TMP_DIR/primary-live-fd-forwarded-build-ssh.yml"
  local -r forwarded_build_ssh_resolved="$TEST_TMP_DIR/primary-live-fd-forwarded-build-ssh.json"
  local -r optional_env_resolved="$TEST_TMP_DIR/primary-live-fd-optional-env-file.json"
  local -r environment_secret_file="$TEST_TMP_DIR/primary-live-fd-environment-secret.yml"
  local -r environment_secret_resolved="$TEST_TMP_DIR/primary-live-fd-environment-secret.json"
  local -r file_secret_resolved="$TEST_TMP_DIR/primary-live-fd-file-secret.json"
  local -r external_secret_resolved="$TEST_TMP_DIR/primary-live-fd-external-secret.json"
  local -r environment_config_resolved="$TEST_TMP_DIR/primary-live-fd-environment-config.json"
  local -r file_config_resolved="$TEST_TMP_DIR/primary-live-fd-file-config.json"
  local -r external_volume_resolved="$TEST_TMP_DIR/primary-live-fd-external-volume.json"
  local -r repurposed_socket_volume_resolved="$TEST_TMP_DIR/primary-live-fd-repurposed-socket-volume.json"
  local -r direct_bind_resolved="$TEST_TMP_DIR/primary-live-fd-direct-bind.json"
  local -r volumes_from_resolved="$TEST_TMP_DIR/primary-live-fd-volumes-from.json"
  local -r expanded_service_security_resolved="$TEST_TMP_DIR/primary-live-fd-expanded-service-security.json"
  local -r privileged_post_start_resolved="$TEST_TMP_DIR/primary-live-fd-privileged-post-start.json"
  local -r privileged_pre_stop_resolved="$TEST_TMP_DIR/primary-live-fd-privileged-pre-stop.json"
  local -r gpu_device_reservation_resolved="$TEST_TMP_DIR/primary-live-fd-gpu-device-reservation.json"
  local -r unknown_service_key_resolved="$TEST_TMP_DIR/primary-live-fd-unknown-service-key.json"
  local -r dependency_topology_resolved="$TEST_TMP_DIR/primary-live-fd-dependency-topology.json"
  local -r changed_command_resolved="$TEST_TMP_DIR/primary-live-fd-changed-command.json"
  local -r changed_entrypoint_resolved="$TEST_TMP_DIR/primary-live-fd-changed-entrypoint.json"
  local -r changed_environment_resolved="$TEST_TMP_DIR/primary-live-fd-changed-environment.json"
  local -r expanded_service_set_resolved="$TEST_TMP_DIR/primary-live-fd-expanded-service-set.json"
  local -r expanded_service_network_resolved="$TEST_TMP_DIR/primary-live-fd-expanded-service-network.json"
  local -r hidden_profile_file="$TEST_TMP_DIR/primary-live-fd-hidden-profile.yml"
  local -ra runtime_environment=(
    "COMPOSE_PROFILES=*"
    "CONTEXT_PROPAGATION=tcp"
    "BRIDGE_TRANSPORT=getsockopt"
    "EXTENSION_ENABLED=true"
    "JAVA_TOOL_OPTIONS_VALUE=-javaagent:/otel/official-javaagent.jar"
    "OTEL_JAVAAGENT_EXTENSIONS_VALUE=/otel/obi-otel-extension.jar"
    "OTEL_PROPAGATORS_VALUE=obi,tracecontext,baggage"
  )
  local compose_overlay=""
  local resolved_compose=""

  (
    docker() {
      if [[ "$*" == 'compose config --help' ]]; then
        printf '%s\n' \
          '--no-consistency' \
          '--no-interpolate' \
          '--no-normalize' || return 2
        return 0
      fi
      command docker "$@"
    }
    assert_policy_acceptance \
      'primary live-descriptor source rejected safe legacy Compose capabilities' \
      compose_file_build_arguments_are_explicit "$compose_file" || return $?
  ) || return $?
  for compose_overlay in "$compose_file" "$primary_fault_file" "$live_fd_file"; do
    assert_policy_acceptance \
      'primary live-descriptor Compose files must use explicit build inputs' \
      compose_file_build_arguments_are_explicit "$compose_overlay" || return $?
  done
  for compose_overlay in "$primary_fault_file" "$live_fd_file"; do
    assert_policy_acceptance \
      'primary live-descriptor overlays must not depend on runtime interpolation' \
      compose_overlay_is_interpolation_free "$compose_overlay" || return $?
  done
  printf '%s\n' \
    'services:' \
    '  java-backend:' \
    '    user: "\u0024{JAVA_BACKEND_USER:-0:0}"' \
    >"$interpolated_live_fd_file" || return 2
  resolve_compose_fixture_without_interpolation \
    "$interpolated_live_fd_file" "$interpolated_live_fd_model" || return $?
  assert_json_fixture_shape \
    "$interpolated_live_fd_model" \
    '.services["java-backend"].user == "${JAVA_BACKEND_USER:-0:0}"' \
    'failed to construct the interpolated overlay regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor overlay accepted runtime interpolation' \
    compose_overlay_is_interpolation_free "$interpolated_live_fd_file" || return $?
  printf '%s\n' \
    'services:' \
    '  java-backend:' \
    '    labels:' \
    '      "\u0024{UNEXPECTED_LABEL_KEY:-obi.review}": safe' \
    >"$interpolated_overlay_key_file" || return 2
  resolve_compose_fixture_without_interpolation \
    "$interpolated_overlay_key_file" "$interpolated_overlay_key_model" || return $?
  assert_json_fixture_shape \
    "$interpolated_overlay_key_model" \
    '.services["java-backend"].labels | has("${UNEXPECTED_LABEL_KEY:-obi.review}")' \
    'failed to construct the interpolated overlay key regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor overlay accepted an interpolated mapping key' \
    compose_overlay_is_interpolation_free "$interpolated_overlay_key_file" || return $?
  resolve_compose_model_without_interpolation \
    "$uninterpolated_live_fd_resolved" \
    "$compose_file" "$primary_fault_file" "$live_fd_file" || return $?
  assert_policy_acceptance \
    'primary live-descriptor runtime model contains unexpected host input or topology' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$uninterpolated_live_fd_resolved" || return $?
  (
    PROJECT_NAME="${PROJECT_NAMESPACE}-review"
    resolve_compose_model_without_interpolation \
      "$custom_project_resolved" \
      "$compose_file" "$primary_fault_file" "$live_fd_file" || return $?
    assert_policy_acceptance \
      'primary live-descriptor runtime rejected a reserved project namespace' \
      compose_runtime_model_interpolation_is_allowlisted \
      "$custom_project_resolved" || return $?
  ) || return $?
  jq '.services["java-backend"].privileged = "${EXTENSION_ENABLED:-false}"' \
    "$uninterpolated_live_fd_resolved" >"$interpolated_security_resolved" || return 2
  assert_json_fixture_shape \
    "$interpolated_security_resolved" \
    '.services["java-backend"].privileged == "${EXTENSION_ENABLED:-false}"' \
    'failed to construct the interpolated security regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor security topology accepted runtime interpolation' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$interpolated_security_resolved" || return $?
  jq '.services["java-backend"].ipc = "${IPC_MODE:-private}"' \
    "$uninterpolated_live_fd_resolved" >"$interpolated_ipc_resolved" || return 2
  assert_json_fixture_shape \
    "$interpolated_ipc_resolved" \
    '.services["java-backend"].ipc == "${IPC_MODE:-private}"' \
    'failed to construct the interpolated IPC regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor security topology accepted interpolated IPC mode' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$interpolated_ipc_resolved" || return $?
  jq '
    .services["java-backend"].environment = [
      "LD_AUDIT=${JAVA_BACKEND_LD_AUDIT:-}"
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$interpolated_array_environment_resolved" || return 2
  assert_json_fixture_shape \
    "$interpolated_array_environment_resolved" \
    '.services["java-backend"].environment == ["LD_AUDIT=${JAVA_BACKEND_LD_AUDIT:-}"]' \
    'failed to construct the array environment regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted array environment interpolation' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$interpolated_array_environment_resolved" || return $?
  jq '
    .services["apache-proxy"].environment = {
      "JDK_JAVA_OPTIONS": "${JDK_CONTROL:-}"
    }
  ' "$uninterpolated_live_fd_resolved" \
    >"$interpolated_object_environment_resolved" || return 2
  assert_json_fixture_shape \
    "$interpolated_object_environment_resolved" \
    '.services["apache-proxy"].environment == {"JDK_JAVA_OPTIONS": "${JDK_CONTROL:-}"}' \
    'failed to construct the object environment regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted object environment interpolation' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$interpolated_object_environment_resolved" || return $?
  jq '
    .services["java-backend"].environment = [
      "${JAVA_BACKEND_EXTRA_ENV:-SAFE_FLAG=1}"
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$interpolated_key_environment_resolved" || return 2
  assert_json_fixture_shape \
    "$interpolated_key_environment_resolved" \
    '.services["java-backend"].environment == ["${JAVA_BACKEND_EXTRA_ENV:-SAFE_FLAG=1}"]' \
    'failed to construct the interpolated environment key regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an interpolated environment key' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$interpolated_key_environment_resolved" || return $?
  jq '.services["java-backend"].environment = ["JDK_JAVA_OPTIONS"]' \
    "$uninterpolated_live_fd_resolved" >"$inherited_environment_resolved" || return 2
  assert_json_fixture_shape \
    "$inherited_environment_resolved" \
    '.services["java-backend"].environment == ["JDK_JAVA_OPTIONS"]' \
    'failed to construct the inherited environment regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted inherited environment input' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$inherited_environment_resolved" || return $?
  jq '
    .services["java-backend"].environment = [
      "JDK_JAVA_OPTIONS=-Dsafe=true\n${JDK_EXTRA_OPTIONS:-}"
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$multiline_environment_resolved" || return 2
  assert_json_fixture_shape \
    "$multiline_environment_resolved" \
    '.services["java-backend"].environment == ["JDK_JAVA_OPTIONS=-Dsafe=true\n${JDK_EXTRA_OPTIONS:-}"]' \
    'failed to construct the multiline environment regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted multiline environment interpolation' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$multiline_environment_resolved" || return $?
  printf '%s\n' \
    'services:' \
    '  obi:' \
    '    build:' \
    '      context: ../..' \
    '      dockerfile: Dockerfile' \
    '      args:' \
    '        TAG:' \
    >"$inherited_build_arg_file" || return 2
  (
    export TAG=latest || return 2
    resolve_compose_fixture \
      "$inherited_build_arg_file" "$inherited_build_arg_resolved"
  ) || return $?
  assert_json_fixture_shape \
    "$inherited_build_arg_resolved" \
    '.services.obi.build.args.TAG == "latest"' \
    'failed to construct the inherited build argument regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor source accepted an inherited build argument' \
    compose_file_build_arguments_are_explicit \
    "$inherited_build_arg_file" || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an inherited build argument' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$inherited_build_arg_resolved" || return $?
  printf '%s\n' \
    'services:' \
    '  obi:' \
    '    build:' \
    '      context: ../..' \
    '      dockerfile: Dockerfile' \
    '      args:' \
    '        - RELEASE_REVISION=local' \
    '        - RELEASE_VERSION=apache-java-https-demo' \
    >"$safe_list_build_arg_file" || return 2
  assert_policy_acceptance \
    'primary live-descriptor source rejected exact list-form build arguments' \
    compose_file_build_arguments_are_explicit \
    "$safe_list_build_arg_file" || return $?
  jq '
    .services.obi.build.args = [
      "RELEASE_REVISION=local",
      "RELEASE_VERSION=apache-java-https-demo"
    ]
  ' "$uninterpolated_live_fd_resolved" >"$safe_list_build_arg_resolved" || return 2
  assert_policy_acceptance \
    'primary live-descriptor runtime rejected exact list-form build arguments' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$safe_list_build_arg_resolved" || return $?
  jq '
    .services.obi.build.args = [
      "RELEASE_REVISION=local",
      "RELEASE_REVISION=local"
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$duplicate_list_build_arg_resolved" || return 2
  assert_json_fixture_shape \
    "$duplicate_list_build_arg_resolved" \
    '.services.obi.build.args == [
      "RELEASE_REVISION=local",
      "RELEASE_REVISION=local"
    ]' \
    'failed to construct the duplicate list build argument fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted duplicate list build arguments' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$duplicate_list_build_arg_resolved" || return $?
  jq '
    .services.obi.build.context = "/tmp/host-controlled-build-context"
    | .services.obi.build.dockerfile_inline = "FROM scratch"
  ' "$uninterpolated_live_fd_resolved" \
    >"$host_build_context_resolved" || return 2
  assert_json_fixture_shape \
    "$host_build_context_resolved" \
    '.services.obi.build.context == "/tmp/host-controlled-build-context"
      and .services.obi.build.dockerfile_inline == "FROM scratch"' \
    'failed to construct the host build input regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted host-controlled build inputs' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$host_build_context_resolved" || return $?
  printf '%s\n' \
    'services:' \
    '  obi:' \
    '    build:' \
    '      context: ../..' \
    '      dockerfile: Dockerfile' \
    '      args:' \
    '        RELEASE_REVISION: local' \
    '        RELEASE_VERSION: apache-java-https-demo' \
    '      ssh:' \
    '        - default' \
    >"$forwarded_build_ssh_file" || return 2
  resolve_compose_fixture_without_interpolation \
    "$forwarded_build_ssh_file" "$forwarded_build_ssh_resolved" || return $?
  assert_json_fixture_shape \
    "$forwarded_build_ssh_resolved" \
    '(.services.obi.build.ssh == ["default"])
      or ((.services.obi.build.ssh | type) == "object"
        and (.services.obi.build.ssh | has("default"))
        and (.services.obi.build.ssh.default == null))' \
    'failed to construct the forwarded build SSH regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted forwarded build SSH credentials' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$forwarded_build_ssh_resolved" || return $?
  jq '
    .services["java-backend"].env_file = [
      {
        "path": "/tmp/obi-host-controlled-java.env",
        "required": false
      }
    ]
  ' "$uninterpolated_live_fd_resolved" >"$optional_env_resolved" || return 2
  assert_json_fixture_shape \
    "$optional_env_resolved" \
    '.services["java-backend"].env_file == [{
      "path": "/tmp/obi-host-controlled-java.env",
      "required": false
    }]' \
    'failed to construct the optional environment file regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an optional environment file' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$optional_env_resolved" || return $?
  printf '%s\n' \
    'services:' \
    '  java-backend:' \
    '    image: busybox:1.36' \
    '    secrets:' \
    '      - source: java-preload' \
    '        target: /etc/ld.so.preload' \
    'secrets:' \
    '  java-preload:' \
    '    environment: JAVA_PRELOAD_CONTENT' \
    >"$environment_secret_file" || return 2
  resolve_compose_fixture_without_interpolation \
    "$environment_secret_file" "$environment_secret_resolved" || return $?
  assert_json_fixture_shape \
    "$environment_secret_resolved" \
    '.secrets["java-preload"].environment == "JAVA_PRELOAD_CONTENT"
      and .services["java-backend"].secrets[0].target == "/etc/ld.so.preload"' \
    'failed to construct the environment-backed secret regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an environment-backed secret' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$environment_secret_resolved" || return $?
  jq '
    del(.secrets["java-preload"].environment)
    | .secrets["java-preload"].file = "/tmp/obi-host-controlled-secret"
  ' "$environment_secret_resolved" >"$file_secret_resolved" || return 2
  assert_json_fixture_shape \
    "$file_secret_resolved" \
    '.secrets["java-preload"].file == "/tmp/obi-host-controlled-secret"
      and (.secrets["java-preload"] | has("environment") | not)' \
    'failed to construct the file-backed secret regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a file-backed secret' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$file_secret_resolved" || return $?
  jq '
    del(.secrets["java-preload"].environment)
    | .secrets["java-preload"].external = true
  ' "$environment_secret_resolved" >"$external_secret_resolved" || return 2
  assert_json_fixture_shape \
    "$external_secret_resolved" \
    '.secrets["java-preload"].external == true
      and (.secrets["java-preload"] | has("environment") | not)' \
    'failed to construct the external secret regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an external secret' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$external_secret_resolved" || return $?
  jq '
    .services["java-backend"].configs = [
      {
        "source": "java-options",
        "target": "/opt/java-options"
      }
    ]
    | .configs["java-options"] = {
        "environment": "JAVA_OPTIONS_CONTENT"
      }
  ' "$uninterpolated_live_fd_resolved" \
    >"$environment_config_resolved" || return 2
  assert_json_fixture_shape \
    "$environment_config_resolved" \
    '.configs["java-options"].environment == "JAVA_OPTIONS_CONTENT"
      and .services["java-backend"].configs[0].target == "/opt/java-options"' \
    'failed to construct the environment-backed config regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an environment-backed config' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$environment_config_resolved" || return $?
  jq '
    del(.configs["java-options"].environment)
    | .configs["java-options"].file = "/tmp/obi-host-controlled-config"
  ' "$environment_config_resolved" >"$file_config_resolved" || return 2
  assert_json_fixture_shape \
    "$file_config_resolved" \
    '.configs["java-options"].file == "/tmp/obi-host-controlled-config"
      and (.configs["java-options"] | has("environment") | not)' \
    'failed to construct the file-backed config regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a file-backed config' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$file_config_resolved" || return $?
  jq '
    .volumes["host-otel"] = {
      "external": true,
      "name": "host-otel"
    }
    | .services["java-backend"].volumes += [
        {
          "source": "host-otel",
          "target": "/otel",
          "type": "volume",
          "volume": {}
        }
      ]
  ' "$uninterpolated_live_fd_resolved" >"$external_volume_resolved" || return 2
  assert_json_fixture_shape \
    "$external_volume_resolved" \
    '.volumes["host-otel"].external == true
      and any(
        .services["java-backend"].volumes[];
        .source == "host-otel" and .target == "/otel"
      )' \
    'failed to construct the external volume regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an external agent volume' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$external_volume_resolved" || return $?
  jq '
    .volumes["java-remote-parent-socket"] = {
      "driver": "local",
      "driver_opts": {
        "device": "/tmp/host-controlled-socket",
        "o": "bind",
        "type": "none"
      },
      "name": "host-preseeded-socket"
    }
  ' "$uninterpolated_live_fd_resolved" \
    >"$repurposed_socket_volume_resolved" || return 2
  assert_json_fixture_shape \
    "$repurposed_socket_volume_resolved" \
    '.volumes["java-remote-parent-socket"].driver_opts.device
      == "/tmp/host-controlled-socket"
      and .volumes["java-remote-parent-socket"].name
      == "host-preseeded-socket"' \
    'failed to construct the repurposed socket volume regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a repurposed socket volume' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$repurposed_socket_volume_resolved" || return $?
  jq '
    .services["java-backend"].volumes += [
      {
        "bind": {"create_host_path": false},
        "read_only": true,
        "source": "/tmp/host-controlled-otel",
        "target": "/otel",
        "type": "bind"
      }
    ]
  ' "$uninterpolated_live_fd_resolved" >"$direct_bind_resolved" || return 2
  assert_json_fixture_shape \
    "$direct_bind_resolved" \
    'any(
      .services["java-backend"].volumes[];
      .type == "bind"
        and .source == "/tmp/host-controlled-otel"
        and .target == "/otel"
    )' \
    'failed to construct the direct agent bind regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a direct agent bind' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$direct_bind_resolved" || return $?
  jq '
    .services["java-backend"].volumes_from = ["container:host-payload:ro"]
  ' "$uninterpolated_live_fd_resolved" >"$volumes_from_resolved" || return 2
  assert_json_fixture_shape \
    "$volumes_from_resolved" \
    '.services["java-backend"].volumes_from
      == ["container:host-payload:ro"]' \
    'failed to construct the volumes-from regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted volumes-from host input' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$volumes_from_resolved" || return $?
  jq '
    .services["bridge-fault"] += {
      "cap_add": ["NET_ADMIN"],
      "cgroup": "host",
      "cgroup_parent": "/host-controlled",
      "dns": ["203.0.113.53"],
      "dns_opt": ["use-vc"],
      "dns_search": ["host.invalid"],
      "extra_hosts": {"gateway": "host-gateway"},
      "group_add": ["docker"],
      "ipc": "host",
      "isolation": "process",
      "network_mode": "host",
      "pid": "host",
      "privileged": true,
      "runtime": "runsc",
      "security_opt": ["seccomp=unconfined"],
      "sysctls": {"net.ipv4.ip_forward": "1"},
      "userns_mode": "host",
      "uts": "host"
    }
  ' "$uninterpolated_live_fd_resolved" \
    >"$expanded_service_security_resolved" || return 2
  assert_json_fixture_shape \
    "$expanded_service_security_resolved" \
    '.services["bridge-fault"].privileged == true
      and .services["bridge-fault"].network_mode == "host"
      and .services["bridge-fault"].pid == "host"
      and .services["bridge-fault"].cap_add == ["NET_ADMIN"]' \
    'failed to construct the service security topology regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted expanded service security topology' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$expanded_service_security_resolved" || return $?
  jq '
    .services["bridge-fault"].post_start = [
      {
        "command": ["/bin/true"],
        "privileged": true,
        "user": "0:0"
      }
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$privileged_post_start_resolved" || return 2
  assert_json_fixture_shape \
    "$privileged_post_start_resolved" \
    '.services["bridge-fault"].post_start == [{
      "command": ["/bin/true"],
      "privileged": true,
      "user": "0:0"
    }]' \
    'failed to construct the privileged post-start regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a privileged post-start hook' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$privileged_post_start_resolved" || return $?
  jq '
    .services["bridge-fault"].pre_stop = [
      {
        "command": ["/bin/true"],
        "privileged": true,
        "user": "0:0"
      }
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$privileged_pre_stop_resolved" || return 2
  assert_json_fixture_shape \
    "$privileged_pre_stop_resolved" \
    '.services["bridge-fault"].pre_stop == [{
      "command": ["/bin/true"],
      "privileged": true,
      "user": "0:0"
    }]' \
    'failed to construct the privileged pre-stop regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a privileged pre-stop hook' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$privileged_pre_stop_resolved" || return $?
  jq '
    .services["bridge-fault"].deploy.resources.reservations.devices = [
      {
        "capabilities": ["gpu"],
        "count": "all",
        "driver": "nvidia"
      }
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$gpu_device_reservation_resolved" || return 2
  assert_json_fixture_shape \
    "$gpu_device_reservation_resolved" \
    '.services["bridge-fault"].deploy.resources.reservations.devices == [{
      "capabilities": ["gpu"],
      "count": "all",
      "driver": "nvidia"
    }]' \
    'failed to construct the GPU reservation regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a GPU device reservation' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$gpu_device_reservation_resolved" || return $?
  jq '.services.obi.cpu_rt_runtime = 950000' \
    "$uninterpolated_live_fd_resolved" \
    >"$unknown_service_key_resolved" || return 2
  assert_json_fixture_shape \
    "$unknown_service_key_resolved" \
    '.services.obi.cpu_rt_runtime == 950000' \
    'failed to construct the unknown service-key regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an unknown service key' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$unknown_service_key_resolved" || return $?
  jq '
    .services["java-backend"].depends_on["trace-receiver"].condition =
      "service_healthy"
  ' "$uninterpolated_live_fd_resolved" \
    >"$dependency_topology_resolved" || return 2
  assert_json_fixture_shape \
    "$dependency_topology_resolved" \
    '.services["java-backend"].depends_on["trace-receiver"].condition
      == "service_healthy"' \
    'failed to construct the dependency topology regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted changed dependency topology' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$dependency_topology_resolved" || return $?
  jq '
    .services["socket-init"].command = [
      "id > /var/run/obi/host-control"
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$changed_command_resolved" || return 2
  assert_json_fixture_shape \
    "$changed_command_resolved" \
    '.services["socket-init"].command
      == ["id > /var/run/obi/host-control"]' \
    'failed to construct the changed command regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a changed service command' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$changed_command_resolved" || return $?
  jq '
    .services["map-pressure"].entrypoint = [
      "/bin/sh",
      "-ec",
      "id"
    ]
  ' "$uninterpolated_live_fd_resolved" \
    >"$changed_entrypoint_resolved" || return 2
  assert_json_fixture_shape \
    "$changed_entrypoint_resolved" \
    '.services["map-pressure"].entrypoint
      == ["/bin/sh", "-ec", "id"]' \
    'failed to construct the changed entrypoint regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted a changed service entrypoint' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$changed_entrypoint_resolved" || return $?
  jq '
    if (.services["java-backend"].environment | type) == "array" then
      .services["java-backend"].environment |= map(
        if startswith("LD_PRELOAD=") then
          "LD_PRELOAD=/tmp/host-controlled.so"
        else
          .
        end
      )
    else
      .services["java-backend"].environment.LD_PRELOAD =
        "/tmp/host-controlled.so"
    end
  ' "$uninterpolated_live_fd_resolved" \
    >"$changed_environment_resolved" || return 2
  assert_json_fixture_shape \
    "$changed_environment_resolved" \
    'if (.services["java-backend"].environment | type) == "array" then
      any(
        .services["java-backend"].environment[];
        . == "LD_PRELOAD=/tmp/host-controlled.so"
      )
    else
      .services["java-backend"].environment.LD_PRELOAD
        == "/tmp/host-controlled.so"
    end' \
    'failed to construct the changed environment regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted changed service environment' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$changed_environment_resolved" || return $?
  jq '
    .services.hidden = {
      "image": "busybox:1.36",
      "network_mode": "host",
      "privileged": true
    }
    | .services |= with_entries(.value |= del(.volumes, .tmpfs))
    | del(.volumes)
  ' "$uninterpolated_live_fd_resolved" \
    >"$expanded_service_set_resolved" || return 2
  assert_json_fixture_shape \
    "$expanded_service_set_resolved" \
    '.services.hidden.privileged == true
      and (.volumes | not)
      and all(.services[]; has("volumes") | not)' \
    'failed to construct the expanded service-set regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted an expanded service set' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$expanded_service_set_resolved" || return $?
  jq '
    del(.services["bridge-fault"].network_mode)
    | .services["bridge-fault"].networks = {
        "default": {"aliases": ["fault-shadow"]}
      }
    | .services["bridge-fault"].ports = [
        {
          "mode": "ingress",
          "protocol": "tcp",
          "published": "18443",
          "target": 443
        }
      ]
    | .services["bridge-fault"].links = ["java-backend:backend"]
    | .services["bridge-fault"].external_links = ["host-payload:payload"]
  ' "$uninterpolated_live_fd_resolved" \
    >"$expanded_service_network_resolved" || return 2
  assert_json_fixture_shape \
    "$expanded_service_network_resolved" \
    '(.services["bridge-fault"] | has("network_mode") | not)
      and .services["bridge-fault"].networks.default.aliases == ["fault-shadow"]
      and .services["bridge-fault"].ports[0].published == "18443"' \
    'failed to construct the service network topology regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted expanded service network topology' \
    compose_runtime_model_interpolation_is_allowlisted \
    "$expanded_service_network_resolved" || return $?
  if ! env "${runtime_environment[@]}" docker compose \
    --project-name "$PROJECT_NAME" --file "$compose_file" \
    config --format json >"$base_resolved"; then
    return 2
  fi
  if ! env "${runtime_environment[@]}" docker compose \
    --project-name "$PROJECT_NAME" --file "$compose_file" \
    --file "$primary_fault_file" config --format json >"$primary_fault_resolved"; then
    return 2
  fi
  if ! env "${runtime_environment[@]}" docker compose \
    --project-name "$PROJECT_NAME" --file "$compose_file" \
    --file "$primary_fault_file" --file "$live_fd_file" \
    config --format json >"$live_fd_resolved"; then
    return 2
  fi
  assert_policy_acceptance \
    'primary W3C fault runtime expanded beyond its scoped backend changes' \
    primary_fault_resolved_topology_is_scoped \
    "$base_resolved" "$primary_fault_resolved" || return $?
  jq '
    .services["unexpected-privileged-sidecar"] = {
      "image": "busybox:1.36",
      "privileged": true
    }
    | .services["java-backend"].depends_on["unexpected-privileged-sidecar"] = {
        "condition": "service_started",
        "required": true
      }
  ' "$primary_fault_resolved" >"$expanded_primary_fault_resolved" || return 2
  assert_json_fixture_shape \
    "$expanded_primary_fault_resolved" \
    '.services["unexpected-privileged-sidecar"].privileged == true
      and .services["java-backend"].depends_on["unexpected-privileged-sidecar"].required == true' \
    'failed to construct the privileged dependency regression fixture' || return $?
  assert_policy_rejection \
    'primary W3C fault runtime accepted a privileged dependency' \
    primary_fault_resolved_topology_is_scoped \
    "$base_resolved" "$expanded_primary_fault_resolved" || return $?
  for resolved_compose in "$base_resolved" "$primary_fault_resolved"; do
    assert_policy_acceptance \
      'base or primary W3C fault runtime unexpectedly gained SYS_PTRACE' \
      jq -e -s '
        length == 1
        and (
          .[0].services["java-backend"] as $backend
          | ($backend | type == "object")
            and (($backend.cap_add // []) == [])
        )
      ' "$resolved_compose" >/dev/null || return $?
  done
  assert_policy_acceptance \
    'primary live-descriptor runtime lost its scoped SYS_PTRACE topology' \
    primary_live_fd_resolved_topology_is_scoped \
    "$primary_fault_resolved" "$live_fd_resolved" || return $?
  printf '%s\n' \
    'services:' \
    '  unexpected-privileged-sidecar:' \
    '    image: busybox:1.36' \
    '    privileged: true' \
    '    profiles: [hidden]' \
    >"$hidden_profile_file" || return 2
  if ! env "${runtime_environment[@]}" docker compose \
    --project-name "$PROJECT_NAME" --file "$compose_file" \
    --file "$primary_fault_file" --file "$live_fd_file" \
    --file "$hidden_profile_file" config --format json \
    >"$expanded_live_fd_resolved"; then
    return 2
  fi
  assert_json_fixture_shape \
    "$expanded_live_fd_resolved" \
    '.services["unexpected-privileged-sidecar"].privileged == true
      and .services["unexpected-privileged-sidecar"].profiles == ["hidden"]' \
    'failed to render the hidden-profile topology regression fixture' || return $?
  assert_policy_rejection \
    'primary live-descriptor runtime accepted hidden-profile topology expansion' \
    primary_live_fd_resolved_topology_is_scoped \
    "$primary_fault_resolved" "$expanded_live_fd_resolved" || return $?
}

test_benchmark_client_compose_topology_is_least_privilege() {
  local -r compose_file="$TEST_SCRIPT_DIR/../docker-compose.yml"
  local -r resolved_compose="$TEST_TMP_DIR/benchmark-client-resolved-compose.json"
  local -r override_ca="$TEST_TMP_DIR/benchmark-client-override-ca.crt"
  local -r override_resolved_compose="$TEST_TMP_DIR/benchmark-client-override-resolved-compose.json"
  local -r omitted_false_compose="$TEST_TMP_DIR/benchmark-client-omitted-false-compose.json"
  local -r multi_document_compose="$TEST_TMP_DIR/benchmark-client-multi-document-compose.json"
  local example_directory=""
  local benchmark_service=""
  local benchmark_volumes=""
  local raw_volume_count=""

  example_directory="$(cd -- "$TEST_SCRIPT_DIR/.." && pwd -P)" || return 2
  if ! BENCHMARK_CA_SOURCE='' COMPOSE_PROFILES=tools \
    docker compose --file "$compose_file" config --format json \
    >"$resolved_compose"; then
    return 2
  fi
  if ! BENCHMARK_CA_SOURCE="$override_ca" COMPOSE_PROFILES=tools \
    docker compose --file "$compose_file" config --format json \
    >"$override_resolved_compose"; then
    return 2
  fi
  benchmark_service="$(compose_service_block "$compose_file" benchmark)" || return 2
  benchmark_volumes="$(awk '
    $0 == "    volumes:" { inside = 1; next }
    inside && $0 ~ /^    [^[:space:]#][^:]*:/ { exit }
    inside { print }
  ' <<<"$benchmark_service")" || return 2
  raw_volume_count="$(awk '/^      - type: bind$/ { count += 1 } END { print count + 0 }' \
    <<<"$benchmark_volumes")" || return 2

  [[ "$benchmark_service" == *'user: "65532:65532"'* &&
    "$benchmark_service" == *$'cap_drop:\n      - ALL'* &&
    "$benchmark_service" == *'security_opt:'* &&
    "$benchmark_service" == *'      - no-new-privileges:true'* &&
    "$benchmark_service" == *'read_only: true'* &&
    "$benchmark_service" != *'privileged:'* &&
    "$benchmark_service" != *'cap_add:'* &&
    "$benchmark_service" != *'pid:'* &&
    "$benchmark_service" != *'userns_mode:'* &&
    "$raw_volume_count" == "1" &&
    "$benchmark_volumes" == $'      - type: bind\n        source: ${BENCHMARK_CA_SOURCE:-./.runtime/certs/ca.crt}\n        target: /benchmark-ca.crt\n        read_only: true\n        bind:\n          create_host_path: false' ]] || {
    printf 'benchmark client must retain its exact read-only CA-only topology\n' >&2
    return 1
  }
  assert_policy_acceptance \
    'resolved benchmark client topology exposed more than its verified CA' \
    benchmark_client_resolved_topology_is_least_privilege \
    "$resolved_compose" "$example_directory/.runtime/certs/ca.crt" || return $?
  jq 'del(.services.benchmark.volumes[0].bind.create_host_path)' \
    "$resolved_compose" >"$omitted_false_compose" || return 2
  assert_policy_acceptance \
    'resolved benchmark client rejected an omitted false bind option' \
    benchmark_client_resolved_topology_is_least_privilege \
    "$omitted_false_compose" "$example_directory/.runtime/certs/ca.crt" || return $?
  jq '(.services.benchmark.privileged = true), .' \
    "$resolved_compose" >"$multi_document_compose" || return 2
  assert_policy_rejection \
    'resolved benchmark client accepted multiple Compose documents' \
    benchmark_client_resolved_topology_is_least_privilege \
    "$multi_document_compose" "$example_directory/.runtime/certs/ca.crt" || return $?
  assert_policy_acceptance \
    'resolved benchmark client did not confine its explicit CA override' \
    benchmark_client_resolved_topology_is_least_privilege \
    "$override_resolved_compose" "$override_ca" || return $?
}

test_unix_security_probe_topology_is_least_privilege() {
  local -r obi_config="$TEST_SCRIPT_DIR/../configs/obi.yaml"
  local -r compose_file="$TEST_SCRIPT_DIR/../docker-compose.yml"
  local -r resolved_compose="$TEST_TMP_DIR/unix-security-resolved-compose.yaml"
  local sibling_service=""
  local resolved_sibling_service=""
  local endpoint_service=""
  local socket_init_service=""
  local obi_service=""
  local sibling_volumes=""
  local resolved_sibling_volumes=""
  local resolved_sibling_volume_count=""
  local resolved_sibling_security_options=""
  local resolved_sibling_security_option_count=""
  local endpoint_volumes=""

  grep -Fqx '    socket_group_id: 65534' "$obi_config" || return $?
  if ! COMPOSE_PROFILES=tools docker compose --file "$compose_file" config \
    >"$resolved_compose"; then
    return 2
  fi
  socket_init_service="$(compose_service_block "$compose_file" socket-init)" || return $?
  obi_service="$(compose_service_block "$compose_file" obi)" || return $?
  sibling_service="$(compose_service_block \
    "$compose_file" security-unix-sibling-probe)" || return $?
  resolved_sibling_service="$(compose_service_block \
    "$resolved_compose" security-unix-sibling-probe)" || return $?
  endpoint_service="$(compose_service_block "$compose_file" security-probe)" || return $?
  sibling_volumes="$(awk '
    $0 == "    volumes:" { inside = 1; next }
    inside && $0 ~ /^    [^[:space:]#][^:]*:/ { exit }
    inside && $0 ~ /^      - / { print }
  ' <<<"$sibling_service")" || return $?
  resolved_sibling_volumes="$(awk '
    $0 == "    volumes:" { inside = 1; next }
    inside && $0 ~ /^    [^[:space:]#][^:]*:/ { exit }
    inside { print }
  ' <<<"$resolved_sibling_service")" || return $?
  resolved_sibling_volume_count="$(awk '
    /^      - type:/ { count += 1 }
    END { print count + 0 }
  ' <<<"$resolved_sibling_volumes")" || return $?
  resolved_sibling_security_options="$(awk '
    $0 == "    security_opt:" { inside = 1; next }
    inside && $0 ~ /^    [^[:space:]#][^:]*:/ { exit }
    inside { print }
  ' <<<"$resolved_sibling_service")" || return $?
  resolved_sibling_security_option_count="$(awk '
    /^      - / { count += 1 }
    END { print count + 0 }
  ' <<<"$resolved_sibling_security_options")" || return $?
  endpoint_volumes="$(awk '
    $0 == "    volumes:" { inside = 1; next }
    inside && $0 ~ /^    [^[:space:]#][^:]*:/ { exit }
    inside && $0 ~ /^      - / { print }
  ' <<<"$endpoint_service")" || return $?

  [[ "$socket_init_service" == *'chown 0:65534 /var/run/obi && chmod 0750 /var/run/obi'* &&
    "$obi_service" == *'OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_GROUP_ID: "65534"'* ]] || {
    printf 'Unix socket group is not owned consistently by socket-init and OBI\n' >&2
    return 1
  }
  [[ "$resolved_sibling_service" != *'privileged: true'* &&
    "$resolved_sibling_service" != *'cap_add:'* &&
    "$resolved_sibling_service" != *'pid: host'* &&
    "$resolved_sibling_service" != *'userns_mode: host'* &&
    "$resolved_sibling_service" != *'tmpfs:'* &&
    "$resolved_sibling_volume_count" == "1" &&
    "$resolved_sibling_volumes" == *'source: java-remote-parent-socket'* &&
    "$resolved_sibling_volumes" == *'target: /var/run/obi'* &&
    "$resolved_sibling_volumes" == *'read_only: true'* &&
    "$resolved_sibling_security_option_count" == "1" &&
    "$resolved_sibling_security_options" == '      - no-new-privileges:true' ]] || {
    printf 'resolved Unix sibling probe gained an unsafe topology through Compose inheritance\n' >&2
    return 1
  }
  [[ "$sibling_service" == *'network_mode: none'* &&
    "$sibling_service" == *'user: "65534:65534"'* &&
    "$sibling_service" == *'read_only: true'* &&
    "$sibling_service" == *'cap_drop: [ALL]'* &&
    "$sibling_service" == *'security_opt: [no-new-privileges:true]'* &&
    "$sibling_service" == *'      - abuse-race'* &&
    "$sibling_service" != *'privileged:'* &&
    "$sibling_service" != *'cap_add:'* &&
    "$sibling_service" != *'pid:'* &&
    "$sibling_service" != *'userns_mode:'* &&
    "$sibling_volumes" == '      - java-remote-parent-socket:/var/run/obi:ro' ]] || {
    printf 'Unix sibling probe lacks a least-privilege peer topology\n' >&2
    return 1
  }
  [[ "$endpoint_service" == *'user: "0:0"'* &&
    "$endpoint_volumes" == '      - java-remote-parent-socket:/var/run/obi' ]] || {
    printf 'endpoint-replacement probe lost its required writable root topology\n' >&2
    return 1
  }
}

main() {
  TEST_TMP_DIR="$(mktemp -d)"
  test_project_name_validation
  test_compose_cleanup_requires_ownership_sentinel
  test_successful_cleanup_invalidates_current_transport_before_down
  test_delayed_otlp_temporary_cleanup_preserves_failure
  test_cleanup_refuses_down_when_transport_invalidation_fails
  test_cleanup_failure_changes_successful_run_status
  test_primary_fault_recovery_marker_forces_cleanup_with_keep
  test_primary_live_fd_recovery_marker_forces_cleanup_with_keep
  test_run_status_publication_failure_changes_successful_exit
  test_cleanup_only_invalidates_matching_project_evidence_before_down
  test_cleanup_only_refuses_untrusted_current_evidence_identity
  test_cleanup_only_refuses_down_when_project_evidence_invalidation_fails
  test_cleanup_only_fails_closed_on_project_matcher_error
  test_main_propagates_cleanup_only_failure
  test_acceptance_requires_fresh_bridge_build
  test_custom_all_request_count_is_non_acceptance
  test_numeric_options_reject_overflow
  test_transport_configuration_parser_is_exact
  test_selected_transport_uses_java_diagnostics
  test_transport_configuration_file_size_boundary_is_exact
  test_control_modes_are_distinct
  test_benchmark_controls_use_shared_concurrency_workload
  test_benchmark_controls_configure_their_runtime
  test_benchmark_startup_selects_runtime_contract
  test_benchmark_control_passes_assertion_mode_to_tracecheck
  test_benchmark_controls_are_bounded
  test_all_suite_includes_every_scenario
  test_unix_all_suite_includes_fault_control
  test_run_demo_preserves_strict_scenario_execution
  test_delayed_otlp_run_demo_defers_runtime_evidence
  test_helper_attach_failure_dispatch_and_seed_are_exact
  test_w3c_fault_requires_forced_unix
  test_primary_w3c_stale_requires_forced_primary
  test_primary_generation_mismatch_requires_one_forced_primary
  test_unix_w3c_stale_requires_forced_unix
  test_primary_w3c_fault_requires_forced_primary
  test_primary_w3c_fault_modes_are_exact
  test_primary_w3c_fault_control_scripts_publish_and_consume_exactly
  test_primary_w3c_stale_control_restores_the_normal_ttls
  test_unix_w3c_stale_control_restores_the_normal_ttls
  test_unix_w3c_stale_control_recovers_after_a_failed_stale_assertion
  test_w3c_stale_scenarios_use_in_band_diagnostics
  test_primary_w3c_fault_recreation_uses_the_overlay_only
  test_primary_w3c_fault_scenario_arms_after_the_baseline
  test_primary_w3c_fault_control_restores_the_base_stack
  test_security_accepts_enabled_transports
  test_tls_boundary_requires_split_and_coalesced_pair
  test_coalesced_bridge_requires_exact_live_pair
  test_tls_boundary_receive_cursor_map_evidence_is_exact_and_steady
  test_receive_cursor_map_helper_bounds_evidence_before_replay
  test_w3c_match_uses_controlled_unix_fixture
  test_matching_bridge_sequence_is_exact
  test_matching_bridge_start_failure_is_cleaned_up
  test_cleanup_stops_matching_bridge_when_stack_is_kept
  test_runtime_directory_rejects_symlink
  test_bridge_artifact_metadata
  test_agent_download_rejects_symlink_output
  test_metrics_delta_reports_counters_and_map_occupancy
  test_java_attach_error_metric_is_exact_unique
  test_java_attach_error_wait_requires_exact_stability
  test_log_pid_count_requires_an_exact_numeric_token
  test_helper_unavailable_metric_boundary_preserves_counters
  test_metric_boundary_helpers_are_reason_coded
  test_duplicate_suppression_wait_primes_java_export
  test_duplicate_suppression_absence_requires_a_clean_metric_snapshot
  test_delayed_otlp_window_requires_a_fresh_generation
  test_delayed_otlp_settlement_covers_pinned_obi_delivery_bound
  test_delayed_otlp_snapshot_fetch_wrapper_is_exact_and_bounded
  test_delayed_otlp_run_identity_and_receiver_continuity
  test_delayed_otlp_pre_export_evidence_is_atomic
  test_delayed_otlp_receiver_snapshots_prove_export_boundary
  test_delayed_otlp_receiver_wait_enforces_export_deadline
  test_delayed_otlp_suppression_control_has_one_pre_export_request
  test_delayed_otlp_suppression_control_restores_schedule_delay
  test_delayed_otlp_suppression_recovers_after_startup_failure
  test_pressure_map_metric_requires_exact_unique_series
  test_bridge_metric_wait_requires_quiescent_report
  test_security_probe_window_covers_metric_fences
  test_primary_security_quiescence_restores_policy
  test_bridge_take_attempt_total_is_transport_scoped
  test_bridge_inject_attempt_total_is_reason_agnostic
  test_pressure_monitor_uses_prefill_baseline
  test_pressure_state_uses_baseline_and_retains_steady_recovery
  test_pressure_state_has_attempt_and_wall_clock_bounds
  test_pressure_state_fails_closed_on_evidence_write_error
  test_map_pressure_prepare_fill_cleanup_transaction
  test_map_pressure_pre_mutation_failures_do_not_fill
  test_map_pressure_fill_failure_uses_prepared_cleanup_identity
  test_map_pressure_cleanup_retries_keep_immutable_artifacts
  test_map_pressure_result_contract_is_single_record_and_exact
  test_map_pressure_helper_capture_preserves_status_and_streams
  test_map_pressure_canonical_promotion_rolls_back_partial_files
  test_bridge_take_count_includes_cancelled_request
  test_pressure_scenario_counts_are_unique_and_bounded
  test_concurrency_overlap_reconciliation_is_exact
  test_reason_coded_scenario_reconciliation_is_exact
  test_bridge_metric_delta_requires_exact_one_shot_results
  test_coalesced_bridge_metrics_follow_explicit_outcome
  test_timeout_cancellation_metrics_follow_explicit_outcome
  test_pressure_bridge_reconciliation_preserves_failure_reasons
  test_primary_security_metrics_are_explicitly_scoped
  test_primary_security_identity_requires_same_cgroup_and_nonroot_user
  test_primary_security_probe_is_not_self_certifying
  test_generation_fault_protocol_and_output_are_exact
  test_generation_process_identity_is_namespace_qualified
  test_generation_mismatch_mutation_spans_the_victim_take
  test_generation_take_fence_waits_for_the_fourth_attempt
  test_primary_live_fd_descriptor_is_exact_and_bounded
  test_primary_live_fd_probe_result_is_exact
  test_primary_live_fd_barrier_consumption_accepts_empty_inode
  test_primary_live_fd_control_uses_exact_barrier_protocol
  test_primary_live_fd_barrier_budget_is_consistent
  test_primary_live_fd_recovery_scenario_propagates_failure
  test_primary_live_fd_control_restores_the_base_stack
  test_unix_security_metrics_require_explicit_race_scope
  test_unix_security_provider_wait_uses_restart_cursor
  test_unix_security_quiescence_restores_policy
  test_background_process_polling_handles_proc_race_quietly
  test_unix_security_identity_requires_same_cgroup_nonroot_capabilityfree
  test_unix_security_pid_namespace_identity_requires_exact_single_layer
  test_unix_security_pid_namespace_capture_redacts_proc_races
  test_unix_sibling_security_options_require_exact_nnp
  test_unix_sibling_tmpfs_requires_empty_configuration
  test_unix_abuse_race_result_requires_every_case
  test_unix_security_controls_use_isolated_topology_windows
  test_permissive_unix_directory_control_refuses_and_restores
  test_permissive_unix_directory_rejects_socket_probe_error
  test_unix_endpoint_restart_invalidates_before_stack_mutation
  test_java_diagnostics_schema_is_exact
  test_java_diagnostics_delta_is_exact
  test_reason_coded_control_diagnostics_are_exact
  test_pressure_unix_already_consumed_diagnostics_are_exact
  test_java_diagnostics_header_is_exact_and_piggybacked
  test_pre_stop_diagnostics_failure_does_not_stop_obi
  test_fault_diagnostics_result_is_single_sanitized_snapshot
  test_java_diagnostics_result_is_single_sanitized_snapshot
  test_w3c_fault_diagnostics_mappings_are_exact
  test_fault_scenario_chains_in_band_diagnostics_without_direct_probe
  test_fault_scenario_failure_retains_in_band_diagnostics
  test_w3c_fault_control_preserves_scenario_failure_in_conditional
  test_final_java_diagnostics_skip_active_fault_bridge
  test_helper_unavailable_scenario_injects_without_staging_or_retrieval
  test_scenario_fences_metrics_around_diagnostics
  test_pressure_scenario_reconciles_roots_with_bridge_and_java_counts
  test_pressure_unix_scenario_uses_strict_already_consumed_reconciliation
  test_pressure_failure_retains_wrong_parent_counts_and_cleans_up
  test_pressure_empty_result_fails_closed_and_cleans_up
  test_scenario_controls_matching_fixture_lifecycle
  test_scenario_supports_metrics_only_security_evidence
  test_security_controls_select_metrics_only_evidence
  test_scenario_records_metric_boundary_failure
  test_bridge_metric_boundary_fails_closed_on_fetch_failure
  test_scenario_records_required_evidence_failures
  test_java_diagnostics_parser_uses_base36
  test_restart_fault_diagnostics_require_overlap
  test_apache_tls_runtime_evidence_is_required
  test_bounded_commands_close_stdin
  test_optional_evidence_closes_stdin
  test_compose_commands_close_stdin
  test_pipeline_dependencies_are_declared
  test_runtime_environment_line_matching
  test_primary_fault_runtime_contract_is_exact_and_base_is_clean
  test_primary_live_fd_runtime_topology_is_exact
  test_benchmark_client_compose_topology_is_least_privilege
  test_extension_disabled_runtime_requires_explicit_false
  test_disabled_runtime_requires_explicit_transport_disable
  test_helper_attach_runtime_requires_exact_dynamic_disable
  test_delayed_otlp_runtime_requires_bounded_export_contract
  test_start_stack_invalidates_project_evidence_before_compose_up
  test_primary_w3c_fault_startup_uses_normal_runtime_contract
  test_instrumented_readiness_precedes_https_traffic
  test_delayed_otlp_startup_avoids_java_traffic
  test_delayed_otlp_recreate_avoids_java_traffic
  test_apache_readiness_requires_the_full_pool
  test_apache_instrumented_process_metric_is_exact
  test_apache_readiness_uses_elapsed_deadline
  test_apache_instrumentation_drain_is_a_generation_boundary
  test_apache_process_count_uses_docker_compatible_columns
  test_apache_readiness_rejects_failed_process_inspection
  test_apache_pool_bounds_pressure
  test_https_health_probes_close_the_backend_connection
  test_recreated_stack_readiness_uses_log_cursor
  test_disabled_control_waits_for_instrumentation
  test_uninstrumented_control_invalidates_before_stack_mutation
  test_standalone_restart_invalidates_before_stack_mutation
  test_extension_disabled_control_uses_configuration_log
  test_permanent_absence_requires_a_full_jvm_lifetime_boundary
  test_permanent_absence_startup_uses_normal_runtime_contract
  test_permanent_absence_startup_refuses_prior_run_recovery
  test_permanent_absence_project_guard_is_host_shared
  test_project_guard_terminal_handoff_is_status_truthful
  test_project_guard_terminal_handoff_wraps_real_runner
  test_permanent_absence_global_marker_is_exact_and_daemon_bound
  test_project_guard_docker_identity_capture_is_source_bounded
  test_permanent_absence_cleanup_only_clears_after_verified_down
  test_permanent_absence_global_marker_forces_exit_cleanup
  test_cleanup_signal_status_matches_retained_evidence
  test_permanent_absence_log_capture_is_source_bounded
  test_cleanup_compose_log_capture_is_source_bounded
  test_permanent_absence_readiness_is_source_bounded
  test_permanent_absence_failure_stops_the_jvm_before_recovery
  test_permanent_absence_identity_and_log_evidence_is_bounded
  test_permanent_absence_refuses_recovery_if_jvm_stop_fails
  test_permanent_absence_refuses_jvm_stop_after_docker_drift
  test_permanent_absence_refuses_stale_evidence_before_mutation
  test_late_attach_recycles_only_apache_after_readiness
  test_control_response_normalizes_connection_diagnostics
  test_required_read_failures_do_not_publish_evidence
  test_helper_attach_failure_control_restores_and_preserves_status
  test_restart_readiness_uses_log_cursor
  test_failed_log_read_cannot_satisfy_readiness
  test_standalone_restart_waits_for_apache_instrumentation
  test_restart_fault_recovery_waits_for_apache_instrumentation
  test_restart_fault_rejects_traffic_ending_before_first_barrier
  test_restart_failure_reaps_background_traffic
  test_scenario_failure_retains_after_evidence
  test_start_failure_retains_command_boundary
  test_pre_environment_failure_retains_acceptance_eligibility
  test_log_write_failure_is_not_ignored
  test_footer_write_failure_preserves_first_failure
  test_error_logging_preserves_primary_status
  test_die_records_explicit_failure_boundary
  test_assertion_failure_control_is_explicit
  test_assertion_failure_control_retains_failure_evidence
  test_non_acceptance_reasons_are_recorded
  test_retained_evidence_provenance_is_verified
  test_primary_wrong_live_socket_evidence_is_exact
  test_retained_evidence_v2_git_tree_schema_is_verified
  test_source_gitlink_depth_is_bounded
  test_source_git_tree_path_validation_is_byte_safe
  test_clean_source_checkout_stability_rejects_changed_revision
  test_source_controls_and_bridge_export_use_private_work_directory
  test_clean_source_snapshot_uses_pinned_git_inputs
  test_run_status_serializes_default_acceptance_reason
  test_release_source_uses_one_version_for_extension
  test_java_build_uses_isolated_gradle_home
  test_demo_diagnostics_are_loopback_only
  test_apache_diagnostic_denial_matrix_is_exact
  test_compatibility_matrix_lists_deployment_modes
  test_demo_uses_only_explicit_tcp_context
  test_demo_java_attach_timeout_is_explicit
  test_primary_live_fd_compose_topology_is_scoped
  test_unix_security_probe_topology_is_least_privilege
  printf 'demo harness tests passed\n'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
