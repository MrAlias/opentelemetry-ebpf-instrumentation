#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# This harness intentionally overrides sourced run.sh globals and functions in isolated subshells.
# shellcheck disable=SC2016,SC2030,SC2031,SC2034,SC2329

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
  local -r fake_docker="$fake_bin/docker"

  mkdir -p -- "$fake_bin"
  cat >"$fake_docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "$1 $2" in
  "container ls") printf 'demo-container\n' ;;
  "volume ls") printf 'demo-volume\n' ;;
  "network ls") printf 'demo-network\n' ;;
  "container inspect"|"volume inspect"|"network inspect")
    if [[ "$FAKE_DOCKER_MODE" == "foreign" && "$1" == "container" ]]; then
      printf 'someone-else\n'
    else
      printf 'acceptance-demo-v1\n'
    fi
    ;;
  "compose --project-name") ;;
  *) printf 'unexpected fake Docker arguments: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
  chmod 0755 "$fake_docker"

  (
    export PATH="$fake_bin:$PATH"
    export FAKE_DOCKER_LOG="$docker_log"
    export FAKE_DOCKER_MODE=owned
    PROJECT_NAME="obi-apache-java-https-test"
    COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE")
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

  : >"$docker_log"
  if (
    export PATH="$fake_bin:$PATH"
    export FAKE_DOCKER_LOG="$docker_log"
    export FAKE_DOCKER_MODE=foreign
    PROJECT_NAME="obi-apache-java-https-test"
    COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE")
    safe_compose_down
  ) >/dev/null 2>&1; then
    printf 'cleanup accepted a foreign resource in the reserved project namespace\n' >&2
    return 1
  fi
  if grep -Fq 'compose --project-name' "$docker_log"; then
    printf 'cleanup invoked Compose down after ownership verification failed\n' >&2
    return 1
  fi
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
  if (
    TRANSPORT="getsockopt"
    SCENARIO="all"
    parse_args --transport getsockopt --scenario uninstrumented
  ) >/dev/null 2>&1; then
    printf 'accepted an uninstrumented control with an enabled transport\n' >&2
    return 1
  fi
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
  local -r expected=$'basic\nsecurity\nkeepalive\npipelining\nconcurrency\nconnection-churn\nfd-port-reuse\nslow-body\ntls-boundary\ntimeout-retry\npressure\nhandoff\nvirtual-thread\nnetty\ndispatch\nw3c\nw3c-match\nobi-flags\nfail-open\nw3c-only\nrestart\nrestart-fault\ndisabled\nw3c-only\nw3c-only\nuninstrumented'

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
    record_unsupported_scenario() {
      return 0
    }
    run_primary_security_control() {
      run_scenario security
    }
    run_disabled_control() {
      run_scenario disabled
    }
    run_restart_during_traffic_control() {
      run_scenario restart-fault
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
    run_w3c_fault_control() {
      run_scenario w3c-fault
    }
    run_unix_security_control() {
      run_scenario security
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
    run_extension_controls() {
      run_scenario w3c-only
      run_scenario w3c-only
    }
    run_uninstrumented_control() {
      run_scenario uninstrumented
    }
    execute_requested_scenarios
  )

  [[ "$(<"$actual")" == *$'basic\nsecurity\nkeepalive'* && \
    "$(<"$actual")" == *$'obi-flags\nw3c-fault\nfail-open'* ]] || {
    printf 'Unix all suite omitted the security or bounded W3C fault control\n' >&2
    return 1
  }
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

test_tls_boundary_requires_both_deterministic_modes() {
  (
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --scenario tls-boundary --requests 2
    [[ "$SCENARIO" == "tls-boundary" && "$REQUEST_COUNT" == "2" ]]
  ) || {
    printf 'rejected the exact two-case TLS boundary scenario\n' >&2
    return 1
  }
  if (
    SCENARIO=all
    REQUEST_COUNT=0
    parse_args --scenario tls-boundary --requests 1
  ) >/dev/null 2>&1; then
    printf 'accepted a TLS boundary run without both deterministic modes\n' >&2
    return 1
  fi
}

test_w3c_match_selects_header_and_tcp_propagation() {
  (
    SCENARIO=w3c-match
    export_compose_environment
    [[ "$CONTEXT_PROPAGATION" == "headers,tcp" ]]
  ) || {
    printf 'W3C match did not select isolated headers and TCP propagation\n' >&2
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

  cat >"$before" <<'EOF'
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 2
obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 7
EOF
  cat >"$after" <<'EOF'
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 5
obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 1
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
}

test_metric_boundary_helpers_are_reason_coded() {
  local metrics="$TEST_TMP_DIR/bridge-metrics.prom"
  local pressure=""

  cat >"$metrics" <<'EOF'
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 2
obi_java_remote_parent_operations_total{operation="discard",status="valid",transport="unix"} 3
obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} 99
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} 99
obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7
obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 10000
obi_avoided_services{otel_metric_overflow="false",service_name="java-backend",service_namespace="apache-java-https",telemetry_type="traces"} 1
EOF

  [[ "$(bridge_success_total "$metrics")" == "5" ]] || {
    printf 'bridge success total included a non-success or non-transport counter\n' >&2
    return 1
  }
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

test_pressure_monitor_requires_full_occupancy() {
  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-failure"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    : >"$PRESSURE_MONITOR_OUTPUT"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 9' >"$1"
    }
    if (monitor_map_pressure); then
      printf 'pressure monitor accepted below-full occupancy\n' >&2
      return 1
    fi
    grep -Fq 'status=failed reason=occupancy map_id=41 expected=10 actual=9' \
      "$PRESSURE_MONITOR_OUTPUT"
  )

  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-success"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_LABEL="pressure-test"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 10' >"$1"
    }
    start_map_pressure_monitor
    local monitor_pid="$PRESSURE_MONITOR_PID"
    stop_map_pressure_monitor
    if kill -0 "$monitor_pid" 2>/dev/null; then
      printf 'pressure monitor was not terminated and reaped\n' >&2
      return 1
    fi
    grep -Fq 'status=full ' "$PRESSURE_MONITOR_OUTPUT"
  )
}

test_bridge_take_count_includes_cancelled_request() {
  REQUEST_COUNT=0
  [[ "$(scenario_bridge_take_count basic)" == "1" ]] || {
    printf 'basic bridge take count did not match its request count\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_take_count timeout-retry)" == "2" ]] || {
    printf 'timeout/retry bridge take count omitted the cancelled request\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count basic true getsockopt)" == "0" &&
    "$(scenario_java_missing_count basic true)" == "1" ]] || {
    printf 'getsockopt diagnostics miss expectations were conflated\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count basic true unix)" == "1" &&
    "$(scenario_java_missing_count basic true)" == "1" ]] || {
    printf 'Unix diagnostics miss expectations did not include the transport lookup\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count tls-boundary true getsockopt)" == "0" &&
    "$(scenario_java_missing_count tls-boundary true)" == "4" ]] || {
    printf 'getsockopt TLS-boundary miss expectations were not local-only\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count tls-boundary true unix)" == "4" &&
    "$(scenario_java_missing_count tls-boundary true)" == "4" ]] || {
    printf 'Unix TLS-boundary miss expectations omitted transport lookups\n' >&2
    return 1
  }
}

test_bridge_metric_delta_requires_exact_one_shot_results() {
  local -r delta="$TEST_TMP_DIR/w3c-metrics.delta"

  cat >"$delta" <<'EOF'
obi_java_remote_parent_operations_total{operation="candidate",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="inject",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="stage",status="valid",transport="tcp"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="candidate",status="ambiguous",transport="tcp"} before=1 after=3 delta=2
obi_java_remote_parent_operations_total{operation="cleanup",status="valid",transport="tcp"} before=0 after=16 delta=16
obi_java_remote_parent_operations_total{operation="negotiate",status="missing",transport="getsockopt"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="discard",status="valid",transport="getsockopt"} before=1 after=1 delta=0
obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} before=3 after=5 delta=2
obi_java_remote_parent_operations_total{operation="take",status="missing",transport="getsockopt"} before=0 after=0 delta=0
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
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="candidate",status="overload",transport="tcp"} before=0 after=1 delta=1' \
    >>"$delta"
  if assert_bridge_metric_delta "$delta" getsockopt 2 0 >/dev/null 2>&1; then
    printf 'bridge metric delta accepted candidate overload\n' >&2
    return 1
  fi
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
    'obi_java_remote_parent_operations_total{operation="take",status="unauthorized",transport="getsockopt"} before=0 after=1 delta=1' \
    >>"$sibling_delta"
  if assert_primary_security_metric_delta "$sibling_delta" take 0 0 >/dev/null 2>&1; then
    printf 'sibling security control accepted an intercepted take\n' >&2
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

test_permissive_unix_directory_control_refuses_and_restores() {
  local -r result_dir="$TEST_TMP_DIR/permissive-directory-control"
  local -r observed="$result_dir/observed"

  mkdir -p -- "$result_dir"
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
        *" logs --no-color "*)
          printf 'must not be group writable or world accessible\n'
          ;;
      esac
      printf '%s\n' "$*" >>"$observed"
    }
    wait_for_log() {
      printf 'wait:%s\n' "$2" >>"$observed"
    }
    assert_selected_transport() {
      SELECTED_TRANSPORT=unix
    }
    date() {
      printf 'security-cursor\n'
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

    run_unix_permissive_directory_control
    [[ "$directory_mode" == "0750" ]]
    [[ "$UNIX_SECURITY_DIRECTORY_RELAXED" == "false" ]]
    [[ "$BRIDGE_RUNNING" == "true" ]]
  ) || {
    printf 'permissive Unix directory control did not refuse and restore safely\n' >&2
    return 1
  }
  grep -Fq 'wait:must not be group writable or world accessible' "$observed"
  grep -Fq 'wait:Java remote parent bridge ready' "$observed"
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
  local snapshot="cfg_on=0,cfg_off=0,provider_ok=0,provider_reject=0,provider_ver=0,extension_reg=0,lookup_ready=0,lookup_missing=0,lookup_version=0,lookup_error=0,record_version=0,invoke_error=0,discard_standard=$standard,extract_fields=0,extract_invalid=0,extract_error=0,registration_ok=0,registration_fail=0,take_sampled=$sampled,take_unsampled=$unsampled,tls_reads=0,tls_bytes=0"
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

  write_diagnostics_fixture "$snapshot" 0 0 0 0 0 0
  assert_sanitized_java_diagnostics "$snapshot"

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
}

test_java_diagnostics_delta_is_exact() {
  local -r before="$TEST_TMP_DIR/java-before.txt"
  local -r after="$TEST_TMP_DIR/java-after.txt"
  local -r delta="$TEST_TMP_DIR/java.delta"

  write_diagnostics_fixture "$before" 0 0 0 0 0 0
  write_diagnostics_fixture "$after" 2 0 0 1 1 1 missing 1
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 || {
    printf 'Java diagnostics rejected exact expected deltas\n' >&2
    return 1
  }

  sed -i 's/t_missing before=0 after=1 delta=1/t_missing before=0 after=2 delta=2/' "$delta"
  if assert_java_diagnostics_delta "$delta" 2 0 0 1 1 1 1 >/dev/null 2>&1; then
    printf 'Java diagnostics accepted an additional missing lookup\n' >&2
    return 1
  fi
  sed -i 's/t_missing before=0 after=2 delta=2/t_missing before=0 after=1 delta=1/' "$delta"

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
  write_diagnostics_fixture "$after" 0 0 0 0 0 0 transport_error 1
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_java_diagnostics_delta "$delta" 0 0 0 0 0 0 0 transport_error 1 || {
    printf 'Java diagnostics rejected an attributable fault status\n' >&2
    return 1
  }
}

test_fault_scenario_does_not_probe_java_diagnostics() {
  local -r diagnostics_calls="$TEST_TMP_DIR/fault-diagnostics.calls"

  (
    RESULT_DIR="$TEST_TMP_DIR/fault-scenario"
    mkdir -p -- "$RESULT_DIR"
    BRIDGE_RUNNING=false
    COMPOSE=(docker compose)
    FAULT_MODE=alternating
    FAULT_REQUEST_COUNT=2
    REPEAT_COUNT=1
    REQUEST_COUNT=0
    SCENARIO_SEED=1
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
      printf '{"status":"passed"}\n'
    }

    run_scenario w3c-fault >/dev/null
    run_scenario basic false >/dev/null
  ) || {
    printf 'scenario failed with diagnostics probes explicitly disabled\n' >&2
    return 1
  }

  if [[ -e "$diagnostics_calls" ]]; then
    printf 'scenario consumed a diagnostics probe while probes were disabled\n' >&2
    return 1
  fi
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
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_restart_fault_diagnostics "$delta" 32 "$result"
  grep -Fqx 'take_fail_open=12' "$result"

  write_diagnostics_fixture "$after" w 0 0 w 0 w
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted a run without an observed bridge fault\n' >&2
    return 1
  fi
}

test_pipeline_dependencies_are_declared() {
  local definition=""

  definition="$(declare -f check_dependencies)"
  [[ "$definition" == *" mv "* && "$definition" == *" tee "* ]] || {
    printf 'runner dependency check omitted mv or tee\n' >&2
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
    verify_compose_project_ownership() {
      return 0
    }
    run_bounded() {
      return 0
    }
    run_logged_bounded() {
      return 0
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }
    wait_for_log() {
      printf 'log:%s\n' "$3" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    assert_runtime_contract() {
      printf 'runtime\n' >>"$observed"
    }

    start_stack
  ) || {
    printf 'instrumented readiness-order probe failed\n' >&2
    return 1
  }

  printf '%s\n' \
    'http:trace receiver' \
    'log:OBI remote-parent bridge' \
    'log:injected Java helper' \
    'log:external OTel extension' \
    'transport' \
    'log:injected Java instrumentation' \
    'http:verified Apache-to-Jetty HTTPS path' \
    'runtime' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'instrumented HTTPS traffic ran before bridge readiness\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
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

  (
    COMPOSE=(test-compose)
    BRIDGE_RUNNING=false
    date() {
      printf 'recreate-cursor\n'
    }
    run_bounded() {
      printf 'compose:%s\n' "$*" >>"$observed"
    }
    wait_for_log() {
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    wait_for_http() {
      printf 'http:%s\n' "$2" >>"$observed"
    }

    recreate_instrumented_stack tcp restoration
  ) || {
    printf 'recreated stack readiness-order probe failed\n' >&2
    return 1
  }

  printf '%s\n' \
    'compose:180 test-compose up --detach --force-recreate java-backend apache-proxy obi' \
    'log:restoration OBI remote-parent bridge:recreate-cursor' \
    'log:restoration injected Java helper:recreate-cursor' \
    'log:restoration external OTel extension:recreate-cursor' \
    'log:restoration injected Java instrumentation:recreate-cursor' \
    'transport' \
    'http:restoration HTTPS path' >"$expected"
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

  mkdir -p -- "$result_dir"
  (
    RESULT_DIR="$result_dir"
    COMPOSE=(test-compose)
    date() {
      printf 'disabled-cursor\n'
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
    run_scenario() {
      printf 'scenario:%s\n' "$1" >>"$observed"
    }

    run_disabled_control
  ) || {
    printf 'disabled-control readiness-order probe failed\n' >&2
    return 1
  }

  printf '%s\n' \
    'compose:30 test-compose config' \
    'compose:120 test-compose up --detach --force-recreate java-backend apache-proxy obi' \
    'log:disabled-control external extension:disabled-cursor' \
    'log:disabled-control Java instrumentation:disabled-cursor' \
    'http:disabled-control HTTPS path' \
    'runtime:disabled' \
    'scenario:disabled' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'disabled control used stale instrumentation readiness\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
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
    'compose:120 test-compose up --detach --force-recreate --no-deps apache-proxy' \
    'log:late-attach Apache instrumentation:late-attach-cursor' \
    'http:late-attach recovered HTTPS path' \
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
    '{"marker":"instrumentation-control","backend_connection_id":17,"backend_remote_port":41000,"backend_socket_fd":0}' \
    >"$instrumented"
  printf '%s\n' \
    '{"marker":"instrumentation-control","backend_connection_id":3,"backend_remote_port":42000,"backend_socket_fd":0}' \
    >"$uninstrumented"

  normalize_control_response "$instrumented" "$instrumented_normalized"
  normalize_control_response "$uninstrumented" "$uninstrumented_normalized"
  cmp "$instrumented_normalized" "$uninstrumented_normalized" || {
    printf 'control response normalization retained recreated connection identity\n' >&2
    return 1
  }
  grep -Fq '"backend_connection_id":0' "$instrumented_normalized"
  grep -Fq '"backend_remote_port":0' "$instrumented_normalized"
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

test_restart_failure_reaps_background_traffic() {
  local -r fake_compose="$TEST_TMP_DIR/restart-failure-compose"
  local -r traffic_pid_file="$TEST_TMP_DIR/restart-traffic.pid"
  local -r traffic_term_file="$TEST_TMP_DIR/restart-traffic.terminated"
  local status=0
  local traffic_pid=""
  local -i elapsed=0

  cat >"$fake_compose" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case " $* " in
  *" run --rm --no-deps scenario "*)
    printf '%d\n' "$$" >"$RESTART_TRAFFIC_PID_FILE"
    trap 'printf "terminated\n" >"$RESTART_TRAFFIC_TERM_FILE"; exit 0' TERM INT
    while true; do sleep 1; done
    ;;
  *" stop --timeout 5 obi "*) exit 23 ;;
  *) exit 0 ;;
esac
EOF
  chmod 0755 "$fake_compose"

  if (
    export RESTART_TRAFFIC_PID_FILE="$traffic_pid_file"
    export RESTART_TRAFFIC_TERM_FILE="$traffic_term_file"
    RESULT_DIR="$TEST_TMP_DIR/restart-failure"
    mkdir -p -- "$RESULT_DIR"
    COMPOSE=("$fake_compose")
    BRIDGE_RUNNING=true
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
    COMMAND_TIMEOUT_SECONDS=5
    STACK_STARTED=false
    BRIDGE_RUNNING=false
    mkdir -p -- "$RESULT_DIR" || return 1
    verify_compose_project_ownership() {
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
  ) || {
    printf 'logged failure evidence was incomplete\n' >&2
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

test_demo_diagnostics_are_loopback_only() {
  local -r apache_config="$TEST_SCRIPT_DIR/../apache/httpd.conf"
  local -r obi_config="$TEST_SCRIPT_DIR/../configs/obi.yaml"

  grep -Fqx 'Listen 127.0.0.1:18080' "$apache_config"
  grep -Fq '<Location "/obi-diagnostics">' "$apache_config"
  grep -Fq 'Require all denied' "$apache_config"
  grep -Fq 'address: 127.0.0.1' "$obi_config"
  grep -Fqx '  buffer_sizes:' "$obi_config"
  grep -Fqx '    http: 8192' "$obi_config"
  grep -Fqx '                - X-OBI-Demo-ID' "$obi_config"
}

main() {
  TEST_TMP_DIR="$(mktemp -d)"
  test_project_name_validation
  test_compose_cleanup_requires_ownership_sentinel
  test_acceptance_requires_fresh_bridge_build
  test_custom_all_request_count_is_non_acceptance
  test_numeric_options_reject_overflow
  test_control_modes_are_distinct
  test_benchmark_controls_are_bounded
  test_all_suite_includes_every_scenario
  test_unix_all_suite_includes_fault_control
  test_w3c_fault_requires_forced_unix
  test_security_accepts_enabled_transports
  test_tls_boundary_requires_both_deterministic_modes
  test_w3c_match_selects_header_and_tcp_propagation
  test_runtime_directory_rejects_symlink
  test_bridge_artifact_metadata
  test_agent_download_rejects_symlink_output
  test_metrics_delta_reports_counters_and_map_occupancy
  test_metric_boundary_helpers_are_reason_coded
  test_pressure_monitor_requires_full_occupancy
  test_bridge_take_count_includes_cancelled_request
  test_bridge_metric_delta_requires_exact_one_shot_results
  test_primary_security_metrics_are_explicitly_scoped
  test_primary_security_identity_requires_same_cgroup_and_nonroot_user
  test_unix_security_metrics_require_explicit_race_scope
  test_permissive_unix_directory_control_refuses_and_restores
  test_java_diagnostics_schema_is_exact
  test_java_diagnostics_delta_is_exact
  test_fault_scenario_does_not_probe_java_diagnostics
  test_java_diagnostics_parser_uses_base36
  test_restart_fault_diagnostics_require_overlap
  test_pipeline_dependencies_are_declared
  test_runtime_environment_line_matching
  test_instrumented_readiness_precedes_https_traffic
  test_https_health_probes_close_the_backend_connection
  test_recreated_stack_readiness_uses_log_cursor
  test_disabled_control_waits_for_instrumentation
  test_late_attach_recycles_only_apache_after_readiness
  test_control_response_normalizes_connection_diagnostics
  test_restart_readiness_uses_log_cursor
  test_restart_failure_reaps_background_traffic
  test_scenario_failure_retains_after_evidence
  test_start_failure_retains_command_boundary
  test_log_write_failure_is_not_ignored
  test_footer_write_failure_preserves_first_failure
  test_error_logging_preserves_primary_status
  test_die_records_explicit_failure_boundary
  test_non_acceptance_reasons_are_recorded
  test_release_source_uses_one_version_for_extension
  test_demo_diagnostics_are_loopback_only
  printf 'demo harness tests passed\n'
}

main "$@"
