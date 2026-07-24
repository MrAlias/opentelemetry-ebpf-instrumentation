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
obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7
obi_bpf_map_max_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 10000
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

test_pressure_map_metric_requires_exact_unique_series() {
  local -r metrics="$TEST_TMP_DIR/pressure-map-metric.prom"

  printf '%s\n' \
    'obi_bpf_map_entries_total_shadow{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 9' \
    >"$metrics"
  if pressure_map_metric "$metrics" obi_bpf_map_entries_total 41 >/dev/null; then
    printf 'pressure-map resolver accepted a prefixed metric name\n' >&2
    return 1
  fi

  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
    >>"$metrics"
  [[ "$(pressure_map_metric "$metrics" obi_bpf_map_entries_total 41)" == "41 7" ]]

  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 8' \
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
        (2 * readiness_timeout) + 143 + (repeat_count * 232)
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
223 10
EOF
    if (
      READINESS_TIMEOUT_SECONDS="$MAX_SHELL_INTEGER"
      REPEAT_COUNT=1
      configure_security_probe_timeouts
    ) >/dev/null 2>&1; then
      return 1
    fi
    if (
      READINESS_TIMEOUT_SECONDS=224
      REPEAT_COUNT=10
      configure_security_probe_timeouts
    ) >/dev/null 2>&1; then
      return 1
    fi
    READINESS_TIMEOUT_SECONDS=224
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
    PRESSURE_TAKE_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    : >"$PRESSURE_MONITOR_OUTPUT"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' >"$1"
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
    PRESSURE_TAKE_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    PRESSURE_MONITOR_OUTPUT="$RESULT_DIR/monitor.log"
    : >"$PRESSURE_MONITOR_OUTPUT"
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 18446744073709551625' >"$1"
    }
    if (monitor_map_pressure); then
      printf 'pressure monitor accepted an overflowing occupancy value\n' >&2
      return 1
    fi
    grep -Fq 'actual=18446744073709551625' "$PRESSURE_MONITOR_OUTPUT"
  )

  (
    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-success"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_LABEL="pressure-test"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_TAKE_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    fetch_obi_metrics() {
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 9' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 5' >"$1"
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
    local fixture_take_total=4

    RESULT_DIR="$TEST_TMP_DIR/pressure-monitor-stop-race"
    mkdir -p -- "$RESULT_DIR"
    PRESSURE_LABEL="pressure-test"
    PRESSURE_MAP_ID=41
    PRESSURE_MAP_MAX_ENTRIES=10
    PRESSURE_MAP_BASELINE_ENTRIES=7
    PRESSURE_TAKE_TARGET=5
    SELECTED_TRANSPORT=getsockopt
    fetch_obi_metrics() {
      fetch_calls="$((fetch_calls + 1))"
      if ((fetch_calls > 1)); then
        fixture_take_total=5
      fi
      printf '%s\n' \
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 9' \
        "obi_java_remote_parent_operations_total{operation=\"take\",status=\"valid\",transport=\"getsockopt\"} $fixture_take_total" >"$1"
    }
    start_map_pressure_monitor
    stop_map_pressure_monitor
    grep -Fq 'status=traffic-complete ' "$PRESSURE_MONITOR_OUTPUT"
    [[ -f "$PRESSURE_MONITOR_FINAL_OUTPUT" ]]
  )
}

pressure_prepare_result() {
  local -r token_base="$1"

  printf '{"status":"passed","mode":"prepare","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":%s,"touched":0}\n' \
    "$token_base"
}

pressure_fill_result() {
  local -r token_base="$1"

  printf '{"status":"passed","mode":"fill","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":%s,"touched":11,"evicted_entries":2}\n' \
    "$token_base"
}

pressure_cleanup_result() {
  local -r token_base="$1"

  printf '{"status":"passed","mode":"cleanup","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":10,"process_map_id":0,"process_pid":101,"process_namespace":202,"token_base":%s,"touched":9,"cleanup_verified":true,"verified_absent_entries":11}\n' \
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
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 8' >"$1"
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
      printf 'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash",sample="%d"} %s\n' \
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
        'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 3' >"$1"
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
      'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 3' \
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
    [[ "$PRESSURE_TAKE_TARGET" == "8" ]] || return 1
    [[ "$PRESSURE_ACTIVE" == "true" && \
      "$PRESSURE_MAP_BASELINE_ENTRIES" == "7" && \
      "$PRESSURE_PROCESS_MAP_ID" == "42" && \
      "$PRESSURE_TOKEN_BASE" == "$token_base" && \
      "$PRESSURE_TOUCHED_ENTRIES" == "11" && \
      "$PRESSURE_EVICTED_ENTRIES" == "2" ]] || {
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
      'obi_bpf_map_entries_total{map_id="99",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
      'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="lru_hash"} 7' \
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
  [[ "$(scenario_bridge_missing_count tls-boundary getsockopt)" == "0" &&
    "$(scenario_java_missing_count tls-boundary true)" == "4" ]] || {
    printf 'getsockopt TLS-boundary miss expectations were not local-only\n' >&2
    return 1
  }
  [[ "$(scenario_bridge_missing_count tls-boundary unix)" == "3" &&
    "$(scenario_java_missing_count tls-boundary true)" == "4" ]] || {
    printf 'Unix TLS-boundary miss expectations included baseline diagnostics\n' >&2
    return 1
  }
}

test_bridge_metric_delta_requires_exact_one_shot_results() {
  local -r delta="$TEST_TMP_DIR/w3c-metrics.delta"

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
    }
    wait_for_log() {
      printf 'log:%s:%s\n' "$3" "${4:-}" >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
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
  grep -Fq 'logs --no-color --since security-cursor obi' "$observed"
  awk '
    /up --detach --no-deps --force-recreate obi/ { recovery = NR }
    $0 == "log:post-permission Java bridge provider:security-cursor" { provider = NR }
    $0 == "apache:unix-permission-recovery" { readiness = NR }
    END {
      exit recovery > 0 && provider > recovery && readiness > provider ? 0 : 1
    }
  ' "$observed" || {
    printf 'Unix permission recovery resumed before Apache instrumentation readiness\n' >&2
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
  sed -i 's/t_missing=0/t_missing=1/' "$after"
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
    [[ "$(<"$call_log")" == "$(printf \
      'boundary:%s\ndiagnostics:%s-before\nwait:0:0\nevidence:%s-before\nscenario:%s\nwait:%d:%d\nevidence:%s-after\ndiagnostics:%s-after' \
      "$name" "$name" "$name" "$wanted_request_argument" \
      "$expected_requests" "$expected_requests" "$name" "$name")" ]]
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
  run_accounting_case tls-boundary 0 2 4 2 0 0 2 || {
    printf 'TLS-boundary scenario did not fence metrics around diagnostics\n' >&2
    return 1
  }
  run_accounting_case obi-flags 4 4 1 2 2 0 4 || {
    printf 'OBI-flags scenario did not preserve sampled and unsampled takes\n' >&2
    return 1
  }
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
  local unix_control=""

  primary_control="$(declare -f run_primary_security_control)"
  unix_control="$(declare -f run_unix_security_control)"
  [[ "$primary_control" == *'run_scenario concurrency false metrics'* &&
    "$unix_control" == *'run_scenario concurrency false metrics'* ]] || {
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
  sed -i 's/t_missing=0/t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_restart_fault_diagnostics "$delta" 32 "$result"
  grep -Fqx 'observed_take_total=33' "$result"
  grep -Fqx 'workload_valid_min=19' "$result"
  grep -Fqx 'workload_valid_max=20' "$result"
  grep -Fqx 'workload_fail_open_min=12' "$result"
  grep -Fqx 'workload_fail_open_max=13' "$result"

  write_diagnostics_fixture "$after" k 0 0 k 0 k timeout c
  sed -i 's/t_already_consumed=0/t_already_consumed=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  assert_restart_fault_diagnostics "$delta" 32 "$result" || {
    printf 'restart diagnostics rejected an already-consumed self lookup\n' >&2
    return 1
  }
  grep -Fqx 'observed_take_total=33' "$result"
  grep -Fqx 'workload_valid_min=19' "$result"
  grep -Fqx 'workload_valid_max=20' "$result"
  grep -Fqx 'workload_fail_open_min=12' "$result"
  grep -Fqx 'workload_fail_open_max=13' "$result"

  sed -i 's/t_missing=0/t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted an additional take result\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" k 0 0 k 0 k timeout d
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted a run without a diagnostics-eligible result\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" 6 0 0 6 0 6 timeout k
  sed -i 's/t_missing=0/t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  sed -i '/^t_valid /p' "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted duplicate rows that forged the take total\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" 1 0 0 1 0 0 missing w
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 "$result" >/dev/null 2>&1; then
    printf 'restart diagnostics accepted an attribution-ambiguous single valid result\n' >&2
    return 1
  fi

  write_diagnostics_fixture "$after" w 0 0 w 0 w
  sed -i 's/t_missing=0/t_missing=1/' "$after"
  write_java_diagnostics_delta "$before" "$after" "$delta"
  if assert_restart_fault_diagnostics "$delta" 32 "$result" >/dev/null 2>&1; then
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
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
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
    'apache:startup' \
    'http:verified Apache-to-Jetty HTTPS path' \
    'runtime' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'instrumented HTTPS traffic ran before bridge readiness\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_apache_readiness_requires_the_full_pool() {
  local -r result_dir="$TEST_TMP_DIR/apache-readiness"

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
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
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
    'apache:recreate-instrumented' \
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

test_standalone_restart_waits_for_apache_instrumentation() {
  local -r observed="$TEST_TMP_DIR/restart-readiness.observed"
  local -r expected="$TEST_TMP_DIR/restart-readiness.expected"

  (
    SCENARIO=restart
    COMPOSE=(test-compose)
    date() {
      printf 'restart-cursor\n'
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
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
    }
    run_scenario() {
      printf 'scenario:%s\n' "$1" >>"$observed"
    }

    execute_requested_scenarios
  ) || {
    printf 'standalone restart readiness-order probe failed\n' >&2
    return 1
  }

  printf '%s\n' \
    'compose:60 test-compose restart --timeout 10 obi' \
    'log:restarted OBI remote-parent bridge:restart-cursor' \
    'log:restarted Java bridge provider:restart-cursor' \
    'transport' \
    'apache:restart' \
    'scenario:restart' >"$expected"
  cmp -s -- "$expected" "$observed" || {
    printf 'standalone restart resumed before Apache instrumentation readiness\n' >&2
    diff -u -- "$expected" "$observed" >&2 || true
    return 1
  }
}

test_restart_fault_recovery_waits_for_apache_instrumentation() {
  local -r fake_compose="$TEST_TMP_DIR/restart-success-compose"
  local -r ready="$TEST_TMP_DIR/restart-success.ready"
  local -r observed="$TEST_TMP_DIR/restart-success.observed"

  cat >"$fake_compose" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'compose:%s\n' "$*" >>"$RESTART_SUCCESS_OBSERVED"
case " $* " in
  *" run --rm --no-deps --no-TTY scenario "*)
    while [[ ! -e "$RESTART_SUCCESS_READY" ]]; do
      sleep 0.01
    done
    printf '{}\n'
    ;;
  *" up --detach obi "*)
    : >"$RESTART_SUCCESS_READY"
    ;;
esac
EOF
  chmod 0755 "$fake_compose"

  (
    export RESTART_SUCCESS_READY="$ready"
    export RESTART_SUCCESS_OBSERVED="$observed"
    RESULT_DIR="$TEST_TMP_DIR/restart-success-result"
    COMPOSE=("$fake_compose")
    BRIDGE_RUNNING=true
    SCENARIO_VARIANT=""
    mkdir -p -- "$RESULT_DIR"
    date() {
      printf 'restart-success-cursor\n'
    }
    sleep() {
      return 0
    }
    wait_for_log() {
      printf 'log:%s\n' "$3" >>"$observed"
    }
    assert_selected_transport() {
      printf 'transport\n' >>"$observed"
    }
    wait_for_apache_instrumentation() {
      printf 'apache:%s\n' "$1" >>"$observed"
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
    $0 == "log:Java bridge recovered during restart traffic" { provider = NR }
    $0 == "apache:restart-fault-recovery" { readiness = NR }
    $0 == "capture:restart-fault-after" { capture = NR }
    $0 == "scenario:restart:restart-recovery" { scenario = NR }
    END {
      exit provider > 0 && readiness > provider && capture > readiness &&
        scenario > capture ? 0 : 1
    }
  ' "$observed" || {
    printf 'restart-fault recovery resumed before Apache instrumentation readiness\n' >&2
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
  *" run --rm --no-deps --no-TTY scenario "*)
    if IFS= read -r unexpected; then
      printf 'unexpected stdin: %s\n' "$unexpected" >&2
      exit 64
    fi
    printf '%d\n' "$$" >"$RESTART_TRAFFIC_PID_FILE"
    trap 'printf "terminated\n" >"$RESTART_TRAFFIC_TERM_FILE"; exit 0' TERM INT
    while true; do sleep 1; done
    ;;
  *" stop --timeout 5 obi "*) exit 23 ;;
  *) exit 0 ;;
esac
EOF
  chmod 0755 "$fake_compose"

  if printf 'must-not-reach-restart-traffic\n' | (
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
  test_pressure_map_metric_requires_exact_unique_series
  test_bridge_metric_wait_requires_quiescent_report
  test_security_probe_window_covers_metric_fences
  test_primary_security_quiescence_restores_policy
  test_bridge_take_attempt_total_is_transport_scoped
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
  test_bridge_metric_delta_requires_exact_one_shot_results
  test_primary_security_metrics_are_explicitly_scoped
  test_primary_security_identity_requires_same_cgroup_and_nonroot_user
  test_unix_security_metrics_require_explicit_race_scope
  test_permissive_unix_directory_control_refuses_and_restores
  test_java_diagnostics_schema_is_exact
  test_java_diagnostics_delta_is_exact
  test_fault_scenario_does_not_probe_java_diagnostics
  test_scenario_fences_metrics_around_diagnostics
  test_scenario_supports_metrics_only_security_evidence
  test_security_controls_select_metrics_only_evidence
  test_scenario_records_metric_boundary_failure
  test_java_diagnostics_parser_uses_base36
  test_restart_fault_diagnostics_require_overlap
  test_apache_tls_runtime_evidence_is_required
  test_bounded_commands_close_stdin
  test_optional_evidence_closes_stdin
  test_compose_commands_close_stdin
  test_pipeline_dependencies_are_declared
  test_runtime_environment_line_matching
  test_instrumented_readiness_precedes_https_traffic
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
  test_late_attach_recycles_only_apache_after_readiness
  test_control_response_normalizes_connection_diagnostics
  test_restart_readiness_uses_log_cursor
  test_standalone_restart_waits_for_apache_instrumentation
  test_restart_fault_recovery_waits_for_apache_instrumentation
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
