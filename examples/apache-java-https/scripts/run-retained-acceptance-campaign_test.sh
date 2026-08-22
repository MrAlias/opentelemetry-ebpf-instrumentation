#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# This test intentionally sources the runner, replaces dependency seams, and
# exercises the resulting functions from subshells.
# shellcheck disable=SC1090,SC1091,SC2016,SC2030,SC2031,SC2034,SC2153,SC2317,SC2329

set -Eeuo pipefail

TEST_SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TEST_SCRIPT_DIR
TEST_REPOSITORY_ROOT="$(CDPATH='' cd -- "$TEST_SCRIPT_DIR/../../.." && pwd -P)"
readonly TEST_REPOSITORY_ROOT
readonly CAMPAIGN_RUNNER="$TEST_SCRIPT_DIR/run-retained-acceptance-campaign.sh"
readonly CAMPAIGN_WORKFLOW="$TEST_REPOSITORY_ROOT/.github/workflows/java_remote_parent_acceptance_claims.yml"
readonly TEST_REVISION='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly TEST_TREE_SHA256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
readonly TEST_WORKFLOW_SHA256='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
readonly TEST_EVIDENCE_ID='dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'

TEST_TMP_DIR=""

die() {
  printf 'run-retained-acceptance-campaign_test.sh: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local pid_file=""
  local pid=""

  if [[ -n "${TEST_TMP_DIR:-}" && -d "$TEST_TMP_DIR" && ! -L "$TEST_TMP_DIR" ]]; then
    while IFS= read -r pid_file; do
      [[ -f "$pid_file" && ! -L "$pid_file" ]] || continue
      pid="$(<"$pid_file")"
      if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
      fi
    done < <(find -- "$TEST_TMP_DIR" -name holder.pid -type f -print)
    chmod -R u+rwX -- "$TEST_TMP_DIR" >/dev/null 2>&1 || true
    rm -rf -- "$TEST_TMP_DIR"
  fi
}

trap cleanup EXIT

create_test_tmp_dir() {
  local parent="${TMPDIR:-/tmp}"
  local identity=""

  [[ "$parent" == /* && -d "$parent" && ! -L "$parent" ]] || return 1
  parent="$(CDPATH='' cd -- "$parent" && pwd -P)" || return 1
  TEST_TMP_DIR="$(mktemp -d "$parent/obi-i34-campaign-test.XXXXXX")" || return 1
  TEST_TMP_DIR="$(CDPATH='' cd -- "$TEST_TMP_DIR" && pwd -P)" || return 1
  identity="$(stat -Lc '%u:%a' -- "$TEST_TMP_DIR")" || return 1
  [[ "$identity" == "$EUID:700" ]]
}

write_environment_fixture() {
  local -r output="$1"
  local -r scenario="$2"
  local acceptance=true
  local reason=none
  local invocation='./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3'

  if [[ "$scenario" == assertion-failure ]]; then
    acceptance=false
    reason='deliberate-assertion-failure,targeted-scenario'
    invocation='./examples/apache-java-https/run.sh --transport getsockopt --scenario assertion-failure'
  fi
  {
    printf 'invocation=%s\n' "$invocation"
    printf 'revision=%s\n' "$SOURCE_REVISION"
    printf 'dirty=false\n'
    printf 'source_tree_sha256=%s\n' "$TEST_TREE_SHA256"
    printf 'source_tree_manifest_schema=git-tree-v2\n'
    printf 'tracked_patch_sha256=%064d\n' 0
    printf 'patch_identity_sha256=%064d\n' 1
    printf 'transport=getsockopt\n'
    printf 'agent_distribution=otel\n'
    printf 'tls_protocol=TLSv1.3\n'
    printf 'scenario=%s\n' "$scenario"
    printf 'request_count=0\nrepeat_count=1\nscenario_seed=1\n'
    printf 'bridge_build_mode=fresh\n'
    printf 'acceptance_evidence=%s\n' "$acceptance"
    printf 'acceptance_evidence_reason=%s\n' "$reason"
    printf 'architecture=%s\n' "$ARCHITECTURE"
  } >"$output"
  chmod 0644 -- "$output"
}

create_raw_result_fixture() {
  local -r checkout="$1"
  local -r role="$2"
  local results_root="$checkout/examples/apache-java-https/.runtime/results"
  local name='20260819T120000Z-1001'
  local scenario=all
  local result=""
  local status=passed
  local exit_status=0
  local acceptance=true
  local reason=none
  local failure_stage=none

  if [[ "$role" == assertion-failure ]]; then
    name='20260819T120001Z-1002'
    scenario=assertion-failure
    status=failed
    exit_status=2
    acceptance=false
    reason='deliberate-assertion-failure,targeted-scenario'
    failure_stage=deliberate-assertion-failure
  fi
  mkdir -p -- "$results_root"
  chmod 0755 -- "$results_root"
  if [[ ! -e "$results_root/.obi-metric-capture.lock" &&
    ! -L "$results_root/.obi-metric-capture.lock" ]]; then
    install -m 0600 /dev/null "$results_root/.obi-metric-capture.lock"
  fi
  result="$results_root/$name"
  mkdir -m 0755 -- "$result"
  write_environment_fixture "$result/environment.txt" "$scenario"
  jq -cS -n --arg schema 'obi-apache-java-https-run-status-v3' \
    --arg status "$status" --argjson exit_status "$exit_status" \
    --argjson acceptance "$acceptance" --arg reason "$reason" \
    --arg failure_stage "$failure_stage" --arg result "$result" '{
      acceptance_evidence: $acceptance,
      acceptance_evidence_reason: $reason,
      evidence_directory: $result,
      exit_status: $exit_status,
      failure_stage: $failure_stage,
      schema: $schema,
      status: $status
    }' >"$result/run-status.json"
  chmod 0644 -- "$result/run-status.json"
  printf 'private raw fixture\n' >"$result/private-fixture.txt"
  chmod 0644 -- "$result/private-fixture.txt"
  printf '%s\n' "$result"
}

create_failed_acceptance_result_fixture() {
  local -r checkout="$1"
  local -r exit_status="$2"
  local results_root="$checkout/examples/apache-java-https/.runtime/results"
  local result="$results_root/20260819T120000Z-1001"
  local index="$result/obi-metric-boundary-index.json"
  local java_terminal="$result/terminal-java-diagnostics.json"
  local obi_terminal="$result/terminal-obi-metrics.json"
  local run_status="$result/run-status.json"
  local ids_json=""
  local java_reference='phases/keepalive-after/java-diagnostics.txt'
  local java_snapshot=""
  local pair_reference='obi-metric-pairs/keepalive-pair.json'
  local pair_payload=""
  local pair_digest=""
  local index_digest=""
  local java_digest=""
  local obi_digest=""
  local status_digest=""
  local source_line=1
  local terminal_count=3
  local first_incomplete_json='"keepalive"'
  local source_line_json=1
  local counter=""
  local reason=acceptance_failed
  local all_terminal=false
  local na_prefix=false

  case "$CAMPAIGN_TEST_MUTATION" in
    acceptance-failure-source-line-zero)
      source_line=0
      source_line_json=null
      ;;
    acceptance-failure-na-prefix)
      na_prefix=true
      ;;
    acceptance-failure-all-terminal)
      all_terminal=true
      terminal_count="${#ACCEPTANCE_BOUNDARY_IDS[@]}"
      first_incomplete_json=null
      ;;
  esac
  case "$exit_status" in
    124|137) reason=acceptance_timeout ;;
    129|130|143) reason=acceptance_interrupted ;;
  esac

  mkdir -p -- "$results_root"
  chmod 0755 -- "$results_root"
  if [[ ! -e "$results_root/.obi-metric-capture.lock" &&
    ! -L "$results_root/.obi-metric-capture.lock" ]]; then
    install -m 0600 /dev/null "$results_root/.obi-metric-capture.lock"
  fi
  mkdir -m 0755 -- "$result"
  write_environment_fixture "$result/environment.txt" all
  ids_json="$(printf '%s\n' "${ACCEPTANCE_BOUNDARY_IDS[@]}" |
    jq -Rsc 'split("\n") | map(select(length > 0))')" || return 1
  for counter in "${ACCEPTANCE_JAVA_DIAGNOSTIC_COUNTER_NAMES[@]}"; do
    if [[ -n "$java_snapshot" ]]; then
      java_snapshot+=,
    fi
    java_snapshot+="$counter=0"
  done
  java_digest="$(printf '%s\n' "$java_snapshot" | sha256sum)"
  java_digest="${java_digest%% *}"
  pair_payload="$(jq -cnS '{
    schema: "test-obi-metric-pair-v1",
    before: {state: "running"},
    after: {state: "running"}
  }')" || return 1
  pair_digest="$(printf '%s\n' "$pair_payload" | sha256sum)"
  pair_digest="${pair_digest%% *}"
  jq -cS -n --argjson ids "$ids_json" \
    --arg java_reference "$java_reference" --arg java_digest "$java_digest" \
    --arg pair_reference "$pair_reference" --arg pair_digest "$pair_digest" \
    --argjson all_terminal "$all_terminal" --argjson na_prefix "$na_prefix" '{
    schema: "obi-metric-boundary-index-v1",
    selection: {
      scenario: "all",
      requested_transport: "getsockopt",
      selected_transport: "getsockopt",
      repeat_count: 1
    },
    boundaries: ($ids | to_entries | map(
      if $all_terminal and .key == 3 then {
        id: .value,
        ordinal: (.key + 1),
        state: "complete",
        captures: [{
          id: "keepalive-pair",
          kind: "pair",
          state: "captured",
          pair_reference: $pair_reference,
          pair_sha256: $pair_digest,
          java_reference: $java_reference,
          java_sha256: $java_digest
        }],
        status_references: [{
          reference: ("scenario-" + .value + "-status.json"),
          sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }],
        not_applicable_reason: null
      } elif $all_terminal then {
        id: .value,
        ordinal: (.key + 1),
        state: "complete",
        captures: [{
          id: .value,
          kind: "unavailable",
          reason: "obi_process_not_running",
          reference: ("phases/" + .value + "/obi-metrics.prom"),
          sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          state: "captured"
        }],
        status_references: [{
          reference: ("scenario-" + .value + "-status.json"),
          sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }],
        not_applicable_reason: null
      } elif $na_prefix and .key == 1 then {
        id: .value,
        ordinal: (.key + 1),
        state: "not_applicable",
        captures: [],
        status_references: [{
          reference: ("scenario-" + .value + "-status.json"),
          sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }],
        not_applicable_reason: "fixed-test-not-applicable"
      } elif .key < 3 then {
        id: .value,
        ordinal: (.key + 1),
        state: "complete",
        captures: [{
          id: .value,
          kind: "unavailable",
          reason: "obi_process_not_running",
          reference: ("phases/" + .value + "/obi-metrics.prom"),
          sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          state: "captured"
        }],
        status_references: [{
          reference: ("scenario-" + .value + "-status.json"),
          sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }],
        not_applicable_reason: null
      } elif .key == 3 then {
        id: .value,
        ordinal: (.key + 1),
        state: "active",
        captures: [{
          id: "keepalive-pair",
          kind: "pair",
          state: "captured",
          pair_reference: $pair_reference,
          pair_sha256: $pair_digest,
          java_reference: $java_reference,
          java_sha256: $java_digest
        }],
        status_references: [],
        not_applicable_reason: null
      } else {
        id: .value,
        ordinal: (.key + 1),
        state: "planned",
        captures: [],
        status_references: [],
        not_applicable_reason: null
      } end))
  }' >"$index"
  chmod 0644 -- "$index"
  index_digest="$(sha256sum <"$index")"
  index_digest="${index_digest%% *}"
  printf 'obi-metric-boundary-index-frozen-v1:%s\n' "$index_digest" \
    >"$result/.obi-metric-boundary-index.freeze"
  chmod 0600 -- "$result/.obi-metric-boundary-index.freeze"
  jq -cS -n --arg reference "$java_reference" \
    --arg snapshot "$java_snapshot" '{
      schema: "obi-java-bridge-terminal-diagnostics-v1",
      sealed: true,
      available: true,
      phase: "keepalive-after",
      reference: $reference,
      snapshot: $snapshot,
      counters: ($snapshot | split(",") |
        map(split("=") | {(.[0]): .[1]}) | add)
  }' >"$java_terminal"
  chmod 0644 -- "$java_terminal"
  if [[ "$all_terminal" == true ]]; then
    jq -cS -n --arg index_digest "$index_digest" '{
      schema: "obi-java-remote-parent-terminal-metrics-v2",
      sealed: true,
      available: false,
      reason: "no-active-boundary",
      active_boundary_id: null,
      boundary_index_reference: "obi-metric-boundary-index.json",
      boundary_index_sha256: $index_digest
    }' >"$obi_terminal"
  else
    jq -cS -n --arg index_digest "$index_digest" \
      --arg pair_reference "$pair_reference" --argjson pair "$pair_payload" '{
      schema: "obi-java-remote-parent-terminal-metrics-v2",
      sealed: true,
      available: true,
      active_boundary_id: "keepalive",
      boundary_index_reference: "obi-metric-boundary-index.json",
      boundary_index_sha256: $index_digest,
      pair_reference: $pair_reference,
      pair: $pair
    }' >"$obi_terminal"
  fi
  chmod 0644 -- "$obi_terminal"
  jq -n --arg result "$result" --argjson exit_status "$exit_status" \
    --arg index_digest "$index_digest" --argjson source_line "$source_line" \
    --slurpfile java "$java_terminal" --slurpfile obi "$obi_terminal" '{
      schema: "obi-apache-java-https-run-status-v3",
      status: "failed",
      exit_status: $exit_status,
      acceptance_evidence: true,
      acceptance_evidence_reason: "none",
      failure_stage: "scenarios",
      failure_line: $source_line,
      evidence_directory: $result,
      java_bridge_diagnostics_reference: "terminal-java-diagnostics.json",
      java_bridge_diagnostics: $java[0],
      obi_metric_evidence_reference: "terminal-obi-metrics.json",
      obi_metric_evidence: $obi[0],
      obi_metric_boundary_index_reference: "obi-metric-boundary-index.json",
      obi_metric_boundary_index_sha256: $index_digest
    }' >"$run_status"
  chmod 0644 -- "$run_status"
  java_digest="$(sha256sum <"$java_terminal")"
  java_digest="${java_digest%% *}"
  obi_digest="$(sha256sum <"$obi_terminal")"
  obi_digest="${obi_digest%% *}"
  status_digest="$(sha256sum <"$run_status")"
  status_digest="${status_digest%% *}"
  jq -cS -n --arg boundary_index_sha256 "$index_digest" --arg reason "$reason" \
    --arg terminal_java_sha256 "$java_digest" \
    --arg terminal_obi_sha256 "$obi_digest" \
    --arg run_status_sha256 "$status_digest" \
    --argjson terminal_count "$terminal_count" \
    --argjson first_incomplete "$first_incomplete_json" \
    --argjson source_line "$source_line_json" '{
      boundary_index_sha256: $boundary_index_sha256,
      failure_stage: "scenarios",
      first_incomplete_boundary: $first_incomplete,
      reason: $reason,
      run_status_sha256: $run_status_sha256,
      source_line: $source_line,
      terminal_boundary_count: $terminal_count,
      terminal_java_sha256: $terminal_java_sha256,
      terminal_obi_sha256: $terminal_obi_sha256
    }' >"$CASE_ROOT/expected-classification.json"
  chmod 0600 -- "$CASE_ROOT/expected-classification.json"
  printf '%s\n' "$result"
}

set_failed_acceptance_cleanup_stage_fixture() {
  local -r result="$1"
  local -r stage="$2"
  local run_status="$result/run-status.json"
  local expected="$CASE_ROOT/expected-classification.json"
  local candidate=""
  local status_digest=""

  [[ "$stage" == pressure-runtime-cleanup ||
    "$stage" == pressure-map-cleanup ||
    "$stage" == pressure-post-shutdown-cleanup ]] || return 1
  candidate="$result/run-status.cleanup-stage"
  jq --arg stage "$stage" '
    .failure_stage = $stage |
    .failure_line = 0
  ' "$run_status" >"$candidate" || return 1
  mv -fT -- "$candidate" "$run_status" || return 1
  chmod 0644 -- "$run_status" || return 1
  status_digest="$(sha256sum <"$run_status")" || return 1
  status_digest="${status_digest%% *}"
  [[ "$status_digest" =~ ^[0-9a-f]{64}$ ]] || return 1

  candidate="$CASE_ROOT/expected-classification.cleanup-stage"
  jq -cS --arg stage "$stage" --arg status_digest "$status_digest" '
    .failure_stage = $stage |
    .source_line = null |
    .run_status_sha256 = $status_digest
  ' "$expected" >"$candidate" || return 1
  mv -fT -- "$candidate" "$expected" || return 1
  chmod 0600 -- "$expected"
}

refresh_failed_run_status_terminals() {
  local -r result="$1"
  local run_status="$result/run-status.json"
  local candidate="$result/run-status.refresh"

  jq --slurpfile java "$result/terminal-java-diagnostics.json" \
    --slurpfile obi "$result/terminal-obi-metrics.json" '
      .java_bridge_diagnostics = $java[0] |
      .obi_metric_evidence = $obi[0]
    ' "$run_status" >"$candidate" || return 1
  mv -fT -- "$candidate" "$run_status" || return 1
  chmod 0644 -- "$run_status"
}

refresh_failed_index_bindings() {
  local -r result="$1"
  local index="$result/obi-metric-boundary-index.json"
  local obi_terminal="$result/terminal-obi-metrics.json"
  local run_status="$result/run-status.json"
  local candidate=""
  local index_digest=""

  index_digest="$(sha256sum <"$index")" || return 1
  index_digest="${index_digest%% *}"
  printf 'obi-metric-boundary-index-frozen-v1:%s\n' "$index_digest" \
    >"$result/.obi-metric-boundary-index.freeze" || return 1
  chmod 0600 -- "$result/.obi-metric-boundary-index.freeze" || return 1
  candidate="$result/terminal-obi-metrics.refresh"
  jq -cS --arg digest "$index_digest" \
    '.boundary_index_sha256 = $digest' "$obi_terminal" >"$candidate" ||
    return 1
  mv -fT -- "$candidate" "$obi_terminal" || return 1
  chmod 0644 -- "$obi_terminal" || return 1
  candidate="$result/run-status.refresh"
  jq --arg digest "$index_digest" \
    '.obi_metric_boundary_index_sha256 = $digest' "$run_status" \
    >"$candidate" || return 1
  mv -fT -- "$candidate" "$run_status" || return 1
  chmod 0644 -- "$run_status" || return 1
  refresh_failed_run_status_terminals "$result"
}

create_public_fixture() {
  local -r output="$1"
  local -r verify_mutation="$2"
  local file=""
  local evidence_id="$TEST_EVIDENCE_ID"
  local -a files=(
    README.md SANITIZATION.md acceptance-claims.json authority-summary.json
    derivation-receipt.json verify.sh SHA256SUMS
  )

  mkdir -m 0700 -- "$output"
  for file in "${files[@]}"; do
    printf 'public fixture: %s\n' "$file" >"$output/$file"
  done
  if [[ "$verify_mutation" == public-evidence-id-nonhex ]]; then
    evidence_id=not-lowercase-hex
  fi
  jq -cS -n --arg evidence_id "$evidence_id" \
    '{evidence_id:$evidence_id}' >"$output/derivation-receipt.json"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' '[[ $# == 0 ]]'
    printf '%s\n' \
      'script_source="${BASH_SOURCE[0]}"' \
      '[[ "$script_source" == /* ]]' \
      'script_path="$(readlink -f -- "$script_source")"' \
      '[[ "$script_path" == "$script_source" ]] || exit 91' \
      'script_directory="$(CDPATH= cd -P -- "$(dirname -- "$script_source")" && pwd -P)"' \
      '[[ -f "$script_directory/derivation-receipt.json" ]]'
    case "$verify_mutation" in
      public-verify-failure)
        printf '%s\n' 'exit 1'
        ;;
      public-verify-missing)
        printf '%s\n' 'exit 0'
        ;;
      public-verify-wrong)
        printf '%s\n' \
          "printf '%s\\n' 'bounded claim bundle internally consistent (not authenticated): eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'"
        ;;
      public-verify-nonhex)
        printf '%s\n' \
          "printf '%s\\n' 'bounded claim bundle internally consistent (not authenticated): NOT-LOWERCASE-HEX'"
        ;;
      public-verify-extra-line)
        printf '%s\n' \
          "printf '%s\\n' 'bounded claim bundle internally consistent (not authenticated): $TEST_EVIDENCE_ID' 'unexpected-extra-line'"
        ;;
      public-verify-suffix)
        printf '%s\n' \
          "printf '%s\\n' 'bounded claim bundle internally consistent (not authenticated): ${TEST_EVIDENCE_ID}-suffix'"
        ;;
      *)
        printf '%s\n' \
          "printf '%s\\n' 'bounded claim bundle internally consistent (not authenticated): $evidence_id'"
        ;;
    esac
  } >"$output/verify.sh"
  chmod 0444 -- "$output"/*
  chmod 0555 -- "$output"
}

write_location_aware_projector_fixture() {
  local -r scripts="$1"

  mkdir -p -- "$scripts"
  {
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -Eeuo pipefail' \
      'script_source="${BASH_SOURCE[0]}"' \
      '[[ "$script_source" == /* ]]' \
      'script_path="$(readlink -f -- "$script_source")"' \
      '[[ "$script_path" == "$script_source" ]] || exit 91' \
      'script_directory="$(CDPATH= cd -P -- "$(dirname -- "$script_source")" && pwd -P)"' \
      '[[ -x "$script_directory/verify-retained-evidence.sh" ]]' \
      '[[ $# == 5 && "$1" == --claims-v2 ]]' \
      '"$script_directory/verify-retained-evidence.sh" "$5" "$script_source" "$1"'
  } >"$scripts/project-retained-acceptance-evidence.sh"
  {
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -Eeuo pipefail' \
      '[[ $# == 3 ]]' \
      'mkdir -m 0700 -- "$1"' \
      'printf '\''%s\n'\'' "$2" >"$1/projector-source"' \
      'printf '\''%s\n'\'' "$3" >"$1/projector-selector"'
  } >"$scripts/verify-retained-evidence.sh"
  chmod 0755 -- "$scripts/project-retained-acceptance-evidence.sh" \
    "$scripts/verify-retained-evidence.sh"
}

compute_public_fixture_closure() {
  local -r output="$1"
  local file=""
  local file_identity=""
  local file_sha256=""
  local closure_sha256=""
  local -a closure_rows=()
  local -a files=(
    README.md SANITIZATION.md acceptance-claims.json authority-summary.json
    derivation-receipt.json verify.sh SHA256SUMS
  )

  for file in "${files[@]}"; do
    file_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$output/$file")" ||
      return 1
    file_sha256="$(sha256sum <"$output/$file")" || return 1
    file_sha256="${file_sha256%% *}"
    closure_rows+=("$file"$'\t'"$file_identity"$'\t'"$file_sha256")
  done
  closure_sha256="$(printf '%s\n' "${closure_rows[@]}" | sha256sum)" ||
    return 1
  printf '%s\n' "${closure_sha256%% *}"
}

extract_independent_verify_step() {
  awk '
    $0 == "      - name: Independently verify the public closure" {
      found=1
      next
    }
    found && $0 == "        run: |" {
      body=1
      next
    }
    body && /^      - name: / { exit }
    body && $0 == "" { print; next }
    body {
      if (substr($0, 1, 10) != "          ") exit 42
      print substr($0, 11)
    }
    END { if (!body) exit 43 }
  ' "$CAMPAIGN_WORKFLOW"
}

mock_authority_preflight() {
  SOURCE_REVISION="$TEST_REVISION"
  SOURCE_TREE_SHA256="$TEST_TREE_SHA256"
  WORKFLOW_BLOB_SHA256="$TEST_WORKFLOW_SHA256"
  WORKFLOW_REF='MrAlias/opentelemetry-ebpf-instrumentation/.github/workflows/java_remote_parent_acceptance_claims.yml@refs/heads/agent/java-remote-parent-bridge'
  RUN_ID=123456789
  RUN_ATTEMPT=1
  RUN_URL='https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/123456789/attempts/1'
  ARCHITECTURE=x86_64
  COMPOSE_VERSION=2.39.0
  DOCKER_VERSION=28.0.0
  GO_VERSION=1.25.11
  JAVA_VERSION=21.0.8
  OPERATING_SYSTEM=Linux
  GITHUB_OUTPUT="$CASE_ROOT/github-output"
  install -m 0600 /dev/null "$GITHUB_OUTPUT"
  assert_output_target
}

mock_assert_transaction_parent() {
  [[ "$TRANSACTION_PARENT" == "$CASE_ROOT/private" &&
    -d "$TRANSACTION_PARENT" && ! -L "$TRANSACTION_PARENT" ]]
}

mock_verify_clone_root() {
  [[ -d "$CHECKOUT_DIRECTORY" && ! -L "$CHECKOUT_DIRECTORY" &&
    "$(stat -Lc '%u:%a' -- "$CHECKOUT_DIRECTORY")" == "$EUID:700" ]] ||
    return 1
  CHECKOUT_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$CHECKOUT_DIRECTORY")"
}

mock_verify_exact_checkout() {
  assert_checkout_identity
}

mock_assert_source_authority_unchanged() {
  assert_checkout_identity
}

mock_assert_cleanup_execution_authority() {
  local run_script="$CHECKOUT_DIRECTORY/examples/apache-java-https/run.sh"
  local marker="$CASE_ROOT/cleanup-authority-mutated"
  local observed_digest=""
  local expected_digest=""

  if [[ ! -e "$marker" && ! -L "$marker" ]]; then
    case "$CAMPAIGN_TEST_MUTATION" in
      cleanup-run-sh-bytes)
        printf 'mutated cleanup bytes\n' >>"$run_script"
        : >"$marker"
        ;;
      cleanup-run-sh-symlink)
        mv -- "$run_script" "$PRIVATE_DIRECTORY/authoritative-run.sh"
        ln -s -- "$PRIVATE_DIRECTORY/authoritative-run.sh" "$run_script"
        : >"$marker"
        ;;
      cleanup-checkout-root-replacement)
        mv -- "$CHECKOUT_DIRECTORY" "$PRIVATE_DIRECTORY/source-authoritative"
        mkdir -m 0700 -- "$CHECKOUT_DIRECTORY"
        : >"$marker"
        ;;
    esac
  fi
  assert_checkout_identity || return 1
  [[ -f "$run_script" && ! -L "$run_script" &&
    "$(readlink -f -- "$run_script")" == "$run_script" &&
    "$(stat -Lc '%u:%a:%h' -- "$run_script")" == "$EUID:755:1" ]] ||
    return 1
  observed_digest="$(sha256sum <"$run_script")"
  observed_digest="${observed_digest%% *}"
  expected_digest="$(printf '%s\n' '#!/usr/bin/env bash' 'exit 0' | sha256sum)"
  expected_digest="${expected_digest%% *}"
  [[ "$observed_digest" == "$expected_digest" ]]
}

mock_assert_projection_execution_authority() {
  local projector="$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh"
  local verifier="$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/verify-retained-evidence.sh"
  local marker="$CASE_ROOT/projection-authority-mutated"

  if [[ ! -e "$marker" && ! -L "$marker" ]]; then
    case "$CAMPAIGN_TEST_MUTATION" in
      projector-bytes)
        printf 'mutated projector bytes\n' >>"$projector"
        : >"$marker"
        ;;
      projector-symlink)
        mv -- "$projector" "$PRIVATE_DIRECTORY/authoritative-projector.sh"
        ln -s -- "$PRIVATE_DIRECTORY/authoritative-projector.sh" "$projector"
        : >"$marker"
        ;;
      verifier-bytes)
        printf 'mutated verifier bytes\n' >>"$verifier"
        : >"$marker"
        ;;
      verifier-symlink)
        mv -- "$verifier" "$PRIVATE_DIRECTORY/authoritative-verifier.sh"
        ln -s -- "$PRIVATE_DIRECTORY/authoritative-verifier.sh" "$verifier"
        : >"$marker"
        ;;
    esac
  fi
  assert_checkout_identity || return 1
  [[ -f "$projector" && ! -L "$projector" &&
    "$(readlink -f -- "$projector")" == "$projector" &&
    "$(stat -Lc '%u:%a:%h' -- "$projector")" == "$EUID:755:1" &&
    -f "$verifier" && ! -L "$verifier" &&
    "$(readlink -f -- "$verifier")" == "$verifier" &&
    "$(stat -Lc '%u:%a:%h' -- "$verifier")" == "$EUID:755:1" ]] ||
    return 1
  cmp -s -- "$projector" \
    <(printf '%s\n' '#!/usr/bin/env bash' 'exit 0') || return 1
  cmp -s -- "$verifier" \
    <(printf '%s\n' '#!/usr/bin/env bash' 'exit 0') || return 1
  assert_checkout_identity
}

mock_private_destroy_checkpoint() {
  local -r phase="$1"
  local marker="$CASE_ROOT/private-destroy-renamed"

  if [[ "$CAMPAIGN_TEST_MUTATION" == private-destroy-rename &&
    "$phase" == before-delete && ! -e "$marker" && ! -L "$marker" ]]; then
    mv -- "$PRIVATE_DIRECTORY" "$CASE_ROOT/renamed-private"
    : >"$marker"
  fi
}

mock_public_closure_checkpoint() {
  local -r phase="$1"
  local marker="$CASE_ROOT/public-directory-replaced"

  if [[ "$CAMPAIGN_TEST_MUTATION" == output-directory-replacement &&
    "$phase" == after-project-closure && ! -e "$marker" && ! -L "$marker" ]]; then
    mv -- "$OUTPUT_DIRECTORY" "$CASE_ROOT/original-public-output"
    create_public_fixture "$OUTPUT_DIRECTORY" none
    : >"$marker"
  fi
}

mock_result_snapshot_checkpoint() {
  local -r phase="$1"
  local -r results_root="$2"
  local marker="$CASE_ROOT/results-root-pre-find-replaced"

  if [[ "$CAMPAIGN_TEST_MUTATION" == results-root-pre-find-replacement &&
    "$phase" == before-find && ! -e "$marker" && ! -L "$marker" ]]; then
    mv -- "$results_root" "$PRIVATE_DIRECTORY/original-results-root"
    cp -a -- "$PRIVATE_DIRECTORY/original-results-root" "$results_root"
    : >"$marker"
  fi
}

mock_failure_classification_checkpoint() {
  local -r phase="$1"
  local -r path="${2:-}"
  local marker="$CASE_ROOT/failure-classification-race"
  local original=""
  local mutated=""
  local results_root=""
  local fd_count=""
  local fd_flags=""
  local fd_access_mode=""
  local -a observed_fds=()

  case "$phase:$CAMPAIGN_TEST_MUTATION" in
    after-snapshot-seal:*)
      fd_flags="$(awk '$1 == "flags:" { print $2 }' "/proc/$BASHPID/fdinfo/${5}")"
      [[ "$fd_flags" =~ ^[0-7]+$ ]] || return 1
      fd_access_mode="$((8#$fd_flags & 3))"
      printf '%s\t%s\t%s\n' "${path##*/}" "$(stat -Lc '%a' -- "${4}")" \
        "$fd_access_mode" \
        >>"$CASE_ROOT/classifier-snapshot-seals"
      ;;
    after-input-snapshot:acceptance-failure-race)
      if [[ "${path##*/}" == run-status.json &&
        ! -e "$marker" && ! -L "$marker" ]]; then
        mv -- "$path" "$CASE_ROOT/original-run-status.json"
        cp -- "$CASE_ROOT/original-run-status.json" "$path"
        chmod 0644 -- "$path"
        : >"$marker"
      fi
      ;;
    after-input-snapshot:acceptance-failure-same-inode-aba)
      marker="$CASE_ROOT/failure-classification-same-inode-aba"
      if [[ "${path##*/}" == run-status.json &&
        ! -e "$marker" && ! -L "$marker" ]]; then
        original="$(<"$path")"
        mutated="${original//\"scenarios\"/\"readiness\"}"
        [[ "${#mutated}" == "${#original}" && "$mutated" != "$original" ]] ||
          return 1
        printf '%s\n' "$mutated" >"$path"
        printf '%s\n' "$original" >"$path"
        chmod 0644 -- "$path"
        : >"$marker"
      fi
      ;;
    after-result-open:acceptance-failure-result-parent-replacement)
      marker="$CASE_ROOT/failure-classification-parent-replaced"
      if [[ ! -e "$marker" && ! -L "$marker" ]]; then
        results_root="${path%/*}"
        mv -- "$results_root" "$PRIVATE_DIRECTORY/original-results-root"
        cp -a -- "$PRIVATE_DIRECTORY/original-results-root" "$results_root"
        : >"$marker"
      fi
      ;;
    before-classification-validation:*)
      observed_fds=("/proc/$BASHPID/fd/"*)
      fd_count="${#observed_fds[@]}"
      printf '%s\n' "$fd_count" >"$CASE_ROOT/classifier-fd-count-before"
      ;;
    after-classification-validation:*)
      observed_fds=("/proc/$BASHPID/fd/"*)
      fd_count="${#observed_fds[@]}"
      printf '%s\n' "$fd_count" >"$CASE_ROOT/classifier-fd-count-after"
      ;;
  esac
}

mock_failure_classification_path_is_mountpoint() {
  local -r path="$1"

  if [[ "$CAMPAIGN_TEST_MUTATION" == acceptance-failure-result-mountpoint &&
    "${path##*/}" == 20260819T120000Z-1001 ]]; then
    : >"$CASE_ROOT/failure-classification-mountpoint"
    return 0
  fi
  if [[ "$CAMPAIGN_TEST_MUTATION" == \
      acceptance-failure-child-mountpoint &&
    "${path##*/}" == terminal-java-diagnostics.json ]]; then
    : >"$CASE_ROOT/failure-classification-child-mountpoint"
    return 0
  fi
  failure_classification_mountinfo_path_is_mountpoint "$path"
}

mock_failure_classification_fd_mount_id() {
  local -r descriptor="$1"
  local -r output_name="$2"
  local observed_mount_id=""
  local descriptor_target=""

  failure_classification_fdinfo_mount_id "$descriptor" observed_mount_id ||
    return 1
  descriptor_target="$(readlink -- "/proc/$BASHPID/fd/$descriptor")" ||
    return 1
  if [[ "$CAMPAIGN_TEST_MUTATION" == \
      acceptance-failure-child-bind-mount &&
    "${descriptor_target##*/}" == terminal-java-diagnostics.json ]]; then
    # A bind-mounted regular file can retain its device/inode while acquiring
    # a different mount ID.  Model only that kernel-observable distinction.
    observed_mount_id="9$observed_mount_id"
    : >"$CASE_ROOT/failure-classification-child-bind-mount"
  fi
  printf -v "$output_name" '%s' "$observed_mount_id"
}

mock_receipt_preopen_checkpoint() {
  local -r receipt="$1"
  local sentinel="$CASE_ROOT/receipt-preopen-sentinel"

  case "$CAMPAIGN_TEST_MUTATION" in
    receipt-preopen-symlink|receipt-preopen-hardlink)
      printf 'receipt sentinel content\n' >"$sentinel"
      chmod 0600 -- "$sentinel"
      if [[ "$CAMPAIGN_TEST_MUTATION" == receipt-preopen-symlink ]]; then
        ln -s -- "$sentinel" "$receipt"
      else
        ln -- "$sentinel" "$receipt"
      fi
      ;;
  esac
}

mock_assert_exact_command() {
  local -r command_id="$1"
  shift
  local index=0
  local -a actual=("$@")
  local -a expected_argv=()

  case "$command_id" in
    clone)
      expected_argv=(git clone --no-checkout --no-tags -- "$REPOSITORY_URL"
        "$CHECKOUT_DIRECTORY")
      ;;
    checkout-exact-revision)
      expected_argv=(git -C "$CHECKOUT_DIRECTORY" checkout --detach
        "$SOURCE_REVISION")
      ;;
    clean-status-before|clean-status-after-validation|clean-status-final)
      expected_argv=(git status --porcelain)
      ;;
    certificate-generation)
      expected_argv=(./examples/apache-java-https/certs/generate_test.sh)
      ;;
    run-test)
      expected_argv=(./examples/apache-java-https/scripts/run_test.sh)
      ;;
    tracecheck-tests)
      expected_argv=(go test ./examples/apache-java-https/tracecheck/...)
      ;;
    compose-config)
      expected_argv=(docker compose --project-name obi-apache-java-https --file
        examples/apache-java-https/docker-compose.yml config --quiet)
      ;;
    acceptance-all-otel-getsockopt-tls13)
      expected_argv=(./examples/apache-java-https/run.sh --transport getsockopt
        --agent otel --tls TLSv1.3)
      ;;
    assertion-failure-exit-2)
      expected_argv=(./examples/apache-java-https/run.sh --transport getsockopt
        --scenario assertion-failure)
      ;;
    scoped-cleanup|emergency-scoped-cleanup)
      expected_argv=(./examples/apache-java-https/run.sh --cleanup-only)
      ;;
    *) return 1 ;;
  esac
  (( ${#actual[@]} == ${#expected_argv[@]} )) || return 1
  for ((index = 0; index < ${#expected_argv[@]}; index += 1)); do
    [[ "${actual[$index]}" == "${expected_argv[$index]}" ]] || return 1
  done
}

mock_campaign_execute() {
  local -r command_id="$1"
  shift
  local results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local acceptance_result=""
  local replacement=""
  local holder_pid=""
  local failure_exit_status=7
  local candidate=""

  mock_assert_exact_command "$command_id" "$@" || return 96
  case "$command_id" in
    clone)
      mkdir -m 0700 -- "$CHECKOUT_DIRECTORY"
      mkdir -p -- "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts"
      printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
        >"$CHECKOUT_DIRECTORY/examples/apache-java-https/run.sh"
      chmod 0755 -- "$CHECKOUT_DIRECTORY/examples/apache-java-https/run.sh"
      printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
        >"$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh"
      printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
        >"$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/verify-retained-evidence.sh"
      chmod 0755 -- \
        "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh" \
        "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/verify-retained-evidence.sh"
      printf 'clone-output\n'
      ;;
    checkout-exact-revision|certificate-generation|run-test|tracecheck-tests|compose-config)
      printf '%s-output\n' "$command_id"
      ;;
    clean-status-before|clean-status-final)
      ;;
    clean-status-after-validation)
      if [[ "$CAMPAIGN_TEST_MUTATION" == stable-preexisting-lock ]]; then
        mkdir -p -- "$results_root"
        chmod 0755 -- "$results_root"
        install -m 0600 /dev/null \
          "$results_root/.obi-metric-capture.lock"
      fi
      ;;
    acceptance-all-otel-getsockopt-tls13)
      if [[ "$CAMPAIGN_TEST_MUTATION" == acceptance-failure-* ]]; then
        case "$CAMPAIGN_TEST_MUTATION" in
          acceptance-failure-timeout) failure_exit_status=124 ;;
          acceptance-failure-interrupted) failure_exit_status=130 ;;
        esac
        acceptance_result="$(create_failed_acceptance_result_fixture \
          "$CHECKOUT_DIRECTORY" "$failure_exit_status")" || return 98
        case "$CAMPAIGN_TEST_MUTATION" in
          acceptance-failure-valid|acceptance-failure-race|\
          acceptance-failure-same-inode-aba|acceptance-failure-timeout|\
          acceptance-failure-interrupted|acceptance-failure-source-line-zero|\
          acceptance-failure-na-prefix|acceptance-failure-all-terminal|\
          acceptance-failure-result-parent-replacement|\
          acceptance-failure-result-mountpoint|\
          acceptance-failure-child-mountpoint|\
          acceptance-failure-child-bind-mount) ;;
          acceptance-failure-pressure-runtime-cleanup)
            set_failed_acceptance_cleanup_stage_fixture \
              "$acceptance_result" pressure-runtime-cleanup || return 98
            ;;
          acceptance-failure-pressure-map-cleanup)
            set_failed_acceptance_cleanup_stage_fixture \
              "$acceptance_result" pressure-map-cleanup || return 98
            ;;
          acceptance-failure-pressure-post-shutdown-cleanup)
            set_failed_acceptance_cleanup_stage_fixture \
              "$acceptance_result" pressure-post-shutdown-cleanup || return 98
            ;;
          acceptance-failure-malformed)
            printf '%s\n' '{malformed-private-status' \
              >"$acceptance_result/run-status.json"
            ;;
          acceptance-failure-duplicate-key)
            candidate="$acceptance_result/run-status.tmp"
            sed '2i\  "failure_stage": "failure-classifier-secret-canary",' \
              "$acceptance_result/run-status.json" >"$candidate"
            mv -fT -- "$candidate" "$acceptance_result/run-status.json"
            chmod 0644 -- "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-multiple)
            cp -a -- "$acceptance_result" \
              "$results_root/20260819T120002Z-1003"
            ;;
          acceptance-failure-symlink)
            mv -- "$acceptance_result/run-status.json" \
              "$CASE_ROOT/private-run-status-target.json"
            ln -s -- "$CASE_ROOT/private-run-status-target.json" \
              "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-hardlink)
            ln -- "$acceptance_result/run-status.json" \
              "$CASE_ROOT/private-run-status-hardlink.json"
            ;;
          acceptance-failure-extra-key)
            jq '.private_extra_key="failure-classifier-secret-canary"' \
              "$acceptance_result/run-status.json" \
              >"$acceptance_result/run-status.tmp"
            mv -- "$acceptance_result/run-status.tmp" \
              "$acceptance_result/run-status.json"
            chmod 0644 -- "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-stage)
            jq '.failure_stage="private/unallowlisted/stage"' \
              "$acceptance_result/run-status.json" \
              >"$acceptance_result/run-status.tmp"
            mv -- "$acceptance_result/run-status.tmp" \
              "$acceptance_result/run-status.json"
            chmod 0644 -- "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-reason)
            jq '.acceptance_evidence_reason="private-unallowlisted-reason"' \
              "$acceptance_result/run-status.json" \
              >"$acceptance_result/run-status.tmp"
            mv -- "$acceptance_result/run-status.tmp" \
              "$acceptance_result/run-status.json"
            chmod 0644 -- "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-environment)
            sed -i 's/^scenario=all$/scenario=security/' \
              "$acceptance_result/environment.txt"
            ;;
          acceptance-failure-exit-crosslink)
            candidate="$acceptance_result/run-status.tmp"
            jq '.exit_status=8' "$acceptance_result/run-status.json" \
              >"$candidate"
            mv -fT -- "$candidate" "$acceptance_result/run-status.json"
            chmod 0644 -- "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-source-line-bound)
            candidate="$acceptance_result/run-status.tmp"
            jq '.failure_line=3' "$acceptance_result/run-status.json" \
              >"$candidate"
            mv -fT -- "$candidate" "$acceptance_result/run-status.json"
            chmod 0644 -- "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-hash-crosslink)
            candidate="$acceptance_result/run-status.tmp"
            jq '.obi_metric_boundary_index_sha256 =
              "abababababababababababababababababababababababababababababababab"' \
              "$acceptance_result/run-status.json" >"$candidate"
            mv -fT -- "$candidate" "$acceptance_result/run-status.json"
            chmod 0644 -- "$acceptance_result/run-status.json"
            ;;
          acceptance-failure-input-size)
            truncate -s "$((MAX_ENVIRONMENT_BYTES + 1))" \
              "$acceptance_result/environment.txt"
            ;;
          acceptance-failure-input-mode)
            chmod 0600 -- "$acceptance_result/environment.txt"
            ;;
          acceptance-failure-active-boundary)
            candidate="$acceptance_result/terminal-obi-metrics.tmp"
            jq -cS '.active_boundary_id="security"' \
              "$acceptance_result/terminal-obi-metrics.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/terminal-obi-metrics.json"
            chmod 0644 -- "$acceptance_result/terminal-obi-metrics.json"
            refresh_failed_run_status_terminals "$acceptance_result"
            ;;
          acceptance-failure-pair-reference)
            candidate="$acceptance_result/terminal-obi-metrics.tmp"
            jq -cS '.pair_reference="obi-metric-pairs/other.json"' \
              "$acceptance_result/terminal-obi-metrics.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/terminal-obi-metrics.json"
            chmod 0644 -- "$acceptance_result/terminal-obi-metrics.json"
            refresh_failed_run_status_terminals "$acceptance_result"
            ;;
          acceptance-failure-pair-digest)
            candidate="$acceptance_result/obi-metric-boundary-index.tmp"
            jq -cS '(.boundaries[] | select(.id == "keepalive") |
              .captures[] | select(.kind == "pair") |
              .pair_sha256) =
              "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"' \
              "$acceptance_result/obi-metric-boundary-index.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/obi-metric-boundary-index.json"
            chmod 0644 -- \
              "$acceptance_result/obi-metric-boundary-index.json"
            refresh_failed_index_bindings "$acceptance_result"
            ;;
          acceptance-failure-java-reference)
            candidate="$acceptance_result/terminal-java-diagnostics.tmp"
            jq -cS '.reference="phases/other/java-diagnostics.txt" |
              .phase="other"' \
              "$acceptance_result/terminal-java-diagnostics.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/terminal-java-diagnostics.json"
            chmod 0644 -- "$acceptance_result/terminal-java-diagnostics.json"
            refresh_failed_run_status_terminals "$acceptance_result"
            ;;
          acceptance-failure-java-counters)
            candidate="$acceptance_result/terminal-java-diagnostics.tmp"
            jq -cS '.counters.cfg_on="1"' \
              "$acceptance_result/terminal-java-diagnostics.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/terminal-java-diagnostics.json"
            chmod 0644 -- "$acceptance_result/terminal-java-diagnostics.json"
            refresh_failed_run_status_terminals "$acceptance_result"
            ;;
          acceptance-failure-java-snapshot-nul)
            candidate="$acceptance_result/terminal-java-diagnostics.tmp"
            jq -cS '.snapshot += "\u0000"' \
              "$acceptance_result/terminal-java-diagnostics.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/terminal-java-diagnostics.json"
            chmod 0644 -- "$acceptance_result/terminal-java-diagnostics.json"
            grep -Fq '\u0000' \
              "$acceptance_result/terminal-java-diagnostics.json" || return 1
            : >"$CASE_ROOT/failure-classification-java-snapshot-nul"
            refresh_failed_run_status_terminals "$acceptance_result"
            ;;
          acceptance-failure-java-digest)
            candidate="$acceptance_result/obi-metric-boundary-index.tmp"
            jq -cS '(.boundaries[] | select(.id == "keepalive") |
              .captures[] | select(.kind == "pair") |
              .java_sha256) =
              "dededededededededededededededededededededededededededededededede"' \
              "$acceptance_result/obi-metric-boundary-index.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/obi-metric-boundary-index.json"
            chmod 0644 -- \
              "$acceptance_result/obi-metric-boundary-index.json"
            refresh_failed_index_bindings "$acceptance_result"
            ;;
          acceptance-failure-terminal-index-hash)
            candidate="$acceptance_result/terminal-obi-metrics.tmp"
            jq -cS '.boundary_index_sha256 =
              "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"' \
              "$acceptance_result/terminal-obi-metrics.json" >"$candidate"
            mv -fT -- "$candidate" \
              "$acceptance_result/terminal-obi-metrics.json"
            chmod 0644 -- "$acceptance_result/terminal-obi-metrics.json"
            refresh_failed_run_status_terminals "$acceptance_result"
            ;;
          *) return 99 ;;
        esac
        printf '%s\n' \
          'failure-classifier-secret-canary path=/private/raw pid=4242 id=raw-id timestamp=2026-08-19T12:00:00Z'
        return "$failure_exit_status"
      fi
      if [[ "$CAMPAIGN_TEST_MUTATION" != missing-result ]]; then
        create_raw_result_fixture "$CHECKOUT_DIRECTORY" acceptance >/dev/null
      else
        mkdir -p -- "$results_root"
        chmod 0755 -- "$results_root"
        install -m 0600 /dev/null "$results_root/.obi-metric-capture.lock"
      fi
      case "$CAMPAIGN_TEST_MUTATION" in
        two-results)
          mkdir -m 0755 -- "$results_root/20260819T120002Z-1003"
          ;;
        wrong-result-mode)
          chmod 0700 -- "$results_root/20260819T120000Z-1001"
          ;;
        wrong-lock-mode)
          chmod 0644 -- "$results_root/.obi-metric-capture.lock"
          ;;
        lock-hardlink)
          ln -- "$results_root/.obi-metric-capture.lock" \
            "$CASE_ROOT/lock-hardlink"
          ;;
        lock-symlink)
          mv -- "$results_root/.obi-metric-capture.lock" \
            "$CASE_ROOT/lock-symlink-target"
          ln -s -- "$CASE_ROOT/lock-symlink-target" \
            "$results_root/.obi-metric-capture.lock"
          ;;
        unrelated-addition)
          printf 'unexpected\n' >"$results_root/unrelated"
          ;;
        before-snapshot-rewrite)
          chmod 0600 -- "$PRIVATE_DIRECTORY/results-before-acceptance"
          printf 'forged snapshot bytes\n' \
            >"$PRIVATE_DIRECTORY/results-before-acceptance"
          chmod 0400 -- "$PRIVATE_DIRECTORY/results-before-acceptance"
          ;;
        before-snapshot-mode)
          chmod 0600 -- "$PRIVATE_DIRECTORY/results-before-acceptance"
          ;;
        before-snapshot-replacement)
          mv -- "$PRIVATE_DIRECTORY/results-before-acceptance" \
            "$PRIVATE_DIRECTORY/original-results-before-acceptance"
          printf 'forged snapshot bytes\n' \
            >"$PRIVATE_DIRECTORY/results-before-acceptance"
          chmod 0400 -- "$PRIVATE_DIRECTORY/results-before-acceptance"
          ;;
      esac
      printf 'acceptance-output\n'
      ;;
    assertion-failure-exit-2)
      case "$CAMPAIGN_TEST_MUTATION" in
        lock-replacement)
          mv -- "$results_root/.obi-metric-capture.lock" \
            "$CASE_ROOT/replaced-lock"
          ;;
        root-replacement)
          replacement="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results-old"
          mv -- "$results_root" "$replacement"
          mkdir -m 0755 -- "$results_root"
          mv -- "$replacement/.obi-metric-capture.lock" "$results_root/"
          acceptance_result="$replacement/20260819T120000Z-1001"
          mv -- "$acceptance_result" "$results_root/"
          rmdir -- "$replacement"
          ;;
        root-disappearance)
          rm -rf -- "$results_root"
          printf 'assertion-output\n'
          return 2
          ;;
        acceptance-result-replacement)
          acceptance_result="$results_root/20260819T120000Z-1001"
          mv -- "$acceptance_result" "$CASE_ROOT/replaced-acceptance"
          cp -a -- "$CASE_ROOT/replaced-acceptance" "$acceptance_result"
          ;;
      esac
      create_raw_result_fixture "$CHECKOUT_DIRECTORY" assertion-failure >/dev/null
      if [[ "$CAMPAIGN_TEST_MUTATION" == lock-removal ]]; then
        rm -- "$results_root/.obi-metric-capture.lock"
      fi
      printf 'assertion-output\n'
      if [[ "$CAMPAIGN_TEST_MUTATION" == assertion-wrong-exit ]]; then
        return 0
      fi
      return 2
      ;;
    scoped-cleanup)
      printf 'cleanup-output\n'
      if [[ "$CAMPAIGN_TEST_MUTATION" == cleanup-failure ]]; then
        return 9
      fi
      ;;
    emergency-scoped-cleanup)
      : >"$CASE_ROOT/emergency-invoked"
      printf 'emergency-cleanup-output\n'
      ;;
    *)
      printf 'unexpected command id: %s\n' "$command_id" >&2
      return 97
      ;;
  esac
  if [[ "$CAMPAIGN_TEST_MUTATION" == command-row-forgery &&
    "$command_id" == compose-config ]]; then
    jq -cS -n '{duration_seconds:999,exit_status:0,id:"clone",
      output_sha256:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      status:"passed"}' >"$PRIVATE_DIRECTORY/command-rows.jsonl"
    chmod 0600 -- "$PRIVATE_DIRECTORY/command-rows.jsonl"
    chmod 0600 -- "$COMMAND_DIRECTORY/02-clean-status-before.log"
    printf 'forged nonempty clean status\n' \
      >"$COMMAND_DIRECTORY/02-clean-status-before.log"
    chmod 0400 -- "$COMMAND_DIRECTORY/02-clean-status-before.log"
  fi
  if [[ "$CAMPAIGN_TEST_MUTATION" == cleanup-hardlink-sentinel &&
    "$command_id" == compose-config ]]; then
    printf 'external sentinel content\n' >"$CASE_ROOT/external-sentinel"
    chmod 0400 -- "$CASE_ROOT/external-sentinel"
    ln -- "$CASE_ROOT/external-sentinel" \
      "$PRIVATE_DIRECTORY/external-sentinel-hardlink"
  fi
  if [[ "$CAMPAIGN_TEST_MUTATION" == held-lock &&
    "$command_id" == acceptance-all-otel-getsockopt-tls13 ]]; then
    (
      local held_fd=""
      exec {held_fd}>"$results_root/.obi-metric-capture.lock"
      flock -n "$held_fd"
      : >"$CASE_ROOT/holder.ready"
      sleep 300
    ) &
    holder_pid=$!
    printf '%s\n' "$holder_pid" >"$CASE_ROOT/holder.pid"
    for _ in {1..100}; do
      [[ -f "$CASE_ROOT/holder.ready" ]] && break
      sleep 0.01
    done
    [[ -f "$CASE_ROOT/holder.ready" ]] || return 1
  fi
}

mock_projector_execute() {
  local -r projector="$1"
  local -r selector="$2"
  local -r acceptance="$3"
  local -r assertion_result="$4"
  local -r receipt="$5"
  local -r output="$6"
  local receipt_text=""
  local mutant=""
  local receipt_mutation=""

  [[ -f "$projector" &&
    "$(readlink -f -- "$projector")" == \
      "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh" &&
    "$selector" == --claims-v2 &&
    "$acceptance" == "$RAW_ACCEPTANCE" &&
    "$assertion_result" == "$RAW_ASSERTION" &&
    "$receipt" == "$RECEIPT" && "$output" == "$OUTPUT_DIRECTORY" ]] || return 1
  : >"$CASE_ROOT/projector-invoked"
  printf '%s\n' "$selector" >"$CASE_ROOT/projector-selector"
  assert_receipt_unchanged || return 1
  validate_receipt "$receipt" || return 1
  [[ "$(stat -Lc '%u:%a:%h' -- "$receipt")" == "$EUID:600:1" ]] ||
    return 1
  receipt_text="$(<"$receipt")"
  for receipt_mutation in mode-0400 mode-0644 mode-0755 pretty reordered \
    concatenated missing-lf; do
    mutant="$CASE_ROOT/receipt-$receipt_mutation.json"
    case "$receipt_mutation" in
      mode-0400)
        cp -- "$receipt" "$mutant"
        chmod 0400 -- "$mutant"
        ;;
      mode-0644)
        cp -- "$receipt" "$mutant"
        chmod 0644 -- "$mutant"
        ;;
      mode-0755)
        cp -- "$receipt" "$mutant"
        chmod 0755 -- "$mutant"
        ;;
      pretty)
        jq . "$receipt" >"$mutant"
        chmod 0600 -- "$mutant"
        ;;
      reordered)
        jq -c '{schema,commands,environment,execution_locator,output_contract,
          source_revision,source_tree_sha256}' "$receipt" >"$mutant"
        chmod 0600 -- "$mutant"
        ;;
      concatenated)
        printf '%s\n%s\n' "$receipt_text" "$receipt_text" >"$mutant"
        chmod 0600 -- "$mutant"
        ;;
      missing-lf)
        printf '%s' "$receipt_text" >"$mutant"
        chmod 0600 -- "$mutant"
        ;;
    esac
    if validate_receipt "$mutant" >/dev/null 2>&1; then
      return 1
    fi
  done
  assert_receipt_unchanged || return 1
  cp -- "$receipt" "$CASE_ROOT/observed-receipt.json" || return 1
  chmod 0600 -- "$CASE_ROOT/observed-receipt.json" || return 1
  if [[ "$CAMPAIGN_TEST_MUTATION" == projector-failure ]]; then
    return 1
  fi
  [[ ! -e "$output" && ! -L "$output" ]] || return 1
  create_public_fixture "$output" "$CAMPAIGN_TEST_MUTATION"
  if [[ "$CAMPAIGN_TEST_MUTATION" == public-extra-file ]]; then
    chmod 0755 -- "$output"
    printf 'not allowlisted\n' >"$output/raw-evidence.json"
    chmod 0444 -- "$output/raw-evidence.json"
    chmod 0555 -- "$output"
  fi
  if [[ "$CAMPAIGN_TEST_MUTATION" == output-parent-replacement ]]; then
    mv -- "$OUTPUT_PARENT" "$CASE_ROOT/original-public-parent"
    mkdir -m 0700 -- "$OUTPUT_PARENT"
    create_public_fixture "$OUTPUT_DIRECTORY" none
    : >"$CASE_ROOT/public-parent-replaced"
  fi
}

run_mock_campaign_case() {
  local -r name="$1"
  local -r mutation="$2"
  local -r expected_status="$3"
  local case_root="$TEST_TMP_DIR/$name"
  local output_parent="$case_root/public-parent"
  local output="$output_parent/test-claims"
  local stdout_log="$case_root/stdout.log"
  local stderr_log="$case_root/stderr.log"
  local status=0
  local private_entry=""

  mkdir -m 0700 -- "$case_root" "$output_parent" "$case_root/private"
  set +e
  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    CASE_ROOT="$case_root"
    CAMPAIGN_TEST_MUTATION="$mutation"
    TRANSACTION_PARENT="$case_root/private"
    authority_preflight() { mock_authority_preflight; }
    assert_transaction_parent() { mock_assert_transaction_parent; }
    campaign_execute() { mock_campaign_execute "$@"; }
    verify_clone_root() { mock_verify_clone_root; }
    verify_exact_checkout() { mock_verify_exact_checkout; }
    assert_source_authority_unchanged() { mock_assert_source_authority_unchanged; }
    assert_cleanup_execution_authority() {
      mock_assert_cleanup_execution_authority
    }
    assert_projection_execution_authority() {
      mock_assert_projection_execution_authority
    }
    projection_blob_sha256() {
      printf '%s\n' '#!/usr/bin/env bash' 'exit 0' | sha256sum | awk '{print $1}'
    }
    projector_execute() { mock_projector_execute "$@"; }
    private_destroy_checkpoint() { mock_private_destroy_checkpoint "$@"; }
    public_closure_checkpoint() { mock_public_closure_checkpoint "$@"; }
    result_snapshot_checkpoint() { mock_result_snapshot_checkpoint "$@"; }
    failure_classification_checkpoint() {
      mock_failure_classification_checkpoint "$@"
    }
    failure_classification_path_is_mountpoint() {
      mock_failure_classification_path_is_mountpoint "$@"
    }
    failure_classification_fd_mount_id() {
      mock_failure_classification_fd_mount_id "$@"
    }
    receipt_preopen_checkpoint() { mock_receipt_preopen_checkpoint "$@"; }
    campaign_entry "$output"
  ) >"$stdout_log" 2>"$stderr_log"
  status=$?
  set -e
  if [[ "$expected_status" == success ]]; then
    [[ "$status" == 0 ]] || {
      tail -240 -- "$stderr_log" >&2
      die "$name failed with status $status"
    }
  else
    (( status != 0 )) || die "$name unexpectedly passed"
  fi
  private_entry="$(find -- "$case_root/private" -mindepth 1 -print -quit)"
  [[ -z "$private_entry" ]] || die "$name retained private transaction state"
  if [[ -f "$case_root/holder.pid" ]]; then
    kill "$(<"$case_root/holder.pid")" >/dev/null 2>&1 || true
  fi
  printf '%s\n' "$case_root"
}

assert_success_state_machine() {
  local -r stderr_log="$1"
  local expected=""
  local observed=""

  expected="$(printf '%s\n' \
    AUTHORITY_PREFLIGHT PRIVATE_TXN CLONE EXACT_CHECKOUT CLEAN_BEFORE CERTS \
    RUN_TEST TRACECHECK COMPOSE_CONFIG CLEAN_AFTER_VALIDATION ACCEPTANCE \
    ASSERTION_CONTROL SCOPED_CLEANUP FINAL_CLEAN RECEIPT_SEAL PROJECT \
    PRIVATE_DESTROY PUBLIC_REVERIFY SUCCESS)"
  observed="$(awk '$2 == "STATE" { print $3 }' "$stderr_log")"
  [[ "$observed" == "$expected" ]] || die 'success state sequence is not exact'
}

assert_success_handoff() {
  local -r case_root="$1"
  local output_parent="$case_root/public-parent"
  local output="$output_parent/test-claims"
  local handoff="$case_root/github-output"
  local parent_identity=""
  local directory_identity=""
  local closure_sha256=""
  local evidence_id=""
  local key=""
  local value=""
  local file=""
  local file_identity=""
  local file_sha256=""
  local computed_closure=""
  local -a closure_rows=()
  local -a files=(
    README.md SANITIZATION.md acceptance-claims.json authority-summary.json
    derivation-receipt.json verify.sh SHA256SUMS
  )

  [[ -f "$handoff" && ! -L "$handoff" &&
    "$(wc -l <"$handoff")" == 4 ]] || die 'workflow handoff is not exact'
  while IFS='=' read -r key value; do
    case "$key" in
      public_parent_identity) parent_identity="$value" ;;
      public_directory_identity) directory_identity="$value" ;;
      public_closure_sha256) closure_sha256="$value" ;;
      public_evidence_id) evidence_id="$value" ;;
      *) die "unexpected workflow handoff key: $key" ;;
    esac
  done <"$handoff"
  [[ "$parent_identity" == "$(stat -Lc '%d:%i:%u:%a' -- "$output_parent")" &&
    "$directory_identity" == "$(stat -Lc '%d:%i:%u:%a' -- "$output")" &&
    "$closure_sha256" =~ ^[0-9a-f]{64}$ &&
    "$evidence_id" == "$TEST_EVIDENCE_ID" ]] ||
    die 'workflow handoff identity is not bound to the public closure'
  for file in "${files[@]}"; do
    file_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$output/$file")"
    file_sha256="$(sha256sum <"$output/$file")"
    file_sha256="${file_sha256%% *}"
    closure_rows+=("$file"$'\t'"$file_identity"$'\t'"$file_sha256")
  done
  computed_closure="$(printf '%s\n' "${closure_rows[@]}" | sha256sum)"
  computed_closure="${computed_closure%% *}"
  [[ "$computed_closure" == "$closure_sha256" ]] ||
    die 'workflow handoff closure digest does not match exact public bytes'
}

assert_observed_receipt() {
  local -r receipt="$1"
  local empty_sha=""
  local clone_sha=""
  local mutated="$receipt.mutated"

  empty_sha="$(sha256sum </dev/null)"
  empty_sha="${empty_sha%% *}"
  clone_sha="$(printf 'clone-output\n' | sha256sum)"
  clone_sha="${clone_sha%% *}"
  [[ "$(stat -Lc '%u:%a:%h' -- "$receipt")" == "$EUID:600:1" ]] ||
    die 'observed receipt metadata is not the frozen private contract'
  cmp -s -- "$receipt" <(jq -cS . "$receipt") ||
    die 'observed receipt is not one canonical line with terminal LF'
  jq -e --arg empty_sha "$empty_sha" --arg clone_sha "$clone_sha" '
    keys == ["commands", "environment", "execution_locator",
      "output_contract", "schema", "source_revision", "source_tree_sha256"] and
    .output_contract == {algorithm:"sha256",
      bytes:"exact-command-order-no-normalization",
      stream:"combined-stdout-stderr"} and
    (.commands | length) == 12 and
    .commands[0].output_sha256 == $clone_sha and
    .commands[2].output_sha256 == $empty_sha and
    .commands[7].output_sha256 == $empty_sha and
    .commands[11].output_sha256 == $empty_sha and
    .commands[9].status == "expected_failure" and
    .commands[9].exit_status == 2 and
    all(.commands[]; keys == ["duration_seconds", "exit_status", "id",
      "output_sha256", "status"])
  ' "$receipt" >/dev/null || die 'observed receipt violates the closed contract'
  for mutation in algorithm bytes stream top-key command-key command-order; do
    case "$mutation" in
      algorithm) jq '.output_contract.algorithm="sha512"' "$receipt" >"$mutated" ;;
      bytes) jq '.output_contract.bytes="normalized"' "$receipt" >"$mutated" ;;
      stream) jq '.output_contract.stream="separate"' "$receipt" >"$mutated" ;;
      top-key) jq '.unexpected=true' "$receipt" >"$mutated" ;;
      command-key) jq '.commands[0].argv=[]' "$receipt" >"$mutated" ;;
      command-order) jq '.commands[0:2] |= reverse' "$receipt" >"$mutated" ;;
    esac
    if jq -e '
      keys == ["commands", "environment", "execution_locator",
        "output_contract", "schema", "source_revision", "source_tree_sha256"] and
      .output_contract == {algorithm:"sha256",
        bytes:"exact-command-order-no-normalization",
        stream:"combined-stdout-stderr"} and
      [.commands[].id] == ["clone","checkout-exact-revision",
        "clean-status-before","certificate-generation","run-test",
        "tracecheck-tests","compose-config","clean-status-after-validation",
        "acceptance-all-otel-getsockopt-tls13","assertion-failure-exit-2",
        "scoped-cleanup","clean-status-final"] and
      all(.commands[]; keys == ["duration_seconds", "exit_status", "id",
        "output_sha256", "status"])
    ' "$mutated" >/dev/null; then
      die "receipt validator accepted $mutation mutation"
    fi
  done
  rm -f -- "$mutated"
}

test_success_and_failure_campaigns() {
  local success_root=""
  local stable_lock_root=""
  local private_rename_root=""
  local row_forgery_root=""
  local hardlink_root=""
  local case_root=""
  local -a failure_mutations=(
    assertion-wrong-exit cleanup-failure missing-result two-results
    wrong-result-mode wrong-lock-mode lock-hardlink lock-symlink
    unrelated-addition held-lock lock-replacement lock-removal
    root-replacement root-disappearance acceptance-result-replacement
    results-root-pre-find-replacement
    receipt-preopen-symlink receipt-preopen-hardlink
    before-snapshot-rewrite before-snapshot-replacement before-snapshot-mode
    cleanup-run-sh-bytes cleanup-run-sh-symlink
    cleanup-checkout-root-replacement
    projector-bytes projector-symlink verifier-bytes verifier-symlink
    projector-failure public-extra-file public-verify-failure
    public-verify-missing public-verify-wrong public-verify-nonhex
    public-verify-extra-line public-verify-suffix public-evidence-id-nonhex
    output-parent-replacement output-directory-replacement
  )

  success_root="$(run_mock_campaign_case success none success)"
  assert_success_state_machine "$success_root/stderr.log"
  assert_success_handoff "$success_root"
  assert_observed_receipt "$success_root/observed-receipt.json"
  [[ -f "$success_root/projector-selector" &&
    "$(<"$success_root/projector-selector")" == --claims-v2 ]] ||
    die 'successful campaign silently fell back from claims-v2 projection'
  ! grep -Fq 'acceptance_failure_classification=' "$success_root/stderr.log" ||
    die 'successful campaign emitted a failure classification'
  [[ -d "$success_root/public-parent/test-claims" &&
    "$(find -- "$success_root/public-parent/test-claims" -mindepth 1 \
      -maxdepth 1 -printf '%f\n' | LC_ALL=C sort | wc -l)" == 7 ]] ||
    die 'success did not retain exactly seven public files'
  if grep -R -Fq -- 'private raw fixture' \
    "$success_root/public-parent/test-claims"; then
    die 'success leaked private raw fixture content'
  fi
  stable_lock_root="$(run_mock_campaign_case stable-preexisting-lock \
    stable-preexisting-lock success)"
  assert_success_state_machine "$stable_lock_root/stderr.log"
  assert_success_handoff "$stable_lock_root"
  private_rename_root="$(run_mock_campaign_case private-destroy-rename \
    private-destroy-rename success)"
  assert_success_state_machine "$private_rename_root/stderr.log"
  assert_success_handoff "$private_rename_root"
  [[ -f "$private_rename_root/private-destroy-renamed" &&
    ! -e "$private_rename_root/renamed-private" &&
    ! -L "$private_rename_root/renamed-private" ]] ||
    die 'pinned private destruction did not remove the renamed transaction inode'
  row_forgery_root="$(run_mock_campaign_case command-row-forgery \
    command-row-forgery success)"
  jq -e --arg empty_sha \
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' '
    .commands[0].duration_seconds != 999 and
    .commands[0].output_sha256 !=
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" and
    .commands[2].output_sha256 == $empty_sha
  ' "$row_forgery_root/observed-receipt.json" >/dev/null ||
    die 'mutable diagnostic paths replaced parent-memory command authority'
  hardlink_root="$(run_mock_campaign_case cleanup-hardlink-sentinel \
    cleanup-hardlink-sentinel success)"
  [[ "$(stat -Lc '%u:%a:%h' -- "$hardlink_root/external-sentinel")" == \
      "$EUID:400:1" &&
    "$(<"$hardlink_root/external-sentinel")" == 'external sentinel content' ]] ||
    die 'private cleanup mutated or removed an external hardlink inode'
  for mutation in "${failure_mutations[@]}"; do
    case_root="$(run_mock_campaign_case "failure-$mutation" "$mutation" failure)"
    if [[ "$mutation" == cleanup-failure ]]; then
      grep -Fq 'command scoped-cleanup exited 9; expected 0' \
        "$case_root/stderr.log" || die 'cleanup failure was not sticky'
    fi
    case "$mutation" in
      cleanup-run-sh-bytes|cleanup-run-sh-symlink|cleanup-checkout-root-replacement)
        [[ ! -e "$case_root/emergency-invoked" &&
          ! -e "$case_root/public-parent/test-claims" ]] ||
          die "$mutation executed mutable cleanup authority or published"
        ;;
      projector-bytes|projector-symlink|verifier-bytes|verifier-symlink)
        [[ ! -e "$case_root/projector-invoked" &&
          ! -e "$case_root/public-parent/test-claims" ]] ||
          die "$mutation executed mutable projection authority or published"
        ;;
      output-parent-replacement|output-directory-replacement)
        [[ -f "$case_root/github-output" &&
          ! -s "$case_root/github-output" ]] ||
          die "$mutation produced an upload-authority handoff"
        ;;
      receipt-preopen-symlink|receipt-preopen-hardlink)
        [[ -f "$case_root/receipt-preopen-sentinel" &&
          ! -L "$case_root/receipt-preopen-sentinel" &&
          "$(<"$case_root/receipt-preopen-sentinel")" == 'receipt sentinel content' &&
          "$(stat -Lc '%u:%a:%h' -- \
            "$case_root/receipt-preopen-sentinel")" == "$EUID:600:1" ]] ||
          die "$mutation modified the preexisting receipt target"
        ;;
    esac
  done
}

test_acceptance_failure_classification() {
  local mutation=""
  local case_root=""
  local classification_line=""
  local classification_json=""
  local run_binding_payload=""
  local expected_run_binding=""
  local expected_exit=7
  local -a detailed_mutations=(
    acceptance-failure-valid acceptance-failure-same-inode-aba
    acceptance-failure-timeout acceptance-failure-interrupted
    acceptance-failure-source-line-zero acceptance-failure-na-prefix
    acceptance-failure-all-terminal
    acceptance-failure-pressure-runtime-cleanup
    acceptance-failure-pressure-map-cleanup
    acceptance-failure-pressure-post-shutdown-cleanup
  )
  local -a unavailable_mutations=(
    acceptance-failure-malformed acceptance-failure-duplicate-key
    acceptance-failure-multiple
    acceptance-failure-symlink acceptance-failure-hardlink
    acceptance-failure-race acceptance-failure-extra-key
    acceptance-failure-stage acceptance-failure-reason
    acceptance-failure-environment acceptance-failure-exit-crosslink
    acceptance-failure-source-line-bound
    acceptance-failure-hash-crosslink acceptance-failure-input-size
    acceptance-failure-input-mode acceptance-failure-active-boundary
    acceptance-failure-pair-reference acceptance-failure-pair-digest
    acceptance-failure-java-reference acceptance-failure-java-counters
    acceptance-failure-java-snapshot-nul acceptance-failure-java-digest
    acceptance-failure-terminal-index-hash
    acceptance-failure-result-parent-replacement
    acceptance-failure-result-mountpoint
    acceptance-failure-child-mountpoint acceptance-failure-child-bind-mount
  )

  run_binding_payload="$(jq -cnS \
    --arg repository 'MrAlias/opentelemetry-ebpf-instrumentation' \
    --arg source_revision "$TEST_REVISION" \
    --arg workflow_blob_sha256 "$TEST_WORKFLOW_SHA256" \
    --arg workflow_ref \
      'MrAlias/opentelemetry-ebpf-instrumentation/.github/workflows/java_remote_parent_acceptance_claims.yml@refs/heads/agent/java-remote-parent-bridge' \
    --arg run_id 123456789 --arg run_attempt 1 '{
      repository: $repository,
      run_attempt: $run_attempt,
      run_id: $run_id,
      source_revision: $source_revision,
      workflow_blob_sha256: $workflow_blob_sha256,
      workflow_ref: $workflow_ref
    }')" || return 1
  expected_run_binding="$(printf '%s\n' "$run_binding_payload" | sha256sum)"
  expected_run_binding="${expected_run_binding%% *}"

  for mutation in "${detailed_mutations[@]}"; do
    expected_exit=7
    case "$mutation" in
      acceptance-failure-timeout) expected_exit=124 ;;
      acceptance-failure-interrupted) expected_exit=130 ;;
    esac
    case_root="$(run_mock_campaign_case "$mutation" "$mutation" failure)"
    [[ "$(grep -Fc 'acceptance_failure_classification=' \
        "$case_root/stderr.log")" == 1 ]] ||
      die "$mutation did not emit exactly one detailed classification"
    classification_line="$(grep -F 'acceptance_failure_classification=' \
      "$case_root/stderr.log")"
    classification_json="${classification_line#*acceptance_failure_classification=}"
    [[ "$classification_json" == "$(jq -cS . <<<"$classification_json")" ]] ||
      die "$mutation classification is not canonical JSON"
    jq -e --slurpfile expected "$case_root/expected-classification.json" \
      --arg revision "$TEST_REVISION" --arg run_binding "$expected_run_binding" \
      --argjson expected_exit "$expected_exit" '
      keys == [
        "boundary_index_sha256", "exit_status", "failure_stage",
        "first_incomplete_boundary", "reason", "run_binding_sha256",
        "run_status_sha256", "source_line", "source_revision",
        "terminal_boundary_count", "terminal_java_sha256",
        "terminal_obi_sha256"
      ] and
      .exit_status == $expected_exit and
      .source_revision == $revision and .run_binding_sha256 == $run_binding and
      .reason == $expected[0].reason and
      .failure_stage == $expected[0].failure_stage and
      .source_line == $expected[0].source_line and
      .terminal_boundary_count == $expected[0].terminal_boundary_count and
      .first_incomplete_boundary == $expected[0].first_incomplete_boundary and
      .boundary_index_sha256 == $expected[0].boundary_index_sha256 and
      .run_status_sha256 == $expected[0].run_status_sha256 and
      .terminal_java_sha256 == $expected[0].terminal_java_sha256 and
      .terminal_obi_sha256 == $expected[0].terminal_obi_sha256
    ' <<<"$classification_json" >/dev/null ||
      die "$mutation classification did not match its immutable snapshots"
    [[ -f "$case_root/emergency-invoked" &&
      ! -e "$case_root/public-parent/test-claims" &&
      -f "$case_root/github-output" && ! -s "$case_root/github-output" &&
      -f "$case_root/classifier-fd-count-before" &&
      -f "$case_root/classifier-fd-count-after" &&
      "$(<"$case_root/classifier-fd-count-before")" == \
        "$(<"$case_root/classifier-fd-count-after")" &&
      -f "$case_root/classifier-snapshot-seals" &&
      "$(wc -l <"$case_root/classifier-snapshot-seals")" == 6 &&
      "$(awk -F '\t' '$2 != 400 || $3 != 0 { bad=1 }
          END { print bad + 0 }' \
        "$case_root/classifier-snapshot-seals")" == 0 ]] ||
      die "$mutation weakened cleanup, FD closure, or snapshot sealing"
    if grep -Fq 'failure-classifier-secret-canary' \
      "$case_root/stdout.log" "$case_root/stderr.log" \
      "$case_root/github-output"; then
      die "$mutation detailed classification disclosed private output"
    fi
  done
  [[ -f "$TEST_TMP_DIR/acceptance-failure-same-inode-aba/failure-classification-same-inode-aba" ]] ||
    die 'same-inode rewrite-and-restore regression did not reach its checkpoint'

  for mutation in "${unavailable_mutations[@]}"; do
    case_root="$(run_mock_campaign_case "$mutation" "$mutation" failure)"
    case "$mutation" in
      acceptance-failure-race)
        [[ -f "$case_root/failure-classification-race" ]] ||
          die 'path replacement race did not reach its checkpoint'
        ;;
      acceptance-failure-result-parent-replacement)
        [[ -f "$case_root/failure-classification-parent-replaced" ]] ||
          die 'result-parent replacement did not reach its checkpoint'
        ;;
      acceptance-failure-result-mountpoint)
        [[ -f "$case_root/failure-classification-mountpoint" ]] ||
          die 'result mountpoint fence was not exercised'
        ;;
      acceptance-failure-java-snapshot-nul)
        [[ -f "$case_root/failure-classification-java-snapshot-nul" ]] ||
          die 'escaped-NUL Java snapshot regression was not constructed'
        ! grep -Fq 'ignored null byte' \
          "$case_root/stdout.log" "$case_root/stderr.log" ||
          die 'escaped-NUL Java snapshot reached Bash command substitution'
        ;;
      acceptance-failure-child-mountpoint)
        [[ -f "$case_root/failure-classification-child-mountpoint" ]] ||
          die 'evidence child mountpoint fence was not exercised'
        ;;
      acceptance-failure-child-bind-mount)
        [[ -f "$case_root/failure-classification-child-bind-mount" ]] ||
          die 'evidence child mount-ID fence was not exercised'
        ;;
    esac
    [[ "$(grep -Fc 'acceptance_failure_classification=' \
        "$case_root/stderr.log")" == 1 ]] ||
      die "$mutation did not emit exactly one unavailable classification"
    classification_line="$(grep -F 'acceptance_failure_classification=' \
      "$case_root/stderr.log")"
    classification_json="${classification_line#*acceptance_failure_classification=}"
    [[ "$classification_json" == "$(jq -cS . <<<"$classification_json")" ]] ||
      die "$mutation classification is not canonical JSON"
    jq -e --arg revision "$TEST_REVISION" \
      --arg run_binding "$expected_run_binding" '
      keys == [
        "exit_status", "failure_stage", "reason", "run_binding_sha256",
        "source_revision", "terminal_boundary_count"
      ] and
      .terminal_boundary_count == 0 and .exit_status == 7 and
      .failure_stage == "classification-unavailable" and
      .reason == "classification_unavailable" and
      .run_binding_sha256 == $run_binding and .source_revision == $revision
    ' <<<"$classification_json" >/dev/null ||
      die "$mutation did not fail closed to the fixed unavailable shape"
    [[ -f "$case_root/emergency-invoked" &&
      ! -e "$case_root/public-parent/test-claims" &&
      -f "$case_root/github-output" && ! -s "$case_root/github-output" &&
      -f "$case_root/classifier-fd-count-before" &&
      -f "$case_root/classifier-fd-count-after" &&
      "$(<"$case_root/classifier-fd-count-before")" == \
        "$(<"$case_root/classifier-fd-count-after")" ]] ||
      die "$mutation weakened cleanup, publication privacy, or FD closure"
    if grep -Fq 'failure-classifier-secret-canary' \
      "$case_root/stdout.log" "$case_root/stderr.log" \
      "$case_root/github-output"; then
      die "$mutation disclosed an unallowlisted private string"
    fi
  done
}

test_lock_validation_and_fd_closure() {
  local root="$TEST_TMP_DIR/lock-unit/results"
  local lock="$root/.obi-metric-capture.lock"
  local identity=""
  local held_fd=""
  local before_count=""
  local after_count=""
  local iteration=0

  mkdir -p -- "$root"
  chmod 0755 -- "$root"
  install -m 0600 /dev/null "$lock"
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$lock")"
  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    RESULTS_ROOT_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$root")"
    before_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    for ((iteration = 0; iteration < 20; iteration += 1)); do
      metric_capture_lock_matches_snapshot "$root" "$identity"
    done
    after_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    [[ "$before_count" == "$after_count" ]]
    exec {held_fd}>"$lock"
    flock -n "$held_fd"
    before_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    if metric_capture_lock_matches_snapshot "$root" "$identity"; then
      exit 1
    fi
    after_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    [[ "$before_count" == "$after_count" ]]
    flock -u "$held_fd"
    exec {held_fd}>&-
    metric_capture_lock_matches_snapshot "$root" "$identity"
    if metric_capture_lock_matches_snapshot "$root" "${identity%:*}:644"; then
      exit 1
    fi
  ) || die 'metric lock validation or FD closure failed'
}

test_timeout_budget_and_producer_umask() {
  local timeout_status=0
  local producer_umask=""
  local checkout_umask=""
  local private_umask=""
  local caller_umask=""
  local private_mode_root="$TEST_TMP_DIR/private-umask"
  local producer_mode_root="$TEST_TMP_DIR/producer-umask"
  local -i total=0

  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    command_timeout_seconds() { printf '1\n'; }
    if campaign_execute clone bash -c 'sleep 3'; then
      exit 1
    else
      timeout_status=$?
    fi
    [[ "$timeout_status" == 124 ]]
  ) || die 'command timeout did not terminate a hung command'
  producer_umask="$(
    source "$CAMPAIGN_RUNNER"
    campaign_execute acceptance-all-otel-getsockopt-tls13 bash -c umask
  )"
  checkout_umask="$(
    source "$CAMPAIGN_RUNNER"
    campaign_execute checkout-exact-revision bash -c umask
  )"
  private_umask="$(
    source "$CAMPAIGN_RUNNER"
    campaign_execute clean-status-before bash -c umask
  )"
  caller_umask="$(
    source "$CAMPAIGN_RUNNER"
    campaign_execute checkout-exact-revision bash -c true
    umask
  )"
  [[ "$producer_umask" == 0022 && "$checkout_umask" == 0022 &&
    "$private_umask" == 0077 && "$caller_umask" == 0077 ]] ||
    die 'producer/private umask scopes are not exact'
  mkdir -m 0700 -- "$private_mode_root" "$producer_mode_root"
  (
    source "$CAMPAIGN_RUNNER"
    campaign_execute clean-status-before bash -c \
      'mkdir -- "$1/directory"; : >"$1/file"' _ "$private_mode_root"
  )
  (
    source "$CAMPAIGN_RUNNER"
    campaign_execute acceptance-all-otel-getsockopt-tls13 bash -c \
      'mkdir -- "$1/directory"; : >"$1/file"' _ "$producer_mode_root"
  )
  [[ "$(stat -Lc '%a' -- "$private_mode_root/directory")" == 700 &&
    "$(stat -Lc '%a' -- "$private_mode_root/file")" == 600 &&
    "$(stat -Lc '%a' -- "$producer_mode_root/directory")" == 755 &&
    "$(stat -Lc '%a' -- "$producer_mode_root/file")" == 644 ]] ||
    die 'private checkout and producer object modes are not scoped'
  (
    source "$CAMPAIGN_RUNNER"
    local -a expected_timeouts=(
      300 60 30 120 1200 600 120 30 6600 1200 300 30
    )
    local -i index=0
    local actual_timeout=""
    for id in "${RECEIPT_COMMAND_IDS[@]}"; do
      actual_timeout="$(command_timeout_seconds "$id")"
      [[ "$actual_timeout" == "${expected_timeouts[$index]}" ]]
      index=$((index + 1))
      total=$((total + $(command_timeout_seconds "$id")))
    done
    [[ "$(command_timeout_seconds emergency-scoped-cleanup)" == 300 ]]
    (( total == 10590 && index == ${#RECEIPT_COMMAND_IDS[@]} ))
    total=$((
      total + ${#RECEIPT_COMMAND_IDS[@]} * COMMAND_KILL_AFTER_SECONDS +
      PROJECT_TIMEOUT_SECONDS + PROJECT_KILL_AFTER_SECONDS +
      PUBLIC_VERIFY_TIMEOUT_SECONDS + PUBLIC_VERIFY_KILL_AFTER_SECONDS +
      EMERGENCY_CLEANUP_TIMEOUT_SECONDS + COMMAND_KILL_AFTER_SECONDS
    ))
    (( total == 13420 && total < 14400 ))
  ) || die 'fixed command deadlines exceed the workflow budget'
}

test_real_git_private_checkout_modes() {
  local source_repository="$TEST_TMP_DIR/checkout-mode-source"
  local clone_parent="$TEST_TMP_DIR/checkout-mode-private"
  local checkout="$clone_parent/source"
  local revision=""

  mkdir -m 0700 -- "$source_repository" "$clone_parent"
  git -C "$source_repository" init -q
  git -C "$source_repository" config user.name 'Campaign Mode Test'
  git -C "$source_repository" config user.email 'campaign-mode@example.invalid'
  printf 'plain tracked bytes\n' >"$source_repository/plain.txt"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$source_repository/tool.sh"
  chmod 0644 -- "$source_repository/plain.txt"
  chmod 0755 -- "$source_repository/tool.sh"
  git -C "$source_repository" add -- plain.txt tool.sh
  git -C "$source_repository" -c commit.gpgSign=false commit -q -m fixture
  revision="$(git -C "$source_repository" rev-parse HEAD)"
  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    [[ "$(umask)" == 0077 ]]
    campaign_execute clone git clone --no-checkout --no-tags -- \
      "$source_repository" "$checkout" >/dev/null 2>&1
    [[ "$(stat -Lc '%u:%a' -- "$checkout")" == "$EUID:700" ]]
    campaign_execute checkout-exact-revision git -C "$checkout" checkout \
      --detach "$revision" >/dev/null 2>&1
    [[ "$(umask)" == 0077 &&
      "$(stat -Lc '%u:%a' -- "$checkout")" == "$EUID:700" &&
      "$(stat -Lc '%u:%a' -- "$checkout/plain.txt")" == "$EUID:644" &&
      "$(stat -Lc '%u:%a' -- "$checkout/tool.sh")" == "$EUID:755" ]]
  ) || die 'real private clone/checkout modes do not preserve the execution contract'
}

test_recorded_command_timeout_classification() {
  local root="$TEST_TMP_DIR/recorded-timeout"
  local private="$root/obi-java-remote-parent-acceptance.ABC123"
  local stderr_log="$root/stderr.log"

  mkdir -m 0700 -- "$root" "$private" "$private/commands"
  if (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    TRANSACTION_PARENT="$root"
    PRIVATE_DIRECTORY="$private"
    PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")"
    exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY"
    COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
    COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
      "$COMMAND_DIRECTORY")"
    COMMAND_COUNT=0
    command_timeout_seconds() {
      [[ "$1" == clone ]] || return 1
      printf '1\n'
    }
    if run_recorded_command clone 0 "$PRIVATE_DIRECTORY" bash -c 'sleep 3'; then
      exit 1
    fi
    [[ "${#COMMAND_ROWS_MEMORY[@]}" == 1 ]]
    jq -e '
      .id == "clone" and .exit_status == 124 and
      .output_sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ' <<<"${COMMAND_ROWS_MEMORY[0]}" >/dev/null
  ) 2>"$stderr_log"; then
    :
  else
    tail -80 -- "$stderr_log" >&2
    die 'recorded timeout classification harness failed'
  fi
  grep -Fq 'command clone exceeded its 1s deadline' "$stderr_log" ||
    die 'recorded timeout was not distinguished from an ordinary exit'
}

test_recorded_log_identity_and_fd_closure() {
  local root="$TEST_TMP_DIR/recorded-log-identity"
  local mutation=""

  mkdir -m 0700 -- "$root"
  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    local before_count=""
    local after_count=""
    local iteration=0
    before_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    for ((iteration = 0; iteration < 20; iteration += 1)); do
      TRANSACTION_PARENT="$root"
      printf -v PRIVATE_DIRECTORY \
        '%s/obi-java-remote-parent-acceptance.A%05d' "$root" "$iteration"
      mkdir -m 0700 -- "$PRIVATE_DIRECTORY" "$PRIVATE_DIRECTORY/commands"
      PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")"
      exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY"
      COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
      COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
        "$COMMAND_DIRECTORY")"
      COMMAND_COUNT=0
      COMMAND_ROWS_MEMORY=()
      COMMAND_OUTPUT_SHA256=()
      run_recorded_command clone 0 "$PRIVATE_DIRECTORY" \
        bash -c 'printf "recorded-output-%s\\n" "$1"' _ "$iteration" \
        >/dev/null 2>&1
      exec {PRIVATE_DIRECTORY_FD}<&-
      PRIVATE_DIRECTORY_FD=""
    done
    after_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    [[ "$before_count" == "$after_count" ]]
  ) || die 'successful command recording leaked an output descriptor'

  for mutation in replacement symlink same-inode directory-replacement \
    directory-symlink; do
    (
      # shellcheck source=run-retained-acceptance-campaign.sh
      source "$CAMPAIGN_RUNNER"
      local mutation_root="$root/$mutation"
      local private="$mutation_root/obi-java-remote-parent-acceptance.ABC123"
      local external="$mutation_root/external-directory"
      local before_count=""
      local after_count=""
      local old_identity=""
      local new_identity=""
      mkdir -m 0700 -- "$mutation_root" "$private" "$private/commands" \
        "$external"
      printf 'external sentinel bytes\n' >"$external/sentinel"
      chmod 0400 -- "$external/sentinel"
      TRANSACTION_PARENT="$mutation_root"
      PRIVATE_DIRECTORY="$private"
      PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")"
      exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY"
      COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
      COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
        "$COMMAND_DIRECTORY")"
      COMMAND_COUNT=0
      COMMAND_ROWS_MEMORY=()
      COMMAND_OUTPUT_SHA256=()
      recorded_log_checkpoint() {
        local -r phase="$1"
        local -r log="$2"
        case "$mutation:$phase" in
          replacement:after-command)
            mv -- "$log" "$PRIVATE_DIRECTORY/original.log"
            printf 'replacement bytes\n' >"$log"
            chmod 0600 -- "$log"
            ;;
          symlink:after-command)
            mv -- "$log" "$PRIVATE_DIRECTORY/original.log"
            ln -s -- "$PRIVATE_DIRECTORY/original.log" "$log"
            ;;
          same-inode:after-fd-digest)
            old_identity="$(stat -Lc '%d:%i' -- "$log")"
            printf 'same inode drift\n' >"$log"
            new_identity="$(stat -Lc '%d:%i' -- "$log")"
            [[ "$old_identity" == "$new_identity" ]] || return 1
            : >"$mutation_root/same-inode-confirmed"
            ;;
          directory-replacement:after-command)
            mv -- "$COMMAND_DIRECTORY" \
              "$PRIVATE_DIRECTORY/original-commands"
            mkdir -m 0700 -- "$COMMAND_DIRECTORY"
            ;;
          directory-symlink:after-command)
            mv -- "$COMMAND_DIRECTORY" \
              "$PRIVATE_DIRECTORY/original-commands"
            ln -s -- "$external" "$COMMAND_DIRECTORY"
            ;;
        esac
      }
      before_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
      if run_recorded_command clone 0 "$PRIVATE_DIRECTORY" \
        bash -c 'printf "authoritative bytes\\n"'; then
        exit 1
      fi
      after_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
      [[ "$before_count" == "$after_count" ]]
      if [[ "$mutation" == same-inode ]]; then
        [[ -f "$mutation_root/same-inode-confirmed" ]]
      fi
      [[ "$(<"$external/sentinel")" == 'external sentinel bytes' &&
        "$(stat -Lc '%u:%a:%h' -- "$external/sentinel")" == "$EUID:400:1" &&
        "$(find -- "$external" -mindepth 1 -maxdepth 1 -printf '%f\n')" == sentinel ]]
    ) || die "recorded log accepted $mutation drift or leaked its descriptor"
  done
}

test_recorded_log_preopen_leaf_fence() {
  local mutation=""

  for mutation in symlink hardlink; do
    (
      # shellcheck source=run-retained-acceptance-campaign.sh
      source "$CAMPAIGN_RUNNER"
      local root="$TEST_TMP_DIR/recorded-log-preopen-$mutation"
      local private="$root/obi-java-remote-parent-acceptance.ABC123"
      local external="$root/external"
      local sentinel="$external/sentinel"
      local marker="$root/command-invoked"
      local before_count=""
      local after_count=""
      mkdir -m 0700 -- "$root" "$private" "$private/commands" "$external"
      printf 'sentinel must survive\n' >"$sentinel"
      chmod 0600 -- "$sentinel"
      TRANSACTION_PARENT="$root"
      PRIVATE_DIRECTORY="$private"
      PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")"
      exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY"
      COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
      COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
        "$COMMAND_DIRECTORY")"
      COMMAND_COUNT=0
      recorded_log_preopen_checkpoint() {
        local -r log="$1"

        if [[ "$mutation" == symlink ]]; then
          ln -s -- "$sentinel" "$log"
        else
          ln -- "$sentinel" "$log"
        fi
      }
      before_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
      if run_recorded_command clone 0 "$PRIVATE_DIRECTORY" \
          bash -c ': >"$1"' _ "$marker" >/dev/null 2>&1; then
        exit 1
      fi
      after_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
      [[ "$before_count" == "$after_count" && ! -e "$marker" &&
        ! -L "$marker" && "$(<"$sentinel")" == 'sentinel must survive' &&
        "${#COMMAND_ROWS_MEMORY[@]}" == 0 && "$COMMAND_COUNT" == 0 ]]
      if [[ "$mutation" == symlink ]]; then
        [[ "$(stat -Lc '%h' -- "$sentinel")" == 1 ]]
      else
        [[ "$(stat -Lc '%h' -- "$sentinel")" == 2 ]]
      fi
      exec {PRIVATE_DIRECTORY_FD}<&-
    ) || die "exclusive log creation accepted a pre-open $mutation leaf"
  done
}

test_command_directory_and_working_root_fences() {
  local mutation=""

  for mutation in replacement symlink; do
    (
      # shellcheck source=run-retained-acceptance-campaign.sh
      source "$CAMPAIGN_RUNNER"
      local root="$TEST_TMP_DIR/preopen-command-directory-$mutation"
      local private="$root/obi-java-remote-parent-acceptance.ABC123"
      local external="$root/external-directory"
      local before_count=""
      local after_count=""
      mkdir -m 0700 -- "$root" "$private" "$private/commands" "$external"
      printf 'external sentinel bytes\n' >"$external/sentinel"
      chmod 0400 -- "$external/sentinel"
      TRANSACTION_PARENT="$root"
      PRIVATE_DIRECTORY="$private"
      PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")"
      exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY"
      COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
      COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
        "$COMMAND_DIRECTORY")"
      mv -- "$COMMAND_DIRECTORY" "$PRIVATE_DIRECTORY/original-commands"
      if [[ "$mutation" == replacement ]]; then
        mkdir -m 0700 -- "$COMMAND_DIRECTORY"
      else
        ln -s -- "$external" "$COMMAND_DIRECTORY"
      fi
      before_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
      if run_recorded_command clone 0 "$PRIVATE_DIRECTORY" \
        bash -c 'printf "must not execute\n"'; then
        exit 1
      fi
      after_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
      [[ "$before_count" == "$after_count" &&
        "$(<"$external/sentinel")" == 'external sentinel bytes' &&
        "$(stat -Lc '%u:%a:%h' -- "$external/sentinel")" == "$EUID:400:1" &&
        "$(find -- "$external" -mindepth 1 -maxdepth 1 -printf '%f\n')" == sentinel ]]
    ) || die "pre-open command-directory $mutation touched an external path"
  done

  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    local root="$TEST_TMP_DIR/recorded-working-root"
    local private="$root/obi-java-remote-parent-acceptance.ABC123"
    local marker="$root/command-invoked"
    mkdir -m 0700 -- "$root" "$private" "$private/commands" "$private/source"
    TRANSACTION_PARENT="$root"
    PRIVATE_DIRECTORY="$private"
    PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")"
    exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY"
    COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
    COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
      "$COMMAND_DIRECTORY")"
    CHECKOUT_DIRECTORY="$PRIVATE_DIRECTORY/source"
    CHECKOUT_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$CHECKOUT_DIRECTORY")"
    mv -- "$CHECKOUT_DIRECTORY" "$PRIVATE_DIRECTORY/source-original"
    mkdir -m 0700 -- "$CHECKOUT_DIRECTORY"
    COMMAND_COUNT=1
    if run_recorded_command checkout-exact-revision 0 "$CHECKOUT_DIRECTORY" \
      bash -c ': >"$1"' _ "$marker"; then
      exit 1
    fi
    [[ ! -e "$marker" && ! -L "$marker" &&
      ! -e "$COMMAND_DIRECTORY/01-checkout-exact-revision.log" ]]
  ) || die 'recorded command accepted a replaced checkout working root'

  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    COMMAND_OUTPUT_SHA256["clean-status-before"]="$EMPTY_SHA256"
    assert_command_output_empty clean-status-before
    COMMAND_OUTPUT_SHA256["clean-status-before"]="$(printf x | sha256sum)"
    COMMAND_OUTPUT_SHA256["clean-status-before"]="${COMMAND_OUTPUT_SHA256["clean-status-before"]%% *}"
    if assert_command_output_empty clean-status-before; then
      exit 1
    fi
  ) || die 'empty command output is not bound to the captured parent-memory digest'
}

test_state_transition_rejection() {
  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    enter_state AUTHORITY_PREFLIGHT
    if enter_state CLONE >/dev/null 2>&1; then
      exit 1
    fi
  ) >/dev/null 2>&1 || die 'state machine accepted an out-of-order transition'
}

test_private_cleanup_mount_fence() {
  local mountinfo="$TEST_TMP_DIR/mountinfo-fixture"

  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    PRIVATE_DIRECTORY="$TEST_TMP_DIR/private-mount-fence"
    printf '%s\n' \
      '40 20 0:40 / / rw,relatime - ext4 /dev/root rw' >"$mountinfo"
    if private_tree_has_mountpoint "$mountinfo"; then
      exit 1
    fi
    printf '41 40 0:99 / %s/nested rw - tmpfs tmpfs rw\n' \
      "$PRIVATE_DIRECTORY" >>"$mountinfo"
    private_tree_has_mountpoint "$mountinfo"
  ) || die 'private cleanup mountpoint source fence is not fail-closed'
  if grep -Fq 'chmod -R' "$CAMPAIGN_RUNNER"; then
    die 'private cleanup recursively chmods potentially external inodes'
  fi
}

test_github_authority_mutations() {
  local event="$TEST_TMP_DIR/github-event.json"
  local symlink="$TEST_TMP_DIR/github-event-link.json"
  local hardlink="$TEST_TMP_DIR/github-event-hardlink.json"
  local event_payload=""
  local before_count=""
  local after_count=""
  local variable=""
  local original=""

  jq -cn --arg after "$TEST_REVISION" '{after:$after,
    ref:"refs/heads/agent/java-remote-parent-bridge",
    repository:{full_name:"MrAlias/opentelemetry-ebpf-instrumentation"}}' >"$event"
  chmod 0600 -- "$event"
  (
    source "$CAMPAIGN_RUNNER"
    SOURCE_REVISION="$TEST_REVISION"
    WORKFLOW_REF='MrAlias/opentelemetry-ebpf-instrumentation/.github/workflows/java_remote_parent_acceptance_claims.yml@refs/heads/agent/java-remote-parent-bridge'
    GITHUB_EVENT_NAME=push
    GITHUB_REPOSITORY='MrAlias/opentelemetry-ebpf-instrumentation'
    GITHUB_REF='refs/heads/agent/java-remote-parent-bridge'
    GITHUB_SERVER_URL='https://github.com'
    GITHUB_ACTIONS=true
    CI=true
    RUNNER_ENVIRONMENT=github-hosted
    RUNNER_OS=Linux
    RUNNER_ARCH=X64
    GITHUB_SHA="$TEST_REVISION"
    GITHUB_WORKFLOW_SHA="$TEST_REVISION"
    GITHUB_EVENT_PATH="$event"
    validate_github_runner_environment
    validate_github_event_payload
    before_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    for _ in {1..20}; do
      validate_github_event_payload
    done
    after_count="$(find "/proc/$BASHPID/fd" -mindepth 1 -maxdepth 1 | wc -l)"
    [[ "$before_count" == "$after_count" ]]
    for variable in GITHUB_SHA GITHUB_WORKFLOW_SHA GITHUB_ACTIONS CI \
      RUNNER_ENVIRONMENT RUNNER_OS RUNNER_ARCH GITHUB_EVENT_NAME \
      GITHUB_REPOSITORY GITHUB_REF GITHUB_SERVER_URL WORKFLOW_REF; do
      original="${!variable}"
      printf -v "$variable" '%s' mutation
      if validate_github_runner_environment; then
        exit 1
      fi
      printf -v "$variable" '%s' "$original"
    done
    for field in after ref repository; do
      case "$field" in
        after) jq '.after="mutation"' "$event" >"$event.tmp" ;;
        ref) jq '.ref="refs/heads/mutation"' "$event" >"$event.tmp" ;;
        repository) jq '.repository.full_name="mutation/repository"' "$event" >"$event.tmp" ;;
      esac
      mv -- "$event.tmp" "$event"
      chmod 0600 -- "$event"
      if validate_github_event_payload; then
        exit 1
      fi
      jq -cn --arg after "$TEST_REVISION" '{after:$after,
        ref:"refs/heads/agent/java-remote-parent-bridge",
        repository:{full_name:"MrAlias/opentelemetry-ebpf-instrumentation"}}' >"$event"
      chmod 0600 -- "$event"
    done
    event_payload="$(jq -c . "$event")"
    printf '%s%s\n' "$event_payload" "$event_payload" >"$event.second"
    mv -- "$event.second" "$event"
    chmod 0600 -- "$event"
    if validate_github_event_payload; then
      exit 1
    fi
    printf '%s\n' "$event_payload" >"$event"
    chmod 0600 -- "$event"
    chmod 0666 -- "$event"
    if validate_github_event_payload; then
      exit 1
    fi
    chmod 0600 -- "$event"
    ln -- "$event" "$hardlink"
    if validate_github_event_payload; then
      exit 1
    fi
    rm -- "$hardlink"
    ln -s -- "$event" "$symlink"
    GITHUB_EVENT_PATH="$symlink"
    if validate_github_event_payload; then
      exit 1
    fi
  ) || die 'GitHub runner/event authority mutation was accepted'
}

workflow_has_once() {
  local -r workflow="$1"
  local -r literal="$2"
  [[ "$(grep -F -c -- "$literal" "$workflow")" == 1 ]]
}

workflow_text_has_count() {
  local -r workflow_text="$1"
  local -r literal="$2"
  local -r expected_count="$3"
  [[ "$(grep -F -c -- "$literal" <<<"$workflow_text")" == "$expected_count" ]]
}

workflow_text_has_once() {
  workflow_text_has_count "$1" "$2" 1
}

workflow_job_text() {
  local -r workflow="$1"
  local -r target="$2"

  awk -v target="$target" '
    $0 == "jobs:" { in_jobs=1; next }
    !in_jobs { next }
    /^  [[:alnum:]_-]+:$/ {
      current=$0
      sub(/^  /, "", current)
      sub(/:$/, "", current)
      if (emit) exit
      if (current == target) {
        emit=1
        found=1
      }
    }
    emit { print }
    END { if (!found) exit 42 }
  ' "$workflow"
}

validate_workflow_contract_file() {
  local -r workflow="$1"
  local acceptance_job=""
  local profile_job=""
  local aggregate_job=""
  local workflow_jobs=""
  local upload_condition=""
  local upload_paths=""
  local expected_paths=""
  local profile_roles=""
  local expected_profile_roles=""
  local aggregate_inputs=""
  local expected_aggregate_inputs=""
  local aggregate_upload_paths=""
  local expected_aggregate_upload_paths=""
  local early_line=""
  local free_disk_line=""
  local literal=""
  local -a profile_exact_literals=()
  local -a aggregate_exact_literals=()
  local -a exact_literals=(
    '      - agent/java-remote-parent-bridge'
    '    runs-on: ubuntu-24.04'
    '    timeout-minutes: 240'
    '  group: java-remote-parent-acceptance-claims-${{ github.workflow }}-${{ github.ref }}'
    '  cancel-in-progress: false'
    '      PUBLIC_PARENT: /tmp/obi-java-remote-parent-public-${{ github.run_id }}-${{ github.run_attempt }}'
    '      PUBLIC_OUTPUT: /tmp/obi-java-remote-parent-public-${{ github.run_id }}-${{ github.run_attempt }}/java-remote-parent-claims-${{ github.sha }}'
    '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
    '          fetch-depth: 0'
    '          persist-credentials: false'
    '        uses: ./.github/actions/free-disk'
    '        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0'
    '        uses: actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95 # v5.6.0'
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1'
    '          cache: false'
    '        id: campaign'
    '        id: independent_verify'
    "        if: steps.campaign.outcome == 'success'"
    '        id: privacy'
    '        if: always()'
    '          CAMPAIGN_OUTCOME: ${{ steps.campaign.outcome }}'
    '          INDEPENDENT_OUTCOME: ${{ steps.independent_verify.outcome }}'
    '            "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"'
    '          [[ "$(git rev-parse --verify '\''HEAD^{commit}'\'')" == "$GITHUB_SHA" ]]'
    'jq -se --arg after "$GITHUB_SHA" --arg ref "$expected_ref"'
    '          exec {event_fd}<"$GITHUB_EVENT_PATH"'
    '            "/proc/$BASHPID/fd/$event_fd")" || event_descriptor_identity='
    $'          .github/actions/free-disk/action.yml\t100644\t644'
    '            git diff --quiet --no-ext-diff --no-textconv "$GITHUB_SHA" -- "$relative"'
    '            [[ "$disk_sha" == "$blob_sha" ]]'
    '          if [[ "$CAMPAIGN_OUTCOME" != success ]]; then'
    '            [[ -z "$sibling_inventory" ]] || {'
    '            "$INDEPENDENT_OUTCOME" == success ]]'
    'obi-java-remote-parent-acceptance.*'
    '.retained-projection-transaction.*'
    '          evidence_id="$(jq -er '
    '          [[ "$evidence_id" == "$EXPECTED_EVIDENCE_ID" ]]'
    '          exec {verify_fd}<"/proc/$BASHPID/fd/$verify_directory_fd/verify.sh"'
    '          if verify_output="$(cd / && bash "$PUBLIC_OUTPUT/verify.sh")"; then'
    '            "bounded claim bundle internally consistent (not authenticated): $evidence_id" ]]'
    '          if-no-files-found: error'
    '          include-hidden-files: false'
    '          retention-days: 14'
  )
  profile_exact_literals=(
    '  fault-security-profile:'
    '    name: Fault/security profile ${{ matrix.role }}'
    '    runs-on: ubuntu-24.04'
    '    timeout-minutes: 180'
    '    strategy:'
    '      fail-fast: false'
    '      matrix:'
    '        role:'
    '      CELL_PARENT: /tmp/obi-java-remote-parent-cell-${{ matrix.role }}-${{ github.run_id }}-${{ github.run_attempt }}'
    '      CELL_OUTPUT: /tmp/obi-java-remote-parent-cell-${{ matrix.role }}-${{ github.run_id }}-${{ github.run_attempt }}/public'
    '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
    '          fetch-depth: 0'
    '          persist-credentials: false'
    '      - uses: ./.github/actions/free-disk'
    '      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0'
    '      - uses: actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95 # v5.6.0'
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1'
    $'          docker-prune: \'false\''
    '          cache: false'
    '        id: profile'
    '          RUNNER_ENVIRONMENT: ${{ runner.environment }}'
    $'            --profile \'${{ matrix.role }}\' "$CELL_OUTPUT"'
    '        id: privacy'
    '        if: always()'
    '          PROFILE_OUTCOME: ${{ steps.profile.outcome }}'
    $'          expected=$\'SANITIZATION.md\\tf\\nSHA256SUMS\\tf\\nprofile.json\\tf\\nverify.sh\\tf\''
    $'          (CDPATH=\'\' cd / && bash "$CELL_OUTPUT/verify.sh" >/dev/null)'
    "          !cancelled() && steps.profile.outcome == 'success' &&"
    "          steps.privacy.outcome == 'success'"
    '          name: java-remote-parent-fault-security-cell-${{ matrix.role }}-${{ github.run_id }}-${{ github.run_attempt }}'
    '          path: ${{ env.CELL_OUTPUT }}'
    '          if-no-files-found: error'
    '          include-hidden-files: false'
    '          retention-days: 90'
  )
  aggregate_exact_literals=(
    '  fault-security-matrix:'
    '    name: Aggregate five sanitized fault/security cells'
    '    needs: fault-security-profile'
    '    runs-on: ubuntu-24.04'
    '    timeout-minutes: 30'
    '      CELL_ROOT: /tmp/fault-security-cells-${{ github.run_id }}-${{ github.run_attempt }}'
    '      MATRIX_PARENT: /tmp/fault-security-matrix-${{ github.run_id }}-${{ github.run_attempt }}'
    '      MATRIX_OUTPUT: /tmp/fault-security-matrix-${{ github.run_id }}-${{ github.run_attempt }}/public'
    '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
    '          fetch-depth: 0'
    '          persist-credentials: false'
    '        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1'
    '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1'
    '          pattern: java-remote-parent-fault-security-cell-*-${{ github.run_id }}-${{ github.run_attempt }}'
    '          path: ${{ env.CELL_ROOT }}'
    '          merge-multiple: false'
    '          [[ "$observed" == "$expected" ]]'
    '        id: aggregate'
    '            "java-remote-parent-fault-security-cell-all-getsockopt${suffix}" \'
    '            "java-remote-parent-fault-security-cell-all-unix${suffix}" \'
    '            "java-remote-parent-fault-security-cell-all-auto${suffix}" \'
    '            "java-remote-parent-fault-security-cell-pid-reuse-getsockopt${suffix}" \'
    '            "java-remote-parent-fault-security-cell-pid-reuse-unix${suffix}"'
    '            --aggregate-cells-v1 \'
    '            --fault-security-matrix-v1 "$MATRIX_OUTPUT" >/dev/null'
    $'          (CDPATH=\'\' cd / && bash "$MATRIX_OUTPUT/verify.sh" >/dev/null)'
    "        if: steps.aggregate.outcome == 'success'"
    '          name: java-remote-parent-fault-security-${{ github.run_id }}-${{ github.run_attempt }}'
    '          path: |'
    '            ${{ env.MATRIX_OUTPUT }}/README.md'
    '            ${{ env.MATRIX_OUTPUT }}/SANITIZATION.md'
    '            ${{ env.MATRIX_OUTPUT }}/fault-security-matrix.json'
    '            ${{ env.MATRIX_OUTPUT }}/derivation-receipt.json'
    '            ${{ env.MATRIX_OUTPUT }}/verify.sh'
    '            ${{ env.MATRIX_OUTPUT }}/SHA256SUMS'
    '          if-no-files-found: error'
    '          include-hidden-files: false'
    '          retention-days: 14'
  )

  acceptance_job="$(workflow_job_text "$workflow" acceptance)" || return 1
  profile_job="$(workflow_job_text "$workflow" fault-security-profile)" || return 1
  aggregate_job="$(workflow_job_text "$workflow" fault-security-matrix)" || return 1
  workflow_jobs="$(awk '
    $0 == "jobs:" { in_jobs=1; next }
    in_jobs && /^  [[:alnum:]_-]+:$/ {
      sub(/^  /, "")
      sub(/:$/, "")
      print
    }
  ' "$workflow")" || return 1
  [[ "$workflow_jobs" == $'acceptance\nfault-security-profile\nfault-security-matrix' ]] ||
    return 1

  [[ "$(grep -Ec '^[[:space:]]+(-[[:space:]]+)?uses:' "$workflow")" == 13 &&
    "$(grep -Fc 'actions/checkout@' "$workflow")" == 3 &&
    "$(grep -Fc 'actions/upload-artifact@' "$workflow")" == 3 &&
    "$(grep -Fc 'actions/download-artifact@' "$workflow")" == 1 &&
    "$(grep -Fc './.github/actions/free-disk' "$workflow")" == 2 &&
    "$(grep -Fc 'actions/setup-go@' "$workflow")" == 2 &&
    "$(grep -Fc 'actions/setup-java@' "$workflow")" == 2 &&
    "$(grep -Ec '^[[:space:]]+retention-days: 14$' "$workflow")" == 2 &&
    "$(grep -Ec '^[[:space:]]+retention-days: 90$' "$workflow")" == 1 ]] ||
    return 1

  [[ "$(grep -Ec '^[[:space:]]+(-[[:space:]]+)?uses:' <<<"$acceptance_job")" == 5 &&
    "$(grep -Fc 'actions/upload-artifact@' <<<"$acceptance_job")" == 1 &&
    "$(grep -Fc 'RUNNER_ENVIRONMENT: ${{ runner.environment }}' <<<"$acceptance_job")" == 2 &&
    "$(grep -Fc 'EXPECTED_PARENT_IDENTITY: ${{ steps.campaign.outputs.public_parent_identity }}' <<<"$acceptance_job")" == 2 &&
    "$(grep -Fc 'EXPECTED_DIRECTORY_IDENTITY: ${{ steps.campaign.outputs.public_directory_identity }}' <<<"$acceptance_job")" == 2 &&
    "$(grep -Fc 'EXPECTED_CLOSURE_SHA256: ${{ steps.campaign.outputs.public_closure_sha256 }}' <<<"$acceptance_job")" == 2 &&
    "$(grep -Fc 'EXPECTED_EVIDENCE_ID: ${{ steps.campaign.outputs.public_evidence_id }}' <<<"$acceptance_job")" == 2 &&
    "$(grep -Fc '"$observed_closure" == "$EXPECTED_CLOSURE_SHA256"' <<<"$acceptance_job")" == 3 &&
    "$(grep -Fc '$(sha256sum <"$PUBLIC_OUTPUT/verify.sh")' <<<"$acceptance_job")" == 2 ]] ||
    return 1
  [[ "$(grep -Ec '^[[:space:]]+(-[[:space:]]+)?uses:' <<<"$profile_job")" == 5 &&
    "$(grep -Fc 'actions/upload-artifact@' <<<"$profile_job")" == 1 &&
    "$(grep -Fc 'actions/download-artifact@' <<<"$profile_job")" == 0 &&
    "$(grep -Fc 'RUNNER_ENVIRONMENT: ${{ runner.environment }}' <<<"$profile_job")" == 1 ]] ||
    return 1
  [[ "$(grep -Ec '^[[:space:]]+(-[[:space:]]+)?uses:' <<<"$aggregate_job")" == 3 &&
    "$(grep -Fc 'actions/upload-artifact@' <<<"$aggregate_job")" == 1 &&
    "$(grep -Fc 'actions/download-artifact@' <<<"$aggregate_job")" == 1 ]] ||
    return 1
  for literal in "${exact_literals[@]}"; do
    case "$literal" in
      '      - agent/java-remote-parent-bridge' | \
        '  group: java-remote-parent-acceptance-claims-${{ github.workflow }}-${{ github.ref }}' | \
        '  cancel-in-progress: false')
        workflow_has_once "$workflow" "$literal"
        ;;
      *)
        workflow_text_has_once "$acceptance_job" "$literal"
        ;;
    esac || {
      printf 'workflow literal is not exact: %s\n' "$literal" >&2
      return 1
    }
  done
  for literal in "${profile_exact_literals[@]}"; do
    workflow_text_has_once "$profile_job" "$literal" || {
      printf 'profile workflow literal is not exact: %s\n' "$literal" >&2
      return 1
    }
  done
  for literal in "${aggregate_exact_literals[@]}"; do
    workflow_text_has_once "$aggregate_job" "$literal" || {
      printf 'aggregate workflow literal is not exact: %s\n' "$literal" >&2
      return 1
    }
  done
  workflow_has_once "$workflow" '  actions: read' || return 1
  workflow_has_once "$workflow" '  contents: read' || return 1
  if grep -Eq 'workflow_dispatch:|pull_request:|schedule:|^[[:space:]]+paths:|^[[:space:]]+tags:|continue-on-error:|actions/cache@' \
    "$workflow"; then
    return 1
  fi
  if grep -Fq 'download-artifact@' <<<"$acceptance_job"; then
    return 1
  fi
  early_line="$(grep -nF -m1 -- '- name: Verify exact push and tracked execution bytes' \
    <<<"$acceptance_job")" || return 1
  free_disk_line="$(grep -nF -m1 -- '- name: Reclaim hosted-runner disk space' \
    <<<"$acceptance_job")" || return 1
  early_line="${early_line%%:*}"
  free_disk_line="${free_disk_line%%:*}"
  (( early_line < free_disk_line )) || return 1
  upload_condition="$(awk '
    /- name: Upload verified bounded-claim projection/ { upload=1 }
    upload && /if: >-/ { condition=1; next }
    condition && /uses:/ { exit }
    condition { gsub(/[[:space:]]/, ""); printf "%s", $0 }
  ' <<<"$acceptance_job")" || return 1
  [[ "$upload_condition" == \
    "!cancelled()&&steps.campaign.outcome=='success'&&steps.independent_verify.outcome=='success'&&steps.privacy.outcome=='success'" ]] ||
    return 1
  upload_paths="$(awk '
    /^[[:space:]]+path: \|$/ { paths=1; next }
    paths && /^[[:space:]]+if-no-files-found:/ { exit }
    paths { sub(/^[[:space:]]+/, ""); print }
  ' <<<"$acceptance_job")" || return 1
  expected_paths="$(printf '%s\n' \
    '${{ env.PUBLIC_OUTPUT }}/README.md' \
    '${{ env.PUBLIC_OUTPUT }}/SANITIZATION.md' \
    '${{ env.PUBLIC_OUTPUT }}/acceptance-claims.json' \
    '${{ env.PUBLIC_OUTPUT }}/authority-summary.json' \
    '${{ env.PUBLIC_OUTPUT }}/derivation-receipt.json' \
    '${{ env.PUBLIC_OUTPUT }}/verify.sh' \
    '${{ env.PUBLIC_OUTPUT }}/SHA256SUMS')"
  [[ "$upload_paths" == "$expected_paths" ]] || return 1

  profile_roles="$(awk '
    $0 == "        role:" { roles=1; next }
    roles && $0 == "    env:" { exit }
    roles {
      sub(/^          - /, "")
      print
    }
  ' <<<"$profile_job")" || return 1
  expected_profile_roles="$(printf '%s\n' \
    all-getsockopt all-unix all-auto pid-reuse-getsockopt pid-reuse-unix)"
  [[ "$profile_roles" == "$expected_profile_roles" ]] || return 1

  aggregate_inputs="$(awk '
    /--aggregate-cells-v1 \\$/ { inputs=1; next }
    inputs {
      sub(/^[[:space:]]+/, "")
      print
      if ($0 == "\"$MATRIX_OUTPUT\"") exit
    }
  ' <<<"$aggregate_job")" || return 1
  expected_aggregate_inputs=$'"${prefix}all-getsockopt${suffix}" \\\n"${prefix}all-unix${suffix}" \\\n"${prefix}all-auto${suffix}" \\\n"${prefix}pid-reuse-getsockopt${suffix}" \\\n"${prefix}pid-reuse-unix${suffix}" \\\n"$MATRIX_OUTPUT"'
  [[ "$aggregate_inputs" == "$expected_aggregate_inputs" ]] || return 1

  aggregate_upload_paths="$(awk '
    /^[[:space:]]+path: \|$/ { paths=1; next }
    paths && /^[[:space:]]+if-no-files-found:/ { exit }
    paths { sub(/^[[:space:]]+/, ""); print }
  ' <<<"$aggregate_job")" || return 1
  expected_aggregate_upload_paths="$(printf '%s\n' \
    '${{ env.MATRIX_OUTPUT }}/README.md' \
    '${{ env.MATRIX_OUTPUT }}/SANITIZATION.md' \
    '${{ env.MATRIX_OUTPUT }}/fault-security-matrix.json' \
    '${{ env.MATRIX_OUTPUT }}/derivation-receipt.json' \
    '${{ env.MATRIX_OUTPUT }}/verify.sh' \
    '${{ env.MATRIX_OUTPUT }}/SHA256SUMS')"
  [[ "$aggregate_upload_paths" == "$expected_aggregate_upload_paths" ]]
}

replace_first_literal() {
  local -r input="$1"
  local -r old="$2"
  local -r new="$3"
  local temporary="$input.next"
  local -r occurrence="${4:-1}"

  awk -v old="$old" -v new="$new" -v occurrence="$occurrence" '
    index($0, old) { matches += 1 }
    !changed && matches == occurrence && index($0, old) {
      at=index($0, old)
      $0=substr($0, 1, at - 1) new substr($0, at + length(old))
      changed=1
    }
    { print }
    END { if (!changed) exit 42 }
  ' "$input" >"$temporary" || return 1
  mv -- "$temporary" "$input"
}

assert_workflow_mutation_rejected() {
  local -r name="$1"
  local -r old="$2"
  local -r new="$3"
  local -r occurrence="${4:-1}"
  local mutant="$TEST_TMP_DIR/workflow-$name.yml"

  cp -- "$CAMPAIGN_WORKFLOW" "$mutant"
  replace_first_literal "$mutant" "$old" "$new" "$occurrence" ||
    die "workflow mutation $name did not match its target"
  if validate_workflow_contract_file "$mutant" >/dev/null 2>&1; then
    die "workflow contract accepted $name mutation"
  fi
}

test_real_location_aware_projector_execution() {
  local case_root="$TEST_TMP_DIR/location-aware-projector"
  local checkout="$case_root/checkout"
  local scripts="$checkout/examples/apache-java-https/scripts"
  local projector="$scripts/project-retained-acceptance-evidence.sh"
  local acceptance="$case_root/acceptance"
  local assertion_result="$case_root/assertion"
  local receipt="$case_root/receipt.json"
  local procfd_output="$case_root/procfd-output"
  local default_output="$case_root/public/default-output"
  local claims_v1_output="$case_root/public/claims-v1-output"
  local projected_output="$case_root/public/projected"
  local projector_fd=""
  local projector_procfd=""
  local default_status=0
  local claims_v1_status=0
  local procfd_status=0

  mkdir -p -- "$case_root/public" "$case_root/private"
  mkdir -m 0700 -- "$acceptance" "$assertion_result"
  printf '%s\n' '{}' >"$receipt"
  chmod 0600 -- "$receipt"
  write_location_aware_projector_fixture "$scripts"

  set +e
  "$projector" "$acceptance" "$assertion_result" "$receipt" \
    "$default_output" >/dev/null 2>&1
  default_status=$?
  "$projector" --claims-v1 "$acceptance" "$assertion_result" "$receipt" \
    "$claims_v1_output" >/dev/null 2>&1
  claims_v1_status=$?
  set -e
  [[ "$default_status" != 0 && "$claims_v1_status" != 0 &&
    ! -e "$default_output" && ! -L "$default_output" &&
    ! -e "$claims_v1_output" && ! -L "$claims_v1_output" ]] ||
    die 'location-aware projector fixture accepted a default/v1 fallback'

  exec {projector_fd}<"$projector"
  projector_procfd="/proc/$BASHPID/fd/$projector_fd"
  set +e
  "$projector_procfd" --claims-v2 \
    "$acceptance" "$assertion_result" "$receipt" \
    "$procfd_output" >/dev/null 2>&1
  procfd_status=$?
  set -e
  exec {projector_fd}<&-
  [[ "$procfd_status" == 91 && ! -e "$procfd_output" &&
    ! -L "$procfd_output" ]] ||
    die 'location-aware projector did not reject procfd self-location'

  (
    # shellcheck source=run-retained-acceptance-campaign.sh
    source "$CAMPAIGN_RUNNER"
    PRIVATE_DIRECTORY="$case_root/private"
    CHECKOUT_DIRECTORY="$checkout"
    RAW_ACCEPTANCE="$acceptance"
    RAW_ASSERTION="$assertion_result"
    RECEIPT="$receipt"
    OUTPUT_DIRECTORY="$projected_output"
    exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY"
    assert_output_target() {
      [[ ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]]
    }
    assert_private_directory_identity() { :; }
    assert_projection_execution_authority() { :; }
    assert_result_identity() { :; }
    assert_receipt_unchanged() { :; }
    assert_source_authority_unchanged() { :; }
    assert_output_parent_unchanged() { :; }
    projection_blob_sha256() {
      sha256sum <"$projector" | awk '{print $1}'
    }

    project_claims
    [[ -f "$projected_output/projector-source" &&
      "$(<"$projected_output/projector-source")" == "$projector" &&
      -f "$projected_output/projector-selector" &&
      "$(<"$projected_output/projector-selector")" == --claims-v2 ]]
    exec {PRIVATE_DIRECTORY_FD}<&-
  ) || die 'project_claims did not execute the pinned canonical projector path'
}

test_extracted_workflow_location_aware_verifier() {
  local case_root="$TEST_TMP_DIR/location-aware-workflow-verifier"
  local public_parent="$case_root/public-parent"
  local public_output="$public_parent/projected"
  local extracted="$case_root/independent-verify.sh"
  local parent_identity=""
  local directory_identity=""
  local closure_sha256=""
  local verifier_fd=""
  local verifier_procfd=""
  local procfd_status=0

  mkdir -m 0700 -- "$case_root" "$public_parent"
  create_public_fixture "$public_output" none
  parent_identity="$(stat -Lc '%d:%i:%u:%a' -- "$public_parent")"
  directory_identity="$(stat -Lc '%d:%i:%u:%a' -- "$public_output")"
  closure_sha256="$(compute_public_fixture_closure "$public_output")"
  extract_independent_verify_step >"$extracted"
  chmod 0700 -- "$extracted"
  grep -Fq 'bash "$PUBLIC_OUTPUT/verify.sh"' "$extracted" ||
    die 'extracted independent verifier does not use its canonical path'
  if grep -Fq 'bash "/proc/$BASHPID/fd/$verify_fd"' "$extracted"; then
    die 'extracted independent verifier executes a procfd path'
  fi
  env \
    PUBLIC_PARENT="$public_parent" \
    PUBLIC_OUTPUT="$public_output" \
    EXPECTED_PARENT_IDENTITY="$parent_identity" \
    EXPECTED_DIRECTORY_IDENTITY="$directory_identity" \
    EXPECTED_CLOSURE_SHA256="$closure_sha256" \
    EXPECTED_EVIDENCE_ID="$TEST_EVIDENCE_ID" \
    bash "$extracted" ||
    die 'extracted independent workflow verifier rejected canonical execution'

  exec {verifier_fd}<"$public_output/verify.sh"
  verifier_procfd="/proc/$BASHPID/fd/$verifier_fd"
  set +e
  (CDPATH='' cd / && bash "$verifier_procfd") >/dev/null 2>&1
  procfd_status=$?
  set -e
  exec {verifier_fd}<&-
  [[ "$procfd_status" == 91 ]] ||
    die 'location-aware bundled verifier did not reject procfd self-location'
}

test_workflow_contract() {
  local public_file=""

  if command -v actionlint >/dev/null 2>&1; then
    actionlint "$CAMPAIGN_WORKFLOW" || return 1
  fi
  validate_workflow_contract_file "$CAMPAIGN_WORKFLOW" ||
    die 'workflow publication contract is incomplete'

  assert_workflow_mutation_rejected branch \
    'agent/java-remote-parent-bridge' 'agent/mutated-branch'
  assert_workflow_mutation_rejected checkout-pin \
    3d3c42e5aac5ba805825da76410c181273ba90b1 \
    0000000000000000000000000000000000000000
  assert_workflow_mutation_rejected setup-go-pin \
    b7ad1dad31e06c5925ef5d2fc7ad053ef454303e \
    0000000000000000000000000000000000000000
  assert_workflow_mutation_rejected setup-java-pin \
    03ad4de0992f5dab5e18fcb136590ce7c4a0ac95 \
    0000000000000000000000000000000000000000
  assert_workflow_mutation_rejected upload-pin \
    043fb46d1a93c77aae656e7c1c64a875d1fc6a0a \
    0000000000000000000000000000000000000000
  assert_workflow_mutation_rejected local-action \
    './.github/actions/free-disk' './.github/actions/mutated'
  assert_workflow_mutation_rejected early-event-cardinality \
    'jq -se --arg after' 'jq -e --arg after'
  assert_workflow_mutation_rejected early-head \
    'HEAD^{commit}' 'HEAD^{tree}'
  assert_workflow_mutation_rejected early-byte-gate \
    '"$disk_sha" == "$blob_sha"' '"$disk_sha" != "$blob_sha"'
  assert_workflow_mutation_rejected independent-gate \
    'id: independent_verify' 'id: mutated_verify'
  assert_workflow_mutation_rejected handoff-parent \
    'steps.campaign.outputs.public_parent_identity' \
    'steps.campaign.outputs.mutated_parent_identity'
  assert_workflow_mutation_rejected handoff-directory \
    'steps.campaign.outputs.public_directory_identity' \
    'steps.campaign.outputs.mutated_directory_identity'
  assert_workflow_mutation_rejected handoff-closure \
    'steps.campaign.outputs.public_closure_sha256' \
    'steps.campaign.outputs.mutated_closure_sha256'
  assert_workflow_mutation_rejected handoff-evidence \
    'steps.campaign.outputs.public_evidence_id' \
    'steps.campaign.outputs.mutated_evidence_id'
  assert_workflow_mutation_rejected closure-digest-gate \
    '"$observed_closure" == "$EXPECTED_CLOSURE_SHA256"' \
    '"$observed_closure" != "$EXPECTED_CLOSURE_SHA256"'
  assert_workflow_mutation_rejected unrelated-cwd \
    '(cd / && bash' '(cd "$GITHUB_WORKSPACE" && bash'
  assert_workflow_mutation_rejected verifier-procfd-execution \
    'if verify_output="$(cd / && bash "$PUBLIC_OUTPUT/verify.sh")"; then' \
    'if verify_output="$(cd / && bash "/proc/$BASHPID/fd/$verify_fd")"; then'
  assert_workflow_mutation_rejected verifier-evidence-read \
    'jq -er '\''.evidence_id'\''' 'jq -r '\''.evidence_id'\'''
  assert_workflow_mutation_rejected verifier-evidence-shape \
    '"$evidence_id" == "$EXPECTED_EVIDENCE_ID"' \
    '"$evidence_id" =~ ^.*$'
  assert_workflow_mutation_rejected verifier-stdout-contract \
    'bounded claim bundle internally consistent (not authenticated): $evidence_id' \
    'mutated verifier success: $evidence_id'
  assert_workflow_mutation_rejected privacy-always \
    'if: always()' "if: steps.campaign.outcome == 'success'"
  assert_workflow_mutation_rejected privacy-failure-branch \
    'if [[ "$CAMPAIGN_OUTCOME" != success ]]; then' \
    'if [[ "$CAMPAIGN_OUTCOME" == success ]]; then'
  assert_workflow_mutation_rejected privacy-empty-branch \
    '[[ -z "$sibling_inventory" ]]' '[[ -n "$sibling_inventory" ]]'
  assert_workflow_mutation_rejected privacy-independent \
    '"$INDEPENDENT_OUTCOME" == success' '"$INDEPENDENT_OUTCOME" != success'
  assert_workflow_mutation_rejected privacy-prefix \
    "obi-java-remote-parent-acceptance.*" 'mutated-private-prefix.*'
  assert_workflow_mutation_rejected upload-cancelled \
    '!cancelled()' 'cancelled()'
  assert_workflow_mutation_rejected upload-campaign \
    "          steps.campaign.outcome == 'success'" \
    "          steps.campaign.outcome != 'success'"
  assert_workflow_mutation_rejected upload-independent \
    "steps.independent_verify.outcome == 'success'" \
    "steps.independent_verify.outcome != 'success'"
  assert_workflow_mutation_rejected upload-privacy \
    "steps.privacy.outcome == 'success'" \
    "steps.privacy.outcome != 'success'"
  for public_file in README.md SANITIZATION.md acceptance-claims.json \
    authority-summary.json derivation-receipt.json verify.sh SHA256SUMS; do
    assert_workflow_mutation_rejected "upload-$public_file" \
      '${{ env.PUBLIC_OUTPUT }}/'"$public_file" \
      '${{ env.PUBLIC_OUTPUT }}/raw-private.json'
  done
  assert_workflow_mutation_rejected cache \
    'cache: false' 'cache: true'
  assert_workflow_mutation_rejected profile-timeout \
    'timeout-minutes: 180' 'timeout-minutes: 181'
  assert_workflow_mutation_rejected profile-fail-fast \
    'fail-fast: false' 'fail-fast: true'
  assert_workflow_mutation_rejected profile-role \
    '          - all-auto' '          - mutated-auto'
  assert_workflow_mutation_rejected profile-mode \
    $'--profile \'${{ matrix.role }}\' "$CELL_OUTPUT"' \
    $'--profile \'${{ matrix.role }}\' "$CELL_PARENT"'
  assert_workflow_mutation_rejected profile-artifact-name \
    'java-remote-parent-fault-security-cell-${{ matrix.role }}-' \
    'mutated-fault-security-cell-${{ matrix.role }}-'
  assert_workflow_mutation_rejected profile-retention \
    'retention-days: 90' 'retention-days: 89'
  assert_workflow_mutation_rejected profile-persist-credentials \
    'persist-credentials: false' 'persist-credentials: true' 2
  assert_workflow_mutation_rejected profile-fetch-depth \
    'fetch-depth: 0' 'fetch-depth: 1' 2
  assert_workflow_mutation_rejected aggregate-needs \
    'needs: fault-security-profile' 'needs: acceptance'
  assert_workflow_mutation_rejected aggregate-timeout \
    'timeout-minutes: 30' 'timeout-minutes: 31'
  assert_workflow_mutation_rejected aggregate-persist-credentials \
    'persist-credentials: false' 'persist-credentials: true' 3
  assert_workflow_mutation_rejected aggregate-fetch-depth \
    'fetch-depth: 0' 'fetch-depth: 1' 3
  assert_workflow_mutation_rejected download-pin \
    3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c \
    0000000000000000000000000000000000000000
  assert_workflow_mutation_rejected download-pattern \
    'java-remote-parent-fault-security-cell-*-${{ github.run_id }}-${{ github.run_attempt }}' \
    'java-remote-parent-fault-security-cell-*'
  assert_workflow_mutation_rejected aggregate-mode \
    '--aggregate-cells-v1' '--aggregate-cells-v2'
  assert_workflow_mutation_rejected aggregate-input-order \
    '"${prefix}all-unix${suffix}" \' \
    '"${prefix}all-auto${suffix}" \'
  assert_workflow_mutation_rejected aggregate-artifact-name \
    'name: java-remote-parent-fault-security-${{ github.run_id }}-${{ github.run_attempt }}' \
    'name: mutated-fault-security-${{ github.run_id }}-${{ github.run_attempt }}'
  assert_workflow_mutation_rejected aggregate-output \
    '${{ env.MATRIX_OUTPUT }}/fault-security-matrix.json' \
    '${{ env.CELL_ROOT }}/fault-security-matrix.json'
  assert_workflow_mutation_rejected aggregate-inventory-gate \
    '[[ "$observed" == "$expected" ]]' '[[ "$observed" != "$expected" ]]' 3
}

test_static_privacy_and_wiring_contract() {
  ! grep -Fq 'BASH_COMMAND' "$CAMPAIGN_RUNNER" || return 1
  ! grep -Fq 'COMMAND_LOGS' "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'COMMAND_OUTPUT_SHA256["$command_id"]="$digest"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'COMMAND_DIRECTORY_IDENTITY' "$CAMPAIGN_RUNNER" || return 1
  grep -Fq '"/proc/$BASHPID/fd/$directory_fd/$leaf"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'RESULT_SNAPSHOT_IDENTITY["$snapshot"]="$sealed_identity"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'find -H "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD" -xdev -depth' \
    "$CAMPAIGN_RUNNER" || return 1
  ! grep -Fq 'rm -rf --one-file-system -- "$PRIVATE_DIRECTORY"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'open_exclusive_output_fd "$command_directory_fd" "$log_name" log_fd' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'public_parent_identity=$OUTPUT_PARENT_IDENTITY' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'public_directory_identity=$OUTPUT_DIRECTORY_IDENTITY' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'public_closure_sha256=$PUBLIC_CLOSURE_SHA256' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'output_contract:' "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'bytes: "exact-command-order-no-normalization"' "$CAMPAIGN_RUNNER" ||
    return 1
  grep -Fq 'stream: "combined-stdout-stderr"' "$CAMPAIGN_RUNNER" || return 1
  [[ "$(grep -Fc \
    'if projector_execute "$projector" --claims-v2 "$RAW_ACCEPTANCE"' \
    "$CAMPAIGN_RUNNER")" == 1 ]] || return 1
  ! grep -Fq 'if projector_execute "$projector" "$RAW_ACCEPTANCE"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq '"${PUBLIC_VERIFY_TIMEOUT_SECONDS}s" bash "$verifier")"; then' \
    "$CAMPAIGN_RUNNER" || return 1
  ! grep -Fq 'projector_execution_path=' "$CAMPAIGN_RUNNER" || return 1
  ! grep -Fq 'verifier_execution_path=' "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'run-retained-acceptance-campaign_test.sh' \
    "$TEST_SCRIPT_DIR/run_test.sh" || return 1
  [[ "$(grep -c 'run-retained-acceptance-campaign_test.sh' \
    "$TEST_SCRIPT_DIR/run_test.sh")" == 1 ]]
}

main() {
  create_test_tmp_dir
  test_lock_validation_and_fd_closure
  test_timeout_budget_and_producer_umask
  test_real_git_private_checkout_modes
  test_recorded_command_timeout_classification
  test_recorded_log_identity_and_fd_closure
  test_recorded_log_preopen_leaf_fence
  test_command_directory_and_working_root_fences
  test_state_transition_rejection
  test_private_cleanup_mount_fence
  test_github_authority_mutations
  test_real_location_aware_projector_execution
  test_success_and_failure_campaigns
  test_acceptance_failure_classification
  test_workflow_contract
  test_extracted_workflow_location_aware_verifier
  test_static_privacy_and_wiring_contract
  printf 'retained acceptance campaign transaction and mutation tests passed\n'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
