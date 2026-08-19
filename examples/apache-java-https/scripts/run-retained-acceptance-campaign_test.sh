#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# This test intentionally sources the runner, replaces dependency seams, and
# exercises the resulting functions from subshells.
# shellcheck disable=SC1090,SC1091,SC2016,SC2034,SC2153,SC2317,SC2329

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

mock_campaign_execute() {
  local -r command_id="$1"
  shift
  local results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local acceptance_result=""
  local replacement=""
  local holder_pid=""

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
  local -r acceptance="$2"
  local -r assertion_result="$3"
  local -r receipt="$4"
  local -r output="$5"
  local receipt_text=""
  local mutant=""
  local receipt_mutation=""

  [[ "$projector" == \
      "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh" &&
    "$acceptance" == "$RAW_ACCEPTANCE" &&
    "$assertion_result" == "$RAW_ASSERTION" &&
    "$receipt" == "$RECEIPT" && "$output" == "$OUTPUT_DIRECTORY" ]] || return 1
  : >"$CASE_ROOT/projector-invoked"
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
    projector_execute() { mock_projector_execute "$@"; }
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
  local row_forgery_root=""
  local hardlink_root=""
  local case_root=""
  local -a failure_mutations=(
    assertion-wrong-exit cleanup-failure missing-result two-results
    wrong-result-mode wrong-lock-mode lock-hardlink lock-symlink
    unrelated-addition held-lock lock-replacement lock-removal
    root-replacement root-disappearance acceptance-result-replacement
    before-snapshot-rewrite before-snapshot-replacement before-snapshot-mode
    cleanup-run-sh-bytes cleanup-run-sh-symlink
    cleanup-checkout-root-replacement
    projector-bytes projector-symlink verifier-bytes verifier-symlink
    projector-failure public-extra-file public-verify-failure
    public-verify-missing public-verify-wrong public-verify-nonhex
    public-verify-extra-line public-verify-suffix public-evidence-id-nonhex
  )

  success_root="$(run_mock_campaign_case success none success)"
  assert_success_state_machine "$success_root/stderr.log"
  assert_observed_receipt "$success_root/observed-receipt.json"
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
    esac
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
      COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
      COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
        "$COMMAND_DIRECTORY")"
      COMMAND_COUNT=0
      COMMAND_ROWS_MEMORY=()
      COMMAND_OUTPUT_SHA256=()
      run_recorded_command clone 0 "$PRIVATE_DIRECTORY" \
        bash -c 'printf "recorded-output-%s\\n" "$1"' _ "$iteration" \
        >/dev/null 2>&1
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

validate_workflow_contract_file() {
  local -r workflow="$1"
  local upload_condition=""
  local upload_paths=""
  local expected_paths=""
  local early_line=""
  local free_disk_line=""
  local literal=""
  local -a exact_literals=(
    '      - agent/java-remote-parent-bridge'
    '    runs-on: ubuntu-24.04'
    '    timeout-minutes: 240'
    '  group: java-remote-parent-acceptance-claims-${{ github.workflow }}-${{ github.ref }}'
    '  cancel-in-progress: false'
    '      PUBLIC_PARENT: /tmp/obi-java-remote-parent-public-${{ github.run_id }}-${{ github.run_attempt }}'
    '      PUBLIC_OUTPUT: /tmp/obi-java-remote-parent-public-${{ github.run_id }}-${{ github.run_attempt }}/java-remote-parent-claims-${{ github.sha }}'
    '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
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
    '          [[ "$evidence_id" =~ ^[0-9a-f]{64}$ ]]'
    '          verify_output="$(cd / && bash "$PUBLIC_OUTPUT/verify.sh")"'
    '            "bounded claim bundle internally consistent (not authenticated): $evidence_id" ]]'
    '          if-no-files-found: error'
    '          include-hidden-files: false'
  )

  [[ "$(grep -Ec '^[[:space:]]+uses:' "$workflow")" == 5 &&
    "$(grep -Fc 'actions/upload-artifact@' "$workflow")" == 1 &&
    "$(grep -Fc 'RUNNER_ENVIRONMENT: ${{ runner.environment }}' "$workflow")" == 2 ]] ||
    return 1
  for literal in "${exact_literals[@]}"; do
    workflow_has_once "$workflow" "$literal" || {
      printf 'workflow literal is not exact: %s\n' "$literal" >&2
      return 1
    }
  done
  if grep -Eq 'workflow_dispatch:|pull_request:|schedule:|^[[:space:]]+paths:|^[[:space:]]+tags:|continue-on-error:|actions/cache@|download-artifact@' \
    "$workflow"; then
    return 1
  fi
  early_line="$(grep -nF -m1 -- '- name: Verify exact push and tracked execution bytes' \
    "$workflow")" || return 1
  free_disk_line="$(grep -nF -m1 -- '- name: Reclaim hosted-runner disk space' \
    "$workflow")" || return 1
  early_line="${early_line%%:*}"
  free_disk_line="${free_disk_line%%:*}"
  (( early_line < free_disk_line )) || return 1
  upload_condition="$(awk '
    /- name: Upload verified bounded-claim projection/ { upload=1 }
    upload && /if: >-/ { condition=1; next }
    condition && /uses:/ { exit }
    condition { gsub(/[[:space:]]/, ""); printf "%s", $0 }
  ' "$workflow")" || return 1
  [[ "$upload_condition" == \
    "!cancelled()&&steps.campaign.outcome=='success'&&steps.independent_verify.outcome=='success'&&steps.privacy.outcome=='success'" ]] ||
    return 1
  upload_paths="$(awk '
    /^[[:space:]]+path: \|$/ { paths=1; next }
    paths && /^[[:space:]]+if-no-files-found:/ { exit }
    paths { sub(/^[[:space:]]+/, ""); print }
  ' "$workflow")" || return 1
  expected_paths="$(printf '%s\n' \
    '${{ env.PUBLIC_OUTPUT }}/README.md' \
    '${{ env.PUBLIC_OUTPUT }}/SANITIZATION.md' \
    '${{ env.PUBLIC_OUTPUT }}/acceptance-claims.json' \
    '${{ env.PUBLIC_OUTPUT }}/authority-summary.json' \
    '${{ env.PUBLIC_OUTPUT }}/derivation-receipt.json' \
    '${{ env.PUBLIC_OUTPUT }}/verify.sh' \
    '${{ env.PUBLIC_OUTPUT }}/SHA256SUMS')"
  [[ "$upload_paths" == "$expected_paths" ]]
}

replace_first_literal() {
  local -r input="$1"
  local -r old="$2"
  local -r new="$3"
  local temporary="$input.next"

  awk -v old="$old" -v new="$new" '
    !changed && index($0, old) {
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
  local mutant="$TEST_TMP_DIR/workflow-$name.yml"

  cp -- "$CAMPAIGN_WORKFLOW" "$mutant"
  replace_first_literal "$mutant" "$old" "$new" ||
    die "workflow mutation $name did not match its target"
  if validate_workflow_contract_file "$mutant" >/dev/null 2>&1; then
    die "workflow contract accepted $name mutation"
  fi
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
  assert_workflow_mutation_rejected unrelated-cwd \
    '(cd / && bash' '(cd "$GITHUB_WORKSPACE" && bash'
  assert_workflow_mutation_rejected verifier-evidence-read \
    'jq -er '\''.evidence_id'\''' 'jq -r '\''.evidence_id'\'''
  assert_workflow_mutation_rejected verifier-evidence-shape \
    '^[0-9a-f]{64}$' '^.*$'
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
}

test_static_privacy_and_wiring_contract() {
  ! grep -Fq 'BASH_COMMAND' "$CAMPAIGN_RUNNER" || return 1
  ! grep -Fq 'COMMAND_LOGS' "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'COMMAND_OUTPUT_SHA256["$command_id"]="$digest"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'COMMAND_DIRECTORY_IDENTITY' "$CAMPAIGN_RUNNER" || return 1
  grep -Fq '"/proc/$BASHPID/fd/$command_directory_fd/$log_name"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'RESULT_SNAPSHOT_IDENTITY["$snapshot"]="$sealed_identity"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'rm -rf --one-file-system -- "$PRIVATE_DIRECTORY"' \
    "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'output_contract:' "$CAMPAIGN_RUNNER" || return 1
  grep -Fq 'bytes: "exact-command-order-no-normalization"' "$CAMPAIGN_RUNNER" ||
    return 1
  grep -Fq 'stream: "combined-stdout-stderr"' "$CAMPAIGN_RUNNER" || return 1
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
  test_command_directory_and_working_root_fences
  test_state_transition_rejection
  test_private_cleanup_mount_fence
  test_github_authority_mutations
  test_success_and_failure_campaigns
  test_workflow_contract
  test_static_privacy_and_wiring_contract
  printf 'retained acceptance campaign transaction and mutation tests passed\n'
}

main "$@"
