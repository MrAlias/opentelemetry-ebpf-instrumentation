#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

# Test seams below deliberately override sourced functions inside a subshell.
# shellcheck disable=SC2317

SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=run-retained-fault-security-campaign.sh
source "$SCRIPT_DIRECTORY/run-retained-fault-security-campaign.sh"

TEST_ROOT=''

fail() {
  printf '%s: %s\n' "${BASH_SOURCE[0]##*/}" "$*" >&2
  return 1
}

cleanup() {
  local status="$?"

  trap - EXIT
  if [[ -n "$TEST_ROOT" &&
    "$TEST_ROOT" =~ ^/tmp/obi-fault-security-campaign-test\.[A-Za-z0-9]{6}$ &&
    -d "$TEST_ROOT" && ! -L "$TEST_ROOT" ]]; then
    chmod -R u+rwX -- "$TEST_ROOT" 2>/dev/null || true
    find -- "$TEST_ROOT" -xdev -depth -delete >/dev/null 2>&1 || true
  fi
  exit "$status"
}

assert_profile_roster() {
  local index=0
  local observed=''
  local -a expected=(
    './examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3'
    './examples/apache-java-https/run.sh --transport unix --agent otel --tls TLSv1.3'
    './examples/apache-java-https/run.sh --transport auto --agent otel --tls TLSv1.3'
    './examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3 --scenario pid-reuse'
    './examples/apache-java-https/run.sh --transport unix --agent otel --tls TLSv1.3 --scenario pid-reuse'
  )

  [[ "${#PROFILE_ROLES[@]}" == 5 && "${#PROFILE_KINDS[@]}" == 5 &&
    "${#PROFILE_TRANSPORTS[@]}" == 5 && "${#PROFILE_SCENARIOS[@]}" == 5 ]] ||
    fail 'profile roster is not an exact five-cell matrix' || return 1
  [[ "${PUBLIC_FILES[*]}" == \
    'README.md SANITIZATION.md fault-security-matrix.json derivation-receipt.json verify.sh SHA256SUMS' ]] ||
    fail 'public roster is not the exact ordered six-file closure' || return 1
  [[ "${PROFILE_PUBLIC_FILES[*]}" == \
    'SANITIZATION.md profile.json verify.sh SHA256SUMS' ]] ||
    fail 'profile handoff is not the exact ordered four-file closure' || return 1
  for index in "${!expected[@]}"; do
    build_profile_command "$index" || return 1
    observed="$(printf '%s ' "${PROFILE_COMMAND[@]}")"
    observed="${observed% }"
    [[ "$observed" == "${expected[index]}" ]] ||
      fail "profile $index command drifted" || return 1
  done
  if build_profile_command 5 >/dev/null 2>&1; then
    fail 'out-of-roster profile was accepted'
  fi
}

assert_profile_cli_selection() {
  if ! (
    run_campaign() {
      [[ "$PROFILE_MODE" == true && "$SELECTED_PROFILE_INDEX" == 2 &&
        "$OUTPUT_DIRECTORY" == /tmp/profile-output-fixture ]]
    }
    campaign_entry --profile all-auto /tmp/profile-output-fixture
  ); then
    fail 'exact profile CLI role was not selected'
  fi
  if (
    run_campaign() { :; }
    campaign_entry --profile unknown /tmp/profile-output-fixture
  ) >/dev/null 2>&1; then
    fail 'unknown profile CLI role was accepted'
  fi
}

assert_profile_workflow_contract() {
  local -r workflow="$SCRIPT_DIRECTORY/../../../.github/workflows/java_remote_parent_acceptance_claims.yml"
  grep -Fq -- 'fail-fast: false' "$workflow" ||
    fail 'fault/security profile matrix lost fail-fast false'
  grep -Fq -- 'timeout-minutes: 180' "$workflow" ||
    fail 'fault/security profile jobs lost their bounded timeout'
  grep -Fq -- '--aggregate-cells-v1' "$workflow" ||
    fail 'fault/security final aggregation is absent'
  grep -Fq -- 'retention-days: 90' "$workflow" ||
    fail 'sanitized profile retention is not 90 days'
}

assert_private_descriptor_destroy() {
  local owned_path=''

  # These globals are consumed by the sourced campaign helpers.
  # shellcheck disable=SC2034
  PRIVATE_CREATED=false
  PRIVATE_DIRECTORY=''
  PRIVATE_DIRECTORY_FD=''
  create_private_transaction ||
    fail 'could not create the descriptor-pinned private transaction fixture'
  owned_path="$PRIVATE_DIRECTORY"
  mkdir -p -- "$owned_path/one/two"
  printf 'private canary\n' >"$owned_path/one/two/evidence.log"
  chmod 0400 -- "$owned_path/one/two/evidence.log"
  destroy_private_transaction ||
    fail 'descriptor-pinned private transaction destruction failed'
  [[ ! -e "$owned_path" && ! -L "$owned_path" &&
    -z "$PRIVATE_DIRECTORY_FD" ]] ||
    fail 'private transaction destruction retained raw residue'
}

assert_result_discovery() {
  local results=''
  local before=''
  local after=''
  local resolved=''

  PRIVATE_DIRECTORY="$TEST_ROOT/private"
  CHECKOUT_DIRECTORY="$PRIVATE_DIRECTORY/source"
  results="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  mkdir -p -- "$results/existing"
  before="$PRIVATE_DIRECTORY/before"
  after="$PRIVATE_DIRECTORY/after"
  snapshot_result_names "$before"
  mkdir -- "$results/new-result"
  snapshot_result_names "$after"
  resolved="$(resolve_new_result "$before" "$after")"
  [[ "$resolved" == "$results/new-result" ]] ||
    fail 'single result discovery did not resolve the new raw directory' ||
    return 1

  chmod u+w -- "$after"
  printf '%s\n' existing new-result second-result | LC_ALL=C sort >"$after"
  mkdir -- "$results/second-result"
  if resolve_new_result "$before" "$after" >/dev/null 2>&1; then
    fail 'ambiguous two-result discovery was accepted'
  fi

  : >"$results/not-a-directory"
  chmod u+w -- "$after"
  if snapshot_result_names "$after" >/dev/null 2>&1; then
    fail 'non-directory raw result entry was accepted'
  fi
  rm -- "$results/not-a-directory"
  ln -s -- new-result "$results/result-link"
  if snapshot_result_names "$after" >/dev/null 2>&1; then
    fail 'symbolic-link raw result entry was accepted'
  fi
}

write_public_fixture() {
  local -r directory="$1"
  local file=''

  mkdir -- "$directory"
  for file in "${PUBLIC_FILES[@]}"; do
    printf '%s\n' "$file fixture" >"$directory/$file"
  done
  chmod 0444 -- "$directory"/*
  chmod 0555 -- "$directory"
}

assert_public_closure_mutations() {
  local public_directory="$TEST_ROOT/public/matrix"

  mkdir -m 0700 -- "$TEST_ROOT/public"
  write_public_fixture "$public_directory"
  OUTPUT_DIRECTORY="$public_directory"
  compute_public_closure || fail 'exact six-file public closure was rejected'
  [[ "$PUBLIC_CLOSURE_SHA256" =~ ^[0-9a-f]{64}$ &&
    "$PUBLIC_EVIDENCE_ID" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'public closure identities were not bounded hashes'

  chmod 0755 -- "$public_directory"
  if compute_public_closure >/dev/null 2>&1; then
    fail 'world-writable public directory mode mutation was accepted'
  fi
  chmod 0555 -- "$public_directory"
  chmod 0644 -- "$public_directory/README.md"
  if compute_public_closure >/dev/null 2>&1; then
    fail 'writable public file mode mutation was accepted'
  fi
  chmod 0444 -- "$public_directory/README.md"
  chmod u+w -- "$public_directory"
  : >"$public_directory/extra-private.log"
  chmod 0444 -- "$public_directory/extra-private.log"
  chmod 0555 -- "$public_directory"
  if compute_public_closure >/dev/null 2>&1; then
    fail 'extra public residue was accepted'
  fi
}

assert_failed_public_delete_stays_owned() {
  local output="$TEST_ROOT/public-delete"

  mkdir -- "$output"
  printf 'bounded output\n' >"$output/README.md"
  chmod 0444 -- "$output/README.md"
  chmod 0555 -- "$output"
  if (
    OUTPUT_DIRECTORY="$output"
    # Consumed by remove_public_output from the sourced campaign.
    # shellcheck disable=SC2034
    OUTPUT_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$output")"
    OUTPUT_CREATED=true
    # This seam models a filesystem deletion failure after the output has
    # been identity-pinned. The campaign must not clear its ownership state.
    find() { return 73; }
    if remove_public_output; then
      exit 1
    fi
    [[ "$OUTPUT_CREATED" == true && -d "$output" &&
      -f "$output/README.md" ]]
  ); then
    :
  else
    fail 'failed public deletion was masked or ownership state was cleared'
  fi
}

assert_unsupported_pid_reuse_stays_failed() {
  if (
    snapshot_result_names() { : >"$1"; }
    build_profile_command() { PROFILE_COMMAND=(false); }
    run_private_command() {
      case "$1" in
        run-pid-reuse-getsockopt) return 42 ;;
        *) return 1 ;;
      esac
    }
    run_scoped_cleanup() {
      # Consumed by run_profile from the sourced campaign.
      # shellcheck disable=SC2034
      CLEANUP_REQUIRED=false
      return 0
    }
    run_profile 3
  ); then
    fail 'unsupported PID-reuse producer failure became a passing profile'
  fi
}

main() {
  TEST_ROOT="$(mktemp -d /tmp/obi-fault-security-campaign-test.XXXXXX)"
  TEST_ROOT="$(CDPATH='' cd -- "$TEST_ROOT" && pwd -P)"
  trap cleanup EXIT

  assert_profile_roster
  assert_profile_cli_selection
  assert_profile_workflow_contract
  assert_private_descriptor_destroy
  assert_result_discovery
  assert_public_closure_mutations
  assert_failed_public_delete_stays_owned
  assert_unsupported_pid_reuse_stays_failed
  printf 'fault/security campaign mutation tests passed\n'
}

main "$@"
