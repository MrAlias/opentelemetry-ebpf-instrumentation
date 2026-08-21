#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

TEST_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TEST_DIRECTORY
CAMPAIGN_DIRECTORY="$(cd -- "$TEST_DIRECTORY/.." && pwd -P)"
readonly CAMPAIGN_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$CAMPAIGN_DIRECTORY/run-cell.sh"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  return 1
}

expect_status_mapping() {
  local -r status="$1"
  local -r exit_status="$2"
  local -r expected="$3"

  if compatibility_provider_exit_matches_status "$status" "$exit_status"; then
    [[ "$expected" == accept ]] ||
      fail "accepted provider status mapping $status/$exit_status"
  else
    [[ "$expected" == reject ]] ||
      fail "rejected provider status mapping $status/$exit_status"
  fi
}

main() {
  local -r test_root="${1:?test root is required}"
  local -r source_authority="${2:?source authority is required}"
  local -r fixture="$TEST_DIRECTORY/provider-boundary-fixture.sh"
  local -r campaign=compatibility
  local -r cell_id=k-upstream612-host-v2-getsockopt
  local revision=""
  local plan=""
  local plan_sha256=""
  local case_root=""
  local private=""
  local requested=""
  local result=""
  local manifest=""
  local sealed=""
  local run_status=0
  local mode=""
  local expected_reason=""

  expect_status_mapping pass 0 accept
  expect_status_mapping pass 1 reject
  expect_status_mapping fail 1 accept
  expect_status_mapping fail 0 reject
  expect_status_mapping unsupported 78 accept
  expect_status_mapping unsupported 1 reject
  expect_status_mapping untested 69 accept
  expect_status_mapping untested 0 reject

  compatibility_validate_plan "$campaign"
  export OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256
  OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256="$(compatibility_provider_registry_sha256)"
  plan="$(compatibility_plan_path "$campaign")"
  revision="$(compatibility_campaign_revision "$campaign")"
  plan_sha256="$(compatibility_sha256 "$plan")"
  for mode in malformed missing pass-exit-one untested-exit-zero; do
    case "$mode" in
      malformed|missing) expected_reason="provider-boundary-result-invalid" ;;
      *) expected_reason="provider-exit-status-mismatch" ;;
    esac
    case_root="$test_root/direct-launcher-$mode"
    private="$case_root/private"
    requested="$private/requested.json"
    result="$private/provider-result.json"
    manifest="$case_root/private.sha256"
    sealed="$case_root/cell.json"
    install -d -m 0700 -- "$private"
    compatibility_select_cell "$campaign" "$cell_id" "$requested"
    export OBI_COMPATIBILITY_PROVIDER_RESULT="$result"
    export OBI_COMPATIBILITY_BOUNDARY_FIXTURE_MODE="$mode"
    if run_provider_launcher_boundary \
      "$campaign" "$revision" "$plan_sha256" "$requested" "$fixture" \
      "$private" "$result" "$source_authority"; then
      run_status=0
    else
      run_status=$?
    fi
    [[ "$run_status" == 1 ]] ||
      fail "$mode direct launcher boundary did not normalize to fail"
    jq -e --arg reason "$expected_reason" '
      .status == "fail" and .reason == $reason and
      .provider_exit_status == 1 and
      .assertions.classification == "provider-contract" and
      .assertions.contract_failure == true and
      .infrastructure_failure == false
    ' "$result" >/dev/null ||
      fail "$mode direct launcher boundary did not emit contract-failure evidence"
    compatibility_directory_manifest "$private" "$manifest"
    "$CAMPAIGN_DIRECTORY/seal-cell.sh" \
      --campaign "$campaign" \
      --cell "$requested" \
      --provider-result "$result" \
      --provider-launcher "$fixture" \
      --private-directory "$private" \
      --private-manifest "$manifest" \
      --output "$sealed"
    jq -e --arg reason "$expected_reason" '
      .status == "fail" and .reason == $reason and
      .provider.launcher_exit_status == 1 and
      .assertions.classification == "provider-contract"
    ' "$sealed" >/dev/null ||
      fail "$mode direct launcher boundary did not seal as fail"
  done
}

main "$@"
