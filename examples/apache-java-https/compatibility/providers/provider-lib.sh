#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

PROVIDER_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROVIDER_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$PROVIDER_DIRECTORY/../lib.sh"

provider_require_environment() {
  : "${OBI_COMPATIBILITY_CAMPAIGN:?OBI_COMPATIBILITY_CAMPAIGN is required}"
  : "${OBI_COMPATIBILITY_CAMPAIGN_REVISION:?OBI_COMPATIBILITY_CAMPAIGN_REVISION is required}"
  : "${OBI_COMPATIBILITY_PLAN_SHA256:?OBI_COMPATIBILITY_PLAN_SHA256 is required}"
  : "${OBI_COMPATIBILITY_CELL_JSON:?OBI_COMPATIBILITY_CELL_JSON is required}"
  : "${OBI_COMPATIBILITY_PRIVATE_DIR:?OBI_COMPATIBILITY_PRIVATE_DIR is required}"
  : "${OBI_COMPATIBILITY_PROVIDER_RESULT:?OBI_COMPATIBILITY_PROVIDER_RESULT is required}"
  : "${OBI_COMPATIBILITY_SOURCE_AUTHORITY:?OBI_COMPATIBILITY_SOURCE_AUTHORITY is required}"
  : "${OBI_COMPATIBILITY_SOURCE_AUTHORITY_SHA256:?OBI_COMPATIBILITY_SOURCE_AUTHORITY_SHA256 is required}"
  : "${OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256:?OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256 is required}"

  compatibility_require_regular_file "$OBI_COMPATIBILITY_CELL_JSON"
  compatibility_validate_json_file "$OBI_COMPATIBILITY_CELL_JSON"
  compatibility_validate_source_authority "$OBI_COMPATIBILITY_SOURCE_AUTHORITY"
  [[ "$(compatibility_sha256 "$OBI_COMPATIBILITY_SOURCE_AUTHORITY")" == "$OBI_COMPATIBILITY_SOURCE_AUTHORITY_SHA256" ]] ||
    compatibility_die "source authority digest mismatch" || return
  compatibility_validate_provider_registry
  [[ "$(compatibility_sha256 "$COMPATIBILITY_PROVIDER_REGISTRY")" == \
    "$OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256" ]] ||
    compatibility_die "provider registry digest mismatch" || return
  compatibility_require_directory "$OBI_COMPATIBILITY_PRIVATE_DIR"
  [[ "$OBI_COMPATIBILITY_PLAN_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    compatibility_die "invalid campaign plan digest"
  [[ ! -e "$OBI_COMPATIBILITY_PROVIDER_RESULT" &&
    ! -L "$OBI_COMPATIBILITY_PROVIDER_RESULT" ]] ||
    compatibility_die "provider result already exists"
}

provider_source_json() {
  compatibility_source_checkout_json
}

provider_write_untested() {
  local -r reason="$1"
  local -r provider_name="$2"
  shift 2
  local requested=""
  local source_identity=""
  local command_json=""
  local adapter_path=""
  local adapter_sha256=""

  [[ "$reason" =~ ^[a-z0-9][a-z0-9-]{0,95}$ ]] ||
    compatibility_die "invalid untested reason: $reason" || return
  requested="$(jq -cS . "$OBI_COMPATIBILITY_CELL_JSON")" || return
  source_identity="$(provider_source_json)" || return
  command_json="$(printf '%s\0' "$@" | jq -Rs 'split("\u0000")[:-1]')" || return
  adapter_path="$(readlink -f -- "$0")" || return
  compatibility_require_regular_file "$adapter_path" || return
  adapter_sha256="$(compatibility_sha256 "$adapter_path")" || return
  jq -nS \
    --arg campaign "$OBI_COMPATIBILITY_CAMPAIGN" \
    --arg campaign_revision "$OBI_COMPATIBILITY_CAMPAIGN_REVISION" \
    --arg plan_sha256 "$OBI_COMPATIBILITY_PLAN_SHA256" \
    --arg provider "$provider_name" \
    --arg reason "$reason" \
    --argjson requested "$requested" \
    --argjson source "$source_identity" \
    --argjson command_argv "$command_json" \
    --arg adapter_sha256 "$adapter_sha256" \
    '{
      schema: "compatibility-provider-result-v1",
      campaign: $campaign,
      campaign_revision: $campaign_revision,
      plan_sha256: $plan_sha256,
      cell_id: $requested.id,
      provider: $provider,
      status: "untested",
      reason: $reason,
      attempted: false,
      infrastructure_failure: true,
      requested: $requested,
      provider_registry_sha256: $ENV.OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256,
      external_driver: null,
      command: {
        executed: false,
        argv: $command_argv,
        adapter_sha256: $adapter_sha256,
        exit_status: null
      },
      source: $source,
      runtime: null,
      artifacts: null,
      assertions: null,
      evidence_index: null,
      raw_evidence: null
    }' >"$OBI_COMPATIBILITY_PROVIDER_RESULT"
  chmod 0600 -- "$OBI_COMPATIBILITY_PROVIDER_RESULT"
}

provider_external_driver_identity() {
  local -r driver="$1"
  local metadata=""
  local owner=""
  local mode=""
  local links=""
  local size=""

  [[ "$driver" == /* && -f "$driver" && ! -L "$driver" && -x "$driver" ]] || return 1
  metadata="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$driver")" || return
  IFS=: read -r _ _ owner mode links size <<<"$metadata"
  [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 1
  [[ "$links" == 1 && "$size" =~ ^[1-9][0-9]*$ ]] || return 1
  (( size <= 16777216 && (8#$mode & 0022) == 0 )) || return 1
  printf '%s:%s\n' "$metadata" "$(compatibility_sha256 "$driver")"
}

provider_external_driver_is_unchanged() {
  local -r driver="$1"
  local -r expected_identity="$2"
  local actual_identity=""

  actual_identity="$(provider_external_driver_identity "$driver")" || return 1
  [[ "$actual_identity" == "$expected_identity" ]]
}

provider_write_contract_fail() {
  local -r reason="$1"
  local -r provider_name="$2"
  local -r driver="$3"
  local -r driver_sha256="$4"
  local -r invocation_status="$5"
  local -r rejected_result="$6"
  shift 6
  local evidence_directory="$OBI_COMPATIBILITY_PRIVATE_DIR/provider-contract-evidence"
  local evidence_manifest="$OBI_COMPATIBILITY_PRIVATE_DIR/provider-contract-evidence.sha256"
  local requested=""
  local source_identity=""
  local command_json=""
  local command_adapter_sha256="$driver_sha256"
  local candidate=""
  local size=0

  install -d -m 0700 -- "$evidence_directory"
  printf 'reason=%s\nprovider=%s\ninvocation_status=%s\n' \
    "$reason" "$provider_name" "$invocation_status" \
    >"$evidence_directory/contract-failure.txt"
  chmod 0600 -- "$evidence_directory/contract-failure.txt"
  for candidate in \
    "$OBI_COMPATIBILITY_PRIVATE_DIR/external-provider.stdout" \
    "$OBI_COMPATIBILITY_PRIVATE_DIR/external-provider.stderr"; do
    if [[ -f "$candidate" && ! -L "$candidate" ]]; then
      install -m 0600 -- "$candidate" "$evidence_directory/${candidate##*/}"
    fi
  done
  if [[ -f "$rejected_result" && ! -L "$rejected_result" ]]; then
    size="$(stat -Lc '%s' -- "$rejected_result")" || return
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size <= 4194304 )); then
      install -m 0600 -- "$rejected_result" \
        "$evidence_directory/provider-result.rejected"
    fi
  fi
  compatibility_directory_manifest "$evidence_directory" "$evidence_manifest" || return
  requested="$(jq -cS . "$OBI_COMPATIBILITY_CELL_JSON")" || return
  source_identity="$(provider_source_json)" || return
  command_json="$(printf '%s\0' "$@" | jq -Rs 'split("\u0000")[:-1]')" || return
  if [[ -z "$command_adapter_sha256" ]]; then
    command_adapter_sha256="$(compatibility_sha256 "$(readlink -f -- "$0")")" || return
  fi
  jq -nS \
    --arg campaign "$OBI_COMPATIBILITY_CAMPAIGN" \
    --arg campaign_revision "$OBI_COMPATIBILITY_CAMPAIGN_REVISION" \
    --arg plan_sha256 "$OBI_COMPATIBILITY_PLAN_SHA256" \
    --arg provider "$provider_name" \
    --arg reason "$reason" \
    --arg driver_sha256 "$driver_sha256" \
    --arg command_adapter_sha256 "$command_adapter_sha256" \
    --argjson invocation_status "$invocation_status" \
    --argjson requested "$requested" \
    --argjson command_argv "$command_json" \
    --argjson source "$source_identity" \
    --arg manifest_sha256 "$(compatibility_sha256 "$evidence_manifest")" '
      {
        schema: "compatibility-provider-result-v1",
        campaign: $campaign,
        campaign_revision: $campaign_revision,
        plan_sha256: $plan_sha256,
        cell_id: $requested.id,
        provider: $provider,
        status: "fail",
        reason: $reason,
        attempted: true,
        infrastructure_failure: false,
        requested: $requested,
        provider_registry_sha256: $ENV.OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256,
        external_driver:
          (if $driver_sha256 == "" then null else {
            id: $ENV.OBI_COMPATIBILITY_ACTIVE_DRIVER_ID,
            sha256: $driver_sha256,
            snapshot: "external-driver.snapshot"
          } end),
        command: {
          executed: true,
          argv: $command_argv,
          adapter_sha256: $command_adapter_sha256,
          exit_status: $invocation_status
        },
        source: $source,
        runtime: null,
        artifacts: null,
        assertions: {
          classification: "provider-contract",
          contract_failure: true,
          application_result: "fail",
          cleanup: "unknown",
          product_failure: false,
          required_cells_skipped: false
        },
        evidence_index: [],
        raw_evidence: {
          directory: "provider-contract-evidence",
          manifest: "provider-contract-evidence.sha256",
          manifest_sha256: $manifest_sha256
        }
      }
    ' >"$OBI_COMPATIBILITY_PROVIDER_RESULT"
  chmod 0600 -- "$OBI_COMPATIBILITY_PROVIDER_RESULT"
}

provider_run_external_driver() {
  local -r provider_name="$1"
  local -r driver_environment="$2"
  local -r digest_environment="$3"
  local -r unavailable_reason="$4"
  local driver="${!driver_environment:-}"
  local expected_sha256="${!digest_environment:-}"
  local external_directory="$OBI_COMPATIBILITY_PRIVATE_DIR/external"
  local driver_result="$external_directory/provider-result.json"
  local external_manifest="$OBI_COMPATIBILITY_PRIVATE_DIR/external-directory.sha256"
  local snapshot="$OBI_COMPATIBILITY_PRIVATE_DIR/external-driver.snapshot"
  local snapshot_ready="$OBI_COMPATIBILITY_PRIVATE_DIR/.external-driver.snapshot.ready"
  local identity_file="$OBI_COMPATIBILITY_PRIVATE_DIR/external-driver-identity.json"
  local invocation_status=0
  local driver_id=""
  local original_identity=""
  local snapshot_identity=""
  local command_json=""
  local normalized_result="$OBI_COMPATIBILITY_PRIVATE_DIR/.external-provider-result.normalized"
  local command_name=""
  local -a command=()
  local -a required_commands=(cmp install jq python3 sleep stat timeout)

  if [[ -z "$driver" || -z "$expected_sha256" ]]; then
    provider_write_untested \
      "$unavailable_reason" "$provider_name" \
      "external:$driver_environment" \
      --cell "$OBI_COMPATIBILITY_CELL_JSON" \
      --private-output "$external_directory"
    return 69
  fi
  driver_id="$(compatibility_provider_registry_driver_id \
    "$provider_name" "$expected_sha256" 2>/dev/null || true)"
  if [[ -z "$driver_id" ]]; then
    provider_write_untested \
      "external-provider-not-approved" "$provider_name" \
      "external:$driver_environment" \
      --cell "$OBI_COMPATIBILITY_CELL_JSON" \
      --private-output "$external_directory"
    return 69
  fi
  if ! original_identity="$(provider_external_driver_identity "$driver")" ||
    [[ "${original_identity##*:}" != "$expected_sha256" ]]; then
    provider_write_untested \
      "external-provider-identity-invalid" "$provider_name" \
      "external:$driver_environment" \
      --cell "$OBI_COMPATIBILITY_CELL_JSON" \
      --private-output "$external_directory"
    return 69
  fi
  for command_name in "${required_commands[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      provider_write_untested \
        "external-provider-tool-unavailable" "$provider_name" \
        "$driver" --contract compatibility-external-provider-v1
      return 69
    fi
  done
  [[ ! -e "$snapshot" && ! -L "$snapshot" &&
    ! -e "$snapshot_ready" && ! -L "$snapshot_ready" ]] || return 1
  install -m 0500 -- "$driver" "$snapshot_ready" || return
  mv -T -- "$snapshot_ready" "$snapshot" || return
  snapshot_identity="$(provider_external_driver_identity "$snapshot")" || return
  [[ "${snapshot_identity##*:}" == "$expected_sha256" ]] || return 1
  provider_external_driver_is_unchanged "$driver" "$original_identity" || {
    provider_write_untested external-provider-changed-before-execution \
      "$provider_name" "external:$driver_environment"
    return 69
  }
  jq -nS \
    --arg driver_environment "$driver_environment" \
    --arg driver_id "$driver_id" \
    --arg original_identity "$original_identity" \
    --arg snapshot_identity "$snapshot_identity" \
    '{
      schema: "compatibility-external-driver-private-identity-v1",
      environment: $driver_environment,
      id: $driver_id,
      original_identity: $original_identity,
      snapshot_identity: $snapshot_identity
    }' >"$identity_file"
  chmod 0600 -- "$identity_file"
  export OBI_COMPATIBILITY_ACTIVE_DRIVER_ID="$driver_id"
  install -d -m 0700 -- "$external_directory"
  command=(
    "$snapshot"
    --contract compatibility-external-provider-v1
    --campaign "$OBI_COMPATIBILITY_CAMPAIGN"
    --campaign-revision "$OBI_COMPATIBILITY_CAMPAIGN_REVISION"
    --plan-sha256 "$OBI_COMPATIBILITY_PLAN_SHA256"
    --cell "$OBI_COMPATIBILITY_CELL_JSON"
    --source-authority "$OBI_COMPATIBILITY_SOURCE_AUTHORITY"
    --source-authority-sha256 "$OBI_COMPATIBILITY_SOURCE_AUTHORITY_SHA256"
    --private-output "$external_directory"
  )
  command_json="$(printf '%s\0' "${command[@]}" |
    jq -Rs 'split("\u0000")[:-1]')" || return
  set +e
  compatibility_run_bounded_process_group \
    "$OBI_COMPATIBILITY_PRIVATE_DIR/external-provider.stdout" \
    "$OBI_COMPATIBILITY_PRIVATE_DIR/external-provider.stderr" \
    32768 7200 "${command[@]}"
  invocation_status=$?
  set -e
  if ! provider_external_driver_is_unchanged "$driver" "$original_identity" ||
    ! provider_external_driver_is_unchanged "$snapshot" "$snapshot_identity"; then
    rm -f -- "$snapshot"
    provider_write_contract_fail \
      external-provider-changed-during-execution "$provider_name" \
      "$driver" "" "$invocation_status" "$driver_result" \
      "${command[@]}"
    return 1
  fi
  if ! compatibility_directory_manifest "$external_directory" "$external_manifest"; then
    rm -f -- "$external_manifest"
    provider_write_contract_fail \
      external-provider-evidence-unbounded-or-unsafe "$provider_name" \
      "$snapshot" "$expected_sha256" "$invocation_status" "$driver_result" \
      "${command[@]}" || return
    [[ "$external_directory" == "$OBI_COMPATIBILITY_PRIVATE_DIR/external" ]] || return 1
    rm -rf -- "$external_directory"
    return 1
  fi
  if [[ ! -f "$driver_result" || -L "$driver_result" ]]; then
    provider_write_contract_fail \
      external-provider-result-missing "$provider_name" \
      "$snapshot" "$expected_sha256" "$invocation_status" "$driver_result" \
      "${command[@]}"
    return 1
  fi
  if ! compatibility_validate_json_file "$driver_result"; then
    provider_write_contract_fail \
      external-provider-result-invalid "$provider_name" \
      "$snapshot" "$expected_sha256" "$invocation_status" "$driver_result" \
      "${command[@]}"
    return 1
  fi
  jq -e \
    --arg provider "$provider_name" \
    --arg driver_sha256 "$expected_sha256" \
    --argjson status "$invocation_status" \
    --argjson command "$command_json" '
      .schema == "compatibility-provider-result-v1" and
      .provider == $provider and
      (has("provider_exit_status") | not) and
      (has("provider_registry_sha256") | not) and
      (has("external_driver") | not) and
      .command.adapter_sha256 == $driver_sha256 and
      .command.exit_status == $status and
      .command.argv == $command and
      (.status == "pass" or .status == "fail" or
        .status == "unsupported" or .status == "untested") and
      (if .status == "untested" then .assertions == null
       else (.assertions | type) == "object"
       end)
    ' "$driver_result" >/dev/null || {
      provider_write_contract_fail \
        external-provider-result-invalid "$provider_name" \
        "$snapshot" "$expected_sha256" "$invocation_status" "$driver_result" \
        "${command[@]}"
      return 1
    }
  jq -S \
    --arg registry_sha256 "$OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256" \
    --arg driver_id "$driver_id" \
    --arg driver_sha256 "$expected_sha256" \
    --argjson invocation_status "$invocation_status" \
    --argjson command "$command_json" '
      . + {
        provider_registry_sha256: $registry_sha256,
        external_driver: {
          id: $driver_id,
          sha256: $driver_sha256,
          snapshot: "external-driver.snapshot"
        },
        command: {
          executed: true,
          argv: $command,
          adapter_sha256: $driver_sha256,
          exit_status: $invocation_status
        }
      }
    ' "$driver_result" >"$normalized_result" || return
  chmod 0600 -- "$normalized_result"
  mv -T -- "$normalized_result" "$OBI_COMPATIBILITY_PROVIDER_RESULT"
  return "$invocation_status"
}
