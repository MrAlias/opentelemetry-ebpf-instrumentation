#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/lib.sh"

RUN_CELL_TEMP_DIRECTORY=""
RUN_CELL_TEMP_IDENTITY=""
RUN_CELL_TEMP_PARENT=""

cleanup_run_cell_temp() {
  [[ -n "$RUN_CELL_TEMP_DIRECTORY" ]] || return 0
  compatibility_remove_owned_temp_directory \
    "$RUN_CELL_TEMP_DIRECTORY" "$RUN_CELL_TEMP_IDENTITY" \
    "$RUN_CELL_TEMP_PARENT" "[.]compatibility-cell[.]" ||
    compatibility_error "refused to remove replaced cell staging directory"
}

usage() {
  cat >&2 <<'USAGE'
Usage: run-cell.sh --campaign compatibility|helper-lifecycle --cell ID \
  --source-authority FILE --output DIR

The output directory must not already exist. The command records every attempt as
pass, fail, unsupported, or infrastructure-only untested evidence.
USAGE
}

provider_path() {
  local -r provider="$1"

  case "$provider" in
    runsh-java21-container-v1|preprovisioned-host-application-v1|\
      preprovisioned-jvm-application-v1|preprovisioned-lifecycle-application-v1)
      printf '%s/providers/%s.sh\n' "$SCRIPT_DIRECTORY" "$provider"
      ;;
    *)
      compatibility_die "campaign names an unknown provider adapter: $provider"
      ;;
  esac
}

runner_source_json() {
  compatibility_source_checkout_json
}

write_boundary_contract_fail() {
  local -r reason="$1"
  local -r campaign="$2"
  local -r revision="$3"
  local -r plan_sha256="$4"
  local -r requested_file="$5"
  local -r launcher="$6"
  local -r provider_status="$7"
  local -r private_directory="$8"
  local -r rejected_result="$9"
  local -r rejected_log="${10}"
  local -r output="${11}"
  local evidence_directory="$private_directory/runner-contract-evidence"
  local evidence_manifest="$private_directory/runner-contract-evidence.sha256"
  local requested=""
  local source=""
  local candidate=""
  local size=0

  install -d -m 0700 -- "$evidence_directory"
  [[ "$reason" =~ ^[a-z0-9][a-z0-9-]{0,95}$ ]] ||
    compatibility_die "invalid provider boundary failure reason" || return
  printf 'reason=%s\nprovider_status=%s\n' \
    "$reason" "$provider_status" >"$evidence_directory/contract-failure.txt"
  chmod 0600 -- "$evidence_directory/contract-failure.txt"
  for candidate in \
    "$private_directory/provider.stdout" \
    "$private_directory/provider.stderr" \
    "$rejected_result" \
    "$rejected_log"; do
    if [[ -f "$candidate" && ! -L "$candidate" ]]; then
      size="$(stat -Lc '%s' -- "$candidate")" || return
      if [[ "$size" =~ ^[0-9]+$ ]] && (( size <= 4194304 )); then
        install -m 0600 -- "$candidate" "$evidence_directory/${candidate##*/}"
      fi
    fi
  done
  compatibility_directory_manifest "$evidence_directory" "$evidence_manifest" || return
  requested="$(jq -cS . "$requested_file")" || return
  source="$(runner_source_json)" || return
  jq -nS \
    --arg campaign "$campaign" \
    --arg revision "$revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg reason "$reason" \
    --arg launcher "$launcher" \
    --arg launcher_sha256 "$(compatibility_sha256 "$launcher")" \
    --argjson provider_status "$provider_status" \
    --argjson requested "$requested" \
    --argjson source "$source" \
    --arg manifest_sha256 "$(compatibility_sha256 "$evidence_manifest")" '
      {
        schema: "compatibility-provider-result-v1",
        campaign: $campaign,
        campaign_revision: $revision,
        plan_sha256: $plan_sha256,
        cell_id: $requested.id,
        provider: $requested.provider,
        status: "fail",
        reason: $reason,
        attempted: true,
        infrastructure_failure: false,
        requested: $requested,
        provider_registry_sha256: $ENV.OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256,
        external_driver: null,
        command: {
          executed: true,
          argv: [$launcher],
          adapter_sha256: $launcher_sha256,
          exit_status: $provider_status
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
          directory: "runner-contract-evidence",
          manifest: "runner-contract-evidence.sha256",
          manifest_sha256: $manifest_sha256
        }
      }
    ' >"$output"
  chmod 0600 -- "$output"
}

provider_result_file_is_safe() {
  local -r result="$1"
  local metadata=""
  local owner=""
  local mode=""
  local links=""

  [[ -f "$result" && ! -L "$result" ]] || return 1
  metadata="$(stat -Lc '%u:%a:%h' -- "$result")" || return
  IFS=: read -r owner mode links <<<"$metadata"
  [[ "$owner" == "$EUID" && "$mode" == 600 && "$links" == 1 ]] || return 1
  compatibility_validate_json_file "$result" >/dev/null 2>&1
}

attach_normalized_provider_exit_status() {
  local -r result="$1"
  local -r provider_status="$2"
  local candidate="${result}.with-provider-exit"

  compatibility_provider_exit_matches_status \
    "$(jq -er '.status' "$result")" "$provider_status" || return
  jq -e 'has("provider_exit_status") | not' "$result" >/dev/null || return 1
  jq -S --argjson provider_status "$provider_status" \
    '. + {provider_exit_status: $provider_status}' "$result" >"$candidate" || return
  chmod 0600 -- "$candidate"
  mv -fT -- "$candidate" "$result"
}

run_provider_launcher_boundary() {
  local -r campaign="$1"
  local -r revision="$2"
  local -r plan_sha256="$3"
  local -r requested="$4"
  local -r launcher="$5"
  local -r private="$6"
  local -r provider_result="$7"
  local -r source_authority="$8"
  local rejected_result="$private/.provider-result.rejected-boundary"
  local provider_status=0
  local reason=""

  if compatibility_run_bounded_process_group \
    "$private/provider.stdout" "$private/provider.stderr" \
    2097152 7800 "$launcher"; then
    provider_status=0
  else
    provider_status=$?
  fi
  if ! provider_result_file_is_safe "$provider_result"; then
    reason="provider-boundary-result-invalid"
  elif jq -e 'has("provider_exit_status")' "$provider_result" >/dev/null; then
    reason="provider-reserved-field-present"
  elif ! compatibility_provider_result_matches_exit \
    "$provider_result" "$provider_status"; then
    reason="provider-exit-status-mismatch"
  elif ! compatibility_provider_result_matches_source_authority \
    "$provider_result" "$source_authority"; then
    reason="provider-source-authority-mismatch"
  else
    attach_normalized_provider_exit_status \
      "$provider_result" "$provider_status" || return
    return "$provider_status"
  fi

  if [[ -f "$provider_result" && ! -L "$provider_result" ]]; then
    mv -- "$provider_result" "$rejected_result" || return
  elif [[ -e "$provider_result" || -L "$provider_result" ]]; then
    # The exact result path is inside the runner-owned staging directory. Unsafe
    # entry types cannot be retained in the bounded private manifest.
    rm -rf -- "$provider_result" || return
  fi
  write_boundary_contract_fail \
    "$reason" "$campaign" "$revision" "$plan_sha256" "$requested" \
    "$launcher" "$provider_status" "$private" "$rejected_result" \
    "$private/provider.stderr" "$provider_result" || return
  rm -f -- "$rejected_result"
  attach_normalized_provider_exit_status "$provider_result" 1 || return
  return 1
}

main() {
  local campaign=""
  local cell_id=""
  local source_authority_input=""
  local source_authority=""
  local source_authority_sha256=""
  local output=""
  local output_parent=""
  local output_name=""
  local staging=""
  local private=""
  local requested=""
  local plan=""
  local revision=""
  local plan_sha256=""
  local provider=""
  local provider_registry_sha256=""
  local launcher=""
  local provider_result=""
  local private_manifest=""
  local sealed=""
  local seal_log=""
  local provider_status=0
  local seal_status=0
  local final_status=""

  while (( $# > 0 )); do
    case "$1" in
      --campaign)
        (( $# >= 2 )) || { usage; return 2; }
        campaign="$2"
        shift 2
        ;;
      --cell)
        (( $# >= 2 )) || { usage; return 2; }
        cell_id="$2"
        shift 2
        ;;
      --output)
        (( $# >= 2 )) || { usage; return 2; }
        output="$2"
        shift 2
        ;;
      --source-authority)
        (( $# >= 2 )) || { usage; return 2; }
        source_authority_input="$2"
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        compatibility_error "unknown argument: $1"
        usage
        return 2
        ;;
    esac
  done
  [[ -n "$campaign" && -n "$cell_id" && -n "$source_authority_input" &&
    -n "$output" ]] || { usage; return 2; }

  compatibility_require_commands git install jq mktemp mv sha256sum stat || return
  compatibility_validate_plan "$campaign" || return
  compatibility_validate_source_authority "$source_authority_input" || return
  compatibility_source_authority_matches_checkout "$source_authority_input" || return
  [[ ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "cell output already exists: $output" || return
  output_parent="$(dirname -- "$output")" || return
  output_name="$(basename -- "$output")" || return
  compatibility_require_directory "$output_parent" || return
  output_parent="$(cd -- "$output_parent" && pwd -P)" || return
  compatibility_require_outside_repository "$output_parent" || return
  [[ "$output_name" != . && "$output_name" != .. && "$output_name" != */* &&
    "$output_name" != *$'\n'* ]] || compatibility_die "unsafe output name" || return
  output="$output_parent/$output_name"

  staging="$(mktemp -d "$output_parent/.compatibility-cell.XXXXXX")" || return
  RUN_CELL_TEMP_DIRECTORY="$staging"
  RUN_CELL_TEMP_PARENT="$output_parent"
  RUN_CELL_TEMP_IDENTITY="$(compatibility_directory_identity "$staging")" || return
  trap cleanup_run_cell_temp EXIT
  chmod 0700 -- "$staging"
  private="$staging/private"
  install -d -m 0700 -- "$private"
  source_authority="$private/source-authority.json"
  source_authority_sha256="$(compatibility_sha256 "$source_authority_input")" || return
  install -m 0600 -- "$source_authority_input" "$source_authority"
  [[ "$(compatibility_sha256 "$source_authority")" == "$source_authority_sha256" ]] ||
    compatibility_die "source authority changed while entering the sealed boundary" || return
  compatibility_validate_source_authority "$source_authority" || return
  requested="$private/requested.json"
  compatibility_select_cell "$campaign" "$cell_id" "$requested" || return
  plan="$(compatibility_plan_path "$campaign")" || return
  revision="$(compatibility_campaign_revision "$campaign")" || return
  plan_sha256="$(compatibility_sha256 "$plan")" || return
  provider_registry_sha256="$(compatibility_provider_registry_sha256)" || return
  provider="$(jq -er '.provider' "$requested")" || return
  launcher="$(provider_path "$provider")" || return
  compatibility_require_regular_file "$launcher" || return
  [[ -x "$launcher" ]] || compatibility_die "provider adapter is not executable: $launcher" || return

  provider_result="$private/provider-result.json"
  export OBI_COMPATIBILITY_CAMPAIGN="$campaign"
  export OBI_COMPATIBILITY_CAMPAIGN_REVISION="$revision"
  export OBI_COMPATIBILITY_PLAN_SHA256="$plan_sha256"
  export OBI_COMPATIBILITY_CELL_JSON="$requested"
  export OBI_COMPATIBILITY_PRIVATE_DIR="$private"
  export OBI_COMPATIBILITY_PROVIDER_RESULT="$provider_result"
  export OBI_COMPATIBILITY_SOURCE_AUTHORITY="$source_authority"
  export OBI_COMPATIBILITY_SOURCE_AUTHORITY_SHA256="$source_authority_sha256"
  export OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256="$provider_registry_sha256"
  if run_provider_launcher_boundary \
    "$campaign" "$revision" "$plan_sha256" "$requested" "$launcher" \
    "$private" "$provider_result" "$source_authority"; then
    provider_status=0
  else
    provider_status=$?
  fi
  compatibility_source_authority_matches_checkout "$source_authority" || return

  private_manifest="$staging/private.sha256"
  compatibility_directory_manifest "$private" "$private_manifest" || return
  sealed="$staging/cell.json"
  seal_log="$staging/seal.stderr"
  set +e
  "$SCRIPT_DIRECTORY/seal-cell.sh" \
    --campaign "$campaign" \
    --cell "$requested" \
    --provider-result "$provider_result" \
    --provider-launcher "$launcher" \
    --private-directory "$private" \
    --private-manifest "$private_manifest" \
    --output "$sealed" 2>"$seal_log"
  seal_status=$?
  set -e
  if (( seal_status != 0 )); then
    mv -- "$provider_result" "$private/provider-result.rejected-contract.json"
    mv -- "$seal_log" "$private/provider-result.rejected-contract.stderr"
    rm -f -- "$private_manifest" "$sealed"
    write_boundary_contract_fail \
      provider-result-contract-invalid \
      "$campaign" "$revision" "$plan_sha256" "$requested" "$launcher" \
      "$provider_status" "$private" \
      "$private/provider-result.rejected-contract.json" \
      "$private/provider-result.rejected-contract.stderr" \
      "$provider_result" || return
    provider_status=1
    attach_normalized_provider_exit_status "$provider_result" "$provider_status" || return
    compatibility_directory_manifest "$private" "$private_manifest" || return
    "$SCRIPT_DIRECTORY/seal-cell.sh" \
      --campaign "$campaign" \
      --cell "$requested" \
      --provider-result "$provider_result" \
      --provider-launcher "$launcher" \
      --private-directory "$private" \
      --private-manifest "$private_manifest" \
      --output "$sealed"
  else
    rm -f -- "$seal_log"
  fi

  compatibility_sha256 "$sealed" >"$staging/cell.json.sha256"
  chmod 0644 -- "$sealed" "$staging/cell.json.sha256"
  final_status="$(jq -er '.status' "$sealed")" || return
  compatibility_provider_exit_matches_status "$final_status" "$provider_status" ||
    compatibility_die \
      "sealed status does not match the normalized provider exit status" || return
  compatibility_source_authority_matches_checkout "$source_authority" || return
  mv -T -- "$staging" "$output"
  case "$final_status" in
    pass) return 0 ;;
    fail) return 1 ;;
    unsupported) return 78 ;;
    untested) return 69 ;;
    *) compatibility_die "sealed an unknown status: $final_status" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
