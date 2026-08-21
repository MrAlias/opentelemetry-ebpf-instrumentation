#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/lib.sh"

COLLECT_TEMP_DIRECTORY=""
COLLECT_TEMP_IDENTITY=""
COLLECT_TEMP_PARENT=""

cleanup_collect_temp() {
  [[ -n "$COLLECT_TEMP_DIRECTORY" ]] || return 0
  compatibility_remove_owned_temp_directory \
    "$COLLECT_TEMP_DIRECTORY" "$COLLECT_TEMP_IDENTITY" "$COLLECT_TEMP_PARENT" \
    "[.]compatibility-collect[.]" ||
    compatibility_error "refused to remove replaced collector scratch directory"
}

usage() {
  cat >&2 <<'USAGE'
Usage: collect.sh --campaign compatibility|helper-lifecycle --input-root DIR \
  --source-authority FILE --output DIR

The input root must contain exactly one sealed directory per frozen campaign ID.
Only public cell records are copied into the aggregate output.
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
      compatibility_die "sealed cell names an unknown provider adapter: $provider"
      ;;
  esac
}

verify_cell_root_shape() {
  local -r directory="$1"
  local observed=""
  local -r expected=$'cell.json\ncell.json.sha256\nprivate\nprivate.sha256'

  observed="$(find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' |
    LC_ALL=C sort)" || return
  [[ "$observed" == "$expected" ]] ||
    compatibility_die "sealed cell has unexpected root entries: $directory"
}

main() {
  local campaign=""
  local input_root=""
  local source_authority_input=""
  local source_authority=""
  local source_authority_sha256=""
  local output=""
  local output_parent=""
  local output_name=""
  local plan=""
  local revision=""
  local plan_sha256=""
  local expected_ids=""
  local expected_count=""
  local scratch=""
  local staging=""
  local actual_ids=""
  local sorted_expected_ids=""
  local records=""
  local driver_identities=""
  local registry_sha256=""
  local cell_id=""
  local directory=""
  local cell=""
  local cell_sha_file=""
  local cell_sha=""
  local requested=""
  local provider_result=""
  local cell_source_authority=""
  local private_manifest=""
  local launcher=""
  local resealed=""
  local schema=""
  local unexpected=""

  while (( $# > 0 )); do
    case "$1" in
      --campaign)
        (( $# >= 2 )) || { usage; return 2; }
        campaign="$2"
        shift 2
        ;;
      --input-root)
        (( $# >= 2 )) || { usage; return 2; }
        input_root="$2"
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
  [[ -n "$campaign" && -n "$input_root" && -n "$source_authority_input" &&
    -n "$output" ]] || { usage; return 2; }

  compatibility_require_commands cmp find install jq mktemp mv sha256sum sort || return
  compatibility_validate_plan "$campaign" || return
  compatibility_validate_source_authority "$source_authority_input" || return
  compatibility_source_authority_matches_checkout "$source_authority_input" || return
  compatibility_require_directory "$input_root" || return
  input_root="$(cd -- "$input_root" && pwd -P)" || return
  compatibility_require_outside_repository "$input_root" || return
  [[ ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "aggregate output already exists: $output" || return
  output_parent="$(dirname -- "$output")" || return
  output_name="$(basename -- "$output")" || return
  compatibility_require_directory "$output_parent" || return
  output_parent="$(cd -- "$output_parent" && pwd -P)" || return
  compatibility_require_outside_repository "$output_parent" || return
  [[ "$output_parent" != "$input_root" && "$output_parent" != "$input_root"/* ]] ||
    compatibility_die "aggregate output parent must be outside the cell input root" || return
  [[ "$output_name" != . && "$output_name" != .. && "$output_name" != */* &&
    "$output_name" != *$'\n'* ]] || compatibility_die "unsafe output name" || return
  output="$output_parent/$output_name"

  plan="$(compatibility_plan_path "$campaign")" || return
  revision="$(compatibility_campaign_revision "$campaign")" || return
  plan_sha256="$(compatibility_sha256 "$plan")" || return
  registry_sha256="$(compatibility_provider_registry_sha256)" || return
  expected_ids="$(compatibility_expected_ids_path "$campaign")" || return
  expected_count="$(jq -er '.expected_cell_count' "$plan")" || return
  unexpected="$(find "$input_root" -mindepth 1 -maxdepth 1 \
    \( -type l -o ! -type d \) -print -quit)" || return
  [[ -z "$unexpected" ]] ||
    compatibility_die "aggregate input contains a symlink or non-directory entry" || return

  scratch="$(mktemp -d "$output_parent/.compatibility-collect.XXXXXX")" || return
  COLLECT_TEMP_DIRECTORY="$scratch"
  COLLECT_TEMP_PARENT="$output_parent"
  COLLECT_TEMP_IDENTITY="$(compatibility_directory_identity "$scratch")" || return
  trap cleanup_collect_temp EXIT
  chmod 0700 -- "$scratch"
  source_authority="$scratch/source-authority.json"
  source_authority_sha256="$(compatibility_sha256 "$source_authority_input")" || return
  install -m 0600 -- "$source_authority_input" "$source_authority"
  [[ "$(compatibility_sha256 "$source_authority")" == "$source_authority_sha256" ]] ||
    compatibility_die "source authority changed while entering the collector boundary" || return
  compatibility_validate_source_authority "$source_authority" || return
  actual_ids="$scratch/actual-ids.txt"
  sorted_expected_ids="$scratch/expected-ids.txt"
  LC_ALL=C sort "$expected_ids" >"$sorted_expected_ids"
  find "$input_root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
    LC_ALL=C sort >"$actual_ids"
  cmp -s -- "$sorted_expected_ids" "$actual_ids" ||
    compatibility_die "aggregate input has missing, foreign, or duplicate directory IDs" || return
  [[ "$(wc -l <"$actual_ids")" == "$expected_count" ]] ||
    compatibility_die "aggregate input count differs from the frozen campaign count" || return

  staging="$scratch/output"
  install -d -m 0755 -- "$staging/cells"
  install -m 0644 -- "$source_authority" "$staging/source-authority.json"
  records="$scratch/records.jsonl"
  driver_identities="$scratch/external-driver-identities.jsonl"
  : >"$records"
  : >"$driver_identities"
  while IFS= read -r cell_id; do
    directory="$input_root/$cell_id"
    compatibility_require_directory "$directory" || return
    verify_cell_root_shape "$directory" || return
    cell="$directory/cell.json"
    cell_sha_file="$directory/cell.json.sha256"
    requested="$directory/private/requested.json"
    provider_result="$directory/private/provider-result.json"
    cell_source_authority="$directory/private/source-authority.json"
    private_manifest="$directory/private.sha256"
    compatibility_require_regular_file "$cell" || return
    compatibility_require_regular_file "$cell_sha_file" || return
    compatibility_require_regular_file "$requested" || return
    compatibility_require_regular_file "$provider_result" || return
    compatibility_require_regular_file "$cell_source_authority" || return
    compatibility_require_regular_file "$private_manifest" || return
    compatibility_validate_json_file "$cell" || return
    compatibility_validate_json_file "$requested" || return
    compatibility_validate_json_file "$provider_result" || return
    compatibility_validate_source_authority "$cell_source_authority" || return
    cmp -s -- "$source_authority" "$cell_source_authority" ||
      compatibility_die "cell retained a different source authority: $cell_id" || return
    cell_sha="$(compatibility_sha256 "$cell")" || return
    [[ "$(<"$cell_sha_file")" == "$cell_sha" ]] ||
      compatibility_die "public cell digest mismatch: $cell_id" || return
    jq -e --arg id "$cell_id" --slurpfile plan "$plan" '
      .schema == "compatibility-cell-record-v1" and
      .cell_id == $id and .requested.id == $id and
      ([.requested as $requested |
        $plan[0].cells[] | select(.id == $id and . == $requested)] | length == 1)
    ' "$cell" >/dev/null ||
      compatibility_die "public cell ID or requested dimensions were substituted: $cell_id" || return
    launcher="$(provider_path "$(jq -er '.requested.provider' "$cell")")" || return
    resealed="$scratch/resealed-$cell_id.json"
    "$SCRIPT_DIRECTORY/seal-cell.sh" \
      --campaign "$campaign" \
      --cell "$requested" \
      --provider-result "$provider_result" \
      --provider-launcher "$launcher" \
      --private-directory "$directory/private" \
      --private-manifest "$private_manifest" \
      --output "$resealed" || return
    cmp -s -- "$cell" "$resealed" ||
      compatibility_die "public cell does not match its private sealed evidence: $cell_id" || return
    compatibility_provider_result_matches_source_authority \
      "$provider_result" "$source_authority" ||
      compatibility_die "cell source identity differs from the campaign authority: $cell_id" || return
    install -m 0644 -- "$cell" "$staging/cells/$cell_id.json"
    jq -cS '
      select(.provider.external_driver != null) |
      {
        provider: .provider.name,
        id: .provider.external_driver.id,
        sha256: .provider.external_driver.sha256
      }
    ' "$cell" >>"$driver_identities"
    jq -cnS \
      --arg cell_id "$cell_id" \
      --arg status "$(jq -er '.status' "$cell")" \
      --arg reason "$(jq -er '.reason' "$cell")" \
      --arg path "cells/$cell_id.json" \
      --arg sha256 "$cell_sha" \
      '{
        cell_id: $cell_id,
        status: $status,
        reason: $reason,
        record: {path: $path, sha256: $sha256}
      }' >>"$records"
  done <"$sorted_expected_ids"
  compatibility_validate_collected_driver_identities "$driver_identities" || return

  case "$campaign" in
    compatibility) schema=compatibility-matrix-aggregate-v3 ;;
    helper-lifecycle) schema=helper-lifecycle-aggregate-v1 ;;
  esac
  jq -sS \
    --arg schema "$schema" \
    --arg campaign "$campaign" \
    --arg revision "$revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg provider_registry_sha256 "$registry_sha256" \
    --arg expected_ids_sha256 "$(compatibility_sha256 "$expected_ids")" \
    --arg source_authority_sha256 "$source_authority_sha256" \
    --argjson expected_count "$expected_count" \
    --slurpfile source_authority "$source_authority" \
    --slurpfile plan "$plan" '
      . as $records |
      (["pass", "fail", "unsupported", "untested"] |
        map(. as $status | {
          key: $status,
          value: ([ $records[] | select(.status == $status) ] | length)
        }) |
        from_entries) as $counts |
      {
        schema: $schema,
        campaign: $campaign,
        campaign_revision: $revision,
        plan_sha256: $plan_sha256,
        provider_registry_sha256: $provider_registry_sha256,
        expected_cell_ids_sha256: $expected_ids_sha256,
        source_authority: $source_authority[0],
        source_authority_sha256: $source_authority_sha256,
        expected_cell_count: $expected_count,
        collected_cell_count: ($records | length),
        status_counts: $counts,
        campaign_state:
          (if $counts.untested > 0 then "incomplete-untested"
           elif $counts.fail > 0 then "complete-failed"
           elif $counts.unsupported > 0 then "complete-with-unsupported"
           else "complete-passed"
           end),
        cells: $records
      } + if $campaign == "compatibility" then {
        excluded_dimensions: $plan[0].excluded_dimensions
      } else {
        required_frameworks: $plan[0].required_frameworks,
        required_lifecycle: $plan[0].required_lifecycle,
        required_repeated_resource_gates: $plan[0].required_repeated_resource_gates
      } end
    ' "$records" | compatibility_atomic_json_write "$staging/aggregate.json"
  compatibility_sha256 "$staging/aggregate.json" >"$staging/aggregate.json.sha256"
  chmod 0644 -- "$staging/aggregate.json" "$staging/aggregate.json.sha256"
  compatibility_source_authority_matches_checkout "$source_authority" || return
  mv -T -- "$staging" "$output"
}

main "$@"
