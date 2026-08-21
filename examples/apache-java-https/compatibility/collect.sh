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
COLLECT_TEMP_DESCRIPTOR=""

cleanup_collect_temp() {
  if [[ "$COLLECT_TEMP_DESCRIPTOR" =~ ^[1-9][0-9]*$ ]]; then
    exec {COLLECT_TEMP_DESCRIPTOR}<&- || true
    COLLECT_TEMP_DESCRIPTOR=""
  fi
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
  local source_authority_source_identity=""
  local source_authority_snapshot_identity=""
  local output=""
  local output_parent=""
  local output_name=""
  local plan=""
  local revision=""
  local plan_sha256=""
  local plan_source=""
  local plan_source_identity=""
  local plan_snapshot_identity=""
  local expected_ids=""
  local expected_ids_source=""
  local expected_ids_source_identity=""
  local expected_ids_snapshot_identity=""
  local expected_count=""
  local scratch=""
  local scratch_authority=""
  local staging=""
  local staging_source=""
  local staging_identity=""
  local actual_ids=""
  local sorted_expected_ids=""
  local records=""
  local driver_identities=""
  local lifecycle_executor_identities=""
  local registry_sha256=""
  local lifecycle_executor_registry_sha256=""
  local registry_snapshot=""
  local lifecycle_executor_registry_snapshot=""
  local registry_source_identity=""
  local lifecycle_executor_registry_source_identity=""
  local registry_snapshot_identity=""
  local lifecycle_executor_registry_snapshot_identity=""
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
  local input_snapshot=""
  local private_source_ledger=""
  local private_snapshot_ledger=""
  local private_source_ledger_identity=""
  local private_snapshot_ledger_identity=""
  local directory_identity=""
  local cell_source_identity=""
  local cell_snapshot_identity=""
  local cell_sha_source_identity=""
  local cell_sha_snapshot_identity=""
  local private_manifest_source_identity=""
  local private_manifest_snapshot_identity=""
  local staged_cell_identity=""
  local records_identity=""
  local driver_identities_identity=""
  local lifecycle_executor_identities_identity=""
  local aggregate_candidate=""
  local aggregate_candidate_identity=""
  local aggregate_digest_candidate=""
  local aggregate_digest_identity=""
  local index=0
  local -a source_directories=()
  local -a source_directory_identities=()
  local -a source_ledgers=()
  local -a source_ledger_identities=()
  local -a source_cells=()
  local -a source_cell_identities=()
  local -a source_cell_sha_files=()
  local -a source_cell_sha_identities=()
  local -a source_private_manifests=()
  local -a source_private_manifest_identities=()

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

  compatibility_require_commands \
    cmp find install jq mktemp sha256sum sort stat || return
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
  expected_ids="$(compatibility_expected_ids_path "$campaign")" || return
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
  exec {COLLECT_TEMP_DESCRIPTOR}<"$scratch" || return
  [[ "$(stat -Lc '%d:%i:%u' -- "/proc/self/fd/$COLLECT_TEMP_DESCRIPTOR")" == \
      "$COLLECT_TEMP_IDENTITY" &&
    "$(stat -Lc '%a:%u' -- "/proc/self/fd/$COLLECT_TEMP_DESCRIPTOR")" == \
      "700:$EUID" ]] ||
    compatibility_die "collector scratch authority changed" || return
  scratch_authority="/proc/self/fd/$COLLECT_TEMP_DESCRIPTOR/."
  registry_snapshot="$scratch_authority/provider-registry.snapshot.json"
  lifecycle_executor_registry_snapshot=\
"$scratch_authority/lifecycle-executor-registry.snapshot.json"
  registry_source_identity="$(
    compatibility_prepare_provider_registry_snapshot "$registry_snapshot"
  )" || return
  lifecycle_executor_registry_source_identity="$(
    compatibility_prepare_lifecycle_executor_registry_snapshot \
      "$lifecycle_executor_registry_snapshot"
  )" || return
  registry_snapshot_identity="$(compatibility_stable_file_identity \
    "$registry_snapshot" 67108864)" || return
  lifecycle_executor_registry_snapshot_identity="$(
    compatibility_stable_file_identity \
      "$lifecycle_executor_registry_snapshot" 67108864
  )" || return
  registry_sha256="$(compatibility_provider_registry_sha256 "$registry_snapshot")" ||
    return
  lifecycle_executor_registry_sha256="$(
    compatibility_lifecycle_executor_registry_sha256 \
      "$lifecycle_executor_registry_snapshot"
  )" || return
  compatibility_validate_plan \
    "$campaign" "$registry_snapshot" "$lifecycle_executor_registry_snapshot" ||
    return
  plan_source="$plan"
  plan_source_identity="$(compatibility_create_stable_file_snapshot \
    "$plan_source" "$scratch_authority/plan.snapshot.json" 67108864)" || return
  plan="$scratch_authority/plan.snapshot.json"
  plan_snapshot_identity="$(compatibility_stable_file_identity \
    "$plan" 67108864)" || return
  case "$campaign" in
    compatibility) revision="$(jq -er '.matrix_revision' "$plan")" || return ;;
    helper-lifecycle) revision="$(jq -er '.campaign_revision' "$plan")" || return ;;
    *) return 2 ;;
  esac
  plan_sha256="${plan_snapshot_identity##*:}"
  expected_ids_source="$expected_ids"
  expected_ids_source_identity="$(compatibility_create_stable_file_snapshot \
    "$expected_ids_source" "$scratch_authority/expected-ids.snapshot.txt" \
    1048576)" ||
    return
  expected_ids="$scratch_authority/expected-ids.snapshot.txt"
  expected_ids_snapshot_identity="$(compatibility_stable_file_identity \
    "$expected_ids" 1048576)" || return
  compatibility_validate_expected_ids_file "$expected_ids" || return
  expected_count="$(jq -er '.expected_cell_count' "$plan")" || return
  source_authority="$scratch_authority/source-authority.json"
  source_authority_source_identity="$(compatibility_create_stable_file_snapshot \
    "$source_authority_input" "$source_authority" 67108864)" || return
  chmod 0600 -- "$source_authority" || return
  source_authority_snapshot_identity="$(compatibility_stable_file_identity \
    "$source_authority" 67108864)" || return
  source_authority_sha256="${source_authority_snapshot_identity##*:}"
  compatibility_validate_source_authority "$source_authority" || return
  actual_ids="$scratch_authority/actual-ids.txt"
  sorted_expected_ids="$scratch_authority/expected-ids.txt"
  LC_ALL=C sort "$expected_ids" >"$sorted_expected_ids"
  find "$input_root" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
    LC_ALL=C sort >"$actual_ids"
  cmp -s -- "$sorted_expected_ids" "$actual_ids" ||
    compatibility_die "aggregate input has missing, foreign, or duplicate directory IDs" || return
  [[ "$(wc -l <"$actual_ids")" == "$expected_count" ]] ||
    compatibility_die "aggregate input count differs from the frozen campaign count" || return

  staging_source="$scratch/output"
  staging="$scratch_authority/output"
  install -d -m 0755 -- "$staging/cells"
  compatibility_publish_stable_file \
    "$source_authority" "$source_authority_snapshot_identity" \
    "$staging/source-authority.json" 0644 || return
  records="$scratch_authority/records.jsonl"
  driver_identities="$scratch_authority/external-driver-identities.jsonl"
  lifecycle_executor_identities=\
"$scratch_authority/lifecycle-executor-identities.jsonl"
  : >"$records"
  : >"$driver_identities"
  : >"$lifecycle_executor_identities"
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
    directory_identity="$(compatibility_stable_directory_identity "$directory")" ||
      return

    input_snapshot="$scratch_authority/input-$cell_id"
    install -d -m 0700 -- "$input_snapshot"
    cell_source_identity="$(compatibility_create_stable_file_snapshot \
      "$cell" "$input_snapshot/cell.json" 67108864)" || return
    chmod 0400 -- "$input_snapshot/cell.json" || return
    cell_snapshot_identity="$(compatibility_stable_file_identity \
      "$input_snapshot/cell.json" 67108864)" || return
    cell_sha_source_identity="$(compatibility_create_stable_file_snapshot \
      "$cell_sha_file" "$input_snapshot/cell.json.sha256" 4096)" || return
    chmod 0400 -- "$input_snapshot/cell.json.sha256" || return
    cell_sha_snapshot_identity="$(compatibility_stable_file_identity \
      "$input_snapshot/cell.json.sha256" 4096)" || return
    private_manifest_source_identity="$(compatibility_create_stable_file_snapshot \
      "$private_manifest" "$input_snapshot/private.sha256" 67108864)" || return
    chmod 0400 -- "$input_snapshot/private.sha256" || return
    private_manifest_snapshot_identity="$(compatibility_stable_file_identity \
      "$input_snapshot/private.sha256" 67108864)" || return
    private_source_ledger=\
"$scratch_authority/private-source-$cell_id.identity.json"
    private_snapshot_ledger=\
"$scratch_authority/private-snapshot-$cell_id.identity.json"
    compatibility_snapshot_manifest_directory \
      "$directory/private" "$input_snapshot/private.sha256" \
      "$input_snapshot/private" "$private_source_ledger" \
      "$private_snapshot_ledger" "$private_manifest_snapshot_identity" || return
    private_source_ledger_identity="$(compatibility_stable_file_identity \
      "$private_source_ledger" 67108864)" || return
    private_snapshot_ledger_identity="$(compatibility_stable_file_identity \
      "$private_snapshot_ledger" 67108864)" || return
    compatibility_verify_manifest_directory_source \
      "$directory/private" "$private_source_ledger" \
      "$private_source_ledger_identity" || return
    compatibility_verify_manifest_directory_source \
      "$input_snapshot/private" "$private_snapshot_ledger" \
      "$private_snapshot_ledger_identity" || return

    source_directories+=("$directory")
    source_directory_identities+=("$directory_identity")
    source_ledgers+=("$private_source_ledger")
    source_ledger_identities+=("$private_source_ledger_identity")
    source_cells+=("$cell")
    source_cell_identities+=("$cell_source_identity")
    source_cell_sha_files+=("$cell_sha_file")
    source_cell_sha_identities+=("$cell_sha_source_identity")
    source_private_manifests+=("$private_manifest")
    source_private_manifest_identities+=("$private_manifest_source_identity")

    directory="$input_snapshot"
    cell="$directory/cell.json"
    cell_sha_file="$directory/cell.json.sha256"
    requested="$directory/private/requested.json"
    provider_result="$directory/private/provider-result.json"
    cell_source_authority="$directory/private/source-authority.json"
    private_manifest="$directory/private.sha256"
    verify_cell_root_shape "$directory" || return
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
    resealed="$scratch_authority/resealed-$cell_id.json"
    "$SCRIPT_DIRECTORY/seal-cell.sh" \
      --campaign "$campaign" \
      --cell "$requested" \
      --provider-result "$provider_result" \
      --provider-launcher "$launcher" \
      --private-directory "$directory/private" \
      --private-manifest "$private_manifest" \
      --provider-registry-snapshot "$registry_snapshot" \
      --provider-registry-snapshot-identity "$registry_snapshot_identity" \
      --provider-registry-source-identity "$registry_source_identity" \
      --lifecycle-executor-registry-snapshot \
        "$lifecycle_executor_registry_snapshot" \
      --lifecycle-executor-registry-snapshot-identity \
        "$lifecycle_executor_registry_snapshot_identity" \
      --lifecycle-executor-registry-source-identity \
        "$lifecycle_executor_registry_source_identity" \
      --output "$resealed" || return
    cmp -s -- "$cell" "$resealed" ||
      compatibility_die "public cell does not match its private sealed evidence: $cell_id" || return
    compatibility_provider_result_matches_source_authority \
      "$provider_result" "$source_authority" ||
      compatibility_die "cell source identity differs from the campaign authority: $cell_id" || return
    [[ "$(compatibility_stable_file_identity "$cell" 67108864)" == \
        "$cell_snapshot_identity" &&
      "$(compatibility_stable_file_identity "$cell_sha_file" 4096)" == \
        "$cell_sha_snapshot_identity" &&
      "$(compatibility_stable_file_identity "$private_manifest" 67108864)" == \
        "$private_manifest_snapshot_identity" ]] ||
      compatibility_die "collector cell snapshot changed during resealing" || return
    compatibility_verify_manifest_directory_source \
      "$directory/private" "$private_snapshot_ledger" \
      "$private_snapshot_ledger_identity" || return
    compatibility_publish_stable_file \
      "$cell" "$cell_snapshot_identity" "$staging/cells/$cell_id.json" 0644 ||
      return
    staged_cell_identity="$(compatibility_stable_file_identity \
      "$staging/cells/$cell_id.json" 67108864)" || return
    [[ "${staged_cell_identity##*:}" == "$cell_sha" ]] ||
      compatibility_die "staged cell digest differs from its retained record" || return
    jq -cS '
      select(.provider.external_driver != null) |
      {
        provider: .provider.name,
        id: .provider.external_driver.id,
        sha256: .provider.external_driver.sha256
      }
    ' "$cell" >>"$driver_identities"
    jq -cS '
      select(.provider.lifecycle_executor != null) |
      {
        cell_id: .cell_id,
        registry_sha256: .provider.lifecycle_executor.registry_sha256,
        approval: .provider.lifecycle_executor.approval
      }
    ' "$cell" >>"$lifecycle_executor_identities"
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
  compatibility_validate_collected_driver_identities \
    "$driver_identities" "$registry_snapshot" || return
  compatibility_validate_collected_lifecycle_executor_identities \
    "$lifecycle_executor_identities" "$lifecycle_executor_registry_sha256" \
    "$lifecycle_executor_registry_snapshot" || return

  case "$campaign" in
    compatibility) schema=compatibility-matrix-aggregate-v3 ;;
    helper-lifecycle) schema=helper-lifecycle-aggregate-v1 ;;
  esac
  records_identity="$(compatibility_stable_file_identity "$records" 67108864)" ||
    return
  driver_identities_identity="$(compatibility_stable_file_identity \
    "$driver_identities" 67108864)" || return
  lifecycle_executor_identities_identity="$(compatibility_stable_file_identity \
    "$lifecycle_executor_identities" 67108864)" || return
  aggregate_candidate="$scratch_authority/aggregate.candidate.json"
  jq -sS \
    --arg schema "$schema" \
    --arg campaign "$campaign" \
    --arg revision "$revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg provider_registry_sha256 "$registry_sha256" \
    --arg lifecycle_executor_registry_sha256 \
      "$lifecycle_executor_registry_sha256" \
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
        lifecycle_executor_registry_sha256:
          $lifecycle_executor_registry_sha256,
        required_frameworks: $plan[0].required_frameworks,
        required_lifecycle: $plan[0].required_lifecycle,
        required_repeated_resource_gates: $plan[0].required_repeated_resource_gates
      } end
    ' "$records" >"$aggregate_candidate" || return
  chmod 0400 -- "$aggregate_candidate" || return
  compatibility_validate_json_file "$aggregate_candidate" || return
  aggregate_candidate_identity="$(compatibility_stable_file_identity \
    "$aggregate_candidate" 67108864)" || return
  compatibility_publish_stable_file \
    "$aggregate_candidate" "$aggregate_candidate_identity" \
    "$staging/aggregate.json" 0644 || return
  aggregate_digest_candidate="$scratch_authority/aggregate.candidate.sha256"
  printf '%s\n' "${aggregate_candidate_identity##*:}" \
    >"$aggregate_digest_candidate"
  chmod 0400 -- "$aggregate_digest_candidate" || return
  aggregate_digest_identity="$(compatibility_stable_file_identity \
    "$aggregate_digest_candidate" 4096)" || return
  compatibility_publish_stable_file \
    "$aggregate_digest_candidate" "$aggregate_digest_identity" \
    "$staging/aggregate.json.sha256" 0644 || return

  for (( index = 0; index < ${#source_directories[@]}; index += 1 )); do
    [[ "$(compatibility_stable_directory_identity \
        "${source_directories[index]}")" == \
        "${source_directory_identities[index]}" ]] ||
      compatibility_die "collector input root changed after snapshot" || return
    compatibility_verify_manifest_directory_source \
      "${source_directories[index]}/private" "${source_ledgers[index]}" \
      "${source_ledger_identities[index]}" ||
      compatibility_die "collector private evidence changed after snapshot" || return
    [[ "$(compatibility_stable_file_identity \
        "${source_cells[index]}" 67108864)" == \
        "${source_cell_identities[index]}" &&
      "$(compatibility_stable_file_identity \
        "${source_cell_sha_files[index]}" 4096)" == \
        "${source_cell_sha_identities[index]}" &&
      "$(compatibility_stable_file_identity \
        "${source_private_manifests[index]}" 67108864)" == \
        "${source_private_manifest_identities[index]}" ]] ||
      compatibility_die "collector public input changed after snapshot" || return
  done
  while IFS=$'\t' read -r cell_id cell_sha; do
    [[ "$(compatibility_sha256 "$staging/cells/$cell_id.json")" == \
      "$cell_sha" ]] ||
      compatibility_die "staged collection cell changed before publication" || return
  done < <(jq -r '[.cell_id,.record.sha256] | @tsv' "$records")
  [[ "$(compatibility_stable_file_identity "$records" 67108864)" == \
      "$records_identity" &&
    "$(compatibility_stable_file_identity \
      "$driver_identities" 67108864)" == "$driver_identities_identity" &&
    "$(compatibility_stable_file_identity \
      "$lifecycle_executor_identities" 67108864)" == \
      "$lifecycle_executor_identities_identity" &&
    "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_PROVIDER_REGISTRY" 67108864)" == \
      "$registry_source_identity" &&
    "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY" 67108864)" == \
      "$lifecycle_executor_registry_source_identity" &&
    "$(compatibility_stable_file_identity "$registry_snapshot" 67108864)" == \
      "$registry_snapshot_identity" &&
    "$(compatibility_stable_file_identity \
      "$lifecycle_executor_registry_snapshot" 67108864)" == \
      "$lifecycle_executor_registry_snapshot_identity" &&
    "$(compatibility_stable_file_identity "$plan_source" 67108864)" == \
      "$plan_source_identity" &&
    "$(compatibility_stable_file_identity "$plan" 67108864)" == \
      "$plan_snapshot_identity" &&
    "$(compatibility_stable_file_identity "$expected_ids_source" 1048576)" == \
      "$expected_ids_source_identity" &&
    "$(compatibility_stable_file_identity "$expected_ids" 1048576)" == \
      "$expected_ids_snapshot_identity" &&
    "$(compatibility_stable_file_identity \
      "$source_authority_input" 67108864)" == \
      "$source_authority_source_identity" &&
    "$(compatibility_stable_file_identity "$source_authority" 67108864)" == \
      "$source_authority_snapshot_identity" ]] ||
    compatibility_die "collector authority changed before publication" || return
  compatibility_source_authority_matches_checkout "$source_authority" || return
  staging_identity="$(compatibility_stable_directory_identity "$staging")" ||
    return
  compatibility_publish_stable_directory \
    "$staging_source" "$staging_identity" "$output" || return
}

main "$@"
