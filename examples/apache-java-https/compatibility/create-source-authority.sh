#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/lib.sh"

AUTHORITY_TEMP_DIRECTORY=""
AUTHORITY_TEMP_IDENTITY=""
AUTHORITY_TEMP_PARENT=""

cleanup_authority_temp() {
  [[ -n "$AUTHORITY_TEMP_DIRECTORY" ]] || return 0
  compatibility_remove_owned_temp_directory \
    "$AUTHORITY_TEMP_DIRECTORY" "$AUTHORITY_TEMP_IDENTITY" \
    "$AUTHORITY_TEMP_PARENT" "[.]compatibility-authority[.]" ||
    compatibility_error "refused to remove replaced source-authority scratch directory"
}

usage() {
  printf '%s\n' \
    'Usage: create-source-authority.sh --output FILE' \
    '' \
    'The checkout must be clean. Output must be outside the checkout.' >&2
}

main() {
  local output=""
  local output_parent=""
  local output_name=""

  while (( $# > 0 )); do
    case "$1" in
      --output)
        (( $# >= 2 )) || { usage; return 2; }
        output="$2"
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
  [[ -n "$output" ]] || { usage; return 2; }

  compatibility_require_commands git jq mktemp mv sha256sum stat || return
  [[ ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "source-authority output already exists: $output" || return
  output_parent="$(dirname -- "$output")" || return
  output_name="$(basename -- "$output")" || return
  compatibility_require_directory "$output_parent" || return
  output_parent="$(cd -- "$output_parent" && pwd -P)" || return
  compatibility_require_outside_repository "$output_parent" || return
  [[ "$output_name" != . && "$output_name" != .. && "$output_name" != */* &&
    "$output_name" != *$'\n'* ]] ||
    compatibility_die "unsafe source-authority output name" || return
  output="$output_parent/$output_name"

  AUTHORITY_TEMP_DIRECTORY="$(
    mktemp -d "$output_parent/.compatibility-authority.XXXXXX"
  )" || return
  AUTHORITY_TEMP_PARENT="$output_parent"
  AUTHORITY_TEMP_IDENTITY="$(
    compatibility_directory_identity "$AUTHORITY_TEMP_DIRECTORY"
  )" || return
  trap cleanup_authority_temp EXIT
  chmod 0700 -- "$AUTHORITY_TEMP_DIRECTORY"

  compatibility_capture_clean_source_authority \
    "$COMPATIBILITY_REPOSITORY_ROOT" "$AUTHORITY_TEMP_DIRECTORY" \
    "$AUTHORITY_TEMP_DIRECTORY/source-authority.json" || return
  mv -T -- "$AUTHORITY_TEMP_DIRECTORY/source-authority.json" "$output"
}

main "$@"
