#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

# Private snapshots and transaction metadata must not inherit permissive caller
# defaults. The projector is a child process, so this does not alter the
# invoking shell's umask; public modes are set explicitly during sealing.
umask 077

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERIFIER="$SCRIPT_DIR/verify-retained-evidence.sh"
readonly SCRIPT_NAME SCRIPT_DIR VERIFIER
readonly RAW_MAX_FILES=32768
readonly RAW_MAX_BYTES=603979776
readonly PUBLIC_MAX_FILES=8192
readonly PUBLIC_MAX_BYTES=268435456
readonly RUNBOOK_MAX_BYTES=1048576
readonly RESOURCE_VM_MAX_KIB=17179869184
readonly RESOURCE_FDS_MAX=4096
readonly RESOURCE_THREADS_MAX=2048
readonly RESOURCE_RSS_MAX_KIB=4194304
readonly OTEL_AGENT_VERSION='2.28.1'
readonly OTEL_AGENT_SHA256='faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589'
readonly OTEL_AGENT_URL='https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar'

ACCEPTANCE_SOURCE=""
ASSERTION_SOURCE=""
RUNBOOK_SOURCE=""
OUTPUT_DIRECTORY=""
OUTPUT_PARENT=""
OUTPUT_NAME=""
WORK_DIRECTORY=""
WORK_IDENTITY=""
CANDIDATE_DIRECTORY=""
CANDIDATE_IDENTITY=""
ACCEPTANCE_SNAPSHOT=""
ASSERTION_SNAPSHOT=""
RUNBOOK_SNAPSHOT=""
ACCEPTANCE_PRIVATE_STAT=""
ASSERTION_PRIVATE_STAT=""
RUNBOOK_PRIVATE_SHA256=""

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME ABS_ACCEPTANCE_ALL ABS_ASSERTION_FAILURE ABS_RUNBOOK_RECEIPT ABS_NONEXISTENT_OUTPUT" \
    "" \
    "Validate two private v3 runs and publish one closed seven-file bounded-claim summary." \
    "All inputs and the output must be absolute paths. The output must not exist."
}

die() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

materialize_cleanup_directories() {
  local -r path="$1"
  local -r root_device="$2"
  local -r output="$3"
  local directory=""
  local identity=""
  local device=""
  local owner=""
  local mount_status=0

  find -- "$path" -xdev -type d -print0 | LC_ALL=C sort -z >"$output" ||
    return 1
  while IFS= read -r -d '' directory; do
    [[ -d "$directory" && ! -L "$directory" &&
      "$(readlink -f -- "$directory")" == "$directory" ]] || return 1
    identity="$(stat -Lc '%d:%u' -- "$directory")" || return 1
    IFS=: read -r device owner <<<"$identity"
    [[ "$device" == "$root_device" && "$owner" == "$EUID" ]] || return 1
    if [[ "$directory" != "$path" ]]; then
      if mountpoint -q -- "$directory"; then
        return 1
      else
        mount_status=$?
        ((mount_status == 32)) || return 1
      fi
    fi
  done <"$output"
}

open_cleanup_directories() {
  local -r path="$1"
  local -r root_device="$2"
  local -r input="$3"
  local directory=""
  local identity=""
  local descriptor_identity=""
  local path_identity=""
  local directory_fd=""
  local mount_status=0

  while IFS= read -r -d '' directory; do
    [[ -d "$directory" && ! -L "$directory" &&
      "$(readlink -f -- "$directory")" == "$directory" ]] || return 1
    identity="$(stat -Lc '%d:%i:%u' -- "$directory")" || return 1
    [[ "${identity%%:*}" == "$root_device" && "${identity##*:}" == "$EUID" ]] ||
      return 1
    if [[ "$directory" != "$path" ]]; then
      if mountpoint -q -- "$directory"; then
        return 1
      else
        mount_status=$?
        ((mount_status == 32)) || return 1
      fi
    fi
    exec {directory_fd}<"$directory" || return 1
    descriptor_identity="$(stat -Lc '%d:%i:%u' \
      -- "/proc/self/fd/$directory_fd")" || {
      exec {directory_fd}<&-
      return 1
    }
    path_identity="$(stat -Lc '%d:%i:%u' -- "$directory")" || {
      exec {directory_fd}<&-
      return 1
    }
    [[ "$descriptor_identity" == "$identity" && "$path_identity" == "$identity" &&
      -d "/proc/self/fd/$directory_fd" ]] || {
      exec {directory_fd}<&-
      return 1
    }
    chmod u+rwx -- "/proc/self/fd/$directory_fd" >/dev/null 2>&1 || {
      exec {directory_fd}<&-
      return 1
    }
    exec {directory_fd}<&-
  done <"$input"
}

cleanup_owned_directory() {
  local -r path="$1"
  local -r expected_identity="$2"
  local observed_identity=""
  local root_device=""
  local parent=""
  local first=""
  local second=""
  local status=0

  [[ -n "$path" && -n "$expected_identity" && -d "$path" && ! -L "$path" ]] ||
    return 0
  observed_identity="$(stat -Lc '%d:%i:%u' -- "$path")" || return 1
  [[ "$observed_identity" == "$expected_identity" ]] || return 1
  root_device="${expected_identity%%:*}"
  parent="${path%/*}"
  first="$(mktemp "$parent/.cleanup-directories.XXXXXX")" || return 1
  second="$(mktemp "$parent/.cleanup-directories.XXXXXX")" || {
    rm -f -- "$first" >/dev/null 2>&1 || true
    return 1
  }
  chmod 0600 -- "$first" "$second" || status=1
  if ((status == 0)); then
    materialize_cleanup_directories "$path" "$root_device" "$first" || status=1
  fi
  if ((status == 0)); then
    open_cleanup_directories "$path" "$root_device" "$first" || status=1
  fi
  if ((status == 0)); then
    materialize_cleanup_directories "$path" "$root_device" "$second" || status=1
  fi
  if ((status == 0)); then
    cmp -s -- "$first" "$second" || status=1
  fi
  observed_identity="$(stat -Lc '%d:%i:%u' -- "$path" 2>/dev/null || true)"
  [[ "$observed_identity" == "$expected_identity" ]] || status=1
  if ((status == 0)); then
    rm --one-file-system -rf -- "$path" || status=1
  fi
  rm -f -- "$first" "$second" || status=1
  [[ ! -e "$path" && ! -L "$path" ]] || status=1
  ((status == 0))
}

cleanup() {
  local status=0

  if [[ -n "${CANDIDATE_DIRECTORY:-}" && -d "$CANDIDATE_DIRECTORY" &&
    ! -L "$CANDIDATE_DIRECTORY" ]]; then
    cleanup_owned_directory "$CANDIDATE_DIRECTORY" "$CANDIDATE_IDENTITY" || status=1
  elif [[ -n "${CANDIDATE_DIRECTORY:-}" &&
    ( -e "$CANDIDATE_DIRECTORY" || -L "$CANDIDATE_DIRECTORY" ) ]]; then
    status=1
  fi
  if [[ -n "${WORK_DIRECTORY:-}" && -d "$WORK_DIRECTORY" &&
    ! -L "$WORK_DIRECTORY" ]]; then
    cleanup_owned_directory "$WORK_DIRECTORY" "$WORK_IDENTITY" || status=1
  elif [[ -n "${WORK_DIRECTORY:-}" &&
    ( -e "$WORK_DIRECTORY" || -L "$WORK_DIRECTORY" ) ]]; then
    status=1
  fi
  if ((status != 0)); then
    printf '%s: private transaction cleanup was incomplete\n' \
      "$SCRIPT_NAME" >&2
    return 1
  fi
}

cleanup_on_exit() {
  local -r original_status="$?"
  local cleanup_status=0

  trap - EXIT
  cleanup || cleanup_status=$?
  if ((original_status == 0 && cleanup_status != 0)); then
    exit 1
  fi
  exit "$original_status"
}

on_error() {
  local -r line="$1"
  local -r status="$2"
  printf '%s: command failed at line %s with status %s\n' \
    "$SCRIPT_NAME" "$line" "$status" >&2
}

trap 'on_error "$LINENO" "$?"' ERR
trap cleanup_on_exit EXIT

check_dependencies() {
  local -a missing=()
  local command_name=""

  for command_name in awk cat chmod cmp cp dirname find git grep jq mkdir mktemp \
    mountpoint mv readlink rm sha256sum sort stat tail wc; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  (( ${#missing[@]} == 0 )) || die "missing required commands: ${missing[*]}"
  [[ -x "$VERIFIER" ]] || die "retained evidence verifier is not executable"
}

is_sha1() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

is_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

is_allowed_raw_source_owner() {
  [[ "$1" == "$EUID" || "$1" == 0 ]]
}

is_safe_relative_path() {
  local path="$1"
  local component=""

  [[ -n "$path" && "$path" != /* && "$path" != */ && "$path" != *'//' ]] ||
    return 1
  while [[ "$path" == */* ]]; do
    component="${path%%/*}"
    [[ "$component" =~ ^[A-Za-z0-9._-]+$ && "$component" != . &&
      "$component" != .. ]] || return 1
    path="${path#*/}"
  done
  [[ "$path" =~ ^[A-Za-z0-9._-]+$ && "$path" != . && "$path" != .. ]]
}

assert_absolute_physical_directory() {
  local -r path="$1"
  local owner=""
  local mode=""
  local -i mode_bits=0

  [[ "$path" == /* && "$path" != */ && -d "$path" && ! -L "$path" ]] ||
    return 1
  [[ "$(cd -- "$path" && pwd -P)" == "$path" ]] || return 1
  owner="$(stat -Lc '%u' -- "$path")" || return 1
  mode="$(stat -Lc '%a' -- "$path")" || return 1
  is_allowed_raw_source_owner "$owner" || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_bits=$((8#$mode))
  (( (mode_bits & 0022) == 0 ))
}

assert_output_parent() {
  local owner=""
  local mode=""
  local -i mode_bits=0

  [[ "$OUTPUT_DIRECTORY" == /* && "$OUTPUT_DIRECTORY" != */ &&
    ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]] ||
    die "output must be a nonexistent absolute path"
  OUTPUT_PARENT="${OUTPUT_DIRECTORY%/*}"
  OUTPUT_NAME="${OUTPUT_DIRECTORY##*/}"
  [[ -n "$OUTPUT_PARENT" && "$OUTPUT_NAME" =~ ^[a-z0-9][a-z0-9._-]*$ ]] ||
    die "output name is not a safe evidence identifier"
  [[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" &&
    "$(cd -- "$OUTPUT_PARENT" && pwd -P)" == "$OUTPUT_PARENT" ]] ||
    die "output parent must be a physical directory"
  owner="$(stat -Lc '%u' -- "$OUTPUT_PARENT")" || die "could not inspect output parent"
  mode="$(stat -Lc '%a' -- "$OUTPUT_PARENT")" || die "could not inspect output parent"
  [[ "$owner" == "$EUID" && "$mode" =~ ^[0-7]{3,4}$ ]] ||
    die "output parent ownership or mode is unsafe"
  mode_bits=$((8#$mode))
  (( (mode_bits & 0022) == 0 )) || die "output parent must not be group/world writable"
}

write_sorted_directory_entries() {
  local -r source="$1"
  local -r files_only="$2"
  local -r output="$3"

  [[ "$output" == "$WORK_DIRECTORY/"* && -f "$output" && ! -L "$output" ]] ||
    return 1
  if [[ "$files_only" == true ]]; then
    find -- "$source" -xdev -mindepth 1 -type f -print0 |
      LC_ALL=C sort -z >"$output"
  elif [[ "$files_only" == false ]]; then
    find -- "$source" -xdev -mindepth 1 -print0 |
      LC_ALL=C sort -z >"$output"
  else
    return 1
  fi
}

assert_pinned_directory_identity() {
  local -r path="$1"
  local -r expected_identity="$2"

  [[ -d "$path" && ! -L "$path" &&
    "$(cd -- "$path" && pwd -P)" == "$path" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$path")" == "$expected_identity" ]]
}

preflight_directory_budget() {
  local -r source="$1"
  local path=""
  local relative=""
  local owner=""
  local mode=""
  local links=""
  local size=""
  local root_device=""
  local device=""
  local entries=""
  local -i mode_bits=0
  local -i directories=0
  local -i files=0
  local -i bytes=0

  assert_absolute_physical_directory "$source" || return 1
  entries="$(mktemp "$WORK_DIRECTORY/preflight-entries.XXXXXX")" || return 1
  write_sorted_directory_entries "$source" false "$entries" || return 1
  root_device="$(stat -Lc '%d' -- "$source")" || return 1
  [[ "$root_device" =~ ^[0-9]+$ ]] || return 1
  while IFS= read -r -d '' path; do
    relative="${path#"$source"/}"
    is_safe_relative_path "$relative" || return 1
    [[ ! -L "$path" ]] || return 1
    device="$(stat -Lc '%d' -- "$path")" || return 1
    [[ "$device" == "$root_device" ]] || return 1
    owner="$(stat -Lc '%u' -- "$path")" || return 1
    mode="$(stat -Lc '%a' -- "$path")" || return 1
    links="$(stat -Lc '%h' -- "$path")" || return 1
    is_allowed_raw_source_owner "$owner" || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    mode_bits=$((8#$mode))
    (( (mode_bits & 0022) == 0 )) || return 1
    if [[ -d "$path" ]]; then
      ((directories < RAW_MAX_FILES)) || return 1
      directories=$((directories + 1))
      [[ -n "$(find -- "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        return 1
      continue
    fi
    [[ -f "$path" && "$links" == 1 ]] || return 1
    size="$(stat -Lc '%s' -- "$path")" || return 1
    [[ "$size" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    ((files < RAW_MAX_FILES && bytes <= RAW_MAX_BYTES - size)) || return 1
    files=$((files + 1))
    bytes=$((bytes + size))
  done <"$entries"
  rm -f -- "$entries" || return 1
  ((files > 0))
}

write_source_manifest() {
  local -r source="$1"
  local -r output="$2"
  local path=""
  local relative=""
  local identity=""
  local descriptor_identity=""
  local descriptor_path=""
  local digest=""
  local source_fd=""
  local root_device=""
  local device=""
  local entries=""

  : >"$output"
  entries="$(mktemp "$WORK_DIRECTORY/manifest-entries.XXXXXX")" || return 1
  write_sorted_directory_entries "$source" true "$entries" || return 1
  root_device="$(stat -Lc '%d' -- "$source")" || return 1
  [[ "$root_device" =~ ^[0-9]+$ ]] || return 1
  while IFS= read -r -d '' path; do
    [[ -f "$path" && ! -L "$path" ]] || continue
    device="$(stat -Lc '%d' -- "$path")" || return 1
    [[ "$device" == "$root_device" ]] || return 1
    relative="${path#"$source"/}"
    is_safe_relative_path "$relative" || return 1
    identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" || return 1
    exec {source_fd}<"$path" || return $?
    descriptor_path="/proc/$BASHPID/fd/$source_fd"
    descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
      -- "$descriptor_path")" || {
      exec {source_fd}<&-
      return 1
    }
    [[ "$descriptor_identity" == "$identity" ]] || {
      exec {source_fd}<&-
      return 1
    }
    digest="$(sha256sum <"$descriptor_path")" || {
      exec {source_fd}<&-
      return 1
    }
    digest="${digest%% *}"
    descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
      -- "$descriptor_path")" || {
      exec {source_fd}<&-
      return 1
    }
    exec {source_fd}<&-
    [[ -f "$path" && ! -L "$path" &&
      "$(readlink -f -- "$path")" == "$path" &&
      "$descriptor_identity" == "$identity" &&
      "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" == "$identity" ]] ||
      return 1
    is_sha256 "$digest" || return 1
    printf '%s\t%s\t%s\n' "$relative" "$identity" "$digest" >>"$output" ||
      return 1
  done <"$entries"
  rm -f -- "$entries"
}

copy_pinned_file() {
  local -r source="$1"
  local -r destination="$2"
  local -r expected_identity="$3"
  local -r expected_digest="$4"
  local descriptor_path=""
  local identity=""
  local digest=""
  local descriptor_digest=""
  local destination_digest=""
  local source_fd=""

  [[ -f "$source" && ! -L "$source" && ! -e "$destination" &&
    ! -L "$destination" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source")" || return 1
  [[ "$identity" == "$expected_identity" ]] || return 1
  exec {source_fd}<"$source" || return $?
  descriptor_path="/proc/$BASHPID/fd/$source_fd"
  identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  [[ "$identity" == "$expected_identity" ]] || {
    exec {source_fd}<&-
    return 1
  }
  digest="$(sha256sum <"$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  digest="${digest%% *}"
  [[ "$digest" == "$expected_digest" ]] || {
    exec {source_fd}<&-
    return 1
  }
  mkdir -p -- "${destination%/*}" || {
    exec {source_fd}<&-
    return 1
  }
  cp -- "$descriptor_path" "$destination" || {
    exec {source_fd}<&-
    return 1
  }
  chmod 0600 -- "$destination" || {
    exec {source_fd}<&-
    return 1
  }
  destination_digest="$(sha256sum <"$destination")" || {
    exec {source_fd}<&-
    return 1
  }
  destination_digest="${destination_digest%% *}"
  identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  descriptor_digest="$(sha256sum <"$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  descriptor_digest="${descriptor_digest%% *}"
  exec {source_fd}<&-
  [[ -f "$source" && ! -L "$source" &&
    "$(readlink -f -- "$source")" == "$source" &&
    "$destination_digest" == "$expected_digest" &&
    "$descriptor_digest" == "$expected_digest" &&
    "$identity" == "$expected_identity" &&
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source")" == "$expected_identity" ]]
}

snapshot_directory() {
  local -r source="$1"
  local -r destination_parent="$2"
  local -r before_manifest="$destination_parent.before"
  local -r after_manifest="$destination_parent.after"
  local -r destination="$destination_parent/${source##*/}"
  local relative=""
  local identity=""
  local digest=""
  local root_identity=""

  root_identity="$(stat -Lc '%d:%i:%u:%a' -- "$source")" ||
    die "could not pin raw input root identity"
  assert_pinned_directory_identity "$source" "$root_identity" ||
    die "raw input root is not stable"
  preflight_directory_budget "$source" || die "raw input is unsafe or exceeds its budget"
  assert_pinned_directory_identity "$source" "$root_identity" ||
    die "raw input root changed during preflight"
  write_source_manifest "$source" "$before_manifest" || die "could not freeze raw input"
  assert_pinned_directory_identity "$source" "$root_identity" ||
    die "raw input root changed while freezing"
  mkdir -m 0700 -- "$destination_parent" "$destination" ||
    die "could not create private raw snapshot"
  while IFS=$'\t' read -r relative identity digest; do
    copy_pinned_file \
      "$source/$relative" "$destination/$relative" "$identity" "$digest" ||
      die "raw input changed during pinned copy: $relative"
  done <"$before_manifest"
  assert_pinned_directory_identity "$source" "$root_identity" ||
    die "raw input root changed during pinned copy"
  write_source_manifest "$source" "$after_manifest" || die "could not recheck raw input"
  preflight_directory_budget "$source" ||
    die "raw input changed to an unsafe or oversized layout"
  cmp -s -- "$before_manifest" "$after_manifest" ||
    die "raw input changed during pinned copy"
  assert_pinned_directory_identity "$source" "$root_identity" ||
    die "raw input root changed after pinned copy"
  printf '%s\n' "$destination"
}

snapshot_runbook_receipt() {
  local identity=""
  local digest=""
  local before_identity=""
  local links=""
  local mode=""
  local size=""
  local -i mode_bits=0

  [[ "$RUNBOOK_SOURCE" == /* && -f "$RUNBOOK_SOURCE" && ! -L "$RUNBOOK_SOURCE" ]] ||
    die "runbook receipt must be an absolute regular-file path"
  before_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$RUNBOOK_SOURCE")" ||
    die "could not inspect runbook receipt"
  IFS=: read -r _ _ identity _ links size <<<"$before_identity"
  mode="$(stat -Lc '%a' -- "$RUNBOOK_SOURCE")" ||
    die "could not inspect runbook receipt mode"
  [[ "$mode" == 600 && "$links" == 1 &&
    "$size" =~ ^(0|[1-9][0-9]*)$ ]] ||
    die "runbook receipt mode, link count, or size is invalid"
  mode_bits=$((8#$mode))
  [[ "$identity" == "$EUID" && $mode_bits == 384 ]] ||
    die "runbook receipt must be EUID-owned mode 0600 with one link"
  ((size <= RUNBOOK_MAX_BYTES)) || die "runbook receipt exceeds its byte cap"
  digest="$(sha256sum <"$RUNBOOK_SOURCE")" || die "could not hash runbook receipt"
  digest="${digest%% *}"
  RUNBOOK_SNAPSHOT="$WORK_DIRECTORY/runbook-receipt.json"
  copy_pinned_file "$RUNBOOK_SOURCE" "$RUNBOOK_SNAPSHOT" \
    "$before_identity" "$digest" || die "runbook receipt changed during pinned copy"
}

source_manifest_stat_json() {
  local -r snapshot="$1"
  local -r role="${2:-${snapshot##*/}}"
  local manifest="$WORK_DIRECTORY/$role.publication-manifest"
  local path=""
  local relative=""
  local digest=""
  local size=""
  local manifest_digest=""
  local run_status_digest=""
  local entries=""
  local -i file_count=0
  local -i total_bytes=0

  is_safe_relative_path "$role" || return 1
  printf '%s\n%s\n' 'obi-private-file-manifest-commitment-v1' "$role" \
    >"$manifest" || return 1
  entries="$(mktemp "$WORK_DIRECTORY/publication-entries.XXXXXX")" || return 1
  write_sorted_directory_entries "$snapshot" true "$entries" || return 1
  while IFS= read -r -d '' path; do
    relative="${path#"$snapshot"/}"
    digest="$(sha256sum <"$path")" || return 1
    digest="${digest%% *}"
    size="$(stat -Lc '%s' -- "$path")" || return 1
    printf '%s  ./%s\n' "$digest" "$relative" >>"$manifest" || return 1
    file_count=$((file_count + 1))
    total_bytes=$((total_bytes + size))
  done <"$entries"
  rm -f -- "$entries" || return 1
  manifest_digest="$(sha256sum <"$manifest")" || return 1
  manifest_digest="${manifest_digest%% *}"
  run_status_digest="$(sha256sum <"$snapshot/run-status.json")" || return 1
  run_status_digest="${run_status_digest%% *}"
  jq -cn --argjson file_count "$file_count" --argjson total_bytes "$total_bytes" \
    --arg manifest_sha256 "$manifest_digest" --arg role "$role" \
    --arg run_status_sha256 "$run_status_digest" '{
      file_count: $file_count,
      commitment_schema: "obi-private-file-manifest-commitment-v1",
      manifest_sha256: $manifest_sha256,
      role: $role,
      run_status_sha256: $run_status_sha256,
      total_bytes: $total_bytes
    }'
}

capture_private_input_authority() {
  ACCEPTANCE_PRIVATE_STAT="$(source_manifest_stat_json \
    "$ACCEPTANCE_SNAPSHOT" acceptance)" || return 1
  ASSERTION_PRIVATE_STAT="$(source_manifest_stat_json \
    "$ASSERTION_SNAPSHOT" assertion-failure)" || return 1
  RUNBOOK_PRIVATE_SHA256="$(sha256sum <"$RUNBOOK_SNAPSHOT")" || return 1
  RUNBOOK_PRIVATE_SHA256="${RUNBOOK_PRIVATE_SHA256%% *}"
  is_sha256 "$RUNBOOK_PRIVATE_SHA256"
}

assert_private_input_authority_unchanged() {
  local acceptance=""
  local assertion=""
  local runbook=""

  acceptance="$(source_manifest_stat_json \
    "$ACCEPTANCE_SNAPSHOT" acceptance)" || return 1
  assertion="$(source_manifest_stat_json \
    "$ASSERTION_SNAPSHOT" assertion-failure)" || return 1
  runbook="$(sha256sum <"$RUNBOOK_SNAPSHOT")" || return 1
  runbook="${runbook%% *}"
  [[ "$acceptance" == "$ACCEPTANCE_PRIVATE_STAT" &&
    "$assertion" == "$ASSERTION_PRIVATE_STAT" &&
    "$runbook" == "$RUNBOOK_PRIVATE_SHA256" ]]
}

seal_private_input_snapshots() {
  find -- "$ACCEPTANCE_SNAPSHOT" "$ASSERTION_SNAPSHOT" -type f \
    -exec chmod 0400 -- {} + || return 1
  find -- "$ACCEPTANCE_SNAPSHOT" "$ASSERTION_SNAPSHOT" -depth -type d \
    -exec chmod 0500 -- {} + || return 1
  chmod 0400 -- "$RUNBOOK_SNAPSHOT"
}

write_file() {
  local -r relative="$1"
  local -r destination="$CANDIDATE_DIRECTORY/$relative"

  is_safe_relative_path "$relative" || return 1
  [[ ! -e "$destination" && ! -L "$destination" ]] || return 1
  mkdir -p -- "${destination%/*}" || return 1
  cat >"$destination" || return 1
  chmod 0644 -- "$destination"
}

key_value() {
  local -r file="$1"
  local -r wanted="$2"
  local line=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "${line%%=*}" == "$wanted" ]] || continue
    printf '%s\n' "${line#*=}"
    return 0
  done <"$file"
  return 1
}

validate_official_javaagent_metadata() {
  local -r path="$1"

  [[ -f "$path" && ! -L "$path" ]] || return 1
  jq -e -s --arg version "$OTEL_AGENT_VERSION" \
    --arg sha256 "$OTEL_AGENT_SHA256" --arg url "$OTEL_AGENT_URL" '
    length == 1 and (.[0] | keys == [
      "distribution", "sha256", "url", "version"
    ]) and .[0] == {
      distribution: "otel",
      sha256: $sha256,
      url: $url,
      version: $version
    }
  ' "$path" >/dev/null
}

assert_raw_runs_share_authority() {
  local acceptance_revision=""
  local assertion_revision=""
  local acceptance_tree=""
  local assertion_tree=""
  local acceptance_architecture=""
  local file=""
  local field=""
  local acceptance_value=""
  local assertion_value=""
  local -a shared_environment_fields=(
    revision source_tree_sha256 source_tree_manifest_schema dirty
    tracked_patch_sha256 patch_identity_sha256 transport agent_distribution
    tls_protocol obi_log_level request_count repeat_count scenario_seed
    bridge_build_mode architecture
  )

  acceptance_revision="$(key_value "$ACCEPTANCE_SNAPSHOT/environment.txt" revision)" ||
    return 1
  assertion_revision="$(key_value "$ASSERTION_SNAPSHOT/environment.txt" revision)" ||
    return 1
  acceptance_tree="$(key_value \
    "$ACCEPTANCE_SNAPSHOT/environment.txt" source_tree_sha256)" || return 1
  acceptance_architecture="$(key_value \
    "$ACCEPTANCE_SNAPSHOT/environment.txt" architecture)" || return 1
  assertion_tree="$(key_value \
    "$ASSERTION_SNAPSHOT/environment.txt" source_tree_sha256)" || return 1
  [[ "$acceptance_revision" == "$assertion_revision" &&
    "$acceptance_tree" == "$assertion_tree" ]] || return 1
  validate_official_javaagent_metadata \
    "$ACCEPTANCE_SNAPSHOT/official-javaagent.json" || return 1
  validate_official_javaagent_metadata \
    "$ASSERTION_SNAPSHOT/official-javaagent.json" || return 1
  for field in "${shared_environment_fields[@]}"; do
    acceptance_value="$(key_value \
      "$ACCEPTANCE_SNAPSHOT/environment.txt" "$field")" || return 1
    assertion_value="$(key_value \
      "$ASSERTION_SNAPSHOT/environment.txt" "$field")" || return 1
    [[ "$acceptance_value" == "$assertion_value" ]] || return 1
  done
  for file in source-tree.manifest bridge-artifacts.json bridge-source-revision.txt \
    bridge-source-tree.sha256 official-javaagent.json source-state.txt git-status.txt; do
    cmp -s -- "$ACCEPTANCE_SNAPSHOT/$file" "$ASSERTION_SNAPSHOT/$file" || return 1
  done
  jq -e --arg revision "$acceptance_revision" --arg tree "$acceptance_tree" \
    --arg architecture "$acceptance_architecture" '
    .source_revision == $revision and .source_tree_sha256 == $tree
    and .environment.architecture == $architecture
  ' "$RUNBOOK_SNAPSHOT" >/dev/null
}

sanitize_projector_git_environment() {
  local variable=""

  unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CEILING_DIRECTORIES GIT_COMMON_DIR \
    GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM \
    GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_DIR GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_GLOB_PATHSPECS GIT_INDEX_FILE GIT_LITERAL_PATHSPECS GIT_NAMESPACE \
    GIT_NOGLOB_PATHSPECS GIT_OBJECT_DIRECTORY GIT_OPTIONAL_LOCKS \
    GIT_REPLACE_REF_BASE GIT_WORK_TREE
  for variable in "${!GIT_CONFIG_KEY_@}" "${!GIT_CONFIG_VALUE_@}"; do
    [[ -n "$variable" ]] || continue
    unset "$variable"
  done
  export GIT_NO_REPLACE_OBJECTS=1
}

validate_otel_agent_source_contract() {
  local -r repository="$1"
  local -r head="$2"
  local -r source_path='examples/apache-java-https/scripts/download-agent.sh'
  local actual=""
  local expected=""

  actual="$(mktemp "$WORK_DIRECTORY/otel-agent-source.actual.XXXXXX")" || return 1
  expected="$(mktemp "$WORK_DIRECTORY/otel-agent-source.expected.XXXXXX")" ||
    return 1
  git -C "$repository" show "$head:$source_path" | awk '
    $0 == "    otel)" && capturing == 0 { capturing = 1 }
    capturing == 1 { print }
    capturing == 1 && $0 == "      ;;" { complete = 1; exit }
    END { if (complete != 1) exit 1 }
  ' >"$actual" || return 1
  printf '%s\n' \
    '    otel)' \
    '      VERSION="2.28.1"' \
    '      SHA256="faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589"' \
    '      URL="https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/${VERSION}/opentelemetry-javaagent-${VERSION}.jar"' \
    '      ;;' >"$expected" || return 1
  cmp -s -- "$expected" "$actual"
}

validate_execution_bytes_and_locator() {
  local repository=""
  local expected_repository=""
  local head=""
  local acceptance_revision=""
  local assertion_revision=""
  local receipt_revision=""
  local workflow_path=""
  local workflow_sha=""
  local workflow_digest=""
  local expected_workflow_digest=""
  local relative=""
  local tracked_mode=""
  local actual_mode=""
  local actual_owner=""

  sanitize_projector_git_environment
  repository="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)" || return 1
  repository="$(cd -- "$repository" && pwd -P)" || return 1
  expected_repository="$(cd -- "$SCRIPT_DIR/../../.." && pwd -P)" || return 1
  [[ "$repository" == "$expected_repository" ]] || return 1
  head="$(git -C "$repository" rev-parse --verify 'HEAD^{commit}')" || return 1
  is_sha1 "$head" || return 1
  acceptance_revision="$(key_value \
    "$ACCEPTANCE_SNAPSHOT/environment.txt" revision)" || return 1
  assertion_revision="$(key_value \
    "$ASSERTION_SNAPSHOT/environment.txt" revision)" || return 1
  receipt_revision="$(jq -er '.source_revision' "$RUNBOOK_SNAPSHOT")" || return 1
  workflow_path="$(jq -er '.execution_locator.workflow_path' \
    "$RUNBOOK_SNAPSHOT")" || return 1
  workflow_sha="$(jq -er '.execution_locator.workflow_sha' \
    "$RUNBOOK_SNAPSHOT")" || return 1
  expected_workflow_digest="$(jq -er '.execution_locator.workflow_blob_sha256' \
    "$RUNBOOK_SNAPSHOT")" || return 1
  [[ "$acceptance_revision" == "$head" && "$assertion_revision" == "$head" &&
    "$receipt_revision" == "$head" && "$workflow_sha" == "$head" &&
    "$workflow_path" == ".github/workflows/java_remote_parent_acceptance_claims.yml" &&
    "$expected_workflow_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  validate_otel_agent_source_contract "$repository" "$head" || return 1
  [[ -z "$(git -C "$repository" status --porcelain=v1 \
    --untracked-files=all --ignore-submodules=none)" ]] || return 1

  for relative in \
    examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh \
    examples/apache-java-https/scripts/verify-retained-evidence.sh; do
    [[ -f "$repository/$relative" && ! -L "$repository/$relative" &&
      "$(readlink -f -- "$repository/$relative")" == "$repository/$relative" ]] ||
      return 1
    git -C "$repository" diff --quiet --no-ext-diff --no-textconv HEAD -- \
      "$relative" || return 1
    tracked_mode="$(git -C "$repository" ls-tree HEAD -- "$relative" |
      awk 'NR == 1 { print $1 } END { if (NR != 1) exit 1 }')" || return 1
    actual_mode="$(stat -Lc '%a' -- "$repository/$relative")" || return 1
    actual_owner="$(stat -Lc '%u' -- "$repository/$relative")" || return 1
    [[ "$tracked_mode" == 100755 && "$actual_mode" == 755 &&
      "$actual_owner" == "$EUID" ]] || return 1
  done
  workflow_digest="$(git -C "$repository" show "$workflow_sha:$workflow_path" |
    sha256sum)" || return 1
  workflow_digest="${workflow_digest%% *}"
  [[ "$workflow_digest" == "$expected_workflow_digest" ]]
}

read_resource_record() {
  local -r relative_path="$1"
  local -r path="$ACCEPTANCE_SNAPSHOT/$relative_path"
  local -a lines=()
  local -a vm_names=(VmPeak VmSize VmRSS VmData VmStk VmExe VmLib)
  local -a vm_values=()
  local container_id=""
  local host_pid=""
  local threads=""
  local fds=""
  local value=""
  local -i index=0

  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ -s "$path" && -z "$(tail -c 1 -- "$path")" ]] || return 1
  mapfile -t lines <"$path" || return 1
  ((${#lines[@]} == 11)) || return 1
  [[ "${lines[0]}" =~ ^container_id=([0-9a-f]{64})$ ]] || return 1
  container_id="${BASH_REMATCH[1]}"
  [[ "${lines[1]}" =~ ^host_pid=([1-9][0-9]*)$ ]] || return 1
  host_pid="${BASH_REMATCH[1]}"
  ((host_pid <= RESOURCE_VM_MAX_KIB)) || return 1
  for ((index = 0; index < ${#vm_names[@]}; index++)); do
    [[ "${lines[index + 2]}" =~ ^${vm_names[index]}:[[:space:]]+([0-9]+)[[:space:]]+kB$ ]] ||
      return 1
    value="${BASH_REMATCH[1]}"
    ((value <= RESOURCE_VM_MAX_KIB)) || return 1
    vm_values+=("$value")
  done
  [[ "${lines[9]}" =~ ^Threads:[[:space:]]+([0-9]+)$ ]] || return 1
  threads="${BASH_REMATCH[1]}"
  ((threads <= RESOURCE_THREADS_MAX)) || return 1
  [[ "${lines[10]}" =~ ^FDs:[[:space:]]+([0-9]+)$ ]] || return 1
  fds="${BASH_REMATCH[1]}"
  ((fds <= RESOURCE_FDS_MAX)) || return 1
  ((vm_values[2] <= RESOURCE_RSS_MAX_KIB)) || return 1
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$container_id" "$host_pid" "${vm_values[2]}" "$threads" "$fds"
}

read_running_obi_identity_record() {
  local -r phase="$1"
  local -r path="$ACCEPTANCE_SNAPSHOT/phases/$phase/obi-identity.json"

  [[ -f "$path" && ! -L "$path" ]] || return 1
  jq -er '
    select(
      .schema == "obi-process-identity-v1" and .state == "running" and
      (.container_id | type == "string" and test("^[0-9a-f]{64}$")) and
      (.host_pid | type == "string" and test("^[1-9][0-9]*$"))
    ) |
    [.container_id, .host_pid] | @tsv
  ' "$path"
}

write_resource_recovery_summary() {
  local -r rows="$WORK_DIRECTORY/resource-recovery-rows.tsv"
  local -a services=(
    obi apache-proxy java-backend coalesced-source trace-receiver
  )
  local -a phases=(keepalive-before pressure-after handoff-before)
  local service=""
  local phase=""
  local record=""
  local container_id=""
  local host_pid=""
  local rss=""
  local threads=""
  local fds=""
  local identity_record=""
  local identity_container_id=""
  local identity_host_pid=""
  local baseline_container_id=""
  local baseline_host_pid=""
  local -i baseline_rss=0
  local -i baseline_threads=0
  local -i baseline_fds=0
  local -a recovery_rss=()
  local -a recovery_threads=()
  local -a recovery_fds=()
  local -a baseline_container_ids=()
  local -a baseline_host_pids=()
  local -i rss_growth_cap=0
  local -i index=0
  local -i rss_delta_one=0
  local -i rss_delta_two=0
  local -i threads_delta_one=0
  local -i threads_delta_two=0
  local -i fds_delta_one=0
  local -i fds_delta_two=0
  local -i rss_spread=0
  local -i threads_spread=0
  local -i fds_spread=0

  : >"$rows" || return 1
  for service in "${services[@]}"; do
    case "$service" in
      obi|trace-receiver) rss_growth_cap=65536 ;;
      apache-proxy|coalesced-source) rss_growth_cap=32768 ;;
      java-backend) rss_growth_cap=131072 ;;
      *) return 1 ;;
    esac
    recovery_rss=()
    recovery_threads=()
    recovery_fds=()
    for ((index = 0; index < ${#phases[@]}; index++)); do
      phase="${phases[index]}"
      record="$(read_resource_record \
        "phases/$phase/$service-resources.txt")" || return 1
      IFS=$'\t' read -r container_id host_pid rss threads fds <<<"$record"
      if [[ "$service" == obi ]]; then
        identity_record="$(read_running_obi_identity_record "$phase")" || return 1
        IFS=$'\t' read -r identity_container_id identity_host_pid \
          <<<"$identity_record"
        [[ "$container_id" == "$identity_container_id" &&
          "$host_pid" == "$identity_host_pid" ]] || return 1
      fi
      if ((index == 0)); then
        baseline_container_id="$container_id"
        baseline_host_pid="$host_pid"
        baseline_container_ids+=("$container_id")
        baseline_host_pids+=("$host_pid")
        baseline_rss="$rss"
        baseline_threads="$threads"
        baseline_fds="$fds"
      else
        [[ "$container_id" == "$baseline_container_id" &&
          "$host_pid" == "$baseline_host_pid" ]] || return 1
        recovery_rss+=("$rss")
        recovery_threads+=("$threads")
        recovery_fds+=("$fds")
      fi
    done
    rss_delta_one=$((recovery_rss[0] - baseline_rss))
    rss_delta_two=$((recovery_rss[1] - baseline_rss))
    threads_delta_one=$((recovery_threads[0] - baseline_threads))
    threads_delta_two=$((recovery_threads[1] - baseline_threads))
    fds_delta_one=$((recovery_fds[0] - baseline_fds))
    fds_delta_two=$((recovery_fds[1] - baseline_fds))
    rss_spread=$((recovery_rss[0] - recovery_rss[1]))
    if ((rss_spread < 0)); then
      rss_spread=$((-rss_spread))
    fi
    threads_spread=$((recovery_threads[0] - recovery_threads[1]))
    if ((threads_spread < 0)); then
      threads_spread=$((-threads_spread))
    fi
    fds_spread=$((recovery_fds[0] - recovery_fds[1]))
    if ((fds_spread < 0)); then
      fds_spread=$((-fds_spread))
    fi
    ((rss_delta_one <= rss_growth_cap && rss_delta_two <= rss_growth_cap &&
      threads_delta_one <= 32 && threads_delta_two <= 32 &&
      fds_delta_one <= 8 && fds_delta_two <= 8 &&
      rss_spread <= 32768 && threads_spread <= 2 && fds_spread <= 2)) ||
      return 1
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$service" "$fds_delta_one" "$threads_delta_one" "$rss_delta_one" \
      "$fds_delta_two" "$threads_delta_two" "$rss_delta_two" \
      "$fds_spread" "$threads_spread" "$rss_spread" >>"$rows" || return 1
  done
  ((${#baseline_container_ids[@]} == 5 && ${#baseline_host_pids[@]} == 5)) ||
    return 1
  (($(printf '%s\n' "${baseline_container_ids[@]}" | LC_ALL=C sort -u |
    wc -l) == 5)) || return 1
  (($(printf '%s\n' "${baseline_host_pids[@]}" | LC_ALL=C sort -u |
    wc -l) == 5)) || return 1
  jq -cS -Rn '
    [inputs | split("\t") | {
      service: .[0],
      identity_continuous: true,
      within_absolute_policy: true,
      recovery: [
        {phase: "pressure-after", delta: {
          fds: (.[1] | tonumber), threads: (.[2] | tonumber),
          vm_rss_kib: (.[3] | tonumber)}, within_growth_policy: true},
        {phase: "handoff-before", delta: {
          fds: (.[4] | tonumber), threads: (.[5] | tonumber),
          vm_rss_kib: (.[6] | tonumber)}, within_growth_policy: true}
      ],
      spread: {fds: (.[7] | tonumber), threads: (.[8] | tonumber),
        vm_rss_kib: (.[9] | tonumber), within_policy: true}
    }] | {
      schema: "obi-container-leader-resource-recovery-projection-v1",
      status: "passed",
      scope: "container_leader_process",
      baseline_phase: "keepalive-before",
      recovery_phases: ["pressure-after", "handoff-before"],
      distinct_container_identity_count: 5,
      distinct_host_pid_count: 5,
      distinct_service_identities: true,
      service_order: [.[].service],
      policy: {
        absolute: {fds: 4096, threads: 2048, vm_rss_kib: 4194304},
        growth: {fds: 8, threads: 32, vm_rss_kib_by_service: {
          obi: 65536, "apache-proxy": 32768, "java-backend": 131072,
          "coalesced-source": 32768, "trace-receiver": 65536}},
        recovery_spread: {fds: 2, threads: 2, vm_rss_kib: 32768}
      },
      services: .
    }
  ' <"$rows" | write_file resource-recovery-summary.json
}

write_checksum_manifest() {
  local relative=""
  local path=""
  local digest=""
  local entries=""

  entries="$(mktemp "$WORK_DIRECTORY/checksum-entries.XXXXXX")" || return 1
  write_sorted_directory_entries "$CANDIDATE_DIRECTORY" true "$entries" ||
    return 1
  while IFS= read -r -d '' path; do
    relative="${path#"$CANDIDATE_DIRECTORY"/}"
    [[ "$relative" != SHA256SUMS ]] || continue
    digest="$(sha256sum <"$path")" || return 1
    digest="${digest%% *}"
    is_sha256 "$digest" || return 1
    printf '%s  ./%s\n' "$digest" "$relative"
  done <"$entries" | write_file SHA256SUMS || return 1
  rm -f -- "$entries"
}

validate_public_candidate_budget() {
  local path=""
  local size=""
  local entries=""
  local -i files=0
  local -i bytes=0

  entries="$(mktemp "$WORK_DIRECTORY/public-budget-entries.XXXXXX")" || return 1
  write_sorted_directory_entries "$CANDIDATE_DIRECTORY" true "$entries" ||
    return 1
  while IFS= read -r -d '' path; do
    [[ -f "$path" && ! -L "$path" && "$(stat -Lc '%h' -- "$path")" == 1 ]] ||
      return 1
    size="$(stat -Lc '%s' -- "$path")" || return 1
    [[ "$size" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    ((files < PUBLIC_MAX_FILES && bytes <= PUBLIC_MAX_BYTES - size)) || return 1
    files=$((files + 1))
    bytes=$((bytes + size))
  done <"$entries"
  rm -f -- "$entries" || return 1
  ((files > 0))
}

seal_public_candidate() {
  find -- "$CANDIDATE_DIRECTORY" -type f -exec chmod 0444 -- {} + || return 1
  find -- "$CANDIDATE_DIRECTORY" -depth -type d -exec chmod 0555 -- {} +
}

retain_invalid_publication() {
  local -r reason="$1"

  printf '%s: publication did not complete authoritatively (%s); output was retained at %s and must be treated as invalid/non-authoritative\n' \
    "$SCRIPT_NAME" "$reason" "$OUTPUT_DIRECTORY" >&2
  return 1
}

publish_verified_candidate() {
  local candidate_after=""
  local candidate_mode=""
  local output_after=""
  local output_mode=""
  local -i move_status=0

  [[ ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]] ||
    die "output appeared before atomic publication"
  candidate_after="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")" ||
    die "candidate disappeared before atomic publication"
  candidate_mode="$(stat -Lc '%a' -- "$CANDIDATE_DIRECTORY")" ||
    die "candidate mode could not be inspected before atomic publication"
  [[ "$candidate_after" == "$CANDIDATE_IDENTITY" &&
    "$candidate_mode" == 555 ]] ||
    die "sealed candidate identity or mode changed before atomic publication"

  chmod 0700 -- "$CANDIDATE_DIRECTORY" ||
    die "could not open the verified candidate root for atomic publication"
  candidate_after="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")" ||
    die "candidate disappeared after opening its publication root"
  candidate_mode="$(stat -Lc '%a' -- "$CANDIDATE_DIRECTORY")" ||
    die "candidate mode could not be inspected after opening its publication root"
  [[ "$candidate_after" == "$CANDIDATE_IDENTITY" &&
    "$candidate_mode" == 700 ]] ||
    die "candidate identity or mode changed before the publication move"

  if mv -Tn -- "$CANDIDATE_DIRECTORY" "$OUTPUT_DIRECTORY"; then
    move_status=0
  else
    move_status=$?
  fi

  if [[ -d "$CANDIDATE_DIRECTORY" && ! -L "$CANDIDATE_DIRECTORY" ]]; then
    candidate_after="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")" ||
      candidate_after=""
  else
    candidate_after=""
  fi
  if [[ -d "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]]; then
    output_after="$(stat -Lc '%d:%i:%u' -- "$OUTPUT_DIRECTORY")" ||
      output_after=""
    output_mode="$(stat -Lc '%a' -- "$OUTPUT_DIRECTORY")" || output_mode=""
  else
    output_after=""
    output_mode=""
  fi

  if ((move_status != 0)); then
    if [[ -z "$candidate_after" && "$output_after" == "$CANDIDATE_IDENTITY" ]]; then
      if [[ "$output_mode" == 700 ]] &&
        chmod 0555 -- "$OUTPUT_DIRECTORY"; then
        output_after="$(stat -Lc '%d:%i:%u' -- "$OUTPUT_DIRECTORY")" ||
          output_after=""
        output_mode="$(stat -Lc '%a' -- "$OUTPUT_DIRECTORY")" || output_mode=""
      else
        retain_invalid_publication \
          "move returned status $move_status after a side effect and resealing failed"
        return 1
      fi
      if [[ "$output_after" != "$CANDIDATE_IDENTITY" ||
        "$output_mode" != 555 ]]; then
        retain_invalid_publication \
          "move returned status $move_status after a side effect and the resealed identity changed"
        return 1
      fi
      retain_invalid_publication \
        "move returned status $move_status after transferring the candidate"
      return 1
    fi
    if [[ "$candidate_after" == "$CANDIDATE_IDENTITY" &&
      ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]]; then
      die "atomic publication failed before transferring the candidate (status $move_status)"
    fi
    if [[ -e "$OUTPUT_DIRECTORY" || -L "$OUTPUT_DIRECTORY" ]]; then
      retain_invalid_publication \
        "move returned status $move_status with an ambiguous output side effect"
      return 1
    fi
    die "atomic publication failed with ambiguous candidate state (status $move_status)"
  fi

  if [[ -n "$candidate_after" || "$output_after" != "$CANDIDATE_IDENTITY" ||
    "$output_mode" != 700 ]]; then
    if [[ -e "$OUTPUT_DIRECTORY" || -L "$OUTPUT_DIRECTORY" ]]; then
      retain_invalid_publication \
        "the no-clobber move did not transfer the pinned candidate exactly"
      return 1
    fi
    die "the no-clobber move did not transfer the pinned candidate"
  fi
  if ! chmod 0555 -- "$OUTPUT_DIRECTORY"; then
    retain_invalid_publication "the moved candidate root could not be resealed"
    return 1
  fi
  output_after="$(stat -Lc '%d:%i:%u' -- "$OUTPUT_DIRECTORY")" || {
    retain_invalid_publication "the resealed output could not be inspected"
    return 1
  }
  output_mode="$(stat -Lc '%a' -- "$OUTPUT_DIRECTORY")" || {
    retain_invalid_publication "the resealed output mode could not be inspected"
    return 1
  }
  if [[ "$output_after" != "$CANDIDATE_IDENTITY" || "$output_mode" != 555 ]]; then
    retain_invalid_publication "the moved candidate identity or sealed mode changed"
    return 1
  fi
  if ! "$VERIFIER" --claims-v1 "$OUTPUT_DIRECTORY" >/dev/null; then
    retain_invalid_publication "post-move claims-v1 verification failed"
    return 1
  fi
  if ! (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null); then
    retain_invalid_publication "post-move portable verification failed"
    return 1
  fi
}

write_expected_claim_boundary_roster() {
  local -r output="$1"

  printf '%s\t%s\t%s\t%s\n' \
    1 basic complete '' \
    2 delayed-otlp-suppression complete '' \
    3 security complete '' \
    4 keepalive complete '' \
    5 pipelining complete '' \
    6 concurrency complete '' \
    7 connection-churn complete '' \
    8 fd-port-reuse complete '' \
    9 slow-body complete '' \
    10 tls-boundary complete '' \
    11 coalesced-bridge complete '' \
    12 timeout-retry complete '' \
    13 pressure complete '' \
    14 handoff complete '' \
    15 virtual-thread complete '' \
    16 netty complete '' \
    17 netty-server complete '' \
    18 dispatch complete '' \
    19 w3c complete '' \
    20 w3c-match complete '' \
    21 obi-flags complete '' \
    22 primary-w3c-stale complete '' \
    23 primary-generation-mismatch complete '' \
    24 primary-w3c-fault complete '' \
    25 unix-w3c-stale not_applicable 'requires forced Unix transport' \
    26 unix-generation-mismatch not_applicable \
    'requires forced Unix transport' \
    27 w3c-fault not_applicable 'requires forced Unix transport' \
    28 permanent-absence complete '' \
    29 auto-unavailable not_applicable \
    'requires auto transport selection' \
    30 late-attach complete '' \
    31 restart-during-traffic complete '' \
    32 helper-attach-failure complete '' \
    33 disabled complete '' \
    34 extension-controls complete '' \
    35 uninstrumented complete '' \
    >"$output"
}

write_expected_claim_status_owners() {
  local -r output="$1"

  cat >"$output" <<'STATUS_OWNERS'
auto-unavailable	scenario-auto-unavailable-status.json
basic	scenario-basic-status.json
coalesced-bridge	scenario-coalesced-bridge-status.json
concurrency	scenario-concurrency-status.json
connection-churn	scenario-connection-churn-status.json
delayed-otlp-suppression	scenario-basic-delayed-otlp-suppression-status.json
disabled	scenario-disabled-status.json
dispatch	scenario-dispatch-status.json
extension-controls	scenario-w3c-only-extension-absent-status.json
extension-controls	scenario-w3c-only-extension-disabled-status.json
fd-port-reuse	scenario-fd-port-reuse-status.json
handoff	scenario-handoff-status.json
helper-attach-failure	scenario-basic-helper-attach-recovery-status.json
helper-attach-failure	scenario-disabled-helper-attach-bridge-disabled-status.json
helper-attach-failure	scenario-helper-attach-failure-helper-unavailable-status.json
helper-attach-failure	scenario-w3c-helper-unavailable-status.json
keepalive	scenario-keepalive-status.json
late-attach	scenario-fail-open-obi-absent-status.json
late-attach	scenario-restart-late-attach-recovery-status.json
late-attach	scenario-w3c-only-obi-absent-status.json
netty	scenario-netty-status.json
netty-server	scenario-netty-server-status.json
obi-flags	scenario-obi-flags-status.json
permanent-absence	scenario-basic-permanent-absence-recovery-status.json
permanent-absence	scenario-disabled-permanent-absence-baseline-status.json
permanent-absence	scenario-fail-open-permanent-absence-status.json
permanent-absence	scenario-permanent-absence-status.json
permanent-absence	scenario-w3c-only-permanent-absence-status.json
pipelining	scenario-pipelining-status.json
pressure	scenario-pressure-status.json
primary-generation-mismatch	scenario-basic-primary-generation-mismatch-recovery-status.json
primary-generation-mismatch	scenario-primary-generation-mismatch-status.json
primary-w3c-fault	scenario-basic-primary-w3c-fault-recovery-status.json
primary-w3c-fault	scenario-primary-w3c-fault-bad-size-status.json
primary-w3c-fault	scenario-primary-w3c-fault-version-mismatch-status.json
primary-w3c-fault	scenario-primary-w3c-fault-zero-span-id-status.json
primary-w3c-fault	scenario-primary-w3c-fault-zero-trace-id-status.json
primary-w3c-stale	scenario-basic-primary-w3c-stale-recovery-status.json
primary-w3c-stale	scenario-primary-w3c-stale-status.json
restart-during-traffic	scenario-restart-fault-status.json
restart-during-traffic	scenario-restart-restart-recovery-status.json
security	scenario-basic-security-primary-live-fd-recovery-status.json
security	scenario-basic-security-primary-recovery-status.json
security	scenario-concurrency-security-primary-victim-status.json
security	scenario-primary-live-fd-security-status.json
security	scenario-security-status.json
slow-body	scenario-slow-body-status.json
timeout-retry	scenario-timeout-retry-status.json
tls-boundary	scenario-tls-boundary-status.json
uninstrumented	scenario-uninstrumented-status.json
unix-generation-mismatch	scenario-unix-generation-mismatch-status.json
unix-w3c-stale	scenario-unix-w3c-stale-status.json
virtual-thread	scenario-virtual-thread-status.json
w3c	scenario-w3c-status.json
w3c-fault	scenario-w3c-fault-status.json
w3c-match	scenario-w3c-match-status.json
STATUS_OWNERS
}

validate_private_claim_roster() {
  local -r index="$ACCEPTANCE_SNAPSHOT/obi-metric-boundary-index.json"
  local -r expected_boundaries="$WORK_DIRECTORY/claim-boundaries.expected"
  local -r actual_boundaries="$WORK_DIRECTORY/claim-boundaries.actual"
  local -r expected_owners="$WORK_DIRECTORY/claim-status-owners.expected"
  local -r actual_owners="$WORK_DIRECTORY/claim-status-owners.actual"
  local owner=""
  local reference=""
  local state=""
  local reason=""

  write_expected_claim_boundary_roster "$expected_boundaries" || return 1
  write_expected_claim_status_owners "$expected_owners" || return 1
  [[ "$(awk 'END { print NR + 0 }' "$expected_boundaries")" == 35 &&
    "$(awk 'END { print NR + 0 }' "$expected_owners")" == 56 ]] || return 1
  LC_ALL=C sort -c -- "$expected_owners" || return 1

  jq -r '
    .boundaries[] |
    [.ordinal, .id, .state, (.not_applicable_reason // "")] | @tsv
  ' "$index" >"$actual_boundaries" || return 1
  cmp -s -- "$expected_boundaries" "$actual_boundaries" || return 1
  jq -r '
    .boundaries[] as $boundary |
    $boundary.status_references[] |
    [$boundary.id, .reference] | @tsv
  ' "$index" | LC_ALL=C sort >"$actual_owners" || return 1
  cmp -s -- "$expected_owners" "$actual_owners" || return 1
  [[ "$(cut -f2 -- "$actual_owners" | LC_ALL=C sort -u |
    awk 'END { print NR + 0 }')" == 56 ]] || return 1

  while IFS=$'\t' read -r owner reference; do
    [[ -n "$owner" && -n "$reference" ]] || return 1
    state="$(awk -F '\t' -v wanted="$owner" '$2 == wanted { print $3 }' \
      "$expected_boundaries")" || return 1
    reason="$(awk -F '\t' -v wanted="$owner" '$2 == wanted { print $4 }' \
      "$expected_boundaries")" || return 1
    [[ -n "$state" && -f "$ACCEPTANCE_SNAPSHOT/$reference" &&
      ! -L "$ACCEPTANCE_SNAPSHOT/$reference" ]] || return 1
    if [[ "$state" == not_applicable ]]; then
      jq -e --arg owner "$owner" --arg reason "$reason" '
        .status == "not_applicable" and .scenario == $owner and
        .reason == $reason and .obi_metric_boundary_ids == [$owner]
      ' "$ACCEPTANCE_SNAPSHOT/$reference" >/dev/null || return 1
    else
      jq -e --arg owner "$owner" '
        .status == "passed" and .obi_metric_boundary_ids == [$owner] and
        (if has("exit_status") then .exit_status == 0 else true end)
      ' "$ACCEPTANCE_SNAPSHOT/$reference" >/dev/null || return 1
    fi
  done <"$expected_owners"
}

validate_private_stress_pair_authority() {
  local -r index="$ACCEPTANCE_SNAPSHOT/obi-metric-boundary-index.json"
  local -a scenarios=(
    keepalive pipelining concurrency connection-churn fd-port-reuse slow-body
    tls-boundary coalesced-bridge timeout-retry pressure handoff
  )
  local scenario=""
  local pair_reference=""
  local before_identity_reference=""
  local after_identity_reference=""
  local before_java_reference=""
  local after_java_reference=""
  local status_reference=""
  local pair_sha256=""
  local java_sha256=""
  local status_sha256=""
  local before_snapshot=""
  local after_snapshot=""

  for scenario in "${scenarios[@]}"; do
    pair_reference="obi-metric-pairs/$scenario.json"
    before_identity_reference="phases/$scenario-before/obi-identity.json"
    after_identity_reference="phases/$scenario-after/obi-identity.json"
    before_java_reference="phases/$scenario-before/java-diagnostics.txt"
    after_java_reference="phases/$scenario-after/java-diagnostics.txt"
    status_reference="scenario-$scenario-status.json"
    [[ -f "$ACCEPTANCE_SNAPSHOT/$pair_reference" &&
      ! -L "$ACCEPTANCE_SNAPSHOT/$pair_reference" &&
      -f "$ACCEPTANCE_SNAPSHOT/$before_java_reference" &&
      ! -L "$ACCEPTANCE_SNAPSHOT/$before_java_reference" &&
      -f "$ACCEPTANCE_SNAPSHOT/$after_java_reference" &&
      ! -L "$ACCEPTANCE_SNAPSHOT/$after_java_reference" &&
      -f "$ACCEPTANCE_SNAPSHOT/$status_reference" &&
      ! -L "$ACCEPTANCE_SNAPSHOT/$status_reference" ]] || return 1
    IFS= read -r before_snapshot \
      <"$ACCEPTANCE_SNAPSHOT/$before_java_reference" || return 1
    IFS= read -r after_snapshot \
      <"$ACCEPTANCE_SNAPSHOT/$after_java_reference" || return 1
    pair_sha256="$(sha256sum <"$ACCEPTANCE_SNAPSHOT/$pair_reference")" ||
      return 1
    pair_sha256="${pair_sha256%% *}"
    java_sha256="$(sha256sum \
      <"$ACCEPTANCE_SNAPSHOT/$after_java_reference")" || return 1
    java_sha256="${java_sha256%% *}"
    status_sha256="$(sha256sum \
      <"$ACCEPTANCE_SNAPSHOT/$status_reference")" || return 1
    status_sha256="${status_sha256%% *}"

    jq -e --arg scenario "$scenario" \
      --arg pair_reference "$pair_reference" \
      --arg pair_sha256 "$pair_sha256" \
      --arg java_reference "$after_java_reference" \
      --arg java_sha256 "$java_sha256" \
      --arg status_reference "$status_reference" \
      --arg status_sha256 "$status_sha256" '
        . as $root |
        ([$root.boundaries[] | select(.id == $scenario)]) as $boundaries |
        ($boundaries | length) == 1 and
        ($boundaries[0] | .state == "complete" and
          .not_applicable_reason == null and
          ([.captures[] | select(.kind == "pair")] | length) == 1 and
          ([.captures[] | select(.kind == "pair")][0] |
            .id == $scenario and .state == "captured" and
            .pair_reference == $pair_reference and
            .pair_sha256 == $pair_sha256 and
            .java_reference == $java_reference and
            .java_sha256 == $java_sha256) and
          .status_references == [{
            reference: $status_reference,
            sha256: $status_sha256
          }])
      ' "$index" >/dev/null || return 1
    jq -e --arg scenario "$scenario" \
      --arg before_identity_reference "$before_identity_reference" \
      --arg after_identity_reference "$after_identity_reference" '
        .boundary == $scenario and .continuity == "same_process" and
        .before == {state:"running",
          identity_reference:$before_identity_reference} and
        .after == {state:"running",
          identity_reference:$after_identity_reference}
      ' "$ACCEPTANCE_SNAPSHOT/$pair_reference" >/dev/null || return 1
    jq -e --arg scenario "$scenario" \
      --arg pair_reference "$pair_reference" \
      --arg before_java_reference "$before_java_reference" \
      --arg after_java_reference "$after_java_reference" \
      --arg before_snapshot "$before_snapshot" \
      --arg after_snapshot "$after_snapshot" \
      --slurpfile pair "$ACCEPTANCE_SNAPSHOT/$pair_reference" '
        def java_evidence($reference; $snapshot): {
          reference: $reference,
          snapshot: $snapshot,
          counters: ($snapshot | split(",") |
            map(split("=") | {(.[0]): .[1]}) | add)
        };
        .status == "passed" and .scenario == $scenario and
        .exit_status == 0 and .metric_status == 0 and
        .result == ("scenario-" + $scenario + ".json") and
        .obi_metric_boundary_ids == [$scenario] and
        .before_phase == ("phases/" + $scenario + "-before") and
        .after_phase == ("phases/" + $scenario + "-after") and
        .obi_metric_evidence == {
          reference: $pair_reference,
          pair: $pair[0]
        } and
        .java_diagnostics == {
          before: java_evidence($before_java_reference; $before_snapshot),
          after: java_evidence($after_java_reference; $after_snapshot)
        }
      ' "$ACCEPTANCE_SNAPSHOT/$status_reference" >/dev/null || return 1
  done
}

validate_private_claim_inputs() {
  local -r index="$ACCEPTANCE_SNAPSHOT/obi-metric-boundary-index.json"
  local -r expected_commands='["clone","checkout-exact-revision","clean-status-before","certificate-generation","run-test","tracecheck-tests","compose-config","clean-status-after-validation","acceptance-all-otel-getsockopt-tls13","assertion-failure-exit-2","scoped-cleanup","clean-status-final"]'
  local -r empty_sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  local -a scenarios=(
    keepalive pipelining concurrency connection-churn fd-port-reuse slow-body
    tls-boundary coalesced-bridge timeout-retry pressure handoff
  )
  local scenario=""
  local reference=""
  local canonical_runbook=""

  canonical_runbook="$(mktemp "$WORK_DIRECTORY/runbook-canonical.XXXXXX")" ||
    return 1
  jq -cS -e -s '
    if length == 1 and (.[0] | type == "object") then .[0]
    else error("one canonical runbook object required") end
  ' "$RUNBOOK_SNAPSHOT" >"$canonical_runbook" || return 1
  cmp -s -- "$RUNBOOK_SNAPSHOT" "$canonical_runbook" || return 1
  rm -f -- "$canonical_runbook" || return 1

  jq -e --argjson commands "$expected_commands" \
    --arg empty_sha256 "$empty_sha256" \
    --arg head_sha "$(key_value \
      "$ACCEPTANCE_SNAPSHOT/environment.txt" revision)" \
    --arg source_tree "$(key_value \
      "$ACCEPTANCE_SNAPSHOT/environment.txt" source_tree_sha256)" \
    --arg architecture "$(key_value \
      "$ACCEPTANCE_SNAPSHOT/environment.txt" architecture)" '
    keys == ["commands", "environment", "execution_locator", "output_contract",
      "schema", "source_revision", "source_tree_sha256"] and
    .schema == "obi-apache-java-https-runbook-receipt-v1" and
    .source_revision == $ARGS.named.head_sha and
    .source_tree_sha256 == $ARGS.named.source_tree and
    (.environment |
      keys == ["architecture", "compose_version", "docker_version",
        "go_version", "java_version", "operating_system"] and
      .architecture == $ARGS.named.architecture and
      .operating_system == "Linux" and
      all([.compose_version, .docker_version, .go_version, .java_version][];
        type == "string" and length >= 1 and length <= 64 and
        test("^[A-Za-z0-9][A-Za-z0-9._+~-]*$"))) and
    .output_contract == {algorithm:"sha256",
      bytes:"exact-command-order-no-normalization",
      stream:"combined-stdout-stderr"} and
    (.execution_locator |
      keys == ["event", "head_sha", "kind", "repository", "run_attempt",
        "run_id", "run_url", "workflow_blob_sha256", "workflow_path",
        "workflow_ref", "workflow_sha"] and
      .kind == "github-actions" and
      .event == "push" and
      .repository == "MrAlias/opentelemetry-ebpf-instrumentation" and
      .workflow_path ==
        ".github/workflows/java_remote_parent_acceptance_claims.yml" and
      (.run_id | type == "string" and test("^[1-9][0-9]{0,18}$")) and
      (.run_attempt | type == "string" and test("^[1-9][0-9]{0,18}$")) and
      (.head_sha | type == "string" and . == $ARGS.named.head_sha) and
      .workflow_sha == .head_sha and
      (.workflow_blob_sha256 | type == "string" and
        test("^[0-9a-f]{64}$")) and
      .workflow_ref == (.repository + "/" + .workflow_path +
        "@refs/heads/agent/java-remote-parent-bridge") and
      .run_url == ("https://github.com/" + .repository + "/actions/runs/" +
        .run_id + "/attempts/" + .run_attempt)) and
    [.commands[].id] == $commands and
    all(.commands[];
      keys == ["duration_seconds", "exit_status", "id", "output_sha256",
        "status"] and
      (.duration_seconds | type == "number" and floor == . and
        . >= 0 and . <= 86400) and
      (.output_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (if .id == "clean-status-before" or
          .id == "clean-status-after-validation" or
          .id == "clean-status-final"
       then .output_sha256 == $empty_sha256 else true end) and
      (if .id == "assertion-failure-exit-2" then
        .status == "expected_failure" and .exit_status == 2
      else .status == "passed" and .exit_status == 0 end)) and
    ([.commands[] | select(.id == "scoped-cleanup" or
      .id == "clean-status-final") | .status] == ["passed", "passed"])
  ' "$RUNBOOK_SNAPSHOT" >/dev/null || return 1

  validate_private_claim_roster || return 1
  validate_private_stress_pair_authority || return 1

  jq -e --argjson scenarios "$(printf '%s\n' "${scenarios[@]}" |
    jq -Rsc 'split("\n") | map(select(length > 0))')" '
    . as $root |
    $root.selection == {repeat_count: 1, requested_transport: "getsockopt",
      scenario: "all", selected_transport: "getsockopt"} and
    all($scenarios[]; . as $scenario |
      ([$root.boundaries[] | select(.id == $scenario)]) as $boundaries |
      ($boundaries | length) == 1 and
      ($boundaries[0] | .state == "complete" and
        .not_applicable_reason == null and
        ([.captures[] | select(.kind == "pair" and .state == "captured")] |
          length) == 1 and
        ([.captures[] | select(.kind == "pair")][0] |
          (.java_reference | type == "string") and
          (.java_sha256 | type == "string" and test("^[0-9a-f]{64}$"))) and
        .status_references == [{
          reference: ("scenario-" + $scenario + "-status.json"),
          sha256: .status_references[0].sha256
        }])) and
    ([.boundaries[].status_references[].reference] as $references |
      ($references | length) == ($references | unique | length))
  ' "$index" >/dev/null || return 1

  for scenario in "${scenarios[@]}"; do
    reference="scenario-$scenario-status.json"
    jq -e --arg scenario "$scenario" '
      .status == "passed" and .scenario == $scenario and .exit_status == 0 and
      .result == ("scenario-" + $scenario + ".json") and
      .obi_metric_boundary_ids == [$scenario]
    ' "$ACCEPTANCE_SNAPSHOT/$reference" >/dev/null || return 1
  done
}

write_claim_authority_summary() {
  local revision=""
  local tree=""
  local architecture=""
  local acceptance_stat=""
  local assertion_stat=""
  local runbook_sha256=""

  revision="$(key_value "$ACCEPTANCE_SNAPSHOT/environment.txt" revision)" ||
    return 1
  tree="$(key_value \
    "$ACCEPTANCE_SNAPSHOT/environment.txt" source_tree_sha256)" || return 1
  architecture="$(key_value \
    "$ACCEPTANCE_SNAPSHOT/environment.txt" architecture)" || return 1
  acceptance_stat="$ACCEPTANCE_PRIVATE_STAT"
  assertion_stat="$ASSERTION_PRIVATE_STAT"
  runbook_sha256="$RUNBOOK_PRIVATE_SHA256"
  [[ -n "$acceptance_stat" && -n "$assertion_stat" ]] || return 1
  is_sha256 "$runbook_sha256" || return 1
  jq -cS -n --arg revision "$revision" --arg tree "$tree" \
    --arg architecture "$architecture" --arg runbook_sha256 "$runbook_sha256" \
    --argjson acceptance "$acceptance_stat" --argjson assertion "$assertion_stat" \
    --slurpfile agent "$ACCEPTANCE_SNAPSHOT/official-javaagent.json" \
    --slurpfile runbook "$RUNBOOK_SNAPSHOT" '{
      schema: "obi-bounded-claim-authority-v1",
      source: {
        revision: $revision,
        tree_sha256: $tree,
        clean: true,
        architecture: $architecture
      },
      official_agent: {
        distribution: $agent[0].distribution,
        version: $agent[0].version,
        sha256: $agent[0].sha256
      },
      fixed_run_profile: {
        acceptance_scenario: "all",
        assertion_scenario: "assertion-failure",
        repeat_count: 1,
        request_count_override: 0,
        seed: 1,
        transport: "getsockopt",
        agent_distribution: "otel",
        tls_protocol: "TLSv1.3",
        keep_requested: false
      },
      execution_locator: $runbook[0].execution_locator,
      private_commitment_profile: {
        schema: "obi-private-file-manifest-commitment-v1",
        algorithm: "sha256",
        preimage: "obi-private-file-manifest-commitment-v1\\n<role>\\n<content-sha256>  ./<safe-relative-path>\\n",
        ordering: "LC_ALL=C relative-path byte order",
        entries: "regular-files-only",
        directory_rule: "empty-directories-rejected",
        modes_included: false,
        role_bound: true,
        terminal_lf: true
      },
      private_input_roots: {
        acceptance: {schema: $acceptance.commitment_schema,
          role: $acceptance.role, file_count: $acceptance.file_count,
          total_bytes: $acceptance.total_bytes,
          sha256: $acceptance.manifest_sha256,
          run_status_sha256: $acceptance.run_status_sha256},
        assertion: {schema: $assertion.commitment_schema,
          role: $assertion.role, file_count: $assertion.file_count,
          total_bytes: $assertion.total_bytes,
          sha256: $assertion.manifest_sha256,
          run_status_sha256: $assertion.run_status_sha256},
        runbook: {role: "runbook-receipt", sha256: $runbook_sha256}
      }
    }' | write_file authority-summary.json
}

write_acceptance_claim_summary() {
  local roster="$WORK_DIRECTORY/producer-status-roster.preimage"
  local boundary_roster="$WORK_DIRECTORY/claim-boundaries.expected"
  local status_rows="$WORK_DIRECTORY/producer-status-roster.rows"
  local roster_sha256=""
  local pressure_exact=""
  local pressure_roots=""
  local timeout_outcome=""
  local timeout_reason=""

  [[ -f "$boundary_roster" && ! -L "$boundary_roster" ]] || return 1
  jq -r '
    .boundaries[] as $boundary |
    $boundary.status_references[] |
    [$boundary.id, .reference, .sha256] | @tsv
  ' "$ACCEPTANCE_SNAPSHOT/obi-metric-boundary-index.json" |
    LC_ALL=C sort >"$status_rows" || return 1
  [[ "$(awk 'END { print NR + 0 }' "$status_rows")" == 56 ]] || return 1
  {
    printf '%s\n' 'obi-producer-status-roster-commitment-v1'
    cat -- "$boundary_roster"
    printf '%s\n' '--status-references--'
    cat -- "$status_rows"
  } >"$roster" || return 1
  roster_sha256="$(sha256sum <"$roster")" || return 1
  roster_sha256="${roster_sha256%% *}"
  pressure_exact="$(jq -er '.pressure_correlation.exact_hit_count' \
    "$ACCEPTANCE_SNAPSHOT/scenario-pressure.json")" || return 1
  pressure_roots="$(jq -er '.pressure_correlation.explicit_root_count' \
    "$ACCEPTANCE_SNAPSHOT/scenario-pressure.json")" || return 1
  timeout_outcome="$(jq -er '.faults[0].parent_outcome' \
    "$ACCEPTANCE_SNAPSHOT/scenario-timeout-retry.json")" || return 1
  timeout_reason="$(jq -ce \
    '.faults[0].drop_reasons | if length == 1 then .[0] else null end' \
    "$ACCEPTANCE_SNAPSHOT/scenario-timeout-retry.json")" || return 1

  write_resource_recovery_summary || return 1
  jq -cS -n --arg roster_sha256 "$roster_sha256" \
    --argjson pressure_exact "$pressure_exact" \
    --argjson pressure_roots "$pressure_roots" \
    --arg timeout_outcome "$timeout_outcome" \
    --argjson timeout_reason "$timeout_reason" \
    --slurpfile resources \
      "$CANDIDATE_DIRECTORY/resource-recovery-summary.json" '
    def scenario($name; $count; $exact; $roots; $topology): {
      name: $name,
      request_count: $count,
      duration_cap_nanos: 75000000000,
      bounded_duration_verified: true,
      zero_wrong_parent: true,
      zero_unresolved_parent: true,
      exact_parent_count: $exact,
      explicit_local_root_count: $roots,
      required_metric_pair_and_java_capture_verified: true,
      topology_contract: $topology
    };
    def timeout_scenario($outcome; $reason): {
      name: "timeout-retry",
      request_count: 1,
      duration_cap_nanos: 75000000000,
      bounded_duration_verified: true,
      zero_wrong_parent: true,
      zero_unresolved_parent: true,
      required_metric_pair_and_java_capture_verified: true,
      topology_contract: "reason-coded-timeout-reconciliation",
      reconciliation: {outcome: $outcome, reason: $reason}
    };
    {
      schema: "obi-bounded-acceptance-claims-v1",
      status: "passed",
      issue_32: {
        clean_source_before_and_after: true,
        no_keep_invocation: true,
        scoped_cleanup_passed: true,
        final_clean_status_passed: true,
        acceptance_run: {status: "passed", exit_status: 0,
          acceptance_evidence: true},
        assertion_control: {status: "failed", exit_status: 2,
          failure_stage: "deliberate-assertion-failure",
          reason: "deliberate-assertion-failure,targeted-scenario"},
        basic_control: {status: "passed", request_count: 1,
          zero_wrong_parent: true},
        producer_status_roster: {
          boundary_count: 35,
          boundary_order: [
            "basic", "delayed-otlp-suppression", "security", "keepalive",
            "pipelining", "concurrency", "connection-churn", "fd-port-reuse",
            "slow-body", "tls-boundary", "coalesced-bridge", "timeout-retry",
            "pressure", "handoff", "virtual-thread", "netty", "netty-server",
            "dispatch", "w3c", "w3c-match", "obi-flags", "primary-w3c-stale",
            "primary-generation-mismatch", "primary-w3c-fault", "unix-w3c-stale",
            "unix-generation-mismatch", "w3c-fault", "permanent-absence",
            "auto-unavailable", "late-attach", "restart-during-traffic",
            "helper-attach-failure", "disabled", "extension-controls",
            "uninstrumented"
          ],
          commitment: {
            algorithm: "sha256",
            preimage: "obi-producer-status-roster-commitment-v1",
            sha256: $roster_sha256
          },
          exact_once: true,
          not_applicable: [
            {id:"unix-w3c-stale", reason:"requires forced Unix transport"},
            {id:"unix-generation-mismatch", reason:"requires forced Unix transport"},
            {id:"w3c-fault", reason:"requires forced Unix transport"},
            {id:"auto-unavailable", reason:"requires auto transport selection"}
          ],
          schema: "obi-producer-status-roster-commitment-v1",
          status_entry_count: 56
        }
      },
      issue_34: {
        marker_role: "verification-only",
        marker_authority: "exact-source-and-test-identity",
        trace_selection_order_independent: true,
        tracecheck_tests_passed: true,
        recorded_seed: 1,
        request_count_override: 0,
        duration_cap_nanos: 75000000000,
        zero_wrong_parent: true,
        reason_coded_misses_and_drops: true,
        scenario_order: [
          "keepalive", "pipelining", "concurrency",
          "connection-churn", "fd-port-reuse", "slow-body", "tls-boundary",
          "coalesced-bridge", "timeout-retry", "pressure", "handoff"
        ],
        scenarios: [
          scenario("keepalive"; 10; 10; 0; "single-backend-connection"),
          scenario("pipelining"; 10; 10; 0; "preterminal-backend-reuse"),
          scenario("concurrency"; 16; 16; 0; "barrier-and-worker-concurrency"),
          scenario("connection-churn"; 32; 32; 0; "multiple-backend-connections"),
          scenario("fd-port-reuse"; 32; 32; 0; "frontend-port-and-fd-reuse"),
          scenario("slow-body"; 8; 8; 0; "split-tls-read-deltas"),
          scenario("tls-boundary"; 3; 3; 0; "current-tls-boundary-evidence"),
          scenario("coalesced-bridge"; 2; 0; 2; "explicit-local-java-roots"),
          timeout_scenario($timeout_outcome; $timeout_reason),
          scenario("pressure"; 128; $pressure_exact; $pressure_roots;
            "pressure-exact-or-explicit-root"),
          scenario("handoff"; 4; 4; 0; "parallel-handoff-chain")
        ],
        map_safety: {
          map_type: "non-evicting HASH",
          capacity: 10000,
          capacity_rejection_observed: true,
          post_rejection_correctness_verified: true,
          steady_baseline_recovered: true,
          old_lru_eviction_wording_superseded: true,
          lru_eviction_exercised: false
        },
        container_leader_resource_recovery: {
          scope: $resources[0].scope,
          distinct_container_identity_count:
            $resources[0].distinct_container_identity_count,
          distinct_host_pid_count: $resources[0].distinct_host_pid_count,
          distinct_service_identities: $resources[0].distinct_service_identities,
          policy: $resources[0].policy,
          services: $resources[0].services
        }
      }
    }
  ' | write_file acceptance-claims.json || return 1
  rm -f -- "$CANDIDATE_DIRECTORY/resource-recovery-summary.json"
}

write_derivation_receipt() {
  local authority_sha256=""
  local claims_sha256=""
  local evidence_id=""

  authority_sha256="$(sha256sum \
    <"$CANDIDATE_DIRECTORY/authority-summary.json")" || return 1
  authority_sha256="${authority_sha256%% *}"
  claims_sha256="$(sha256sum \
    <"$CANDIDATE_DIRECTORY/acceptance-claims.json")" || return 1
  claims_sha256="${claims_sha256%% *}"
  evidence_id="$(printf '%s\n' 'obi-bounded-claims-evidence-v1' \
    "$OUTPUT_NAME" "$authority_sha256" "$claims_sha256" | sha256sum)" ||
    return 1
  evidence_id="${evidence_id%% *}"
  jq -cS -n --arg authority_sha256 "$authority_sha256" \
    --arg claims_sha256 "$claims_sha256" --arg evidence_id "$evidence_id" \
    --arg bundle_name "$OUTPUT_NAME" '{
      schema: "obi-bounded-claim-derivation-v1",
      derivation_contract: "private-raw-v3-to-bounded-claims-v1",
      bundle_name: $bundle_name,
      evidence_id: $evidence_id,
      authority: {reference: "authority-summary.json", sha256: $authority_sha256},
      claims: {reference: "acceptance-claims.json", sha256: $claims_sha256},
      private_validation_profile: {
        exact_complete_producer_roster_validated: true,
        fixed_invocations_without_keep_validated: true,
        raw_snapshots_same_device_and_capped: true,
        required_eleven_stress_pair_ownership_validated: true,
        raw_semantics_validated_before_projection: true,
        raw_semantics_recomputable_from_public_bundle: false
      },
      public_file_order: [
        "README.md", "SANITIZATION.md", "acceptance-claims.json",
        "authority-summary.json", "derivation-receipt.json", "verify.sh",
        "SHA256SUMS"
      ]
    }' | write_file derivation-receipt.json
}

write_claim_summary_notes() {
  {
    printf '# Bounded retained acceptance claims\n\n'
    printf 'This is a bounded claim summary derived from privately verified raw-v3 runs.\n'
    printf 'Run `cd /path/to/bundle && bash verify.sh` (or `bash /path/to/bundle/verify.sh`) to verify canonical bytes, closure, hashes, modes, and cross-file relations.\n'
    printf 'The bundled verifier and SHA256SUMS prove internal consistency only; they are not signatures or independent authenticity evidence. Compare both the evidence ID and the verifier SHA-256 digest with an externally trusted record.\n'
    printf 'The public bundle intentionally cannot recompute raw trace, metric, journal, process, or resource semantics after private raw evidence expires.\n'
    printf 'Issue #34 map safety uses non-evicting HASH capacity rejection and recovery; it supersedes the issue body\x27s old LRU-eviction wording and does not claim that LRU eviction was exercised.\n'
  } | write_file README.md || return 1
  {
    printf '# Sanitization contract\n\n'
    printf 'Only canonical allowlisted claim, authority, derivation, and verification fields are public.\n'
    printf 'No raw paths, logs, traces, spans, metrics, markers, connection data, process identities, timestamps, absolute resource values, credentials, payloads, or runbook output are retained.\n'
    printf 'Private trees use obi-private-file-manifest-commitment-v1: SHA-256 over the domain line, role line, then LC_ALL=C path-ordered `<content-sha256>  ./<safe-relative-path>` lines with terminal LF; regular files are included, modes are excluded, and empty directories are rejected.\n'
    printf 'The runbook is represented by a SHA-256 commitment plus a closed GitHub Actions execution locator; no runbook output is copied.\n'
  } | write_file SANITIZATION.md
}

write_portable_claim_verifier() {
  write_file verify.sh <<'CLAIM_VERIFY_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
LC_ALL=C
export LC_ALL
verification_tmp_parent="/tmp"
readonly verification_tmp_parent

fail() {
  printf 'verify.sh: %s\n' "$*" >&2
  exit 1
}

verification_tmp_parent_is_trusted() {
  local root_physical=""
  local parent_physical=""
  local root_owner=""
  local root_mode=""
  local parent_owner=""
  local parent_mode=""
  local -i root_mode_bits=0
  local -i parent_mode_bits=0

  [[ "$verification_tmp_parent" == /* && -d / && ! -L / ]] || return 1
  root_physical="$(CDPATH='' cd -P -- / && pwd -P)" || return 1
  [[ "$root_physical" == / ]] || return 1
  root_owner="$(stat --format=%u -- /)" || return 1
  root_mode="$(stat --format=%a -- /)" || return 1
  [[ "$root_owner" == 0 && "$root_mode" =~ ^[0-7]{3,4}$ ]] || return 1
  root_mode_bits=$((8#$root_mode))
  (( (root_mode_bits & 0022) == 0 )) || return 1

  [[ -d "$verification_tmp_parent" && ! -L "$verification_tmp_parent" ]] ||
    return 1
  parent_physical="$(CDPATH='' cd -P -- "$verification_tmp_parent" && pwd -P)" ||
    return 1
  [[ "$parent_physical" == "$verification_tmp_parent" ]] || return 1
  parent_owner="$(stat --format=%u -- "$verification_tmp_parent")" || return 1
  parent_mode="$(stat --format=%a -- "$verification_tmp_parent")" || return 1
  [[ "$parent_owner" == 0 && "$parent_mode" =~ ^[0-7]{3,4}$ ]] || return 1
  parent_mode_bits=$((8#$parent_mode))
  (( (parent_mode_bits & 01000) != 0 && (parent_mode_bits & 0002) != 0 ))
}

private_verification_tmp_is_safe() {
  local physical=""
  local owner=""
  local mode=""

  verification_tmp_parent_is_trusted || return 1
  [[ "$temporary_directory" == "$verification_tmp_parent"/obi-claims-verify.* &&
    -d "$temporary_directory" && ! -L "$temporary_directory" ]] || return 1
  physical="$(CDPATH='' cd -P -- "$temporary_directory" && pwd -P)" || return 1
  [[ "$physical" == "$temporary_directory" ]] || return 1
  owner="$(stat --format=%u -- "$temporary_directory")" || return 1
  mode="$(stat --format=%a -- "$temporary_directory")" || return 1
  [[ "$owner" == "$EUID" && "$mode" == 700 ]]
}

is_decimal_at_most() {
  local -r value="$1"
  local -r maximum="$2"

  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  ((${#value} < ${#maximum})) && return 0
  ((${#value} > ${#maximum})) && return 1
  [[ "$value" == "$maximum" || "$value" < "$maximum" ]]
}

public_file_maximum() {
  case "$1" in
    README.md|SANITIZATION.md) printf '%s\n' 4096 ;;
    acceptance-claims.json) printf '%s\n' 65536 ;;
    authority-summary.json) printf '%s\n' 32768 ;;
    derivation-receipt.json) printf '%s\n' 16384 ;;
    SHA256SUMS) printf '%s\n' 4096 ;;
    verify.sh) printf '%s\n' 65536 ;;
    *) return 1 ;;
  esac
}

materialize_bundle_closure() {
  local -r directory="$1"
  local -r output="$2"
  local candidate="${output}.candidate"

  find -- "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' |
    LC_ALL=C sort >"$candidate" || return 1
  mv -fT -- "$candidate" "$output"
}

copy_pinned_public_file() {
  local -r file="$1"
  local source_path="$source_bundle_directory/$file"
  local destination="$snapshot_bundle_directory/$file"
  local identity=""
  local descriptor_identity=""
  local path_identity=""
  local source_digest=""
  local copied_digest=""
  local after_digest=""
  local maximum=""
  local size=""
  local device=""
  local owner=""
  local mode=""
  local links=""
  local read_fd=""
  local copy_fd=""

  maximum="$(public_file_maximum "$file")" || return 1
  [[ -f "$source_path" && ! -L "$source_path" &&
    "$(readlink -f -- "$source_path")" == "$source_path" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source_path")" || return 1
  IFS=: read -r device _ owner mode links size <<<"$identity"
  [[ "$device" == "$root_device" && "$owner" == "$EUID" &&
    "$mode" == "$expected_file_mode" && "$links" == 1 ]] || return 1
  is_decimal_at_most "$size" "$maximum" || return 1
  total_bytes=$((total_bytes + size))
  ((total_bytes <= 188416)) || return 1

  exec {read_fd}<"$source_path" || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
    -- "/proc/self/fd/$read_fd")" || {
    exec {read_fd}<&-
    return 1
  }
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source_path")" || {
    exec {read_fd}<&-
    return 1
  }
  [[ "$descriptor_identity" == "$identity" && "$path_identity" == "$identity" &&
    -f "$source_path" && ! -L "$source_path" &&
    "$(readlink -f -- "$source_path")" == "$source_path" ]] || {
    exec {read_fd}<&-
    return 1
  }
  source_digest="$(sha256sum <&"$read_fd")" || {
    exec {read_fd}<&-
    return 1
  }
  exec {read_fd}<&-
  source_digest="${source_digest%% *}"
  [[ "$source_digest" =~ ^[0-9a-f]{64}$ ]] || return 1

  exec {copy_fd}<"$source_path" || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
    -- "/proc/self/fd/$copy_fd")" || {
    exec {copy_fd}<&-
    return 1
  }
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source_path")" || {
    exec {copy_fd}<&-
    return 1
  }
  [[ "$descriptor_identity" == "$identity" && "$path_identity" == "$identity" &&
    -f "$source_path" && ! -L "$source_path" ]] || {
    exec {copy_fd}<&-
    return 1
  }
  cat <&"$copy_fd" >"$destination" || {
    exec {copy_fd}<&-
    return 1
  }
  exec {copy_fd}<&-
  chmod 0600 -- "$destination" || return 1
  copied_digest="$(sha256sum <"$destination")" || return 1
  copied_digest="${copied_digest%% *}"
  [[ "$copied_digest" == "$source_digest" ]] || return 1
  [[ -f "$source_path" && ! -L "$source_path" &&
    "$(readlink -f -- "$source_path")" == "$source_path" &&
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source_path")" == "$identity" ]] ||
    return 1
  after_digest="$(sha256sum <"$source_path")" || return 1
  after_digest="${after_digest%% *}"
  [[ "$after_digest" == "$source_digest" &&
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source_path")" == "$identity" ]] ||
    return 1
  printf '%s\t%s\t%s\n' "$file" "$identity" "$source_digest" \
    >>"$source_manifest"
}

reassert_source_bundle() {
  local file=""
  local identity=""
  local expected_digest=""
  local observed_digest=""
  local path=""

  [[ -d "$source_bundle_directory" && ! -L "$source_bundle_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$source_bundle_directory")" == "$source_root_identity" ]] ||
    return 1
  materialize_bundle_closure \
    "$source_bundle_directory" "$temporary_directory/source-files.final" ||
    return 1
  cmp -s -- "$temporary_directory/expected-files" \
    "$temporary_directory/source-files.final" || return 1
  while IFS=$'\t' read -r file identity expected_digest; do
    [[ -n "$file" && -n "$identity" && -n "$expected_digest" ]] || return 1
    path="$source_bundle_directory/$file"
    [[ -f "$path" && ! -L "$path" &&
      "$(readlink -f -- "$path")" == "$path" &&
      "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" == "$identity" ]] ||
      return 1
    observed_digest="$(sha256sum <"$path")" || return 1
    observed_digest="${observed_digest%% *}"
    [[ "$observed_digest" == "$expected_digest" &&
      "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" == "$identity" ]] ||
      return 1
  done <"$source_manifest"
  [[ -d "$source_bundle_directory" && ! -L "$source_bundle_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$source_bundle_directory")" == "$source_root_identity" ]]
}

temporary_directory=""
temporary_identity=""
materialize_cleanup_directories() {
  local -r path="$1"
  local -r root_device="$2"
  local -r output="$3"
  local directory=""
  local identity=""
  local device=""
  local owner=""
  local mount_status=0

  find -- "$path" -xdev -type d -print0 | LC_ALL=C sort -z >"$output" ||
    return 1
  while IFS= read -r -d '' directory; do
    [[ -d "$directory" && ! -L "$directory" &&
      "$(readlink -f -- "$directory")" == "$directory" ]] || return 1
    identity="$(stat -Lc '%d:%u' -- "$directory")" || return 1
    IFS=: read -r device owner <<<"$identity"
    [[ "$device" == "$root_device" && "$owner" == "$EUID" ]] || return 1
    if [[ "$directory" != "$path" ]]; then
      if mountpoint -q -- "$directory"; then
        return 1
      else
        mount_status=$?
        ((mount_status == 32)) || return 1
      fi
    fi
  done <"$output"
}

open_cleanup_directories() {
  local -r path="$1"
  local -r root_device="$2"
  local -r input="$3"
  local directory=""
  local identity=""
  local descriptor_identity=""
  local path_identity=""
  local directory_fd=""
  local mount_status=0

  while IFS= read -r -d '' directory; do
    [[ -d "$directory" && ! -L "$directory" &&
      "$(readlink -f -- "$directory")" == "$directory" ]] || return 1
    identity="$(stat -Lc '%d:%i:%u' -- "$directory")" || return 1
    [[ "${identity%%:*}" == "$root_device" && "${identity##*:}" == "$EUID" ]] ||
      return 1
    if [[ "$directory" != "$path" ]]; then
      if mountpoint -q -- "$directory"; then
        return 1
      else
        mount_status=$?
        ((mount_status == 32)) || return 1
      fi
    fi
    exec {directory_fd}<"$directory" || return 1
    descriptor_identity="$(stat -Lc '%d:%i:%u' \
      -- "/proc/self/fd/$directory_fd")" || {
      exec {directory_fd}<&-
      return 1
    }
    path_identity="$(stat -Lc '%d:%i:%u' -- "$directory")" || {
      exec {directory_fd}<&-
      return 1
    }
    [[ "$descriptor_identity" == "$identity" && "$path_identity" == "$identity" &&
      -d "/proc/self/fd/$directory_fd" ]] || {
      exec {directory_fd}<&-
      return 1
    }
    chmod u+rwx -- "/proc/self/fd/$directory_fd" >/dev/null 2>&1 || {
      exec {directory_fd}<&-
      return 1
    }
    exec {directory_fd}<&-
  done <"$input"
}

cleanup_on_exit() {
  local -r original_status="$?"
  local cleanup_status=0
  local observed_identity=""
  local root_device=""
  local first=""
  local second=""

  trap - EXIT
  if [[ -n "$temporary_directory" ]]; then
    verification_tmp_parent_is_trusted || cleanup_status=1
    [[ "$temporary_directory" == "$verification_tmp_parent"/obi-claims-verify.* ]] ||
      cleanup_status=1
    if [[ -e "$temporary_directory" || -L "$temporary_directory" ]]; then
      if [[ -d "$temporary_directory" && ! -L "$temporary_directory" ]]; then
        observed_identity="$(stat -Lc '%d:%i:%u' -- "$temporary_directory")" ||
          cleanup_status=1
        if [[ "$observed_identity" == "$temporary_identity" ]]; then
          root_device="${temporary_identity%%:*}"
          if ((cleanup_status == 0)); then
            first="$(mktemp \
              "$verification_tmp_parent/.obi-claims-cleanup-directories.XXXXXX")" ||
              cleanup_status=1
          fi
          if ((cleanup_status == 0)); then
            second="$(mktemp \
              "$verification_tmp_parent/.obi-claims-cleanup-directories.XXXXXX")" ||
              cleanup_status=1
          fi
          if ((cleanup_status == 0)); then
            chmod 0600 -- "$first" "$second" || cleanup_status=1
          fi
          if ((cleanup_status == 0)); then
            materialize_cleanup_directories \
              "$temporary_directory" "$root_device" "$first" || cleanup_status=1
          fi
          if ((cleanup_status == 0)); then
            open_cleanup_directories \
              "$temporary_directory" "$root_device" "$first" || cleanup_status=1
          fi
          if ((cleanup_status == 0)); then
            materialize_cleanup_directories \
              "$temporary_directory" "$root_device" "$second" || cleanup_status=1
          fi
          if ((cleanup_status == 0)); then
            cmp -s -- "$first" "$second" || cleanup_status=1
          fi
          observed_identity="$(stat -Lc '%d:%i:%u' \
            -- "$temporary_directory" 2>/dev/null || true)"
          [[ "$observed_identity" == "$temporary_identity" ]] || cleanup_status=1
          if ((cleanup_status == 0)); then
            rm --one-file-system -rf -- "$temporary_directory" || cleanup_status=1
          fi
        else
          cleanup_status=1
        fi
      else
        cleanup_status=1
      fi
    fi
    if [[ -n "$first" ]]; then rm -f -- "$first" || cleanup_status=1; fi
    if [[ -n "$second" ]]; then rm -f -- "$second" || cleanup_status=1; fi
    [[ ! -e "$temporary_directory" && ! -L "$temporary_directory" ]] ||
      cleanup_status=1
  fi
  if ((original_status == 0 && cleanup_status != 0)); then
    printf 'verify.sh: temporary cleanup was incomplete\n' >&2
    exit 1
  fi
  exit "$original_status"
}
trap cleanup_on_exit EXIT

[[ $# == 0 ]] || { printf 'usage: bash /path/to/bundle/verify.sh\n' >&2; exit 2; }
for command_name in cat chmod cmp dirname find jq mkdir mktemp mountpoint mv pwd \
  readlink rm sha256sum sort stat; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "missing dependency: $command_name"
done

script_source="${BASH_SOURCE[0]}"
logical_directory="$(CDPATH='' cd -L -- "$(dirname -- "$script_source")" && pwd -L)" ||
  fail 'could not resolve the logical script directory'
script_directory="$(CDPATH='' cd -P -- "$(dirname -- "$script_source")" && pwd -P)" ||
  fail 'could not resolve the physical script directory'
[[ "$logical_directory" == "$script_directory" ]] ||
  fail 'the bundle path contains a symbolic-link component'
script_path="$script_directory/${script_source##*/}"
[[ -f "$script_path" && ! -L "$script_path" &&
  "$(readlink -f -- "$script_path")" == "$script_path" ]] ||
  fail 'verify.sh must be a physical regular file'
source_bundle_directory="$script_directory"
bundle_directory="$source_bundle_directory"
bundle_name="${source_bundle_directory##*/}"
[[ "$bundle_name" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] ||
  fail 'bundle name is not a safe evidence identifier'

verification_tmp_parent_is_trusted ||
  fail 'verification temporary parent must be physical, root-owned, sticky, and world writable'
temporary_directory="$(mktemp -d \
  "$verification_tmp_parent/obi-claims-verify.XXXXXX")" ||
  fail 'could not create a verification temporary directory'
temporary_directory="$(CDPATH='' cd -P -- "$temporary_directory" && pwd -P)" ||
  fail 'could not resolve the verification temporary directory'
private_verification_tmp_is_safe ||
  fail 'verification temporary directory must be a private physical mode-0700 directory'
temporary_identity="$(stat -Lc '%d:%i:%u' -- "$temporary_directory")" ||
  fail 'could not pin the verification temporary directory'
[[ "${temporary_identity##*:}" == "$EUID" ]] ||
  fail 'verification temporary directory ownership is unsafe'

printf '%s\n' README.md SANITIZATION.md acceptance-claims.json \
  authority-summary.json derivation-receipt.json SHA256SUMS verify.sh |
  LC_ALL=C sort >"$temporary_directory/expected-files" ||
  fail 'could not materialize the expected closure'
materialize_bundle_closure \
  "$source_bundle_directory" "$temporary_directory/actual-files" ||
  fail 'could not traverse the public bundle'
cmp -s -- "$temporary_directory/expected-files" \
  "$temporary_directory/actual-files" || fail 'public file closure is not exact'

source_root_identity="$(stat -Lc '%d:%i:%u:%a' -- "$source_bundle_directory")" ||
  fail 'could not pin the bundle root identity'
root_device="${source_root_identity%%:*}"
root_authority="${source_root_identity#*:*:}"
[[ -d "$source_bundle_directory" && ! -L "$source_bundle_directory" &&
  "$(stat -Lc '%d:%i:%u:%a' -- "$source_bundle_directory")" == "$source_root_identity" ]] ||
  fail 'bundle root is not stable'
root_device="$(stat -Lc '%d' -- "$source_bundle_directory")" ||
  fail 'could not inspect the bundle device'
[[ "${root_authority%%:*}" == "$EUID" ]] || fail 'bundle root owner is unsafe'
root_mode="${root_authority#*:}"
case "$root_mode" in
  555) expected_file_mode=444 ;;
  755) expected_file_mode=644 ;;
  *) fail 'bundle mode is neither sealed 0555 nor Git-portable 0755' ;;
esac
snapshot_bundle_directory="$temporary_directory/bundle"
mkdir -m 0700 -- "$snapshot_bundle_directory" ||
  fail 'could not create the private bundle snapshot'
source_manifest="$temporary_directory/source.manifest"
: >"$source_manifest" || fail 'could not create the pinned source manifest'
total_bytes=0
while IFS= read -r file; do
  copy_pinned_public_file "$file" || fail "public file changed or is unsafe: $file"
done <"$temporary_directory/expected-files"
[[ -d "$source_bundle_directory" && ! -L "$source_bundle_directory" &&
  "$(stat -Lc '%d:%i:%u:%a' -- "$source_bundle_directory")" == "$source_root_identity" ]] ||
  fail 'bundle root changed during pinned copy'
materialize_bundle_closure \
  "$source_bundle_directory" "$temporary_directory/source-files.after-copy" ||
  fail 'could not recheck source closure after pinned copy'
cmp -s -- "$temporary_directory/expected-files" \
  "$temporary_directory/source-files.after-copy" ||
  fail 'public file closure changed during pinned copy'
bundle_directory="$snapshot_bundle_directory"

printf '%s\n' README.md SANITIZATION.md acceptance-claims.json \
  authority-summary.json derivation-receipt.json verify.sh |
  LC_ALL=C sort >"$temporary_directory/manifest-paths" ||
  fail 'could not materialize manifest paths'
: >"$temporary_directory/manifest.expected"
while IFS= read -r file; do
  digest="$(sha256sum <"$bundle_directory/$file")" || fail "could not hash: $file"
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "invalid digest: $file"
  printf '%s  ./%s\n' "$digest" "$file" >>"$temporary_directory/manifest.expected" ||
    fail 'could not reconstruct SHA256SUMS'
done <"$temporary_directory/manifest-paths"
cmp -s -- "$bundle_directory/SHA256SUMS" \
  "$temporary_directory/manifest.expected" ||
  fail 'SHA256SUMS is not the exact path-ordered canonical manifest'

cat >"$temporary_directory/README.expected" <<'README_TEXT'
# Bounded retained acceptance claims

This is a bounded claim summary derived from privately verified raw-v3 runs.
Run `cd /path/to/bundle && bash verify.sh` (or `bash /path/to/bundle/verify.sh`) to verify canonical bytes, closure, hashes, modes, and cross-file relations.
The bundled verifier and SHA256SUMS prove internal consistency only; they are not signatures or independent authenticity evidence. Compare both the evidence ID and the verifier SHA-256 digest with an externally trusted record.
The public bundle intentionally cannot recompute raw trace, metric, journal, process, or resource semantics after private raw evidence expires.
Issue #34 map safety uses non-evicting HASH capacity rejection and recovery; it supersedes the issue body's old LRU-eviction wording and does not claim that LRU eviction was exercised.
README_TEXT
cat >"$temporary_directory/SANITIZATION.expected" <<'SANITIZATION_TEXT'
# Sanitization contract

Only canonical allowlisted claim, authority, derivation, and verification fields are public.
No raw paths, logs, traces, spans, metrics, markers, connection data, process identities, timestamps, absolute resource values, credentials, payloads, or runbook output are retained.
Private trees use obi-private-file-manifest-commitment-v1: SHA-256 over the domain line, role line, then LC_ALL=C path-ordered `<content-sha256>  ./<safe-relative-path>` lines with terminal LF; regular files are included, modes are excluded, and empty directories are rejected.
The runbook is represented by a SHA-256 commitment plus a closed GitHub Actions execution locator; no runbook output is copied.
SANITIZATION_TEXT
cmp -s -- "$bundle_directory/README.md" "$temporary_directory/README.expected" ||
  fail 'README.md is not the fixed trust statement'
cmp -s -- "$bundle_directory/SANITIZATION.md" \
  "$temporary_directory/SANITIZATION.expected" ||
  fail 'SANITIZATION.md is not the fixed privacy statement'

for json in acceptance-claims.json authority-summary.json derivation-receipt.json; do
  jq -cS -e -s 'if length == 1 and (.[0] | type == "object") then .[0]
    else error("one object required") end' "$bundle_directory/$json" \
    >"$temporary_directory/$json" || fail "invalid JSON: $json"
  cmp -s -- "$bundle_directory/$json" "$temporary_directory/$json" ||
    fail "noncanonical JSON: $json"
done

jq -e '
  def sha256: type == "string" and test("^[0-9a-f]{64}$");
  def bounded_integer($minimum; $maximum):
    type == "number" and floor == . and . >= $minimum and . <= $maximum;
  keys == ["execution_locator", "fixed_run_profile", "official_agent",
    "private_commitment_profile", "private_input_roots", "schema", "source"] and
  .schema == "obi-bounded-claim-authority-v1" and
  (.source | keys == ["architecture", "clean", "revision", "tree_sha256"] and
    .clean == true and (.revision | test("^[0-9a-f]{40}$")) and
    (.tree_sha256 | sha256) and
    (.architecture == "x86_64" or .architecture == "aarch64")) and
  .official_agent == {
    distribution:"otel",
    sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",
    version:"2.28.1"} and
  .fixed_run_profile == {acceptance_scenario:"all", agent_distribution:"otel",
    assertion_scenario:"assertion-failure", keep_requested:false,
    repeat_count:1, request_count_override:0, seed:1,
    tls_protocol:"TLSv1.3", transport:"getsockopt"} and
  (.execution_locator |
    keys == ["event", "head_sha", "kind", "repository", "run_attempt",
      "run_id", "run_url", "workflow_blob_sha256", "workflow_path",
      "workflow_ref", "workflow_sha"] and .kind == "github-actions" and
    .event == "push" and
    .repository == "MrAlias/opentelemetry-ebpf-instrumentation" and
    .workflow_path == ".github/workflows/java_remote_parent_acceptance_claims.yml" and
    (.run_id | test("^[1-9][0-9]{0,18}$")) and
    (.run_attempt | test("^[1-9][0-9]{0,18}$")) and
    (.head_sha | test("^[0-9a-f]{40}$")) and .workflow_sha == .head_sha and
    (.workflow_blob_sha256 | sha256) and
    .workflow_ref == (.repository + "/" + .workflow_path +
      "@refs/heads/agent/java-remote-parent-bridge") and
    .run_url == ("https://github.com/" + .repository + "/actions/runs/" +
      .run_id + "/attempts/" + .run_attempt)) and
  .execution_locator.head_sha == .source.revision and
  .private_commitment_profile == {
    algorithm:"sha256", directory_rule:"empty-directories-rejected",
    entries:"regular-files-only", modes_included:false,
    ordering:"LC_ALL=C relative-path byte order",
    preimage:"obi-private-file-manifest-commitment-v1\\n<role>\\n<content-sha256>  ./<safe-relative-path>\\n",
    role_bound:true, schema:"obi-private-file-manifest-commitment-v1",
    terminal_lf:true} and
  (.private_input_roots |
    keys == ["acceptance", "assertion", "runbook"] and
    (.acceptance | keys == ["file_count", "role", "run_status_sha256",
      "schema", "sha256", "total_bytes"] and .role == "acceptance" and
      .schema == "obi-private-file-manifest-commitment-v1" and
      (.file_count | bounded_integer(1;32768)) and
      (.total_bytes | bounded_integer(1;603979776)) and
      (.sha256 | sha256) and (.run_status_sha256 | sha256)) and
    (.assertion | keys == ["file_count", "role", "run_status_sha256",
      "schema", "sha256", "total_bytes"] and .role == "assertion-failure" and
      .schema == "obi-private-file-manifest-commitment-v1" and
      (.file_count | bounded_integer(1;32768)) and
      (.total_bytes | bounded_integer(1;603979776)) and
      (.sha256 | sha256) and (.run_status_sha256 | sha256)) and
    .runbook == {role:"runbook-receipt", sha256:.runbook.sha256} and
    (.runbook.sha256 | sha256))
' "$bundle_directory/authority-summary.json" >/dev/null ||
  fail 'authority-summary.json violates its closed schema'

jq -e '
  def sha256: type == "string" and test("^[0-9a-f]{64}$");
  def integer_between($minimum; $maximum):
    type == "number" and floor == . and . >= $minimum and . <= $maximum;
  def recovery($phase; $rss_cap):
    keys == ["delta", "phase", "within_growth_policy"] and
    .phase == $phase and .within_growth_policy == true and
    (.delta | keys == ["fds", "threads", "vm_rss_kib"] and
      (.fds | integer_between(-4096;8)) and
      (.threads | integer_between(-2048;32)) and
      (.vm_rss_kib | integer_between(-4194304;$rss_cap)));
  def service($name; $rss_cap):
    keys == ["identity_continuous", "recovery", "service", "spread",
      "within_absolute_policy"] and .service == $name and
    .identity_continuous == true and .within_absolute_policy == true and
    (.recovery | length == 2) and
    (.recovery[0] | recovery("pressure-after";$rss_cap)) and
    (.recovery[1] | recovery("handoff-before";$rss_cap)) and
    (.spread | keys == ["fds", "threads", "vm_rss_kib", "within_policy"] and
      .within_policy == true and (.fds | integer_between(0;2)) and
      (.threads | integer_between(0;2)) and
      (.vm_rss_kib | integer_between(0;32768)));
  def scenario($name; $count; $exact; $roots; $topology): {
    bounded_duration_verified:true, duration_cap_nanos:75000000000,
    exact_parent_count:$exact, explicit_local_root_count:$roots, name:$name,
    request_count:$count, required_metric_pair_and_java_capture_verified:true,
    topology_contract:$topology, zero_unresolved_parent:true,
    zero_wrong_parent:true};
  def timeout_scenario($outcome; $reason): {
    bounded_duration_verified:true, duration_cap_nanos:75000000000,
    name:"timeout-retry", reconciliation:{outcome:$outcome,reason:$reason},
    request_count:1, required_metric_pair_and_java_capture_verified:true,
    topology_contract:"reason-coded-timeout-reconciliation",
    zero_unresolved_parent:true, zero_wrong_parent:true};
  def fixed_drop_reason:
    . == "missing" or . == "stale" or . == "unsupported" or
    . == "malformed" or . == "version_mismatch" or . == "ambiguous" or
    . == "unauthorized" or . == "already_consumed" or . == "timeout" or
    . == "overload" or . == "transport_error" or . == "disabled";
  keys == ["issue_32", "issue_34", "schema", "status"] and
  .schema == "obi-bounded-acceptance-claims-v1" and .status == "passed" and
  (.issue_32 |
    keys == ["acceptance_run", "assertion_control", "basic_control",
      "clean_source_before_and_after", "final_clean_status_passed",
      "no_keep_invocation", "producer_status_roster", "scoped_cleanup_passed"] and
    .clean_source_before_and_after == true and .no_keep_invocation == true and
    .scoped_cleanup_passed == true and .final_clean_status_passed == true and
    .acceptance_run == {acceptance_evidence:true, exit_status:0, status:"passed"} and
    .assertion_control == {exit_status:2,
      failure_stage:"deliberate-assertion-failure",
      reason:"deliberate-assertion-failure,targeted-scenario", status:"failed"} and
    .basic_control == {request_count:1, status:"passed", zero_wrong_parent:true} and
    (.producer_status_roster |
      keys == ["boundary_count", "boundary_order", "commitment", "exact_once",
        "not_applicable", "schema", "status_entry_count"] and
      .schema == "obi-producer-status-roster-commitment-v1" and
      .boundary_count == 35 and .status_entry_count == 56 and .exact_once == true and
      .boundary_order == ["basic","delayed-otlp-suppression","security",
        "keepalive","pipelining","concurrency","connection-churn",
        "fd-port-reuse","slow-body","tls-boundary","coalesced-bridge",
        "timeout-retry","pressure","handoff","virtual-thread","netty",
        "netty-server","dispatch","w3c","w3c-match","obi-flags",
        "primary-w3c-stale","primary-generation-mismatch","primary-w3c-fault",
        "unix-w3c-stale","unix-generation-mismatch","w3c-fault",
        "permanent-absence","auto-unavailable","late-attach",
        "restart-during-traffic","helper-attach-failure","disabled",
        "extension-controls","uninstrumented"] and
      .not_applicable == [
        {id:"unix-w3c-stale",reason:"requires forced Unix transport"},
        {id:"unix-generation-mismatch",reason:"requires forced Unix transport"},
        {id:"w3c-fault",reason:"requires forced Unix transport"},
        {id:"auto-unavailable",reason:"requires auto transport selection"}] and
      (.commitment | keys == ["algorithm", "preimage", "sha256"] and
        .algorithm == "sha256" and
        .preimage == "obi-producer-status-roster-commitment-v1" and
        (.sha256 | sha256)))) and
  (.issue_34 |
    keys == ["container_leader_resource_recovery", "duration_cap_nanos",
      "map_safety", "marker_authority", "marker_role",
      "reason_coded_misses_and_drops", "recorded_seed", "request_count_override",
      "scenario_order", "scenarios", "trace_selection_order_independent",
      "tracecheck_tests_passed", "zero_wrong_parent"] and
    .marker_role == "verification-only" and
    .marker_authority == "exact-source-and-test-identity" and
    .trace_selection_order_independent == true and .tracecheck_tests_passed == true and
    .recorded_seed == 1 and .request_count_override == 0 and
    .duration_cap_nanos == 75000000000 and .zero_wrong_parent == true and
    .reason_coded_misses_and_drops == true and
    .scenario_order == ["keepalive","pipelining","concurrency",
      "connection-churn","fd-port-reuse","slow-body","tls-boundary",
      "coalesced-bridge","timeout-retry","pressure","handoff"] and
    (.scenarios | type == "array" and length == 11) and
    .scenarios[0:8] == [
      scenario("keepalive";10;10;0;"single-backend-connection"),
      scenario("pipelining";10;10;0;"preterminal-backend-reuse"),
      scenario("concurrency";16;16;0;"barrier-and-worker-concurrency"),
      scenario("connection-churn";32;32;0;"multiple-backend-connections"),
      scenario("fd-port-reuse";32;32;0;"frontend-port-and-fd-reuse"),
      scenario("slow-body";8;8;0;"split-tls-read-deltas"),
      scenario("tls-boundary";3;3;0;"current-tls-boundary-evidence"),
      scenario("coalesced-bridge";2;0;2;"explicit-local-java-roots")] and
    (.scenarios[8] as $timeout |
      ($timeout.reconciliation |
        keys == ["outcome", "reason"] and
        ((.outcome == "exact" or .outcome == "missing") and .reason == null or
          .outcome == "reason_coded_drop" and
            (.reason | type == "string" and fixed_drop_reason))) and
      $timeout == timeout_scenario(
        $timeout.reconciliation.outcome; $timeout.reconciliation.reason)) and
    (.scenarios[9] as $pressure |
      ($pressure.exact_parent_count | integer_between(0;128)) and
      ($pressure.explicit_local_root_count | integer_between(0;128)) and
      ($pressure.exact_parent_count +
        $pressure.explicit_local_root_count) == 128 and
      $pressure == scenario("pressure";128;
        $pressure.exact_parent_count; $pressure.explicit_local_root_count;
        "pressure-exact-or-explicit-root")) and
    .scenarios[10] ==
      scenario("handoff";4;4;0;"parallel-handoff-chain") and
    .map_safety == {capacity:10000, capacity_rejection_observed:true,
      lru_eviction_exercised:false, map_type:"non-evicting HASH",
      old_lru_eviction_wording_superseded:true,
      post_rejection_correctness_verified:true, steady_baseline_recovered:true} and
    (.container_leader_resource_recovery |
      keys == ["distinct_container_identity_count", "distinct_host_pid_count",
        "distinct_service_identities", "policy", "scope", "services"] and
      .scope == "container_leader_process" and
      .distinct_container_identity_count == 5 and .distinct_host_pid_count == 5 and
      .distinct_service_identities == true and
      .policy == {absolute:{fds:4096,threads:2048,vm_rss_kib:4194304},
        growth:{fds:8,threads:32,vm_rss_kib_by_service:{"apache-proxy":32768,
          "coalesced-source":32768,"java-backend":131072,obi:65536,
          "trace-receiver":65536}},
        recovery_spread:{fds:2,threads:2,vm_rss_kib:32768}} and
      (.services | length == 5) and
      (.services[0] | service("obi";65536)) and
      (.services[1] | service("apache-proxy";32768)) and
      (.services[2] | service("java-backend";131072)) and
      (.services[3] | service("coalesced-source";32768)) and
      (.services[4] | service("trace-receiver";65536))))
' "$bundle_directory/acceptance-claims.json" >/dev/null ||
  fail 'acceptance-claims.json violates its closed schema'

authority_sha256="$(sha256sum <"$bundle_directory/authority-summary.json")" ||
  fail 'could not hash authority-summary.json'
authority_sha256="${authority_sha256%% *}"
claims_sha256="$(sha256sum <"$bundle_directory/acceptance-claims.json")" ||
  fail 'could not hash acceptance-claims.json'
claims_sha256="${claims_sha256%% *}"
evidence_id="$(printf '%s\n' 'obi-bounded-claims-evidence-v1' "$bundle_name" \
  "$authority_sha256" "$claims_sha256" | sha256sum)" ||
  fail 'could not derive the evidence ID'
evidence_id="${evidence_id%% *}"
jq -e --arg bundle_name "$bundle_name" --arg authority "$authority_sha256" \
  --arg claims "$claims_sha256" --arg evidence_id "$evidence_id" '
  keys == ["authority", "bundle_name", "claims", "derivation_contract",
    "evidence_id", "private_validation_profile", "public_file_order", "schema"] and
  .schema == "obi-bounded-claim-derivation-v1" and
  .derivation_contract == "private-raw-v3-to-bounded-claims-v1" and
  .bundle_name == $bundle_name and .evidence_id == $evidence_id and
  .authority == {reference:"authority-summary.json", sha256:$authority} and
  .claims == {reference:"acceptance-claims.json", sha256:$claims} and
  .private_validation_profile == {
    exact_complete_producer_roster_validated:true,
    fixed_invocations_without_keep_validated:true,
    raw_semantics_recomputable_from_public_bundle:false,
    raw_semantics_validated_before_projection:true,
    raw_snapshots_same_device_and_capped:true,
    required_eleven_stress_pair_ownership_validated:true} and
  .public_file_order == ["README.md","SANITIZATION.md","acceptance-claims.json",
    "authority-summary.json","derivation-receipt.json","verify.sh","SHA256SUMS"]
' "$bundle_directory/derivation-receipt.json" >/dev/null ||
  fail 'derivation-receipt.json violates its closed schema or bundle name'

reassert_source_bundle ||
  fail 'source bundle changed during standalone verification'
printf 'bounded claim bundle internally consistent (not authenticated): %s\n' \
  "$evidence_id"
CLAIM_VERIFY_SCRIPT
}

main() {
  if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    usage
    return 0
  fi
  [[ $# == 4 ]] || {
    usage >&2
    return 2
  }
  ACCEPTANCE_SOURCE="$1"
  ASSERTION_SOURCE="$2"
  RUNBOOK_SOURCE="$3"
  OUTPUT_DIRECTORY="$4"
  check_dependencies
  assert_absolute_physical_directory "$ACCEPTANCE_SOURCE" ||
    die "acceptance input must be a private physical directory owned by this user"
  assert_absolute_physical_directory "$ASSERTION_SOURCE" ||
    die "assertion input must be a private physical directory owned by this user"
  [[ "$ACCEPTANCE_SOURCE" != "$ASSERTION_SOURCE" ]] ||
    die "acceptance and assertion inputs must be distinct"
  assert_output_parent
  WORK_DIRECTORY="$(mktemp -d \
    "$OUTPUT_PARENT/.retained-projection-transaction.XXXXXX")" ||
    die "could not create same-filesystem private transaction"
  WORK_DIRECTORY="$(cd -- "$WORK_DIRECTORY" && pwd -P)" ||
    die "could not resolve private transaction"
  chmod 0700 -- "$WORK_DIRECTORY" || die "could not seal private transaction"
  WORK_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$WORK_DIRECTORY")" ||
    die "could not pin private transaction identity"

  ACCEPTANCE_SNAPSHOT="$(snapshot_directory \
    "$ACCEPTANCE_SOURCE" "$WORK_DIRECTORY/acceptance")"
  ASSERTION_SNAPSHOT="$(snapshot_directory \
    "$ASSERTION_SOURCE" "$WORK_DIRECTORY/assertion")"
  snapshot_runbook_receipt
  capture_private_input_authority || die "could not commit the private inputs"
  seal_private_input_snapshots || die "could not seal the private input snapshots"
  assert_private_input_authority_unchanged ||
    die "private inputs changed while being sealed"
  validate_execution_bytes_and_locator ||
    die "execution checkout bytes or run locator are not authoritative"
  "$VERIFIER" --raw-v3 acceptance "$ACCEPTANCE_SNAPSHOT" ||
    die "acceptance raw-v3 input did not verify"
  "$VERIFIER" --raw-v3 assertion-failure "$ASSERTION_SNAPSHOT" ||
    die "assertion-failure raw-v3 input did not verify"
  assert_raw_runs_share_authority ||
    die "the two raw runs do not share one pinned source and runtime authority"
  validate_private_claim_inputs ||
    die "private raw runs do not satisfy the bounded claim profile"
  assert_private_input_authority_unchanged ||
    die "private inputs changed during semantic verification"

  CANDIDATE_DIRECTORY="$WORK_DIRECTORY/$OUTPUT_NAME"
  mkdir -m 0700 -- "$CANDIDATE_DIRECTORY" ||
    die "could not create private publication candidate"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")" ||
    die "could not pin publication candidate identity"
  write_claim_authority_summary || die "could not derive public authority"
  write_acceptance_claim_summary || die "could not derive acceptance claims"
  write_derivation_receipt || die "could not bind the derivation receipt"
  write_claim_summary_notes || die "could not write bounded-claim notes"
  write_portable_claim_verifier || die "could not write portable verifier"
  write_checksum_manifest || die "could not seal the checksum closure"
  assert_private_input_authority_unchanged ||
    die "private inputs changed during bounded-claim derivation"
  validate_public_candidate_budget ||
    die "public candidate exceeds its exact file or byte cap"
  seal_public_candidate || die "could not make the candidate immutable"
  "$VERIFIER" --claims-v1 "$CANDIDATE_DIRECTORY" >/dev/null ||
    die "bounded-claim candidate did not pass claims-v1 verification"
  (CDPATH='' cd / && bash "$CANDIDATE_DIRECTORY/verify.sh" >/dev/null) ||
    die "bounded-claim candidate did not pass portable verification"
  publish_verified_candidate || return 1
  cleanup || die "private transaction cleanup failed after publication"
  trap - EXIT
  printf 'bounded claim evidence published: %s\n' "$OUTPUT_DIRECTORY"
}

main "$@"
