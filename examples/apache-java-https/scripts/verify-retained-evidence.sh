#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERIFICATION_TMP_PARENT="/tmp"
readonly SCRIPT_NAME SCRIPT_DIR VERIFICATION_TMP_PARENT

readonly EMPTY_SHA256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
readonly MAX_UINT64_DECIMAL='18446744073709551615'
readonly JAVA_DIAGNOSTIC_COUNTER_MAX=999999999
readonly RUN_STATUS_MAX_BYTES=262144
readonly TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES=16384
readonly OBI_METRIC_PAIR_MAX_BYTES=131072
readonly OBI_PROCESS_IDENTITY_MAX_BYTES=2048
readonly OBI_METRIC_PAIR_MAX_SERIES=792
readonly OBI_METRIC_SNAPSHOT_MAX_BYTES=8388608
readonly OBI_METRIC_SNAPSHOT_MAX_LINES=20000
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_BYTES=4194304
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_BOUNDARIES=256
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_CAPTURES=4096
readonly OBI_METRIC_BOUNDARY_INDEX_MAX_STATUS_REFERENCES=1024
readonly OBI_METRIC_BOUNDARY_STATUS_MAX_BYTES=262144
readonly OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES=536870912
readonly OBI_METRIC_BOUNDARY_FREEZE_MAX_BYTES=160
readonly BUNDLE_ARCHIVE_MAX_BYTES=603979776
readonly BUNDLE_ARCHIVE_MAX_FILES=32768
readonly RAW_V3_ARCHIVE_MAX_BYTES=603979776
readonly RAW_V3_ARCHIVE_MAX_FILES=32768
readonly CLAIM_V1_ARCHIVE_MAX_BYTES=188416
readonly CLAIM_V1_ARCHIVE_MAX_FILES=7
readonly CLAIM_VERIFY_SH_SHA256='376907ef806b4fdbdc971dde6d4a6f968476c64b237900d80a80dcd8d83e6f8b'
readonly RAW_V3_JSON_MAX_BYTES=1048576
readonly RAW_V3_SCENARIO_MAX_BYTES=8388608
readonly RAW_V3_SCENARIO_MAX_LINES=131072
readonly RAW_V3_RESOURCE_MAX_BYTES=2048
readonly RAW_V3_RESOURCE_VM_MAX_KIB=17179869184
readonly RAW_V3_RESOURCE_FDS_MAX=4096
readonly RAW_V3_RESOURCE_THREADS_MAX=2048
readonly RAW_V3_RESOURCE_RSS_MAX_KIB=4194304
readonly OTEL_AGENT_VERSION='2.28.1'
readonly OTEL_AGENT_SHA256='faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589'
readonly OTEL_AGENT_URL='https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar'

BUNDLE_DIR=""
BUNDLE_NAME=""
TRUSTED_REPO_ROOT=""
TRUSTED_HEAD=""
REPO_ROOT=""
TMP_DIR=""
TMP_DIR_IDENTITY=""
BUNDLE_SNAPSHOT_ROOT=""
REQUIRE_CURRENT_CODE=false
VERIFICATION_MODE="tracked"
RAW_V3_KIND=""
EXTERNAL_SOURCE_DIRECTORY=""
OBI_METRIC_BOUNDARY_INDEX_PAYLOAD=""
OBI_METRIC_BOUNDARY_INDEX_SHA256=""
declare -A VERIFIED_REFERENCE_SHA256=()
declare -A VALIDATED_JAVA_DIAGNOSTICS_REFERENCES=()
declare -A VALIDATED_OBI_IDENTITY_REFERENCES=()
declare -A VALIDATED_OBI_PAIR_REFERENCES=()
declare -A VALIDATED_OBI_UNAVAILABLE_REFERENCES=()
declare -A VALIDATED_STATUS_REFERENCES=()
declare -A PARSED_OBI_METRIC_REFERENCES=()
declare -A OBI_IDENTITY_STATE=()
declare -A OBI_IDENTITY_CONTAINER_ID=()
declare -A OBI_IDENTITY_STARTED_AT=()
declare -A OBI_IDENTITY_METRICS_REFERENCE=()

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME [--current-code] BUNDLE_DIRECTORY" \
    "       $SCRIPT_NAME --raw-v3 acceptance ABSOLUTE_RESULT_DIRECTORY" \
    "       $SCRIPT_NAME --raw-v3 assertion-failure ABSOLUTE_RESULT_DIRECTORY" \
    "       $SCRIPT_NAME --claims-v1 ABSOLUTE_BUNDLE_DIRECTORY" \
    "" \
    "Verify one sanitized retained acceptance-evidence bundle in this Git checkout." \
    "The verifier checks the checksum manifest, canonical evidence identity, clean" \
    "full-suite status, and source-tree provenance reconstructed from the recorded commit." \
    "By default, historical evidence remains valid for its recorded revision only." \
    "--current-code also rejects changes after that revision except retained evidence" \
    "publication and Markdown documentation in the repository's documentation locations." \
    "The raw-v3 modes validate private producer output without publishing it." \
    "The claims-v1 mode validates one closed bounded-claim summary."
}

die() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

sanitize_git_environment() {
  local git_variable=""

  # The physical checkout containing this verifier is the trust root. Do not
  # let caller-provided Git selection or temporary-config state redirect any
  # of the Git queries used to establish that root or archive its evidence.
  unset \
    GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_CEILING_DIRECTORIES \
    GIT_COMMON_DIR \
    GIT_CONFIG \
    GIT_CONFIG_COUNT \
    GIT_CONFIG_GLOBAL \
    GIT_CONFIG_NOSYSTEM \
    GIT_CONFIG_PARAMETERS \
    GIT_CONFIG_SYSTEM \
    GIT_DIR \
    GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_DIFF_OPTS \
    GIT_EXTERNAL_DIFF \
    GIT_GLOB_PATHSPECS \
    GIT_ICASE_PATHSPECS \
    GIT_INDEX_FILE \
    GIT_LITERAL_PATHSPECS \
    GIT_NAMESPACE \
    GIT_NOGLOB_PATHSPECS \
    GIT_OBJECT_DIRECTORY \
    GIT_OPTIONAL_LOCKS \
    GIT_REPLACE_REF_BASE \
    GIT_WORK_TREE \
    TAR_OPTIONS
  for git_variable in "${!GIT_CONFIG_KEY_@}" "${!GIT_CONFIG_VALUE_@}"; do
    [[ -n "$git_variable" ]] || continue
    unset "$git_variable"
  done
  export GIT_NO_REPLACE_OBJECTS=1
}

assert_verification_tmp_parent_is_trusted() {
  local -r tmp_parent="$VERIFICATION_TMP_PARENT"
  local root_physical=""
  local parent_physical=""
  local root_owner=""
  local root_mode=""
  local parent_owner=""
  local parent_mode=""
  local -i root_mode_bits=0
  local -i parent_mode_bits=0

  [[ "$tmp_parent" == /* ]] || die "verification temporary parent must be absolute"
  [[ -d / && ! -L / ]] || die "verification filesystem root is not a regular directory"
  root_physical="$(cd -- / && pwd -P)" || {
    die "could not resolve the verification filesystem root"
  }
  [[ "$root_physical" == / ]] || die "verification filesystem root must be physical"
  root_owner="$(stat --format=%u -- /)" || {
    die "could not inspect the verification filesystem root owner"
  }
  root_mode="$(stat --format=%a -- /)" || {
    die "could not inspect the verification filesystem root mode"
  }
  [[ "$root_owner" == 0 && "$root_mode" =~ ^[0-7]{3,4}$ ]] || {
    die "verification filesystem root ownership or mode is invalid"
  }
  root_mode_bits=$((8#$root_mode))
  (( (root_mode_bits & 0022) == 0 )) || {
    die "verification filesystem root must not be group or world writable"
  }

  [[ -d "$tmp_parent" && ! -L "$tmp_parent" ]] || {
    die "verification temporary parent is not a regular directory"
  }
  parent_physical="$(cd -- "$tmp_parent" && pwd -P)" || {
    die "could not resolve the verification temporary parent"
  }
  [[ "$parent_physical" == "$tmp_parent" ]] || {
    die "verification temporary parent must be physical"
  }
  parent_owner="$(stat --format=%u -- "$tmp_parent")" || {
    die "could not inspect the verification temporary parent owner"
  }
  parent_mode="$(stat --format=%a -- "$tmp_parent")" || {
    die "could not inspect the verification temporary parent mode"
  }
  [[ "$parent_owner" == 0 && "$parent_mode" =~ ^[0-7]{3,4}$ ]] || {
    die "verification temporary parent ownership or mode is invalid"
  }
  parent_mode_bits=$((8#$parent_mode))
  (( (parent_mode_bits & 01000) != 0 && (parent_mode_bits & 0002) != 0 )) || {
    die "verification temporary parent must be root-owned, sticky, and world writable"
  }
}

assert_private_verification_tmp_dir() {
  local tmp_physical=""
  local owner=""
  local mode=""

  assert_verification_tmp_parent_is_trusted
  [[ "$TMP_DIR" == "$VERIFICATION_TMP_PARENT"/verify-retained-evidence.* && \
    -d "$TMP_DIR" && ! -L "$TMP_DIR" ]] || {
    die "verification temporary directory is unsafe"
  }
  tmp_physical="$(cd -- "$TMP_DIR" && pwd -P)" || {
    die "could not resolve the verification temporary directory"
  }
  [[ "$tmp_physical" == "$TMP_DIR" ]] || {
    die "verification temporary directory must be physical"
  }
  owner="$(stat --format=%u -- "$TMP_DIR")" || {
    die "could not inspect the verification temporary directory owner"
  }
  mode="$(stat --format=%a -- "$TMP_DIR")" || {
    die "could not inspect the verification temporary directory mode"
  }
  [[ "$owner" == "$EUID" && "$mode" == 700 ]] || {
    die "verification temporary directory ownership or mode is invalid"
  }
}

assert_bundle_snapshot_root_has_mode() {
  local -r expected_mode="$1"
  local snapshot_physical=""
  local snapshot_owner=""
  local snapshot_mode=""

  assert_private_verification_tmp_dir
  [[ "$BUNDLE_SNAPSHOT_ROOT" == "$TMP_DIR"/archive.* && \
    -d "$BUNDLE_SNAPSHOT_ROOT" && ! -L "$BUNDLE_SNAPSHOT_ROOT" ]] || {
    die "verification archive snapshot is unsafe"
  }
  snapshot_physical="$(cd -- "$BUNDLE_SNAPSHOT_ROOT" && pwd -P)" || {
    die "could not resolve the verification archive snapshot"
  }
  [[ "$snapshot_physical" == "$BUNDLE_SNAPSHOT_ROOT" ]] || {
    die "verification archive snapshot must be physical"
  }
  snapshot_owner="$(stat --format=%u -- "$BUNDLE_SNAPSHOT_ROOT")" || {
    die "could not inspect the verification archive snapshot owner"
  }
  snapshot_mode="$(stat --format=%a -- "$BUNDLE_SNAPSHOT_ROOT")" || {
    die "could not inspect the verification archive snapshot mode"
  }
  [[ "$expected_mode" =~ ^[0-7]{3,4}$ && "$snapshot_owner" == "$EUID" && \
    "$snapshot_mode" == "$expected_mode" ]] || {
    die "verification archive snapshot ownership or mode is invalid"
  }
}

assert_sealed_bundle_snapshot_is_private() {
  local bundle_physical=""

  assert_bundle_snapshot_root_has_mode 500
  [[ "$BUNDLE_DIR" == "$BUNDLE_SNAPSHOT_ROOT/"* && \
    -d "$BUNDLE_DIR" && ! -L "$BUNDLE_DIR" ]] || {
    die "verification bundle snapshot is unsafe"
  }
  bundle_physical="$(cd -- "$BUNDLE_DIR" && pwd -P)" || {
    die "could not resolve the verification bundle snapshot"
  }
  [[ "$bundle_physical" == "$BUNDLE_DIR" ]] || {
    die "verification bundle snapshot must be physical"
  }
}

seal_bundle_snapshot() {
  assert_bundle_snapshot_root_has_mode 700
  find -- "$BUNDLE_SNAPSHOT_ROOT" -type f -exec chmod a-w -- {} + || {
    die "could not seal verification archive files"
  }
  find -- "$BUNDLE_SNAPSHOT_ROOT" -type d -exec chmod a-w -- {} + || {
    die "could not seal verification archive directories"
  }
  assert_sealed_bundle_snapshot_is_private
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
  local first=""
  local second=""
  local status=0

  [[ -n "$path" && -n "$expected_identity" &&
    "$path" == "$VERIFICATION_TMP_PARENT"/verify-retained-evidence.* &&
    -d "$path" && ! -L "$path" ]] || return 1
  observed_identity="$(stat -Lc '%d:%i:%u' -- "$path")" || return 1
  [[ "$observed_identity" == "$expected_identity" ]] || return 1
  root_device="${expected_identity%%:*}"
  first="$(mktemp "$VERIFICATION_TMP_PARENT/.verify-cleanup-directories.XXXXXX")" ||
    return 1
  second="$(mktemp "$VERIFICATION_TMP_PARENT/.verify-cleanup-directories.XXXXXX")" || {
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

  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" && ! -L "$TMP_DIR" ]]; then
    cleanup_owned_directory "$TMP_DIR" "$TMP_DIR_IDENTITY" || status=1
  elif [[ -n "${TMP_DIR:-}" && ( -e "$TMP_DIR" || -L "$TMP_DIR" ) ]]; then
    status=1
  fi
  if ((status != 0)); then
    printf '%s: private verification cleanup was incomplete\n' \
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

trap cleanup_on_exit EXIT

check_dependencies() {
  local -a missing=()
  local command_name=""

  for command_name in awk chmod cmp cp cut find git grep jq mkdir mktemp \
    mountpoint readlink rm sha256sum sort stat tail tar tr; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    die "missing required commands: ${missing[*]}"
  fi
}

is_sha1() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

is_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

is_safe_relative_path() {
  local -r path="$1"
  local remainder="$path"
  local component=""

  [[ -n "$path" && "$path" != /* && "$path" != */ && "$path" != *'//' ]] || return 1
  while true; do
    if [[ "$remainder" == */* ]]; then
      component="${remainder%%/*}"
      remainder="${remainder#*/}"
    else
      component="$remainder"
      remainder=""
    fi
    [[ -n "$component" && "$component" != "." && "$component" != ".." && \
      "$component" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    [[ -n "$remainder" ]] || return 0
  done
}

is_runtime_private_retained_path() {
  local -r relative_path="$1"

  # Every hidden path used by the producer is private transaction state or
  # scratch space. A checksum entry cannot turn stranded state into retained
  # evidence. The root boundary-index freeze is the sole published exception.
  [[ "$relative_path" == .obi-metric-boundary-index.freeze ]] && return 1
  if [[ "$VERIFICATION_MODE" == raw-v3 ]]; then
    case "$relative_path" in
      .terminal-java-diagnostics.lock|\
      .terminal-java-diagnostics-transition.lock|\
      .terminal-java-diagnostics.freeze|\
      .last-valid-java-diagnostics.json)
        return 1
        ;;
    esac
  fi
  [[ "$relative_path" == .* || "$relative_path" == */.* ]]
}

reset_reference_validation_caches() {
  VERIFIED_REFERENCE_SHA256=()
  VALIDATED_JAVA_DIAGNOSTICS_REFERENCES=()
  VALIDATED_OBI_IDENTITY_REFERENCES=()
  VALIDATED_OBI_PAIR_REFERENCES=()
  VALIDATED_OBI_UNAVAILABLE_REFERENCES=()
  VALIDATED_STATUS_REFERENCES=()
  PARSED_OBI_METRIC_REFERENCES=()
  OBI_IDENTITY_STATE=()
  OBI_IDENTITY_CONTAINER_ID=()
  OBI_IDENTITY_STARTED_AT=()
  OBI_IDENTITY_METRICS_REFERENCE=()
}

verify_reference_sha256() {
  local -r reference="$1"
  local -r expected_digest="$2"
  local observed_digest=""

  is_safe_relative_path "$reference" || return 1
  is_sha256 "$expected_digest" || return 1
  [[ -f "$BUNDLE_DIR/$reference" && ! -L "$BUNDLE_DIR/$reference" ]] || return 1
  if [[ -n "${VERIFIED_REFERENCE_SHA256[$reference]+present}" ]]; then
    [[ "${VERIFIED_REFERENCE_SHA256[$reference]}" == "$expected_digest" ]]
    return
  fi
  observed_digest="$(sha256sum "$BUNDLE_DIR/$reference")" || return 1
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$expected_digest" ]] || return 1
  VERIFIED_REFERENCE_SHA256["$reference"]="$observed_digest"
}

require_regular_file() {
  local -r relative_path="$1"
  local -r path="$BUNDLE_DIR/$relative_path"

  assert_sealed_bundle_snapshot_is_private
  [[ -f "$path" && ! -L "$path" ]] || {
    die "required regular file is missing: $relative_path"
  }
}

resolve_trusted_repository() {
  local trusted_repo_root=""

  trusted_repo_root="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)" || {
    die "the verifier must run from a Git checkout"
  }
  TRUSTED_REPO_ROOT="$(cd -- "$trusted_repo_root" && pwd -P)" || {
    die "could not resolve the verifier Git checkout"
  }
  TRUSTED_HEAD="$(git -C "$TRUSTED_REPO_ROOT" rev-parse --verify --quiet 'HEAD^{commit}')" || {
    die "the verifier Git checkout does not have a HEAD commit"
  }
}

validate_tracked_bundle_archive_budget() {
  local -r relative_path="$1"
  local tree_manifest="$TMP_DIR/tracked-bundle-tree"
  local entry=""
  local metadata=""
  local entry_path=""
  local bundle_relative_path=""
  local mode=""
  local object_type=""
  local object_id=""
  local size=""
  local extra=""
  local remaining_bytes=""
  local size_comparison=""
  local -i file_count=0
  local -i total_bytes=0

  git -C "$REPO_ROOT" ls-tree -lr -z --long \
    "$TRUSTED_HEAD" -- "$relative_path" >"$tree_manifest" || return 1
  while IFS= read -r -d '' entry; do
    [[ "$entry" == *$'\t'* ]] || return 1
    metadata="${entry%%$'\t'*}"
    entry_path="${entry#*$'\t'}"
    mode=""
    object_type=""
    object_id=""
    size=""
    extra=""
    read -r mode object_type object_id size extra <<<"$metadata"
    [[ -z "$extra" && ( "$mode" == 100644 || "$mode" == 100755 ) &&
      "$object_type" == blob ]] || return 1
    is_sha1 "$object_id" || return 1
    [[ "$entry_path" == "$relative_path/"* ]] || return 1
    bundle_relative_path="${entry_path#"$relative_path"/}"
    is_safe_relative_path "$bundle_relative_path" || return 1
    ! is_runtime_private_retained_path "$bundle_relative_path" || return 1
    canonical_uint64_string "$size" || return 1
    ((file_count < BUNDLE_ARCHIVE_MAX_FILES)) || return 1
    file_count=$((file_count + 1))
    remaining_bytes="$((BUNDLE_ARCHIVE_MAX_BYTES - total_bytes))"
    uint64_string_compare "$size" "$remaining_bytes" size_comparison || return 1
    [[ "$size_comparison" != 1 ]] || return 1
    total_bytes=$((total_bytes + size))
  done <"$tree_manifest"
  ((file_count > 0))
}

snapshot_bundle() {
  local -r source_directory="$1"
  local source_repo_root=""
  local relative_path=""
  local snapshot_parent=""

  source_repo_root="$(git -C "$source_directory" rev-parse --show-toplevel)" || {
    die "bundle must be in the verifier Git checkout"
  }
  REPO_ROOT="$(cd -- "$source_repo_root" && pwd -P)" || {
    die "could not resolve the bundle Git checkout"
  }
  [[ "$REPO_ROOT" == "$TRUSTED_REPO_ROOT" ]] || {
    die "bundle must be in the verifier Git checkout"
  }
  [[ "$source_directory" != "$REPO_ROOT" && "$source_directory" == "$REPO_ROOT/"* ]] || {
    die "bundle directory must be below the Git checkout root"
  }
  relative_path="${source_directory#"$REPO_ROOT"/}"
  is_safe_relative_path "$relative_path" || {
    die "bundle path is not safe"
  }
  [[ "$relative_path" == "examples/apache-java-https/evidence/$BUNDLE_NAME" ]] || {
    die "bundle must be a published evidence directory"
  }
  git -C "$REPO_ROOT" cat-file -e "$TRUSTED_HEAD:$relative_path/SHA256SUMS" || {
    die "bundle is not tracked in the verifier Git checkout HEAD"
  }
  verify_bundle_worktree_matches_pinned_head "$relative_path"

  assert_private_verification_tmp_dir
  validate_tracked_bundle_archive_budget "$relative_path" || {
    die "tracked bundle exceeds the safe archive budget or has unsupported entries"
  }
  snapshot_parent="$(mktemp -d "$TMP_DIR/archive.XXXXXX")" || {
    die "could not create the private verification archive directory"
  }
  BUNDLE_SNAPSHOT_ROOT="$snapshot_parent"
  assert_bundle_snapshot_root_has_mode 700
  if ! git -C "$REPO_ROOT" archive --format=tar "$TRUSTED_HEAD" -- "$relative_path" |
    (
      cd -- "$snapshot_parent" || exit 1
      exec tar -xf -
    ); then
    die "could not archive the tracked evidence bundle"
  fi
  BUNDLE_DIR="$snapshot_parent/$relative_path"
  [[ -d "$BUNDLE_DIR" && ! -L "$BUNDLE_DIR" ]] || {
    die "tracked evidence bundle is missing or a symbolic link"
  }
  seal_bundle_snapshot
}

validate_external_bundle_budget() {
  local -r source_directory="$1"
  local -r maximum_files="$2"
  local -r maximum_bytes="$3"
  local -r required_file_mode="${4:-}"
  local -r required_directory_mode="${5:-}"
  local effective_file_mode="$required_file_mode"
  local effective_directory_mode="$required_directory_mode"
  local path=""
  local relative_path=""
  local size=""
  local remaining_bytes=""
  local comparison=""
  local owner=""
  local mode=""
  local links=""
  local root_device=""
  local device=""
  local entries=""
  local -i mode_bits=0
  local -i directory_count=0
  local -i file_count=0
  local -i total_bytes=0

  [[ "$source_directory" == /* && "$source_directory" != */ &&
    -d "$source_directory" && ! -L "$source_directory" ]] || return 1
  [[ "$(cd -- "$source_directory" && pwd -P)" == "$source_directory" ]] || return 1
  root_device="$(stat -Lc '%d' -- "$source_directory")" || return 1
  [[ "$root_device" =~ ^[0-9]+$ ]] || return 1
  owner="$(stat -Lc '%u' -- "$source_directory")" || return 1
  mode="$(stat -Lc '%a' -- "$source_directory")" || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  if [[ "$VERIFICATION_MODE" == raw-v3 ]]; then
    [[ "$owner" == "$EUID" || "$owner" == 0 ]] || return 1
  else
    [[ "$owner" == "$EUID" ]] || return 1
  fi
  if [[ "$VERIFICATION_MODE" == claims-v1 ]]; then
    case "$mode" in
      555)
        effective_file_mode=444
        effective_directory_mode=555
        ;;
      755)
        effective_file_mode=644
        effective_directory_mode=755
        ;;
      *) return 1 ;;
    esac
  fi
  [[ -z "$effective_directory_mode" ||
    "$mode" == "$effective_directory_mode" ]] || return 1
  mode_bits=$((8#$mode))
  (( (mode_bits & 0022) == 0 )) || return 1

  entries="$(mktemp "$TMP_DIR/external-budget-entries.XXXXXX")" || return 1
  if ! find -- "$source_directory" -xdev -mindepth 1 -print0 |
    LC_ALL=C sort -z >"$entries"; then
    return 1
  fi
  while IFS= read -r -d '' path; do
    relative_path="${path#"$source_directory"/}"
    is_safe_relative_path "$relative_path" || return 1
    [[ ! -L "$path" ]] || return 1
    device="$(stat -Lc '%d' -- "$path")" || return 1
    [[ "$device" == "$root_device" ]] || return 1
    owner="$(stat -Lc '%u' -- "$path")" || return 1
    mode="$(stat -Lc '%a' -- "$path")" || return 1
    links="$(stat -Lc '%h' -- "$path")" || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ && "$links" =~ ^[1-9][0-9]*$ ]] || return 1
    if [[ "$VERIFICATION_MODE" == raw-v3 ]]; then
      [[ "$owner" == "$EUID" || "$owner" == 0 ]] || return 1
    else
      [[ "$owner" == "$EUID" ]] || return 1
    fi
    mode_bits=$((8#$mode))
    (( (mode_bits & 0022) == 0 )) || return 1
    if [[ -d "$path" ]]; then
      [[ -z "$effective_directory_mode" ||
        "$mode" == "$effective_directory_mode" ]] || return 1
      ((directory_count < maximum_files)) || return 1
      directory_count=$((directory_count + 1))
      [[ -n "$(find -- "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        return 1
      continue
    fi
    [[ -f "$path" && "$links" == 1 ]] || return 1
    [[ -z "$effective_file_mode" || "$mode" == "$effective_file_mode" ]] ||
      return 1
    size="$(stat -Lc '%s' -- "$path")" || return 1
    canonical_uint64_string "$size" || return 1
    ((file_count < maximum_files)) || return 1
    file_count=$((file_count + 1))
    remaining_bytes="$((maximum_bytes - total_bytes))"
    uint64_string_compare "$size" "$remaining_bytes" comparison || return 1
    [[ "$comparison" != 1 ]] || return 1
    total_bytes=$((total_bytes + size))
  done <"$entries"
  rm -f -- "$entries" || return 1
  ((file_count > 0))
}

write_external_bundle_manifest() {
  local -r source_directory="$1"
  local -r output="$2"
  local path=""
  local relative_path=""
  local identity=""
  local digest=""
  local root_device=""
  local device=""
  local entries=""

  : >"$output"
  root_device="$(stat -Lc '%d' -- "$source_directory")" || return 1
  [[ "$root_device" =~ ^[0-9]+$ ]] || return 1
  entries="$(mktemp "$TMP_DIR/external-manifest-entries.XXXXXX")" || return 1
  if ! find -- "$source_directory" -xdev -mindepth 1 -type f -print0 |
    LC_ALL=C sort -z >"$entries"; then
    return 1
  fi
  while IFS= read -r -d '' path; do
    [[ -f "$path" && ! -L "$path" ]] || continue
    device="$(stat -Lc '%d' -- "$path")" || return 1
    [[ "$device" == "$root_device" ]] || return 1
    relative_path="${path#"$source_directory"/}"
    is_safe_relative_path "$relative_path" || return 1
    identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" || return 1
    digest="$(sha256sum <"$path")" || return 1
    digest="${digest%% *}"
    is_sha256 "$digest" || return 1
    printf '%s\t%s\t%s\n' "$relative_path" "$identity" "$digest" >>"$output" ||
      return 1
  done <"$entries"
  rm -f -- "$entries"
}

copy_external_bundle_file_by_descriptor() {
  local -r source_directory="$1"
  local -r destination_directory="$2"
  local -r relative_path="$3"
  local -r expected_identity="$4"
  local -r expected_digest="$5"
  local source_path="$source_directory/$relative_path"
  local destination_path="$destination_directory/$relative_path"
  local descriptor_path=""
  local path_identity=""
  local descriptor_identity=""
  local destination_digest=""
  local descriptor_digest=""
  local source_fd=""

  [[ -f "$source_path" && ! -L "$source_path" && ! -e "$destination_path" &&
    ! -L "$destination_path" ]] || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source_path")" || return 1
  [[ "$path_identity" == "$expected_identity" ]] || return 1
  exec {source_fd}<"$source_path" || return $?
  descriptor_path="/proc/$BASHPID/fd/$source_fd"
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  [[ "$descriptor_identity" == "$expected_identity" ]] || {
    exec {source_fd}<&-
    return 1
  }
  descriptor_digest="$(sha256sum <"$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  descriptor_digest="${descriptor_digest%% *}"
  [[ "$descriptor_digest" == "$expected_digest" ]] || {
    exec {source_fd}<&-
    return 1
  }
  mkdir -p -- "${destination_path%/*}" || {
    exec {source_fd}<&-
    return 1
  }
  if ! cp -- "$descriptor_path" "$destination_path"; then
    exec {source_fd}<&-
    return 1
  fi
  destination_digest="$(sha256sum <"$destination_path")" || {
    exec {source_fd}<&-
    return 1
  }
  destination_digest="${destination_digest%% *}"
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  descriptor_digest="$(sha256sum <"$descriptor_path")" || {
    exec {source_fd}<&-
    return 1
  }
  descriptor_digest="${descriptor_digest%% *}"
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source_path")" || {
    exec {source_fd}<&-
    return 1
  }
  exec {source_fd}<&-
  [[ "$destination_digest" == "$expected_digest" &&
    "$descriptor_digest" == "$expected_digest" &&
    "$descriptor_identity" == "$expected_identity" &&
    "$path_identity" == "$expected_identity" ]]
}

snapshot_external_bundle() {
  local -r source_directory="$1"
  local -r maximum_files="$2"
  local -r maximum_bytes="$3"
  local -r required_file_mode="${4:-}"
  local -r required_directory_mode="${5:-}"
  local before_manifest="$TMP_DIR/external-before.manifest"
  local after_manifest="$TMP_DIR/external-after.manifest"
  local snapshot_parent=""
  local relative_path=""
  local identity=""
  local digest=""
  local root_identity=""

  root_identity="$(stat -Lc '%d:%i:%u:%a' -- "$source_directory")" ||
    die "could not pin the external evidence root"
  [[ -d "$source_directory" && ! -L "$source_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$source_directory")" == "$root_identity" ]] ||
    die "external evidence root is not stable"
  validate_external_bundle_budget \
    "$source_directory" "$maximum_files" "$maximum_bytes" \
    "$required_file_mode" "$required_directory_mode" || {
    die "external evidence exceeds its archive budget or has unsafe entries"
  }
  [[ -d "$source_directory" && ! -L "$source_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$source_directory")" == "$root_identity" ]] ||
    die "external evidence root changed during preflight"
  write_external_bundle_manifest "$source_directory" "$before_manifest" || {
    die "could not freeze the external evidence manifest"
  }
  [[ -d "$source_directory" && ! -L "$source_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$source_directory")" == "$root_identity" ]] ||
    die "external evidence root changed while freezing"
  snapshot_parent="$(mktemp -d "$TMP_DIR/archive.XXXXXX")" || {
    die "could not create the private external-evidence archive"
  }
  BUNDLE_SNAPSHOT_ROOT="$snapshot_parent"
  if [[ "$VERIFICATION_MODE" == claims-v1 ]]; then
    BUNDLE_DIR="$snapshot_parent/$BUNDLE_NAME"
  else
    BUNDLE_DIR="$snapshot_parent/bundle"
  fi
  mkdir -m 0700 -- "$BUNDLE_DIR" || die "could not create the evidence snapshot"
  while IFS=$'\t' read -r relative_path identity digest; do
    [[ -n "$relative_path" && -n "$identity" && -n "$digest" ]] || {
      die "external evidence manifest is malformed"
    }
    copy_external_bundle_file_by_descriptor \
      "$source_directory" "$BUNDLE_DIR" "$relative_path" "$identity" "$digest" || {
      die "external evidence changed while being snapshotted: $relative_path"
    }
    if [[ -n "$required_file_mode" ]]; then
      chmod "$required_file_mode" -- "$BUNDLE_DIR/$relative_path" || {
        die "could not preserve the projected evidence file mode: $relative_path"
      }
    fi
  done <"$before_manifest"
  [[ -d "$source_directory" && ! -L "$source_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$source_directory")" == "$root_identity" ]] ||
    die "external evidence root changed during pinned copy"
  write_external_bundle_manifest "$source_directory" "$after_manifest" || {
    die "could not recheck the external evidence manifest"
  }
  validate_external_bundle_budget \
    "$source_directory" "$maximum_files" "$maximum_bytes" \
    "$required_file_mode" "$required_directory_mode" || {
    die "external evidence changed to an unsafe or oversized layout"
  }
  cmp -s -- "$before_manifest" "$after_manifest" || {
    die "external evidence changed while being snapshotted"
  }
  [[ -d "$source_directory" && ! -L "$source_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$source_directory")" == "$root_identity" ]] ||
    die "external evidence root changed after pinned copy"
  seal_bundle_snapshot
}

verify_bundle_worktree_matches_pinned_head() {
  local -r relative_path="$1"
  local extra_paths=""

  if ! git -C "$REPO_ROOT" diff --quiet "$TRUSTED_HEAD" -- "$relative_path"; then
    die "bundle working-tree content differs from the captured HEAD commit"
  fi
  extra_paths="$(git -C "$REPO_ROOT" ls-files --others --exclude-standard -- "$relative_path")" || {
    die "could not inspect untracked bundle files"
  }
  [[ -z "$extra_paths" ]] || {
    die "bundle contains untracked or ignored working-tree files"
  }
  extra_paths="$(git -C "$REPO_ROOT" ls-files --others --ignored --exclude-standard -- "$relative_path")" || {
    die "could not inspect ignored bundle files"
  }
  [[ -z "$extra_paths" ]] || {
    die "bundle contains untracked or ignored working-tree files"
  }
}

validate_bundle_file_types() {
  local path=""
  local relative_path=""

  assert_sealed_bundle_snapshot_is_private
  if [[ -n "$(find -- "$BUNDLE_DIR" -type l -print -quit)" ]]; then
    die "bundle must not contain symbolic links"
  fi
  if [[ -n "$(find -- "$BUNDLE_DIR" -mindepth 1 ! -type d ! -type f -print -quit)" ]]; then
    die "bundle must contain only regular files and directories"
  fi
  while IFS= read -r -d '' path; do
    relative_path="${path#"$BUNDLE_DIR"/}"
    is_safe_relative_path "$relative_path" || {
      die "bundle contains an unsafe path"
    }
    ! is_runtime_private_retained_path "$relative_path" || {
      die "bundle contains a runtime-private publication path: $relative_path"
    }
  done < <(find -- "$BUNDLE_DIR" -mindepth 1 -print0)
}

validate_checksum_manifest() {
  local -r manifest="$BUNDLE_DIR/SHA256SUMS"
  local line=""
  local relative_path=""
  local -a declared_paths=()
  declare -A seen_paths=()

  assert_sealed_bundle_snapshot_is_private
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" != *$'\r'* && "$line" =~ ^[0-9a-f]{64}\ \ \./.+$ ]] || {
      die "checksum manifest contains an invalid entry"
    }
    relative_path="${line:68}"
    is_safe_relative_path "$relative_path" || {
      die "checksum manifest contains an unsafe path"
    }
    [[ "$relative_path" != "SHA256SUMS" ]] || {
      die "checksum manifest must not include itself"
    }
    [[ -z "${seen_paths[$relative_path]:-}" ]] || {
      die "checksum manifest contains a duplicate path"
    }
    seen_paths["$relative_path"]=1
    [[ -f "$BUNDLE_DIR/$relative_path" && ! -L "$BUNDLE_DIR/$relative_path" ]] || {
      die "checksum manifest references a missing regular file"
    }
    declared_paths+=("$relative_path")
  done <"$manifest"

  (( ${#declared_paths[@]} > 0 )) || die "checksum manifest is empty"
  printf '%s\n' "${declared_paths[@]}" >"$TMP_DIR/declared-paths.original"
  LC_ALL=C sort -- "$TMP_DIR/declared-paths.original" \
    >"$TMP_DIR/declared-paths"
  cmp -s -- "$TMP_DIR/declared-paths.original" "$TMP_DIR/declared-paths" || {
    die "checksum manifest entries are not in canonical path order"
  }
  (
    cd -- "$BUNDLE_DIR"
    find . -type f ! -path './SHA256SUMS' -printf '%P\n' | LC_ALL=C sort \
      >"$TMP_DIR/actual-paths"
  )
  cmp -s "$TMP_DIR/declared-paths" "$TMP_DIR/actual-paths" || {
    die "checksum manifest does not cover the exact bundle file set"
  }
  (
    cd -- "$BUNDLE_DIR"
    sha256sum --check --strict --status SHA256SUMS
  ) || die "checksum manifest verification failed"
}

validate_key_value_file() {
  local -r file="$1"
  local line=""
  local key=""
  local value=""
  local -i line_count=0
  declare -A seen_keys=()

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" != *$'\r'* && "$line" == *=* ]] || return 1
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$key" =~ ^[a-z][a-z0-9_]*$ && -n "$value" ]] || return 1
    [[ -z "${seen_keys[$key]:-}" ]] || return 1
    seen_keys["$key"]=1
    ((line_count += 1))
  done <"$file"
  ((line_count > 0))
}

key_value() {
  local -r file="$1"
  local -r expected_key="$2"
  local line=""
  local key=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    key="${line%%=*}"
    if [[ "$key" == "$expected_key" ]]; then
      printf '%s\n' "${line#*=}"
      return 0
    fi
  done <"$file"
  return 1
}

read_single_hex() {
  local -r file="$1"
  local -r width="$2"
  local -a lines=()

  mapfile -t lines <"$file"
  [[ ${#lines[@]} == 1 && "$(stat -Lc '%s' -- "$file")" == "$((width + 1))" ]] ||
    return 1
  case "$width" in
    40) is_sha1 "${lines[0]}" ;;
    64) is_sha256 "${lines[0]}" ;;
    *) return 1 ;;
  esac || return 1
  printf '%s\n' "${lines[0]}"
}

validate_canonical_key_value_order() {
  local -r file="$1"
  shift
  local -a lines=()
  local -a expected_keys=("$@")
  local -i index=0

  validate_key_value_file "$file" || return 1
  [[ -s "$file" && -z "$(tail -c 1 -- "$file")" ]] || return 1
  mapfile -t lines <"$file" || return 1
  ((${#lines[@]} == ${#expected_keys[@]})) || return 1
  for ((index = 0; index < ${#expected_keys[@]}; index++)); do
    [[ "${lines[index]}" == "${expected_keys[index]}="* &&
      "${lines[index]}" != "${expected_keys[index]}=" ]] || return 1
  done
}

uses_historical_run_status_schema() {
  local -r evidence_id="$1"
  local -r revision="$2"

  case "$evidence_id:$revision" in
    otel-getsockopt-tls12-c7209e43:c7209e4306694ed2f6fe4d2bb813d7b632915dd2|\
    otel-getsockopt-tls13-7482d908:7482d90807afd849575a8f8dda67e255daf0680d|\
    otel-getsockopt-tls13-94221a91:94221a9127553adb233a7560baa6f2a327c558b8|\
    otel-getsockopt-tls13-c9d14356:c9d14356ce5b1aadd72a2e21f4212971d7c32584|\
    otel-unix-tls12-acedb68a:acedb68a01e5e3a5205ca1a462c345ecb184e5e7|\
    otel-unix-tls12-bd1c9327:bd1c932791791b910bba071e912de9455169c69d|\
    splunk-getsockopt-tls13-47237792:472377929106fa57c1575ab0942984d5d499b731)
      return 0
      ;;
  esac
  return 1
}

uses_pre_v2_run_status_schema() {
  local -r evidence_id="$1"
  local -r revision="$2"

  # Keep this complete schema-transition allowlist independent from the older
  # seven-bundle exceptions used by other provenance rules below.
  case "$evidence_id:$revision" in
    otel-getsockopt-tls12-c7209e43:c7209e4306694ed2f6fe4d2bb813d7b632915dd2|\
    otel-getsockopt-tls13-74576ec6:74576ec657056dc3f63cb90f4c95f6f362a2dd39|\
    otel-getsockopt-tls13-7482d908:7482d90807afd849575a8f8dda67e255daf0680d|\
    otel-getsockopt-tls13-8282d2ed:8282d2ed9c3a3f6925902cd84f11f491bc4f4565|\
    otel-getsockopt-tls13-94221a91:94221a9127553adb233a7560baa6f2a327c558b8|\
    otel-getsockopt-tls13-b678ce1e:b678ce1e2415906d45df3bf0728e7ed9e92c52c9|\
    otel-getsockopt-tls13-c9d14356:c9d14356ce5b1aadd72a2e21f4212971d7c32584|\
    otel-getsockopt-tls13-e8db066a:e8db066ac36748f17d8debd9098e9d1ddba67067|\
    otel-unix-tls12-acedb68a:acedb68a01e5e3a5205ca1a462c345ecb184e5e7|\
    otel-unix-tls12-bd1c9327:bd1c932791791b910bba071e912de9455169c69d|\
    otel-unix-tls13-6c4a2505:6c4a2505b6a6d4e89d3aedd9952097ad42ce1457|\
    splunk-getsockopt-tls13-47237792:472377929106fa57c1575ab0942984d5d499b731)
      return 0
      ;;
  esac
  return 1
}

uses_legacy_environment_schema() {
  local -r evidence_id="$1"
  local -r revision="$2"

  case "$evidence_id:$revision" in
    otel-getsockopt-tls12-c7209e43:c7209e4306694ed2f6fe4d2bb813d7b632915dd2|\
    otel-unix-tls12-bd1c9327:bd1c932791791b910bba071e912de9455169c69d|\
    splunk-getsockopt-tls13-47237792:472377929106fa57c1575ab0942984d5d499b731)
      return 0
      ;;
  esac
  return 1
}

uses_historical_source_tree_manifest_schema() {
  uses_historical_run_status_schema "$1" "$2"
}

allows_missing_git_status_record() {
  local -r evidence_id="$1"
  local -r revision="$2"

  case "$evidence_id:$revision" in
    otel-getsockopt-tls12-c7209e43:c7209e4306694ed2f6fe4d2bb813d7b632915dd2|\
    splunk-getsockopt-tls13-47237792:472377929106fa57c1575ab0942984d5d499b731)
      return 0
      ;;
  esac
  return 1
}

validate_acceptance_environment() {
  local -r environment="$1"
  local -r allow_legacy_schema="$2"
  local request_count=""
  local bridge_build_mode=""
  local reason=""

  if request_count="$(key_value "$environment" request_count)"; then
    [[ "$request_count" == "0" ]] || {
      die "retained result used a custom request count"
    }
  elif [[ "$allow_legacy_schema" != "true" ]]; then
    die "retained environment lacks request-count eligibility evidence"
  fi
  if bridge_build_mode="$(key_value "$environment" bridge_build_mode)"; then
    [[ "$bridge_build_mode" == "fresh" ]] || {
      die "retained result reused bridge artifacts"
    }
  elif [[ "$allow_legacy_schema" != "true" ]]; then
    die "retained environment lacks fresh-build eligibility evidence"
  fi
  if reason="$(key_value "$environment" acceptance_evidence_reason)"; then
    [[ "$reason" == "none" ]] || {
      die "retained environment has an ineligible reason"
    }
  elif [[ "$allow_legacy_schema" != "true" ]]; then
    die "retained environment lacks an eligibility reason"
  fi
}

validate_source_tree_manifest_schema() {
  local -r environment="$1"
  local -r source_state="$2"
  local -r allow_historical_schema="$3"
  local environment_schema=""
  local source_state_schema=""

  if [[ "$allow_historical_schema" == "true" ]]; then
    if environment_schema="$(key_value "$environment" source_tree_manifest_schema)" || \
      source_state_schema="$(key_value "$source_state" source_tree_manifest_schema)"; then
      die "historical retained evidence must not claim a source-tree schema"
    fi
    return 0
  fi
  environment_schema="$(key_value "$environment" source_tree_manifest_schema)" || {
    die "environment evidence lacks the source-tree schema"
  }
  source_state_schema="$(key_value "$source_state" source_tree_manifest_schema)" || {
    die "source state lacks the source-tree schema"
  }
  [[ "$environment_schema" == "git-tree-v2" && \
    "$source_state_schema" == "git-tree-v2" ]] || {
    die "retained source-tree schema is not canonical Git-tree v2"
  }
}

write_source_tree_manifest_for_revision() {
  local -r revision="$1"
  local -r output="$2"
  local entries=""
  local entry=""
  local metadata=""
  local path=""
  local mode=""
  local object_id=""
  local executable=""

  git -C "$REPO_ROOT" cat-file -e "${revision}^{commit}" || return 1
  entries="$TMP_DIR/source-tree-entries"
  git -C "$REPO_ROOT" ls-tree -r -z --full-tree "$revision" >"$entries" || return 1
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    case "$mode" in
      100644) executable='-' ;;
      100755) executable='x' ;;
      120000) executable='l' ;;
      160000) executable='g' ;;
      *) return 1 ;;
    esac
    is_sha1 "$object_id" || return 1
    LC_ALL=C printf '%s %s %q\n' "$object_id" "$executable" "$path"
  done <"$entries" >"$output"
}

validate_clean_source_metadata() {
  local -r environment="$1"
  local -r source_state="$2"
  local -r allow_legacy_schema="$3"
  local source_state_patch_sha256=""
  local environment_patch_sha256=""

  source_state_patch_sha256="$(key_value "$source_state" tracked_patch_sha256)" || {
    die "source state lacks the tracked-patch digest"
  }
  [[ "$source_state_patch_sha256" == "$EMPTY_SHA256" ]] || {
    die "source state has a tracked patch"
  }
  if environment_patch_sha256="$(key_value "$environment" tracked_patch_sha256)"; then
    [[ "$environment_patch_sha256" == "$EMPTY_SHA256" ]] || {
      die "environment evidence has a tracked patch"
    }
  elif [[ "$allow_legacy_schema" != "true" ]]; then
    die "environment evidence lacks the tracked-patch digest"
  fi
}

validate_bounded_regular_file() {
  local -r relative_path="$1"
  local -r maximum_bytes="$2"
  local -r maximum_lines="${3:-0}"
  local -r path="$BUNDLE_DIR/$relative_path"
  local size=""
  local line_count=""

  is_safe_relative_path "$relative_path" || return 1
  [[ "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$maximum_lines" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  require_regular_file "$relative_path"
  size="$(stat -Lc '%s' -- "$path")" || return 1
  ((size > 0 && size <= maximum_bytes)) || return 1
  if ((maximum_lines > 0)); then
    line_count="$(awk 'END { print NR }' "$path")" || return 1
    [[ "$line_count" =~ ^[0-9]+$ ]] || return 1
    ((line_count > 0 && line_count <= maximum_lines)) || return 1
  fi
}

validate_bounded_regular_file_allow_empty() {
  local -r relative_path="$1"
  local -r maximum_bytes="$2"
  local -r maximum_lines="${3:-0}"
  local -r path="$BUNDLE_DIR/$relative_path"
  local size=""
  local line_count=""

  is_safe_relative_path "$relative_path" || return 1
  [[ "$maximum_bytes" =~ ^[1-9][0-9]*$ &&
    "$maximum_lines" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  require_regular_file "$relative_path"
  size="$(stat -Lc '%s' -- "$path")" || return 1
  [[ "$size" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  ((size <= maximum_bytes)) || return 1
  if ((maximum_lines > 0)); then
    line_count="$(awk 'END { print NR + 0 }' "$path")" || return 1
    [[ "$line_count" =~ ^[0-9]+$ ]] || return 1
    ((line_count <= maximum_lines)) || return 1
  fi
}

validate_single_json_object() {
  local -r relative_path="$1"
  local -r maximum_bytes="$2"

  validate_bounded_regular_file "$relative_path" "$maximum_bytes" || return 1
  jq -e -s 'length == 1 and (.[0] | type == "object")' \
    "$BUNDLE_DIR/$relative_path" >/dev/null
}

canonical_uint64_string() {
  local -r value="$1"
  local LC_ALL=C

  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  # Equal-width canonical decimal strings compare safely without arithmetic.
  # shellcheck disable=SC2071
  if (( ${#value} > ${#MAX_UINT64_DECIMAL} )) ||
    { (( ${#value} == ${#MAX_UINT64_DECIMAL} )) &&
      [[ "$value" > "$MAX_UINT64_DECIMAL" ]]; }; then
    return 1
  fi
}

uint64_string_compare() {
  local -r left="$1"
  local -r right="$2"
  local -r output_name="$3"
  local comparison_result=""
  local LC_ALL=C

  canonical_uint64_string "$left" || return 1
  canonical_uint64_string "$right" || return 1
  [[ "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || return 1
  # Equal-width canonical decimal strings compare safely without arithmetic.
  # shellcheck disable=SC2071
  if (( ${#left} < ${#right} )); then
    comparison_result=-1
  elif (( ${#left} > ${#right} )); then
    comparison_result=1
  elif [[ "$left" == "$right" ]]; then
    comparison_result=0
  elif [[ "$left" < "$right" ]]; then
    comparison_result=-1
  else
    comparison_result=1
  fi
  printf -v "$output_name" '%s' "$comparison_result"
}

uint64_string_subtract() {
  local -r minuend="$1"
  local -r subtrahend="$2"
  local -r output_name="$3"
  local comparison=""
  local result=""
  local digit=""
  local -i minuend_index=0
  local -i subtrahend_index=0
  local -i minuend_digit=0
  local -i subtrahend_digit=0
  local -i borrow=0
  local -i difference=0

  uint64_string_compare "$minuend" "$subtrahend" comparison || return 1
  [[ "$comparison" != -1 && "$output_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] ||
    return 1
  minuend_index=$((${#minuend} - 1))
  subtrahend_index=$((${#subtrahend} - 1))
  while ((minuend_index >= 0)); do
    minuend_digit=$((10#${minuend:minuend_index:1} - borrow))
    subtrahend_digit=0
    if ((subtrahend_index >= 0)); then
      subtrahend_digit=$((10#${subtrahend:subtrahend_index:1}))
    fi
    if ((minuend_digit < subtrahend_digit)); then
      minuend_digit=$((minuend_digit + 10))
      borrow=1
    else
      borrow=0
    fi
    difference=$((minuend_digit - subtrahend_digit))
    printf -v digit '%d' "$difference"
    result="$digit$result"
    minuend_index=$((minuend_index - 1))
    subtrahend_index=$((subtrahend_index - 1))
  done
  ((borrow == 0)) || return 1
  while (( ${#result} > 1 )) && [[ "$result" == 0* ]]; do
    result="${result#0}"
  done
  canonical_uint64_string "$result" || return 1
  printf -v "$output_name" '%s' "$result"
}

obi_metric_label_value_is_allowed() {
  local -r kind="$1"
  local -r value="$2"

  case "$kind:$value" in
    transport:tcp|transport:getsockopt|transport:unix|transport:disabled|\
    operation:stage|operation:candidate|operation:handoff|operation:inject|\
    operation:take|operation:discard|operation:negotiate|\
    operation:availability|operation:cleanup|operation:evict|operation:report|\
    status:unknown|status:valid|status:missing|status:stale|\
    status:unsupported|status:malformed|status:version_mismatch|\
    status:ambiguous|status:unauthorized|status:already_consumed|\
    status:timeout|status:overload|status:transport_error|status:disabled|\
    status:segmented|status:load_denied|status:permission_denied|\
    status:verifier_rejected)
      return 0
      ;;
  esac
  return 1
}

parse_obi_metric_snapshot() {
  local -r relative_path="$1"
  local -r output="$2"
  local -r strict_projected="${3:-false}"
  local -r input="$BUNDLE_DIR/$relative_path"
  local line=""
  local canonical_line=""
  local metric=""
  local raw_value=""
  local extra=""
  local labels=""
  local entry=""
  local label_name=""
  local label_value=""
  local transport=""
  local operation=""
  local status=""
  local error_type=""
  local process_name=""
  local key=""
  local unsorted=""
  local cache_file=""
  local cache_key=""
  local canonical_input=""
  local attach_value=0
  local attach_present=false
  local -i strict_line_count=0
  local -a label_entries=()
  declare -A seen_series=()
  declare -A seen_labels=()

  [[ "$strict_projected" == true || "$strict_projected" == false ]] || return 1
  [[ ! -L "$output" ]] || return 1
  cache_key="$strict_projected:$relative_path"
  if [[ -n "${PARSED_OBI_METRIC_REFERENCES[$cache_key]+present}" ]]; then
    cp -- "${PARSED_OBI_METRIC_REFERENCES[$cache_key]}" "$output"
    return
  fi
  validate_bounded_regular_file \
    "$relative_path" "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
    "$OBI_METRIC_SNAPSHOT_MAX_LINES" || return 1
  unsorted="$(mktemp "$TMP_DIR/obi-metric-snapshot.XXXXXX")" || return $?
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" != *$'\r'* ]] || {
      rm -f -- "$unsorted"
      return 1
    }
    if [[ -z "$line" || "$line" == \#* ]]; then
      if [[ "$strict_projected" == true ]]; then
        rm -f -- "$unsorted"
        return 1
      fi
      continue
    fi
    metric=""
    raw_value=""
    extra=""
    read -r metric raw_value extra <<<"$line"
    if [[ "$metric" == obi_java_remote_parent_operations_total* ]]; then
      [[ -z "$extra" &&
        "$metric" == 'obi_java_remote_parent_operations_total{'*'}' ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      labels="${metric#*\{}"
      labels="${labels%\}}"
      IFS=',' read -r -a label_entries <<<"$labels"
      (( ${#label_entries[@]} == 3 )) || {
        rm -f -- "$unsorted"
        return 1
      }
      transport=""
      operation=""
      status=""
      seen_labels=()
      for entry in "${label_entries[@]}"; do
        [[ "$entry" =~ ^(operation|status|transport)=\"([a-z_]+)\"$ ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        label_name="${BASH_REMATCH[1]}"
        label_value="${BASH_REMATCH[2]}"
        [[ -z "${seen_labels[$label_name]:-}" ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        seen_labels["$label_name"]=1
        obi_metric_label_value_is_allowed "$label_name" "$label_value" || {
          rm -f -- "$unsorted"
          return 1
        }
        case "$label_name" in
          transport) transport="$label_value" ;;
          operation) operation="$label_value" ;;
          status) status="$label_value" ;;
        esac
      done
      [[ -n "$transport" && -n "$operation" && -n "$status" ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      canonical_uint64_string "$raw_value" || {
        rm -f -- "$unsorted"
        return 1
      }
      key="$transport|$operation|$status"
      [[ -z "${seen_series[$key]:-}" ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      seen_series["$key"]=1
      if (( ${#seen_series[@]} > OBI_METRIC_PAIR_MAX_SERIES )); then
        rm -f -- "$unsorted"
        return 1
      fi
      printf 'series\t%s\t%s\t%s\t%s\n' \
        "$transport" "$operation" "$status" "$raw_value" >>"$unsorted" || {
        rm -f -- "$unsorted"
        return 1
      }
      if [[ "$strict_projected" == true ]]; then
        printf -v canonical_line \
          'obi_java_remote_parent_operations_total{operation="%s",status="%s",transport="%s"} %s' \
          "$operation" "$status" "$transport" "$raw_value"
        [[ "$line" == "$canonical_line" ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        strict_line_count=$((strict_line_count + 1))
      fi
      continue
    fi
    if [[ "$metric" == obi_instrumentation_errors_total* &&
      "$metric" == *'attaching_java_agent'* ]]; then
      [[ -z "$extra" && "$metric" == 'obi_instrumentation_errors_total{'*'}' ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      labels="${metric#*\{}"
      labels="${labels%\}}"
      IFS=',' read -r -a label_entries <<<"$labels"
      (( ${#label_entries[@]} == 2 )) || {
        rm -f -- "$unsorted"
        return 1
      }
      error_type=""
      process_name=""
      seen_labels=()
      for entry in "${label_entries[@]}"; do
        [[ "$entry" =~ ^(error_type|process_name)=\"([a-z_]+)\"$ ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        label_name="${BASH_REMATCH[1]}"
        label_value="${BASH_REMATCH[2]}"
        [[ -z "${seen_labels[$label_name]:-}" ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        seen_labels["$label_name"]=1
        case "$label_name" in
          error_type) error_type="$label_value" ;;
          process_name) process_name="$label_value" ;;
        esac
      done
      if [[ "$error_type" != attaching_java_agent || "$process_name" != java ]]; then
        if [[ "$strict_projected" == true ]]; then
          rm -f -- "$unsorted"
          return 1
        fi
        continue
      fi
      [[ "$attach_present" == false ]] || {
        rm -f -- "$unsorted"
        return 1
      }
      canonical_uint64_string "$raw_value" || {
        rm -f -- "$unsorted"
        return 1
      }
      attach_present=true
      attach_value="$raw_value"
      if [[ "$strict_projected" == true ]]; then
        printf -v canonical_line \
          'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} %s' \
          "$raw_value"
        [[ "$line" == "$canonical_line" ]] || {
          rm -f -- "$unsorted"
          return 1
        }
        strict_line_count=$((strict_line_count + 1))
      fi
      continue
    fi
    if [[ "$strict_projected" == true ]]; then
      rm -f -- "$unsorted"
      return 1
    fi
  done <"$input"
  if [[ "$strict_projected" == true && "$strict_line_count" == 0 ]]; then
    rm -f -- "$unsorted"
    return 1
  fi
  if [[ "$strict_projected" == true ]]; then
    canonical_input="$(mktemp "$TMP_DIR/obi-metric-canonical.XXXXXX")" || {
      rm -f -- "$unsorted"
      return 1
    }
    if ! LC_ALL=C sort -- "$input" >"$canonical_input" ||
      ! cmp -s -- "$input" "$canonical_input"; then
      rm -f -- "$unsorted" "$canonical_input"
      return 1
    fi
    rm -f -- "$canonical_input" || {
      rm -f -- "$unsorted"
      return 1
    }
  fi
  if LC_ALL=C sort -- "$unsorted" >"$output" &&
    printf 'attach\t%s\t%s\n' "$attach_present" "$attach_value" >>"$output"; then
    rm -f -- "$unsorted" || return 1
    cache_file="$(mktemp "$TMP_DIR/obi-metric-parsed-cache.XXXXXX")" || return $?
    if ! cp -- "$output" "$cache_file"; then
      rm -f -- "$cache_file"
      return 1
    fi
    PARSED_OBI_METRIC_REFERENCES["$cache_key"]="$cache_file"
    return 0
  fi
  rm -f -- "$unsorted" "$output" || true
  return 1
}

validate_java_diagnostics_snapshot() {
  local -r snapshot="$1"
  local entry=""
  local name=""
  local value=""
  local -i decoded=0
  local -i index=0
  local -a entries=()
  local -a expected_names=(
    cfg_on cfg_off provider_ok provider_reject provider_ver extension_reg
    lookup_ready lookup_missing lookup_version lookup_error record_version
    invoke_error discard_standard extract_fields extract_invalid extract_error
    registration_ok registration_fail take_sampled take_unsampled tls_reads tls_bytes
    framework_depth framework_cycle framework_late transport_missing
    t_unknown d_unknown t_valid d_valid t_missing d_missing t_stale d_stale
    t_unsupported d_unsupported t_malformed d_malformed
    t_version_mismatch d_version_mismatch t_ambiguous d_ambiguous
    t_unauthorized d_unauthorized t_already_consumed d_already_consumed
    t_timeout d_timeout t_overload d_overload
    t_transport_error d_transport_error t_disabled d_disabled
  )

  IFS=',' read -r -a entries <<<"$snapshot"
  (( ${#entries[@]} == ${#expected_names[@]} )) || return 1
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^[a-z_]+=(0|[1-9a-z][0-9a-z]*)$ ]] || return 1
    name="${entry%%=*}"
    value="${entry#*=}"
    [[ "$name" == "${expected_names[$index]}" && ${#value} -le 6 ]] || return 1
    decoded="$((36#$value))"
    ((decoded < JAVA_DIAGNOSTIC_COUNTER_MAX)) || return 1
    ((index += 1))
  done
}

validate_java_diagnostics_reference() {
  local -r reference="$1"
  local phase=""
  local diagnostics=""
  local -a lines=()

  [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/java-diagnostics\.txt$ ]] ||
    return 1
  phase="${BASH_REMATCH[1]}"
  [[ "$reference" == "phases/$phase/java-diagnostics.txt" ]] || return 1
  if [[ -n "${VALIDATED_JAVA_DIAGNOSTICS_REFERENCES[$reference]+present}" ]]; then
    return 0
  fi
  validate_bounded_regular_file \
    "$reference" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" 1 || return 1
  mapfile -t lines <"$BUNDLE_DIR/$reference"
  (( ${#lines[@]} == 1 )) || return 1
  diagnostics="${lines[0]}"
  validate_java_diagnostics_snapshot "$diagnostics" || return 1
  VALIDATED_JAVA_DIAGNOSTICS_REFERENCES["$reference"]=1
}

validate_terminal_java_diagnostics() {
  local -r relative_path='terminal-java-diagnostics.json'
  local -r input="$BUNDLE_DIR/$relative_path"
  local reference=""
  local phase=""
  local snapshot=""
  local diagnostics=""

  validate_single_json_object \
    "$relative_path" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" || return 1
  jq -e '
    keys == [
      "available", "counters", "phase", "reference", "schema", "sealed", "snapshot"
    ] and
    .schema == "obi-java-bridge-terminal-diagnostics-v1" and
    .sealed == true and
    .available == true and
    ([.phase, .reference, .snapshot] | all(.[]; type == "string")) and
    (.counters | type == "object")
  ' "$input" >/dev/null || return 1
  reference="$(jq -er '.reference' "$input")" || return 1
  phase="$(jq -er '.phase' "$input")" || return 1
  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ &&
    "$reference" == "phases/$phase/java-diagnostics.txt" ]] || return 1
  validate_java_diagnostics_reference "$reference" || return 1
  IFS= read -r diagnostics <"$BUNDLE_DIR/$reference" || return 1
  snapshot="$(jq -er '.snapshot' "$input")" || return 1
  [[ "$snapshot" == "$diagnostics" ]] || return 1
  jq -e --arg snapshot "$snapshot" '
    .counters == (
      $snapshot
      | split(",")
      | map(split("=") | {(.[0]): .[1]})
      | add
    )
  ' "$input" >/dev/null
}

validate_terminal_java_diagnostics_any() {
  local -r relative_path='terminal-java-diagnostics.json'

  validate_single_json_object \
    "$relative_path" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" || return 1
  if jq -e '
    keys == ["available", "reason", "schema", "sealed"] and
    .schema == "obi-java-bridge-terminal-diagnostics-v1" and
    .sealed == true and .available == false and
    .reason == "no-valid-snapshot-before-terminal-boundary"
  ' "$BUNDLE_DIR/$relative_path" >/dev/null; then
    return 0
  fi
  validate_terminal_java_diagnostics
}

validate_obi_process_identity_reference() {
  local -r reference="$1"
  local phase=""
  local state=""
  local container_id=""
  local host_pid=""
  local started_at=""
  local finished_at=""
  local exit_code=""
  local metrics_reference=""
  local metrics_sha256=""
  local parsed_metrics=""
  local input=""

  [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-identity\.json$ ]] ||
    return 1
  phase="${BASH_REMATCH[1]}"
  if [[ -n "${VALIDATED_OBI_IDENTITY_REFERENCES[$reference]+present}" ]]; then
    return 0
  fi
  validate_single_json_object "$reference" "$OBI_PROCESS_IDENTITY_MAX_BYTES" ||
    return 1
  input="$BUNDLE_DIR/$reference"
  state="$(jq -er '.state' "$input")" || return 1
  case "$state" in
    running)
      jq -e '
        keys == [
          "container_id", "host_pid", "metrics_reference", "metrics_sha256",
          "schema", "started_at", "state"
        ] and
        .schema == "obi-process-identity-v1" and
        .state == "running" and
        ([.container_id, .host_pid, .metrics_reference, .metrics_sha256,
          .started_at] | all(.[]; type == "string"))
      ' "$input" >/dev/null || return 1
      ;;
    obi_stopped)
      jq -e '
        keys == [
          "container_id", "exit_code", "finished_at", "host_pid", "schema",
          "started_at", "state"
        ] and
        .schema == "obi-process-identity-v1" and
        .state == "obi_stopped" and
        ([.container_id, .exit_code, .finished_at, .host_pid, .started_at] |
          all(.[]; type == "string"))
      ' "$input" >/dev/null || return 1
      ;;
    *) return 1 ;;
  esac
  container_id="$(jq -er '.container_id' "$input")" || return 1
  host_pid="$(jq -er '.host_pid' "$input")" || return 1
  started_at="$(jq -er '.started_at' "$input")" || return 1
  [[ "$container_id" =~ ^[0-9a-f]{64}$ &&
    "$started_at" =~ ^[0-9TZ:.-]{20,64}$ ]] || return 1
  canonical_uint64_string "$host_pid" || return 1
  if [[ "$state" == running ]]; then
    [[ "$host_pid" != 0 ]] || return 1
    metrics_reference="$(jq -er '.metrics_reference' "$input")" || return 1
    metrics_sha256="$(jq -er '.metrics_sha256' "$input")" || return 1
    [[ "$metrics_reference" == "phases/$phase/obi-metrics.prom" &&
      "$metrics_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
    validate_bounded_regular_file \
      "$metrics_reference" "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
      "$OBI_METRIC_SNAPSHOT_MAX_LINES" || return 1
    verify_reference_sha256 "$metrics_reference" "$metrics_sha256" || return 1
    parsed_metrics="$(mktemp "$TMP_DIR/obi-identity-metrics.XXXXXX")" || return $?
    parse_obi_metric_snapshot "$metrics_reference" "$parsed_metrics" || return 1
  else
    finished_at="$(jq -er '.finished_at' "$input")" || return 1
    exit_code="$(jq -er '.exit_code' "$input")" || return 1
    [[ "$finished_at" =~ ^[0-9TZ:.-]{20,64}$ ]] || return 1
    canonical_uint64_string "$exit_code" || return 1
    [[ ! -e "$BUNDLE_DIR/phases/$phase/obi-metrics.prom" &&
      ! -L "$BUNDLE_DIR/phases/$phase/obi-metrics.prom" ]] || return 1
  fi
  OBI_IDENTITY_STATE["$reference"]="$state"
  OBI_IDENTITY_CONTAINER_ID["$reference"]="$container_id"
  OBI_IDENTITY_STARTED_AT["$reference"]="$started_at"
  OBI_IDENTITY_METRICS_REFERENCE["$reference"]="$metrics_reference"
  VALIDATED_OBI_IDENTITY_REFERENCES["$reference"]=1
}

validate_obi_metric_pair() {
  local -r pair_reference="$1"
  local pair=""
  local boundary=""
  local continuity=""
  local before_reference=""
  local after_reference=""
  local before_state=""
  local after_state=""
  local before_container_id=""
  local after_container_id=""
  local before_started_at=""
  local after_started_at=""
  local before_metrics_reference=""
  local after_metrics_reference=""
  local before_parsed=""
  local after_parsed=""
  local record_type=""
  local first=""
  local second=""
  local third=""
  local fourth=""
  local key=""
  local previous_key=""
  local transport=""
  local operation=""
  local status=""
  local before=""
  local after=""
  local delta=""
  local expected_before=""
  local expected_after=""
  local expected_delta=""
  local attach_before=""
  local attach_after=""
  local attach_delta=""
  local attach_before_value=0
  local attach_after_value=0
  local attach_before_present=false
  local attach_after_present=false
  local series_count=""
  local -i observed_series=0
  local LC_ALL=C
  declare -A before_values=()
  declare -A after_values=()
  declare -A union=()
  declare -A pair_seen=()

  [[ "$pair_reference" =~ ^obi-metric-pairs/([a-z0-9][a-z0-9-]{0,63})\.json$ ]] ||
    return 1
  boundary="${BASH_REMATCH[1]}"
  if [[ -n "${VALIDATED_OBI_PAIR_REFERENCES[$pair_reference]+present}" ]]; then
    return 0
  fi
  validate_single_json_object "$pair_reference" "$OBI_METRIC_PAIR_MAX_BYTES" ||
    return 1
  pair="$BUNDLE_DIR/$pair_reference"
  jq -e '
    keys == [
      "after", "before", "boundary", "continuity", "java_attach_errors",
      "schema", "series"
    ] and
    .schema == "obi-java-remote-parent-metric-pair-v1" and
    (.boundary | type == "string") and
    (.continuity == "same_process" or .continuity == "process_replaced") and
    (.before | keys == ["identity_reference", "state"]) and
    (.after | keys == ["identity_reference", "state"]) and
    .before.state == "running" and
    (.after.state == "running" or .after.state == "obi_stopped") and
    ([.before.identity_reference, .after.identity_reference] |
      all(.[]; type == "string")) and
    (.series | type == "array") and
    all(.series[];
      keys == ["after", "before", "delta", "operation", "status", "transport"] and
      ([.transport, .operation, .status, .before] |
        all(.[]; type == "string")) and
      (.after == null or (.after | type == "string")) and
      (.delta == null or (.delta | type == "string"))) and
    (.java_attach_errors | keys == ["after", "before", "delta"]) and
    (.java_attach_errors.before | type == "string") and
    (.java_attach_errors.after == null or
      (.java_attach_errors.after | type == "string")) and
    (.java_attach_errors.delta == null or
      (.java_attach_errors.delta | type == "string"))
  ' "$pair" >/dev/null || return 1
  [[ "$(jq -er '.boundary' "$pair")" == "$boundary" ]] || return 1
  continuity="$(jq -er '.continuity' "$pair")" || return 1
  before_reference="$(jq -er '.before.identity_reference' "$pair")" || return 1
  after_reference="$(jq -er '.after.identity_reference' "$pair")" || return 1
  [[ "$before_reference" != "$after_reference" ]] || return 1
  before_state="$(jq -er '.before.state' "$pair")" || return 1
  after_state="$(jq -er '.after.state' "$pair")" || return 1
  validate_obi_process_identity_reference "$before_reference" || return 1
  validate_obi_process_identity_reference "$after_reference" || return 1
  [[ "${OBI_IDENTITY_STATE[$before_reference]}" == "$before_state" &&
    "${OBI_IDENTITY_STATE[$after_reference]}" == "$after_state" ]] || return 1
  before_container_id="${OBI_IDENTITY_CONTAINER_ID[$before_reference]}"
  after_container_id="${OBI_IDENTITY_CONTAINER_ID[$after_reference]}"
  before_started_at="${OBI_IDENTITY_STARTED_AT[$before_reference]}"
  after_started_at="${OBI_IDENTITY_STARTED_AT[$after_reference]}"
  if [[ "$after_state" == obi_stopped ]]; then
    [[ "$continuity" == same_process &&
      "$before_container_id" == "$after_container_id" &&
      "$before_started_at" == "$after_started_at" ]] || return 1
  elif [[ "$continuity" == same_process ]]; then
    [[ "$before_container_id" == "$after_container_id" &&
      "$before_started_at" == "$after_started_at" ]] || return 1
  else
    [[ "$before_container_id" != "$after_container_id" ||
      "$before_started_at" != "$after_started_at" ]] || return 1
  fi

  before_metrics_reference="${OBI_IDENTITY_METRICS_REFERENCE[$before_reference]}"
  before_parsed="$(mktemp "$TMP_DIR/obi-metric-before.XXXXXX")" || return $?
  after_parsed="$(mktemp "$TMP_DIR/obi-metric-after.XXXXXX")" || return $?
  parse_obi_metric_snapshot "$before_metrics_reference" "$before_parsed" || return 1
  if [[ "$after_state" == running ]]; then
    after_metrics_reference="${OBI_IDENTITY_METRICS_REFERENCE[$after_reference]}"
    parse_obi_metric_snapshot "$after_metrics_reference" "$after_parsed" || return 1
  else
    : >"$after_parsed"
    printf 'attach\tfalse\t0\n' >>"$after_parsed"
  fi
  while IFS=$'\t' read -r record_type first second third fourth; do
    case "$record_type" in
      series)
        key="$first|$second|$third"
        before_values["$key"]="$fourth"
        union["$key"]=1
        ;;
      attach)
        attach_before_present="$first"
        attach_before_value="$second"
        ;;
      *) return 1 ;;
    esac
  done <"$before_parsed"
  while IFS=$'\t' read -r record_type first second third fourth; do
    case "$record_type" in
      series)
        key="$first|$second|$third"
        after_values["$key"]="$fourth"
        union["$key"]=1
        ;;
      attach)
        attach_after_present="$first"
        attach_after_value="$second"
        ;;
      *) return 1 ;;
    esac
  done <"$after_parsed"

  series_count="$(jq -er '.series | length' "$pair")" || return 1
  [[ "$series_count" =~ ^[0-9]+$ ]] || return 1
  ((series_count <= OBI_METRIC_PAIR_MAX_SERIES &&
    series_count == ${#union[@]})) || return 1
  while IFS=$'\t' read -r transport operation status before after delta; do
    ((observed_series += 1))
    [[ -n "$transport" && -n "$operation" && -n "$status" ]] || return 1
    obi_metric_label_value_is_allowed transport "$transport" || return 1
    obi_metric_label_value_is_allowed operation "$operation" || return 1
    obi_metric_label_value_is_allowed status "$status" || return 1
    key="$transport|$operation|$status"
    # Canonical allowlisted tuple keys are intentionally compared lexically.
    # shellcheck disable=SC2071
    [[ -z "$previous_key" || "$key" > "$previous_key" ]] || return 1
    previous_key="$key"
    [[ -n "${union[$key]:-}" && -z "${pair_seen[$key]:-}" ]] || return 1
    pair_seen["$key"]=1
    canonical_uint64_string "$before" || return 1
    expected_before="${before_values[$key]:-0}"
    [[ "$before" == "$expected_before" ]] || return 1
    if [[ "$after_state" == obi_stopped ]]; then
      [[ "$after" == __null__ && "$delta" == __null__ ]] || return 1
    elif [[ "$continuity" == process_replaced ]]; then
      canonical_uint64_string "$after" || return 1
      expected_after="${after_values[$key]:-0}"
      [[ "$after" == "$expected_after" && "$delta" == __null__ ]] || return 1
    else
      [[ -z "${before_values[$key]+present}" ||
        -n "${after_values[$key]+present}" ]] || return 1
      canonical_uint64_string "$after" || return 1
      expected_after="${after_values[$key]:-0}"
      [[ "$after" == "$expected_after" ]] || return 1
      uint64_string_subtract "$expected_after" "$expected_before" expected_delta ||
        return 1
      [[ "$delta" == "$expected_delta" ]] || return 1
    fi
  done < <(jq -r '
    .series[] |
    [.transport, .operation, .status, .before,
      (if .after == null then "__null__" else .after end),
      (if .delta == null then "__null__" else .delta end)] | @tsv
  ' "$pair")
  ((observed_series == series_count)) || return 1

  attach_before="$(jq -er '.java_attach_errors.before' "$pair")" || return 1
  attach_after="$(jq -r '
    .java_attach_errors.after |
    if . == null then "__null__" elif type == "string" then . else error("invalid") end
  ' "$pair")" || return 1
  attach_delta="$(jq -r '
    .java_attach_errors.delta |
    if . == null then "__null__" elif type == "string" then . else error("invalid") end
  ' "$pair")" || return 1
  canonical_uint64_string "$attach_before" || return 1
  [[ "$attach_before" == "$attach_before_value" ]] || return 1
  if [[ "$after_state" == obi_stopped ]]; then
    [[ "$attach_after" == __null__ && "$attach_delta" == __null__ ]] || return 1
  elif [[ "$continuity" == process_replaced ]]; then
    canonical_uint64_string "$attach_after" || return 1
    [[ "$attach_after" == "$attach_after_value" &&
      "$attach_delta" == __null__ ]] || return 1
  else
    [[ "$attach_before_present" != true || "$attach_after_present" == true ]] ||
      return 1
    canonical_uint64_string "$attach_after" || return 1
    [[ "$attach_after" == "$attach_after_value" ]] || return 1
    uint64_string_subtract \
      "$attach_after_value" "$attach_before_value" expected_delta || return 1
    [[ "$attach_delta" == "$expected_delta" ]] || return 1
  fi
  if ((series_count == 0)); then
    [[ "$attach_before" != 0 ||
      ( "$attach_after" != __null__ && "$attach_after" != 0 ) ]] || return 1
  fi
  VALIDATED_OBI_PAIR_REFERENCES["$pair_reference"]=1
}

read_canonical_obi_metric_boundary_index() {
  local -r relative_path='obi-metric-boundary-index.json'
  local payload=""
  local canonical=""
  local size=""
  local -a lines=()

  validate_bounded_regular_file \
    "$relative_path" "$OBI_METRIC_BOUNDARY_INDEX_MAX_BYTES" 1 || return 1
  mapfile -t lines <"$BUNDLE_DIR/$relative_path"
  (( ${#lines[@]} == 1 )) || return 1
  payload="${lines[0]}"
  size="$(stat -Lc '%s' -- "$BUNDLE_DIR/$relative_path")" || return 1
  [[ "$size" == "$(( ${#payload} + 1 ))" ]] || return 1
  canonical="$(jq -cS . <<<"$payload")" || return 1
  [[ "$payload" == "$canonical" ]] || return 1
  jq -e \
    --argjson maximum_boundaries "$OBI_METRIC_BOUNDARY_INDEX_MAX_BOUNDARIES" \
    --argjson maximum_captures "$OBI_METRIC_BOUNDARY_INDEX_MAX_CAPTURES" \
    --argjson maximum_statuses "$OBI_METRIC_BOUNDARY_INDEX_MAX_STATUS_REFERENCES" '
      keys == ["boundaries", "schema", "selection"] and
      .schema == "obi-metric-boundary-index-v1" and
      (.selection | keys == [
        "repeat_count", "requested_transport", "scenario", "selected_transport"
      ]) and
      (.selection.scenario | type == "string") and
      (.selection.requested_transport == "auto" or
        .selection.requested_transport == "getsockopt" or
        .selection.requested_transport == "unix" or
        .selection.requested_transport == "disabled") and
      (.selection.selected_transport == null or
        .selection.selected_transport == "getsockopt" or
        .selection.selected_transport == "unix") and
      (.selection.repeat_count | type == "number" and floor == . and
        . >= 1 and . <= 10) and
      (.boundaries | type == "array" and length >= 1 and
        length <= $maximum_boundaries) and
      ([.boundaries[].id] | length == (unique | length)) and
      ([.boundaries[].ordinal] | length == (unique | length)) and
      ([.boundaries[] | select(.state == "active")] | length <= 1) and
      ([.boundaries[].captures[]] | length <= $maximum_captures) and
      ([.boundaries[].status_references[]] | length <= $maximum_statuses) and
      (.boundaries | to_entries | all(.[]; .value.ordinal == (.key + 1))) and
      all(.boundaries[];
        keys == [
          "captures", "id", "not_applicable_reason", "ordinal", "state",
          "status_references"
        ] and
        (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$")) and
        (.ordinal | type == "number" and floor == . and . >= 1) and
        (.state == "planned" or .state == "active" or
          .state == "complete" or .state == "not_applicable") and
        (.captures | type == "array") and
        (.status_references | type == "array") and
        ([.captures[].id] | length == (unique | length)) and
        ([.status_references[].reference] | length == (unique | length)) and
        (if .state == "planned" then
          .captures == [] and .status_references == [] and
          .not_applicable_reason == null
        elif .state == "active" then
          .not_applicable_reason == null
        elif .state == "complete" then
          (.captures | length) > 0 and
          all(.captures[]; .state == "captured") and
          (any(.captures[]; .kind == "pair" and .state == "captured") or
            all(.captures[]; .kind == "unavailable")) and
          (.status_references | length) > 0 and
          .not_applicable_reason == null
        else
          .captures == [] and (.status_references | length) == 1 and
          (.not_applicable_reason | type == "string" and length >= 1 and
            length <= 160)
        end) and
        all(.status_references[];
          keys == ["reference", "sha256"] and
          (.reference | type == "string" and
            test("^scenario-[a-z0-9][a-z0-9-]{0,95}-status\\.json$")) and
          (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) and
        all(.captures[];
          ((.kind == "phase" and .state == "captured" and
            keys == ["id", "identity_reference", "identity_sha256", "kind", "state"] and
            (.identity_reference | type == "string") and
            (.identity_sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "java" and .state == "captured" and
            keys == ["id", "kind", "reference", "sha256", "state"] and
            (.reference | type == "string") and
            (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "artifact" and .state == "captured" and
            keys == ["id", "kind", "reference", "sha256", "state"] and
            (.reference | type == "string") and
            (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "unavailable" and .state == "captured" and
            keys == ["id", "kind", "reason", "reference", "sha256", "state"] and
            .reason == "obi_process_not_running" and
            (.reference | type == "string") and
            (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
          (.kind == "pair" and
            keys == [
              "id", "java_reference", "java_sha256", "kind", "pair_reference",
              "pair_sha256", "state"
            ] and
            (.state == "planned" or .state == "captured") and
            (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$")) and
            (if .state == "planned" then
              .pair_reference == null and .pair_sha256 == null and
              .java_reference == null and .java_sha256 == null
            else
              (.pair_reference | type == "string") and
              (.pair_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
              ((.java_reference == null and .java_sha256 == null) or
                ((.java_reference | type == "string") and
                  (.java_sha256 | type == "string" and test("^[0-9a-f]{64}$"))))
            end)) and
          (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$")))
        )
      )
    ' <<<"$payload" >/dev/null || return 1
  jq -e '
    [.boundaries[].state] as $states |
    ($states | length) as $count |
    all(range(0; $count); . as $index |
      if ($states[$index] == "complete" or
        $states[$index] == "not_applicable") then
        all(range(0; $index); . as $prior |
          $states[$prior] == "complete" or
          $states[$prior] == "not_applicable")
      elif $states[$index] == "active" then
        all(range(0; $index); . as $prior |
          $states[$prior] == "complete" or
          $states[$prior] == "not_applicable") and
        all(range($index + 1; $count); . as $later |
          $states[$later] == "planned")
      else
        all(range($index + 1; $count); . as $later |
          $states[$later] == "planned")
      end) and
    all(.boundaries[];
      ([.captures[] | select(.kind == "pair") | .state]) as $pair_states |
      all(range(0; ($pair_states | length)); . as $index |
        if $pair_states[$index] == "planned" then
          all(range($index + 1; ($pair_states | length)); . as $later |
            $pair_states[$later] == "planned")
        else true end))
  ' <<<"$payload" >/dev/null || return 1
  printf '%s\n' "$payload"
}

preflight_obi_metric_boundary_referenced_bytes() {
  local payload=""
  local raw_references="$TMP_DIR/obi-boundary-references.raw"
  local direct_references="$TMP_DIR/obi-boundary-references.direct"
  local expanded_references="$TMP_DIR/obi-boundary-references.expanded"
  local final_references="$TMP_DIR/obi-boundary-references.final"
  local pair_identity_references="$TMP_DIR/obi-boundary-pair-identities"
  local reference=""
  local identity_reference=""
  local metrics_reference=""
  local state=""
  local size=""
  local remaining_bytes=""
  local size_comparison=""
  local -i total_bytes=0

  payload="$(read_canonical_obi_metric_boundary_index)" || return 1
  jq -r '
    .boundaries[] |
    (.captures[] |
      if .kind == "phase" then .identity_reference
      elif .kind == "pair" and .state == "captured" then
        .pair_reference, (.java_reference // empty)
      elif .kind == "pair" then empty
      else .reference end),
    (.status_references[].reference)
  ' <<<"$payload" >"$raw_references" || return 1
  LC_ALL=C sort -u -- "$raw_references" >"$direct_references" || return 1
  : >"$expanded_references"
  while IFS= read -r reference; do
    [[ -n "$reference" ]] || continue
    is_safe_relative_path "$reference" || return 1
    [[ -f "$BUNDLE_DIR/$reference" && ! -L "$BUNDLE_DIR/$reference" ]] || return 1
    printf '%s\n' "$reference" >>"$expanded_references" || return 1
    if [[ "$reference" =~ ^obi-metric-pairs/[a-z0-9][a-z0-9-]{0,63}\.json$ ]]; then
      validate_single_json_object "$reference" "$OBI_METRIC_PAIR_MAX_BYTES" || return 1
      jq -er '
        [.before.identity_reference, .after.identity_reference] as $references |
        if ($references | length) == 2 and
          all($references[]; type == "string")
        then $references[] else error("invalid pair identity references") end
      ' "$BUNDLE_DIR/$reference" >"$pair_identity_references" || return 1
      [[ "$(awk 'END { print NR + 0 }' "$pair_identity_references")" == 2 ]] ||
        return 1
      while IFS= read -r identity_reference; do
        is_safe_relative_path "$identity_reference" || return 1
        printf '%s\n' "$identity_reference" >>"$expanded_references" || return 1
      done <"$pair_identity_references"
    fi
  done <"$direct_references"
  LC_ALL=C sort -u -- "$expanded_references" >"$final_references.tmp" || return 1
  cp -- "$final_references.tmp" "$expanded_references" || return 1
  while IFS= read -r reference; do
    [[ "$reference" =~ ^phases/[a-z0-9][a-z0-9-]{0,63}/obi-identity\.json$ ]] ||
      continue
    validate_single_json_object "$reference" "$OBI_PROCESS_IDENTITY_MAX_BYTES" ||
      return 1
    state="$(jq -er '.state' "$BUNDLE_DIR/$reference")" || return 1
    case "$state" in
      running)
        metrics_reference="$(jq -er '.metrics_reference' "$BUNDLE_DIR/$reference")" ||
          return 1
        is_safe_relative_path "$metrics_reference" || return 1
        printf '%s\n' "$metrics_reference" >>"$expanded_references" || return 1
        ;;
      obi_stopped) ;;
      *) return 1 ;;
    esac
  done <"$final_references.tmp"
  LC_ALL=C sort -u -- "$expanded_references" >"$final_references" || return 1
  while IFS= read -r reference; do
    [[ -n "$reference" && -f "$BUNDLE_DIR/$reference" &&
      ! -L "$BUNDLE_DIR/$reference" ]] || return 1
    size="$(stat -Lc '%s' -- "$BUNDLE_DIR/$reference")" || return 1
    canonical_uint64_string "$size" || return 1
    remaining_bytes="$((OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES - total_bytes))"
    uint64_string_compare "$size" "$remaining_bytes" size_comparison || return 1
    [[ "$size_comparison" != 1 ]] || return 1
    total_bytes=$((total_bytes + size))
  done <"$final_references"
}

emit_repeated_planned_obi_metric_boundary_ids() {
  local -r base="$1"
  local -r repeat_count="$2"
  local -i run_number=0

  for ((run_number = 1; run_number <= repeat_count; run_number++)); do
    if ((repeat_count == 1)); then
      printf '%s\n' "$base"
    else
      printf '%s-run-%02d\n' "$base" "$run_number"
    fi
  done
}

planned_obi_metric_boundary_ids() {
  local -r scenario="$1"
  local -r repeat_count="$2"
  local name=""
  local -a direct_after_controls=(
    keepalive pipelining concurrency connection-churn fd-port-reuse
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff
    virtual-thread netty netty-server dispatch w3c
  )

  [[ "$repeat_count" =~ ^([1-9]|10)$ ]] || return 1
  if [[ "$scenario" == all ]]; then
    emit_repeated_planned_obi_metric_boundary_ids basic "$repeat_count"
    printf '%s\n' delayed-otlp-suppression security
    for name in "${direct_after_controls[@]}"; do
      emit_repeated_planned_obi_metric_boundary_ids "$name" "$repeat_count"
    done
    printf 'w3c-match\n'
    emit_repeated_planned_obi_metric_boundary_ids obi-flags "$repeat_count"
    printf '%s\n' \
      primary-w3c-stale primary-generation-mismatch primary-w3c-fault \
      unix-w3c-stale unix-generation-mismatch w3c-fault \
      permanent-absence auto-unavailable late-attach restart-during-traffic \
      helper-attach-failure disabled extension-controls uninstrumented
    return 0
  fi
  case "$scenario" in
    assertion-failure)
      emit_repeated_planned_obi_metric_boundary_ids basic "$repeat_count"
      ;;
    restart-fault) printf 'restart-during-traffic\n' ;;
    benchmark-disabled|benchmark-uninstrumented|pid-reuse|restart)
      printf '%s\n' "$scenario"
      ;;
    fail-open|w3c-only|w3c-match|w3c-fault|primary-w3c-stale|unix-w3c-stale|\
    primary-w3c-fault|primary-generation-mismatch|unix-generation-mismatch|\
    permanent-absence|auto-unavailable|security|delayed-otlp-suppression|\
    helper-attach-failure)
      printf '%s\n' "$scenario"
      ;;
    *) emit_repeated_planned_obi_metric_boundary_ids "$scenario" "$repeat_count" ;;
  esac
}

validate_obi_metric_boundary_index() {
  local -r environment="$1"
  local -r index_relative='obi-metric-boundary-index.json'
  local -r freeze_relative='.obi-metric-boundary-index.freeze'
  local payload=""
  local index_digest=""
  local frozen_index_digest=""
  local freeze_payload=""
  local scenario=""
  local requested_transport=""
  local repeat_count=""
  local expected_ids="$TMP_DIR/obi-boundary-ids.expected"
  local observed_ids="$TMP_DIR/obi-boundary-ids.observed"
  local capture_manifest="$TMP_DIR/obi-boundary-captures"
  local status_manifest="$TMP_DIR/obi-boundary-statuses"
  local expected_pairs="$TMP_DIR/obi-boundary-pairs.expected"
  local actual_pairs="$TMP_DIR/obi-boundary-pairs.actual"
  local expected_statuses="$TMP_DIR/obi-boundary-statuses.expected"
  local actual_statuses="$TMP_DIR/obi-boundary-statuses.actual"
  local expected_owners="$TMP_DIR/obi-boundary-status-owners.expected"
  local actual_owners="$TMP_DIR/obi-boundary-status-owners.actual"
  local boundary_id=""
  local boundary_state=""
  local not_applicable_reason=""
  local capture_id=""
  local kind=""
  local capture_state=""
  local reference=""
  local expected_digest=""
  local java_reference=""
  local java_digest=""
  local unavailable_phase=""
  local path=""
  local expected_capture_count=""
  local expected_status_count=""
  local -i capture_count=0
  local -i status_count=0
  local -a freeze_lines=()

  reset_reference_validation_caches
  payload="$(read_canonical_obi_metric_boundary_index)" || return 1
  preflight_obi_metric_boundary_referenced_bytes || return 1
  validate_bounded_regular_file \
    "$freeze_relative" "$OBI_METRIC_BOUNDARY_FREEZE_MAX_BYTES" 1 || return 1
  mapfile -t freeze_lines <"$BUNDLE_DIR/$freeze_relative"
  (( ${#freeze_lines[@]} == 1 )) || return 1
  freeze_payload="${freeze_lines[0]}"
  [[ "$(stat -Lc '%s' -- "$BUNDLE_DIR/$freeze_relative")" == \
    "$(( ${#freeze_payload} + 1 ))" ]] || return 1
  [[ "$freeze_payload" =~ ^obi-metric-boundary-index-frozen-v1:([0-9a-f]{64})$ ]] ||
    return 1
  frozen_index_digest="${BASH_REMATCH[1]}"
  index_digest="$(sha256sum "$BUNDLE_DIR/$index_relative")" || return 1
  index_digest="${index_digest%% *}"
  [[ "$index_digest" == "$frozen_index_digest" ]] || return 1

  scenario="$(key_value "$environment" scenario)" || return 1
  requested_transport="$(key_value "$environment" transport)" || return 1
  repeat_count="$(key_value "$environment" repeat_count)" || return 1
  [[ "$requested_transport" =~ ^(auto|getsockopt|unix|disabled)$ &&
    "$repeat_count" =~ ^([1-9]|10)$ ]] || return 1
  jq -e --arg scenario "$scenario" \
    --arg requested_transport "$requested_transport" \
    --argjson repeat_count "$repeat_count" '
      .selection.scenario == $scenario and
      .selection.requested_transport == $requested_transport and
      .selection.repeat_count == $repeat_count and
      (if $requested_transport == "getsockopt" then
        (.selection.selected_transport == null or
          .selection.selected_transport == "getsockopt")
      elif $requested_transport == "unix" then
        (.selection.selected_transport == null or
          .selection.selected_transport == "unix")
      elif $requested_transport == "disabled" then
        .selection.selected_transport == null
      else
        (.selection.selected_transport == null or
          .selection.selected_transport == "getsockopt" or
          .selection.selected_transport == "unix")
      end)
    ' <<<"$payload" >/dev/null || return 1
  planned_obi_metric_boundary_ids "$scenario" "$repeat_count" >"$expected_ids" ||
    return 1
  jq -r '.boundaries[].id' <<<"$payload" >"$observed_ids" || return 1
  cmp -s -- "$expected_ids" "$observed_ids" || return 1

  jq -r '
    .boundaries[] as $boundary |
    $boundary.captures[] |
    [
      $boundary.id, $boundary.state,
      ($boundary.not_applicable_reason // "__null__"),
      .id, .kind, .state,
      (if .kind == "phase" then .identity_reference
       elif .kind == "pair" then (.pair_reference // "__null__")
       else .reference end),
      (if .kind == "phase" then .identity_sha256
       elif .kind == "pair" then (.pair_sha256 // "__null__")
       else .sha256 end),
      (.java_reference // "__null__"), (.java_sha256 // "__null__")
    ] | @tsv
  ' <<<"$payload" >"$capture_manifest" || return 1
  expected_capture_count="$(jq -er '[.boundaries[].captures[]] | length' \
    <<<"$payload")" || return 1
  : >"$expected_pairs"
  while IFS=$'\t' read -r \
    boundary_id boundary_state not_applicable_reason capture_id kind capture_state \
    reference expected_digest java_reference java_digest; do
    [[ -n "$boundary_id" ]] || continue
    ((capture_count += 1))
    case "$kind:$capture_state" in
      pair:planned)
        continue
        ;;
      phase:captured)
        [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-identity\.json$ &&
          "$capture_id" == "${BASH_REMATCH[1]}" ]] || return 1
        validate_obi_process_identity_reference "$reference" || return 1
        ;;
      java:captured)
        [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/java-diagnostics\.txt$ &&
          "$capture_id" == "java-${BASH_REMATCH[1]}" ]] || return 1
        validate_java_diagnostics_reference "$reference" || return 1
        ;;
      artifact:captured)
        [[ "$reference" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ &&
          -f "$BUNDLE_DIR/$reference" && ! -L "$BUNDLE_DIR/$reference" ]] ||
          return 1
        ;;
      unavailable:captured)
        [[ "$reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-metrics\.prom$ ]] ||
          return 1
        unavailable_phase="${BASH_REMATCH[1]}"
        [[ "$capture_id" == "$unavailable_phase" ]] || return 1
        if [[ -z "${VALIDATED_OBI_UNAVAILABLE_REFERENCES[$reference]+present}" ]]; then
          [[ ! -e "$BUNDLE_DIR/phases/$unavailable_phase/obi-identity.json" &&
            ! -L "$BUNDLE_DIR/phases/$unavailable_phase/obi-identity.json" &&
            "$(stat -Lc '%s' -- "$BUNDLE_DIR/$reference")" == 12 &&
            "$(<"$BUNDLE_DIR/$reference")" == unavailable ]] || return 1
          VALIDATED_OBI_UNAVAILABLE_REFERENCES["$reference"]=1
        fi
        ;;
      pair:captured)
        [[ "$reference" =~ ^obi-metric-pairs/([a-z0-9][a-z0-9-]{0,63})\.json$ &&
          "$capture_id" == "${BASH_REMATCH[1]}" ]] ||
          return 1
        validate_obi_metric_pair "$reference" || return 1
        printf '%s\n' "$reference" >>"$expected_pairs" || return 1
        if [[ "$java_reference" != __null__ ]]; then
          validate_java_diagnostics_reference "$java_reference" || return 1
          verify_reference_sha256 "$java_reference" "$java_digest" || return 1
        fi
        ;;
      *) return 1 ;;
    esac
    verify_reference_sha256 "$reference" "$expected_digest" || return 1
  done <"$capture_manifest"
  ((capture_count == expected_capture_count)) || return 1

  LC_ALL=C sort -- "$expected_pairs" >"$expected_pairs.sorted" || return 1
  [[ "$(LC_ALL=C sort -u -- "$expected_pairs" | awk 'END { print NR + 0 }')" == \
    "$(awk 'END { print NR + 0 }' "$expected_pairs")" ]] || return 1
  : >"$actual_pairs"
  if [[ -e "$BUNDLE_DIR/obi-metric-pairs" || -L "$BUNDLE_DIR/obi-metric-pairs" ]]; then
    [[ -d "$BUNDLE_DIR/obi-metric-pairs" &&
      ! -L "$BUNDLE_DIR/obi-metric-pairs" ]] || return 1
    while IFS= read -r -d '' path; do
      [[ -f "$path" && ! -L "$path" ]] || return 1
      reference="obi-metric-pairs/${path##*/}"
      [[ "$reference" =~ ^obi-metric-pairs/[a-z0-9][a-z0-9-]{0,63}\.json$ ]] ||
        return 1
      printf '%s\n' "$reference" >>"$actual_pairs" || return 1
    done < <(find -- "$BUNDLE_DIR/obi-metric-pairs" -mindepth 1 -maxdepth 1 -print0)
  fi
  LC_ALL=C sort -- "$actual_pairs" >"$actual_pairs.sorted" || return 1
  cmp -s -- "$expected_pairs.sorted" "$actual_pairs.sorted" || return 1

  jq -r '
    .boundaries[] as $boundary |
    $boundary.status_references[] |
    [
      $boundary.id, $boundary.state,
      ($boundary.not_applicable_reason // "__null__"),
      .reference, .sha256
    ] | @tsv
  ' <<<"$payload" >"$status_manifest" || return 1
  expected_status_count="$(jq -er \
    '[.boundaries[].status_references[]] | length' <<<"$payload")" || return 1
  : >"$expected_statuses"
  while IFS=$'\t' read -r \
    boundary_id boundary_state not_applicable_reason reference expected_digest; do
    [[ -n "$boundary_id" ]] || continue
    ((status_count += 1))
    [[ "$reference" =~ ^scenario-[a-z0-9][a-z0-9-]{0,95}-status\.json$ ]] ||
      return 1
    if [[ -z "${VALIDATED_STATUS_REFERENCES[$reference]+present}" ]]; then
      validate_single_json_object \
        "$reference" "$OBI_METRIC_BOUNDARY_STATUS_MAX_BYTES" || return 1
      VALIDATED_STATUS_REFERENCES["$reference"]=1
    fi
    verify_reference_sha256 "$reference" "$expected_digest" || return 1
    if [[ "$boundary_state" == not_applicable ]]; then
      [[ "$reference" == "scenario-$boundary_id-status.json" &&
        "$not_applicable_reason" != __null__ ]] || return 1
      jq -e --arg boundary_id "$boundary_id" \
        --arg reason "$not_applicable_reason" '
          .status == "not_applicable" and
          .obi_metric_boundary_ids == [$boundary_id] and
          .reason == $reason
        ' "$BUNDLE_DIR/$reference" >/dev/null || return 1
    fi
    printf '%s\n' "$reference" >>"$expected_statuses" || return 1
  done <"$status_manifest"
  ((status_count == expected_status_count)) || return 1

  LC_ALL=C sort -u -- "$expected_statuses" >"$expected_statuses.sorted" || return 1
  find -- "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 \
    -name 'scenario-*-status.json' -printf '%f\n' |
    if [[ "$VERIFICATION_MODE" == raw-v3 &&
      "$RAW_V3_KIND" == assertion-failure ]]; then
      LC_ALL=C grep -v -x 'scenario-assertion-failure-status.json' || true
    else
      cat
    fi | LC_ALL=C sort \
    >"$actual_statuses" || return 1
  cmp -s -- "$expected_statuses.sorted" "$actual_statuses" || return 1
  while IFS= read -r reference; do
    [[ -n "$reference" ]] || continue
    jq -e '
      (.obi_metric_boundary_ids | type == "array" and length >= 1) and
      ([.obi_metric_boundary_ids[]] | length == (unique | length)) and
      all(.obi_metric_boundary_ids[];
        type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$"))
    ' "$BUNDLE_DIR/$reference" >/dev/null || return 1
    jq -r --arg reference "$reference" '
      [.boundaries[] |
        select(any(.status_references[]; .reference == $reference)) | .id] |
      unique[]
    ' <<<"$payload" | LC_ALL=C sort >"$expected_owners" || return 1
    jq -r '.obi_metric_boundary_ids[]' "$BUNDLE_DIR/$reference" |
      LC_ALL=C sort >"$actual_owners" || return 1
    cmp -s -- "$expected_owners" "$actual_owners" || return 1
  done <"$expected_statuses.sorted"

  OBI_METRIC_BOUNDARY_INDEX_PAYLOAD="$payload"
  OBI_METRIC_BOUNDARY_INDEX_SHA256="$index_digest"
}

validate_terminal_obi_metrics() {
  local -r relative_path='terminal-obi-metrics.json'
  local -r terminal="$BUNDLE_DIR/$relative_path"
  local pair_reference=""
  local boundary=""

  validate_single_json_object "$relative_path" "$OBI_METRIC_PAIR_MAX_BYTES" ||
    return 1
  jq -e '
    keys == ["available", "pair", "pair_reference", "schema", "sealed"] and
    .schema == "obi-java-remote-parent-terminal-metrics-v1" and
    .sealed == true and
    .available == true and
    (.pair_reference | type == "string") and
    (.pair | type == "object")
  ' "$terminal" >/dev/null || return 1
  pair_reference="$(jq -er '.pair_reference' "$terminal")" || return 1
  [[ "$pair_reference" =~ ^obi-metric-pairs/([a-z0-9][a-z0-9-]{0,63})\.json$ ]] ||
    return 1
  boundary="${BASH_REMATCH[1]}"
  validate_obi_metric_pair "$pair_reference" || return 1
  [[ "$(jq -er '.pair.boundary' "$terminal")" == "$boundary" ]] || return 1
  jq -e -s '
    length == 2 and
    .[0].pair == .[1]
  ' "$terminal" "$BUNDLE_DIR/$pair_reference" >/dev/null
}

validate_terminal_evidence_crosslinks() {
  local -r java_terminal="$BUNDLE_DIR/terminal-java-diagnostics.json"
  local -r obi_terminal="$BUNDLE_DIR/terminal-obi-metrics.json"
  local java_phase=""
  local java_reference=""
  local after_reference=""
  local after_phase=""

  java_phase="$(jq -er '.phase' "$java_terminal")" || return 1
  java_reference="$(jq -er '.reference' "$java_terminal")" || return 1
  after_reference="$(jq -er '.pair.after.identity_reference' "$obi_terminal")" ||
    return 1
  [[ "$after_reference" =~ ^phases/([a-z0-9][a-z0-9-]{0,63})/obi-identity\.json$ ]] ||
    return 1
  after_phase="${BASH_REMATCH[1]}"
  [[ "$java_phase" == "$after_phase" &&
    "$java_reference" == "phases/$after_phase/java-diagnostics.txt" ]]
}

journal_paths_are_absent() {
  [[ ! -e "$BUNDLE_DIR/obi-metric-boundary-index.json" &&
    ! -L "$BUNDLE_DIR/obi-metric-boundary-index.json" &&
    ! -e "$BUNDLE_DIR/.obi-metric-boundary-index.freeze" &&
    ! -L "$BUNDLE_DIR/.obi-metric-boundary-index.freeze" ]]
}

validate_terminal_obi_metrics_v2() {
  local -r relative_path='terminal-obi-metrics.json'
  local -r terminal="$BUNDLE_DIR/$relative_path"
  local active_boundary_id=""
  local pair_state=""
  local pair_reference=""

  [[ -n "$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" &&
    "$OBI_METRIC_BOUNDARY_INDEX_SHA256" =~ ^[0-9a-f]{64}$ ]] || return 1
  validate_single_json_object "$relative_path" "$OBI_METRIC_PAIR_MAX_BYTES" ||
    return 1
  jq -e --arg index_digest "$OBI_METRIC_BOUNDARY_INDEX_SHA256" '
    .schema == "obi-java-remote-parent-terminal-metrics-v2" and
    .sealed == true and
    .boundary_index_reference == "obi-metric-boundary-index.json" and
    .boundary_index_sha256 == $index_digest
  ' "$terminal" >/dev/null || return 1
  active_boundary_id="$(jq -r '
    [.boundaries[] | select(.state == "active") | .id] |
    if length == 0 then "" elif length == 1 then .[0]
    else error("multiple active boundaries") end
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD")" || return 1
  if [[ -z "$active_boundary_id" ]]; then
    jq -e '
      keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "reason", "schema", "sealed"
      ] and
      .available == false and .active_boundary_id == null and
      .reason == "no-active-boundary"
    ' "$terminal" >/dev/null
    return
  fi
  pair_state="$(jq -r --arg boundary_id "$active_boundary_id" '
    [.boundaries[] | select(.id == $boundary_id) | .captures[] |
      select(.kind == "pair") | .state] |
    if length == 0 then "none" else .[-1] end
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD")" || return 1
  if [[ "$pair_state" != captured ]]; then
    jq -e --arg active_boundary_id "$active_boundary_id" '
      keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "reason", "schema", "sealed"
      ] and
      .available == false and .active_boundary_id == $active_boundary_id and
      .reason == "active-boundary-incomplete"
    ' "$terminal" >/dev/null
    return
  fi
  pair_reference="$(jq -er --arg boundary_id "$active_boundary_id" '
    [.boundaries[] | select(.id == $boundary_id) | .captures[] |
      select(.kind == "pair")][-1].pair_reference
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD")" || return 1
  jq -e --arg active_boundary_id "$active_boundary_id" \
    --arg pair_reference "$pair_reference" '
      keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "pair", "pair_reference", "schema", "sealed"
      ] and
      .available == true and .active_boundary_id == $active_boundary_id and
      .pair_reference == $pair_reference and (.pair | type == "object")
    ' "$terminal" >/dev/null || return 1
  jq -e -s 'length == 2 and .[0].pair == .[1]' \
    "$terminal" "$BUNDLE_DIR/$pair_reference" >/dev/null
}

validate_terminal_java_diagnostics_context() {
  local -r terminal="$BUNDLE_DIR/terminal-java-diagnostics.json"
  local active_boundary_id=""
  local expected_reference=""

  validate_terminal_java_diagnostics_any || return 1
  active_boundary_id="$(jq -r '
    [.boundaries[] | select(.state == "active") | .id] |
    if length == 0 then "" elif length == 1 then .[0]
    else error("multiple active boundaries") end
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD")" || return 1
  # With no active boundary the last valid Java checkpoint remains independent.
  [[ -n "$active_boundary_id" ]] || return 0
  expected_reference="$(jq -r --arg boundary_id "$active_boundary_id" '
    [.boundaries[] | select(.id == $boundary_id) | .captures][0] as $captures |
    [$captures | to_entries[] | select(.value.kind == "pair")] as $pairs |
    if ($pairs | length) == 0 then
      [$captures[] | select(.kind == "java" and .state == "captured") |
        .reference] | if length == 0 then "" else .[-1] end
    elif $pairs[-1].value.state == "captured" then
      ($pairs[-1].value.java_reference // "")
    else
      [$captures | to_entries[] |
        select(.key > $pairs[-1].key and .value.kind == "java" and
          .value.state == "captured") | .value.reference] |
      if length == 0 then "" else .[-1] end
    end
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD")" || return 1
  if [[ -z "$expected_reference" ]]; then
    jq -e '.available == false' "$terminal" >/dev/null
  else
    jq -e --arg reference "$expected_reference" '
      .available == true and .reference == $reference
    ' "$terminal" >/dev/null
  fi
}

validate_pre_v2_run_status() {
  local -r evidence_id="$1"
  local -r allow_historical_status_schema="$2"

  journal_paths_are_absent || return 1
  jq -e -s --arg evidence_id "$evidence_id" \
    --argjson allow_historical_status_schema "$allow_historical_status_schema" '
    length == 1 and
    (.[0] |
      type == "object" and
      (has("schema") | not) and
      .status == "passed" and
      .exit_status == 0 and
      .acceptance_evidence == true and
      .failure_stage == "none" and
      .failure_line == 0 and
      .evidence_id == $evidence_id and
      (has("evidence_directory") | not) and
      (if $allow_historical_status_schema then
        ((has("acceptance_evidence_reason") | not) or
          .acceptance_evidence_reason == "none")
      else
        .acceptance_evidence_reason == "none"
      end))
  ' "$BUNDLE_DIR/run-status.json" >/dev/null
}

validate_run_status_v2() {
  local -r evidence_id="$1"

  journal_paths_are_absent || return 1
  reset_reference_validation_caches
  require_regular_file terminal-java-diagnostics.json
  require_regular_file terminal-obi-metrics.json
  validate_terminal_java_diagnostics || return 1
  validate_terminal_obi_metrics || return 1
  validate_terminal_evidence_crosslinks || return 1
  jq -e -s --arg evidence_id "$evidence_id" '
    length == 3 and
    (.[0] |
      type == "object" and
      keys == [
        "acceptance_evidence", "acceptance_evidence_reason", "evidence_id",
        "exit_status", "failure_line", "failure_stage",
        "java_bridge_diagnostics", "java_bridge_diagnostics_reference",
        "obi_metric_evidence", "obi_metric_evidence_reference", "schema", "status"
      ] and
      .schema == "obi-apache-java-https-run-status-v2" and
      .status == "passed" and
      .exit_status == 0 and
      .acceptance_evidence == true and
      .acceptance_evidence_reason == "none" and
      .failure_stage == "none" and
      .failure_line == 0 and
      .evidence_id == $evidence_id and
      .java_bridge_diagnostics_reference == "terminal-java-diagnostics.json" and
      .obi_metric_evidence_reference == "terminal-obi-metrics.json") and
    .[0].java_bridge_diagnostics == .[1] and
    .[0].obi_metric_evidence == .[2]
  ' \
    "$BUNDLE_DIR/run-status.json" \
    "$BUNDLE_DIR/terminal-java-diagnostics.json" \
    "$BUNDLE_DIR/terminal-obi-metrics.json" >/dev/null
}

validate_run_status_v3() {
  local -r evidence_id="$1"
  local -r environment="$BUNDLE_DIR/environment.txt"

  require_regular_file terminal-java-diagnostics.json
  require_regular_file terminal-obi-metrics.json
  require_regular_file obi-metric-boundary-index.json
  require_regular_file .obi-metric-boundary-index.freeze
  validate_obi_metric_boundary_index "$environment" || return 1
  jq -e '
    all(.boundaries[];
      .state == "complete" or .state == "not_applicable")
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" >/dev/null || return 1
  validate_terminal_java_diagnostics_context || return 1
  validate_terminal_obi_metrics_v2 || return 1
  jq -e -s --arg evidence_id "$evidence_id" \
    --arg index_digest "$OBI_METRIC_BOUNDARY_INDEX_SHA256" '
    length == 3 and
    (.[0] |
      type == "object" and
      keys == [
        "acceptance_evidence", "acceptance_evidence_reason", "evidence_id",
        "exit_status", "failure_line", "failure_stage",
        "java_bridge_diagnostics", "java_bridge_diagnostics_reference",
        "obi_metric_boundary_index_reference", "obi_metric_boundary_index_sha256",
        "obi_metric_evidence", "obi_metric_evidence_reference", "schema", "status"
      ] and
      .schema == "obi-apache-java-https-run-status-v3" and
      .status == "passed" and .exit_status == 0 and
      .acceptance_evidence == true and .acceptance_evidence_reason == "none" and
      .failure_stage == "none" and .failure_line == 0 and
      .evidence_id == $evidence_id and
      .java_bridge_diagnostics_reference == "terminal-java-diagnostics.json" and
      .obi_metric_evidence_reference == "terminal-obi-metrics.json" and
      .obi_metric_boundary_index_reference == "obi-metric-boundary-index.json" and
      .obi_metric_boundary_index_sha256 == $index_digest) and
    .[0].java_bridge_diagnostics == .[1] and
    .[0].obi_metric_evidence == .[2]
  ' \
    "$BUNDLE_DIR/run-status.json" \
    "$BUNDLE_DIR/terminal-java-diagnostics.json" \
    "$BUNDLE_DIR/terminal-obi-metrics.json" >/dev/null
}

validate_raw_v3_run_status() {
  local -r kind="$1"
  local -r environment="$BUNDLE_DIR/environment.txt"

  require_regular_file terminal-java-diagnostics.json
  require_regular_file terminal-obi-metrics.json
  require_regular_file obi-metric-boundary-index.json
  require_regular_file .obi-metric-boundary-index.freeze
  validate_obi_metric_boundary_index "$environment" || {
    printf '%s: raw run-status predicate failed: boundary-index-authority\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  jq -e 'all(.boundaries[]; .state == "complete" or .state == "not_applicable")' \
    <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" >/dev/null || {
    printf '%s: raw run-status predicate failed: terminal-boundary-states\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  jq -e '
    .selection.requested_transport == "getsockopt" and
    .selection.selected_transport == "getsockopt" and
    .selection.repeat_count == 1 and
    all(.boundaries[].captures[]; .kind != "artifact")
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" >/dev/null || {
    printf '%s: raw run-status predicate failed: fixed-boundary-selection\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  validate_terminal_java_diagnostics_context || {
    printf '%s: raw run-status predicate failed: terminal-java-authority\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  validate_terminal_obi_metrics_v2 || {
    printf '%s: raw run-status predicate failed: terminal-obi-authority\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  case "$kind" in
    acceptance)
      jq -e -s \
        --arg index_digest "$OBI_METRIC_BOUNDARY_INDEX_SHA256" '
          length == 3 and
          (.[0] |
            type == "object" and
            keys == [
              "acceptance_evidence", "acceptance_evidence_reason",
              "evidence_directory", "exit_status",
              "failure_line", "failure_stage", "java_bridge_diagnostics",
              "java_bridge_diagnostics_reference",
              "obi_metric_boundary_index_reference",
              "obi_metric_boundary_index_sha256", "obi_metric_evidence",
              "obi_metric_evidence_reference", "schema", "status"
            ] and
            .schema == "obi-apache-java-https-run-status-v3" and
            .status == "passed" and .exit_status == 0 and
            .acceptance_evidence == true and
            .acceptance_evidence_reason == "none" and
            .failure_stage == "none" and .failure_line == 0 and
            (.evidence_directory | type == "string" and startswith("/") and
              length >= 2 and length <= 4096 and
              (contains("\n") or contains("\r") | not)) and
            .java_bridge_diagnostics_reference ==
              "terminal-java-diagnostics.json" and
            .obi_metric_evidence_reference == "terminal-obi-metrics.json" and
            .obi_metric_boundary_index_reference ==
              "obi-metric-boundary-index.json" and
            .obi_metric_boundary_index_sha256 == $index_digest) and
          .[0].java_bridge_diagnostics == .[1] and
          .[0].obi_metric_evidence == .[2]
        ' "$BUNDLE_DIR/run-status.json" \
          "$BUNDLE_DIR/terminal-java-diagnostics.json" \
          "$BUNDLE_DIR/terminal-obi-metrics.json" >/dev/null || {
        printf '%s: raw run-status predicate failed: acceptance-envelope\n' \
          "$SCRIPT_NAME" >&2
        return 1
      }
      ;;
    assertion-failure)
      jq -e -s \
        --arg index_digest "$OBI_METRIC_BOUNDARY_INDEX_SHA256" '
          length == 3 and
          (.[0] |
            type == "object" and
            keys == [
              "acceptance_evidence", "acceptance_evidence_reason",
              "evidence_directory", "exit_status",
              "failure_line", "failure_stage", "java_bridge_diagnostics",
              "java_bridge_diagnostics_reference",
              "obi_metric_boundary_index_reference",
              "obi_metric_boundary_index_sha256", "obi_metric_evidence",
              "obi_metric_evidence_reference", "schema", "status"
            ] and
            .schema == "obi-apache-java-https-run-status-v3" and
            .status == "failed" and .exit_status == 2 and
            .acceptance_evidence == false and
            .acceptance_evidence_reason ==
              "deliberate-assertion-failure,targeted-scenario" and
            .failure_stage == "deliberate-assertion-failure" and
            (.failure_line | type == "number" and floor == . and . > 0) and
            (.evidence_directory | type == "string" and startswith("/") and
              length >= 2 and length <= 4096 and
              (contains("\n") or contains("\r") | not)) and
            .java_bridge_diagnostics_reference ==
              "terminal-java-diagnostics.json" and
            .obi_metric_evidence_reference == "terminal-obi-metrics.json" and
            .obi_metric_boundary_index_reference ==
              "obi-metric-boundary-index.json" and
            .obi_metric_boundary_index_sha256 == $index_digest) and
          .[0].java_bridge_diagnostics == .[1] and
          .[0].obi_metric_evidence == .[2]
        ' "$BUNDLE_DIR/run-status.json" \
          "$BUNDLE_DIR/terminal-java-diagnostics.json" \
          "$BUNDLE_DIR/terminal-obi-metrics.json" >/dev/null || {
        printf '%s: raw run-status predicate failed: assertion-envelope\n' \
          "$SCRIPT_NAME" >&2
        return 1
      }
      ;;
    *) return 1 ;;
  esac
}

validate_raw_source_provenance() {
  local -r kind="$1"
  local -r environment="$BUNDLE_DIR/environment.txt"
  local -r source_state="$BUNDLE_DIR/source-state.txt"
  local revision=""
  local source_state_revision=""
  local bridge_revision=""
  local source_tree_sha256=""
  local state_tree_sha256=""
  local bridge_tree_sha256=""
  local manifest_tree_sha256=""
  local expected_manifest="$TMP_DIR/raw-source-tree.manifest"
  local expected_scenario="all"
  local expected_acceptance="true"
  local expected_reason="none"
  local expected_invocation='./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3'
  local invocation=""

  if [[ "$kind" == assertion-failure ]]; then
    expected_scenario="assertion-failure"
    expected_acceptance="false"
    expected_reason="deliberate-assertion-failure,targeted-scenario"
    expected_invocation='./examples/apache-java-https/run.sh --transport getsockopt --scenario assertion-failure'
  fi
  validate_canonical_key_value_order "$environment" \
    invocation revision dirty source_tree_sha256 source_tree_manifest_schema \
    tracked_patch_sha256 patch_identity_sha256 transport agent_distribution \
    tls_protocol obi_log_level scenario request_count repeat_count scenario_seed \
    bridge_build_mode acceptance_evidence acceptance_evidence_reason \
    compose_project command_timeout_seconds readiness_timeout_seconds \
    architecture kernel openssl docker compose || {
    printf '%s: raw provenance predicate failed: environment-key-value-shape\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  validate_canonical_key_value_order "$source_state" \
    revision dirty source_tree_sha256 source_tree_manifest_schema \
    tracked_patch_sha256 patch_identity_sha256 || {
    printf '%s: raw provenance predicate failed: source-state-key-value-shape\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  revision="$(key_value "$environment" revision)" || {
    printf '%s: raw provenance predicate failed: environment-revision\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  invocation="$(key_value "$environment" invocation)" || {
    printf '%s: raw provenance predicate failed: environment-invocation\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  [[ "$invocation" == "$expected_invocation" ]] || {
    printf '%s: raw provenance predicate failed: fixed-invocation-profile\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  source_state_revision="$(key_value "$source_state" revision)" || {
    printf '%s: raw provenance predicate failed: source-state-revision\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  bridge_revision="$(read_single_hex "$BUNDLE_DIR/bridge-source-revision.txt" 40)" ||
    return 1
  is_sha1 "$revision" || {
    printf '%s: raw provenance predicate failed: source-revision-format\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  [[ "$revision" == "$source_state_revision" && "$revision" == "$bridge_revision" ]] ||
    {
      printf '%s: raw provenance predicate failed: source-revision-agreement\n' \
        "$SCRIPT_NAME" >&2
      return 1
    }
  source_tree_sha256="$(key_value "$environment" source_tree_sha256)" || return 1
  state_tree_sha256="$(key_value "$source_state" source_tree_sha256)" || return 1
  bridge_tree_sha256="$(read_single_hex "$BUNDLE_DIR/bridge-source-tree.sha256" 64)" ||
    return 1
  manifest_tree_sha256="$(sha256sum <"$BUNDLE_DIR/source-tree.manifest")" || return 1
  manifest_tree_sha256="${manifest_tree_sha256%% *}"
  is_sha256 "$source_tree_sha256" || {
    printf '%s: raw provenance predicate failed: source-tree-digest-format\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  [[ "$source_tree_sha256" == "$state_tree_sha256" &&
    "$source_tree_sha256" == "$bridge_tree_sha256" &&
    "$source_tree_sha256" == "$manifest_tree_sha256" ]] || {
    printf '%s: raw provenance predicate failed: source-tree-digest-agreement\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  REPO_ROOT="$TRUSTED_REPO_ROOT"
  write_source_tree_manifest_for_revision "$revision" "$expected_manifest" || {
    printf '%s: raw provenance predicate failed: source-tree-reconstruction\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  cmp -s -- "$expected_manifest" "$BUNDLE_DIR/source-tree.manifest" || {
    printf '%s: raw provenance predicate failed: source-tree-exact-match\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  [[ "$(key_value "$environment" source_tree_manifest_schema)" == git-tree-v2 &&
    "$(key_value "$source_state" source_tree_manifest_schema)" == git-tree-v2 &&
    "$(key_value "$environment" dirty)" == false &&
    "$(key_value "$source_state" dirty)" == false &&
    "$(key_value "$environment" tracked_patch_sha256)" == "$EMPTY_SHA256" &&
    "$(key_value "$source_state" tracked_patch_sha256)" == "$EMPTY_SHA256" &&
    "$(key_value "$environment" patch_identity_sha256)" =~ ^[0-9a-f]{64}$ &&
    "$(key_value "$environment" patch_identity_sha256)" == \
      "$(key_value "$source_state" patch_identity_sha256)" &&
    "$(key_value "$environment" transport)" == getsockopt &&
    "$(key_value "$environment" agent_distribution)" == otel &&
    "$(key_value "$environment" tls_protocol)" == TLSv1.3 &&
    "$(key_value "$environment" obi_log_level)" == info &&
    "$(key_value "$environment" scenario)" == "$expected_scenario" &&
    "$(key_value "$environment" request_count)" == 0 &&
    "$(key_value "$environment" repeat_count)" == 1 &&
    "$(key_value "$environment" scenario_seed)" == 1 &&
    "$(key_value "$environment" bridge_build_mode)" == fresh &&
    "$(key_value "$environment" architecture)" =~ ^(x86_64|aarch64)$ &&
    "$(key_value "$environment" acceptance_evidence)" == "$expected_acceptance" &&
    "$(key_value "$environment" acceptance_evidence_reason)" == "$expected_reason" &&
    "$(key_value "$environment" command_timeout_seconds)" == 180 &&
    "$(key_value "$environment" readiness_timeout_seconds)" == 120 &&
    "$(key_value "$environment" compose_project)" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ &&
    -n "$(key_value "$environment" kernel)" &&
    -n "$(key_value "$environment" openssl)" &&
    "$(key_value "$environment" docker)" =~ ^[0-9][A-Za-z0-9.+~-]{0,63}$ &&
    "$(key_value "$environment" compose)" =~ ^[0-9][A-Za-z0-9.+~-]{0,63}$ ]] ||
    {
      printf '%s: raw provenance predicate failed: fixed-environment-profile\n' \
        "$SCRIPT_NAME" >&2
      return 1
    }
  [[ -f "$BUNDLE_DIR/git-status.txt" && ! -L "$BUNDLE_DIR/git-status.txt" &&
    ! -s "$BUNDLE_DIR/git-status.txt" ]] || {
    printf '%s: raw provenance predicate failed: clean-git-status\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  jq -e --arg revision "$revision" --arg tree "$source_tree_sha256" '
    keys == ["obi_java_agent_sha256", "obi_otel_extension_sha256",
      "source_revision", "source_tree_sha256"] and
    .source_revision == $revision and .source_tree_sha256 == $tree and
    (.obi_java_agent_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.obi_otel_extension_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
  ' "$BUNDLE_DIR/bridge-artifacts.json" >/dev/null || {
    printf '%s: raw provenance predicate failed: bridge-artifact-authority\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
  validate_raw_v3_run_status "$kind" || {
    printf '%s: raw provenance predicate failed: run-status-authority\n' \
      "$SCRIPT_NAME" >&2
    return 1
  }
}

validate_raw_scenario_graph() {
  local -r scenario="$1"
  local -r result="scenario-$scenario.json"
  local -r status="scenario-$scenario-status.json"
  local expected_count=""
  local expected_endpoint='/api/echo'

  case "$scenario" in
    basic|timeout-retry) expected_count=1 ;;
    keepalive|pipelining) expected_count=10 ;;
    concurrency) expected_count=16 ;;
    connection-churn|fd-port-reuse) expected_count=32 ;;
    slow-body) expected_count=8 ;;
    tls-boundary) expected_count=3 ;;
    coalesced-bridge) expected_count=2 ;;
    pressure) expected_count=128 ;;
    handoff) expected_count=4 ;;
    *) return 1 ;;
  esac
  case "$scenario" in
    pressure|handoff) expected_endpoint='/api/handoff' ;;
    tls-boundary) expected_endpoint='' ;;
    coalesced-bridge) expected_endpoint='/api/coalesced-bridge' ;;
  esac

  validate_single_json_object "$result" "$RAW_V3_SCENARIO_MAX_BYTES" ||
    return 1
  [[ "$(awk 'END { print NR + 0 }' "$BUNDLE_DIR/$result")" -le \
    "$RAW_V3_SCENARIO_MAX_LINES" ]] || return 1
  validate_single_json_object "$status" "$OBI_METRIC_BOUNDARY_STATUS_MAX_BYTES" ||
    return 1
  jq -e --arg scenario "$scenario" --arg endpoint "$expected_endpoint" \
    --argjson expected_count "$expected_count" '
    . as $root |
    def timestamp_key:
      capture("^(?<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\\.(?<fraction>[0-9]{1,9}))?Z$") as $parts |
      [($parts.base + "Z" | fromdateiso8601),
        (((($parts.fraction // "") + "000000000")[0:9]) | tonumber)];
    def padded_index:
      tostring as $value | if ($value | length) < 2 then "0" + $value else $value end;
    (.started_at | timestamp_key) as $started |
    (.finished_at | timestamp_key) as $finished |
    .status == "passed" and .scenario == $scenario and
    .seed == 1 and .request_count == $expected_count and
    (if $scenario == "tls-boundary" then
      [.cases[].request.endpoint] == [
        "/api/tls-boundary/split", "/api/tls-boundary/coalesced",
        "/api/tls-boundary/coalesced"
      ]
    else all(.cases[].request; .endpoint == $endpoint) end) and
    ($started < $finished) and
    (($finished[0] - $started[0]) < 75 or
      (($finished[0] - $started[0]) == 75 and
        $finished[1] <= $started[1])) and
    (.traffic_elapsed_nanos | type == "number" and floor == . and
      . >= 1 and . <= 75000000000) and
    (.throughput_per_second | type == "number" and . > 0) and
    (.latency | keys == ["p50_nanos", "p95_nanos", "p99_nanos"] and
      all(.[]; type == "number" and floor == . and
        . >= 1 and . <= 75000000000)) and
    (.request_count as $request_count |
      .cases | type == "array" and length == $request_count) and
    ([.cases[].request.marker] | length == (unique | length)) and
    (.cases | to_entries | all(.[];
      .key as $index | .value as $case |
      $case.request.marker ==
        ($scenario + "-" + ($index | padded_index) + "-" +
          ($case.request.marker | split("-")[-1])) and
      ($case.request.marker | test("-[0-9a-f]{16}$")))) and
    all(.cases[];
      (.latency_nanos | type == "number" and floor == . and
        . >= 1 and . <= 75000000000) and
      (.request.marker | type == "string" and length >= 1 and length <= 128) and
      .response.marker == .request.marker and .response.secure == true and
      .response.protocol == "HTTP/1.1" and
      .response.tls_protocol == "TLSv1.3" and
      (.response.backend_connection_id | type == "number" and floor == . and
        . >= 1 and . <= 9007199254740991) and
      (.response.backend_remote_port | type == "number" and floor == . and
        . >= 1 and . <= 65535) and
      (if .response.backend_socket_fd == null then true else
        (.response.backend_socket_fd | type == "number" and floor == . and
          . >= 0 and . <= 1048576) end) and
      (.response.tls_read_events | type == "number" and floor == . and
        . >= -1 and . <= 9007199254740991) and
      (.response.tls_read_bytes | type == "number" and floor == . and
        . >= -1 and . <= 9007199254740991) and
      (.response.tls_cipher | type == "string" and
        test("^[A-Z0-9_-]{1,96}$")) and
      (.trace.spans | type == "array") and
      ((.trace.related_spans // []) | type == "array") and
      .trace.marker == .request.marker and
      (.trace.receiver_instance_id | type == "string" and length >= 1 and
        length <= 128) and
      (.trace.reset_generation | type == "number" and floor == . and . >= 0) and
      (.trace.received_batches | type == "number" and floor == . and . >= 0) and
      (.trace.received_spans | type == "number" and floor == . and . >= 0) and
      .trace.dropped_spans == 0 and .trace.dropped_count_spans == 0 and
      .trace.dropped_value_limit_spans == 0 and
      .trace.dropped_retained_limit_spans == 0 and
      (.trace.omitted_related_spans // 0) == 0 and
      (.trace.ambiguous_related_spans // 0) == 0 and
      (.trace.retained_bytes | type == "number" and floor == . and . >= 0) and
      (.trace.max_retained_bytes | type == "number" and floor == . and . >= 1) and
      (.trace.max_value_bytes | type == "number" and floor == . and . >= 1)) and
    ([.cases[].trace.receiver_instance_id] | unique | length) == 1 and
    ([.cases[].trace.reset_generation] | unique | length) == 1
  ' "$BUNDLE_DIR/$result" >/dev/null || {
    printf '%s: raw scenario predicate failed: %s-result-envelope\n' \
      "$SCRIPT_NAME" "$scenario" >&2
    return 1
  }
  jq -e --arg scenario "$scenario" '
    keys == ["after_phase", "before_phase", "exit_status", "java_diagnostics",
      "metric_status", "obi_metric_boundary_ids", "obi_metric_evidence",
      "pressure_correlation", "receive_coordination_maps", "result",
      "scenario", "scenario_reconciliation", "status", "stderr"] and
    .status == "passed" and .scenario == $scenario and .exit_status == 0 and
    .metric_status == 0 and .result == ("scenario-" + $scenario + ".json")
  ' "$BUNDLE_DIR/$status" >/dev/null || {
    printf '%s: raw scenario predicate failed: %s-status-envelope\n' \
      "$SCRIPT_NAME" "$scenario" >&2
    return 1
  }

  if [[ "$scenario" == coalesced-bridge ]]; then
    jq -e '
      def trace_id:
        type == "string" and test("^[0-9a-f]{32}$") and
        . != "00000000000000000000000000000000";
      def span_id:
        type == "string" and test("^[0-9a-f]{16}$") and
        . != "0000000000000000";
      def zero_parent:
        . == null or . == "" or . == "0000000000000000";
      def url_path($value):
        $value |
        sub("^[A-Za-z][A-Za-z0-9+.-]*://[^/]*"; "") |
        split("#")[0] | split("?")[0];
      def endpoint($span; $wanted):
        $span.attributes["url.path"] == $wanted or
        $span.attributes["http.route"] == $wanted or
        (($span.attributes["url.full"] // null) != null and
          url_path($span.attributes["url.full"]) == $wanted);
      def marker($span):
        [$span.attributes | to_entries[] |
          {key: (.key | ascii_downcase), value: .value} |
          select(.key == "obi.related.marker.invalid" or
            .key == "http.request.header.x-obi-demo-id" or
            .key == "http.request.header.x_obi_demo_id")] as $rows |
        if any($rows[]; .key == "obi.related.marker.invalid") then
          error("invalid marker attribute")
        elif any($rows[]; (.value | type) != "string" or .value == "") then
          error("invalid marker value")
        elif ([$rows[].value] | unique | length) > 1 then
          error("conflicting marker values")
        elif ($rows | length) == 0 then null else $rows[0].value end;
      def descends($spans; $descendant; $ancestor):
        def climb($parent_id; $seen):
          if ($parent_id | zero_parent) then false
          elif $parent_id == $ancestor.span_id then true
          elif ($seen | index($parent_id)) != null then false
          else
            [$spans[] | select(
              .trace_id == $descendant.trace_id and
              .service_name == $ancestor.service_name and
              .span_id == $parent_id)] as $parents |
            ($parents | length) == 1 and
              climb($parents[0].parent_span_id; $seen + [$parent_id])
          end;
        $descendant.trace_id == $ancestor.trace_id and
        $descendant.service_name == $ancestor.service_name and
        climb($descendant.parent_span_id; []);
      . as $root |
      [$root.cases[].trace.spans[]] as $spans |
      [$root.cases[] as $case |
        [$case.trace.spans[] | select(
          .service_name == "java-backend" and .kind == "SERVER" and
          marker(.) == $case.request.marker and
          endpoint(.; $case.request.endpoint))] |
        if length == 1 then .[0] else error("ambiguous Java root") end
      ] as $java_roots |
      [$spans[] | select(.service_name == "coalesced-source" and
        .kind == "SERVER" and endpoint(.; "/api/coalesced-source") and
        marker(.) == $root.cases[0].request.marker)] as $source_servers |
      [$spans[] | select(.service_name == "apache-proxy" and
        .kind == "SERVER" and endpoint(.; "/api/coalesced-source") and
        marker(.) == $root.cases[0].request.marker)] as $apache_servers |
      [$spans[] | select(.service_name == "apache-proxy" and
        .kind == "CLIENT" and endpoint(.; "/api/coalesced-source") and
        marker(.) == $root.cases[0].request.marker)] as $apache_clients |
      .request_count == 2 and
      ($root.connection_evidence |
        keys == ["frontend_connections", "frontend_protocol",
          "source_backend_tls_connections", "source_plaintext_sha256",
          "source_plaintext_write_bytes", "source_plaintext_write_calls",
          "source_request_boundaries"] and
        .frontend_connections == 1 and .frontend_protocol == "HTTP/1.1" and
        .source_backend_tls_connections == 1 and
        .source_plaintext_write_calls == 1 and
        (.source_plaintext_write_bytes | type == "number" and floor == . and
          . >= 1 and . <= 8192) and
        (.source_plaintext_sha256 | type == "string" and
          test("^[0-9a-f]{64}$")) and
        .source_request_boundaries == 2 and
        (.source_traceparent_header_count // 0) == 0) and
      ([.cases[].response.backend_connection_id] | unique | length) == 1 and
      ([.cases[].response.backend_remote_port] | unique | length) == 1 and
      all(.cases[].response;
        .backend_kind == "netty-coalesced-bridge" and
        (.coalesced_bridge |
          keys == ["failure_reason", "one_plaintext_receive",
            "parser_callback_generations", "parser_markers",
            "parser_request_count", "passed", "plaintext_callback_bytes",
            "plaintext_callback_count", "plaintext_sha256",
            "request_markers_exact", "traceparent_header_count"] and
          .passed == true and .failure_reason == "none" and
          .plaintext_callback_count == 1 and
          .plaintext_callback_bytes ==
            $root.connection_evidence.source_plaintext_write_bytes and
          .plaintext_sha256 ==
            $root.connection_evidence.source_plaintext_sha256 and
          .parser_request_count == 2 and
          .parser_callback_generations == [1, 1] and
          .parser_markers == [$root.cases[].request.marker] and
          .traceparent_header_count == 0 and
          .request_markers_exact == true and
          .one_plaintext_receive == true)) and
      ([$spans[] | .trace_id + "/" + .span_id] | length) ==
        ([$spans[] | .trace_id + "/" + .span_id] | unique | length) and
      all($spans[]; (.trace_id | trace_id) and (.span_id | span_id)) and
      ($java_roots | length) == 2 and
      all($java_roots[];
        (.parent_span_id | zero_parent) and
        (.flags | type == "number" and floor == . and . >= 0) and
        (((.flags / 256) | floor) % 2) == 1 and
        (((.flags / 512) | floor) % 2) == 0) and
      ([$java_roots[].trace_id] | unique | length) == 2 and
      ($source_servers | length) == 1 and ($apache_servers | length) == 1 and
      ($apache_clients | length) == 1 and
      ([$spans[] | select(.service_name == "coalesced-source" and
        .kind == "SERVER" and marker(.) == $root.cases[0].request.marker)] |
        length) == 1 and
      ([$spans[] | select(.service_name == "apache-proxy" and
        .kind == "SERVER" and marker(.) == $root.cases[0].request.marker)] |
        length) == 1 and
      ([$spans[] | select(.service_name == "apache-proxy" and
        .kind == "CLIENT" and marker(.) == $root.cases[0].request.marker)] |
        length) == 1 and
      ($source_servers[0].parent_span_id | zero_parent) and
      ($apache_servers[0].parent_span_id | zero_parent) and
      $source_servers[0].trace_id != $apache_servers[0].trace_id and
      descends($spans; $apache_clients[0]; $apache_servers[0]) and
      all($java_roots[];
        .trace_id != $source_servers[0].trace_id and
        .trace_id != $apache_servers[0].trace_id) and
      (.coalesced_bridge_correlation |
        .outcome == "receive_ambiguous" and .exact_hit_count == 0 and
        .explicit_root_count == 2 and .wrong_parent_count == 0 and
        .unresolved_count == 0 and .source_client_operations == 1 and
        .source_client_marker == "absent" and
        .apache_trigger_chain_proven == true and
        .source_operation_chain_proven == true and
        .source_plaintext_write_bytes ==
          $root.connection_evidence.source_plaintext_write_bytes and
        (.source_plaintext_write_bytes | type == "number" and floor == . and
          . >= 1 and . <= 8192) and
        .tls_read_delta == 1 and
        .tls_bytes_delta == .source_plaintext_write_bytes and
        .take_missing_delta == 2 and .discard_total_delta == 1 and
        .discard_ambiguous_delta == 1)
    ' "$BUNDLE_DIR/$result" >/dev/null || return 1
    jq -e -s '
      .[0].coalesced_bridge_correlation == .[1].scenario_reconciliation and
      .[1].receive_coordination_maps == .[2]
    ' "$BUNDLE_DIR/$result" "$BUNDLE_DIR/$status" \
      "$BUNDLE_DIR/receive-cursor-map-coalesced-bridge-status.json" >/dev/null ||
      return 1
    return
  fi
  jq -e --arg scenario "$scenario" '
    def trace_id:
      type == "string" and test("^[0-9a-f]{32}$") and
      . != "00000000000000000000000000000000";
    def span_id:
      type == "string" and test("^[0-9a-f]{16}$") and
      . != "0000000000000000";
    def zero_parent:
      . == null or . == "" or . == "0000000000000000";
    def marker($span):
      [$span.attributes | to_entries[] |
        {key: (.key | ascii_downcase), value: .value} |
        select(.key == "obi.related.marker.invalid" or
          .key == "http.request.header.x-obi-demo-id" or
          .key == "http.request.header.x_obi_demo_id")] as $rows |
      if any($rows[]; .key == "obi.related.marker.invalid") then
        error("invalid marker attribute")
      elif any($rows[]; (.value | type) != "string" or .value == "") then
        error("invalid marker value")
      elif ([$rows[].value] | unique | length) > 1 then
        error("conflicting marker values")
      elif ($rows | length) == 0 then null else $rows[0].value end;
    def url_path($value):
      $value | sub("^[A-Za-z][A-Za-z0-9+.-]*://[^/]*"; "") |
      split("#")[0] | split("?")[0];
    def endpoint_values($span):
      [($span.attributes["http.route"] // empty),
       ($span.attributes["url.path"] // empty),
       (($span.attributes["http.target"] // empty) | url_path(.)),
       (($span.attributes["http.url"] // empty) | url_path(.)),
       (($span.attributes["url.full"] // empty) | url_path(.))];
    def endpoint_exact($span; $wanted):
      endpoint_values($span) as $values |
      ($values | length) > 0 and all($values[]; . == $wanted);
    def endpoint_matches($span; $wanted):
      any(endpoint_values($span)[]; . == $wanted);
    def descends($spans; $descendant; $ancestor):
      def climb($parent_id; $seen):
        if ($parent_id | zero_parent) then false
        elif $parent_id == $ancestor.span_id then true
        elif ($seen | index($parent_id)) != null then false
        else
          [$spans[] | select(.trace_id == $descendant.trace_id and
            .service_name == $ancestor.service_name and
            .span_id == $parent_id)] as $parents |
          ($parents | length) == 1 and
            climb($parents[0].parent_span_id; $seen + [$parent_id])
        end;
      $descendant.trace_id == $ancestor.trace_id and
      $descendant.service_name == $ancestor.service_name and
      climb($descendant.parent_span_id; []);
    all(.cases[];
      . as $case |
      (.trace.spans + (.trace.related_spans // [])) as $spans |
      ([$spans[] |
        select(.service_name == "apache-proxy" and .kind == "CLIENT" and
          marker(.) == $case.request.marker and
          endpoint_matches(.; $case.request.endpoint))]) as $client |
      ([$spans[] |
        select(.service_name == "java-backend" and .kind == "SERVER" and
          (marker(.) == null or marker(.) == $case.request.marker))]) as $java |
      ([$spans[] |
        select(.service_name == "apache-proxy" and .kind == "SERVER" and
          (marker(.) == null or marker(.) == $case.request.marker))]) as $server |
      ($client | length) == 1 and ($java | length) == 1 and
      (if $scenario == "pipelining" then ($server | length) <= 1
       else ($server | length) == 1 end) and
      marker($java[0]) == $case.request.marker and
      endpoint_exact($java[0]; $case.request.endpoint) and
      ($client[0].trace_id | trace_id) and
      ($java[0].trace_id | trace_id) and
      ($client[0].span_id | span_id) and
      ($java[0].span_id | span_id) and
      (if $scenario == "pressure" then
        (($java[0].parent_span_id | zero_parent) or
          ($java[0].parent_span_id | span_id))
      else ($java[0].parent_span_id | span_id) end) and
      ([$spans[] | select(.trace_id == $java[0].trace_id and
        .parent_span_id == $java[0].parent_span_id and
        .span_id != $java[0].span_id)] | length) == 0 and
      (if ($server | length) == 1 then
        marker($server[0]) == $case.request.marker and
        endpoint_exact($server[0]; $case.request.endpoint) and
        ($server[0].trace_id | trace_id) and ($server[0].span_id | span_id) and
        ($server[0].parent_span_id | zero_parent) and
        descends($spans; $client[0]; $server[0])
      else ($client[0].parent_span_id | zero_parent) end) and
      $client[0].span_id != $java[0].span_id and
      ($client[0].flags | type == "number" and floor == . and . >= 0) and
      ($java[0].flags | type == "number" and floor == . and . >= 0) and
      (if $scenario == "pressure" and
          ($java[0].parent_span_id | zero_parent) then
        (($java[0].flags / 512 | floor) % 2) == 0 and
        $client[0].trace_id != $java[0].trace_id
      else
        $client[0].trace_id == $java[0].trace_id and
        $client[0].span_id == $java[0].parent_span_id and
        (($java[0].flags / 256 | floor) % 2) == 1 and
        (($java[0].flags / 512 | floor) % 2) == 1 and
        ($client[0].flags % 256) == ($java[0].flags % 256)
      end))
  ' "$BUNDLE_DIR/$result" >/dev/null || {
    printf '%s: raw scenario predicate failed: %s-bridge-topology\n' \
      "$SCRIPT_NAME" "$scenario" >&2
    return 1
  }
  case "$scenario" in
    keepalive|pipelining|concurrency|fd-port-reuse|tls-boundary|pressure|handoff)
      jq -e '
        all(.cases[];
          ([.trace.spans[] | select(
            .service_name == "java-backend" and .kind == "SERVER")] |
            length) == 1) and
        ([.cases[] as $case |
          [$case.trace.spans[] |
            select(.service_name == "java-backend" and .kind == "SERVER" and
              .attributes["http.request.header.x-obi-demo-id"] ==
                $case.request.marker and
              .attributes["url.path"] == $case.request.endpoint)][0] |
          [.trace_id, (.parent_span_id // "0000000000000000")]]) as $parents |
        ($parents | length) == ($parents | unique | length)
      ' "$BUNDLE_DIR/$result" >/dev/null || {
        printf '%s: raw scenario predicate failed: %s-distinct-java-parents\n' \
          "$SCRIPT_NAME" "$scenario" >&2
        return 1
      }
      ;;
  esac
  case "$scenario" in
    keepalive)
      jq -e '
        (has("connection_evidence") | not) and
        ([.cases[].response.backend_connection_id] | unique | length) == 1 and
        ([.cases[].response.backend_remote_port] | unique | length) == 1 and
        ([.cases[].response.tls_protocol] | unique | length) == 1 and
        ([.cases[].response.tls_cipher] | unique | length) == 1
      ' "$BUNDLE_DIR/$result" >/dev/null || {
        printf '%s: raw scenario predicate failed: keepalive-connection-shape\n' \
          "$SCRIPT_NAME" >&2
        return 1
      }
      ;;
    pipelining)
      jq -e '
        . as $root |
        ($root.cases[0].response.backend_connection_id) as $reused |
        ($root.connection_evidence |
          type == "object" and
          (keys == ["frontend_connections", "frontend_protocol",
            "pipelined_requests", "requests_written_before_first_read"]) and
          .frontend_connections == 1 and .frontend_protocol == "HTTP/1.1" and
          .pipelined_requests == 10 and
          .requests_written_before_first_read == 10) and
        all($root.cases[0:-1][];
          .response.backend_connection_id == $reused) and
        ([$root.cases[].response.backend_connection_id] | unique | length) <= 2
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      ;;
    concurrency)
      jq -e '
        . as $root |
        $root.connection_evidence as $e |
        ($e | type == "object" and
          (keys == ["concurrency_max_active", "concurrency_participants",
            "concurrency_release", "distinct_backend_workers",
            "distinct_concurrency_arrivals", "frontend_connections",
            "frontend_protocol"]) and
          .frontend_connections == 16 and
          .frontend_protocol == "HTTP/1.1" and
          .distinct_backend_workers == 16 and
          .distinct_concurrency_arrivals == 16 and
          .concurrency_participants == 16 and
          .concurrency_max_active == 16 and
          (.concurrency_release | type == "number" and floor == . and
            . >= 1 and . <= 9007199254740991)) and
        ($root.cases | map(.request.concurrency_batch) | unique) ==
          ["c0000000000000001"] and
        all($root.cases[].request; .concurrency_expected == 16) and
        all($root.cases[].response;
          (.backend_worker_id | type == "number" and floor == . and
            . >= 1 and . <= 9007199254740991)) and
        ([$root.cases[].response.backend_worker_id] | unique | length) == 16 and
        ([$root.cases[].response.backend_connection_id] | unique | length) >= 2 and
        all($root.cases[].response;
          .concurrency_batch == "c0000000000000001" and
          .concurrency_participants == 16 and .concurrency_max_active == 16 and
          .concurrency_release == $e.concurrency_release) and
        ([$root.cases[].response.concurrency_arrival] | sort) == [range(1; 17)]
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      jq -e -s '.[0].connection_evidence == .[1].scenario_reconciliation' \
        "$BUNDLE_DIR/$result" "$BUNDLE_DIR/$status" >/dev/null
      ;;
    connection-churn)
      jq -e '
        (has("connection_evidence") | not) and
        ([.cases[].response.backend_connection_id] | unique | length) >= 2
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      ;;
    fd-port-reuse)
      jq -e '
        . as $root |
        .connection_evidence as $e |
        ($e | keys) == [
          "backend_connections", "distinct_backend_connection_ids",
          "distinct_backend_remote_ports", "distinct_frontend_local_ports",
          "frontend_connections", "frontend_protocol",
          "reused_backend_file_descriptor",
          "reused_frontend_file_descriptor", "reused_frontend_local_port"
        ] and
        $e.frontend_connections == 32 and
        $e.frontend_protocol == "HTTP/1.1" and
        $e.distinct_frontend_local_ports == 1 and
        ($e.reused_frontend_local_port | type == "number" and floor == . and
          . >= 1 and . <= 65535) and
        ($e.reused_frontend_file_descriptor |
          type == "number" and floor == . and . >= 1 and . <= 1048576) and
        $e.backend_connections == 32 and
        $e.distinct_backend_connection_ids == 32 and
        $e.distinct_backend_connection_ids ==
          ([$root.cases[].response.backend_connection_id] | unique | length) and
        $e.distinct_backend_remote_ports ==
          ([$root.cases[].response.backend_remote_port] | unique | length) and
        all($root.cases[].response;
          (.backend_socket_fd | type == "number" and floor == . and
            . >= 1 and . <= 1048576)) and
        ($e.reused_backend_file_descriptor |
          type == "number" and floor == . and . >= 1 and . <= 1048576) and
        ([$root.cases[].response |
          select(.backend_socket_fd == $e.reused_backend_file_descriptor) |
          .backend_connection_id] | unique | length) >= 2
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      ;;
    slow-body)
      jq -e '
        . as $root |
        (has("connection_evidence") | not) and
        all(.cases[].response;
          (.tls_read_events | type == "number" and floor == . and . >= 0) and
          (.tls_read_bytes | type == "number" and floor == . and . >= 0)) and
        ([range(1; $root.request_count)] | all(.[];
          . as $index |
          ($root.cases[$index].response.tls_read_events -
            $root.cases[$index - 1].response.tls_read_events) >= 2 and
          ($root.cases[$index].response.tls_read_bytes -
            $root.cases[$index - 1].response.tls_read_bytes) >= 65536))
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      ;;
    tls-boundary)
      jq -e '
        def positive_bytes:
          type == "number" and floor == . and . >= 1 and . <= 73728;
        def positive_bounded:
          type == "number" and floor == . and . >= 1 and . <= 32;
        def trace_id:
          type == "string" and test("^[0-9a-f]{32}$") and
          . != "00000000000000000000000000000000";
        def span_id:
          type == "string" and test("^[0-9a-f]{16}$") and
          . != "0000000000000000";
        def url_path:
          sub("^[A-Za-z][A-Za-z0-9+.-]*://[^/]*"; "") |
          split("#")[0] | split("?")[0];
        def evidence_keys:
          ["coalescing_grace_expired", "coalescing_grace_millis",
            "decrypted_callback_lengths", "decrypted_total_bytes",
            "delivery_shape", "emission_order",
            "emission_parser_callback_order", "evidence_phase",
            "failure_reason", "fallback_reason",
            "first_response_keeps_alive", "handoff_before_parse",
            "headers_spanned_records", "mode", "parser_callback_count",
            "parser_callback_lengths", "parser_facing_coalesced",
            "parser_shape_exact", "parser_total_bytes", "passed",
            "request_body_bytes", "request_bytes_preserved",
            "request_complete", "request_count", "request_header_bytes",
            "request_header_decrypted_callback_counts", "request_order",
            "request_total_bytes",
            "requests_emitted_from_single_parser_callback",
            "response_connection_close", "response_forces_connection_close",
            "response_order", "split_buffers_forwarded_unchanged",
            "tls_application_record_legacy_versions",
            "tls_application_record_payload_lengths",
            "verification_buffer_bytes", "verification_buffer_limit_bytes",
            "verification_pair_digest_exact", "wire_decrypted_pairs_exact"];
        def positive_integer($maximum):
          type == "number" and floor == . and . >= 1 and . <= $maximum;
        def is_prefix($short; $long):
          ($short | length) <= ($long | length) and
          $long[0:($short | length)] == $short;
        def prefix_sum($values; $end):
          (($values[0:$end] | add) // 0);
        def exact_callback_segment_count($lengths; $start; $bytes):
          ($start + $bytes) as $end |
          [range(0; ($lengths | length) + 1) as $index |
            select(prefix_sum($lengths; $index) == $start) | $index] as $starts |
          [range(0; ($lengths | length) + 1) as $index |
            select(prefix_sum($lengths; $index) == $end) | $index] as $ends |
          if ($starts | length) == 1 and ($ends | length) == 1 and
              $ends[0] > $starts[0]
          then $ends[0] - $starts[0] else null end;
        def intersecting_callback_count($lengths; $start; $bytes):
          ($start + $bytes) as $end |
          [range(0; ($lengths | length)) as $index |
            prefix_sum($lengths; $index) as $callback_start |
            ($callback_start + $lengths[$index]) as $callback_end |
            select($callback_end > $start and $callback_start < $end)] | length;
        def common_evidence($e):
          ($e | keys) == evidence_keys and
          $e.failure_reason == "none" and
          $e.wire_decrypted_pairs_exact == true and
          $e.headers_spanned_records == true and
          $e.parser_shape_exact == true and
          $e.parser_facing_coalesced == false and
          $e.handoff_before_parse == true and
          ($e.request_count | positive_integer(2)) and
          ($e.request_header_bytes | length) == $e.request_count and
          ($e.request_body_bytes | length) == $e.request_count and
          ($e.request_total_bytes | length) == $e.request_count and
          ($e.request_header_decrypted_callback_counts | length) ==
            $e.request_count and
          all([range(0; $e.request_count)][];
            . as $i |
            ($e.request_header_bytes[$i] | type == "number" and floor == . and
              . >= 16385 and . <= 32768) and
            $e.request_body_bytes[$i] == 32768 and
            $e.request_total_bytes[$i] ==
              ($e.request_header_bytes[$i] + $e.request_body_bytes[$i]) and
            $e.request_total_bytes[$i] <= 73728 and
            ($e.request_header_decrypted_callback_counts[$i] |
              positive_integer(32)) and
            $e.request_header_decrypted_callback_counts[$i] >= 2) and
          ($e.decrypted_callback_lengths | type == "array" and
            length >= 2 and length <= 32) and
          ($e.tls_application_record_legacy_versions | length) ==
            ($e.decrypted_callback_lengths | length) and
          ($e.tls_application_record_payload_lengths | length) ==
            ($e.decrypted_callback_lengths | length) and
          all([range(0; ($e.decrypted_callback_lengths | length))][];
            . as $i |
            ($e.decrypted_callback_lengths[$i] | positive_integer(16384)) and
            $e.tls_application_record_legacy_versions[$i] == 771 and
            ($e.tls_application_record_payload_lengths[$i] | type == "number" and
              floor == . and . > $e.decrypted_callback_lengths[$i] and
              . <= ($e.decrypted_callback_lengths[$i] + 256) and
              . <= 18432)) and
          all([range(0; $e.request_count)][];
            . as $i |
            prefix_sum($e.request_total_bytes; $i) as $request_offset |
            $e.request_header_decrypted_callback_counts[$i] ==
              intersecting_callback_count(
                $e.decrypted_callback_lengths; $request_offset;
                $e.request_header_bytes[$i])) and
          $e.decrypted_total_bytes == ($e.decrypted_callback_lengths | add) and
          $e.parser_total_bytes == ($e.parser_callback_lengths | add) and
          $e.decrypted_total_bytes == ($e.request_total_bytes | add) and
          $e.parser_total_bytes == ($e.request_total_bytes | add) and
          $e.parser_callback_count == ($e.parser_callback_lengths | length) and
          ($e.emission_order | length) == $e.request_count and
          ($e.response_order | length) == $e.request_count and
          ($e.response_connection_close | length) == $e.request_count;
        . as $root |
        .request_count == 3 and
        (.connection_evidence |
          keys == ["frontend_connections", "frontend_protocol",
            "responses_read_before_next_write", "sequential_requests"] and
          .frontend_connections == 2 and .frontend_protocol == "HTTP/1.1" and
          .sequential_requests == 2 and
          .responses_read_before_next_write == 1 and
          (.pipelined_requests // 0) == 0 and
          (.requests_written_before_first_read // 0) == 0) and
        $root.cases[0].response.backend_connection_id !=
          $root.cases[1].response.backend_connection_id and
        $root.cases[1].response.backend_connection_id ==
          $root.cases[2].response.backend_connection_id and
        $root.cases[1].response.backend_remote_port ==
          $root.cases[2].response.backend_remote_port and
        $root.cases[1].response.tls_protocol ==
          $root.cases[2].response.tls_protocol and
        $root.cases[1].response.tls_cipher ==
          $root.cases[2].response.tls_cipher and
        (.tls_boundary_correlation |
          .exact_parent_count == 3 and .same_request_evidence_count == 3 and
          .wrong_parent_count == 0 and .unresolved_count == 0 and
          (.requests | length == 3) and
          .requests[0].mode == "split" and
          .requests[0].delivery_shape == "split" and
          .requests[1].mode == "coalesced" and
          .requests[1].delivery_shape == "serialized_proxy_fallback" and
          .requests[2].mode == "coalesced" and
          .requests[2].sequence == 2 and
          .requests[2].evidence_phase == "final" and
          .requests[2].delivery_shape == "serialized_proxy_fallback" and
          all(.requests[];
            keys == [
              "apache_client_span_id", "decrypted_callback_count",
              "delivery_shape", "evidence_phase", "exact_parent",
              "header_decrypted_callback_count", "java_parent_span_id",
              "java_server_span_id", "marker", "mode", "parser_bytes",
              "parser_callback_count", "request_bytes",
              "same_request_evidence", "sequence",
              "tls_application_record_count", "trace_id"
            ] and
            (.trace_id | trace_id) and
            (.apache_client_span_id | span_id) and
            (.java_server_span_id | span_id) and
            (.java_parent_span_id | span_id) and
            .java_parent_span_id == .apache_client_span_id and
            .java_server_span_id != .apache_client_span_id and
            .exact_parent == true and .same_request_evidence == true and
            (.request_bytes | positive_bytes) and
            (.tls_application_record_count | positive_bounded) and
            .tls_application_record_count >= 2 and
            (.decrypted_callback_count | positive_bounded) and
            .decrypted_callback_count >= 2 and
            .decrypted_callback_count == .tls_application_record_count and
            (.header_decrypted_callback_count | positive_bounded) and
            .header_decrypted_callback_count >= 2 and
            .header_decrypted_callback_count <= .decrypted_callback_count and
            (.parser_callback_count | positive_bounded) and
            (.parser_bytes | positive_bytes) and
            .parser_bytes == .request_bytes) and
          .requests[0].sequence == 1 and
          .requests[0].evidence_phase == "final" and
          .requests[0].parser_callback_count ==
            .requests[0].decrypted_callback_count and
          .requests[1].sequence == 1 and
          .requests[1].evidence_phase == "partial" and
          .requests[1].parser_callback_count == 1 and
          .requests[2].parser_callback_count == 1 and
          (.requests | map([
            .trace_id + "/" + .apache_client_span_id,
            .trace_id + "/" + .java_server_span_id
          ]) | add | unique | length) == 6) and
        (.cases | to_entries | all(.[];
          .key as $index | .value as $case |
          $root.tls_boundary_correlation.requests[$index] as $row |
          ([ $case.trace.spans[] | select(
            .service_name == "apache-proxy" and .kind == "CLIENT" and
            .attributes["http.request.header.x-obi-demo-id"] ==
              $case.request.marker and
            (.attributes["url.full"] | url_path) == $case.request.endpoint) ][0])
            as $client |
          ([ $case.trace.spans[] | select(
            .service_name == "java-backend" and .kind == "SERVER" and
            .attributes["http.request.header.x-obi-demo-id"] ==
              $case.request.marker and
            .attributes["url.path"] == $case.request.endpoint) ][0]) as $java |
          $row.marker == $case.request.marker and
          $row.trace_id == $client.trace_id and
          $row.trace_id == $java.trace_id and
          $row.apache_client_span_id == $client.span_id and
          $row.java_server_span_id == $java.span_id and
          $row.java_parent_span_id == $java.parent_span_id and
          $case.response.backend_kind == "netty-tls-boundary" and
          $case.request.tls_boundary_mode == $row.mode and
          $case.request.tls_boundary_sequence == $row.sequence and
          ($case.response.tls_boundary |
            . as $e |
            ($row.sequence - 1) as $request_index |
            prefix_sum($e.request_total_bytes; $request_index) as $request_offset |
            exact_callback_segment_count(
              $e.decrypted_callback_lengths; $request_offset;
              $e.request_total_bytes[$request_index]) as $decrypted_segments |
            exact_callback_segment_count(
              $e.parser_callback_lengths; $request_offset;
              $e.request_total_bytes[$request_index]) as $parser_segments |
            common_evidence($e) and
            .mode == $row.mode and .delivery_shape == $row.delivery_shape and
            .evidence_phase == $row.evidence_phase and
            .request_total_bytes[$row.sequence - 1] == $row.request_bytes and
            .request_header_decrypted_callback_counts[$row.sequence - 1] ==
              $row.header_decrypted_callback_count and
            $row.parser_bytes == $row.request_bytes and
            $decrypted_segments != null and $parser_segments != null and
            $row.tls_application_record_count == $decrypted_segments and
            $row.decrypted_callback_count == $decrypted_segments and
            $row.parser_callback_count == $parser_segments and
            (if $index == 0 then
              .mode == "split" and .delivery_shape == "split" and
              .evidence_phase == "final" and .fallback_reason == "none" and
              .coalescing_grace_millis == 0 and
              .coalescing_grace_expired == false and
              .verification_buffer_bytes == 0 and
              .verification_buffer_limit_bytes == 0 and
              .verification_pair_digest_exact == false and .passed == true and
              .request_complete == true and .request_count == 1 and
              .request_order == [1] and .emission_order == [1] and
              (.emission_parser_callback_order | length) == 1 and
              (.emission_parser_callback_order[0] | type == "number" and
                floor == . and . >= 1) and
              .emission_parser_callback_order[0] <=
                (.decrypted_callback_lengths | length) and
              .emission_parser_callback_order[0] >=
                .request_header_decrypted_callback_counts[0] and
              .response_order == [1] and .response_connection_close == [true] and
              .request_bytes_preserved == true and
              .response_forces_connection_close == true and
              .requests_emitted_from_single_parser_callback == true and
              .split_buffers_forwarded_unchanged == true and
              .first_response_keeps_alive == false and
              .parser_callback_lengths == .decrypted_callback_lengths and
              .parser_callback_count == $row.parser_callback_count
            elif $index == 1 then
              .mode == "coalesced" and
              .delivery_shape == "serialized_proxy_fallback" and
              .evidence_phase == "partial" and
              .fallback_reason == "coalescing_grace_expired" and
              (.coalescing_grace_millis | positive_integer(1000)) and
              .coalescing_grace_expired == true and
              .verification_buffer_limit_bytes == 147456 and
              .verification_buffer_bytes == (.request_total_bytes | add) and
              .verification_pair_digest_exact == false and .passed == false and
              .request_complete == false and .request_count == 1 and
              .request_order == [1] and .emission_order == [1] and
              .emission_parser_callback_order == [1] and
              .response_order == [1] and .response_connection_close == [false] and
              .request_bytes_preserved == false and
              .response_forces_connection_close == false and
              .requests_emitted_from_single_parser_callback == false and
              .split_buffers_forwarded_unchanged == false and
              .first_response_keeps_alive == true and
              .parser_callback_lengths == .request_total_bytes and
              $row.parser_callback_count == 1
            else
              .mode == "coalesced" and
              .delivery_shape == "serialized_proxy_fallback" and
              .evidence_phase == "final" and
              .fallback_reason == "coalescing_grace_expired" and
              (.coalescing_grace_millis | positive_integer(1000)) and
              .coalescing_grace_expired == true and
              .verification_buffer_limit_bytes == 147456 and
              .verification_buffer_bytes == (.request_total_bytes | add) and
              .verification_pair_digest_exact == true and .passed == true and
              .request_complete == true and .request_count == 2 and
              .request_order == [1, 2] and .emission_order == [1, 2] and
              .emission_parser_callback_order == [1, 2] and
              .response_order == [1, 2] and
              .response_connection_close == [false, true] and
              .request_bytes_preserved == true and
              .response_forces_connection_close == true and
              .requests_emitted_from_single_parser_callback == false and
              .split_buffers_forwarded_unchanged == false and
              .first_response_keeps_alive == true and
              .parser_callback_lengths == .request_total_bytes and
              $row.parser_callback_count == 1
            end)))) and
        ($root.cases[1].response.tls_boundary) as $partial |
        ($root.cases[2].response.tls_boundary) as $final |
        $partial.mode == $final.mode and
        $partial.delivery_shape == $final.delivery_shape and
        $partial.fallback_reason == $final.fallback_reason and
        $partial.coalescing_grace_millis == $final.coalescing_grace_millis and
        $partial.coalescing_grace_expired == $final.coalescing_grace_expired and
        $partial.verification_buffer_limit_bytes ==
          $final.verification_buffer_limit_bytes and
        all([
          "request_header_bytes", "request_body_bytes", "request_total_bytes",
          "request_header_decrypted_callback_counts", "request_order",
          "emission_order", "emission_parser_callback_order", "response_order",
          "tls_application_record_legacy_versions",
          "tls_application_record_payload_lengths", "decrypted_callback_lengths",
          "parser_callback_lengths"
        ][]; . as $field |
          is_prefix($partial[$field]; $final[$field])) and
        is_prefix($partial.response_connection_close;
          $final.response_connection_close) and
        $partial.decrypted_total_bytes < $final.decrypted_total_bytes and
        $partial.parser_total_bytes < $final.parser_total_bytes and
        $partial.verification_buffer_bytes < $final.verification_buffer_bytes and
        ($partial.decrypted_total_bytes + $final.request_total_bytes[1]) ==
          $final.decrypted_total_bytes and
        ($partial.parser_total_bytes + $final.request_total_bytes[1]) ==
          $final.parser_total_bytes
      ' "$BUNDLE_DIR/$result" >/dev/null || {
        printf '%s: raw scenario predicate failed: tls-boundary-response-evidence\n' \
          "$SCRIPT_NAME" >&2
        return 1
      }
      jq -e -s '
        .[0].tls_boundary_correlation == .[1].scenario_reconciliation and
        .[1].receive_coordination_maps == .[2]
      ' "$BUNDLE_DIR/$result" "$BUNDLE_DIR/$status" \
        "$BUNDLE_DIR/receive-cursor-map-tls-boundary-status.json" >/dev/null ||
        {
          printf '%s: raw scenario predicate failed: tls-boundary-status-crosslink\n' \
            "$SCRIPT_NAME" >&2
          return 1
        }
      ;;
    pressure)
      jq -e '
        def zero_parent:
          . == null or . == "" or . == "0000000000000000";
        . as $root |
        [$root.cases[] |
          [.trace.spans[] | select(
            .service_name == "java-backend" and .kind == "SERVER")][0] |
          if (.parent_span_id | zero_parent) then "explicit_root"
          else "exact" end] as $outcomes |
        (.cases | to_entries | all(.[];
          .key as $index | .value as $case |
          $case.request.handoff_hops == (2 + ($index % 7)) and
          $case.request.handoff_fault == "none" and
          $case.response.workload == "servlet-async-executor" and
          $case.response.handoff_hops == ((2 + ($index % 7)) | tostring) and
          $case.response.handoff_fault == "none")) and
        ([$outcomes[] | select(. == "exact")] | length) ==
          .pressure_correlation.exact_hit_count and
        ([$outcomes[] | select(. == "explicit_root")] | length) ==
          .pressure_correlation.explicit_root_count and
        (.pressure_correlation.exact_hit_count | type == "number" and
          floor == . and . >= 0 and . <= $root.request_count) and
        (.pressure_correlation.explicit_root_count | type == "number" and
          floor == . and . >= 0 and . <= $root.request_count) and
        (.pressure_correlation.exact_hit_count +
          .pressure_correlation.explicit_root_count) == .request_count and
        .pressure_correlation.wrong_parent_count == 0 and
        .pressure_correlation.unresolved_count == 0
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      jq -e -s '
        def count:
          type == "number" and floor == . and . >= 0 and . <= 128;
        .[0].pressure_correlation as $trace |
        .[1].pressure_correlation as $status |
        $trace == $status.trace and
        ($status.bridge as $bridge |
          $bridge.transport == "getsockopt" and
          ($bridge.phase_outcome_counts |
            keys == ["candidate", "inject", "retrieval", "stage"] and
            all(.[]; count) and .inject == 128 and
            .inject >= .candidate and .candidate >= .stage and
            .stage >= .retrieval) and
          ($bridge.auxiliary_outcome_counts |
            keys == ["handoff"] and (.handoff | count) and
            .handoff <= $trace.exact_hit_count) and
          ($bridge.retrieval_valid_count | count) and
          ($bridge.upstream_failure_count | count) and
          ($bridge.retrieval_failure_count | count) and
          $bridge.retrieval_valid_count == $trace.exact_hit_count and
          ($bridge.upstream_failure_count +
            $bridge.retrieval_failure_count) ==
              $trace.explicit_root_count and
          $bridge.phase_outcome_counts.retrieval ==
            ($bridge.retrieval_valid_count +
              $bridge.retrieval_failure_count) and
          (128 - $bridge.phase_outcome_counts.retrieval) ==
            $bridge.upstream_failure_count and
          ($bridge.upstream_failure_reason_counts |
            keys == ["ambiguous", "malformed", "missing", "overload",
              "segmented", "stale"] and all(.[]; count) and
            ([.[]] | add) == $bridge.upstream_failure_count) and
          ($bridge.retrieval_failure_reason_counts |
            keys == ["already_consumed", "ambiguous", "disabled",
              "malformed", "missing", "overload", "stale", "timeout",
              "transport_error", "unauthorized", "unsupported",
              "version_mismatch"] and all(.[]; count) and
            ([.[]] | add) == $bridge.retrieval_failure_count)) and
        ($status.java_reconciliation_target |
          .take_valid_count == $trace.exact_hit_count and
          .attributable_absence_count == $trace.explicit_root_count and
          (.diagnostic_self_miss_count | count))
      ' "$BUNDLE_DIR/$result" "$BUNDLE_DIR/$status" >/dev/null || return 1
      ;;
    handoff)
      jq -e '
        ["none", "cancel", "reject", "timeout"] as $faults |
        (.cases | to_entries | all(.[];
          .key as $index | .value as $case |
          $case.request.handoff_hops == ($index + 1) and
          $case.request.handoff_fault == $faults[$index] and
          $case.response.workload == "servlet-async-executor" and
          $case.response.handoff_hops == (($index + 1) | tostring) and
          $case.response.handoff_fault == $faults[$index]))
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      ;;
    timeout-retry)
      jq -e '
        def fixed_reason:
          . == "missing" or . == "stale" or . == "unsupported" or
          . == "malformed" or . == "version_mismatch" or . == "ambiguous" or
          . == "unauthorized" or . == "already_consumed" or . == "timeout" or
          . == "overload" or . == "transport_error" or . == "disabled";
        def trace_id:
          type == "string" and test("^[0-9a-f]{32}$") and
          . != "00000000000000000000000000000000";
        def span_id:
          type == "string" and test("^[0-9a-f]{16}$") and
          . != "0000000000000000";
        def zero_parent:
          . == null or . == "" or . == "0000000000000000";
        def marker($span):
          [($span.attributes // {}) | to_entries[] |
            {key: (.key | ascii_downcase), value: .value} |
            select(.key == "obi.related.marker.invalid" or
              .key == "http.request.header.x-obi-demo-id" or
              .key == "http.request.header.x_obi_demo_id")] as $rows |
          if any($rows[]; .key == "obi.related.marker.invalid") then
            error("invalid marker attribute")
          elif any($rows[]; (.value | type) != "string" or .value == "") then
            error("invalid marker value")
          elif ([$rows[].value] | unique | length) > 1 then
            error("conflicting marker values")
          elif ($rows | length) == 0 then null else $rows[0].value end;
        def url_path($value):
          $value | sub("^[A-Za-z][A-Za-z0-9+.-]*://[^/]*"; "") |
          split("#")[0] | split("?")[0];
        def endpoint_matches($span; $wanted):
          any([
            ($span.attributes["http.route"] // empty),
            ($span.attributes["url.path"] // empty),
            (($span.attributes["http.target"] // empty) | url_path(.)),
            (($span.attributes["http.url"] // empty) | url_path(.)),
            (($span.attributes["url.full"] // empty) | url_path(.))
          ][]; . == $wanted);
        def flag($span; $bit):
          ((($span.flags / $bit) | floor) % 2) == 1;
        def snapshot_outcome($fault):
          $fault.trace as $snapshot |
          ($snapshot.spans + ($snapshot.related_spans // [])) as $spans |
          [$spans[] | select(
            .service_name == "apache-proxy" and .kind == "CLIENT")] as $clients |
          [$clients[] | select(marker(.) == $fault.marker)] as $marked_clients |
          [$spans[] | select(
            .service_name == "java-backend" and .kind == "SERVER")] as $java |
          [$java[] | select(marker(.) == $fault.marker)] as $marked_java |
          if (($snapshot | keys) - [
              "ambiguous_related_spans", "dropped_count_spans",
              "dropped_retained_limit_spans", "dropped_spans",
              "dropped_value_limit_spans", "marker", "max_retained_bytes",
              "max_value_bytes", "omitted_related_spans", "received_batches",
              "received_spans", "receiver_instance_id", "related_spans",
              "reset_generation", "retained_bytes", "spans"
            ] | length) != 0 or
            ($snapshot.receiver_instance_id | type != "string" or
              length < 1 or length > 128) or
            ($snapshot.reset_generation | type != "number" or floor != . or . < 0) or
            ($snapshot.received_batches | type != "number" or floor != . or . < 0) or
            ($snapshot.received_spans | type != "number" or floor != . or . < 0) or
            ($snapshot.retained_bytes | type != "number" or floor != . or . < 0) or
            ($snapshot.max_retained_bytes | type != "number" or floor != . or . < 1) or
            ($snapshot.max_value_bytes | type != "number" or floor != . or . < 1) or
            $snapshot.marker != $fault.marker or
            ($snapshot.spans | type) != "array" or
            (($snapshot.related_spans // []) | type) != "array" or
            $snapshot.dropped_spans != 0 or
            $snapshot.dropped_count_spans != 0 or
            $snapshot.dropped_value_limit_spans != 0 or
            $snapshot.dropped_retained_limit_spans != 0 or
            ($snapshot.omitted_related_spans // 0) != 0 or
            ($snapshot.ambiguous_related_spans // 0) != 0 or
            ($clients | length) != 1 or ($marked_clients | length) != 1 or
            (endpoint_matches($marked_clients[0]; "/api/echo") | not) or
            ($java | length) != ($marked_java | length) or
            ($marked_java | length) > 1 or
            ($marked_clients[0].trace_id | trace_id | not) or
            ($marked_clients[0].span_id | span_id | not) or
            ($marked_clients[0].flags | type != "number" or floor != . or . < 0)
          then null
          elif ($marked_java | length) == 0 then
            if ($fault.drop_reasons | length) == 0 then "missing" else null end
          else
            $marked_java[0] as $child |
            if (($child.trace_id | trace_id | not) or
                ($child.span_id | span_id | not) or
                ($child.flags | type != "number" or floor != . or . < 0) or
                (endpoint_matches($child; "/api/echo") | not)) then null
            elif ($child.parent_span_id | zero_parent) then
              if (flag($child; 512) | not) and
                  $child.trace_id != $marked_clients[0].trace_id and
                  ($fault.drop_reasons | length) == 1 and
                  ($fault.drop_reasons[0] | fixed_reason)
              then "reason_coded_drop" else null end
            elif $child.trace_id == $marked_clients[0].trace_id and
                $child.parent_span_id == $marked_clients[0].span_id and
                flag($child; 256) and flag($child; 512) and
                (($child.flags % 256) == ($marked_clients[0].flags % 256)) and
                ($fault.drop_reasons | length) == 0
            then "exact" else null end
          end;
        (.faults | type == "array" and length == 1) and
        all(.faults[];
          (keys == ["drop_reasons", "elapsed_nanos", "kind", "marker",
            "outcome", "parent_outcome", "trace"]) and
          .kind == "client-timeout" and
          .outcome == "deadline-exceeded-as-expected" and
          (.elapsed_nanos | type == "number" and floor == . and
            . >= 1 and . <= 75000000000) and
          (.marker | type == "string" and
            test("^timeout-retry-cancelled-[0-9]+$")) and
          (.parent_outcome == "exact" or .parent_outcome == "missing" or
            .parent_outcome == "reason_coded_drop") and
          (.drop_reasons | type == "array") and
          all(.drop_reasons[]; type == "string" and fixed_reason) and
          (if .parent_outcome == "reason_coded_drop" then
             (.drop_reasons | length == 1)
           else (.drop_reasons | length == 0) end) and
          snapshot_outcome(.) == .parent_outcome)
      ' "$BUNDLE_DIR/$result" >/dev/null || return 1
      jq -e -s '.[0].faults[0] == .[1].scenario_reconciliation' \
        "$BUNDLE_DIR/$result" "$BUNDLE_DIR/$status" >/dev/null || return 1
      ;;
  esac
}

validate_raw_stress_pair_authority() {
  local -r index="$BUNDLE_DIR/obi-metric-boundary-index.json"
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
    validate_obi_metric_pair "$pair_reference" || return 1
    validate_java_diagnostics_reference "$before_java_reference" || return 1
    validate_java_diagnostics_reference "$after_java_reference" || return 1
    IFS= read -r before_snapshot \
      <"$BUNDLE_DIR/$before_java_reference" || return 1
    IFS= read -r after_snapshot \
      <"$BUNDLE_DIR/$after_java_reference" || return 1
    pair_sha256="$(sha256sum <"$BUNDLE_DIR/$pair_reference")" || return 1
    pair_sha256="${pair_sha256%% *}"
    java_sha256="$(sha256sum <"$BUNDLE_DIR/$after_java_reference")" || return 1
    java_sha256="${java_sha256%% *}"
    status_sha256="$(sha256sum <"$BUNDLE_DIR/$status_reference")" || return 1
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
      --arg pair_reference "$pair_reference" \
      --arg before_identity_reference "$before_identity_reference" \
      --arg after_identity_reference "$after_identity_reference" '
        .boundary == $scenario and .continuity == "same_process" and
        .before == {state:"running",
          identity_reference:$before_identity_reference} and
        .after == {state:"running",
          identity_reference:$after_identity_reference}
      ' "$BUNDLE_DIR/$pair_reference" >/dev/null || return 1
    jq -e --arg scenario "$scenario" \
      --arg pair_reference "$pair_reference" \
      --arg before_java_reference "$before_java_reference" \
      --arg after_java_reference "$after_java_reference" \
      --arg before_snapshot "$before_snapshot" \
      --arg after_snapshot "$after_snapshot" \
      --slurpfile pair "$BUNDLE_DIR/$pair_reference" '
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
      ' "$BUNDLE_DIR/$status_reference" >/dev/null || return 1
    jq -e --arg scenario "$scenario" '
      .status == "passed" and .scenario == $scenario
    ' "$BUNDLE_DIR/scenario-$scenario.json" >/dev/null || return 1
  done
}

json_decimal_lexeme() {
  local -r relative_path="$1"
  local -r field="$2"
  local record=""
  local value=""

  [[ "$field" =~ ^[a-z_]+$ ]] || return 1
  IFS= read -r record <"$BUNDLE_DIR/$relative_path" || return 1
  [[ "$record" == *\"$field\":* ]] || return 1
  value="${record#*\""$field"\":}"
  value="${value%%,*}"
  value="${value%\}}"
  canonical_uint64_string "$value" || return 1
  printf '%s\n' "$value"
}

raw_pressure_map_entries() {
  local -r relative_path="$1"
  local -r wanted_map_id="$2"

  validate_bounded_regular_file \
    "$relative_path" "$OBI_METRIC_SNAPSHOT_MAX_BYTES" \
    "$OBI_METRIC_SNAPSHOT_MAX_LINES" || return 1
  LC_ALL=C awk -v wanted="$wanted_map_id" '
    $1 ~ /^obi_bpf_map_entries_total\{/ &&
      $1 ~ /map_name="java_remote_par"/ {
      id = $1
      sub(/^.*map_id="/, "", id)
      sub(/".*$/, "", id)
      if (id == wanted) {
        if (NF != 2 || $2 !~ /^(0|[1-9][0-9]*)$/) {
          invalid = 1
        }
        value = $2
        count++
      }
    }
    END {
      if (invalid || count != 1) exit 1
      print value
    }
  ' "$BUNDLE_DIR/$relative_path"
}

validate_raw_pressure_monitor() {
  local -r relative_path='map-pressure-pressure-monitor.log'
  local -r map_id="$1"
  local -r baseline="$2"
  local -r capacity="$3"

  validate_bounded_regular_file \
    "$relative_path" "$RAW_V3_JSON_MAX_BYTES" 4096 || return 1
  LC_ALL=C awk -v wanted_id="$map_id" -v baseline="$baseline" \
    -v capacity="$capacity" '
    function field(name,  i, parts) {
      for (i = 1; i <= NF; i++) {
        split($i, parts, "=")
        if (parts[1] == name) return parts[2]
      }
      return ""
    }
    /^status=pressured / || /^status=traffic-complete / {
      id = field("map_id")
      observed_baseline = field("baseline")
      observed_capacity = field("max_entries")
      entries = field("entries")
      if (id != wanted_id || observed_baseline != baseline ||
          observed_capacity != capacity || entries !~ /^(0|[1-9][0-9]*)$/ ||
          entries <= baseline || entries > capacity) invalid = 1
      if ($1 == "status=pressured") pressured++
      if ($1 == "status=traffic-complete") {
        inject_total = field("inject_total")
        target = field("target")
        if (field("operation") != "inject" || field("transport") != "tcp" ||
            inject_total !~ /^(0|[1-9][0-9]*)$/ || target != inject_total) {
          invalid = 1
        }
        complete++
      }
      next
    }
    { invalid = 1 }
    END { if (invalid || pressured < 1 || complete != 1) exit 1 }
  ' "$BUNDLE_DIR/$relative_path"
}

validate_raw_pressure_evidence() {
  local -r prepare='map-pressure-pressure-prepare.json'
  local -r fill='map-pressure-pressure-fill.json'
  local -r cleanup='map-pressure-pressure-cleanup.json'
  local cleanup_status=""
  local label=""
  local map_id=""
  local capacity=""
  local token_prepare=""
  local token_fill=""
  local token_cleanup=""
  local baseline_entries=""
  local pressured_entries=""
  local traffic_entries=""
  local recovered_entries=""
  local sample_one_entries=""
  local sample_two_entries=""
  local attempt_name=""
  local attempt_status=""
  local attempt_command_status=""
  local attempt_validation_status=""
  local expected_attempts="$TMP_DIR/raw-pressure-attempts.expected"
  local actual_attempts="$TMP_DIR/raw-pressure-attempts.actual"
  local -i attempt=0
  local -i final_attempt=0

  validate_single_json_object "$prepare" 4096 || return 1
  validate_single_json_object "$fill" 4096 || return 1
  validate_single_json_object "$cleanup" 4096 || return 1
  [[ "$(awk 'END { print NR + 0 }' "$BUNDLE_DIR/$prepare")" == 1 &&
    "$(awk 'END { print NR + 0 }' "$BUNDLE_DIR/$fill")" == 1 &&
    "$(awk 'END { print NR + 0 }' "$BUNDLE_DIR/$cleanup")" == 1 ]] || return 1
  jq -e -s '
    length == 3 and .[0] as $prepare | .[1] as $fill | .[2] as $cleanup |
    ($prepare | keys == [
        "kernel_name", "map_id", "map_name", "map_type", "max_entries",
        "mode", "process_map_id", "process_namespace", "process_pid",
        "status", "token_base", "touched"
      ] and .status == "passed" and .mode == "prepare" and
      .map_name == "java_remote_parent_handoff_claims" and
      .kernel_name == "java_remote_par" and .map_type == "Hash" and
      (.map_id | type == "number" and floor == . and . >= 1 and
        . <= 4294967295) and
      .max_entries == 10000 and
      (.process_map_id | type == "number" and floor == . and . >= 1 and
        . <= 4294967295) and
      (.process_pid | type == "number" and floor == . and . >= 1 and
        . <= 4294967295) and
      (.process_namespace | type == "number" and floor == . and . >= 1 and
        . <= 4294967295) and
      .map_id != .process_map_id and .touched == 0) and
    ($fill | keys == [
        "capacity_rejected_entries", "kernel_name", "map_id", "map_name",
        "map_type", "max_entries", "mode", "process_map_id",
        "process_namespace", "process_pid", "status", "token_base",
        "touched", "verified_present_entries"
      ] and .status == "passed" and .mode == "fill" and
      .map_name == $prepare.map_name and .kernel_name == $prepare.kernel_name and
      .map_type == $prepare.map_type and
      .map_id == $prepare.map_id and .max_entries == $prepare.max_entries and
      .process_map_id == $prepare.process_map_id and
      .process_pid == $prepare.process_pid and
      .process_namespace == $prepare.process_namespace and
      (.touched | type == "number" and floor == . and
        . > 0 and . <= $prepare.max_entries) and
      .capacity_rejected_entries == 1 and
      .verified_present_entries == .touched) and
    ($cleanup | keys == [
        "cleanup_verified", "kernel_name", "map_id", "map_name", "map_type",
        "max_entries", "mode", "process_map_id", "process_namespace",
        "process_pid", "status", "token_base", "touched",
        "verified_absent_entries"
      ] and .status == "passed" and .mode == "cleanup" and
      .map_name == $prepare.map_name and .kernel_name == $prepare.kernel_name and
      .map_type == $prepare.map_type and
      .map_id == $prepare.map_id and .max_entries == $prepare.max_entries and
      .process_map_id == 0 and .process_pid == $prepare.process_pid and
      .process_namespace == $prepare.process_namespace and
      (.touched | type == "number" and floor == . and
        . >= 0 and . <= $fill.touched) and
      .cleanup_verified == true and
      .verified_absent_entries == ($prepare.max_entries + 1) and
      .touched <= $fill.touched)
  ' "$BUNDLE_DIR/$prepare" "$BUNDLE_DIR/$fill" "$BUNDLE_DIR/$cleanup" >/dev/null ||
    return 1
  map_id="$(json_decimal_lexeme "$prepare" map_id)" || return 1
  capacity="$(json_decimal_lexeme "$prepare" max_entries)" || return 1
  token_prepare="$(json_decimal_lexeme "$prepare" token_base)" || return 1
  token_fill="$(json_decimal_lexeme "$fill" token_base)" || return 1
  token_cleanup="$(json_decimal_lexeme "$cleanup" token_base)" || return 1
  [[ "$token_prepare" != 0 && "$token_prepare" == "$token_fill" &&
    "$token_prepare" == "$token_cleanup" ]] || return 1
  for label in prepare fill cleanup; do
    validate_bounded_regular_file_allow_empty \
      "map-pressure-pressure-$label.stderr.log" \
      "$RAW_V3_JSON_MAX_BYTES" 4096 || return 1
  done
  cleanup_status="$(find -- "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type f \
    -name 'map-pressure-pressure-cleanup-attempt-*.status' -print |
    LC_ALL=C sort | tail -n 1)" || return 1
  [[ -n "$cleanup_status" ]] || return 1
  validate_key_value_file "$cleanup_status" || return 1
  [[ "$(awk 'END { print NR + 0 }' "$cleanup_status")" == 4 &&
    "$(cut -d= -f1 -- "$cleanup_status" | LC_ALL=C sort | tr '\n' ' ')" == \
      'command_status monitor_status recovery_status validation_status ' ]] ||
    return 1
  [[ "$(key_value "$cleanup_status" command_status)" == 0 &&
    "$(key_value "$cleanup_status" validation_status)" == passed &&
    "$(key_value "$cleanup_status" recovery_status)" == passed &&
    "$(key_value "$cleanup_status" monitor_status)" == 0 ]] || return 1
  [[ "${cleanup_status##*/}" =~ ^map-pressure-pressure-cleanup-attempt-0([1-3])\.status$ ]] ||
    return 1
  final_attempt="${BASH_REMATCH[1]}"
  : >"$expected_attempts"
  for ((attempt = 1; attempt <= final_attempt; attempt++)); do
    printf -v attempt_name 'map-pressure-pressure-cleanup-attempt-%02d' "$attempt"
    printf '%s\n' "$attempt_name.json" "$attempt_name.stderr.log" \
      "$attempt_name.status" >>"$expected_attempts" || return 1
    validate_bounded_regular_file_allow_empty \
      "$attempt_name.stderr.log" "$RAW_V3_JSON_MAX_BYTES" 4096 || return 1
    attempt_status="$BUNDLE_DIR/$attempt_name.status"
    validate_key_value_file "$attempt_status" || return 1
    attempt_command_status="$(key_value "$attempt_status" command_status)" ||
      return 1
    attempt_validation_status="$(key_value \
      "$attempt_status" validation_status)" || return 1
    if [[ "$attempt_command_status" == 0 &&
      "$attempt_validation_status" == passed ]]; then
      validate_single_json_object "$attempt_name.json" 4096 || return 1
    else
      validate_bounded_regular_file_allow_empty \
        "$attempt_name.json" 4096 4096 || return 1
    fi
  done
  find -- "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type f \
    \( -name 'map-pressure-pressure-cleanup-attempt-??.json' -o \
       -name 'map-pressure-pressure-cleanup-attempt-??.stderr.log' -o \
       -name 'map-pressure-pressure-cleanup-attempt-??.status' \) \
    -printf '%f\n' | LC_ALL=C sort >"$actual_attempts" || return 1
  LC_ALL=C sort -o "$expected_attempts" -- "$expected_attempts" || return 1
  cmp -s -- "$expected_attempts" "$actual_attempts" || return 1
  printf -v attempt_name \
    'map-pressure-pressure-cleanup-attempt-%02d' "$final_attempt"
  cmp -s -- "$BUNDLE_DIR/$attempt_name.json" "$BUNDLE_DIR/$cleanup" || return 1

  baseline_entries="$(raw_pressure_map_entries \
    phases/pressure-before/obi-metrics.prom "$map_id")" || return 1
  pressured_entries="$(raw_pressure_map_entries \
    map-pressure-pressure-pressured.prom "$map_id")" || return 1
  traffic_entries="$(raw_pressure_map_entries \
    map-pressure-pressure-traffic-complete.prom "$map_id")" || return 1
  recovered_entries="$(raw_pressure_map_entries \
    map-pressure-pressure-recovered.prom "$map_id")" || return 1
  sample_one_entries="$(raw_pressure_map_entries \
    map-pressure-pressure-recovered-sample-01.prom "$map_id")" || return 1
  sample_two_entries="$(raw_pressure_map_entries \
    map-pressure-pressure-recovered-sample-02.prom "$map_id")" || return 1
  [[ "$baseline_entries" =~ ^[0-9]+$ && "$pressured_entries" =~ ^[0-9]+$ &&
    "$traffic_entries" =~ ^[0-9]+$ && "$recovered_entries" =~ ^[0-9]+$ &&
    "$sample_one_entries" =~ ^[0-9]+$ && "$sample_two_entries" =~ ^[0-9]+$ ]] ||
    return 1
  ((baseline_entries < capacity && pressured_entries > baseline_entries &&
    pressured_entries <= capacity && traffic_entries > baseline_entries &&
    traffic_entries <= capacity && recovered_entries <= baseline_entries &&
    sample_one_entries <= baseline_entries && sample_two_entries <= baseline_entries)) ||
    return 1
  validate_raw_pressure_monitor "$map_id" "$baseline_entries" "$capacity" ||
    return 1
  validate_bounded_regular_file \
    map-pressure-pressure-recovered-samples.log "$RAW_V3_JSON_MAX_BYTES" 4096 ||
    return 1
  [[ "$(tail -n 2 -- "$BUNDLE_DIR/map-pressure-pressure-recovered-samples.log" |
    awk -v baseline="$baseline_entries" '
      $0 ~ / matched=true / && $0 ~ / consecutive=[12]$/ {
        entries = $0
        sub(/^.* entries=/, "", entries)
        sub(/ .*/, "", entries)
        if (entries ~ /^(0|[1-9][0-9]*)$/ && entries <= baseline) count++
      }
      END { print count + 0 }')" == 2 ]] || return 1

  for label in tls-boundary coalesced-bridge; do
    validate_raw_receive_coordination "$label" || return 1
  done
  jq -e -s '
    .[0].cursor_map_id == .[1].cursor_map_id and
    .[0].guard_map_id == .[1].guard_map_id and
    .[0].cursor_map_id != .[2].map_id and
    .[0].guard_map_id != .[2].map_id
  ' "$BUNDLE_DIR/receive-cursor-map-tls-boundary-before.json" \
    "$BUNDLE_DIR/receive-cursor-map-coalesced-bridge-before.json" \
    "$BUNDLE_DIR/map-pressure-pressure-prepare.json" >/dev/null
}

validate_raw_receive_coordination() {
  local -r label="$1"
  local -r before="receive-cursor-map-$label-before.json"
  local -r after="receive-cursor-map-$label-after.json"
  local -r status="receive-cursor-map-$label-status.json"
  local -r samples="receive-cursor-map-$label-recovery-samples.log"
  local matched_count=""
  local attempts=""
  local attempt_name=""
  local expected_attempts="$TMP_DIR/raw-receive-$label-attempts.expected"
  local actual_attempts="$TMP_DIR/raw-receive-$label-attempts.actual"
  local -i attempt=0

  validate_single_json_object "$before" 4096 || return 1
  validate_single_json_object "$after" 4096 || return 1
  validate_single_json_object "$status" "$RAW_V3_JSON_MAX_BYTES" || return 1
  [[ "$(awk 'END { print NR + 0 }' "$BUNDLE_DIR/$before")" == 1 &&
    "$(awk 'END { print NR + 0 }' "$BUNDLE_DIR/$after")" == 1 ]] || return 1
  validate_bounded_regular_file "$samples" "$RAW_V3_JSON_MAX_BYTES" 1024 ||
    return 1
  jq -e -s --arg before_reference "$before" --arg after_reference "$after" \
    --arg samples_reference "$samples" '
    length == 3 and .[0] as $before | .[1] as $after | .[2] as $status |
    ($before | keys == [
        "cursor_entries", "cursor_kernel_name", "cursor_key_size",
        "cursor_map_id", "cursor_map_name", "cursor_map_type",
        "cursor_max_entries", "cursor_value_size", "guard_entries",
        "guard_kernel_name", "guard_key_size", "guard_map_id",
        "guard_map_name", "guard_map_type", "guard_max_entries",
        "guard_value_size", "status"
      ] and .status == "passed" and
      .cursor_map_name == "jrp_recv_cur" and .guard_map_name == "jrp_recv_guard" and
      .cursor_kernel_name == "jrp_recv_cur" and
      .guard_kernel_name == "jrp_recv_guard" and
      .cursor_map_type == "Hash" and .guard_map_type == "Hash" and
      .cursor_key_size == 8 and .cursor_value_size == 56 and
      .guard_key_size == 8 and .guard_value_size == 56 and
      .cursor_max_entries == 10000 and .guard_max_entries == 10000 and
      (.cursor_map_id | type == "number" and floor == . and . >= 1 and
        . <= 4294967295) and
      (.guard_map_id | type == "number" and floor == . and . >= 1 and
        . <= 4294967295) and
      (.cursor_entries | type == "number" and floor == . and
        . >= 0 and . <= 10000) and
      (.guard_entries | type == "number" and floor == . and
        . >= 0 and . <= 10000) and
      .cursor_map_id != .guard_map_id) and
    ($after | keys == ($before | keys) and .status == "passed" and
      .cursor_map_name == $before.cursor_map_name and
      .guard_map_name == $before.guard_map_name and
      .cursor_kernel_name == $before.cursor_kernel_name and
      .guard_kernel_name == $before.guard_kernel_name and
      .cursor_map_type == $before.cursor_map_type and
      .guard_map_type == $before.guard_map_type and
      .cursor_key_size == $before.cursor_key_size and
      .cursor_value_size == $before.cursor_value_size and
      .guard_key_size == $before.guard_key_size and
      .guard_value_size == $before.guard_value_size and
      .cursor_max_entries == $before.cursor_max_entries and
      .guard_max_entries == $before.guard_max_entries and
      .cursor_map_id == $before.cursor_map_id and
      .guard_map_id == $before.guard_map_id and
      .cursor_entries == $before.cursor_entries and
      .guard_entries == $before.guard_entries) and
    ($status | keys == [
        "after", "attempts", "before", "cursor_baseline_entries",
        "cursor_final_entries", "cursor_map_id", "guard_baseline_entries",
        "guard_final_entries", "guard_map_id", "reason",
        "required_consecutive_samples", "samples", "status"
      ] and .status == "passed" and .reason == "steady-baseline" and
      .cursor_map_id == $before.cursor_map_id and
      .guard_map_id == $before.guard_map_id and
      .cursor_baseline_entries == $before.cursor_entries and
      .guard_baseline_entries == $before.guard_entries and
      .cursor_final_entries == $after.cursor_entries and
      .guard_final_entries == $after.guard_entries and
      .required_consecutive_samples == 2 and
      (.attempts | type == "number" and floor == . and . >= 2) and
      .before == $before_reference and .after == $after_reference and
      .samples == $samples_reference)
  ' "$BUNDLE_DIR/$before" "$BUNDLE_DIR/$after" "$BUNDLE_DIR/$status" >/dev/null ||
    return 1
  validate_bounded_regular_file_allow_empty \
    "receive-cursor-map-$label-before.stderr.log" \
    65536 512 || return 1
  attempts="$(jq -er '.attempts' "$BUNDLE_DIR/$status")" || return 1
  [[ "$attempts" =~ ^[0-9]+$ ]] || return 1
  ((attempts >= 2 && attempts <= 10)) || return 1
  : >"$expected_attempts"
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    printf -v attempt_name \
      'receive-cursor-map-%s-recovery-attempt-%02d' "$label" "$attempt"
    printf '%s\n' "$attempt_name.json" "$attempt_name.stderr.log" \
      >>"$expected_attempts" || return 1
    if ((attempt >= attempts - 1)); then
      validate_single_json_object "$attempt_name.json" 4096 || return 1
      jq -e -s 'length == 2 and .[0] == .[1]' \
        "$BUNDLE_DIR/$attempt_name.json" "$BUNDLE_DIR/$before" \
        >/dev/null || return 1
    else
      validate_bounded_regular_file_allow_empty \
        "$attempt_name.json" 4096 || return 1
    fi
    if ((attempt >= attempts - 1)); then
      validate_bounded_regular_file_allow_empty \
        "$attempt_name.stderr.log" 65536 512 || return 1
    else
      validate_bounded_regular_file_allow_empty \
        "$attempt_name.stderr.log" 65536 || return 1
    fi
  done
  find -- "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type f \
    \( -name "receive-cursor-map-$label-recovery-attempt-??.json" -o \
       -name "receive-cursor-map-$label-recovery-attempt-??.stderr.log" \) \
    -printf '%f\n' | LC_ALL=C sort >"$actual_attempts" || return 1
  LC_ALL=C sort -o "$expected_attempts" -- "$expected_attempts" || return 1
  cmp -s -- "$expected_attempts" "$actual_attempts" || return 1
  printf -v attempt_name \
    'receive-cursor-map-%s-recovery-attempt-%02d.json' "$label" "$attempts"
  cmp -s -- "$BUNDLE_DIR/$attempt_name" "$BUNDLE_DIR/$after" || return 1
  matched_count="$(awk -v expected_attempts="$attempts" \
      -v cursor_id="$(jq -r '.cursor_map_id' "$BUNDLE_DIR/$before")" \
      -v guard_id="$(jq -r '.guard_map_id' "$BUNDLE_DIR/$before")" \
      -v cursor_entries="$(jq -r '.cursor_entries' "$BUNDLE_DIR/$before")" \
      -v guard_entries="$(jq -r '.guard_entries' "$BUNDLE_DIR/$before")" '
      {
        expected_prefix = "attempt=" NR " "
        if (index($0, expected_prefix) != 1) invalid = 1
      }
      NR == expected_attempts - 1 || NR == expected_attempts {
        consecutive = NR - (expected_attempts - 2)
        if ($0 !~ (" cursor_map_id=" cursor_id " ") ||
          $0 !~ (" cursor_entries=" cursor_entries " ") ||
          $0 !~ (" guard_map_id=" guard_id " ") ||
          $0 !~ (" guard_entries=" guard_entries " ") ||
          $0 !~ / matched=true / ||
          $0 !~ (" consecutive=" consecutive "$") ) invalid = 1
        count++
      }
      END {
        if (invalid || NR != expected_attempts) exit 1
        print count + 0
      }' "$BUNDLE_DIR/$samples")" || return 1
  [[ "$matched_count" == 2 ]]
}

validate_raw_assertion_failure_control() {
  validate_single_json_object \
    scenario-assertion-failure.json "$RAW_V3_JSON_MAX_BYTES" || return 1
  validate_single_json_object \
    scenario-assertion-failure-status.json "$RAW_V3_JSON_MAX_BYTES" || return 1
  validate_key_value_file "$BUNDLE_DIR/failure-context.txt" || return 1
  [[ "$(awk 'END { print NR + 0 }' "$BUNDLE_DIR/failure-context.txt")" == 4 &&
    "$(cut -d= -f1 -- "$BUNDLE_DIR/failure-context.txt" |
      LC_ALL=C sort | tr '\n' ' ')" == 'command exit_status line stage ' ]] ||
    return 1
  jq -e '
    keys == ["expected_exit_status", "reason", "scenario", "status"] and
    .status == "failed" and .scenario == "assertion-failure" and
    .reason == "deliberate assertion failure requested" and
    .expected_exit_status == 2
  ' "$BUNDLE_DIR/scenario-assertion-failure.json" >/dev/null || return 1
  jq -e -s '
    length == 2 and
    (.[0] | keys == [
        "exit_status", "failure_context", "java_bridge_diagnostics",
        "java_bridge_diagnostics_reference", "metric_status",
        "obi_metric_boundary_ids", "result", "scenario", "status"
      ] and
      .status == "failed" and .scenario == "assertion-failure" and
      .exit_status == 2 and .metric_status == 0 and
      .result == "scenario-assertion-failure.json" and
      .failure_context == "failure-context.txt" and
      .obi_metric_boundary_ids == ["basic"] and
      .java_bridge_diagnostics_reference == "terminal-java-diagnostics.json") and
    .[0].java_bridge_diagnostics == .[1] and
    (.[1] | .sealed == true and .available == true and
      .phase == "basic-after" and
      .reference == "phases/basic-after/java-diagnostics.txt")
  ' "$BUNDLE_DIR/scenario-assertion-failure-status.json" \
    "$BUNDLE_DIR/terminal-java-diagnostics.json" >/dev/null || return 1
  jq -e '
    .schema == "obi-java-remote-parent-terminal-metrics-v2" and
    .sealed == true and .available == false and
    .reason == "no-active-boundary" and .active_boundary_id == null
  ' "$BUNDLE_DIR/terminal-obi-metrics.json" >/dev/null || return 1
  [[ "$(key_value "$BUNDLE_DIR/failure-context.txt" stage)" == \
      deliberate-assertion-failure &&
    "$(key_value "$BUNDLE_DIR/failure-context.txt" exit_status)" == 2 &&
    "$(key_value "$BUNDLE_DIR/failure-context.txt" line)" =~ ^[1-9][0-9]*$ &&
    "$(key_value "$BUNDLE_DIR/failure-context.txt" line)" == \
      "$(jq -er '.failure_line | tostring' "$BUNDLE_DIR/run-status.json")" &&
    "$(key_value "$BUNDLE_DIR/failure-context.txt" command)" == \
      'die:\ deliberate\ assertion\ failure\ requested' ]]
}

raw_v3_manifest_add_phase() {
  local -r files="$1"
  local -r directories="$2"
  local -r phase="$3"
  local -r shape="$4"
  local service=""

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  printf 'phases/%s\n' "$phase" >>"$directories" || return 1
  case "$shape" in
    metric-live|metric-live-delta)
      printf '%s\n' \
        "phases/$phase/obi-metrics.prom" \
        "phases/$phase/obi-identity.json" >>"$files" || return 1
      [[ "$shape" == metric-live ]] ||
        printf 'phases/%s/obi-metrics.delta\n' "$phase" >>"$files" || return 1
      ;;
    full-live*|full-unavailable*)
      printf '%s\n' \
        "phases/$phase/obi-metrics.prom" \
        "phases/$phase/container-stats.jsonl" >>"$files" || return 1
      if [[ "$shape" == full-live* ]]; then
        printf 'phases/%s/obi-identity.json\n' "$phase" >>"$files" || return 1
      fi
      for service in obi apache-proxy java-backend coalesced-source trace-receiver; do
        printf 'phases/%s/%s-resources.txt\n' "$phase" "$service" \
          >>"$files" || return 1
        if [[ "$shape" == full-live* || "$service" != obi ]]; then
          printf 'phases/%s/%s-processes.txt\n' "$phase" "$service" \
            >>"$files" || return 1
        fi
      done
      case "$shape" in
        *-java|*-java-metric|*-java-java-delta|*-java-both)
          printf '%s\n' \
            "phases/$phase/java-diagnostics.txt" \
            "phases/$phase/java-diagnostics.stderr" >>"$files" || return 1
          ;;
        *-java-text|*-java-text-both)
          printf 'phases/%s/java-diagnostics.txt\n' "$phase" >>"$files" || return 1
          ;;
      esac
      case "$shape" in
        *-metric|*-both)
          printf 'phases/%s/obi-metrics.delta\n' "$phase" >>"$files" || return 1
          ;;
      esac
      case "$shape" in
        *-java-delta|*-both)
          printf 'phases/%s/java-diagnostics.delta\n' "$phase" >>"$files" || return 1
          ;;
      esac
      ;;
    stopped-attestation|java-only)
      if [[ "$shape" == stopped-attestation ]]; then
        printf 'phases/%s/obi-identity.json\n' "$phase" >>"$files" || return 1
      fi
      printf '%s\n' \
        "phases/$phase/java-diagnostics.txt" \
        "phases/$phase/java-diagnostics.stderr" >>"$files" || return 1
      ;;
    *) return 1 ;;
  esac
}

raw_v3_manifest_add_pair() {
  local -r files="$1"
  local -r pairs="$2"
  local -r label="$3"
  local -r reference="obi-metric-pairs/$label.json"

  [[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  printf '%s\n' "$reference" >>"$files" || return 1
  printf '%s\n' "$reference" >>"$pairs"
}

raw_v3_manifest_add_scenario() {
  local -r files="$1"
  local -r directories="$2"
  local -r pairs="$3"
  local -r statuses="$4"
  local -r label="$5"
  local -r before_shape="$6"
  local -r after_shape="$7"
  local -r metric_shape="$8"
  local -r retain_pair="$9"

  [[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  printf '%s\n' \
    "scenario-$label.json" \
    "scenario-$label.stderr.log" \
    "scenario-$label-status.json" >>"$files" || return 1
  printf 'scenario-%s-status.json\n' "$label" >>"$statuses" || return 1
  case "$metric_shape" in
    full)
      printf '%s\n' \
        "metrics-boundary-$label.prom" \
        "metrics-diagnostics-$label.prom" \
        "metrics-after-$label.prom" >>"$files" || return 1
      ;;
    boundary-after)
      printf '%s\n' \
        "metrics-boundary-$label.prom" \
        "metrics-after-$label.prom" >>"$files" || return 1
      ;;
    boundary)
      printf 'metrics-boundary-%s.prom\n' "$label" >>"$files" || return 1
      ;;
    none) ;;
    *) return 1 ;;
  esac
  raw_v3_manifest_add_phase \
    "$files" "$directories" "$label-before" "$before_shape" || return 1
  raw_v3_manifest_add_phase \
    "$files" "$directories" "$label-after" "$after_shape" || return 1
  if [[ "$retain_pair" == true ]]; then
    raw_v3_manifest_add_pair "$files" "$pairs" "$label" || return 1
  else
    [[ "$retain_pair" == false ]] || return 1
  fi
}

raw_v3_producer_boundary_owner() {
  local -r label="$1"

  case "$label" in
    basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
    slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff|\
    virtual-thread|netty|netty-server|dispatch|w3c|w3c-match|obi-flags|\
    disabled|uninstrumented|unix-w3c-stale|unix-generation-mismatch|\
    w3c-fault|auto-unavailable)
      printf '%s\n' "$label"
      ;;
    basic-delayed-otlp-suppression|delayed-otlp-prime-suppression)
      printf 'delayed-otlp-suppression\n'
      ;;
    security|concurrency-security-primary-victim|\
    basic-security-primary-recovery|\
    basic-security-primary-live-fd-recovery|security-primary-sibling|\
    security-primary-same-cgroup|primary-live-fd-probe|primary-live-fd-full|\
    primary-live-fd-security)
      printf 'security\n'
      ;;
    primary-w3c-stale|basic-primary-w3c-stale-recovery)
      printf 'primary-w3c-stale\n'
      ;;
    primary-generation-mismatch|primary-generation-mismatch-fault|\
    basic-primary-generation-mismatch-recovery)
      printf 'primary-generation-mismatch\n'
      ;;
    primary-w3c-fault-version-mismatch|primary-w3c-fault-bad-size|\
    primary-w3c-fault-zero-trace-id|primary-w3c-fault-zero-span-id|\
    basic-primary-w3c-fault-recovery)
      printf 'primary-w3c-fault\n'
      ;;
    permanent-absence|disabled-permanent-absence-baseline|\
    fail-open-permanent-absence|w3c-only-permanent-absence|\
    basic-permanent-absence-recovery)
      printf 'permanent-absence\n'
      ;;
    late-attach-obi-stopped|fail-open-obi-absent|w3c-only-obi-absent|\
    restart-late-attach-recovery)
      printf 'late-attach\n'
      ;;
    restart-fault|restart-restart-recovery)
      printf 'restart-during-traffic\n'
      ;;
    helper-attach-rejection|disabled-helper-attach-bridge-disabled|\
    helper-attach-failure-helper-unavailable|w3c-helper-unavailable|\
    basic-helper-attach-recovery)
      printf 'helper-attach-failure\n'
      ;;
    w3c-match-obi-stopped)
      printf 'w3c-match\n'
      ;;
    extension-controls-obi-stopped|w3c-only-extension-absent|\
    w3c-only-extension-disabled)
      printf 'extension-controls\n'
      ;;
    *) return 1 ;;
  esac
}

validate_raw_v3_terminal_private_state() {
  local -r kind="$1"
  local -r last='.last-valid-java-diagnostics.json'
  local expected_phase=""
  local reference=""
  local snapshot=""
  local diagnostics=""

  case "$kind" in
    acceptance) expected_phase=extension-controls-obi-stopped ;;
    assertion-failure) expected_phase=basic-after ;;
    *) return 1 ;;
  esac

  [[ -f "$BUNDLE_DIR/.terminal-java-diagnostics.lock" &&
    ! -L "$BUNDLE_DIR/.terminal-java-diagnostics.lock" &&
    ! -s "$BUNDLE_DIR/.terminal-java-diagnostics.lock" &&
    -f "$BUNDLE_DIR/.terminal-java-diagnostics-transition.lock" &&
    ! -L "$BUNDLE_DIR/.terminal-java-diagnostics-transition.lock" &&
    ! -s "$BUNDLE_DIR/.terminal-java-diagnostics-transition.lock" ]] || return 1
  validate_bounded_regular_file \
    .terminal-java-diagnostics.freeze 160 1 || return 1
  [[ "$(<"$BUNDLE_DIR/.terminal-java-diagnostics.freeze")" == \
    terminal-java-diagnostics-frozen-v1 ]] || return 1
  validate_single_json_object "$last" "$TERMINAL_JAVA_DIAGNOSTICS_MAX_BYTES" ||
    return 1
  jq -e --arg expected_phase "$expected_phase" '
    keys == [
      "available", "counters", "phase", "reference", "schema", "sealed", "snapshot"
    ] and
    .schema == "obi-java-bridge-terminal-diagnostics-v1" and
    .sealed == false and .available == true and
    ([.phase, .reference, .snapshot] | all(.[]; type == "string")) and
    (.counters | type == "object") and
    .phase == $expected_phase and
    .reference == ("phases/" + .phase + "/java-diagnostics.txt")
  ' "$BUNDLE_DIR/$last" >/dev/null || return 1
  reference="$(jq -er '.reference' "$BUNDLE_DIR/$last")" || return 1
  validate_java_diagnostics_reference "$reference" || return 1
  IFS= read -r diagnostics <"$BUNDLE_DIR/$reference" || return 1
  snapshot="$(jq -er '.snapshot' "$BUNDLE_DIR/$last")" || return 1
  [[ "$snapshot" == "$diagnostics" ]] || return 1
  jq -e --arg snapshot "$snapshot" '
    .counters == (
      $snapshot | split(",") |
      map(split("=") | {(.[0]): .[1]}) | add)
  ' "$BUNDLE_DIR/$last" >/dev/null || return 1
  jq -e -s '
    length == 2 and (.[0] as $last | .[1] == ($last | .sealed = true))
  ' "$BUNDLE_DIR/$last" \
    "$BUNDLE_DIR/terminal-java-diagnostics.json" >/dev/null
}

validate_raw_v3_exact_closure() {
  local -r kind="$1"
  local expected_files="$TMP_DIR/raw-v3-files.expected"
  local expected_directories="$TMP_DIR/raw-v3-directories.expected"
  local expected_pairs="$TMP_DIR/raw-v3-pairs.expected"
  local expected_statuses="$TMP_DIR/raw-v3-statuses.expected"
  local actual_files="$TMP_DIR/raw-v3-files.actual"
  local actual_directories="$TMP_DIR/raw-v3-directories.actual"
  local actual_pairs="$TMP_DIR/raw-v3-pairs.actual"
  local actual_statuses="$TMP_DIR/raw-v3-statuses.actual"
  local expected_pair_owners="$TMP_DIR/raw-v3-pair-owners.expected"
  local actual_pair_owners="$TMP_DIR/raw-v3-pair-owners.actual"
  local expected_status_owners="$TMP_DIR/raw-v3-status-owners.expected"
  local actual_status_owners="$TMP_DIR/raw-v3-status-owners.actual"
  local label=""
  local owner=""
  local reference=""
  local mode=""
  local control=""
  local attempt_name=""
  local attempt_status=""
  local command_status=""
  local validation_status=""
  local recovery_status=""
  local monitor_status=""
  local attempts=""
  local cleanup_status=""
  local -i attempt=0
  local -i final_attempt=0
  local -a normal_scenarios=(
    basic keepalive pipelining concurrency connection-churn fd-port-reuse
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff
    virtual-thread netty netty-server dispatch w3c obi-flags
    basic-delayed-otlp-suppression basic-primary-w3c-stale-recovery
    basic-security-primary-live-fd-recovery basic-primary-generation-mismatch-recovery
    basic-primary-w3c-fault-recovery basic-permanent-absence-recovery
    restart-late-attach-recovery restart-restart-recovery
    basic-helper-attach-recovery
  )
  local -a no_diagnostics_scenarios=(
    basic-security-primary-recovery
    helper-attach-failure-helper-unavailable
    w3c-helper-unavailable
  )
  local -a disabled_bridge_scenarios=(
    disabled-permanent-absence-baseline
    disabled-helper-attach-bridge-disabled
    disabled
  )
  local -a stopped_scenarios=(
    fail-open-permanent-absence w3c-only-permanent-absence
    fail-open-obi-absent w3c-only-obi-absent
    w3c-only-extension-absent w3c-only-extension-disabled uninstrumented
  )

  : >"$expected_files"
  printf '%s\n' phases obi-metric-pairs >"$expected_directories" || return 1
  : >"$expected_pairs"
  : >"$expected_statuses"
  printf '%s\n' \
    source-state.txt source-tree.manifest git-status.txt bridge-build.log \
    environment.txt official-javaagent.json bridge-artifacts.json \
    bridge-artifacts.sha256 bridge-metadata.sha256 bridge-source-revision.txt \
    bridge-source-tree.sha256 certificates.json compose-resolved.yaml compose-up.log \
    apache-instrumentation-startup.prom apache-instrumentation-startup.txt \
    java-selected-transport-configuration.txt host-topology.txt \
    bpftool-feature-probe.txt bpftool-maps.txt bpftool-programs.txt \
    compose-images.json container-identities.txt image-identities.txt \
    java-version.txt apache-version.txt apache-openssl-version.txt \
    obi-startup.log java-startup.log apache-startup.log \
    obi-metric-boundary-index.json .obi-metric-boundary-index.freeze \
    terminal-java-diagnostics.json terminal-obi-metrics.json run-status.json \
    .terminal-java-diagnostics.lock \
    .terminal-java-diagnostics-transition.lock \
    .terminal-java-diagnostics.freeze .last-valid-java-diagnostics.json \
    compose-ps.txt compose.log final-receiver-snapshot.json \
    >>"$expected_files" || return 1
  if [[ "$kind" == acceptance ]]; then
    printf '%s\n' \
      apache-instrumentation-recreate-instrumented.prom \
      apache-instrumentation-recreate-instrumented.txt \
      apache-instrumentation-disabled-control.prom \
      apache-instrumentation-disabled-control.txt \
      apache-instrumentation-late-attach.prom \
      apache-instrumentation-late-attach.txt \
      apache-instrumentation-restart-fault-recovery.prom \
      apache-instrumentation-restart-fault-recovery.txt \
      apache-instrumentation-helper-attach-failure.prom \
      apache-instrumentation-helper-attach-failure.txt \
      apache-instrumentation-helper-attach-recovery.prom \
      apache-instrumentation-helper-attach-recovery.txt \
      apache-instrumentation-drain-late-attach.prom \
      apache-instrumentation-drain-late-attach.txt \
      runtime-assertions-all.txt runtime-assertions-basic.txt \
      runtime-assertions-delayed-otlp-suppression.txt \
      runtime-assertions-obi-absent.txt \
      runtime-assertions-permanent-absence.txt \
      runtime-assertions-extension-absent.txt \
      runtime-assertions-extension-disabled.txt \
      runtime-assertions-helper-attach-fault.txt \
      runtime-assertions-primary-live-fd-security.txt \
      runtime-assertions-primary-generation-mismatch.txt \
      runtime-assertions-primary-w3c-fault.txt \
      runtime-assertions-disabled.txt runtime-assertions-uninstrumented.txt \
      duplicate-suppression-all.prom duplicate-suppression-disabled.prom \
      duplicate-suppression-delayed-otlp-before-request.prom \
      duplicate-suppression-delayed-otlp-before-export.prom \
      duplicate-suppression-delayed-otlp-ready.prom \
      duplicate-suppression-post-delayed-otlp-suppression-restoration.prom \
      duplicate-suppression-primary-live-descriptor-security-preparation.prom \
      duplicate-suppression-post-primary-live-descriptor-security-recovery.prom \
      duplicate-suppression-matching-W3C-and-OBI-preparation.prom \
      duplicate-suppression-post-match-bridge-restoration.prom \
      duplicate-suppression-primary-W3C-stale-preparation.prom \
      duplicate-suppression-post-primary-W3C-stale-recovery.prom \
      duplicate-suppression-primary-W3C-fault-preparation.prom \
      duplicate-suppression-post-primary-W3C-fault-recovery.prom \
      duplicate-suppression-primary-generation-mismatch-preparation.prom \
      duplicate-suppression-post-primary-generation-mismatch-recovery.prom \
      duplicate-suppression-post-permanent-absence-recovery.prom \
      duplicate-suppression-late-attach-recovery.prom \
      duplicate-suppression-restart-fault-recovery.prom \
      duplicate-suppression-helper-attach-failure-preparation.prom \
      map-pressure-pressure-prepare.json map-pressure-pressure-prepare.stderr.log \
      map-pressure-pressure-fill.json map-pressure-pressure-fill.stderr.log \
      map-pressure-pressure-cleanup.json map-pressure-pressure-cleanup.stderr.log \
      map-pressure-pressure-monitor.log map-pressure-pressure-pressured.prom \
      map-pressure-pressure-traffic-complete.prom \
      map-pressure-pressure-recovered.prom \
      map-pressure-pressure-recovered-sample-01.prom \
      map-pressure-pressure-recovered-sample-02.prom \
      map-pressure-pressure-recovered-samples.log \
      delayed-otlp-window.txt delayed-otlp-receiver-before-request.json \
      delayed-otlp-receiver-before-export.json delayed-otlp-receiver-ready.json \
      compose-primary-live-fd-resolved.yaml \
      security-primary-sibling.log security-primary-sibling.json \
      security-primary-sibling.cgroup security-primary-same-cgroup.log \
      security-primary-same-cgroup.txt security-primary-java.cgroup \
      security-primary-probe.cgroup security-primary-probe.status \
      metrics-security-primary-sibling-ready.prom \
      metrics-security-primary-sibling-complete.prom \
      metrics-security-primary-probe-ready.prom \
      primary-live-fd-security-armed.txt primary-live-fd-security-released.txt \
      primary-live-fd-security-consumed.txt security-primary-live-fd.log \
      scenario-security-primary-live-fd-victim.json \
      scenario-security-primary-live-fd-victim.stderr.log \
      metrics-security-primary-live-fd-before.prom \
      metrics-security-primary-live-fd-probe.prom \
      metrics-security-primary-live-fd-after.prom \
      scenario-primary-live-fd-security-status.json scenario-security-status.json \
      w3c-match-matching-bridge.log compose-primary-fault-resolved.yaml \
      primary-generation-mismatch-barrier-armed.txt \
      primary-generation-mismatch-barrier-released.txt \
      primary-generation-mismatch-barrier-consumed.txt \
      scenario-primary-generation-mismatch.json \
      scenario-primary-generation-mismatch.stderr.log \
      generation-mismatch-helper.json generation-mismatch-helper.stderr.log \
      metrics-primary-generation-mismatch-take.prom \
      scenario-primary-generation-mismatch-status.json \
      compose-disabled-control.yaml permanent-absence-lifetime.txt \
      permanent-absence-java-before.txt permanent-absence-java-after.txt \
      permanent-absence-java.log scenario-permanent-absence-status.json \
      scenario-restart-fault.json scenario-restart-fault.stderr.log \
      scenario-restart-fault-status.json restart-fault-diagnostics.txt \
      compose-helper-attach-failure.yaml helper-attach-failure-obi.log \
      helper-attach-failure-java.log helper-attach-failure-metrics-before.prom \
      helper-attach-failure-metrics-after.prom \
      helper-attach-failure-metrics-quiet.prom \
      helper-attach-failure-metrics-recovery.prom \
      helper-attach-failure-metrics.delta helper-attach-failure-obi-before.txt \
      helper-attach-failure-obi-fault.txt \
      helper-attach-failure-obi-recovery.txt \
      helper-attach-failure-java-fault.txt \
      helper-attach-failure-java-after-traffic.txt \
      helper-attach-failure-java-recovery.txt \
      helper-attach-failure-java-diagnostics.txt \
      compose-uninstrumented-control.yaml \
      >>"$expected_files" || return 1

    for control in permanent-absence-disabled permanent-absence \
      helper-attach-bridge-disabled helper-attach-failure helper-attach-recovery \
      instrumented-control uninstrumented-control; do
      printf '%s\n' \
        "$control-response.json" \
        "$control-response.normalized.json" \
        "$control-response.status" >>"$expected_files" || return 1
    done

    for label in tls-boundary coalesced-bridge; do
      printf '%s\n' \
        "receive-cursor-map-$label-before.json" \
        "receive-cursor-map-$label-before.stderr.log" \
        "receive-cursor-map-$label-after.json" \
        "receive-cursor-map-$label-status.json" \
        "receive-cursor-map-$label-recovery-samples.log" \
        >>"$expected_files" || return 1
      attempts="$(jq -er '.attempts' \
        "$BUNDLE_DIR/receive-cursor-map-$label-status.json")" || return 1
      [[ "$attempts" =~ ^[0-9]+$ ]] || return 1
      ((attempts >= 2 && attempts <= 10)) || return 1
      for ((attempt = 1; attempt <= attempts; attempt++)); do
        printf -v attempt_name \
          'receive-cursor-map-%s-recovery-attempt-%02d' "$label" "$attempt"
        printf '%s\n' "$attempt_name.json" "$attempt_name.stderr.log" \
          >>"$expected_files" || return 1
      done
    done

    cleanup_status="$(find -- "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -type f \
      -name 'map-pressure-pressure-cleanup-attempt-??.status' -print |
      LC_ALL=C sort | tail -n 1)" || return 1
    [[ "${cleanup_status##*/}" =~ ^map-pressure-pressure-cleanup-attempt-0([1-3])\.status$ ]] ||
      return 1
    final_attempt="${BASH_REMATCH[1]}"
    for ((attempt = 1; attempt <= final_attempt; attempt++)); do
      printf -v attempt_name 'map-pressure-pressure-cleanup-attempt-%02d' "$attempt"
      printf '%s\n' "$attempt_name.json" "$attempt_name.stderr.log" \
        "$attempt_name.status" >>"$expected_files" || return 1
      attempt_status="$BUNDLE_DIR/$attempt_name.status"
      validate_key_value_file "$attempt_status" || return 1
      [[ "$(awk 'END { print NR + 0 }' "$attempt_status")" == 4 &&
        "$(cut -d= -f1 -- "$attempt_status" | LC_ALL=C sort | tr '\n' ' ')" == \
          'command_status monitor_status recovery_status validation_status ' ]] ||
        return 1
      command_status="$(key_value "$attempt_status" command_status)" || return 1
      validation_status="$(key_value "$attempt_status" validation_status)" ||
        return 1
      recovery_status="$(key_value "$attempt_status" recovery_status)" || return 1
      monitor_status="$(key_value "$attempt_status" monitor_status)" || return 1
      [[ "$command_status" =~ ^(0|[1-9][0-9]{0,2})$ &&
        "$monitor_status" == 0 ]] || return 1
      ((command_status <= 255)) || return 1
      case "$command_status:$validation_status:$recovery_status" in
        0:passed:passed)
          ((attempt == final_attempt)) || return 1
          printf '%s\n' \
            "$attempt_name-recovered.prom" \
            "$attempt_name-recovered-sample-01.prom" \
            "$attempt_name-recovered-sample-02.prom" \
            "$attempt_name-recovered-samples.log" \
            >>"$expected_files" || return 1
          ;;
        0:passed:failed)
          ((attempt < final_attempt)) || return 1
          if [[ -e "$BUNDLE_DIR/$attempt_name-recovered.prom" ||
            -e "$BUNDLE_DIR/$attempt_name-recovered-sample-01.prom" ||
            -e "$BUNDLE_DIR/$attempt_name-recovered-sample-02.prom" ]]; then
            [[ -f "$BUNDLE_DIR/$attempt_name-recovered.prom" &&
              ! -L "$BUNDLE_DIR/$attempt_name-recovered.prom" &&
              -f "$BUNDLE_DIR/$attempt_name-recovered-sample-01.prom" &&
              ! -L "$BUNDLE_DIR/$attempt_name-recovered-sample-01.prom" &&
              -f "$BUNDLE_DIR/$attempt_name-recovered-sample-02.prom" &&
              ! -L "$BUNDLE_DIR/$attempt_name-recovered-sample-02.prom" ]] ||
              return 1
            printf '%s\n' \
              "$attempt_name-recovered.prom" \
              "$attempt_name-recovered-sample-01.prom" \
              "$attempt_name-recovered-sample-02.prom" \
              >>"$expected_files" || return 1
          fi
          printf '%s-recovered-samples.log\n' "$attempt_name" \
            >>"$expected_files" || return 1
          ;;
        0:failed:passed)
          ((attempt < final_attempt)) || return 1
          printf '%s\n' \
            "$attempt_name-recovered.prom" \
            "$attempt_name-recovered-sample-01.prom" \
            "$attempt_name-recovered-sample-02.prom" \
            "$attempt_name-recovered-samples.log" >>"$expected_files" || return 1
          ;;
        0:failed:not-run|[1-9]*:not-run:not-run)
          ((attempt < final_attempt)) || return 1
          ;;
        *) return 1 ;;
      esac
    done

    for label in "${normal_scenarios[@]}"; do
      if [[ "$label" == coalesced-bridge || "$label" == timeout-retry ]]; then
        raw_v3_manifest_add_scenario \
          "$expected_files" "$expected_directories" "$expected_pairs" \
          "$expected_statuses" "$label" full-live-java \
          full-live-java-text-both full true || return 1
      else
        raw_v3_manifest_add_scenario \
          "$expected_files" "$expected_directories" "$expected_pairs" \
          "$expected_statuses" "$label" full-live-java \
          full-live-java-both full true || return 1
      fi
    done
    raw_v3_manifest_add_scenario \
      "$expected_files" "$expected_directories" "$expected_pairs" \
      "$expected_statuses" primary-w3c-stale full-live-java-text \
      full-live-java-text-both full true || return 1
    for label in "${no_diagnostics_scenarios[@]}"; do
      raw_v3_manifest_add_scenario \
        "$expected_files" "$expected_directories" "$expected_pairs" \
        "$expected_statuses" "$label" full-live full-live-metric \
        boundary-after true || return 1
    done
    raw_v3_manifest_add_scenario \
      "$expected_files" "$expected_directories" "$expected_pairs" \
      "$expected_statuses" concurrency-security-primary-victim metric-live \
      metric-live-delta boundary-after true || return 1
    for label in "${disabled_bridge_scenarios[@]}"; do
      raw_v3_manifest_add_scenario \
        "$expected_files" "$expected_directories" "$expected_pairs" \
        "$expected_statuses" "$label" full-live-java full-live-java-metric \
        none true || return 1
    done
    for label in "${stopped_scenarios[@]}"; do
      raw_v3_manifest_add_scenario \
        "$expected_files" "$expected_directories" "$expected_pairs" \
        "$expected_statuses" "$label" full-unavailable-java \
        full-unavailable-java-metric none false || return 1
    done
    raw_v3_manifest_add_scenario \
      "$expected_files" "$expected_directories" "$expected_pairs" \
      "$expected_statuses" w3c-match full-unavailable-java \
      full-unavailable-java-both boundary false || return 1

    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      delayed-otlp-prime-before full-live || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      delayed-otlp-suppression-after full-live || return 1
    raw_v3_manifest_add_pair \
      "$expected_files" "$expected_pairs" delayed-otlp-prime-suppression || return 1

    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      security-primary-diagnostics-before java-only || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      security-primary-diagnostics-after java-only || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      security-primary-before full-live || return 1
    for label in security-primary-sibling-ready security-primary-probe-ready; do
      raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
        "$label" metric-live-delta || return 1
    done
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      security-primary-sibling-complete metric-live || return 1
    for label in security-primary-live-fd-before security-primary-live-fd-probe \
      security-primary-live-fd-after; do
      if [[ "$label" == security-primary-live-fd-before ]]; then
        raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
          "$label" metric-live || return 1
      else
        raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
          "$label" metric-live-delta || return 1
      fi
    done
    for label in security-primary-sibling security-primary-same-cgroup \
      primary-live-fd-probe primary-live-fd-full; do
      raw_v3_manifest_add_pair "$expected_files" "$expected_pairs" "$label" || return 1
    done
    printf '%s\n' scenario-primary-live-fd-security-status.json \
      scenario-security-status.json >>"$expected_statuses" || return 1

    for label in w3c-match late-attach extension-controls; do
      raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
        "$label-obi-running" full-live || return 1
      raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
        "$label-obi-stopped" stopped-attestation || return 1
      raw_v3_manifest_add_pair \
        "$expected_files" "$expected_pairs" "$label-obi-stopped" || return 1
    done
    printf 'metrics-boundary-late-attach.prom\n' >>"$expected_files" || return 1

    for mode in version-mismatch bad-size zero-trace-id zero-span-id; do
      label="primary-w3c-fault-$mode"
      printf '%s\n' \
        "scenario-$label.json" "scenario-$label.stderr.log" \
        "scenario-$label-status.json" "metrics-boundary-$label.prom" \
        "metrics-after-$label.prom" \
        "$label-run-1-armed.txt" "$label-run-1-consumed.txt" \
        >>"$expected_files" || return 1
      printf 'scenario-%s-status.json\n' "$label" >>"$expected_statuses" || return 1
      raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
        "$label-before" full-live-java-text || return 1
      raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
        "$label-after" full-live-java-text-both || return 1
      raw_v3_manifest_add_pair "$expected_files" "$expected_pairs" "$label" || return 1
    done

    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      primary-generation-mismatch-before full-live-java-text || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      primary-generation-mismatch-after full-live-java-text-both || return 1
    raw_v3_manifest_add_pair "$expected_files" "$expected_pairs" \
      primary-generation-mismatch-fault || return 1
    printf 'metrics-boundary-primary-generation-mismatch.prom\n' \
      >>"$expected_files" || return 1
    printf 'scenario-primary-generation-mismatch-status.json\n' \
      >>"$expected_statuses" || return 1

    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      permanent-absence java-only || return 1
    printf 'scenario-permanent-absence-status.json\n' \
      >>"$expected_statuses" || return 1

    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      restart-fault-before full-live-java || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      restart-fault-after full-live-java-java-delta || return 1
    raw_v3_manifest_add_pair \
      "$expected_files" "$expected_pairs" restart-fault || return 1
    printf 'scenario-restart-fault-status.json\n' >>"$expected_statuses" || return 1
    printf 'restart-control\n' >>"$expected_directories" || return 1
    for control in events.log pre-stop-ready obi-stopped stopped-traffic-complete \
      obi-ready post-restart-traffic-complete; do
      printf 'restart-control/%s\n' "$control" >>"$expected_files" || return 1
    done

    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      helper-attach-failure-before full-live || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      helper-attach-failure-after full-live || return 1
    raw_v3_manifest_add_pair \
      "$expected_files" "$expected_pairs" helper-attach-rejection || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      helper-attach-recovery java-only || return 1

    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      pressure-pressured full-live || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      final full-unavailable-java || return 1

    for label in unix-w3c-stale unix-generation-mismatch w3c-fault \
      auto-unavailable; do
      printf 'scenario-%s-status.json\n' "$label" >>"$expected_files" || return 1
      printf 'scenario-%s-status.json\n' "$label" >>"$expected_statuses" || return 1
    done
  else
    printf '%s\n' runtime-assertions-assertion-failure.txt \
      duplicate-suppression-assertion-failure.prom \
      scenario-assertion-failure.json scenario-assertion-failure-status.json \
      failure-context.txt \
      >>"$expected_files" || return 1
    raw_v3_manifest_add_scenario \
      "$expected_files" "$expected_directories" "$expected_pairs" \
      "$expected_statuses" basic full-live-java full-live-java-both \
      full true || return 1
    raw_v3_manifest_add_phase "$expected_files" "$expected_directories" \
      final java-only || return 1
  fi

  LC_ALL=C sort -u -o "$expected_files" -- "$expected_files" || return 1
  LC_ALL=C sort -u -o "$expected_directories" -- "$expected_directories" || return 1
  LC_ALL=C sort -u -o "$expected_pairs" -- "$expected_pairs" || return 1
  LC_ALL=C sort -u -o "$expected_statuses" -- "$expected_statuses" || return 1

  jq -r '.boundaries[].captures[] |
    select(.kind == "pair" and .state == "captured") | .pair_reference' \
    <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" | LC_ALL=C sort -u \
    >"$actual_pairs" || return 1
  cmp -s -- "$expected_pairs" "$actual_pairs" || return 1
  jq -r '.boundaries[].status_references[].reference' \
    <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" | LC_ALL=C sort -u \
    >"$actual_statuses" || return 1
  cmp -s -- "$expected_statuses" "$actual_statuses" || return 1

  : >"$expected_pair_owners"
  while IFS= read -r reference; do
    [[ "$reference" =~ ^obi-metric-pairs/([a-z0-9][a-z0-9-]{0,63})\.json$ ]] ||
      return 1
    owner="$(raw_v3_producer_boundary_owner "${BASH_REMATCH[1]}")" || return 1
    printf '%s\t%s\n' "$owner" "$reference" \
      >>"$expected_pair_owners" || return 1
  done <"$expected_pairs"
  LC_ALL=C sort -o "$expected_pair_owners" -- "$expected_pair_owners" || return 1
  jq -r '
    .boundaries[] as $boundary | $boundary.captures[] |
    select(.kind == "pair" and .state == "captured") |
    [$boundary.id, .pair_reference] | @tsv
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" | LC_ALL=C sort \
    >"$actual_pair_owners" || return 1
  cmp -s -- "$expected_pair_owners" "$actual_pair_owners" || return 1

  : >"$expected_status_owners"
  while IFS= read -r reference; do
    [[ "$reference" =~ ^scenario-([a-z0-9][a-z0-9-]{0,95})-status\.json$ ]] ||
      return 1
    owner="$(raw_v3_producer_boundary_owner "${BASH_REMATCH[1]}")" || return 1
    printf '%s\t%s\n' "$owner" "$reference" \
      >>"$expected_status_owners" || return 1
  done <"$expected_statuses"
  LC_ALL=C sort -o "$expected_status_owners" -- "$expected_status_owners" ||
    return 1
  jq -r '
    .boundaries[] as $boundary | $boundary.status_references[] |
    [$boundary.id, .reference] | @tsv
  ' <<<"$OBI_METRIC_BOUNDARY_INDEX_PAYLOAD" | LC_ALL=C sort \
    >"$actual_status_owners" || return 1
  cmp -s -- "$expected_status_owners" "$actual_status_owners" || return 1

  [[ -z "$(find -- "$BUNDLE_DIR" -mindepth 1 \
    ! -type f ! -type d -print -quit)" ]] || return 1
  find -- "$BUNDLE_DIR" -mindepth 1 -type f -printf '%P\n' |
    LC_ALL=C sort >"$actual_files" || return 1
  find -- "$BUNDLE_DIR" -mindepth 1 -type d -printf '%P\n' |
    LC_ALL=C sort >"$actual_directories" || return 1
  cmp -s -- "$expected_files" "$actual_files" || return 1
  cmp -s -- "$expected_directories" "$actual_directories"
}

raw_resource_value_at_most() {
  local -r value="$1"
  local -r maximum="$2"
  local comparison=""

  uint64_string_compare "$value" "$maximum" comparison || return 1
  ((comparison <= 0))
}

normalize_raw_resource_record() {
  local -r relative_path="$1"
  local -r path="$BUNDLE_DIR/$relative_path"
  local -a lines=()
  local -a vm_names=(VmPeak VmSize VmRSS VmData VmStk VmExe VmLib)
  local -a vm_values=()
  local container_id=""
  local host_pid=""
  local threads=""
  local fds=""
  local value=""
  local -i index=0

  validate_bounded_regular_file \
    "$relative_path" "$RAW_V3_RESOURCE_MAX_BYTES" 11 || return 1
  [[ -s "$path" && -z "$(tail -c 1 -- "$path")" ]] || return 1
  mapfile -t lines <"$path" || return 1
  ((${#lines[@]} == 11)) || return 1
  [[ "${lines[0]}" =~ ^container_id=([0-9a-f]{64})$ ]] || return 1
  container_id="${BASH_REMATCH[1]}"
  [[ "${lines[1]}" =~ ^host_pid=([1-9][0-9]*)$ ]] || return 1
  host_pid="${BASH_REMATCH[1]}"
  raw_resource_value_at_most "$host_pid" "$RAW_V3_RESOURCE_VM_MAX_KIB" ||
    return 1
  for ((index = 0; index < ${#vm_names[@]}; index++)); do
    [[ "${lines[index + 2]}" =~ ^${vm_names[index]}:[[:space:]]+([0-9]+)[[:space:]]+kB$ ]] ||
      return 1
    value="${BASH_REMATCH[1]}"
    raw_resource_value_at_most "$value" "$RAW_V3_RESOURCE_VM_MAX_KIB" ||
      return 1
    vm_values+=("$value")
  done
  [[ "${lines[9]}" =~ ^Threads:[[:space:]]+([0-9]+)$ ]] || return 1
  threads="${BASH_REMATCH[1]}"
  raw_resource_value_at_most "$threads" "$RAW_V3_RESOURCE_THREADS_MAX" ||
    return 1
  [[ "${lines[10]}" =~ ^FDs:[[:space:]]+([0-9]+)$ ]] || return 1
  fds="${BASH_REMATCH[1]}"
  raw_resource_value_at_most "$fds" "$RAW_V3_RESOURCE_FDS_MAX" || return 1
  raw_resource_value_at_most "${vm_values[2]}" \
    "$RAW_V3_RESOURCE_RSS_MAX_KIB" || return 1
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$container_id" "$host_pid" "${vm_values[2]}" "$threads" "$fds"
}

validate_raw_resource_recovery() {
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
  local identity_reference=""
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
  local -i difference=0

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
      record="$(normalize_raw_resource_record \
        "phases/$phase/$service-resources.txt")" || return 1
      IFS=$'\t' read -r container_id host_pid rss threads fds <<<"$record"
      [[ -n "$container_id" && -n "$host_pid" && -n "$rss" &&
        -n "$threads" && -n "$fds" ]] || return 1
      if [[ "$service" == obi ]]; then
        identity_reference="phases/$phase/obi-identity.json"
        validate_obi_process_identity_reference "$identity_reference" || return 1
        [[ "${OBI_IDENTITY_STATE[$identity_reference]}" == running ]] || return 1
        identity_container_id="${OBI_IDENTITY_CONTAINER_ID[$identity_reference]}"
        identity_host_pid="$(jq -er '.host_pid' \
          "$BUNDLE_DIR/$identity_reference")" || return 1
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
        continue
      fi
      [[ "$container_id" == "$baseline_container_id" &&
        "$host_pid" == "$baseline_host_pid" ]] || return 1
      ((rss - baseline_rss <= rss_growth_cap)) || return 1
      ((threads - baseline_threads <= 32)) || return 1
      ((fds - baseline_fds <= 8)) || return 1
      recovery_rss+=("$rss")
      recovery_threads+=("$threads")
      recovery_fds+=("$fds")
    done
    ((${#recovery_rss[@]} == 2 && ${#recovery_threads[@]} == 2 &&
      ${#recovery_fds[@]} == 2)) || return 1
    difference=$((recovery_rss[0] - recovery_rss[1]))
    if ((difference < 0)); then
      difference=$((-difference))
    fi
    ((difference <= 32768)) || return 1
    difference=$((recovery_threads[0] - recovery_threads[1]))
    if ((difference < 0)); then
      difference=$((-difference))
    fi
    ((difference <= 2)) || return 1
    difference=$((recovery_fds[0] - recovery_fds[1]))
    if ((difference < 0)); then
      difference=$((-difference))
    fi
    ((difference <= 2)) || return 1
  done
  ((${#baseline_container_ids[@]} == 5 && ${#baseline_host_pids[@]} == 5)) ||
    return 1
  [[ "$(printf '%s\n' "${baseline_container_ids[@]}" | LC_ALL=C sort -u |
    awk 'END { print NR + 0 }')" == 5 ]] || return 1
  [[ "$(printf '%s\n' "${baseline_host_pids[@]}" | LC_ALL=C sort -u |
    awk 'END { print NR + 0 }')" == 5 ]]
}

validate_raw_official_javaagent_metadata() {
  validate_single_json_object official-javaagent.json "$RAW_V3_JSON_MAX_BYTES" ||
    return 1
  jq -e --arg version "$OTEL_AGENT_VERSION" \
    --arg sha256 "$OTEL_AGENT_SHA256" --arg url "$OTEL_AGENT_URL" '
    keys == ["distribution", "sha256", "url", "version"] and
    . == {
      distribution: "otel",
      sha256: $sha256,
      url: $url,
      version: $version
    }
  ' "$BUNDLE_DIR/official-javaagent.json" >/dev/null
}

validate_raw_v3_bundle() {
  local -r kind="$1"
  local scenario=""
  local -a stress_scenarios=(
    basic keepalive pipelining concurrency connection-churn fd-port-reuse
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff
  )

  for scenario in environment.txt source-state.txt source-tree.manifest git-status.txt \
    bridge-source-revision.txt bridge-source-tree.sha256 bridge-artifacts.json \
    official-javaagent.json \
    run-status.json terminal-java-diagnostics.json terminal-obi-metrics.json \
    obi-metric-boundary-index.json .obi-metric-boundary-index.freeze; do
    require_regular_file "$scenario"
  done
  validate_raw_source_provenance "$kind" || {
    die "raw v3 source, status, or boundary provenance is inconsistent"
  }
  validate_raw_official_javaagent_metadata ||
    die "raw official agent identity does not match the source-pinned OTel release"
  validate_raw_v3_terminal_private_state "$kind" || {
    die "raw terminal Java private publication state is inconsistent"
  }
  if [[ "$kind" == acceptance ]]; then
    for scenario in "${stress_scenarios[@]}"; do
      validate_raw_scenario_graph "$scenario" || {
        die "raw v3 stress evidence is invalid: $scenario"
      }
    done
    validate_raw_stress_pair_authority || {
      die "raw v3 stress metric-pair phase authority is invalid"
    }
    validate_raw_pressure_evidence || die "raw v3 pressure evidence is invalid"
    validate_raw_resource_recovery || {
      die "raw v3 container-leader resource recovery evidence is invalid"
    }
  else
    validate_raw_scenario_graph basic || {
      die "raw deliberate-failure control did not first pass basic"
    }
    validate_raw_assertion_failure_control || {
      die "raw deliberate-failure authority is invalid"
    }
  fi
  validate_raw_v3_exact_closure "$kind" || {
    die "raw v3 file and directory closure is invalid"
  }
}

# The bounded public contract is implemented by one pinned portable verifier.
# The source verifier hashes those bytes before execution, so bundle-controlled
# script replacement cannot select an alternate validation path.
validate_claim_summary_bundle() {
  local verifier_sha256=""

  [[ -f "$BUNDLE_DIR/verify.sh" && ! -L "$BUNDLE_DIR/verify.sh" ]] || return 1
  verifier_sha256="$(sha256sum <"$BUNDLE_DIR/verify.sh")" || return 1
  verifier_sha256="${verifier_sha256%% *}"
  [[ "$verifier_sha256" == "$CLAIM_VERIFY_SH_SHA256" ]] || return 1
  find -- "$BUNDLE_DIR" -type f -exec chmod 0444 -- {} + || return 1
  find -- "$BUNDLE_DIR" -depth -type d -exec chmod 0555 -- {} + || return 1
  (CDPATH='' cd / && bash "$BUNDLE_DIR/verify.sh" >/dev/null)
}

validate_json_provenance() {
  local -r evidence_id="$1"
  local -r revision="$2"
  local -r source_tree_sha256="$3"
  local -r allow_historical_status_schema="$4"
  local run_status_schema=""

  validate_single_json_object run-status.json "$RUN_STATUS_MAX_BYTES" || {
    die "run status is not one bounded JSON object"
  }
  run_status_schema="$(jq -er -s '
    if length != 1 or (.[0] | type) != "object" then
      error("invalid run status")
    elif .[0] | has("schema") then
      if (.[0].schema | type) == "string" then
        .[0].schema
      else
        error("invalid run-status schema")
      end
    else
      "__pre_v2__"
    end
  ' "$BUNDLE_DIR/run-status.json")" || {
    die "run status is malformed"
  }
  case "$run_status_schema" in
    obi-apache-java-https-run-status-v3)
      validate_run_status_v3 "$evidence_id" || {
        die "run-status v3 evidence is malformed or inconsistent"
      }
      ;;
    obi-apache-java-https-run-status-v2)
      validate_run_status_v2 "$evidence_id" || {
        die "run-status v2 evidence is malformed or inconsistent"
      }
      ;;
    __pre_v2__)
      uses_pre_v2_run_status_schema "$evidence_id" "$revision" || {
        die "schema-less run status is not an allowlisted historical result"
      }
      validate_pre_v2_run_status \
        "$evidence_id" "$allow_historical_status_schema" || {
        die "historical run status is not an eligible retained acceptance result"
      }
      ;;
    *)
      die "run status uses an unsupported schema"
      ;;
  esac
  jq -e -s --arg evidence_id "$evidence_id" --arg revision "$revision" '
    length == 1 and
    (.[0] |
      type == "object" and
      .sanitized == true and
      .evidence_id == $evidence_id and
      .source_revision == $revision)
  ' "$BUNDLE_DIR/runtime-metadata.json" >/dev/null || {
    die "runtime metadata does not match the retained evidence identity"
  }
  jq -e -s --arg revision "$revision" --arg source_tree_sha256 "$source_tree_sha256" '
    length == 1 and
    (.[0] |
      type == "object" and
      .source_revision == $revision and
      .source_tree_sha256 == $source_tree_sha256)
  ' "$BUNDLE_DIR/bridge-artifacts.json" >/dev/null || {
    die "bridge artifact metadata does not match the retained source identity"
  }
}

is_current_code_compatible_path() {
  local -r path="$1"

  case "$path" in
    examples/apache-java-https/evidence/*|\
    examples/apache-java-https/focused-validation/*)
      return 0
      ;;
    devdocs/*.md)
      return 0
      ;;
    examples/apache-java-https/*.md)
      [[ "${path#examples/apache-java-https/}" != */* ]]
      return
      ;;
    *.md)
      [[ "$path" != */* ]]
      return
      ;;
  esac
  return 1
}

validate_current_code_compatibility() {
  local -r tested_revision="$1"
  local changed_paths="$TMP_DIR/current-code-changed-paths"
  local changed_path=""
  local quoted_path=""

  if ! git -C "$REPO_ROOT" merge-base --is-ancestor \
    "$tested_revision" "$TRUSTED_HEAD"; then
    die "current-code policy requires the tested revision to be an ancestor of current HEAD"
  fi
  git -C "$REPO_ROOT" diff --name-only --no-renames --no-ext-diff --no-textconv -z \
    "$tested_revision" "$TRUSTED_HEAD" -- >"$changed_paths" || {
    die "current-code policy could not compare the tested revision with current HEAD"
  }
  while IFS= read -r -d '' changed_path; do
    if ! is_current_code_compatible_path "$changed_path"; then
      printf -v quoted_path '%q' "$changed_path"
      die "current-code policy rejects a post-test source change: $quoted_path"
    fi
  done <"$changed_paths"
}

validate_provenance() {
  local -r environment="$BUNDLE_DIR/environment.txt"
  local -r source_state="$BUNDLE_DIR/source-state.txt"
  local evidence_id=""
  local environment_revision=""
  local source_state_revision=""
  local bridge_revision=""
  local environment_tree_sha256=""
  local source_state_tree_sha256=""
  local bridge_tree_sha256=""
  local manifest_tree_sha256=""
  local expected_manifest="$TMP_DIR/expected-source-tree.manifest"
  local allow_legacy_environment_schema=false
  local allow_historical_status_schema=false
  local allow_historical_source_tree_schema=false
  local allow_missing_git_status=false

  assert_sealed_bundle_snapshot_is_private
  evidence_id="$BUNDLE_NAME"
  [[ "$evidence_id" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
    die "bundle directory name is not a safe evidence identifier"
  }
  validate_key_value_file "$environment" || {
    die "environment evidence is malformed"
  }
  validate_key_value_file "$source_state" || {
    die "source-state evidence is malformed"
  }

  environment_revision="$(key_value "$environment" revision)" || die "environment lacks revision"
  source_state_revision="$(key_value "$source_state" revision)" || die "source state lacks revision"
  bridge_revision="$(read_single_hex "$BUNDLE_DIR/bridge-source-revision.txt" 40)" || {
    die "bridge source revision is malformed"
  }
  if ! is_sha1 "$environment_revision" || ! is_sha1 "$source_state_revision"; then
    die "retained source revision is malformed"
  fi
  [[ "$environment_revision" == "$source_state_revision" && \
    "$environment_revision" == "$bridge_revision" ]] || {
    die "retained source revisions disagree"
  }
  if uses_legacy_environment_schema "$evidence_id" "$environment_revision"; then
    allow_legacy_environment_schema=true
  fi
  if uses_historical_run_status_schema "$evidence_id" "$environment_revision"; then
    allow_historical_status_schema=true
  fi
  if uses_historical_source_tree_manifest_schema "$evidence_id" "$environment_revision"; then
    allow_historical_source_tree_schema=true
  fi
  if allows_missing_git_status_record "$evidence_id" "$environment_revision"; then
    allow_missing_git_status=true
  fi
  validate_source_tree_manifest_schema \
    "$environment" "$source_state" "$allow_historical_source_tree_schema"

  environment_tree_sha256="$(key_value "$environment" source_tree_sha256)" || {
    die "environment lacks source-tree digest"
  }
  source_state_tree_sha256="$(key_value "$source_state" source_tree_sha256)" || {
    die "source state lacks source-tree digest"
  }
  bridge_tree_sha256="$(read_single_hex "$BUNDLE_DIR/bridge-source-tree.sha256" 64)" || {
    die "bridge source-tree digest is malformed"
  }
  manifest_tree_sha256="$(sha256sum <"$BUNDLE_DIR/source-tree.manifest")"
  manifest_tree_sha256="${manifest_tree_sha256%% *}"
  if ! is_sha256 "$environment_tree_sha256" || ! is_sha256 "$source_state_tree_sha256" || \
    ! is_sha256 "$manifest_tree_sha256"; then
    die "retained source-tree digest is malformed"
  fi
  [[ "$environment_tree_sha256" == "$source_state_tree_sha256" && \
    "$environment_tree_sha256" == "$bridge_tree_sha256" && \
    "$environment_tree_sha256" == "$manifest_tree_sha256" ]] || {
    die "retained source-tree digests disagree"
  }
  write_source_tree_manifest_for_revision "$environment_revision" "$expected_manifest" || {
    die "claimed source revision is unavailable or cannot be reconstructed"
  }
  cmp -s "$expected_manifest" "$BUNDLE_DIR/source-tree.manifest" || {
    die "source-tree manifest does not match the claimed Git revision"
  }

  [[ "$(key_value "$environment" dirty)" == "false" && \
    "$(key_value "$source_state" dirty)" == "false" ]] || {
    die "retained source state is dirty"
  }
  [[ "$(key_value "$environment" scenario)" == "all" ]] || {
    die "retained result did not run the full scenario suite"
  }
  [[ "$(key_value "$environment" acceptance_evidence)" == "true" ]] || {
    die "retained result is not acceptance evidence"
  }
  validate_acceptance_environment "$environment" "$allow_legacy_environment_schema"
  validate_clean_source_metadata \
    "$environment" "$source_state" "$allow_legacy_environment_schema"
  if [[ -e "$BUNDLE_DIR/git-status.txt" ]]; then
    [[ -f "$BUNDLE_DIR/git-status.txt" && ! -L "$BUNDLE_DIR/git-status.txt" && \
      ! -s "$BUNDLE_DIR/git-status.txt" ]] || {
      die "retained git status is not a clean regular file"
    }
  elif [[ "$allow_missing_git_status" != "true" ]]; then
    die "retained evidence lacks a clean git-status record"
  fi

  validate_json_provenance \
    "$evidence_id" "$environment_revision" "$environment_tree_sha256" \
    "$allow_historical_status_schema"
  if [[ "$REQUIRE_CURRENT_CODE" == "true" ]]; then
    validate_current_code_compatibility "$environment_revision"
  fi
}

main() {
  if [[ $# == 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
    usage
    return 0
  fi
  if [[ ${1:-} == "--current-code" ]]; then
    REQUIRE_CURRENT_CODE=true
    shift
  fi
  case "${1:-}" in
    --raw-v3)
      [[ "$REQUIRE_CURRENT_CODE" == false && $# == 3 &&
        ( "$2" == acceptance || "$2" == assertion-failure ) ]] || {
        usage >&2
        return 2
      }
      VERIFICATION_MODE=raw-v3
      RAW_V3_KIND="$2"
      shift 2
      ;;
    --claims-v1)
      [[ "$REQUIRE_CURRENT_CODE" == false && $# == 2 ]] || {
        usage >&2
        return 2
      }
      VERIFICATION_MODE=claims-v1
      shift
      ;;
    *)
      [[ $# == 1 ]] || {
        usage >&2
        return 2
      }
      ;;
  esac
  [[ -d "$1" && ! -L "$1" ]] || die "bundle directory is missing or a symbolic link"
  if [[ "$VERIFICATION_MODE" != tracked && "$1" != /* ]]; then
    die "raw-v3 and claims-v1 directories must be absolute"
  fi
  EXTERNAL_SOURCE_DIRECTORY="$(cd -- "$1" && pwd -P)" || {
    die "could not resolve bundle directory"
  }
  BUNDLE_DIR="$EXTERNAL_SOURCE_DIRECTORY"
  BUNDLE_NAME="${EXTERNAL_SOURCE_DIRECTORY##*/}"
  [[ "$BUNDLE_NAME" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
    die "bundle directory name is not a safe evidence identifier"
  }
  check_dependencies
  sanitize_git_environment
  resolve_trusted_repository
  assert_verification_tmp_parent_is_trusted
  TMP_DIR="$(mktemp -d "$VERIFICATION_TMP_PARENT/verify-retained-evidence.XXXXXX")" || {
    die "could not create temporary verification directory"
  }
  TMP_DIR="$(cd -- "$TMP_DIR" && pwd -P)" || {
    die "could not resolve temporary verification directory"
  }
  assert_private_verification_tmp_dir
  TMP_DIR_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$TMP_DIR")" || {
    die "could not pin temporary verification directory identity"
  }
  [[ -n "$TMP_DIR_IDENTITY" ]] || {
    die "temporary verification directory identity is empty"
  }
  case "$VERIFICATION_MODE" in
    tracked)
      snapshot_bundle "$BUNDLE_DIR"
      ;;
    raw-v3)
      snapshot_external_bundle \
        "$BUNDLE_DIR" "$RAW_V3_ARCHIVE_MAX_FILES" "$RAW_V3_ARCHIVE_MAX_BYTES"
      validate_bundle_file_types
      validate_raw_v3_bundle "$RAW_V3_KIND"
      printf 'raw v3 evidence verified: %s (%s, checkout commit %s)\n' \
        "$BUNDLE_NAME" "$RAW_V3_KIND" "$TRUSTED_HEAD"
      return 0
      ;;
    claims-v1)
      snapshot_external_bundle \
        "$BUNDLE_DIR" "$CLAIM_V1_ARCHIVE_MAX_FILES" \
        "$CLAIM_V1_ARCHIVE_MAX_BYTES" 444 555
      validate_claim_summary_bundle || die "claims-v1 bundle is invalid"
      printf 'bounded claims verified: %s (checkout commit %s)\n' \
        "$BUNDLE_NAME" "$TRUSTED_HEAD"
      return 0
      ;;
    *) die "internal verification mode is invalid" ;;
  esac

  require_regular_file SHA256SUMS
  require_regular_file run-status.json
  require_regular_file environment.txt
  require_regular_file source-state.txt
  require_regular_file source-tree.manifest
  require_regular_file runtime-metadata.json
  require_regular_file bridge-source-revision.txt
  require_regular_file bridge-source-tree.sha256
  require_regular_file bridge-artifacts.json
  validate_bundle_file_types
  if [[ -e "$BUNDLE_DIR/obi-metric-boundary-index.json" ||
    -L "$BUNDLE_DIR/obi-metric-boundary-index.json" ||
    -e "$BUNDLE_DIR/.obi-metric-boundary-index.freeze" ||
    -L "$BUNDLE_DIR/.obi-metric-boundary-index.freeze" ]]; then
    [[ -f "$BUNDLE_DIR/obi-metric-boundary-index.json" &&
      ! -L "$BUNDLE_DIR/obi-metric-boundary-index.json" &&
      -f "$BUNDLE_DIR/.obi-metric-boundary-index.freeze" &&
      ! -L "$BUNDLE_DIR/.obi-metric-boundary-index.freeze" ]] || {
      die "boundary journal paths are incomplete or unsafe"
    }
    preflight_obi_metric_boundary_referenced_bytes || {
      die "boundary journal references are malformed or exceed the byte budget"
    }
  fi
  validate_checksum_manifest
  validate_provenance
  printf 'retained evidence verified: %s (checkout commit %s)\n' \
    "$BUNDLE_NAME" "$TRUSTED_HEAD"
}

main "$@"
