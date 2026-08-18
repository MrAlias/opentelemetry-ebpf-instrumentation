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

BUNDLE_DIR=""
BUNDLE_NAME=""
TRUSTED_REPO_ROOT=""
TRUSTED_HEAD=""
REPO_ROOT=""
TMP_DIR=""
BUNDLE_SNAPSHOT_ROOT=""
REQUIRE_CURRENT_CODE=false
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
    "" \
    "Verify one sanitized retained acceptance-evidence bundle in this Git checkout." \
    "The verifier checks the checksum manifest, canonical evidence identity, clean" \
    "full-suite status, and source-tree provenance reconstructed from the recorded commit." \
    "By default, historical evidence remains valid for its recorded revision only." \
    "--current-code also rejects changes after that revision except retained evidence" \
    "publication and Markdown documentation in the repository's documentation locations."
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

cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    find -- "$TMP_DIR" -type d -exec chmod u+rwx -- {} + >/dev/null 2>&1 || true
    rm -rf -- "$TMP_DIR"
  fi
}

trap cleanup EXIT

check_dependencies() {
  local -a missing=()
  local command_name=""

  for command_name in awk chmod cmp cp find git jq mkdir mktemp rm sha256sum sort stat tar; do
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
  printf '%s\n' "${declared_paths[@]}" | LC_ALL=C sort >"$TMP_DIR/declared-paths"
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
  [[ ${#lines[@]} == 1 ]] || return 1
  case "$width" in
    40) is_sha1 "${lines[0]}" ;;
    64) is_sha256 "${lines[0]}" ;;
    *) return 1 ;;
  esac || return 1
  printf '%s\n' "${lines[0]}"
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
  local -r input="$BUNDLE_DIR/$relative_path"
  local line=""
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
  local attach_value=0
  local attach_present=false
  local -a label_entries=()
  declare -A seen_series=()
  declare -A seen_labels=()

  [[ ! -L "$output" ]] || return 1
  if [[ -n "${PARSED_OBI_METRIC_REFERENCES[$relative_path]+present}" ]]; then
    cp -- "${PARSED_OBI_METRIC_REFERENCES[$relative_path]}" "$output"
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
    [[ -n "$line" && "$line" != \#* ]] || continue
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
      [[ "$error_type" == attaching_java_agent ]] || continue
      [[ "$process_name" == java ]] || continue
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
    fi
  done <"$input"
  if LC_ALL=C sort -- "$unsorted" >"$output" &&
    printf 'attach\t%s\t%s\n' "$attach_present" "$attach_value" >>"$output"; then
    rm -f -- "$unsorted" || return 1
    cache_file="$(mktemp "$TMP_DIR/obi-metric-parsed-cache.XXXXXX")" || return $?
    if ! cp -- "$output" "$cache_file"; then
      rm -f -- "$cache_file"
      return 1
    fi
    PARSED_OBI_METRIC_REFERENCES["$relative_path"]="$cache_file"
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
    -name 'scenario-*-status.json' -printf '%f\n' | LC_ALL=C sort \
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
  (( $# == 1 )) || {
    usage >&2
    return 2
  }
  [[ -d "$1" && ! -L "$1" ]] || die "bundle directory is missing or a symbolic link"
  BUNDLE_DIR="$(cd -- "$1" && pwd -P)" || die "could not resolve bundle directory"
  BUNDLE_NAME="${BUNDLE_DIR##*/}"
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
  snapshot_bundle "$BUNDLE_DIR"

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
