#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERIFICATION_TMP_PARENT="/tmp"
readonly SCRIPT_NAME SCRIPT_DIR VERIFICATION_TMP_PARENT

readonly EMPTY_SHA256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

BUNDLE_DIR=""
BUNDLE_NAME=""
TRUSTED_REPO_ROOT=""
TRUSTED_HEAD=""
REPO_ROOT=""
TMP_DIR=""
BUNDLE_SNAPSHOT_ROOT=""
REQUIRE_CURRENT_CODE=false

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

  for command_name in chmod cmp find git jq mkdir mktemp rm sha256sum sort stat tar; do
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
      die "bundle contains an unsafe file path"
    }
  done < <(find -- "$BUNDLE_DIR" -type f -print0)
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

validate_json_provenance() {
  local -r evidence_id="$1"
  local -r revision="$2"
  local -r source_tree_sha256="$3"
  local -r allow_historical_status_schema="$4"

  jq -e -s --arg evidence_id "$evidence_id" \
    --argjson allow_historical_status_schema "$allow_historical_status_schema" '
    length == 1 and
    (.[0] |
      type == "object" and
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
  ' "$BUNDLE_DIR/run-status.json" >/dev/null || {
    die "run status is not an eligible retained acceptance result"
  }
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
  validate_checksum_manifest
  validate_provenance
  printf 'retained evidence verified: %s (checkout commit %s)\n' \
    "$BUNDLE_NAME" "$TRUSTED_HEAD"
}

main "$@"
