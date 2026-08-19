#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

# The campaign handles private raw evidence. Do not inherit a permissive umask.
umask 077

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AUTHORITY_REPOSITORY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd -P)"
readonly SCRIPT_NAME SCRIPT_DIR AUTHORITY_REPOSITORY_ROOT

readonly REPOSITORY_SLUG='MrAlias/opentelemetry-ebpf-instrumentation'
readonly REPOSITORY_URL='https://github.com/MrAlias/opentelemetry-ebpf-instrumentation.git'
readonly CAMPAIGN_BRANCH='refs/heads/agent/java-remote-parent-bridge'
readonly WORKFLOW_PATH='.github/workflows/java_remote_parent_acceptance_claims.yml'
readonly RECEIPT_SCHEMA='obi-apache-java-https-runbook-receipt-v1'
readonly PUBLIC_VERIFY_SUCCESS_PREFIX='bounded claim bundle internally consistent (not authenticated): '
readonly EMPTY_SHA256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
readonly MAX_COMMAND_SECONDS=86400
readonly MAX_ENVIRONMENT_TOKEN_BYTES=64
readonly MAX_RECEIPT_BYTES=1048576
readonly MAX_RUN_STATUS_BYTES=262144
readonly MAX_ENVIRONMENT_BYTES=65536
readonly MAX_GITHUB_EVENT_BYTES=2097152
readonly PROJECT_TIMEOUT_SECONDS=1800
readonly PUBLIC_VERIFY_TIMEOUT_SECONDS=300
readonly EMERGENCY_CLEANUP_TIMEOUT_SECONDS=300
readonly COMMAND_KILL_AFTER_SECONDS=30
readonly PROJECT_KILL_AFTER_SECONDS=30
readonly PUBLIC_VERIFY_KILL_AFTER_SECONDS=10

readonly -a CAMPAIGN_STATES=(
  AUTHORITY_PREFLIGHT PRIVATE_TXN CLONE EXACT_CHECKOUT CLEAN_BEFORE CERTS
  RUN_TEST TRACECHECK COMPOSE_CONFIG CLEAN_AFTER_VALIDATION ACCEPTANCE
  ASSERTION_CONTROL SCOPED_CLEANUP FINAL_CLEAN RECEIPT_SEAL PROJECT
  PRIVATE_DESTROY PUBLIC_REVERIFY SUCCESS
)

readonly -a RECEIPT_COMMAND_IDS=(
  clone checkout-exact-revision clean-status-before certificate-generation
  run-test tracecheck-tests compose-config clean-status-after-validation
  acceptance-all-otel-getsockopt-tls13 assertion-failure-exit-2
  scoped-cleanup clean-status-final
)

readonly -a PUBLIC_FILES=(
  README.md SANITIZATION.md acceptance-claims.json authority-summary.json
  derivation-receipt.json verify.sh SHA256SUMS
)

OUTPUT_DIRECTORY=""
OUTPUT_PARENT=""
OUTPUT_NAME=""
OUTPUT_PARENT_IDENTITY=""
SOURCE_REVISION=""
SOURCE_TREE_SHA256=""
WORKFLOW_BLOB_SHA256=""
WORKFLOW_REF=""
RUN_ID=""
RUN_ATTEMPT=""
RUN_URL=""
ARCHITECTURE=""
COMPOSE_VERSION=""
DOCKER_VERSION=""
GO_VERSION=""
JAVA_VERSION=""
OPERATING_SYSTEM=""

# This assignment deliberately ignores a caller-provided environment value.
# Tests that source this file may replace it after the assignment.
TRANSACTION_PARENT='/tmp'
PRIVATE_DIRECTORY=""
PRIVATE_IDENTITY=""
CHECKOUT_DIRECTORY=""
CHECKOUT_IDENTITY=""
COMMAND_DIRECTORY=""
COMMAND_DIRECTORY_IDENTITY=""
STATE_JOURNAL=""
RECEIPT=""
RECEIPT_IDENTITY=""
RECEIPT_SHA256=""
RAW_ACCEPTANCE=""
RAW_ACCEPTANCE_IDENTITY=""
RAW_ASSERTION=""
RAW_ASSERTION_IDENTITY=""
RESULT_LOCK_IDENTITY=""
RESULTS_ROOT_IDENTITY=""
CURRENT_STATE_INDEX=-1
COMMAND_COUNT=0
CLEANUP_REQUIRED=false
STICKY_CLEANUP_FAILURE=false
PRIMARY_FAILURE=""
declare -a STATE_HISTORY=()
declare -a COMMAND_ROWS_MEMORY=()
declare -A COMMAND_OUTPUT_SHA256=()
declare -A RESULT_SNAPSHOT_IDENTITY=()
declare -A RESULT_SNAPSHOT_SHA256=()

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME ABS_NONEXISTENT_PUBLIC_OUTPUT" \
    "" \
    "Run the exact GitHub clean-host acceptance campaign and publish only its" \
    "closed seven-file bounded-claim projection. This command is restricted to" \
    "the push workflow on $CAMPAIGN_BRANCH."
}

log_info() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
}

die() {
  log_info "ERROR: $*"
  return 1
}

on_error() {
  local -r line="$1"
  local -r status="$2"
  local state=none

  if [[ -z "$PRIMARY_FAILURE" ]]; then
    if (( CURRENT_STATE_INDEX >= 0 &&
      CURRENT_STATE_INDEX < ${#CAMPAIGN_STATES[@]} )); then
      state="${CAMPAIGN_STATES[$CURRENT_STATE_INDEX]}"
    fi
    PRIMARY_FAILURE="state=$state line=$line status=$status reason=unhandled-error"
  fi
}

sanitize_git_environment() {
  local variable=""

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
  for variable in "${!GIT_CONFIG_KEY_@}" "${!GIT_CONFIG_VALUE_@}"; do
    [[ -n "$variable" ]] || continue
    unset "$variable"
  done
  export GIT_NO_REPLACE_OBJECTS=1
  export GIT_TERMINAL_PROMPT=0
}

require_commands() {
  local -a missing=()
  local command_name=""

  for command_name in awk bash chmod cmp comm cp date dirname docker find flock git \
    go id install java jq mkdir mktemp mv readlink realpath rm sha256sum sort \
    stat timeout uname wc; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  (( ${#missing[@]} == 0 )) || {
    die "missing required commands: ${missing[*]}"
    return 1
  }
}

is_sha1() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

is_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

is_positive_decimal() {
  [[ "$1" =~ ^[1-9][0-9]{0,18}$ ]]
}

is_safe_public_name() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]]
}

sha256_file() {
  local -r input="$1"
  local output=""
  local digest=""

  [[ -f "$input" && ! -L "$input" ]] || return 1
  output="$(sha256sum <"$input")" || return 1
  digest="${output%% *}"
  is_sha256 "$digest" || return 1
  printf '%s\n' "$digest"
}

sha256_git_blob() {
  local -r repository="$1"
  local -r revision="$2"
  local -r path="$3"
  local output=""
  local digest=""

  output="$(git -C "$repository" show "$revision:$path" | sha256sum)" ||
    return 1
  digest="${output%% *}"
  is_sha256 "$digest" || return 1
  printf '%s\n' "$digest"
}

assert_exact_tracked_file() {
  local -r repository="$1"
  local -r revision="$2"
  local -r relative="$3"
  local -r expected_tree_mode="$4"
  local -r expected_disk_mode="$5"
  local tree_mode=""
  local disk_mode=""
  local owner=""
  local links=""
  local actual_digest=""
  local blob_digest=""

  [[ -f "$repository/$relative" && ! -L "$repository/$relative" &&
    "$(readlink -f -- "$repository/$relative")" == "$repository/$relative" ]] ||
    return 1
  tree_mode="$(git -C "$repository" ls-tree "$revision" -- "$relative" |
    awk 'NR == 1 { print $1 } END { if (NR != 1) exit 1 }')" || return 1
  disk_mode="$(stat -Lc '%a' -- "$repository/$relative")" || return 1
  owner="$(stat -Lc '%u' -- "$repository/$relative")" || return 1
  links="$(stat -Lc '%h' -- "$repository/$relative")" || return 1
  [[ "$tree_mode" == "$expected_tree_mode" &&
    "$disk_mode" == "$expected_disk_mode" && "$owner" == "$EUID" &&
    "$links" == 1 ]] ||
    return 1
  actual_digest="$(sha256_file "$repository/$relative")" || return 1
  blob_digest="$(sha256_git_blob "$repository" "$revision" "$relative")" ||
    return 1
  [[ "$actual_digest" == "$blob_digest" ]]
}

assert_output_target() {
  local parent_physical=""
  local owner=""
  local mode=""
  local -i mode_bits=0

  [[ "$OUTPUT_DIRECTORY" == /* && "$OUTPUT_DIRECTORY" != */ &&
    ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]] || {
    die "public output must be a nonexistent absolute path"
    return 1
  }
  OUTPUT_PARENT="${OUTPUT_DIRECTORY%/*}"
  OUTPUT_NAME="${OUTPUT_DIRECTORY##*/}"
  is_safe_public_name "$OUTPUT_NAME" || {
    die "public output name is not a safe evidence identifier"
    return 1
  }
  [[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" ]] || {
    die "public output parent is not a physical directory"
    return 1
  }
  parent_physical="$(CDPATH='' cd -- "$OUTPUT_PARENT" && pwd -P)" || return 1
  [[ "$parent_physical" == "$OUTPUT_PARENT" ]] || {
    die "public output parent contains a symbolic-link component"
    return 1
  }
  owner="$(stat -Lc '%u' -- "$OUTPUT_PARENT")" || return 1
  mode="$(stat -Lc '%a' -- "$OUTPUT_PARENT")" || return 1
  [[ "$owner" == "$EUID" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  mode_bits=$((8#$mode))
  (( (mode_bits & 0022) == 0 )) || {
    die "public output parent must not be group or world writable"
    return 1
  }
  if [[ -z "$OUTPUT_PARENT_IDENTITY" ]]; then
    OUTPUT_PARENT_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_PARENT")" ||
      return 1
  else
    [[ "$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_PARENT")" == "$OUTPUT_PARENT_IDENTITY" ]] || {
      die "public output parent identity changed"
      return 1
    }
  fi
  case "$OUTPUT_PARENT" in
    "$AUTHORITY_REPOSITORY_ROOT"|"$AUTHORITY_REPOSITORY_ROOT"/*)
      die "public output must be outside the authority checkout"
      return 1
      ;;
  esac
}

read_environment_version() {
  local -r description="$1"
  local value="$2"

  value="${value#v}"
  [[ -n "$value" && ${#value} -le MAX_ENVIRONMENT_TOKEN_BYTES &&
    "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]*$ ]] || {
    die "$description is not a bounded version token"
    return 1
  }
  printf '%s\n' "$value"
}

capture_environment_authority() {
  local java_properties=""
  local java_value=""

  OPERATING_SYSTEM="$(uname -s)" || return 1
  [[ "$OPERATING_SYSTEM" == Linux ]] || {
    die "the acceptance campaign requires Linux"
    return 1
  }
  ARCHITECTURE="$(uname -m)" || return 1
  [[ "$ARCHITECTURE" == x86_64 ]] || {
    die "the hosted acceptance campaign requires x86_64"
    return 1
  }
  COMPOSE_VERSION="$(read_environment_version 'Compose version' \
    "$(docker compose version --short)")" || return 1
  DOCKER_VERSION="$(read_environment_version 'Docker version' \
    "$(docker version --format '{{.Server.Version}}')")" || return 1
  GO_VERSION="$(go env GOVERSION)" || return 1
  GO_VERSION="${GO_VERSION#go}"
  GO_VERSION="$(read_environment_version 'Go version' "$GO_VERSION")" ||
    return 1
  java_properties="$(java -XshowSettings:properties -version 2>&1)" || return 1
  java_value="$(awk -F= '
    $1 ~ /^[[:space:]]*java\.version[[:space:]]*$/ {
      value=$2
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' <<<"$java_properties")" || return 1
  JAVA_VERSION="$(read_environment_version 'Java version' "$java_value")" ||
    return 1
  [[ "$JAVA_VERSION" == 21 || "$JAVA_VERSION" == 21.* ||
    "$JAVA_VERSION" == 21-* || "$JAVA_VERSION" == 21+* ]] || {
    die "the acceptance campaign requires Java 21"
    return 1
  }
}

validate_github_event_payload() {
  local -r event_path="${GITHUB_EVENT_PATH:-}"
  local path_identity=""
  local descriptor_identity=""
  local post_identity=""
  local event_size=""
  local event_fd=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local -i mode_bits=0

  [[ "$event_path" == /* && -f "$event_path" && ! -L "$event_path" &&
    "$(readlink -f -- "$event_path")" == "$event_path" ]] || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$event_path")" || return 1
  IFS=: read -r device inode owner mode links <<<"$path_identity"
  [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ &&
    "$owner" == "$EUID" && "$mode" =~ ^[0-7]{3,4}$ && "$links" == 1 ]] ||
    return 1
  mode_bits=$((8#$mode))
  (( (mode_bits & 0022) == 0 )) || return 1
  event_size="$(stat -Lc '%s' -- "$event_path")" || return 1
  [[ "$event_size" =~ ^[1-9][0-9]*$ ]] || return 1
  (( event_size <= MAX_GITHUB_EVENT_BYTES )) || return 1
  exec {event_fd}<"$event_path" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$BASHPID/fd/$event_fd")" ||
    descriptor_identity=""
  if [[ "$descriptor_identity" == "$path_identity" ]]; then
    jq -se --arg after "$SOURCE_REVISION" --arg ref "$CAMPAIGN_BRANCH" \
      --arg repository "$REPOSITORY_SLUG" '
        length == 1 and (.[0] |
          .after == $after and .ref == $ref and
          .repository.full_name == $repository)
      ' "/proc/$BASHPID/fd/$event_fd" >/dev/null || descriptor_identity=""
  fi
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$event_path")" ||
    post_identity=""
  exec {event_fd}<&- || return $?
  [[ -f "$event_path" && ! -L "$event_path" &&
    "$path_identity" == "$descriptor_identity" &&
    "$path_identity" == "$post_identity" ]]
}

validate_github_runner_environment() {
  [[ "${GITHUB_EVENT_NAME:-}" == push &&
    "${GITHUB_REPOSITORY:-}" == "$REPOSITORY_SLUG" &&
    "${GITHUB_REF:-}" == "$CAMPAIGN_BRANCH" &&
    "$WORKFLOW_REF" == "$REPOSITORY_SLUG/$WORKFLOW_PATH@$CAMPAIGN_BRANCH" &&
    "${GITHUB_SERVER_URL:-}" == 'https://github.com' &&
    "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true &&
    "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
    "${RUNNER_OS:-}" == Linux && "${RUNNER_ARCH:-}" == X64 &&
    "${GITHUB_SHA:-}" == "$SOURCE_REVISION" &&
    "${GITHUB_WORKFLOW_SHA:-}" == "$SOURCE_REVISION" ]]
}

authority_preflight() {
  local head=""
  local object_type=""
  local source_status=""
  local workspace_physical=""

  require_commands
  sanitize_git_environment
  SOURCE_REVISION="${GITHUB_SHA:-}"
  RUN_ID="${GITHUB_RUN_ID:-}"
  RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}"
  WORKFLOW_REF="${GITHUB_WORKFLOW_REF:-}"
  validate_github_runner_environment || {
    die "GitHub execution locator is outside the push-only campaign authority"
    return 1
  }
  is_sha1 "$SOURCE_REVISION" || {
    die "GITHUB_SHA is not an exact lowercase commit identifier"
    return 1
  }
  if ! is_positive_decimal "$RUN_ID" ||
    ! is_positive_decimal "$RUN_ATTEMPT"; then
    die "GitHub run identity is invalid"
    return 1
  fi
  RUN_URL="https://github.com/$REPOSITORY_SLUG/actions/runs/$RUN_ID/attempts/$RUN_ATTEMPT"
  [[ "${GITHUB_WORKSPACE:-}" == "$AUTHORITY_REPOSITORY_ROOT" ]] || {
    die "GITHUB_WORKSPACE does not name the authority checkout"
    return 1
  }
  workspace_physical="$(CDPATH='' cd -- "${GITHUB_WORKSPACE}" && pwd -P)" ||
    return 1
  [[ "$workspace_physical" == "$AUTHORITY_REPOSITORY_ROOT" ]] || return 1
  object_type="$(git -C "$AUTHORITY_REPOSITORY_ROOT" cat-file -t \
    "$SOURCE_REVISION")" || return 1
  [[ "$object_type" == commit ]] || return 1
  head="$(git -C "$AUTHORITY_REPOSITORY_ROOT" rev-parse --verify 'HEAD^{commit}')" ||
    return 1
  [[ "$head" == "$SOURCE_REVISION" ]] || {
    die "authority checkout does not match GITHUB_SHA"
    return 1
  }
  validate_github_event_payload || {
    die "GitHub push event authority is invalid"
    return 1
  }
  source_status="$(git -C "$AUTHORITY_REPOSITORY_ROOT" status --porcelain \
    --untracked-files=all --ignore-submodules=none)" || return 1
  [[ -z "$source_status" ]] || {
    die "authority checkout is not clean"
    return 1
  }
  assert_exact_tracked_file "$AUTHORITY_REPOSITORY_ROOT" "$SOURCE_REVISION" \
    "$WORKFLOW_PATH" 100644 644 || return 1
  for relative in \
    examples/apache-java-https/scripts/run-retained-acceptance-campaign.sh \
    examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh \
    examples/apache-java-https/scripts/verify-retained-evidence.sh; do
    assert_exact_tracked_file "$AUTHORITY_REPOSITORY_ROOT" "$SOURCE_REVISION" \
      "$relative" 100755 755 || return 1
  done
  WORKFLOW_BLOB_SHA256="$(sha256_git_blob "$AUTHORITY_REPOSITORY_ROOT" \
    "$SOURCE_REVISION" "$WORKFLOW_PATH")" || return 1
  capture_environment_authority
  assert_output_target
}

enter_state() {
  local -r requested="$1"
  local -i next_index=$((CURRENT_STATE_INDEX + 1))
  local expected=""

  (( next_index < ${#CAMPAIGN_STATES[@]} )) || {
    die "state machine advanced beyond SUCCESS"
    return 1
  }
  expected="${CAMPAIGN_STATES[$next_index]}"
  [[ "$requested" == "$expected" ]] || {
    die "invalid state transition: expected $expected, received $requested"
    return 1
  }
  CURRENT_STATE_INDEX=$next_index
  STATE_HISTORY+=("$requested")
  log_info "STATE $requested"
  if [[ -n "$STATE_JOURNAL" && -f "$STATE_JOURNAL" &&
    ! -L "$STATE_JOURNAL" ]]; then
    printf '%02d\t%s\n' "$CURRENT_STATE_INDEX" "$requested" >>"$STATE_JOURNAL"
  fi
}

assert_transaction_parent() {
  local root_owner=""
  local root_mode=""
  local parent_physical=""
  local parent_owner=""
  local parent_mode=""
  local -i root_mode_bits=0
  local -i parent_mode_bits=0

  [[ "$TRANSACTION_PARENT" == /tmp && -d / && ! -L / &&
    -d "$TRANSACTION_PARENT" && ! -L "$TRANSACTION_PARENT" ]] || return 1
  root_owner="$(stat -Lc '%u' -- /)" || return 1
  root_mode="$(stat -Lc '%a' -- /)" || return 1
  [[ "$root_owner" == 0 && "$root_mode" =~ ^[0-7]{3,4}$ ]] || return 1
  root_mode_bits=$((8#$root_mode))
  (( (root_mode_bits & 0022) == 0 )) || return 1
  parent_physical="$(CDPATH='' cd -- "$TRANSACTION_PARENT" && pwd -P)" ||
    return 1
  [[ "$parent_physical" == "$TRANSACTION_PARENT" ]] || return 1
  parent_owner="$(stat -Lc '%u' -- "$TRANSACTION_PARENT")" || return 1
  parent_mode="$(stat -Lc '%a' -- "$TRANSACTION_PARENT")" || return 1
  [[ "$parent_owner" == 0 && "$parent_mode" =~ ^[0-7]{3,4}$ ]] || return 1
  parent_mode_bits=$((8#$parent_mode))
  (( (parent_mode_bits & 01000) != 0 && (parent_mode_bits & 0002) != 0 ))
}

assert_private_directory_identity() {
  local observed=""

  [[ -n "$PRIVATE_DIRECTORY" && -n "$PRIVATE_IDENTITY" &&
    "$PRIVATE_DIRECTORY" == "$TRANSACTION_PARENT"/obi-java-remote-parent-acceptance.* &&
    "${PRIVATE_DIRECTORY##*/}" =~ ^obi-java-remote-parent-acceptance\.[A-Za-z0-9]{6}$ &&
    -d "$PRIVATE_DIRECTORY" && ! -L "$PRIVATE_DIRECTORY" &&
    "$(CDPATH='' cd -- "$PRIVATE_DIRECTORY" && pwd -P)" == "$PRIVATE_DIRECTORY" ]] ||
    return 1
  observed="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")" || return 1
  [[ "$observed" == "$PRIVATE_IDENTITY" && "$observed" == *":$EUID:700" ]]
}

assert_command_directory_identity() {
  local observed=""

  [[ -n "$COMMAND_DIRECTORY" && -n "$COMMAND_DIRECTORY_IDENTITY" &&
    "$COMMAND_DIRECTORY" == "$PRIVATE_DIRECTORY/commands" &&
    -d "$COMMAND_DIRECTORY" && ! -L "$COMMAND_DIRECTORY" &&
    "$(CDPATH='' cd -- "$COMMAND_DIRECTORY" && pwd -P)" == "$COMMAND_DIRECTORY" ]] ||
    return 1
  observed="$(stat -Lc '%d:%i:%u:%a' -- "$COMMAND_DIRECTORY")" || return 1
  [[ "$observed" == "$COMMAND_DIRECTORY_IDENTITY" &&
    "$observed" == *":$EUID:700" ]]
}

create_private_transaction() {
  local create_status=0

  assert_transaction_parent || {
    die "private transaction parent is not the trusted /tmp boundary"
    return 1
  }
  [[ -z "$PRIVATE_DIRECTORY" && -z "$PRIVATE_IDENTITY" ]] || return 1
  if PRIVATE_DIRECTORY="$(mktemp -d \
    "$TRANSACTION_PARENT/obi-java-remote-parent-acceptance.XXXXXX")"; then
    create_status=0
  else
    create_status=$?
  fi
  [[ -n "$PRIVATE_DIRECTORY" && -d "$PRIVATE_DIRECTORY" &&
    ! -L "$PRIVATE_DIRECTORY" ]] || return "$create_status"
  chmod 0700 -- "$PRIVATE_DIRECTORY" || return 1
  PRIVATE_DIRECTORY="$(CDPATH='' cd -- "$PRIVATE_DIRECTORY" && pwd -P)" ||
    return 1
  PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")" ||
    return 1
  assert_private_directory_identity || return 1
  CHECKOUT_DIRECTORY="$PRIVATE_DIRECTORY/source"
  COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
  STATE_JOURNAL="$PRIVATE_DIRECTORY/state-journal.tsv"
  mkdir -m 0700 -- "$COMMAND_DIRECTORY" || return 1
  COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
    "$COMMAND_DIRECTORY")" || return 1
  assert_command_directory_identity || return 1
  : >"$STATE_JOURNAL"
  chmod 0600 -- "$STATE_JOURNAL"
  COMMAND_ROWS_MEMORY=()
  COMMAND_OUTPUT_SHA256=()
  RESULT_SNAPSHOT_IDENTITY=()
  RESULT_SNAPSHOT_SHA256=()
  local index=0
  local state=""
  for state in "${STATE_HISTORY[@]}"; do
    printf '%02d\t%s\n' "$index" "$state" >>"$STATE_JOURNAL"
    index=$((index + 1))
  done
}

private_tree_has_mountpoint() {
  local -r mountinfo="$1"

  [[ -n "$PRIVATE_DIRECTORY" && -f "$mountinfo" && ! -L "$mountinfo" ]] ||
    return 0
  awk -v root="$PRIVATE_DIRECTORY" '
    $5 == root || index($5, root "/") == 1 { found=1 }
    END { exit(found ? 0 : 1) }
  ' "$mountinfo"
}

destroy_private_transaction() {
  local removal_status=0

  if [[ -z "$PRIVATE_DIRECTORY" ]]; then
    [[ -z "$PRIVATE_IDENTITY" ]]
    return
  fi
  assert_private_directory_identity || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  if private_tree_has_mountpoint /proc/self/mountinfo; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  assert_private_directory_identity || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  rm -rf --one-file-system -- "$PRIVATE_DIRECTORY" || removal_status=$?
  if (( removal_status != 0 )) ||
    [[ -e "$PRIVATE_DIRECTORY" || -L "$PRIVATE_DIRECTORY" ]]; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  PRIVATE_DIRECTORY=""
  PRIVATE_IDENTITY=""
  CHECKOUT_DIRECTORY=""
  CHECKOUT_IDENTITY=""
  COMMAND_DIRECTORY=""
  COMMAND_DIRECTORY_IDENTITY=""
  STATE_JOURNAL=""
  RECEIPT=""
  RECEIPT_IDENTITY=""
  RECEIPT_SHA256=""
  RAW_ACCEPTANCE=""
  RAW_ACCEPTANCE_IDENTITY=""
  RAW_ASSERTION=""
  RAW_ASSERTION_IDENTITY=""
  RESULT_LOCK_IDENTITY=""
  RESULTS_ROOT_IDENTITY=""
  COMMAND_ROWS_MEMORY=()
  COMMAND_OUTPUT_SHA256=()
  RESULT_SNAPSHOT_IDENTITY=()
  RESULT_SNAPSHOT_SHA256=()
}

campaign_execute() (
  local -r command_id="$1"
  local timeout_seconds=""
  shift

  timeout_seconds="$(command_timeout_seconds "$command_id")" || return 1
  case "$command_id" in
    checkout-exact-revision|acceptance-all-otel-getsockopt-tls13|assertion-failure-exit-2)
      umask 022
      ;;
    scoped-cleanup|emergency-scoped-cleanup)
      assert_cleanup_execution_authority || return 1
      ;;
  esac
  timeout --foreground --signal=TERM \
    --kill-after="${COMMAND_KILL_AFTER_SECONDS}s" \
    "${timeout_seconds}s" "$@" </dev/null
)

command_timeout_seconds() {
  case "$1" in
    clone) printf '300\n' ;;
    checkout-exact-revision) printf '60\n' ;;
    clean-status-before|clean-status-after-validation|clean-status-final)
      printf '30\n'
      ;;
    certificate-generation) printf '120\n' ;;
    run-test) printf '1200\n' ;;
    tracecheck-tests) printf '600\n' ;;
    compose-config) printf '120\n' ;;
    acceptance-all-otel-getsockopt-tls13) printf '6600\n' ;;
    assertion-failure-exit-2) printf '1200\n' ;;
    scoped-cleanup) printf '300\n' ;;
    emergency-scoped-cleanup)
      printf '%s\n' "$EMERGENCY_CLEANUP_TIMEOUT_SECONDS"
      ;;
    *) return 1 ;;
  esac
}

recorded_log_checkpoint() {
  # A no-op production seam used by the sourced mutation test to exercise
  # path and same-inode races at deterministic capture boundaries.
  : "$@"
}

sha256_open_fd() {
  local -r descriptor="$1"
  local output=""
  local digest=""

  [[ "$descriptor" =~ ^[0-9]+$ ]] || return 1
  output="$(sha256sum <"/proc/$BASHPID/fd/$descriptor")" || return 1
  digest="${output%% *}"
  is_sha256 "$digest" || return 1
  printf '%s\n' "$digest"
}

run_recorded_command() {
  local -r command_id="$1"
  local -r expected_exit="$2"
  local -r working_directory="$3"
  shift 3
  local expected_id=""
  local log=""
  local log_name=""
  local log_identity=""
  local descriptor_identity=""
  local post_descriptor_identity=""
  local sealed_identity=""
  local final_identity=""
  local post_identity=""
  local command_directory_descriptor_identity=""
  local digest=""
  local sealed_fd_digest=""
  local path_digest=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local size=""
  local status_label=passed
  local -i command_status=0
  local -i start_seconds=0
  local -i end_seconds=0
  local -i duration_seconds=0
  local -i validation_status=0
  local -i close_status=0
  local command_directory_fd=""
  local log_fd=""
  local timeout_seconds=""
  local command_row=""

  (( COMMAND_COUNT < ${#RECEIPT_COMMAND_IDS[@]} )) || return 1
  expected_id="${RECEIPT_COMMAND_IDS[$COMMAND_COUNT]}"
  [[ "$command_id" == "$expected_id" && "$expected_exit" =~ ^[0-9]+$ &&
    -d "$working_directory" && ! -L "$working_directory" ]] || return 1
  case "$command_id" in
    clone)
      [[ "$working_directory" == "$PRIVATE_DIRECTORY" ]] &&
        assert_private_directory_identity || return 1
      ;;
    *)
      [[ "$working_directory" == "$CHECKOUT_DIRECTORY" ]] &&
        assert_checkout_identity || return 1
      ;;
  esac
  assert_command_directory_identity || return 1
  printf -v log_name '%02d-%s.log' "$COMMAND_COUNT" "$command_id"
  printf -v log '%s/%s' "$COMMAND_DIRECTORY" "$log_name"
  [[ ! -e "$log" && ! -L "$log" ]] || return 1
  exec {command_directory_fd}<"$COMMAND_DIRECTORY" || return $?
  command_directory_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$command_directory_fd")" || {
    exec {command_directory_fd}<&-
    return 1
  }
  if ! assert_command_directory_identity ||
    [[ "$command_directory_descriptor_identity" != "$COMMAND_DIRECTORY_IDENTITY" ]]; then
    exec {command_directory_fd}<&-
    return 1
  fi
  exec {log_fd}>"/proc/$BASHPID/fd/$command_directory_fd/$log_name" || {
    close_status=$?
    exec {command_directory_fd}<&-
    return "$close_status"
  }
  if ! assert_command_directory_identity ||
    [[ "$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$command_directory_fd")" != "$COMMAND_DIRECTORY_IDENTITY" ]]; then
    exec {log_fd}>&-
    exec {command_directory_fd}<&-
    return 1
  fi
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$log_fd")" || {
    exec {log_fd}>&-
    exec {command_directory_fd}<&-
    return 1
  }
  log_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$log")" || {
    exec {log_fd}>&-
    exec {command_directory_fd}<&-
    return 1
  }
  IFS=: read -r device inode owner mode links <<<"$log_identity"
  [[ -f "$log" && ! -L "$log" && "$(readlink -f -- "$log")" == "$log" &&
    "$log_identity" == "$descriptor_identity" && "$device" =~ ^[0-9]+$ &&
    "$inode" =~ ^[0-9]+$ && "$owner" == "$EUID" && "$mode" == 600 &&
    "$links" == 1 ]] || {
    exec {log_fd}>&-
    exec {command_directory_fd}<&-
    return 1
  }
  start_seconds="$(date +%s)" || {
    exec {log_fd}>&-
    exec {command_directory_fd}<&-
    return 1
  }
  if (
    case "$command_id" in
      clone)
        [[ "$working_directory" == "$PRIVATE_DIRECTORY" ]] &&
          assert_private_directory_identity
        ;;
      *)
        [[ "$working_directory" == "$CHECKOUT_DIRECTORY" ]] &&
          assert_checkout_identity
        ;;
    esac || exit 125
    CDPATH='' cd -- "$working_directory"
    campaign_execute "$command_id" "$@"
  ) >&"$log_fd" 2>&1; then
    command_status=0
  else
    command_status=$?
  fi
  if ! end_seconds="$(date +%s)"; then
    validation_status=1
  fi
  recorded_log_checkpoint after-command "$log" "$log_fd" ||
    validation_status=1
  if (( validation_status == 0 )); then
    if ! assert_command_directory_identity; then
      validation_status=1
    else
      command_directory_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
        "/proc/$BASHPID/fd/$command_directory_fd")" || validation_status=1
    fi
  fi
  if (( validation_status == 0 )); then
    descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
      "/proc/$BASHPID/fd/$log_fd")" || validation_status=1
    post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$log")" ||
      validation_status=1
    [[ -f "$log" && ! -L "$log" &&
      "$(readlink -f -- "$log")" == "$log" &&
      "$command_directory_descriptor_identity" == "$COMMAND_DIRECTORY_IDENTITY" &&
      "$descriptor_identity" == "$post_identity" &&
      "$descriptor_identity" == "$device:$inode:$owner:600:$links:"* ]] ||
      validation_status=1
  fi
  if (( validation_status == 0 )); then
    digest="$(sha256_open_fd "$log_fd")" || validation_status=1
  fi
  recorded_log_checkpoint after-fd-digest "$log" "$log_fd" ||
    validation_status=1
  if (( validation_status == 0 )); then
    if ! assert_command_directory_identity; then
      validation_status=1
    else
      command_directory_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
        "/proc/$BASHPID/fd/$command_directory_fd")" || validation_status=1
    fi
  fi
  if (( validation_status == 0 )); then
    post_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
      "/proc/$BASHPID/fd/$log_fd")" || validation_status=1
    post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$log")" ||
      validation_status=1
    [[ -f "$log" && ! -L "$log" &&
      "$(readlink -f -- "$log")" == "$log" &&
      "$command_directory_descriptor_identity" == "$COMMAND_DIRECTORY_IDENTITY" &&
      "$post_descriptor_identity" == "$descriptor_identity" &&
      "$post_identity" == "$descriptor_identity" ]] || validation_status=1
  fi
  if (( validation_status == 0 )); then
    chmod 0400 -- "/proc/$BASHPID/fd/$log_fd" || validation_status=1
  fi
  if (( validation_status == 0 )); then
    if ! assert_command_directory_identity; then
      validation_status=1
    else
      command_directory_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
        "/proc/$BASHPID/fd/$command_directory_fd")" || validation_status=1
    fi
  fi
  if (( validation_status == 0 )); then
    IFS=: read -r device inode owner mode links size <<<"$descriptor_identity"
    sealed_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$log")" ||
      validation_status=1
    post_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
      "/proc/$BASHPID/fd/$log_fd")" || validation_status=1
    sealed_fd_digest="$(sha256_open_fd "$log_fd")" || validation_status=1
    path_digest="$(sha256_file "$log")" || validation_status=1
    final_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$log")" ||
      validation_status=1
    [[ -f "$log" && ! -L "$log" &&
      "$(readlink -f -- "$log")" == "$log" &&
      "$command_directory_descriptor_identity" == "$COMMAND_DIRECTORY_IDENTITY" &&
      "$sealed_identity" == "$device:$inode:$owner:400:$links:$size" &&
      "$post_descriptor_identity" == "$sealed_identity" &&
      "$final_identity" == "$sealed_identity" &&
      "$sealed_fd_digest" == "$digest" && "$path_digest" == "$digest" ]] ||
      validation_status=1
  fi
  exec {log_fd}>&- || close_status=$?
  if ! assert_command_directory_identity ||
    [[ "$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$command_directory_fd")" != "$COMMAND_DIRECTORY_IDENTITY" ]]; then
    validation_status=1
  fi
  exec {command_directory_fd}<&- || close_status=$?
  (( validation_status == 0 && close_status == 0 )) || return 1
  (( end_seconds >= start_seconds )) || return 1
  duration_seconds=$((end_seconds - start_seconds))
  (( duration_seconds <= MAX_COMMAND_SECONDS )) || return 1
  timeout_seconds="$(command_timeout_seconds "$command_id")" || return 1
  if [[ "$expected_exit" == 2 ]]; then
    status_label=expected_failure
  fi
  command_row="$(jq -cS -n --arg id "$command_id" \
    --arg status "$status_label" \
    --argjson duration_seconds "$duration_seconds" \
    --argjson exit_status "$command_status" \
    --arg output_sha256 "$digest" '{
      duration_seconds: $duration_seconds,
      exit_status: $exit_status,
      id: $id,
      output_sha256: $output_sha256,
      status: $status
    }')" || return 1
  COMMAND_ROWS_MEMORY+=("$command_row")
  COMMAND_OUTPUT_SHA256["$command_id"]="$digest"
  COMMAND_COUNT=$((COMMAND_COUNT + 1))
  log_info "command $command_id exit=$command_status sha256=$digest"
  if [[ "$command_status" == 124 || "$command_status" == 137 ]]; then
    die "command $command_id exceeded its ${timeout_seconds}s deadline"
    return 1
  fi
  [[ "$command_status" == "$expected_exit" ]] || {
    die "command $command_id exited $command_status; expected $expected_exit"
    return 1
  }
}

assert_command_output_empty() {
  local -r command_id="$1"
  local digest="${COMMAND_OUTPUT_SHA256[$command_id]:-}"

  [[ "$digest" == "$EMPTY_SHA256" ]]
}

verify_clone_root() {
  local checkout_physical=""
  local owner=""
  local mode=""
  local origin=""

  [[ -d "$CHECKOUT_DIRECTORY" && ! -L "$CHECKOUT_DIRECTORY" ]] || return 1
  checkout_physical="$(CDPATH='' cd -- "$CHECKOUT_DIRECTORY" && pwd -P)" ||
    return 1
  [[ "$checkout_physical" == "$CHECKOUT_DIRECTORY" ]] || return 1
  owner="$(stat -Lc '%u' -- "$CHECKOUT_DIRECTORY")" || return 1
  mode="$(stat -Lc '%a' -- "$CHECKOUT_DIRECTORY")" || return 1
  [[ "$owner" == "$EUID" && "$mode" == 700 ]] || return 1
  CHECKOUT_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$CHECKOUT_DIRECTORY")" ||
    return 1
  origin="$(git -C "$CHECKOUT_DIRECTORY" remote get-url origin)" || return 1
  [[ "$origin" == "$REPOSITORY_URL" ]]
}

assert_checkout_identity() {
  [[ -n "$CHECKOUT_IDENTITY" && -d "$CHECKOUT_DIRECTORY" &&
    ! -L "$CHECKOUT_DIRECTORY" &&
    "$(CDPATH='' cd -- "$CHECKOUT_DIRECTORY" && pwd -P)" == "$CHECKOUT_DIRECTORY" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$CHECKOUT_DIRECTORY")" == "$CHECKOUT_IDENTITY" ]]
}

assert_cleanup_execution_authority() {
  local head=""

  assert_checkout_identity || return 1
  head="$(git -C "$CHECKOUT_DIRECTORY" rev-parse --verify 'HEAD^{commit}')" ||
    return 1
  [[ "$head" == "$SOURCE_REVISION" ]] || return 1
  assert_exact_tracked_file "$CHECKOUT_DIRECTORY" "$SOURCE_REVISION" \
    examples/apache-java-https/run.sh 100755 755
}

verify_exact_checkout() {
  local head=""
  local symbolic_ref=""

  assert_checkout_identity || return 1
  head="$(git -C "$CHECKOUT_DIRECTORY" rev-parse --verify 'HEAD^{commit}')" ||
    return 1
  [[ "$head" == "$SOURCE_REVISION" ]] || return 1
  if symbolic_ref="$(git -C "$CHECKOUT_DIRECTORY" symbolic-ref -q HEAD)"; then
    [[ -z "$symbolic_ref" ]] || return 1
  fi
  assert_exact_tracked_file "$CHECKOUT_DIRECTORY" "$SOURCE_REVISION" \
    "$WORKFLOW_PATH" 100644 644 || return 1
  for relative in \
    examples/apache-java-https/run.sh \
    examples/apache-java-https/certs/generate_test.sh \
    examples/apache-java-https/scripts/run_test.sh \
    examples/apache-java-https/scripts/run-retained-acceptance-campaign.sh \
    examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh \
    examples/apache-java-https/scripts/verify-retained-evidence.sh; do
    assert_exact_tracked_file "$CHECKOUT_DIRECTORY" "$SOURCE_REVISION" \
      "$relative" 100755 755 || return 1
  done
  [[ "$(sha256_git_blob "$CHECKOUT_DIRECTORY" "$SOURCE_REVISION" \
    "$WORKFLOW_PATH")" == "$WORKFLOW_BLOB_SHA256" ]]
}

seal_result_snapshot() {
  local -r snapshot="$1"
  local path_identity=""
  local descriptor_identity=""
  local sealed_identity=""
  local post_identity=""
  local digest=""
  local path_digest=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local size=""
  local snapshot_fd=""
  local close_status=0

  [[ "$snapshot" == "$PRIVATE_DIRECTORY/"* && -f "$snapshot" &&
    ! -L "$snapshot" && "$(readlink -f -- "$snapshot")" == "$snapshot" ]] ||
    return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" ||
    return 1
  IFS=: read -r device inode owner mode links size <<<"$path_identity"
  [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ &&
    "$owner" == "$EUID" && "$mode" == 600 && "$links" == 1 &&
    "$size" =~ ^[0-9]+$ ]] || return 1
  exec {snapshot_fd}<"$snapshot" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$snapshot_fd")" || descriptor_identity=""
  if [[ "$descriptor_identity" == "$path_identity" ]]; then
    digest="$(sha256_open_fd "$snapshot_fd")" || digest=""
  fi
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" ||
    post_identity=""
  if [[ -n "$digest" && "$post_identity" == "$path_identity" ]]; then
    chmod 0400 -- "/proc/$BASHPID/fd/$snapshot_fd" || digest=""
  fi
  sealed_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$snapshot_fd")" || sealed_identity=""
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" ||
    post_identity=""
  if [[ -n "$digest" ]]; then
    path_digest="$(sha256_file "$snapshot")" || path_digest=""
  fi
  exec {snapshot_fd}<&- || close_status=$?
  [[ "$close_status" == 0 && -n "$digest" && "$path_digest" == "$digest" &&
    "$sealed_identity" == "$device:$inode:$owner:400:$links:$size" &&
    "$post_identity" == "$sealed_identity" && -f "$snapshot" &&
    ! -L "$snapshot" && "$(readlink -f -- "$snapshot")" == "$snapshot" ]] ||
    return 1
  RESULT_SNAPSHOT_IDENTITY["$snapshot"]="$sealed_identity"
  RESULT_SNAPSHOT_SHA256["$snapshot"]="$digest"
}

assert_result_snapshot_unchanged() {
  local -r snapshot="$1"
  local expected_identity="${RESULT_SNAPSHOT_IDENTITY[$snapshot]:-}"
  local expected_digest="${RESULT_SNAPSHOT_SHA256[$snapshot]:-}"
  local path_identity=""
  local descriptor_identity=""
  local post_identity=""
  local digest=""
  local snapshot_fd=""
  local close_status=0

  [[ -n "$expected_identity" && -n "$expected_digest" &&
    "$snapshot" == "$PRIVATE_DIRECTORY/"* && -f "$snapshot" &&
    ! -L "$snapshot" && "$(readlink -f -- "$snapshot")" == "$snapshot" ]] ||
    return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" ||
    return 1
  [[ "$path_identity" == "$expected_identity" ]] || return 1
  exec {snapshot_fd}<"$snapshot" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$snapshot_fd")" || descriptor_identity=""
  if [[ "$descriptor_identity" == "$expected_identity" ]]; then
    digest="$(sha256_open_fd "$snapshot_fd")" || digest=""
  fi
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" ||
    post_identity=""
  exec {snapshot_fd}<&- || close_status=$?
  [[ "$close_status" == 0 && "$descriptor_identity" == "$expected_identity" &&
    "$post_identity" == "$expected_identity" && "$digest" == "$expected_digest" &&
    -f "$snapshot" && ! -L "$snapshot" &&
    "$(readlink -f -- "$snapshot")" == "$snapshot" ]]
}

snapshot_result_names() {
  local -r output="$1"
  local -r results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local owner=""
  local mode=""
  local root_identity=""

  [[ "$output" == "$PRIVATE_DIRECTORY/"* && ! -e "$output" &&
    ! -L "$output" ]] || return 1
  : >"$output" || return 1
  chmod 0600 -- "$output" || return 1
  if [[ ! -e "$results_root" && ! -L "$results_root" ]]; then
    [[ -z "$RESULTS_ROOT_IDENTITY" ]] || return 1
  else
    [[ -d "$results_root" && ! -L "$results_root" &&
      "$(CDPATH='' cd -- "$results_root" && pwd -P)" == "$results_root" ]] ||
      return 1
    owner="$(stat -Lc '%u' -- "$results_root")" || return 1
    mode="$(stat -Lc '%a' -- "$results_root")" || return 1
    [[ "$owner" == "$EUID" && "$mode" =~ ^[0-7]{3,4}$ &&
      $((8#$mode & 0022)) == 0 ]] || return 1
    root_identity="$(stat -Lc '%d:%i:%u:%a' -- "$results_root")" || return 1
    if [[ -z "$RESULTS_ROOT_IDENTITY" ]]; then
      RESULTS_ROOT_IDENTITY="$root_identity"
    else
      [[ "$root_identity" == "$RESULTS_ROOT_IDENTITY" ]] || return 1
    fi
    find -- "$results_root" -mindepth 1 -maxdepth 1 \
      -printf '%f\t%y:%D:%i:%U:%m\n' | LC_ALL=C sort >"$output" || return 1
  fi
  seal_result_snapshot "$output"
}

metric_capture_lock_matches_snapshot() {
  local -r results_root="$1"
  local -r snapshot_identity="$2"
  local -r lock="$results_root/.obi-metric-capture.lock"
  local lock_fd=""
  local path_identity=""
  local descriptor_identity=""
  local post_identity=""
  local lock_acquired=false
  local unlock_status=0

  [[ "$snapshot_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ &&
    -d "$results_root" && ! -L "$results_root" &&
    "$(realpath -e -- "$results_root")" == "$results_root" &&
    -f "$lock" && ! -L "$lock" &&
    "$(realpath -e -- "$lock")" == "$lock" ]] || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock")" || return 1
  [[ "${path_identity%:*}" == "$snapshot_identity" &&
    "$path_identity" == *":$EUID:600:1" ]] || return 1
  exec {lock_fd}<"$lock" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$lock_fd")" || descriptor_identity=""
  if [[ "$descriptor_identity" == "$path_identity" ]] &&
    flock -n "$lock_fd"; then
    lock_acquired=true
    flock -u "$lock_fd" || unlock_status=$?
  fi
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock")" ||
    post_identity=""
  exec {lock_fd}<&- || return $?
  [[ "$lock_acquired" == true && "$unlock_status" == 0 &&
    -f "$lock" && ! -L "$lock" &&
    "$(realpath -e -- "$lock")" == "$lock" &&
    "$path_identity" == "$descriptor_identity" &&
    "$path_identity" == "$post_identity" ]]
}

assert_result_inventory() {
  local -r inventory="$1"
  shift
  local -r results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local name=""
  local metadata=""
  local type=""
  local identity=""
  local expected_path=""
  local expected_identity=""
  local observed_lock_identity=""
  local lock_seen=false
  local -i expected_count=0
  local -i observed_count=0
  declare -A expected_results=()
  declare -A observed_results=()

  assert_result_snapshot_unchanged "$inventory" || return 1
  (( $# % 2 == 0 )) || return 1
  while (( $# > 0 )); do
    expected_path="$1"
    expected_identity="$2"
    shift 2
    [[ "$expected_path" == "$results_root/"* &&
      "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
    name="${expected_path##*/}"
    [[ -z "${expected_results[$name]+present}" ]] || return 1
    expected_results["$name"]="$expected_identity"
    expected_count=$((expected_count + 1))
  done
  while IFS=$'\t' read -r name metadata; do
    [[ -n "$name" && -n "$metadata" ]] || return 1
    type="${metadata%%:*}"
    identity="${metadata#*:}"
    case "$name" in
      .obi-metric-capture.lock)
        [[ "$lock_seen" == false && "$type" == f ]] || return 1
        metric_capture_lock_matches_snapshot "$results_root" "$identity" ||
          return 1
        if [[ -n "$RESULT_LOCK_IDENTITY" ]]; then
          [[ "$identity" == "$RESULT_LOCK_IDENTITY" ]] || return 1
        fi
        observed_lock_identity="$identity"
        lock_seen=true
        ;;
      *)
        [[ "$type" == d && -n "${expected_results[$name]+present}" &&
          -z "${observed_results[$name]+present}" &&
          "$identity" == "${expected_results[$name]}" ]] || return 1
        observed_results["$name"]="$identity"
        observed_count=$((observed_count + 1))
        ;;
    esac
  done <"$inventory"
  (( observed_count == expected_count )) || return 1
  for name in "${!expected_results[@]}"; do
    [[ -n "${observed_results[$name]+present}" ]] || return 1
  done
  if [[ "$lock_seen" == true && -z "$RESULT_LOCK_IDENTITY" ]]; then
    RESULT_LOCK_IDENTITY="$observed_lock_identity"
  fi
  { (( expected_count == 0 )) || [[ "$lock_seen" == true ]]; } &&
    assert_result_snapshot_unchanged "$inventory"
}

read_environment_value() {
  local -r input="$1"
  local -r key="$2"
  local -a values=()

  [[ -f "$input" && ! -L "$input" &&
    "$(stat -Lc '%s' -- "$input")" -le MAX_ENVIRONMENT_BYTES ]] || return 1
  mapfile -t values < <(awk -F= -v wanted="$key" '$1 == wanted {
    print substr($0, length($1) + 2)
  }' "$input")
  (( ${#values[@]} == 1 )) || return 1
  printf '%s\n' "${values[0]}"
}

assert_raw_result() {
  local -r role="$1"
  local -r result="$2"
  local run_status="$result/run-status.json"
  local environment="$result/environment.txt"
  local result_physical=""
  local result_owner=""
  local result_mode=""
  local revision=""
  local dirty=""
  local source_tree=""
  local architecture=""
  local scenario=""

  [[ "$result" == "$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results/"* &&
    -d "$result" && ! -L "$result" ]] || return 1
  result_physical="$(CDPATH='' cd -- "$result" && pwd -P)" || return 1
  [[ "$result_physical" == "$result" ]] || return 1
  result_owner="$(stat -Lc '%u' -- "$result")" || return 1
  result_mode="$(stat -Lc '%a' -- "$result")" || return 1
  [[ "$result_owner" == "$EUID" && "$result_mode" == 755 ]] || return 1
  [[ -f "$run_status" && ! -L "$run_status" &&
    "$(stat -Lc '%s' -- "$run_status")" -le MAX_RUN_STATUS_BYTES &&
    -f "$environment" && ! -L "$environment" ]] || return 1
  revision="$(read_environment_value "$environment" revision)" || return 1
  dirty="$(read_environment_value "$environment" dirty)" || return 1
  source_tree="$(read_environment_value "$environment" source_tree_sha256)" ||
    return 1
  architecture="$(read_environment_value "$environment" architecture)" ||
    return 1
  scenario="$(read_environment_value "$environment" scenario)" || return 1
  [[ "$revision" == "$SOURCE_REVISION" && "$dirty" == false &&
    "$architecture" == "$ARCHITECTURE" ]] || return 1
  is_sha256 "$source_tree" || return 1
  case "$role" in
    acceptance)
      [[ "$scenario" == all ]] || return 1
      jq -e --arg result "$result" '
        .schema == "obi-apache-java-https-run-status-v3" and
        .status == "passed" and .exit_status == 0 and
        .acceptance_evidence == true and
        .acceptance_evidence_reason == "none" and
        .evidence_directory == $result
      ' "$run_status" >/dev/null || return 1
      ;;
    assertion-failure)
      [[ "$scenario" == assertion-failure ]] || return 1
      jq -e --arg result "$result" '
        .schema == "obi-apache-java-https-run-status-v3" and
        .status == "failed" and .exit_status == 2 and
        .acceptance_evidence == false and
        .acceptance_evidence_reason ==
          "deliberate-assertion-failure,targeted-scenario" and
        .failure_stage == "deliberate-assertion-failure" and
        .evidence_directory == $result
      ' "$run_status" >/dev/null || return 1
      ;;
    *) return 1 ;;
  esac
}

resolve_new_result() {
  local -r role="$1"
  local -r before="$2"
  local -r output_name="$3"
  local -r output_identity_name="$4"
  local after="$PRIVATE_DIRECTORY/results-after-$role"
  local additions="$PRIVATE_DIRECTORY/results-additions-$role"
  local removals="$PRIVATE_DIRECTORY/results-removals-$role"
  local results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local name=""
  local metadata=""
  local type=""
  local identity=""
  local result=""
  local result_identity=""
  local stable_lock_seen=false
  local added_lock_seen=false
  local result_seen=false

  [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_identity_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  snapshot_result_names "$after" || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  assert_result_snapshot_unchanged "$after" || return 1
  LC_ALL=C comm -13 -- "$before" "$after" >"$additions" || return 1
  LC_ALL=C comm -23 -- "$before" "$after" >"$removals" || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  assert_result_snapshot_unchanged "$after" || return 1
  [[ ! -s "$removals" ]] || return 1
  while IFS=$'\t' read -r name metadata; do
    [[ -n "$name" && -n "$metadata" ]] || return 1
    type="${metadata%%:*}"
    identity="${metadata#*:}"
    [[ "$name" == .obi-metric-capture.lock ]] || continue
    [[ "$stable_lock_seen" == false && "$type" == f ]] || return 1
    metric_capture_lock_matches_snapshot "$results_root" "$identity" || return 1
    if [[ -n "$RESULT_LOCK_IDENTITY" ]]; then
      [[ "$identity" == "$RESULT_LOCK_IDENTITY" ]] || return 1
    fi
    stable_lock_seen=true
  done <"$before"
  while IFS=$'\t' read -r name metadata; do
    [[ -n "$name" && -n "$metadata" ]] || return 1
    type="${metadata%%:*}"
    identity="${metadata#*:}"
    case "$name" in
      .obi-metric-capture.lock)
        [[ "$stable_lock_seen" == false && "$added_lock_seen" == false &&
          "$type" == f ]] || return 1
        metric_capture_lock_matches_snapshot "$results_root" "$identity" ||
          return 1
        added_lock_seen=true
        ;;
      *)
        [[ "$result_seen" == false && "$type" == d &&
          "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ &&
          "$identity" == *":$EUID:755" &&
          "$name" =~ ^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$ ]] || return 1
        result="$results_root/$name"
        [[ -d "$result" && ! -L "$result" &&
          "$(stat -Lc '%d:%i:%u:%a' -- "$result")" == "$identity" ]] ||
          return 1
        result_identity="$identity"
        result_seen=true
        ;;
    esac
  done <"$additions"
  [[ "$result_seen" == true &&
    ( "$stable_lock_seen" == true || "$added_lock_seen" == true ) ]] ||
    return 1
  assert_raw_result "$role" "$result" || return 1
  if [[ "$added_lock_seen" == true ]]; then
    RESULT_LOCK_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
      "$results_root/.obi-metric-capture.lock")" || return 1
  fi
  [[ -n "$RESULT_LOCK_IDENTITY" ]] || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  assert_result_snapshot_unchanged "$after" || return 1
  printf -v "$output_name" '%s' "$result"
  printf -v "$output_identity_name" '%s' "$result_identity"
}

assert_result_identity() {
  local -r path="$1"
  local -r identity="$2"
  [[ -d "$path" && ! -L "$path" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$path")" == "$identity" ]]
}

assert_source_authority_unchanged() {
  local head=""
  local status=""

  verify_exact_checkout || return 1
  head="$(git -C "$CHECKOUT_DIRECTORY" rev-parse --verify 'HEAD^{commit}')" ||
    return 1
  status="$(git -C "$CHECKOUT_DIRECTORY" status --porcelain \
    --untracked-files=all --ignore-submodules=none)" || return 1
  [[ "$head" == "$SOURCE_REVISION" && -z "$status" ]]
}

seal_receipt() {
  local commands_json=""
  local candidate=""
  local candidate_identity=""
  local source_tree=""
  local assertion_tree=""
  local receipt_size=""

  (( COMMAND_COUNT == ${#RECEIPT_COMMAND_IDS[@]} )) || return 1
  (( ${#COMMAND_ROWS_MEMORY[@]} == ${#RECEIPT_COMMAND_IDS[@]} )) || return 1
  commands_json="$(printf '%s\n' "${COMMAND_ROWS_MEMORY[@]}" | jq -cs '.')" ||
    return 1
  source_tree="$(read_environment_value "$RAW_ACCEPTANCE/environment.txt" \
    source_tree_sha256)" || return 1
  assertion_tree="$(read_environment_value "$RAW_ASSERTION/environment.txt" \
    source_tree_sha256)" || return 1
  [[ "$source_tree" == "$assertion_tree" ]] || return 1
  is_sha256 "$source_tree" || return 1
  SOURCE_TREE_SHA256="$source_tree"
  candidate="$(mktemp "$PRIVATE_DIRECTORY/.runbook-receipt.XXXXXX")" ||
    return 1
  candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" ||
    return 1
  [[ "$candidate_identity" == *":$EUID:600:1" ]] || return 1
  jq -cS -n \
    --arg schema "$RECEIPT_SCHEMA" \
    --arg source_revision "$SOURCE_REVISION" \
    --arg source_tree_sha256 "$SOURCE_TREE_SHA256" \
    --arg architecture "$ARCHITECTURE" \
    --arg compose_version "$COMPOSE_VERSION" \
    --arg docker_version "$DOCKER_VERSION" \
    --arg go_version "$GO_VERSION" \
    --arg java_version "$JAVA_VERSION" \
    --arg operating_system "$OPERATING_SYSTEM" \
    --arg head_sha "$SOURCE_REVISION" \
    --arg repository "$REPOSITORY_SLUG" \
    --arg run_attempt "$RUN_ATTEMPT" \
    --arg run_id "$RUN_ID" \
    --arg run_url "$RUN_URL" \
    --arg workflow_blob_sha256 "$WORKFLOW_BLOB_SHA256" \
    --arg workflow_path "$WORKFLOW_PATH" \
    --arg workflow_ref "$WORKFLOW_REF" \
    --arg workflow_sha "$SOURCE_REVISION" \
    --argjson commands "$commands_json" '{
      commands: $commands,
      environment: {
        architecture: $architecture,
        compose_version: $compose_version,
        docker_version: $docker_version,
        go_version: $go_version,
        java_version: $java_version,
        operating_system: $operating_system
      },
      execution_locator: {
        event: "push",
        head_sha: $head_sha,
        kind: "github-actions",
        repository: $repository,
        run_attempt: $run_attempt,
        run_id: $run_id,
        run_url: $run_url,
        workflow_blob_sha256: $workflow_blob_sha256,
        workflow_path: $workflow_path,
        workflow_ref: $workflow_ref,
        workflow_sha: $workflow_sha
      },
      output_contract: {
        algorithm: "sha256",
        bytes: "exact-command-order-no-normalization",
        stream: "combined-stdout-stderr"
      },
      schema: $schema,
      source_revision: $source_revision,
      source_tree_sha256: $source_tree_sha256
    }' >"$candidate" || return 1
  receipt_size="$(stat -Lc '%s' -- "$candidate")" || return 1
  [[ "$receipt_size" =~ ^[0-9]+$ ]] || return 1
  (( receipt_size <= MAX_RECEIPT_BYTES )) || return 1
  validate_receipt "$candidate" || return 1
  RECEIPT="$PRIVATE_DIRECTORY/runbook-receipt.json"
  [[ ! -e "$RECEIPT" && ! -L "$RECEIPT" ]] || return 1
  mv -T -- "$candidate" "$RECEIPT" || return 1
  RECEIPT_IDENTITY="$(stat -Lc '%d:%i:%u:%a:%h' -- "$RECEIPT")" ||
    return 1
  [[ "$RECEIPT_IDENTITY" == *":$EUID:600:1" ]] || return 1
  RECEIPT_SHA256="$(sha256_file "$RECEIPT")" || return 1
}

validate_receipt() {
  local -r receipt="$1"
  local expected_ids=""

  [[ -f "$receipt" && ! -L "$receipt" &&
    "$(stat -Lc '%u:%a:%h' -- "$receipt")" == "$EUID:600:1" ]] ||
    return 1
  cmp -s -- "$receipt" <(jq -cS . "$receipt") || return 1
  expected_ids="$(printf '%s\n' "${RECEIPT_COMMAND_IDS[@]}" |
    jq -Rsc 'split("\n") | map(select(length > 0))')" || return 1
  jq -se --argjson ids "$expected_ids" \
    --arg revision "$SOURCE_REVISION" \
    --arg source_tree "$SOURCE_TREE_SHA256" \
    --arg architecture "$ARCHITECTURE" \
    --arg workflow_digest "$WORKFLOW_BLOB_SHA256" '
    length == 1 and (.[0] |
    keys == ["commands", "environment", "execution_locator",
      "output_contract", "schema", "source_revision", "source_tree_sha256"] and
    .schema == "obi-apache-java-https-runbook-receipt-v1" and
    .source_revision == $revision and .source_tree_sha256 == $source_tree and
    (.environment |
      keys == ["architecture", "compose_version", "docker_version",
        "go_version", "java_version", "operating_system"] and
      .architecture == $architecture and .operating_system == "Linux" and
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
      .event == "push" and .kind == "github-actions" and
      .repository == "MrAlias/opentelemetry-ebpf-instrumentation" and
      .head_sha == $revision and .workflow_sha == $revision and
      .workflow_blob_sha256 == $workflow_digest and
      .workflow_path ==
        ".github/workflows/java_remote_parent_acceptance_claims.yml" and
      .workflow_ref ==
        "MrAlias/opentelemetry-ebpf-instrumentation/.github/workflows/java_remote_parent_acceptance_claims.yml@refs/heads/agent/java-remote-parent-bridge" and
      (.run_id | test("^[1-9][0-9]{0,18}$")) and
      (.run_attempt | test("^[1-9][0-9]{0,18}$")) and
      .run_url == ("https://github.com/" + .repository + "/actions/runs/" +
        .run_id + "/attempts/" + .run_attempt)) and
    [.commands[].id] == $ids and
    all(.commands[];
      keys == ["duration_seconds", "exit_status", "id", "output_sha256",
        "status"] and
      (.duration_seconds | type == "number" and floor == . and
        . >= 0 and . <= 86400) and
      (.output_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (if .id == "assertion-failure-exit-2" then
        .status == "expected_failure" and .exit_status == 2
      else .status == "passed" and .exit_status == 0 end)))
  ' "$receipt" >/dev/null
}

assert_receipt_unchanged() {
  [[ -f "$RECEIPT" && ! -L "$RECEIPT" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$RECEIPT")" == "$RECEIPT_IDENTITY" &&
    "$(sha256_file "$RECEIPT")" == "$RECEIPT_SHA256" ]]
}

assert_projection_execution_authority() {
  local head=""

  assert_checkout_identity || return 1
  head="$(git -C "$CHECKOUT_DIRECTORY" rev-parse --verify 'HEAD^{commit}')" ||
    return 1
  [[ "$head" == "$SOURCE_REVISION" ]] || return 1
  assert_exact_tracked_file "$CHECKOUT_DIRECTORY" "$SOURCE_REVISION" \
    examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh \
    100755 755 || return 1
  assert_exact_tracked_file "$CHECKOUT_DIRECTORY" "$SOURCE_REVISION" \
    examples/apache-java-https/scripts/verify-retained-evidence.sh \
    100755 755 || return 1
  assert_checkout_identity
}

projector_execute() {
  timeout --foreground --signal=TERM \
    --kill-after="${PROJECT_KILL_AFTER_SECONDS}s" \
    "${PROJECT_TIMEOUT_SECONDS}s" "$@"
}

project_claims() {
  local -r projector="$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh"
  local projector_log="$PRIVATE_DIRECTORY/projector.log"
  local projector_status=0

  assert_output_target || return 1
  assert_private_directory_identity || return 1
  assert_projection_execution_authority || return 1
  assert_result_identity "$RAW_ACCEPTANCE" "$RAW_ACCEPTANCE_IDENTITY" ||
    return 1
  assert_result_identity "$RAW_ASSERTION" "$RAW_ASSERTION_IDENTITY" ||
    return 1
  assert_receipt_unchanged || return 1
  assert_projection_execution_authority || return 1
  if projector_execute "$projector" "$RAW_ACCEPTANCE" \
      "$RAW_ASSERTION" "$RECEIPT" "$OUTPUT_DIRECTORY" \
      >"$projector_log" 2>&1; then
    projector_status=0
  else
    projector_status=$?
  fi
  chmod 0400 -- "$projector_log" 2>/dev/null || projector_status=1
  (( projector_status == 0 )) || {
    die "bounded-claim projection failed"
    return 1
  }
  assert_projection_execution_authority || return 1
  assert_receipt_unchanged
}

assert_public_closure() {
  local expected=""
  local observed=""
  local file=""
  local root_device=""

  [[ -d "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" &&
    "$(CDPATH='' cd -- "$OUTPUT_DIRECTORY" && pwd -P)" == "$OUTPUT_DIRECTORY" &&
    "$(stat -Lc '%u:%a' -- "$OUTPUT_DIRECTORY")" == "$EUID:555" ]] ||
    return 1
  expected="$(printf '%s\tf\n' "${PUBLIC_FILES[@]}" | LC_ALL=C sort)" ||
    return 1
  observed="$(find -- "$OUTPUT_DIRECTORY" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' | LC_ALL=C sort)" || return 1
  [[ "$observed" == "$expected" ]] || return 1
  root_device="$(stat -Lc '%d' -- "$OUTPUT_DIRECTORY")" || return 1
  for file in "${PUBLIC_FILES[@]}"; do
    [[ -f "$OUTPUT_DIRECTORY/$file" && ! -L "$OUTPUT_DIRECTORY/$file" &&
      "$(stat -Lc '%d:%u:%a:%h' -- "$OUTPUT_DIRECTORY/$file")" == "$root_device:$EUID:444:1" ]] || return 1
  done
}

public_reverify() {
  local output=""
  local evidence_id=""

  assert_public_closure || return 1
  evidence_id="$(jq -er '.evidence_id' \
    "$OUTPUT_DIRECTORY/derivation-receipt.json")" || return 1
  is_sha256 "$evidence_id" || return 1
  output="$(CDPATH='' cd / && timeout --foreground --signal=TERM \
    --kill-after="${PUBLIC_VERIFY_KILL_AFTER_SECONDS}s" \
    "${PUBLIC_VERIFY_TIMEOUT_SECONDS}s" \
    bash "$OUTPUT_DIRECTORY/verify.sh")" || return 1
  [[ "$output" == "$PUBLIC_VERIFY_SUCCESS_PREFIX$evidence_id" ]]
}

emergency_scoped_cleanup() {
  local emergency_log=""
  local cleanup_status=0

  [[ "$CLEANUP_REQUIRED" == true ]] || return 0
  if ! assert_cleanup_execution_authority 2>/dev/null; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  emergency_log="$PRIVATE_DIRECTORY/emergency-scoped-cleanup.log"
  if (
    CDPATH='' cd -- "$CHECKOUT_DIRECTORY"
    campaign_execute emergency-scoped-cleanup \
      ./examples/apache-java-https/run.sh --cleanup-only
  ) >"$emergency_log" 2>&1; then
    cleanup_status=0
  else
    cleanup_status=$?
  fi
  chmod 0400 -- "$emergency_log" 2>/dev/null || cleanup_status=1
  if (( cleanup_status != 0 )); then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  CLEANUP_REQUIRED=false
  # Deliberately do not clear STICKY_CLEANUP_FAILURE. A failed authoritative
  # cleanup command cannot be repaired into a publishable campaign by a retry.
}

cleanup_on_exit() {
  local -r original_status="$?"
  local cleanup_status=0

  trap - EXIT ERR HUP INT TERM
  set +e
  emergency_scoped_cleanup || cleanup_status=1
  destroy_private_transaction || cleanup_status=1
  if [[ -n "$PRIMARY_FAILURE" ]]; then
    log_info "failure context: $PRIMARY_FAILURE"
  fi
  if (( original_status == 0 )) &&
    { (( cleanup_status != 0 )) || [[ "$STICKY_CLEANUP_FAILURE" == true ]]; }; then
    exit 1
  fi
  exit "$original_status"
}

install_campaign_traps() {
  trap 'on_error "$LINENO" "$?"' ERR
  trap cleanup_on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

run_campaign() {
  local before_acceptance=""
  local before_assertion=""
  local final_inventory=""

  enter_state AUTHORITY_PREFLIGHT
  authority_preflight

  enter_state PRIVATE_TXN
  create_private_transaction

  enter_state CLONE
  run_recorded_command clone 0 "$PRIVATE_DIRECTORY" \
    git clone --no-checkout --no-tags -- "$REPOSITORY_URL" "$CHECKOUT_DIRECTORY"
  verify_clone_root

  enter_state EXACT_CHECKOUT
  run_recorded_command checkout-exact-revision 0 "$CHECKOUT_DIRECTORY" \
    git -C "$CHECKOUT_DIRECTORY" checkout --detach "$SOURCE_REVISION"
  verify_exact_checkout

  enter_state CLEAN_BEFORE
  run_recorded_command clean-status-before 0 "$CHECKOUT_DIRECTORY" \
    git status --porcelain
  assert_command_output_empty clean-status-before

  enter_state CERTS
  run_recorded_command certificate-generation 0 "$CHECKOUT_DIRECTORY" \
    ./examples/apache-java-https/certs/generate_test.sh

  enter_state RUN_TEST
  run_recorded_command run-test 0 "$CHECKOUT_DIRECTORY" \
    ./examples/apache-java-https/scripts/run_test.sh

  enter_state TRACECHECK
  run_recorded_command tracecheck-tests 0 "$CHECKOUT_DIRECTORY" \
    go test ./examples/apache-java-https/tracecheck/...

  enter_state COMPOSE_CONFIG
  run_recorded_command compose-config 0 "$CHECKOUT_DIRECTORY" \
    docker compose --project-name obi-apache-java-https \
      --file examples/apache-java-https/docker-compose.yml config --quiet

  enter_state CLEAN_AFTER_VALIDATION
  run_recorded_command clean-status-after-validation 0 "$CHECKOUT_DIRECTORY" \
    git status --porcelain
  assert_command_output_empty clean-status-after-validation
  assert_source_authority_unchanged

  before_acceptance="$PRIVATE_DIRECTORY/results-before-acceptance"
  snapshot_result_names "$before_acceptance"
  assert_result_inventory "$before_acceptance" || {
    die "clean clone has preexisting raw result directories"
    return 1
  }
  enter_state ACCEPTANCE
  CLEANUP_REQUIRED=true
  run_recorded_command acceptance-all-otel-getsockopt-tls13 0 \
    "$CHECKOUT_DIRECTORY" ./examples/apache-java-https/run.sh \
      --transport getsockopt --agent otel --tls TLSv1.3
  resolve_new_result acceptance "$before_acceptance" RAW_ACCEPTANCE \
    RAW_ACCEPTANCE_IDENTITY

  before_assertion="$PRIVATE_DIRECTORY/results-before-assertion-failure"
  snapshot_result_names "$before_assertion"
  assert_result_inventory "$before_assertion" \
    "$RAW_ACCEPTANCE" "$RAW_ACCEPTANCE_IDENTITY"
  enter_state ASSERTION_CONTROL
  run_recorded_command assertion-failure-exit-2 2 "$CHECKOUT_DIRECTORY" \
    ./examples/apache-java-https/run.sh --transport getsockopt \
      --scenario assertion-failure
  assert_result_identity "$RAW_ACCEPTANCE" "$RAW_ACCEPTANCE_IDENTITY"
  resolve_new_result assertion-failure "$before_assertion" RAW_ASSERTION \
    RAW_ASSERTION_IDENTITY

  enter_state SCOPED_CLEANUP
  if ! assert_cleanup_execution_authority 2>/dev/null; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  if ! run_recorded_command scoped-cleanup 0 "$CHECKOUT_DIRECTORY" \
    ./examples/apache-java-https/run.sh --cleanup-only; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  CLEANUP_REQUIRED=false

  enter_state FINAL_CLEAN
  run_recorded_command clean-status-final 0 "$CHECKOUT_DIRECTORY" \
    git status --porcelain
  assert_command_output_empty clean-status-final
  assert_source_authority_unchanged
  assert_result_identity "$RAW_ACCEPTANCE" "$RAW_ACCEPTANCE_IDENTITY"
  assert_result_identity "$RAW_ASSERTION" "$RAW_ASSERTION_IDENTITY"
  final_inventory="$PRIVATE_DIRECTORY/results-final"
  snapshot_result_names "$final_inventory"
  assert_result_inventory "$final_inventory" \
    "$RAW_ACCEPTANCE" "$RAW_ACCEPTANCE_IDENTITY" \
    "$RAW_ASSERTION" "$RAW_ASSERTION_IDENTITY"

  enter_state RECEIPT_SEAL
  seal_receipt

  enter_state PROJECT
  project_claims
  assert_public_closure

  enter_state PRIVATE_DESTROY
  destroy_private_transaction

  enter_state PUBLIC_REVERIFY
  public_reverify

  enter_state SUCCESS
  [[ "$CURRENT_STATE_INDEX" == $((${#CAMPAIGN_STATES[@]} - 1)) &&
    "$STICKY_CLEANUP_FAILURE" == false ]]
  log_info "verified public bounded-claim evidence: $OUTPUT_DIRECTORY"
}

campaign_entry() {
  if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    usage
    return 0
  fi
  [[ $# == 1 ]] || {
    usage >&2
    return 2
  }
  OUTPUT_DIRECTORY="$1"
  install_campaign_traps
  run_campaign
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  campaign_entry "$@"
fi
