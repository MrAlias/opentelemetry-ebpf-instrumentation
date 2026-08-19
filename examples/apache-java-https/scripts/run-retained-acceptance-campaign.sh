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
readonly MAX_FAILURE_BOUNDARY_INDEX_BYTES=4194304
readonly MAX_FAILURE_JAVA_TERMINAL_BYTES=16384
readonly MAX_FAILURE_OBI_TERMINAL_BYTES=131072
readonly MAX_FAILURE_FREEZE_BYTES=160
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

# This is the exact scenario=all, repeat=1 boundary roster at the authority
# revision.  Failure classification never publishes a boundary name supplied
# only by private evidence; it first proves an exact match to this allowlist.
readonly -a ACCEPTANCE_BOUNDARY_IDS=(
  basic delayed-otlp-suppression security keepalive pipelining concurrency
  connection-churn fd-port-reuse slow-body tls-boundary coalesced-bridge
  timeout-retry pressure handoff virtual-thread netty netty-server dispatch
  w3c w3c-match obi-flags primary-w3c-stale primary-generation-mismatch
  primary-w3c-fault unix-w3c-stale unix-generation-mismatch w3c-fault
  permanent-absence auto-unavailable late-attach restart-during-traffic
  helper-attach-failure disabled extension-controls uninstrumented
)

readonly -a ACCEPTANCE_FAILURE_STAGES=(
  initialization argument-validation project-guard runtime-preparation
  source-state source-snapshot certificates official-agent bridge-artifacts
  bridge-build source-snapshot-seal compose-environment environment-evidence
  compose-ownership compose-configuration compose-build-start readiness
  scenarios runtime-evidence deliberate-assertion-failure complete
  primary-w3c-fault-recovery primary-generation-mismatch-recovery
  unix-generation-mismatch-recovery permanent-absence-recovery
  primary-live-fd-security-recovery temporary-cleanup compose-cleanup
  project-guard-handoff signal evidence-publication project-guard-status
)

# This is the exact public counter schema accepted by run.sh for a sealed Java
# terminal snapshot.  The classifier never publishes a counter or its value;
# it uses the fixed roster only to prove that the terminal digest commits to a
# structurally valid snapshot referenced by the frozen boundary index.
readonly -a ACCEPTANCE_JAVA_DIAGNOSTIC_COUNTER_NAMES=(
  cfg_on cfg_off provider_ok provider_reject provider_ver extension_reg
  lookup_ready lookup_missing lookup_version lookup_error record_version
  invoke_error discard_standard extract_fields extract_invalid extract_error
  registration_ok registration_fail take_sampled take_unsampled tls_reads
  tls_bytes framework_depth framework_cycle framework_late transport_missing
  t_unknown d_unknown t_valid d_valid t_missing d_missing t_stale d_stale
  t_unsupported d_unsupported t_malformed d_malformed t_version_mismatch
  d_version_mismatch t_ambiguous d_ambiguous t_unauthorized d_unauthorized
  t_already_consumed d_already_consumed t_timeout d_timeout t_overload
  d_overload t_transport_error d_transport_error t_disabled d_disabled
)

OUTPUT_DIRECTORY=""
OUTPUT_PARENT=""
OUTPUT_NAME=""
OUTPUT_PARENT_IDENTITY=""
OUTPUT_PARENT_FD=""
OUTPUT_DIRECTORY_IDENTITY=""
OUTPUT_DIRECTORY_FD=""
PUBLIC_CLOSURE_SHA256=""
PUBLIC_EVIDENCE_ID=""
WORKFLOW_OUTPUT_IDENTITY=""
WORKFLOW_OUTPUT_FD=""
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
PRIVATE_DIRECTORY_FD=""
CHECKOUT_DIRECTORY=""
CHECKOUT_IDENTITY=""
COMMAND_DIRECTORY=""
COMMAND_DIRECTORY_IDENTITY=""
STATE_JOURNAL=""
STATE_JOURNAL_FD=""
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
LAST_RECORDED_COMMAND_ID=""
LAST_RECORDED_COMMAND_EXIT_STATUS=""
LAST_RECORDED_COMMAND_VALIDATED=false
FAILURE_CLASSIFICATION_JSON=""
FAILURE_CLASSIFICATION_EMITTED=false
FAILURE_CLASSIFICATION_STAGE=""
FAILURE_CLASSIFICATION_SOURCE_LINE=""
FAILURE_CLASSIFICATION_FIRST_INCOMPLETE=""
FAILURE_CLASSIFICATION_TERMINAL_COUNT=""
FAILURE_CLASSIFICATION_JAVA_TERMINAL_SHA256=""
FAILURE_CLASSIFICATION_OBI_TERMINAL_SHA256=""
FAILURE_CLASSIFICATION_INDEX_SHA256=""
FAILURE_CLASSIFICATION_RUN_STATUS_SHA256=""
declare -a STATE_HISTORY=()
declare -a COMMAND_ROWS_MEMORY=()
declare -A COMMAND_OUTPUT_SHA256=()
declare -A RESULT_SNAPSHOT_IDENTITY=()
declare -A RESULT_SNAPSHOT_SHA256=()
declare -A PUBLIC_FILE_IDENTITY=()
declare -A PUBLIC_FILE_SHA256=()

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

assert_output_parent_unchanged() {
  local parent_physical=""
  local owner=""
  local mode=""
  local observed_identity=""
  local descriptor_identity=""
  local candidate_fd=""
  local -i mode_bits=0

  [[ -n "$OUTPUT_PARENT" && "$OUTPUT_PARENT" == /* ]] || return 1
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
  observed_identity="$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_PARENT")" ||
    return 1
  if [[ -z "$OUTPUT_PARENT_IDENTITY" ]]; then
    exec {candidate_fd}<"$OUTPUT_PARENT" || return $?
    descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$candidate_fd")" || {
      exec {candidate_fd}<&-
      return 1
    }
    [[ "$descriptor_identity" == "$observed_identity" ]] || {
      exec {candidate_fd}<&-
      return 1
    }
    OUTPUT_PARENT_IDENTITY="$observed_identity"
    OUTPUT_PARENT_FD="$candidate_fd"
  else
    [[ "$OUTPUT_PARENT_FD" =~ ^[0-9]+$ ]] || return 1
    descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$OUTPUT_PARENT_FD")" || return 1
    [[ "$observed_identity" == "$OUTPUT_PARENT_IDENTITY" &&
      "$descriptor_identity" == "$OUTPUT_PARENT_IDENTITY" ]] || {
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

assert_output_target() {
  local derived_parent=""
  local derived_name=""

  [[ "$OUTPUT_DIRECTORY" == /* && "$OUTPUT_DIRECTORY" != */ &&
    ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]] || {
    die "public output must be a nonexistent absolute path"
    return 1
  }
  derived_parent="${OUTPUT_DIRECTORY%/*}"
  derived_name="${OUTPUT_DIRECTORY##*/}"
  is_safe_public_name "$derived_name" || {
    die "public output name is not a safe evidence identifier"
    return 1
  }
  if [[ -n "$OUTPUT_PARENT" ]]; then
    [[ "$derived_parent" == "$OUTPUT_PARENT" &&
      "$derived_name" == "$OUTPUT_NAME" ]] || return 1
  else
    OUTPUT_PARENT="$derived_parent"
    OUTPUT_NAME="$derived_name"
  fi
  assert_output_parent_unchanged
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

open_workflow_output_channel() {
  local -r workflow_output="${GITHUB_OUTPUT:-}"
  local path_identity=""
  local descriptor_identity=""
  local post_identity=""
  local owner=""
  local mode=""
  local links=""
  local candidate_fd=""
  local -i mode_bits=0

  [[ "$workflow_output" == /* && -f "$workflow_output" &&
    ! -L "$workflow_output" &&
    "$(readlink -f -- "$workflow_output")" == "$workflow_output" ]] ||
    return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$workflow_output")" ||
    return 1
  IFS=: read -r _ _ owner mode links <<<"$path_identity"
  [[ "$owner" == "$EUID" && "$mode" =~ ^[0-7]{3,4}$ && "$links" == 1 ]] ||
    return 1
  mode_bits=$((8#$mode))
  (( (mode_bits & 0022) == 0 )) || return 1
  exec {candidate_fd}>>"$workflow_output" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$candidate_fd")" || descriptor_identity=""
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$workflow_output")" ||
    post_identity=""
  if [[ "$descriptor_identity" != "$path_identity" ||
    "$post_identity" != "$path_identity" ]]; then
    exec {candidate_fd}>&-
    return 1
  fi
  WORKFLOW_OUTPUT_IDENTITY="$path_identity"
  WORKFLOW_OUTPUT_FD="$candidate_fd"
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
  if [[ -n "$STATE_JOURNAL" && "$STATE_JOURNAL_FD" =~ ^[0-9]+$ &&
    -f "/proc/$BASHPID/fd/$STATE_JOURNAL_FD" ]]; then
    printf '%02d\t%s\n' "$CURRENT_STATE_INDEX" "$requested" \
      >&"$STATE_JOURNAL_FD"
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
  local descriptor_identity=""

  [[ -n "$PRIVATE_DIRECTORY" && -n "$PRIVATE_IDENTITY" &&
    "$PRIVATE_DIRECTORY_FD" =~ ^[0-9]+$ &&
    "$PRIVATE_DIRECTORY" == "$TRANSACTION_PARENT"/obi-java-remote-parent-acceptance.* &&
    "${PRIVATE_DIRECTORY##*/}" =~ ^obi-java-remote-parent-acceptance\.[A-Za-z0-9]{6}$ &&
    -d "$PRIVATE_DIRECTORY" && ! -L "$PRIVATE_DIRECTORY" &&
    "$(CDPATH='' cd -- "$PRIVATE_DIRECTORY" && pwd -P)" == "$PRIVATE_DIRECTORY" ]] ||
    return 1
  observed="$(stat -Lc '%d:%i:%u:%a' -- "$PRIVATE_DIRECTORY")" || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" || return 1
  [[ "$observed" == "$PRIVATE_IDENTITY" &&
    "$descriptor_identity" == "$PRIVATE_IDENTITY" &&
    "$observed" == *":$EUID:700" ]]
}

assert_private_descriptor_identity() {
  [[ -n "$PRIVATE_IDENTITY" && "$PRIVATE_DIRECTORY_FD" =~ ^[0-9]+$ &&
    -d "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD" &&
    "$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" == "$PRIVATE_IDENTITY" ]]
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
  local candidate_fd=""
  local descriptor_identity=""

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
  exec {candidate_fd}<"$PRIVATE_DIRECTORY" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$candidate_fd")" || {
    exec {candidate_fd}<&-
    return 1
  }
  [[ "$descriptor_identity" == "$PRIVATE_IDENTITY" ]] || {
    exec {candidate_fd}<&-
    return 1
  }
  PRIVATE_DIRECTORY_FD="$candidate_fd"
  assert_private_directory_identity || return 1
  CHECKOUT_DIRECTORY="$PRIVATE_DIRECTORY/source"
  COMMAND_DIRECTORY="$PRIVATE_DIRECTORY/commands"
  STATE_JOURNAL="$PRIVATE_DIRECTORY/state-journal.tsv"
  mkdir -m 0700 -- "$COMMAND_DIRECTORY" || return 1
  COMMAND_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
    "$COMMAND_DIRECTORY")" || return 1
  assert_command_directory_identity || return 1
  open_exclusive_output_fd "$PRIVATE_DIRECTORY_FD" state-journal.tsv \
    STATE_JOURNAL_FD || return 1
  chmod 0600 -- "/proc/$BASHPID/fd/$STATE_JOURNAL_FD" || return 1
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$STATE_JOURNAL_FD")" == *":$EUID:600:1" ]] ||
    return 1
  COMMAND_ROWS_MEMORY=()
  COMMAND_OUTPUT_SHA256=()
  RESULT_SNAPSHOT_IDENTITY=()
  RESULT_SNAPSHOT_SHA256=()
  local index=0
  local state=""
  for state in "${STATE_HISTORY[@]}"; do
    printf '%02d\t%s\n' "$index" "$state" >&"$STATE_JOURNAL_FD"
    index=$((index + 1))
  done
}

private_tree_has_mountpoint() {
  local -r mountinfo="$1"
  local -r private_root="${2:-$PRIVATE_DIRECTORY}"

  [[ "$private_root" == /* && -f "$mountinfo" && ! -L "$mountinfo" ]] ||
    return 0
  awk -v root="$private_root" '
    $5 == root || index($5, root "/") == 1 { found=1 }
    END { exit(found ? 0 : 1) }
  ' "$mountinfo"
}

private_destroy_checkpoint() {
  : "$@"
}

destroy_private_transaction() {
  local descriptor_root=""
  local descriptor_identity=""
  local descriptor_links=""
  local residue=""
  local removal_status=0

  if [[ -z "$PRIVATE_DIRECTORY" ]]; then
    [[ -z "$PRIVATE_IDENTITY" && -z "$PRIVATE_DIRECTORY_FD" ]]
    return
  fi
  assert_private_descriptor_identity || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  descriptor_root="$(readlink -f -- "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  [[ "$descriptor_root" == /* && -d "$descriptor_root" &&
    ! -L "$descriptor_root" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$descriptor_root")" == "$PRIVATE_IDENTITY" ]] || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  if private_tree_has_mountpoint /proc/self/mountinfo "$descriptor_root"; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  private_destroy_checkpoint before-delete "$descriptor_root" || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  assert_private_descriptor_identity || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  descriptor_root="$(readlink -f -- "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- "$descriptor_root")" || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  [[ "$descriptor_identity" == "$PRIVATE_IDENTITY" ]] || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  if private_tree_has_mountpoint /proc/self/mountinfo "$descriptor_root"; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  find -H "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD" -xdev -depth \
    -mindepth 1 -delete || removal_status=$?
  residue="$(find -H "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD" -xdev \
    -mindepth 1 -print -quit)" || removal_status=$?
  if (( removal_status != 0 )) || [[ -n "$residue" ]]; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  if [[ "$STATE_JOURNAL_FD" =~ ^[0-9]+$ ]]; then
    exec {STATE_JOURNAL_FD}>&- || removal_status=$?
    STATE_JOURNAL_FD=""
  fi
  assert_private_descriptor_identity || removal_status=1
  [[ -d "$descriptor_root" && ! -L "$descriptor_root" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$descriptor_root")" == "$PRIVATE_IDENTITY" ]] ||
    removal_status=1
  if (( removal_status == 0 )); then
    rmdir -- "$descriptor_root" || removal_status=$?
  fi
  descriptor_links="$(stat -Lc '%h' -- "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" ||
    descriptor_links=""
  [[ "$descriptor_links" == 0 && ! -e "$descriptor_root" &&
    ! -L "$descriptor_root" && ! -e "$PRIVATE_DIRECTORY" &&
    ! -L "$PRIVATE_DIRECTORY" ]] || removal_status=1
  exec {PRIVATE_DIRECTORY_FD}<&- || removal_status=$?
  PRIVATE_DIRECTORY_FD=""
  if (( removal_status != 0 )); then
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
  STATE_JOURNAL_FD=""
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

recorded_log_preopen_checkpoint() {
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

open_verified_input_fd() {
  local -r path="$1"
  local -r expected_mode="$2"
  local -r expected_identity="$3"
  local -r expected_digest="$4"
  local -r output_fd_name="$5"
  local -r output_identity_name="$6"
  local opened_input_fd=""
  local path_identity=""
  local descriptor_identity=""
  local post_identity=""
  local digest=""

  [[ "$path" == /* && -f "$path" && ! -L "$path" &&
    "$(readlink -f -- "$path")" == "$path" &&
    "$expected_mode" =~ ^[0-7]{3,4}$ &&
    "$expected_digest" =~ ^[0-9a-f]{64}$ &&
    "$output_fd_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_identity_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" || return 1
  [[ "$path_identity" == *":$EUID:$expected_mode:1:"* ]] || return 1
  if [[ -n "$expected_identity" ]]; then
    [[ "$path_identity" == "$expected_identity" ]] || return 1
  fi
  exec {opened_input_fd}<"$path" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$opened_input_fd")" || descriptor_identity=""
  if [[ "$descriptor_identity" == "$path_identity" ]]; then
    digest="$(sha256_open_fd "$opened_input_fd")" || digest=""
  fi
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" ||
    post_identity=""
  if [[ "$descriptor_identity" != "$path_identity" ||
    "$post_identity" != "$path_identity" || "$digest" != "$expected_digest" ]]; then
    exec {opened_input_fd}<&-
    return 1
  fi
  printf -v "$output_fd_name" '%s' "$opened_input_fd"
  printf -v "$output_identity_name" '%s' "$path_identity"
}

failure_classification_checkpoint() {
  # A no-op production seam used by the sourced mutation test to exercise
  # descriptor, same-inode, parent, and mount races at deterministic points.
  : "$@"
}

failure_classification_mountinfo_path_is_mountpoint() {
  local -r path="$1"

  [[ "$path" == /* && "$path" != *[$'\t\n \\']* &&
    -r /proc/self/mountinfo ]] || return 2
  awk -v wanted="$path" '
    $5 == wanted { found=1 }
    END { exit(found ? 0 : 1) }
  ' /proc/self/mountinfo
}

failure_classification_path_is_mountpoint() {
  failure_classification_mountinfo_path_is_mountpoint "$@"
}

failure_classification_fdinfo_mount_id() {
  local -r descriptor="$1"
  local -r output_name="$2"
  local mount_id=""

  [[ "$descriptor" =~ ^[0-9]+$ &&
    "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    -r "/proc/$BASHPID/fdinfo/$descriptor" ]] || return 1
  mount_id="$(awk '
    $1 == "mnt_id:" {
      if (seen || NF != 2 || $2 !~ /^[1-9][0-9]*$/) exit 2
      mount_id=$2
      seen=1
    }
    END {
      if (!seen) exit 1
      print mount_id
    }
  ' "/proc/$BASHPID/fdinfo/$descriptor")" || return 1
  [[ "$mount_id" =~ ^[1-9][0-9]*$ ]] || return 1
  printf -v "$output_name" '%s' "$mount_id"
}

failure_classification_fd_mount_id() {
  # A production wrapper retained as a narrow sourced-test seam.  Tests use
  # it to model a same-device bind-mounted evidence leaf without mounting.
  failure_classification_fdinfo_mount_id "$@"
}

create_failure_classification_snapshot_directory() {
  local -r output_path_name="$1"
  local -r output_fd_name="$2"
  local -r output_identity_name="$3"
  local candidate=""
  local identity=""
  local descriptor_identity=""
  local parent_identity=""
  local candidate_fd=""
  local mount_status=0

  [[ "$output_path_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_fd_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_identity_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  assert_private_directory_identity || return 1
  candidate="$(mktemp -d \
    "$PRIVATE_DIRECTORY/.acceptance-failure-classifier.XXXXXX")" || return 1
  [[ "${candidate%/*}" == "$PRIVATE_DIRECTORY" &&
    "${candidate##*/}" =~ ^\.acceptance-failure-classifier\.[A-Za-z0-9]{6}$ &&
    -d "$candidate" && ! -L "$candidate" &&
    "$(readlink -f -- "$candidate")" == "$candidate" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$candidate")" || return 1
  [[ "$identity" == "${PRIVATE_IDENTITY%%:*}:"* &&
    "$identity" == *":$EUID:700" ]] || return 1
  if failure_classification_path_is_mountpoint "$candidate"; then
    return 1
  else
    mount_status=$?
  fi
  (( mount_status == 1 )) || return 1
  exec {candidate_fd}<"$candidate" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$candidate_fd")" || return 1
  parent_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$candidate_fd/..")" || return 1
  [[ "$descriptor_identity" == "$identity" &&
    "$parent_identity" == "$PRIVATE_IDENTITY" ]] || return 1
  printf -v "$output_path_name" '%s' "$candidate"
  printf -v "$output_fd_name" '%s' "$candidate_fd"
  printf -v "$output_identity_name" '%s' "$identity"
}

open_bounded_failure_input_snapshot() {
  local -r result="$1"
  local -r result_fd="$2"
  local -r expected_result_identity="$3"
  local -r leaf="$4"
  local -r expected_mode="$5"
  local -r maximum_bytes="$6"
  local -r snapshot_directory="$7"
  local -r snapshot_directory_fd="$8"
  local -r snapshot_leaf="$9"
  local -r output_path_name="${10}"
  local -r output_fd_name="${11}"
  local -r output_identity_name="${12}"
  local -r output_digest_name="${13}"
  local path="$result/$leaf"
  local snapshot="$snapshot_directory/$snapshot_leaf"
  local source_fd=""
  local snapshot_fd=""
  local sealed_snapshot_fd=""
  local result_descriptor_identity=""
  local result_post_identity=""
  local snapshot_directory_identity=""
  local path_identity=""
  local source_descriptor_identity=""
  local source_post_descriptor_identity=""
  local source_post_identity=""
  local snapshot_created_identity=""
  local snapshot_descriptor_identity=""
  local snapshot_identity=""
  local sealed_snapshot_flags=""
  local result_mount_id=""
  local source_mount_id=""
  local source_post_mount_id=""
  local digest=""
  local device=""
  local inode=""
  local owner=""
  local mode=""
  local links=""
  local size=""

  [[ "$result" == /* && "$result_fd" =~ ^[0-9]+$ &&
    "$expected_result_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:755$ &&
    "$leaf" =~ ^[.A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
    "$snapshot_directory" == "$PRIVATE_DIRECTORY/"* &&
    "$snapshot_directory_fd" =~ ^[0-9]+$ &&
    "$snapshot_leaf" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
    "$expected_mode" =~ ^[0-7]{3,4}$ &&
    "$maximum_bytes" =~ ^[1-9][0-9]{0,18}$ &&
    "$output_path_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_fd_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_identity_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_digest_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    -f "$path" && ! -L "$path" &&
    "$(readlink -f -- "$path")" == "$path" ]] || return 1
  result_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$result_fd")" || return 1
  snapshot_directory_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$snapshot_directory_fd")" || return 1
  [[ "$result_descriptor_identity" == "$expected_result_identity" &&
    "$snapshot_directory_identity" == *":$EUID:700" &&
    -d "$snapshot_directory" && ! -L "$snapshot_directory" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$snapshot_directory")" == \
      "$snapshot_directory_identity" && ! -e "$snapshot" &&
    ! -L "$snapshot" ]] || return 1
  failure_classification_assert_not_mountpoint "$path" || return 1
  failure_classification_fd_mount_id "$result_fd" result_mount_id || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" || return 1
  IFS=: read -r device inode owner mode links size <<<"$path_identity"
  [[ "$device" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ &&
    "$device" == "${expected_result_identity%%:*}" &&
    "$owner" == "$EUID" && "$mode" == "$expected_mode" &&
    "$links" == 1 && "$size" =~ ^[1-9][0-9]{0,18}$ ]] || return 1
  (( size <= maximum_bytes )) || return 1
  exec {source_fd}<"/proc/$BASHPID/fd/$result_fd/$leaf" || return $?
  source_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$source_fd")" || source_descriptor_identity=""
  failure_classification_fd_mount_id "$source_fd" source_mount_id || {
    exec {source_fd}<&-
    return 1
  }
  [[ "$source_descriptor_identity" == "$path_identity" &&
    "$source_mount_id" == "$result_mount_id" ]] || {
    exec {source_fd}<&-
    return 1
  }
  open_exclusive_output_fd "$snapshot_directory_fd" "$snapshot_leaf" \
    snapshot_fd || {
    exec {source_fd}<&-
    return 1
  }
  snapshot_created_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$snapshot_fd")" || snapshot_created_identity=""
  [[ "$snapshot_created_identity" == *":$EUID:600:1:0" &&
    "${snapshot_created_identity%%:*}" == \
      "${snapshot_directory_identity%%:*}" &&
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" == \
      "$snapshot_created_identity" ]] || return 1
  cp -- "/proc/$BASHPID/fd/$source_fd" \
    "/proc/$BASHPID/fd/$snapshot_fd" || return 1
  failure_classification_checkpoint after-input-snapshot "$path" "$source_fd" \
    "$snapshot" "$snapshot_fd" || return 1
  source_post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" ||
    source_post_identity=""
  source_post_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$source_fd")" || source_post_descriptor_identity=""
  failure_classification_fd_mount_id "$source_fd" source_post_mount_id ||
    source_post_mount_id=""
  result_post_identity="$(stat -Lc '%d:%i:%u:%a' -- "$result")" ||
    result_post_identity=""
  snapshot_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$snapshot_fd")" || snapshot_descriptor_identity=""
  if [[ "$source_descriptor_identity" != "$path_identity" ||
    "$source_post_descriptor_identity" != "$path_identity" ||
    "$source_mount_id" != "$result_mount_id" ||
    "$source_post_mount_id" != "$result_mount_id" ||
    "$source_post_identity" != "$path_identity" ||
    "$result_post_identity" != "$expected_result_identity" ||
    "$snapshot_descriptor_identity" != \
      "${snapshot_created_identity%:*}:$size" ||
    ! -f "$path" || -L "$path" ||
    "$(readlink -f -- "$path")" != "$path" ]]; then
    exec {source_fd}<&-
    exec {snapshot_fd}>&-
    return 1
  fi
  if ! failure_classification_assert_not_mountpoint "$path"; then
    exec {source_fd}<&-
    exec {snapshot_fd}>&-
    return 1
  fi
  chmod 0400 -- "/proc/$BASHPID/fd/$snapshot_fd" || return 1
  snapshot_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" ||
    return 1
  snapshot_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$snapshot_fd")" || return 1
  [[ "$snapshot_identity" == "$snapshot_descriptor_identity" &&
    "$snapshot_identity" == \
      "${snapshot_created_identity%:600:1:0}:400:1:$size" &&
    -f "$snapshot" && ! -L "$snapshot" &&
    "$(readlink -f -- "$snapshot")" == "$snapshot" ]] || return 1
  exec {snapshot_fd}>&- || return 1
  exec {sealed_snapshot_fd}<"/proc/$BASHPID/fd/$snapshot_directory_fd/$snapshot_leaf" ||
    return $?
  snapshot_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$sealed_snapshot_fd")" || return 1
  sealed_snapshot_flags="$(awk '$1 == "flags:" { print $2 }' \
    "/proc/$BASHPID/fdinfo/$sealed_snapshot_fd")" || return 1
  [[ "$snapshot_descriptor_identity" == "$snapshot_identity" &&
    "$sealed_snapshot_flags" =~ ^[0-7]+$ &&
    $((8#$sealed_snapshot_flags & 3)) == 0 &&
    "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$snapshot")" == \
      "$snapshot_identity" ]] || return 1
  digest="$(sha256_open_fd "$sealed_snapshot_fd")" || return 1
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  failure_classification_checkpoint after-snapshot-seal "$path" "$source_fd" \
    "$snapshot" "$sealed_snapshot_fd" || return 1
  exec {source_fd}<&- || return 1
  printf -v "$output_path_name" '%s' "$snapshot"
  printf -v "$output_fd_name" '%s' "$sealed_snapshot_fd"
  printf -v "$output_identity_name" '%s' "$snapshot_identity"
  printf -v "$output_digest_name" '%s' "$digest"
}

assert_verified_input_fd_unchanged() {
  local -r path="$1"
  local -r descriptor="$2"
  local -r expected_identity="$3"
  local -r expected_digest="$4"
  local descriptor_identity=""
  local path_identity=""
  local descriptor_digest=""

  [[ "$descriptor" =~ ^[0-9]+$ && "$expected_identity" == *:* &&
    "$expected_digest" =~ ^[0-9a-f]{64}$ && -f "$path" && ! -L "$path" &&
    "$(readlink -f -- "$path")" == "$path" ]] || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "/proc/$BASHPID/fd/$descriptor")" || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" || return 1
  descriptor_digest="$(sha256_open_fd "$descriptor")" || return 1
  [[ "$descriptor_identity" == "$expected_identity" &&
    "$path_identity" == "$expected_identity" &&
    "$descriptor_digest" == "$expected_digest" ]]
}

open_exclusive_output_fd() {
  local -r directory_fd="$1"
  local -r leaf="$2"
  local -r output_name="$3"
  local opened_fd=""
  local open_status=0
  local restore_noclobber=false

  [[ "$directory_fd" =~ ^[0-9]+$ &&
    "$leaf" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
    "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    -d "/proc/$BASHPID/fd/$directory_fd" ]] || return 1
  if [[ $- != *C* ]]; then
    set -o noclobber
    restore_noclobber=true
  fi
  if exec {opened_fd}>"/proc/$BASHPID/fd/$directory_fd/$leaf"; then
    open_status=0
  else
    open_status=$?
  fi
  if [[ "$restore_noclobber" == true ]]; then
    set +o noclobber
  fi
  (( open_status == 0 )) || return "$open_status"
  printf -v "$output_name" '%s' "$opened_fd"
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

  LAST_RECORDED_COMMAND_ID=""
  LAST_RECORDED_COMMAND_EXIT_STATUS=""
  LAST_RECORDED_COMMAND_VALIDATED=false

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
  recorded_log_preopen_checkpoint "$log" "$log_name" || {
    exec {command_directory_fd}<&-
    return 1
  }
  open_exclusive_output_fd "$command_directory_fd" "$log_name" log_fd || {
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
  LAST_RECORDED_COMMAND_ID="$command_id"
  LAST_RECORDED_COMMAND_EXIT_STATUS="$command_status"
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
  LAST_RECORDED_COMMAND_VALIDATED=true
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

result_snapshot_checkpoint() {
  : "$@"
}

snapshot_result_names() {
  local -r output="$1"
  local -r results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local owner=""
  local mode=""
  local root_identity=""
  local root_descriptor_identity=""
  local root_post_identity=""
  local results_root_fd=""
  local snapshot_fd=""
  local snapshot_identity=""
  local snapshot_path_identity=""
  local snapshot_status=0
  local close_status=0

  [[ "$output" == "$PRIVATE_DIRECTORY/"* && ! -e "$output" &&
    ! -L "$output" ]] || return 1
  open_exclusive_output_fd "$PRIVATE_DIRECTORY_FD" "${output##*/}" \
    snapshot_fd || return 1
  chmod 0600 -- "/proc/$BASHPID/fd/$snapshot_fd" || return 1
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
    exec {results_root_fd}<"$results_root" || return $?
    root_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$results_root_fd")" || snapshot_status=1
    [[ "$root_descriptor_identity" == "$root_identity" ]] || snapshot_status=1
    result_snapshot_checkpoint before-find "$results_root" "$results_root_fd" ||
      snapshot_status=1
    root_post_identity="$(stat -Lc '%d:%i:%u:%a' -- "$results_root")" ||
      snapshot_status=1
    [[ "$root_post_identity" == "$root_identity" ]] || snapshot_status=1
    find -H "/proc/$BASHPID/fd/$results_root_fd" -mindepth 1 -maxdepth 1 \
      -printf '%f\t%y:%D:%i:%U:%m\n' | LC_ALL=C sort \
      >&"$snapshot_fd" || snapshot_status=$?
    root_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$results_root_fd")" || snapshot_status=1
    root_post_identity="$(stat -Lc '%d:%i:%u:%a' -- "$results_root")" ||
      snapshot_status=1
    [[ "$root_descriptor_identity" == "$root_identity" &&
      "$root_post_identity" == "$root_identity" ]] || snapshot_status=1
    exec {results_root_fd}<&- || close_status=$?
  fi
  snapshot_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$snapshot_fd")" || snapshot_status=1
  snapshot_path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$output")" ||
    snapshot_status=1
  exec {snapshot_fd}>&- || close_status=$?
  (( snapshot_status == 0 && close_status == 0 )) || return 1
  [[ "$snapshot_identity" == "$snapshot_path_identity" &&
    "$snapshot_identity" == *":$EUID:600:1" ]] || return 1
  seal_result_snapshot "$output"
}

metric_capture_lock_matches_snapshot() {
  local -r results_root="$1"
  local -r snapshot_identity="$2"
  local -r lock="$results_root/.obi-metric-capture.lock"
  local lock_fd=""
  local results_root_fd=""
  local root_identity=""
  local root_descriptor_identity=""
  local root_post_identity=""
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
  root_identity="$(stat -Lc '%d:%i:%u:%a' -- "$results_root")" || return 1
  [[ -n "$RESULTS_ROOT_IDENTITY" &&
    "$root_identity" == "$RESULTS_ROOT_IDENTITY" ]] || return 1
  exec {results_root_fd}<"$results_root" || return $?
  root_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$results_root_fd")" || root_descriptor_identity=""
  [[ "$root_descriptor_identity" == "$root_identity" ]] || {
    exec {results_root_fd}<&-
    return 1
  }
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock")" || return 1
  [[ "${path_identity%:*}" == "$snapshot_identity" &&
    "$path_identity" == *":$EUID:600:1" ]] || return 1
  exec {lock_fd}<"/proc/$BASHPID/fd/$results_root_fd/.obi-metric-capture.lock" ||
    return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$lock_fd")" || descriptor_identity=""
  if [[ "$descriptor_identity" == "$path_identity" ]] &&
    flock -n "$lock_fd"; then
    lock_acquired=true
    flock -u "$lock_fd" || unlock_status=$?
  fi
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock")" ||
    post_identity=""
  root_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$results_root_fd")" || root_descriptor_identity=""
  root_post_identity="$(stat -Lc '%d:%i:%u:%a' -- "$results_root")" ||
    root_post_identity=""
  exec {lock_fd}<&- || return $?
  exec {results_root_fd}<&- || return $?
  [[ "$lock_acquired" == true && "$unlock_status" == 0 &&
    -f "$lock" && ! -L "$lock" &&
    "$(realpath -e -- "$lock")" == "$lock" &&
    "$root_descriptor_identity" == "$root_identity" &&
    "$root_post_identity" == "$root_identity" &&
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

is_allowed_acceptance_failure_stage() {
  local -r candidate="$1"
  local allowed=""

  for allowed in "${ACCEPTANCE_FAILURE_STAGES[@]}"; do
    [[ "$candidate" == "$allowed" ]] && return 0
  done
  return 1
}

read_failure_environment_value() {
  local -r descriptor="$1"
  local -r key="$2"
  local -r output_name="$3"
  local -a values=()

  [[ "$descriptor" =~ ^[0-9]+$ &&
    "$key" =~ ^[a-z][a-z0-9_]{0,63}$ &&
    "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  mapfile -t values < <(awk -F= -v wanted="$key" '$1 == wanted {
    print substr($0, length($1) + 2)
  }' "/proc/$BASHPID/fd/$descriptor")
  (( ${#values[@]} == 1 )) || return 1
  printf -v "$output_name" '%s' "${values[0]}"
}

validate_failure_environment_fd() {
  local -r descriptor="$1"
  local revision=""
  local dirty=""
  local source_tree=""
  local transport=""
  local agent=""
  local tls=""
  local scenario=""
  local request_count=""
  local repeat_count=""
  local scenario_seed=""
  local build_mode=""
  local acceptance=""
  local acceptance_reason=""
  local architecture=""

  read_failure_environment_value "$descriptor" revision revision || return 1
  read_failure_environment_value "$descriptor" dirty dirty || return 1
  read_failure_environment_value "$descriptor" source_tree_sha256 \
    source_tree || return 1
  read_failure_environment_value "$descriptor" transport transport || return 1
  read_failure_environment_value "$descriptor" agent_distribution agent ||
    return 1
  read_failure_environment_value "$descriptor" tls_protocol tls || return 1
  read_failure_environment_value "$descriptor" scenario scenario || return 1
  read_failure_environment_value "$descriptor" request_count request_count ||
    return 1
  read_failure_environment_value "$descriptor" repeat_count repeat_count ||
    return 1
  read_failure_environment_value "$descriptor" scenario_seed scenario_seed ||
    return 1
  read_failure_environment_value "$descriptor" bridge_build_mode build_mode ||
    return 1
  read_failure_environment_value "$descriptor" acceptance_evidence acceptance ||
    return 1
  read_failure_environment_value "$descriptor" acceptance_evidence_reason \
    acceptance_reason || return 1
  read_failure_environment_value "$descriptor" architecture architecture ||
    return 1
  [[ "$revision" == "$SOURCE_REVISION" && "$dirty" == false &&
    "$source_tree" =~ ^[0-9a-f]{64}$ && "$transport" == getsockopt &&
    "$agent" == otel && "$tls" == TLSv1.3 && "$scenario" == all &&
    "$request_count" == 0 && "$repeat_count" == 1 &&
    "$scenario_seed" == 1 && "$build_mode" == fresh &&
    "$acceptance" == true && "$acceptance_reason" == none &&
    "$architecture" == "$ARCHITECTURE" ]]
}

acceptance_boundary_ids_json() {
  printf '%s\n' "${ACCEPTANCE_BOUNDARY_IDS[@]}" |
    jq -Rsc 'split("\n") | map(select(length > 0))'
}

validate_failure_boundary_index_fd() {
  local -r descriptor="$1"
  local -r output_count_name="$2"
  local -r output_first_name="$3"
  local -r output_active_name="$4"
  local expected_ids=""
  local summary=""
  local observed_terminal_count=""
  local observed_first_incomplete=""
  local observed_active_boundary=""

  [[ "$descriptor" =~ ^[0-9]+$ &&
    "$output_count_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_first_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_active_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  expected_ids="$(acceptance_boundary_ids_json)" || return 1
  cmp -s -- "/proc/$BASHPID/fd/$descriptor" \
    <(jq -cS . "/proc/$BASHPID/fd/$descriptor") || return 1
  summary="$(jq -ceS --argjson ids "$expected_ids" '
    def terminal: . == "complete" or . == "not_applicable";
    if (keys == ["boundaries", "schema", "selection"] and
    .schema == "obi-metric-boundary-index-v1" and
    (.selection | keys == [
      "repeat_count", "requested_transport", "scenario", "selected_transport"
    ]) and
    .selection.scenario == "all" and
    .selection.requested_transport == "getsockopt" and
    (.selection.selected_transport == null or
      .selection.selected_transport == "getsockopt") and
    .selection.repeat_count == 1 and
    (.boundaries | type == "array" and length == ($ids | length)) and
    [.boundaries[].id] == $ids and
    [.boundaries[].ordinal] == [range(1; ($ids | length) + 1)] and
    ([.boundaries[].captures[] |
      select(.kind == "pair" and .state == "captured") |
      .pair_reference] | length == (unique | length)) and
    ([.boundaries[] | select(.state == "active")] | length) <= 1 and
    all(.boundaries[];
      keys == [
        "captures", "id", "not_applicable_reason", "ordinal", "state",
        "status_references"
      ] and
      (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$")) and
      (.ordinal | type == "number" and floor == . and . >= 1) and
      (.captures | type == "array") and
      (.status_references | type == "array") and
      ([.captures[].id] | length == (unique | length)) and
      ([.status_references[].reference] | length == (unique | length)) and
      (.state == "planned" or .state == "active" or
        .state == "complete" or .state == "not_applicable") and
      (if .state == "planned" then
        .captures == [] and .status_references == [] and
        .not_applicable_reason == null
      elif .state == "active" then
        .not_applicable_reason == null
      elif .state == "complete" then
        (.captures | length) > 0 and
        all(.captures[]; .state == "captured") and
        (any(.captures[]; .kind == "pair") or
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
          keys == [
            "id", "identity_reference", "identity_sha256", "kind", "state"
          ] and
          (.identity_reference | type == "string" and
            test("^phases/[a-z0-9][a-z0-9-]{0,63}/obi-identity\\.json$")) and
          (.identity_sha256 | type == "string" and
            test("^[0-9a-f]{64}$"))) or
        (.kind == "java" and .state == "captured" and
          keys == ["id", "kind", "reference", "sha256", "state"] and
          (.reference | type == "string" and
            test("^phases/[a-z0-9][a-z0-9-]{0,63}/java-diagnostics\\.txt$")) and
          (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
        (.kind == "artifact" and .state == "captured" and
          keys == ["id", "kind", "reference", "sha256", "state"] and
          (.reference | type == "string" and
            test("^[a-z0-9][a-z0-9._-]{0,127}$")) and
          (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
        (.kind == "unavailable" and .state == "captured" and
          keys == [
            "id", "kind", "reason", "reference", "sha256", "state"
          ] and .reason == "obi_process_not_running" and
          (.reference | type == "string" and
            test("^phases/[a-z0-9][a-z0-9-]{0,63}/obi-metrics\\.prom$")) and
          (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))) or
        (.kind == "pair" and
          keys == [
            "id", "java_reference", "java_sha256", "kind", "pair_reference",
            "pair_sha256", "state"
          ] and
          (.state == "planned" or .state == "captured") and
          (.id | type == "string" and
            test("^[a-z0-9][a-z0-9-]{0,63}$")) and
          (if .state == "planned" then
            .pair_reference == null and .pair_sha256 == null and
            .java_reference == null and .java_sha256 == null
          else
            .pair_reference == ("obi-metric-pairs/" + .id + ".json") and
            (.pair_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
            ((.java_reference == null and .java_sha256 == null) or
              ((.java_reference | type == "string" and
                test("^phases/[a-z0-9][a-z0-9-]{0,63}/java-diagnostics\\.txt$")) and
                (.java_sha256 | type == "string" and
                  test("^[0-9a-f]{64}$"))))
          end))) and
        (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$"))) and
      ([.captures[] | select(.kind == "pair") | .state] as $pair_states |
        all(range(0; $pair_states | length); . as $pair_index |
          if $pair_states[$pair_index] == "planned" then
            all(range($pair_index + 1; $pair_states | length); . as $later |
              $pair_states[$later] == "planned")
          else true end))) and
    ([.boundaries[].state] as $states |
      all(range(0; $states | length); . as $index |
        if ($states[$index] | terminal) then
          all(range(0; $index); . as $prior | ($states[$prior] | terminal))
        elif $states[$index] == "active" then
          all(range(0; $index); . as $prior | ($states[$prior] | terminal)) and
          all(range($index + 1; $states | length); . as $later |
            $states[$later] == "planned")
        else
          all(range($index + 1; $states | length); . as $later |
            $states[$later] == "planned")
        end)))
    then
    ([.boundaries[] | select(.state | terminal)] | length) as $terminal_count |
    ([.boundaries[] | select((.state | terminal) | not) | .id] | first // null)
      as $first |
    ([.boundaries[] | select(.state == "active") | .id] | first // null)
      as $active |
    {
      active_boundary: $active,
      first_incomplete_boundary: $first,
      terminal_boundary_count: $terminal_count
    }
    else error("invalid failure boundary index") end
  ' "/proc/$BASHPID/fd/$descriptor")" || return 1
  observed_terminal_count="$(jq -er '.terminal_boundary_count' \
    <<<"$summary")" || return 1
  observed_first_incomplete="$(jq -r '.first_incomplete_boundary // ""' \
    <<<"$summary")" || return 1
  observed_active_boundary="$(jq -r '.active_boundary // ""' \
    <<<"$summary")" || return 1
  [[ "$observed_terminal_count" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  (( observed_terminal_count <= ${#ACCEPTANCE_BOUNDARY_IDS[@]} )) || return 1
  if [[ -n "$observed_first_incomplete" ]]; then
    local allowed=false
    local boundary=""
    for boundary in "${ACCEPTANCE_BOUNDARY_IDS[@]}"; do
      if [[ "$observed_first_incomplete" == "$boundary" ]]; then
        allowed=true
        break
      fi
    done
    [[ "$allowed" == true ]] || return 1
  fi
  if [[ -n "$observed_active_boundary" ]]; then
    [[ "$observed_active_boundary" == "$observed_first_incomplete" ]] ||
      return 1
  fi
  printf -v "$output_count_name" '%s' "$observed_terminal_count"
  printf -v "$output_first_name" '%s' "$observed_first_incomplete"
  printf -v "$output_active_name" '%s' "$observed_active_boundary"
}

failure_expected_java_link_json() {
  local -r index_descriptor="$1"

  [[ "$index_descriptor" =~ ^[0-9]+$ ]] || return 1
  jq -ceS '
    [.boundaries[] | select(.state == "active")] as $active |
    if ($active | length) == 0 then
      [.boundaries[].captures[] |
        if .kind == "java" and .state == "captured" then
          {reference: .reference, sha256: .sha256}
        elif .kind == "pair" and .state == "captured" and
          .java_reference != null then
          {reference: .java_reference, sha256: .java_sha256}
        else empty end] as $java |
      if ($java | length) == 0 then {reference: null, sha256: null}
      else $java[-1] end
    else
      $active[0].captures as $captures |
      [$captures | to_entries[] | select(.value.kind == "pair")] as $pairs |
      if ($pairs | length) == 0 then
        [$captures[] | select(.kind == "java" and .state == "captured")] as $java |
        if ($java | length) == 0 then {reference: null, sha256: null}
        else {reference: $java[-1].reference, sha256: $java[-1].sha256} end
      elif $pairs[-1].value.state == "captured" then
        {
          reference: $pairs[-1].value.java_reference,
          sha256: $pairs[-1].value.java_sha256
        }
      else
        $pairs[-1].key as $pair_index |
        [$captures | to_entries[] |
          select(.key > $pair_index and .value.kind == "java" and
            .value.state == "captured") | .value] as $java |
        if ($java | length) == 0 then {reference: null, sha256: null}
        else {reference: $java[-1].reference, sha256: $java[-1].sha256} end
      end
    end
  ' "/proc/$BASHPID/fd/$index_descriptor"
}

validate_failure_java_terminal_fd() {
  local -r descriptor="$1"
  local -r index_descriptor="$2"
  local expected=""
  local expected_reference=""
  local expected_digest=""
  local phase=""
  local counter_names=""
  local snapshot_digest=""

  [[ "$descriptor" =~ ^[0-9]+$ && "$index_descriptor" =~ ^[0-9]+$ ]] ||
    return 1
  cmp -s -- "/proc/$BASHPID/fd/$descriptor" \
    <(jq -cS . "/proc/$BASHPID/fd/$descriptor") || return 1
  expected="$(failure_expected_java_link_json "$index_descriptor")" ||
    return 1
  expected_reference="$(jq -r '.reference // ""' <<<"$expected")" || return 1
  expected_digest="$(jq -r '.sha256 // ""' <<<"$expected")" || return 1
  if [[ -z "$expected_reference" ]]; then
    [[ -z "$expected_digest" ]] || return 1
    jq -e '
      keys == ["available", "reason", "schema", "sealed"] and
      .schema == "obi-java-bridge-terminal-diagnostics-v1" and
      .sealed == true and .available == false and
      .reason == "no-valid-snapshot-before-terminal-boundary"
    ' "/proc/$BASHPID/fd/$descriptor" >/dev/null
    return
  fi
  [[ "$expected_reference" =~ \
    ^phases/([a-z0-9][a-z0-9-]{0,63})/java-diagnostics\.txt$ ]] || return 1
  phase="${BASH_REMATCH[1]}"
  [[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  counter_names="$(printf '%s\n' \
    "${ACCEPTANCE_JAVA_DIAGNOSTIC_COUNTER_NAMES[@]}" |
    jq -Rsc 'split("\n")[:-1]')" || return 1
  jq -e --arg reference "$expected_reference" --arg phase "$phase" \
    --argjson counter_names "$counter_names" '
    def base36:
      reduce (explode[]) as $code
        (0;
          . * 36 +
          (if $code >= 48 and $code <= 57 then $code - 48
           elif $code >= 97 and $code <= 122 then $code - 87
           else error("invalid base36 digit")
           end));
    def entry_pattern:
      "\\A(?<name>[a-z_]+)=(?<value>0|[1-9a-z][0-9a-z]{0,5})\\z";
    . as $terminal |
    keys == [
        "available", "counters", "phase", "reference", "schema", "sealed",
        "snapshot"
      ] and
      .schema == "obi-java-bridge-terminal-diagnostics-v1" and
      .sealed == true and .available == true and
      .phase == $phase and .reference == $reference and
      (.snapshot | type == "string" and utf8bytelength <= 16384) and
      (.counters | type == "object") and
      ($terminal.snapshot | split(",")) as $entries |
      ($entries | length) == ($counter_names | length) and
      all(range(0; $counter_names | length);
        ($entries[.] | test(entry_pattern)) and
        (($entries[.] | capture(entry_pattern)) as $entry |
          $entry.name == $counter_names[.] and
          (($entry.value | base36) < 999999999))) and
      $terminal.counters ==
        ($entries |
          map(capture(entry_pattern) | {(.name): .value}) |
          add)
  ' "/proc/$BASHPID/fd/$descriptor" >/dev/null || return 1
  # The decoded snapshot can contain arbitrary bytes.  Stream it directly
  # from the immutable JSON descriptor into the digest; never place it in a
  # shell variable, where Bash would discard embedded NUL bytes.
  snapshot_digest="$(
    jq -jre '.snapshot + "\n"' "/proc/$BASHPID/fd/$descriptor" |
      sha256sum
  )" || return 1
  snapshot_digest="${snapshot_digest%% *}"
  [[ "$snapshot_digest" =~ ^[0-9a-f]{64}$ &&
    "$snapshot_digest" == "$expected_digest" ]]
}

failure_expected_obi_link_json() {
  local -r index_descriptor="$1"

  [[ "$index_descriptor" =~ ^[0-9]+$ ]] || return 1
  jq -ceS '
    [.boundaries[] | select(.state == "active")] as $active |
    if ($active | length) == 0 then
      {active_boundary: null, pair_reference: null, pair_sha256: null}
    else
      [$active[0].captures[] | select(.kind == "pair")] as $pairs |
      if ($pairs | length) > 0 and $pairs[-1].state == "captured" then
        {
          active_boundary: $active[0].id,
          pair_reference: $pairs[-1].pair_reference,
          pair_sha256: $pairs[-1].pair_sha256
        }
      else
        {
          active_boundary: $active[0].id,
          pair_reference: null,
          pair_sha256: null
        }
      end
    end
  ' "/proc/$BASHPID/fd/$index_descriptor"
}

validate_failure_obi_terminal_fd() {
  local -r descriptor="$1"
  local -r index_digest="$2"
  local -r index_descriptor="$3"
  local expected=""
  local active_boundary=""
  local pair_reference=""
  local pair_digest=""
  local observed_pair=""
  local observed_pair_digest=""

  [[ "$descriptor" =~ ^[0-9]+$ && "$index_digest" =~ ^[0-9a-f]{64}$ &&
    "$index_descriptor" =~ ^[0-9]+$ ]] || return 1
  cmp -s -- "/proc/$BASHPID/fd/$descriptor" \
    <(jq -cS . "/proc/$BASHPID/fd/$descriptor") || return 1
  expected="$(failure_expected_obi_link_json "$index_descriptor")" || return 1
  active_boundary="$(jq -r '.active_boundary // ""' <<<"$expected")" ||
    return 1
  pair_reference="$(jq -r '.pair_reference // ""' <<<"$expected")" ||
    return 1
  pair_digest="$(jq -r '.pair_sha256 // ""' <<<"$expected")" || return 1
  if [[ -z "$active_boundary" ]]; then
    [[ -z "$pair_reference" && -z "$pair_digest" ]] || return 1
    jq -e --arg index_digest "$index_digest" '
      keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "reason", "schema", "sealed"
      ] and
      .schema == "obi-java-remote-parent-terminal-metrics-v2" and
      .sealed == true and .available == false and
      .active_boundary_id == null and .reason == "no-active-boundary" and
      .boundary_index_reference == "obi-metric-boundary-index.json" and
      .boundary_index_sha256 == $index_digest
    ' "/proc/$BASHPID/fd/$descriptor" >/dev/null
    return
  fi
  [[ "$active_boundary" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  if [[ -z "$pair_reference" ]]; then
    [[ -z "$pair_digest" ]] || return 1
    jq -e --arg index_digest "$index_digest" \
      --arg active_boundary "$active_boundary" '
      keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "reason", "schema", "sealed"
      ] and
      .schema == "obi-java-remote-parent-terminal-metrics-v2" and
      .sealed == true and .available == false and
      .active_boundary_id == $active_boundary and
      .reason == "active-boundary-incomplete" and
      .boundary_index_reference == "obi-metric-boundary-index.json" and
      .boundary_index_sha256 == $index_digest
    ' "/proc/$BASHPID/fd/$descriptor" >/dev/null
    return
  fi
  [[ "$pair_reference" =~ \
      ^obi-metric-pairs/[a-z0-9][a-z0-9-]{0,63}\.json$ &&
    "$pair_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  jq -e --arg index_digest "$index_digest" \
    --arg active_boundary "$active_boundary" \
    --arg pair_reference "$pair_reference" '
    keys == [
        "active_boundary_id", "available", "boundary_index_reference",
        "boundary_index_sha256", "pair", "pair_reference", "schema", "sealed"
      ] and
      .schema == "obi-java-remote-parent-terminal-metrics-v2" and
      .sealed == true and .available == true and
      .active_boundary_id == $active_boundary and
      .boundary_index_reference == "obi-metric-boundary-index.json" and
      .boundary_index_sha256 == $index_digest and
      .pair_reference == $pair_reference and
      (.pair | type == "object")
  ' "/proc/$BASHPID/fd/$descriptor" >/dev/null || return 1
  observed_pair="$(jq -cS '.pair' "/proc/$BASHPID/fd/$descriptor")" || return 1
  observed_pair_digest="$(printf '%s\n' "$observed_pair" | sha256sum)" ||
    return 1
  observed_pair_digest="${observed_pair_digest%% *}"
  [[ "$observed_pair_digest" == "$pair_digest" ]]
}

failure_classification_assert_not_mountpoint() {
  local -r path="$1"
  local status=0

  if failure_classification_path_is_mountpoint "$path"; then
    return 1
  else
    status=$?
  fi
  (( status == 1 ))
}

assert_failure_result_topology_unchanged() {
  local -r results_root="$1"
  local -r results_root_fd="$2"
  local -r results_root_identity="$3"
  local -r result="$4"
  local -r result_fd="$5"
  local -r result_identity="$6"
  local result_parent_identity=""
  local results_root_mount_id=""
  local result_mount_id=""

  [[ "$results_root_fd" =~ ^[0-9]+$ && "$result_fd" =~ ^[0-9]+$ &&
    "$results_root_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    "$result_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:755$ &&
    "${results_root_identity%%:*}" == "${CHECKOUT_IDENTITY%%:*}" &&
    "${result_identity%%:*}" == "${results_root_identity%%:*}" &&
    -d "$results_root" && ! -L "$results_root" &&
    "$(readlink -f -- "$results_root")" == "$results_root" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$results_root")" == \
      "$results_root_identity" &&
    "$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$results_root_fd")" == "$results_root_identity" &&
    -d "$result" && ! -L "$result" &&
    "$(readlink -f -- "$result")" == "$result" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$result")" == "$result_identity" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "/proc/$BASHPID/fd/$result_fd")" == \
      "$result_identity" ]] || return 1
  result_parent_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$result_fd/..")" || return 1
  failure_classification_fd_mount_id "$results_root_fd" \
    results_root_mount_id || return 1
  failure_classification_fd_mount_id "$result_fd" result_mount_id || return 1
  [[ "$result_parent_identity" == "$results_root_identity" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$result/..")" == \
      "$results_root_identity" &&
    "$result_mount_id" == "$results_root_mount_id" ]] || return 1
  failure_classification_assert_not_mountpoint "$results_root" || return 1
  failure_classification_assert_not_mountpoint "$result"
}

validate_acceptance_failure_result_details() {
  local -r result="$1"
  local -r expected_result_identity="$2"
  local -r expected_exit_status="$3"
  local -r results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local result_name=""
  local results_root_fd=""
  local results_root_identity=""
  local result_fd=""
  local result_identity=""
  local result_descriptor_identity=""
  local snapshot_directory=""
  local snapshot_directory_fd=""
  local snapshot_directory_identity=""
  local environment_snapshot=""
  local environment_fd=""
  local environment_identity=""
  local environment_digest=""
  local index_snapshot=""
  local index_fd=""
  local index_identity=""
  local index_digest=""
  local freeze_snapshot=""
  local freeze_fd=""
  local freeze_identity=""
  local freeze_digest=""
  local java_snapshot=""
  local java_fd=""
  local java_identity=""
  local java_digest=""
  local obi_snapshot=""
  local obi_fd=""
  local obi_identity=""
  local obi_digest=""
  local status_snapshot=""
  local status_fd=""
  local status_identity=""
  local status_digest=""
  local terminal_count=""
  local first_incomplete=""
  local active_boundary=""
  local failure_stage=""
  local failure_line=""
  local maximum_source_line=""
  local expected_freeze=""

  [[ "$expected_exit_status" =~ ^[1-9][0-9]{0,2}$ ]] || return 1
  (( expected_exit_status <= 255 )) || return 1
  verify_exact_checkout || return 1
  [[ "$result" == \
      "$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results/"* &&
    "$expected_result_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:755$ &&
    -n "$RESULTS_ROOT_IDENTITY" &&
    -d "$result" && ! -L "$result" &&
    "$(CDPATH='' cd -- "$result" && pwd -P)" == "$result" ]] || return 1
  result_name="${result##*/}"
  [[ "$result" == "$results_root/$result_name" &&
    "$result_name" =~ ^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$ &&
    -d "$results_root" && ! -L "$results_root" &&
    "$(readlink -f -- "$results_root")" == "$results_root" ]] || return 1
  results_root_identity="$(stat -Lc '%d:%i:%u:%a' -- "$results_root")" ||
    return 1
  [[ "$results_root_identity" == "$RESULTS_ROOT_IDENTITY" &&
    "${results_root_identity%%:*}" == "${CHECKOUT_IDENTITY%%:*}" ]] || return 1
  exec {results_root_fd}<"$results_root" || return $?
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "/proc/$BASHPID/fd/$results_root_fd")" == \
    "$results_root_identity" ]] || return 1
  result_identity="$(stat -Lc '%d:%i:%u:%a' -- "$result")" || return 1
  [[ "$result_identity" == "$expected_result_identity" &&
    "$result_identity" == *":$EUID:755" &&
    "${result_identity%%:*}" == "${results_root_identity%%:*}" ]] || return 1
  exec {result_fd}<"/proc/$BASHPID/fd/$results_root_fd/$result_name" ||
    return $?
  result_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$result_fd")" || return 1
  [[ "$result_descriptor_identity" == "$result_identity" ]] || return 1
  failure_classification_checkpoint after-result-open "$result" "$result_fd" \
    "$results_root" "$results_root_fd" || return 1
  assert_failure_result_topology_unchanged "$results_root" "$results_root_fd" \
    "$results_root_identity" "$result" "$result_fd" "$result_identity" ||
    return 1
  create_failure_classification_snapshot_directory snapshot_directory \
    snapshot_directory_fd snapshot_directory_identity || return 1

  open_bounded_failure_input_snapshot "$result" "$result_fd" \
    "$result_identity" environment.txt 644 "$MAX_ENVIRONMENT_BYTES" \
    "$snapshot_directory" "$snapshot_directory_fd" environment.txt \
    environment_snapshot environment_fd environment_identity \
    environment_digest || return 1
  validate_failure_environment_fd "$environment_fd" || return 1

  open_bounded_failure_input_snapshot "$result" "$result_fd" \
    "$result_identity" obi-metric-boundary-index.json 644 \
    "$MAX_FAILURE_BOUNDARY_INDEX_BYTES" "$snapshot_directory" \
    "$snapshot_directory_fd" boundary-index.json index_snapshot index_fd \
    index_identity index_digest || return 1
  validate_failure_boundary_index_fd "$index_fd" terminal_count \
    first_incomplete active_boundary || return 1
  [[ -z "$active_boundary" || "$active_boundary" == "$first_incomplete" ]] ||
    return 1
  open_bounded_failure_input_snapshot "$result" "$result_fd" \
    "$result_identity" .obi-metric-boundary-index.freeze 600 \
    "$MAX_FAILURE_FREEZE_BYTES" "$snapshot_directory" \
    "$snapshot_directory_fd" boundary-index.freeze freeze_snapshot freeze_fd \
    freeze_identity freeze_digest || return 1
  expected_freeze="obi-metric-boundary-index-frozen-v1:$index_digest"
  cmp -s -- "/proc/$BASHPID/fd/$freeze_fd" \
    <(printf '%s\n' "$expected_freeze") || return 1

  open_bounded_failure_input_snapshot "$result" "$result_fd" \
    "$result_identity" terminal-java-diagnostics.json 644 \
    "$MAX_FAILURE_JAVA_TERMINAL_BYTES" "$snapshot_directory" \
    "$snapshot_directory_fd" terminal-java.json java_snapshot java_fd \
    java_identity java_digest || return 1
  validate_failure_java_terminal_fd "$java_fd" "$index_fd" || return 1
  open_bounded_failure_input_snapshot "$result" "$result_fd" \
    "$result_identity" terminal-obi-metrics.json 644 \
    "$MAX_FAILURE_OBI_TERMINAL_BYTES" "$snapshot_directory" \
    "$snapshot_directory_fd" terminal-obi.json obi_snapshot obi_fd \
    obi_identity obi_digest || return 1
  validate_failure_obi_terminal_fd "$obi_fd" "$index_digest" "$index_fd" ||
    return 1

  open_bounded_failure_input_snapshot "$result" "$result_fd" \
    "$result_identity" run-status.json 644 "$MAX_RUN_STATUS_BYTES" \
    "$snapshot_directory" "$snapshot_directory_fd" run-status.json \
    status_snapshot status_fd status_identity status_digest || return 1
  # run.sh writes this object with jq's deterministic pretty printer.  An
  # exact re-render rejects duplicate keys and alternate tokenizations before
  # any field is trusted, while preserving the producer's v3 byte contract.
  cmp -s -- "/proc/$BASHPID/fd/$status_fd" \
    <(jq . "/proc/$BASHPID/fd/$status_fd") || return 1
  jq -e --arg result "$result" --arg index_digest "$index_digest" \
    --argjson expected_exit "$expected_exit_status" \
    --slurpfile java "/proc/$BASHPID/fd/$java_fd" \
    --slurpfile obi "/proc/$BASHPID/fd/$obi_fd" '
    keys == [
      "acceptance_evidence", "acceptance_evidence_reason", "evidence_directory",
      "exit_status", "failure_line", "failure_stage", "java_bridge_diagnostics",
      "java_bridge_diagnostics_reference", "obi_metric_boundary_index_reference",
      "obi_metric_boundary_index_sha256", "obi_metric_evidence",
      "obi_metric_evidence_reference", "schema", "status"
    ] and
    .schema == "obi-apache-java-https-run-status-v3" and
    .status == "failed" and .exit_status == $expected_exit and
    .acceptance_evidence == true and .acceptance_evidence_reason == "none" and
    .evidence_directory == $result and
    (.failure_stage | type == "string" and length >= 1 and length <= 64) and
    (.failure_line | type == "number" and floor == . and . >= 0) and
    .java_bridge_diagnostics_reference == "terminal-java-diagnostics.json" and
    ($java | length) == 1 and .java_bridge_diagnostics == $java[0] and
    .obi_metric_evidence_reference == "terminal-obi-metrics.json" and
    ($obi | length) == 1 and .obi_metric_evidence == $obi[0] and
    .obi_metric_boundary_index_reference == "obi-metric-boundary-index.json" and
    .obi_metric_boundary_index_sha256 == $index_digest
  ' "/proc/$BASHPID/fd/$status_fd" >/dev/null || return 1
  failure_stage="$(jq -er '.failure_stage' \
    "/proc/$BASHPID/fd/$status_fd")" || return 1
  is_allowed_acceptance_failure_stage "$failure_stage" || return 1
  failure_line="$(jq -er '.failure_line' \
    "/proc/$BASHPID/fd/$status_fd")" || return 1
  maximum_source_line="$(wc -l <"$CHECKOUT_DIRECTORY/examples/apache-java-https/run.sh")" ||
    return 1
  [[ "$maximum_source_line" =~ ^[1-9][0-9]{0,8}$ &&
    "$failure_line" =~ ^(0|[1-9][0-9]{0,8})$ ]] || return 1
  (( failure_line <= maximum_source_line )) || return 1

  assert_verified_input_fd_unchanged "$environment_snapshot" "$environment_fd" \
    "$environment_identity" "$environment_digest" || return 1
  assert_verified_input_fd_unchanged "$index_snapshot" "$index_fd" \
    "$index_identity" "$index_digest" || return 1
  assert_verified_input_fd_unchanged "$freeze_snapshot" "$freeze_fd" \
    "$freeze_identity" "$freeze_digest" || return 1
  assert_verified_input_fd_unchanged "$java_snapshot" "$java_fd" \
    "$java_identity" "$java_digest" || return 1
  assert_verified_input_fd_unchanged "$obi_snapshot" "$obi_fd" \
    "$obi_identity" "$obi_digest" || return 1
  assert_verified_input_fd_unchanged "$status_snapshot" "$status_fd" \
    "$status_identity" "$status_digest" || return 1
  verify_exact_checkout || return 1
  assert_failure_result_topology_unchanged "$results_root" "$results_root_fd" \
    "$results_root_identity" "$result" "$result_fd" "$result_identity" ||
    return 1
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "$snapshot_directory")" == \
      "$snapshot_directory_identity" &&
    "$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$snapshot_directory_fd")" == \
      "$snapshot_directory_identity" &&
    "$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$snapshot_directory_fd/..")" == \
      "$PRIVATE_IDENTITY" ]] || return 1
  exec {status_fd}<&- || return 1
  exec {obi_fd}<&- || return 1
  exec {java_fd}<&- || return 1
  exec {freeze_fd}<&- || return 1
  exec {index_fd}<&- || return 1
  exec {environment_fd}<&- || return 1
  exec {snapshot_directory_fd}<&- || return 1
  exec {result_fd}<&- || return 1
  exec {results_root_fd}<&- || return 1
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$failure_stage" "$failure_line" "$terminal_count" \
    "${first_incomplete:-__none__}" "$java_digest" "$obi_digest" \
    "$index_digest" "$status_digest"
}

validate_acceptance_failure_result() {
  local -r result="$1"
  local -r expected_result_identity="$2"
  local details=""
  local stage=""
  local source_line=""
  local terminal_count=""
  local first_incomplete=""
  local java_digest=""
  local obi_digest=""
  local index_digest=""
  local status_digest=""

  [[ "$LAST_RECORDED_COMMAND_ID" == \
      acceptance-all-otel-getsockopt-tls13 &&
    "$LAST_RECORDED_COMMAND_VALIDATED" == true &&
    "$LAST_RECORDED_COMMAND_EXIT_STATUS" =~ ^[1-9][0-9]{0,2}$ ]] || return 1
  details="$(validate_acceptance_failure_result_details "$result" \
    "$expected_result_identity" "$LAST_RECORDED_COMMAND_EXIT_STATUS")" ||
    return 1
  IFS=$'\t' read -r stage source_line terminal_count first_incomplete \
    java_digest obi_digest index_digest status_digest <<<"$details"
  [[ -n "$stage" && "$source_line" =~ ^(0|[1-9][0-9]{0,8})$ &&
    "$terminal_count" =~ ^(0|[1-9][0-9]{0,2})$ &&
    "$first_incomplete" =~ ^(__none__|[a-z0-9][a-z0-9-]{0,63})$ &&
    "$java_digest" =~ ^[0-9a-f]{64}$ &&
    "$obi_digest" =~ ^[0-9a-f]{64}$ &&
    "$index_digest" =~ ^[0-9a-f]{64}$ &&
    "$status_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  FAILURE_CLASSIFICATION_STAGE="$stage"
  FAILURE_CLASSIFICATION_SOURCE_LINE="$source_line"
  FAILURE_CLASSIFICATION_TERMINAL_COUNT="$terminal_count"
  FAILURE_CLASSIFICATION_FIRST_INCOMPLETE="$first_incomplete"
  FAILURE_CLASSIFICATION_JAVA_TERMINAL_SHA256="$java_digest"
  FAILURE_CLASSIFICATION_OBI_TERMINAL_SHA256="$obi_digest"
  FAILURE_CLASSIFICATION_INDEX_SHA256="$index_digest"
  FAILURE_CLASSIFICATION_RUN_STATUS_SHA256="$status_digest"
}

assert_raw_result() {
  local -r role="$1"
  local -r result="$2"
  local -r expected_result_identity="${3:-}"
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

  if [[ "$role" == acceptance-failure ]]; then
    validate_acceptance_failure_result "$result" "$expected_result_identity"
    return
  fi

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
  local additions_fd=""
  local removals_fd=""
  local additions_identity=""
  local removals_identity=""
  local close_status=0
  local stable_lock_seen=false
  local added_lock_seen=false
  local result_seen=false

  [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ &&
    "$output_identity_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  snapshot_result_names "$after" || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  assert_result_snapshot_unchanged "$after" || return 1
  open_exclusive_output_fd "$PRIVATE_DIRECTORY_FD" "${additions##*/}" \
    additions_fd || return 1
  open_exclusive_output_fd "$PRIVATE_DIRECTORY_FD" "${removals##*/}" \
    removals_fd || return 1
  LC_ALL=C comm -13 -- "$before" "$after" >&"$additions_fd" || return 1
  LC_ALL=C comm -23 -- "$before" "$after" >&"$removals_fd" || return 1
  additions_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$additions_fd")" || return 1
  removals_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$removals_fd")" || return 1
  [[ "$additions_identity" == "$(stat -Lc '%d:%i:%u:%a:%h' -- \
      "$additions")" && "$additions_identity" == *":$EUID:600:1" &&
    "$removals_identity" == "$(stat -Lc '%d:%i:%u:%a:%h' -- \
      "$removals")" && "$removals_identity" == *":$EUID:600:1" ]] ||
    return 1
  exec {additions_fd}>&- || close_status=$?
  exec {removals_fd}>&- || close_status=$?
  (( close_status == 0 )) || return 1
  seal_result_snapshot "$additions" || return 1
  seal_result_snapshot "$removals" || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  assert_result_snapshot_unchanged "$after" || return 1
  assert_result_snapshot_unchanged "$additions" || return 1
  assert_result_snapshot_unchanged "$removals" || return 1
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
  assert_raw_result "$role" "$result" "$result_identity" || return 1
  if [[ "$added_lock_seen" == true ]]; then
    RESULT_LOCK_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
      "$results_root/.obi-metric-capture.lock")" || return 1
  fi
  [[ -n "$RESULT_LOCK_IDENTITY" ]] || return 1
  assert_result_snapshot_unchanged "$before" || return 1
  assert_result_snapshot_unchanged "$after" || return 1
  assert_result_snapshot_unchanged "$additions" || return 1
  assert_result_snapshot_unchanged "$removals" || return 1
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

acceptance_failure_run_binding_sha256() {
  local payload=""
  local digest=""

  is_sha1 "$SOURCE_REVISION" || return 1
  is_sha256 "$WORKFLOW_BLOB_SHA256" || return 1
  is_positive_decimal "$RUN_ID" || return 1
  is_positive_decimal "$RUN_ATTEMPT" || return 1
  [[ "$WORKFLOW_REF" == \
      "$REPOSITORY_SLUG/$WORKFLOW_PATH@$CAMPAIGN_BRANCH" &&
    "$RUN_URL" == \
      "https://github.com/$REPOSITORY_SLUG/actions/runs/$RUN_ID/attempts/$RUN_ATTEMPT" ]] ||
    return 1
  payload="$(jq -cnS \
    --arg repository "$REPOSITORY_SLUG" \
    --arg source_revision "$SOURCE_REVISION" \
    --arg workflow_blob_sha256 "$WORKFLOW_BLOB_SHA256" \
    --arg workflow_ref "$WORKFLOW_REF" \
    --arg run_id "$RUN_ID" \
    --arg run_attempt "$RUN_ATTEMPT" '{
      repository: $repository,
      run_attempt: $run_attempt,
      run_id: $run_id,
      source_revision: $source_revision,
      workflow_blob_sha256: $workflow_blob_sha256,
      workflow_ref: $workflow_ref
    }')" || return 1
  digest="$(printf '%s\n' "$payload" | sha256sum)" || return 1
  digest="${digest%% *}"
  is_sha256 "$digest" || return 1
  printf '%s\n' "$digest"
}

reset_failure_classification_values() {
  FAILURE_CLASSIFICATION_JSON=""
  FAILURE_CLASSIFICATION_STAGE=""
  FAILURE_CLASSIFICATION_SOURCE_LINE=""
  FAILURE_CLASSIFICATION_FIRST_INCOMPLETE=""
  FAILURE_CLASSIFICATION_TERMINAL_COUNT=""
  FAILURE_CLASSIFICATION_JAVA_TERMINAL_SHA256=""
  FAILURE_CLASSIFICATION_OBI_TERMINAL_SHA256=""
  FAILURE_CLASSIFICATION_INDEX_SHA256=""
  FAILURE_CLASSIFICATION_RUN_STATUS_SHA256=""
}

emit_acceptance_failure_classification() {
  local -r before="$1"
  local source_revision="$SOURCE_REVISION"
  local run_binding_sha256=""
  local exit_status="$LAST_RECORDED_COMMAND_EXIT_STATUS"
  local reason=acceptance_failed
  local source_line_json=null
  local first_incomplete_json=null
  local detailed=false

  [[ "$FAILURE_CLASSIFICATION_EMITTED" == false &&
    "$LAST_RECORDED_COMMAND_ID" == \
      acceptance-all-otel-getsockopt-tls13 &&
    "$exit_status" =~ ^[1-9][0-9]{0,2}$ ]] || return 1
  (( exit_status <= 255 )) || return 1
  reset_failure_classification_values
  if ! is_sha1 "$source_revision"; then
    source_revision=0000000000000000000000000000000000000000
  fi
  run_binding_sha256="$(acceptance_failure_run_binding_sha256 2>/dev/null)" ||
    run_binding_sha256="$EMPTY_SHA256"

  failure_classification_checkpoint before-classification-validation "$before" ||
    return 1
  if resolve_new_result acceptance-failure "$before" RAW_ACCEPTANCE \
      RAW_ACCEPTANCE_IDENTITY 2>/dev/null; then
    detailed=true
  fi
  failure_classification_checkpoint after-classification-validation "$before" ||
    detailed=false
  if [[ "$detailed" == true ]]; then
    case "$exit_status:$FAILURE_CLASSIFICATION_STAGE" in
      124:*|137:*) reason=acceptance_timeout ;;
      129:*|130:*|143:*|*:signal) reason=acceptance_interrupted ;;
      *) reason=acceptance_failed ;;
    esac
    if [[ "$FAILURE_CLASSIFICATION_SOURCE_LINE" != 0 ]]; then
      source_line_json="$FAILURE_CLASSIFICATION_SOURCE_LINE"
    fi
    if [[ "$FAILURE_CLASSIFICATION_FIRST_INCOMPLETE" != __none__ ]]; then
      first_incomplete_json="$(jq -cn \
        --arg value "$FAILURE_CLASSIFICATION_FIRST_INCOMPLETE" '$value')" ||
        detailed=false
    fi
  fi
  if [[ "$detailed" == true ]]; then
    FAILURE_CLASSIFICATION_JSON="$(jq -cnS \
      --argjson exit_status "$exit_status" \
      --arg failure_stage "$FAILURE_CLASSIFICATION_STAGE" \
      --arg reason "$reason" \
      --argjson source_line "$source_line_json" \
      --argjson terminal_count "$FAILURE_CLASSIFICATION_TERMINAL_COUNT" \
      --argjson first_incomplete "$first_incomplete_json" \
      --arg terminal_java_sha256 \
        "$FAILURE_CLASSIFICATION_JAVA_TERMINAL_SHA256" \
      --arg terminal_obi_sha256 \
        "$FAILURE_CLASSIFICATION_OBI_TERMINAL_SHA256" \
      --arg boundary_index_sha256 "$FAILURE_CLASSIFICATION_INDEX_SHA256" \
      --arg run_status_sha256 "$FAILURE_CLASSIFICATION_RUN_STATUS_SHA256" \
      --arg source_revision "$source_revision" \
      --arg run_binding_sha256 "$run_binding_sha256" '{
        boundary_index_sha256: $boundary_index_sha256,
        exit_status: $exit_status,
        failure_stage: $failure_stage,
        first_incomplete_boundary: $first_incomplete,
        reason: $reason,
        run_binding_sha256: $run_binding_sha256,
        run_status_sha256: $run_status_sha256,
        source_line: $source_line,
        source_revision: $source_revision,
        terminal_boundary_count: $terminal_count,
        terminal_java_sha256: $terminal_java_sha256,
        terminal_obi_sha256: $terminal_obi_sha256
      }')" || detailed=false
  fi
  if [[ "$detailed" != true ]]; then
    FAILURE_CLASSIFICATION_JSON="$(jq -cnS \
      --argjson exit_status "$exit_status" \
      --arg source_revision "$source_revision" \
      --arg run_binding_sha256 "$run_binding_sha256" '{
        exit_status: $exit_status,
        failure_stage: "classification-unavailable",
        reason: "classification_unavailable",
        run_binding_sha256: $run_binding_sha256,
        source_revision: $source_revision,
        terminal_boundary_count: 0
      }')" || return 1
  fi
  [[ -n "$FAILURE_CLASSIFICATION_JSON" &&
    "$FAILURE_CLASSIFICATION_JSON" == \
      "$(jq -cS . <<<"$FAILURE_CLASSIFICATION_JSON")" ]] || return 1
  FAILURE_CLASSIFICATION_EMITTED=true
  printf '%s: acceptance_failure_classification=%s\n' \
    "$SCRIPT_NAME" "$FAILURE_CLASSIFICATION_JSON" >&2
}

receipt_preopen_checkpoint() {
  : "$@"
}

seal_receipt() {
  local commands_json=""
  local candidate=""
  local candidate_identity=""
  local candidate_descriptor_identity=""
  local candidate_fd=""
  local source_tree=""
  local assertion_tree=""
  local receipt_size=""
  local close_status=0

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
  RECEIPT="$PRIVATE_DIRECTORY/runbook-receipt.json"
  candidate="$RECEIPT"
  [[ ! -e "$candidate" && ! -L "$candidate" ]] || return 1
  receipt_preopen_checkpoint "$candidate" || return 1
  open_exclusive_output_fd "$PRIVATE_DIRECTORY_FD" "${candidate##*/}" \
    candidate_fd || return 1
  candidate_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$candidate_fd")" || return 1
  candidate_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$candidate_fd")" || return 1
  [[ "$candidate_descriptor_identity" == "$candidate_identity" &&
    "$candidate_identity" == *":$EUID:600:1" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" == "$candidate_identity" ]] ||
    return 1
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
    }' >&"$candidate_fd" || return 1
  candidate_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$candidate_fd")" || return 1
  [[ "$candidate_descriptor_identity" == "$candidate_identity" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "$candidate")" == "$candidate_identity" ]] ||
    return 1
  receipt_size="$(stat -Lc '%s' -- "/proc/$BASHPID/fd/$candidate_fd")" ||
    return 1
  [[ "$receipt_size" =~ ^[0-9]+$ ]] || return 1
  (( receipt_size <= MAX_RECEIPT_BYTES )) || return 1
  validate_receipt "$candidate" || return 1
  RECEIPT_IDENTITY="$(stat -Lc '%d:%i:%u:%a:%h' -- "$RECEIPT")" ||
    return 1
  candidate_descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$candidate_fd")" || return 1
  [[ "$RECEIPT_IDENTITY" == "$candidate_identity" &&
    "$candidate_descriptor_identity" == "$candidate_identity" ]] || return 1
  RECEIPT_SHA256="$(sha256_open_fd "$candidate_fd")" || return 1
  [[ "$(sha256_file "$RECEIPT")" == "$RECEIPT_SHA256" ]] || return 1
  exec {candidate_fd}>&- || close_status=$?
  (( close_status == 0 ))
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

projection_blob_sha256() {
  local -r relative="$1"

  sha256_git_blob "$CHECKOUT_DIRECTORY" "$SOURCE_REVISION" "$relative"
}

public_closure_checkpoint() {
  : "$@"
}

project_claims() {
  local -r projector_relative='examples/apache-java-https/scripts/project-retained-acceptance-evidence.sh'
  local -r projector="$CHECKOUT_DIRECTORY/$projector_relative"
  local projector_log="$PRIVATE_DIRECTORY/projector.log"
  local projector_log_fd=""
  local projector_log_identity=""
  local projector_log_path_identity=""
  local projector_fd=""
  local projector_identity=""
  local projector_digest=""
  local close_status=0
  local projector_status=0
  local validation_status=0

  assert_output_target || return 1
  assert_private_directory_identity || return 1
  assert_projection_execution_authority || return 1
  assert_result_identity "$RAW_ACCEPTANCE" "$RAW_ACCEPTANCE_IDENTITY" ||
    return 1
  assert_result_identity "$RAW_ASSERTION" "$RAW_ASSERTION_IDENTITY" ||
    return 1
  assert_receipt_unchanged || return 1
  assert_projection_execution_authority || return 1
  projector_digest="$(projection_blob_sha256 "$projector_relative")" ||
    return 1
  open_verified_input_fd "$projector" 755 '' "$projector_digest" \
    projector_fd projector_identity || return 1
  open_exclusive_output_fd "$PRIVATE_DIRECTORY_FD" projector.log \
    projector_log_fd || return 1
  projector_log_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$projector_log_fd")" || return 1
  projector_log_path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "$projector_log")" || return 1
  [[ "$projector_log_identity" == "$projector_log_path_identity" &&
    "$projector_log_identity" == *":$EUID:600:1" ]] || return 1
  assert_verified_input_fd_unchanged "$projector" "$projector_fd" \
    "$projector_identity" "$projector_digest" || return 1
  if projector_execute "$projector" "$RAW_ACCEPTANCE" \
      "$RAW_ASSERTION" "$RECEIPT" "$OUTPUT_DIRECTORY" \
      >&"$projector_log_fd" 2>&1; then
    projector_status=0
  else
    projector_status=$?
  fi
  assert_verified_input_fd_unchanged "$projector" "$projector_fd" \
    "$projector_identity" "$projector_digest" || validation_status=1
  chmod 0400 -- "/proc/$BASHPID/fd/$projector_log_fd" 2>/dev/null ||
    validation_status=1
  assert_projection_execution_authority || validation_status=1
  assert_receipt_unchanged || validation_status=1
  assert_output_parent_unchanged || validation_status=1
  exec {projector_log_fd}>&- || close_status=$?
  exec {projector_fd}<&- || close_status=$?
  (( close_status == 0 )) || validation_status=1
  (( projector_status == 0 && validation_status == 0 )) || {
    die "bounded-claim projection failed"
    return 1
  }
}

assert_public_closure() {
  local expected=""
  local observed=""
  local file=""
  local anchored_file=""
  local path_identity=""
  local descriptor_identity=""
  local post_identity=""
  local digest=""
  local closure_digest=""
  local directory_identity=""
  local directory_descriptor_identity=""
  local directory_post_identity=""
  local candidate_directory_fd=""
  local file_fd=""
  local close_status=0
  local root_device=""
  local -a closure_rows=()

  assert_output_parent_unchanged || return 1
  [[ -d "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" &&
    "$(CDPATH='' cd -- "$OUTPUT_DIRECTORY" && pwd -P)" == "$OUTPUT_DIRECTORY" &&
    "$(stat -Lc '%u:%a' -- "$OUTPUT_DIRECTORY")" == "$EUID:555" ]] ||
    return 1
  directory_identity="$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_DIRECTORY")" ||
    return 1
  if [[ -z "$OUTPUT_DIRECTORY_IDENTITY" ]]; then
    exec {candidate_directory_fd}<"$OUTPUT_DIRECTORY" || return $?
    directory_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$candidate_directory_fd")" || {
      exec {candidate_directory_fd}<&-
      return 1
    }
    [[ "$directory_descriptor_identity" == "$directory_identity" ]] || {
      exec {candidate_directory_fd}<&-
      return 1
    }
    OUTPUT_DIRECTORY_IDENTITY="$directory_identity"
    OUTPUT_DIRECTORY_FD="$candidate_directory_fd"
  else
    [[ "$OUTPUT_DIRECTORY_FD" =~ ^[0-9]+$ &&
      "$directory_identity" == "$OUTPUT_DIRECTORY_IDENTITY" ]] || return 1
    directory_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
      "/proc/$BASHPID/fd/$OUTPUT_DIRECTORY_FD")" || return 1
    [[ "$directory_descriptor_identity" == "$OUTPUT_DIRECTORY_IDENTITY" ]] ||
      return 1
  fi
  expected="$(printf '%s\tf\n' "${PUBLIC_FILES[@]}" | LC_ALL=C sort)" ||
    return 1
  observed="$(find -H "/proc/$BASHPID/fd/$OUTPUT_DIRECTORY_FD" \
    -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' | LC_ALL=C sort)" || return 1
  [[ "$observed" == "$expected" ]] || return 1
  root_device="${OUTPUT_DIRECTORY_IDENTITY%%:*}"
  for file in "${PUBLIC_FILES[@]}"; do
    anchored_file="/proc/$BASHPID/fd/$OUTPUT_DIRECTORY_FD/$file"
    [[ -f "$OUTPUT_DIRECTORY/$file" && ! -L "$OUTPUT_DIRECTORY/$file" &&
      "$(readlink -f -- "$OUTPUT_DIRECTORY/$file")" == \
        "$OUTPUT_DIRECTORY/$file" ]] || return 1
    path_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
      "$OUTPUT_DIRECTORY/$file")" || return 1
    [[ "$path_identity" == "$root_device:"*":$EUID:444:1:"* ]] || return 1
    exec {file_fd}<"$anchored_file" || return $?
    descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
      "/proc/$BASHPID/fd/$file_fd")" || descriptor_identity=""
    if [[ "$descriptor_identity" == "$path_identity" ]]; then
      digest="$(sha256_open_fd "$file_fd")" || digest=""
    else
      digest=""
    fi
    post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
      "$OUTPUT_DIRECTORY/$file")" || post_identity=""
    exec {file_fd}<&- || close_status=$?
    (( close_status == 0 )) || return 1
    [[ -n "$digest" && "$descriptor_identity" == "$path_identity" &&
      "$post_identity" == "$path_identity" ]] || return 1
    if [[ -n "${PUBLIC_FILE_IDENTITY[$file]:-}" ]]; then
      [[ "${PUBLIC_FILE_IDENTITY[$file]}" == "$path_identity" &&
        "${PUBLIC_FILE_SHA256[$file]}" == "$digest" ]] || return 1
    else
      PUBLIC_FILE_IDENTITY["$file"]="$path_identity"
      PUBLIC_FILE_SHA256["$file"]="$digest"
    fi
    closure_rows+=("$file"$'\t'"$path_identity"$'\t'"$digest")
  done
  closure_digest="$(printf '%s\n' "${closure_rows[@]}" | sha256sum)" ||
    return 1
  closure_digest="${closure_digest%% *}"
  is_sha256 "$closure_digest" || return 1
  if [[ -z "$PUBLIC_CLOSURE_SHA256" ]]; then
    PUBLIC_CLOSURE_SHA256="$closure_digest"
  else
    [[ "$closure_digest" == "$PUBLIC_CLOSURE_SHA256" ]] || return 1
  fi
  assert_output_parent_unchanged || return 1
  directory_post_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "$OUTPUT_DIRECTORY")" || return 1
  directory_descriptor_identity="$(stat -Lc '%d:%i:%u:%a' -- \
    "/proc/$BASHPID/fd/$OUTPUT_DIRECTORY_FD")" || return 1
  [[ "$directory_post_identity" == "$OUTPUT_DIRECTORY_IDENTITY" &&
    "$directory_descriptor_identity" == "$OUTPUT_DIRECTORY_IDENTITY" ]]
}

public_reverify() {
  local output=""
  local evidence_id=""
  local receipt="$OUTPUT_DIRECTORY/derivation-receipt.json"
  local verifier="$OUTPUT_DIRECTORY/verify.sh"
  local receipt_fd=""
  local receipt_identity=""
  local verifier_fd=""
  local verifier_identity=""
  local close_status=0
  local verifier_status=0
  local validation_status=0

  assert_public_closure || return 1
  open_verified_input_fd "$receipt" 444 \
    "${PUBLIC_FILE_IDENTITY[derivation-receipt.json]}" \
    "${PUBLIC_FILE_SHA256[derivation-receipt.json]}" receipt_fd \
    receipt_identity || return 1
  evidence_id="$(jq -er '.evidence_id' \
    "/proc/$BASHPID/fd/$receipt_fd")" || validation_status=1
  assert_verified_input_fd_unchanged "$receipt" "$receipt_fd" \
    "$receipt_identity" "${PUBLIC_FILE_SHA256[derivation-receipt.json]}" ||
    validation_status=1
  exec {receipt_fd}<&- || close_status=$?
  (( close_status == 0 && validation_status == 0 )) || return 1
  is_sha256 "$evidence_id" || return 1
  open_verified_input_fd "$verifier" 444 "${PUBLIC_FILE_IDENTITY[verify.sh]}" \
    "${PUBLIC_FILE_SHA256[verify.sh]}" verifier_fd verifier_identity || return 1
  assert_verified_input_fd_unchanged "$verifier" "$verifier_fd" \
    "$verifier_identity" "${PUBLIC_FILE_SHA256[verify.sh]}" || return 1
  if output="$(CDPATH='' cd / && timeout --foreground --signal=TERM \
      --kill-after="${PUBLIC_VERIFY_KILL_AFTER_SECONDS}s" \
      "${PUBLIC_VERIFY_TIMEOUT_SECONDS}s" bash "$verifier")"; then
    verifier_status=0
  else
    verifier_status=$?
  fi
  assert_verified_input_fd_unchanged "$verifier" "$verifier_fd" \
    "$verifier_identity" "${PUBLIC_FILE_SHA256[verify.sh]}" || validation_status=1
  exec {verifier_fd}<&- || close_status=$?
  (( close_status == 0 )) || validation_status=1
  assert_public_closure || validation_status=1
  (( verifier_status == 0 && validation_status == 0 )) || return 1
  [[ "$output" == "$PUBLIC_VERIFY_SUCCESS_PREFIX$evidence_id" ]] || return 1
  if [[ -z "$PUBLIC_EVIDENCE_ID" ]]; then
    PUBLIC_EVIDENCE_ID="$evidence_id"
  else
    [[ "$PUBLIC_EVIDENCE_ID" == "$evidence_id" ]]
  fi
}

publish_workflow_handoff() {
  local descriptor_identity=""
  local path_identity=""
  local close_status=0

  [[ "$OUTPUT_PARENT_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ &&
    "$OUTPUT_DIRECTORY_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ ]] ||
    return 1
  is_sha256 "$PUBLIC_CLOSURE_SHA256" || return 1
  is_sha256 "$PUBLIC_EVIDENCE_ID" || return 1
  assert_public_closure || return 1
  open_workflow_output_channel || return 1
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$WORKFLOW_OUTPUT_FD")" || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$GITHUB_OUTPUT")" ||
    return 1
  [[ "$descriptor_identity" == "$WORKFLOW_OUTPUT_IDENTITY" &&
    "$path_identity" == "$WORKFLOW_OUTPUT_IDENTITY" ]] || return 1
  printf '%s\n' \
    "public_parent_identity=$OUTPUT_PARENT_IDENTITY" \
    "public_directory_identity=$OUTPUT_DIRECTORY_IDENTITY" \
    "public_closure_sha256=$PUBLIC_CLOSURE_SHA256" \
    "public_evidence_id=$PUBLIC_EVIDENCE_ID" >&"$WORKFLOW_OUTPUT_FD" ||
    return 1
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- \
    "/proc/$BASHPID/fd/$WORKFLOW_OUTPUT_FD")" || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$GITHUB_OUTPUT")" ||
    return 1
  [[ "$descriptor_identity" == "$WORKFLOW_OUTPUT_IDENTITY" &&
    "$path_identity" == "$WORKFLOW_OUTPUT_IDENTITY" ]] || return 1
  exec {WORKFLOW_OUTPUT_FD}>&- || close_status=$?
  WORKFLOW_OUTPUT_FD=""
  (( close_status == 0 ))
}

emergency_scoped_cleanup() {
  local emergency_log_fd=""
  local close_status=0
  local cleanup_status=0

  [[ "$CLEANUP_REQUIRED" == true ]] || return 0
  if ! assert_cleanup_execution_authority 2>/dev/null; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  assert_private_directory_identity || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  open_exclusive_output_fd "$PRIVATE_DIRECTORY_FD" emergency-scoped-cleanup.log \
    emergency_log_fd || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  if (
    CDPATH='' cd -- "$CHECKOUT_DIRECTORY"
    campaign_execute emergency-scoped-cleanup \
      ./examples/apache-java-https/run.sh --cleanup-only
  ) >&"$emergency_log_fd" 2>&1; then
    cleanup_status=0
  else
    cleanup_status=$?
  fi
  chmod 0400 -- "/proc/$BASHPID/fd/$emergency_log_fd" 2>/dev/null ||
    cleanup_status=1
  exec {emergency_log_fd}>&- || close_status=$?
  (( close_status == 0 )) || cleanup_status=1
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
  if [[ "$STATE_JOURNAL_FD" =~ ^[0-9]+$ ]]; then
    exec {STATE_JOURNAL_FD}>&- || cleanup_status=1
    STATE_JOURNAL_FD=""
  fi
  if [[ "$PRIVATE_DIRECTORY_FD" =~ ^[0-9]+$ ]]; then
    exec {PRIVATE_DIRECTORY_FD}<&- || cleanup_status=1
    PRIVATE_DIRECTORY_FD=""
  fi
  if [[ "$OUTPUT_DIRECTORY_FD" =~ ^[0-9]+$ ]]; then
    exec {OUTPUT_DIRECTORY_FD}<&- || cleanup_status=1
    OUTPUT_DIRECTORY_FD=""
  fi
  if [[ "$OUTPUT_PARENT_FD" =~ ^[0-9]+$ ]]; then
    exec {OUTPUT_PARENT_FD}<&- || cleanup_status=1
    OUTPUT_PARENT_FD=""
  fi
  if [[ "$WORKFLOW_OUTPUT_FD" =~ ^[0-9]+$ ]]; then
    exec {WORKFLOW_OUTPUT_FD}>&- || cleanup_status=1
    WORKFLOW_OUTPUT_FD=""
  fi
  if [[ -n "$PRIMARY_FAILURE" &&
    "$FAILURE_CLASSIFICATION_EMITTED" != true ]]; then
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
  if ! run_recorded_command acceptance-all-otel-getsockopt-tls13 0 \
      "$CHECKOUT_DIRECTORY" ./examples/apache-java-https/run.sh \
        --transport getsockopt --agent otel --tls TLSv1.3; then
    if [[ "$LAST_RECORDED_COMMAND_ID" == \
        acceptance-all-otel-getsockopt-tls13 &&
      "$LAST_RECORDED_COMMAND_EXIT_STATUS" =~ ^[1-9][0-9]{0,2}$ ]]; then
      emit_acceptance_failure_classification "$before_acceptance" || return 1
    fi
    return 1
  fi
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
  public_closure_checkpoint after-project-closure

  enter_state PRIVATE_DESTROY
  destroy_private_transaction

  enter_state PUBLIC_REVERIFY
  public_reverify
  publish_workflow_handoff

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
