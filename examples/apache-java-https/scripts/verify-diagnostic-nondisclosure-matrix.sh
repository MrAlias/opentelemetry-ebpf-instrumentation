#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

readonly SCRIPT_NAME="${0##*/}"
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
DEMO_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly DEMO_DIR
REPO_ROOT="$(git -C "$DEMO_DIR" rev-parse --show-toplevel)"
readonly REPO_ROOT
readonly COMPOSE_FILE="$DEMO_DIR/docker-compose.yml"
readonly MATRIX_RUNNER="$SCRIPT_DIR/run-diagnostic-nondisclosure-matrix.sh"
readonly WORKFLOW_FILE="$REPO_ROOT/.github/workflows/java_diagnostic_nondisclosure.yml"
readonly REPORT_REFERENCE="scenario-diagnostic-nondisclosure-status.json"
readonly MAX_SCENARIO_BYTES=1048576
readonly MAX_SCENARIO_LINES=10000
readonly MAX_REPORT_BYTES=32768
readonly MAX_JAVA_BYTES=16384
readonly MAX_METRICS_BYTES=8388608
readonly MAX_METRICS_LINES=20000
readonly MAX_OBI_LOG_BYTES=2097152
readonly MAX_JAVA_LOG_BYTES=1048576
readonly MAX_LOG_LINES=10000
readonly MAX_TRANSPORT_BYTES=256
readonly MAX_CANARY_BYTES=16384
readonly JAVA_COUNTER_LIMIT=999999999
readonly MAX_RAW_CELL_BYTES=536870912
readonly MAX_PAIR_SERIES=792
readonly EMPTY_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
readonly PUBLIC_WORKFLOW_NAME="Java diagnostic nondisclosure matrix"
readonly PUBLIC_WORKFLOW_PATH=".github/workflows/java_diagnostic_nondisclosure.yml"

readonly -a CELL_IDS=(
  otel-getsockopt-info otel-getsockopt-debug
  otel-unix-info otel-unix-debug
  splunk-getsockopt-info splunk-getsockopt-debug
  splunk-unix-info splunk-unix-debug
)
readonly -a SURFACE_NAMES=(
  java_endpoint java_header java_transport_configuration
  obi_metrics obi_log java_log
)
readonly -a SURFACE_REFERENCES=(
  diagnostic-nondisclosure-java-endpoint.txt
  diagnostic-nondisclosure-java-header.txt
  diagnostic-nondisclosure-java-transport-configuration.txt
  diagnostic-nondisclosure-obi-metrics.prom
  diagnostic-nondisclosure-obi.log
  diagnostic-nondisclosure-java.log
)
readonly -a FIXED_CANARY_VARIABLES=(
  DIAGNOSTIC_NONDISCLOSURE_TRACE_ID
  DIAGNOSTIC_NONDISCLOSURE_PARENT_SPAN_ID
  DIAGNOSTIC_NONDISCLOSURE_MARKER
  DIAGNOSTIC_NONDISCLOSURE_HEADER_CANARY
  DIAGNOSTIC_NONDISCLOSURE_BODY_CANARY
  DIAGNOSTIC_NONDISCLOSURE_CREDENTIAL_CANARY
)
readonly UNIX_CANARY_VARIABLE=DIAGNOSTIC_NONDISCLOSURE_UNIX_PAYLOAD_CANARY

MATRIX_ROOT=""
TEMP_DIR=""
TEMP_DIR_IDENTITY=""
TEMP_DIR_STATE=""
PUBLIC_CANDIDATE=""
PUBLIC_CANDIDATE_IDENTITY=""
PUBLIC_CANDIDATE_STATE=""
PUBLIC_CANDIDATE_DESTINATION=""
TRUSTED_RUN_BLOB=""
TRUSTED_COMPOSE_BLOB=""
TRUSTED_RUNNER_BLOB=""
TRUSTED_VERIFIER_BLOB=""
HEAD_REVISION=""
SOURCE_TREE_SHA256=""
SOURCE_TREE_MANIFEST_SCHEMA=""
TRACKED_PATCH_SHA256=""
PATCH_IDENTITY_SHA256=""
declare -A OBSERVED_PROJECTS=()
declare -A OFFICIAL_PIN_DIGESTS=()
BRIDGE_JAVA_SHA256=""
BRIDGE_EXTENSION_SHA256=""
CI_REPOSITORY=""
CI_RUN_ID=""
CI_RUN_ATTEMPT=""
CI_RUN_URL=""
CI_EVENT=""
CI_RUNNER_OS=""
CI_RUNNER_ARCH=""
CI_TRIGGER_SHA=""
CI_WORKFLOW_SHA=""
CI_WORKFLOW_REF=""
CI_WORKFLOW_BLOB_SHA256=""

die() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

matrix_move() {
  mv -T -- "$1" "$2"
}

matrix_remove_tree() {
  rm -rf -- "$1"
}

matrix_mktemp_directory() {
  mktemp -d "$1"
}

matrix_sha256_stream() {
  sha256sum
}

sha256_file() {
  local -r input="$1"
  local output=""
  local digest=""

  output="$(matrix_sha256_stream <"$input")" || return 1
  digest="${output%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

sha256_lines() {
  local -r output="$1"
  shift
  local result=""

  result="$({ printf '%s\n' "$@" || exit $?; } | matrix_sha256_stream)" || return 1
  result="${result%% *}"
  [[ "$result" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf -v "$output" '%s' "$result"
}

safe_reference() {
  local -r reference="$1"
  local remainder="$reference"
  local component=""

  [[ -n "$reference" && ${#reference} -le 256 && "$reference" != /* &&
    "$reference" != */ && "$reference" != *'//' && "$reference" != *$'\n'* ]] || return 1
  while :; do
    component="${remainder%%/*}"
    [[ -n "$component" && "$component" != . && "$component" != .. &&
      "$component" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    [[ "$remainder" == */* ]] || break
    remainder="${remainder#*/}"
  done
}

canonical_uint64() {
  local -r value="$1"
  local max=18446744073709551615

  [[ "$value" =~ ^(0|[1-9][0-9]{0,19})$ ]] || return 1
  ((${#value} < ${#max})) || {
    ((${#value} == ${#max})) || return 1
    LC_ALL=C awk -v value="$value" -v maximum="$max" \
      'BEGIN { exit (("x" value) <= ("x" maximum)) ? 0 : 1 }'
  }
}

uint64_subtract() {
  local -r minuend="$1"
  local -r subtrahend="$2"

  canonical_uint64 "$minuend" || return 1
  canonical_uint64 "$subtrahend" || return 1
  LC_ALL=C awk -v a="$minuend" -v b="$subtrahend" '
    function trim(v) { sub(/^0+/, "", v); return v == "" ? "0" : v }
    function ge(x,y) { return length(x) > length(y) || (length(x) == length(y) && x >= y) }
    BEGIN {
      if (!ge(a,b)) exit 2
      out=""; borrow=0; j=length(b)
      for (i=length(a); i>=1; i--) {
        da=substr(a,i,1)-borrow; db=(j>0 ? substr(b,j,1) : 0)
        if (da < db) { da+=10; borrow=1 } else borrow=0
        out=(da-db) out; j--
      }
      if (borrow) exit 3
      print trim(out)
    }
  '
}

clear_public_candidate_state() {
  PUBLIC_CANDIDATE=""
  PUBLIC_CANDIDATE_IDENTITY=""
  PUBLIC_CANDIDATE_STATE=""
  PUBLIC_CANDIDATE_DESTINATION=""
}

normalize_public_candidate() {
  local -r preserve_commit="${1:-false}"
  local identity=""

  if [[ -z "$PUBLIC_CANDIDATE" ]]; then
    [[ -z "$PUBLIC_CANDIDATE_IDENTITY" && -z "$PUBLIC_CANDIDATE_STATE" &&
      -z "$PUBLIC_CANDIDATE_DESTINATION" ]]
    return
  fi
  [[ -n "$MATRIX_ROOT" && "${PUBLIC_CANDIDATE%/*}" == "$MATRIX_ROOT" &&
    "${PUBLIC_CANDIDATE##*/}" =~ ^\.public\.[A-Za-z0-9]{6}$ ]] || return 1
  if [[ "$PUBLIC_CANDIDATE_STATE" == moving &&
    ! -e "$PUBLIC_CANDIDATE" && ! -L "$PUBLIC_CANDIDATE" ]]; then
    [[ "$PUBLIC_CANDIDATE_DESTINATION" == "$MATRIX_ROOT/public" &&
      -n "$PUBLIC_CANDIDATE_IDENTITY" &&
      -d "$PUBLIC_CANDIDATE_DESTINATION" && ! -L "$PUBLIC_CANDIDATE_DESTINATION" ]] || return 1
    identity="$(stat -Lc '%d:%i:%u:%a' -- "$PUBLIC_CANDIDATE_DESTINATION")" || return 1
    [[ "$identity" == "$PUBLIC_CANDIDATE_IDENTITY" ]] || return 1
    if [[ "$preserve_commit" == true ]]; then
      clear_public_candidate_state
      return 0
    fi
    matrix_remove_tree "$PUBLIC_CANDIDATE_DESTINATION" || {
      [[ ! -e "$PUBLIC_CANDIDATE_DESTINATION" && ! -L "$PUBLIC_CANDIDATE_DESTINATION" ]] || return 1
    }
    [[ ! -e "$PUBLIC_CANDIDATE_DESTINATION" && ! -L "$PUBLIC_CANDIDATE_DESTINATION" ]] || return 1
    clear_public_candidate_state
    return 0
  fi
  if [[ ! -e "$PUBLIC_CANDIDATE" && ! -L "$PUBLIC_CANDIDATE" ]]; then
    [[ "$PUBLIC_CANDIDATE_STATE" != moving &&
      ( -z "$PUBLIC_CANDIDATE_DESTINATION" || ! -e "$PUBLIC_CANDIDATE_DESTINATION" ) ]] || return 1
    clear_public_candidate_state
    return 0
  fi
  [[ -d "$PUBLIC_CANDIDATE" && ! -L "$PUBLIC_CANDIDATE" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$PUBLIC_CANDIDATE")" || return 1
  [[ "$identity" =~ :$EUID:(700|755)$ &&
    ( -z "$PUBLIC_CANDIDATE_IDENTITY" || "$identity" == "$PUBLIC_CANDIDATE_IDENTITY" ) ]] || return 1
  matrix_remove_tree "$PUBLIC_CANDIDATE" || {
    [[ ! -e "$PUBLIC_CANDIDATE" && ! -L "$PUBLIC_CANDIDATE" ]] || return 1
  }
  [[ ! -e "$PUBLIC_CANDIDATE" && ! -L "$PUBLIC_CANDIDATE" ]] || return 1
  clear_public_candidate_state
}

cleanup_temp_directory() {
  local identity=""

  if [[ -z "$TEMP_DIR" ]]; then
    [[ -z "$TEMP_DIR_IDENTITY" && -z "$TEMP_DIR_STATE" ]]
    return
  fi
  [[ "${TEMP_DIR%/*}" == "${TMPDIR:-/tmp}" &&
    "${TEMP_DIR##*/}" =~ ^obi-i39-verify\.[A-Za-z0-9]{6}$ ]] || return 1
  if [[ ! -e "$TEMP_DIR" && ! -L "$TEMP_DIR" ]]; then
    TEMP_DIR=""; TEMP_DIR_IDENTITY=""; TEMP_DIR_STATE=""; return 0
  fi
  [[ -d "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$TEMP_DIR")" || return 1
  [[ "$identity" =~ :$EUID:700$ &&
    ( -z "$TEMP_DIR_IDENTITY" || "$identity" == "$TEMP_DIR_IDENTITY" ) ]] || return 1
  matrix_remove_tree "$TEMP_DIR" || {
    [[ ! -e "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || return 1
  }
  [[ ! -e "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || return 1
  TEMP_DIR=""; TEMP_DIR_IDENTITY=""; TEMP_DIR_STATE=""
}

cleanup() {
  local status="$?"
  trap - EXIT
  if ! normalize_public_candidate false; then ((status != 0)) || status=1; fi
  if ! cleanup_temp_directory; then ((status != 0)) || status=1; fi
  exit "$status"
}

create_verifier_temp_directory() {
  local create_status=0
  local identity=""
  local -r parent="${TMPDIR:-/tmp}"

  [[ -z "$TEMP_DIR" && -z "$TEMP_DIR_IDENTITY" && -z "$TEMP_DIR_STATE" &&
    -d "$parent" && ! -L "$parent" ]] || return 1
  if TEMP_DIR="$(umask 077; matrix_mktemp_directory "$parent/obi-i39-verify.XXXXXX")"; then
    create_status=0
  else
    create_status=$?
  fi
  TEMP_DIR_STATE=provisional
  if [[ -z "$TEMP_DIR" ]]; then
    TEMP_DIR_STATE=""
    ((create_status != 0)) || create_status=1
    return "$create_status"
  fi
  [[ -n "$TEMP_DIR" && "${TEMP_DIR%/*}" == "$parent" &&
    "${TEMP_DIR##*/}" =~ ^obi-i39-verify\.[A-Za-z0-9]{6}$ ]] || return 1
  ((create_status == 0)) || { cleanup_temp_directory || :; return "$create_status"; }
  [[ -d "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || { cleanup_temp_directory || :; return 1; }
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$TEMP_DIR")" || { cleanup_temp_directory || :; return 1; }
  [[ "$identity" =~ :$EUID:700$ ]] || { cleanup_temp_directory || :; return 1; }
  TEMP_DIR_IDENTITY="$identity"
  TEMP_DIR_STATE=identified
}

create_public_candidate() {
  local create_status=0
  local identity=""

  [[ -n "$MATRIX_ROOT" && -d "$MATRIX_ROOT" && ! -L "$MATRIX_ROOT" &&
    -z "$PUBLIC_CANDIDATE" && -z "$PUBLIC_CANDIDATE_IDENTITY" &&
    -z "$PUBLIC_CANDIDATE_STATE" && -z "$PUBLIC_CANDIDATE_DESTINATION" ]] || return 1
  if PUBLIC_CANDIDATE="$(umask 077; matrix_mktemp_directory "$MATRIX_ROOT/.public.XXXXXX")"; then
    create_status=0
  else
    create_status=$?
  fi
  PUBLIC_CANDIDATE_STATE=provisional
  if [[ -z "$PUBLIC_CANDIDATE" ]]; then
    PUBLIC_CANDIDATE_STATE=""
    ((create_status != 0)) || create_status=1
    return "$create_status"
  fi
  [[ -n "$PUBLIC_CANDIDATE" && "${PUBLIC_CANDIDATE%/*}" == "$MATRIX_ROOT" &&
    "${PUBLIC_CANDIDATE##*/}" =~ ^\.public\.[A-Za-z0-9]{6}$ ]] || return 1
  ((create_status == 0)) || { normalize_public_candidate false || :; return "$create_status"; }
  [[ -d "$PUBLIC_CANDIDATE" && ! -L "$PUBLIC_CANDIDATE" ]] || {
    normalize_public_candidate false || :; return 1;
  }
  chmod 0755 -- "$PUBLIC_CANDIDATE" || { normalize_public_candidate false || :; return 1; }
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$PUBLIC_CANDIDATE")" || {
    normalize_public_candidate false || :; return 1;
  }
  [[ "$identity" =~ :$EUID:755$ ]] || { normalize_public_candidate false || :; return 1; }
  PUBLIC_CANDIDATE_IDENTITY="$identity"
  PUBLIC_CANDIDATE_STATE=identified
}

require_commands() {
  local command=""
  for command in git jq sha256sum stat find sort cmp grep awk wc realpath mktemp \
    chmod mv rm bash install; do
    command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: $command"
  done
}

bounded_regular_file() {
  local -r path="$1"
  local -r maximum_bytes="$2"
  local -r maximum_lines="$3"
  local size=""
  local lines=""

  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ "$(stat -Lc '%u:%a:%h' -- "$path")" == "$EUID:600:1" ]] || return 1
  size="$(stat -Lc '%s' -- "$path")" || return 1
  lines="$(LC_ALL=C wc -l <"$path")" || return 1
  [[ "$size" =~ ^[0-9]+$ && "$lines" =~ ^[0-9]+$ ]] || return 1
  ((size >= 1 && size <= maximum_bytes && lines >= 1 && lines <= maximum_lines))
}

regular_file_at_most() {
  local -r path="$1"
  local -r maximum="$2"
  local size=""
  [[ -f "$path" && ! -L "$path" && "$(stat -Lc '%u:%a:%h' -- "$path")" == "$EUID:600:1" ]] || return 1
  size="$(stat -Lc '%s' -- "$path")" || return 1
  [[ "$size" =~ ^[0-9]+$ ]] && ((size <= maximum))
}

prepare_trusted_run_blob() {
  local object_type=""

  HEAD_REVISION="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" || return 1
  [[ "$HEAD_REVISION" =~ ^[0-9a-f]{40}$ ]] || return 1
  object_type="$(git -C "$REPO_ROOT" cat-file -t "$HEAD_REVISION")" || return 1
  [[ "$object_type" == commit ]] || return 1
  TRUSTED_RUN_BLOB="$TEMP_DIR/run.sh.from-head"
  git -C "$REPO_ROOT" show "$HEAD_REVISION:examples/apache-java-https/run.sh" \
    >"$TRUSTED_RUN_BLOB" || return 1
  [[ -s "$TRUSTED_RUN_BLOB" && ! -L "$TRUSTED_RUN_BLOB" ]] || return 1
}

validate_ci_identity() {
  local -r repository="${GITHUB_REPOSITORY:-}"
  local -r workflow="${GITHUB_WORKFLOW:-}"
  local -r workflow_ref="${GITHUB_WORKFLOW_REF:-}"
  local -r sha="${GITHUB_SHA:-}"
  local -r requested_ref="${MATRIX_REQUESTED_REF:-}"
  local -r workflow_sha="${GITHUB_WORKFLOW_SHA:-}"
  local -r server_url="${GITHUB_SERVER_URL:-}"
  local -r run_id="${GITHUB_RUN_ID:-}"
  local -r run_attempt="${GITHUB_RUN_ATTEMPT:-}"
  local -r event="${GITHUB_EVENT_NAME:-}"
  local -r runner_os="${RUNNER_OS:-}"
  local -r runner_arch="${RUNNER_ARCH:-}"
  local workflow_type="" workflow_blob="$TEMP_DIR/executed-workflow.yml"
  local workflow_relative="${WORKFLOW_FILE#"$REPO_ROOT/"}"

  [[ "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true ]] || return 1
  [[ "$repository" =~ ^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$ ]] || return 1
  [[ "$workflow" == "$PUBLIC_WORKFLOW_NAME" ]] || return 1
  [[ "$workflow_ref" == "$repository/$PUBLIC_WORKFLOW_PATH@"* && ${#workflow_ref} -le 512 &&
    "$workflow_ref" != *$'\n'* ]] || return 1
  [[ "$requested_ref" == "$HEAD_REVISION" && "$sha" =~ ^[0-9a-f]{40}$ &&
    "$workflow_sha" =~ ^[0-9a-f]{40}$ && "$server_url" == https://github.com ]] || return 1
  canonical_uint64 "$run_id" || return 1
  canonical_uint64 "$run_attempt" || return 1
  [[ "$run_id" != 0 && "$run_attempt" != 0 ]] || return 1
  [[ "$event" == push || "$event" == workflow_dispatch ]] || return 1
  [[ "$event" != push || "$sha" == "$HEAD_REVISION" ]] || return 1
  [[ "$runner_os" == Linux && "$runner_arch" == X64 ]] || return 1
  workflow_type="$(git -C "$REPO_ROOT" cat-file -t "$workflow_sha")" || return 1
  [[ "$workflow_type" == commit ]] || return 1
  [[ "$workflow_relative" == "$PUBLIC_WORKFLOW_PATH" ]] || return 1
  git -C "$REPO_ROOT" show "$workflow_sha:$workflow_relative" >"$workflow_blob" || return 1
  CI_WORKFLOW_BLOB_SHA256="$(sha256_file "$workflow_blob")" || return 1
  CI_REPOSITORY="$repository"
  CI_RUN_ID="$run_id"
  CI_RUN_ATTEMPT="$run_attempt"
  CI_RUN_URL="$server_url/$repository/actions/runs/$run_id/attempts/$run_attempt"
  CI_EVENT="$event"
  CI_RUNNER_OS="$runner_os"
  CI_RUNNER_ARCH="$runner_arch"
  CI_TRIGGER_SHA="$sha"
  CI_WORKFLOW_SHA="$workflow_sha"
  CI_WORKFLOW_REF="$workflow_ref"
}

validate_repository_execution_bytes() {
  local status_before="" status_after="" revision_after=""
  local relative="" expected_mode="" entry="" metadata="" tree_path="" blob=""
  local -a paths=(
    examples/apache-java-https/run.sh
    "${COMPOSE_FILE#"$REPO_ROOT/"}"
    "${MATRIX_RUNNER#"$REPO_ROOT/"}"
    "${BASH_SOURCE[0]#"$REPO_ROOT/"}"
  )
  local -a modes=(100755 100644 100755 100755)
  local index=0

  status_before="$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" || return 1
  [[ -z "$status_before" ]] || return 1
  for index in "${!paths[@]}"; do
    relative="${paths[$index]}"; expected_mode="${modes[$index]}"
    entry="$(git -C "$REPO_ROOT" ls-tree "$HEAD_REVISION" -- "$relative")" || return 1
    metadata="${entry%%$'\t'*}"; tree_path="${entry#*$'\t'}"
    [[ "$metadata" =~ ^$expected_mode\ blob\ [0-9a-f]{40}$ && "$tree_path" == "$relative" ]] || return 1
    blob="$TEMP_DIR/head-byte-$index"
    git -C "$REPO_ROOT" show "$HEAD_REVISION:$relative" >"$blob" || return 1
    cmp -s -- "$blob" "$REPO_ROOT/$relative" || return 1
  done
  revision_after="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')" || return 1
  status_after="$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" || return 1
  [[ "$revision_after" == "$HEAD_REVISION" && -z "$status_after" ]] || return 1
  TRUSTED_COMPOSE_BLOB="$TEMP_DIR/head-byte-1"
  TRUSTED_RUNNER_BLOB="$TEMP_DIR/head-byte-2"
  TRUSTED_VERIFIER_BLOB="$TEMP_DIR/head-byte-3"
  [[ -f "$TRUSTED_COMPOSE_BLOB" && -f "$TRUSTED_RUNNER_BLOB" && -f "$TRUSTED_VERIFIER_BLOB" ]]
}

validate_source_runtime_contract() {
  local -r dockerfile="$TEMP_DIR/java-dockerfile.from-head"

  git -C "$REPO_ROOT" show "$HEAD_REVISION:examples/apache-java-https/java/Dockerfile" \
    >"$dockerfile" || return 1
  LC_ALL=C awk '
    /^FROM / {
      count++
      last=$0
      if ($0 ~ /^FROM eclipse-temurin:21\.[0-9]+\.[0-9]+_[0-9]+-jre@sha256:[0-9a-f]{64}$/) runtime++
    }
    END { exit count < 1 || runtime != 1 || last !~ /^FROM eclipse-temurin:21\.[0-9]+\.[0-9]+_[0-9]+-jre@sha256:[0-9a-f]{64}$/ }
  ' "$dockerfile"
}

read_source_literal() {
  local -r variable="$1"
  local matches=""

  matches="$(LC_ALL=C awk -v name="$variable" '
    index($0, name "=\"") == 1 {
      if ($0 !~ /^[A-Z0-9_]+="[A-Za-z0-9._:-]+"$/) exit 3
      count++
      value = substr($0, length(name) + 3)
      sub(/"$/, "", value)
      print value
    }
    END { if (count != 1) exit 4 }
  ' "$TRUSTED_RUN_BLOB")" || return 1
  [[ "$matches" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || return 1
  printf '%s\n' "$matches"
}

assert_java_diagnostics() {
  local -r input="$1"
  local snapshot=""
  local entry=""
  local name=""
  local value=""
  local decoded=0
  local index=0
  local -a entries=()
  local -a expected=(
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

  bounded_regular_file "$input" "$MAX_JAVA_BYTES" 1 || return 1
  IFS= read -r snapshot <"$input" || return 1
  ((${#snapshot} + 1 == $(stat -Lc '%s' -- "$input"))) || return 1
  IFS=',' read -r -a entries <<<"$snapshot"
  ((${#entries[@]} == ${#expected[@]})) || return 1
  for entry in "${entries[@]}"; do
    [[ "$entry" =~ ^[a-z_]+=(0|[1-9a-z][0-9a-z]*)$ ]] || return 1
    name="${entry%%=*}"
    value="${entry#*=}"
    [[ "$name" == "${expected[$index]}" && ${#value} -le 6 ]] || return 1
    decoded="$((36#$value))"
    ((decoded < JAVA_COUNTER_LIMIT)) || return 1
    ((index += 1))
  done
}

assert_transport_configuration() {
  local -r input="$1"
  local -r expected_transport="$2"
  local configuration=""
  local version="" status="" requested="" selected="" attempted="" getsockopt="" unix=""

  bounded_regular_file "$input" "$MAX_TRANSPORT_BYTES" 1 || return 1
  IFS= read -r configuration <"$input" || return 1
  [[ "$configuration" =~ ^version=([0-9]+),status=([0-9]+),requested=([0-9]+),selected=([0-9]+),attempted=([0-9]+),getsockopt=([0-9]+),unix=([0-9]+)$ ]] || return 1
  version="${BASH_REMATCH[1]}"; status="${BASH_REMATCH[2]}"; requested="${BASH_REMATCH[3]}"
  selected="${BASH_REMATCH[4]}"; attempted="${BASH_REMATCH[5]}"; getsockopt="${BASH_REMATCH[6]}"; unix="${BASH_REMATCH[7]}"
  [[ "$version" == 2 && "$status" == 1 ]] || return 1
  case "$expected_transport" in
    getsockopt) [[ "$requested" == 1 && "$selected" == 1 && "$attempted" == 1 && "$getsockopt" == 1 && "$unix" == 0 ]] ;;
    unix) [[ "$requested" == 2 && "$selected" == 2 && "$attempted" == 2 && "$getsockopt" == 0 && "$unix" == 1 ]] ;;
    *) return 1 ;;
  esac
}

assert_metrics() {
  local -r input="$1"
  local -r transport="$2"
  local parsed="$TEMP_DIR/diagnostic-metrics-$RANDOM"
  local record="" observed_transport="" operation="" status="" value=""
  local availability=0

  parse_metric_snapshot "$input" "$parsed" || return 1
  while IFS=$'\t' read -r record observed_transport operation status value; do
    if [[ "$record" == series && "$observed_transport" == "$transport" &&
      "$operation" == availability && "$status" == valid && "$value" != 0 ]]; then
      ((availability += 1))
    fi
  done <"$parsed"
  ((availability == 1))
}

assert_obi_log() {
  local -r input="$1"
  local -r level="$2"
  local -r transport="$3"

  bounded_regular_file "$input" "$MAX_OBI_LOG_BYTES" "$MAX_LOG_LINES" || return 1
  LC_ALL=C awk -v level="$level" -v transport="$transport" '
    length($0) > 16384 { invalid = 1 }
    index($0, "msg=\"Java remote parent bridge ready details\"") {
      details++
      if (!index($0, "transport=" transport) || !index($0, "socket_path=")) invalid = 1
    }
    index($0, "msg=\"Java remote parent bridge ready\"") &&
      !index($0, "msg=\"Java remote parent bridge ready details\"") {
      ready++
      if (!index($0, "transport=" transport)) invalid = 1
    }
    index($0, "traceID=") || index($0, "spanID=") ||
      index($0, " conn=") || index($0, " buf=") ||
      index($0, " request=") || index($0, " response=") ||
      index($0, " reqErr=") || index($0, " respErr=") { invalid = 1 }
    level == "info" &&
      (index($0, " level=DEBUG ") || index($0, "socket_path=") || index($0, " error=")) { invalid = 1 }
    END { exit invalid || ready != 1 || (level == "info" && details != 0) ||
      (level == "debug" && details != 1) ? 1 : 0 }
  ' "$input"
}

assert_java_log() {
  local -r input="$1"

  bounded_regular_file "$input" "$MAX_JAVA_LOG_BYTES" "$MAX_LOG_LINES" || return 1
  LC_ALL=C awk '
    length($0) > 16384 { invalid = 1 }
    index($0, "OBI remote-parent provider ready") { provider++ }
    index($0, "OBI remote-parent propagator enabled") { propagator++ }
    index($0, "Jetty HTTPS backend ready on 127.0.0.1:18443") { jetty++ }
    index($0, "OBI remote-parent diagnostics reason=") {
      value = $0; sub(/^.*OBI remote-parent diagnostics reason=/, "", value)
      if (value !~ /^[a-z][a-z0-9_]{0,31} count=(0|[1-9][0-9]{0,8})$/) invalid = 1
    }
    END { exit invalid || provider < 1 || propagator != 1 || jetty != 1 ? 1 : 0 }
  ' "$input"
}

validate_w3c_result() {
  local -r scenario="$1"

  bounded_regular_file "$scenario" "$MAX_SCENARIO_BYTES" "$MAX_SCENARIO_LINES" || return 1
  jq -e -s '
    def integer($min;$max): type == "number" and floor == . and . >= $min and . <= $max;
    def positive: type == "number" and isfinite and . > 0;
    def timestamp: type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9}Z$");
    def marker: type == "string" and length >= 1 and length <= 128 and test("^[A-Za-z0-9._:-]+$");
    def trace_id: type == "string" and test("^[0-9a-f]{32}$") and . != "00000000000000000000000000000000";
    def span_id: type == "string" and test("^[0-9a-f]{16}$") and . != "0000000000000000";
    def subset($allowed): keys - $allowed == [];
    def span:
      type == "object" and
      subset(["attributes","end_unix_nano","flags","kind","name","parent_span_id","received_unix_milli","scope_name","service_name","span_id","start_unix_nano","trace_id"]) and
      (.trace_id | trace_id) and (.span_id | span_id) and
      ((.parent_span_id? // "0000000000000001") | span_id) and
      (.flags | integer(0;4294967295)) and
      ([.service_name,.name,.kind][] | type == "string" and length >= 1 and length <= 1024) and
      ((.scope_name? // "") | type == "string" and length <= 1024) and
      ((.attributes? // {}) | type == "object" and all(to_entries[]; (.key | type == "string" and length <= 1024) and (.value | type == "string" and length <= 4096))) and
      (.start_unix_nano | integer(1;1e20)) and
      (.end_unix_nano | integer(1;1e20)) and .end_unix_nano >= .start_unix_nano and
      ((.received_unix_milli? // 0) | integer(0;9007199254740991));
    def zero_span_id: . == null or . == "" or . == "0000000000000000";
    def remote_parent:
      (.flags |
        if type == "number" then
          floor == . and . >= 0 and
          ((. / 256 | floor) % 2) == 1 and
          ((. / 512 | floor) % 2) == 1
        else false
        end);
    def trace_flags:
      (.flags | if type == "number" and floor == . and . >= 0 then . % 256 else -1 end);
    def marked($marker):
      (.attributes | type == "object") and
      .attributes["http.request.header.x-obi-demo-id"] == $marker;
    def endpoint_matches:
      (.attributes | type == "object") and
      (.attributes["http.route"] == "/api/echo" or
       .attributes["url.path"] == "/api/echo" or
       (.attributes["url.full"] | type == "string" and test("/api/echo(?:[?].*)?$")));
    def descends_from($spans;$descendant;$ancestor):
      def follow($parent;$seen):
        if $parent == $ancestor.span_id then true
        elif ($parent | zero_span_id) or ($seen | index($parent)) != null then false
        else ([ $spans[] | select(.trace_id == $descendant.trace_id and
          .service_name == "apache-proxy" and .span_id == $parent) ]) as $parents |
          ($parents | length) == 1 and follow($parents[0].parent_span_id; $seen + [$parent])
        end;
      $descendant.trace_id == $ancestor.trace_id and follow($descendant.parent_span_id; []);
    length == 1 and
    (.[0] | . as $result | keys == ["cases","finished_at","latency","request_count","scenario","seed","started_at","status","throughput_per_second","traffic_elapsed_nanos"] and
      .status == "passed" and .scenario == "w3c" and
      (.seed | integer(0;9007199254740991)) and
      (.started_at | timestamp) and (.finished_at | timestamp) and .started_at < .finished_at and
      .request_count == 2 and (.traffic_elapsed_nanos | integer(1;9007199254740991)) and
      (.throughput_per_second | positive) and
      (.latency | keys == ["p50_nanos","p95_nanos","p99_nanos"] and
        (.p50_nanos | integer(1;9007199254740991)) and
        (.p95_nanos | integer(1;9007199254740991)) and
        (.p99_nanos | integer(1;9007199254740991)) and
        .p50_nanos <= .p95_nanos and .p95_nanos <= .p99_nanos) and
      (.cases | type == "array" and length == $result.request_count) and
      ([.cases[].request.marker] | length == (unique | length)) and
      all(.cases[];
        . as $case |
        keys == ["latency_nanos","request","response","trace"] and
        (.latency_nanos | integer(1;9007199254740991)) and
        (.request | type == "object" and
          subset(["endpoint","invalid_w3c","marker","w3c_case","w3c_parent_span_id","w3c_trace_flags","w3c_trace_id"]) and
          (.marker | marker) and (.endpoint | type == "string" and test("^/[A-Za-z0-9/?&=._:-]{1,255}$")) and
          (.w3c_case | type == "string" and test("^[a-z0-9-]{1,64}$")) and
          ((.w3c_trace_id? // "00000000000000000000000000000001") | trace_id) and
          ((.w3c_parent_span_id? // "0000000000000001") | span_id) and
          ((.w3c_trace_flags? // "01") | type == "string" and test("^[0-9a-f]{2}$")) and
          ((.invalid_w3c? // false) | type == "boolean")) and
        (.response | type == "object" and
          subset(["backend_connection_id","backend_remote_port","backend_socket_fd","marker","protocol","secure","tls_cipher","tls_protocol","tls_read_bytes","tls_read_events"]) and
          .marker == $case.request.marker and .secure == true and .protocol == "HTTP/1.1" and
          .tls_protocol == "TLSv1.3" and (.tls_cipher | type == "string" and length >= 1 and length <= 128) and
          (.backend_connection_id | integer(1;9007199254740991)) and
          (.backend_remote_port | integer(1;65535)) and
          ((.backend_socket_fd? // 0) | integer(0;9007199254740991)) and
          (.tls_read_events | integer(1;9007199254740991)) and
          (.tls_read_bytes | integer(1;9007199254740991))) and
        (.trace | type == "object" and
          subset(["ambiguous_related_spans","dropped_count_spans","dropped_retained_limit_spans","dropped_spans","dropped_value_limit_spans","marker","max_retained_bytes","max_value_bytes","omitted_related_spans","received_batches","received_spans","receiver_instance_id","related_spans","reset_generation","retained_bytes","spans"]) and
          .marker == $case.request.marker and
          ([.received_batches,.received_spans,.retained_bytes,.max_retained_bytes,.max_value_bytes][] | integer(0;9007199254740991)) and
          .received_batches >= 1 and .received_spans >= 1 and
          .dropped_spans == 0 and .dropped_count_spans == 0 and
          .dropped_value_limit_spans == 0 and .dropped_retained_limit_spans == 0 and
          ((.omitted_related_spans? // 0) == 0) and ((.ambiguous_related_spans? // 0) == 0) and
          ((.receiver_instance_id? // "") | type == "string" and length <= 128) and
          ((.reset_generation? // 0) | integer(0;9007199254740991)) and
          (.spans | type == "array" and length >= 3 and all(.[]; span)) and
          ((.related_spans? // []) | type == "array" and all(.[]; span)))) and
      [.cases[].request.w3c_case] == ["conflicting-valid-w3c-and-obi","malformed-w3c-valid-obi"] and
      (.cases[0] as $case | $case.trace.spans as $spans | $case.request as $request |
        ([ $spans[] | select(.service_name == "java-backend" and .kind == "SERVER" and marked($request.marker) and endpoint_matches) ]) as $java |
        ([ $spans[] | select(.service_name == "apache-proxy" and .kind == "SERVER" and marked($request.marker) and endpoint_matches) ]) as $server |
        ([ $spans[] | select(.service_name == "apache-proxy" and .kind == "CLIENT" and marked($request.marker) and endpoint_matches) ]) as $client |
        ($request | keys == ["endpoint","marker","w3c_case","w3c_parent_span_id","w3c_trace_flags","w3c_trace_id"]) and
        $request.endpoint == "/api/echo" and $request.w3c_trace_flags == "01" and
        ($java | length) == 1 and ($server | length) == 1 and ($client | length) == 1 and
        $java[0].trace_id == $request.w3c_trace_id and $java[0].parent_span_id == $request.w3c_parent_span_id and
        ($java[0] | remote_parent) and ($java[0] | trace_flags) == 1 and
        $server[0].trace_id == $request.w3c_trace_id and $server[0].parent_span_id == $request.w3c_parent_span_id and
        ($server[0] | trace_flags) == 1 and
        $client[0].trace_id == $request.w3c_trace_id and $client[0].span_id != $request.w3c_parent_span_id and
        ($client[0] | trace_flags) == 1 and
        descends_from($spans;$client[0];$server[0])) and
      (.cases[1] as $case | $case.trace.spans as $spans | $case.request as $request |
        ([ $spans[] | select(.service_name == "java-backend" and .kind == "SERVER" and marked($request.marker) and endpoint_matches) ]) as $java |
        ([ $spans[] | select(.service_name == "apache-proxy" and .kind == "SERVER" and marked($request.marker) and endpoint_matches) ]) as $server |
        ([ $spans[] | select(.service_name == "apache-proxy" and .kind == "CLIENT" and marked($request.marker) and endpoint_matches) ]) as $client |
        ($request | keys == ["endpoint","invalid_w3c","marker","w3c_case"]) and
        $request.endpoint == "/api/echo" and $request.invalid_w3c == true and
        ($java | length) == 1 and ($server | length) == 1 and ($client | length) == 1 and
        ($server[0].parent_span_id | zero_span_id) and
        $server[0].trace_id == $client[0].trace_id and descends_from($spans;$client[0];$server[0]) and
        $java[0].trace_id == $client[0].trace_id and $java[0].parent_span_id == $client[0].span_id and
        ($java[0] | remote_parent) and
        ($java[0] | trace_flags) == ($client[0] | trace_flags)))
  ' "$scenario" >/dev/null
}

build_canaries() {
  local -r scenario="$1"
  local -r transport="$2"
  local -r output="$3"
  local variable=""
  local value=""
  local unsorted="$TEMP_DIR/canaries.unsorted"

  : >"$unsorted" || return 1
  for variable in "${FIXED_CANARY_VARIABLES[@]}"; do
    value="$(read_source_literal "$variable")" || return 1
    printf '%s\n' "$value" >>"$unsorted" || return 1
  done
  if [[ "$transport" == unix ]]; then
    value="$(read_source_literal "$UNIX_CANARY_VARIABLE")" || return 1
    printf '%s\n' "$value" >>"$unsorted" || return 1
  fi
  jq -er '
    if .status == "passed" and .scenario == "w3c" and
      (.cases | type == "array" and length > 0)
    then .cases[] |
      .request.marker,
      (.request.w3c_trace_id // empty),
      (.request.w3c_parent_span_id // empty),
      (.trace.spans[]? | .trace_id, .span_id, (.parent_span_id // empty)),
      (.trace.related_spans[]? | .trace_id, .span_id, (.parent_span_id // empty))
    else error("invalid W3C scenario evidence") end
  ' "$scenario" >>"$unsorted" || return 1
  LC_ALL=C sort -u -- "$unsorted" >"$output" || return 1
  LC_ALL=C awk '
    length($0) < 1 || length($0) > 128 || $0 !~ /^[A-Za-z0-9._:-]+$/ { exit 2 }
    seen[$0]++ { exit 3 }
    END { if (NR < 6 || NR > 128) exit 4 }
  ' "$output" || return 1
  (($(stat -Lc '%s' -- "$output") <= MAX_CANARY_BYTES))
}

assert_no_canaries() {
  local -r canaries="$1"
  local -r surface="$2"
  local status=0

  if LC_ALL=C grep --fixed-strings --file="$canaries" -- "$surface" >/dev/null; then
    return 1
  else
    status=$?
  fi
  [[ "$status" == 1 ]]
}

validate_report() {
  local -r report="$1"
  local -r agent="$2"
  local -r transport="$3"
  local -r level="$4"
  local -r canary_source_sha256="$5"
  local canonical=""

  bounded_regular_file "$report" "$MAX_REPORT_BYTES" 1 || return 1
  canonical="$(jq -ceS -s \
    --arg agent "$agent" --arg transport "$transport" --arg level "$level" \
    --arg canary_sha "$canary_source_sha256" \
    --argjson obi_log_max_bytes "$MAX_OBI_LOG_BYTES" \
    --argjson java_log_max_bytes "$MAX_JAVA_LOG_BYTES" \
    --argjson log_max_lines "$MAX_LOG_LINES" '
    if length == 1 then .[0] else error("report must contain exactly one object") end | . as $r |
    if keys == ["agent_distribution","canary_bytes","canary_count","canary_source","debug_controls","obi_log_level","obi_metric_boundary_ids","policy","scenario","schema","selected_transport","status","surfaces","tls_protocol","window"] and
      .schema == "obi-diagnostic-nondisclosure-v1" and .status == "passed" and
      .scenario == "diagnostic-nondisclosure" and .agent_distribution == $agent and
      .selected_transport == $transport and .obi_log_level == $level and
      .tls_protocol == "TLSv1.3" and .obi_metric_boundary_ids == ["diagnostic-nondisclosure"] and
      (.canary_count | type == "number" and floor == . and . >= 6 and . <= 128) and
      (.canary_bytes | type == "number" and floor == . and . >= 1 and . <= 16384) and
      .canary_source == {reference:"scenario-w3c.json",sha256:$canary_sha} and
      .debug_controls == {"bpf_debug":false,"protocol_debug":false} and
      .policy == {"log_capture_complete":true,"no_canary_matches":true,"runtime_configuration_attested":true,"surface_schemas_valid":true} and
      (.window | keys == ["since","until"]) and
      (.window.since | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9}Z$")) and
      (.window.until | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9}Z$")) and
      .window.since < .window.until and
      (.surfaces | type == "array" and length == 6) and
      [.surfaces[].name] == ["java_endpoint","java_header","java_transport_configuration","obi_metrics","obi_log","java_log"] and
      [.surfaces[].reference] == ["diagnostic-nondisclosure-java-endpoint.txt","diagnostic-nondisclosure-java-header.txt","diagnostic-nondisclosure-java-transport-configuration.txt","diagnostic-nondisclosure-obi-metrics.prom","diagnostic-nondisclosure-obi.log","diagnostic-nondisclosure-java.log"] and
      all(.surfaces[]; keys == ["canary_match_count","line_count","name","reference","schema_valid","sha256","size_bytes"] and
        .canary_match_count == 0 and .schema_valid == true and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.size_bytes | type == "number" and floor == . and . >= 1) and
        (.line_count | type == "number" and floor == . and . >= 1) and
        (if .name == "obi_log" then
          .size_bytes <= $obi_log_max_bytes and .line_count <= $log_max_lines
         elif .name == "java_log" then
          .size_bytes <= $java_log_max_bytes and .line_count <= $log_max_lines
         else true end))
    then $r else error("invalid report") end
  ' "$report")" || return 1
  [[ "$(<"$report")" == "$canonical" ]]
}

environment_value() {
  local -r input="$1"
  local -r key="$2"

  LC_ALL=C awk -F= -v key="$key" '
    $1 == key { count++; value = substr($0, length(key) + 2) }
    END { if (count != 1 || value == "") exit 1; print value }
  ' "$input"
}

validate_environment() {
  local -r input="$1"
  local -r agent="$2"
  local -r transport="$3"
  local -r level="$4"
  local revision="" project="" value="" observed_keys=""
  local expected_keys=$'invocation\nrevision\ndirty\nsource_tree_sha256\nsource_tree_manifest_schema\ntracked_patch_sha256\npatch_identity_sha256\ntransport\nagent_distribution\ntls_protocol\nobi_log_level\nscenario\nrequest_count\nrepeat_count\nscenario_seed\nbridge_build_mode\nacceptance_evidence\nacceptance_evidence_reason\ncompose_project\ncommand_timeout_seconds\nreadiness_timeout_seconds\narchitecture\nkernel\nopenssl\ndocker\ncompose'

  bounded_regular_file "$input" 65536 200 || return 1
  observed_keys="$(LC_ALL=C awk -F= 'NF < 2 || $1 !~ /^[a-z0-9_]+$/ { exit 2 } { print $1 }' "$input")" || return 1
  [[ "$observed_keys" == "$expected_keys" ]] || return 1
  revision="$(environment_value "$input" revision)" || return 1
  [[ "$revision" == "$HEAD_REVISION" ]] || return 1
  value="$(environment_value "$input" dirty)" || return 1; [[ "$value" == false ]] || return 1
  value="$(environment_value "$input" transport)" || return 1; [[ "$value" == "$transport" ]] || return 1
  value="$(environment_value "$input" agent_distribution)" || return 1; [[ "$value" == "$agent" ]] || return 1
  value="$(environment_value "$input" tls_protocol)" || return 1; [[ "$value" == TLSv1.3 ]] || return 1
  value="$(environment_value "$input" obi_log_level)" || return 1; [[ "$value" == "$level" ]] || return 1
  value="$(environment_value "$input" scenario)" || return 1; [[ "$value" == diagnostic-nondisclosure ]] || return 1
  value="$(environment_value "$input" request_count)" || return 1; [[ "$value" == 0 ]] || return 1
  value="$(environment_value "$input" repeat_count)" || return 1; [[ "$value" == 1 ]] || return 1
  value="$(environment_value "$input" scenario_seed)" || return 1; canonical_uint64 "$value" || return 1
  value="$(environment_value "$input" bridge_build_mode)" || return 1; [[ "$value" == fresh ]] || return 1
  value="$(environment_value "$input" acceptance_evidence)" || return 1; [[ "$value" == false ]] || return 1
  value="$(environment_value "$input" acceptance_evidence_reason)" || return 1; [[ "$value" == targeted-scenario ]] || return 1
  value="$(environment_value "$input" command_timeout_seconds)" || return 1; [[ "$value" =~ ^[1-9][0-9]{0,5}$ ]] || return 1
  value="$(environment_value "$input" readiness_timeout_seconds)" || return 1; [[ "$value" =~ ^[1-9][0-9]{0,5}$ ]] || return 1
  project="$(environment_value "$input" compose_project)" || return 1
  [[ "$project" =~ ^obi-apache-java-https-i39-[a-z0-9-]{1,34}$ &&
    ${#project} -le 63 && -z "${OBSERVED_PROJECTS[$project]+present}" ]] || return 1
  OBSERVED_PROJECTS["$project"]=1
  value="$(environment_value "$input" source_tree_sha256)" || return 1
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ -z "$SOURCE_TREE_SHA256" ]]; then SOURCE_TREE_SHA256="$value"; else [[ "$SOURCE_TREE_SHA256" == "$value" ]] || return 1; fi
  value="$(environment_value "$input" source_tree_manifest_schema)" || return 1
  [[ "$value" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || return 1
  if [[ -z "$SOURCE_TREE_MANIFEST_SCHEMA" ]]; then SOURCE_TREE_MANIFEST_SCHEMA="$value"; else [[ "$SOURCE_TREE_MANIFEST_SCHEMA" == "$value" ]] || return 1; fi
  value="$(environment_value "$input" tracked_patch_sha256)" || return 1
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ -z "$TRACKED_PATCH_SHA256" ]]; then TRACKED_PATCH_SHA256="$value"; else [[ "$TRACKED_PATCH_SHA256" == "$value" ]] || return 1; fi
  value="$(environment_value "$input" patch_identity_sha256)" || return 1
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ -z "$PATCH_IDENTITY_SHA256" ]]; then PATCH_IDENTITY_SHA256="$value"; else [[ "$PATCH_IDENTITY_SHA256" == "$value" ]] || return 1; fi
}

validate_official_pin() {
  local -r input="$1"
  local -r agent="$2"
  local canonical="" digest=""

  bounded_regular_file "$input" 4096 20 || return 1
  canonical="$(jq -ceS -s --arg agent "$agent" '
    if length == 1 and (($agent == "otel" and .[0] == {distribution:"otel",sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",version:"2.28.1"}) or
        ($agent == "splunk" and .[0] == {distribution:"splunk",embedded_opentelemetry_version:"2.28.1",sha256:"70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",url:"https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar",version:"2.28.0"}))
    then .[0] else error("invalid official agent pin") end
  ' "$input")" || return 1
  [[ -n "$canonical" ]] || return 1
  sha256_lines digest "$canonical" || return 1
  if [[ -n "${OFFICIAL_PIN_DIGESTS[$agent]:-}" ]]; then
    [[ "${OFFICIAL_PIN_DIGESTS[$agent]}" == "$digest" ]] || return 1
  else
    OFFICIAL_PIN_DIGESTS["$agent"]="$digest"
  fi
}

validate_source_provenance() {
  local -r directory="$1"
  local revision="" tree="" tracked="" patch="" schema=""
  local status_digest="" manifest_digest="" computed_patch=""
  local environment_tree="" environment_schema="" environment_tracked="" environment_patch=""
  local state_keys="" java_sha="" extension_sha="" bridge_canonical=""
  local expected_manifest="$TEMP_DIR/expected-source-tree.manifest"
  local tree_entries="$TEMP_DIR/source-tree.entries"
  local entry="" metadata="" path="" mode="" object="" marker=""

  revision="$HEAD_REVISION"
  regular_file_at_most "$directory/git-status.txt" 65536 || return 1
  [[ ! -s "$directory/git-status.txt" ]] || return 1
  bounded_regular_file "$directory/source-state.txt" 4096 20 || return 1
  bounded_regular_file "$directory/source-tree.manifest" 536870912 2000000 || return 1
  state_keys="$(LC_ALL=C awk -F= 'NF != 2 || $1 !~ /^[a-z0-9_]+$/ { exit 2 } { print $1 }' "$directory/source-state.txt")" || return 1
  [[ "$state_keys" == $'revision\ndirty\nsource_tree_sha256\nsource_tree_manifest_schema\ntracked_patch_sha256\npatch_identity_sha256' ]] || return 1
  [[ "$(environment_value "$directory/source-state.txt" revision)" == "$revision" &&
    "$(environment_value "$directory/source-state.txt" dirty)" == false ]] || return 1
  tree="$(environment_value "$directory/source-state.txt" source_tree_sha256)" || return 1
  schema="$(environment_value "$directory/source-state.txt" source_tree_manifest_schema)" || return 1
  tracked="$(environment_value "$directory/source-state.txt" tracked_patch_sha256)" || return 1
  patch="$(environment_value "$directory/source-state.txt" patch_identity_sha256)" || return 1
  manifest_digest="$(sha256_file "$directory/source-tree.manifest")" || return 1
  status_digest="$(sha256_file "$directory/git-status.txt")" || return 1
  sha256_lines computed_patch "$status_digest" "$manifest_digest" "$tracked" || return 1
  [[ "$schema" == git-tree-v2 && "$tree" == "$manifest_digest" &&
    "$status_digest" == "$EMPTY_SHA256" && "$tracked" == "$EMPTY_SHA256" &&
    "$patch" == "$computed_patch" &&
    "$tree" == "$SOURCE_TREE_SHA256" && "$schema" == "$SOURCE_TREE_MANIFEST_SCHEMA" &&
    "$tracked" == "$TRACKED_PATCH_SHA256" && "$patch" == "$PATCH_IDENTITY_SHA256" ]] || return 1
  environment_tree="$(environment_value "$directory/environment.txt" source_tree_sha256)" || return 1
  environment_schema="$(environment_value "$directory/environment.txt" source_tree_manifest_schema)" || return 1
  environment_tracked="$(environment_value "$directory/environment.txt" tracked_patch_sha256)" || return 1
  environment_patch="$(environment_value "$directory/environment.txt" patch_identity_sha256)" || return 1
  [[ "$environment_tree" == "$tree" && "$environment_schema" == "$schema" &&
    "$environment_tracked" == "$tracked" && "$environment_patch" == "$patch" ]] || return 1
  git -C "$REPO_ROOT" ls-tree -r -z --full-tree "$revision" >"$tree_entries" || return 1
  : >"$expected_manifest" || return 1
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"; path="${entry#*$'\t'}"; mode="${metadata%% *}"; object="${metadata##* }"
    case "$mode" in 100644) marker=- ;; 100755) marker=x ;; 120000) marker=l ;; 160000) marker=g ;; *) return 1 ;; esac
    LC_ALL=C printf '%s %s %q\n' "$object" "$marker" "$path" >>"$expected_manifest" || return 1
  done <"$tree_entries"
  cmp -s -- "$expected_manifest" "$directory/source-tree.manifest" || return 1
  bounded_regular_file "$directory/bridge-source-revision.txt" 80 1 || return 1
  bounded_regular_file "$directory/bridge-source-tree.sha256" 80 1 || return 1
  [[ "$(<"$directory/bridge-source-revision.txt")" == "$revision" &&
    "$(<"$directory/bridge-source-tree.sha256")" == "$tree" ]] || return 1
  bounded_regular_file "$directory/bridge-artifacts.json" 16384 100 || return 1
  bridge_canonical="$(jq -ceS -s --arg revision "$revision" --arg tree "$tree" '
    if length == 1 and (.[0] | keys == ["obi_java_agent_sha256","obi_otel_extension_sha256","source_revision","source_tree_sha256"] and
      .source_revision == $revision and .source_tree_sha256 == $tree and
      (.obi_java_agent_sha256 | test("^[0-9a-f]{64}$")) and
      (.obi_otel_extension_sha256 | test("^[0-9a-f]{64}$")))
    then .[0] else error("invalid bridge metadata") end
  ' "$directory/bridge-artifacts.json")" || return 1
  java_sha="$(jq -er '.obi_java_agent_sha256' <<<"$bridge_canonical")" || return 1
  extension_sha="$(jq -er '.obi_otel_extension_sha256' <<<"$bridge_canonical")" || return 1
  if [[ -z "$BRIDGE_JAVA_SHA256" ]]; then
    BRIDGE_JAVA_SHA256="$java_sha"; BRIDGE_EXTENSION_SHA256="$extension_sha"
  else
    [[ "$BRIDGE_JAVA_SHA256" == "$java_sha" && "$BRIDGE_EXTENSION_SHA256" == "$extension_sha" ]] || return 1
  fi
}

validate_run_status_and_freeze() {
  local -r directory="$1"
  local -r boundary="$directory/obi-metric-boundary-index.json"
  local digest="" freeze=""

  digest="$(sha256_file "$boundary")" || return 1
  bounded_regular_file "$directory/run-status.json" 262144 10000 || return 1
  jq -e -s --arg digest "$digest" \
    --slurpfile java "$directory/terminal-java-diagnostics.json" \
    --slurpfile metrics "$directory/terminal-obi-metrics.json" '
    length == 1 and ($java | length) == 1 and ($metrics | length) == 1 and (.[0] |
    keys == ["acceptance_evidence","acceptance_evidence_reason","evidence_directory","exit_status","failure_line","failure_stage","java_bridge_diagnostics","java_bridge_diagnostics_reference","obi_metric_boundary_index_reference","obi_metric_boundary_index_sha256","obi_metric_evidence","obi_metric_evidence_reference","schema","status"] and
    .schema == "obi-apache-java-https-run-status-v3" and .status == "passed" and
    .exit_status == 0 and .acceptance_evidence == false and
    .acceptance_evidence_reason == "targeted-scenario" and
    .failure_stage == "none" and .failure_line == 0 and
    (.evidence_directory | type == "string" and startswith("/") and length <= 4096) and
    .java_bridge_diagnostics_reference == "terminal-java-diagnostics.json" and
    .java_bridge_diagnostics == $java[0] and
    .obi_metric_evidence_reference == "terminal-obi-metrics.json" and
    .obi_metric_evidence == $metrics[0] and
    .obi_metric_boundary_index_reference == "obi-metric-boundary-index.json" and
    .obi_metric_boundary_index_sha256 == $digest)
  ' "$directory/run-status.json" >/dev/null || return 1
  bounded_regular_file "$directory/.obi-metric-boundary-index.freeze" 160 1 || return 1
  freeze="$(<"$directory/.obi-metric-boundary-index.freeze")"
  [[ "$freeze" == "obi-metric-boundary-index-frozen-v1:$digest" ]]
}

validate_terminal_evidence() {
  local -r directory="$1"
  local digest="" reference="" snapshot="" canonical=""

  digest="$(sha256_file "$directory/obi-metric-boundary-index.json")" || return 1
  bounded_regular_file "$directory/terminal-obi-metrics.json" 1048576 1 || return 1
  canonical="$(jq -ceS -s --arg digest "$digest" '
    if length == 1 and (.[0] | keys == ["active_boundary_id","available","boundary_index_reference","boundary_index_sha256","reason","schema","sealed"] and
      .schema == "obi-java-remote-parent-terminal-metrics-v2" and .sealed == true and
      .available == false and .reason == "no-active-boundary" and .active_boundary_id == null and
      .boundary_index_reference == "obi-metric-boundary-index.json" and .boundary_index_sha256 == $digest)
    then .[0] else error("invalid terminal metrics") end
  ' "$directory/terminal-obi-metrics.json")" || return 1
  [[ "$(<"$directory/terminal-obi-metrics.json")" == "$canonical" ]] || return 1
  bounded_regular_file "$directory/terminal-java-diagnostics.json" "$MAX_JAVA_BYTES" 1 || return 1
  canonical="$(jq -ceS -s '
    if length == 1 and (.[0] | keys == ["available","counters","phase","reference","schema","sealed","snapshot"] and
    .schema == "obi-java-bridge-terminal-diagnostics-v1" and .sealed == true and .available == true and
    ((.reference == "phases/final/java-diagnostics.txt" and .phase == "final") or
     (.reference == "phases/diagnostic-nondisclosure-header/java-diagnostics.txt" and
      .phase == "diagnostic-nondisclosure-header")) and
    (.snapshot | type == "string") and (.counters | type == "object"))
    then .[0] else error("invalid terminal Java diagnostics") end
  ' "$directory/terminal-java-diagnostics.json")" || return 1
  [[ "$(<"$directory/terminal-java-diagnostics.json")" == "$canonical" ]] || return 1
  reference="$(jq -er '.reference' "$directory/terminal-java-diagnostics.json")" || return 1
  [[ -f "$directory/$reference" && ! -L "$directory/$reference" ]] || return 1
  assert_java_diagnostics "$directory/$reference" || return 1
  snapshot="$(<"$directory/$reference")"
  jq -e --arg snapshot "$snapshot" --arg reference "$reference" '
    .reference == $reference and .snapshot == $snapshot and
    .phase == ($reference | capture("^phases/(?<p>[^/]+)/").p) and
    .counters == ($snapshot | split(",") | map(split("=") | {(.[0]):.[1]}) | add)
  ' "$directory/terminal-java-diagnostics.json" >/dev/null
}

java_evidence_json() {
  local -r input="$1"
  local -r reference="$2"
  local snapshot=""

  assert_java_diagnostics "$input" || return 1
  snapshot="$(<"$input")"
  jq -cnS --arg reference "$reference" --arg snapshot "$snapshot" '
    {counters:($snapshot | split(",") | map(split("=") | {(.[0]):.[1]}) | add),
     reference:$reference,snapshot:$snapshot}
  '
}

validate_w3c_status() {
  local -r directory="$1"
  local status="$directory/scenario-w3c-status.json"
  local result="" stderr="" before_java="" after_java="" pair=""

  bounded_regular_file "$status" 1048576 10000 || return 1
  regular_file_at_most "$directory/scenario-w3c.stderr.log" 1048576 || return 1
  [[ ! -s "$directory/scenario-w3c.stderr.log" ]] || return 1
  before_java="$(java_evidence_json "$directory/phases/w3c-before/java-diagnostics.txt" \
    phases/w3c-before/java-diagnostics.txt)" || return 1
  after_java="$(java_evidence_json "$directory/phases/w3c-after/java-diagnostics.txt" \
    phases/w3c-after/java-diagnostics.txt)" || return 1
  pair="$(jq -ce -s 'if length == 1 and (.[0] | type == "object") then .[0] else error("pair must be one object") end' \
    "$directory/obi-metric-pairs/w3c.json")" || return 1
  jq -e -s --argjson before "$before_java" --argjson after "$after_java" --argjson pair "$pair" '
    length == 1 and (.[0] |
    keys == ["after_phase","before_phase","exit_status","java_diagnostics","metric_status","obi_metric_boundary_ids","obi_metric_evidence","pressure_correlation","receive_coordination_maps","result","scenario","scenario_reconciliation","status","stderr"] and
    .status == "passed" and .scenario == "w3c" and .exit_status == 0 and .metric_status == 0 and
    .obi_metric_boundary_ids == ["diagnostic-nondisclosure"] and
    .result == "scenario-w3c.json" and .stderr == "scenario-w3c.stderr.log" and
    .before_phase == "phases/w3c-before" and .after_phase == "phases/w3c-after" and
    .pressure_correlation == null and .scenario_reconciliation == null and
    .receive_coordination_maps == null and
    .java_diagnostics == {after:$after,before:$before} and
    .obi_metric_evidence == {pair:$pair,reference:"obi-metric-pairs/w3c.json"})
  ' "$status" >/dev/null || return 1
  result="$(jq -er '.result' "$status")" || return 1
  stderr="$(jq -er '.stderr' "$status")" || return 1
  [[ "$result" == scenario-w3c.json && "$stderr" == scenario-w3c.stderr.log ]] || return 1
  [[ "$result" == scenario-w3c.json && "$stderr" == scenario-w3c.stderr.log ]]
}

metric_label_allowed() {
  case "$1:$2" in
    transport:tcp|transport:getsockopt|transport:unix|transport:disabled|\
    operation:stage|operation:candidate|operation:handoff|operation:inject|\
    operation:take|operation:discard|operation:negotiate|operation:availability|\
    operation:cleanup|operation:evict|operation:report|\
    status:unknown|status:valid|status:missing|status:stale|status:unsupported|\
    status:malformed|status:version_mismatch|status:ambiguous|status:unauthorized|\
    status:already_consumed|status:timeout|status:overload|status:transport_error|\
    status:disabled|status:segmented|status:load_denied|status:permission_denied|\
    status:verifier_rejected) return 0 ;;
  esac
  return 1
}

parse_metric_snapshot() {
  local -r input="$1"
  local -r output="$2"
  local unsorted="$TEMP_DIR/metric-unsorted-$RANDOM-$$"
  local line="" metric="" value="" extra="" labels="" entry="" name="" label_value=""
  local transport="" operation="" status="" error_type="" process_name="" key=""
  local operation_label_pattern='^(operation|status|transport)="([a-z_]+)"$'
  local attach_label_pattern='^(error_type|process_name)="([a-z_]+)"$'
  local attach_value=0 attach_present=false
  local -a entries=()
  declare -A labels_seen=()
  declare -A series_seen=()

  bounded_regular_file "$input" "$MAX_METRICS_BYTES" "$MAX_METRICS_LINES" || return 1
  : >"$unsorted" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" != *$'\r'* ]] || return 1
    [[ -n "$line" && "$line" != \#* ]] || continue
    metric=""; value=""; extra=""
    IFS=$' \t' read -r metric value extra <<<"$line"
    if [[ "$metric" == obi_java_remote_parent_operations_total* ]]; then
      [[ -z "$extra" && "$metric" == 'obi_java_remote_parent_operations_total{'*'}' ]] || return 1
      labels="${metric#*\{}"; labels="${labels%\}}"
      IFS=',' read -r -a entries <<<"$labels"
      ((${#entries[@]} == 3)) || return 1
      transport=""; operation=""; status=""; labels_seen=()
      for entry in "${entries[@]}"; do
        [[ "$entry" =~ $operation_label_pattern ]] || return 1
        name="${BASH_REMATCH[1]}"; label_value="${BASH_REMATCH[2]}"
        [[ -z "${labels_seen[$name]:-}" ]] || return 1
        labels_seen["$name"]=1
        metric_label_allowed "$name" "$label_value" || return 1
        case "$name" in transport) transport="$label_value" ;; operation) operation="$label_value" ;; status) status="$label_value" ;; esac
      done
      [[ -n "$transport" && -n "$operation" && -n "$status" ]] || return 1
      canonical_uint64 "$value" || return 1
      key="$transport|$operation|$status"
      [[ -z "${series_seen[$key]:-}" ]] || return 1
      series_seen["$key"]="$value"
      ((${#series_seen[@]} <= MAX_PAIR_SERIES)) || return 1
      printf 'series\t%s\t%s\t%s\t%s\n' "$transport" "$operation" "$status" "$value" >>"$unsorted" || return 1
    elif [[ "$metric" == obi_instrumentation_errors_total* && "$metric" == *attaching_java_agent* ]]; then
      [[ -z "$extra" && "$metric" == 'obi_instrumentation_errors_total{'*'}' ]] || return 1
      labels="${metric#*\{}"; labels="${labels%\}}"
      IFS=',' read -r -a entries <<<"$labels"
      ((${#entries[@]} == 2)) || return 1
      error_type=""; process_name=""; labels_seen=()
      for entry in "${entries[@]}"; do
        [[ "$entry" =~ $attach_label_pattern ]] || return 1
        name="${BASH_REMATCH[1]}"; label_value="${BASH_REMATCH[2]}"
        [[ -z "${labels_seen[$name]:-}" ]] || return 1
        labels_seen["$name"]=1
        case "$name" in error_type) error_type="$label_value" ;; process_name) process_name="$label_value" ;; esac
      done
      [[ "$error_type" == attaching_java_agent && "$process_name" == java ]] || continue
      [[ "$attach_present" == false ]] || return 1
      canonical_uint64 "$value" || return 1
      attach_present=true; attach_value="$value"
    fi
  done <"$input"
  LC_ALL=C sort -- "$unsorted" >"$output" || return 1
  printf 'attach\t%s\t%s\n' "$attach_present" "$attach_value" >>"$output" || return 1
  rm -- "$unsorted" || return 1
}

validate_process_identity() {
  local -r input="$1"
  local -r expected_reference="$2"
  local canonical="" digest="" metrics_digest="" container="" pid="" started=""

  bounded_regular_file "$input" 16384 1 || return 1
  digest="$(sha256_file "${input%/obi-identity.json}/obi-metrics.prom")" || return 1
  canonical="$(jq -ceS -s --arg ref "$expected_reference" --arg digest "$digest" '
    if length == 1 and (.[0] |
      keys == ["container_id","host_pid","metrics_reference","metrics_sha256","schema","started_at","state"] and
      .schema == "obi-process-identity-v1" and .state == "running" and
      (.container_id | type == "string" and test("^[0-9a-f]{64}$")) and
      (.host_pid | type == "string") and .metrics_reference == $ref and .metrics_sha256 == $digest and
      (.started_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z$")))
    then .[0] else error("invalid process identity") end
  ' "$input")" || return 1
  [[ "$(<"$input")" == "$canonical" ]] || return 1
  metrics_digest="$(jq -er '.metrics_sha256' <<<"$canonical")" || return 1
  [[ "$metrics_digest" == "$digest" ]] || return 1
  container="$(jq -er '.container_id' <<<"$canonical")" || return 1
  [[ "$container" != 0000000000000000000000000000000000000000000000000000000000000000 ]] || return 1
  pid="$(jq -er '.host_pid' <<<"$canonical")" || return 1
  canonical_uint64 "$pid" || return 1
  [[ "$pid" != 0 ]] || return 1
  started="$(jq -er '.started_at' <<<"$canonical")" || return 1
  printf '%s\t%s\t%s\n' "$container" "$pid" "$started"
}

validate_metric_pair() {
  local -r directory="$1"
  local before_parsed="$TEMP_DIR/before-metrics-$RANDOM" after_parsed="$TEMP_DIR/after-metrics-$RANDOM"
  local union_file="$TEMP_DIR/metric-union-$RANDOM" series_file="$TEMP_DIR/metric-series-$RANDOM"
  local record="" transport="" operation="" status="" value="" key=""
  local before="" after="" delta="" before_attach=0 after_attach=0 attach_delta=""
  local before_present=false after_present=false actual="" expected_payload="" before_identity="" after_identity=""
  declare -A before_values=() after_values=() union=()

  before_identity="$(validate_process_identity "$directory/phases/w3c-before/obi-identity.json" phases/w3c-before/obi-metrics.prom)" || return 1
  after_identity="$(validate_process_identity "$directory/phases/w3c-after/obi-identity.json" phases/w3c-after/obi-metrics.prom)" || return 1
  [[ "$before_identity" == "$after_identity" ]] || return 1
  parse_metric_snapshot "$directory/phases/w3c-before/obi-metrics.prom" "$before_parsed" || return 1
  parse_metric_snapshot "$directory/phases/w3c-after/obi-metrics.prom" "$after_parsed" || return 1
  while IFS=$'\t' read -r record transport operation status value; do
    if [[ "$record" == series ]]; then key="$transport|$operation|$status"; before_values["$key"]="$value"; union["$key"]=1
    elif [[ "$record" == attach ]]; then before_present="$transport"; before_attach="$operation"
    else return 1; fi
  done <"$before_parsed"
  while IFS=$'\t' read -r record transport operation status value; do
    if [[ "$record" == series ]]; then key="$transport|$operation|$status"; after_values["$key"]="$value"; union["$key"]=1
    elif [[ "$record" == attach ]]; then after_present="$transport"; after_attach="$operation"
    else return 1; fi
  done <"$after_parsed"
  ((${#union[@]} >= 1 && ${#union[@]} <= MAX_PAIR_SERIES)) || return 1
  [[ "$before_present" == false || "$after_present" == true ]] || return 1
  : >"$union_file" || return 1
  printf '%s\n' "${!union[@]}" | LC_ALL=C sort >"$union_file" || return 1
  : >"$series_file" || return 1
  while IFS= read -r key; do
    IFS='|' read -r transport operation status <<<"$key"
    before="${before_values[$key]:-0}"; after="${after_values[$key]:-0}"
    [[ -z "${before_values[$key]+present}" || -n "${after_values[$key]+present}" ]] || return 1
    delta="$(uint64_subtract "$after" "$before")" || return 1
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$transport" "$operation" "$status" "$before" "$after" "$delta" >>"$series_file" || return 1
  done <"$union_file"
  attach_delta="$(uint64_subtract "$after_attach" "$before_attach")" || return 1
  expected_payload="$(jq -Rcn --arg before_ref phases/w3c-before/obi-identity.json \
    --arg after_ref phases/w3c-after/obi-identity.json --arg attach_before "$before_attach" \
    --arg attach_after "$after_attach" --arg attach_delta "$attach_delta" '
    {schema:"obi-java-remote-parent-metric-pair-v1",boundary:"w3c",continuity:"same_process",
     before:{state:"running",identity_reference:$before_ref},after:{state:"running",identity_reference:$after_ref},
     series:[inputs | split("\t") | {transport:.[0],operation:.[1],status:.[2],before:.[3],after:.[4],delta:.[5]}],
     java_attach_errors:{before:$attach_before,after:$attach_after,delta:$attach_delta}}
  ' <"$series_file")" || return 1
  bounded_regular_file "$directory/obi-metric-pairs/w3c.json" 1048576 1 || return 1
  actual="$(jq -ce -s 'if length == 1 and (.[0] | type == "object") then .[0] else error("pair must be one object") end' \
    "$directory/obi-metric-pairs/w3c.json")" || return 1
  [[ "$(<"$directory/obi-metric-pairs/w3c.json")" == "$actual" && "$actual" == "$expected_payload" ]]
}

validate_boundary_authority() {
  local -r directory="$1"
  local -r transport="$2"
  local -r boundary="$directory/obi-metric-boundary-index.json"
  local canonical="" pair_sha="" before_java_sha="" before_id_sha="" after_id_sha=""
  local after_java_sha="" header_java_sha="" w3c_status_sha="" report_sha=""
  local endpoint_sha="" header_sha="" transport_sha="" metrics_sha="" obi_log_sha="" java_log_sha=""

  bounded_regular_file "$boundary" 1048576 1 || return 1
  canonical="$(jq -ceS -s 'if length == 1 and (.[0] | type == "object") then .[0] else error("boundary must be one object") end' "$boundary")" || return 1
  [[ "$(<"$boundary")" == "$canonical" ]] || return 1
  pair_sha="$(sha256_file "$directory/obi-metric-pairs/w3c.json")" || return 1
  before_java_sha="$(sha256_file "$directory/phases/w3c-before/java-diagnostics.txt")" || return 1
  before_id_sha="$(sha256_file "$directory/phases/w3c-before/obi-identity.json")" || return 1
  after_id_sha="$(sha256_file "$directory/phases/w3c-after/obi-identity.json")" || return 1
  after_java_sha="$(sha256_file "$directory/phases/w3c-after/java-diagnostics.txt")" || return 1
  header_java_sha="$(sha256_file "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt")" || return 1
  endpoint_sha="$(sha256_file "$directory/${SURFACE_REFERENCES[0]}")" || return 1
  header_sha="$(sha256_file "$directory/${SURFACE_REFERENCES[1]}")" || return 1
  transport_sha="$(sha256_file "$directory/${SURFACE_REFERENCES[2]}")" || return 1
  metrics_sha="$(sha256_file "$directory/${SURFACE_REFERENCES[3]}")" || return 1
  obi_log_sha="$(sha256_file "$directory/${SURFACE_REFERENCES[4]}")" || return 1
  java_log_sha="$(sha256_file "$directory/${SURFACE_REFERENCES[5]}")" || return 1
  w3c_status_sha="$(sha256_file "$directory/scenario-w3c-status.json")" || return 1
  report_sha="$(sha256_file "$directory/$REPORT_REFERENCE")" || return 1
  jq -e --arg transport "$transport" --arg pair "$pair_sha" --arg before_java "$before_java_sha" \
    --arg before_id "$before_id_sha" --arg after_id "$after_id_sha" --arg after_java "$after_java_sha" \
    --arg header_java "$header_java_sha" --arg endpoint "$endpoint_sha" --arg header "$header_sha" \
    --arg transport_sha "$transport_sha" --arg metrics "$metrics_sha" --arg obi_log "$obi_log_sha" \
    --arg java_log "$java_log_sha" --arg w3c_status "$w3c_status_sha" --arg report "$report_sha" '
    keys == ["boundaries","schema","selection"] and .schema == "obi-metric-boundary-index-v1" and
    .selection == {repeat_count:1,requested_transport:$transport,scenario:"diagnostic-nondisclosure",selected_transport:$transport} and
    .boundaries == [{captures:[
      {id:"w3c",java_reference:"phases/w3c-after/java-diagnostics.txt",java_sha256:$after_java,kind:"pair",pair_reference:"obi-metric-pairs/w3c.json",pair_sha256:$pair,state:"captured"},
      {id:"java-w3c-before",kind:"java",reference:"phases/w3c-before/java-diagnostics.txt",sha256:$before_java,state:"captured"},
      {id:"w3c-before",identity_reference:"phases/w3c-before/obi-identity.json",identity_sha256:$before_id,kind:"phase",state:"captured"},
      {id:"w3c-after",identity_reference:"phases/w3c-after/obi-identity.json",identity_sha256:$after_id,kind:"phase",state:"captured"},
      {id:"java-w3c-after",kind:"java",reference:"phases/w3c-after/java-diagnostics.txt",sha256:$after_java,state:"captured"},
      {id:"java-diagnostic-nondisclosure-header",kind:"java",reference:"phases/diagnostic-nondisclosure-header/java-diagnostics.txt",sha256:$header_java,state:"captured"},
      {id:"diagnostic-java-endpoint",kind:"artifact",reference:"diagnostic-nondisclosure-java-endpoint.txt",sha256:$endpoint,state:"captured"},
      {id:"diagnostic-java-header",kind:"artifact",reference:"diagnostic-nondisclosure-java-header.txt",sha256:$header,state:"captured"},
      {id:"diagnostic-java-transport",kind:"artifact",reference:"diagnostic-nondisclosure-java-transport-configuration.txt",sha256:$transport_sha,state:"captured"},
      {id:"diagnostic-obi-metrics",kind:"artifact",reference:"diagnostic-nondisclosure-obi-metrics.prom",sha256:$metrics,state:"captured"},
      {id:"diagnostic-obi-log",kind:"artifact",reference:"diagnostic-nondisclosure-obi.log",sha256:$obi_log,state:"captured"},
      {id:"diagnostic-java-log",kind:"artifact",reference:"diagnostic-nondisclosure-java.log",sha256:$java_log,state:"captured"}],
      id:"diagnostic-nondisclosure",not_applicable_reason:null,ordinal:1,state:"complete",
      status_references:[{reference:"scenario-w3c-status.json",sha256:$w3c_status},{reference:"scenario-diagnostic-nondisclosure-status.json",sha256:$report}]}]
  ' "$boundary" >/dev/null || return 1
  validate_metric_pair "$directory" || return 1
  assert_java_diagnostics "$directory/phases/w3c-before/java-diagnostics.txt" || return 1
  assert_java_diagnostics "$directory/phases/w3c-after/java-diagnostics.txt" || return 1
  assert_java_diagnostics "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt" || return 1
  cmp -s -- "$directory/${SURFACE_REFERENCES[1]}" \
    "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt"
}

validate_raw_closure() {
  local expected_paths="$TEMP_DIR/raw-expected"
  local expected_unsorted="$TEMP_DIR/raw-expected-unsorted"
  local observed="$TEMP_DIR/raw-observed"
  local top_observed="$TEMP_DIR/raw-top-observed" dirs="$TEMP_DIR/raw-dirs" files="$TEMP_DIR/raw-files"
  local child_dirs="$TEMP_DIR/raw-child-dirs"
  local id="" reference="" terminal_reference="" path="" metadata="" links="" expected_links="" relative_dir=""
  local size="" total=0 matrix_total=0

  [[ "$(stat -Lc '%u:%a' -- "$MATRIX_ROOT")" == "$EUID:700" ]] || return 1
  find "$MATRIX_ROOT" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' >"$top_observed" || return 1
  LC_ALL=C sort -o "$top_observed" "$top_observed" || return 1
  if [[ -d "$MATRIX_ROOT/public" && ! -L "$MATRIX_ROOT/public" ]]; then
    [[ "$(<"$top_observed")" == $'cells\td\npublic\td' ]] || return 1
    [[ "$(stat -Lc '%h' -- "$MATRIX_ROOT")" == 4 ]] || return 1
  else
    [[ "$(<"$top_observed")" == $'cells\td' ]] || return 1
    [[ "$(stat -Lc '%h' -- "$MATRIX_ROOT")" == 3 ]] || return 1
  fi
  [[ -d "$MATRIX_ROOT/cells" && ! -L "$MATRIX_ROOT/cells" ]] || return 1
  : >"$expected_unsorted" || return 1
  for id in "${CELL_IDS[@]}"; do
    [[ -d "$MATRIX_ROOT/cells/$id" && ! -L "$MATRIX_ROOT/cells/$id" ]] || return 1
    printf '%s\td\n' "$id" >>"$expected_unsorted" || return 1
    for reference in environment.txt source-state.txt source-tree.manifest git-status.txt \
      bridge-source-revision.txt bridge-source-tree.sha256 bridge-artifacts.json \
      official-javaagent.json run-status.json terminal-java-diagnostics.json terminal-obi-metrics.json \
      obi-metric-boundary-index.json .obi-metric-boundary-index.freeze \
      scenario-w3c-status.json scenario-w3c.json scenario-w3c.stderr.log \
      "$REPORT_REFERENCE" obi-metric-pairs/w3c.json \
      phases/w3c-before/obi-metrics.prom phases/w3c-before/obi-identity.json \
      phases/w3c-before/java-diagnostics.txt phases/w3c-after/obi-metrics.prom \
      phases/w3c-after/obi-identity.json phases/w3c-after/java-diagnostics.txt \
      phases/diagnostic-nondisclosure-header/java-diagnostics.txt \
      "${SURFACE_REFERENCES[@]}"; do
      printf '%s/%s\tf\n' "$id" "$reference" >>"$expected_unsorted" || return 1
    done
    bounded_regular_file "$MATRIX_ROOT/cells/$id/terminal-java-diagnostics.json" "$MAX_JAVA_BYTES" 1 || return 1
    terminal_reference="$(jq -er -s 'if length == 1 then .[0].reference else error("invalid terminal") end' \
      "$MATRIX_ROOT/cells/$id/terminal-java-diagnostics.json")" || return 1
    safe_reference "$terminal_reference" || return 1
    [[ "$terminal_reference" == phases/final/java-diagnostics.txt ||
      "$terminal_reference" == phases/diagnostic-nondisclosure-header/java-diagnostics.txt ]] || return 1
    printf '%s/%s\tf\n' "$id" "$terminal_reference" >>"$expected_unsorted" || return 1
    for relative_dir in obi-metric-pairs phases phases/w3c-before phases/w3c-after \
      phases/diagnostic-nondisclosure-header "${terminal_reference%/java-diagnostics.txt}"; do
      printf '%s/%s\td\n' "$id" "$relative_dir" >>"$expected_unsorted" || return 1
    done
  done
  LC_ALL=C sort -u -- "$expected_unsorted" >"$expected_paths" || return 1
  find "$MATRIX_ROOT/cells" -mindepth 1 -printf '%P\t%y\n' >"$observed" || return 1
  LC_ALL=C sort -o "$observed" "$observed" || return 1
  cmp -s -- "$expected_paths" "$observed" || return 1
  find "$MATRIX_ROOT/cells" -type d -printf '%p\n' >"$dirs" || return 1
  while IFS= read -r path; do
    metadata="$(stat -Lc '%u:%a:%h' -- "$path")" || return 1
    IFS=: read -r _ _ links <<<"$metadata"
    [[ "$metadata" == "$EUID:700:"* && "$links" =~ ^[0-9]+$ ]] || return 1
    find "$path" -mindepth 1 -maxdepth 1 -type d -printf '.\n' >"$child_dirs" || return 1
    expected_links="$(LC_ALL=C wc -l <"$child_dirs")" || return 1
    ((expected_links += 2))
    [[ "$links" == "$expected_links" ]] || return 1
  done <"$dirs"
  find "$MATRIX_ROOT/cells" -type f -printf '%p\n' >"$files" || return 1
  while IFS= read -r path; do
    [[ "$(stat -Lc '%u:%a:%h' -- "$path")" == "$EUID:600:1" ]] || return 1
  done <"$files"
  for id in "${CELL_IDS[@]}"; do
    total=0
    find "$MATRIX_ROOT/cells/$id" -type f -printf '%s\n' >"$files" || return 1
    while IFS= read -r size; do
      [[ "$size" =~ ^[0-9]+$ ]] || return 1
      ((size <= MAX_RAW_CELL_BYTES - total && size <= MAX_RAW_CELL_BYTES - matrix_total)) || return 1
      ((total += size))
      ((matrix_total += size))
    done <"$files"
  done
}

validate_cell() {
  local -r index="$1"
  local -r id="${CELL_IDS[$index]}"
  local -r ordinal="$((index + 1))"
  local directory="$MATRIX_ROOT/cells/$id"
  local agent="" transport="" level=""
  local report="$directory/$REPORT_REFERENCE"
  local scenario="$directory/scenario-w3c.json"
  local canaries="$TEMP_DIR/canaries-$ordinal.txt"
  local surface="" reference="" digest="" size="" lines=""
  local scenario_digest="" report_digest="" surface_set_digest="" canary_count="" canary_bytes=""
  local public_surfaces=""
  local boundary_digest="" freeze_digest="" freeze_payload="" pair_digest="" run_status_digest=""
  local terminal_java_digest="" terminal_obi_digest="" w3c_status_digest=""
  local surface_digest_input="$TEMP_DIR/surface-digests-$ordinal"
  local i=0

  IFS='-' read -r agent transport level <<<"$id"
  validate_environment "$directory/environment.txt" "$agent" "$transport" "$level" || return 1
  validate_source_provenance "$directory" || return 1
  validate_official_pin "$directory/official-javaagent.json" "$agent" || return 1
  validate_w3c_result "$scenario" || return 1
  scenario_digest="$(sha256_file "$scenario")" || return 1
  validate_report "$report" "$agent" "$transport" "$level" "$scenario_digest" || return 1
  validate_w3c_status "$directory" || return 1
  validate_terminal_evidence "$directory" || return 1
  validate_run_status_and_freeze "$directory" || return 1
  validate_boundary_authority "$directory" "$transport" || return 1
  build_canaries "$scenario" "$transport" "$canaries" || return 1
  canary_count="$(LC_ALL=C wc -l <"$canaries")" || return 1
  canary_bytes="$(stat -Lc '%s' -- "$canaries")" || return 1
  [[ "$canary_count" == "$(jq -r '.canary_count' "$report")" &&
    "$canary_bytes" == "$(jq -r '.canary_bytes' "$report")" ]] || return 1
  : >"$surface_digest_input" || return 1
  for i in "${!SURFACE_REFERENCES[@]}"; do
    surface="${SURFACE_NAMES[$i]}"; reference="${SURFACE_REFERENCES[$i]}"
    digest="$(sha256_file "$directory/$reference")" || return 1
    size="$(stat -Lc '%s' -- "$directory/$reference")" || return 1
    lines="$(LC_ALL=C wc -l <"$directory/$reference")" || return 1
    jq -e --arg name "$surface" --arg ref "$reference" --arg digest "$digest" --argjson size "$size" --argjson lines "$lines" --argjson i "$i" '
      .surfaces[$i].name == $name and .surfaces[$i].reference == $ref and
      .surfaces[$i].sha256 == $digest and .surfaces[$i].size_bytes == $size and
      .surfaces[$i].line_count == $lines
    ' "$report" >/dev/null || return 1
    assert_no_canaries "$canaries" "$directory/$reference" || return 1
    printf '%s\n' "$digest" >>"$surface_digest_input" || return 1
  done
  assert_java_diagnostics "$directory/${SURFACE_REFERENCES[0]}" || return 1
  assert_java_diagnostics "$directory/${SURFACE_REFERENCES[1]}" || return 1
  assert_transport_configuration "$directory/${SURFACE_REFERENCES[2]}" "$transport" || return 1
  assert_metrics "$directory/${SURFACE_REFERENCES[3]}" "$transport" || return 1
  assert_obi_log "$directory/${SURFACE_REFERENCES[4]}" "$level" "$transport" || return 1
  assert_java_log "$directory/${SURFACE_REFERENCES[5]}" || return 1
  report_digest="$(sha256_file "$report")" || return 1
  surface_set_digest="$(sha256_file "$surface_digest_input")" || return 1
  boundary_digest="$(sha256_file "$directory/obi-metric-boundary-index.json")" || return 1
  freeze_digest="$(sha256_file "$directory/.obi-metric-boundary-index.freeze")" || return 1
  freeze_payload="$(<"$directory/.obi-metric-boundary-index.freeze")"
  pair_digest="$(sha256_file "$directory/obi-metric-pairs/w3c.json")" || return 1
  run_status_digest="$(sha256_file "$directory/run-status.json")" || return 1
  terminal_java_digest="$(sha256_file "$directory/terminal-java-diagnostics.json")" || return 1
  terminal_obi_digest="$(sha256_file "$directory/terminal-obi-metrics.json")" || return 1
  w3c_status_digest="$(sha256_file "$directory/scenario-w3c-status.json")" || return 1
  public_surfaces="$(jq -ce '[.surfaces[] |
    {canary_match_count,line_count,name,schema_valid,sha256,size_bytes}]' "$report")" || return 1
  jq -cnS --arg agent "$agent" --arg transport "$transport" --arg level "$level" \
    --arg report_sha "$report_digest" --arg surface_sha "$surface_set_digest" --arg canary_source_sha "$scenario_digest" \
    --arg boundary_sha "$boundary_digest" --arg freeze_sha "$freeze_digest" --arg freeze_payload "$freeze_payload" \
    --arg pair_sha "$pair_digest" --arg run_status_sha "$run_status_digest" --arg terminal_java_sha "$terminal_java_digest" \
    --arg terminal_obi_sha "$terminal_obi_digest" --arg w3c_status_sha "$w3c_status_digest" \
    --argjson canary_count "$canary_count" --argjson canary_bytes "$canary_bytes" \
    --argjson surfaces "$public_surfaces" --argjson ordinal "$ordinal" '
      {agent_distribution:$agent,authority:{artifact_count:6,boundary_complete:true,
         boundary_freeze:{payload:$freeze_payload,sha256:$freeze_sha},boundary_index_sha256:$boundary_sha,
         metric_pair_sha256:$pair_sha,run_status_sha256:$run_status_sha,status_only:true,
         terminal_java_sha256:$terminal_java_sha,terminal_obi_sha256:$terminal_obi_sha,
         w3c_result_sha256:$canary_source_sha,w3c_status_sha256:$w3c_status_sha},
       canary_bytes:$canary_bytes,canary_count:$canary_count,canary_source_sha256:$canary_source_sha,
       diagnostic_report_sha256:$report_sha,obi_log_level:$level,ordinal:$ordinal,
       selected_transport:$transport,status:"passed",tls_protocol:"TLSv1.3",
       surface_set_sha256:$surface_sha,surfaces:$surfaces}
    ' >>"$TEMP_DIR/cells.jsonl" || return 1
}

write_public_verify_script() {
  local -r output="$1"

  write_public_verify_script_v2 "$output" || return 1
  : <<'OBSOLETE_PUBLIC_VERIFY_V1'

  # shellcheck disable=SC2016
  printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' 'IFS=$'"'"'\n\t'"'" \
    'root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"' \
    'expected=$'"'"'README.md\nSANITIZATION.md\nSHA256SUMS\nmatrix-summary.json\nrun-identity.json\nverify.sh'"'" \
    'observed="$(find "$root" -mindepth 1 -maxdepth 1 -printf '"'"'%f\t%y\n'"'"' | LC_ALL=C sort)"' \
    'expected_typed="$(printf '"'"'%s\tf\n'"'"' README.md SANITIZATION.md SHA256SUMS matrix-summary.json run-identity.json verify.sh | LC_ALL=C sort)"' \
    '[[ "$observed" == "$expected_typed" ]]' \
    'while IFS= read -r file; do [[ -f "$root/$file" && ! -L "$root/$file" && "$(stat -Lc '"'"'%a:%h'"'"' -- "$root/$file")" == 644:1 ]]; done <<<"$expected"' \
    'manifest_expected=$'"'"'README.md\nSANITIZATION.md\nmatrix-summary.json\nrun-identity.json\nverify.sh'"'" \
    'manifest_observed="$(awk '"'"'{ if (NF != 2 || $1 !~ /^[0-9a-f]{64}$/) exit 2; print $2 }'"'"' "$root/SHA256SUMS")"' \
    '[[ "$manifest_observed" == "$manifest_expected" ]]' \
    '(cd -- "$root" && sha256sum --check --strict SHA256SUMS)' \
    'summary="$(jq -ceS -s '"'"'if length == 1 and (.[0] | keys == ["acceptance_evidence","cells","evidence_class","evidence_id","matrix","runtime_contract","schema","status"] and .schema == "obi-diagnostic-nondisclosure-public-matrix-v1" and .status == "passed" and .acceptance_evidence == false and .evidence_class == "focused_non_acceptance" and (.evidence_id | test("^diagnostic-nondisclosure-[0-9a-f]{12}-[0-9a-f]{16}$")) and .matrix == {agent_distributions:["otel","splunk"],cell_count:8,obi_log_levels:["info","debug"],selected_transports:["getsockopt","unix"]} and .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and (.cells | type == "array" and length == 8) and [.cells[].ordinal] == [1,2,3,4,5,6,7,8] and [.cells[].agent_distribution] == ["otel","otel","otel","otel","splunk","splunk","splunk","splunk"] and [.cells[].selected_transport] == ["getsockopt","getsockopt","unix","unix","getsockopt","getsockopt","unix","unix"] and [.cells[].obi_log_level] == ["info","debug","info","debug","info","debug","info","debug"] and all(.cells[]; keys == ["agent_distribution","authority","canary_bytes","canary_count","canary_source_sha256","diagnostic_report_sha256","obi_log_level","ordinal","selected_transport","status","surface_set_sha256","surfaces","tls_protocol"] and (.authority | keys == ["artifact_count","boundary_complete","boundary_freeze","boundary_index_sha256","metric_pair_sha256","run_status_sha256","status_only","terminal_java_sha256","terminal_obi_sha256","w3c_result_sha256","w3c_status_sha256"] and .artifact_count == 6 and .boundary_complete == true and .status_only == true and (.boundary_freeze | keys == ["payload","sha256"] and (.payload | test("^obi-metric-boundary-index-frozen-v1:[0-9a-f]{64}$")) and (.sha256 | test("^[0-9a-f]{64}$"))) and all([.boundary_index_sha256,.metric_pair_sha256,.run_status_sha256,.terminal_java_sha256,.terminal_obi_sha256,.w3c_result_sha256,.w3c_status_sha256][]; test("^[0-9a-f]{64}$"))) and .authority.boundary_freeze.payload == ("obi-metric-boundary-index-frozen-v1:" + .authority.boundary_index_sha256) and .authority.w3c_result_sha256 == .canary_source_sha256 and .status == "passed" and .tls_protocol == "TLSv1.3" and (.canary_count | type == "number" and floor == . and . >= 6 and . <= 128) and (.canary_bytes | type == "number" and floor == . and . >= 1 and . <= 16384) and (.canary_source_sha256 | test("^[0-9a-f]{64}$")) and (.diagnostic_report_sha256 | test("^[0-9a-f]{64}$")) and (.surface_set_sha256 | test("^[0-9a-f]{64}$")) and (.surfaces | type == "array" and length == 6) and [.surfaces[].name] == ["java_endpoint","java_header","java_transport_configuration","obi_metrics","obi_log","java_log"] and all(.surfaces[]; keys == ["canary_match_count","line_count","name","schema_valid","sha256","size_bytes"] and .canary_match_count == 0 and .schema_valid == true and (.sha256 | test("^[0-9a-f]{64}$")) and (.line_count | type == "number" and floor == . and . >= 1) and (.size_bytes | type == "number" and floor == . and . >= 1)))) then .[0] else error("invalid public summary") end'"'"' "$root/matrix-summary.json")"' \
    '[[ "$(<"$root/matrix-summary.json")" == "$summary" ]]' \
    'jq -e '"'"'all(.cells[].surfaces[]; if .name == "java_endpoint" or .name == "java_header" then .line_count == 1 and .size_bytes <= 16384 elif .name == "java_transport_configuration" then .line_count == 1 and .size_bytes <= 256 elif .name == "obi_metrics" then .line_count <= 20000 and .size_bytes <= 8388608 elif .name == "obi_log" then .line_count <= 10000 and .size_bytes <= 2097152 else .line_count <= 10000 and .size_bytes <= 1048576 end)'"'"' "$root/matrix-summary.json" >/dev/null' \
    'for index in {0..7}; do surface_sha="$(jq -er --argjson index "$index" '"'"'.cells[$index].surfaces[].sha256'"'"' "$root/matrix-summary.json" | sha256sum)"; surface_sha="${surface_sha%% *}"; [[ "$surface_sha" == "$(jq -er --argjson index "$index" '"'"'.cells[$index].surface_set_sha256'"'"' "$root/matrix-summary.json")" ]]; freeze_payload="$(jq -er --argjson index "$index" '"'"'.cells[$index].authority.boundary_freeze.payload'"'"' "$root/matrix-summary.json")"; freeze_sha="$({ printf '"'"'%s\n'"'"' "$freeze_payload" || exit $?; } | sha256sum)"; freeze_sha="${freeze_sha%% *}"; [[ "$freeze_sha" == "$(jq -er --argjson index "$index" '"'"'.cells[$index].authority.boundary_freeze.sha256'"'"' "$root/matrix-summary.json")" ]]; done' \
    'summary_sha="$(sha256sum <"$root/matrix-summary.json")"; summary_sha="${summary_sha%% *}"; [[ "$summary_sha" =~ ^[0-9a-f]{64}$ ]]' \
    'evidence_id="$(jq -er '"'"'.evidence_id'"'"' <<<"$summary")"' \
    'identity="$(jq -ceS -s --arg digest "$summary_sha" --arg evidence_id "$evidence_id" '"'"'if length == 1 and (.[0] | keys == ["bridge_artifacts","compose_sha256","evidence_id","matrix_summary_sha256","official_agent_pin_sha256","official_agents","patch_identity_sha256","revision","run_sha256","runner","runner_sha256","runtime_contract","schema","source_tree_manifest_schema","source_tree_sha256","tracked_patch_sha256","verifier_sha256","workflow"] and .schema == "obi-diagnostic-nondisclosure-public-run-identity-v1" and (.bridge_artifacts | keys == ["obi_java_agent_sha256","obi_otel_extension_sha256"] and all(.[]; type == "string" and test("^[0-9a-f]{64}$"))) and .evidence_id == $evidence_id and .matrix_summary_sha256 == $digest and (.revision | test("^[0-9a-f]{40}$")) and .source_tree_manifest_schema == "git-tree-v2" and all([.compose_sha256,.patch_identity_sha256,.run_sha256,.runner_sha256,.source_tree_sha256,.tracked_patch_sha256,.verifier_sha256,.official_agent_pin_sha256.otel,.official_agent_pin_sha256.splunk][]; type == "string" and test("^[0-9a-f]{64}$")) and (.official_agent_pin_sha256 | keys == ["otel","splunk"]) and .official_agents == {otel:{distribution:"otel",sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",version:"2.28.1"},splunk:{distribution:"splunk",embedded_opentelemetry_version:"2.28.1",sha256:"70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",url:"https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar",version:"2.28.0"}} and .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and .runner == {arch:"X64",os:"Linux"} and (.workflow | keys == ["event","name","path","repository","run_attempt","run_id","run_url","trigger_sha","workflow_blob_sha256","workflow_ref","workflow_sha"] and (.event == "push" or .event == "workflow_dispatch") and .name == "Java diagnostic nondisclosure matrix" and .path == ".github/workflows/java_diagnostic_nondisclosure.yml" and (.repository | test("^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")) and (.run_id | test("^[1-9][0-9]{0,18}$")) and (.run_attempt | test("^[1-9][0-9]{0,18}$")) and (.trigger_sha | test("^[0-9a-f]{40}$")) and (.workflow_sha | test("^[0-9a-f]{40}$")) and (.workflow_blob_sha256 | test("^[0-9a-f]{64}$")) and (.workflow_ref | type == "string" and length <= 512 and startswith(.repository + "/" + .path + "@")) and .run_url == ("https://github.com/" + .repository + "/actions/runs/" + .run_id + "/attempts/" + .run_attempt) and (.event != "push" or .trigger_sha == .revision)) then .[0] else error("invalid public identity") end'"'"' "$root/run-identity.json")"' \
    '[[ "$(<"$root/run-identity.json")" == "$identity" ]]' \
    'otel_pin="$(jq -cS '"'"'.official_agents.otel'"'"' "$root/run-identity.json" | sha256sum)"; otel_pin="${otel_pin%% *}"; splunk_pin="$(jq -cS '"'"'.official_agents.splunk'"'"' "$root/run-identity.json" | sha256sum)"; splunk_pin="${splunk_pin%% *}"; [[ "$otel_pin" == "$(jq -er '"'"'.official_agent_pin_sha256.otel'"'"' <<<"$identity")" && "$splunk_pin" == "$(jq -er '"'"'.official_agent_pin_sha256.splunk'"'"' <<<"$identity")" ]]' \
    'tracked="$(jq -er '"'"'.tracked_patch_sha256'"'"' <<<"$identity")"; [[ "$tracked" == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ]]; tree="$(jq -er '"'"'.source_tree_sha256'"'"' <<<"$identity")"; patch="$(printf '"'"'%s\n%s\n%s\n'"'"' "$tracked" "$tree" "$tracked" | sha256sum)"; patch="${patch%% *}"; [[ "$patch" == "$(jq -er '"'"'.patch_identity_sha256'"'"' <<<"$identity")" ]]' \
    'cells_sha="$(jq -cS '"'"'.cells[]'"'"' "$root/matrix-summary.json" | sha256sum)"; cells_sha="${cells_sha%% *}"; revision="$(jq -er '"'"'.revision'"'"' <<<"$identity")"; [[ "$evidence_id" == "diagnostic-nondisclosure-${revision:0:12}-${cells_sha:0:16}" ]]' >"$output" || return 1
OBSOLETE_PUBLIC_VERIFY_V1
}

write_public_verify_script_v2() {
  local -r output="$1"
  local content=""

  IFS= read -r -d '' content <<'PUBLIC_VERIFY' || [[ -n "$content" ]]
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'README.md\t f\nSANITIZATION.md\t f\nSHA256SUMS\t f\nmatrix-summary.json\t f\nrun-identity.json\t f\nverify.sh\t f'
observed="$(find "$root" -mindepth 1 -maxdepth 1 -printf '%f\t %y\n' | LC_ALL=C sort)"
[[ "$observed" == "$expected" ]]
for file in README.md SANITIZATION.md SHA256SUMS matrix-summary.json run-identity.json verify.sh; do
  [[ -f "$root/$file" && ! -L "$root/$file" && "$(stat -Lc '%a:%h' -- "$root/$file")" == 644:1 ]]
done
manifest_expected=$'README.md\nSANITIZATION.md\nmatrix-summary.json\nrun-identity.json\nverify.sh'
manifest_observed="$(awk '{ if (NF != 2 || $1 !~ /^[0-9a-f]{64}$/) exit 2; print $2 }' "$root/SHA256SUMS")"
[[ "$manifest_observed" == "$manifest_expected" ]]
(cd -- "$root" && sha256sum --check --strict SHA256SUMS)
summary="$(jq -ceS -s '
  if length == 1 then .[0] as $s |
    if ($s | keys == ["acceptance_evidence","cells","evidence_class","evidence_id","matrix","runtime_contract","schema","status"] and
      .schema == "obi-diagnostic-nondisclosure-public-matrix-v1" and .status == "passed" and
      .acceptance_evidence == false and .evidence_class == "focused_non_acceptance" and
      (.evidence_id | test("^diagnostic-nondisclosure-[0-9a-f]{12}-[0-9a-f]{16}$")) and
      .matrix == {agent_distributions:["otel","splunk"],cell_count:8,obi_log_levels:["info","debug"],selected_transports:["getsockopt","unix"]} and
      .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
      (.cells | type == "array" and length == 8) and [.cells[].ordinal] == [1,2,3,4,5,6,7,8] and
      [.cells[].agent_distribution] == ["otel","otel","otel","otel","splunk","splunk","splunk","splunk"] and
      [.cells[].selected_transport] == ["getsockopt","getsockopt","unix","unix","getsockopt","getsockopt","unix","unix"] and
      [.cells[].obi_log_level] == ["info","debug","info","debug","info","debug","info","debug"] and
      all(.cells[];
        keys == ["agent_distribution","authority","canary_bytes","canary_count","canary_source_sha256","diagnostic_report_sha256","obi_log_level","ordinal","selected_transport","status","surface_set_sha256","surfaces","tls_protocol"] and
        (.authority | keys == ["artifact_count","boundary_complete","boundary_freeze","boundary_index_sha256","metric_pair_sha256","run_status_sha256","status_only","terminal_java_sha256","terminal_obi_sha256","w3c_result_sha256","w3c_status_sha256"] and
          .artifact_count == 6 and .boundary_complete == true and .status_only == true and
          (.boundary_freeze | keys == ["payload","sha256"] and (.payload | test("^obi-metric-boundary-index-frozen-v1:[0-9a-f]{64}$")) and (.sha256 | test("^[0-9a-f]{64}$"))) and
          all([.boundary_index_sha256,.metric_pair_sha256,.run_status_sha256,.terminal_java_sha256,.terminal_obi_sha256,.w3c_result_sha256,.w3c_status_sha256][]; test("^[0-9a-f]{64}$"))) and
        .authority.boundary_freeze.payload == ("obi-metric-boundary-index-frozen-v1:" + .authority.boundary_index_sha256) and
        .authority.w3c_result_sha256 == .canary_source_sha256 and .status == "passed" and .tls_protocol == "TLSv1.3" and
        (.canary_count | type == "number" and floor == . and . >= 6 and . <= 128) and
        (.canary_bytes | type == "number" and floor == . and . >= 1 and . <= 16384) and
        (.canary_source_sha256 | test("^[0-9a-f]{64}$")) and (.diagnostic_report_sha256 | test("^[0-9a-f]{64}$")) and
        (.surface_set_sha256 | test("^[0-9a-f]{64}$")) and (.surfaces | type == "array" and length == 6) and
        [.surfaces[].name] == ["java_endpoint","java_header","java_transport_configuration","obi_metrics","obi_log","java_log"] and
        all(.surfaces[];
          keys == ["canary_match_count","line_count","name","schema_valid","sha256","size_bytes"] and
          .canary_match_count == 0 and .schema_valid == true and (.sha256 | test("^[0-9a-f]{64}$")) and
          (.line_count | type == "number" and floor == . and . >= 1) and (.size_bytes | type == "number" and floor == . and . >= 1) and
          (if .name == "java_endpoint" or .name == "java_header" then .line_count == 1 and .size_bytes <= 16384
           elif .name == "java_transport_configuration" then .line_count == 1 and .size_bytes <= 256
           elif .name == "obi_metrics" then .line_count <= 20000 and .size_bytes <= 8388608
           elif .name == "obi_log" then .line_count <= 10000 and .size_bytes <= 2097152
           else .line_count <= 10000 and .size_bytes <= 1048576 end))))
    then $s else error("invalid public summary") end
  else error("invalid public summary document count") end
' "$root/matrix-summary.json")"
[[ "$(<"$root/matrix-summary.json")" == "$summary" ]]
for index in {0..7}; do
  surface_sha="$(jq -er --argjson index "$index" '.cells[$index].surfaces[].sha256' "$root/matrix-summary.json" | sha256sum)"
  surface_sha="${surface_sha%% *}"
  [[ "$surface_sha" == "$(jq -er --argjson index "$index" '.cells[$index].surface_set_sha256' "$root/matrix-summary.json")" ]]
  freeze_payload="$(jq -er --argjson index "$index" '.cells[$index].authority.boundary_freeze.payload' "$root/matrix-summary.json")"
  freeze_sha="$(printf '%s\n' "$freeze_payload" | sha256sum)"; freeze_sha="${freeze_sha%% *}"
  [[ "$freeze_sha" == "$(jq -er --argjson index "$index" '.cells[$index].authority.boundary_freeze.sha256' "$root/matrix-summary.json")" ]]
done
summary_sha="$(sha256sum <"$root/matrix-summary.json")"; summary_sha="${summary_sha%% *}"
evidence_id="$(jq -er '.evidence_id' <<<"$summary")"
identity="$(jq -ceS -s --arg summary_sha "$summary_sha" --arg evidence_id "$evidence_id" '
  if length == 1 then .[0] as $i |
    if ($i | keys == ["bridge_artifacts","compose_sha256","evidence_id","matrix_summary_sha256","official_agent_pin_sha256","official_agents","patch_identity_sha256","revision","run_sha256","runner","runner_sha256","runtime_contract","schema","source_tree_manifest_schema","source_tree_sha256","tracked_patch_sha256","verifier_sha256","workflow"] and
      .schema == "obi-diagnostic-nondisclosure-public-run-identity-v1" and .evidence_id == $evidence_id and .matrix_summary_sha256 == $summary_sha and
      (.revision | test("^[0-9a-f]{40}$")) and .source_tree_manifest_schema == "git-tree-v2" and
      (.bridge_artifacts | keys == ["obi_java_agent_sha256","obi_otel_extension_sha256"] and all(.[]; type == "string" and test("^[0-9a-f]{64}$"))) and
      all([.compose_sha256,.patch_identity_sha256,.run_sha256,.runner_sha256,.source_tree_sha256,.tracked_patch_sha256,.verifier_sha256,.official_agent_pin_sha256.otel,.official_agent_pin_sha256.splunk][]; type == "string" and test("^[0-9a-f]{64}$")) and
      (.official_agent_pin_sha256 | keys == ["otel","splunk"]) and
      .official_agents == {otel:{distribution:"otel",sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",version:"2.28.1"},splunk:{distribution:"splunk",embedded_opentelemetry_version:"2.28.1",sha256:"70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",url:"https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar",version:"2.28.0"}} and
      .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
      .runner == {arch:"X64",os:"Linux"} and
      (.workflow as $w | ($w | keys == ["event","name","path","repository","run_attempt","run_id","run_url","trigger_sha","workflow_blob_sha256","workflow_ref","workflow_sha"]) and
        ($w.event == "push" or $w.event == "workflow_dispatch") and $w.name == "Java diagnostic nondisclosure matrix" and
        $w.path == ".github/workflows/java_diagnostic_nondisclosure.yml" and
        ($w.repository | test("^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")) and
        ($w.run_id | test("^[1-9][0-9]{0,18}$")) and ($w.run_attempt | test("^[1-9][0-9]{0,18}$")) and
        ($w.trigger_sha | test("^[0-9a-f]{40}$")) and ($w.workflow_sha | test("^[0-9a-f]{40}$")) and
        ($w.workflow_blob_sha256 | test("^[0-9a-f]{64}$")) and
        ($w.workflow_ref | test("^[^\\n]{1,512}$") and startswith($w.repository + "/" + $w.path + "@")) and
        $w.run_url == ("https://github.com/" + $w.repository + "/actions/runs/" + $w.run_id + "/attempts/" + $w.run_attempt) and
        ($w.event != "push" or $w.trigger_sha == $i.revision)))
    then $i else error("invalid public identity") end
  else error("invalid public identity document count") end
' "$root/run-identity.json")"
[[ "$(<"$root/run-identity.json")" == "$identity" ]]
otel_pin="$(jq -cS '.official_agents.otel' "$root/run-identity.json" | sha256sum)"; otel_pin="${otel_pin%% *}"
splunk_pin="$(jq -cS '.official_agents.splunk' "$root/run-identity.json" | sha256sum)"; splunk_pin="${splunk_pin%% *}"
[[ "$otel_pin" == "$(jq -er '.official_agent_pin_sha256.otel' <<<"$identity")" && "$splunk_pin" == "$(jq -er '.official_agent_pin_sha256.splunk' <<<"$identity")" ]]
empty_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
tracked="$(jq -er '.tracked_patch_sha256' <<<"$identity")"; [[ "$tracked" == "$empty_sha" ]]
tree="$(jq -er '.source_tree_sha256' <<<"$identity")"
patch="$(printf '%s\n%s\n%s\n' "$empty_sha" "$tree" "$empty_sha" | sha256sum)"; patch="${patch%% *}"
[[ "$patch" == "$(jq -er '.patch_identity_sha256' <<<"$identity")" ]]
cells_sha="$(jq -cS '.cells[]' "$root/matrix-summary.json" | sha256sum)"; cells_sha="${cells_sha%% *}"
revision="$(jq -er '.revision' <<<"$identity")"
[[ "$evidence_id" == "diagnostic-nondisclosure-${revision:0:12}-${cells_sha:0:16}" ]]
PUBLIC_VERIFY
  printf '%s\n' "$content" >"$output" || return 1
}

validate_public_directory() {
  local -r directory="$1"
  local observed="" expected_inventory="" reference="" digest="" summary="" identity="" summary_digest="" evidence_id=""
  local expected_surface_digest="" observed_surface_digest="" freeze_digest="" freeze_payload=""
  local cells_digest="" expected_evidence_id="" revision="" index=0
  local run_digest="" compose_digest="" runner_digest="" verifier_digest="" computed_patch=""
  local checksums="$TEMP_DIR/public-expected-checksums"
  local canonical_cells="$TEMP_DIR/public-canonical-cells"

  [[ -d "$directory" && ! -L "$directory" && "$(stat -Lc '%u:%a:%h' -- "$directory")" == "$EUID:755:2" ]] || return 1
  observed="$(find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)" || return 1
  expected_inventory="$(printf '%s\tf\n' README.md SANITIZATION.md SHA256SUMS matrix-summary.json run-identity.json verify.sh | LC_ALL=C sort)" || return 1
  [[ "$observed" == "$expected_inventory" ]] || return 1
  for reference in README.md SANITIZATION.md SHA256SUMS matrix-summary.json run-identity.json verify.sh; do
    [[ -f "$directory/$reference" && ! -L "$directory/$reference" &&
      "$(stat -Lc '%u:%a:%h' -- "$directory/$reference")" == "$EUID:644:1" ]] || return 1
  done
  : >"$checksums" || return 1
  for reference in README.md SANITIZATION.md matrix-summary.json run-identity.json verify.sh; do
    digest="$(sha256_file "$directory/$reference")" || return 1
    printf '%s  %s\n' "$digest" "$reference" >>"$checksums" || return 1
  done
  cmp -s -- "$checksums" "$directory/SHA256SUMS" || return 1
  summary="$(jq -ceS -s '
    if length == 1 and (.[0] | keys == ["acceptance_evidence","cells","evidence_class","evidence_id","matrix","runtime_contract","schema","status"] and
      .schema == "obi-diagnostic-nondisclosure-public-matrix-v1" and .status == "passed" and
      .acceptance_evidence == false and .evidence_class == "focused_non_acceptance" and
      (.evidence_id | test("^diagnostic-nondisclosure-[0-9a-f]{12}-[0-9a-f]{16}$")) and
      .matrix == {agent_distributions:["otel","splunk"],cell_count:8,obi_log_levels:["info","debug"],selected_transports:["getsockopt","unix"]} and
      .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
      (.cells | type == "array" and length == 8) and [.cells[].ordinal] == [1,2,3,4,5,6,7,8] and
      [.cells[].agent_distribution] == ["otel","otel","otel","otel","splunk","splunk","splunk","splunk"] and
      [.cells[].selected_transport] == ["getsockopt","getsockopt","unix","unix","getsockopt","getsockopt","unix","unix"] and
      [.cells[].obi_log_level] == ["info","debug","info","debug","info","debug","info","debug"] and
      all(.cells[]; keys == ["agent_distribution","authority","canary_bytes","canary_count","canary_source_sha256","diagnostic_report_sha256","obi_log_level","ordinal","selected_transport","status","surface_set_sha256","surfaces","tls_protocol"] and
        (.authority | keys == ["artifact_count","boundary_complete","boundary_freeze","boundary_index_sha256","metric_pair_sha256","run_status_sha256","status_only","terminal_java_sha256","terminal_obi_sha256","w3c_result_sha256","w3c_status_sha256"] and
          .artifact_count == 6 and .boundary_complete == true and .status_only == true and
          (.boundary_freeze | keys == ["payload","sha256"] and (.payload | test("^obi-metric-boundary-index-frozen-v1:[0-9a-f]{64}$")) and (.sha256 | test("^[0-9a-f]{64}$"))) and
          all([.boundary_index_sha256,.metric_pair_sha256,.run_status_sha256,.terminal_java_sha256,.terminal_obi_sha256,.w3c_result_sha256,.w3c_status_sha256][]; test("^[0-9a-f]{64}$"))) and
        .authority.boundary_freeze.payload == ("obi-metric-boundary-index-frozen-v1:" + .authority.boundary_index_sha256) and
        .authority.w3c_result_sha256 == .canary_source_sha256 and .status == "passed" and .tls_protocol == "TLSv1.3" and
        (.canary_count | type == "number" and floor == . and . >= 6 and . <= 128) and
        (.canary_bytes | type == "number" and floor == . and . >= 1 and . <= 16384) and
        (.canary_source_sha256 | test("^[0-9a-f]{64}$")) and
        (.diagnostic_report_sha256 | test("^[0-9a-f]{64}$")) and (.surface_set_sha256 | test("^[0-9a-f]{64}$")) and
        (.surfaces | type == "array" and length == 6) and
        [.surfaces[].name] == ["java_endpoint","java_header","java_transport_configuration","obi_metrics","obi_log","java_log"] and
        all(.surfaces[]; keys == ["canary_match_count","line_count","name","schema_valid","sha256","size_bytes"] and
          .canary_match_count == 0 and .schema_valid == true and (.sha256 | test("^[0-9a-f]{64}$")) and
          (.line_count | type == "number" and floor == . and . >= 1) and
          (.size_bytes | type == "number" and floor == . and . >= 1) and
          (if .name == "java_endpoint" or .name == "java_header" then .line_count == 1 and .size_bytes <= 16384
           elif .name == "java_transport_configuration" then .line_count == 1 and .size_bytes <= 256
           elif .name == "obi_metrics" then .line_count <= 20000 and .size_bytes <= 8388608
           elif .name == "obi_log" then .line_count <= 10000 and .size_bytes <= 2097152
           else .line_count <= 10000 and .size_bytes <= 1048576 end))))
    then .[0] else error("invalid public summary") end
  ' "$directory/matrix-summary.json")" || return 1
  [[ "$(<"$directory/matrix-summary.json")" == "$summary" ]] || return 1
  summary_digest="$(sha256_file "$directory/matrix-summary.json")" || return 1
  evidence_id="$(jq -er '.evidence_id' <<<"$summary")" || return 1
  run_digest="$(sha256_file "$TRUSTED_RUN_BLOB")" || return 1
  compose_digest="$(sha256_file "$TRUSTED_COMPOSE_BLOB")" || return 1
  runner_digest="$(sha256_file "$TRUSTED_RUNNER_BLOB")" || return 1
  verifier_digest="$(sha256_file "$TRUSTED_VERIFIER_BLOB")" || return 1
  sha256_lines computed_patch "$EMPTY_SHA256" "$SOURCE_TREE_SHA256" "$EMPTY_SHA256" || return 1
  [[ "$TRACKED_PATCH_SHA256" == "$EMPTY_SHA256" && "$PATCH_IDENTITY_SHA256" == "$computed_patch" ]] || return 1
  for index in {0..7}; do
    jq -er --argjson index "$index" '.cells[$index].surfaces[].sha256' \
      "$directory/matrix-summary.json" >"$TEMP_DIR/public-surface-digests" || return 1
    expected_surface_digest="$(sha256_file "$TEMP_DIR/public-surface-digests")" || return 1
    observed_surface_digest="$(jq -er --argjson index "$index" '.cells[$index].surface_set_sha256' \
      "$directory/matrix-summary.json")" || return 1
    [[ "$observed_surface_digest" == "$expected_surface_digest" ]] || return 1
    freeze_payload="$(jq -er --argjson index "$index" '.cells[$index].authority.boundary_freeze.payload' \
      "$directory/matrix-summary.json")" || return 1
    sha256_lines freeze_digest "$freeze_payload" || return 1
    [[ "$freeze_digest" == "$(jq -er --argjson index "$index" '.cells[$index].authority.boundary_freeze.sha256' \
      "$directory/matrix-summary.json")" ]] || return 1
  done
  identity="$(jq -ceS -s --arg digest "$summary_digest" --arg evidence_id "$evidence_id" \
    --arg repository "$CI_REPOSITORY" --arg run_id "$CI_RUN_ID" --arg run_attempt "$CI_RUN_ATTEMPT" \
    --arg run_url "$CI_RUN_URL" --arg event "$CI_EVENT" --arg runner_os "$CI_RUNNER_OS" --arg runner_arch "$CI_RUNNER_ARCH" \
    --arg bridge_java "$BRIDGE_JAVA_SHA256" --arg bridge_extension "$BRIDGE_EXTENSION_SHA256" \
    --arg revision "$HEAD_REVISION" --arg tree "$SOURCE_TREE_SHA256" --arg tree_schema "$SOURCE_TREE_MANIFEST_SCHEMA" \
    --arg tracked "$TRACKED_PATCH_SHA256" --arg patch "$PATCH_IDENTITY_SHA256" \
    --arg run "$run_digest" --arg compose "$compose_digest" --arg runner_sha "$runner_digest" --arg verifier "$verifier_digest" \
    --arg otel_pin "${OFFICIAL_PIN_DIGESTS[otel]}" --arg splunk_pin "${OFFICIAL_PIN_DIGESTS[splunk]}" \
    --arg trigger_sha "$CI_TRIGGER_SHA" --arg workflow_sha "$CI_WORKFLOW_SHA" \
    --arg workflow_ref "$CI_WORKFLOW_REF" --arg workflow_blob "$CI_WORKFLOW_BLOB_SHA256" '
    if length == 1 and (.[0] | keys == ["bridge_artifacts","compose_sha256","evidence_id","matrix_summary_sha256","official_agent_pin_sha256","official_agents","patch_identity_sha256","revision","run_sha256","runner","runner_sha256","runtime_contract","schema","source_tree_manifest_schema","source_tree_sha256","tracked_patch_sha256","verifier_sha256","workflow"] and
      .schema == "obi-diagnostic-nondisclosure-public-run-identity-v1" and .evidence_id == $evidence_id and
      .matrix_summary_sha256 == $digest and .revision == $revision and .source_tree_manifest_schema == $tree_schema and
      .source_tree_sha256 == $tree and .tracked_patch_sha256 == $tracked and .patch_identity_sha256 == $patch and
      .run_sha256 == $run and .compose_sha256 == $compose and .runner_sha256 == $runner_sha and .verifier_sha256 == $verifier and
      all([.compose_sha256,.patch_identity_sha256,.run_sha256,.runner_sha256,.source_tree_sha256,.tracked_patch_sha256,.verifier_sha256,.official_agent_pin_sha256.otel,.official_agent_pin_sha256.splunk][]; type == "string" and test("^[0-9a-f]{64}$")) and
      .bridge_artifacts == {obi_java_agent_sha256:$bridge_java,obi_otel_extension_sha256:$bridge_extension} and
      .official_agent_pin_sha256 == {otel:$otel_pin,splunk:$splunk_pin} and
      .official_agents == {otel:{distribution:"otel",sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",version:"2.28.1"},splunk:{distribution:"splunk",embedded_opentelemetry_version:"2.28.1",sha256:"70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",url:"https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar",version:"2.28.0"}} and
      .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
      .runner == {arch:$runner_arch,os:$runner_os} and
      .workflow == {event:$event,name:"Java diagnostic nondisclosure matrix",path:".github/workflows/java_diagnostic_nondisclosure.yml",repository:$repository,run_attempt:$run_attempt,run_id:$run_id,run_url:$run_url,trigger_sha:$trigger_sha,workflow_blob_sha256:$workflow_blob,workflow_ref:$workflow_ref,workflow_sha:$workflow_sha})
    then .[0] else error("invalid public identity") end
  ' "$directory/run-identity.json")" || return 1
  [[ "$(<"$directory/run-identity.json")" == "$identity" ]] || return 1
  revision="$(jq -er '.revision' <<<"$identity")" || return 1
  jq -cS '.cells[]' "$directory/matrix-summary.json" >"$canonical_cells" || return 1
  cells_digest="$(sha256_file "$canonical_cells")" || return 1
  expected_evidence_id="diagnostic-nondisclosure-${revision:0:12}-${cells_digest:0:16}"
  [[ "$evidence_id" == "$expected_evidence_id" ]]
}

build_public_candidate() {
  local candidate=""
  local summary="" identity="" cells="" cells_digest="" evidence_id="" summary_digest=""
  local run_digest="" compose_digest="" runner_digest="" verifier_digest="" reference="" digest=""

  create_public_candidate || return 1
  candidate="$PUBLIC_CANDIDATE"
  summary="$candidate/matrix-summary.json"
  identity="$candidate/run-identity.json"
  cells="$(jq -ceS -s 'if length == 8 then . else error("invalid cell count") end' "$TEMP_DIR/cells.jsonl")" || return 1
  cells_digest="$(sha256_file "$TEMP_DIR/cells.jsonl")" || return 1
  evidence_id="diagnostic-nondisclosure-${HEAD_REVISION:0:12}-${cells_digest:0:16}"
  jq -cnS --argjson cells "$cells" --arg evidence_id "$evidence_id" '
    {acceptance_evidence:false,cells:$cells,evidence_class:"focused_non_acceptance",evidence_id:$evidence_id,
     matrix:{agent_distributions:["otel","splunk"],cell_count:8,obi_log_levels:["info","debug"],selected_transports:["getsockopt","unix"]},
     runtime_contract:{java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"},
     schema:"obi-diagnostic-nondisclosure-public-matrix-v1",status:"passed"}
  ' >"$summary" || return 1
  summary_digest="$(sha256_file "$summary")" || return 1
  run_digest="$(sha256_file "$TRUSTED_RUN_BLOB")" || return 1
  compose_digest="$(sha256_file "$TRUSTED_COMPOSE_BLOB")" || return 1
  runner_digest="$(sha256_file "$TRUSTED_RUNNER_BLOB")" || return 1
  verifier_digest="$(sha256_file "$TRUSTED_VERIFIER_BLOB")" || return 1
  jq -cnS --arg revision "$HEAD_REVISION" --arg summary "$summary_digest" --arg evidence_id "$evidence_id" \
    --arg run "$run_digest" --arg compose "$compose_digest" --arg runner "$runner_digest" --arg verifier "$verifier_digest" \
    --arg tree "$SOURCE_TREE_SHA256" --arg tree_schema "$SOURCE_TREE_MANIFEST_SCHEMA" \
    --arg tracked "$TRACKED_PATCH_SHA256" --arg patch "$PATCH_IDENTITY_SHA256" \
    --arg otel "${OFFICIAL_PIN_DIGESTS[otel]}" --arg splunk "${OFFICIAL_PIN_DIGESTS[splunk]}" \
    --arg repository "$CI_REPOSITORY" --arg workflow_name "$PUBLIC_WORKFLOW_NAME" \
    --arg workflow_path "$PUBLIC_WORKFLOW_PATH" --arg run_url "$CI_RUN_URL" \
    --arg run_id "$CI_RUN_ID" --arg run_attempt "$CI_RUN_ATTEMPT" --arg event "$CI_EVENT" \
    --arg runner_os "$CI_RUNNER_OS" --arg runner_arch "$CI_RUNNER_ARCH" \
    --arg bridge_java "$BRIDGE_JAVA_SHA256" --arg bridge_extension "$BRIDGE_EXTENSION_SHA256" \
    --arg trigger_sha "$CI_TRIGGER_SHA" --arg workflow_sha "$CI_WORKFLOW_SHA" \
    --arg workflow_ref "$CI_WORKFLOW_REF" --arg workflow_blob "$CI_WORKFLOW_BLOB_SHA256" '
      {bridge_artifacts:{obi_java_agent_sha256:$bridge_java,obi_otel_extension_sha256:$bridge_extension},
       compose_sha256:$compose,evidence_id:$evidence_id,matrix_summary_sha256:$summary,official_agent_pin_sha256:{otel:$otel,splunk:$splunk},
       official_agents:{
         otel:{distribution:"otel",sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",version:"2.28.1"},
         splunk:{distribution:"splunk",embedded_opentelemetry_version:"2.28.1",sha256:"70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",url:"https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar",version:"2.28.0"}},
       patch_identity_sha256:$patch,revision:$revision,run_sha256:$run,runner_sha256:$runner,
       runner:{arch:$runner_arch,os:$runner_os},runtime_contract:{java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"},
       schema:"obi-diagnostic-nondisclosure-public-run-identity-v1",source_tree_manifest_schema:$tree_schema,
       source_tree_sha256:$tree,tracked_patch_sha256:$tracked,verifier_sha256:$verifier,
       workflow:{event:$event,name:$workflow_name,path:$workflow_path,repository:$repository,run_attempt:$run_attempt,run_id:$run_id,run_url:$run_url,
         trigger_sha:$trigger_sha,workflow_blob_sha256:$workflow_blob,workflow_ref:$workflow_ref,workflow_sha:$workflow_sha}}
    ' >"$identity" || return 1
  # shellcheck disable=SC2016
  printf '%s\n' \
    '# Diagnostic nondisclosure focused-validation matrix' '' \
    'This closed bundle records the independently verified result of all eight agent, transport, and log-level cells.' \
    'It is focused validation and is intentionally not acceptance evidence.' '' \
    'Verify this uploaded bundle with: `bash verify.sh`' >"$candidate/README.md" || return 1
  printf '%s\n' \
    '# Sanitization' '' \
    'The retained bundle is a closed, summary-only projection.' \
    'Raw logs, metrics, diagnostics, request markers, trace identifiers, timestamps, paths, and source references are excluded.' \
    'The verifier reconstructed sensitive tokens from the pinned producer and retained W3C evidence, rescanned all six raw surfaces per cell, and published only stable status and digest claims.' >"$candidate/SANITIZATION.md" || return 1
  write_public_verify_script "$candidate/verify.sh" || return 1
  chmod 0644 -- "$candidate/README.md" "$candidate/SANITIZATION.md" "$summary" "$identity" "$candidate/verify.sh" || return 1
  : >"$candidate/SHA256SUMS" || return 1
  for reference in README.md SANITIZATION.md matrix-summary.json run-identity.json verify.sh; do
    digest="$(sha256_file "$candidate/$reference")" || return 1
    printf '%s  %s\n' "$digest" "$reference" >>"$candidate/SHA256SUMS" || return 1
  done
  chmod 0644 -- "$candidate/SHA256SUMS" || return 1
  validate_public_directory "$candidate" || return 1
  bash "$candidate/verify.sh" >/dev/null || return 1
}

commit_public_candidate() {
  local -r candidate="$1"
  local -r destination="$MATRIX_ROOT/public"
  local destination_identity="" move_status=0

  [[ "$candidate" == "$PUBLIC_CANDIDATE" && "$PUBLIC_CANDIDATE_STATE" == identified &&
    -n "$PUBLIC_CANDIDATE_IDENTITY" && ! -e "$destination" && ! -L "$destination" &&
    -d "$candidate" && ! -L "$candidate" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$candidate")" == "$PUBLIC_CANDIDATE_IDENTITY" ]] || return 1
  PUBLIC_CANDIDATE_DESTINATION="$destination"
  PUBLIC_CANDIDATE_STATE=moving
  if matrix_move "$candidate" "$destination"; then move_status=0; else move_status=$?; fi
  if [[ ! -e "$candidate" && ! -L "$candidate" && -d "$destination" && ! -L "$destination" ]]; then
    destination_identity="$(stat -Lc '%d:%i:%u:%a' -- "$destination")" || return 1
    if [[ "$destination_identity" == "$PUBLIC_CANDIDATE_IDENTITY" ]]; then
      clear_public_candidate_state
      return 0
    fi
  fi
  ((move_status != 0)) || move_status=1
  return "$move_status"
}

publish_public_projection() {
  local candidate="" reference=""

  if [[ -d "$MATRIX_ROOT/public" && ! -L "$MATRIX_ROOT/public" ]]; then
    build_public_candidate || return 1
    candidate="$PUBLIC_CANDIDATE"
    [[ -n "$candidate" && "${candidate%/*}" == "$MATRIX_ROOT" ]] || return 1
    validate_public_directory "$MATRIX_ROOT/public" || return 1
    for reference in README.md SANITIZATION.md SHA256SUMS matrix-summary.json run-identity.json verify.sh; do
      cmp -s -- "$candidate/$reference" "$MATRIX_ROOT/public/$reference" || return 1
    done
    normalize_public_candidate false || return 1
    cleanup_temp_directory
    return
  fi
  [[ ! -e "$MATRIX_ROOT/public" && ! -L "$MATRIX_ROOT/public" ]] || return 1
  build_public_candidate || return 1
  candidate="$PUBLIC_CANDIDATE"
  [[ -n "$candidate" ]] || return 1
  cleanup_temp_directory || return 1
  commit_public_candidate "$candidate"
}

main() {
  local index=0

  (($# == 1)) || die "usage: $SCRIPT_NAME ABSOLUTE_RAW_MATRIX_DIRECTORY"
  trap cleanup EXIT
  [[ "$1" == /* ]] || die "raw matrix directory must be absolute"
  require_commands
  [[ -d "$1" && ! -L "$1" ]] || die "raw matrix directory is not a regular directory: $1"
  MATRIX_ROOT="$(realpath -e -- "$1")" || die "raw matrix directory cannot be resolved"
  [[ "$MATRIX_ROOT" == "$1" ]] || die "raw matrix directory must already be canonical"
  [[ ( ! -e "$MATRIX_ROOT/public" && ! -L "$MATRIX_ROOT/public" ) ||
    ( -d "$MATRIX_ROOT/public" && ! -L "$MATRIX_ROOT/public" ) ]] ||
    die "raw matrix has an unsafe public projection"
  [[ ! -e "$MATRIX_ROOT/partial-safe" && ! -L "$MATRIX_ROOT/partial-safe" ]] ||
    die "raw matrix has an ambiguous preexisting projection"
  create_verifier_temp_directory || die "cannot create verifier workspace"
  : >"$TEMP_DIR/cells.jsonl" || die "cannot initialize cell summary"
  prepare_trusted_run_blob || die "could not load the trusted producer from HEAD"
  validate_ci_identity || die "GitHub Actions run identity is incomplete or inconsistent"
  validate_repository_execution_bytes || die "matrix execution bytes are not the clean selected commit"
  validate_source_runtime_contract || die "Java 21 Temurin source configuration is not pinned by the selected commit"
  validate_raw_closure || die "private raw matrix staging is not closed"
  for index in "${!CELL_IDS[@]}"; do
    validate_cell "$index" || die "matrix cell failed verification: ${CELL_IDS[$index]}"
  done
  publish_public_projection || die "could not publish the closed public projection"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
