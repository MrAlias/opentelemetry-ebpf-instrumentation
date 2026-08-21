#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

# Raw traces, process identifiers, socket paths, and controller logs remain in
# this private transaction. Only the bounded matrix may cross the handoff.
umask 077

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AUTHORITY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIRECTORY/../../.." && pwd -P)"
readonly SCRIPT_NAME SCRIPT_DIRECTORY AUTHORITY_ROOT

readonly REPOSITORY_SLUG='MrAlias/opentelemetry-ebpf-instrumentation'
readonly REPOSITORY_URL='https://github.com/MrAlias/opentelemetry-ebpf-instrumentation.git'
readonly CAMPAIGN_REF='refs/heads/agent/java-remote-parent-bridge'
readonly WORKFLOW_PATH='.github/workflows/java_remote_parent_acceptance_claims.yml'
readonly COMMAND_TIMEOUT_SECONDS=7200
readonly COMMAND_KILL_AFTER_SECONDS=30
readonly -a PROFILE_ROLES=(
  all-getsockopt all-unix all-auto pid-reuse-getsockopt pid-reuse-unix
)
readonly -a PROFILE_KINDS=(
  acceptance-getsockopt acceptance-unix acceptance-auto
  pid-reuse-getsockopt pid-reuse-unix
)
readonly -a PROFILE_TRANSPORTS=(getsockopt unix auto getsockopt unix)
readonly -a PROFILE_SCENARIOS=(all all all pid-reuse pid-reuse)
readonly -a PUBLIC_FILES=(
  README.md SANITIZATION.md fault-security-matrix.json
  derivation-receipt.json verify.sh SHA256SUMS
)
readonly -a PROFILE_PUBLIC_FILES=(
  SANITIZATION.md profile.json verify.sh SHA256SUMS
)

OUTPUT_DIRECTORY=''
OUTPUT_PARENT=''
OUTPUT_PARENT_IDENTITY=''
OUTPUT_DIRECTORY_IDENTITY=''
PUBLIC_CLOSURE_SHA256=''
PUBLIC_EVIDENCE_ID=''
SOURCE_REVISION=''
PRIVATE_DIRECTORY=''
PRIVATE_IDENTITY=''
PRIVATE_DIRECTORY_FD=''
CHECKOUT_DIRECTORY=''
OUTPUT_CREATED=false
PRIVATE_CREATED=false
CLEANUP_REQUIRED=false
CAMPAIGN_SUCCEEDED=false
STICKY_CLEANUP_FAILURE=false
PROFILE_MODE=false
SELECTED_PROFILE_INDEX=-1
declare -a RAW_DIRECTORIES=()

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME ABS_NONEXISTENT_PUBLIC_OUTPUT" \
    "       $SCRIPT_NAME --profile ROLE ABS_NONEXISTENT_PUBLIC_OUTPUT" \
    '' \
    'Run the clean-source Java remote-parent fault/security campaign.' \
    'Profile mode publishes one sanitized cell; default mode publishes the six-file' \
    'matrix. Raw evidence is destroyed before either handoff becomes uploadable.'
}

log_info() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
}

die() {
  log_info "ERROR: $*"
  return 1
}

is_safe_leaf() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
    "$1" != . && "$1" != .. ]]
}

require_commands() {
  local command=''

  for command in awk bash chmod comm docker find git go jq mktemp readlink \
    sha256sum sort stat timeout; do
    command -v "$command" >/dev/null 2>&1 ||
      die "required command is unavailable: $command" || return 1
  done
}

sanitize_git_environment() {
  local variable=''

  unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CEILING_DIRECTORIES \
    GIT_COMMON_DIR GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL \
    GIT_CONFIG_NOSYSTEM GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_DIR \
    GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_DIFF_OPTS GIT_EXTERNAL_DIFF \
    GIT_GLOB_PATHSPECS GIT_ICASE_PATHSPECS GIT_INDEX_FILE \
    GIT_LITERAL_PATHSPECS GIT_NAMESPACE GIT_NOGLOB_PATHSPECS \
    GIT_OBJECT_DIRECTORY GIT_OPTIONAL_LOCKS GIT_REPLACE_REF_BASE \
    GIT_WORK_TREE TAR_OPTIONS
  for variable in "${!GIT_CONFIG_KEY_@}" "${!GIT_CONFIG_VALUE_@}"; do
    [[ -n "$variable" ]] || continue
    unset "$variable"
  done
  export GIT_NO_REPLACE_OBJECTS=1
  export GIT_TERMINAL_PROMPT=0
}

validate_output_target() {
  [[ "$OUTPUT_DIRECTORY" == /* && ! -e "$OUTPUT_DIRECTORY" &&
    ! -L "$OUTPUT_DIRECTORY" ]] ||
    die 'public output must be absolute and nonexistent' || return 1
  is_safe_leaf "${OUTPUT_DIRECTORY##*/}" ||
    die 'public output leaf is unsafe' || return 1
  OUTPUT_PARENT="${OUTPUT_DIRECTORY%/*}"
  [[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" &&
    "$(readlink -f -- "$OUTPUT_PARENT")" == "$OUTPUT_PARENT" &&
    "$(stat -Lc '%u:%a' -- "$OUTPUT_PARENT")" == "$EUID:700" ]] ||
    die 'public output parent must be private, physical, and caller-owned' ||
    return 1
  OUTPUT_PARENT_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_PARENT")"
}

validate_event_authority() {
  local event_identity=''
  local event_post_identity=''
  local event_fd=''
  local expected_workflow_ref=''
  local event_device=''
  local event_inode=''
  local event_owner=''
  local event_mode=''
  local event_links=''
  local event_size=''

  expected_workflow_ref="$REPOSITORY_SLUG/$WORKFLOW_PATH@$CAMPAIGN_REF"
  [[ "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true &&
    "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
    "${RUNNER_OS:-}" == Linux && "${RUNNER_ARCH:-}" == X64 &&
    "${GITHUB_EVENT_NAME:-}" == push &&
    "${GITHUB_REPOSITORY:-}" == "$REPOSITORY_SLUG" &&
    "${GITHUB_REF:-}" == "$CAMPAIGN_REF" &&
    "${GITHUB_WORKFLOW_REF:-}" == "$expected_workflow_ref" &&
    "${GITHUB_WORKFLOW_SHA:-}" == "${GITHUB_SHA:-}" &&
    "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ &&
    "${GITHUB_WORKSPACE:-}" == "$AUTHORITY_ROOT" ]] ||
    die 'workflow execution authority is not exact' || return 1
  [[ "${GITHUB_EVENT_PATH:-}" == /* && -f "$GITHUB_EVENT_PATH" &&
    ! -L "$GITHUB_EVENT_PATH" &&
    "$(readlink -f -- "$GITHUB_EVENT_PATH")" == "$GITHUB_EVENT_PATH" ]] ||
    die 'push event authority is unsafe' || return 1
  event_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$GITHUB_EVENT_PATH")"
  IFS=: read -r event_device event_inode event_owner event_mode event_links \
    event_size <<<"$event_identity"
  [[ "$event_device" =~ ^[0-9]+$ && "$event_inode" =~ ^[0-9]+$ &&
    "$event_owner" == "$EUID" && "$event_mode" =~ ^[0-7]{3,4}$ &&
    "$event_links" == 1 && "$event_size" =~ ^[1-9][0-9]*$ &&
    "$event_size" -le 2097152 && $((8#$event_mode & 0022)) == 0 ]] ||
    die 'push event authority has unsafe metadata' || return 1
  exec {event_fd}<"$GITHUB_EVENT_PATH"
  [[ "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "/proc/$BASHPID/fd/$event_fd")" == \
    "$event_identity" ]] || return 1
  jq -se --arg after "$GITHUB_SHA" --arg ref "$CAMPAIGN_REF" \
    --arg repository "$REPOSITORY_SLUG" '
      length == 1 and (.[0] | .after == $after and .ref == $ref and
        .repository.full_name == $repository)
    ' "/proc/$BASHPID/fd/$event_fd" >/dev/null || return 1
  event_post_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
    "$GITHUB_EVENT_PATH")"
  exec {event_fd}<&-
  [[ "$event_post_identity" == "$event_identity" ]]
}

validate_source_authority() {
  local relative=''
  local expected_mode=''
  local disk_mode=''
  local disk_sha256=''
  local blob_sha256=''

  SOURCE_REVISION="$(git -C "$AUTHORITY_ROOT" rev-parse --verify 'HEAD^{commit}')"
  [[ "$SOURCE_REVISION" == "$GITHUB_SHA" &&
    -z "$(git -C "$AUTHORITY_ROOT" status --porcelain --untracked-files=all \
      --ignore-submodules=none)" ]] ||
    die 'authority checkout is not the exact clean push source' || return 1
  while IFS=$'\t' read -r relative expected_mode disk_mode; do
    [[ -f "$AUTHORITY_ROOT/$relative" && ! -L "$AUTHORITY_ROOT/$relative" &&
      "$(readlink -f -- "$AUTHORITY_ROOT/$relative")" == \
        "$AUTHORITY_ROOT/$relative" &&
      "$(stat -Lc '%u:%a' -- "$AUTHORITY_ROOT/$relative")" == \
        "$EUID:$disk_mode" ]] || return 1
    [[ "$(git -C "$AUTHORITY_ROOT" ls-tree "$SOURCE_REVISION" -- "$relative" |
      awk 'NR == 1 {print $1} END {if (NR != 1) exit 1}')" == \
      "$expected_mode" ]] || return 1
    disk_sha256="$(sha256sum <"$AUTHORITY_ROOT/$relative")"
    disk_sha256="${disk_sha256%% *}"
    blob_sha256="$(git -C "$AUTHORITY_ROOT" show \
      "$SOURCE_REVISION:$relative" | sha256sum)"
    blob_sha256="${blob_sha256%% *}"
    [[ "$disk_sha256" == "$blob_sha256" ]] || return 1
  done <<'TRACKED_CAMPAIGN_FILES'
.github/workflows/java_remote_parent_acceptance_claims.yml	100644	644
examples/apache-java-https/run.sh	100755	755
examples/apache-java-https/scripts/run-retained-fault-security-campaign.sh	100755	755
examples/apache-java-https/scripts/project-retained-fault-security-matrix.sh	100755	755
examples/apache-java-https/scripts/verify-retained-evidence.sh	100755	755
TRACKED_CAMPAIGN_FILES
}

create_private_transaction() {
  PRIVATE_DIRECTORY="$(mktemp -d /tmp/obi-fault-security-campaign.XXXXXX)" ||
    return 1
  PRIVATE_DIRECTORY="$(CDPATH='' cd -- "$PRIVATE_DIRECTORY" && pwd -P)"
  [[ "$PRIVATE_DIRECTORY" =~ ^/tmp/obi-fault-security-campaign\.[A-Za-z0-9]{6}$ &&
    "$(stat -Lc '%u:%a:%h' -- "$PRIVATE_DIRECTORY")" == "$EUID:700:2" ]] ||
    return 1
  PRIVATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$PRIVATE_DIRECTORY")"
  exec {PRIVATE_DIRECTORY_FD}<"$PRIVATE_DIRECTORY" || return 1
  [[ "$(stat -Lc '%d:%i:%u' -- "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" == \
    "$PRIVATE_IDENTITY" ]] || return 1
  CHECKOUT_DIRECTORY="$PRIVATE_DIRECTORY/source"
  PRIVATE_CREATED=true
}

assert_private_identity() {
  [[ "$PRIVATE_CREATED" == true && -d "$PRIVATE_DIRECTORY" &&
    ! -L "$PRIVATE_DIRECTORY" &&
    "$(readlink -f -- "$PRIVATE_DIRECTORY")" == "$PRIVATE_DIRECTORY" &&
    "$(stat -Lc '%d:%i:%u' -- "$PRIVATE_DIRECTORY")" == "$PRIVATE_IDENTITY" &&
    "$PRIVATE_DIRECTORY_FD" =~ ^[0-9]+$ &&
    "$(stat -Lc '%d:%i:%u' -- "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" == \
      "$PRIVATE_IDENTITY" ]]
}

private_tree_has_mountpoint() {
  local -r root="$1"

  [[ "$root" == /tmp/obi-fault-security-campaign.* &&
    -f /proc/self/mountinfo && ! -L /proc/self/mountinfo ]] || return 0
  awk -v root="$root" '
    $5 == root || index($5, root "/") == 1 {found = 1}
    END {exit(found ? 0 : 1)}
  ' /proc/self/mountinfo
}

destroy_private_transaction() {
  local residue=''
  local removal_status=0

  [[ "$PRIVATE_CREATED" == true ]] || return 0
  assert_private_identity || {
    STICKY_CLEANUP_FAILURE=true
    return 1
  }
  if private_tree_has_mountpoint "$PRIVATE_DIRECTORY"; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  chmod -R u+rwX -- "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD" \
    2>/dev/null || true
  assert_private_identity || return 1
  find -H "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD" -xdev -depth \
    -mindepth 1 -delete || removal_status=$?
  residue="$(find -H "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD" -xdev \
    -mindepth 1 -print -quit)" || removal_status=$?
  if ((removal_status != 0)) || [[ -n "$residue" ]]; then
    STICKY_CLEANUP_FAILURE=true
    return 1
  fi
  assert_private_identity || return 1
  rmdir -- "$PRIVATE_DIRECTORY" || return 1
  [[ "$(stat -Lc '%h' -- "/proc/$BASHPID/fd/$PRIVATE_DIRECTORY_FD")" == 0 &&
    ! -e "$PRIVATE_DIRECTORY" && ! -L "$PRIVATE_DIRECTORY" ]] || return 1
  exec {PRIVATE_DIRECTORY_FD}<&- || return 1
  PRIVATE_CREATED=false
  PRIVATE_DIRECTORY=''
  PRIVATE_IDENTITY=''
  PRIVATE_DIRECTORY_FD=''
  CHECKOUT_DIRECTORY=''
  RAW_DIRECTORIES=()
}

remove_public_output() {
  [[ "$OUTPUT_CREATED" == true ]] || return 0
  [[ -d "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" &&
    "$(readlink -f -- "$OUTPUT_DIRECTORY")" == "$OUTPUT_DIRECTORY" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_DIRECTORY")" == \
      "$OUTPUT_DIRECTORY_IDENTITY" ]] || return 1
  chmod -R u+rwX -- "$OUTPUT_DIRECTORY" 2>/dev/null || true
  find -- "$OUTPUT_DIRECTORY" -xdev -depth -delete || return 1
  [[ ! -e "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" ]] || return 1
  OUTPUT_CREATED=false
  OUTPUT_DIRECTORY_IDENTITY=''
}

run_private_command() {
  local -r label="$1"
  local -r directory="$2"
  shift 2
  local log_file=''
  local resolved_directory=''
  local status=0

  is_safe_leaf "$label" || return 1
  assert_private_identity || return 1
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  resolved_directory="$(readlink -f -- "$directory")" || return 1
  [[ "$resolved_directory" == "$PRIVATE_DIRECTORY" ||
    "$resolved_directory" == "$PRIVATE_DIRECTORY"/* ]] || return 1
  log_file="$PRIVATE_DIRECTORY/$label.log"
  [[ ! -e "$log_file" && ! -L "$log_file" ]] || return 1
  if (CDPATH='' cd -- "$directory" && timeout --foreground --signal=TERM \
      --kill-after="${COMMAND_KILL_AFTER_SECONDS}s" \
      "${COMMAND_TIMEOUT_SECONDS}s" "$@") >"$log_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  chmod 0400 -- "$log_file" || return 1
  if ((status != 0)); then
    log_info "private command failed: $label (status $status)"
    return "$status"
  fi
}

snapshot_result_names() {
  local -r output="$1"
  local results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local inventory=''

  [[ "$output" == "$PRIVATE_DIRECTORY"/* && ! -e "$output" &&
    ! -L "$output" ]] || return 1
  if [[ ! -e "$results_root" && ! -L "$results_root" ]]; then
    : >"$output"
    chmod 0400 -- "$output"
    return
  fi
  [[ -d "$results_root" && ! -L "$results_root" &&
    "$(readlink -f -- "$results_root")" == "$results_root" ]] || return 1
  inventory="$(find -- "$results_root" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' | LC_ALL=C sort)" || return 1
  if [[ -n "$inventory" ]]; then
    awk -F '\t' '
      NF != 2 || $2 != "d" || $1 !~ /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/ {
        exit 1
      }
      { print $1 }
    ' <<<"$inventory" >"$output" || return 1
  else
    : >"$output"
  fi
  chmod 0400 -- "$output"
}

resolve_new_result() {
  local -r before="$1"
  local -r after="$2"
  local -r results_root="$CHECKOUT_DIRECTORY/examples/apache-java-https/.runtime/results"
  local difference=''

  difference="$(comm -13 "$before" "$after")" || return 1
  [[ -n "$difference" && "$difference" != *$'\n'* ]] || return 1
  is_safe_leaf "$difference" || return 1
  [[ -d "$results_root/$difference" && ! -L "$results_root/$difference" &&
    "$(readlink -f -- "$results_root/$difference")" == \
      "$results_root/$difference" ]] || return 1
  printf '%s\n' "$results_root/$difference"
}

build_profile_command() {
  local -r index="$1"

  [[ "$index" =~ ^[0-4]$ ]] || return 1
  PROFILE_COMMAND=(./examples/apache-java-https/run.sh
    --transport "${PROFILE_TRANSPORTS[index]}" --agent otel --tls TLSv1.3)
  if [[ "${PROFILE_SCENARIOS[index]}" == pid-reuse ]]; then
    PROFILE_COMMAND+=(--scenario pid-reuse)
  fi
}

run_scoped_cleanup() {
  local label="$1"

  if run_private_command "$label" "$CHECKOUT_DIRECTORY" \
      ./examples/apache-java-https/run.sh --cleanup-only; then
    CLEANUP_REQUIRED=false
    return 0
  fi
  STICKY_CLEANUP_FAILURE=true
  return 1
}

run_profile() {
  local -r index="$1"
  local before=''
  local after=''
  local raw=''
  local status=0

  before="$PRIVATE_DIRECTORY/results-before-${PROFILE_ROLES[index]}"
  after="$PRIVATE_DIRECTORY/results-after-${PROFILE_ROLES[index]}"
  snapshot_result_names "$before" || return 1
  build_profile_command "$index" || return 1
  CLEANUP_REQUIRED=true
  if run_private_command "run-${PROFILE_ROLES[index]}" "$CHECKOUT_DIRECTORY" \
      "${PROFILE_COMMAND[@]}"; then
    status=0
  else
    status=$?
  fi
  # Unsupported PID namespace/reuse prerequisites are producer failures. They
  # are deliberately never reclassified or projected as a passing cell.
  if ((status != 0)); then
    run_scoped_cleanup "cleanup-failed-${PROFILE_ROLES[index]}" || true
    return "$status"
  fi
  snapshot_result_names "$after" || return 1
  raw="$(resolve_new_result "$before" "$after")" || return 1
  "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/verify-retained-evidence.sh" \
    --raw-v3 "${PROFILE_KINDS[index]}" "$raw" >/dev/null || return 1
  RAW_DIRECTORIES[index]="$raw"
  run_scoped_cleanup "cleanup-${PROFILE_ROLES[index]}"
}

assert_exact_clone() {
  [[ "$(git -C "$CHECKOUT_DIRECTORY" rev-parse --verify 'HEAD^{commit}')" == \
      "$SOURCE_REVISION" &&
    -z "$(git -C "$CHECKOUT_DIRECTORY" status --porcelain \
      --untracked-files=all --ignore-submodules=none)" ]] || return 1
  git -C "$CHECKOUT_DIRECTORY" diff --quiet --no-ext-diff --no-textconv \
    "$SOURCE_REVISION" --
}

compute_public_closure() {
  local expected=''
  local observed=''
  local file=''
  local identity=''
  local digest=''
  local -a rows=()
  local -a files=()

  [[ -d "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" &&
    "$(readlink -f -- "$OUTPUT_DIRECTORY")" == "$OUTPUT_DIRECTORY" &&
    "$(stat -Lc '%u:%a' -- "$OUTPUT_DIRECTORY")" == "$EUID:555" ]] ||
    return 1
  if [[ "$PROFILE_MODE" == true ]]; then
    expected=$'SANITIZATION.md\tf\nSHA256SUMS\tf\nprofile.json\tf\nverify.sh\tf'
    files=("${PROFILE_PUBLIC_FILES[@]}")
  else
    expected=$'README.md\tf\nSANITIZATION.md\tf\nSHA256SUMS\tf\nderivation-receipt.json\tf\nfault-security-matrix.json\tf\nverify.sh\tf'
    files=("${PUBLIC_FILES[@]}")
  fi
  observed="$(find -- "$OUTPUT_DIRECTORY" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' | LC_ALL=C sort)" || return 1
  [[ "$observed" == "$expected" ]] || return 1
  for file in "${files[@]}"; do
    [[ -f "$OUTPUT_DIRECTORY/$file" && ! -L "$OUTPUT_DIRECTORY/$file" ]] ||
      return 1
    identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- \
      "$OUTPUT_DIRECTORY/$file")" || return 1
    [[ "$identity" == *":$EUID:444:1:"* ]] || return 1
    digest="$(sha256sum <"$OUTPUT_DIRECTORY/$file")" || return 1
    digest="${digest%% *}"
    rows+=("$file"$'\t'"$identity"$'\t'"$digest")
  done
  PUBLIC_CLOSURE_SHA256="$(printf '%s\n' "${rows[@]}" | sha256sum)"
  PUBLIC_CLOSURE_SHA256="${PUBLIC_CLOSURE_SHA256%% *}"
  if [[ "$PROFILE_MODE" == true ]]; then
    PUBLIC_EVIDENCE_ID="$(jq -er '.evidence_id' \
      "$OUTPUT_DIRECTORY/profile.json")"
  else
    PUBLIC_EVIDENCE_ID="$(sha256sum < \
      "$OUTPUT_DIRECTORY/derivation-receipt.json")"
  fi
  PUBLIC_EVIDENCE_ID="${PUBLIC_EVIDENCE_ID%% *}"
  [[ "$PUBLIC_CLOSURE_SHA256" =~ ^[0-9a-f]{64}$ &&
    "$PUBLIC_EVIDENCE_ID" =~ ^[0-9a-f]{64}$ ]]
}

publish_workflow_handoff() {
  local output_identity=''
  local output_fd=''

  [[ "${GITHUB_OUTPUT:-}" == /* && -f "$GITHUB_OUTPUT" &&
    ! -L "$GITHUB_OUTPUT" &&
    "$(readlink -f -- "$GITHUB_OUTPUT")" == "$GITHUB_OUTPUT" ]] || return 1
  output_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$GITHUB_OUTPUT")" ||
    return 1
  [[ "$output_identity" == *":$EUID:"* && "$output_identity" == *":1" ]] ||
    return 1
  exec {output_fd}>>"$GITHUB_OUTPUT"
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$BASHPID/fd/$output_fd")" == \
    "$output_identity" ]] || return 1
  printf '%s\n' \
    "public_parent_identity=$OUTPUT_PARENT_IDENTITY" \
    "public_directory_identity=$OUTPUT_DIRECTORY_IDENTITY" \
    "public_closure_sha256=$PUBLIC_CLOSURE_SHA256" \
    "public_evidence_id=$PUBLIC_EVIDENCE_ID" >&"$output_fd" || return 1
  exec {output_fd}>&-
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$GITHUB_OUTPUT")" == \
    "$output_identity" ]]
}

cleanup_on_exit() {
  local -r original_status="$?"
  local cleanup_status=0

  trap - EXIT ERR HUP INT TERM
  set +e
  if [[ "$CLEANUP_REQUIRED" == true && -n "$CHECKOUT_DIRECTORY" &&
    -d "$CHECKOUT_DIRECTORY" ]]; then
    run_scoped_cleanup emergency-cleanup || cleanup_status=1
  fi
  destroy_private_transaction || cleanup_status=1
  if [[ "$CAMPAIGN_SUCCEEDED" != true ]]; then
    remove_public_output || cleanup_status=1
  fi
  if ((original_status == 0)) &&
    { ((cleanup_status != 0)) || [[ "$STICKY_CLEANUP_FAILURE" == true ]]; }; then
    exit 1
  fi
  exit "$original_status"
}

run_campaign() {
  local index=0
  local -a projection_command=()

  require_commands
  sanitize_git_environment
  validate_output_target
  validate_event_authority
  validate_source_authority
  create_private_transaction

  run_private_command clone "$PRIVATE_DIRECTORY" git clone --no-checkout \
    --no-tags -- "$REPOSITORY_URL" "$CHECKOUT_DIRECTORY"
  run_private_command checkout "$CHECKOUT_DIRECTORY" git checkout --detach \
    "$SOURCE_REVISION"
  assert_exact_clone
  run_private_command certificates "$CHECKOUT_DIRECTORY" \
    ./examples/apache-java-https/certs/generate_test.sh
  run_private_command run-test "$CHECKOUT_DIRECTORY" \
    ./examples/apache-java-https/scripts/run_test.sh
  run_private_command tracecheck-tests "$CHECKOUT_DIRECTORY" \
    go test ./examples/apache-java-https/tracecheck/...
  run_private_command compose-config "$CHECKOUT_DIRECTORY" docker compose \
    --project-name obi-apache-java-https \
    --file examples/apache-java-https/docker-compose.yml config --quiet
  assert_exact_clone

  if [[ "$PROFILE_MODE" == true ]]; then
    index="$SELECTED_PROFILE_INDEX"
    log_info "running private source profile: ${PROFILE_ROLES[index]}"
    run_profile "$index"
    [[ -n "${RAW_DIRECTORIES[index]:-}" && "$CLEANUP_REQUIRED" == false &&
      "$STICKY_CLEANUP_FAILURE" == false ]] || return 1
  else
    for index in "${!PROFILE_ROLES[@]}"; do
      log_info "running private source profile: ${PROFILE_ROLES[index]}"
      run_profile "$index"
    done
    [[ "${#RAW_DIRECTORIES[@]}" == 5 && "$CLEANUP_REQUIRED" == false &&
      "$STICKY_CLEANUP_FAILURE" == false ]] || return 1
  fi
  assert_exact_clone

  if [[ "$PROFILE_MODE" == true ]]; then
    index="$SELECTED_PROFILE_INDEX"
    projection_command=(
      "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-fault-security-matrix.sh"
      --profile-cell-v1 "${PROFILE_ROLES[index]}" "${PROFILE_KINDS[index]}"
      "${RAW_DIRECTORIES[index]}" "$OUTPUT_DIRECTORY"
    )
  else
    projection_command=(
      "$CHECKOUT_DIRECTORY/examples/apache-java-https/scripts/project-retained-fault-security-matrix.sh"
      "${RAW_DIRECTORIES[0]}" "${RAW_DIRECTORIES[1]}"
      "${RAW_DIRECTORIES[2]}" "${RAW_DIRECTORIES[3]}"
      "${RAW_DIRECTORIES[4]}" "$OUTPUT_DIRECTORY"
    )
  fi
  if ! "${projection_command[@]}" >/dev/null; then
    if [[ -d "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" &&
      "$(readlink -f -- "$OUTPUT_DIRECTORY")" == "$OUTPUT_DIRECTORY" ]]; then
      OUTPUT_CREATED=true
      OUTPUT_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- \
        "$OUTPUT_DIRECTORY")"
    fi
    return 1
  fi
  OUTPUT_CREATED=true
  OUTPUT_DIRECTORY_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_DIRECTORY")"
  compute_public_closure

  destroy_private_transaction
  [[ ! -e "$AUTHORITY_ROOT/examples/apache-java-https/.runtime/results" &&
    ! -L "$AUTHORITY_ROOT/examples/apache-java-https/.runtime/results" ]] ||
    return 1
  if [[ "$PROFILE_MODE" != true ]]; then
    "$AUTHORITY_ROOT/examples/apache-java-https/scripts/verify-retained-evidence.sh" \
      --fault-security-matrix-v1 "$OUTPUT_DIRECTORY" >/dev/null
  fi
  (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null)
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_PARENT")" == \
    "$OUTPUT_PARENT_IDENTITY" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$OUTPUT_DIRECTORY")" == \
      "$OUTPUT_DIRECTORY_IDENTITY" ]] || return 1
  compute_public_closure
  publish_workflow_handoff
  CAMPAIGN_SUCCEEDED=true
  log_info "verified bounded fault/security matrix: $OUTPUT_DIRECTORY"
}

campaign_entry() {
  if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    usage
    return 0
  fi
  if [[ $# == 3 && "$1" == --profile ]]; then
    PROFILE_MODE=true
    case "$2" in
      all-getsockopt) SELECTED_PROFILE_INDEX=0 ;;
      all-unix) SELECTED_PROFILE_INDEX=1 ;;
      all-auto) SELECTED_PROFILE_INDEX=2 ;;
      pid-reuse-getsockopt) SELECTED_PROFILE_INDEX=3 ;;
      pid-reuse-unix) SELECTED_PROFILE_INDEX=4 ;;
      *)
        usage >&2
        return 2
        ;;
    esac
    OUTPUT_DIRECTORY="$3"
  elif [[ $# == 1 ]]; then
    OUTPUT_DIRECTORY="$1"
  else
    usage >&2
    return 2
  fi
  trap cleanup_on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  run_campaign
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  campaign_entry "$@"
fi
