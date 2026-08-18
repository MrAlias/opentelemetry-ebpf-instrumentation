#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_NAME="${0##*/}"
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
DEMO_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly DEMO_DIR
REPO_ROOT="$(git -C "$DEMO_DIR" rev-parse --show-toplevel)"
readonly REPO_ROOT
readonly RUN_SCRIPT="$DEMO_DIR/run.sh"
readonly VERIFIER="$SCRIPT_DIR/verify-diagnostic-nondisclosure-matrix.sh"
readonly RESULTS_ROOT="$DEMO_DIR/.runtime/results"
readonly RUNTIME_DIR="$DEMO_DIR/.runtime"
readonly LOCK_FILE="$RUNTIME_DIR/.diagnostic-nondisclosure-matrix.lock"
readonly MAX_RAW_CELL_BYTES=536870912
readonly -a CELL_IDS=(
  otel-getsockopt-info otel-getsockopt-debug
  otel-unix-info otel-unix-debug
  splunk-getsockopt-info splunk-getsockopt-debug
  splunk-unix-info splunk-unix-debug
)
readonly -a BASE_REFERENCES=(
  environment.txt source-state.txt source-tree.manifest git-status.txt
  bridge-source-revision.txt bridge-source-tree.sha256 bridge-artifacts.json
  official-javaagent.json run-status.json terminal-java-diagnostics.json
  terminal-obi-metrics.json obi-metric-boundary-index.json
  .obi-metric-boundary-index.freeze
)

RAW_ROOT=""
TEMP_DIR=""
TEMP_DIR_IDENTITY=""
TEMP_DIR_STATE=""
RUN_STAMP=""
RAW_MATRIX_BYTES=0
COPIED_REFERENCE_SIZE=""
MATRIX_FAILURE_STAGE=setup
MATRIX_FAILURE_REASON=setup_failed
ACTIVE_CANDIDATE=""
ACTIVE_CANDIDATE_IDENTITY=""
ACTIVE_CANDIDATE_MODE=""
ACTIVE_CANDIDATE_STATE=""
ACTIVE_CANDIDATE_DESTINATION=""
ACTIVE_CANDIDATE_VALIDATOR=""
ACTIVE_CANDIDATE_VALIDATOR_ARG=""
declare -A CELL_STATUS=()
declare -A CELL_REASON=()

die() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

matrix_move() {
  mv -T -- "$1" "$2"
}

matrix_mktemp_directory() {
  mktemp -d "$1"
}

matrix_execute() {
  "$@"
}

invoke_matrix_producer() {
  local -r project="$1"
  local -r log="$2"
  local -r agent="$3"
  local -r transport="$4"
  local -r level="$5"

  (
    umask 022
    COMPOSE_PROJECT_NAME="$project" matrix_execute "$RUN_SCRIPT" \
      --agent "$agent" --transport "$transport" --tls TLSv1.3 \
      --obi-log-level "$level" --scenario diagnostic-nondisclosure
  ) >"$log" 2>&1
}

invoke_matrix_verifier() {
  matrix_execute "$VERIFIER" "$RAW_ROOT"
}

create_owned_candidate() {
  local -r prefix="$1"
  local -r mode="$2"
  local identity=""
  local create_status=0

  [[ -n "$RAW_ROOT" && -d "$RAW_ROOT" && ! -L "$RAW_ROOT" &&
    -z "$ACTIVE_CANDIDATE" && -z "$ACTIVE_CANDIDATE_IDENTITY" &&
    -z "$ACTIVE_CANDIDATE_MODE" && -z "$ACTIVE_CANDIDATE_STATE" &&
    -z "$ACTIVE_CANDIDATE_DESTINATION" && -z "$ACTIVE_CANDIDATE_VALIDATOR" &&
    -z "$ACTIVE_CANDIDATE_VALIDATOR_ARG" &&
    "$prefix" =~ ^(cell-[a-z0-9-]+|partial-safe)$ &&
    ( "$mode" == 700 || "$mode" == 755 ) ]] || return 1
  if ACTIVE_CANDIDATE="$(umask 077; matrix_mktemp_directory "$RAW_ROOT/.$prefix.XXXXXX")"; then
    create_status=0
  else
    create_status=$?
  fi
  ACTIVE_CANDIDATE_IDENTITY=""
  ACTIVE_CANDIDATE_MODE=700
  ACTIVE_CANDIDATE_STATE=provisional
  [[ -n "$ACTIVE_CANDIDATE" && "${ACTIVE_CANDIDATE%/*}" == "$RAW_ROOT" &&
    "${ACTIVE_CANDIDATE##*/}" =~ ^\.$prefix\.[A-Za-z0-9]{6}$ ]] || {
    ACTIVE_CANDIDATE=""; ACTIVE_CANDIDATE_MODE=""; ACTIVE_CANDIDATE_STATE=""; return 1;
  }
  if ((create_status != 0)); then
    normalize_active_candidate || :
    return "$create_status"
  fi
  [[ -d "$ACTIVE_CANDIDATE" && ! -L "$ACTIVE_CANDIDATE" ]] || {
    normalize_active_candidate || :
    return 1
  }
  if [[ "$mode" == 755 ]]; then
    chmod 0755 -- "$ACTIVE_CANDIDATE" || { normalize_active_candidate || :; return 1; }
    ACTIVE_CANDIDATE_MODE=755
  fi
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$ACTIVE_CANDIDATE")" || {
    normalize_active_candidate || :
    return 1
  }
  [[ "$identity" == *":$EUID:$mode" ]] || { normalize_active_candidate || :; return 1; }
  ACTIVE_CANDIDATE_IDENTITY="$identity"
  ACTIVE_CANDIDATE_STATE=identified
}

normalize_active_candidate() {
  local identity=""

  if [[ -z "$ACTIVE_CANDIDATE" ]]; then
    [[ -z "$ACTIVE_CANDIDATE_IDENTITY" && -z "$ACTIVE_CANDIDATE_MODE" &&
      -z "$ACTIVE_CANDIDATE_STATE" && -z "$ACTIVE_CANDIDATE_DESTINATION" &&
      -z "$ACTIVE_CANDIDATE_VALIDATOR" && -z "$ACTIVE_CANDIDATE_VALIDATOR_ARG" ]] || return 1
    return 0
  fi
  [[ -n "$RAW_ROOT" && "${ACTIVE_CANDIDATE%/*}" == "$RAW_ROOT" &&
    "${ACTIVE_CANDIDATE##*/}" =~ ^\.(cell-[a-z0-9-]+|partial-safe)\.[A-Za-z0-9]{6}$ ]] || return 1
  if [[ "$ACTIVE_CANDIDATE_STATE" == moving && -n "$ACTIVE_CANDIDATE_DESTINATION" &&
    ! -e "$ACTIVE_CANDIDATE" && ! -L "$ACTIVE_CANDIDATE" ]]; then
    if classify_active_candidate_commit; then return 0; fi
    if [[ -d "$ACTIVE_CANDIDATE_DESTINATION" && ! -L "$ACTIVE_CANDIDATE_DESTINATION" &&
      -n "$ACTIVE_CANDIDATE_IDENTITY" &&
      "$(stat -Lc '%d:%i:%u:%a' -- "$ACTIVE_CANDIDATE_DESTINATION")" == "$ACTIVE_CANDIDATE_IDENTITY" ]]; then
      rm -rf -- "$ACTIVE_CANDIDATE_DESTINATION" || {
        [[ ! -e "$ACTIVE_CANDIDATE_DESTINATION" && ! -L "$ACTIVE_CANDIDATE_DESTINATION" ]] || return 1
      }
    elif [[ -e "$ACTIVE_CANDIDATE_DESTINATION" || -L "$ACTIVE_CANDIDATE_DESTINATION" ]]; then
      return 1
    fi
  fi
  if [[ ! -e "$ACTIVE_CANDIDATE" && ! -L "$ACTIVE_CANDIDATE" ]]; then
    ACTIVE_CANDIDATE=""
    ACTIVE_CANDIDATE_IDENTITY=""
    ACTIVE_CANDIDATE_MODE=""
    ACTIVE_CANDIDATE_STATE=""
    ACTIVE_CANDIDATE_DESTINATION=""
    ACTIVE_CANDIDATE_VALIDATOR=""
    ACTIVE_CANDIDATE_VALIDATOR_ARG=""
    return 0
  fi
  [[ -d "$ACTIVE_CANDIDATE" && ! -L "$ACTIVE_CANDIDATE" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$ACTIVE_CANDIDATE")" || return 1
  if [[ -z "$ACTIVE_CANDIDATE_STATE" || "$ACTIVE_CANDIDATE_STATE" == provisional ]]; then
    [[ ( -z "$ACTIVE_CANDIDATE_IDENTITY" || "$identity" == "$ACTIVE_CANDIDATE_IDENTITY" ) &&
      ( -z "$ACTIVE_CANDIDATE_MODE" || "$ACTIVE_CANDIDATE_MODE" == 700 || "$ACTIVE_CANDIDATE_MODE" == 755 ) &&
      "$identity" =~ :$EUID:(700|755)$ &&
      "$(stat -Lc '%h' -- "$ACTIVE_CANDIDATE")" == 2 ]] || return 1
    ACTIVE_CANDIDATE_IDENTITY="$identity"
    ACTIVE_CANDIDATE_MODE="${identity##*:}"
    ACTIVE_CANDIDATE_STATE=identified
  else
    [[ -n "$ACTIVE_CANDIDATE_IDENTITY" && "$identity" == "$ACTIVE_CANDIDATE_IDENTITY" ]] || return 1
  fi
  rm -rf -- "$ACTIVE_CANDIDATE" || {
    [[ ! -e "$ACTIVE_CANDIDATE" && ! -L "$ACTIVE_CANDIDATE" ]] || return 1
  }
  [[ ! -e "$ACTIVE_CANDIDATE" && ! -L "$ACTIVE_CANDIDATE" ]] || return 1
  ACTIVE_CANDIDATE=""
  ACTIVE_CANDIDATE_IDENTITY=""
  ACTIVE_CANDIDATE_MODE=""
  ACTIVE_CANDIDATE_STATE=""
  ACTIVE_CANDIDATE_DESTINATION=""
  ACTIVE_CANDIDATE_VALIDATOR=""
  ACTIVE_CANDIDATE_VALIDATOR_ARG=""
}

active_candidate_validator_succeeds() {
  local -r directory="$1"
  case "$ACTIVE_CANDIDATE_VALIDATOR" in
    validate_partial_candidate) validate_partial_candidate "$directory" ;;
    validate_cell_candidate) validate_cell_candidate "$directory" "$ACTIVE_CANDIDATE_VALIDATOR_ARG" ;;
    *) return 1 ;;
  esac
}

classify_active_candidate_commit() {
  local destination_identity=""

  [[ "$ACTIVE_CANDIDATE_STATE" == moving && -n "$ACTIVE_CANDIDATE" &&
    -n "$ACTIVE_CANDIDATE_IDENTITY" && -n "$ACTIVE_CANDIDATE_DESTINATION" &&
    ! -e "$ACTIVE_CANDIDATE" && ! -L "$ACTIVE_CANDIDATE" &&
    -d "$ACTIVE_CANDIDATE_DESTINATION" && ! -L "$ACTIVE_CANDIDATE_DESTINATION" ]] || return 1
  destination_identity="$(stat -Lc '%d:%i:%u:%a' -- "$ACTIVE_CANDIDATE_DESTINATION")" || return 1
  [[ "$destination_identity" == "$ACTIVE_CANDIDATE_IDENTITY" ]] || return 1
  active_candidate_validator_succeeds "$ACTIVE_CANDIDATE_DESTINATION" || return 1
  ACTIVE_CANDIDATE=""
  ACTIVE_CANDIDATE_IDENTITY=""
  ACTIVE_CANDIDATE_MODE=""
  ACTIVE_CANDIDATE_STATE=""
  ACTIVE_CANDIDATE_DESTINATION=""
  ACTIVE_CANDIDATE_VALIDATOR=""
  ACTIVE_CANDIDATE_VALIDATOR_ARG=""
}

cleanup_temp_directory() {
  local identity=""

  if [[ -z "$TEMP_DIR" ]]; then
    [[ -z "$TEMP_DIR_IDENTITY" && -z "$TEMP_DIR_STATE" ]] || return 1
    return 0
  fi
  [[ "$TEMP_DIR" == "${TMPDIR:-/tmp}"/obi-i39-run.* &&
    "${TEMP_DIR##*/}" =~ ^obi-i39-run\.[A-Za-z0-9]{6}$ &&
    ( -z "$TEMP_DIR_STATE" || "$TEMP_DIR_STATE" == provisional || "$TEMP_DIR_STATE" == identified ) ]] || return 1
  if [[ ! -e "$TEMP_DIR" && ! -L "$TEMP_DIR" ]]; then
    TEMP_DIR=""; TEMP_DIR_IDENTITY=""; TEMP_DIR_STATE=""; return 0
  fi
  [[ -d "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$TEMP_DIR")" || return 1
  if [[ "$TEMP_DIR_STATE" == identified ]]; then
    [[ -n "$TEMP_DIR_IDENTITY" && "$identity" == "$TEMP_DIR_IDENTITY" ]] || return 1
  else
    [[ ( -z "$TEMP_DIR_IDENTITY" || "$identity" == "$TEMP_DIR_IDENTITY" ) &&
      "$identity" == *":$EUID:700" && "$(stat -Lc '%h' -- "$TEMP_DIR")" == 2 ]] || return 1
    TEMP_DIR_IDENTITY="$identity"
    TEMP_DIR_STATE=identified
  fi
  rm -rf -- "$TEMP_DIR" || {
    [[ ! -e "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || return 1
  }
  [[ ! -e "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || return 1
  TEMP_DIR=""; TEMP_DIR_IDENTITY=""; TEMP_DIR_STATE=""
}

create_temp_directory() {
  local create_status=0

  [[ -z "$TEMP_DIR" && -z "$TEMP_DIR_IDENTITY" && -z "$TEMP_DIR_STATE" ]] || return 1
  if TEMP_DIR="$(umask 077; matrix_mktemp_directory "${TMPDIR:-/tmp}/obi-i39-run.XXXXXX")"; then
    create_status=0
  else
    create_status=$?
  fi
  TEMP_DIR_STATE=provisional
  [[ -n "$TEMP_DIR" && "${TEMP_DIR##*/}" =~ ^obi-i39-run\.[A-Za-z0-9]{6}$ ]] || {
    TEMP_DIR=""; TEMP_DIR_STATE=""; return 1;
  }
  if ((create_status != 0)); then cleanup_temp_directory || :; return "$create_status"; fi
  [[ -d "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] || { cleanup_temp_directory || :; return 1; }
  TEMP_DIR_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "$TEMP_DIR")" || {
    cleanup_temp_directory || :; return 1;
  }
  [[ "$TEMP_DIR_IDENTITY" == *":$EUID:700" ]] || { cleanup_temp_directory || :; return 1; }
  TEMP_DIR_STATE=identified
}

prepare_runtime_lock() {
  local -r runtime_dir="$1"
  local -r lock_file="$2"
  local runtime_identity="" lock_identity="" fd_identity=""

  [[ "$lock_file" == "$runtime_dir/.diagnostic-nondisclosure-matrix.lock" ]] || return 1
  if [[ ! -e "$runtime_dir" && ! -L "$runtime_dir" ]]; then
    mkdir -m 0700 -- "$runtime_dir" || return 1
  fi
  [[ -d "$runtime_dir" && ! -L "$runtime_dir" &&
    "$(realpath -e -- "$runtime_dir")" == "$runtime_dir" ]] || return 1
  runtime_identity="$(stat -Lc '%u:%a' -- "$runtime_dir")" || return 1
  [[ "${runtime_identity%%:*}" == "$EUID" ]] || return 1
  if [[ "$runtime_identity" != "$EUID:700" ]]; then
    chmod 0700 -- "$runtime_dir" || return 1
  fi
  [[ "$(stat -Lc '%u:%a' -- "$runtime_dir")" == "$EUID:700" ]] || return 1
  if [[ ! -e "$lock_file" && ! -L "$lock_file" ]]; then
    (umask 077; set -o noclobber; : >"$lock_file") || return 1
  fi
  [[ -f "$lock_file" && ! -L "$lock_file" ]] || return 1
  lock_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock_file")" || return 1
  [[ "$lock_identity" =~ ^[0-9]+:[0-9]+:$EUID:(600|644):1$ ]] || return 1
  if [[ "${lock_identity%:1}" == *:644 ]]; then
    chmod 0600 -- "$lock_file" || return 1
    lock_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock_file")" || return 1
  fi
  [[ "$lock_identity" =~ ^[0-9]+:[0-9]+:$EUID:600:1$ ]] || return 1
  exec 9<>"$lock_file" || return 1
  fd_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$$/fd/9")" || return 1
  [[ "$fd_identity" == "$lock_identity" ]] || return 1
  flock -n 9 || return 1
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock_file")" == "$lock_identity" &&
    "$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$$/fd/9")" == "$lock_identity" ]] || return 1
}

sha256_file() {
  local -r input="$1"
  local output=""
  local digest=""

  output="$(sha256sum <"$input")" || return 1
  digest="${output%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

require_commands() {
  local command=""
  for command in git jq sha256sum stat find sort comm cmp realpath mktemp install flock \
    awk wc grep mkdir mv rm date chmod bash; do
    command -v "$command" >/dev/null 2>&1 || die "required command is unavailable: $command"
  done
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

write_partial_verify_script() {
  local -r output="$1"
  local content=""

  # Uploaded scripts are data files with mode 0644 and are invoked with Bash.
  IFS= read -r -d '' content <<'PARTIAL_VERIFY' || [[ -n "$content" ]]
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'README.md\tf\nSHA256SUMS\tf\nmatrix-status.json\tf\nverify.sh\tf'
observed="$(find "$root" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)"
[[ "$observed" == "$expected" && "$(stat -Lc '%a:%h' -- "$root")" == 755:2 ]]
for file in README.md SHA256SUMS matrix-status.json verify.sh; do
  [[ -f "$root/$file" && ! -L "$root/$file" && "$(stat -Lc '%a:%h' -- "$root/$file")" == 644:1 ]]
done
manifest_expected=$'README.md\nmatrix-status.json\nverify.sh'
manifest_observed="$(awk '{ if (NF != 2 || $1 !~ /^[0-9a-f]{64}$/) exit 2; print $2 }' "$root/SHA256SUMS")"
[[ "$manifest_observed" == "$manifest_expected" ]]
(cd -- "$root" && sha256sum --check --strict SHA256SUMS)
canonical="$(jq -ceS -s '
  def exact_cells:
    (.cells | type == "array" and length == 8) and
    [.cells[].ordinal] == [1,2,3,4,5,6,7,8] and
    [.cells[].agent_distribution] == ["otel","otel","otel","otel","splunk","splunk","splunk","splunk"] and
    [.cells[].selected_transport] == ["getsockopt","getsockopt","unix","unix","getsockopt","getsockopt","unix","unix"] and
    [.cells[].obi_log_level] == ["info","debug","info","debug","info","debug","info","debug"] and
    all(.cells[]; keys == ["agent_distribution","failure_reason","obi_log_level","ordinal","selected_transport","status"]);
  def all_not_run: all(.cells[]; .status == "not_run" and .failure_reason == "matrix_incomplete");
  def all_passed: all(.cells[]; .status == "passed" and .failure_reason == "none");
  def cell_failure:
    ([.cells[] | select(.status == "failed")] | length == 1) and
    ([.cells[].status] | join(",") | test("^(passed,)*failed(,not_run)*$")) and
    all(.cells[];
      if .status == "passed" then .failure_reason == "none"
      elif .status == "failed" then
        (.failure_reason == "result_inventory" or .failure_reason == "result_resolution" or
         .failure_reason == "runner_exit" or .failure_reason == "result_identity" or
         .failure_reason == "project_identity" or .failure_reason == "raw_projection")
      elif .status == "not_run" then .failure_reason == "matrix_incomplete"
      else false end);
  if length == 1 then .[0] as $m |
    if ($m | keys == ["acceptance_evidence","cells","evidence_class","failure_reason","failure_stage","publishable","schema","status"] and
      .schema == "obi-diagnostic-nondisclosure-partial-safe-v1" and .status == "failed" and
      .publishable == false and .acceptance_evidence == false and .evidence_class == "focused_non_acceptance" and exact_cells and
      ((.failure_stage == "setup" and .failure_reason == "setup_failed" and all_not_run) or
       (.failure_stage == "cell" and .failure_reason == "cell_failed" and cell_failure) or
       (.failure_stage == "runner_cleanup" and .failure_reason == "private_cleanup_failed" and all_passed) or
       (.failure_stage == "verification" and .failure_reason == "verifier_failed" and all_passed)))
    then $m else error("invalid partial projection") end
  else error("invalid partial projection document count") end
' "$root/matrix-status.json")"
[[ "$(<"$root/matrix-status.json")" == "$canonical" ]]
PARTIAL_VERIFY
  printf '%s\n' "$content" >"$output" || return 1
}

validate_partial_candidate() {
  local -r candidate="$1"
  local observed=""
  local expected=""
  local canonical=""
  local digest=""
  local reference=""
  local expected_checksums=""

  [[ -d "$candidate" && ! -L "$candidate" &&
    "$(stat -Lc '%u:%a:%h' -- "$candidate")" == "$EUID:755:2" ]] || return 1
  observed="$(find "$candidate" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)" || return 1
  expected="$(printf '%s\tf\n' README.md SHA256SUMS matrix-status.json verify.sh | LC_ALL=C sort)" || return 1
  [[ "$observed" == "$expected" ]] || return 1
  for reference in README.md SHA256SUMS matrix-status.json verify.sh; do
    [[ -f "$candidate/$reference" && ! -L "$candidate/$reference" &&
      "$(stat -Lc '%u:%a:%h' -- "$candidate/$reference")" == "$EUID:644:1" ]] || return 1
  done
  canonical="$(jq -ceS -s '
    def exact_cells:
      (.cells | type == "array" and length == 8) and
      [.cells[].ordinal] == [1,2,3,4,5,6,7,8] and
      [.cells[].agent_distribution] == ["otel","otel","otel","otel","splunk","splunk","splunk","splunk"] and
      [.cells[].selected_transport] == ["getsockopt","getsockopt","unix","unix","getsockopt","getsockopt","unix","unix"] and
      [.cells[].obi_log_level] == ["info","debug","info","debug","info","debug","info","debug"] and
      all(.cells[]; keys == ["agent_distribution","failure_reason","obi_log_level","ordinal","selected_transport","status"]);
    def all_not_run: all(.cells[]; .status == "not_run" and .failure_reason == "matrix_incomplete");
    def all_passed: all(.cells[]; .status == "passed" and .failure_reason == "none");
    def cell_failure:
      ([.cells[] | select(.status == "failed")] | length == 1) and
      ([.cells[].status] | join(",") | test("^(passed,)*failed(,not_run)*$")) and
      all(.cells[];
        if .status == "passed" then .failure_reason == "none"
        elif .status == "failed" then
          (.failure_reason == "result_inventory" or .failure_reason == "result_resolution" or
           .failure_reason == "runner_exit" or .failure_reason == "result_identity" or
           .failure_reason == "project_identity" or .failure_reason == "raw_projection")
        elif .status == "not_run" then .failure_reason == "matrix_incomplete"
        else false end);
    if length == 1 then .[0] as $m |
    if ($m | keys == ["acceptance_evidence","cells","evidence_class","failure_reason","failure_stage","publishable","schema","status"] and
      .acceptance_evidence == false and .evidence_class == "focused_non_acceptance" and
      .publishable == false and .schema == "obi-diagnostic-nondisclosure-partial-safe-v1" and
      .status == "failed" and exact_cells and
      ((.failure_stage == "setup" and .failure_reason == "setup_failed" and all_not_run) or
       (.failure_stage == "cell" and .failure_reason == "cell_failed" and cell_failure) or
       (.failure_stage == "runner_cleanup" and .failure_reason == "private_cleanup_failed" and all_passed) or
       (.failure_stage == "verification" and .failure_reason == "verifier_failed" and all_passed)))
    then $m else error("invalid partial projection") end
    else error("invalid partial projection document count") end
  ' "$candidate/matrix-status.json")" || return 1
  [[ "$(<"$candidate/matrix-status.json")" == "$canonical" ]] || return 1
  for reference in README.md matrix-status.json verify.sh; do
    digest="$(sha256_file "$candidate/$reference")" || return 1
    expected_checksums+="${expected_checksums:+$'\n'}$digest  $reference"
  done
  [[ "$(<"$candidate/SHA256SUMS")" == "$expected_checksums" ]] || return 1
  bash "$candidate/verify.sh" >/dev/null || return 1
}

validate_cell_candidate() {
  local -r candidate="$1"
  local -r references="$2"
  local expected="$TEMP_DIR/candidate-expected"
  local observed="$TEMP_DIR/candidate-observed"
  local reference="" parent="" path="" size="" total=0

  [[ -d "$candidate" && ! -L "$candidate" && -f "$references" && ! -L "$references" &&
    "$(stat -Lc '%u:%a' -- "$candidate")" == "$EUID:700" ]] || return 1
  : >"$expected" || return 1
  while IFS= read -r reference; do
    safe_reference "$reference" || return 1
    printf '%s\tf\n' "$reference" >>"$expected" || return 1
    parent="${reference%/*}"
    while [[ "$parent" != "$reference" ]]; do
      printf '%s\td\n' "$parent" >>"$expected" || return 1
      reference="$parent"
      parent="${reference%/*}"
    done
  done <"$references"
  LC_ALL=C sort -u -o "$expected" "$expected" || return 1
  find "$candidate" -mindepth 1 -printf '%P\t%y\n' >"$observed" || return 1
  LC_ALL=C sort -o "$observed" "$observed" || return 1
  cmp -s -- "$expected" "$observed" || return 1
  find "$candidate" -type d -printf '%p\n' >"$observed" || return 1
  while IFS= read -r path; do
    [[ "$(stat -Lc '%u:%a' -- "$path")" == "$EUID:700" ]] || return 1
  done <"$observed"
  find "$candidate" -type f -printf '%p\n' >"$observed" || return 1
  while IFS= read -r path; do
    [[ "$(stat -Lc '%u:%a:%h' -- "$path")" == "$EUID:600:1" ]] || return 1
    size="$(stat -Lc '%s' -- "$path")" || return 1
    [[ "$size" =~ ^[0-9]+$ ]] || return 1
    ((size <= MAX_RAW_CELL_BYTES - total && size <= MAX_RAW_CELL_BYTES - RAW_MATRIX_BYTES - total)) || return 1
    ((total += size))
  done <"$observed"
}

commit_candidate_directory() {
  local -r candidate="$1"
  local -r destination="$2"
  local -r validator="$3"
  local -r validator_arg="${4:-}"
  local identity=""
  local move_status=0

  [[ "$candidate" == "$ACTIVE_CANDIDATE" && "$ACTIVE_CANDIDATE_STATE" == identified &&
    -n "$ACTIVE_CANDIDATE_IDENTITY" &&
    ( "$validator" == validate_partial_candidate || "$validator" == validate_cell_candidate ) &&
    -d "$candidate" && ! -L "$candidate" && ! -e "$destination" && ! -L "$destination" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a' -- "$candidate")" || return 1
  [[ "$identity" == "$ACTIVE_CANDIDATE_IDENTITY" ]] || return 1
  ACTIVE_CANDIDATE_VALIDATOR="$validator"
  ACTIVE_CANDIDATE_VALIDATOR_ARG="$validator_arg"
  ACTIVE_CANDIDATE_DESTINATION="$destination"
  ACTIVE_CANDIDATE_STATE=moving
  active_candidate_validator_succeeds "$candidate" || return 1
  if matrix_move "$candidate" "$destination"; then
    move_status=0
  else
    move_status=$?
  fi
  if classify_active_candidate_commit; then return 0; fi
  ((move_status != 0)) || move_status=1
  return "$move_status"
}

write_partial_safe() {
  local partial="$RAW_ROOT/partial-safe"
  local candidate=""
  local cells=""
  local id="" agent="" transport="" level="" status="" reason=""
  local ordinal=0
  local reference="" digest=""

  [[ -n "$RAW_ROOT" && -d "$RAW_ROOT" && ! -L "$RAW_ROOT" &&
    ! -e "$RAW_ROOT/public" && ! -L "$RAW_ROOT/public" &&
    ! -e "$partial" && ! -L "$partial" ]] || return 1
  normalize_active_candidate || return 1
  create_owned_candidate partial-safe 755 || return 1
  candidate="$ACTIVE_CANDIDATE"
  cells="$candidate/.partial-cells.jsonl"
  : >"$cells" || return 1
  for id in "${CELL_IDS[@]}"; do
    ((ordinal += 1))
    IFS='-' read -r agent transport level <<<"$id"
    status="${CELL_STATUS[$id]:-not_run}"
    reason="${CELL_REASON[$id]:-matrix_incomplete}"
    jq -cnS --arg agent "$agent" --arg transport "$transport" --arg level "$level" \
      --arg status "$status" --arg reason "$reason" --argjson ordinal "$ordinal" '
        {agent_distribution:$agent,failure_reason:$reason,obi_log_level:$level,
         ordinal:$ordinal,selected_transport:$transport,status:$status}
      ' >>"$cells" || return 1
  done
  jq -cs --arg failure_stage "$MATRIX_FAILURE_STAGE" --arg failure_reason "$MATRIX_FAILURE_REASON" \
    '{acceptance_evidence:false,cells:.,evidence_class:"focused_non_acceptance",
    failure_reason:$failure_reason,failure_stage:$failure_stage,publishable:false,
    schema:"obi-diagnostic-nondisclosure-partial-safe-v1",status:"failed"}' \
    "$cells" >"$candidate/matrix-status.json" || return 1
  rm -- "$cells" || return 1
  # shellcheck disable=SC2016
  printf '%s\n' '# Incomplete diagnostic nondisclosure matrix' '' \
    'This bounded status projection is nonpublishable and is not evidence that the matrix passed.' \
    'No raw cell evidence is retained in this projection.' '' \
    'Verify this uploaded projection with: `bash verify.sh`' >"$candidate/README.md" || return 1
  write_partial_verify_script "$candidate/verify.sh" || return 1
  chmod 0644 -- "$candidate/README.md" "$candidate/matrix-status.json" "$candidate/verify.sh" || return 1
  : >"$candidate/SHA256SUMS" || return 1
  for reference in README.md matrix-status.json verify.sh; do
    digest="$(sha256_file "$candidate/$reference")" || return 1
    printf '%s  %s\n' "$digest" "$reference" >>"$candidate/SHA256SUMS" || return 1
  done
  chmod 0644 -- "$candidate/SHA256SUMS" || return 1
  validate_partial_candidate "$candidate" || return 1
  commit_candidate_directory "$candidate" "$partial" validate_partial_candidate
}

cleanup() {
  local status="$?"
  trap - EXIT
  if ! normalize_active_candidate; then ((status != 0)) || status=1; fi
  if ((status != 0)) && [[ -n "$RAW_ROOT" && -d "$RAW_ROOT" && ! -L "$RAW_ROOT" &&
    ! -e "$RAW_ROOT/public" && ! -L "$RAW_ROOT/public" &&
    ! -e "$RAW_ROOT/partial-safe" && ! -L "$RAW_ROOT/partial-safe" ]]; then
    write_partial_safe || true
  fi
  if ! normalize_active_candidate; then ((status != 0)) || status=1; fi
  if ! cleanup_temp_directory; then
    ((status != 0)) || status=1
  fi
  exit "$status"
}

snapshot_results() {
  local -r output="$1"
  local -r results_root="${2:-$RESULTS_ROOT}"
  if [[ ! -e "$results_root" && ! -L "$results_root" ]]; then
    : >"$output"
    return 0
  fi
  [[ -d "$results_root" && ! -L "$results_root" ]] || return 1
  find "$results_root" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y:%D:%i:%U:%m\n' | LC_ALL=C sort >"$output"
}

metric_capture_lock_matches_snapshot() {
  local -r results_root="$1"
  local -r snapshot_identity="$2"
  local -r lock="$results_root/.obi-metric-capture.lock"
  local lock_fd=""
  local path_identity=""
  local descriptor_identity=""
  local post_identity=""

  [[ "$snapshot_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ &&
    -d "$results_root" && ! -L "$results_root" &&
    "$(realpath -e -- "$results_root")" == "$results_root" &&
    -f "$lock" && ! -L "$lock" ]] || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock")" || return 1
  [[ "${path_identity%:*}" == "$snapshot_identity" &&
    "$path_identity" == *":$EUID:600:1" ]] || return 1
  exec {lock_fd}<"$lock" || return $?
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/self/fd/$lock_fd")" ||
    descriptor_identity=""
  post_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$lock")" || post_identity=""
  exec {lock_fd}>&- || return $?
  [[ -f "$lock" && ! -L "$lock" &&
    "$path_identity" == "$descriptor_identity" &&
    "$path_identity" == "$post_identity" ]]
}

resolve_new_result() {
  local -r before="$1"
  local -r after="$2"
  local -r output_path_name="$3"
  local -r output_identity_name="$4"
  local -r results_root="${5:-$RESULTS_ROOT}"
  local removed="$TEMP_DIR/results-removed"
  local added="$TEMP_DIR/results-added"
  local name="" metadata="" type="" identity=""
  local resolved_path="" resolved_identity=""
  local result_seen=false
  local lock_seen=false

  comm -23 -- "$before" "$after" >"$removed" || return 1
  comm -13 -- "$before" "$after" >"$added" || return 1
  [[ ! -s "$removed" ]] || return 1
  while IFS=$'\t' read -r name metadata; do
    [[ -n "$name" && -n "$metadata" ]] || return 1
    type="${metadata%%:*}"
    identity="${metadata#*:}"
    case "$name" in
      .obi-metric-capture.lock)
        [[ "$lock_seen" == false && "$type" == f ]] || return 1
        metric_capture_lock_matches_snapshot "$results_root" "$identity" || return 1
        lock_seen=true
        ;;
      *)
        [[ "$result_seen" == false && "$type" == d &&
          "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ &&
          "$name" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ &&
          -d "$results_root/$name" && ! -L "$results_root/$name" &&
          "$(stat -Lc '%d:%i:%u:%a' -- "$results_root/$name")" == "$identity" &&
          "$identity" == *":$EUID:755" ]] || return 1
        resolved_path="$results_root/$name"
        resolved_identity="$identity"
        result_seen=true
        ;;
    esac
  done <"$added"
  [[ "$result_seen" == true ]] || return 1
  printf -v "$output_path_name" '%s' "$resolved_path"
  printf -v "$output_identity_name" '%s' "$resolved_identity"
}

result_directory_has_identity() {
  local -r result="$1"
  local -r expected_identity="$2"
  [[ -d "$result" && ! -L "$result" &&
    "$(stat -Lc '%d:%i:%u:%a' -- "$result")" == "$expected_identity" ]]
}

result_status_names_directory() {
  local -r status_file="$1"
  local -r result="$2"

  [[ -f "$status_file" && ! -L "$status_file" ]] || return 1
  jq -e -s --arg result "$result" '
    length == 1 and (.[0] | type == "object" and .evidence_directory == $result)
  ' "$status_file" >/dev/null
}

assert_no_private_residue() {
  local -r result="$1"
  local hidden=""
  local inventory="$TEMP_DIR/hidden-paths"

  find "$result" -mindepth 1 -name '.*' -printf '%P\n' >"$inventory" || return 1
  while IFS= read -r hidden; do
    [[ "$hidden" == .obi-metric-boundary-index.freeze ]] || return 1
  done <"$inventory"
}

collect_references() {
  local -r result="$1"
  local -r output="$2"
  local boundary="$result/obi-metric-boundary-index.json"
  local pair_ref="" identity_ref=""
  local identity_references="$TEMP_DIR/identity-references"

  printf '%s\n' "${BASE_REFERENCES[@]}" >"$output" || return 1
  jq -er '(.boundaries[0].captures[] |
    if .kind == "pair" then .pair_reference, (.java_reference // empty)
    elif .kind == "phase" then .identity_reference
    elif .kind == "java" or .kind == "artifact" then .reference else empty end),
    (.boundaries[0].status_references[].reference)' "$boundary" >>"$output" || return 1
  jq -er '.result,.stderr' "$result/scenario-w3c-status.json" >>"$output" || return 1
  jq -er '.reference' "$result/terminal-java-diagnostics.json" >>"$output" || return 1
  jq -er '.java_bridge_diagnostics_reference,.obi_metric_evidence_reference,.obi_metric_boundary_index_reference' \
    "$result/run-status.json" >>"$output" || return 1
  pair_ref="$(jq -er '.boundaries[0].captures[] | select(.kind == "pair") | .pair_reference' "$boundary")" || return 1
  jq -er '.before.identity_reference,.after.identity_reference' "$result/$pair_ref" >"$identity_references" || return 1
  cat -- "$identity_references" >>"$output" || return 1
  while IFS= read -r identity_ref; do
    jq -er '.metrics_reference' "$result/$identity_ref" >>"$output" || return 1
  done <"$identity_references"
  LC_ALL=C sort -u -o "$output" "$output" || return 1
}

pinned_path_has_identity() {
  local -r source="$1"
  local -r expected_identity="$2"
  local resolved=""
  local identity=""

  [[ -f "$source" && ! -L "$source" ]] || return 1
  resolved="$(realpath -e -- "$source")" || return 1
  [[ "$resolved" == "$source" ]] || return 1
  identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source")" || return 1
  [[ "$identity" == "$expected_identity" ]] || return 1
  # Repeat the lstat-sensitive checks after stat so a stable symlink swap is
  # never accepted as the pathname corresponding to the pinned descriptor.
  [[ -f "$source" && ! -L "$source" ]] || return 1
  resolved="$(realpath -e -- "$source")" || return 1
  [[ "$resolved" == "$source" ]] || return 1
  [[ "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$source")" == "$expected_identity" ]]
}

copy_pinned_reference() {
  local -r source="$1"
  local -r destination="$2"
  local -r remaining_bytes="$3"
  local source_fd=""
  local fd_path=""
  local fd_identity=""
  local source_digest=""
  local copied_digest=""
  local post_digest=""
  local size=""
  local status=0

  COPIED_REFERENCE_SIZE=""
  if ! exec {source_fd}<"$source"; then
    if [[ -n "$source_fd" ]]; then
      exec {source_fd}<&- || :
    fi
    return 1
  fi
  fd_path="/proc/self/fd/$source_fd"

  fd_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$fd_path")" || status=1
  if ((status == 0)); then
    [[ "$fd_identity" =~ ^[0-9]+:[0-9]+:$EUID:(600|644):1:([0-9]+)$ ]] || status=1
  fi
  if ((status == 0)); then
    size="${BASH_REMATCH[2]}"
    ((size <= remaining_bytes)) || status=1
  fi
  if ((status == 0)); then
    pinned_path_has_identity "$source" "$fd_identity" || status=1
  fi
  if ((status == 0)); then
    source_digest="$(sha256_file "$fd_path")" || status=1
  fi
  if ((status == 0)); then
    [[ "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$fd_path")" == "$fd_identity" ]] || status=1
  fi
  if ((status == 0)); then
    pinned_path_has_identity "$source" "$fd_identity" || status=1
  fi
  if ((status == 0)); then
    install -m 0600 -- "$fd_path" "$destination" || status=1
  fi
  if ((status == 0)); then
    [[ "$(stat -Lc '%u:%a:%h' -- "$destination")" == "$EUID:600:1" ]] || status=1
  fi
  if ((status == 0)); then
    copied_digest="$(sha256_file "$destination")" || status=1
  fi
  if ((status == 0)); then
    [[ "$copied_digest" == "$source_digest" ]] || status=1
  fi
  if ((status == 0)); then
    pinned_path_has_identity "$source" "$fd_identity" || status=1
  fi
  if ((status == 0)); then
    [[ "$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$fd_path")" == "$fd_identity" ]] || status=1
  fi
  if ((status == 0)); then
    post_digest="$(sha256_file "$fd_path")" || status=1
  fi
  if ((status == 0)); then
    [[ "$post_digest" == "$source_digest" ]] || status=1
  fi
  exec {source_fd}<&- || status=1
  ((status == 0)) || return 1
  COPIED_REFERENCE_SIZE="$size"
}

copy_raw_cell() {
  local -r result="$1"
  local -r id="$2"
  local -r result_identity="$3"
  local references="$TEMP_DIR/references-$id"
  local stage=""
  local reference="" parent="" total=0

  result_directory_has_identity "$result" "$result_identity" || return 1
  result_status_names_directory "$result/run-status.json" "$result" || return 1
  assert_no_private_residue "$result" || return 1
  collect_references "$result" "$references" || return 1
  create_owned_candidate "cell-$id" 700 || return 1
  stage="$ACTIVE_CANDIDATE"
  while IFS= read -r reference; do
    safe_reference "$reference" || return 1
    parent="${reference%/*}"
    if [[ "$parent" != "$reference" ]]; then
      mkdir -p -- "$stage/$parent" || return 1
    fi
    copy_pinned_reference "$result/$reference" "$stage/$reference" \
      "$((MAX_RAW_CELL_BYTES - total))" || return 1
    ((total += COPIED_REFERENCE_SIZE))
  done <"$references"
  result_status_names_directory "$result/run-status.json" "$result" || return 1
  result_status_names_directory "$stage/run-status.json" "$result" || return 1
  result_directory_has_identity "$result" "$result_identity" || return 1
  commit_candidate_directory "$stage" "$RAW_ROOT/cells/$id" validate_cell_candidate "$references" || return 1
  ((RAW_MATRIX_BYTES += total))
  result_directory_has_identity "$result" "$result_identity" &&
    result_status_names_directory "$result/run-status.json" "$result"
}

run_cell() {
  local -r ordinal="$1"
  local -r id="${CELL_IDS[$((ordinal - 1))]}"
  local agent="" transport="" level=""
  local project="" before="" after="" log="" result="" result_identity=""
  local run_status=0

  IFS='-' read -r agent transport level <<<"$id"
  project="obi-apache-java-https-i39-$RUN_STAMP-$$-$ordinal"
  ((${#project} <= 63)) || return 1
  before="$TEMP_DIR/results-before-$ordinal"; after="$TEMP_DIR/results-after-$ordinal"
  log="$TEMP_DIR/run-$ordinal.log"
  snapshot_results "$before" || { CELL_STATUS[$id]=failed; CELL_REASON[$id]=result_inventory; return 1; }
  if invoke_matrix_producer "$project" "$log" "$agent" "$transport" "$level"; then
    run_status=0
  else
    run_status=$?
  fi
  snapshot_results "$after" || { CELL_STATUS[$id]=failed; CELL_REASON[$id]=result_inventory; return 1; }
  resolve_new_result "$before" "$after" result result_identity || { CELL_STATUS[$id]=failed; CELL_REASON[$id]=result_resolution; return 1; }
  if ((run_status != 0)); then CELL_STATUS[$id]=failed; CELL_REASON[$id]=runner_exit; return 1; fi
  result_directory_has_identity "$result" "$result_identity" || { CELL_STATUS[$id]=failed; CELL_REASON[$id]=result_identity; return 1; }
  [[ "$(awk -F= '$1 == "compose_project" {print substr($0,length($1)+2)}' "$result/environment.txt")" == "$project" ]] || {
    CELL_STATUS[$id]=failed; CELL_REASON[$id]=project_identity; return 1;
  }
  result_directory_has_identity "$result" "$result_identity" || { CELL_STATUS[$id]=failed; CELL_REASON[$id]=result_identity; return 1; }
  copy_raw_cell "$result" "$id" "$result_identity" || { CELL_STATUS[$id]=failed; CELL_REASON[$id]=raw_projection; return 1; }
  CELL_STATUS[$id]=passed
  CELL_REASON[$id]=none
}

run_cells_serial() {
  local ordinal=0

  for ordinal in {1..8}; do
    if ! run_cell "$ordinal"; then
      return 1
    fi
  done
}

main() {
  local failures=0
  local status_output=""

  (($# == 1)) || die "usage: $SCRIPT_NAME ABSOLUTE_RAW_MATRIX_DIRECTORY"
  trap cleanup EXIT
  [[ "$1" == /* ]] || die "raw matrix directory must be absolute"
  require_commands
  [[ -x "$RUN_SCRIPT" && -x "$VERIFIER" ]] || die "producer or verifier is not executable"
  status_output="$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" || die "could not inspect source checkout"
  [[ -z "$status_output" ]] || die "matrix requires a clean source checkout"
  [[ ! -e "$1" && ! -L "$1" ]] || die "raw matrix output already exists: $1"
  [[ -d "${1%/*}" && ! -L "${1%/*}" ]] || die "raw matrix parent is not a regular directory"
  create_temp_directory || die "cannot create a private runner workspace"
  RAW_ROOT="$1"
  mkdir -m 0700 -- "$RAW_ROOT" || die "cannot create raw matrix root"
  [[ "$(realpath -e -- "$RAW_ROOT")" == "$RAW_ROOT" ]] || die "raw matrix root must be canonical"
  mkdir -m 0700 -- "$RAW_ROOT/cells" || die "cannot create raw cells directory"
  RUN_STAMP="$(date -u +%s)"
  prepare_runtime_lock "$RUNTIME_DIR" "$LOCK_FILE" || die "could not acquire the diagnostic nondisclosure matrix lock"
  MATRIX_FAILURE_STAGE=cell
  MATRIX_FAILURE_REASON=cell_failed
  if ! run_cells_serial; then
    failures=1
  fi
  if ((failures != 0)); then
    write_partial_safe || die "matrix failed and partial-safe projection could not be written"
    die "$failures matrix cell(s) failed; bounded status is $RAW_ROOT/partial-safe"
  fi
  MATRIX_FAILURE_STAGE=runner_cleanup
  MATRIX_FAILURE_REASON=private_cleanup_failed
  cleanup_temp_directory || die "could not remove private runner workspace before publication"
  MATRIX_FAILURE_STAGE=verification
  MATRIX_FAILURE_REASON=verifier_failed
  invoke_matrix_verifier || die "raw matrix verification failed"
  MATRIX_FAILURE_STAGE=none
  MATRIX_FAILURE_REASON=none
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
