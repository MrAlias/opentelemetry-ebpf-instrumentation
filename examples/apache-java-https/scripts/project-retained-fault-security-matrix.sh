#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

umask 077

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERIFIER="$SCRIPT_DIR/verify-retained-evidence.sh"
readonly SCRIPT_NAME SCRIPT_DIR VERIFIER
readonly RAW_MAX_FILES=32768
readonly RAW_MAX_BYTES=603979776
readonly PUBLIC_FILE_COUNT=6
readonly PROFILE_CELL_FILE_COUNT=4

WORK_DIRECTORY=""
WORK_IDENTITY=""
CANDIDATE_DIRECTORY=""
CANDIDATE_IDENTITY=""
OUTPUT_DIRECTORY=""
OUTPUT_PARENT=""
declare -a SNAPSHOTS=()

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME ABS_ALL_GETSOCKOPT ABS_ALL_UNIX ABS_ALL_AUTO" \
    "       ABS_PID_REUSE_GETSOCKOPT ABS_PID_REUSE_UNIX ABS_NONEXISTENT_OUTPUT" \
    "       $SCRIPT_NAME --profile-cell-v1 ROLE RAW_KIND ABS_RAW ABS_OUTPUT" \
    "       $SCRIPT_NAME --aggregate-cells-v1 CELL1 CELL2 CELL3 CELL4 CELL5 ABS_OUTPUT" \
    "" \
    "Validate five private raw-v3 cells and publish one bounded six-file" \
    "fault/security matrix. Raw identifiers and raw artifacts are not copied."
}

die() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

check_dependencies() {
  local -a missing=()
  local command_name=""

  for command_name in awk chmod cmp cp find id jq mkdir mktemp mv readlink rm \
    sha256sum sort stat; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  (( ${#missing[@]} == 0 )) ||
    die "missing required commands: ${missing[*]}"
}

is_safe_name() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]]
}

is_safe_relative_path() {
  local -r path="$1"
  local remainder="$path"
  local component=""

  [[ -n "$path" && "$path" != /* && "$path" != */ && "$path" != *'//' ]] ||
    return 1
  while true; do
    if [[ "$remainder" == */* ]]; then
      component="${remainder%%/*}"
      remainder="${remainder#*/}"
    else
      component="$remainder"
      remainder=""
    fi
    [[ "$component" =~ ^[A-Za-z0-9._-]+$ &&
      "$component" != . && "$component" != .. ]] || return 1
    [[ -n "$remainder" ]] || return 0
  done
}

cleanup_owned_directory() {
  local -r path="$1"
  local -r expected_identity="$2"
  local observed_identity=""

  [[ -n "$path" && -n "$expected_identity" && -d "$path" && ! -L "$path" ]] ||
    return 0
  observed_identity="$(stat -Lc '%d:%i:%u' -- "$path")" || return 1
  [[ "$observed_identity" == "$expected_identity" ]] || return 1
  if [[ "$path" != /tmp/obi-fault-security-project.* ]]; then
    [[ -n "${OUTPUT_PARENT:-}" &&
      "$path" == "$OUTPUT_PARENT"/.fault-security-matrix.* ]] || return 1
  fi
  chmod -R u+rwX -- "$path" >/dev/null 2>&1 || return 1
  rm --one-file-system -rf -- "$path"
}

cleanup() {
  local status=0

  if [[ -n "${CANDIDATE_DIRECTORY:-}" && -d "$CANDIDATE_DIRECTORY" &&
    ! -L "$CANDIDATE_DIRECTORY" ]]; then
    cleanup_owned_directory "$CANDIDATE_DIRECTORY" "$CANDIDATE_IDENTITY" ||
      status=1
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
  ((status == 0))
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

directory_manifest() {
  local -r directory="$1"
  local -r output="$2"
  local relative=""
  local digest=""
  local size=""

  : >"$output"
  while IFS= read -r -d '' relative; do
    relative="${relative#./}"
    is_safe_relative_path "$relative" || return 1
    digest="$(sha256sum <"$directory/$relative")" || return 1
    digest="${digest%% *}"
    size="$(stat -Lc '%s' -- "$directory/$relative")" || return 1
    [[ "$digest" =~ ^[0-9a-f]{64}$ && "$size" =~ ^(0|[1-9][0-9]*)$ ]] ||
      return 1
    printf '%s\t%s\t%s\n' "$relative" "$size" "$digest" >>"$output" ||
      return 1
  done < <(CDPATH='' cd -- "$directory" && find . -type f -print0 |
    LC_ALL=C sort -z)
}

snapshot_raw_input() {
  local -r source="$1"
  local -r role="$2"
  local destination="$WORK_DIRECTORY/$role"
  local before="$WORK_DIRECTORY/$role.before"
  local after="$WORK_DIRECTORY/$role.after"
  local copied="$WORK_DIRECTORY/$role.copied"
  local count=""
  local bytes=""
  local source_identity=""
  local destination_identity=""

  [[ "$source" == /* && -d "$source" && ! -L "$source" &&
    "$(readlink -f -- "$source")" == "$source" ]] || return 1
  source_identity="$(stat -Lc '%d:%i:%u' -- "$source")" || return 1
  [[ "$source_identity" == *":$EUID" ]] || return 1
  [[ -z "$(find -- "$source" -mindepth 1 ! -type f ! -type d -print -quit)" ]] ||
    return 1
  count="$(find -- "$source" -type f -printf '.\n' | awk 'END {print NR + 0}')" ||
    return 1
  bytes="$(find -- "$source" -type f -printf '%s\n' |
    awk '{sum += $1} END {printf "%.0f\n", sum + 0}')" || return 1
  [[ "$count" =~ ^[1-9][0-9]*$ && "$bytes" =~ ^[1-9][0-9]*$ &&
    "$count" -le "$RAW_MAX_FILES" && "$bytes" -le "$RAW_MAX_BYTES" ]] ||
    return 1
  directory_manifest "$source" "$before" || return 1
  mkdir -m 0700 -- "$destination" || return 1
  destination_identity="$(stat -Lc '%d:%i:%u' -- "$destination")" || return 1
  [[ "$destination_identity" == *":$EUID" ]] || return 1
  cp -a -- "$source/." "$destination/" || return 1
  [[ -z "$(find -- "$source" -mindepth 1 ! -type f ! -type d \
    -print -quit)" &&
    -z "$(find -- "$destination" -mindepth 1 ! -type f ! -type d \
      -print -quit)" ]] || return 1
  [[ "$(stat -Lc '%d:%i:%u' -- "$source")" == "$source_identity" &&
    "$(stat -Lc '%d:%i:%u' -- "$destination")" == \
      "$destination_identity" ]] || return 1
  directory_manifest "$source" "$after" || return 1
  directory_manifest "$destination" "$copied" || return 1
  cmp -s -- "$before" "$after" && cmp -s -- "$before" "$copied" || return 1
  find -- "$destination" -type f -exec chmod 0400 -- {} + || return 1
  find -- "$destination" -depth -type d -exec chmod 0500 -- {} + || return 1
  SNAPSHOTS+=("$destination")
  printf '%s\n' "$destination"
}

key_value() {
  local -r file="$1"
  local -r key="$2"

  awk -F= -v key="$key" '
    $1 == key {count++; value = substr($0, length(key) + 2)}
    END {if (count != 1 || value == "") exit 1; print value}
  ' "$file"
}

private_commitment_json() {
  local -r role="$1"
  local -r snapshot="$2"
  local manifest="$WORK_DIRECTORY/$role.commitment"
  local digest=""
  local count=""
  local bytes=""

  directory_manifest "$snapshot" "$manifest" || return 1
  digest="$(sha256sum <"$manifest")" || return 1
  digest="${digest%% *}"
  count="$(awk 'END {print NR + 0}' "$manifest")" || return 1
  bytes="$(awk -F '\t' '{sum += $2} END {printf "%.0f\n", sum + 0}' \
    "$manifest")" || return 1
  jq -cn --arg sha256 "$digest" --argjson file_count "$count" \
    --argjson total_bytes "$bytes" '{
      schema: "obi-private-file-manifest-commitment-v1",
      sha256: $sha256,
      file_count: $file_count,
      total_bytes: $total_bytes
    }'
}

profile_json() {
  local -r id="$1"
  local -r kind="$2"
  local -r snapshot="$3"
  local environment="$snapshot/environment.txt"
  local index="$snapshot/obi-metric-boundary-index.json"
  local requested=""
  local selected=""
  local scenario=""
  local complete=""
  local not_applicable=""
  local commitment=""
  local pid_reuse=null

  requested="$(key_value "$environment" transport)" || return 1
  scenario="$(key_value "$environment" scenario)" || return 1
  selected="$(jq -er '.selection.selected_transport' "$index")" || return 1
  complete="$(jq -er '[.boundaries[] | select(.state == "complete")] | length' \
    "$index")" || return 1
  not_applicable="$(jq -er \
    '[.boundaries[] | select(.state == "not_applicable")] | length' \
    "$index")" || return 1
  commitment="$(private_commitment_json "$id" "$snapshot")" || return 1
  if [[ "$scenario" == pid-reuse ]]; then
    jq -e '.schema == "obi-pid-reuse-public-v1" and .status == "passed"' \
      "$snapshot/pid-reuse-controller.json" >/dev/null || return 1
    pid_reuse="$(jq -cS '{
      same_numeric_pid, same_numeric_tid, different_lifetime,
      a_reaped_before_b, authorization_maps_agree,
      injected_residue_rejected, injected_residue_preserved,
      w3c_fail_open, recovery_status, recovery_parent_exact,
      private_artifacts_removed, negative_status
    }' "$snapshot/pid-reuse-controller.json")" || return 1
  fi
  jq -cn --arg id "$id" --arg kind "$kind" --arg scenario "$scenario" \
    --arg requested "$requested" --arg selected "$selected" \
    --argjson complete "$complete" --argjson not_applicable "$not_applicable" \
    --argjson private_input "$commitment" --argjson pid_reuse "$pid_reuse" '{
      id: $id,
      raw_v3_profile: $kind,
      scenario: $scenario,
      requested_transport: $requested,
      selected_transport: $selected,
      status: "passed",
      boundary_summary: {
        complete: $complete,
        not_applicable: $not_applicable
      },
      private_input: $private_input,
      pid_reuse: $pid_reuse
  }'
}

validate_profile_cell_json() {
  local -r file="$1"
  local profile=''
  local expected_evidence_id=''

  cmp -s -- "$file" <(jq -cS . "$file") || return 1
  jq -e '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    . as $cell |
    keys == ["evidence_id","privacy","profile","raw_v3_profile","role",
      "schema","source","status"] and
    .schema == "obi-bounded-fault-security-profile-cell-v1" and
    .status == "passed" and (.evidence_id | sha256) and
    .privacy == {raw_identifiers_published:false,raw_inputs_retained:false} and
    (.source | keys == ["clean","revision","source_tree_sha256"] and
      (.revision | test("^[0-9a-f]{40}$")) and
      (.source_tree_sha256 | sha256) and .clean == true) and
    (.profile | keys == ["boundary_summary","id","pid_reuse","private_input",
      "raw_v3_profile","requested_transport","scenario","selected_transport",
      "status"] and .status == "passed" and .id == $cell.role and
      .raw_v3_profile == $cell.raw_v3_profile and
      (.boundary_summary | keys == ["complete","not_applicable"] and
        .complete >= 1 and .not_applicable >= 0) and
      (.private_input | keys == ["file_count","schema","sha256","total_bytes"] and
        .schema == "obi-private-file-manifest-commitment-v1" and
        (.sha256 | sha256) and .file_count >= 1 and .total_bytes >= 1)) and
    (($cell.role == "all-getsockopt" and
        $cell.raw_v3_profile == "acceptance-getsockopt" and
        .profile.scenario == "all" and
        .profile.requested_transport == "getsockopt" and
        .profile.selected_transport == "getsockopt" and
        .profile.pid_reuse == null) or
     ($cell.role == "all-unix" and $cell.raw_v3_profile == "acceptance-unix" and
        .profile.scenario == "all" and .profile.requested_transport == "unix" and
        .profile.selected_transport == "unix" and .profile.pid_reuse == null) or
     ($cell.role == "all-auto" and $cell.raw_v3_profile == "acceptance-auto" and
        .profile.scenario == "all" and .profile.requested_transport == "auto" and
        .profile.selected_transport == "getsockopt" and .profile.pid_reuse == null) or
     ($cell.role == "pid-reuse-getsockopt" and
        $cell.raw_v3_profile == "pid-reuse-getsockopt" and
        .profile.scenario == "pid-reuse" and
        .profile.requested_transport == "getsockopt" and
        .profile.selected_transport == "getsockopt") or
     ($cell.role == "pid-reuse-unix" and
        $cell.raw_v3_profile == "pid-reuse-unix" and
        .profile.scenario == "pid-reuse" and
        .profile.requested_transport == "unix" and
        .profile.selected_transport == "unix")) and
    (if .profile.pid_reuse == null then true else
      (.profile.pid_reuse | keys == ["a_reaped_before_b","authorization_maps_agree",
        "different_lifetime","injected_residue_preserved","injected_residue_rejected",
        "negative_status","private_artifacts_removed","recovery_parent_exact",
        "recovery_status","same_numeric_pid","same_numeric_tid","w3c_fail_open"] and
       .same_numeric_pid == true and .same_numeric_tid == true and
       .different_lifetime == true and .a_reaped_before_b == true and
       .authorization_maps_agree == true and .injected_residue_rejected == true and
       .injected_residue_preserved == true and .w3c_fail_open == true and
       .recovery_status == "valid" and .recovery_parent_exact == true and
       .private_artifacts_removed == true and
       (($cell.role == "pid-reuse-getsockopt" and
          .negative_status == "unsupported") or
        ($cell.role == "pid-reuse-unix" and .negative_status == "ambiguous")))
     end)
  ' "$file" >/dev/null || return 1
  profile="$(jq -cS '.profile' "$file")" || return 1
  expected_evidence_id="$(printf '%s\n' \
    'obi-bounded-fault-security-profile-cell-v1' \
    "$(jq -er '.source.revision' "$file")" \
    "$(jq -er '.source.source_tree_sha256' "$file")" \
    "$(jq -er '.role' "$file")" "$profile" | sha256sum)" || return 1
  expected_evidence_id="${expected_evidence_id%% *}"
  [[ "$(jq -er '.evidence_id' "$file")" == "$expected_evidence_id" ]]
}

write_portable_verifier() {
  local -r output="$1"

  cat >"$output" <<'VERIFY'
#!/usr/bin/env bash
set -Eeuo pipefail

bundle_directory="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'README.md\tf\nSANITIZATION.md\tf\nSHA256SUMS\tf\nderivation-receipt.json\tf\nfault-security-matrix.json\tf\nverify.sh\tf'
observed="$(find -H "$bundle_directory" -mindepth 1 -maxdepth 1 \
  -printf '%f\t%y\n' | LC_ALL=C sort)"
[[ "$observed" == "$expected" ]]
while IFS= read -r line; do
  [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]]
  [[ "${BASH_REMATCH[2]}" != SHA256SUMS ]]
done <"$bundle_directory/SHA256SUMS"
[[ "$(awk 'END {print NR + 0}' "$bundle_directory/SHA256SUMS")" == 5 ]]
(CDPATH='' cd -- "$bundle_directory" && sha256sum --check --strict SHA256SUMS \
  >/dev/null)
jq -e '
  keys == ["coverage", "privacy", "profiles", "schema", "source", "status"] and
  .schema == "obi-bounded-fault-security-matrix-v1" and .status == "passed" and
  (.source | keys == ["agent_distribution", "clean", "revision",
    "source_tree_sha256", "tls_protocol"] and .clean == true and
    .agent_distribution == "otel" and .tls_protocol == "TLSv1.3" and
    (.revision | test("^[0-9a-f]{40}$")) and
    (.source_tree_sha256 | test("^[0-9a-f]{64}$"))) and
  (.privacy == {
    raw_identifiers_published: false,
    raw_inputs_retained: false,
    unsupported_pid_reuse_outcome: "rejected"
  }) and
  (.profiles | map(.id)) == [
    "all-getsockopt", "all-unix", "all-auto",
    "pid-reuse-getsockopt", "pid-reuse-unix"
  ] and
  (.profiles | map([.scenario, .requested_transport,
    .selected_transport, .status])) == [
      ["all", "getsockopt", "getsockopt", "passed"],
      ["all", "unix", "unix", "passed"],
      ["all", "auto", "getsockopt", "passed"],
      ["pid-reuse", "getsockopt", "getsockopt", "passed"],
      ["pid-reuse", "unix", "unix", "passed"]
    ] and
  all(.profiles[];
    (keys == ["boundary_summary", "id", "pid_reuse", "private_input",
      "raw_v3_profile", "requested_transport", "scenario",
      "selected_transport", "status"]) and
    (.boundary_summary | keys == ["complete", "not_applicable"] and
      .complete >= 1 and .not_applicable >= 0) and
    (.private_input | keys == ["file_count", "schema", "sha256", "total_bytes"] and
      .schema == "obi-private-file-manifest-commitment-v1" and
      (.sha256 | test("^[0-9a-f]{64}$")) and .file_count >= 1 and
      .total_bytes >= 1)) and
  all(.profiles[0:3][]; .pid_reuse == null) and
  all(.profiles[3:5][];
    (.pid_reuse | keys == ["a_reaped_before_b", "authorization_maps_agree",
      "different_lifetime", "injected_residue_preserved",
      "injected_residue_rejected", "negative_status",
      "private_artifacts_removed", "recovery_parent_exact", "recovery_status",
      "same_numeric_pid", "same_numeric_tid", "w3c_fail_open"] and
      .same_numeric_pid == true and .same_numeric_tid == true and
      .different_lifetime == true and .a_reaped_before_b == true and
      .authorization_maps_agree == true and
      .injected_residue_rejected == true and
      .injected_residue_preserved == true and .w3c_fail_open == true and
      .recovery_status == "valid" and .recovery_parent_exact == true and
      .private_artifacts_removed == true)) and
  .profiles[3].pid_reuse.negative_status == "unsupported" and
  .profiles[4].pid_reuse.negative_status == "ambiguous" and
  .coverage == {
    issue_36: {status: "passed", profiles: [
      "all-getsockopt", "all-unix", "all-auto",
      "pid-reuse-getsockopt", "pid-reuse-unix"]},
    issue_40: {status: "passed", profiles: [
      "all-getsockopt", "all-unix",
      "pid-reuse-getsockopt", "pid-reuse-unix"]}
  }
' "$bundle_directory/fault-security-matrix.json" >/dev/null
matrix_sha256="$(sha256sum <"$bundle_directory/fault-security-matrix.json")"
matrix_sha256="${matrix_sha256%% *}"
verifier_sha256="$(sha256sum <"$bundle_directory/verify.sh")"
verifier_sha256="${verifier_sha256%% *}"
jq -e --arg matrix_sha256 "$matrix_sha256" \
  --arg verifier_sha256 "$verifier_sha256" '
  keys == ["derivation_contract", "matrix", "public_file_order", "schema",
    "verifier"] and
  .schema == "obi-bounded-fault-security-derivation-v1" and
  .derivation_contract == "private-raw-v3-to-bounded-fault-security-matrix-v1" and
  .matrix == {reference: "fault-security-matrix.json", sha256: $matrix_sha256} and
  .verifier == {reference: "verify.sh", sha256: $verifier_sha256} and
  .public_file_order == ["README.md", "SANITIZATION.md",
    "fault-security-matrix.json", "derivation-receipt.json", "verify.sh",
    "SHA256SUMS"]
' "$bundle_directory/derivation-receipt.json" >/dev/null
evidence_id="$(sha256sum <"$bundle_directory/derivation-receipt.json")"
evidence_id="${evidence_id%% *}"
printf 'bounded fault/security matrix internally consistent (not authenticated): %s\n' \
  "$evidence_id"
VERIFY
  chmod 0444 -- "$output"
}

write_public_bundle() {
  local -r revision="$1"
  local -r source_tree_sha256="$2"
  shift 2
  local profiles_json=""
  local matrix_sha256=""
  local verifier_sha256=""
  local file=""
  local -a profile_rows=("$@")

  profiles_json="$(printf '%s\n' "${profile_rows[@]}" | jq -cs '.')" || return 1
  jq -cS -n --arg revision "$revision" --arg tree "$source_tree_sha256" \
    --argjson profiles "$profiles_json" '{
      schema: "obi-bounded-fault-security-matrix-v1",
      status: "passed",
      source: {
        revision: $revision,
        source_tree_sha256: $tree,
        clean: true,
        agent_distribution: "otel",
        tls_protocol: "TLSv1.3"
      },
      profiles: $profiles,
      coverage: {
        issue_36: {status: "passed", profiles: [
          "all-getsockopt", "all-unix", "all-auto",
          "pid-reuse-getsockopt", "pid-reuse-unix"]},
        issue_40: {status: "passed", profiles: [
          "all-getsockopt", "all-unix",
          "pid-reuse-getsockopt", "pid-reuse-unix"]}
      },
      privacy: {
        raw_identifiers_published: false,
        raw_inputs_retained: false,
        unsupported_pid_reuse_outcome: "rejected"
      }
    }' >"$CANDIDATE_DIRECTORY/fault-security-matrix.json" || return 1

  printf '%s\n' \
    '# Bounded Java remote-parent fault/security matrix' \
    '' \
    'This six-file bundle records five independently validated current-source cells:' \
    'full forced getsockopt, full forced Unix, full auto selection, and accepted' \
    'numeric PID/TID-reuse controls for each forced transport.' \
    '' \
    'The matrix is publishable only when every cell passes. A PID-reuse controller' \
    'that reports unsupported is rejected and cannot be represented as a pass.' \
    '' \
    'Run bash verify.sh from any directory to check the closed bundle.' \
    >"$CANDIDATE_DIRECTORY/README.md" || return 1
  printf '%s\n' \
    '# Sanitization contract' \
    '' \
    '- No trace ID, span ID, request marker, process ID, thread ID, socket path,' \
    '  container ID, host path, raw log, metric sample, or raw evidence filename is published.' \
    '- Private input roots are represented only by role-bound manifest commitments,' \
    '  file counts, and byte counts.' \
    '- Raw inputs remain private transaction data and are destroyed by the campaign' \
    '  before this bundle is eligible for upload.' \
    >"$CANDIDATE_DIRECTORY/SANITIZATION.md" || return 1
  write_portable_verifier "$CANDIDATE_DIRECTORY/verify.sh" || return 1
  matrix_sha256="$(sha256sum \
    <"$CANDIDATE_DIRECTORY/fault-security-matrix.json")" || return 1
  matrix_sha256="${matrix_sha256%% *}"
  verifier_sha256="$(sha256sum <"$CANDIDATE_DIRECTORY/verify.sh")" || return 1
  verifier_sha256="${verifier_sha256%% *}"
  jq -cS -n --arg matrix_sha256 "$matrix_sha256" \
    --arg verifier_sha256 "$verifier_sha256" '{
      schema: "obi-bounded-fault-security-derivation-v1",
      derivation_contract: "private-raw-v3-to-bounded-fault-security-matrix-v1",
      matrix: {reference: "fault-security-matrix.json", sha256: $matrix_sha256},
      verifier: {reference: "verify.sh", sha256: $verifier_sha256},
      public_file_order: ["README.md", "SANITIZATION.md",
        "fault-security-matrix.json", "derivation-receipt.json", "verify.sh",
        "SHA256SUMS"]
    }' >"$CANDIDATE_DIRECTORY/derivation-receipt.json" || return 1
  (
    CDPATH='' cd -- "$CANDIDATE_DIRECTORY"
    for file in README.md SANITIZATION.md fault-security-matrix.json \
      derivation-receipt.json verify.sh; do
      sha256sum "$file"
    done
  ) >"$CANDIDATE_DIRECTORY/SHA256SUMS" || return 1
  find -- "$CANDIDATE_DIRECTORY" -type f -exec chmod 0444 -- {} + || return 1
  find -- "$CANDIDATE_DIRECTORY" -depth -type d -exec chmod 0555 -- {} + ||
    return 1
  (CDPATH='' cd / && bash "$CANDIDATE_DIRECTORY/verify.sh" >/dev/null) || return 1
  [[ "$(find -- "$CANDIDATE_DIRECTORY" -type f -printf '.\n' |
    awk 'END {print NR + 0}')" == "$PUBLIC_FILE_COUNT" ]] || return 1
}

emit_profile_cell_verifier() {
  cat <<'VERIFY_CELL'
#!/usr/bin/env bash
set -Eeuo pipefail
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'SANITIZATION.md\tf\nSHA256SUMS\tf\nprofile.json\tf\nverify.sh\tf'
observed="$(find -H "$root" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)"
[[ "$observed" == "$expected" ]]
[[ "$(awk 'END {print NR + 0}' "$root/SHA256SUMS")" == 3 ]]
(CDPATH='' cd -- "$root" && sha256sum --check --strict SHA256SUMS >/dev/null)
cmp -s -- "$root/profile.json" <(jq -cS . "$root/profile.json")
jq -e '
  def sha256: type == "string" and test("^[0-9a-f]{64}$");
  . as $cell |
  keys == ["evidence_id","privacy","profile","raw_v3_profile","role",
    "schema","source","status"] and
  .schema == "obi-bounded-fault-security-profile-cell-v1" and
  .status == "passed" and (.evidence_id | sha256) and
  .privacy == {raw_identifiers_published:false,raw_inputs_retained:false} and
  (.source | keys == ["clean","revision","source_tree_sha256"] and
    (.revision | test("^[0-9a-f]{40}$")) and
    (.source_tree_sha256 | sha256) and .clean == true) and
  (.profile | keys == ["boundary_summary","id","pid_reuse","private_input",
    "raw_v3_profile","requested_transport","scenario","selected_transport",
    "status"] and .status == "passed" and .id == $cell.role and
    .raw_v3_profile == $cell.raw_v3_profile and
    (.boundary_summary | keys == ["complete","not_applicable"] and
      .complete >= 1 and .not_applicable >= 0) and
    (.private_input | keys == ["file_count","schema","sha256","total_bytes"] and
      .schema == "obi-private-file-manifest-commitment-v1" and
      (.sha256 | sha256) and .file_count >= 1 and .total_bytes >= 1)) and
  (($cell.role == "all-getsockopt" and
      $cell.raw_v3_profile == "acceptance-getsockopt" and
      .profile.scenario == "all" and .profile.requested_transport == "getsockopt" and
      .profile.selected_transport == "getsockopt" and .profile.pid_reuse == null) or
   ($cell.role == "all-unix" and $cell.raw_v3_profile == "acceptance-unix" and
      .profile.scenario == "all" and .profile.requested_transport == "unix" and
      .profile.selected_transport == "unix" and .profile.pid_reuse == null) or
   ($cell.role == "all-auto" and $cell.raw_v3_profile == "acceptance-auto" and
      .profile.scenario == "all" and .profile.requested_transport == "auto" and
      .profile.selected_transport == "getsockopt" and .profile.pid_reuse == null) or
   ($cell.role == "pid-reuse-getsockopt" and
      $cell.raw_v3_profile == "pid-reuse-getsockopt" and
      .profile.scenario == "pid-reuse" and
      .profile.requested_transport == "getsockopt" and
      .profile.selected_transport == "getsockopt") or
   ($cell.role == "pid-reuse-unix" and
      $cell.raw_v3_profile == "pid-reuse-unix" and
      .profile.scenario == "pid-reuse" and .profile.requested_transport == "unix" and
      .profile.selected_transport == "unix")) and
  (if .profile.pid_reuse == null then true else
    (.profile.pid_reuse | keys == ["a_reaped_before_b","authorization_maps_agree",
      "different_lifetime","injected_residue_preserved","injected_residue_rejected",
      "negative_status","private_artifacts_removed","recovery_parent_exact",
      "recovery_status","same_numeric_pid","same_numeric_tid","w3c_fail_open"] and
     .same_numeric_pid == true and .same_numeric_tid == true and
     .different_lifetime == true and .a_reaped_before_b == true and
     .authorization_maps_agree == true and .injected_residue_rejected == true and
     .injected_residue_preserved == true and .w3c_fail_open == true and
     .recovery_status == "valid" and .recovery_parent_exact == true and
     .private_artifacts_removed == true and
     (($cell.role == "pid-reuse-getsockopt" and
        .negative_status == "unsupported") or
      ($cell.role == "pid-reuse-unix" and .negative_status == "ambiguous")))
   end)
' "$root/profile.json" >/dev/null
profile="$(jq -cS '.profile' "$root/profile.json")"
expected_evidence_id="$(printf '%s\n' \
  'obi-bounded-fault-security-profile-cell-v1' \
  "$(jq -er '.source.revision' "$root/profile.json")" \
  "$(jq -er '.source.source_tree_sha256' "$root/profile.json")" \
  "$(jq -er '.role' "$root/profile.json")" "$profile" | sha256sum)"
expected_evidence_id="${expected_evidence_id%% *}"
[[ "$(jq -er '.evidence_id' "$root/profile.json")" == "$expected_evidence_id" ]]
if grep -Eqi -- '(/tmp/|/home/|/proc/|"(pid|tid|trace_id|span_id|socket_path|binary|binaries)"[[:space:]]*:|\.log")' "$root/profile.json"; then
  printf '%s\n' 'private raw identifier leaked into profile cell' >&2
  exit 1
fi
printf 'bounded fault/security profile cell internally consistent: %s\n' \
  "$(jq -er '.evidence_id' "$root/profile.json")"
VERIFY_CELL
}

write_profile_cell_verifier() {
  local -r output="$1"
  emit_profile_cell_verifier >"$output" || return 1
  chmod 0444 -- "$output"
}

write_profile_cell_bundle() {
  local -r role="$1"
  local -r kind="$2"
  local -r snapshot="$3"
  local revision=""
  local tree=""
  local profile=""
  local evidence_id=""
  local file=""

  revision="$(key_value "$snapshot/environment.txt" revision)" || return 1
  tree="$(key_value "$snapshot/environment.txt" source_tree_sha256)" || return 1
  profile="$(profile_json "$role" "$kind" "$snapshot" | jq -cS .)" || return 1
  evidence_id="$(printf '%s\n' 'obi-bounded-fault-security-profile-cell-v1' \
    "$revision" "$tree" "$role" "$profile" | sha256sum)" || return 1
  evidence_id="${evidence_id%% *}"
  CANDIDATE_DIRECTORY="$(mktemp -d "$OUTPUT_PARENT/.fault-security-matrix.XXXXXX")" ||
    return 1
  CANDIDATE_DIRECTORY="$(CDPATH='' cd -- "$CANDIDATE_DIRECTORY" && pwd -P)"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")"
  jq -cS -n --arg evidence_id "$evidence_id" --arg role "$role" \
    --arg kind "$kind" --arg revision "$revision" --arg tree "$tree" \
    --argjson profile "$profile" '{
      schema:"obi-bounded-fault-security-profile-cell-v1",status:"passed",
      evidence_id:$evidence_id,role:$role,raw_v3_profile:$kind,
      source:{revision:$revision,source_tree_sha256:$tree,clean:true},
      profile:$profile,
      privacy:{raw_identifiers_published:false,raw_inputs_retained:false}}
  ' >"$CANDIDATE_DIRECTORY/profile.json" || return 1
  printf '%s\n' '# Sanitized fault/security profile cell' '' \
    'This handoff contains a bounded profile summary and a role-bound raw manifest' \
    'commitment only. Raw evidence was destroyed before this directory became uploadable.' \
    >"$CANDIDATE_DIRECTORY/SANITIZATION.md" || return 1
  write_profile_cell_verifier "$CANDIDATE_DIRECTORY/verify.sh" || return 1
  (
    CDPATH='' cd -- "$CANDIDATE_DIRECTORY"
    for file in SANITIZATION.md profile.json verify.sh; do sha256sum "$file"; done
  ) >"$CANDIDATE_DIRECTORY/SHA256SUMS" || return 1
  find -- "$CANDIDATE_DIRECTORY" -type f -exec chmod 0444 -- {} + || return 1
  find -- "$CANDIDATE_DIRECTORY" -depth -type d -exec chmod 0555 -- {} + ||
    return 1
  (CDPATH='' cd / && bash "$CANDIDATE_DIRECTORY/verify.sh" >/dev/null) || return 1
  [[ "$(find -- "$CANDIDATE_DIRECTORY" -type f -printf '.\n' |
    awk 'END {print NR + 0}')" == "$PROFILE_CELL_FILE_COUNT" ]] || return 1
}

prepare_projection_transaction() {
  OUTPUT_DIRECTORY="$1"
  [[ "$OUTPUT_DIRECTORY" == /* && ! -e "$OUTPUT_DIRECTORY" &&
    ! -L "$OUTPUT_DIRECTORY" ]] || die "output must be absolute and nonexistent"
  is_safe_name "${OUTPUT_DIRECTORY##*/}" || die "output name is unsafe"
  OUTPUT_PARENT="${OUTPUT_DIRECTORY%/*}"
  [[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" &&
    "$(readlink -f -- "$OUTPUT_PARENT")" == "$OUTPUT_PARENT" &&
    "$(stat -Lc '%u:%a' -- "$OUTPUT_PARENT")" == "$EUID:700" ]] ||
    die "output parent must be a private physical directory owned by the caller"
  WORK_DIRECTORY="$(mktemp -d /tmp/obi-fault-security-project.XXXXXX)" ||
    die "could not create private projection transaction"
  WORK_DIRECTORY="$(CDPATH='' cd -- "$WORK_DIRECTORY" && pwd -P)"
  WORK_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$WORK_DIRECTORY")"
  [[ "$(stat -Lc '%u:%a' -- "$WORK_DIRECTORY")" == "$EUID:700" ]] ||
    die "private projection transaction has unsafe ownership or mode"
}

profile_cell_main() {
  local -r role="$1"
  local -r kind="$2"
  local -r source="$3"
  local -r output="$4"
  local snapshot=""

  case "$role:$kind" in
    all-getsockopt:acceptance-getsockopt|all-unix:acceptance-unix|\
      all-auto:acceptance-auto|pid-reuse-getsockopt:pid-reuse-getsockopt|\
      pid-reuse-unix:pid-reuse-unix)
      ;;
    *)
      die "profile role and raw kind do not form an exact matrix cell"
      ;;
  esac
  check_dependencies
  [[ -x "$VERIFIER" && -f "$VERIFIER" && ! -L "$VERIFIER" ]] ||
    die "raw verifier is not an executable regular file"
  prepare_projection_transaction "$output"
  snapshot="$(snapshot_raw_input "$source" "$role")" ||
    die "could not snapshot $role"
  "$VERIFIER" --raw-v3 "$kind" "$snapshot" >/dev/null ||
    die "raw-v3 validation failed for $role"
  write_profile_cell_bundle "$role" "$kind" "$snapshot" ||
    die "could not build bounded profile cell"
  mv -T -- "$CANDIDATE_DIRECTORY" "$OUTPUT_DIRECTORY" ||
    die "could not publish bounded profile cell"
  CANDIDATE_DIRECTORY=""
  CANDIDATE_IDENTITY=""
  (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null) ||
    die "published profile cell did not reverify"
}

aggregate_cells_main() {
  local -a sources=("$1" "$2" "$3" "$4" "$5")
  local -a roles=(
    all-getsockopt all-unix all-auto pid-reuse-getsockopt pid-reuse-unix
  )
  local output="$6"
  local source=""
  local role=""
  local observed_role=""
  local revision=""
  local tree=""
  local observed_revision=""
  local observed_tree=""
  local profile=""
  local index=0
  local expected=$'SANITIZATION.md\tf\nSHA256SUMS\tf\nprofile.json\tf\nverify.sh\tf'
  local observed=""
  local -a profiles=()

  check_dependencies
  prepare_projection_transaction "$output"
  for index in "${!sources[@]}"; do
    source="${sources[index]}"
    [[ "$source" == /* && -d "$source" && ! -L "$source" &&
      "$(readlink -f -- "$source")" == "$source" ]] ||
      die "profile cell is not a physical absolute directory"
    observed="$(find -- "$source" -mindepth 1 -maxdepth 1 \
      -printf '%f\t%y\n' | LC_ALL=C sort)" || die "could not inspect profile cell"
    [[ "$observed" == "$expected" ]] || die "profile cell inventory is not exact"
    [[ "$(awk 'END {print NR + 0}' "$source/SHA256SUMS")" == 3 ]] ||
      die "profile cell manifest is not exact"
    (CDPATH='' cd -- "$source" &&
      sha256sum --check --strict SHA256SUMS >/dev/null) ||
      die "profile cell manifest failed"
    cmp -s -- "$source/verify.sh" <(emit_profile_cell_verifier) ||
      die "profile cell verifier bytes are not source-authenticated"
    validate_profile_cell_json "$source/profile.json" ||
      die "profile cell schema or bounded semantics are invalid"
    observed_role="$(jq -er '.role' "$source/profile.json")" ||
      die "profile cell role is absent"
    role="${roles[index]}"
    [[ "$observed_role" == "$role" ]] || die "profile cells are mixed or reordered"
    observed_revision="$(jq -er '.source.revision' "$source/profile.json")" || return 1
    observed_tree="$(jq -er '.source.source_tree_sha256' "$source/profile.json")" || return 1
    if ((index == 0)); then revision="$observed_revision"; tree="$observed_tree"; fi
    [[ "$observed_revision" == "$revision" && "$observed_tree" == "$tree" ]] ||
      die "profile cells do not share one exact source"
    profile="$(jq -cS '.profile' "$source/profile.json")" || return 1
    profiles+=("$profile")
  done
  CANDIDATE_DIRECTORY="$(mktemp -d "$OUTPUT_PARENT/.fault-security-matrix.XXXXXX")" ||
    die "could not create public matrix candidate"
  CANDIDATE_DIRECTORY="$(CDPATH='' cd -- "$CANDIDATE_DIRECTORY" && pwd -P)"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")"
  write_public_bundle "$revision" "$tree" "${profiles[@]}" ||
    die "could not build the bounded matrix from profile cells"
  mv -T -- "$CANDIDATE_DIRECTORY" "$OUTPUT_DIRECTORY" ||
    die "could not publish the bounded matrix"
  CANDIDATE_DIRECTORY=""
  CANDIDATE_IDENTITY=""
  (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null) ||
    die "published bounded matrix did not reverify"
}

raw_matrix_main() {
  local -a sources=()
  local -a roles=(
    all-getsockopt all-unix all-auto pid-reuse-getsockopt pid-reuse-unix
  )
  local -a kinds=(
    acceptance-getsockopt acceptance-unix acceptance-auto
    pid-reuse-getsockopt pid-reuse-unix
  )
  local -a profiles=()
  local source=""
  local snapshot=""
  local revision=""
  local tree=""
  local observed_revision=""
  local observed_tree=""
  local index=0

  if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    usage
    return 0
  fi
  [[ $# == 6 ]] || {
    usage >&2
    return 2
  }
  check_dependencies
  [[ -x "$VERIFIER" && -f "$VERIFIER" && ! -L "$VERIFIER" ]] ||
    die "raw verifier is not an executable regular file"
  sources=("$1" "$2" "$3" "$4" "$5")
  prepare_projection_transaction "$6"

  for index in "${!sources[@]}"; do
    source="${sources[index]}"
    snapshot="$(snapshot_raw_input "$source" "${roles[index]}")" ||
      die "could not snapshot ${roles[index]}"
    "$VERIFIER" --raw-v3 "${kinds[index]}" "$snapshot" >/dev/null ||
      die "raw-v3 validation failed for ${roles[index]}"
    observed_revision="$(key_value "$snapshot/environment.txt" revision)" ||
      die "missing source revision for ${roles[index]}"
    observed_tree="$(key_value "$snapshot/environment.txt" source_tree_sha256)" ||
      die "missing source tree for ${roles[index]}"
    if ((index == 0)); then
      revision="$observed_revision"
      tree="$observed_tree"
    fi
    [[ "$observed_revision" == "$revision" && "$observed_tree" == "$tree" ]] ||
      die "matrix cells do not share one exact source"
    profiles+=("$(profile_json \
      "${roles[index]}" "${kinds[index]}" "$snapshot")")
  done

  CANDIDATE_DIRECTORY="$(mktemp -d "$OUTPUT_PARENT/.fault-security-matrix.XXXXXX")" ||
    die "could not create public candidate"
  CANDIDATE_DIRECTORY="$(CDPATH='' cd -- "$CANDIDATE_DIRECTORY" && pwd -P)"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")"
  write_public_bundle "$revision" "$tree" "${profiles[@]}" ||
    die "could not build the bounded matrix"
  mv -T -- "$CANDIDATE_DIRECTORY" "$OUTPUT_DIRECTORY" ||
    die "could not publish the bounded matrix"
  CANDIDATE_DIRECTORY=""
  CANDIDATE_IDENTITY=""
  (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null) ||
    die "published bounded matrix did not reverify"
  printf 'bounded fault/security matrix published: %s\n' "$OUTPUT_DIRECTORY"
}

main() {
  case "${1:-}" in
    --profile-cell-v1)
      [[ $# == 5 ]] || { usage >&2; return 2; }
      profile_cell_main "$2" "$3" "$4" "$5"
      ;;
    --aggregate-cells-v1)
      [[ $# == 7 ]] || { usage >&2; return 2; }
      aggregate_cells_main "$2" "$3" "$4" "$5" "$6" "$7"
      ;;
    -h|--help)
      usage
      ;;
    *)
      raw_matrix_main "$@"
      ;;
  esac
}

main "$@"
