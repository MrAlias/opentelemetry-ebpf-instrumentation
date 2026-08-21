#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIRECTORY/../../.." && pwd -P)"
readonly SCRIPT_NAME SCRIPT_DIRECTORY REPOSITORY_ROOT

readonly REPOSITORY='MrAlias/opentelemetry-ebpf-instrumentation'
readonly BRANCH='agent/java-remote-parent-bridge'
readonly REF="refs/heads/$BRANCH"
readonly WORKFLOW_PATH='.github/workflows/java_remote_parent_acceptance_claims.yml'
readonly WORKFLOW_NAME='Java remote-parent bounded acceptance claims'
readonly MAX_API_BYTES=2097152
readonly MAX_ARCHIVE_BYTES=16777216
readonly MAX_EXPANDED_BYTES=8388608
readonly MAX_MEMBER_BYTES=2097152
readonly MAX_MEMBERS=16
readonly -a ACCEPTANCE_FILES=(
  README.md SANITIZATION.md acceptance-claims.json authority-summary.json
  derivation-receipt.json verify.sh SHA256SUMS
)
readonly -a FAULT_FILES=(
  README.md SANITIZATION.md fault-security-matrix.json derivation-receipt.json
  verify.sh SHA256SUMS
)

WORK_DIRECTORY=''
WORK_IDENTITY=''
CANDIDATE_DIRECTORY=''
CANDIDATE_IDENTITY=''
OUTPUT_DIRECTORY=''
OUTPUT_PARENT=''
OUTPUT_PARENT_IDENTITY=''
OUTPUT_NAME=''
HEAD_SHA=''
SOURCE_TREE_SHA256=''
RUN_ID=''
RUN_ATTEMPT=''
EVIDENCE_ID=''
ACCEPTANCE_ARTIFACT=''
FAULT_ARTIFACT=''

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME claims-v1 RUN.json ARTIFACTS.json ACCEPTANCE.zip FAULT.zip ABS_OUTPUT" \
    '' \
    'Post-run promotion only: import one completed, successful fixed-branch run' \
    'from a clean checkout at that run head into a source-bound canonical bundle.' \
    'The importer refuses GITHUB_OUTPUT so it cannot promote its own active run.'
}

die() {
  printf '%s: ERROR: %s\n' "$SCRIPT_NAME" "$*" >&2
  return 1
}

require_commands() {
  local command=''
  for command in awk bash chmod cmp cp find git install jq mktemp mv python3 \
    readlink sha256sum sort stat; do
    command -v "$command" >/dev/null 2>&1 ||
      die "required command is unavailable: $command" || return 1
  done
}

is_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

is_safe_leaf() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ &&
    "$1" != . && "$1" != .. ]]
}

safe_owned_regular() {
  local -r file="$1"
  local -r maximum="$2"
  local identity=''
  local owner=''
  local mode=''
  local links=''
  local size=''

  [[ "$file" == /* && -f "$file" && ! -L "$file" &&
    "$(readlink -f -- "$file")" == "$file" ]] || return 1
  identity="$(stat -Lc '%u:%a:%h:%s' -- "$file")" || return 1
  IFS=: read -r owner mode links size <<<"$identity"
  [[ "$owner" == "$EUID" && "$mode" =~ ^[0-7]{3,4}$ &&
    $((8#$mode & 0022)) == 0 && "$links" == 1 &&
    "$size" =~ ^[1-9][0-9]*$ && "$size" -le "$maximum" ]]
}

reject_duplicate_json_keys() {
  local -r file="$1"
  python3 - "$file" <<'PY'
import json
import sys

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result

with open(sys.argv[1], "rb") as source:
    value = json.load(source, object_pairs_hook=unique)
if not isinstance(value, dict):
    raise ValueError("top-level JSON value must be an object")
PY
}

canonical_json() {
  local -r file="$1"
  local canonical=''
  canonical="$(jq -cS . "$file")" || return 1
  cmp -s -- "$file" <(printf '%s\n' "$canonical")
}

validate_json_authority() {
  local -r file="$1"
  safe_owned_regular "$file" "$MAX_API_BYTES" || return 1
  reject_duplicate_json_keys "$file" || return 1
  jq -e 'type == "object"' "$file" >/dev/null
}

snapshot_input_checkpoint() {
  :
}

snapshot_owned_regular() {
  local -r source="$1"
  local -r maximum="$2"
  local -r destination="$3"
  local source_fd=''
  local path_identity=''
  local descriptor_identity=''

  safe_owned_regular "$source" "$maximum" || return 1
  [[ "$destination" == /* && ! -e "$destination" && ! -L "$destination" &&
    -d "${destination%/*}" && ! -L "${destination%/*}" ]] || return 1
  exec {source_fd}<"$source" || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$source")" || {
    exec {source_fd}<&-
    return 1
  }
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/self/fd/$source_fd")" || {
    exec {source_fd}<&-
    return 1
  }
  if [[ "$path_identity" != "$descriptor_identity" || ! -f "$source" ||
    -L "$source" || "$(readlink -f -- "$source")" != "$source" ]]; then
    exec {source_fd}<&-
    return 1
  fi
  snapshot_input_checkpoint "$source" || {
    exec {source_fd}<&-
    return 1
  }
  if ! python3 - "$source_fd" "$destination" "$maximum" <<'PY'
import os
import sys

source_fd, destination, maximum = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
with os.fdopen(os.dup(source_fd), "rb") as source:
    data = source.read(maximum + 1)
if not data or len(data) > maximum:
    raise ValueError("input snapshot size is out of bounds")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
output_fd = os.open(destination, flags, 0o400)
try:
    with os.fdopen(output_fd, "wb") as output:
        output_fd = -1
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
finally:
    if output_fd >= 0:
        os.close(output_fd)
PY
  then
    exec {source_fd}<&-
    return 1
  fi
  exec {source_fd}<&-
}

directory_manifest() {
  local -r directory="$1"
  local -r output="$2"
  local relative=''
  local size=''
  local digest=''
  : >"$output"
  while IFS= read -r -d '' relative; do
    relative="${relative#./}"
    is_safe_leaf "$relative" || return 1
    size="$(stat -Lc '%s' -- "$directory/$relative")" || return 1
    digest="$(sha256sum <"$directory/$relative")" || return 1
    digest="${digest%% *}"
    printf '%s\t%s\t%s\n' "$relative" "$size" "$digest" >>"$output" ||
      return 1
  done < <(CDPATH='' cd -- "$directory" &&
    find . -mindepth 1 -maxdepth 1 -type f -print0 | LC_ALL=C sort -z)
}

cleanup_owned_directory() {
  local -r path="$1"
  local -r expected_identity="$2"
  [[ -n "$path" && -n "$expected_identity" && -d "$path" &&
    ! -L "$path" && "$(stat -Lc '%d:%i:%u' -- "$path")" == "$expected_identity" ]] ||
    return 1
  case "$path" in
    /tmp/obi-retained-ci-import.*|"$OUTPUT_PARENT"/.retained-ci-import.*|\
      "$OUTPUT_DIRECTORY")
      ;;
    *)
      return 1
      ;;
  esac
  chmod -R u+rwX -- "$path" >/dev/null 2>&1 || return 1
  find -- "$path" -xdev -depth -delete
}

cleanup() {
  local original_status="$?"
  local cleanup_status=0
  trap - EXIT HUP INT TERM
  if [[ -n "$CANDIDATE_DIRECTORY" && -e "$CANDIDATE_DIRECTORY" ]]; then
    cleanup_owned_directory "$CANDIDATE_DIRECTORY" "$CANDIDATE_IDENTITY" ||
      cleanup_status=1
  fi
  if [[ -n "$WORK_DIRECTORY" && -e "$WORK_DIRECTORY" ]]; then
    cleanup_owned_directory "$WORK_DIRECTORY" "$WORK_IDENTITY" ||
      cleanup_status=1
  fi
  if ((original_status == 0 && cleanup_status != 0)); then
    exit 1
  fi
  exit "$original_status"
}
trap cleanup EXIT HUP INT TERM

validate_output_parent() {
  OUTPUT_DIRECTORY="$1"
  [[ "$OUTPUT_DIRECTORY" == /* && ! -e "$OUTPUT_DIRECTORY" &&
    ! -L "$OUTPUT_DIRECTORY" ]] ||
    die 'output must be absolute and nonexistent' || return 1
  OUTPUT_NAME="${OUTPUT_DIRECTORY##*/}"
  is_safe_leaf "$OUTPUT_NAME" || die 'output leaf is unsafe' || return 1
  OUTPUT_PARENT="${OUTPUT_DIRECTORY%/*}"
  [[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" &&
    "$(readlink -f -- "$OUTPUT_PARENT")" == "$OUTPUT_PARENT" &&
    "$(stat -Lc '%u:%a' -- "$OUTPUT_PARENT")" == "$EUID:700" ]] ||
    die 'output parent must be a caller-owned physical 0700 directory' ||
    return 1
  OUTPUT_PARENT_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$OUTPUT_PARENT")"
}

validate_source_authority() {
  local -r verifier_path='examples/apache-java-https/scripts/verify-retained-evidence.sh'
  local -r importer_path='examples/apache-java-https/scripts/import-retained-ci-evidence.sh'
  local relative=''
  local expected_mode=''
  local observed_mode=''
  local disk_sha=''
  local blob_sha=''
  local status=''
  HEAD_SHA="$(git -C "$REPOSITORY_ROOT" rev-parse --verify 'HEAD^{commit}')" ||
    return 1
  [[ "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || return 1
  status="$(git -C "$REPOSITORY_ROOT" status --porcelain=v1 \
    --untracked-files=all --ignore-submodules=none)" || return 1
  [[ -z "$status" ]] || return 1
  while IFS=$'\t' read -r relative expected_mode; do
    [[ -f "$REPOSITORY_ROOT/$relative" && ! -L "$REPOSITORY_ROOT/$relative" &&
      "$(readlink -f -- "$REPOSITORY_ROOT/$relative")" == "$REPOSITORY_ROOT/$relative" ]] ||
      return 1
    observed_mode="$(git -C "$REPOSITORY_ROOT" ls-tree "$HEAD_SHA" -- \
      "$relative" | awk 'NR == 1 {print $1} END {if (NR != 1) exit 1}')" ||
      return 1
    [[ "$observed_mode" == "$expected_mode" ]] || return 1
    disk_sha="$(sha256sum <"$REPOSITORY_ROOT/$relative")" || return 1
    disk_sha="${disk_sha%% *}"
    blob_sha="$(git -C "$REPOSITORY_ROOT" show \
      "$HEAD_SHA:$relative" | sha256sum)" || return 1
    blob_sha="${blob_sha%% *}"
    [[ "$disk_sha" == "$blob_sha" ]] || return 1
  done <<AUTHORITY_FILES
$WORKFLOW_PATH	100644
$importer_path	100755
$verifier_path	100755
AUTHORITY_FILES
}

validate_run_json() {
  local -r run_json="$1"
  validate_json_authority "$run_json" || return 1
  jq -e --arg repository "$REPOSITORY" --arg branch "$BRANCH" \
    --arg head "$HEAD_SHA" --arg workflow "$WORKFLOW_PATH" '
    (.id | type == "number" and floor == . and . >= 1) and
    (.run_attempt | type == "number" and floor == . and . >= 1) and
    .event == "push" and .head_branch == $branch and .head_sha == $head and
    .status == "completed" and .conclusion == "success" and
    .path == $workflow and .repository.full_name == $repository and
    .head_repository.full_name == $repository and
    .html_url == ("https://github.com/" + $repository + "/actions/runs/" +
      (.id | tostring))
  ' "$run_json" >/dev/null || return 1
  RUN_ID="$(jq -er '.id | tostring' "$run_json")" || return 1
  RUN_ATTEMPT="$(jq -er '.run_attempt | tostring' "$run_json")" || return 1
  [[ "$RUN_ID" =~ ^[1-9][0-9]{0,18}$ &&
    "$RUN_ATTEMPT" =~ ^[1-9][0-9]{0,18}$ ]]
}

artifact_row() {
  local -r artifacts_json="$1"
  local -r expected_name="$2"
  jq -cer --arg name "$expected_name" --argjson run_id "$RUN_ID" \
    --arg head "$HEAD_SHA" --arg branch "$BRANCH" '
    [.artifacts[] | select(.name == $name)] |
    if length != 1 then error("artifact role is absent or duplicated") else .[0] end |
    select(
      (.id | type == "number" and floor == . and . >= 1) and
      (.size_in_bytes | type == "number" and floor == . and . >= 1 and
        . <= 16777216) and .expired == false and
      (.expires_at | type == "string" and length >= 20 and length <= 40) and
      (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      .workflow_run.id == $run_id and .workflow_run.head_sha == $head and
      .workflow_run.head_branch == $branch)
  ' "$artifacts_json"
}

validate_artifact_json() {
  local -r artifacts_json="$1"
  local acceptance_name="java-remote-parent-acceptance-claims-$RUN_ID-$RUN_ATTEMPT"
  local fault_name="java-remote-parent-fault-security-$RUN_ID-$RUN_ATTEMPT"
  validate_json_authority "$artifacts_json" || return 1
  jq -e --arg acceptance "$acceptance_name" --arg fault "$fault_name" \
    --arg prefix "java-remote-parent-fault-security-cell-" \
    --arg suffix "-$RUN_ID-$RUN_ATTEMPT" '
    (.total_count | type == "number" and floor == . and . == 7) and
    (.artifacts | type == "array" and length == 7) and
    ([.artifacts[].id] | unique | length) == 7 and
    ([.artifacts[].name] | unique | length) == 7 and
    ([.artifacts[].name] | sort) ==
      ([$acceptance,$fault,
        ($prefix + "all-getsockopt" + $suffix),
        ($prefix + "all-unix" + $suffix),
        ($prefix + "all-auto" + $suffix),
        ($prefix + "pid-reuse-getsockopt" + $suffix),
        ($prefix + "pid-reuse-unix" + $suffix)] | sort)
  ' "$artifacts_json" >/dev/null || return 1
  ACCEPTANCE_ARTIFACT="$(artifact_row "$artifacts_json" "$acceptance_name")" ||
    return 1
  FAULT_ARTIFACT="$(artifact_row "$artifacts_json" "$fault_name")" || return 1
}

# Test seams are deliberately inert in the executable. They let hermetic tests
# replace caller-owned paths at the exact descriptor-binding boundary.
extract_archive_checkpoint() {
  :
}

extract_archive() {
  local -r role="$1"
  local -r archive="$2"
  local -r artifact_json="$3"
  local -r destination="$4"
  local expected_digest=''
  local expected_size=''
  local path_identity=''
  local descriptor_identity=''
  local archive_fd=''

  expected_digest="$(jq -er '.digest | sub("^sha256:"; "")' \
    <<<"$artifact_json")" || return 1
  expected_size="$(jq -er '.size_in_bytes' <<<"$artifact_json")" || return 1
  is_sha256 "$expected_digest" || return 1
  [[ "$expected_size" =~ ^[1-9][0-9]*$ &&
    "$expected_size" -le "$MAX_ARCHIVE_BYTES" ]] || return 1
  safe_owned_regular "$archive" "$MAX_ARCHIVE_BYTES" || return 1
  install -d -m 0700 -- "$destination" || return 1
  exec {archive_fd}<"$archive" || return 1
  path_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "$archive")" || {
    exec {archive_fd}<&-
    return 1
  }
  descriptor_identity="$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/self/fd/$archive_fd")" || {
    exec {archive_fd}<&-
    return 1
  }
  if [[ "$path_identity" != "$descriptor_identity" || ! -f "$archive" ||
    -L "$archive" || "$(readlink -f -- "$archive")" != "$archive" ]]; then
    exec {archive_fd}<&-
    return 1
  fi
  extract_archive_checkpoint "$role" "$archive" || {
    exec {archive_fd}<&-
    return 1
  }
  if ! python3 - "$archive_fd" "$destination" "$expected_digest" \
    "$expected_size" "$MAX_ARCHIVE_BYTES" "$MAX_MEMBERS" \
    "$MAX_MEMBER_BYTES" "$MAX_EXPANDED_BYTES" <<'PY'
import hashlib
import io
import os
import stat
import sys
import zipfile

archive_fd, destination, expected_digest = int(sys.argv[1]), sys.argv[2], sys.argv[3]
expected_size, max_archive, max_members, max_member, max_total = map(int, sys.argv[4:])
with os.fdopen(os.dup(archive_fd), "rb") as archive_source:
    archive_bytes = archive_source.read(max_archive + 1)
if (len(archive_bytes) != expected_size or len(archive_bytes) > max_archive or
        hashlib.sha256(archive_bytes).hexdigest() != expected_digest):
    raise ValueError("archive bytes do not match the artifact API identity")
with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as source:
    members = source.infolist()
    if not 1 <= len(members) <= max_members:
        raise ValueError("archive member count is out of bounds")
    names = set()
    total = 0
    for member in members:
        name = member.filename
        if (name in names or not name or "/" in name or "\\" in name or
                name in (".", "..") or name.startswith(".") or
                not all(c.isalnum() or c in "._-" for c in name)):
            raise ValueError("unsafe or duplicate archive member")
        names.add(name)
        mode = (member.external_attr >> 16) & 0xffff
        file_type = stat.S_IFMT(mode)
        if member.is_dir() or file_type not in (0, stat.S_IFREG):
            raise ValueError("archive contains a non-regular member")
        if member.flag_bits & 1:
            raise ValueError("encrypted archive members are forbidden")
        if member.file_size < 1 or member.file_size > max_member:
            raise ValueError("archive member size is out of bounds")
        total += member.file_size
        if total > max_total:
            raise ValueError("archive expansion exceeds the total bound")
        target = os.path.join(destination, name)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        written = 0
        try:
            with source.open(member, "r") as member_source, os.fdopen(fd, "wb") as target_file:
                fd = -1
                while True:
                    block = member_source.read(65536)
                    if not block:
                        break
                    written += len(block)
                    if written > member.file_size or written > max_member:
                        raise ValueError("archive member exceeded its declared bound")
                    target_file.write(block)
            if written != member.file_size:
                raise ValueError("archive member size changed during extraction")
        finally:
            if fd >= 0:
                os.close(fd)
PY
  then
    exec {archive_fd}<&-
    return 1
  fi
  exec {archive_fd}<&-
  [[ -z "$(find -- "$destination" -mindepth 1 ! -type f -print -quit)" ]] ||
    return 1
  find -- "$destination" -type f -exec chmod 0444 -- {} + || return 1
  chmod 0555 -- "$destination" || return 1
  printf '%s\n' "$role" >/dev/null
}

exact_inventory() {
  local -r directory="$1"
  shift
  local expected=''
  local observed=''
  expected="$(printf '%s\tf\n' "$@" | LC_ALL=C sort)" || return 1
  observed="$(find -- "$directory" -mindepth 1 -maxdepth 1 \
    -printf '%f\t%y\n' | LC_ALL=C sort)" || return 1
  [[ "$observed" == "$expected" ]]
}

is_safe_git_tree_path() {
  local remainder="$1"
  local component=''
  [[ -n "$remainder" && "$remainder" != /* && "$remainder" != */ &&
    "$remainder" != *'//' ]] || return 1
  while true; do
    if [[ "$remainder" == */* ]]; then
      component="${remainder%%/*}"
      remainder="${remainder#*/}"
    else
      component="$remainder"
      remainder=''
    fi
    [[ -n "$component" && "$component" != . && "$component" != .. ]] ||
      return 1
    [[ -n "$remainder" ]] || return 0
  done
}

compute_source_tree_sha256() {
  local entries="$WORK_DIRECTORY/source-tree.entries"
  local manifest="$WORK_DIRECTORY/source-tree.manifest"
  local entry=''
  local metadata=''
  local path=''
  local mode=''
  local object_id=''
  local marker=''
  local digest=''

  git -C "$REPOSITORY_ROOT" ls-tree -r -z --full-tree "$HEAD_SHA" >"$entries" ||
    return 1
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    is_safe_git_tree_path "$path" || return 1
    case "$mode" in
      100644) marker='-' ;;
      100755) marker='x' ;;
      120000) marker='l' ;;
      160000) marker='g' ;;
      *) return 1 ;;
    esac
    [[ "$object_id" =~ ^[0-9a-f]{40}$ ]] || return 1
    LC_ALL=C printf '%s %s %q\n' "$object_id" "$marker" "$path" || return 1
  done <"$entries" >"$manifest"
  digest="$(sha256sum <"$manifest")" || return 1
  printf '%s\n' "${digest%% *}"
}

verify_nested_bundles() {
  local -r acceptance="$1"
  local -r fault="$2"
  exact_inventory "$acceptance" "${ACCEPTANCE_FILES[@]}" || return 1
  exact_inventory "$fault" "${FAULT_FILES[@]}" || return 1
  canonical_json "$acceptance/acceptance-claims.json" || return 1
  canonical_json "$acceptance/authority-summary.json" || return 1
  canonical_json "$acceptance/derivation-receipt.json" || return 1
  canonical_json "$fault/fault-security-matrix.json" || return 1
  canonical_json "$fault/derivation-receipt.json" || return 1
  (CDPATH='' cd / && bash "$acceptance/verify.sh" >/dev/null) || return 1
  (CDPATH='' cd / && bash "$fault/verify.sh" >/dev/null) || return 1
  "$SCRIPT_DIRECTORY/verify-retained-evidence.sh" \
    --claims-v1 "$acceptance" >/dev/null || return 1
  "$SCRIPT_DIRECTORY/verify-retained-evidence.sh" \
    --fault-security-matrix-v1 "$fault" >/dev/null || return 1
  SOURCE_TREE_SHA256="$(jq -er '.source.tree_sha256' \
    "$acceptance/authority-summary.json")" || return 1
  [[ "$SOURCE_TREE_SHA256" == "$(compute_source_tree_sha256)" ]] || return 1
  jq -e --arg head "$HEAD_SHA" --arg tree "$SOURCE_TREE_SHA256" '
    .status == "passed" and .issue_32 and .issue_34
  ' "$acceptance/acceptance-claims.json" >/dev/null || return 1
  jq -e --arg head "$HEAD_SHA" --arg tree "$SOURCE_TREE_SHA256" '
    .source.revision == $head and .source.tree_sha256 == $tree and
    .execution_locator.head_sha == $head
  ' "$acceptance/authority-summary.json" >/dev/null || return 1
  jq -e --arg head "$HEAD_SHA" --arg tree "$SOURCE_TREE_SHA256" '
    .status == "passed" and .source.revision == $head and
    .source.source_tree_sha256 == $tree and
    .coverage.issue_36.status == "passed" and .coverage.issue_40.status == "passed"
  ' "$fault/fault-security-matrix.json" >/dev/null
}

write_portable_verifier() {
  local -r output="$1"
  cat >"$output" <<'VERIFY'
#!/usr/bin/env bash
set -Eeuo pipefail
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'SHA256SUMS\tf\nacceptance\td\nclaim-index.json\tf\nfault-security\td\nrun-identity.json\tf\nverify.sh\tf'
observed="$(find -H "$root" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)"
[[ "$observed" == "$expected" ]]
while IFS= read -r line; do
  [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]]
  [[ "${BASH_REMATCH[2]}" != SHA256SUMS && "${BASH_REMATCH[2]}" != /* &&
    "${BASH_REMATCH[2]}" != *..* ]]
done <"$root/SHA256SUMS"
[[ "$(awk 'END {print NR + 0}' "$root/SHA256SUMS")" == 16 ]]
(CDPATH='' cd -- "$root" && sha256sum --check --strict SHA256SUMS >/dev/null)
(CDPATH='' cd / && bash "$root/acceptance/verify.sh" >/dev/null)
(CDPATH='' cd / && bash "$root/fault-security/verify.sh" >/dev/null)
cmp -s -- "$root/run-identity.json" <(jq -cS . "$root/run-identity.json")
cmp -s -- "$root/claim-index.json" <(jq -cS . "$root/claim-index.json")
jq -e '
  . as $identity |
  keys == ["artifacts","conclusion","event","head_sha","ref","repository",
    "run_attempt","run_id","run_url","schema","source_tree_sha256","status",
    "workflow"] and
  .schema == "obi-retained-ci-run-identity-v1" and .status == "passed" and
  .repository == "MrAlias/opentelemetry-ebpf-instrumentation" and
  .event == "push" and .ref == "refs/heads/agent/java-remote-parent-bridge" and
  .conclusion == "success" and (.run_id | test("^[1-9][0-9]{0,18}$")) and
  (.run_attempt | test("^[1-9][0-9]{0,18}$")) and
  (.head_sha | test("^[0-9a-f]{40}$")) and
  (.source_tree_sha256 | test("^[0-9a-f]{64}$")) and
  .run_url == ("https://github.com/" + .repository + "/actions/runs/" +
    .run_id + "/attempts/" + .run_attempt) and
  (.workflow | keys == ["blob_sha256","name","path","ref","sha"] and
    .path == ".github/workflows/java_remote_parent_acceptance_claims.yml" and
    .name == "Java remote-parent bounded acceptance claims" and
    .sha == $identity.head_sha and (.blob_sha256 | test("^[0-9a-f]{64}$")) and
    .ref == ($identity.repository + "/" + .path + "@" + $identity.ref)) and
  [.artifacts[].role] == ["acceptance","fault-security"] and
  all(.artifacts[];
    keys == ["digest","expired","expires_at","head_branch","head_sha","id",
      "name","role","run_id","size_in_bytes"] and
    (.id | test("^[1-9][0-9]{0,18}$")) and .size_in_bytes >= 1 and
    .expired == false and
    (.expires_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z$")) and
    (.digest | test("^sha256:[0-9a-f]{64}$")) and
    .run_id == $identity.run_id and .head_sha == $identity.head_sha and
    .head_branch == "agent/java-remote-parent-bridge") and
  .artifacts[0].name == ("java-remote-parent-acceptance-claims-" + .run_id +
    "-" + .run_attempt) and
  .artifacts[1].name == ("java-remote-parent-fault-security-" + .run_id +
    "-" + .run_attempt)
' "$root/run-identity.json" >/dev/null
jq -e --slurpfile identity "$root/run-identity.json" '
  keys == ["coverage","evidence_id","schema","source","status"] and
  .schema == "obi-retained-ci-claim-index-v1" and .status == "passed" and
  (.evidence_id | test("^[0-9a-f]{64}$")) and
  .source == {revision:$identity[0].head_sha,tree_sha256:$identity[0].source_tree_sha256} and
  .coverage == {
    issue_32:{pointer:"acceptance/acceptance-claims.json#/issue_32",status:"passed"},
    issue_34:{pointer:"acceptance/acceptance-claims.json#/issue_34",status:"passed"},
    issue_36:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_36",status:"passed"},
    issue_40:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40",status:"passed"}}
' "$root/claim-index.json" >/dev/null
head_sha="$(jq -er '.head_sha' "$root/run-identity.json")"
source_tree="$(jq -er '.source_tree_sha256' "$root/run-identity.json")"
jq -e --arg head "$head_sha" --arg tree "$source_tree" '
  .source.revision == $head and .source.tree_sha256 == $tree and
  .execution_locator.head_sha == $head
' "$root/acceptance/authority-summary.json" >/dev/null
jq -e --arg head "$head_sha" --arg tree "$source_tree" '
  .source.revision == $head and .source.source_tree_sha256 == $tree
' "$root/fault-security/fault-security-matrix.json" >/dev/null
evidence_id="$(jq -er '.evidence_id' "$root/claim-index.json")"
acceptance_receipt="$(sha256sum <"$root/acceptance/derivation-receipt.json")"
acceptance_receipt="${acceptance_receipt%% *}"
fault_receipt="$(sha256sum <"$root/fault-security/derivation-receipt.json")"
fault_receipt="${fault_receipt%% *}"
expected_evidence_id="$(printf '%s\n' "$head_sha" \
  "$(jq -er '.run_id' "$root/run-identity.json")" \
  "$(jq -er '.run_attempt' "$root/run-identity.json")" \
  "$acceptance_receipt" "$fault_receipt" | sha256sum)"
expected_evidence_id="${expected_evidence_id%% *}"
[[ "$evidence_id" == "$expected_evidence_id" ]]
[[ "${root##*/}" == "retained-claims-${head_sha:0:12}-${evidence_id:0:12}" ]]
printf 'source-bound retained CI claims internally consistent: %s\n' "$evidence_id"
VERIFY
  chmod 0444 -- "$output"
}

write_bundle() {
  local -r run_json="$1"
  local -r acceptance="$2"
  local -r fault="$3"
  local workflow_sha=''
  local acceptance_receipt=''
  local fault_receipt=''
  local artifact_seed=''
  local file=''

  workflow_sha="$(sha256sum <"$REPOSITORY_ROOT/$WORKFLOW_PATH")"
  workflow_sha="${workflow_sha%% *}"
  acceptance_receipt="$(sha256sum <"$acceptance/derivation-receipt.json")"
  acceptance_receipt="${acceptance_receipt%% *}"
  fault_receipt="$(sha256sum <"$fault/derivation-receipt.json")"
  fault_receipt="${fault_receipt%% *}"
  artifact_seed="$(printf '%s\n' "$HEAD_SHA" "$RUN_ID" "$RUN_ATTEMPT" \
    "$acceptance_receipt" "$fault_receipt" | sha256sum)"
  EVIDENCE_ID="${artifact_seed%% *}"
  [[ "$OUTPUT_NAME" == \
    "retained-claims-${HEAD_SHA:0:12}-${EVIDENCE_ID:0:12}" ]] ||
    die 'output leaf does not match the canonical evidence identity' || return 1

  CANDIDATE_DIRECTORY="$(mktemp -d \
    "$OUTPUT_PARENT/.retained-ci-import.XXXXXX")" || return 1
  CANDIDATE_DIRECTORY="$(CDPATH='' cd -- "$CANDIDATE_DIRECTORY" && pwd -P)"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")"
  [[ "${CANDIDATE_IDENTITY%%:*}" == "${OUTPUT_PARENT_IDENTITY%%:*}" ]] ||
    die 'candidate and output parent are not on one filesystem' || return 1
  install -d -m 0700 -- "$CANDIDATE_DIRECTORY/acceptance" \
    "$CANDIDATE_DIRECTORY/fault-security"
  cp -a -- "$acceptance/." "$CANDIDATE_DIRECTORY/acceptance/"
  cp -a -- "$fault/." "$CANDIDATE_DIRECTORY/fault-security/"

  jq -cS -n --arg repository "$REPOSITORY" --arg event push \
    --arg ref "$REF" --arg head "$HEAD_SHA" --arg tree "$SOURCE_TREE_SHA256" \
    --arg workflow_name "$WORKFLOW_NAME" --arg workflow_path "$WORKFLOW_PATH" \
    --arg workflow_ref "$REPOSITORY/$WORKFLOW_PATH@$REF" \
    --arg workflow_sha "$HEAD_SHA" --arg workflow_blob "$workflow_sha" \
    --arg run_id "$RUN_ID" --arg run_attempt "$RUN_ATTEMPT" \
    --arg run_url "https://github.com/$REPOSITORY/actions/runs/$RUN_ID/attempts/$RUN_ATTEMPT" \
    --argjson acceptance "$ACCEPTANCE_ARTIFACT" \
    --argjson fault "$FAULT_ARTIFACT" '
    def artifact($role; $a): {
      role:$role,id:($a.id|tostring),name:$a.name,digest:$a.digest,
      size_in_bytes:$a.size_in_bytes,expired:$a.expired,expires_at:$a.expires_at,
      run_id:($a.workflow_run.id|tostring),head_branch:$a.workflow_run.head_branch,
      head_sha:$a.workflow_run.head_sha};
    {schema:"obi-retained-ci-run-identity-v1",status:"passed",
      repository:$repository,event:$event,ref:$ref,head_sha:$head,
      source_tree_sha256:$tree,run_id:$run_id,run_attempt:$run_attempt,
      conclusion:"success",run_url:$run_url,
      workflow:{name:$workflow_name,path:$workflow_path,ref:$workflow_ref,
        sha:$workflow_sha,blob_sha256:$workflow_blob},
      artifacts:[artifact("acceptance";$acceptance),
        artifact("fault-security";$fault)]}
  ' >"$CANDIDATE_DIRECTORY/run-identity.json" || return 1
  jq -cS -n --arg evidence_id "$EVIDENCE_ID" --arg head "$HEAD_SHA" \
    --arg tree "$SOURCE_TREE_SHA256" '
    {schema:"obi-retained-ci-claim-index-v1",status:"passed",
      evidence_id:$evidence_id,source:{revision:$head,tree_sha256:$tree},
      coverage:{
        issue_32:{status:"passed",pointer:"acceptance/acceptance-claims.json#/issue_32"},
        issue_34:{status:"passed",pointer:"acceptance/acceptance-claims.json#/issue_34"},
        issue_36:{status:"passed",pointer:"fault-security/fault-security-matrix.json#/coverage/issue_36"},
        issue_40:{status:"passed",pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40"}}}
  ' >"$CANDIDATE_DIRECTORY/claim-index.json" || return 1
  write_portable_verifier "$CANDIDATE_DIRECTORY/verify.sh"
  (
    CDPATH='' cd -- "$CANDIDATE_DIRECTORY"
    for file in run-identity.json claim-index.json verify.sh \
      acceptance/README.md acceptance/SANITIZATION.md \
      acceptance/acceptance-claims.json acceptance/authority-summary.json \
      acceptance/derivation-receipt.json acceptance/verify.sh \
      acceptance/SHA256SUMS fault-security/README.md \
      fault-security/SANITIZATION.md fault-security/fault-security-matrix.json \
      fault-security/derivation-receipt.json fault-security/verify.sh \
      fault-security/SHA256SUMS; do
      sha256sum "$file"
    done
  ) >"$CANDIDATE_DIRECTORY/SHA256SUMS" || return 1
  find -- "$CANDIDATE_DIRECTORY" -type f -exec chmod 0444 -- {} +
  find -- "$CANDIDATE_DIRECTORY" -depth -type d -exec chmod 0555 -- {} +
  [[ "$(stat -Lc '%d:%i:%u' -- "$OUTPUT_PARENT")" == "$OUTPUT_PARENT_IDENTITY" ]] ||
    return 1
  mv -T -- "$CANDIDATE_DIRECTORY" "$OUTPUT_DIRECTORY" || return 1
  CANDIDATE_DIRECTORY="$OUTPUT_DIRECTORY"
  (CDPATH='' cd / && bash "$OUTPUT_DIRECTORY/verify.sh" >/dev/null) ||
    return 1
  CANDIDATE_DIRECTORY=''
  CANDIDATE_IDENTITY=''
  return 0
}

claims_v1() {
  local -r run_json="$1"
  local -r artifacts_json="$2"
  local -r acceptance_zip="$3"
  local -r fault_zip="$4"
  local -r output="$5"
  local acceptance_directory=''
  local fault_directory=''
  local acceptance_before=''
  local acceptance_after=''
  local fault_before=''
  local fault_after=''
  local run_snapshot=''
  local artifacts_snapshot=''

  require_commands
  [[ -z "${GITHUB_OUTPUT:-}" ]] ||
    die 'GITHUB_OUTPUT is forbidden for post-run promotion' || return 1
  validate_output_parent "$output"
  validate_source_authority || die 'source authority is not exact' || return 1
  WORK_DIRECTORY="$(mktemp -d /tmp/obi-retained-ci-import.XXXXXX)" || return 1
  WORK_DIRECTORY="$(CDPATH='' cd -- "$WORK_DIRECTORY" && pwd -P)"
  WORK_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$WORK_DIRECTORY")"
  run_snapshot="$WORK_DIRECTORY/run-api.json"
  artifacts_snapshot="$WORK_DIRECTORY/artifacts-api.json"
  snapshot_owned_regular "$run_json" "$MAX_API_BYTES" "$run_snapshot" ||
    die 'run API JSON could not be pinned' || return 1
  snapshot_owned_regular "$artifacts_json" "$MAX_API_BYTES" \
    "$artifacts_snapshot" || die 'artifact API JSON could not be pinned' || return 1
  validate_run_json "$run_snapshot" || die 'run API JSON is not authoritative' ||
    return 1
  validate_artifact_json "$artifacts_snapshot" ||
    die 'artifact API JSON is not the exact seven-artifact source set' || return 1
  acceptance_directory="$WORK_DIRECTORY/acceptance"
  fault_directory="$WORK_DIRECTORY/fault-security"
  extract_archive acceptance "$acceptance_zip" "$ACCEPTANCE_ARTIFACT" \
    "$acceptance_directory" || die 'acceptance ZIP is unsafe or inauthentic' ||
    return 1
  extract_archive fault-security "$fault_zip" "$FAULT_ARTIFACT" \
    "$fault_directory" || die 'fault/security ZIP is unsafe or inauthentic' ||
    return 1
  acceptance_before="$WORK_DIRECTORY/acceptance.before.manifest"
  acceptance_after="$WORK_DIRECTORY/acceptance.after.manifest"
  fault_before="$WORK_DIRECTORY/fault.before.manifest"
  fault_after="$WORK_DIRECTORY/fault.after.manifest"
  directory_manifest "$acceptance_directory" "$acceptance_before"
  directory_manifest "$fault_directory" "$fault_before"
  verify_nested_bundles "$acceptance_directory" "$fault_directory" ||
    die 'nested claim bundle validation failed' || return 1
  directory_manifest "$acceptance_directory" "$acceptance_after"
  directory_manifest "$fault_directory" "$fault_after"
  cmp -s -- "$acceptance_before" "$acceptance_after" ||
    die 'acceptance bundle changed during nested verification' || return 1
  cmp -s -- "$fault_before" "$fault_after" ||
    die 'fault/security bundle changed during nested verification' || return 1
  write_bundle "$run_snapshot" "$acceptance_directory" "$fault_directory"
}

main() {
  if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    usage
    return 0
  fi
  [[ $# == 6 && "$1" == claims-v1 ]] || {
    usage >&2
    return 2
  }
  claims_v1 "$2" "$3" "$4" "$5" "$6"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
