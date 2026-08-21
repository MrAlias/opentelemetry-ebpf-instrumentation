#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

COMPATIBILITY_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly COMPATIBILITY_DIRECTORY
COMPATIBILITY_REPOSITORY_ROOT="$(cd -- "$COMPATIBILITY_DIRECTORY/../../.." && pwd -P)"
# shellcheck disable=SC2034 # Public to scripts that source this library.
readonly COMPATIBILITY_REPOSITORY_ROOT
readonly COMPATIBILITY_MAX_PRIVATE_FILES=4096
readonly COMPATIBILITY_MAX_PRIVATE_BYTES=2147483648
readonly COMPATIBILITY_MAX_REGISTRY_ENTRIES=256
readonly COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES=1048576
# shellcheck disable=SC2034 # Public to scripts that source this library.
readonly COMPATIBILITY_MAX_ASSERTION_COUNT=1000000000
# shellcheck disable=SC2034 # Public to scripts that source this library.
readonly COMPATIBILITY_MAX_RESOURCE_MAGNITUDE=1000000000
readonly COMPATIBILITY_PROVIDER_REGISTRY="$COMPATIBILITY_DIRECTORY/provider-registry-v1.json"
readonly COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY="$COMPATIBILITY_DIRECTORY/lifecycle-executor-registry-v1.json"

compatibility_error() {
  printf 'ERROR: %s\n' "$*" >&2
}

compatibility_die() {
  compatibility_error "$*"
  return 1
}

compatibility_require_commands() {
  local command_name=""
  local -a missing=()

  for command_name in "$@"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    compatibility_die "missing required commands: ${missing[*]}"
  fi
}

compatibility_require_regular_file() {
  local -r path="$1"

  [[ -f "$path" && ! -L "$path" ]] ||
    compatibility_die "expected a regular non-symlink file: $path"
}

compatibility_require_directory() {
  local -r path="$1"

  [[ -d "$path" && ! -L "$path" ]] ||
    compatibility_die "expected a non-symlink directory: $path"
}

compatibility_require_outside_repository() {
  local -r path="$1"

  [[ "$path" == /* ]] ||
    compatibility_die "path must be absolute before repository-boundary validation" || return
  [[ "$path" != "$COMPATIBILITY_REPOSITORY_ROOT" &&
    "$path" != "$COMPATIBILITY_REPOSITORY_ROOT"/* ]] ||
    compatibility_die "campaign results must be outside the source checkout: $path"
}

compatibility_validate_json_file() {
  local -r path="$1"
  local -r expected_identity="${2:-}"
  local -r stable_identity_pattern='^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]{64}$'

  compatibility_require_commands python3 || return
  [[ -z "$expected_identity" ||
    "$expected_identity" =~ $stable_identity_pattern ]] || return 2
  python3 - "$path" "$expected_identity" <<'PY'
import hashlib
import json
import math
import os
import stat
import sys


MAX_SAFE_INTEGER = 9_007_199_254_740_991


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def reject_non_finite(value):
    raise ValueError(f"non-finite JSON number: {value}")


def parse_bounded_integer(value):
    result = int(value)
    if abs(result) > MAX_SAFE_INTEGER:
        raise ValueError(f"JSON integer exceeds the exact IEEE-754 range: {value}")
    return result


def parse_finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite JSON number: {value}")
    return result


def identity_text(state, digest):
    return ":".join(str(value) for value in (
        state.st_dev,
        state.st_ino,
        state.st_uid,
        format(stat.S_IMODE(state.st_mode), "o"),
        state.st_nlink,
        state.st_size,
        state.st_mtime_ns,
        state.st_ctime_ns,
        digest,
    ))


path, expected_identity = sys.argv[1:3]
maximum_bytes = 64 * 1024 * 1024
descriptor = os.open(
    path,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("JSON input is not regular")
    if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
        raise RuntimeError("JSON input has unsafe ownership or links")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        raise RuntimeError("JSON input exceeds the 64 MiB parser bound")
    payload = bytearray()
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1))
        if not chunk:
            break
        payload.extend(chunk)
        digest.update(chunk)
        if len(payload) > maximum_bytes:
            raise RuntimeError("JSON input grew beyond the 64 MiB parser bound")
    after = os.fstat(descriptor)
    fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise RuntimeError("JSON input changed while reading")
    current = os.stat(path, follow_symlinks=False)
    if any(getattr(after, field) != getattr(current, field) for field in fields):
        raise RuntimeError("JSON input path changed while reading")
    observed_identity = identity_text(after, digest.hexdigest())
    if expected_identity and observed_identity != expected_identity:
        raise RuntimeError("JSON input differs from its retained identity")
finally:
    os.close(descriptor)
json.loads(
    bytes(payload).decode("utf-8"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_non_finite,
    parse_int=parse_bounded_integer,
    parse_float=parse_finite_float,
)
PY
}

compatibility_source_checkout_json() {
  local revision=""
  local tree=""
  local clean=false
  local source_status=""
  local status_available=false

  revision="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" \
    rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)"
  tree="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" \
    rev-parse --verify 'HEAD^{tree}' 2>/dev/null || true)"
  if source_status="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" status \
    --porcelain=v1 --untracked-files=all 2>/dev/null)"; then
    status_available=true
  fi
  if [[ "$revision" =~ ^[0-9a-f]{40}$ && "$tree" =~ ^[0-9a-f]{40}$ &&
    "$status_available" == true && -z "$source_status" ]]; then
    clean=true
  fi
  jq -cnS \
    --arg revision "$revision" \
    --arg git_tree "$tree" \
    --argjson clean "$clean" \
    '{revision: $revision, git_tree: $git_tree, clean: $clean}'
}

compatibility_validate_source_authority() {
  local -r authority="$1"

  compatibility_validate_json_file "$authority" || return
  jq -e '
    def sha1: type == "string" and test("^[0-9a-f]{40}$");
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    keys == [
      "git_tree", "patch_identity_sha256", "revision", "schema",
      "source_tree_sha256", "tracked_patch_sha256"
    ] and
    .schema == "compatibility-source-authority-v1" and
    (.revision | sha1) and (.git_tree | sha1) and
    (.source_tree_sha256 | sha256) and
    (.tracked_patch_sha256 | sha256) and
    (.patch_identity_sha256 | sha256)
  ' "$authority" >/dev/null ||
    compatibility_die "invalid compatibility source authority"
}

compatibility_safe_git_tree_path() {
  local remainder="$1"
  local component=""

  [[ -n "$remainder" && "$remainder" != /* && "$remainder" != */ &&
    "$remainder" != *'//' && "$remainder" != *$'\n'* ]] || return 1
  while [[ "$remainder" == */* ]]; do
    component="${remainder%%/*}"
    remainder="${remainder#*/}"
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
  done
  [[ -n "$remainder" && "$remainder" != . && "$remainder" != .. ]]
}

compatibility_capture_clean_source_authority() {
  local -r requested_repository="$1"
  local -r requested_scratch="$2"
  local -r requested_output="$3"
  local repository=""
  local scratch=""
  local output=""
  local revision=""
  local final_revision=""
  local git_tree=""
  local final_git_tree=""
  local entry=""
  local metadata=""
  local path=""
  local mode=""
  local object_id=""
  local marker=""
  local flag=""
  local source_tree_sha256=""
  local tracked_patch_sha256=""
  local status_sha256=""
  local patch_identity_sha256=""

  compatibility_require_commands cmp git jq sha256sum || return
  compatibility_require_directory "$requested_repository" || return
  compatibility_require_directory "$requested_scratch" || return
  repository="$(cd -- "$requested_repository" && pwd -P)" || return
  scratch="$(cd -- "$requested_scratch" && pwd -P)" || return
  [[ "$scratch" != "$repository" && "$scratch" != "$repository"/* ]] ||
    compatibility_die "source-authority scratch must be outside the checkout" || return
  [[ "$(dirname -- "$requested_output")" == "$scratch" ]] ||
    compatibility_die "source-authority output must be directly inside its scratch directory" || return
  output="$scratch/$(basename -- "$requested_output")"
  [[ "${output##*/}" != . && "${output##*/}" != .. &&
    "${output##*/}" != */* && "${output##*/}" != *$'\n'* &&
    ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "unsafe source-authority capture output" || return

  revision="$(git -C "$repository" rev-parse --verify 'HEAD^{commit}')" || return
  git_tree="$(git -C "$repository" rev-parse --verify 'HEAD^{tree}')" || return
  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$git_tree" =~ ^[0-9a-f]{40}$ ]] ||
    compatibility_die "checkout has invalid Git source identities" || return

  git -C "$repository" ls-files -v -z >"$scratch/index-flags" || return
  while IFS= read -r -d '' entry; do
    flag="${entry:0:1}"
    case "$flag" in
      [a-z]|S)
        compatibility_die "source index hides assume-unchanged or skip-worktree entries"
        return
        ;;
    esac
  done <"$scratch/index-flags"
  git -C "$repository" ls-files --unmerged -z >"$scratch/unmerged" || return
  [[ ! -s "$scratch/unmerged" ]] ||
    compatibility_die "source index contains unresolved entries" || return
  git -C "$repository" submodule status --recursive >"$scratch/submodules" || return
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "${entry:0:1}" in
      ' ') ;;
      *)
        compatibility_die "source authority requires every gitlink at its pinned revision"
        return
        ;;
    esac
  done <"$scratch/submodules"
  git -C "$repository" status \
    --porcelain=v1 --untracked-files=all --ignore-submodules=none \
    >"$scratch/status" || return
  [[ ! -s "$scratch/status" ]] ||
    compatibility_die "source authority requires a clean checkout" || return
  git -C "$repository" diff --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "working tree differs from the authority revision" || return
  git -C "$repository" diff --cached --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "index differs from the authority revision" || return

  git -C "$repository" ls-tree -r -z --full-tree "$revision" \
    >"$scratch/tree-entries" || return
  : >"$scratch/source-tree.manifest"
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    compatibility_safe_git_tree_path "$path" ||
      compatibility_die "Git tree contains an unsafe path" || return
    case "$mode" in
      100644) marker=- ;;
      100755) marker=x ;;
      120000) marker=l ;;
      160000) marker=g ;;
      *) compatibility_die "Git tree contains an unsupported mode: $mode"; return ;;
    esac
    [[ "$object_id" =~ ^[0-9a-f]{40}$ ]] ||
      compatibility_die "Git tree contains an invalid object identity" || return
    printf '%s %s %q\n' "$object_id" "$marker" "$path" \
      >>"$scratch/source-tree.manifest"
  done <"$scratch/tree-entries"
  git -C "$repository" diff --binary --no-ext-diff "$revision" -- \
    >"$scratch/tracked.patch" || return
  [[ ! -s "$scratch/tracked.patch" ]] ||
    compatibility_die "tracked patch became nonempty during authority capture" || return
  source_tree_sha256="$(compatibility_sha256 "$scratch/source-tree.manifest")" || return
  tracked_patch_sha256="$(compatibility_sha256 "$scratch/tracked.patch")" || return
  status_sha256="$(compatibility_sha256 "$scratch/status")" || return
  printf '%s\n%s\n%s\n' \
    "$status_sha256" "$source_tree_sha256" "$tracked_patch_sha256" \
    >"$scratch/patch-identity.input"
  patch_identity_sha256="$(compatibility_sha256 "$scratch/patch-identity.input")" || return

  final_revision="$(git -C "$repository" rev-parse --verify 'HEAD^{commit}')" || return
  final_git_tree="$(git -C "$repository" rev-parse --verify 'HEAD^{tree}')" || return
  [[ "$final_revision" == "$revision" && "$final_git_tree" == "$git_tree" ]] ||
    compatibility_die "source revision changed during authority capture" || return
  git -C "$repository" status \
    --porcelain=v1 --untracked-files=all --ignore-submodules=none \
    >"$scratch/final-status" || return
  cmp -s -- "$scratch/status" "$scratch/final-status" ||
    compatibility_die "source checkout changed during authority capture" || return
  git -C "$repository" diff --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "working tree changed during authority capture" || return
  git -C "$repository" diff --cached --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "index changed during authority capture" || return

  jq -nS \
    --arg revision "$revision" \
    --arg git_tree "$git_tree" \
    --arg source_tree_sha256 "$source_tree_sha256" \
    --arg tracked_patch_sha256 "$tracked_patch_sha256" \
    --arg patch_identity_sha256 "$patch_identity_sha256" '
      {
        schema: "compatibility-source-authority-v1",
        revision: $revision,
        git_tree: $git_tree,
        source_tree_sha256: $source_tree_sha256,
        tracked_patch_sha256: $tracked_patch_sha256,
        patch_identity_sha256: $patch_identity_sha256
      }
    ' >"$output"
  chmod 0600 -- "$output"
  compatibility_validate_source_authority "$output"
}

compatibility_source_authority_matches_checkout() (
  local -r authority="$1"
  local scratch_parent=""
  local scratch=""
  local scratch_identity=""
  local recomputed=""

  compatibility_validate_source_authority "$authority" || return
  compatibility_require_commands cmp mktemp || return
  scratch_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$scratch_parent" || return
  scratch="$(mktemp -d "$scratch_parent/.compatibility-authority-check.XXXXXX")" || return
  scratch_identity="$(compatibility_directory_identity "$scratch")" || return
  trap 'compatibility_remove_owned_temp_directory \
    "$scratch" "$scratch_identity" "$scratch_parent" \
    "[.]compatibility-authority-check[.]" || true' EXIT
  recomputed="$scratch/current-source-authority.json"
  compatibility_capture_clean_source_authority \
    "$COMPATIBILITY_REPOSITORY_ROOT" "$scratch" "$recomputed" || return
  cmp -s -- "$authority" "$recomputed" ||
    compatibility_die "source checkout differs from the exact clean source authority"
)

compatibility_provider_result_matches_source_authority() {
  local -r result="$1"
  local -r authority="$2"

  compatibility_validate_json_file "$result" >/dev/null 2>&1 || return 1
  compatibility_validate_source_authority "$authority" >/dev/null 2>&1 || return 1
  jq -e --slurpfile authority "$authority" '
    $authority[0] as $a |
    .source as $source |
    if ($source | type) != "object" then false
    elif ($source | keys) == [
      "clean", "patch_identity_sha256", "revision", "source_tree_sha256",
      "tracked_patch_sha256"
    ] then
      $source.revision == $a.revision and
      $source.source_tree_sha256 == $a.source_tree_sha256 and
      $source.tracked_patch_sha256 == $a.tracked_patch_sha256 and
      $source.patch_identity_sha256 == $a.patch_identity_sha256
    elif ($source | keys) == ["clean", "git_tree", "revision"] then
      if .status == "untested" and
        $source.revision == "" and $source.git_tree == "" then true
      else
        $source.revision == $a.revision and $source.git_tree == $a.git_tree
      end
    else false
    end
  ' "$result" >/dev/null
}

compatibility_provider_exit_matches_status() {
  local -r status="$1"
  local -r exit_status="$2"

  [[ "$exit_status" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  (( exit_status <= 255 )) || return 1
  case "$status" in
    pass) (( exit_status == 0 )) ;;
    fail) (( exit_status != 0 )) ;;
    unsupported) (( exit_status == 78 )) ;;
    untested) (( exit_status == 69 )) ;;
    *) return 1 ;;
  esac
}

compatibility_provider_result_matches_exit() {
  local -r result="$1"
  local -r exit_status="$2"
  local status=""

  compatibility_validate_json_file "$result" >/dev/null 2>&1 || return 1
  status="$(jq -er '.status | select(type == "string")' "$result")" || return
  compatibility_provider_exit_matches_status "$status" "$exit_status"
}

compatibility_sha256() {
  local -r path="$1"
  local digest=""

  compatibility_require_regular_file "$path" || return
  digest="$(sha256sum -- "$path")" || return
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] ||
    compatibility_die "invalid SHA-256 output for $path"
  printf '%s\n' "$digest"
}

compatibility_stable_file_identity() {
  local -r path="$1"
  local -r maximum_bytes="${2:-67108864}"

  [[ "$path" == /* && "$maximum_bytes" =~ ^[1-9][0-9]*$ ]] || return 2
  python3 - "$path" "$maximum_bytes" <<'PY'
import hashlib
import os
import stat
import sys


path = sys.argv[1]
maximum_bytes = int(sys.argv[2])
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
descriptor = os.open(path, flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("source is not a regular file")
    if before.st_uid not in (0, os.geteuid()):
        raise RuntimeError("source has foreign ownership")
    if before.st_nlink != 1:
        raise RuntimeError("source has an unsafe link count")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        raise RuntimeError("source exceeds its byte bound")
    digest = hashlib.sha256()
    observed_bytes = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1))
        if not chunk:
            break
        observed_bytes += len(chunk)
        if observed_bytes > maximum_bytes:
            raise RuntimeError("source grew beyond its byte bound")
        digest.update(chunk)
    after = os.fstat(descriptor)
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
              "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise RuntimeError("source changed while hashing")
    current = os.stat(path, follow_symlinks=False)
    if any(getattr(after, field) != getattr(current, field) for field in fields):
        raise RuntimeError("source path changed while hashing")
    print(":".join(str(value) for value in (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        format(stat.S_IMODE(after.st_mode), "o"),
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        digest.hexdigest(),
    )))
finally:
    os.close(descriptor)
PY
}

compatibility_create_stable_file_snapshot() {
  local -r source="$1"
  local -r destination="$2"
  local -r maximum_bytes="${3:-67108864}"

  [[ "$source" == /* && "$destination" == /* &&
    "$maximum_bytes" =~ ^[1-9][0-9]*$ ]] || return 2
  python3 - "$source" "$destination" "$maximum_bytes" <<'PY'
import hashlib
import os
import stat
import sys


source, destination = sys.argv[1:3]
maximum_bytes = int(sys.argv[3])
source_fd = os.open(
    source,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
destination_fd = None
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("snapshot source is not regular")
    if before.st_uid not in (0, os.geteuid()):
        raise RuntimeError("snapshot source has foreign ownership")
    if before.st_nlink != 1:
        raise RuntimeError("snapshot source has an unsafe link count")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        raise RuntimeError("snapshot source exceeds its byte bound")
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o400,
    )
    digest = hashlib.sha256()
    observed_bytes = 0
    while True:
        chunk = os.read(source_fd, min(1024 * 1024, maximum_bytes + 1))
        if not chunk:
            break
        observed_bytes += len(chunk)
        if observed_bytes > maximum_bytes:
            raise RuntimeError("snapshot source grew beyond its byte bound")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            view = view[written:]
    os.fsync(destination_fd)
    after = os.fstat(source_fd)
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
              "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise RuntimeError("snapshot source changed while copying")
    current = os.stat(source, follow_symlinks=False)
    if any(getattr(after, field) != getattr(current, field) for field in fields):
        raise RuntimeError("snapshot source path changed while copying")
    print(":".join(str(value) for value in (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        format(stat.S_IMODE(after.st_mode), "o"),
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        digest.hexdigest(),
    )))
finally:
    os.close(source_fd)
    if destination_fd is not None:
        os.close(destination_fd)
PY
}

compatibility_descriptor_file_identity() {
  local -r descriptor="$1"
  local -r maximum_bytes="${2:-67108864}"

  [[ "$descriptor" =~ ^[1-9][0-9]*$ &&
    "$maximum_bytes" =~ ^[1-9][0-9]*$ ]] || return 2
  python3 - "$descriptor" "$maximum_bytes" <<'PY'
import fcntl
import hashlib
import os
import stat
import sys


descriptor = int(sys.argv[1])
maximum_bytes = int(sys.argv[2])
before = os.fstat(descriptor)
if (
    not stat.S_ISREG(before.st_mode)
    or before.st_uid not in (0, os.geteuid())
    or before.st_nlink != 1
    or before.st_size < 0
    or before.st_size > maximum_bytes
):
    raise RuntimeError("unsafe descriptor-backed file")
fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
          "st_mtime_ns", "st_ctime_ns")
reader = descriptor
close_reader = False
position = None
try:
    access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    if access_mode == os.O_WRONLY:
        reader = os.open(f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_CLOEXEC)
        close_reader = True
        reader_state = os.fstat(reader)
        if any(
            getattr(before, field) != getattr(reader_state, field)
            for field in fields
        ):
            raise RuntimeError("descriptor reader differs from retained file")
    else:
        position = os.lseek(reader, 0, os.SEEK_CUR)
    os.lseek(reader, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    observed_bytes = 0
    while True:
        chunk = os.read(reader, min(1024 * 1024, maximum_bytes + 1))
        if not chunk:
            break
        observed_bytes += len(chunk)
        if observed_bytes > maximum_bytes:
            raise RuntimeError("descriptor-backed file exceeds its byte bound")
        digest.update(chunk)
    if position is not None:
        os.lseek(reader, position, os.SEEK_SET)
    after = os.fstat(descriptor)
    reader_after = os.fstat(reader)
    if any(
        getattr(before, field) != getattr(after, field)
        or getattr(after, field) != getattr(reader_after, field)
        for field in fields
    ):
        raise RuntimeError("descriptor-backed file changed while hashing")
finally:
    if close_reader:
        os.close(reader)
print(":".join(str(value) for value in (
    after.st_dev,
    after.st_ino,
    after.st_uid,
    format(stat.S_IMODE(after.st_mode), "o"),
    after.st_nlink,
    after.st_size,
    after.st_mtime_ns,
    after.st_ctime_ns,
    digest.hexdigest(),
)))
PY
}

compatibility_stable_jq_query() {
  [[ $# -ge 6 ]] || return 2
  python3 - "$@" <<'PY'
import hashlib
import os
import stat
import subprocess
import sys


arguments = sys.argv[1:]
try:
    separator = arguments.index("--")
except ValueError:
    raise SystemExit(2)
specification = arguments[:separator]
command = arguments[separator + 1 :]
if not command or command[0] != "jq" or len(specification) == 0 or len(specification) % 4:
    raise SystemExit(2)

identity_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
    "st_mtime_ns", "st_ctime_ns",
)


def identity_text(state, digest):
    return ":".join(str(value) for value in (
        state.st_dev,
        state.st_ino,
        state.st_uid,
        format(stat.S_IMODE(state.st_mode), "o"),
        state.st_nlink,
        state.st_size,
        state.st_mtime_ns,
        state.st_ctime_ns,
        digest,
    ))


def descriptor_identity(descriptor, maximum_bytes):
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("stable jq input is not regular")
    if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
        raise RuntimeError("stable jq input has unsafe ownership or links")
    if before.st_size < 0 or before.st_size > maximum_bytes:
        raise RuntimeError("stable jq input exceeds its byte bound")
    position = os.lseek(descriptor, 0, os.SEEK_CUR)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    observed_bytes = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1))
        if not chunk:
            break
        observed_bytes += len(chunk)
        if observed_bytes > maximum_bytes:
            raise RuntimeError("stable jq input grew beyond its byte bound")
        digest.update(chunk)
    os.lseek(descriptor, position, os.SEEK_SET)
    after = os.fstat(descriptor)
    if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
        raise RuntimeError("stable jq input changed while hashing")
    return identity_text(after, digest.hexdigest()), after


opened = []
replacements = {}
try:
    for index in range(0, len(specification), 4):
        token, path, expected_identity, maximum_text = specification[index:index + 4]
        if not token.startswith("@") or not token.endswith("@") or token in replacements:
            raise RuntimeError("invalid stable jq input token")
        maximum_bytes = int(maximum_text)
        if maximum_bytes <= 0:
            raise RuntimeError("invalid stable jq byte bound")
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        observed_identity, state = descriptor_identity(descriptor, maximum_bytes)
        if observed_identity != expected_identity:
            os.close(descriptor)
            raise RuntimeError("stable jq input differs from its retained identity")
        opened.append((path, descriptor, expected_identity, maximum_bytes, state))
        replacements[token] = f"/proc/self/fd/{descriptor}"

    resolved_command = [replacements.get(value, value) for value in command]
    completed = subprocess.run(
        resolved_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=tuple(item[1] for item in opened),
        check=False,
    )
    for path, descriptor, expected_identity, maximum_bytes, retained_state in opened:
        observed_identity, current_state = descriptor_identity(descriptor, maximum_bytes)
        if observed_identity != expected_identity or any(
            getattr(retained_state, field) != getattr(current_state, field)
            for field in identity_fields
        ):
            raise RuntimeError("stable jq input changed during query")
        path_state = os.stat(path, follow_symlinks=False)
        if any(
            getattr(current_state, field) != getattr(path_state, field)
            for field in identity_fields
        ):
            raise RuntimeError("stable jq input path changed during query")
    if len(completed.stdout) > 64 * 1024 * 1024 or len(completed.stderr) > 4 * 1024 * 1024:
        raise RuntimeError("stable jq output exceeds its byte bound")
    if completed.returncode != 0:
        os.write(2, completed.stderr)
        raise SystemExit(completed.returncode)
    os.write(1, completed.stdout)
finally:
    for _, descriptor, _, _, _ in opened:
        os.close(descriptor)
PY
}

compatibility_tree_authority() {
  local -r operation="$1"
  local -r source="$2"
  local -r argument="${3:-}"
  local -r target="${4:-}"
  local -r test_hook="${5:-}"

  [[ "$source" == /* &&
    ( "$operation" == identity || "$operation" == manifest ||
      "$operation" == publish ) ]] || return 2
  python3 - "$operation" "$source" "$argument" "$target" "$test_hook" \
    "$COMPATIBILITY_MAX_PRIVATE_FILES" \
    "$COMPATIBILITY_MAX_PRIVATE_BYTES" <<'PY'
import ctypes
import errno
import hashlib
import json
import os
import re
import resource
import secrets
import stat
import subprocess
import sys


operation, source, argument, target, test_hook = sys.argv[1:6]
maximum_entries = int(sys.argv[6])
maximum_bytes = int(sys.argv[7])
directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
identity_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
    "st_mtime_ns", "st_ctime_ns",
)
directory_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
    "st_mtime_ns", "st_ctime_ns",
)
root_post_rename_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
)
safe_component = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def values(state, fields):
    return tuple(getattr(state, field) for field in fields)


def same(left, right, fields):
    return values(left, fields) == values(right, fields)


def require_safe_directory(state, root_device):
    if not stat.S_ISDIR(state.st_mode):
        raise RuntimeError("tree entry is not a directory")
    if state.st_dev != root_device or state.st_uid != os.geteuid():
        raise RuntimeError("tree directory has unsafe device or ownership")
    if stat.S_IMODE(state.st_mode) & 0o022:
        raise RuntimeError("tree directory is group/world writable")


def require_safe_file(state, root_device):
    if not stat.S_ISREG(state.st_mode):
        raise RuntimeError("tree entry is not a regular file")
    if state.st_dev != root_device or state.st_uid != os.geteuid() or state.st_nlink != 1:
        raise RuntimeError("tree file has unsafe device, ownership, or link count")
    if stat.S_IMODE(state.st_mode) & 0o022:
        raise RuntimeError("tree file is group/world writable")
    if state.st_size < 0:
        raise RuntimeError("tree file has a negative size")


def hash_file(descriptor, maximum, midpoint_hook=None):
    before = os.fstat(descriptor)
    position = os.lseek(descriptor, 0, os.SEEK_CUR)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    observed = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1))
        if not chunk:
            break
        observed += len(chunk)
        if observed > maximum:
            raise RuntimeError("tree file exceeds the byte bound")
        digest.update(chunk)
        if midpoint_hook is not None:
            hook = midpoint_hook
            midpoint_hook = None
            hook()
    os.lseek(descriptor, position, os.SEEK_SET)
    after = os.fstat(descriptor)
    if not same(before, after, identity_fields) or observed != after.st_size:
        raise RuntimeError("tree file changed while hashing")
    return digest.hexdigest(), after


def run_test_hook(phase, path):
    if not test_hook:
        return
    if not os.path.isabs(test_hook):
        raise RuntimeError("publication test hook must be absolute")
    hook_state = os.stat(test_hook, follow_symlinks=False)
    if not stat.S_ISREG(hook_state.st_mode) or hook_state.st_uid != os.geteuid():
        raise RuntimeError("publication test hook is unsafe")
    if stat.S_IMODE(hook_state.st_mode) & 0o022 or not os.access(test_hook, os.X_OK):
        raise RuntimeError("publication test hook permissions are unsafe")
    completed = subprocess.run(
        [test_hook, phase, path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if len(completed.stderr) > 65536 or completed.returncode != 0:
        raise RuntimeError("publication test hook failed")


class RetainedTree:
    def __init__(self, path):
        self.path = path
        self.root_fd = os.open(path, directory_flags)
        self.directories = {}
        self.files = {}
        self.rosters = {}
        self.total_bytes = 0
        self.root_state = os.fstat(self.root_fd)
        self.root_device = self.root_state.st_dev
        require_safe_directory(self.root_state, self.root_device)
        path_state = os.stat(path, follow_symlinks=False)
        if not same(self.root_state, path_state, directory_fields):
            raise RuntimeError("tree root path changed while opening")
        self.directories[""] = (self.root_fd, self.root_state)
        self._open_tree()

    def _open_tree(self):
        pending = [""]
        entry_count = 0
        while pending:
            relative_directory = pending.pop(0)
            directory_fd, _ = self.directories[relative_directory]
            names = sorted(os.listdir(directory_fd))
            if len(names) != len(set(names)):
                raise RuntimeError("tree directory contains duplicate names")
            self.rosters[relative_directory] = tuple(names)
            for name in names:
                if not safe_component.fullmatch(name) or name in (".", ".."):
                    raise RuntimeError("tree contains an unsafe path component")
                relative = name if not relative_directory else f"{relative_directory}/{name}"
                if len(relative) > 512:
                    raise RuntimeError("tree path exceeds the length bound")
                entry_count += 1
                if entry_count > maximum_entries:
                    raise RuntimeError("tree exceeds the entry bound")
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(observed.st_mode):
                    descriptor = os.open(name, directory_flags, dir_fd=directory_fd)
                    retained = os.fstat(descriptor)
                    if not same(observed, retained, directory_fields):
                        os.close(descriptor)
                        raise RuntimeError("tree directory changed while opening")
                    require_safe_directory(retained, self.root_device)
                    self.directories[relative] = (descriptor, retained)
                    pending.append(relative)
                elif stat.S_ISREG(observed.st_mode):
                    descriptor = os.open(name, file_flags, dir_fd=directory_fd)
                    retained = os.fstat(descriptor)
                    if not same(observed, retained, identity_fields):
                        os.close(descriptor)
                        raise RuntimeError("tree file changed while opening")
                    require_safe_file(retained, self.root_device)
                    self.total_bytes += retained.st_size
                    if self.total_bytes > maximum_bytes:
                        os.close(descriptor)
                        raise RuntimeError("tree exceeds the byte bound")
                    digest, retained_after = hash_file(descriptor, retained.st_size)
                    if not same(retained, retained_after, identity_fields):
                        os.close(descriptor)
                        raise RuntimeError("tree file changed during initial hashing")
                    self.files[relative] = (descriptor, retained, digest)
                else:
                    raise RuntimeError("tree contains a symlink or special entry")
        required = 32 + len(self.directories) + len(self.files)
        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_limit != resource.RLIM_INFINITY and soft_limit < required:
            raise RuntimeError("insufficient descriptor limit for retained tree authority")

    def _parent_and_name(self, relative):
        parent, _, name = relative.rpartition("/")
        return self.directories[parent][0], name

    def manifest_records(self):
        root = self.root_state
        records = [[
            "directory", "", root.st_dev, root.st_ino, root.st_uid,
            root.st_mode, root.st_nlink,
        ]]
        for relative in sorted(key for key in self.directories if key):
            state = self.directories[relative][1]
            records.append([
                "directory", relative, state.st_dev, state.st_ino, state.st_uid,
                state.st_mode, state.st_nlink, state.st_mtime_ns, state.st_ctime_ns,
            ])
        for relative in sorted(self.files):
            _, state, digest = self.files[relative]
            records.append([
                "file", relative, state.st_dev, state.st_ino, state.st_uid,
                state.st_mode, state.st_nlink, state.st_size,
                state.st_mtime_ns, state.st_ctime_ns, digest,
            ])
        return records

    def manifest_digest(self):
        payload = json.dumps(
            self.manifest_records(), sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def identity_text(self):
        state = self.root_state
        return ":".join(str(value) for value in (
            state.st_dev,
            state.st_ino,
            state.st_uid,
            format(stat.S_IMODE(state.st_mode), "o"),
            state.st_nlink,
            state.st_mtime_ns,
            state.st_ctime_ns,
            self.manifest_digest(),
        ))

    def public_manifest(self):
        lines = [f"{self.files[path][2]}  {path}\n" for path in sorted(self.files)]
        return "".join(lines).encode("ascii")

    def verify(self, root_path, allow_root_rename=False, hook_phase=""):
        for relative, (descriptor, retained) in self.directories.items():
            current = os.fstat(descriptor)
            fields = root_post_rename_fields if relative == "" and allow_root_rename else directory_fields
            if not same(retained, current, fields):
                raise RuntimeError("retained tree directory identity changed")
            if tuple(sorted(os.listdir(descriptor))) != self.rosters[relative]:
                raise RuntimeError("retained tree roster changed")
        if hook_phase:
            run_test_hook(hook_phase, root_path)
        for relative, (descriptor, retained, retained_digest) in self.files.items():
            midpoint_hook = None
            if hook_phase:
                midpoint_hook = lambda relative=relative: run_test_hook(
                    f"{hook_phase}-midpoint",
                    f"{root_path}/{relative}",
                )
            current_digest, current = hash_file(
                descriptor,
                retained.st_size,
                midpoint_hook,
            )
            if not same(retained, current, identity_fields) or current_digest != retained_digest:
                raise RuntimeError("retained tree file changed")
            parent_fd, name = self._parent_and_name(relative)
            path_state = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not same(current, path_state, identity_fields):
                raise RuntimeError("retained tree file path changed")
        for relative, (descriptor, retained) in self.directories.items():
            if tuple(sorted(os.listdir(descriptor))) != self.rosters[relative]:
                raise RuntimeError("retained tree roster changed during final hashing")
            if relative:
                parent_fd, name = self._parent_and_name(relative)
                path_state = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not same(retained, path_state, directory_fields):
                    raise RuntimeError("retained tree directory path changed")
        current_root = os.stat(root_path, follow_symlinks=False)
        root_fields = root_post_rename_fields if allow_root_rename else directory_fields
        if not same(self.root_state, current_root, root_fields):
            raise RuntimeError("retained tree root path changed")

    def close(self):
        for relative, (descriptor, _) in sorted(
            self.directories.items(), key=lambda item: item[0].count("/"), reverse=True
        ):
            if descriptor >= 0:
                os.close(descriptor)
        for descriptor, _, _ in self.files.values():
            os.close(descriptor)


libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    raise RuntimeError("renameat2 is unavailable")
renameat2.argtypes = (
    ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
)
renameat2.restype = ctypes.c_int


def safe_parent(state):
    return (
        stat.S_ISDIR(state.st_mode)
        and state.st_uid == os.geteuid()
        and not stat.S_IMODE(state.st_mode) & 0o022
    )


def parent_matches(path, descriptor):
    return same(
        os.fstat(descriptor),
        os.stat(path, follow_symlinks=False),
        ("st_dev", "st_ino", "st_uid", "st_mode"),
    )


def move_to_quarantine(parent_fd, name, label):
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return ""
    for _ in range(128):
        quarantine = f".compatibility-rejected.{label}.{secrets.token_hex(16)}"
        if renameat2(
            parent_fd,
            os.fsencode(name),
            parent_fd,
            os.fsencode(quarantine),
            1,
        ) == 0:
            os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
            return quarantine
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            continue
        if error_number == errno.ENOENT:
            return ""
        raise OSError(error_number, os.strerror(error_number))
    raise RuntimeError("could not allocate a publication quarantine name")


def publish_payload(payload, output, mode, tree=None):
    parent_path, name = os.path.split(output)
    if not parent_path or not name or name in (".", "..") or "/" in name or "\n" in name:
        raise RuntimeError("unsafe output path")
    parent_fd = os.open(parent_path, directory_flags)
    candidate_fd = None
    candidate_name = ""
    moved = False
    try:
        if not safe_parent(os.fstat(parent_fd)) or not parent_matches(parent_path, parent_fd):
            raise RuntimeError("unsafe publication parent")
        if tree is not None and any(
            values(os.fstat(parent_fd), ("st_dev", "st_ino")) ==
            values(state, ("st_dev", "st_ino"))
            for _, state in tree.directories.values()
        ):
            raise RuntimeError("manifest output parent is inside the evidenced tree")
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(errno.EEXIST, "publication target exists", output)
        for _ in range(128):
            candidate_name = f".compatibility-publish.{secrets.token_hex(16)}"
            try:
                candidate_fd = os.open(
                    candidate_name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    mode,
                    dir_fd=parent_fd,
                )
                break
            except FileExistsError:
                continue
        if candidate_fd is None:
            raise RuntimeError("could not allocate a publication candidate")
        view = memoryview(payload)
        while view:
            written = os.write(candidate_fd, view)
            if written <= 0:
                raise RuntimeError("short publication write")
            view = view[written:]
        os.fchmod(candidate_fd, mode)
        os.fsync(candidate_fd)
        candidate_digest, candidate_state = hash_file(candidate_fd, len(payload))
        if candidate_digest != hashlib.sha256(payload).hexdigest():
            raise RuntimeError("publication candidate digest mismatch")
        named_state = os.stat(candidate_name, dir_fd=parent_fd, follow_symlinks=False)
        if not same(candidate_state, named_state, identity_fields):
            raise RuntimeError("publication candidate name changed")
        if tree is not None:
            tree.verify(tree.path)
        if renameat2(
            parent_fd, os.fsencode(candidate_name), parent_fd, os.fsencode(name), 1
        ) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number), output)
        moved = True
        renamed_state = os.fstat(candidate_fd)
        final_state = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not same(renamed_state, final_state, identity_fields):
            raise RuntimeError("published file name differs from retained candidate")
        final_digest, retained_state = hash_file(candidate_fd, len(payload))
        if not same(renamed_state, retained_state, identity_fields) or \
                final_digest != candidate_digest:
            raise RuntimeError("published file differs from retained candidate")
        if tree is not None:
            tree.verify(tree.path)
        if not parent_matches(parent_path, parent_fd):
            raise RuntimeError("publication parent path changed")
        os.fsync(parent_fd)
    except BaseException:
        retained = move_to_quarantine(parent_fd, name if moved else candidate_name, "file")
        if retained:
            print(
                f"rejected publication retained in quarantine: {parent_path}/{retained}",
                file=sys.stderr,
            )
        raise
    finally:
        if candidate_fd is not None:
            os.close(candidate_fd)
        os.close(parent_fd)


tree = RetainedTree(source)
try:
    tree.verify(source)
    if operation == "identity":
        if argument or target or test_hook:
            raise SystemExit(2)
        print(tree.identity_text())
    elif operation == "manifest":
        if not argument or target or test_hook:
            raise SystemExit(2)
        publish_payload(tree.public_manifest(), argument, 0o600, tree)
    elif operation == "publish":
        if not argument or not target:
            raise SystemExit(2)
        if tree.identity_text() != argument:
            raise RuntimeError("directory publication source identity changed")
        source_parent, source_name = os.path.split(source)
        target_parent, target_name = os.path.split(target)
        if not source_parent or not target_parent or not source_name or not target_name:
            raise RuntimeError("unsafe directory publication path")
        source_parent_fd = os.open(source_parent, directory_flags)
        target_parent_fd = os.open(target_parent, directory_flags)
        moved = False
        try:
            if not safe_parent(os.fstat(source_parent_fd)) or not safe_parent(
                os.fstat(target_parent_fd)
            ):
                raise RuntimeError("directory publication parent is unsafe")
            if not parent_matches(source_parent, source_parent_fd) or not parent_matches(
                target_parent, target_parent_fd
            ):
                raise RuntimeError("directory publication parent path changed")
            source_state = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
            if not same(source_state, tree.root_state, directory_fields):
                raise RuntimeError("directory publication source path changed")
            try:
                os.stat(target_name, dir_fd=target_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(errno.EEXIST, "directory publication target exists")
            tree.verify(source, hook_phase="directory-before-rename-final-rehash")
            if renameat2(
                source_parent_fd,
                os.fsencode(source_name),
                target_parent_fd,
                os.fsencode(target_name),
                1,
            ) != 0:
                error_number = ctypes.get_errno()
                raise OSError(error_number, os.strerror(error_number))
            moved = True
            tree.root_state = os.fstat(tree.root_fd)
            tree.directories[""] = (tree.root_fd, tree.root_state)
            tree.verify(
                target,
                hook_phase="directory-after-rename-final-rehash",
            )
            try:
                os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("directory publication left the source name occupied")
            if not parent_matches(source_parent, source_parent_fd) or not parent_matches(
                target_parent, target_parent_fd
            ):
                raise RuntimeError("directory publication parent path changed")
            os.fsync(target_parent_fd)
        except BaseException:
            if moved:
                retained = move_to_quarantine(target_parent_fd, target_name, "directory")
                if retained:
                    print(
                        f"rejected directory retained in quarantine: {target_parent}/{retained}",
                        file=sys.stderr,
                    )
            raise
        finally:
            os.close(source_parent_fd)
            os.close(target_parent_fd)
finally:
    tree.close()
PY
}

compatibility_stable_directory_identity() {
  local -r path="$1"

  [[ "$path" == /* ]] || return 2
  compatibility_tree_authority identity "$path"
}

compatibility_snapshot_manifest_directory() {
  local -r source_directory="$1"
  local -r manifest="$2"
  local -r destination_directory="$3"
  local -r identity_ledger="$4"
  local -r snapshot_identity_ledger="${5:-}"
  local -r expected_manifest_identity="${6:-}"
  local -r stable_identity_pattern='^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]{64}$'

  [[ "$source_directory" == /* && "$manifest" == /* &&
    "$destination_directory" == /* && "$identity_ledger" == /* &&
    ( -z "$snapshot_identity_ledger" || "$snapshot_identity_ledger" == /* ) &&
    "$expected_manifest_identity" =~ $stable_identity_pattern ]] ||
    return 2
  python3 - "$source_directory" "$manifest" "$destination_directory" \
    "$identity_ledger" "$snapshot_identity_ledger" \
    "$expected_manifest_identity" \
    "$COMPATIBILITY_MAX_PRIVATE_FILES" \
    "$COMPATIBILITY_MAX_PRIVATE_BYTES" <<'PY'
import hashlib
import json
import os
import re
import resource
import stat
import sys


source, manifest_path, destination, ledger_path, snapshot_ledger_path = sys.argv[1:6]
expected_manifest_identity = sys.argv[6]
maximum_entries = int(sys.argv[7])
maximum_bytes = int(sys.argv[8])
safe_path = re.compile(
    r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$",
)
identity_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
    "st_mtime_ns", "st_ctime_ns",
)
directory_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
    "st_mtime_ns", "st_ctime_ns",
)


def values(state, fields):
    return [getattr(state, field) for field in fields]


def same(left, right, fields):
    return values(left, fields) == values(right, fields)


def write_all(descriptor, payload):
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("short snapshot write")
        view = view[written:]


def write_ledger(path, value):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o400,
    )
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        write_all(descriptor, payload.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def file_identity(state, digest):
    return ":".join(str(value) for value in (
        state.st_dev,
        state.st_ino,
        state.st_uid,
        format(stat.S_IMODE(state.st_mode), "o"),
        state.st_nlink,
        state.st_size,
        state.st_mtime_ns,
        state.st_ctime_ns,
        digest,
    ))


maximum_manifest_bytes = maximum_entries * (64 + 2 + 512 + 1)
manifest_fd = os.open(
    manifest_path,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
try:
    manifest_before = os.fstat(manifest_fd)
    if not stat.S_ISREG(manifest_before.st_mode):
        raise RuntimeError("manifest authority is not regular")
    if manifest_before.st_uid not in (0, os.geteuid()) or manifest_before.st_nlink != 1:
        raise RuntimeError("manifest authority has unsafe ownership or links")
    if manifest_before.st_size < 0 or manifest_before.st_size > maximum_manifest_bytes:
        raise RuntimeError("manifest authority exceeds its byte bound")
    manifest_payload = bytearray()
    manifest_digest = hashlib.sha256()
    while True:
        chunk = os.read(manifest_fd, min(1024 * 1024, maximum_manifest_bytes + 1))
        if not chunk:
            break
        manifest_payload.extend(chunk)
        manifest_digest.update(chunk)
        if len(manifest_payload) > maximum_manifest_bytes:
            raise RuntimeError("manifest authority grew beyond its byte bound")
    manifest_after = os.fstat(manifest_fd)
    if not same(manifest_before, manifest_after, identity_fields):
        raise RuntimeError("manifest authority changed while reading")
    manifest_current = os.stat(manifest_path, follow_symlinks=False)
    if not same(manifest_after, manifest_current, identity_fields):
        raise RuntimeError("manifest authority path changed while reading")
    if file_identity(manifest_after, manifest_digest.hexdigest()) != expected_manifest_identity:
        raise RuntimeError("manifest authority differs from its retained identity")
finally:
    os.close(manifest_fd)
if manifest_payload and (not manifest_payload.endswith(b"\n") or b"\r" in manifest_payload):
    raise RuntimeError("manifest has non-canonical line endings")
manifest_lines = bytes(manifest_payload).decode("ascii").splitlines()
if len(manifest_lines) > maximum_entries:
    raise RuntimeError("manifest exceeds the entry bound")

entries = []
seen = set()
for line in manifest_lines:
    if len(line) < 67 or line[64:66] != "  ":
        raise RuntimeError("malformed manifest line")
    digest, relative = line[:64], line[66:]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("malformed manifest digest")
    if not safe_path.fullmatch(relative) or any(
        component in ("", ".", "..") for component in relative.split("/")
    ) or len(relative) > 512 or any(
        len(component) > 128 for component in relative.split("/")
    ):
        raise RuntimeError("unsafe manifest path")
    if relative in seen:
        raise RuntimeError("duplicate manifest path")
    seen.add(relative)
    entries.append((relative, digest))
if entries != sorted(entries, key=lambda item: item[0]):
    raise RuntimeError("manifest paths are not canonical")

required_fds = 32 + len(entries) * 2
soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
if soft_limit != resource.RLIM_INFINITY and soft_limit < required_fds:
    raise RuntimeError("insufficient descriptor limit for an atomic evidence snapshot")

root_fd = os.open(
    source,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
)
directory_fds = {"": root_fd}
directory_states = {"": os.fstat(root_fd)}
file_fds = {}
file_states = {}
ledger = {"directories": {}, "files": {}, "schema": "compatibility-directory-source-identity-v1"}
total_bytes = 0
try:
    root_state = directory_states[""]
    if root_state.st_uid not in (0, os.geteuid()) or stat.S_IMODE(root_state.st_mode) & 0o022:
        raise RuntimeError("unsafe evidence root authority")
    os.mkdir(destination, 0o700)
    for relative, expected_digest in entries:
        components = relative.split("/")
        parent_key = ""
        for component in components[:-1]:
            child_key = component if not parent_key else f"{parent_key}/{component}"
            if child_key not in directory_fds:
                child_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                    dir_fd=directory_fds[parent_key],
                )
                child_state = os.fstat(child_fd)
                if child_state.st_uid not in (0, os.geteuid()) or stat.S_IMODE(child_state.st_mode) & 0o022:
                    os.close(child_fd)
                    raise RuntimeError("unsafe evidence directory authority")
                directory_fds[child_key] = child_fd
                directory_states[child_key] = child_state
                os.makedirs(os.path.join(destination, child_key), mode=0o700, exist_ok=True)
            parent_key = child_key

        leaf_fd = os.open(
            components[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fds[parent_key],
        )
        before = os.fstat(leaf_fd)
        if not stat.S_ISREG(before.st_mode):
            os.close(leaf_fd)
            raise RuntimeError("manifest entry is not a regular file")
        if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
            os.close(leaf_fd)
            raise RuntimeError("unsafe evidence file authority")
        if stat.S_IMODE(before.st_mode) & 0o022:
            os.close(leaf_fd)
            raise RuntimeError("evidence file is group/world writable")
        if before.st_size < 0:
            os.close(leaf_fd)
            raise RuntimeError("negative evidence size")
        total_bytes += before.st_size
        if total_bytes > maximum_bytes:
            os.close(leaf_fd)
            raise RuntimeError("manifest exceeds the byte bound")

        destination_path = os.path.join(destination, relative)
        destination_fd = os.open(
            destination_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o400,
        )
        digest = hashlib.sha256()
        observed_bytes = 0
        try:
            while True:
                chunk = os.read(leaf_fd, min(1024 * 1024, maximum_bytes + 1))
                if not chunk:
                    break
                observed_bytes += len(chunk)
                if observed_bytes > before.st_size or total_bytes > maximum_bytes:
                    raise RuntimeError("evidence file grew while copying")
                digest.update(chunk)
                write_all(destination_fd, chunk)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        after = os.fstat(leaf_fd)
        if not same(before, after, identity_fields):
            os.close(leaf_fd)
            raise RuntimeError("evidence file changed while copying")
        if observed_bytes != before.st_size or digest.hexdigest() != expected_digest:
            os.close(leaf_fd)
            raise RuntimeError("evidence file differs from its manifest")
        file_fds[relative] = leaf_fd
        file_states[relative] = before

    for key, descriptor in directory_fds.items():
        state = os.fstat(descriptor)
        if not same(directory_states[key], state, directory_fields):
            raise RuntimeError("evidence directory changed during snapshot")
        ledger["directories"][key] = values(state, directory_fields)
    for relative, descriptor in file_fds.items():
        state = os.fstat(descriptor)
        if not same(file_states[relative], state, identity_fields):
            raise RuntimeError("evidence file changed during snapshot")
        ledger["files"][relative] = values(state, identity_fields)

    current_root = os.stat(source, follow_symlinks=False)
    if not same(directory_states[""], current_root, directory_fields):
        raise RuntimeError("evidence root path changed during snapshot")
    for key in sorted(directory_fds, key=lambda item: item.count("/")):
        if key == "":
            continue
        parent, _, leaf = key.rpartition("/")
        current = os.stat(leaf, dir_fd=directory_fds[parent], follow_symlinks=False)
        if not same(directory_states[key], current, directory_fields):
            raise RuntimeError("evidence directory path changed during snapshot")
    for relative, descriptor in file_fds.items():
        parent, _, leaf = relative.rpartition("/")
        current = os.stat(leaf, dir_fd=directory_fds[parent], follow_symlinks=False)
        if not same(file_states[relative], current, identity_fields):
            raise RuntimeError("evidence file path changed during snapshot")

    write_ledger(ledger_path, ledger)
    if snapshot_ledger_path:
        snapshot_ledger = {
            "directories": {},
            "files": {},
            "schema": "compatibility-directory-source-identity-v1",
        }
        snapshot_root = os.open(
            destination,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        )
        snapshot_directories = {"": snapshot_root}
        snapshot_files = []
        try:
            snapshot_ledger["directories"][""] = values(
                os.fstat(snapshot_root), directory_fields
            )
            for key in sorted(directory_fds, key=lambda item: item.count("/")):
                if key == "":
                    continue
                parent, _, leaf = key.rpartition("/")
                descriptor = os.open(
                    leaf,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
                    dir_fd=snapshot_directories[parent],
                )
                snapshot_directories[key] = descriptor
                snapshot_ledger["directories"][key] = values(
                    os.fstat(descriptor), directory_fields
                )
            for relative, _ in entries:
                parent, _, leaf = relative.rpartition("/")
                descriptor = os.open(
                    leaf,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=snapshot_directories[parent],
                )
                snapshot_files.append(descriptor)
                snapshot_ledger["files"][relative] = values(
                    os.fstat(descriptor), identity_fields
                )
            write_ledger(snapshot_ledger_path, snapshot_ledger)
        finally:
            for descriptor in snapshot_files:
                os.close(descriptor)
            for key in sorted(
                snapshot_directories,
                key=lambda item: item.count("/"),
                reverse=True,
            ):
                os.close(snapshot_directories[key])
finally:
    for descriptor in file_fds.values():
        os.close(descriptor)
    for key in sorted(directory_fds, key=lambda item: item.count("/"), reverse=True):
        os.close(directory_fds[key])
PY
}

compatibility_verify_manifest_directory_source() {
  local -r source_directory="$1"
  local -r identity_ledger="$2"
  local -r expected_ledger_identity="$3"
  local -r stable_identity_pattern='^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]{64}$'

  [[ "$source_directory" == /* && "$identity_ledger" == /* &&
    "$expected_ledger_identity" =~ $stable_identity_pattern ]] ||
    return 2
  python3 - "$source_directory" "$identity_ledger" \
    "$expected_ledger_identity" <<'PY'
import hashlib
import json
import os
import stat
import sys


source, ledger_path, expected_ledger_identity = sys.argv[1:4]
ledger_fd = os.open(
    ledger_path,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
try:
    before = os.fstat(ledger_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("unsafe evidence identity ledger")
    payload = bytearray()
    digest = hashlib.sha256()
    while True:
        chunk = os.read(ledger_fd, 1024 * 1024)
        if not chunk:
            break
        payload.extend(chunk)
        digest.update(chunk)
        if len(payload) > 64 * 1024 * 1024:
            raise RuntimeError("evidence identity ledger exceeds its bound")
    after = os.fstat(ledger_fd)
    fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise RuntimeError("evidence identity ledger changed while reading")
    observed_ledger_identity = ":".join(str(value) for value in (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        format(stat.S_IMODE(after.st_mode), "o"),
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        digest.hexdigest(),
    ))
    if observed_ledger_identity != expected_ledger_identity:
        raise RuntimeError("evidence identity ledger authority changed")
    ledger = json.loads(bytes(payload).decode("ascii"))
finally:
    os.close(ledger_fd)
if set(ledger) != {"directories", "files", "schema"} or ledger["schema"] != "compatibility-directory-source-identity-v1":
    raise RuntimeError("invalid evidence identity ledger")
directory_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
    "st_mtime_ns", "st_ctime_ns",
)
file_fields = (
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
    "st_mtime_ns", "st_ctime_ns",
)


def values(state, fields):
    return [getattr(state, field) for field in fields]


root_fd = os.open(
    source,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
)
directory_fds = {"": root_fd}
file_fds = []
try:
    if values(os.fstat(root_fd), directory_fields) != ledger["directories"].get(""):
        raise RuntimeError("evidence root authority changed")
    for key in sorted(ledger["directories"], key=lambda item: item.count("/")):
        if key == "":
            continue
        parent, _, leaf = key.rpartition("/")
        if parent not in directory_fds:
            raise RuntimeError("identity ledger has an orphan directory")
        descriptor = os.open(
            leaf,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
            dir_fd=directory_fds[parent],
        )
        if values(os.fstat(descriptor), directory_fields) != ledger["directories"][key]:
            os.close(descriptor)
            raise RuntimeError("evidence directory authority changed")
        directory_fds[key] = descriptor
    for relative, expected in ledger["files"].items():
        parent, _, leaf = relative.rpartition("/")
        if parent not in directory_fds:
            raise RuntimeError("identity ledger has an orphan file")
        descriptor = os.open(
            leaf,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fds[parent],
        )
        file_fds.append(descriptor)
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode) or values(state, file_fields) != expected:
            raise RuntimeError("evidence file authority changed")
finally:
    for descriptor in file_fds:
        os.close(descriptor)
    for key in sorted(directory_fds, key=lambda item: item.count("/"), reverse=True):
        os.close(directory_fds[key])
PY
}

compatibility_validate_relative_evidence_path() {
  local -r value="$1"

  [[ -n "$value" && ${#value} -le 512 &&
    "$value" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ &&
    "$value" != /* && "$value" != *$'\n'* && "$value" != *$'\r'* &&
    "$value" != . && "$value" != .. &&
    "$value" != ../* && "$value" != */../* && "$value" != */.. &&
    "$value" != ./* && "$value" != */./* && "$value" != */. ]]
}

compatibility_validate_public_evidence_path() {
  local -r value="$1"
  local -r secret_pattern='(^|[^[:alnum:]])(secret|password|passwd|token|credential|api[-_]?key|private[-_]?key)([^[:alnum:]]|$)'
  local lowercase=""

  compatibility_validate_relative_evidence_path "$value" || return
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$ ]] ||
    return 1
  lowercase="${value,,}"
  [[ ! "$lowercase" =~ $secret_pattern ]]
}

compatibility_registry_traversal_hook() {
  :
}

compatibility_registry_consumer_hook() {
  :
}

compatibility_materialize_provider_registry_roster() {
  local -r registry="$1"
  local -r output="$2"

  jq -r '
    .providers | to_entries | sort_by(.key)[] as $provider |
    ($provider.value.approved_drivers | sort_by(.id))[]? |
    [$provider.key, .path, .sha256] | @tsv
  ' "$registry" >"$output"
}

compatibility_materialize_lifecycle_executor_registry_roster() {
  local -r registry="$1"
  local -r output="$2"

  jq -r '
    .approved_executors | sort_by(.id)[]? | [.path, .sha256] | @tsv
  ' "$registry" >"$output"
}

compatibility_validate_registry_roster_descriptor() {
  local -r descriptor="$1"
  local -r expected_count="$2"
  local -r expected_identity="$3"
  local size=""
  local actual_count=""

  [[ "$descriptor" =~ ^[1-9][0-9]*$ &&
    "$expected_count" =~ ^[0-9]+$ &&
    "$expected_count" -le "$COMPATIBILITY_MAX_REGISTRY_ENTRIES" ]] || return 2
  [[ "$(compatibility_descriptor_file_identity \
    "$descriptor" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" == \
    "$expected_identity" ]] || return 1
  size="$(stat -Lc '%s' -- "/proc/self/fd/$descriptor")" || return
  actual_count="$(wc -l <"/proc/self/fd/$descriptor")" || return
  [[ "$size" =~ ^[0-9]+$ && "$actual_count" =~ ^[0-9]+$ &&
    "$size" -le "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES" &&
    "$actual_count" == "$expected_count" ]] ||
    compatibility_die "registry roster is partial, excessive, or malformed"
}

compatibility_validate_provider_registry() (
  local -r registry="${1:-$COMPATIBILITY_PROVIDER_REGISTRY}"
  local -r expected_registry_identity="${2:-}"
  local scratch_parent=""
  local scratch=""
  local scratch_identity=""
  local snapshot=""
  local source_identity=""
  local snapshot_identity=""
  local registry_descriptor=""
  local roster=""
  local roster_descriptor=""
  local roster_identity=""
  local expected_count=""
  local provider=""
  local relative_path=""
  local expected_sha256=""
  local approved_path=""
  local producer_status=0

  compatibility_require_commands jq mktemp python3 stat wc || return
  scratch_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$scratch_parent" || return
  scratch="$(mktemp -d "$scratch_parent/.compatibility-provider-registry.XXXXXX")" ||
    return
  scratch_identity="$(compatibility_directory_identity "$scratch")" || return
  trap 'compatibility_remove_owned_temp_directory \
    "$scratch" "$scratch_identity" "$scratch_parent" \
    "[.]compatibility-provider-registry[.]" || true' EXIT
  snapshot="$scratch/provider-registry.snapshot.json"
  source_identity="$(compatibility_create_stable_file_snapshot \
    "$registry" "$snapshot" 67108864)" || return
  [[ -z "$expected_registry_identity" ||
    "$source_identity" == "$expected_registry_identity" ]] ||
    compatibility_die "provider registry differs from its retained identity" || return
  snapshot_identity="$(compatibility_stable_file_identity "$snapshot" 67108864)" ||
    return
  compatibility_validate_json_file "$snapshot" || return
  exec {registry_descriptor}<"$snapshot" || return
  [[ "$(compatibility_descriptor_file_identity \
    "$registry_descriptor" 67108864)" == "$snapshot_identity" ]] || return 1
  jq -e --argjson max_entries "$COMPATIBILITY_MAX_REGISTRY_ENTRIES" '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def token: type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$");
    (keys == ["providers", "schema"]) and
    .schema == "compatibility-provider-registry-v1" and
    (.providers | keys) == [
      "preprovisioned-host-application-v1",
      "preprovisioned-jvm-application-v1",
      "preprovisioned-lifecycle-application-v1",
      "runsh-java21-container-v1"
    ] and
    all(.providers | to_entries[];
      (.value | keys == ["approved_drivers", "kind", "launcher"]) and
      .value.kind ==
        (if .key == "runsh-java21-container-v1" then "local" else "external" end) and
      .value.launcher == ("providers/" + .key + ".sh") and
      (.value.approved_drivers | type == "array" and length <= $max_entries) and
      all(.value.approved_drivers[];
        keys == ["id", "path", "sha256"] and
        (.id | token) and (.sha256 | sha256) and
        (.path | type == "string" and
          test("^providers/[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$"))) and
      ([.value.approved_drivers[].id] | unique | length) ==
        (.value.approved_drivers | length) and
      ([.value.approved_drivers[].path] | unique | length) ==
        (.value.approved_drivers | length) and
      ([.value.approved_drivers[].sha256] | unique | length) ==
        (.value.approved_drivers | length) and
      (if .value.kind == "local" then
        (.value.approved_drivers | length) == 0
       else true end)) and
    ([.providers[].approved_drivers[].id] | unique | length) ==
      ([.providers[].approved_drivers[].id] | length) and
    ([.providers[].approved_drivers[]] | length) <= $max_entries
  ' "/proc/self/fd/$registry_descriptor" >/dev/null ||
    compatibility_die "invalid compatibility provider registry" || return
  expected_count="$(jq -er '[.providers[].approved_drivers[]] | length' \
    "/proc/self/fd/$registry_descriptor")" || return
  roster="$scratch/provider-registry.roster.tsv"
  : >"$roster"
  chmod 0600 -- "$roster"
  exec {roster_descriptor}<>"$roster" || return
  compatibility_registry_traversal_hook \
    provider before "$registry" "$snapshot" "$roster" || return
  compatibility_materialize_provider_registry_roster \
    "/proc/self/fd/$registry_descriptor" "/proc/self/fd/$roster_descriptor" || {
    producer_status=$?
    compatibility_error "provider registry roster producer failed"
    return "$producer_status"
  }
  chmod 0400 -- "/proc/self/fd/$roster_descriptor" || return
  roster_identity="$(compatibility_descriptor_file_identity \
    "$roster_descriptor" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" || return
  compatibility_registry_traversal_hook \
    provider after "$registry" "$snapshot" "$roster" || return
  [[ "$(compatibility_stable_file_identity \
    "$roster" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" == \
    "$roster_identity" ]] ||
    compatibility_die "provider registry roster path changed" || return
  compatibility_validate_registry_roster_descriptor \
    "$roster_descriptor" "$expected_count" "$roster_identity" || return
  compatibility_registry_traversal_hook \
    provider before-read "$registry" "$snapshot" "$roster" || return
  while IFS=$'\t' read -r provider relative_path expected_sha256; do
    [[ -n "$provider" && -n "$relative_path" &&
      "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
    compatibility_validate_relative_evidence_path "$relative_path" ||
      compatibility_die "approved driver has an unsafe source path" || return
    approved_path="$COMPATIBILITY_DIRECTORY/$relative_path"
    compatibility_require_regular_file "$approved_path" || return
    [[ -x "$approved_path" && "$(readlink -f -- "$approved_path")" == "$approved_path" ]] ||
      compatibility_die "approved driver is not the exact executable source path" || return
    [[ "$(compatibility_sha256 "$approved_path")" == "$expected_sha256" ]] ||
      compatibility_die "approved driver digest does not match its source path" || return
  done <"/proc/self/fd/$roster_descriptor"
  compatibility_registry_traversal_hook \
    provider after-read "$registry" "$snapshot" "$roster" || return
  [[ "$(compatibility_descriptor_file_identity \
      "$registry_descriptor" 67108864)" == "$snapshot_identity" &&
    "$(compatibility_descriptor_file_identity \
      "$roster_descriptor" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" == \
      "$roster_identity" ]] || return 1
  exec {registry_descriptor}<&-
  exec {roster_descriptor}<&-
  [[ "$(compatibility_stable_file_identity "$snapshot" 67108864)" == \
      "$snapshot_identity" &&
    "$(compatibility_stable_file_identity \
      "$roster" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" == \
      "$roster_identity" ]] ||
    compatibility_die "provider registry snapshot changed during traversal" || return
  [[ "$(compatibility_stable_file_identity "$registry" 67108864)" == \
    "$source_identity" ]] ||
    compatibility_die "provider registry source changed during traversal"
)

compatibility_provider_registry_sha256() {
  local snapshot="${1:-}"
  local scratch_parent=""
  local scratch=""
  local scratch_identity=""
  local source_identity=""
  local snapshot_identity=""

  if [[ -n "$snapshot" ]]; then
    snapshot_identity="$(compatibility_stable_file_identity "$snapshot" 67108864)" ||
      return
    compatibility_validate_provider_registry "$snapshot" "$snapshot_identity" ||
      return
    [[ "$(compatibility_stable_file_identity "$snapshot" 67108864)" == \
      "$snapshot_identity" ]] ||
      compatibility_die "provider registry snapshot changed after validation" || return
    printf '%s\n' "${snapshot_identity##*:}"
    return
  fi

  scratch_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$scratch_parent" || return
  scratch="$(mktemp -d "$scratch_parent/.compatibility-provider-authority.XXXXXX")" ||
    return
  scratch_identity="$(compatibility_directory_identity "$scratch")" || return
  trap 'compatibility_remove_owned_temp_directory \
    "$scratch" "$scratch_identity" "$scratch_parent" \
    "[.]compatibility-provider-authority[.]" || true' RETURN
  snapshot="$scratch/provider-registry.snapshot.json"
  source_identity="$(compatibility_prepare_provider_registry_snapshot "$snapshot")" ||
    return
  snapshot_identity="$(compatibility_stable_file_identity "$snapshot" 67108864)" ||
    return
  [[ "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_PROVIDER_REGISTRY" 67108864)" == "$source_identity" ]] ||
    compatibility_die "provider registry source changed after validation" || return
  printf '%s\n' "${snapshot_identity##*:}"
}

compatibility_validate_lifecycle_executor_registry() (
  local -r registry="${1:-$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY}"
  local -r expected_registry_identity="${2:-}"
  local -r plan="$COMPATIBILITY_DIRECTORY/helper-lifecycle-v1.json"
  local scratch_parent=""
  local scratch=""
  local scratch_identity=""
  local registry_snapshot=""
  local plan_snapshot=""
  local registry_source_identity=""
  local plan_source_identity=""
  local registry_snapshot_identity=""
  local plan_snapshot_identity=""
  local registry_descriptor=""
  local plan_descriptor=""
  local roster=""
  local roster_descriptor=""
  local roster_identity=""
  local expected_count=""
  local relative_path=""
  local expected_sha256=""
  local approved_path=""
  local producer_status=0

  compatibility_require_commands jq mktemp python3 stat wc || return
  scratch_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$scratch_parent" || return
  scratch="$(mktemp -d "$scratch_parent/.compatibility-executor-registry.XXXXXX")" ||
    return
  scratch_identity="$(compatibility_directory_identity "$scratch")" || return
  trap 'compatibility_remove_owned_temp_directory \
    "$scratch" "$scratch_identity" "$scratch_parent" \
    "[.]compatibility-executor-registry[.]" || true' EXIT
  registry_snapshot="$scratch/lifecycle-executor-registry.snapshot.json"
  plan_snapshot="$scratch/helper-lifecycle-plan.snapshot.json"
  registry_source_identity="$(compatibility_create_stable_file_snapshot \
    "$registry" "$registry_snapshot" 67108864)" || return
  [[ -z "$expected_registry_identity" ||
    "$registry_source_identity" == "$expected_registry_identity" ]] ||
    compatibility_die \
      "lifecycle executor registry differs from its retained identity" || return
  plan_source_identity="$(compatibility_create_stable_file_snapshot \
    "$plan" "$plan_snapshot" 67108864)" || return
  registry_snapshot_identity="$(compatibility_stable_file_identity \
    "$registry_snapshot" 67108864)" || return
  plan_snapshot_identity="$(compatibility_stable_file_identity \
    "$plan_snapshot" 67108864)" || return
  compatibility_validate_json_file "$registry_snapshot" || return
  compatibility_validate_json_file "$plan_snapshot" || return
  exec {registry_descriptor}<"$registry_snapshot" || return
  exec {plan_descriptor}<"$plan_snapshot" || return
  [[ "$(compatibility_descriptor_file_identity \
      "$registry_descriptor" 67108864)" == "$registry_snapshot_identity" &&
    "$(compatibility_descriptor_file_identity \
      "$plan_descriptor" 67108864)" == "$plan_snapshot_identity" ]] || return 1
  jq -e \
    --argjson max_entries "$COMPATIBILITY_MAX_REGISTRY_ENTRIES" \
    --slurpfile plan "/proc/self/fd/$plan_descriptor" '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def token: type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$");
    def safe_path:
      type == "string" and
      test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$");
    ($plan[0].cells | map(.id) | sort) as $cell_ids |
    keys == ["approved_executors", "schema"] and
    .schema == "compatibility-lifecycle-executor-registry-v1" and
    (.approved_executors | type == "array" and length <= $max_entries) and
    all(.approved_executors[];
      keys == ["allowed_cell_ids", "id", "path", "sha256"] and
      (.id | token) and (.path | safe_path) and (.sha256 | sha256) and
      (.allowed_cell_ids | type == "array" and length > 0 and
        length <= ($cell_ids | length) and . == (sort | unique) and
        all(.[]; . as $cell_id | $cell_ids | index($cell_id) != null))) and
    ([.approved_executors[].id] | unique | length) ==
      (.approved_executors | length) and
    ([.approved_executors[].path] | unique | length) ==
      (.approved_executors | length) and
    ([.approved_executors[].sha256] | unique | length) ==
      (.approved_executors | length)
  ' "/proc/self/fd/$registry_descriptor" >/dev/null ||
    compatibility_die "invalid lifecycle executor registry" || return
  expected_count="$(jq -er '.approved_executors | length' \
    "/proc/self/fd/$registry_descriptor")" || return
  roster="$scratch/lifecycle-executor-registry.roster.tsv"
  : >"$roster"
  chmod 0600 -- "$roster"
  exec {roster_descriptor}<>"$roster" || return
  compatibility_registry_traversal_hook \
    lifecycle before "$registry" "$registry_snapshot" "$roster" || return
  compatibility_materialize_lifecycle_executor_registry_roster \
    "/proc/self/fd/$registry_descriptor" "/proc/self/fd/$roster_descriptor" || {
    producer_status=$?
    compatibility_error "lifecycle executor registry roster producer failed"
    return "$producer_status"
  }
  chmod 0400 -- "/proc/self/fd/$roster_descriptor" || return
  roster_identity="$(compatibility_descriptor_file_identity \
    "$roster_descriptor" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" || return
  compatibility_registry_traversal_hook \
    lifecycle after "$registry" "$registry_snapshot" "$roster" || return
  [[ "$(compatibility_stable_file_identity \
    "$roster" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" == \
    "$roster_identity" ]] ||
    compatibility_die "lifecycle executor registry roster path changed" || return
  compatibility_validate_registry_roster_descriptor \
    "$roster_descriptor" "$expected_count" "$roster_identity" || return
  compatibility_registry_traversal_hook \
    lifecycle before-read "$registry" "$registry_snapshot" "$roster" || return
  while IFS=$'\t' read -r relative_path expected_sha256; do
    [[ -n "$relative_path" && "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] ||
      return 1
    compatibility_validate_relative_evidence_path "$relative_path" ||
      compatibility_die "approved lifecycle executor has an unsafe source path" ||
      return
    approved_path="$COMPATIBILITY_DIRECTORY/$relative_path"
    compatibility_require_regular_file "$approved_path" || return
    [[ -x "$approved_path" &&
      "$(readlink -f -- "$approved_path")" == "$approved_path" ]] ||
      compatibility_die \
        "approved lifecycle executor is not the exact executable source path" ||
      return
    [[ "$(compatibility_sha256 "$approved_path")" == "$expected_sha256" ]] ||
      compatibility_die \
        "approved lifecycle executor digest does not match its source path" ||
      return
  done <"/proc/self/fd/$roster_descriptor"
  compatibility_registry_traversal_hook \
    lifecycle after-read "$registry" "$registry_snapshot" "$roster" || return
  [[ "$(compatibility_descriptor_file_identity \
      "$registry_descriptor" 67108864)" == "$registry_snapshot_identity" &&
    "$(compatibility_descriptor_file_identity \
      "$plan_descriptor" 67108864)" == "$plan_snapshot_identity" &&
    "$(compatibility_descriptor_file_identity \
      "$roster_descriptor" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" == \
      "$roster_identity" ]] || return 1
  exec {registry_descriptor}<&-
  exec {plan_descriptor}<&-
  exec {roster_descriptor}<&-
  [[ "$(compatibility_stable_file_identity \
      "$registry_snapshot" 67108864)" == "$registry_snapshot_identity" &&
    "$(compatibility_stable_file_identity \
      "$plan_snapshot" 67108864)" == "$plan_snapshot_identity" &&
    "$(compatibility_stable_file_identity \
      "$roster" "$COMPATIBILITY_MAX_REGISTRY_ROSTER_BYTES")" == \
      "$roster_identity" ]] ||
    compatibility_die "lifecycle registry snapshot changed during traversal" || return
  [[ "$(compatibility_stable_file_identity "$registry" 67108864)" == \
      "$registry_source_identity" &&
    "$(compatibility_stable_file_identity "$plan" 67108864)" == \
      "$plan_source_identity" ]] ||
    compatibility_die "lifecycle registry source changed during traversal"
)

compatibility_lifecycle_executor_registry_sha256() {
  local snapshot="${1:-}"
  local scratch_parent=""
  local scratch=""
  local scratch_identity=""
  local source_identity=""
  local snapshot_identity=""

  if [[ -n "$snapshot" ]]; then
    snapshot_identity="$(compatibility_stable_file_identity "$snapshot" 67108864)" ||
      return
    compatibility_validate_lifecycle_executor_registry \
      "$snapshot" "$snapshot_identity" || return
    [[ "$(compatibility_stable_file_identity "$snapshot" 67108864)" == \
      "$snapshot_identity" ]] ||
      compatibility_die "lifecycle executor registry snapshot changed after validation" ||
      return
    printf '%s\n' "${snapshot_identity##*:}"
    return
  fi

  scratch_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$scratch_parent" || return
  scratch="$(mktemp -d "$scratch_parent/.compatibility-executor-authority.XXXXXX")" ||
    return
  scratch_identity="$(compatibility_directory_identity "$scratch")" || return
  trap 'compatibility_remove_owned_temp_directory \
    "$scratch" "$scratch_identity" "$scratch_parent" \
    "[.]compatibility-executor-authority[.]" || true' RETURN
  snapshot="$scratch/lifecycle-executor-registry.snapshot.json"
  source_identity="$(
    compatibility_prepare_lifecycle_executor_registry_snapshot "$snapshot"
  )" || return
  snapshot_identity="$(compatibility_stable_file_identity "$snapshot" 67108864)" ||
    return
  [[ "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY" 67108864)" == \
      "$source_identity" ]] ||
    compatibility_die "lifecycle executor registry source changed after validation" ||
    return
  printf '%s\n' "${snapshot_identity##*:}"
}

compatibility_prepare_provider_registry_snapshot() {
  local -r destination="$1"
  local source_identity=""
  local snapshot_identity=""

  source_identity="$(compatibility_create_stable_file_snapshot \
    "$COMPATIBILITY_PROVIDER_REGISTRY" "$destination" 67108864)" || return
  snapshot_identity="$(compatibility_stable_file_identity \
    "$destination" 67108864)" || return
  compatibility_validate_provider_registry \
    "$destination" "$snapshot_identity" || return
  [[ "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_PROVIDER_REGISTRY" 67108864)" == "$source_identity" ]] ||
    compatibility_die "provider registry changed while retaining authority" || return
  printf '%s\n' "$source_identity"
}

compatibility_prepare_lifecycle_executor_registry_snapshot() {
  local -r destination="$1"
  local source_identity=""
  local snapshot_identity=""

  source_identity="$(compatibility_create_stable_file_snapshot \
    "$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY" "$destination" 67108864)" ||
    return
  snapshot_identity="$(compatibility_stable_file_identity \
    "$destination" 67108864)" || return
  compatibility_validate_lifecycle_executor_registry \
    "$destination" "$snapshot_identity" || return
  [[ "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY" 67108864)" == \
      "$source_identity" ]] ||
    compatibility_die \
      "lifecycle executor registry changed while retaining authority" || return
  printf '%s\n' "$source_identity"
}

compatibility_lifecycle_executor_approval() {
  local -r approval_id="$1"
  local -r source_path="$2"
  local -r executor_sha256="$3"
  local -r cell_id="$4"
  local -r registry="${5:-$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY}"
  local registry_identity=""
  local selected=""
  local query_status=0

  registry_identity="$(compatibility_stable_file_identity "$registry" 67108864)" ||
    return
  compatibility_validate_lifecycle_executor_registry \
    "$registry" "$registry_identity" || return
  [[ "$approval_id" =~ ^[a-z0-9][a-z0-9-]{0,95}$ &&
    "$source_path" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$ &&
    "$executor_sha256" =~ ^[0-9a-f]{64}$ &&
    "$cell_id" =~ ^[a-z0-9][a-z0-9-]{0,95}$ ]] || return 1
  compatibility_registry_consumer_hook lifecycle before-select "$registry" ||
    return
  selected="$(compatibility_stable_jq_query \
    @REGISTRY@ "$registry" "$registry_identity" 67108864 -- jq -cer \
    --arg id "$approval_id" \
    --arg path "$source_path" \
    --arg sha256 "$executor_sha256" \
    --arg cell_id "$cell_id" '
      [.approved_executors[] |
        select(.id == $id and .path == $path and .sha256 == $sha256 and
          (.allowed_cell_ids | index($cell_id) != null))] |
      if length == 1 then .[0] else empty end
    ' @REGISTRY@)" || query_status=$?
  compatibility_registry_consumer_hook lifecycle after-select "$registry" ||
    return
  (( query_status == 0 )) || return "$query_status"
  [[ "$(compatibility_stable_file_identity "$registry" 67108864)" == \
    "$registry_identity" ]] || return 1
  printf '%s\n' "$selected"
}

compatibility_provider_registry_driver_id() {
  local -r provider="$1"
  local -r driver_sha256="$2"
  local -r driver_path="$3"
  local -r registry="${4:-$COMPATIBILITY_PROVIDER_REGISTRY}"
  local resolved=""
  local relative=""
  local registry_identity=""
  local selected=""
  local query_status=0

  registry_identity="$(compatibility_stable_file_identity "$registry" 67108864)" ||
    return
  compatibility_validate_provider_registry "$registry" "$registry_identity" ||
    return
  [[ "$provider" =~ ^[a-z0-9][a-z0-9-]{0,95}$ &&
    "$driver_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  resolved="$(readlink -f -- "$driver_path" 2>/dev/null || true)"
  [[ "$resolved" == "$COMPATIBILITY_DIRECTORY"/* ]] || return 1
  relative="${resolved#"$COMPATIBILITY_DIRECTORY"/}"
  compatibility_validate_relative_evidence_path "$relative" || return
  compatibility_registry_consumer_hook provider before-select "$registry" ||
    return
  selected="$(compatibility_stable_jq_query \
    @REGISTRY@ "$registry" "$registry_identity" 67108864 -- jq -er \
    --arg provider "$provider" \
    --arg path "$relative" \
    --arg sha256 "$driver_sha256" '
    [.providers[$provider].approved_drivers[]? |
      select(.path == $path and .sha256 == $sha256)] |
    if length == 1 then .[0].id else empty end
  ' @REGISTRY@)" || query_status=$?
  compatibility_registry_consumer_hook provider after-select "$registry" ||
    return
  (( query_status == 0 )) || return "$query_status"
  [[ "$(compatibility_stable_file_identity "$registry" 67108864)" == \
    "$registry_identity" ]] || return 1
  printf '%s\n' "$selected"
}

compatibility_expected_evidence_index() {
  local -r result="$1"

  compatibility_validate_json_file "$result" || return
  jq -cS '
    . as $root |
    [(.runtime // {}), (.artifacts // {}), (.assertions // {})] as $roots |
    ([range(0; $roots | length) as $root_index |
      ($roots[$root_index] |
        paths(scalars) as $path |
        ($path[-1] | tostring) as $leaf |
        select($leaf == "sha256" or ($leaf | endswith("_sha256"))) |
        {
          field: ([(["runtime", "artifacts", "assertions"][$root_index])] +
            ($path | map(tostring)) | join(".")),
          sha256: getpath($path)
        })] +
      (if $root.lifecycle_executor? == null then [] else [{
        field: "lifecycle_executor.receipt_sha256",
        sha256: $root.lifecycle_executor.receipt_sha256
      }] end) | sort_by(.field))
  ' "$result"
}

compatibility_validate_evidence_index_shape() {
  local -r result="$1"

  compatibility_validate_json_file "$result" || return
  jq -e '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def contains_secret_word:
      test("(^|[^[:alnum:]])(secret|password|passwd|token|credential|api[-_]?key|private[-_]?key)([^[:alnum:]]|$)"; "i");
    def field:
      type == "string" and length > 0 and length <= 512 and
      test("^(runtime|artifacts|assertions|lifecycle_executor)([.][A-Za-z0-9_-]+)+$");
    def path_component:
      type == "string" and length > 0 and length <= 128 and
      test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$") and
      (contains_secret_word | not);
    def path:
      type == "string" and length > 0 and length <= 512 and
      (split("/") | all(.[]; path_component));
    if .status == "untested" and .lifecycle_executor? == null then
      .evidence_index == null
    elif .status == "fail" and .assertions.classification? == "provider-contract" then
      .evidence_index == []
    else
      (.evidence_index | type == "array" and length > 0 and length <= 512) and
      all(.evidence_index[];
        keys == ["field", "path", "sha256"] and
        (.field | field) and (.path | path) and (.sha256 | sha256)) and
      ([.evidence_index[].field] | sort) == [.evidence_index[].field] and
      ([.evidence_index[].field] | unique | length) == (.evidence_index | length) and
      ([.evidence_index[].path] | unique | length) == (.evidence_index | length)
    end
  ' "$result" >/dev/null ||
    compatibility_die "provider result has an invalid canonical evidence index"
}

compatibility_validate_collected_driver_identities() {
  local -r identities="$1"
  local -r registry="${2:-$COMPATIBILITY_PROVIDER_REGISTRY}"
  local identities_identity=""
  local registry_identity=""
  local query_status=0

  compatibility_require_regular_file "$identities" || return
  identities_identity="$(compatibility_stable_file_identity \
    "$identities" 67108864)" || return
  registry_identity="$(compatibility_stable_file_identity "$registry" 67108864)" ||
    return
  compatibility_validate_provider_registry "$registry" "$registry_identity" ||
    return
  compatibility_registry_consumer_hook \
    provider before-reapproval "$registry" "$identities" || return
  compatibility_stable_jq_query \
    @IDENTITIES@ "$identities" "$identities_identity" 67108864 \
    @REGISTRY@ "$registry" "$registry_identity" 67108864 -- \
    jq -s -e --slurpfile registry @REGISTRY@ '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def token: type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$");
    all(.[]; . as $root |
      keys == ["id", "provider", "sha256"] and
      (.id | token) and (.provider | token) and (.sha256 | sha256) and
      ([ $registry[0].providers[$root.provider].approved_drivers[]? |
        select(.id == $root.id and .sha256 == $root.sha256) ] | length == 1)) and
    (group_by(.provider) |
      all(.[]; ([.[] | [.id, .sha256]] | unique | length) == 1))
  ' @IDENTITIES@ >/dev/null || query_status=$?
  compatibility_registry_consumer_hook \
    provider after-reapproval "$registry" "$identities" || return
  (( query_status == 0 )) ||
    {
      compatibility_die "aggregate mixes or malforms external driver identities"
      return
    }
  [[ "$(compatibility_stable_file_identity "$registry" 67108864)" == \
      "$registry_identity" &&
    "$(compatibility_stable_file_identity "$identities" 67108864)" == \
      "$identities_identity" ]] ||
    compatibility_die "provider registry changed during collector reapproval"
}

compatibility_validate_collected_lifecycle_executor_identities() {
  local -r identities="$1"
  local -r registry_sha256="$2"
  local -r registry="${3:-$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY}"
  local identities_identity=""
  local registry_identity=""
  local query_status=0

  compatibility_require_regular_file "$identities" || return
  identities_identity="$(compatibility_stable_file_identity \
    "$identities" 67108864)" || return
  registry_identity="$(compatibility_stable_file_identity "$registry" 67108864)" ||
    return
  compatibility_validate_lifecycle_executor_registry \
    "$registry" "$registry_identity" || return
  [[ "$registry_sha256" == \
    "$(compatibility_lifecycle_executor_registry_sha256 "$registry")" ]] || return 1
  compatibility_registry_consumer_hook \
    lifecycle before-reapproval "$registry" "$identities" || return
  compatibility_stable_jq_query \
    @IDENTITIES@ "$identities" "$identities_identity" 67108864 \
    @REGISTRY@ "$registry" "$registry_identity" 67108864 -- \
    jq -s -e \
    --arg registry_sha256 "$registry_sha256" \
    --slurpfile registry @REGISTRY@ '
      def sha256: type == "string" and test("^[0-9a-f]{64}$");
      def token: type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$");
      all(.[]; . as $root |
        keys == ["approval", "cell_id", "registry_sha256"] and
        (.cell_id | token) and .registry_sha256 == $registry_sha256 and
        (.approval | keys == ["allowed_cell_ids", "id", "path", "sha256"]) and
        (.approval.id | token) and (.approval.sha256 | sha256) and
        ([ $registry[0].approved_executors[] |
          select(. == $root.approval and
            (.allowed_cell_ids | index($root.cell_id) != null)) ] | length == 1)) and
      ([.[] | [.approval.id, .approval.path, .approval.sha256]] | unique | length)
        <= 1
    ' @IDENTITIES@ >/dev/null || query_status=$?
  compatibility_registry_consumer_hook \
    lifecycle after-reapproval "$registry" "$identities" || return
  (( query_status == 0 )) ||
    {
      compatibility_die \
        "aggregate mixes or uses unapproved lifecycle executor identities"
      return
    }
  [[ "$(compatibility_stable_file_identity "$registry" 67108864)" == \
      "$registry_identity" &&
    "$(compatibility_stable_file_identity "$identities" 67108864)" == \
      "$identities_identity" ]] ||
    compatibility_die "lifecycle executor registry changed during collector reapproval"
}

compatibility_plan_path() {
  local -r campaign="$1"

  case "$campaign" in
    compatibility)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/campaign-v3.json"
      ;;
    helper-lifecycle)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/helper-lifecycle-v1.json"
      ;;
    *)
      compatibility_die "unknown campaign: $campaign"
      ;;
  esac
}

compatibility_expected_ids_path() {
  local -r campaign="$1"

  case "$campaign" in
    compatibility)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/expected-v3-cell-ids.txt"
      ;;
    helper-lifecycle)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/expected-helper-cell-ids.txt"
      ;;
    *)
      compatibility_die "unknown campaign: $campaign"
      ;;
  esac
}

compatibility_campaign_revision() {
  local -r campaign="$1"
  local plan=""

  plan="$(compatibility_plan_path "$campaign")" || return
  case "$campaign" in
    compatibility)
      jq -er '.matrix_revision' "$plan"
      ;;
    helper-lifecycle)
      jq -er '.campaign_revision' "$plan"
      ;;
  esac
}

compatibility_validate_expected_ids_file() {
  local -r expected_ids="$1"

  compatibility_require_regular_file "$expected_ids" || return
  awk '
    !/^[a-z0-9][a-z0-9-]{0,95}$/ { exit 1 }
    seen[$0]++ { exit 1 }
    END { if (NR == 0) exit 1 }
  ' "$expected_ids" || compatibility_die "invalid expected cell ID roster: $expected_ids"
}

compatibility_validate_plan() (
  local -r campaign="$1"
  local provider_registry="${2:-}"
  local executor_registry="${3:-}"
  local plan=""
  local expected_ids=""
  local actual=""
  local expected=""
  local plan_count=""
  local expected_count=""
  local authority_parent=""
  local authority_scratch=""
  local authority_identity=""
  local plan_identity=""
  local expected_ids_identity=""
  local provider_registry_identity=""
  local executor_registry_identity=""

  compatibility_require_commands jq sha256sum sort cmp mktemp || return
  authority_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$authority_parent" || return
  authority_scratch="$(mktemp -d \
    "$authority_parent/.compatibility-plan-authority.XXXXXX")" || return
  authority_identity="$(compatibility_directory_identity "$authority_scratch")" ||
    return
  trap 'compatibility_remove_owned_temp_directory \
    "$authority_scratch" "$authority_identity" "$authority_parent" \
    "[.]compatibility-plan-authority[.]" || true' EXIT
  if [[ -z "$provider_registry" || -z "$executor_registry" ]]; then
    [[ -z "$provider_registry" && -z "$executor_registry" ]] || return 2
    provider_registry="$authority_scratch/provider-registry.snapshot.json"
    executor_registry="$authority_scratch/lifecycle-executor-registry.snapshot.json"
    compatibility_prepare_provider_registry_snapshot "$provider_registry" >/dev/null ||
      return
    compatibility_prepare_lifecycle_executor_registry_snapshot \
      "$executor_registry" >/dev/null || return
  fi
  plan="$(compatibility_plan_path "$campaign")" || return
  expected_ids="$(compatibility_expected_ids_path "$campaign")" || return
  compatibility_require_regular_file "$plan" || return
  plan_identity="$(compatibility_stable_file_identity "$plan" 67108864)" || return
  expected_ids_identity="$(compatibility_stable_file_identity \
    "$expected_ids" 1048576)" || return
  compatibility_validate_json_file "$plan" "$plan_identity" ||
    compatibility_die "campaign plan is not unambiguous JSON: $plan" || return
  provider_registry_identity="$(compatibility_stable_file_identity \
    "$provider_registry" 67108864)" || return
  executor_registry_identity="$(compatibility_stable_file_identity \
    "$executor_registry" 67108864)" || return
  compatibility_validate_provider_registry \
    "$provider_registry" "$provider_registry_identity" || return
  compatibility_validate_lifecycle_executor_registry \
    "$executor_registry" "$executor_registry_identity" || return
  compatibility_validate_expected_ids_file "$expected_ids" || return
  compatibility_stable_jq_query \
    @PLAN@ "$plan" "$plan_identity" 67108864 \
    @REGISTRY@ "$provider_registry" "$provider_registry_identity" 67108864 -- \
    jq -e --slurpfile registry @REGISTRY@ '
    ([.cells[].provider] | unique | sort) as $plan_providers |
    ($registry[0].providers | keys | sort) as $registry_providers |
    all($plan_providers[]; $registry_providers | index(.) != null)
  ' @PLAN@ >/dev/null ||
    compatibility_die "campaign plan names a provider absent from the registry" || return

  actual="$(mktemp "$authority_scratch/actual.XXXXXX")" || return
  expected="$(mktemp "$authority_scratch/expected.XXXXXX")" || return

  compatibility_stable_jq_query \
    @PLAN@ "$plan" "$plan_identity" 67108864 -- jq -er '
    .expected_cell_count as $count |
    ($count | type == "number" and floor == . and . > 0 and . <= 1000) and
    (.cells | type == "array" and length == $count)
  ' @PLAN@ >/dev/null ||
    compatibility_die "campaign plan count is malformed: $plan" || return

  compatibility_stable_jq_query \
    @PLAN@ "$plan" "$plan_identity" 67108864 -- jq -er '
    .cells[] |
    (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$")) and
    (.kernel | type == "string" and length > 0 and length <= 64) and
    (.deployment == "host-process" or .deployment == "container-process") and
    (.cgroup_topology == "unified-v2" or
      .cgroup_topology == "hybrid-v1-v2" or
      .cgroup_topology == "nested-delegated-v2" or
      .cgroup_topology == "sibling-containers") and
    (.architecture == "amd64" or .architecture == "arm64") and
    (.jvm_feature == 8 or .jvm_feature == 11 or
      .jvm_feature == 17 or .jvm_feature == 21) and
    (.agent_distribution == "otel" or .agent_distribution == "splunk") and
    (.agent_version | type == "string" and length > 0 and length <= 64) and
    (.tls == "TLSv1.2" or .tls == "TLSv1.3") and
    (.transport == "getsockopt" or .transport == "unix" or .transport == "auto") and
    (.provider | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$"))
  ' @PLAN@ >/dev/null || compatibility_die "campaign plan contains an invalid cell" || return

  compatibility_stable_jq_query \
    @PLAN@ "$plan" "$plan_identity" 67108864 -- \
    jq -r '.cells[].id' @PLAN@ | LC_ALL=C sort >"$actual"
  LC_ALL=C sort "$expected_ids" >"$expected"
  cmp -s -- "$expected" "$actual" ||
    compatibility_die "campaign plan cell IDs differ from the frozen roster" || return

  plan_count="$(compatibility_stable_jq_query \
    @PLAN@ "$plan" "$plan_identity" 67108864 -- \
    jq -er '.expected_cell_count' @PLAN@)" || return
  expected_count="$(wc -l <"$expected_ids")" || return
  [[ "$plan_count" == "$expected_count" ]] ||
    compatibility_die "campaign plan count differs from the frozen roster"

  if [[ "$campaign" == compatibility ]]; then
    compatibility_stable_jq_query \
      @PLAN@ "$plan" "$plan_identity" 67108864 -- jq -e '
      def baseline_dimensions:
        .architecture == "amd64" and .jvm_feature == 21 and
        .agent_distribution == "otel" and .agent_version == "2.28.1" and
        .tls == "TLSv1.3" and .profile == "compatibility-smoke";
      (keys == [
        "baseline", "cells", "excluded_dimensions", "expected_cell_count",
        "matrix_revision", "schema"
      ]) and
      (all(.cells[]; keys == [
        "agent_distribution", "agent_version", "architecture", "cgroup_topology",
        "deployment", "id", "jvm_feature", "kernel", "profile", "provider",
        "slice", "tls", "transport"
      ])) and
      .baseline == {
        kernel: "upstream-6.12", deployment: "container-process",
        cgroup_topology: "unified-v2", architecture: "amd64",
        jvm_feature: 21, agent_distribution: "otel", agent_version: "2.28.1",
        tls: "TLSv1.3", transport: "getsockopt"
      } and
      ([.cells[] | select(.slice == "kernel-topology-deployment")] | length == 34) and
      ([.cells[] | select(.slice == "jvm-agent")] | length == 7) and
      ([.cells[] | select(.slice == "architecture")] | length == 2) and
      ([.cells[] | select(.slice == "tls")] | length == 2) and
      (all(.cells[] | select(.slice == "kernel-topology-deployment");
        baseline_dimensions)) and
      ([.cells[] | select(.slice == "kernel-topology-deployment") |
        [.kernel, .deployment, .cgroup_topology]] | unique | sort) == ([
          ["rhel-9.6-5.14", "container-process", "unified-v2"],
          ["rhel-9.6-5.14", "host-process", "unified-v2"],
          ["supported-runtime-probed", "container-process", "hybrid-v1-v2"],
          ["supported-runtime-probed", "container-process", "nested-delegated-v2"],
          ["supported-runtime-probed", "container-process", "sibling-containers"],
          ["supported-runtime-probed", "host-process", "hybrid-v1-v2"],
          ["supported-runtime-probed", "host-process", "nested-delegated-v2"],
          ["upstream-5.10", "container-process", "unified-v2"],
          ["upstream-5.10", "host-process", "unified-v2"],
          ["upstream-5.15", "container-process", "unified-v2"],
          ["upstream-5.15", "host-process", "unified-v2"],
          ["upstream-6.1", "container-process", "unified-v2"],
          ["upstream-6.1", "host-process", "unified-v2"],
          ["upstream-6.12", "container-process", "unified-v2"],
          ["upstream-6.12", "host-process", "unified-v2"],
          ["upstream-6.6", "container-process", "unified-v2"],
          ["upstream-6.6", "host-process", "unified-v2"]
        ] | sort) and
      (all([.cells[] | select(.slice == "kernel-topology-deployment") |
        {row: [.kernel, .deployment, .cgroup_topology], transport: .transport}] |
        group_by(.row)[];
        ([.[].transport] | sort) == ["getsockopt", "unix"])) and
      ([.cells[] | select(.slice == "jvm-agent") |
        [.jvm_feature, .agent_distribution, .agent_version]] | sort) == ([
          [8, "otel", "2.28.1"], [8, "splunk", "2.28.0"],
          [11, "otel", "2.28.1"], [11, "splunk", "2.28.0"],
          [17, "otel", "2.28.1"], [17, "splunk", "2.28.0"],
          [21, "splunk", "2.28.0"]
        ] | sort) and
      (all(.cells[] | select(.slice == "jvm-agent");
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .architecture == "amd64" and
        .tls == "TLSv1.3" and .transport == "getsockopt" and
        .profile == "compatibility-smoke")) and
      ([.cells[] | select(.slice == "architecture") | .transport] | sort) ==
        ["getsockopt", "unix"] and
      (all(.cells[] | select(.slice == "architecture");
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .architecture == "arm64" and
        .jvm_feature == 21 and .agent_distribution == "otel" and
        .agent_version == "2.28.1" and .tls == "TLSv1.3" and
        .profile == "compatibility-smoke")) and
      ([.cells[] | select(.slice == "tls") | .transport] | sort) ==
        ["getsockopt", "unix"] and
      (all(.cells[] | select(.slice == "tls");
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .architecture == "amd64" and
        .jvm_feature == 21 and .agent_distribution == "otel" and
        .agent_version == "2.28.1" and .tls == "TLSv1.2" and
        .profile == "compatibility-smoke")) and
      .excluded_dimensions == [
        {
          dimension: "rhel-8-4.18-backport", status: "untested",
          reason: "direct-execution-required-no-version-inference"
        },
        {
          dimension: "http2-backend", status: "unsupported",
          reason: "request-safe-http2-not-proven"
        },
        {
          dimension: "auto-transport", status: "out-of-scope",
          reason: "issue-36-control-not-issue-38-transport-dimension"
        }
      ] and
      (all(.cells[]; .transport == "getsockopt" or .transport == "unix")) and
      (all(.cells[]; (.kernel | test("rhel-8|4[.]18"; "i") | not))) and
      (.excluded_dimensions | any(
        .dimension == "rhel-8-4.18-backport" and .status == "untested" and
        .reason == "direct-execution-required-no-version-inference")) and
      (.excluded_dimensions | any(
        .dimension == "http2-backend" and .status == "unsupported"))
    ' @PLAN@ >/dev/null ||
      compatibility_die "compatibility plan lost its 34+7+2+2 factorization or exclusions"
  else
    compatibility_stable_jq_query \
      @PLAN@ "$plan" "$plan_identity" 67108864 -- jq -e '
      (keys == [
        "campaign_revision", "cells", "expected_cell_count",
        "java_21_only_lifecycle", "required_frameworks", "required_lifecycle",
        "required_repeated_resource_gates", "schema", "unavailable_bridge_contract"
      ]) and
      (all(.cells[]; keys == [
        "agent_distribution", "agent_version", "architecture", "cgroup_topology",
        "deployment", "id", "jvm_feature", "kernel", "provider", "tls",
        "transport"
      ])) and
      (.required_frameworks | sort == [
        "blocking-sslsocket", "netty-sslhandler", "sslengine-socketchannel"
      ]) and
      (.required_repeated_resource_gates | sort == [
        "classloader-weak-reference", "direct-buffer", "live-thread", "native-fd",
        "request-state", "same-process-identity", "task-state", "thread-local-state"
      ]) and
      .unavailable_bridge_contract == {
        max_diagnostic_bytes: 65536,
        max_diagnostic_count: 64
      } and
      (.required_lifecycle | sort == [
        "cross-request-isolation", "cross-thread-handoff", "duplicate-callback",
        "executor-handoff", "extension-absent", "extension-loaded-first",
        "fallback-context-unavailable", "helper-early-attach", "helper-late-attach",
        "normal-extraction", "obi-absent", "obi-restart", "platform-thread",
        "stale-state", "unsupported-transport", "version-mismatch"
      ]) and
      ([.cells[] | [.jvm_feature, .architecture, .transport]] | sort) == ([
        [8, "amd64", "getsockopt"], [11, "amd64", "getsockopt"],
        [17, "amd64", "getsockopt"], [21, "amd64", "getsockopt"],
        [21, "amd64", "unix"], [21, "amd64", "auto"],
        [21, "arm64", "getsockopt"]
      ] | sort) and
      (all(.cells[];
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .agent_distribution == "otel" and
        .agent_version == "2.28.1" and .tls == "TLSv1.3" and
        .provider == "preprovisioned-lifecycle-application-v1")) and
      ([.cells[] | select(.transport == "auto")] | length == 1)
    ' @PLAN@ >/dev/null ||
      compatibility_die "helper lifecycle plan lost a required framework, resource gate, or auto cell"
  fi
  [[ "$(compatibility_stable_file_identity "$provider_registry" 67108864)" == \
      "$provider_registry_identity" &&
    "$(compatibility_stable_file_identity "$executor_registry" 67108864)" == \
      "$executor_registry_identity" &&
    "$(compatibility_stable_file_identity "$plan" 67108864)" == \
      "$plan_identity" &&
    "$(compatibility_stable_file_identity "$expected_ids" 1048576)" == \
      "$expected_ids_identity" ]] ||
    compatibility_die "registry authority changed during plan validation"
)

compatibility_select_cell() {
  local -r campaign="$1"
  local -r cell_id="$2"
  local -r output="$3"
  local plan=""

  [[ "$cell_id" =~ ^[a-z0-9][a-z0-9-]{0,95}$ ]] ||
    compatibility_die "invalid cell ID: $cell_id" || return
  plan="$(compatibility_plan_path "$campaign")" || return
  compatibility_require_regular_file "$plan" || return
  compatibility_validate_json_file "$plan" || return
  [[ ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "cell selection output already exists: $output" || return
  jq -e --arg id "$cell_id" '[.cells[] | select(.id == $id)] | length == 1' \
    "$plan" >/dev/null || compatibility_die "unknown or duplicate cell ID: $cell_id" || return
  jq -S --arg id "$cell_id" '.cells[] | select(.id == $id)' "$plan" >"$output"
  chmod 0600 -- "$output"
}

compatibility_normalize_architecture() {
  local -r architecture="$1"

  case "$architecture" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) printf 'unknown\n' ;;
  esac
}

compatibility_publish_stable_file() {
  local -r source="$1"
  local -r expected_identity="$2"
  local -r target="$3"
  local -r requested_mode="$4"
  local -r test_hook="${5:-}"
  local -r stable_identity_pattern='^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]{64}$'

  [[ "$source" == /* && "$target" == /* &&
    "$expected_identity" =~ $stable_identity_pattern &&
    "$requested_mode" =~ ^0?[0-7]{3}$ ]] || return 2
  python3 - "$source" "$expected_identity" "$target" "$requested_mode" \
    "$test_hook" <<'PY'
import ctypes
import errno
import hashlib
import os
import secrets
import stat
import subprocess
import sys


source, expected_identity, target, requested_mode, test_hook = sys.argv[1:6]
target_mode = int(requested_mode, 8)
parent = os.path.dirname(target)
name = os.path.basename(target)
if not name or name in (".", "..") or "/" in name or "\n" in name:
    raise RuntimeError("unsafe publication target name")


def identity(descriptor):
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("unsafe publication source")
    position = os.lseek(descriptor, 0, os.SEEK_CUR)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, position, os.SEEK_SET)
    after = os.fstat(descriptor)
    fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise RuntimeError("publication source changed while hashing")
    return ":".join(str(value) for value in (
        after.st_dev,
        after.st_ino,
        after.st_uid,
        format(stat.S_IMODE(after.st_mode), "o"),
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        digest.hexdigest(),
    ))


def same(left, right):
    fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def run_test_hook(phase, path):
    if not test_hook:
        return
    if not os.path.isabs(test_hook):
        raise RuntimeError("publication test hook must be absolute")
    hook_state = os.stat(test_hook, follow_symlinks=False)
    if not stat.S_ISREG(hook_state.st_mode) or hook_state.st_uid != os.geteuid():
        raise RuntimeError("publication test hook is unsafe")
    if stat.S_IMODE(hook_state.st_mode) & 0o022 or not os.access(test_hook, os.X_OK):
        raise RuntimeError("publication test hook permissions are unsafe")
    completed = subprocess.run(
        [test_hook, phase, path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if len(completed.stderr) > 65536 or completed.returncode != 0:
        raise RuntimeError("publication test hook failed")


libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    raise RuntimeError("renameat2 is unavailable for no-replace publication")
renameat2.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
)
renameat2.restype = ctypes.c_int


def move_to_quarantine(parent_descriptor, current_name):
    try:
        os.stat(current_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return ""
    for _ in range(128):
        quarantine_name = f".compatibility-rejected.file.{secrets.token_hex(16)}"
        if renameat2(
            parent_descriptor,
            os.fsencode(current_name),
            parent_descriptor,
            os.fsencode(quarantine_name),
            1,
        ) == 0:
            os.stat(quarantine_name, dir_fd=parent_descriptor, follow_symlinks=False)
            return quarantine_name
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            continue
        if error_number == errno.ENOENT:
            return ""
        raise OSError(error_number, os.strerror(error_number))
    raise RuntimeError("could not allocate a publication quarantine name")


source_fd = os.open(
    source,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
parent_fd = os.open(
    parent,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
)
candidate_fd = None
candidate_name = ""
published = False
try:
    if identity(source_fd) != expected_identity:
        raise RuntimeError("publication source identity changed")
    parent_state = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_state.st_mode) or parent_state.st_uid != os.geteuid():
        raise RuntimeError("unsafe publication parent")
    if stat.S_IMODE(parent_state.st_mode) & 0o022:
        raise RuntimeError("publication parent is group/world writable")
    parent_path_state = os.stat(parent, follow_symlinks=False)
    if not all(
        getattr(parent_state, field) == getattr(parent_path_state, field)
        for field in ("st_dev", "st_ino", "st_uid", "st_mode")
    ):
        raise RuntimeError("publication parent path changed")
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(errno.EEXIST, "publication target exists", target)
    for _ in range(128):
        candidate_name = f".compatibility-publish.{secrets.token_hex(16)}"
        try:
            candidate_fd = os.open(
                candidate_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                target_mode,
                dir_fd=parent_fd,
            )
            break
        except FileExistsError:
            continue
    if candidate_fd is None:
        raise RuntimeError("could not allocate a publication candidate")
    os.fchmod(candidate_fd, target_mode)
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        view = memoryview(chunk)
        while view:
            written = os.write(candidate_fd, view)
            if written <= 0:
                raise RuntimeError("short publication write")
            view = view[written:]
    os.fsync(candidate_fd)
    if identity(source_fd) != expected_identity:
        raise RuntimeError("publication source changed while copying")
    candidate_identity = identity(candidate_fd)
    candidate_state = os.fstat(candidate_fd)
    if candidate_identity.rsplit(":", 1)[1] != expected_identity.rsplit(":", 1)[1]:
        raise RuntimeError("publication candidate digest differs from source")
    named_candidate_state = os.stat(
        candidate_name,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )
    if not same(candidate_state, named_candidate_state):
        raise RuntimeError("publication candidate name changed")
    source_path_state = os.stat(source, follow_symlinks=False)
    source_fd_state = os.fstat(source_fd)
    source_fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    if any(
        getattr(source_path_state, field) != getattr(source_fd_state, field)
        for field in source_fields
    ):
        raise RuntimeError("publication source path changed")
    run_test_hook("file-candidate-before-rename", f"{parent}/{candidate_name}")
    named_candidate_state = os.stat(
        candidate_name,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )
    if not same(candidate_state, named_candidate_state) or identity(candidate_fd) != candidate_identity:
        raise RuntimeError("publication candidate changed before rename")
    if renameat2(
        parent_fd,
        candidate_name.encode("utf-8"),
        parent_fd,
        name.encode("utf-8"),
        1,
    ) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), target)
    published = True
    renamed_state = os.fstat(candidate_fd)
    renamed_identity = identity(candidate_fd)
    renamed_path_state = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not same(renamed_state, renamed_path_state):
        raise RuntimeError("published file name differs from its retained candidate")
    run_test_hook("file-after-rename-final-rehash", target)
    final_state = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not same(renamed_state, final_state) or identity(candidate_fd) != renamed_identity:
        raise RuntimeError("published file differs from its retained candidate")
    parent_path_state = os.stat(parent, follow_symlinks=False)
    if not all(
        getattr(parent_state, field) == getattr(parent_path_state, field)
        for field in ("st_dev", "st_ino", "st_uid", "st_mode")
    ):
        raise RuntimeError("publication parent path changed")
    os.fsync(parent_fd)
except BaseException:
    retained = move_to_quarantine(parent_fd, name if published else candidate_name)
    if retained:
        print(
            f"rejected publication retained in quarantine: {parent}/{retained}",
            file=sys.stderr,
        )
    raise
finally:
    if candidate_fd is not None:
        os.close(candidate_fd)
    os.close(source_fd)
    os.close(parent_fd)
PY
}

compatibility_publish_stable_directory() {
  local -r source="$1"
  local -r expected_identity="$2"
  local -r target="$3"
  local -r test_hook="${4:-}"

  [[ "$source" == /* && "$target" == /* &&
    "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]{64}$ ]] ||
    return 2
  compatibility_tree_authority \
    publish "$source" "$expected_identity" "$target" "$test_hook"
}

compatibility_directory_identity() {
  local -r directory="$1"
  local identity=""

  compatibility_require_directory "$directory" || return
  identity="$(stat -c '%d:%i:%u' -- "$directory")" || return
  [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
  printf '%s\n' "$identity"
}

compatibility_temp_cleanup_before_quarantine() {
  :
}

compatibility_remove_owned_temp_directory() {
  local -r directory="$1"
  local -r expected_identity="$2"
  local -r expected_parent="$3"
  local -r expected_prefix="$4"
  local name=""
  local physical_parent=""
  local parent_identity=""

  [[ "$expected_parent" == /* && -d "$expected_parent" && ! -L "$expected_parent" ]] ||
    return 1
  physical_parent="$(cd -- "$expected_parent" && pwd -P)" || return
  [[ "$physical_parent" == "$expected_parent" ]] || return 1
  parent_identity="$(stat -Lc '%d:%i:%u:%f' -- "$expected_parent")" || return
  [[ "$parent_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9a-fA-F]+$ ]] || return 1
  [[ "$directory" == "$expected_parent"/* ]] || return 1
  [[ "${directory%/*}" == "$expected_parent" ]] || return 1
  name="${directory##*/}"
  [[ ${#name} -le 128 && "$name" =~ ^${expected_prefix}[A-Za-z0-9]{6}$ ]] ||
    return 1
  [[ "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
  [[ -e "$directory" || -L "$directory" ]] || return 0
  compatibility_temp_cleanup_before_quarantine \
    "$directory" "$expected_identity" "$expected_parent" "$expected_prefix" ||
    return
  python3 - "$expected_parent" "$name" "$expected_identity" \
    "$parent_identity" <<'PY'
import ctypes
import errno
import os
import secrets
import stat
import sys


parent, name, expected_text, expected_parent_text = sys.argv[1:5]
expected = tuple(int(value) for value in expected_text.split(":"))
if len(expected) != 3:
    raise SystemExit(2)
parent_fields = expected_parent_text.split(":")
if len(parent_fields) != 4:
    raise SystemExit(2)
expected_parent = (
    int(parent_fields[0]),
    int(parent_fields[1]),
    int(parent_fields[2]),
    int(parent_fields[3], 16),
)
if os.path.realpath(parent) != parent:
    raise SystemExit(2)

directory_flag = getattr(os, "O_DIRECTORY", 0)
no_follow_flag = getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open(
    parent,
    os.O_RDONLY | os.O_CLOEXEC | directory_flag | no_follow_flag,
)
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    raise RuntimeError("renameat2 is unavailable for quarantine")
renameat2.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
)
renameat2.restype = ctypes.c_int
rename_noreplace = 1


def identity(value):
    return (value.st_dev, value.st_ino, value.st_uid)


def full_parent_identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode)


def quarantine_entry(directory_fd, entry_name, prefix):
    before = os.stat(entry_name, dir_fd=directory_fd, follow_symlinks=False)
    quarantine_name = ""
    for _ in range(128):
        candidate = f"{prefix}{secrets.token_hex(12)}"
        if renameat2(
            directory_fd,
            os.fsencode(entry_name),
            directory_fd,
            os.fsencode(candidate),
            rename_noreplace,
        ) == 0:
            quarantine_name = candidate
            break
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            continue
        raise OSError(error, os.strerror(error), entry_name)
    if not quarantine_name:
        raise RuntimeError("could not allocate a quarantine name")
    after = os.stat(quarantine_name, dir_fd=directory_fd, follow_symlinks=False)
    if identity(after) != identity(before) or stat.S_IFMT(after.st_mode) != stat.S_IFMT(before.st_mode):
        raise RuntimeError(f"entry changed while entering quarantine: {entry_name}")
    return quarantine_name, after


try:
    parent_state = os.fstat(parent_fd)
    if full_parent_identity(parent_state) != expected_parent:
        raise RuntimeError("cleanup parent identity changed")
    parent_path_state = os.stat(parent, follow_symlinks=False)
    if full_parent_identity(parent_path_state) != expected_parent:
        raise RuntimeError("cleanup parent path no longer names its authority")
    parent_mode = stat.S_IMODE(parent_state.st_mode)
    private_parent = (
        parent_state.st_uid in (0, os.geteuid()) and not parent_mode & 0o022
    )
    sticky_root_parent = (
        parent_state.st_uid == 0
        and bool(parent_mode & stat.S_ISVTX)
        and bool(parent_mode & 0o002)
    )
    if not stat.S_ISDIR(parent_state.st_mode) or not (
        private_parent or sticky_root_parent
    ):
        raise RuntimeError("cleanup parent is not trusted")
    try:
        quarantine_name, quarantined = quarantine_entry(
            parent_fd,
            name,
            f".compatibility-quarantine.{name}.",
        )
    except FileNotFoundError:
        raise SystemExit(0)
    if not stat.S_ISDIR(quarantined.st_mode) or identity(quarantined) != expected:
        print(
            f"refused cleanup; foreign entry retained as {parent}/{quarantine_name}",
            file=sys.stderr,
        )
        raise SystemExit(75)
    try:
        replacement_name, _ = quarantine_entry(
            parent_fd,
            name,
            f".compatibility-quarantine.{name}.late.",
        )
    except FileNotFoundError:
        raise SystemExit(0)
    print(
        f"refused cleanup; late replacement retained as {parent}/{replacement_name}",
        file=sys.stderr,
    )
    raise SystemExit(75)
except OSError as error:
    if error.errno == errno.ENOENT:
        raise SystemExit(0)
    print(f"quarantine cleanup failed: {error}", file=sys.stderr)
    raise SystemExit(77)
except RuntimeError as error:
    print(f"refused cleanup; quarantined bytes preserved: {error}", file=sys.stderr)
    raise SystemExit(76)
finally:
    parent_changed = False
    try:
        final_parent_state = os.stat(parent, follow_symlinks=False)
        if full_parent_identity(final_parent_state) != expected_parent:
            print("cleanup parent changed during quarantine", file=sys.stderr)
            parent_changed = True
    except OSError:
        print("cleanup parent disappeared during quarantine", file=sys.stderr)
        parent_changed = True
    os.close(parent_fd)
    if parent_changed:
        raise SystemExit(78)
PY
}

compatibility_quarantine_entry_to_parent() {
  local -r entry="$1"
  local -r expected_source_parent="$2"
  local -r quarantine_parent="$3"
  local -r label="$4"

  [[ "$entry" == /* && "$expected_source_parent" == /* &&
    "$quarantine_parent" == /* &&
    "$label" =~ ^[a-z0-9][a-z0-9.-]{0,63}$ &&
    "$entry" == "$expected_source_parent"/* &&
    "${entry%/*}" == "$expected_source_parent" ]] || return 2
  python3 - "$entry" "$expected_source_parent" "$quarantine_parent" \
    "$label" <<'PY'
import ctypes
import errno
import os
import secrets
import stat
import sys


entry, source_parent, quarantine_parent, label = sys.argv[1:5]
name = os.path.basename(entry)
directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
source_fd = os.open(source_parent, directory_flags)
quarantine_fd = None
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    raise RuntimeError("renameat2 is unavailable for quarantine")
renameat2.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
)
renameat2.restype = ctypes.c_int


def safe_parent(state):
    mode = stat.S_IMODE(state.st_mode)
    return stat.S_ISDIR(state.st_mode) and (
        (state.st_uid in (0, os.geteuid()) and not mode & 0o022)
        or (state.st_uid == 0 and mode & stat.S_ISVTX and mode & 0o002)
    )


def same_parent(left, right):
    fields = ("st_dev", "st_ino", "st_uid", "st_mode")
    return all(getattr(left, field) == getattr(right, field) for field in fields)


try:
    quarantine_fd = os.open(quarantine_parent, directory_flags)
    source_state = os.fstat(source_fd)
    quarantine_state = os.fstat(quarantine_fd)
    if not safe_parent(source_state) or not safe_parent(quarantine_state):
        raise RuntimeError("quarantine parent authority is unsafe")
    if not same_parent(source_state, os.stat(source_parent, follow_symlinks=False)):
        raise RuntimeError("source quarantine parent path changed")
    if not same_parent(
        quarantine_state,
        os.stat(quarantine_parent, follow_symlinks=False),
    ):
        raise RuntimeError("destination quarantine parent path changed")
    try:
        before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise SystemExit(0)
    for _ in range(128):
        quarantine_name = (
            f".compatibility-quarantine.{label}.{secrets.token_hex(12)}"
        )
        if renameat2(
            source_fd,
            os.fsencode(name),
            quarantine_fd,
            os.fsencode(quarantine_name),
            1,
        ) == 0:
            break
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            continue
        if error_number == errno.ENOENT:
            raise FileNotFoundError(entry)
        raise OSError(error_number, os.strerror(error_number))
    else:
        raise RuntimeError("could not allocate a quarantine entry")
    after = os.stat(
        quarantine_name,
        dir_fd=quarantine_fd,
        follow_symlinks=False,
    )
    if (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) != (
        after.st_dev,
        after.st_ino,
        stat.S_IFMT(after.st_mode),
    ):
        raise RuntimeError("quarantined entry identity changed during rename")
    if not same_parent(source_state, os.stat(source_parent, follow_symlinks=False)):
        raise RuntimeError("source quarantine parent changed during rename")
    if not same_parent(
        quarantine_state,
        os.stat(quarantine_parent, follow_symlinks=False),
    ):
        raise RuntimeError("destination quarantine parent changed during rename")
    print(os.path.join(quarantine_parent, quarantine_name))
finally:
    os.close(source_fd)
    if quarantine_fd is not None:
        os.close(quarantine_fd)
PY
}

compatibility_process_identity() {
  local -r pid="$1"

  [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" -gt 1 ]] || return 2
  python3 - "$pid" <<'PY'
import sys


pid = int(sys.argv[1])
try:
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stream:
        value = stream.read()
except (FileNotFoundError, ProcessLookupError, PermissionError):
    raise SystemExit(1)
close = value.rfind(") ")
if close < 0:
    raise SystemExit(1)
fields = value[close + 2 :].split()
if len(fields) < 20:
    raise SystemExit(1)
try:
    process_group = int(fields[2])
    session = int(fields[3])
    starttime = int(fields[19])
except ValueError:
    raise SystemExit(1)
if min(pid, process_group, session, starttime) <= 0:
    raise SystemExit(1)
print(f"{pid}:{starttime}:{session}:{process_group}")
PY
}

compatibility_signal_process_identity() {
  local -r expected_identity="$1"
  local -r signal_name="$2"

  [[ "$expected_identity" =~ ^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$ ]] ||
    return 2
  [[ "$signal_name" == TERM || "$signal_name" == KILL ||
    "$signal_name" == HUP || "$signal_name" == INT ]] || return 2
  python3 - "$expected_identity" "$signal_name" <<'PY'
import os
import signal
import sys


expected_text, signal_name = sys.argv[1:3]
pid, starttime, session_id, process_group = (
    int(value) for value in expected_text.split(":")
)
requested_signal = getattr(signal, f"SIG{signal_name}")


def identity(observed_pid):
    try:
        with open(f"/proc/{observed_pid}/stat", "r", encoding="ascii") as stream:
            value = stream.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    close = value.rfind(") ")
    if close < 0:
        return None
    fields = value[close + 2 :].split()
    if len(fields) < 20:
        return None
    try:
        return (
            observed_pid,
            int(fields[19]),
            int(fields[3]),
            int(fields[2]),
        )
    except ValueError:
        return None


expected = (pid, starttime, session_id, process_group)
if identity(pid) is None:
    raise SystemExit(0)
if identity(pid) != expected:
    raise SystemExit(75)
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(76)
descriptor = os.pidfd_open(pid, 0)
try:
    if identity(pid) != expected:
        raise SystemExit(75)
    signal.pidfd_send_signal(descriptor, requested_signal)
except ProcessLookupError:
    pass
finally:
    os.close(descriptor)
PY
}

compatibility_wait_process_identity() {
  local -r expected_identity="$1"
  local -r timeout_seconds="$2"

  [[ "$expected_identity" =~ ^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$ &&
    "$timeout_seconds" =~ ^[1-9][0-9]*$ && "$timeout_seconds" -le 86430 ]] ||
    return 2
  python3 - "$expected_identity" "$timeout_seconds" <<'PY'
import os
import select
import signal
import sys


expected_text, timeout_text = sys.argv[1:3]
expected = tuple(int(value) for value in expected_text.split(":"))
pid = expected[0]


def identity(observed_pid):
    try:
        with open(f"/proc/{observed_pid}/stat", "r", encoding="ascii") as stream:
            value = stream.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    close = value.rfind(") ")
    if close < 0:
        return None
    fields = value[close + 2 :].split()
    if len(fields) < 20:
        return None
    try:
        return (
            observed_pid,
            int(fields[19]),
            int(fields[3]),
            int(fields[2]),
        )
    except ValueError:
        return None


observed = identity(pid)
if observed is None:
    raise SystemExit(0)
if observed != expected:
    raise SystemExit(75)
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(76)
descriptor = os.pidfd_open(pid, 0)
try:
    if identity(pid) != expected:
        raise SystemExit(75)
    poller = select.poll()
    poller.register(descriptor, select.POLLIN)
    if not poller.poll(int(timeout_text) * 1000):
        raise SystemExit(124)
finally:
    os.close(descriptor)
PY
}

compatibility_run_bounded_process_group() (
  local -r stdout_file="$1"
  local -r stderr_file="$2"
  local -r file_limit_blocks="$3"
  local -r timeout_seconds="$4"
  shift 4
  local output_parent=""
  local ready_parent=""
  local ready_directory=""
  local ready_directory_identity=""
  local ready_file=""
  local acknowledgement_file=""
  local acknowledgement_descriptor=""
  local supervisor=0
  local supervisor_identity=""
  local observed_supervisor_identity=""
  local leader_identity=""
  local ready_nonce=""
  local wait_status=125
  local cleanup_status=0
  local attempt=0
  local inherited_authority_fds="${OBI_COMPATIBILITY_INHERITED_AUTHORITY_FDS:-}"
  local -a command=("$@")

  [[ ${#command[@]} -gt 0 ]] || return 2
  [[ "$file_limit_blocks" =~ ^[1-9][0-9]*$ ]] || return 2
  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ && "$timeout_seconds" -le 86400 ]] ||
    return 2
  compatibility_require_commands jq mktemp python3 sleep || return
  output_parent="$(dirname -- "$stdout_file")" || return
  compatibility_require_directory "$output_parent" || return
  output_parent="$(cd -- "$output_parent" && pwd -P)" || return
  [[ "$(cd -- "$(dirname -- "$stderr_file")" && pwd -P)" == "$output_parent" ]] ||
    compatibility_die "bounded command outputs must share one safe parent" || return
  [[ ! -e "$stdout_file" && ! -L "$stdout_file" &&
    ! -e "$stderr_file" && ! -L "$stderr_file" ]] ||
    compatibility_die "bounded command output already exists" || return
  ready_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_directory "$ready_parent" || return
  ready_directory="$(mktemp -d \
    "$ready_parent/.compatibility-process-supervisor.XXXXXX")" || return
  ready_directory_identity="$(compatibility_directory_identity "$ready_directory")" ||
    return
  ready_file="$ready_directory/ready.json"
  acknowledgement_file="$ready_directory/acknowledgement"
  : >"$ready_file"
  : >"$acknowledgement_file"
  chmod 0600 -- "$ready_file"
  chmod 0600 -- "$acknowledgement_file"
  exec {acknowledgement_descriptor}<>"$acknowledgement_file" || return

  # shellcheck disable=SC2317 # Invoked indirectly by signal and EXIT traps.
  cleanup_process_supervisor() {
    local status=0
    local wait_identity_status=0

    if (( supervisor > 1 )) && [[ -n "$supervisor_identity" ]]; then
      compatibility_signal_process_identity "$supervisor_identity" TERM || status=$?
      if (( status == 0 )); then
        set +e
        compatibility_wait_process_identity "$supervisor_identity" 5
        wait_identity_status=$?
        set -e
        if (( wait_identity_status == 124 )); then
          compatibility_signal_process_identity \
            "$supervisor_identity" KILL || status=$?
          if (( status == 0 )); then
            set +e
            compatibility_wait_process_identity "$supervisor_identity" 10
            wait_identity_status=$?
            set -e
          fi
        fi
        if (( wait_identity_status == 0 )); then
          wait "$supervisor" 2>/dev/null || true
          supervisor=0
        else
          status="$wait_identity_status"
        fi
      fi
    fi
    if [[ -n "$acknowledgement_descriptor" ]]; then
      exec {acknowledgement_descriptor}>&-
      acknowledgement_descriptor=""
    fi
    if [[ -n "$ready_directory" ]]; then
      compatibility_remove_owned_temp_directory \
        "$ready_directory" "$ready_directory_identity" "$ready_parent" \
        "[.]compatibility-process-supervisor[.]" || status=$?
      ready_directory=""
    fi
    return "$status"
  }
  trap 'cleanup_process_supervisor || true' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  python3 - "$ready_file" "$acknowledgement_file" \
    "$stdout_file" "$stderr_file" \
    "$(( file_limit_blocks * 1024 ))" "$timeout_seconds" \
    "$inherited_authority_fds" -- "${command[@]}" <<'PY' &
import ctypes
import errno
import fcntl
import json
import os
import resource
import secrets
import signal
import stat
import subprocess
import sys
import time


PR_SET_CHILD_SUBREAPER = 36
TERM_GRACE_SECONDS = 5
KILL_GRACE_SECONDS = 10

ready_path, acknowledgement_path, stdout_path, stderr_path = sys.argv[1:5]
file_limit_bytes = int(sys.argv[5])
timeout_seconds = int(sys.argv[6])
authority_text = sys.argv[7]
if sys.argv[8:9] != ["--"]:
    raise SystemExit(125)
command = sys.argv[9:]
if not command or file_limit_bytes <= 0 or timeout_seconds <= 0:
    raise SystemExit(125)
authority_fds = []
if authority_text:
    components = authority_text.split(",")
    if len(components) > 8 or len(components) != len(set(components)):
        raise SystemExit(125)
    for component in components:
        if not component.isdigit() or int(component) < 3:
            raise SystemExit(125)
        descriptor = int(component)
        state = os.fstat(descriptor)
        if not (stat.S_ISDIR(state.st_mode) or stat.S_ISREG(state.st_mode)):
            raise SystemExit(125)
        if state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) & 0o022:
            raise SystemExit(125)
        if fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise SystemExit(125)
        authority_fds.append(descriptor)
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(125)
self_pidfd = os.pidfd_open(os.getpid(), 0)
try:
    signal.pidfd_send_signal(self_pidfd, 0)
finally:
    os.close(self_pidfd)

libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))


def process_identity(pid):
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stream:
            value = stream.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    close = value.rfind(") ")
    if close < 0:
        return None
    fields = value[close + 2 :].split()
    if len(fields) < 20:
        return None
    try:
        return {
            "pid": pid,
            "ppid": int(fields[1]),
            "pgrp": int(fields[2]),
            "session": int(fields[3]),
            "starttime": int(fields[19]),
        }
    except ValueError:
        return None


def identity_text(value):
    return ":".join(str(value[key]) for key in ("pid", "starttime", "session", "pgrp"))


def same_process_authority(left, right):
    return left is not None and right is not None and all(
        left[key] == right[key] for key in ("pid", "starttime")
    )


def same_topology(left, right):
    return left is not None and right is not None and all(
        left[key] == right[key] for key in ("session", "pgrp")
    )


def descendant_identities(root_pid):
    processes = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    for name in names:
        if not name.isdigit():
            continue
        observed = process_identity(int(name))
        if observed is not None:
            processes[observed["pid"]] = observed
    pending = [root_pid]
    seen = {root_pid}
    descendants = []
    while pending:
        parent = pending.pop()
        for observed in processes.values():
            if observed["ppid"] != parent or observed["pid"] in seen:
                continue
            seen.add(observed["pid"])
            descendants.append(observed)
            pending.append(observed["pid"])
    return descendants


tracked = {}
topology_changed = False


def remember_descendants():
    global topology_changed
    for observed in descendant_identities(os.getpid()):
        key = (observed["pid"], observed["starttime"])
        if key in tracked:
            original, _ = tracked[key]
            if not same_topology(observed, original):
                topology_changed = True
            continue
        try:
            descriptor = os.pidfd_open(observed["pid"], 0)
        except ProcessLookupError:
            continue
        current = process_identity(observed["pid"])
        if not same_process_authority(current, observed):
            os.close(descriptor)
            continue
        tracked[key] = (dict(observed), descriptor)


def identity_is_live(observed):
    return same_process_authority(process_identity(observed["pid"]), observed)


def signal_tracked(requested_signal):
    for observed, descriptor in list(tracked.values()):
        if not identity_is_live(observed):
            continue
        try:
            signal.pidfd_send_signal(descriptor, requested_signal)
        except ProcessLookupError:
            pass


def reap_children():
    while True:
        try:
            waited, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if waited == 0:
            return


def live_descendants():
    remember_descendants()
    return [
        observed
        for observed, _ in tracked.values()
        if identity_is_live(observed)
    ]


def terminate_all():
    for requested_signal, grace in (
        (signal.SIGTERM, TERM_GRACE_SECONDS),
        (signal.SIGKILL, KILL_GRACE_SECONDS),
    ):
        deadline = time.monotonic() + grace
        while True:
            current = live_descendants()
            if not current:
                reap_children()
                if not descendant_identities(os.getpid()):
                    return True
            signal_tracked(requested_signal)
            reap_children()
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
    reap_children()
    return not live_descendants() and not descendant_identities(os.getpid())


interrupted_signal = None


def request_shutdown(signum, _frame):
    global interrupted_signal
    interrupted_signal = signum


for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(handled_signal, request_shutdown)

open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
stdout_fd = os.open(stdout_path, open_flags, 0o600)
try:
    stderr_fd = os.open(stderr_path, open_flags, 0o600)
except Exception:
    os.close(stdout_fd)
    raise
try:
    acknowledgement_fd = os.open(
        acknowledgement_path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
except Exception:
    os.close(stdout_fd)
    os.close(stderr_fd)
    raise
acknowledgement_state = os.fstat(acknowledgement_fd)
if not stat.S_ISREG(acknowledgement_state.st_mode) or not (
    acknowledgement_state.st_uid == os.geteuid()
    and stat.S_IMODE(acknowledgement_state.st_mode) == 0o600
    and acknowledgement_state.st_nlink == 1
    and acknowledgement_state.st_size == 0
):
    os.close(stdout_fd)
    os.close(stderr_fd)
    os.close(acknowledgement_fd)
    raise RuntimeError("unsafe process supervisor acknowledgement file")


def limit_output_size():
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit_bytes, file_limit_bytes))


primary = None
primary_status = 125
timed_out = False
cleanup_complete = False
supervisor_failed = False
try:
    primary = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=stdout_fd,
        stderr=stderr_fd,
        close_fds=True,
        pass_fds=tuple(authority_fds),
        start_new_session=True,
        preexec_fn=limit_output_size,
    )
    leader = None
    for _ in range(100):
        leader = process_identity(primary.pid)
        if leader is not None:
            break
        if primary.poll() is not None:
            break
        time.sleep(0.01)
    if leader is None or not (
        leader["pid"] == leader["pgrp"] == leader["session"]
    ):
        raise RuntimeError("command leader lacks an exact session identity")
    remember_descendants()
    leader_key = (leader["pid"], leader["starttime"])
    if leader_key not in tracked:
        raise RuntimeError("command leader could not be pidfd-authenticated")
    supervisor_identity = process_identity(os.getpid())
    if supervisor_identity is None:
        raise RuntimeError("supervisor identity is unavailable")
    ready_nonce = secrets.token_hex(32)
    ready_fd = os.open(ready_path, os.O_WRONLY | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        ready_state = os.fstat(ready_fd)
        if not stat.S_ISREG(ready_state.st_mode) or ready_state.st_uid != os.geteuid():
            raise RuntimeError("unsafe process supervisor ready file")
        payload = json.dumps(
            {
                "leader": identity_text(leader),
                "nonce": ready_nonce,
                "schema": "compatibility-process-supervisor-ready-v1",
                "supervisor": identity_text(supervisor_identity),
            },
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        os.write(ready_fd, payload.encode("ascii"))
        os.fsync(ready_fd)
    finally:
        os.close(ready_fd)
    acknowledgement_deadline = time.monotonic() + 5
    expected_acknowledgement = (ready_nonce + "\n").encode("ascii")
    while True:
        acknowledgement = os.pread(
            acknowledgement_fd,
            len(expected_acknowledgement) + 1,
            0,
        )
        if acknowledgement == expected_acknowledgement:
            break
        if acknowledgement or time.monotonic() >= acknowledgement_deadline:
            raise RuntimeError("invalid or absent process supervisor acknowledgement")
        time.sleep(0.01)
    current_acknowledgement = os.stat(
        acknowledgement_path,
        follow_symlinks=False,
    )
    if any(
        getattr(acknowledgement_state, field) !=
        getattr(current_acknowledgement, field)
        for field in ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink")
    ):
        raise RuntimeError("process supervisor acknowledgement path changed")
    deadline = time.monotonic() + timeout_seconds
    while primary.poll() is None:
        remember_descendants()
        if interrupted_signal is not None:
            break
        if time.monotonic() >= deadline:
            timed_out = True
            break
        time.sleep(0.05)
    if primary.returncode is not None:
        primary_status = primary.returncode
    cleanup_complete = terminate_all()
    if primary.returncode is None:
        try:
            primary.wait(timeout=1)
        except subprocess.TimeoutExpired:
            cleanup_complete = False
        else:
            primary_status = primary.returncode
except BaseException:
    supervisor_failed = True
    if primary is not None:
        try:
            cleanup_complete = terminate_all()
        except BaseException:
            cleanup_complete = False
finally:
    if primary is not None and not cleanup_complete:
        try:
            cleanup_complete = terminate_all()
        except BaseException:
            cleanup_complete = False
    os.close(stdout_fd)
    os.close(stderr_fd)
    os.close(acknowledgement_fd)
    for _, descriptor in tracked.values():
        os.close(descriptor)

if supervisor_failed or not cleanup_complete or topology_changed:
    raise SystemExit(125)
if interrupted_signal is not None:
    raise SystemExit(min(255, 128 + interrupted_signal))
if timed_out:
    raise SystemExit(124)
if primary_status < 0:
    raise SystemExit(min(255, 128 + (-primary_status)))
raise SystemExit(min(255, primary_status))
PY
  supervisor=$!
  for (( attempt = 0; attempt < 100; attempt += 1 )); do
    supervisor_identity="$(compatibility_process_identity "$supervisor" 2>/dev/null || true)"
    [[ -n "$supervisor_identity" ]] && break
    sleep 0.01
  done
  [[ -n "$supervisor_identity" ]] || {
    wait "$supervisor" 2>/dev/null || true
    supervisor=0
    cleanup_process_supervisor || true
    return 125
  }
  for (( attempt = 0; attempt < 200; attempt += 1 )); do
    if [[ -s "$ready_file" ]]; then
      break
    fi
    if ! kill -0 "$supervisor" 2>/dev/null; then
      break
    fi
    sleep 0.01
  done
  if [[ -s "$ready_file" ]]; then
    compatibility_validate_json_file "$ready_file" || {
      cleanup_process_supervisor || true
      return 125
    }
    observed_supervisor_identity="$(jq -er '
      if (keys == ["leader", "nonce", "schema", "supervisor"] and
        .schema == "compatibility-process-supervisor-ready-v1" and
        (.leader | type == "string" and
          test("^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$")) and
        (.supervisor | type == "string" and
          test("^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$")) and
        (.nonce | type == "string" and test("^[0-9a-f]{64}$")))
      then .supervisor
      else empty
      end
    ' "$ready_file")" || {
      cleanup_process_supervisor || true
      return 125
    }
    leader_identity="$(jq -er '.leader' "$ready_file")" || {
      cleanup_process_supervisor || true
      return 125
    }
    ready_nonce="$(jq -er '.nonce' "$ready_file")" || {
      cleanup_process_supervisor || true
      return 125
    }
    IFS=: read -r _ _ observed_leader_session observed_leader_group \
      <<<"$leader_identity"
    [[ "$observed_supervisor_identity" == "$supervisor_identity" &&
      "$(compatibility_process_identity "$supervisor" 2>/dev/null || true)" == \
        "$supervisor_identity" &&
      "${leader_identity%%:*}" == "$observed_leader_session" &&
      "$observed_leader_session" == "$observed_leader_group" ]] || {
      cleanup_process_supervisor || true
      return 125
    }
    printf '%s\n' "$ready_nonce" >&"$acknowledgement_descriptor" || {
      cleanup_process_supervisor || true
      return 125
    }
  else
    set +e
    compatibility_wait_process_identity "$supervisor_identity" 20
    cleanup_status=$?
    if (( cleanup_status == 0 )); then
      wait "$supervisor"
      wait_status=$?
    else
      wait_status=125
    fi
    set -e
    (( cleanup_status == 0 )) && supervisor=0
    cleanup_process_supervisor || return 125
    return "$wait_status"
  fi

  set +e
  compatibility_wait_process_identity \
    "$supervisor_identity" "$(( timeout_seconds + 20 ))"
  cleanup_status=$?
  if (( cleanup_status == 0 )); then
    wait "$supervisor"
    wait_status=$?
  else
    wait_status=125
  fi
  set -e
  (( cleanup_status == 0 )) && supervisor=0
  cleanup_process_supervisor || cleanup_status=$?
  (( cleanup_status == 0 )) || return "$cleanup_status"
  return "$wait_status"
)

compatibility_build_directory_manifest_pass() {
  local -r directory="$1"
  local -r scratch_prefix="$2"
  local -r root_device="$3"
  local files="$scratch_prefix.files"
  local directories="$scratch_prefix.directories"
  local unexpected="$scratch_prefix.unexpected"
  local manifest="$scratch_prefix.manifest"
  local directory_state="$scratch_prefix.directory-state"
  local relative=""
  local path=""
  local metadata=""
  local after_metadata=""
  local device=""
  local owner=""
  local mode=""
  local links=""
  local entry_count=0
  local byte_count=0
  local file_size=0

  find "$directory" -xdev -mindepth 1 \
    \( -type l -o \( ! -type f ! -type d \) \) -print0 >"$unexpected" || return
  if [[ -s "$unexpected" ]]; then
    compatibility_die "private evidence contains a symlink or non-regular entry"
    return 1
  fi
  find "$directory" -xdev -mindepth 1 -type d -print0 |
    LC_ALL=C sort -z >"$directories" || return
  find "$directory" -xdev -mindepth 1 -type f -print0 |
    LC_ALL=C sort -z >"$files" || return
  : >"$directory_state"
  while IFS= read -r -d '' path; do
    relative="${path#"$directory"/}"
    [[ "$relative" != "$path" && "$relative" != /* && "$relative" != *$'\n'* ]] ||
      compatibility_die "unsafe private evidence directory path" || return
    [[ -d "$path" && ! -L "$path" ]] ||
      compatibility_die "private evidence directory changed during traversal" || return
    metadata="$(stat -c '%d:%i:%u:%a:%Y:%Z' -- "$path")" || return
    IFS=: read -r device _ owner mode _ _ <<<"$metadata"
    [[ "$device" == "$root_device" && "$owner" == "$EUID" ]] ||
      compatibility_die "private evidence directory has unsafe device or owner: $path" || return
    (( (8#$mode & 0022) == 0 )) ||
      compatibility_die "private evidence directory is group/world writable: $path" || return
    (( entry_count += 1 ))
    (( entry_count <= COMPATIBILITY_MAX_PRIVATE_FILES )) ||
      compatibility_die "private evidence exceeds the bounded entry limit" || return
    printf '%s  %s\n' "$metadata" "$relative" >>"$directory_state"
  done <"$directories"
  : >"$manifest"
  while IFS= read -r -d '' path; do
    relative="${path#"$directory"/}"
    [[ "$relative" != "$path" && "$relative" != /* && "$relative" != *$'\n'* ]] ||
      compatibility_die "unsafe private evidence path" || return
    [[ -f "$path" && ! -L "$path" ]] ||
      compatibility_die "private evidence file changed during traversal" || return
    metadata="$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$path")" || return
    IFS=: read -r device _ owner mode links file_size _ _ <<<"$metadata"
    [[ "$device" == "$root_device" && "$owner" == "$EUID" && "$links" == 1 ]] ||
      compatibility_die "private evidence has unsafe device, owner, or link count: $path" || return
    (( (8#$mode & 0022) == 0 )) ||
      compatibility_die "private evidence is group/world writable: $path" || return
    [[ "$file_size" =~ ^[0-9]+$ ]] || return 1
    (( entry_count += 1 ))
    (( byte_count += file_size ))
    (( entry_count <= COMPATIBILITY_MAX_PRIVATE_FILES &&
      byte_count <= COMPATIBILITY_MAX_PRIVATE_BYTES )) ||
      compatibility_die "private evidence exceeds the bounded entry or byte limit" || return
    printf '%s  %s\n' "$(compatibility_sha256 "$path")" "$relative" >>"$manifest"
    after_metadata="$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$path")" || return
    [[ "$after_metadata" == "$metadata" ]] ||
      compatibility_die "private evidence changed while hashing: $path" || return
  done <"$files"
}

compatibility_directory_manifest() (
  local -r requested_directory="$1"
  local -r requested_output="$2"

  [[ "$requested_directory" == /* && "$requested_output" == /* ]] || return 2
  compatibility_tree_authority manifest "$requested_directory" "$requested_output"
)
