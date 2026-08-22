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
readonly SOURCE_VERIFIER_MAX_BYTES=1048576
readonly GIT_AUTHORITY_MAX_FILES=10000
readonly GIT_AUTHORITY_MAX_TREES=4000
readonly GIT_AUTHORITY_MAX_MANIFEST_BYTES=4194304
readonly GIT_AUTHORITY_MAX_COMMIT_BYTES=1048576
readonly GIT_AUTHORITY_MAX_TREE_BYTES=1048576
readonly GIT_AUTHORITY_MAX_TREE_TOTAL_BYTES=4194304
readonly GIT_AUTHORITY_MAX_PATH_BYTES=2097152
readonly GIT_AUTHORITY_MAX_PATH_LENGTH=4096
readonly GIT_AUTHORITY_MAX_COMPONENT_LENGTH=255
readonly GIT_AUTHORITY_MAX_PATH_DEPTH=64
readonly GIT_AUTHORITY_MAX_FILE_BYTES=67108864
readonly GIT_AUTHORITY_MAX_SYMLINK_BYTES=4096
readonly GIT_AUTHORITY_MAX_TOTAL_BYTES=268435456
readonly GIT_AUTHORITY_GIT_TIMEOUT_SECONDS=30
readonly GIT_AUTHORITY_TOTAL_TIMEOUT_SECONDS=120
readonly -a GIT_AUTHORITY_OPTIONS=(
  --no-replace-objects
  -c core.fsmonitor=false
  -c core.hooksPath=/dev/null
  -c core.attributesFile=/dev/null
  -c core.bare=false
  -c core.ignoreStat=false
  -c core.trustctime=true
  -c core.checkStat=default
  -c core.untrackedCache=false
  -c core.preloadIndex=false
  -c core.fileMode=true
  -c core.symlinks=true
  -c core.ignoreCase=false
  -c extensions.worktreeConfig=false
  -c index.skipHash=false
  -c index.threads=1
)
readonly CLAIM_V1_VERIFY_SH_SHA256='376907ef806b4fdbdc971dde6d4a6f968476c64b237900d80a80dcd8d83e6f8b'
readonly CLAIM_V2_VERIFY_SH_SHA256='2511f18ed4961eea9f979a6fd8bad9ee973ce768adecaebcf0dea31b9aaa8e7d'
readonly FAULT_VERIFY_SH_SHA256='6f8dabcca0235c585c40c85ffeb978c139eef1a51ba56c40506f61ded58bc027'
readonly CLAIM_V1_WRAPPER_VERIFY_SH_SHA256='a06fa5e279c18c3804857fcb04fec9b7d0aba3ce24dee685a866ef5aab5b94eb'
readonly CLAIM_V2_WRAPPER_VERIFY_SH_SHA256='84af02437538669549f9c4dde0cbe83373762520154305b418ecd785e024197d'
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
CANDIDATE_CLEANUP_ALLOWED=1
OUTPUT_DIRECTORY=''
OUTPUT_PARENT=''
OUTPUT_PARENT_IDENTITY=''
OUTPUT_NAME=''
HEAD_SHA=''
SOURCE_TREE_SHA256=''
AUTHENTICATED_SOURCE_TREE_SHA256=''
WORKFLOW_BLOB_SHA256=''
RUN_ID=''
RUN_ATTEMPT=''
EVIDENCE_ID=''
ACCEPTANCE_ARTIFACT=''
FAULT_ARTIFACT=''
SOURCE_VERIFIER_PATH=''
SOURCE_VERIFIER_SHA256=''

usage() {
  printf '%s\n' \
    "Usage: $SCRIPT_NAME (claims-v1|claims-v2) RUN.json ARTIFACTS.json ACCEPTANCE.zip FAULT.zip ABS_OUTPUT" \
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
  for command in awk bash chmod cmp cp find install jq mktemp mv python3 \
    readlink sha256sum sort stat; do
    command -v "$command" >/dev/null 2>&1 ||
      die "required command is unavailable: $command" || return 1
  done
  [[ -f /usr/bin/python3 && -x /usr/bin/python3 &&
    -f /usr/bin/bash && -x /usr/bin/bash &&
    -f /usr/bin/env && -x /usr/bin/env &&
    -f /usr/bin/git && -x /usr/bin/git &&
    -f /usr/bin/sha256sum && -x /usr/bin/sha256sum &&
    -f /usr/bin/timeout && -x /usr/bin/timeout &&
    "$(stat -Lc '%u:%a' -- /usr/bin/python3)" == 0:* &&
    "$(stat -Lc '%u:%a' -- /usr/bin/bash)" == 0:* &&
    "$(stat -Lc '%u:%a' -- /usr/bin/env)" == 0:* &&
    "$(stat -Lc '%u:%a' -- /usr/bin/git)" == 0:* &&
    "$(stat -Lc '%u:%a' -- /usr/bin/sha256sum)" == 0:* &&
    "$(stat -Lc '%u:%a' -- /usr/bin/timeout)" == 0:* ]] ||
    die 'trusted absolute Bash, env, Git, Python, SHA-256, or timeout runtime is unavailable' ||
    return 1
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

directory_manifest_value() {
  local -r directory="$1"
  shift
  (($# >= 1 && $# <= MAX_MEMBERS)) || return 1
  python3 -I - "$directory" "$MAX_MEMBER_BYTES" "$MAX_EXPANDED_BYTES" \
    "$@" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

ACCEPTANCE_NAMES = (
    "README.md", "SANITIZATION.md", "acceptance-claims.json",
    "authority-summary.json", "derivation-receipt.json", "verify.sh",
    "SHA256SUMS",
)
FAULT_NAMES = (
    "README.md", "SANITIZATION.md", "fault-security-matrix.json",
    "derivation-receipt.json", "verify.sh", "SHA256SUMS",
)

def metadata(value):
    return {
        "ctime_ns": value.st_ctime_ns,
        "dev": value.st_dev,
        "ino": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "mtime_ns": value.st_mtime_ns,
        "nlink": value.st_nlink,
        "uid": value.st_uid,
    }

def main():
    if sys.platform != "linux" or len(sys.argv) < 5:
        raise RuntimeError("Linux descriptor manifests are required")
    path = sys.argv[1]
    maximum_member = int(sys.argv[2])
    maximum_total = int(sys.argv[3])
    expected_names = tuple(sys.argv[4:])
    if (not os.path.isabs(path) or os.path.realpath(path) != path or
            len(set(expected_names)) != len(expected_names) or
            any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
                for name in expected_names)):
        raise ValueError("source manifest arguments are invalid")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open(path, directory_flags)
    try:
        before = os.fstat(directory_fd)
        path_before = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid() or
                (before.st_dev, before.st_ino) !=
                (path_before.st_dev, path_before.st_ino) or
                tuple(sorted(os.listdir(directory_fd))) !=
                tuple(sorted(expected_names))):
            raise ValueError("source directory authority is invalid")
        files = {}
        total = 0
        for name in sorted(expected_names):
            descriptor = os.open(name, file_flags, dir_fd=directory_fd)
            try:
                first = os.fstat(descriptor)
                if (not stat.S_ISREG(first.st_mode) or
                        first.st_uid != os.geteuid() or first.st_nlink != 1 or
                        first.st_size < 1 or first.st_size > maximum_member):
                    raise ValueError("source member metadata is invalid")
                digest = hashlib.sha256()
                offset = 0
                remaining = first.st_size
                while remaining:
                    chunk = os.pread(
                        descriptor, min(remaining, 1024 * 1024), offset)
                    if not chunk:
                        raise ValueError("source member was truncated")
                    digest.update(chunk)
                    offset += len(chunk)
                    remaining -= len(chunk)
                if os.pread(descriptor, 1, first.st_size):
                    raise ValueError("source member grew")
                second = os.fstat(descriptor)
                if metadata(first) != metadata(second) or first.st_size != second.st_size:
                    raise ValueError("source member changed")
                path_value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (path_value.st_dev, path_value.st_ino) != \
                        (first.st_dev, first.st_ino):
                    raise ValueError("source member pathname changed")
                record = metadata(first)
                record["sha256"] = digest.hexdigest()
                record["size"] = first.st_size
                files[name] = record
                total += first.st_size
                if total > maximum_total:
                    raise ValueError("source manifest exceeds its byte bound")
            finally:
                os.close(descriptor)
        after = os.fstat(directory_fd)
        path_after = os.stat(path, follow_symlinks=False)
        if (metadata(before) != metadata(after) or
                (after.st_dev, after.st_ino) !=
                (path_after.st_dev, path_after.st_ino) or
                tuple(sorted(os.listdir(directory_fd))) !=
                tuple(sorted(expected_names))):
            raise ValueError("source directory changed")
        value = {
            "directory": metadata(after),
            "files": files,
            "schema_version": 1,
            "total_size": total,
        }
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if len(rendered) > 65536:
            raise ValueError("source manifest encoding exceeds its byte bound")
        print(rendered)
    finally:
        os.close(directory_fd)

try:
    main()
except (OSError, RuntimeError, ValueError):
    raise SystemExit(1) from None
PY
}

cleanup_owned_directory() {
  local -r path="$1"
  local -r expected_identity="$2"
  [[ -n "$path" && -n "$expected_identity" && -d "$path" &&
    ! -L "$path" && "$(stat -Lc '%d:%i:%u' -- "$path")" == "$expected_identity" ]] ||
    return 1
  case "$path" in
    /tmp/obi-retained-ci-import.*|"$OUTPUT_PARENT"/.retained-ci-import.*)
      ;;
    *)
      return 1
      ;;
  esac
  chmod -R u+rwX -- "$path" >/dev/null 2>&1 || return 1
  find -- "$path" -xdev -depth -delete
}

discard_candidate_after_publication_failure() {
  local cleanup_status=0

  if [[ -n "$CANDIDATE_DIRECTORY" &&
    ( -e "$CANDIDATE_DIRECTORY" || -L "$CANDIDATE_DIRECTORY" ) ]]; then
    cleanup_owned_directory "$CANDIDATE_DIRECTORY" "$CANDIDATE_IDENTITY" ||
      cleanup_status=1
  fi
  # Never retry candidate cleanup after the final publication boundary. A
  # same-UID actor may have replaced the old source leaf with an unknown inode.
  CANDIDATE_DIRECTORY=''
  CANDIDATE_IDENTITY=''
  return "$cleanup_status"
}

cleanup() {
  local original_status="$?"
  local cleanup_status=0
  trap - EXIT
  if ((CANDIDATE_CLEANUP_ALLOWED == 1)) &&
    [[ -n "$CANDIDATE_DIRECTORY" && -e "$CANDIDATE_DIRECTORY" ]]; then
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
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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

# Compare literal HEAD, the index, and tracked filesystem bytes without asking
# Git to convert worktree content. In particular, no status/diff/hash-object
# path can launch a repository-configured fsmonitor or clean-filter command.
validate_literal_worktree_against_head() (
  local -r repository_root="$1"
  local -r expected_head="$2"

  trusted_clean_exec /usr/bin/timeout --signal=KILL 121s \
    /usr/bin/python3 -I - "$repository_root" \
    "$expected_head" "$WORKFLOW_PATH" \
    'examples/apache-java-https/scripts/import-retained-ci-evidence.sh' \
    'examples/apache-java-https/scripts/verify-retained-evidence.sh' \
    "$GIT_AUTHORITY_MAX_FILES" "$GIT_AUTHORITY_MAX_TREES" \
    "$GIT_AUTHORITY_MAX_MANIFEST_BYTES" "$GIT_AUTHORITY_MAX_PATH_BYTES" \
    "$GIT_AUTHORITY_MAX_PATH_LENGTH" \
    "$GIT_AUTHORITY_MAX_COMPONENT_LENGTH" "$GIT_AUTHORITY_MAX_PATH_DEPTH" \
    "$GIT_AUTHORITY_MAX_FILE_BYTES" "$GIT_AUTHORITY_MAX_SYMLINK_BYTES" \
    "$GIT_AUTHORITY_MAX_TOTAL_BYTES" "$GIT_AUTHORITY_MAX_COMMIT_BYTES" \
    "$GIT_AUTHORITY_MAX_TREE_BYTES" "$GIT_AUTHORITY_MAX_TREE_TOTAL_BYTES" \
    "$GIT_AUTHORITY_GIT_TIMEOUT_SECONDS" "$GIT_AUTHORITY_TOTAL_TIMEOUT_SECONDS" \
    "${GIT_AUTHORITY_OPTIONS[@]}" <<'PY'
import functools
import hashlib
import os
import re
import select
import selectors
import stat
import subprocess
import sys
import time

(
    repository_root,
    expected_head,
    workflow_path_text,
    importer_path_text,
    verifier_path_text,
    maximum_files_text,
    maximum_trees_text,
    maximum_manifest_text,
    maximum_path_bytes_text,
    maximum_path_length_text,
    maximum_component_length_text,
    maximum_path_depth_text,
    maximum_file_text,
    maximum_symlink_text,
    maximum_total_text,
    maximum_commit_text,
    maximum_tree_text,
    maximum_tree_total_text,
    git_timeout_text,
    total_timeout_text,
    *git_options,
) = sys.argv[1:]
maximum_files = int(maximum_files_text)
maximum_trees = int(maximum_trees_text)
maximum_manifest = int(maximum_manifest_text)
maximum_path_bytes = int(maximum_path_bytes_text)
maximum_path_length = int(maximum_path_length_text)
maximum_component_length = int(maximum_component_length_text)
maximum_path_depth = int(maximum_path_depth_text)
maximum_file = int(maximum_file_text)
maximum_symlink = int(maximum_symlink_text)
maximum_total = int(maximum_total_text)
maximum_commit = int(maximum_commit_text)
maximum_tree = int(maximum_tree_text)
maximum_tree_total = int(maximum_tree_total_text)
git_timeout = int(git_timeout_text)
total_timeout = int(total_timeout_text)
authority_deadline = time.monotonic() + total_timeout
git_environment = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0",
}


def run_git(maximum_output, *arguments):
    check_deadline()
    process = subprocess.Popen(
        [
            "/usr/bin/git",
            *git_options,
            "-C",
            repository_root,
            f"--work-tree={repository_root}",
            *arguments,
        ],
        env=git_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    poller = selectors.DefaultSelector()
    poller.register(descriptor, selectors.EVENT_READ)
    output = bytearray()
    deadline = min(time.monotonic() + git_timeout, authority_deadline)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("literal Git query timed out")
            if not poller.select(remaining):
                raise TimeoutError("literal Git query timed out")
            chunk = os.read(
                descriptor,
                min(65536, maximum_output + 1 - len(output)),
            )
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum_output:
                raise ValueError("literal Git query exceeded its output bound")
        remaining = max(0.001, deadline - time.monotonic())
        if process.wait(timeout=remaining) != 0:
            raise RuntimeError("literal Git query failed")
        return bytes(output)
    finally:
        poller.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def check_deadline():
    if time.monotonic() >= authority_deadline:
        raise TimeoutError("literal worktree authority timed out")


def git_object_digest(object_type, content):
    digest = hashlib.sha1()
    digest.update(object_type)
    digest.update(b" ")
    digest.update(str(len(content)).encode("ascii"))
    digest.update(b"\0")
    digest.update(content)
    return digest.hexdigest().encode("ascii")


class BatchReader:
    def __init__(self):
        check_deadline()
        self.process = subprocess.Popen(
            [
                "/usr/bin/git",
                *git_options,
                "-C",
                repository_root,
                f"--work-tree={repository_root}",
                "cat-file",
                "--batch",
            ],
            env=git_environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self.input_descriptor = self.process.stdin.fileno()
        self.output_descriptor = self.process.stdout.fileno()
        os.set_blocking(self.input_descriptor, False)
        os.set_blocking(self.output_descriptor, False)
        self.buffer = bytearray()
        self.query_deadline = authority_deadline

    def _remaining(self):
        remaining = min(self.query_deadline, authority_deadline) - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Git object batch query timed out")
        return remaining

    def _write_all(self, value):
        offset = 0
        while offset < len(value):
            check_deadline()
            _, writable, _ = select.select(
                [], [self.input_descriptor], [], self._remaining()
            )
            if not writable:
                raise TimeoutError("Git object batch query timed out")
            written = os.write(self.input_descriptor, value[offset:])
            if written <= 0:
                raise RuntimeError("Git object batch input closed")
            offset += written

    def _fill(self, maximum_read):
        check_deadline()
        readable, _, _ = select.select(
            [self.output_descriptor], [], [], self._remaining()
        )
        if not readable:
            raise TimeoutError("Git object batch query timed out")
        chunk = os.read(self.output_descriptor, maximum_read)
        if not chunk:
            raise RuntimeError("Git object batch output closed")
        self.buffer.extend(chunk)

    def _read_line(self, maximum_length):
        while b"\n" not in self.buffer:
            remaining = maximum_length + 1 - len(self.buffer)
            if remaining <= 0:
                raise ValueError("Git object batch header exceeded its bound")
            self._fill(min(remaining, 4096))
        boundary = self.buffer.index(b"\n")
        if boundary > maximum_length:
            raise ValueError("Git object batch header exceeded its bound")
        result = bytes(self.buffer[:boundary])
        del self.buffer[:boundary + 1]
        return result

    def _read_exact(self, size):
        while len(self.buffer) < size:
            self._fill(min(size - len(self.buffer), 65536))
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def read_object(self, object_id, expected_type, maximum_size):
        if not re.fullmatch(b"[0-9a-f]{40}", object_id):
            raise ValueError("Git object identifier is malformed")
        self.query_deadline = min(
            time.monotonic() + git_timeout, authority_deadline
        )
        self._write_all(object_id + b"\n")
        header = self._read_line(256)
        fields = header.split(b" ")
        if (len(fields) != 3 or fields[0] != object_id or
                fields[1] != expected_type or
                not re.fullmatch(b"0|[1-9][0-9]*", fields[2])):
            raise ValueError("Git object batch header is invalid")
        size = int(fields[2])
        if size > maximum_size:
            raise ValueError("Git object exceeds its byte bound")
        content = self._read_exact(size)
        if self._read_exact(1) != b"\n":
            raise ValueError("Git object batch record is unterminated")
        if git_object_digest(expected_type, content) != object_id:
            raise ValueError("Git object bytes do not match their identifier")
        return content

    def close(self, succeeded):
        try:
            if succeeded:
                if self.buffer:
                    raise ValueError("Git object batch left surplus protocol bytes")
                self.process.stdin.close()
                self.query_deadline = min(
                    time.monotonic() + git_timeout, authority_deadline
                )
                readable, _, _ = select.select(
                    [self.output_descriptor], [], [], self._remaining()
                )
                if not readable or os.read(self.output_descriptor, 1):
                    raise ValueError("Git object batch did not end at clean EOF")
                remaining = max(
                    0.001,
                    min(authority_deadline, time.monotonic() + git_timeout) -
                    time.monotonic(),
                )
                if self.process.wait(timeout=remaining) != 0:
                    raise RuntimeError("Git object batch process failed")
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            if not self.process.stdin.closed:
                self.process.stdin.close()
            self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, _exception, _traceback):
        self.close(exception_type is None)


def parse_commit_tree(content):
    header_end = content.find(b"\n\n")
    if header_end < 0:
        raise ValueError("Git commit object has no header boundary")
    header_lines = content[:header_end].split(b"\n")
    if (not header_lines or
            not re.fullmatch(b"tree [0-9a-f]{40}", header_lines[0]) or
            sum(line.startswith(b"tree ") for line in header_lines) != 1):
        raise ValueError("Git commit object has no unique root tree")
    return header_lines[0][5:]


def parse_tree_object(content):
    entries = []
    names = set()
    offset = 0
    while offset < len(content):
        mode_end = content.find(b" ", offset)
        name_end = content.find(b"\0", mode_end + 1)
        if mode_end <= offset or name_end <= mode_end + 1:
            raise ValueError("Git tree object entry is malformed")
        mode = content[offset:mode_end]
        name = content[mode_end + 1:name_end]
        object_end = name_end + 21
        if object_end > len(content):
            raise ValueError("Git tree object identifier is truncated")
        object_id = content[name_end + 1:object_end].hex().encode("ascii")
        if (mode not in (b"40000", b"100644", b"100755", b"120000") or
                not name or name in (b".", b"..") or b"/" in name or
                len(name) > maximum_component_length or name in names):
            raise ValueError("Git tree object entry is unsafe or unsupported")
        names.add(name)
        entries.append((mode, name, object_id))
        offset = object_end
    if not entries:
        raise ValueError("Git tree object is empty")
    def compare_entries(left, right):
        left_name = left[1]
        right_name = right[1]
        shared = min(len(left_name), len(right_name))
        if left_name[:shared] != right_name[:shared]:
            return -1 if left_name[:shared] < right_name[:shared] else 1
        left_tail = ord("/") if left[0] == b"40000" else 0
        right_tail = ord("/") if right[0] == b"40000" else 0
        if len(left_name) > shared:
            left_tail = left_name[shared]
        if len(right_name) > shared:
            right_tail = right_name[shared]
        return (left_tail > right_tail) - (left_tail < right_tail)
    if entries != sorted(entries, key=functools.cmp_to_key(compare_entries)):
        raise ValueError("Git tree object entries are not canonically ordered")
    return entries


def authenticate_object_graph():
    expected_head_bytes = expected_head.encode("ascii")
    tree_cache = {}
    ordered_leaves = []
    leaves = {}
    path_bytes = 0
    tree_visits = 0
    aggregate_tree_bytes = 0

    with BatchReader() as batch:
        commit_content = batch.read_object(
            expected_head_bytes, b"commit", maximum_commit
        )
        root_tree = parse_commit_tree(commit_content)

        def read_tree(object_id):
            nonlocal aggregate_tree_bytes
            if object_id not in tree_cache:
                if len(tree_cache) >= maximum_trees:
                    raise ValueError("Git object graph exceeds its tree-count bound")
                raw_tree = batch.read_object(object_id, b"tree", maximum_tree)
                aggregate_tree_bytes += len(raw_tree)
                if aggregate_tree_bytes > maximum_tree_total:
                    raise ValueError("Git object graph exceeds its tree-byte bound")
                tree_cache[object_id] = parse_tree_object(raw_tree)
            return tree_cache[object_id]

        def walk_tree(prefix, object_id, depth):
            nonlocal path_bytes, tree_visits
            check_deadline()
            tree_visits += 1
            if tree_visits > maximum_trees or depth > maximum_path_depth:
                raise ValueError("Git object graph exceeds its traversal bound")
            for mode, name, child_id in read_tree(object_id):
                path = name if not prefix else prefix + b"/" + name
                validate_path(path)
                if mode == b"40000":
                    walk_tree(path, child_id, depth + 1)
                    continue
                if path in leaves:
                    raise ValueError("Git object graph duplicates a leaf path")
                path_bytes += len(path)
                if path_bytes > maximum_path_bytes:
                    raise ValueError("Git object graph exceeds its path-byte bound")
                leaves[path] = (mode, child_id)
                ordered_leaves.append((path, mode, child_id))
                if len(leaves) > maximum_files:
                    raise ValueError("Git object graph exceeds its leaf-count bound")

        walk_tree(b"", root_tree, 1)
    if not ordered_leaves:
        raise ValueError("Git object graph has no leaves")
    return leaves, tuple(ordered_leaves)


def format_source_tree_manifest(ordered_leaves):
    formatter_input = bytearray()
    markers = {
        b"100644": b"-",
        b"100755": b"x",
        b"120000": b"l",
    }
    for path, mode, object_id in ordered_leaves:
        formatter_input.extend(object_id)
        formatter_input.extend(b" ")
        formatter_input.extend(markers[mode])
        formatter_input.extend(b" ")
        formatter_input.extend(path)
        formatter_input.extend(b"\0")
    formatter_script = r'''
while IFS= read -r -d '' record; do
  ((${#record} >= 43)) || exit 1
  object_id=${record:0:40}
  [[ ${record:40:1} == ' ' && ${record:42:1} == ' ' ]] || exit 1
  marker=${record:41:1}
  path=${record:43}
  printf '%s %s %q\n' "$object_id" "$marker" "$path" || exit 1
done
exit 0
'''
    process = subprocess.Popen(
        ["/usr/bin/bash", "--noprofile", "--norc", "-c", formatter_script],
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    input_descriptor = process.stdin.fileno()
    output_descriptor = process.stdout.fileno()
    os.set_blocking(input_descriptor, False)
    os.set_blocking(output_descriptor, False)
    poller = selectors.DefaultSelector()
    poller.register(input_descriptor, selectors.EVENT_WRITE, "input")
    poller.register(output_descriptor, selectors.EVENT_READ, "output")
    input_offset = 0
    output = bytearray()
    deadline = min(time.monotonic() + git_timeout, authority_deadline)
    input_open = True
    output_open = True
    try:
        while input_open or output_open:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("source-tree manifest formatter timed out")
            events = poller.select(remaining)
            if not events:
                raise TimeoutError("source-tree manifest formatter timed out")
            for key, _mask in events:
                if key.data == "input":
                    written = os.write(
                        input_descriptor,
                        formatter_input[input_offset:input_offset + 65536],
                    )
                    if written <= 0:
                        raise RuntimeError("source-tree formatter input closed")
                    input_offset += written
                    if input_offset == len(formatter_input):
                        poller.unregister(input_descriptor)
                        process.stdin.close()
                        input_open = False
                else:
                    chunk = os.read(
                        output_descriptor,
                        min(65536, maximum_manifest + 1 - len(output)),
                    )
                    if not chunk:
                        poller.unregister(output_descriptor)
                        process.stdout.close()
                        output_open = False
                        continue
                    output.extend(chunk)
                    if len(output) > maximum_manifest:
                        raise ValueError(
                            "source-tree manifest exceeds its byte bound"
                        )
        remaining = max(0.001, deadline - time.monotonic())
        if process.wait(timeout=remaining) != 0:
            raise RuntimeError("source-tree manifest formatter failed")
        return bytes(output)
    finally:
        poller.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def metadata(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        value.st_ctime_ns,
        value.st_mtime_ns,
    )


def parse_index(data):
    if not data or not data.endswith(b"\0"):
        raise ValueError("Git index is empty or unterminated")
    result = {}
    path_bytes = 0
    for record in data[:-1].split(b"\0"):
        fields, separator, path = record.partition(b"\t")
        parts = fields.split(b" ")
        if (separator != b"\t" or len(parts) != 3 or not path or
                path in result):
            raise ValueError("Git index entry is malformed")
        mode, object_id, stage = parts
        if (mode not in (b"100644", b"100755", b"120000") or
                not re.fullmatch(b"[0-9a-f]{40}", object_id) or stage != b"0"):
            raise ValueError("Git index entry is unsupported")
        validate_path(path)
        path_bytes += len(path)
        if path_bytes > maximum_path_bytes:
            raise ValueError("Git index paths exceed their byte bound")
        result[path] = (mode, object_id)
        if len(result) > maximum_files:
            raise ValueError("Git index exceeds its file-count bound")
    return result


def parse_flags(data):
    if not data or not data.endswith(b"\0"):
        raise ValueError("Git index flags are empty or unterminated")
    result = {}
    path_bytes = 0
    for record in data[:-1].split(b"\0"):
        if len(record) < 3 or record[1:2] != b" ":
            raise ValueError("Git index flags are malformed")
        flag = record[0:1]
        path = record[2:]
        validate_path(path)
        path_bytes += len(path)
        if path_bytes > maximum_path_bytes:
            raise ValueError("Git index-flag paths exceed their byte bound")
        if path in result or flag == b"S" or b"a" <= flag <= b"z":
            raise ValueError("Git index hides or duplicates a tracked path")
        result[path] = flag
        if len(result) > maximum_files:
            raise ValueError("Git index flags exceed the file-count bound")
    return result


def validate_path(path):
    components = path.split(b"/")
    if (path.startswith(b"/") or len(path) > maximum_path_length or
            len(components) > maximum_path_depth or any(
                component in (b"", b".", b"..") or
                len(component) > maximum_component_length
                for component in components)):
        raise ValueError("Git path is unsafe")


def open_parent(root_descriptor, path):
    check_deadline()
    components = path.split(b"/")
    descriptor = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            check_deadline()
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, components[-1]
    except BaseException:
        os.close(descriptor)
        raise


def lstat_path(root_descriptor, path):
    parent, leaf = open_parent(root_descriptor, path)
    try:
        return os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    finally:
        os.close(parent)


def git_blob_sha1(content_length, content):
    digest = hashlib.sha1()
    digest.update(f"blob {content_length}\0".encode("ascii"))
    digest.update(content)
    return digest.hexdigest().encode("ascii")


def verify_regular(root_descriptor, path, expected_mode, expected_object):
    check_deadline()
    parent, leaf = open_parent(root_descriptor, path)
    descriptor = -1
    try:
        descriptor = os.open(
            leaf,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        first = os.fstat(descriptor)
        if not stat.S_ISREG(first.st_mode):
            raise ValueError("tracked regular path changed type")
        if first.st_size > maximum_file:
            raise ValueError("tracked regular path exceeds its byte bound")
        executable = bool(stat.S_IMODE(first.st_mode) & 0o111)
        if executable != (expected_mode == b"100755"):
            raise ValueError("tracked regular path changed executable mode")
        digest = hashlib.sha1()
        digest.update(f"blob {first.st_size}\0".encode("ascii"))
        sha256_digest = hashlib.sha256()
        offset = 0
        remaining = first.st_size
        while remaining:
            check_deadline()
            chunk = os.pread(descriptor, min(remaining, 1024 * 1024), offset)
            if not chunk:
                raise ValueError("tracked regular path was truncated")
            digest.update(chunk)
            sha256_digest.update(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        if os.pread(descriptor, 1, first.st_size):
            raise ValueError("tracked regular path grew")
        second = os.fstat(descriptor)
        if metadata(first) != metadata(second):
            raise ValueError("tracked regular path changed while hashed")
        if digest.hexdigest().encode("ascii") != expected_object:
            raise ValueError("tracked regular bytes differ from literal HEAD")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
    observed_path = lstat_path(root_descriptor, path)
    if metadata(observed_path) != metadata(first):
        raise ValueError("tracked regular pathname changed while hashed")
    return (
        first.st_size,
        metadata(first),
        expected_mode,
        expected_object,
        sha256_digest.hexdigest(),
    )


def verify_symlink(root_descriptor, path, expected_object):
    check_deadline()
    first = lstat_path(root_descriptor, path)
    if not stat.S_ISLNK(first.st_mode):
        raise ValueError("tracked symbolic link changed type")
    parent, leaf = open_parent(root_descriptor, path)
    try:
        target = os.readlink(leaf, dir_fd=parent)
    finally:
        os.close(parent)
    if isinstance(target, str):
        target = os.fsencode(target)
    if len(target) > maximum_symlink:
        raise ValueError("tracked symbolic link exceeds its byte bound")
    second = lstat_path(root_descriptor, path)
    if (metadata(first) != metadata(second) or
            git_blob_sha1(len(target), target) != expected_object):
        raise ValueError("tracked symbolic link differs from literal HEAD")
    return (
        len(target),
        metadata(first),
        b"120000",
        expected_object,
        hashlib.sha256(target).hexdigest(),
    )


repository_root_bytes = os.fsencode(repository_root)
if (sys.platform != "linux" or not os.path.isabs(repository_root) or
        os.path.realpath(repository_root) != repository_root or
        b"\n" in repository_root_bytes or b"\0" in repository_root_bytes or
        not re.fullmatch(r"[0-9a-f]{40}", expected_head) or
        not 1 <= maximum_files <= 10000 or
        not 1 <= maximum_trees <= 4000 or
        not 1 <= maximum_manifest <= 4194304 or
        not 1 <= maximum_path_bytes <= 2097152 or
        not 1 <= maximum_path_length <= 4096 or
        not 1 <= maximum_component_length <= 255 or
        not 1 <= maximum_path_depth <= 64 or
        not 1 <= maximum_symlink <= 4096 or
        not maximum_symlink <= maximum_file <= 67108864 or
        not maximum_file <= maximum_total <= 268435456 or
        not 1 <= maximum_commit <= 1048576 or
        not 1 <= maximum_tree <= 1048576 or
        not maximum_tree <= maximum_tree_total <= 4194304 or
        not 1 <= git_timeout <= 30 or not 1 <= total_timeout <= 120):
    raise ValueError("literal worktree authority arguments are invalid")

authority_paths = (
    (os.fsencode(workflow_path_text), b"100644"),
    (os.fsencode(importer_path_text), b"100755"),
    (os.fsencode(verifier_path_text), b"100755"),
)
if len({path for path, _mode in authority_paths}) != len(authority_paths):
    raise ValueError("literal source-authority paths are not unique")
for authority_path, _authority_mode in authority_paths:
    validate_path(authority_path)

root_descriptor = os.open(
    os.fsencode(repository_root),
    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
)
index_descriptor = -1
result_fields = None
try:
    root_before = os.fstat(root_descriptor)
    root_path_before = os.stat(repository_root, follow_symlinks=False)
    if (not stat.S_ISDIR(root_before.st_mode) or
            metadata(root_before) != metadata(root_path_before)):
        raise ValueError("worktree root descriptor identity is invalid")
    if run_git(64, "rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("literal worktree authority requires SHA-1 Git objects")
    if run_git(
            maximum_path_length + 1, "rev-parse", "--show-toplevel"
        ) != repository_root_bytes + b"\n":
        raise ValueError("Git worktree root differs from physical authority")
    if (run_git(
            64, "rev-parse", "--verify", "HEAD^{commit}"
        ).strip() != expected_head.encode("ascii")):
        raise ValueError("checkout HEAD changed before authority validation")
    index_path = os.fsdecode(
        run_git(4096, "rev-parse", "--git-path", "index").strip()
    )
    if not os.path.isabs(index_path):
        index_path = os.path.join(repository_root, index_path)
    if os.path.realpath(index_path) != index_path:
        raise ValueError("Git index path is not physical")
    index_descriptor = os.open(
        index_path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    index_before = os.fstat(index_descriptor)
    index_path_before = os.stat(index_path, follow_symlinks=False)
    if (not stat.S_ISREG(index_before.st_mode) or
            not 1 <= index_before.st_size <= 16777216 or
            metadata(index_before) != metadata(index_path_before)):
        raise ValueError("Git index descriptor identity is invalid")

    head_entries, head_ordered = authenticate_object_graph()
    head_manifest = format_source_tree_manifest(head_ordered)
    index_manifest = run_git(maximum_manifest, "ls-files", "--stage", "-z")
    flag_manifest = run_git(maximum_manifest, "ls-files", "-v", "-z")
    index_entries = parse_index(index_manifest)
    index_flags = parse_flags(flag_manifest)
    if head_entries != index_entries:
        raise ValueError("Git index differs from literal HEAD")
    if set(index_flags) != set(head_entries):
        raise ValueError("Git index flags do not cover literal HEAD exactly")
    if run_git(1, "ls-files", "--others", "--exclude-standard", "-z"):
        raise ValueError("worktree has untracked non-ignored paths")

    receipts = {}
    total_bytes = 0
    for path, (mode, object_id) in head_entries.items():
        check_deadline()
        if mode in (b"100644", b"100755"):
            receipt = verify_regular(
                root_descriptor, path, mode, object_id
            )
        else:
            receipt = verify_symlink(root_descriptor, path, object_id)
        receipts[path] = receipt
        total_bytes += receipt[0]
        if total_bytes > maximum_total:
            raise ValueError("tracked worktree exceeds its total byte bound")

    def replay_authority_state():
        check_deadline()
        replay_entries, replay_ordered = authenticate_object_graph()
        replay_manifest = format_source_tree_manifest(replay_ordered)
        if run_git(
                maximum_path_length + 1, "rev-parse", "--show-toplevel"
            ) != repository_root_bytes + b"\n":
            raise ValueError("Git worktree root changed during authority replay")
        if (run_git(
                64, "rev-parse", "--verify", "HEAD^{commit}"
            ).strip() != expected_head.encode("ascii") or
                replay_entries != head_entries or
                replay_ordered != head_ordered or
                replay_manifest != head_manifest or
                run_git(maximum_manifest, "ls-files", "--stage", "-z") !=
                index_manifest or
                run_git(maximum_manifest, "ls-files", "-v", "-z") !=
                flag_manifest or
                run_git(
                    1,
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                )):
            raise ValueError(
                "literal HEAD, index, or worktree roster changed"
            )

    replay_authority_state()
    second_total = 0
    for path, (mode, object_id) in head_entries.items():
        check_deadline()
        if mode in (b"100644", b"100755"):
            second_receipt = verify_regular(
                root_descriptor, path, mode, object_id
            )
        else:
            second_receipt = verify_symlink(
                root_descriptor, path, object_id
            )
        if second_receipt != receipts[path]:
            raise ValueError("tracked leaf changed between authority sweeps")
        second_total += second_receipt[0]
        if second_total > maximum_total:
            raise ValueError("final tracked sweep exceeds its byte bound")
    if second_total != total_bytes:
        raise ValueError("tracked byte total changed between authority sweeps")
    replay_authority_state()

    index_after = os.fstat(index_descriptor)
    index_path_after = os.stat(index_path, follow_symlinks=False)
    root_after = os.fstat(root_descriptor)
    root_path_after = os.stat(repository_root, follow_symlinks=False)
    if (metadata(index_before) != metadata(index_after) or
            metadata(index_before) != metadata(index_path_after)):
        raise ValueError("Git index changed during authority validation")
    if (metadata(root_before) != metadata(root_after) or
            metadata(root_before) != metadata(root_path_after)):
        raise ValueError("worktree root changed during authority validation")
    authority_sha256 = []
    for authority_path, authority_mode in authority_paths:
        if (head_entries.get(authority_path) !=
                (authority_mode, receipts[authority_path][3])):
            raise ValueError("literal source-authority mode is invalid")
        authority_sha256.append(receipts[authority_path][4])
    result_fields = (
        hashlib.sha256(head_manifest).hexdigest(),
        *authority_sha256,
    )
    check_deadline()
finally:
    if index_descriptor >= 0:
        os.close(index_descriptor)
    os.close(root_descriptor)
if result_fields is None or any(
        not re.fullmatch(r"[0-9a-f]{64}", value) for value in result_fields):
    raise ValueError("literal source-authority receipt is invalid")
sys.stdout.write(" ".join(result_fields) + "\n")
PY
)

source_authority_final_checkpoint() {
  :
}

source_authority_validator_return_checkpoint() {
  :
}

validate_source_authority() {
  local -r verifier_path='examples/apache-java-https/scripts/verify-retained-evidence.sh'
  local authority_receipt=''
  local authenticated_tree_sha256=''
  local workflow_sha256=''
  local importer_sha256=''
  local verifier_sha256=''
  local receipt_extra=''

  assert_no_git_replacement_authority "$REPOSITORY_ROOT" || return 1
  HEAD_SHA="$(trusted_literal_git -C "$REPOSITORY_ROOT" rev-parse \
    --verify 'HEAD^{commit}')" ||
    return 1
  [[ "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || return 1
  authority_receipt="$(validate_literal_worktree_against_head \
    "$REPOSITORY_ROOT" "$HEAD_SHA")" || return 1
  source_authority_validator_return_checkpoint || return 1
  read -r authenticated_tree_sha256 workflow_sha256 importer_sha256 \
    verifier_sha256 receipt_extra <<<"$authority_receipt"
  [[ -z "$receipt_extra" ]] || return 1
  is_sha256 "$authenticated_tree_sha256" || return 1
  is_sha256 "$workflow_sha256" || return 1
  is_sha256 "$importer_sha256" || return 1
  is_sha256 "$verifier_sha256" || return 1
  AUTHENTICATED_SOURCE_TREE_SHA256="$authenticated_tree_sha256"
  WORKFLOW_BLOB_SHA256="$workflow_sha256"
  SOURCE_VERIFIER_PATH="$REPOSITORY_ROOT/$verifier_path"
  SOURCE_VERIFIER_SHA256="$verifier_sha256"
  source_authority_final_checkpoint || return 1
  [[ "$(trusted_literal_git -C "$REPOSITORY_ROOT" rev-parse \
    --verify 'HEAD^{commit}')" == "$HEAD_SHA" ]] || return 1
  assert_no_git_replacement_authority "$REPOSITORY_ROOT"
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

bundle_publication_checkpoint() {
  :
}

bundle_publication_complete_checkpoint() {
  :
}

bundle_publication_before_validation_checkpoint() {
  :
}

bundle_publication_before_seal_checkpoint() {
  :
}

bundle_publication_validation_checkpoint() {
  :
}

bundle_publication_reconciliation_checkpoint() {
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
  is_sha256 "$AUTHENTICATED_SOURCE_TREE_SHA256" || return 1
  printf '%s\n' "$AUTHENTICATED_SOURCE_TREE_SHA256"
}

source_verifier_execution_checkpoint() {
  :
}

# Reexec the running Bash through its retained executable descriptor, then
# start an absolute command with an empty environment. POSIX mode makes `exec`
# a special builtin before same-shell or imported functions; the randomized
# descriptor spelling also cannot equal a predeclared slash-name function.
# The clean shell proves the retained descriptor is its own executable, closes
# it, and crosses one more special-builtin `exec -c` boundary. This helper is
# called only from the isolated trusted-verifier subshell and never returns on
# success.
trusted_clean_exec() (
  POSIXLY_CORRECT=1
  [[ -o posix ]] && {
    trap - EXIT HUP INT TERM ERR DEBUG RETURN QUIT ALRM
    unset -n OBI_TRUSTED_BOOTSTRAP_FD OBI_TRUSTED_BOOTSTRAP_PATH \
      OBI_TRUSTED_BOOTSTRAP_INDEX OBI_TRUSTED_BOOTSTRAP_PID 2>/dev/null ||
      return 1
    unset -v OBI_TRUSTED_BOOTSTRAP_FD OBI_TRUSTED_BOOTSTRAP_PATH \
      OBI_TRUSTED_BOOTSTRAP_INDEX OBI_TRUSTED_BOOTSTRAP_PID 2>/dev/null ||
      return 1
    OBI_TRUSTED_BOOTSTRAP_FD=''
    OBI_TRUSTED_BOOTSTRAP_PATH=/proc
    OBI_TRUSTED_BOOTSTRAP_INDEX=0
    OBI_TRUSTED_BOOTSTRAP_PID="$BASHPID"
    [[ -z "$OBI_TRUSTED_BOOTSTRAP_FD" &&
      "$OBI_TRUSTED_BOOTSTRAP_PATH" == /proc &&
      "$OBI_TRUSTED_BOOTSTRAP_INDEX" == 0 &&
      "$OBI_TRUSTED_BOOTSTRAP_PID" == "$BASHPID" ]] || return 1
    (($# > 0)) || return 1
    {
    for ((OBI_TRUSTED_BOOTSTRAP_INDEX = 0;
      OBI_TRUSTED_BOOTSTRAP_INDEX < 96;
      OBI_TRUSTED_BOOTSTRAP_INDEX++)); do
      if ((RANDOM & 1)); then
        OBI_TRUSTED_BOOTSTRAP_PATH+=/.
      else
        OBI_TRUSTED_BOOTSTRAP_PATH+=//
      fi
    done
    OBI_TRUSTED_BOOTSTRAP_PATH+="/$OBI_TRUSTED_BOOTSTRAP_PID/fd/$OBI_TRUSTED_BOOTSTRAP_FD"
    [[ "$OBI_TRUSTED_BOOTSTRAP_FD" =~ ^[1-9][0-9]*$ &&
      "$OBI_TRUSTED_BOOTSTRAP_PATH" == /* &&
      -e "/proc/$OBI_TRUSTED_BOOTSTRAP_PID/fd/$OBI_TRUSTED_BOOTSTRAP_FD" &&
      "/proc/$OBI_TRUSTED_BOOTSTRAP_PID/exe" -ef \
        "/proc/$OBI_TRUSTED_BOOTSTRAP_PID/fd/$OBI_TRUSTED_BOOTSTRAP_FD" ]] ||
      return 1
    exec -c "$OBI_TRUSTED_BOOTSTRAP_PATH" --noprofile --norc --posix -c '
      expected_pid=$1
      bootstrap_fd=$2
      shift 2
      [[ -o posix && "$BASHPID" == "$expected_pid" &&
        "$bootstrap_fd" =~ ^[1-9][0-9]*$ &&
        /proc/self/exe -ef "/proc/self/fd/$bootstrap_fd" ]] || exit 1
      exec {bootstrap_fd}<&-
      exec -c "$@"
    ' retained-source-clean-bootstrap "$OBI_TRUSTED_BOOTSTRAP_PID" \
      "$OBI_TRUSTED_BOOTSTRAP_FD" "$@"
    } {OBI_TRUSTED_BOOTSTRAP_FD}<"/proc/$OBI_TRUSTED_BOOTSTRAP_PID/exe"
  }
)

# Run every source-authority Git query with caller state removed and Git's
# replacement machinery disabled twice: once through the environment contract
# and once through Git's own global option. Replacement-ref absence is a policy
# check, not the safety boundary; literal object lookup remains safe if the
# namespace changes after it is enumerated. Eight outer calls at six seconds
# plus the graph supervisor's 121-second deadline bound one validation to
# 169 seconds even if a config or ref path is replaced by a blocking FIFO.
trusted_literal_git() (
  trusted_clean_exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C \
    GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
    /usr/bin/timeout --foreground --kill-after=1s 5s \
    /usr/bin/git "${GIT_AUTHORITY_OPTIONS[@]}" "$@"
)

assert_clean_local_git_config() {
  local -r repository_root="$1"

  trusted_literal_git -C "$repository_root" config --local --no-includes \
    --null --list |
    trusted_clean_exec /usr/bin/python3 -I -c '
import re
import sys

maximum = 1048576
data = sys.stdin.buffer.read(maximum + 1)
if len(data) > maximum or (data and not data.endswith(b"\0")):
    raise ValueError("local Git config exceeds its authority bound")
records = data[:-1].split(b"\0") if data else []
for record in records:
    key, separator, value = record.partition(b"\n")
    if not separator or not key:
        raise ValueError("local Git config record is malformed")
    folded = key.lower()
    if (folded.startswith((b"include.", b"includeif.", b"filter.")) or
            folded in (
                b"core.fsmonitor",
                b"core.attributesfile",
                b"core.worktree",
                b"core.usereplacerefs",
                b"extensions.worktreeconfig",
                b"extensions.partialclone",
            ) or
            re.fullmatch(
                rb"remote\..+\.(promisor|partialclonefilter)", folded
            ) or
            (folded == b"core.bare" and value.lower() != b"false")):
        raise ValueError("local Git config changes source authority")
' "$repository_root"
}

assert_no_git_replacement_authority() {
  local -r repository_root="$1"
  local replacement_refs=''
  local shallow_state=''

  assert_clean_local_git_config "$repository_root" || return 1
  replacement_refs="$(trusted_literal_git -C "$repository_root" \
    for-each-ref --count=1 --format='%(refname)' refs/replace/)" || return 1
  [[ -z "$replacement_refs" || ${#replacement_refs} -le 4096 ]] || return 1
  [[ -z "$replacement_refs" ]] || return 1
  shallow_state="$(trusted_literal_git -C "$repository_root" rev-parse \
    --is-shallow-repository)" || return 1
  [[ "$shallow_state" == false ]]
}

trusted_retained_verifier() (
  [[ "$SOURCE_VERIFIER_PATH" == /* ]] || return 1
  is_sha256 "$SOURCE_VERIFIER_SHA256" || return 1
  # Test-only mutation hooks run outside this launcher's shell state. Their
  # pathname/descriptor effects remain observable, but traps, options,
  # functions, and variable attributes cannot persist into the clean bootstrap.
  (source_verifier_execution_checkpoint "$@") || return 1
  # The clean bootstrap gives trusted absolute Python no caller environment.
  # Python opens the canonical source without blocking, rechecks and seals its
  # bytes, then replaces itself with Bash. A 600-second outer timeout supervises
  # the complete Python-to-hidden-verifier process group. Bash runs under an
  # explicit six-variable environment. Thus no BASH_ENV, exported
  # function, loader/Python state, or Git selector crosses either boundary.
  trusted_clean_exec /usr/bin/timeout --signal=KILL 600s \
    /usr/bin/python3 -I - "$SOURCE_VERIFIER_PATH" \
    "$SOURCE_VERIFIER_SHA256" "$SOURCE_VERIFIER_MAX_BYTES" \
    "$SCRIPT_DIRECTORY" "$REPOSITORY_ROOT" "$HEAD_SHA" "$@" <<'PY'
import fcntl
import hashlib
import os
import re
import stat
import sys

(
    source_path,
    expected_sha256,
    maximum_text,
    script_directory,
    repository_root,
    expected_head,
    *verifier_arguments,
) = sys.argv[1:]

maximum = int(maximum_text)
if (not os.path.isabs(source_path) or os.path.realpath(source_path) != source_path or
        not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or
        not 1 <= maximum <= 1048576):
    raise ValueError("source-verifier authority arguments are invalid")


def metadata(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_ctime_ns,
        value.st_mtime_ns,
    )

source_fd = os.open(
    source_path,
    os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
)
try:
    source_before = os.fstat(source_fd)
    if (not stat.S_ISREG(source_before.st_mode) or
            source_before.st_size < 1 or source_before.st_size > maximum or
            source_before.st_nlink < 1 or
            not stat.S_IMODE(source_before.st_mode) & 0o111):
        raise ValueError("source-verifier descriptor is not an executable regular file")
    source_bytes = bytearray()
    offset = 0
    while len(source_bytes) <= maximum:
        block = os.pread(
            source_fd,
            min(65536, maximum + 1 - len(source_bytes)),
            offset,
        )
        if not block:
            break
        source_bytes.extend(block)
        offset += len(block)
    source_after = os.fstat(source_fd)
    if (len(source_bytes) != source_before.st_size or
            metadata(source_before) != metadata(source_after) or
            hashlib.sha256(source_bytes).hexdigest() != expected_sha256):
        raise ValueError("source-verifier bytes changed before sealing")
finally:
    os.close(source_fd)

required_memfd_flags = getattr(os, "MFD_ALLOW_SEALING", None)
if required_memfd_flags is None or not hasattr(os, "memfd_create"):
    raise RuntimeError("sealed memfd source execution is unavailable")
memfd = os.memfd_create("obi-retained-source-verifier", required_memfd_flags)
try:
    os.fchmod(memfd, 0o500)
    written = 0
    while written < len(source_bytes):
        count = os.write(memfd, source_bytes[written:])
        if count <= 0:
            raise OSError("short write while sealing source verifier")
        written += count
    os.fsync(memfd)
    os.lseek(memfd, 0, os.SEEK_SET)
    required_seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    fcntl.fcntl(memfd, fcntl.F_ADD_SEALS, required_seals)
    if fcntl.fcntl(memfd, fcntl.F_GET_SEALS) != required_seals:
        raise RuntimeError("source-verifier memfd did not acquire the exact seals")
    sealed_stat = os.fstat(memfd)
    if (not stat.S_ISREG(sealed_stat.st_mode) or
            sealed_stat.st_uid != os.geteuid() or
            stat.S_IMODE(sealed_stat.st_mode) != 0o500 or
            sealed_stat.st_nlink != 0 or
            sealed_stat.st_size != len(source_bytes)):
        raise RuntimeError("source-verifier memfd identity changed before execution")
    sealed_bytes = bytearray()
    sealed_offset = 0
    while len(sealed_bytes) <= maximum:
        block = os.pread(
            memfd,
            min(65536, maximum + 1 - len(sealed_bytes)),
            sealed_offset,
        )
        if not block:
            break
        sealed_bytes.extend(block)
        sealed_offset += len(block)
    final_stat = os.fstat(memfd)
    if (len(sealed_bytes) != sealed_stat.st_size or
            bytes(sealed_bytes) != bytes(source_bytes) or
            hashlib.sha256(sealed_bytes).hexdigest() != expected_sha256 or
            (sealed_stat.st_dev, sealed_stat.st_ino, sealed_stat.st_uid,
             sealed_stat.st_mode, sealed_stat.st_nlink, sealed_stat.st_size,
             sealed_stat.st_ctime_ns, sealed_stat.st_mtime_ns) !=
            (final_stat.st_dev, final_stat.st_ino, final_stat.st_uid,
             final_stat.st_mode, final_stat.st_nlink, final_stat.st_size,
             final_stat.st_ctime_ns, final_stat.st_mtime_ns) or
            fcntl.fcntl(memfd, fcntl.F_GET_SEALS) != required_seals):
        raise RuntimeError("source-verifier sealed bytes changed before execution")
    for descriptor_name in os.listdir("/proc/self/fd"):
        inherited_fd = int(descriptor_name)
        if inherited_fd not in (0, 1, 2, memfd):
            try:
                os.set_inheritable(inherited_fd, False)
            except OSError:
                pass
    os.set_inheritable(memfd, True)
    held_source_path = f"/proc/{os.getpid()}/fd/{memfd}"
    arguments = [
        "bash",
        held_source_path,
        "--internal-held-source",
        script_directory,
        repository_root,
        expected_head,
        expected_sha256,
        *verifier_arguments,
    ]
    os.execve(
        "/usr/bin/bash",
        arguments,
        {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        },
    )
finally:
    os.close(memfd)
PY
)

authenticate_nested_verifiers() (
  local -a verifiers=("$1" "$3")
  local -a expected_sha256=("$2" "$4")
  local -a verifier_fds=()
  local -a descriptors=()
  local -a path_identities=()
  local -a descriptor_identities=()
  local acceptance_fd=''
  local fault_fd=''
  local observed_identity=''
  local observed_physical=''
  local observed_sha256=''
  local -i index=0

  for index in 0 1; do
    is_sha256 "${expected_sha256[$index]}" || return 1
    safe_owned_regular "${verifiers[$index]}" "$MAX_MEMBER_BYTES" || return 1
  done
  exec {acceptance_fd}<"${verifiers[0]}" || return 1
  exec {fault_fd}<"${verifiers[1]}" || return 1
  verifier_fds=("$acceptance_fd" "$fault_fd")
  descriptors=(
    "/proc/$BASHPID/fd/${verifier_fds[0]}"
    "/proc/$BASHPID/fd/${verifier_fds[1]}"
  )

  for index in 0 1; do
    path_identities[$index]="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
      -- "${verifiers[$index]}")" || return 1
    descriptor_identities[$index]="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
      -- "${descriptors[$index]}")" || return 1
    observed_physical="$(readlink -f -- "${verifiers[$index]}")" || return 1
    [[ "${path_identities[$index]}" == "${descriptor_identities[$index]}" &&
      -f "${verifiers[$index]}" && ! -L "${verifiers[$index]}" &&
      "$observed_physical" == "${verifiers[$index]}" ]] || return 1
    observed_sha256="$(sha256sum <"${descriptors[$index]}")" || return 1
    [[ "${observed_sha256%% *}" == "${expected_sha256[$index]}" ]] ||
      return 1
  done

  for index in 0 1; do
    observed_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
      -- "${verifiers[$index]}")" || return 1
    [[ "$observed_identity" == "${path_identities[$index]}" ]] || return 1
    observed_identity="$(stat -Lc '%d:%i:%u:%a:%h:%s' \
      -- "${descriptors[$index]}")" || return 1
    observed_physical="$(readlink -f -- "${verifiers[$index]}")" || return 1
    [[ "$observed_identity" == "${descriptor_identities[$index]}" &&
      -f "${verifiers[$index]}" && ! -L "${verifiers[$index]}" &&
      "$observed_physical" == "${verifiers[$index]}" ]] || return 1
    observed_sha256="$(sha256sum <"${descriptors[$index]}")" || return 1
    [[ "${observed_sha256%% *}" == "${expected_sha256[$index]}" ]] ||
      return 1
  done
)

verify_nested_bundles() {
  local -r acceptance="$1"
  local -r fault="$2"
  local -r claims_version="${3:-1}"
  local claims_verifier_mode=''
  local acceptance_verifier_sha256=''

  case "$claims_version" in
    1)
      claims_verifier_mode='--claims-v1'
      acceptance_verifier_sha256="$CLAIM_V1_VERIFY_SH_SHA256"
      ;;
    2)
      claims_verifier_mode='--claims-v2'
      acceptance_verifier_sha256="$CLAIM_V2_VERIFY_SH_SHA256"
      ;;
    *) return 1 ;;
  esac
  trusted_retained_verifier \
    "$claims_verifier_mode" "$acceptance" >/dev/null || return 1
  trusted_retained_verifier \
    --fault-security-matrix-v1 "$fault" >/dev/null || return 1
  # The trusted verifier is the sole nested-script execution authority: it
  # descriptor-snapshots the bundle, authenticates these same pins, and runs
  # only its private canonical snapshot. This independent pair authentication
  # binds the importer's version route without reopening an artifact for Bash.
  authenticate_nested_verifiers \
    "$acceptance/verify.sh" "$acceptance_verifier_sha256" \
    "$fault/verify.sh" "$FAULT_VERIFY_SH_SHA256" || return 1
  exact_inventory "$acceptance" "${ACCEPTANCE_FILES[@]}" || return 1
  exact_inventory "$fault" "${FAULT_FILES[@]}" || return 1
  canonical_json "$acceptance/acceptance-claims.json" || return 1
  canonical_json "$acceptance/authority-summary.json" || return 1
  canonical_json "$acceptance/derivation-receipt.json" || return 1
  canonical_json "$fault/fault-security-matrix.json" || return 1
  canonical_json "$fault/derivation-receipt.json" || return 1
  SOURCE_TREE_SHA256="$(jq -er '.source.tree_sha256' \
    "$acceptance/authority-summary.json")" || return 1
  [[ "$SOURCE_TREE_SHA256" == "$(compute_source_tree_sha256)" ]] || return 1
  jq -e --argjson claims_version "$claims_version" '
    .status == "passed" and .issue_32 and .issue_34 and
    (if $claims_version == 2 then .issue_36.status == "passed"
     else has("issue_36") | not end)
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

write_portable_verifier_v2() {
  local -r output="$1"
  cat >"$output" <<'VERIFY_V2'
#!/usr/bin/env bash
set -Eeuo pipefail
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'SHA256SUMS\tf\nacceptance\td\nclaim-index.json\tf\nfault-security\td\nrun-identity.json\tf\nverify.sh\tf'
observed="$(find -H "$root" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' | LC_ALL=C sort)"
[[ "$observed" == "$expected" ]]
expected_checksum_paths=$'run-identity.json\nclaim-index.json\nverify.sh\nacceptance/README.md\nacceptance/SANITIZATION.md\nacceptance/acceptance-claims.json\nacceptance/authority-summary.json\nacceptance/derivation-receipt.json\nacceptance/verify.sh\nacceptance/SHA256SUMS\nfault-security/README.md\nfault-security/SANITIZATION.md\nfault-security/fault-security-matrix.json\nfault-security/derivation-receipt.json\nfault-security/verify.sh\nfault-security/SHA256SUMS'
observed_checksum_paths=''
checksum_path=''
while IFS= read -r line; do
  [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]]
  checksum_path="${BASH_REMATCH[2]}"
  [[ "$checksum_path" != SHA256SUMS && "$checksum_path" != /* &&
    "$checksum_path" != *..* ]]
  if [[ -n "$observed_checksum_paths" ]]; then
    observed_checksum_paths+=$'\n'
  fi
  observed_checksum_paths+="$checksum_path"
done <"$root/SHA256SUMS"
[[ "$(awk 'END {print NR + 0}' "$root/SHA256SUMS")" == 16 ]]
[[ "$observed_checksum_paths" == "$expected_checksum_paths" ]]
(CDPATH='' cd -- "$root" && sha256sum --check --strict SHA256SUMS >/dev/null)
expected_acceptance_verifier_sha256='2511f18ed4961eea9f979a6fd8bad9ee973ce768adecaebcf0dea31b9aaa8e7d'
expected_fault_security_verifier_sha256='6f8dabcca0235c585c40c85ffeb978c139eef1a51ba56c40506f61ded58bc027'
acceptance_verifier_sha256="$(sha256sum <"$root/acceptance/verify.sh")"
acceptance_verifier_sha256="${acceptance_verifier_sha256%% *}"
fault_security_verifier_sha256="$(sha256sum <"$root/fault-security/verify.sh")"
fault_security_verifier_sha256="${fault_security_verifier_sha256%% *}"
[[ "$acceptance_verifier_sha256" == "$expected_acceptance_verifier_sha256" ]]
[[ "$fault_security_verifier_sha256" == "$expected_fault_security_verifier_sha256" ]]
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
  .schema == "obi-retained-ci-claim-index-v2" and .status == "passed" and
  (.evidence_id | test("^[0-9a-f]{64}$")) and
  .source == {revision:$identity[0].head_sha,tree_sha256:$identity[0].source_tree_sha256} and
  .coverage == {
    issue_32:{pointer:"acceptance/acceptance-claims.json#/issue_32",status:"passed"},
    issue_34:{pointer:"acceptance/acceptance-claims.json#/issue_34",status:"passed"},
    issue_36:{pointers:["acceptance/acceptance-claims.json#/issue_36",
      "fault-security/fault-security-matrix.json#/coverage/issue_36"],status:"passed"},
    issue_40:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40",status:"passed"}}
' "$root/claim-index.json" >/dev/null
head_sha="$(jq -er '.head_sha' "$root/run-identity.json")"
source_tree="$(jq -er '.source_tree_sha256' "$root/run-identity.json")"
jq -e --arg head "$head_sha" --arg tree "$source_tree" '
  .source.revision == $head and .source.tree_sha256 == $tree and
  .execution_locator.head_sha == $head
' "$root/acceptance/authority-summary.json" >/dev/null
jq -e '
  .schema == "obi-bounded-acceptance-claims-v2" and .status == "passed" and
  .issue_32 and .issue_34 and .issue_36.status == "passed"
' "$root/acceptance/acceptance-claims.json" >/dev/null
jq -e --arg head "$head_sha" --arg tree "$source_tree" '
  .schema == "obi-bounded-fault-security-matrix-v1" and .status == "passed" and
  .source.revision == $head and .source.source_tree_sha256 == $tree and
  .coverage.issue_36.status == "passed" and .coverage.issue_40.status == "passed"
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
VERIFY_V2
  chmod 0444 -- "$output"
}

bundle_publication_native_ack_checkpoint() {
  :
}

capture_candidate_publication_seal() {
  local -r candidate_fd="$1"

  [[ "$candidate_fd" =~ ^[1-9][0-9]*$ ]] || return 1
  python3 -I - "$candidate_fd" "$MAX_MEMBER_BYTES" \
    "$((MAX_EXPANDED_BYTES * 2 + MAX_MEMBER_BYTES * 4))" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

EXPECTED_DIRECTORIES = {
    ".": (
        "SHA256SUMS", "acceptance", "claim-index.json", "fault-security",
        "run-identity.json", "verify.sh",
    ),
    "acceptance": (
        "README.md", "SANITIZATION.md", "SHA256SUMS",
        "acceptance-claims.json", "authority-summary.json",
        "derivation-receipt.json", "verify.sh",
    ),
    "fault-security": (
        "README.md", "SANITIZATION.md", "SHA256SUMS",
        "derivation-receipt.json", "fault-security-matrix.json", "verify.sh",
    ),
}
EXPECTED_CHECKSUM_FILES = (
    "run-identity.json", "claim-index.json", "verify.sh",
    "acceptance/README.md", "acceptance/SANITIZATION.md",
    "acceptance/acceptance-claims.json",
    "acceptance/authority-summary.json",
    "acceptance/derivation-receipt.json", "acceptance/verify.sh",
    "acceptance/SHA256SUMS", "fault-security/README.md",
    "fault-security/SANITIZATION.md",
    "fault-security/fault-security-matrix.json",
    "fault-security/derivation-receipt.json", "fault-security/verify.sh",
    "fault-security/SHA256SUMS",
)
EXPECTED_FILES = tuple(sorted(("SHA256SUMS",) + EXPECTED_CHECKSUM_FILES))

def stable_regular_image(parent_fd, name, maximum):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or
                stat.S_IMODE(before.st_mode) != 0o444 or
                before.st_uid != os.geteuid() or before.st_nlink != 1 or
                before.st_size < 1 or before.st_size > maximum):
            raise ValueError("published member metadata is invalid")
        chunks = []
        offset = 0
        remaining = before.st_size
        while remaining:
            chunk = os.pread(descriptor, min(remaining, 1024 * 1024), offset)
            if not chunk:
                raise ValueError("published member was truncated")
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        if os.pread(descriptor, 1, before.st_size):
            raise ValueError("published member grew during capture")
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink",
            "st_size", "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field)
               for field in stable_fields):
            raise ValueError("published member changed during capture")
        path_value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (path_value.st_dev, path_value.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("published member pathname changed")
        data = b"".join(chunks)
        return ({
            "ctime_ns": before.st_ctime_ns,
            "dev": before.st_dev,
            "ino": before.st_ino,
            "mtime_ns": before.st_mtime_ns,
            "mode": stat.S_IMODE(before.st_mode),
            "nlink": before.st_nlink,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": before.st_size,
            "uid": before.st_uid,
        }, data)
    finally:
        os.close(descriptor)

def directory_record(descriptor, expected_mode):
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode) or
            stat.S_IMODE(value.st_mode) != expected_mode or
            value.st_uid != os.geteuid()):
        raise ValueError("published directory metadata is invalid")
    return {
        "ctime_ns": value.st_ctime_ns,
        "dev": value.st_dev,
        "ino": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "mtime_ns": value.st_mtime_ns,
        "nlink": value.st_nlink,
        "uid": value.st_uid,
    }

def main():
    if sys.platform != "linux" or len(sys.argv) != 4:
        raise RuntimeError("Linux descriptor publication is required")
    root_fd = int(sys.argv[1])
    maximum_member = int(sys.argv[2])
    maximum_total = int(sys.argv[3])
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_flags):
        raise RuntimeError("required Linux open flags are unavailable")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fds = {".": os.dup(root_fd)}
    try:
        directory_fds["acceptance"] = os.open(
            "acceptance", directory_flags, dir_fd=root_fd)
        directory_fds["fault-security"] = os.open(
            "fault-security", directory_flags, dir_fd=root_fd)
        directories = {}
        for path in sorted(EXPECTED_DIRECTORIES):
            descriptor = directory_fds[path]
            if tuple(sorted(os.listdir(descriptor))) != EXPECTED_DIRECTORIES[path]:
                raise ValueError("published directory roster is not exact")
            directories[path] = directory_record(descriptor, 0o555)
        files = {}
        total = 0
        checksum_image = b""
        for path in EXPECTED_FILES:
            parent_path, separator, name = path.rpartition("/")
            if not separator:
                parent_path, name = ".", path
            record, data = stable_regular_image(
                directory_fds[parent_path], name, maximum_member)
            if path == "SHA256SUMS":
                checksum_image = data
            total += record["size"]
            if total > maximum_total:
                raise ValueError("published bundle exceeds its byte bound")
            files[path] = record
        if tuple(sorted(path for path in files if path != "SHA256SUMS")) != \
                tuple(sorted(EXPECTED_CHECKSUM_FILES)):
            raise ValueError("published checksum roster is not exact")
        try:
            checksum_lines = checksum_image.decode("ascii").splitlines(keepends=True)
        except UnicodeDecodeError as error:
            raise ValueError("published checksum manifest is not ASCII") from error
        if (len(checksum_lines) != len(EXPECTED_CHECKSUM_FILES) or
                any(not line.endswith("\n") for line in checksum_lines)):
            raise ValueError("published checksum manifest framing is invalid")
        for line, path in zip(checksum_lines, EXPECTED_CHECKSUM_FILES):
            match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\n", line)
            if (match is None or match.group(2) != path or
                    match.group(1) != files[path]["sha256"]):
                raise ValueError("published checksum manifest is not exact")
        value = {
            "directories": directories,
            "files": files,
            "schema_version": 1,
            "total_size": total,
        }
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if len(rendered) > 65536:
            raise ValueError("published seal exceeds its byte bound")
        print(rendered)
    finally:
        for descriptor in directory_fds.values():
            os.close(descriptor)

try:
    main()
except (OSError, RuntimeError, ValueError):
    raise SystemExit(1) from None
PY
}

validate_candidate_publication_semantics() {
  local -r candidate_fd="$1"
  local -r claims_version="$2"
  local -r acceptance_source_manifest="$3"
  local -r fault_source_manifest="$4"
  local expected_acceptance_verifier=''
  local expected_wrapper_verifier=''
  local acceptance_manifest_fd=''
  local fault_manifest_fd=''
  local acceptance_artifact_fd=''
  local fault_artifact_fd=''
  local status=0

  case "$claims_version" in
    1)
      expected_acceptance_verifier="$CLAIM_V1_VERIFY_SH_SHA256"
      expected_wrapper_verifier="$CLAIM_V1_WRAPPER_VERIFY_SH_SHA256"
      ;;
    2)
      expected_acceptance_verifier="$CLAIM_V2_VERIFY_SH_SHA256"
      expected_wrapper_verifier="$CLAIM_V2_WRAPPER_VERIFY_SH_SHA256"
      ;;
    *) return 1 ;;
  esac
  [[ "$candidate_fd" =~ ^[1-9][0-9]*$ &&
    -n "$acceptance_source_manifest" &&
    ${#acceptance_source_manifest} -le 65536 &&
    -n "$fault_source_manifest" && ${#fault_source_manifest} -le 65536 &&
    -n "$ACCEPTANCE_ARTIFACT" && ${#ACCEPTANCE_ARTIFACT} -le MAX_API_BYTES &&
    -n "$FAULT_ARTIFACT" && ${#FAULT_ARTIFACT} -le MAX_API_BYTES &&
    "$WORKFLOW_BLOB_SHA256" =~ ^[0-9a-f]{64}$ ]] || return 1
  exec {acceptance_manifest_fd}<<<"$acceptance_source_manifest" || return 1
  exec {fault_manifest_fd}<<<"$fault_source_manifest" || return 1
  exec {acceptance_artifact_fd}<<<"$ACCEPTANCE_ARTIFACT" || return 1
  exec {fault_artifact_fd}<<<"$FAULT_ARTIFACT" || return 1

  python3 -I - "$candidate_fd" "$claims_version" "$OUTPUT_NAME" \
    "$HEAD_SHA" "$SOURCE_TREE_SHA256" "$RUN_ID" "$RUN_ATTEMPT" \
    "$expected_wrapper_verifier" "$expected_acceptance_verifier" \
    "$FAULT_VERIFY_SH_SHA256" "$WORKFLOW_BLOB_SHA256" "$MAX_MEMBER_BYTES" \
    "$acceptance_manifest_fd" "$fault_manifest_fd" \
    "$acceptance_artifact_fd" "$fault_artifact_fd" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

ACCEPTANCE_NAMES = (
    "README.md", "SANITIZATION.md", "acceptance-claims.json",
    "authority-summary.json", "derivation-receipt.json", "verify.sh",
    "SHA256SUMS",
)
FAULT_NAMES = (
    "README.md", "SANITIZATION.md", "fault-security-matrix.json",
    "derivation-receipt.json", "verify.sh", "SHA256SUMS",
)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def read_regular(parent_fd, name, maximum):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or
                stat.S_IMODE(before.st_mode) != 0o444 or
                before.st_uid != os.geteuid() or before.st_nlink != 1 or
                before.st_size < 1 or before.st_size > maximum):
            raise ValueError("candidate member metadata is invalid")
        data = b""
        offset = 0
        while len(data) < before.st_size:
            chunk = os.pread(
                descriptor, min(before.st_size - len(data), 1024 * 1024), offset)
            if not chunk:
                raise ValueError("candidate member was truncated")
            data += chunk
            offset += len(chunk)
        if os.pread(descriptor, 1, before.st_size):
            raise ValueError("candidate member grew during validation")
        after = os.fstat(descriptor)
        fields = (
            "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
            "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError("candidate member changed during validation")
        path_value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (path_value.st_dev, path_value.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("candidate member pathname changed")
        return data
    finally:
        os.close(descriptor)

def reject_constant(_value):
    raise ValueError("non-finite JSON number")

def parse_json(data):
    if b"\0" in data:
        raise ValueError("candidate JSON contains NUL")
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=unique_object,
            parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("candidate JSON is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("candidate JSON is not an object")
    return value

def json_image(parent_fd, name, maximum):
    data = read_regular(parent_fd, name, maximum)
    return parse_json(data), data

def framed_json(descriptor, maximum):
    with os.fdopen(os.dup(descriptor), "rb") as source:
        data = source.read(maximum + 2)
    if not data or len(data) > maximum + 1 or not data.endswith(b"\n"):
        raise ValueError("held JSON framing is invalid")
    data = data[:-1]
    if not data or len(data) > maximum:
        raise ValueError("held JSON size is invalid")
    return parse_json(data)

def canonical_json(data, value):
    expected = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if data != expected:
        raise ValueError("candidate JSON is not canonical")

def validate_source_manifest(value, expected_names):
    if (set(value) != {"directory", "files", "schema_version", "total_size"} or
            value.get("schema_version") != 1 or
            not isinstance(value.get("directory"), dict) or
            not isinstance(value.get("files"), dict) or
            tuple(sorted(value["files"])) != tuple(sorted(expected_names)) or
            not isinstance(value.get("total_size"), int)):
        raise ValueError("held source manifest is invalid")
    total = 0
    for name in expected_names:
        record = value["files"].get(name)
        if (not isinstance(record, dict) or
                set(record) != {"ctime_ns", "dev", "ino", "mode", "mtime_ns",
                                "nlink", "sha256", "size", "uid"} or
                not isinstance(record.get("size"), int) or record["size"] < 1 or
                not isinstance(record.get("sha256"), str) or
                re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None):
            raise ValueError("held source member record is invalid")
        total += record["size"]
    if total != value["total_size"]:
        raise ValueError("held source manifest total is invalid")

def exact_source_images(parent_fd, manifest, names, maximum):
    images = {}
    for name in names:
        data = read_regular(parent_fd, name, maximum)
        record = manifest["files"][name]
        if len(data) != record["size"] or exact_sha(data) != record["sha256"]:
            raise ValueError("candidate member differs from trusted source")
        images[name] = data
    return images

def exact_sha(data):
    return hashlib.sha256(data).hexdigest()

def passed_pointer(pointer):
    return {"pointer": pointer, "status": "passed"}

def expected_artifact(role, value):
    if (not isinstance(value, dict) or not isinstance(value.get("workflow_run"), dict) or
            not isinstance(value.get("id"), int) or
            not isinstance(value.get("size_in_bytes"), int)):
        raise ValueError("held artifact identity is invalid")
    return {
        "digest": value.get("digest"),
        "expired": value.get("expired"),
        "expires_at": value.get("expires_at"),
        "head_branch": value["workflow_run"].get("head_branch"),
        "head_sha": value["workflow_run"].get("head_sha"),
        "id": str(value["id"]),
        "name": value.get("name"),
        "role": role,
        "run_id": str(value["workflow_run"].get("id")),
        "size_in_bytes": value["size_in_bytes"],
    }

def main():
    if sys.platform != "linux" or len(sys.argv) != 17:
        raise RuntimeError("Linux descriptor validation is required")
    root_fd = int(sys.argv[1])
    claims_version = int(sys.argv[2])
    output_name, head, source_tree, run_id, run_attempt = sys.argv[3:8]
    wrapper_pin, acceptance_pin, fault_pin, workflow_blob = sys.argv[8:12]
    maximum = int(sys.argv[12])
    acceptance_manifest_fd = int(sys.argv[13])
    fault_manifest_fd = int(sys.argv[14])
    acceptance_artifact_fd = int(sys.argv[15])
    fault_artifact_fd = int(sys.argv[16])
    if claims_version not in (1, 2):
        raise ValueError("claims version is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("head revision is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", source_tree):
        raise ValueError("source tree digest is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", workflow_blob):
        raise ValueError("workflow blob digest is invalid")
    acceptance_manifest = framed_json(acceptance_manifest_fd, 65536)
    fault_manifest = framed_json(fault_manifest_fd, 65536)
    acceptance_artifact = framed_json(acceptance_artifact_fd, 2097152)
    fault_artifact = framed_json(fault_artifact_fd, 2097152)
    validate_source_manifest(acceptance_manifest, ACCEPTANCE_NAMES)
    validate_source_manifest(fault_manifest, FAULT_NAMES)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    acceptance_fd = os.open("acceptance", directory_flags, dir_fd=root_fd)
    fault_fd = os.open("fault-security", directory_flags, dir_fd=root_fd)
    try:
        run, run_image = json_image(root_fd, "run-identity.json", maximum)
        index, index_image = json_image(root_fd, "claim-index.json", maximum)
        acceptance_images = exact_source_images(
            acceptance_fd, acceptance_manifest, ACCEPTANCE_NAMES, maximum)
        fault_images = exact_source_images(
            fault_fd, fault_manifest, FAULT_NAMES, maximum)
        acceptance = parse_json(acceptance_images["acceptance-claims.json"])
        authority = parse_json(acceptance_images["authority-summary.json"])
        fault = parse_json(fault_images["fault-security-matrix.json"])
        acceptance_receipt = acceptance_images["derivation-receipt.json"]
        fault_receipt = fault_images["derivation-receipt.json"]
        wrapper_verifier = read_regular(root_fd, "verify.sh", maximum)
        acceptance_verifier = acceptance_images["verify.sh"]
        fault_verifier = fault_images["verify.sh"]
    finally:
        os.close(acceptance_fd)
        os.close(fault_fd)

    if (exact_sha(wrapper_verifier) != wrapper_pin or
            exact_sha(acceptance_verifier) != acceptance_pin or
            exact_sha(fault_verifier) != fault_pin):
        raise ValueError("candidate verifier pin is invalid")
    canonical_json(run_image, run)
    canonical_json(index_image, index)
    evidence = hashlib.sha256((
        f"{head}\n{run_id}\n{run_attempt}\n"
        f"{exact_sha(acceptance_receipt)}\n{exact_sha(fault_receipt)}\n"
    ).encode("ascii")).hexdigest()
    if output_name != f"retained-claims-{head[:12]}-{evidence[:12]}":
        raise ValueError("candidate output identity is invalid")
    expected_source = {"revision": head, "tree_sha256": source_tree}
    expected_workflow = {
        "blob_sha256": workflow_blob,
        "name": "Java remote-parent bounded acceptance claims",
        "path": ".github/workflows/java_remote_parent_acceptance_claims.yml",
        "ref": (
            "MrAlias/opentelemetry-ebpf-instrumentation/"
            ".github/workflows/java_remote_parent_acceptance_claims.yml@"
            "refs/heads/agent/java-remote-parent-bridge"
        ),
        "sha": head,
    }
    expected_artifacts = [
        expected_artifact("acceptance", acceptance_artifact),
        expected_artifact("fault-security", fault_artifact),
    ]
    run_keys = {
        "artifacts", "conclusion", "event", "head_sha", "ref", "repository",
        "run_attempt", "run_id", "run_url", "schema", "source_tree_sha256",
        "status", "workflow",
    }
    if (set(run) != run_keys or
            run.get("schema") != "obi-retained-ci-run-identity-v1" or
            run.get("status") != "passed" or
            run.get("repository") != "MrAlias/opentelemetry-ebpf-instrumentation" or
            run.get("event") != "push" or
            run.get("ref") != "refs/heads/agent/java-remote-parent-bridge" or
            run.get("head_sha") != head or
            run.get("source_tree_sha256") != source_tree or
            run.get("run_id") != run_id or run.get("run_attempt") != run_attempt or
            re.fullmatch(r"[1-9][0-9]{0,18}", run_id) is None or
            re.fullmatch(r"[1-9][0-9]{0,18}", run_attempt) is None or
            run.get("conclusion") != "success" or
            run.get("run_url") != (
                "https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/"
                f"actions/runs/{run_id}/attempts/{run_attempt}") or
            run.get("workflow") != expected_workflow or
            run.get("artifacts") != expected_artifacts):
        raise ValueError("candidate run identity is invalid")
    if (set(index) != {"coverage", "evidence_id", "schema", "source", "status"} or
            index.get("schema") != f"obi-retained-ci-claim-index-v{claims_version}" or
            index.get("status") != "passed" or index.get("evidence_id") != evidence or
            index.get("source") != expected_source):
        raise ValueError("candidate claim index is invalid")
    expected_coverage = {
        "issue_32": passed_pointer(
            "acceptance/acceptance-claims.json#/issue_32"),
        "issue_34": passed_pointer(
            "acceptance/acceptance-claims.json#/issue_34"),
        "issue_40": passed_pointer(
            "fault-security/fault-security-matrix.json#/coverage/issue_40"),
    }
    if claims_version == 1:
        expected_coverage["issue_36"] = passed_pointer(
            "fault-security/fault-security-matrix.json#/coverage/issue_36")
    else:
        expected_coverage["issue_36"] = {
            "pointers": [
                "acceptance/acceptance-claims.json#/issue_36",
                "fault-security/fault-security-matrix.json#/coverage/issue_36",
            ],
            "status": "passed",
        }
    if index.get("coverage") != expected_coverage:
        raise ValueError("candidate claim coverage is invalid")
    if (acceptance.get("schema") !=
            f"obi-bounded-acceptance-claims-v{claims_version}" or
            acceptance.get("status") != "passed" or
            not isinstance(acceptance.get("issue_32"), dict) or
            not isinstance(acceptance.get("issue_34"), dict) or
            (claims_version == 2 and
             not isinstance(acceptance.get("issue_36"), dict))):
        raise ValueError("candidate acceptance claims are invalid")
    if (authority.get("source") != expected_source or
            not isinstance(authority.get("execution_locator"), dict) or
            authority["execution_locator"].get("head_sha") != head):
        raise ValueError("candidate authority summary is invalid")
    if (fault.get("schema") != "obi-bounded-fault-security-matrix-v1" or
            fault.get("status") != "passed" or
            fault.get("source") != {
                "revision": head, "source_tree_sha256": source_tree} or
            not isinstance(fault.get("coverage"), dict) or
            fault["coverage"].get("issue_36", {}).get("status") != "passed" or
            fault["coverage"].get("issue_40", {}).get("status") != "passed"):
        raise ValueError("candidate fault matrix is invalid")

try:
    main()
except (OSError, RuntimeError, ValueError, TypeError):
    raise SystemExit(1) from None
PY
  status=$?
  exec {acceptance_manifest_fd}<&-
  exec {fault_manifest_fd}<&-
  exec {acceptance_artifact_fd}<&-
  exec {fault_artifact_fd}<&-
  return "$status"
}

rename_candidate_directory_noreplace() {
  local -r output_parent_fd="$1"
  local -r expected_parent_identity="$2"
  local -r candidate_fd="$3"
  local -r expected_candidate_identity="$4"
  local -r candidate_name="$5"
  local -r output_name="$6"
  local -r output_parent_path="$7"
  local -r expected_seal="$8"
  local seal_fd=''
  local status=0

  [[ "$output_parent_fd" =~ ^[1-9][0-9]*$ &&
    "$candidate_fd" =~ ^[1-9][0-9]*$ &&
    "$candidate_name" =~ ^\.retained-ci-import\.[A-Za-z0-9]{6}$ &&
    "$output_name" == "$OUTPUT_NAME" && "$output_parent_path" == "$OUTPUT_PARENT" &&
    -n "$expected_seal" && ${#expected_seal} -le 65536 ]] ||
    return 1
  exec {seal_fd}<<<"$expected_seal" || return 1

  python3 -I - "$output_parent_fd" "$expected_parent_identity" \
    "$candidate_fd" "$expected_candidate_identity" "$candidate_name" \
    "$output_name" "$output_parent_path" \
    "$seal_fd" "$MAX_MEMBER_BYTES" \
    "$((MAX_EXPANDED_BYTES * 2 + MAX_MEMBER_BYTES * 4))" <<'PY'
import ctypes
import hashlib
import json
import os
import re
import stat
import sys

RENAME_NOREPLACE = 1
EXPECTED_DIRECTORIES = {
    ".": (
        "SHA256SUMS", "acceptance", "claim-index.json", "fault-security",
        "run-identity.json", "verify.sh",
    ),
    "acceptance": (
        "README.md", "SANITIZATION.md", "SHA256SUMS",
        "acceptance-claims.json", "authority-summary.json",
        "derivation-receipt.json", "verify.sh",
    ),
    "fault-security": (
        "README.md", "SANITIZATION.md", "SHA256SUMS",
        "derivation-receipt.json", "fault-security-matrix.json", "verify.sh",
    ),
}
EXPECTED_CHECKSUM_FILES = (
    "run-identity.json", "claim-index.json", "verify.sh",
    "acceptance/README.md", "acceptance/SANITIZATION.md",
    "acceptance/acceptance-claims.json",
    "acceptance/authority-summary.json",
    "acceptance/derivation-receipt.json", "acceptance/verify.sh",
    "acceptance/SHA256SUMS", "fault-security/README.md",
    "fault-security/SANITIZATION.md",
    "fault-security/fault-security-matrix.json",
    "fault-security/derivation-receipt.json", "fault-security/verify.sh",
    "fault-security/SHA256SUMS",
)
EXPECTED_FILES = tuple(sorted(("SHA256SUMS",) + EXPECTED_CHECKSUM_FILES))

def parse_identity(value):
    fields = value.split(":")
    if len(fields) != 3 or any(not field.isdecimal() for field in fields):
        raise ValueError("invalid expected identity")
    return tuple(int(field) for field in fields)

def identity(value):
    return value.st_dev, value.st_ino, value.st_uid

def require_identity(value, expected, kind, mode):
    if identity(value) != expected or not kind(value.st_mode):
        raise ValueError("filesystem identity changed")
    if stat.S_IMODE(value.st_mode) != mode:
        raise ValueError("filesystem mode changed")

def file_record(value, digest):
    return {
        "ctime_ns": value.st_ctime_ns,
        "dev": value.st_dev,
        "ino": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "mtime_ns": value.st_mtime_ns,
        "nlink": value.st_nlink,
        "sha256": digest,
        "size": value.st_size,
        "uid": value.st_uid,
    }

def directory_record(value):
    return {
        "ctime_ns": value.st_ctime_ns,
        "dev": value.st_dev,
        "ino": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "mtime_ns": value.st_mtime_ns,
        "nlink": value.st_nlink,
        "uid": value.st_uid,
    }

def read_regular(descriptor, maximum):
    value = os.fstat(descriptor)
    if (not stat.S_ISREG(value.st_mode) or
            stat.S_IMODE(value.st_mode) != 0o444 or
            value.st_uid != os.geteuid() or value.st_nlink != 1 or
            value.st_size < 1 or value.st_size > maximum):
        raise ValueError("published member metadata is invalid")
    digest = hashlib.sha256()
    offset = 0
    remaining = value.st_size
    while remaining:
        chunk = os.pread(descriptor, min(remaining, 1024 * 1024), offset)
        if not chunk:
            raise ValueError("published member was truncated")
        digest.update(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    if os.pread(descriptor, 1, value.st_size):
        raise ValueError("published member grew during capture")
    after = os.fstat(descriptor)
    stable_fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    if any(getattr(value, field) != getattr(after, field)
           for field in stable_fields):
        raise ValueError("published member changed during capture")
    return file_record(value, digest.hexdigest())

def capture_held_seal(root_fd, maximum_member, maximum_total):
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fds = {".": os.dup(root_fd)}
    file_fds = {}
    try:
        directory_fds["acceptance"] = os.open(
            "acceptance", directory_flags, dir_fd=root_fd)
        directory_fds["fault-security"] = os.open(
            "fault-security", directory_flags, dir_fd=root_fd)
        directories = {}
        for path in sorted(EXPECTED_DIRECTORIES):
            descriptor = directory_fds[path]
            value = os.fstat(descriptor)
            if (not stat.S_ISDIR(value.st_mode) or
                    stat.S_IMODE(value.st_mode) != 0o555 or
                    value.st_uid != os.geteuid() or
                    tuple(sorted(os.listdir(descriptor))) !=
                    EXPECTED_DIRECTORIES[path]):
                raise ValueError("published directory roster is not exact")
            directories[path] = directory_record(value)
        files = {}
        total = 0
        for path in EXPECTED_FILES:
            parent_path, separator, name = path.rpartition("/")
            if not separator:
                parent_path, name = ".", path
            descriptor = os.open(name, file_flags, dir_fd=directory_fds[parent_path])
            file_fds[path] = descriptor
            record = read_regular(descriptor, maximum_member)
            path_value = os.stat(
                name, dir_fd=directory_fds[parent_path], follow_symlinks=False)
            if (path_value.st_dev, path_value.st_ino) != \
                    (record["dev"], record["ino"]):
                raise ValueError("published member pathname changed")
            files[path] = record
            total += record["size"]
            if total > maximum_total:
                raise ValueError("published bundle exceeds its byte bound")
        if tuple(sorted(path for path in files if path != "SHA256SUMS")) != \
                tuple(sorted(EXPECTED_CHECKSUM_FILES)):
            raise ValueError("published checksum roster is not exact")
        return ({
            "directories": directories,
            "files": files,
            "schema_version": 1,
            "total_size": total,
        }, directory_fds, file_fds)
    except BaseException:
        for descriptor in file_fds.values():
            os.close(descriptor)
        for descriptor in directory_fds.values():
            os.close(descriptor)
        raise

def verify_held_seal(seal, directory_fds, file_fds, maximum_member):
    for path in sorted(EXPECTED_DIRECTORIES):
        descriptor = directory_fds[path]
        value = os.fstat(descriptor)
        if (directory_record(value) != seal["directories"][path] or
                tuple(sorted(os.listdir(descriptor))) != EXPECTED_DIRECTORIES[path]):
            raise ValueError("published directory changed before commit")
    for path in EXPECTED_FILES:
        parent_path, separator, name = path.rpartition("/")
        if not separator:
            parent_path, name = ".", path
        record = read_regular(file_fds[path], maximum_member)
        if record != seal["files"][path]:
            raise ValueError("published member changed before commit")
        path_value = os.stat(
            name, dir_fd=directory_fds[parent_path], follow_symlinks=False)
        if (path_value.st_dev, path_value.st_ino) != \
                (record["dev"], record["ino"]):
            raise ValueError("published member pathname changed before commit")

def main():
    if sys.platform != "linux" or len(sys.argv) != 11:
        raise RuntimeError("Linux renameat2 is required")
    output_fd = int(sys.argv[1])
    expected_output = parse_identity(sys.argv[2])
    candidate_fd = int(sys.argv[3])
    expected_candidate = parse_identity(sys.argv[4])
    candidate_name = sys.argv[5]
    output_name = sys.argv[6]
    output_path = sys.argv[7]
    seal_fd = int(sys.argv[8])
    maximum_member = int(sys.argv[9])
    maximum_total = int(sys.argv[10])
    if not re.fullmatch(r"\.retained-ci-import\.[A-Za-z0-9]{6}", candidate_name):
        raise ValueError("candidate leaf is invalid")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", output_name):
        raise ValueError("output leaf is invalid")
    if not os.path.isabs(output_path) or os.path.realpath(output_path) != output_path:
        raise ValueError("publication parent is not physical")
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_flags):
        raise RuntimeError("required Linux open flags are unavailable")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    path_fd = -1
    directory_fds = {}
    file_fds = {}
    try:
        with os.fdopen(os.dup(seal_fd), "rb") as source:
            encoded_seal = source.read(65537)
        if not encoded_seal or len(encoded_seal) > 65536:
            raise ValueError("published seal is out of bounds")
        if encoded_seal.endswith(b"\n"):
            encoded_seal = encoded_seal[:-1]
        expected_seal = json.loads(encoded_seal)
        if not isinstance(expected_seal, dict):
            raise ValueError("published seal is invalid")
        output_stat = os.fstat(output_fd)
        require_identity(output_stat, expected_output, stat.S_ISDIR, 0o700)
        candidate_stat = os.fstat(candidate_fd)
        require_identity(
            candidate_stat, expected_candidate, stat.S_ISDIR, 0o555)
        if candidate_stat.st_dev != output_stat.st_dev:
            raise ValueError("candidate is not on the publication filesystem")
        require_identity(
            os.stat(candidate_name, dir_fd=output_fd, follow_symlinks=False),
            expected_candidate, stat.S_ISDIR, 0o555)
        path_fd = os.open(output_path, directory_flags)
        require_identity(os.fstat(path_fd), expected_output, stat.S_ISDIR, 0o700)

        observed_seal, directory_fds, file_fds = capture_held_seal(
            candidate_fd, maximum_member, maximum_total)
        if observed_seal != expected_seal:
            raise ValueError("published candidate seal changed")

        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renameat2 = libc.renameat2
        except AttributeError as error:
            raise RuntimeError("libc renameat2 is unavailable") from error
        renameat2.argtypes = (
            ctypes.c_int, ctypes.c_char_p,
            ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        renameat2.restype = ctypes.c_int
        require_identity(os.fstat(output_fd), expected_output, stat.S_ISDIR, 0o700)
        require_identity(os.fstat(candidate_fd), expected_candidate, stat.S_ISDIR, 0o555)
        verify_held_seal(
            observed_seal, directory_fds, file_fds, maximum_member)
        result = renameat2(
            output_fd, os.fsencode(candidate_name),
            output_fd, os.fsencode(output_name), RENAME_NOREPLACE)
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))

        # A successful syscall is not yet an acknowledged commit. Prove that
        # the source name disappeared, the final name resolves to the exact
        # held directory, and every held child still has its pre-rename seal.
        try:
            os.stat(candidate_name, dir_fd=output_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("published candidate source name survived rename")
        final_fd = os.open(output_name, directory_flags, dir_fd=output_fd)
        try:
            final_stat = os.fstat(final_fd)
            require_identity(final_stat, expected_candidate, stat.S_ISDIR, 0o555)
            if (final_stat.st_dev, final_stat.st_ino) != \
                    (candidate_stat.st_dev, candidate_stat.st_ino):
                raise ValueError("published final directory identity changed")
            for path in sorted(EXPECTED_DIRECTORIES):
                descriptor = directory_fds[path]
                value = os.fstat(descriptor)
                expected_record = observed_seal["directories"][path]
                observed_record = directory_record(value)
                if path == ".":
                    observed_record.pop("ctime_ns", None)
                    expected_record = dict(expected_record)
                    expected_record.pop("ctime_ns", None)
                if (observed_record != expected_record or
                        tuple(sorted(os.listdir(descriptor))) !=
                        EXPECTED_DIRECTORIES[path]):
                    raise ValueError("published directory changed after commit")
                if path != ".":
                    path_value = os.stat(
                        path, dir_fd=final_fd, follow_symlinks=False)
                    if (path_value.st_dev, path_value.st_ino) != \
                            (value.st_dev, value.st_ino):
                        raise ValueError(
                            "published child directory pathname changed")
            for path in EXPECTED_FILES:
                record = read_regular(file_fds[path], maximum_member)
                if record != observed_seal["files"][path]:
                    raise ValueError("published member changed after commit")
                parent_path, separator, name = path.rpartition("/")
                if not separator:
                    parent_path, name = ".", path
                path_value = os.stat(
                    name, dir_fd=directory_fds[parent_path],
                    follow_symlinks=False)
                if (path_value.st_dev, path_value.st_ino) != \
                        (record["dev"], record["ino"]):
                    raise ValueError("published member pathname changed")
        finally:
            os.close(final_fd)
        require_identity(os.fstat(output_fd), expected_output, stat.S_ISDIR, 0o700)
        require_identity(os.fstat(path_fd), expected_output, stat.S_ISDIR, 0o700)
    finally:
        for descriptor in file_fds.values():
            os.close(descriptor)
        for descriptor in directory_fds.values():
            os.close(descriptor)
        if path_fd >= 0:
            os.close(path_fd)

try:
    main()
except (OSError, RuntimeError, ValueError):
    raise SystemExit(1) from None
PY
  status=$?
  exec {seal_fd}<&-
  ((status == 0)) || return "$status"
  bundle_publication_native_ack_checkpoint
}

reconcile_candidate_publication() {
  local -r output_parent_fd="$1"
  local -r expected_parent_identity="$2"
  local -r candidate_fd="$3"
  local -r expected_candidate_identity="$4"
  local -r candidate_name="$5"
  local -r output_name="$6"
  local -r output_parent_path="$7"
  local -r expected_seal="$8"
  local observed_seal=''
  local seal_is_exact=0
  local renamed_seal_is_exact=0

  if observed_seal="$(capture_candidate_publication_seal "$candidate_fd")" &&
    [[ "$observed_seal" == "$expected_seal" ]]; then
    seal_is_exact=1
  fi
  if [[ -n "$observed_seal" ]] &&
    printf '%s\n%s\n' "$observed_seal" "$expected_seal" | jq -es '
      length == 2 and
      (.[0] | del(.directories["."].ctime_ns)) ==
      (.[1] | del(.directories["."].ctime_ns))
    ' >/dev/null; then
    renamed_seal_is_exact=1
  fi

  python3 -I - "$output_parent_fd" "$expected_parent_identity" \
    "$candidate_fd" "$expected_candidate_identity" "$candidate_name" "$output_name" \
    "$output_parent_path" "$seal_is_exact" "$renamed_seal_is_exact" <<'PY'
import os
import re
import stat
import sys

def parse_identity(value):
    fields = value.split(":")
    if len(fields) != 3 or any(not field.isdecimal() for field in fields):
        raise ValueError("invalid expected identity")
    return tuple(int(field) for field in fields)

def identity(value):
    return value.st_dev, value.st_ino, value.st_uid

def exact_directory(value, expected, mode):
    return (identity(value) == expected and stat.S_ISDIR(value.st_mode) and
            stat.S_IMODE(value.st_mode) == mode)

def entry_state(parent_fd, name, expected):
    try:
        value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return "absent"
    if exact_directory(value, expected, 0o555):
        return "exact"
    return "foreign"

def lexical_parent_is_exact(path, expected):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        return exact_directory(os.fstat(descriptor), expected, 0o700)
    finally:
        os.close(descriptor)

def main():
    if sys.platform != "linux" or len(sys.argv) != 10:
        raise RuntimeError("Linux descriptor reconciliation is required")
    output_fd = int(sys.argv[1])
    expected_output = parse_identity(sys.argv[2])
    candidate_fd = int(sys.argv[3])
    expected_candidate = parse_identity(sys.argv[4])
    candidate_name, output_name, output_path = sys.argv[5:8]
    seal_is_exact = sys.argv[8] == "1"
    renamed_seal_is_exact = sys.argv[9] == "1"
    if not re.fullmatch(r"\.retained-ci-import\.[A-Za-z0-9]{6}", candidate_name):
        raise ValueError("candidate leaf is invalid")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", output_name):
        raise ValueError("output leaf is invalid")
    if not exact_directory(os.fstat(output_fd), expected_output, 0o700):
        raise ValueError("output parent descriptor changed")
    if not exact_directory(os.fstat(candidate_fd), expected_candidate, 0o555):
        raise ValueError("candidate descriptor changed")
    if not lexical_parent_is_exact(output_path, expected_output):
        print("ambiguous")
        return
    source = entry_state(output_fd, candidate_name, expected_candidate)
    destination = entry_state(output_fd, output_name, expected_candidate)
    if source == "exact" and destination == "absent":
        print("uncommitted" if seal_is_exact else "ambiguous")
        return
    if source == "exact" and destination == "foreign":
        print("collision" if seal_is_exact else "ambiguous")
        return
    if source in ("absent", "foreign") and destination == "exact":
        if not renamed_seal_is_exact:
            print("ambiguous")
            return
        if (not exact_directory(os.fstat(output_fd), expected_output, 0o700) or
                entry_state(output_fd, output_name, expected_candidate) != "exact" or
                not lexical_parent_is_exact(output_path, expected_output)):
            print("ambiguous")
            return
        print("committed")
        return
    print("ambiguous")

try:
    main()
except (OSError, RuntimeError, ValueError):
    raise SystemExit(1) from None
PY
}

bundle_publication_transaction() (
  local -r candidate_bundle="$1"
  local -r expected_candidate_identity="$2"
  local -r claims_version="$3"
  local -r acceptance_source_manifest="$4"
  local -r fault_source_manifest="$5"
  local output_parent_fd=''
  local candidate_fd=''
  local observed_identity=''
  local publication_status=0
  local state=''
  local candidate_name=''
  local candidate_seal=''
  local validated_seal=''

  candidate_name="${CANDIDATE_DIRECTORY##*/}"
  [[ "$candidate_bundle" == "$CANDIDATE_DIRECTORY" &&
    "$CANDIDATE_DIRECTORY" == "$OUTPUT_PARENT/$candidate_name" &&
    "$candidate_name" =~ ^\.retained-ci-import\.[A-Za-z0-9]{6}$ ]] || return 1
  exec {output_parent_fd}<"$OUTPUT_PARENT" || return 1
  exec {candidate_fd}<"$candidate_bundle" || return 1
  observed_identity="$(stat -Lc '%d:%i:%u' \
    -- "/proc/$BASHPID/fd/$output_parent_fd")" || return 1
  [[ "$observed_identity" == "$OUTPUT_PARENT_IDENTITY" ]] || return 1
  observed_identity="$(stat -Lc '%d:%i:%u' \
    -- "/proc/$BASHPID/fd/$candidate_fd")" || return 1
  [[ "$observed_identity" == "$expected_candidate_identity" ]] || return 1
  observed_identity="$(stat -Lc '%d:%i:%u' -- "$OUTPUT_PARENT")" || return 1
  [[ "$observed_identity" == "$OUTPUT_PARENT_IDENTITY" ]] || return 1
  observed_identity="$(stat -Lc '%d:%i:%u' -- "$candidate_bundle")" || return 1
  [[ "$observed_identity" == "$expected_candidate_identity" ]] || return 1
  candidate_seal="$(capture_candidate_publication_seal "$candidate_fd")" ||
    return 1
  bundle_publication_before_validation_checkpoint "$candidate_bundle" || return 1
  validate_candidate_publication_semantics "$candidate_fd" "$claims_version" \
    "$acceptance_source_manifest" "$fault_source_manifest" || return 1
  bundle_publication_validation_checkpoint "$candidate_bundle" || return 1
  validated_seal="$(capture_candidate_publication_seal "$candidate_fd")" ||
    return 1
  [[ "$validated_seal" == "$candidate_seal" ]] || return 1
  bundle_publication_checkpoint "$candidate_bundle" "$OUTPUT_DIRECTORY" ||
    publication_status=$?
  if ((publication_status == 0)); then
    rename_candidate_directory_noreplace \
      "$output_parent_fd" "$OUTPUT_PARENT_IDENTITY" \
      "$candidate_fd" "$expected_candidate_identity" \
      "$candidate_name" "$OUTPUT_NAME" "$OUTPUT_PARENT" "$candidate_seal" ||
      publication_status=$?
  fi
  if ((publication_status == 0)); then
    bundle_publication_complete_checkpoint "$OUTPUT_DIRECTORY" ||
      publication_status=$?
  fi
  bundle_publication_reconciliation_checkpoint \
    "$candidate_bundle" "$OUTPUT_DIRECTORY" "$publication_status" ||
    publication_status=$?
  state="$(reconcile_candidate_publication \
    "$output_parent_fd" "$OUTPUT_PARENT_IDENTITY" \
    "$candidate_fd" "$expected_candidate_identity" \
    "$candidate_name" "$OUTPUT_NAME" "$OUTPUT_PARENT" "$candidate_seal")" ||
    return 1
  case "$state" in
    committed|uncommitted|collision|ambiguous) printf '%s\n' "$state" ;;
    *) return 1 ;;
  esac
)

write_bundle() {
  local -r run_json="$1"
  local -r acceptance="$2"
  local -r fault="$3"
  local -r claims_version="${4:-1}"
  local acceptance_source_manifest="${5:-}"
  local fault_source_manifest="${6:-}"
  local acceptance_receipt=''
  local fault_receipt=''
  local artifact_seed=''
  local file=''
  local candidate_bundle=''
  local candidate_bundle_identity=''
  local publication_state=''

  [[ "$claims_version" == 1 || "$claims_version" == 2 ]] || return 1
  if [[ -z "$acceptance_source_manifest" ]]; then
    acceptance_source_manifest="$(directory_manifest_value \
      "$acceptance" "${ACCEPTANCE_FILES[@]}")" || return 1
  fi
  if [[ -z "$fault_source_manifest" ]]; then
    fault_source_manifest="$(directory_manifest_value \
      "$fault" "${FAULT_FILES[@]}")" || return 1
  fi
  acceptance_receipt="$(jq -er \
    '.files["derivation-receipt.json"].sha256' \
    <<<"$acceptance_source_manifest")" || return 1
  fault_receipt="$(jq -er '.files["derivation-receipt.json"].sha256' \
    <<<"$fault_source_manifest")" || return 1
  is_sha256 "$WORKFLOW_BLOB_SHA256" && is_sha256 "$acceptance_receipt" &&
    is_sha256 "$fault_receipt" || return 1
  artifact_seed="$(printf '%s\n' "$HEAD_SHA" "$RUN_ID" "$RUN_ATTEMPT" \
    "$acceptance_receipt" "$fault_receipt" | sha256sum)"
  EVIDENCE_ID="${artifact_seed%% *}"
  [[ "$OUTPUT_NAME" == \
    "retained-claims-${HEAD_SHA:0:12}-${EVIDENCE_ID:0:12}" ]] ||
    die 'output leaf does not match the canonical evidence identity' || return 1

  CANDIDATE_DIRECTORY="$(mktemp -d \
    "$OUTPUT_PARENT/.retained-ci-import.XXXXXX")" || return 1
  CANDIDATE_CLEANUP_ALLOWED=1
  CANDIDATE_DIRECTORY="$(CDPATH='' cd -- "$CANDIDATE_DIRECTORY" && pwd -P)"
  CANDIDATE_IDENTITY="$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")"
  [[ "${CANDIDATE_IDENTITY%%:*}" == "${OUTPUT_PARENT_IDENTITY%%:*}" ]] ||
    die 'candidate and output parent are not on one filesystem' || return 1
  candidate_bundle="$CANDIDATE_DIRECTORY"
  install -d -m 0700 -- "$candidate_bundle/acceptance" \
    "$candidate_bundle/fault-security"
  cp -a -- "$acceptance/." "$candidate_bundle/acceptance/"
  cp -a -- "$fault/." "$candidate_bundle/fault-security/"

  jq -cS -n --arg repository "$REPOSITORY" --arg event push \
    --arg ref "$REF" --arg head "$HEAD_SHA" --arg tree "$SOURCE_TREE_SHA256" \
    --arg workflow_name "$WORKFLOW_NAME" --arg workflow_path "$WORKFLOW_PATH" \
    --arg workflow_ref "$REPOSITORY/$WORKFLOW_PATH@$REF" \
    --arg workflow_sha "$HEAD_SHA" --arg workflow_blob "$WORKFLOW_BLOB_SHA256" \
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
  ' >"$candidate_bundle/run-identity.json" || return 1
  if [[ "$claims_version" == 1 ]]; then
    jq -cS -n --arg evidence_id "$EVIDENCE_ID" --arg head "$HEAD_SHA" \
      --arg tree "$SOURCE_TREE_SHA256" '
      {schema:"obi-retained-ci-claim-index-v1",status:"passed",
        evidence_id:$evidence_id,source:{revision:$head,tree_sha256:$tree},
        coverage:{
          issue_32:{status:"passed",pointer:"acceptance/acceptance-claims.json#/issue_32"},
          issue_34:{status:"passed",pointer:"acceptance/acceptance-claims.json#/issue_34"},
          issue_36:{status:"passed",pointer:"fault-security/fault-security-matrix.json#/coverage/issue_36"},
          issue_40:{status:"passed",pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40"}}}
    ' >"$candidate_bundle/claim-index.json" || return 1
    write_portable_verifier "$candidate_bundle/verify.sh"
  else
    jq -cS -n --arg evidence_id "$EVIDENCE_ID" --arg head "$HEAD_SHA" \
      --arg tree "$SOURCE_TREE_SHA256" '
      {schema:"obi-retained-ci-claim-index-v2",status:"passed",
        evidence_id:$evidence_id,source:{revision:$head,tree_sha256:$tree},
        coverage:{
          issue_32:{status:"passed",pointer:"acceptance/acceptance-claims.json#/issue_32"},
          issue_34:{status:"passed",pointer:"acceptance/acceptance-claims.json#/issue_34"},
          issue_36:{status:"passed",pointers:[
            "acceptance/acceptance-claims.json#/issue_36",
            "fault-security/fault-security-matrix.json#/coverage/issue_36"]},
          issue_40:{status:"passed",pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40"}}}
    ' >"$candidate_bundle/claim-index.json" || return 1
    write_portable_verifier_v2 "$candidate_bundle/verify.sh"
  fi
  (
    CDPATH='' cd -- "$candidate_bundle"
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
  ) >"$candidate_bundle/SHA256SUMS" || return 1
  find -- "$candidate_bundle" -type f -exec chmod 0444 -- {} +
  find -- "$candidate_bundle" -depth -type d -exec chmod 0555 -- {} +
  candidate_bundle_identity="$(stat -Lc '%d:%i:%u' -- "$candidate_bundle")" ||
    return 1
  [[ "$(stat -Lc '%d:%i:%u' -- "$OUTPUT_PARENT")" == "$OUTPUT_PARENT_IDENTITY" ]] ||
    return 1
  # From this point onward the candidate may cross an adversarial test seam.
  # Recursive pathname cleanup is no longer safe even if reconciliation later
  # observes the original directory inode.
  CANDIDATE_CLEANUP_ALLOWED=0
  if ! bundle_publication_before_seal_checkpoint "$candidate_bundle"; then
    CANDIDATE_DIRECTORY=''
    CANDIDATE_IDENTITY=''
    CANDIDATE_CLEANUP_ALLOWED=1
    return 1
  fi
  publication_state="$(bundle_publication_transaction \
    "$candidate_bundle" "$candidate_bundle_identity" "$claims_version" \
    "$acceptance_source_manifest" "$fault_source_manifest")" ||
    publication_state=ambiguous
  case "$publication_state" in
    committed)
      CANDIDATE_DIRECTORY=''
      CANDIDATE_IDENTITY=''
      CANDIDATE_CLEANUP_ALLOWED=1
      return 0
      ;;
    uncommitted|collision|ambiguous)
      # Seal A is the cleanup surrender boundary. After it, even an exact
      # lexical candidate can acquire an attacker-owned child between a fresh
      # check and recursive deletion. Preserve the sanitized hidden directory
      # for caller inspection; never delete through a mutable pathname.
      CANDIDATE_DIRECTORY=''
      CANDIDATE_IDENTITY=''
      CANDIDATE_CLEANUP_ALLOWED=1
      return 1
      ;;
    *) return 1 ;;
  esac
}

import_claims() {
  local -r claims_version="$1"
  local -r run_json="$2"
  local -r artifacts_json="$3"
  local -r acceptance_zip="$4"
  local -r fault_zip="$5"
  local -r output="$6"
  local acceptance_directory=''
  local fault_directory=''
  local acceptance_before=''
  local acceptance_after=''
  local fault_before=''
  local fault_after=''
  local run_snapshot=''
  local artifacts_snapshot=''

  [[ "$claims_version" == 1 || "$claims_version" == 2 ]] || return 1
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
  acceptance_before="$(directory_manifest_value \
    "$acceptance_directory" "${ACCEPTANCE_FILES[@]}")" || return 1
  fault_before="$(directory_manifest_value \
    "$fault_directory" "${FAULT_FILES[@]}")" || return 1
  verify_nested_bundles \
    "$acceptance_directory" "$fault_directory" "$claims_version" ||
    die 'nested claim bundle validation failed' || return 1
  acceptance_after="$(directory_manifest_value \
    "$acceptance_directory" "${ACCEPTANCE_FILES[@]}")" || return 1
  fault_after="$(directory_manifest_value \
    "$fault_directory" "${FAULT_FILES[@]}")" || return 1
  [[ "$acceptance_before" == "$acceptance_after" ]] ||
    die 'acceptance bundle changed during nested verification' || return 1
  [[ "$fault_before" == "$fault_after" ]] ||
    die 'fault/security bundle changed during nested verification' || return 1
  write_bundle \
    "$run_snapshot" "$acceptance_directory" "$fault_directory" "$claims_version" \
    "$acceptance_after" "$fault_after"
}

claims_v1() {
  import_claims 1 "$@"
}

claims_v2() {
  import_claims 2 "$@"
}

main() {
  if [[ $# == 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    usage
    return 0
  fi
  [[ $# == 6 ]] || {
    usage >&2
    return 2
  }
  case "$1" in
    claims-v1) claims_v1 "$2" "$3" "$4" "$5" "$6" ;;
    claims-v2) claims_v2 "$2" "$3" "$4" "$5" "$6" ;;
    *)
      usage >&2
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
