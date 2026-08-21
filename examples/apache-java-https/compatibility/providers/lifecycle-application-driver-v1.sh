#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077
export LC_ALL=C

readonly DRIVER_SCHEMA=compatibility-lifecycle-application-driver-v1
readonly ENVIRONMENT_SCHEMA=compatibility-helper-lifecycle-environment-v1
readonly RESULT_SCHEMA=compatibility-helper-lifecycle-environment-result-v1
readonly EXECUTOR_REGISTRY_SCHEMA=compatibility-lifecycle-executor-registry-v1
readonly EXECUTION_RECEIPT_SCHEMA=compatibility-lifecycle-execution-receipt-v1
readonly CAMPAIGN_REVISION=apache-java-https-helper-lifecycle-v1
readonly PLAN_SHA256=ffdd6c558d1086014d2085e8c66479c1728f3d28de4984244ee9bf522a6e5856
readonly MAX_RAW_FILES=4096
readonly MAX_RAW_BYTES=2147483648
readonly MAX_ASSERTION_COUNT=1000000000
readonly MAX_RESOURCE_MAGNITUDE=1000000000

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  [[ "$0" == /* ]] || {
    printf 'ERROR: lifecycle driver argv[0] must be an absolute authority path\n' >&2
    exit 2
  }
  DRIVER_PATH="$0"
else
  DRIVER_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
fi
readonly DRIVER_PATH
declare -ar DRIVER_ARGV=("$DRIVER_PATH" "$@")

contract=""
campaign=""
campaign_revision=""
plan_sha256=""
cell=""
source_authority=""
source_authority_sha256=""
private_output=""
contract_cell_source=""
contract_cell_source_identity=""
contract_source_authority_source=""
contract_source_authority_source_identity=""
DRIVER_PRIVATE_DESCRIPTOR=""

error() {
  printf 'ERROR: %s\n' "$*" >&2
}

die() {
  error "$*"
  return 1
}

require_commands() {
  local name=""
  local -a missing=()

  for name in "$@"; do
    if ! command -v "$name" >/dev/null 2>&1; then
      missing+=("$name")
    fi
  done
  (( ${#missing[@]} == 0 )) ||
    die "missing required commands: ${missing[*]}"
}

sha256_file() {
  local -r path="$1"
  local digest=""

  [[ -f "$path" && ! -L "$path" ]] || return 1
  digest="$(sha256sum -- "$path")" || return
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

safe_file_identity() {
  local -r path="$1"
  local -r executable="$2"

  [[ "$path" == /* && ( "$executable" == true || "$executable" == false ) ]] ||
    return 2
  python3 - "$path" "$executable" <<'PY'
import hashlib
import os
import stat
import sys


path = sys.argv[1]
executable = sys.argv[2] == "true"
descriptor = os.open(
    path,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
try:
    before = os.fstat(descriptor)
    mode = stat.S_IMODE(before.st_mode)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("source is not regular")
    if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
        raise RuntimeError("source has unsafe ownership or link count")
    if before.st_size <= 0 or before.st_size > 16 * 1024 * 1024:
        raise RuntimeError("source has an unsafe size")
    if mode & 0o022 or executable and not mode & 0o111:
        raise RuntimeError("source has unsafe permissions")
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    after = os.fstat(descriptor)
    fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
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

safe_descriptor_identity() {
  local -r descriptor_path="$1"

  [[ "$descriptor_path" =~ ^/proc/self/fd/([1-9][0-9]*)$ ]] || return 2
  python3 - "${BASH_REMATCH[1]}" <<'PY'
import hashlib
import os
import stat
import sys


descriptor = int(sys.argv[1])
before = os.fstat(descriptor)
mode = stat.S_IMODE(before.st_mode)
if not stat.S_ISREG(before.st_mode):
    raise RuntimeError("descriptor is not regular")
if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
    raise RuntimeError("descriptor has unsafe ownership or link count")
if before.st_size <= 0 or before.st_size > 16 * 1024 * 1024:
    raise RuntimeError("descriptor has an unsafe size")
if mode & 0o022 or not mode & 0o111:
    raise RuntimeError("descriptor has unsafe permissions")
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
    raise RuntimeError("descriptor changed while hashing")
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

file_identity_is_unchanged() {
  local -r path="$1"
  local -r executable="$2"
  local -r expected="$3"
  local observed=""

  observed="$(safe_file_identity "$path" "$executable")" || return 1
  [[ "$observed" == "$expected" ]]
}

pin_private_output() {
  local original_path=""

  if [[ -n "$DRIVER_PRIVATE_DESCRIPTOR" ]]; then
    [[ "$private_output" == "/proc/self/fd/$DRIVER_PRIVATE_DESCRIPTOR/." ]] ||
      return 1
    return 0
  fi
  original_path="$private_output"
  exec {DRIVER_PRIVATE_DESCRIPTOR}<"$original_path" || return
  python3 - "$original_path" "$DRIVER_PRIVATE_DESCRIPTOR" <<'PY'
import os
import stat
import sys


path = sys.argv[1]
descriptor = int(sys.argv[2])
retained = os.fstat(descriptor)
named = os.stat(path, follow_symlinks=False)
fields = ("st_dev", "st_ino", "st_uid", "st_mode")
if not stat.S_ISDIR(retained.st_mode):
    raise RuntimeError("private output is not a directory")
if retained.st_uid != os.geteuid() or stat.S_IMODE(retained.st_mode) != 0o700:
    raise RuntimeError("private output lacks exact owner-private authority")
if any(getattr(retained, field) != getattr(named, field) for field in fields):
    raise RuntimeError("private output path changed while it was retained")
PY
  private_output="/proc/self/fd/$DRIVER_PRIVATE_DESCRIPTOR/."
}

create_stable_file_snapshot() {
  local -r source="$1"
  local -r destination="$2"
  local -r executable="$3"
  local -r destination_mode="$4"

  [[ "$source" == /* && "$destination" == /* &&
    ( "$executable" == true || "$executable" == false ) &&
    "$destination_mode" =~ ^0?[0-7]{3}$ ]] || return 2
  python3 - "$source" "$destination" "$executable" "$destination_mode" <<'PY'
import hashlib
import os
import stat
import sys


source, destination = sys.argv[1:3]
executable = sys.argv[3] == "true"
destination_mode = int(sys.argv[4], 8)
source_fd = os.open(
    source,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
destination_fd = None
try:
    before = os.fstat(source_fd)
    mode = stat.S_IMODE(before.st_mode)
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("snapshot source is not regular")
    if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
        raise RuntimeError("snapshot source has unsafe ownership or link count")
    if before.st_size <= 0 or before.st_size > 16 * 1024 * 1024:
        raise RuntimeError("snapshot source has an unsafe size")
    if mode & 0o022 or executable and not mode & 0o111:
        raise RuntimeError("snapshot source has unsafe permissions")
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        destination_mode,
    )
    digest = hashlib.sha256()
    observed = 0
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        observed += len(chunk)
        if observed > before.st_size:
            raise RuntimeError("snapshot source grew while copying")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                raise RuntimeError("short snapshot write")
            view = view[written:]
    os.fsync(destination_fd)
    after = os.fstat(source_fd)
    fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    if observed != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in fields
    ):
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

publish_private_file_no_replace() {
  local -r source="$1"
  local -r expected_identity="$2"
  local -r target="$3"
  local -r expected_target_identity="${4:-}"
  local -r test_hook="${5:-}"
  local -r identity_pattern='^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]{64}$'

  [[ "$source" == /* && "$target" == /* &&
    "$expected_identity" =~ $identity_pattern &&
    ( -z "$expected_target_identity" ||
      "$expected_target_identity" =~ $identity_pattern ) ]] || return 2
  python3 - "$source" "$expected_identity" "$target" \
    "$expected_target_identity" "$test_hook" <<'PY'
import ctypes
import errno
import hashlib
import os
import secrets
import stat
import subprocess
import sys


source, expected_identity, target, expected_target_identity, test_hook = sys.argv[1:6]
source_parent = os.path.dirname(source)
source_name = os.path.basename(source)
target_parent = os.path.dirname(target)
target_name = os.path.basename(target)
for name in (source_name, target_name):
    if not name or name in (".", "..") or "/" in name or "\n" in name:
        raise RuntimeError("unsafe private publication name")


def descriptor_identity(descriptor):
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > 64 * 1024 * 1024
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise RuntimeError("unsafe private publication source")
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
        raise RuntimeError("private publication source changed while hashing")
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


def same_object(left, right):
    fields = (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
    )
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def exact_private_parent(descriptor, path):
    retained = os.fstat(descriptor)
    named = os.stat(path, follow_symlinks=False)
    if (
        not stat.S_ISDIR(retained.st_mode)
        or retained.st_uid != os.geteuid()
        or stat.S_IMODE(retained.st_mode) != 0o700
        or not all(
            getattr(retained, field) == getattr(named, field)
            for field in ("st_dev", "st_ino", "st_uid", "st_mode")
        )
    ):
        raise RuntimeError("unsafe private publication parent")
    return retained


def run_hook(phase, path):
    if not test_hook:
        return
    if not os.path.isabs(test_hook):
        raise RuntimeError("publication hook is not absolute")
    state = os.stat(test_hook, follow_symlinks=False)
    if (
        not stat.S_ISREG(state.st_mode)
        or state.st_uid != os.geteuid()
        or stat.S_IMODE(state.st_mode) & 0o022
        or not os.access(test_hook, os.X_OK)
    ):
        raise RuntimeError("unsafe publication hook")
    completed = subprocess.run(
        [test_hook, phase, path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0 or len(completed.stderr) > 65536:
        raise RuntimeError("publication hook failed")


libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    raise RuntimeError("renameat2 is unavailable")
renameat2.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
)
renameat2.restype = ctypes.c_int


def no_replace(source_fd, source_leaf, target_fd, target_leaf):
    if renameat2(
        source_fd,
        os.fsencode(source_leaf),
        target_fd,
        os.fsencode(target_leaf),
        1,
    ) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def quarantine_known(parent_fd, leaf, retained_state, retained_fd, expected_digest):
    try:
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return ""
    if (
        not same_object(current, retained_state)
        or descriptor_identity(retained_fd).rsplit(":", 1)[1]
        != expected_digest
    ):
        return ""
    for _ in range(128):
        quarantine = f".compatibility-rejected.lifecycle.{secrets.token_hex(16)}"
        try:
            no_replace(parent_fd, leaf, parent_fd, quarantine)
        except OSError as error:
            if error.errno == errno.EEXIST:
                continue
            if error.errno == errno.ENOENT:
                return ""
            raise
        moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        descriptor_state = os.fstat(retained_fd)
        if (
            not same_object(moved, descriptor_state)
            or not same_object(retained_state, descriptor_state)
            or descriptor_identity(retained_fd).rsplit(":", 1)[1]
            != expected_digest
        ):
            raise RuntimeError("quarantined private publication changed")
        return quarantine
    raise RuntimeError("could not allocate private publication quarantine")


source_fd = os.open(
    source,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
source_parent_fd = os.open(
    source_parent,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
)
target_parent_fd = os.open(
    target_parent,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
)
published = False
retained_state = os.fstat(source_fd)
target_fd = None
old_quarantine = ""
try:
    source_parent_state = exact_private_parent(source_parent_fd, source_parent)
    target_parent_state = exact_private_parent(target_parent_fd, target_parent)
    if descriptor_identity(source_fd) != expected_identity:
        raise RuntimeError("private publication source identity changed")
    named_source = os.stat(
        source_name,
        dir_fd=source_parent_fd,
        follow_symlinks=False,
    )
    if not same(retained_state, named_source):
        raise RuntimeError("private publication source name changed")
    if expected_target_identity:
        target_fd = os.open(
            target_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=target_parent_fd,
        )
        target_state = os.fstat(target_fd)
        if (
            descriptor_identity(target_fd) != expected_target_identity
            or not same(
                target_state,
                os.stat(
                    target_name,
                    dir_fd=target_parent_fd,
                    follow_symlinks=False,
                ),
            )
        ):
            raise RuntimeError("private publication replacement target changed")
        for _ in range(128):
            old_quarantine = (
                f".compatibility-replaced.lifecycle.{secrets.token_hex(16)}"
            )
            try:
                no_replace(
                    target_parent_fd,
                    target_name,
                    target_parent_fd,
                    old_quarantine,
                )
            except OSError as error:
                if error.errno == errno.EEXIST:
                    continue
                raise
            break
        if not old_quarantine:
            raise RuntimeError("could not retain replaced private publication")
        target_state = os.fstat(target_fd)
        if (
            descriptor_identity(target_fd).rsplit(":", 1)[1]
            != expected_target_identity.rsplit(":", 1)[1]
            or not same(
                target_state,
                os.stat(
                    old_quarantine,
                    dir_fd=target_parent_fd,
                    follow_symlinks=False,
                ),
            )
        ):
            raise RuntimeError("replaced private publication changed in quarantine")
    else:
        try:
            os.stat(target_name, dir_fd=target_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(errno.EEXIST, "private publication target exists")
    run_hook("lifecycle-file-before-rename", source)
    if (
        descriptor_identity(source_fd) != expected_identity
        or not same(
            retained_state,
            os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False),
        )
    ):
        raise RuntimeError("private publication source changed before rename")
    no_replace(source_parent_fd, source_name, target_parent_fd, target_name)
    published = True
    retained_state = os.fstat(source_fd)
    if (
        descriptor_identity(source_fd).rsplit(":", 1)[1]
        != expected_identity.rsplit(":", 1)[1]
        or not same(
            retained_state,
            os.stat(target_name, dir_fd=target_parent_fd, follow_symlinks=False),
        )
    ):
        raise RuntimeError("private publication changed during rename")
    run_hook("lifecycle-file-after-rename-final-rehash", target)
    if (
        descriptor_identity(source_fd).rsplit(":", 1)[1]
        != expected_identity.rsplit(":", 1)[1]
        or not same(
            retained_state,
            os.stat(target_name, dir_fd=target_parent_fd, follow_symlinks=False),
        )
    ):
        raise RuntimeError("private publication changed during final rehash")
    exact_private_parent(source_parent_fd, source_parent)
    exact_private_parent(target_parent_fd, target_parent)
    if target_fd is not None:
        current_old = os.stat(
            old_quarantine,
            dir_fd=target_parent_fd,
            follow_symlinks=False,
        )
        retained_old = os.fstat(target_fd)
        if (
            not same(current_old, retained_old)
            or descriptor_identity(target_fd).rsplit(":", 1)[1]
            != expected_target_identity.rsplit(":", 1)[1]
        ):
            raise RuntimeError("replaced private publication changed before cleanup")
        os.unlink(old_quarantine, dir_fd=target_parent_fd)
        old_quarantine = ""
    os.fsync(target_parent_fd)
except BaseException:
    parent_fd = target_parent_fd if published else source_parent_fd
    leaf = target_name if published else source_name
    retained = quarantine_known(
        parent_fd,
        leaf,
        retained_state,
        source_fd,
        expected_identity.rsplit(":", 1)[1],
    )
    if retained:
        print(f"rejected lifecycle publication retained as {retained}", file=sys.stderr)
    raise
finally:
    os.close(source_fd)
    if target_fd is not None:
        os.close(target_fd)
    os.close(source_parent_fd)
    os.close(target_parent_fd)
PY
}

retain_contract_inputs() {
  local requested_snapshot="$private_output/requested-cell.snapshot.json"
  local authority_snapshot="$private_output/source-authority.snapshot.json"

  contract_cell_source="$cell"
  contract_source_authority_source="$source_authority"
  contract_cell_source_identity="$(safe_file_identity \
    "$contract_cell_source" false)" || return
  contract_source_authority_source_identity="$(safe_file_identity \
    "$contract_source_authority_source" false)" || return
  [[ "$(create_stable_file_snapshot \
      "$contract_cell_source" "$requested_snapshot" false 0400)" == \
      "$contract_cell_source_identity" ]] || return 1
  [[ "$(create_stable_file_snapshot \
      "$contract_source_authority_source" "$authority_snapshot" false 0400)" == \
      "$contract_source_authority_source_identity" ]] || return 1
  cell="$requested_snapshot"
  source_authority="$authority_snapshot"
  validate_contract_inputs
}

validate_json_file() {
  local -r path="$1"
  local size=""

  [[ -f "$path" && ! -L "$path" ]] || return 1
  size="$(stat -Lc '%s' -- "$path")" || return
  [[ "$size" =~ ^[0-9]+$ ]] || return 1
  (( size <= 67108864 )) || return 1
  python3 - "$path" <<'PY'
import json
import math
import sys

def reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    value = json.load(
        stream,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicates,
    )

def validate_numbers(item):
    if isinstance(item, bool) or item is None or isinstance(item, str):
        return
    if isinstance(item, int):
        if abs(item) > 9_007_199_254_740_991:
            raise ValueError("integer exceeds exact JSON range")
        return
    if isinstance(item, float):
        if not math.isfinite(item) or abs(item) > 9_007_199_254_740_991:
            raise ValueError("invalid JSON float")
        return
    if isinstance(item, list):
        for child in item:
            validate_numbers(child)
        return
    if isinstance(item, dict):
        for child in item.values():
            validate_numbers(child)
        return
    raise ValueError("unsupported JSON value")

validate_numbers(value)
PY
}

parse_arguments() {
  while (( $# > 0 )); do
    case "$1" in
      --contract)
        (( $# >= 2 )) || return 2
        [[ -z "$contract" ]] || return 2
        contract="$2"
        shift 2
        ;;
      --campaign)
        (( $# >= 2 )) || return 2
        [[ -z "$campaign" ]] || return 2
        campaign="$2"
        shift 2
        ;;
      --campaign-revision)
        (( $# >= 2 )) || return 2
        [[ -z "$campaign_revision" ]] || return 2
        campaign_revision="$2"
        shift 2
        ;;
      --plan-sha256)
        (( $# >= 2 )) || return 2
        [[ -z "$plan_sha256" ]] || return 2
        plan_sha256="$2"
        shift 2
        ;;
      --cell)
        (( $# >= 2 )) || return 2
        [[ -z "$cell" ]] || return 2
        cell="$2"
        shift 2
        ;;
      --source-authority)
        (( $# >= 2 )) || return 2
        [[ -z "$source_authority" ]] || return 2
        source_authority="$2"
        shift 2
        ;;
      --source-authority-sha256)
        (( $# >= 2 )) || return 2
        [[ -z "$source_authority_sha256" ]] || return 2
        source_authority_sha256="$2"
        shift 2
        ;;
      --private-output)
        (( $# >= 2 )) || return 2
        [[ -z "$private_output" ]] || return 2
        private_output="$2"
        shift 2
        ;;
      *)
        return 2
        ;;
    esac
  done
}

validate_contract_inputs() {
  [[ "$contract" == compatibility-external-provider-v1 ]] ||
    die "unexpected external-provider contract" || return
  [[ "$campaign" == helper-lifecycle ]] ||
    die "lifecycle driver only accepts the helper-lifecycle campaign" || return
  [[ "$campaign_revision" == "$CAMPAIGN_REVISION" ]] ||
    die "unexpected helper-lifecycle campaign revision" || return
  [[ "$plan_sha256" == "$PLAN_SHA256" ]] ||
    die "unexpected helper-lifecycle plan digest" || return
  [[ "$source_authority_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$cell" == /* && "$source_authority" == /* && "$private_output" == /* ]] ||
    die "contract paths must be absolute" || return
  validate_json_file "$cell" || die "invalid requested cell JSON" || return
  validate_json_file "$source_authority" || die "invalid source authority JSON" || return
  [[ "$(sha256_file "$source_authority")" == "$source_authority_sha256" ]] ||
    die "source authority digest mismatch" || return
  [[ -d "$private_output" && ! -L "$private_output" ]] ||
    die "private output is not a regular directory" || return
  pin_private_output || die "could not retain private output authority" || return
  [[ ! -e "$private_output/provider-result.json" &&
    ! -L "$private_output/provider-result.json" ]] ||
    die "provider result already exists" || return
  jq -e '
    keys == [
      "git_tree", "patch_identity_sha256", "revision", "schema",
      "source_tree_sha256", "tracked_patch_sha256"
    ] and
    .schema == "compatibility-source-authority-v1" and
    (.revision | type == "string" and test("^[0-9a-f]{40}$")) and
    (.git_tree | type == "string" and test("^[0-9a-f]{40}$")) and
    all(.source_tree_sha256, .tracked_patch_sha256, .patch_identity_sha256;
      type == "string" and test("^[0-9a-f]{64}$"))
  ' "$source_authority" >/dev/null || die "source authority shape mismatch" || return
  jq -e '
    keys == [
      "agent_distribution", "agent_version", "architecture", "cgroup_topology",
      "deployment", "id", "jvm_feature", "kernel", "provider", "tls",
      "transport"
    ] and
    .kernel == "upstream-6.12" and .deployment == "container-process" and
    .cgroup_topology == "unified-v2" and .agent_distribution == "otel" and
    .agent_version == "2.28.1" and .tls == "TLSv1.3" and
    .provider == "preprovisioned-lifecycle-application-v1" and
    . as $requested |
    any([
      {id:"h-jdk8-amd64-otel-getsockopt",jvm_feature:8,architecture:"amd64",transport:"getsockopt"},
      {id:"h-jdk11-amd64-otel-getsockopt",jvm_feature:11,architecture:"amd64",transport:"getsockopt"},
      {id:"h-jdk17-amd64-otel-getsockopt",jvm_feature:17,architecture:"amd64",transport:"getsockopt"},
      {id:"h-jdk21-amd64-otel-getsockopt",jvm_feature:21,architecture:"amd64",transport:"getsockopt"},
      {id:"h-jdk21-amd64-otel-unix",jvm_feature:21,architecture:"amd64",transport:"unix"},
      {id:"h-jdk21-amd64-otel-auto",jvm_feature:21,architecture:"amd64",transport:"auto"},
      {id:"h-jdk21-arm64-otel-getsockopt",jvm_feature:21,architecture:"arm64",transport:"getsockopt"}
    ][];
      .id == $requested.id and .jvm_feature == $requested.jvm_feature and
      .architecture == $requested.architecture and
      .transport == $requested.transport)
  ' "$cell" >/dev/null || die "requested cell is not one exact helper-lifecycle cell" || return
}

driver_source_json() {
  jq -cS '{
    revision, source_tree_sha256, tracked_patch_sha256, patch_identity_sha256,
    clean: true
  }' "$source_authority"
}

driver_command_json() {
  printf '%s\0' "${DRIVER_ARGV[@]}" | jq -Rs 'split("\u0000")[:-1]'
}

write_untested() {
  local -r reason="$1"
  local requested=""
  local source=""
  local command_json=""
  local driver_sha256=""
  local candidate="$private_output/provider-result.json.candidate"
  local candidate_identity=""

  [[ "$reason" =~ ^[a-z0-9][a-z0-9-]{0,95}$ ]] || return 1
  requested="$(jq -cS . "$cell")" || return
  source="$(jq -cS '{revision, git_tree, clean:true}' "$source_authority")" || return
  command_json="$(driver_command_json)" || return
  driver_sha256="$(sha256_file "$DRIVER_PATH")" || return
  jq -nS \
    --arg campaign "$campaign" \
    --arg campaign_revision "$campaign_revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg reason "$reason" \
    --arg driver_sha256 "$driver_sha256" \
    --argjson requested "$requested" \
    --argjson source "$source" \
    --argjson command_argv "$command_json" '
      {
        schema: "compatibility-provider-result-v1",
        campaign: $campaign,
        campaign_revision: $campaign_revision,
        plan_sha256: $plan_sha256,
        cell_id: $requested.id,
        provider: $requested.provider,
        status: "untested",
        reason: $reason,
        attempted: true,
        infrastructure_failure: true,
        requested: $requested,
        command: {
          executed: true,
          argv: $command_argv,
          adapter_sha256: $driver_sha256,
          exit_status: 69
        },
        lifecycle_executor: null,
        source: $source,
        runtime: null,
        artifacts: null,
        assertions: null,
        evidence_index: null,
        raw_evidence: null
      }
    ' >"$candidate"
  chmod 0600 -- "$candidate"
  candidate_identity="$(safe_file_identity "$candidate" false)" || return
  publish_private_file_no_replace \
    "$candidate" "$candidate_identity" "$private_output/provider-result.json" ||
    return
  return 69
}

validate_environment_descriptor() {
  local -r descriptor="$1"
  local -r descriptor_sha256="$2"

  jq -e \
    --arg schema "$ENVIRONMENT_SCHEMA" \
    --arg descriptor_sha256 "$descriptor_sha256" \
    --slurpfile requested "$cell" '
      keys == ["cell", "executor", "id", "schema"] and
      .schema == $schema and
      (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$")) and
      .cell == $requested[0] and
      (.executor | keys == ["id", "path", "sha256"]) and
      (.executor.id | type == "string" and
        test("^[a-z0-9][a-z0-9-]{0,95}$")) and
      (.executor.path | type == "string" and
        test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$")) and
      (.executor.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      ($descriptor_sha256 | test("^[0-9a-f]{64}$"))
    ' "$descriptor" >/dev/null
}

validate_executor_registry() {
  local -r registry="$1"

  jq -e \
    --arg schema "$EXECUTOR_REGISTRY_SCHEMA" '
      def sha256: type == "string" and test("^[0-9a-f]{64}$");
      def token: type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$");
      def safe_path:
        type == "string" and
        test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$");
      [
        "h-jdk8-amd64-otel-getsockopt",
        "h-jdk11-amd64-otel-getsockopt",
        "h-jdk17-amd64-otel-getsockopt",
        "h-jdk21-amd64-otel-auto",
        "h-jdk21-amd64-otel-getsockopt",
        "h-jdk21-amd64-otel-unix",
        "h-jdk21-arm64-otel-getsockopt"
      ] as $cell_ids |
      keys == ["approved_executors", "schema"] and .schema == $schema and
      (.approved_executors | type == "array") and
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
    ' "$registry" >/dev/null
}

select_executor_approval() {
  local -r registry="$1"
  local -r registry_identity="$2"
  local -r descriptor="$3"
  local -r descriptor_identity="$4"
  local -r requested="$5"
  local -r requested_identity="$6"

  python3 - "$registry" "$registry_identity" \
    "$descriptor" "$descriptor_identity" \
    "$requested" "$requested_identity" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


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


def read_exact(path, expected_identity):
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("approval input is not regular")
        if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
            raise RuntimeError("approval input has unsafe ownership or links")
        if before.st_size <= 0 or before.st_size > 16 * 1024 * 1024:
            raise RuntimeError("approval input has an unsafe size")
        payload = bytearray()
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
            digest.update(chunk)
            if len(payload) > 16 * 1024 * 1024:
                raise RuntimeError("approval input grew beyond its byte bound")
        after = os.fstat(descriptor)
        fields = (
            "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
            "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise RuntimeError("approval input changed while reading")
        current = os.stat(path, follow_symlinks=False)
        if any(getattr(after, field) != getattr(current, field) for field in fields):
            raise RuntimeError("approval input path changed while reading")
        if identity_text(after, digest.hexdigest()) != expected_identity:
            raise RuntimeError("approval input differs from its retained identity")
        return json.loads(
            bytes(payload).decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    finally:
        os.close(descriptor)


registry_path, registry_identity, environment_path, environment_identity, requested_path, requested_identity = sys.argv[1:7]
registry = read_exact(registry_path, registry_identity)
environment = read_exact(environment_path, environment_identity)
requested = read_exact(requested_path, requested_identity)
token = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
safe_path = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$"
)
sha256 = re.compile(r"^[0-9a-f]{64}$")
cell_ids = {
    "h-jdk8-amd64-otel-getsockopt",
    "h-jdk11-amd64-otel-getsockopt",
    "h-jdk17-amd64-otel-getsockopt",
    "h-jdk21-amd64-otel-auto",
    "h-jdk21-amd64-otel-getsockopt",
    "h-jdk21-amd64-otel-unix",
    "h-jdk21-arm64-otel-getsockopt",
}
if set(registry) != {"approved_executors", "schema"} or registry["schema"] != "compatibility-lifecycle-executor-registry-v1":
    raise RuntimeError("invalid retained executor registry")
approvals = registry["approved_executors"]
if not isinstance(approvals, list) or len(approvals) > 256:
    raise RuntimeError("invalid retained executor approvals")
seen_ids = set()
seen_paths = set()
seen_digests = set()
for approval in approvals:
    if not isinstance(approval, dict) or set(approval) != {"allowed_cell_ids", "id", "path", "sha256"}:
        raise RuntimeError("malformed retained executor approval")
    allowed = approval["allowed_cell_ids"]
    if not token.fullmatch(approval["id"]) or not safe_path.fullmatch(approval["path"]) or not sha256.fullmatch(approval["sha256"]):
        raise RuntimeError("malformed retained executor approval value")
    if not isinstance(allowed, list) or not allowed or allowed != sorted(set(allowed)) or any(value not in cell_ids for value in allowed):
        raise RuntimeError("malformed retained executor cell roster")
    if approval["id"] in seen_ids or approval["path"] in seen_paths or approval["sha256"] in seen_digests:
        raise RuntimeError("duplicate retained executor approval")
    seen_ids.add(approval["id"])
    seen_paths.add(approval["path"])
    seen_digests.add(approval["sha256"])
if not isinstance(environment, dict) or set(environment) != {"cell", "executor", "id", "schema"} or environment["schema"] != "compatibility-helper-lifecycle-environment-v1":
    raise RuntimeError("invalid retained lifecycle environment")
executor = environment["executor"]
if environment["cell"] != requested or not token.fullmatch(environment["id"]) or not isinstance(executor, dict) or set(executor) != {"id", "path", "sha256"}:
    raise RuntimeError("invalid retained lifecycle environment binding")
if not token.fullmatch(executor["id"]) or not safe_path.fullmatch(executor["path"]) or not sha256.fullmatch(executor["sha256"]):
    raise RuntimeError("invalid retained lifecycle executor request")
matches = [
    approval for approval in approvals
    if approval["id"] == executor["id"]
    and approval["path"] == executor["path"]
    and approval["sha256"] == executor["sha256"]
    and requested["id"] in approval["allowed_cell_ids"]
]
if len(matches) != 1:
    raise SystemExit(1)
sys.stdout.write(json.dumps(matches[0], sort_keys=True, separators=(",", ":")) + "\n")
PY
}

status_matches_exit() {
  local -r status="$1"
  local -r exit_status="$2"

  [[ "$exit_status" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  (( exit_status <= 255 )) || return 1
  case "$status" in
    pass) (( exit_status == 0 )) ;;
    fail) (( exit_status != 0 && exit_status != 69 && exit_status != 78 )) ;;
    unsupported) (( exit_status == 78 )) ;;
    untested) (( exit_status == 69 )) ;;
    *) return 1 ;;
  esac
}

validate_observation_envelope() {
  local -r result="$1"
  local -r environment_id="$2"
  local -r environment_sha256="$3"
  local -r executor_sha256="$4"
  local -r invocation_status="$5"
  local -r command_json="$6"
  local observed_status=""

  validate_json_file "$result" || return
  observed_status="$(jq -er '.status | select(type == "string")' "$result")" || return
  status_matches_exit "$observed_status" "$invocation_status" || return 1
  jq -e \
    --arg schema "$RESULT_SCHEMA" \
    --arg campaign_revision "$campaign_revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg environment_id "$environment_id" \
    --arg environment_sha256 "$environment_sha256" \
    --arg executor_sha256 "$executor_sha256" \
    --argjson invocation_status "$invocation_status" \
    --argjson command "$command_json" \
    --slurpfile requested "$cell" '
      keys == [
        "artifacts", "assertions", "campaign_revision", "command", "environment",
        "evidence_index", "plan_sha256", "raw_evidence", "reason", "requested",
        "runtime", "schema", "status"
      ] and
      .schema == $schema and .campaign_revision == $campaign_revision and
      .plan_sha256 == $plan_sha256 and .requested == $requested[0] and
      (.reason | type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$")) and
      .environment == {id:$environment_id, sha256:$environment_sha256} and
      .command == {
        argv:$command, executable_sha256:$executor_sha256,
        exit_status:$invocation_status
      } and
      (if .status == "untested" then
        .runtime == null and .artifacts == null and .assertions == null and
        .evidence_index == null and .raw_evidence == null
       else
        (.runtime | type) == "object" and (.artifacts | type) == "object" and
        (.assertions | type) == "object" and
        (.evidence_index | type == "array" and length > 0 and length <= 512) and
        .raw_evidence == {
          directory:"raw", manifest:"raw.sha256",
          manifest_sha256:.raw_evidence.manifest_sha256
        } and
        (.raw_evidence.manifest_sha256 | type == "string" and
          test("^[0-9a-f]{64}$"))
       end)
    ' "$result" >/dev/null
}

validate_helper_pass_assertions() {
  local -r result="$1"

  [[ "$(jq -er '.status' "$result")" == pass ]] || return 0
  jq -e \
    --argjson max_assertion_count "$MAX_ASSERTION_COUNT" \
    --argjson max_resource_magnitude "$MAX_RESOURCE_MAGNITUDE" '
      def sha256: type == "string" and test("^[0-9a-f]{64}$");
      def safe_uint:
        type == "number" and floor == . and . >= 0 and
        . <= $max_assertion_count;
      def safe_int:
        type == "number" and floor == . and
        . >= -$max_resource_magnitude and . <= $max_resource_magnitude;
      def safe_resource_uint:
        type == "number" and floor == . and . >= 0 and
        . <= $max_resource_magnitude;
      def bounded_float:
        type == "number" and
        . >= -$max_resource_magnitude and . <= $max_resource_magnitude;
      def request_gate:
        type == "object" and keys == [
          "crashes", "evidence_sha256", "exact_parents", "requests", "status",
          "wrong_parents"
        ] and .status == "pass" and (.evidence_sha256 | sha256) and
        (.requests | safe_uint and . > 0) and (.exact_parents | safe_uint) and
        (.wrong_parents | safe_uint) and (.crashes | safe_uint) and
        .exact_parents == .requests and .wrong_parents == 0 and .crashes == 0;
      (.assertions | keys == [
        "application_result", "cleanup", "exact_parent", "frameworks", "lifecycle",
        "product_failure", "required_cells_skipped", "resource_gates",
        "unavailable_bridge", "virtual_thread"
      ]) and
      .assertions.application_result == "pass" and .assertions.cleanup == "pass" and
      .assertions.product_failure == false and
      .assertions.required_cells_skipped == false and
      (.assertions.exact_parent | keys == ["matched", "requests", "status", "wrong"]) and
      .assertions.exact_parent.status == "pass" and
      (.assertions.exact_parent.requests | safe_uint and . > 0) and
      .assertions.exact_parent.matched == .assertions.exact_parent.requests and
      .assertions.exact_parent.wrong == 0 and
      (.assertions.frameworks | keys | sort) == [
        "blocking-sslsocket", "netty-sslhandler", "sslengine-socketchannel"
      ] and all(.assertions.frameworks[]; request_gate) and
      (.assertions.lifecycle | keys | sort) == [
        "cross-request-isolation", "cross-thread-handoff", "duplicate-callback",
        "executor-handoff", "extension-absent", "extension-loaded-first",
        "fallback-context-unavailable", "helper-early-attach", "helper-late-attach",
        "normal-extraction", "obi-absent", "obi-restart", "platform-thread",
        "stale-state", "unsupported-transport", "version-mismatch"
      ] and all(.assertions.lifecycle[]; request_gate) and
      (.assertions.resource_gates | keys | sort) == [
        "classloader-weak-reference", "direct-buffer", "live-thread", "native-fd",
        "request-state", "same-process-identity", "task-state", "thread-local-state"
      ] and
      all(.assertions.resource_gates[];
        type == "object" and keys == [
          "allowed_delta", "baseline", "cycles", "delta", "evidence_sha256", "final",
          "maximum_trend_slope", "status", "trend_slope"
        ] and .status == "pass" and (.evidence_sha256 | sha256) and
        (.cycles | safe_uint and . >= 3) and (.baseline | safe_resource_uint) and
        (.final | safe_resource_uint) and (.delta | safe_int) and
        .delta == (.final - .baseline) and (.allowed_delta | safe_uint) and
        .delta <= .allowed_delta and (.trend_slope | bounded_float) and
        (.maximum_trend_slope | bounded_float and . >= 0) and
        .trend_slope <= .maximum_trend_slope) and
      (.assertions.unavailable_bridge | keys == [
        "diagnostics", "normal_agent_extraction", "normal_result_sha256",
        "result_equivalent", "status", "unavailable_result_sha256"
      ]) and .assertions.unavailable_bridge.status == "pass" and
      .assertions.unavailable_bridge.result_equivalent == true and
      (.assertions.unavailable_bridge.normal_result_sha256 | sha256) and
      .assertions.unavailable_bridge.normal_result_sha256 ==
        .assertions.unavailable_bridge.unavailable_result_sha256 and
      (.assertions.unavailable_bridge.normal_agent_extraction | request_gate) and
      (.assertions.unavailable_bridge.diagnostics | keys == [
        "bytes", "count", "evidence_sha256", "max_bytes", "max_count", "status"
      ]) and .assertions.unavailable_bridge.diagnostics.status == "pass" and
      (.assertions.unavailable_bridge.diagnostics.evidence_sha256 | sha256) and
      (.assertions.unavailable_bridge.diagnostics.count | safe_uint) and
      (.assertions.unavailable_bridge.diagnostics.bytes | safe_uint) and
      .assertions.unavailable_bridge.diagnostics.max_count == 64 and
      .assertions.unavailable_bridge.diagnostics.max_bytes == 65536 and
      .assertions.unavailable_bridge.diagnostics.count <= 64 and
      .assertions.unavailable_bridge.diagnostics.bytes <= 65536 and
      (if .requested.jvm_feature == 21 then
        (.assertions.virtual_thread | request_gate)
       else
        (.assertions.virtual_thread | keys == ["evidence_sha256", "reason", "status"]) and
        .assertions.virtual_thread.status == "unsupported" and
        .assertions.virtual_thread.reason == "requires-java-21" and
        (.assertions.virtual_thread.evidence_sha256 | sha256)
       end)
    ' "$result" >/dev/null
}

validate_raw_bundle() {
  local -r result="$1"
  local -r output_directory="$2"
  local raw="$output_directory/raw"
  local manifest="$output_directory/raw.sha256"
  local observed="$private_output/raw-manifest.observed"
  local indexed="$private_output/evidence-index.observed"
  local path=""
  local relative=""
  local metadata=""
  local owner=""
  local mode=""
  local links=""
  local size=""
  local total=0
  local count=0
  local field=""
  local digest=""

  [[ -d "$raw" && ! -L "$raw" && -f "$manifest" && ! -L "$manifest" ]] || return 1
  [[ "$(sha256_file "$manifest")" == \
    "$(jq -er '.raw_evidence.manifest_sha256' "$result")" ]] || return 1
  if find "$raw" -xdev -mindepth 1 \( -type l -o \( ! -type f ! -type d \) \) \
    -print -quit | grep -q .; then
    return 1
  fi
  : >"$observed"
  while IFS= read -r -d '' path; do
    relative="${path#"$raw"/}"
    [[ "$relative" != "$path" && "$relative" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$ ]] || return 1
    metadata="$(stat -Lc '%u:%a:%h:%s' -- "$path")" || return
    IFS=: read -r owner mode links size <<<"$metadata"
    [[ "$owner" == "$EUID" && "$links" == 1 && "$size" =~ ^[0-9]+$ ]] || return 1
    (( (8#$mode & 0022) == 0 )) || return 1
    (( count += 1, total += size ))
    (( count <= MAX_RAW_FILES && total <= MAX_RAW_BYTES )) || return 1
    printf '%s  %s\n' "$(sha256_file "$path")" "$relative" >>"$observed"
  done < <(find "$raw" -xdev -mindepth 1 -type f -print0 | LC_ALL=C sort -z)
  cmp -s -- "$observed" "$manifest" || return 1
  jq -e '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    . as $root |
    [($root.runtime // {}), ($root.artifacts // {}), ($root.assertions // {})] as $roots |
    ([range(0; $roots | length) as $root_index |
      ($roots[$root_index] | paths(scalars) as $path |
        ($path[-1] | tostring) as $leaf |
        select($leaf == "sha256" or ($leaf | endswith("_sha256"))) |
        {
          field: ([( ["runtime", "artifacts", "assertions"][$root_index])] +
            ($path | map(tostring)) | join(".")),
          sha256: getpath($path)
        })] +
      (if $root.lifecycle_executor? == null then [] else [{
        field:"lifecycle_executor.receipt_sha256",
        sha256:$root.lifecycle_executor.receipt_sha256
      }] end) | sort_by(.field)) as $expected |
    ($root.evidence_index | map({field,sha256}) | sort_by(.field)) == $expected and
    ([$root.evidence_index[].field] | unique | length) == ($root.evidence_index | length) and
    ([$root.evidence_index[].path] | unique | length) == ($root.evidence_index | length) and
    ([$root.evidence_index[].field] | sort) == [$root.evidence_index[].field] and
    all($root.evidence_index[];
      (.field | type == "string" and
        test("^(runtime|artifacts|assertions|lifecycle_executor)([.][A-Za-z0-9_-]+)+$")) and
      (.path | type == "string" and
        test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$")) and
      (.sha256 | sha256))
  ' "$result" >/dev/null || return
  jq -r '.evidence_index[] | [.field,.path,.sha256] | @tsv' "$result" >"$indexed" || return
  while IFS=$'\t' read -r field relative digest; do
    [[ -n "$field" && -n "$relative" && "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$(sha256_file "$raw/$relative")" == "$digest" ]] || return 1
    grep -Fqx -- "$digest  $relative" "$manifest" || return 1
  done <"$indexed"
  rm -f -- "$observed" "$indexed"
}

validate_unavailable_bridge_files() {
  local -r result="$1"
  local -r raw="$2"
  local normal_path=""
  local unavailable_path=""
  local extraction_path=""
  local diagnostics_path=""
  local diagnostics_size=""

  [[ "$(jq -er '.status' "$result")" == pass ]] || return 0
  normal_path="$(jq -er '.evidence_index[] | select(.field == "assertions.unavailable_bridge.normal_result_sha256") | .path' "$result")" || return
  unavailable_path="$(jq -er '.evidence_index[] | select(.field == "assertions.unavailable_bridge.unavailable_result_sha256") | .path' "$result")" || return
  extraction_path="$(jq -er '.evidence_index[] | select(.field == "assertions.unavailable_bridge.normal_agent_extraction.evidence_sha256") | .path' "$result")" || return
  diagnostics_path="$(jq -er '.evidence_index[] | select(.field == "assertions.unavailable_bridge.diagnostics.evidence_sha256") | .path' "$result")" || return
  cmp -s -- "$raw/$normal_path" "$raw/$unavailable_path" || return 1
  validate_json_file "$raw/$extraction_path" || return
  jq -e --slurpfile result "$result" '
    $result[0].assertions.unavailable_bridge.normal_agent_extraction as $expected |
    keys == ["crashes", "exact_parents", "requests", "schema", "status", "wrong_parents"] and
    .schema == "compatibility-normal-agent-extraction-v1" and
    .status == $expected.status and .requests == $expected.requests and
    .exact_parents == $expected.exact_parents and
    .wrong_parents == $expected.wrong_parents and .crashes == $expected.crashes
  ' "$raw/$extraction_path" >/dev/null || return
  validate_json_file "$raw/$diagnostics_path" || return
  diagnostics_size="$(stat -Lc '%s' -- "$raw/$diagnostics_path")" || return
  jq -e --argjson bytes "$diagnostics_size" --slurpfile result "$result" '
    $result[0].assertions.unavailable_bridge.diagnostics as $expected |
    keys == ["diagnostics", "schema"] and
    .schema == "compatibility-unavailable-bridge-diagnostics-v1" and
    (.diagnostics | type == "array" and length == $expected.count) and
    all(.diagnostics[];
      type == "string" and length <= 1024 and
      (explode | all(. >= 32 and . <= 126)) and
      (test("secret|password|passwd|token|credential|private[-_]?key"; "i") | not)) and
    $bytes == $expected.bytes and $bytes <= $expected.max_bytes
  ' "$raw/$diagnostics_path" >/dev/null
}

run_supervised_executor() {
  local -r working_directory="$1"
  local -r stdout_file="$2"
  local -r stderr_file="$3"
  local -r executor_snapshot="$4"
  local -r expected_executor_identity="$5"
  shift 5

  python3 - "$working_directory" "$stdout_file" "$stderr_file" \
    "$executor_snapshot" "$expected_executor_identity" "$@" <<'PY'
import ctypes
import errno
import hashlib
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import time


PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
EXECUTION_TIMEOUT_SECONDS = 6900
TERM_GRACE_SECONDS = 5
KILL_GRACE_SECONDS = 10
OUTPUT_FILE_LIMIT_BYTES = 16 * 1024 * 1024


def fail(message):
    raise RuntimeError(message)


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


def descendant_identities(root_pid):
    processes = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    for name in names:
        if not name.isdigit():
            continue
        identity = process_identity(int(name))
        if identity is not None:
            processes[identity["pid"]] = identity
    pending = [root_pid]
    depths = {root_pid: 0}
    descendants = []
    while pending:
        parent = pending.pop()
        for identity in processes.values():
            if identity["ppid"] != parent or identity["pid"] in depths:
                continue
            depth = depths[parent] + 1
            depths[identity["pid"]] = depth
            identity = dict(identity)
            identity["depth"] = depth
            descendants.append(identity)
            pending.append(identity["pid"])
    return sorted(descendants, key=lambda item: item["depth"], reverse=True)


def same_process_authority(left, right):
    return left is not None and right is not None and all(
        left[key] == right[key] for key in ("pid", "starttime")
    )


def same_topology(left, right):
    return left is not None and right is not None and all(
        left[key] == right[key] for key in ("session", "pgrp")
    )


def reap_exited_children():
    while True:
        try:
            waited, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if waited == 0:
            return


tracked = {}
topology_changed = False
leader_authority = None


def remember_descendants(root_pid):
    global topology_changed
    for observed in descendant_identities(root_pid):
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
        if leader_authority in tracked and key != leader_authority and (
            observed["session"], observed["pgrp"]
        ) != (
            tracked[leader_authority][0]["session"],
            tracked[leader_authority][0]["pgrp"],
        ):
            topology_changed = True
        tracked[key] = (dict(observed), descriptor)


def identity_is_live(identity):
    return same_process_authority(process_identity(identity["pid"]), identity)


def live_descendants(root_pid):
    remember_descendants(root_pid)
    return [
        observed
        for observed, _ in tracked.values()
        if identity_is_live(observed)
    ]


def signal_tracked(requested_signal):
    for observed, descriptor in list(tracked.values()):
        if not identity_is_live(observed):
            continue
        try:
            signal.pidfd_send_signal(descriptor, requested_signal)
        except ProcessLookupError:
            pass


def terminate_descendants(root_pid):
    for requested_signal, grace in (
        (signal.SIGTERM, TERM_GRACE_SECONDS),
        (signal.SIGKILL, KILL_GRACE_SECONDS),
    ):
        deadline = time.monotonic() + grace
        while True:
            current = live_descendants(root_pid)
            if not current:
                reap_exited_children()
                if not descendant_identities(root_pid):
                    return True
            signal_tracked(requested_signal)
            reap_exited_children()
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
    reap_exited_children()
    return not live_descendants(root_pid) and not descendant_identities(root_pid)


def normalize_status(return_code):
    if return_code is None:
        return 255
    if return_code < 0:
        return min(255, 128 + (-return_code))
    return min(255, return_code)


working_directory, stdout_path, stderr_path, executor_path, expected_executor_identity = sys.argv[1:6]
command = sys.argv[6:]
if not command or command[0] != "/proc/self/fd/9":
    fail("invalid descriptor-bound executor command")
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    fail("pidfd signalling is unavailable")
self_pidfd = os.pidfd_open(os.getpid(), 0)
try:
    signal.pidfd_send_signal(self_pidfd, 0)
finally:
    os.close(self_pidfd)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))
subreaper_state = ctypes.c_int(0)
if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(subreaper_state), 0, 0, 0) != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))
if subreaper_state.value != 1:
    fail("subreaper capability did not remain active")


def descriptor_identity(descriptor):
    before = os.fstat(descriptor)
    mode = stat.S_IMODE(before.st_mode)
    if not stat.S_ISREG(before.st_mode):
        fail("executor descriptor is not regular")
    if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
        fail("executor descriptor has unsafe ownership or link count")
    if before.st_size <= 0 or before.st_size > 16 * 1024 * 1024:
        fail("executor descriptor has an unsafe size")
    if mode & 0o022 or not mode & 0o111:
        fail("executor descriptor has unsafe permissions")
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
        fail("executor descriptor changed while hashing")
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


executor_fd = os.open(
    executor_path,
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
)
if executor_fd != 9:
    os.dup2(executor_fd, 9, inheritable=True)
    os.close(executor_fd)
executor_fd = 9
executor_descriptor_identity = descriptor_identity(executor_fd)
if executor_descriptor_identity != expected_executor_identity:
    fail("executor descriptor differs from its retained identity")
executor_path_state = os.stat(executor_path, follow_symlinks=False)
if any(
    getattr(executor_path_state, field) != getattr(os.fstat(executor_fd), field)
    for field in (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
):
    fail("executor path differs from its opened descriptor")

open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
stdout_fd = os.open(stdout_path, open_flags, 0o600)
try:
    stderr_fd = os.open(stderr_path, open_flags, 0o600)
except Exception:
    os.close(stdout_fd)
    raise


def prepare_executor():
    os.setsid()
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (OUTPUT_FILE_LIMIT_BYTES, OUTPUT_FILE_LIMIT_BYTES),
    )


primary = None
timed_out = False
containment_violation = False
cleanup_complete = False
observed_descendants = 0
try:
    primary = subprocess.Popen(
        command,
        cwd=working_directory,
        stdin=subprocess.DEVNULL,
        stdout=stdout_fd,
        stderr=stderr_fd,
        close_fds=True,
        pass_fds=(9,),
        preexec_fn=prepare_executor,
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
        fail("executor leader lacks an exact session identity")
    leader_authority = (leader["pid"], leader["starttime"])
    leader_pidfd = os.pidfd_open(leader["pid"], 0)
    if not same_process_authority(process_identity(leader["pid"]), leader):
        os.close(leader_pidfd)
        fail("executor leader changed before pidfd authentication")
    tracked[leader_authority] = (dict(leader), leader_pidfd)
    deadline = time.monotonic() + EXECUTION_TIMEOUT_SECONDS
    while primary.poll() is None and time.monotonic() < deadline:
        remember_descendants(os.getpid())
        time.sleep(0.05)
    if primary.returncode is None:
        timed_out = True
        initial = descendant_identities(os.getpid())
        extra = [item for item in initial if item["pid"] != primary.pid]
        containment_violation = bool(extra) or topology_changed
        observed_descendants = len(extra)
        cleanup_complete = terminate_descendants(os.getpid())
        try:
            primary.wait(timeout=1)
        except subprocess.TimeoutExpired:
            cleanup_complete = False
    else:
        initial = descendant_identities(os.getpid())
        extra = [item for item in initial if item["pid"] != primary.pid]
        containment_violation = bool(extra) or topology_changed
        observed_descendants = len(extra)
        cleanup_complete = terminate_descendants(os.getpid())
        reap_exited_children()
        if descendant_identities(os.getpid()):
            cleanup_complete = False
finally:
    try:
        if descriptor_identity(executor_fd) != expected_executor_identity:
            containment_violation = True
            cleanup_complete = False
        current_path = os.stat(executor_path, follow_symlinks=False)
        current_descriptor = os.fstat(executor_fd)
        if any(
            getattr(current_path, field) != getattr(current_descriptor, field)
            for field in (
                "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns",
            )
        ):
            containment_violation = True
            cleanup_complete = False
    except (OSError, RuntimeError):
        containment_violation = True
        cleanup_complete = False
    os.close(stdout_fd)
    os.close(stderr_fd)
    os.close(executor_fd)
    for _, descriptor in tracked.values():
        os.close(descriptor)

result = {
    "cleanup_complete": cleanup_complete,
    "containment_violation": containment_violation,
    "executor_exit_status": normalize_status(
        None if primary is None else primary.returncode
    ),
    "executor_descriptor_identity": executor_descriptor_identity,
    "observed_descendants": observed_descendants,
    "schema": "compatibility-lifecycle-executor-supervision-v1",
    "timed_out": timed_out,
}
containment_violation = containment_violation or topology_changed
result["containment_violation"] = containment_violation
json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
}

write_provider_result() {
  local -r observation="$1"
  local -r invocation_status="$2"
  local -r lifecycle_executor="$3"
  local -r raw_manifest_sha256="$4"
  local driver_sha256=""
  local command_json=""
  local source=""
  local source_git_tree=""
  local candidate="$private_output/provider-result.json.candidate"
  local candidate_identity=""

  driver_sha256="$(sha256_file "$DRIVER_PATH")" || return
  command_json="$(driver_command_json)" || return
  source="$(driver_source_json)" || return
  source_git_tree="$(jq -er '.git_tree' "$source_authority")" || return
  jq -nS \
    --arg campaign "$campaign" \
    --arg campaign_revision "$campaign_revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg driver_sha256 "$driver_sha256" \
    --arg source_git_tree "$source_git_tree" \
    --arg raw_manifest_sha256 "$raw_manifest_sha256" \
    --argjson invocation_status "$invocation_status" \
    --argjson command_argv "$command_json" \
    --argjson lifecycle_executor "$lifecycle_executor" \
    --argjson source "$source" \
    --slurpfile observed "$observation" '
      $observed[0] as $o |
      {
        schema: "compatibility-provider-result-v1",
        campaign: $campaign,
        campaign_revision: $campaign_revision,
        plan_sha256: $plan_sha256,
        cell_id: $o.requested.id,
        provider: $o.requested.provider,
        status: $o.status,
        reason: $o.reason,
        attempted: true,
        infrastructure_failure: ($o.status == "untested"),
        requested: $o.requested,
        command: {
          executed: true,
          argv: $command_argv,
          adapter_sha256: $driver_sha256,
          exit_status: $invocation_status
        },
        lifecycle_executor: $lifecycle_executor,
        source:
          (if $o.status == "untested" then
            {revision:$source.revision, git_tree:$source_git_tree, clean:true}
           else $source end),
        runtime: $o.runtime,
        artifacts: $o.artifacts,
        assertions: $o.assertions,
        evidence_index:
          ((($o.evidence_index // []) + [{
            field:"lifecycle_executor.receipt_sha256",
            path:"lifecycle-execution-receipt.json",
            sha256:$lifecycle_executor.receipt_sha256
          }]) | sort_by(.field)),
        raw_evidence: {
          directory:"external/environment-output/raw",
          manifest:"external/environment-output/raw.sha256",
          manifest_sha256:$raw_manifest_sha256
        }
      }
    ' >"$candidate" || return
  chmod 0600 -- "$candidate"
  candidate_identity="$(safe_file_identity "$candidate" false)" || return
  publish_private_file_no_replace \
    "$candidate" "$candidate_identity" "$private_output/provider-result.json"
}

run_preprovisioned_environment() {
  local environment_path="${OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT:-}"
  local expected_environment_sha256="${OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256:-}"
  local executor_registry_source_path=\
"${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY:-}"
  local executor_registry_path=\
"${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SNAPSHOT:-$executor_registry_source_path}"
  local expected_executor_registry_sha256="${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SHA256:-}"
  local expected_executor_registry_source_identity=\
"${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SOURCE_IDENTITY:-}"
  local expected_executor_registry_snapshot_identity=\
"${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SNAPSHOT_IDENTITY:-}"
  local executor_registry_identity=""
  local executor_registry_snapshot=""
  local executor_registry_snapshot_identity=""
  local executor_registry_sha256=""
  local executor_registry_directory=""
  local environment_identity=""
  local environment_snapshot="$private_output/lifecycle-environment.snapshot.json"
  local environment_snapshot_identity=""
  local environment_sha256=""
  local environment_id=""
  local approval=""
  local approval_id=""
  local executor_relative_path=""
  local executor_path=""
  local executor_sha256=""
  local executor_identity=""
  local executor_snapshot="$private_output/lifecycle-executor.snapshot"
  local executor_snapshot_identity=""
  local executor_descriptor_identity=""
  local requested_identity=""
  local requested_snapshot="$cell"
  local requested_snapshot_sha256=""
  local source_authority_identity=""
  local source_authority_snapshot="$source_authority"
  local environment_output="$private_output/environment-output"
  local observation="$environment_output/result.json"
  local stdout_file="$private_output/lifecycle-executor.stdout"
  local stderr_file="$private_output/lifecycle-executor.stderr"
  local private_authority="$private_output/lifecycle-execution-authority.json"
  local receipt=""
  local receipt_sha256=""
  local manifest_candidate="$private_output/raw-manifest.with-receipt"
  local raw_manifest_sha256=""
  local manifest_candidate_identity=""
  local replaced_manifest_identity=""
  local lifecycle_executor=""
  local command_json=""
  local supervision_result=""
  local supervision=""
  local supervision_status=0
  local invocation_status=0
  local observed_status=""
  local -a command=()

  if [[ -z "$environment_path" || -z "$expected_environment_sha256" ]]; then
    write_untested lifecycle-environment-unavailable
    return $?
  fi
  if [[ -z "$executor_registry_source_path" || -z "$executor_registry_path" ||
    -z "$expected_executor_registry_sha256" ]]; then
    write_untested lifecycle-executor-registry-unavailable
    return $?
  fi
  if [[ ! "$expected_executor_registry_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    ! executor_registry_identity="$(safe_file_identity "$executor_registry_path" false)" ||
    [[ "${executor_registry_identity##*:}" != \
      "$expected_executor_registry_sha256" ]]; then
    write_untested lifecycle-executor-registry-identity-invalid
    return $?
  fi
  if [[ -n "$expected_executor_registry_snapshot_identity" &&
    "$executor_registry_identity" != \
      "$expected_executor_registry_snapshot_identity" ]]; then
    write_untested lifecycle-executor-registry-identity-invalid
    return $?
  fi
  executor_registry_directory="$(dirname -- "$executor_registry_source_path")" ||
    return
  executor_registry_directory="$(cd -- "$executor_registry_directory" && pwd -P)" ||
    return
  [[ "$(readlink -f -- "$executor_registry_source_path")" == \
    "$executor_registry_directory/lifecycle-executor-registry-v1.json" ]] || {
    write_untested lifecycle-executor-registry-path-invalid
    return $?
  }
  executor_registry_snapshot="$executor_registry_path"
  executor_registry_snapshot_identity="$executor_registry_identity"
  executor_registry_sha256="$(sha256_file "$executor_registry_snapshot")" || return
  [[ "$executor_registry_sha256" == "$expected_executor_registry_sha256" ]] ||
    return 1
  validate_json_file "$executor_registry_snapshot" || return
  validate_executor_registry "$executor_registry_snapshot" || {
    write_untested lifecycle-executor-registry-invalid
    return $?
  }
  file_identity_is_unchanged \
    "$executor_registry_path" false "$executor_registry_identity" || {
    write_untested lifecycle-executor-registry-changed-before-execution
    return $?
  }
  if [[ -n "$expected_executor_registry_source_identity" ]]; then
    [[ "$(safe_file_identity "$executor_registry_source_path" false)" == \
      "$expected_executor_registry_source_identity" ]] || {
      write_untested lifecycle-executor-registry-changed-before-execution
      return $?
    }
  fi
  if [[ ! "$expected_environment_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    ! environment_identity="$(safe_file_identity "$environment_path" false)" ||
    [[ "${environment_identity##*:}" != "$expected_environment_sha256" ]]; then
    write_untested lifecycle-environment-identity-invalid
    return $?
  fi
  [[ "$(create_stable_file_snapshot \
      "$environment_path" "$environment_snapshot" false 0400)" == \
      "$environment_identity" ]] || return 1
  environment_snapshot_identity="$(safe_file_identity \
    "$environment_snapshot" false)" || return
  environment_sha256="$(sha256_file "$environment_snapshot")" || return
  [[ "$environment_sha256" == "$expected_environment_sha256" ]] || return 1
  validate_json_file "$environment_snapshot" || {
    write_untested lifecycle-environment-descriptor-invalid
    return $?
  }
  validate_environment_descriptor "$environment_snapshot" "$environment_sha256" || {
    write_untested lifecycle-environment-cell-mismatch
    return $?
  }
  file_identity_is_unchanged "$environment_path" false "$environment_identity" || {
    write_untested lifecycle-environment-changed-before-execution
    return $?
  }
  requested_identity="$(safe_file_identity "$cell" false)" || return
  source_authority_identity="$(safe_file_identity "$source_authority" false)" ||
    return
  environment_id="$(jq -er '.id' "$environment_snapshot")" || return
  approval="$(select_executor_approval \
    "$executor_registry_snapshot" "$executor_registry_snapshot_identity" \
    "$environment_snapshot" "$environment_snapshot_identity" \
    "$cell" "$requested_identity" 2>/dev/null || true)"
  if [[ -z "$approval" ]]; then
    write_untested lifecycle-executor-not-approved
    return $?
  fi
  approval_id="$(jq -er '.id' <<<"$approval")" || return
  executor_relative_path="$(jq -er '.path' <<<"$approval")" || return
  executor_path="$executor_registry_directory/$executor_relative_path"
  [[ "$(readlink -f -- "$executor_path" 2>/dev/null || true)" == "$executor_path" ]] || {
    write_untested lifecycle-executor-source-path-invalid
    return $?
  }
  executor_sha256="$(jq -er '.executor.sha256' "$environment_snapshot")" || return
  if ! executor_identity="$(safe_file_identity "$executor_path" true)" ||
    [[ "${executor_identity##*:}" != "$executor_sha256" ]]; then
    write_untested lifecycle-executor-identity-invalid
    return $?
  fi
  [[ "$(create_stable_file_snapshot \
      "$executor_path" "$executor_snapshot" true 0500)" == \
      "$executor_identity" ]] || return 1
  executor_snapshot_identity="$(safe_file_identity "$executor_snapshot" true)" ||
    return
  [[ "${executor_snapshot_identity##*:}" == "$executor_sha256" ]] || return 1
  file_identity_is_unchanged "$executor_path" true "$executor_identity" || {
    write_untested lifecycle-executor-changed-before-execution
    return $?
  }
  requested_snapshot_sha256="$(sha256_file "$requested_snapshot")" || return
  [[ "$(sha256_file "$source_authority_snapshot")" == \
    "$source_authority_sha256" ]] ||
    return 1
  [[ ! -e "$environment_output" && ! -L "$environment_output" ]] || return 1
  command=(
    /proc/self/fd/9
    --contract "$ENVIRONMENT_SCHEMA"
    --campaign-revision "$campaign_revision"
    --plan-sha256 "$plan_sha256"
    --cell requested-cell.snapshot.json
    --source-authority source-authority.snapshot.json
    --source-authority-sha256 "$source_authority_sha256"
    --environment lifecycle-environment.snapshot.json
    --environment-sha256 "$environment_sha256"
    --output environment-output
  )
  command_json="$(printf '%s\0' "${command[@]}" | jq -Rs 'split("\u0000")[:-1]')" || return
  set +e
  supervision_result="$(run_supervised_executor \
    "$private_output" "$stdout_file" "$stderr_file" \
    "$executor_snapshot" "$executor_snapshot_identity" "${command[@]}")"
  supervision_status=$?
  set -e
  if (( supervision_status != 0 )) ||
    ! jq -e '
      keys == [
        "cleanup_complete", "containment_violation", "executor_descriptor_identity",
        "executor_exit_status", "observed_descendants", "schema", "timed_out"
      ] and
      .schema == "compatibility-lifecycle-executor-supervision-v1" and
      (.cleanup_complete | type == "boolean") and
      (.containment_violation | type == "boolean") and
      (.timed_out | type == "boolean") and
      (.observed_descendants | type == "number" and floor == . and . >= 0 and
        . <= 1000000) and
      (.executor_descriptor_identity | type == "string" and
        test("^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]{64}$")) and
      (.executor_exit_status | type == "number" and floor == . and . >= 0 and
        . <= 255)
    ' >/dev/null <<<"$supervision_result"; then
    error "lifecycle executor supervisor failed with status $supervision_status"
    if [[ -n "$supervision_result" ]]; then
      printf '%s\n' "$supervision_result" >&2
    fi
    return 1
  fi
  executor_descriptor_identity="$(
    jq -er '.executor_descriptor_identity' <<<"$supervision_result"
  )" || return
  [[ "$executor_descriptor_identity" == "$executor_snapshot_identity" ]] ||
    die "lifecycle executor descriptor identity was substituted" || return
  supervision="$(jq -cS 'del(.executor_descriptor_identity)' \
    <<<"$supervision_result")" || return
  invocation_status="$(jq -er '.executor_exit_status' <<<"$supervision")" || return
  if [[ "$(jq -er '.timed_out' <<<"$supervision")" == true ||
    "$(jq -er '.containment_violation' <<<"$supervision")" == true ||
    "$(jq -er '.cleanup_complete' <<<"$supervision")" != true ]]; then
    die "lifecycle executor left an uncontained or timed-out process tree"
    return
  fi
  if [[ -n "$expected_executor_registry_source_identity" &&
    "$(safe_file_identity "$executor_registry_source_path" false)" != \
      "$expected_executor_registry_source_identity" ]]; then
    die "lifecycle executor registry source changed during execution"
    return
  fi
  if [[ "$(safe_file_identity "$contract_cell_source" false)" != \
      "$contract_cell_source_identity" ||
    "$(safe_file_identity "$contract_source_authority_source" false)" != \
      "$contract_source_authority_source_identity" ]]; then
    die "lifecycle driver contract inputs changed during execution"
    return
  fi
  if ! file_identity_is_unchanged \
    "$executor_registry_path" false "$executor_registry_identity" ||
    ! file_identity_is_unchanged \
      "$executor_registry_snapshot" false \
      "$executor_registry_snapshot_identity" ||
    ! file_identity_is_unchanged "$environment_path" false "$environment_identity" ||
    ! file_identity_is_unchanged "$executor_path" true "$executor_identity" ||
    ! file_identity_is_unchanged \
      "$environment_snapshot" false "$environment_snapshot_identity" ||
    ! file_identity_is_unchanged \
      "$executor_snapshot" true "$executor_snapshot_identity" ||
    ! file_identity_is_unchanged "$cell" false "$requested_identity" ||
    ! file_identity_is_unchanged \
      "$source_authority" false "$source_authority_identity" ||
    [[ "$(sha256_file "$requested_snapshot")" != "$requested_snapshot_sha256" ]] ||
    [[ "$(sha256_file "$source_authority_snapshot")" != \
      "$source_authority_sha256" ]]; then
    die "preprovisioned environment identity changed during execution"
    return
  fi
  jq -nS \
    --arg schema "$DRIVER_SCHEMA" \
    --arg executor_registry_sha256 "$executor_registry_sha256" \
    --arg executor_registry_identity "$executor_registry_identity" \
    --arg environment_id "$environment_id" \
    --arg environment_sha256 "$environment_sha256" \
    --arg environment_identity "$environment_identity" \
    --arg approval_id "$approval_id" \
    --arg executor_sha256 "$executor_sha256" \
    --arg executor_identity "$executor_identity" \
    --arg executor_snapshot_identity "$executor_snapshot_identity" \
    --arg executor_descriptor_identity "$executor_descriptor_identity" \
    --argjson argv "$command_json" \
    --argjson exit_status "$invocation_status" \
    --argjson supervision "$supervision" '{
      schema:$schema,
      registry:{sha256:$executor_registry_sha256,identity:$executor_registry_identity},
      environment:{id:$environment_id,sha256:$environment_sha256},
      environment_identity:$environment_identity,
      executor:{
        approval_id:$approval_id,sha256:$executor_sha256,
        original_identity:$executor_identity,
        snapshot_identity:$executor_snapshot_identity,
        descriptor_identity:$executor_descriptor_identity,
        argv:$argv,exit_status:$exit_status
      },
      supervision:$supervision
    }' >"$private_authority"
  chmod 0600 -- "$private_authority"
  [[ -d "$environment_output" && ! -L "$environment_output" ]] ||
    die "lifecycle executor did not create its output directory" || return
  [[ -f "$observation" && ! -L "$observation" ]] ||
    die "lifecycle executor did not create its result" || return
  validate_observation_envelope \
    "$observation" "$environment_id" "$environment_sha256" "$executor_sha256" \
    "$invocation_status" "$command_json" ||
    die "lifecycle executor result violates its envelope" || return
  observed_status="$(jq -er '.status' "$observation")" || return
  if [[ "$observed_status" != untested ]]; then
    validate_helper_pass_assertions "$observation" ||
      die "lifecycle executor result violates helper pass assertions" || return
    validate_raw_bundle "$observation" "$environment_output" ||
      die "lifecycle executor raw evidence is unsafe or inconsistent" || return
    validate_unavailable_bridge_files "$observation" "$environment_output/raw" ||
      die "lifecycle unavailable-bridge evidence is inconsistent" || return
  else
    observed_status="untested"
    [[ ! -e "$environment_output/raw" && ! -L "$environment_output/raw" &&
      ! -e "$environment_output/raw.sha256" &&
      ! -L "$environment_output/raw.sha256" ]] || return 1
    install -d -m 0700 -- "$environment_output/raw"
  fi
  receipt="$environment_output/raw/lifecycle-execution-receipt.json"
  jq -nS \
    --arg schema "$EXECUTION_RECEIPT_SCHEMA" \
    --arg registry_sha256 "$executor_registry_sha256" \
    --arg environment_id "$environment_id" \
    --arg environment_sha256 "$environment_sha256" \
    --arg requested_cell_id "$(jq -er '.id' "$requested_snapshot")" \
    --argjson approval "$approval" \
    --argjson argv "$command_json" \
    --arg executor_sha256 "$executor_sha256" \
    --argjson exit_status "$invocation_status" \
    --argjson supervision "$supervision" '{
      schema:$schema,
      registry_sha256:$registry_sha256,
      approval:$approval,
      environment:{id:$environment_id,sha256:$environment_sha256},
      requested_cell_id:$requested_cell_id,
      command:{
        argv:$argv,executable_sha256:$executor_sha256,exit_status:$exit_status
      },
      supervision:$supervision
    }' >"$receipt"
  chmod 0600 -- "$receipt"
  receipt_sha256="$(sha256_file "$receipt")" || return
  if [[ -e "$environment_output/raw.sha256" ||
    -L "$environment_output/raw.sha256" ]]; then
    replaced_manifest_identity="$(safe_file_identity \
      "$environment_output/raw.sha256" false)" || return
  fi
  (
    CDPATH='' cd -- "$environment_output/raw"
    find . -mindepth 1 -type f -printf '%P\0' | LC_ALL=C sort -z |
      while IFS= read -r -d '' path; do
        printf '%s  %s\n' "$(sha256_file "$path")" "$path"
      done
  ) >"$manifest_candidate"
  chmod 0600 -- "$manifest_candidate"
  manifest_candidate_identity="$(safe_file_identity \
    "$manifest_candidate" false)" || return
  publish_private_file_no_replace \
    "$manifest_candidate" "$manifest_candidate_identity" \
    "$environment_output/raw.sha256" "$replaced_manifest_identity" || return
  raw_manifest_sha256="$(sha256_file "$environment_output/raw.sha256")" || return
  lifecycle_executor="$(jq -cnS \
    --arg schema compatibility-lifecycle-executor-authority-v1 \
    --arg registry_sha256 "$executor_registry_sha256" \
    --argjson approval "$approval" \
    --arg environment_id "$environment_id" \
    --arg environment_sha256 "$environment_sha256" \
    --argjson argv "$command_json" \
    --arg executor_sha256 "$executor_sha256" \
    --argjson exit_status "$invocation_status" \
    --arg receipt_sha256 "$receipt_sha256" '{
      schema:$schema,
      registry_sha256:$registry_sha256,
      approval:$approval,
      environment:{id:$environment_id,sha256:$environment_sha256},
      command:{
        argv:$argv,executable_sha256:$executor_sha256,exit_status:$exit_status
      },
      receipt_sha256:$receipt_sha256
    }')" || return
  write_provider_result \
    "$observation" "$invocation_status" "$lifecycle_executor" \
    "$raw_manifest_sha256" || return
  validate_raw_bundle "$private_output/provider-result.json" "$environment_output" ||
    die "lifecycle executor receipt or final raw evidence is inconsistent" || return
  return "$invocation_status"
}

main() {
  require_commands cmp dirname find grep install jq python3 readlink rm sha256sum sort stat || return
  parse_arguments "$@" || die "invalid lifecycle driver arguments" || return
  validate_contract_inputs || return
  retain_contract_inputs || die "could not retain lifecycle driver contract inputs" || return
  run_preprovisioned_environment
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
