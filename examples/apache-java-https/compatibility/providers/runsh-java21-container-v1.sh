#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/provider-lib.sh"

readonly PROVIDER_NAME=runsh-java21-container-v1
readonly ADAPTER="$SCRIPT_DIRECTORY/runsh-java21-container-v1.sh"
readonly RUNNER="$COMPATIBILITY_REPOSITORY_ROOT/examples/apache-java-https/run.sh"
readonly RUN_RESULTS="$COMPATIBILITY_REPOSITORY_ROOT/examples/apache-java-https/.runtime/results"
readonly MAX_RUN_SECONDS=7200
KERNEL_PROVENANCE_IDENTITY=""
TOPOLOGY_ATTESTATION_IDENTITY=""
KERNEL_PROVENANCE_SNAPSHOT=""
TOPOLOGY_ATTESTATION_SNAPSHOT=""
TOPOLOGY_PROCESS_CGROUPS_SHA256=""

cell_value() {
  local -r expression="$1"
  jq -er "$expression" "$OBI_COMPATIBILITY_CELL_JSON"
}

environment_value() {
  local -r file="$1"
  local -r key="$2"

  awk -F= -v key="$key" '
    $1 == key { count++; value = substr($0, length(key) + 2) }
    END { if (count == 1) print value; else exit 1 }
  ' "$file"
}

kernel_matches() {
  local -r selector="$1"
  local -r release="$2"

  case "$selector" in
    rhel-9.6-5.14) [[ "$release" =~ ^5[.]14([.-]|$) ]] ;;
    upstream-5.10) [[ "$release" =~ ^5[.]10([.-]|$) ]] ;;
    upstream-5.15) [[ "$release" =~ ^5[.]15([.-]|$) ]] ;;
    upstream-6.1) [[ "$release" =~ ^6[.]1([.-]|$) ]] ;;
    upstream-6.6) [[ "$release" =~ ^6[.]6([.-]|$) ]] ;;
    upstream-6.12) [[ "$release" =~ ^6[.]12([.-]|$) ]] ;;
    supported-runtime-probed) [[ -n "$release" ]] ;;
    *) return 1 ;;
  esac
}

topology_matches() {
  local -r topology="$1"
  local has_v1=false
  local has_v2=false

  grep -Eq '[[:space:]]cgroup[[:space:]]' /proc/mounts && has_v1=true
  grep -Eq '[[:space:]]cgroup2[[:space:]]' /proc/mounts && has_v2=true
  case "$topology" in
    unified-v2)
      [[ "$has_v1" == false && "$has_v2" == true &&
        -r /sys/fs/cgroup/cgroup.controllers ]]
      ;;
    hybrid-v1-v2)
      [[ "$has_v1" == true && "$has_v2" == true ]]
      ;;
    nested-delegated-v2)
      [[ "$has_v2" == true && -r /sys/fs/cgroup/cgroup.controllers &&
        -n "${OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION:-}" ]]
      ;;
    sibling-containers)
      [[ "$has_v2" == true ]]
      ;;
    *) return 1 ;;
  esac
}

validate_kernel_provenance() {
  local -r selector="$1"
  local provenance="${OBI_COMPATIBILITY_KERNEL_PROVENANCE:-}"

  [[ -n "$provenance" ]] || return 1
  compatibility_require_regular_file "$provenance" || return
  compatibility_validate_json_file "$provenance" || return
  jq -e --arg selector "$selector" --arg release "$(uname -r)" '
    keys == [
      "observed_release", "schema", "selector", "source_digest",
      "version_inference"
    ] and .schema == "compatibility-kernel-provenance-v1" and
    .selector == $selector and
    .observed_release == $release and
    (.source_digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
    (.version_inference == false)
  ' "$provenance" >/dev/null
}

validate_topology_attestation() {
  local -r topology="$1"
  local attestation="${OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION:-}"
  local process_cgroups_sha256=""

  [[ -n "$attestation" ]] || return 1
  compatibility_require_regular_file "$attestation" || return
  compatibility_validate_json_file "$attestation" || return
  process_cgroups_sha256="$(compatibility_sha256 /proc/self/cgroup)" || return
  jq -e --arg topology "$topology" \
    --arg process_cgroups_sha256 "$process_cgroups_sha256" '
    (if $topology == "nested-delegated-v2" then
      keys == [
        "cgroup_topology", "delegation_writable", "nested_path_observed",
        "process_cgroups_sha256", "runtime_observed", "schema"
      ]
     elif $topology == "sibling-containers" then
      keys == [
        "cgroup_topology", "distinct_sibling_cgroups", "process_cgroups_sha256",
        "runtime_observed", "schema"
      ]
     else
      keys == [
        "cgroup_topology", "process_cgroups_sha256", "runtime_observed", "schema"
      ]
     end) and .schema == "compatibility-topology-attestation-v1" and
    .cgroup_topology == $topology and
    .runtime_observed == true and
    .process_cgroups_sha256 == $process_cgroups_sha256 and
    (if $topology == "nested-delegated-v2" then
      .delegation_writable == true and .nested_path_observed == true
     elif $topology == "sibling-containers" then
      .distinct_sibling_cgroups == true
     else true
     end)
  ' "$attestation" >/dev/null
}

attestation_identity() {
  local -r path="$1"
  local metadata=""
  local owner=""
  local mode=""
  local links=""
  local size=""

  compatibility_require_regular_file "$path" || return
  metadata="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$path")" || return
  IFS=: read -r _ _ owner mode links size <<<"$metadata"
  [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 1
  [[ "$links" == 1 && "$size" =~ ^[1-9][0-9]*$ ]] || return 1
  (( size <= 1048576 && (8#$mode & 0022) == 0 )) || return 1
  printf '%s:%s\n' "$metadata" "$(compatibility_sha256 "$path")"
}

snapshot_runtime_attestations() {
  local -r selector="$1"
  local -r topology="$2"
  local snapshot_directory="$OBI_COMPATIBILITY_PRIVATE_DIR/runtime-attestation-snapshot"

  validate_kernel_provenance "$selector" || return
  validate_topology_attestation "$topology" || return
  KERNEL_PROVENANCE_IDENTITY="$(attestation_identity \
    "$OBI_COMPATIBILITY_KERNEL_PROVENANCE")" || return
  TOPOLOGY_ATTESTATION_IDENTITY="$(attestation_identity \
    "$OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION")" || return
  TOPOLOGY_PROCESS_CGROUPS_SHA256="$(compatibility_sha256 /proc/self/cgroup)" || return
  install -d -m 0700 -- "$snapshot_directory"
  KERNEL_PROVENANCE_SNAPSHOT="$snapshot_directory/kernel-provenance.json"
  TOPOLOGY_ATTESTATION_SNAPSHOT="$snapshot_directory/topology-attestation.json"
  install -m 0400 -- "$OBI_COMPATIBILITY_KERNEL_PROVENANCE" \
    "$KERNEL_PROVENANCE_SNAPSHOT"
  install -m 0400 -- "$OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION" \
    "$TOPOLOGY_ATTESTATION_SNAPSHOT"
  [[ "$(compatibility_sha256 "$KERNEL_PROVENANCE_SNAPSHOT")" == \
    "${KERNEL_PROVENANCE_IDENTITY##*:}" &&
    "$(compatibility_sha256 "$TOPOLOGY_ATTESTATION_SNAPSHOT")" == \
    "${TOPOLOGY_ATTESTATION_IDENTITY##*:}" ]] || return 1
  validate_kernel_provenance "$selector" || return
  validate_topology_attestation "$topology" || return
  [[ "$(attestation_identity "$OBI_COMPATIBILITY_KERNEL_PROVENANCE")" == \
    "$KERNEL_PROVENANCE_IDENTITY" &&
    "$(attestation_identity "$OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION")" == \
    "$TOPOLOGY_ATTESTATION_IDENTITY" ]]
}

runtime_attestations_are_unchanged() {
  [[ -n "$KERNEL_PROVENANCE_IDENTITY" && -n "$TOPOLOGY_ATTESTATION_IDENTITY" &&
    -n "$KERNEL_PROVENANCE_SNAPSHOT" && -n "$TOPOLOGY_ATTESTATION_SNAPSHOT" &&
    -n "$TOPOLOGY_PROCESS_CGROUPS_SHA256" ]] ||
    return 1
  [[ "$(attestation_identity "$OBI_COMPATIBILITY_KERNEL_PROVENANCE")" == \
    "$KERNEL_PROVENANCE_IDENTITY" &&
    "$(attestation_identity "$OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION")" == \
    "$TOPOLOGY_ATTESTATION_IDENTITY" &&
    "$(compatibility_sha256 "$KERNEL_PROVENANCE_SNAPSHOT")" == \
    "${KERNEL_PROVENANCE_IDENTITY##*:}" &&
    "$(compatibility_sha256 "$TOPOLOGY_ATTESTATION_SNAPSHOT")" == \
    "${TOPOLOGY_ATTESTATION_IDENTITY##*:}" &&
    "$(compatibility_sha256 /proc/self/cgroup)" == \
    "$TOPOLOGY_PROCESS_CGROUPS_SHA256" ]]
}

preflight_or_untested() {
  local architecture=""
  local expected_architecture=""
  local selector=""
  local topology=""
  local source_status=""
  local command_name=""
  local -a required_commands=(
    awk bpftool docker find git grep jq python3 sha256sum sleep sort stat timeout uname unzip
  )

  jq -e '
    .provider == "runsh-java21-container-v1" and
    .deployment == "container-process" and
    .jvm_feature == 21 and
    (.transport == "getsockopt" or .transport == "unix")
  ' "$OBI_COMPATIBILITY_CELL_JSON" >/dev/null || {
    provider_write_untested provider-cell-contract-mismatch "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  for command_name in "${required_commands[@]}"; do
    command -v "$command_name" >/dev/null 2>&1 || {
      provider_write_untested "required-command-unavailable" "$PROVIDER_NAME" "$RUNNER"
      return 69
    }
  done
  compatibility_require_regular_file "$RUNNER" || {
    provider_write_untested source-runner-unavailable "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  source_status="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" status \
    --porcelain=v1 --untracked-files=all)" || {
    provider_write_untested source-identity-unavailable "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  [[ -z "$source_status" ]] || {
    provider_write_untested source-checkout-dirty "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  docker info >/dev/null 2>&1 || {
    provider_write_untested docker-runtime-unavailable "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  architecture="$(compatibility_normalize_architecture "$(uname -m)")" || return
  expected_architecture="$(cell_value '.architecture')" || return
  [[ "$architecture" == "$expected_architecture" ]] || {
    provider_write_untested architecture-mismatch "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  selector="$(cell_value '.kernel')" || return
  kernel_matches "$selector" "$(uname -r)" || {
    provider_write_untested kernel-release-mismatch "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  topology="$(cell_value '.cgroup_topology')" || return
  topology_matches "$topology" || {
    provider_write_untested cgroup-topology-mismatch "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  snapshot_runtime_attestations "$selector" "$topology" || {
    provider_write_untested runtime-attestation-unavailable "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  [[ -r /sys/kernel/btf/vmlinux ]] || {
    provider_write_untested kernel-btf-unavailable "$PROVIDER_NAME" "$RUNNER"
    return 69
  }
  return 0
}

find_result_directory() {
  local -r combined_log="$1"
  local result=""

  result="$(awk -F'retained run evidence: ' '
    NF == 2 { count++; value = $2 }
    END { if (count == 1) print value; else exit 1 }
  ' "$combined_log")" || return 1
  [[ "$result" == "$RUN_RESULTS"/* && -d "$result" && ! -L "$result" ]] || return 1
  printf '%s\n' "$result"
}

classify_failed_run() {
  local -r run_status="$1"
  local failure_stage=""

  [[ -f "$run_status" && ! -L "$run_status" ]] || {
    printf 'contract\trun-status-unavailable\n'
    return
  }
  compatibility_validate_json_file "$run_status" >/dev/null 2>&1 || {
    printf 'contract\trun-status-malformed\n'
    return
  }
  jq -e '
    (.schema == "obi-apache-java-https-run-status-v2" or
      .schema == "obi-apache-java-https-run-status-v3") and
    .status == "failed" and
    (.exit_status | type == "number" and floor == . and . >= 1 and . <= 255) and
    (.acceptance_evidence | type == "boolean") and
    (.failure_stage | type == "string" and length > 0 and length <= 128) and
    (.failure_line | type == "number" and floor == . and . >= 0 and
      . <= 1000000000)
  ' "$run_status" >/dev/null 2>&1 || {
    printf 'contract\trun-status-contract-invalid\n'
    return
  }
  failure_stage="$(jq -er '.failure_stage' "$run_status" 2>/dev/null || true)"
  case "$failure_stage" in
    scenarios|runtime-evidence|compose-cleanup|pressure-*|evidence-publication|complete)
      printf 'fail\tapplication-or-cleanup-assertion-failed\n'
      ;;
    *)
      printf 'untested\tinfrastructure-before-product-assertion\n'
      ;;
  esac
}

classify_authoritative_unsupported_control() {
  local -r control="$1"
  local -r requested_transport="$2"

  compatibility_validate_json_file "$control" || return
  jq -e --arg requested "$requested_transport" '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    keys == [
      "attempted_transports", "exact_parent", "feature_probe", "no_crash",
      "no_request_mutation", "requested_transport", "schema",
      "selected_transport", "status"
    ] and
    .schema == "compatibility-runsh-unsupported-control-v1" and
    .status == "unsupported" and .requested_transport == $requested and
    .attempted_transports == [$requested] and .selected_transport == null and
    .feature_probe == {authoritative:true, supported:false} and
    (.exact_parent | keys == ["matched", "requests", "status", "wrong"]) and
    .exact_parent.status == "pass" and
    (.exact_parent.requests | type == "number" and floor == . and . > 0 and
      . <= 1000000000) and
    .exact_parent.matched == .exact_parent.requests and .exact_parent.wrong == 0 and
    (.no_request_mutation | keys == ["evidence_sha256", "status"]) and
    .no_request_mutation.status == "pass" and
    (.no_request_mutation.evidence_sha256 | sha256) and
    (.no_crash | keys == ["evidence_sha256", "status"]) and
    .no_crash.status == "pass" and (.no_crash.evidence_sha256 | sha256)
  ' "$control" >/dev/null
}

transport_selection_from_evidence() {
  local -r evidence="$1"
  local -r requested="$2"
  local selected=""

  selected_transport_is_exact "$evidence" "$requested" || return
  case "$requested" in
    getsockopt) selected=getsockopt ;;
    unix) selected=unix ;;
    *) return 1 ;;
  esac
  jq -cnS --arg requested "$requested" --arg selected "$selected" '
    {
      attempted_transports: [$requested],
      selected_transport: $selected,
      supported: true
    }
  '
}

selected_transport_is_exact() {
  local -r evidence="$1"
  local -r transport="$2"
  local expected=""

  case "$transport" in
    getsockopt) expected='version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0' ;;
    unix) expected='version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=1' ;;
    *) return 1 ;;
  esac
  [[ "$(<"$evidence")" == "$expected" ]]
}

exact_parent_assertion() {
  local -r scenario="$1"

  compatibility_validate_json_file "$scenario" || return
  jq -cS '
    def safe_count:
      type == "number" and floor == . and . >= 0 and . <= 1000000000;
    def safe_nanos:
      type == "number" and floor == . and . >= 0 and . <= 9007199254740991;
    def trace_id:
      type == "string" and test("^[0-9a-f]{32}$") and
      . != "00000000000000000000000000000000";
    def span_id:
      type == "string" and test("^[0-9a-f]{16}$") and
      . != "0000000000000000";
    def exact_case:
      type == "object" and
      keys == ["latency_nanos", "request", "response", "trace"] and
      (.latency_nanos | safe_nanos) and
      (.request | type == "object") and (.response | type == "object") and
      (.trace | type == "object") and
      (.request.marker | type == "string" and
        test("^[a-z0-9][a-z0-9-]{0,95}$")) and
      .response.marker == .request.marker and .trace.marker == .request.marker and
      (.trace.spans | type == "array") and
      .trace.spans as $spans |
      [$spans[] | select(.service_name == "apache-proxy" and .kind == "CLIENT")] as $clients |
      [$spans[] | select(.service_name == "java-backend" and .kind == "SERVER")] as $servers |
      ($clients | length == 1) and ($servers | length == 1) and
      ($clients[0].trace_id | trace_id) and
      ($servers[0].trace_id | trace_id) and
      ($clients[0].span_id | span_id) and
      ($servers[0].span_id | span_id) and
      ($servers[0].parent_span_id | span_id) and
      ($clients[0].trace_id == $servers[0].trace_id) and
      ($clients[0].span_id == $servers[0].parent_span_id) and
      ($clients[0].span_id != $servers[0].span_id);
    ((.request_count | safe_count) and .request_count > 0 and
      (.cases | type == "array") and (.cases | length) == .request_count and
      ([.cases[].request.marker] | unique | length) == .request_count) as $roster |
    (.status == "passed" and $roster) as $passed |
    ([.cases[] | select(exact_case)] | length) as $matched |
    (.cases | length) as $case_count |
    {
      status: (if $passed and $matched == $case_count then "pass" else "fail" end),
      requests: .request_count,
      matched: $matched,
      wrong: ($case_count - $matched)
    }
  ' "$scenario"
}

expected_runsh_project_name() {
  local cell_sha256=""

  cell_sha256="$(compatibility_sha256 "$OBI_COMPATIBILITY_CELL_JSON")" || return
  printf 'obi-apache-java-https-compat-%s\n' "${cell_sha256:0:12}"
}

validate_local_runtime_evidence() {
  local -r evidence="$1"
  local -r attestation="$2"
  local expected_project=""

  compatibility_require_directory "$evidence" || return
  compatibility_validate_json_file "$OBI_COMPATIBILITY_CELL_JSON" || return
  compatibility_validate_json_file "$attestation" || return
  expected_project="$(expected_runsh_project_name)" || return
  python3 - \
    "$evidence" "$OBI_COMPATIBILITY_CELL_JSON" "$attestation" \
    "$expected_project" "$(uname -m)" "$(uname -srvmo)" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys


root = Path(sys.argv[1])
requested_path = Path(sys.argv[2])
attestation_path = Path(sys.argv[3])
expected_project = sys.argv[4]
uname_machine = sys.argv[5]
uname_full = sys.argv[6]

MAX_BYTES = 1_048_576
MAX_LINES = 8192
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
CGROUP_V1 = re.compile(r"^[1-9][0-9]*:[A-Za-z0-9_,.=-]+:/[^\x00-\x1f]*$")
CGROUP_V2 = re.compile(r"^0::/[^\x00-\x1f]*$")
JAVA_VERSION = re.compile(r'^openjdk version "(21(?:[.][0-9]+){1,3}(?:[+._-][A-Za-z0-9._+-]+)?)"(?: .*)?$')


def fail(message):
    raise ValueError(message)


def load_json(path):
    def no_duplicates(pairs):
        value = {}
        for key, member in pairs:
            if key in value:
                fail(f"duplicate JSON key in {path.name}: {key}")
            value[key] = member
        return value

    with path.open("r", encoding="utf-8") as source:
        return json.load(source, object_pairs_hook=no_duplicates)


def read_text(name):
    path = root / name
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"unsafe evidence entry: {name}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_BYTES:
        fail(f"unbounded evidence entry: {name}")
    data = path.read_bytes()
    if b"\x00" in data:
        fail(f"NUL in evidence entry: {name}")
    text = data.decode("utf-8")
    if len(text.splitlines()) > MAX_LINES:
        fail(f"too many evidence lines: {name}")
    if any(ord(character) < 32 and character not in "\n\r\t" for character in text):
        fail(f"control byte in evidence entry: {name}")
    return text


def parse_capture(name):
    lines = read_text(name).splitlines()
    if len(lines) < 3 or not lines[0].startswith("command= "):
        fail(f"missing command envelope: {name}")
    if sum(line.startswith("command=") for line in lines) != 1:
        fail(f"duplicate command envelope: {name}")
    if sum(line.startswith("exit_status=") for line in lines) != 1:
        fail(f"duplicate exit envelope: {name}")
    if lines[-1] != "exit_status=0":
        fail(f"unsuccessful command envelope: {name}")
    argv = shlex.split(lines[0][len("command="):], posix=True)
    payload = lines[1:-1]
    if not argv or not payload or any(not line for line in payload):
        fail(f"empty command or payload: {name}")
    return argv, payload


def parse_json_values(line, count):
    decoder = json.JSONDecoder()
    position = 0
    values = []
    while position < len(line):
        while position < len(line) and line[position].isspace():
            position += 1
        if position == len(line):
            break
        value, position = decoder.raw_decode(line, position)
        values.append(value)
    if len(values) != count:
        fail("identity row has the wrong field count")
    return values


requested = load_json(requested_path)
attestation = load_json(attestation_path)
topology = requested["cgroup_topology"]
requested_architecture = requested["architecture"]

environment = {}
for line in read_text("environment.txt").splitlines():
    if "=" not in line:
        fail("malformed environment row")
    key, value = line.split("=", 1)
    if not key or key in environment:
        fail("duplicate environment key")
    environment[key] = value
for required_key in (
    "dirty", "scenario", "transport", "agent_distribution", "tls_protocol",
    "repeat_count", "compose_project", "architecture", "kernel", "docker",
    "compose", "acceptance_evidence",
):
    if required_key not in environment:
        fail(f"missing environment key: {required_key}")
if environment["dirty"] != "false" or environment["scenario"] != "all":
    fail("non-authoritative source or scenario environment")
if environment["transport"] != requested["transport"]:
    fail("transport environment mismatch")
if environment["agent_distribution"] != requested["agent_distribution"]:
    fail("agent environment mismatch")
if environment["tls_protocol"] != requested["tls"] or environment["repeat_count"] != "1":
    fail("TLS or repeat environment mismatch")
if environment["compose_project"] != expected_project:
    fail("Compose project identity mismatch")
if environment["architecture"] != uname_machine or environment["kernel"] != uname_full:
    fail("host environment identity mismatch")
if environment["acceptance_evidence"] != "true":
    fail("run.sh did not publish acceptance evidence")
if not environment["docker"] or not environment["compose"]:
    fail("Docker runtime identity unavailable")

host_lines = read_text("host-topology.txt").splitlines()
try:
    cgroup_marker = host_lines.index("/proc/self/cgroup:")
    mount_marker = host_lines.index("/proc/mounts cgroup entries:")
except ValueError as error:
    fail(f"missing host topology section: {error}")
if cgroup_marker != 6 or mount_marker <= cgroup_marker + 2:
    fail("host topology section order changed")
if host_lines[5] != "" or host_lines[mount_marker - 1] != "":
    fail("host topology section separator changed")
header = {}
for line in host_lines[:5]:
    if line.count("=") != 1:
        fail("malformed host topology header")
    key, value = line.split("=", 1)
    if key in header:
        fail("duplicate host topology key")
    header[key] = value
if set(header) != {
    "architecture", "kernel", "cgroup_filesystem",
    "unprivileged_bpf_disabled", "vmlinux_btf",
}:
    fail("host topology header roster changed")
if header["architecture"] != uname_machine or header["kernel"] != uname_full:
    fail("host topology identity mismatch")
if header["vmlinux_btf"] != "readable":
    fail("kernel BTF unavailable")
if not re.fullmatch(r"[012]", header["unprivileged_bpf_disabled"]):
    fail("ambiguous unprivileged BPF state")
cgroup_lines = host_lines[cgroup_marker + 1:mount_marker - 1]
if not cgroup_lines or any(not (CGROUP_V1.fullmatch(line) or CGROUP_V2.fullmatch(line)) for line in cgroup_lines):
    fail("malformed process cgroup roster")
if len(set(cgroup_lines)) != len(cgroup_lines):
    fail("duplicate process cgroup row")
observed_cgroups = ("\n".join(cgroup_lines) + "\n").encode("utf-8")
live_cgroups = Path("/proc/self/cgroup").read_bytes()
if observed_cgroups != live_cgroups:
    fail("retained and live process cgroups differ")
if attestation.get("process_cgroups_sha256") != hashlib.sha256(live_cgroups).hexdigest():
    fail("topology attestation is not bound to the process cgroup roster")
if attestation.get("cgroup_topology") != topology or attestation.get("runtime_observed") is not True:
    fail("topology attestation request mismatch")
mount_lines = host_lines[mount_marker + 1:]
if not mount_lines:
    fail("missing cgroup mount evidence")
mount_types = []
for line in mount_lines:
    fields = line.split()
    if len(fields) < 6 or fields[2] not in {"cgroup", "cgroup2"}:
        fail("malformed cgroup mount row")
    mount_types.append(fields[2])
if topology == "hybrid-v1-v2":
    if not {"cgroup", "cgroup2"}.issubset(set(mount_types)):
        fail("hybrid cgroup mount evidence mismatch")
elif topology in {"unified-v2", "nested-delegated-v2", "sibling-containers"}:
    if "cgroup2" not in mount_types or header["cgroup_filesystem"] != "cgroup2fs":
        fail("cgroup v2 topology evidence mismatch")
    if topology == "unified-v2" and "cgroup" in mount_types:
        fail("unified cgroup evidence contains v1 mounts")
else:
    fail("unknown requested cgroup topology")

bpftool_argv, bpftool_payload = parse_capture("bpftool-feature-probe.txt")
if bpftool_argv != ["bpftool", "feature", "probe"]:
    fail("bpftool command identity mismatch")
canonical_sockopt_support = "eBPF program_type cgroup_sockopt is available"
sockopt_support_rows = [line for line in bpftool_payload if "cgroup_sockopt" in line]
if sockopt_support_rows != [canonical_sockopt_support]:
    fail("bpftool cgroup_sockopt support evidence is missing, duplicated, or contradictory")

identity_format = (
    "{{json .Name}} {{json .Id}} {{json .Image}} {{json .Config.Image}} "
    "{{json .HostConfig.NetworkMode}} {{json .HostConfig.PidMode}}"
)
container_argv, container_payload = parse_capture("container-identities.txt")
if container_argv[:4] != ["docker", "inspect", "--format", identity_format]:
    fail("container inspection command mismatch")
containers = {}
container_ids = []
for line in container_payload:
    name, container_id, image_id, config_image, network_mode, pid_mode = parse_json_values(line, 6)
    if not all(isinstance(value, str) for value in (
        name, container_id, image_id, config_image, network_mode, pid_mode
    )):
        fail("container identity field type mismatch")
    if not re.fullmatch(r"[0-9a-f]{64}", container_id) or not IMAGE_ID.fullmatch(image_id):
        fail("container digest identity malformed")
    if not re.fullmatch(rf"/{re.escape(expected_project)}-[a-z0-9][a-z0-9-]*-[1-9][0-9]*", name):
        fail("foreign Compose container identity")
    if name in containers or container_id in container_ids:
        fail("duplicate container identity")
    containers[name] = (container_id, image_id, config_image, network_mode, pid_mode)
    container_ids.append(container_id)
if container_argv[4:] != container_ids:
    fail("container command and result roster differ")

image_references = [
    "httpd:2.4.68-alpine@sha256:1b766f17b84026429b7cb243317b142921b24432336e798bc881c43f45ed9567",
    "obi-apache-java-https-tracecheck:local",
    "obi-apache-java-https-backend:local",
    "obi-apache-java-https:local",
]
image_argv, image_payload = parse_capture("image-identities.txt")
if image_argv != ["docker", "image", "inspect", "--format", "{{json .Id}} {{json .RepoTags}} {{json .RepoDigests}}", *image_references]:
    fail("image inspection command mismatch")
if len(image_payload) != len(image_references):
    fail("image result roster mismatch")
images = {}
for reference, line in zip(image_references, image_payload):
    image_id, tags, digests = parse_json_values(line, 3)
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        fail("image ID malformed")
    if tags is not None and (not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags)):
        fail("image tag roster malformed")
    if digests is not None and (not isinstance(digests, list) or not all(isinstance(digest, str) for digest in digests)):
        fail("image digest roster malformed")
    if "@sha256:" in reference:
        tagged_name, digest = reference.split("@", 1)
        last_slash = tagged_name.rfind("/")
        last_colon = tagged_name.rfind(":")
        repository = tagged_name[:last_colon] if last_colon > last_slash else tagged_name
        canonical_digest = f"{repository}@{digest}"
        if not digests or canonical_digest not in digests:
            fail("pinned image digest was not retained")
    elif not tags or reference not in tags:
        fail("local image tag was not retained")
    images[reference] = image_id
if len(set(images.values())) != len(images):
    fail("distinct configured images resolved to a duplicate identity")

required_services = {
    "trace-receiver": image_references[1],
    "java-backend": image_references[2],
    "coalesced-source": image_references[1],
    "apache-proxy": image_references[0],
    "obi": image_references[3],
}
for service, reference in required_services.items():
    name = f"/{expected_project}-{service}-1"
    if name not in containers:
        fail(f"missing required Compose service: {service}")
    _, image_id, config_image, network_mode, pid_mode = containers[name]
    if image_id != images[reference] or config_image != reference:
        fail(f"container/image cross-binding failed: {service}")
    if network_mode != "host":
        fail(f"unexpected network topology: {service}")
    if pid_mode != ("host" if service == "obi" else ""):
        fail(f"unexpected PID topology: {service}")

java_argv, java_payload = parse_capture("java-version.txt")
if len(java_argv) != 13 or java_argv[:5] != [
    "docker", "compose", "--project-name", expected_project, "--project-directory"
] or java_argv[6] != "--file" or java_argv[8:] != [
    "exec", "--no-TTY", "java-backend", "java", "-version"
]:
    fail("Java runtime command mismatch")
project_directory = Path(java_argv[5])
compose_file = Path(java_argv[7])
if not project_directory.is_absolute() or ".." in project_directory.parts:
    fail("Java runtime command used a noncanonical Compose project directory")
if compose_file != project_directory / "docker-compose.yml":
    fail("Java runtime command used a foreign Compose file")
versions = [JAVA_VERSION.fullmatch(line) for line in java_payload]
versions = [match for match in versions if match is not None]
if len(versions) != 1:
    fail("Java 21 runtime identity is missing or ambiguous")
if any(re.search(r"(?:^|[^a-z])(error|failed|unavailable)(?:[^a-z]|$)", line, re.IGNORECASE) for line in java_payload):
    fail("Java runtime capture contains an error")

apache = {}
for line in read_text("apache-openssl-version.txt").splitlines():
    if line.count("=") != 1:
        fail("malformed Apache/OpenSSL evidence")
    key, value = line.split("=", 1)
    if key in apache:
        fail("duplicate Apache/OpenSSL evidence key")
    apache[key] = value
if set(apache) != {
    "apache_version", "apache_ssl_module", "apache_mod_ssl_path",
    "apache_mod_ssl_needed", "openssl_libssl_path", "openssl_libssl_owner",
    "openssl_libcrypto_path", "openssl_libcrypto_owner",
}:
    fail("Apache/OpenSSL evidence roster changed")
if not re.fullmatch(r"Apache/2[.]4[.][0-9]+ [(]Unix[)]", apache["apache_version"]):
    fail("Apache runtime version malformed")
if apache["apache_ssl_module"] != "ssl_module (shared)":
    fail("Apache SSL module was not loaded")
if apache["apache_mod_ssl_path"] != "/usr/local/apache2/modules/mod_ssl.so":
    fail("Apache mod_ssl path mismatch")
if apache["openssl_libssl_path"] != "/usr/lib/libssl.so.3" or apache["openssl_libcrypto_path"] != "/usr/lib/libcrypto.so.3":
    fail("OpenSSL runtime paths mismatch")
if not apache["openssl_libssl_owner"].startswith("libssl3-") or not apache["openssl_libcrypto_owner"].startswith("libcrypto3-"):
    fail("OpenSSL package ownership mismatch")
if "libssl.so.3" not in apache["apache_mod_ssl_needed"] or "libcrypto.so.3" not in apache["apache_mod_ssl_needed"]:
    fail("mod_ssl dependency evidence mismatch")
PY
}

java_runtime_identity() {
  local -r java_version="$1"
  local version_line=""
  local version=""

  version_line="$(grep -E '^openjdk version "21([.][0-9]+){1,3}([+._-][A-Za-z0-9._+-]+)?"( .*)?$' \
    "$java_version")" || return
  [[ "$(grep -Ec '^openjdk version "21([.][0-9]+){1,3}([+._-][A-Za-z0-9._+-]+)?"( .*)?$' \
    "$java_version")" == 1 ]] || return 1
  version="${version_line#*\"}"
  version="${version%%\"*}"
  [[ "$version" =~ ^21[.][0-9]+([.][0-9]+){0,2}([+._-][A-Za-z0-9._+-]+)?$ ]] || return 1
  printf 'openjdk-%s\n' "$version"
}

prepare_indexed_proof_files() {
  local -r evidence="$1"
  local -r architecture="$2"
  local proof="$evidence/campaign-proofs"
  local attestations="$evidence/campaign-attestations"
  local artifacts="$COMPATIBILITY_REPOSITORY_ROOT/examples/apache-java-https/.runtime/artifacts"
  local generic_object=""
  local sockopt_object=""
  local jni_entry=""

  runtime_attestations_are_unchanged || return
  case "$architecture" in
    amd64)
      generic_object="$COMPATIBILITY_REPOSITORY_ROOT/pkg/internal/ebpf/tpinjector/bpf_x86_bpfel.o"
      sockopt_object="$COMPATIBILITY_REPOSITORY_ROOT/pkg/internal/ebpf/tpinjector/bpfjavaremoteparent_x86_bpfel.o"
      jni_entry=native/linux-amd64/libobijni.so
      ;;
    arm64)
      generic_object="$COMPATIBILITY_REPOSITORY_ROOT/pkg/internal/ebpf/tpinjector/bpf_arm64_bpfel.o"
      sockopt_object="$COMPATIBILITY_REPOSITORY_ROOT/pkg/internal/ebpf/tpinjector/bpfjavaremoteparent_arm64_bpfel.o"
      jni_entry=native/linux-aarch64/libobijni.so
      ;;
    *) return 1 ;;
  esac
  compatibility_require_regular_file "$artifacts/official-javaagent.jar" || return
  compatibility_require_regular_file "$artifacts/obi-java-agent.jar" || return
  compatibility_require_regular_file "$artifacts/obi-otel-extension.jar" || return
  compatibility_require_regular_file "$generic_object" || return
  compatibility_require_regular_file "$sockopt_object" || return
  compatibility_require_regular_file /sys/kernel/btf/vmlinux || return
  install -d -m 0700 -- "$proof" "$attestations"
  install -m 0600 -- "$KERNEL_PROVENANCE_SNAPSHOT" \
    "$attestations/kernel-provenance.json"
  install -m 0600 -- "$TOPOLOGY_ATTESTATION_SNAPSHOT" \
    "$attestations/topology-attestation.json"
  install -m 0600 -- /sys/kernel/btf/vmlinux "$proof/kernel-btf-vmlinux"
  install -m 0600 -- "$artifacts/official-javaagent.jar" \
    "$proof/official-javaagent.jar"
  install -m 0600 -- "$artifacts/obi-java-agent.jar" "$proof/obi-java-agent.jar"
  install -m 0600 -- "$artifacts/obi-otel-extension.jar" \
    "$proof/obi-otel-extension.jar"
  install -m 0600 -- "$generic_object" "$proof/generic-bpf.o"
  install -m 0600 -- "$sockopt_object" "$proof/sockopt-bpf.o"
  unzip -p "$artifacts/obi-java-agent.jar" "$jni_entry" >"$proof/libobijni.so" || return
  chmod 0600 -- "$proof/libobijni.so"
  (
    cd -- "$COMPATIBILITY_REPOSITORY_ROOT"
    sha256sum \
      examples/apache-java-https/configs/obi.yaml \
      examples/apache-java-https/docker-compose.yml \
      examples/apache-java-https/apache/httpd.conf
  ) >"$proof/runtime-config.sha256" || return
  chmod 0600 -- "$proof/runtime-config.sha256"
  runtime_attestations_are_unchanged
}

artifact_identities() {
  local -r evidence="$1"
  local -r architecture="$2"
  local proof="$evidence/campaign-proofs"
  local bridge="$evidence/bridge-artifacts.json"
  local jni_entry=""

  case "$architecture" in
    amd64)
      jni_entry=native/linux-amd64/libobijni.so
      ;;
    arm64)
      jni_entry=native/linux-aarch64/libobijni.so
      ;;
    *) return 1 ;;
  esac
  compatibility_require_regular_file "$bridge" || return
  compatibility_validate_json_file "$bridge" || return
  jq -e \
    --arg helper "$(compatibility_sha256 "$proof/obi-java-agent.jar")" \
    --arg extension "$(compatibility_sha256 "$proof/obi-otel-extension.jar")" '
      .obi_java_agent_sha256 == $helper and
      .obi_otel_extension_sha256 == $extension
    ' "$bridge" >/dev/null || return 1
  jq -cnS \
    --arg generic_bpf_sha256 "$(compatibility_sha256 "$proof/generic-bpf.o")" \
    --arg sockopt_bpf_sha256 "$(compatibility_sha256 "$proof/sockopt-bpf.o")" \
    --arg jni_entry "$jni_entry" \
    --arg jni_sha256 "$(compatibility_sha256 "$proof/libobijni.so")" \
    --arg helper_sha256 "$(compatibility_sha256 "$proof/obi-java-agent.jar")" \
    --arg extension_sha256 "$(compatibility_sha256 "$proof/obi-otel-extension.jar")" \
    --arg config_sha256 "$(compatibility_sha256 "$proof/runtime-config.sha256")" \
    '{
      generic_bpf_sha256: $generic_bpf_sha256,
      sockopt_bpf_sha256: $sockopt_bpf_sha256,
      jni: {entry: $jni_entry, sha256: $jni_sha256},
      helper_sha256: $helper_sha256,
      extension_sha256: $extension_sha256,
      runtime_config_sha256: $config_sha256
    }'
}

source_identity_from_evidence() {
  local -r evidence="$1"
  local -r source_state="$evidence/source-state.txt"
  local revision=""
  local dirty=""
  local source_tree=""
  local tracked_patch=""
  local patch_identity=""

  compatibility_require_regular_file "$source_state" || return
  revision="$(environment_value "$source_state" revision)" || return
  dirty="$(environment_value "$source_state" dirty)" || return
  source_tree="$(environment_value "$source_state" source_tree_sha256)" || return
  tracked_patch="$(environment_value "$source_state" tracked_patch_sha256)" || return
  patch_identity="$(environment_value "$source_state" patch_identity_sha256)" || return
  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$dirty" == false &&
    "$source_tree" =~ ^[0-9a-f]{64}$ &&
    "$tracked_patch" =~ ^[0-9a-f]{64}$ &&
    "$patch_identity" =~ ^[0-9a-f]{64}$ ]] || return 1
  jq -cnS \
    --arg revision "$revision" \
    --arg source_tree_sha256 "$source_tree" \
    --arg tracked_patch_sha256 "$tracked_patch" \
    --arg patch_identity_sha256 "$patch_identity" \
    '{
      revision: $revision,
      clean: true,
      source_tree_sha256: $source_tree_sha256,
      tracked_patch_sha256: $tracked_patch_sha256,
      patch_identity_sha256: $patch_identity_sha256
    }'
}

runtime_identity() {
  local -r evidence="$1"
  local -r requested_json="$2"
  local architecture=""
  local java_line=""
  local agent_json=""
  local topology_digest=""
  local btf_digest=""
  local feature_digest=""
  local provenance_digest=""
  local deployment_digest=""
  local image_digest=""
  local userspace_digest=""
  local java_digest=""
  local topology_attestation_digest=""
  local selection_json=""

  runtime_attestations_are_unchanged || return
  validate_local_runtime_evidence \
    "$evidence" "$evidence/campaign-attestations/topology-attestation.json" || return
  architecture="$(compatibility_normalize_architecture "$(uname -m)")" || return
  java_line="$(java_runtime_identity "$evidence/java-version.txt")" || return
  compatibility_validate_json_file "$evidence/official-javaagent.json" || return
  agent_json="$(jq -cS . "$evidence/official-javaagent.json")" || return
  topology_digest="$(compatibility_sha256 "$evidence/host-topology.txt")" || return
  btf_digest="$(compatibility_sha256 "$evidence/campaign-proofs/kernel-btf-vmlinux")" || return
  feature_digest="$(compatibility_sha256 "$evidence/bpftool-feature-probe.txt")" || return
  provenance_digest="$(compatibility_sha256 \
    "$evidence/campaign-attestations/kernel-provenance.json")" || return
  topology_attestation_digest="$(compatibility_sha256 \
    "$evidence/campaign-attestations/topology-attestation.json")" || return
  deployment_digest="$(compatibility_sha256 "$evidence/container-identities.txt")" || return
  image_digest="$(compatibility_sha256 "$evidence/image-identities.txt")" || return
  userspace_digest="$(compatibility_sha256 "$evidence/apache-openssl-version.txt")" || return
  java_digest="$(compatibility_sha256 "$evidence/java-version.txt")" || return
  [[ "$(environment_value "$evidence/environment.txt" transport)" == \
    "$(jq -er '.transport' <<<"$requested_json")" ]] || return 1
  [[ "$(environment_value "$evidence/environment.txt" agent_distribution)" == \
    "$(jq -er '.agent_distribution' <<<"$requested_json")" ]] || return 1
  [[ "$(environment_value "$evidence/environment.txt" tls_protocol)" == \
    "$(jq -er '.tls' <<<"$requested_json")" ]] || return 1
  selection_json="$(transport_selection_from_evidence \
    "$evidence/java-selected-transport-configuration.txt" \
    "$(jq -er '.transport' <<<"$requested_json")")" || return
  jq -e --argjson requested "$requested_json" '
    .distribution == $requested.agent_distribution and
    .version == $requested.agent_version and
    (.sha256 | test("^[0-9a-f]{64}$"))
  ' <<<"$agent_json" >/dev/null || return 1
  [[ "$(jq -er '.sha256' <<<"$agent_json")" == \
    "$(compatibility_sha256 "$evidence/campaign-proofs/official-javaagent.jar")" ]] ||
    return 1

  jq -cnS \
    --argjson requested "$requested_json" \
    --arg kernel_release "$(uname -r)" \
    --arg kernel_provenance_sha256 "$provenance_digest" \
    --arg architecture "$architecture" \
    --arg topology_sha256 "$topology_digest" \
    --arg deployment_sha256 "$deployment_digest" \
    --arg btf_sha256 "$btf_digest" \
    --arg java_runtime "$java_line" \
    --arg java_evidence_sha256 "$java_digest" \
    --argjson agent "$agent_json" \
    --arg image_identities_sha256 "$image_digest" \
    --arg apache_openssl_sha256 "$userspace_digest" \
    --arg feature_probe_sha256 "$feature_digest" \
    --arg topology_attestation_sha256 "$topology_attestation_digest" \
    --argjson selection "$selection_json" \
    '{
      kernel: {
        selector: $requested.kernel,
        release: $kernel_release,
        provenance_sha256: $kernel_provenance_sha256,
        version_inference: false,
        btf_sha256: $btf_sha256
      },
      architecture: $architecture,
      deployment: {
        requested: $requested.deployment,
        observed: "container-process",
        proof: "runsh-compose-container-identities",
        evidence_sha256: $deployment_sha256
      },
      cgroup_topology: {
        requested: $requested.cgroup_topology,
        observed: $requested.cgroup_topology,
        evidence_sha256: $topology_sha256,
        attestation_sha256: $topology_attestation_sha256
      },
      jvm: {
        requested_feature: $requested.jvm_feature,
        observed_feature: 21,
        runtime: $java_runtime,
        evidence_sha256: $java_evidence_sha256
      },
      agent: ($agent + {
        requested_distribution: $requested.agent_distribution,
        requested_version: $requested.agent_version
      }),
      tls: {requested: $requested.tls, observed: $requested.tls},
      userspace: {
        image_identities_sha256: $image_identities_sha256,
        apache_openssl_evidence_sha256: $apache_openssl_sha256
      },
      provider: {
        production: true,
        requested_transport: $requested.transport,
        attempted_transports: $selection.attempted_transports,
        selected_transport: $selection.selected_transport,
        feature_probe: {
          authoritative: true,
          kind: "production-load-attach-selection-and-request",
          supported: $selection.supported,
          evidence_sha256: $feature_probe_sha256
        },
        load_reason: "production-bridge-ready",
        attach_reason: "production-helper-attached"
      }
    }'
}

build_runsh_evidence_index() {
  local -r result="$1"
  local -r output="$2"

  compatibility_expected_evidence_index "$result" |
    jq -cS '
      {
        "runtime.kernel.btf_sha256": "campaign-proofs/kernel-btf-vmlinux",
        "runtime.kernel.provenance_sha256": "campaign-attestations/kernel-provenance.json",
        "runtime.deployment.evidence_sha256": "container-identities.txt",
        "runtime.cgroup_topology.evidence_sha256": "host-topology.txt",
        "runtime.cgroup_topology.attestation_sha256": "campaign-attestations/topology-attestation.json",
        "runtime.jvm.evidence_sha256": "java-version.txt",
        "runtime.agent.sha256": "campaign-proofs/official-javaagent.jar",
        "runtime.userspace.image_identities_sha256": "image-identities.txt",
        "runtime.userspace.apache_openssl_evidence_sha256": "apache-openssl-version.txt",
        "runtime.provider.feature_probe.evidence_sha256": "bpftool-feature-probe.txt",
        "artifacts.generic_bpf_sha256": "campaign-proofs/generic-bpf.o",
        "artifacts.sockopt_bpf_sha256": "campaign-proofs/sockopt-bpf.o",
        "artifacts.jni.sha256": "campaign-proofs/libobijni.so",
        "artifacts.helper_sha256": "campaign-proofs/obi-java-agent.jar",
        "artifacts.extension_sha256": "campaign-proofs/obi-otel-extension.jar",
        "artifacts.runtime_config_sha256": "campaign-proofs/runtime-config.sha256"
      } as $paths |
      map(. as $entry |
        if $paths[$entry.field] == null then
          error("unmapped run.sh public digest field: " + $entry.field)
        else $entry + {path: $paths[$entry.field]} end) |
      sort_by(.field)
    ' >"$output"
}

write_result() {
  local -r status="$1"
  local -r reason="$2"
  local -r attempted="$3"
  local -r infrastructure_failure="$4"
  local -r exit_status="$5"
  local -r evidence="${6:-}"
  shift 6 || true
  local requested=""
  local source_identity=""
  local runtime_json=null
  local artifacts_json=null
  local assertions_json=null
  local command_json=""
  local raw_json=null
  local exact_parent=""
  local raw_manifest=""
  local provisional="$OBI_COMPATIBILITY_PRIVATE_DIR/.runsh-provider-result.provisional"
  local indexed="$OBI_COMPATIBILITY_PRIVATE_DIR/.runsh-provider-result.indexed"
  local evidence_index="$OBI_COMPATIBILITY_PRIVATE_DIR/.runsh-evidence-index.json"

  requested="$(jq -cS . "$OBI_COMPATIBILITY_CELL_JSON")" || return
  source_identity="$(provider_source_json)" || return
  command_json="$(printf '%s\0' "$@" | jq -Rs 'split("\u0000")[:-1]')" || return
  if [[ "$status" == pass || "$status" == fail ]]; then
    prepare_indexed_proof_files "$evidence" "$(cell_value '.architecture')" || return
    source_identity="$(source_identity_from_evidence "$evidence")" || return
    runtime_json="$(runtime_identity "$evidence" "$requested")" || return
    artifacts_json="$(artifact_identities "$evidence" "$(cell_value '.architecture')")" || return
  fi
  if [[ "$status" == pass ]]; then
    exact_parent="$(exact_parent_assertion "$evidence/scenario-basic.json")" || return
    assertions_json="$(jq -cnS \
      --argjson exact_parent "$exact_parent" \
      --arg profile "$(cell_value '.profile')" \
      '{
        profile: $profile,
        exact_parent: $exact_parent,
        application_result: "pass",
        cleanup: "pass",
        required_cells_skipped: false,
        product_failure: false
      }')" || return
  elif [[ "$status" == fail ]]; then
    assertions_json='{"application_result":"fail","cleanup":"unknown","product_failure":true,"required_cells_skipped":false}'
  fi

  jq -nS \
    --arg campaign "$OBI_COMPATIBILITY_CAMPAIGN" \
    --arg campaign_revision "$OBI_COMPATIBILITY_CAMPAIGN_REVISION" \
    --arg plan_sha256 "$OBI_COMPATIBILITY_PLAN_SHA256" \
    --arg provider "$PROVIDER_NAME" \
    --arg status "$status" \
    --arg reason "$reason" \
    --argjson attempted "$attempted" \
    --argjson infrastructure_failure "$infrastructure_failure" \
    --argjson exit_status "$exit_status" \
    --argjson requested "$requested" \
    --argjson command_argv "$command_json" \
    --arg adapter_sha256 "$(compatibility_sha256 "$ADAPTER")" \
    --arg runner_sha256 "$(compatibility_sha256 "$RUNNER")" \
    --argjson source "$source_identity" \
    --argjson runtime "$runtime_json" \
    --argjson artifacts "$artifacts_json" \
    --argjson assertions "$assertions_json" \
    --argjson raw_evidence "$raw_json" \
    '{
      schema: "compatibility-provider-result-v1",
      campaign: $campaign,
      campaign_revision: $campaign_revision,
      plan_sha256: $plan_sha256,
      cell_id: $requested.id,
      provider: $provider,
      status: $status,
      reason: $reason,
      attempted: $attempted,
      infrastructure_failure: $infrastructure_failure,
      requested: $requested,
      provider_registry_sha256: $ENV.OBI_COMPATIBILITY_PROVIDER_REGISTRY_SHA256,
      external_driver: null,
      command: {
        executed: $attempted,
        argv: $command_argv,
        adapter_sha256: $adapter_sha256,
        executable_sha256: $runner_sha256,
        exit_status: $exit_status
      },
      source: $source,
      runtime: $runtime,
      artifacts: $artifacts,
      assertions: $assertions,
      evidence_index: (if $status == "untested" then null else [] end),
      raw_evidence: $raw_evidence
    }' >"$provisional"
  chmod 0600 -- "$provisional"
  if [[ "$status" == pass || "$status" == fail ]]; then
    build_runsh_evidence_index "$provisional" "$evidence_index" || return
    jq -S --slurpfile index "$evidence_index" \
      '.evidence_index = $index[0]' "$provisional" >"$indexed" || return
    chmod 0600 -- "$indexed"
    raw_manifest="$OBI_COMPATIBILITY_PRIVATE_DIR/runsh-evidence.sha256"
    compatibility_directory_manifest "$evidence" "$raw_manifest" || return
    raw_json="$(jq -cnS \
      --arg directory runsh-evidence \
      --arg manifest runsh-evidence.sha256 \
      --arg manifest_sha256 "$(compatibility_sha256 "$raw_manifest")" \
      '{
        directory: $directory,
        manifest: $manifest,
        manifest_sha256: $manifest_sha256
      }')" || return
    jq -S --argjson raw "$raw_json" '.raw_evidence = $raw' \
      "$indexed" >"$OBI_COMPATIBILITY_PROVIDER_RESULT" || return
  else
    mv -T -- "$provisional" "$OBI_COMPATIBILITY_PROVIDER_RESULT"
  fi
  rm -f -- "$provisional" "$indexed" "$evidence_index"
  chmod 0600 -- "$OBI_COMPATIBILITY_PROVIDER_RESULT"
}

validate_pass_evidence() {
  local -r evidence="$1"
  local -r transport="$2"
  local -r agent="$3"
  local -r agent_version="$4"
  local -r tls="$5"
  local environment="$evidence/environment.txt"

  compatibility_validate_json_file "$evidence/run-status.json" || return
  compatibility_validate_json_file "$evidence/official-javaagent.json" || return
  compatibility_validate_json_file "$evidence/scenario-basic.json" || return
  compatibility_require_regular_file "$environment" || return
  compatibility_require_regular_file "$evidence/apache-openssl-version.txt" || return
  compatibility_require_regular_file "$evidence/bpftool-feature-probe.txt" || return
  compatibility_require_regular_file "$evidence/container-identities.txt" || return
  compatibility_require_regular_file "$evidence/image-identities.txt" || return
  compatibility_require_regular_file "$evidence/host-topology.txt" || return
  compatibility_require_regular_file "$evidence/java-version.txt" || return
  compatibility_require_regular_file "$evidence/source-state.txt" || return
  runtime_attestations_are_unchanged || return
  validate_local_runtime_evidence "$evidence" "$TOPOLOGY_ATTESTATION_SNAPSHOT" || return

  jq -e '
    .status == "passed" and .exit_status == 0 and
    .acceptance_evidence == true and
    .schema == "obi-apache-java-https-run-status-v3"
  ' "$evidence/run-status.json" >/dev/null || return 1
  [[ "$(environment_value "$environment" dirty)" == false ]] || return 1
  [[ "$(environment_value "$environment" scenario)" == all ]] || return 1
  [[ "$(environment_value "$environment" transport)" == "$transport" ]] || return 1
  [[ "$(environment_value "$environment" agent_distribution)" == "$agent" ]] || return 1
  [[ "$(environment_value "$environment" tls_protocol)" == "$tls" ]] || return 1
  [[ "$(environment_value "$environment" repeat_count)" == 1 ]] || return 1
  selected_transport_is_exact "$evidence/java-selected-transport-configuration.txt" "$transport" || return 1
  jq -e --arg agent "$agent" --arg version "$agent_version" '
    .distribution == $agent and .version == $version and
    (.sha256 | test("^[0-9a-f]{64}$"))
  ' "$evidence/official-javaagent.json" >/dev/null || return 1
  jq -e --arg tls "$tls" '
    .status == "passed" and .request_count > 0 and
    all(.cases[]; .response.tls_protocol == $tls)
  ' "$evidence/scenario-basic.json" >/dev/null || return 1
  [[ "$(jq -er '.status' <<<"$(exact_parent_assertion "$evidence/scenario-basic.json")")" == pass ]] || return 1
}

main() {
  local preflight_status=0
  local run_status=0
  local result_directory=""
  local copied_evidence="$OBI_COMPATIBILITY_PRIVATE_DIR/runsh-evidence"
  local combined_log="$OBI_COMPATIBILITY_PRIVATE_DIR/runsh-combined.log"
  local classification=""
  local status=""
  local reason=""
  local transport=""
  local agent=""
  local agent_version=""
  local tls=""
  local project_suffix=""
  local -a command=()

  provider_require_environment
  if preflight_or_untested; then
    preflight_status=0
  else
    preflight_status=$?
  fi
  (( preflight_status == 0 )) || return "$preflight_status"

  transport="$(cell_value '.transport')" || return
  agent="$(cell_value '.agent_distribution')" || return
  agent_version="$(cell_value '.agent_version')" || return
  tls="$(cell_value '.tls')" || return
  project_suffix="$(compatibility_sha256 "$OBI_COMPATIBILITY_CELL_JSON")"
  project_suffix="${project_suffix:0:12}"
  command=(
    "$RUNNER"
    --transport "$transport"
    --agent "$agent"
    --tls "$tls"
    --scenario all
    --repeat 1
    --seed 1
  )
  set +e
  COMPOSE_PROJECT_NAME="obi-apache-java-https-compat-$project_suffix" \
    compatibility_run_bounded_process_group \
      "$OBI_COMPATIBILITY_PRIVATE_DIR/runsh.stdout" \
      "$OBI_COMPATIBILITY_PRIVATE_DIR/runsh.stderr" \
      2097152 "$MAX_RUN_SECONDS" "${command[@]}"
  run_status=$?
  set -e
  {
    cat "$OBI_COMPATIBILITY_PRIVATE_DIR/runsh.stdout"
    cat "$OBI_COMPATIBILITY_PRIVATE_DIR/runsh.stderr"
  } >"$combined_log"
  runtime_attestations_are_unchanged || return 1
  if result_directory="$(find_result_directory "$combined_log")"; then
    cp -a -- "$result_directory" "$copied_evidence"
  else
    return 1
  fi
  runtime_attestations_are_unchanged || return 1

  if (( run_status != 0 )); then
    classification="$(classify_failed_run "$copied_evidence/run-status.json")" || return
    IFS=$'\t' read -r status reason <<<"$classification"
    [[ "$status" != contract ]] || return 1
    if [[ "$status" == fail ]]; then
      write_result fail "$reason" true false "$run_status" "$copied_evidence" "${command[@]}"
      return 1
    fi
    write_result untested "$reason" true true "$run_status" "" "${command[@]}"
    return 69
  fi
  if ! validate_pass_evidence \
    "$copied_evidence" "$transport" "$agent" "$agent_version" "$tls"; then
    write_result fail evidence-contract-failed true false 1 "$copied_evidence" "${command[@]}"
    return 1
  fi
  write_result pass all-required-assertions-passed true false 0 "$copied_evidence" "${command[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
