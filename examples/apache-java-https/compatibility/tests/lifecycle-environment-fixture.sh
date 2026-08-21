#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Synthetic contract fixture only. It never executes OBI, Java, or a provider.
set -Eeuo pipefail
umask 077
export LC_ALL=C

FIXTURE_PATH="$0"
readonly FIXTURE_PATH
declare -ar FIXTURE_ARGV=("$FIXTURE_PATH" "$@")

contract=""
campaign_revision=""
plan_sha256=""
cell=""
source_authority=""
source_authority_sha256=""
environment=""
environment_sha256=""
output=""

sha256_file() {
  local digest=""
  digest="$(sha256sum -- "$1")" || return
  printf '%s\n' "${digest%% *}"
}

parse_arguments() {
  while (( $# > 0 )); do
    (( $# >= 2 )) || return 2
    case "$1" in
      --contract) [[ -z "$contract" ]] || return 2; contract="$2" ;;
      --campaign-revision) [[ -z "$campaign_revision" ]] || return 2; campaign_revision="$2" ;;
      --plan-sha256) [[ -z "$plan_sha256" ]] || return 2; plan_sha256="$2" ;;
      --cell) [[ -z "$cell" ]] || return 2; cell="$2" ;;
      --source-authority) [[ -z "$source_authority" ]] || return 2; source_authority="$2" ;;
      --source-authority-sha256) [[ -z "$source_authority_sha256" ]] || return 2; source_authority_sha256="$2" ;;
      --environment) [[ -z "$environment" ]] || return 2; environment="$2" ;;
      --environment-sha256) [[ -z "$environment_sha256" ]] || return 2; environment_sha256="$2" ;;
      --output) [[ -z "$output" ]] || return 2; output="$2" ;;
      *) return 2 ;;
    esac
    shift 2
  done
}

write_untested() {
  local -r result="$output/result.json"
  local requested=""
  local command_json=""
  local executor_sha256=""
  local environment_id=""

  requested="$(jq -cS . "$cell")"
  command_json="$(printf '%s\0' "${FIXTURE_ARGV[@]}" |
    jq -Rs 'split("\u0000")[:-1]')"
  executor_sha256="$(sha256_file "$FIXTURE_PATH")"
  environment_id="$(jq -er '.id' "$environment")"
  jq -nS \
    --arg campaign_revision "$campaign_revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg environment_id "$environment_id" \
    --arg environment_sha256 "$environment_sha256" \
    --arg executor_sha256 "$executor_sha256" \
    --argjson requested "$requested" \
    --argjson command "$command_json" '{
      schema:"compatibility-helper-lifecycle-environment-result-v1",
      campaign_revision:$campaign_revision,
      plan_sha256:$plan_sha256,
      requested:$requested,
      environment:{id:$environment_id,sha256:$environment_sha256},
      command:{argv:$command,executable_sha256:$executor_sha256,exit_status:69},
      status:"untested",
      reason:"synthetic-lifecycle-infrastructure-unavailable",
      runtime:null,
      artifacts:null,
      assertions:null,
      evidence_index:null,
      raw_evidence:null
    }' >"$result"
  chmod 0600 -- "$result"
}

write_pass_observation() {
  local -r mode="$1"
  local raw="$output/raw"
  local result="$output/result.json"
  local manifest="$output/raw.sha256"
  local index_entries="$output/index-entries.jsonl"
  local index_fields="$output/index-fields.tsv"
  local candidate="$output/result.candidate.json"
  local requested=""
  local command_json=""
  local executor_sha256=""
  local environment_id=""
  local frameworks=""
  local lifecycle=""
  local resources=""
  local assertions=""
  local field=""
  local path=""
  local file=""
  local digest=""
  local count=0
  local gate=""

  install -d -m 0700 -- "$raw"
  requested="$(jq -cS . "$cell")"
  command_json="$(printf '%s\0' "${FIXTURE_ARGV[@]}" |
    jq -Rs 'split("\u0000")[:-1]')"
  executor_sha256="$(sha256_file "$FIXTURE_PATH")"
  environment_id="$(jq -er '.id' "$environment")"
  frameworks="$(jq -cnS '
    ["blocking-sslsocket", "sslengine-socketchannel", "netty-sslhandler"] |
    map({key:.,value:{
      status:"pass",evidence_sha256:("0" * 64),requests:3,
      exact_parents:3,wrong_parents:0,crashes:0
    }}) | from_entries
  ')"
  lifecycle="$(jq -cnS '
    [
      "normal-extraction", "fallback-context-unavailable", "platform-thread",
      "executor-handoff", "cross-thread-handoff", "cross-request-isolation",
      "duplicate-callback", "stale-state", "helper-early-attach",
      "helper-late-attach", "obi-absent", "unsupported-transport", "obi-restart",
      "version-mismatch", "extension-absent", "extension-loaded-first"
    ] | map({key:.,value:{
      status:"pass",evidence_sha256:("0" * 64),requests:3,
      exact_parents:3,wrong_parents:0,crashes:0
    }}) | from_entries
  ')"
  resources="$(jq -cnS '
    [
      "native-fd", "live-thread", "direct-buffer", "classloader-weak-reference",
      "request-state", "task-state", "thread-local-state", "same-process-identity"
    ] | map({key:.,value:{
      status:"pass",cycles:3,evidence_sha256:("0" * 64),baseline:1,final:1,
      delta:0,allowed_delta:0,trend_slope:0,maximum_trend_slope:0
    }}) | from_entries
  ')"
  assertions="$(jq -cnS \
    --argjson jvm "$(jq -er '.jvm_feature' "$cell")" \
    --argjson frameworks "$frameworks" \
    --argjson lifecycle "$lifecycle" \
    --argjson resources "$resources" '
      {
        application_result:"pass",cleanup:"pass",product_failure:false,
        required_cells_skipped:false,
        exact_parent:{status:"pass",requests:3,matched:3,wrong:0},
        frameworks:$frameworks,
        lifecycle:$lifecycle,
        resource_gates:$resources,
        unavailable_bridge:{
          status:"pass",result_equivalent:true,
          normal_result_sha256:("0" * 64),
          unavailable_result_sha256:("0" * 64),
          normal_agent_extraction:{
            status:"pass",evidence_sha256:("0" * 64),requests:3,
            exact_parents:3,wrong_parents:0,crashes:0
          },
          diagnostics:{
            status:"pass",evidence_sha256:("0" * 64),count:1,bytes:0,
            max_count:64,max_bytes:65536
          }
        },
        virtual_thread:
          (if $jvm == 21 then {
            status:"pass",evidence_sha256:("0" * 64),requests:3,
            exact_parents:3,wrong_parents:0,crashes:0
          } else {
            status:"unsupported",reason:"requires-java-21",
            evidence_sha256:("0" * 64)
          } end)
      }
    ')"
  jq -nS \
    --arg campaign_revision "$campaign_revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg environment_id "$environment_id" \
    --arg environment_sha256 "$environment_sha256" \
    --arg executor_sha256 "$executor_sha256" \
    --argjson requested "$requested" \
    --argjson command "$command_json" \
    --argjson assertions "$assertions" '
      $requested as $r |
      {
        schema:"compatibility-helper-lifecycle-environment-result-v1",
        campaign_revision:$campaign_revision,
        plan_sha256:$plan_sha256,
        requested:$r,
        environment:{id:$environment_id,sha256:$environment_sha256},
        command:{argv:$command,executable_sha256:$executor_sha256,exit_status:0},
        status:"pass",
        reason:"synthetic-lifecycle-fixture-pass",
        runtime:{
          kernel:{selector:$r.kernel,release:"6.12.0-fixture",provenance_sha256:("0" * 64),version_inference:false,btf_sha256:("0" * 64)},
          architecture:$r.architecture,
          deployment:{requested:$r.deployment,observed:$r.deployment,proof:"synthetic-lifecycle-fixture",evidence_sha256:("0" * 64)},
          cgroup_topology:{requested:$r.cgroup_topology,observed:$r.cgroup_topology,evidence_sha256:("0" * 64),attestation_sha256:("0" * 64)},
          jvm:{requested_feature:$r.jvm_feature,observed_feature:$r.jvm_feature,runtime:("fixture-java-" + ($r.jvm_feature|tostring)),evidence_sha256:("0" * 64)},
          agent:{requested_distribution:$r.agent_distribution,distribution:$r.agent_distribution,requested_version:$r.agent_version,version:$r.agent_version,sha256:("0" * 64),url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar"},
          tls:{requested:$r.tls,observed:$r.tls},
          userspace:{image_identities_sha256:("0" * 64),apache_openssl_evidence_sha256:("0" * 64)},
          provider:{production:true,requested_transport:$r.transport,attempted_transports:(if $r.transport == "auto" then ["getsockopt"] else [$r.transport] end),selected_transport:(if $r.transport == "auto" then "getsockopt" else $r.transport end),feature_probe:{authoritative:true,supported:true,kind:"preprovisioned-lifecycle-fixture",evidence_sha256:("0" * 64)},load_reason:"fixture",attach_reason:"fixture"}
        },
        artifacts:{
          generic_bpf_sha256:("0" * 64),sockopt_bpf_sha256:("0" * 64),
          jni:{entry:(if $r.architecture == "amd64" then "native/linux-amd64/libobijni.so" else "native/linux-aarch64/libobijni.so" end),sha256:("0" * 64)},
          helper_sha256:("0" * 64),extension_sha256:("0" * 64),runtime_config_sha256:("0" * 64)
        },
        assertions:$assertions,
        evidence_index:[],
        raw_evidence:{directory:"raw",manifest:"raw.sha256",manifest_sha256:("0" * 64)}
      }
    ' >"$result"
  chmod 0600 -- "$result"

  jq -r '
    [(.runtime // {}),(.artifacts // {}),(.assertions // {})] as $roots |
    [range(0; $roots|length) as $root_index |
      ($roots[$root_index] | paths(scalars) as $path |
        ($path[-1]|tostring) as $leaf |
        select($leaf == "sha256" or ($leaf|endswith("_sha256"))) |
        {
          field:([(["runtime","artifacts","assertions"][$root_index])] +
            ($path|map(tostring)) | join(".")),
          sha256:getpath($path)
        })] | sort_by(.field)[] | [.field,.sha256] | @tsv
  ' "$result" >"$index_fields"
  : >"$index_entries"
  while IFS=$'\t' read -r field _; do
    (( count += 1 ))
    path="proof-$(printf '%03d' "$count").txt"
    case "$field" in
      assertions.unavailable_bridge.normal_result_sha256)
        path=unavailable-bridge/normal-result.json ;;
      assertions.unavailable_bridge.unavailable_result_sha256)
        path=unavailable-bridge/unavailable-result.json ;;
      assertions.unavailable_bridge.normal_agent_extraction.evidence_sha256)
        path=unavailable-bridge/normal-agent-extraction.json ;;
      assertions.unavailable_bridge.diagnostics.evidence_sha256)
        path=unavailable-bridge/diagnostics.json ;;
    esac
    file="$raw/$path"
    install -d -m 0700 -- "$(dirname -- "$file")"
    case "$field" in
      assertions.unavailable_bridge.normal_result_sha256|assertions.unavailable_bridge.unavailable_result_sha256)
        jq -nS '{schema:"compatibility-bridge-result-v1",result:"unchanged"}' >"$file" ;;
      assertions.unavailable_bridge.normal_agent_extraction.evidence_sha256)
        jq -nS '{schema:"compatibility-normal-agent-extraction-v1",status:"pass",requests:3,exact_parents:3,wrong_parents:0,crashes:0}' >"$file" ;;
      assertions.unavailable_bridge.diagnostics.evidence_sha256)
        jq -nS '{schema:"compatibility-unavailable-bridge-diagnostics-v1",diagnostics:["bridge-unavailable-control"]}' >"$file" ;;
      *) printf 'synthetic lifecycle proof for %s\n' "$field" >"$file" ;;
    esac
    chmod 0600 -- "$file"
    if [[ "$field" == assertions.unavailable_bridge.diagnostics.evidence_sha256 ]]; then
      jq -S --argjson bytes "$(stat -Lc '%s' -- "$file")" \
        '.assertions.unavailable_bridge.diagnostics.bytes=$bytes' \
        "$result" >"$candidate"
      mv -fT -- "$candidate" "$result"
    fi
    digest="$(sha256_file "$file")"
    jq -S --arg field "$field" --arg digest "$digest" \
      'setpath(($field|split("."));$digest)' "$result" >"$candidate"
    mv -fT -- "$candidate" "$result"
    jq -cnS --arg field "$field" --arg path "$path" --arg sha256 "$digest" \
      '{field:$field,path:$path,sha256:$sha256}' >>"$index_entries"
  done <"$index_fields"
  jq -sS 'sort_by(.field)' "$index_entries" >"$candidate"
  jq -S --slurpfile index "$candidate" '.evidence_index=$index[0]' \
    "$result" >"$result.new"
  mv -fT -- "$result.new" "$result"
  rm -f -- "$candidate" "$index_entries" "$index_fields"

  case "$mode" in
    pass|swap-open-snapshot|setsid-escape|delayed-double-fork-setsid-escape) ;;
    lifecycle-fail:*)
      gate="${mode#lifecycle-fail:}"
      jq -S --arg gate "$gate" '.assertions.lifecycle[$gate].status="fail"' \
        "$result" >"$result.new"
      mv -fT -- "$result.new" "$result"
      ;;
    resource-leak:*)
      gate="${mode#resource-leak:}"
      jq -S --arg gate "$gate" '
        .assertions.resource_gates[$gate].final=2 |
        .assertions.resource_gates[$gate].delta=1
      ' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result"
      ;;
    resource-trend:*)
      gate="${mode#resource-trend:}"
      jq -S --arg gate "$gate" '
        .assertions.resource_gates[$gate].trend_slope=1
      ' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result"
      ;;
    wrong-cell)
      jq -S '.requested.id="h-jdk17-amd64-otel-getsockopt"' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result" ;;
    wrong-transport)
      jq -S '.requested.transport="unix"' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result" ;;
    wrong-jdk)
      jq -S '.requested.jvm_feature=17' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result" ;;
    wrong-arch)
      jq -S '.requested.architecture="arm64"' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result" ;;
    lying-argv)
      jq -S '.command.argv=["fabricated-lifecycle-command"]' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result" ;;
    result-different)
      printf '{"schema":"compatibility-bridge-result-v1","result":"changed"}\n' \
        >"$raw/unavailable-bridge/unavailable-result.json"
      digest="$(sha256_file "$raw/unavailable-bridge/unavailable-result.json")"
      jq -S --arg digest "$digest" '
        .assertions.unavailable_bridge.unavailable_result_sha256=$digest |
        .evidence_index |= map(
          if .field == "assertions.unavailable_bridge.unavailable_result_sha256"
          then .sha256=$digest else . end)
      ' "$result" >"$result.new"
      mv -fT -- "$result.new" "$result"
      ;;
    diagnostic-count)
      jq -S '.assertions.unavailable_bridge.diagnostics.count=65' \
        "$result" >"$result.new"
      mv -fT -- "$result.new" "$result" ;;
    diagnostic-bytes)
      jq -S '.assertions.unavailable_bridge.diagnostics.bytes=65537' \
        "$result" >"$result.new"
      mv -fT -- "$result.new" "$result" ;;
    malformed)
      printf '{"schema":' >"$result"
      return 0
      ;;
    *)
      printf 'unknown lifecycle fixture mode: %s\n' "$mode" >&2
      return 2
      ;;
  esac
  (
    CDPATH='' cd -- "$raw"
    find . -mindepth 1 -type f -printf '%P\0' | LC_ALL=C sort -z |
      while IFS= read -r -d '' path; do
        printf '%s  %s\n' "$(sha256_file "$path")" "$path"
      done
  ) >"$manifest"
  chmod 0600 -- "$manifest"
  jq -S --arg sha256 "$(sha256_file "$manifest")" \
    '.raw_evidence.manifest_sha256=$sha256' "$result" >"$result.new"
  mv -fT -- "$result.new" "$result"
  chmod 0600 -- "$result"
}

main() {
  local mode="${OBI_COMPATIBILITY_LIFECYCLE_FIXTURE_MODE:-pass}"
  local snapshot_target=""
  local escape_pid_file=""
  local iteration=0

  parse_arguments "$@"
  [[ "$contract" == compatibility-helper-lifecycle-environment-v1 ]]
  [[ "$campaign_revision" == apache-java-https-helper-lifecycle-v1 ]]
  [[ "$plan_sha256" =~ ^[0-9a-f]{64}$ ]]
  [[ -f "$cell" && ! -L "$cell" ]]
  [[ -f "$source_authority" && ! -L "$source_authority" ]]
  [[ "$(sha256_file "$source_authority")" == "$source_authority_sha256" ]]
  [[ -f "$environment" && ! -L "$environment" ]]
  [[ "$(sha256_file "$environment")" == "$environment_sha256" ]]
  [[ ! -e "$output" && ! -L "$output" ]]
  install -d -m 0700 -- "$output"
  case "$mode" in
    untested)
      write_untested
      exit 69
      ;;
    missing-result)
      exit 0
      ;;
    *)
      write_pass_observation "$mode"
      ;;
  esac
  case "$mode" in
    swap-open-snapshot)
      snapshot_target="$(readlink -f -- "$FIXTURE_PATH")"
      [[ -f "$snapshot_target" && ! -L "$snapshot_target" ]]
      mv -- "$snapshot_target" "$snapshot_target.before-swap"
      printf '#!/usr/bin/env bash\nexit 99\n' >"$snapshot_target"
      chmod 0500 -- "$snapshot_target"
      ;;
    setsid-escape)
      escape_pid_file="$output/escaped-descendant.pid"
      python3 - "$escape_pid_file" <<'PY' &
import os
import sys
import time

os.setsid()
with open(sys.argv[1], "w", encoding="ascii") as stream:
    stream.write(f"{os.getpid()}\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(300)
PY
      for (( iteration = 0; iteration < 100; iteration += 1 )); do
        [[ -s "$escape_pid_file" ]] && break
        sleep 0.01
      done
      [[ -s "$escape_pid_file" ]]
      ;;
    delayed-double-fork-setsid-escape)
      escape_pid_file="$output/escaped-descendant.pid"
      python3 - "$escape_pid_file" <<'PY' &
import os
import sys
import time


time.sleep(0.2)
os.setsid()
time.sleep(0.2)
if os.fork() != 0:
    os._exit(0)
if os.fork() != 0:
    os._exit(0)
with open(sys.argv[1], "w", encoding="ascii") as stream:
    stream.write(f"{os.getpid()}\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(300)
PY
      for (( iteration = 0; iteration < 200; iteration += 1 )); do
        [[ -s "$escape_pid_file" ]] && break
        sleep 0.01
      done
      [[ -s "$escape_pid_file" ]]
      ;;
  esac
}

main "$@"
