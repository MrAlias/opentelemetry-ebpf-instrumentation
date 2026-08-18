#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERIFIER="$SCRIPT_DIR/verify-retained-evidence.sh"
TEST_TMP_DIR=""
readonly MAX_UINT64_DECIMAL='18446744073709551615'
readonly SCRIPT_DIR VERIFIER MAX_UINT64_DECIMAL

die() {
  printf 'verify-retained-evidence_test.sh: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TEST_TMP_DIR:-}" && -d "$TEST_TMP_DIR" ]]; then
    rm -rf -- "$TEST_TMP_DIR"
  fi
}

trap cleanup EXIT

check_dependencies() {
  local -a missing=()
  local command_name=""

  for command_name in chmod cp find git jq mkdir mktemp mv rm sed sha256sum sort stat; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  (( ${#missing[@]} == 0 )) || die "missing required commands: ${missing[*]}"
}

commit_fixture() {
  local -r repository="$1"
  local -r subject="$2"

  git -C "$repository" add -A
  git -C "$repository" commit --quiet -m "$subject"
}

write_source_tree_manifest() {
  local -r repository="$1"
  local -r revision="$2"
  local -r output="$3"
  local entries="$TEST_TMP_DIR/source-tree-entries"
  local entry=""
  local metadata=""
  local path=""
  local mode=""
  local object_id=""
  local executable=""

  git -C "$repository" ls-tree -r -z --full-tree "$revision" >"$entries"
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    case "$mode" in
      100644) executable='-' ;;
      100755) executable='x' ;;
      *) die "unexpected fixture Git mode: $mode" ;;
    esac
    LC_ALL=C printf '%s %s %q\n' "$object_id" "$executable" "$path"
  done <"$entries" >"$output"
}

write_bundle_checksums() {
  local -r bundle="$1"
  local file=""

  (
    cd -- "$bundle"
    while IFS= read -r -d '' file; do
      sha256sum "$file"
    done < <(find . -type f ! -path './SHA256SUMS' -print0 | LC_ALL=C sort -z)
  ) >"$bundle/SHA256SUMS"
}

replace_json_file() {
  local -r file="$1"
  local -r filter="$2"
  local -r candidate="$file.tmp"

  jq "$filter" "$file" >"$candidate"
  mv -- "$candidate" "$file"
}

sync_obi_pair_embeddings() {
  local -r bundle="$1"
  local -r pair="$bundle/obi-metric-pairs/terminal.json"
  local -r terminal="$bundle/terminal-obi-metrics.json"
  local -r status="$bundle/run-status.json"
  local -r terminal_candidate="$terminal.tmp"
  local -r status_candidate="$status.tmp"

  jq --slurpfile pair "$pair" '.pair = $pair[0]' \
    "$terminal" >"$terminal_candidate"
  mv -- "$terminal_candidate" "$terminal"
  jq --slurpfile terminal "$terminal" \
    '.obi_metric_evidence = $terminal[0]' \
    "$status" >"$status_candidate"
  mv -- "$status_candidate" "$status"
}

sync_run_status_obi_embedding() {
  local -r bundle="$1"
  local -r terminal="$bundle/terminal-obi-metrics.json"
  local -r status="$bundle/run-status.json"
  local -r candidate="$status.tmp"

  jq --slurpfile terminal "$terminal" \
    '.obi_metric_evidence = $terminal[0]' \
    "$status" >"$candidate"
  mv -- "$candidate" "$status"
}

sync_run_status_java_embedding() {
  local -r bundle="$1"
  local -r terminal="$bundle/terminal-java-diagnostics.json"
  local -r status="$bundle/run-status.json"
  local -r candidate="$status.tmp"

  jq --slurpfile terminal "$terminal" \
    '.java_bridge_diagnostics = $terminal[0]' \
    "$status" >"$candidate"
  mv -- "$candidate" "$status"
}

refresh_running_identity_metrics_digest() {
  local -r bundle="$1"
  local -r phase="$2"
  local -r metrics="$bundle/phases/$phase/obi-metrics.prom"
  local -r identity="$bundle/phases/$phase/obi-identity.json"
  local -r candidate="$identity.tmp"
  local digest=""

  digest="$(sha256sum "$metrics")" || return 1
  digest="${digest%% *}"
  jq --arg digest "$digest" '.metrics_sha256 = $digest' \
    "$identity" >"$candidate"
  mv -- "$candidate" "$identity"
}

expect_committed_bundle_rejection() {
  local -r repository="$1"
  local -r verifier="$2"
  local -r bundle="$3"
  local -r subject="$4"

  write_bundle_checksums "$bundle"
  commit_fixture "$repository" "$subject"
  if "$verifier" "$bundle" >/dev/null 2>&1; then
    die "verifier accepted $subject"
  fi
}

restore_valid_bundle() {
  local -r repository="$1"
  local -r bundle="$2"
  local -r baseline="$3"
  local -r subject="$4"
  local -r expected_prefix="$repository/examples/apache-java-https/evidence/"

  [[ "$bundle" == "$expected_prefix"* && -d "$baseline" ]] || {
    die "refusing to restore an unsafe fixture bundle path"
  }
  rm -rf -- "$bundle"
  mkdir -p -- "$bundle"
  cp -a -- "$baseline/." "$bundle/"
  commit_fixture "$repository" "$subject"
}

test_v2_mutation_rejections() {
  local -r repository="$1"
  local -r verifier="$2"
  local -r bundle="$3"
  local -r baseline="$4"
  local before_metrics=""
  local after_metrics=""
  local after_identity=""
  local digest=""
  local java_diagnostics=""
  local snapshot=""

  replace_json_file "$bundle/phases/terminal-after/obi-identity.json" '
    .container_id = "2222222222222222222222222222222222222222222222222222222222222222" |
    .started_at = "2026-08-17T00:02:00.000000000Z"
  '
  replace_json_file "$bundle/obi-metric-pairs/terminal.json" '
    .continuity = "process_replaced" |
    (.series[].delta = null) |
    .java_attach_errors.delta = null
  '
  sync_obi_pair_embeddings "$bundle"
  write_bundle_checksums "$bundle"
  commit_fixture "$repository" 'Accept valid process-replacement continuity'
  "$verifier" "$bundle" >/dev/null
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after process replacement'

  replace_json_file "$bundle/phases/terminal-after/obi-identity.json" '
    {
      schema: "obi-process-identity-v1",
      state: "obi_stopped",
      container_id: .container_id,
      host_pid: "0",
      started_at: .started_at,
      finished_at: "2026-08-17T00:03:00.000000000Z",
      exit_code: "0"
    }
  '
  rm -f -- "$bundle/phases/terminal-after/obi-metrics.prom"
  replace_json_file "$bundle/obi-metric-pairs/terminal.json" '
    .after.state = "obi_stopped" |
    (.series[].after = null) |
    (.series[].delta = null) |
    .java_attach_errors.after = null |
    .java_attach_errors.delta = null
  '
  sync_obi_pair_embeddings "$bundle"
  write_bundle_checksums "$bundle"
  commit_fixture "$repository" 'Accept valid stopped-process continuity'
  "$verifier" "$bundle" >/dev/null
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after stopped process'

  replace_json_file "$bundle/run-status.json" 'del(.schema)'
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject unallowlisted schema-less run status'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after schema mutation'

  replace_json_file "$bundle/run-status.json" \
    '.evidence_directory = "/tmp/raw-result"'
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject runtime-local evidence directory in retained status'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after raw-path mutation'

  replace_json_file "$bundle/run-status.json" \
    '.java_bridge_diagnostics.counters.cfg_on = "1"'
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject mismatched embedded Java diagnostics'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after Java embedding mutation'

  java_diagnostics="$bundle/phases/terminal-after/java-diagnostics.txt"
  snapshot="$(<"$java_diagnostics")"
  [[ "$snapshot" == cfg_on=0,* ]] || die "unexpected Java fixture snapshot"
  printf 'cfg_on=1,%s\n' "${snapshot#cfg_on=0,}" >"$java_diagnostics"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject terminal Java diagnostics differing from the raw snapshot'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after raw Java mutation'

  mkdir -p -- "$bundle/phases/stale-java"
  cp -- "$bundle/phases/terminal-after/java-diagnostics.txt" \
    "$bundle/phases/stale-java/java-diagnostics.txt"
  replace_json_file "$bundle/terminal-java-diagnostics.json" '
    .phase = "stale-java" |
    .reference = "phases/stale-java/java-diagnostics.txt"
  '
  sync_run_status_java_embedding "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject stale Java diagnostics from a different OBI after phase'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after stale-Java mutation'

  replace_json_file "$bundle/terminal-obi-metrics.json" \
    '.pair.series[0].delta = "0"'
  sync_run_status_obi_embedding "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject terminal OBI pair differing from its reference'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after pair-reference mutation'

  replace_json_file "$bundle/obi-metric-pairs/terminal.json" '
    .before.identity_reference = .after.identity_reference |
    .series[0].before = "18446744073709551615" |
    .series[0].delta = "0" |
    .java_attach_errors.before = "10" |
    .java_attach_errors.delta = "0"
  '
  sync_obi_pair_embeddings "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject a pair collapsed onto one rederived identity reference'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after collapsed-reference mutation'

  replace_json_file "$bundle/obi-metric-pairs/terminal.json" \
    '.series[0].delta = "0"'
  sync_obi_pair_embeddings "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject self-consistent copies with a rederived delta mismatch'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after delta mutation'

  replace_json_file "$bundle/obi-metric-pairs/terminal.json" \
    '.series[0].before = "018446744073709551614"'
  sync_obi_pair_embeddings "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject noncanonical uint64 metric strings'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after uint64 mutation'

  replace_json_file "$bundle/obi-metric-pairs/terminal.json" \
    '.continuity = "process_replaced" | (.series[].delta = null) | .java_attach_errors.delta = null'
  sync_obi_pair_embeddings "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject continuity inconsistent with process identities'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after continuity mutation'

  before_metrics="$bundle/phases/terminal-before/obi-metrics.prom"
  after_metrics="$bundle/phases/terminal-after/obi-metrics.prom"
  after_identity="$bundle/phases/terminal-after/obi-identity.json"
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 7' \
    >"$before_metrics"
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 8' \
    >"$after_metrics"
  refresh_running_identity_metrics_digest "$bundle" terminal-before
  refresh_running_identity_metrics_digest "$bundle" terminal-after
  replace_json_file "$bundle/obi-metric-pairs/terminal.json" '
    .series = [] |
    .java_attach_errors = {before: "0", after: "0", delta: "0"}
  '
  sync_obi_pair_embeddings "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject unrelated-only raw snapshots with an empty zero pair'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after empty-target mutation'

  after_metrics="$bundle/phases/terminal-after/obi-metrics.prom"
  after_identity="$bundle/phases/terminal-after/obi-identity.json"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 18446744073709551613' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 10' \
    >"$after_metrics"
  digest="$(sha256sum "$after_metrics")"
  digest="${digest%% *}"
  jq --arg digest "$digest" '.metrics_sha256 = $digest' \
    "$after_identity" >"$after_identity.tmp"
  mv -- "$after_identity.tmp" "$after_identity"
  replace_json_file "$bundle/obi-metric-pairs/terminal.json" '
    .series[0].after = "18446744073709551613" |
    .series[0].delta = "0"
  '
  sync_obi_pair_embeddings "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject a same-process monotonic counter regression'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after monotonicity mutation'

  after_metrics="$bundle/phases/terminal-after/obi-metrics.prom"
  after_identity="$bundle/phases/terminal-after/obi-identity.json"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 18446744073709551616' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 10' \
    >"$after_metrics"
  digest="$(sha256sum "$after_metrics")"
  digest="${digest%% *}"
  jq --arg digest "$digest" '.metrics_sha256 = $digest' \
    "$after_identity" >"$after_identity.tmp"
  mv -- "$after_identity.tmp" "$after_identity"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject out-of-range raw uint64 metrics despite a matching digest'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after raw-metric mutation'

  "$verifier" "$bundle" >/dev/null
}

write_java_diagnostics_fixture() {
  local -r bundle="$1"
  local -r phase="$2"
  local -r output="$bundle/phases/$phase/java-diagnostics.txt"
  local snapshot=""
  local name=""
  local separator=""
  local -a names=(
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

  mkdir -p -- "${output%/*}"
  for name in "${names[@]}"; do
    snapshot+="$separator$name=0"
    separator=,
  done
  printf '%s\n' "$snapshot" >"$output"
  jq -cn \
    --arg phase "$phase" \
    --arg reference "phases/$phase/java-diagnostics.txt" \
    --arg snapshot "$snapshot" '
      {
        schema: "obi-java-bridge-terminal-diagnostics-v1",
        sealed: true,
        available: true,
        phase: $phase,
        reference: $reference,
        snapshot: $snapshot,
        counters: (
          $snapshot
          | split(",")
          | map(split("=") | {(.[0]): .[1]})
          | add
        )
      }
    ' >"$bundle/terminal-java-diagnostics.json"
}

write_running_identity_fixture() {
  local -r bundle="$1"
  local -r phase="$2"
  local -r container_id="$3"
  local -r started_at="$4"
  local -r metrics="$bundle/phases/$phase/obi-metrics.prom"
  local digest=""

  digest="$(sha256sum "$metrics")" || return 1
  digest="${digest%% *}"
  jq -cn \
    --arg container_id "$container_id" \
    --arg started_at "$started_at" \
    --arg metrics_reference "phases/$phase/obi-metrics.prom" \
    --arg metrics_sha256 "$digest" '
      {
        schema: "obi-process-identity-v1",
        state: "running",
        container_id: $container_id,
        host_pid: "101",
        started_at: $started_at,
        metrics_reference: $metrics_reference,
        metrics_sha256: $metrics_sha256
      }
    ' >"$bundle/phases/$phase/obi-identity.json"
}

write_terminal_metric_fixture() {
  local -r bundle="$1"
  local -r before_phase='terminal-before'
  local -r after_phase='terminal-after'
  local -r boundary='terminal'
  local -r container_id='1111111111111111111111111111111111111111111111111111111111111111'
  local -r started_at='2026-08-17T00:00:00.000000000Z'
  local -r pair_reference="obi-metric-pairs/$boundary.json"
  local -r pair="$bundle/$pair_reference"

  mkdir -p -- \
    "$bundle/phases/$before_phase" "$bundle/phases/$after_phase" \
    "$bundle/obi-metric-pairs"
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 7' \
    'obi_java_remote_parent_operations_total{status="valid",transport="getsockopt",operation="take"} 18446744073709551614' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="python"} 200' \
    'obi_instrumentation_errors_total{process_name="java",error_type="attaching_java_agent"} 9' \
    >"$bundle/phases/$before_phase/obi-metrics.prom"
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="1",map_name="java_remote_parent_state",map_type="hash"} 8' \
    "obi_java_remote_parent_operations_total{operation=\"take\",status=\"valid\",transport=\"getsockopt\"} $MAX_UINT64_DECIMAL" \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="python"} 201' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 10' \
    >"$bundle/phases/$after_phase/obi-metrics.prom"
  write_running_identity_fixture \
    "$bundle" "$before_phase" "$container_id" "$started_at"
  write_running_identity_fixture \
    "$bundle" "$after_phase" "$container_id" "$started_at"
  jq -cn \
    --arg boundary "$boundary" \
    --arg before_reference "phases/$before_phase/obi-identity.json" \
    --arg after_reference "phases/$after_phase/obi-identity.json" '
      {
        schema: "obi-java-remote-parent-metric-pair-v1",
        boundary: $boundary,
        continuity: "same_process",
        before: {state: "running", identity_reference: $before_reference},
        after: {state: "running", identity_reference: $after_reference},
        series: [{
          transport: "getsockopt",
          operation: "take",
          status: "valid",
          before: "18446744073709551614",
          after: "18446744073709551615",
          delta: "1"
        }],
        java_attach_errors: {before: "9", after: "10", delta: "1"}
      }
    ' >"$pair"
  jq -cn --arg pair_reference "$pair_reference" --slurpfile pair "$pair" '
    {
      schema: "obi-java-remote-parent-terminal-metrics-v1",
      sealed: true,
      available: true,
      pair_reference: $pair_reference,
      pair: $pair[0]
    }
  ' >"$bundle/terminal-obi-metrics.json"
  write_java_diagnostics_fixture "$bundle" "$after_phase"
}

create_bundle() {
  local -r repository="$1"
  local -r evidence_id="$2"
  local -r revision="$3"
  local -r bundle="$repository/examples/apache-java-https/evidence/$evidence_id"
  local source_tree_sha256=""

  mkdir -p -- "$bundle"
  write_source_tree_manifest "$repository" "$revision" "$bundle/source-tree.manifest"
  source_tree_sha256="$(sha256sum <"$bundle/source-tree.manifest")"
  source_tree_sha256="${source_tree_sha256%% *}"

  printf '%s\n' "$revision" >"$bundle/bridge-source-revision.txt"
  printf '%s\n' "$source_tree_sha256" >"$bundle/bridge-source-tree.sha256"
  : >"$bundle/git-status.txt"
  printf '%s\n' \
    "revision=$revision" \
    'dirty=false' \
    "source_tree_sha256=$source_tree_sha256" \
    'source_tree_manifest_schema=git-tree-v2' \
    'tracked_patch_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    >"$bundle/source-state.txt"
  printf '%s\n' \
    'invocation=synthetic-current-code' \
    "revision=$revision" \
    'dirty=false' \
    "source_tree_sha256=$source_tree_sha256" \
    'source_tree_manifest_schema=git-tree-v2' \
    'tracked_patch_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    'transport=getsockopt' \
    'scenario=all' \
    'repeat_count=1' \
    'acceptance_evidence=true' \
    'request_count=0' \
    'bridge_build_mode=fresh' \
    'acceptance_evidence_reason=none' \
    >"$bundle/environment.txt"
  write_terminal_metric_fixture "$bundle"
  jq -cn \
    --arg evidence_id "$evidence_id" \
    --slurpfile java_bridge_diagnostics "$bundle/terminal-java-diagnostics.json" \
    --slurpfile obi_metric_evidence "$bundle/terminal-obi-metrics.json" '{
      schema: "obi-apache-java-https-run-status-v2",
      status: "passed",
      exit_status: 0,
      acceptance_evidence: true,
      acceptance_evidence_reason: "none",
      failure_stage: "none",
      failure_line: 0,
      evidence_id: $evidence_id,
      java_bridge_diagnostics_reference: "terminal-java-diagnostics.json",
      java_bridge_diagnostics: $java_bridge_diagnostics[0],
      obi_metric_evidence_reference: "terminal-obi-metrics.json",
      obi_metric_evidence: $obi_metric_evidence[0]
    }' >"$bundle/run-status.json"
  jq -cn --arg evidence_id "$evidence_id" --arg revision "$revision" '{
    sanitized: true,
    evidence_id: $evidence_id,
    source_revision: $revision
  }' >"$bundle/runtime-metadata.json"
  jq -cn --arg revision "$revision" --arg source_tree_sha256 "$source_tree_sha256" '{
    source_revision: $revision,
    source_tree_sha256: $source_tree_sha256
  }' >"$bundle/bridge-artifacts.json"
  write_bundle_checksums "$bundle"
}

all_v3_boundary_ids_json() {
  printf '%s\n' \
    basic delayed-otlp-suppression security \
    keepalive pipelining concurrency connection-churn fd-port-reuse \
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff \
    virtual-thread netty netty-server dispatch w3c w3c-match obi-flags \
    primary-w3c-stale primary-generation-mismatch primary-w3c-fault \
    unix-w3c-stale unix-generation-mismatch w3c-fault \
    permanent-absence auto-unavailable late-attach restart-during-traffic \
    helper-attach-failure disabled extension-controls uninstrumented |
    jq -Rsc 'split("\n") | map(select(length > 0))'
}

sync_v3_index_envelopes() {
  local -r bundle="$1"
  local -r index="$bundle/obi-metric-boundary-index.json"
  local -r terminal="$bundle/terminal-obi-metrics.json"
  local -r status="$bundle/run-status.json"
  local digest=""

  jq -cS . "$index" >"$index.tmp"
  mv -- "$index.tmp" "$index"
  digest="$(sha256sum "$index")" || return 1
  digest="${digest%% *}"
  printf 'obi-metric-boundary-index-frozen-v1:%s\n' "$digest" \
    >"$bundle/.obi-metric-boundary-index.freeze"
  jq --arg digest "$digest" '.boundary_index_sha256 = $digest' \
    "$terminal" >"$terminal.tmp"
  mv -- "$terminal.tmp" "$terminal"
  jq --arg digest "$digest" --slurpfile terminal "$terminal" \
    --slurpfile java "$bundle/terminal-java-diagnostics.json" '
      .obi_metric_boundary_index_sha256 = $digest |
      .obi_metric_evidence = $terminal[0] |
      .java_bridge_diagnostics = $java[0]
    ' "$status" >"$status.tmp"
  mv -- "$status.tmp" "$status"
}

upgrade_bundle_to_v3() {
  local -r bundle="$1"
  local -r evidence_id="$2"
  local ids=""
  local status_digest=""
  local pair_digest=""
  local java_digest=""
  local phase_identity_digest=""
  local unavailable_digest=""

  ids="$(all_v3_boundary_ids_json)" || return 1
  jq -cn --argjson ids "$ids" '{
    status: "passed",
    scenario: "all",
    obi_metric_boundary_ids: $ids
  }' >"$bundle/scenario-all-status.json"
  status_digest="$(sha256sum "$bundle/scenario-all-status.json")"
  status_digest="${status_digest%% *}"
  pair_digest="$(sha256sum "$bundle/obi-metric-pairs/terminal.json")"
  pair_digest="${pair_digest%% *}"
  java_digest="$(sha256sum "$bundle/phases/terminal-after/java-diagnostics.txt")"
  java_digest="${java_digest%% *}"
  phase_identity_digest="$(sha256sum \
    "$bundle/phases/terminal-before/obi-identity.json")"
  phase_identity_digest="${phase_identity_digest%% *}"
  mkdir -p -- "$bundle/phases/journal-unavailable"
  printf 'unavailable\n' >"$bundle/phases/journal-unavailable/obi-metrics.prom"
  unavailable_digest="$(sha256sum \
    "$bundle/phases/journal-unavailable/obi-metrics.prom")"
  unavailable_digest="${unavailable_digest%% *}"
  jq -cnS \
    --argjson ids "$ids" \
    --arg status_digest "$status_digest" \
    --arg pair_digest "$pair_digest" \
    --arg java_digest "$java_digest" \
    --arg phase_identity_digest "$phase_identity_digest" \
    --arg unavailable_digest "$unavailable_digest" '
      {
        schema: "obi-metric-boundary-index-v1",
        selection: {
          scenario: "all",
          requested_transport: "getsockopt",
          selected_transport: "getsockopt",
          repeat_count: 1
        },
        boundaries: ($ids | to_entries | map(
          .value as $id |
          {
            id: $id,
            ordinal: (.key + 1),
            state: "complete",
            captures: (
              if .key == 0 then [
                {
                  id: "terminal",
                  kind: "pair",
                  state: "captured",
                  pair_reference: "obi-metric-pairs/terminal.json",
                  pair_sha256: $pair_digest,
                  java_reference: "phases/terminal-after/java-diagnostics.txt",
                  java_sha256: $java_digest
                },
                {
                  id: "java-terminal-after",
                  kind: "java",
                  state: "captured",
                  reference: "phases/terminal-after/java-diagnostics.txt",
                  sha256: $java_digest
                },
                {
                  id: "terminal-before",
                  kind: "phase",
                  state: "captured",
                  identity_reference: "phases/terminal-before/obi-identity.json",
                  identity_sha256: $phase_identity_digest
                }
              ] else [{
                id: "journal-unavailable",
                kind: "unavailable",
                state: "captured",
                reason: "obi_process_not_running",
                reference: "phases/journal-unavailable/obi-metrics.prom",
                sha256: $unavailable_digest
              }] end
            ),
            status_references: [{
              reference: "scenario-all-status.json",
              sha256: $status_digest
            }],
            not_applicable_reason: null
          }
        ))
      }
    ' >"$bundle/obi-metric-boundary-index.json"
  jq -cn '{
    schema: "obi-java-remote-parent-terminal-metrics-v2",
    sealed: true,
    available: false,
    reason: "no-active-boundary",
    active_boundary_id: null,
    boundary_index_reference: "obi-metric-boundary-index.json",
    boundary_index_sha256: "pending"
  }' >"$bundle/terminal-obi-metrics.json"
  jq -cn --arg evidence_id "$evidence_id" \
    --slurpfile java "$bundle/terminal-java-diagnostics.json" \
    --slurpfile terminal "$bundle/terminal-obi-metrics.json" '{
      schema: "obi-apache-java-https-run-status-v3",
      status: "passed",
      exit_status: 0,
      acceptance_evidence: true,
      acceptance_evidence_reason: "none",
      failure_stage: "none",
      failure_line: 0,
      evidence_id: $evidence_id,
      java_bridge_diagnostics_reference: "terminal-java-diagnostics.json",
      java_bridge_diagnostics: $java[0],
      obi_metric_evidence_reference: "terminal-obi-metrics.json",
      obi_metric_evidence: $terminal[0],
      obi_metric_boundary_index_reference: "obi-metric-boundary-index.json",
      obi_metric_boundary_index_sha256: "pending"
    }' >"$bundle/run-status.json"
  sync_v3_index_envelopes "$bundle"
  write_bundle_checksums "$bundle"
}

refresh_v3_status_digest() {
  local -r bundle="$1"
  local -r reference="$2"
  local digest=""

  digest="$(sha256sum "$bundle/$reference")" || return 1
  digest="${digest%% *}"
  jq --arg reference "$reference" --arg digest "$digest" '
    (.boundaries[].status_references[] |
      select(.reference == $reference).sha256) = $digest
  ' "$bundle/obi-metric-boundary-index.json" \
    >"$bundle/obi-metric-boundary-index.json.tmp"
  mv -- "$bundle/obi-metric-boundary-index.json.tmp" \
    "$bundle/obi-metric-boundary-index.json"
  sync_v3_index_envelopes "$bundle"
}

test_v3_mutation_rejections() {
  local -r repository="$1"
  local -r verifier="$2"
  local -r bundle="$3"
  local -r baseline="$4"
  local digest=""

  replace_json_file "$bundle/obi-metric-boundary-index.json" \
    '.selection.selected_transport = null'
  sync_v3_index_envelopes "$bundle"
  write_bundle_checksums "$bundle"
  commit_fixture "$repository" 'Accept nullable selected transport in v3 index'
  "$verifier" "$bundle" >/dev/null
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore selected transport fixture'

  replace_json_file "$bundle/obi-metric-boundary-index.json" \
    '.selection.selected_transport = "unix"'
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject Unix initial selection for requested getsockopt transport'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after initial-selection mismatch'

  sed -i 's/^transport=getsockopt$/transport=disabled/' "$bundle/environment.txt"
  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    .selection.requested_transport = "disabled" |
    .selection.selected_transport = "getsockopt"
  '
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject non-null initial selection for disabled transport'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after disabled-selection mismatch'

  replace_json_file "$bundle/terminal-java-diagnostics.json" '{
    schema: "obi-java-bridge-terminal-diagnostics-v1",
    sealed: true,
    available: false,
    reason: "no-valid-snapshot-before-terminal-boundary"
  }'
  sync_run_status_java_embedding "$bundle"
  write_bundle_checksums "$bundle"
  commit_fixture "$repository" 'Accept independent unavailable Java terminal with no active boundary'
  "$verifier" "$bundle" >/dev/null
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore available Java terminal fixture'

  replace_json_file "$bundle/scenario-all-status.json" \
    '.obi_metric_boundary_ids |= map(select(. != "uninstrumented"))'
  refresh_v3_status_digest "$bundle" scenario-all-status.json
  jq -cn '{
    status: "not_applicable",
    scenario: "uninstrumented",
    reason: "planner skipped",
    obi_metric_boundary_ids: ["uninstrumented"]
  }' >"$bundle/scenario-uninstrumented-status.json"
  digest="$(sha256sum "$bundle/scenario-uninstrumented-status.json")"
  digest="${digest%% *}"
  jq --arg digest "$digest" '
    .boundaries[-1].state = "not_applicable" |
    .boundaries[-1].captures = [] |
    .boundaries[-1].not_applicable_reason = "planner skipped" |
    .boundaries[-1].status_references = [{
      reference: "scenario-uninstrumented-status.json",
      sha256: $digest
    }]
  ' "$bundle/obi-metric-boundary-index.json" \
    >"$bundle/obi-metric-boundary-index.json.tmp"
  mv -- "$bundle/obi-metric-boundary-index.json.tmp" \
    "$bundle/obi-metric-boundary-index.json"
  sync_v3_index_envelopes "$bundle"
  write_bundle_checksums "$bundle"
  commit_fixture "$repository" 'Accept exact not-applicable transition provenance'
  "$verifier" "$bundle" >/dev/null
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore complete-boundary fixture'

  printf 'obi-metric-boundary-index-frozen-v1:%064d\n' 0 \
    >"$bundle/.obi-metric-boundary-index.freeze"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject a stale boundary-index freeze digest'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after freeze mutation'

  jq . "$bundle/obi-metric-boundary-index.json" \
    >"$bundle/obi-metric-boundary-index.json.tmp"
  mv -- "$bundle/obi-metric-boundary-index.json.tmp" \
    "$bundle/obi-metric-boundary-index.json"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject a noncanonical boundary index'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after index-canonicality mutation'

  replace_json_file "$bundle/run-status.json" \
    '.obi_metric_boundary_index_sha256 = ("0" * 64)'
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject a stale run-status index digest'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after run-status digest mutation'

  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    (.boundaries[].captures[] | select(.kind == "java").id) = "java-wrong"
  '
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject a noncanonical Java capture ID'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after Java capture-ID mutation'

  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    (.boundaries[].captures[] | select(.kind == "pair").id) = "wrong-pair"
  '
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject a pair ID differing from its basename'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after pair capture-ID mutation'

  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    (.boundaries[].captures[] | select(.kind == "phase").id) = "wrong-phase"
  '
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject a phase ID differing from its reference'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after phase capture-ID mutation'

  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    (.boundaries[].captures[] | select(.kind == "unavailable").id) = "wrong-phase"
  '
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject an unavailable ID differing from its phase'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after unavailable capture-ID mutation'

  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    .boundaries[1].captures = [
      .boundaries[0].captures[] | select(.kind == "java")
    ]
  '
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" \
    'Reject a complete OBI-running boundary without a captured pair'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after pairless-complete mutation'

  replace_json_file "$bundle/terminal-obi-metrics.json" \
    '.reason = "active-boundary-incomplete"'
  sync_run_status_obi_embedding "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject stale terminal active-boundary state'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after terminal-state mutation'

  cp -- "$bundle/obi-metric-pairs/terminal.json" \
    "$bundle/obi-metric-pairs/orphan.json"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject an orphan boundary pair'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after orphan-pair mutation'

  printf 'unavailable-extra\n' \
    >"$bundle/phases/journal-unavailable/obi-metrics.prom"
  digest="$(sha256sum "$bundle/phases/journal-unavailable/obi-metrics.prom")"
  digest="${digest%% *}"
  jq --arg digest "$digest" '
    (.boundaries[].captures[] |
      select(.kind == "unavailable").sha256) = $digest
  ' "$bundle/obi-metric-boundary-index.json" \
    >"$bundle/obi-metric-boundary-index.json.tmp"
  mv -- "$bundle/obi-metric-boundary-index.json.tmp" \
    "$bundle/obi-metric-boundary-index.json"
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject non-exact unavailable evidence'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after unavailable mutation'

  replace_json_file "$bundle/scenario-all-status.json" \
    '.obi_metric_boundary_ids |= .[:-1]'
  refresh_v3_status_digest "$bundle" scenario-all-status.json
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject incomplete scenario-status ID coverage'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after status-ID mutation'

  jq -cn '{status: "passed", obi_metric_boundary_ids: ["basic"]}' \
    >"$bundle/scenario-post-freeze-status.json"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject an unreferenced scenario status'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after extra-status mutation'

  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    .boundaries[-1].state = "not_applicable" |
    .boundaries[-1].captures = [] |
    .boundaries[-1].not_applicable_reason = "planner skipped"
  '
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject invalid not-applicable provenance'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after not-applicable mutation'

  replace_json_file "$bundle/obi-metric-boundary-index.json" \
    '.boundaries[-1].state = "active"'
  sync_v3_index_envelopes "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject stale Java and metric active selection'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after active-selection mutation'

  replace_json_file "$bundle/terminal-obi-metrics.json" '{
    schema: "obi-java-remote-parent-terminal-metrics-v1",
    sealed: true,
    available: false,
    reason: "no-valid-pair-before-terminal-boundary"
  }'
  sync_run_status_obi_embedding "$bundle"
  expect_committed_bundle_rejection \
    "$repository" "$verifier" "$bundle" 'Reject terminal-metrics v1 under run-status v3'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after terminal-schema mutation'

  "$verifier" "$bundle" >/dev/null
}

v3_unique_referenced_bytes() {
  local -r bundle="$1"
  local -i total=0
  local reference=""
  local size=""
  local -a references=(
    obi-metric-pairs/terminal.json
    phases/terminal-after/java-diagnostics.txt
    phases/journal-unavailable/obi-metrics.prom
    scenario-all-status.json
    phases/terminal-before/obi-identity.json
    phases/terminal-after/obi-identity.json
    phases/terminal-before/obi-metrics.prom
    phases/terminal-after/obi-metrics.prom
  )

  for reference in "${references[@]}"; do
    size="$(stat -Lc '%s' -- "$bundle/$reference")" || return 1
    [[ "$size" =~ ^[0-9]+$ ]] || return 1
    total=$((total + size))
  done
  printf '%d\n' "$total"
}

write_preflight_command_wrappers() {
  local -r directory="$1"

  mkdir -p -- "$directory"
  # These are literal wrapper-script lines; expansion happens when each wrapper runs.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'if [[ -n "${SHA256_COUNT_LOG:-}" && $# == 1 &&' \
    '  "$1" == */evidence/"$COUNT_EVIDENCE_ID"/* ]]; then' \
    '  printf "%s\\n" "${1#*/evidence/"$COUNT_EVIDENCE_ID"/}" >>"$SHA256_COUNT_LOG"' \
    'fi' \
    '[[ -z "${SHA256_MARKER:-}" ]] || : >"$SHA256_MARKER"' \
    'exec "$REAL_SHA256SUM" "$@"' \
    >"$directory/sha256sum"
  # These are literal wrapper-script lines; expansion happens when the wrapper runs.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'last_argument="${!#}"' \
    'if [[ -n "${JQ_COUNT_LOG:-}" &&' \
    '  "$last_argument" == */evidence/"$COUNT_EVIDENCE_ID"/* ]]; then' \
    '  printf "%s\\n" "${last_argument#*/evidence/"$COUNT_EVIDENCE_ID"/}" >>"$JQ_COUNT_LOG"' \
    'fi' \
    'for argument in "$@"; do' \
    '  if [[ "${MOCK_JQ_PARTIAL:-false}" == true &&' \
    '    "$argument" == *"invalid pair identity references"* ]]; then' \
    '    : >"$JQ_FAILURE_MARKER"' \
    '    printf "%s\\n" phases/terminal-before/obi-identity.json' \
    '    exit 1' \
    '  fi' \
    'done' \
    'exec "$REAL_JQ" "$@"' \
    >"$directory/jq"
  # These are literal wrapper-script lines; expansion happens when the wrapper runs.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'last_argument="${!#}"' \
    'if [[ "${MOCK_STAT_OVERFLOW:-false}" == true &&' \
    '  "$last_argument" == */scenario-all-status.json ]]; then' \
    '  printf "%s\\n" 18446744073709551615' \
    '  exit 0' \
    'fi' \
    'exec "$REAL_STAT" "$@"' \
    >"$directory/stat"
  # These are literal wrapper-script lines; expansion happens when the wrapper runs.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'long_tree=false' \
    'for argument in "$@"; do' \
    '  [[ "$argument" == archive ]] && : >"$ARCHIVE_MARKER"' \
    '  [[ "$argument" == --long ]] && long_tree=true' \
    'done' \
    'if [[ "$long_tree" == true && "${MOCK_TREE:-none}" == exact-cap ]]; then' \
    '  printf "100644 blob %040d %s\\t%s/SHA256SUMS\\0" 0 603979776 "$MOCK_BUNDLE_RELATIVE"' \
    '  exit 0' \
    'fi' \
    'if [[ "$long_tree" == true && "${MOCK_TREE:-none}" == cap-plus-one ]]; then' \
    '  printf "100644 blob %040d %s\\t%s/SHA256SUMS\\0" 0 603979777 "$MOCK_BUNDLE_RELATIVE"' \
    '  exit 0' \
    'fi' \
    'if [[ "$long_tree" == true && "${MOCK_TREE:-none}" == malformed-size ]]; then' \
    '  printf "100644 blob %040d 01\\t%s/SHA256SUMS\\0" 0 "$MOCK_BUNDLE_RELATIVE"' \
    '  exit 0' \
    'fi' \
    'if [[ "$long_tree" == true && "${MOCK_TREE:-none}" == invalid-type ]]; then' \
    '  printf "120000 blob %040d 1\\t%s/SHA256SUMS\\0" 0 "$MOCK_BUNDLE_RELATIVE"' \
    '  exit 0' \
    'fi' \
    'if [[ "$long_tree" == true && "${MOCK_TREE:-none}" == ls-tree-failure ]]; then' \
    '  exit 71' \
    'fi' \
    'if [[ "$long_tree" == true && "${MOCK_TREE:-none}" == blob-count-plus-one ]]; then' \
    '  for ((index = 1; index <= 32769; index++)); do' \
    '    printf "100644 blob %040d 0\\t%s/file-%05d\\0" 0 "$MOCK_BUNDLE_RELATIVE" "$index"' \
    '  done' \
    '  exit 0' \
    'fi' \
    'if [[ "$long_tree" == true && "${MOCK_TREE:-none}" == single-path ]]; then' \
    '  printf "100644 blob %040d 1\\t%s/%s\\0" 0 "$MOCK_BUNDLE_RELATIVE" "$MOCK_TREE_PATH"' \
    '  exit 0' \
    'fi' \
    'exec "$REAL_GIT" "$@"' \
    >"$directory/git"
  # These are literal wrapper-script lines; expansion happens when the wrapper runs.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    ': >"$ARCHIVE_MARKER"' \
    'if [[ -n "${INJECT_EXTRACTED_PATH:-}" ]]; then' \
    '  "$REAL_TAR" "$@"' \
    '  injected="$MOCK_BUNDLE_RELATIVE/$INJECT_EXTRACTED_PATH"' \
    '  mkdir -p -- "${injected%/*}"' \
    '  : >"$injected"' \
    '  exit 0' \
    'fi' \
    'exec "$REAL_TAR" "$@"' \
    >"$directory/tar"
  chmod 0755 -- \
    "$directory/sha256sum" "$directory/jq" "$directory/stat" \
    "$directory/git" "$directory/tar"
}

test_v3_preflight_guards() {
  local -r repository="$1"
  local -r verifier="$2"
  local -r bundle="$3"
  local -r baseline="$4"
  local cap_verifier="$repository/cap-verifier.sh"
  local wrappers="$TEST_TMP_DIR/preflight-wrappers"
  local marker="$TEST_TMP_DIR/sha256-called"
  local jq_marker="$TEST_TMP_DIR/jq-partial-failure-called"
  local archive_marker="$TEST_TMP_DIR/archive-called"
  local sha_count_log="$TEST_TMP_DIR/shared-reference-sha-counts"
  local jq_count_log="$TEST_TMP_DIR/shared-reference-jq-counts"
  local bundle_relative="${bundle#"$repository"/}"
  local real_git=""
  local real_jq=""
  local real_sha256sum=""
  local real_stat=""
  local real_tar=""
  local cap=""
  local count=""
  local digest=""
  local reference=""
  local tree_fault=""
  local -a once_hashed_references=(
    scenario-all-status.json
    phases/journal-unavailable/obi-metrics.prom
    phases/terminal-after/java-diagnostics.txt
    phases/terminal-before/obi-identity.json
    phases/terminal-before/obi-metrics.prom
    phases/terminal-after/obi-metrics.prom
  )

  real_git="$(command -v git)" || return 1
  real_jq="$(command -v jq)" || return 1
  real_sha256sum="$(command -v sha256sum)" || return 1
  real_stat="$(command -v stat)" || return 1
  real_tar="$(command -v tar)" || return 1
  write_preflight_command_wrappers "$wrappers"

  rm -f -- "$archive_marker"
  if ! PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
    REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
    ARCHIVE_MARKER="$archive_marker" SHA256_MARKER="$marker" \
    MOCK_TREE=exact-cap MOCK_BUNDLE_RELATIVE="$bundle_relative" \
    "$verifier" "$bundle" >/dev/null 2>&1; then
    die "verifier rejected a tracked bundle at the exact archive cap"
  fi
  [[ -e "$archive_marker" ]] || {
    die "verifier did not proceed to extraction at the exact archive cap"
  }

  rm -f -- "$archive_marker"
  if PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
    REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
    ARCHIVE_MARKER="$archive_marker" SHA256_MARKER="$marker" \
    MOCK_TREE=cap-plus-one MOCK_BUNDLE_RELATIVE="$bundle_relative" \
    "$verifier" "$bundle" >/dev/null 2>&1; then
    die "verifier accepted a tracked bundle at archive cap plus one"
  fi
  [[ ! -e "$archive_marker" ]] || {
    die "verifier invoked archive extraction for a bundle at cap plus one"
  }

  rm -f -- "$archive_marker"
  if PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
    REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
    ARCHIVE_MARKER="$archive_marker" SHA256_MARKER="$marker" \
    MOCK_TREE=blob-count-plus-one MOCK_BUNDLE_RELATIVE="$bundle_relative" \
    "$verifier" "$bundle" >/dev/null 2>&1; then
    die "verifier accepted 32769 tracked bundle blobs"
  fi
  [[ ! -e "$archive_marker" ]] || {
    die "verifier invoked archive extraction for 32769 blobs"
  }

  for tree_fault in malformed-size invalid-type ls-tree-failure; do
    rm -f -- "$archive_marker"
    if PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
      REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
      ARCHIVE_MARKER="$archive_marker" SHA256_MARKER="$marker" \
      MOCK_TREE="$tree_fault" MOCK_BUNDLE_RELATIVE="$bundle_relative" \
      "$verifier" "$bundle" >/dev/null 2>&1; then
      die "verifier accepted tracked-tree fault $tree_fault"
    fi
    [[ ! -e "$archive_marker" ]] || {
      die "verifier invoked archive extraction after tracked-tree fault $tree_fault"
    }
  done

  jq '.boundary = "shared-pair"' "$bundle/obi-metric-pairs/terminal.json" \
    >"$bundle/obi-metric-pairs/shared-pair.json"
  digest="$(sha256sum "$bundle/obi-metric-pairs/shared-pair.json")"
  digest="${digest%% *}"
  jq --arg digest "$digest" '
    .boundaries[1].captures += [{
      id: "shared-pair",
      kind: "pair",
      state: "captured",
      pair_reference: "obi-metric-pairs/shared-pair.json",
      pair_sha256: $digest,
      java_reference: .boundaries[0].captures[0].java_reference,
      java_sha256: .boundaries[0].captures[0].java_sha256
    }]
  ' "$bundle/obi-metric-boundary-index.json" \
    >"$bundle/obi-metric-boundary-index.json.tmp"
  mv -- "$bundle/obi-metric-boundary-index.json.tmp" \
    "$bundle/obi-metric-boundary-index.json"
  sync_v3_index_envelopes "$bundle"
  write_bundle_checksums "$bundle"
  commit_fixture "$repository" 'Exercise shared transitive reference memoization'
  rm -f -- "$sha_count_log" "$jq_count_log" "$marker"
  PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
    REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
    ARCHIVE_MARKER="$archive_marker" SHA256_MARKER="$marker" \
    SHA256_COUNT_LOG="$sha_count_log" JQ_COUNT_LOG="$jq_count_log" \
    COUNT_EVIDENCE_ID="${bundle##*/}" \
    "$verifier" "$bundle" >/dev/null
  for reference in "${once_hashed_references[@]}"; do
    count="$(awk -v reference="$reference" '
      $0 == reference { count += 1 }
      END { print count + 0 }
    ' "$sha_count_log")"
    [[ "$count" == 1 ]] || {
      die "shared reference $reference was hashed $count times"
    }
  done
  count="$(awk '
    $0 == "scenario-all-status.json" { count += 1 }
    END { print count + 0 }
  ' "$jq_count_log")"
  [[ "$count" == 3 ]] || {
    die "shared scenario status was parsed $count times instead of three bounded passes"
  }
  count="$(awk '
    $0 == "phases/terminal-before/obi-identity.json" { count += 1 }
    END { print count + 0 }
  ' "$jq_count_log")"
  ((count > 0 && count <= 14)) || {
    die "shared transitive identity required $count jq passes"
  }
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after memoization fixture'

  rm -f -- "$marker" "$jq_marker"
  if PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
    REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
    ARCHIVE_MARKER="$archive_marker" \
    MOCK_JQ_PARTIAL=true SHA256_MARKER="$marker" \
    JQ_FAILURE_MARKER="$jq_marker" \
    "$verifier" "$bundle" >/dev/null 2>&1; then
    die "verifier accepted a partial jq pair-identity manifest"
  fi
  [[ -e "$jq_marker" ]] || die "partial jq fault injection did not trigger"
  [[ ! -e "$marker" ]] || {
    die "verifier hashed referenced evidence after preflight jq failure"
  }

  rm -f -- "$marker"
  if PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
    REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
    ARCHIVE_MARKER="$archive_marker" \
    MOCK_STAT_OVERFLOW=true SHA256_MARKER="$marker" \
    "$verifier" "$bundle" >/dev/null 2>&1; then
    die "verifier accepted an overflowing referenced-file size"
  fi
  [[ ! -e "$marker" ]] || {
    die "verifier hashed evidence before rejecting an overflowing size"
  }

  cap="$(v3_unique_referenced_bytes "$bundle")" || return 1
  sed \
    "s/^readonly OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES=.*/readonly OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES=$cap/" \
    "$verifier" >"$cap_verifier"
  chmod 0755 -- "$cap_verifier"
  "$cap_verifier" "$bundle" >/dev/null || {
    die "verifier rejected deduplicated references at the exact byte cap"
  }
  rm -f -- "$cap_verifier"

  printf x >"$bundle/cap-overflow.bin"
  digest="$(sha256sum "$bundle/cap-overflow.bin")"
  digest="${digest%% *}"
  jq --arg digest "$digest" '
    .boundaries[0].captures += [{
      id: "cap-overflow",
      kind: "artifact",
      state: "captured",
      reference: "cap-overflow.bin",
      sha256: $digest
    }]
  ' "$bundle/obi-metric-boundary-index.json" \
    >"$bundle/obi-metric-boundary-index.json.tmp"
  mv -- "$bundle/obi-metric-boundary-index.json.tmp" \
    "$bundle/obi-metric-boundary-index.json"
  sync_v3_index_envelopes "$bundle"
  write_bundle_checksums "$bundle"
  commit_fixture "$repository" 'Reject cumulative journal references at cap plus one'
  sed \
    "s/^readonly OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES=.*/readonly OBI_METRIC_BOUNDARY_REFERENCED_MAX_BYTES=$cap/" \
    "$verifier" >"$cap_verifier"
  chmod 0755 -- "$cap_verifier"
  rm -f -- "$marker"
  if PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
    REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
    ARCHIVE_MARKER="$archive_marker" \
    SHA256_MARKER="$marker" \
    "$cap_verifier" "$bundle" >/dev/null 2>&1; then
    die "verifier accepted journal references at cap plus one"
  fi
  [[ ! -e "$marker" ]] || {
    die "verifier hashed referenced evidence before rejecting cap plus one"
  }
  rm -f -- "$cap_verifier"
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore after byte-cap mutation'
  "$verifier" "$bundle" >/dev/null
}

test_v3_runtime_private_path_guards() {
  local -r repository="$1"
  local -r verifier="$2"
  local -r bundle="$3"
  local wrappers="$TEST_TMP_DIR/private-path-wrappers"
  local archive_marker="$TEST_TMP_DIR/private-path-archive-called"
  local bundle_relative="${bundle#"$repository"/}"
  local real_git=""
  local real_jq=""
  local real_sha256sum=""
  local real_stat=""
  local real_tar=""
  local private_path=""
  local allowed_path=""
  local rejection_output=""
  local -a private_paths=(
    .lock
    .unrelated.lock
    .hidden-directory/entry
    .terminal-java-diagnostics.freeze
    .terminal-java-diagnostics.lock
    .terminal-java-diagnostics-recovery-boundary.json
    .terminal-java-diagnostics-recovery-boundary.A1b2C3
    .terminal-java-diagnostics-recovery-commit.A1b2C3
    .terminal-java-diagnostics-freeze.A1b2C3
    .terminal-java-diagnostics.A1b2C3
    .terminal-java-diagnostics.stranded-private-state
    .terminal-obi-metrics.A1b2C3
    .last-valid-java-diagnostics.json
    .last-valid-java-diagnostics.A1b2C3
    .last-valid-java-diagnostics-stranded
    .last-valid-terminal-boundary.json
    .run-status.A1b2C3
    .obi-metric-boundary-index.A1b2C3
    .obi-metric-boundary-index-backup.A1b2C3
    .obi-metric-boundary-index-restore.A1b2C3
    .obi-metric-boundary-index-freeze.A1b2C3
    .obi-metric-boundary-plan.A1b2C3
    obi-metric-pairs/.pair.A1b2C3
    phases/terminal-after/.java-diagnostics-header.A1b2C3
    phases/terminal-after/.terminal-diagnostics.A1b2C3
    phases/terminal-after/.obi-identity.A1b2C3
    phases/terminal-after/.obi-metrics.A1b2C3
    phases/terminal-after/.obi-metrics-parsed.A1b2C3
    phases/terminal-after/.obi-metrics-unavailable.A1b2C3
    phases/terminal-after/.unrelated.lock
    phases/terminal-after/.hidden-directory/entry
  )
  local -a allowed_paths=(
    .obi-metric-boundary-index.freeze
  )

  real_git="$(command -v git)" || return 1
  real_jq="$(command -v jq)" || return 1
  real_sha256sum="$(command -v sha256sum)" || return 1
  real_stat="$(command -v stat)" || return 1
  real_tar="$(command -v tar)" || return 1
  write_preflight_command_wrappers "$wrappers"

  # Mutate the immutable tree manifest one reserved path at a time. Every
  # rejection must precede both `git archive` and tar extraction.
  for private_path in "${private_paths[@]}"; do
    rm -f -- "$archive_marker"
    if PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
      REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
      ARCHIVE_MARKER="$archive_marker" MOCK_TREE=single-path \
      MOCK_TREE_PATH="$private_path" MOCK_BUNDLE_RELATIVE="$bundle_relative" \
      "$verifier" "$bundle" >/dev/null 2>&1; then
      die "verifier accepted immutable runtime-private path $private_path"
    fi
    [[ ! -e "$archive_marker" ]] || {
      die "verifier extracted immutable runtime-private path $private_path"
    }
  done

  # The canonical boundary-index freeze is the sole retained hidden path.
  for allowed_path in "${allowed_paths[@]}"; do
    rm -f -- "$archive_marker"
    PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
      REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
      ARCHIVE_MARKER="$archive_marker" MOCK_TREE=single-path \
      MOCK_TREE_PATH="$allowed_path" MOCK_BUNDLE_RELATIVE="$bundle_relative" \
      "$verifier" "$bundle" >/dev/null || {
      die "verifier rejected allowed immutable path $allowed_path"
    }
    [[ -e "$archive_marker" ]] || {
      die "verifier did not extract after allowed immutable path $allowed_path"
    }
  done

  # Inject the same paths only after a clean immutable-tree preflight. The
  # extracted-tree scan must identify the reserved path itself, rather than
  # relying on the later checksum exact-closure failure.
  for private_path in "${private_paths[@]}"; do
    rm -f -- "$archive_marker"
    if rejection_output="$(
      PATH="$wrappers:$PATH" REAL_GIT="$real_git" REAL_JQ="$real_jq" \
        REAL_SHA256SUM="$real_sha256sum" REAL_STAT="$real_stat" REAL_TAR="$real_tar" \
        ARCHIVE_MARKER="$archive_marker" MOCK_BUNDLE_RELATIVE="$bundle_relative" \
        INJECT_EXTRACTED_PATH="$private_path" \
        "$verifier" "$bundle" 2>&1
    )"; then
      die "verifier accepted extracted runtime-private path $private_path"
    fi
    [[ -e "$archive_marker" ]] || {
      die "extracted runtime-private path mutation did not reach tar: $private_path"
    }
    [[ "$rejection_output" == *"runtime-private publication path:"* ]] || {
      die "verifier did not diagnose extracted runtime-private path $private_path"
    }
  done
  "$verifier" "$bundle" >/dev/null
}

main() {
  local -r evidence_id='synthetic-current-code'
  local repository=""
  local fixture_verifier=""
  local bundle=""
  local baseline=""
  local v3_baseline=""
  local source_revision=""
  local rejection_output=""

  check_dependencies
  [[ -x "$VERIFIER" ]] || die "verifier is not executable: $VERIFIER"
  TEST_TMP_DIR="$(mktemp -d)"
  repository="$TEST_TMP_DIR/repository"
  fixture_verifier="$repository/examples/apache-java-https/scripts/verify-retained-evidence.sh"
  bundle="$repository/examples/apache-java-https/evidence/$evidence_id"
  baseline="$TEST_TMP_DIR/valid-v2-bundle"
  v3_baseline="$TEST_TMP_DIR/valid-v3-bundle"

  git init --quiet "$repository"
  git -C "$repository" config user.email 'retained-evidence-test@example.invalid'
  git -C "$repository" config user.name 'Retained Evidence Test'
  git -C "$repository" config commit.gpgSign false
  mkdir -p -- "${fixture_verifier%/*}"
  cp -- "$VERIFIER" "$fixture_verifier"
  chmod 0755 -- "$fixture_verifier"
  printf 'tested source\n' >"$repository/source.txt"
  commit_fixture "$repository" 'Create tested source revision'
  source_revision="$(git -C "$repository" rev-parse HEAD)"

  create_bundle "$repository" "$evidence_id" "$source_revision"
  commit_fixture "$repository" 'Publish retained evidence'
  "$fixture_verifier" "$bundle" >/dev/null
  "$fixture_verifier" --current-code "$bundle" >/dev/null
  cp -a -- "$bundle" "$baseline"
  test_v2_mutation_rejections \
    "$repository" "$fixture_verifier" "$bundle" "$baseline"

  printf '{}\n' >"$bundle/obi-metric-boundary-index.json"
  printf 'obi-metric-boundary-index-frozen-v1:%064d\n' 0 \
    >"$bundle/.obi-metric-boundary-index.freeze"
  expect_committed_bundle_rejection \
    "$repository" "$fixture_verifier" "$bundle" \
    'Reject run-status v2 with boundary journal paths'
  restore_valid_bundle \
    "$repository" "$bundle" "$baseline" 'Restore journal-free run-status v2'

  upgrade_bundle_to_v3 "$bundle" "$evidence_id"
  commit_fixture "$repository" 'Publish synthetic boundary-journal evidence'
  "$fixture_verifier" "$bundle" >/dev/null
  "$fixture_verifier" --current-code "$bundle" >/dev/null
  cp -a -- "$bundle" "$v3_baseline"
  test_v3_mutation_rejections \
    "$repository" "$fixture_verifier" "$bundle" "$v3_baseline"
  test_v3_preflight_guards \
    "$repository" "$fixture_verifier" "$bundle" "$v3_baseline"
  test_v3_runtime_private_path_guards \
    "$repository" "$fixture_verifier" "$bundle"

  mkdir -p -- "$repository/devdocs"
  printf 'Documentation-only follow-up.\n' >"$repository/devdocs/freshness.md"
  printf 'Published evidence summary.\n' \
    >"$repository/examples/apache-java-https/FINAL-RESULT.md"
  commit_fixture "$repository" 'Document retained evidence'
  "$fixture_verifier" --current-code "$bundle" >/dev/null

  printf 'changed source\n' >"$repository/source.txt"
  commit_fixture "$repository" 'Change tested source'
  "$fixture_verifier" "$bundle" >/dev/null
  if rejection_output="$("$fixture_verifier" --current-code "$bundle" 2>&1)"; then
    die "current-code policy accepted a post-test source change"
  fi
  [[ "$rejection_output" == *'post-test source change: source.txt'* ]] || {
    die "current-code policy did not identify the rejected source change"
  }

  printf 'verify-retained-evidence v2/v3 and current-code tests passed\n'
}

main "$@"
