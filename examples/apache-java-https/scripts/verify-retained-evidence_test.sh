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
    chmod -R u+rwX -- "$TEST_TMP_DIR" >/dev/null 2>&1 || true
    rm -rf -- "$TEST_TMP_DIR"
  fi
}

trap cleanup EXIT

check_dependencies() {
  local -a missing=()
  local command_name=""

  for command_name in awk chmod cp find git grep jq mkdir mktemp mountpoint mv \
    readlink rm sed sha256sum sort stat truncate; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  (( ${#missing[@]} == 0 )) || die "missing required commands: ${missing[*]}"
}

assert_no_invalid_jq_generator_binders() {
  local matches=""

  matches="$(grep -En \
    '(all|any)\([^;]* as \$[A-Za-z_][A-Za-z0-9_]*;' "$VERIFIER" || true)"
  [[ -z "$matches" ]] ||
    die "jq generator binders must bind in the condition with '|': $matches"
}

assert_jq_generator_context_semantics() {
  jq -n -e '
    def exact_owners($root; $scenarios):
      all($scenarios[]; . as $scenario |
        ([$root.boundaries[] | select(.id == $scenario)] | length) == 1);
    def reused_fd($root):
      any($root.cases[].fd_alias; . as $fd |
        ([$root.cases[] | select(.fd_alias == $fd) | .connection_alias] |
          unique | length) >= 2);
    {boundaries:[{id:"one"},{id:"two"}]} as $index |
    {cases:[
      {fd_alias:"fd-1",connection_alias:"connection-1"},
      {fd_alias:"fd-1",connection_alias:"connection-2"}
    ]} as $reused |
    {cases:[
      {fd_alias:"fd-1",connection_alias:"connection-1"},
      {fd_alias:"fd-2",connection_alias:"connection-2"}
    ]} as $distinct |
    exact_owners($index; ["one","two"]) and
    (exact_owners($index; ["one","missing"]) | not) and
    reused_fd($reused) and (reused_fd($distinct) | not)
  ' >/dev/null || die "jq generator context positive/negative gate failed"
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
  shift 2

  jq "$@" "$filter" "$file" >"$candidate"
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
  jq -cS --arg digest "$digest" '.boundary_index_sha256 = $digest' \
    "$terminal" >"$terminal.tmp"
  mv -- "$terminal.tmp" "$terminal"
  jq -cS --arg digest "$digest" --slurpfile terminal "$terminal" \
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

scenario_request_count_fixture() {
  case "$1" in
    basic|timeout-retry) printf '1\n' ;;
    keepalive|pipelining) printf '10\n' ;;
    concurrency) printf '16\n' ;;
    connection-churn|fd-port-reuse) printf '32\n' ;;
    slow-body) printf '8\n' ;;
    tls-boundary) printf '3\n' ;;
    coalesced-bridge) printf '2\n' ;;
    pressure) printf '128\n' ;;
    handoff) printf '4\n' ;;
    *) return 1 ;;
  esac
}

write_external_v3_authority_fixture() {
  local -r repository="$1"
  local -r revision="$2"
  local -r bundle="$3"
  local -r kind="$4"
  local expected_scenario='all'
  local expected_acceptance='true'
  local expected_reason='none'
  local expected_invocation='./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3'
  local source_tree_sha256=""

  if [[ "$kind" == assertion-failure ]]; then
    expected_scenario='assertion-failure'
    expected_acceptance='false'
    expected_reason='deliberate-assertion-failure,targeted-scenario'
    expected_invocation='./examples/apache-java-https/run.sh --transport getsockopt --scenario assertion-failure'
  fi
  mkdir -p -- "$bundle"
  write_source_tree_manifest "$repository" "$revision" \
    "$bundle/source-tree.manifest"
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
    'patch_identity_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    >"$bundle/source-state.txt"
  printf '%s\n' \
    "invocation=$expected_invocation" \
    "revision=$revision" \
    'dirty=false' \
    "source_tree_sha256=$source_tree_sha256" \
    'source_tree_manifest_schema=git-tree-v2' \
    'tracked_patch_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    'patch_identity_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    'transport=getsockopt' \
    'agent_distribution=otel' \
    'tls_protocol=TLSv1.3' \
    'obi_log_level=info' \
    "scenario=$expected_scenario" \
    'request_count=0' \
    'repeat_count=1' \
    'scenario_seed=1' \
    'bridge_build_mode=fresh' \
    "acceptance_evidence=$expected_acceptance" \
    "acceptance_evidence_reason=$expected_reason" \
    'compose_project=obi-java-https-test' \
    'command_timeout_seconds=180' \
    'readiness_timeout_seconds=120' \
    'architecture=x86_64' \
    'kernel=Linux-6.1.0-x86_64' \
    'openssl=OpenSSL-3.0.0' \
    'docker=28.0.0' \
    'compose=2.39.0' \
    >"$bundle/environment.txt"
  jq -cn --arg revision "$revision" --arg tree "$source_tree_sha256" '{
    source_revision: $revision,
    source_tree_sha256: $tree,
    obi_java_agent_sha256: ("1" * 64),
    obi_otel_extension_sha256: ("2" * 64)
  }' >"$bundle/bridge-artifacts.json"
  if [[ "$kind" == projected ]]; then
    jq -cn '{
      distribution: "otel",
      sha256: ("3" * 64),
      version: "2.28.1"
    }' >"$bundle/official-javaagent.json"
  else
    jq -cn '{
      distribution: "otel",
      sha256: "faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",
      url: "https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",
      version: "2.28.1"
    }' >"$bundle/official-javaagent.json"
  fi
}

write_external_v3_journal_fixture() {
  local -r bundle="$1"
  local -r profile="${2:-raw}"
  local before_phase='basic-before'
  local after_phase='basic-after'
  local unavailable_phase='journal-unavailable'
  local phase_only=''
  local capture_phase_only=''
  local pair_name='basic'
  local -r container_id='0000000000000000000000000000000000000000000000000000000000000001'
  local -r started_at='2000-01-01T00:00:00.000000001Z'
  local pair=""
  local -i pair_ordinal=0

  if [[ "$profile" == projected ]]; then
    before_phase='phase-0001'
    after_phase='phase-0002'
    phase_only='phase-0003'
    unavailable_phase='phase-0004'
    pair_name='pair-0001'
  elif [[ "$profile" != raw ]]; then
    return 1
  fi
  pair="$bundle/obi-metric-pairs/$pair_name.json"

  mkdir -p -- \
    "$bundle/phases/$before_phase" "$bundle/phases/$after_phase" \
    "$bundle/phases/$unavailable_phase" "$bundle/obi-metric-pairs"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 0' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
    >"$bundle/phases/$before_phase/obi-metrics.prom"
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 1' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
    >"$bundle/phases/$after_phase/obi-metrics.prom"
  write_running_identity_fixture \
    "$bundle" "$before_phase" "$container_id" "$started_at"
  write_running_identity_fixture \
    "$bundle" "$after_phase" "$container_id" "$started_at"
  write_java_diagnostics_fixture "$bundle" "$after_phase"
  if [[ "$profile" == projected ]]; then
    replace_json_file "$bundle/phases/$before_phase/obi-identity.json" \
      '.host_pid = "1"'
    replace_json_file "$bundle/phases/$after_phase/obi-identity.json" \
      '.host_pid = "1"'
    mkdir -p -- "$bundle/phases/$phase_only"
    printf '%s\n' \
      'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 2' \
      'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
      >"$bundle/phases/$phase_only/obi-metrics.prom"
    write_running_identity_fixture \
      "$bundle" "$phase_only" \
      '0000000000000000000000000000000000000000000000000000000000000002' \
      '2000-01-01T00:00:00.000000002Z'
    replace_json_file "$bundle/phases/$phase_only/obi-identity.json" \
      '.host_pid = "2"'
  fi
  if [[ "$profile" == raw ]]; then
    : >"$bundle/.terminal-java-diagnostics.lock"
    : >"$bundle/.terminal-java-diagnostics-transition.lock"
    printf 'terminal-java-diagnostics-frozen-v1\n' \
      >"$bundle/.terminal-java-diagnostics.freeze"
    jq -cS '.sealed = false' "$bundle/terminal-java-diagnostics.json" \
      >"$bundle/.last-valid-java-diagnostics.json"
    chmod 0600 -- \
      "$bundle/.terminal-java-diagnostics.lock" \
      "$bundle/.terminal-java-diagnostics-transition.lock" \
      "$bundle/.terminal-java-diagnostics.freeze"
    chmod 0644 -- "$bundle/.last-valid-java-diagnostics.json"
  fi
  jq -cn \
    --arg before_reference "phases/$before_phase/obi-identity.json" \
    --arg after_reference "phases/$after_phase/obi-identity.json" \
    --arg boundary "$pair_name" '{
      schema: "obi-java-remote-parent-metric-pair-v1",
      boundary: $boundary,
      continuity: "same_process",
      before: {state: "running", identity_reference: $before_reference},
      after: {state: "running", identity_reference: $after_reference},
      series: [{
        transport: "getsockopt",
        operation: "take",
        status: "valid",
        before: "0",
        after: "1",
        delta: "1"
      }],
      java_attach_errors: {before: "0", after: "0", delta: "0"}
    }' >"$pair"
  if [[ "$profile" == projected ]]; then
    for ((pair_ordinal = 2; pair_ordinal <= 11; pair_ordinal++)); do
      printf -v pair_name 'pair-%04d' "$pair_ordinal"
      printf -v before_phase 'phase-%04d' "$((pair_ordinal * 2 + 1))"
      printf -v after_phase 'phase-%04d' "$((pair_ordinal * 2 + 2))"
      mkdir -p -- "$bundle/phases/$before_phase" "$bundle/phases/$after_phase"
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 0' \
        'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
        >"$bundle/phases/$before_phase/obi-metrics.prom"
      printf '%s\n' \
        'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 1' \
        'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
        >"$bundle/phases/$after_phase/obi-metrics.prom"
      write_running_identity_fixture \
        "$bundle" "$before_phase" "$container_id" "$started_at"
      write_running_identity_fixture \
        "$bundle" "$after_phase" "$container_id" "$started_at"
      replace_json_file "$bundle/phases/$before_phase/obi-identity.json" \
        '.host_pid = "1"'
      replace_json_file "$bundle/phases/$after_phase/obi-identity.json" \
        '.host_pid = "1"'
      write_java_diagnostics_fixture "$bundle" "$after_phase"
      jq -cn \
        --arg before_reference "phases/$before_phase/obi-identity.json" \
        --arg after_reference "phases/$after_phase/obi-identity.json" \
        --arg boundary "$pair_name" '{
          schema: "obi-java-remote-parent-metric-pair-v1",
          boundary: $boundary,
          continuity: "same_process",
          before: {state: "running", identity_reference: $before_reference},
          after: {state: "running", identity_reference: $after_reference},
          series: [{transport: "getsockopt", operation: "take", status: "valid",
            before: "0", after: "1", delta: "1"}],
          java_attach_errors: {before: "0", after: "0", delta: "0"}
        }' >"$bundle/obi-metric-pairs/$pair_name.json"
    done
  fi
  printf 'unavailable\n' \
    >"$bundle/phases/$unavailable_phase/obi-metrics.prom"
}

write_external_v3_index_fixture() {
  local -r bundle="$1"
  local -r scenario="$2"
  local -r ids_json="$3"
  local -r profile="${4:-raw}"
  local rows=""
  local status_reference=""
  local status_digest=""
  local pair_digest=""
  local java_digest=""
  local unavailable_digest=""
  local phase_identity_digest=""
  local id=""
  local pair_name='basic'
  local java_phase='basic-after'
  local unavailable_phase='journal-unavailable'
  local phase_only=''
  local capture_pair=false
  local -i ordinal=0
  local -i stress_pair_ordinal=0

  if [[ "$profile" == projected ]]; then
    pair_name='pair-0001'
    java_phase='phase-0002'
    phase_only='phase-0003'
    unavailable_phase='phase-0004'
  elif [[ "$profile" != raw ]]; then
    return 1
  fi

  rows="$(mktemp "$TEST_TMP_DIR/v3-index-rows.XXXXXX")" || return 1
  pair_digest="$(sha256sum "$bundle/obi-metric-pairs/$pair_name.json")"
  pair_digest="${pair_digest%% *}"
  java_digest="$(sha256sum \
    "$bundle/phases/$java_phase/java-diagnostics.txt")"
  java_digest="${java_digest%% *}"
  unavailable_digest="$(sha256sum \
    "$bundle/phases/$unavailable_phase/obi-metrics.prom")"
  unavailable_digest="${unavailable_digest%% *}"
  if [[ -n "$phase_only" ]]; then
    phase_identity_digest="$(sha256sum \
      "$bundle/phases/$phase_only/obi-identity.json")"
    phase_identity_digest="${phase_identity_digest%% *}"
  fi
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    ordinal=$((ordinal + 1))
    capture_pair=false
    capture_phase_only=''
    if [[ "$profile" == projected ]]; then
      case "$id" in
        basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
        slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure)
          capture_pair=true
          stress_pair_ordinal=$((stress_pair_ordinal + 1))
          printf -v pair_name 'pair-%04d' "$stress_pair_ordinal"
          if ((stress_pair_ordinal == 1)); then
            java_phase='phase-0002'
            capture_phase_only="$phase_only"
          else
            printf -v java_phase 'phase-%04d' \
              "$((stress_pair_ordinal * 2 + 2))"
          fi
          pair_digest="$(sha256sum \
            "$bundle/obi-metric-pairs/$pair_name.json")"
          pair_digest="${pair_digest%% *}"
          java_digest="$(sha256sum \
            "$bundle/phases/$java_phase/java-diagnostics.txt")"
          java_digest="${java_digest%% *}"
          ;;
      esac
    elif ((ordinal == 1)); then
      capture_pair=true
    fi
    if [[ "$profile" == projected ]]; then
      printf -v status_reference \
        'scenario-journal-status-%04d-status.json' "$ordinal"
    else
      status_reference="scenario-$id-status.json"
    fi
    status_digest="$(sha256sum "$bundle/$status_reference")"
    status_digest="${status_digest%% *}"
    if [[ "$capture_pair" == true ]]; then
      jq -cn \
        --arg id "$id" \
        --argjson ordinal "$ordinal" \
        --arg status_reference "$status_reference" \
        --arg status_digest "$status_digest" \
        --arg pair_digest "$pair_digest" \
        --arg java_digest "$java_digest" \
        --arg phase_only "$capture_phase_only" \
        --arg phase_identity_digest "$phase_identity_digest" \
        --arg pair_name "$pair_name" --arg java_phase "$java_phase" '{
          id: $id,
          ordinal: $ordinal,
          state: "complete",
          captures: ([{
            id: $pair_name,
            kind: "pair",
            state: "captured",
            pair_reference: ("obi-metric-pairs/" + $pair_name + ".json"),
            pair_sha256: $pair_digest,
            java_reference: ("phases/" + $java_phase + "/java-diagnostics.txt"),
            java_sha256: $java_digest
          }] + (if $phase_only == "" then [] else [{
            id: $phase_only,
            kind: "phase",
            state: "captured",
            identity_reference:
              ("phases/" + $phase_only + "/obi-identity.json"),
            identity_sha256: $phase_identity_digest
          }] end)),
          status_references: [{
            reference: $status_reference,
            sha256: $status_digest
          }],
          not_applicable_reason: null
        }' >>"$rows"
    else
      jq -cn \
        --arg id "$id" \
        --argjson ordinal "$ordinal" \
        --arg status_reference "$status_reference" \
        --arg status_digest "$status_digest" \
        --arg unavailable_digest "$unavailable_digest" \
        --arg unavailable_phase "$unavailable_phase" '{
          id: $id,
          ordinal: $ordinal,
          state: "complete",
          captures: [{
            id: $unavailable_phase,
            kind: "unavailable",
            state: "captured",
            reason: "obi_process_not_running",
            reference: ("phases/" + $unavailable_phase + "/obi-metrics.prom"),
            sha256: $unavailable_digest
          }],
          status_references: [{
            reference: $status_reference,
            sha256: $status_digest
          }],
          not_applicable_reason: null
        }' >>"$rows"
    fi
  done < <(jq -r '.[]' <<<"$ids_json")
  jq -csS --arg scenario "$scenario" '{
    schema: "obi-metric-boundary-index-v1",
    selection: {
      scenario: $scenario,
      requested_transport: "getsockopt",
      selected_transport: "getsockopt",
      repeat_count: 1
    },
    boundaries: .
  }' "$rows" >"$bundle/obi-metric-boundary-index.json"
  rm -f -- "$rows"
  jq -cn '{
    schema: "obi-java-remote-parent-terminal-metrics-v2",
    sealed: true,
    available: false,
    reason: "no-active-boundary",
    active_boundary_id: null,
    boundary_index_reference: "obi-metric-boundary-index.json",
    boundary_index_sha256: "pending"
  }' >"$bundle/terminal-obi-metrics.json"
}

write_raw_v3_scenario_result_fixture() {
  local -r bundle="$1"
  local -r scenario="$2"
  local -r request_count="$3"
  local endpoint='/api/echo'
  local rows=""
  local marker=""
  local trace_id=""
  local client_span_id=""
  local java_span_id=""
  local server_span_id=""
  local -i index=0

  case "$scenario" in
    pressure|handoff) endpoint='/api/handoff' ;;
    tls-boundary) endpoint='/api/tls-boundary' ;;
    coalesced-bridge) endpoint='/api/coalesced-bridge' ;;
  esac
  rows="$(mktemp "$TEST_TMP_DIR/raw-scenario-rows.XXXXXX")" || return 1
  for ((index = 0; index < request_count; index++)); do
    printf -v marker '%s-%02d-%016x' "$scenario" "$index" "$((index + 1))"
    printf -v trace_id '%032x' "$((index + 1))"
    printf -v client_span_id '%016x' "$((index * 2 + 1))"
    printf -v java_span_id '%016x' "$((index * 2 + 2))"
    printf -v server_span_id '%016x' "$((10000 + index))"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$marker" "$endpoint" "$trace_id" "$client_span_id" "$java_span_id" \
      "$server_span_id" \
      >>"$rows"
  done
  jq -Rn '
    [inputs | split("\t") | {
      latency_nanos: 1000000,
      request: {marker: .[0], endpoint: .[1]},
      response: {
        marker: .[0],
        secure: true,
        protocol: "HTTP/1.1",
        tls_protocol: "TLSv1.3",
        tls_cipher: "TLS_AES_128_GCM_SHA256",
        backend_connection_id: 1,
        backend_remote_port: 50000,
        tls_read_events: 1000,
        tls_read_bytes: 100000
      },
      trace: {spans: [
        {
          service_name: "apache-proxy",
          kind: "CLIENT",
          trace_id: .[2],
          span_id: .[3],
          parent_span_id: .[5],
          flags: 1,
          attributes: {
            "http.request.header.x-obi-demo-id": .[0],
            "url.full": ("https://apache-proxy" + .[1])
          }
        },
        {
          service_name: "java-backend",
          kind: "SERVER",
          trace_id: .[2],
          span_id: .[4],
          parent_span_id: .[3],
          flags: 769,
          attributes: {
            "http.request.header.x-obi-demo-id": .[0],
            "url.path": .[1]
          }
        },
        {
          service_name: "apache-proxy",
          kind: "SERVER",
          trace_id: .[2],
          span_id: .[5],
          parent_span_id: "0000000000000000",
          flags: 1,
          attributes: {
            "http.request.header.x-obi-demo-id": .[0],
            "url.path": .[1]
          }
        }
      ],
      receiver_instance_id: "fixture-receiver-instance",
      reset_generation: 1,
      marker: .[0],
      received_batches: 1,
      received_spans: 3,
      dropped_spans: 0,
      dropped_count_spans: 0,
      dropped_value_limit_spans: 0,
      dropped_retained_limit_spans: 0,
      retained_bytes: 3,
      max_retained_bytes: 1048576,
      max_value_bytes: 65536
      }
    }]
  ' <"$rows" >"$bundle/scenario-$scenario.json.cases"
  rm -f -- "$rows"
  jq -cn --arg scenario "$scenario" --argjson seed 1 \
    --argjson request_count "$request_count" \
    --slurpfile cases "$bundle/scenario-$scenario.json.cases" '{
      status: "passed",
      scenario: $scenario,
      seed: $seed,
      started_at: "2026-08-17T00:00:00Z",
      finished_at: "2026-08-17T00:00:01Z",
      request_count: $request_count,
      traffic_elapsed_nanos: 1000000000,
      throughput_per_second: $request_count,
      latency: {
        p50_nanos: 1000000,
        p95_nanos: 1000000,
        p99_nanos: 1000000
      },
      cases: $cases[0]
    }' >"$bundle/scenario-$scenario.json"
  rm -f -- "$bundle/scenario-$scenario.json.cases"
  case "$scenario" in
    connection-churn)
      # Each request closes its connection; use the fully distinct shape seen
      # in real acceptance while the verifier mirrors the producer's >=2 rule.
      # shellcheck disable=SC2016
      replace_json_file "$bundle/scenario-$scenario.json" '
        .cases |= (to_entries | map(
          .key as $index | .value |
          .response.backend_connection_id = ($index + 1) |
          .response.backend_remote_port = (50000 + $index)
        ))
      '
      ;;
    fd-port-reuse)
      # Stable connection IDs are distinct while two positive backend file
      # descriptors are deliberately reused across those identities.
      # shellcheck disable=SC2016
      replace_json_file "$bundle/scenario-$scenario.json" '
        .cases |= (to_entries | map(
          .key as $index | .value |
          .response.backend_connection_id = ($index + 1) |
          .response.backend_remote_port = (51000 + $index) |
          .response.backend_socket_fd = (100 + ($index % 2))
        )) |
        .connection_evidence = {
          frontend_connections: 32,
          frontend_protocol: "HTTP/1.1",
          reused_frontend_local_port: 39000,
          reused_frontend_file_descriptor: 7,
          distinct_frontend_local_ports: 1,
          backend_connections: 32,
          distinct_backend_connection_ids: 32,
          distinct_backend_remote_ports: 32,
          reused_backend_file_descriptor: 100
        }
      '
      ;;
    slow-body)
      # The first cumulative sample is the producer baseline. Every later
      # request proves at least two reads and the fixed 64 KiB body.
      # shellcheck disable=SC2016
      replace_json_file "$bundle/scenario-$scenario.json" '
        .cases |= (to_entries | map(
          .key as $index | .value |
          .response.tls_read_events = (1000 + ($index * 3)) |
          .response.tls_read_bytes = (100000 + ($index * 65536))
        ))
      '
      ;;
    pipelining)
      replace_json_file "$bundle/scenario-$scenario.json" '
        .connection_evidence = {
          frontend_connections: 1,
          frontend_protocol: "HTTP/1.1",
          pipelined_requests: 10,
          requests_written_before_first_read: 10
        }
      '
      ;;
    concurrency)
      # jq's $index is an internal binding, not a shell expansion.
      # shellcheck disable=SC2016
      replace_json_file "$bundle/scenario-$scenario.json" '
        .cases |= (to_entries | map(
          .key as $index | .value |
          .request += {
            concurrency_batch: "c0000000000000001",
            concurrency_expected: 16
          } |
          .response += {
            backend_worker_id: ($index + 1),
            backend_connection_id: ($index + 1),
            backend_remote_port: (50000 + $index),
            backend_socket_fd: (100 + $index),
            concurrency_batch: "c0000000000000001",
            concurrency_participants: 16,
            concurrency_max_active: 16,
            concurrency_arrival: ($index + 1),
            concurrency_release: 17
          }
        )) |
        .connection_evidence = {
          frontend_connections: 16,
          frontend_protocol: "HTTP/1.1",
          distinct_backend_workers: 16,
          distinct_concurrency_arrivals: 16,
          concurrency_participants: 16,
          concurrency_max_active: 16,
          concurrency_release: 17
        }
      '
      ;;
    pressure)
      replace_json_file "$bundle/scenario-$scenario.json" '
        .cases |= (to_entries | map(
          .key as $index | .value |
          .request.handoff_hops = (2 + ($index % 7)) |
          .request.handoff_fault = "none" |
          .response.workload = "servlet-async-executor" |
          .response.handoff_hops = ((2 + ($index % 7)) | tostring) |
          .response.handoff_fault = "none" |
          if $index == 127 then
            (.trace.spans[] | select(
              .service_name == "java-backend" and .kind == "SERVER")) |=
              (.trace_id = ("e" * 32) |
                .parent_span_id = "0000000000000000" |
                .flags = 257)
          else . end
        )) |
        .pressure_correlation = {
          exact_hit_count: (.request_count - 1),
          explicit_root_count: 1,
          wrong_parent_count: 0,
          unresolved_count: 0
        }
      '
      ;;
    timeout-retry)
      replace_json_file "$bundle/scenario-$scenario.json" '
        .cases[0] as $case |
        .faults = [{
          kind: "client-timeout",
          outcome: "deadline-exceeded-as-expected",
          elapsed_nanos: 1000000,
          marker: "timeout-retry-cancelled-1",
          parent_outcome: "reason_coded_drop",
          drop_reasons: ["timeout"],
          trace: ($case.trace |
            .marker = "timeout-retry-cancelled-1" |
            .spans |= map(
              if (.service_name == "apache-proxy" or
                .service_name == "java-backend") then
                .attributes["http.request.header.x-obi-demo-id"] =
                  "timeout-retry-cancelled-1"
              else . end) |
            (.spans[] | select(
              .service_name == "java-backend" and .kind == "SERVER")) |=
              (.trace_id = ("f" * 32) |
                .parent_span_id = "0000000000000000" |
                .flags = 257))
        }]
      '
      ;;
    handoff)
      replace_json_file "$bundle/scenario-$scenario.json" '
        ["none", "cancel", "reject", "timeout"] as $faults |
        .cases |= (to_entries | map(
          .key as $index | .value |
          .request.handoff_hops = ($index + 1) |
          .request.handoff_fault = $faults[$index] |
          .response.workload = "servlet-async-executor" |
          .response.handoff_hops = (($index + 1) | tostring) |
          .response.handoff_fault = $faults[$index]
        ))
      '
      ;;
    coalesced-bridge)
      replace_json_file "$bundle/scenario-$scenario.json" '
        . as $root |
        ($root.cases | map(.request.marker)) as $markers |
        .connection_evidence = {
          frontend_connections: 1,
          frontend_protocol: "HTTP/1.1",
          source_backend_tls_connections: 1,
          source_plaintext_write_calls: 1,
          source_plaintext_write_bytes: 128,
          source_plaintext_sha256: ("a" * 64),
          source_request_boundaries: 2
        } |
        .cases |= (to_entries | map(
          .key as $index | .value |
          .response.backend_kind = "netty-coalesced-bridge" |
          .response.coalesced_bridge = {
            plaintext_callback_count: 1,
            plaintext_callback_bytes: 128,
            plaintext_sha256: ("a" * 64),
            parser_request_count: 2,
            parser_callback_generations: [1, 1],
            parser_markers: $markers,
            traceparent_header_count: 0,
            request_markers_exact: true,
            one_plaintext_receive: true,
            passed: true,
            failure_reason: "none"
          } |
          .trace.spans = (if $index == 0 then [
            {
              service_name: "apache-proxy", kind: "SERVER",
              trace_id: ("a" * 32), span_id: "aaaaaaaaaaaaaaaa",
              parent_span_id: "0000000000000000", flags: 1,
              attributes: {
                "http.request.header.x-obi-demo-id": $markers[0],
                "http.route": "/api/coalesced-source"
              }
            },
            {
              service_name: "apache-proxy", kind: "INTERNAL",
              trace_id: ("a" * 32), span_id: "aaaaaaaaaaaaaaab",
              parent_span_id: "aaaaaaaaaaaaaaaa", flags: 1,
              attributes: {}
            },
            {
              service_name: "apache-proxy", kind: "CLIENT",
              trace_id: ("a" * 32), span_id: "aaaaaaaaaaaaaaac",
              parent_span_id: "aaaaaaaaaaaaaaab", flags: 1,
              attributes: {
                "http.request.header.x-obi-demo-id": $markers[0],
                "http.route": "/api/coalesced-source"
              }
            },
            {
              service_name: "coalesced-source", kind: "SERVER",
              trace_id: ("b" * 32), span_id: "bbbbbbbbbbbbbbbb",
              parent_span_id: "0000000000000000", flags: 1,
              attributes: {
                "http.request.header.x-obi-demo-id": $markers[0],
                "http.route": "/api/coalesced-source"
              }
            },
            {
              service_name: "java-backend", kind: "SERVER",
              trace_id: ("c" * 32), span_id: "cccccccccccccccc",
              parent_span_id: "0000000000000000", flags: 259,
              attributes: {
                "http.request.header.x-obi-demo-id": $markers[0],
                "url.path": "/api/coalesced-bridge"
              }
            }
          ] else [{
            service_name: "java-backend", kind: "SERVER",
            trace_id: ("d" * 32), span_id: "dddddddddddddddd",
            parent_span_id: "0000000000000000", flags: 259,
            attributes: {
              "http.request.header.x-obi-demo-id": $markers[1],
              "url.path": "/api/coalesced-bridge"
            }
          }] end) |
          .trace.received_spans = (.trace.spans | length) |
          .trace.retained_bytes = (.trace.spans | length)
        )) |
        .coalesced_bridge_correlation = {
          outcome: "receive_ambiguous",
          exact_hit_count: 0,
          explicit_root_count: 2,
          wrong_parent_count: 0,
          unresolved_count: 0,
          source_client_operations: 1,
          source_client_marker: "absent",
          apache_trigger_chain_proven: true,
          source_operation_chain_proven: true,
          source_plaintext_write_bytes: 128,
          tls_read_delta: 1,
          tls_bytes_delta: 128,
          take_missing_delta: 2,
          discard_total_delta: 1,
          discard_ambiguous_delta: 1
        }
      '
      ;;
    tls-boundary)
      # jq's $cases is an internal binding, not a shell expansion.
      # shellcheck disable=SC2016
      replace_json_file "$bundle/scenario-$scenario.json" '
        def request_bytes: 52768;
        def callbacks: [10000, 10000, 16000, 16000, 768];
        def payloads: [10016, 10016, 16016, 16016, 784];
        def versions: [771, 771, 771, 771, 771];
        def evidence($index):
          if $index == 0 then {
            mode: "split", delivery_shape: "split", evidence_phase: "final",
            fallback_reason: "none", coalescing_grace_millis: 0,
            coalescing_grace_expired: false, verification_buffer_bytes: 0,
            verification_buffer_limit_bytes: 0,
            verification_pair_digest_exact: false, passed: true,
            failure_reason: "none", request_complete: true, request_count: 1,
            request_header_bytes: [20000], request_body_bytes: [32768],
            request_total_bytes: [request_bytes],
            request_header_decrypted_callback_counts: [2],
            request_order: [1], emission_order: [1],
            emission_parser_callback_order: [2], response_order: [1],
            response_connection_close: [true],
            tls_application_record_legacy_versions: versions,
            tls_application_record_payload_lengths: payloads,
            decrypted_callback_lengths: callbacks,
            parser_callback_lengths: callbacks,
            decrypted_total_bytes: request_bytes,
            parser_total_bytes: request_bytes, parser_callback_count: 5,
            wire_decrypted_pairs_exact: true, headers_spanned_records: true,
            parser_shape_exact: true, parser_facing_coalesced: false,
            requests_emitted_from_single_parser_callback: true,
            request_bytes_preserved: true,
            split_buffers_forwarded_unchanged: true,
            handoff_before_parse: true, first_response_keeps_alive: false,
            response_forces_connection_close: true
          } elif $index == 1 then {
            mode: "coalesced", delivery_shape: "serialized_proxy_fallback",
            evidence_phase: "partial",
            fallback_reason: "coalescing_grace_expired",
            coalescing_grace_millis: 1, coalescing_grace_expired: true,
            verification_buffer_bytes: request_bytes,
            verification_buffer_limit_bytes: 147456,
            verification_pair_digest_exact: false, passed: false,
            failure_reason: "none", request_complete: false, request_count: 1,
            request_header_bytes: [20000], request_body_bytes: [32768],
            request_total_bytes: [request_bytes],
            request_header_decrypted_callback_counts: [2],
            request_order: [1], emission_order: [1],
            emission_parser_callback_order: [1], response_order: [1],
            response_connection_close: [false],
            tls_application_record_legacy_versions: versions,
            tls_application_record_payload_lengths: payloads,
            decrypted_callback_lengths: callbacks,
            parser_callback_lengths: [request_bytes],
            decrypted_total_bytes: request_bytes,
            parser_total_bytes: request_bytes, parser_callback_count: 1,
            wire_decrypted_pairs_exact: true, headers_spanned_records: true,
            parser_shape_exact: true, parser_facing_coalesced: false,
            requests_emitted_from_single_parser_callback: false,
            request_bytes_preserved: false,
            split_buffers_forwarded_unchanged: false,
            handoff_before_parse: true, first_response_keeps_alive: true,
            response_forces_connection_close: false
          } else {
            mode: "coalesced", delivery_shape: "serialized_proxy_fallback",
            evidence_phase: "final",
            fallback_reason: "coalescing_grace_expired",
            coalescing_grace_millis: 1, coalescing_grace_expired: true,
            verification_buffer_bytes: (request_bytes * 2),
            verification_buffer_limit_bytes: 147456,
            verification_pair_digest_exact: true, passed: true,
            failure_reason: "none", request_complete: true, request_count: 2,
            request_header_bytes: [20000, 20000],
            request_body_bytes: [32768, 32768],
            request_total_bytes: [request_bytes, request_bytes],
            request_header_decrypted_callback_counts: [2, 2],
            request_order: [1, 2], emission_order: [1, 2],
            emission_parser_callback_order: [1, 2], response_order: [1, 2],
            response_connection_close: [false, true],
            tls_application_record_legacy_versions: (versions + versions),
            tls_application_record_payload_lengths: (payloads + payloads),
            decrypted_callback_lengths: (callbacks + callbacks),
            parser_callback_lengths: [request_bytes, request_bytes],
            decrypted_total_bytes: (request_bytes * 2),
            parser_total_bytes: (request_bytes * 2), parser_callback_count: 2,
            wire_decrypted_pairs_exact: true, headers_spanned_records: true,
            parser_shape_exact: true, parser_facing_coalesced: false,
            requests_emitted_from_single_parser_callback: false,
            request_bytes_preserved: true,
            split_buffers_forwarded_unchanged: false,
            handoff_before_parse: true, first_response_keeps_alive: true,
            response_forces_connection_close: true
          } end;
        .cases |= (to_entries | map(
          .key as $index | .value |
          .request.endpoint = (if $index == 0 then
            "/api/tls-boundary/split" else
            "/api/tls-boundary/coalesced" end) |
          .request.tls_boundary_mode =
            (if $index == 0 then "split" else "coalesced" end) |
          .request.tls_boundary_sequence = (if $index == 2 then 2 else 1 end) |
          (.trace.spans[] | select(.service_name == "apache-proxy") |
            .attributes["url.full"]) = ("https://apache-proxy" +
              .request.endpoint) |
          (.trace.spans[] | select(
            .service_name == "apache-proxy" and .kind == "SERVER") |
            .attributes["url.path"]) = .request.endpoint |
          (.trace.spans[] | select(.service_name == "java-backend") |
            .attributes["url.path"]) = .request.endpoint |
          .response.backend_kind = "netty-tls-boundary" |
          .response.tls_boundary = evidence($index) |
          .response.backend_connection_id =
            (if $index == 0 then 1 else 2 end) |
          .response.backend_remote_port =
            (if $index == 0 then 50000 else 50001 end)
        )) |
        .connection_evidence = {
          frontend_connections: 2,
          frontend_protocol: "HTTP/1.1",
          sequential_requests: 2,
          responses_read_before_next_write: 1
        } |
        .cases as $cases |
        .tls_boundary_correlation = {
          exact_parent_count: 3,
          wrong_parent_count: 0,
          unresolved_count: 0,
          same_request_evidence_count: 3,
          requests: [range(0; 3) as $index | {
            marker: $cases[$index].request.marker,
            mode: (if $index == 0 then "split" else "coalesced" end),
            sequence: (if $index == 2 then 2 else 1 end),
            evidence_phase: (if $index == 1 then "partial" else "final" end),
            delivery_shape: (if $index == 0 then
              "split" else "serialized_proxy_fallback" end),
            trace_id: $cases[$index].trace.spans[0].trace_id,
            apache_client_span_id: $cases[$index].trace.spans[0].span_id,
            java_server_span_id: $cases[$index].trace.spans[1].span_id,
            java_parent_span_id: $cases[$index].trace.spans[0].span_id,
            exact_parent: true,
            same_request_evidence: true,
            request_bytes: 52768,
            tls_application_record_count: 5,
            decrypted_callback_count: 5,
            header_decrypted_callback_count: 2,
            parser_callback_count: (if $index == 0 then 5 else 1 end),
            parser_bytes: 52768
          }]
        }
      '
      ;;
  esac
}

write_raw_receive_fixture() {
  local -r bundle="$1"
  local -r label="$2"
  local cursor_map_id=51
  local guard_map_id=52
  local before="$bundle/receive-cursor-map-$label-before.json"
  local after="$bundle/receive-cursor-map-$label-after.json"
  local status="$bundle/receive-cursor-map-$label-status.json"
  local samples="$bundle/receive-cursor-map-$label-recovery-samples.log"

  jq -cn --argjson cursor_map_id "$cursor_map_id" \
    --argjson guard_map_id "$guard_map_id" '{
      status: "passed",
      cursor_map_id: $cursor_map_id,
      cursor_map_name: "jrp_recv_cur",
      cursor_kernel_name: "jrp_recv_cur",
      cursor_map_type: "Hash",
      cursor_key_size: 8,
      cursor_value_size: 56,
      cursor_max_entries: 10000,
      cursor_entries: 0,
      guard_map_id: $guard_map_id,
      guard_map_name: "jrp_recv_guard",
      guard_kernel_name: "jrp_recv_guard",
      guard_map_type: "Hash",
      guard_key_size: 8,
      guard_value_size: 56,
      guard_max_entries: 10000,
      guard_entries: 0
    }' >"$before"
  cp -- "$before" "$after"
  jq -cn --arg label "$label" \
    --argjson cursor_map_id "$cursor_map_id" \
    --argjson guard_map_id "$guard_map_id" '{
      status: "passed",
      reason: "steady-baseline",
      cursor_map_id: $cursor_map_id,
      guard_map_id: $guard_map_id,
      cursor_baseline_entries: 0,
      guard_baseline_entries: 0,
      cursor_final_entries: 0,
      guard_final_entries: 0,
      required_consecutive_samples: 2,
      attempts: 2,
      before: ("receive-cursor-map-" + $label + "-before.json"),
      after: ("receive-cursor-map-" + $label + "-after.json"),
      samples: ("receive-cursor-map-" + $label + "-recovery-samples.log")
    }' >"$status"
  : >"$bundle/receive-cursor-map-$label-before.stderr.log"
  cp -- "$before" \
    "$bundle/receive-cursor-map-$label-recovery-attempt-01.json"
  cp -- "$before" \
    "$bundle/receive-cursor-map-$label-recovery-attempt-02.json"
  : >"$bundle/receive-cursor-map-$label-recovery-attempt-01.stderr.log"
  : >"$bundle/receive-cursor-map-$label-recovery-attempt-02.stderr.log"
  printf '%s\n' \
    "attempt=1 observed_at=2000-01-01T00:00:01Z cursor_map_id=$cursor_map_id cursor_entries=0 guard_map_id=$guard_map_id guard_entries=0 matched=true consecutive=1" \
    "attempt=2 observed_at=2000-01-01T00:00:02Z cursor_map_id=$cursor_map_id cursor_entries=0 guard_map_id=$guard_map_id guard_entries=0 matched=true consecutive=2" \
    >"$samples"
}

write_raw_v3_scenario_status_fixture() {
  local -r bundle="$1"
  local -r scenario="$2"
  local reconciliation='null'
  local receive='null'
  local pressure='null'

  case "$scenario" in
    concurrency)
      reconciliation="$(jq -c '.connection_evidence' \
        "$bundle/scenario-$scenario.json")"
      ;;
    pressure)
      reconciliation='null'
      pressure="$(jq -c '{
        trace: .pressure_correlation,
        bridge: {
          transport: "getsockopt",
          phase_outcome_counts: {inject: 128,
            candidate: .pressure_correlation.exact_hit_count,
            stage: .pressure_correlation.exact_hit_count,
            retrieval: .pressure_correlation.exact_hit_count},
          auxiliary_outcome_counts: {handoff: 0},
          retrieval_valid_count: .pressure_correlation.exact_hit_count,
          upstream_failure_count: .pressure_correlation.explicit_root_count,
          retrieval_failure_count: 0,
          upstream_failure_reason_counts: {
            missing: 0, stale: 0, ambiguous: 0, malformed: 0,
            overload: .pressure_correlation.explicit_root_count, segmented: 0
          },
          retrieval_failure_reason_counts: {
            missing: 0, stale: 0, unsupported: 0, malformed: 0,
            version_mismatch: 0, ambiguous: 0, unauthorized: 0,
            already_consumed: 0, timeout: 0, overload: 0,
            transport_error: 0, disabled: 0
          }
        },
        java_reconciliation_target: {
          take_valid_count: .pressure_correlation.exact_hit_count,
          attributable_absence_count: .pressure_correlation.explicit_root_count,
          diagnostic_self_miss_count: 1
        }
      }' "$bundle/scenario-$scenario.json")"
      ;;
    timeout-retry)
      reconciliation="$(jq -c '.faults[0]' \
        "$bundle/scenario-$scenario.json")"
      ;;
    tls-boundary)
      reconciliation="$(jq -c '.tls_boundary_correlation' \
        "$bundle/scenario-$scenario.json")"
      receive="$(jq -c . \
        "$bundle/receive-cursor-map-$scenario-status.json")"
      ;;
    coalesced-bridge)
      reconciliation="$(jq -c '.coalesced_bridge_correlation' \
        "$bundle/scenario-$scenario.json")"
      receive="$(jq -c . \
        "$bundle/receive-cursor-map-$scenario-status.json")"
      ;;
  esac
  jq -cn --arg scenario "$scenario" \
    --arg result "scenario-$scenario.json" \
    --argjson pressure "$pressure" \
    --argjson reconciliation "$reconciliation" \
    --argjson receive "$receive" '{
      status: "passed",
      scenario: $scenario,
      exit_status: 0,
      metric_status: 0,
      pressure_correlation: $pressure,
      scenario_reconciliation: $reconciliation,
      receive_coordination_maps: $receive,
      java_diagnostics: {before: null, after: null},
      obi_metric_evidence: null,
      obi_metric_boundary_ids: [$scenario],
      result: $result,
      stderr: ("scenario-" + $scenario + ".stderr.log"),
      before_phase: ("phases/" + $scenario + "-before"),
      after_phase: ("phases/" + $scenario + "-after")
    }' >"$bundle/scenario-$scenario-status.json"
  : >"$bundle/scenario-$scenario.stderr.log"
}

write_raw_v3_stress_phase_authority_fixture() {
  local -r bundle="$1"
  local -r scenario="$2"
  local -r container_id='0000000000000000000000000000000000000000000000000000000000000001'
  local -r started_at='2000-01-01T00:00:00.000000001Z'
  local phase=""
  local value=""

  [[ "$scenario" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  for phase in "$scenario-before" "$scenario-after"; do
    if [[ "$phase" == *-before ]]; then
      value=0
    else
      value=1
    fi
    mkdir -p -- "$bundle/phases/$phase" || return 1
    if [[ "$phase" == pressure-before &&
      -s "$bundle/phases/$phase/obi-metrics.prom" ]]; then
      printf '%s\n' \
        "obi_java_remote_parent_operations_total{operation=\"take\",status=\"valid\",transport=\"getsockopt\"} $value" \
        'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
        >>"$bundle/phases/$phase/obi-metrics.prom" || return 1
      LC_ALL=C sort -o "$bundle/phases/$phase/obi-metrics.prom" -- \
        "$bundle/phases/$phase/obi-metrics.prom" || return 1
    else
      printf '%s\n' \
        "obi_java_remote_parent_operations_total{operation=\"take\",status=\"valid\",transport=\"getsockopt\"} $value" \
        'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
        >"$bundle/phases/$phase/obi-metrics.prom" || return 1
    fi
    write_running_identity_fixture \
      "$bundle" "$phase" "$container_id" "$started_at" || return 1
    write_java_diagnostics_fixture "$bundle" "$phase" || return 1
  done
}

sync_raw_v3_stress_status_authority_fixture() {
  local -r bundle="$1"
  local -r scenario="$2"
  local -r pair_reference="obi-metric-pairs/$scenario.json"
  local -r before_reference="phases/$scenario-before/java-diagnostics.txt"
  local -r after_reference="phases/$scenario-after/java-diagnostics.txt"
  local -r status="$bundle/scenario-$scenario-status.json"
  local candidate="$status.tmp"

  [[ -f "$bundle/$pair_reference" && ! -L "$bundle/$pair_reference" &&
    -f "$bundle/$before_reference" && ! -L "$bundle/$before_reference" &&
    -f "$bundle/$after_reference" && ! -L "$bundle/$after_reference" &&
    -f "$status" && ! -L "$status" ]] || return 1
  jq -cS --arg scenario "$scenario" \
    --arg pair_reference "$pair_reference" \
    --arg before_reference "$before_reference" \
    --arg after_reference "$after_reference" \
    --rawfile before_snapshot "$bundle/$before_reference" \
    --rawfile after_snapshot "$bundle/$after_reference" \
    --slurpfile pair "$bundle/$pair_reference" '
      def java_evidence($reference; $raw):
        ($raw | rtrimstr("\n")) as $snapshot |
        {
          reference: $reference,
          snapshot: $snapshot,
          counters: ($snapshot | split(",") |
            map(split("=") | {(.[0]): .[1]}) | add)
        };
      .before_phase = ("phases/" + $scenario + "-before") |
      .after_phase = ("phases/" + $scenario + "-after") |
      .java_diagnostics = {
        before: java_evidence($before_reference; $before_snapshot),
        after: java_evidence($after_reference; $after_snapshot)
      } |
      .obi_metric_evidence = {reference: $pair_reference, pair: $pair[0]}
    ' "$status" >"$candidate" || return 1
  mv -fT -- "$candidate" "$status"
}

sync_timeout_status_fixture() {
  local -r bundle="$1"
  local fault=""

  fault="$(jq -c '.faults[0]' "$bundle/scenario-timeout-retry.json")" ||
    return 1
  replace_json_file "$bundle/scenario-timeout-retry-status.json" \
    '.scenario_reconciliation = $fault' --argjson fault "$fault"
}

write_raw_pressure_fixture() {
  local -r bundle="$1"

  printf '%s\n' \
    '{"status":"passed","mode":"prepare","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10000,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"touched":0}' \
    >"$bundle/map-pressure-pressure-prepare.json"
  printf '%s\n' \
    '{"status":"passed","mode":"fill","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10000,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"touched":10000,"capacity_rejected_entries":1,"verified_present_entries":10000}' \
    >"$bundle/map-pressure-pressure-fill.json"
  printf '%s\n' \
    '{"status":"passed","mode":"cleanup","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10000,"process_map_id":0,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"touched":10000,"cleanup_verified":true,"verified_absent_entries":10001}' \
    >"$bundle/map-pressure-pressure-cleanup.json"
  printf '%s\n' \
    'command_status=0' \
    'validation_status=passed' \
    'recovery_status=passed' \
    'monitor_status=0' \
    >"$bundle/map-pressure-pressure-cleanup-attempt-01.status"
  cp -- "$bundle/map-pressure-pressure-cleanup.json" \
    "$bundle/map-pressure-pressure-cleanup-attempt-01.json"
  : >"$bundle/map-pressure-pressure-prepare.stderr.log"
  : >"$bundle/map-pressure-pressure-fill.stderr.log"
  : >"$bundle/map-pressure-pressure-cleanup.stderr.log"
  : >"$bundle/map-pressure-pressure-cleanup-attempt-01.stderr.log"
  mkdir -p -- "$bundle/phases/pressure-before"
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 0' \
    >"$bundle/phases/pressure-before/obi-metrics.prom"
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 10000' \
    >"$bundle/map-pressure-pressure-pressured.prom"
  cp -- "$bundle/map-pressure-pressure-pressured.prom" \
    "$bundle/map-pressure-pressure-traffic-complete.prom"
  printf '%s\n' \
    'obi_bpf_map_entries_total{map_id="41",map_name="java_remote_par",map_type="hash"} 0' \
    >"$bundle/map-pressure-pressure-recovered.prom"
  cp -- "$bundle/map-pressure-pressure-recovered.prom" \
    "$bundle/map-pressure-pressure-recovered-sample-01.prom"
  cp -- "$bundle/map-pressure-pressure-recovered.prom" \
    "$bundle/map-pressure-pressure-recovered-sample-02.prom"
  printf '%s\n' \
    'attempt=1 observed_at=2000-01-01T00:00:03Z entries=0 matched=true consecutive=1' \
    'attempt=2 observed_at=2000-01-01T00:00:04Z entries=0 matched=true consecutive=2' \
    >"$bundle/map-pressure-pressure-recovered-samples.log"
  cp -- "$bundle/map-pressure-pressure-recovered.prom" \
    "$bundle/map-pressure-pressure-cleanup-attempt-01-recovered.prom"
  cp -- "$bundle/map-pressure-pressure-recovered-sample-01.prom" \
    "$bundle/map-pressure-pressure-cleanup-attempt-01-recovered-sample-01.prom"
  cp -- "$bundle/map-pressure-pressure-recovered-sample-02.prom" \
    "$bundle/map-pressure-pressure-cleanup-attempt-01-recovered-sample-02.prom"
  cp -- "$bundle/map-pressure-pressure-recovered-samples.log" \
    "$bundle/map-pressure-pressure-cleanup-attempt-01-recovered-samples.log"
  printf '%s\n' \
    'status=pressured observed_at=2000-01-01T00:00:01Z map_id=41 baseline=0 max_entries=10000 entries=10000' \
    'status=traffic-complete observed_at=2000-01-01T00:00:02Z map_id=41 baseline=0 max_entries=10000 entries=10000 operation=inject transport=tcp inject_total=128 target=128' \
    >"$bundle/map-pressure-pressure-monitor.log"
}

materialize_raw_v3_fixture_file() {
  local -r bundle="$1"
  local -r relative="$2"

  [[ "$relative" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || return 1
  [[ ! -L "$bundle/$relative" ]] || return 1
  if [[ ! -e "$bundle/$relative" ]]; then
    if [[ "$relative" == */* ]]; then
      mkdir -p -- "${bundle}/${relative%/*}" || return 1
    fi
    : >"$bundle/$relative" || return 1
  fi
  [[ -f "$bundle/$relative" ]]
}

materialize_raw_v3_phase_fixture() {
  local -r bundle="$1"
  local -r phase="$2"
  local -r shape="$3"
  local service=""

  [[ "$phase" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  mkdir -p -- "$bundle/phases/$phase" || return 1
  case "$shape" in
    metric-live|metric-live-delta)
      materialize_raw_v3_fixture_file \
        "$bundle" "phases/$phase/obi-metrics.prom" || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" "phases/$phase/obi-identity.json" || return 1
      if [[ "$shape" == metric-live-delta ]]; then
        materialize_raw_v3_fixture_file \
          "$bundle" "phases/$phase/obi-metrics.delta" || return 1
      fi
      ;;
    full-live*|full-unavailable*)
      materialize_raw_v3_fixture_file \
        "$bundle" "phases/$phase/obi-metrics.prom" || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" "phases/$phase/container-stats.jsonl" || return 1
      if [[ "$shape" == full-live* ]]; then
        materialize_raw_v3_fixture_file \
          "$bundle" "phases/$phase/obi-identity.json" || return 1
      fi
      for service in obi apache-proxy java-backend coalesced-source trace-receiver; do
        materialize_raw_v3_fixture_file \
          "$bundle" "phases/$phase/$service-resources.txt" || return 1
        if [[ "$shape" == full-live* || "$service" != obi ]]; then
          materialize_raw_v3_fixture_file \
            "$bundle" "phases/$phase/$service-processes.txt" || return 1
        fi
      done
      case "$shape" in
        *-java|*-java-metric|*-java-java-delta|*-java-both)
          materialize_raw_v3_fixture_file \
            "$bundle" "phases/$phase/java-diagnostics.txt" || return 1
          materialize_raw_v3_fixture_file \
            "$bundle" "phases/$phase/java-diagnostics.stderr" || return 1
          ;;
        *-java-text|*-java-text-both)
          materialize_raw_v3_fixture_file \
            "$bundle" "phases/$phase/java-diagnostics.txt" || return 1
          ;;
      esac
      case "$shape" in
        *-metric|*-both)
          materialize_raw_v3_fixture_file \
            "$bundle" "phases/$phase/obi-metrics.delta" || return 1
          ;;
      esac
      case "$shape" in
        *-java-delta|*-both)
          materialize_raw_v3_fixture_file \
            "$bundle" "phases/$phase/java-diagnostics.delta" || return 1
          ;;
      esac
      ;;
    stopped-attestation|java-only)
      if [[ "$shape" == stopped-attestation ]]; then
        materialize_raw_v3_fixture_file \
          "$bundle" "phases/$phase/obi-identity.json" || return 1
      fi
      materialize_raw_v3_fixture_file \
        "$bundle" "phases/$phase/java-diagnostics.txt" || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" "phases/$phase/java-diagnostics.stderr" || return 1
      ;;
    *) return 1 ;;
  esac
}

materialize_raw_v3_scenario_fixture() {
  local -r bundle="$1"
  local -r label="$2"
  local -r before_shape="$3"
  local -r after_shape="$4"
  local -r metric_shape="$5"
  local -r statuses="$6"

  [[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  if [[ ! -e "$bundle/scenario-$label.json" ]]; then
    jq -cn --arg scenario "$label" '{status: "passed", scenario: $scenario}' \
      >"$bundle/scenario-$label.json" || return 1
  fi
  materialize_raw_v3_fixture_file \
    "$bundle" "scenario-$label.stderr.log" || return 1
  printf 'scenario-%s-status.json\n' "$label" >>"$statuses" || return 1
  case "$metric_shape" in
    full)
      materialize_raw_v3_fixture_file \
        "$bundle" "metrics-boundary-$label.prom" || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" "metrics-diagnostics-$label.prom" || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" "metrics-after-$label.prom" || return 1
      ;;
    boundary-after)
      materialize_raw_v3_fixture_file \
        "$bundle" "metrics-boundary-$label.prom" || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" "metrics-after-$label.prom" || return 1
      ;;
    boundary)
      materialize_raw_v3_fixture_file \
        "$bundle" "metrics-boundary-$label.prom" || return 1
      ;;
    none) ;;
    *) return 1 ;;
  esac
  materialize_raw_v3_phase_fixture \
    "$bundle" "$label-before" "$before_shape" || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" "$label-after" "$after_shape"
}

raw_v3_pair_labels_fixture() {
  printf '%s\n' \
    basic keepalive pipelining concurrency connection-churn fd-port-reuse \
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff \
    virtual-thread netty netty-server dispatch w3c obi-flags \
    basic-delayed-otlp-suppression basic-primary-w3c-stale-recovery \
    basic-security-primary-live-fd-recovery \
    basic-primary-generation-mismatch-recovery \
    basic-primary-w3c-fault-recovery basic-permanent-absence-recovery \
    restart-late-attach-recovery restart-restart-recovery \
    basic-helper-attach-recovery primary-w3c-stale \
    basic-security-primary-recovery \
    helper-attach-failure-helper-unavailable w3c-helper-unavailable \
    concurrency-security-primary-victim \
    disabled-permanent-absence-baseline \
    disabled-helper-attach-bridge-disabled disabled \
    delayed-otlp-prime-suppression security-primary-sibling \
    security-primary-same-cgroup primary-live-fd-probe primary-live-fd-full \
    w3c-match-obi-stopped late-attach-obi-stopped \
    extension-controls-obi-stopped primary-w3c-fault-version-mismatch \
    primary-w3c-fault-bad-size primary-w3c-fault-zero-trace-id \
    primary-w3c-fault-zero-span-id primary-generation-mismatch-fault \
    restart-fault helper-attach-rejection
}

raw_v3_status_owner_fixture() {
  case "$1" in
    basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
    slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff|\
    virtual-thread|netty|netty-server|dispatch|w3c|w3c-match|obi-flags|\
    disabled|uninstrumented|unix-w3c-stale|unix-generation-mismatch|\
    w3c-fault|auto-unavailable)
      printf '%s\n' "$1"
      ;;
    basic-delayed-otlp-suppression|delayed-otlp-prime-suppression)
      printf 'delayed-otlp-suppression\n'
      ;;
    security|concurrency-security-primary-victim|\
    basic-security-primary-recovery|\
    basic-security-primary-live-fd-recovery|security-primary-sibling|\
    security-primary-same-cgroup|primary-live-fd-probe|primary-live-fd-full|\
    primary-live-fd-security)
      printf 'security\n'
      ;;
    primary-w3c-stale|basic-primary-w3c-stale-recovery)
      printf 'primary-w3c-stale\n'
      ;;
    primary-generation-mismatch|primary-generation-mismatch-fault|\
    basic-primary-generation-mismatch-recovery)
      printf 'primary-generation-mismatch\n'
      ;;
    primary-w3c-fault-version-mismatch|primary-w3c-fault-bad-size|\
    primary-w3c-fault-zero-trace-id|primary-w3c-fault-zero-span-id|\
    basic-primary-w3c-fault-recovery)
      printf 'primary-w3c-fault\n'
      ;;
    permanent-absence|disabled-permanent-absence-baseline|\
    fail-open-permanent-absence|w3c-only-permanent-absence|\
    basic-permanent-absence-recovery)
      printf 'permanent-absence\n'
      ;;
    late-attach-obi-stopped|fail-open-obi-absent|w3c-only-obi-absent|\
    restart-late-attach-recovery)
      printf 'late-attach\n'
      ;;
    restart-fault|restart-restart-recovery)
      printf 'restart-during-traffic\n'
      ;;
    helper-attach-rejection|disabled-helper-attach-bridge-disabled|\
    helper-attach-failure-helper-unavailable|w3c-helper-unavailable|\
    basic-helper-attach-recovery)
      printf 'helper-attach-failure\n'
      ;;
    w3c-match-obi-stopped)
      printf 'w3c-match\n'
      ;;
    extension-controls-obi-stopped|w3c-only-extension-absent|\
    w3c-only-extension-disabled)
      printf 'extension-controls\n'
      ;;
    *) return 1 ;;
  esac
}

write_raw_v3_pair_fixture() {
  local -r bundle="$1"
  local -r label="$2"
  local -r template="$bundle/obi-metric-pairs/basic.json"
  local -r output="$bundle/obi-metric-pairs/$label.json"

  [[ -f "$template" && ! -L "$template" ]] || return 1
  [[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || return 1
  if [[ "$label" != basic ]]; then
    case "$label" in
      keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
      slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff)
        jq -cS --arg boundary "$label" \
          --arg before_reference "phases/$label-before/obi-identity.json" \
          --arg after_reference "phases/$label-after/obi-identity.json" '
            .boundary = $boundary |
            .before.identity_reference = $before_reference |
            .after.identity_reference = $after_reference
          ' "$template" >"$output" || return 1
        ;;
      *)
        jq -cS --arg boundary "$label" '.boundary = $boundary' "$template" \
          >"$output" || return 1
        ;;
    esac
  fi
}

materialize_raw_v3_common_roots_fixture() {
  local -r bundle="$1"
  local relative=""
  local -a roots=(
    bridge-build.log bridge-artifacts.sha256 bridge-metadata.sha256
    certificates.json compose-resolved.yaml compose-up.log
    apache-instrumentation-startup.prom apache-instrumentation-startup.txt
    java-selected-transport-configuration.txt host-topology.txt
    bpftool-feature-probe.txt bpftool-maps.txt bpftool-programs.txt
    compose-images.json container-identities.txt image-identities.txt
    java-version.txt apache-version.txt apache-openssl-version.txt
    obi-startup.log java-startup.log apache-startup.log compose-ps.txt compose.log
    final-receiver-snapshot.json
  )

  for relative in "${roots[@]}"; do
    materialize_raw_v3_fixture_file "$bundle" "$relative" || return 1
  done
}

materialize_raw_v3_acceptance_roots_fixture() {
  local -r bundle="$1"
  local relative=""
  local control=""
  local -a roots=(
    apache-instrumentation-recreate-instrumented.prom
    apache-instrumentation-recreate-instrumented.txt
    apache-instrumentation-disabled-control.prom
    apache-instrumentation-disabled-control.txt
    apache-instrumentation-late-attach.prom
    apache-instrumentation-late-attach.txt
    apache-instrumentation-restart-fault-recovery.prom
    apache-instrumentation-restart-fault-recovery.txt
    apache-instrumentation-helper-attach-failure.prom
    apache-instrumentation-helper-attach-failure.txt
    apache-instrumentation-helper-attach-recovery.prom
    apache-instrumentation-helper-attach-recovery.txt
    apache-instrumentation-drain-late-attach.prom
    apache-instrumentation-drain-late-attach.txt
    runtime-assertions-all.txt runtime-assertions-basic.txt
    runtime-assertions-delayed-otlp-suppression.txt
    runtime-assertions-obi-absent.txt runtime-assertions-permanent-absence.txt
    runtime-assertions-extension-absent.txt
    runtime-assertions-extension-disabled.txt
    runtime-assertions-helper-attach-fault.txt
    runtime-assertions-primary-live-fd-security.txt
    runtime-assertions-primary-generation-mismatch.txt
    runtime-assertions-primary-w3c-fault.txt runtime-assertions-disabled.txt
    runtime-assertions-uninstrumented.txt
    duplicate-suppression-all.prom duplicate-suppression-disabled.prom
    duplicate-suppression-delayed-otlp-before-request.prom
    duplicate-suppression-delayed-otlp-before-export.prom
    duplicate-suppression-delayed-otlp-ready.prom
    duplicate-suppression-post-delayed-otlp-suppression-restoration.prom
    duplicate-suppression-primary-live-descriptor-security-preparation.prom
    duplicate-suppression-post-primary-live-descriptor-security-recovery.prom
    duplicate-suppression-matching-W3C-and-OBI-preparation.prom
    duplicate-suppression-post-match-bridge-restoration.prom
    duplicate-suppression-primary-W3C-stale-preparation.prom
    duplicate-suppression-post-primary-W3C-stale-recovery.prom
    duplicate-suppression-primary-W3C-fault-preparation.prom
    duplicate-suppression-post-primary-W3C-fault-recovery.prom
    duplicate-suppression-primary-generation-mismatch-preparation.prom
    duplicate-suppression-post-primary-generation-mismatch-recovery.prom
    duplicate-suppression-post-permanent-absence-recovery.prom
    duplicate-suppression-late-attach-recovery.prom
    duplicate-suppression-restart-fault-recovery.prom
    duplicate-suppression-helper-attach-failure-preparation.prom
    delayed-otlp-window.txt delayed-otlp-receiver-before-request.json
    delayed-otlp-receiver-before-export.json delayed-otlp-receiver-ready.json
    compose-primary-live-fd-resolved.yaml security-primary-sibling.log
    security-primary-sibling.json security-primary-sibling.cgroup
    security-primary-same-cgroup.log security-primary-same-cgroup.txt
    security-primary-java.cgroup security-primary-probe.cgroup
    security-primary-probe.status metrics-security-primary-sibling-ready.prom
    metrics-security-primary-sibling-complete.prom
    metrics-security-primary-probe-ready.prom
    primary-live-fd-security-armed.txt primary-live-fd-security-released.txt
    primary-live-fd-security-consumed.txt security-primary-live-fd.log
    scenario-security-primary-live-fd-victim.json
    scenario-security-primary-live-fd-victim.stderr.log
    metrics-security-primary-live-fd-before.prom
    metrics-security-primary-live-fd-probe.prom
    metrics-security-primary-live-fd-after.prom w3c-match-matching-bridge.log
    compose-primary-fault-resolved.yaml
    primary-generation-mismatch-barrier-armed.txt
    primary-generation-mismatch-barrier-released.txt
    primary-generation-mismatch-barrier-consumed.txt
    scenario-primary-generation-mismatch.json
    scenario-primary-generation-mismatch.stderr.log generation-mismatch-helper.json
    generation-mismatch-helper.stderr.log
    metrics-primary-generation-mismatch-take.prom compose-disabled-control.yaml
    permanent-absence-lifetime.txt permanent-absence-java-before.txt
    permanent-absence-java-after.txt permanent-absence-java.log
    scenario-restart-fault.json scenario-restart-fault.stderr.log
    restart-fault-diagnostics.txt compose-helper-attach-failure.yaml
    helper-attach-failure-obi.log helper-attach-failure-java.log
    helper-attach-failure-metrics-before.prom
    helper-attach-failure-metrics-after.prom
    helper-attach-failure-metrics-quiet.prom
    helper-attach-failure-metrics-recovery.prom
    helper-attach-failure-metrics.delta helper-attach-failure-obi-before.txt
    helper-attach-failure-obi-fault.txt helper-attach-failure-obi-recovery.txt
    helper-attach-failure-java-fault.txt
    helper-attach-failure-java-after-traffic.txt
    helper-attach-failure-java-recovery.txt
    helper-attach-failure-java-diagnostics.txt compose-uninstrumented-control.yaml
  )

  for relative in "${roots[@]}"; do
    materialize_raw_v3_fixture_file "$bundle" "$relative" || return 1
  done
  for control in permanent-absence-disabled permanent-absence \
    helper-attach-bridge-disabled helper-attach-failure helper-attach-recovery \
    instrumented-control uninstrumented-control; do
    for relative in "$control-response.json" \
      "$control-response.normalized.json" "$control-response.status"; do
      materialize_raw_v3_fixture_file "$bundle" "$relative" || return 1
    done
  done
  mkdir -p -- "$bundle/restart-control" || return 1
  for relative in events.log pre-stop-ready obi-stopped stopped-traffic-complete \
    obi-ready post-restart-traffic-complete; do
    materialize_raw_v3_fixture_file \
      "$bundle" "restart-control/$relative" || return 1
  done
}

materialize_raw_v3_acceptance_scenarios_fixture() {
  local -r bundle="$1"
  local -r statuses="$2"
  local label=""
  local mode=""
  local relative=""
  local -a normal_scenarios=(
    basic keepalive pipelining concurrency connection-churn fd-port-reuse
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff
    virtual-thread netty netty-server dispatch w3c obi-flags
    basic-delayed-otlp-suppression basic-primary-w3c-stale-recovery
    basic-security-primary-live-fd-recovery
    basic-primary-generation-mismatch-recovery
    basic-primary-w3c-fault-recovery basic-permanent-absence-recovery
    restart-late-attach-recovery restart-restart-recovery
    basic-helper-attach-recovery
  )
  local -a no_diagnostics_scenarios=(
    basic-security-primary-recovery
    helper-attach-failure-helper-unavailable
    w3c-helper-unavailable
  )
  local -a disabled_bridge_scenarios=(
    disabled-permanent-absence-baseline
    disabled-helper-attach-bridge-disabled
    disabled
  )
  local -a stopped_scenarios=(
    fail-open-permanent-absence w3c-only-permanent-absence
    fail-open-obi-absent w3c-only-obi-absent
    w3c-only-extension-absent w3c-only-extension-disabled uninstrumented
  )

  for label in "${normal_scenarios[@]}"; do
    if [[ "$label" == coalesced-bridge || "$label" == timeout-retry ]]; then
      materialize_raw_v3_scenario_fixture "$bundle" "$label" \
        full-live-java full-live-java-text-both full "$statuses" || return 1
    else
      materialize_raw_v3_scenario_fixture "$bundle" "$label" \
        full-live-java full-live-java-both full "$statuses" || return 1
    fi
  done
  materialize_raw_v3_scenario_fixture "$bundle" primary-w3c-stale \
    full-live-java-text full-live-java-text-both full "$statuses" || return 1
  for label in "${no_diagnostics_scenarios[@]}"; do
    materialize_raw_v3_scenario_fixture "$bundle" "$label" \
      full-live full-live-metric boundary-after "$statuses" || return 1
  done
  materialize_raw_v3_scenario_fixture \
    "$bundle" concurrency-security-primary-victim \
    metric-live metric-live-delta boundary-after "$statuses" || return 1
  for label in "${disabled_bridge_scenarios[@]}"; do
    materialize_raw_v3_scenario_fixture "$bundle" "$label" \
      full-live-java full-live-java-metric none "$statuses" || return 1
  done
  for label in "${stopped_scenarios[@]}"; do
    materialize_raw_v3_scenario_fixture "$bundle" "$label" \
      full-unavailable-java full-unavailable-java-metric none "$statuses" ||
      return 1
  done
  printf 'unavailable\n' \
    >"$bundle/phases/uninstrumented-after/obi-metrics.prom" || return 1
  materialize_raw_v3_scenario_fixture "$bundle" w3c-match \
    full-unavailable-java full-unavailable-java-both boundary "$statuses" ||
    return 1

  materialize_raw_v3_phase_fixture \
    "$bundle" delayed-otlp-prime-before full-live || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" delayed-otlp-suppression-after full-live || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-diagnostics-before java-only || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-diagnostics-after java-only || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-before full-live || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-sibling-ready metric-live-delta || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-sibling-complete metric-live || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-probe-ready metric-live-delta || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-live-fd-before metric-live || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-live-fd-probe metric-live-delta || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" security-primary-live-fd-after metric-live-delta || return 1
  printf '%s\n' scenario-primary-live-fd-security-status.json \
    scenario-security-status.json >>"$statuses" || return 1

  for label in w3c-match late-attach extension-controls; do
    materialize_raw_v3_phase_fixture \
      "$bundle" "$label-obi-running" full-live || return 1
    materialize_raw_v3_phase_fixture \
      "$bundle" "$label-obi-stopped" stopped-attestation || return 1
  done
  materialize_raw_v3_fixture_file \
    "$bundle" metrics-boundary-late-attach.prom || return 1

  for mode in version-mismatch bad-size zero-trace-id zero-span-id; do
    label="primary-w3c-fault-$mode"
    for relative in "scenario-$label.json" "scenario-$label.stderr.log" \
      "metrics-boundary-$label.prom" "metrics-after-$label.prom" \
      "$label-run-1-armed.txt" "$label-run-1-consumed.txt"; do
      materialize_raw_v3_fixture_file "$bundle" "$relative" || return 1
    done
    printf 'scenario-%s-status.json\n' "$label" >>"$statuses" || return 1
    materialize_raw_v3_phase_fixture \
      "$bundle" "$label-before" full-live-java-text || return 1
    materialize_raw_v3_phase_fixture \
      "$bundle" "$label-after" full-live-java-text-both || return 1
  done
  materialize_raw_v3_phase_fixture \
    "$bundle" primary-generation-mismatch-before full-live-java-text || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" primary-generation-mismatch-after full-live-java-text-both ||
    return 1
  materialize_raw_v3_fixture_file \
    "$bundle" metrics-boundary-primary-generation-mismatch.prom || return 1
  printf 'scenario-primary-generation-mismatch-status.json\n' \
    >>"$statuses" || return 1
  materialize_raw_v3_phase_fixture "$bundle" permanent-absence java-only || return 1
  printf 'scenario-permanent-absence-status.json\n' >>"$statuses" || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" restart-fault-before full-live-java || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" restart-fault-after full-live-java-java-delta || return 1
  printf 'scenario-restart-fault-status.json\n' >>"$statuses" || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" helper-attach-failure-before full-live || return 1
  materialize_raw_v3_phase_fixture \
    "$bundle" helper-attach-failure-after full-live || return 1
  materialize_raw_v3_phase_fixture "$bundle" helper-attach-recovery java-only ||
    return 1
  materialize_raw_v3_phase_fixture "$bundle" pressure-pressured full-live || return 1
  materialize_raw_v3_phase_fixture "$bundle" final full-unavailable-java || return 1
  for label in unix-w3c-stale unix-generation-mismatch w3c-fault \
    auto-unavailable; do
    printf 'scenario-%s-status.json\n' "$label" >>"$statuses" || return 1
  done
}

write_raw_v3_status_files_fixture() {
  local -r bundle="$1"
  local -r statuses="$2"
  local -r owners="$3"
  local reference=""
  local label=""
  local owner=""
  local reason=""

  LC_ALL=C sort -u -o "$statuses" -- "$statuses" || return 1
  : >"$owners"
  while IFS= read -r reference; do
    [[ "$reference" =~ ^scenario-([a-z0-9][a-z0-9-]{0,95})-status\.json$ ]] ||
      return 1
    label="${BASH_REMATCH[1]}"
    owner="$(raw_v3_status_owner_fixture "$label")" || return 1
    case "$label" in
      unix-w3c-stale|unix-generation-mismatch|w3c-fault)
        reason='requires forced Unix transport'
        jq -cn --arg scenario "$label" --arg reason "$reason" '{
          status: "not_applicable",
          scenario: $scenario,
          reason: $reason,
          obi_metric_boundary_ids: [$scenario]
        }' >"$bundle/$reference" || return 1
        ;;
      auto-unavailable)
        reason='requires auto transport selection'
        jq -cn --arg scenario "$label" --arg reason "$reason" '{
          status: "not_applicable",
          scenario: $scenario,
          reason: $reason,
          obi_metric_boundary_ids: [$scenario]
        }' >"$bundle/$reference" || return 1
        ;;
      basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
      slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff)
        [[ -f "$bundle/$reference" && ! -L "$bundle/$reference" ]] || return 1
        ;;
      *)
        jq -cn --arg scenario "$label" --arg owner "$owner" '{
          status: "passed",
          scenario: $scenario,
          obi_metric_boundary_ids: [$owner]
        }' >"$bundle/$reference" || return 1
        ;;
    esac
    printf '%s\t%s\n' "$owner" "$reference" >>"$owners" || return 1
  done <"$statuses"
}

write_raw_v3_exact_index_fixture() {
  local -r bundle="$1"
  local -r scenario="$2"
  local -r ids_json="$3"
  local -r pairs="$4"
  local -r status_owners="$5"
  local boundary_rows=""
  local capture_rows=""
  local status_rows=""
  local captures_json=""
  local statuses_json=""
  local id=""
  local owner=""
  local reference=""
  local label=""
  local digest=""
  local java_reference=""
  local java_digest=""
  local reason=""
  local -i ordinal=0
  local -a complete_ids=()
  declare -A pair_owner=()

  mapfile -t complete_ids < <(jq -r '.[] | select(
    . != "unix-w3c-stale" and . != "unix-generation-mismatch" and
    . != "w3c-fault" and . != "auto-unavailable")' <<<"$ids_json")
  (( ${#complete_ids[@]} > 0 )) || return 1
  while IFS= read -r label; do
    [[ -n "$label" ]] || continue
    pair_owner["$label"]="$(raw_v3_status_owner_fixture "$label")" || return 1
  done <"$pairs"

  boundary_rows="$(mktemp "$TEST_TMP_DIR/raw-index-boundaries.XXXXXX")" || return 1
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    ordinal=$((ordinal + 1))
    capture_rows="$(mktemp "$TEST_TMP_DIR/raw-index-captures.XXXXXX")" || return 1
    status_rows="$(mktemp "$TEST_TMP_DIR/raw-index-statuses.XXXXXX")" || return 1
    : >"$capture_rows"
    : >"$status_rows"
    while IFS=$'\t' read -r owner reference; do
      [[ "$owner" == "$id" ]] || continue
      digest="$(sha256sum <"$bundle/$reference")" || return 1
      digest="${digest%% *}"
      jq -cn --arg reference "$reference" --arg digest "$digest" '{
        reference: $reference,
        sha256: $digest
      }' >>"$status_rows" || return 1
    done <"$status_owners"
    if [[ "$id" != unix-w3c-stale && "$id" != unix-generation-mismatch &&
      "$id" != w3c-fault && "$id" != auto-unavailable ]]; then
      while IFS= read -r label; do
        [[ -n "$label" && "${pair_owner[$label]}" == "$id" ]] || continue
        reference="obi-metric-pairs/$label.json"
        digest="$(sha256sum <"$bundle/$reference")" || return 1
        digest="${digest%% *}"
        java_reference=""
        java_digest=""
        case "$label" in
          basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
          slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff)
            java_reference="phases/$label-after/java-diagnostics.txt"
            [[ -f "$bundle/$java_reference" && ! -L "$bundle/$java_reference" ]] ||
              return 1
            java_digest="$(sha256sum <"$bundle/$java_reference")" || return 1
            java_digest="${java_digest%% *}"
            ;;
        esac
        jq -cn --arg id "$label" --arg reference "$reference" \
          --arg digest "$digest" --arg java_reference "$java_reference" \
          --arg java_digest "$java_digest" '{
            id: $id,
            kind: "pair",
            state: "captured",
            pair_reference: $reference,
            pair_sha256: $digest,
            java_reference: (if $java_reference == "" then null
              else $java_reference end),
            java_sha256: (if $java_digest == "" then null else $java_digest end)
          }' >>"$capture_rows" || return 1
      done <"$pairs"
      if [[ "$id" == uninstrumented ]]; then
        reference='phases/uninstrumented-after/obi-metrics.prom'
        digest="$(sha256sum <"$bundle/$reference")" || return 1
        digest="${digest%% *}"
        jq -cn --arg reference "$reference" --arg digest "$digest" '{
          id: "uninstrumented-after",
          kind: "unavailable",
          state: "captured",
          reason: "obi_process_not_running",
          reference: $reference,
          sha256: $digest
        }' >>"$capture_rows" || return 1
      fi
    fi
    captures_json="$(jq -cs . "$capture_rows")" || return 1
    statuses_json="$(jq -cs . "$status_rows")" || return 1
    if [[ "$id" == unix-w3c-stale || "$id" == unix-generation-mismatch ||
      "$id" == w3c-fault || "$id" == auto-unavailable ]]; then
      if [[ "$id" == auto-unavailable ]]; then
        reason='requires auto transport selection'
      else
        reason='requires forced Unix transport'
      fi
      [[ "$captures_json" == '[]' && "$statuses_json" != '[]' ]] || return 1
      jq -cn --arg id "$id" --argjson ordinal "$ordinal" \
        --arg reason "$reason" --argjson statuses "$statuses_json" '{
          id: $id,
          ordinal: $ordinal,
          state: "not_applicable",
          captures: [],
          status_references: $statuses,
          not_applicable_reason: $reason
        }' >>"$boundary_rows" || return 1
    else
      [[ "$captures_json" != '[]' && "$statuses_json" != '[]' ]] || return 1
      jq -cn --arg id "$id" --argjson ordinal "$ordinal" \
        --argjson captures "$captures_json" \
        --argjson statuses "$statuses_json" '{
          id: $id,
          ordinal: $ordinal,
          state: "complete",
          captures: $captures,
          status_references: $statuses,
          not_applicable_reason: null
        }' >>"$boundary_rows" || return 1
    fi
    rm -f -- "$capture_rows" "$status_rows"
  done < <(jq -r '.[]' <<<"$ids_json")
  jq -csS --arg scenario "$scenario" '{
    schema: "obi-metric-boundary-index-v1",
    selection: {
      scenario: $scenario,
      requested_transport: "getsockopt",
      selected_transport: "getsockopt",
      repeat_count: 1
    },
    boundaries: .
  }' "$boundary_rows" >"$bundle/obi-metric-boundary-index.json" || return 1
  rm -f -- "$boundary_rows"
  jq -cn '{
    schema: "obi-java-remote-parent-terminal-metrics-v2",
    sealed: true,
    available: false,
    reason: "no-active-boundary",
    active_boundary_id: null,
    boundary_index_reference: "obi-metric-boundary-index.json",
    boundary_index_sha256: "pending"
  }' >"$bundle/terminal-obi-metrics.json"
}

materialize_raw_v3_exact_fixture() {
  local -r bundle="$1"
  local -r kind="$2"
  local ids_json=""
  local statuses=""
  local status_owners=""
  local pairs=""
  local label=""
  local selection=""
  local terminal_phase=""

  statuses="$(mktemp "$TEST_TMP_DIR/raw-statuses.XXXXXX")" || return 1
  status_owners="$(mktemp "$TEST_TMP_DIR/raw-status-owners.XXXXXX")" || return 1
  pairs="$(mktemp "$TEST_TMP_DIR/raw-pairs.XXXXXX")" || return 1
  : >"$statuses"
  : >"$pairs"
  materialize_raw_v3_common_roots_fixture "$bundle" || return 1
  rm -f -- "$bundle/phases/journal-unavailable/obi-metrics.prom"
  rmdir -- "$bundle/phases/journal-unavailable" || return 1
  case "$kind" in
    acceptance)
      ids_json="$(all_v3_boundary_ids_json)" || return 1
      selection=all
      terminal_phase=extension-controls-obi-stopped
      materialize_raw_v3_acceptance_roots_fixture "$bundle" || return 1
      materialize_raw_v3_acceptance_scenarios_fixture \
        "$bundle" "$statuses" || return 1
      raw_v3_pair_labels_fixture >"$pairs" || return 1
      ;;
    assertion-failure)
      ids_json='["basic"]'
      selection='assertion-failure'
      terminal_phase=basic-after
      printf 'scenario-basic-status.json\n' >"$statuses" || return 1
      printf 'basic\n' >"$pairs" || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" runtime-assertions-assertion-failure.txt || return 1
      materialize_raw_v3_fixture_file \
        "$bundle" duplicate-suppression-assertion-failure.prom || return 1
      materialize_raw_v3_scenario_fixture "$bundle" basic \
        full-live-java full-live-java-both full "$statuses" || return 1
      materialize_raw_v3_phase_fixture "$bundle" final java-only || return 1
      ;;
    *) return 1 ;;
  esac
  LC_ALL=C sort -u -o "$pairs" -- "$pairs" || return 1
  while IFS= read -r label; do
    [[ -n "$label" ]] || continue
    case "$label" in
      basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
      slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff)
        write_raw_v3_stress_phase_authority_fixture \
          "$bundle" "$label" || return 1
        ;;
    esac
    write_raw_v3_pair_fixture "$bundle" "$label" || return 1
    case "$label" in
      basic|keepalive|pipelining|concurrency|connection-churn|fd-port-reuse|\
      slow-body|tls-boundary|coalesced-bridge|timeout-retry|pressure|handoff)
        sync_raw_v3_stress_status_authority_fixture \
          "$bundle" "$label" || return 1
        ;;
    esac
  done <"$pairs"
  write_raw_v3_status_files_fixture \
    "$bundle" "$statuses" "$status_owners" || return 1
  write_raw_v3_exact_index_fixture \
    "$bundle" "$selection" \
    "$ids_json" "$pairs" "$status_owners" || return 1
  write_java_diagnostics_fixture "$bundle" "$terminal_phase" || return 1
  : >"$bundle/.terminal-java-diagnostics.lock"
  : >"$bundle/.terminal-java-diagnostics-transition.lock"
  printf 'terminal-java-diagnostics-frozen-v1\n' \
    >"$bundle/.terminal-java-diagnostics.freeze"
  jq -cS '.sealed = false' "$bundle/terminal-java-diagnostics.json" \
    >"$bundle/.last-valid-java-diagnostics.json" || return 1
  chmod 0600 -- \
    "$bundle/.terminal-java-diagnostics.lock" \
    "$bundle/.terminal-java-diagnostics-transition.lock" \
    "$bundle/.terminal-java-diagnostics.freeze"
  chmod 0644 -- "$bundle/.last-valid-java-diagnostics.json"
  rm -f -- "$statuses" "$status_owners" "$pairs"
}

write_raw_v3_run_status_fixture() {
  local -r bundle="$1"
  local -r kind="$2"
  local status='passed'
  local exit_status=0
  local acceptance=true
  local reason='none'
  local failure_stage='none'
  local failure_line=0

  if [[ "$kind" == assertion-failure ]]; then
    status='failed'
    exit_status=2
    acceptance=false
    reason='deliberate-assertion-failure,targeted-scenario'
    failure_stage='deliberate-assertion-failure'
    failure_line=42
  fi
  jq -cn --arg status "$status" --argjson exit_status "$exit_status" \
    --argjson acceptance "$acceptance" --arg reason "$reason" \
    --arg failure_stage "$failure_stage" --argjson failure_line "$failure_line" \
    --arg evidence_directory "$bundle" \
    --slurpfile java "$bundle/terminal-java-diagnostics.json" \
    --slurpfile obi "$bundle/terminal-obi-metrics.json" '{
      schema: "obi-apache-java-https-run-status-v3",
      status: $status,
      exit_status: $exit_status,
      acceptance_evidence: $acceptance,
      acceptance_evidence_reason: $reason,
      failure_stage: $failure_stage,
      failure_line: $failure_line,
      evidence_directory: $evidence_directory,
      java_bridge_diagnostics_reference: "terminal-java-diagnostics.json",
      java_bridge_diagnostics: $java[0],
      obi_metric_evidence_reference: "terminal-obi-metrics.json",
      obi_metric_evidence: $obi[0],
      obi_metric_boundary_index_reference: "obi-metric-boundary-index.json",
      obi_metric_boundary_index_sha256: "pending"
    }' >"$bundle/run-status.json"
  sync_v3_index_envelopes "$bundle"
}

write_raw_resource_recovery_fixture() {
  local -r bundle="$1"
  local -a services=(
    obi apache-proxy java-backend coalesced-source trace-receiver
  )
  local -a phases=(keepalive-before pressure-after handoff-before)
  local service=""
  local phase=""
  local container_id=""
  local -i service_index=0
  local -i phase_index=0
  local -i host_pid=0
  local -i rss=0
  local -i threads=0
  local -i fds=0

  for ((service_index = 0; service_index < ${#services[@]}; service_index++)); do
    service="${services[service_index]}"
    for ((phase_index = 0; phase_index < ${#phases[@]}; phase_index++)); do
      phase="${phases[phase_index]}"
      if [[ "$service" == obi ]]; then
        container_id="$(jq -er '.container_id' \
          "$bundle/phases/$phase/obi-identity.json")" || return 1
        host_pid="$(jq -er '.host_pid' \
          "$bundle/phases/$phase/obi-identity.json")" || return 1
      else
        container_id="$(printf '%s' "resource-$service" | sha256sum)"
        container_id="${container_id%% *}"
        host_pid=$((2000 + service_index))
      fi
      rss=$((100000 + service_index * 10000 + phase_index * 1000))
      threads=$((20 + service_index + phase_index))
      fds=$((10 + service_index + phase_index))
      {
        printf 'container_id=%s\n' "$container_id"
        printf 'host_pid=%s\n' "$host_pid"
        printf 'VmPeak:\t500000 kB\n'
        printf 'VmSize:\t400000 kB\n'
        printf 'VmRSS:\t%s kB\n' "$rss"
        printf 'VmData:\t300000 kB\n'
        printf 'VmStk:\t132 kB\n'
        printf 'VmExe:\t1024 kB\n'
        printf 'VmLib:\t2048 kB\n'
        printf 'Threads:\t%s\n' "$threads"
        printf 'FDs:\t%s\n' "$fds"
      } >"$bundle/phases/$phase/$service-resources.txt" || return 1
    done
  done
}

replace_resource_record_line() {
  local -r file="$1"
  local -r key="$2"
  local -r replacement="$3"
  local -r candidate="$file.tmp"

  awk -v key="$key" -v replacement="$replacement" '
    index($0, key) == 1 { $0 = replacement; replaced++ }
    { print }
    END { if (replaced != 1) exit 1 }
  ' "$file" >"$candidate" || return 1
  mv -- "$candidate" "$file"
}

create_raw_v3_acceptance_fixture() {
  local -r repository="$1"
  local -r revision="$2"
  local -r bundle="$3"
  local scenario=""
  local request_count=""
  local -a stress_scenarios=(
    basic keepalive pipelining concurrency connection-churn fd-port-reuse
    slow-body tls-boundary coalesced-bridge timeout-retry pressure handoff
  )

  write_external_v3_authority_fixture \
    "$repository" "$revision" "$bundle" acceptance
  write_external_v3_journal_fixture "$bundle"
  write_raw_receive_fixture "$bundle" tls-boundary
  write_raw_receive_fixture "$bundle" coalesced-bridge
  for scenario in "${stress_scenarios[@]}"; do
    request_count="$(scenario_request_count_fixture "$scenario")" || return 1
    write_raw_v3_scenario_result_fixture \
      "$bundle" "$scenario" "$request_count"
    write_raw_v3_scenario_status_fixture "$bundle" "$scenario"
  done
  write_raw_pressure_fixture "$bundle"
  materialize_raw_v3_exact_fixture "$bundle" acceptance
  write_raw_resource_recovery_fixture "$bundle"
  write_raw_v3_run_status_fixture "$bundle" acceptance
}

create_raw_v3_assertion_fixture() {
  local -r repository="$1"
  local -r revision="$2"
  local -r bundle="$3"
  write_external_v3_authority_fixture \
    "$repository" "$revision" "$bundle" assertion-failure
  write_external_v3_journal_fixture "$bundle"
  write_raw_v3_scenario_result_fixture "$bundle" basic 1
  write_raw_v3_scenario_status_fixture "$bundle" basic
  materialize_raw_v3_exact_fixture "$bundle" assertion-failure
  write_raw_v3_run_status_fixture "$bundle" assertion-failure
  printf '%s\n' \
    'stage=deliberate-assertion-failure' \
    'line=42' \
    'exit_status=2' \
    'command=die:\ deliberate\ assertion\ failure\ requested' \
    >"$bundle/failure-context.txt"
  jq -cn '{
    status: "failed",
    scenario: "assertion-failure",
    reason: "deliberate assertion failure requested",
    expected_exit_status: 2
  }' >"$bundle/scenario-assertion-failure.json"
  jq -cn --slurpfile java "$bundle/terminal-java-diagnostics.json" '{
    status: "failed",
    scenario: "assertion-failure",
    exit_status: 2,
    metric_status: 0,
    result: "scenario-assertion-failure.json",
    failure_context: "failure-context.txt",
    obi_metric_boundary_ids: ["basic"],
    java_bridge_diagnostics_reference: "terminal-java-diagnostics.json",
    java_bridge_diagnostics: $java[0]
  }' >"$bundle/scenario-assertion-failure-status.json"
}

restore_external_v3_fixture() {
  local -r bundle="$1"
  local -r baseline="$2"

  [[ -n "$TEST_TMP_DIR" && "$bundle" == "$TEST_TMP_DIR"/* &&
    -d "$baseline" && "$baseline" == "$TEST_TMP_DIR"/* ]] || {
    die "refusing to restore an unsafe external v3 fixture"
  }
  chmod -R u+rwX -- "$bundle"
  rm -rf -- "$bundle"
  mkdir -p -- "$bundle"
  cp -a -- "$baseline/." "$bundle/"
}

expect_external_v3_rejection() {
  local -r description="$1"
  shift

  if "$@" >/dev/null 2>&1; then
    die "verifier accepted $description"
  fi
}

write_cleanup_chmod_wrapper() {
  local -r output="$1"

  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'target="${!#}"' \
    'resolved="$($REAL_READLINK -f -- "$target" 2>/dev/null || true)"' \
    'if [[ "$target" == /proc/self/fd/* &&' \
    '  "$resolved" =~ ^/tmp/verify-retained-evidence\.[^/]+$ &&' \
    '  ! -e "$CLEANUP_STATE/triggered" ]]; then' \
    '  printf "%s\n" "$resolved" >"$CLEANUP_PATH_LOG"' \
    '  : >"$CLEANUP_STATE/triggered"' \
    '  case "$CLEANUP_FAULT" in' \
    '    fail) exit 73 ;;' \
    '    replace)' \
    '      "$REAL_MV" -- "$resolved" "$CLEANUP_STATE/owned"' \
    '      "$REAL_MKDIR" -m 0700 -- "$resolved"' \
    '      printf "unowned replacement must survive\n" >"$resolved/sentinel"' \
    '      exit 0' \
    '      ;;' \
    '    hardlink)' \
    '      "$REAL_LN" -- "$CLEANUP_SENTINEL" "$resolved/external-hardlink"' \
    '      ;;' \
    '  esac' \
    'fi' \
    'exec "$REAL_CHMOD" "$@"' \
    >"$output"
  chmod 0755 -- "$output"
}

test_raw_verifier_cleanup_guards() {
  local -r verifier="$1"
  local -r assertion="$2"
  local -r parent="$TEST_TMP_DIR/raw-cleanup-guards"
  local -r wrapper_directory="$parent/bin"
  local -r state="$parent/state"
  local -r path_log="$parent/path.log"
  local -r stderr_log="$parent/verifier.stderr"
  local real_chmod=""
  local real_mkdir=""
  local real_ln=""
  local real_mv=""
  local real_readlink=""
  local real_rm=""
  local retained_path=""
  local fault=""
  local -r sentinel="$parent/external-sentinel"
  local sentinel_digest=""
  local sentinel_mode=""

  mkdir -p -- "$wrapper_directory" "$state"
  real_chmod="$(command -v chmod)" || return 1
  real_ln="$(command -v ln)" || return 1
  real_mkdir="$(command -v mkdir)" || return 1
  real_mv="$(command -v mv)" || return 1
  real_readlink="$(command -v readlink)" || return 1
  real_rm="$(command -v rm)" || return 1
  write_cleanup_chmod_wrapper "$wrapper_directory/chmod"

  for fault in fail replace; do
    "$real_rm" -rf -- "$state/owned"
    rm -f -- "$state/triggered" "$path_log" "$stderr_log"
    if env PATH="$wrapper_directory:$PATH" \
      CLEANUP_FAULT="$fault" CLEANUP_PATH_LOG="$path_log" \
      CLEANUP_STATE="$state" REAL_CHMOD="$real_chmod" \
      REAL_LN="$real_ln" REAL_MKDIR="$real_mkdir" REAL_MV="$real_mv" \
      REAL_READLINK="$real_readlink" CLEANUP_SENTINEL="$sentinel" \
      "$verifier" --raw-v3 assertion-failure "$assertion" \
      >/dev/null 2>"$stderr_log"; then
      die "raw verifier hid a successful-verification cleanup $fault"
    fi
    grep -F 'private verification cleanup was incomplete' \
      "$stderr_log" >/dev/null ||
      die "raw verifier did not propagate cleanup $fault"
    retained_path="$(<"$path_log")"
    [[ "$retained_path" == /tmp/verify-retained-evidence.* ]] ||
      die "cleanup $fault did not retain a bounded verifier path"
    if [[ "$fault" == replace ]]; then
      [[ -f "$retained_path/sentinel" && -d "$state/owned" ]] ||
        die "identity replacement was deleted or the owned tree was lost"
    else
      [[ -d "$retained_path" && ! -L "$retained_path" ]] ||
        die "cleanup chmod failure did not retain private transaction state"
    fi
    "$real_chmod" -R u+rwX -- "$retained_path" "$state/owned" \
      >/dev/null 2>&1 || true
    "$real_rm" -rf -- "$retained_path" "$state/owned"
  done

  printf 'external hardlink sentinel\n' >"$sentinel"
  chmod 0400 -- "$sentinel"
  sentinel_digest="$(sha256sum <"$sentinel")"
  sentinel_digest="${sentinel_digest%% *}"
  sentinel_mode="$(stat -Lc '%a' -- "$sentinel")"
  "$real_rm" -rf -- "$state/owned"
  rm -f -- "$state/triggered" "$path_log" "$stderr_log"
  env PATH="$wrapper_directory:$PATH" \
    CLEANUP_FAULT=hardlink CLEANUP_PATH_LOG="$path_log" \
    CLEANUP_STATE="$state" REAL_CHMOD="$real_chmod" REAL_LN="$real_ln" \
    REAL_MKDIR="$real_mkdir" REAL_MV="$real_mv" \
    REAL_READLINK="$real_readlink" CLEANUP_SENTINEL="$sentinel" \
    "$verifier" --raw-v3 assertion-failure "$assertion" \
    >/dev/null 2>"$stderr_log" ||
    die "raw verifier could not safely unlink an injected external hardlink"
  retained_path="$(<"$path_log")"
  [[ ! -e "$retained_path" && ! -L "$retained_path" ]] ||
    die "raw verifier retained a transaction after safe hardlink cleanup"
  [[ "$(stat -Lc '%a' -- "$sentinel")" == "$sentinel_mode" ]] ||
    die "raw verifier cleanup changed an external hardlink sentinel mode"
  [[ "$(sha256sum <"$sentinel")" == "$sentinel_digest  -" ]] ||
    die "raw verifier cleanup changed external hardlink sentinel content"
}

rewire_raw_stress_pair_authority_fixture() {
  local -r bundle="$1"
  local -r pair_reference='obi-metric-pairs/keepalive.json'
  local -r status_reference='scenario-keepalive-status.json'
  local -r basic_status='scenario-basic-status.json'
  local pair_digest=""
  local java_digest=""
  local status_digest=""

  replace_json_file "$bundle/$pair_reference" '
    .before.identity_reference = "phases/basic-before/obi-identity.json" |
    .after.identity_reference = "phases/basic-after/obi-identity.json"
  '
  pair_digest="$(sha256sum <"$bundle/$pair_reference")" || return 1
  pair_digest="${pair_digest%% *}"
  java_digest="$(sha256sum \
    <"$bundle/phases/basic-after/java-diagnostics.txt")" || return 1
  java_digest="${java_digest%% *}"
  replace_json_file "$bundle/$status_reference" '
    .before_phase = $basic[0].before_phase |
    .after_phase = $basic[0].after_phase |
    .java_diagnostics = $basic[0].java_diagnostics |
    .obi_metric_evidence = {
      reference: $pair_reference,
      pair: $pair[0]
    }
  ' --arg pair_reference "$pair_reference" \
    --slurpfile pair "$bundle/$pair_reference" \
    --slurpfile basic "$bundle/$basic_status"
  status_digest="$(sha256sum <"$bundle/$status_reference")" || return 1
  status_digest="${status_digest%% *}"
  replace_json_file "$bundle/obi-metric-boundary-index.json" '
    (.boundaries[] | select(.id == "keepalive")) |= (
      (.captures[] | select(.kind == "pair")) |= (
        .pair_sha256 = $pair_digest |
        .java_reference = "phases/basic-after/java-diagnostics.txt" |
        .java_sha256 = $java_digest) |
      (.status_references[] |
        select(.reference == $status_reference).sha256) = $status_digest)
  ' --arg pair_digest "$pair_digest" --arg java_digest "$java_digest" \
    --arg status_reference "$status_reference" --arg status_digest "$status_digest"
  sync_v3_index_envelopes "$bundle"
}

mutate_raw_pressure_capacity_fixture() {
  local -r bundle="$1"
  local file=""

  replace_json_file "$bundle/map-pressure-pressure-prepare.json" \
    '.max_entries = 9999'
  replace_json_file "$bundle/map-pressure-pressure-fill.json" '
    .max_entries = 9999 |
    .touched = 9999 |
    .verified_present_entries = 9999
  '
  replace_json_file "$bundle/map-pressure-pressure-cleanup.json" '
    .max_entries = 9999 |
    .touched = 9999 |
    .verified_absent_entries = 10000
  '
  cp -- "$bundle/map-pressure-pressure-cleanup.json" \
    "$bundle/map-pressure-pressure-cleanup-attempt-01.json" || return 1
  for file in map-pressure-pressure-pressured.prom \
    map-pressure-pressure-traffic-complete.prom; do
    sed 's/ 10000$/ 9999/' "$bundle/$file" >"$bundle/$file.tmp" || return 1
    mv -fT -- "$bundle/$file.tmp" "$bundle/$file" || return 1
  done
  sed 's/max_entries=10000 entries=10000/max_entries=9999 entries=9999/g' \
    "$bundle/map-pressure-pressure-monitor.log" \
    >"$bundle/map-pressure-pressure-monitor.log.tmp" || return 1
  mv -fT -- "$bundle/map-pressure-pressure-monitor.log.tmp" \
    "$bundle/map-pressure-pressure-monitor.log"
}

test_raw_v3_mode() {
  local -r repository="$1"
  local -r verifier="$2"
  local -r revision="$3"
  local -r acceptance="$TEST_TMP_DIR/raw-v3-acceptance"
  local -r assertion="$TEST_TMP_DIR/raw-v3-assertion"
  local -r acceptance_baseline="$TEST_TMP_DIR/raw-v3-acceptance-baseline"
  local -r assertion_baseline="$TEST_TMP_DIR/raw-v3-assertion-baseline"
  local reference=""
  local metrics_reference=""
  local digest=""
  local path=""

  create_raw_v3_acceptance_fixture "$repository" "$revision" "$acceptance"
  "$verifier" --raw-v3 acceptance "$acceptance" >/dev/null
  cp -a -- "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/official-javaagent.json" '
    .version = "9.9.9" |
    .sha256 = "9999999999999999999999999999999999999999999999999999999999999999" |
    .url = "https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/9.9.9/opentelemetry-javaagent-9.9.9.jar"
  '
  expect_external_v3_rejection \
    'raw v3 metadata for an OTel release not pinned by authenticated source' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$acceptance/environment.txt" >"$acceptance/environment.txt.tmp"
  mv -- "$acceptance/environment.txt.tmp" "$acceptance/environment.txt"
  expect_external_v3_rejection \
    'raw v3 environment text with reordered canonical keys' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  truncate -s -1 -- "$acceptance/environment.txt"
  expect_external_v3_rejection \
    'raw v3 environment text without a terminal line feed' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$acceptance/source-state.txt" >"$acceptance/source-state.txt.tmp"
  mv -- "$acceptance/source-state.txt.tmp" "$acceptance/source-state.txt"
  expect_external_v3_rejection \
    'raw v3 source-state text with reordered canonical keys' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  truncate -s -1 -- "$acceptance/source-state.txt"
  expect_external_v3_rejection \
    'raw v3 source-state text without a terminal line feed' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$acceptance/phases/keepalive-before/obi-resources.txt" \
    >"$acceptance/phases/keepalive-before/obi-resources.txt.tmp"
  mv -- "$acceptance/phases/keepalive-before/obi-resources.txt.tmp" \
    "$acceptance/phases/keepalive-before/obi-resources.txt"
  expect_external_v3_rejection \
    'raw v3 resource text with reordered canonical fields' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  truncate -s -1 -- \
    "$acceptance/phases/keepalive-before/obi-resources.txt"
  expect_external_v3_rejection \
    'raw v3 resource text without a terminal line feed' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  truncate -s -1 -- "$acceptance/bridge-source-revision.txt"
  expect_external_v3_rejection \
    'raw v3 bridge revision without a terminal line feed' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  truncate -s -1 -- "$acceptance/bridge-source-tree.sha256"
  expect_external_v3_rejection \
    'raw v3 bridge tree digest without a terminal line feed' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-keepalive.json" \
    '.cases[-1].response.backend_remote_port += 1'
  expect_external_v3_rejection \
    'raw v3 keepalive evidence that changed backend connection shape' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-connection-churn.json" \
    '.cases[].response.backend_connection_id = 1'
  expect_external_v3_rejection \
    'raw v3 connection churn without multiple backend connections' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-fd-port-reuse.json" \
    '.connection_evidence.reused_backend_file_descriptor = 999'
  expect_external_v3_rejection \
    'raw v3 file-descriptor reuse evidence not witnessed by distinct connections' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-slow-body.json" '
    .cases[1].response.tls_read_events =
      (.cases[0].response.tls_read_events + 1)
  '
  expect_external_v3_rejection \
    'raw v3 slow-body evidence with fewer than two decrypted reads' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-slow-body.json" '
    .cases[1].response.tls_read_bytes =
      (.cases[0].response.tls_read_bytes + 65535)
  '
  expect_external_v3_rejection \
    'raw v3 slow-body evidence below the fixed 64 KiB body' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-concurrency.json" \
    '.cases[1].response.backend_worker_id = .cases[0].response.backend_worker_id'
  expect_external_v3_rejection \
    'raw v3 concurrency evidence without sixteen distinct backend workers' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-keepalive.json" '
    .cases[0].trace.spans += [(.cases[0].trace.spans[1] |
      .span_id = "eeeeeeeeeeeeeeee" |
      .attributes["url.path"] = "/api/unrelated")]
  '
  expect_external_v3_rejection \
    'raw v3 distinct-parent scenario with an extra Java server span' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-fd-port-reuse.json" \
    'del(.cases[1].response.backend_socket_fd)'
  expect_external_v3_rejection \
    'raw v3 fd-port-reuse evidence with one unobserved backend descriptor' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-tls-boundary.json" \
    '.cases[2].response.backend_connection_id = 3'
  expect_external_v3_rejection \
    'raw v3 TLS-boundary pair without backend connection reuse' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-tls-boundary.json" '
    .cases[2].response.tls_boundary.decrypted_callback_lengths =
      ([10000,10000,16000,16000,768,10000,10000,16000,16000,384,384]) |
    .cases[2].response.tls_boundary.tls_application_record_legacy_versions =
      ([771,771,771,771,771,771,771,771,771,771,771]) |
    .cases[2].response.tls_boundary.tls_application_record_payload_lengths =
      ([10016,10016,16016,16016,784,10016,10016,16016,16016,400,400])
  '
  expect_external_v3_rejection \
    'raw v3 TLS correlation with a forged per-request callback segment count' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-tls-boundary.json" '
    .cases[0].response.tls_boundary.decrypted_callback_lengths =
      [10000,9999,16001,16000,768] |
    .cases[0].response.tls_boundary.parser_callback_lengths =
      .cases[0].response.tls_boundary.decrypted_callback_lengths
  '
  expect_external_v3_rejection \
    'raw v3 TLS evidence with a forged header callback intersection count' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-tls-boundary.json" \
    '.cases[0].response.tls_boundary.emission_parser_callback_order = []'
  expect_external_v3_rejection \
    'raw v3 split TLS evidence without an emission callback' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-tls-boundary.json" \
    '.cases[0].response.tls_boundary.emission_parser_callback_order = [1]'
  expect_external_v3_rejection \
    'raw v3 split TLS evidence emitted before header completion' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-coalesced-bridge.json" \
    '.cases[1].response.coalesced_bridge.plaintext_callback_bytes = 127'
  expect_external_v3_rejection \
    'raw v3 coalesced response that disagrees with source plaintext evidence' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-coalesced-bridge.json" '
    (.cases[1].trace.spans[] |
      select(.service_name == "java-backend" and .kind == "SERVER") |
      .parent_span_id) = "1111111111111111" |
    (.cases[1].trace.spans[] |
      select(.service_name == "java-backend" and .kind == "SERVER") |
      .flags) = 769
  '
  expect_external_v3_rejection \
    'raw v3 coalesced Java span that is not an explicit local root' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-coalesced-bridge.json" '
    (.cases[0].trace.spans[] |
      select(.service_name == "apache-proxy" and .kind == "SERVER") |
      .attributes["http.request.header.x_obi_demo_id"]) = "conflict"
  '
  expect_external_v3_rejection \
    'raw v3 coalesced trigger with conflicting marker aliases' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-basic.json" '
    .cases[0].request.endpoint = "/api/handoff" |
    (.cases[0].trace.spans[] |
      select(.service_name == "apache-proxy")).attributes["url.full"] =
        "https://apache-proxy/api/handoff" |
    (.cases[0].trace.spans[] |
      select(.service_name == "java-backend")).attributes["url.path"] =
        "/api/handoff"
  '
  expect_external_v3_rejection \
    'raw v3 basic scenario using another allowlisted scenario endpoint' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-basic.json" '
    (.cases[0].trace.spans[] |
      select(.service_name == "apache-proxy" and .kind == "CLIENT") |
      .attributes["url.full"]) = "https://apache-proxy/api/echo-evil"
  '
  expect_external_v3_rejection \
    'raw v3 Apache span using a suffix of the fixed scenario endpoint' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-basic.json" \
    '.cases[0].latency_nanos = 75000000001'
  expect_external_v3_rejection \
    'raw v3 scenario evidence with a case above the producer timeout' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-basic.json" \
    '.finished_at = "2026-08-17T00:01:16Z"'
  expect_external_v3_rejection \
    'raw v3 scenario evidence whose wall duration exceeds the producer timeout' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-timeout-retry.json" \
    '.faults[0].elapsed_nanos = 75000000001'
  replace_json_file "$acceptance/scenario-timeout-retry-status.json" \
    '.scenario_reconciliation.elapsed_nanos = 75000000001'
  expect_external_v3_rejection \
    'raw v3 timeout-retry fault above the producer timeout' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-timeout-retry.json" \
    'del(.faults[0].trace)'
  sync_timeout_status_fixture "$acceptance"
  expect_external_v3_rejection \
    'raw v3 timeout reconciliation without its retained trace' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-timeout-retry.json" '
    .faults[0].trace.spans += [(.faults[0].trace.spans[] |
      select(.service_name == "java-backend" and .kind == "SERVER") |
      .span_id = "eeeeeeeeeeeeeeee")]
  '
  sync_timeout_status_fixture "$acceptance"
  expect_external_v3_rejection \
    'raw v3 timeout reconciliation with two marked Java servers' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-timeout-retry.json" \
    '.faults[0].trace.dropped_spans = 1'
  sync_timeout_status_fixture "$acceptance"
  expect_external_v3_rejection \
    'raw v3 timeout reconciliation with receiver loss' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-timeout-retry.json" '
    .faults[0].parent_outcome = "exact" |
    .faults[0].drop_reasons = []
  '
  sync_timeout_status_fixture "$acceptance"
  expect_external_v3_rejection \
    'raw v3 timeout outcome that disagrees with its local-root topology' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-timeout-retry.json" '
    .faults[0].drop_reasons = ["missing", "timeout"]
  '
  sync_timeout_status_fixture "$acceptance"
  expect_external_v3_rejection \
    'raw v3 timeout local root with a non-unique reason-coded drop' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-pressure.json" '
    .cases[0].request.handoff_hops = 9 |
    .cases[0].response.handoff_hops = "9"
  '
  expect_external_v3_rejection \
    'raw v3 pressure workload with a coherent but unplanned handoff hop' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-handoff.json" '
    .cases[2].request.handoff_fault = "none" |
    .cases[2].response.handoff_fault = "none"
  '
  expect_external_v3_rejection \
    'raw v3 handoff workload with a coherent but unplanned fault sequence' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-pressure.json" '
    ([.cases[0].trace.spans[] | select(
      .service_name == "apache-proxy" and .kind == "CLIENT")][0]) as $client |
    ([.cases[0].trace.spans[] | select(
      .service_name == "apache-proxy" and .kind == "SERVER")][0]) as $server |
    ([.cases[0].trace.spans[] | select(
      .service_name == "java-backend" and .kind == "SERVER")][0]) as $java |
    .cases[1].trace.spans |= map(
      if .service_name == "apache-proxy" and .kind == "CLIENT" then
        .trace_id = $client.trace_id | .span_id = $client.span_id |
        .parent_span_id = $server.span_id
      elif .service_name == "apache-proxy" and .kind == "SERVER" then
        .trace_id = $server.trace_id | .span_id = $server.span_id |
        .parent_span_id = "0000000000000000"
      elif .service_name == "java-backend" and .kind == "SERVER" then
        .trace_id = $java.trace_id | .parent_span_id = $java.parent_span_id
      else . end)
  '
  expect_external_v3_rejection \
    'raw v3 pressure cases that share one exact Java parent identity' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  printf 'container=unavailable\n' \
    >"$acceptance/phases/pressure-after/obi-resources.txt"
  expect_external_v3_rejection \
    'raw v3 resource recovery with an unavailable leader-process record' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_resource_record_line \
    "$acceptance/phases/pressure-after/apache-proxy-resources.txt" \
    container_id= \
    'container_id=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
  expect_external_v3_rejection \
    'raw v3 resource recovery with container identity drift' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  for phase in keepalive-before pressure-after handoff-before; do
    cp -- "$acceptance/phases/$phase/obi-resources.txt" \
      "$acceptance/phases/$phase/apache-proxy-resources.txt"
  done
  expect_external_v3_rejection \
    'raw v3 resource recovery that aliases two services to one leader process' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  for phase in keepalive-before pressure-after handoff-before; do
    replace_resource_record_line \
      "$acceptance/phases/$phase/obi-resources.txt" container_id= \
      'container_id=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
    replace_resource_record_line \
      "$acceptance/phases/$phase/obi-resources.txt" host_pid= 'host_pid=9999'
  done
  expect_external_v3_rejection \
    'raw v3 stable OBI resource identity detached from phase process identity' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_resource_record_line \
    "$acceptance/phases/pressure-after/java-backend-resources.txt" \
    VmRSS: $'VmRSS:\t251073 kB'
  expect_external_v3_rejection \
    'raw v3 resource recovery above the Java RSS growth cap' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_resource_record_line \
    "$acceptance/phases/pressure-after/obi-resources.txt" \
    FDs: $'FDs:\t10'
  replace_resource_record_line \
    "$acceptance/phases/handoff-before/obi-resources.txt" \
    FDs: $'FDs:\t13'
  expect_external_v3_rejection \
    'raw v3 resource recovery with unstable recovery-sample FD spread' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  reference='phases/pressure-pressured/obi-identity.json'
  metrics_reference='phases/pressure-pressured/obi-metrics.prom'
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{operation="take",status="valid",transport="getsockopt"} 2' \
    'obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"} 0' \
    >"$acceptance/$metrics_reference"
  write_running_identity_fixture \
    "$acceptance" pressure-pressured \
    '9999999999999999999999999999999999999999999999999999999999999999' \
    '2000-01-01T00:00:00.000000099Z'
  digest="$(sha256sum <"$acceptance/$reference")"
  digest="${digest%% *}"
  # shellcheck disable=SC2016
  replace_json_file "$acceptance/obi-metric-boundary-index.json" \
    '(.boundaries[] | select(.id == "pressure").captures) += [{
      id: "pressure-pressured",
      kind: "phase",
      state: "captured",
      identity_reference: "phases/pressure-pressured/obi-identity.json",
      identity_sha256: $digest
    }]' --arg digest "$digest"
  sync_v3_index_envelopes "$acceptance"
  "$verifier" --raw-v3 acceptance "$acceptance" >/dev/null
  printf '%s\n' \
    'obi_java_remote_parent_operations_total{credential="TOPSECRET"} 1' \
    >>"$acceptance/$metrics_reference"
  digest="$(sha256sum <"$acceptance/$metrics_reference")"
  digest="${digest%% *}"
  # shellcheck disable=SC2016
  replace_json_file "$acceptance/$reference" \
    '.metrics_sha256 = $digest' --arg digest "$digest"
  digest="$(sha256sum <"$acceptance/$reference")"
  digest="${digest%% *}"
  # shellcheck disable=SC2016
  replace_json_file "$acceptance/obi-metric-boundary-index.json" \
    '(.boundaries[].captures[] |
      select(.kind == "phase" and .identity_reference == $reference) |
      .identity_sha256) = $digest' \
    --arg reference "$reference" --arg digest "$digest"
  sync_v3_index_envelopes "$acceptance"
  expect_external_v3_rejection \
    'raw v3 phase-only identity metrics with an unallowlisted label' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  # shellcheck disable=SC2016
  replace_json_file "$acceptance/obi-metric-boundary-index.json" '
    (.boundaries[] | select(.id == "basic") | .captures) as $basic |
    (.boundaries[] | select(.id == "keepalive") | .captures) as $keepalive |
    (.boundaries[] | select(.id == "basic") | .captures) = $keepalive |
    (.boundaries[] | select(.id == "keepalive") | .captures) = $basic
  '
  sync_v3_index_envelopes "$acceptance"
  expect_external_v3_rejection \
    'raw v3 pair captures assigned to the wrong producer boundaries' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  rewire_raw_stress_pair_authority_fixture "$acceptance"
  expect_external_v3_rejection \
    'raw v3 keepalive pair coherently rewired to the basic metric phases' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-basic.json" '
    (.cases[0].trace.spans[] | select(.service_name == "java-backend")).flags = 513
  '
  expect_external_v3_rejection \
    'raw v3 Java parent without the parent-remote-known bit' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/scenario-timeout-retry.json" '
    .faults[0].parent_outcome = "reason_coded_drop" |
    .faults[0].drop_reasons = ["future_reason"]
  '
  replace_json_file "$acceptance/scenario-timeout-retry-status.json" '
    .scenario_reconciliation.parent_outcome = "reason_coded_drop" |
    .scenario_reconciliation.drop_reasons = ["future_reason"]
  '
  expect_external_v3_rejection \
    'raw v3 timeout evidence with an unallowlisted reason' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file "$acceptance/map-pressure-pressure-fill.json" \
    '.capacity_rejected_entries = 0'
  expect_external_v3_rejection \
    'raw v3 pressure evidence without capacity rejection' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  mutate_raw_pressure_capacity_fixture "$acceptance"
  expect_external_v3_rejection \
    'raw v3 pressure evidence with a coherent non-producer map capacity' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"

  replace_json_file \
    "$acceptance/receive-cursor-map-tls-boundary-after.json" \
    '.cursor_entries = 1'
  expect_external_v3_rejection \
    'raw v3 receive coordination that did not return to baseline' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"
  mkdir -- "$acceptance/unexpected-empty-directory"
  expect_external_v3_rejection \
    'raw v3 evidence with an empty unjournaled directory' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"
  printf 'must not be accepted as evidence\n' >"$acceptance/unexpected-private.log"
  expect_external_v3_rejection \
    'raw v3 evidence with an unexpected regular file' \
    "$verifier" --raw-v3 acceptance "$acceptance"
  restore_external_v3_fixture "$acceptance" "$acceptance_baseline"
  "$verifier" --raw-v3 acceptance "$acceptance" >/dev/null

  create_raw_v3_assertion_fixture "$repository" "$revision" "$assertion"
  "$verifier" --raw-v3 assertion-failure "$assertion" >/dev/null
  test_raw_verifier_cleanup_guards "$verifier" "$assertion"
  cp -a -- "$assertion" "$assertion_baseline"
  printf 'unexpected=retained\n' >>"$assertion/failure-context.txt"
  expect_external_v3_rejection \
    'raw v3 assertion context with an extra control field' \
    "$verifier" --raw-v3 assertion-failure "$assertion"
  restore_external_v3_fixture "$assertion" "$assertion_baseline"
  "$verifier" --raw-v3 assertion-failure "$assertion" >/dev/null

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
  assert_no_invalid_jq_generator_binders
  assert_jq_generator_context_semantics
  umask 022
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
  test_raw_v3_mode \
    "$repository" "$fixture_verifier" "$source_revision"

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

  printf 'verify-retained-evidence v2/v3 raw and current-code tests passed\n'
}

main "$@"
