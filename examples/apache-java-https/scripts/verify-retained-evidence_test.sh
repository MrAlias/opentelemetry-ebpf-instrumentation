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

  for command_name in chmod cp find git jq mkdir mktemp mv rm sha256sum sort; do
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
    'scenario=all' \
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

main() {
  local -r evidence_id='synthetic-current-code'
  local repository=""
  local fixture_verifier=""
  local bundle=""
  local baseline=""
  local source_revision=""
  local rejection_output=""

  check_dependencies
  [[ -x "$VERIFIER" ]] || die "verifier is not executable: $VERIFIER"
  TEST_TMP_DIR="$(mktemp -d)"
  repository="$TEST_TMP_DIR/repository"
  fixture_verifier="$repository/examples/apache-java-https/scripts/verify-retained-evidence.sh"
  bundle="$repository/examples/apache-java-https/evidence/$evidence_id"
  baseline="$TEST_TMP_DIR/valid-v2-bundle"

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

  printf 'verify-retained-evidence v2 and current-code tests passed\n'
}

main "$@"
