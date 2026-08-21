#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077
export LC_ALL=C

TEST_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TEST_DIRECTORY
CAMPAIGN_DIRECTORY="$(cd -- "$TEST_DIRECTORY/.." && pwd -P)"
readonly CAMPAIGN_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$CAMPAIGN_DIRECTORY/lib.sh"

TEST_ROOT=""
SOURCE_AUTHORITY=""
SOURCE_AUTHORITY_SHA256=""
PLAN=""
PLAN_SHA256=""
DRIVER=""
DRIVER_SHA256=""
EXECUTOR_REGISTRY=""
EXECUTOR_REGISTRY_SHA256=""
CASE_ROOT=""
CASE_CELL=""
CASE_EXECUTOR=""
CASE_DESCRIPTOR=""
CASE_DESCRIPTOR_SHA256=""
PASS_CELL_ROOT=""

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  return 1
}

report_unhandled_error() {
  local -r line="$1"
  local -r status="$2"

  printf 'FAIL: lifecycle driver test stopped at line %s with status %s\n' \
    "$line" "$status" >&2
}

write_scratch_aba_jq_shim() {
  local -r shim="$1"

  cat >"$shim" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
matched=""
for argument in "$@"; do
  if [[ "$argument" == /proc/self/fd/*/* &&
    "$argument" == *"$OBI_SCRATCH_ABA_MATCH"* ]]; then
    matched="$argument"
    break
  fi
done
if [[ -n "$matched" ]] &&
  (set -o noclobber; : >"$OBI_SCRATCH_ABA_DONE") 2>/dev/null; then
  remainder="${matched#/proc/self/fd/}"
  descriptor="${remainder%%/*}"
  [[ "$descriptor" =~ ^[1-9][0-9]*$ ]]
  authority="$(readlink -- "/proc/self/fd/$descriptor")"
  [[ "$authority" == /* && -d "$authority" && ! -L "$authority" ]]
  mv -- "$authority" "$authority.authority"
  install -d -m 0700 -- "$authority"
  relative="${matched#"/proc/self/fd/$descriptor/./"}"
  install -d -m 0700 -- "$authority/$(dirname -- "$relative")"
  printf '{"authority":"foreign"}\n' >"$authority/$relative"
  chmod 0600 -- "$authority/$relative"
  set +e
  "$OBI_REAL_JQ" "$@"
  status=$?
  set -e
  mv -- "$authority" "$OBI_SCRATCH_ABA_SINK"
  mv -- "$authority.authority" "$authority"
  exit "$status"
fi
exec "$OBI_REAL_JQ" "$@"
SH
  chmod 0700 -- "$shim"
}

if [[ "${OBI_COMPATIBILITY_TEST_DEBUG:-}" == true ]]; then
  trap 'report_unhandled_error "$LINENO" "$?"' ERR
fi

prepare_environment() {
  local -r label="$1"
  local -r cell_id="$2"
  local -r descriptor_mutation="${3:-none}"
  local descriptor_candidate=""
  local executor_sha256=""

  CASE_ROOT="$TEST_ROOT/$label"
  CASE_CELL="$CASE_ROOT/requested.json"
  CASE_EXECUTOR="$CAMPAIGN_DIRECTORY/tests/lifecycle-environment-fixture.sh"
  CASE_DESCRIPTOR="$CASE_ROOT/environment.json"
  install -d -m 0700 -- "$CASE_ROOT"
  jq -eS --arg id "$cell_id" '
    [.cells[] | select(.id == $id)] |
    if length == 1 then .[0] else empty end
  ' "$PLAN" >"$CASE_CELL"
  chmod 0600 -- "$CASE_CELL"
  executor_sha256="$(compatibility_sha256 "$CASE_EXECUTOR")"
  jq -nS \
    --arg id "fixture-$label" \
    --arg executor_sha256 "$executor_sha256" \
    --slurpfile cell "$CASE_CELL" '{
      schema:"compatibility-helper-lifecycle-environment-v1",
      id:$id,
      cell:$cell[0],
      executor:{
        id:"synthetic-lifecycle-executor-v1",
        path:"tests/lifecycle-environment-fixture.sh",
        sha256:$executor_sha256
      }
    }' >"$CASE_DESCRIPTOR"
  case "$descriptor_mutation" in
    none) ;;
    wrong-cell)
      descriptor_candidate="$CASE_DESCRIPTOR.new"
      jq -S '.cell.id="h-jdk17-amd64-otel-getsockopt"' \
        "$CASE_DESCRIPTOR" >"$descriptor_candidate"
      mv -fT -- "$descriptor_candidate" "$CASE_DESCRIPTOR"
      ;;
    wrong-transport)
      descriptor_candidate="$CASE_DESCRIPTOR.new"
      jq -S '.cell.transport="unix"' "$CASE_DESCRIPTOR" >"$descriptor_candidate"
      mv -fT -- "$descriptor_candidate" "$CASE_DESCRIPTOR"
      ;;
    wrong-jdk)
      descriptor_candidate="$CASE_DESCRIPTOR.new"
      jq -S '.cell.jvm_feature=17' "$CASE_DESCRIPTOR" >"$descriptor_candidate"
      mv -fT -- "$descriptor_candidate" "$CASE_DESCRIPTOR"
      ;;
    wrong-arch)
      descriptor_candidate="$CASE_DESCRIPTOR.new"
      jq -S '.cell.architecture="arm64"' "$CASE_DESCRIPTOR" >"$descriptor_candidate"
      mv -fT -- "$descriptor_candidate" "$CASE_DESCRIPTOR"
      ;;
    wrong-executor-path)
      descriptor_candidate="$CASE_DESCRIPTOR.new"
      jq -S '.executor.path="tests/lifecycle-executor-missing.sh"' \
        "$CASE_DESCRIPTOR" >"$descriptor_candidate"
      mv -fT -- "$descriptor_candidate" "$CASE_DESCRIPTOR"
      ;;
    wrong-executor-id)
      descriptor_candidate="$CASE_DESCRIPTOR.new"
      jq -S '.executor.id="unapproved-lifecycle-executor"' \
        "$CASE_DESCRIPTOR" >"$descriptor_candidate"
      mv -fT -- "$descriptor_candidate" "$CASE_DESCRIPTOR"
      ;;
    wrong-executor-hash)
      descriptor_candidate="$CASE_DESCRIPTOR.new"
      jq -S '.executor.sha256=("0" * 64)' \
        "$CASE_DESCRIPTOR" >"$descriptor_candidate"
      mv -fT -- "$descriptor_candidate" "$CASE_DESCRIPTOR"
      ;;
    *) fail "unknown descriptor mutation: $descriptor_mutation" ;;
  esac
  chmod 0600 -- "$CASE_DESCRIPTOR"
  CASE_DESCRIPTOR_SHA256="$(compatibility_sha256 "$CASE_DESCRIPTOR")"
}

invoke_driver_direct() {
  local -r label="$1"
  local -r mode="$2"
  local private="$CASE_ROOT/private-$label"
  local status=0

  install -d -m 0700 -- "$private"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT="$CASE_DESCRIPTOR" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256="$CASE_DESCRIPTOR_SHA256" \
    OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY="$EXECUTOR_REGISTRY" \
    OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SHA256="$EXECUTOR_REGISTRY_SHA256" \
    OBI_COMPATIBILITY_LIFECYCLE_FIXTURE_MODE="$mode" \
    "$DRIVER" \
      --contract compatibility-external-provider-v1 \
      --campaign helper-lifecycle \
      --campaign-revision apache-java-https-helper-lifecycle-v1 \
      --plan-sha256 "$PLAN_SHA256" \
      --cell "$CASE_CELL" \
      --source-authority "$SOURCE_AUTHORITY" \
      --source-authority-sha256 "$SOURCE_AUTHORITY_SHA256" \
      --private-output "$private" \
      >"$CASE_ROOT/direct-$label.stdout" \
      2>"$CASE_ROOT/direct-$label.stderr"
  status=$?
  set -e
  printf '%s\n' "$status"
}

run_cell() {
  local -r label="$1"
  local -r cell_id="$2"
  local -r mode="$3"
  local output="$CASE_ROOT/cell-$label"
  local status=0

  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$DRIVER" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$DRIVER_SHA256" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT="$CASE_DESCRIPTOR" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256="$CASE_DESCRIPTOR_SHA256" \
    OBI_COMPATIBILITY_LIFECYCLE_FIXTURE_MODE="$mode" \
    "$CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell "$cell_id" \
      --source-authority "$SOURCE_AUTHORITY" \
      --output "$output" \
      >"$CASE_ROOT/run-$label.stdout" \
      2>"$CASE_ROOT/run-$label.stderr"
  status=$?
  set -e
  printf '%s\n' "$status"
}

test_all_seven_cells() {
  local cell_id=""
  local status=""
  local output=""

  PASS_CELL_ROOT="$TEST_ROOT/collector-cells"
  install -d -m 0700 -- "$PASS_CELL_ROOT"

  while IFS= read -r cell_id; do
    prepare_environment "pass-$cell_id" "$cell_id"
    status="$(run_cell pass "$cell_id" pass)"
    if [[ "$status" != 0 ]]; then
      printf '%s\n' '--- lifecycle run stderr ---' >&2
      tail -c 32768 -- "$CASE_ROOT/run-pass.stderr" >&2 || true
      printf '%s\n' '--- lifecycle run stdout ---' >&2
      tail -c 32768 -- "$CASE_ROOT/run-pass.stdout" >&2 || true
      if [[ -f "$CASE_ROOT/cell-pass/cell.json" ]]; then
        jq -cS '{status,reason,assertions,provider}' \
          "$CASE_ROOT/cell-pass/cell.json" >&2 || true
      fi
      if [[ -f "$CASE_ROOT/cell-pass/private/external-provider.stderr" ]]; then
        printf '%s\n' '--- external driver stderr ---' >&2
        tail -c 32768 -- \
          "$CASE_ROOT/cell-pass/private/external-provider.stderr" >&2 || true
      fi
      if [[ -f "$CASE_ROOT/cell-pass/private/provider-contract-evidence/external-provider.stderr" ]]; then
        printf '%s\n' '--- retained external driver stderr ---' >&2
        tail -c 32768 -- \
          "$CASE_ROOT/cell-pass/private/provider-contract-evidence/external-provider.stderr" >&2 || true
      fi
      fail "$cell_id synthetic lifecycle contract did not pass sealing"
    fi
    output="$CASE_ROOT/cell-pass"
    jq -e \
      --arg cell_id "$cell_id" \
      --arg driver_sha256 "$DRIVER_SHA256" '
        .status == "pass" and .cell_id == $cell_id and
        .provider.external_driver == {
          id:"source-lifecycle-application-driver-v1",
          sha256:$driver_sha256
        } and
        .provider.lifecycle_executor.schema ==
          "compatibility-lifecycle-executor-authority-v1" and
        .provider.lifecycle_executor.approval.id ==
          "synthetic-lifecycle-executor-v1" and
        .provider.lifecycle_executor.approval.path ==
          "tests/lifecycle-environment-fixture.sh" and
        .provider.lifecycle_executor.command.argv[0] == "/proc/self/fd/9" and
        ([.evidence_index[].field] |
          index("lifecycle_executor.receipt_sha256") != null) and
        (.assertions.lifecycle | keys | length) == 16 and
        (.assertions.resource_gates | keys | length) == 8 and
        .assertions.unavailable_bridge.result_equivalent == true
      ' "$output/cell.json" >/dev/null ||
      fail "$cell_id sealed result lost lifecycle or driver identity"
    mv -T -- "$output" "$PASS_CELL_ROOT/$cell_id"
  done <"$CAMPAIGN_DIRECTORY/expected-helper-cell-ids.txt"
}

test_collector_inner_reapproval() {
  local aggregate="$TEST_ROOT/collector-aggregate"
  local identities="$TEST_ROOT/collector-inner-identities.jsonl"
  local mutated="$TEST_ROOT/collector-inner-identities.mutated.jsonl"
  local shim_directory="$TEST_ROOT/collector-scratch-aba-bin"
  local shim="$shim_directory/jq"
  local mutation_done="$TEST_ROOT/collector-scratch-aba.done"
  local mutation_sink="$TEST_ROOT/collector-scratch-aba.foreign"
  local registry_sha256=""
  local approval=""

  install -d -m 0700 -- "$shim_directory"
  write_scratch_aba_jq_shim "$shim"
  PATH="$shim_directory:$PATH" \
    OBI_REAL_JQ="$(command -v jq)" \
    OBI_SCRATCH_ABA_MATCH=\
"input-h-jdk11-amd64-otel-getsockopt/private/provider-result.json" \
    OBI_SCRATCH_ABA_DONE="$mutation_done" \
    OBI_SCRATCH_ABA_SINK="$mutation_sink" \
    "$CAMPAIGN_DIRECTORY/collect.sh" \
    --campaign helper-lifecycle \
    --input-root "$PASS_CELL_ROOT" \
    --source-authority "$SOURCE_AUTHORITY" \
    --output "$aggregate"
  [[ -f "$mutation_done" &&
    -f "$mutation_sink/input-h-jdk11-amd64-otel-getsockopt/private/provider-result.json" ]] ||
    fail "collector did not exercise its descriptor-pinned scratch ancestor ABA"
  registry_sha256="$(compatibility_sha256 "$EXECUTOR_REGISTRY")"
  jq -e --arg sha256 "$registry_sha256" '
    .schema == "helper-lifecycle-aggregate-v1" and
    .lifecycle_executor_registry_sha256 == $sha256 and
    .status_counts.pass == 7 and .campaign_state == "complete-passed"
  ' "$aggregate/aggregate.json" >/dev/null ||
    fail "collector lost lifecycle executor registry authority"

  approval="$(jq -cer '.approved_executors[0]' "$EXECUTOR_REGISTRY")"
  jq -cnS \
    --arg cell_id h-jdk21-amd64-otel-getsockopt \
    --arg registry_sha256 "$registry_sha256" \
    --argjson approval "$approval" '{
      cell_id:$cell_id,registry_sha256:$registry_sha256,approval:$approval
    }' >"$identities"
  compatibility_validate_collected_lifecycle_executor_identities \
    "$identities" "$registry_sha256"

  jq -cS '.approval.sha256=("0" * 64)' "$identities" >"$mutated"
  if compatibility_validate_collected_lifecycle_executor_identities \
    "$mutated" "$registry_sha256" >/dev/null 2>&1; then
    fail "collector accepted an unapproved inner executor digest"
  fi
  jq -cS '.cell_id="foreign-lifecycle-cell"' "$identities" >"$mutated"
  if compatibility_validate_collected_lifecycle_executor_identities \
    "$mutated" "$registry_sha256" >/dev/null 2>&1; then
    fail "collector accepted an inner executor outside its cell permission"
  fi
  {
    jq -cS . "$identities"
    jq -cS '.approval.id="mixed-lifecycle-executor"' "$identities"
  } >"$mutated"
  if compatibility_validate_collected_lifecycle_executor_identities \
    "$mutated" "$registry_sha256" >/dev/null 2>&1; then
    fail "collector accepted mixed inner executor identities"
  fi

  compatibility_registry_consumer_hook() {
    local -r kind="$1" phase="$2" registry="$3"
    if [[ "$kind:$phase" == lifecycle:before-reapproval ]]; then
      mv -- "$registry" "$registry.authority"
      cp -p -- "$registry.authority" "$registry"
    elif [[ "$kind:$phase" == lifecycle:after-reapproval ]]; then
      mv -- "$registry" "$TEST_ROOT/lifecycle-reapproval-foreign"
      mv -- "$registry.authority" "$registry"
    fi
  }
  if compatibility_validate_collected_lifecycle_executor_identities \
    "$identities" "$registry_sha256" "$EXECUTOR_REGISTRY" \
    >/dev/null 2>&1; then
    fail "collector accepted lifecycle registry pathname ABA"
  fi
  # shellcheck disable=SC2317 # Restores the production indirect callback.
  compatibility_registry_consumer_hook() { :; }
}

expect_mutated_reseal_failure() {
  local -r label="$1"
  local -r directory="$2"
  local status=0

  rm -f -- "$directory/private.sha256" "$directory/mutated-seal.json"
  compatibility_directory_manifest \
    "$directory/private" "$directory/private.sha256"
  set +e
  "$CAMPAIGN_DIRECTORY/seal-cell.sh" \
    --campaign helper-lifecycle \
    --cell "$directory/private/requested.json" \
    --provider-result "$directory/private/provider-result.json" \
    --provider-launcher \
      "$CAMPAIGN_DIRECTORY/providers/preprovisioned-lifecycle-application-v1.sh" \
    --private-directory "$directory/private" \
    --private-manifest "$directory/private.sha256" \
    --output "$directory/mutated-seal.json" \
    >"$directory/mutated-seal.stdout" 2>"$directory/mutated-seal.stderr"
  status=$?
  set -e
  [[ "$status" != 0 && ! -e "$directory/mutated-seal.json" ]] ||
    fail "$label mutation was resealed"
}

test_sealer_inner_authority_mutations() {
  local -r source_cell=h-jdk21-amd64-otel-getsockopt
  local directory=""
  local result=""
  local candidate=""
  local raw=""
  local raw_manifest=""
  local receipt=""
  local receipt_sha256=""

  directory="$TEST_ROOT/mutated-inner-digest"
  cp -a -- "$PASS_CELL_ROOT/$source_cell" "$directory"
  result="$directory/private/provider-result.json"
  candidate="$result.new"
  jq -S '.lifecycle_executor.approval.sha256=("0" * 64)' \
    "$result" >"$candidate"
  mv -fT -- "$candidate" "$result"
  expect_mutated_reseal_failure unapproved-inner-digest "$directory"

  directory="$TEST_ROOT/mutated-inner-cell-permission"
  cp -a -- "$PASS_CELL_ROOT/$source_cell" "$directory"
  result="$directory/private/provider-result.json"
  candidate="$result.new"
  jq -S --arg cell_id "$source_cell" '
    .lifecycle_executor.approval.allowed_cell_ids -= [$cell_id]
  ' "$result" >"$candidate"
  mv -fT -- "$candidate" "$result"
  expect_mutated_reseal_failure inner-cell-permission "$directory"

  directory="$TEST_ROOT/mutated-inner-argv"
  cp -a -- "$PASS_CELL_ROOT/$source_cell" "$directory"
  result="$directory/private/provider-result.json"
  candidate="$result.new"
  jq -S '.lifecycle_executor.command.argv[0]="fabricated-executor"' \
    "$result" >"$candidate"
  mv -fT -- "$candidate" "$result"
  expect_mutated_reseal_failure inner-exact-argv "$directory"

  directory="$TEST_ROOT/mutated-inner-receipt"
  cp -a -- "$PASS_CELL_ROOT/$source_cell" "$directory"
  result="$directory/private/provider-result.json"
  candidate="$result.new"
  raw="$directory/private/external/environment-output/raw"
  raw_manifest="$directory/private/external/environment-output/raw.sha256"
  receipt="$raw/lifecycle-execution-receipt.json"
  jq -S '.requested_cell_id="foreign-lifecycle-cell"' \
    "$receipt" >"$receipt.new"
  mv -fT -- "$receipt.new" "$receipt"
  receipt_sha256="$(compatibility_sha256 "$receipt")"
  jq -S --arg sha256 "$receipt_sha256" '
    .lifecycle_executor.receipt_sha256=$sha256 |
    .evidence_index |= map(
      if .field == "lifecycle_executor.receipt_sha256"
      then .sha256=$sha256 else . end)
  ' "$result" >"$candidate"
  mv -fT -- "$candidate" "$result"
  rm -f -- "$raw_manifest"
  compatibility_directory_manifest "$raw" "$raw_manifest"
  jq -S --arg sha256 "$(compatibility_sha256 "$raw_manifest")" '
    .raw_evidence.manifest_sha256=$sha256
  ' "$result" >"$candidate"
  mv -fT -- "$candidate" "$result"
  expect_mutated_reseal_failure contradictory-inner-receipt "$directory"
}

test_sealer_pinned_scratch_ancestor_aba() {
  local -r source_cell=h-jdk21-amd64-otel-getsockopt
  local directory="$TEST_ROOT/sealer-scratch-aba"
  local shim_directory="$TEST_ROOT/sealer-scratch-aba-bin"
  local shim="$shim_directory/jq"
  local mutation_done="$TEST_ROOT/sealer-scratch-aba.done"
  local mutation_sink="$TEST_ROOT/sealer-scratch-aba.foreign"
  local provider_registry="$CAMPAIGN_DIRECTORY/provider-registry-v1.json"
  local provider_registry_identity=""
  local executor_registry_identity=""

  cp -a -- "$PASS_CELL_ROOT/$source_cell" "$directory"
  install -d -m 0700 -- "$shim_directory"
  write_scratch_aba_jq_shim "$shim"
  provider_registry_identity="$(compatibility_stable_file_identity \
    "$provider_registry" 67108864)" || return
  executor_registry_identity="$(compatibility_stable_file_identity \
    "$EXECUTOR_REGISTRY" 67108864)" || return
  PATH="$shim_directory:$PATH" \
    OBI_REAL_JQ="$(command -v jq)" \
    OBI_SCRATCH_ABA_MATCH="private.snapshot/provider-result.json" \
    OBI_SCRATCH_ABA_DONE="$mutation_done" \
    OBI_SCRATCH_ABA_SINK="$mutation_sink" \
    "$CAMPAIGN_DIRECTORY/seal-cell.sh" \
      --campaign helper-lifecycle \
      --cell "$directory/private/requested.json" \
      --provider-result "$directory/private/provider-result.json" \
      --provider-launcher \
        "$CAMPAIGN_DIRECTORY/providers/preprovisioned-lifecycle-application-v1.sh" \
      --private-directory "$directory/private" \
      --private-manifest "$directory/private.sha256" \
      --provider-registry-snapshot "$provider_registry" \
      --provider-registry-snapshot-identity "$provider_registry_identity" \
      --provider-registry-source-identity "$provider_registry_identity" \
      --lifecycle-executor-registry-snapshot "$EXECUTOR_REGISTRY" \
      --lifecycle-executor-registry-snapshot-identity \
        "$executor_registry_identity" \
      --lifecycle-executor-registry-source-identity \
        "$executor_registry_identity" \
      --output "$directory/resealed.json"
  [[ -f "$mutation_done" &&
    -f "$mutation_sink/private.snapshot/provider-result.json" ]] ||
    fail "sealer did not exercise its descriptor-pinned scratch ancestor ABA"
  cmp -s -- "$directory/cell.json" "$directory/resealed.json" ||
    fail "sealer scratch ancestor ABA changed its pinned evidence result"
}

test_each_lifecycle_and_resource_gate() {
  local -r cell_id=h-jdk21-amd64-otel-getsockopt
  local gate=""
  local status=""
  local -a lifecycle_gates=(
    normal-extraction fallback-context-unavailable platform-thread executor-handoff
    cross-thread-handoff cross-request-isolation duplicate-callback stale-state
    helper-early-attach helper-late-attach obi-absent unsupported-transport
    obi-restart version-mismatch extension-absent extension-loaded-first
  )
  local -a resource_gates=(
    native-fd live-thread direct-buffer classloader-weak-reference request-state
    task-state thread-local-state same-process-identity
  )

  for gate in "${lifecycle_gates[@]}"; do
    prepare_environment "lifecycle-$gate" "$cell_id"
    status="$(invoke_driver_direct "$gate" "lifecycle-fail:$gate")"
    [[ "$status" == 1 ]] || fail "mutated lifecycle gate was accepted: $gate"
    [[ ! -e "$CASE_ROOT/private-$gate/provider-result.json" ]] ||
      fail "mutated lifecycle gate published a provider result: $gate"
  done
  for gate in "${resource_gates[@]}"; do
    prepare_environment "resource-leak-$gate" "$cell_id"
    status="$(invoke_driver_direct "leak-$gate" "resource-leak:$gate")"
    [[ "$status" == 1 ]] || fail "resource leak was accepted: $gate"
    prepare_environment "resource-trend-$gate" "$cell_id"
    status="$(invoke_driver_direct "trend-$gate" "resource-trend:$gate")"
    [[ "$status" == 1 ]] || fail "resource trend was accepted: $gate"
  done
}

test_dimension_and_environment_boundaries() {
  local -r cell_id=h-jdk21-amd64-otel-getsockopt
  local mutation=""
  local status=""
  local private=""

  for mutation in wrong-cell wrong-transport wrong-jdk wrong-arch; do
    prepare_environment "output-$mutation" "$cell_id"
    status="$(invoke_driver_direct "$mutation" "$mutation")"
    [[ "$status" == 1 ]] || fail "contradictory executor output was accepted: $mutation"
    prepare_environment "descriptor-$mutation" "$cell_id" "$mutation"
    status="$(invoke_driver_direct "descriptor-$mutation" pass)"
    [[ "$status" == 69 ]] || fail "mismatched environment was not untested: $mutation"
    private="$CASE_ROOT/private-descriptor-$mutation/provider-result.json"
    jq -e '.status == "untested" and .reason == "lifecycle-environment-cell-mismatch"' \
      "$private" >/dev/null || fail "mismatched environment inferred a product result: $mutation"
  done
  for mutation in wrong-executor-path wrong-executor-hash wrong-executor-id; do
    prepare_environment "descriptor-$mutation" "$cell_id" "$mutation"
    status="$(invoke_driver_direct "descriptor-$mutation" pass)"
    [[ "$status" == 69 ]] || fail "$mutation was not infrastructure untested"
    jq -e '.status == "untested" and .reason == "lifecycle-executor-not-approved"' \
      "$CASE_ROOT/private-descriptor-$mutation/provider-result.json" >/dev/null
  done
  prepare_environment environment-hash "$cell_id"
  CASE_DESCRIPTOR_SHA256="$(printf '%064d' 0)"
  status="$(invoke_driver_direct environment-hash pass)"
  [[ "$status" == 69 ]] || fail "wrong environment hash was not untested"
}

test_result_and_diagnostic_boundaries() {
  local -r cell_id=h-jdk21-amd64-otel-getsockopt
  local mode=""
  local status=""

  for mode in lying-argv result-different diagnostic-count diagnostic-bytes malformed; do
    prepare_environment "result-$mode" "$cell_id"
    status="$(invoke_driver_direct "$mode" "$mode")"
    [[ "$status" == 1 ]] || fail "malformed or contradictory result was accepted: $mode"
    [[ ! -e "$CASE_ROOT/private-$mode/provider-result.json" ]] ||
      fail "malformed or contradictory result published: $mode"
  done
}

test_no_inferred_pass_and_identity_boundaries() {
  local -r cell_id=h-jdk21-amd64-otel-getsockopt
  local status=""
  local output=""
  local copied_driver="$TEST_ROOT/copied-lifecycle-driver.sh"

  prepare_environment missing-environment "$cell_id"
  output="$CASE_ROOT/cell-missing-environment"
  set +e
  env \
    -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER \
    -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256 \
    -u OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT \
    -u OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256 \
    "$CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle --cell "$cell_id" \
      --source-authority "$SOURCE_AUTHORITY" --output "$output"
  status=$?
  set -e
  [[ "$status" == 69 ]] || fail "missing preprovisioned environment was not untested"
  jq -e --arg sha256 "$DRIVER_SHA256" '
    .status == "untested" and
    .reason == "lifecycle-environment-unavailable" and
    .provider.external_driver == {
      id:"source-lifecycle-application-driver-v1",sha256:$sha256
    }
  ' "$output/cell.json" >/dev/null || fail "missing environment inferred a pass"

  prepare_environment executed-untested "$cell_id"
  status="$(run_cell executed-untested "$cell_id" untested)"
  [[ "$status" == 69 ]] || fail "executed infrastructure untested was not preserved"
  jq -e '.status == "untested" and .provider.command.executed == true' \
    "$CASE_ROOT/cell-executed-untested/cell.json" >/dev/null
  jq -e '
    .provider.lifecycle_executor.approval.id ==
      "synthetic-lifecycle-executor-v1" and
    .provider.lifecycle_executor.command.exit_status == 69 and
    .evidence_index == [{
      field:"lifecycle_executor.receipt_sha256",
      path:"lifecycle-execution-receipt.json",
      sha256:.provider.lifecycle_executor.receipt_sha256
    }]
  ' "$CASE_ROOT/cell-executed-untested/cell.json" >/dev/null

  install -m 0500 -- "$DRIVER" "$copied_driver"
  prepare_environment wrong-driver-path "$cell_id"
  output="$CASE_ROOT/cell-wrong-driver-path"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$copied_driver" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$DRIVER_SHA256" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT="$CASE_DESCRIPTOR" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256="$CASE_DESCRIPTOR_SHA256" \
    "$CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle --cell "$cell_id" \
      --source-authority "$SOURCE_AUTHORITY" --output "$output"
  status=$?
  set -e
  [[ "$status" == 69 ]] || fail "same-digest driver at foreign path was executed"
  jq -e '.status == "untested" and .reason == "external-provider-not-approved"' \
    "$output/cell.json" >/dev/null

  prepare_environment wrong-driver-hash "$cell_id"
  output="$CASE_ROOT/cell-wrong-driver-hash"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$DRIVER" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$(printf '%064d' 0)" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT="$CASE_DESCRIPTOR" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256="$CASE_DESCRIPTOR_SHA256" \
    "$CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle --cell "$cell_id" \
      --source-authority "$SOURCE_AUTHORITY" --output "$output"
  status=$?
  set -e
  [[ "$status" == 69 ]] || fail "wrong registered driver digest was executed"

  prepare_environment executor-snapshot-aba "$cell_id"
  status="$(run_cell executor-snapshot-aba "$cell_id" swap-open-snapshot)"
  [[ "$status" == 1 ]] || fail "executor snapshot ABA did not fail closed"
  jq -e '.status == "fail" and .assertions.classification == "provider-contract"' \
    "$CASE_ROOT/cell-executor-snapshot-aba/cell.json" >/dev/null ||
    fail "executor snapshot ABA was not retained as a contract failure"

  prepare_environment malformed-full "$cell_id"
  status="$(run_cell malformed-full "$cell_id" malformed)"
  [[ "$status" == 1 ]] || fail "malformed executed output did not fail closed"
  jq -e '.status == "fail" and .assertions.classification == "provider-contract"' \
    "$CASE_ROOT/cell-malformed-full/cell.json" >/dev/null
}

test_empty_registry_and_process_containment() {
  local -r cell_id=h-jdk21-amd64-otel-getsockopt
  local empty_registry_root="$TEST_ROOT/empty-inner-registry"
  local empty_registry="$empty_registry_root/lifecycle-executor-registry-v1.json"
  local empty_registry_sha=""
  local saved_registry="$TEST_ROOT/lifecycle-executor-registry.saved"
  local status=""
  local escaped_pid=""

  prepare_environment production-empty-registry "$cell_id"
  install -d -m 0700 -- "$empty_registry_root"
  printf '{"approved_executors":[],"schema":"compatibility-lifecycle-executor-registry-v1"}\n' \
    >"$empty_registry"
  chmod 0600 -- "$empty_registry"
  empty_registry_sha="$(compatibility_sha256 "$empty_registry")"
  install -d -m 0700 -- "$CASE_ROOT/private-empty-registry"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT="$CASE_DESCRIPTOR" \
    OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256="$CASE_DESCRIPTOR_SHA256" \
    OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY="$empty_registry" \
    OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SHA256="$empty_registry_sha" \
    "$DRIVER" \
      --contract compatibility-external-provider-v1 \
      --campaign helper-lifecycle \
      --campaign-revision apache-java-https-helper-lifecycle-v1 \
      --plan-sha256 "$PLAN_SHA256" \
      --cell "$CASE_CELL" \
      --source-authority "$SOURCE_AUTHORITY" \
      --source-authority-sha256 "$SOURCE_AUTHORITY_SHA256" \
      --private-output "$CASE_ROOT/private-empty-registry" \
      >"$CASE_ROOT/empty-registry.stdout" 2>"$CASE_ROOT/empty-registry.stderr"
  status=$?
  set -e
  [[ "$status" == 69 ]] || fail "empty production-shaped executor registry was not untested"
  jq -e '
    .status == "untested" and .reason == "lifecycle-executor-not-approved" and
    .lifecycle_executor == null
  ' "$CASE_ROOT/private-empty-registry/provider-result.json" >/dev/null ||
    fail "empty executor registry inferred an execution result"

  prepare_environment disallowed-cell "$cell_id"
  cp -p -- "$EXECUTOR_REGISTRY" "$saved_registry"
  jq -S --arg cell_id "$cell_id" '
    .approved_executors[0].allowed_cell_ids -= [$cell_id]
  ' "$EXECUTOR_REGISTRY" >"$EXECUTOR_REGISTRY.new"
  mv -fT -- "$EXECUTOR_REGISTRY.new" "$EXECUTOR_REGISTRY"
  EXECUTOR_REGISTRY_SHA256="$(compatibility_sha256 "$EXECUTOR_REGISTRY")"
  status="$(invoke_driver_direct disallowed-cell pass)"
  mv -fT -- "$saved_registry" "$EXECUTOR_REGISTRY"
  EXECUTOR_REGISTRY_SHA256="$(compatibility_sha256 "$EXECUTOR_REGISTRY")"
  [[ "$status" == 69 ]] || fail "executor ran outside its approved cell roster"
  jq -e '.reason == "lifecycle-executor-not-approved"' \
    "$CASE_ROOT/private-disallowed-cell/provider-result.json" >/dev/null

  prepare_environment setsid-escape "$cell_id"
  status="$(invoke_driver_direct setsid-escape setsid-escape)"
  [[ "$status" == 1 ]] || fail "setsid descendant escape was accepted"
  [[ ! -e "$CASE_ROOT/private-setsid-escape/provider-result.json" ]] ||
    fail "setsid descendant escape published a provider result"
  escaped_pid="$(<"$CASE_ROOT/private-setsid-escape/environment-output/escaped-descendant.pid")"
  [[ "$escaped_pid" =~ ^[1-9][0-9]*$ ]] || fail "setsid fixture did not record its child"
  if kill -0 "$escaped_pid" 2>/dev/null; then
    fail "setsid descendant survived lifecycle containment cleanup"
  fi

  prepare_environment delayed-double-fork-setsid-escape "$cell_id"
  status="$(invoke_driver_direct delayed-double-fork-setsid-escape \
    delayed-double-fork-setsid-escape)"
  [[ "$status" == 1 ]] ||
    fail "delayed double-fork setsid descendant escape was accepted"
  [[ ! -e \
    "$CASE_ROOT/private-delayed-double-fork-setsid-escape/provider-result.json" ]] ||
    fail "delayed double-fork escape published a provider result"
  escaped_pid="$(<"$CASE_ROOT/private-delayed-double-fork-setsid-escape/environment-output/escaped-descendant.pid")"
  [[ "$escaped_pid" =~ ^[1-9][0-9]*$ ]] ||
    fail "delayed double-fork fixture did not record its child"
  if kill -0 "$escaped_pid" 2>/dev/null; then
    fail "delayed double-fork setsid descendant survived lifecycle cleanup"
  fi
}

test_executor_preopen_type_and_identity_boundaries() {
  local root="$TEST_ROOT/executor-preopen"
  local original="$root/original-executor"
  local candidate=""
  local expected_identity=""
  local status=0

  install -d -m 0700 -- "$root/work"
  install -m 0500 -- "$CASE_EXECUTOR" "$original"
  expected_identity="$(compatibility_stable_file_identity "$original" 16777216)" ||
    return

  candidate="$root/fifo-executor"
  mkfifo -m 0500 -- "$candidate"
  set +e
  timeout 5 bash -c '
    set -Eeuo pipefail
    source "$1"
    run_supervised_executor \
      "$2" "$3" "$4" "$5" "$6" /proc/self/fd/9
  ' _ "$DRIVER" "$root/work" "$root/fifo.stdout" "$root/fifo.stderr" \
    "$candidate" "$expected_identity" >/dev/null 2>&1
  status=$?
  set -e
  [[ "$status" != 0 && "$status" != 124 ]] ||
    fail "executor FIFO pre-open either succeeded or blocked"

  candidate="$root/symlink-executor"
  ln -s -- "$original" "$candidate"
  set +e
  timeout 5 bash -c '
    set -Eeuo pipefail
    source "$1"
    run_supervised_executor \
      "$2" "$3" "$4" "$5" "$6" /proc/self/fd/9
  ' _ "$DRIVER" "$root/work" "$root/symlink.stdout" "$root/symlink.stderr" \
    "$candidate" "$expected_identity" >/dev/null 2>&1
  status=$?
  set -e
  [[ "$status" != 0 && "$status" != 124 ]] ||
    fail "executor symlink pre-open either succeeded or blocked"

  candidate="$root/substituted-executor"
  install -m 0500 -- "$CASE_EXECUTOR" "$candidate"
  set +e
  timeout 5 bash -c '
    set -Eeuo pipefail
    source "$1"
    run_supervised_executor \
      "$2" "$3" "$4" "$5" "$6" /proc/self/fd/9
  ' _ "$DRIVER" "$root/work" "$root/regular.stdout" "$root/regular.stderr" \
    "$candidate" "$expected_identity" >/dev/null 2>&1
  status=$?
  set -e
  [[ "$status" != 0 && "$status" != 124 ]] ||
    fail "executor regular-file inode substitution was accepted"
}

test_private_publication_boundaries() {
  local root="$TEST_ROOT/private-publication"
  local hook="$root/publication-hook"

  install -d -m 0700 -- "$root"
  cat >"$hook" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
phase="$1"
path="$2"
case "${OBI_LIFECYCLE_PUBLICATION_MUTATION:-}:$phase" in
  candidate:lifecycle-file-before-rename)
    mv -- "$path" "$path.authentic"
    printf 'foreign candidate bytes\n' >"$path"
    chmod 0600 -- "$path"
    ;;
  target:lifecycle-file-after-rename-final-rehash)
    mv -- "$path" "$path.authentic"
    printf 'foreign target bytes\n' >"$path"
    chmod 0600 -- "$path"
    ;;
  in-place:lifecycle-file-after-rename-final-rehash)
    printf 'foreign in-place bytes\n' >"$path"
    printf 'trusted in-place bytes\n' >"$path"
    chmod 0600 -- "$path"
    ;;
esac
SH
  chmod 0700 -- "$hook"

  bash -c '
    set -Eeuo pipefail
    source "$1"
    root="$2"
    hook="$3"

    printf "trusted normal bytes\n" >"$root/normal.source"
    chmod 0600 -- "$root/normal.source"
    identity="$(safe_file_identity "$root/normal.source" false)"
    publish_private_file_no_replace \
      "$root/normal.source" "$identity" "$root/normal.target"
    [[ ! -e "$root/normal.source" &&
      "$(<"$root/normal.target")" == "trusted normal bytes" ]]

    printf "trusted replacement bytes\n" >"$root/replace.source"
    printf "retired target bytes\n" >"$root/replace.target"
    chmod 0600 -- "$root/replace.source" "$root/replace.target"
    identity="$(safe_file_identity "$root/replace.source" false)"
    old_identity="$(safe_file_identity "$root/replace.target" false)"
    publish_private_file_no_replace \
      "$root/replace.source" "$identity" "$root/replace.target" "$old_identity"
    [[ "$(<"$root/replace.target")" == "trusted replacement bytes" ]]
    ! compgen -G "$root/.compatibility-replaced.lifecycle.*" >/dev/null

    printf "trusted candidate bytes\n" >"$root/candidate.source"
    chmod 0600 -- "$root/candidate.source"
    identity="$(safe_file_identity "$root/candidate.source" false)"
    if OBI_LIFECYCLE_PUBLICATION_MUTATION=candidate \
      publish_private_file_no_replace \
        "$root/candidate.source" "$identity" "$root/candidate.target" "" "$hook";
    then
      exit 31
    fi
    [[ ! -e "$root/candidate.target" &&
      "$(<"$root/candidate.source")" == "foreign candidate bytes" &&
      "$(<"$root/candidate.source.authentic")" == "trusted candidate bytes" ]]

    printf "trusted target bytes\n" >"$root/target.source"
    chmod 0600 -- "$root/target.source"
    identity="$(safe_file_identity "$root/target.source" false)"
    if OBI_LIFECYCLE_PUBLICATION_MUTATION=target \
      publish_private_file_no_replace \
        "$root/target.source" "$identity" "$root/target.target" "" "$hook";
    then
      exit 32
    fi
    [[ "$(<"$root/target.target")" == "foreign target bytes" &&
      "$(<"$root/target.target.authentic")" == "trusted target bytes" ]]

    printf "trusted in-place bytes\n" >"$root/in-place.source"
    chmod 0600 -- "$root/in-place.source"
    identity="$(safe_file_identity "$root/in-place.source" false)"
    if OBI_LIFECYCLE_PUBLICATION_MUTATION=in-place \
      publish_private_file_no_replace \
        "$root/in-place.source" "$identity" "$root/in-place.target" "" "$hook";
    then
      exit 33
    fi
    [[ ! -e "$root/in-place.target" ]]
    retained="$(find "$root" -mindepth 1 -maxdepth 1 -type f \
      -name ".compatibility-rejected.lifecycle.*" \
      -exec grep -lFx "trusted in-place bytes" "{}" \; -print -quit)"
    [[ -n "$retained" ]]
  ' /bin/bash "$DRIVER" "$root" "$hook" ||
    fail "descriptor-bound lifecycle private publication boundary failed"
}

main() {
  local source_status=""

  TEST_ROOT="${1:?test root is required}"
  SOURCE_AUTHORITY="${2:?source authority is required}"
  PLAN="$CAMPAIGN_DIRECTORY/helper-lifecycle-v1.json"
  DRIVER="$CAMPAIGN_DIRECTORY/providers/lifecycle-application-driver-v1.sh"
  EXECUTOR_REGISTRY="$CAMPAIGN_DIRECTORY/lifecycle-executor-registry-v1.json"
  install -d -m 0700 -- "$TEST_ROOT"
  compatibility_validate_source_authority "$SOURCE_AUTHORITY"
  SOURCE_AUTHORITY_SHA256="$(compatibility_sha256 "$SOURCE_AUTHORITY")"
  PLAN_SHA256="$(compatibility_sha256 "$PLAN")"
  DRIVER_SHA256="$(compatibility_sha256 "$DRIVER")"
  EXECUTOR_REGISTRY_SHA256="$(compatibility_sha256 "$EXECUTOR_REGISTRY")"
  source_status="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" status \
    --porcelain=v1 --untracked-files=all)"
  [[ -z "$source_status" ]] || {
    printf 'dirty lifecycle fixture checkout:\n%s\n' "$source_status" >&2
    fail "lifecycle driver fixture requires the captured clean source"
  }
  test_all_seven_cells
  test_collector_inner_reapproval
  test_sealer_inner_authority_mutations
  test_sealer_pinned_scratch_ancestor_aba
  test_each_lifecycle_and_resource_gate
  test_dimension_and_environment_boundaries
  test_result_and_diagnostic_boundaries
  test_no_inferred_pass_and_identity_boundaries
  test_empty_registry_and_process_containment
  test_executor_preopen_type_and_identity_boundaries
  test_private_publication_boundaries
  printf 'PASS: lifecycle driver cell and mutation tests\n'
}

main "$@"
