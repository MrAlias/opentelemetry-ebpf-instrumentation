#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

TEST_SCRIPT_NAME="${BASH_SOURCE[0]##*/}"
TEST_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECTOR_SOURCE="$TEST_SCRIPT_DIR/project-retained-acceptance-evidence.sh"
VERIFIER_SOURCE="$TEST_SCRIPT_DIR/verify-retained-evidence.sh"
FIXTURE_BUILDERS="$TEST_SCRIPT_DIR/verify-retained-evidence_test.sh"
AGENT_DOWNLOAD_SOURCE="$TEST_SCRIPT_DIR/download-agent.sh"
TEST_TMP_DIR=""
REAL_SHA256SUM=""
REAL_CHMOD=""
REAL_MV=""
REAL_RM=""
REAL_STAT=""
REAL_READLINK=""
readonly TEST_SCRIPT_NAME TEST_SCRIPT_DIR PROJECTOR_SOURCE VERIFIER_SOURCE
readonly FIXTURE_BUILDERS AGENT_DOWNLOAD_SOURCE
readonly -a TEST_CASES=(
  cli
  success-and-determinism
  public-claim-mutations
  private-text-canonicality
  authority-mismatch
  official-agent-authority-mismatch
  runbook-cleanup-mismatch
  existing-output-no-clobber
  symlink-input
  sparse-input-preflight
  sparse-runbook-preflight
  opening-chmod-failure
  move-failure-before-side-effect
  move-failure-after-side-effect
  post-move-identity-drift
  reseal-chmod-failure
  post-move-verifier-failure
  private-cleanup-failure
  raw-source-owner-contract
)

usage() {
  printf '%s\n' \
    "Usage: $TEST_SCRIPT_NAME [--case-range START-END]" \
    "       $TEST_SCRIPT_NAME --list-cases" \
    "" \
    "Run all projector tests, or one inclusive ordinal range from --list-cases."
}

die() {
  printf '%s: %s\n' "$TEST_SCRIPT_NAME" "$*" >&2
  exit 1
}

usage_error() {
  printf '%s: %s\n' "$TEST_SCRIPT_NAME" "$*" >&2
  usage >&2
  exit 2
}

list_cases() {
  local -i ordinal=0

  for ((ordinal = 1; ordinal <= ${#TEST_CASES[@]}; ordinal++)); do
    printf '%02d\t%s\n' "$ordinal" "${TEST_CASES[ordinal - 1]}"
  done
}

parse_case_range() {
  local range=""
  local start=""
  local end=""

  if (($# == 0)); then
    printf '1\t%s\n' "${#TEST_CASES[@]}"
    return 0
  fi
  [[ "$1" == --case-range ]] || usage_error "unknown argument: $1"
  (($# == 2)) || usage_error "--case-range requires exactly START-END"
  range="$2"
  [[ "$range" =~ ^([1-9][0-9]*)-([1-9][0-9]*)$ ]] ||
    usage_error "case range must have the form START-END with positive ordinals"
  start="${BASH_REMATCH[1]}"
  end="${BASH_REMATCH[2]}"
  ((10#$start <= 10#$end)) || usage_error "case range start exceeds its end"
  ((10#$end <= ${#TEST_CASES[@]})) ||
    usage_error "case range exceeds the ${#TEST_CASES[@]} available cases"
  printf '%s\t%s\n' "$((10#$start))" "$((10#$end))"
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

  for command_name in awk bash chmod cmp cp dirname env find git grep head jq ln \
    mkdir mktemp mountpoint mv readlink rm sed sha256sum stat truncate; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  (( ${#missing[@]} == 0 )) || die "missing required commands: ${missing[*]}"
  [[ -x "$PROJECTOR_SOURCE" ]] || die "projector is not executable: $PROJECTOR_SOURCE"
  [[ -x "$VERIFIER_SOURCE" ]] || die "verifier is not executable: $VERIFIER_SOURCE"
  [[ -f "$FIXTURE_BUILDERS" && ! -L "$FIXTURE_BUILDERS" ]] ||
    die "fixture builders are unavailable: $FIXTURE_BUILDERS"
  [[ -f "$AGENT_DOWNLOAD_SOURCE" && ! -L "$AGENT_DOWNLOAD_SOURCE" ]] ||
    die "agent download source is unavailable: $AGENT_DOWNLOAD_SOURCE"
}

assert_no_invalid_jq_generator_binders() {
  local matches=""

  matches="$(grep -En \
    '(all|any)\([^;]* as \$[A-Za-z_][A-Za-z0-9_]*;' \
    "$PROJECTOR_SOURCE" "$VERIFIER_SOURCE" || true)"
  [[ -z "$matches" ]] ||
    die "jq generator binders must bind in the condition with '|': $matches"
}

assert_tls_boundary_jq_filter_compiles() {
  awk '
    /^    tls-boundary\)$/ { in_branch=1; next }
    in_branch && /^      jq -e '\''$/ { capture=1; next }
    capture && /^      '\'' "\$BUNDLE_DIR\/\$result"/ { exit }
    capture { print }
  ' "$VERIFIER_SOURCE" | jq -n -f /dev/stdin >/dev/null ||
    die "TLS-boundary jq evidence filter does not compile"
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

write_verifier_wrapper() {
  local -r output="$1"

  # Runtime wrapper variables must remain literal in the generated script.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'wrapper_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"' \
    'real_verifier="$wrapper_dir/verify-retained-evidence.real.sh"' \
    'if [[ -n "${PROJECTOR_TEST_VERIFIER_LOG:-}" ]]; then' \
    '  printf '\''%s\t%s\n'\'' "${1:-}" "${2:-}" >>"$PROJECTOR_TEST_VERIFIER_LOG"' \
    'fi' \
    'if [[ "${PROJECTOR_TEST_ASSERT_PRIVATE_MODES:-false}" == true &&' \
    '  "$#" == 3 && "$1" == --raw-v3 ]]; then' \
    '  : "${PROJECTOR_TEST_PRIVATE_MODE_LOG:?}"' \
    '  snapshot_parent="${3%/*}"' \
    '  work_directory="${snapshot_parent%/*}"' \
    '  [[ -d "$work_directory" && ! -L "$work_directory" ]] || exit 98' \
    '  while IFS= read -r -d '\'''\'' path; do' \
    '    authority="$(stat -Lc '\''%u:%a'\'' -- "$path")"' \
    '    mode="${authority#*:}"' \
    '    [[ "${authority%%:*}" == "$EUID" ]] || exit 98' \
    '    (( (8#$mode & 0077) == 0 && (8#$mode & 0100) != 0 )) || exit 98' \
    '  done < <(find -- "$work_directory" -xdev -type d -print0)' \
    '  while IFS= read -r -d '\'''\'' path; do' \
    '    authority="$(stat -Lc '\''%u:%a'\'' -- "$path")"' \
    '    mode="${authority#*:}"' \
    '    [[ "${authority%%:*}" == "$EUID" ]] || exit 98' \
    '    (( (8#$mode & 0077) == 0 )) || exit 98' \
    '  done < <(find -- "$work_directory" -xdev -type f -print0)' \
    '  printf '\''%s\n'\'' "$2" >>"$PROJECTOR_TEST_PRIVATE_MODE_LOG"' \
    'fi' \
    'if [[ "${PROJECTOR_TEST_FAIL_POST_MOVE:-false}" == true &&' \
    '  "$#" == 2 && "$1" == --claims-v1 &&' \
    '  "$2" == "${PROJECTOR_TEST_POST_MOVE_PATH:-}" ]]; then' \
    '  printf '\''projector-test injected post-move verifier failure\n'\'' >&2' \
    '  exit 97' \
    'fi' \
    'exec "$real_verifier" "$@"' \
    >"$output"
  chmod 0755 -- "$output"
}

write_sha256sum_wrapper() {
  local -r output="$1"

  # Runtime wrapper variables must remain literal in the generated script.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    ': "${PROJECTOR_TEST_HASH_LOG:?}"' \
    ': "${PROJECTOR_TEST_REAL_SHA256SUM:?}"' \
    'if [[ -n "${PROJECTOR_TEST_FORBID_HASH_PATH:-}" &&' \
    '  -n "${PROJECTOR_TEST_REAL_READLINK:-}" &&' \
    '  "$("$PROJECTOR_TEST_REAL_READLINK" -f -- "/proc/$BASHPID/fd/0" 2>/dev/null || true)" == "$PROJECTOR_TEST_FORBID_HASH_PATH" ]]; then' \
    '  printf '\''forbidden input hashed\n'\'' >>"$PROJECTOR_TEST_HASH_LOG"' \
    '  exit 99' \
    'fi' \
    'printf '\''sha256sum invoked\n'\'' >>"$PROJECTOR_TEST_HASH_LOG"' \
    'exec "$PROJECTOR_TEST_REAL_SHA256SUM" "$@"' \
    >"$output"
  chmod 0755 -- "$output"
}

write_publication_chmod_wrapper() {
  local -r output="$1"
  local -r real_chmod="$2"

  # Runtime wrapper variables must remain literal in the generated script.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    "real_chmod=$real_chmod" \
    'mode="${PROJECTOR_TEST_PUBLICATION_MODE:-}"' \
    'output="${PROJECTOR_TEST_OUTPUT_PATH:-}"' \
    'path="${@: -1}"' \
    'if [[ "$mode" == hardlink-cleanup && "$path" == /proc/self/fd/* &&' \
    '  ! -e "${PROJECTOR_TEST_CLEANUP_STATE:?}/triggered" ]]; then' \
    '  resolved="$("${PROJECTOR_TEST_REAL_READLINK:?}" -f -- "$path" 2>/dev/null || true)"' \
    '  if [[ "$resolved" =~ /\.retained-projection-transaction\.[^/]+$ ]]; then' \
    '    printf "%s\n" "$resolved" >"${PROJECTOR_TEST_CLEANUP_LOG:?}"' \
    '    : >"$PROJECTOR_TEST_CLEANUP_STATE/triggered"' \
    '    "${PROJECTOR_TEST_REAL_LN:?}" -- "${PROJECTOR_TEST_CLEANUP_SENTINEL:?}" "$resolved/external-hardlink"' \
    '  fi' \
    'fi' \
    'if [[ "$mode" == fail-open && "$#" == 3 && "$1" == 0700 &&' \
    '  "$2" == -- && "$path" == */.retained-projection-transaction.*/* &&' \
    '  "${path##*/}" == "${output##*/}" ]]; then' \
    '  exit 91' \
    'fi' \
    'if [[ "$mode" == fail-reseal && "$#" == 3 && "$1" == 0555 &&' \
    '  "$2" == -- && "$path" == "$output" ]]; then' \
    '  exit 92' \
    'fi' \
    'exec "$real_chmod" "$@"' \
    >"$output"
  chmod 0755 -- "$output"
}

write_publication_mv_wrapper() {
  local -r output="$1"
  local -r real_mv="$2"
  local -r real_rm="$3"
  local -r real_chmod="$4"

  # Runtime wrapper variables must remain literal in the generated script.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    "real_mv=$real_mv" \
    "real_rm=$real_rm" \
    "real_chmod=$real_chmod" \
    'mode="${PROJECTOR_TEST_PUBLICATION_MODE:-}"' \
    'output="${PROJECTOR_TEST_OUTPUT_PATH:-}"' \
    'test_root="${PROJECTOR_TEST_ROOT:-}"' \
    'if [[ "$#" != 4 || "$1" != -Tn || "$2" != -- || "$4" != "$output" ]]; then' \
    '  exec "$real_mv" "$@"' \
    'fi' \
    'case "$mode" in' \
    '  fail-move-before)' \
    '    exit 93' \
    '    ;;' \
    '  fail-move-after)' \
    '    "$real_mv" "$@"' \
    '    exit 94' \
    '    ;;' \
    '  drift-identity)' \
    '    [[ -n "$test_root" && "$output" == "$test_root"/* ]] || exit 95' \
    '    "$real_mv" "$@"' \
    '    original_identity="$(stat -Lc '\''%d:%i:%u'\'' -- "$output")"' \
    '    cp -a -- "$output" "$output.identity-drift"' \
    '    "$real_chmod" -R u+rwX -- "$output"' \
    '    "$real_rm" -rf -- "$output"' \
    '    "$real_mv" -T -- "$output.identity-drift" "$output"' \
    '    replacement_identity="$(stat -Lc '\''%d:%i:%u'\'' -- "$output")"' \
    '    [[ "$replacement_identity" != "$original_identity" ]] || exit 96' \
    '    printf '\''%s\t%s\n'\'' "$original_identity" "$replacement_identity" >>"${PROJECTOR_TEST_MUTATION_LOG:?}"' \
    '    exit 0' \
    '    ;;' \
    '  *)' \
    '    exec "$real_mv" "$@"' \
    '    ;;' \
    'esac' \
    >"$output"
  chmod 0755 -- "$output"
}

write_cleanup_rm_wrapper() {
  local -r output="$1"
  local -r real_rm="$2"

  # Runtime wrapper variables must remain literal in the generated script.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    "real_rm=$real_rm" \
    'path="${@: -1}"' \
    'name="${path##*/}"' \
    'parent="${path%/*}"' \
    'output="${PROJECTOR_TEST_OUTPUT_PATH:-}"' \
    'if [[ "${PROJECTOR_TEST_PUBLICATION_MODE:-}" == fail-private-cleanup &&' \
    '  "$#" == 4 && "$1" == --one-file-system && "$2" == -rf && "$3" == -- &&' \
    '  -d "$output" && ! -L "$output" &&' \
    '  "$parent" == "${output%/*}" &&' \
    '  "$name" == .retained-projection-transaction.* ]]; then' \
    '  printf "%s\n" "$path" >"${PROJECTOR_TEST_CLEANUP_FAILURE_LOG:?}"' \
    '  exit 98' \
    'fi' \
    'exec "$real_rm" "$@"' \
    >"$output"
  chmod 0755 -- "$output"
}

write_source_owner_stat_wrapper() {
  local -r output="$1"
  local -r real_stat="$2"
  local -r real_readlink="$3"

  # Runtime wrapper variables must remain literal in the generated script.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    "real_stat=$real_stat" \
    "real_readlink=$real_readlink" \
    'target="${PROJECTOR_TEST_OWNER_PATH:-}"' \
    'owner="${PROJECTOR_TEST_SOURCE_OWNER:-}"' \
    'path="${@: -1}"' \
    'resolved="$($real_readlink -f -- "$path" 2>/dev/null || true)"' \
    'if [[ -z "$target" || -z "$owner" || "$resolved" != "$target" ]]; then' \
    '  exec "$real_stat" "$@"' \
    'fi' \
    'observed="$($real_stat "$@")"' \
    'format=""' \
    'for argument in "$@"; do' \
    '  case "$argument" in' \
    '    %u|--format=%u) format=owner ;;' \
    '    %d:%i:%u:%a:%h:%s) format=identity ;;' \
    '  esac' \
    'done' \
    'case "$format" in' \
    '  owner) printf "%s\n" "$owner" ;;' \
    '  identity)' \
    '    IFS=: read -r device inode _ mode links size <<<"$observed"' \
    '    printf "%s:%s:%s:%s:%s:%s\n" "$device" "$inode" "$owner" "$mode" "$links" "$size"' \
    '    ;;' \
    '  *) printf '\''%s\n'\'' "$observed" ;;' \
    'esac' \
    >"$output"
  chmod 0755 -- "$output"
}

build_private_inputs() {
  local -r repository="$1"
  local -r revision="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r builder_work="$TEST_TMP_DIR/fixture-builder"

  mkdir -m 0700 -- "$builder_work"
  bash -s -- "$FIXTURE_BUILDERS" "$builder_work" "$repository" "$revision" \
    "$acceptance" "$assertion" "$runbook" <<'FIXTURE_BUILDER'
set -Eeuo pipefail
fixture_builders="$1"
builder_work="$2"
repository="$3"
revision="$4"
acceptance="$5"
assertion="$6"
runbook="$7"
# The existing test is the schema-fixture library; omit only its main call.
# shellcheck disable=SC1090
source <(head -n -1 -- "$fixture_builders")
trap - EXIT
TEST_TMP_DIR="$builder_work"
create_raw_v3_acceptance_fixture "$repository" "$revision" "$acceptance"
create_raw_v3_assertion_fixture "$repository" "$revision" "$assertion"
source_tree_sha256="$(awk -F= '$1 == "source_tree_sha256" { print $2 }' \
  "$acceptance/environment.txt")"
workflow_digest="$(git -C "$repository" show \
  "$revision:.github/workflows/java_remote_parent_acceptance_claims.yml" |
  sha256sum)"
workflow_digest="${workflow_digest%% *}"
jq -cS -n --arg revision "$revision" --arg tree "$source_tree_sha256" \
  --arg workflow_digest "$workflow_digest" \
  --arg empty_sha256 \
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" '
  ["clone","checkout-exact-revision","clean-status-before",
    "certificate-generation","run-test","tracecheck-tests","compose-config",
    "clean-status-after-validation","acceptance-all-otel-getsockopt-tls13",
    "assertion-failure-exit-2","scoped-cleanup","clean-status-final"] as $ids |
  {
    schema:"obi-apache-java-https-runbook-receipt-v1",
    source_revision:$revision,
    source_tree_sha256:$tree,
    environment:{architecture:"x86_64",compose_version:"2.39.0",
      docker_version:"28.0.0",go_version:"1.25.0",java_version:"21.0.8",
      operating_system:"Linux"},
    execution_locator:{event:"push",head_sha:$revision,kind:"github-actions",
      repository:"MrAlias/opentelemetry-ebpf-instrumentation",
      run_attempt:"1",run_id:"123456789",
      run_url:"https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/123456789/attempts/1",
      workflow_blob_sha256:$workflow_digest,
      workflow_path:".github/workflows/java_remote_parent_acceptance_claims.yml",
      workflow_ref:"MrAlias/opentelemetry-ebpf-instrumentation/.github/workflows/java_remote_parent_acceptance_claims.yml@refs/heads/agent/java-remote-parent-bridge",
      workflow_sha:$revision},
    output_contract:{algorithm:"sha256",
      bytes:"exact-command-order-no-normalization",
      stream:"combined-stdout-stderr"},
    commands:[$ids[] as $id | {
      id:$id,duration_seconds:1,
      exit_status:(if $id == "assertion-failure-exit-2" then 2 else 0 end),
      output_sha256:(if $id == "clean-status-before" or
          $id == "clean-status-after-validation" or
          $id == "clean-status-final"
        then $empty_sha256 else ("4" * 64) end),
      status:(if $id == "assertion-failure-exit-2" then
        "expected_failure" else "passed" end)}]
  }
' >"$runbook"
FIXTURE_BUILDER
  chmod 0600 -- "$runbook"
}

assert_no_transaction_residue() {
  local -r output="$1"
  local -r parent="${output%/*}"
  local residue=""

  residue="$(find -- "$parent" -mindepth 1 -maxdepth 1 \
    -name '.retained-projection-transaction.*' -print -quit)"
  [[ -z "$residue" ]] || die "private transaction residue remained: $residue"
}

expect_failure_without_output() {
  local -r description="$1"
  local -r expected_message="$2"
  local -r output="$3"
  local -r log_prefix="$4"
  shift 4

  if "$@" >"$log_prefix.stdout" 2>"$log_prefix.stderr"; then
    die "projector accepted $description"
  fi
  [[ ! -e "$output" && ! -L "$output" ]] ||
    die "projector left output after rejecting $description"
  grep -F -- "$expected_message" "$log_prefix.stderr" >/dev/null ||
    die "projector did not classify $description"
  assert_no_transaction_residue "$output"
}

expect_retained_invalid_output() {
  local -r description="$1"
  local -r reason="$2"
  local -r output="$3"
  local -r log_prefix="$4"
  shift 4

  if "$@" >"$log_prefix.stdout" 2>"$log_prefix.stderr"; then
    die "projector hid $description"
  fi
  [[ -d "$output" && ! -L "$output" ]] ||
    die "projector removed the retained output after $description"
  grep -F -- \
    "publication did not complete authoritatively ($reason); output was retained at $output and must be treated as invalid/non-authoritative" \
    "$log_prefix.stderr" >/dev/null ||
    die "projector did not classify $description as invalid/non-authoritative"
  assert_no_transaction_residue "$output"
}

expect_claim_verifier_rejection() {
  local -r verifier="$1"
  local -r output="$2"
  local -r log_prefix="$3"

  if "$verifier" --claims-v1 "$output" \
    >"$log_prefix.stdout" 2>"$log_prefix.stderr"; then
    die "claims verifier accepted a retained invalid output: $output"
  fi
}

assert_sealed_output() {
  local -r output="$1"
  local path=""
  local mode=""
  local unexpected=""

  [[ -d "$output" && ! -L "$output" ]] || die "published output is not physical"
  unexpected="$(find -- "$output" ! -type d ! -type f -print -quit)"
  [[ -z "$unexpected" ]] || die "published output contains a special entry: $unexpected"
  while IFS= read -r -d '' path; do
    mode="$(stat -Lc '%a' -- "$path")"
    [[ "$mode" == 555 ]] || die "published directory is not sealed: $path ($mode)"
  done < <(find -- "$output" -type d -print0)
  while IFS= read -r -d '' path; do
    mode="$(stat -Lc '%a' -- "$path")"
    [[ "$mode" == 444 ]] || die "published file is not sealed: $path ($mode)"
    [[ "$(stat -Lc '%h' -- "$path")" == 1 ]] ||
      die "published file has multiple hard links: $path"
  done < <(find -- "$output" -type f -print0)
}

assert_exact_claim_closure() {
  local -r output="$1"
  local -r expected="$TEST_TMP_DIR/claim-closure.expected"
  local -r actual="$TEST_TMP_DIR/claim-closure.actual"

  printf '%s\n' README.md SANITIZATION.md SHA256SUMS acceptance-claims.json \
    authority-summary.json derivation-receipt.json verify.sh |
    LC_ALL=C sort >"$expected"
  find -- "$output" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' |
    LC_ALL=C sort >"$actual"
  cmp -s -- "$expected" "$actual" ||
    die "published bounded-claim closure is not exactly seven files"
  [[ -z "$(find -- "$output" -mindepth 1 -maxdepth 1 ! -type f \
    -print -quit)" ]] || die "published bounded-claim closure has a non-file entry"
}

run_portable_claim_verifier() {
  local -r output="$1"

  (CDPATH=/definitely/not/a/real/cdpath cd / &&
    bash "$output/verify.sh" >/dev/null) ||
    die "portable claim verifier failed from an unrelated working directory"
  (CDPATH='' cd -- "$output" && bash verify.sh >/dev/null) ||
    die "portable bash-verify.sh contract failed from the bundle directory"
}

make_claim_bundle_mutable() {
  local -r bundle="$1"

  chmod 0755 -- "$bundle"
  find -- "$bundle" -type f -exec chmod 0644 -- {} +
}

seal_claim_bundle() {
  local -r bundle="$1"

  find -- "$bundle" -type f -exec chmod 0444 -- {} +
  chmod 0555 -- "$bundle"
}

write_claim_checksum_manifest() {
  local -r bundle="$1"
  local -r candidate="$bundle/SHA256SUMS.candidate"
  local file=""

  : >"$candidate"
  while IFS= read -r file; do
    sha256sum "$bundle/$file" | sed "s#  $bundle/#  ./#" >>"$candidate"
  done < <(printf '%s\n' README.md SANITIZATION.md acceptance-claims.json \
    authority-summary.json derivation-receipt.json verify.sh | LC_ALL=C sort)
  mv -fT -- "$candidate" "$bundle/SHA256SUMS"
}

reseal_claim_relations() {
  local -r bundle="$1"
  local authority_sha256=""
  local claims_sha256=""
  local evidence_id=""
  local candidate="$bundle/derivation-receipt.json.candidate"

  authority_sha256="$(sha256sum <"$bundle/authority-summary.json")"
  authority_sha256="${authority_sha256%% *}"
  claims_sha256="$(sha256sum <"$bundle/acceptance-claims.json")"
  claims_sha256="${claims_sha256%% *}"
  evidence_id="$(printf '%s\n' 'obi-bounded-claims-evidence-v1' \
    "${bundle##*/}" "$authority_sha256" "$claims_sha256" | sha256sum)"
  evidence_id="${evidence_id%% *}"
  jq -cS --arg bundle_name "${bundle##*/}" --arg authority "$authority_sha256" \
    --arg claims "$claims_sha256" --arg evidence_id "$evidence_id" '
      .bundle_name = $bundle_name | .evidence_id = $evidence_id |
      .authority.sha256 = $authority | .claims.sha256 = $claims
    ' "$bundle/derivation-receipt.json" >"$candidate"
  mv -fT -- "$candidate" "$bundle/derivation-receipt.json"
  write_claim_checksum_manifest "$bundle"
}

expect_claim_bundle_rejection() {
  local -r description="$1"
  local -r verifier="$2"
  local -r bundle="$3"

  if "$verifier" --claims-v1 "$bundle" >/dev/null 2>&1; then
    die "trusted claims verifier accepted $description"
  fi
  if (CDPATH='' cd / && bash "$bundle/verify.sh" >/dev/null 2>&1); then
    die "portable claims verifier accepted $description"
  fi
}

assert_raw_sensitive_artifacts_absent() {
  local -r output="$1"
  local relative=""
  local found=""
  local -a forbidden=(
    failure-context.txt
    scenario-assertion-failure.json
    scenario-assertion-failure-status.json
    map-pressure-pressure-prepare.json
    map-pressure-pressure-fill.json
    map-pressure-pressure-cleanup.json
    map-pressure-pressure-monitor.log
    map-pressure-pressure-recovered-samples.log
    receive-cursor-map-tls-boundary-before.json
    receive-cursor-map-tls-boundary-after.json
    receive-cursor-map-tls-boundary-status.json
    receive-cursor-map-coalesced-bridge-before.json
    receive-cursor-map-coalesced-bridge-after.json
    receive-cursor-map-coalesced-bridge-status.json
  )

  for relative in "${forbidden[@]}"; do
    [[ ! -e "$output/$relative" && ! -L "$output/$relative" ]] ||
      die "raw-sensitive artifact escaped projection: $relative"
  done
  found="$(find -- "$output" -type f \
    \( -name '*.stderr.log' -o -name '*.pem' -o -name '*.key' \
      -o -name '*.jar' -o -name 'failure-context.txt' \) -print -quit)"
  [[ -z "$found" ]] || die "raw-sensitive artifact escaped projection: $found"
}

replace_environment_architecture() {
  local -r environment="$1"
  local -r candidate="$environment.candidate"

  sed 's/^architecture=x86_64$/architecture=aarch64/' \
    "$environment" >"$candidate"
  grep -Fx 'architecture=aarch64' "$candidate" >/dev/null ||
    die "could not mutate assertion authority"
  mv -- "$candidate" "$environment"
}

mutate_runbook_cleanup() {
  local -r runbook="$1"
  local -r candidate="$runbook.candidate"

  jq '(.commands[] | select(.id == "scoped-cleanup")) |=
    (.status = "failed" | .exit_status = 1)' "$runbook" >"$candidate"
  mv -- "$candidate" "$runbook"
  chmod 0600 -- "$runbook"
}

mutate_runbook_architecture() {
  local -r runbook="$1"
  local -r candidate="$runbook.candidate"

  jq -cS '.environment.architecture = "aarch64"' \
    "$runbook" >"$candidate"
  mv -- "$candidate" "$runbook"
  chmod 0600 -- "$runbook"
}

mutate_runbook_clean_output_digest() {
  local -r runbook="$1"
  local -r command_id="$2"
  local -r candidate="$runbook.candidate"

  jq -cS --arg command_id "$command_id" '
    (.commands[] | select(.id == $command_id) | .output_sha256) = ("4" * 64)
  ' "$runbook" >"$candidate"
  mv -- "$candidate" "$runbook"
  chmod 0600 -- "$runbook"
}

test_cli() {
  local -r projector="$1"
  local help_output=""
  local status=0

  help_output="$("$projector" --help)" || die "projector --help failed"
  [[ "$help_output" == *'Usage:'* && "$help_output" == *'ABS_ACCEPTANCE_ALL'* ]] ||
    die "projector --help omitted its contract"
  if "$projector" --unknown >"$TEST_TMP_DIR/unknown.stdout" \
    2>"$TEST_TMP_DIR/unknown.stderr"; then
    status=0
  else
    status=$?
  fi
  ((status == 2)) || die "malformed projector arguments returned $status, not 2"
  grep -F 'Usage:' "$TEST_TMP_DIR/unknown.stderr" >/dev/null ||
    die "malformed projector arguments omitted usage"
}

test_success_and_determinism() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r first_parent="$TEST_TMP_DIR/success-one"
  local -r second_parent="$TEST_TMP_DIR/success-two"
  local -r first="$first_parent/public-v3"
  local -r second="$second_parent/public-v3"
  local -r private_mode_log="$first_parent/private-mode.log"
  local -r expected_private_mode_log="$first_parent/private-mode.expected"
  local caller_umask=""

  mkdir -m 0700 -- "$first_parent" "$second_parent"
  caller_umask="$(umask)"
  (
    local permissive_caller_umask=""

    umask 0002
    permissive_caller_umask="$(umask)"
    PROJECTOR_TEST_ASSERT_PRIVATE_MODES=true \
      PROJECTOR_TEST_PRIVATE_MODE_LOG="$private_mode_log" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$first" >/dev/null
    [[ "$(umask)" == "$permissive_caller_umask" ]] ||
      die "projector changed its caller's umask"
  )
  [[ "$(umask)" == "$caller_umask" ]] ||
    die "permissive-umask regression escaped its caller scope"
  printf '%s\n' acceptance assertion-failure >"$expected_private_mode_log"
  cmp -s -- "$expected_private_mode_log" "$private_mode_log" ||
    die "projector did not keep both raw snapshots at private 0700/0600 modes"
  "$verifier" --claims-v1 "$first" >/dev/null
  run_portable_claim_verifier "$first"
  assert_sealed_output "$first"
  assert_exact_claim_closure "$first"
  assert_raw_sensitive_artifacts_absent "$first"
  jq -e '
    .issue_34.scenarios[8] as $timeout |
    $timeout.name == "timeout-retry" and
    $timeout.reconciliation == {outcome:"reason_coded_drop",reason:"timeout"} and
    ($timeout | has("exact_parent_count") | not) and
    ($timeout | has("explicit_local_root_count") | not) and
    .issue_34.scenarios[9].name == "pressure" and
    .issue_34.scenarios[9].exact_parent_count == 127 and
    .issue_34.scenarios[9].explicit_local_root_count == 1
  ' "$first/acceptance-claims.json" >/dev/null ||
    die "public claims did not preserve accepted timeout and pressure outcome splits"

  "$projector" "$acceptance" "$assertion" "$runbook" "$second" >/dev/null
  "$verifier" --claims-v1 "$second" >/dev/null
  run_portable_claim_verifier "$second"
  assert_sealed_output "$second"
  assert_exact_claim_closure "$second"
  cmp -s -- "$first/SHA256SUMS" "$second/SHA256SUMS" ||
    die "repeat bounded-claim derivation was not deterministic"

  local -r roundtrip_source="$TEST_TMP_DIR/claim-git-source"
  local -r roundtrip_checkout="$TEST_TMP_DIR/claim-git-checkout"
  local -r roundtrip_bundle="$roundtrip_checkout/public-v3"

  git init --quiet "$roundtrip_source"
  git -C "$roundtrip_source" config user.email 'claims-roundtrip@example.invalid'
  git -C "$roundtrip_source" config user.name 'Claims Roundtrip Test'
  git -C "$roundtrip_source" config commit.gpgSign false
  git -C "$roundtrip_source" config tag.gpgSign false
  cp -a -- "$first" "$roundtrip_source/public-v3"
  chmod 0755 -- "$roundtrip_source/public-v3"
  find -- "$roundtrip_source/public-v3" -type f -exec chmod 0644 -- {} +
  git -C "$roundtrip_source" add public-v3
  git -C "$roundtrip_source" commit --quiet -m 'Retain bounded claim summary'
  (umask 0022; git clone --quiet "$roundtrip_source" "$roundtrip_checkout")
  "$verifier" --claims-v1 "$roundtrip_bundle" >/dev/null
  run_portable_claim_verifier "$roundtrip_bundle"
  assert_exact_claim_closure "$roundtrip_bundle"
}

test_public_claim_mutations() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r baseline="$TEST_TMP_DIR/success-one/public-v3"
  local -r parent="$TEST_TMP_DIR/public-claim-mutations"
  local bundle=""
  local candidate=""
  local command_name=""
  local -r dependency_bin="$parent/dependency-bin"
  local -r unsafe_tmp_bin="$parent/unsafe-tmp-bin"
  local -r race_bin="$parent/race-bin"
  local -r race_state="$parent/race-state"
  local -r race_valid_claims="$parent/race-valid-claims.json"
  local -r race_malicious_claims="$parent/race-malicious-claims.json"
  local -r cleanup_bin="$parent/cleanup-bin"
  local -r cleanup_state="$parent/cleanup-state"
  local -r cleanup_log="$parent/cleanup-path.log"
  local -r cleanup_sentinel="$parent/cleanup-external-sentinel"
  local cleanup_path=""
  local cleanup_digest=""
  local observed_digest=""

  if [[ ! -d "$baseline" ]]; then
    mkdir -m 0700 -- "${baseline%/*}"
    "$projector" "$acceptance" "$assertion" "$runbook" "$baseline" >/dev/null
  fi
  mkdir -m 0700 -- "$parent"

  bundle="$parent/readme/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  printf 'forged trust statement\n' >>"$bundle/README.md"
  reseal_claim_relations "$bundle"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'a resealed modified README' "$verifier" "$bundle"

  bundle="$parent/coherent-self-verifier/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  sed -i \
    's/Compare both the evidence ID and the verifier SHA-256 digest with an externally trusted record\./The evidence ID alone authenticates this bundle./' \
    "$bundle/README.md"
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$bundle/verify.sh"
  reseal_claim_relations "$bundle"
  seal_claim_bundle "$bundle"
  [[ "$(jq -r '.evidence_id' "$bundle/derivation-receipt.json")" == \
    "$(jq -r '.evidence_id' "$baseline/derivation-receipt.json")" ]] ||
    die "coherent self-verifier mutation unexpectedly changed the evidence ID"
  if "$verifier" --claims-v1 "$bundle" >/dev/null 2>&1; then
    die "trusted verifier accepted a replaced trust statement and verifier"
  fi
  (CDPATH='' cd / && bash "$bundle/verify.sh" >/dev/null) ||
    die "coherent self-verifier mutation did not exercise self-trust"

  bundle="$parent/nested-extra/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  jq -cS '.issue_34.private_path = "/tmp/private"' \
    "$bundle/acceptance-claims.json" >"$bundle/acceptance-claims.json.tmp"
  mv -fT -- "$bundle/acceptance-claims.json.tmp" \
    "$bundle/acceptance-claims.json"
  reseal_claim_relations "$bundle"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'a resealed nested extra claim' "$verifier" "$bundle"

  bundle="$parent/forged-value/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  jq -cS '.issue_34.zero_wrong_parent = false' \
    "$bundle/acceptance-claims.json" >"$bundle/acceptance-claims.json.tmp"
  mv -fT -- "$bundle/acceptance-claims.json.tmp" \
    "$bundle/acceptance-claims.json"
  reseal_claim_relations "$bundle"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'a resealed forged acceptance value' \
    "$verifier" "$bundle"

  bundle="$parent/standalone-aba/public-v3"
  mkdir -m 0700 -- "${bundle%/*}" "$race_bin" "$race_state"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  cp -- "$bundle/acceptance-claims.json" "$race_valid_claims"
  jq -cS '.issue_34.zero_wrong_parent = false' \
    "$bundle/acceptance-claims.json" >"$bundle/acceptance-claims.json.tmp"
  mv -fT -- "$bundle/acceptance-claims.json.tmp" \
    "$bundle/acceptance-claims.json"
  reseal_claim_relations "$bundle"
  cp -- "$bundle/acceptance-claims.json" "$race_malicious_claims"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Euo pipefail' \
    'target=false' \
    'for argument in "$@"; do' \
    '  [[ "$argument" == */acceptance-claims.json ]] && target=true' \
    'done' \
    'if [[ "$target" == true ]]; then' \
    '  count=0' \
    '  [[ ! -s "$RACE_JQ_COUNT" ]] || read -r count <"$RACE_JQ_COUNT"' \
    '  count=$((count + 1))' \
    '  printf "%s\n" "$count" >"$RACE_JQ_COUNT"' \
    '  "$REAL_CP" -- "$RACE_VALID_CLAIMS" "$RACE_SOURCE_CLAIMS"' \
    '  set +e' \
    '  "$REAL_JQ" "$@"' \
    '  status=$?' \
    '  set -e' \
    '  if ((count > 1)); then' \
    '    "$REAL_CP" -- "$RACE_MALICIOUS_CLAIMS" "$RACE_SOURCE_CLAIMS"' \
    '  fi' \
    '  exit "$status"' \
    'fi' \
    'exec "$REAL_JQ" "$@"' \
    >"$race_bin/jq"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Euo pipefail' \
    'restore=false' \
    'for argument in "$@"; do' \
    '  [[ "$argument" == "$RACE_SOURCE_CLAIMS" ]] && restore=true' \
    'done' \
    'set +e' \
    '"$REAL_CMP" "$@"' \
    'status=$?' \
    'set -e' \
    'if [[ "$restore" == true ]]; then' \
    '  "$REAL_CP" -- "$RACE_MALICIOUS_CLAIMS" "$RACE_SOURCE_CLAIMS"' \
    'fi' \
    'exit "$status"' \
    >"$race_bin/cmp"
  chmod 0755 -- "$race_bin/jq" "$race_bin/cmp"
  if env PATH="$race_bin:$PATH" \
    REAL_JQ="$(command -v jq)" REAL_CMP="$(command -v cmp)" \
    REAL_CP="$(command -v cp)" \
    RACE_JQ_COUNT="$race_state/jq-count" \
    RACE_SOURCE_CLAIMS="$bundle/acceptance-claims.json" \
    RACE_VALID_CLAIMS="$race_valid_claims" \
    RACE_MALICIOUS_CLAIMS="$race_malicious_claims" \
    bash "$bundle/verify.sh" >/dev/null 2>&1; then
    die "portable verifier accepted an ABA-swapped forged claims file"
  fi
  cmp -s -- "$race_malicious_claims" "$bundle/acceptance-claims.json" ||
    die "ABA race shim did not restore the forged source claims"

  bundle="$parent/noncanonical-json/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  jq . "$bundle/acceptance-claims.json" >"$bundle/acceptance-claims.json.tmp"
  mv -fT -- "$bundle/acceptance-claims.json.tmp" \
    "$bundle/acceptance-claims.json"
  reseal_claim_relations "$bundle"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'resealed noncanonical public JSON' \
    "$verifier" "$bundle"

  bundle="$parent/json-no-lf/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  truncate -s -1 -- "$bundle/acceptance-claims.json"
  reseal_claim_relations "$bundle"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'resealed public JSON without terminal LF' \
    "$verifier" "$bundle"

  bundle="$parent/manifest-order/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$bundle/SHA256SUMS" >"$bundle/SHA256SUMS.tmp"
  mv -fT -- "$bundle/SHA256SUMS.tmp" "$bundle/SHA256SUMS"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'a reordered checksum manifest' "$verifier" "$bundle"

  bundle="$parent/manifest-no-lf/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  truncate -s -1 -- "$bundle/SHA256SUMS"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'a checksum manifest without terminal LF' \
    "$verifier" "$bundle"

  bundle="$parent/mixed-modes/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  chmod 0644 -- "$bundle/README.md"
  expect_claim_bundle_rejection 'mixed sealed and Git-portable file modes' \
    "$verifier" "$bundle"

  bundle="$parent/extra-file/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  printf 'unexpected\n' >"$bundle/extra.txt"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'an eighth public file' "$verifier" "$bundle"

  bundle="$parent/oversized-note/public-v3"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  make_claim_bundle_mutable "$bundle"
  awk 'BEGIN { for (i = 0; i < 4097; i++) printf "x" }' >"$bundle/README.md"
  reseal_claim_relations "$bundle"
  seal_claim_bundle "$bundle"
  expect_claim_bundle_rejection 'a public note at its cap plus one byte' \
    "$verifier" "$bundle"

  bundle="$parent/renamed/not-the-bound-name"
  mkdir -m 0700 -- "${bundle%/*}"
  cp -a -- "$baseline" "$bundle"
  expect_claim_bundle_rejection 'a renamed content-bound bundle' "$verifier" "$bundle"

  grep -F 'verification_tmp_parent_is_trusted' "$baseline/verify.sh" >/dev/null ||
    die "portable verifier omits the physical root and /tmp trust preflight"
  grep -F 'private_verification_tmp_is_safe' "$baseline/verify.sh" >/dev/null ||
    die "portable verifier omits private temporary-directory mode validation"
  mkdir -m 0700 -- "$unsafe_tmp_bin"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'if [[ $# == 3 && "$1" == "--format=%a" && "$2" == "--" && "$3" == /tmp ]]; then' \
    '  printf "777\\n"' \
    '  exit 0' \
    'fi' \
    'exec "$REAL_STAT" "$@"' \
    >"$unsafe_tmp_bin/stat"
  chmod 0755 -- "$unsafe_tmp_bin/stat"
  if env PATH="$unsafe_tmp_bin:$PATH" REAL_STAT="$REAL_STAT" \
    /bin/bash "$baseline/verify.sh" >"$parent/unsafe-tmp.stdout" \
      2>"$parent/unsafe-tmp.stderr"; then
    die "portable verifier accepted a non-sticky verification temporary parent"
  fi
  grep -F \
    'verification temporary parent must be physical, root-owned, sticky, and world writable' \
    "$parent/unsafe-tmp.stderr" >/dev/null ||
    die "portable verifier did not diagnose the unsafe temporary parent"

  mkdir -m 0700 -- "$dependency_bin"
  for command_name in chmod cmp dirname find jq mkdir mktemp mountpoint mv pwd \
    readlink rm sha256sum sort stat; do
    ln -s -- "$(command -v "$command_name")" "$dependency_bin/$command_name"
  done
  if env PATH="$dependency_bin" /bin/bash "$baseline/verify.sh" \
    >"$parent/dependency.stdout" 2>"$parent/dependency.stderr"; then
    die "portable verifier accepted a runtime without required cat"
  fi
  grep -F 'missing dependency: cat' "$parent/dependency.stderr" >/dev/null ||
    die "portable verifier did not name its missing cat dependency"

  mkdir -m 0700 -- "$cleanup_bin" "$cleanup_state"
  printf 'external portable-verifier cleanup sentinel\n' >"$cleanup_sentinel"
  chmod 0400 -- "$cleanup_sentinel"
  cleanup_digest="$(sha256sum <"$cleanup_sentinel")"
  cleanup_digest="${cleanup_digest%% *}"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'target="${!#}"' \
    'resolved="$("$REAL_READLINK" -f -- "$target" 2>/dev/null || true)"' \
    'if [[ "$target" == /proc/self/fd/* &&' \
    '  "$resolved" =~ ^/tmp/obi-claims-verify\.[^/]+$ &&' \
    '  ! -e "$CLEANUP_STATE/triggered" ]]; then' \
    '  printf "%s\n" "$resolved" >"$CLEANUP_LOG"' \
    '  : >"$CLEANUP_STATE/triggered"' \
    '  "$REAL_LN" -- "$CLEANUP_SENTINEL" "$resolved/external-hardlink"' \
    'fi' \
    'exec "$REAL_CHMOD" "$@"' \
    >"$cleanup_bin/chmod"
  chmod 0755 -- "$cleanup_bin/chmod"
  env PATH="$cleanup_bin:$PATH" REAL_CHMOD="$(command -v chmod)" \
    REAL_LN="$(command -v ln)" REAL_READLINK="$REAL_READLINK" \
    CLEANUP_STATE="$cleanup_state" CLEANUP_LOG="$cleanup_log" \
    CLEANUP_SENTINEL="$cleanup_sentinel" \
    bash "$baseline/verify.sh" >/dev/null ||
    die "portable verifier could not safely unlink an injected hardlink"
  cleanup_path="$(<"$cleanup_log")"
  [[ ! -e "$cleanup_path" && ! -L "$cleanup_path" ]] ||
    die "portable verifier retained its private cleanup transaction"
  [[ "$(stat -Lc '%a' -- "$cleanup_sentinel")" == 400 ]] ||
    die "portable verifier cleanup changed an external hardlink mode"
  observed_digest="$(sha256sum <"$cleanup_sentinel")"
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$cleanup_digest" ]] ||
    die "portable verifier cleanup changed external hardlink content"
}

test_private_text_canonicality() {
  local -r _projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r _assertion="$4"
  local -r _runbook="$5"
  local -r parent="$TEST_TMP_DIR/private-text-canonicality"
  local mutated=""
  local candidate=""

  mkdir -m 0700 -- "$parent"
  mutated="$parent/environment-order"
  cp -a -- "$acceptance" "$mutated"
  awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$mutated/environment.txt" >"$mutated/environment.txt.tmp"
  mv -fT -- "$mutated/environment.txt.tmp" "$mutated/environment.txt"
  if "$verifier" --raw-v3 acceptance "$mutated" >/dev/null 2>&1; then
    die "raw verifier accepted reordered environment text"
  fi

  mutated="$parent/environment-no-lf"
  cp -a -- "$acceptance" "$mutated"
  truncate -s -1 -- "$mutated/environment.txt"
  if "$verifier" --raw-v3 acceptance "$mutated" >/dev/null 2>&1; then
    die "raw verifier accepted environment text without terminal LF"
  fi

  mutated="$parent/source-state-order"
  cp -a -- "$acceptance" "$mutated"
  awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$mutated/source-state.txt" >"$mutated/source-state.txt.tmp"
  mv -fT -- "$mutated/source-state.txt.tmp" "$mutated/source-state.txt"
  if "$verifier" --raw-v3 acceptance "$mutated" >/dev/null 2>&1; then
    die "raw verifier accepted reordered source-state text"
  fi

  mutated="$parent/source-state-no-lf"
  cp -a -- "$acceptance" "$mutated"
  truncate -s -1 -- "$mutated/source-state.txt"
  if "$verifier" --raw-v3 acceptance "$mutated" >/dev/null 2>&1; then
    die "raw verifier accepted source-state text without terminal LF"
  fi

  mutated="$parent/resource-order"
  cp -a -- "$acceptance" "$mutated"
  candidate="$mutated/phases/keepalive-before/obi-resources.txt.tmp"
  awk 'NR == 1 { first=$0; next } NR == 2 { print; print first; next } { print }' \
    "$mutated/phases/keepalive-before/obi-resources.txt" >"$candidate"
  mv -fT -- "$candidate" \
    "$mutated/phases/keepalive-before/obi-resources.txt"
  if "$verifier" --raw-v3 acceptance "$mutated" >/dev/null 2>&1; then
    die "raw verifier accepted reordered resource text"
  fi

  mutated="$parent/resource-no-lf"
  cp -a -- "$acceptance" "$mutated"
  truncate -s -1 -- "$mutated/phases/keepalive-before/obi-resources.txt"
  if "$verifier" --raw-v3 acceptance "$mutated" >/dev/null 2>&1; then
    die "raw verifier accepted resource text without terminal LF"
  fi

  for candidate in bridge-source-revision.txt bridge-source-tree.sha256; do
    mutated="$parent/${candidate//./-}-no-lf"
    cp -a -- "$acceptance" "$mutated"
    truncate -s -1 -- "$mutated/$candidate"
    if "$verifier" --raw-v3 acceptance "$mutated" >/dev/null 2>&1; then
      die "raw verifier accepted $candidate without terminal LF"
    fi
  done
}

test_authority_mismatch() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r parent="$TEST_TMP_DIR/authority-mismatch"
  local -r mutated="$parent/assertion"
  local -r output="$parent/output"

  mkdir -m 0700 -- "$parent"
  cp -a -- "$assertion" "$mutated"
  replace_environment_architecture "$mutated/environment.txt"
  expect_failure_without_output \
    'raw runs with mismatched authority' \
    'the two raw runs do not share one pinned source and runtime authority' \
    "$output" "$parent/projector" \
    "$projector" "$acceptance" "$mutated" "$runbook" "$output"
}

test_official_agent_authority_mismatch() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r parent="$TEST_TMP_DIR/official-agent-authority-mismatch"
  local -r mutated="$parent/assertion"
  local -r output="$parent/output"
  local -r coherent_acceptance="$parent/coherent-acceptance"
  local -r coherent_assertion="$parent/coherent-assertion"
  local -r coherent_output="$parent/coherent-output"
  local input=""

  mkdir -m 0700 -- "$parent"
  cp -a -- "$assertion" "$mutated"
  jq -cS '
    .sha256 = "4444444444444444444444444444444444444444444444444444444444444444" |
    .url = "https://example.invalid/different-javaagent.jar" |
    .version = "2.29.0"
  ' "$mutated/official-javaagent.json" >"$parent/official-javaagent.json"
  mv -fT -- "$parent/official-javaagent.json" \
    "$mutated/official-javaagent.json"
  expect_failure_without_output \
    'raw runs with mismatched official Java agents' \
    'assertion-failure raw-v3 input did not verify' \
    "$output" "$parent/projector" \
    "$projector" "$acceptance" "$mutated" "$runbook" "$output"

  cp -a -- "$acceptance" "$coherent_acceptance"
  cp -a -- "$assertion" "$coherent_assertion"
  for input in "$coherent_acceptance" "$coherent_assertion"; do
    jq -cS '
      .version = "9.9.9" |
      .sha256 = "9999999999999999999999999999999999999999999999999999999999999999" |
      .url = "https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/9.9.9/opentelemetry-javaagent-9.9.9.jar"
    ' "$input/official-javaagent.json" >"$parent/official-javaagent.json"
    mv -fT -- "$parent/official-javaagent.json" \
      "$input/official-javaagent.json"
  done
  expect_failure_without_output \
    'both raw runs coherently claiming an unpinned official Java agent' \
    'acceptance raw-v3 input did not verify' \
    "$coherent_output" "$parent/coherent-projector" \
    "$projector" "$coherent_acceptance" "$coherent_assertion" "$runbook" \
      "$coherent_output"
}

test_runbook_cleanup_mismatch() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r parent="$TEST_TMP_DIR/runbook-mismatch"
  local -r mutated="$parent/runbook-receipt.json"
  local -r output="$parent/output"
  local command_id=""
  local mode_receipt=""

  mkdir -m 0700 -- "$parent"
  cp -- "$runbook" "$mutated"
  mutate_runbook_cleanup "$mutated"
  expect_failure_without_output \
    'runbook without a successful scoped cleanup' \
    'private raw runs do not satisfy the bounded claim profile' \
    "$output" "$parent/projector" \
    "$projector" "$acceptance" "$assertion" "$mutated" "$output"
  cp -- "$runbook" "$mutated"
  mutate_runbook_architecture "$mutated"
  expect_failure_without_output \
    'runbook with mismatched architecture authority' \
    'the two raw runs do not share one pinned source and runtime authority' \
    "$output" "$parent/projector-architecture" \
    "$projector" "$acceptance" "$assertion" "$mutated" "$output"

  for command_id in clean-status-before clean-status-after-validation \
    clean-status-final; do
    cp -- "$runbook" "$mutated"
    mutate_runbook_clean_output_digest "$mutated" "$command_id"
    expect_failure_without_output \
      "runbook $command_id row with nonempty command output" \
      'private raw runs do not satisfy the bounded claim profile' \
      "$output" "$parent/projector-$command_id-output" \
      "$projector" "$acceptance" "$assertion" "$mutated" "$output"
  done

  jq . "$runbook" >"$mutated"
  chmod 0600 -- "$mutated"
  expect_failure_without_output \
    'pretty-printed runbook receipt' \
    'private raw runs do not satisfy the bounded claim profile' \
    "$output" "$parent/projector-pretty" \
    "$projector" "$acceptance" "$assertion" "$mutated" "$output"

  jq -c 'to_entries | reverse | from_entries' "$runbook" >"$mutated"
  chmod 0600 -- "$mutated"
  expect_failure_without_output \
    'runbook receipt with reordered object keys' \
    'private raw runs do not satisfy the bounded claim profile' \
    "$output" "$parent/projector-reordered" \
    "$projector" "$acceptance" "$assertion" "$mutated" "$output"

  cp -- "$runbook" "$mutated"
  truncate -s -1 -- "$mutated"
  expect_failure_without_output \
    'runbook receipt without a terminal line feed' \
    'private raw runs do not satisfy the bounded claim profile' \
    "$output" "$parent/projector-no-lf" \
    "$projector" "$acceptance" "$assertion" "$mutated" "$output"

  cp -- "$runbook" "$mutated"
  cat -- "$runbook" >>"$mutated"
  expect_failure_without_output \
    'runbook receipt containing two JSON documents' \
    'execution checkout bytes or run locator are not authoritative' \
    "$output" "$parent/projector-two-documents" \
    "$projector" "$acceptance" "$assertion" "$mutated" "$output"

  local mode=""
  for mode in 0400 0644 0755; do
    mode_receipt="$parent/runbook-mode-$mode.json"
    cp -- "$runbook" "$mode_receipt"
    chmod "$mode" -- "$mode_receipt"
    expect_failure_without_output \
      "runbook receipt at mode $mode" \
      'runbook receipt mode, link count, or size is invalid' \
      "$output" "$parent/projector-mode-$mode" \
      "$projector" "$acceptance" "$assertion" "$mode_receipt" "$output"
  done
}

test_existing_output_no_clobber() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r parent="$TEST_TMP_DIR/existing-output"
  local -r output="$parent/output"
  local -r sentinel="$output/sentinel.txt"
  local before=""
  local after=""
  local unexpected=""

  mkdir -m 0700 -- "$parent" "$output"
  printf 'must remain unchanged\n' >"$sentinel"
  before="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$output"):$({
    sha256sum <"$sentinel"
  })"
  if "$projector" "$acceptance" "$assertion" "$runbook" "$output" \
    >"$parent/projector.stdout" 2>"$parent/projector.stderr"; then
    die "projector accepted an existing output"
  fi
  grep -F 'output must be a nonexistent absolute path' \
    "$parent/projector.stderr" >/dev/null ||
    die "existing-output rejection was not classified"
  after="$(stat -Lc '%d:%i:%u:%a:%h:%s' -- "$output"):$({
    sha256sum <"$sentinel"
  })"
  [[ "$after" == "$before" ]] || die "existing output or sentinel changed"
  unexpected="$(find -- "$output" -mindepth 1 -maxdepth 1 \
    ! -name sentinel.txt -print -quit)"
  [[ -z "$unexpected" ]] || die "projector added content to existing output"
  assert_no_transaction_residue "$output"
}

test_symlink_input() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r parent="$TEST_TMP_DIR/symlink-input"
  local -r linked="$parent/acceptance-link"
  local -r output="$parent/output"

  mkdir -m 0700 -- "$parent"
  ln -s -- "$acceptance" "$linked"
  expect_failure_without_output \
    'a symbolic-link acceptance input' \
    'acceptance input must be a private physical directory owned by this user' \
    "$output" "$parent/projector" \
    "$projector" "$linked" "$assertion" "$runbook" "$output"
}

test_sparse_input_preflight() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r verifier_log="$TEST_TMP_DIR/sparse-verifier.log"
  local -r hash_log="$TEST_TMP_DIR/sparse-hash.log"
  local -r shim_directory="$TEST_TMP_DIR/sparse-bin"
  local -r parent="$TEST_TMP_DIR/sparse-input"
  local -r mutated="$parent/acceptance"
  local -r output="$parent/output"

  mkdir -m 0700 -- "$shim_directory" "$parent"
  cp -a -- "$acceptance" "$mutated"
  truncate -s 603979777 -- "$mutated/oversized-sparse.raw"
  chmod 0600 -- "$mutated/oversized-sparse.raw"
  : >"$verifier_log"
  : >"$hash_log"
  write_sha256sum_wrapper "$shim_directory/sha256sum"
  expect_failure_without_output \
    'a sparse raw input over the aggregate byte cap' \
    'raw input is unsafe or exceeds its budget' \
    "$output" "$parent/projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_HASH_LOG="$hash_log" \
      PROJECTOR_TEST_REAL_SHA256SUM="$REAL_SHA256SUM" \
      PROJECTOR_TEST_VERIFIER_LOG="$verifier_log" \
      "$projector" "$mutated" "$assertion" "$runbook" "$output"
  [[ ! -s "$hash_log" ]] || die "sparse preflight invoked sha256sum"
  [[ ! -s "$verifier_log" ]] || die "sparse preflight invoked the verifier"
}

test_sparse_runbook_preflight() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r verifier_log="$TEST_TMP_DIR/sparse-runbook-verifier.log"
  local -r hash_log="$TEST_TMP_DIR/sparse-runbook-hash.log"
  local -r shim_directory="$TEST_TMP_DIR/sparse-runbook-bin"
  local -r parent="$TEST_TMP_DIR/sparse-runbook"
  local -r runbook="$parent/oversized-runbook.json"
  local -r output="$parent/output"

  mkdir -m 0700 -- "$shim_directory" "$parent"
  truncate -s 1048577 -- "$runbook"
  chmod 0600 -- "$runbook"
  : >"$verifier_log"
  : >"$hash_log"
  write_sha256sum_wrapper "$shim_directory/sha256sum"
  expect_failure_without_output \
    'a sparse runbook receipt over its byte cap' \
    'runbook receipt exceeds its byte cap' \
    "$output" "$parent/projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_FORBID_HASH_PATH="$runbook" \
      PROJECTOR_TEST_HASH_LOG="$hash_log" \
      PROJECTOR_TEST_REAL_READLINK="$REAL_READLINK" \
      PROJECTOR_TEST_REAL_SHA256SUM="$REAL_SHA256SUM" \
      PROJECTOR_TEST_VERIFIER_LOG="$verifier_log" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$output"
  ! grep -F 'forbidden input hashed' "$hash_log" >/dev/null ||
    die "sparse runbook was hashed before its byte cap"
  [[ ! -s "$verifier_log" ]] || die "sparse runbook preflight invoked the verifier"
}

test_opening_chmod_failure() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r shim_directory="$5"
  local -r parent="$TEST_TMP_DIR/opening-chmod-failure"
  local -r output="$parent/public-v3"

  mkdir -m 0700 -- "$parent"
  expect_failure_without_output \
    'failure opening the verified candidate root' \
    'could not open the verified candidate root for atomic publication' \
    "$output" "$parent/projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_PUBLICATION_MODE=fail-open \
      PROJECTOR_TEST_OUTPUT_PATH="$output" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$output"
}

test_move_failure_before_side_effect() {
  local -r projector="$1"
  local -r acceptance="$2"
  local -r assertion="$3"
  local -r runbook="$4"
  local -r shim_directory="$5"
  local -r parent="$TEST_TMP_DIR/move-failure-before"
  local -r output="$parent/public-v3"

  mkdir -m 0700 -- "$parent"
  expect_failure_without_output \
    'a no-clobber move error before its side effect' \
    'atomic publication failed before transferring the candidate (status 93)' \
    "$output" "$parent/projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_PUBLICATION_MODE=fail-move-before \
      PROJECTOR_TEST_OUTPUT_PATH="$output" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$output"
}

test_move_failure_after_side_effect() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r shim_directory="$6"
  local -r parent="$TEST_TMP_DIR/move-failure-after"
  local -r output="$parent/public-v3"

  mkdir -m 0700 -- "$parent"
  expect_retained_invalid_output \
    'a no-clobber move error after its real side effect' \
    'move returned status 94 after transferring the candidate' \
    "$output" "$parent/projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_PUBLICATION_MODE=fail-move-after \
      PROJECTOR_TEST_OUTPUT_PATH="$output" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$output"
  assert_sealed_output "$output"
  "$verifier" --claims-v1 "$output" >/dev/null
}

test_post_move_identity_drift() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r shim_directory="$6"
  local -r parent="$TEST_TMP_DIR/post-move-identity-drift"
  local -r output="$parent/public-v3"
  local -r mutation_log="$parent/identity.log"
  local original_identity=""
  local replacement_identity=""

  mkdir -m 0700 -- "$parent"
  : >"$mutation_log"
  expect_retained_invalid_output \
    'post-move candidate identity drift' \
    'the no-clobber move did not transfer the pinned candidate exactly' \
    "$output" "$parent/projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_PUBLICATION_MODE=drift-identity \
      PROJECTOR_TEST_OUTPUT_PATH="$output" \
      PROJECTOR_TEST_ROOT="$TEST_TMP_DIR" \
      PROJECTOR_TEST_MUTATION_LOG="$mutation_log" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$output"
  IFS=$'\t' read -r original_identity replacement_identity <"$mutation_log" ||
    die "identity-drift shim did not record both identities"
  [[ -n "$original_identity" && -n "$replacement_identity" &&
    "$original_identity" != "$replacement_identity" ]] ||
    die "identity-drift shim did not replace the moved directory"
  [[ "$(stat -Lc '%a' -- "$output")" == 700 ]] ||
    die "identity-drift output did not retain its expected open-root state"
  expect_claim_verifier_rejection \
    "$verifier" "$output" "$parent/real-verifier"
}

test_reseal_chmod_failure() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r shim_directory="$6"
  local -r parent="$TEST_TMP_DIR/reseal-chmod-failure"
  local -r output="$parent/public-v3"

  mkdir -m 0700 -- "$parent"
  expect_retained_invalid_output \
    'failure resealing the moved candidate root' \
    'the moved candidate root could not be resealed' \
    "$output" "$parent/projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_PUBLICATION_MODE=fail-reseal \
      PROJECTOR_TEST_OUTPUT_PATH="$output" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$output"
  [[ "$(stat -Lc '%a' -- "$output")" == 700 ]] ||
    die "reseal failure did not retain the moved output at mode 0700"
  expect_claim_verifier_rejection \
    "$verifier" "$output" "$parent/real-verifier"
}

test_post_move_verifier_failure() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r parent="$TEST_TMP_DIR/post-move-failure"
  local -r output="$parent/public-v3"
  local -r verifier_log="$parent/verifier.log"
  local -r stderr_log="$parent/projector.stderr"
  local -a verifier_calls=()

  mkdir -m 0700 -- "$parent"
  : >"$verifier_log"
  if env PROJECTOR_TEST_FAIL_POST_MOVE=true \
    PROJECTOR_TEST_POST_MOVE_PATH="$output" \
    PROJECTOR_TEST_VERIFIER_LOG="$verifier_log" \
    "$projector" "$acceptance" "$assertion" "$runbook" "$output" \
    >"$parent/projector.stdout" 2>"$stderr_log"; then
    die "projector hid an injected post-move verifier failure"
  fi
  [[ -d "$output" && ! -L "$output" ]] ||
    die "post-move verifier failure removed the published output"
  grep -F -- \
    "publication did not complete authoritatively (post-move claims-v1 verification failed); output was retained at $output and must be treated as invalid/non-authoritative" \
    "$stderr_log" >/dev/null || die "post-move failure lacked invalid classification"
  grep -F 'projector-test injected post-move verifier failure' \
    "$stderr_log" >/dev/null || die "post-move verifier hook did not trigger"
  mapfile -t verifier_calls <"$verifier_log"
  (( ${#verifier_calls[@]} == 4 )) ||
    die "unexpected verifier call count during post-move test: ${#verifier_calls[@]}"
  [[ "${verifier_calls[3]}" == $'--claims-v1\t'"$output" ]] ||
    die "injected verifier failure did not target the moved output"
  "$verifier" --claims-v1 "$output" >/dev/null
  assert_sealed_output "$output"
  assert_no_transaction_residue "$output"
}

test_private_cleanup_failure() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r shim_directory="$6"
  local -r parent="$TEST_TMP_DIR/private-cleanup-failure"
  local -r output="$parent/public-v3"
  local -r hardlink_output="$parent/hardlink-safe-public-v3"
  local -r cleanup_state="$parent/hardlink-state"
  local -r cleanup_log="$parent/hardlink-cleanup.log"
  local -r cleanup_failure_log="$parent/private-cleanup-failure.log"
  local -r expected_stdout="$parent/projector.expected-stdout"
  local -r sentinel="$parent/external-hardlink-sentinel"
  local residue=""
  local sentinel_digest=""
  local sentinel_mode=""
  local observed_digest=""
  local acceptance_revision=""
  local assertion_revision=""
  local -a cleanup_failures=()

  mkdir -m 0700 -- "$parent"
  if env PATH="$shim_directory:$PATH" \
    PROJECTOR_TEST_PUBLICATION_MODE=fail-private-cleanup \
    PROJECTOR_TEST_OUTPUT_PATH="$output" \
    PROJECTOR_TEST_CLEANUP_FAILURE_LOG="$cleanup_failure_log" \
    "$projector" "$acceptance" "$assertion" "$runbook" "$output" \
    >"$parent/projector.stdout" 2>"$parent/projector.stderr"; then
    die "projector hid a private transaction cleanup failure"
  fi
  [[ -d "$output" && ! -L "$output" ]] ||
    die "private cleanup failure removed the verified public output"
  grep -F 'private transaction cleanup failed after publication' \
    "$parent/projector.stderr" >/dev/null ||
    die "private cleanup failure was not propagated"
  "$verifier" --claims-v1 "$output" >/dev/null
  assert_sealed_output "$output"
  [[ -f "$cleanup_failure_log" && ! -L "$cleanup_failure_log" ]] ||
    die "private cleanup failure hook did not write its transaction log"
  mapfile -t cleanup_failures <"$cleanup_failure_log"
  (( ${#cleanup_failures[@]} == 1 )) ||
    die "private cleanup failure hook did not record one transaction root"
  residue="$(find -- "$parent" -mindepth 1 -maxdepth 1 \
    -name '.retained-projection-transaction.*' -print -quit)"
  [[ -n "$residue" && -d "$residue" && ! -L "$residue" ]] ||
    die "private cleanup failure did not exercise retained transaction state"
  [[ "${cleanup_failures[0]}" == "$residue" ]] ||
    die "private cleanup failure hook did not target the retained transaction root"
  acceptance_revision="$(awk -F= '$1 == "revision" { print $2 }' \
    "$residue/acceptance/${acceptance##*/}/environment.txt")"
  assertion_revision="$(awk -F= '$1 == "revision" { print $2 }' \
    "$residue/assertion/${assertion##*/}/environment.txt")"
  [[ "$acceptance_revision" =~ ^[0-9a-f]{40}$ &&
    "$assertion_revision" =~ ^[0-9a-f]{40}$ &&
    "$acceptance_revision" == "$assertion_revision" ]] ||
    die "retained private cleanup snapshots have invalid source revisions"
  printf 'raw v3 evidence verified: %s (acceptance, checkout commit %s)\nraw v3 evidence verified: %s (assertion-failure, checkout commit %s)\n' \
    "${acceptance##*/}" "$acceptance_revision" \
    "${assertion##*/}" "$assertion_revision" \
    >"$expected_stdout"
  if grep -F 'bounded claim evidence published:' \
    "$parent/projector.stdout" >/dev/null; then
    die "private cleanup failure printed a publication success result"
  fi
  cmp -s -- "$expected_stdout" "$parent/projector.stdout" ||
    die "private cleanup failure stdout was not the two private verification receipts"
  "$REAL_CHMOD" -R u+rwX -- "$residue"
  "$REAL_RM" -rf -- "$residue"
  assert_no_transaction_residue "$output"

  mkdir -m 0700 -- "$cleanup_state"
  printf 'external projector cleanup sentinel\n' >"$sentinel"
  chmod 0400 -- "$sentinel"
  sentinel_digest="$(sha256sum <"$sentinel")"
  sentinel_digest="${sentinel_digest%% *}"
  sentinel_mode="$(stat -Lc '%a' -- "$sentinel")"
  env PATH="$shim_directory:$PATH" \
    PROJECTOR_TEST_PUBLICATION_MODE=hardlink-cleanup \
    PROJECTOR_TEST_OUTPUT_PATH="$hardlink_output" \
    PROJECTOR_TEST_CLEANUP_STATE="$cleanup_state" \
    PROJECTOR_TEST_CLEANUP_LOG="$cleanup_log" \
    PROJECTOR_TEST_CLEANUP_SENTINEL="$sentinel" \
    PROJECTOR_TEST_REAL_LN="$(command -v ln)" \
    PROJECTOR_TEST_REAL_READLINK="$REAL_READLINK" \
    "$projector" "$acceptance" "$assertion" "$runbook" "$hardlink_output" \
    >/dev/null || die "projector could not safely unlink an injected hardlink"
  [[ -s "$cleanup_log" ]] || die "projector hardlink cleanup hook did not run"
  residue="$(<"$cleanup_log")"
  [[ ! -e "$residue" && ! -L "$residue" ]] ||
    die "projector retained its transaction after safe hardlink cleanup"
  [[ "$(stat -Lc '%a' -- "$sentinel")" == "$sentinel_mode" ]] ||
    die "projector cleanup changed an external hardlink sentinel mode"
  observed_digest="$(sha256sum <"$sentinel")"
  observed_digest="${observed_digest%% *}"
  [[ "$observed_digest" == "$sentinel_digest" ]] ||
    die "projector cleanup changed external hardlink sentinel content"
  "$verifier" --claims-v1 "$hardlink_output" >/dev/null
  assert_sealed_output "$hardlink_output"
}

test_raw_source_owner_contract() {
  local -r projector="$1"
  local -r verifier="$2"
  local -r acceptance="$3"
  local -r assertion="$4"
  local -r runbook="$5"
  local -r parent="$TEST_TMP_DIR/source-owner-contract"
  local -r shim_directory="$parent/bin"
  local -r root_output="$parent/root-owner-public-v3"
  local -r wrong_output="$parent/wrong-owner-public-v3"
  local -r target="$acceptance/environment.txt"
  local wrong_owner=""

  mkdir -m 0700 -- "$parent" "$shim_directory"
  write_source_owner_stat_wrapper \
    "$shim_directory/stat" "$REAL_STAT" "$REAL_READLINK"
  env PATH="$shim_directory:$PATH" \
    PROJECTOR_TEST_OWNER_PATH="$target" PROJECTOR_TEST_SOURCE_OWNER=0 \
    "$verifier" --raw-v3 acceptance "$acceptance" >/dev/null
  env PATH="$shim_directory:$PATH" \
    PROJECTOR_TEST_OWNER_PATH="$target" PROJECTOR_TEST_SOURCE_OWNER=0 \
    "$projector" "$acceptance" "$assertion" "$runbook" "$root_output" >/dev/null
  "$verifier" --claims-v1 "$root_output" >/dev/null
  assert_sealed_output "$root_output"
  wrong_owner="$((EUID + 1))"
  expect_failure_without_output \
    'a raw source file owned by neither root nor the invoking user' \
    'raw input is unsafe or exceeds its budget' \
    "$wrong_output" "$parent/wrong-owner-projector" \
    env PATH="$shim_directory:$PATH" \
      PROJECTOR_TEST_OWNER_PATH="$target" \
      PROJECTOR_TEST_SOURCE_OWNER="$wrong_owner" \
      "$projector" "$acceptance" "$assertion" "$runbook" "$wrong_output"
}

run_selected_cases() {
  local -i first_ordinal="$1"
  local -i last_ordinal="$2"
  local -r projector="$3"
  local -r verifier="$4"
  local -r acceptance="$5"
  local -r assertion="$6"
  local -r runbook="$7"
  local -r publication_shim="$8"
  local -i ordinal=0
  local -i executed=0
  local case_name=""

  for ((ordinal = first_ordinal; ordinal <= last_ordinal; ordinal++)); do
    case_name="${TEST_CASES[ordinal - 1]}"
    printf 'projector test case %02d/%02d: %s\n' \
      "$ordinal" "${#TEST_CASES[@]}" "$case_name" >&2
    case "$case_name" in
      cli)
        test_cli "$projector"
        ;;
      success-and-determinism)
        test_success_and_determinism \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook"
        ;;
      public-claim-mutations)
        test_public_claim_mutations \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook"
        ;;
      private-text-canonicality)
        test_private_text_canonicality \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook"
        ;;
      authority-mismatch)
        test_authority_mismatch \
          "$projector" "$acceptance" "$assertion" "$runbook"
        ;;
      official-agent-authority-mismatch)
        test_official_agent_authority_mismatch \
          "$projector" "$acceptance" "$assertion" "$runbook"
        ;;
      runbook-cleanup-mismatch)
        test_runbook_cleanup_mismatch \
          "$projector" "$acceptance" "$assertion" "$runbook"
        ;;
      existing-output-no-clobber)
        test_existing_output_no_clobber \
          "$projector" "$acceptance" "$assertion" "$runbook"
        ;;
      symlink-input)
        test_symlink_input \
          "$projector" "$acceptance" "$assertion" "$runbook"
        ;;
      sparse-input-preflight)
        test_sparse_input_preflight \
          "$projector" "$acceptance" "$assertion" "$runbook"
        ;;
      sparse-runbook-preflight)
        test_sparse_runbook_preflight \
          "$projector" "$acceptance" "$assertion"
        ;;
      opening-chmod-failure)
        test_opening_chmod_failure \
          "$projector" "$acceptance" "$assertion" "$runbook" \
          "$publication_shim"
        ;;
      move-failure-before-side-effect)
        test_move_failure_before_side_effect \
          "$projector" "$acceptance" "$assertion" "$runbook" \
          "$publication_shim"
        ;;
      move-failure-after-side-effect)
        test_move_failure_after_side_effect \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook" \
          "$publication_shim"
        ;;
      post-move-identity-drift)
        test_post_move_identity_drift \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook" \
          "$publication_shim"
        ;;
      reseal-chmod-failure)
        test_reseal_chmod_failure \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook" \
          "$publication_shim"
        ;;
      post-move-verifier-failure)
        test_post_move_verifier_failure \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook"
        ;;
      private-cleanup-failure)
        test_private_cleanup_failure \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook" \
          "$publication_shim"
        ;;
      raw-source-owner-contract)
        test_raw_source_owner_contract \
          "$projector" "$verifier" "$acceptance" "$assertion" "$runbook"
        ;;
      *)
        die "internal error: no implementation for test case $ordinal ($case_name)"
        ;;
    esac
    executed=$((executed + 1))
  done
  ((executed == last_ordinal - first_ordinal + 1)) ||
    die "internal error: selected test-case range was not executed exactly once"
}

main() {
  local -r repository="$TEST_TMP_DIR/repository"
  local -r fixture_scripts="$repository/examples/apache-java-https/scripts"
  local -r fixture_projector="$fixture_scripts/project-retained-acceptance-evidence.sh"
  local -r fixture_verifier="$fixture_scripts/verify-retained-evidence.sh"
  local -r fixture_real_verifier="$fixture_scripts/verify-retained-evidence.real.sh"
  local -r fixture_agent_download="$fixture_scripts/download-agent.sh"
  local -r acceptance="$TEST_TMP_DIR/private-acceptance"
  local -r assertion="$TEST_TMP_DIR/private-assertion"
  local -r runbook="$TEST_TMP_DIR/runbook-receipt.json"
  local -r publication_shim="$TEST_TMP_DIR/publication-bin"
  local selected_range=""
  local -i first_ordinal=1
  local -i last_ordinal="${#TEST_CASES[@]}"
  local revision=""

  if [[ "${1:-}" == --list-cases ]]; then
    (($# == 1)) || usage_error "--list-cases accepts no other arguments"
    list_cases
    return 0
  fi
  selected_range="$(parse_case_range "$@")"
  IFS=$'\t' read -r first_ordinal last_ordinal <<<"$selected_range"
  check_dependencies
  assert_no_invalid_jq_generator_binders
  assert_tls_boundary_jq_filter_compiles
  assert_jq_generator_context_semantics
  umask 077
  REAL_SHA256SUM="$(command -v sha256sum)"
  REAL_CHMOD="$(command -v chmod)"
  REAL_MV="$(command -v mv)"
  REAL_RM="$(command -v rm)"
  REAL_STAT="$(command -v stat)"
  REAL_READLINK="$(command -v readlink)"
  [[ "$REAL_SHA256SUM" == /* && -x "$REAL_SHA256SUM" &&
    "$REAL_CHMOD" == /* && -x "$REAL_CHMOD" &&
    "$REAL_MV" == /* && -x "$REAL_MV" &&
    "$REAL_RM" == /* && -x "$REAL_RM" &&
    "$REAL_STAT" == /* && -x "$REAL_STAT" &&
    "$REAL_READLINK" == /* && -x "$REAL_READLINK" ]] ||
    die "could not resolve the real filesystem commands"

  git init --quiet "$repository"
  git -C "$repository" config user.email 'retained-projection-test@example.invalid'
  git -C "$repository" config user.name 'Retained Projection Test'
  git -C "$repository" config commit.gpgSign false
  mkdir -p -- "$fixture_scripts" "$repository/.github/workflows"
  cp -- "$PROJECTOR_SOURCE" "$fixture_projector"
  cp -- "$VERIFIER_SOURCE" "$fixture_real_verifier"
  cp -- "$AGENT_DOWNLOAD_SOURCE" "$fixture_agent_download"
  chmod 0755 -- \
    "$fixture_projector" "$fixture_real_verifier" "$fixture_agent_download"
  write_verifier_wrapper "$fixture_verifier"
  printf '%s\n' 'name: synthetic acceptance claims' \
    >"$repository/.github/workflows/java_remote_parent_acceptance_claims.yml"
  printf 'tested source\n' >"$repository/source.txt"
  commit_fixture "$repository" 'Create synthetic projector authority'
  revision="$(git -C "$repository" rev-parse HEAD)"
  build_private_inputs \
    "$repository" "$revision" "$acceptance" "$assertion" "$runbook"
  mkdir -m 0700 -- "$publication_shim"
  write_publication_chmod_wrapper \
    "$publication_shim/chmod" "$REAL_CHMOD"
  write_publication_mv_wrapper \
    "$publication_shim/mv" "$REAL_MV" "$REAL_RM" "$REAL_CHMOD"
  write_cleanup_rm_wrapper "$publication_shim/rm" "$REAL_RM"

  run_selected_cases \
    "$first_ordinal" "$last_ordinal" \
    "$fixture_projector" "$fixture_real_verifier" \
    "$acceptance" "$assertion" "$runbook" "$publication_shim"

  if ((first_ordinal == 1 && last_ordinal == ${#TEST_CASES[@]})); then
    printf 'project-retained-acceptance-evidence success and fail-closed tests passed\n'
  else
    printf 'project-retained-acceptance-evidence cases %02d-%02d passed\n' \
      "$first_ordinal" "$last_ordinal"
  fi
}

TEST_TMP_DIR="$(mktemp -d)"
main "$@"
