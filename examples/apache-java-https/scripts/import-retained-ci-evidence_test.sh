#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$SCRIPT_DIRECTORY/import-retained-ci-evidence.sh"
trap - EXIT HUP INT TERM ERR DEBUG RETURN QUIT ALRM

TEST_ROOT=''
TEST_NESTED_RUNNER_DIRECTORY=''
TEST_NESTED_RUNNER_LOG=''
REBOUND_ROOT=''
REAL_BASH="$(command -v bash)"
readonly REAL_BASH
readonly ORIGINAL_PATH="$PATH"
readonly ACCEPTANCE_PROJECTOR="$SCRIPT_DIRECTORY/project-retained-acceptance-evidence.sh"
readonly FAULT_SECURITY_PROJECTOR="$SCRIPT_DIRECTORY/project-retained-fault-security-matrix.sh"
readonly EXPECTED_ACCEPTANCE_V1_VERIFIER_SHA256='376907ef806b4fdbdc971dde6d4a6f968476c64b237900d80a80dcd8d83e6f8b'
readonly EXPECTED_ACCEPTANCE_VERIFIER_SHA256='2511f18ed4961eea9f979a6fd8bad9ee973ce768adecaebcf0dea31b9aaa8e7d'
readonly EXPECTED_FAULT_SECURITY_VERIFIER_SHA256='6f8dabcca0235c585c40c85ffeb978c139eef1a51ba56c40506f61ded58bc027'
readonly EXPECTED_V2_WRAPPER_VERIFIER_SHA256='84af02437538669549f9c4dde0cbe83373762520154305b418ecd785e024197d'

test_cleanup() {
  if [[ -n "$TEST_ROOT" && -d "$TEST_ROOT" && ! -L "$TEST_ROOT" &&
    "$TEST_ROOT" == /tmp/obi-retained-ci-import-test.* ]]; then
    chmod -R u+rwX -- "$TEST_ROOT" >/dev/null 2>&1 || true
    find -- "$TEST_ROOT" -xdev -depth -delete >/dev/null 2>&1 || true
  fi
}
trap test_cleanup EXIT HUP INT TERM

fail() {
  printf 'import-retained-ci-evidence_test.sh: %s\n' "$*" >&2
  return 1
}

test_trusted_clean_exec_rejects_local_poison() (
  local -r importer="$SCRIPT_DIRECTORY/import-retained-ci-evidence.sh"
  local -r child_code='source "$1"; trap - EXIT HUP INT TERM ERR DEBUG RETURN QUIT ALRM; trusted_clean_exec /usr/bin/false'

  if (
    function local() { exit 0; }
    trusted_clean_exec /usr/bin/false
  ); then
    fail 'same-shell local function bypassed the clean execution boundary'
  fi

  if "$REAL_BASH" --noprofile --norc -c '
    function local() { exit 0; }
    export -f local
    exec "$1" --noprofile --norc -c "$2" clean-bootstrap-child "$3"
  ' clean-bootstrap-parent "$REAL_BASH" "$child_code" "$importer"; then
    fail 'exported local function bypassed the clean execution boundary'
  fi
)

prepare_nested_verifier_runner() {
  # The nested verifier projects have their own semantic suites. These importer
  # fixtures assert their exact bytes, then isolate only the wrapper handoff.
  TEST_NESTED_RUNNER_DIRECTORY="$TEST_ROOT/nested-verifier-runner"
  mkdir -m 0700 -- "$TEST_NESTED_RUNNER_DIRECTORY"
  cat >"$TEST_NESTED_RUNNER_DIRECTORY/bash" <<'RUNNER'
#!/usr/bin/bash
set -Eeuo pipefail
case "${1:-}" in
  */acceptance/verify.sh|*/fault-security/verify.sh)
    [[ $# == 1 && -f "$1" ]]
    printf '%s\n' "$1" >>"${IMPORT_TEST_NESTED_RUNNER_LOG:?}"
    exit 0
    ;;
esac
exec "${IMPORT_TEST_REAL_BASH:?}" "$@"
RUNNER
  chmod 0700 -- "$TEST_NESTED_RUNNER_DIRECTORY/bash"
  TEST_NESTED_RUNNER_LOG="$TEST_ROOT/nested-verifier-runs.log"
  : >"$TEST_NESTED_RUNNER_LOG"
  chmod 0600 -- "$TEST_NESTED_RUNNER_LOG"
  PATH="$TEST_NESTED_RUNNER_DIRECTORY:$ORIGINAL_PATH"
  IMPORT_TEST_REAL_BASH="$REAL_BASH"
  IMPORT_TEST_NESTED_RUNNER_LOG="$TEST_NESTED_RUNNER_LOG"
  export PATH IMPORT_TEST_REAL_BASH IMPORT_TEST_NESTED_RUNNER_LOG
  hash -r
}

run_portable_verifier() {
  local -r root="$1"
  "$REAL_BASH" "$root/verify.sh"
}

run_write_bundle() {
  write_bundle "$@"
}

run_verify_nested_bundles() {
  verify_nested_bundles "$@"
}

configure_test_source_verifier_authority() {
  local -r source="$1"
  local digest=''

  # These sourced-script globals bind the verifier used by the production
  # launcher; ShellCheck cannot see that cross-file consumption.
  # shellcheck disable=SC2034
  SOURCE_VERIFIER_PATH="$source"
  digest="$(sha256sum <"$source")" || return 1
  # shellcheck disable=SC2034
  SOURCE_VERIFIER_SHA256="${digest%% *}"
  HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
}

candidate_seal_from_path() {
  local -r path="$1"
  local descriptor=''
  local seal=''
  exec {descriptor}<"$path" || return 1
  seal="$(capture_candidate_publication_seal "$descriptor")" || {
    exec {descriptor}<&-
    return 1
  }
  exec {descriptor}<&-
  printf '%s\n' "$seal"
}

one_hidden_candidate() {
  local -r output_parent="$1"
  local -a candidates=()
  mapfile -d '' -t candidates < <(find -- "$output_parent" -mindepth 1 \
    -maxdepth 1 -name '.retained-ci-import.*' -print0)
  ((${#candidates[@]} == 1)) || return 1
  printf '%s\n' "${candidates[0]}"
}

bundle_test_output() {
  local -r fixture="$1"
  local -r output_parent="$2"
  local acceptance_receipt=''
  local fault_receipt=''
  local evidence=''

  acceptance_receipt="$(sha256sum \
    <"$fixture/acceptance/derivation-receipt.json")"
  acceptance_receipt="${acceptance_receipt%% *}"
  fault_receipt="$(sha256sum \
    <"$fixture/fault-security/derivation-receipt.json")"
  fault_receipt="${fault_receipt%% *}"
  evidence="$(printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    123 2 "$acceptance_receipt" "$fault_receipt" | sha256sum)"
  evidence="${evidence%% *}"
  printf '%s/retained-claims-aaaaaaaaaaaa-%s\n' \
    "$output_parent" "${evidence:0:12}"
}

configure_write_bundle_test_authority() {
  local -r output="$1"

  # These globals are consumed by the sourced write_bundle implementation.
  # shellcheck disable=SC2034
  HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  # shellcheck disable=SC2034
  SOURCE_TREE_SHA256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  # shellcheck disable=SC2034
  WORKFLOW_BLOB_SHA256="$(sha256sum <"$REPOSITORY_ROOT/$WORKFLOW_PATH")"
  WORKFLOW_BLOB_SHA256="${WORKFLOW_BLOB_SHA256%% *}"
  # shellcheck disable=SC2034
  RUN_ID=123
  # shellcheck disable=SC2034
  RUN_ATTEMPT=2
  validate_output_parent "$output"
  # shellcheck disable=SC2034
  ACCEPTANCE_ARTIFACT="$(jq -cn --arg head "$HEAD_SHA" --arg branch "$BRANCH" '{
    id:1,name:"java-remote-parent-acceptance-claims-123-2",size_in_bytes:100,
    expired:false,expires_at:"2026-11-18T00:00:00Z",
    digest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    workflow_run:{id:123,head_sha:$head,head_branch:$branch}}')"
  # shellcheck disable=SC2034
  FAULT_ARTIFACT="$(jq -cn --arg head "$HEAD_SHA" --arg branch "$BRANCH" '{
    id:2,name:"java-remote-parent-fault-security-123-2",size_in_bytes:100,
    expired:false,expires_at:"2026-11-18T00:00:00Z",
    digest:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    workflow_run:{id:123,head_sha:$head,head_branch:$branch}}')"
}

write_pinned_nested_verifiers() {
  local -r root="$1"
  local -r claims_version="${2:-2}"
  local work=''
  local observed=''
  local expected_acceptance_sha256=''

  case "$claims_version" in
    1) expected_acceptance_sha256="$EXPECTED_ACCEPTANCE_V1_VERIFIER_SHA256" ;;
    2) expected_acceptance_sha256="$EXPECTED_ACCEPTANCE_VERIFIER_SHA256" ;;
    *) return 1 ;;
  esac

  work="$(mktemp -d "$TEST_ROOT/nested-verifier-work.XXXXXX")"
  # shellcheck disable=SC2016
  CLAIM_PROJECTOR="$ACCEPTANCE_PROJECTOR" CLAIM_OUTPUT="$root/acceptance" \
    CLAIM_WORK="$work" CLAIMS_VERSION_INPUT="$claims_version" \
    "$REAL_BASH" -c '
      source <(head -n -1 -- "$CLAIM_PROJECTOR")
      trap - EXIT HUP INT TERM
      CANDIDATE_DIRECTORY="$CLAIM_OUTPUT"
      WORK_DIRECTORY="$CLAIM_WORK"
      CLAIMS_VERSION="$CLAIMS_VERSION_INPUT"
      if [[ "$CLAIMS_VERSION" == 1 ]]; then
        write_portable_claim_verifier
      else
        write_portable_claim_verifier_v2
      fi
    '
  # shellcheck disable=SC2016
  FAULT_PROJECTOR="$FAULT_SECURITY_PROJECTOR" \
    FAULT_OUTPUT="$root/fault-security/verify.sh" "$REAL_BASH" -c '
      source <(head -n -1 -- "$FAULT_PROJECTOR")
      trap - EXIT HUP INT TERM
      write_portable_verifier "$FAULT_OUTPUT"
    '
  observed="$(sha256sum <"$root/acceptance/verify.sh")"
  [[ "${observed%% *}" == "$expected_acceptance_sha256" ]] ||
    fail "current claims-v$claims_version projector emitted unexpected portable verifier bytes"
  observed="$(sha256sum <"$root/fault-security/verify.sh")"
  [[ "${observed%% *}" == "$EXPECTED_FAULT_SECURITY_VERIFIER_SHA256" ]] ||
    fail 'current fault-security projector emitted unexpected portable verifier bytes'
}

expect_reject() {
  local -r label="$1"
  shift
  if ("$@") >/dev/null 2>&1; then
    fail "accepted mutation: $label"
  fi
}

zip_artifact_json() {
  local -r archive="$1"
  local digest=''
  local size=''
  digest="$(sha256sum <"$archive")"; digest="${digest%% *}"
  size="$(stat -Lc '%s' -- "$archive")"
  jq -cn --arg digest "sha256:$digest" --argjson size "$size" \
    '{digest:$digest,size_in_bytes:$size}'
}

make_zip() {
  local -r archive="$1"
  local -r kind="$2"
  python3 - "$archive" "$kind" <<'PY'
import stat
import sys
import warnings
import zipfile

archive, kind = sys.argv[1:]
warnings.filterwarnings("ignore", message="Duplicate name:.*")
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
    if kind in ("valid", "confused"):
        output.writestr("README.md", ("safe\n" if kind == "valid" else "confused\n"))
        output.writestr("verify.sh", "#!/usr/bin/env bash\nexit 0\n")
    elif kind == "traversal":
        output.writestr("../escape", "bad\n")
    elif kind == "duplicate":
        output.writestr("same", "one\n")
        output.writestr("same", "two\n")
    elif kind in ("symlink", "fifo"):
        info = zipfile.ZipInfo("member")
        mode = stat.S_IFLNK | 0o777 if kind == "symlink" else stat.S_IFIFO | 0o600
        info.create_system = 3
        info.external_attr = mode << 16
        output.writestr(info, "target")
    elif kind == "overcap":
        output.writestr("large", b"x" * 2097153)
    else:
        raise ValueError(kind)
PY
  chmod 0600 -- "$archive"
}

test_duplicate_json_keys() {
  local file="$TEST_ROOT/duplicate.json"
  printf '%s\n' '{"id":1,"id":2}' >"$file"
  chmod 0600 -- "$file"
  expect_reject 'duplicate JSON keys' reject_duplicate_json_keys "$file"
}

test_zip_guards() {
  local kind=''
  local archive=''
  local destination=''
  local artifact=''

  archive="$TEST_ROOT/valid.zip"
  make_zip "$archive" valid
  artifact="$(zip_artifact_json "$archive")"
  destination="$TEST_ROOT/valid-output"
  extract_archive acceptance "$archive" "$artifact" "$destination" ||
    fail 'valid bounded ZIP was rejected'
  [[ "$(find -- "$destination" -type f -printf '%f\n' | LC_ALL=C sort)" == \
    $'README.md\nverify.sh' ]] || fail 'valid ZIP extraction inventory changed'

  for kind in traversal duplicate symlink fifo overcap; do
    archive="$TEST_ROOT/$kind.zip"
    destination="$TEST_ROOT/$kind-output"
    make_zip "$archive" "$kind"
    artifact="$(zip_artifact_json "$archive")"
    expect_reject "ZIP $kind" extract_archive acceptance "$archive" \
      "$artifact" "$destination"
  done
  archive="$TEST_ROOT/digest.zip"
  make_zip "$archive" valid
  artifact="$(zip_artifact_json "$archive" | jq -c \
    '.digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"')"
  expect_reject 'artifact digest confusion' extract_archive acceptance "$archive" \
    "$artifact" "$TEST_ROOT/digest-output"

  archive="$TEST_ROOT/pinned.zip"
  local replacement="$TEST_ROOT/replacement.zip"
  make_zip "$archive" valid
  make_zip "$replacement" confused
  artifact="$(zip_artifact_json "$archive")"
  extract_archive_checkpoint() {
    mv -- "$archive" "$TEST_ROOT/pinned-original.zip"
    cp -- "$replacement" "$archive"
    chmod 0600 -- "$archive"
  }
  extract_archive acceptance "$archive" "$artifact" "$TEST_ROOT/pinned-output" ||
    fail 'descriptor-pinned archive rejected its authenticated bytes'
  [[ "$(<"$TEST_ROOT/pinned-output/README.md")" == safe ]] ||
    fail 'atomic archive replacement confused the authenticated payload'
  extract_archive_checkpoint() { :; }
}

write_run_json() {
  local -r file="$1"
  jq -cS -n --arg head "$HEAD_SHA" --arg branch "$BRANCH" \
    --arg repository "$REPOSITORY" --arg path "$WORKFLOW_PATH" '{
      id:123,run_attempt:2,event:"push",head_branch:$branch,head_sha:$head,
      status:"completed",conclusion:"success",path:$path,
      repository:{full_name:$repository},head_repository:{full_name:$repository},
      html_url:("https://github.com/"+$repository+"/actions/runs/123")}' >"$file"
  chmod 0600 -- "$file"
}

write_artifact_json() {
  local -r file="$1"
  local role=''
  local -a names=(
    "java-remote-parent-acceptance-claims-123-2"
    "java-remote-parent-fault-security-123-2"
    "java-remote-parent-fault-security-cell-all-getsockopt-123-2"
    "java-remote-parent-fault-security-cell-all-unix-123-2"
    "java-remote-parent-fault-security-cell-all-auto-123-2"
    "java-remote-parent-fault-security-cell-pid-reuse-getsockopt-123-2"
    "java-remote-parent-fault-security-cell-pid-reuse-unix-123-2"
  )
  : >"$TEST_ROOT/artifact-rows"
  local index=0
  for role in "${names[@]}"; do
    jq -cn --arg name "$role" --arg head "$HEAD_SHA" --arg branch "$BRANCH" \
      --argjson id "$((index + 1))" '{id:$id,name:$name,size_in_bytes:100,
        expired:false,expires_at:"2026-11-18T00:00:00Z",
        digest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        workflow_run:{id:123,head_sha:$head,head_branch:$branch}}' \
      >>"$TEST_ROOT/artifact-rows"
    ((index += 1))
  done
  jq -cS -s '{total_count:length,artifacts:.}' "$TEST_ROOT/artifact-rows" >"$file"
  chmod 0600 -- "$file"
}

test_api_identity_guards() {
  local run="$TEST_ROOT/run.json"
  local artifacts="$TEST_ROOT/artifacts.json"
  local replacement="$TEST_ROOT/run-replacement.json"
  local snapshot="$TEST_ROOT/run-snapshot.json"
  HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  write_run_json "$run"
  validate_run_json "$run" || fail 'valid completed run API JSON was rejected'
  jq -cS '.head_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$run" >"$run.tmp"
  chmod 0600 -- "$run.tmp"
  expect_reject 'run/source mismatch' validate_run_json "$run.tmp"
  jq -cS '.conclusion="failure"' "$run" >"$run.tmp"
  expect_reject 'non-success conclusion' validate_run_json "$run.tmp"
  jq -cS '.status="in_progress"|.conclusion=null' "$run" >"$run.tmp"
  expect_reject 'same-run or otherwise in-progress promotion' \
    validate_run_json "$run.tmp"

  jq -cS '.conclusion="failure"' "$run" >"$replacement"
  chmod 0600 -- "$replacement"
  snapshot_input_checkpoint() {
    local -r checkpoint_source="$1"
    [[ "$checkpoint_source" == "$run" ]] || return 0
    mv -- "$run" "$TEST_ROOT/run-original.json"
    cp -- "$replacement" "$run"
    chmod 0600 -- "$run"
  }
  snapshot_owned_regular "$run" "$MAX_API_BYTES" "$snapshot" ||
    fail 'descriptor-pinned API snapshot failed'
  validate_run_json "$snapshot" ||
    fail 'atomic API replacement changed descriptor-pinned bytes'
  expect_reject 'replacement API pathname after descriptor pin' validate_run_json "$run"
  snapshot_input_checkpoint() { :; }

  # These globals are consumed by sourced validator functions.
  # shellcheck disable=SC2034
  RUN_ID=123
  # shellcheck disable=SC2034
  RUN_ATTEMPT=2
  write_artifact_json "$artifacts"
  validate_artifact_json "$artifacts" || fail 'valid exact artifact set was rejected'
  jq -cS '.artifacts[6].name=.artifacts[5].name' "$artifacts" >"$artifacts.tmp"
  chmod 0600 -- "$artifacts.tmp"
  expect_reject 'duplicate artifact role' validate_artifact_json "$artifacts.tmp"
  jq -cS '.artifacts[0].workflow_run.head_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    "$artifacts" >"$artifacts.tmp"
  expect_reject 'artifact/source mismatch' validate_artifact_json "$artifacts.tmp"
}

build_wrapper_fixture() {
  local -r root="$1"
  local -r claims_version="${2:-1}"
  local head=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local evidence=''
  local file=''
  [[ "$claims_version" == 1 || "$claims_version" == 2 ]] || return 1
  mkdir -p -- "$root/acceptance" "$root/fault-security"
  for file in README.md SANITIZATION.md acceptance-claims.json \
    authority-summary.json derivation-receipt.json SHA256SUMS; do
    printf '{}\n' >"$root/acceptance/$file"
  done
  for file in README.md SANITIZATION.md fault-security-matrix.json \
    derivation-receipt.json SHA256SUMS; do
    printf '{}\n' >"$root/fault-security/$file"
  done
  write_pinned_nested_verifiers "$root" "$claims_version"
  local acceptance_receipt=''
  local fault_receipt=''
  acceptance_receipt="$(sha256sum <"$root/acceptance/derivation-receipt.json")"
  acceptance_receipt="${acceptance_receipt%% *}"
  fault_receipt="$(sha256sum <"$root/fault-security/derivation-receipt.json")"
  fault_receipt="${fault_receipt%% *}"
  evidence="$(printf '%s\n' "$head" 123 2 "$acceptance_receipt" \
    "$fault_receipt" | sha256sum)"
  evidence="${evidence%% *}"
  jq -cS -n --arg head "$head" '{source:{revision:$head,
    tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
    execution_locator:{head_sha:$head}}' >"$root/acceptance/authority-summary.json"
  if [[ "$claims_version" == 1 ]]; then
    jq -cS -n '{schema:"obi-bounded-acceptance-claims-v1",status:"passed",
      issue_32:{},issue_34:{}}' >"$root/acceptance/acceptance-claims.json"
    jq -cS -n --arg head "$head" '{
      schema:"obi-bounded-fault-security-matrix-v1",status:"passed",
      source:{revision:$head,
        source_tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
      coverage:{issue_36:{status:"passed"},issue_40:{status:"passed"}}}' \
      >"$root/fault-security/fault-security-matrix.json"
  else
    jq -cS -n '{schema:"obi-bounded-acceptance-claims-v2",status:"passed",
      issue_32:{},issue_34:{},issue_36:{status:"passed"}}' \
      >"$root/acceptance/acceptance-claims.json"
    jq -cS -n --arg head "$head" '{
      schema:"obi-bounded-fault-security-matrix-v1",status:"passed",
      source:{revision:$head,
        source_tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
      coverage:{issue_36:{status:"passed"},issue_40:{status:"passed"}}}' \
      >"$root/fault-security/fault-security-matrix.json"
  fi
  jq -cS -n --arg head "$head" '{schema:"obi-retained-ci-run-identity-v1",
    status:"passed",repository:"MrAlias/opentelemetry-ebpf-instrumentation",
    event:"push",ref:"refs/heads/agent/java-remote-parent-bridge",head_sha:$head,
    source_tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    run_id:"123",run_attempt:"2",conclusion:"success",
    run_url:"https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/123/attempts/2",
    workflow:{path:".github/workflows/java_remote_parent_acceptance_claims.yml",
      name:"Java remote-parent bounded acceptance claims",
      ref:"MrAlias/opentelemetry-ebpf-instrumentation/.github/workflows/java_remote_parent_acceptance_claims.yml@refs/heads/agent/java-remote-parent-bridge",
      sha:$head,
      blob_sha256:"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
    artifacts:[{role:"acceptance",id:"1",name:"java-remote-parent-acceptance-claims-123-2",
        expired:false,expires_at:"2026-11-18T00:00:00Z",size_in_bytes:100,
        run_id:"123",head_branch:"agent/java-remote-parent-bridge",head_sha:$head,
        digest:"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
      {role:"fault-security",id:"2",name:"java-remote-parent-fault-security-123-2",
        expired:false,expires_at:"2026-11-18T00:00:00Z",size_in_bytes:100,
        run_id:"123",head_branch:"agent/java-remote-parent-bridge",head_sha:$head,
        digest:"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}' \
    >"$root/run-identity.json"
  if [[ "$claims_version" == 1 ]]; then
    jq -cS -n --arg evidence "$evidence" --arg head "$head" '{
      schema:"obi-retained-ci-claim-index-v1",status:"passed",evidence_id:$evidence,
      source:{revision:$head,tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
      coverage:{issue_32:{pointer:"acceptance/acceptance-claims.json#/issue_32",status:"passed"},
        issue_34:{pointer:"acceptance/acceptance-claims.json#/issue_34",status:"passed"},
        issue_36:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_36",status:"passed"},
        issue_40:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40",status:"passed"}}}' \
      >"$root/claim-index.json"
    write_portable_verifier "$root/verify.sh"
  else
    jq -cS -n --arg evidence "$evidence" --arg head "$head" '{
      schema:"obi-retained-ci-claim-index-v2",status:"passed",evidence_id:$evidence,
      source:{revision:$head,tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
      coverage:{issue_32:{pointer:"acceptance/acceptance-claims.json#/issue_32",status:"passed"},
        issue_34:{pointer:"acceptance/acceptance-claims.json#/issue_34",status:"passed"},
        issue_36:{pointers:["acceptance/acceptance-claims.json#/issue_36",
          "fault-security/fault-security-matrix.json#/coverage/issue_36"],
          status:"passed"},
        issue_40:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40",status:"passed"}}}' \
      >"$root/claim-index.json"
    write_portable_verifier_v2 "$root/verify.sh"
  fi
  (CDPATH='' cd -- "$root" &&
    for file in run-identity.json claim-index.json verify.sh \
      acceptance/README.md acceptance/SANITIZATION.md acceptance/acceptance-claims.json \
      acceptance/authority-summary.json acceptance/derivation-receipt.json \
      acceptance/verify.sh acceptance/SHA256SUMS fault-security/README.md \
      fault-security/SANITIZATION.md fault-security/fault-security-matrix.json \
      fault-security/derivation-receipt.json fault-security/verify.sh \
      fault-security/SHA256SUMS; do sha256sum "$file"; done) >"$root/SHA256SUMS"
  chmod -R a-w -- "$root"
}

reseal_wrapper_claim_index() {
  local -r root="$1"
  local -r filter="$2"
  local candidate="$root/claim-index.json.next"

  chmod u+w -- "$root" "$root/claim-index.json" "$root/SHA256SUMS"
  jq -cS "$filter" "$root/claim-index.json" >"$candidate"
  mv -fT -- "$candidate" "$root/claim-index.json"
  (
    CDPATH='' cd -- "$root"
    sha256sum claim-index.json >SHA256SUMS.next
    awk '$2 != "claim-index.json"' SHA256SUMS >>SHA256SUMS.next
    mv -fT -- SHA256SUMS.next SHA256SUMS
  )
  chmod a-w -- "$root/claim-index.json" "$root/SHA256SUMS" "$root"
}

expect_index_mutation_rejected() {
  local -r label="$1"
  local -r baseline="$2"
  local -r mutation="$3"
  local -r filter="$4"
  local parent="$TEST_ROOT/index-mutations/$mutation"
  local root="$parent/${baseline##*/}"

  mkdir -p -- "$parent"
  cp -a -- "$baseline" "$root"
  reseal_wrapper_claim_index "$root" "$filter"
  expect_reject "$label" run_portable_verifier "$root"
}

omit_run_identity_checksum_entry() {
  local -r root="$1"
  local -r manifest="$root/SHA256SUMS"
  local duplicate_line=''
  local candidate="$root/SHA256SUMS.next"

  chmod u+w -- "$root" "$manifest"
  duplicate_line="$(awk '
    $2 == "acceptance/README.md" { print; matches++ }
    END { if (matches != 1) exit 1 }
  ' "$manifest")"
  awk -v duplicate="$duplicate_line" '
    $2 == "run-identity.json" { print duplicate; replaced++; next }
    { print }
    END { if (replaced != 1) exit 1 }
  ' "$manifest" >"$candidate"
  mv -fT -- "$candidate" "$manifest"
  [[ "$(awk 'END { print NR + 0 }' "$manifest")" == 16 &&
    "$(awk '$2 == "run-identity.json" { count++ }
      END { print count + 0 }' "$manifest")" == 0 &&
    "$(awk '$2 == "acceptance/README.md" { count++ }
      END { print count + 0 }' "$manifest")" == 2 ]]
  chmod a-w -- "$manifest" "$root"
}

reseal_nested_checksum_manifest() {
  local -r root="$1"
  local -r role="$2"
  local -r directory="$root/$role"
  local file=''
  local -a files=()

  case "$role" in
    acceptance)
      files=(README.md SANITIZATION.md acceptance-claims.json \
        authority-summary.json derivation-receipt.json verify.sh)
      ;;
    fault-security)
      files=(README.md SANITIZATION.md fault-security-matrix.json \
        derivation-receipt.json verify.sh)
      ;;
    *) return 1 ;;
  esac
  chmod u+w -- "$directory" "$directory/SHA256SUMS"
  (
    CDPATH='' cd -- "$directory"
    for file in "${files[@]}"; do
      sha256sum "$file"
    done
  ) >"$directory/SHA256SUMS.next"
  mv -fT -- "$directory/SHA256SUMS.next" "$directory/SHA256SUMS"
  [[ "$(awk 'END { print NR + 0 }' "$directory/SHA256SUMS")" == \
    "${#files[@]}" ]]
  (CDPATH='' cd -- "$directory" &&
    sha256sum --check --strict SHA256SUMS >/dev/null)
  chmod a-w -- "$directory/SHA256SUMS" "$directory"
}

reseal_outer_checksum_manifest() {
  local -r root="$1"
  local file=''
  local -a files=(
    run-identity.json claim-index.json verify.sh
    acceptance/README.md acceptance/SANITIZATION.md
    acceptance/acceptance-claims.json acceptance/authority-summary.json
    acceptance/derivation-receipt.json acceptance/verify.sh
    acceptance/SHA256SUMS fault-security/README.md
    fault-security/SANITIZATION.md fault-security/fault-security-matrix.json
    fault-security/derivation-receipt.json fault-security/verify.sh
    fault-security/SHA256SUMS
  )

  chmod u+w -- "$root" "$root/SHA256SUMS"
  (
    CDPATH='' cd -- "$root"
    for file in "${files[@]}"; do
      sha256sum "$file"
    done
  ) >"$root/SHA256SUMS.next"
  mv -fT -- "$root/SHA256SUMS.next" "$root/SHA256SUMS"
  [[ "$(awk 'END { print NR + 0 }' "$root/SHA256SUMS")" == \
    "${#files[@]}" ]]
  (CDPATH='' cd -- "$root" &&
    sha256sum --check --strict SHA256SUMS >/dev/null)
  chmod a-w -- "$root/SHA256SUMS" "$root"
}

rebind_wrapper_evidence_id() {
  local -r root="$1"
  local head=''
  local run_id=''
  local run_attempt=''
  local acceptance_receipt=''
  local fault_receipt=''
  local evidence=''
  local leaf=''
  local new_root=''
  local candidate=''

  head="$(jq -er '.head_sha' "$root/run-identity.json")"
  run_id="$(jq -er '.run_id' "$root/run-identity.json")"
  run_attempt="$(jq -er '.run_attempt' "$root/run-identity.json")"
  acceptance_receipt="$(sha256sum \
    <"$root/acceptance/derivation-receipt.json")"
  acceptance_receipt="${acceptance_receipt%% *}"
  fault_receipt="$(sha256sum \
    <"$root/fault-security/derivation-receipt.json")"
  fault_receipt="${fault_receipt%% *}"
  evidence="$(printf '%s\n' "$head" "$run_id" "$run_attempt" \
    "$acceptance_receipt" "$fault_receipt" | sha256sum)"
  evidence="${evidence%% *}"
  leaf="retained-claims-${head:0:12}-${evidence:0:12}"
  new_root="${root%/*}/$leaf"
  candidate="$root/claim-index.json.next"
  chmod u+w -- "$root" "$root/claim-index.json"
  jq -cS --arg evidence "$evidence" '.evidence_id = $evidence' \
    "$root/claim-index.json" >"$candidate"
  mv -fT -- "$candidate" "$root/claim-index.json"
  if [[ "$new_root" != "$root" ]]; then
    mv -T -- "$root" "$new_root"
  fi
  chmod a-w -- "$new_root/claim-index.json" "$new_root"
  REBOUND_ROOT="$new_root"
}

test_cli_version_routing() (
  local calls="$TEST_ROOT/cli-version-calls"
  local help=''

  claims_v1() { printf 'v1\t%s\n' "$*" >>"$calls"; }
  claims_v2() { printf 'v2\t%s\n' "$*" >>"$calls"; }
  help="$(main --help)" || fail 'importer help failed'
  [[ "$help" == *claims-v1* && "$help" == *claims-v2* ]] ||
    fail 'importer help omitted a claims version'
  main claims-v1 run artifacts acceptance fault /absolute-output
  main claims-v2 run artifacts acceptance fault /absolute-output
  [[ "$(<"$calls")" == $'v1\trun artifacts acceptance fault /absolute-output\nv2\trun artifacts acceptance fault /absolute-output' ]] ||
    fail 'importer CLI did not preserve exact v1/v2 routing'
  expect_reject 'unknown claims version' \
    main claims-v3 run artifacts acceptance fault /absolute-output
)

test_nested_claim_version_routing() (
  local v1_root="$TEST_ROOT/nested-v1"
  local v2_root="$TEST_ROOT/nested-v2"
  local missing_root="$TEST_ROOT/nested-v2-missing-issue36"
  local calls="$TEST_ROOT/nested-verifier-calls"

  build_wrapper_fixture "$v1_root" 1
  build_wrapper_fixture "$v2_root" 2
  HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  compute_source_tree_sha256() {
    printf '%s\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  }
  trusted_retained_verifier() {
    local -r mode="$1"
    local -r bundle="$2"
    printf '%s\t%s\n' "$mode" "$bundle" >>"$calls"
    case "$mode" in
      --claims-v1)
        jq -e '.schema == "obi-bounded-acceptance-claims-v1"' \
          "$bundle/acceptance-claims.json" >/dev/null
        ;;
      --claims-v2)
        jq -e '.schema == "obi-bounded-acceptance-claims-v2"' \
          "$bundle/acceptance-claims.json" >/dev/null
        ;;
      --fault-security-matrix-v1)
        jq -e '.schema == "obi-bounded-fault-security-matrix-v1"' \
          "$bundle/fault-security-matrix.json" >/dev/null
        ;;
      *) return 1 ;;
    esac
  }

  : >"$TEST_NESTED_RUNNER_LOG"
  run_verify_nested_bundles \
    "$v1_root/acceptance" "$v1_root/fault-security" 1 ||
    fail 'claims-v1 nested route failed'
  [[ ! -s "$TEST_NESTED_RUNNER_LOG" ]] ||
    fail 'claims-v1 importer directly executed an artifact verifier'
  : >"$TEST_NESTED_RUNNER_LOG"
  run_verify_nested_bundles \
    "$v2_root/acceptance" "$v2_root/fault-security" 2 ||
    fail 'claims-v2 nested route failed'
  [[ ! -s "$TEST_NESTED_RUNNER_LOG" ]] ||
    fail 'claims-v2 importer directly executed an artifact verifier'
  grep -Fqx -- $'--claims-v1\t'"$v1_root/acceptance" "$calls" ||
    fail 'claims-v1 did not select trusted --claims-v1 verification'
  grep -Fqx -- $'--claims-v2\t'"$v2_root/acceptance" "$calls" ||
    fail 'claims-v2 did not select trusted --claims-v2 verification'
  expect_reject 'claims-v1 route over a v2 acceptance bundle' \
    run_verify_nested_bundles \
      "$v2_root/acceptance" "$v2_root/fault-security" 1
  expect_reject 'claims-v2 route over a v1 acceptance bundle' \
    run_verify_nested_bundles \
      "$v1_root/acceptance" "$v1_root/fault-security" 2

  cp -a -- "$v2_root" "$missing_root"
  chmod u+w -- "$missing_root/acceptance" \
    "$missing_root/acceptance/acceptance-claims.json"
  jq -cS 'del(.issue_36)' "$missing_root/acceptance/acceptance-claims.json" \
    >"$missing_root/acceptance/acceptance-claims.json.next"
  mv -fT -- "$missing_root/acceptance/acceptance-claims.json.next" \
    "$missing_root/acceptance/acceptance-claims.json"
  expect_reject 'claims-v2 acceptance without issue_36' \
    run_verify_nested_bundles \
      "$missing_root/acceptance" "$missing_root/fault-security" 2
)

test_source_authority_rejects_git_object_replacements() (
  local parent="$TEST_ROOT/source-authority-git-replacements"
  local repository="$parent/repository"
  local scripts="$repository/examples/apache-java-https/scripts"
  local fixture_importer="$scripts/import-retained-ci-evidence.sh"
  local fixture_verifier="$scripts/verify-retained-evidence.sh"
  local original_verifier="$parent/original-verifier.sh"
  local forged_marker="$parent/forged-verifier-ran.marker"
  local fsmonitor_hook="$parent/fsmonitor-hook.sh"
  local fsmonitor_marker="$parent/fsmonitor-ran.marker"
  local filter_hook="$parent/filter-hook.sh"
  local filter_marker="$parent/filter-ran.marker"
  local validator_return_marker="$parent/validator-returned.marker"
  local config_backup="$parent/repository-config"
  local head_backup="$parent/repository-head"
  local unused_bundle="$parent/unused-bundle"
  local verifier_path='examples/apache-java-https/scripts/verify-retained-evidence.sh'
  local literal_head=''
  local literal_tree=''
  local moved_head=''
  local literal_object=''
  local literal_object_backup="$parent/literal-commit.object"
  local literal_tree_object=''
  local literal_tree_object_backup="$parent/literal-tree.object"
  local forged_tree=''
  local forged_commit=''
  local forged_sha256=''
  local observed_status=''
  local setting=''
  local fifo_probe_status=0
  local children_before=''
  local children_after=''

  run_fifo_authority_probe() {
    local -r label="$1"

    children_before="$(<"/proc/$BASHPID/task/$BASHPID/children")"
    set +e
    /usr/bin/timeout --foreground --kill-after=1s 8s \
      "$REAL_BASH" --noprofile --norc -c '
        source "$1"
        if validate_source_authority; then
          exit 0
        fi
        exit 91
      ' source-authority-fifo-probe "$fixture_importer" >/dev/null 2>&1
    fifo_probe_status=$?
    set -e
    children_after="$(<"/proc/$BASHPID/task/$BASHPID/children")"
    [[ "$fifo_probe_status" != 0 && "$fifo_probe_status" != 124 ]] ||
      fail "$label did not fail inside the outer eight-second safety bound"
    [[ "$children_after" == "$children_before" ]] ||
      fail "$label left an unreaped authority child"
    [[ ! -e "$forged_marker" && ! -L "$forged_marker" ]] ||
      fail "$label executed the forged source verifier"
  }

  mkdir -p -- "$scripts" "$repository/.github/workflows" "$unused_bundle"
  git init --quiet "$repository"
  git -C "$repository" config user.email 'source-authority-test@example.invalid'
  git -C "$repository" config user.name 'Source Authority Test'
  git -C "$repository" config commit.gpgSign false
  cp -- "$SCRIPT_DIRECTORY/import-retained-ci-evidence.sh" "$fixture_importer"
  cp -- "$SCRIPT_DIRECTORY/verify-retained-evidence.sh" "$fixture_verifier"
  cp -- "$fixture_verifier" "$original_verifier"
  cp -- "$REPOSITORY_ROOT/$WORKFLOW_PATH" \
    "$repository/$WORKFLOW_PATH"
  printf '%s filter=source-authority-test\n' "$verifier_path" \
    >"$repository/.gitattributes"
  printf 'newline-safe tracked path\n' \
    >"$repository/"$'authority\nnewline.txt'
  ln -s -- .gitattributes "$repository/authority-link"
  chmod 0755 -- "$fixture_importer" "$fixture_verifier"
  git -C "$repository" add -- .
  git -C "$repository" commit --quiet -m 'Create literal source authority'
  literal_head="$(git -C "$repository" rev-parse HEAD)"
  literal_tree="$(git -C "$repository" rev-parse "$literal_head^{tree}")"
  [[ "$literal_head" =~ ^[0-9a-f]{40}$ &&
    "$literal_tree" =~ ^[0-9a-f]{40}$ ]] ||
    fail 'source-authority replacement fixture lacks literal Git objects'
  if ! "$REAL_BASH" --noprofile --norc -c '
    source "$1"
    SOURCE_AUTHORITY_RETURN_MARKER=$2
    source_authority_validator_return_checkpoint() {
      : >"$SOURCE_AUTHORITY_RETURN_MARKER"
    }
    validate_source_authority
  ' source-authority-literal-control "$fixture_importer" \
    "$validator_return_marker" \
    >/dev/null 2>&1; then
    fail 'literal worktree control with a symlink and newline path was rejected'
  fi
  [[ -f "$validator_return_marker" && ! -L "$validator_return_marker" ]] ||
    fail 'literal worktree validator did not return to its Bash caller'

  moved_head="$(printf '%s\n' 'Move HEAD without changing its tree' |
    git --no-replace-objects -C "$repository" commit-tree "$literal_tree" \
      -p "$literal_head")"
  [[ "$moved_head" =~ ^[0-9a-f]{40}$ && "$moved_head" != "$literal_head" ]] ||
    fail 'source-authority HEAD-move fixture lacks a distinct commit'
  if "$REAL_BASH" --noprofile --norc -c '
    source "$1"
    SOURCE_AUTHORITY_MOVED_HEAD=$2
    source_authority_final_checkpoint() {
      git --no-replace-objects -C "$REPOSITORY_ROOT" update-ref HEAD \
        "$SOURCE_AUTHORITY_MOVED_HEAD"
    }
    if validate_source_authority; then
      exit 0
    fi
    exit 91
  ' source-authority-head-move-probe "$fixture_importer" "$moved_head" \
    >/dev/null 2>&1; then
    fail 'source authority accepted a same-tree HEAD move after file pinning'
  fi
  [[ "$(git --no-replace-objects -C "$repository" rev-parse HEAD)" == \
    "$moved_head" ]] ||
    fail 'source-authority final-checkpoint fixture did not move HEAD'
  git --no-replace-objects -C "$repository" update-ref HEAD "$literal_head"

  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf ': >%q\n' "$forged_marker"
    printf '%s\n' 'exit 0'
  } >"$fixture_verifier"
  chmod 0755 -- "$fixture_verifier"
  git -C "$repository" add -- "$verifier_path"
  forged_tree="$(git -C "$repository" write-tree)"
  forged_commit="$(printf '%s\n' 'Forge the source verifier' |
    git -C "$repository" commit-tree "$forged_tree" -p "$literal_head")"
  [[ "$forged_commit" =~ ^[0-9a-f]{40}$ ]] ||
    fail 'source-authority replacement fixture lacks a forged commit'

  literal_tree_object="$repository/.git/objects/${literal_tree:0:2}/${literal_tree:2}"
  [[ -f "$literal_tree_object" && ! -L "$literal_tree_object" ]] ||
    fail 'loose-object substitution fixture lacks the literal root tree object'
  cp -- "$literal_tree_object" "$literal_tree_object_backup"
  git --no-replace-objects -C "$repository" cat-file tree "$forged_tree" |
    /usr/bin/python3 -I -c '
import sys
import zlib

content = sys.stdin.buffer.read(1048577)
if not content or len(content) > 1048576:
    raise ValueError("forged tree payload is outside its test bound")
payload = b"tree " + str(len(content)).encode("ascii") + b"\0" + content
sys.stdout.buffer.write(zlib.compress(payload))
' >"$literal_tree_object.next"
  mv -fT -- "$literal_tree_object.next" "$literal_tree_object"
  [[ "$(git --no-replace-objects -C "$repository" rev-parse HEAD)" == \
    "$literal_head" ]] ||
    fail 'root-tree substitution changed the literal HEAD name'
  if "$REAL_BASH" --noprofile --norc -c '
    source "$1"
    if validate_source_authority; then
      trusted_retained_verifier --claims-v2 "$2"
      exit $?
    fi
    exit 91
  ' source-authority-root-tree-probe "$fixture_importer" "$unused_bundle" \
    >/dev/null 2>&1; then
    fail 'root-tree object substitution authenticated and executed a forged verifier'
  fi
  [[ ! -e "$forged_marker" && ! -L "$forged_marker" ]] ||
    fail 'root-tree object substitution executed the forged source verifier'
  mv -fT -- "$literal_tree_object_backup" "$literal_tree_object"

  literal_object="$repository/.git/objects/${literal_head:0:2}/${literal_head:2}"
  [[ -f "$literal_object" && ! -L "$literal_object" ]] ||
    fail 'loose-object substitution fixture lacks the literal commit object'
  cp -- "$literal_object" "$literal_object_backup"
  git --no-replace-objects -C "$repository" cat-file commit "$forged_commit" |
    /usr/bin/python3 -I -c '
import sys
import zlib

content = sys.stdin.buffer.read(1048577)
if not content or len(content) > 1048576:
    raise ValueError("forged commit payload is outside its test bound")
payload = b"commit " + str(len(content)).encode("ascii") + b"\0" + content
sys.stdout.buffer.write(zlib.compress(payload))
' >"$literal_object.next"
  mv -fT -- "$literal_object.next" "$literal_object"
  [[ "$(git --no-replace-objects -C "$repository" rev-parse HEAD)" == \
    "$literal_head" ]] ||
    fail 'loose-object substitution changed the literal HEAD name'
  observed_status="$(git --no-replace-objects -C "$repository" status \
    --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
  [[ -z "$observed_status" ]] ||
    fail 'loose-object substitution did not reproduce a clean forged tree'
  if "$REAL_BASH" --noprofile --norc -c '
    source "$1"
    if validate_source_authority; then
      trusted_retained_verifier --claims-v2 "$2"
      exit $?
    fi
    exit 91
  ' source-authority-loose-object-probe "$fixture_importer" "$unused_bundle" \
    >/dev/null 2>&1; then
    fail 'loose-object substitution authenticated and executed a forged verifier'
  fi
  [[ ! -e "$forged_marker" && ! -L "$forged_marker" ]] ||
    fail 'loose-object substitution executed the forged source verifier'
  mv -fT -- "$literal_object_backup" "$literal_object"

  git -C "$repository" update-ref "refs/replace/$literal_head" "$forged_commit"
  git -C "$repository" pack-refs --all --prune
  [[ "$(git -C "$repository" rev-parse HEAD)" == "$literal_head" ]] ||
    fail 'standard replacement fixture changed the literal HEAD name'
  observed_status="$(git -C "$repository" status --porcelain=v1 \
    --untracked-files=all --ignore-submodules=none)"
  [[ -z "$observed_status" ]] ||
    fail 'standard replacement fixture did not reproduce a clean forged tree'
  if "$REAL_BASH" --noprofile --norc -c '
    source "$1"
    if validate_source_authority; then
      trusted_retained_verifier --claims-v2 "$2"
      exit $?
    fi
    exit 91
  ' source-authority-probe "$fixture_importer" "$unused_bundle" \
    >/dev/null 2>&1; then
    fail 'standard replace ref authenticated and executed a forged verifier'
  fi
  [[ ! -e "$forged_marker" && ! -L "$forged_marker" ]] ||
    fail 'standard replace ref executed the forged source verifier'

  git -C "$repository" update-ref -d "refs/replace/$literal_head"
  git -C "$repository" update-ref \
    "refs/alternate-replace/$literal_head" "$forged_commit"
  observed_status="$(GIT_REPLACE_REF_BASE=refs/alternate-replace \
    git -C "$repository" status --porcelain=v1 \
      --untracked-files=all --ignore-submodules=none)"
  [[ -z "$observed_status" ]] ||
    fail 'custom replacement-base fixture did not reproduce a clean forged tree'
  if GIT_REPLACE_REF_BASE=refs/alternate-replace \
    "$REAL_BASH" --noprofile --norc -c '
      source "$1"
      if validate_source_authority; then
        trusted_retained_verifier --claims-v2 "$2"
        exit $?
      fi
      exit 91
    ' source-authority-probe "$fixture_importer" "$unused_bundle" \
      >/dev/null 2>&1; then
    fail 'custom replacement base authenticated and executed a forged verifier'
  fi
  [[ ! -e "$forged_marker" && ! -L "$forged_marker" ]] ||
    fail 'custom replacement base executed the forged source verifier'

  git -C "$repository" update-ref -d \
    "refs/alternate-replace/$literal_head"
  cp -- "$original_verifier" "$fixture_verifier"
  chmod 0755 -- "$fixture_verifier"
  git -C "$repository" add -- "$verifier_path"
  observed_status="$(git --no-replace-objects -C "$repository" status \
    --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
  [[ -z "$observed_status" ]] ||
    fail 'source-authority config fixture was not restored to literal HEAD'
  for setting in true false; do
    git -C "$repository" config core.useReplaceRefs "$setting"
    if "$REAL_BASH" --noprofile --norc -c '
      source "$1"
      if validate_source_authority; then
        exit 0
      fi
      exit 91
    ' source-authority-config-probe "$fixture_importer" \
      >/dev/null 2>&1; then
      fail "explicit core.useReplaceRefs=$setting was accepted"
    fi
    git -C "$repository" config --unset-all core.useReplaceRefs
  done
  [[ ! -e "$forged_marker" && ! -L "$forged_marker" ]] ||
    fail 'replacement-config rejection executed the forged source verifier'

  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf ': >%q\n' "$forged_marker"
    printf '%s\n' 'exit 0'
  } >"$fixture_verifier"
  chmod 0755 -- "$fixture_verifier"
  forged_sha256="$(/usr/bin/sha256sum <"$fixture_verifier")"
  forged_sha256="${forged_sha256%% *}"
  git -C "$repository" update-index --skip-worktree -- "$verifier_path"
  observed_status="$(git --no-replace-objects -C "$repository" status \
    --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
  [[ -z "$observed_status" ]] ||
    fail 'skip-worktree fixture did not hide the forged verifier pathname'
  if "$REAL_BASH" --noprofile --norc -c '
    FORGED_SHA256=$3
    sha256sum() {
      printf "%s  -\n" "$FORGED_SHA256"
    }
    awk() {
      local record=""
      record="$(</dev/stdin)"
      case "$record" in
        *java_remote_parent_acceptance_claims.yml) printf "%s\n" 100644 ;;
        *) printf "%s\n" 100755 ;;
      esac
    }
    export -f awk sha256sum
    source "$1"
    if validate_source_authority; then
      trusted_retained_verifier --claims-v2 "$2"
      exit $?
    fi
    exit 91
  ' source-authority-sha-probe "$fixture_importer" "$unused_bundle" \
    "$forged_sha256" >/dev/null 2>&1; then
    fail 'hostile SHA-256 function authenticated and executed a skip-worktree verifier'
  fi
  [[ ! -e "$forged_marker" && ! -L "$forged_marker" ]] ||
    fail 'hostile SHA-256 function executed the skip-worktree verifier'
  git -C "$repository" update-index --no-skip-worktree -- "$verifier_path"
  cp -- "$original_verifier" "$fixture_verifier"
  chmod 0755 -- "$fixture_verifier"
  git -C "$repository" add -- "$verifier_path"

  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf ': >%q\n' "$fsmonitor_marker"
    printf '%s\n' 'exit 0'
  } >"$fsmonitor_hook"
  chmod 0700 -- "$fsmonitor_hook"
  git -C "$repository" config core.fsmonitor "$fsmonitor_hook"
  if "$REAL_BASH" --noprofile --norc -c '
    source "$1"
    validate_source_authority
  ' source-authority-fsmonitor-probe "$fixture_importer" \
    >/dev/null 2>&1; then
    fail 'repository core.fsmonitor config was accepted as source authority'
  fi
  [[ ! -e "$fsmonitor_marker" && ! -L "$fsmonitor_marker" ]] ||
    fail 'repository core.fsmonitor executed inside source authority'
  git -C "$repository" config --unset-all core.fsmonitor

  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf ': >%q\n' "$filter_marker"
    printf '%s\n' 'cat'
  } >"$filter_hook"
  chmod 0700 -- "$filter_hook"
  git -C "$repository" config filter.source-authority-test.clean \
    "$filter_hook"
  touch -- "$fixture_verifier"
  if "$REAL_BASH" --noprofile --norc -c '
    source "$1"
    validate_source_authority
  ' source-authority-filter-probe "$fixture_importer" \
    >/dev/null 2>&1; then
    fail 'repository clean-filter command was accepted as source authority'
  fi
  [[ ! -e "$filter_marker" && ! -L "$filter_marker" ]] ||
    fail 'repository clean-filter command executed inside source authority'
  git -C "$repository" config --unset-all \
    filter.source-authority-test.clean

  mv -T -- "$repository/.git/config" "$config_backup"
  mkfifo -m 0600 -- "$repository/.git/config"
  run_fifo_authority_probe 'FIFO-backed repository config'
  rm -- "$repository/.git/config"
  mv -T -- "$config_backup" "$repository/.git/config"

  mv -T -- "$repository/.git/HEAD" "$head_backup"
  mkfifo -m 0600 -- "$repository/.git/HEAD"
  run_fifo_authority_probe 'FIFO-backed loose HEAD ref'
)

test_source_verifier_execution_is_sealed_copy_stable() (
  local parent="$TEST_ROOT/source-verifier-execution"
  local source="$parent/verify-retained-evidence.sh"
  local original="$parent/verify-retained-evidence.original"
  local hostile="$parent/verify-retained-evidence.hostile"
  local displaced="$parent/verify-retained-evidence.displaced"
  local symlink_original="$parent/verify-retained-evidence.symlink-original"
  local fifo_original="$parent/verify-retained-evidence.fifo-original"
  local safe_marker="$parent/safe.marker"
  local hostile_marker="$parent/hostile.marker"
  local original_identity=''
  local restored_identity=''
  local source_identity=''
  local mutated_identity=''
  local source_sha256=''
  local fifo_status=0
  local children_before=''
  local children_after=''

  mkdir -m 0700 -- "$parent"
  {
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -Eeuo pipefail' \
      '[[ $# == 7 && "$1" == --internal-held-source ]]'
    printf ': >%q\n' "$safe_marker"
  } >"$source"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf ': >%q\n' "$hostile_marker"
  } >"$hostile"
  chmod 0700 -- "$source" "$hostile"
  original_identity="$(stat -Lc '%d:%i:%u' -- "$source")"
  configure_test_source_verifier_authority "$source"
  source_verifier_execution_checkpoint() {
    mv -T -- "$source" "$original"
    mv -T -- "$hostile" "$source"
  }
  expect_reject 'same-UID source-verifier pathname swap before clean open' \
    trusted_retained_verifier --claims-v2 "$parent/unused-bundle"
  [[ ! -e "$safe_marker" && ! -L "$safe_marker" &&
    ! -e "$hostile_marker" && ! -L "$hostile_marker" ]] ||
    fail 'pathname-swapped source-verifier bytes executed'
  mv -T -- "$source" "$displaced"
  mv -T -- "$original" "$source"
  restored_identity="$(stat -Lc '%d:%i:%u' -- "$source")"
  [[ "$restored_identity" == "$original_identity" ]] ||
    fail 'pathname-swap regression did not restore the exact trusted inode'

  configure_test_source_verifier_authority "$source"
  source_verifier_execution_checkpoint() {
    mv -T -- "$source" "$symlink_original"
    ln -s -- "$symlink_original" "$source"
  }
  expect_reject 'symbolic-link source substitution before clean open' \
    trusted_retained_verifier --claims-v2 "$parent/unused-bundle"
  [[ ! -e "$safe_marker" && ! -L "$safe_marker" &&
    ! -e "$hostile_marker" && ! -L "$hostile_marker" ]] ||
    fail 'symbolic-link-substituted source-verifier bytes executed'
  rm -- "$source"
  mv -T -- "$symlink_original" "$source"

  source_sha256="$(sha256sum <"$source")"
  source_sha256="${source_sha256%% *}"
  children_before="$(<"/proc/$BASHPID/task/$BASHPID/children")"
  set +e
  /usr/bin/timeout --foreground --kill-after=1s 4s \
    "$REAL_BASH" --noprofile --norc -c '
      source "$1"
      trap - EXIT HUP INT TERM ERR DEBUG RETURN QUIT ALRM
      SOURCE_VERIFIER_PATH=$2
      SOURCE_VERIFIER_SHA256=$3
      HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      SOURCE_VERIFIER_FIFO_ORIGINAL=$4
      source_verifier_execution_checkpoint() {
        mv -T -- "$SOURCE_VERIFIER_PATH" "$SOURCE_VERIFIER_FIFO_ORIGINAL"
        mkfifo -m 0600 -- "$SOURCE_VERIFIER_PATH"
      }
      if trusted_retained_verifier --claims-v2 "$5"; then
        exit 0
      fi
      exit 91
    ' source-verifier-fifo-probe \
      "$SCRIPT_DIRECTORY/import-retained-ci-evidence.sh" "$source" \
      "$source_sha256" "$fifo_original" "$parent/unused-bundle" \
      >/dev/null 2>&1
  fifo_status=$?
  set -e
  children_after="$(<"/proc/$BASHPID/task/$BASHPID/children")"
  [[ "$fifo_status" == 91 ]] ||
    fail "FIFO source substitution returned $fifo_status instead of bounded rejection"
  [[ "$children_after" == "$children_before" ]] ||
    fail 'FIFO source substitution left an unreaped verifier child'
  [[ ! -e "$safe_marker" && ! -L "$safe_marker" &&
    ! -e "$hostile_marker" && ! -L "$hostile_marker" ]] ||
    fail 'FIFO-substituted source-verifier bytes executed'
  rm -- "$source"
  mv -T -- "$fifo_original" "$source"

  rm -f -- "$safe_marker" "$hostile_marker"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf ': >%q\n' "$safe_marker"
  } >"$source"
  chmod 0700 -- "$source"
  configure_test_source_verifier_authority "$source"
  source_verifier_execution_checkpoint() {
    {
      printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
      printf ': >%q\n' "$hostile_marker"
    } >"$source"
  }
  expect_reject 'same-inode source mutation before the sealed copy' \
    trusted_retained_verifier --claims-v2 "$parent/unused-bundle"
  [[ ! -e "$hostile_marker" && ! -L "$hostile_marker" ]] ||
    fail 'same-inode pre-copy source-verifier mutation executed'

  rm -f -- "$safe_marker" "$hostile_marker"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf '/bin/cp -- %q %q\n' "$hostile" "$source"
    printf ': >%q\n' "$safe_marker"
  } >"$source"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    printf ': >%q\n' "$hostile_marker"
  } >"$hostile"
  chmod 0700 -- "$source" "$hostile"
  source_identity="$(stat -Lc '%d:%i:%u' -- "$source")"
  configure_test_source_verifier_authority "$source"
  source_verifier_execution_checkpoint() { :; }
  trusted_retained_verifier --claims-v2 "$parent/unused-bundle" ||
    fail 'sealed source verifier failed after its source inode was mutated'
  mutated_identity="$(stat -Lc '%d:%i:%u' -- "$source")"
  [[ "$mutated_identity" == "$source_identity" && -f "$safe_marker" &&
    ! -e "$hostile_marker" && ! -L "$hostile_marker" ]] ||
    fail 'post-copy same-inode mutation affected sealed verifier execution'
  cmp -s -- "$source" "$hostile" ||
    fail 'post-copy same-inode mutation regression did not exercise hostile bytes'
)

test_source_verifier_bootstrap_rejects_caller_environment() (
  local parent="$TEST_ROOT/source-verifier-bootstrap"
  local source="$parent/verify-retained-evidence.sh"
  local bash_environment="$parent/bash-environment"
  local python_directory="$parent/python"
  local poison_bin="$parent/bin"
  local verified_marker="$parent/exact-verifier-ran.marker"
  local poison_marker="$parent/caller-environment-ran.marker"
  local bash_environment_fd=''
  local children_before=''
  local children_after=''
  local checkpoint_poison_case=''
  local verifier_status=0

  mkdir -m 0700 -- "$parent" "$python_directory" "$poison_bin"
  {
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -Eeuo pipefail' \
      '[[ $# == 7 && "$1" == --internal-held-source ]]' \
      '[[ "$PATH" == /usr/bin:/bin && "${LC_ALL:-}" == C && "${LANG:-}" == C ]]' \
      '[[ -z "${BASH_ENV:-}${ENV:-}${LD_PRELOAD:-}${LD_LIBRARY_PATH:-}" ]]' \
      '[[ -z "${PYTHONPATH:-}${PYTHONHOME:-}${GIT_DIR:-}${GIT_WORK_TREE:-}" ]]' \
      '[[ "$(type -t exec)" == builtin && "$(type -t command)" == builtin ]]' \
      '[[ -z "$(type -t git 2>/dev/null || true)" || "$(type -t git)" == file ]]'
    printf ': >%q\n' "$verified_marker"
    printf '%s\n' 'exit 23'
  } >"$source"
  {
    printf ': >%q\n' "$poison_marker"
    printf '%s\n' 'exit 0'
  } >"$bash_environment"
  {
    printf 'from pathlib import Path\nPath(%q).touch()\n' "$poison_marker"
  } >"$python_directory/sitecustomize.py"
  for poison_name in bash git python3 sha256sum stat; do
    {
      printf '%s\n' '#!/usr/bin/env bash'
      printf ': >%q\n' "$poison_marker"
      printf '%s\n' 'exit 0'
    } >"$poison_bin/$poison_name"
    chmod 0700 -- "$poison_bin/$poison_name"
  done
  chmod 0700 -- "$source"
  chmod 0600 -- "$bash_environment" "$python_directory/sitecustomize.py"
  configure_test_source_verifier_authority "$source"
  exec {bash_environment_fd}<"$bash_environment"
  children_before="$(<"/proc/$BASHPID/task/$BASHPID/children")"

  bootstrap_poison() { : >"$poison_marker"; return 0; }
  function exec() { bootstrap_poison; }
  function unset() { bootstrap_poison; }
  function command() { bootstrap_poison; }
  function builtin() { bootstrap_poison; }
  function type() { bootstrap_poison; }
  function /usr/bin/python3() { bootstrap_poison; }
  export -f bootstrap_poison exec unset command builtin type
  export SHELLOPTS BASHOPTS

  set +e
  BASH_ENV="/proc/$BASHPID/fd/$bash_environment_fd" \
    ENV="/proc/$BASHPID/fd/$bash_environment_fd" \
    LD_PRELOAD="$parent/hostile-loader.so" \
    LD_LIBRARY_PATH="$parent" \
    PYTHONPATH="$python_directory" \
    PYTHONHOME="$parent/hostile-python-home" \
    GIT_DIR="$parent/hostile-git-dir" \
    GIT_WORK_TREE="$parent" \
    PATH="$poison_bin:/usr/bin:/bin" \
    trusted_retained_verifier --claims-v2 "$parent/nonexistent-bundle"
  verifier_status=$?
  set -e
  children_after="$(<"/proc/$BASHPID/task/$BASHPID/children")"

  [[ "$verifier_status" == 23 && -f "$verified_marker" &&
    ! -e "$poison_marker" && ! -L "$poison_marker" ]] ||
    fail 'caller environment bypassed or pre-executed the exact held verifier'
  [[ "$children_after" == "$children_before" ]] ||
    fail 'clean source-verifier bootstrap left an unreaped Bash/Python/Git child'

  # The checkpoint models same-UID byte/path races, but it is not allowed to
  # persist shell-control state into the trusted launch subprocess.
  for checkpoint_poison_case in functions DEBUG RETURN; do
    rm -f -- "$verified_marker" "$poison_marker"
    source_verifier_execution_checkpoint() {
      checkpoint_poison() { : >"$poison_marker"; exit 0; }
      function local() { checkpoint_poison; }
      function exec() { checkpoint_poison; }
      function type() { checkpoint_poison; }
      function /usr/bin/python3() { checkpoint_poison; }
      if [[ "$checkpoint_poison_case" != functions ]]; then
        set -T
        trap 'if [[ ${FUNCNAME[0]-} == trusted_clean_exec ]]; then checkpoint_poison; fi' \
          "$checkpoint_poison_case"
      fi
    }
    set +e
    trusted_retained_verifier --claims-v2 "$parent/nonexistent-bundle"
    verifier_status=$?
    set -e
    [[ "$verifier_status" == 23 && -f "$verified_marker" &&
      ! -e "$poison_marker" && ! -L "$poison_marker" ]] ||
      fail "checkpoint $checkpoint_poison_case state crossed the clean launch boundary"
  done
)

test_source_import_rejects_resealed_forged_nested_verifiers() (
  local calls="$TEST_ROOT/source-import-forged-verifier-calls"
  local baseline=''
  local root=''
  local marker=''
  local role=''
  local expected_calls=''
  local -i claims_version=0

  HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  compute_source_tree_sha256() {
    printf '%s\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  }
  trusted_retained_verifier() {
    local -r mode="$1"
    local -r bundle="$2"
    printf '%s\t%s\n' "$mode" "$bundle" >>"$calls"
    case "$mode" in
      --claims-v1)
        jq -e '.schema == "obi-bounded-acceptance-claims-v1"' \
          "$bundle/acceptance-claims.json" >/dev/null
        ;;
      --claims-v2)
        jq -e '.schema == "obi-bounded-acceptance-claims-v2"' \
          "$bundle/acceptance-claims.json" >/dev/null
        ;;
      --fault-security-matrix-v1)
        jq -e '.schema == "obi-bounded-fault-security-matrix-v1"' \
          "$bundle/fault-security-matrix.json" >/dev/null
        ;;
      *) return 1 ;;
    esac
  }

  for claims_version in 1 2; do
    baseline="$TEST_ROOT/source-import-forged-v$claims_version/baseline"
    build_wrapper_fixture "$baseline" "$claims_version"
    for role in acceptance fault-security; do
      root="$TEST_ROOT/source-import-forged-v$claims_version/$role"
      marker="$TEST_ROOT/forged-v$claims_version-$role.marker"
      cp -a -- "$baseline" "$root"
      chmod u+w -- "$root/$role" "$root/$role/verify.sh"
      cat >"$root/$role/verify.sh" <<'FORGED_VERIFIER'
#!/usr/bin/env bash
set -Eeuo pipefail
: >"${IMPORT_TEST_FORGED_VERIFIER_MARKER:?}"
FORGED_VERIFIER
      reseal_nested_checksum_manifest "$root" "$role"
      reseal_outer_checksum_manifest "$root"
      chmod -R a-w -- "$root"
      : >"$calls"
      : >"$TEST_NESTED_RUNNER_LOG"
      rm -f -- "$marker"
      IMPORT_TEST_FORGED_VERIFIER_MARKER="$marker"
      export IMPORT_TEST_FORGED_VERIFIER_MARKER
      expect_reject \
        "claims-v$claims_version fully resealed forged $role verifier" \
        run_verify_nested_bundles \
          "$root/acceptance" "$root/fault-security" "$claims_version"
      [[ ! -e "$marker" && ! -L "$marker" ]] ||
        fail "claims-v$claims_version forged $role verifier executed"
      [[ ! -s "$TEST_NESTED_RUNNER_LOG" ]] ||
        fail "claims-v$claims_version invoked artifact Bash before rejecting forged $role verifier"
      expected_calls="--claims-v$claims_version"$'\t'"$root/acceptance"$'\n'
      expected_calls+="--fault-security-matrix-v1"$'\t'"$root/fault-security"
      [[ "$(<"$calls")" == "$expected_calls" ]] ||
        fail "claims-v$claims_version did not complete both trusted validations before rejecting forged $role verifier"
    done
  done
)

test_wrapper_version_contracts() {
  local receipt_sha=''
  local evidence=''
  local leaf=''
  local v1_root=''
  local v2_root=''
  local v1_verifier_sha256=''
  local v2_verifier_sha256=''

  receipt_sha="$(printf '{}\n' | sha256sum)"; receipt_sha="${receipt_sha%% *}"
  evidence="$(printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 123 2 \
    "$receipt_sha" "$receipt_sha" | sha256sum)"; evidence="${evidence%% *}"
  leaf="retained-claims-aaaaaaaaaaaa-${evidence:0:12}"
  v1_root="$TEST_ROOT/versioned-wrappers/v1/$leaf"
  v2_root="$TEST_ROOT/versioned-wrappers/v2/$leaf"
  mkdir -p -- "${v1_root%/*}" "${v2_root%/*}"
  build_wrapper_fixture "$v1_root" 1
  build_wrapper_fixture "$v2_root" 2
  v1_verifier_sha256="$(sha256sum <"$v1_root/verify.sh")"
  v1_verifier_sha256="${v1_verifier_sha256%% *}"
  [[ "$v1_verifier_sha256" == \
    a06fa5e279c18c3804857fcb04fec9b7d0aba3ce24dee685a866ef5aab5b94eb ]] ||
    fail 'legacy claims-v1 portable verifier bytes changed'
  v2_verifier_sha256="$(sha256sum <"$v2_root/verify.sh")"
  v2_verifier_sha256="${v2_verifier_sha256%% *}"
  [[ "$v2_verifier_sha256" == "$EXPECTED_V2_WRAPPER_VERIFIER_SHA256" ]] ||
    fail 'claims-v2 portable wrapper bytes changed'
  (CDPATH='' cd / && run_portable_verifier "$v1_root" >/dev/null) ||
    fail 'legacy claims-v1 wrapper compatibility failed'
  (CDPATH='' cd / && run_portable_verifier "$v2_root" >/dev/null) ||
    fail 'claims-v2 wrapper did not verify'
  jq -e '
    .schema == "obi-retained-ci-claim-index-v1" and
    .coverage.issue_36 == {pointer:
      "fault-security/fault-security-matrix.json#/coverage/issue_36",
      status:"passed"}
  ' "$v1_root/claim-index.json" >/dev/null ||
    fail 'legacy claims-v1 index shape changed'
  jq -e '
    .schema == "obi-retained-ci-claim-index-v2" and
    .coverage.issue_36 == {pointers:[
      "acceptance/acceptance-claims.json#/issue_36",
      "fault-security/fault-security-matrix.json#/coverage/issue_36"],
      status:"passed"}
  ' "$v2_root/claim-index.json" >/dev/null ||
    fail 'claims-v2 issue_36 pointer closure is not exact'

  expect_index_mutation_rejected 'v1 wrapper with v2 index schema' \
    "$v1_root" v1-to-v2-schema '.schema = "obi-retained-ci-claim-index-v2"'
  expect_index_mutation_rejected 'v2 wrapper with v1 index schema' \
    "$v2_root" v2-to-v1-schema '.schema = "obi-retained-ci-claim-index-v1"'
  expect_index_mutation_rejected 'forged v2 index schema' \
    "$v2_root" forged-schema '.schema = "obi-retained-ci-claim-index-v9"'
  expect_index_mutation_rejected 'swapped v2 issue_36 pointers' \
    "$v2_root" swapped-pointers '.coverage.issue_36.pointers |= reverse'
  expect_index_mutation_rejected 'duplicate v2 issue_36 pointers' \
    "$v2_root" duplicate-pointers \
    '.coverage.issue_36.pointers = [.coverage.issue_36.pointers[0], .coverage.issue_36.pointers[0]]'
  expect_index_mutation_rejected 'extra v2 issue_36 pointer' \
    "$v2_root" extra-pointer \
    '.coverage.issue_36.pointers += ["acceptance/acceptance-claims.json#/issue_36"]'
  expect_index_mutation_rejected 'forged acceptance issue_36 pointer' \
    "$v2_root" forged-acceptance-pointer \
    '.coverage.issue_36.pointers[0] = "acceptance/acceptance-claims.json#/issue_34"'
  expect_index_mutation_rejected 'forged fault-security issue_36 pointer' \
    "$v2_root" forged-fault-pointer \
    '.coverage.issue_36.pointers[1] = "fault-security/fault-security-matrix.json#/coverage/issue_40"'
}

test_v2_checksum_roster_rejections() {
  local receipt_sha=''
  local evidence=''
  local leaf=''
  local baseline=''
  local duplicate_root=''
  local mutated_root=''
  local candidate=''

  receipt_sha="$(printf '{}\n' | sha256sum)"
  receipt_sha="${receipt_sha%% *}"
  evidence="$(printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 123 2 \
    "$receipt_sha" "$receipt_sha" | sha256sum)"
  evidence="${evidence%% *}"
  leaf="retained-claims-aaaaaaaaaaaa-${evidence:0:12}"
  baseline="$TEST_ROOT/checksum-roster/baseline/$leaf"
  duplicate_root="$TEST_ROOT/checksum-roster/duplicate/$leaf"
  mutated_root="$TEST_ROOT/checksum-roster/mutated/$leaf"
  mkdir -p -- "${baseline%/*}" "${duplicate_root%/*}" "${mutated_root%/*}"
  build_wrapper_fixture "$baseline" 2
  (CDPATH='' cd / && run_portable_verifier "$baseline" >/dev/null) ||
    fail 'claims-v2 checksum-roster positive control failed'

  cp -a -- "$baseline" "$duplicate_root"
  omit_run_identity_checksum_entry "$duplicate_root"
  expect_reject 'claims-v2 duplicate checksum path with omitted run identity' \
    run_portable_verifier "$duplicate_root"

  cp -a -- "$baseline" "$mutated_root"
  chmod u+w -- "$mutated_root" "$mutated_root/run-identity.json"
  candidate="$mutated_root/run-identity.json.next"
  jq -cS '
    .artifacts[0].digest =
      "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  ' "$mutated_root/run-identity.json" >"$candidate"
  mv -fT -- "$candidate" "$mutated_root/run-identity.json"
  omit_run_identity_checksum_entry "$mutated_root"
  chmod a-w -- "$mutated_root/run-identity.json"
  expect_reject 'claims-v2 omitted and mutated unchecked run identity' \
    run_portable_verifier "$mutated_root"
}

test_v2_nested_verifier_pin_rejections() {
  local receipt_sha=''
  local evidence=''
  local leaf=''
  local baseline=''
  local root=''
  local candidate=''
  local claims_sha256=''
  local matrix_sha256=''
  local verifier_sha256=''

  receipt_sha="$(printf '{}\n' | sha256sum)"
  receipt_sha="${receipt_sha%% *}"
  evidence="$(printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 123 2 \
    "$receipt_sha" "$receipt_sha" | sha256sum)"
  evidence="${evidence%% *}"
  leaf="retained-claims-aaaaaaaaaaaa-${evidence:0:12}"
  baseline="$TEST_ROOT/nested-pin-attacks/baseline/$leaf"
  mkdir -p -- "${baseline%/*}"
  build_wrapper_fixture "$baseline" 2
  : >"$TEST_NESTED_RUNNER_LOG"
  run_portable_verifier "$baseline" >/dev/null ||
    fail 'claims-v2 nested-verifier pin positive control failed'
  [[ "$(<"$TEST_NESTED_RUNNER_LOG")" == \
    "$baseline/acceptance/verify.sh"$'\n'"$baseline/fault-security/verify.sh" ]] ||
    fail 'claims-v2 positive control did not execute both pinned verifiers'

  root="$TEST_ROOT/nested-pin-attacks/stale-acceptance-receipt/$leaf"
  mkdir -p -- "${root%/*}"
  cp -a -- "$baseline" "$root"
  chmod u+w -- "$root/acceptance" \
    "$root/acceptance/acceptance-claims.json" \
    "$root/acceptance/verify.sh"
  candidate="$root/acceptance/acceptance-claims.json.next"
  jq -cS '.issue_36.fabricated_pressure = {
    w3c_parent_count:999,capacity_rejection_errno:"SUCCESS"}' \
    "$root/acceptance/acceptance-claims.json" >"$candidate"
  mv -fT -- "$candidate" "$root/acceptance/acceptance-claims.json"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$root/acceptance/verify.sh"
  reseal_nested_checksum_manifest "$root" acceptance
  reseal_outer_checksum_manifest "$root"
  chmod -R a-w -- "$root"
  : >"$TEST_NESTED_RUNNER_LOG"
  expect_reject \
    'resealed acceptance verifier replacement with stale derivation receipt' \
    run_portable_verifier "$root"
  [[ ! -s "$TEST_NESTED_RUNNER_LOG" ]] ||
    fail 'replacement acceptance verifier executed before its pin rejected'

  root="$TEST_ROOT/nested-pin-attacks/rebound-acceptance-receipt/$leaf"
  mkdir -p -- "${root%/*}"
  cp -a -- "$baseline" "$root"
  chmod u+w -- "$root/acceptance" \
    "$root/acceptance/acceptance-claims.json" \
    "$root/acceptance/derivation-receipt.json" \
    "$root/acceptance/verify.sh"
  candidate="$root/acceptance/acceptance-claims.json.next"
  jq -cS '.issue_36.fabricated_pressure = {
    w3c_parent_count:999,capacity_rejection_errno:"SUCCESS"}' \
    "$root/acceptance/acceptance-claims.json" >"$candidate"
  mv -fT -- "$candidate" "$root/acceptance/acceptance-claims.json"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$root/acceptance/verify.sh"
  claims_sha256="$(sha256sum \
    <"$root/acceptance/acceptance-claims.json")"
  claims_sha256="${claims_sha256%% *}"
  verifier_sha256="$(sha256sum <"$root/acceptance/verify.sh")"
  verifier_sha256="${verifier_sha256%% *}"
  jq -cS -n --arg claims "$claims_sha256" --arg verifier "$verifier_sha256" \
    '{fabricated_binding:{claims_sha256:$claims,verifier_sha256:$verifier}}' \
    >"$root/acceptance/derivation-receipt.json.next"
  mv -fT -- "$root/acceptance/derivation-receipt.json.next" \
    "$root/acceptance/derivation-receipt.json"
  rebind_wrapper_evidence_id "$root"
  root="$REBOUND_ROOT"
  reseal_nested_checksum_manifest "$root" acceptance
  reseal_outer_checksum_manifest "$root"
  chmod -R a-w -- "$root"
  : >"$TEST_NESTED_RUNNER_LOG"
  expect_reject \
    'resealed acceptance claims and receipt with replacement verifier' \
    run_portable_verifier "$root"
  [[ ! -s "$TEST_NESTED_RUNNER_LOG" ]] ||
    fail 'receipt-rebound acceptance verifier executed before its pin rejected'

  root="$TEST_ROOT/nested-pin-attacks/rebound-fault-receipt/$leaf"
  mkdir -p -- "${root%/*}"
  cp -a -- "$baseline" "$root"
  chmod u+w -- "$root/fault-security" \
    "$root/fault-security/fault-security-matrix.json" \
    "$root/fault-security/derivation-receipt.json" \
    "$root/fault-security/verify.sh"
  candidate="$root/fault-security/fault-security-matrix.json.next"
  jq -cS '.coverage.issue_36.fabricated_profile = "passed-without-proof"' \
    "$root/fault-security/fault-security-matrix.json" >"$candidate"
  mv -fT -- "$candidate" "$root/fault-security/fault-security-matrix.json"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$root/fault-security/verify.sh"
  matrix_sha256="$(sha256sum \
    <"$root/fault-security/fault-security-matrix.json")"
  matrix_sha256="${matrix_sha256%% *}"
  verifier_sha256="$(sha256sum <"$root/fault-security/verify.sh")"
  verifier_sha256="${verifier_sha256%% *}"
  jq -cS -n --arg matrix "$matrix_sha256" --arg verifier "$verifier_sha256" \
    '{fabricated_binding:{matrix_sha256:$matrix,verifier_sha256:$verifier}}' \
    >"$root/fault-security/derivation-receipt.json.next"
  mv -fT -- "$root/fault-security/derivation-receipt.json.next" \
    "$root/fault-security/derivation-receipt.json"
  rebind_wrapper_evidence_id "$root"
  root="$REBOUND_ROOT"
  reseal_nested_checksum_manifest "$root" fault-security
  reseal_outer_checksum_manifest "$root"
  chmod -R a-w -- "$root"
  : >"$TEST_NESTED_RUNNER_LOG"
  expect_reject \
    'resealed fault issue_36 and receipt with replacement verifier' \
    run_portable_verifier "$root"
  [[ ! -s "$TEST_NESTED_RUNNER_LOG" ]] ||
    fail 'replacement fault verifier executed before its pin rejected'
}

test_wrapper_overclaim_and_leakage() {
  local receipt_sha=''
  local evidence=''
  receipt_sha="$(printf '{}\n' | sha256sum)"; receipt_sha="${receipt_sha%% *}"
  evidence="$(printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 123 2 \
    "$receipt_sha" "$receipt_sha" | sha256sum)"; evidence="${evidence%% *}"
  local root="$TEST_ROOT/retained-claims-aaaaaaaaaaaa-${evidence:0:12}"
  build_wrapper_fixture "$root"
  (CDPATH='' cd / && bash "$root/verify.sh" >/dev/null) ||
    fail 'valid wrapper fixture did not verify'
  local trusted_wrapper="$TEST_ROOT/trusted-wrapper"
  local arbitrary_root="$TEST_ROOT/retained-claims-aaaaaaaaaaaa-bbbbbbbbbbbb"
  cp -a -- "$root" "$trusted_wrapper"
  chmod u+w -- "$root" "$root/claim-index.json" "$root/SHA256SUMS"
  jq -cS '.evidence_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    "$root/claim-index.json" >"$root/claim-index.tmp"
  mv -- "$root/claim-index.tmp" "$root/claim-index.json"
  (CDPATH='' cd -- "$root" && sha256sum claim-index.json >SHA256SUMS.tmp &&
    awk '$2 != "claim-index.json"' SHA256SUMS >>SHA256SUMS.tmp &&
    mv SHA256SUMS.tmp SHA256SUMS)
  mv -- "$root" "$arbitrary_root"
  expect_reject 'arbitrary retained wrapper identity' bash "$arbitrary_root/verify.sh"
  mv -- "$trusted_wrapper" "$root"
  chmod u+w -- "$root" "$root/claim-index.json" "$root/SHA256SUMS"
  jq -cS '.coverage.issue_11={status:"closed"}' "$root/claim-index.json" \
    >"$root/claim-index.tmp"
  mv -- "$root/claim-index.tmp" "$root/claim-index.json"
  (CDPATH='' cd -- "$root" && sha256sum claim-index.json >SHA256SUMS.tmp &&
    awk '$2 != "claim-index.json"' SHA256SUMS >>SHA256SUMS.tmp &&
    mv SHA256SUMS.tmp SHA256SUMS)
  expect_reject '#11 closure overclaim' bash "$root/verify.sh"
  test_cleanup
  TEST_ROOT="$(mktemp -d /tmp/obi-retained-ci-import-test.XXXXXX)"
  chmod 0700 -- "$TEST_ROOT"
  test_trusted_clean_exec_rejects_local_poison
  prepare_nested_verifier_runner
  root="$TEST_ROOT/retained-claims-aaaaaaaaaaaa-${evidence:0:12}"
  build_wrapper_fixture "$root"
  chmod u+w -- "$root"
  printf 'private\n' >"$root/raw.log"
  expect_reject 'private leakage inventory' bash "$root/verify.sh"
}

test_write_bundle_publication_path() {
  local fixture="$TEST_ROOT/bundle-input"
  local v2_fixture="$TEST_ROOT/bundle-input-v2"
  local output_parent="$TEST_ROOT/bundle-output"
  local v2_output_parent="$TEST_ROOT/bundle-output-v2"
  local output=''
  local v2_output=''
  local python_poison="$TEST_ROOT/publication-python-poison"
  local python_poison_marker="$TEST_ROOT/publication-python-poison.marker"
  build_wrapper_fixture "$fixture"
  mkdir -m 0700 -- "$output_parent"
  output="$(bundle_test_output "$fixture" "$output_parent")"
  configure_write_bundle_test_authority "$output"
  write_bundle unused "$fixture/acceptance" "$fixture/fault-security" ||
    fail 'canonical bundle could not publish under its final verified leaf'
  [[ -d "$output" && ! -L "$output" ]] || fail 'bundle publication is absent'
  (CDPATH='' cd / && bash "$output/verify.sh" >/dev/null) ||
    fail 'published bundle failed portable verification'
  jq -e '
    .schema == "obi-retained-ci-claim-index-v1" and
    .coverage.issue_36 == {pointer:
      "fault-security/fault-security-matrix.json#/coverage/issue_36",
      status:"passed"}
  ' "$output/claim-index.json" >/dev/null ||
    fail 'published claims-v1 index semantics changed'

  build_wrapper_fixture "$v2_fixture" 2
  mkdir -m 0700 -- "$v2_output_parent"
  v2_output="$(bundle_test_output "$v2_fixture" "$v2_output_parent")"
  configure_write_bundle_test_authority "$v2_output"
  mkdir -m 0700 -- "$python_poison"
  cat >"$python_poison/sitecustomize.py" <<'PYTHON_POISON'
import os
with open(os.environ["IMPORT_TEST_PYTHON_POISON_MARKER"], "w") as marker:
    marker.write("loaded\n")
PYTHON_POISON
  PYTHONPATH="$python_poison" \
    IMPORT_TEST_PYTHON_POISON_MARKER="$python_poison_marker" \
    run_write_bundle unused \
    "$v2_fixture/acceptance" "$v2_fixture/fault-security" 2 ||
    fail 'canonical claims-v2 bundle could not publish'
  [[ ! -e "$python_poison_marker" && ! -L "$python_poison_marker" ]] ||
    fail 'publication authority imported PYTHONPATH-controlled startup code'
  [[ -d "$v2_output" && ! -L "$v2_output" ]] ||
    fail 'claims-v2 bundle publication is absent'
  (CDPATH='' cd / && run_portable_verifier "$v2_output" >/dev/null) ||
    fail 'published claims-v2 bundle failed portable verification'
  jq -e '
    .schema == "obi-retained-ci-claim-index-v2" and
    .coverage.issue_36 == {pointers:[
      "acceptance/acceptance-claims.json#/issue_36",
      "fault-security/fault-security-matrix.json#/coverage/issue_36"],
      status:"passed"}
  ' "$v2_output/claim-index.json" >/dev/null ||
    fail 'published claims-v2 index semantics are not exact'
}

test_candidate_semantics_precede_authoritative_seal() (
  local fixture="$TEST_ROOT/pre-seal-input"
  local mutation=''
  local output_parent=''
  local output=''
  local hidden=''
  local marker="$TEST_ROOT/pre-seal-artifact-executed.marker"
  local hook_receipt=''

  build_wrapper_fixture "$fixture" 2
  for mutation in run-crosslink index-noncanonical nested-source top-verifier; do
    output_parent="$TEST_ROOT/pre-seal-$mutation"
    mkdir -m 0700 -- "$output_parent"
    output="$(bundle_test_output "$fixture" "$output_parent")"
    configure_write_bundle_test_authority "$output"
    hook_receipt="$TEST_ROOT/pre-seal-$mutation.receipt"
    bundle_publication_before_seal_checkpoint() {
      local -r candidate="$1"
      local temporary=''
      printf '%s\n' "$(stat -Lc '%d:%i:%u' -- "$candidate")" \
        >"$hook_receipt" || return 1
      case "$mutation" in
        run-crosslink)
          chmod u+w -- "$candidate" "$candidate/run-identity.json"
          temporary="$candidate/run-identity.json.next"
          jq -cS '.run_url="https://invalid.example/forged"' \
            "$candidate/run-identity.json" >"$temporary" || return 1
          mv -fT -- "$temporary" "$candidate/run-identity.json"
          chmod 0444 -- "$candidate/run-identity.json"
          reseal_outer_checksum_manifest "$candidate"
          chmod 0444 -- "$candidate/SHA256SUMS"
          ;;
        index-noncanonical)
          chmod u+w -- "$candidate/claim-index.json"
          printf '\n' >>"$candidate/claim-index.json"
          chmod 0444 -- "$candidate/claim-index.json"
          reseal_outer_checksum_manifest "$candidate"
          chmod 0444 -- "$candidate/SHA256SUMS"
          ;;
        nested-source)
          chmod u+w -- "$candidate/acceptance" \
            "$candidate/acceptance/acceptance-claims.json"
          temporary="$candidate/acceptance/acceptance-claims.json.next"
          jq -cS '.artifact_controlled_extra=true' \
            "$candidate/acceptance/acceptance-claims.json" >"$temporary" ||
            return 1
          mv -fT -- "$temporary" \
            "$candidate/acceptance/acceptance-claims.json"
          chmod 0444 -- "$candidate/acceptance/acceptance-claims.json"
          reseal_nested_checksum_manifest "$candidate" acceptance
          reseal_outer_checksum_manifest "$candidate"
          chmod 0444 -- "$candidate/acceptance/SHA256SUMS" \
            "$candidate/SHA256SUMS"
          ;;
        top-verifier)
          chmod u+w -- "$candidate/verify.sh"
          printf '#!/usr/bin/env bash\nprintf marker >%q\n' "$marker" \
            >"$candidate/verify.sh"
          chmod 0444 -- "$candidate/verify.sh"
          reseal_outer_checksum_manifest "$candidate"
          chmod 0444 -- "$candidate/SHA256SUMS"
          ;;
        *) return 1 ;;
      esac
    }
    if run_write_bundle unused \
      "$fixture/acceptance" "$fixture/fault-security" 2; then
      fail "pre-seal $mutation mutation was published"
    fi
    [[ ! -e "$output" && ! -L "$output" && ! -e "$marker" ]] ||
      fail "pre-seal $mutation mutation executed or published artifact bytes"
    hidden="$(one_hidden_candidate "$output_parent")" ||
      fail "pre-seal $mutation failure did not preserve one hidden candidate"
    [[ "$(stat -Lc '%d:%i:%u' -- "$hidden")" == "$(<"$hook_receipt")" ]] ||
      fail "pre-seal $mutation failure changed the hidden candidate identity"
    candidate_seal_from_path "$hidden" >/dev/null ||
      fail "pre-seal $mutation candidate did not retain its recorded exact roster"
  done
)

test_candidate_seal_brackets_validation() (
  local fixture="$TEST_ROOT/seal-bracket-input"
  local mutation=''
  local output_parent=''
  local output=''
  local hidden=''
  local marker="$TEST_ROOT/seal-bracket-artifact-executed.marker"
  local hook_receipt=''

  build_wrapper_fixture "$fixture" 2
  for mutation in before-validation after-validation transient-restore; do
    output_parent="$TEST_ROOT/seal-bracket-$mutation"
    mkdir -m 0700 -- "$output_parent"
    output="$(bundle_test_output "$fixture" "$output_parent")"
    configure_write_bundle_test_authority "$output"
    hook_receipt="$TEST_ROOT/seal-bracket-$mutation.receipt"
    bundle_publication_before_validation_checkpoint() {
      local -r candidate="$1"
      [[ "$mutation" == before-validation ]] || return 0
      stat -Lc '%d:%i:%u' -- "$candidate" >"$hook_receipt" || return 1
      chmod u+w -- "$candidate/verify.sh"
      printf '#!/usr/bin/env bash\nprintf marker >%q\n' "$marker" \
        >"$candidate/verify.sh"
      chmod 0444 -- "$candidate/verify.sh"
    }
    bundle_publication_validation_checkpoint() {
      local -r candidate="$1"
      local original=''
      [[ "$mutation" != before-validation ]] || return 0
      stat -Lc '%d:%i:%u' -- "$candidate" >"$hook_receipt" || return 1
      case "$mutation" in
        after-validation)
          chmod u+w -- "$candidate/claim-index.json"
          printf 'FOREIGN\n' >"$candidate/claim-index.json"
          chmod 0444 -- "$candidate/claim-index.json"
          ;;
        transient-restore)
          original="$(<"$candidate/claim-index.json")"
          chmod u+w -- "$candidate/claim-index.json"
          printf 'FOREIGN\n' >"$candidate/claim-index.json"
          printf '%s\n' "$original" >"$candidate/claim-index.json"
          chmod 0444 -- "$candidate/claim-index.json"
          ;;
        *) return 1 ;;
      esac
    }
    if run_write_bundle unused \
      "$fixture/acceptance" "$fixture/fault-security" 2; then
      fail "$mutation crossed the candidate validation seal"
    fi
    [[ ! -e "$output" && ! -L "$output" && ! -e "$marker" ]] ||
      fail "$mutation executed artifact bytes or published a final bundle"
    hidden="$(one_hidden_candidate "$output_parent")" ||
      fail "$mutation did not preserve one hidden candidate"
    [[ "$(stat -Lc '%d:%i:%u' -- "$hidden")" == "$(<"$hook_receipt")" ]] ||
      fail "$mutation changed the preserved candidate identity"
    if [[ "$mutation" == transient-restore ]]; then
      candidate_seal_from_path "$hidden" >/dev/null ||
        fail 'transient restore did not restore the original candidate bytes'
    fi
  done
)

test_bundle_publication_noreplace_preserves_foreign_targets() (
  local fixture="$TEST_ROOT/publication-race-input"
  local target_kind=''
  local output_parent=''
  local output=''
  local foreign_receipt=''
  local gap_receipt=''
  local foreign_identity=''
  local observed_identity=''
  local candidate_residue=''
  local candidate_identity_receipt=''

  build_wrapper_fixture "$fixture" 2
  for target_kind in regular symlink directory; do
    output_parent="$TEST_ROOT/publication-race-$target_kind"
    mkdir -m 0700 -- "$output_parent"
    output="$(bundle_test_output "$fixture" "$output_parent")"
    configure_write_bundle_test_authority "$output"
    foreign_receipt="$TEST_ROOT/publication-race-$target_kind.identity"
    gap_receipt="$TEST_ROOT/publication-race-$target_kind.gap"
    candidate_identity_receipt="$TEST_ROOT/publication-race-$target_kind.candidate"
    foreign_identity=''
    bundle_publication_checkpoint() {
      local -r checkpoint_candidate="$1"
      local -r checkpoint_output="$2"
      [[ -d "$checkpoint_candidate" && ! -L "$checkpoint_candidate" &&
        "$checkpoint_candidate" == "$CANDIDATE_DIRECTORY" &&
        "${checkpoint_candidate##*/}" =~ ^\.retained-ci-import\.[A-Za-z0-9]{6}$ &&
        "$checkpoint_output" == "$output" && ! -e "$checkpoint_output" &&
        ! -L "$checkpoint_output" ]] || return 1
      printf 'gap\n' >>"$gap_receipt"
      stat -Lc '%d:%i:%u' -- "$checkpoint_candidate" \
        >"$candidate_identity_receipt" || return 1
      case "$target_kind" in
        regular)
          printf 'FOREIGN-FILE\n' >"$checkpoint_output"
          chmod 0600 -- "$checkpoint_output"
          ;;
        symlink)
          ln -s -- "foreign-target-$target_kind" "$checkpoint_output"
          ;;
        directory)
          mkdir -m 0711 -- "$checkpoint_output"
          ;;
        *) return 1 ;;
      esac
      stat -c '%d:%i:%u:%f' -- "$checkpoint_output" >"$foreign_receipt"
    }

    if run_write_bundle unused \
      "$fixture/acceptance" "$fixture/fault-security" 2; then
      fail "publication replaced a foreign $target_kind target"
    fi
    foreign_identity="$(<"$foreign_receipt")"
    [[ "$(<"$gap_receipt")" == gap ]] ||
      fail "foreign $target_kind final-gap seam did not run exactly once"
    observed_identity="$(stat -c '%d:%i:%u:%f' -- "$output")" ||
      fail "foreign $target_kind target disappeared"
    [[ "$observed_identity" == "$foreign_identity" ]] ||
      fail "foreign $target_kind target identity changed"
    case "$target_kind" in
      regular)
        cmp -s -- "$output" <(printf 'FOREIGN-FILE\n') ||
          fail 'foreign regular-file bytes changed'
        ;;
      symlink)
        [[ -L "$output" && "$(readlink -- "$output")" == \
          "foreign-target-$target_kind" ]] ||
          fail 'foreign symlink target changed'
        ;;
      directory)
        [[ -d "$output" && ! -L "$output" &&
          -z "$(find -- "$output" -mindepth 1 -print -quit)" ]] ||
          fail 'foreign empty directory changed'
        ;;
    esac
    candidate_residue="$(find -- "$output_parent" -mindepth 1 -maxdepth 1 \
      -name '.retained-ci-import.*' -print)"
    [[ -n "$candidate_residue" && \
      "$(printf '%s\n' "$candidate_residue" | wc -l)" == 1 &&
      "$(stat -Lc '%d:%i:%u' -- "$candidate_residue")" == \
        "$(<"$candidate_identity_receipt")" &&
      -z "$CANDIDATE_DIRECTORY" &&
      -z "$CANDIDATE_IDENTITY" ]] ||
      fail "foreign $target_kind rejection did not preserve one exact candidate"
    candidate_seal_from_path "$candidate_residue" >/dev/null ||
      fail "foreign $target_kind rejection changed the sanitized candidate"
  done
)

test_lost_ack_reconciles_committed_directory() (
  local fixture="$TEST_ROOT/post-rename-input"
  local output_parent="$TEST_ROOT/post-rename-output"
  local output=''
  local published_identity=''
  local observed_identity=''
  local candidate_residue=''
  local published_receipt="$TEST_ROOT/post-rename-published.identity"

  build_wrapper_fixture "$fixture" 2
  mkdir -m 0700 -- "$output_parent"
  output="$(bundle_test_output "$fixture" "$output_parent")"
  configure_write_bundle_test_authority "$output"
  bundle_publication_native_ack_checkpoint() {
    stat -Lc '%d:%i:%u' -- "$output" >"$published_receipt" || return 1
    return 1
  }

  run_write_bundle unused \
    "$fixture/acceptance" "$fixture/fault-security" 2 ||
    fail 'lost native acknowledgement was not reconciled as committed'
  observed_identity="$(stat -Lc '%d:%i:%u' -- "$output")" ||
    fail 'lost acknowledgement rolled back the published directory'
  published_identity="$(<"$published_receipt")"
  [[ "$observed_identity" == "$published_identity" &&
    -z "$CANDIDATE_DIRECTORY" && -z "$CANDIDATE_IDENTITY" ]] ||
    fail 'lost acknowledgement changed publication ownership or identity'
  candidate_residue="$(find -- "$output_parent" -mindepth 1 -maxdepth 1 \
    -name '.retained-ci-import.*' -print -quit)"
  [[ -z "$candidate_residue" ]] ||
    fail 'lost acknowledgement left a hidden candidate residue'
  (CDPATH='' cd / && run_portable_verifier "$output" >/dev/null) ||
    fail 'lost-ack publication is not the exact preverified bundle'
)

test_publication_authority_rejects_namespace_drift() (
  local fixture="$TEST_ROOT/namespace-drift-input"
  local mode=''
  local output_parent=''
  local output=''
  local hidden=''
  local moved_parent=''
  local saved_candidate=''
  local foreign_candidate=''
  local candidate_receipt=''
  local original_native=''

  build_wrapper_fixture "$fixture" 2
  original_native="$(declare -f rename_candidate_directory_noreplace)"
  for mode in candidate-substitution parent-rebind unsupported-native \
    post-reconcile-member; do
    eval "$original_native"
    output_parent="$TEST_ROOT/namespace-drift-$mode"
    mkdir -m 0700 -- "$output_parent"
    output="$(bundle_test_output "$fixture" "$output_parent")"
    configure_write_bundle_test_authority "$output"
    candidate_receipt="$TEST_ROOT/namespace-drift-$mode.candidate"
    moved_parent="$TEST_ROOT/namespace-drift-$mode.original-parent"
    saved_candidate="$output_parent/.saved-candidate-$mode"
    bundle_publication_before_seal_checkpoint() {
      stat -Lc '%d:%i:%u' -- "$1" >"$candidate_receipt"
    }
    bundle_publication_checkpoint() { :; }
    bundle_publication_reconciliation_checkpoint() { :; }
    case "$mode" in
      candidate-substitution)
        bundle_publication_checkpoint() {
          local -r candidate="$1"
          mv -T -- "$candidate" "$saved_candidate" || return 1
          mkdir -m 0700 -- "$candidate" || return 1
          printf 'FOREIGN-CANDIDATE\n' >"$candidate/foreign.txt" || return 1
          chmod 0400 -- "$candidate/foreign.txt"
          chmod 0555 -- "$candidate"
        }
        ;;
      parent-rebind)
        bundle_publication_checkpoint() {
          mv -T -- "$output_parent" "$moved_parent" || return 1
          mkdir -m 0700 -- "$output_parent"
        }
        ;;
      unsupported-native)
        rename_candidate_directory_noreplace() { return 95; }
        ;;
      post-reconcile-member)
        bundle_publication_checkpoint() {
          printf 'FOREIGN-FINAL\n' >"$output" || return 1
          chmod 0600 -- "$output"
        }
        bundle_publication_reconciliation_checkpoint() {
          local -r candidate="$1"
          chmod u+w -- "$candidate" || return 1
          printf 'FOREIGN-MEMBER\n' >"$candidate/foreign-member.txt" || return 1
          chmod 0400 -- "$candidate/foreign-member.txt"
          chmod 0555 -- "$candidate"
        }
        ;;
      *) return 1 ;;
    esac

    if run_write_bundle unused \
      "$fixture/acceptance" "$fixture/fault-security" 2; then
      fail "$mode publication authority failure was accepted"
    fi
    [[ -z "$CANDIDATE_DIRECTORY" && -z "$CANDIDATE_IDENTITY" ]] ||
      fail "$mode failure retained mutable cleanup ownership"
    case "$mode" in
      candidate-substitution)
        foreign_candidate="$(one_hidden_candidate "$output_parent")" ||
          fail 'candidate pathname substitution lost the foreign candidate'
        [[ -d "$saved_candidate" && ! -L "$saved_candidate" &&
          "$(stat -Lc '%d:%i:%u' -- "$saved_candidate")" == \
            "$(<"$candidate_receipt")" &&
          -f "$foreign_candidate/foreign.txt" &&
          "$(<"$foreign_candidate/foreign.txt")" == \
            FOREIGN-CANDIDATE && ! -e "$output" && ! -L "$output" ]] ||
          fail 'candidate pathname substitution was not preserved exactly'
        candidate_seal_from_path "$saved_candidate" >/dev/null ||
          fail 'candidate substitution changed the held exact candidate'
        ;;
      parent-rebind)
        [[ -d "$output_parent" && -d "$moved_parent" &&
          ! -e "$output" && ! -L "$output" ]] ||
          fail 'output-parent rebound state was not preserved'
        hidden="$(one_hidden_candidate "$moved_parent")" ||
          fail 'output-parent rebind lost the exact hidden candidate'
        [[ "$(stat -Lc '%d:%i:%u' -- "$hidden")" == \
          "$(<"$candidate_receipt")" ]] ||
          fail 'output-parent rebind changed the candidate identity'
        ;;
      unsupported-native)
        hidden="$(one_hidden_candidate "$output_parent")" ||
          fail 'unsupported rename authority did not preserve the candidate'
        [[ "$(stat -Lc '%d:%i:%u' -- "$hidden")" == \
          "$(<"$candidate_receipt")" && ! -e "$output" && ! -L "$output" ]] ||
          fail 'unsupported rename authority used a fallback or changed identity'
        candidate_seal_from_path "$hidden" >/dev/null ||
          fail 'unsupported rename authority changed the candidate seal'
        ;;
      post-reconcile-member)
        hidden="$(one_hidden_candidate "$output_parent")" ||
          fail 'post-reconcile foreign member removed the hidden candidate'
        [[ "$(<"$hidden/foreign-member.txt")" == FOREIGN-MEMBER &&
          "$(<"$output")" == FOREIGN-FINAL ]] ||
          fail 'post-reconcile cleanup deleted or changed foreign bytes'
        ;;
    esac
  done
)

test_postrename_final_swap_is_not_executed_or_rolled_back() (
  local fixture="$TEST_ROOT/postrename-swap-input"
  local output_parent="$TEST_ROOT/postrename-swap-output"
  local marker="$TEST_ROOT/postrename-foreign-verifier.marker"
  local output=''
  local saved=''
  local foreign_identity=''

  build_wrapper_fixture "$fixture" 2
  mkdir -m 0700 -- "$output_parent"
  output="$(bundle_test_output "$fixture" "$output_parent")"
  saved="$output_parent/.saved-published-bundle"
  configure_write_bundle_test_authority "$output"
  bundle_publication_complete_checkpoint() {
    mv -T -- "$output" "$saved" || return 1
    mkdir -m 0700 -- "$output" || return 1
    printf '#!/usr/bin/env bash\nprintf marker >%q\n' "$marker" \
      >"$output/verify.sh" || return 1
    chmod 0500 -- "$output/verify.sh"
    stat -Lc '%d:%i:%u' -- "$output" \
      >"$TEST_ROOT/postrename-foreign.identity"
  }

  if run_write_bundle unused \
    "$fixture/acceptance" "$fixture/fault-security" 2; then
    fail 'postrename foreign final swap was accepted'
  fi
  foreign_identity="$(<"$TEST_ROOT/postrename-foreign.identity")"
  [[ -d "$output" && "$(stat -Lc '%d:%i:%u' -- "$output")" == \
    "$foreign_identity" && ! -e "$marker" && -d "$saved" &&
    -z "$CANDIDATE_DIRECTORY" && -z "$CANDIDATE_IDENTITY" ]] ||
    fail 'postrename foreign final was executed, replaced, or rolled back'
  candidate_seal_from_path "$saved" >/dev/null ||
    fail 'postrename swap changed the exact native-published bundle'
)

test_lost_ack_with_foreign_hidden_leaf_still_commits() (
  local fixture="$TEST_ROOT/lost-ack-foreign-input"
  local output_parent="$TEST_ROOT/lost-ack-foreign-output"
  local output=''
  local foreign_hidden=''
  local foreign_identity=''

  build_wrapper_fixture "$fixture" 2
  mkdir -m 0700 -- "$output_parent"
  output="$(bundle_test_output "$fixture" "$output_parent")"
  configure_write_bundle_test_authority "$output"
  bundle_publication_native_ack_checkpoint() {
    mkdir -m 0700 -- "$CANDIDATE_DIRECTORY" || return 1
    printf 'FOREIGN-HIDDEN\n' >"$CANDIDATE_DIRECTORY/foreign.txt" || return 1
    chmod 0400 -- "$CANDIDATE_DIRECTORY/foreign.txt"
    chmod 0555 -- "$CANDIDATE_DIRECTORY"
    stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY" \
      >"$TEST_ROOT/lost-ack-foreign.identity" || return 1
    return 1
  }

  run_write_bundle unused \
    "$fixture/acceptance" "$fixture/fault-security" 2 ||
    fail 'lost ACK plus foreign hidden leaf did not reconcile committed output'
  foreign_hidden="$(one_hidden_candidate "$output_parent")" ||
    fail 'lost ACK foreign hidden leaf was not preserved'
  foreign_identity="$(<"$TEST_ROOT/lost-ack-foreign.identity")"
  [[ "$(stat -Lc '%d:%i:%u' -- "$foreign_hidden")" == "$foreign_identity" &&
    "$(<"$foreign_hidden/foreign.txt")" == FOREIGN-HIDDEN &&
    -d "$output" && -z "$CANDIDATE_DIRECTORY" && -z "$CANDIDATE_IDENTITY" ]] ||
    fail 'lost ACK reconciliation changed foreign or committed identities'
  (CDPATH='' cd / && run_portable_verifier "$output" >/dev/null) ||
    fail 'lost ACK with foreign hidden leaf changed the committed bundle'
)

run_publication_signal_case() (
  local -r phase="$1"
  local -r fixture="$2"
  local -r output="$3"
  local -r receipt="$4"
  local signal_target_pid=''

  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  signal_target_pid="$BASHPID"
  bundle_publication_checkpoint() {
    [[ "$phase" == pre-rename ]] || return 0
    printf '%s\t%s\n' "$CANDIDATE_DIRECTORY" \
      "$(stat -Lc '%d:%i:%u' -- "$CANDIDATE_DIRECTORY")" >>"$receipt" ||
      return 1
    kill -TERM "$signal_target_pid"
    return 143
  }
  bundle_publication_complete_checkpoint() {
    [[ "$phase" == post-rename ]] || return 0
    printf '%s\t%s\n' "$output" "$(stat -Lc '%d:%i:%u' -- "$output")" \
      >>"$receipt" || return 1
    kill -TERM "$signal_target_pid"
    return 143
  }
  run_write_bundle unused \
    "$fixture/acceptance" "$fixture/fault-security" 2
)

test_publication_signals_never_roll_back_or_report_success() (
  local fixture="$TEST_ROOT/publication-signal-input"
  local phase=''
  local output_parent=''
  local output=''
  local receipt=''
  local status=0
  local receipt_path=''
  local receipt_identity=''
  local hidden=''
  local nested_runs_before=''
  local nested_runs_after=''

  build_wrapper_fixture "$fixture" 2
  nested_runs_before="$(wc -l <"$TEST_NESTED_RUNNER_LOG")"
  for phase in pre-rename post-rename; do
    output_parent="$TEST_ROOT/publication-signal-$phase"
    mkdir -m 0700 -- "$output_parent"
    output="$(bundle_test_output "$fixture" "$output_parent")"
    configure_write_bundle_test_authority "$output"
    receipt="$TEST_ROOT/publication-signal-$phase.receipt"
    : >"$receipt"
    set +e
    run_publication_signal_case "$phase" "$fixture" "$output" "$receipt"
    status=$?
    set -e
    [[ "$status" == 143 ]] ||
      fail "$phase TERM returned $status instead of fixed status 143"
    [[ "$(wc -l <"$receipt")" == 1 ]] ||
      fail "$phase TERM checkpoint did not fire exactly once"
    IFS=$'\t' read -r receipt_path receipt_identity <"$receipt"
    case "$phase" in
      pre-rename)
        [[ ! -e "$output" && ! -L "$output" ]] ||
          fail 'pre-rename TERM published a final bundle'
        hidden="$(one_hidden_candidate "$output_parent")" ||
          fail 'pre-rename TERM did not preserve one sealed candidate'
        [[ "$hidden" == "$receipt_path" &&
          "$(stat -Lc '%d:%i:%u' -- "$hidden")" == "$receipt_identity" ]] ||
          fail 'pre-rename TERM changed the preserved candidate identity'
        candidate_seal_from_path "$hidden" >/dev/null ||
          fail 'pre-rename TERM changed the candidate seal'
        ;;
      post-rename)
        [[ -d "$output" && ! -L "$output" && "$output" == "$receipt_path" &&
          "$(stat -Lc '%d:%i:%u' -- "$output")" == "$receipt_identity" &&
          -z "$(find -- "$output_parent" -mindepth 1 -maxdepth 1 \
            -name '.retained-ci-import.*' -print -quit)" ]] ||
          fail 'post-rename TERM rolled back or changed the committed final'
        candidate_seal_from_path "$output" >/dev/null ||
          fail 'post-rename TERM changed the committed final seal'
        ;;
      *) return 1 ;;
    esac
  done
  nested_runs_after="$(wc -l <"$TEST_NESTED_RUNNER_LOG")"
  [[ "$nested_runs_after" == "$nested_runs_before" ]] ||
    fail 'publication signal boundary executed artifact-controlled Bash'
)

test_post_run_only_publication_guard() {
  local handoff="$TEST_ROOT/github-output"
  local output="$TEST_ROOT/retained-claims-aaaaaaaaaaaa-bbbbbbbbbbbb"
  : >"$handoff"
  chmod 0600 -- "$handoff"
  if GITHUB_OUTPUT="$handoff" "$SCRIPT_DIRECTORY/import-retained-ci-evidence.sh" \
    claims-v1 missing-run missing-artifacts missing-acceptance missing-fault \
    "$output" >/dev/null 2>&1; then
    fail 'same-run GITHUB_OUTPUT promotion was accepted'
  fi
  [[ ! -e "$output" && ! -L "$output" ]] ||
    fail 'same-run promotion failure left a published output'
  [[ ! -s "$handoff" ]] || fail 'same-run promotion wrote a handoff'
}

test_partial_cleanup_identity_guard() {
  # cleanup_owned_directory consumes this sourced-script global.
  # shellcheck disable=SC2034
  OUTPUT_PARENT="$TEST_ROOT"
  local candidate="$TEST_ROOT/.retained-ci-import.partial"
  mkdir -- "$candidate"
  local identity=''
  identity="$(stat -Lc '%d:%i:%u' -- "$candidate")"
  expect_reject 'cleanup identity mismatch' cleanup_owned_directory "$candidate" \
    "${identity%:*}:999999"
  [[ -d "$candidate" ]] || fail 'identity mismatch removed an unowned path'
}

main_test() {
  TEST_ROOT="$(mktemp -d /tmp/obi-retained-ci-import-test.XXXXXX)"
  chmod 0700 -- "$TEST_ROOT"
  prepare_nested_verifier_runner
  test_duplicate_json_keys
  test_zip_guards
  test_api_identity_guards
  test_partial_cleanup_identity_guard
  test_cli_version_routing
  test_source_authority_rejects_git_object_replacements
  test_source_verifier_execution_is_sealed_copy_stable
  test_source_verifier_bootstrap_rejects_caller_environment
  test_nested_claim_version_routing
  test_source_import_rejects_resealed_forged_nested_verifiers
  test_wrapper_version_contracts
  test_v2_checksum_roster_rejections
  test_v2_nested_verifier_pin_rejections
  test_wrapper_overclaim_and_leakage
  test_write_bundle_publication_path
  test_candidate_semantics_precede_authoritative_seal
  test_candidate_seal_brackets_validation
  test_bundle_publication_noreplace_preserves_foreign_targets
  test_lost_ack_reconciles_committed_directory
  test_publication_authority_rejects_namespace_drift
  test_postrename_final_swap_is_not_executed_or_rolled_back
  test_lost_ack_with_foreign_hidden_leaf_still_commits
  test_publication_signals_never_roll_back_or_report_success
  test_post_run_only_publication_guard
  printf 'retained CI importer adversarial tests passed\n'
}

main_test
