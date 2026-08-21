#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$SCRIPT_DIRECTORY/import-retained-ci-evidence.sh"
trap - EXIT HUP INT TERM

TEST_ROOT=''

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
  local head=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  local evidence=''
  local file=''
  mkdir -p -- "$root/acceptance" "$root/fault-security"
  for file in README.md SANITIZATION.md acceptance-claims.json \
    authority-summary.json derivation-receipt.json SHA256SUMS; do
    printf '{}\n' >"$root/acceptance/$file"
  done
  for file in README.md SANITIZATION.md fault-security-matrix.json \
    derivation-receipt.json SHA256SUMS; do
    printf '{}\n' >"$root/fault-security/$file"
  done
  printf '#!/usr/bin/env bash\nexit 0\n' >"$root/acceptance/verify.sh"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$root/fault-security/verify.sh"
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
  jq -cS -n --arg head "$head" '{source:{revision:$head,
    source_tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}' \
    >"$root/fault-security/fault-security-matrix.json"
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
  jq -cS -n --arg evidence "$evidence" --arg head "$head" '{
    schema:"obi-retained-ci-claim-index-v1",status:"passed",evidence_id:$evidence,
    source:{revision:$head,tree_sha256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
    coverage:{issue_32:{pointer:"acceptance/acceptance-claims.json#/issue_32",status:"passed"},
      issue_34:{pointer:"acceptance/acceptance-claims.json#/issue_34",status:"passed"},
      issue_36:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_36",status:"passed"},
      issue_40:{pointer:"fault-security/fault-security-matrix.json#/coverage/issue_40",status:"passed"}}}' \
    >"$root/claim-index.json"
  write_portable_verifier "$root/verify.sh"
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
  root="$TEST_ROOT/retained-claims-aaaaaaaaaaaa-${evidence:0:12}"
  build_wrapper_fixture "$root"
  chmod u+w -- "$root"
  printf 'private\n' >"$root/raw.log"
  expect_reject 'private leakage inventory' bash "$root/verify.sh"
}

test_write_bundle_publication_path() {
  local fixture="$TEST_ROOT/bundle-input"
  local output_parent="$TEST_ROOT/bundle-output"
  local receipt_sha=''
  local evidence=''
  local output=''
  build_wrapper_fixture "$fixture"
  mkdir -m 0700 -- "$output_parent"
  HEAD_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  # These globals are consumed by the sourced write_bundle implementation.
  # shellcheck disable=SC2034
  SOURCE_TREE_SHA256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  RUN_ID=123
  RUN_ATTEMPT=2
  receipt_sha="$(sha256sum <"$fixture/acceptance/derivation-receipt.json")"
  receipt_sha="${receipt_sha%% *}"
  evidence="$(printf '%s\n' "$HEAD_SHA" "$RUN_ID" "$RUN_ATTEMPT" \
    "$receipt_sha" "$receipt_sha" | sha256sum)"; evidence="${evidence%% *}"
  output="$output_parent/retained-claims-${HEAD_SHA:0:12}-${evidence:0:12}"
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
  write_bundle unused "$fixture/acceptance" "$fixture/fault-security" ||
    fail 'canonical bundle could not publish under its final verified leaf'
  [[ -d "$output" && ! -L "$output" ]] || fail 'bundle publication is absent'
  (CDPATH='' cd / && bash "$output/verify.sh" >/dev/null) ||
    fail 'published bundle failed portable verification'
}

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
  test_duplicate_json_keys
  test_zip_guards
  test_api_identity_guards
  test_partial_cleanup_identity_guard
  test_wrapper_overclaim_and_leakage
  test_write_bundle_publication_path
  test_post_run_only_publication_guard
  printf 'retained CI importer adversarial tests passed\n'
}

main_test
