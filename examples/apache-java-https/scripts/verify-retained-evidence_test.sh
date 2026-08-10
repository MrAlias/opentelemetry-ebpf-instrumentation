#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERIFIER="$SCRIPT_DIR/verify-retained-evidence.sh"
TEST_TMP_DIR=""
readonly SCRIPT_DIR VERIFIER

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

  for command_name in cp find git jq mkdir mktemp rm sha256sum sort; do
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
  jq -cn --arg evidence_id "$evidence_id" '{
    status: "passed",
    exit_status: 0,
    acceptance_evidence: true,
    acceptance_evidence_reason: "none",
    failure_stage: "none",
    failure_line: 0,
    evidence_id: $evidence_id
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
  local source_revision=""
  local rejection_output=""

  check_dependencies
  [[ -x "$VERIFIER" ]] || die "verifier is not executable: $VERIFIER"
  TEST_TMP_DIR="$(mktemp -d)"
  repository="$TEST_TMP_DIR/repository"
  fixture_verifier="$repository/examples/apache-java-https/scripts/verify-retained-evidence.sh"
  bundle="$repository/examples/apache-java-https/evidence/$evidence_id"

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

  printf 'verify-retained-evidence current-code tests passed\n'
}

main "$@"
