#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

COMPATIBILITY_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly COMPATIBILITY_DIRECTORY
COMPATIBILITY_REPOSITORY_ROOT="$(cd -- "$COMPATIBILITY_DIRECTORY/../../.." && pwd -P)"
# shellcheck disable=SC2034 # Public to scripts that source this library.
readonly COMPATIBILITY_REPOSITORY_ROOT
readonly COMPATIBILITY_MAX_PRIVATE_FILES=4096
readonly COMPATIBILITY_MAX_PRIVATE_BYTES=2147483648
# shellcheck disable=SC2034 # Public to scripts that source this library.
readonly COMPATIBILITY_MAX_ASSERTION_COUNT=1000000000
# shellcheck disable=SC2034 # Public to scripts that source this library.
readonly COMPATIBILITY_MAX_RESOURCE_MAGNITUDE=1000000000
readonly COMPATIBILITY_PROVIDER_REGISTRY="$COMPATIBILITY_DIRECTORY/provider-registry-v1.json"

compatibility_error() {
  printf 'ERROR: %s\n' "$*" >&2
}

compatibility_die() {
  compatibility_error "$*"
  return 1
}

compatibility_require_commands() {
  local command_name=""
  local -a missing=()

  for command_name in "$@"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    compatibility_die "missing required commands: ${missing[*]}"
  fi
}

compatibility_require_regular_file() {
  local -r path="$1"

  [[ -f "$path" && ! -L "$path" ]] ||
    compatibility_die "expected a regular non-symlink file: $path"
}

compatibility_require_directory() {
  local -r path="$1"

  [[ -d "$path" && ! -L "$path" ]] ||
    compatibility_die "expected a non-symlink directory: $path"
}

compatibility_require_outside_repository() {
  local -r path="$1"

  [[ "$path" == /* ]] ||
    compatibility_die "path must be absolute before repository-boundary validation" || return
  [[ "$path" != "$COMPATIBILITY_REPOSITORY_ROOT" &&
    "$path" != "$COMPATIBILITY_REPOSITORY_ROOT"/* ]] ||
    compatibility_die "campaign results must be outside the source checkout: $path"
}

compatibility_validate_json_file() {
  local -r path="$1"
  local size=0

  compatibility_require_commands python3 || return
  compatibility_require_regular_file "$path" || return
  size="$(stat -Lc '%s' -- "$path")" || return
  [[ "$size" =~ ^[0-9]+$ ]] || return 1
  (( size <= 67108864 )) ||
    compatibility_die "JSON input exceeds the 64 MiB parser bound: $path" || return
  python3 - "$path" <<'PY'
import json
import math
import sys


MAX_SAFE_INTEGER = 9_007_199_254_740_991


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def reject_non_finite(value):
    raise ValueError(f"non-finite JSON number: {value}")


def parse_bounded_integer(value):
    result = int(value)
    if abs(result) > MAX_SAFE_INTEGER:
        raise ValueError(f"JSON integer exceeds the exact IEEE-754 range: {value}")
    return result


def parse_finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite JSON number: {value}")
    return result


with open(sys.argv[1], "r", encoding="utf-8") as source:
    json.load(
        source,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_non_finite,
        parse_int=parse_bounded_integer,
        parse_float=parse_finite_float,
    )
PY
}

compatibility_source_checkout_json() {
  local revision=""
  local tree=""
  local clean=false
  local source_status=""
  local status_available=false

  revision="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" \
    rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)"
  tree="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" \
    rev-parse --verify 'HEAD^{tree}' 2>/dev/null || true)"
  if source_status="$(git -C "$COMPATIBILITY_REPOSITORY_ROOT" status \
    --porcelain=v1 --untracked-files=all 2>/dev/null)"; then
    status_available=true
  fi
  if [[ "$revision" =~ ^[0-9a-f]{40}$ && "$tree" =~ ^[0-9a-f]{40}$ &&
    "$status_available" == true && -z "$source_status" ]]; then
    clean=true
  fi
  jq -cnS \
    --arg revision "$revision" \
    --arg git_tree "$tree" \
    --argjson clean "$clean" \
    '{revision: $revision, git_tree: $git_tree, clean: $clean}'
}

compatibility_validate_source_authority() {
  local -r authority="$1"

  compatibility_validate_json_file "$authority" || return
  jq -e '
    def sha1: type == "string" and test("^[0-9a-f]{40}$");
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    keys == [
      "git_tree", "patch_identity_sha256", "revision", "schema",
      "source_tree_sha256", "tracked_patch_sha256"
    ] and
    .schema == "compatibility-source-authority-v1" and
    (.revision | sha1) and (.git_tree | sha1) and
    (.source_tree_sha256 | sha256) and
    (.tracked_patch_sha256 | sha256) and
    (.patch_identity_sha256 | sha256)
  ' "$authority" >/dev/null ||
    compatibility_die "invalid compatibility source authority"
}

compatibility_safe_git_tree_path() {
  local remainder="$1"
  local component=""

  [[ -n "$remainder" && "$remainder" != /* && "$remainder" != */ &&
    "$remainder" != *'//' && "$remainder" != *$'\n'* ]] || return 1
  while [[ "$remainder" == */* ]]; do
    component="${remainder%%/*}"
    remainder="${remainder#*/}"
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
  done
  [[ -n "$remainder" && "$remainder" != . && "$remainder" != .. ]]
}

compatibility_capture_clean_source_authority() {
  local -r requested_repository="$1"
  local -r requested_scratch="$2"
  local -r requested_output="$3"
  local repository=""
  local scratch=""
  local output=""
  local revision=""
  local final_revision=""
  local git_tree=""
  local final_git_tree=""
  local entry=""
  local metadata=""
  local path=""
  local mode=""
  local object_id=""
  local marker=""
  local flag=""
  local source_tree_sha256=""
  local tracked_patch_sha256=""
  local status_sha256=""
  local patch_identity_sha256=""

  compatibility_require_commands cmp git jq sha256sum || return
  compatibility_require_directory "$requested_repository" || return
  compatibility_require_directory "$requested_scratch" || return
  repository="$(cd -- "$requested_repository" && pwd -P)" || return
  scratch="$(cd -- "$requested_scratch" && pwd -P)" || return
  [[ "$scratch" != "$repository" && "$scratch" != "$repository"/* ]] ||
    compatibility_die "source-authority scratch must be outside the checkout" || return
  [[ "$(dirname -- "$requested_output")" == "$scratch" ]] ||
    compatibility_die "source-authority output must be directly inside its scratch directory" || return
  output="$scratch/$(basename -- "$requested_output")"
  [[ "${output##*/}" != . && "${output##*/}" != .. &&
    "${output##*/}" != */* && "${output##*/}" != *$'\n'* &&
    ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "unsafe source-authority capture output" || return

  revision="$(git -C "$repository" rev-parse --verify 'HEAD^{commit}')" || return
  git_tree="$(git -C "$repository" rev-parse --verify 'HEAD^{tree}')" || return
  [[ "$revision" =~ ^[0-9a-f]{40}$ && "$git_tree" =~ ^[0-9a-f]{40}$ ]] ||
    compatibility_die "checkout has invalid Git source identities" || return

  git -C "$repository" ls-files -v -z >"$scratch/index-flags" || return
  while IFS= read -r -d '' entry; do
    flag="${entry:0:1}"
    case "$flag" in
      [a-z]|S)
        compatibility_die "source index hides assume-unchanged or skip-worktree entries"
        return
        ;;
    esac
  done <"$scratch/index-flags"
  git -C "$repository" ls-files --unmerged -z >"$scratch/unmerged" || return
  [[ ! -s "$scratch/unmerged" ]] ||
    compatibility_die "source index contains unresolved entries" || return
  git -C "$repository" submodule status --recursive >"$scratch/submodules" || return
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "${entry:0:1}" in
      ' ') ;;
      *)
        compatibility_die "source authority requires every gitlink at its pinned revision"
        return
        ;;
    esac
  done <"$scratch/submodules"
  git -C "$repository" status \
    --porcelain=v1 --untracked-files=all --ignore-submodules=none \
    >"$scratch/status" || return
  [[ ! -s "$scratch/status" ]] ||
    compatibility_die "source authority requires a clean checkout" || return
  git -C "$repository" diff --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "working tree differs from the authority revision" || return
  git -C "$repository" diff --cached --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "index differs from the authority revision" || return

  git -C "$repository" ls-tree -r -z --full-tree "$revision" \
    >"$scratch/tree-entries" || return
  : >"$scratch/source-tree.manifest"
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    mode="${metadata%% *}"
    object_id="${metadata##* }"
    compatibility_safe_git_tree_path "$path" ||
      compatibility_die "Git tree contains an unsafe path" || return
    case "$mode" in
      100644) marker=- ;;
      100755) marker=x ;;
      120000) marker=l ;;
      160000) marker=g ;;
      *) compatibility_die "Git tree contains an unsupported mode: $mode"; return ;;
    esac
    [[ "$object_id" =~ ^[0-9a-f]{40}$ ]] ||
      compatibility_die "Git tree contains an invalid object identity" || return
    printf '%s %s %q\n' "$object_id" "$marker" "$path" \
      >>"$scratch/source-tree.manifest"
  done <"$scratch/tree-entries"
  git -C "$repository" diff --binary --no-ext-diff "$revision" -- \
    >"$scratch/tracked.patch" || return
  [[ ! -s "$scratch/tracked.patch" ]] ||
    compatibility_die "tracked patch became nonempty during authority capture" || return
  source_tree_sha256="$(compatibility_sha256 "$scratch/source-tree.manifest")" || return
  tracked_patch_sha256="$(compatibility_sha256 "$scratch/tracked.patch")" || return
  status_sha256="$(compatibility_sha256 "$scratch/status")" || return
  printf '%s\n%s\n%s\n' \
    "$status_sha256" "$source_tree_sha256" "$tracked_patch_sha256" \
    >"$scratch/patch-identity.input"
  patch_identity_sha256="$(compatibility_sha256 "$scratch/patch-identity.input")" || return

  final_revision="$(git -C "$repository" rev-parse --verify 'HEAD^{commit}')" || return
  final_git_tree="$(git -C "$repository" rev-parse --verify 'HEAD^{tree}')" || return
  [[ "$final_revision" == "$revision" && "$final_git_tree" == "$git_tree" ]] ||
    compatibility_die "source revision changed during authority capture" || return
  git -C "$repository" status \
    --porcelain=v1 --untracked-files=all --ignore-submodules=none \
    >"$scratch/final-status" || return
  cmp -s -- "$scratch/status" "$scratch/final-status" ||
    compatibility_die "source checkout changed during authority capture" || return
  git -C "$repository" diff --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "working tree changed during authority capture" || return
  git -C "$repository" diff --cached --quiet --no-ext-diff "$revision" -- ||
    compatibility_die "index changed during authority capture" || return

  jq -nS \
    --arg revision "$revision" \
    --arg git_tree "$git_tree" \
    --arg source_tree_sha256 "$source_tree_sha256" \
    --arg tracked_patch_sha256 "$tracked_patch_sha256" \
    --arg patch_identity_sha256 "$patch_identity_sha256" '
      {
        schema: "compatibility-source-authority-v1",
        revision: $revision,
        git_tree: $git_tree,
        source_tree_sha256: $source_tree_sha256,
        tracked_patch_sha256: $tracked_patch_sha256,
        patch_identity_sha256: $patch_identity_sha256
      }
    ' >"$output"
  chmod 0600 -- "$output"
  compatibility_validate_source_authority "$output"
}

compatibility_source_authority_matches_checkout() (
  local -r authority="$1"
  local scratch_parent=""
  local scratch=""
  local scratch_identity=""
  local recomputed=""

  compatibility_validate_source_authority "$authority" || return
  compatibility_require_commands cmp mktemp || return
  scratch_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$scratch_parent" || return
  scratch="$(mktemp -d "$scratch_parent/.compatibility-authority-check.XXXXXX")" || return
  scratch_identity="$(compatibility_directory_identity "$scratch")" || return
  trap 'compatibility_remove_owned_temp_directory \
    "$scratch" "$scratch_identity" "$scratch_parent" \
    "[.]compatibility-authority-check[.]" || true' EXIT
  recomputed="$scratch/current-source-authority.json"
  compatibility_capture_clean_source_authority \
    "$COMPATIBILITY_REPOSITORY_ROOT" "$scratch" "$recomputed" || return
  cmp -s -- "$authority" "$recomputed" ||
    compatibility_die "source checkout differs from the exact clean source authority"
)

compatibility_provider_result_matches_source_authority() {
  local -r result="$1"
  local -r authority="$2"

  compatibility_validate_json_file "$result" >/dev/null 2>&1 || return 1
  compatibility_validate_source_authority "$authority" >/dev/null 2>&1 || return 1
  jq -e --slurpfile authority "$authority" '
    $authority[0] as $a |
    .source as $source |
    if ($source | type) != "object" then false
    elif ($source | keys) == [
      "clean", "patch_identity_sha256", "revision", "source_tree_sha256",
      "tracked_patch_sha256"
    ] then
      $source.revision == $a.revision and
      $source.source_tree_sha256 == $a.source_tree_sha256 and
      $source.tracked_patch_sha256 == $a.tracked_patch_sha256 and
      $source.patch_identity_sha256 == $a.patch_identity_sha256
    elif ($source | keys) == ["clean", "git_tree", "revision"] then
      if .status == "untested" and
        $source.revision == "" and $source.git_tree == "" then true
      else
        $source.revision == $a.revision and $source.git_tree == $a.git_tree
      end
    else false
    end
  ' "$result" >/dev/null
}

compatibility_provider_exit_matches_status() {
  local -r status="$1"
  local -r exit_status="$2"

  [[ "$exit_status" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  (( exit_status <= 255 )) || return 1
  case "$status" in
    pass) (( exit_status == 0 )) ;;
    fail) (( exit_status != 0 )) ;;
    unsupported) (( exit_status == 78 )) ;;
    untested) (( exit_status == 69 )) ;;
    *) return 1 ;;
  esac
}

compatibility_provider_result_matches_exit() {
  local -r result="$1"
  local -r exit_status="$2"
  local status=""

  compatibility_validate_json_file "$result" >/dev/null 2>&1 || return 1
  status="$(jq -er '.status | select(type == "string")' "$result")" || return
  compatibility_provider_exit_matches_status "$status" "$exit_status"
}

compatibility_sha256() {
  local -r path="$1"
  local digest=""

  compatibility_require_regular_file "$path" || return
  digest="$(sha256sum -- "$path")" || return
  digest="${digest%% *}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] ||
    compatibility_die "invalid SHA-256 output for $path"
  printf '%s\n' "$digest"
}

compatibility_validate_relative_evidence_path() {
  local -r value="$1"

  [[ -n "$value" && ${#value} -le 512 &&
    "$value" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ &&
    "$value" != /* && "$value" != *$'\n'* && "$value" != *$'\r'* &&
    "$value" != . && "$value" != .. &&
    "$value" != ../* && "$value" != */../* && "$value" != */.. &&
    "$value" != ./* && "$value" != */./* && "$value" != */. ]]
}

compatibility_validate_public_evidence_path() {
  local -r value="$1"
  local -r secret_pattern='(^|[^[:alnum:]])(secret|password|passwd|token|credential|api[-_]?key|private[-_]?key)([^[:alnum:]]|$)'
  local lowercase=""

  compatibility_validate_relative_evidence_path "$value" || return
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$ ]] ||
    return 1
  lowercase="${value,,}"
  [[ ! "$lowercase" =~ $secret_pattern ]]
}

compatibility_validate_provider_registry() {
  local -r registry="$COMPATIBILITY_PROVIDER_REGISTRY"

  compatibility_validate_json_file "$registry" || return
  jq -e '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def token: type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$");
    (keys == ["providers", "schema"]) and
    .schema == "compatibility-provider-registry-v1" and
    (.providers | keys) == [
      "preprovisioned-host-application-v1",
      "preprovisioned-jvm-application-v1",
      "preprovisioned-lifecycle-application-v1",
      "runsh-java21-container-v1"
    ] and
    all(.providers | to_entries[];
      (.value | keys == ["approved_drivers", "kind", "launcher"]) and
      .value.kind ==
        (if .key == "runsh-java21-container-v1" then "local" else "external" end) and
      .value.launcher == ("providers/" + .key + ".sh") and
      (.value.approved_drivers | type == "array") and
      all(.value.approved_drivers[];
        keys == ["id", "sha256"] and (.id | token) and (.sha256 | sha256)) and
      ([.value.approved_drivers[].id] | unique | length) ==
        (.value.approved_drivers | length) and
      ([.value.approved_drivers[].sha256] | unique | length) ==
        (.value.approved_drivers | length) and
      (if .value.kind == "local" then
        (.value.approved_drivers | length) == 0
       else true end)) and
    ([.providers[].approved_drivers[].id] | unique | length) ==
      ([.providers[].approved_drivers[].id] | length)
  ' "$registry" >/dev/null ||
    compatibility_die "invalid compatibility provider registry"
}

compatibility_provider_registry_sha256() {
  compatibility_validate_provider_registry || return
  compatibility_sha256 "$COMPATIBILITY_PROVIDER_REGISTRY"
}

compatibility_provider_registry_driver_id() {
  local -r provider="$1"
  local -r driver_sha256="$2"

  compatibility_validate_provider_registry || return
  [[ "$provider" =~ ^[a-z0-9][a-z0-9-]{0,95}$ &&
    "$driver_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  jq -er --arg provider "$provider" --arg sha256 "$driver_sha256" '
    [.providers[$provider].approved_drivers[]? | select(.sha256 == $sha256)] |
    if length == 1 then .[0].id else empty end
  ' "$COMPATIBILITY_PROVIDER_REGISTRY"
}

compatibility_expected_evidence_index() {
  local -r result="$1"

  compatibility_validate_json_file "$result" || return
  jq -cS '
    [(.runtime // {}), (.artifacts // {}), (.assertions // {})] as $roots |
    [range(0; $roots | length) as $root_index |
      ($roots[$root_index] |
        paths(scalars) as $path |
        ($path[-1] | tostring) as $leaf |
        select($leaf == "sha256" or ($leaf | endswith("_sha256"))) |
        {
          field: ([(["runtime", "artifacts", "assertions"][$root_index])] +
            ($path | map(tostring)) | join(".")),
          sha256: getpath($path)
        })] |
    sort_by(.field)
  ' "$result"
}

compatibility_validate_evidence_index_shape() {
  local -r result="$1"

  compatibility_validate_json_file "$result" || return
  jq -e '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def contains_secret_word:
      test("(^|[^[:alnum:]])(secret|password|passwd|token|credential|api[-_]?key|private[-_]?key)([^[:alnum:]]|$)"; "i");
    def field:
      type == "string" and length > 0 and length <= 512 and
      test("^(runtime|artifacts|assertions)([.][A-Za-z0-9_-]+)+$");
    def path_component:
      type == "string" and length > 0 and length <= 128 and
      test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$") and
      (contains_secret_word | not);
    def path:
      type == "string" and length > 0 and length <= 512 and
      (split("/") | all(.[]; path_component));
    if .status == "untested" then .evidence_index == null
    elif .status == "fail" and .assertions.classification? == "provider-contract" then
      .evidence_index == []
    else
      (.evidence_index | type == "array" and length > 0 and length <= 512) and
      all(.evidence_index[];
        keys == ["field", "path", "sha256"] and
        (.field | field) and (.path | path) and (.sha256 | sha256)) and
      ([.evidence_index[].field] | sort) == [.evidence_index[].field] and
      ([.evidence_index[].field] | unique | length) == (.evidence_index | length) and
      ([.evidence_index[].path] | unique | length) == (.evidence_index | length)
    end
  ' "$result" >/dev/null ||
    compatibility_die "provider result has an invalid canonical evidence index"
}

compatibility_validate_collected_driver_identities() {
  local -r identities="$1"

  compatibility_require_regular_file "$identities" || return
  jq -s -e '
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def token: type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$");
    all(.[];
      keys == ["id", "provider", "sha256"] and
      (.id | token) and (.provider | token) and (.sha256 | sha256)) and
    (group_by(.provider) |
      all(.[]; ([.[] | [.id, .sha256]] | unique | length) == 1))
  ' "$identities" >/dev/null ||
    compatibility_die "aggregate mixes or malforms external driver identities"
}

compatibility_plan_path() {
  local -r campaign="$1"

  case "$campaign" in
    compatibility)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/campaign-v3.json"
      ;;
    helper-lifecycle)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/helper-lifecycle-v1.json"
      ;;
    *)
      compatibility_die "unknown campaign: $campaign"
      ;;
  esac
}

compatibility_expected_ids_path() {
  local -r campaign="$1"

  case "$campaign" in
    compatibility)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/expected-v3-cell-ids.txt"
      ;;
    helper-lifecycle)
      printf '%s\n' "$COMPATIBILITY_DIRECTORY/expected-helper-cell-ids.txt"
      ;;
    *)
      compatibility_die "unknown campaign: $campaign"
      ;;
  esac
}

compatibility_campaign_revision() {
  local -r campaign="$1"
  local plan=""

  plan="$(compatibility_plan_path "$campaign")" || return
  case "$campaign" in
    compatibility)
      jq -er '.matrix_revision' "$plan"
      ;;
    helper-lifecycle)
      jq -er '.campaign_revision' "$plan"
      ;;
  esac
}

compatibility_validate_expected_ids_file() {
  local -r expected_ids="$1"

  compatibility_require_regular_file "$expected_ids" || return
  awk '
    !/^[a-z0-9][a-z0-9-]{0,95}$/ { exit 1 }
    seen[$0]++ { exit 1 }
    END { if (NR == 0) exit 1 }
  ' "$expected_ids" || compatibility_die "invalid expected cell ID roster: $expected_ids"
}

compatibility_validate_plan() (
  local -r campaign="$1"
  local plan=""
  local expected_ids=""
  local actual=""
  local expected=""
  local plan_count=""
  local expected_count=""

  compatibility_require_commands jq sha256sum sort cmp mktemp || return
  plan="$(compatibility_plan_path "$campaign")" || return
  expected_ids="$(compatibility_expected_ids_path "$campaign")" || return
  compatibility_require_regular_file "$plan" || return
  compatibility_validate_json_file "$plan" ||
    compatibility_die "campaign plan is not unambiguous JSON: $plan" || return
  compatibility_validate_provider_registry || return
  compatibility_validate_expected_ids_file "$expected_ids" || return
  jq -e --slurpfile registry "$COMPATIBILITY_PROVIDER_REGISTRY" '
    ([.cells[].provider] | unique | sort) as $plan_providers |
    ($registry[0].providers | keys | sort) as $registry_providers |
    all($plan_providers[]; $registry_providers | index(.) != null)
  ' "$plan" >/dev/null ||
    compatibility_die "campaign plan names a provider absent from the registry" || return

  actual="$(mktemp)" || return
  expected="$(mktemp)" || {
    rm -f -- "$actual"
    return 1
  }
  trap 'rm -f -- "$actual" "$expected"' EXIT

  jq -er '
    .expected_cell_count as $count |
    ($count | type == "number" and floor == . and . > 0 and . <= 1000) and
    (.cells | type == "array" and length == $count)
  ' "$plan" >/dev/null ||
    compatibility_die "campaign plan count is malformed: $plan" || return

  jq -er '
    .cells[] |
    (.id | type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$")) and
    (.kernel | type == "string" and length > 0 and length <= 64) and
    (.deployment == "host-process" or .deployment == "container-process") and
    (.cgroup_topology == "unified-v2" or
      .cgroup_topology == "hybrid-v1-v2" or
      .cgroup_topology == "nested-delegated-v2" or
      .cgroup_topology == "sibling-containers") and
    (.architecture == "amd64" or .architecture == "arm64") and
    (.jvm_feature == 8 or .jvm_feature == 11 or
      .jvm_feature == 17 or .jvm_feature == 21) and
    (.agent_distribution == "otel" or .agent_distribution == "splunk") and
    (.agent_version | type == "string" and length > 0 and length <= 64) and
    (.tls == "TLSv1.2" or .tls == "TLSv1.3") and
    (.transport == "getsockopt" or .transport == "unix" or .transport == "auto") and
    (.provider | type == "string" and test("^[a-z0-9][a-z0-9-]{0,63}$"))
  ' "$plan" >/dev/null || compatibility_die "campaign plan contains an invalid cell" || return

  jq -r '.cells[].id' "$plan" | LC_ALL=C sort >"$actual"
  LC_ALL=C sort "$expected_ids" >"$expected"
  cmp -s -- "$expected" "$actual" ||
    compatibility_die "campaign plan cell IDs differ from the frozen roster" || return

  plan_count="$(jq -er '.expected_cell_count' "$plan")" || return
  expected_count="$(wc -l <"$expected_ids")" || return
  [[ "$plan_count" == "$expected_count" ]] ||
    compatibility_die "campaign plan count differs from the frozen roster"

  if [[ "$campaign" == compatibility ]]; then
    jq -e '
      def baseline_dimensions:
        .architecture == "amd64" and .jvm_feature == 21 and
        .agent_distribution == "otel" and .agent_version == "2.28.1" and
        .tls == "TLSv1.3" and .profile == "compatibility-smoke";
      (keys == [
        "baseline", "cells", "excluded_dimensions", "expected_cell_count",
        "matrix_revision", "schema"
      ]) and
      (all(.cells[]; keys == [
        "agent_distribution", "agent_version", "architecture", "cgroup_topology",
        "deployment", "id", "jvm_feature", "kernel", "profile", "provider",
        "slice", "tls", "transport"
      ])) and
      .baseline == {
        kernel: "upstream-6.12", deployment: "container-process",
        cgroup_topology: "unified-v2", architecture: "amd64",
        jvm_feature: 21, agent_distribution: "otel", agent_version: "2.28.1",
        tls: "TLSv1.3", transport: "getsockopt"
      } and
      ([.cells[] | select(.slice == "kernel-topology-deployment")] | length == 34) and
      ([.cells[] | select(.slice == "jvm-agent")] | length == 7) and
      ([.cells[] | select(.slice == "architecture")] | length == 2) and
      ([.cells[] | select(.slice == "tls")] | length == 2) and
      (all(.cells[] | select(.slice == "kernel-topology-deployment");
        baseline_dimensions)) and
      ([.cells[] | select(.slice == "kernel-topology-deployment") |
        [.kernel, .deployment, .cgroup_topology]] | unique | sort) == ([
          ["rhel-9.6-5.14", "container-process", "unified-v2"],
          ["rhel-9.6-5.14", "host-process", "unified-v2"],
          ["supported-runtime-probed", "container-process", "hybrid-v1-v2"],
          ["supported-runtime-probed", "container-process", "nested-delegated-v2"],
          ["supported-runtime-probed", "container-process", "sibling-containers"],
          ["supported-runtime-probed", "host-process", "hybrid-v1-v2"],
          ["supported-runtime-probed", "host-process", "nested-delegated-v2"],
          ["upstream-5.10", "container-process", "unified-v2"],
          ["upstream-5.10", "host-process", "unified-v2"],
          ["upstream-5.15", "container-process", "unified-v2"],
          ["upstream-5.15", "host-process", "unified-v2"],
          ["upstream-6.1", "container-process", "unified-v2"],
          ["upstream-6.1", "host-process", "unified-v2"],
          ["upstream-6.12", "container-process", "unified-v2"],
          ["upstream-6.12", "host-process", "unified-v2"],
          ["upstream-6.6", "container-process", "unified-v2"],
          ["upstream-6.6", "host-process", "unified-v2"]
        ] | sort) and
      (all([.cells[] | select(.slice == "kernel-topology-deployment") |
        {row: [.kernel, .deployment, .cgroup_topology], transport: .transport}] |
        group_by(.row)[];
        ([.[].transport] | sort) == ["getsockopt", "unix"])) and
      ([.cells[] | select(.slice == "jvm-agent") |
        [.jvm_feature, .agent_distribution, .agent_version]] | sort) == ([
          [8, "otel", "2.28.1"], [8, "splunk", "2.28.0"],
          [11, "otel", "2.28.1"], [11, "splunk", "2.28.0"],
          [17, "otel", "2.28.1"], [17, "splunk", "2.28.0"],
          [21, "splunk", "2.28.0"]
        ] | sort) and
      (all(.cells[] | select(.slice == "jvm-agent");
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .architecture == "amd64" and
        .tls == "TLSv1.3" and .transport == "getsockopt" and
        .profile == "compatibility-smoke")) and
      ([.cells[] | select(.slice == "architecture") | .transport] | sort) ==
        ["getsockopt", "unix"] and
      (all(.cells[] | select(.slice == "architecture");
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .architecture == "arm64" and
        .jvm_feature == 21 and .agent_distribution == "otel" and
        .agent_version == "2.28.1" and .tls == "TLSv1.3" and
        .profile == "compatibility-smoke")) and
      ([.cells[] | select(.slice == "tls") | .transport] | sort) ==
        ["getsockopt", "unix"] and
      (all(.cells[] | select(.slice == "tls");
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .architecture == "amd64" and
        .jvm_feature == 21 and .agent_distribution == "otel" and
        .agent_version == "2.28.1" and .tls == "TLSv1.2" and
        .profile == "compatibility-smoke")) and
      .excluded_dimensions == [
        {
          dimension: "rhel-8-4.18-backport", status: "untested",
          reason: "direct-execution-required-no-version-inference"
        },
        {
          dimension: "http2-backend", status: "unsupported",
          reason: "request-safe-http2-not-proven"
        },
        {
          dimension: "auto-transport", status: "out-of-scope",
          reason: "issue-36-control-not-issue-38-transport-dimension"
        }
      ] and
      (all(.cells[]; .transport == "getsockopt" or .transport == "unix")) and
      (all(.cells[]; (.kernel | test("rhel-8|4[.]18"; "i") | not))) and
      (.excluded_dimensions | any(
        .dimension == "rhel-8-4.18-backport" and .status == "untested" and
        .reason == "direct-execution-required-no-version-inference")) and
      (.excluded_dimensions | any(
        .dimension == "http2-backend" and .status == "unsupported"))
    ' "$plan" >/dev/null ||
      compatibility_die "compatibility plan lost its 34+7+2+2 factorization or exclusions"
  else
    jq -e '
      (keys == [
        "campaign_revision", "cells", "expected_cell_count",
        "java_21_only_lifecycle", "required_frameworks", "required_lifecycle",
        "required_repeated_resource_gates", "schema", "unavailable_bridge_contract"
      ]) and
      (all(.cells[]; keys == [
        "agent_distribution", "agent_version", "architecture", "cgroup_topology",
        "deployment", "id", "jvm_feature", "kernel", "provider", "tls",
        "transport"
      ])) and
      (.required_frameworks | sort == [
        "blocking-sslsocket", "netty-sslhandler", "sslengine-socketchannel"
      ]) and
      (.required_repeated_resource_gates | sort == [
        "classloader-weak-reference", "direct-buffer", "live-thread", "native-fd",
        "request-state", "same-process-identity", "task-state", "thread-local-state"
      ]) and
      .unavailable_bridge_contract == {
        max_diagnostic_bytes: 65536,
        max_diagnostic_count: 64
      } and
      (.required_lifecycle | sort == [
        "cross-request-isolation", "cross-thread-handoff", "duplicate-callback",
        "executor-handoff", "extension-absent", "extension-loaded-first",
        "fallback-context-unavailable", "helper-early-attach", "helper-late-attach",
        "normal-extraction", "obi-absent", "obi-restart", "platform-thread",
        "stale-state", "unsupported-transport", "version-mismatch"
      ]) and
      ([.cells[] | [.jvm_feature, .architecture, .transport]] | sort) == ([
        [8, "amd64", "getsockopt"], [11, "amd64", "getsockopt"],
        [17, "amd64", "getsockopt"], [21, "amd64", "getsockopt"],
        [21, "amd64", "unix"], [21, "amd64", "auto"],
        [21, "arm64", "getsockopt"]
      ] | sort) and
      (all(.cells[];
        .kernel == "upstream-6.12" and .deployment == "container-process" and
        .cgroup_topology == "unified-v2" and .agent_distribution == "otel" and
        .agent_version == "2.28.1" and .tls == "TLSv1.3" and
        .provider == "preprovisioned-lifecycle-application-v1")) and
      ([.cells[] | select(.transport == "auto")] | length == 1)
    ' "$plan" >/dev/null ||
      compatibility_die "helper lifecycle plan lost a required framework, resource gate, or auto cell"
  fi
)

compatibility_select_cell() {
  local -r campaign="$1"
  local -r cell_id="$2"
  local -r output="$3"
  local plan=""

  [[ "$cell_id" =~ ^[a-z0-9][a-z0-9-]{0,95}$ ]] ||
    compatibility_die "invalid cell ID: $cell_id" || return
  plan="$(compatibility_plan_path "$campaign")" || return
  compatibility_require_regular_file "$plan" || return
  compatibility_validate_json_file "$plan" || return
  [[ ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "cell selection output already exists: $output" || return
  jq -e --arg id "$cell_id" '[.cells[] | select(.id == $id)] | length == 1' \
    "$plan" >/dev/null || compatibility_die "unknown or duplicate cell ID: $cell_id" || return
  jq -S --arg id "$cell_id" '.cells[] | select(.id == $id)' "$plan" >"$output"
  chmod 0600 -- "$output"
}

compatibility_normalize_architecture() {
  local -r architecture="$1"

  case "$architecture" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) printf 'unknown\n' ;;
  esac
}

compatibility_atomic_json_write() {
  local -r target="$1"
  local parent=""
  local candidate=""

  parent="$(dirname -- "$target")" || return
  compatibility_require_directory "$parent" || return
  [[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] ||
    compatibility_die "unsafe JSON output target: $target" || return
  candidate="$(mktemp "$parent/.compatibility-json.XXXXXX")" || return
  if jq -S . >"$candidate" && chmod 0644 -- "$candidate" &&
    mv -fT -- "$candidate" "$target"; then
    return 0
  fi
  local status=$?
  rm -f -- "$candidate"
  return "$status"
}

compatibility_directory_identity() {
  local -r directory="$1"
  local identity=""

  compatibility_require_directory "$directory" || return
  identity="$(stat -c '%d:%i:%u' -- "$directory")" || return
  [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
  printf '%s\n' "$identity"
}

compatibility_remove_owned_temp_directory() {
  local -r directory="$1"
  local -r expected_identity="$2"
  local -r expected_parent="$3"
  local -r expected_prefix="$4"
  local name=""
  local actual_identity=""

  [[ "$expected_parent" == /* && -d "$expected_parent" && ! -L "$expected_parent" ]] ||
    return 1
  [[ "$directory" == "$expected_parent"/* ]] || return 1
  [[ "${directory%/*}" == "$expected_parent" ]] || return 1
  name="${directory##*/}"
  [[ "$name" =~ ^${expected_prefix}[A-Za-z0-9]{6}$ ]] || return 1
  [[ "$expected_identity" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
  [[ -e "$directory" || -L "$directory" ]] || return 0
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  actual_identity="$(compatibility_directory_identity "$directory")" || return
  [[ "$actual_identity" == "$expected_identity" ]] || return 1
  rm -rf -- "$directory"
}

compatibility_terminate_process_group() {
  local -r process_group="$1"
  local attempt=0

  [[ "$process_group" =~ ^[1-9][0-9]*$ && "$process_group" -gt 1 ]] || return 1
  if ! kill -0 -- "-$process_group" 2>/dev/null; then
    return 0
  fi
  kill -TERM -- "-$process_group" 2>/dev/null || true
  for (( attempt = 0; attempt < 25; attempt += 1 )); do
    if ! kill -0 -- "-$process_group" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  kill -KILL -- "-$process_group" 2>/dev/null || true
  for (( attempt = 0; attempt < 25; attempt += 1 )); do
    if ! kill -0 -- "-$process_group" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  compatibility_die "provider process group did not terminate: $process_group"
}

compatibility_run_bounded_process_group() (
  local -r stdout_file="$1"
  local -r stderr_file="$2"
  local -r file_limit_blocks="$3"
  local -r timeout_seconds="$4"
  shift 4
  local output_parent=""
  local ready_file=""
  local leader=0
  local process_group=0
  local ready_leader=0
  local ready_identity=""
  local wait_status=125
  local cleanup_status=0
  local attempt=0
  local -a command=("$@")
  local -a bounded_command=()

  [[ ${#command[@]} -gt 0 ]] || return 2
  [[ "$file_limit_blocks" =~ ^[1-9][0-9]*$ ]] || return 2
  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || return 2
  compatibility_require_commands python3 sleep timeout || return
  bounded_command=(
    timeout --foreground --signal=TERM --kill-after=60s "${timeout_seconds}s"
    "${command[@]}"
  )
  output_parent="$(dirname -- "$stdout_file")" || return
  compatibility_require_directory "$output_parent" || return
  output_parent="$(cd -- "$output_parent" && pwd -P)" || return
  [[ "$(cd -- "$(dirname -- "$stderr_file")" && pwd -P)" == "$output_parent" ]] ||
    compatibility_die "bounded command outputs must share one safe parent" || return
  [[ ! -e "$stdout_file" && ! -L "$stdout_file" &&
    ! -e "$stderr_file" && ! -L "$stderr_file" ]] ||
    compatibility_die "bounded command output already exists" || return
  ready_file="$(mktemp "$output_parent/.compatibility-process-group.XXXXXX")" || return
  ready_identity="$(stat -c '%d:%i:%u' -- "$ready_file")" || return

  # shellcheck disable=SC2317 # Invoked indirectly by signal and EXIT traps.
  cleanup_process_group() {
    local status=0

    if (( process_group > 1 )); then
      compatibility_terminate_process_group "$process_group" || status=$?
      process_group=0
    fi
    if [[ -f "$ready_file" && ! -L "$ready_file" &&
      "$(stat -c '%d:%i:%u' -- "$ready_file" 2>/dev/null || true)" == "$ready_identity" ]]; then
      rm -f -- "$ready_file"
    fi
    return "$status"
  }
  trap 'cleanup_process_group || true' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  (
    ulimit -f "$file_limit_blocks"
    exec python3 -c '
import os
import sys

ready = sys.argv[1]
command = sys.argv[2:]
os.setsid()
with open(ready, "w", encoding="ascii") as stream:
    stream.write(f"{os.getpid()}:{os.getpgrp()}\n")
    stream.flush()
    os.fsync(stream.fileno())
os.execvp(command[0], command)
' "$ready_file" "${bounded_command[@]}"
  ) >"$stdout_file" 2>"$stderr_file" &
  leader=$!
  for (( attempt = 0; attempt < 100; attempt += 1 )); do
    if [[ -s "$ready_file" ]]; then
      break
    fi
    if ! kill -0 "$leader" 2>/dev/null; then
      break
    fi
    sleep 0.01
  done
  if [[ -s "$ready_file" ]]; then
    IFS=: read -r ready_leader process_group <"$ready_file"
    [[ "$ready_leader" == "$leader" && "$process_group" == "$leader" ]] || {
      process_group=0
      kill -KILL "$leader" 2>/dev/null || true
      wait "$leader" 2>/dev/null || true
      return 125
    }
  else
    set +e
    wait "$leader"
    wait_status=$?
    set -e
    return "$wait_status"
  fi

  set +e
  wait "$leader"
  wait_status=$?
  set -e
  compatibility_terminate_process_group "$process_group" || cleanup_status=$?
  process_group=0
  (( cleanup_status == 0 )) || return "$cleanup_status"
  return "$wait_status"
)

compatibility_build_directory_manifest_pass() {
  local -r directory="$1"
  local -r scratch_prefix="$2"
  local -r root_device="$3"
  local files="$scratch_prefix.files"
  local directories="$scratch_prefix.directories"
  local unexpected="$scratch_prefix.unexpected"
  local manifest="$scratch_prefix.manifest"
  local directory_state="$scratch_prefix.directory-state"
  local relative=""
  local path=""
  local metadata=""
  local after_metadata=""
  local device=""
  local owner=""
  local mode=""
  local links=""
  local entry_count=0
  local byte_count=0
  local file_size=0

  find "$directory" -xdev -mindepth 1 \
    \( -type l -o \( ! -type f ! -type d \) \) -print0 >"$unexpected" || return
  if [[ -s "$unexpected" ]]; then
    compatibility_die "private evidence contains a symlink or non-regular entry"
    return 1
  fi
  find "$directory" -xdev -mindepth 1 -type d -print0 |
    LC_ALL=C sort -z >"$directories" || return
  find "$directory" -xdev -mindepth 1 -type f -print0 |
    LC_ALL=C sort -z >"$files" || return
  : >"$directory_state"
  while IFS= read -r -d '' path; do
    relative="${path#"$directory"/}"
    [[ "$relative" != "$path" && "$relative" != /* && "$relative" != *$'\n'* ]] ||
      compatibility_die "unsafe private evidence directory path" || return
    [[ -d "$path" && ! -L "$path" ]] ||
      compatibility_die "private evidence directory changed during traversal" || return
    metadata="$(stat -c '%d:%i:%u:%a:%Y:%Z' -- "$path")" || return
    IFS=: read -r device _ owner mode _ _ <<<"$metadata"
    [[ "$device" == "$root_device" && "$owner" == "$EUID" ]] ||
      compatibility_die "private evidence directory has unsafe device or owner: $path" || return
    (( (8#$mode & 0022) == 0 )) ||
      compatibility_die "private evidence directory is group/world writable: $path" || return
    (( entry_count += 1 ))
    (( entry_count <= COMPATIBILITY_MAX_PRIVATE_FILES )) ||
      compatibility_die "private evidence exceeds the bounded entry limit" || return
    printf '%s  %s\n' "$metadata" "$relative" >>"$directory_state"
  done <"$directories"
  : >"$manifest"
  while IFS= read -r -d '' path; do
    relative="${path#"$directory"/}"
    [[ "$relative" != "$path" && "$relative" != /* && "$relative" != *$'\n'* ]] ||
      compatibility_die "unsafe private evidence path" || return
    [[ -f "$path" && ! -L "$path" ]] ||
      compatibility_die "private evidence file changed during traversal" || return
    metadata="$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$path")" || return
    IFS=: read -r device _ owner mode links file_size _ _ <<<"$metadata"
    [[ "$device" == "$root_device" && "$owner" == "$EUID" && "$links" == 1 ]] ||
      compatibility_die "private evidence has unsafe device, owner, or link count: $path" || return
    (( (8#$mode & 0022) == 0 )) ||
      compatibility_die "private evidence is group/world writable: $path" || return
    [[ "$file_size" =~ ^[0-9]+$ ]] || return 1
    (( entry_count += 1 ))
    (( byte_count += file_size ))
    (( entry_count <= COMPATIBILITY_MAX_PRIVATE_FILES &&
      byte_count <= COMPATIBILITY_MAX_PRIVATE_BYTES )) ||
      compatibility_die "private evidence exceeds the bounded entry or byte limit" || return
    printf '%s  %s\n' "$(compatibility_sha256 "$path")" "$relative" >>"$manifest"
    after_metadata="$(stat -c '%d:%i:%u:%a:%h:%s:%Y:%Z' -- "$path")" || return
    [[ "$after_metadata" == "$metadata" ]] ||
      compatibility_die "private evidence changed while hashing: $path" || return
  done <"$files"
}

compatibility_directory_manifest() (
  local -r requested_directory="$1"
  local -r requested_output="$2"
  local output=""
  local directory=""
  local output_parent=""
  local output_name=""
  local scratch=""
  local scratch_identity=""
  local root_identity=""
  local final_root_identity=""
  local root_device=""
  local owner=""
  local mode=""

  compatibility_require_commands cmp find mktemp mv sort stat || return
  compatibility_require_directory "$requested_directory" || return
  directory="$(cd -- "$requested_directory" && pwd -P)" || return
  output_parent="$(dirname -- "$requested_output")" || return
  output_name="$(basename -- "$requested_output")" || return
  compatibility_require_directory "$output_parent" || return
  output_parent="$(cd -- "$output_parent" && pwd -P)" || return
  [[ "$output_name" != . && "$output_name" != .. && "$output_name" != */* &&
    "$output_name" != *$'\n'* ]] || compatibility_die "unsafe manifest output name" || return
  output="$output_parent/$output_name"
  [[ ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "manifest output already exists: $output" || return
  [[ "$output_parent" != "$directory" && "$output_parent" != "$directory"/* ]] ||
    compatibility_die "manifest output must be outside the evidenced directory" || return

  root_identity="$(stat -c '%d:%i:%u:%a:%Y:%Z' -- "$directory")" || return
  IFS=: read -r root_device _ owner mode _ _ <<<"$root_identity"
  [[ "$owner" == "$EUID" ]] ||
    compatibility_die "private evidence root has foreign ownership" || return
  (( (8#$mode & 0022) == 0 )) ||
    compatibility_die "private evidence root is group/world writable" || return

  scratch="$(mktemp -d "$output_parent/.compatibility-manifest.XXXXXX")" || return
  scratch_identity="$(compatibility_directory_identity "$scratch")" || return
  trap 'compatibility_remove_owned_temp_directory \
    "$scratch" "$scratch_identity" "$output_parent" "[.]compatibility-manifest[.]" || true' EXIT
  compatibility_build_directory_manifest_pass \
    "$directory" "$scratch/first" "$root_device" || return
  compatibility_build_directory_manifest_pass \
    "$directory" "$scratch/second" "$root_device" || return
  cmp -s -- "$scratch/first.files" "$scratch/second.files" ||
    compatibility_die "private evidence file list changed between manifest passes" || return
  cmp -s -- "$scratch/first.directories" "$scratch/second.directories" ||
    compatibility_die "private evidence directory list changed between manifest passes" || return
  cmp -s -- "$scratch/first.directory-state" "$scratch/second.directory-state" ||
    compatibility_die "private evidence directory metadata changed between manifest passes" || return
  cmp -s -- "$scratch/first.manifest" "$scratch/second.manifest" ||
    compatibility_die "private evidence content changed between manifest passes" || return
  final_root_identity="$(stat -c '%d:%i:%u:%a:%Y:%Z' -- "$directory")" || return
  [[ "$final_root_identity" == "$root_identity" ]] ||
    compatibility_die "private evidence root changed during manifest construction" || return
  chmod 0600 -- "$scratch/first.manifest"
  mv -T -- "$scratch/first.manifest" "$output"
)
