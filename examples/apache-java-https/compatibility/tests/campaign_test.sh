#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

TEST_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TEST_DIRECTORY
CAMPAIGN_DIRECTORY="$(cd -- "$TEST_DIRECTORY/.." && pwd -P)"
readonly CAMPAIGN_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$CAMPAIGN_DIRECTORY/lib.sh"

TEST_ROOT=""
TEST_ROOT_IDENTITY=""
TEST_ROOT_PARENT=""
FAILURE_OUTPUT_COUNTER=0
SOURCE_AUTHORITY=""
RUN_SOURCE_AUTHORITY=""
EXECUTION_REPOSITORY=""
EXECUTION_CAMPAIGN_DIRECTORY=""
SOURCE_MARKER=""
FIXTURE_REVISION=""
FIXTURE_GIT_TREE=""
FIXTURE_TREE=""
FIXTURE_PATCH=""
FIXTURE_SHA=""

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  return 1
}

cleanup_test_root() {
  [[ -n "$TEST_ROOT" ]] || return 0
  compatibility_remove_owned_temp_directory \
    "$TEST_ROOT" "$TEST_ROOT_IDENTITY" "$TEST_ROOT_PARENT" \
    "obi-compatibility-test[.]" ||
    compatibility_error "refused to remove replaced test scratch directory"
}

create_clean_execution_repository() {
  local destination_parent=""
  local mock_driver_sha=""
  local registry=""

  EXECUTION_REPOSITORY="$TEST_ROOT/source-checkout"
  destination_parent="$EXECUTION_REPOSITORY/examples/apache-java-https"
  install -d -m 0700 -- "$destination_parent"
  cp -a -- "$CAMPAIGN_DIRECTORY" "$destination_parent/compatibility"
  EXECUTION_CAMPAIGN_DIRECTORY="$destination_parent/compatibility"
  registry="$EXECUTION_CAMPAIGN_DIRECTORY/provider-registry-v1.json"
  mock_driver_sha="$(compatibility_sha256 "$TEST_DIRECTORY/mock-external-driver.sh")"
  jq -S --arg sha "$mock_driver_sha" '
    .providers["preprovisioned-host-application-v1"].approved_drivers =
      [{id: "fixture-host-driver-v1", sha256: $sha}] |
    .providers["preprovisioned-jvm-application-v1"].approved_drivers =
      [{id: "fixture-jvm-driver-v1", sha256: $sha}] |
    .providers["preprovisioned-lifecycle-application-v1"].approved_drivers =
      [{id: "fixture-lifecycle-driver-v1", sha256: $sha}]
  ' "$registry" >"$registry.new"
  mv -fT -- "$registry.new" "$registry"
  SOURCE_MARKER="$EXECUTION_REPOSITORY/source-authority-marker.txt"
  printf 'source authority marker\n' >"$SOURCE_MARKER"
  chmod 0600 -- "$SOURCE_MARKER"
  git -C "$EXECUTION_REPOSITORY" init --quiet
  git -C "$EXECUTION_REPOSITORY" add --all
  git -C "$EXECUTION_REPOSITORY" \
    -c user.name='Compatibility Test' \
    -c user.email='compatibility-test@example.invalid' \
    commit --quiet --no-gpg-sign -m 'compatibility source fixture'

  "$EXECUTION_CAMPAIGN_DIRECTORY/create-source-authority.sh" \
    --output "$SOURCE_AUTHORITY"
  install -m 0600 -- "$SOURCE_AUTHORITY" "$RUN_SOURCE_AUTHORITY"
  FIXTURE_REVISION="$(jq -er '.revision' "$SOURCE_AUTHORITY")"
  FIXTURE_GIT_TREE="$(jq -er '.git_tree' "$SOURCE_AUTHORITY")"
  FIXTURE_TREE="$(jq -er '.source_tree_sha256' "$SOURCE_AUTHORITY")"
  FIXTURE_PATCH="$(jq -er '.tracked_patch_sha256' "$SOURCE_AUTHORITY")"
  FIXTURE_SHA="$(jq -er '.patch_identity_sha256' "$SOURCE_AUTHORITY")"
}

restore_source_marker() {
  printf 'source authority marker\n' >"$SOURCE_MARKER"
  chmod 0600 -- "$SOURCE_MARKER"
}

provider_path() {
  local -r provider="$1"
  printf '%s/providers/%s.sh\n' \
    "${EXECUTION_CAMPAIGN_DIRECTORY:-$CAMPAIGN_DIRECTORY}" "$provider"
}

test_registry_path() {
  printf '%s/provider-registry-v1.json\n' \
    "${EXECUTION_CAMPAIGN_DIRECTORY:-$CAMPAIGN_DIRECTORY}"
}

test_sealer_path() {
  printf '%s/seal-cell.sh\n' \
    "${EXECUTION_CAMPAIGN_DIRECTORY:-$CAMPAIGN_DIRECTORY}"
}

expect_failure() {
  local -r label="$1"
  shift

  if "$@" >"$TEST_ROOT/$label.stdout" 2>"$TEST_ROOT/$label.stderr"; then
    fail "$label unexpectedly succeeded"
  fi
}

make_untested_cell() {
  local -r campaign="$1"
  local -r cell_id="$2"
  local -r output="$3"
  local private="$output/private"
  local requested="$private/requested.json"
  local result="$private/provider-result.json"
  local plan=""
  local revision=""
  local plan_sha256=""
  local provider=""
  local launcher=""

  install -d -m 0700 -- "$private"
  install -m 0600 -- "$SOURCE_AUTHORITY" "$private/source-authority.json"
  compatibility_select_cell "$campaign" "$cell_id" "$requested"
  plan="$(compatibility_plan_path "$campaign")"
  revision="$(compatibility_campaign_revision "$campaign")"
  plan_sha256="$(compatibility_sha256 "$plan")"
  provider="$(jq -er '.provider' "$requested")"
  launcher="$(provider_path "$provider")"
  jq -nS \
    --arg campaign "$campaign" \
    --arg revision "$revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg provider "$provider" \
    --arg registry_sha256 "$(compatibility_sha256 "$(test_registry_path)")" \
    --arg adapter_sha256 "$(compatibility_sha256 "$launcher")" \
    --slurpfile requested "$requested" '
      {
        schema: "compatibility-provider-result-v1",
        campaign: $campaign,
        campaign_revision: $revision,
        plan_sha256: $plan_sha256,
        cell_id: $requested[0].id,
        provider: $provider,
        provider_exit_status: 69,
        status: "untested",
        reason: "fixture-platform-unavailable",
        attempted: false,
        infrastructure_failure: true,
        requested: $requested[0],
        provider_registry_sha256: $registry_sha256,
        external_driver: null,
        command: {
          executed: false,
          argv: ["fixture:platform-unavailable"],
          adapter_sha256: $adapter_sha256,
          exit_status: null
        },
        source: {revision: "", git_tree: "", clean: false},
        runtime: null,
        artifacts: null,
        assertions: null,
        evidence_index: null,
        raw_evidence: null
      }
    ' >"$result"
  chmod 0600 -- "$result"
  compatibility_directory_manifest "$private" "$output/private.sha256"
  "$(test_sealer_path)" \
    --campaign "$campaign" \
    --cell "$requested" \
    --provider-result "$result" \
    --provider-launcher "$launcher" \
    --private-directory "$private" \
    --private-manifest "$output/private.sha256" \
    --output "$output/cell.json"
  compatibility_sha256 "$output/cell.json" >"$output/cell.json.sha256"
  chmod 0644 -- "$output/cell.json" "$output/cell.json.sha256"
}

refresh_private_manifest() {
  local -r cell_directory="$1"
  local candidate="$cell_directory/private.sha256.new"

  compatibility_directory_manifest "$cell_directory/private" "$candidate"
  mv -fT -- "$candidate" "$cell_directory/private.sha256"
}

refresh_raw_manifest() {
  local -r cell_directory="$1"
  local raw="$cell_directory/private/raw"
  local manifest="$cell_directory/private/raw.sha256"
  local candidate="${manifest}.new"

  compatibility_directory_manifest "$raw" "$candidate"
  mv -fT -- "$candidate" "$manifest"
  rewrite_json "$cell_directory/private/provider-result.json" \
    ".raw_evidence.manifest_sha256 = \"$(compatibility_sha256 "$manifest")\""
  refresh_private_manifest "$cell_directory"
}

rebind_indexed_file() {
  local -r result="$1"
  local -r raw="$2"
  local -r field="$3"
  local path=""
  local sha256=""

  path="$(jq -er --arg field "$field" \
    '.evidence_index[] | select(.field == $field) | .path' "$result")"
  sha256="$(compatibility_sha256 "$raw/$path")"
  rewrite_json "$result" \
    "setpath((\"$field\" | split(\".\")); \"$sha256\") |
     .evidence_index |= map(if .field == \"$field\" then
       .sha256 = \"$sha256\" else . end)"
}

rebind_indexed_path() {
  local -r cell_directory="$1"
  local -r field="$2"
  local -r new_path="$3"
  local result="$cell_directory/private/provider-result.json"
  local raw="$cell_directory/private/raw"
  local candidate="${result}.indexed-path"
  local old_path=""
  local new_parent=""

  compatibility_validate_relative_evidence_path "$new_path" || return
  old_path="$(jq -er --arg field "$field" '
    [.evidence_index[] | select(.field == $field)] |
    if length == 1 then .[0].path else empty end
  ' "$result")" || return
  compatibility_require_regular_file "$raw/$old_path" || return
  [[ ! -e "$raw/$new_path" && ! -L "$raw/$new_path" ]] || return 1
  new_parent="$(dirname -- "$raw/$new_path")" || return
  install -d -m 0700 -- "$new_parent"
  mv -- "$raw/$old_path" "$raw/$new_path"
  jq -S --arg field "$field" --arg path "$new_path" '
    .evidence_index |= map(
      if .field == $field then .path = $path else . end)
  ' "$result" >"$candidate"
  chmod --reference="$result" -- "$candidate"
  mv -fT -- "$candidate" "$result"
  refresh_raw_manifest "$cell_directory"
}

refresh_cell_digest() {
  local -r cell_directory="$1"
  compatibility_sha256 "$cell_directory/cell.json" >"$cell_directory/cell.json.sha256"
  chmod 0644 -- "$cell_directory/cell.json.sha256"
}

refresh_sealed_cell() {
  local -r campaign="$1"
  local -r cell_directory="$2"
  local candidate="$cell_directory/cell.json.new"
  local launcher=""

  launcher="$(provider_path "$(
    jq -er '.provider' "$cell_directory/private/requested.json"
  )")"
  "$(test_sealer_path)" \
    --campaign "$campaign" \
    --cell "$cell_directory/private/requested.json" \
    --provider-result "$cell_directory/private/provider-result.json" \
    --provider-launcher "$launcher" \
    --private-directory "$cell_directory/private" \
    --private-manifest "$cell_directory/private.sha256" \
    --output "$candidate"
  mv -fT -- "$candidate" "$cell_directory/cell.json"
  refresh_cell_digest "$cell_directory"
}

rewrite_json() {
  local -r path="$1"
  local -r filter="$2"
  local candidate="$path.new"

  jq -S "$filter" "$path" >"$candidate"
  chmod --reference="$path" -- "$candidate"
  mv -fT -- "$candidate" "$path"
}

expect_collect_failure() {
  local -r label="$1"
  local -r campaign="$2"
  local -r input_root="$3"
  local output=""

  (( FAILURE_OUTPUT_COUNTER += 1 ))
  output="$TEST_ROOT/rejected-aggregate-$FAILURE_OUTPUT_COUNTER"
  expect_failure "$label" "$EXECUTION_CAMPAIGN_DIRECTORY/collect.sh" \
    --campaign "$campaign" --input-root "$input_root" \
    --source-authority "$SOURCE_AUTHORITY" --output "$output"
  [[ ! -e "$output" && ! -L "$output" ]] || fail "$label published an aggregate"
}

bind_candidate_evidence_index() {
  local -r result="$1"
  local -r raw="$2"
  local entries="$raw/.index-entries.jsonl"
  local fields="$raw/.index-fields.tsv"
  local candidate="${result}.indexed"
  local field=""
  local path=""
  local file=""
  local sha256=""
  local selector=""
  local release=""
  local topology=""
  local count=0

  selector="$(jq -er '.requested.kernel' "$result")"
  release="$(jq -er '.runtime.kernel.release' "$result")"
  topology="$(jq -er '.requested.cgroup_topology' "$result")"
  compatibility_expected_evidence_index "$result" |
    jq -r '.[] | [.field, .sha256] | @tsv' >"$fields"
  : >"$entries"
  while IFS=$'\t' read -r field _; do
    (( count += 1 ))
    path="proof-$(printf '%03d' "$count").txt"
    case "$field" in
      runtime.kernel.provenance_sha256)
        path="campaign-attestations/kernel-provenance.json"
        ;;
      runtime.cgroup_topology.attestation_sha256)
        path="campaign-attestations/topology-attestation.json"
        ;;
      assertions.unavailable_bridge.normal_result_sha256)
        path=unavailable-bridge/normal-result.json
        ;;
      assertions.unavailable_bridge.unavailable_result_sha256)
        path=unavailable-bridge/unavailable-result.json
        ;;
      assertions.unavailable_bridge.normal_agent_extraction.evidence_sha256)
        path=unavailable-bridge/normal-agent-extraction.json
        ;;
      assertions.unavailable_bridge.diagnostics.evidence_sha256)
        path=unavailable-bridge/diagnostics.json
        ;;
    esac
    file="$raw/$path"
    install -d -m 0700 -- "$(dirname -- "$file")"
    case "$field" in
      runtime.kernel.provenance_sha256)
        jq -nS --arg selector "$selector" --arg release "$release" '{
          schema: "compatibility-kernel-provenance-v1",
          selector: $selector,
          observed_release: $release,
          source_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          version_inference: false
        }' >"$file"
        ;;
      runtime.cgroup_topology.attestation_sha256)
        jq -nS --arg topology "$topology" '
          {
            schema: "compatibility-topology-attestation-v1",
            cgroup_topology: $topology,
            runtime_observed: true,
            process_cgroups_sha256:
              "2222222222222222222222222222222222222222222222222222222222222222"
          } +
          (if $topology == "nested-delegated-v2" then
            {delegation_writable:true, nested_path_observed:true}
           elif $topology == "sibling-containers" then
            {distinct_sibling_cgroups:true}
           else {} end)
        ' >"$file"
        ;;
      assertions.unavailable_bridge.normal_result_sha256|\
        assertions.unavailable_bridge.unavailable_result_sha256)
        jq -nS '{schema:"compatibility-bridge-result-v1",result:"unchanged"}' >"$file"
        ;;
      assertions.unavailable_bridge.normal_agent_extraction.evidence_sha256)
        jq -nS '{
          schema:"compatibility-normal-agent-extraction-v1", status:"pass",
          requests:3, exact_parents:3, wrong_parents:0, crashes:0
        }' >"$file"
        ;;
      assertions.unavailable_bridge.diagnostics.evidence_sha256)
        jq -nS '{
          schema:"compatibility-unavailable-bridge-diagnostics-v1",
          diagnostics:["bridge-unavailable-control"]
        }' >"$file"
        ;;
      *) printf 'synthetic proof for %s\n' "$field" >"$file" ;;
    esac
    chmod 0600 -- "$file"
    if [[ "$field" == assertions.unavailable_bridge.diagnostics.evidence_sha256 ]]; then
      jq -S --argjson bytes "$(stat -Lc '%s' -- "$file")" \
        '.assertions.unavailable_bridge.diagnostics.bytes = $bytes' \
        "$result" >"$candidate"
      chmod 0600 -- "$candidate"
      mv -fT -- "$candidate" "$result"
    fi
    sha256="$(compatibility_sha256 "$file")"
    jq -S --arg field "$field" --arg sha256 "$sha256" \
      'setpath(($field | split(".")); $sha256)' "$result" >"$candidate"
    chmod 0600 -- "$candidate"
    mv -fT -- "$candidate" "$result"
    jq -cnS --arg field "$field" --arg path "$path" --arg sha256 "$sha256" \
      '{field:$field,path:$path,sha256:$sha256}' >>"$entries"
  done <"$fields"
  jq -sS 'sort_by(.field)' "$entries" >"$raw/.evidence-index.json"
  jq -S --slurpfile index "$raw/.evidence-index.json" \
    '.evidence_index = $index[0]' "$result" >"$candidate"
  chmod 0600 -- "$candidate"
  mv -fT -- "$candidate" "$result"
  rm -f -- "$entries" "$fields" "$raw/.evidence-index.json"
}

write_claimed_pass_candidate() {
  local -r campaign="$1"
  local -r cell_id="$2"
  local -r output="$3"
  local private="$output/private"
  local raw="$private/raw"
  local requested="$private/requested.json"
  local result="$private/provider-result.json"
  local plan=""
  local revision=""
  local plan_sha256=""
  local provider=""
  local launcher=""
  local frameworks='{}'
  local lifecycle='{}'
  local resources='{}'
  local assertions='{}'
  local external_driver=null
  local registry_sha256=""
  local driver_id=""
  local command_adapter_sha256=""

  install -d -m 0700 -- "$private" "$raw"
  install -m 0600 -- "$SOURCE_AUTHORITY" "$private/source-authority.json"
  printf 'synthetic mutation fixture; not execution evidence\n' >"$raw/fixture.txt"
  chmod 0600 -- "$raw/fixture.txt"
  compatibility_select_cell "$campaign" "$cell_id" "$requested"
  plan="$(compatibility_plan_path "$campaign")"
  revision="$(compatibility_campaign_revision "$campaign")"
  plan_sha256="$(compatibility_sha256 "$plan")"
  provider="$(jq -er '.provider' "$requested")"
  launcher="$(provider_path "$provider")"
  if [[ "$campaign" == helper-lifecycle ]]; then
    frameworks="$(jq -cS --arg sha "$FIXTURE_SHA" '
      .required_frameworks |
      map({key: ., value: {
        status: "pass", evidence_sha256: $sha,
        requests: 3, exact_parents: 3, wrong_parents: 0, crashes: 0
      }}) | from_entries
    ' "$plan")"
    lifecycle="$(jq -cS --arg sha "$FIXTURE_SHA" '
      .required_lifecycle |
      map({key: ., value: {
        status: "pass", evidence_sha256: $sha,
        requests: 3, exact_parents: 3, wrong_parents: 0, crashes: 0
      }}) | from_entries
    ' "$plan")"
    resources="$(jq -cS --arg sha "$FIXTURE_SHA" '
      .required_repeated_resource_gates |
      map({key: ., value: {
        status: "pass", cycles: 3, evidence_sha256: $sha,
        baseline: 0, final: 0, delta: 0, allowed_delta: 0,
        trend_slope: 0, maximum_trend_slope: 0
      }}) | from_entries
    ' "$plan")"
    assertions="$(jq -cnS \
      --arg sha "$FIXTURE_SHA" \
      --argjson jvm "$(jq -er '.jvm_feature' "$requested")" \
      --argjson frameworks "$frameworks" \
      --argjson lifecycle "$lifecycle" \
      --argjson resources "$resources" '
        {
          application_result: "pass", cleanup: "pass",
          required_cells_skipped: false, product_failure: false,
          exact_parent: {status: "pass", requests: 3, matched: 3, wrong: 0},
          frameworks: $frameworks,
          lifecycle: $lifecycle,
          resource_gates: $resources,
          unavailable_bridge: {
            status: "pass", result_equivalent: true,
            normal_result_sha256: $sha,
            unavailable_result_sha256: $sha,
            normal_agent_extraction: {
              status: "pass", evidence_sha256: $sha,
              requests: 3, exact_parents: 3, wrong_parents: 0, crashes: 0
            },
            diagnostics: {
              status: "pass", evidence_sha256: $sha,
              count: 1, bytes: 0, max_count: 64, max_bytes: 65536
            }
          },
          virtual_thread:
            (if $jvm == 21 then {
              status: "pass", evidence_sha256: $sha,
              requests: 3, exact_parents: 3, wrong_parents: 0, crashes: 0
            }
             else {status: "unsupported", reason: "requires-java-21", evidence_sha256: $sha}
             end)
        }
      ')"
  else
    assertions="$(jq -cnS --arg profile "$(jq -er '.profile' "$requested")" '
      {
        profile: $profile, application_result: "pass", cleanup: "pass",
        required_cells_skipped: false, product_failure: false,
        exact_parent: {status: "pass", requests: 3, matched: 3, wrong: 0}
      }
    ')"
  fi
  registry_sha256="$(compatibility_sha256 "$(test_registry_path)")"
  command_adapter_sha256="$(compatibility_sha256 "$launcher")"
  if [[ "$provider" != runsh-java21-container-v1 ]]; then
    case "$provider" in
      preprovisioned-host-application-v1) driver_id="fixture-host-driver-v1" ;;
      preprovisioned-jvm-application-v1) driver_id="fixture-jvm-driver-v1" ;;
      preprovisioned-lifecycle-application-v1) driver_id="fixture-lifecycle-driver-v1" ;;
      *) return 1 ;;
    esac
    install -m 0500 -- "$TEST_DIRECTORY/mock-external-driver.sh" \
      "$private/external-driver.snapshot"
    command_adapter_sha256="$(compatibility_sha256 \
      "$private/external-driver.snapshot")"
    external_driver="$(jq -cnS \
      --arg id "$driver_id" --arg sha256 "$command_adapter_sha256" '{
        id:$id, sha256:$sha256, snapshot:"external-driver.snapshot"
      }')"
  fi
  jq -nS \
    --arg campaign "$campaign" \
    --arg revision "$revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg provider "$provider" \
    --arg adapter_sha256 "$command_adapter_sha256" \
    --arg registry_sha256 "$registry_sha256" \
    --arg source_revision "$FIXTURE_REVISION" \
    --arg source_tree "$FIXTURE_TREE" \
    --arg source_patch "$FIXTURE_PATCH" \
    --arg sha "$FIXTURE_SHA" \
    --arg raw_manifest_sha256 "$FIXTURE_SHA" \
    --slurpfile requested "$requested" \
    --argjson assertions "$assertions" \
    --argjson external_driver "$external_driver" '
      $requested[0] as $r |
      {
        schema: "compatibility-provider-result-v1",
        campaign: $campaign,
        campaign_revision: $revision,
        plan_sha256: $plan_sha256,
        cell_id: $r.id,
        provider: $provider,
        provider_exit_status: 0,
        status: "pass",
        reason: "synthetic-claimed-pass",
        attempted: true,
        infrastructure_failure: false,
        requested: $r,
        provider_registry_sha256: $registry_sha256,
        external_driver: $external_driver,
        command: {
          executed: true,
          argv: ["fixture-driver", "--cell", $r.id],
          adapter_sha256: $adapter_sha256,
          exit_status: 0
        },
        source: {
          revision: $source_revision, clean: true,
          source_tree_sha256: $source_tree,
          tracked_patch_sha256: $source_patch,
          patch_identity_sha256: $sha
        },
        runtime: {
          kernel: {
            selector: $r.kernel, release: "6.12.0-fixture",
            provenance_sha256: $sha, version_inference: false, btf_sha256: $sha
          },
          architecture: $r.architecture,
          deployment: {
            requested: $r.deployment, observed: $r.deployment,
            proof: "synthetic-mutation-fixture", evidence_sha256: $sha
          },
          cgroup_topology: {
            requested: $r.cgroup_topology, observed: $r.cgroup_topology,
            evidence_sha256: $sha, attestation_sha256: $sha
          },
          jvm: {
            requested_feature: $r.jvm_feature, observed_feature: $r.jvm_feature,
            runtime: ("fixture-java-" + ($r.jvm_feature | tostring)),
            evidence_sha256: $sha
          },
          agent: {
            requested_distribution: $r.agent_distribution,
            distribution: $r.agent_distribution,
            requested_version: $r.agent_version,
            version: $r.agent_version,
            sha256: $sha,
            url:
              (if $r.agent_distribution == "otel" then
                "https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar"
               else
                "https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar"
               end)
          },
          tls: {requested: $r.tls, observed: $r.tls},
          userspace: {
            image_identities_sha256: $sha,
            apache_openssl_evidence_sha256: $sha
          },
          provider: {
            production: true,
            requested_transport: $r.transport,
            attempted_transports:
              (if $r.transport == "auto" then ["getsockopt"] else [$r.transport] end),
            selected_transport:
              (if $r.transport == "auto" then "getsockopt" else $r.transport end),
            feature_probe: {
              authoritative: true, supported: true,
              kind: "synthetic-mutation-fixture", evidence_sha256: $sha
            },
            load_reason: "fixture", attach_reason: "fixture"
          }
        },
        artifacts: {
          generic_bpf_sha256: $sha, sockopt_bpf_sha256: $sha,
          jni: {
            entry:
              (if $r.architecture == "amd64" then
                "native/linux-amd64/libobijni.so"
               else "native/linux-aarch64/libobijni.so" end),
            sha256: $sha
          },
          helper_sha256: $sha, extension_sha256: $sha,
          runtime_config_sha256: $sha
        },
        assertions: $assertions,
        evidence_index: [],
        raw_evidence: {
          directory: "raw", manifest: "raw.sha256",
          manifest_sha256: $raw_manifest_sha256
        }
      }
    ' >"$result"
  chmod 0600 -- "$result"
  bind_candidate_evidence_index "$result" "$raw"
  compatibility_directory_manifest "$raw" "$private/raw.sha256"
  rewrite_json "$result" \
    ".raw_evidence.manifest_sha256 = \"$(compatibility_sha256 "$private/raw.sha256")\""
  compatibility_directory_manifest "$private" "$output/private.sha256"
}

seal_candidate() {
  local -r campaign="$1"
  local -r directory="$2"
  local output="$directory/sealed.json"
  local launcher=""

  launcher="$(provider_path "$(jq -er '.provider' "$directory/private/requested.json")")"
  "$(test_sealer_path)" \
    --campaign "$campaign" \
    --cell "$directory/private/requested.json" \
    --provider-result "$directory/private/provider-result.json" \
    --provider-launcher "$launcher" \
    --private-directory "$directory/private" \
    --private-manifest "$directory/private.sha256" \
    --output "$output"
}

test_plans() {
  jq -e . "$CAMPAIGN_DIRECTORY"/schemas/*.schema.json >/dev/null
  "$CAMPAIGN_DIRECTORY/validate-plan.sh" compatibility
  "$CAMPAIGN_DIRECTORY/validate-plan.sh" helper-lifecycle
  [[ "$(jq -r '.cells | length' "$CAMPAIGN_DIRECTORY/campaign-v3.json")" == 45 ]]
  jq -e '
    ([.cells[] | select(.slice == "kernel-topology-deployment")] | length == 34) and
    ([.cells[] | select(.slice == "jvm-agent")] | length == 7) and
    ([.cells[] | select(.slice == "architecture")] | length == 2) and
    ([.cells[] | select(.slice == "tls")] | length == 2)
  ' "$CAMPAIGN_DIRECTORY/campaign-v3.json" >/dev/null
}

test_exact_aggregate_and_mutations() {
  local cells="$TEST_ROOT/compatibility-cells"
  local aggregate="$TEST_ROOT/compatibility-aggregate"
  local first=k-rhel96-container-v2-getsockopt
  local second=k-rhel96-container-v2-unix
  local holding="$TEST_ROOT/held-cell"
  local foreign="$cells/foreign-cell"
  local backup_cell="$TEST_ROOT/cell.backup"
  local backup_sha="$TEST_ROOT/cell-sha.backup"
  local backup_result="$TEST_ROOT/provider-result.backup"
  local backup_manifest="$TEST_ROOT/private-manifest.backup"
  local backup_authority="$TEST_ROOT/source-authority.backup"
  local id=""

  install -d -m 0700 -- "$cells"
  while IFS= read -r id; do
    make_untested_cell compatibility "$id" "$cells/$id"
  done <"$CAMPAIGN_DIRECTORY/expected-v3-cell-ids.txt"
  "$EXECUTION_CAMPAIGN_DIRECTORY/collect.sh" \
    --campaign compatibility --input-root "$cells" \
    --source-authority "$SOURCE_AUTHORITY" --output "$aggregate"
  jq -e --arg revision "$FIXTURE_REVISION" --arg git_tree "$FIXTURE_GIT_TREE" '
    .schema == "compatibility-matrix-aggregate-v3" and
    .expected_cell_count == 45 and .collected_cell_count == 45 and
    .status_counts == {pass: 0, fail: 0, unsupported: 0, untested: 45} and
    .campaign_state == "incomplete-untested" and
    .source_authority.revision == $revision and
    .source_authority.git_tree == $git_tree and
    (.source_authority_sha256 | test("^[0-9a-f]{64}$")) and
    ([.cells[].cell_id] | unique | length == 45)
  ' "$aggregate/aggregate.json" >/dev/null
  if jq -e '.. | strings | select(startswith("/"))' \
    "$aggregate/aggregate.json" "$aggregate"/cells/*.json >/dev/null; then
    fail "public aggregate leaked an absolute raw/private path"
  fi

  printf 'tracked mutation after authority capture\n' >>"$SOURCE_MARKER"
  expect_collect_failure post-authority-tracked-source-mutation compatibility "$cells"
  restore_source_marker
  printf 'untracked mutation after authority capture\n' \
    >"$EXECUTION_REPOSITORY/untracked-source-mutation.txt"
  expect_collect_failure post-authority-untracked-source-mutation compatibility "$cells"
  mv -- "$EXECUTION_REPOSITORY/untracked-source-mutation.txt" \
    "$TEST_ROOT/retired-untracked-collect-mutation.txt"

  mv -- "$cells/$first" "$holding"
  expect_collect_failure missing-cell compatibility "$cells"
  mv -- "$holding" "$cells/$first"

  install -d -m 0700 -- "$foreign"
  expect_collect_failure foreign-cell compatibility "$cells"
  mv -- "$foreign" "$TEST_ROOT/foreign-cell"

  cp -p -- "$cells/$first/cell.json" "$backup_cell"
  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  rewrite_json "$cells/$first/cell.json" ".cell_id = \"$second\" | .requested.id = \"$second\""
  refresh_cell_digest "$cells/$first"
  expect_collect_failure duplicate-cell-id compatibility "$cells"
  mv -fT -- "$backup_cell" "$cells/$first/cell.json"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"

  cp -p -- "$cells/$first/cell.json" "$backup_cell"
  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  {
    printf '{"cell_id":"%s",' "$first"
    tail -c +2 "$backup_cell"
  } >"$cells/$first/cell.json"
  chmod 0644 -- "$cells/$first/cell.json"
  refresh_cell_digest "$cells/$first"
  expect_collect_failure duplicate-public-json-key compatibility "$cells"
  mv -fT -- "$backup_cell" "$cells/$first/cell.json"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"

  cp -p -- "$cells/$first/cell.json" "$backup_cell"
  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  rewrite_json "$cells/$first/cell.json" \
    '.plan_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"'
  refresh_cell_digest "$cells/$first"
  expect_collect_failure stale-plan compatibility "$cells"
  mv -fT -- "$backup_cell" "$cells/$first/cell.json"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"

  cp -p -- "$cells/$first/cell.json" "$backup_cell"
  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  cp -p -- "$cells/$second/cell.json" "$cells/$first/cell.json"
  cp -p -- "$cells/$second/cell.json.sha256" "$cells/$first/cell.json.sha256"
  expect_collect_failure cross-cell-public-substitution compatibility "$cells"
  mv -fT -- "$backup_cell" "$cells/$first/cell.json"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"

  cp -p -- "$cells/$first/private/provider-result.json" "$backup_result"
  cp -p -- "$cells/$first/private.sha256" "$backup_manifest"
  rewrite_json "$cells/$first/private/provider-result.json" \
    '.provider = "preprovisioned-host-application-v1"'
  refresh_private_manifest "$cells/$first"
  expect_collect_failure cross-provider-substitution compatibility "$cells"
  mv -fT -- "$backup_result" "$cells/$first/private/provider-result.json"
  mv -fT -- "$backup_manifest" "$cells/$first/private.sha256"

  cp -p -- "$cells/$first/private/source-authority.json" "$backup_authority"
  cp -p -- "$cells/$first/private.sha256" "$backup_manifest"
  rewrite_json "$cells/$first/private/source-authority.json" \
    '.revision = "6666666666666666666666666666666666666666"'
  refresh_private_manifest "$cells/$first"
  expect_collect_failure cross-cell-source-authority-substitution compatibility "$cells"
  mv -fT -- "$backup_authority" "$cells/$first/private/source-authority.json"
  mv -fT -- "$backup_manifest" "$cells/$first/private.sha256"

  cp -p -- "$cells/$first/private/provider-result.json" "$backup_result"
  cp -p -- "$cells/$first/private.sha256" "$backup_manifest"
  cp -p -- "$cells/$second/private/provider-result.json" \
    "$cells/$first/private/provider-result.json"
  refresh_private_manifest "$cells/$first"
  expect_collect_failure cross-cell-private-substitution compatibility "$cells"
  mv -fT -- "$backup_result" "$cells/$first/private/provider-result.json"
  mv -fT -- "$backup_manifest" "$cells/$first/private.sha256"

  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  printf '%064d\n' 0 >"$cells/$first/cell.json.sha256"
  expect_collect_failure public-digest-substitution compatibility "$cells"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"

  mv -- "$cells/$first" "$TEST_ROOT/source-authority-untested-cell"
  write_claimed_pass_candidate compatibility "$first" "$cells/$first"
  seal_candidate compatibility "$cells/$first"
  mv -fT -- "$cells/$first/sealed.json" "$cells/$first/cell.json"
  refresh_cell_digest "$cells/$first"
  "$EXECUTION_CAMPAIGN_DIRECTORY/collect.sh" \
    --campaign compatibility --input-root "$cells" \
    --source-authority "$SOURCE_AUTHORITY" \
    --output "$TEST_ROOT/source-authority-mixed-status-aggregate"

  cp -p -- "$cells/$first/cell.json" "$backup_cell"
  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  cp -p -- "$cells/$first/private/provider-result.json" "$backup_result"
  cp -p -- "$cells/$first/private.sha256" "$backup_manifest"
  rewrite_json "$cells/$first/private/provider-result.json" \
    '.source.revision = "6666666666666666666666666666666666666666"'
  refresh_private_manifest "$cells/$first"
  refresh_sealed_cell compatibility "$cells/$first"
  expect_collect_failure mixed-source-revision compatibility "$cells"
  mv -fT -- "$backup_cell" "$cells/$first/cell.json"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"
  mv -fT -- "$backup_result" "$cells/$first/private/provider-result.json"
  mv -fT -- "$backup_manifest" "$cells/$first/private.sha256"

  cp -p -- "$cells/$first/cell.json" "$backup_cell"
  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  cp -p -- "$cells/$first/private/provider-result.json" "$backup_result"
  cp -p -- "$cells/$first/private.sha256" "$backup_manifest"
  rewrite_json "$cells/$first/private/provider-result.json" \
    '.source.source_tree_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"'
  refresh_private_manifest "$cells/$first"
  refresh_sealed_cell compatibility "$cells/$first"
  expect_collect_failure mixed-source-tree compatibility "$cells"
  mv -fT -- "$backup_cell" "$cells/$first/cell.json"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"
  mv -fT -- "$backup_result" "$cells/$first/private/provider-result.json"
  mv -fT -- "$backup_manifest" "$cells/$first/private.sha256"

  cp -p -- "$cells/$first/cell.json" "$backup_cell"
  cp -p -- "$cells/$first/cell.json.sha256" "$backup_sha"
  cp -p -- "$cells/$first/private/provider-result.json" "$backup_result"
  cp -p -- "$cells/$first/private.sha256" "$backup_manifest"
  rewrite_json "$cells/$first/private/provider-result.json" \
    '.source.patch_identity_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"'
  refresh_private_manifest "$cells/$first"
  refresh_sealed_cell compatibility "$cells/$first"
  expect_collect_failure mixed-patch-identity compatibility "$cells"
  mv -fT -- "$backup_cell" "$cells/$first/cell.json"
  mv -fT -- "$backup_sha" "$cells/$first/cell.json.sha256"
  mv -fT -- "$backup_result" "$cells/$first/private/provider-result.json"
  mv -fT -- "$backup_manifest" "$cells/$first/private.sha256"
}

test_classification_and_assertion_mutations() {
  local candidate="$TEST_ROOT/candidate"
  local result=""

  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.provider_exit_status = 1'
  refresh_private_manifest "$candidate"
  expect_failure provider-pass-exit-mismatch seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-provider-exit"
  candidate="$TEST_ROOT/candidate"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.assertions.resource_gates["native-fd"].status = "untested"'
  refresh_private_manifest "$candidate"
  expect_failure claimed-pass-with-untested-resource seal_candidate helper-lifecycle "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-resource"
  candidate="$TEST_ROOT/candidate-parent"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" \
    '.assertions.exact_parent.status = "fail" | .assertions.exact_parent.wrong = 1'
  refresh_private_manifest "$candidate"
  expect_failure exact-parent-assertion-failure seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-exact-parent"
  candidate="$TEST_ROOT/candidate-unsupported"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .status = "unsupported" |
    .provider_exit_status = 78 |
    .reason = "production-feature-probe-unsupported" |
    .command.exit_status = 78 |
    .runtime.provider.selected_transport = null |
    .runtime.provider.feature_probe.supported = false |
    .runtime.provider.feature_probe.authoritative = false |
    .assertions.no_request_mutation = {status: "pass", evidence_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} |
    .assertions.no_crash = {status: "pass", evidence_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  '
  refresh_private_manifest "$candidate"
  expect_failure nonauthoritative-unsupported seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-unsupported-boundary"
  candidate="$TEST_ROOT/candidate-fail"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .status = "fail" |
    .provider_exit_status = 1 |
    .reason = "application-assertion-failed" |
    .command.exit_status = 1 |
    .assertions.application_result = "fail" |
    .assertions.product_failure = false
  '
  refresh_private_manifest "$candidate"
  expect_failure false-product-fail seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-fail-boundary"
  candidate="$TEST_ROOT/candidate-untested"
  make_untested_cell compatibility k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.infrastructure_failure = false'
  refresh_private_manifest "$candidate"
  expect_failure false-infrastructure-untested seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-untested-boundary"
  candidate="$TEST_ROOT/candidate-duplicate-provider"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  cp -p -- "$result" "$TEST_ROOT/provider-for-duplicate.json"
  {
    printf '{"status":"pass",'
    tail -c +2 "$TEST_ROOT/provider-for-duplicate.json"
  } >"$result"
  chmod 0600 -- "$result"
  refresh_private_manifest "$candidate"
  expect_failure duplicate-provider-json-key seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-duplicate-provider-key"
  candidate="$TEST_ROOT/candidate-duplicate-request"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  cp -p -- "$candidate/private/requested.json" "$TEST_ROOT/request-for-duplicate.json"
  {
    printf '{"id":"k-upstream612-container-v2-getsockopt",'
    tail -c +2 "$TEST_ROOT/request-for-duplicate.json"
  } >"$candidate/private/requested.json"
  chmod 0600 -- "$candidate/private/requested.json"
  refresh_private_manifest "$candidate"
  expect_failure duplicate-request-json-key seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-duplicate-request-key"
  candidate="$TEST_ROOT/candidate-unknown-field"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.unexpected_field = true'
  refresh_private_manifest "$candidate"
  expect_failure provider-exact-schema seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-unknown-provider-field"
  candidate="$TEST_ROOT/candidate-raw-alias"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.raw_evidence.directory = "raw/../raw"'
  refresh_private_manifest "$candidate"
  expect_failure raw-directory-alias seal_candidate compatibility "$candidate"

  mv -- "$candidate" "$TEST_ROOT/candidate-raw-path-alias"
  candidate="$TEST_ROOT/candidate-raw-substitution"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  printf 'substituted after raw manifest\n' >"$candidate/private/raw/fixture.txt"
  chmod 0600 -- "$candidate/private/raw/fixture.txt"
  refresh_private_manifest "$candidate"
  expect_failure raw-private-evidence-substitution seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-fractional-parent"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .assertions.exact_parent.requests = 3.5 |
    .assertions.exact_parent.matched = 3.5
  '
  refresh_private_manifest "$candidate"
  expect_failure fractional-exact-parent-count seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-huge-parent"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .assertions.exact_parent.requests = 1000000001 |
    .assertions.exact_parent.matched = 1000000001
  '
  refresh_private_manifest "$candidate"
  expect_failure over-cap-exact-parent-count seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-fractional-provider-exit"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.provider_exit_status = 0.5'
  refresh_private_manifest "$candidate"
  expect_failure fractional-provider-exit seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-command-exit-overflow"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.command.exit_status = 256'
  refresh_private_manifest "$candidate"
  expect_failure command-exit-over-255 seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-helper-fractional-request"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .assertions.frameworks["blocking-sslsocket"].requests = 3.5 |
    .assertions.frameworks["blocking-sslsocket"].exact_parents = 3.5
  '
  refresh_private_manifest "$candidate"
  expect_failure fractional-helper-request-count \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-helper-resource-over-cap"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .assertions.resource_gates["native-fd"].baseline = 1000000001 |
    .assertions.resource_gates["native-fd"].final = 1000000001
  '
  refresh_private_manifest "$candidate"
  expect_failure over-cap-resource-counter seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-helper-negative-resource-baseline"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .assertions.resource_gates["native-fd"].baseline = -1 |
    .assertions.resource_gates["native-fd"].final = 0 |
    .assertions.resource_gates["native-fd"].delta = 1 |
    .assertions.resource_gates["native-fd"].allowed_delta = 1
  '
  refresh_private_manifest "$candidate"
  expect_failure negative-resource-baseline seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-helper-negative-resource-final"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .assertions.resource_gates["native-fd"].baseline = 0 |
    .assertions.resource_gates["native-fd"].final = -1 |
    .assertions.resource_gates["native-fd"].delta = -1
  '
  refresh_private_manifest "$candidate"
  expect_failure negative-resource-final seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-helper-slope-over-cap"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .assertions.resource_gates["native-fd"].trend_slope = 1000000001 |
    .assertions.resource_gates["native-fd"].maximum_trend_slope = 1000000001
  '
  refresh_private_manifest "$candidate"
  expect_failure over-cap-resource-slope seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-provider-exit-ieee-overflow"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  sed '0,/"provider_exit_status": 0/s//"provider_exit_status": 9007199254740992/' \
    "$result" >"$result.new"
  cmp -s -- "$result" "$result.new" && fail "failed to inject huge JSON integer"
  chmod 0600 -- "$result.new"
  mv -fT -- "$result.new" "$result"
  refresh_private_manifest "$candidate"
  expect_failure inexact-ieee-provider-exit seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-helper-nonfinite-slope"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  sed '0,/"trend_slope": 0/s//"trend_slope": 1e999/' \
    "$result" >"$result.new"
  cmp -s -- "$result" "$result.new" && fail "failed to inject non-finite JSON exponent"
  chmod 0600 -- "$result.new"
  mv -fT -- "$result.new" "$result"
  refresh_private_manifest "$candidate"
  expect_failure nonfinite-resource-slope seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-unbound-digest"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" \
    '.artifacts.helper_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
  refresh_private_manifest "$candidate"
  expect_failure unbound-public-digest seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-duplicate-index-path"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.evidence_index[1].path = .evidence_index[0].path'
  refresh_private_manifest "$candidate"
  expect_failure duplicate-raw-path-binding seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-duplicate-index-path-alias"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" \
    '.evidence_index[1].path = ("./" + .evidence_index[0].path)'
  refresh_private_manifest "$candidate"
  expect_failure duplicate-raw-path-alias seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-private-index-path"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.evidence_index[0].path = "/tmp/private-evidence"'
  refresh_private_manifest "$candidate"
  expect_failure private-path-in-public-index seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-path-alias"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.evidence_index[0].path = "proof/../aliased-evidence"'
  refresh_private_manifest "$candidate"
  expect_failure aliased-path-in-public-index seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-dot-component"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.evidence_index[0].path = "proof/./evidence.txt"'
  refresh_private_manifest "$candidate"
  expect_failure dot-component-in-public-index seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-hidden-component"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.evidence_index[0].path = "proof/.hidden.txt"'
  refresh_private_manifest "$candidate"
  expect_failure hidden-component-in-public-index seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-control"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.evidence_index[0].path = "proof/\u0001evidence.txt"'
  refresh_private_manifest "$candidate"
  expect_failure control-character-in-public-index seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-over-cap"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.evidence_index[0].path = ("a" * 513)'
  refresh_private_manifest "$candidate"
  expect_failure over-cap-public-index-path seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-rebound-password"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  rebind_indexed_path "$candidate" artifacts.helper_sha256 password.txt
  expect_failure fully-rebound-password-index-path \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-rebound-case-punctuation"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  rebind_indexed_path "$candidate" artifacts.helper_sha256 \
    proof/PaSsWoRd-report.txt
  expect_failure case-punctuation-secret-index-path \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-rebound-api-key"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  rebind_indexed_path "$candidate" artifacts.helper_sha256 \
    proof/API_KEY-report.json
  expect_failure case-underscore-secret-index-path \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-rebound-secret-component"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  rebind_indexed_path "$candidate" artifacts.helper_sha256 \
    proof/token/result.txt
  expect_failure secret-path-component-in-public-index \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-index-rebound-benign"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  rebind_indexed_path "$candidate" artifacts.helper_sha256 \
    safe/passwordless-report.txt
  rebind_indexed_path "$candidate" artifacts.extension_sha256 \
    tokenizer/secretary-evidence.json
  rebind_indexed_path "$candidate" artifacts.runtime_config_sha256 \
    credentialed-client/proof.txt
  seal_candidate compatibility "$candidate" ||
    fail "benign canonical evidence paths were rejected"
  jq -e '
    [.evidence_index[].path] as $paths |
    ($paths | index("safe/passwordless-report.txt")) != null and
    ($paths | index("tokenizer/secretary-evidence.json")) != null and
    ($paths | index("credentialed-client/proof.txt")) != null
  ' "$candidate/sealed.json" >/dev/null ||
    fail "benign rebound evidence paths were not published exactly"

  candidate="$TEST_ROOT/candidate-public-secret"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.jvm.runtime = "password=do-not-publish"'
  refresh_private_manifest "$candidate"
  expect_failure secret-in-public-runtime seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-password-space"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.jvm.runtime = "OpenJDK password value"'
  refresh_private_manifest "$candidate"
  expect_failure whitespace-delimited-secret-in-public-runtime \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-password-parentheses"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.jvm.runtime = "OpenJDK password(hunter2)"'
  refresh_private_manifest "$candidate"
  expect_failure parenthesis-delimited-secret-in-public-runtime \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-password-brackets"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.jvm.runtime = "OpenJDK [password] runtime"'
  refresh_private_manifest "$candidate"
  expect_failure bracket-delimited-secret-in-public-runtime \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-password-quotes"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.jvm.runtime = "OpenJDK \"password\" runtime"'
  refresh_private_manifest "$candidate"
  expect_failure quote-delimited-secret-in-public-runtime \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-password-punctuation"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.jvm.runtime = "OpenJDK password+hunter2"'
  refresh_private_manifest "$candidate"
  expect_failure punctuation-delimited-secret-in-public-runtime \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-secret-reason"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.reason = "secret-runtime-ready"'
  refresh_private_manifest "$candidate"
  expect_failure secret-in-top-level-reason \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-password-reason"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.reason = "password-runtime-ready"'
  refresh_private_manifest "$candidate"
  expect_failure password-in-top-level-reason \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-nonsensitive-words"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .reason = "passwordless-runtime-ready" |
    .runtime.deployment.proof = "secretary-observed" |
    .runtime.provider.load_reason = "tokenizer-ready" |
    .runtime.provider.attach_reason = "credentialed-client" |
    .runtime.jvm.runtime = "OpenJDK Passwordless Runtime"
  '
  refresh_private_manifest "$candidate"
  seal_candidate compatibility "$candidate" ||
    fail "nonsensitive public words were rejected as secrets"

  candidate="$TEST_ROOT/candidate-public-private-path"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.jvm.runtime = "OpenJDK runtime path=/tmp/private"'
  refresh_private_manifest "$candidate"
  expect_failure private-path-in-public-runtime seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-provenance-deleted"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  mv -- "$candidate/private/raw/campaign-attestations/kernel-provenance.json" \
    "$candidate/kernel-provenance.deleted"
  refresh_raw_manifest "$candidate"
  expect_failure deleted-kernel-provenance seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-provenance-mutated"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json \
    "$candidate/private/raw/campaign-attestations/kernel-provenance.json" \
    '.version_inference = true'
  rebind_indexed_file "$result" "$candidate/private/raw" \
    runtime.kernel.provenance_sha256
  refresh_raw_manifest "$candidate"
  expect_failure mutated-kernel-provenance seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-topology-deleted"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  mv -- "$candidate/private/raw/campaign-attestations/topology-attestation.json" \
    "$candidate/topology-attestation.deleted"
  refresh_raw_manifest "$candidate"
  expect_failure deleted-topology-attestation seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-topology-substituted"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  install -m 0600 -- \
    "$candidate/private/raw/campaign-attestations/kernel-provenance.json" \
    "$candidate/private/raw/campaign-attestations/topology-attestation.json"
  rebind_indexed_file "$result" "$candidate/private/raw" \
    runtime.cgroup_topology.attestation_sha256
  refresh_raw_manifest "$candidate"
  expect_failure substituted-topology-attestation \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-topology-unexpected-field"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json \
    "$candidate/private/raw/campaign-attestations/topology-attestation.json" \
    '.unvalidated_topology_claim = true'
  rebind_indexed_file "$result" "$candidate/private/raw" \
    runtime.cgroup_topology.attestation_sha256
  refresh_raw_manifest "$candidate"
  expect_failure unexpected-topology-attestation-field \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-url-prefix-bypass"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .runtime.provider.load_reason =
      "https://repo.maven.apache.org/maven2/private-token"
  '
  refresh_private_manifest "$candidate"
  expect_failure public-url-prefix-bypass seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-agent-url-cross-field"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .runtime.provider.attach_reason =
      "https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar"
  '
  refresh_private_manifest "$candidate"
  expect_failure agent-url-in-reason-field seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-public-proof-path"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.runtime.deployment.proof = "/tmp/private-proof"'
  refresh_private_manifest "$candidate"
  expect_failure public-deployment-proof-path seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-forced-pass-alternate"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .runtime.provider.attempted_transports = ["unix"] |
    .runtime.provider.selected_transport = "unix"
  '
  refresh_private_manifest "$candidate"
  expect_failure forced-pass-alternate-transport seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-forced-fail-alternate"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .status = "fail" | .provider_exit_status = 1 |
    .reason = "application-assertion-failed" | .command.exit_status = 1 |
    .runtime.provider.attempted_transports = ["unix"] |
    .runtime.provider.selected_transport = "unix" |
    .assertions = {
      application_result:"fail", cleanup:"unknown", product_failure:true,
      required_cells_skipped:false
    }
  '
  refresh_private_manifest "$candidate"
  expect_failure forced-fail-alternate-transport seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-forced-unsupported-alternate"
  write_claimed_pass_candidate compatibility \
    k-upstream612-container-v2-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .status = "unsupported" | .provider_exit_status = 78 |
    .reason = "production-feature-probe-unsupported" | .command.exit_status = 78 |
    .runtime.provider.attempted_transports = ["unix"] |
    .runtime.provider.selected_transport = null |
    .runtime.provider.feature_probe.supported = false |
    .assertions = {
      application_result:"pass", cleanup:"pass", product_failure:false,
      required_cells_skipped:false,
      exact_parent:{status:"pass",requests:3,matched:3,wrong:0},
      no_request_mutation:{status:"pass",evidence_sha256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      no_crash:{status:"pass",evidence_sha256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
    }
  '
  bind_candidate_evidence_index "$result" "$candidate/private/raw"
  refresh_raw_manifest "$candidate"
  expect_failure forced-unsupported-alternate-transport \
    seal_candidate compatibility "$candidate"

  candidate="$TEST_ROOT/candidate-auto-primary-with-fallback-attempt"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-auto "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" \
    '.runtime.provider.attempted_transports = ["getsockopt", "unix"]'
  refresh_private_manifest "$candidate"
  expect_failure auto-primary-selected-after-fallback-attempt \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-auto-fallback-without-primary-attempt"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-auto "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .runtime.provider.attempted_transports = ["unix"] |
    .runtime.provider.selected_transport = "unix"
  '
  refresh_private_manifest "$candidate"
  expect_failure auto-fallback-without-primary-attempt \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-auto-unsupported-before-fallback"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-auto "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '
    .status = "unsupported" | .provider_exit_status = 78 |
    .reason = "production-feature-probe-unsupported" | .command.exit_status = 78 |
    .runtime.provider.attempted_transports = ["getsockopt"] |
    .runtime.provider.selected_transport = null |
    .runtime.provider.feature_probe.supported = false |
    .assertions = {
      application_result:"pass", cleanup:"pass", product_failure:false,
      required_cells_skipped:false,
      exact_parent:{status:"pass",requests:3,matched:3,wrong:0},
      no_request_mutation:{status:"pass",evidence_sha256:("a" * 64)},
      no_crash:{status:"pass",evidence_sha256:("b" * 64)}
    }
  '
  bind_candidate_evidence_index "$result" "$candidate/private/raw"
  refresh_raw_manifest "$candidate"
  expect_failure auto-unsupported-before-fallback \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-unavailable-result-changed"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  printf '{"schema":"compatibility-bridge-result-v1","result":"changed"}\n' \
    >"$candidate/private/raw/unavailable-bridge/unavailable-result.json"
  chmod 0600 -- "$candidate/private/raw/unavailable-bridge/unavailable-result.json"
  rebind_indexed_file "$result" "$candidate/private/raw" \
    assertions.unavailable_bridge.unavailable_result_sha256
  refresh_raw_manifest "$candidate"
  expect_failure changed-unavailable-bridge-result \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-unavailable-diagnostics-unbounded"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  rewrite_json "$result" '.assertions.unavailable_bridge.diagnostics.count = 65'
  refresh_private_manifest "$candidate"
  expect_failure unbounded-unavailable-bridge-diagnostics \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-unavailable-diagnostics-missing"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  mv -- "$candidate/private/raw/unavailable-bridge/diagnostics.json" \
    "$candidate/unavailable-diagnostics.deleted"
  refresh_raw_manifest "$candidate"
  expect_failure missing-unavailable-bridge-diagnostics \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-unavailable-diagnostics-changed"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  result="$candidate/private/provider-result.json"
  jq -nS '{
    schema:"compatibility-unavailable-bridge-diagnostics-v1",
    diagnostics:["changed-diagnostic", "unexpected-second-diagnostic"]
  }' >"$candidate/private/raw/unavailable-bridge/diagnostics.json"
  chmod 0600 -- "$candidate/private/raw/unavailable-bridge/diagnostics.json"
  rebind_indexed_file "$result" "$candidate/private/raw" \
    assertions.unavailable_bridge.diagnostics.evidence_sha256
  refresh_raw_manifest "$candidate"
  expect_failure changed-unavailable-bridge-diagnostics \
    seal_candidate helper-lifecycle "$candidate"

  candidate="$TEST_ROOT/candidate-normal-extraction-missing"
  write_claimed_pass_candidate helper-lifecycle \
    h-jdk21-amd64-otel-getsockopt "$candidate"
  mv -- "$candidate/private/raw/unavailable-bridge/normal-agent-extraction.json" \
    "$candidate/normal-agent-extraction.deleted"
  refresh_raw_manifest "$candidate"
  expect_failure missing-normal-agent-extraction-proof \
    seal_candidate helper-lifecycle "$candidate"
}

test_manifest_and_cleanup_boundaries() {
  local directory=""
  local output=""
  local owned=""
  local owned_identity=""
  local replaced=""
  local replaced_identity=""
  local replacement_identity=""
  local identities="$TEST_ROOT/driver-identities.jsonl"

  directory="$TEST_ROOT/manifest-symlink"
  install -d -m 0700 -- "$directory"
  ln -s -- /dev/null "$directory/link"
  expect_failure manifest-symlink compatibility_directory_manifest \
    "$directory" "$TEST_ROOT/manifest-symlink.sha256"

  directory="$TEST_ROOT/manifest-special"
  install -d -m 0700 -- "$directory"
  mkfifo -m 0600 -- "$directory/fifo"
  expect_failure manifest-special-file compatibility_directory_manifest \
    "$directory" "$TEST_ROOT/manifest-special.sha256"

  directory="$TEST_ROOT/manifest-hardlink"
  install -d -m 0700 -- "$directory"
  printf 'hard link fixture\n' >"$directory/original"
  chmod 0600 -- "$directory/original"
  ln -- "$directory/original" "$directory/peer"
  expect_failure manifest-hardlink compatibility_directory_manifest \
    "$directory" "$TEST_ROOT/manifest-hardlink.sha256"

  directory="$TEST_ROOT/manifest-over-cap"
  install -d -m 0700 -- "$directory"
  truncate -s 2147483649 "$directory/sparse"
  chmod 0600 -- "$directory/sparse"
  expect_failure manifest-over-cap compatibility_directory_manifest \
    "$directory" "$TEST_ROOT/manifest-over-cap.sha256"

  directory="$TEST_ROOT/manifest-find-failure"
  install -d -m 0700 -- "$directory"
  printf 'fixture\n' >"$directory/file"
  chmod 0600 -- "$directory/file"
  # shellcheck disable=SC2317 # Injected into the manifest subshell by name.
  find() { return 71; }
  expect_failure manifest-find-failure compatibility_directory_manifest \
    "$directory" "$TEST_ROOT/manifest-find-failure.sha256"
  unset -f find

  directory="$TEST_ROOT/manifest-sort-failure"
  install -d -m 0700 -- "$directory"
  printf 'fixture\n' >"$directory/file"
  chmod 0600 -- "$directory/file"
  # shellcheck disable=SC2317 # Injected into the manifest subshell by name.
  sort() { return 72; }
  expect_failure manifest-sort-failure compatibility_directory_manifest \
    "$directory" "$TEST_ROOT/manifest-sort-failure.sha256"
  unset -f sort

  owned="$(mktemp -d "$TEST_ROOT/.identity.XXXXXX")"
  owned_identity="$(compatibility_directory_identity "$owned")"
  compatibility_remove_owned_temp_directory \
    "$owned" "$owned_identity" "$TEST_ROOT" "[.]identity[.]"
  [[ ! -e "$owned" ]] || fail "identity-scoped cleanup left its exact directory"

  replaced="$(mktemp -d "$TEST_ROOT/.identity.XXXXXX")"
  replaced_identity="$(compatibility_directory_identity "$replaced")"
  mv -- "$replaced" "$replaced.original"
  install -d -m 0700 -- "$replaced"
  printf 'must survive refused cleanup\n' >"$replaced/sentinel"
  replacement_identity="$(compatibility_directory_identity "$replaced")"
  [[ "$replacement_identity" != "$replaced_identity" ]]
  expect_failure temp-inode-replacement compatibility_remove_owned_temp_directory \
    "$replaced" "$replaced_identity" "$TEST_ROOT" "[.]identity[.]"
  [[ -f "$replaced/sentinel" ]] || fail "cleanup deleted a replacement directory"

  printf '{"cells":[],"cells":[]}\n' >"$TEST_ROOT/duplicate-plan.json"
  chmod 0600 -- "$TEST_ROOT/duplicate-plan.json"
  expect_failure duplicate-plan-json-key compatibility_validate_json_file \
    "$TEST_ROOT/duplicate-plan.json"

  printf '%s\n' \
    '{"schema":"compatibility-source-authority-v1","schema":"compatibility-source-authority-v1"}' \
    >"$TEST_ROOT/duplicate-source-authority.json"
  chmod 0600 -- "$TEST_ROOT/duplicate-source-authority.json"
  expect_failure duplicate-source-authority-key \
    compatibility_validate_source_authority \
    "$TEST_ROOT/duplicate-source-authority.json"

  printf '%s\n' \
    '{"id":"driver-one","provider":"provider-one","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
    '{"id":"driver-one","provider":"provider-one","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
    >"$identities"
  chmod 0600 -- "$identities"
  compatibility_validate_collected_driver_identities "$identities"
  printf '%s\n' \
    '{"id":"driver-one","provider":"provider-one","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
    '{"id":"driver-two","provider":"provider-one","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}' \
    >"$identities"
  expect_failure mixed-approved-driver-identities \
    compatibility_validate_collected_driver_identities "$identities"
}

test_process_group_boundary() {
  local fixture="$TEST_DIRECTORY/process-group-fixture.sh"
  local child_pid=0
  local run_code=0

  compatibility_run_bounded_process_group \
    "$TEST_ROOT/process-normal.stdout" "$TEST_ROOT/process-normal.stderr" \
    1024 5 "$fixture" leave-child "$TEST_ROOT/process-normal.pid"
  child_pid="$(<"$TEST_ROOT/process-normal.pid")"
  if kill -0 "$child_pid" 2>/dev/null; then
    kill -KILL "$child_pid" 2>/dev/null || true
    fail "normal provider return left a descendant alive"
  fi

  set +e
  compatibility_run_bounded_process_group \
    "$TEST_ROOT/process-timeout.stdout" "$TEST_ROOT/process-timeout.stderr" \
    1024 1 "$fixture" wait-for-timeout "$TEST_ROOT/process-timeout.pid"
  run_code=$?
  set -e
  [[ "$run_code" == 124 ]] || fail "bounded process group did not return timeout status"
  child_pid="$(<"$TEST_ROOT/process-timeout.pid")"
  if kill -0 "$child_pid" 2>/dev/null; then
    kill -KILL "$child_pid" 2>/dev/null || true
    fail "timed-out provider left a descendant alive"
  fi
}

test_source_status_failure_is_not_clean() {
  local source=""

  # shellcheck disable=SC2317  # Invoked through compatibility_source_checkout_json.
  git() {
    case "$*" in
      *"HEAD^{commit}"*) printf '%s\n' 1111111111111111111111111111111111111111 ;;
      *"HEAD^{tree}"*) printf '%s\n' 2222222222222222222222222222222222222222 ;;
      *" status "*) return 73 ;;
      *) return 74 ;;
    esac
  }
  source="$(compatibility_source_checkout_json)"
  unset -f git
  jq -e '.clean == false' <<<"$source" >/dev/null ||
    fail "git status failure was represented as a clean checkout"
}

test_run_cell_source_authority_drift() {
  local output=""

  output="$TEST_ROOT/rejected-run-cell-tracked-source"
  printf 'tracked mutation after authority capture\n' >>"$SOURCE_MARKER"
  expect_failure post-authority-run-cell-tracked-source \
    env -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER \
      -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256 \
      "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
        --campaign helper-lifecycle \
        --cell h-jdk21-amd64-otel-getsockopt \
        --source-authority "$RUN_SOURCE_AUTHORITY" --output "$output"
  [[ ! -e "$output" && ! -L "$output" ]] ||
    fail "run-cell published after a tracked post-authority source mutation"
  restore_source_marker

  output="$TEST_ROOT/rejected-run-cell-untracked-source"
  printf 'untracked mutation after authority capture\n' \
    >"$EXECUTION_REPOSITORY/untracked-run-cell-mutation.txt"
  expect_failure post-authority-run-cell-untracked-source \
    env -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER \
      -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256 \
      "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
        --campaign helper-lifecycle \
        --cell h-jdk21-amd64-otel-getsockopt \
        --source-authority "$RUN_SOURCE_AUTHORITY" --output "$output"
  [[ ! -e "$output" && ! -L "$output" ]] ||
    fail "run-cell published after an untracked post-authority source mutation"
  mv -- "$EXECUTION_REPOSITORY/untracked-run-cell-mutation.txt" \
    "$TEST_ROOT/retired-untracked-run-cell-mutation.txt"
}

test_external_driver_boundaries() {
  local driver="$TEST_DIRECTORY/mock-external-driver.sh"
  local driver_sha=""
  local output="$TEST_ROOT/external-malformed"
  local run_code=0
  local campaign=""
  local cell_id=""
  local driver_environment=""
  local digest_environment=""
  local label=""
  local -a adapter_cases=(
    "compatibility|k-upstream612-host-v2-getsockopt|OBI_COMPATIBILITY_HOST_APPLICATION_DRIVER|OBI_COMPATIBILITY_HOST_APPLICATION_DRIVER_SHA256|host"
    "compatibility|j-jdk8-otel-getsockopt|OBI_COMPATIBILITY_JVM_APPLICATION_DRIVER|OBI_COMPATIBILITY_JVM_APPLICATION_DRIVER_SHA256|jvm"
    "helper-lifecycle|h-jdk21-amd64-otel-getsockopt|OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER|OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256|lifecycle"
  )
  local adapter_case=""
  local unapproved_driver="$TEST_ROOT/unapproved-external-driver.sh"
  local swap_driver="$TEST_ROOT/swap-external-driver.sh"

  driver_sha="$(compatibility_sha256 "$driver")"
  for adapter_case in "${adapter_cases[@]}"; do
    IFS='|' read -r campaign cell_id driver_environment digest_environment label \
      <<<"$adapter_case"
    output="$TEST_ROOT/external-missing-assertions-$label"
    set +e
    env \
      "$driver_environment=$driver" \
      "$digest_environment=$driver_sha" \
      OBI_COMPATIBILITY_MOCK_MODE=missing-assertions \
      "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
        --campaign "$campaign" --cell "$cell_id" \
        --source-authority "$RUN_SOURCE_AUTHORITY" --output "$output"
    run_code=$?
    set -e
    [[ "$run_code" == 1 ]] ||
      fail "$label provider missing assertions was not classified fail"
    jq -e '
      .status == "fail" and .reason == "external-provider-result-invalid" and
      .assertions.classification == "provider-contract"
    ' "$output/cell.json" >/dev/null
  done

  output="$TEST_ROOT/external-malformed"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$driver" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$driver_sha" \
    OBI_COMPATIBILITY_MOCK_MODE=malformed \
    "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell h-jdk21-amd64-otel-getsockopt \
      --source-authority "$RUN_SOURCE_AUTHORITY" \
      --output "$output"
  run_code=$?
  set -e
  [[ "$run_code" == 1 ]] || fail "malformed present driver was not classified fail"
  jq -e '
    .status == "fail" and .reason == "external-provider-result-invalid" and
    .assertions.classification == "provider-contract" and
    .evidence.raw_manifest_sha256 != null
  ' "$output/cell.json" >/dev/null

  output="$TEST_ROOT/external-missing-result"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$driver" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$driver_sha" \
    OBI_COMPATIBILITY_MOCK_MODE=missing \
    "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell h-jdk21-amd64-otel-getsockopt \
      --source-authority "$RUN_SOURCE_AUTHORITY" \
      --output "$output"
  run_code=$?
  set -e
  [[ "$run_code" == 1 ]] || fail "missing result from present driver was not classified fail"
  jq -e '.status == "fail" and .reason == "external-provider-result-missing"' \
    "$output/cell.json" >/dev/null

  output="$TEST_ROOT/external-unavailable"
  set +e
  env -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER \
    -u OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256 \
    "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell h-jdk21-amd64-otel-getsockopt \
      --source-authority "$RUN_SOURCE_AUTHORITY" \
      --output "$output"
  run_code=$?
  set -e
  [[ "$run_code" == 69 ]] || fail "missing driver was not classified untested"
  jq -e '.status == "untested" and .infrastructure_failure == true' \
    "$output/private/provider-result.json" >/dev/null

  output="$TEST_ROOT/external-attempted-untested"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$driver" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$driver_sha" \
    OBI_COMPATIBILITY_MOCK_MODE=untested \
    "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell h-jdk21-amd64-otel-getsockopt \
      --source-authority "$RUN_SOURCE_AUTHORITY" \
      --output "$output"
  run_code=$?
  set -e
  [[ "$run_code" == 69 ]] || fail "executed external untested result was rejected"
  jq -e --arg sha256 "$driver_sha" '
    .status == "untested" and .attempted == true and
    .command.executed == true and .command.exit_status == 69 and
    .external_driver == {
      id:"fixture-lifecycle-driver-v1", sha256:$sha256,
      snapshot:"external-driver.snapshot"
    }
  ' "$output/private/provider-result.json" >/dev/null ||
    fail "executed external untested result lost its approved private identity"
  jq -e --arg sha256 "$driver_sha" '
    .status == "untested" and
    .provider.external_driver == {
      id:"fixture-lifecycle-driver-v1", sha256:$sha256
    }
  ' "$output/cell.json" >/dev/null ||
    fail "executed external untested cell lost its approved public identity"

  install -m 0500 -- "$driver" "$unapproved_driver"
  chmod 0700 -- "$unapproved_driver"
  printf '# unapproved identity mutation\n' >>"$unapproved_driver"
  chmod 0500 -- "$unapproved_driver"
  output="$TEST_ROOT/external-unapproved-self-matching"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$unapproved_driver" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$(compatibility_sha256 \
      "$unapproved_driver")" \
    OBI_COMPATIBILITY_MOCK_MODE=malformed \
    "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell h-jdk21-amd64-otel-getsockopt \
      --source-authority "$RUN_SOURCE_AUTHORITY" --output "$output"
  run_code=$?
  set -e
  [[ "$run_code" == 69 ]] || fail "unapproved self-matching driver was executed"
  jq -e '.status == "untested" and .reason == "external-provider-not-approved" and
    .provider.external_driver == null' "$output/cell.json" >/dev/null

  output="$TEST_ROOT/external-lying-argv"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$driver" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$driver_sha" \
    OBI_COMPATIBILITY_MOCK_MODE=lying-argv \
    "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell h-jdk21-amd64-otel-getsockopt \
      --source-authority "$RUN_SOURCE_AUTHORITY" --output "$output"
  run_code=$?
  set -e
  [[ "$run_code" == 1 ]] || fail "lying external argv was not rejected"
  jq -e '.status == "fail" and .reason == "external-provider-result-invalid"' \
    "$output/cell.json" >/dev/null

  install -m 0500 -- "$driver" "$swap_driver"
  output="$TEST_ROOT/external-swap-after-hash"
  set +e
  OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$swap_driver" \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$driver_sha" \
    OBI_COMPATIBILITY_MOCK_MODE=swap-driver \
    OBI_COMPATIBILITY_MOCK_SWAP_TARGET="$swap_driver" \
    "$EXECUTION_CAMPAIGN_DIRECTORY/run-cell.sh" \
      --campaign helper-lifecycle \
      --cell h-jdk21-amd64-otel-getsockopt \
      --source-authority "$RUN_SOURCE_AUTHORITY" --output "$output"
  run_code=$?
  set -e
  [[ "$run_code" == 1 ]] || fail "external driver swap was not rejected"
  jq -e '.status == "fail" and
    .reason == "external-provider-changed-during-execution" and
    .assertions.classification == "provider-contract"' \
    "$output/cell.json" >/dev/null
}

test_direct_launcher_boundary() {
  "$TEST_DIRECTORY/provider-boundary-test.sh" "$TEST_ROOT" "$RUN_SOURCE_AUTHORITY"
}

main() {
  compatibility_require_commands \
    cmp cp env find git install jq kill ln mkfifo mktemp mv python3 sed sha256sum \
    sleep stat tail timeout truncate
  TEST_ROOT_PARENT="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
  TEST_ROOT="$(mktemp -d "$TEST_ROOT_PARENT/obi-compatibility-test.XXXXXX")"
  TEST_ROOT_IDENTITY="$(compatibility_directory_identity "$TEST_ROOT")"
  trap cleanup_test_root EXIT
  SOURCE_AUTHORITY="$TEST_ROOT/source-authority.json"
  RUN_SOURCE_AUTHORITY="$TEST_ROOT/run-source-authority.json"
  create_clean_execution_repository
  test_plans
  test_exact_aggregate_and_mutations
  test_classification_and_assertion_mutations
  test_manifest_and_cleanup_boundaries
  test_process_group_boundary
  test_source_status_failure_is_not_clean
  test_run_cell_source_authority_drift
  test_external_driver_boundaries
  test_direct_launcher_boundary
  "$TEST_DIRECTORY/runsh-boundary-test.sh" "$TEST_ROOT/runsh-boundaries"
  printf 'PASS: compatibility campaign schema and mutation tests\n'
}

main "$@"
