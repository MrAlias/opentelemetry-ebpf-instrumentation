#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/lib.sh"

SEAL_TEMP_DIRECTORY=""
SEAL_TEMP_IDENTITY=""
SEAL_TEMP_PARENT=""
SEAL_TEMP_DESCRIPTOR=""

cleanup_seal_temp() {
  if [[ "$SEAL_TEMP_DESCRIPTOR" =~ ^[1-9][0-9]*$ ]]; then
    exec {SEAL_TEMP_DESCRIPTOR}<&- || true
    SEAL_TEMP_DESCRIPTOR=""
  fi
  [[ -n "$SEAL_TEMP_DIRECTORY" ]] || return 0
  compatibility_remove_owned_temp_directory \
    "$SEAL_TEMP_DIRECTORY" "$SEAL_TEMP_IDENTITY" "$SEAL_TEMP_PARENT" \
    "[.]compatibility-seal[.]" ||
    compatibility_error "refused to remove replaced seal scratch directory"
}

usage() {
  cat >&2 <<'USAGE'
Usage: seal-cell.sh --campaign NAME --cell FILE --provider-result FILE \
  --provider-launcher FILE --private-directory DIR --private-manifest FILE \
  [--provider-registry-snapshot FILE --provider-registry-snapshot-identity ID \
   --provider-registry-source-identity ID \
   --lifecycle-executor-registry-snapshot FILE \
   --lifecycle-executor-registry-snapshot-identity ID \
   --lifecycle-executor-registry-source-identity ID] \
  --output FILE
USAGE
}

validate_relative_evidence_path() {
  local -r value="$1"

  [[ -n "$value" && "$value" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ &&
    "$value" != /* && "$value" != *$'\n'* &&
    "$value" != . && "$value" != .. &&
    "$value" != ../* && "$value" != */../* && "$value" != */.. &&
    "$value" != ./* && "$value" != */./* && "$value" != */. ]]
}

validate_provider_result() {
  local -r campaign="$1"
  local -r cell="$2"
  local -r result="$3"
  local -r revision="$4"
  local -r plan_sha256="$5"
  local -r registry_sha256="$6"
  local -r executor_registry_sha256="$7"
  local -r source_authority_sha256="$8"
  local -r provider_registry="$9"
  local -r executor_registry="${10}"

  jq -e \
    --arg campaign "$campaign" \
    --arg revision "$revision" \
    --arg plan_sha256 "$plan_sha256" \
    --arg registry_sha256 "$registry_sha256" \
    --arg executor_registry_sha256 "$executor_registry_sha256" \
    --arg source_authority_sha256 "$source_authority_sha256" \
    --argjson max_assertion_count "$COMPATIBILITY_MAX_ASSERTION_COUNT" \
    --argjson max_resource_magnitude "$COMPATIBILITY_MAX_RESOURCE_MAGNITUDE" \
    --slurpfile requested "$cell" \
    --slurpfile registry "$provider_registry" \
    --slurpfile executor_registry "$executor_registry" '
      def sha256: type == "string" and test("^[0-9a-f]{64}$");
      def revision: type == "string" and test("^[0-9a-f]{40}$");
      def contains_secret_word:
        test("(^|[^[:alnum:]])(secret|password|passwd|token|credential|api[-_]?key|private[-_]?key)([^[:alnum:]]|$)"; "i");
      def reason:
        type == "string" and test("^[a-z0-9][a-z0-9-]{0,95}$") and
        (contains_secret_word | not);
      def exit_code:
        type == "number" and floor == . and . >= 0 and . <= 255;
      def safe_uint:
        type == "number" and floor == . and
        . >= 0 and . <= $max_assertion_count;
      def safe_int:
        type == "number" and floor == . and
        . >= -$max_resource_magnitude and . <= $max_resource_magnitude;
      def bounded_float:
        type == "number" and
        . >= -$max_resource_magnitude and . <= $max_resource_magnitude;
      def safe_public_string:
        type == "string" and length <= 1024 and
        (explode | all(. >= 32 and . <= 126)) and
        (contains_secret_word | not) and
        (startswith("/") | not) and
        (test("(^|[[:space:]=:])/[A-Za-z0-9._-]") | not) and
        (contains("../") | not) and (contains("/..") | not) and
        (contains("\\\\") | not);
      def strong_source:
        (.source | type == "object") and
        (.source | keys == [
          "clean", "patch_identity_sha256", "revision", "source_tree_sha256",
          "tracked_patch_sha256"
        ]) and
        (.source.revision | revision) and .source.clean == true and
        (.source.source_tree_sha256 | sha256) and
        (.source.tracked_patch_sha256 | sha256) and
        (.source.patch_identity_sha256 | sha256);
      def raw_evidence:
        (.raw_evidence | type == "object") and
        (.raw_evidence | keys == ["directory", "manifest", "manifest_sha256"]) and
        (.raw_evidence.directory | type == "string" and length > 0) and
        (.raw_evidence.manifest | type == "string" and length > 0) and
        (.raw_evidence.manifest_sha256 | sha256);
      def runtime_identity:
        (.runtime | type == "object") and
        (.runtime | keys == [
          "agent", "architecture", "cgroup_topology", "deployment", "jvm",
          "kernel", "provider", "tls", "userspace"
        ]) and
        (.runtime.kernel | keys == [
          "btf_sha256", "provenance_sha256", "release", "selector",
          "version_inference"
        ]) and
        .runtime.kernel.selector == $requested[0].kernel and
        (.runtime.kernel.release | type == "string" and length > 0) and
        (.runtime.kernel.release | test("^[A-Za-z0-9._+-]{1,128}$")) and
        (.runtime.kernel.provenance_sha256 | sha256) and
        .runtime.kernel.version_inference == false and
        (.runtime.kernel.btf_sha256 | sha256) and
        .runtime.architecture == $requested[0].architecture and
        (.runtime.deployment | keys == [
          "evidence_sha256", "observed", "proof", "requested"
        ]) and
        .runtime.deployment.requested == $requested[0].deployment and
        .runtime.deployment.observed == $requested[0].deployment and
        (.runtime.deployment.proof | reason) and
        (.runtime.deployment.evidence_sha256 | sha256) and
        (.runtime.cgroup_topology | keys == [
          "attestation_sha256", "evidence_sha256", "observed", "requested"
        ]) and
        .runtime.cgroup_topology.requested == $requested[0].cgroup_topology and
        .runtime.cgroup_topology.observed == $requested[0].cgroup_topology and
        (.runtime.cgroup_topology.evidence_sha256 | sha256) and
        (.runtime.cgroup_topology.attestation_sha256 | sha256) and
        (.runtime.jvm | keys == [
          "evidence_sha256", "observed_feature", "requested_feature", "runtime"
        ]) and
        .runtime.jvm.requested_feature == $requested[0].jvm_feature and
        .runtime.jvm.observed_feature == $requested[0].jvm_feature and
        (.runtime.jvm.runtime | type == "string" and length > 0 and
          length <= 512 and test("^[A-Za-z0-9 ._+()-]+$")) and
        (.runtime.jvm.evidence_sha256 | sha256) and
        (.runtime.agent | keys == [
          "distribution", "requested_distribution", "requested_version", "sha256",
          "url", "version"
        ]) and
        .runtime.agent.requested_distribution == $requested[0].agent_distribution and
        .runtime.agent.distribution == $requested[0].agent_distribution and
        .runtime.agent.requested_version == $requested[0].agent_version and
        .runtime.agent.version == $requested[0].agent_version and
        (.runtime.agent.sha256 | sha256) and
        .runtime.agent.url ==
          (if $requested[0].agent_distribution == "otel" then
            "https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar"
           else
            "https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar"
           end) and
        (.runtime.tls | keys == ["observed", "requested"]) and
        .runtime.tls.requested == $requested[0].tls and
        .runtime.tls.observed == $requested[0].tls and
        (.runtime.userspace | keys == [
          "apache_openssl_evidence_sha256", "image_identities_sha256"
        ]) and
        (.runtime.userspace.image_identities_sha256 | sha256) and
        (.runtime.userspace.apache_openssl_evidence_sha256 | sha256) and
        (.runtime.provider | keys == [
          "attach_reason", "attempted_transports", "feature_probe", "load_reason",
          "production", "requested_transport", "selected_transport"
        ]) and
        .runtime.provider.production == true and
        .runtime.provider.requested_transport == $requested[0].transport and
        (.runtime.provider.attempted_transports | type == "array" and length > 0 and
          all(.[]; . == "getsockopt" or . == "unix") and
          (unique | length) == length) and
        (.runtime.provider.feature_probe.authoritative == true) and
        (.runtime.provider.feature_probe | keys == [
          "authoritative", "evidence_sha256", "kind", "supported"
        ]) and
        (.runtime.provider.feature_probe.kind | reason) and
        (.runtime.provider.feature_probe.evidence_sha256 | sha256) and
        (.runtime.provider.load_reason | reason) and
        (.runtime.provider.attach_reason | reason);
      def pass_transport:
        if $requested[0].transport == "auto" then
          if .runtime.provider.selected_transport == "getsockopt" then
            .runtime.provider.attempted_transports == ["getsockopt"]
          elif .runtime.provider.selected_transport == "unix" then
            .runtime.provider.attempted_transports == ["getsockopt", "unix"]
          else false
          end
        else
          .runtime.provider.attempted_transports == [$requested[0].transport] and
          .runtime.provider.selected_transport == $requested[0].transport
        end;
      def artifact_identity:
        (.artifacts | keys == [
          "extension_sha256", "generic_bpf_sha256", "helper_sha256", "jni",
          "runtime_config_sha256", "sockopt_bpf_sha256"
        ]) and
        (.artifacts.generic_bpf_sha256 | sha256) and
        (.artifacts.sockopt_bpf_sha256 | sha256) and
        (.artifacts.jni | keys == ["entry", "sha256"]) and
        .artifacts.jni.entry ==
          (if $requested[0].architecture == "amd64" then
            "native/linux-amd64/libobijni.so"
           else "native/linux-aarch64/libobijni.so" end) and
        (.artifacts.jni.sha256 | sha256) and
        (.artifacts.helper_sha256 | sha256) and
        (.artifacts.extension_sha256 | sha256) and
        (.artifacts.runtime_config_sha256 | sha256);
      def lifecycle_executor_authority:
        .lifecycle_executor as $inner |
        (.lifecycle_executor | type == "object") and
        (.lifecycle_executor | keys == [
          "approval", "command", "environment", "receipt_sha256",
          "registry_sha256", "schema"
        ]) and
        .lifecycle_executor.schema ==
          "compatibility-lifecycle-executor-authority-v1" and
        .lifecycle_executor.registry_sha256 == $executor_registry_sha256 and
        (.lifecycle_executor.approval | keys == [
          "allowed_cell_ids", "id", "path", "sha256"
        ]) and
        (.lifecycle_executor.approval.id | reason) and
        (.lifecycle_executor.approval.path | type == "string" and
          test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})*$")) and
        (.lifecycle_executor.approval.sha256 | sha256) and
        (.lifecycle_executor.approval.allowed_cell_ids | type == "array" and
          length > 0 and . == (sort | unique) and
          index($requested[0].id) != null) and
        ([$executor_registry[0].approved_executors[] |
          select(. == $inner.approval)] | length == 1) and
        (.lifecycle_executor.environment | keys == ["id", "sha256"]) and
        (.lifecycle_executor.environment.id | reason) and
        (.lifecycle_executor.environment.sha256 | sha256) and
        (.lifecycle_executor.command | keys == [
          "argv", "executable_sha256", "exit_status"
        ]) and
        .lifecycle_executor.command.executable_sha256 ==
          .lifecycle_executor.approval.sha256 and
        (.lifecycle_executor.command.exit_status | exit_code) and
        .lifecycle_executor.command.argv == [
          "/proc/self/fd/9",
          "--contract", "compatibility-helper-lifecycle-environment-v1",
          "--campaign-revision", $revision,
          "--plan-sha256", $plan_sha256,
          "--cell", "requested-cell.snapshot.json",
          "--source-authority", "source-authority.snapshot.json",
          "--source-authority-sha256", $source_authority_sha256,
          "--environment", "lifecycle-environment.snapshot.json",
          "--environment-sha256", .lifecycle_executor.environment.sha256,
          "--output", "environment-output"
        ] and
        (.lifecycle_executor.receipt_sha256 | sha256);
      . as $root |
      ((keys == [
        "artifacts", "assertions", "attempted", "campaign", "campaign_revision",
        "cell_id", "command", "evidence_index", "external_driver",
        "infrastructure_failure", "plan_sha256", "provider",
        "provider_exit_status", "provider_registry_sha256", "raw_evidence", "reason",
        "requested", "runtime", "schema", "source", "status"
      ]) or (keys == [
        "artifacts", "assertions", "attempted", "campaign", "campaign_revision",
        "cell_id", "command", "evidence_index", "external_driver",
        "infrastructure_failure", "lifecycle_executor", "plan_sha256", "provider",
        "provider_exit_status", "provider_registry_sha256", "raw_evidence", "reason",
        "requested", "runtime", "schema", "source", "status"
      ])) and
      .schema == "compatibility-provider-result-v1" and
      .campaign == $campaign and .campaign_revision == $revision and
      .plan_sha256 == $plan_sha256 and .requested == $requested[0] and
      .cell_id == $requested[0].id and .provider == $requested[0].provider and
      .provider_registry_sha256 == $registry_sha256 and
      (.status == "pass" or .status == "fail" or
        .status == "unsupported" or .status == "untested") and
      (.provider_exit_status | exit_code) and
      (if .status == "pass" then .provider_exit_status == 0
       elif .status == "unsupported" then .provider_exit_status == 78
       elif .status == "untested" then .provider_exit_status == 69
       else .provider_exit_status != 0
       end) and
      (.reason | reason) and (.attempted | type == "boolean") and
      (.infrastructure_failure | type == "boolean") and
      (.command | type == "object") and
      ((.command | keys) == ["adapter_sha256", "argv", "executed", "exit_status"] or
        (.command | keys) == [
          "adapter_sha256", "argv", "executed", "executable_sha256", "exit_status"
        ]) and
      (.command.executed | type == "boolean") and
      (.command.argv | type == "array" and length > 0 and length <= 64 and
        all(.[]; type == "string" and length > 0 and length <= 4096 and
          (contains("\u0000") | not))) and
      (.command.adapter_sha256 | sha256) and
      (if $requested[0].provider == "runsh-java21-container-v1" then
        .external_driver == null
       elif .attempted == false then
        .external_driver == null
       elif .status == "fail" and
         .assertions.classification? == "provider-contract" and
         .external_driver == null then true
       else
        (.external_driver | keys == ["id", "sha256", "snapshot"]) and
        (.external_driver.id | reason) and (.external_driver.sha256 | sha256) and
        .external_driver.snapshot == "external-driver.snapshot" and
        ([ $registry[0].providers[$requested[0].provider].approved_drivers[] |
          select(.id == $root.external_driver.id and
            .sha256 == $root.external_driver.sha256) ] | length == 1)
       end) and
      ([.reason, ((.runtime // {}) | del(.agent.url)),
        .artifacts // {}, .assertions // {}, .evidence_index // [],
        .lifecycle_executor // {}] |
        all(.. | strings; . == "/proc/self/fd/9" or safe_public_string)) and
      (if $requested[0].provider ==
        "preprovisioned-lifecycle-application-v1" then
        (.lifecycle_executor? == null or lifecycle_executor_authority)
       else .lifecycle_executor? == null
       end) and
      (if .status == "pass" then
        .attempted == true and .infrastructure_failure == false and
        .command.executed == true and
        (.command.exit_status | exit_code) and .command.exit_status == 0 and
        strong_source and runtime_identity and pass_transport and
        .runtime.provider.feature_probe.supported == true and
        artifact_identity and raw_evidence and
        (if $requested[0].provider ==
          "preprovisioned-lifecycle-application-v1" then
          lifecycle_executor_authority and
          .lifecycle_executor.command.exit_status == 0
         else true end) and
        (.assertions.exact_parent | keys == ["matched", "requests", "status", "wrong"]) and
        .assertions.application_result == "pass" and
        .assertions.cleanup == "pass" and
        .assertions.required_cells_skipped == false and
        .assertions.product_failure == false and
        .assertions.exact_parent.status == "pass" and
        (.assertions.exact_parent.requests | safe_uint and . > 0) and
        (.assertions.exact_parent.matched | safe_uint) and
        (.assertions.exact_parent.wrong | safe_uint) and
        .assertions.exact_parent.matched == .assertions.exact_parent.requests and
        .assertions.exact_parent.wrong == 0
      elif .status == "fail" then
        .attempted == true and .infrastructure_failure == false and
        .command.executed == true and
        (.command.exit_status | exit_code) and raw_evidence and
        .assertions.application_result == "fail" and
        .assertions.required_cells_skipped == false and
        (if .assertions.classification == "provider-contract" then
          (.assertions | keys == [
            "application_result", "classification", "cleanup", "contract_failure",
            "product_failure", "required_cells_skipped"
          ]) and
          .assertions.contract_failure == true and
          .assertions.product_failure == false and
          (.source | keys == ["clean", "git_tree", "revision"]) and
          (.source.revision | revision) and
          (.source.git_tree | revision) and
          (.source.clean | type == "boolean") and
          .runtime == null and .artifacts == null
         else
          (.assertions | keys == [
            "application_result", "cleanup", "product_failure", "required_cells_skipped"
          ]) and
        .command.exit_status != 0 and strong_source and runtime_identity and
          artifact_identity and pass_transport and
          (if $requested[0].provider ==
            "preprovisioned-lifecycle-application-v1" then
            lifecycle_executor_authority and
            .lifecycle_executor.command.exit_status == .command.exit_status
           else true end) and
          .runtime.provider.feature_probe.supported == true and
          .assertions.product_failure == true
         end)
      elif .status == "unsupported" then
        .attempted == true and .infrastructure_failure == false and
        .command.executed == true and
        (.command.exit_status | exit_code) and .command.exit_status == 78 and
        strong_source and runtime_identity and artifact_identity and raw_evidence and
        (if $requested[0].provider ==
          "preprovisioned-lifecycle-application-v1" then
          lifecycle_executor_authority and
          .lifecycle_executor.command.exit_status == 78
         else true end) and
        .runtime.provider.feature_probe.supported == false and
        (if $requested[0].transport == "auto" then
          .runtime.provider.attempted_transports == ["getsockopt", "unix"]
         else
          .runtime.provider.attempted_transports == [$requested[0].transport]
         end) and
        .runtime.provider.selected_transport == null and
        .assertions.application_result == "pass" and
        .assertions.cleanup == "pass" and
        .assertions.product_failure == false and
        .assertions.required_cells_skipped == false and
        (.assertions | keys == [
          "application_result", "cleanup", "exact_parent", "no_crash",
          "no_request_mutation", "product_failure", "required_cells_skipped"
        ]) and
        (.assertions.exact_parent | keys == ["matched", "requests", "status", "wrong"]) and
        (.assertions.no_request_mutation | keys == ["evidence_sha256", "status"]) and
        (.assertions.no_crash | keys == ["evidence_sha256", "status"]) and
        .assertions.no_request_mutation.status == "pass" and
        (.assertions.no_request_mutation.evidence_sha256 | sha256) and
        .assertions.no_crash.status == "pass" and
        (.assertions.no_crash.evidence_sha256 | sha256) and
        .assertions.exact_parent.status == "pass" and
        (.assertions.exact_parent.requests | safe_uint and . > 0) and
        (.assertions.exact_parent.matched | safe_uint) and
        (.assertions.exact_parent.wrong | safe_uint) and
        .assertions.exact_parent.matched == .assertions.exact_parent.requests and
        .assertions.exact_parent.wrong == 0
      else
        .infrastructure_failure == true and
        (.source | keys == ["clean", "git_tree", "revision"]) and
        (.source.clean | type == "boolean") and
        (.source.revision | type == "string" and
          (. == "" or test("^[0-9a-f]{40}$"))) and
        (.source.git_tree | type == "string" and
          (. == "" or test("^[0-9a-f]{40}$"))) and
        .runtime == null and .artifacts == null and .assertions == null and
        (if .lifecycle_executor? == null then
          .raw_evidence == null and .evidence_index == null
         else
          lifecycle_executor_authority and
          .lifecycle_executor.command.exit_status == 69 and
          raw_evidence and
          .evidence_index == [{
            field:"lifecycle_executor.receipt_sha256",
            path:"lifecycle-execution-receipt.json",
            sha256:.lifecycle_executor.receipt_sha256
          }]
         end) and
        (if .attempted then
          .command.executed == true and (.command.exit_status | exit_code)
         else
          .command.executed == false and .command.exit_status == null
         end)
      end)
    ' "$result" >/dev/null ||
    compatibility_die "provider result violates the fail-closed status contract"
}

validate_campaign_assertions() {
  local -r campaign="$1"
  local -r result="$2"
  local -r plan="$3"

  [[ "$(jq -er '.status' "$result")" == pass ]] || return 0
  if [[ "$campaign" == compatibility ]]; then
    jq -e --slurpfile plan "$plan" '
      (.assertions | keys == [
        "application_result", "cleanup", "exact_parent", "product_failure",
        "profile", "required_cells_skipped"
      ]) and
      .assertions.profile == .requested.profile and
      .assertions.profile == $plan[0].cells[0].profile
    ' "$result" >/dev/null ||
      compatibility_die "compatibility pass lacks the required application profile"
    return
  fi
  jq -e \
    --argjson max_assertion_count "$COMPATIBILITY_MAX_ASSERTION_COUNT" \
    --argjson max_resource_magnitude "$COMPATIBILITY_MAX_RESOURCE_MAGNITUDE" \
    --slurpfile plan "$plan" '
      def sha256: type == "string" and test("^[0-9a-f]{64}$");
      def safe_uint:
        type == "number" and floor == . and
        . >= 0 and . <= $max_assertion_count;
      def safe_int:
        type == "number" and floor == . and
        . >= -$max_resource_magnitude and . <= $max_resource_magnitude;
      def safe_resource_uint:
        type == "number" and floor == . and
        . >= 0 and . <= $max_resource_magnitude;
      def bounded_float:
        type == "number" and
        . >= -$max_resource_magnitude and . <= $max_resource_magnitude;
      def passed_gate:
        type == "object" and .status == "pass" and
      (.evidence_sha256 | sha256);
    def request_gate:
      passed_gate and
      (keys == [
        "crashes", "evidence_sha256", "exact_parents", "requests", "status",
        "wrong_parents"
      ]) and
      (.requests | safe_uint and . > 0) and
      (.exact_parents | safe_uint) and (.wrong_parents | safe_uint) and
      (.crashes | safe_uint) and
      .exact_parents == .requests and .wrong_parents == 0 and .crashes == 0;
    (.assertions | keys == [
      "application_result", "cleanup", "exact_parent", "frameworks", "lifecycle",
      "product_failure", "required_cells_skipped", "resource_gates",
      "unavailable_bridge", "virtual_thread"
    ]) and
    (.assertions.frameworks | keys | sort) ==
      ($plan[0].required_frameworks | sort) and
    all(.assertions.frameworks[]; request_gate) and
    (.assertions.lifecycle | keys | sort) ==
      ($plan[0].required_lifecycle | sort) and
    all(.assertions.lifecycle[]; request_gate) and
    (.assertions.resource_gates | keys | sort) ==
      ($plan[0].required_repeated_resource_gates | sort) and
    all(.assertions.resource_gates[];
      passed_gate and
      (keys == [
        "allowed_delta", "baseline", "cycles", "delta", "evidence_sha256", "final",
        "maximum_trend_slope", "status", "trend_slope"
      ]) and
      (.cycles | safe_uint and . >= 3) and
      (.baseline | safe_resource_uint) and
      (.final | safe_resource_uint) and
      (.delta | safe_int) and
      .delta == (.final - .baseline) and
      (.allowed_delta | safe_uint) and
      .delta <= .allowed_delta and
      (.trend_slope | bounded_float) and
      (.maximum_trend_slope | bounded_float and . >= 0) and
      .trend_slope <= .maximum_trend_slope) and
    (.assertions.unavailable_bridge | keys == [
      "diagnostics", "normal_agent_extraction", "normal_result_sha256",
      "result_equivalent", "status", "unavailable_result_sha256"
    ]) and
    .assertions.unavailable_bridge.status == "pass" and
    .assertions.unavailable_bridge.result_equivalent == true and
    (.assertions.unavailable_bridge.normal_result_sha256 | sha256) and
    (.assertions.unavailable_bridge.unavailable_result_sha256 | sha256) and
    .assertions.unavailable_bridge.normal_result_sha256 ==
      .assertions.unavailable_bridge.unavailable_result_sha256 and
    (.assertions.unavailable_bridge.normal_agent_extraction | request_gate) and
    (.assertions.unavailable_bridge.diagnostics | keys == [
      "bytes", "count", "evidence_sha256", "max_bytes", "max_count", "status"
    ]) and
    .assertions.unavailable_bridge.diagnostics.status == "pass" and
    (.assertions.unavailable_bridge.diagnostics.evidence_sha256 | sha256) and
    (.assertions.unavailable_bridge.diagnostics.count | safe_uint) and
    (.assertions.unavailable_bridge.diagnostics.bytes | safe_uint) and
    .assertions.unavailable_bridge.diagnostics.max_count ==
      $plan[0].unavailable_bridge_contract.max_diagnostic_count and
    .assertions.unavailable_bridge.diagnostics.max_bytes ==
      $plan[0].unavailable_bridge_contract.max_diagnostic_bytes and
    .assertions.unavailable_bridge.diagnostics.count <=
      .assertions.unavailable_bridge.diagnostics.max_count and
    .assertions.unavailable_bridge.diagnostics.bytes <=
      .assertions.unavailable_bridge.diagnostics.max_bytes and
    (if .requested.jvm_feature == 21 then
      .assertions.virtual_thread | request_gate
     else
      (.assertions.virtual_thread | keys == ["evidence_sha256", "reason", "status"]) and
      .assertions.virtual_thread.status == "unsupported" and
      .assertions.virtual_thread.reason == "requires-java-21" and
      (.assertions.virtual_thread.evidence_sha256 | sha256)
     end)
  ' "$result" >/dev/null ||
    compatibility_die "helper lifecycle pass lacks a framework, lifecycle, or repeated resource gate"
}

validate_indexed_public_evidence() {
  local -r result="$1"
  local -r raw_directory="$2"
  local -r raw_manifest="$3"
  local -r scratch="$4"
  local expected="$scratch/expected-evidence-index.json"
  local actual="$scratch/actual-evidence-index.json"
  local entries="$scratch/evidence-index.tsv"
  local field=""
  local path=""
  local sha256=""
  local indexed_file=""

  compatibility_validate_evidence_index_shape "$result" || return
  compatibility_expected_evidence_index "$result" >"$expected" || return
  jq -cS '[.evidence_index[]? | {field, sha256}]' "$result" >"$actual" || return
  cmp -s -- "$expected" "$actual" ||
    compatibility_die "public digest leaves are not exactly bound by the evidence index" || return
  if [[ "$(jq -er '.evidence_index == null or (.evidence_index | length == 0)' \
    "$result")" == true ]]; then
    [[ "$(jq -er 'length' "$expected")" == 0 ]] || return 1
    return 0
  fi
  compatibility_require_directory "$raw_directory" || return
  compatibility_require_regular_file "$raw_manifest" || return
  jq -r '.evidence_index[] | [.field, .path, .sha256] | @tsv' \
    "$result" >"$entries" || return
  while IFS=$'\t' read -r field path sha256; do
    [[ -n "$field" && -n "$path" && "$sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
    compatibility_validate_public_evidence_path "$path" ||
      compatibility_die "evidence index contains an unsafe raw path" || return
    indexed_file="$raw_directory/$path"
    compatibility_require_regular_file "$indexed_file" || return
    [[ "$(compatibility_sha256 "$indexed_file")" == "$sha256" ]] ||
      compatibility_die "indexed raw evidence content digest mismatch: $field" || return
    grep -Fqx -- "$sha256  $path" "$raw_manifest" ||
      compatibility_die "indexed raw evidence is absent from the raw manifest: $field" || return
  done <"$entries"
}

validate_external_driver_snapshot() {
  local -r result="$1"
  local -r private_directory="$2"
  local snapshot=""

  [[ "$(jq -er '.external_driver == null' "$result")" == false ]] || return 0
  snapshot="$(jq -er '.external_driver.snapshot' "$result")" || return
  compatibility_validate_relative_evidence_path "$snapshot" || return 1
  [[ "$snapshot" == "external-driver.snapshot" ]] || return 1
  compatibility_require_regular_file "$private_directory/$snapshot" || return
  [[ "$(compatibility_sha256 "$private_directory/$snapshot")" == \
    "$(jq -er '.external_driver.sha256' "$result")" ]] ||
    compatibility_die "external driver snapshot no longer matches its approved identity"
}

validate_local_attestation_evidence() {
  local -r result="$1"
  local -r raw_directory="$2"
  local -r requested="$3"
  local kernel_file="$raw_directory/campaign-attestations/kernel-provenance.json"
  local topology_file="$raw_directory/campaign-attestations/topology-attestation.json"

  [[ "$(jq -er '.provider' "$result")" == runsh-java21-container-v1 ]] || return 0
  [[ "$(jq -er '.status == "pass" or
    (.status == "fail" and .assertions.classification? != "provider-contract") or
    .status == "unsupported"' "$result")" == true ]] || return 0
  jq -e '
    ([.evidence_index[] | select(
      .field == "runtime.kernel.provenance_sha256" and
      .path == "campaign-attestations/kernel-provenance.json")] | length == 1) and
    ([.evidence_index[] | select(
      .field == "runtime.cgroup_topology.attestation_sha256" and
      .path == "campaign-attestations/topology-attestation.json")] | length == 1)
  ' "$result" >/dev/null ||
    compatibility_die "local runtime did not bind the exact campaign attestations" || return
  compatibility_validate_json_file "$kernel_file" || return
  compatibility_validate_json_file "$topology_file" || return
  jq -e --slurpfile result "$result" --slurpfile requested "$requested" '
    keys == ["observed_release", "schema", "selector", "source_digest", "version_inference"] and
    .schema == "compatibility-kernel-provenance-v1" and
    .selector == $requested[0].kernel and
    .observed_release == $result[0].runtime.kernel.release and
    .version_inference == false and
    (.source_digest | test("^sha256:[0-9a-f]{64}$"))
  ' "$kernel_file" >/dev/null || return 1
  jq -e --slurpfile result "$result" --slurpfile requested "$requested" '
    (if $requested[0].cgroup_topology == "nested-delegated-v2" then
      keys == [
        "cgroup_topology", "delegation_writable", "nested_path_observed",
        "process_cgroups_sha256", "runtime_observed", "schema"
      ]
     elif $requested[0].cgroup_topology == "sibling-containers" then
      keys == [
        "cgroup_topology", "distinct_sibling_cgroups", "process_cgroups_sha256",
        "runtime_observed", "schema"
      ]
     else
      keys == [
        "cgroup_topology", "process_cgroups_sha256", "runtime_observed", "schema"
      ]
     end) and .schema == "compatibility-topology-attestation-v1" and
    .cgroup_topology == $requested[0].cgroup_topology and
    .runtime_observed == true and
    (.process_cgroups_sha256 | test("^[0-9a-f]{64}$")) and
    (if .cgroup_topology == "nested-delegated-v2" then
      .delegation_writable == true and .nested_path_observed == true
     elif .cgroup_topology == "sibling-containers" then
      .distinct_sibling_cgroups == true
     else true end) and
    $result[0].runtime.cgroup_topology.observed == .cgroup_topology
  ' "$topology_file" >/dev/null || return 1
}

validate_helper_unavailable_bridge_evidence() {
  local -r campaign="$1"
  local -r result="$2"
  local -r raw_directory="$3"
  local normal_path=""
  local unavailable_path=""
  local extraction_path=""
  local diagnostics_path=""
  local diagnostics_size=""

  [[ "$campaign" == helper-lifecycle && "$(jq -er '.status' "$result")" == pass ]] ||
    return 0
  normal_path="$(jq -er '.evidence_index[] | select(
    .field == "assertions.unavailable_bridge.normal_result_sha256") | .path' \
    "$result")" || return
  unavailable_path="$(jq -er '.evidence_index[] | select(
    .field == "assertions.unavailable_bridge.unavailable_result_sha256") | .path' \
    "$result")" || return
  extraction_path="$(jq -er '.evidence_index[] | select(
    .field == "assertions.unavailable_bridge.normal_agent_extraction.evidence_sha256") |
    .path' "$result")" || return
  diagnostics_path="$(jq -er '.evidence_index[] | select(
    .field == "assertions.unavailable_bridge.diagnostics.evidence_sha256") | .path' \
    "$result")" || return
  cmp -s -- "$raw_directory/$normal_path" "$raw_directory/$unavailable_path" ||
    compatibility_die "unavailable-bridge result changed from the normal control" || return
  compatibility_validate_json_file "$raw_directory/$extraction_path" || return
  jq -e --slurpfile result "$result" '
    $result[0].assertions.unavailable_bridge.normal_agent_extraction as $expected |
    keys == ["crashes", "exact_parents", "requests", "schema", "status", "wrong_parents"] and
    .schema == "compatibility-normal-agent-extraction-v1" and
    .status == $expected.status and .requests == $expected.requests and
    .exact_parents == $expected.exact_parents and
    .wrong_parents == $expected.wrong_parents and .crashes == $expected.crashes
  ' "$raw_directory/$extraction_path" >/dev/null ||
    compatibility_die "normal-agent extraction proof does not match its public assertion" || return
  compatibility_validate_json_file "$raw_directory/$diagnostics_path" || return
  diagnostics_size="$(stat -Lc '%s' -- "$raw_directory/$diagnostics_path")" || return
  jq -e --argjson bytes "$diagnostics_size" --slurpfile result "$result" '
    $result[0].assertions.unavailable_bridge.diagnostics as $expected |
    keys == ["diagnostics", "schema"] and
    .schema == "compatibility-unavailable-bridge-diagnostics-v1" and
    (.diagnostics | type == "array" and length == $expected.count) and
    all(.diagnostics[];
      type == "string" and length <= 1024 and
      (explode | all(. >= 32 and . <= 126)) and
      (test("secret|password|passwd|token|credential|private[-_]?key"; "i") | not)) and
    $bytes == $expected.bytes and $bytes <= $expected.max_bytes
  ' "$raw_directory/$diagnostics_path" >/dev/null ||
    compatibility_die "unavailable-bridge diagnostics are missing, changed, or unbounded"
}

validate_lifecycle_executor_receipt() {
  local -r result="$1"
  local -r raw_directory="$2"
  local receipt_path=""
  local receipt=""

  [[ "$(jq -er '.lifecycle_executor? != null' "$result")" == true ]] || return 0
  receipt_path="$(jq -er '
    [.evidence_index[] |
      select(.field == "lifecycle_executor.receipt_sha256") | .path] |
    if length == 1 then .[0] else empty end
  ' "$result")" || return
  [[ "$receipt_path" == lifecycle-execution-receipt.json ]] ||
    compatibility_die "lifecycle executor receipt uses a noncanonical path" || return
  receipt="$raw_directory/$receipt_path"
  compatibility_require_regular_file "$receipt" || return
  compatibility_validate_json_file "$receipt" || return
  jq -e --slurpfile result "$result" '
    $result[0] as $root |
    keys == [
      "approval", "command", "environment", "registry_sha256",
      "requested_cell_id", "schema", "supervision"
    ] and
    .schema == "compatibility-lifecycle-execution-receipt-v1" and
    .registry_sha256 == $root.lifecycle_executor.registry_sha256 and
    .approval == $root.lifecycle_executor.approval and
    .environment == $root.lifecycle_executor.environment and
    .requested_cell_id == $root.requested.id and
    .command == $root.lifecycle_executor.command and
    (.supervision | keys == [
      "cleanup_complete", "containment_violation", "executor_exit_status",
      "observed_descendants", "schema", "timed_out"
    ]) and
    .supervision == {
      cleanup_complete:true,
      containment_violation:false,
      executor_exit_status:$root.lifecycle_executor.command.exit_status,
      observed_descendants:0,
      schema:"compatibility-lifecycle-executor-supervision-v1",
      timed_out:false
    }
  ' "$receipt" >/dev/null ||
    compatibility_die "lifecycle executor receipt is malformed or contradictory"
}

main() {
  local campaign=""
  local cell=""
  local provider_result=""
  local provider_launcher=""
  local private_directory=""
  local private_manifest=""
  local output=""
  local plan=""
  local revision=""
  local plan_sha256=""
  local registry_sha256=""
  local executor_registry_sha256=""
  local registry_snapshot=""
  local executor_registry_snapshot=""
  local registry_source_identity=""
  local executor_registry_source_identity=""
  local registry_snapshot_identity=""
  local executor_registry_snapshot_identity=""
  local source_authority_sha256=""
  local launcher_sha256=""
  local launcher_source=""
  local launcher_source_identity=""
  local launcher_snapshot_identity=""
  local provider_result_sha256=""
  local private_manifest_sha256=""
  local raw_manifest_sha256=""
  local argv_sha256=""
  local scratch=""
  local scratch_authority=""
  local plan_source=""
  local plan_source_identity=""
  local plan_snapshot_identity=""
  local private_source=""
  local private_source_ledger=""
  local private_source_ledger_identity=""
  local private_snapshot=""
  local private_snapshot_ledger=""
  local private_snapshot_ledger_identity=""
  local private_manifest_source=""
  local private_manifest_source_identity=""
  local private_manifest_snapshot_identity=""
  local cell_source=""
  local provider_result_source=""
  local regenerated=""
  local raw_directory=""
  local raw_manifest=""
  local raw_regenerated=""
  local output_parent=""
  local scratch_parent=""
  local sealed_candidate=""
  local sealed_candidate_identity=""

  while (( $# > 0 )); do
    case "$1" in
      --campaign)
        (( $# >= 2 )) || { usage; return 2; }
        campaign="$2"
        shift 2
        ;;
      --cell)
        (( $# >= 2 )) || { usage; return 2; }
        cell="$2"
        shift 2
        ;;
      --provider-result)
        (( $# >= 2 )) || { usage; return 2; }
        provider_result="$2"
        shift 2
        ;;
      --provider-launcher)
        (( $# >= 2 )) || { usage; return 2; }
        provider_launcher="$2"
        shift 2
        ;;
      --private-directory)
        (( $# >= 2 )) || { usage; return 2; }
        private_directory="$2"
        shift 2
        ;;
      --private-manifest)
        (( $# >= 2 )) || { usage; return 2; }
        private_manifest="$2"
        shift 2
        ;;
      --provider-registry-snapshot)
        (( $# >= 2 )) || { usage; return 2; }
        registry_snapshot="$2"
        shift 2
        ;;
      --provider-registry-snapshot-identity)
        (( $# >= 2 )) || { usage; return 2; }
        registry_snapshot_identity="$2"
        shift 2
        ;;
      --provider-registry-source-identity)
        (( $# >= 2 )) || { usage; return 2; }
        registry_source_identity="$2"
        shift 2
        ;;
      --lifecycle-executor-registry-snapshot)
        (( $# >= 2 )) || { usage; return 2; }
        executor_registry_snapshot="$2"
        shift 2
        ;;
      --lifecycle-executor-registry-snapshot-identity)
        (( $# >= 2 )) || { usage; return 2; }
        executor_registry_snapshot_identity="$2"
        shift 2
        ;;
      --lifecycle-executor-registry-source-identity)
        (( $# >= 2 )) || { usage; return 2; }
        executor_registry_source_identity="$2"
        shift 2
        ;;
      --output)
        (( $# >= 2 )) || { usage; return 2; }
        output="$2"
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        compatibility_error "unknown argument: $1"
        usage
        return 2
        ;;
    esac
  done
  [[ -n "$campaign" && -n "$cell" && -n "$provider_result" &&
    -n "$provider_launcher" && -n "$private_directory" &&
    -n "$private_manifest" && -n "$output" ]] || { usage; return 2; }

  compatibility_require_commands cmp jq mktemp python3 sha256sum stat || return
  compatibility_require_regular_file "$cell" || return
  compatibility_require_regular_file "$provider_result" || return
  compatibility_require_regular_file "$provider_launcher" || return
  compatibility_require_directory "$private_directory" || return
  compatibility_require_regular_file "$private_manifest" || return
  private_source="${private_directory%/}"
  cell_source="$cell"
  provider_result_source="$provider_result"
  private_manifest_source="$private_manifest"
  launcher_source="$(readlink -f -- "$provider_launcher")" || return
  [[ "$cell_source" == "$private_source/requested.json" &&
    "$provider_result_source" == "$private_source/provider-result.json" ]] ||
    compatibility_die "sealer inputs are not the canonical private evidence files" ||
    return
  [[ ! -e "$output" && ! -L "$output" ]] ||
    compatibility_die "sealed cell output already exists: $output" || return
  output_parent="$(dirname -- "$output")" || return
  compatibility_require_directory "$output_parent" || return
  output_parent="$(cd -- "$output_parent" && pwd -P)" || return
  output="$output_parent/$(basename -- "$output")"
  scratch_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" || return
  compatibility_require_outside_repository "$scratch_parent" || return
  scratch="$(mktemp -d "$scratch_parent/.compatibility-seal.XXXXXX")" || return
  SEAL_TEMP_DIRECTORY="$scratch"
  SEAL_TEMP_PARENT="$scratch_parent"
  SEAL_TEMP_IDENTITY="$(compatibility_directory_identity "$scratch")" || return
  trap cleanup_seal_temp EXIT
  chmod 0700 -- "$scratch"
  exec {SEAL_TEMP_DESCRIPTOR}<"$scratch" || return
  [[ "$(stat -Lc '%d:%i:%u' -- "/proc/self/fd/$SEAL_TEMP_DESCRIPTOR")" == \
      "$SEAL_TEMP_IDENTITY" &&
    "$(stat -Lc '%a:%u' -- "/proc/self/fd/$SEAL_TEMP_DESCRIPTOR")" == \
      "700:$EUID" ]] || compatibility_die "seal scratch authority changed" || return
  scratch_authority="/proc/self/fd/$SEAL_TEMP_DESCRIPTOR/."

  if [[ -z "$registry_snapshot" && -z "$registry_snapshot_identity" &&
    -z "$registry_source_identity" && -z "$executor_registry_snapshot" &&
    -z "$executor_registry_snapshot_identity" &&
    -z "$executor_registry_source_identity" ]]; then
    registry_snapshot="$scratch_authority/provider-registry.snapshot.json"
    executor_registry_snapshot=\
"$scratch_authority/lifecycle-executor-registry.snapshot.json"
    registry_source_identity="$(
      compatibility_prepare_provider_registry_snapshot "$registry_snapshot"
    )" || return
    executor_registry_source_identity="$(
      compatibility_prepare_lifecycle_executor_registry_snapshot \
        "$executor_registry_snapshot"
    )" || return
    registry_snapshot_identity="$(compatibility_stable_file_identity \
      "$registry_snapshot" 67108864)" || return
    executor_registry_snapshot_identity="$(compatibility_stable_file_identity \
      "$executor_registry_snapshot" 67108864)" || return
  else
    [[ -n "$registry_snapshot" && -n "$registry_snapshot_identity" &&
      -n "$registry_source_identity" && -n "$executor_registry_snapshot" &&
      -n "$executor_registry_snapshot_identity" &&
      -n "$executor_registry_source_identity" ]] || return 2
    compatibility_validate_provider_registry \
      "$registry_snapshot" "$registry_snapshot_identity" || return
    compatibility_validate_lifecycle_executor_registry \
      "$executor_registry_snapshot" "$executor_registry_snapshot_identity" ||
      return
    [[ "$(compatibility_stable_file_identity \
        "$COMPATIBILITY_PROVIDER_REGISTRY" 67108864)" == \
        "$registry_source_identity" &&
      "$(compatibility_stable_file_identity \
        "$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY" 67108864)" == \
        "$executor_registry_source_identity" ]] ||
      compatibility_die "supplied registry source authority changed" || return
  fi
  registry_sha256="$(compatibility_provider_registry_sha256 "$registry_snapshot")" ||
    return
  executor_registry_sha256="$(
    compatibility_lifecycle_executor_registry_sha256 "$executor_registry_snapshot"
  )" || return
  compatibility_validate_plan \
    "$campaign" "$registry_snapshot" "$executor_registry_snapshot" || return

  plan_source="$(compatibility_plan_path "$campaign")" || return
  plan_source_identity="$(compatibility_create_stable_file_snapshot \
    "$plan_source" "$scratch_authority/plan.snapshot.json" 67108864)" || return
  plan="$scratch_authority/plan.snapshot.json"
  plan_snapshot_identity="$(compatibility_stable_file_identity "$plan" 67108864)" ||
    return
  case "$campaign" in
    compatibility) revision="$(jq -er '.matrix_revision' "$plan")" || return ;;
    helper-lifecycle) revision="$(jq -er '.campaign_revision' "$plan")" || return ;;
    *) return 2 ;;
  esac
  plan_sha256="${plan_snapshot_identity##*:}"

  private_manifest_source_identity="$(compatibility_create_stable_file_snapshot \
    "$private_manifest_source" \
    "$scratch_authority/private-manifest.snapshot.sha256" \
    67108864)" || return
  private_manifest="$scratch_authority/private-manifest.snapshot.sha256"
  private_manifest_snapshot_identity="$(compatibility_stable_file_identity \
    "$private_manifest" 67108864)" || return
  regenerated="$scratch_authority/private.sha256"
  compatibility_directory_manifest "$private_source" "$regenerated" || return
  cmp -s -- "$private_manifest" "$regenerated" ||
    compatibility_die "private evidence manifest is incomplete or stale" || return

  private_snapshot="$scratch_authority/private.snapshot"
  private_source_ledger="$scratch_authority/private-source-identity.json"
  private_snapshot_ledger="$scratch_authority/private-snapshot-identity.json"
  compatibility_snapshot_manifest_directory \
    "$private_source" "$private_manifest" "$private_snapshot" \
    "$private_source_ledger" "$private_snapshot_ledger" \
    "$private_manifest_snapshot_identity" || return
  private_source_ledger_identity="$(compatibility_stable_file_identity \
    "$private_source_ledger" 67108864)" || return
  private_snapshot_ledger_identity="$(compatibility_stable_file_identity \
    "$private_snapshot_ledger" 67108864)" || return
  compatibility_verify_manifest_directory_source \
    "$private_source" "$private_source_ledger" \
    "$private_source_ledger_identity" || return
  compatibility_verify_manifest_directory_source \
    "$private_snapshot" "$private_snapshot_ledger" \
    "$private_snapshot_ledger_identity" || return
  regenerated="$scratch_authority/private-snapshot.sha256"
  compatibility_directory_manifest "$private_snapshot" "$regenerated" || return
  cmp -s -- "$private_manifest" "$regenerated" ||
    compatibility_die "private evidence snapshot differs from its manifest" || return

  cell="$private_snapshot/requested.json"
  provider_result="$private_snapshot/provider-result.json"
  private_directory="$private_snapshot"
  compatibility_validate_json_file "$cell" || return
  compatibility_validate_json_file "$provider_result" || return
  launcher_source_identity="$(compatibility_create_stable_file_snapshot \
    "$launcher_source" "$scratch_authority/provider-launcher.snapshot" \
    16777216)" || return
  provider_launcher="$scratch_authority/provider-launcher.snapshot"
  chmod 0500 -- "$provider_launcher" || return
  launcher_snapshot_identity="$(compatibility_stable_file_identity \
    "$provider_launcher" 16777216)" || return
  if [[ "$(jq -er '.provider' "$cell")" == \
    preprovisioned-lifecycle-application-v1 ]]; then
    compatibility_require_regular_file "$private_directory/source-authority.json" ||
      return
    source_authority_sha256="$(
      compatibility_sha256 "$private_directory/source-authority.json"
    )" || return
  fi
  jq -e --slurpfile plan "$plan" '
    . as $requested |
    [$plan[0].cells[] | select(.id == $requested.id and . == $requested)] | length == 1
  ' "$cell" >/dev/null || compatibility_die "selected cell differs from the campaign plan" || return

  validate_provider_result "$campaign" "$cell" "$provider_result" \
    "$revision" "$plan_sha256" "$registry_sha256" \
    "$executor_registry_sha256" "$source_authority_sha256" \
    "$registry_snapshot" "$executor_registry_snapshot" || return
  validate_campaign_assertions "$campaign" "$provider_result" "$plan" || return

  if [[ "$(jq -er '.raw_evidence != null' "$provider_result")" == true ]]; then
    raw_directory="$(jq -er '.raw_evidence.directory' "$provider_result")" || return
    raw_manifest="$(jq -er '.raw_evidence.manifest' "$provider_result")" || return
    validate_relative_evidence_path "$raw_directory" ||
      compatibility_die "unsafe raw evidence directory" || return
    validate_relative_evidence_path "$raw_manifest" ||
      compatibility_die "unsafe raw evidence manifest" || return
    raw_directory="$private_directory/$raw_directory"
    raw_manifest="$private_directory/$raw_manifest"
    compatibility_require_directory "$raw_directory" || return
    compatibility_require_regular_file "$raw_manifest" || return
    [[ "$(compatibility_sha256 "$raw_manifest")" == \
      "$(jq -er '.raw_evidence.manifest_sha256' "$provider_result")" ]] ||
      compatibility_die "raw evidence manifest digest mismatch" || return
    raw_regenerated="$scratch_authority/raw.sha256"
    compatibility_directory_manifest "$raw_directory" "$raw_regenerated" || return
    cmp -s -- "$raw_manifest" "$raw_regenerated" ||
      compatibility_die "raw evidence manifest is incomplete or stale" || return
  fi
  validate_external_driver_snapshot "$provider_result" "$private_directory" || return
  validate_indexed_public_evidence \
    "$provider_result" "$raw_directory" "$raw_manifest" \
    "$scratch_authority" || return
  validate_local_attestation_evidence \
    "$provider_result" "$raw_directory" "$cell" || return
  validate_helper_unavailable_bridge_evidence \
    "$campaign" "$provider_result" "$raw_directory" || return
  validate_lifecycle_executor_receipt "$provider_result" "$raw_directory" || return

  jq -cS '.command.argv' "$provider_result" \
    >"$scratch_authority/argv.json"
  argv_sha256="$(compatibility_sha256 "$scratch_authority/argv.json")" || return
  launcher_sha256="$(compatibility_sha256 "$provider_launcher")" || return
  provider_result_sha256="$(compatibility_sha256 "$provider_result")" || return
  private_manifest_sha256="$(compatibility_sha256 "$private_manifest")" || return
  raw_manifest_sha256="$(jq -er '.raw_evidence.manifest_sha256 // ""' \
    "$provider_result")" || return

  sealed_candidate="$scratch_authority/cell-record.candidate.json"
  jq -nS \
    --slurpfile result "$provider_result" \
    --arg launcher_sha256 "$launcher_sha256" \
    --arg result_sha256 "$provider_result_sha256" \
    --arg argv_sha256 "$argv_sha256" \
    --arg private_manifest_sha256 "$private_manifest_sha256" \
    --arg raw_manifest_sha256 "$raw_manifest_sha256" '
      $result[0] as $r |
      {
        schema: "compatibility-cell-record-v1",
        campaign: $r.campaign,
        campaign_revision: $r.campaign_revision,
        plan_sha256: $r.plan_sha256,
        cell_id: $r.cell_id,
        status: $r.status,
        reason: $r.reason,
        requested: $r.requested,
        provider: {
          name: $r.provider,
          registry_sha256: $r.provider_registry_sha256,
          external_driver:
            (if $r.external_driver == null then null else
              ($r.external_driver | del(.snapshot)) end),
          launcher_sha256: $launcher_sha256,
          launcher_exit_status: $r.provider_exit_status,
          result_sha256: $result_sha256,
          command: ($r.command | del(.argv) + {argv_sha256: $argv_sha256}),
          lifecycle_executor: ($r.lifecycle_executor // null)
        },
        source: $r.source,
        runtime: $r.runtime,
        artifacts: $r.artifacts,
        assertions: $r.assertions,
        evidence_index: $r.evidence_index,
        evidence: {
          private_manifest_sha256: $private_manifest_sha256,
          raw_manifest_sha256:
            (if $raw_manifest_sha256 == "" then null else $raw_manifest_sha256 end)
        }
      }
    ' >"$sealed_candidate" || return
  chmod 0400 -- "$sealed_candidate" || return
  compatibility_validate_json_file "$sealed_candidate" || return
  sealed_candidate_identity="$(compatibility_stable_file_identity \
    "$sealed_candidate" 67108864)" || return

  compatibility_verify_manifest_directory_source \
    "$private_source" "$private_source_ledger" \
    "$private_source_ledger_identity" ||
    compatibility_die "private evidence source changed during sealing" || return
  compatibility_verify_manifest_directory_source \
    "$private_snapshot" "$private_snapshot_ledger" \
    "$private_snapshot_ledger_identity" ||
    compatibility_die "private evidence snapshot changed during sealing" || return
  [[ "$(compatibility_stable_file_identity \
      "$private_manifest_source" 67108864)" == \
      "$private_manifest_source_identity" &&
    "$(compatibility_stable_file_identity "$private_manifest" 67108864)" == \
      "$private_manifest_snapshot_identity" &&
    "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_PROVIDER_REGISTRY" 67108864)" == \
      "$registry_source_identity" &&
    "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY" 67108864)" == \
      "$executor_registry_source_identity" &&
    "$(compatibility_stable_file_identity "$registry_snapshot" 67108864)" == \
      "$registry_snapshot_identity" &&
    "$(compatibility_stable_file_identity \
      "$executor_registry_snapshot" 67108864)" == \
      "$executor_registry_snapshot_identity" &&
    "$(compatibility_stable_file_identity "$plan_source" 67108864)" == \
      "$plan_source_identity" &&
    "$(compatibility_stable_file_identity "$plan" 67108864)" == \
      "$plan_snapshot_identity" &&
    "$(compatibility_stable_file_identity "$launcher_source" 16777216)" == \
      "$launcher_source_identity" &&
    "$(compatibility_stable_file_identity "$provider_launcher" 16777216)" == \
      "$launcher_snapshot_identity" ]] ||
    compatibility_die "sealing authority changed before publication" || return
  compatibility_publish_stable_file \
    "$sealed_candidate" "$sealed_candidate_identity" "$output" 0644
}

main "$@"
