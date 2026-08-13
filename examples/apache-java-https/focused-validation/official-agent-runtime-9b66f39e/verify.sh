#!/usr/bin/env bash

set -euo pipefail

bundle_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd -- "$bundle_dir"

manifest_targets=(
  README.md
  SANITIZATION.md
  matrix-summary.json
  run-identity.json
  verify.sh
)

for retained_file in "${manifest_targets[@]}" SHA256SUMS; do
  if [[ ! -f "$retained_file" || -L "$retained_file" ]]; then
    echo "retained evidence file must be a regular non-symlink: $retained_file" >&2
    exit 1
  fi
done

if ! manifest_output="$(
  awk '
    NF != 2 || $1 !~ /^[[:xdigit:]]{64}$/ || $2 !~ /^[A-Za-z0-9._-]+$/ {
      exit 2
    }
    { print $2 }
  ' SHA256SUMS
)"; then
  echo "SHA256SUMS contains an invalid entry" >&2
  exit 1
fi
mapfile -t manifest_names <<<"$manifest_output"
if [[ "${manifest_names[*]}" != "${manifest_targets[*]}" ]]; then
  echo "SHA256SUMS must contain the exact ordered retained evidence file set" >&2
  exit 1
fi

sha256sum -c --strict SHA256SUMS

for json_file in matrix-summary.json run-identity.json; do
  if ! cmp -s -- "$json_file" <(jq --indent 2 . -- "$json_file"); then
    echo "JSON evidence must be canonical and contain no duplicate keys: $json_file" >&2
    exit 1
  fi
done

jq -e -s '
  length == 1 and
  .[0] == {
    "format": 1,
    "kind": "focused-official-agent-runtime-compatibility",
    "matrix_revision": "official-agent-runtime-v1",
    "source_revision": "9b66f39eb0e5897b6b27d999e461267dfa85fd70",
    "provenance": {
      "repository": "MrAlias/opentelemetry-ebpf-instrumentation",
      "workflow": "Java Agent CI",
      "workflow_path": ".github/workflows/java-agent.yml",
      "workflow_run_url": "https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31695707017",
      "run_id": 31695707017,
      "run_number": 107,
      "run_attempt": 1,
      "event": "workflow_dispatch",
      "status": "completed",
      "conclusion": "success",
      "artifacts": [
        {
          "java_feature": 8,
          "name": "java-agent-compatibility-java-8-31695707017-1",
          "archive_size_bytes": 5631,
          "digest": "sha256:a557db1d8b4094d5637f088bb31638360af04d7b64038eff7bfa283f07635f94"
        },
        {
          "java_feature": 11,
          "name": "java-agent-compatibility-java-11-31695707017-1",
          "archive_size_bytes": 5331,
          "digest": "sha256:da103526b191c5af90720edd53455d5110ba3f9a8dc5cd4cffdacb48f478f1bf"
        },
        {
          "java_feature": 17,
          "name": "java-agent-compatibility-java-17-31695707017-1",
          "archive_size_bytes": 5335,
          "digest": "sha256:d14f27e2fd92f2686e37eb8c0af6f2dbc26ecf3393874f9c83c7947cb41e05a1"
        },
        {
          "java_feature": 21,
          "name": "java-agent-compatibility-java-21-31695707017-1",
          "archive_size_bytes": 4847,
          "digest": "sha256:9f53b0dfce32686b391957668435984afa090feb7bd7786e95128818a4a33145"
        }
      ]
    },
    "agent_artifacts": [
      {
        "distribution": "opentelemetry",
        "artifact_distribution": "otel",
        "version": "2.28.1",
        "sha256": "faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",
        "url": "https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar"
      },
      {
        "distribution": "splunk",
        "artifact_distribution": "splunk",
        "version": "2.28.0",
        "embedded_opentelemetry_version": "2.28.1",
        "sha256": "70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",
        "url": "https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar"
      }
    ],
    "validation": {
      "github_archive_digests_verified": true,
      "independent_maven_agent_sha256_verified": true,
      "source_revision_matches_run_and_all_artifacts": true
    },
    "scope": {
      "supports_issue": 27,
      "stock_official_agent_runtime": true,
      "privileged_compose": false,
      "apache_acceptance_matrix_cell": false,
      "runner_architectures": ["X64/x86_64"],
      "does_not_establish": [
        "arm64",
        "issue-23-helper-lifecycle-matrix",
        "issue-38-broader-environment-matrix"
      ]
    }
  }
' run-identity.json >/dev/null

jq -n -e \
  --slurpfile identity run-identity.json \
  --slurpfile summaries matrix-summary.json '
  def expected_runtime($feature):
    {
      "8": "Eclipse Temurin 1.8.0_492-b09",
      "11": "Eclipse Temurin 11.0.31+11",
      "17": "Eclipse Temurin 17.0.19+10",
      "21": "Eclipse Temurin 21.0.12+8-LTS"
    }[$feature | tostring];

  def expected_suites($feature):
    [
      {
        "class": "OfficialAgentCompatibilityTest",
        "tests": 2,
        "skipped": 0,
        "failures": 0,
        "errors": 0
      },
      {
        "class": "OfficialAgentJava21ConcurrencyRuntimeTest",
        "tests": 2,
        "skipped": (if $feature == 21 then 0 else 2 end),
        "failures": 0,
        "errors": 0
      },
      {
        "class": "OfficialAgentJettyRuntimeTest",
        "tests": 2,
        "skipped": (if $feature == 8 then 2 else 0 end),
        "failures": 0,
        "errors": 0
      },
      {
        "class": "OfficialAgentNettyRuntimeTest",
        "tests": 2,
        "skipped": 0,
        "failures": 0,
        "errors": 0
      }
    ];

  def expected_skip_count($feature):
    if $feature == 8 then 4
    elif $feature == 21 then 0
    else 2
    end;

  ($identity | length) == 1 and
  ($summaries | length) == 1 and
  ($identity[0]) as $run |
  ($summaries[0]) as $matrix |
  ($run.provenance.artifacts |
    map({key: (.java_feature | tostring), value: .}) |
    from_entries) as $artifacts |
  ($matrix | keys) == [
    "agent_application_matrix",
    "cells",
    "expected_skips",
    "fixtures",
    "format",
    "matrix_revision",
    "runtime_contract",
    "source_revision",
    "status"
  ] and
  $matrix.format == 1 and
  $matrix.matrix_revision == $run.matrix_revision and
  $matrix.source_revision == $run.source_revision and
  $matrix.status == "passed" and
  $matrix.runtime_contract == {
    "java_features": [8, 11, 17, 21],
    "opentelemetry_agent": "2.28.1",
    "splunk_agent": "2.28.0",
    "splunk_embedded_opentelemetry": "2.28.1",
    "opentelemetry_api": "1.62.0",
    "opentelemetry_api_version_source": "agent_spi_alignment",
    "opentelemetry_autoconfigure_spi": "1.62.0",
    "obi_extension_version": "0.1.0",
    "api_loader": "bootstrap",
    "spi_loader": "io.opentelemetry.javaagent.bootstrap.AgentClassLoader",
    "extension_loader": "io.opentelemetry.javaagent.tooling.ExtensionClassLoader",
    "provider_result": "supported=true,reason=compatible",
    "official_agent_artifacts_modified": false,
    "extension_supplies_agent_or_fixture_application_classes": false
  } and
  $matrix.fixtures == {
    "jetty": "11.0.26",
    "netty": "4.1.135.Final",
    "java21_concurrency": "Java 21 only"
  } and
  $matrix.expected_skips == {
    "java_8": [
      "Jetty 11 requires Java 11 or newer (2 tests)",
      "Java 21 concurrency probe requires Java 21 (2 tests)"
    ],
    "java_11": ["Java 21 concurrency probe requires Java 21 (2 tests)"],
    "java_17": ["Java 21 concurrency probe requires Java 21 (2 tests)"],
    "java_21": []
  } and
  ($matrix.cells | map(.java_feature)) == [8, 11, 17, 21] and
  all($matrix.cells[];
    . as $cell |
    ($cell | keys) == [
      "artifact_digest",
      "artifact_name",
      "java_feature",
      "java_runtime",
      "junit",
      "runner",
      "status"
    ] and
    ($artifacts[$cell.java_feature | tostring]) as $artifact |
    $artifact != null and
    $cell.artifact_name == $artifact.name and
    $cell.artifact_digest == $artifact.digest and
    $cell.java_runtime == expected_runtime($cell.java_feature) and
    $cell.runner == {"os": "Linux", "arch": "X64", "uname_machine": "x86_64"} and
    $cell.status == "pass" and
    $cell.junit == {
      "tests": 8,
      "skipped": expected_skip_count($cell.java_feature),
      "failures": 0,
      "errors": 0,
      "suites": expected_suites($cell.java_feature)
    } and
    $cell.junit.tests == ($cell.junit.suites | map(.tests) | add) and
    $cell.junit.skipped == ($cell.junit.suites | map(.skipped) | add) and
    $cell.junit.failures == ($cell.junit.suites | map(.failures) | add) and
    $cell.junit.errors == ($cell.junit.suites | map(.errors) | add)) and
  ($matrix.cells | map(.junit.tests) | add) == 32 and
  ($matrix.cells | map(.junit.skipped) | add) == 8 and
  ($matrix.cells | map(.junit.failures) | add) == 0 and
  ($matrix.cells | map(.junit.errors) | add) == 0 and
  ($matrix.agent_application_matrix |
    map([.java_feature, .agent])) == [
      [8, "opentelemetry-2.28.1"],
      [8, "splunk-2.28.0"],
      [11, "opentelemetry-2.28.1"],
      [11, "splunk-2.28.0"],
      [17, "opentelemetry-2.28.1"],
      [17, "splunk-2.28.0"],
      [21, "opentelemetry-2.28.1"],
      [21, "splunk-2.28.0"]
    ] and
  all($matrix.agent_application_matrix[];
    (. | keys) == [
      "agent",
      "extension_startup",
      "java_feature",
      "jetty-11.0.26",
      "netty-4.1.135.Final"
    ] and
    .extension_startup == "pass" and
    ."netty-4.1.135.Final" == "pass" and
    (if .java_feature == 8
     then ."jetty-11.0.26" == "unsupported"
     else ."jetty-11.0.26" == "pass"
     end)) and
  $matrix.runtime_contract.opentelemetry_agent == $run.agent_artifacts[0].version and
  $matrix.runtime_contract.splunk_agent == $run.agent_artifacts[1].version and
  $matrix.runtime_contract.splunk_embedded_opentelemetry ==
    $run.agent_artifacts[1].embedded_opentelemetry_version
' >/dev/null

echo "official-agent runtime evidence verified"
