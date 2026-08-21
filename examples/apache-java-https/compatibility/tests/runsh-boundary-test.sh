#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

TEST_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TEST_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$TEST_DIRECTORY/../providers/runsh-java21-container-v1.sh"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  return 1
}

expect_failure() {
  local -r label="$1"
  shift
  "$@" >/dev/null 2>&1 && fail "$label unexpectedly succeeded"
  return 0
}

write_failed_status() {
  local -r output="$1"
  local -r stage="$2"

  jq -nS --arg stage "$stage" '{
    schema:"obi-apache-java-https-run-status-v3", status:"failed",
    exit_status:1, acceptance_evidence:true, failure_stage:$stage,
    failure_line:123
  }' >"$output"
  chmod 0600 -- "$output"
}

write_attestations() {
  local -r root="$1"
  local -r release="$(uname -r)"
  local process_cgroups_sha256=""

  process_cgroups_sha256="$(sha256sum /proc/self/cgroup)"
  process_cgroups_sha256="${process_cgroups_sha256%% *}"

  jq -nS --arg release "$release" '{
    schema:"compatibility-kernel-provenance-v1",
    selector:"supported-runtime-probed", observed_release:$release,
    source_digest:"sha256:1111111111111111111111111111111111111111111111111111111111111111",
    version_inference:false
  }' >"$root/kernel.json"
  jq -nS --arg process_cgroups_sha256 "$process_cgroups_sha256" '{
    schema:"compatibility-topology-attestation-v1",
    cgroup_topology:"unified-v2", runtime_observed:true,
    process_cgroups_sha256:$process_cgroups_sha256
  }' >"$root/topology.json"
  chmod 0600 -- "$root/kernel.json" "$root/topology.json"
}

write_optional_capture() {
  local -r output="$1"
  shift

  {
    printf 'command='
    printf ' %q' "$@"
    printf '\n'
    cat
    printf 'exit_status=0\n'
  } >"$output"
  chmod 0600 -- "$output"
}

write_exact_parent_scenario() {
  local -r output="$1"

  jq -nS '
    def span($service; $kind; $trace; $span; $parent): {
      service_name:$service, kind:$kind, trace_id:$trace,
      span_id:$span, parent_span_id:$parent
    };
    def exact_case($marker; $trace; $client; $server): {
      latency_nanos:1000,
      request:{marker:$marker}, response:{marker:$marker},
      trace:{
        marker:$marker,
        spans:[
          span("apache-proxy"; "CLIENT"; $trace; $client; "root"),
          span("java-backend"; "SERVER"; $trace; $server; $client)
        ]
      }
    };
    {
      status:"passed", request_count:2,
      cases:[
        exact_case("case-1"; "11111111111111111111111111111111";
          "1111111111111111"; "1111111111111112"),
        exact_case("case-2"; "22222222222222222222222222222222";
          "2222222222222221"; "2222222222222222")
      ]
    }
  ' >"$output"
  chmod 0600 -- "$output"
}

test_exact_parent_roster_boundaries() {
  local -r root="$1"
  local scenario="$root/exact-parent.json"
  local mutated="$root/exact-parent-mutated.json"
  local assertion=""
  local filter=""
  local label=""
  local mutation=""
  local -a id_mutations=(
    'missing-client-trace|del(.cases[0].trace.spans[0].trace_id)'
    'missing-server-trace|del(.cases[0].trace.spans[1].trace_id)'
    'missing-client-span|del(.cases[0].trace.spans[0].span_id)'
    'missing-server-span|del(.cases[0].trace.spans[1].span_id)'
    'missing-server-parent|del(.cases[0].trace.spans[1].parent_span_id)'
    'null-client-trace|.cases[0].trace.spans[0].trace_id = null'
    'null-server-parent|.cases[0].trace.spans[1].parent_span_id = null'
    'empty-client-span|.cases[0].trace.spans[0].span_id = ""'
    'zero-client-trace|.cases[0].trace.spans[0].trace_id = ("0" * 32)'
    'zero-server-trace|.cases[0].trace.spans[1].trace_id = ("0" * 32)'
    'zero-client-span|.cases[0].trace.spans[0].span_id = ("0" * 16)'
    'zero-server-parent|.cases[0].trace.spans[1].parent_span_id = ("0" * 16)'
    'malformed-client-trace|.cases[0].trace.spans[0].trace_id = ("A" * 32)'
    'malformed-server-span|.cases[0].trace.spans[1].span_id = "not-a-span"'
    'malformed-server-parent|.cases[0].trace.spans[1].parent_span_id = ("f" * 15)'
    'self-parent-edge|.cases[0].trace.spans[1].span_id = .cases[0].trace.spans[0].span_id'
  )

  write_exact_parent_scenario "$scenario"
  assertion="$(exact_parent_assertion "$scenario")"
  jq -e '. == {status:"pass",requests:2,matched:2,wrong:0}' \
    <<<"$assertion" >/dev/null || fail "exact parent roster was not accepted"

  jq '.cases += [.cases[0]] | .cases[2].request.marker = "case-3" |
    .cases[2].response.marker = "case-3" | .cases[2].trace.marker = "case-3"' \
    "$scenario" >"$mutated"
  chmod 0600 -- "$mutated"
  assertion="$(exact_parent_assertion "$mutated")"
  jq -e '.status == "fail" and .requests == 2 and .matched == 3 and .wrong == 0' \
    <<<"$assertion" >/dev/null || fail "extra exact case did not fail the roster"

  jq '.cases += [.cases[0]] | .cases[2].request.marker = "case-3" |
    .cases[2].response.marker = "case-3" | .cases[2].trace.marker = "case-3" |
    .cases[2].trace.spans[1].parent_span_id = "ffffffffffffffff"' \
    "$scenario" >"$mutated"
  chmod 0600 -- "$mutated"
  assertion="$(exact_parent_assertion "$mutated")"
  jq -e '.status == "fail" and .requests == 2 and .matched == 2 and .wrong == 1' \
    <<<"$assertion" >/dev/null || fail "wrong parents were not derived from the case roster"

  jq '.cases[1].request.marker = "case-1" |
    .cases[1].response.marker = "case-1" | .cases[1].trace.marker = "case-1"' \
    "$scenario" >"$mutated"
  chmod 0600 -- "$mutated"
  [[ "$(jq -er '.status' <<<"$(exact_parent_assertion "$mutated")")" == fail ]] ||
    fail "duplicate case marker passed the exact roster"

  jq '.request_count = 3' "$scenario" >"$mutated"
  chmod 0600 -- "$mutated"
  [[ "$(jq -er '.status' <<<"$(exact_parent_assertion "$mutated")")" == fail ]] ||
    fail "missing exact case passed the request roster"

  for mutation in "${id_mutations[@]}"; do
    label="${mutation%%|*}"
    filter="${mutation#*|}"
    jq "$filter" "$scenario" >"$mutated"
    chmod 0600 -- "$mutated"
    assertion="$(exact_parent_assertion "$mutated")" ||
      fail "$label did not produce a fail-closed assertion"
    jq -e '.status == "fail" and .requests == 2 and
      .matched == 1 and .wrong == 1' <<<"$assertion" >/dev/null ||
      fail "$label passed the exact trace/parent identity contract"
  done
}

test_classification_boundaries() {
  local -r root="$1"
  local classification=""

  classification="$(classify_failed_run "$root/missing.json")"
  [[ "$classification" == $'contract\trun-status-unavailable' ]] ||
    fail "missing run status was not a provider-contract boundary"
  printf '{"schema":' >"$root/malformed.json"
  chmod 0600 -- "$root/malformed.json"
  classification="$(classify_failed_run "$root/malformed.json")"
  [[ "$classification" == $'contract\trun-status-malformed' ]] ||
    fail "malformed run status was not a provider-contract boundary"
  jq -nS '{failure_stage:"scenarios"}' >"$root/incomplete.json"
  chmod 0600 -- "$root/incomplete.json"
  classification="$(classify_failed_run "$root/incomplete.json")"
  [[ "$classification" == $'contract\trun-status-contract-invalid' ]] ||
    fail "incomplete run status was not a provider-contract boundary"
  write_failed_status "$root/infrastructure.json" initialization
  classification="$(classify_failed_run "$root/infrastructure.json")"
  [[ "$classification" == $'untested\tinfrastructure-before-product-assertion' ]] ||
    fail "pre-product infrastructure failure was not untested"
  write_failed_status "$root/product.json" scenarios
  classification="$(classify_failed_run "$root/product.json")"
  [[ "$classification" == $'fail\tapplication-or-cleanup-assertion-failed' ]] ||
    fail "product assertion failure was not fail"
}

test_transport_boundaries() {
  local -r root="$1"
  local selection=""

  printf '%s' 'version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0' \
    >"$root/selection.txt"
  chmod 0600 -- "$root/selection.txt"
  selection="$(transport_selection_from_evidence "$root/selection.txt" getsockopt)"
  jq -e '.attempted_transports == ["getsockopt"] and
    .selected_transport == "getsockopt" and .supported == true' \
    <<<"$selection" >/dev/null || fail "transport selection was not evidence-derived"
  expect_failure alternate-transport \
    transport_selection_from_evidence "$root/selection.txt" unix

  expect_failure missing-unsupported-control \
    classify_authoritative_unsupported_control "$root/missing-control.json" getsockopt
  jq -nS '{schema:"compatibility-runsh-unsupported-control-v1"}' \
    >"$root/malformed-control.json"
  chmod 0600 -- "$root/malformed-control.json"
  expect_failure malformed-unsupported-control \
    classify_authoritative_unsupported_control "$root/malformed-control.json" getsockopt
  jq -nS '{
    schema:"compatibility-runsh-unsupported-control-v1", status:"unsupported",
    requested_transport:"getsockopt", attempted_transports:["getsockopt"],
    selected_transport:null, feature_probe:{authoritative:true,supported:false},
    exact_parent:{status:"pass",requests:3,matched:3,wrong:0},
    no_request_mutation:{status:"pass",evidence_sha256:("a" * 64)},
    no_crash:{status:"pass",evidence_sha256:("b" * 64)}
  }' >"$root/unsupported-control.json"
  chmod 0600 -- "$root/unsupported-control.json"
  classify_authoritative_unsupported_control \
    "$root/unsupported-control.json" getsockopt ||
    fail "authoritative unsupported control was rejected"
}

test_attestation_snapshot_boundaries() {
  local -r root="$1"
  local case_root=""

  case_root="$root/attestation-mutation"
  install -d -m 0700 -- "$case_root/private"
  write_attestations "$case_root"
  export OBI_COMPATIBILITY_PRIVATE_DIR="$case_root/private"
  export OBI_COMPATIBILITY_KERNEL_PROVENANCE="$case_root/kernel.json"
  export OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION="$case_root/topology.json"
  snapshot_runtime_attestations supported-runtime-probed unified-v2
  runtime_attestations_are_unchanged
  printf '\n' >>"$case_root/topology.json"
  expect_failure mutated-topology runtime_attestations_are_unchanged

  # shellcheck disable=SC2034  # Consumed by the sourced attestation functions.
  KERNEL_PROVENANCE_IDENTITY=""
  # shellcheck disable=SC2034  # Consumed by the sourced attestation functions.
  TOPOLOGY_ATTESTATION_IDENTITY=""
  KERNEL_PROVENANCE_SNAPSHOT=""
  TOPOLOGY_ATTESTATION_SNAPSHOT=""
  case_root="$root/provenance-mutation"
  install -d -m 0700 -- "$case_root/private"
  write_attestations "$case_root"
  OBI_COMPATIBILITY_PRIVATE_DIR="$case_root/private"
  OBI_COMPATIBILITY_KERNEL_PROVENANCE="$case_root/kernel.json"
  OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION="$case_root/topology.json"
  snapshot_runtime_attestations supported-runtime-probed unified-v2
  printf '\n' >>"$case_root/kernel.json"
  expect_failure mutated-kernel-provenance runtime_attestations_are_unchanged

  # shellcheck disable=SC2034  # Consumed by the sourced attestation functions.
  KERNEL_PROVENANCE_IDENTITY=""
  # shellcheck disable=SC2034  # Consumed by the sourced attestation functions.
  TOPOLOGY_ATTESTATION_IDENTITY=""
  KERNEL_PROVENANCE_SNAPSHOT=""
  TOPOLOGY_ATTESTATION_SNAPSHOT=""
  case_root="$root/attestation-deletion"
  install -d -m 0700 -- "$case_root/private"
  write_attestations "$case_root"
  OBI_COMPATIBILITY_PRIVATE_DIR="$case_root/private"
  OBI_COMPATIBILITY_KERNEL_PROVENANCE="$case_root/kernel.json"
  OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION="$case_root/topology.json"
  snapshot_runtime_attestations supported-runtime-probed unified-v2
  mv -- "$KERNEL_PROVENANCE_SNAPSHOT" "$case_root/deleted-snapshot.json"
  expect_failure deleted-provenance-snapshot runtime_attestations_are_unchanged

  # shellcheck disable=SC2034  # Consumed by the sourced attestation functions.
  KERNEL_PROVENANCE_IDENTITY=""
  # shellcheck disable=SC2034  # Consumed by the sourced attestation functions.
  TOPOLOGY_ATTESTATION_IDENTITY=""
  KERNEL_PROVENANCE_SNAPSHOT=""
  TOPOLOGY_ATTESTATION_SNAPSHOT=""
  case_root="$root/attestation-substitution"
  install -d -m 0700 -- "$case_root/private"
  write_attestations "$case_root"
  OBI_COMPATIBILITY_PRIVATE_DIR="$case_root/private"
  OBI_COMPATIBILITY_KERNEL_PROVENANCE="$case_root/kernel.json"
  OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION="$case_root/topology.json"
  snapshot_runtime_attestations supported-runtime-probed unified-v2
  mv -- "$TOPOLOGY_ATTESTATION_SNAPSHOT" "$case_root/original-snapshot.json"
  install -m 0400 -- "$case_root/kernel.json" "$TOPOLOGY_ATTESTATION_SNAPSHOT"
  expect_failure substituted-topology-snapshot runtime_attestations_are_unchanged
}

write_runtime_evidence_fixture() {
  local -r root="$1"
  local -r requested="$2"
  local -r attestation="$3"
  local evidence="$root/evidence"
  local architecture=""
  local topology=""
  local project=""
  local process_cgroups_sha256=""
  local cgroup_filesystem=""
  local unprivileged_bpf=0
  local identity_format='{{json .Name}} {{json .Id}} {{json .Image}} {{json .Config.Image}} {{json .HostConfig.NetworkMode}} {{json .HostConfig.PidMode}}'
  local httpd_reference='httpd:2.4.68-alpine@sha256:1b766f17b84026429b7cb243317b142921b24432336e798bc881c43f45ed9567'
  local httpd_digest_reference='httpd@sha256:1b766f17b84026429b7cb243317b142921b24432336e798bc881c43f45ed9567'
  local trace_reference='obi-apache-java-https-tracecheck:local'
  local backend_reference='obi-apache-java-https-backend:local'
  local obi_reference='obi-apache-java-https:local'
  local httpd_image='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  local trace_image='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  local backend_image='sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
  local obi_image='sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
  local -a container_ids=(
    1111111111111111111111111111111111111111111111111111111111111111
    2222222222222222222222222222222222222222222222222222222222222222
    3333333333333333333333333333333333333333333333333333333333333333
    4444444444444444444444444444444444444444444444444444444444444444
    5555555555555555555555555555555555555555555555555555555555555555
  )

  architecture="$(compatibility_normalize_architecture "$(uname -m)")"
  if grep -Eq '[[:space:]]cgroup[[:space:]]' /proc/mounts &&
    grep -Eq '[[:space:]]cgroup2[[:space:]]' /proc/mounts; then
    topology=hybrid-v1-v2
  else
    topology=unified-v2
  fi
  jq -nS \
    --arg architecture "$architecture" \
    --arg topology "$topology" '{
      id:"runtime-evidence-fixture", architecture:$architecture,
      cgroup_topology:$topology, transport:"getsockopt",
      agent_distribution:"otel", tls:"TLSv1.3"
    }' >"$requested"
  chmod 0600 -- "$requested"
  export OBI_COMPATIBILITY_CELL_JSON="$requested"
  project="$(expected_runsh_project_name)"
  process_cgroups_sha256="$(sha256sum /proc/self/cgroup)"
  process_cgroups_sha256="${process_cgroups_sha256%% *}"
  jq -nS \
    --arg topology "$topology" \
    --arg process_cgroups_sha256 "$process_cgroups_sha256" '{
      schema:"compatibility-topology-attestation-v1",
      cgroup_topology:$topology, runtime_observed:true,
      process_cgroups_sha256:$process_cgroups_sha256
    }' >"$attestation"
  chmod 0600 -- "$attestation"

  install -d -m 0700 -- "$evidence"
  {
    printf 'dirty=false\n'
    printf 'scenario=all\n'
    printf 'transport=getsockopt\n'
    printf 'agent_distribution=otel\n'
    printf 'tls_protocol=TLSv1.3\n'
    printf 'repeat_count=1\n'
    printf 'compose_project=%s\n' "$project"
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'docker=27.5.1\n'
    printf 'compose=2.32.4\n'
    printf 'acceptance_evidence=true\n'
  } >"$evidence/environment.txt"
  cgroup_filesystem="$(stat --file-system --format '%T' /sys/fs/cgroup)"
  if [[ -r /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
    unprivileged_bpf="$(</proc/sys/kernel/unprivileged_bpf_disabled)"
  fi
  {
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'cgroup_filesystem=%s\n' "$cgroup_filesystem"
    printf 'unprivileged_bpf_disabled=%s\n' "$unprivileged_bpf"
    printf 'vmlinux_btf=readable\n'
    printf '\n/proc/self/cgroup:\n'
    cat /proc/self/cgroup
    printf '\n/proc/mounts cgroup entries:\n'
    while IFS= read -r mount_entry; do
      if [[ "$mount_entry" == *" cgroup "* || "$mount_entry" == *" cgroup2 "* ]]; then
        printf '%s\n' "$mount_entry"
      fi
    done </proc/mounts
  } >"$evidence/host-topology.txt"

  write_optional_capture "$evidence/bpftool-feature-probe.txt" \
    bpftool feature probe <<'EOF'
Scanning system configuration...
bpf() syscall is available
eBPF program_type cgroup_sockopt is available
EOF

  write_optional_capture "$evidence/container-identities.txt" \
    docker inspect --format "$identity_format" "${container_ids[@]}" <<EOF
"/$project-trace-receiver-1" "${container_ids[0]}" "$trace_image" "$trace_reference" "host" ""
"/$project-java-backend-1" "${container_ids[1]}" "$backend_image" "$backend_reference" "host" ""
"/$project-coalesced-source-1" "${container_ids[2]}" "$trace_image" "$trace_reference" "host" ""
"/$project-apache-proxy-1" "${container_ids[3]}" "$httpd_image" "$httpd_reference" "host" ""
"/$project-obi-1" "${container_ids[4]}" "$obi_image" "$obi_reference" "host" "host"
EOF

  write_optional_capture "$evidence/image-identities.txt" \
    docker image inspect --format \
    '{{json .Id}} {{json .RepoTags}} {{json .RepoDigests}}' \
    "$httpd_reference" "$trace_reference" "$backend_reference" "$obi_reference" <<EOF
"$httpd_image" null ["$httpd_digest_reference"]
"$trace_image" ["$trace_reference"] null
"$backend_image" ["$backend_reference"] null
"$obi_image" ["$obi_reference"] null
EOF

  write_optional_capture "$evidence/java-version.txt" \
    docker compose --project-name "$project" \
    --project-directory /tmp/runtime-evidence-fixture \
    --file /tmp/runtime-evidence-fixture/docker-compose.yml \
    exec --no-TTY java-backend java -version <<'EOF'
openjdk version "21.0.10" 2026-01-20 LTS
OpenJDK Runtime Environment Temurin-21.0.10+7 (build 21.0.10+7-LTS)
OpenJDK 64-Bit Server VM Temurin-21.0.10+7 (build 21.0.10+7-LTS, mixed mode)
EOF

  {
    printf 'apache_version=Apache/2.4.68 (Unix)\n'
    printf 'apache_ssl_module=ssl_module (shared)\n'
    printf 'apache_mod_ssl_path=/usr/local/apache2/modules/mod_ssl.so\n'
    printf 'apache_mod_ssl_needed=libssl.so.3,libcrypto.so.3\n'
    printf 'openssl_libssl_path=/usr/lib/libssl.so.3\n'
    printf 'openssl_libssl_owner=libssl3-3.5.4-r0\n'
    printf 'openssl_libcrypto_path=/usr/lib/libcrypto.so.3\n'
    printf 'openssl_libcrypto_owner=libcrypto3-3.5.4-r0\n'
  } >"$evidence/apache-openssl-version.txt"
  chmod 0600 -- "$evidence"/*
}

test_runtime_evidence_semantic_boundaries() {
  local -r root="$1"
  local requested="$root/runtime-requested.json"
  local attestation="$root/runtime-topology.json"
  local base="$root/runtime-fixture"
  local project=""
  local mutated=""

  install -d -m 0700 -- "$base"
  write_runtime_evidence_fixture "$base" "$requested" "$attestation"
  validate_local_runtime_evidence "$base/evidence" "$attestation" ||
    fail "valid local runtime evidence bundle was rejected"
  [[ "$(java_runtime_identity "$base/evidence/java-version.txt")" == openjdk-21.0.10 ]] ||
    fail "Java runtime identity was not normalized"
  project="$(expected_runsh_project_name)"

  mutated="$root/runtime-bpftool-mutated"
  cp -a -- "$base/evidence" "$mutated"
  sed -i 's/eBPF program_type cgroup_sockopt is available/eBPF program_type cgroup_sockopt is not available/' \
    "$mutated/bpftool-feature-probe.txt"
  expect_failure bpftool-semantic-mutation \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-bpftool-contradictory"
  cp -a -- "$base/evidence" "$mutated"
  sed -i '/eBPF program_type cgroup_sockopt is available/a eBPF program_type cgroup_sockopt is not available' \
    "$mutated/bpftool-feature-probe.txt"
  expect_failure bpftool-contradictory-support \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-bpftool-duplicate"
  cp -a -- "$base/evidence" "$mutated"
  sed -i '/eBPF program_type cgroup_sockopt is available/a eBPF program_type cgroup_sockopt is available' \
    "$mutated/bpftool-feature-probe.txt"
  expect_failure bpftool-duplicate-support \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-bpftool-extra"
  cp -a -- "$base/evidence" "$mutated"
  sed -i '/eBPF program_type cgroup_sockopt is available/a eBPF program_type cgroup_sockopt is available with caveat' \
    "$mutated/bpftool-feature-probe.txt"
  expect_failure bpftool-noncanonical-extra-support \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-container-mutated"
  cp -a -- "$base/evidence" "$mutated"
  sed -i "s#/$project-java-backend-1#/foreign-java-backend-1#" \
    "$mutated/container-identities.txt"
  expect_failure container-project-mutation \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-image-mutated"
  cp -a -- "$base/evidence" "$mutated"
  sed -i 's/\["obi-apache-java-https-tracecheck:local"\]/["foreign-tracecheck:local"]/' \
    "$mutated/image-identities.txt"
  expect_failure image-roster-mutation \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-java-mutated"
  cp -a -- "$base/evidence" "$mutated"
  sed -i 's/openjdk version "21.0.10"/openjdk version "22.0.1"/' \
    "$mutated/java-version.txt"
  expect_failure java-runtime-mutation \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-java-duplicate-project"
  cp -a -- "$base/evidence" "$mutated"
  sed -i "s/--project-name $project/--project-name $project --project-name foreign-project/" \
    "$mutated/java-version.txt"
  expect_failure java-duplicate-project-name \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-java-alternate-project"
  cp -a -- "$base/evidence" "$mutated"
  sed -i "s/--project-name $project/--project-name $project -p foreign-project/" \
    "$mutated/java-version.txt"
  expect_failure java-alternate-project-flag \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-java-option-order"
  cp -a -- "$base/evidence" "$mutated"
  sed -i \
    "s#--project-name $project --project-directory /tmp/runtime-evidence-fixture#--project-directory /tmp/runtime-evidence-fixture --project-name $project#" \
    "$mutated/java-version.txt"
  expect_failure java-global-option-order \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-project-mutated"
  cp -a -- "$base/evidence" "$mutated"
  sed -i "s/compose_project=$project/compose_project=foreign-project/" \
    "$mutated/environment.txt"
  expect_failure environment-project-mutation \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-cgroup-mutated"
  cp -a -- "$base/evidence" "$mutated"
  awk '
    after_marker && !changed && NF > 0 { print $0 "/foreign"; changed=1; next }
    { print }
    $0 == "/proc/self/cgroup:" { after_marker=1 }
  ' "$mutated/host-topology.txt" >"$mutated/host-topology.txt.new"
  chmod 0600 -- "$mutated/host-topology.txt.new"
  mv -fT -- "$mutated/host-topology.txt.new" "$mutated/host-topology.txt"
  expect_failure proc-cgroup-mutation \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-topology-mutated.json"
  jq '.process_cgroups_sha256 = ("f" * 64)' "$attestation" >"$mutated"
  chmod 0600 -- "$mutated"
  expect_failure topology-cross-binding-mutation \
    validate_local_runtime_evidence "$base/evidence" "$mutated"

  mutated="$root/runtime-apache-mutated"
  cp -a -- "$base/evidence" "$mutated"
  sed -i 's/openssl_libssl_owner=libssl3-/openssl_libssl_owner=foreign-/' \
    "$mutated/apache-openssl-version.txt"
  expect_failure userspace-ownership-mutation \
    validate_local_runtime_evidence "$mutated" "$attestation"

  mutated="$root/runtime-envelope-mutated"
  cp -a -- "$base/evidence" "$mutated"
  sed -i '$i command= bpftool feature probe' "$mutated/bpftool-feature-probe.txt"
  expect_failure duplicate-command-envelope \
    validate_local_runtime_evidence "$mutated" "$attestation"
}

main() {
  local -r root="${1:?test root is required}"
  install -d -m 0700 -- "$root"
  test_classification_boundaries "$root"
  test_transport_boundaries "$root"
  test_exact_parent_roster_boundaries "$root"
  test_attestation_snapshot_boundaries "$root"
  test_runtime_evidence_semantic_boundaries "$root"
}

main "$@"
