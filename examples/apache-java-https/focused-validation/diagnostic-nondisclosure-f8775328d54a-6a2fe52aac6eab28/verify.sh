#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
expected=$'README.md\t f\nSANITIZATION.md\t f\nSHA256SUMS\t f\nmatrix-summary.json\t f\nrun-identity.json\t f\nverify.sh\t f'
observed="$(find "$root" -mindepth 1 -maxdepth 1 -printf '%f\t %y\n' | LC_ALL=C sort)"
[[ "$observed" == "$expected" ]]
for file in README.md SANITIZATION.md SHA256SUMS matrix-summary.json run-identity.json verify.sh; do
  [[ -f "$root/$file" && ! -L "$root/$file" && "$(stat -Lc '%a:%h' -- "$root/$file")" == 644:1 ]]
done
manifest_expected=$'README.md\nSANITIZATION.md\nmatrix-summary.json\nrun-identity.json\nverify.sh'
manifest_observed="$(awk '{ if (NF != 2 || $1 !~ /^[0-9a-f]{64}$/) exit 2; print $2 }' "$root/SHA256SUMS")"
[[ "$manifest_observed" == "$manifest_expected" ]]
(cd -- "$root" && sha256sum --check --strict SHA256SUMS)
summary="$(jq -ceS -s '
  if length == 1 then .[0] as $s |
    if ($s | keys == ["acceptance_evidence","cells","evidence_class","evidence_id","matrix","runtime_contract","schema","status"] and
      .schema == "obi-diagnostic-nondisclosure-public-matrix-v1" and .status == "passed" and
      .acceptance_evidence == false and .evidence_class == "focused_non_acceptance" and
      (.evidence_id | test("^diagnostic-nondisclosure-[0-9a-f]{12}-[0-9a-f]{16}$")) and
      .matrix == {agent_distributions:["otel","splunk"],cell_count:8,obi_log_levels:["info","debug"],selected_transports:["getsockopt","unix"]} and
      .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
      (.cells | type == "array" and length == 8) and [.cells[].ordinal] == [1,2,3,4,5,6,7,8] and
      [.cells[].agent_distribution] == ["otel","otel","otel","otel","splunk","splunk","splunk","splunk"] and
      [.cells[].selected_transport] == ["getsockopt","getsockopt","unix","unix","getsockopt","getsockopt","unix","unix"] and
      [.cells[].obi_log_level] == ["info","debug","info","debug","info","debug","info","debug"] and
      all(.cells[];
        keys == ["agent_distribution","authority","canary_bytes","canary_count","canary_source_sha256","diagnostic_report_sha256","obi_log_level","ordinal","selected_transport","status","surface_set_sha256","surfaces","tls_protocol"] and
        (.authority | keys == ["artifact_count","boundary_complete","boundary_freeze","boundary_index_sha256","metric_pair_sha256","run_status_sha256","status_only","terminal_java_sha256","terminal_obi_sha256","w3c_result_sha256","w3c_status_sha256"] and
          .artifact_count == 6 and .boundary_complete == true and .status_only == true and
          (.boundary_freeze | keys == ["payload","sha256"] and (.payload | test("^obi-metric-boundary-index-frozen-v1:[0-9a-f]{64}$")) and (.sha256 | test("^[0-9a-f]{64}$"))) and
          all([.boundary_index_sha256,.metric_pair_sha256,.run_status_sha256,.terminal_java_sha256,.terminal_obi_sha256,.w3c_result_sha256,.w3c_status_sha256][]; test("^[0-9a-f]{64}$"))) and
        .authority.boundary_freeze.payload == ("obi-metric-boundary-index-frozen-v1:" + .authority.boundary_index_sha256) and
        .authority.w3c_result_sha256 == .canary_source_sha256 and .status == "passed" and .tls_protocol == "TLSv1.3" and
        (.canary_count | type == "number" and floor == . and . >= 6 and . <= 128) and
        (.canary_bytes | type == "number" and floor == . and . >= 1 and . <= 16384) and
        (.canary_source_sha256 | test("^[0-9a-f]{64}$")) and (.diagnostic_report_sha256 | test("^[0-9a-f]{64}$")) and
        (.surface_set_sha256 | test("^[0-9a-f]{64}$")) and (.surfaces | type == "array" and length == 6) and
        [.surfaces[].name] == ["java_endpoint","java_header","java_transport_configuration","obi_metrics","obi_log","java_log"] and
        all(.surfaces[];
          keys == ["canary_match_count","line_count","name","schema_valid","sha256","size_bytes"] and
          .canary_match_count == 0 and .schema_valid == true and (.sha256 | test("^[0-9a-f]{64}$")) and
          (.line_count | type == "number" and floor == . and . >= 1) and (.size_bytes | type == "number" and floor == . and . >= 1) and
          (if .name == "java_endpoint" or .name == "java_header" then .line_count == 1 and .size_bytes <= 16384
           elif .name == "java_transport_configuration" then .line_count == 1 and .size_bytes <= 256
           elif .name == "obi_metrics" then .line_count <= 20000 and .size_bytes <= 8388608
           elif .name == "obi_log" then .line_count <= 10000 and .size_bytes <= 2097152
           else .line_count <= 10000 and .size_bytes <= 1048576 end))))
    then $s else error("invalid public summary") end
  else error("invalid public summary document count") end
' "$root/matrix-summary.json")"
[[ "$(<"$root/matrix-summary.json")" == "$summary" ]]
for index in {0..7}; do
  surface_sha="$(jq -er --argjson index "$index" '.cells[$index].surfaces[].sha256' "$root/matrix-summary.json" | sha256sum)"
  surface_sha="${surface_sha%% *}"
  [[ "$surface_sha" == "$(jq -er --argjson index "$index" '.cells[$index].surface_set_sha256' "$root/matrix-summary.json")" ]]
  freeze_payload="$(jq -er --argjson index "$index" '.cells[$index].authority.boundary_freeze.payload' "$root/matrix-summary.json")"
  freeze_sha="$(printf '%s\n' "$freeze_payload" | sha256sum)"; freeze_sha="${freeze_sha%% *}"
  [[ "$freeze_sha" == "$(jq -er --argjson index "$index" '.cells[$index].authority.boundary_freeze.sha256' "$root/matrix-summary.json")" ]]
done
summary_sha="$(sha256sum <"$root/matrix-summary.json")"; summary_sha="${summary_sha%% *}"
evidence_id="$(jq -er '.evidence_id' <<<"$summary")"
identity="$(jq -ceS -s --arg summary_sha "$summary_sha" --arg evidence_id "$evidence_id" '
  if length == 1 then .[0] as $i |
    if ($i | keys == ["bridge_artifacts","compose_sha256","evidence_id","matrix_summary_sha256","official_agent_pin_sha256","official_agents","patch_identity_sha256","revision","run_sha256","runner","runner_sha256","runtime_contract","schema","source_tree_manifest_schema","source_tree_sha256","tracked_patch_sha256","verifier_sha256","workflow"] and
      .schema == "obi-diagnostic-nondisclosure-public-run-identity-v1" and .evidence_id == $evidence_id and .matrix_summary_sha256 == $summary_sha and
      (.revision | test("^[0-9a-f]{40}$")) and .source_tree_manifest_schema == "git-tree-v2" and
      (.bridge_artifacts | keys == ["obi_java_agent_sha256","obi_otel_extension_sha256"] and all(.[]; type == "string" and test("^[0-9a-f]{64}$"))) and
      all([.compose_sha256,.patch_identity_sha256,.run_sha256,.runner_sha256,.source_tree_sha256,.tracked_patch_sha256,.verifier_sha256,.official_agent_pin_sha256.otel,.official_agent_pin_sha256.splunk][]; type == "string" and test("^[0-9a-f]{64}$")) and
      (.official_agent_pin_sha256 | keys == ["otel","splunk"]) and
      .official_agents == {otel:{distribution:"otel",sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",version:"2.28.1"},splunk:{distribution:"splunk",sha256:"70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",url:"https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar",version:"2.28.0"}} and
      .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
      .runner == {arch:"X64",os:"Linux"} and
      (.workflow as $w | ($w | keys == ["event","name","path","repository","run_attempt","run_id","run_url","trigger_sha","workflow_blob_sha256","workflow_ref","workflow_sha"]) and
        ($w.event == "push" or $w.event == "workflow_dispatch") and $w.name == "Java diagnostic nondisclosure matrix" and
        $w.path == ".github/workflows/java_diagnostic_nondisclosure.yml" and
        ($w.repository | test("^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")) and
        ($w.run_id | test("^[1-9][0-9]{0,18}$")) and ($w.run_attempt | test("^[1-9][0-9]{0,18}$")) and
        ($w.trigger_sha | test("^[0-9a-f]{40}$")) and ($w.workflow_sha | test("^[0-9a-f]{40}$")) and
        ($w.workflow_blob_sha256 | test("^[0-9a-f]{64}$")) and
        ($w.workflow_ref | test("^[^\\n]{1,512}$") and startswith($w.repository + "/" + $w.path + "@")) and
        $w.run_url == ("https://github.com/" + $w.repository + "/actions/runs/" + $w.run_id + "/attempts/" + $w.run_attempt) and
        ($w.event != "push" or $w.trigger_sha == $i.revision)))
    then $i else error("invalid public identity") end
  else error("invalid public identity document count") end
' "$root/run-identity.json")"
[[ "$(<"$root/run-identity.json")" == "$identity" ]]
otel_pin="$(jq -cS '.official_agents.otel' "$root/run-identity.json" | sha256sum)"; otel_pin="${otel_pin%% *}"
splunk_pin="$(jq -cS '.official_agents.splunk' "$root/run-identity.json" | sha256sum)"; splunk_pin="${splunk_pin%% *}"
[[ "$otel_pin" == "$(jq -er '.official_agent_pin_sha256.otel' <<<"$identity")" && "$splunk_pin" == "$(jq -er '.official_agent_pin_sha256.splunk' <<<"$identity")" ]]
empty_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
tracked="$(jq -er '.tracked_patch_sha256' <<<"$identity")"; [[ "$tracked" == "$empty_sha" ]]
tree="$(jq -er '.source_tree_sha256' <<<"$identity")"
patch="$(printf '%s\n%s\n%s\n' "$empty_sha" "$tree" "$empty_sha" | sha256sum)"; patch="${patch%% *}"
[[ "$patch" == "$(jq -er '.patch_identity_sha256' <<<"$identity")" ]]
cells_sha="$(jq -cS '.cells[]' "$root/matrix-summary.json" | sha256sum)"; cells_sha="${cells_sha%% *}"
revision="$(jq -er '.revision' <<<"$identity")"
[[ "$evidence_id" == "diagnostic-nondisclosure-${revision:0:12}-${cells_sha:0:16}" ]]
