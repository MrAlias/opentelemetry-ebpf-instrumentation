#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
DEMO_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly DEMO_DIR
REPO_ROOT="$(git -C "$DEMO_DIR" rev-parse --show-toplevel)"
readonly REPO_ROOT
readonly VERIFIER="$SCRIPT_DIR/verify-diagnostic-nondisclosure-matrix.sh"
readonly RUNNER="$SCRIPT_DIR/run-diagnostic-nondisclosure-matrix.sh"
readonly WORKFLOW="$REPO_ROOT/.github/workflows/java_diagnostic_nondisclosure.yml"
readonly -a CELL_IDS=(
  otel-getsockopt-info otel-getsockopt-debug
  otel-unix-info otel-unix-debug
  splunk-getsockopt-info splunk-getsockopt-debug
  splunk-unix-info splunk-unix-debug
)
readonly -a SURFACE_REFS=(
  diagnostic-nondisclosure-java-endpoint.txt
  diagnostic-nondisclosure-java-header.txt
  diagnostic-nondisclosure-java-transport-configuration.txt
  diagnostic-nondisclosure-obi-metrics.prom
  diagnostic-nondisclosure-obi.log
  diagnostic-nondisclosure-java.log
)

TEMP_DIR=""

cleanup() {
  local -r status="$?"
  trap - EXIT
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" && ! -L "$TEMP_DIR" &&
    "${TEMP_DIR##*/}" =~ ^obi-i39-test\.[A-Za-z0-9]{6}$ ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
  exit "$status"
}

digest() {
  local output="" value=""
  output="$(sha256sum <"$1")" || return 1
  value="${output%% *}"
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$value"
}

digest_lines() {
  local output=""
  output="$({ printf '%s\n' "$@" || exit $?; } | sha256sum)" || return 1
  output="${output%% *}"
  [[ "$output" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$output"
}

write_debug_log_volume() {
  local -r output="$1"
  local -r transport="$2"
  local -r line_count="$3"
  local -r filler_width="$4"

  awk -v transport="$transport" -v line_count="$line_count" \
    -v filler_width="$filler_width" '
    BEGIN {
      filler = ""
      for (column = 0; column < filler_width; column++) filler = filler "x"
      print "ts level=INFO msg=\"Java remote parent bridge ready\" transport=" transport
      print "ts level=DEBUG msg=\"Java remote parent bridge ready details\" transport=" transport " socket_path=/configured/path"
      for (line = 0; line < line_count; line++)
        print "ts level=DEBUG msg=\"safe diagnostic volume\" filler=" filler
    }
  ' >"$output"
}

write_java_log_volume() {
  local -r output="$1"
  local -r line_count="$2"
  local -r filler_width="$3"

  awk -v line_count="$line_count" -v filler_width="$filler_width" '
    BEGIN {
      filler = ""
      for (column = 0; column < filler_width; column++) filler = filler "x"
      print "OBI remote-parent provider ready"
      print "OBI remote-parent propagator enabled"
      print "Jetty HTTPS backend ready on 127.0.0.1:18443"
      for (line = 0; line < line_count; line++)
        print "safe java diagnostic volume " filler
    }
  ' >"$output"
}

write_source_manifest() {
  local -r output="$1"
  local entries="$TEMP_DIR/tree.entries"
  local entry="" metadata="" path="" mode="" object="" marker=""
  git -C "$REPO_ROOT" ls-tree -r -z --full-tree HEAD >"$entries"
  : >"$output"
  while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"; path="${entry#*$'\t'}"; mode="${metadata%% *}"; object="${metadata##* }"
    case "$mode" in 100644) marker=- ;; 100755) marker=x ;; 120000) marker=l ;; 160000) marker=g ;; *) return 1 ;; esac
    LC_ALL=C printf '%s %s %q\n' "$object" "$marker" "$path" >>"$output"
  done <"$entries"
}

diagnostics_snapshot() {
  local name="" output=""
  local -a names=(
    cfg_on cfg_off provider_ok provider_reject provider_ver extension_reg
    lookup_ready lookup_missing lookup_version lookup_error record_version
    invoke_error discard_standard extract_fields extract_invalid extract_error
    registration_ok registration_fail take_sampled take_unsampled tls_reads tls_bytes
    framework_depth framework_cycle framework_late transport_missing
    t_unknown d_unknown t_valid d_valid t_missing d_missing t_stale d_stale
    t_unsupported d_unsupported t_malformed d_malformed
    t_version_mismatch d_version_mismatch t_ambiguous d_ambiguous
    t_unauthorized d_unauthorized t_already_consumed d_already_consumed
    t_timeout d_timeout t_overload d_overload t_transport_error d_transport_error
    t_disabled d_disabled
  )
  for name in "${names[@]}"; do output+="${output:+,}$name=0"; done
  printf '%s\n' "$output"
}

write_cell() {
  local -r root="$1"
  local -r id="$2"
  local agent="" transport="" level="" project="" directory="$root/cells/$id"
  local revision="" tree_sha="" patch="" status_sha=""
  local snapshot="" metrics="" requested="" selected=""
  local canaries="$TEMP_DIR/canaries-$id" count="" bytes=""
  local trusted_run="$TEMP_DIR/run-from-head-$id"
  local surfaces="$TEMP_DIR/surfaces-$id.jsonl" report=""
  local before_identity="" after_identity="" pair="" terminal_java="" terminal_metrics=""
  local terminal_reference="phases/final/java-diagnostics.txt" terminal_phase="final"
  local before_metrics_sha="" after_metrics_sha="" scenario_sha="" before_java_evidence="" after_java_evidence=""
  local boundary="" w3c_status="" report_digest="" boundary_digest=""
  local i=0 ref="" name="" sha="" size="" lines=""
  local -a names=(java_endpoint java_header java_transport_configuration obi_metrics obi_log java_log)

  IFS='-' read -r agent transport level <<<"$id"
  project="obi-apache-java-https-i39-fixture-$id"
  if [[ "$id" == splunk-unix-debug ]]; then
    terminal_reference="phases/diagnostic-nondisclosure-header/java-diagnostics.txt"
    terminal_phase=diagnostic-nondisclosure-header
  fi
  revision="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  mkdir -p -- "$directory/obi-metric-pairs" "$directory/phases/w3c-before" \
    "$directory/phases/w3c-after" "$directory/phases/diagnostic-nondisclosure-header"
  if [[ "$terminal_phase" == final ]]; then
    mkdir -p -- "$directory/phases/final" || return 1
  fi
  write_source_manifest "$directory/source-tree.manifest"
  tree_sha="$(digest "$directory/source-tree.manifest")"
  : >"$directory/git-status.txt"
  status_sha="$(digest "$directory/git-status.txt")"
  patch="$(digest_lines "$status_sha" "$tree_sha" e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"
  printf '%s\n' "revision=$revision" 'dirty=false' "source_tree_sha256=$tree_sha" \
    'source_tree_manifest_schema=git-tree-v2' \
    'tracked_patch_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    "patch_identity_sha256=$patch" >"$directory/source-state.txt"
  printf '%s\n' "$revision" >"$directory/bridge-source-revision.txt"
  printf '%s\n' "$tree_sha" >"$directory/bridge-source-tree.sha256"
  jq -nS --arg revision "$revision" --arg tree "$tree_sha" \
    '{obi_java_agent_sha256:("1"*64),obi_otel_extension_sha256:("2"*64),source_revision:$revision,source_tree_sha256:$tree}' \
    >"$directory/bridge-artifacts.json"
  printf '%s\n' invocation=test "revision=$revision" dirty=false "source_tree_sha256=$tree_sha" \
    source_tree_manifest_schema=git-tree-v2 \
    tracked_patch_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
    "patch_identity_sha256=$patch" "transport=$transport" "agent_distribution=$agent" \
    tls_protocol=TLSv1.3 "obi_log_level=$level" scenario=diagnostic-nondisclosure \
    request_count=0 repeat_count=1 scenario_seed=1 bridge_build_mode=fresh acceptance_evidence=false \
    acceptance_evidence_reason=targeted-scenario \
    "compose_project=$project" command_timeout_seconds=30 \
    readiness_timeout_seconds=30 architecture=test kernel=test openssl=test docker=test compose=test \
    >"$directory/environment.txt"
  if [[ "$agent" == otel ]]; then
    jq -cnS '{distribution:"otel",sha256:"faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",url:"https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.28.1/opentelemetry-javaagent-2.28.1.jar",version:"2.28.1"}' >"$directory/official-javaagent.json"
  else
    jq -cnS '{distribution:"splunk",embedded_opentelemetry_version:"2.28.1",sha256:"70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",url:"https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/2.28.0/splunk-otel-javaagent-2.28.0.jar",version:"2.28.0"}' >"$directory/official-javaagent.json"
  fi

  snapshot="$(diagnostics_snapshot)"
  printf '%s\n' "$snapshot" >"$directory/${SURFACE_REFS[0]}"
  printf '%s\n' "$snapshot" >"$directory/${SURFACE_REFS[1]}"
  printf '%s\n' "$snapshot" >"$directory/phases/w3c-before/java-diagnostics.txt"
  printf '%s\n' "$snapshot" >"$directory/phases/w3c-after/java-diagnostics.txt"
  printf '%s\n' "$snapshot" >"$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt"
  if [[ "$terminal_phase" == final ]]; then
    printf '%s\n' "$snapshot" >"$directory/$terminal_reference" || return 1
  fi
  if [[ "$transport" == getsockopt ]]; then requested=1; selected=1; else requested=2; selected=2; fi
  printf 'version=2,status=1,requested=%s,selected=%s,attempted=%s,getsockopt=%s,unix=%s\n' \
    "$requested" "$selected" "$selected" "$([[ "$transport" == getsockopt ]] && printf 1 || printf 0)" \
    "$([[ "$transport" == unix ]] && printf 1 || printf 0)" >"$directory/${SURFACE_REFS[2]}"
  metrics="obi_java_remote_parent_operations_total{operation=\"availability\",status=\"valid\",transport=\"$transport\"}"
  printf '%s 2\n' "$metrics" >"$directory/${SURFACE_REFS[3]}"
  printf '%s 1\n' "$metrics" >"$directory/phases/w3c-before/obi-metrics.prom"
  printf '%s 2\n' "$metrics" >"$directory/phases/w3c-after/obi-metrics.prom"
  printf 'ts level=INFO msg="Java remote parent bridge ready" transport=%s\n' "$transport" >"$directory/${SURFACE_REFS[4]}"
  if [[ "$level" == debug ]]; then printf 'ts level=DEBUG msg="Java remote parent bridge ready details" transport=%s socket_path=/private\n' "$transport" >>"$directory/${SURFACE_REFS[4]}"; fi
  printf '%s\n' 'OBI remote-parent provider ready' 'OBI remote-parent propagator enabled' \
    'Jetty HTTPS backend ready on 127.0.0.1:18443' >"$directory/${SURFACE_REFS[5]}"
  jq -nS '{
    status:"passed",scenario:"w3c",seed:1,
    started_at:"2026-01-01T00:00:00.000000000Z",finished_at:"2026-01-01T00:00:01.000000000Z",
    request_count:2,traffic_elapsed_nanos:1000000,throughput_per_second:2,
    latency:{p50_nanos:100,p95_nanos:200,p99_nanos:300},
    cases:[
      {request:{marker:"dynamic-marker-a",endpoint:"/api/echo",w3c_trace_id:"11111111111111111111111111111111",w3c_parent_span_id:"2222222222222222",w3c_trace_flags:"01",w3c_case:"conflicting-valid-w3c-and-obi"},
       response:{marker:"dynamic-marker-a",secure:true,protocol:"HTTP/1.1",tls_protocol:"TLSv1.3",tls_cipher:"TLS_AES_128_GCM_SHA256",backend_connection_id:1,backend_remote_port:12345,tls_read_events:1,tls_read_bytes:128},
       latency_nanos:100,
       trace:{marker:"dynamic-marker-a",received_batches:1,received_spans:3,dropped_spans:0,dropped_count_spans:0,dropped_value_limit_spans:0,dropped_retained_limit_spans:0,retained_bytes:384,max_retained_bytes:67108864,max_value_bytes:4096,
         spans:[
           {trace_id:"11111111111111111111111111111111",span_id:"3333333333333333",parent_span_id:"2222222222222222",flags:1,service_name:"apache-proxy",name:"GET /api/echo",kind:"SERVER",attributes:{"http.request.header.x-obi-demo-id":"dynamic-marker-a","http.route":"/api/echo"},start_unix_nano:1000,end_unix_nano:2000},
           {trace_id:"11111111111111111111111111111111",span_id:"4444444444444444",parent_span_id:"3333333333333333",flags:1,service_name:"apache-proxy",name:"GET /api/echo",kind:"CLIENT",attributes:{"http.request.header.x-obi-demo-id":"dynamic-marker-a","url.path":"/api/echo"},start_unix_nano:1100,end_unix_nano:1900},
           {trace_id:"11111111111111111111111111111111",span_id:"5555555555555555",parent_span_id:"2222222222222222",flags:769,service_name:"java-backend",name:"GET /api/echo",kind:"SERVER",attributes:{"http.request.header.x-obi-demo-id":"dynamic-marker-a","http.route":"/api/echo"},start_unix_nano:1200,end_unix_nano:1800}],related_spans:[]}},
      {request:{marker:"dynamic-marker-b",endpoint:"/api/echo",w3c_case:"malformed-w3c-valid-obi",invalid_w3c:true},
       response:{marker:"dynamic-marker-b",secure:true,protocol:"HTTP/1.1",tls_protocol:"TLSv1.3",tls_cipher:"TLS_AES_128_GCM_SHA256",backend_connection_id:1,backend_remote_port:12345,tls_read_events:2,tls_read_bytes:256},
       latency_nanos:200,
       trace:{marker:"dynamic-marker-b",received_batches:1,received_spans:3,dropped_spans:0,dropped_count_spans:0,dropped_value_limit_spans:0,dropped_retained_limit_spans:0,retained_bytes:384,max_retained_bytes:67108864,max_value_bytes:4096,
         spans:[
           {trace_id:"77777777777777777777777777777777",span_id:"8888888888888888",flags:1,service_name:"apache-proxy",name:"GET /api/echo",kind:"SERVER",attributes:{"http.request.header.x-obi-demo-id":"dynamic-marker-b","http.route":"/api/echo"},start_unix_nano:3000,end_unix_nano:4000},
           {trace_id:"77777777777777777777777777777777",span_id:"9999999999999999",parent_span_id:"8888888888888888",flags:1,service_name:"apache-proxy",name:"GET /api/echo",kind:"CLIENT",attributes:{"http.request.header.x-obi-demo-id":"dynamic-marker-b","url.path":"/api/echo"},start_unix_nano:3100,end_unix_nano:3900},
           {trace_id:"77777777777777777777777777777777",span_id:"aaaaaaaaaaaaaaaa",parent_span_id:"9999999999999999",flags:769,service_name:"java-backend",name:"GET /api/echo",kind:"SERVER",attributes:{"http.request.header.x-obi-demo-id":"dynamic-marker-b","http.route":"/api/echo"},start_unix_nano:3200,end_unix_nano:3800}],related_spans:[]}}
    ]
  }' >"$directory/scenario-w3c.json"
  case "$id" in
    otel-getsockopt-info)
      printf ' Container %s-scenario-run-0123456789ab Creating \n Container %s-scenario-run-0123456789ab Created \n' \
        "$project" "$project" >"$directory/scenario-w3c.stderr.log"
      ;;
    otel-getsockopt-debug)
      printf ' Container %s-scenario-run-0123456789ab  Creating\n Container %s-scenario-run-0123456789ab  Created\n' \
        "$project" "$project" >"$directory/scenario-w3c.stderr.log"
      ;;
    *) : >"$directory/scenario-w3c.stderr.log" ;;
  esac
  git -C "$REPO_ROOT" show "$revision:examples/apache-java-https/run.sh" >"$trusted_run"
  {
    sed -n -E 's/^DIAGNOSTIC_NONDISCLOSURE_(TRACE_ID|PARENT_SPAN_ID|MARKER|HEADER_CANARY|BODY_CANARY|CREDENTIAL_CANARY)="([A-Za-z0-9._:-]+)"$/\2/p' "$trusted_run"
    [[ "$transport" == unix ]] && sed -n -E 's/^DIAGNOSTIC_NONDISCLOSURE_UNIX_PAYLOAD_CANARY="([A-Za-z0-9._:-]+)"$/\1/p' "$trusted_run"
    jq -r '.cases[] | .request.marker,(.request.w3c_trace_id // empty),(.request.w3c_parent_span_id // empty),(.trace.spans[]|.trace_id,.span_id,(.parent_span_id // empty)),(.trace.related_spans[]?|.trace_id,.span_id,(.parent_span_id // empty))' "$directory/scenario-w3c.json"
  } | LC_ALL=C sort -u >"$canaries"
  count="$(wc -l <"$canaries")"; bytes="$(stat -Lc '%s' "$canaries")"
  : >"$surfaces"
  for i in "${!SURFACE_REFS[@]}"; do
    ref="${SURFACE_REFS[$i]}"; name="${names[$i]}"; sha="$(digest "$directory/$ref")"
    size="$(stat -Lc '%s' "$directory/$ref")"; lines="$(wc -l <"$directory/$ref")"
    jq -cnS --arg name "$name" --arg ref "$ref" --arg sha "$sha" --argjson size "$size" --argjson lines "$lines" \
      '{canary_match_count:0,line_count:$lines,name:$name,reference:$ref,schema_valid:true,sha256:$sha,size_bytes:$size}' >>"$surfaces"
  done
  scenario_sha="$(digest "$directory/scenario-w3c.json")"
  report="$(jq -cs --arg agent "$agent" --arg transport "$transport" --arg level "$level" --arg source_sha "$scenario_sha" --argjson count "$count" --argjson bytes "$bytes" '
    {agent_distribution:$agent,canary_bytes:$bytes,canary_count:$count,canary_source:{reference:"scenario-w3c.json",sha256:$source_sha},debug_controls:{bpf_debug:false,protocol_debug:false},obi_log_level:$level,obi_metric_boundary_ids:["diagnostic-nondisclosure"],policy:{log_capture_complete:true,no_canary_matches:true,runtime_configuration_attested:true,surface_schemas_valid:true},scenario:"diagnostic-nondisclosure",schema:"obi-diagnostic-nondisclosure-v1",selected_transport:$transport,status:"passed",surfaces:.,tls_protocol:"TLSv1.3",window:{since:"2026-01-01T00:00:00.000000000Z",until:"2026-01-01T00:00:01.000000000Z"}}' "$surfaces")"
  printf '%s\n' "$report" >"$directory/scenario-diagnostic-nondisclosure-status.json"

  before_metrics_sha="$(digest "$directory/phases/w3c-before/obi-metrics.prom")"
  after_metrics_sha="$(digest "$directory/phases/w3c-after/obi-metrics.prom")"
  before_identity="$(jq -cnS --arg ref phases/w3c-before/obi-metrics.prom --arg sha "$before_metrics_sha" '{container_id:("a"*64),host_pid:"1",metrics_reference:$ref,metrics_sha256:$sha,schema:"obi-process-identity-v1",started_at:"2026-01-01T00:00:00.000000000Z",state:"running"}')"
  after_identity="$(jq -cnS --arg ref phases/w3c-after/obi-metrics.prom --arg sha "$after_metrics_sha" '{container_id:("a"*64),host_pid:"1",metrics_reference:$ref,metrics_sha256:$sha,schema:"obi-process-identity-v1",started_at:"2026-01-01T00:00:00.000000000Z",state:"running"}')"
  printf '%s\n' "$before_identity" >"$directory/phases/w3c-before/obi-identity.json"
  printf '%s\n' "$after_identity" >"$directory/phases/w3c-after/obi-identity.json"
  pair="$(jq -cn --arg transport "$transport" '{schema:"obi-java-remote-parent-metric-pair-v1",boundary:"w3c",continuity:"same_process",before:{state:"running",identity_reference:"phases/w3c-before/obi-identity.json"},after:{state:"running",identity_reference:"phases/w3c-after/obi-identity.json"},series:[{transport:$transport,operation:"availability",status:"valid",before:"1",after:"2",delta:"1"}],java_attach_errors:{before:"0",after:"0",delta:"0"}}')"
  printf '%s\n' "$pair" >"$directory/obi-metric-pairs/w3c.json"
  terminal_java="$(jq -cn --arg snapshot "$snapshot" --arg ref "$terminal_reference" --arg phase "$terminal_phase" '
    {reference:$ref,snapshot:$snapshot,
     counters:($snapshot|split(",")|map(split("=")|{(.[0]):.[1]})|add)} +
    {schema:"obi-java-bridge-terminal-diagnostics-v1",sealed:true,available:true,phase:$phase}')"
  printf '%s\n' "$terminal_java" >"$directory/terminal-java-diagnostics.json"
  before_java_evidence="$(jq -cnS --arg snapshot "$snapshot" --arg ref phases/w3c-before/java-diagnostics.txt '{counters:($snapshot|split(",")|map(split("=")|{(.[0]):.[1]})|add),reference:$ref,snapshot:$snapshot}')"
  after_java_evidence="$(jq -cnS --arg snapshot "$snapshot" --arg ref phases/w3c-after/java-diagnostics.txt '{counters:($snapshot|split(",")|map(split("=")|{(.[0]):.[1]})|add),reference:$ref,snapshot:$snapshot}')"
  w3c_status="$(jq -cnS --argjson before "$before_java_evidence" --argjson after "$after_java_evidence" --argjson pair "$pair" '{after_phase:"phases/w3c-after",before_phase:"phases/w3c-before",exit_status:0,java_diagnostics:{after:$after,before:$before},metric_status:0,obi_metric_boundary_ids:["diagnostic-nondisclosure"],obi_metric_evidence:{pair:$pair,reference:"obi-metric-pairs/w3c.json"},pressure_correlation:null,receive_coordination_maps:null,result:"scenario-w3c.json",scenario:"w3c",scenario_reconciliation:null,status:"passed",stderr:"scenario-w3c.stderr.log"}')"
  printf '%s\n' "$w3c_status" >"$directory/scenario-w3c-status.json"
  report_digest="$(digest "$directory/scenario-diagnostic-nondisclosure-status.json")"
  boundary="$(jq -cnS --arg transport "$transport" --arg w3c_status "$(digest "$directory/scenario-w3c-status.json")" --arg report "$report_digest" \
    --arg pair "$(digest "$directory/obi-metric-pairs/w3c.json")" --arg before_java "$(digest "$directory/phases/w3c-before/java-diagnostics.txt")" \
    --arg before_id "$(digest "$directory/phases/w3c-before/obi-identity.json")" --arg after_id "$(digest "$directory/phases/w3c-after/obi-identity.json")" \
    --arg after_java "$(digest "$directory/phases/w3c-after/java-diagnostics.txt")" --arg header_java "$(digest "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt")" \
    --arg e "$(digest "$directory/${SURFACE_REFS[0]}")" --arg h "$(digest "$directory/${SURFACE_REFS[1]}")" --arg t "$(digest "$directory/${SURFACE_REFS[2]}")" \
    --arg m "$(digest "$directory/${SURFACE_REFS[3]}")" --arg o "$(digest "$directory/${SURFACE_REFS[4]}")" --arg j "$(digest "$directory/${SURFACE_REFS[5]}")" '
    {boundaries:[{captures:[
      {id:"w3c",java_reference:"phases/w3c-after/java-diagnostics.txt",java_sha256:$after_java,kind:"pair",pair_reference:"obi-metric-pairs/w3c.json",pair_sha256:$pair,state:"captured"},
      {id:"java-w3c-before",kind:"java",reference:"phases/w3c-before/java-diagnostics.txt",sha256:$before_java,state:"captured"},
      {id:"w3c-before",identity_reference:"phases/w3c-before/obi-identity.json",identity_sha256:$before_id,kind:"phase",state:"captured"},
      {id:"w3c-after",identity_reference:"phases/w3c-after/obi-identity.json",identity_sha256:$after_id,kind:"phase",state:"captured"},
      {id:"java-w3c-after",kind:"java",reference:"phases/w3c-after/java-diagnostics.txt",sha256:$after_java,state:"captured"},
      {id:"java-diagnostic-nondisclosure-header",kind:"java",reference:"phases/diagnostic-nondisclosure-header/java-diagnostics.txt",sha256:$header_java,state:"captured"},
      {id:"diagnostic-java-endpoint",kind:"artifact",reference:"diagnostic-nondisclosure-java-endpoint.txt",sha256:$e,state:"captured"},
      {id:"diagnostic-java-header",kind:"artifact",reference:"diagnostic-nondisclosure-java-header.txt",sha256:$h,state:"captured"},
      {id:"diagnostic-java-transport",kind:"artifact",reference:"diagnostic-nondisclosure-java-transport-configuration.txt",sha256:$t,state:"captured"},
      {id:"diagnostic-obi-metrics",kind:"artifact",reference:"diagnostic-nondisclosure-obi-metrics.prom",sha256:$m,state:"captured"},
      {id:"diagnostic-obi-log",kind:"artifact",reference:"diagnostic-nondisclosure-obi.log",sha256:$o,state:"captured"},
      {id:"diagnostic-java-log",kind:"artifact",reference:"diagnostic-nondisclosure-java.log",sha256:$j,state:"captured"}],id:"diagnostic-nondisclosure",not_applicable_reason:null,ordinal:1,state:"complete",status_references:[{reference:"scenario-w3c-status.json",sha256:$w3c_status},{reference:"scenario-diagnostic-nondisclosure-status.json",sha256:$report}]}],schema:"obi-metric-boundary-index-v1",selection:{repeat_count:1,requested_transport:$transport,scenario:"diagnostic-nondisclosure",selected_transport:$transport}}')"
  printf '%s\n' "$boundary" >"$directory/obi-metric-boundary-index.json"
  boundary_digest="$(digest "$directory/obi-metric-boundary-index.json")"
  printf 'obi-metric-boundary-index-frozen-v1:%s\n' "$boundary_digest" >"$directory/.obi-metric-boundary-index.freeze"
  terminal_metrics="$(jq -cnS --arg sha "$boundary_digest" '{active_boundary_id:null,available:false,boundary_index_reference:"obi-metric-boundary-index.json",boundary_index_sha256:$sha,reason:"no-active-boundary",schema:"obi-java-remote-parent-terminal-metrics-v2",sealed:true}')"
  printf '%s\n' "$terminal_metrics" >"$directory/terminal-obi-metrics.json"
  jq -nS --arg sha "$boundary_digest" --argjson java "$terminal_java" --argjson metrics "$terminal_metrics" \
    '{acceptance_evidence:false,acceptance_evidence_reason:"targeted-scenario",evidence_directory:"/private/results/fixture",exit_status:0,failure_line:0,failure_stage:"none",java_bridge_diagnostics:$java,java_bridge_diagnostics_reference:"terminal-java-diagnostics.json",obi_metric_boundary_index_reference:"obi-metric-boundary-index.json",obi_metric_boundary_index_sha256:$sha,obi_metric_evidence:$metrics,obi_metric_evidence_reference:"terminal-obi-metrics.json",schema:"obi-apache-java-https-run-status-v3",status:"passed"}' >"$directory/run-status.json"
  find "$directory" -type d -exec chmod 0700 {} +
  find "$directory" -type f -exec chmod 0600 {} +
}

json_update() {
  local -r input="$1"
  local -r filter="$2"
  local temporary=""

  temporary="$(mktemp "$TEMP_DIR/json-update.XXXXXX")" || return 1
  jq -c "$filter" "$input" >"$temporary" || return 1
  chmod 0600 -- "$temporary" || return 1
  mv -fT -- "$temporary" "$input" || return 1
}

json_update_sorted() {
  local -r input="$1"
  local -r filter="$2"
  local temporary=""

  temporary="$(mktemp "$TEMP_DIR/json-update.XXXXXX")" || return 1
  jq -cS "$filter" "$input" >"$temporary" || return 1
  chmod 0600 -- "$temporary" || return 1
  mv -fT -- "$temporary" "$input" || return 1
}

write_test_canaries() {
  local -r directory="$1"
  local -r output="$2"
  local transport=""
  local trusted_run=""

  IFS='-' read -r _ transport _ <<<"${directory##*/}"
  trusted_run="$(mktemp "$TEMP_DIR/trusted-run.XXXXXX")" || return 1
  git -C "$REPO_ROOT" show "HEAD:examples/apache-java-https/run.sh" >"$trusted_run" || return 1
  {
    sed -n -E 's/^DIAGNOSTIC_NONDISCLOSURE_(TRACE_ID|PARENT_SPAN_ID|MARKER|HEADER_CANARY|BODY_CANARY|CREDENTIAL_CANARY)="([A-Za-z0-9._:-]+)"$/\2/p' "$trusted_run" || exit $?
    if [[ "$transport" == unix ]]; then
      sed -n -E 's/^DIAGNOSTIC_NONDISCLOSURE_UNIX_PAYLOAD_CANARY="([A-Za-z0-9._:-]+)"$/\1/p' "$trusted_run" || exit $?
    fi
    jq -r '.cases[] | .request.marker,(.request.w3c_trace_id // empty),(.request.w3c_parent_span_id // empty),(.trace.spans[]|.trace_id,.span_id,(.parent_span_id // empty)),(.trace.related_spans[]?|.trace_id,.span_id,(.parent_span_id // empty))' \
      "$directory/scenario-w3c.json" || exit $?
  } | LC_ALL=C sort -u >"$output" || return 1
}

refresh_report() {
  local -r directory="$1"
  local id="${directory##*/}" agent="" transport="" level=""
  local canaries="" surfaces="" count="" bytes="" scenario_sha=""
  local reference="" name="" sha="" size="" lines="" report=""
  local i=0
  local -a names=(java_endpoint java_header java_transport_configuration obi_metrics obi_log java_log)

  IFS='-' read -r agent transport level <<<"$id"
  canaries="$(mktemp "$TEMP_DIR/canaries-refresh.XXXXXX")" || return 1
  surfaces="$(mktemp "$TEMP_DIR/surfaces-refresh.XXXXXX")" || return 1
  write_test_canaries "$directory" "$canaries" || return 1
  count="$(LC_ALL=C wc -l <"$canaries")" || return 1
  bytes="$(stat -Lc '%s' -- "$canaries")" || return 1
  scenario_sha="$(digest "$directory/scenario-w3c.json")" || return 1
  : >"$surfaces" || return 1
  for i in "${!SURFACE_REFS[@]}"; do
    reference="${SURFACE_REFS[$i]}"; name="${names[$i]}"
    sha="$(digest "$directory/$reference")" || return 1
    size="$(stat -Lc '%s' -- "$directory/$reference")" || return 1
    lines="$(LC_ALL=C wc -l <"$directory/$reference")" || return 1
    jq -cnS --arg name "$name" --arg ref "$reference" --arg sha "$sha" \
      --argjson size "$size" --argjson lines "$lines" \
      '{canary_match_count:0,line_count:$lines,name:$name,reference:$ref,schema_valid:true,sha256:$sha,size_bytes:$size}' \
      >>"$surfaces" || return 1
  done
  report="$(jq -cs --arg agent "$agent" --arg transport "$transport" --arg level "$level" \
    --arg source_sha "$scenario_sha" --argjson count "$count" --argjson bytes "$bytes" '
    {agent_distribution:$agent,canary_bytes:$bytes,canary_count:$count,canary_source:{reference:"scenario-w3c.json",sha256:$source_sha},debug_controls:{bpf_debug:false,protocol_debug:false},obi_log_level:$level,obi_metric_boundary_ids:["diagnostic-nondisclosure"],policy:{log_capture_complete:true,no_canary_matches:true,runtime_configuration_attested:true,surface_schemas_valid:true},scenario:"diagnostic-nondisclosure",schema:"obi-diagnostic-nondisclosure-v1",selected_transport:$transport,status:"passed",surfaces:.,tls_protocol:"TLSv1.3",window:{since:"2026-01-01T00:00:00.000000000Z",until:"2026-01-01T00:00:01.000000000Z"}}' \
    "$surfaces")" || return 1
  printf '%s\n' "$report" >"$directory/scenario-diagnostic-nondisclosure-status.json" || return 1
  chmod 0600 -- "$directory/scenario-diagnostic-nondisclosure-status.json" || return 1
}

refresh_identities() {
  local -r directory="$1"
  local phase="" reference="" sha=""

  for phase in w3c-before w3c-after; do
    reference="phases/$phase/obi-metrics.prom"
    sha="$(digest "$directory/$reference")" || return 1
    jq -cS --arg sha "$sha" --arg ref "$reference" \
      '.metrics_sha256=$sha | .metrics_reference=$ref' \
      "$directory/phases/$phase/obi-identity.json" >"$TEMP_DIR/identity" || return 1
    mv -fT -- "$TEMP_DIR/identity" "$directory/phases/$phase/obi-identity.json" || return 1
    chmod 0600 -- "$directory/phases/$phase/obi-identity.json" || return 1
  done
}

refresh_terminal_java() {
  local -r directory="$1"
  local reference="" phase="" snapshot=""

  reference="$(jq -er '.reference' "$directory/terminal-java-diagnostics.json")" || return 1
  phase="${reference#phases/}"; phase="${phase%/java-diagnostics.txt}"
  snapshot="$(<"$directory/$reference")"
  jq -cnS --arg snapshot "$snapshot" --arg ref "$reference" --arg phase "$phase" \
    '{available:true,counters:($snapshot|split(",")|map(split("=")|{(.[0]):.[1]})|add),phase:$phase,reference:$ref,schema:"obi-java-bridge-terminal-diagnostics-v1",sealed:true,snapshot:$snapshot}' \
    >"$directory/terminal-java-diagnostics.json" || return 1
  chmod 0600 -- "$directory/terminal-java-diagnostics.json" || return 1
}

java_evidence() {
  local -r input="$1"
  local -r reference="$2"
  local snapshot=""

  snapshot="$(<"$input")"
  jq -cnS --arg snapshot "$snapshot" --arg ref "$reference" \
    '{counters:($snapshot|split(",")|map(split("=")|{(.[0]):.[1]})|add),reference:$ref,snapshot:$snapshot}'
}

refresh_w3c_status() {
  local -r directory="$1"
  local before="" after="" pair=""

  before="$(java_evidence "$directory/phases/w3c-before/java-diagnostics.txt" phases/w3c-before/java-diagnostics.txt)" || return 1
  after="$(java_evidence "$directory/phases/w3c-after/java-diagnostics.txt" phases/w3c-after/java-diagnostics.txt)" || return 1
  pair="$(jq -ce -s 'if length == 1 then .[0] else error("pair") end' "$directory/obi-metric-pairs/w3c.json")" || return 1
  jq -cnS --argjson before "$before" --argjson after "$after" --argjson pair "$pair" \
    '{after_phase:"phases/w3c-after",before_phase:"phases/w3c-before",exit_status:0,java_diagnostics:{after:$after,before:$before},metric_status:0,obi_metric_boundary_ids:["diagnostic-nondisclosure"],obi_metric_evidence:{pair:$pair,reference:"obi-metric-pairs/w3c.json"},pressure_correlation:null,receive_coordination_maps:null,result:"scenario-w3c.json",scenario:"w3c",scenario_reconciliation:null,status:"passed",stderr:"scenario-w3c.stderr.log"}' \
    >"$directory/scenario-w3c-status.json" || return 1
  chmod 0600 -- "$directory/scenario-w3c-status.json" || return 1
}

refresh_boundary() {
  local -r directory="$1"
  local transport="" pair_sha="" before_java_sha="" before_id_sha="" after_id_sha=""
  local after_java_sha="" header_java_sha="" w3c_status_sha="" report_sha=""
  local endpoint_sha="" header_sha="" transport_sha="" metrics_sha="" obi_log_sha="" java_log_sha=""

  IFS='-' read -r _ transport _ <<<"${directory##*/}"
  pair_sha="$(digest "$directory/obi-metric-pairs/w3c.json")" || return 1
  before_java_sha="$(digest "$directory/phases/w3c-before/java-diagnostics.txt")" || return 1
  before_id_sha="$(digest "$directory/phases/w3c-before/obi-identity.json")" || return 1
  after_id_sha="$(digest "$directory/phases/w3c-after/obi-identity.json")" || return 1
  after_java_sha="$(digest "$directory/phases/w3c-after/java-diagnostics.txt")" || return 1
  header_java_sha="$(digest "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt")" || return 1
  endpoint_sha="$(digest "$directory/${SURFACE_REFS[0]}")" || return 1
  header_sha="$(digest "$directory/${SURFACE_REFS[1]}")" || return 1
  transport_sha="$(digest "$directory/${SURFACE_REFS[2]}")" || return 1
  metrics_sha="$(digest "$directory/${SURFACE_REFS[3]}")" || return 1
  obi_log_sha="$(digest "$directory/${SURFACE_REFS[4]}")" || return 1
  java_log_sha="$(digest "$directory/${SURFACE_REFS[5]}")" || return 1
  w3c_status_sha="$(digest "$directory/scenario-w3c-status.json")" || return 1
  report_sha="$(digest "$directory/scenario-diagnostic-nondisclosure-status.json")" || return 1
  jq -cnS --arg transport "$transport" --arg pair "$pair_sha" --arg before_java "$before_java_sha" \
    --arg before_id "$before_id_sha" --arg after_id "$after_id_sha" --arg after_java "$after_java_sha" \
    --arg header_java "$header_java_sha" --arg endpoint "$endpoint_sha" --arg header "$header_sha" \
    --arg transport_sha "$transport_sha" --arg metrics "$metrics_sha" --arg obi_log "$obi_log_sha" \
    --arg java_log "$java_log_sha" --arg w3c_status "$w3c_status_sha" --arg report "$report_sha" '
    {boundaries:[{captures:[
      {id:"w3c",java_reference:"phases/w3c-after/java-diagnostics.txt",java_sha256:$after_java,kind:"pair",pair_reference:"obi-metric-pairs/w3c.json",pair_sha256:$pair,state:"captured"},
      {id:"java-w3c-before",kind:"java",reference:"phases/w3c-before/java-diagnostics.txt",sha256:$before_java,state:"captured"},
      {id:"w3c-before",identity_reference:"phases/w3c-before/obi-identity.json",identity_sha256:$before_id,kind:"phase",state:"captured"},
      {id:"w3c-after",identity_reference:"phases/w3c-after/obi-identity.json",identity_sha256:$after_id,kind:"phase",state:"captured"},
      {id:"java-w3c-after",kind:"java",reference:"phases/w3c-after/java-diagnostics.txt",sha256:$after_java,state:"captured"},
      {id:"java-diagnostic-nondisclosure-header",kind:"java",reference:"phases/diagnostic-nondisclosure-header/java-diagnostics.txt",sha256:$header_java,state:"captured"},
      {id:"diagnostic-java-endpoint",kind:"artifact",reference:"diagnostic-nondisclosure-java-endpoint.txt",sha256:$endpoint,state:"captured"},
      {id:"diagnostic-java-header",kind:"artifact",reference:"diagnostic-nondisclosure-java-header.txt",sha256:$header,state:"captured"},
      {id:"diagnostic-java-transport",kind:"artifact",reference:"diagnostic-nondisclosure-java-transport-configuration.txt",sha256:$transport_sha,state:"captured"},
      {id:"diagnostic-obi-metrics",kind:"artifact",reference:"diagnostic-nondisclosure-obi-metrics.prom",sha256:$metrics,state:"captured"},
      {id:"diagnostic-obi-log",kind:"artifact",reference:"diagnostic-nondisclosure-obi.log",sha256:$obi_log,state:"captured"},
      {id:"diagnostic-java-log",kind:"artifact",reference:"diagnostic-nondisclosure-java.log",sha256:$java_log,state:"captured"}],
      id:"diagnostic-nondisclosure",not_applicable_reason:null,ordinal:1,state:"complete",status_references:[{reference:"scenario-w3c-status.json",sha256:$w3c_status},{reference:"scenario-diagnostic-nondisclosure-status.json",sha256:$report}]}],
      schema:"obi-metric-boundary-index-v1",selection:{repeat_count:1,requested_transport:$transport,scenario:"diagnostic-nondisclosure",selected_transport:$transport}}' \
    >"$directory/obi-metric-boundary-index.json" || return 1
  chmod 0600 -- "$directory/obi-metric-boundary-index.json" || return 1
}

refresh_run_outer() {
  local -r directory="$1"
  local boundary_sha="" java="" metrics=""

  boundary_sha="$(digest "$directory/obi-metric-boundary-index.json")" || return 1
  printf 'obi-metric-boundary-index-frozen-v1:%s\n' "$boundary_sha" \
    >"$directory/.obi-metric-boundary-index.freeze" || return 1
  metrics="$(jq -cnS --arg sha "$boundary_sha" '{active_boundary_id:null,available:false,boundary_index_reference:"obi-metric-boundary-index.json",boundary_index_sha256:$sha,reason:"no-active-boundary",schema:"obi-java-remote-parent-terminal-metrics-v2",sealed:true}')" || return 1
  printf '%s\n' "$metrics" >"$directory/terminal-obi-metrics.json" || return 1
  java="$(jq -ce -s 'if length == 1 then .[0] else error("java") end' "$directory/terminal-java-diagnostics.json")" || return 1
  jq -nS --arg sha "$boundary_sha" --argjson java "$java" --argjson metrics "$metrics" \
    '{acceptance_evidence:false,acceptance_evidence_reason:"targeted-scenario",evidence_directory:"/private/results/fixture",exit_status:0,failure_line:0,failure_stage:"none",java_bridge_diagnostics:$java,java_bridge_diagnostics_reference:"terminal-java-diagnostics.json",obi_metric_boundary_index_reference:"obi-metric-boundary-index.json",obi_metric_boundary_index_sha256:$sha,obi_metric_evidence:$metrics,obi_metric_evidence_reference:"terminal-obi-metrics.json",schema:"obi-apache-java-https-run-status-v3",status:"passed"}' \
    >"$directory/run-status.json" || return 1
  chmod 0600 -- "$directory/.obi-metric-boundary-index.freeze" \
    "$directory/terminal-obi-metrics.json" "$directory/run-status.json" || return 1
}

reseal_cell() {
  local -r directory="$1"

  refresh_identities "$directory" || return 1
  refresh_terminal_java "$directory" || return 1
  refresh_w3c_status "$directory" || return 1
  refresh_report "$directory" || return 1
  refresh_boundary "$directory" || return 1
  refresh_run_outer "$directory"
}

expect_failure() {
  local -r label="$1"
  local -r root="$2"
  local -r expected_stage="${3:-}"
  local had_public=false
  local output=""

  if [[ -e "$root/public" || -L "$root/public" ]]; then had_public=true; fi
  if [[ -n "$expected_stage" ]]; then
    if output="$(run_verifier "$root" 2>&1)"; then
      printf 'mutation unexpectedly passed: %s\n' "$label" >&2
      return 1
    fi
    [[ "$output" == *"matrix cell failed verification: otel-getsockopt-info stage=$expected_stage"* ]] || {
      printf 'mutation reported the wrong validation stage: %s\n' "$label" >&2
      return 1
    }
  elif run_verifier "$root" >/dev/null 2>&1; then
    printf 'mutation unexpectedly passed: %s\n' "$label" >&2
    return 1
  fi
  if [[ "$had_public" == false && ( -e "$root/public" || -L "$root/public" ) ]]; then
    printf 'failed verification published public output: %s\n' "$label" >&2
    return 1
  fi
}

assert_validation_stage_source_contract() {
  local observed=""
  local expected=$'initialization\nenvironment\nsource_provenance\nofficial_agent_pin\nw3c_result\nw3c_result_digest\ndiagnostic_report\nw3c_status\nterminal_evidence\nrun_status_freeze\nboundary_authority\ncanary_manifest\ncanary_summary\nsurface_binding\nsurface_canary_scan\njava_endpoint\njava_header\ntransport_configuration\nmetrics\nobi_log\njava_log\npublic_authority\nnone'

  observed="$(sed -n '/^validate_cell() {/,/^}/p' "$VERIFIER" |
    sed -n 's/^[[:space:]]*CELL_VALIDATION_STAGE=\([a-z0-9_]*\)$/\1/p')" || return 1
  [[ "$observed" == "$expected" ]] || return 1
  grep -Fq 'die "matrix cell failed verification: ${CELL_IDS[$index]} stage=$CELL_VALIDATION_STAGE"' \
    "$VERIFIER"
}

run_verifier() {
  local -r root="$1"

  bash -c '
    test_verifier_path="$1"
    source "$test_verifier_path"
    validate_ci_identity() {
      [[ "${GITHUB_ACTIONS:-}" == true && "${CI:-}" == true &&
        "${GITHUB_REPOSITORY:-}" == example/obi &&
        "${GITHUB_WORKFLOW:-}" == "Java diagnostic nondisclosure matrix" &&
        "${MATRIX_REQUESTED_REF:-}" == "$HEAD_REVISION" &&
        "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_SHA:-}" == "$HEAD_REVISION" &&
        "${RUNNER_OS:-}" == Linux && "${RUNNER_ARCH:-}" == X64 ]]
      CI_REPOSITORY="$GITHUB_REPOSITORY"; CI_RUN_ID="$GITHUB_RUN_ID"; CI_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT"
      CI_RUN_URL="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT"
      CI_EVENT="$GITHUB_EVENT_NAME"; CI_RUNNER_OS="$RUNNER_OS"; CI_RUNNER_ARCH="$RUNNER_ARCH"
      CI_TRIGGER_SHA="$GITHUB_SHA"; CI_WORKFLOW_SHA="$GITHUB_WORKFLOW_SHA"; CI_WORKFLOW_REF="$GITHUB_WORKFLOW_REF"
      CI_WORKFLOW_BLOB_SHA256="$(sha256_file "$WORKFLOW_FILE")"
    }
    validate_repository_execution_bytes() {
      TRUSTED_COMPOSE_BLOB="$TEMP_DIR/test-compose-from-head"
      TRUSTED_RUNNER_BLOB="$TEMP_DIR/test-runner-from-head"
      TRUSTED_VERIFIER_BLOB="$TEMP_DIR/test-verifier-from-head"
      cp -- "$COMPOSE_FILE" "$TRUSTED_COMPOSE_BLOB"
      cp -- "$MATRIX_RUNNER" "$TRUSTED_RUNNER_BLOB"
      cp -- "$test_verifier_path" "$TRUSTED_VERIFIER_BLOB"
    }
    main "$2"
  ' _ "$VERIFIER" "$root"
}

copy_mutation() {
  local -r fixture="$1"
  local -r name="$2"
  local -r output_name="$3"
  local destination="$TEMP_DIR/$name"

  cp -a -- "$fixture" "$destination" || return 1
  rm -rf -- "$destination/public" || return 1
  printf -v "$output_name" '%s' "$destination"
}

refresh_public_outer() {
  local -r public="$1"
  local -r recompute_evidence_id="${2:-true}"
  local cells="" cells_sha="" revision="" evidence_id="" summary_sha=""

  cells="$(mktemp "$TEMP_DIR/public-cells.XXXXXX")" || return 1
  if [[ "$recompute_evidence_id" == true ]]; then
    jq -cS '.cells[]' "$public/matrix-summary.json" >"$cells" || return 1
    cells_sha="$(digest "$cells")" || return 1
    revision="$(jq -er '.revision' "$public/run-identity.json")" || return 1
    evidence_id="diagnostic-nondisclosure-${revision:0:12}-${cells_sha:0:16}"
    json_update_sorted "$public/matrix-summary.json" ".evidence_id=\"$evidence_id\"" || return 1
  else
    evidence_id="$(jq -er '.evidence_id' "$public/matrix-summary.json")" || return 1
  fi
  summary_sha="$(digest "$public/matrix-summary.json")" || return 1
  jq -cS --arg evidence_id "$evidence_id" --arg summary_sha "$summary_sha" \
    '.evidence_id=$evidence_id | .matrix_summary_sha256=$summary_sha' \
    "$public/run-identity.json" >"$cells" || return 1
  mv -fT -- "$cells" "$public/run-identity.json" || return 1
  chmod 0644 -- "$public/matrix-summary.json" "$public/run-identity.json" || return 1
  (
    cd -- "$public" || exit $?
    sha256sum README.md SANITIZATION.md matrix-summary.json run-identity.json verify.sh >SHA256SUMS
  ) || return 1
  chmod 0644 -- "$public/SHA256SUMS" || return 1
}

assert_workflow_contract() {
  local public_block="" partial_block="" projection_block="" paths="" retentions=""

  # shellcheck disable=SC2016
  grep -F 'MATRIX_REQUESTED_REF: ${{ github.event_name ==' "$WORKFLOW" >/dev/null || return 1
  # shellcheck disable=SC2016
  grep -F 'requested_type="$(git cat-file -t "$MATRIX_REQUESTED_REF")"' "$WORKFLOW" >/dev/null || return 1
  # shellcheck disable=SC2016
  grep -F '"$checked_out_commit" != "$MATRIX_REQUESTED_REF"' "$WORKFLOW" >/dev/null || return 1
  grep -F "if: steps.matrix.outcome == 'success'" "$WORKFLOW" >/dev/null || return 1
  # shellcheck disable=SC1003
  grep -F './examples/apache-java-https/scripts/verify-diagnostic-nondisclosure-matrix.sh \' "$WORKFLOW" >/dev/null || return 1
  public_block="$(awk '/- name: Upload verified public diagnostic nondisclosure matrix/{capture=1} capture{print} /retention-days: 14/{if (capture) exit}' "$WORKFLOW")" || return 1
  partial_block="$(awk '/- name: Upload non-publishable partial safe diagnostics/{capture=1} capture{print} /retention-days: 14/{if (capture) exit}' "$WORKFLOW")" || return 1
  projection_block="$(awk '/- name: Verify mutually exclusive upload projection/{capture=1} capture{print} /- name: Upload verified public diagnostic nondisclosure matrix/{if (capture) exit}' "$WORKFLOW")" || return 1
  [[ "$public_block" == *"steps.matrix.outcome == 'success'"* &&
    "$public_block" == *"steps.verify.outcome == 'success'"* &&
    "$public_block" == *"steps.projection.outcome == 'success'"* &&
    "$public_block" == *'diagnostic-nondisclosure-matrix/public'* ]] || return 1
  [[ "$partial_block" == *"steps.matrix.outcome != 'success'"* &&
    "$partial_block" == *"steps.projection.outcome == 'success'"* &&
    "$partial_block" == *'diagnostic-nondisclosure-matrix/partial-safe'* ]] || return 1
  # shellcheck disable=SC2016
  [[ "$projection_block" == *'VERIFY_OUTCOME: ${{ steps.verify.outcome }}'* &&
    "$projection_block" == *'if [[ "$VERIFY_OUTCOME" != success ]]'* &&
    "$projection_block" == *'will not be uploaded'* ]] || return 1
  paths="$(awk '$1 == "path:" {print $2}' "$WORKFLOW")" || return 1
  [[ "$paths" == $'${{\n${{' && "$public_block" == *'/public'* && "$partial_block" == *'/partial-safe'* ]] || return 1
  ! grep -Eq '^[[:space:]]*path:.*(/cells([/[:space:]]|$)|MATRIX_OUTPUT)' "$WORKFLOW" || return 1
  retentions="$(grep -c '^[[:space:]]*retention-days: 14$' "$WORKFLOW")" || return 1
  [[ "$retentions" == 2 ]] || return 1
  ! grep -F 'Upload quarantined' "$WORKFLOW" >/dev/null || return 1
}

assert_production_identity_and_byte_gates() {
  local sandbox="$TEMP_DIR/production-gates"
  local repository="$sandbox/repository"

  mkdir -p -- "$repository/.github/workflows" "$repository/examples/apache-java-https/scripts" \
    "$repository/examples/apache-java-https/java" || return 1
  cp -- "$VERIFIER" "$repository/examples/apache-java-https/scripts/verify-diagnostic-nondisclosure-matrix.sh" || return 1
  cp -- "$RUNNER" "$repository/examples/apache-java-https/scripts/run-diagnostic-nondisclosure-matrix.sh" || return 1
  cp -- "$DEMO_DIR/run.sh" "$repository/examples/apache-java-https/run.sh" || return 1
  cp -- "$DEMO_DIR/docker-compose.yml" "$repository/examples/apache-java-https/docker-compose.yml" || return 1
  cp -- "$DEMO_DIR/java/Dockerfile" "$repository/examples/apache-java-https/java/Dockerfile" || return 1
  cp -- "$WORKFLOW" "$repository/.github/workflows/java_diagnostic_nondisclosure.yml" || return 1
  chmod 0755 -- "$repository/examples/apache-java-https/run.sh" \
    "$repository/examples/apache-java-https/scripts/run-diagnostic-nondisclosure-matrix.sh" \
    "$repository/examples/apache-java-https/scripts/verify-diagnostic-nondisclosure-matrix.sh" || return 1
  chmod 0644 -- "$repository/examples/apache-java-https/docker-compose.yml" \
    "$repository/examples/apache-java-https/java/Dockerfile" \
    "$repository/.github/workflows/java_diagnostic_nondisclosure.yml" || return 1
  git -C "$repository" init -q || return 1
  git -C "$repository" add . || return 1
  git -C "$repository" -c user.name=test -c user.email=test@example.invalid \
    commit -q --no-gpg-sign -m fixture || return 1

  bash -c '
    source "$1"
    TEMP_DIR="$(mktemp -d)"; trap '\''rm -rf -- "$TEMP_DIR"'\'' EXIT
    HEAD_REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    export CI=true GITHUB_ACTIONS=true GITHUB_REPOSITORY=example/obi
    export GITHUB_WORKFLOW="Java diagnostic nondisclosure matrix"
    export GITHUB_WORKFLOW_REF="example/obi/.github/workflows/java_diagnostic_nondisclosure.yml@refs/heads/test"
    MATRIX_REQUESTED_REF="$HEAD_REVISION"; export MATRIX_REQUESTED_REF
    GITHUB_WORKFLOW_SHA="$HEAD_REVISION"; export GITHUB_WORKFLOW_SHA
    export GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    export GITHUB_SERVER_URL=https://github.com GITHUB_RUN_ID=42 GITHUB_RUN_ATTEMPT=3
    export GITHUB_EVENT_NAME=workflow_dispatch RUNNER_OS=Linux RUNNER_ARCH=X64
    validate_ci_identity
    [[ "$CI_TRIGGER_SHA" == "$GITHUB_SHA" && "$CI_WORKFLOW_SHA" == "$HEAD_REVISION" &&
      "$CI_WORKFLOW_REF" == "$GITHUB_WORKFLOW_REF" && "$CI_WORKFLOW_BLOB_SHA256" =~ ^[0-9a-f]{64}$ ]]
    GITHUB_EVENT_NAME=push
    if validate_ci_identity; then exit 1; fi
    GITHUB_EVENT_NAME=workflow_dispatch

    validate_repository_execution_bytes
    cmp -s -- "$TRUSTED_COMPOSE_BLOB" "$COMPOSE_FILE"
    cmp -s -- "$TRUSTED_RUNNER_BLOB" "$MATRIX_RUNNER"
    cmp -s -- "$TRUSTED_VERIFIER_BLOB" "$1"
    trusted_compose_sha="$(sha256_file "$TRUSTED_COMPOSE_BLOB")"
    chmod 0644 -- "$MATRIX_RUNNER"
    if validate_repository_execution_bytes; then exit 1; fi
    chmod 0755 -- "$MATRIX_RUNNER"
    printf "# dirty byte\n" >>"$COMPOSE_FILE"
    if validate_repository_execution_bytes; then exit 1; fi
    [[ "$(sha256_file "$TRUSTED_COMPOSE_BLOB")" == "$trusted_compose_sha" &&
      "$(sha256_file "$COMPOSE_FILE")" != "$trusted_compose_sha" ]]
  ' _ "$repository/examples/apache-java-https/scripts/verify-diagnostic-nondisclosure-matrix.sh" || return 1
}

assert_result_resolution_inventory() {
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    TEMP_DIR="$sandbox/work"
    mkdir -m 0700 -- "$TEMP_DIR"

    fd_count() {
      find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf ".\n" | wc -l
    }
    write_lock() {
      local -r root="$1" mode="${2:-0600}"
      (umask 077; : >"$root/.obi-metric-capture.lock")
      chmod "$mode" -- "$root/.obi-metric-capture.lock"
    }
    write_result() {
      mkdir -m 0755 -- "$1/$2"
    }
    expect_resolution_failure() {
      local output="" resolved_id=""
      if resolve_new_result "$1" "$2" output resolved_id "$3"; then
        return 1
      fi
    }

    root="$sandbox/new-lock-results"
    before="$sandbox/new-lock.before"; after="$sandbox/new-lock.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"
    write_lock "$root"
    write_result "$root" 20260818T120000Z-101
    snapshot_results "$after" "$root"
    result=""; result_identity=""; before_fds="$(fd_count)"
    resolve_new_result "$before" "$after" result result_identity "$root"
    after_fds="$(fd_count)"
    [[ "$result" == "$root/20260818T120000Z-101" &&
      "$result_identity" == "$(stat -Lc "%d:%i:%u:%a" -- "$result")" &&
      "$before_fds" == "$after_fds" ]]

    root="$sandbox/stable-lock-results"
    before="$sandbox/stable-lock.before"; after="$sandbox/stable-lock.after"
    mkdir -m 0755 -- "$root"
    write_lock "$root"
    snapshot_results "$before" "$root"
    write_result "$root" 20260818T120001Z-102
    snapshot_results "$after" "$root"
    result=""; result_identity=""
    resolve_new_result "$before" "$after" result result_identity "$root"
    [[ "$result" == "$root/20260818T120001Z-102" ]]

    root="$sandbox/no-result"
    before="$sandbox/no-result.before"; after="$sandbox/no-result.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; write_lock "$root"
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/two-results"
    before="$sandbox/two-results.before"; after="$sandbox/two-results.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; write_lock "$root"
    write_result "$root" 20260818T120002Z-103
    write_result "$root" 20260818T120003Z-104
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/unrelated-addition"
    before="$sandbox/unrelated.before"; after="$sandbox/unrelated.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; write_lock "$root"
    write_result "$root" 20260818T120004Z-105
    : >"$root/unexpected"
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/removal"
    before="$sandbox/removal.before"; after="$sandbox/removal.after"
    mkdir -m 0755 -- "$root"; write_lock "$root"
    write_result "$root" 20260818T120005Z-106
    snapshot_results "$before" "$root"
    rmdir -- "$root/20260818T120005Z-106"
    write_result "$root" 20260818T120006Z-107
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/wrong-mode-lock"
    before="$sandbox/wrong-mode.before"; after="$sandbox/wrong-mode.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; write_lock "$root" 0644
    write_result "$root" 20260818T120007Z-108
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/hardlink-lock"
    before="$sandbox/hardlink.before"; after="$sandbox/hardlink.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; write_lock "$root"
    ln -- "$root/.obi-metric-capture.lock" "$sandbox/hardlink-peer"
    write_result "$root" 20260818T120008Z-109
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/symlink-lock"
    before="$sandbox/symlink.before"; after="$sandbox/symlink.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; : >"$sandbox/symlink-target"
    ln -s -- "$sandbox/symlink-target" "$root/.obi-metric-capture.lock"
    write_result "$root" 20260818T120009Z-110
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/nonregular-lock"
    before="$sandbox/nonregular.before"; after="$sandbox/nonregular.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; mkdir -m 0700 -- "$root/.obi-metric-capture.lock"
    write_result "$root" 20260818T120010Z-111
    snapshot_results "$after" "$root"
    expect_resolution_failure "$before" "$after" "$root"

    root="$sandbox/replaced-lock"
    before="$sandbox/replaced.before"; after="$sandbox/replaced.after"
    snapshot_results "$before" "$root"
    mkdir -m 0755 -- "$root"; write_lock "$root"
    write_result "$root" 20260818T120011Z-112
    snapshot_results "$after" "$root"
    (umask 077; : >"$sandbox/replacement-lock")
    command mv -fT -- "$sandbox/replacement-lock" "$root/.obi-metric-capture.lock"
    before_fds="$(fd_count)"
    expect_resolution_failure "$before" "$after" "$root"
    after_fds="$(fd_count)"
    [[ "$before_fds" == "$after_fds" ]]

    run_lock_race() {
      local -r mode="$1"
      local -r root="$sandbox/lock-race-$mode"
      local -r before="$sandbox/lock-race-$mode.before"
      local -r after="$sandbox/lock-race-$mode.after"
      local -r lock="$root/.obi-metric-capture.lock"
      local -r alternate="$sandbox/lock-race-$mode.alternate"
      local -r saved="$sandbox/lock-race-$mode.saved"
      local -r displaced="$sandbox/lock-race-$mode.displaced"
      local -r first_marker="$sandbox/lock-race-$mode.first"
      local -r second_marker="$sandbox/lock-race-$mode.second"
      local output="" status=0 last=""

      snapshot_results "$before" "$root"
      mkdir -m 0755 -- "$root"
      write_lock "$root"
      write_result "$root" 20260818T120012Z-113
      (umask 077; : >"$alternate")
      snapshot_results "$after" "$root"

      stat() {
        local output="" last="${*: -1}"
        case "$mode:$last" in
          descriptor:"$lock")
            if [[ ! -e "$first_marker" ]]; then
              output="$(command stat "$@")" || return $?
              command mv -T -- "$lock" "$saved" || return $?
              command mv -T -- "$alternate" "$lock" || return $?
              : >"$first_marker" || return $?
              printf "%s\n" "$output"
              return $?
            fi
            ;;
          descriptor:/proc/self/fd/*)
            if [[ -e "$first_marker" && ! -e "$second_marker" ]]; then
              output="$(command stat "$@")" || return $?
              command mv -T -- "$lock" "$displaced" || return $?
              command mv -T -- "$saved" "$lock" || return $?
              : >"$second_marker" || return $?
              printf "%s\n" "$output"
              return $?
            fi
            ;;
          post:/proc/self/fd/*)
            if [[ ! -e "$first_marker" ]]; then
              output="$(command stat "$@")" || return $?
              command mv -T -- "$lock" "$saved" || return $?
              command mv -T -- "$alternate" "$lock" || return $?
              : >"$first_marker" || return $?
              printf "%s\n" "$output"
              return $?
            fi
            ;;
          symlink:/proc/self/fd/*)
            if [[ ! -e "$first_marker" ]]; then
              output="$(command stat "$@")" || return $?
              command mv -T -- "$lock" "$saved" || return $?
              ln -s -- "$saved" "$lock" || return $?
              : >"$first_marker" || return $?
              printf "%s\n" "$output"
              return $?
            fi
            ;;
        esac
        command stat "$@"
      }

      before_fds="$(fd_count)"
      if resolve_new_result "$before" "$after" output status "$root"; then
        unset -f stat
        return 1
      fi
      after_fds="$(fd_count)"
      unset -f stat
      [[ "$before_fds" == "$after_fds" && -e "$first_marker" ]] || return 1
      if [[ "$mode" == descriptor ]]; then
        [[ -e "$second_marker" && -f "$lock" && ! -L "$lock" ]] || return 1
      elif [[ "$mode" == symlink ]]; then
        [[ -L "$lock" ]] || return 1
      else
        [[ -f "$lock" && ! -L "$lock" ]] || return 1
      fi
    }

    run_lock_race descriptor
    run_lock_race post
    run_lock_race symlink
  ' _ "$RUNNER" || return 1
}

assert_library_and_failure_seams() {
  local forbidden_log_token=""

  # shellcheck disable=SC2016
  grep -F 'git -C "$REPO_ROOT" show "$workflow_sha:$workflow_relative"' "$VERIFIER" >/dev/null || return 1
  grep -F 'validate_repository_execution_bytes || die' "$VERIFIER" >/dev/null || return 1
  grep -F 'cleanup_temp_directory || return 1' "$VERIFIER" >/dev/null || return 1
  grep -F 'readonly MAX_OBI_LOG_BYTES=2097152' "$VERIFIER" >/dev/null || return 1
  grep -F 'readonly MAX_JAVA_LOG_BYTES=1048576' "$VERIFIER" >/dev/null || return 1
  [[ "$(grep -Fc -- \
    'elif .name == "obi_log" then .line_count <= 10000 and .size_bytes <= 2097152' \
    "$VERIFIER")" == 3 ]] || return 1
  for forbidden_log_token in \
    'index($0, "traceID=")' 'index($0, "spanID=")' \
    'index($0, " conn=")' 'index($0, " buf=")' \
    'index($0, " request=")' 'index($0, " response=")' \
    'index($0, " reqErr=")' 'index($0, " respErr=")'; do
    grep -F -- "$forbidden_log_token" "$VERIFIER" >/dev/null || return 1
  done
  bash -c 'source "$1"' _ "$RUNNER" >/dev/null || return 1
  bash -c 'source "$1"' _ "$VERIFIER" >/dev/null || return 1
  if "$RUNNER" >/dev/null 2>&1 || "$VERIFIER" >/dev/null 2>&1; then return 1; fi
  bash -c '
    source "$1"
    calls=0
    run_cell() { ((calls += 1)); return 19; }
    if run_cells_serial; then exit 1; fi
    [[ "$calls" == 1 ]]
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    capture="$sandbox/calls"; : >"$capture"
    matrix_execute() {
      [[ "$(umask)" == 0022 ]] || return 99
      printf "%s" "$COMPOSE_PROJECT_NAME" >>"$capture"
      printf "\t%s" "$@" >>"$capture"
      printf "\n" >>"$capture"
    }
    ordinal=0
    for id in "${CELL_IDS[@]}"; do
      ((ordinal += 1)); IFS=- read -r agent transport level <<<"$id"
      invoke_matrix_producer "project-$ordinal" "$sandbox/log-$ordinal" "$agent" "$transport" "$level"
      [[ "$(umask)" == 0077 ]]
      [[ -f "$sandbox/log-$ordinal" && ! -L "$sandbox/log-$ordinal" ]]
      [[ "$(stat -Lc "%u:%a:%h" -- "$sandbox/log-$ordinal")" == "$EUID:600:1" ]]
    done
    [[ "$(wc -l <"$capture")" == 8 ]]
    awk -F"\t" '\''
      BEGIN { agents[1]="otel"; agents[2]="otel"; agents[3]="otel"; agents[4]="otel"; agents[5]="splunk"; agents[6]="splunk"; agents[7]="splunk"; agents[8]="splunk";
        transports[1]="getsockopt"; transports[2]="getsockopt"; transports[3]="unix"; transports[4]="unix"; transports[5]="getsockopt"; transports[6]="getsockopt"; transports[7]="unix"; transports[8]="unix";
        levels[1]="info"; levels[2]="debug"; levels[3]="info"; levels[4]="debug"; levels[5]="info"; levels[6]="debug"; levels[7]="info"; levels[8]="debug" }
      { n=NR; if ($1 != "project-" n || $3 != "--agent" || $4 != agents[n] || $5 != "--transport" || $6 != transports[n] || $7 != "--tls" || $8 != "TLSv1.3" || $9 != "--obi-log-level" || $10 != levels[n] || $11 != "--scenario" || $12 != "diagnostic-nondisclosure") exit 1 }
    '\'' "$capture"
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    RAW_ROOT="$sandbox/raw"; mkdir -m 0700 "$RAW_ROOT"
    matrix_mktemp_directory() { path="${1/XXXXXX/ABC123}"; mkdir -m 0700 "$path"; printf "%s\n" "$path"; return 73; }
    if create_owned_candidate cell-otel-getsockopt-info 700; then exit 1; fi
    [[ -z "$ACTIVE_CANDIDATE" && ! -e "$RAW_ROOT/.cell-otel-getsockopt-info.ABC123" ]]
    candidate="$RAW_ROOT/.cell-otel-getsockopt-info.XYZ789"; mkdir -m 0700 "$candidate"
    ACTIVE_CANDIDATE="$candidate"; ACTIVE_CANDIDATE_STATE=provisional; ACTIVE_CANDIDATE_MODE=700
    normalize_active_candidate
    [[ -z "$ACTIVE_CANDIDATE" && ! -e "$candidate" ]]
    result="$sandbox/result"; mkdir -m 0755 "$result"; identity="$(stat -Lc "%d:%i:%u:%a" "$result")"
    result_directory_has_identity "$result" "$identity"
    mv "$result" "$sandbox/original-result"; mkdir -m 0755 "$result"
    if result_directory_has_identity "$result" "$identity"; then exit 1; fi
    jq -cn --arg directory "$result" '\''{evidence_directory:$directory}'\'' >"$result/run-status.json"
    result_status_names_directory "$result/run-status.json" "$result"
    jq -cn --arg directory "$sandbox/original-result" '\''{evidence_directory:$directory}'\'' >"$result/run-status.json"
    if result_status_names_directory "$result/run-status.json" "$result"; then exit 1; fi
    safe_reference phases/w3c-before/obi-metrics.prom
    if safe_reference ../escape || safe_reference /absolute || safe_reference phases//bad; then exit 1; fi
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    collect_references() { printf "%s\n" run-status.json >"$2"; }
    commit_candidate_directory() {
      command mv -T -- "$1" "$2" || return 1
      ACTIVE_CANDIDATE=""; ACTIVE_CANDIDATE_IDENTITY=""; ACTIVE_CANDIDATE_MODE=""
      ACTIVE_CANDIDATE_STATE=""; ACTIVE_CANDIDATE_DESTINATION=""
      ACTIVE_CANDIDATE_VALIDATOR=""; ACTIVE_CANDIDATE_VALIDATOR_ARG=""
    }
    prepare_copy_case() {
      local label="$1" mode="$2"
      RAW_ROOT="$sandbox/$label/raw"; TEMP_DIR="$sandbox/$label/tmp"
      result="$sandbox/$label/result"
      mkdir -m 0700 -p -- "$RAW_ROOT/cells" "$TEMP_DIR"
      mkdir -m 0755 -p -- "$result"
      jq -cn --arg directory "$result" '\''{evidence_directory:$directory}'\'' >"$result/run-status.json"
      chmod "$mode" -- "$result/run-status.json"
      result_identity="$(stat -Lc "%d:%i:%u:%a" -- "$result")"
      RAW_MATRIX_BYTES=0
    }
    normalize_failed_copy() {
      normalize_active_candidate
      [[ -z "$ACTIVE_CANDIDATE" && ! -e "$RAW_ROOT/cells/otel-getsockopt-info" ]]
    }
    fd_count() { find "/proc/$$/fd" -mindepth 1 -maxdepth 1 -printf "." | wc -c; }

    copy_definition="$(declare -f copy_pinned_reference)"
    for required in '\''exec {source_fd}< "$source"'\'' '\''/proc/self/fd/$source_fd'\'' \
      '\''pinned_path_has_identity "$source" "$fd_identity"'\'' \
      '\''source_digest="$(sha256_file "$fd_path")"'\'' \
      '\''install -m 0600 -- "$fd_path" "$destination"'\'' \
      '\''copied_digest="$(sha256_file "$destination")"'\'' \
      '\''post_digest="$(sha256_file "$fd_path")"'\'' '\''exec {source_fd}>&-'\''; do
      grep -F -- "$required" <<<"$copy_definition" >/dev/null
    done

    prepare_copy_case success-0600 0600
    for private_path in \
      .terminal-java-diagnostics.lock \
      .terminal-java-diagnostics-transition.lock \
      .terminal-java-diagnostics.freeze \
      .last-valid-java-diagnostics.json \
      .unexpected-private-canary; do
      printf "private-runtime-canary:%s\n" "$private_path" >"$result/$private_path"
      chmod 0600 -- "$result/$private_path"
    done
    before_fds="$(fd_count)"
    copy_raw_cell "$result" otel-getsockopt-info "$result_identity"
    after_fds="$(fd_count)"
    [[ "$before_fds" == "$after_fds" && "$(stat -Lc "%u:%a:%h" -- "$RAW_ROOT/cells/otel-getsockopt-info/run-status.json")" == "$EUID:600:1" ]]
    cmp -s -- "$result/run-status.json" "$RAW_ROOT/cells/otel-getsockopt-info/run-status.json"
    [[ "$(find "$RAW_ROOT/cells/otel-getsockopt-info" -mindepth 1 -printf "%P:%y\n")" == run-status.json:f ]]
    if grep -R -F -- private-runtime-canary "$RAW_ROOT/cells/otel-getsockopt-info"; then
      exit 1
    fi

    prepare_copy_case success-0644 0644
    copy_raw_cell "$result" otel-getsockopt-info "$result_identity"
    [[ "$(stat -Lc "%a:%h" -- "$RAW_ROOT/cells/otel-getsockopt-info/run-status.json")" == 600:1 ]]

    prepare_copy_case hardlink 0644
    ln -- "$result/run-status.json" "$result/hardlink-peer"
    before_fds="$(fd_count)"
    if copy_raw_cell "$result" otel-getsockopt-info "$result_identity"; then exit 1; fi
    after_fds="$(fd_count)"
    [[ "$before_fds" == "$after_fds" ]]; normalize_failed_copy

    prepare_copy_case wrong-mode 0666
    if copy_raw_cell "$result" otel-getsockopt-info "$result_identity"; then exit 1; fi
    normalize_failed_copy

    prepare_copy_case copied-digest 0644
    install() { command install "$@" || return; printf X >>"$5"; }
    if copy_raw_cell "$result" otel-getsockopt-info "$result_identity"; then exit 1; fi
    unset -f install; normalize_failed_copy

    prepare_copy_case same-inode-drift 0644
    TEST_SOURCE="$result/run-status.json"
    install() {
      command install "$@" || return
      printf X | dd of="$TEST_SOURCE" bs=1 seek=0 conv=notrunc status=none
    }
    if copy_raw_cell "$result" otel-getsockopt-info "$result_identity"; then exit 1; fi
    unset -f install; normalize_failed_copy

    prepare_copy_case pathname-replacement 0644
    TEST_SOURCE="$result/run-status.json"; TEST_REPLACEMENT="$result/replacement"
    install() {
      command install "$@" || return
      command cp -p -- "$TEST_SOURCE" "$TEST_REPLACEMENT" || return
      command mv -fT -- "$TEST_REPLACEMENT" "$TEST_SOURCE"
    }
    if copy_raw_cell "$result" otel-getsockopt-info "$result_identity"; then exit 1; fi
    unset -f install; normalize_failed_copy

    prepare_copy_case symlink-swap 0644
    TEST_SOURCE="$result/run-status.json"; TEST_ORIGINAL="$result/original"
    install() {
      command install "$@" || return
      command mv -- "$TEST_SOURCE" "$TEST_ORIGINAL" || return
      ln -s -- "$TEST_ORIGINAL" "$TEST_SOURCE"
    }
    if copy_raw_cell "$result" otel-getsockopt-info "$result_identity"; then exit 1; fi
    unset -f install; normalize_failed_copy

    prepare_copy_case digest-command 0644
    sha256_file() { return 77; }
    if copy_raw_cell "$result" otel-getsockopt-info "$result_identity"; then exit 1; fi
    normalize_failed_copy
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    runtime="$sandbox/runtime"; lock="$runtime/.diagnostic-nondisclosure-matrix.lock"
    mkdir -m 0700 "$runtime"; printf keep >"$sandbox/target"; ln -s "$sandbox/target" "$lock"
    if prepare_runtime_lock "$runtime" "$lock"; then exit 1; fi
    [[ "$(<"$sandbox/target")" == keep ]]
    rm "$lock"; prepare_runtime_lock "$runtime" "$lock"
    [[ -f "$lock" && ! -L "$lock" && "$(stat -Lc "%u:%a:%h" "$lock")" == "$EUID:600:1" ]]
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    RAW_ROOT="$sandbox/raw"; TEMP_DIR="$sandbox/tmp"
    mkdir -m 0700 -- "$RAW_ROOT" "$RAW_ROOT/cells" "$TEMP_DIR"
    MATRIX_FAILURE_STAGE=cell
    MATRIX_FAILURE_REASON=cell_failed
    CELL_STATUS[otel-getsockopt-info]=failed
    CELL_REASON[otel-getsockopt-info]=runner_exit
    write_partial_safe
    [[ -d "$RAW_ROOT/partial-safe" && ! -e "$RAW_ROOT/public" ]]
    [[ "$(find "$RAW_ROOT/partial-safe" -mindepth 1 -maxdepth 1 -printf "%f\\n" | LC_ALL=C sort)" == $'\''README.md\nSHA256SUMS\nmatrix-status.json\nverify.sh'\'' ]]
    bash "$RAW_ROOT/partial-safe/verify.sh" >/dev/null
    [[ "$(jq -r '\''.failure_stage + ":" + .failure_reason + ":" + .cells[0].status + ":" + .cells[0].failure_reason + ":" + .cells[1].status'\'' "$RAW_ROOT/partial-safe/matrix-status.json")" == cell:cell_failed:failed:runner_exit:not_run ]]
    cp -- "$RAW_ROOT/partial-safe/matrix-status.json" "$sandbox/original-status"
    jq -cS '\''.cells[0].failure_reason = "unknown_failure"'\'' "$sandbox/original-status" >"$RAW_ROOT/partial-safe/matrix-status.json"
    (cd -- "$RAW_ROOT/partial-safe" && sha256sum README.md matrix-status.json verify.sh >SHA256SUMS)
    chmod 0644 -- "$RAW_ROOT/partial-safe/SHA256SUMS" "$RAW_ROOT/partial-safe/matrix-status.json"
    if bash "$RAW_ROOT/partial-safe/verify.sh" >/dev/null 2>&1; then exit 1; fi
    jq -cS '\''.cells[1] = (.cells[1] | .status = "passed" | .failure_reason = "none")'\'' \
      "$sandbox/original-status" >"$RAW_ROOT/partial-safe/matrix-status.json"
    (cd -- "$RAW_ROOT/partial-safe" && sha256sum README.md matrix-status.json verify.sh >SHA256SUMS)
    chmod 0644 -- "$RAW_ROOT/partial-safe/SHA256SUMS" "$RAW_ROOT/partial-safe/matrix-status.json"
    if bash "$RAW_ROOT/partial-safe/verify.sh" >/dev/null 2>&1; then exit 1; fi
    jq -cS '\''.cells |= reverse'\'' "$RAW_ROOT/partial-safe/matrix-status.json" >"$sandbox/reordered"
    mv -fT -- "$sandbox/reordered" "$RAW_ROOT/partial-safe/matrix-status.json"
    chmod 0644 -- "$RAW_ROOT/partial-safe/matrix-status.json"
    (cd -- "$RAW_ROOT/partial-safe" && sha256sum README.md matrix-status.json verify.sh >SHA256SUMS)
    chmod 0644 -- "$RAW_ROOT/partial-safe/SHA256SUMS"
    if bash "$RAW_ROOT/partial-safe/verify.sh" >/dev/null 2>&1; then exit 1; fi
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    RAW_ROOT="$sandbox/setup"; mkdir -m 0700 -- "$RAW_ROOT" "$RAW_ROOT/cells"
    MATRIX_FAILURE_STAGE=setup; MATRIX_FAILURE_REASON=setup_failed
    write_partial_safe
    jq -e '\''.failure_stage == "setup" and .failure_reason == "setup_failed" and all(.cells[]; .status == "not_run" and .failure_reason == "matrix_incomplete")'\'' \
      "$RAW_ROOT/partial-safe/matrix-status.json" >/dev/null
    bash "$RAW_ROOT/partial-safe/verify.sh" >/dev/null

    RAW_ROOT="$sandbox/verification"; mkdir -m 0700 -- "$RAW_ROOT" "$RAW_ROOT/cells"
    MATRIX_FAILURE_STAGE=verification; MATRIX_FAILURE_REASON=verifier_failed
    for id in "${CELL_IDS[@]}"; do CELL_STATUS[$id]=passed; CELL_REASON[$id]=none; done
    write_partial_safe
    jq -e '\''.failure_stage == "verification" and .failure_reason == "verifier_failed" and all(.cells[]; .status == "passed" and .failure_reason == "none")'\'' \
      "$RAW_ROOT/partial-safe/matrix-status.json" >/dev/null
    bash "$RAW_ROOT/partial-safe/verify.sh" >/dev/null
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    TMPDIR="$sandbox"; export TMPDIR
    git() { return 0; }
    prepare_runtime_lock() { return 70; }
    if (main "$sandbox/pre-cell") >/dev/null 2>&1; then exit 1; fi
    [[ -d "$sandbox/pre-cell/partial-safe" && ! -e "$sandbox/pre-cell/public" ]]
    jq -e '\''.failure_stage == "setup" and .failure_reason == "setup_failed" and all(.cells[]; .status == "not_run")'\'' \
      "$sandbox/pre-cell/partial-safe/matrix-status.json" >/dev/null
    bash "$sandbox/pre-cell/partial-safe/verify.sh" >/dev/null
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    TMPDIR="$sandbox"; export TMPDIR
    git() { return 0; }
    prepare_runtime_lock() { return 0; }
    run_cells_serial() { for id in "${CELL_IDS[@]}"; do CELL_STATUS[$id]=passed; CELL_REASON[$id]=none; done; }
    invoke_matrix_verifier() { return 71; }
    if (main "$sandbox/verifier-failure") >/dev/null 2>&1; then exit 1; fi
    [[ -d "$sandbox/verifier-failure/partial-safe" && ! -e "$sandbox/verifier-failure/public" ]]
    jq -e '\''.failure_stage == "verification" and .failure_reason == "verifier_failed" and all(.cells[]; .status == "passed")'\'' \
      "$sandbox/verifier-failure/partial-safe/matrix-status.json" >/dev/null
    bash "$sandbox/verifier-failure/partial-safe/verify.sh" >/dev/null
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    TMPDIR="$sandbox"; export TMPDIR
    calls="$sandbox/cell-calls"; : >"$calls"
    git() { return 0; }
    prepare_runtime_lock() { return 0; }
    run_cell() {
      local ordinal="$1" id="${CELL_IDS[$((ordinal - 1))]}"
      printf "%s\n" "$ordinal" >>"$calls"
      if ((ordinal == 1)); then
        CELL_STATUS[$id]=passed; CELL_REASON[$id]=none; return 0
      fi
      CELL_STATUS[$id]=failed; CELL_REASON[$id]=runner_exit; return 71
    }
    if (main "$sandbox/cell-failure") >/dev/null 2>&1; then exit 1; fi
    [[ "$(tr "\n" ":" <"$calls")" == 1:2: ]]
    jq -e '\''
      .failure_stage == "cell" and .failure_reason == "cell_failed" and
      .cells[0].status == "passed" and .cells[0].failure_reason == "none" and
      .cells[1].status == "failed" and .cells[1].failure_reason == "runner_exit" and
      all(.cells[2:8][]; .status == "not_run" and .failure_reason == "matrix_incomplete")
    '\'' "$sandbox/cell-failure/partial-safe/matrix-status.json" >/dev/null
    bash "$sandbox/cell-failure/partial-safe/verify.sh" >/dev/null
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    TMPDIR="$sandbox"; export TMPDIR
    calls="$sandbox/cleanup-calls"; : >"$calls"
    git() { return 0; }
    prepare_runtime_lock() { return 0; }
    run_cell() {
      local ordinal="$1" id="${CELL_IDS[$((ordinal - 1))]}"
      printf "%s\n" "$ordinal" >>"$calls"
      CELL_STATUS[$id]=passed; CELL_REASON[$id]=none
    }
    cleanup_temp_directory() { return 79; }
    if (main "$sandbox/cleanup-failure") >/dev/null 2>&1; then exit 1; fi
    [[ "$(wc -l <"$calls")" == 8 ]]
    jq -e '\''
      .failure_stage == "runner_cleanup" and .failure_reason == "private_cleanup_failed" and
      all(.cells[]; .status == "passed" and .failure_reason == "none")
    '\'' "$sandbox/cleanup-failure/partial-safe/matrix-status.json" >/dev/null
    bash "$sandbox/cleanup-failure/partial-safe/verify.sh" >/dev/null
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    RAW_ROOT="$sandbox"; candidate="$(mktemp -d "$sandbox/.partial-safe.XXXXXX")"
    destination="$sandbox/partial-safe"; ACTIVE_CANDIDATE="$candidate"
    matrix_move() { command mv -T -- "$1" "$2"; return 73; }
    ACTIVE_CANDIDATE_IDENTITY="$(stat -Lc "%d:%i:%u:%a" "$candidate")"
    ACTIVE_CANDIDATE_MODE=700; ACTIVE_CANDIDATE_STATE=identified
    validate_partial_candidate() { [[ -d "$1" && ! -L "$1" ]]; }
    commit_candidate_directory "$candidate" "$destination" validate_partial_candidate
    [[ -d "$destination" && ! -e "$candidate" && -z "$ACTIVE_CANDIDATE" ]]
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    RAW_ROOT="$sandbox"; candidate="$(mktemp -d "$sandbox/.partial-safe.XXXXXX")"
    destination="$sandbox/partial-safe"; ACTIVE_CANDIDATE="$candidate"
    ACTIVE_CANDIDATE_IDENTITY="$(stat -Lc "%d:%i:%u:%a" "$candidate")"
    ACTIVE_CANDIDATE_MODE=700; ACTIVE_CANDIDATE_STATE=identified
    validate_partial_candidate() { [[ -d "$1" && ! -e "$1/unexpected" ]]; }
    matrix_move() { command mv -T -- "$1" "$2"; : >"$2/unexpected"; return 73; }
    if commit_candidate_directory "$candidate" "$destination" validate_partial_candidate; then exit 1; fi
    normalize_active_candidate
    [[ ! -e "$destination" && ! -L "$destination" && -z "$ACTIVE_CANDIDATE" ]]

    candidate="$(mktemp -d "$sandbox/.partial-safe.XXXXXX")"; destination="$sandbox/partial-safe"
    ACTIVE_CANDIDATE="$candidate"; ACTIVE_CANDIDATE_IDENTITY="$(stat -Lc "%d:%i:%u:%a" "$candidate")"
    ACTIVE_CANDIDATE_MODE=700; ACTIVE_CANDIDATE_STATE=identified
    foreign_source="$sandbox/foreign-source"; mkdir -m 0700 -- "$foreign_source"; : >"$foreign_source/foreign"
    matrix_move() { command mv -T -- "$1" "$2"; command rm -rf -- "$2"; command mv -T -- "$foreign_source" "$2"; return 74; }
    if commit_candidate_directory "$candidate" "$destination" validate_partial_candidate; then exit 1; fi
    if normalize_active_candidate; then exit 1; fi
    [[ -f "$destination/foreign" && -n "$ACTIVE_CANDIDATE" ]]
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''command rm -rf -- "$sandbox"'\'' EXIT
    TMPDIR="$sandbox"; export TMPDIR
    create_temp_directory
    rm() { command rm "$@"; return 75; }
    cleanup_temp_directory
    [[ -z "$TEMP_DIR" ]]
    create_temp_directory
    private="$TEMP_DIR"
    rm() { return 76; }
    if cleanup_temp_directory; then exit 1; fi
    [[ -d "$private" && "$TEMP_DIR" == "$private" ]]
  ' _ "$RUNNER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    MATRIX_ROOT="$sandbox"; candidate="$(mktemp -d "$sandbox/.public.XXXXXX")"
    chmod 0755 "$candidate"; PUBLIC_CANDIDATE="$candidate"
    PUBLIC_CANDIDATE_IDENTITY="$(stat -Lc "%d:%i:%u:%a" "$candidate")"
    PUBLIC_CANDIDATE_STATE=identified
    matrix_move() { command mv -T -- "$1" "$2"; return 74; }
    commit_public_candidate "$candidate"
    [[ -d "$sandbox/public" && ! -e "$candidate" && -z "$PUBLIC_CANDIDATE" ]]
  ' _ "$VERIFIER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    MATRIX_ROOT="$sandbox"
    matrix_mktemp_directory() { path="${1/XXXXXX/ABC123}"; mkdir -m 0700 "$path"; printf "%s\n" "$path"; return 73; }
    if create_public_candidate; then exit 1; fi
    [[ -z "$PUBLIC_CANDIDATE" && ! -e "$sandbox/.public.ABC123" ]]
    candidate="$sandbox/.public.XYZ789"; mkdir -m 0755 "$candidate"
    PUBLIC_CANDIDATE="$candidate"; PUBLIC_CANDIDATE_STATE=provisional
    normalize_public_candidate false
    [[ -z "$PUBLIC_CANDIDATE" && ! -e "$candidate" ]]
  ' _ "$VERIFIER" || return 1
  bash -c '
    source "$1"
    sandbox="$(mktemp -d)"; trap '\''rm -rf -- "$sandbox"'\'' EXIT
    TMPDIR="$sandbox"; export TMPDIR
    create_verifier_temp_directory
    matrix_remove_tree() { command rm -rf -- "$1"; return 75; }
    cleanup_temp_directory
    [[ -z "$TEMP_DIR" ]]
    create_verifier_temp_directory
    private="$TEMP_DIR"
    matrix_remove_tree() { return 76; }
    if cleanup_temp_directory; then exit 1; fi
    [[ -d "$private" && "$TEMP_DIR" == "$private" ]]
  ' _ "$VERIFIER" || return 1
  bash -c '
    source "$1"
    input="$(mktemp)"; trap '\''rm -f -- "$input"'\'' EXIT
    printf x >"$input"
    matrix_sha256_stream() { return 77; }
    if sha256_file "$input" >/dev/null; then exit 1; fi
  ' _ "$VERIFIER" || return 1
  bash -c '
    source "$1"
    if write_public_verify_script_v2 /dev/full >/dev/null 2>&1; then exit 1; fi
  ' _ "$VERIFIER" || return 1
}

main() {
  local fixture="" mutated="" id="" directory="" report_copy="" scenario_copy="" hostile_marker="" summary_sha="" revision=""
  trap cleanup EXIT
  export CI=true
  export GITHUB_ACTIONS=true
  export GITHUB_REPOSITORY=example/obi
  export GITHUB_WORKFLOW='Java diagnostic nondisclosure matrix'
  export GITHUB_WORKFLOW_REF='example/obi/.github/workflows/java_diagnostic_nondisclosure.yml@refs/heads/test'
  GITHUB_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"; export GITHUB_SHA
  MATRIX_REQUESTED_REF="$GITHUB_SHA"; export MATRIX_REQUESTED_REF
  GITHUB_WORKFLOW_SHA="$GITHUB_SHA"; export GITHUB_WORKFLOW_SHA
  export GITHUB_SERVER_URL=https://github.com
  export GITHUB_RUN_ID=123456789
  export GITHUB_RUN_ATTEMPT=2
  export GITHUB_EVENT_NAME=push
  export RUNNER_OS=Linux
  export RUNNER_ARCH=X64
  assert_validation_stage_source_contract || {
    printf '%s\n' 'validation-stage source contract failed' >&2
    return 1
  }
  TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/obi-i39-test.XXXXXX")"
  fixture="$TEMP_DIR/fixture"
  mkdir -m 0700 -- "$fixture" "$fixture/cells"
  for id in "${CELL_IDS[@]}"; do write_cell "$fixture" "$id"; done
  run_verifier "$fixture" >/dev/null
  run_verifier "$fixture" >/dev/null
  bash "$fixture/public/verify.sh" >/dev/null
  [[ "$(find "$fixture/public" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" == \
    $'README.md\nSANITIZATION.md\nSHA256SUMS\nmatrix-summary.json\nrun-identity.json\nverify.sh' ]]
  grep -F 'bash verify.sh' "$fixture/public/README.md" >/dev/null
  jq -e '
    .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
    all(.cells[]; (.canary_count >= 6) and (.canary_bytes >= 1) and
      (.canary_source_sha256 | test("^[0-9a-f]{64}$")) and
      (.surfaces | length == 6) and all(.surfaces[]; .canary_match_count == 0 and .schema_valid == true and (has("reference") | not)))
  ' "$fixture/public/matrix-summary.json" >/dev/null
  jq -e '
    .official_agents.otel.version == "2.28.1" and .official_agents.splunk.version == "2.28.0" and
    .runtime_contract == {java:{attestation:"source_configured",distribution:"temurin",version:"21"},tls_protocol:"TLSv1.3"} and
    .runner == {arch:"X64",os:"Linux"} and
    .bridge_artifacts == {obi_java_agent_sha256:("1"*64),obi_otel_extension_sha256:("2"*64)} and
    .workflow.event == "push" and .workflow.name == "Java diagnostic nondisclosure matrix" and
    .workflow.path == ".github/workflows/java_diagnostic_nondisclosure.yml" and .workflow.repository == "example/obi" and
    .workflow.run_attempt == "2" and .workflow.run_id == "123456789" and
    .workflow.run_url == "https://github.com/example/obi/actions/runs/123456789/attempts/2" and
    .workflow.trigger_sha == .revision and .workflow.workflow_sha == .revision and
    (.workflow.workflow_blob_sha256 | test("^[0-9a-f]{64}$"))
  ' "$fixture/public/run-identity.json" >/dev/null
  if grep -R -E 'scenario-w3c|diagnostic-nondisclosure-java|window|/private|/tmp/' \
    "$fixture/public" >/dev/null; then
    return 1
  fi

  copy_mutation "$fixture" obi-log-dedicated-cap mutated
  directory="$mutated/cells/otel-getsockopt-debug"
  write_debug_log_volume "$directory/${SURFACE_REFS[4]}" getsockopt 6000 180
  chmod 0600 -- "$directory/${SURFACE_REFS[4]}"
  [[ "$(stat -Lc '%s' -- "$directory/${SURFACE_REFS[4]}")" -gt 1048576 &&
    "$(stat -Lc '%s' -- "$directory/${SURFACE_REFS[4]}")" -le 2097152 ]]
  reseal_cell "$directory"
  run_verifier "$mutated" >/dev/null
  bash "$mutated/public/verify.sh" >/dev/null

  copy_mutation "$fixture" obi-log-overflow mutated
  directory="$mutated/cells/otel-getsockopt-debug"
  write_debug_log_volume "$directory/${SURFACE_REFS[4]}" getsockopt 9500 220
  chmod 0600 -- "$directory/${SURFACE_REFS[4]}"
  [[ "$(stat -Lc '%s' -- "$directory/${SURFACE_REFS[4]}")" -gt 2097152 ]]
  reseal_cell "$directory"
  expect_failure obi-log-dedicated-cap-overflow "$mutated"

  copy_mutation "$fixture" java-log-overflow mutated
  directory="$mutated/cells/otel-getsockopt-info"
  write_java_log_volume "$directory/${SURFACE_REFS[5]}" 6000 180
  chmod 0600 -- "$directory/${SURFACE_REFS[5]}"
  [[ "$(stat -Lc '%s' -- "$directory/${SURFACE_REFS[5]}")" -gt 1048576 ]]
  reseal_cell "$directory"
  expect_failure java-log-generic-cap-overflow "$mutated"

  copy_mutation "$fixture" obi-log-private-field mutated
  directory="$mutated/cells/otel-getsockopt-debug"
  printf '%s\n' 'ts level=DEBUG msg="unsafe" reqErr=non-canary-private-data' \
    >>"$directory/${SURFACE_REFS[4]}"
  reseal_cell "$directory"
  expect_failure obi-log-private-field "$mutated"

  copy_mutation "$fixture" fixed-canary mutated
  directory="$mutated/cells/otel-getsockopt-info"
  printf '%s\n' 'issue39privatebodyvalue' >>"$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[5]}"
  reseal_cell "$directory"
  expect_failure fixed-canary-injection "$mutated"

  copy_mutation "$fixture" dynamic-canary mutated
  directory="$mutated/cells/otel-getsockopt-info"
  printf '%s\n' 'dynamic-marker-a' >>"$directory/${SURFACE_REFS[3]}"
  reseal_cell "$directory"
  expect_failure dynamic-w3c-canary-injection "$mutated"

  copy_mutation "$fixture" changed-id-canary mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c.json" '.cases[0].request.w3c_trace_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
  printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >>"$directory/${SURFACE_REFS[0]}"
  reseal_cell "$directory"
  expect_failure same-length-w3c-id-canary "$mutated"

  copy_mutation "$fixture" w3c-topology mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c.json" \
    '.cases[1].trace.spans[] |= if .service_name == "java-backend" then .parent_span_id="8888888888888888" else . end'
  reseal_cell "$directory"
  expect_failure w3c-topology-rewire "$mutated"

  copy_mutation "$fixture" w3c-standard-parent-precedence mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c.json" \
    '.cases[0].trace.spans[] |= if .service_name == "java-backend" then .parent_span_id="4444444444444444" else . end'
  reseal_cell "$directory"
  expect_failure w3c-standard-parent-precedence-rewire "$mutated"

  copy_mutation "$fixture" w3c-java-remote-bits mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c.json" \
    '.cases[0].trace.spans[] |= if .service_name == "java-backend" then .flags=1 else . end'
  reseal_cell "$directory"
  expect_failure w3c-java-missing-remote-parent-bits "$mutated"

  copy_mutation "$fixture" w3c-java-low-byte mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c.json" \
    '.cases[0].trace.spans[] |= if .service_name == "java-backend" then .flags=770 else . end'
  reseal_cell "$directory"
  expect_failure w3c-java-wrong-trace-flags "$mutated"

  copy_mutation "$fixture" w3c-malformed-java-remote-bits mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c.json" \
    '.cases[1].trace.spans[] |= if .service_name == "java-backend" then .flags=1 else . end'
  reseal_cell "$directory"
  expect_failure w3c-malformed-java-missing-remote-parent-bits "$mutated"

  copy_mutation "$fixture" w3c-malformed-java-low-byte mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c.json" \
    '.cases[1].trace.spans[] |= if .service_name == "java-backend" then .flags=770 else . end'
  reseal_cell "$directory"
  expect_failure w3c-malformed-java-wrong-trace-flags "$mutated"

  copy_mutation "$fixture" pair-delta mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update "$directory/obi-metric-pairs/w3c.json" '.series[0].delta="2"'
  refresh_w3c_status "$directory"; refresh_boundary "$directory"; refresh_run_outer "$directory"
  expect_failure recomputed-pair-delta "$mutated"

  copy_mutation "$fixture" metric-labels mutated
  directory="$mutated/cells/otel-getsockopt-info"
  printf '%s\n' 'obi_java_remote_parent_operations_total{transport="getsockopt",transport="getsockopt",operation="availability",status="valid"} 1' \
    >"$directory/phases/w3c-before/obi-metrics.prom"
  reseal_cell "$directory"
  expect_failure duplicate-metric-label "$mutated"

  copy_mutation "$fixture" metric-tuple mutated
  directory="$mutated/cells/otel-getsockopt-info"
  printf '%s\n' 'obi_java_remote_parent_operations_total{operation="availability",status="valid",transport="getsockopt"} 1' \
    >>"$directory/phases/w3c-before/obi-metrics.prom"
  reseal_cell "$directory"
  expect_failure duplicate-metric-tuple "$mutated"

  copy_mutation "$fixture" identity mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/phases/w3c-before/obi-identity.json" '.host_pid="01"'
  refresh_boundary "$directory"; refresh_run_outer "$directory"
  expect_failure noncanonical-process-identity "$mutated"

  copy_mutation "$fixture" header-mismatch mutated
  directory="$mutated/cells/otel-getsockopt-info"
  sed 's/^cfg_on=0/cfg_on=1/' "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt" \
    >"$TEMP_DIR/header" && mv -fT -- "$TEMP_DIR/header" "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt"
  chmod 0600 -- "$directory/phases/diagnostic-nondisclosure-header/java-diagnostics.txt"
  refresh_terminal_java "$directory"; refresh_boundary "$directory"; refresh_run_outer "$directory"
  expect_failure diagnostic-header-mismatch "$mutated"

  copy_mutation "$fixture" terminal-extra-phase mutated
  directory="$mutated/cells/otel-getsockopt-info"
  mv -- "$directory/phases/final" "$directory/phases/unbound-terminal"
  json_update_sorted "$directory/terminal-java-diagnostics.json" \
    '.phase="unbound-terminal" | .reference="phases/unbound-terminal/java-diagnostics.txt"'
  refresh_run_outer "$directory"
  expect_failure terminal-unbound-extra-phase "$mutated"

  copy_mutation "$fixture" duplicate-terminal-java mutated
  directory="$mutated/cells/otel-getsockopt-info"
  report_copy="$(<"$directory/terminal-java-diagnostics.json")"
  printf '%s %s\n' "$report_copy" "$report_copy" \
    >"$directory/terminal-java-diagnostics.json"
  expect_failure duplicate-terminal-java-object "$mutated"

  copy_mutation "$fixture" terminal-java-extra-key mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/terminal-java-diagnostics.json" '.extra=true'
  refresh_run_outer "$directory"
  expect_failure terminal-java-closed-keyset "$mutated" terminal_evidence

  copy_mutation "$fixture" terminal-java-snapshot mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/terminal-java-diagnostics.json" \
    '.snapshot |= sub("^cfg_on=0";"cfg_on=1") | .counters.cfg_on="1"'
  refresh_run_outer "$directory"
  expect_failure terminal-java-reference-snapshot "$mutated"

  copy_mutation "$fixture" terminal-java-counters mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/terminal-java-diagnostics.json" \
    '.counters.cfg_on="1"'
  refresh_run_outer "$directory"
  expect_failure terminal-java-reconstructed-counters "$mutated"

  copy_mutation "$fixture" reference-rewire mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/obi-metric-boundary-index.json" \
    '.boundaries[0].captures[1].reference="phases/w3c-after/java-diagnostics.txt"'
  refresh_run_outer "$directory"
  expect_failure exact-journal-reference-rewire "$mutated"

  copy_mutation "$fixture" duplicate-report mutated
  directory="$mutated/cells/otel-getsockopt-info"
  report_copy="$(<"$directory/scenario-diagnostic-nondisclosure-status.json")"
  printf '%s\n%s\n' "$report_copy" "$report_copy" >"$directory/scenario-diagnostic-nondisclosure-status.json"
  refresh_boundary "$directory"; refresh_run_outer "$directory"
  expect_failure duplicate-report-object "$mutated"

  copy_mutation "$fixture" duplicate-w3c mutated
  directory="$mutated/cells/otel-getsockopt-info"
  scenario_copy="$(<"$directory/scenario-w3c.json")"
  printf '%s\n%s\n' "$scenario_copy" "$scenario_copy" >"$directory/scenario-w3c.json"
  refresh_report "$directory"; refresh_boundary "$directory"; refresh_run_outer "$directory"
  expect_failure duplicate-w3c-object "$mutated"

  copy_mutation "$fixture" failed-status mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-w3c-status.json" '.status="failed" | .exit_status=1'
  refresh_boundary "$directory"; refresh_run_outer "$directory"
  expect_failure failed-w3c-status "$mutated"

  copy_mutation "$fixture" failed-diagnostic-report-status mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/scenario-diagnostic-nondisclosure-status.json" '.status="failed"'
  refresh_boundary "$directory"; refresh_run_outer "$directory"
  expect_failure failed-diagnostic-report-status "$mutated"

  copy_mutation "$fixture" w3c-status-digest mutated
  directory="$mutated/cells/otel-getsockopt-info"
  jq '.' "$directory/scenario-w3c-status.json" >"$TEMP_DIR/w3c-status-pretty"
  mv -fT -- "$TEMP_DIR/w3c-status-pretty" "$directory/scenario-w3c-status.json"
  chmod 0600 -- "$directory/scenario-w3c-status.json"
  expect_failure w3c-status-journal-digest "$mutated"

  copy_mutation "$fixture" run-status-state mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/run-status.json" '.status="failed"'
  expect_failure run-status-not-passed "$mutated"

  copy_mutation "$fixture" run-status-exit mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/run-status.json" '.exit_status=1'
  expect_failure run-status-nonzero-exit "$mutated"

  copy_mutation "$fixture" run-status-failure-location mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/run-status.json" '.failure_stage="scenario:w3c" | .failure_line=123'
  expect_failure run-status-failure-stage-line "$mutated"

  copy_mutation "$fixture" run-status-acceptance mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/run-status.json" '.acceptance_evidence=true'
  expect_failure run-status-acceptance-flag "$mutated"

  copy_mutation "$fixture" run-status-acceptance-reason mutated
  directory="$mutated/cells/otel-getsockopt-info"
  json_update_sorted "$directory/run-status.json" '.acceptance_evidence_reason="full-scenario"'
  expect_failure run-status-acceptance-reason "$mutated"

  copy_mutation "$fixture" unexpected-stderr mutated
  printf '%s\n' 'unexpected private diagnostic' >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure nonempty-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-extra-line mutated
  printf '%s\n' ' Container obi-apache-java-https-i39-fixture-otel-getsockopt-info-scenario-run-0123456789ab Started ' \
    >>"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure extra-w3c-stderr-line "$mutated"

  copy_mutation "$fixture" stderr-wrong-project mutated
  printf ' Container %s-scenario-run-0123456789ab Creating \n Container %s-scenario-run-0123456789ab Created \n' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-debug \
    obi-apache-java-https-i39-fixture-otel-getsockopt-debug \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure wrong-project-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-mismatched-suffix mutated
  printf ' Container %s-scenario-run-0123456789ab Creating \n Container %s-scenario-run-fedcba987654 Created \n' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure mismatched-container-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-invalid-suffix mutated
  printf ' Container %s-scenario-run-0123456789ag Creating \n Container %s-scenario-run-0123456789ag Created \n' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure invalid-container-suffix-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-long-suffix mutated
  printf ' Container %s-scenario-run-0123456789abc Creating \n Container %s-scenario-run-0123456789abc Created \n' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure long-container-suffix-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-wrong-state mutated
  printf ' Container %s-scenario-run-0123456789ab Created \n Container %s-scenario-run-0123456789ab Creating \n' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure wrong-order-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-missing-final-lf mutated
  printf ' Container %s-scenario-run-0123456789ab Creating \n Container %s-scenario-run-0123456789ab Created ' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure missing-final-lf-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-missing-trailing-spaces mutated
  printf ' Container %s-scenario-run-0123456789ab Creating\n Container %s-scenario-run-0123456789ab Created\n' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure missing-trailing-spaces-w3c-stderr "$mutated"

  copy_mutation "$fixture" stderr-mixed-compose-renderings mutated
  printf ' Container %s-scenario-run-0123456789ab  Creating\n Container %s-scenario-run-0123456789ab Created \n' \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    obi-apache-java-https-i39-fixture-otel-getsockopt-info \
    >"$mutated/cells/otel-getsockopt-info/scenario-w3c.stderr.log"
  expect_failure mixed-compose-renderings-w3c-stderr "$mutated" w3c_status

  copy_mutation "$fixture" status-as-artifact mutated
  directory="$mutated/cells/otel-getsockopt-info"
  jq -cS '.boundaries[0].captures[6].reference="scenario-diagnostic-nondisclosure-status.json"' \
    "$directory/obi-metric-boundary-index.json" >"$TEMP_DIR/index" &&
    mv -fT -- "$TEMP_DIR/index" "$directory/obi-metric-boundary-index.json"
  chmod 0600 -- "$directory/obi-metric-boundary-index.json"
  refresh_run_outer "$directory"
  expect_failure status-artifact-alias "$mutated"

  copy_mutation "$fixture" source mutated
  printf 'x' >>"$mutated/cells/otel-getsockopt-info/source-tree.manifest"
  expect_failure source-drift "$mutated"

  copy_mutation "$fixture" freeze mutated
  printf '%s\n' 'obi-metric-boundary-index-frozen-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"$mutated/cells/otel-getsockopt-info/.obi-metric-boundary-index.freeze"
  expect_failure freeze-digest-drift "$mutated"

  copy_mutation "$fixture" missing mutated
  rm -- "$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[0]}"
  expect_failure missing-surface "$mutated"

  copy_mutation "$fixture" mode mutated
  chmod 0644 -- "$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[0]}"
  expect_failure raw-file-mode "$mutated"

  copy_mutation "$fixture" hardlink mutated
  rm -- "$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[1]}"
  ln -- "$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[0]}" \
    "$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[1]}"
  expect_failure raw-hardlink "$mutated"

  copy_mutation "$fixture" type mutated
  rm -- "$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[0]}"
  mkdir -- "$mutated/cells/otel-getsockopt-info/${SURFACE_REFS[0]}"
  expect_failure reserved-path-type "$mutated"

  copy_mutation "$fixture" residue mutated
  : >"$mutated/.private-residue"
  expect_failure raw-residue "$mutated"

  mutated="$TEMP_DIR/public-obi-dedicated-cap"; cp -a -- "$fixture" "$mutated"
  json_update_sorted "$mutated/public/matrix-summary.json" \
    '.cells[0].surfaces[4].size_bytes = 1048577'
  refresh_public_outer "$mutated/public"
  bash "$mutated/public/verify.sh" >/dev/null

  mutated="$TEMP_DIR/public-obi-overflow"; cp -a -- "$fixture" "$mutated"
  json_update_sorted "$mutated/public/matrix-summary.json" \
    '.cells[0].surfaces[4].size_bytes = 2097153'
  refresh_public_outer "$mutated/public"
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-obi-log-dedicated-cap-overflow "$mutated"

  mutated="$TEMP_DIR/public-java-overflow"; cp -a -- "$fixture" "$mutated"
  json_update_sorted "$mutated/public/matrix-summary.json" \
    '.cells[0].surfaces[5].size_bytes = 1048577'
  refresh_public_outer "$mutated/public"
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-java-log-generic-cap-overflow "$mutated"

  mutated="$TEMP_DIR/public-extra"; cp -a -- "$fixture" "$mutated"
  : >"$mutated/public/extra.txt"
  expect_failure public-closure "$mutated"

  mutated="$TEMP_DIR/public-checksum"; cp -a -- "$fixture" "$mutated"
  sed '/verify\.sh$/d' "$mutated/public/SHA256SUMS" >"$TEMP_DIR/checksums"
  mv -fT -- "$TEMP_DIR/checksums" "$mutated/public/SHA256SUMS"
  chmod 0644 -- "$mutated/public/SHA256SUMS"
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-checksum-omission "$mutated"

  mutated="$TEMP_DIR/public-hostile"; cp -a -- "$fixture" "$mutated"
  hostile_marker="$TEMP_DIR/hostile-executed"
  printf '#!/usr/bin/env bash\ntouch %q\nexit 0\n' "$hostile_marker" >"$mutated/public/verify.sh"
  chmod 0644 -- "$mutated/public/verify.sh"
  (
    cd -- "$mutated/public"
    sha256sum README.md SANITIZATION.md matrix-summary.json run-identity.json verify.sh >SHA256SUMS
  )
  chmod 0644 -- "$mutated/public/SHA256SUMS"
  expect_failure hostile-public-verifier "$mutated"
  [[ ! -e "$hostile_marker" && ! -L "$hostile_marker" ]]

  mutated="$TEMP_DIR/public-pin-digest"; cp -a -- "$fixture" "$mutated"
  jq -cS '.official_agent_pin_sha256.otel=("0"*64)' "$mutated/public/run-identity.json" \
    >"$TEMP_DIR/public-pin-identity.tmp"
  mv -fT -- "$TEMP_DIR/public-pin-identity.tmp" "$mutated/public/run-identity.json"
  chmod 0644 -- "$mutated/public/run-identity.json"
  (
    cd -- "$mutated/public"
    sha256sum README.md SANITIZATION.md matrix-summary.json run-identity.json verify.sh >SHA256SUMS
  )
  chmod 0644 -- "$mutated/public/SHA256SUMS"
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-pin-digest "$mutated"

  mutated="$TEMP_DIR/public-surface-set"; cp -a -- "$fixture" "$mutated"
  jq -cS '.cells[0].surface_set_sha256=("0"*64)' "$mutated/public/matrix-summary.json" \
    >"$TEMP_DIR/public-summary.tmp"
  mv -fT -- "$TEMP_DIR/public-summary.tmp" "$mutated/public/matrix-summary.json"
  chmod 0644 -- "$mutated/public/matrix-summary.json"
  refresh_public_outer "$mutated/public"
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-surface-set-relation "$mutated"

  mutated="$TEMP_DIR/public-freeze-relation"; cp -a -- "$fixture" "$mutated"
  jq -cS '.cells[0].authority.boundary_freeze.sha256=("0"*64)' "$mutated/public/matrix-summary.json" \
    >"$TEMP_DIR/public-summary.tmp"
  mv -fT -- "$TEMP_DIR/public-summary.tmp" "$mutated/public/matrix-summary.json"
  chmod 0644 -- "$mutated/public/matrix-summary.json"
  refresh_public_outer "$mutated/public"
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-freeze-relation "$mutated"

  mutated="$TEMP_DIR/public-patch-relation"; cp -a -- "$fixture" "$mutated"
  jq -cS '.patch_identity_sha256=("0"*64)' "$mutated/public/run-identity.json" \
    >"$TEMP_DIR/public-identity.tmp"
  mv -fT -- "$TEMP_DIR/public-identity.tmp" "$mutated/public/run-identity.json"
  chmod 0644 -- "$mutated/public/run-identity.json"
  refresh_public_outer "$mutated/public" false
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-patch-relation "$mutated"

  mutated="$TEMP_DIR/public-evidence-id"; cp -a -- "$fixture" "$mutated"
  revision="$(jq -er '.revision' "$mutated/public/run-identity.json")"
  jq -cS --arg evidence_id "diagnostic-nondisclosure-${revision:0:12}-0000000000000000" \
    '.evidence_id=$evidence_id' "$mutated/public/matrix-summary.json" >"$TEMP_DIR/public-summary.tmp"
  mv -fT -- "$TEMP_DIR/public-summary.tmp" "$mutated/public/matrix-summary.json"
  chmod 0644 -- "$mutated/public/matrix-summary.json"
  refresh_public_outer "$mutated/public" false
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-evidence-id-relation "$mutated"

  mutated="$TEMP_DIR/public-derived-schema"; cp -a -- "$fixture" "$mutated"
  jq -cS 'del(.cells[0].surfaces[0])' "$mutated/public/matrix-summary.json" >"$TEMP_DIR/public-summary.tmp"
  mv -fT -- "$TEMP_DIR/public-summary.tmp" "$mutated/public/matrix-summary.json"
  summary_sha="$(digest "$mutated/public/matrix-summary.json")"
  jq -cS --arg sha "$summary_sha" '.matrix_summary_sha256=$sha' \
    "$mutated/public/run-identity.json" >"$TEMP_DIR/public-identity.tmp"
  mv -fT -- "$TEMP_DIR/public-identity.tmp" "$mutated/public/run-identity.json"
  chmod 0644 -- "$mutated/public/matrix-summary.json" "$mutated/public/run-identity.json"
  (
    cd -- "$mutated/public"
    sha256sum README.md SANITIZATION.md matrix-summary.json run-identity.json verify.sh >SHA256SUMS
  )
  chmod 0644 -- "$mutated/public/SHA256SUMS"
  if bash "$mutated/public/verify.sh" >/dev/null 2>&1; then return 1; fi
  expect_failure public-derived-schema "$mutated"

  assert_library_and_failure_seams
  assert_result_resolution_inventory
  assert_workflow_contract
  assert_production_identity_and_byte_gates

  printf 'diagnostic nondisclosure matrix verifier tests passed\n'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
