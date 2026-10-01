#!/usr/bin/env bash
set -Eeuo pipefail

readonly OBI_BASE_URL="${OBI_BASE_URL:-http://127.0.0.1:8090/obi}"
readonly TEMPO_BASE_URL="${TEMPO_BASE_URL:-http://127.0.0.1:8090/tempo}"
readonly CHECKOUT_URL="${CHECKOUT_URL:-http://127.0.0.1:18081/checkout}"
readonly RULE_ID="trace-chain-smoke-$$"
readonly ATTEMPTS=30
readonly TRACE_COUNT=3

tmpdir=""
rule_created=false

log() {
    printf 'trace-chain-smoke: %s\n' "$*" >&2
}

cleanup() {
    if [[ "$rule_created" == "true" ]]; then
        curl --silent --show-error --request DELETE \
            "$OBI_BASE_URL/v1/dynamic-instrumentation/rules/$RULE_ID" >/dev/null || true
    fi
    if [[ -n "${tmpdir:-}" && -d "$tmpdir" ]]; then
        rm -rf -- "$tmpdir"
    fi
}

on_error() {
    log "failed at line $1"
}

trap 'on_error "$LINENO"' ERR
trap cleanup EXIT

check_dependencies() {
    local -a missing=()
    local command_name=""

    for command_name in curl jq tr; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            missing+=("$command_name")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "missing required commands: ${missing[*]}"
        return 1
    fi
}

active_span_name() {
    local -r probes="$1"
    local -r function_name="$2"

    jq -er --arg function_name "$function_name" \
        '[.probes[] | select(.function == $function_name and .status == "attached")][0].span_name' \
        <<<"$probes" 2>/dev/null
}

ensure_java_probes() {
    local probes=""
    local spans='[]'
    local index=0
    local function_name=""
    local span_name=""
    local -a functions=(
        "demo.inventory.InventoryServer.availability"
        "demo.inventory.CatalogService.findProduct"
        "demo.inventory.NodeCatalogClient.findProduct"
    )
    local -a defaults=(
        "smoke.InventoryServer.availability"
        "smoke.CatalogService.findProduct"
        "smoke.NodeCatalogClient.findProduct"
    )

    probes="$(curl --fail --silent --show-error --get \
        "$OBI_BASE_URL/v1/dynamic-instrumentation/probes" \
        --data-urlencode 'service=[{"open_ports":"18082"}]')"

    for index in "${!functions[@]}"; do
        function_name="${functions[$index]}"
        if active_span_name "$probes" "$function_name" >/dev/null; then
            continue
        fi
        span_name="${defaults[$index]}"
        spans="$(jq -cn \
            --argjson spans "$spans" \
            --arg function_name "$function_name" \
            --arg span_name "$span_name" \
            '$spans + [{name: $span_name, on: {function_span: $function_name}}]')"
    done

    if [[ "$(jq 'length' <<<"$spans")" -gt 0 ]]; then
        curl --fail --silent --show-error --request PUT \
            --header 'Content-Type: application/json' \
            --data "$(jq -cn --argjson spans "$spans" \
                '{service: [{open_ports: "18082"}], spans: $spans}')" \
            "$OBI_BASE_URL/v1/dynamic-instrumentation/rules/$RULE_ID" >/dev/null
        rule_created=true
    fi

    probes="$(curl --fail --silent --show-error --get \
        "$OBI_BASE_URL/v1/dynamic-instrumentation/probes" \
        --data-urlencode 'service=[{"open_ports":"18082"}]')"
    for function_name in "${functions[@]}"; do
        span_name="$(active_span_name "$probes" "$function_name")"
        span_names+=("$span_name")
    done
}

validate_trace() {
    local -r trace_file="$1"
    local -r inventory_span="$2"
    local -r catalog_span="$3"
    local -r node_client_span="$4"

    jq -e \
        --arg inventory_span "$inventory_span" \
        --arg catalog_span "$catalog_span" \
        --arg node_client_span "$node_client_span" '
        [
          .batches[]
          | (.resource.attributes
              | map(select(.key == "service.name"))[0].value.stringValue) as $service
          | .scopeSpans[]?.spans[]?
          | {service: $service, name, spanId, parentSpanId}
        ] as $spans
        | def one($service; $name):
            [$spans[] | select(.service == $service and .name == $name)]
            | if length == 1 then .[0]
              else error("expected one \($service) \($name) span, found \(length)")
              end;
          one("coupon-checkout"; "POST /checkout") as $go_root
        | one("coupon-checkout"; "processing") as $go_processing
        | one("coupon-checkout"; "GET /availability") as $go_client
        | one("inventory-java"; "GET /availability") as $java_server
        | one("inventory-java"; $inventory_span) as $inventory
        | one("inventory-java"; $catalog_span) as $catalog
        | one("inventory-java"; $node_client_span) as $node_client
        | one("inventory-java"; "GET") as $java_client
        | one("inventory-node"; "GET /availability") as $node_server
        | [
            [$go_processing, $go_root],
            [$go_client, $go_processing],
            [$java_server, $go_client],
            [$inventory, $java_server],
            [$catalog, $inventory],
            [$node_client, $catalog],
            [$java_client, $node_client],
            [$node_server, $java_client]
          ]
        | if all(.[]; .[0].parentSpanId == .[1].spanId) then true
          else error("one or more spans have the wrong direct parent")
          end
        ' "$trace_file" >/dev/null
}

verify_request() {
    local -r sequence="$1"
    local trace_id=""
    local parent_id=""
    local trace_file=""
    local status=""
    local attempt=0

    trace_id="$(tr -d '-' </proc/sys/kernel/random/uuid)"
    parent_id="$(tr -d '-' </proc/sys/kernel/random/uuid)"
    parent_id="${parent_id:0:16}"
    trace_file="$tmpdir/$trace_id.json"

    curl --fail --silent --show-error \
        --header 'Content-Type: application/json' \
        --header "traceparent: 00-$trace_id-$parent_id-01" \
        --data "{\"cart_id\":\"trace-chain-$sequence\",\"coupon\":\"\",\"sku\":\"frog-plush\"}" \
        "$CHECKOUT_URL" >/dev/null

    for ((attempt = 1; attempt <= ATTEMPTS; attempt += 1)); do
        if ! status="$(curl --silent --show-error --output "$trace_file" --write-out '%{http_code}' \
            "$TEMPO_BASE_URL/api/traces/$trace_id")"; then
            status="000"
        fi
        if [[ "$status" == "200" ]] && validate_trace "$trace_file" "${span_names[0]}" "${span_names[1]}" "${span_names[2]}" 2>/dev/null; then
            log "verified trace $sequence/$TRACE_COUNT: $trace_id"
            return 0
        fi
        sleep 1
    done

    log "trace $trace_id never contained the required direct parent chain"
    if [[ -s "$trace_file" ]]; then
        validate_trace "$trace_file" "${span_names[0]}" "${span_names[1]}" "${span_names[2]}"
    fi
    return 1
}

main() {
    local sequence=0

    check_dependencies
    tmpdir="$(mktemp -d)"
    ensure_java_probes
    if [[ ${#span_names[@]} -ne 3 ]]; then
        log "could not resolve all required Java probes"
        return 1
    fi

    for ((sequence = 1; sequence <= TRACE_COUNT; sequence += 1)); do
        verify_request "$sequence"
    done
}

declare -a span_names=()
main "$@"
