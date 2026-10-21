# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Run inside the source container; exit nonzero unless the requested contract holds."""

import argparse
import concurrent.futures
import json
import os
import secrets
import time
from importlib.metadata import version
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SOURCE_URL = os.getenv("SOURCE_URL", "http://source:8080")
JAEGER_URL = os.getenv("JAEGER_URL", "http://jaeger:16686")
RECORDS_URL = os.getenv("RECORDS_URL", "http://proxy:8082")


def get(url, headers=None):
    with urlopen(Request(url, headers=headers or {}), timeout=15) as response:
        return json.load(response)


def eventually(call, timeout=45):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return call()
        except (AssertionError, OSError, KeyError, IndexError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def trace_spans(trace_id):
    traces = get(f"{JAEGER_URL}/api/traces/{trace_id}")["data"]
    assert traces, f"no trace {trace_id}"
    return traces[0]


def parent(span):
    return [ref["spanID"] for ref in span["references"] if ref["refType"] == "CHILD_OF"]


def request(mode="normal", supplied=None, path="/call"):
    trace_id, parent_id = secrets.token_hex(16), secrets.token_hex(8)
    token = secrets.token_hex(8)
    query = {"id": token, "mode": mode}
    if supplied:
        query["tp"] = supplied
    result = get(SOURCE_URL + path + "?" + urlencode(query),
                 {"traceparent": f"00-{trace_id}-{parent_id}-01"})
    return {"id": token, "trace_id": trace_id, "incoming_parent": parent_id,
            "mode": mode, "wire": result}


def verify_source(item, allow_processing_span=True, require_client=True):
    trace = trace_spans(item["trace_id"])
    source_ids = {key for key, process in trace["processes"].items()
                  if process["serviceName"] == "httpx-source"}
    servers, clients = [], []
    for span in trace["spans"]:
        if span["processID"] not in source_ids:
            continue
        tags = {tag["key"]: tag["value"] for tag in span["tags"]}
        if tags.get("span.kind") == "server":
            servers.append(span)
        if tags.get("span.kind") == "client":
            clients.append(span)
    assert len(servers) == 1, (item["id"], "source servers", servers)
    assert parent(servers[0]) == [item["incoming_parent"]], (
        item["id"], "server parent", parent(servers[0]), item["incoming_parent"])
    if not require_client:
        return servers[0], None
    assert len(clients) == 1, (item["id"], "source clients", clients)
    if parent(clients[0]) != [servers[0]["spanID"]]:
        assert allow_processing_span, (
            item["id"], "client parent", parent(clients[0]), servers[0]["spanID"])
        processing = [span for span in trace["spans"]
                      if span["processID"] in source_ids
                      and span["operationName"] == "processing"
                      and [span["spanID"]] == parent(clients[0])]
        assert len(processing) == 1, (item["id"], "missing processing parent", processing)
        tags = {tag["key"]: tag["value"] for tag in processing[0]["tags"]}
        assert tags.get("span.kind") == "internal", processing
        assert parent(processing[0]) == [servers[0]["spanID"]], processing
        item["source_processing"] = processing[0]["spanID"]
    return servers[0], clients[0]


def verify(item, expectation, supplied, allow_processing_span=True):
    wire = item["wire"]
    assert wire["body"] == "httpx-body", wire
    assert wire["repeated"] == ["one", "two"], wire
    assert wire["request"] == f"POST /echo?id={item['id']} HTTP/1.1", wire
    if item["mode"] == "supplied":
        assert wire["traceparents"] == [supplied], wire
        assert wire["downstream"]["trace_id"] == supplied.split("-")[1], wire
        eventually(lambda: verify_downstream(wire, [supplied.split("-")[2]]))
        return
    server, client = eventually(lambda: verify_source(item, allow_processing_span), timeout=10)
    item["source_server"] = server["spanID"]
    item["source_client"] = client["spanID"]
    if expectation in ("gap", "disabled"):
        assert wire["traceparents"] == [], wire
        assert wire["downstream"]["trace_id"] != item["trace_id"], wire
    else:
        assert wire["traceparents"] == [f"00-{item['trace_id']}-{client['spanID']}-01"], wire
        assert wire["downstream"]["trace_id"] == item["trace_id"], wire

    expected = [client["spanID"]] if expectation == "injected" else []
    eventually(lambda: verify_downstream(wire, expected))


def verify_downstream(wire, expected):
    trace = trace_spans(wire["downstream"]["trace_id"])
    spans = [s for s in trace["spans"] if s["spanID"] == wire["downstream"]["span_id"]]
    assert len(spans) == 1
    assert parent(spans[0]) == expected, spans[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", choices=["gap", "injected", "disabled"], required=True)
    parser.add_argument("--require-direct-server-parent", action="store_true")
    args = parser.parse_args()
    versions = eventually(lambda: get(SOURCE_URL + "/ready"))
    assert versions["loop"] == "_UnixSelectorEventLoop", versions
    assert not versions["otel_loaded"], versions
    print(json.dumps({"versions": versions, "expectation": args.expect}), flush=True)
    print(json.dumps({"dependencies": {name: version(name) for name in [
        "httpx", "httpcore", "anyio", "h11", "uvicorn", "opentelemetry-sdk",
        "opentelemetry-instrumentation-asgi"]}}), flush=True)
    # Observe OBI before opening the pool: TLS probes must see SSL_set_bio.
    def server_ready():
        candidate = request(path="/ready")
        return eventually(lambda: verify_source(candidate, require_client=False), timeout=3)

    eventually(server_ready, timeout=120)
    # Readiness requires a recorded OBI client and its correct source parent.
    def ready():
        candidate = request()
        request()
        return eventually(lambda: verify_source(candidate, not args.require_direct_server_parent), timeout=3)

    eventually(ready, timeout=120)
    first, second = request(), request()
    assert first["wire"]["connection"] == second["wire"]["connection"], "pool was not reused"
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        overlap = list(pool.map(lambda _: request(), range(12)))
    cancelled = request("cancel")
    assert cancelled["wire"] == {"cancelled": True}
    after_cancel = request()

    def cancellation_record():
        record = get(f"{RECORDS_URL}/{cancelled['id']}")
        assert record and "downstream" in record, "cancelled request never reached the downstream"
        assert len(record["traceparents"]) == (1 if args.expect == "injected" else 0), record
        if args.expect == "injected":
            assert record["traceparents"][0].split("-")[1] == cancelled["trace_id"], record
            verify_downstream(record, [record["traceparents"][0].split("-")[2]])
        return record

    cancelled["recorded"] = eventually(cancellation_record)
    supplied = f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01"
    explicit = request("supplied", supplied)
    # Closing the pool flushes OBI's delayed TLS response observations.
    assert get(SOURCE_URL + "/close") == {"closed": True}
    print(json.dumps({"cancelled": cancelled}), flush=True)
    server, client = eventually(lambda: verify_source(cancelled, not args.require_direct_server_parent))
    cancelled["source_server"] = server["spanID"]
    cancelled["source_client"] = client["spanID"]
    if args.expect == "injected":
        assert cancelled["recorded"]["traceparents"][0].split("-")[2] == client["spanID"], cancelled
    items = [first, second, *overlap, after_cancel, explicit]
    errors = []
    for item in items:
        # Flush evidence before an assertion so failed injection remains inspectable.
        print(json.dumps(item), flush=True)
        try:
            verify(item, args.expect, supplied, not args.require_direct_server_parent)
        except AssertionError as error:
            errors.append({"id": item["id"], "error": str(error)})
            print(json.dumps({"failed": item, "error": str(error)}), flush=True)
        else:
            print(json.dumps({"verified": item}), flush=True)
    print(json.dumps({"passed": len(items) - len(errors), "errors": errors,
                      "cancelled": cancelled}), flush=True)
    assert not errors, errors


if __name__ == "__main__":
    main()
