# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import base64
import json
import os
import sys
import uuid

import aiohttp


SOURCE = os.environ.get("SOURCE_URL", "http://source:8080")
PROXY = os.environ.get("PROXY_ADMIN_URL", "https://proxy:8443")
JAEGER = os.environ.get("JAEGER_URL", "http://jaeger:16686")
MODE = os.environ.get("PROPAGATION", "headers")
FIXTURE_ONLY = "--fixture-only" in sys.argv
BASELINE = "--baseline" in sys.argv
SESSION_TP = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
REQUEST_TP = "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01"
BODY = bytes(range(256)) * 32


async def get_json(session, url):
    async with session.get(url, ssl=False) as response:
        response.raise_for_status()
        return await response.json()


async def eventually(check, timeout=60):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            return await check()
        except (AssertionError, aiohttp.ClientError, KeyError):
            if asyncio.get_running_loop().time() >= deadline:
                raise
            await asyncio.sleep(0.2)


def tags(span):
    return {tag["key"]: tag["value"] for tag in span["tags"]}


def parent(span):
    return [(ref["traceID"], ref["spanID"]) for ref in span["references"]
            if ref["refType"] == "CHILD_OF"]


async def main():
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(force_close=True),
        timeout=aiohttp.ClientTimeout(total=20),
    ) as session:
        async def ready():
            health = await get_json(session, SOURCE + "/health")
            assert health["loop"] == "_UnixSelectorEventLoop", health
            assert not health["otel_loaded"], health
            return health

        print("versions:", json.dumps(await eventually(ready)), flush=True)
        proxy_health = await eventually(lambda: get_json(session, PROXY + "/health"))
        assert not proxy_health["otel_loaded"], proxy_health
        await eventually(lambda: get_json(
            session, os.environ.get("DOWNSTREAM_URL", "http://downstream:8081") + "/health"))
        if not FIXTURE_ONLY:
            async def instrumented():
                await ready()
                result = await get_json(session, JAEGER + "/api/traces?service=aiohttp-source&limit=10")
                assert any(tags(span).get("url.path") == "/health"
                           for trace in result["data"] for span in trace["spans"]), result
            await eventually(instrumented)

        calls = []

        async def call(label, query="", application_tp=None):
            slug = label + "-" + uuid.uuid4().hex
            trace_id, incoming_span = uuid.uuid4().hex, uuid.uuid4().hex[:16]
            headers = {"traceparent": f"00-{trace_id}-{incoming_span}-01"}
            if application_tp:
                headers["X-Application-Traceparent"] = application_tp
            async with session.post(SOURCE + "/forward/" + slug + query,
                                    headers=headers, data=BODY) as response:
                response.raise_for_status()
                result = await response.json()
            calls.append((slug, trace_id, incoming_span, application_tp, result, "cancel=1" in query))
            return slug

        reuse = [await call("reuse-a"), await call("reuse-b")]
        group = uuid.uuid4().hex
        await asyncio.gather(call("overlap-a", "?group=" + group),
                             call("overlap-b", "?group=" + group))
        await call("cancelled", "?cancel=1")
        await call("after-cancel")
        async with session.post(SOURCE + "/defaults", json={"traceparent": SESSION_TP}) as response:
            response.raise_for_status()
        await call("session", application_tp=None)
        await call("override", application_tp=REQUEST_TP)
        async with session.post(SOURCE + "/defaults", json={}) as response:
            response.raise_for_status()
        await call("after-defaults")

        records = await get_json(session, PROXY + "/records")
        print("wire evidence:", json.dumps([
            {key: value for key, value in record.items() if key != "body"}
            for record in records
        ]), flush=True)
        assert len(records) == len(calls), records
        by_slug = {record["slug"]: record for record in records}
        assert len(by_slug) == len(calls), records
        assert by_slug[reuse[0]]["connection"] == by_slug[reuse[1]]["connection"], reuse

        for slug, trace_id, incoming_span, supplied, result, cancelled in calls:
            record = by_slug[slug]
            assert record["tls"] and record["http_version"] == [1, 1], record
            assert base64.b64decode(record["body"]) == BODY, slug
            headers = {}
            for key, value in record["headers"]:
                headers.setdefault(key.lower(), []).append(value)
            assert headers["x-session"] == ["session"], headers
            assert headers["x-precedence"] == ["request"], headers
            assert headers["x-unrelated"] == ["kept"], headers
            expected = supplied or (SESSION_TP if slug.startswith("session-") else None)
            transmitted = headers.get("traceparent", [])
            if expected:
                assert transmitted == [expected], (slug, transmitted)
            elif MODE == "disabled" or FIXTURE_ONLY or BASELINE:
                assert transmitted == [], (slug, transmitted)
            else:
                assert len(transmitted) == 1, (slug, transmitted)
                parts = transmitted[0].split("-")
                assert parts[0] == "00" and parts[1] == trace_id and parts[3] == "01", (slug, parts)
                assert len(parts[2]) == 16 and int(parts[2], 16) != 0, (slug, parts)
            if cancelled:
                assert result == {"cancelled": True}, result
                if not FIXTURE_ONLY:
                    await eventually(lambda: check_trace(session, slug, trace_id, incoming_span,
                                                        transmitted, result, expected, cancelled=True))
                continue
            assert base64.b64decode(result["body"]) == BODY, result
            if expected or transmitted:
                assert result["trace_id"] == (expected or transmitted[0]).split("-")[1], result
            else:
                assert result["trace_id"] != trace_id, result
            if not FIXTURE_ONLY:
                await eventually(lambda: check_trace(session, slug, trace_id, incoming_span,
                                                    transmitted, result, expected))
        print("PASS:", MODE, "fixture-only" if FIXTURE_ONLY else "baseline" if BASELINE else "integration", flush=True)


async def check_trace(session, slug, trace_id, incoming_span, transmitted, result, supplied, cancelled=False):
    data = await get_json(session, JAEGER + "/api/traces/" + trace_id)
    assert len(data["data"]) == 1, data
    trace = data["data"][0]
    source = [span for span in trace["spans"]
              if trace["processes"][span["processID"]]["serviceName"] == "aiohttp-source"]
    servers = [span for span in source if tags(span).get("span.kind") == "server"
               and tags(span).get("url.path") == "/forward/" + slug]
    clients = [span for span in source if tags(span).get("span.kind") == "client"
               and span["operationName"] == "POST /" + slug]
    assert len(servers) == 1, source
    server = servers[0]
    assert parent(server) == [(trace_id, incoming_span)], server
    # Supplied headers can intentionally replace the outgoing trace context.
    if not supplied:
        assert len(clients) == 1, source
        client = clients[0]
        server_ids = {server["spanID"]}
        server_ids.update(span["spanID"] for span in source
                          if span["operationName"] == "processing"
                          and tags(span).get("span.kind") == "internal"
                          and parent(span) == [(trace_id, server["spanID"])])
        assert len(parent(client)) == 1, client
        assert parent(client)[0][0] == trace_id and parent(client)[0][1] in server_ids, client
        if transmitted:
            assert transmitted[0].split("-")[2] == client["spanID"], (transmitted, client)
    if cancelled:
        return
    downstream_data = await get_json(session, JAEGER + "/api/traces/" + result["trace_id"])
    downstream = [span for trace in downstream_data["data"] for span in trace["spans"]
                  if span["spanID"] == result["span_id"]]
    assert len(downstream) == 1, downstream_data
    if transmitted:
        parts = transmitted[0].split("-")
        assert parent(downstream[0]) == [(parts[1], parts[2])], downstream
    else:
        assert parent(downstream[0]) == [], downstream


if __name__ == "__main__":
    asyncio.run(main())
