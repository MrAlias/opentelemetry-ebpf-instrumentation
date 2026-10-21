# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import base64
import contextlib
import os
import ssl
import sys

import aiohttp
import multidict
from aiohttp import web
from multidict import CIMultiDict


async def session_context(app):
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=2),
        headers={"X-Session": "session", "X-Precedence": "session"},
        version=aiohttp.HttpVersion11,
    ) as session:
        app["session"] = session
        yield


async def health(request):
    return web.json_response({
        "python": sys.version,
        "aiohttp": aiohttp.__version__,
        "multidict": multidict.__version__,
        "openssl": ssl.OPENSSL_VERSION,
        "loop": type(asyncio.get_running_loop()).__name__,
        "otel_loaded": "opentelemetry.sdk.trace" in sys.modules,
    })


async def forward(request):
    session = request.app["session"]
    body = await request.read()
    headers = CIMultiDict()
    headers["X-Precedence"] = "request"
    headers["X-Unrelated"] = "kept"
    for value in request.headers.getall("X-Application-Traceparent", []):
        headers.add("TrAcEpArEnT", value)
    query = request.query_string
    url = os.environ["PROXY_URL"] + "/" + request.match_info["slug"]
    if query:
        url += "?" + query

    async def send():
        async with session.post(url, data=body, headers=headers, ssl=False) as response:
            response.raise_for_status()
            started.set()
            return await response.read()

    started = asyncio.Event()
    if request.query.get("cancel") == "1":
        task = asyncio.create_task(send())
        await asyncio.wait_for(started.wait(), 10)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return web.json_response({"cancelled": task.cancelled()})
    return web.Response(body=await send(), content_type="application/json")


async def defaults(request):
    headers = request.app["session"].headers
    headers.popall("traceparent", None)
    value = (await request.json()).get("traceparent")
    if value:
        headers["Traceparent"] = value
    return web.json_response({"ok": True})


async def proxy(request):
    body = await request.read()
    transport = request.transport
    if transport not in request.app["connections"]:
        request.app["connections"][transport] = len(request.app["connections"]) + 1
    record = {
        "slug": request.match_info["slug"],
        "headers": [(k.decode("ascii"), v.decode("latin1")) for k, v in request.raw_headers],
        "body": base64.b64encode(body).decode("ascii"),
        "connection": request.app["connections"][transport],
        "http_version": [request.version.major, request.version.minor],
        "tls": transport.get_extra_info("ssl_object") is not None,
    }
    request.app["records"].append(record)
    if request.query.get("cancel") == "1":
        response = web.StreamResponse()
        await response.prepare(request)
        await asyncio.sleep(2)
        with contextlib.suppress(ConnectionResetError):
            await response.write_eof()
        return response
    group = request.query.get("group")
    if group:
        event, arrivals = request.app["barriers"].setdefault(group, (asyncio.Event(), []))
        arrivals.append(record["slug"])
        if len(arrivals) == 2:
            event.set()
        await asyncio.wait_for(event.wait(), 10)
    headers = CIMultiDict((k, v) for k, v in record["headers"] if k.lower() not in {
        "host", "content-length", "transfer-encoding", "connection",
    })
    async with request.app["session"].post(
        os.environ["DOWNSTREAM_URL"] + "/" + record["slug"], data=body, headers=headers,
    ) as response:
        return web.Response(body=await response.read(), status=response.status,
                            content_type="application/json")


async def records(request):
    return web.json_response(request.app["records"])


async def downstream(request):
    from opentelemetry import propagate, trace

    with trace.get_tracer("aiohttp-tls-regression").start_as_current_span(
        "POST /" + request.match_info["slug"],
        context=propagate.extract(request.headers),
        kind=trace.SpanKind.SERVER,
    ) as span:
        body = await request.read()
        span.set_attribute("url.path", request.path)
        span.set_attribute("http.request.method", "POST")
        span.set_attribute("http.response.status_code", 200)
        ctx = span.get_span_context()
        return web.json_response({
            "trace_id": format(ctx.trace_id, "032x"),
            "span_id": format(ctx.span_id, "016x"),
            "body": base64.b64encode(body).decode("ascii"),
        })


def application(role):
    app = web.Application()
    app.router.add_get("/health", health)
    if role == "source":
        app.cleanup_ctx.append(session_context)
        app.router.add_post("/defaults", defaults)
        app.router.add_post("/forward/{slug}", forward)
    elif role == "proxy":
        app.cleanup_ctx.append(session_context)
        app["records"] = []
        app["connections"] = {}
        app["barriers"] = {}
        app.router.add_get("/records", records)
        app.router.add_post("/{slug}", proxy)
    else:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": "aiohttp-downstream"}))
        provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        app.router.add_post("/{slug}", downstream)
    return app


if __name__ == "__main__":
    role = sys.argv[1]
    tls = None
    if role == "proxy":
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain("server.crt", "server.key")
    web.run_app(application(role), port=int(os.environ.get("PORT", "8080")), ssl_context=tls)
