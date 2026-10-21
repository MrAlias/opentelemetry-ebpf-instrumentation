# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import os
from urllib.parse import parse_qs

import uvicorn
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

provider = TracerProvider(resource=Resource.create({"service.name": "httpx-downstream"}))
provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(
    endpoint=os.getenv("OTLP_ENDPOINT", "http://jaeger:4318/v1/traces"))))
trace.set_tracer_provider(provider)


async def app(scope, receive, send):
    while (await receive()).get("more_body", False):
        pass
    context = trace.get_current_span().get_span_context()
    body = json.dumps({"trace_id": f"{context.trace_id:032x}", "span_id": f"{context.span_id:016x}"}).encode()
    args = parse_qs(scope["query_string"].decode())
    await asyncio.sleep(float(args.get("delay", ["0.05"])[0]))
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


uvicorn.run(OpenTelemetryMiddleware(app), host="0.0.0.0", port=int(os.getenv("DOWNSTREAM_PORT", "8081")),
            loop="asyncio", lifespan="off")
