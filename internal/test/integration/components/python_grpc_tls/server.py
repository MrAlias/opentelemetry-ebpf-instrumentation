# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import grpc
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.grpc import GrpcInstrumentorServer
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider(resource=Resource.create({"service.name": "grpc-downstream"}))
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint="http://jaeger:4318/v1/traces")))
trace.set_tracer_provider(provider)
GrpcInstrumentorServer().instrument()

lock = threading.Lock()
active = 0
maximum = 0


def echo(request, context):
    global active, maximum
    with lock:
        active += 1
        maximum = max(maximum, active)
        observed_max = maximum
    try:
        time.sleep(0.15)
        metadata = context.invocation_metadata()
        span = trace.get_current_span().get_span_context()
        result = {
            "traceparents": [value for key, value in metadata if key == "traceparent"],
            "users": [value for key, value in metadata if key == "x-user"],
            "binary": [value.hex() for key, value in metadata if key == "x-user-bin"],
            "case": [value for key, value in metadata if key == "x-case"],
            "trace_id": format(span.trace_id, "032x"),
            "span_id": format(span.span_id, "016x"),
            "peer": context.peer(),
            "max_active": observed_max,
        }
        print("OBI_PYTHON_GRPC " + json.dumps(result), flush=True)
        return json.dumps(result).encode()
    finally:
        with lock:
            active -= 1


server = grpc.server(ThreadPoolExecutor(max_workers=16))
server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
    "regression.Echo", {"Call": grpc.unary_unary_rpc_method_handler(echo)}
),))
server.add_insecure_port("0.0.0.0:50051")
server.start()
server.wait_for_termination()
