# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import grpc


class Source(BaseHTTPRequestHandler):
    channel = None
    lock = threading.Lock()

    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        if urlsplit(self.path).path == "/health":
            result = {
                "healthy": True,
                "grpc_hook_ready": bool(
                    getattr(
                        getattr(sys.modules.get("grpc._channel"), "Channel", None),
                        "unary_unary",
                        None,
                    )
                    and getattr(grpc._channel.Channel.unary_unary, "_obi_grpc", False)
                ),
            }
        else:
            with self.lock:
                if Source.channel is None:
                    with open("/cert.pem", "rb") as certificate:
                        Source.channel = grpc.secure_channel(
                            "proxy:8443",
                            grpc.ssl_channel_credentials(certificate.read()),
                        )
            call = self.channel.unary_unary("/regression.Echo/Call")
            metadata = (
                ("x-case", query["case"][0]),
                ("x-user", "first"),
                ("x-user", "second"),
                ("x-user-bin", b"\x00\xff"),
            )
            if "app_tp" in query:
                metadata += (("traceparent", query["app_tp"][0]),)
            try:
                result = [
                    json.loads(call(b"request", metadata=metadata, timeout=15))
                    for _ in range(int(query.get("repeat", ["1"])[0]))
                ]
            except grpc.RpcError as error:
                self.send_error(502, str(error))
                return
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer(("0.0.0.0", 8080), Source).serve_forever()
