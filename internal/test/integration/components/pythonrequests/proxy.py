# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import http.client
import json
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    lock = threading.Lock()
    active = 0

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with Proxy.lock:
            Proxy.active += 1
        try:
            if self.headers.get("X-Concurrent") == "true":
                time.sleep(0.3)
            with Proxy.lock:
                active = Proxy.active
            connection = http.client.HTTPConnection(os.environ.get("DOWNSTREAM_HOST", "downstream"),
                                                    8082, timeout=10)
            try:
                connection.putrequest(self.command, self.path, skip_host=True,
                                      skip_accept_encoding=True)
                for name, value in self.headers.items():
                    connection.putheader(name, value)
                connection.endheaders(body)
                response = connection.getresponse()
                downstream = json.loads(response.read())
                if response.status != 200:
                    raise RuntimeError(f"downstream status {response.status}")
            finally:
                connection.close()
            observation = {
                "case_id": self.headers["X-Case-ID"],
                "traceparents": self.headers.get_all("traceparent", []),
                "peer": f"{self.client_address[0]}:{self.client_address[1]}",
                "active": active, "body_hex": body.hex(),
                "method": self.command, "path": self.path,
                "http_version": self.request_version,
                "headers": dict(self.headers), "downstream": downstream,
            }
            print("OBI_REQUESTS_OBSERVATION " + json.dumps(observation), flush=True)
            data = json.dumps(observation).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            with Proxy.lock:
                Proxy.active -= 1


if __name__ == "__main__":
    plaintext = ThreadingHTTPServer(("0.0.0.0", 8081), Proxy)
    threading.Thread(target=plaintext.serve_forever, daemon=True).start()
    tls = ThreadingHTTPServer(("0.0.0.0", 8443), Proxy)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(os.environ.get("TLS_CERT", "/app/server.crt"),
                            os.environ.get("TLS_KEY", "/app/server.key"))
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    tls.serve_forever()
