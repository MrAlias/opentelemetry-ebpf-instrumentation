# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
import urllib3


BODY = b"prepared-body:\x00\xff\r\nend"
OWNED_TRACEPARENT = "00-33333333333333333333333333333333-4444444444444444-01"


class Source(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = ("prepared", "password")
        self.session.cookies.set("session-cookie", "preserved")
        self.session.headers["X-Session"] = "preserved"

    def finish(self):
        self.session.close()
        super().finish()

    def reply(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        if urlsplit(self.path).path == "/health":
            self.reply(200, {"python": sys.version, "requests": requests.__version__,
                             "urllib3": urllib3.__version__, "openssl": ssl.OPENSSL_VERSION})
            return
        try:
            observations = []
            scheme = query.get("scheme", ["https"])[0]
            if scheme not in ("http", "https"):
                raise ValueError("unsupported scheme")
            port = 8443 if scheme == "https" else 8081
            for index in range(int(query.get("count", ["1"])[0])):
                case_id = query["case"][0] + "/" + str(index)
                headers = {"X-Case-ID": case_id, "X-Unrelated": "preserved"}
                if query.get("owned") == ["valid"]:
                    headers["TrAcEpArEnT"] = OWNED_TRACEPARENT
                elif query.get("owned") == ["invalid"]:
                    headers["TrAcEpArEnT"] = "application-owned-invalid-value"
                if query.get("concurrent") == ["true"]:
                    headers["X-Concurrent"] = "true"
                proxy = os.environ.get("PROXY_HOST", "proxy")
                request = requests.Request(
                    "POST", f"{scheme}://{proxy}:{port}/observe?{urlencode({'case': case_id})}",
                    data=BODY, headers=headers,
                )
                prepared = self.session.prepare_request(request)
                before = dict(prepared.headers)
                with self.session.send(prepared, verify=False, timeout=15) as response:
                    response.raise_for_status()
                    observation = response.json()
                observation["prepared_before"] = before
                observation["prepared_after"] = dict(prepared.headers)
                observation["prepared_body_hex"] = prepared.body.hex()
                observations.append(observation)
            self.reply(200, observations)
        except Exception as error:
            self.reply(500, {"error": repr(error)})


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    ThreadingHTTPServer(("0.0.0.0", 8080), Source).serve_forever()
