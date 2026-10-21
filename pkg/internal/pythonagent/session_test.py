# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import concurrent.futures
import ctypes
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import ssl
import struct
import threading
import unittest
from unittest import mock

import requests
import urllib3

import session as agent


CONTEXT = threading.local()
TRACEPARENT = b"00-11111111111111111111111111111111-2222222222222222-01"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.respond(b"")

    def do_POST(self):
        if self.headers.get("Transfer-Encoding") == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if not size:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            body = b"".join(chunks)
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.respond(body)

    def respond(self, body):
        data = json.dumps({
            "traceparents": self.headers.get_all("traceparent", []),
            "headers": dict(self.headers), "body": body.hex(),
            "peer": self.client_address, "path": self.path,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class SessionAgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        cls.originals = (
            requests.sessions.Session.send, requests.adapters.HTTPAdapter.send,
            urllib3.connectionpool.HTTPConnectionPool.urlopen,
            http.client.HTTPConnection._send_output, http.client.HTTPConnection.send,
        )
        agent.install(lambda connection: (getattr(CONTEXT, "value", None), lambda: None))
        cls.servers = []
        cls.urls = []
        root = Path(__file__).resolve().parents[3]
        for tls in (False, True):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.set_alpn_protocols(["http/1.1"])
                context.load_cert_chain(
                    root / "internal/test/integration/components/pythonserver/server.crt",
                    root / "internal/test/integration/components/pythonserver/server.key",
                )
                server.socket = context.wrap_socket(server.socket, server_side=True)
            cls.servers.append(server)
            cls.urls.append(("https" if tls else "http") + "://127.0.0.1:" + str(server.server_port))
            threading.Thread(target=server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        (requests.sessions.Session.send, requests.adapters.HTTPAdapter.send,
         urllib3.connectionpool.HTTPConnectionPool.urlopen,
         http.client.HTTPConnection._send_output, http.client.HTTPConnection.send) = cls.originals

    def setUp(self):
        CONTEXT.value = TRACEPARENT

    def new_session(self):
        result = requests.Session()
        result.trust_env = False
        self.addCleanup(result.close)
        return result

    def test_prepared_request_and_connection_reuse(self):
        for url in self.urls:
            with self.subTest(url=url):
                client = self.new_session()
                client.auth = ("user", "password")
                client.cookies.set("test-cookie", "preserved")
                client.headers["X-Session"] = "preserved"
                peers = []
                for index in range(3):
                    request = client.prepare_request(requests.Request(
                        "POST", url + "/prepared?index=" + str(index),
                        headers={"X-Unrelated": "preserved"}, data=b"body\x00\xff\r\n",
                    ))
                    headers = dict(request.headers)
                    body = request.body
                    with client.send(request, verify=False, timeout=5) as response:
                        response.raise_for_status()
                        observation = response.json()
                    self.assertEqual(headers, dict(request.headers))
                    self.assertIs(body, request.body)
                    self.assertEqual(body.hex(), observation["body"])
                    self.assertEqual([TRACEPARENT.decode()], observation["traceparents"])
                    received = requests.structures.CaseInsensitiveDict(observation["headers"])
                    for name, value in headers.items():
                        self.assertEqual(value, received[name], name)
                    self.assertEqual("/prepared?index=" + str(index), observation["path"])
                    peers.append(observation["peer"])
                self.assertEqual([peers[0]] * 3, peers)

    def test_application_header_preserved(self):
        for url in self.urls:
            for value in (TRACEPARENT.decode(), "invalid-application-value", ""):
                with self.subTest(url=url, value=value):
                    client = self.new_session()
                    with client.get(url, headers={"TrAcEpArEnT": value}, verify=False, timeout=5) as response:
                        self.assertEqual([value], response.json()["traceparents"])

    def test_body_writes_do_not_receive_headers(self):
        body = b"POST /fake HTTP/1.1\r\nX-Body: preserved\r\n\r\n\x00\xff"
        for url in self.urls:
            for data in (body, io.BytesIO(body), iter((body[:5], body[5:]))):
                with self.subTest(url=url, body_type=type(data).__name__):
                    client = self.new_session()
                    with client.post(url, data=data, verify=False, timeout=5) as response:
                        observed = response.json()
                        self.assertEqual(body.hex(), observed["body"])
                        self.assertEqual([TRACEPARENT.decode()], observed["traceparents"])

    def test_direct_urllib3_is_excluded_even_inside_response_hook(self):
        for url in self.urls:
            with self.subTest(url=url):
                pool = urllib3.PoolManager(cert_reqs="CERT_NONE")
                self.addCleanup(pool.clear)
                self.assertEqual([], json.loads(pool.request("GET", url).data)["traceparents"])
                observed = []

                def response_hook(response, *args, **kwargs):
                    observed.append(json.loads(pool.request("GET", url).data)["traceparents"])
                    return response

                client = self.new_session()
                with client.get(url, hooks={"response": response_hook}, verify=False, timeout=5) as response:
                    self.assertEqual([TRACEPARENT.decode()], response.json()["traceparents"])
                self.assertEqual([[]], observed)

    def test_direct_adapter_is_excluded(self):
        client = self.new_session()
        for url in self.urls:
            request = client.prepare_request(requests.Request("GET", url))
            with client.get_adapter(url).send(request, verify=False, timeout=5) as response:
                self.assertEqual([], response.json()["traceparents"])

    def test_direct_urllib3_inside_body_generator_is_excluded(self):
        for url in self.urls:
            with self.subTest(url=url):
                pool = urllib3.PoolManager(cert_reqs="CERT_NONE")
                self.addCleanup(pool.clear)
                observed = []

                def body():
                    observed.append(json.loads(pool.request("GET", url).data)["traceparents"])
                    yield b"preserved"

                client = self.new_session()
                with client.post(url, data=body(), verify=False, timeout=5) as response:
                    self.assertEqual([TRACEPARENT.decode()], response.json()["traceparents"])
                    self.assertEqual(b"preserved".hex(), response.json()["body"])
                self.assertEqual([[]], observed)

    def test_missing_or_invalid_bridge_context(self):
        for value in (None, b"", b"invalid", b"00-" + b"0" * 32 + b"-" + b"2" * 16 + b"-01"):
            CONTEXT.value = value
            for url in self.urls:
                client = self.new_session()
                with client.get(url, verify=False, timeout=5) as response:
                    self.assertEqual([], response.json()["traceparents"])

    def test_concurrent_contexts(self):
        for url in self.urls:
            def call(index):
                context = ("00-%032x-%016x-01" % (index + 1, index + 1)).encode()
                CONTEXT.value = context
                with requests.Session() as client:
                    client.trust_env = False
                    for _ in range(3):
                        with client.get(url, verify=False, timeout=5) as response:
                            self.assertEqual([context.decode()], response.json()["traceparents"])

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(call, range(8)))

    def test_install_is_idempotent(self):
        original = requests.Session.send
        agent.install()
        self.assertIs(original, requests.Session.send)

    def test_bridge_abi_and_cleanup(self):
        class Connection:
            closed = False

            def getsockname(self):
                if self.closed:
                    raise OSError("closed")
                return "127.0.0.1", 40000

            def getpeername(self):
                return "127.0.0.2", 443

        operations = []

        def ioctl(fd, command, packet):
            self.assertEqual(0, fd)
            self.assertEqual(0x0B10B2, command)
            self.assertEqual(100, len(packet.raw))
            version, operation, local, peer, local_port, peer_port = struct.unpack_from(
                "=II16s16sHH", packet.raw,
            )
            self.assertEqual(1, version)
            self.assertEqual(b"\x00" * 10 + b"\xff\xff\x7f\x00\x00\x01", local)
            self.assertEqual(b"\x00" * 10 + b"\xff\xff\x7f\x00\x00\x02", peer)
            self.assertEqual((40000, 443), (local_port, peer_port))
            operations.append(operation)
            if operation == 1:
                ctypes.memmove(ctypes.addressof(packet) + 44, TRACEPARENT + b"\x00", 56)
            return -1

        connection = Connection()
        with mock.patch.object(agent, "_ioctl", ioctl):
            value, clear = agent._prepare_context(connection)
            self.assertEqual(TRACEPARENT, value)
            connection.closed = True
            clear()
        self.assertEqual([1, 2], operations)


if __name__ == "__main__":
    unittest.main()
