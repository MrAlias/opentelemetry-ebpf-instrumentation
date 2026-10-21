# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import ctypes
import importlib.util
import pathlib
import socket
import types
import unittest

import h11
import httpcore
import httpx
from httpcore._async.http11 import AsyncHTTP11Connection


class HTTPXAgentTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_send = httpx.AsyncClient._send_single_request
        self.original_headers = AsyncHTTP11Connection._send_request_headers
        self.sent = []
        self.operations = []
        self.after_headers = []
        self.disabled = False
        self.block = False
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

        async def headers(connection, request):
            self.sent.append(request)
            if self.block:
                self.entered.set()
                await self.release.wait()
            else:
                await asyncio.sleep(0)
            return request

        async def send(client, request):
            result = await AsyncHTTP11Connection._send_request_headers(
                self.connection, request
            )
            state = self.agent._active.get()
            self.after_headers.append([packet.operation for packet in state.packets])
            await asyncio.sleep(0)
            return result

        httpx.AsyncClient._send_single_request = send
        AsyncHTTP11Connection._send_request_headers = headers
        spec = importlib.util.spec_from_file_location(
            "obi_httpx_test_agent", pathlib.Path(__file__).with_name("httpx_agent.py")
        )
        self.agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.agent)

        def exchange(packet):
            task = asyncio.current_task()
            self.operations.append(
                (task.get_name(), packet.operation, bytes(packet.traceparent))
            )
            if packet.operation == 1 and not self.disabled:
                value = f"00-{'1' * 32}-{int(task.get_name()):016x}-01".encode()
                packet.traceparent[:] = value
                packet.status = 1

        self.agent._exchange = exchange
        self.sock = types.SimpleNamespace(
            family=socket.AF_INET,
            getsockname=lambda: ("127.0.0.1", 41000),
            getpeername=lambda: ("127.0.0.1", 8443),
        )
        self.connection = types.SimpleNamespace(
            _network_stream=types.SimpleNamespace(get_extra_info=lambda name: self.sock)
        )
        asyncio.current_task().set_name("1")
        self.assertTrue(self.agent.install())

    async def asyncTearDown(self):
        httpx.AsyncClient._send_single_request = self.original_send
        AsyncHTTP11Connection._send_request_headers = self.original_headers

    def request(self, headers=None, url=b"https://example.test/path?q=a%2Fb"):
        return httpcore.Request(
            b"POST",
            url,
            headers=headers
            or [(b"Host", b"example.test"), (b"X-A", b"1"), (b"X-A", b"2")],
            content=b"body",
            extensions={"trace": object(), "timeout": {"write": 3}},
        )

    async def send(self, request):
        if not asyncio.current_task().get_name().isdigit():
            asyncio.current_task().set_name("1")
        return await httpx.AsyncClient._send_single_request(None, request)

    async def test_private_copy_and_idempotent_install(self):
        self.assertEqual(ctypes.sizeof(self.agent._Packet), 112)
        self.assertEqual(self.agent._Packet.traceparent.offset, 56)
        wrapper = httpx.AsyncClient._send_single_request
        self.assertTrue(self.agent.install())
        self.assertIs(wrapper, httpx.AsyncClient._send_single_request)
        request = self.request()
        forwarded = await self.send(request)
        self.assertIsNot(forwarded, request)
        self.assertEqual(forwarded.headers[:-1], request.headers)
        self.assertEqual(forwarded.headers[-1][0], b"traceparent")
        self.assertEqual(len(forwarded.headers[-1][1]), 55)
        serialized = h11.Connection(h11.CLIENT).send(
            h11.Request(
                method=forwarded.method,
                target=forwarded.url.target,
                headers=forwarded.headers,
            )
        )
        self.assertTrue(serialized.endswith(forwarded.headers[-1][1] + b"\r\n\r\n"))
        for attribute in ("stream", "extensions", "url", "method"):
            self.assertIs(getattr(forwarded, attribute), getattr(request, attribute))
        self.assertEqual([op[1] for op in self.operations], [1, 2])
        self.assertEqual(self.after_headers, [[1]])
        self.assertEqual(self.operations[1][2], forwarded.headers[-1][1])
        self.assertIsNone(self.agent._active.get())

    async def test_overlap_and_reuse_leave_original_request_clean(self):
        request = self.request()
        tasks = [
            asyncio.create_task(self.send(request), name=str(i)) for i in range(2, 14)
        ]
        results = await asyncio.gather(*tasks)
        values = [result.headers[-1][1] for result in results]
        self.assertEqual(len(set(values)), len(tasks))
        again = await self.send(request)
        self.assertNotIn(again.headers[-1][1], values)
        self.assertFalse(
            any(name.lower() == b"traceparent" for name, _ in request.headers)
        )

    async def test_application_traceparent_is_preserved(self):
        request = self.request(
            [(b"Host", b"example.test"), (b"TrAcEpArEnT", b"custom")]
        )
        self.assertIs(await self.send(request), request)
        self.assertEqual(self.operations, [])

    async def test_socket_addresses(self):
        asyncio.current_task().set_name("1")
        packet = self.agent._begin(self.connection)
        self.assertEqual(
            bytes(packet.source_address), b"\x00" * 10 + b"\xff\xff\x7f\x00\x00\x01"
        )
        self.assertEqual(packet.source_port, 41000)
        self.assertEqual(packet.destination_port, 8443)
        self.sock.family = socket.AF_INET6
        self.sock.getsockname = lambda: ("::1", 41001, 0, 0)
        self.sock.getpeername = lambda: ("2001:db8::1", 8443, 0, 0)
        packet = self.agent._begin(self.connection)
        self.assertEqual(
            bytes(packet.source_address), socket.inet_pton(socket.AF_INET6, "::1")
        )
        self.assertEqual(
            bytes(packet.destination_address),
            socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        )

    async def test_disabled_or_unavailable_bridge(self):
        self.disabled = True
        request = self.request()
        self.assertIs(await self.send(request), request)
        self.assertEqual([op[1] for op in self.operations], [1])

    async def test_cancellation_cleanup_then_next_request(self):
        self.block = True
        task = asyncio.create_task(self.send(self.request()), name="2")
        await self.entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual([op[1] for op in self.operations], [1, 2])
        self.block = False
        result = await self.send(self.request())
        self.assertEqual(
            result.headers[-1][1], b"00-" + b"1" * 32 + b"-0000000000000001-01"
        )

    async def test_other_transports_and_calls_outside_asyncclient(self):
        request = self.request(url=b"http://example.test/")
        self.assertIs(await self.send(request), request)
        request = self.request()
        self.assertIs(
            await AsyncHTTP11Connection._send_request_headers(self.connection, request),
            request,
        )
        self.assertEqual(self.operations, [])

    async def test_cleanup_error_preserves_send_error(self):
        self.block = True
        task = asyncio.create_task(self.send(self.request()), name="2")
        await self.entered.wait()

        def broken_exchange(packet):
            raise RuntimeError("bridge unavailable")

        self.agent._exchange = broken_exchange
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task


if __name__ == "__main__":
    unittest.main()
