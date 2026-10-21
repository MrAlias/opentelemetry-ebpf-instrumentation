# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import concurrent.futures
import ctypes
import json
import struct
import unittest
from unittest.mock import patch

import grpc

import agent


class AgentTest(unittest.TestCase):
    def test_exchange_retains_writes_after_ioctl_error(self):
        packet = bytearray(agent._PACKET_SIZE)

        def failing_ioctl(fd, command, address):
            self.assertEqual((0, agent._IOCTL_COMMAND), (fd, command))
            ctypes.memmove(address + agent._ACTIVE_OFFSET, struct.pack("=I", 1), 4)
            return -1

        with patch.object(agent, "_ioctl", failing_ioctl):
            agent.exchange(packet)
        self.assertEqual(1, struct.unpack_from("=I", packet, agent._ACTIVE_OFFSET)[0])

    @classmethod
    def setUpClass(cls):
        cls.server = grpc.server(concurrent.futures.ThreadPoolExecutor(8))

        def echo(request, context):
            if request == b"fail":
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid")
            return json.dumps([
                (key, value.hex() if isinstance(value, bytes) else value)
                for key, value in context.invocation_metadata()
                if key != "user-agent"
            ]).encode()

        handler = grpc.unary_unary_rpc_method_handler(echo)
        cls.server.add_generic_rpc_handlers((
            grpc.method_handlers_generic_handler("test.Service", {"Call": handler}),
        ))
        with open("/key.pem", "rb") as file:
            key = file.read()
        with open("/cert.pem", "rb") as file:
            cls.cert = file.read()
        cls.port = cls.server.add_secure_port(
            "localhost:0", grpc.ssl_server_credentials(((key, cls.cert),)))
        cls.plain_port = cls.server.add_insecure_port("localhost:0")
        cls.server.start()
        assert agent.install()
        assert agent.install()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop(0).wait()

    def channel(self):
        return grpc.secure_channel(
            f"localhost:{self.port}", grpc.ssl_channel_credentials(self.cert),
            options=(("grpc.ssl_target_name_override", "proxy"),))

    def test_metadata_with_call_and_error(self):
        completed = []

        def exchange(packet):
            if struct.unpack_from("=I", packet)[0] == 1:
                struct.pack_into("=I", packet, 4, 1)
                packet[268:323] = b"00-" + b"1" * 32 + b"-" + b"2" * 16 + b"-01"
            else:
                completed.append(struct.unpack_from("=I", packet, 64)[0])

        metadata = [("x-user", "first"), ("x-user", "second"), ("x-user-bin", b"\x00\xff")]
        with self.channel() as channel, patch.object(agent, "exchange", exchange):
            call = channel.unary_unary("/test.Service/Call")
            response, rpc = call.with_call(b"ok", metadata=metadata, timeout=5)
            self.assertEqual(grpc.StatusCode.OK, rpc.code())
            values = json.loads(response)
            self.assertEqual([["x-user", "first"], ["x-user", "second"], ["x-user-bin", "00ff"]],
                             [value for value in values if value[0] != "traceparent"])
            self.assertEqual(1, sum(key == "traceparent" for key, _ in values))
            self.assertEqual(3, len(metadata))
            with self.assertRaises(grpc.RpcError) as error:
                call(b"fail", timeout=5)
            self.assertEqual(grpc.StatusCode.INVALID_ARGUMENT, error.exception.code())
        self.assertEqual([0, 3], completed)

    def test_application_traceparent_and_unavailable_bridge(self):
        with self.channel() as channel:
            call = channel.unary_unary("/test.Service/Call")
            with patch.object(agent, "exchange") as exchange:
                metadata = (("traceparent", "application"),)
                self.assertEqual([["traceparent", "application"]], json.loads(call(b"ok", metadata=metadata)))
                exchange.assert_not_called()
            # No BPF response: preserve normal RPC behavior without injection.
            self.assertEqual([], json.loads(call(b"ok", timeout=5)))

    def test_excluded_calls(self):
        with self.channel() as channel, grpc.insecure_channel(f"localhost:{self.plain_port}") as plain:
            with patch.object(agent, "exchange") as exchange:
                self.assertEqual([], json.loads(channel.unary_unary("/test.Service/Call").future(b"ok").result(5)))
                self.assertEqual([], json.loads(plain.unary_unary("/test.Service/Call")(b"ok", timeout=5)))
                self.assertFalse(isinstance(channel.unary_stream("/test.Service/Call"), type(channel.unary_unary("/test.Service/Call"))))
                exchange.assert_not_called()


if __name__ == "__main__":
    unittest.main()
