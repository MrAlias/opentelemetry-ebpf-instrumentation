# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import ctypes
import importlib
import struct
import sys


_IOCTL_COMMAND = 0x0B10B2
_PACKET_SIZE = 328
_OP_START = 1
_OP_END = 2
_ACTIVE_OFFSET = 4
_STATUS_OFFSET = 64
_PATH_OFFSET = 68
_HOST_OFFSET = 168
_FIELD_SIZE = 100
_TRACEPARENT_OFFSET = 268
_TRACEPARENT_SIZE = 55

_ioctl = ctypes.CDLL(None, use_errno=True).ioctl
_ioctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p)
_ioctl.restype = ctypes.c_int


def install():
    # Avoid importing grpc into applications which do not use it.
    grpc = sys.modules.get("grpc")
    if grpc is None or grpc.__version__ != "1.78.0":
        return False
    channel_module = importlib.import_module("grpc._channel")
    channel_type = channel_module.Channel
    if getattr(channel_type.unary_unary, "_obi_grpc", False):
        return True

    class UnaryUnary(grpc.UnaryUnaryMultiCallable):
        def __init__(self, call, method, target):
            self._call = call
            self._method = method.encode() if isinstance(method, str) else method
            self._target = target.encode() if isinstance(target, str) else target

        def _invoke(self, invoke, request, timeout, metadata, credentials,
                    wait_for_ready, compression):
            values = tuple(metadata) if metadata is not None else ()
            if any(key in ("traceparent", b"traceparent") for key, _ in values):
                return invoke(request, timeout, values, credentials,
                              wait_for_ready, compression)

            packet = bytearray(_PACKET_SIZE)
            struct.pack_into("=I", packet, 0, _OP_START)
            method = self._method[:_FIELD_SIZE - 1]
            target = self._target[:_FIELD_SIZE - 1]
            packet[_PATH_OFFSET:_PATH_OFFSET + len(method)] = method
            packet[_HOST_OFFSET:_HOST_OFFSET + len(target)] = target
            exchange(packet)
            active = struct.unpack_from("=I", packet, _ACTIVE_OFFSET)[0] == 1
            if active:
                traceparent = packet[
                    _TRACEPARENT_OFFSET:_TRACEPARENT_OFFSET + _TRACEPARENT_SIZE
                ].decode("ascii")
                values += (("traceparent", traceparent),)
            status = 2  # UNKNOWN if a non-gRPC exception interrupts the call.
            try:
                result = invoke(request, timeout, values, credentials,
                                wait_for_ready, compression)
                status = 0
                return result
            except grpc.RpcError as error:
                status = error.code().value[0]
                raise
            finally:
                if active:
                    struct.pack_into("=I", packet, 0, _OP_END)
                    struct.pack_into("=I", packet, _STATUS_OFFSET, status)
                    exchange(packet)

        def __call__(self, request, timeout=None, metadata=None, credentials=None,
                     wait_for_ready=None, compression=None):
            return self._invoke(self._call, request, timeout, metadata,
                                credentials, wait_for_ready, compression)

        def with_call(self, request, timeout=None, metadata=None, credentials=None,
                      wait_for_ready=None, compression=None):
            return self._invoke(self._call.with_call, request, timeout, metadata,
                                credentials, wait_for_ready, compression)

        def future(self, *args, **kwargs):
            return self._call.future(*args, **kwargs)

    original_init = channel_type.__init__
    original_unary_unary = channel_type.unary_unary

    def initialize(self, target, options, credentials, compression):
        original_init(self, target, options, credentials, compression)
        self._obi_grpc_secure = credentials is not None

    def unary_unary(self, method, *args, **kwargs):
        call = original_unary_unary(self, method, *args, **kwargs)
        if getattr(self, "_obi_grpc_secure", False):
            return UnaryUnary(call, method, self._target)
        return call

    unary_unary._obi_grpc = True
    channel_type.__init__ = initialize
    channel_type.unary_unary = unary_unary
    return True


def exchange(packet):
    _ioctl(0, _IOCTL_COMMAND, ctypes.addressof(ctypes.c_char.from_buffer(packet)))
