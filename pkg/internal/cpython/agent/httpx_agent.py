# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""OBI's request-local HTTP/1.1 bridge. Executed in a private module namespace."""

import asyncio
import contextvars
import copy
import ctypes
import functools
import importlib
import socket

_IOCTL = 0x0B10B2
_MAGIC = 0x4F42495059544831
_active = contextvars.ContextVar("obi_httpx_asyncio", default=None)


class _RequestState:
    def __init__(self, task):
        self.task = task
        self.packets = []


class _Packet(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("operation", ctypes.c_uint8),
        ("status", ctypes.c_uint8),
        ("source_port", ctypes.c_uint16),
        ("destination_port", ctypes.c_uint16),
        ("_reserved", ctypes.c_ubyte * 6),
        ("source_address", ctypes.c_ubyte * 16),
        ("destination_address", ctypes.c_ubyte * 16),
        ("traceparent", ctypes.c_ubyte * 55),
        ("_pad", ctypes.c_ubyte * 1),
    ]


_ioctl = ctypes.PyDLL(None).ioctl
_ioctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p)
_ioctl.restype = ctypes.c_int


def _exchange(packet):
    # An invalid descriptor makes the syscall inert when OBI is absent.
    _ioctl(-1, _IOCTL, ctypes.byref(packet))


def _begin(connection):
    sock = connection._network_stream.get_extra_info("socket")
    if sock is None:
        return None
    local = sock.getsockname()
    remote = sock.getpeername()
    packet = _Packet(
        magic=_MAGIC,
        size=ctypes.sizeof(_Packet),
        operation=1,
        source_port=local[1],
        destination_port=remote[1],
    )
    prefix = b"\x00" * 10 + b"\xff\xff" if sock.family == socket.AF_INET else b""
    packet.source_address[:] = prefix + socket.inet_pton(sock.family, local[0])
    packet.destination_address[:] = prefix + socket.inet_pton(sock.family, remote[0])
    _exchange(packet)
    return packet if packet.status == 1 else None


def _end(packet):
    packet.operation = 2
    try:
        _exchange(packet)
    except Exception:  # noqa: BLE001 - cleanup must preserve application exceptions
        return


def _current_task():
    try:
        if type(asyncio.get_running_loop()).__module__.startswith("asyncio."):
            return asyncio.current_task()
    except RuntimeError:
        pass
    return None


def install():
    try:
        httpx = importlib.import_module("httpx")
        http11 = importlib.import_module("httpcore._async.http11")
    except ImportError:
        return False
    original_send = httpx.AsyncClient._send_single_request
    if getattr(original_send, "__obi_httpx__", False):
        return True
    original_headers = http11.AsyncHTTP11Connection._send_request_headers

    @functools.wraps(original_send)
    async def send(client, request):
        task = _current_task()
        if task is None:
            return await original_send(client, request)
        state = _RequestState(task)
        token = _active.set(state)
        try:
            return await original_send(client, request)
        finally:
            # MemoryBIO observation can lag header serialization.
            for packet in state.packets:
                _end(packet)
            _active.reset(token)

    @functools.wraps(original_headers)
    async def headers(connection, request):
        packet = None
        forwarded = request
        state = _active.get()
        if (
            state is not None
            and state.task is _current_task()
            and request.url.scheme == b"https"
            and not any(name.lower() == b"traceparent" for name, _ in request.headers)
        ):
            try:
                packet = _begin(connection)
                if packet is not None:
                    forwarded = copy.copy(request)
                    forwarded.headers = [
                        *request.headers,
                        (b"traceparent", bytes(packet.traceparent)),
                    ]
                    state.packets.append(packet)
            except Exception:  # noqa: BLE001 - instrumentation must preserve request behavior
                if packet is not None:
                    _end(packet)
                    packet = None
                forwarded = request
        return await original_headers(connection, forwarded)

    send.__obi_httpx__ = True
    http11.AsyncHTTP11Connection._send_request_headers = headers
    httpx.AsyncClient._send_single_request = send
    return True
