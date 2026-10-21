# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import ctypes
import functools
import http.client
import re
import socket
import struct
import threading

_IOCTL_CONTEXT = 0x0B10B2
_TRACEPARENT = re.compile(rb"00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}\Z")
_ioctl = ctypes.CDLL(None).ioctl
_ioctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p)
_ioctl.restype = ctypes.c_int


def _address(host):
    if ":" in host:
        return socket.inet_pton(socket.AF_INET6, host.split("%", 1)[0])
    return b"\x00" * 10 + b"\xff\xff" + socket.inet_pton(socket.AF_INET, host)


def _prepare_context(connection):
    local = connection.getsockname()
    peer = connection.getpeername()
    # Shared with python_requests.h: version, operation, connection, value and NUL.
    packet = ctypes.create_string_buffer(100)
    struct.pack_into("=II16s16sHH", packet, 0, 1, 1,
                     _address(local[0]), _address(peer[0]), local[1], peer[1])
    _ioctl(0, _IOCTL_CONTEXT, packet)

    def clear():
        struct.pack_into("=I", packet, 4, 2)
        _ioctl(0, _IOCTL_CONTEXT, packet)

    return packet.raw[44:99], clear


def _valid_context(value):
    return (isinstance(value, bytes) and _TRACEPARENT.fullmatch(value) is not None
            and value[3:35] != b"0" * 32 and value[36:52] != b"0" * 16)


def install(prepare_context=_prepare_context):
    try:
        import requests.adapters
        import requests.sessions
        import urllib3.connectionpool
    except ImportError:
        return False

    session_type = requests.sessions.Session
    if getattr(session_type.send, "_obi_requests_session", False):
        return True

    local = threading.local()
    session_send = session_type.send
    adapter_send = requests.adapters.HTTPAdapter.send
    pool_urlopen = urllib3.connectionpool.HTTPConnectionPool.urlopen
    send_output = http.client.HTTPConnection._send_output
    send = http.client.HTTPConnection.send

    @functools.wraps(session_send)
    def scoped_session(self, request, *args, **kwargs):
        previous = getattr(local, "session_request", None)
        local.session_request = request
        try:
            return session_send(self, request, *args, **kwargs)
        finally:
            local.session_request = previous

    @functools.wraps(adapter_send)
    def scoped_adapter(self, request, *args, **kwargs):
        previous = getattr(local, "prepared", None)
        local.prepared = request if getattr(local, "session_request", None) is not None else None
        try:
            return adapter_send(self, request, *args, **kwargs)
        finally:
            local.prepared = previous

    @functools.wraps(pool_urlopen)
    def scoped_pool(self, method, url, *args, **kwargs):
        prepared = getattr(local, "prepared", None)
        headers = kwargs.get("headers", args[1] if len(args) > 1 else None)
        previous = getattr(local, "pool_request", None)
        local.pool_request = prepared if prepared is not None and headers is prepared.headers else None
        try:
            return pool_urlopen(self, method, url, *args, **kwargs)
        finally:
            local.pool_request = previous

    @functools.wraps(send_output)
    def scoped_output(self, *args, **kwargs):
        previous = getattr(local, "header_connection", None)
        local.header_connection = self if getattr(local, "pool_request", None) is not None else None
        try:
            return send_output(self, *args, **kwargs)
        finally:
            local.header_connection = previous

    @functools.wraps(send)
    def inject(self, data):
        if getattr(local, "header_connection", None) is not self:
            return send(self, data)

        # _send_output sends the complete header block before any body chunks.
        local.header_connection = None
        prepared = getattr(local, "pool_request", None)
        if not isinstance(data, bytes) or self._http_vsn != 11 or prepared is None:
            return send(self, data)

        boundary = data.find(b"\r\n\r\n")
        if boundary < 0:
            return send(self, data)
        lines = data[:boundary].split(b"\r\n")
        if any(line.partition(b":")[0].strip().lower() == b"traceparent" for line in lines[1:]):
            return send(self, data)

        if self.sock is None:
            if not self.auto_open:
                return send(self, data)
            self.connect()

        try:
            context, clear = prepare_context(self.sock)
        except Exception:
            return send(self, data)
        try:
            if _valid_context(context):
                data = data[:boundary] + b"\r\ntraceparent: " + context + data[boundary:]
            return send(self, data)
        finally:
            try:
                clear()
            except Exception:
                pass

    scoped_session._obi_requests_session = True
    session_type.send = scoped_session
    requests.adapters.HTTPAdapter.send = scoped_adapter
    urllib3.connectionpool.HTTPConnectionPool.urlopen = scoped_pool
    http.client.HTTPConnection._send_output = scoped_output
    http.client.HTTPConnection.send = inject
    return True
