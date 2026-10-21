# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Uninstrumented TLS terminator. Record raw header multiplicity before forwarding."""

import asyncio
import itertools
import json
import os
import ssl

connections = itertools.count(1)
records = {}


async def handle(reader, writer):
    connection = next(connections)
    try:
        while True:
            raw = await reader.readuntil(b"\r\n\r\n")
            lines = raw[:-4].split(b"\r\n")
            headers = [line.split(b":", 1) for line in lines[1:]]
            length = next((int(v) for k, v in headers if k.lower() == b"content-length"), 0)
            body = await reader.readexactly(length)
            record = {"connection": connection, "request": lines[0].decode(),
                      "traceparents": [v.strip().decode() for k, v in headers if k.lower() == b"traceparent"],
                      "repeated": [v.strip().decode() for k, v in headers if k.lower() == b"x-repeated"],
                      "body": body.decode()}
            token = next(v.strip().decode() for k, v in headers if k.lower() == b"x-test-id")
            records[token] = record
            print(json.dumps(record), flush=True)
            upstream_reader, upstream_writer = await asyncio.open_connection(
                os.getenv("DOWNSTREAM_HOST", "downstream"), int(os.getenv("DOWNSTREAM_PORT", "8081")))
            upstream_writer.write(raw + body)
            await upstream_writer.drain()
            response_headers = await upstream_reader.readuntil(b"\r\n\r\n")
            response_length = next(int(line.split(b":", 1)[1]) for line in response_headers.split(b"\r\n")
                                   if line.lower().startswith(b"content-length:"))
            response_body = await upstream_reader.readexactly(response_length)
            upstream_writer.close()
            await upstream_writer.wait_closed()
            record["downstream"] = json.loads(response_body)
            payload = json.dumps(record).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def recorded(reader, writer):
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
        token = raw.split(b" ")[1].decode().removeprefix("/")
        payload = json.dumps(records.get(token)).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                     + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("server.crt", "server.key")
    tls.set_alpn_protocols(["http/1.1"])
    server = await asyncio.start_server(handle, "0.0.0.0", int(os.getenv("PROXY_PORT", "8443")), ssl=tls)
    admin = await asyncio.start_server(recorded, "0.0.0.0", int(os.getenv("RECORDS_PORT", "8082")))
    async with server, admin:
        await asyncio.gather(server.serve_forever(), admin.serve_forever())


asyncio.run(main())
