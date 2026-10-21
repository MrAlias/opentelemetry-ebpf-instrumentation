# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import select
import socket
import ssl
import threading


def forward(client):
    with client, socket.create_connection(("downstream", 50051), timeout=15) as upstream:
        client.settimeout(30)
        upstream.settimeout(30)
        while True:
            readable, _, _ = select.select([client, upstream], [], [], 1)
            if client.pending() and client not in readable:
                readable.append(client)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = upstream if source is client else client
                destination.sendall(data)


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/cert.pem", "/key.pem")
context.set_alpn_protocols(["h2"])
with socket.create_server(("0.0.0.0", 8443)) as listener:
    while True:
        client, _ = listener.accept()
        threading.Thread(target=forward, args=(context.wrap_socket(client, server_side=True),)).start()
