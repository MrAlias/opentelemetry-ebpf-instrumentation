# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""OBI-only source: one shared HTTPX client, standard asyncio, no OTel SDK."""

import asyncio
import contextlib
import json
import os
import ssl
import sys
from urllib.parse import parse_qs

import httpx
import uvicorn


async def main():
    async with httpx.AsyncClient(
        verify=False, http2=False, trust_env=False, timeout=10,
    ) as client:
        async def app(scope, receive, send):
            try:
                target = scope["path"]
                args = parse_qs(scope["query_string"].decode())
                token = args.get("id", ["ready"])[0]
                mode = args.get("mode", ["normal"])[0]
                if target.startswith("/ready"):
                    result = {"python": sys.version, "httpx": httpx.__version__,
                              "openssl": ssl.OPENSSL_VERSION,
                              "loop": type(asyncio.get_running_loop()).__name__,
                              "otel_loaded": any(n.startswith("opentelemetry") for n in sys.modules)}
                elif target == "/close":
                    await client.aclose()
                    result = {"closed": True}
                else:
                    headers = [("X-Test-ID", token), ("X-Repeated", "one"),
                               ("X-Repeated", "two")]
                    if mode == "supplied":
                        headers.append(("TraceParent", args["tp"][0]))
                    url = os.getenv("UPSTREAM_URL", "https://proxy:8443") + f"/echo?id={token}"
                    if mode == "cancel":
                        sent = asyncio.Event()

                        async def trace(name, info):
                            if name == "http11.send_request_body.complete":
                                sent.set()

                        task = asyncio.create_task(client.get(
                            url + "&delay=2", headers=headers, extensions={"trace": trace}))
                        try:
                            await asyncio.wait_for(sent.wait(), timeout=10)
                        finally:
                            task.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await task
                        assert task.cancelled(), "HTTPX request completed before cancellation"
                        result = {"cancelled": True}
                    else:
                        # Exercise a body and repeated headers as well as pooling.
                        response = await client.post(url, headers=headers, content=b"httpx-body")
                        response.raise_for_status()
                        assert response.http_version == "HTTP/1.1"
                        result = response.json()
                body = json.dumps(result).encode()
                await send({"type": "http.response.start", "status": 200,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
            except Exception as error:
                print(f"source failed: {error!r}", flush=True)
                raise

        config = uvicorn.Config(app, host="0.0.0.0", port=int(os.getenv("SOURCE_PORT", "8080")),
                                loop="asyncio", http="h11", lifespan="off")
        await uvicorn.Server(config).serve()


asyncio.run(main())
