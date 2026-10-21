# HTTPX asyncio HTTPS propagation reproduction

This fixture checks HTTP/1.1 HTTPS requests from one shared `httpx.AsyncClient`
running under standard asyncio. Only the source is selected by OBI. The TLS
proxy records every raw `traceparent` field before forwarding the request to an
OpenTelemetry ASGI downstream. TCP-option and black-box propagation are disabled.

The source imports no OpenTelemetry instrumentation. Its readiness endpoint
reports the loop, Python, HTTPX, and OpenSSL versions and checks whether any
OpenTelemetry modules were loaded. Use the full Python image: slim images strip
the local `_asyncio` symbols needed by OBI's task probes.
The checker waits for an OBI server span before opening the shared TLS pool,
then requires a correctly linked client span before running the cases.

From the repository root:

```sh
make docker-generate BPF_TARGETS=amd64
make compile
docker compose -p obi-python-httpx -f internal/test/integration/docker-compose-python-httpx.yml up --build -d
docker compose -p obi-python-httpx -f internal/test/integration/docker-compose-python-httpx.yml exec -T source python check.py --expect injected
docker compose -p obi-python-httpx -f internal/test/integration/docker-compose-python-httpx.yml down
```

Against an unmodified OBI binary, `--expect gap` asserts the baseline failure:
correctly linked source server and client spans, no transmitted header, and an
independent downstream trace. `--expect injected` is the injection regression gate. It
requires exactly one transmitted W3C header containing the OBI client span ID
and a downstream server span parented to that client.

OBI can export an internal `processing` span when it observes queue time. The
checker permits exactly that additional span, verifies both source parent
links, and records its ID as `source_processing`. It rejects missing,
unrelated, or unexported parents. `--require-direct-server-parent` additionally
requires the client to reference the outer server span directly, which fails
when OBI exports its queue and processing spans. The fixture preserves OBI's
existing span hierarchy.

For the disabled control, start a fresh stack with
`HTTPX_PROPAGATION=disabled` before the `up` command and run the checker with
`--expect disabled`. Start a fresh source for every checker run: the checker
closes its shared client at the end to flush delayed TLS span observations.

The checker covers sequential connection reuse, twelve overlapping requests
with distinct incoming contexts, cancellation after transmission followed by
another request, and preservation of an application-supplied mixed-case header.
Cancellation waits for the request's HTTPX trace callback and asserts that the
task was cancelled, so replacing that callback or finishing the request first
cannot silently pass.
The cancelled request must also export its source client span with the same
span ID transmitted to the downstream.
It also checks the request target, method, body, and repeated headers at the
proxy. Its JSON output records request IDs, incoming parents, source span IDs,
downstream IDs, wire headers, and connection identities. Failures exit nonzero;
an unavailable OBI or missing source parentage cannot pass as a propagation gap.

The synchronous HTTPX client, Trio, and HTTP/2 are outside this fixture's scope.

The [recorded prototype results](evidence/README.md) include captured checker
output, baseline trace responses, tested versions, and validation commands.
Production-readiness work is tracked in
[issue #3861](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3861).
