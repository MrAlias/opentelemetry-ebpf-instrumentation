# Recorded HTTPX prototype results

These results establish functional behavior in the tested setup. The prototype
remains experimental; architecture, lifecycle safety, compatibility, and
production-readiness work are tracked in
[issue #3861](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3861).

## Evidence

The OBI-only source uses one shared AsyncClient on standard asyncio with HTTP/2
disabled. An uninstrumented TLS proxy records raw headers and forwards to an
OpenTelemetry downstream. Header propagation is enabled for the injection run;
TCP-option and black-box propagation are disabled.

| Run | Result |
| --- | --- |
| Original baseline | 16 expected-gap cases: no injected header and an independent downstream trace |
| Headers enabled | Two fresh iterations: 16 cases plus cancellation passed |
| Propagation disabled | Two fresh iterations: 16 cases plus cancellation passed |

The final cases cover overlapping contexts, pooled reuse, cancellation followed
by another request, supplied-header preservation, request target, method, body,
and repeated headers. Source ancestry permits the existing internal `processing`
span and verifies both parent links. The cancelled client span must also match
the transmitted span ID in the injection run.

- [Machine-readable results](results.json) contain versions, validation outcomes,
  case IDs, span IDs, wire records, and the validated binary checksum.
- [Headers-enabled checker output](headers.jsonl) and
  [disabled checker output](disabled.jsonl) retain the version, verified-case,
  and final-result JSON records from the final integration run.
- The baseline example includes the original Jaeger responses for the
  [source trace](baseline-httpx-source.json) and
  [independent downstream trace](baseline-httpx-downstream.json).

The baseline revision is `e64f42f703b6b3ff4a5ffd675a6ba01e7440da5f`.
Final results were collected from the prototype source changes before publication.
The final checker records demonstrate successful assertions; they are not raw
Jaeger responses for the final spans. The baseline Jaeger responses are retained
separately above.

## Tested environment

| Component | Version |
| --- | --- |
| Integration CPython | 3.12.13, full Docker Official Python image |
| HTTPX / httpcore | 0.28.1 / 1.0.9 |
| AnyIO / h11 | 4.15.1 / 0.16.0 |
| Uvicorn | 0.41.0 |
| OpenTelemetry SDK / ASGI instrumentation | 1.39.1 / 0.60b1 |
| Jaeger | 1.60 |
| OpenSSL | 3.0.20 final; 3.0.13 original host baseline |
| Platform | Linux amd64, kernel 7.0.0-1014-aws |
| Go | 1.27.2 |
| BPF generator | 0.2.17, LLVM 22 |
| Live loader unit-test CPython | Host 3.12.3 |

## Reproduce the integration

Run from the repository root on Linux amd64 with Docker and the process/BPF
permissions described in the Python runtime documentation:

```sh
make docker-generate BPF_TARGETS=amd64,arm64
make compile
docker compose -f internal/test/integration/docker-compose-python-httpx.yml build source
SKIP_DOCKER_BUILD=1 go test -v -count=2 -run '^TestPythonHTTPXHTTPSPropagation$' -timeout 10m ./internal/test/integration/
```

The explicit image build makes the subsequent skip-build setting safe. The
integration starts fresh headers-enabled and disabled stacks for each iteration.
It closes the shared client to flush delayed observations and tears down each
stack. See the [fixture README](../README.md) for manual mode-specific commands
and the baseline `--expect gap` check against an unmodified binary.

## Validation recorded

- `GOFLAGS=-p=2 make verify` passed for the main and collector modules. An earlier
  parallel run hit the unrelated Kubernetes `TestBlockedClients` deadline; the
  reduced-concurrency retry passed, including that test.
- BPF generation for amd64 and arm64, compilation, LLVM 22 C formatting/linting,
  BPF unit tests, and Markdown lint passed.
- Go race tests passed for the agent and generic tracer packages, including the
  live loader tests with `OBI_TEST_PYTHON_AGENT=1`.
- Eight Python agent tests and Ruff 0.17.1 checks passed. Tests include request
  object preservation, h11 serialization, distinct task contexts, cancellation
  cleanup, supplied headers, unavailable bridges, and IPv4/IPv6 socket encoding.

## Limits and remaining investigation

The loader supports Linux amd64 GIL builds. Debug/free-threaded builds,
synchronous HTTPX, Trio, uvloop, and HTTP/2 are outside this prototype path.
Required private `_asyncio` symbols can be absent from slim/stripped builds.
Generating arm64 BPF artifacts does not establish arm64 loader support.

The final fixture waits for an exported OBI server span before opening the TLS
pool. Earlier attempts opened connections before TLS probe attachment and could
miss the cancelled client span with propagation disabled. Dedicated attachment
tests for pre-existing TLS pools, lifecycle/failure injection, sustained load,
overhead, trace flags, and `tracestate` remain open in #3861.
