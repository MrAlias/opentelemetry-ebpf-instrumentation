# Synchronous OkHttp TLS propagation regression

This fixture isolates header propagation from TCP propagation and black-box
correlation. `Source` receives a known incoming traceparent and uses one shared
OkHttpClient with `Protocol.HTTP_1_1` to POST through a TLS-terminating proxy.
Only the source is selected by OBI. The proxy, downstream, and receiver use
separate listeners in one unselected observer process. The proxy records received headers and
connection addresses and forwards them unchanged to an OpenTelemetry SDK
instrumented downstream. The observer also accepts OBI's OTLP/HTTP traces.

The source has no OpenTelemetry SDK or agent. Its assertions check that executing
a call preserves the original immutable request, body identity, method, tag, and
unrelated headers. The observer checks the actual transmitted body and headers.
The verifier checks three sequential calls on one pooled connection, sixteen
calls on eight concurrent workers, and an application-supplied traceparent.

## Run

Run these commands from the repository root. Use separate terminals for the
three long-running processes. The fixture binds ports 18080, 18081, 18082, and
18443 on the host. It requires Linux with BTF and privileges to run OBI.

Build OBI and the source using the repository Java build instructions:

```sh
make java-build
make docker-generate
make compile
gradle -p internal/test/integration/components/java_tls/okhttp installDist
```

Start the uninstrumented proxy, downstream, and OTLP receiver:

```sh
go run ./internal/test/integration/components/java_tls/okhttp/observer
```

Start the source without an OpenTelemetry agent:

```sh
mkdir -p /tmp/obi-okhttp-jvm
TMPDIR=/tmp/obi-okhttp-jvm \
  internal/test/integration/components/java_tls/okhttp/build/install/okhttp-source/bin/okhttp-source
```

Warm its connection before dynamic attachment:

```sh
curl -H 'X-Id: warmup' http://127.0.0.1:18080/call
```

Start OBI, selecting only the source port. `headers` explicitly excludes TCP
option propagation. Header tracking stays enabled for the disabled control.
The request timeout ensures completed client spans on idle pooled connections
are eventually exported.

```sh
sudo env \
  OTEL_EBPF_OPEN_PORT=18080 \
  OTEL_EBPF_BPF_CONTEXT_PROPAGATION=headers \
  OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS=true \
  OTEL_EBPF_JAVAAGENT_ATTACH_TIMEOUT=2m \
  OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT=2s \
  OTEL_EBPF_BPF_BATCH_TIMEOUT=100ms \
  OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT=100ms \
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:18082 \
  OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf \
  ./bin/obi
```

The verifier waits for an OBI TLS client span before exercising the matrix:

```sh
python3 internal/test/integration/components/java_tls/okhttp/verify.py \
  enabled --base 10000 --output /tmp/okhttp-enabled.json
```

For the negative control, stop OBI and the source, restart the source, and start
OBI with `OTEL_EBPF_BPF_CONTEXT_PROPAGATION=disabled`. Then run:

```sh
python3 internal/test/integration/components/java_tls/okhttp/verify.py \
  disabled --base 20000 --output /tmp/okhttp-disabled.json
```

Use a fresh base for every run to keep request IDs unique. For the baseline,
build the unchanged revision and use `baseline` with header propagation enabled.
The baseline verifier expects missing injected headers and independent downstream
traces; it still requires OBI source server and TLS client spans.

## Span relationships

For enabled propagation, each proxy request must carry exactly one traceparent
whose trace ID matches the incoming one and whose parent ID is the OBI client
span ID. The downstream server must use that client span as its parent.
OBI can export an existing `processing` span between the source server and
client; the verifier explicitly follows and checks that additional edge.
The source server's parent must match the known incoming parent ID.

A valid, single application-supplied version-00 header is preserved. With header
propagation enabled, its span ID is adopted for the OBI client span. An explicit
header in another trace intentionally breaks ancestry with the source server.
Malformed or multiple application-supplied headers are left to the application.
With propagation disabled, OBI adds no header; an application-supplied header
still reaches downstream unchanged.

## Scope

The hook is limited to synchronous `Call.execute()` using OkHttp's
`Http1ExchangeCodec` and a JDK `SSLSocket`. `enqueue()`, HTTP/2, older `Http1Codec`
implementations, other TLS providers, redirects, authentication retries, and
WebSockets are outside the tested scope. Injection requires the existing
`bpf_probe_write_user` capability and lockdown checks to allow user-memory
writes. Failure leaves the application request unchanged.

## Tested versions and evidence

Tested on Linux amd64 with kernel `7.0.0-1014-aws`, Temurin OpenJDK
`21.0.8+9`, OkHttp `4.12.0`, Okio `3.6.0`, Gradle `9.8.0`, Go `1.27.2`,
and OpenTelemetry Go SDK `1.47.0`. The agent still compiles for Java 8.
The baseline was repository revision
`e64f42f703b6b3ff4a5ffd675a6ba01e7440da5f`, reproduced before instrumentation
edits. LLVM `22.1.8` was used for final C formatting, linting, and generation.
Other OkHttp/JDK combinations and runtime execution on arm64 were not tested.

| Run | Automatic headers (19 calls) | Supplied header (1 call) | Downstream ancestry |
| --- | --- | --- | --- |
| Unchanged baseline, headers enabled | Absent | Preserved once | Independent traces without supplied context |
| Final, headers enabled | Exactly one, incoming trace ID | Preserved once | OBI client is downstream server's parent |
| Final, propagation disabled | Absent | Preserved once | Independent traces without supplied context |

For example, enabled request `30000` arrived with
`00-00000000000000000000000000007530-0000000000007918-01` and the proxy saw exactly
`00-00000000000000000000000000007530-db34969cbc753249-01`.
The exported ancestry was:

```text
incoming 0000000000007918
  source server 3e7a2818517cac04
    processing 090254327bd1dbac
      source client db34969cbc753249
        downstream server 7739fa797cf30891
```

The first three enabled requests reused TLS peer address `127.0.0.1:45368`,
also used by a request sent before dynamic attachment.
The source and verifier assertions passed for all 20 enabled and 20 disabled
requests. Raw local captures were saved as `/tmp/obi-okhttp-packaged-enabled.json` and
`/tmp/obi-okhttp-packaged-disabled.json`; baseline captures were saved under
`/tmp/obi-okhttp-baseline/`. The initial baseline attach hit the default ten-second
attach timeout under host load; a subsequent pass confirmed TLS client spans
before relying on the baseline. Final runs used the two-minute timeout above.

Validation passed: all 144 agent tests, the Gradle build and Spotless checks,
focused Go tests for `pkg/internal/ebpf/generictracer` and `pkg/internal/java`,
`make compile`, generation for amd64 and arm64, LLVM 22 formatting and C lint,
Markdown lint, and license-header checks. The full repository `make verify`
suite was not run. Initial attempts hit Docker stalls and a full shared disk;
validation completed using the same LLVM 22 tools locally and temporary
RAM-backed Go build space. Both JNI architectures are packaged; JNI source was
unchanged, so the existing arm64 native library was reused for local packaging.

## Remaining prototype work

Application-owned context needs a defined adoption policy before merging. The
supplied-header test uses a fresh span ID. Copying the incoming traceparent
unchanged could instead reuse an ancestor ID for the OBI client span and create
cyclic ancestry; that case has not been tested or resolved.

Further work includes redirects, authentication retries, cancellation and
failed-write cleanup, sustained concurrency and overhead, trace flags and
existing `tracestate`, a supported OkHttp/JDK/kernel/capability matrix, CI
integration, support-matrix updates, and complete repository validation.
