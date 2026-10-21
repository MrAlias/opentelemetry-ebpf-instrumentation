# HttpClient 5 classic propagation regression

The source uses `CloseableHttpClient` with a shared connection pool and no
OpenTelemetry SDK or SDK agent. OBI attaches its Java agent dynamically. Only
the source Java process on port 8080 is selected for instrumentation.

The Go proxy terminates TLS, records every received `traceparent` value and the
client connection address, and forwards headers to the downstream without
tracing instrumentation. The downstream uses the OpenTelemetry Go SDK to
extract the header and export a server span. Its response reports its trace,
span, and parent IDs, along with the method, path, custom header, and POST body.

The suite compares those observations with exported spans in Jaeger. It checks
both edges of source server → source client → downstream server, including the
known incoming remote parent. When OBI emits queue and processing subspans, the
client must parent to the processing span, which must parent to the server span.
Sequential requests must reuse one TLS connection;
eight concurrent callers use distinct incoming contexts. A foreign,
application-supplied header must survive unchanged, intentionally separating the
downstream trace from the incoming source trace. With propagation disabled,
header extraction stays enabled so source nesting can still be checked.

The enabled configuration selects `headers` only; TCP-option propagation is
excluded. HTTP/1.1 is explicit on both the source request and TLS proxy. The
asynchronous Apache client is outside this fixture's scope.

Fixture versions:

- Apache HttpClient 5.4.4 and HttpCore 5.3.4.
- Temurin 21.0.12.1+1 from the pinned Gradle 9.8.0 JDK image in the Dockerfile.
- OpenTelemetry Go SDK 1.47.0, pinned by the repository module.
- Jaeger 2.22.0, pinned by the Compose file.

Run from the repository root:

```sh
go test -v -run '^TestJavaHTTPClient5Traceparent$' -timeout 10m ./internal/test/integration/
```

Each case logs the transmitted header values, TLS connection, and downstream
IDs. Successful enabled cases also log the three exported span IDs. Compose
logs are retained in `testoutput/java-httpclient5-{headers,disabled}.log`.

## Prototype evidence

Validation on 2026-10-21 used the fixture versions above on Linux amd64,
kernel 7.0.0-1014-aws. These results establish the scoped prototype; they do
not establish production support across Java or Apache client versions.

The clean baseline at `e64f42f70` passed the warm-up gate requiring an exported
TLS client span, then failed the first pooled request: the proxy received zero
traceparents and the downstream created a separate root. The baseline binary
used the original embedded agent and regenerated BPF, in a separate image.

The final regression passed both modes in 356.98 seconds. With headers enabled,
the first request transmitted exactly:

```text
00-ab000000000000000000000000000001-96228a5ad96b98e8-01
```

All spans retained that trace ID. The observed parent chain was:

| Context/span | Span ID | Parent ID |
| --- | --- | --- |
| Incoming remote context | cd00000000000001 | — |
| Source server | bce0edf4af6db88d | cd00000000000001 |
| Source processing | b874ad422e747a73 | bce0edf4af6db88d |
| Source client | 96228a5ad96b98e8 | b874ad422e747a73 |
| Downstream server | abd12cbfa337112a | 96228a5ad96b98e8 |

Two sequential requests reused the same TLS connection with distinct contexts;
eight overlapping callers retained their own contexts. Application-owned
traceparents survived exactly once in both modes. Normal disabled requests
sent no header and produced downstream roots. Method, path, custom header, and
POST body were preserved.

The implementation hooks the classic request executor before serialization,
requests a client-context reservation through the existing Java ioctl bridge,
and lets the existing TLS capture adopt it. Advice removes only its own header
and releases an unconsumed reservation on exit. Header propagation and the
existing `bpf_probe_write_user` capability check gate injection.

Validation passed: the complete Java build/tests/Spotless checks and both JNI
builds; CI-image C formatting and full clang-tidy; BPF generation for amd64 and
arm64; compilation; focused Go race tests; eight focused kernel-verifier
combinations; integration; and Markdown lint. End-to-end and kernel-verifier
execution were on amd64, not arm64.

Full `GOMAXPROCS=4 GOFLAGS=-p=1 make verify -o install-hooks` passed. Shared-host
contention and a competing port 8080 affected earlier runs. The successful run
serialized packages in a private network namespace with a dummy interface and
default route, without excluding packages. The hook installer assumes `.git`
is a directory; required C checks ran manually instead. Metrics passed freshly
in the preceding isolated run and were cached in the final run; Kubernetes
envtest and both collector packages passed freshly in the final run.

## Remaining production validation

- Reconcile the shared Java propagation hooks and ioctl ABI with #3798 and
  other Java prototypes before merging.
- Validate retries, redirects, cancellation, failed writes, and
  `Expect: 100-continue`, including reservation and header cleanup. This fixture
  disables automatic retries and redirects.
- Exercise sustained concurrency and measure overhead; eight overlapping
  callers are regression coverage rather than a sustained-load result.
- Define and test a supported client/JDK/kernel/architecture matrix, including
  unavailable capabilities and integrity mode. Only the stack above has
  end-to-end evidence.
- Validate trace flags (including unsampled incoming context), `tracestate`,
  and context-ownership policy. The known incoming contexts here use flags `01`;
  preserving an explicit foreign header intentionally separates the traces.
- Finish capability diagnostics tracked in #3842, support-matrix and propagation
  documentation, and canonical CI validation against the remaining #3839 criteria.

HttpClient 5 asynchronous APIs, HTTP/2, and other TLS transports require separate
work; this prototype does not establish their propagation support.
