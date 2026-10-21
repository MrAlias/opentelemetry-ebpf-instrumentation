# Reactor Netty HTTPS/HTTP/1.1 propagation prototype

This unmerged prototype carries the OBI parent through Reactor subscriber
`Context` and prepares the client span before HTTP headers are serialized. It
reuses the Java ioctl transport, parent lookup, Netty connection extraction, and
the TLS parser's adoption of an entry in `outgoing_trace_map`.

The scope is direct `reactor.netty.http.client.HttpClient` HTTPS/HTTP/1.1 calls.
HTTP/2, WebSocket, and Spring WebClient-specific instrumentation are excluded.

## Reproduction

Run from the repository root on a host capable of running OBI integration tests:

```sh
go test -v -run '^TestJavaReactorTraceparent$' -timeout 10m ./internal/test/integration/
```

The Compose fixture starts an OBI-only Java source, an uninstrumented TLS proxy,
an OpenTelemetry SDK downstream, and Jaeger. Only the source JVM is selected for
OBI instrumentation. The proxy forwards HTTP after terminating TLS and does not
initialize an SDK. Propagation modes are `headers` and `disabled`; TCP-option
propagation is disabled in both.

The source subscribes to a shared publisher using a shared client with one Netty
event loop and a pool of at most two TLS connections. Eight concurrent request
pairs have distinct incoming traceparents; one request per pair uses
`subscribeOn(boundedElastic())`. Downstream echoes all received traceparent
values, its SDK span identity, the TLS peer, and active subscription count.

## Observed results

The baseline at `e64f42f703b6b3ff4a5ffd675a6ba01e7440da5f` was exercised with
the same native fixture before adding instrumentation. The final Compose run
also verified OBI's automatic Java attachment.

| Case | Ordinary requests | Received traceparents per request | Result |
| --- | ---: | ---: | --- |
| Baseline, headers enabled | 16 | 0 | SDK downstream starts independent traces |
| Prototype, headers enabled | 16 | 1 | Incoming trace and complete exported ancestry match |
| Prototype, propagation disabled | 16 | 0 | Local source ancestry retained; downstream starts independent traces |

Each mode also preserved exactly one application-supplied mixed-case
`TraceParent` header, and the SDK downstream followed that supplied parent.
Enabled and disabled runs reached two overlapping subscriptions and reused at
most two outbound TLS connections. The enabled assertions compare the transmitted
parent ID with the exported OBI client span ID and the downstream server's parent.
An existing OBI processing span may sit between source server and client.

One final enabled request illustrates the checked ancestry:

```text
trace:           000000000000000018e09b43c5608306
incoming parent: 0000000000000001
source server:   660b848fa92ea555
processing:      5ce18d14f156d73d
source client:   21fb03354e3d8c0b
downstream:      69bdffb0f3ce79f3
wire header:     00-000000000000000018e09b43c5608306-21fb03354e3d8c0b-01
```

## Versions and validation

Runtime tests used Linux amd64, kernel `7.0.0-1014-aws`, Reactor Netty 1.2.15,
Reactor Core 3.7.16, Netty 4.1.131.Final, JDK TLS, and downstream Go OpenTelemetry
SDK 1.47.0. The native baseline/final comparison used Temurin 21.0.8+9; the final
Compose run used Temurin 21.0.12.1+1 and Go 1.27.2.

Validation passed: the Compose regression in both modes, 144 Java tests,
Spotless, focused Go tests, eBPF generation for amd64/arm64, LLVM 22 formatting
and clang-tidy, Markdown lint, and full `make build` including `make verify`,
race tests, and compilation. The local envtest suite required a private network
namespace and memory-backed temporary storage to avoid host port and disk
contention; its assertions were unchanged. Both JNI architectures compiled;
ARM64 runtime behavior was not tested.

## Remaining investigation

- An initial Compose run with reused incoming HTTP connections failed one
  incoming trace-ID assertion. A fresh-ingress control passed, but the cause is
  unresolved. The committed fixture uses fresh incoming connections and keeps
  each server handler open until its outbound response completes. It still tests
  outbound TLS reuse; it does not establish general asynchronous server ingress
  support.
- Review the reach and overhead of wrapping Mono/Flux subscriptions, including
  subscription/fusion behavior, allocation, reflection, and ioctl cost.
- Exercise cancellation, errors, retries, redirects, request bodies, repeated
  subscriptions, and sustained concurrency with separate checks for wrong
  headers, missing exports, and duplicate spans.
- Validate trace flags, existing `tracestate`, application-owned context and
  local span identity, additional client/JDK/classloader layouts, and unavailable
  capabilities. Injection depends on the existing `bpf_probe_write_user` and
  lockdown/integrity gates. Native TLS providers remain untested.
- Complete operator capability diagnostics and support-matrix documentation
  before treating the prototype as supported coverage.
