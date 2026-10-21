# .NET HttpClient Activity prototype

This prototype supports evaluation of
[#3845](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3845).
It demonstrates async span association for `HttpClient.SendAsync()` over HTTPS
HTTP/1.1. It does not establish completion of that issue's production acceptance
criteria.

## Approach

Default `System.Net.Http` diagnostics already inject a W3C traceparent and
preserve an application-supplied header. The prototype reuses OBI's diagnostic
socket and EventPipe collector to export the native client activity and associate
its ASP.NET parent with OBI's outer server span. Matching BPF client observations
supply metrics without exporting a second client trace. Existing TLS probes also
attach to CoreCLR's OpenSSL wrapper before its first lazy load.

No application SDK, profiler, or code changes are required. The validated scope
is ASP.NET Core requests with known incoming W3C context and outbound HTTPS
HTTP/1.1 on .NET 8 CoreCLR, Linux x86-64. Live final coverage used .NET 8.0.27;
the baseline and EventPipe replay fixture used 8.0.0. Broader compatibility has
not been established. See [runtime details](dotnet.md#http-tracing-and-context-propagation).

## Baseline and final evidence

The baseline at `e64f42f70` transmitted one traceparent, but OBI's client span had
no parent and did not match the transmitted span ID. These representative traces
come from the baseline and final integration runs:

| Observation | Baseline (.NET 8.0.0) | Prototype (.NET 8.0.27) |
| --- | --- | --- |
| Trace ID | `99a119964f2f4d4ba1e49ab445c006e9` | `e28ce1abbe462bda3bacbadb92280a8c` |
| Source server ID | `db7b263bb9418f8b` | `8daae1177eba4b77` |
| Source client ID | `3124060694a2dfae` | `00f3f42780c2a77a` |
| Source client parent | absent | `8daae1177eba4b77` |
| Wire span ID / downstream parent | `92dfc5fc1c2dc3c7` | `00f3f42780c2a77a` |
| Downstream server ID | not recorded here | `6056727e87621621` |

The fixture uses an OBI-only source, a TLS-terminating proxy without
instrumentation that records header values and connection peers, and an OTel SDK
downstream. It explicitly requests and verifies HTTP/1.1, enables header
propagation, and disables TCP-option and black-box correlation.

The four-mode integration matrix passed. Each default-propagation run records
13 requests with exactly one traceparent each and verifies 11 complete
source server → source client → downstream server chains. Coverage includes eight
overlapping async calls with distinct incoming contexts, sequential pooled
connection reuse, cancellation followed by a successful request, and preservation
of an application-supplied header with a different trace ID. The enabled case
also passed three additional consecutive runs; this is bounded repeatability
coverage, not a sustained-load qualification.

Disabling OBI propagation preserves independent framework propagation. Explicit
runtime opt-out (`DOTNET_SYSTEM_NET_HTTP_ENABLEACTIVITYPROPAGATION=false`) is
respected and remains unsupported for independent injection.

## Validation and follow-up

`make verify`, `make compile`, focused unit tests, source/peer Docker builds,
integration-test compilation, and `make lint-markdown` passed. The full race suite
used private temporary files and a private network namespace to avoid unrelated
shared ELF-fixture and Kubernetes port collisions; no repository changes were
made for those environment issues.

Run the integration regression with:

```sh
go test -v -run '^TestSuite_DotNetHTTPClientTraceparent$' -timeout 10m ./internal/test/integration/
```

Before proposing production support, establish maintainer agreement on native
Activity ownership, measure EventPipe overhead under sustained concurrency, and
exercise diagnostic-socket unavailability, event loss, reconnection, and fallback
behavior. Trace flags, `tracestate`, request bodies, additional runtime versions
and architectures, operator-visible capability reporting, and support-matrix
documentation still need qualification against #3845.
