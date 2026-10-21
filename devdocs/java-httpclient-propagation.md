# Java HTTP client HTTPS propagation

OBI can inject a W3C `traceparent` into synchronous Java 11+ `java.net.http.HttpClient.send()`
requests sent over HTTPS with HTTP/1.1. Enable header propagation through the existing
`capture.engine.propagation.context_propagation: headers` setting in Config v2.
TCP-option propagation is independent and is not required.

The injected OBI Java agent must be enabled, and the kernel must support
`bpf_probe_write_user` under OBI's existing capability and lockdown checks.
On kernels that require it, OBI needs `CAP_SYS_ADMIN`. If those checks fail,
OBI leaves the request unchanged. No additional configuration is introduced.

## Injection and span identity

The agent tracks requests created during a synchronous `send()`, including
internal copies used for redirects and retries. Public `sendAsync()` calls
temporarily suspend that tracking, including calls made reentrantly during a
synchronous send. Tracking is removed when `send()` returns or throws.

The HTTP/1.1 header hook runs before TLS encryption. It obtains the connected
socket's addresses and asks eBPF to reserve an outbound client span identity.
At entry to `send()`, a separate control packet captures the current Java
server context before work moves to pooled workers. The captured parent is
retained only within that `send()`, so concurrent calls, retries on another
worker, and new connections keep their own parent. Each attempt receives a fresh
client span ID using OBI's existing trace flags policy. An acknowledged empty
context starts a new trace; an unacknowledged capture skips injection.
The agent adds the resulting header to new serialized buffers, preserving
the application's immutable request and its headers.

When the existing Java TLS observation path reports the plaintext request,
eBPF compares the injected value with the reservation and uses the reserved
identity for the emitted client span. The header's trace ID therefore matches
the incoming trace, and its parent ID is the outbound client span ID. A
downstream service that extracts this header creates a child of that client span.

Java request tracking and retained native packets are each capped at 10,000
entries per JVM; capacity exhaustion skips injection without evicting active
requests. Reservations are keyed by PID and the full connection tuple. The bounded hash
map does not evict active reservations; when full, new requests are sent without
injection. Reservations are consumed on observation, released when `send()`
exits, and removed when the socket closes. Release checks the reserved value so
an older request cannot delete a later request's state on a reused connection.

## Ownership and compatibility

Any application-supplied `traceparent` prevents injection. This includes mixed-case
names, invalid or empty values, and multiple values. OBI neither repairs nor adds
to an application-owned header. Other headers, including `tracestate`, retain
their application-provided values; OBI does not synthesize `tracestate`.

OBI checks the required JDK class, field, and method shapes before installing
the propagation hooks. The secure-connection and socket accessors are resolved
once inside the JDK module and cached. An incompatible layout disables this
feature with one diagnostic. Ordinary socket-close failures leave the original
headers intact and do not disable propagation for later requests.

These additional control operations preserve the existing agent contract version.
The agent publishes `otel.obi.java.agent.httpclient.propagation` to distinguish
this feature from an older or disabled agent. OBI warns when an already attached
agent cannot provide it. Restart the JVM to load the newer agent; a running
Java agent cannot be replaced. Agent options are established at attachment, so enabling propagation
for a JVM originally attached with header propagation disabled also requires a
JVM restart. Disabling header propagation in OBI always prevents injection.

## Scope and validation

Only actual HTTPS HTTP/1.1 requests from synchronous `send()` are eligible.
`sendAsync()`, HTTP/2, plaintext HTTP, other clients, and messaging use their
existing instrumentation paths without this injection. An HTTP/2 preference
that negotiates HTTP/1.1 is still an HTTP/1.1 request.

The complete serialized header block after injection must fit within the
existing Java plaintext capture limit of 16 KiB. Larger headers are sent
unchanged, avoiding propagation with a client span identity that OBI cannot
correlate. Reflection failures and unavailable reservation state likewise
leave the request unchanged. Trace continuity is not guaranteed when the
underlying Java TLS observation itself is unavailable. Parent capture uses the
current Java server context; this feature does not add context inheritance for
new threads or tasks. It never infers a virtual thread's parent from stale
carrier-thread state.
With header propagation disabled, the existing Java TLS path can export a
virtual-thread HttpClient client span in a separate trace.

The integration fixture records the headers received by a TLS-terminating proxy
and checks the exported downstream trace. It covers application-owned headers,
disabled propagation, concurrent and pooled distinct parents, request reuse,
retries, redirects, authentication, request bodies, async calls, HTTP/2 and
HTTP/1.1 fallback, virtual threads on Java 21+, oversized headers, and cleanup
after timeouts, interruption, TLS rejection, and connection failure.

Run the focused integration suite with:

```sh
go test -v -count=1 -run '^TestJavaHTTPClientTraceparent$' -timeout 15m ./internal/test/integration/
```

To select another JDK, set `JAVA_HTTPCLIENT_RUNTIME_IMAGE` to a digest-pinned
Java 11+ runtime image before building the fixture. Unit compatibility tests
also run in the Java agent CI JDK matrix. The JMH
`JdkHttpClientPropagationBenchmark` compares bounded byte-buffer preparation
against the prototype's string decoding and splitting; it does not measure
total application or eBPF overhead.

## Apache HttpClient 4 synchronous execution

The OBI Java agent also injects `traceparent` for synchronous
`org.apache.http.impl.client.CloseableHttpClient.execute()` calls over HTTPS
HTTP/1.1 using JSSE `SSLSocket` streams. Apache HttpClient 4.5.14 on Java 21 is
covered by the integration fixture. This uses the same header-propagation
configuration, kernel capability checks, parent capture, and client span
reservations described above; TCP-option propagation is not required.

The scope starts at `execute()` and covers its overloads. Each
`HttpRequestExecutor.doSendRequest()` attempt can inject into the first TLS
plaintext write on its managed connection's socket. Writes through other sockets
on the same thread are excluded. The agent copies that write before encryption, preserving the
application's request object, body bytes, unrelated headers, and `tracestate`.
An existing `traceparent`, including a mixed-case name, prevents injection.
Reservations are released when `execute()` returns or throws, so pooled
connections and concurrent calls retain their own incoming context.

The first write must contain the complete HTTP/1.1 header block, and the entire
write after injection must fit the existing 16 KiB plaintext capture limit.
Split headers and larger writes are sent unchanged. Later body writes are never
treated as headers, even when their contents resemble an HTTP request.
This path does not enable injection for HttpClient 5, Apache's asynchronous
client, HTTP/2, plaintext HTTP, or custom transports that bypass these synchronous
execution and JSSE stream methods. Those paths retain their existing behavior.
Restart JVMs with an already attached older OBI agent to load these new hooks.

The Apache fixture uses an OBI-only source, an uninstrumented TLS-terminating
proxy that records received headers, and an OpenTelemetry SDK downstream. It
checks exactly one transmitted header and the exported source server → source
client → downstream server chain (including OBI's existing internal `processing`
span when emitted), pooled connection reuse with distinct parents,
concurrent contexts, application-owned headers, disabled propagation, and body
and unrelated-header preservation.

```sh
go test -v -count=1 -run '^TestJavaApacheHTTPClientTraceparent$' -timeout 10m ./internal/test/integration/
```
