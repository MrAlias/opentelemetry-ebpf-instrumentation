# Java HttpClient HTTPS propagation

OBI can inject a W3C `traceparent` into Java 11+ `java.net.http.HttpClient.send()` and `sendAsync()`
requests sent over HTTPS with HTTP/1.1. Enable header propagation through the existing
`capture.engine.propagation.context_propagation: headers` setting in Config v2.
TCP-option propagation is independent and is not required.

The injected OBI Java agent must be enabled, and the kernel must support
`bpf_probe_write_user` under OBI's existing capability and lockdown checks.
On kernels that require it, OBI needs `CAP_SYS_ADMIN`. If those checks fail,
OBI leaves the request unchanged. No additional configuration is introduced.

## Injection and span identity

The agent tracks internal request instances and copies used for redirects and retries.
Each public `sendAsync()` call captures its own parent, including reentrant calls.
Its temporary caller scope is restored before returning the original future;
request ownership remains until that future completes, fails, or is cancelled.
Completion cleanup removes ownership and reservations without setting or clearing
thread-local context on the completion thread. Application completion callbacks
and later executor tasks cannot inherit this propagation scope.
Tracking for synchronous `send()` is removed when it returns or throws.

The HTTP/1.1 header hook runs before TLS encryption. It obtains the connected
socket's addresses and asks eBPF to reserve an outbound client span identity.
At entry to `send()` or `sendAsync()`, a separate control packet captures the current Java
server context before work moves to pooled workers. The captured parent is
retained only for that request, so concurrent calls, retries on another
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
injection. Reservations are consumed on observation, released when the owning call
completes, and removed when the socket closes. Release checks the reserved value so
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

Only actual HTTPS HTTP/1.1 requests from `send()` and `sendAsync()` are eligible.
HTTP/2, plaintext HTTP, other clients, and messaging use their
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

The asynchronous suite instruments only the source with OBI and runs the
OpenTelemetry Java agent on the downstream. The proxy is not instrumented, and
TCP-option propagation is disabled. It checks exactly one header with the incoming
trace ID and exported client span ID, the source server/client ancestry (including
OBI processing spans), and direct downstream server parentage. It also exercises
concurrent distinct contexts, connection and request reuse, application-owned
headers, disabled propagation, and callback/executor scope isolation.

The integration fixture records the headers received by a TLS-terminating proxy
and checks the exported downstream trace. It covers application-owned headers,
disabled propagation, concurrent and pooled distinct parents, request reuse,
retries, redirects, authentication, request bodies, async calls, HTTP/2 and
HTTP/1.1 fallback, virtual threads on Java 21+, oversized headers, and cleanup
after timeouts, interruption, TLS rejection, and connection failure.

Run the focused integration suite with:

```sh
go test -v -count=1 -run '^TestJavaHTTPClient(Async)?Traceparent$' -timeout 15m ./internal/test/integration/
```

To select another JDK, set `JAVA_HTTPCLIENT_RUNTIME_IMAGE` to a digest-pinned
Java 11+ runtime image before building the fixture. Unit compatibility tests
also run in the Java agent CI JDK matrix. The JMH
`JdkHttpClientPropagationBenchmark` compares bounded byte-buffer preparation
against the prototype's string decoding and splitting; it does not measure
total application or eBPF overhead.
