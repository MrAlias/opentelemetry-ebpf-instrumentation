# ADR: Bridge socket-owned OBI context into Java

- Status: accepted for proof of concept
- Scope: Apache/OpenSSL outbound HTTPS to auto-instrumented Jetty and bounded
  inbound-Netty fixtures
- Last updated: 2026-07-28

## Decision

OBI owns the cross-process correlation context. A request-scoped eBPF entry is
consumed once by a dynamically attached Java helper through a forced
`getsockopt` path or a credential-checked Unix socket fallback. A separate
external extension adds an extract-only `obi` propagator to an official,
unmodified OpenTelemetry or Splunk Java agent.

The primary `getsockopt` path runs on the backend's accepted application
socket. A connected dummy socket probes hook availability only. This
intentionally supersedes issue #20's cached dummy-socket retrieval proposal so
socket-local negotiation, tuple, and network namespace can bind the claim to
the connection that received the request.

The propagator stages the candidate before server span creation. A valid W3C
context has precedence. The OBI candidate is fail-open: missing, stale,
malformed, timed-out, or unauthorized data produces no parent rather than an
incorrect one. Existing Java span suppression remains in force; bridge setup
does not authorize duplicate OBI Java server spans.

## Why

Apache terminates an inbound request and opens a separate TLS connection to
Java. The Java agent cannot see the upstream Apache span in HTTP headers when
OBI uses socket-level propagation. OBI can correlate the outbound Apache
request with the accepted Java socket, but the official Java agent owns server
span creation. A one-shot handoff joins those two ownership domains without
forking the upstream agent or requiring a proprietary backend.

## Boundaries

- Primary keying is request/socket ownership established by OBI, never a
  caller-supplied PID or marker.
- Primary retrieval uses the accepted backend socket; a dummy socket is never
  a request-data carrier.
- Exact executor, ForkJoin, Netty, and virtual-thread task captures share a
  one-shot accepted-socket holder with the generation-bound task token. Unknown
  framework handoffs still fail open instead of using a connection-only guess.
- The marker header exists only in the verifier; it is not an input to bridge
  lookup.
- Unix callers are authenticated from kernel peer credentials.
- Contexts have bounded lifetime and one-shot take/discard semantics.
- The extension may read a parent but may not inject HTTP propagation headers.
- HTTP/1.1 is the only demonstrated backend protocol.

## Alternatives rejected

- **Fork the Java agent:** creates an unmaintainable distribution and does not
  prove compatibility with official artifacts.
- **Inject `traceparent` in Apache traffic:** bypasses the socket handoff being
  evaluated and changes application-visible network bytes.
- **Export OBI and Java roots and join later:** does not produce a valid trace
  parent relationship and depends on backend-specific processing.
- **Trust caller identity fields on a Unix socket:** allows confused-deputy and
  context-consumption attacks.
- **Use request markers as a correlation key:** useful for test selection, but
  unsafe and semantically wrong as a production bridge identity.

## Consequences

The implementation needs versioned fixed-size ABIs, feature detection,
bounded timeouts and maps, classloader-safe extension loading, and explicit
diagnostics. Compatibility is narrower than general Java auto-instrumentation;
the matrix must report unsupported and untested cells rather than infer them
from versions.
