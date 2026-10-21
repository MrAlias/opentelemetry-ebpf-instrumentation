# JDK HttpClient sendAsync HTTPS/HTTP/1.1 prototype

This prototype extends the synchronous propagation implementation from
`054656d1dc4e39e5aa90b2a3ab80b94dea978b46` (#3798). It is an unmerged,
validated snapshot; it must be reconciled with subsequent synchronous changes
before proposing production support. Java client coverage is tracked in #3839.

## Mechanism and scope

The public `sendAsync()` entry captures the current server parent using the
existing control packet. Internal request copies retain that ownership through
HTTP/1.1 serialization, which uses the existing header injector and native span
reservation. The caller scope is restored before returning the original future.
Completion releases request ownership and reservations without modifying the
completion thread's context. No executor or completion classes are transformed,
and no C, JNI, or eBPF changes are added by this extension.

Only actual HTTPS/HTTP/1.1 requests are eligible. HTTP/2, plaintext HTTP, and
other clients are outside this prototype. See the
[propagation documentation](../../../../../devdocs/java-httpclient-propagation.md)
for existing capability, ownership, and size limits.

## Baseline and final evidence

The source service has OBI only. A non-instrumented Go TLS-terminating proxy
records the received headers and forwards to a downstream using OpenTelemetry
Java agent 2.21.0. Header propagation is enabled and TCP-option propagation is
disabled. Runtime validation used JDK 21.0.12.1 on Linux amd64.

At the base commit, the asynchronous HTTPS request returned HTTP 200 and
preserved application headers, but the proxy received zero `traceparent`
headers. The new integration assertion failed as expected.

The final run received exactly one header:

```text
00-11111111111111111111111111111111-4b29c541747beb22-01
```

The captured trace had these identities:

| Role | Span ID | Parent span ID |
| --- | --- | --- |
| Incoming context | `2222222222222222` | — |
| OBI source server | `790a5876e2e4a7ec` | `2222222222222222` |
| OBI source client | `4b29c541747beb22` | `790a5876e2e4a7ec` |
| OTel downstream server | `a943ae840bdc00ff` | `4b29c541747beb22` |

All spans used incoming trace ID `11111111111111111111111111111111`.
The proxy recorded HTTP/1.1, application header `preserved`, and existing
`tracestate: fixture=preserved`.

## Regression coverage and validation

`TestJavaHTTPClientAsyncTraceparent` checks generated headers, reuse of the
same immutable request, pooled TLS connection reuse with distinct parents,
application-supplied headers, four overlapping distinct traces, four
overlapping parents within one trace, a subsequent request, and propagation
disabled. It checks actual headers, exported client identity, source ancestry,
downstream parentage, caller/completion/executor scope isolation, and eventual
zero request/reservation counts. Supplied headers are preserved; the full
OBI-owned span-chain assertion applies to generated-header cases.

Recorded results for this snapshot:

- Java suite: 154 tests, zero failures or errors; Spotless passed.
- Async integration: enabled and disabled modes passed (176.68 seconds total).
- Existing integration regressions: async, reentrant async, and HTTP/2 passed
  (68.88 seconds total). HTTP/2 checks exclusion from this injection path.
- `make compile` and `make lint-markdown` passed.
- `make verify -o install-hooks TEST_OUTPUT=./testoutput/sendasync-validation`
  passed, including root/collector lint, module tidy, race tests, and licenses.
  Hook installation was skipped because the linked worktree has a `.git` file.
- The embedded helper matches the compiled class. Both packaged native
  libraries are unchanged from the base.

Integration execution used temporary port/endpoint overlays and uniquely
tagged fixture images to avoid shared-host collisions. The overlays retained
the canonical assertions; the generated evidence case used the fixed incoming
context above. The canonical fixture Dockerfile also built successfully.
Repository verification ran as the normal workspace user in a private network
namespace with isolated temporary directories and bounded build parallelism.
These runs do not establish canonical CI execution or sustained-load behavior.

To run the committed async integration test in an isolated development host:

```sh
go test -v -count=1 -run '^TestJavaHTTPClientAsyncTraceparent$' -timeout 15m ./internal/test/integration/
```

## Remaining production work

- Reconcile this snapshot with the latest synchronous propagation work in
  #3798, including its outstanding sustained-load trace-linkage concerns.
- Run the supported JDK and architecture matrix; this prototype has runtime
  evidence only for JDK 21 on Linux amd64.
- Exercise repeated sustained concurrency and network failures, timeouts,
  cancellation, redirects, and retries; measure end-to-end overhead and state
  retention. Unit lifecycle tests do not replace transport-level fault tests.
- Validate trace flags and application-owned context policy, retain
  `tracestate`, and integrate canonical CI coverage and capability diagnostics
  (#3842) before treating this slice as complete.

Existing kernel permission/lockdown requirements, the 16 KiB serialized-header
limit, and bounded request/reservation tracking still apply. Use the matching
OBI binary and embedded agent from this snapshot. Already-attached JVMs need a
restart to load a different agent; an existing agent cannot be replaced live.
