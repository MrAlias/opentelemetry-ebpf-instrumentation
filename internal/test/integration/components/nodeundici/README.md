# Undici HTTPS propagation regression

This fixture exercises npm `undici.request()` over TLS with HTTP/1.1 and the
package's unchanged global pooled Agent. The source has no OpenTelemetry SDK.
OBI instruments only the source. An uninstrumented TLS proxy records every raw
`traceparent` field before forwarding to a downstream service instrumented by
OpenTelemetry's HTTP instrumentation.

The Config v2 fixture enables `headers` propagation, which excludes TCP-option
propagation. The suite repeats with propagation `disabled`.

```sh
make docker-generate
make testoutput
go test -v -run '^TestNodeUndiciHTTPSPropagation$' -timeout 10m ./internal/test/integration/
```

For focused JavaScript checks, including missing/failed context queries and
reinjection:

```sh
cd internal/test/integration/components/nodeundici
npm ci
node --test transport.test.js
```

These JavaScript tests emulate BPF's synchronous reply. The Go integration test
uses actual OBI injection and eBPF, raw TLS-terminated headers, and Jaeger spans.
It checks three waves of eight concurrent requests with distinct incoming
traceparents, pooled connection reuse, buffered and streamed binary bodies,
object headers, flat arrays, iterable pairs, and `Headers` objects. Existing
mixed-case application traceparents must remain single and unchanged. The SDK
must extract their parent IDs even when OBI propagation is disabled.

For automatically injected headers, the wire span ID must match the emitted OBI
client span and the downstream server's parent. The source server must retain
the known incoming parent. OBI's exported `processing` span may appear between
its source server and client spans.

## Baseline evidence

At repository revision `e64f42f70`, Node.js **22.23.3** and npm Undici **6.29.1**
transmitted **zero traceparents in 12 requests** under OBI with header propagation
enabled. All 12 requests reused one TLS connection, preserved their bodies, and
kept the global dispatcher unchanged. OBI captured source server/client spans;
the downstream started independent traces. This was measured with three local
service processes and the compiled baseline OBI binary. The original temporary
baseline logs were lost across a host restart; the observed results are recorded
here.

The locked downstream dependencies are OpenTelemetry API **1.9.1**, Node SDK
**2.11.0**, resources **2.12.0**, and HTTP instrumentation/exporter **0.223.0**. The container fixture
pins the repository's Node 20 image by digest; container execution must be
reported separately from local Node 22 execution.

## Final evidence

On Linux **7.0.0-1014-aws**, amd64, Go **1.27.2**, the implementation
passed the local three-process check on both Node **20.20.0** and **22.23.3** with
Undici **6.29.1**. Each run sent 24 requests in three concurrent waves, reused eight
TLS connections, transmitted exactly one traceparent per request, and verified
the known incoming parent, the OBI server/client relationship, the wire client
span ID, and the exported downstream SDK server's parent. Four additional
application-header cases preserved their supplied context and bodies.

With propagation disabled, both Node versions transmitted no traceparent on all 24
requests, reused eight connections, and preserved all four application-header
cases. The six focused carrier tests passed on both runtime versions, including
an inspector-style injection where `require` disappears before callbacks run.

The source/SSL binding uses the fd captured for the dispatched request rather
than the thread's last accept/connect event. Readiness probes close their incoming
connections so test traffic is accepted after OBI injection; outgoing requests
always retain the normal pooled dispatcher.

The final container suite passed both modes, including cleanup, in **262.14 s**
on Node **20.20.0** with the normal OBI and fixture images. Each mode completed three
eight-way concurrent waves, reused eight TLS connections, and passed four
existing-header cases. Header mode verified all 24 wire headers and exported span
relationships; disabled mode transmitted none of the 24 automatic headers.
The integration runner was compiled once with `go test -c` and invoked with
`GOMAXPROCS=2`, `-test.parallel=8`, and `-test.run=^TestNodeUndiciHTTPSPropagation$`.

Both pinned images built successfully using their committed Dockerfiles. The
normal OBI image was built with `--resource memory=8g` and
`--resource cpu-quota=400000`. The run used the local image tag
`hatest-obi-node-undici` to avoid replacing another task's image, without a host
binary mount. The final Compose configuration uses the standard `hatest-obi` tag
so CI can reuse its prebuilt image; Compose configuration validation passed.
The runner log and exit status are retained under ignored
`testoutput/.undici-validation/` as
`integration-normal-images-retry.log` and `integration-normal-images-retry.exit`.

Focused Go package tests, the existing 29 Node agent tests, the six carrier tests,
`make lint`, `make compile`, pinned LLVM 22 formatting/tidy, and BPF generation for
amd64 and arm64 passed. Runtime checks were amd64 only. The late header-mode map
guard was regenerated, compiled, and checked with focused C tidy. Final Markdown
lint passed.

Full `make verify` passed with exit code **0**, including module tidying,
import/dependency checks, the assertion analyzer, BPF guard checks, both Go
linters, main-module race/coverage tests, collector race tests, and the license
check. The six carrier tests also passed again on Node **22.23.3**.

Shared-host attempts encountered an envtest port **8080** collision and exceeded
`TestBlockedClients`' **10 s** deadline while creating **1500** pods. Validation
then ran as the original user in private network, PID, and mount namespaces,
with a **6 GiB** tmpfs at `/tmp` for disposable control-plane data and build
scratch. No test assertions or deadlines changed. The envtest package passed
both alone and in the full run; the latter completed in **12.951 s**. The
namespaces and their child processes were cleaned up after validation.

The successful command was
`make verify LINT_EXTRA_ARGS='--timeout=30m --concurrency=2'`, using a private Go
cache, `GOTMPDIR=/tmp`, `TMPDIR=/tmp`, `GOMAXPROCS=8`, `GOFLAGS=-p=2`, and
`GOMEMLIMIT=2GiB` inside those namespaces. Logs, exit codes, and the disposable
runner are retained under ignored `testoutput/.undici-validation/` as
`verify-private-namespace.log` / `.exit`,
`envtest-private-namespace.log` / `.exit`, `run-isolated.sh`, and
`namespace-setup.sh`. The runner passed Bash syntax checks and ShellCheck
**0.10.0**. Earlier failed-attempt logs are retained in the same directory.

## Boundaries

Built-in `fetch`, npm Undici's other APIs, plaintext HTTP, and HTTP/2 are outside
this regression. The hook recognizes the installed npm package's request and
handler types; bundled or renamed package layouts and future internal changes
need separate validation. The test uses the default dispatcher and HTTP/1.1
pipelining setting, without installing interceptors or replacing the dispatcher.

The context query uses OBI's existing server context, manual-span parent override,
and connection trace map. It requires the existing user-memory-write capability
and lockdown checks to pass. The inherited four-digit fd sentinel limits this
path to descriptors below 10000. Missing context or failed queries leave the
original request unchanged. Application-provided traceparents retain their own
context rather than being replaced with OBI's generated client context.
