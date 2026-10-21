# grpc-js unary TLS propagation regression

The source uses only OBI instrumentation. It receives known incoming HTTP
traceparents and makes unary grpc-js calls over one TLS channel through an
uninstrumented HTTP/2 proxy. The proxy terminates TLS and forwards to an
OpenTelemetry-instrumented gRPC server in a separate process.

From the repository root, build OBI and run:

```sh
make docker-generate
make compile
npm ci --prefix internal/test/integration/components/nodegrpc
node internal/test/integration/components/nodegrpc/reproduce.js
PROPAGATION=disabled node internal/test/integration/components/nodegrpc/reproduce.js
```

Docker must support privileged containers with host PID and network namespaces.
Alternatively, set `OBI_NATIVE=1` to run OBI locally with passwordless `sudo`.
Both modes select only the source's listening port. The source, proxy and server
use ephemeral ports. TLS certificates are generated for each run with OpenSSL.

The default propagation mode is `headers`, disabling TCP-option propagation.
The runner waits for the injected agent and source spans before exercising
overlapping calls, repeated calls, callback follow-ups, shared Metadata,
application-owned traceparent and a background call. It checks one TLS session,
preserved application metadata, exact header values and the complete source
server → source client → downstream server parent chain. Application-owned
traceparents retain their original context; background calls use an independent
root client context. Streaming and the native `grpc` package are outside scope.

Each run prints the temporary directory containing `evidence.json` (received
metadata, SDK span contexts, OBI spans and versions) and `obi.log`. Assertions
fail on missing instrumentation or parentage. To reproduce the original gap
against a pre-change binary, use `BASELINE=1 OBI_BINARY=/absolute/path/to/obi`;
that mode asserts absent generated traceparents while preserving the
application-owned value.
