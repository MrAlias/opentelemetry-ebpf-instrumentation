# Python gRPC TLS propagation PoC

Baseline captures, final integration results, tested versions, and the
reproduction entry point are collected in the
[prototype evidence](prototypes/python-grpc/README.md).

With header propagation enabled, OBI attaches a Python hook to selected
CPython 3.14 processes using the interpreter's remote-execution interface.
The PoC supports grpcio 1.78.0 and synchronous unary-unary calls made through
`grpc.secure_channel()`. The process must have imported `grpc` before
attachment and create its channels after attachment. OBI logs
`Python gRPC agent attached` when installation finishes.

The hook covers blocking calls and `with_call`. Futures, streaming,
`grpc.aio`, pre-existing channels, and other grpcio versions are outside this
PoC. Plaintext channels continue through the existing native instrumentation.
No OpenTelemetry SDK is needed in the source application.

Before grpcio hands a blocking call to native workers, the hook asks BPF for
the caller's trace context through a direct-pointer libc ioctl buffer. The
pointer keeps BPF's writes visible even though this private ioctl returns
`ENOTTY`. BPF creates a client span under the caller's current Python context,
which can include an internal processing span below the incoming server span.
The hook appends that client's W3C traceparent
to a copy of the outbound metadata and reports completion through the same
buffer. BPF emits the existing gRPC client event. Every invocation owns its
buffer; neither channels nor native workers retain trace context.
Parent lookup uses the active server trace on the calling OS thread. Parentage
from an asyncio task without a current-thread server trace is outside this PoC.

An application-supplied `traceparent` takes precedence: the hook preserves it
and delegates the call without creating another client span. Other metadata,
including duplicate keys and binary values, is preserved. Metadata added later
by call-credential plugins is not inspected by this PoC.

Attachment requires access to the target's process memory and writable `/tmp`
in its mount namespace. Non-free-threaded final CPython 3.14 builds with remote
execution enabled are supported through the existing CPython runtime resolver.
Only the main interpreter is targeted. OBI refuses an already-pending remote
execution request. The main thread must return to Python within the attachment
deadline. A pending script is retained in the target's `/tmp/.obi-python-*`
directory if acknowledgement times out, so a delayed interpreter can still
read it. Successful attachment removes the temporary files. Concurrent use of
another remote-execution tool during attachment is outside this PoC.

The regression uses an OBI-only Python HTTP source, a shared secure channel,
an uninstrumented TLS-terminating HTTP/2 proxy, and an OpenTelemetry SDK gRPC
server. TCP-option propagation is disabled. It checks concurrent and repeated
RPCs, metadata ownership, disabled propagation, and exported server → client →
server parentage.

```sh
go test -v -run '^TestSuite_PythonGRPCTLS$' -timeout 10m ./internal/test/integration/
```

The hook's focused tests use real TLS grpcio calls in the regression image:

```sh
docker build -t hatest-python-grpc-tls \
  -f internal/test/integration/components/python_grpc_tls/Dockerfile .
docker run --rm -v "$PWD/pkg/internal/cpython/grpc:/agent:ro" -w /agent \
  hatest-python-grpc-tls python -m unittest -v agent_test
go test ./pkg/internal/cpython/grpc
```
