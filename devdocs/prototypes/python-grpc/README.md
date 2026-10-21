# Synchronous Python gRPC TLS traceparent prototype

This branch is an experimental implementation for [#3868](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3868),
under the Python propagation work in [#3841](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3841).
It adds W3C `traceparent` metadata to OBI-owned synchronous unary-unary
`grpc.secure_channel()` calls before grpcio hands them to native workers.
The source application uses no OpenTelemetry SDK or separate auto-instrumentation.

The [implementation notes](../../python-grpc-context-propagation.md) describe
the attachment, per-call context bridge, supported scope, and reproduction
commands. The integration fixture is in
`internal/test/integration/components/python_grpc_tls/`, and its assertions
are in `internal/test/integration/python_grpc_tls_test.go`.

## Evidence

The [pre-change baseline summary](evidence/baseline-summary.json),
[received metadata](evidence/baseline-observations.json), and
[exported traces](evidence/baseline-traces.json) were captured on base commit
`e64f42f703b6b3ff4a5ffd675a6ba01e7440da5f`. With header propagation
enabled and TCP-option propagation disabled, 24 ordinary RPCs transmitted
no traceparent and produced no source gRPC client spans. Eight callers shared
one channel and TLS connection, with up to eight concurrent HTTP/2 streams.
Four application-supplied traceparents arrived once and unchanged. The
[disabled baseline](evidence/disabled-baseline-summary.json) also sent no
generated traceparent.

The [final integration run](evidence/final-integration.txt) passed both
`headers` and `disabled` modes, with 32 RPCs in each mode. In `headers` mode,
the test checks exactly one generated traceparent on each of 24 ordinary RPCs
and one later RPC, the incoming trace ID, distinct client span IDs on repeated
calls, and source server → optional internal processing span → source client
→ downstream server parentage. Seven application-supplied traceparents remain
unchanged. In `disabled` mode, no generated traceparent is received. Both
modes check duplicate and binary metadata, one shared TLS connection, and
overlapping HTTP/2 streams through an uninstrumented TLS terminator.

The [validation record](evidence/validation-results.txt) lists focused tests,
BPF verifier, generation, compilation, formatting, and lint checks that passed.
The baseline used CPython 3.12.3, grpcio 1.78.0, OpenTelemetry SDK 1.39.1,
gRPC instrumentation 0.60b1, and proxy OpenSSL 3.0.13. The final fixture used
CPython 3.14.3, grpcio 1.78.0, OpenTelemetry SDK 1.39.1,
gRPC instrumentation 0.60b1, and OpenSSL 3.5.4. The runtime versions therefore
differ between the baseline and the final integration; the result establishes
feasibility in the tested setup, not a compatibility claim across versions.

Run the integration with:

```sh
go test -v -run '^TestSuite_PythonGRPCTLS$' -timeout 10m ./internal/test/integration/
```

The test builds the pinned Python image and OBI image and requires Docker and
the privileges needed by OBI's eBPF and CPython attachment paths. See the
[implementation notes](../../python-grpc-context-propagation.md) for focused
Python and Go checks.
