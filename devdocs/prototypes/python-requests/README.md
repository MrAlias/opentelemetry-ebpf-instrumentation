# Requests Session traceparent prototype

This experimental implementation adds W3C `traceparent` injection for synchronous
`requests.Session` HTTP/1.1 requests before TLS encryption. Tracking:
[Requests prototype #3858](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3858),
under [Python coverage #3841](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3841).
The prototype is based on commit `e64f42f703b6b3ff4a5ffd675a6ba01e7440da5f`.

OBI discovers the process and loads its wrapper through the existing runtime
injection queue, a Linux amd64 ptrace bootstrap, and CPython pending calls. A
scoped ioctl bridge reuses OBI's Python request association and HTTP client
context. The wrapper copies serialized headers before TLS, preserving the
PreparedRequest and body. The source application imports no tracing SDK and
loads no agent itself. See the [implementation notes](../../context-propagation.md#python-requestssession-regression-fixture).

## Reproduce

Use Linux amd64 with BTF, Docker Compose, and the repository's Go/toolchain
prerequisites. The integration's OBI container is privileged; the host must allow
ptrace and `bpf_probe_write_user` through its security/lockdown policy. Run from
the repository root after checking out this prototype commit:

```sh
make docker-generate
go test -v -run '^TestSuite_PythonRequestsTraceparent$' \
  -timeout 10m ./internal/test/integration/
```

The fixture builds an OBI-only Python source, an uninstrumented HTTP/TLS proxy
that records every transmitted traceparent field, and an OpenTelemetry Go SDK
downstream. Both `headers` and `disabled` propagation run automatically, with
TCP-option propagation and black-box correlation disabled. Known incoming
traceparents originate in the test driver. The source never injects them.

The assertions cover plaintext HTTP and HTTPS; reuse within and across incoming
requests; overlapping independent incoming contexts; supplied valid/invalid
traceparents; prepared authentication, cookies and unrelated headers; and binary
bodies. They verify exactly one generated traceparent and its client span ID,
known incoming parent → source server → optional existing internal `processing`
span → source client → downstream server. Every edge is checked.

The default source image is digest-pinned CPython 3.14.3, with requests 2.32.5 and
urllib3 2.6.3 installed from the hash-pinned requirements. To exercise another
compatible image, set `REQUESTS_PYTHON_IMAGE`. `REQUESTS_OBI_IMAGE` selects an OBI
image tag; if using a prebuilt image, prebuild all other fixture images and set
`SKIP_DOCKER_BUILD=1` to prevent Compose rebuilding it. Suite logs are written to
`testoutput/` by the existing test harness.

For the focused wrapper tests, select each interpreter being checked:

```sh
python3 -m venv /tmp/obi-requests-test
/tmp/obi-requests-test/bin/pip install --require-hashes \
  -r internal/test/integration/components/pythonrequests/requirements.txt
/tmp/obi-requests-test/bin/python pkg/internal/pythonagent/session_test.py
```

With ptrace/BPF privileges available to the test process, run the real owned-child
attachment tests and the kernel context bridge tests:

```sh
OBI_PYTHON_TEST_EXECUTABLE=/tmp/obi-requests-test/bin/python \
  go test -v -tags=privileged_tests -run '^TestAttach' \
  ./pkg/internal/pythonagent/
go test -v -tags=privileged_tests -run '^TestPythonRequestsContextBridge$' \
  ./pkg/internal/ebpf/generictracer/
```

Repository validation uses `make compile`, `make verify`, and the pinned LLVM
format/lint targets (`make docker-clang-format` and `make docker-clang-tidy`).

## Captured evidence

These captures preserve the observed wire fields and IDs. Native span records
are normalized exported-span excerpts (service, name, kind, trace/span/parent
IDs), rather than complete Jaeger responses. Docker captures contain wire
observations and downstream IDs; source ancestry is checked by the integration
test. All credentials and cookies are synthetic fixture values, including Basic
`prepared:password`. Peer addresses identify local fixture connections.

| Capture | Ordinary requests | Application-owned headers | Evidence |
| --- | --- | --- | --- |
| Native baseline, headers enabled | 2 without a header; downstream roots | 4 preserved | [Wire and exported spans](baseline.json) |
| Native automatic attachment, enabled | 13 with exactly one header | 4 preserved | [Wire and exported spans](native-enabled.json) |
| Native automatic attachment, disabled | 13 without a header; downstream roots | 4 preserved | [Wire and exported spans](native-disabled.json) |
| Final Docker HTTP + HTTPS, enabled | 29 with exactly one header, including readiness | 8 preserved | [Wire observations](docker-headers-observations.json) |
| Final Docker HTTP + HTTPS, disabled | 28 without a header; downstream roots | 8 preserved | [Wire observations](docker-disabled-observations.json) |

The baseline used CPython 3.12.3, requests 2.31.0, urllib3 2.0.7 and OpenSSL
3.0.13; its dependency versions differ from the final pins. The native automatic
runs used CPython 3.12.3/OpenSSL 3.0.13 with the final requests/urllib3 pins.
The enabled native span snapshot contains 11 ordinary chains through
`processing` and two direct server-to-client chains. Final Docker integration
passed in 531.52 seconds using official CPython 3.14.3 (GCC 14.2.0), OpenSSL
3.5.4, requests 2.32.5, urllib3 2.6.3 and OpenTelemetry Go SDK 1.47.0.
The captured baseline is historical; the commands above reproduce the final
regression, rather than the original standalone baseline harness.

Ten wrapper tests and owned-child attachment checks passed on all six versions
in [tested-versions.json](tested-versions.json). Full OBI/TLS pipeline coverage was
run on 3.12.3 and 3.14.3; the six-version matrix does not establish that coverage
on every interpreter/build.

| CPython | OpenSSL | Wrapper / owned-child attachment |
| --- | --- | --- |
| 3.9.25 | 3.5.4 | Passed |
| 3.10.22 | 3.5.9 | Passed |
| 3.11.17 | 3.5.9 | Passed |
| 3.12.3 | 3.0.13 | Passed |
| 3.13.16 | 3.5.9 | Passed |
| 3.14.3 (Clang build) | 3.5.5 | Passed |

Real-child installation, cancellation, stopped-process preservation, and signal
forwarding passed on system 3.12.3 and the exact official 3.14.3 fixture image.
The bridge's enabled/disabled and thread-lifecycle guard tests passed on the
real kernel. BPF generation passed for amd64 and arm64 with Clang 18; CI LLVM
22.1.8 formatting/lint, compilation, and full `make verify` passed. The full
verify run used Go 1.27.2, `GOFLAGS=-p=2`, and `GOMAXPROCS=4`. Earlier runs hit
an unchanged Kubernetes test's ten-second deadline under host contention; the
final full run passed without modifying that test or its dependencies.

## Limits and follow-up

Attachment currently supports Linux amd64 GIL-enabled CPython 3.9–3.14. Arm64
artifacts compile, but runtime attachment and free-threaded builds are unsupported.
The bootstrap requires ptrace and the existing probe-write-user gate, refuses
already-stopped processes and hardware breakpoints, and retains two callback/ack
pages per process until exit. Direct urllib3 use and async clients are excluded.

Issue #3858 keeps architecture/opt-in review, attachment pause and request
overhead measurements, fork/restart/shutdown/coexistence stress, expanded
kernel/client/build coverage, sustained concurrency/export accounting, trace
flags and `tracestate`, and effective-capability reporting open. These passing
functional checks do not establish general Requests support or default enablement.
