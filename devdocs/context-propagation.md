# Context Propagation Architecture

This document explains how OpenTelemetry context propagation works in the eBPF instrumentation, including the coordination between different injection layers and the mutual exclusion mechanism.

## Table Of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [Egress (Sending) Flow](#egress-sending-flow)
  - [Execution Order](#execution-order)
    - [Scenario A: Go HTTP or SSL/TLS (uprobes involved)](#scenario-a-go-http-or-ssltls-uprobes-involved)
    - [Scenario B: Plain HTTP (no uprobes, kprobes only)](#scenario-b-plain-http-no-uprobes-kprobes-only)
    - [Scenario C: Non-HTTP TCP (no uprobes, socket not in sockmap)](#scenario-c-non-http-tcp-no-uprobes-socket-not-in-sockmap)
  - [Mutual Exclusion Mechanism](#mutual-exclusion-mechanism)
    - [Case 1: Traffic in sockmap with Go/SSL uprobes](#case-1-traffic-in-sockmap-with-gossl-uprobes)
    - [Case 2: Traffic in sockmap without uprobes (plain HTTP via kprobes)](#case-2-traffic-in-sockmap-without-uprobes-plain-http-via-kprobes)
    - [Case 3: Traffic NOT in sockmap (tpinjector doesn't run)](#case-3-traffic-not-in-sockmap-tpinjector-doesnt-run)
- [Ingress (Receiving) Flow](#ingress-receiving-flow)
  - [Execution Order](#execution-order-1)
  - ["Last One Wins" Strategy](#last-one-wins-strategy)
  - [Why "Last One Wins" on Ingress?](#why-last-one-wins-on-ingress)
- [The outgoing_trace_map](#the-outgoing_trace_map)
  - [tp_info_pid_t::valid (u8)](#tp_info_pid_tvalid-u8)
  - [tp_info_pid_t::written (u8)](#tp_info_pid_twritten-u8)
- [The server_traces Map](#the-server_traces-map)
- [The incoming_trace_map](#the-incoming_trace_map)
- [The sock_dir sockmap](#the-sock_dir-sockmap)
- [Summary](#summary)

For trace-log correlation (log enricher / `traces_ctx_v1` map), see [trace-log-correlation.md](trace-log-correlation.md).

## Overview

Context propagation allows distributed tracing by injecting trace context (trace ID, span ID) into outgoing requests. The eBPF instrumentation supports three injection methods:

1. **HTTP/1 headers** (L7) - `Traceparent:` header in plaintext HTTP requests
2. **HTTP/2 / gRPC HPACK** (L7) - per-stream `traceparent` field in HEADERS frames. This is the only network mechanism for multiplexed HTTP/2. See [gRPC/HTTP2 Context Propagation](grpc-context-propagation.md).
3. **TCP options** (L4) - Custom TCP option (kind 25) for HTTP/1 and non-multiplexed TCP. **Not used for HTTP/2 or gRPC** — a connection-scoped option cannot represent N concurrent stream contexts.

## Configuration

Context propagation is controlled via `OTEL_EBPF_BPF_CONTEXT_PROPAGATION` which accepts a comma-separated list:

- `headers` - Inject HTTP headers
- `tcp` - Inject TCP options
- `all` - Enable all methods
- `disabled` - Disable context propagation (default)

Examples:

- `headers,tcp` - HTTP headers for plaintext HTTP, TCP options otherwise
- `tcp` - TCP options only
- `headers` - HTTP headers only

> **⚠️ TCP options and middleboxes.** TCP-option propagation writes an unknown
> TCP option (kind 25) onto the connection's segments. On SSL/TLS connections
> this is the *only* channel, since the payload is ciphertext (see Case 1). An
> unknown TCP option on an established connection is not preserved end-to-end
> across many network paths: L7 proxies and load balancers discard and replay
> the original packets, and some middleboxes and managed endpoints drop or reset
> the segment that carries it. The client then sees `connection reset by peer`,
> typically on the first request after connect. The effect is path-dependent, so
> it appears intermittently.
>
> If your instrumented services talk through such intermediaries, use
> `headers` and do not enable `tcp`. HTTP-header propagation is unaffected;
> only cross-service linking over paths that require the TCP-option channel
> (chiefly non-Go SSL/TLS clients) is lost. TCP options are safe only when OBI
> is on both ends and the path preserves them (typically a direct L2/L3 network
> with no option-stripping middlebox).

## Egress (Sending) Flow

### Execution Order

The order in which BPF programs execute varies depending on whether Go uprobes or SSL detection is involved:

#### Scenario A: Go HTTP or SSL/TLS (uprobes involved)

1. **uprobes** (Go HTTP client or SSL detection)
   - Populate `outgoing_trace_map` with initial trace context
   - Set `valid=1` for non-SSL, `valid=0` for SSL

2. **sk_msg (tpinjector)**
   - Runs for packets in sockmap
   - Can inject HTTP headers and/or schedule TCP options
   - Sets `written=1` when injection succeeds

3. **kprobe (tcp_sendmsg / protocol_http)**
   - Protocol detection and trace setup
   - Checks `written` flag to reuse trace info
   - Deletes from `outgoing_trace_map` if tpinjector handled it

#### Scenario B: Plain HTTP (no uprobes, kprobes only)

1. **sk_msg (tpinjector)**
   - Runs first for packets in sockmap
   - Protocol detector checks if HTTP
   - Can inject HTTP headers and/or schedule TCP options
   - Creates new trace info and sets `written=1`

2. **kprobe (tcp_sendmsg / protocol_http)**
   - Protocol detection and trace setup
   - Checks `written` flag - if set, reuses trace from tpinjector
   - Deletes from `outgoing_trace_map` if tpinjector handled it

#### Scenario C: Non-HTTP TCP (no uprobes, socket not in sockmap)

1. **kprobe (tcp_sendmsg)**
   - Creates trace info in `outgoing_trace_map`
   - Sets `valid=1, written=0`

Note: tpinjector does not run for this traffic because the socket was not in `sock_dir`. The `iter/tcp` iterator pre-populates `sock_dir` at startup for existing connections; new connections are added via `BPF_SOCK_OPS`.

### Mutual Exclusion Mechanism

The `written` flag implements mutual exclusion through the natural execution order. The key principle: **only inject via one method per connection**.

#### Case 1: Traffic in sockmap with Go/SSL uprobes

**For SSL/TLS:**

```
1. Uprobe sets valid=0, written=0 in outgoing_trace_map
2. tpinjector (sk_msg) runs:
   - Schedules TCP options
   - Sees valid=0 (SSL), deletes outgoing_trace_map entry
3. protocol_http runs:
   - Lookup fails (entry deleted), skips
Result: TCP options only ✓
```

TCP options are the only channel here, and they only reach the peer on paths
that preserve the option (see the middlebox warning under
[Configuration](#configuration)). Where they do not, prefer `headers`.

**For Go HTTP (plaintext):**

Go supports two approaches for HTTP header injection:

- **Approach 1 (uprobe)**: Use `bpf_probe_write_user` to inject directly into Go's HTTP buffer
- **Approach 2 (sk_msg)**: Use tpinjector to extend the packet

The uprobe attempts approach 1 first. If successful, it deletes the `outgoing_trace_map` entry to prevent approach 2 from running:

```
1. uprobe_persistConnRoundTrip sets valid=1, written=0 in outgoing_trace_map
2. uprobe_writeSubset attempts bpf_probe_write_user:
   - If successful: deletes outgoing_trace_map entry
   - If failed: entry remains for tpinjector
3. tpinjector runs (only if entry still exists):
   - Schedules TCP options
   - Injects HTTP headers via sk_msg, sets written=1
4. protocol_http runs:
   - If written=1: reuses trace, deletes outgoing_trace_map
   - If written=0: creates new trace
Result: HTTP headers (via uprobe OR sk_msg) + TCP options ✓
```

#### Case 2: Traffic in sockmap without uprobes (plain HTTP via kprobes)

**For plaintext HTTP with headers+tcp:**

```
1. tpinjector runs first:
   - Protocol detector identifies HTTP
   - Schedules TCP options
   - Injects HTTP headers
   - Creates trace, sets written=1, stores in outgoing_trace_map
2. protocol_http (kprobe) runs:
   - Sees written=1, reuses trace from tpinjector
   - Deletes outgoing_trace_map
Result: HTTP headers + TCP options ✓
```

**For plaintext HTTP with tcp only:**

```
1. tpinjector runs first:
   - Protocol detector identifies HTTP
   - Schedules TCP options, sets written=1
   - Skips HTTP headers (inject_flags check)
   - Creates trace, stores in outgoing_trace_map
2. protocol_http (kprobe) runs:
   - Sees written=1, reuses trace from tpinjector
   - Deletes outgoing_trace_map
Result: TCP options only ✓
```

#### Case 3: Traffic NOT in sockmap (tpinjector doesn't run)

```
1. Kprobe sets valid=1, written=0 in outgoing_trace_map
2. tpinjector doesn't run (socket not in sockmap)
3. protocol_http runs:
   - Sees written=0, creates new trace
Result: no context propagation for this connection ✓
```

## Ingress (Receiving) Flow

### Execution Order

On ingress, the execution order is:

1. **BPF_SOCK_OPS (tpinjector)** - Parses TCP options
2. **kprobe (tcp_recvmsg / protocol_http)** - Parses HTTP headers

### "Last One Wins" Strategy

Unlike egress (which uses mutual exclusion), ingress uses a **"last one wins"** approach:

1. **BPF_SOCK_OPS** parses TCP options (if present)
   - Extracts trace_id and span_id from TCP option
   - Stores in `incoming_trace_map`

2. **protocol_http** parses HTTP headers (if present)
   - Extracts trace_id, span_id, flags from `Traceparent:` header
   - **Overwrites** previous values

This creates a natural priority hierarchy:

- **TCP options**: Lower priority
- **HTTP headers**: Highest priority (W3C standard, most reliable)

### Why "Last One Wins" on Ingress?

1. **Unknown sender behavior**: We don't control what the sender injected
2. **Natural priority**: Execution order matches reliability (most reliable parsed last)
3. **Handles redundancy**: If sender sent multiple methods, we automatically use the best one
4. **Simplicity**: No coordination logic needed between layers

## The outgoing_trace_map

`outgoing_trace_map` is a BPF map (type: `BPF_MAP_TYPE_HASH`) that coordinates context propagation between egress layers. It stores `tp_info_pid_t` structs keyed by connection info.

### tp_info_pid_t::valid (u8)

Boolean indicating whether the trace context can be used:

- **0**: Invalid/SSL (don't inject)
- **1**: Valid

**Set to 0:**

- Go uprobes: SSL connections (`go_nethttp.c`)
- Kprobes: SSL connections (`trace_lifecycle.h`)

**Set to 1:**

- tpinjector: Creating new trace (`tpinjector.c::create_trace_info`)
- protocol_http: Creating new trace (`protocol_http.h::protocol_http`)
- protocol_tcp: Creating new trace (`protocol_tcp.h`)

**Checked:**

- tpinjector: Skip protocol detection for SSL (`tpinjector.c::handle_existing_tp_pid`)

### tp_info_pid_t::written (u8)

Coordination flag for mutual exclusion between egress injection layers:

- **0**: Not yet handled by tpinjector (sk_msg layer)
- **1**: Already handled by tpinjector (TCP options or HTTP headers injected)

**Purpose**: Implements the fallback hierarchy by preventing lower layers from injecting when higher layers already succeeded.

**Set to 0:**

- tpinjector: Initializing new trace (`tpinjector.c::create_trace_info`)
- protocol_http: Initializing new trace (`protocol_http.h::protocol_http`)
- Go uprobes: Creating client requests (`go_nethttp.c`)

**Set to 1:**

- tpinjector: After scheduling TCP options (`tpinjector.c::schedule_write_tcp_option`)
- tpinjector: After injecting HTTP headers (`tpinjector.c::write_http_traceparent`, `tpinjector.c::obi_packet_extender`)

**Checked:**

- protocol_http: Skip processing if tpinjector handled it (`protocol_http.h::protocol_http`)

## The server_traces Map

`server_traces` stores the server trace associated with a thread. Its `valid`
field remains boolean: invalid entries cannot parent children, while valid
entries can.

For delayed plaintext HTTP responses, `response_sent` separates trace validity
from slot ownership:

- **0**: The request is active. Another HTTP request on the same thread is a
  conflict, so the existing entry is invalidated.
- **1**: Response headers were observed. The entry remains valid for late
  same-thread children, but the next request can replace it.

The entry is deleted when the request finishes. Invalid and response-sent
entries can be replaced immediately.

## The incoming_trace_map

`incoming_trace_map` is a BPF map (type: `BPF_MAP_TYPE_HASH`) that stores parsed trace context from incoming packets. It stores `tp_info_pid_t` structs keyed by connection info.

Unlike `outgoing_trace_map`, there is no coordination between layers - each layer independently parses and overwrites the map entry if context is found, implementing the "last one wins" strategy.

## The sock_dir sockmap

`sock_dir` is a `BPF_MAP_TYPE_SOCKHASH` map keyed by `u64` socket cookie. It controls which sockets the `sk_msg` program (tpinjector) runs on.

Sockets are added to `sock_dir` in two ways:

1. **`BPF_SOCK_OPS`**: New connections are added automatically as they are established
2. **`iter/tcp` iterator** (`bpf/tpinjector/sock_iter.c`): Runs at tpinjector startup and iterates over all existing TCP sockets, inserting each into `sock_dir` with `BPF_NOEXIST`. This ensures connections established before tpinjector attached are tracked.

## Summary

1. **Egress uses mutual exclusion**:
   - Upper layers (tpinjector, protocol_http) delete the `outgoing_trace_map` entry
   - Lower layers can't inject if entry is already deleted
   - Result: Only one injection method per connection

2. **Ingress uses "last one wins"**:
   - Each layer independently parses if context is present
   - Later layers overwrite earlier layers
   - Result: Most reliable method takes precedence

3. **HTTP/1 TLS uses TCP options, not HTTP headers**:
   - Can't inject into encrypted payload
   - TCP options work before TLS handshake
   - tpinjector deletes entry early to skip HTTP detection
   - HTTP/2 / gRPC TLS never uses TCP options (multiplexing). Generic TLS HTTP/2 cannot splice HPACK into ciphertext. Go TLS injects via uprobe before encrypt.

4. **Execution order varies by scenario**:
   - Go/SSL: uprobes → tpinjector → kprobe
   - Plain HTTP (sockmap): tpinjector → kprobe
   - Non-sockmap: kprobe only

## Python requests.Session regression fixture

The [prototype handoff](prototypes/python-requests/README.md) includes reproduction
commands, captured baseline/final evidence, tested versions, and support limits.

`TestSuite_PythonRequestsTraceparent` exercises a synchronous Python source
without an OpenTelemetry SDK. The source prepares requests through
`requests.Session` and sends them through a separate HTTP/1.1 proxy to an
OpenTelemetry SDK downstream. The proxy terminates TLS and records all
`traceparent` fields before forwarding them. OBI selects only the source;
the proxy and downstream are outside its PID namespace.

The Config v2 fixture selects `headers` propagation and disables black-box
correlation. A second run selects `disabled`. Neither run enables TCP-option
propagation. Assertions cover exact header counts, exported span parentage,
connection reuse within and between incoming requests, concurrent independent
incoming requests, application-owned valid and invalid headers, binary bodies,
and prepared authentication, cookies, and unrelated headers.

Run the instrumented regression with generated BPF bindings available:

```sh
go test -v -run '^TestSuite_PythonRequestsTraceparent$' \
  -timeout 10m ./internal/test/integration/
```

Process discovery loads the Session wrapper through OBI's existing serialized
runtime-injection queue.
Attachment uses a pinned process identity and CPython's pending-call mechanism;
it requires no application-side tracing SDK or application-side agent loading.
The current attachment implementation supports Linux amd64 and GIL-enabled
CPython builds. Other architectures and free-threaded builds are not supported
by this attachment path.

Existing OpenSSL probes observe plaintext but cannot grow its buffers. The
wrapper copies the serialized HTTP/1.1 header block before the TLS write. A
scoped ioctl bridge reuses OBI's existing client-context association and supplies
the same span ID to its normal HTTP parser. The wrapper matches the prepared
request's headers at the urllib3 pool boundary, so direct urllib3 calls nested
inside a Session body generator remain excluded. Neither the PreparedRequest
nor its body changes. Supplied traceparent headers bypass injection.

Attachment requires ptrace access and the existing `bpf_probe_write_user`
capability/lockdown gate. It refuses already-stopped processes and existing
hardware breakpoints. It waits for a supported CPython C API boundary; cleanup
can wait for a traced thread to return from a kernel operation before detaching.
The callback code and acknowledgement occupy two pages until process exit;
the temporary script and enqueue stack are released.

A source-only OBI baseline on Linux 7.0.0-1014-aws amd64 captured six HTTPS
observations: two ordinary requests transmitted no traceparent, and their SDK
downstream spans were independent roots. Four application-owned valid/invalid
header observations preserved those headers. This used CPython 3.12.3,
requests 2.31.0, urllib3 2.0.7, and OpenSSL 3.0.13. TCP-option propagation was
disabled. The baseline dependency versions differ from the final pinned fixture.

The native automatic-attachment run used the unmodified source fixture with
CPython 3.12.3, requests 2.32.5, urllib3 2.6.3, and OpenSSL 3.0.13. It passed
all 17 HTTPS wire observations and exported 17 source client and 17 downstream
server spans. Assertions covered exactly one transmitted traceparent, known
trace identity, the downstream parent ID matching the transmitted client span
ID, reuse within and between incoming requests, concurrent independent incoming
requests, supplied-header preservation, prepared headers, and binary bodies.
A second automatic run with propagation disabled passed the same 17 wire
observations: ordinary requests had no generated header and independent
SDK downstream roots; supplied headers remained unchanged. Both runs used
Go 1.27.2 and OpenTelemetry Go SDK 1.47.0, with TCP-option propagation disabled.

The exported hierarchy follows OBI's existing queue-timing behavior. When
queue timing is available, the exporter inserts an internal `processing` span
carrying the BPF server span ID: server → processing → client → downstream
server. Otherwise, the client is a direct child of the server. The regression
checks every edge and allows only that specific internal span from the source
service. The enabled native snapshot verified 11 ordinary requests through
`processing` and two requests with direct server-to-client edges. The downstream
server must always be a direct child of the source client identified by the
transmitted traceparent.

The final Docker regression passed all HTTP and HTTPS cases with official
CPython 3.14.3 (GCC 14.2.0), OpenSSL 3.5.4, requests 2.32.5, and urllib3
2.6.3. Enabled propagation recorded 37 wire observations including readiness:
29 ordinary requests each carried one generated traceparent, and eight
application-owned headers remained unchanged. Disabled propagation recorded
36 observations: 28 ordinary requests had no traceparent and their downstream
spans were roots; eight application-owned headers remained unchanged. The
exported-span assertions verified the known incoming parent, each source
server-to-client edge (including `processing` when present), and each direct
client-to-downstream edge. Prepared headers, bodies, reuse, and concurrency
checks passed in both modes. Fixture-specific host ports isolate this test
from other local integration suites; `REQUESTS_OBI_IMAGE` can select a prebuilt
OBI image while retaining the default `hatest-obi` build for normal runs.

The ten focused wrapper tests use a synthetic context provider and real local
HTTP/TLS servers. They passed across the required version range with the
fixture's pinned requests 2.32.5 and urllib3 2.6.3 dependencies:

| CPython | OpenSSL |
| --- | --- |
| 3.9.25 | 3.5.4 |
| 3.10.22 | 3.5.9 |
| 3.11.17 | 3.5.9 |
| 3.12.3 | 3.0.13 |
| 3.13.16 | 3.5.9 |
| 3.14.3 | 3.5.5 |

Run them with `python pkg/internal/pythonagent/session_test.py`. They cover
binary, file and generator bodies, prepared-request semantics, reuse,
concurrency, supplied valid/invalid/empty headers, bridge ABI/cleanup, and
direct urllib3 calls from response hooks and body generators. Real attachment
to an owned thread-creating child also passed on all six versions. Those tests
prove wrapper behavior and attachment, not the full BPF/TLS pipeline for every
version; the native automatic pipeline runs above used CPython 3.12.3.

The current ioctl kprobe bridge passed enabled/disabled kernel tests, including
the thread-lifecycle guard. Native amd64 and arm64 BPF generation passed with
Clang 18. The repository's pinned generator image subsequently ran successfully:
LLVM 22.1.8 formatting and lint passed for the changed C files and headers.
The changed Markdown passed markdownlint-cli2 0.23.3. Real-child installation,
cancellation, stopped-process preservation, and application-signal forwarding
checks passed on the system CPython 3.12.3 interpreter and in the official
CPython 3.14.3 image. CPython 3.14 attachment watches both compatible C API
boundaries to accommodate GCC and Clang/tail-call builds. The current OBI binary
compiled and the integration package typechecked.

The final full `make verify` run passed with `GOFLAGS=-p=2` and
`GOMAXPROCS=4`, including root and collector lint, race-enabled tests, and
license checks. Earlier runs encountered a ten-second deadline in the existing
Kubernetes `TestBlockedClients` test during heavy host contention. That test
passed in the final full run. A dependency audit confirmed no Go source changes
in that test or its 18 repository dependency packages; no Kubernetes code was
changed to obtain the passing result.

The arm64 package cross-compile passed after generating all required bindings,
but runtime attachment on arm64 is still unsupported.
