# Python runtime

## HTTPX HTTPS header propagation

With header context propagation enabled, OBI loads a small Python agent into
selected CPython processes. It adds a W3C `traceparent` to HTTPS requests from
`httpx.AsyncClient` using HTTP/1.1 on the standard asyncio event loop. The
agent preserves an application-supplied header, including its spelling and
value. Synchronous HTTPX clients, Trio, uvloop, and HTTP/2 are outside this path.

The loader currently supports Linux `amd64`. It needs process access through
`ptrace`, executable anonymous memory, and the exported CPython pending-call
API. It queues installation while the main thread is idle in an event-loop
syscall; CPython executes the agent in its main interpreter with the GIL held.
Free-threaded and debug builds are excluded. HTTPX must be installed in the
target environment. The request bridge also needs `bpf_probe_write_user`, with
the same capability and lockdown restrictions as Go header propagation.
Existing Python task probes must be available for parent association; stripped
`_asyncio` builds can lack these symbols.

The agent hooks HTTP/1.1 header serialization after connection acquisition. It
uses a private header list and preserves the request's URL, method, stream, and
extensions. An ioctl bridge obtains the owning asyncio task's server context
and creates the client span ID before serialization. The TLS observer adopts
that same client context. Pending state belongs to the process, connection,
and task generation and is cleared on both completion and cancellation.
The bridge also supplies the socket addresses so the existing SSL-write probes
can bind MemoryBIO TLS to the request's connection instead of another socket
used by the asyncio thread. Binding requires the generated token in the TLS
header write, so other TLS activity in an application trace callback cannot
claim the request's socket.
It remains available through response headers so a delayed MemoryBIO
observation can adopt the same client span ID.

For TLS with separate read and write BIOs, passive tracing also waits for
ciphertext-to-socket correlation instead of inheriting a thread's last socket.
This association rule applies with propagation disabled as well.

Disabling header propagation prevents agent loading. An agent remaining after
OBI detaches receives no context from the bridge and forwards requests normally.
Loading failures are logged and leave passive application tracing available.

The regression fixture in
`internal/test/integration/components/pythonhttpx/` records raw headers at an
uninstrumented TLS proxy and checks them against OBI source spans and an
OpenTelemetry downstream span. It pins HTTPX 0.28.1 and httpcore 1.0.9.

## Garbage collector metrics

With `application_runtime` enabled, OBI reads cumulative garbage-collector
counters from supported CPython processes and exports all nine combinations of
these metrics and generations 0, 1, and 2:

| OTel metric | Prometheus metric | Unit |
| --- | --- | --- |
| `cpython.gc.collections` | `cpython_gc_collections_total` | `{collection}` |
| `cpython.gc.collected_objects` | `cpython_gc_collected_objects_total` | `{object}` |
| `cpython.gc.uncollectable_objects` | `cpython_gc_uncollectable_objects_total` | `{object}` |

Each point has the integer `cpython.gc.generation` attribute. OBI tracks source
counters per PID and aggregates processes that share the exported attributes.
OBI reports the main interpreter only; it does not aggregate subinterpreters.

Enable Python runtime metrics through the shared runtime metrics feature:

```yaml
metrics:
  features:
    - application_runtime
```

## Architecture

The generic tracer owns Python metric collection. A PID-scoped probe runs when
CPython completes a GC collection. The eBPF program then reads all nine
cumulative counters.

```mermaid
flowchart LR
    Events[Python process events] --> Controller[Generic tracer controller]
    Controller --> Resolver[Runtime resolver]
    Resolver --> ELF[Executable or libpython ELF]
    Resolver --> Layout[ABI layout]
    Resolver --> Probe[GC completion probe]
    Probe --> BPF[eBPF counter reader]
    BPF --> Ring[Shared ring buffer]
    BPF --> Final[Latest snapshot map]
    Ring --> Queue[Runtime metrics queue]
    Final -->|Read on process exit| Controller
    Controller -->|Final snapshot| Queue
    Queue --> Gate[Dynamic PID gate]
    Gate --> OTel[OTel exporter]
    Gate --> Prometheus[Prometheus endpoint]
```

### Target setup

The resolver locates `_PyRuntime` in the mapped executable or `libpython`.
It reads the CPython version from the mapped ELF file. CPython 3.9 through 3.12
use embedded structure offsets. CPython 3.13 and 3.14 combine embedded offsets
with build-dependent values from `_Py_DebugOffsets` in the ELF file. The
resolver selects one mapped ELF object that owns `_PyRuntime`. It validates the
ELF format, CPython version, runtime layout, and probe metadata.

### Probe selection

The resolver selects a valid `python:gc__done` USDT probe as the primary probe.
On Linux `amd64`, it can also resolve a supported private collector return probe.
If USDT is unavailable, the private probe becomes the primary probe. If USDT
attachment fails, the controller tries the private probe as a fallback.

OBI attaches each probe to one PID:

| Probe | Architectures | Attachment |
| --- | --- | --- |
| `python:gc__done` USDT | `amd64`, `arm64` | PID-scoped uprobe at the USDT file offset |
| Internal GC fallback | `amd64` | PID-scoped uretprobe at the collector function file offset |

Python runtime metric activation requires a supported layout and one probe
from this table. Builds outside this table continue with OBI application tracing.

### Internal GC fallback

When `python:gc__done` is unavailable, Linux `amd64` resolves CPython's internal
`collect` or `gc_collect_main` function. The resolver uses a recognized symbol
when the ELF provides one. For stripped builds, it starts at the exported
`PyGC_Collect` symbol and derives the internal function from validated machine
code. The controller attaches a PID-scoped uretprobe at the resolved file offset.

Some full Docker Official Images omit SystemTap notes but retain private
collector symbols with link-time optimization (LTO) suffixes. The resolver
accepts suffixed symbols when all recognized variants identify one address.

For stripped CPython 3.9 through 3.12, the resolver matches the internal GC
call between two calls to the same callback. For CPython 3.13 and 3.14, it
matches the current thread-state lookup and the internal GC call with generation
2 and the manual-collection reason. Function starts from `.eh_frame_hdr` bound
each instruction scan and validate the resolved local call target.

Application tracing continues when the mapped ELF has no safe GC completion probe.

### Counter collection

The eBPF program runs after each completed GC collection. It reads the main
interpreter and all nine counters with `bpf_probe_read_user`. The program emits
a snapshot after the runtime addresses, memory reads, and counters pass validation.

The program sends each snapshot through the shared ring buffer. It also stores
the latest snapshot in a process map. The controller reads this map at process
exit and forwards the latest successfully read snapshot before removal.

Each completed GC collection performs the counter reads, snapshot-map update,
ring-buffer submission, and userspace counter update.

The snapshot contains three cumulative counters for each CPython GC generation:

```text
PythonRuntimeMetricSnapshot
└── generations 0, 1, and 2
    ├── collections
    ├── collected objects
    └── uncollectable objects
```

The exporters produce nine cumulative metric series for each exported attribute
set. They keep a separate source-counter baseline for each PID before aggregation.

## Compatibility

Python runtime metrics support validated, non-free-threaded CPython 3.9 through
3.14 final releases on Linux `amd64` and `arm64`. The embedded offset data records
the latest validated patch in each series. The offset update check extends each
series after validating a newer patch. Linux `amd64` validation includes full,
`slim`, and `alpine` Docker Official Python images.

CPython 3.9 through 3.12 use validated per-minor layouts. CPython 3.13 and 3.14
use the runtime's `_Py_DebugOffsets` table for build-dependent structure sizes
and offsets. Compatible rebuilt and repackaged interpreters qualify through
their runtime layout, independent of ELF build ID availability. CPython 3.13
and 3.14 use an embedded `generation_stats` offset. New patch activation follows
offset update validation for that field.

Private collector probe resolution supports Linux `amd64` only. Linux `arm64`
requires a valid `python:gc__done` USDT probe.
Application tracing continues for Python targets outside this runtime-metrics
compatibility set.

## Updating offsets

Run `make update-python-offsets` from a Linux `amd64` checkout. The target
downloads the latest CPython releases, compiles the ABI validation probe, and
updates the embedded offsets and version checkpoint when the layouts remain
compatible. Review both generated files and run the Python runtime package
tests before accepting the update.

## Collection and permissions

OBI attaches one PID-scoped uprobe or uretprobe to each supported Python
process. The eBPF program reads user memory only when CPython completes a GC
collection. The Go controller consumes ring buffer events and reads the latest
snapshot once when the process exits.

Attachment requires the same BPF and process access as other OBI user probes.
Linux policy, namespaces, capabilities, and procfs visibility can deny access.
Application tracing continues when attachment fails, while Python runtime
metric collection stays inactive for that process.
