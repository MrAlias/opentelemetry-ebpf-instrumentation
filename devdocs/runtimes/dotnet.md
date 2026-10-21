# .NET runtime support

## HTTP tracing and context propagation

With header propagation enabled, OBI associates Linux .NET HTTP/1.1 HTTPS
`HttpClient.SendAsync()` requests with their native HTTP activities. No
application SDK or code changes are required. The supported runtime is .NET 8
CoreCLR on Linux x86-64. HTTP association on .NET 9, .NET 10, other architectures,
and NativeAOT has not been validated; runtime-metrics compatibility below does
not establish HTTP association support.

`System.Net.Http` performs W3C header injection through its diagnostic handler.
OBI reuses that header and preserves application-supplied traceparents. It does
not write an additional header or replace an existing one. Disabling OBI
propagation leaves the runtime's independent propagation enabled. Applications
that explicitly disable runtime propagation with
`DOTNET_SYSTEM_NET_HTTP_ENABLEACTIVITYPROPAGATION=false` are outside this support;
OBI respects that opt-out and has no independent TLS header-insertion fallback.

OBI uses its existing diagnostic-socket collector to subscribe to ASP.NET Core
server starts and native HTTP client activities. The collector requires access
to the target's diagnostic socket and enabled .NET diagnostics. A native server
activity is associated with an observed server request using its process,
incoming W3C context, connection, method, path, and monotonic request interval.
Client traces use the native activity and its existing request header rather
than depending on a TLS probe observing every async request. Matching BPF client
records supply metrics instead of duplicate traces. This avoids using thread
identity to associate async work. Incomplete server observations do not establish
a parent link.

Plaintext is observed with the existing `CryptoNative_SslRead` and
`CryptoNative_SslWrite` probes in
`libSystem.Security.Cryptography.Native.OpenSsl.so`. OBI also looks for this
library beside the loaded `libcoreclr.so`, allowing attachment before the first
TLS request lazily loads the wrapper. Existing queue and processing spans retain
their IDs; the native HttpClient activity is parented to the outer server span.
The validated parent chain uses an ASP.NET Core HTTP/1.1 source request with a
valid incoming W3C traceparent and an HTTP/1.1 HTTPS outbound request. HTTP/2,
requests without incoming context, and other HTTP client implementations are
outside this scope.

The Linux .NET 8 regression fixture in
`internal/test/integration/docker-compose-dotnet-httpclient.yml` forces
`RequestVersionExact` HTTP/1.1 and uses an OBI-only ASP.NET source, an
uninstrumented TLS proxy recording header values and connections, and an OTel
SDK downstream. `TestSuite_DotNetHTTPClientTraceparent` checks sequential pool
reuse, overlapping async requests, cancellation recovery, supplied headers,
and propagation disabled. Controls with runtime diagnostic propagation disabled
verify the explicit application opt-out. The fixture asserts exactly one wire
traceparent and the complete span-ID chain, rather than only matching trace IDs.
Live integration coverage runs on .NET 8.0.27 (Linux x86-64). Native EventPipe
decoding also has a replay fixture captured on .NET 8.0.0.

The runtime behavior is defined in
[.NET 8 DiagnosticsHandler](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Net.Http/src/System/Net/Http/DiagnosticsHandler.cs).

## Runtime metrics

With `application_runtime` enabled, OBI collects runtime metrics from
.NET 8 and newer processes on Linux through their diagnostic Unix sockets.

| OTel metric | Prometheus metric | Unit |
| --- | --- | --- |
| `dotnet.gc.collections` | `dotnet_gc_collections_total` | `{collection}` |
| `dotnet.process.cpu.count` | `dotnet_process_cpu_count` | `{cpu}` |
| `dotnet.process.cpu.time` | `dotnet_process_cpu_time_seconds_total` | `s` |
| `dotnet.process.memory.working_set` | `dotnet_process_memory_working_set_bytes` | `By` |
| `dotnet.gc.last_collection.heap.size` | `dotnet_gc_last_collection_heap_size_bytes` | `By` |
| `dotnet.gc.last_collection.memory.committed_size` | `dotnet_gc_last_collection_memory_committed_size_bytes` | `By` |
| `dotnet.thread_pool.thread.count` | `dotnet_thread_pool_thread_count` | `{thread}` |
| `dotnet.thread_pool.queue.length` | `dotnet_thread_pool_queue_length` | `{work_item}` |
| `dotnet.timer.count` | `dotnet_timer_count` | `{timer}` |
| `dotnet.assembly.count` | `dotnet_assembly_count` | `{assembly}` |
| `dotnet.gc.heap.total_allocated` | `dotnet_gc_heap_allocated_bytes_total` | `By` |
| `dotnet.gc.pause.time` | `dotnet_gc_pause_time_seconds_total` | `s` |
| `dotnet.jit.compiled_il.size` | `dotnet_jit_compiled_il_size_bytes_total` | `By` |
| `dotnet.jit.compiled_methods` | `dotnet_jit_compiled_methods_total` | `{method}` |
| `dotnet.jit.compilation.time` | `dotnet_jit_compilation_time_seconds_total` | `s` |
| `dotnet.thread_pool.work_item.count` | `dotnet_thread_pool_work_item_count_total` | `{work_item}` |
| `dotnet.monitor.lock_contentions` | `dotnet_monitor_lock_contentions_total` | `{contention}` |

For GC collection counts, `dotnet.gc.heap.generation` identifies `gen0`, `gen1`, and `gen2`.
Counts are exclusive: a full gen2 collection adds one to gen2, while gen0 and
gen1 remain unchanged.

Heap size reports bytes after the latest collection, including fragmentation,
with `dotnet.gc.heap.generation` values `gen0`, `gen1`, `gen2`, `loh`, and `poh`.
The five generation-size EventCounters supply these values on .NET 8, 9, and 10.
Each value can increase or decrease and remains unchanged until another GC.
The runtime polls each generation separately; a GC during polling can span two
collection states. Missing values are omitted from that sampling round.

CPU time has separate `cpu.mode=user` and `cpu.mode=system` series. CPU count
reports the runtime's `Environment.ProcessorCount`, including its processor-count
override, container CPU quota, and processor affinity.

Enable .NET runtime metrics through the shared runtime metrics feature:

```yaml
metrics:
  features:
    - application_runtime
```

`dotnet_runtime_metrics.sampling_interval` controls `System.Runtime` EventCounter
polling and the delay before reconnecting after a collection session ends.
`dotnet_runtime_metrics.timeout` bounds diagnostic IPC setup and the final
EventPipe shutdown and drain. With HTTP header propagation enabled, it also
bounds the wait for a matching native client record before falling back to the
BPF client trace.

```yaml
dotnet_runtime_metrics:
  sampling_interval: 1s
  timeout: 10s
```

Both settings must be positive. Their environment variables are
`OBI_DOTNET_RUNTIME_METRICS_SAMPLING_INTERVAL` and
`OBI_DOTNET_RUNTIME_METRICS_TIMEOUT`.

## Collection path

.NET runtime metrics flow through diagnostic IPC and EventPipe to the shared
runtime metrics export queue:

1. Discovery starts one collector for each selected .NET process.
2. A stable process handle provides the namespace PID and access to the target's
   temporary directory (`TMPDIR`, or `/tmp`).
3. `ProcessInfo2` verifies the socket's PID and confirms that the CLR version is
   .NET 8 or newer.
4. The collector starts an EventPipe session and decodes its NetTrace stream.
   The `ProcessorCount` event supplies the CPU count retained for that session.
5. Sampling rounds containing GC counts, cumulative counters, and available
   current values enter the runtime metrics queue and reach the OTLP and
   Prometheus exporters.

Before publishing each round, OBI reads user and system CPU ticks from
`/proc/<pid>/stat` through the stable process handle and converts them to seconds.
These are process-lifetime totals sampled at publication time. A failed read
omits CPU time from that round while the other available metrics still publish.

The first sample for each generation establishes a baseline. Exported totals
therefore cover collection after attachment, rather than the process lifetime.
The runtime polls generation counters separately, so sampling boundaries are
approximate. OBI defers inconsistent or decreasing exclusive totals until a
later complete round catches up.

Allocation bytes, GC pause time, JIT compilation time, completed work items,
and monitor lock contentions also cover collection after attachment. Each
counter's first increment establishes its baseline; later increments accumulate
in the collector. GC pause and JIT compilation durations use seconds.
Compiled IL bytes and compiled method counts use the runtime's absolute
process-lifetime totals, including their first observed values.

An unavailable counter is omitted from that sampling round and retains its
baseline. Each exporter tracks the last published value per process and adds
its increase to the shared service counter. A process exit preserves the
exported cumulative total, and a replacement process establishes its own
baseline. Current-value metrics reflect the latest available process values.

On stream loss, OBI reconnects while the process is alive and preserves the last
published attachment-relative totals. Increments during the gap are unavailable;
CPU time and the two absolute JIT counters continue to report process-lifetime values.
Process removal cancels collection; shutdown sends `StopTracing` while draining
the stream.

## Requirements and limitations

This collector accepts .NET 8 and newer. Integration coverage targets .NET 8, 9,
and 10. Later versions can attempt collection, but compatibility is not guaranteed.
CLR versions below 8 are skipped.

OBI must be able to access the target process through `/proc`, including its
root filesystem, and connect to its diagnostic socket. Socket lookup uses the
application's absolute `TMPDIR`, or `/tmp` when unset, inside that filesystem.

Keep the application's default diagnostic port enabled.
`DOTNET_EnableDiagnostics=0` disables collection.

The implementation requests a 16 MiB EventPipe buffer per process and rejects
detected event loss instead of accumulating incomplete counter deltas.
