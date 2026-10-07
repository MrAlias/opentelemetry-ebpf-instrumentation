# Observed request-waiting results

The combination adds request identity to a real blocking stack for an OS-thread
syscall wait. It does not explain a parked Go goroutine's one-second wait.
An observed off-CPU duration anomaly prevents a claim of accurate request time
accounting, even where recorded sample IDs match real spans.

## Recorded run

- Evidence: [20261005T202941Z](evidence/20261005T202941Z/metadata.json).
- Linux amd64, kernel 7.0.0-1012-aws; Python standard library runner; no AI.
- OBI revision `6d873d705d77e9764adab67502d65695df986e93`.
- Collector profiler 0.160.0; LGTM 0.33.1; Go fixture builder 1.27.0.
- Six sustained traffic workers, approximately one-second requests, two per route.
- Each collection interval is 60 seconds, after discovery warm-up, then 20 seconds
  for export. The three absolute intervals are recorded in each `window.json`.

| Mode | What the telemetry actually adds |
| --- | --- |
| OBI only | About one-second processing spans for `/syscall` and `/runtime`; no internal waiting stack. `/downstream` already exposes its approximately one-second HTTP dependency. |
| Profiler only | Aggregate off-CPU profile includes `main.blockingSyscall` / `syscall.Nanosleep` (40.005 s cumulative) and idle `runtime.futexsleep` (83.713 s cumulative). Zero span exemplars, as required with context reading disabled. These totals do not identify individual requests. |
| Combined | Sixteen off-CPU exemplars match exact `processing` span IDs in retrieved traces: 12 under `/syscall`, two under `/delay`, one under `/runtime`, one under `/downstream`. Associated blocking syscall stacks identify the code for particular `/syscall` requests. The runtime request has only a brief incidental OS-thread wait. |

The profiler-only off-CPU profile total is 143.373 s; the combined profile total
is 255.217 s. These include multiple threads and idle runtime waits; they cannot
be compared directly to a 60-second window or summed into request latency.
The backend profile-type listing includes unrelated built-in profiles; the
helper selects this executable's service and nanosecond CPU/off-CPU types only.

## Exact evidence

A `/syscall` processing span `b350d0be8c9393eb` in trace
`134a4f627d053b5f6a144f02fe6c7358` lasts 1.000325383 s. Its selected off-CPU profile
contains 1.000270461 s through `main.blockingSyscall` and
`syscall.Nanosleep`. The exact ID association is present in exported telemetry:
[profile](http://localhost:3102/a/grafana-pyroscope-app/explore?var-serviceName=obi-poc-waiting&var-dataSource=pyroscope&var-profileMetricId=off_cpu%3Aoff_cpu%3Ananoseconds%3A%3A&explorationType=flame-graph&from=1791232424315&to=1791232484315&showSpanHeatmap=true&var-spanSelector=b350d0be8c9393eb) and [trace](http://localhost:3102/explore?schemaVersion=1&orgId=1&panes=%7B%22trace%22%3A+%7B%22datasource%22%3A+%22tempo%22%2C+%22queries%22%3A+%5B%7B%22refId%22%3A+%22A%22%2C+%22queryType%22%3A+%22traceql%22%2C+%22query%22%3A+%22134a4f627d053b5f6a144f02fe6c7358%22%7D%5D%2C+%22range%22%3A+%7B%22from%22%3A+%221791232424315%22%2C+%22to%22%3A+%221791232484315%22%7D%7D%7D).

A `/runtime` processing span `effa403d86632a6b` in trace
`89cafa1251448d5ae22197379b022e88` lasts 1.000754074 s, but its linked off-CPU
profile contains only 12170 ns. That evidence cannot explain the
one-second runtime-managed wait. Aggregate futex/idle stacks do not establish
which outstanding goroutine was waiting or why.

## Important unsuccessful result: time attribution

Another `/syscall` span `5a05eabc06facabc` lasts
1.000336933 s, while its selected off-CPU profile contains
1.830984411 s. The request performs one synchronous syscall wait.
The larger profile value contradicts a literal per-request waiting budget.
[Anomalous profile](http://localhost:3102/a/grafana-pyroscope-app/explore?var-serviceName=obi-poc-waiting&var-dataSource=pyroscope&var-profileMetricId=off_cpu%3Aoff_cpu%3Ananoseconds%3A%3A&explorationType=flame-graph&from=1791232424315&to=1791232484315&showSpanHeatmap=true&var-spanSelector=5a05eabc06facabc) and [trace](http://localhost:3102/explore?schemaVersion=1&orgId=1&panes=%7B%22trace%22%3A+%7B%22datasource%22%3A+%22tempo%22%2C+%22queries%22%3A+%5B%7B%22refId%22%3A+%22A%22%2C+%22queryType%22%3A+%22traceql%22%2C+%22query%22%3A+%22a4b9fe2b98afb1b120a716005bcdb99f%22%7D%5D%2C+%22range%22%3A+%7B%22from%22%3A+%221791232424315%22%2C+%22to%22%3A+%221791232484315%22%7D%7D%7D) preserve this result.

Exact span-ID matching establishes that the samples were tagged with that span;
it does not establish that every nanosecond of the measured interval belongs to
that request. This run therefore supports correlated blocking-stack discovery,
with unreliable duration attribution. It does not support complete latency
accounting or a claim that all waiting has been explained.

A candidate mechanism deserves a focused upstream reproduction: the off-CPU
implementation stores switch-out timestamps in an `LRU_PERCPU_HASH`, while a
thread can resume on another CPU. Context is read at resumption rather than
captured at switch-out. Migration, stale per-CPU entries, or context changes
could affect interval attribution. This run has not proved that mechanism.
See the profiler's [off-CPU implementation](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/v0.0.202633/support/ebpf/off_cpu.ebpf.c).

The smallest useful follow-up is to reproduce duration attribution under CPU
migration and validate preservation of start-time request identity. Explaining
parked Go goroutines additionally requires runtime waiting events and their
request context; ordinary OS-thread off-CPU collection cannot supply that data.

## Attachment and traffic impact

Container ID, host PID 3950181, and start time remained identical across all
attachments; the app used its ordinary container PID namespace. See
[continuity](evidence/20261005T202941Z/continuity.json) and
[traffic measurements](evidence/20261005T202941Z/traffic-summary.json).

Ten requests per route completed before first attachment. Each mode recorded
116 to 118 complete requests per route within its selected window, with zero
observed errors. Median `/syscall` latency was 1.001609 s before attachment and
1.001617 s combined; `/runtime` was 1.001629 s and 1.001921 s; `/downstream` was
1.001637 s and 1.002713 s. These are small controlled samples, with sequential
modes and other diagnostics on the host. They are not an overhead benchmark and
do not establish zero overhead.

## Validation and failures

- Compose configuration validation and pinned fixture Docker build passed.
- Independent Go fixture build and three Python query tests passed.
- Full `make lint-markdown` fails on an untouched pre-existing trailing space
  in `examples/trace-profile/talk-proposals.md:9`. Owned Markdown is validated
  separately with the same pinned lint image and repository configuration.
- The profiler logged a nonfatal attachment warning for
  `finish_task_switch.isra.0.cold` because debugfs was mounted read-only. Other
  probes attached and real off-CPU profiles were exported. Coverage is partial.
- Trace search returns at most 100 traces; the helper retrieves at most 30
  independently of exemplar traces. Search is not an exhaustive request census.
- Existing host OBI/profiler demonstrations remained running. Only this project's
  agents were stopped or recreated; shared-host overhead and interaction remain
  experimental limitations.
- The first browser launch lacked a cached headless-shell executable; the cached
  browser container attempt then raced automatic cleanup and found the backend
  unavailable. Both failed attempts are retained in `browser-attempts.json`.
- Reopening only this project's persisted backend successfully verified both
  returned evidence links using cached Playwright 1.63.0. The
  [span-specific off-CPU screenshot](evidence/20261005T202941Z/waiting-offcpu-span.png)
  shows the selected span and `main.blockingSyscall` / `syscall.Nanosleep` flame
  graph. The [exact trace screenshot](evidence/20261005T202941Z/waiting-exact-trace.png)
  shows `/syscall` and its one-second processing span. Screenshots and body text
  are saved; no application or diagnostics were restarted for this check.
- The profile exemplar table rendered the span ID but left span name, trace ID,
  and duration blank, despite trace IDs being available in the backend response.
  The explicit generated trace URL works. Automatic UI enrichment/navigation
  therefore remains an integration limitation for this observed configuration.
