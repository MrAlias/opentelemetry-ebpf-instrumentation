# Request-cost findings

## Outcome

The combination answered a question neither signal independently resolved in
this experiment: **which execution path consumes the extra CPU in slow requests
to the same endpoint, despite unrelated traffic dominating the service profile?**

The saved combined window contained 57 ordinary `/work` requests and 18 slow
`/work` requests. Ordinary requests averaged **147.0 milliseconds of sampled CPU**;
slow requests averaged **801.8 milliseconds**, about **5.45 times as much CPU per
request**. Their leading self-CPU functions were `main.readEntry` and
`main.rebuildEntry`, respectively. Those names and values come from queried
profiles, rather than assertions about fixture source.

The whole-service profile's leading function was instead `main.exportReport`,
with 68.186 of 93.381 sampled CPU seconds, about 73% of the aggregate. Combining
trace selection with exact span profiles directs investigation of slow `/work`
requests toward their own expensive path. Optimizing the aggregate hotspot would
address a different workload; this evidence does not establish it as the cause
of `/work` latency.

## Independent signals and cooperation

| Mode | Recorded evidence | Supported answer |
| --- | --- | --- |
| OBI alone | 57 ordinary requests near 150 ms; 18 slow requests near 800 ms; request and processing spans | There are two latency groups on the same route. Traces do not expose their CPU stacks. |
| Profiler alone | 81.247 sampled CPU seconds; `main.exportReport` accounts for 59.546 seconds; additional `readEntry` and `rebuildEntry` work; no request exemplars | Identifies process CPU work. Stack names can suggest operations, but CPU alone cannot classify individual requests by latency or identify their traces. |
| Both, with context | 75 complete selected target traces; 74 requests have samples; 16 actual target exemplars; exact span profiles | The slow group runs `rebuildEntry` and has about 5.45 times the sampled CPU per request of the ordinary group. |
| Both, context disabled | 77.392 sampled aggregate CPU seconds; 74 selected target traces; zero target exemplars and zero exact-span CPU | Both signals exist, but their request association is absent. Temporal coexistence supplies no replacement link. |

Ordinary requests had samples in 56 of 57 selected spans; slow requests had
samples in all 18. The mean includes the ordinary request without samples.
One negative-control request completion was not represented in the selected
trace set (74 traces versus 75 client completions). Boundary differences or
incomplete telemetry remain possible; that discrepancy is preserved explicitly.

## Exact evidence and browser result

All IDs are read from backend telemetry and normalized to hexadecimal widths.
The replay command checks that each processing span is a child of the selected
`GET /work` server span in the exact trace and that saved exemplars exist in the
raw heatmap response.

One browser-verified slow request used:

- Trace ID: `8e8498797abf524988c892b30e2e0bb5`.
- Processing span ID: `c8ac7d377a88f29b`.
- Trace processing duration: 800.37 ms.
- Browser-selected profile: `main.rebuildEntry`, 814 ms of sampled CPU.

One browser-verified ordinary request used:

- Trace ID: `572b19b7a7b8b81392fc0884d8808dba`.
- Processing span ID: `eb706806a811d12a`.

Screenshots, visible text, and the actual links are in
`evidence/validated-20261005/combined/browser/`. Both trace IDs appeared on their
trace pages. Both profile pages preserved the exact span selector and rendered
profiles. Anonymous star requests returned 401 and the unused recording-rules
endpoint returned 404; those errors are recorded in `browser/links.json` and did
not prevent profile or trace rendering.

The backend volume was removed during this project's cleanup. Historical URLs
are durable evidence of what was queried, but a new run is needed for interactive
viewing. `replay.py` verifies the saved raw telemetry without a backend.

## Attachment continuity and measured traffic

Application identity remained unchanged across all diagnostic modes:

- Container ID: `b19c96fdb2a2c9dc5c0a075c27fea39f9ce93a037588fe7e81121f1b01f0fad2`.
- Host PID: `3966172`.
- Start time: `2026-10-05T20:35:12.63287411Z`.
- PID mode: ordinary container namespace, not host PID mode.

The sustained traffic ran for approximately 299 seconds. Before attachment,
23 completed `/work` requests had a median of 151.289 ms. During the combined
window, 75 completed requests had a median of 151.498 ms. Before attachment,
eight `/report` completions had a median of 2001.385 ms; during the combined
window, 32 completions had a median of 2001.411 ms. No traffic errors were observed.

These are measurements from one small controlled run, with unequal sample sizes
and existing external workloads and diagnostics. They do not establish zero
overhead or an overhead bound. Full counts and latency summaries are saved in
`traffic-summary.json`, with application snapshots in `continuity.json`.

## Collection windows and versions

All timestamps below are UTC; windows are disjoint and exclude startup evidence.

| Mode | Start | End |
| --- | --- | --- |
| OBI alone | 2026-10-05 20:36:00.542 | 2026-10-05 20:36:35.542 |
| Profiler alone | 2026-10-05 20:37:12.258 | 2026-10-05 20:37:47.258 |
| Combined | 2026-10-05 20:38:23.564 | 2026-10-05 20:38:58.564 |
| No correlation | 2026-10-05 20:39:35.791 | 2026-10-05 20:40:10.791 |

The run used OBI revision
`6d873d705d77e9764adab67502d65695df986e93`, profiler Collector 0.160.0,
LGTM 0.33.1, Go 1.27.1, and Linux amd64 kernel `7.0.0-1012-aws`.
Image digests/IDs, Docker and Python versions, background container names, and
refresh timing are saved in `metadata.json`. Browser capture used the cached
Playwright 1.63.0 image. No AI model or application SDK was used.

## Failures, improvements, and limits

The first pilot failed while parsing a shortened hexadecimal trace ID from Tempo.
Its raw search, partial traces, traffic, and continuity evidence remain under
`evidence/live-20261005/`. The parser now restores omitted leading zeros only for
valid hexadecimal IDs within the expected width; a regression test covers it.

A fixed 15-second export wait initially returned only 42 combined target traces.
A subsequent query of the **same recorded interval** returned 75, matching the
75 measured client completions. The final results above use that refresh.
Initial console observations and final counts are retained in each mode's
`collection-history.json`; initial raw responses were replaced by the refreshed
responses. The operator runner now performs bounded visibility retries and
reports incomplete evidence explicitly. That retry change is covered by unit
tests; it was not used for a second live collection run.

CPU samples estimate execution. Slightly more sampled CPU than wall time for an
individual span can reflect sampling and reporting granularity; it is not an
exact request clock. Cumulative stack values overlap; self values and individual
span totals were verified against merged cohort totals.

This is a forced two-path fixture, not proof of a production cache defect or of
causality behind every slow request. The conclusion is specifically that the
slow group executes a different, substantially more CPU-expensive path. Further
evidence would be needed to explain why an application selected that path or
whether all its work is necessary. This PoC does not measure runtime waiting or
contention ownership.

No OBI or profiler public API or correlation implementation was changed. The
additional analysis is an example-local join and cohort comparison using
existing trace and profile APIs.

## Validation

- Docker Compose configuration validation passed.
- Independent Go application Docker build and local Go build passed.
- Five Python tests passed: ID handling, accounting, missing evidence/backend
  failures, exact-span URLs, and bounded visibility/incompleteness handling.
- Saved-evidence replay passed for all four modes, including exact trace/span
  relationships, raw exemplars, aggregate totals, and individual/cohort CPU sums.
- Four browser screenshots confirmed ordinary and slow request profiles/traces.
- Targeted Markdown lint for this PoC passed.
- `make lint-markdown` encountered a pre-existing trailing-space error in
  `examples/trace-profile/talk-proposals.md:9`. That file was not changed.

Only Compose project `obi-poc-cost` was stopped and removed. Its backend volume
was removed, fixture image and evidence remain, and default profiler context
consumption is enabled in the finished configuration.
