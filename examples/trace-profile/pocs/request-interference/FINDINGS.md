# Request interference findings

## Result

**Request CPU attribution is strengthened; request interference remains unresolved.**

The corrected six-phase run completed on 2026-10-05 in 319.4 seconds.
It compared OBI alone, the profiler alone, and both together in a shared-lock
case and an independent-wait control. Both cases produced approximately two
seconds of `/work` latency while `/report` ran the same CPU-intensive function.

The combined samples identified exact requests executing `main.prepareReport`.
They did not expose which mutex a different request waited for or who held it.
The control is important: the same hotspot and overlapping slow requests occur
when `/report` does not obstruct `/work`. Those observations cannot establish
interference.

## Recorded observations

The table reports the initial fixed-window query results, not complete CPU
accounting. Search indexing and sample availability were incomplete. Each phase
completed ten `/work` and ten `/report` requests with HTTP 200.

| Case | Mode | Sampled CPU seconds | Trace search count / completions | Verified exemplar IDs |
| --- | --- | ---: | ---: | ---: |
| shared-lock | obi | Not collected | 6 / 20 | 0 / 0 |
| shared-lock | profiler | 18.680 | Not collected | 0 / 0 |
| shared-lock | combined | 20.175 | 6 / 20 | 12 / 12 |
| control | obi | Not collected | 6 / 20 | 0 / 0 |
| control | profiler | 5.093 | Not collected | 0 / 0 |
| control | combined | 3.608 | 6 / 20 | 4 / 4 |

In both profiler-enabled cases, `main.prepareReport` dominates the returned
CPU profile; `main.finishWork` consumes much less sampled CPU. Handler names
in profiler stacks can already suggest the operation. OBI adds the actual HTTP
request, trace identity, and exact sampled span rather than requiring an
interpretation of function names.

All 16 returned combined exemplars matched both their exact span ID and trace
ID in fetched Tempo payloads. The sampled spans were `processing` spans within
`GET /report` or `GET /work` traces. No span attribute or display adapter
manufactured these associations. Profiler-only runs explicitly disabled
`obi_process_ctx` and returned aggregate profiles with no span exemplars.

| Mode | Supported observation | What remains missing |
| --- | --- | --- |
| OBI | Long `/work` and `/report` request spans, with queue and processing timing | The resource and blocking request are not identified. |
| Profiler | Hot report-handler execution and light work-handler execution | Exact request identity and mutex lifecycle are not recorded in this mode. |
| Combined | Measured execution belongs to exact HTTP request spans | Resource, waiter, acquisition/release, and holder relationships remain absent. |

The initial trace searches returned only six of twenty successful requests in
each trace-enabled phase. `collection.json` explicitly marks that incomplete
count. Individual traces were also fetched directly using recorded exemplar
IDs, so search incompleteness does not substitute for exact-ID verification.
CPU totals differ substantially between phases even though the fixture performs
the same work. These totals cannot justify a claim about overhead, cost changes,
or complete request CPU coverage.

## Controlled workload truth

Application mutex events are stored separately in `fixture-ground-truth.json`.
They validate the workload construction and are excluded from the diagnostic
evidence. `verify-fixture` does not map local request sequence numbers to OTel
spans by timestamps.

- Shared-lock combined: ten of ten `/work` waits began while `/report` held the
  same recorded mutex; work acquired it after the report began releasing it.
  Median wait: 1900.253 ms.
- Control combined: ten of ten `/work` waits were independent, with no mutex
  resource associated with work. Median wait: 1900.209 ms.

This confirms different causal ground truth behind similar latency and CPU
symptoms. It does not claim that OBI or the profiler supplied the mutex events.

## Attachment continuity

All six diagnostic attachments preserved the application container ID, host
PID, and start time. The application used its ordinary container PID namespace
and no tracing/profiling SDK. Changing the scenario deliberately recreated the
application between experiments; the backend stayed running.

The corrected run recorded 24 completions before attachment, 72 during startup,
and 120 in measurement intervals, with zero recorded errors. Before/after
`/work` medians were approximately 2.001 seconds in both cases. This small
fixture observation is not an overhead benchmark or a claim of zero disruption.
Other diagnostic projects were already running on the host and remained
untouched; their identities are recorded in `metadata.json`.

## Browser evidence

Four browser pages loaded with HTTP 200 and expected service/request text.
The two span-filtered flame graphs visibly contain `main.prepareReport`; their
selected span IDs match the separately verified raw telemetry. The two Tempo
pages display the associated `GET /report` traces. Browser navigation alone is
not the association check.

- [shared lock profile](http://localhost:3103/a/grafana-pyroscope-app/explore?var-serviceName=obi-poc-interference&var-dataSource=pyroscope&var-profileMetricId=process_cpu%3Acpu%3Ananoseconds%3Acpu%3Ananoseconds&explorationType=flame-graph&from=1791234152688&to=1791234174708&showSpanHeatmap=true&var-spanSelector=daa29be958d43c10) — [screenshot](evidence/validated-20261005/shared-lock-profile.png).
- [shared lock trace](http://localhost:3103/explore?schemaVersion=1&orgId=1&panes=%7B%22trace%22%3A+%7B%22datasource%22%3A+%22tempo%22%2C+%22queries%22%3A+%5B%7B%22refId%22%3A+%22A%22%2C+%22queryType%22%3A+%22traceql%22%2C+%22query%22%3A+%22c8e82576135ba5050d49e0ebfb6a31de%22%7D%5D%2C+%22range%22%3A+%7B%22from%22%3A+%222026-10-05T21%3A02%3A32.688000%2B00%3A00%22%2C+%22to%22%3A+%222026-10-05T21%3A02%3A54.708000%2B00%3A00%22%7D%7D%7D) — [screenshot](evidence/validated-20261005/shared-lock-trace.png).
- [control profile](http://localhost:3103/a/grafana-pyroscope-app/explore?var-serviceName=obi-poc-interference&var-dataSource=pyroscope&var-profileMetricId=process_cpu%3Acpu%3Ananoseconds%3Acpu%3Ananoseconds&explorationType=flame-graph&from=1791234312499&to=1791234334518&showSpanHeatmap=true&var-spanSelector=814221cf79436c71) — [screenshot](evidence/validated-20261005/control-profile.png).
- [control trace](http://localhost:3103/explore?schemaVersion=1&orgId=1&panes=%7B%22trace%22%3A+%7B%22datasource%22%3A+%22tempo%22%2C+%22queries%22%3A+%5B%7B%22refId%22%3A+%22A%22%2C+%22queryType%22%3A+%22traceql%22%2C+%22query%22%3A+%220fc4c8ed2c72cbd645a8e52b6f607451%22%7D%5D%2C+%22range%22%3A+%7B%22from%22%3A+%222026-10-05T21%3A05%3A12.499000%2B00%3A00%22%2C+%22to%22%3A+%222026-10-05T21%3A05%3A34.518000%2B00%3A00%22%7D%7D%7D) — [screenshot](evidence/validated-20261005/control-trace.png).

Live URLs require the retained backend volume. Restart only `lgtm` with the
README command after cleanup. Raw responses and screenshots work without it.

## Preserved pilot failures

The interrupted pilot is retained in `evidence/pilot-20261005.tar.gz`:

1. A profiler-only interval returned no fixture samples despite a ready agent.
   This was an unsuccessful collection, not a causal negative. A fresh readiness
   run with sustained startup traffic returned 20.835 sampled CPU seconds. The
   precise cause of the initial missing data was not isolated.
2. Expired retries replaced a useful partial summary with deadline errors.
   The helper now retains actual partial responses. Pilot partial summaries
   were recovered from their saved raw attempts and replayed; deadline errors
   remain archived. Its combined interval had 7/7 exact verified IDs.
3. The pilot recreated the backend during a scenario transition before stopping
   the old agents, causing shutdown export drops. The corrected runner stops
   agents before the transition and keeps the backend stable.

Extract the pilot when investigating these failures:

```sh
tar -xzf evidence/pilot-20261005.tar.gz -C evidence
python3 poc.py replay --output evidence/pilot-20261005/shared-lock-combined
```

## Smallest justified next experiment

A probe for one specific synchronization primitive should record resource
identity, successful acquisition/release, the waiter interval and execution
identity, and request context at those events. For Go it must follow goroutines,
cover inlined fast paths, and handle unlock by another goroutine. Lost events
and unknown ownership must stay explicit.

OBI would contribute request context, the profiler would contribute execution
stacks, and that third capability would establish the resource relationship.
It should pass this same independent-wait control before the talk promises
request interference diagnosis. Off-CPU timing or a generic function event
count alone does not supply this ownership evidence.

## Validation and cleanup

- Go fixture builds; `go test ./...` succeeds (no fixture unit tests).
- Seven Python tests pass, including malformed IDs, profile self accounting,
  backend failure states, and expired retry preservation.
- All six saved phases replay successfully; 16/16 combined IDs are verified.
- Compose configuration and JavaScript syntax checks pass.
- Owned Markdown files pass the repository-pinned targeted linter. Full
  `make lint-markdown` fails only on the existing trailing space in
  `examples/trace-profile/talk-proposals.md:9`; that unrelated file is unchanged.
- Browser capture holds the host lock through cleanup. `cleanup.json` confirms
  no remaining `obi-poc-interference` containers. Its backend volume is retained.
