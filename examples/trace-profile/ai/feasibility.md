# AI investigation feasibility report

## Outcome

Validated on 2026-10-05: Codex requested approved diagnostic attachment to an
already-running Go container and used real sample links to investigate `/work`.
The CPU case produced a supported function-level explanation. The waiting case
correctly remained unresolved rather than blaming the competing `/report`
hotspot. The correlation control preserved CPU profiles while removing links;
the assistant did not invent a request association.

These are one fresh final session per scenario plus a separate control session,
all in randomly named empty working directories. Earlier pilot and failed
launcher attempts are retained separately. No fixture source, configuration or
expected answer was supplied to the final sessions; shell, web and app connectors
were disabled, and the transcripts contain no non-telemetry tool violations.

Raw results and screenshots are saved locally under `ai/results/`, which is
gitignored. Export that directory separately when sharing the demonstration.

## Environment

- Model: `gpt-6.1-sol` using existing Codex login; client `codex-cli 0.159.3`.
- Linux amd64, kernel `7.0.0-1012-aws`, ordinary app container PID namespace.
- OBI built from checkout `6d873d705d77e9764adab67502d65695df986e93`; the running OBI startup log
  reports that revision. Image identities are recorded in each run's metadata.
- Profiler Collector `0.160.0`, LGTM `0.33.1`, Grafana `13.2.1`.
- Grafana MCP `2.0.0`; Go MCP SDK `1.8.0`. Actual MCP versions and binary hashes
  are recorded. No separate model API application or credentials were used.

## Evidence and diagnosis

- [cpu final answer](results/cpu/investigation.md), [tool transcript](results/cpu/investigation.jsonl), [continuity](results/cpu/continuity.json).
- [waiting final answer](results/waiting/investigation.md), [tool transcript](results/waiting/investigation.jsonl), [continuity](results/waiting/continuity.json).
- [negative final answer](results/negative/investigation.md), [tool transcript](results/negative/investigation.jsonl), [continuity](results/negative/continuity.json).

The CPU transcript retrieves a recorded exemplar's trace, verifies its exact
processing span, and queries that span's CPU profile. The sampled hot function
is `main.burnCPU`, with approximately five CPU seconds in a five-second request.
Partial earlier profiles are explicitly treated as incomplete evidence.

The waiting transcript retrieves `/work` traces with approximately five seconds
in processing and negligible instrumented queue time. Its exact processing-span
profiles contain no matching CPU samples. Recorded hot-span exemplars instead
resolve to `/report`. The assistant treats waiting as plausible but unproven and
asks for request-correlated off-CPU, blocking or scheduler evidence.

The negative control uses a separate fresh window with `obi_process_ctx=false`.
Aggregate CPU remains available; span exemplars and exact-span CPU matches are
absent. The assistant reports that it cannot attribute the aggregate hotspot to
`/work`, despite being able to retrieve `/work` traces.

Browser captures are saved with each result. The returned profile and trace links
were opened in Grafana. Exact sampled IDs were also cross-checked against the
retrieved trace payloads; `evidence-verification.json` records the check.

Verified exemplar evidence (links require the retained local Grafana backend):

| Case | Exact linked span ID | Trace ID | Browser evidence |
| --- | --- | --- | --- |
| CPU target | `8ae25af18b130038` | `3aeaefb0aebb62b560537a7ecd19058b` | [Profile](http://localhost:3001/a/grafana-pyroscope-app/explore?explorationType=flame-graph&from=1791222372093&showSpanHeatmap=true&to=1791222402273&var-dataSource=pyroscope&var-profileMetricId=process_cpu%3Acpu%3Ananoseconds%3Acpu%3Ananoseconds&var-serviceName=obi-ai-demo&var-spanSelector=8ae25af18b130038), [trace](http://localhost:3001/explore?schemaVersion=1&orgId=1&panes=%7B%22trace%22%3A%7B%22datasource%22%3A%22tempo%22%2C%22queries%22%3A%5B%7B%22query%22%3A%223aeaefb0aebb62b560537a7ecd19058b%22%2C%22queryType%22%3A%22traceql%22%2C%22refId%22%3A%22A%22%7D%5D%2C%22range%22%3A%7B%22from%22%3A%222026-10-05T17%3A46%3A12.093037332Z%22%2C%22to%22%3A%222026-10-05T17%3A46%3A42.273901526Z%22%7D%7D%7D) |
| Waiting case: competing CPU | `8ab5205be9843c80` | `fff5933fbc402d68105c0e8aae979553` | [Profile](http://localhost:3001/a/grafana-pyroscope-app/explore?explorationType=flame-graph&from=1791222535587&showSpanHeatmap=true&to=1791222569321&var-dataSource=pyroscope&var-profileMetricId=process_cpu%3Acpu%3Ananoseconds%3Acpu%3Ananoseconds&var-serviceName=obi-ai-demo&var-spanSelector=8ab5205be9843c80), [trace](http://localhost:3001/explore?schemaVersion=1&orgId=1&panes=%7B%22trace%22%3A%7B%22datasource%22%3A%22tempo%22%2C%22queries%22%3A%5B%7B%22query%22%3A%22fff5933fbc402d68105c0e8aae979553%22%2C%22queryType%22%3A%22traceql%22%2C%22refId%22%3A%22A%22%7D%5D%2C%22range%22%3A%7B%22from%22%3A%222026-10-05T17%3A48%3A55.587945413Z%22%2C%22to%22%3A%222026-10-05T17%3A49%3A29.321727766Z%22%7D%7D%7D) |

## Attachment continuity and traffic

Approval precedes the only permitted mutation: fixed-project startup of OBI and
the profiler with `--no-deps --no-build --pull never`. Application container ID,
host PID and start time stayed identical during each final investigation:

| Case | Container ID prefix | Host PID | Application start time | Incident to final completion |
| --- | --- | --- | --- | --- |
| cpu | `ad94d5e93317` | 3864334 | `2026-10-05T17:45:26.514897301Z` | 135.6 s |
| waiting | `7035364eb2fa` | 3867188 | `2026-10-05T17:48:11.977744459Z` | 166.7 s |
| negative | `548fe4ad2279` | 3870376 | `2026-10-05T17:51:36.256330945Z` | 187.5 s |

| Case | Operator approval (UTC) | Collection start (UTC) |
| --- | --- | --- |
| cpu | `2026-10-05T17:46:03.911155+00:00` | `2026-10-05T17:46:12.093037332Z` |
| waiting | `2026-10-05T17:48:47.418634+00:00` | `2026-10-05T17:48:55.587945413Z` |
| negative | `2026-10-05T17:52:11.793559+00:00` | `2026-10-05T17:52:20.884509038Z` |

The reported elapsed times include pre-attachment traffic, the approval exchange,
collection and answer generation. Collection query windows are bounded to two
minutes after attachment; the final local MCP tools enforce those bounds.
Raw traffic includes requests straddling attachment; the comparison below
excludes those requests. Counts are successful completions, latency is median
milliseconds, and errors include failed requests and non-200 responses:

| Case and route | Completions before / after | Median ms before / after | Errors before / after |
| --- | --- | --- | --- |
| cpu /work | 8 / 17 | 5001.600 / 5001.640 | 0 / 0 |
| cpu /report | 8 / 17 | 5001.444 / 5001.513 | 0 / 0 |
| waiting /work | 8 / 23 | 5001.558 / 5001.564 | 0 / 0 |
| waiting /report | 8 / 23 | 5001.710 / 5001.669 | 0 / 0 |
| negative /work | 8 / 27 | 5001.591 / 5001.687 | 0 / 0 |
| negative /report | 8 / 27 | 5001.561 / 5001.583 | 0 / 0 |

This is a small continuity check, not an overhead benchmark. Both fixture paths
are deliberately approximately five seconds, concurrency is low, and no baseline
CPU-cost measurement was taken. The observed request results do not establish
zero overhead or absence of disruption under other loads.

## Failures and repairs

- Initial launcher attempts failed on CLI flag placement, noninteractive MCP
  approval policy, a malformed Docker identity template, and the Compose profile
  selection used for image metadata. They started no diagnostic collection and
  are preserved as unsuccessful bootstrap attempts.
- Pilot runs exposed browser link errors: Profiles Drilldown needs epoch
  milliseconds; this Grafana build accepts a bare trace ID through `traceql`, not
  `traceId`. The local link generator and prompt were corrected. The overlay also
  sets Grafana's public origin to port 3001. Original failed links and subsequent
  correction transcripts are retained with the pilots.
- Pilot working-directory names contained scenario labels. Final sessions use
  random neutral directories to remove that potential cue.
- Stale trace-search results were rejected by the final waiting session before
  attachment. Empty early trace/profile results and backend/query errors are preserved in
  transcripts. The assistant waits for fresh evidence or states uncertainty;
  missing evidence is never counted as a successful diagnosis.
- Correlation was restored after the control; the restoration record and fresh
  exemplars are saved with the control result (six fresh exemplars in the final
  restoration interval, with unchanged application identity). Startup/export delay is recorded
  when an initial restoration lookup is empty.

## Feasibility and talk claim

The assistant materially advanced the CPU investigation by attaching diagnostics
only after approval and connecting a hot function to the target request through
recorded IDs. In the waiting case its useful contribution was avoiding a false
attribution and identifying the missing evidence. The control demonstrates that
aggregate CPU and a slow trace alone do not establish their association.

A supported talk claim is **approved, out-of-band diagnostics can give an AI
assistant fresh request-correlated evidence without rebuilding or redeploying
the application**. This PoC establishes feasibility for this Go fixture on this
host. It does not establish diagnosis reliability, general runtime coverage,
automated mitigation or AI resolution of waiting latency.

Compose configuration validation, independent app/MCP builds and tests, and
`make lint-markdown` passed. Cleanup remains an operator action documented in the
[experiment instructions](README.md).
