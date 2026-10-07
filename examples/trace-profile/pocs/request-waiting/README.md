# Request waiting: OBI, the profiler, and their cooperation

This independent experiment asks what explains the elapsed time of a particular
request that uses little CPU. It runs the same uninstrumented Go process in three
fresh intervals: OBI only, profiler only, and both. No AI investigator is involved.
The application uses its ordinary container PID namespace and has no telemetry SDK.

| Route | Controlled behavior | Question |
| --- | --- | --- |
| `/syscall` | Blocking `syscall.Nanosleep`, retrying interrupted sleeps | Can OS-thread waiting stacks be associated with this request? |
| `/runtime` | `time.Sleep` parks a Go goroutine | Does OS-thread off-CPU profiling explain runtime-managed waiting? |
| `/downstream` | HTTP call to this process's `/delay` endpoint | How much can OBI already explain through a downstream span? |

Each wait lasts approximately one second. Two traffic workers per route run
before attachment and across all collection intervals. The controlled behavior
is ground truth for checking a diagnosis; the query helper reads only telemetry.

## Prerequisites and build

Use a Linux amd64 host with Docker Compose, privileged eBPF access, BTF, writable
`/sys/fs/bpf`, and Python 3. No additional Python packages are required. The app
builder, profiler 0.160.0, and LGTM 0.33.1 images are pinned by digest. Ports 8182
and 3102 must be free. The services have their own Compose project, backend data
volume, and BPF root `/sys/fs/bpf/obi-poc-waiting`.

The checked validation image is `obi-ai-investigation:6d873d7`, built from
`6d873d705d77e9764adab67502d65695df986e93`. On a fresh machine, build the current
checkout's OBI image from the repository root and select it explicitly:

```sh
docker build -t obi-poc-waiting-obi:local \
  --build-arg RELEASE_REVISION="$(git rev-parse HEAD)" .
export OBI_IMAGE=obi-poc-waiting-obi:local
```

The validated revision publishes OBI context without a
`populate_trace_context` configuration switch. This example verifies exported
IDs rather than adding an unsupported configuration option.

## Run and inspect

From this directory:

```sh
docker compose -f compose.yaml config --quiet
python3 -m unittest test_queries.py
python3 run.py --seconds 60 --keep
```

The runner builds the fixture, starts the application and backend, then starts
only the selected diagnostics. Agent attachment does not restart the application.
It holds `/tmp/obi-diagnostic-poc-live.lock` throughout collection; sibling PoCs
using the same lock run sequentially. With `--keep`, services remain available for
browser inspection after collection. The default command cleans up this project.

Open [Grafana](http://localhost:3102/). `evidence/<run>/<mode>/summary.json` contains
clickable aggregate and span-specific profile URLs and exact trace URLs. Select
the off-CPU profile type in Profiles Drilldown, inspect its stacks, and follow a
recorded exemplar to its trace. The helper checks that the exact exemplar span
ID appears in that trace; it never creates associations from overlapping times.
Compare `/syscall`, `/runtime`, and `/downstream` processing spans in Tempo.

Each mode directory contains its absolute interval, raw profile types, aggregate
flame graph, heatmap exemplars, selected span profiles, trace responses, logs,
and an accounting summary. The top-level traffic log records completions,
errors, and latency; continuity records container ID, PID, and start time.
Profile-only mode explicitly disables OBI context reading, including retained
map entries from an earlier OBI process.

To requery an interval while the backend is running:

```sh
python3 query.py --start-ms 1234567890000 --end-ms 1234567950000 \
  --output evidence/requery
```

Use the actual values in a recorded `window.json`. A new output directory is
required. Failed queries remain explicit errors rather than a diagnosis.
After the default cleanup, reopen the retained backend with
`docker compose -f compose.yaml up -d --no-deps lgtm` to inspect saved evidence
links. This starts neither the application nor diagnostic agents.

## Interpretation limits

The off-CPU threshold is 1: all eligible scheduler transitions are selected.
This can increase host-wide collection overhead. Queries select only the
fixture's service, but the privileged profiler observes other host processes.
Off-CPU durations are nanoseconds between a recorded switch-out and resumption;
they include sleeping and scheduling delays. They do not establish a lock owner,
an I/O cause, or why the request was blocked. CPU values are sampled execution.

OS-thread waiting is different from parked goroutine waiting. OBI preserves
context for a Go goroutine in syscall state, removes it when the goroutine parks,
and restores it when execution resumes. The profiler reads context when
collecting the resumed thread's stack. Runtime idle stacks must not be attributed
to `/runtime` merely because the request is outstanding.

Profiles and exemplar selection are not exhaustive. Exports can cross window
boundaries, waits can be missed, stacks can fail to unwind, and the off-CPU map has
finite capacity. Function cumulative values overlap and must not be summed;
self values are checked against the profile total. Neither total is a complete
request latency decomposition. No matching sample is missing evidence, not proof
that a request did not execute or wait. Retained backend data cannot supply an
answer outside the selected interval.

## Cleanup

```sh
docker compose -f compose.yaml down
```

This retains evidence files and the project's backend volume. To remove only
this example's backend data, use `docker compose -f compose.yaml down --volumes`.
Do not run a global Docker prune or remove shared host BPF files.

See [FINDINGS.md](FINDINGS.md) for actual observed outcomes and limitations.
