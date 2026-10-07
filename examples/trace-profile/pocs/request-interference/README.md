# Does one request make another wait?

This experiment compares OBI alone, the OpenTelemetry eBPF profiler alone,
and their cooperation against two deliberately similar workloads. Both expose
slow `/work` requests and overlapping CPU-heavy `/report` requests. In one,
`/report` owns the mutex that `/work` needs. In the control, `/work` sleeps
independently while `/report` does the same CPU work.

The question is whether the diagnostic evidence establishes that `/report`
caused `/work` to wait. CPU attribution establishes which request ran hot code.
It does not establish lock ownership or interference. See [FINDINGS.md](FINDINGS.md)
for the recorded outcome, including what remains unresolved.

## Requirements

- A Linux host with BTF and eBPF support, Docker daemon access, and Docker Compose.
- Python 3.11 or newer. The helper uses only the standard library.
- TCP ports 8183 and 3103 available on localhost.
- An OBI image built from this checkout. The application needs no tracing or
  profiling SDK and uses its ordinary container PID namespace.

The application, Compose project, service name, backend volume, and BPF pin root
are specific to this example. The profiler samples the host, so its collection
overhead is not isolated to the fixture. The runner holds
`/tmp/obi-diagnostic-poc-live.lock` while agents are active and through optional
cleanup, to serialize the diagnostic PoCs in this directory tree.

## Build and run

From the repository root, build OBI if the validated local image
`obi-ai-investigation:6d873d7` is unavailable:

```sh
docker build --build-arg RELEASE_REVISION="$(git rev-parse HEAD)" \
  -t obi-poc-interference-obi:local .
export OBI_IMAGE=obi-poc-interference-obi:local
export OBI_BUILD_REVISION="$(git rev-parse HEAD)"
```

Record the checkout revision when using a custom image. The recorded validation
used revision `6d873d705d77e9764adab67502d65695df986e93`; `metadata.json` records
the actual image IDs, digests, checkout revision, and configured references.
`reference_obi_revision` describes the default cached image. A custom image's
build revision is unknown unless the operator records it separately; an image
ID or tag does not establish a Git revision.

```sh
cd examples/trace-profile/pocs/request-interference
docker compose --profile diagnostics config --quiet
docker compose --profile diagnostics pull lgtm profiler
python3 -m unittest -v test_poc.py
python3 poc.py run --build --output evidence/my-run
```

The run takes several minutes. Each of the six case/mode combinations has a
separate recorded interval. The application starts before diagnostic agents;
the runner records two request pairs before attachment, six during diagnostic
startup, and ten in the selected collection interval afterward. Traffic
continues during agent discovery rather than waiting idle for a fixed delay.
Container identity, host PID, and start time must remain unchanged across that
attachment. The application is deliberately recreated when changing scenarios.

Profiler-only runs set `obi_process_ctx: false`. This prevents the profiler from
reading a retained OBI map after OBI has stopped. Combined runs enable it and
use the shared map under `/sys/fs/bpf/obi-poc-interference/otel/traces_ctx_v1`.
This OBI revision populates the shared context without a
`populate_trace_context` configuration field; an ignored flag is not used.

To run only one combination:

```sh
python3 poc.py run --cases shared-lock --modes combined \
  --output evidence/my-combined-run
```

Output directories must be new. If another PoC holds the host lock, the command
fails without starting agents; select a new output directory when retrying.
The runner stops its own diagnostic agents at completion or failure. Add
`--cleanup` to remove this project's containers and network while preserving
its backend volume. It never stops other Compose projects.

## Browser investigation

Open [Grafana](http://localhost:3103). For a saved phase:

1. Open its `summary.json` and follow `profile_url` to the aggregate CPU graph.
   The expected report hotspot is `main.prepareReport`.
2. In a combined phase, choose an exemplar with `exact_span_found: true` and
   follow `profile_url` and `trace_url`. Those URLs use the actual exported IDs.
   The saved `trace_spans` lists the enclosing HTTP request and the exact
   sampled processing span.
3. Inspect a `/work` trace from the same interval. Ask what evidence establishes
   its wait location and the resource owner. A long span, overlapping traffic,
   and an unrelated CPU hotspot do not establish those facts.
4. Compare the shared-lock and control phases. Their similar symptoms test
   whether an interpretation based on temporal overlap would invent causality.

The URLs require the same retained backend data and localhost port. A new host
can replay raw saved responses without running Docker, but must collect its
own telemetry for live browser links. No `pyroscope.profile.id` display adapter
or trace-to-profile span attribute is added.

For optional reproducible screenshots, Node 20 or newer and npm are needed to
install the pinned Playwright client. The Docker image supplies its browser:

```sh
python3 poc.py browser-links --output evidence/my-run
npm ci --prefix browser --ignore-scripts
docker run --rm --network host \
  -v "$(realpath browser)":/tools:ro \
  -v "$(realpath evidence/my-run)":/evidence -w /tools \
  mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27 \
  node capture.cjs /evidence/browser-links.json
```

Capture writes PNGs, page text, and `browser-results.json`. A loaded page is
not proof of an association; exact trace/span IDs are verified separately from
raw backend responses by `replay`.

## Evidence and replay

Each phase saves:

- `window.json`: fixed query interval; `collection.json`: bounded retry outcome.
- `traffic.json` and `continuity.json`: completions, errors, latency, and
  application identity before and after attachment. These are observations,
  not an overhead benchmark.
- `raw/`: actual API requests and unmodified backend responses, including
  trace search, individual traces, aggregate CPU, span exemplars, and exact
  span-selected profiles.
- `summary.json`: CPU self and cumulative values in nanoseconds, normalized
  IDs, exact trace/span verification, bounded exemplar selection, and links.
  Function cumulative values overlap and must not be summed.
- `fixture-ground-truth.json`: application-emitted mutex events used only to
  validate the controlled workload. These are explicitly excluded from the
  diagnostic evidence; they are not a feature supplied by OBI or the profiler.
- `agent-logs.json`: logs for this project's diagnostic agents.

```sh
python3 poc.py replay --output evidence/my-run/shared-lock-combined
python3 poc.py replay --output evidence/my-run/control-combined
python3 poc.py verify-fixture --output evidence/my-run/shared-lock-combined
python3 poc.py verify-fixture --output evidence/my-run/control-combined
```

Replay checks sample accounting and that each claimed association has the exact
span ID and trace ID in the fetched payload. It does not reinterpret nearby
requests as correlations. Exemplars are a bounded selection, not an exhaustive
request list. Empty profiles or absent exemplars do not prove that execution
or contention did not happen.
`verify-fixture` checks the controlled mutex lifecycle separately. It does not
associate its local application request sequence with OTel span IDs or supply
missing diagnostic ownership measurements.

To query a recorded interval again while the backend is running:

```sh
python3 poc.py collect --mode combined --start-ms 1234567890000 \
  --end-ms 1234567920000 --output evidence/my-query
```

Use the real epoch millisecond values from `window.json`. Backend errors are
preserved explicitly. Initial export delay is retried for at most two minutes
against the original fixed interval; later traffic cannot supply its answer.
The runner retries missing signals; it does not wait for every request to
appear in a trace search. `collection.json` compares the observed search count
with successful HTTP completions and explicitly records an incomplete count.
Search remains bounded to 200 traces, and stored individual payloads are a
selection, not a claim of complete capture.
When the last retry expires, the helper retains the most complete actual saved
response and preserves deadline errors separately in `deadline-response/`.
`summary.json` records the selected attempt. The validation exposed this edge
case; `recover-partial` applies the same selection to an existing phase and
then replays its accounting and exact IDs:

```sh
python3 poc.py recover-partial --output evidence/my-run/shared-lock-obi
```

## What a causal extension would need

The smallest justified next experiment is a resource ownership probe for one
known synchronization primitive. It must capture resource identity, acquisition
and release, waiter identity and wait interval, and the relevant request context
at each event. For Go, identities must follow goroutines rather than only OS
threads. Pair events by resource and execution identity; never infer ownership
from timestamp overlap alone. Record lost events and unresolved owners.

OBI would provide request context. The profiler would provide the holder's
execution stacks. The ownership probe would supply the causal relationship.
That is a third measurement capability. It must pass this same noninterfering
control before it supports a stronger talk claim.

Upstream's [async collection proposal](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/issues/1769)
discusses capturing a stack at initiation and attaching a measurement at
completion. That would help wait-duration attribution; it does not itself
identify a mutex owner. Existing generic uprobe event counts also do not supply
the required ownership lifecycle. OS-thread off-CPU stacks cannot substitute
for Go goroutine contention events, as the
[off-CPU design](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/design-docs/00001-off-cpu-profiling/README.md)
explains.

A Go mutex probe also has to capture successful fast-path acquisitions, which
can be inlined, and tolerate an unlock performed by a different goroutine.
The [Go mutex contract](https://pkg.go.dev/sync#Mutex)
does not bind a locked mutex to a particular goroutine. Calling the last
observed OS thread its owner would be incorrect. These constraints are reasons
to scope a next experiment carefully rather than promise general ownership
tracking from the existing shared trace-context map.

## Cleanup

```sh
docker compose --profile diagnostics down
```

This removes only the example's containers and network. Its named backend volume
remains for later browsing. To restart the backend without attaching agents:

```sh
docker compose up -d --no-deps lgtm
```

Delete this project's retained backend data only when finished:

```sh
docker compose --profile diagnostics down --volumes
```

## Validation

```sh
python3 -m unittest -v test_poc.py
cd app
go test ./...
go build -o /tmp/obi-poc-interference .
cd ..
docker compose --profile diagnostics config --quiet
```

Run `make lint-markdown` from the repository root.
