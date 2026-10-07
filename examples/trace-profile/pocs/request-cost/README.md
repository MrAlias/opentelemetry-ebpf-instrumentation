# Why are some requests to the same endpoint expensive?

This experiment compares OBI alone, the OpenTelemetry eBPF profiler alone, and
both together. It uses uninstrumented Go HTTP handlers, an ordinary application
container PID namespace, and concurrent unrelated CPU work. The result is a
comparison of ordinary and slow `/work` requests using CPU samples associated
with their exact OBI processing span IDs.

This is a controlled diagnostic experiment. The fixture implements two CPU
paths under the same route, with one path taking longer, and two workers generate
unrelated `/report` traffic. Function names describe fixture work; the application
does not implement a real cache or report export. The analysis discovers paths
from telemetry and does not assert an expected function name as its diagnosis.

## Requirements

- Linux amd64 with Docker Engine and Docker Compose v2, kernel eBPF support, and
  a writable BPF filesystem at `/sys/fs/bpf`. The diagnostic agents are privileged.
- Python 3.10 or later, with its standard library. No AI client or API key is needed.
- Available localhost ports 8181 (application) and 3101 (Grafana).
- The OBI image built from the checkout under investigation. The recorded run used
  revision `6d873d705d77e9764adab67502d65695df986e93` and its local image tag
  `obi-ai-investigation:6d873d7`.

From the repository root, build a fresh image when that local image is absent:

```sh
docker build --build-arg RELEASE_REVISION="$(git rev-parse HEAD)" \
  --build-arg RELEASE_VERSION=poc -t obi-request-cost:local .
export COST_OBI_IMAGE=obi-request-cost:local
```

The pinned profiler is Collector 0.160.0 and the pinned backend is
`grafana/otel-lgtm:0.33.1`. Image digests appear in `compose.yaml`; the Go builder
is also pinned. The app has an independent Go manifest and no external Go
packages, tracing SDK, or profiling SDK.

This OBI revision publishes shared context directly and does not expose
`populate_trace_context`. The experiment does not set an unsupported knob. It
records actual sample IDs and verifies them against trace payloads.

## Run all four comparisons

From the repository root:

```sh
python3 examples/trace-profile/pocs/request-cost/run.py \
  --output /tmp/request-cost-evidence --seconds 45
```

Choose an unused output directory. The runner:

1. Holds `/tmp/obi-diagnostic-poc-live.lock` through setup, collection, and cleanup.
2. Starts only Compose project `obi-poc-cost` and records application identity.
3. Generates sustained requests before diagnostics attach and through collection.
4. Collects distinct windows for `obi-only`, `profiler-only`, `combined`, and
   `no-correlation`, allowing discovery and export time between them.
5. Retries visibility checks for at most 90 seconds after the initial export wait,
   comparing retrieved target traces with recorded request completions. Missing
   evidence after that bound remains an explicit uncertainty.
6. Retrieves real traces, aggregate profiles, span exemplars, and exact-span
   profiles. It compares `/work` requests below and above 400 milliseconds.
7. Saves telemetry, normalized CPU values, identity checks, image identities, and
   traffic outcomes. It removes only this project's containers and data volume.

`profiler-only` explicitly disables OBI context consumption, so stopped OBI's
pinned map cannot provide stale associations. `no-correlation` runs both agents
with that consumption disabled. `combined` restores it. The app is never
restarted or recreated when changing diagnostic modes.

Inspect each mode's `summary.json`, `requests.json`, `aggregate-summary.json`,
`ordinary-requests.json`, `slow-requests.json`, and `verified-exemplars.json`.
`traces/` and the profile JSON files contain the backend responses supporting the
analysis. Backend and accounting failures stop collection and are saved as
`failure.json`; they are not replaced by a diagnosis or by an empty profile.
`traffic-summary.json` reports request completions, errors, and latency before
attachment and within each collection window; it does not establish zero overhead.

Use `--modes combined --keep-running` for browser inspection. This retains the
application and backend after collection. Diagnostic agents stop before the
host lock is released, so browser inspection does not retain active diagnostic
programs. Operator cleanup is required afterward.

## Inspect the browser evidence

For a retained run, open <http://localhost:3101> and navigate through Profiles
Drilldown to service `obi-poc-cost`. Set the exact interval from `summary.json`.
The whole-service flame graph contains the unrelated CPU work as well as target
work. The span heatmap exposes recorded exemplars and their trace IDs.

Each row in `ordinary-requests.json` and `slow-requests.json` contains a
`profile_url` and `trace_url`. Open both:

- The trace must contain `GET /work` and the exact `processing_span_id`.
- The profile URL selects that processing span's samples, rather than all service
  samples. Compare ordinary and slow requests.
- `verified-exemplars.json` contains actual exemplars matched to both trace ID
  and processing span ID. This relationship is not constructed from timestamps.

Optional screenshots use a separate pinned Playwright dependency:

```sh
cd examples/trace-profile/pocs/request-cost/browser
npm ci
npx playwright install chromium
node capture.cjs /tmp/request-cost-evidence/combined
```

The helper records browser screenshots, visible text, exact evidence links, and
whether the trace ID appears in the trace page. It requires a running backend;
the historical evidence files alone do not restore backend storage.

## Replay the saved evidence without Docker

```sh
python3 examples/trace-profile/pocs/request-cost/replay.py \
  examples/trace-profile/pocs/request-cost/evidence/validated-20261005
```

This verifies raw trace/span relationships, recorded exemplars, individual CPU
profiles, cohort totals, and aggregate accounting. It prints the observed hot
functions and CPU per request without reading fixture source or contacting a
backend. Screenshots under `combined/browser/` preserve the validated UI result.
The historical links require the original backend data, which operator cleanup
removed; a new live run supplies usable links for its own fresh interval.

## Interpretation and limitations

OBI alone shows request durations and distinct latency groups on `/work`. The
profiler alone shows CPU functions and may identify a handler from its stacks, but
cannot identify an individual request trace or separate latency cohorts from CPU
samples alone.
The combined mode measures which functions contributed CPU to each group, even
when other traffic dominates the aggregate profile.

CPU totals are nanoseconds of sampled execution, not request wall time. Per-request
means divide by every selected completed request, including requests without
samples. `requests_with_samples` exposes coverage. Function self values sum to
CPU total; cumulative values overlap and must not be added together. A missing
sample does not prove that a request consumed no CPU.

The comparison includes only whole server spans inside the recorded interval
with one exact OBI `processing` child. Trace search is capped at 1,000 traces;
cohort selection is capped at 100 requests, and truncation is reported. The
heatmap supplies a bounded exemplar selection. These are diagnostic samples,
not a production cost-accounting or overhead benchmark. Concurrent external
workloads and diagnostic agents are recorded in metadata and can affect timings.

The fixture forces two execution paths. An observed association establishes
where sampled CPU executed; it does not establish why a production application
selected a path, whether that path is unnecessary, or whether CPU explains all
latency. Those require further application or waiting evidence.

## Checks and cleanup

```sh
docker compose -f examples/trace-profile/pocs/request-cost/compose.yaml \
  --profile diagnostics config --quiet
python3 -m unittest discover -s examples/trace-profile/pocs/request-cost \
  -p test_run.py
(cd examples/trace-profile/pocs/request-cost/app && go build -buildvcs=false -o /tmp/obi-poc-cost .)
make lint-markdown
```

After a retained browser run, hold the shared lock while removing only this
project:

```sh
flock /tmp/obi-diagnostic-poc-live.lock docker compose \
  -p obi-poc-cost -f examples/trace-profile/pocs/request-cost/compose.yaml \
  --profile diagnostics down --volumes
```

The runner changes no unrelated project, image, application, or global settings.
The fixture image and evidence files remain available for another run.
