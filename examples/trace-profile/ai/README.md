# AI investigation experiment

This optional experiment asks Codex to investigate a slow `/work` request using
telemetry collected after attachment. It does not change the app or apply fixes.
The original browser example remains available through the base Compose file.

## Prepare the operator environment

Use the Linux and Docker requirements in the [example README](../README.md).
Also install Go, Python 3.11 or newer, and Codex CLI; run `codex login` if needed.
The runner uses the existing login and `model` in the local Codex configuration.
No separate model API key is required. It runs each investigation in a fresh
empty randomly named directory outside the repository, with shell, web search and app connectors
disabled. Do not provide the assistant with source, fixture settings or expected
answers; such a run is invalid.

From the repository root, build OBI from this checkout and the local MCP server:

```sh
revision=$(git rev-parse HEAD)
export AI_OBI_IMAGE="obi-ai-investigation:${revision}"
docker build -t "$AI_OBI_IMAGE" \
  --build-arg RELEASE_REVISION="$revision" \
  --build-arg RELEASE_VERSION=ai-poc .
(cd examples/trace-profile/ai && go build -o /tmp/obi-incident .)
```

Install the official [Grafana MCP server](https://github.com/grafana/mcp-grafana)
**v2.0.0**, choosing the release archive for your host. For Linux amd64:

```sh
curl --fail --location --output /tmp/mcp-grafana.tar.gz \
  https://github.com/grafana/mcp-grafana/releases/download/v2.0.0/mcp-grafana_Linux_x86_64.tar.gz
printf '%s  %s\n' \
  0a0dde2c882c24fedcce79a07d97b232f71730c744b84a09b6b0735c2ca3d024 \
  /tmp/mcp-grafana.tar.gz | sha256sum --check
mkdir -p /tmp/obi-grafana-mcp
tar -xzf /tmp/mcp-grafana.tar.gz -C /tmp/obi-grafana-mcp
```

From `examples/trace-profile`, start only the app and backend:

```sh
docker compose -p obi-ai-investigation \
  -f docker-compose.yml -f docker-compose.ai.yml up --build -d app lgtm
```

Wait for [AI Grafana](http://localhost:3001) to be ready. The AI app listens on
`localhost:8081`, runs as an unprivileged user in its ordinary container PID
namespace, and uses executable/service name `obi-ai-demo`. The diagnostics share
`/sys/fs/bpf/obi-ai-investigation`; this also isolates them from the original
browser example. The profiler and LGTM retain their pinned images.

## Run one fresh investigation per scenario

From `examples/trace-profile`:

```sh
python3 ai/run.py --scenario cpu --output /tmp/obi-ai-cpu \
  --incident-binary /tmp/obi-incident \
  --grafana-binary /tmp/obi-grafana-mcp/mcp-grafana --approve-attachment
python3 ai/run.py --scenario waiting --output /tmp/obi-ai-waiting \
  --incident-binary /tmp/obi-incident \
  --grafana-binary /tmp/obi-grafana-mcp/mcp-grafana --approve-attachment
```

Choose unused output directories. The operator selects the scenario before the
incident; the assistant receives the same generic symptom in both cases. The
runner stops this project's diagnostic agents and recreates the fixture **before**
the incident, then keeps concurrent `/work` and `/report` traffic running before
attachment and throughout investigation. It records container ID, host PID,
start time, individual request results and latency summaries. Requests straddling
attachment remain in the raw log but are excluded from before/after summaries.

`--approve-attachment` is an explicit operator authorization for this run. It is
recorded and granted only after the assistant invokes attachment and receives
`approval_required`. Without the flag, the run stops at the approval request and
starts no agents. The assistant cannot write the authorization file because shell
and file tools are disabled. Cleanup is never exposed through MCP.

The local server listens on a random loopback port with a per-run bearer token.
The generated `mcp.config.toml` is local, mode 0600, and changes no global Codex
configuration. The HTTP server runs outside the assistant sandbox to inspect
Docker. Codex permits calls to this fixed tool server; the server independently
checks operator authorization before mutation. Grafana MCP exposes only the
allowlisted datasource, Pyroscope, Tempo and link tools with writes disabled.

The runner saves prompts, actual client/MCP versions, model, revision and image
identities, MCP calls and outputs,
operator approval, collection times, application continuity, traffic, and both
assistant answers. Review `investigation.md`, not just `valid_run`:
that flag checks isolation and continuity, not diagnosis correctness. Preserve
unsuccessful and inconclusive results. An uncorrelated hotspot is not sufficient
to explain the target request.

## Tools and evidence

The example-local server uses the pinned Go MCP SDK and Pyroscope's existing
Connect APIs through Grafana's datasource proxy:

| Tool | Responsibility |
| --- | --- |
| `diagnostic_status` | App identity, agent state, current time and backend availability |
| `attach_diagnostics` | Approval-gated, fixed-project start of `obi` and `profiler` only |
| `span_exemplars` | Actual sampled trace/span IDs, timestamps, values and browser links |
| `span_profile` | CPU samples for exact span IDs, total, function self/cumulative values |

Attachment uses `up -d --no-deps --no-build --pull never obi profiler` with fixed
Compose paths. It cannot build, restart or recreate the application. The server
checks application identity before and after attachment. A failed identity check
is reported as failure, not silently repaired.

Profile totals are computed and checked in code. IDs are normalized from hex or
protobuf base64. Responses include nanosecond units, intervals, truncation and
explicit missing-data states. Exemplars are a bounded selection, not all requests;
CPU time is not wall time. Backend failures remain errors instead of empty data.
Use `span_exemplars` IDs to retrieve a Tempo trace and verify that it contains the
exact linked span before attributing a hotspot to `/work`.

The generic [investigation prompt](investigate.md) requires facts, a supported
hypothesis, uncertainty and clickable evidence. Queries must use the fresh
incident interval and retries stop two minutes after attachment. The local
profile tools reject windows before `collection_start` or after
`collection_deadline`; historical inspection of the recorded window remains
possible afterward. Distinguish
export delay, missing CPU profiles, absent sample links and unavailable traces.
The waiting case should ask for additional waiting/off-CPU, dependency or runtime
evidence rather than blame concurrent `/report` CPU activity.

## Negative check and browser validation

Run the correlation control in a **new interval**, preserving the app and OBI:

```sh
OBI_PROCESS_CTX=false docker compose -p obi-ai-investigation \
  -f docker-compose.yml -f docker-compose.ai.yml \
  up -d --no-deps --force-recreate profiler
```

Generate sustained concurrent requests. Query aggregate CPU and span exemplars
for only this new interval. Aggregate CPU must remain available while exemplars
are absent. For a fresh assistant control, repeat `ai/run.py` with a new output
directory and `OBI_PROCESS_CTX=false` in the operator environment. The assistant
is given the same generic incident prompt, without the control setting. An assistant examining this control must report the missing
association, not invent a trace based on timestamps. Restore correlation:

```sh
OBI_PROCESS_CTX=true docker compose -p obi-ai-investigation \
  -f docker-compose.yml -f docker-compose.ai.yml \
  up -d --no-deps --force-recreate profiler
```

Open returned evidence links in Grafana and save screenshots beside the run.
Check that a profile link selects the exact span and that the Tempo trace contains
that span ID. Sign in with `admin` / `admin` if prompted. Multi-span profile queries
provide an aggregate browser link; their exact ID set remains in the tool output.
See the [feasibility report](feasibility.md) for the recorded validation outcome.

## Validate and clean up

```sh
docker compose -p obi-ai-investigation \
  -f docker-compose.yml -f docker-compose.ai.yml --profile diagnostics config --quiet
(cd ai && go test ./... && go build -o /tmp/obi-incident .)
(cd app && go test ./... && go build -o /tmp/obi-ai-app .)
```

Run `make lint-markdown` from the repository root. The operator removes this
experiment with:

```sh
docker compose -p obi-ai-investigation \
  -f docker-compose.yml -f docker-compose.ai.yml down
```

These scenarios test feasibility only. They do not establish reliability,
zero overhead, arbitrary runtime coverage or automated resolution.
