# eBPF CPU profiles linked to OBI traces

Open the app's CPU flame graph in Grafana Profiles Drilldown, select a span exemplar, and open its trace in Tempo. Tempo stores traces; Pyroscope stores profiles. The Go app uses neither a tracing SDK nor a profiling SDK.

## Requirements

- A Linux host (amd64 or arm64) with BTF and a kernel supported by both OBI and the eBPF profiler; kernel 5.8 or newer is the OBI baseline.
- Docker Engine and Docker Compose with permission to run privileged containers and use the host PID namespace. Docker Desktop's VM is not the intended host for this example.
- A writable BPF filesystem mounted at `/sys/fs/bpf`. Check with `findmnt /sys/fs/bpf`; its filesystem type must be `bpf`. If it is not mounted, mount it on the host:

  ```sh
  sudo mount -t bpf bpf /sys/fs/bpf
  ```

The profiler samples processes across the host. Use a development host: OBI and the profiler run privileged. Grafana and the demo app are exposed only on localhost.

## Start and generate requests

From this directory:

```sh
docker compose up --build -d
```

Wait for [Grafana](http://localhost:3000) to become available and for OBI to attach to `obi-profile-demo` (normally a few seconds after app startup). Generate several five-second CPU-bound requests:

```sh
for i in 1 2 3 4 5; do
  curl --fail --max-time 15 http://localhost:8080/work
done
```

Allow a minute for traces and profiles to be exported and queryable. This example pins OBI `v0.13.0`, the OTel eBPF profiler Collector `0.160.0`, and `grafana/otel-lgtm:0.33.1`. Profiles are an evolving OTLP signal; keep these versions together.

## Open a trace from its profile

1. Open [Grafana Profiles Drilldown](http://localhost:3000/a/grafana-pyroscope-app/explore). If prompted, sign in with `admin` / `admin`.
2. Select the **Pyroscope** datasource, service **obi-profile-demo**, and **CPU time consumed** profile type (`process_cpu:cpu:nanoseconds:cpu:nanoseconds`). Use a recent time range covering the requests.
3. Select **Flame graph** and confirm the workload includes **main.burnCPU**.
4. In **Profile timeline visualization**, select **Span heatmap**. Under **Top span exemplars**, select **Tempo** as the trace datasource.
5. Choose an exemplar and click **Open trace**. Confirm the associated `/work` trace appears and contains the exemplar's span ID. For this app and OBI version, CPU samples are attributed to the `processing` child span.
6. Close the trace drawer and use **Open flame graph** on the same exemplar to inspect its CPU samples, including **main.burnCPU**. Exemplars can represent a portion of a request captured in one profile export interval.

The initial flame graph aggregates multiple requests. A span exemplar identifies a contributing span using the trace/span IDs recorded during sampling. Sampling is statistical, so short spans may have no exemplars.

Profiles-to-traces is a Grafana public preview feature. Compose enables the `profilesHeatmap` feature flag required by the pinned Grafana build. See [Grafana's profiles-to-traces browser workflow](https://grafana.com/docs/grafana/latest/visualizations/simplified-exploration/profiles/investigate/#move-from-profiles-to-traces).

## How correlation works

- OBI publishes the active trace/span context. For this Go HTTP app on OBI `v0.13.0`, samples belong to the `processing` child span.
- The demo app also uses the host PID namespace so Go runtime thread IDs match the host IDs used in the shared map, including threads already running when OBI attaches. It still runs as an unprivileged user with all capabilities dropped.
- OBI and the profiler share the same writable host `/sys/fs/bpf` mount. OBI publishes active trace/span context in `/sys/fs/bpf/otel/traces_ctx_v1`.
- The profiler's `obi_process_ctx: true` reads that map while sampling and exports actual sample links carrying trace and span IDs over OTLP to LGTM's Collector. The Collector forwards profiles to Pyroscope and traces to Tempo.
- Pyroscope maps `process.executable.name` to `service_name`. The binary and OBI trace service both use `obi-profile-demo`.
- Grafana Profiles Drilldown reads span exemplars from Pyroscope and uses their trace IDs to look up traces in the selected Tempo datasource. No Collector span enrichment or span-name matching is required.

See the [Grafana eBPF profiler setup](https://grafana.com/docs/pyroscope/latest/configure-client/opentelemetry/ebpf-profiler/).

## Negative check: turn off sample correlation

Keep OBI running and recreate the profiler with correlation disabled:

```sh
OBI_PROCESS_CTX=false docker compose up -d --force-recreate profiler
```

Wait for the profiler to start, then generate **new** `/work` requests using the loop above. Set Grafana's time range to cover only these new requests. The service flame graph should still contain `main.burnCPU`, but there must be no span exemplars linking this workload to Tempo. **Span heatmap** may be unavailable when the selected interval contains no linked samples. Old linked samples remain stored, so exclude the positive-check interval.

Restore the finished example and repeat with another new request:

```sh
docker compose up -d --force-recreate profiler
curl --fail --max-time 15 http://localhost:8080/work
```

Ensure `OBI_PROCESS_CTX` is unset or `true` in your shell when restoring.

## Validation and troubleshooting

```sh
docker compose config --quiet
```

From the repository root, run `make lint-markdown`. Successful configuration validation is not live proof of correlation: complete both browser checks above on the Linux host.

Live browser validation on Linux amd64 with these pinned images confirmed:

- A Pyroscope span exemplar opens its associated `/work` trace in Grafana's trace drawer. The trace contains the exemplar's exact `processing` span ID and has no `pyroscope.profile.id` enrichment.
- **Open flame graph** on that exemplar returns samples containing `main.burnCPU`.
- With `obi_process_ctx` disabled, a fresh time window still contains the CPU workload but has no span exemplars; the span heatmap selector is disabled. Correlation was restored afterward.

- **No trace:** check `docker compose logs obi`; wait for attachment before sending traffic.
- **No profiles at all:** check `docker compose logs profiler lgtm`, allow time for export, and inspect the service CPU flame graph.
- **No span exemplars:** check that both agents see the same mounted BPF filesystem, that `otel/traces_ctx_v1` exists, and that `OBI_PROCESS_CTX` is `true`. Check that Grafana's `profilesHeatmap` feature is enabled and the time range covers new requests.
- **Exemplars exist but traces do not load:** select the Tempo datasource, allow time for OBI to export traces, and check Collector and Tempo logs.

Stop and remove the demo containers with `docker compose down`. Do not delete shared BPF pins while another OBI/profiler deployment uses them.

## Optional AI investigation

The [Codex and MCP experiment](ai/README.md) collects fresh telemetry after
approved diagnostic attachment to an already-running container. It tests both a
CPU-heavy target request and a waiting target with competing CPU activity, and
records evidence, application continuity and measured traffic impact.

## Request investigation PoCs

The [request investigation experiments](pocs/README.md) compare OBI alone, the
profiler alone, and both for request cost, waiting, and interference. Each has
an independent workload and runner, recorded live evidence, and findings that
separate supported conclusions from missing measurements.
