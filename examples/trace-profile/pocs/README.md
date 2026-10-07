# Request investigation experiments

These experiments compare OpenTelemetry eBPF Instrumentation (OBI), the
OpenTelemetry eBPF profiler, and their cooperation. Each experiment supplies an
independent workload, Docker Compose project, runner, retained evidence, and a
findings document. The original browser and AI examples remain separate.

## Questions

| Experiment | Question | Comparison |
| --- | --- | --- |
| [Request cost](request-cost/README.md) | Why are some requests to the same endpoint expensive? | CPU evidence for ordinary and expensive requests amid unrelated CPU traffic |
| [Request waiting](request-waiting/README.md) | Where does a request spend time when it uses little CPU? | Blocking system call, parked goroutine, and traced downstream call |
| [Request interference](request-interference/README.md) | Is another request responsible for the wait? | Shared-lock contention and a control with overlapping CPU activity but no shared lock |

## Recorded findings

The retained Linux runs establish different limits for these questions:

| Experiment | Observed result | What cooperation adds |
| --- | --- | --- |
| [Request cost](request-cost/FINDINGS.md) | **Answered:** slow requests used about 5.45 times the sampled CPU per request and ran a different execution path. Unrelated traffic supplied about 73% of the service's aggregate CPU. | Request duration selects the cohorts; exact span profiles identify their own hot code. |
| [Request waiting](request-waiting/FINDINGS.md) | **Strengthened:** real blocking syscall stacks were associated with exact requests. Parked Go goroutine waits remained unexplained. One selected off-CPU duration exceeded its request's wall time. | Request identity makes blocking stacks useful for an individual investigation; reliable waiting-time accounting remains unestablished. |
| [Request interference](request-interference/FINDINGS.md) | **Unresolved:** both the shared-lock case and the independent-wait control produced report CPU profiles associated with exact request spans. | Identifies the requests doing CPU work, but supplies no resource ownership measurement that distinguishes the causes of the target's wait. |

Each findings document preserves the comparison modes, actual IDs, collection
failures, application continuity, traffic measurements, and browser evidence.
Saved raw responses can be inspected without Docker. Historical browser URLs
require retained backend data; follow the individual README to collect new data
or reopen its retained backend.

## Run independently

Use a supported Linux amd64 host with Docker Compose, privileged eBPF access,
BTF, writable `/sys/fs/bpf`, and Python 3.11 or later. Build OBI once from the
repository root and select that image for all three experiments:

```sh
docker build -t obi-diagnostic-pocs:local \
  --build-arg RELEASE_REVISION="$(git rev-parse HEAD)" \
  --build-arg RELEASE_VERSION=diagnostic-poc .
export COST_OBI_IMAGE=obi-diagnostic-pocs:local
export OBI_IMAGE=obi-diagnostic-pocs:local
export OBI_BUILD_REVISION="$(git rev-parse HEAD)"
```

Run any experiment from the repository root. Choose an unused output directory
for each run:

```sh
python3 examples/trace-profile/pocs/request-cost/run.py \
  --output /tmp/request-cost-evidence
python3 examples/trace-profile/pocs/request-waiting/run.py \
  --output /tmp/request-waiting-evidence
python3 examples/trace-profile/pocs/request-interference/poc.py run \
  --build --cleanup --output /tmp/request-interference-evidence
```

The individual READMEs explain browser inspection, saved evidence, validation,
and cleanup. The pinned profiler and backend images are shared Docker image
layers; each project has independent containers and data.

## What counts as an answer

Each runner collects fresh intervals for OBI alone, the profiler alone, and both.
The fixture supplies ground truth for evaluating conclusions; operational
conclusions must come from captured telemetry. Profile attribution requires
actual sample trace/span IDs verified against the retrieved trace. Temporal
overlap does not establish request attribution or resource ownership.

Reports distinguish three outcomes:

- **Answered:** the collected evidence supports the stated conclusion.
- **Strengthened:** cooperation adds useful evidence but does not settle the
  question.
- **Unresolved:** a required measurement is absent or collection is inconclusive.

Missing CPU samples do not prove that no CPU work occurred. CPU sample values
are estimates, not request wall time. Cohort comparisons disclose their request
counts, sampling coverage, units, and normalization.

## Isolation

| Experiment | Compose project | Application port | Browser port | BPF root |
| --- | --- | --- | --- | --- |
| Request cost | `obi-poc-cost` | `8181` | `3101` | `/sys/fs/bpf/obi-poc-cost` |
| Request waiting | `obi-poc-waiting` | `8182` | `3102` | `/sys/fs/bpf/obi-poc-waiting` |
| Request interference | `obi-poc-interference` | `8183` | `3103` | `/sys/fs/bpf/obi-poc-interference` |

Application and browser ports bind to localhost. Each experiment uses its own
application executable/service identity and backend data. Runners serialize
default live collection with `/tmp/obi-diagnostic-poc-live.lock` to avoid
interference between these experiments. If keeping agents running for browser
inspection, clean up that project before running another experiment. Existing
host activity can still affect results;
these are diagnostic feasibility experiments, not overhead benchmarks.

Use the setup, run, evidence inspection, and project-specific cleanup commands
in each experiment's README. The runners do not require an AI client or model
credentials. Supported hosts need Linux, Docker access, and the prerequisites
listed by the selected experiment.
