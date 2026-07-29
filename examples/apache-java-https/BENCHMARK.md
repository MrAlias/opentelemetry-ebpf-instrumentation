# Benchmark plan and result matrix

Status: **untested**

Correctness has priority over throughput. Any wrong parent, duplicate Java
server span, crash, unbounded resource growth, or application failure makes a
performance cell fail regardless of latency.

## Predeclared PoC gates

- zero wrong parents and zero duplicate Java server spans;
- no monotonic file-descriptor, thread, native-memory, or map growth after the
  workload and one idle recovery interval;
- primary helper lookup p99 below 1 ms;
- Unix fallback lookup completes below its configured 50 ms deadline;
- steady-state application throughput and p99 latency regression no worse than
  10% against the same official-agent baseline.

These are PoC acceptance gates, not production SLOs.

## Comparison matrix

Run on one otherwise idle host with fixed CPU/memory limits, request mix,
warmup, duration, concurrency, JVM flags, and agent artifact.

| Mode | Throughput | p50 | p95 | p99 | CPU | RSS/native | FD/thread | Map occupancy/eviction | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| uninstrumented JVM, OBI stopped | — | — | — | — | — | — | — | — | untested |
| official agent and extension, bridge disabled | — | — | — | — | — | — | — | — | untested |
| forced `getsockopt`, hit | — | — | — | — | — | — | — | — | untested |
| forced `getsockopt`, miss | — | — | — | — | — | — | — | — | untested |
| forced `unix`, hit | — | — | — | — | — | — | — | — | untested |
| forced `unix`, miss/timeout | — | — | — | — | — | — | — | — | untested |
| valid W3C, OBI candidate discarded | — | — | — | — | — | — | — | — | untested |
| executor and servlet-async handoff | — | — | — | — | — | — | — | — | untested |
| Java 21 virtual-thread handoff | — | — | — | — | — | — | — | — | untested |
| Netty event-loop to worker handoff | — | — | — | — | — | — | — | — | untested |
| repeated servlet async redispatch | — | — | — | — | — | — | — | — | untested |
| map pressure/eviction | — | — | — | — | — | — | — | — | untested |

## Procedure

The included runner provides bounded exact-parent assertions and targeted
resource evidence. Its request count is not a sustained benchmark: use the
dedicated harness for the comparable core cells.

## Core sustained benchmark harness

`scripts/benchmark.sh` runs five sequential, isolated cells:

| Cell | Runtime | Transport | Correctness assertion |
| --- | --- | --- | --- |
| `uninstrumented` | no Java agent or OBI | disabled | no marker-correlated spans |
| `bridge-disabled` | official Java agent, extension, and OBI | disabled | Java root span |
| `getsockopt-hit` | official Java agent, extension, and OBI | forced `getsockopt` | exact remote parent |
| `unix-hit` | official Java agent, extension, and OBI | forced Unix fallback | exact remote parent |
| `getsockopt-w3c` | official Java agent, extension, and OBI | forced `getsockopt` | valid W3C parent wins; staged OBI candidate is discarded |

For every cell, the harness first asks `run.sh` to retain a fixed 16-request,
scenario-specific correctness preflight and leave only that scoped Compose
project running. The hit controls use concurrent preflight traffic; the W3C
control is serial so it can alternate exact valid-W3C and malformed-W3C cases.
It then warms the existing locked-down `benchmark` Compose client and runs five
to ten fixed-duration closed-loop repetitions. The client uses closed
connections, `/api/echo?delay_ms=150`, and a fixed seed of zero. The first four
cells deliberately send no W3C header. `getsockopt-w3c` sends a valid W3C
`traceparent` on every sustained request. Its preflight and post-load sentinel
use the existing `w3c` control: they require the exact W3C Java parent, retain
the runner's `discard_standard` diagnostic delta, and retain a direct
before/after diagnostic delta of eight `discard_standard` events and sixteen
`t_valid` takes for the 16-request post-load control: every request stages a
valid OBI candidate, while the eight valid-W3C cases discard theirs because the
standard parent wins. Separately, the harness requires the warmup plus every
measured W3C request to produce both `discard_standard` and `t_valid` deltas
equal to the summed successful client requests; that binds the staged-candidate
precedence invariant to the sustained workload rather than only to its
controls. The same snapshots require `d_valid` to remain zero, proving no
second discard consumed a valid record. The user seed applies only to the
preflight and post-load tracecheck sentinel; the sustained W3C identifier
sequence is deterministic through the client seed of zero. The retained client
result must report traffic from the requested duration through that duration plus a
two-second cancellation-drain tolerance. The client's per-request contexts
derive from one shared measurement deadline, so this small tolerance is only
for scheduler and worker shutdown jitter; the separate 30-second command-start
allowance is not measurement time. Each cell ends with its fixed scenario-
specific correctness sentinel before the harness invokes `run.sh --cleanup-only`
for that project.

The manifest preserves its v1 `w3c_headers: false` baseline for existing
consumers. Its authoritative per-cell traffic record is
`workload.w3c_headers_by_cell`: only `getsockopt-w3c` is `true`; the four
comparison controls are `false`.

Create a private parent outside the repository for the retained artifact, then
run the harness from the repository root:

```bash
benchmark_parent="$(mktemp -d)"
./examples/apache-java-https/scripts/benchmark.sh \
  --output "$benchmark_parent/core-$(date -u +%Y%m%dT%H%M%SZ)" \
  --warmup-seconds 30 \
  --duration-seconds 60 \
  --concurrency 16 \
  --repetitions 5 \
  --seed 20260721
```

The output path must be an absolute, fresh child of an existing current-user,
owner-private directory outside the repository. This avoids both recording
benchmark data in a shared location and contaminating the runner's source-state
evidence with untracked artifacts. The harness uses an owner-private
`.runtime/benchmark.lock` and serializes all cells because they use host-network
ports. It creates only project names in the demo's reserved Compose namespace
and never calls raw `docker compose down`; teardown is delegated to the runner's
ownership-checked cleanup path.

Run it on a Linux host with Docker Compose v2 plus the GNU/procps/util-linux
tools it validates at startup, including `timeout`, `setsid`, `ps`, and `sleep`.

Each cell retains the runner's preflight provenance, warmup and repetition
JSON, post-load sentinel, host environment, Docker stats and inspect records,
`/proc` memory/fd/thread snapshots, OBI metrics when applicable, and Java
diagnostics. A snapshot labelled `unsynchronized_midpoint` is a point sample
while the load command is still running; it is not proof that traffic was live
throughout the sample. The manifest includes a shell-escaped invocation for
reproduction. On a successful full harness run, `variance.json` records every
requested completed sustained-client repetition separately for each core cell;
it preserves the ordinal source paths rather than combining cells, warmups,
sentinels, midpoint samples, or individual requests. `summary.json` links that
artifact only when it is available.

For every retained per-repetition value, `variance.json` reports the observed
minimum, numeric median, and maximum. With an odd sample count, the median is
the middle sorted value; with an even count, it is the arithmetic mean of the
two middle values. The observed minimum--maximum range is a spread, not a
variance estimator or confidence interval. In particular, a latency p99 median
is the median of repetition p99 values, not a pooled all-request p99. Missing,
malformed, failed, symlinked, or unexpected numeric repetition artifacts fail the
harness instead of being dropped or converted to zero.

Both `variance.json` and `summary.json` are descriptive, non-acceptance
evidence: they apply no threshold, make no acceptable-regression decision, and
do not establish a production SLO. `summary.json` also does not turn unavailable
measurements into zeroes.

The initial harness intentionally records these #37 dimensions as
`not_collected`: JNI lookup percentiles, JFR/NMT allocation/native/direct-memory
summaries, primary cgroup-sockopt program CPU, BPF map insertion failures, map
evictions, and BPF lock contention. Do not use the repository-wide
`scripts/bpf-metrics-sampler.sh` for this harness: it changes a host-global BPF
statistics sysctl and is not scoped to the demo project.

The five core cells are not the complete #37 matrix. Explicit primary/fallback
miss or timeout and pressure cells still require separately measured evidence
before declaring the benchmark issue complete. No checked-in benchmark artifact
exists yet, so this harness change does not turn the W3C row in the comparison
matrix into a passed result.

For focused runner iteration, use the same request count, repetitions, and
seed for every mode:

```bash
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario pressure \
  --requests 128 \
  --repeat 5 \
  --seed 20260721
```

Repeat with `--transport unix`; use the full `all` suite for the disabled,
uninstrumented, W3C/no-state, miss, timeout, async-handoff, redispatch,
virtual-thread, Netty, and restart controls. The pressure helper discovers the
live handoff-claim LRU and records the exact map and JVM cleanup identity before
mutation. It then arms cleanup, fills the reported capacity plus one, scans all
synthetic keys to prove order-independent eviction, and uses fresh monotonic
claim values tied to the one unambiguous live JVM incarnation. During 128
concurrent marked handoff requests it checks once per second that exact-map
occupancy remains above the pre-fill baseline without requiring exact capacity.
The monitor retains an independent terminal sample and stops when the exact
aggregate TCP-inject outcome total proves that outbound request publication,
rather than later trace polling, is complete. It is reaped before removing only the
deterministic keys reconstructed from the captured PID, namespace, and
non-secret per-run token base, verifies every synthetic key is absent, then
retains two consecutive at-or-below-baseline samples within a bounded TTL-aware
recovery deadline. Canonical cleanup evidence is promoted only after that
recovery gate passes. The incarnation capability is never written to evidence.
Pressure results report exact hits and explicit Java roots separately: every
nonzero parent must identify the exact Apache client, exact hits plus roots must
equal the request count, and wrong-parent and unresolved counts must be zero.
Stable bridge deltas retain upstream and retrieval failures by reason. A
transport-aware conservation check reconciles those aggregate bridge outcomes
and the Java diagnostic counts with the trace outcomes.
For a production-style sustained benchmark, keep the stack with `--keep` and
add a fixed-duration external load generator; do not compare that result
directly with the bounded runner.

Record at minimum:

- hardware, architecture, kernel, cgroup mode, Docker, JVM and agent versions;
- exact warmup, measurement duration, concurrency, connection reuse, seed and
  request rate;
- client throughput and latency histogram;
- OBI, Apache and Java container CPU and memory;
- Java JFR/NMT allocation and native-memory summaries;
- `/proc/<pid>/fd` and `/proc/<pid>/task` counts before, during, and after;
- bridge lookup p50/p95/p99 and reason-coded hit/miss/timeout counters;
- the Java-service duplicate-trace suppression sample together with successful
  exact-parent bridge assertions;
- BPF map occupancy, insert failures, evictions and lock contention.

Retain raw summaries and the exact command with the result artifact. Do not
enable host-global BPF statistics as part of a shared benchmark host without an
explicit host-level measurement plan.

The harness requires five to ten measurement repetitions and records the
per-cell median and observed spread in `variance.json`; report it with the
fixed-host artifact rather than pooling transport configurations or lookup
paths. Do not combine primary and fallback lookup latency into one percentile.
Stop the scoped stack afterward:

```bash
./examples/apache-java-https/run.sh --cleanup-only
```
