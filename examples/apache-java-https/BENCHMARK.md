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

The included runner provides a bounded, repeatable PoC comparison with exact
parent assertions and before/after resource evidence. Use the same request
count, repetitions, and seed for every mode:

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
The monitor retains an independent terminal sample and stops when the selected
transport's exact expected bridge-take total proves that request traffic, rather
than later trace polling, is complete. It is reaped before removing only the
deterministic keys reconstructed from the captured PID, namespace, and
non-secret per-run token base, verifies every synthetic key is absent, then
retains two consecutive at-or-below-baseline samples within a bounded TTL-aware
recovery deadline. Canonical cleanup evidence is promoted only after that
recovery gate passes. The incarnation capability is never written to evidence.
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

The repository's `scripts/bpf-metrics-sampler.sh` and
`scripts/bpf-metrics-summary.sh` can capture map/program resource evidence.
Retain raw summaries and the exact command with the result artifact.

Run at least five measurement repetitions and report median plus spread. Do not
combine primary and fallback lookup latency into one percentile. Stop the
scoped stack afterward:

```bash
./examples/apache-java-https/run.sh --cleanup-only
```
