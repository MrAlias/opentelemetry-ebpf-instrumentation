# RHEL 9.6 packaged-JVM transport focused validation

Status: **focused validation passed; non-acceptance evidence**

This record retains a sanitized, recomputable projection of the schema-v2
packaged-agent Java transport benchmark at clean source revision
`a86faf0170d237df66055d22e1f316ff693d890a`. The benchmark ran in GitHub
Actions on the digest-pinned RHEL 9.6 LVH kernel with Alpine 3.23.4 VM
userspace. Eight Java workers crossed the packaged agent through either raw
JNI or the bridge/provider JNI path and exercised the production cgroup
`getsockopt` programs or authenticated Unix server.

## Result

Each row retains 2,048 latency samples, 2,048 same-thread allocated-byte
samples, and 2,048 paired allocation-control samples. `Allocation p50` is a
Java `ThreadMXBean` observation, not a native-memory measurement.

| Scope | Transport | Outcome | p50 | p95 | p99 | Allocation p50 | Gate |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| raw JNI | `getsockopt` | miss | 3,586 ns | 8,924 ns | 32,819 ns | 0 B | pass |
| raw JNI | `getsockopt` | hit | 12,899 ns | 22,574 ns | 46,108 ns | 0 B | pass |
| raw JNI | `getsockopt` | stale | 12,819 ns | 22,734 ns | 48,773 ns | 0 B | pass |
| bridge/provider JNI | `getsockopt` | miss | 4,817 ns | 23,805 ns | 40,390 ns | 120 B | pass |
| bridge/provider JNI | `getsockopt` | hit | 14,381 ns | 38,297 ns | 57,375 ns | 520 B | pass |
| bridge/provider JNI | `getsockopt` | stale | 13,820 ns | 33,260 ns | 55,112 ns | 232 B | pass |
| raw JNI | Unix | miss | 556,199 ns | 1,194,769 ns | 2,254,629 ns | 0 B | pass |
| raw JNI | Unix | hit | 1,643,479 ns | 3,502,337 ns | 5,543,878 ns | 0 B | pass |
| raw JNI | Unix | stale | 1,545,151 ns | 3,067,339 ns | 3,852,128 ns | 0 B | pass |
| bridge/provider JNI | Unix | miss | 600,905 ns | 1,405,674 ns | 2,566,564 ns | 128 B | pass |
| bridge/provider JNI | Unix | hit | 1,584,771 ns | 3,162,781 ns | 3,919,980 ns | 528 B | pass |
| bridge/provider JNI | Unix | stale | 1,516,238 ns | 3,012,657 ns | 3,705,520 ns | 184 B | pass |
| raw JNI | Unix | timeout | 50,165,372 ns | 50,248,231 ns | 50,293,077 ns | 0 B | pass |
| bridge/provider JNI | Unix | timeout | 50,169,063 ns | 50,260,759 ns | 50,310,343 ns | 184 B | pass |

All 14 series were correct and passed their predeclared gates. The six
`getsockopt` rows required p99 below 1 ms; the six non-timeout Unix rows
required p99 below 50 ms; and both Unix timeout rows required p50 at or above
50 ms and p99 at or below 100 ms.

The fixture ran 16 warmup batches and 256 retained batches at concurrency 8:
128 warmup calls, 2,048 retained calls, and 2,176 total calls per series. Each
series reported exactly 2,176 statuses of its expected kind. Across the run,
30,464 Java and native calls, 15,232 bridge calls, 13,056 primary BPF calls,
13,056 non-timeout Unix requests, and 4,352 complete timeout requests matched
their exact expected/observed accounting. The verifier recomputes every
latency and allocation aggregate, status distribution, call delta, and gate.

The revisionless two-level cgroup-v2 fixture retained 3,808 successful
pre-batch and 3,808 successful post-batch topology snapshots, with zero query
errors and zero topology mismatches. It observed the intended getsockopt,
setsockopt, and sockops program identities under the exact operator premise
`operator_controlled_no_concurrent_cgroup_bpf_mutation`. Boundary identity
checks cannot exclude an attach and detach completed wholly between queries.

## Provenance and identity

The exact successful
[GitHub Actions run](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31839215163)
used workflow `.github/workflows/java_remote_parent_rhel.yml`, attempt 1, and
source revision `a86faf0170d237df66055d22e1f316ff693d890a`. GitHub artifact
ID `9233961250` was named
`java-remote-parent-rhel9.6-kernel-sockopt-31839215163`. The downloaded archive
was 36,207,445 bytes with SHA-256
`d0c39375633205f0d556727d16d810005611028ca4beecd99eda2150c49d4455`.
The exact raw schema-v2 benchmark was 371,859 bytes with SHA-256
`794d16ab745d8b7cd0d0a413ac6b17d78fe017e16dce9e9695441de18c89ba21`.

The run used RHEL 9.6 LVH tag `rhel9.6-20260720.023802`, pinned image digest
`sha256:ae4ce64faec9c87b702a89ca48bba9e8798861d199942bd8ebddf1937ee098ad`,
Linux 5.14.0 on `x86_64`, and Alpine OpenJDK 21.0.12. The Java child had
all-zero capabilities, `no_new_privs`, and no BPF descriptors. The run's
compiled strict decoder and CI cross-link validator both passed.

Cleanup was a fatal publication gate. Before publishing the raw benchmark,
the fixture required benchmark map keys absent, closed its BPF resources, and
required the direct and effective cgroup chains empty. The cleanup fields in
this projection are explicitly derived from that source-controlled ordering
and the successful benchmark; the raw schema has no cleanup object.

## Scope

This is focused, non-acceptance evidence. It advances issues #11, #18, #20,
and #37 and closes none. The VM userspace was Alpine, so this is not RHEL
userspace compatibility evidence. Eight-worker fixture concurrency is not
sustained application concurrency.

The timed regions exclude staging, acknowledgement, and harness coordination.
The run contains no application request or throughput measurement, process
CPU, RSS/native/direct-memory, FD, thread, or map-growth measurement,
run-to-run variance, or native-sanitizer result. Per-thread allocated-byte
observations do not fill those resource gaps. A single two-vCPU CI execution
and exploratory latency gates establish neither production SLOs nor
distributional stability.

The bounded decision is **GO** for continued PoC transport evaluation and
implementation. It is **NO-GO** for production readiness or compatibility
claims until sustained application request/throughput and resource/variance
evidence plus the required cgroup/namespace matrix are retained.

## Verify

From this directory or any unrelated working directory:

```bash
./verify.sh
```

The verifier fails closed on an unexpected file or symlink, malformed
manifest, noncanonical or multi-document JSON, duplicate or unknown JSON key,
frozen identity mismatch, inconsistent latency/allocation aggregate,
status/call/gate drift, broken cross-link, or forbidden operational identifier.
The repository commit containing this bundle is the trust anchor for
`verify.sh` and `SHA256SUMS`; self-checks alone do not authenticate an
adversarially replaced bundle.
