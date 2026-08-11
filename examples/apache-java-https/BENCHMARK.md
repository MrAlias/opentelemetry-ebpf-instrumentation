# Benchmark plan and result matrix

Status: **partial — the core application harness and bounded/native fixtures
are implemented, but no retained full application run completes the
native-memory and attributable map-growth acceptance evidence**

The retained benchmark evidence remains partial and does not close the open
[MrAlias/opentelemetry-ebpf-instrumentation issue #37](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/issues/37).

Correctness has priority over throughput. Any wrong parent, duplicate Java
server span, crash, unbounded resource growth, or application failure makes a
performance cell fail regardless of latency.

## Predeclared PoC gates

- zero wrong parents and zero duplicate Java server spans;
- no monotonic file-descriptor, thread, native-memory, or map growth after the
  workload and one idle recovery interval;
- privileged Go transport-harness `getsockopt` miss and hit p99 below 1 ms;
- privileged Go transport-harness Unix miss and hit p99 below 50 ms;
- Unix timeout p50 at or above its 50 ms absolute deadline and p99 at or
  below 100 ms;
- steady-state application throughput and p99 latency regression no worse than
  10% against the same official-agent baseline.

These are PoC acceptance gates, not production SLOs.

The harness mechanically evaluates the currently supported subset in
`poc-gates.json`: zero failures in the six core correctness cells; exactly five
steady-state repetitions; at most 10% median-throughput and median-p99
regression for the comparable instrumented cells against `bridge-disabled`;
and bounded process FD/thread growth from the before and idle-recovery samples.
Unavailable required process samples fail that process dimension closed, and
unavailable descriptive map samples prevent successful harness completion.

The file does not claim a complete PoC result. The exported
`java_remote_par` map series are host-global and carry no demo-project ownership
label. The harness retains their before/recovery deltas descriptively with
`ownership_attribution: false`, but the map dimension and overall gate remain
`partial`/`not_evaluated` even when every visible series is stable. The
overall status remains `partial` and its result becomes `failed` if a supported
correctness, performance, or process-growth dimension fails; it can never be
reported as a complete pass without attributable map evidence. The
bridge-disabled cell still has the minimized bridge maps (maximum one entry),
so its samples are required rather than treated as not applicable. JFR/NMT
allocation, native/direct-memory growth, primary cgroup-sockopt program CPU,
and BPF lock contention are also uncollected. A `passed` `summary.json` status
means only that the requested harness execution completed; it is neither a
passing PoC gate nor issue-acceptance evidence.

## Privileged transport microbenchmark

The final RHEL 9.6 kernel workflow runs
`TestJavaRemoteParentTransportBenchmark` as root with the
`privileged_tests` build tag and retains its owner-private JSON artifact. The
schema-v2 artifact contains six independently reported series:

| Series | Samples | Latency gate |
| --- | ---: | --- |
| `getsockopt` miss | 4096 | p99 < 1 ms |
| `getsockopt` hit | 4096 | p99 < 1 ms |
| `getsockopt` one-shot contention | 4096 | correctness only: exactly one valid take per round |
| Unix miss | 1024 | p99 < 50 ms |
| Unix hit | 1024 | p99 < 50 ms |
| Unix timeout | 1024 | p50 >= 50 ms and p99 <= 100 ms |

The timeout control uses one 50 ms absolute client connection deadline against
a deliberate Unix non-responder that accepts the request but withholds the
response. It measures a client deadline error, not a provider
`StatusTimeout` response. A result that returns early or exceeds the bounded
upper tail fails even when it has the expected timeout error.

A digest-pinned RHEL 9.6 kernel run at
`4fe50533cd1d66b6bb94f2ea34be4b03e3727849` passed all six correctness gates,
including all five latency-threshold gates and the one-shot correctness-only
gate. The sanitized
[focused preflight record](focused-validation/rhel96-kernel-sockopt-4fe50533/README.md)
retains the exact aggregate series and public artifact provenance.

This is a Go transport/provider microbenchmark. The primary series attach the
real cgroup `getsockopt` programs; the Unix miss/hit series exercise the Go Unix
client, server admission, and map-provider path, while the timeout series uses
the deliberate non-responder described above. It does not load the Java agent,
call the JNI entry point, run Java instrumentation or extraction, or measure
application request latency. Consequently these percentiles must not be
reported as Java/JNI lookup or end-to-end workload measurements.

The opt-in privileged benchmark is intentionally not run as part of local
validation. Local checks compile and test the artifact validation code; the
digest-pinned RHEL workflow supplies the required root privileges, cgroup/BPF
facilities, fixed kernel identity, and retained execution evidence. The focused
run above satisfies only the six Go transport/provider gates. Every application
comparison-matrix cell below remains `untested`.

The harness records the measured `passed` value for all six series and
atomically publishes the artifact before asserting the latency gates. The VM
runner validates and reports a structurally consistent artifact even when one
of those values is `false`, then fails the workflow. This preserves the failed
measurement for diagnosis instead of losing the evidence that caused the gate
failure. The VM path is deterministically
`transport-benchmark/benchmark.json` below the workflow output directory; the
runner refuses to reuse an existing artifact directory, so a rerun cannot leave
multiple candidates associated with one log.

## Comparison matrix

Run on one otherwise idle host with fixed CPU/memory limits, request mix,
warmup, duration, concurrency, JVM flags, and agent artifact.

| Mode | Throughput | p50 | p95 | p99 | CPU | RSS/native | FD/thread | Map occupancy/capacity | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| uninstrumented JVM, OBI stopped | — | — | — | — | — | — | — | — | untested |
| official agent and extension, bridge disabled | — | — | — | — | — | — | — | — | untested |
| direct Java HTTPS, active `getsockopt` helper, no Apache handoff | — | — | — | — | — | — | — | — | untested |
| forced `getsockopt`, hit | — | — | — | — | — | — | — | — | untested |
| forced `getsockopt`, miss | — | — | — | — | — | — | — | — | untested |
| forced `unix`, hit | — | — | — | — | — | — | — | — | untested |
| forced `unix`, miss/timeout | — | — | — | — | — | — | — | — | untested |
| valid W3C, OBI candidate discarded | — | — | — | — | — | — | — | — | untested |
| executor and servlet-async handoff | — | — | — | — | — | — | — | — | untested |
| Java 21 virtual-thread handoff | — | — | — | — | — | — | — | — | untested |
| Netty event-loop to worker handoff | — | — | — | — | — | — | — | — | untested |
| repeated servlet async redispatch | — | — | — | — | — | — | — | — | untested |
| map pressure/capacity rejection | — | — | — | — | — | — | — | — | untested |

## Procedure

The included runner provides bounded exact-parent assertions and targeted
resource evidence. Its request count is not a sustained benchmark: use the
dedicated harness for the comparable core cells.

## Core sustained benchmark harness

`scripts/benchmark.sh` runs six sequential, isolated cells:

| Cell | Runtime | Transport | Correctness assertion |
| --- | --- | --- | --- |
| `uninstrumented` | no Java agent or OBI | disabled | no marker-correlated spans |
| `bridge-disabled` | official Java agent, extension, and OBI | disabled | Java root span |
| `getsockopt-hit` | official Java agent, extension, and OBI | forced `getsockopt` | exact remote parent |
| `unix-hit` | official Java agent, extension, and OBI | forced Unix fallback | exact remote parent |
| `getsockopt-w3c` | official Java agent, extension, and OBI | forced `getsockopt` | valid W3C parent wins; staged OBI candidate is discarded |
| `getsockopt-helper-idle` | official Java agent, extension, and OBI | active forced `getsockopt`; direct Java HTTPS workload | no Apache upstream handoff in the exact window; not a state-map-miss proof |

The default `--cells core` run produces the sustained application benchmark.
`variance.json` retains each cell's five repetitions and their median and
observed range. `poc-gates.json` applies the predeclared zero-failure and 10%
regression thresholds to the supported core dimensions, while preserving the
partial resource result described above.

`--cells complete` additionally produces `lookup-paths.json` and
`native-jni/benchmark.json`. It runs one bounded correctness execution for the
getsockopt and Unix hit paths, getsockopt and Unix stale paths, Unix timeout,
and getsockopt pressure. These artifacts use
`bounded_correctness_observed_once`; they intentionally contain no application
throughput or p50/p95/p99 claim. The pressure observation retains exact-parent
and root counts, bounded capacity rejection, verified non-eviction for the
non-evicting hash map, cleanup, and two canonical recovery Prometheus samples.
Validation parses the baseline, pressured, traffic-complete, recovery samples,
canonical recovered sample, and recovery-attempt log; it requires one stable
map ID/type/capacity, the declared occupancy predicates, exactly two terminal
consecutive recovery samples, and exact log/sample reconciliation. Nonempty or
garbage files cannot satisfy that contract. It is one correctness observation,
not a pressure performance benchmark.

The native fixture executes 1,000 warmups and 10,000 measured operations for
each getsockopt and Unix hit/miss/failure series and reports native p50/p95/p99.
It builds the production C transport/provider implementation against
deterministic syscall/socket fixtures. Before building, the harness asks
`Makefile.jni` which `CC` it would use, honors an inherited `CC`, resolves and
pins the compiler's canonical executable path, and records its SHA-256,
version, flags, requested build command, and expanded Make command. Those
compiler-version, dry-run, build, and native-fixture commands run with an empty
inherited environment plus only `PATH=/usr/bin:/bin` and `LC_ALL=C`; dynamic
loader variables are absent before `env -i` starts because Bash `exec -c`
launches it with an empty environment. GNU Make control variables
and compiler/linker search-path variables from the caller therefore cannot
change the recorded or executed build. The harness verifies the four relevant
tracked source/build inputs are clean before and after the build, copies those
exact blob-verified inputs into a private, Make-safe `/tmp` staging directory,
and never passes the user-selected artifact path to Make. It retains the
before/after source identity and copied binary, then removes the staging tree.
Those
percentiles do not include the in-JVM Java-to-native transition or application
request processing and are not acceptance evidence. `lookup-paths.json`
therefore remains `partial_with_explicit_gaps`: application state-map misses
and in-JVM transition percentiles are blocked. Its embedded observations carry
explicit root-relative `source_artifact` and `link_base` fields; validation
requires each full standalone artifact and every linked provenance/result file
to resolve under the retained output root.

For every cell, the harness first asks `run.sh` to retain a fixed 16-request,
scenario-specific correctness preflight and leave only that scoped Compose
project running. The hit controls use concurrent preflight traffic; the W3C
control is serial so it can alternate exact valid-W3C and malformed-W3C cases.
It then warms the existing locked-down `benchmark` Compose client and runs
exactly five fixed-duration closed-loop repetitions. The client uses closed
connections, `/api/echo?delay_ms=150`, and a fixed seed of zero. All cells
except `getsockopt-w3c` deliberately send no W3C header. `getsockopt-w3c`
sends a valid W3C `traceparent` on every sustained request. Its preflight and post-load sentinel
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
result must report traffic from the requested duration through that duration
plus a two-second in-flight-drain tolerance. A monotonic gate closes admissions
at the measurement deadline, while admitted requests drain under their
per-request deadline so server-completed requests remain in the client's
success count. The client can wait for its configured per-request timeout, but
the harness rejects a retained sample whose drain exceeds two seconds.
Throughput uses the full admission-plus-drain wall time. The separate 30-second
command-start allowance is not measurement time. Each cell ends with its fixed
scenario-specific correctness sentinel before the harness invokes
`run.sh --cleanup-only` for that project.

The schema-v2 manifest preserves its `w3c_headers: false` baseline for existing
consumers. Its authoritative per-cell traffic record is
`workload.w3c_headers_by_cell`: only `getsockopt-w3c` is `true`; the four
other Apache comparison controls and the direct-Java helper-idle control are
`false`. `workload.by_cell` records the base URL, CA-file use, TLS verification,
and handoff contract for every cell.

### Direct-Java helper-idle control

`getsockopt-helper-idle` first keeps the normal 16-request forced-`getsockopt`
concurrency preflight, so the configured bridge still has an ordinary
Apache-to-Java hit control. Its sustained client then connects directly to the
Java backend at `https://127.0.0.1:18443`, with W3C disabled and only the
generated CA certificate mounted read-only at `/benchmark-ca.crt`; it has no
Apache upstream connection to hand off. The benchmark Compose client remains
non-root, read-only, capability-free, and `no-new-privileges`; it does not
receive the certificate private key or PKCS#12 keystore.

The exact helper-idle window is deliberately ordered as follows: a Java
diagnostics snapshot; a fresh OBI metrics seed followed by two serial
`tcp/report/valid` BPF-stats passes; the direct warmup and all repetitions; a
fresh post-workload seed followed by two more serial BPF-stats passes; then a
Java diagnostics snapshot. The marker is published last by the single periodic
stats reader, not by an individual request: the second pass after each boundary
is therefore the retained causal fence. Normal before/after/idle resource
snapshots, the preflight, and the post-load sentinel remain outside this window.

Each helper-idle repetition still retains an unsynchronized in-load resource
point sample for OBI and Java CPU/RSS/thread/FD/container comparison. Its
`snapshot.json` explicitly marks Java diagnostics `not_collected`; the sample
retains process, container, and OBI-metrics artifacts but deliberately omits
only the `/obi-diagnostics` request, because that server-instrumented request
would contaminate exact `t_missing` accounting.

For `N` successful direct-Java requests, the raw Java `t_missing` delta is
exactly `N + 1`: the final diagnostics request is itself server-instrumented and
is included in the after snapshot. The retained reconciliation records that
one-event correction and requires corrected workload `t_missing == N`. It also
requires zero deltas for TCP `candidate`, `inject`, `stage`, and `handoff`, and
for `getsockopt` `take` and `discard`; `getsockopt/negotiate/missing` is retained
only as informative context, not as a retrieval-outcome reconciliation.

This control is labeled
`direct_java_no_upstream_handoff_not_state_map_miss_proof`. It proves neither a
`java_remote_parent_state` map absence nor eviction, timeout, or a per-request
native `getsockopt` retrieval. It is therefore a direct-Java/no-Apache-handoff
comparison, not the required primary or Unix state-map miss/timeout benchmark
cell.

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

Before any Compose execution, the harness rejects `DOCKER_HOST`, resolves the
active Docker context and its Docker endpoint, and requires an absolute local
`unix:///...` endpoint whose path is an existing non-symlink Unix socket.
`docker-daemon.json` retains that context, endpoint, socket path, device, and
inode, and successful summary publication re-resolves all of them. A TCP, SSH,
missing, symlinked, changed, or otherwise non-socket endpoint is not accepted.
This proves only the selected local filesystem socket endpoint; a Unix socket
can proxy a remote daemon, so it does not prove Docker daemon process locality,
host identity, or immutable hardware/kernel settings. `host-environment.txt`
remains the descriptive host record.

Run it on a Linux host with Docker Compose v2 plus the GNU/procps/util-linux
tools it validates at startup, including `timeout`, `setsid`, `ps`, and `sleep`.

Each cell retains the runner's preflight provenance, warmup and repetition
JSON, post-load sentinel, host environment, Docker stats and inspect records,
`/proc` memory/fd/thread snapshots, OBI metrics when applicable, and requested
Java diagnostics. The helper-idle midpoint is the documented exception: it
omits Java diagnostics and records that explicit reason in `snapshot.json`.
A process sample is available only when the Compose-owned full container ID,
Docker-reported host PID, local `/proc/<pid>/stat` start time, and SHA-256 of
the bounded local `/proc/<pid>/cgroup` file remain stable around collection,
and that cgroup file contains the exact full 64-hex container ID at non-hex
token boundaries. The explicit cgroup/container binding is retained in every
available identity, snapshot, and process observation. The before and
idle-recovery process-growth gate requires that entire identity and binding to
match, preventing an unrelated process or a reused numeric PID from completing
the gate. This process evidence is separate from the Unix-socket evidence.

Every core cell, including uninstrumented, bridge-disabled, W3C, and
helper-idle, must retain one clean application source identity. Complete mode
extends the same identity to all four bounded cells and the native source
artifact. `application-source-identity.json` requires identical revision,
Git-tree identity, clean status, source-tree manifest, and tracked-patch digest
across all requested cells, retains each runner's original patch-identity
value, and derives a path-independent canonical patch identity from retained
content digests. The harness independently regenerates the exact `git-tree-v2`
mode/blob/path manifest from the recorded Git tree and requires every retained
runner manifest to match it byte-for-byte. The live checkout is rechecked for
revision/index/worktree/untracked-file drift both when this artifact is created
and before a successful summary is published.
A clean preflight runs from a sealed source snapshot that is removed when the
runner exits with its scoped stack still active. Before starting any sustained
client, the harness therefore reads only the public CA certificate from the
identity-verified live Apache proxy container, caps it at 16 KiB, requires one
canonical PEM certificate with critical `CA:TRUE` constraints, a current
validity window, and a valid self-signature under an isolated trust store, and
matches its SHA-256 certificate fingerprint to the preflight's retained
`certificates.json`. The read-only public certificate resides in the private
per-cell artifact directory and is the only file mounted into the
least-privileged benchmark client; no private key or PKCS#12 keystore is copied.
A snapshot labelled `unsynchronized_midpoint` is a point sample while the load
command is still running; it is not proof that traffic was live throughout the
sample. The manifest includes a shell-escaped invocation for reproduction. On a
successful full harness run, `variance.json` records every requested completed
sustained-client repetition separately for each core cell; it preserves the
ordinal source paths rather than combining cells, warmups, sentinels, midpoint
samples, or individual requests. `summary.json` links that artifact only when
it is available.

For every retained per-repetition value, `variance.json` reports the observed
minimum, numeric median, and maximum. With an odd sample count, the median is
the middle sorted value; with an even count, it is the arithmetic mean of the
two middle values. The observed minimum--maximum range is a spread, not a
variance estimator or confidence interval. In particular, a latency p99 median
is the median of repetition p99 values, not a pooled all-request p99. Missing,
malformed, failed, symlinked, or unexpected numeric repetition artifacts fail the
harness instead of being dropped or converted to zero.

`variance.json` is the application performance benchmark and is descriptive by
itself; it does not establish a production SLO. `poc-gates.json` applies the
predeclared threshold to its fixed-five-repetition medians, but its overall
result remains partial because the map-growth dimension is not attributable.
`summary.json` links both artifacts without turning unavailable measurements
into zeroes or treating successful harness completion as issue acceptance.

The optional complete mode adds native transport/provider lookup percentiles
and bounded pressure capacity/cleanup evidence as described above. It does not
collect in-JVM JNI-transition percentiles, JFR/NMT
allocation/native/direct-memory summaries, primary cgroup-sockopt program CPU,
or BPF lock contention. Its capacity-rejection observation is not a general
BPF map-insertion-failure counter, and its non-evicting-map check is not an
eviction-rate benchmark. Do not use the repository-wide
`scripts/bpf-metrics-sampler.sh` for this harness: it changes a host-global BPF
statistics sysctl and is not scoped to the demo project.

The six sustained core cells and the optional observed-once path controls are
not the complete matrix for the open fork issue linked above. End-to-end
application state-map miss performance,
in-JVM Java-to-native transition percentiles, sustained stale/timeout/pressure
performance, attributable map growth, and native-memory evidence still require
separate measurement before declaring the benchmark issue complete. The
privileged Go transport artifact and the native deterministic fixture are
complementary evidence; neither fills those application-workload cells. The
checked-in
[focused artifact](focused-validation/rhel96-kernel-sockopt-4fe50533/README.md)
therefore does not turn the W3C row or any other application comparison-matrix
row into a passed result.

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
live non-evicting handoff-claim `HASH` map and records the exact map and JVM
cleanup identity before mutation. It then arms cleanup, inserts tagged `OPEN`
admission tickets until the first bounded capacity rejection, and scans every
successful synthetic key to prove that none was evicted. Values use fresh
monotonic observations tied to the one unambiguous live JVM incarnation. During 128
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

The harness requires exactly five measurement repetitions and records the
per-cell median and observed spread in `variance.json`; report it with the
fixed-host artifact rather than pooling transport configurations or lookup
paths. Do not combine primary and fallback lookup latency into one percentile.
Stop the scoped stack afterward:

```bash
./examples/apache-java-https/run.sh --cleanup-only
```
