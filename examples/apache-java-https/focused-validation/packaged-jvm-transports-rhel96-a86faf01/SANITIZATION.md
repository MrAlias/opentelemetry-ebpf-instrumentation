# Sanitization record

## Source

The source is GitHub Actions artifact ID `9233961250`, named
`java-remote-parent-rhel9.6-kernel-sockopt-31839215163`, from successful run
[31839215163](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31839215163)
at clean revision `a86faf0170d237df66055d22e1f316ff693d890a`. The downloaded
archive is not checked in. Its SHA-256
(`d0c39375633205f0d556727d16d810005611028ca4beecd99eda2150c49d4455`)
and byte size (36,207,445) are retained in `run-identity.json`.

The raw `benchmark.json` is also not checked in. Its SHA-256
(`794d16ab745d8b7cd0d0a413ac6b17d78fe017e16dce9e9695441de18c89ba21`),
byte size (371,859), schema version (2), and exact series order cross-link the
sanitized projection to the source benchmark.

## Retained

- all 14 ordered raw-JNI and bridge/provider-JNI series across `getsockopt`
  miss/hit/stale and Unix miss/hit/stale/timeout;
- all 28,672 latency samples, all 28,672 thread allocated-byte samples, and
  all 28,672 paired allocation-control samples;
- every sample-derived total and nearest-rank p50, p95, and p99 aggregate;
- all status counters, expected and observed Java/native/bridge/BPF/server
  call counters, cumulative status-counter boundaries, correctness results,
  and predeclared latency gates;
- the eight-worker, 16-warmup-batch, 256-measurement-batch setup and timed-call,
  staging, TTL/staleness, timeout, allocation, environment, and agent controls;
- clean source identity and SHA-256/size identities for the test binary,
  packaged agent, sockopt BPF, and sockops BPF;
- the Java executable content hash; bounded kernel, userspace, JVM, CPU,
  memory, cgroup, and Java privilege facts; and
- topology roles, stable BPF program names/types/tags, exact revision support,
  observation counts, operator premise and limitation, CI validation passes,
  and the source-ordered cleanup publication gate.

## Removed or normalized

- the raw archive and benchmark, logs, JARs, test binary, kernel files, and
  complete identity/environment records;
- the artifact creation time and all other absolute timestamps;
- every raw absolute filesystem, cgroup, Java, agent, BPF, source, and Unix
  socket path; the temporary socket root is represented as
  `<temporary-root>`, cgroups as `root`/`target` roles, and the child
  environment by its exact allowlisted key set and normalized policy;
- device and inode numbers, numeric BPF program IDs, and cgroup IDs;
- numeric runtime UID/GID values, thread/process/namespace identifiers,
  socket descriptors and cookies, usernames, and hostnames; and
- root-harness environment values and package-manager output.

The public run ID, artifact ID, artifact name, and run URL are deliberate
provenance locators. Cumulative BPF/server status-counter boundaries are
retained measurement accounting, not BPF program IDs or process identities.
Content hashes, stable BPF names/types/tags, fixed workload counts, durations,
and byte-allocation observations are deliberate identity or measurement
fields rather than transient operational identifiers.

The raw schema has no post-run cleanup object. Sanitized cleanup booleans are
derived from the benchmark source's fatal pre-publication ordering and the
successful test: publication follows exact map cleanup, BPF resource closure,
and empty direct/effective topology checks. This derivation is labeled in
`run-identity.json`.

## Claim boundary

Sanitization does not promote the run. The archive digest establishes byte
identity against GitHub metadata; it does not independently prove semantic
claims. This is one GitHub-hosted, two-vCPU, Alpine-userspace run on a
digest-pinned RHEL 9.6 kernel. Revisionless boundary checks plus the operator
premise cannot exclude an attach/detach wholly between snapshots.

The record is focused non-acceptance evidence that advances, but does not
close, issues #11, #18, #20, and #37. It supplies no application request,
throughput, process/native resource-growth, run-to-run variance, native
sanitizer, or RHEL userspace compatibility evidence. Thread allocated-byte
samples are bounded Java observations, not JFR/NMT or native-memory evidence.
