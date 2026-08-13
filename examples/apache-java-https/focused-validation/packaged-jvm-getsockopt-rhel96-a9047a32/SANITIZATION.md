# Sanitization record

## Source

The source is GitHub Actions artifact
`java-remote-parent-rhel9.6-kernel-sockopt-31741417915` from successful run
[31741417915](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31741417915)
at clean revision `a9047a32788e545b0c24a17e620708b488120a74`. The downloaded
archive is not checked in. Its SHA-256
(`f8dc199c64a518dd0e6c957cc9f78259aa14e0ae420b0d6d3061144ba6fff367`)
and byte size (35,934,009) are retained in `run-identity.json`.

The packaged `benchmark.json` is also not checked in. Its SHA-256
(`8cc7c5b1815878d7ebb51b42eabdb48a08f27ff78f185d084d8d5dc281e82e17`)
and byte size (8,761) cross-link the sanitized projection to the exact raw
benchmark.

## Retained

- all 256 miss and 256 hit latency samples, counts, sums, minima, maxima, and
  nearest-rank p50, p95, and p99 values;
- exact status counts, errors, warmup and measurement counts, total call count,
  topology snapshot counts, and p99 gates;
- clean source identity and SHA-256/size identities for the test binary,
  packaged agent, sockopt BPF, and sockops BPF;
- the Java executable SHA-256 from the VM identity record;
- the digest-pinned RHEL 9.6 LVH tag and digest, kernel release and image/config
  hashes, architecture, Alpine userspace, CPU model, CPU count, memory, cgroup
  mode, hierarchy depth, and JVM package/version/privilege state;
- the normalized child setup, timed-call boundary, miss-control semantics, and
  one-thread execution;
- revisionless topology mode, exact operator premise and limitation, hierarchy
  roles, program counts, and intended program names, types, and tags;
- pre-call and post-call topology observation counts and errors; and
- CI decoder/cross-link passes, the independent decoder pass, and the
  source-ordered cleanup publication gate.

## Removed or normalized

- the raw archive, benchmark JSON, logs, JARs, test binary, kernel
  configuration/build files, and complete identity/environment records;
- the artifact creation timestamp and other absolute timestamps;
- every raw absolute filesystem path, including Java, source, cgroup, agent,
  BPF, and test-binary paths;
- device and inode numbers;
- numeric BPF program IDs;
- numeric runtime UID/GID values, socket descriptors, cgroup identities, and
  process or namespace identifiers;
- usernames and hostnames; and
- root-harness environment values and package-manager output.

The public workflow-run URL and artifact name deliberately retain the numeric
run locator. The Java executable content hash, kernel-image metadata, stable
BPF program names/types/tags, and aggregate nanosecond durations are deliberate
identity or measurement fields, not transient operational identifiers. The
Java child environment is represented by its exact allowlisted key set and
normalized policy rather than path-valued entries.

The raw topology did not contain a post-run cleanup object. The sanitized
cleanup booleans are derived from the benchmark source's fatal pre-publication
ordering and the successful test: artifact publication occurs only after map
cleanup, BPF resource closure, and an empty direct/effective topology check.
This derivation is labeled in `run-identity.json`.

## Claim boundary

Sanitization does not promote the run. The GitHub archive digest establishes
byte identity against GitHub metadata; it does not independently prove the
semantic claims. This is a single GitHub-hosted, two-vCPU, Alpine-userspace run
on a digest-pinned RHEL 9.6 kernel. Revisionless boundary checks plus the
operator premise cannot exclude an attach/detach entirely between snapshots.

The record is focused non-acceptance evidence that advances, but does not
close, issues #11, #20, and #37. It establishes neither full RHEL userspace
compatibility nor Apache application, concurrency, allocation, sustained-load,
resource-growth, or run-to-run variance evidence.
