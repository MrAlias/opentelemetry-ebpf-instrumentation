# Sanitization record

## Source

The source was the owner-private
`packaged-jvm-getsockopt.json` produced by the packaged-JVM benchmark at clean
revision `75aa1a06afad7777cfc67b0632ae8f3402f40264`. The raw artifact is not
checked in. Its SHA-256 and byte size are retained in `run-identity.json` and
cross-linked from `benchmark-summary.json`.

## Retained

- all 256 miss and 256 hit latency samples and their aggregates;
- the exact status counts, errors, warmup and measurement counts, total call
  count, topology snapshot counts, and p99 gates;
- clean source identity and content hashes/sizes for the test binary, packaged
  agent, sockopt BPF, and sockops BPF;
- JVM distribution/version, kernel release, architecture, CPU model, logical
  CPU count, total memory, cgroup mode, and hierarchy depth;
- the normalized child setup, timed-call boundary, miss-control semantics, and
  one-thread execution;
- topology stability mode, query mode, hierarchy-level revision support,
  revisions, program counts, and intended attach names, types, and tags; and
- the compiled decoder pass plus post-run empty-chain and intended-program-ID
  absence results.

## Removed or normalized

- the artifact creation timestamp;
- every raw absolute filesystem path, including the Java executable and cgroup
  hierarchy paths;
- device and inode numbers;
- numeric BPF program IDs;
- session/user numeric cgroup components;
- numeric runtime UID/GID values; and
- usernames and hostnames.

The hierarchy is represented by zero-based level, role, depth, revision, and
program count. Program names, types, and tags remain because they bind the
measured topology to the intended loaded programs without disclosing transient
kernel IDs. The Java child environment is represented by its exact allowlisted
key set and normalized policy rather than path-valued entries.

## Claim boundary

Sanitization does not promote the run. This is local upstream-host focused
non-acceptance evidence with no public CI locator. It advances, but does not
close, issues #11, #20, and #37.
