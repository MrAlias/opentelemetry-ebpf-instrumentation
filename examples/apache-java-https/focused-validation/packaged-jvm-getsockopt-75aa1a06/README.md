# Packaged-JVM getsockopt focused validation

Status: **focused validation pass; non-acceptance evidence**

This record retains a sanitized, recomputable result from the packaged-agent
Java/JNI/cgroup-`getsockopt` microbenchmark at source revision
`75aa1a06afad7777cfc67b0632ae8f3402f40264`. The run used a real accepted Java
socket and crossed the packaged agent, Java native call, JNI, kernel
`getsockopt`, and the intended cgroup BPF programs.

## Result

| Outcome | Measured samples | Warmups | p50 | p95 | p99 | Min | Max | Status count | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| state-only miss | 256 | 16 | 7,379 ns | 8,387 ns | 19,997 ns | 4,092 ns | 27,450 ns | 256 missing | p99 < 1 ms: pass |
| hit | 256 | 16 | 16,131 ns | 17,825 ns | 25,049 ns | 11,261 ns | 35,211 ns | 256 valid | p99 < 1 ms: pass |

Both series completed with zero errors. The single-threaded fixture made 544
total calls, including warmups, and retained 544 successful pre-call plus 544
successful post-call topology snapshots with zero query errors and zero
topology mismatches. `benchmark-summary.json` contains all 512 measured samples
so the count, sum, min, max, and nearest-rank percentiles can be independently
recomputed.

The cgroup-v2 hierarchy had depth four. All direct queries supported revisions,
so the run used `revision_and_identity` stability. The retained summary removes
operational paths and numeric program IDs but preserves every hierarchy level's
direct revision and program count, plus the intended program names, types, and
tags. Post-run checks found the intended program IDs absent and all effective
chains empty.

## Provenance and validation

The owner-private raw artifact is not retained in the repository. Its identity
is preserved as SHA-256
`ad9f0cd2b2d33dc0402821eb87b3de9e0c23750a423cba262246964841e9b7a5`
and size 9,837 bytes. The repository's compiled
`TestValidatePackagedJVMBenchmarkArtifactFile` decoder passed against that exact
artifact without loading BPF. `run-identity.json` binds those facts to the clean
source revision and the sanitized summary.

This execution was on a local upstream host and has no public CI locator. It is
a focused result, not an Apache application acceptance bundle or a RHEL 9
matrix cell.

## Scope

This record advances the Java/JNI latency evidence requested by
issues #11, #20, and #37. It closes none of them. It does not measure provider selection,
record decoding, Unix fallback, application instrumentation or request latency,
throughput, allocations, native/process resource growth, concurrency, or
run-to-run variance.

## Verify

From this directory:

```bash
./verify.sh
```

The verifier also resolves its own directory, so it can be invoked from an
unrelated working directory. It fails closed on an unexpected file, symlink,
manifest entry, noncanonical or multi-document JSON, duplicate JSON key,
claim-bearing value mismatch, inconsistent aggregate, or forbidden operational
identifier.
