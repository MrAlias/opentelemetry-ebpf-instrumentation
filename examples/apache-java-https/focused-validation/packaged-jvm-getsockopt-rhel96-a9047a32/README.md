# RHEL 9.6 packaged-JVM getsockopt focused validation

Status: **focused validation passed; non-acceptance evidence**

This record retains a sanitized, recomputable result from the packaged-agent
Java/JNI/cgroup-`getsockopt` microbenchmark at clean source revision
`a9047a32788e545b0c24a17e620708b488120a74`. The benchmark ran in GitHub
Actions on the digest-pinned RHEL 9.6 LVH kernel with Alpine 3.23.4 VM
userspace. It used a real accepted Java socket and crossed the packaged agent,
Java native call, JNI, kernel `getsockopt`, and the intended cgroup BPF
programs.

## Result

| Outcome | Samples | Warmups | Total | Min | p50 | p95 | p99 | Max | Status count | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| state-only miss | 256 | 16 | 1,924,099 ns | 6,312 ns | 7,003 ns | 8,024 ns | 29,034 ns | 46,998 ns | 256 missing | p99 < 1 ms: pass |
| hit | 256 | 16 | 5,147,901 ns | 16,130 ns | 18,164 ns | 36,608 ns | 61,183 ns | 72,315 ns | 256 valid | p99 < 1 ms: pass |

Both series completed with zero errors. The single-threaded fixture made 544
calls including warmups. It retained 544 successful pre-call and 544
successful post-call topology snapshots, with zero query errors and zero
topology mismatches. [benchmark-summary.json](benchmark-summary.json) contains
all 512 measured samples so the counts, sums, minima, maxima, and nearest-rank
percentiles can be independently recomputed.

## Provenance and identity

The exact successful
[GitHub Actions run](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31741417915)
used workflow `.github/workflows/java_remote_parent_rhel.yml`, attempt 1, and
source revision `a9047a32788e545b0c24a17e620708b488120a74`. The downloaded raw
archive was 35,934,009 bytes with SHA-256
`f8dc199c64a518dd0e6c957cc9f78259aa14e0ae420b0d6d3061144ba6fff367`,
exactly matching GitHub metadata. The packaged benchmark JSON was 8,761 bytes
with SHA-256
`8cc7c5b1815878d7ebb51b42eabdb48a08f27ff78f185d084d8d5dc281e82e17`.

The run used RHEL 9.6 LVH tag `rhel9.6-20260720.023802`, pinned image digest
`sha256:ae4ce64faec9c87b702a89ca48bba9e8798861d199942bd8ebddf1937ee098ad`,
Linux 5.14.0 on `x86_64`, and Alpine OpenJDK 21.0.12. The retained summary
binds the exact packaged agent, test binary, Java executable, sockopt BPF, and
sockops BPF identities. The Java child ran with all-zero capabilities,
`no_new_privs`, and no BPF descriptors.

The repository's compiled strict decoder and CI cross-link validator passed
during the run. A read-only independent rerun of
`TestValidatePackagedJVMBenchmarkArtifactFile` also passed against the exact
JSON without loading BPF; the copied validator and input hashes were unchanged.

## Topology and cleanup boundary

The two-level cgroup-v2 hierarchy exposed no direct-query revisions. The
fixture therefore used `boundary_identity_only` under the exact operator
premise `operator_controlled_no_concurrent_cgroup_bpf_mutation`. Every
observed boundary contained only the intended getsockopt, setsockopt, and
sockops program identities. This cannot exclude an attach and detach completed
wholly between two queries.

Cleanup was a fatal publication gate in the successful benchmark test. Before
writing the raw JSON, the fixture required its generation state and authorized
process keys absent, closed all benchmark BPF links, programs, and maps, and
required every direct and effective cgroup chain empty. The cleanup result in
the sanitized files is derived from that source-controlled ordering plus the
successful test and published artifact; it was not a field in the raw JSON.

## Scope

This is focused, non-acceptance evidence. It supplies a retained packaged-JVM
cell on a digest-pinned RHEL 9.6 kernel and advances issues #11, #20, and #37;
it closes none of them. The VM userspace was Alpine, so this is not RHEL
userspace compatibility evidence.

The timed region excludes map staging, acknowledgement, and harness
coordination. This run does not measure an application request,
instrumentation, provider selection, record decoding, Unix fallback,
throughput, sustained load, allocations, native or process resource growth,
concurrency, CPU isolation, or run-to-run variance. Its exploratory p99 gate
is a PoC gate, not a production SLO, and one successful two-vCPU CI execution
does not establish distributional stability.

## Verify

From this directory or any unrelated working directory:

```bash
./verify.sh
```

The verifier fails closed on an unexpected file, symlink, malformed manifest,
noncanonical or multi-document JSON, duplicate or unknown JSON key, frozen
identity mismatch, inconsistent sample aggregate, claim-bearing value drift,
broken cross-link, or forbidden operational identifier. The repository commit
that contains this bundle is the trust anchor for `verify.sh` and
`SHA256SUMS`; self-checks alone do not authenticate an adversarially replaced
bundle.
