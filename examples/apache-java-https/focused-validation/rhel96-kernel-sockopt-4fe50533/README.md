# Focused RHEL 9.6 kernel socket-option preflight

Result: **focused preflight passed — not acceptance evidence**

This reviewer-facing record summarizes a bounded, digest-pinned RHEL 9.6
kernel preflight from source revision
`4fe50533cd1d66b6bb94f2ea34be4b03e3727849`. The preflight ran the selected
Java bridge ABI checks, both production BPF verifier profiles, nine privileged
kernel socket-option tests, and the six-series Go transport/provider
microbenchmark. The public
[workflow run](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31323884217)
and GitHub-reported artifact archive digest bind this summary to one exact
execution.

The workflow is intentionally narrower than the Apache-to-Java HTTPS `all`
suite. It did not run the full application acceptance matrix and therefore
does not produce acceptance evidence.

## Retained result

| Check | Result | Bounded coverage |
| --- | --- | --- |
| Source and platform | passed | Exact source revision, digest-pinned RHEL 9.6 kernel target, 5.14 kernel family, Alpine 3.23 VM userspace, x86_64, cgroup v2, vmlinux BTF, and bpftool availability |
| Java bridge ABI | 10/10 passed | Record framing, golden vectors, typed version mismatch, ID validation, request source, and sampling round trips |
| Production BPF verifier | 3/3 passed | Parent test plus `generictracer/apache-java-https` and `tpinjector/java-remote-parent` production profiles |
| Privileged socket option | 9/9 passed | Authority, authoritative data hook, JVM fault handling, direct SSL sockets, cgroup lifecycle/cleanup/rollback, and privilege rejection |
| Transport microbenchmark | 6/6 correct; 6/6 gates passed | `getsockopt` miss/hit/one-shot and Unix miss/hit/timeout series |

[run-identity.json](run-identity.json) contains the allowlisted source, kernel,
and scope facts. [preflight-results.json](preflight-results.json) records the
selected test names and bounded pass counts.

[transport-benchmark.json](transport-benchmark.json) retains the six aggregate
series from the preflight artifact. Its scope is important: the harness
measures the Go transport/provider path and explicitly excludes Java and JNI.
These values are not end-to-end JVM latency or allocation measurements.

## Not established here

- full Apache-to-Java HTTPS application acceptance;
- a broader RHEL userspace, kernel, architecture, JVM, or agent compatibility
  matrix;
- production-path JVM-to-provider-to-JNI latency or allocation behavior;
- sustained load, pressure, fallback, or exporter performance; or
- closure of any requirement that calls for clean retained `all`-suite
  evidence.

The original workflow artifact remains outside Git. Its public run locator,
artifact name, and GitHub-reported archive digest are retained for provenance;
raw logs, JARs, kernel configuration, build metadata, BPF feature output,
per-file raw checksums, operational identifiers, and paths were intentionally
omitted. [SANITIZATION.md](SANITIZATION.md) describes every retained
transformation and omission.

## Integrity

From this directory:

```bash
sha256sum -c SHA256SUMS

jq -e '
  .kind == "focused-rhel-kernel-sockopt-preflight" and
  .source_revision == "4fe50533cd1d66b6bb94f2ea34be4b03e3727849" and
  .provenance.artifact.digest == "sha256:c52d96acd4cf105abd8f2fb57a86c752378663ee965045d39b9ad52b0ad0f4c5" and
  .scope.acceptance_evidence == false
' run-identity.json

jq -e '
  .status == "passed" and
  .acceptance_evidence == false and
  .checks.abi.passed == 10 and
  .checks.production_verifier.passed == 3 and
  .checks.privileged_sockopt.passed == 9 and
  .checks.transport_benchmark.correct_series == 6 and
  .checks.transport_benchmark.latency_threshold_gates_passed == 5 and
  .checks.transport_benchmark.correctness_only_gates_passed == 1
' preflight-results.json

jq -e '
  .status == "passed" and
  .scope.excludes == ["java", "jni"] and
  (.series | length) == 6 and
  all(.series[]; .correct and .errors == 0 and .latency_gate.passed)
' transport-benchmark.json
```

The checksum manifest supports verification against a separately trusted
checkout or commit. It does not authenticate the omitted raw artifact.
