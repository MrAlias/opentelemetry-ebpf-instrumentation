# OpenTelemetry getsockopt TLS 1.3 wrong-live-socket acceptance

Result: **pass**

This bounded public subset comes from a clean full `all` run. It records the
source-exact primary `getsockopt` live-descriptor control at
`b678ce1e2415906d45df3bf0728e7ed9e92c52c9`: a same-JVM, separate live
unnegotiated TCP socket is denied before the held legitimate request is
released, then the existing root duplicated-descriptor probe is denied, the
held request keeps its exact parent, and normal recovery succeeds.

It promotes only that primary wrong-live-socket case to a retained acceptance
result. It does not establish a general socket-identity claim, a Unix fallback
case, the VM-gated JVM fixture, sustained benchmark results, or unexecuted
compatibility-matrix cells.

## Run identity

| Field | Value |
| --- | --- |
| Public evidence ID | otel-getsockopt-tls13-b678ce1e |
| Source revision | b678ce1e2415906d45df3bf0728e7ed9e92c52c9 |
| Source state | clean |
| Source-tree manifest SHA-256 | a35b3419e7e969b98511913377e97838bd5d022301664df69ea42d1f899847ed |
| Invocation | ./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3 --scenario all |
| Acceptance mode | full all suite |
| Runner results | 44 passed, 2 expected unsupported, 0 failed |
| Agent | official OpenTelemetry Java agent 2.28.1 |
| JVM | Temurin 21.0.10+7 |
| Transport | forced getsockopt |
| TLS | 1.3 |
| Architecture / cgroup | x86_64 / unified v2 |

[run-status.json](run-status.json), [environment.txt](environment.txt),
[source-state.txt](source-state.txt), and
[runtime-metadata.json](runtime-metadata.json) record the public run and source
identity. [source-tree.manifest](source-tree.manifest) is regenerated from the
recorded Git revision by the retained-evidence verifier.

## Ordered primary controls

The dedicated Compose overlay gives only the Java container `SYS_PTRACE`. It
keeps a private PID namespace, Docker's default seccomp profile, and
`privileged: false`.

| Claim | Retained proof |
| --- | --- |
| A separate same-JVM live socket is denied | The [sanitized summary](security-primary-live-fd.json) records a separate, established, unnegotiated loopback TCP socket that calls the raw retrieval before the barrier becomes ready. |
| A root wrong-process duplicate is denied | The [probe record](security-primary-live-fd-probe.json) records an opened `pidfd_getfd` duplicate; the summary records the subsequent pre-release denial window. |
| Neither control consumes the victim context | The pre-release metric delta contains zero valid takes and exactly two unauthorized takes. |
| The victim preserves its exact parent | [Held-victim trace graph](scenario-security-primary-live-fd-victim.json). |
| The stack recovers normally | [Recovery status](scenario-basic-security-primary-live-fd-recovery-status.json) and [trace graph](scenario-basic-security-primary-live-fd-recovery.json). |
| Barrier ordering is retained | [Armed](primary-live-fd-security-armed.txt), [released](primary-live-fd-security-released.txt), and [consumed](primary-live-fd-security-consumed.txt) records. |

The two `take_unauthorized` events are an aggregate reason-coded metric, not
per-attacker labels. The runner's ordering is the attribution boundary: the
same-JVM decoy occurs before `ready`, the duplicated-FD probe occurs after
`ready` and before `release`, and the metric window contains exactly those two
denials. The raw `native-unsupported` probe results are not enforcement proof;
the acceptance decision requires the metric window, held-victim graph, and
recovery together.

## Boundaries

This run does not prove:

- a second negotiated socket or every possible primary socket mismatch;
- a Unix wrong-socket descriptor case;
- JVM-to-JNI-to-cgroup-sockopt coverage in the VM-gated fixture;
- sustained benchmark or external compatibility matrix rows.

See [SECURITY.md](../../SECURITY.md),
[COMPATIBILITY.md](../../COMPATIBILITY.md), and
[FINAL-RESULT.md](../../FINAL-RESULT.md) for the current remaining gaps.

## Integrity

From the repository root:

    ( cd examples/apache-java-https/evidence/otel-getsockopt-tls13-b678ce1e && sha256sum -c SHA256SUMS )

    ./examples/apache-java-https/scripts/verify-retained-evidence.sh \
      examples/apache-java-https/evidence/otel-getsockopt-tls13-b678ce1e

    jq -e '
      .status == "passed" and
      .controls.wrong_live_socket.status == "metrics_verified" and
      .controls.duplicated_fd_wrong_process.status == "metrics_verified" and
      .metric_windows.probe_delta.take_valid == 0 and
      .metric_windows.probe_delta.take_unauthorized == 2 and
      .metric_windows.after_from_before_delta.take_valid == 1 and
      .legitimate_victim.status == "passed" and
      .post_abuse_recovery.status == "passed"
    ' examples/apache-java-https/evidence/otel-getsockopt-tls13-b678ce1e/security-primary-live-fd.json

[SANITIZATION.md](SANITIZATION.md) lists transformations and omitted raw
records. The checksum manifest authenticates this public subset, not the
ignored runtime bundle.
