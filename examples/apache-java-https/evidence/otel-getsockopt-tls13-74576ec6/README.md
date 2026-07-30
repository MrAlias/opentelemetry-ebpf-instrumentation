# OpenTelemetry getsockopt TLS 1.3 live-descriptor security acceptance

Result: **pass**

This is a bounded public subset of a clean full `all` run. It records the
current source revision's primary live-descriptor control only: a root attacker
in the Java container's PID 1 cgroup duplicated a real accepted descriptor,
and metric attribution, a held exact-parent victim, and recovery all passed.

It promotes that exact primary control to a retained acceptance result. It does
not establish a general descriptor-security claim, close issue #40, or turn
the unexecuted Unix, wrong-socket, benchmark, compatibility, JVM, kernel, or
architecture cells into passes.

## Run identity

| Field | Value |
| --- | --- |
| Public evidence ID | otel-getsockopt-tls13-74576ec6 |
| Source revision | 74576ec657056dc3f63cb90f4c95f6f362a2dd39 |
| Source state | clean |
| Source-tree manifest SHA-256 | c86009d00bba0ccacda40e5506d791eafafa14dff9249ec5f4613929f42f9012 |
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

## Live-descriptor proof

The dedicated Compose overlay gave only the Java container `SYS_PTRACE`; it
kept a private PID namespace, Docker's default seccomp profile, and
`privileged: false`. The runner verified that topology before the root attacker
was executed and verified that the attacker cgroup matched Java PID 1.

| Claim | Retained proof |
| --- | --- |
| A real accepted descriptor was duplicated | The [probe record](security-primary-live-fd-probe.json) has a `pidfd-duplicate` case with `opened` outcome; the [sanitized summary](security-primary-live-fd.json) records the bounded case outcomes. |
| The attacker did not consume a valid parent | The probe-window summary records one unauthorized negotiate and take, with zero valid takes during the probe. |
| The victim preserved its exact parent | [victim status](scenario-concurrency-security-primary-victim-status.json) and [trace graph](scenario-security-primary-live-fd-victim.json). |
| The stack recovered normally | [recovery status](scenario-basic-security-primary-live-fd-recovery-status.json) and [trace graph](scenario-basic-security-primary-live-fd-recovery.json). |
| The barrier was ordered | [armed](primary-live-fd-security-armed.txt), [released](primary-live-fd-security-released.txt), and [consumed](primary-live-fd-security-consumed.txt) records. |

The raw probe's `native-unsupported` outcomes are not enforcement proof.
The acceptance decision is the isolated unauthorized-metric window, zero valid
take delta while the descriptor was held, exact-parent victim, and recovery.

## Boundaries

This run does not prove:

- rejection of a wrong live socket identity;
- a Unix same-cgroup or sibling attacker topology, or a retained Unix stale
  state;
- JVM-to-JNI-to-cgroup-sockopt coverage in the VM-gated fixture;
- benchmark or external compatibility matrix rows.

See [SECURITY.md](../../SECURITY.md),
[COMPATIBILITY.md](../../COMPATIBILITY.md), and
[FINAL-RESULT.md](../../FINAL-RESULT.md) for the current remaining gaps.

## Integrity

From the repository root:

    ( cd examples/apache-java-https/evidence/otel-getsockopt-tls13-74576ec6 && sha256sum -c SHA256SUMS )

    ./examples/apache-java-https/scripts/verify-retained-evidence.sh \
      examples/apache-java-https/evidence/otel-getsockopt-tls13-74576ec6

    jq -e '
      .status == "passed" and
      .probe.case_outcomes.pidfd_duplicate == "opened" and
      .metric_windows.probe_delta.take_valid == 0 and
      .metric_windows.probe_delta.take_unauthorized == 1 and
      .legitimate_victim.status == "passed" and
      .post_abuse_recovery.status == "passed"
    ' examples/apache-java-https/evidence/otel-getsockopt-tls13-74576ec6/security-primary-live-fd.json

[SANITIZATION.md](SANITIZATION.md) lists the transformations and omitted raw
records. The checksum manifest authenticates this public subset, not the
ignored runtime bundle.
