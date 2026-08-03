# OpenTelemetry getsockopt TLS 1.3 acceptance

Result: **pass**

This bounded public subset comes from a clean full `all` run at
`e8db066ac36748f17d8debd9098e9d1ddba67067`. It supersedes older primary
OpenTelemetry/TLS 1.3 bundles for current-source claims and proves only the
exact matrix cell and controls recorded here. It does not turn unexecuted
transports, TLS versions, agents, kernels, cgroup topologies, architectures,
JVMs, or benchmarks into passing cells.

## Run identity

| Field | Value |
| --- | --- |
| Public evidence ID | `otel-getsockopt-tls13-e8db066a` |
| Source revision | `e8db066ac36748f17d8debd9098e9d1ddba67067` |
| Source state | clean |
| Source-tree manifest SHA-256 | `b79e7b00a4ca7b3a10a6e913880942c919d59975a04d416661dcfe886e5c991f` |
| Invocation | `./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3` |
| Acceptance mode | fresh-build full `all` suite |
| Runner results | 44 passed, 2 expected unsupported, 0 failed |
| Agent | official OpenTelemetry Java agent 2.28.1 |
| Agent SHA-256 | `faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589` |
| JVM | Eclipse Temurin 21.0.10+7 |
| Transport | forced `getsockopt` |
| TLS / backend HTTP | TLS 1.3 / HTTP/1.1 |
| Apache / OpenSSL | Apache 2.4.68 / OpenSSL 3.5.7 |
| Architecture / cgroup | x86_64 / unified v2 |
| Kernel | Linux 7.0.0-1009-aws; distribution not independently recorded |

[run-status.json](run-status.json), [environment.txt](environment.txt),
[source-state.txt](source-state.txt), [runtime-metadata.json](runtime-metadata.json),
[official-javaagent.json](official-javaagent.json), and
[bridge-artifacts.json](bridge-artifacts.json) retain the bounded run and
source identity. The retained-evidence verifier regenerates
[source-tree.manifest](source-tree.manifest) from the recorded Git revision.

The two unsupported statuses are the Unix-only stale-state and responder-fault
suites. Their exclusion is expected for a forced primary run and is not
reported as a pass.

## Transport selection

[java-selected-transport-configuration.txt](java-selected-transport-configuration.txt)
is the V2 Java configuration snapshot:

    version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0

It proves that the forced primary configuration selected `getsockopt` after
one native attempt. OBI availability metrics are lifecycle/readiness evidence,
not per-request transport-selection evidence; the scenario graphs provide the
independent request-level proof.

## Retained proof

| Claim | Primary artifacts |
| --- | --- |
| Verified Apache-to-Jetty HTTPS, HTTP/1.1, TLS 1.3 | [Apache/OpenSSL identity](apache-openssl-runtime.txt), [certificate metadata](certificates.json), and [basic exact-parent graph](scenario-basic.json) |
| Apache-to-inbound-Netty bounded receive-to-extraction fixture | [Netty-server graph](scenario-netty-server.json) and [status](scenario-netty-server-status.json) |
| Unmodified official agent, separate extension, and dynamically attached helper | [agent identity](official-javaagent.json), [runtime metadata](runtime-metadata.json), [bridge checksums](bridge-artifacts.json), and [helper recovery](scenario-basic-helper-attach-recovery.json) |
| Exact remote parent, W3C precedence, matching context, and sampled/unsampled flags | [basic](scenario-basic.json), [conflicting and invalid W3C](scenario-w3c.json), [matching W3C](scenario-w3c-match.json), and [flag outcomes](scenario-obi-flags.json) |
| Keepalive, pipelining, parallelism, churn, descriptor/port reuse, slow body, decrypted-read boundary shapes under TLS, and retry | [keepalive](scenario-keepalive.json), [pipelining](scenario-pipelining.json), [concurrency](scenario-concurrency.json), [churn](scenario-connection-churn.json), [reuse](scenario-fd-port-reuse.json), [slow body](scenario-slow-body.json), [decrypted-read boundary fixture](scenario-tls-boundary.json), and [retry](scenario-timeout-retry.json) |
| Executor, virtual-thread, Netty-worker, redispatch, and inbound-Netty handoff surfaces | [executor](scenario-handoff.json), [virtual thread](scenario-virtual-thread.json), [Netty worker](scenario-netty.json), [redispatch](scenario-dispatch.json), and [inbound Netty](scenario-netty-server.json) |
| Live map pressure, exact-parent accounting, cleanup, and recovery | [pressure status](scenario-pressure-status.json), [pressure traces](scenario-pressure.json), and [sanitized pressure summary](map-pressure-summary.json) |
| Bounded startup absence followed by late attach, restart during traffic, helper failure, and recovery | [absence](scenario-fail-open-obi-absent.json), [restart traffic](scenario-restart-fault.json), [restart events](restart-control/events.txt), [late-attach recovery](scenario-restart-late-attach-recovery.json), [helper failure](scenario-helper-attach-failure-helper-unavailable.json), and [helper recovery](scenario-basic-helper-attach-recovery.json) |
| Bridge/extension disabled and uninstrumented controls | [bridge disabled](scenario-disabled.json), [extension absent](scenario-w3c-only-extension-absent.json), [extension disabled](scenario-w3c-only-extension-disabled.json), [instrumented response](instrumented-control-response.normalized.json), and [uninstrumented](scenario-uninstrumented.json) control |
| First-export suppression detection and post-detection duplicate avoidance | [bounded delayed-export summary](delayed-otlp-suppression.json), [post-detection graph](scenario-basic-delayed-otlp-suppression.json), and [status](scenario-basic-delayed-otlp-suppression-status.json) |
| Same-cgroup, sibling, wrong-process duplicated-descriptor, and same-JVM wrong-live-socket rejection with exact-parent victims and recovery | [probe summary](security-primary-probes.json), [ordered live-descriptor summary](security-primary-live-fd.json), [held victim](scenario-security-primary-live-fd-victim.json), [concurrent victim](scenario-concurrency-security-primary-victim.json), and [recovery](scenario-basic-security-primary-live-fd-recovery.json) |
| Primary stale-state fail-open with valid W3C precedence and normal recovery | [stale graph and terminal diagnostics](scenario-primary-w3c-stale.json), [status](scenario-primary-w3c-stale-status.json), and [recovery](scenario-basic-primary-w3c-stale-recovery.json) |
| Primary returned-response version, declared-size, zero-trace-ID, and zero-span-ID faults fail open to valid W3C and recover | [version mismatch](scenario-primary-w3c-fault-version-mismatch.json), [bad size](scenario-primary-w3c-fault-bad-size.json), [zero trace ID](scenario-primary-w3c-fault-zero-trace-id.json), [zero span ID](scenario-primary-w3c-fault-zero-span-id.json), their one-shot arm/consumption records, and [recovery](scenario-basic-primary-w3c-fault-recovery.json) |
| Java SDK duplicate suppression | [allowlisted suppression metric](duplicate-suppression.json) and the scenario status records |

The primary fault graphs retain their terminal fixed-schema Java diagnostics.
They show one version-mismatch result, three malformed results, and the exact
valid W3C parent for every injected fault. Each one-shot control was armed and
consumed before the normal-stack recovery graph passed.

The delayed-export summary retains only relative timing and counts: the fresh
receiver is empty before the prime request and before the predeclared 60-second
export boundary, one unscoped startup-window OBI Java server span arrives
before that boundary, the official scoped SDK span arrives after it, the
suppression signal appears, and the subsequent normal scenario contains one
scoped Java server span with the exact Apache parent and no OBI Java duplicate.

The two `take_unauthorized` events in the live-descriptor control are an
aggregate reason-coded metric, not per-attacker labels. The runner ordering is
the attribution boundary: the same-JVM decoy occurs before `ready`, the
duplicated-FD probe occurs after `ready` and before `release`, and the metric
window contains exactly those two denials. The held victim then preserves its
exact Apache parent and the normal stack recovers.

The inbound-Netty result is a bounded receive-to-extraction fixture. It does
not establish support for arbitrary Netty applications or frameworks.

[bpftool-feature-probe.txt](bpftool-feature-probe.txt) records that an
unprivileged host-side full feature probe was unavailable. The privileged OBI
container nevertheless loaded the programs and completed the forced-primary
assertions. This artifact does not establish compatibility with another
kernel.

## Integrity checks

From the repository root:

    ( cd examples/apache-java-https/evidence/otel-getsockopt-tls13-e8db066a && sha256sum -c SHA256SUMS )

    ./examples/apache-java-https/scripts/verify-retained-evidence.sh \
      examples/apache-java-https/evidence/otel-getsockopt-tls13-e8db066a

    test "$(sha256sum examples/apache-java-https/evidence/otel-getsockopt-tls13-e8db066a/source-tree.manifest | cut -d' ' -f1)" = \
      b79e7b00a4ca7b3a10a6e913880942c919d59975a04d416661dcfe886e5c991f

    jq -e -s '
      length == 46 and
      (map(select(.status == "passed")) | length == 44) and
      (map(select(.status == "unsupported")) | length == 2) and
      (map(select(.status != "passed" and .status != "unsupported")) | length == 0)
    ' examples/apache-java-https/evidence/otel-getsockopt-tls13-e8db066a/scenario-*-status.json

    jq -e '
      .status == "passed" and
      .metric_windows.probe_delta.take_valid == 0 and
      .metric_windows.probe_delta.take_unauthorized == 2 and
      .metric_windows.after_from_before_delta.take_valid == 1 and
      .legitimate_victim.status == "passed" and
      .post_abuse_recovery.status == "passed"
    ' examples/apache-java-https/evidence/otel-getsockopt-tls13-e8db066a/security-primary-live-fd.json

    jq -e '
      .status == "passed" and
      .map.max_entries == 10000 and
      .fill.synthetic_entries_requested == 10001 and
      .traffic.requests == 128 and
      .traffic.exact_parent_hits == 128 and
      .traffic.wrong_parents == 0 and
      .traffic.unresolved_parents == 0 and
      .cleanup.verified == true and
      .recovery.verified == true
    ' examples/apache-java-https/evidence/otel-getsockopt-tls13-e8db066a/map-pressure-summary.json

    jq -e '
      .status == "passed" and
      .schedule_delay_milliseconds == 60000 and
      .receiver_before_request.received_spans == 0 and
      .receiver_before_export_boundary.received_spans == 0 and
      .receiver_ready.span_inventory.unscoped_obi_java_server_spans == 1 and
      .receiver_ready.span_inventory.official_sdk_jetty_server_spans == 1 and
      .post_detection.official_sdk_jetty_server_spans == 1 and
      .post_detection.unscoped_obi_java_server_spans == 0 and
      .post_detection.exact_remote_parent == true
    ' examples/apache-java-https/evidence/otel-getsockopt-tls13-e8db066a/delayed-otlp-suppression.json

[SANITIZATION.md](SANITIZATION.md) enumerates transformations and omitted raw
records. The checksum manifest authenticates this public subset, not the
ignored operational bundle.

## Unproven by this run

- forced Unix fallback and TLS 1.2;
- the Splunk Java agent and `auto` selection;
- permanent process-lifetime OBI absence, an explicit stale-generation
  mismatch, and genuine TID/PID reuse;
- an all-or-nothing-disable guard for missing protocol coverage, dedicated
  stock-agent repeated extraction and nested/duplicate server instrumentation,
  actual TLS-record split/coalescing, a runtime parent-chain depth/cycle-limit
  control, runtime diagnostic/log side-channel evidence, and primary
  wrong-current-TID/logical-execution rejection;
- RHEL kernels, the declared representative upstream kernels, hybrid or
  delegated cgroups, host-process deployment, arm64, and JVM 8/11/17;
- the VM-gated JVM-to-JNI-to-cgroup-sockopt fixture;
- transport microbenchmarks, sustained overhead gates, and fixed-host resource
  recovery.

Those cells remain untested until their own clean, full, retained evidence
exists.
