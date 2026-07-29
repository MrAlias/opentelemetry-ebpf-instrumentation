# Final result record

Status: **partial — three OpenTelemetry transport/TLS cells and one Splunk primary cell passed**

The clean full
[getsockopt/TLS 1.3](evidence/otel-getsockopt-tls13-c9d14356/README.md),
[getsockopt/TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md), and
[Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md), and the
[Splunk getsockopt/TLS 1.3](evidence/splunk-getsockopt-tls13-47237792/README.md)
runs are retained with source revision, environment, scenario graphs,
diagnostic deltas, and checksums. The refreshed OpenTelemetry primary run also
includes the bounded inbound-Netty fixture. Each proves only its exact matrix
cell. Rows requiring a different transport/TLS/agent/environment combination
remain `untested`. A row's `pass` applies only to its linked retained evidence.

## Parent tracker definition-of-done reconciliation

This is the explicit reconciliation for
[issue #2](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/issues/2).
`fail` below means the complete parent requirement is not yet satisfied; it
does not invalidate the named passing matrix cells. The
[runbook](README.md), [compatibility matrix](COMPATIBILITY.md), and linked
evidence define the current boundary of the result.

| Parent definition-of-done item | Status | Evidence or exact gap |
| --- | --- | --- |
| 1. Apache proxies to Java over HTTPS | pass | [Apache runtime and certificate evidence](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) and the [exact-parent graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-basic.json). |
| 2. Apache is instrumented by OBI | pass | [OBI startup and Apache instrumentation evidence](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof). |
| 3. Java uses the official agent and OBI extension/helper | pass | [official agent metadata](evidence/otel-unix-tls12-bd1c9327/official-javaagent.json), [external-extension runtime metadata](evidence/otel-getsockopt-tls13-c9d14356/runtime-metadata.json), and [dynamic helper attach evidence](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof). |
| 4. Traffic and traces are collected without a vendor UI | pass | [local receiver inventory](evidence/otel-getsockopt-tls13-c9d14356/runtime-images.json) and retained scenario JSON. |
| 5. Apache client and Java server spans have one exact trace/parent relationship | pass | [basic trace graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-basic.json). |
| 6. Precedence, concurrency, keepalive, failure, and compatibility cases are exercised | fail | Retained controls pass precedence, concurrency, keepalive, and Unix fault cells. Unexecuted source controls cover a forced-primary Apache stale record with W3C precedence and recovery, plus VM-gated JVM-to-JNI-to-cgroup-sockopt stale, ABI-mismatch, and zero-ID records. Neither has a retained privileged artifact, and the JVM fixture is not an application/OpenTelemetry/W3C fault result; [#37 benchmark](BENCHMARK.md) and [#38 compatibility](COMPATIBILITY.md) rows remain untested. |
| 7. Exact build, run, certificate, host, agent, and cleanup steps are documented | pass | [reproducible runbook](README.md), including the bounded [deliberate assertion failure](README.md#deliberate-assertion-failure-control), and retained environment/certificate evidence. |

| Acceptance item | Status | Evidence or remaining requirement |
| --- | --- | --- |
| Apache 2.4 proxies to Jetty over verified HTTPS | pass | [runtime and certificate evidence](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) |
| Backend protocol is HTTP/1.1 | pass | [basic response and trace graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-basic.json) |
| Forced Unix/TLS 1.2 | pass | [forced Unix response and trace graph](evidence/otel-unix-tls12-bd1c9327/scenario-basic.json) |
| Forced `getsockopt`/TLS 1.2 | pass | [OpenTelemetry graph](evidence/otel-getsockopt-tls12-c7209e43/scenario-basic.json) |
| Forced `getsockopt`/TLS 1.3 | pass | [OpenTelemetry graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-basic.json) and [Splunk graph](evidence/splunk-getsockopt-tls13-47237792/scenario-basic.json) |
| Official OpenTelemetry agent in retained cells | pass | [version, URL, and checksum](evidence/otel-unix-tls12-bd1c9327/official-javaagent.json) |
| Official Splunk agent | pass | [pinned version, URL, and checksum](evidence/splunk-getsockopt-tls13-47237792/official-javaagent.json), [runtime metadata](evidence/splunk-getsockopt-tls13-47237792/runtime-metadata.json), and [full acceptance](evidence/splunk-getsockopt-tls13-47237792/README.md) |
| OBI helper is dynamically attached | pass | [startup and late-attach recovery](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) |
| External extension is separately loaded | pass | [sanitized runtime metadata](evidence/otel-getsockopt-tls13-c9d14356/runtime-metadata.json) |
| Forced `getsockopt` bridge | pass | [TLS 1.3](evidence/otel-getsockopt-tls13-c9d14356/README.md) and [TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md) exact trace/parent graphs and run identities |
| Java V2 transport configuration | pass | [getsockopt](evidence/otel-getsockopt-tls13-c9d14356/java-selected-transport-configuration.txt) and [Unix](evidence/otel-unix-tls12-bd1c9327/java-selected-transport-configuration.txt) snapshots; exact trace assertions independently prove request use |
| Forced Unix fallback | pass | [exact trace/parent graph and V2 selection](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| Remote parent flag | pass | [basic exact-parent graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-basic.json) |
| W3C-only, no OBI state | pass | [OBI-absent W3C graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-w3c-only-obi-absent.json) |
| Conflicting W3C context wins | pass | [precedence graph and counters](evidence/otel-getsockopt-tls13-c9d14356/scenario-w3c.json) |
| Matching W3C and OBI context | pass | [matching-context graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-w3c-match.json) |
| Sampled and unsampled OBI-only take outcomes | pass | [lookup classification graph and diagnostics](evidence/otel-getsockopt-tls13-c9d14356/scenario-obi-flags.json) |
| Valid W3C through Unix bridge faults | pass | [named bounded responder modes, graphs, and Java deltas](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| Invalid W3C falls through to OBI | pass | [fallback graph and counters](evidence/otel-getsockopt-tls13-c9d14356/scenario-w3c.json) |
| Sequential backend keepalive | pass | [keepalive graph and connection evidence](evidence/otel-getsockopt-tls13-c9d14356/scenario-keepalive.json) |
| HTTP/1.1 pipelining | pass | [pipelining graph and connection evidence](evidence/otel-getsockopt-tls13-c9d14356/scenario-pipelining.json) |
| Parallel requests/connections | pass | [concurrency graph and connection evidence](evidence/otel-getsockopt-tls13-c9d14356/scenario-concurrency.json) |
| FD and ephemeral-port reuse | pass | [reuse graph and connection evidence](evidence/otel-getsockopt-tls13-c9d14356/scenario-fd-port-reuse.json) |
| Servlet/executor handoff | pass | [executor-handoff graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-handoff.json) |
| Java 21 virtual-thread handoff | pass | [virtual-thread graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-virtual-thread.json) |
| Jetty Netty-executor handoff | pass | [Netty handoff graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-netty.json) |
| Inbound Netty server extraction | pass | [Apache-to-Netty exact-parent graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-netty-server.json); this is the bounded fixture only |
| Repeated servlet async redispatch | pass | [redispatch graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-dispatch.json) |
| Live handoff-map pressure | pass | [pressure accounting](evidence/otel-getsockopt-tls13-c9d14356/scenario-pressure-status.json), [cleanup and recovery](evidence/otel-getsockopt-tls13-c9d14356/map-pressure-summary.json) |
| OBI absent at JVM start and late attach | pass | [absence, late attach, and recovery evidence](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) |
| Bridge-disabled control | pass | [bridge-disabled graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-disabled.json) |
| Extension absent and disabled controls | pass | [extension-control graphs](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) |
| Uninstrumented control | pass | [zero-span control](evidence/otel-getsockopt-tls13-c9d14356/scenario-uninstrumented.json) |
| Java SDK duplicate suppression | pass | [allowlisted suppression metric](evidence/otel-getsockopt-tls13-c9d14356/duplicate-suppression.json) |
| No duplicate Java server span | pass | [all scenario graphs and statuses](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) |
| No vendor UI or backend | pass | [sanitized runtime image inventory](evidence/otel-getsockopt-tls13-c9d14356/runtime-images.json) |

## VM-gated primary fault fixture

[`TestJavaRemoteParentPrimaryJVMFaults`](../../pkg/internal/ebpf/tpinjector/java_remote_parent_jvm_privileged_test.go)
starts a clean JVM with the packaged OBI agent but disables its automatic
remote-parent transport provider. The probe explicitly initializes the primary
`getsockopt` transport through the bootstrap bridge, which configures it via
JNI, then obtains the Java-created socket's FD and calls the Java bridge after
staging a remote-parent state and associated BPF map entries. Its cases are
valid, stale, ABI-version mismatch, all-zero trace ID, and all-zero parent span
ID. When run, it asserts the status and returned identifiers, cleared socket
FD, and absence of the staged state and data acknowledgement.

The fixture is run by
[`run-java-remote-parent-rhel.sh`](../../internal/test/vm/run-java-remote-parent-rhel.sh)
and is intended for the RHEL kernel VM workflow. It calls
`RemoteParentBridge.takeRemoteParent()` directly and manually stages BPF state;
therefore it is source-level bridge/provider coverage, not a retained Apache,
OpenTelemetry extraction, or W3C precedence acceptance result. A successful
privileged run and its artifact, plus an application-level primary fault
control, remain required before this record can claim those outcomes.

## Reproduction commands

```bash
./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3
./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.2
./examples/apache-java-https/run.sh --transport unix --agent otel --tls TLSv1.3
./examples/apache-java-https/run.sh --transport unix --agent otel --tls TLSv1.2
./examples/apache-java-https/run.sh --transport getsockopt --agent splunk --tls TLSv1.3
```

Record the repository revision, host/kernel/cgroup mode, architecture, Docker
version, Apache version, loaded TLS module, `mod_ssl` OpenSSL dependencies and
package owners, JVM version, agent metadata, command line, result directory,
and every unsupported cell. A negative result is complete only when it names
the last correct boundary and exact failure (attach, map, transport, JNI,
classloader, extraction, or assertion) and records both forced transport
outcomes.

## Issue coverage and remaining evidence gaps

The retained OpenTelemetry cells and the named Splunk primary cell prove
applicable issue #28 extraction cases, including exact one-shot operation
counters and request graphs. The V2 Java snapshots record configuration
selection; OBI availability metrics remain readiness evidence only. Benchmark
and external compatibility requirements remain open as listed in the final
column.

| Issue | Asset coverage | Still required before pass |
| --- | --- | --- |
| #19 Java SDK suppression | retained getsockopt and Unix avoided-service metrics plus exact-parent traffic passed | retain any additional supported agent cells required by the final support statement |
| #27 agent compatibility | OpenTelemetry cells at `c9d14356`, `c7209e43`, and `bd1c9327`, plus Splunk 2.28.0 at `47237792`, passed their named cells | execute the declared JVM/architecture matrix and remaining agent cells |
| #28 Java extraction matrix | applicable getsockopt and Unix OpenTelemetry cases, plus Splunk getsockopt/TLS 1.3, passed with exact graphs and one-shot counters | execute remaining agent, transport, and child-semantics cells |
| #31 deterministic traffic/assertions | retained OpenTelemetry and Splunk primary cells passed with exact IDs, flags, controls, and status records | retain the remaining advertised cells |
| #32 complete runbook | current runbook contains bounded startup/cleanup, exact controls, and an intentional failed-assertion artifact path | retain a clean-host execution whenever the runbook changes |
| #33 final report | definition-of-done reconciliation names every parent item and the currently passing evidence | resolve the parent item 6 gaps before declaring PoC success |
| #34 stress | retained TLS 1.3 and TLS 1.2 primary, and TLS 1.2 Unix stress, reuse, TLS-boundary-fixture, pressure, cleanup, and recovery cases passed | execute remaining advertised cells |
| #35 handoff | executor, virtual-thread, Netty worker, redispatch, and bounded inbound-Netty receive-to-extraction scenarios passed in the retained primary run | execute the remaining framework and environment matrix evidence |
| #36 fail-open | retained primary and Unix absence, restart, attach, disabled, fault, and recovery controls passed; unexecuted source controls cover a forced-primary Apache stale/W3C/recovery path and VM-gated stale, ABI-mismatch, and zero-ID component cases | retain a successful privileged artifact and a JVM/application primary-transport malformed fault control; the existing fault responder is Unix-only |
| #37 benchmark | predeclared matrix, repeated bounded workload, and resource/map snapshots | execute on fixed hardware and add sustained latency/throughput evidence |
| #38 compatibility | explicit untested matrix | execute each claimed kernel/cgroup/architecture/JVM/agent/TLS/transport cell |
| #39 diagnostics | retained OpenTelemetry and Splunk per-scenario counters, current availability schema, V2 snapshots, and suppression evidence passed | execute remaining agent/environment cells |
| #40 security | retained primary probes plus Unix forged/flood/path/permission matrix, exact-parent victim, and recovery passed; unexecuted source controls encode stale TTL rejection at Apache and primary-component boundaries | retain primary wrong-live-socket and stale-TTL evidence before marking the partial security matrix complete |

Unexecuted rows remain `untested`; a plan or template is not a successful
validation result.
