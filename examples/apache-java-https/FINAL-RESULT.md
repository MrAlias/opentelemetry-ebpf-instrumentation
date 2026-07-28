# Final result record

Status: **partial — two OpenTelemetry transport/TLS cells passed**

The clean full
[getsockopt/TLS 1.3](evidence/otel-getsockopt-tls13-c9d14356/README.md) and
[Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md) runs are retained
with source revision, environment, scenario graphs, diagnostic deltas, and
checksums. The refreshed primary run also includes the bounded inbound-Netty
fixture. Each proves only its exact matrix cell. Rows requiring a different
transport/TLS/agent/environment combination remain `untested`. Unless a row
names both retained cells, its `pass` applies only to the evidence link in its
final column.

| Acceptance item | Status | Evidence or remaining requirement |
| --- | --- | --- |
| Apache 2.4 proxies to Jetty over verified HTTPS | pass | [runtime and certificate evidence](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) |
| Backend protocol is HTTP/1.1 | pass | [basic response and trace graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-basic.json) |
| Forced Unix/TLS 1.2 | pass | [forced Unix response and trace graph](evidence/otel-unix-tls12-bd1c9327/scenario-basic.json) |
| Forced `getsockopt`/TLS 1.3 | pass | [forced `getsockopt` response and trace graph](evidence/otel-getsockopt-tls13-c9d14356/scenario-basic.json) |
| Official OpenTelemetry agent in retained cells | pass | [version, URL, and checksum](evidence/otel-unix-tls12-bd1c9327/official-javaagent.json) |
| Official Splunk agent | untested | version, URL, checksum, startup log |
| OBI helper is dynamically attached | pass | [startup and late-attach recovery](evidence/otel-getsockopt-tls13-c9d14356/README.md#retained-proof) |
| External extension is separately loaded | pass | [sanitized runtime metadata](evidence/otel-getsockopt-tls13-c9d14356/runtime-metadata.json) |
| Forced `getsockopt` bridge | pass | [exact trace/parent graph and run identity](evidence/otel-getsockopt-tls13-c9d14356/README.md) |
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

The retained OpenTelemetry cells now prove applicable issue #28 extraction
cases, including exact one-shot operation counters and request graphs. The V2
Java snapshots record configuration selection; OBI availability metrics remain
readiness evidence only. Splunk, benchmark, and external compatibility
requirements remain open as listed in the final column.

| Issue | Asset coverage | Still required before pass |
| --- | --- | --- |
| #19 Java SDK suppression | retained getsockopt and Unix avoided-service metrics plus exact-parent traffic passed | retain any additional supported agent cells required by the final support statement |
| #27 agent compatibility | tested revisions `c9d14356` and `bd1c9327` OpenTelemetry cells passed; pinned Splunk artifact is selectable | execute Splunk and the declared JVM/architecture matrix |
| #28 Java extraction matrix | applicable getsockopt and Unix OpenTelemetry cases passed with exact graphs, one-shot counters, and the bounded inbound-Netty fixture | execute Splunk at a named source revision and end-to-end child flag semantics |
| #31 deterministic traffic/assertions | retained OpenTelemetry cells passed with exact IDs, flags, controls, and status records | retain the remaining advertised cells |
| #33 final report | two OpenTelemetry matrix cells are populated from retained bundles, with the primary cell refreshed for inbound Netty | complete benchmark, compatibility, and Splunk outcomes |
| #34 stress | retained TLS 1.3 primary and TLS 1.2 Unix stress, reuse, TLS-boundary-fixture, pressure, cleanup, and recovery cases passed | execute remaining advertised cells |
| #35 handoff | executor, virtual-thread, Netty worker, redispatch, and bounded inbound-Netty receive-to-extraction scenarios passed in the retained primary run | execute the remaining framework and environment matrix evidence |
| #36 fail-open | retained primary and Unix absence, restart, attach, disabled, fault, and recovery controls passed | retain any additional advertised cells |
| #37 benchmark | predeclared matrix, repeated bounded workload, and resource/map snapshots | execute on fixed hardware and add sustained latency/throughput evidence |
| #38 compatibility | explicit untested matrix | execute each claimed kernel/cgroup/architecture/JVM/agent/TLS/transport cell |
| #39 diagnostics | retained primary and Unix per-scenario counters, current availability schema, V2 snapshots, and suppression evidence passed | execute remaining agent/environment cells |
| #40 security | retained primary probes plus Unix forged/flood/path/permission matrix, exact-parent victim, and recovery passed | execute the remaining primary negative cases and other matrix cells |

Unexecuted rows remain `untested`; a plan or template is not a successful
validation result.
