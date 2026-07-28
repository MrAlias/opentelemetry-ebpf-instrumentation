# Final result record

Status: **partial — OpenTelemetry/`getsockopt`/TLS 1.3 passed**

The clean full run
[otel-getsockopt-tls13-94221a91](evidence/otel-getsockopt-tls13-94221a91/README.md)
is retained with source revision, environment, scenario graphs, diagnostic
deltas, and checksums. It proves only its exact matrix cell. Rows requiring a
different transport, TLS version, agent, or environment remain `untested`.

| Acceptance item | Status | Evidence or remaining requirement |
| --- | --- | --- |
| Apache 2.4 proxies to Jetty over verified HTTPS | pass | [runtime and certificate evidence](evidence/otel-getsockopt-tls13-94221a91/README.md#retained-proof) |
| Backend protocol is HTTP/1.1 | pass | [basic response and trace graph](evidence/otel-getsockopt-tls13-94221a91/scenario-basic.json) |
| TLS 1.2 | untested | forced run and response `tls_protocol`/cipher |
| TLS 1.3 | pass | [basic response and trace graph](evidence/otel-getsockopt-tls13-94221a91/scenario-basic.json) |
| Official OpenTelemetry agent | pass | [version, URL, and checksum](evidence/otel-getsockopt-tls13-94221a91/official-javaagent.json) |
| Official Splunk agent | untested | version, URL, checksum, startup log |
| OBI helper is dynamically attached | pass | [startup and late-attach recovery](evidence/otel-getsockopt-tls13-94221a91/README.md#retained-proof) |
| External extension is separately loaded | pass | [sanitized runtime metadata](evidence/otel-getsockopt-tls13-94221a91/runtime-metadata.json) |
| Forced `getsockopt` bridge | pass | [exact trace/parent graph and run identity](evidence/otel-getsockopt-tls13-94221a91/README.md) |
| Java V2 transport configuration | pass | [fixed selected-transport snapshot](evidence/otel-getsockopt-tls13-94221a91/java-selected-transport-configuration.txt); exact trace assertions independently prove request use |
| Forced Unix fallback | untested | exact trace/parent graph and transport log |
| Remote parent flag | pass | [basic exact-parent graph](evidence/otel-getsockopt-tls13-94221a91/scenario-basic.json) |
| W3C-only, no OBI state | pass | [OBI-absent W3C graph](evidence/otel-getsockopt-tls13-94221a91/scenario-w3c-only-obi-absent.json) |
| Conflicting W3C context wins | pass | [precedence graph and counters](evidence/otel-getsockopt-tls13-94221a91/scenario-w3c.json) |
| Matching W3C and OBI context | pass | [matching-context graph](evidence/otel-getsockopt-tls13-94221a91/scenario-w3c-match.json) |
| Sampled and unsampled OBI-only take outcomes | pass | [lookup classification graph and diagnostics](evidence/otel-getsockopt-tls13-94221a91/scenario-obi-flags.json) |
| Valid W3C through Unix bridge faults | untested | named bounded responder modes, exact W3C parent/flags, exact attributable deltas |
| Invalid W3C falls through to OBI | pass | [fallback graph and counters](evidence/otel-getsockopt-tls13-94221a91/scenario-w3c.json) |
| Sequential backend keepalive | pass | [keepalive graph and connection evidence](evidence/otel-getsockopt-tls13-94221a91/scenario-keepalive.json) |
| HTTP/1.1 pipelining | pass | [pipelining graph and connection evidence](evidence/otel-getsockopt-tls13-94221a91/scenario-pipelining.json) |
| Parallel requests/connections | pass | [concurrency graph and connection evidence](evidence/otel-getsockopt-tls13-94221a91/scenario-concurrency.json) |
| FD and ephemeral-port reuse | pass | [reuse graph and connection evidence](evidence/otel-getsockopt-tls13-94221a91/scenario-fd-port-reuse.json) |
| Servlet/executor handoff | pass | [executor-handoff graph](evidence/otel-getsockopt-tls13-94221a91/scenario-handoff.json) |
| Java 21 virtual-thread handoff | pass | [virtual-thread graph](evidence/otel-getsockopt-tls13-94221a91/scenario-virtual-thread.json) |
| Netty event-loop to worker handoff | pass | [Netty handoff graph](evidence/otel-getsockopt-tls13-94221a91/scenario-netty.json) |
| Repeated servlet async redispatch | pass | [redispatch graph](evidence/otel-getsockopt-tls13-94221a91/scenario-dispatch.json) |
| Live handoff-map pressure | pass | [pressure accounting](evidence/otel-getsockopt-tls13-94221a91/scenario-pressure-status.json), [cleanup and recovery](evidence/otel-getsockopt-tls13-94221a91/map-pressure-summary.json) |
| OBI absent at JVM start and late attach | pass | [absence, late attach, and recovery evidence](evidence/otel-getsockopt-tls13-94221a91/README.md#retained-proof) |
| Bridge-disabled control | pass | [bridge-disabled graph](evidence/otel-getsockopt-tls13-94221a91/scenario-disabled.json) |
| Extension absent and disabled controls | pass | [extension-control graphs](evidence/otel-getsockopt-tls13-94221a91/README.md#retained-proof) |
| Uninstrumented control | pass | [zero-span control](evidence/otel-getsockopt-tls13-94221a91/scenario-uninstrumented.json) |
| Java SDK duplicate suppression | pass | [allowlisted suppression metric](evidence/otel-getsockopt-tls13-94221a91/duplicate-suppression.json) |
| No duplicate Java server span | pass | [all scenario graphs and statuses](evidence/otel-getsockopt-tls13-94221a91/README.md#retained-proof) |
| No vendor UI or backend | pass | [sanitized runtime image inventory](evidence/otel-getsockopt-tls13-94221a91/runtime-images.json) |

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

The retained primary run now proves the applicable issue #28 extraction cases,
including exact one-shot operation counters and request graphs. The V2 Java snapshot records configuration selection; OBI availability metrics remain readiness evidence only. Unix, TLS 1.2,
Splunk, benchmark, and external compatibility requirements remain open as
listed in the final column.

| Issue | Asset coverage | Still required before pass |
| --- | --- | --- |
| #19 Java SDK suppression | primary avoided-service metric plus exact-parent traffic passed | retain any additional supported transport/agent cells required by the final support statement |
| #27 agent compatibility | tested revision `94221a91` OpenTelemetry cell passed; pinned Splunk artifact is selectable | execute Splunk and the declared JVM/architecture matrix |
| #28 Java extraction matrix | applicable primary OpenTelemetry cases passed with exact graphs and one-shot counters | execute a clean full Unix run, Splunk at a named source revision, end-to-end child flag semantics, and the missing Netty pre-extraction integration |
| #31 deterministic traffic/assertions | primary OpenTelemetry cell passed with exact IDs, flags, controls, and status records | retain the remaining advertised cells |
| #33 final report | primary cell populated from a retained bundle | complete benchmark, compatibility, fallback, TLS 1.2, and Splunk outcomes |
| #34 stress | primary TLS 1.3 stress, reuse, receive-boundary, pressure, cleanup, and recovery cases passed | execute forced Unix and TLS 1.2 cells |
| #35 handoff | executor, virtual-thread, Netty worker, and redispatch scenarios passed in the retained primary run | add the stock Netty receive-to-pre-extraction integration and remaining matrix evidence |
| #36 fail-open | primary absence, restart, attach, disabled, and recovery controls passed | execute and retain the clean full Unix fault suite |
| #37 benchmark | predeclared matrix, repeated bounded workload, and resource/map snapshots | execute on fixed hardware and add sustained latency/throughput evidence |
| #38 compatibility | explicit untested matrix | execute each claimed kernel/cgroup/architecture/JVM/agent/TLS/transport cell |
| #39 diagnostics | primary per-scenario counters, current availability schema, V2 Java configuration snapshot, and suppression evidence passed | execute the Unix negative/fault matrix |
| #40 security | retained primary same-cgroup/sibling probes, exact-parent victim, and recovery passed | execute the remaining primary negative cases and the Unix forged/flood/path/permission matrix |

Unexecuted rows remain `untested`; a plan or template is not a successful
validation result.
