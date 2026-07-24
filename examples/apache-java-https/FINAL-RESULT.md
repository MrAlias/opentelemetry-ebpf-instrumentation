# Final result record

Status: **untested**

This file is a checked-in evidence template. No privileged eBPF/Compose run was
performed merely by adding the example, so no acceptance item is marked pass.
Replace `untested` only from a retained `.runtime/results/<run-id>/` bundle and
link that bundle or its sanitized CI artifact.

| Acceptance item | Status | Required evidence |
| --- | --- | --- |
| Apache 2.4 proxies to Jetty over verified HTTPS | untested | `/healthz` body, Apache log, certificate metadata |
| Backend protocol is HTTP/1.1 | untested | scenario response `protocol` |
| TLS 1.2 | untested | forced run and response `tls_protocol`/cipher |
| TLS 1.3 | untested | forced run and response `tls_protocol`/cipher |
| Official OpenTelemetry agent | untested | version, URL, checksum, startup log |
| Official Splunk agent | untested | version, URL, checksum, startup log |
| OBI helper is dynamically attached | untested | exact helper readiness log |
| External extension is separately loaded | untested | exact extension readiness log |
| Forced `getsockopt` bridge | untested | exact trace/parent graph and transport log |
| Forced Unix fallback | untested | exact trace/parent graph and transport log |
| Remote parent flag | untested | OTLP `HAS_IS_REMOTE` and `IS_REMOTE` bits on exact Java parent |
| W3C-only, no OBI state | untested | OBI absent, exact remote W3C parent, no Apache spans |
| Conflicting W3C context wins | untested | exact IDs/flags, distinct Apache candidate graph, one take and one `discard_standard` selection |
| Matching W3C and OBI context | untested | isolated header+TCP injection, exact candidate parent/flags, one-shot counters |
| Sampled and unsampled OBI-only context | untested | stripped backend W3C header, exact Apache flags, `take_sampled`/`take_unsampled` deltas |
| Valid W3C through Unix bridge faults | untested | named bounded responder modes, exact W3C parent/flags, exact attributable deltas |
| Invalid W3C falls through to OBI | untested | exact OBI parent plus take delta |
| Sequential backend keepalive | untested | one stable Jetty connection ID, zero wrong parents |
| HTTP/1.1 pipelining | untested | one frontend connection, all requests written before the first response read, distinct exact parents, zero wrong parents |
| Parallel requests/connections | untested | multiple stable Jetty connection IDs, distinct exact parents |
| FD and ephemeral-port reuse | untested | fixed frontend source port across reconnects, reused frontend fd, reused Jetty fd across distinct stable Jetty connection IDs, distinct exact parents, zero wrong parents |
| Servlet/executor handoff | untested | varied hops/faults and distinct exact parents |
| Java 21 virtual-thread handoff | untested | mixed/canceled workloads and distinct exact parents |
| Netty event-loop to worker handoff | untested | real event-loop/cancellation headers and exact parents |
| Repeated servlet async redispatch | untested | invocation-count headers, one Java server span, and one bridge take |
| Live handoff-map pressure | untested | exact map/JVM identity, fresh values, scanned order-independent eviction, above-baseline samples through aggregate TCP-inject completion, exact hits plus explicit roots, transport-aware upstream/retrieval reason conservation, zero wrong/unresolved parents, verified synthetic cleanup, steady-baseline recovery |
| OBI absent at JVM start and late attach | untested | root/W3C behavior while absent, helper-ready log after OBI starts, exact-parent recovery without JVM restart |
| Bridge-disabled control | untested | official agent/extension present, HTTP success, one Java root |
| Extension absent and disabled controls | untested | official agent retained, exact W3C parent, healthy response in both topologies |
| Uninstrumented control | untested | OBI/agent absent, equivalent HTTP response, zero marker spans |
| Java SDK duplicate suppression | untested | avoided-service metric plus successful exact-parent bridge |
| No duplicate Java server span | untested | exactly one span for every marker |
| No vendor UI or backend | untested | resolved Compose topology |

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

The runner now implements the issue #28 extraction matrix listed below,
including exact one-shot operation and selection counters. Those cases remain
`untested` until a privileged run supplies retained evidence. Other issues can
still require both implementation work and execution, as listed explicitly in
the final column.

| Issue | Asset coverage | Still required before pass |
| --- | --- | --- |
| #19 Java SDK suppression | runtime assertion for the exact Java avoided-service metric followed by exact-parent bridge traffic | retain successful privileged-run evidence for both invariants |
| #27 agent compatibility | pinned official OTel/Splunk downloads and selectable Compose startup | execute both artifacts and any additional supported-version cells |
| #28 Java extraction matrix | stock-agent paths for no state, W3C-only, OBI-only, matching/conflicting W3C, sampled/unsampled flags, malformed-W3C fallback, stale/malformed OBI fallback, redispatch, async, keepalive, and parallel; exact one-shot transport and Java diagnostics | execute privileged paths and retain the resulting evidence |
| #31 deterministic traffic/assertions | exact IDs/remote flags, marker selection, W3C precedence/fallback/no-state, keepalive, concurrency, and two distinct controls | retain successful privileged-run artifacts |
| #33 final report | this result template and automatic environment/evidence bundle | populate every row from real runs |
| #34 stress | keepalive, explicit HTTP/1.1 pipelining, parallel/churn, stable Jetty connection IDs, deterministic frontend ephemeral-port reuse, observed frontend/Jetty fd reuse, slow body, deterministic split/coalesced TLS receive-boundary fixtures for TLS 1.2/1.3, cancellation/retry, and live map pressure/eviction assets | execute privileged runs and retain the scenario connection/trace evidence |
| #35 handoff | one-shot accepted-socket task propagation plus packaged nested-executor, cancellation/reuse, Java 21 carrier-migration, servlet async/redispatch, and real Netty event-loop/worker assets | execute privileged runs and retain exact-parent evidence for the framework scenarios |
| #36 fail-open | OBI absent at JVM start, late attach/recovery, live valid-W3C traffic spanning an enforced OBI stop/restart, bridge/extension disabled and extension-absent controls, true uninstrumented equivalence, and named bounded Unix response faults | execute privileged runs and retain each per-fault diagnostic delta |
| #37 benchmark | predeclared matrix, repeated bounded workload, and resource/map snapshots | execute on fixed hardware and add sustained latency/throughput evidence |
| #38 compatibility | explicit untested matrix | execute each claimed kernel/cgroup/architecture/JVM/agent/TLS/transport cell |
| #39 diagnostics | bounded sanitized receiver, exact per-scenario take/status/flag/selection deltas, zero unexpected retrieval results, runtime topology, and suppression evidence | execute runs and verify every remaining core reason/cardinality bound under negative tests |
| #40 security | same-cgroup and sibling-container primary controls, concurrent Unix forged/repeated/flood abuse with an exact-parent victim, UDS replacement, permissive-directory refusal, exact diagnostics schema, and post-abuse recovery | execute privileged runs and retain every topology, metric, response, and sanitized-log artifact |

Until those rows have attached evidence, they remain `untested`; a plan or
template is not a successful validation result.
