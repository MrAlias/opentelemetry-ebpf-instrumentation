# Final result record

Status: **partial — four OpenTelemetry transport/TLS cells and one Splunk primary cell passed**

The clean full
[getsockopt/TLS 1.3](evidence/otel-getsockopt-tls13-e8db066a/README.md),
[getsockopt/TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md), and
[Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md), and
[Unix/TLS 1.3](evidence/otel-unix-tls13-6c4a2505/README.md), and the
[Splunk getsockopt/TLS 1.3](evidence/splunk-getsockopt-tls13-47237792/README.md)
runs are retained with source revision, environment, scenario graphs,
bounded diagnostics, and checksums. The refreshed OpenTelemetry primary run
also includes the bounded inbound-Netty fixture. Each proves only its exact matrix
cell. Rows requiring a different transport/TLS/agent/environment combination
remain `untested`. A row's `pass` applies only to its linked retained evidence.
The clean full TLS 1.3
[issue #34 supplement](evidence/otel-getsockopt-tls13-8282d2ed/README.md)
retains a current-revision nested wire-record/decrypted-callback fixture. Its
correlated Apache-to-Java trigger is a separate path, so the supplement does
not close #34 or replace the broader primary bundle for unrelated controls.
The [full primary socket-isolation acceptance bundle](evidence/otel-getsockopt-tls13-e8db066a/README.md)
records a clean full run at its named revision with same-cgroup, sibling,
same-JVM wrong-live-socket, and root duplicated-descriptor controls; primary
stale-state and four returned-response fault modes; exact-parent victims; and
recovery. It promotes only those named primary controls to `pass`.
The current Unix/TLS 1.3 bundle additionally records a clean full acceptance
run with sibling and same-cgroup attacker controls, concurrent legitimate
victims, endpoint and directory controls, and a 1ns stale-retrieval recovery.
It promotes only that exact forced-Unix matrix cell and those named Unix
controls to `pass`.
Three clean focused OpenTelemetry/`getsockopt`/TLS 1.3 runs at
`8f0aa1f6a7a28af93875823e4cf41675221d3542` remain historical targeted
validation. The full primary bundle independently exercises those
controls and additionally retains the malformed declared-size response; the
focused records are not used to promote an acceptance cell.

## Parent tracker definition-of-done reconciliation

This is the explicit reconciliation for
[issue #2](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/issues/2).
`fail` below means the complete parent requirement is not yet satisfied; it
does not invalidate the named passing matrix cells. The
[runbook](README.md), [compatibility matrix](COMPATIBILITY.md), and linked
evidence define the current boundary of the result.

Matrix revision: `apache-java-https-compatibility-v2`.
<!-- obi-compatibility-matrix-revision: apache-java-https-compatibility-v2 -->

| Parent definition-of-done item | Status | Evidence or exact gap |
| --- | --- | --- |
| 1. Apache proxies to Java over HTTPS | pass | [Apache runtime and certificate evidence](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) and the [exact-parent graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic.json). |
| 2. Apache is instrumented by OBI | pass | [OBI startup and Apache instrumentation evidence](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof). |
| 3. Java uses the official agent and OBI extension/helper | pass | [official agent metadata](evidence/otel-unix-tls12-bd1c9327/official-javaagent.json), [external-extension runtime metadata](evidence/otel-getsockopt-tls13-e8db066a/runtime-metadata.json), and [dynamic helper attach evidence](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof). |
| 4. Traffic and traces are collected without a vendor UI | pass | [local receiver inventory](evidence/otel-getsockopt-tls13-e8db066a/runtime-images.json) and retained scenario JSON. |
| 5. Apache client and Java server spans have one exact trace/parent relationship | pass | [basic trace graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic.json). |
| 6. Precedence, concurrency, keepalive, failure, and compatibility cases are exercised | fail | Retained controls pass precedence, concurrency, keepalive, primary and Unix fail-open/fault cases, [current Unix sibling/same-cgroup/stale controls](evidence/otel-unix-tls13-6c4a2505/README.md), and [full primary same/sibling/live-descriptor/stale/malformed-response controls](evidence/otel-getsockopt-tls13-e8db066a/README.md). The [TLS wire-record/decrypted-callback fixture](evidence/otel-getsockopt-tls13-8282d2ed/README.md) passes on a nested Java-to-loopback-Netty connection, but its exact-parent Apache-to-Java trigger is a separate path; the same-request conjunction remains untested for #34. A Unix application-descriptor mismatch is not applicable because Unix opens a fresh broker socket and authorizes peer/TID/capability instead of accepting the application FD; its meaningful peer and endpoint analogues pass in the retained Unix cells. Permanent process-lifetime OBI absence, explicit stale-generation mismatch, genuine TID/PID reuse, and an `auto` primary-unavailable-plus-fallback-unavailable application control remain untested for #36. Literal retained-evidence gaps for #28, #34, #35, #39, and #40 are listed below. The [#37 benchmark](BENCHMARK.md) and unexecuted [#38 compatibility](COMPATIBILITY.md) rows also prevent the complete workstream from passing. The [VM-gated focused preflight](focused-validation/rhel96-kernel-sockopt-4fe50533/README.md) is a narrower retained component result, not a substitute for this full application evidence. |
| 7. Exact build, run, certificate, host, agent, and cleanup steps are documented | pass | [reproducible runbook](README.md), including the bounded [deliberate assertion failure](README.md#deliberate-assertion-failure-control), and retained environment/certificate evidence. |

| Acceptance item | Status | Evidence or remaining requirement |
| --- | --- | --- |
| Apache 2.4 proxies to Jetty over verified HTTPS | pass | [runtime and certificate evidence](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| Backend protocol is HTTP/1.1 | pass | [basic response and trace graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic.json) |
| Forced Unix/TLS 1.2 | pass | [forced Unix response and trace graph](evidence/otel-unix-tls12-bd1c9327/scenario-basic.json) |
| Forced Unix/TLS 1.3 | pass | [forced Unix recovery graph and V2 selection](evidence/otel-unix-tls13-6c4a2505/README.md#retained-proof) |
| Forced `getsockopt`/TLS 1.2 | pass | [OpenTelemetry graph](evidence/otel-getsockopt-tls12-c7209e43/scenario-basic.json) |
| Forced `getsockopt`/TLS 1.3 | pass | [OpenTelemetry graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic.json) and [Splunk graph](evidence/splunk-getsockopt-tls13-47237792/scenario-basic.json) |
| Official OpenTelemetry agent in retained cells | pass | [version, URL, and checksum](evidence/otel-unix-tls12-bd1c9327/official-javaagent.json) |
| Official Splunk agent | pass | [pinned version, URL, and checksum](evidence/splunk-getsockopt-tls13-47237792/official-javaagent.json), [runtime metadata](evidence/splunk-getsockopt-tls13-47237792/runtime-metadata.json), and [full acceptance](evidence/splunk-getsockopt-tls13-47237792/README.md) |
| OBI helper is dynamically attached | pass | [startup and late-attach recovery](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| External extension is separately loaded | pass | [sanitized runtime metadata](evidence/otel-getsockopt-tls13-e8db066a/runtime-metadata.json) |
| Forced `getsockopt` bridge | pass | [TLS 1.3](evidence/otel-getsockopt-tls13-e8db066a/README.md) and [TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md) exact trace/parent graphs and run identities |
| Java V2 transport configuration | pass | [getsockopt](evidence/otel-getsockopt-tls13-e8db066a/java-selected-transport-configuration.txt), [Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/java-selected-transport-configuration.txt), and [Unix/TLS 1.3](evidence/otel-unix-tls13-6c4a2505/java-selected-transport-configuration.txt) snapshots; exact trace assertions independently prove request use |
| Forced Unix fallback | pass | [TLS 1.2 exact trace/parent graph](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) and [TLS 1.3 V2 selection plus recovery](evidence/otel-unix-tls13-6c4a2505/README.md#retained-proof) |
| Remote parent flag | pass | [basic exact-parent graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic.json) |
| W3C-only, no OBI state | pass | [OBI-absent W3C graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-only-obi-absent.json) |
| Conflicting W3C context wins | pass | [precedence graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c.json) and [passing counter assertion status](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-status.json); the ordinary phase counter values are omitted |
| Matching W3C and OBI context | pass | [matching-context graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-match.json) |
| Sampled and unsampled OBI-only take outcomes | pass | [lookup classification graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-obi-flags.json) and [passing diagnostic assertion status](evidence/otel-getsockopt-tls13-e8db066a/scenario-obi-flags-status.json); the ordinary phase diagnostic values are omitted |
| Valid W3C through Unix bridge faults | pass | [named bounded responder modes, graphs, and Java deltas](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| Valid W3C through stale primary state | pass | [retained `1ns` stale graph, terminal diagnostics, and recovery](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| Valid W3C through primary version, declared-size, and zero-ID responses | pass | [four one-shot returned-response fault graphs and normal recovery](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| Primary same/sibling and live-descriptor isolation | pass | [bounded probes, ordered metric windows, exact-parent victims, and recovery](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| Unix application-descriptor mismatch | not applicable | Unix does not accept an application FD; [peer/TID/capability and endpoint controls](SECURITY.md) are the applicable isolation cases |
| Invalid W3C falls through to OBI | pass | [fallback graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c.json) and [passing counter assertion status](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-status.json); the ordinary phase counter values are omitted |
| Sequential backend keepalive | pass | [keepalive graph and connection evidence](evidence/otel-getsockopt-tls13-e8db066a/scenario-keepalive.json) |
| HTTP/1.1 pipelining | pass | [pipelining graph and connection evidence](evidence/otel-getsockopt-tls13-e8db066a/scenario-pipelining.json) |
| TLS record split/coalescing across Java callbacks | partial | [nested wire-record/decrypted-callback fixture and separate outer exact-parent graph](evidence/otel-getsockopt-tls13-8282d2ed/README.md#retained-proof); the same Apache-to-Java correlated request must exercise both properties |
| Parallel requests/connections | pass | [concurrency graph and connection evidence](evidence/otel-getsockopt-tls13-e8db066a/scenario-concurrency.json) |
| FD and ephemeral-port reuse | pass | [reuse graph and connection evidence](evidence/otel-getsockopt-tls13-e8db066a/scenario-fd-port-reuse.json) |
| Servlet/executor handoff | pass | [executor-handoff graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-handoff.json) |
| Java 21 virtual-thread handoff | pass | [virtual-thread graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-virtual-thread.json) |
| Jetty Netty-executor handoff | pass | [Netty handoff graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-netty.json) |
| Inbound Netty server extraction | pass | [Apache-to-Netty exact-parent graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-netty-server.json); this is the bounded fixture only |
| Repeated servlet async redispatch | pass | [redispatch graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-dispatch.json) |
| Live handoff-map pressure | pass | [pressure accounting](evidence/otel-getsockopt-tls13-e8db066a/scenario-pressure-status.json), [cleanup and recovery](evidence/otel-getsockopt-tls13-e8db066a/map-pressure-summary.json) |
| OBI absent at JVM start and late attach | pass | [absence, late attach, and recovery evidence](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| Bridge-disabled control | pass | [bridge-disabled graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-disabled.json) |
| Extension absent and disabled controls | pass | [extension-control graphs](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| Uninstrumented control | pass | [zero-span control](evidence/otel-getsockopt-tls13-e8db066a/scenario-uninstrumented.json) |
| Java SDK duplicate-suppression detection | pass | [allowlisted suppression metric and bounded first-export timing](evidence/otel-getsockopt-tls13-e8db066a/delayed-otlp-suppression.json); detection occurs only after the first official SDK export |
| No duplicate Java server span after detection | pass | [post-detection exact-parent graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic-delayed-otlp-suppression.json); the retained prime request has one startup-window OBI span before detection and is an explicit limitation, not a no-duplicate pass |
| No vendor UI or backend | pass | [sanitized runtime image inventory](evidence/otel-getsockopt-tls13-e8db066a/runtime-images.json) |

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
privileged run is retained in the
[focused RHEL kernel preflight](focused-validation/rhel96-kernel-sockopt-4fe50533/README.md),
which promotes only the named component checks and Go transport/provider gates.
Separately, the [focused application-level primary control](focused-validation/primary-getsockopt-8f0aa1f6/README.md)
at `8f0aa1f6` passed stale, version-mismatch, and zero-ID cases with W3C
precedence and recovery, but is targeted non-acceptance output.

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
applicable issue #28 extraction cases through request graphs and passing
one-shot counter/diagnostic assertions. Exact counter values are retained only
for the explicitly linked bounded fault, security, pressure, and suppression
summaries; ordinary phase snapshots are omitted. The V2 Java snapshots record
configuration selection; OBI availability metrics remain readiness evidence
only. Benchmark and external compatibility requirements remain open as listed
in the final column.

| Issue | Asset coverage | Still required before pass |
| --- | --- | --- |
| #19 Java SDK suppression | retained getsockopt and Unix avoided-service metrics plus exact-parent traffic pass after detection; the delayed-export control records one bounded startup-window OBI span before behavioral detection and one exact-parent official SDK span with no OBI duplicate afterward; [`TestFilter_OTelDetectionKeepsKProbeCaptureEligibleForUncoveredProtocol`](../../pkg/ebpf/common/pids_test.go) proves behavioral detection preserves KProbe capture for an SDK-uncovered Redis protocol, while [`TestTracesSkipsInstrumented`](../../pkg/export/otel/traces_test.go) preserves service-wide export suppression | none at source/test scope; broader agent and environment execution remains tracked by #27 and #38 and does not reopen #19; the pre-detection startup window remains an explicit limitation |
| #27 agent compatibility | OpenTelemetry cells at `e8db066a`, `c7209e43`, `bd1c9327`, and `6c4a2505`, plus Splunk 2.28.0 at `47237792`, passed their named cells | execute the declared JVM/architecture matrix and remaining agent cells |
| #28 Java extraction matrix | applicable getsockopt and Unix OpenTelemetry cases, including Unix/TLS 1.3 at `6c4a2505`, plus Splunk getsockopt/TLS 1.3, passed with exact graphs and passing one-shot counter assertions | retain dedicated stock-agent runtime controls for multiple extraction calls on one request and nested/duplicate-server-instrumenter activation; execute remaining agent, transport, and child-semantics cells |
| #31 deterministic traffic/assertions | retained OpenTelemetry and Splunk primary cells plus the Unix/TLS 1.3 control cell passed with exact IDs, flags, controls, and status records | retain the remaining advertised cells |
| #32 complete runbook | current runbook contains bounded startup/cleanup, exact controls, and an intentional failed-assertion artifact path | retain a clean-host execution whenever the runbook changes |
| #33 final report | definition-of-done reconciliation names every parent item and the currently passing evidence | resolve the parent item 6 gaps before declaring PoC success |
| #34 stress | retained keepalive, pipelining, concurrency, churn, fd/port reuse, slow-body, timeout/retry, pressure/cleanup, reason-coded outcome, and exact-parent controls pass; the [current TLS 1.3 supplement](evidence/otel-getsockopt-tls13-8282d2ed/README.md) adds actual nested TLS-record split/coalescing with exact decrypted callbacks and ordering | retain the conjunction on the same correlated Apache-to-Java request; the current exact-parent graph is the outer trigger while boundary traffic is a separate Java-to-loopback-Netty connection |
| #35 handoff | executor, virtual-thread, Netty worker, redispatch, and bounded inbound-Netty receive-to-extraction scenarios passed in the retained primary run; the [packaged-agent component control](../../pkg/internal/java/agent/src/test/javaProbe/io/opentelemetry/obi/java/probe/ExecutorRuntimeProbe.java) exercises the exact 64-scope Java relay bound, ancestor-cycle rejection, Java fail-closed lookup and unlink emission, complete unwind, cleanup, and fresh recovery | retain framework/application depth- and cycle-miss evidence and reason-coded unsupported-timing diagnostics; execute the remaining framework and environment matrix evidence |
| #36 fail-open | retained primary and Unix bounded startup absence/late attach, failed attach, disabled, timeout, disconnect, overload, restart, TTL-stale, version, declared-size, truncated-frame, zero-ID, map-pressure/FD-reuse, W3C-precedence, and recovery controls pass for their transport-applicable cells; the focused RHEL kernel preflight retains the direct JVM fault component fixture | retain application-level controls for permanent process-lifetime OBI absence, an explicit stale-generation mismatch, genuine TID/PID reuse, and `auto` with both primary and fallback unavailable; the VM-gated direct component fixture remains narrower than an application compatibility cell |
| #37 benchmark | predeclared matrix, repeated bounded workload, resource/map snapshots, and a focused digest-pinned RHEL kernel result with all six Go transport/provider gates passed | execute on fixed hardware and add sustained application plus Java/JNI latency, allocation, and resource evidence |
| #38 compatibility | exact Linux unified-v2 `amd64` OpenTelemetry Unix/TLS 1.3 cell at `6c4a2505` is retained; the rest remains explicitly untested | execute each remaining claimed kernel/cgroup/architecture/JVM/agent/TLS/transport cell |
| #39 diagnostics | retained OpenTelemetry and Splunk per-scenario assertion statuses, current availability schema, V2 snapshots, delayed-first-export suppression evidence, and bounded public diagnostic summaries passed; exact values are retained only for named bounded controls | retain bounded counter/log evidence that makes every negative test diagnosable and a runtime endpoint/log non-disclosure audit; execute remaining agent/environment cells |
| #40 security | retained Unix forged/flood/path/permission matrix, sibling and same-cgroup topology, exact-parent victims, stale-TTL rejection, and recovery pass; the [current primary acceptance result](evidence/otel-getsockopt-tls13-e8db066a/README.md) adds same/sibling isolated unauthorized windows, same-JVM wrong-live-socket and duplicated-descriptor controls, exact-parent victims, stale/malformed rejection, and recovery | retain explicit stale-generation-mismatch, genuine TID/PID-reuse, primary wrong-current-TID/logical-execution, and runtime diagnostic-side-channel controls; broader environment coverage remains tracked by #38 |

Unexecuted rows remain `untested`; a plan or template is not a successful
validation result.
