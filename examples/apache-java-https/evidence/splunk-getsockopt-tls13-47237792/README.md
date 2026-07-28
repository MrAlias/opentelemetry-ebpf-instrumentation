# Splunk getsockopt TLS 1.3 acceptance

Result: **pass**

This bounded, reviewer-facing subset of a clean full run is published under
the non-runtime-derived evidence ID **splunk-getsockopt-tls13-47237792**. It
proves only the matrix cell recorded below. It does not turn unexecuted
transports, TLS versions, agents, kernels, cgroup topologies, architectures,
or JVMs into passing cells.

## Run identity

| Field | Value |
| --- | --- |
| Public evidence ID | splunk-getsockopt-tls13-47237792 |
| Source revision | 472377929106fa57c1575ab0942984d5d499b731 |
| Source state | clean |
| Source-tree manifest SHA-256 | 72f6d2460015ac566b0febd4f130a966e665ff54b07ecbce26853272f1e3da76 |
| Invocation | examples/apache-java-https/run.sh --transport getsockopt --agent splunk --tls TLSv1.3 --command-timeout 1800 |
| Acceptance mode | full all suite |
| Transport | forced getsockopt |
| Agent | official Splunk Java agent 2.28.0 |
| Agent SHA-256 | 70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351 |
| TLS | 1.3 |
| JVM | Temurin 21.0.10+7 |
| Architecture | x86_64 |
| Kernel | Linux 7.0.0-1009-aws; distribution not independently recorded |
| Cgroup | unified v2 |
| Runner result | 34 passed, 1 expected unsupported, 0 failed |

[environment.txt](environment.txt), [source-state.txt](source-state.txt),
[runtime-metadata.json](runtime-metadata.json),
[official-javaagent.json](official-javaagent.json), and
[bridge-artifacts.json](bridge-artifacts.json) retain the bounded run and
source identity. [run-status.json](run-status.json) records status passed,
exit status 0, and acceptance evidence.

The sole unsupported status is [the Unix-only W3C fault suite](scenario-w3c-fault-status.json).
Its exclusion is expected for a forced primary-transport run and is not
reported as a pass.

## Transport-configuration snapshot

[java-selected-transport-configuration.txt](java-selected-transport-configuration.txt)
is the V2 Java configuration snapshot:

    version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0

It proves that the forced primary configuration selected getsockopt after one
native attempt. It does not prove that a particular request used that
transport; the exact trace assertions in the scenario graphs provide that
independent request-level proof.

OBI `operation=availability` metrics are bridge lifecycle/readiness evidence
only. They are not Java transport-selection evidence and must not be read as a
per-request transport claim.

## Retained proof

| Claim | Primary artifacts |
| --- | --- |
| Verified Apache-to-Jetty HTTPS, HTTP/1.1, TLS 1.3 | [Apache/OpenSSL identity](apache-openssl-runtime.txt), [certificate metadata](certificates.json), [basic response and exact-parent graph](scenario-basic.json) |
| Pinned Splunk agent plus separate helper and extension | [official agent identity](official-javaagent.json), [bridge checksums](bridge-artifacts.json), and [sanitized runtime metadata](runtime-metadata.json) |
| Exact remote parent and W3C precedence | [basic](scenario-basic.json), [conflicting/invalid W3C](scenario-w3c.json), [matching W3C](scenario-w3c-match.json), and [sampled and unsampled OBI take outcomes](scenario-obi-flags.json) |
| Keepalive, pipelining, parallelism, churn, descriptor/port reuse, slow body, TLS receive boundaries, and retry | [keepalive](scenario-keepalive.json), [pipelining](scenario-pipelining.json), [concurrency](scenario-concurrency.json), [churn](scenario-connection-churn.json), [reuse](scenario-fd-port-reuse.json), [slow body](scenario-slow-body.json), [TLS boundary](scenario-tls-boundary.json), and [retry](scenario-timeout-retry.json) |
| Executor, virtual-thread, Netty-worker, inbound-Netty fixture, and redispatch handoff | [executor](scenario-handoff.json), [virtual thread](scenario-virtual-thread.json), [Netty worker](scenario-netty.json), [inbound Netty](scenario-netty-server.json), and [redispatch](scenario-dispatch.json) |
| Live map pressure, exact-parent accounting, cleanup, and recovery | [pressure status](scenario-pressure-status.json), [pressure traces](scenario-pressure.json), and [sanitized pressure summary](map-pressure-summary.json) |
| OBI restart, absence, late attach, helper failure, and recovery | [restart traffic](scenario-restart-fault.json), [restart events](restart-control/events.txt), [late-attach recovery](scenario-restart-late-attach-recovery.json), [helper failure](scenario-helper-attach-failure-helper-unavailable.json), and [helper recovery](scenario-basic-helper-attach-recovery.json) |
| Bridge/extension disabled and uninstrumented controls | [bridge disabled](scenario-disabled.json), [extension absent](scenario-w3c-only-extension-absent.json), [extension disabled](scenario-w3c-only-extension-disabled.json), and [uninstrumented](scenario-uninstrumented.json) |
| Same-cgroup and sibling primary-transport abuse controls with post-abuse recovery | [security status](scenario-security-status.json), [sanitized probe outcomes](security-primary-probes.json), [victim traffic](scenario-concurrency-security-primary-victim.json), and [recovery](scenario-basic-security-primary-recovery.json) |
| Low-cardinality diagnostics and duplicate suppression | Java and OBI phase deltas, [allowlisted suppression metric](duplicate-suppression.json), and every scenario status |

The inbound-Netty result is a bounded receive-to-extraction fixture. It does
not establish support for arbitrary Netty applications, frameworks, or
pre-extraction handoff surfaces.

Every retained scenario result contains synthetic traffic and the bounded trace
graph used by the assertion. Status records capture the runner exit and metric
assertion results; references to intentionally omitted stderr logs were
removed. No private keys, request bodies, credentials, baggage, tracestate, or
JVM-incarnation capability are retained. The only retained request-header
attribute is the synthetic `x-obi-demo-id` marker used to join each test request
to its trace graph.

The full runtime bundle contained bulk metric snapshots and unbounded
operational logs. They are intentionally omitted; the bounded restart event
sequence is the only transformed operational-log artifact retained. Retained
OBI metric files contain only bridge operation/status/transport labels and
per-phase deltas; absolute before/after values, map identifiers, and unrelated
host metrics are excluded. The retained Java diagnostic deltas and scenario
results are sufficient to reproduce the acceptance decisions. The original
source manifest is retained so its digest can be checked independently.
[SANITIZATION.md](SANITIZATION.md) enumerates the transformed and omitted
operational records. The checksum manifest authenticates the retained public
subset, not the omitted raw bundle.

## Integrity checks

From this directory:

    sha256sum -c SHA256SUMS

    test "$(sha256sum source-tree.manifest | cut -d' ' -f1)" = \
      72f6d2460015ac566b0febd4f130a966e665ff54b07ecbce26853272f1e3da76

    grep -Fx \
      'version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0' \
      java-selected-transport-configuration.txt

    jq -e -s '
      (length == 35) and
      (map(select(.status == "passed")) | length == 34) and
      (map(select(.status == "unsupported")) | length == 1) and
      (map(select(.status != "passed" and .status != "unsupported")) | length == 0)
    ' scenario-*-status.json

    jq -e '
      .distribution == "splunk" and
      .version == "2.28.0" and
      .sha256 == "70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351"
    ' official-javaagent.json

    jq -e '
      .status == "passed" and
      .request_count == 4 and
      (.cases | length == 4) and
      all(.cases[]; .response.backend_kind == "netty" and .response.tls_protocol == "TLSv1.3")
    ' scenario-netty-server.json

bpftool-feature-probe.txt records that an unprivileged host-side full feature
probe was unavailable. The privileged OBI container nevertheless loaded the
programs and completed the forced primary-transport assertions. This artifact
therefore does not establish compatibility with any other kernel.

## Unproven by this run

- forced Unix fallback, including its fault and abuse matrix;
- TLS 1.2;
- auto transport selection;
- RHEL kernels, the declared representative upstream kernels, hybrid or
  delegated cgroups, arm64, and JVM 8/11/17;
- transport microbenchmarks and sustained overhead gates.

Those cells remain untested in the companion matrices until their own clean,
full, retained evidence exists.
