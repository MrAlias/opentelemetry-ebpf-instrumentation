# Apache-to-Java HTTPS remote-parent demo

This example is a vendor-neutral, machine-verifiable proof of the OBI Java
remote-parent bridge. It runs this fixed topology on a Linux Docker host:

It is the executable evidence harness for
[issue #2](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/issues/2)
and its bridge architecture, implementation, integration, and validation
sub-issues.

```text
trace-scenario
    |
    | HTTP/1.1 :18080
    v
Apache HTTP Server 2.4 (mod_proxy_http + mod_ssl)
    |
    | verified HTTPS, TLS 1.2 or 1.3, HTTP/1.1 :18443
    v
embedded Jetty + official Java agent + external OBI extension

Apache OBI spans -------------------+
Java agent spans -------------------+--> local OTLP/HTTP receiver :14318
```

No vendor UI, account, access token, or proprietary backend is used. The
receiver keeps a bounded, sanitized trace graph and the scenario runner exits
nonzero unless the exact trace and parent span IDs are correct.

The receiver independently caps retained span count, each retained string,
and aggregate retained payload bytes. Any count, value, or aggregate-limit
drop is exposed in the snapshot and causes the corresponding assertion to
fail.

The checked-in result matrices are intentionally marked **untested**. They are
templates for evidence produced on the machine where the privileged eBPF tests
are actually run; the presence of this example does not claim those cells
passed.

## What the assertion proves

Each request has a random `x-obi-demo-id` marker. Both instrumenters capture
that one allowlisted header for correlation only. The assertion identifies
spans by marker, `service.name`, span kind, and endpoint; it never relies on
export order.

For an OBI-derived parent, it requires all of the following:

1. exactly one `java-backend` server span;
2. a nonzero Java parent span ID;
3. exactly one `apache-proxy` inbound server span;
4. exactly one `apache-proxy` client span whose span ID equals the Java parent
   and which descends from that inbound Apache span through only the retained
   in-process ancestry;
5. an exact trace ID match across that chain.

The pipelining stress is the only exception to item 3. Coalesced HTTP/1.1
requests are intentionally sent in one buffered write, while OBI can retain
only one in-flight inbound request per connection. The assertion therefore
accepts zero or one marker-correlated inbound Apache span. When that span is
absent, the Apache client span must be a root; when present, the normal ancestry
check still applies. Every marker must still have one exact Apache client to
Java remote-parent link, and multiple inbound candidates are rejected.

The pressure scenario is the only exception to item 2. After the complete
Apache candidate graph is present, it classifies each Java span as an exact hit
or an explicit root. A root must have a zero parent, no remote-parent bit, and a
trace distinct from the Apache candidate. Every nonzero parent must still match
the exact candidate. The result records each outcome and aggregate exact-hit,
explicit-root, wrong-parent, and unresolved counts. Exact hits plus explicit
roots must equal the request count, and wrong-parent and unresolved counts must
both be zero. Aggregate bridge metrics preserve the actual upstream and
retrieval failure reasons, while Java diagnostics account for valid retrievals,
roots, and the independent diagnostic self-probe. Transport-aware conservation
checks reconcile those layers without treating every root as a bridge
`take/missing` result.

All selected spans must have the scenario's exact endpoint and exact random
marker value in addition to the expected `service.name` and span kind. Prefix,
substring, wrong-route, and cross-request matches are rejected.

The W3C control supplies a known `traceparent` and requires the Java server span
to use its exact trace ID and parent span ID. A second request deliberately
supplies invalid W3C context and must fall through to the OBI parent. The
bridge-disabled and OBI-absent controls require the request to succeed with
exactly one Java root span. The uninstrumented control requires an equivalent
HTTP response and no marker-correlated spans. Concurrent, pipelined, and
fd/port-reuse requests also require distinct parents, so a stale or
cross-request lookup fails loudly.

The receiver retains the OTLP span flags. Every remote-parent assertion
requires both the `HAS_IS_REMOTE` and `IS_REMOTE` flag bits, in addition to the
exact exported trace and parent IDs.

The checked-in #28 matrix is explicit about which layer proves each case:

| Extraction case | Checked-in proof path | Remaining live gap |
| --- | --- | --- |
| no W3C and no OBI state | `fail-open`: OBI stopped, one Java root | privileged run |
| valid W3C only | `w3c-only`: OBI stopped, exact remote W3C parent | privileged run |
| valid OBI only | `basic`: exact Apache client parent | privileged run |
| matching W3C and OBI | `w3c-match`: controlled Unix bridge candidate plus an identical W3C header, exact Java parent, and one standard-parent discard | privileged run |
| conflicting valid W3C and OBI | `w3c`: exact W3C parent, distinct Apache candidate, one discard | privileged run |
| malformed W3C and valid OBI | `w3c`: exact Apache client parent, one take | privileged run |
| valid W3C and no OBI | `w3c-only` plus named Unix fault modes | privileged run |
| sampled and unsampled OBI flags | `obi-flags`: exact IDs, flags, and diagnostics | privileged run |
| repeated extraction | exact one-take/discard diagnostics per marked request | privileged run |
| nested/duplicate server instrumentation | repeated Jetty async redispatch, exactly one Java server span | privileged run |
| async/executor/Netty/virtual-thread handoff | dedicated exact-parent scenarios | privileged run |
| sequential keepalive, HTTP/1.1 pipelining, parallel connections, and fd/port reuse | dedicated exact-parent scenarios with connection evidence | privileged run |

Unit tests alone do not mark a stock-agent E2E row as passed. The Unix-only
fault control supplies bounded stale, malformed, timeout, disconnect,
overload, truncated, wrong-magic, wrong-size, version-mismatch, zero-trace-ID,
and zero-span-ID responses while valid W3C context remains authoritative.
The matching control uses the canonical sampled ABI vector as a bounded Unix
bridge fixture and supplies the same IDs in a real `traceparent` header. This
isolates extraction precedence without enabling generic payload header mutation
on the production Java TLS bridge path.

## Prerequisites

- Linux on `amd64` or `arm64`; Docker Desktop is not a supported eBPF host.
- Docker Engine with Compose v2 and permission to run privileged containers.
- A kernel supported by OBI (normally Linux 5.8+ with BTF, or a documented
  RHEL 8 backport).
- `bash`, `curl`, `git`, `openssl`, `sha256sum`, and GNU `timeout`.
- Free loopback ports `14318`, `18080`, and `18443`.
- Internet access for pinned container images, Maven dependencies, and the
  selected official Java agent.

OBI uses host PID and network namespaces, mounts cgroup, security, tracefs, and
debugfs read-only, and runs privileged. The tracing mounts let OBI resolve the
kernel tracepoints required by TCP context propagation. Review the Compose file
before granting those permissions.

Validate the non-privileged harness logic before a run:

```bash
./examples/apache-java-https/certs/generate_test.sh
./examples/apache-java-https/scripts/run_test.sh
go test ./examples/apache-java-https/tracecheck/...
docker compose \
  --project-name obi-apache-java-https \
  --file examples/apache-java-https/docker-compose.yml \
  config --quiet
```

## Reproducible inputs

`scripts/download-agent.sh` downloads exactly one unmodified agent from Maven
Central and verifies it before use:

| Distribution | Version | SHA-256 |
| --- | --- | --- |
| OpenTelemetry | 2.28.1 | `faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589` |
| Splunk | 2.28.0 | `70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351` |

Container base images are pinned by digest. The repository Java build exports
the separately reviewed `obi-java-agent.jar` helper and
`obi-otel-extension.jar` external extension. The helper is embedded into the
locally built OBI image and dynamically attached; it is not substituted for
the official OpenTelemetry or Splunk agent.

The test CA and private keys are generated at runtime under `.runtime/certs/`,
which is ignored by Git. The CA subject, server subject, serials, SANs, key
sizes, and validity are fixed, while private key material remains freshly
random. Apache requires that CA, checks certificate expiry, and verifies the
`localhost` hostname. Reuse requires a valid chain and expiry window, the exact
SAN set, matching certificate/private-key pairs, and a parseable PKCS#12 whose
leaf, CA, and private key match the PEM files. Runtime certificates are excluded
from both Docker build contexts, and each service mounts only the certificate
file it needs. Disabling verification is not a supported option.

`--skip-bridge-build` only reuses artifacts with intact checksum metadata whose
recorded revision and complete source-tree digest match the current checkout.
It does not create new metadata for unverified JARs, is rejected by the full
`all` suite, and marks targeted-run output as non-acceptance evidence.

## Run the complete suite

From the repository root:

```bash
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --agent otel \
  --tls TLSv1.3
```

The default `all` suite runs, in order:

- an exact OBI-derived parent check;
- bounded primary and fallback abuse controls that keep legitimate exact-parent
  traffic active, distinguish the same-cgroup attacker from a sibling
  container, reject a world-accessible Unix directory, and prove recovery;
- sequential requests over one reused backend connection;
- bodyless HTTP/1.1 requests written as one pipeline before any response read;
- parallel requests that force multiple backend connections;
- connection close/reopen churn;
- closed and reopened connections that reuse one frontend ephemeral port and
  require observed frontend and Jetty file-descriptor reuse across distinct
  stable Jetty connection IDs;
- 64 KiB request bodies paced in small writes, with monotonic backend counters
  requiring multiple decrypted Java receive callbacks per request;
- deterministic split and coalesced plaintext callback shapes in the opt-in
  Netty TLS fixture, reached from exact-parented Apache-to-Java requests and
  validated under the selected TLS 1.2 or TLS 1.3 backend protocol;
- a canceled request followed by a successful retry;
- order-independent handoff-claim LRU eviction under sustained concurrent
  pressure, with exact hits and explicit roots counted separately and
  reconciled across trace, bridge, and Java diagnostics;
- servlet async and executor handoff across varied hop counts, cancellation,
  rejection, and timeout paths;
- Java 21 virtual-thread migration, mixed execution, and cancellation paths;
- real Netty event-loop to platform-worker handoff, including canceled Netty
  work, while the successful request remains exact-parented;
- repeated real Jetty async redispatch with exactly one Java server span;
- valid W3C precedence and invalid-W3C fallback to OBI;
- a JVM started while OBI is absent, with root and valid-W3C behavior before
  late helper attach and exact-parent recovery without a JVM restart;
- valid-W3C traffic spanning an enforced OBI stop interval and restart,
  followed by an exact OBI-parent recovery check;
- a bridge-disabled JVM that still loads the official agent and extension;
- official-agent controls with the external extension absent and present but
  disabled;
- an uninstrumented JVM, with OBI stopped, whose HTTP response must match the
  instrumented control and whose marker must produce no spans.

Run the fallback transport and TLS version separately:

```bash
./examples/apache-java-https/run.sh --transport unix --tls TLSv1.2
```

The `tls-boundary` target runs both the split and coalesced cases. Run it once
per declared protocol when iterating on that boundary:

```bash
./examples/apache-java-https/run.sh --scenario tls-boundary --tls TLSv1.2
./examples/apache-java-https/run.sh --scenario tls-boundary --tls TLSv1.3
```

Exercise the Splunk distribution without changing the backend:

```bash
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --agent splunk \
  --tls TLSv1.3
```

The `auto` transport is available for feature-detection validation. Forced
`getsockopt` and `unix` runs are still required evidence because `auto` alone
does not prove both paths.

## Target one control

```bash
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario concurrency

./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario pipelining

./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario fd-port-reuse

./examples/apache-java-https/run.sh \
  --transport disabled \
  --scenario disabled

./examples/apache-java-https/run.sh \
  --transport disabled \
  --scenario uninstrumented

./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario w3c-only
```

Use `--keep` to inspect a successful or failed stack. Stop only this Compose
project afterward:

```bash
./examples/apache-java-https/run.sh --cleanup-only
```

The project name is reserved to `obi-apache-java-https` and names with a
lowercase suffix such as `obi-apache-java-https-ci1`. Every demo container,
volume, and network carries an ownership sentinel. Startup and cleanup
enumerate all resources with the selected Compose project label and refuse to
continue if any resource lacks that sentinel. Cleanup never removes images,
unrelated containers, or retained result directories.

## Startup gates

Before traffic begins, the orchestrator uses bounded waits for:

- the local OTLP receiver health endpoint;
- OBI log `Java remote parent bridge ready`;
- helper log `OBI remote-parent provider ready`;
- extension log `OBI remote-parent propagator enabled`;
- injected-instrumentation log `OBI Java instrumentation ready`;
- Apache's `/healthz` request through the verified HTTPS Jetty path, with the
  backend connection closed before measured traffic begins.

The bridge-disabled control skips OBI/helper bridge readiness but still
requires external-extension and injected-instrumentation readiness. The
late-attach control requires the official agent and extension to remain healthy
while OBI is absent, then waits for provider and injected-instrumentation
readiness after OBI starts. It preserves the JVM and recycles only Apache so no
pre-attach backend TLS connection enters the recovery scenario. Separate
controls run with the extension absent and disabled. The uninstrumented control
requires that the official agent, extension, and OBI are absent. Every build,
Compose operation, HTTP request, and trace wait has a deadline.

## Configuration contract

OBI accepts these environment overrides (the YAML equivalents are in
`configs/obi.yaml`):

| Setting | Value in this demo |
| --- | --- |
| `OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP` | `true` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT` | `disabled`, `auto`, `getsockopt`, or `unix` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_PATH` | `/var/run/obi/java-remote-parent.sock` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_GROUP_ID` | `0` (the demo JVM runs as root) |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT` | `50ms` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TTL` | `30s` |

The official agent loads the external extension with
`OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar`. The propagator order
is `obi,tracecontext,baggage`, and the explicit opt-in is
`OTEL_OBI_REMOTE_PARENT_ENABLED=true`. The equivalent system properties are
`otel.javaagent.extensions`, `otel.propagators`, and
`otel.obi.remote.parent.enabled`. Valid W3C context therefore wins and the OBI
candidate is discarded; invalid W3C context falls through to OBI. The opt-in
is disabled when unset or empty and otherwise accepts only case-insensitive
`true` or `false`; another value fails open by disabling OBI extraction and
logs one fixed warning without echoing the value. The bridge-disabled control
keeps the official agent and extension enabled while disabling only the OBI
transport. The uninstrumented control removes the agent and stops OBI.

OBI context propagation is `tcp`, not `headers` or `all`. That prevents OBI
HTTP header injection from hiding whether the Java bridge works. The fixture
also disables legacy black-box correlation so unrelated loopback connections
cannot be joined when an ephemeral source port is reused. Exact incoming TCP
candidates are consumed before that fallback is gated, so the Java bridge
remains enabled.

## Evidence

Every run retains a timestamped directory under `.runtime/results/` with:

- repository revision, dirty status, tracked-patch digest, complete source
  manifest, source-tree digest, and patch identity;
- kernel, architecture, cgroup/BTF state, `bpftool` feature/program/map output
  (including command status when unavailable), Docker, Compose, Apache TLS
  module state, `mod_ssl` library dependencies, OpenSSL package ownership,
  mode, and TLS version;
- resolved Compose configuration and running container topology;
- container image IDs, configured image references, available repository
  digests, and Apache/JVM version output;
- official and local artifact SHA-256 and source-provenance metadata;
- CA and server certificate fingerprints and validity;
- one JSON trace graph and assertion result per scenario, plus retained
  assertion stderr;
- machine-readable connection evidence for pipeline depth, writes completed
  before the first response read, stable Jetty connection IDs, fixed frontend
  ephemeral-port reuse, and frontend/backend descriptor reuse;
- before/after OBI metrics, Java bridge diagnostics, scoped container
  CPU/memory/PID samples, process RSS/thread/fd counts, and reason-coded metric
  deltas for every scenario repetition;
- live pressure-helper output naming the exact BPF map ID, capacity, non-secret
  JVM PID/namespace identity, complete fill count, and scanned eviction count;
  a read-only preparation record retained before mutation; once-per-second
  above-prefill-baseline monitoring through an independently counted aggregate
  TCP-inject outcome boundary and its terminal metric sample; exact per-request
  and aggregate parent outcomes with zero wrong or unresolved parents; actual
  reason-coded upstream and retrieval failures; and transport-aware aggregate
  reconciliation with Java diagnostics;
  synthetic-key cleanup verification; and both samples from the final
  steady-recovery gate, with canonical cleanup/recovery evidence promoted only
  when the complete gate passes;
- per-mode runtime assertions for the official-agent/extension/OBI topology
  and the Java-service duplicate-suppression metric; after each OBI
  create/restart, a non-measured health request drives behavioral detection
  and asserted traffic starts only after the new process reports suppression;
- final receiver snapshot, Compose state, and component logs.

Build and startup output is streamed to the terminal and retained in
`bridge-build.log` and `compose-up.log`. A failed run also records the exact
failure stage, source line, exit status, and shell-escaped command in
`failure-context.txt`; `run-status.json` repeats the stage and line for
machine-readable triage.

Only a generated marker header is captured. The receiver rejects compressed or
oversized requests, enforces configured count, per-string, and aggregate
retained-byte ceilings, and strips arbitrary headers and bodies before writing
evidence. Any receiver eviction or rejection is reason-coded and invalidates
the scenario. For ordinary scenarios, Java diagnostics are fetched after each
post-scenario OBI metric snapshot. Their delta requires exactly one
self-observed missing lookup, so the diagnostic request cannot mask another
missing lookup in the reason-coded interval attributed to that scenario. A
fault-injection request instead opts in to the same fixed snapshot on its
response after Java extraction. The runner captures its baseline from the
existing pre-control health request, validates the exact bounded schema, and
chains response-to-response deltas while the fault suite remains serial. This
avoids an extra bridge take and requires exactly the normalized Java status for
each injected mode with no unexpected retrieval result. The restart-fault
interval also includes the headerless readiness request used to re-establish
duplicate suppression, so it requires exactly two non-workload takes and
reports conservative workload attribution bounds.

A dirty source tree, `--skip-bridge-build`, or an individually targeted
scenario is explicitly labeled non-acceptance evidence. Only a clean full
`all` run is eligible to populate the result matrices.

## Diagnostics

For an early failure, inspect `failure-context.txt`, then `bridge-build.log` or
`compose-up.log` for the named stage. If readiness fails after startup, inspect
the retained `compose.log` in this order:

1. `trace-receiver` must listen on `127.0.0.1:14318`.
2. Jetty must report HTTP/1.1 and the selected TLS protocol.
3. Apache must load `mod_ssl` and verify the generated CA and hostname.
4. OBI must discover ports `18080` and `18443`, then report its selected
   remote-parent transport.
5. The JVM must report provider, extension, and injected-instrumentation
   readiness messages.
6. A failed scenario JSON shows sanitized span graphs from the latest polling
   pass. A marker whose fetch fails or completes after the polling deadline has
   an empty graph instead of reusing an older graph; pressure evidence
   classifies it as unresolved. A fetched assertion failure retains its exact
   unmatched trace/parent boundary.

For `unix`, verify that the scoped `java-remote-parent-socket` volume is owned
by `root:root`, has mode `0750`, and is mounted by both OBI and Java at
`/var/run/obi`. The one-shot `socket-init` service establishes those
permissions before either service starts. For `getsockopt`, confirm the kernel
reports support rather than silently accepting fallback; a forced mode must
not change transport.

## Explicit limitations

- Backend HTTP/2 is unsupported and not exercised. The Jetty connector and
  Apache proxy protocol are deliberately HTTP/1.1-only.
- Pipelining is exercised only on the plaintext HTTP/1.1 client-to-Apache hop.
  The scenario writes every request before reading a response and fails unless
  every response and exact parent is returned.
- The final serial request, and every parallel request, sends `Connection:
  close` and asks the backend to close its response. This preserves earlier
  backend reuse while giving OBI a TCP close boundary that finishes delayed TLS
  spans before trace assertions.
- Readiness and metric-boundary health probes also ask Jetty to close the
  backend connection, preventing probe state from entering a measured scenario.
- The slow-body control proves that each measured request after the baseline
  crosses at least two decrypted Java receive callbacks and that those
  callbacks account for at least the full 64 KiB body. It does not infer exact
  Apache/OpenSSL TLS record boundaries from the client-side write pattern.
- The helper carries accepted-socket ownership through exact executor,
  ForkJoin, Netty-worker, and virtual-thread task contexts. Packaged-agent tests
  cover nested hops, cancellation, worker reuse, and Java 21 carrier migration.
  The Compose servlet scenarios still begin after stock server extraction, so
  a retained privileged run is required before claiming a specific framework's
  receive-to-pre-extraction path.
- The fd/port-reuse scenario is Linux-only. It reuses one client ephemeral port
  across closed frontend connections and asks the demo backend to resolve its
  accepted socket descriptor from `/proc/self`. A synchronized weak-key map
  assigns a monotonic opaque ID to each Jetty connection object. Connection
  reuse and churn are proved with those IDs; ports remain diagnostics only.
  The scenario fails unless frontend descriptor reuse and Jetty descriptor
  reuse across distinct connection IDs are both observed.
- This is a privileged PoC, not a production deployment manifest.
- The Compose acceptance backend is pinned to Java 21; the Java 8, 11, 17, and
  21 extension compatibility checks run in the Java CI matrix.
- Compatibility and performance claims require executing and attaching the
  evidence described in the companion matrices.

See [ADR.md](ADR.md), [COMPATIBILITY.md](COMPATIBILITY.md),
[BENCHMARK.md](BENCHMARK.md), [SECURITY.md](SECURITY.md), and
[FINAL-RESULT.md](FINAL-RESULT.md) for the decision record and evidence
templates.
