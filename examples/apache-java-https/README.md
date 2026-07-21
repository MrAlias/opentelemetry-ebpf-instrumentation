# Apache-to-Java HTTPS remote-parent demo

This example is a vendor-neutral, machine-verifiable proof of the OBI Java
remote-parent bridge. It runs this fixed topology on a Linux Docker host:

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
   and whose parent is that inbound Apache span;
5. an exact trace ID match across that chain.

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
| matching W3C and OBI | `w3c-match`: isolated header+TCP injection with exact candidate IDs | privileged run |
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

## Prerequisites

- Linux on `amd64` or `arm64`; Docker Desktop is not a supported eBPF host.
- Docker Engine with Compose v2 and permission to run privileged containers.
- A kernel supported by OBI (normally Linux 5.8+ with BTF, or a documented
  RHEL 8 backport).
- `bash`, `curl`, `git`, `openssl`, `sha256sum`, and GNU `timeout`.
- Free loopback ports `14318`, `18080`, and `18443`.
- Internet access for pinned container images, Maven dependencies, and the
  selected official Java agent.

OBI uses host PID and network namespaces, mounts cgroup and security filesystems
read-only, and runs privileged. Review the Compose file before granting those
permissions.

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
- sequential requests over one reused backend connection;
- bodyless HTTP/1.1 requests written as one pipeline before any response read;
- parallel requests that force multiple backend connections;
- connection close/reopen churn;
- closed and reopened connections that reuse one frontend ephemeral port and
  require observed frontend and Jetty file-descriptor reuse across distinct
  stable Jetty connection IDs;
- request bodies paced in small writes on the client-to-Apache hop;
- a canceled request followed by a successful retry;
- live handoff-claim LRU saturation and eviction during concurrent traffic;
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
- Apache's `/healthz` request through the verified HTTPS Jetty path;
- OBI log `Java remote parent bridge ready`;
- helper log `OBI remote-parent provider ready`;
- extension log `OBI remote-parent propagator enabled`.

The bridge-disabled control skips OBI/helper bridge readiness but still
requires the official agent and external-extension readiness. The
late-attach control requires the official agent and extension to remain healthy
while OBI is absent, then waits for helper readiness after OBI starts. Separate
controls run with the extension absent and disabled. The uninstrumented control
requires that the official agent, extension, and OBI are absent. Every build,
Compose operation, HTTP request, and trace wait has a deadline.

## Configuration contract

OBI accepts these environment overrides (the YAML equivalents are in
`configs/obi.yaml`):

| Setting | Value in this demo |
| --- | --- |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT` | `disabled`, `auto`, `getsockopt`, or `unix` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_PATH` | `/var/run/obi/java-remote-parent.sock` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_GROUP_ID` | `0` (the demo JVM runs as root) |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT` | `50ms` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TTL` | `30s` |

The official agent loads the external extension with
`OTEL_JAVAAGENT_EXTENSIONS=/otel/obi-otel-extension.jar`. The propagator order
is `obi,tracecontext,baggage`, and the explicit opt-in is
`OTEL_OBI_REMOTE_PARENT_ENABLED=true`. Valid W3C context therefore wins and the
OBI candidate is discarded; invalid W3C context falls through to OBI. The
bridge-disabled control keeps the official agent and extension enabled while
disabling only the OBI transport. The uninstrumented control removes the agent
and stops OBI.

OBI context propagation is `tcp`, not `headers` or `all`. That prevents OBI
HTTP header injection from hiding whether the Java bridge works.

## Evidence

Every run retains a timestamped directory under `.runtime/results/` with:

- repository revision, dirty status, tracked-patch digest, complete source
  manifest, source-tree digest, and patch identity;
- kernel, architecture, cgroup/BTF state, `bpftool` feature/program/map output
  (including command status when unavailable), Docker, Compose, OpenSSL, mode,
  and TLS version;
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
- live pressure-helper output naming the exact BPF map ID, capacity, and
  non-secret JVM PID/namespace identity, plus once-per-second full-occupancy
  monitoring throughout traffic and saturated/recovered samples;
- per-mode runtime assertions for the official-agent/extension/OBI topology
  and the Java-service duplicate-suppression metric;
- final receiver snapshot, Compose state, and component logs.

Only a generated marker header is captured. The receiver rejects compressed or
oversized requests, enforces configured count, per-string, and aggregate
retained-byte ceilings, and strips arbitrary headers and bodies before writing
evidence. Any receiver eviction or rejection is reason-coded and invalidates
the scenario. Java diagnostics are fetched only after each post-scenario OBI
metric snapshot and delta, so the diagnostic request cannot change the
reason-coded interval attributed to that scenario.

A dirty source tree, `--skip-bridge-build`, or an individually targeted
scenario is explicitly labeled non-acceptance evidence. Only a clean full
`all` run is eligible to populate the result matrices.

## Diagnostics

If readiness fails, inspect the retained `compose.log` in this order:

1. `trace-receiver` must listen on `127.0.0.1:14318`.
2. Jetty must report HTTP/1.1 and the selected TLS protocol.
3. Apache must load `mod_ssl` and verify the generated CA and hostname.
4. OBI must discover ports `18080` and `18443`, then report its selected
   remote-parent transport.
5. The JVM must report both helper and extension readiness messages.
6. A failed scenario JSON shows the last sanitized span graph, including the
   exact unmatched trace/parent boundary.

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
- The slow-body control paces writes only on the client-to-Apache hop. It does
  not prove how Apache/OpenSSL segments plaintext into backend TLS records or
  how many Java receive callbacks observe that plaintext.
- Servlet, executor, Netty-worker, and virtual-thread scenarios begin after the
  stock server instrumentation has extracted the parent. They validate
  post-extraction ownership cleanup and reuse, not an unproven
  receive-to-pre-extraction framework handoff.
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
