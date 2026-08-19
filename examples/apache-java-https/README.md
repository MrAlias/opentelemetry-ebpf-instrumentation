# Apache-to-Java HTTPS remote-parent demo

This example is a vendor-neutral, machine-verifiable proof of the OBI Java
remote-parent bridge. It runs this fixed topology on a Linux Docker host:

It is the executable evidence harness for
[issue #2](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/issues/2)
and its bridge architecture, implementation, integration, and validation
sub-issues. The [compatibility matrix](COMPATIBILITY.md) limits support claims
to directly observed cells. The [final result](FINAL-RESULT.md) reconciles the
parent tracker's definition of done against that same retained evidence
boundary.

Matrix revision: `apache-java-https-compatibility-v2`.
<!-- obi-compatibility-matrix-revision: apache-java-https-compatibility-v2 -->

```text
trace-scenario
    |
    | HTTP/1.1 :18080
    v
Apache HTTP Server 2.4 (mod_proxy_http + mod_ssl)
    |\
    | \-- ordinary routes:
    |     verified HTTPS, TLS 1.2 or 1.3, HTTP/1.1 :18443
    |     --> embedded Jetty
    |\
    | \-- /api/netty-server:
    |     verified HTTPS, TLS 1.2 or 1.3, HTTP/1.1 :18444
    |     --> inbound Netty fixture
    |\
    | \-- /api/tls-boundary/split and /api/tls-boundary/coalesced:
    |     verified HTTPS, TLS 1.2 or 1.3, HTTP/1.1 :18445/:18446
    |     --> dedicated Netty boundary listeners
    |
    \---- /api/coalesced-source:
          loopback HTTP/1.1 :18081 --> instrumented Go source
          --> verified TLS 1.2 or 1.3, HTTP/1.1 :18444
          --> inbound Netty fixture

Java backend process + official Java agent + external OBI extension
Go coalesced source + OBI instrumentation

Apache OBI spans -------------------+
Java agent spans -------------------+--> local OTLP/HTTP receiver :14318
OBI internal metrics ------------------> loopback Prometheus :18990
```

No vendor UI, account, access token, or proprietary backend is used. The
receiver keeps a bounded, sanitized trace graph and the scenario runner exits
nonzero unless the exact trace and parent span IDs are correct.

The receiver independently caps retained span count, each retained string,
and aggregate retained payload bytes. Any count, value, or aggregate-limit
drop is exposed in the snapshot and causes the corresponding assertion to
fail.

Checked-in result matrices mark only linked retained evidence as passed; every
other cell remains **untested**. The presence of this example does not claim
that an unlinked cell passed.

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

| Extraction case | Checked-in proof path | Retained evidence or remaining boundary |
| --- | --- | --- |
| no W3C and no OBI state | `fail-open`: OBI stopped, one Java root | [current primary acceptance](evidence/otel-getsockopt-tls13-e8db066a/scenario-fail-open-obi-absent.json) |
| valid W3C only | `w3c-only`: OBI stopped, exact remote W3C parent | [current primary acceptance](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-only-obi-absent.json) |
| valid OBI only | `basic`: exact Apache client parent | [current primary acceptance](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic.json) |
| matching W3C and OBI | `w3c-match`: controlled bridge candidate plus an identical W3C header, exact Java parent, and one standard-parent discard assertion | [graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-match.json) and [passing status](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-match-status.json); ordinary phase values are omitted |
| conflicting valid W3C and OBI | `w3c`: exact W3C parent, distinct Apache candidate, and one discard assertion | [graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c.json) and [passing status](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-status.json); ordinary phase values are omitted |
| malformed W3C and valid OBI | `w3c`: exact Apache client parent and one take assertion | [graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c.json) and [passing status](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-status.json); ordinary phase values are omitted |
| valid W3C and no OBI | `w3c-only` plus named Unix fault modes | [primary](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-only-obi-absent.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) acceptance |
| valid W3C and stale primary state | `primary-w3c-stale`: forced `getsockopt` retrieval TTL of `1ns`, exact W3C parent, one workload stale bridge take with an in-band terminal diagnostics snapshot, then normal-TTL recovery | [current primary acceptance](evidence/otel-getsockopt-tls13-e8db066a/scenario-primary-w3c-stale.json) |
| valid W3C and malformed primary response | `primary-w3c-fault`: version, declared-size, zero-trace-ID, and zero-span-ID responses, exact W3C parent, then normal recovery | [current primary acceptance](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |
| valid W3C and stale Unix state | `unix-w3c-stale`: forced `unix` retrieval TTL of `1ns`, exact W3C parent, one workload stale bridge take with an in-band terminal diagnostics snapshot, then normal-TTL recovery | [current Unix acceptance](evidence/otel-unix-tls13-6c4a2505/README.md#retained-proof) |
| sampled and unsampled OBI flags | `obi-flags`: exact IDs and flags plus counter/diagnostic assertions | [graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-obi-flags.json) and [passing assertion status](evidence/otel-getsockopt-tls13-e8db066a/scenario-obi-flags-status.json); ordinary phase values are omitted |
| repeated extraction | `OfficialAgentJettyRuntimeTest` drives the registered stock-agent extraction chain at least twice for one request and requires one `VALID` take followed by `ALREADY_CONSUMED` | The [retained official-agent runtime matrix](focused-validation/official-agent-runtime-9b66f39e/README.md) passed with pinned, checksum-verified OpenTelemetry 2.28.1 and Splunk 2.28.0 agents |
| nested/duplicate server instrumentation | `OfficialAgentJettyRuntimeTest` activates stock Jetty and Servlet server advice, compares a Servlet-disabled control, and requires exactly one exported Jetty server span | The [retained official-agent runtime matrix](focused-validation/official-agent-runtime-9b66f39e/README.md) passed across Java 8, 11, 17, and 21; Jetty 11 is explicitly unsupported on Java 8 and passes on 11, 17, and 21 |
| async/executor/Netty/virtual-thread handoff | dedicated exact-parent application scenarios plus stock-agent Jetty depth-64, ancestor-cycle, late-framework, Netty relay/cleanup, and Java 21 carrier-reuse controls | [current primary acceptance](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) and the [retained official-agent runtime matrix](focused-validation/official-agent-runtime-9b66f39e/README.md); broader framework/environment expansion remains tracked by #38 |
| inbound Netty receive-to-extraction | `netty-server`: Apache-to-inbound-Netty HTTPS with exact remote parent | [bounded fixture passed](evidence/otel-getsockopt-tls13-e8db066a/scenario-netty-server.json); arbitrary Netty frameworks or applications remain unproven |
| sequential keepalive, HTTP/1.1 pipelining, parallel connections, and fd/port reuse | dedicated exact-parent scenarios with connection evidence | [current primary acceptance](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) |

Unit tests alone do not mark a stock-agent E2E row as passed. The Unix-only
fault control supplies bounded stale, malformed, timeout, disconnect,
overload, truncated, wrong-magic, wrong-size, version-mismatch, zero-trace-ID,
and zero-span-ID responses while valid W3C context remains authoritative.
The matching control uses the canonical sampled ABI vector as a bounded Unix
bridge fixture and supplies the same IDs in a real `traceparent` header. This
isolates extraction precedence without enabling generic payload header mutation
on the production Java TLS bridge path.

The primary `primary-w3c-stale` control force-recreates OBI with a `1ns`
retrieval TTL while retaining the normal `30s` Apache prewrite and cleanup TTL.
It verifies a healthy Apache request whose exact W3C parent wins after the
primary stale retrieval, then restores the normal retrieval setting before
proving a normal bridge recovery. It is an executable source control. The current
[primary acceptance bundle](evidence/otel-getsockopt-tls13-e8db066a/README.md)
retains that execution, so the exact primary cell is no longer source-only.
The control does not synthesize a malformed primary
record. The Unix `unix-w3c-stale` control follows the same TTL and recovery
sequence through the real OBI Unix handler, not the synthetic `w3c-fault`
responder. The current
[Unix acceptance bundle](evidence/otel-unix-tls13-6c4a2505/README.md) retains
that execution. Both stale controls capture their baseline on the existing
bridge-boundary health request and their terminal diagnostics on the marked
workload response, avoiding a separate diagnostics request with its own lookup.
The separate `primary-w3c-fault` control uses a private one-shot
response shim to exercise declared-size and zero-ID malformed primary replies,
plus ABI-version mismatch, while the supplied W3C parent remains authoritative.
The [current primary acceptance bundle](evidence/otel-getsockopt-tls13-e8db066a/README.md)
retains all four one-shot response modes and normal recovery.

## Prerequisites

- Linux on `amd64` or `arm64`; Docker Desktop is not a supported eBPF host.
- Docker Engine with Compose v2 and permission to run privileged containers.
- A kernel supported by OBI (normally Linux 5.8+ with BTF, or a documented
  RHEL 8 backport).
- Go 1.25.11 (for the repository and tracecheck tests).
- `bash`, `cmp`, `curl`, `flock`, `git`, `jq`, `openssl`, `sha256sum`, and GNU
  `timeout`.
- Free loopback ports `14318`, `18080`, `18081`, `18443`, `18444`, `18445`,
  `18446`, and `18990`.
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

## Clean-host bootstrap

Start from a clean checkout of the exact revision being evaluated. For example:

```bash
git clone https://github.com/MrAlias/opentelemetry-ebpf-instrumentation.git
cd opentelemetry-ebpf-instrumentation
git checkout <recorded-revision>
git status --porcelain
./examples/apache-java-https/certs/generate_test.sh
./examples/apache-java-https/scripts/run_test.sh
go test ./examples/apache-java-https/tracecheck/...
git status --porcelain
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --agent otel \
  --tls TLSv1.3
```

The final `git status --porcelain` before the acceptance command must be
empty. `run.sh` builds the bridge artifacts from that checkout: it invokes
`docker build --file javaagent.Dockerfile --target export` and records the
resulting helper and external-extension checksums with the run. Do not replace
those artifacts manually. `--skip-bridge-build` is only for checksum-verified,
targeted local iteration and is never acceptance evidence.

### Push-only retained-acceptance campaign

The [clean-host acceptance workflow](../../.github/workflows/java_remote_parent_acceptance_claims.yml)
runs only for pushes to `agent/java-remote-parent-bridge`. It rechecks the exact
push event, workflow revision, tracked execution bytes, and clean authority
checkout before using the local disk-reclamation action. The private campaign
then clones and checks out that same revision, runs the four validation commands
above, executes the exact OpenTelemetry/`getsockopt`/TLS 1.3 acceptance command,
requires the deliberate assertion control to exit `2`, performs scoped cleanup,
and proves a final clean checkout. Every command's exact combined output digest,
exit status, and duration is sealed into an owner-private canonical receipt.

Raw run directories, command logs, and that receipt are never artifacts. The
projector validates them in its private transaction, emits only `README.md`,
`SANITIZATION.md`, `acceptance-claims.json`, `authority-summary.json`,
`derivation-receipt.json`, `verify.sh`, and `SHA256SUMS`, and destroys the raw
transaction before the campaign re-verifies the public bundle. A separate
workflow step runs the bundled verifier from `/`; an always-run privacy guard
must also prove that no private residue or ambiguous public candidate remains
before those seven individual files can be uploaded. The projection contains
bounded derived claims and an internal-consistency check, not raw evidence or an
authentication claim. Until a source-revision-matched workflow artifact passes
all three gates, existing untested rows remain untested.

### Exact component build mapping

The clean-host `run.sh` command above is the canonical build command. It builds
from a private snapshot of the recorded source tree, copies the two exported
JARs into the scoped runtime artifact directory, records their checksums, and
then runs Compose with `--build`. The underlying build boundaries are:

| Requested component | Exact build boundary and output |
| --- | --- |
| OBI | The `obi` service in `docker-compose.yml` builds the repository-root `Dockerfile` with `RELEASE_VERSION=apache-java-https-demo` and `RELEASE_REVISION=local`. |
| JNI library | The `jni-builder` stage in `javaagent.Dockerfile` runs `make -f Makefile.jni` for both `linux-amd64` and `linux-aarch64`, producing `libobijni.so` files that are embedded in the helper JAR. |
| dynamically attached helper | The `export` stage in `javaagent.Dockerfile` exports `obi-java-agent.jar`. |
| Java-agent extension | The same `export` stage exports the separately loaded `obi-otel-extension.jar`. |

For a non-acceptance inspection build from the repository root, these are the
exact standalone commands represented by those two runner boundaries:

```bash
(
  set -Eeuo pipefail
  bridge_export="$(mktemp -d)"
  trap 'rm -rf -- "$bridge_export"' EXIT
  docker build \
    --file javaagent.Dockerfile \
    --target export \
    --output "type=local,dest=$bridge_export" \
    .
  sha256sum \
    "$bridge_export/obi-java-agent.jar" \
    "$bridge_export/obi-otel-extension.jar"
)

docker compose \
  --project-name obi-apache-java-https \
  --project-directory examples/apache-java-https \
  --file examples/apache-java-https/docker-compose.yml \
  build obi
```

These standalone commands do not create acceptance evidence. Acceptance still
requires the clean `run.sh` invocation, which binds the source snapshot, build
logs, checksums, resolved Compose model, runtime assertions, and cleanup into
one result.

## Reproducible inputs

`scripts/download-agent.sh` downloads exactly one unmodified agent from Maven
Central and verifies it before use:

| Distribution | Version | SHA-256 |
| --- | --- | --- |
| OpenTelemetry | 2.28.1 | `faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589` |
| Splunk | 2.28.0 | `70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351` |

The [retained stock-agent CI record](focused-validation/official-agent-runtime-9b66f39e/README.md)
binds these pins to source revision
`9b66f39eb0e5897b6b27d999e461267dfa85fd70`, four Linux `X64`/`x86_64`
Java 8/11/17/21 cells, exact JUnit totals, and the raw GitHub artifact archive
digests. It closes issue #27's declared stock-agent compatibility range when
read with the existing Java 21 privileged Compose cells. It does not mark Java
8, 11, or 17 as privileged Compose passes, establish `arm64`, or close the
broader issue #23 or issue #38 matrices.

The retained [diagnostic nondisclosure matrix](focused-validation/diagnostic-nondisclosure-f8775328d54a-6a2fe52aac6eab28/README.md)
records exact revision `f8775328d54a7c0e45c3117539f5b99946601b1a`,
source-configured Temurin Java 21, TLS 1.3, and checksum-verified OpenTelemetry
2.28.1 and Splunk 2.28.0 agents across forced `getsockopt` and Unix transports
at INFO and DEBUG: eight cells in total. For each cell, the verifier checked the
Java diagnostic endpoint, response header, selected-transport configuration,
OBI metrics, complete bounded OBI log, and complete bounded Java log. It
reconstructed the request, context, and credential canaries from pinned source
and W3C evidence and found zero matches; the six raw surfaces remain private.

The `obi_java_remote_parent_operations_total` label contract permits four
transports × eleven operations × eighteen statuses, or at most 792 distinct
label tuples. The exact
`obi_instrumentation_errors_total{error_type="attaching_java_agent",process_name="java"}`
tuple is projected separately as one fixed scalar and is not part of that 792
bound. This summary-only `focused_non_acceptance` record closes issue #39; it
does not populate the full acceptance or compatibility matrix, expand issue #38,
or close issue #40.

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
  container, reject a world-accessible Unix directory, attempt a root
  same-cgroup `pidfd_getfd` duplication of a live accepted Java descriptor,
  and prove recovery;
- sequential requests over one reused backend connection;
- bodyless HTTP/1.1 requests written as one pipeline before any response read;
- parallel requests that force multiple backend connections and enter one
  bounded Jetty worker barrier; every response reports a worker identity,
  common release generation, participant count, and maximum overlap, and the
  control requires more than one backend worker and connection;
- connection close/reopen churn;
- closed and reopened connections that reuse one frontend ephemeral port and
  require observed frontend and Jetty file-descriptor reuse across distinct
  stable Jetty connection IDs;
- 64 KiB request bodies paced in small writes, with monotonic backend counters
  requiring multiple decrypted Java receive callbacks per request;
- deterministic split and coalesced TLS application-data record counts and
  matching plaintext callback shapes in the opt-in Netty TLS fixture, reached
  from exact-parented Apache-to-Java requests and validated under the selected
  TLS 1.2 or TLS 1.3 backend protocol; the bounded wire observer retains only
  application-data type, legacy-version, length, and count metadata, never
  record contents;
- a separate live coalesced-parent control, triggered through Apache, whose
  instrumented Go source performs one bounded plaintext write containing two
  HTTP/1.1 request boundaries on one TLS connection to the real Netty receive
  path;
- a canceled request followed by a successful retry; the canceled marker is
  retained and boundedly classified as exact, absent, or one fixed
  reason-coded root, while any wrong parent fails the run;
- non-evicting handoff-claim capacity rejection under sustained concurrent
  pressure, with every admitted synthetic ticket verified present and exact
  hits and explicit roots reconciled across trace, bridge, and Java diagnostics;
- servlet async and executor handoff across varied hop counts, cancellation,
  rejection, and timeout paths;
- Java 21 virtual-thread migration, mixed execution, and cancellation paths;
- real Netty event-loop to platform-worker handoff, including canceled Netty
  work, while the successful request remains exact-parented;
- inbound Netty HTTPS server extraction through the Apache `/api/netty-server`
  route, with a separate exact-parent assertion for each request;
- repeated real Jetty async redispatch with exactly one Java server span;
- valid W3C precedence and invalid-W3C fallback to OBI;
- forced-primary stale (`primary-w3c-stale`), generation-mismatch
  (`primary-generation-mismatch`), and ABI-version/declared-size/zero-ID
  (`primary-w3c-fault`) fail-open controls, or the transport-applicable
  forced-Unix stale (`unix-w3c-stale`), generation-mismatch
  (`unix-generation-mismatch`), and responder-fault (`w3c-fault`) controls;
  controls for the other forced transport are retained as `unsupported`, never
  as passes;
- one complete JVM lifetime with OBI permanently absent (`permanent-absence`),
  followed by a fresh JVM and exact-parent recovery;
- when `--transport auto` is selected, one JVM lifetime with both primary and
  Unix retrieval unavailable (`auto-unavailable`), followed by recovery;
  forced-primary and forced-Unix runs retain that mode-specific control as
  `unsupported`;
- a JVM started while OBI is absent, with root and valid-W3C behavior before
  late helper attach and exact-parent recovery without a JVM restart;
- valid-W3C traffic spanning an enforced OBI stop interval and restart,
  followed by an exact OBI-parent recovery check;
- a bridge-disabled JVM that still loads the official agent and extension;
- official-agent controls with the external extension absent and present but
  disabled;
- an uninstrumented JVM, with OBI stopped, whose HTTP response must match the
  instrumented control and whose marker must produce no spans.

The genuine PID-reuse allocator control is deliberately targeted and is not
part of `all`. Start it only with a fresh scoped Compose project:

```bash
./examples/apache-java-https/run.sh --cleanup-only
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario pid-reuse
```

It runs the PID-namespace allocator/controller before Java backend readiness,
then runs only the recovered `basic` exact-parent assertion. Because it is an
individually targeted scenario, its result is always labeled non-acceptance
evidence and cannot promote a compatibility or final-result cell.

Run the fallback transport and TLS version separately:

```bash
./examples/apache-java-https/run.sh --transport unix --tls TLSv1.2
```

The `tls-boundary` target sends three fixed 32 KiB POST requests through Apache
to dedicated Netty HTTPS listeners: one isolated split request, followed by two
sequential requests on one frontend keep-alive connection and one reused
Apache-to-Netty TLS connection. Three bounded padding headers make each actual
backend header block exceed the TLS 16 KiB plaintext-record limit, so Java
cannot emit that HTTP request to the server instrumentation until at least two
post-handshake TLS records and decrypted callbacks have arrived. The split case
forwards each natural callback unchanged to the HTTP parser. The fixture raises
OBI's bounded HTTP capture buffer to 32 KiB so the deliberate 18 KiB header,
including its allowlisted marker, remains parseable; the 32 KiB request body is
not retained by the trace receiver.

Apache `mod_proxy_http` does not forward the second backend request before its
first backend response. The coalesced listener therefore waits for a bounded
grace period: when the second request is already present it combines both real
requests into one parser callback; on the live Apache path it emits the first
request after the grace expires, returns the keep-alive response, then emits the
second request and reports a bounded cumulative byte/digest verification. The
partial and final responses label that path `serialized_proxy_fallback`; they
do not claim that `SSLEngine` naturally returned one callback or that Apache
backend-pipelined the pair. The direct Java socket test retains the
`parser_coalesced` proof, but it has no Apache span and is not an exact-parent
bridge result. This distinction follows the
[bridge contract](../../devdocs/java-remote-parent-bridge.md): two requests
decoded from one plaintext emission are deliberately unsupported for parent
selection, while the live fallback preserves one request ownership boundary per
parser emission.

The live trace check requires each Java server span to have the exact Apache
client span as its remote parent for the same marker and requires the pair to
reuse one backend TLS identity. Evidence retains only bounded record metadata,
byte counts, digest-equality booleans, lifecycle order, and delivery-shape
labels. The scenario result binds those two proof surfaces in one
`tls_boundary_correlation` object: all three ordered rows must identify one
canonical Apache client span and its exact Java server child, and the same row
must account for that request's real TLS records, decrypted callbacks, parser
callbacks, and bytes. The runner independently reconciles exact-parent and
same-request counts as `3/3`, with zero wrong or unresolved parents. The runner
also resolves both fixed-capacity receive coordination maps by their exact
kernel layouts: `jrp_recv_cur` and `jrp_recv_guard` are distinct 10,000-entry
hash maps with 8-byte socket-cookie keys and 56-byte exact cursor values. It
records both map IDs and occupancies before traffic, then reopens those same IDs
after traffic. The scenario passes only after two consecutive bounded samples
show both maps at their respective pre-run occupancies. The before,
per-attempt, final, and status artifacts make cursor and guard cleanup
independently auditable; neither map relies on a truncated, ambiguous kernel
label.

Internally, the fixture temporarily retains raw request bytes in a
verification buffer capped at 144 KiB (`2 * MAX_REQUEST_BYTES`). On the
serialized path it keeps request 1 until request 2 arrives, the connection
closes, or the five-second absolute request deadline expires; it releases the
combined buffer immediately after the final digest comparison. The coalescing
grace defaults to 150 ms and constructors reject values above 1000 ms. This
bounded delay and buffering belong only to the verification fixture—they are
not bridge product behavior or performance evidence. Run once per declared
protocol when iterating on that boundary:

```bash
./examples/apache-java-https/run.sh --scenario tls-boundary --tls TLSv1.2
./examples/apache-java-https/run.sh --scenario tls-boundary --tls TLSv1.3
```

The earlier clean full TLS 1.3
[retained fixture evidence](evidence/otel-getsockopt-tls13-8282d2ed/README.md)
remains scoped to its nested Java-to-loopback-Netty connection and does not by
itself prove the same-request conjunction. The current `tls-boundary` scenario
performs the supported serialized conjunction on the real Apache-to-Java path;
it is not relabeled as a coalesced bridge-parent result. The separate live
control below exercises the actual two-boundary plaintext receive. A later
retained acceptance bundle must be used for either durable result.

The distinct `coalesced-bridge` target is a live negative control for an
unsupported Go `crypto/tls` sender and a coalesced Java receive. It does not by
itself close the retained issue #34 gap or claim positive end-to-end bridge
propagation. Apache handles one marked trigger to `/api/coalesced-source`. The
separately discovered `coalesced-source` process follows that trigger on its
own local server-to-client trace, opens one TLS 1.2 or TLS 1.3 connection to
Netty, and calls `Write` once with two complete requests and no `traceparent`
header. The Go TLS probe reports that write as one generic HTTP transaction;
it does not use the bridge's request-owned native exact-prewrite path. Generic
payload propagation is disabled while bridge mode is enabled, so the Apache
trigger trace and source trace intentionally remain separate and no native
candidate, injection, stage, handoff, take, or discard is permitted.

The Netty fixture accepts the traffic shape only when one bounded
post-`SslHandler` `channelRead` contains the exact plaintext digest and its
HTTP/1 parser emits both distinct markers from callback generation one. Raw
plaintext is retained only in the fixture's 8 KiB verification buffer and is
not exported. Trace polling is order-independent and remains stable for six
seconds. It fetches both marker views plus an unfiltered view from one receiver
generation and requires: one markerless source client operation descending
locally from the marked source server; one independent marked Apache
server-to-client trigger chain; and exactly two distinct, explicitly local Java
server roots, one per request marker. The Java diagnostics delta must be
exactly `t_missing=2` and `d_ambiguous=1`, with no valid take, other result, or
failure. Any receiver loss, foreign or unknown parent, trace reuse, missing
local chain, marked second source operation, or nonzero native bridge lifecycle
fails closed. The runner also returns both receive-coordination maps to their
steady pre-run occupancies. A future exact-parent branch requires a supported
exact-prewrite sender or new Go multi-request propagation support and must be
added as a separate positive control.

Run the real control separately for both protocol versions:

```bash
./examples/apache-java-https/run.sh --scenario coalesced-bridge --tls TLSv1.2
./examples/apache-java-https/run.sh --scenario coalesced-bridge --tls TLSv1.3
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
  --scenario coalesced-bridge

./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario security

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

./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario delayed-otlp-suppression
```

The forced-primary `security` control includes the live-descriptor probe. It
holds one real request at the Java barrier, runs a root probe in the Java
container's PID 1 cgroup, and attempts `pidfd_getfd` against that accepted
descriptor. A standalone `--scenario security` invocation is a targeted
source-control run and remains non-acceptance evidence even when its checks
pass. The same control is acceptance evidence only when it runs as part of a
clean full `all` suite. A host that cannot duplicate the descriptor records
`pidfd-duplicate-unavailable` as `unsupported`; it does not silently fall back
to Unix or count as a primary pass, and the runner exits nonzero after releasing
the held victim while its exit trap restores the base stack.

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

## Deliberate assertion-failure control

Use this bounded, non-acceptance control to verify that a failed assertion is
understandable without causing a transport, certificate, or stack failure:

```bash
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --scenario assertion-failure
```

It first completes the normal `basic` assertion, then exits with status `2`
and the terminal message `deliberate assertion failure requested`. Its retained
result directory contains `scenario-basic.json`,
`scenario-assertion-failure.json`, `scenario-assertion-failure-status.json`,
`failure-context.txt`, and `run-status.json`. The two assertion-failure JSON
files name the expected exit status, failure-context path, and sealed last
valid fixed-schema Java bridge diagnostics. The same object is retained in
`terminal-java-diagnostics.json` and embedded in `run-status.json`, while the
standard files identify the exact shell stage, source line, and command. The
control is deliberately excluded from `all` and never contributes acceptance
evidence. Use `--keep` only if you want to inspect the stack before running the
scoped `--cleanup-only` command above.

## Startup gates

Before traffic begins, the orchestrator uses bounded waits for:

- the local OTLP receiver health endpoint;
- OBI log `Java remote parent bridge ready`;
- helper log `OBI remote-parent provider ready`;
- Jetty log `Jetty HTTPS backend ready on 127.0.0.1:18443`;
- Netty log `Netty HTTPS backend ready on 127.0.0.1:18444`;
- boundary-listener logs for `127.0.0.1:18445` and `127.0.0.1:18446`;
- the coalesced source's loopback health endpoint on `127.0.0.1:18081`;
- the Java backend's loopback-only transport-configuration endpoint, whose
  fixed snapshot must prove the requested and selected transport;
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

## Delayed first-OTLP suppression control

The `delayed-otlp-suppression` control exercises the
[startup-window limitation](../../devdocs/exclude-otel-instrumented-services.md#1-startup-window-duplicates-until-the-first-export)
without treating bridge propagation as part of exporter suppression. It
force-recreates the Java backend, OBI, Apache, and receiver, sets
`OTEL_BSP_SCHEDULE_DELAY=60000`, and performs exactly one marked Apache-to-Java
prime request. Safe startup checks do not send an ordinary request to the Java
backend before that prime.

The control records an empty fresh receiver before the request. It then rejects
any marker-correlated Java SDK Jetty server span received before the Java
container's start time plus the configured 60-second delay. The receiver stamps
the accepted OTLP request in milliseconds, so a delayed harness poll cannot
hide an early export. After the deadline, it requires exactly one Java SDK
server span from the `io.opentelemetry.jetty-11.0` scope, the Java duplicate
suppression signal from OBI, and the normal exact-parent `basic` assertion.
A single unscoped pre-detection OBI Java server span, when present, is retained as
startup-window evidence. Its end timestamp, rather than its OTLP batch arrival
order, must place it before the export boundary. After suppression, the `basic`
assertion must have only the normal Java SDK server span. Apache OBI spans are
also allowed during the window.

The OBI OTLP batch timeout is pinned to 15 seconds, exporter retry time is
bounded to 2 seconds, and each OBI export attempt is capped at 5 seconds. Their
pinned delivery bound is 22 seconds (`15 + 2 + 5`); the integer-clock
settlement interval is 23 seconds so it cannot end early because of `SECONDS`
quantization. The Java batch export attempt is separately capped at 5 seconds,
and Java OTLP retry is disabled for this deterministic control. Only after
suppression readiness, the control re-fetches the cumulative receiver snapshot
through that settlement interval and a final one-second poll. Its start is
limited to the next integer-clock slack bucket and its termination grace is one
second. Each control run uses a fresh request marker and binds every
single-object snapshot to the receiver instance and reset generation observed
before the request.
Receiver counters and the optional startup span must remain monotonic; any
receiver restart/reset, drop, omission, or ambiguous span identity fails the
control closed with the discontinuous snapshot retained. These bounds keep an
SDK-only poll from hiding a queued OBI batch, a retry from an earlier run,
malformed span, or duplicate Java SDK export.

The `all` suite includes this control, then restores the prior export-delay
setting and a normal instrumented stack before the remaining scenarios.

## Configuration contract

OBI accepts these environment overrides (the YAML equivalents are in
`configs/obi.yaml`):

| Setting | Value in this demo |
| --- | --- |
| `OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP` | `true` |
| `OTEL_EBPF_BPF_BUFFER_SIZE_HTTP` | `32768` bytes, enough to parse the deliberate 18 KiB boundary header |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TRANSPORT` | `disabled`, `auto`, `getsockopt`, or `unix` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_PATH` | `/var/run/obi/java-remote-parent.sock` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_SOCKET_GROUP_ID` | `65534` (the bounded Unix attacker fixture; the demo JVM runs as root) |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TIMEOUT` | `50ms` |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_TTL` | `30s` prewrite and cleanup retention |
| `OTEL_EBPF_JAVA_REMOTE_PARENT_RETRIEVAL_TTL` | `0s` (inherits `TTL` and must not exceed it; stale controls set `1ns`) |

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
- for a clean full forced-primary run whose live-descriptor status is `passed`:
  barrier arm, release, and consumption records;
  `security-primary-live-fd.log`; the held victim's JSON and stderr;
  before/probe/after metric phases; and
  `scenario-primary-live-fd-security-status.json`. An unsupported pidfd result
  instead retains the barrier records, probe log, held-victim JSON and stderr,
  baseline metric evidence, and unsupported status. It does not produce the
  probe/after phases or explicit post-abuse recovery scenario, and exits
  nonzero after its trap restores the base stack;
- machine-readable connection evidence for pipeline depth, writes completed
  before the first response read, stable Jetty connection IDs, fixed frontend
  ephemeral-port reuse, and frontend/backend descriptor reuse;
- before/after OBI metrics, Java bridge diagnostics, scoped container
  CPU/memory/PID samples, process RSS/thread/fd counts, and reason-coded metric
  deltas for every scenario repetition;
- for `tls-boundary` and `coalesced-bridge`, the exact receive cursor and guard
  map IDs and layouts, both pre-run occupancies, every bounded recovery attempt,
  two consecutive samples in which both maps are at steady baseline, and the
  same evidence embedded in the scenario status;
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
  and the Java-service duplicate-suppression metric; after each normal OBI
  create/restart, a non-measured health request drives behavioral detection
  and asserted traffic starts only after the new process reports suppression.
  The host-PID OBI service explicitly disables any daemon-default init shim,
  keeping Docker's recorded PID bound to `/obi` resource evidence, and uses a
  30-second Compose stop grace around its explicit 10-second internal shutdown
  bound. Force-recreates can unload tracers and let Docker reap the process
  before it may escalate to `SIGKILL`.
  The delayed-first-OTLP control is distinct: it sends one marked prime request
  only after safe startup and performs no generic Java health request before it;
- final receiver snapshot, Compose state, and component logs.

Build and startup output is streamed to the terminal and retained in
`bridge-build.log` and `compose-up.log`. A failed run also records the exact
failure stage, source line, exit status, and shell-escaped command in
`failure-context.txt`; `run-status.json` repeats the stage, line, and
acceptance-evidence eligibility reason for machine-readable triage, including
failures that occur after the result directory exists but before
`environment.txt` can be written. It also embeds and references
`terminal-java-diagnostics.json`. Before fault-control recovery, the runner
durably captures the last validated fixed-schema boundary. If recovery fails,
that captured boundary is sealed and embedded; successful recovery commits and
discards it so the later terminal status can use the latest valid snapshot. A
failure before the first valid JVM snapshot records an explicit bounded
`available:false` object instead of inventing evidence.

Every `scenario-*-status.json` produced by `run_scenario` names both phase
directories and embeds each available fixed-schema Java diagnostics snapshot
with its relative artifact reference, exact base-36 snapshot, and structured
counter values. This evidence is published even when the scenario process or a
later metric or diagnostic assertion fails. A snapshot that was never captured
is represented as `null`; the runner never fabricates an after value, and a
present malformed or symlinked snapshot fails the scenario instead of entering
the status.

Only a generated marker header is captured. The receiver rejects compressed or
oversized requests, enforces configured count, per-string, and aggregate
retained-byte ceilings, and strips arbitrary headers and bodies before writing
evidence. Any receiver eviction or rejection is reason-coded and invalidates
the scenario. For ordinary non-stale scenarios, Java diagnostics are fetched
after each post-scenario OBI metric snapshot. Their delta requires exactly one
self-observed missing lookup, so the diagnostic request cannot mask another
missing lookup in the reason-coded interval attributed to that scenario. The
forced `1ns` stale controls instead use in-band snapshots from the existing
bridge-boundary health request and the marked workload response, which keeps
their exact stale delta tied to the workload. A fault-injection request also
opts in to the fixed snapshot on its response after Java extraction. The runner
captures its baseline from the existing pre-control health request, validates
the exact bounded schema, and chains response-to-response deltas while the
fault suite remains serial. This avoids an extra bridge take and requires
exactly the normalized Java status for each injected mode with no unexpected
retrieval result. `coalesced-bridge` and `timeout-retry` likewise return their
terminal fixed-schema snapshot in-band. The former records exactly two missing
receives and one reason-coded ambiguity for its unsupported Go TLS/coalesced-
receive control; the latter retains the canceled marker and its exact, missing,
or single reason-coded disposition. Neither control adds a post-workload
diagnostic self-probe. The restart-fault
interval also includes the after-restart diagnostics snapshot, the
duplicate-suppression readiness request, and the single post-readiness
transport-configuration request, so it requires exactly three non-workload
takes and reports conservative workload attribution bounds. The transport
request is not retried because every processed retry would add another take; a
failed request fails the scenario. After the provider retry interval, that
duplicate-suppression request must produce a post-restart provider-ready log
before the transport snapshot is captured and traffic resumes, preventing a
pre-restart snapshot from satisfying the gate.

A dirty source tree, `--skip-bridge-build`, an individually targeted scenario,
or `--scenario all --requests N` is explicitly labeled non-acceptance evidence.
Only a clean, fresh-build full `all` run with the default per-scenario request
counts is eligible to populate the result matrices.
Reviewer-facing scoped records are listed in the
[focused-validation index](focused-validation/README.md). The clean focused
primary-control record is retained separately in
[focused-validation/primary-getsockopt-8f0aa1f6](focused-validation/primary-getsockopt-8f0aa1f6/README.md)
so its isolation and fail-open outcomes can be reviewed without being promoted
to an acceptance cell. That historical record predates the live-descriptor
control and does not establish its result. A clean full current-revision run
with the primary security artifacts above is required before a matrix cell can
be updated.

## Diagnostics

For an early failure, inspect `failure-context.txt`, then `bridge-build.log` or
`compose-up.log` for the named stage. If readiness fails after startup, inspect
the retained `compose.log` in this order:

1. `trace-receiver` must listen on `127.0.0.1:14318`.
2. Jetty must report HTTP/1.1 and the selected TLS protocol.
3. Apache must load `mod_ssl` and verify the generated CA and hostname.
4. OBI must discover Apache on `18080`, the coalesced source on `18081`, and
   the Java listeners on `18443` through `18446`, expose its loopback internal
   metrics on `18990`, then report bridge availability.
5. The JVM must report provider, extension, and injected-instrumentation
   readiness messages. Its loopback-only `/obi-transport-configuration`
   endpoint must return a fixed snapshot that proves the requested and selected
   transport; the harness retains that exact snapshot as
   `java-selected-transport-configuration.txt`. The current-generation
   `java-transport-configuration.txt` is cleared before helper or bridge
   generation changes, without deleting the retained positive evidence.
6. A failed scenario JSON shows sanitized span graphs from the latest polling
   pass. A marker whose fetch fails or completes after the polling deadline has
   an empty graph instead of reusing an older graph; pressure evidence
   classifies it as unresolved. A fetched assertion failure retains its exact
   unmatched trace/parent boundary.

For `unix`, verify that the scoped `java-remote-parent-socket` volume is owned
by `root:65534`, has mode `0750`, and is mounted by both OBI and Java at
`/var/run/obi`. The one-shot `socket-init` service establishes those
permissions before either service starts. Membership in this socket group only
permits directory listing/traversal and socket connection: OBI derives Unix
peer credentials and still requires the peer process to satisfy its
authorization checks. The hardened
`security-unix-sibling-probe` fixture deliberately uses that group without
root, network access, capabilities, a writable root filesystem, or a writable
socket mount. Within the Unix control, `security-probe` remains root-owned
only for endpoint-replacement testing; the separate `getsockopt` control
reuses its image for native protocol checks. For `getsockopt`, confirm the
kernel reports support rather than silently accepting fallback; a forced mode
must not change transport.

The live-descriptor probe intentionally reports its direct native observation
as `unverified`: a native `getsockopt` result alone cannot show whether the
cgroup program enforced denial. A passing scenario status instead requires
`probe_verification: metrics_verified`, one unauthorized negotiate and take
metric window with zero valid retrievals, a held legitimate victim with an
exact parent, and a post-abuse recovery scenario. Preserve all of the listed
artifacts when that status is `passed`. If the status is `unsupported` with
`pidfd-duplicate-unavailable`, retain it as an unsupported primary capability
result and do not promote the targeted run to an acceptance matrix cell.

## Explicit limitations

- Backend HTTP/2 is unsupported and not exercised. The Jetty connector and
  Apache proxy protocol are deliberately HTTP/1.1-only.
- Pipelining is exercised only on the plaintext HTTP/1.1 client-to-Apache hop.
  The scenario writes every request before reading a response and fails unless
  every response and exact parent is returned.
- Outside the TLS-boundary fixture, the final serial request and every parallel
  request send `Connection: close` and ask the backend to close its response.
  This preserves earlier backend reuse while giving OBI a TCP close boundary
  that finishes delayed TLS spans before trace assertions. The boundary client
  instead keeps its frontend connection persistent for the pair, Apache emits
  reusable backend requests, and the sequence-aware Netty fixture itself forces
  the final backend response and TLS connection closed.
- Readiness and metric-boundary health probes also ask Jetty to close the
  backend connection, preventing probe state from entering a measured scenario.
- The slow-body control proves that each measured request after the baseline
  crosses at least two decrypted Java receive callbacks and that those
  callbacks account for at least the full 64 KiB body. It does not infer exact
  Apache/OpenSSL TLS record boundaries from the client-side write pattern.
- The earlier retained TLS-boundary fixture observes bounded post-handshake TLS
  application-record version and length metadata without retaining payloads.
  Its exact record/callback cardinality proof is scoped to planned fixture
  writes and does not claim a general one-write/one-record JSSE contract. The
  current same-path scenario instead frames actual Apache-to-Java records before
  Netty decryption and fails on any record/callback shape it cannot associate
  exactly. On the live Apache path, each supported request is parser-delivered
  separately after its own records are aggregated. A direct Java socket control
  proves that two requests can share one deliberately aggregated parser buffer;
  that control has no bridge-parent assertion because the bridge contract marks
  more than one request ownership boundary per plaintext emission unsupported.
- The helper carries accepted-socket ownership through exact executor,
  ForkJoin, Netty-worker, and virtual-thread task contexts. Packaged-agent tests
  cover nested hops, cancellation, worker reuse, and Java 21 carrier migration.
  The Jetty servlet scenarios still begin after stock server extraction. The
  retained inbound-Netty fixture proves its own receive-to-extraction path, but
  neither result establishes arbitrary framework or Netty application support.
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
