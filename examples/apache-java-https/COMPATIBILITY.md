# Compatibility evidence matrix

Cells without a linked run artifact remain **untested**. Kernel or distribution
version inference is not evidence. Runtime feature detection must name the
selected transport in the JVM's fixed transport-configuration snapshot; OBI's
bridge-readiness log proves availability, not Java selection. This snapshot is
retained as `java-selected-transport-configuration.txt` and is required for new
evidence produced after the V2 diagnostics contract was introduced. Older
linked bundles remain historical results for their recorded revisions, but do
not establish V2 selection at the current revision. `auto` cannot stand in for
forced primary and fallback tests.

Each result must be one of `pass`, `fail`, `unsupported`, or `untested` and
include revision, kernel, architecture, cgroup mode, JVM, agent, Apache,
OpenSSL, TLS, transport, command, and artifact link.

## Kernel, cgroup, and transport

Use Java 21, the OpenTelemetry agent, TLS 1.3, `amd64`, and one fixed container
stack while varying this table.

| Environment | Cgroup topology | `getsockopt` | `unix` | `auto` |
| --- | --- | --- | --- | --- |
| RHEL 9 / kernel 5.14 | unified v2 | untested | untested | untested |
| upstream 5.10 | unified v2 | untested | untested | untested |
| upstream 5.15 | unified v2 | untested | untested | untested |
| upstream 6.1 | unified v2 | untested | untested | untested |
| upstream 6.6 | unified v2 | untested | untested | untested |
| upstream 6.12 | unified v2 | untested | untested | untested |
| RHEL 8 / 4.18 backport | host default | untested | untested | untested |
| supported kernel | hybrid v1/v2 | untested | untested | untested |
| supported kernel | nested/delegated v2 | untested | untested | untested |
| supported kernel | sibling containers | untested | untested | untested |

The following additional host is directly observed. It is not a substitute for
any representative kernel row above.

| Environment | Cgroup topology | `getsockopt` | `unix` | `auto` | Evidence |
| --- | --- | --- | --- | --- | --- |
| Linux 6.17.0-1019-aws (distribution not recorded) | unified v2 | pass | untested | untested | [clean full OpenTelemetry/TLS 1.3 run](evidence/otel-getsockopt-tls13-7482d908/README.md) |

RHEL 8 support may only be reported from direct execution on the documented
backport. If a required cgroup hook is absent, report forced `getsockopt` as
`unsupported` with feature-detection evidence and test the Unix fallback.

## Architecture

Use a supported upstream kernel, unified cgroup v2, Java 21, OpenTelemetry
agent, TLS 1.3, and both forced transports.

| Architecture | `getsockopt` | `unix` | Evidence |
| --- | --- | --- | --- |
| `amd64` | pass | untested | [Linux 6.17/OpenTelemetry/TLS 1.3](evidence/otel-getsockopt-tls13-7482d908/README.md) |
| `arm64` | untested | untested | not recorded |

## JVM and official agent

Use one fixed supported kernel/architecture and TLS 1.3. The Compose backend is
pinned to Java 21; Java 8, 11, and 17 cells require a directly recorded backend
image override or dedicated CI fixture. Do not mark them from unit tests alone.

The external extension has a deliberately narrow runtime gate:

| Contract field | Accepted value |
| --- | --- |
| JVM feature version | 8, 11, 17, or 21 |
| OpenTelemetry Java agent | 2.28.1 |
| Splunk Java agent | 2.28.0 embedding OpenTelemetry 2.28.1 |
| OpenTelemetry API | 1.62.0 |
| OpenTelemetry autoconfigure SPI | 1.62.0 |

The Java CI workflow is configured to execute the test suite on all four JVM
versions and, for every JVM matrix entry, download both unmodified official
agents and prove that each loads the separately built external extension.
Boundary tests require adjacent agent, API, SPI, and JVM versions to be
rejected with a deterministic reason. These checks establish the declared
compatibility contract when they pass; they do not replace a privileged
Compose run for a matrix cell below.

| JVM | OpenTelemetry 2.28.1 | Splunk 2.28.0 | Evidence |
| --- | --- | --- | --- |
| 8 | untested | untested | configured official-agent smoke; no privileged run recorded |
| 11 | untested | untested | configured official-agent smoke; no privileged run recorded |
| 17 | untested | untested | configured official-agent smoke; no privileged run recorded |
| 21 | pass | untested | [Temurin 21/OpenTelemetry/`amd64` privileged run](evidence/otel-getsockopt-tls13-7482d908/README.md) |

Additional agent releases must be selected deliberately, pinned by checksum,
and added as new rows. “Latest” is not a matrix cell.

## Apache, OpenSSL, and TLS

| Apache / OpenSSL | TLS 1.2 | TLS 1.3 | Backend HTTP |
| --- | --- | --- | --- |
| `httpd:2.4.68-alpine` image pinned in Compose | untested | [pass graph](evidence/otel-getsockopt-tls13-7482d908/scenario-basic.json), [runtime](evidence/otel-getsockopt-tls13-7482d908/apache-openssl-runtime.txt) | HTTP/1.1 only |

Every run must produce `apache-openssl-version.txt` proving that Apache loaded
`ssl_module`, that `mod_ssl.so` links to `libssl.so.3` and `libcrypto.so.3`,
and that Alpine attributes those exact runtime libraries to the expected
OpenSSL packages. A public retained subset may publish the allowlisted result
as `apache-openssl-runtime.txt`, but the TLS pass also requires a linked
scenario response naming the negotiated protocol and cipher. Missing or
malformed runtime evidence fails the run.

Backend HTTP/2 is currently **unsupported**, not silently untested. If support
is later proposed, it needs a separate topology and exact concurrency evidence
before changing that status.

## Cell procedure

```bash
./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --agent otel \
  --tls TLSv1.3

./examples/apache-java-https/run.sh \
  --transport unix \
  --agent otel \
  --tls TLSv1.3

./examples/apache-java-https/run.sh \
  --transport getsockopt \
  --agent otel \
  --tls TLSv1.2

./examples/apache-java-https/run.sh \
  --transport unix \
  --agent otel \
  --tls TLSv1.2
```

Attach the result directories, `bpftool feature probe` output, cgroup mount
layout, `uname -a`, container image IDs, and any reason-coded miss/drop
counters. A pass requires zero wrong parents. Under live map pressure, an
explicit Java root is permitted only when the transport-aware bridge pipeline
conserves the full request count, retains the actual upstream and retrieval
failure reasons, and reconciles with the aggregate Java diagnostics. Other
tests may report a miss only when their expected outcome permits it.

The narrowest directly demonstrated configuration is currently the exact Linux
6.17.0-1019-aws, unified-cgroup-v2, `amd64`, Temurin 21, OpenTelemetry 2.28.1,
forced-`getsockopt`, Apache 2.4.68, OpenSSL 3.5.7, TLS 1.3 cell linked above.
The distribution was not recorded independently, and no broader compatibility
claim follows from that result.
