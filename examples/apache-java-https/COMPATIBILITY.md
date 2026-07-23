# Compatibility evidence matrix

All cells below are **untested** until a run artifact from that exact cell is
attached. Kernel or distribution version inference is not evidence. Runtime
feature detection must name the selected transport; `auto` cannot stand in for
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

RHEL 8 support may only be reported from direct execution on the documented
backport. If a required cgroup hook is absent, report forced `getsockopt` as
`unsupported` with feature-detection evidence and test the Unix fallback.

## Architecture

Use a supported upstream kernel, unified cgroup v2, Java 21, OpenTelemetry
agent, TLS 1.3, and both forced transports.

| Architecture | `getsockopt` | `unix` | Evidence |
| --- | --- | --- | --- |
| `amd64` | untested | untested | not recorded |
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
| 21 | untested | untested | configured official-agent smoke; no privileged run recorded |

Additional agent releases must be selected deliberately, pinned by checksum,
and added as new rows. “Latest” is not a matrix cell.

## Apache, OpenSSL, and TLS

| Apache / OpenSSL | TLS 1.2 | TLS 1.3 | Backend HTTP |
| --- | --- | --- | --- |
| `httpd:2.4.68-alpine` image pinned in Compose | untested | untested | HTTP/1.1 only |

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
counters. A pass requires zero wrong parents; an explicit miss may be reported
only in a test whose expected outcome permits it.
