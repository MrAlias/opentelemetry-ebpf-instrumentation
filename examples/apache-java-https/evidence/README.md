# Retained acceptance evidence

This directory contains bounded, sanitized artifacts from clean full demo runs.
Each evidence directory records the exact source revision and invocation,
contains a checksum manifest, and states which matrix cell it can support.

## Historical metric schemas

The retained bundles are immutable evidence for their recorded revisions. The
two historical bundles `otel-getsockopt-tls13-7482d908` and
`otel-unix-tls12-acedb68a` predate the `availability` rename, so their OBI
metric deltas can contain `operation="select"`. In those historical revisions,
`select` means only OBI-side transport readiness or preference; it is neither
Java helper selection nor proof that a request used that transport. The current
`otel-getsockopt-tls13-c9d14356`, `otel-unix-tls12-bd1c9327`, and
`splunk-getsockopt-tls13-47237792` bundles use `operation="availability"` and
retain V2 Java transport-configuration snapshots. The prior
`otel-getsockopt-tls13-94221a91` bundle uses the same current schema. The
current schema has an
eleven-operation, 792-series upper bound, as documented in the [Java
remote-parent bridge guide](../../../devdocs/java-remote-parent-bridge.md).
Checksum verification authenticates the retained artifacts; it does not recast
their historical schema.

| Evidence | Result | Matrix cell |
| --- | --- | --- |
| [splunk-getsockopt-tls13-47237792](splunk-getsockopt-tls13-47237792/README.md) | pass | Splunk 2.28.0, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2; includes bounded primary-transport security controls |
| [otel-getsockopt-tls13-c9d14356](otel-getsockopt-tls13-c9d14356/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2; includes the bounded inbound-Netty fixture |
| [otel-getsockopt-tls13-94221a91](otel-getsockopt-tls13-94221a91/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2 |
| [otel-unix-tls12-bd1c9327](otel-unix-tls12-bd1c9327/README.md) | pass | OpenTelemetry 2.28.1, forced Unix RPC, TLS 1.2, Java 21, `amd64`, unified cgroup v2 |
| [otel-getsockopt-tls13-7482d908](otel-getsockopt-tls13-7482d908/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2 |
| [otel-unix-tls12-acedb68a](otel-unix-tls12-acedb68a/README.md) | pass | OpenTelemetry 2.28.1, forced Unix RPC, TLS 1.2, Java 21, `amd64`, unified cgroup v2 |

An omitted matrix cell remains `untested`. A targeted run whose
`acceptance_evidence` field is false is not retained here as acceptance
evidence.
