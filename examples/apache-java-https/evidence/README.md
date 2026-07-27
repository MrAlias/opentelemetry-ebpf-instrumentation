# Retained acceptance evidence

This directory contains bounded, sanitized artifacts from clean full demo runs.
Each evidence directory records the exact source revision and invocation,
contains a checksum manifest, and states which matrix cell it can support.

| Evidence | Result | Matrix cell |
| --- | --- | --- |
| [otel-getsockopt-tls13-7482d908](otel-getsockopt-tls13-7482d908/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2 |
| [otel-unix-tls12-acedb68a](otel-unix-tls12-acedb68a/README.md) | pass | OpenTelemetry 2.28.1, forced Unix RPC, TLS 1.2, Java 21, `amd64`, unified cgroup v2 |

An omitted matrix cell remains `untested`. A targeted run whose
`acceptance_evidence` field is false is not retained here as acceptance
evidence.
