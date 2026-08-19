# Focused validation records

These reviewer-facing bundles retain bounded validation results that are useful
outside the clean full Apache-to-Java HTTPS acceptance-bundle contract. Each
record states its own evidence scope. A focused result does not automatically
populate a privileged Compose, architecture, kernel, or transport matrix cell.

| Record | Result | Scope |
| --- | --- | --- |
| [diagnostic-nondisclosure-f8775328d54a-6a2fe52aac6eab28](diagnostic-nondisclosure-f8775328d54a-6a2fe52aac6eab28/README.md) | focused validation pass | Issue #39 source-configured Temurin Java 21/TLS 1.3 runtime non-disclosure matrix: checksum-verified OpenTelemetry 2.28.1 and Splunk 2.28.0 agents across forced `getsockopt`/Unix and INFO/DEBUG; all eight cells passed six governed diagnostic surfaces with zero reconstructed-canary matches; summary-only non-acceptance evidence that closes #39 without populating a compatibility cell or closing #40 |
| [official-agent-runtime-9b66f39e](official-agent-runtime-9b66f39e/README.md) | pass | Issue #27 stock official-agent runtime matrix on Linux `X64`/`x86_64`: OpenTelemetry 2.28.1 and Splunk 2.28.0 on Java 8, 11, 17, and 21; separate from the Java 21 privileged Compose evidence |
| [packaged-jvm-getsockopt-75aa1a06](packaged-jvm-getsockopt-75aa1a06/README.md) | focused validation pass | Local upstream-host packaged-agent Java/JNI/cgroup-`getsockopt` miss/hit latency result; no public CI locator and explicitly non-acceptance evidence that advances but does not close #11, #20, or #37 |
| [packaged-jvm-getsockopt-rhel96-a9047a32](packaged-jvm-getsockopt-rhel96-a9047a32/README.md) | focused validation pass | GitHub-hosted packaged-agent Java/JNI/cgroup-`getsockopt` miss/hit latency result on a digest-pinned RHEL 9.6 kernel with Alpine userspace; explicitly non-acceptance evidence that advances but does not close #11, #20, or #37 |
| [packaged-jvm-transports-rhel96-a86faf01](packaged-jvm-transports-rhel96-a86faf01/README.md) | focused validation pass | GitHub-hosted schema-v2 packaged-agent concurrent Java/JNI transport result on a digest-pinned RHEL 9.6 kernel with Alpine userspace; all 14 raw-JNI and bridge/provider-JNI `getsockopt` miss/hit/stale and Unix miss/hit/stale/timeout series passed their predeclared gates; explicitly non-acceptance evidence that advances but does not close #11, #18, #20, or #37 |
| [primary-getsockopt-8f0aa1f6](primary-getsockopt-8f0aa1f6/README.md) | focused validation pass | Targeted forced-primary application controls; explicitly non-acceptance evidence |
| [rhel96-kernel-sockopt-4fe50533](rhel96-kernel-sockopt-4fe50533/README.md) | focused preflight pass | Targeted RHEL 9.6 kernel/provider preflight; explicitly non-acceptance evidence |

Every record has its own `SANITIZATION.md` and `SHA256SUMS`. Run the integrity
commands in that record's README from the record directory.
