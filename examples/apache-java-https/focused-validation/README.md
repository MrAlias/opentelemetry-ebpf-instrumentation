# Focused validation records

These reviewer-facing bundles retain bounded validation results that are useful
outside the clean full Apache-to-Java HTTPS acceptance-bundle contract. Each
record states its own evidence scope. A focused result does not automatically
populate a privileged Compose, architecture, kernel, or transport matrix cell.

| Record | Result | Scope |
| --- | --- | --- |
| [official-agent-runtime-9b66f39e](official-agent-runtime-9b66f39e/README.md) | pass | Issue #27 stock official-agent runtime matrix on Linux `X64`/`x86_64`: OpenTelemetry 2.28.1 and Splunk 2.28.0 on Java 8, 11, 17, and 21; separate from the Java 21 privileged Compose evidence |
| [packaged-jvm-getsockopt-75aa1a06](packaged-jvm-getsockopt-75aa1a06/README.md) | focused validation pass | Local upstream-host packaged-agent Java/JNI/cgroup-`getsockopt` miss/hit latency result; no public CI locator and explicitly non-acceptance evidence that advances but does not close #11, #20, or #37 |
| [primary-getsockopt-8f0aa1f6](primary-getsockopt-8f0aa1f6/README.md) | focused validation pass | Targeted forced-primary application controls; explicitly non-acceptance evidence |
| [rhel96-kernel-sockopt-4fe50533](rhel96-kernel-sockopt-4fe50533/README.md) | focused preflight pass | Targeted RHEL 9.6 kernel/provider preflight; explicitly non-acceptance evidence |

Every record has its own `SANITIZATION.md` and `SHA256SUMS`. Run the integrity
commands in that record's README from the record directory.
