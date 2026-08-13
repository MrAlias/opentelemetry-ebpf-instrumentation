# Focused official Java-agent runtime compatibility

Result: **issue #27 compatibility scope passed — stock-agent CI evidence**

This reviewer-facing record retains the exact result of
[Java Agent CI run 31695707017](https://github.com/MrAlias/opentelemetry-ebpf-instrumentation/actions/runs/31695707017)
at source revision `9b66f39eb0e5897b6b27d999e461267dfa85fd70`.
All four Java jobs and their `official-agent-runtime-v1` cells passed. The four
raw archives independently matched GitHub's reported SHA-256 digests before
this sanitized summary was produced.

The CI cells used checksum-verified, unmodified official Maven artifacts and a
separately built external OBI extension. They establish the declared stock-agent
runtime contract on Linux `X64`/`x86_64`. Existing privileged Java 21 Compose
runs separately establish real OBI dynamic helper attach, bridge calls, bounded
stack cleanup, and exact Apache-to-Java parentage for both distributions.
The two evidence layers close issue #27's declared compatibility scope without
promoting Java 8, 11, or 17 to privileged Compose passes.

## Exact runtime matrix

Each agent/application entry below comes from its named JUnit test case, not
from the overall job conclusion alone. `unsupported` is the expected Jetty 11
result on Java 8; the fixture requires Java 11 or newer.

| JVM | Temurin runtime | Agent | Extension startup | Jetty 11.0.26 | Netty 4.1.135.Final | Java 21 concurrency | JUnit cell |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | 1.8.0_492-b09 | OpenTelemetry 2.28.1 | pass | unsupported | pass | skipped: requires Java 21 | 8 tests, 4 skipped, 0 failures/errors |
| 8 | 1.8.0_492-b09 | Splunk 2.28.0 | pass | unsupported | pass | skipped: requires Java 21 | same Java 8 artifact cell |
| 11 | 11.0.31+11 | OpenTelemetry 2.28.1 | pass | pass | pass | skipped: requires Java 21 | 8 tests, 2 skipped, 0 failures/errors |
| 11 | 11.0.31+11 | Splunk 2.28.0 | pass | pass | pass | skipped: requires Java 21 | same Java 11 artifact cell |
| 17 | 17.0.19+10 | OpenTelemetry 2.28.1 | pass | pass | pass | skipped: requires Java 21 | 8 tests, 2 skipped, 0 failures/errors |
| 17 | 17.0.19+10 | Splunk 2.28.0 | pass | pass | pass | skipped: requires Java 21 | same Java 17 artifact cell |
| 21 | 21.0.12+8-LTS | OpenTelemetry 2.28.1 | pass | pass | pass | pass | 8 tests, 0 skipped, 0 failures/errors |
| 21 | 21.0.12+8-LTS | Splunk 2.28.0 | pass | pass | pass | pass | same Java 21 artifact cell |

Across the four artifacts, the exact total is 32 tests, 8 expected skips, zero
failures, and zero errors. Every cell recorded `runner_os=Linux`,
`runner_arch=X64`, and an `x86_64` uname machine.

## Pinned official artifacts and runtime contract

| Distribution | Version | SHA-256 |
| --- | --- | --- |
| OpenTelemetry | 2.28.1 | `faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589` |
| Splunk | 2.28.0, embedding OpenTelemetry 2.28.1 | `70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351` |

Both agents exposed OpenTelemetry API 1.62.0 and autoconfigure SPI 1.62.0 and
loaded OBI extension version 0.1.0. The runtime assertions observed the API on
the bootstrap loader, the SPI on
`io.opentelemetry.javaagent.bootstrap.AgentClassLoader`, and the extension on
`io.opentelemetry.javaagent.tooling.ExtensionClassLoader`. They required the
`obi` provider to report `supported=true,reason=compatible`, verified startup
with the extension enabled and disabled, rejected invalid configuration without
disclosing its value, and inspected the extension and probe JARs for forbidden
application or agent-provided classes.

## Issue #27 closure map

| Acceptance criterion | Evidence |
| --- | --- |
| Versioned agent/JVM/application-server matrix | [matrix-summary.json](matrix-summary.json) records `official-agent-runtime-v1`, both agents, Java 8/11/17/21, Jetty 11.0.26, Netty 4.1.135.Final, exact passes, the Java 8 Jetty unsupported result, and every expected skip. |
| One official OpenTelemetry and one official Splunk agent complete the same parentage test | Both distributions pass the same Netty exact-parent test on all four JVMs and the same Jetty exact-parent test on Java 11, 17, and 21. The separately retained [OpenTelemetry](../../evidence/otel-getsockopt-tls13-e8db066a/README.md) and [Splunk](../../evidence/splunk-getsockopt-tls13-47237792/README.md) Java 21 privileged Compose cells pass the same Apache-to-Java parentage requirement with real OBI attach. |
| Every tested release and checksum is recorded | [run-identity.json](run-identity.json) retains the exact Maven coordinates and pins. Every CI metadata file agreed, the runtime tests compared the downloaded JAR bytes with the pins, and an independent Maven download reproduced both SHA-256 values. |
| No application or Java-agent classes are replaced from the extension | The official JAR hashes prove the agents were unmodified. Passing packaging/runtime assertions reject agent/API/SDK namespaces in the extension; the Jetty, Netty, and Java 21 fixtures are separate source sets and classpaths, not extension contents. |
| Compatibility failures identify the exact linkage, SPI, or behavior | No supported cell failed. The same successful jobs ran the deterministic boundary suite, which rejects adjacent agent, API, SPI, and JVM values with `unsupported_agent`, `unsupported_api`, `unsupported_spi`, or `unsupported_java`. Runtime classloader and provider values are retained above. |
| Documented range or deterministic rejection | The accepted range is exactly the two pinned distributions, API/SPI 1.62.0, and JVM features 8, 11, 17, and 21. Values outside it fail the compatibility gate with the named reason; no broader range is implied. |
| No custom Java-agent fork | Both agents came from their official Maven coordinates and loaded the separately built extension through the public extension property. The OBI repository fork is not a Java-agent source fork. |

The issue scope is also accounted for directly: the four CI cells establish
official-agent startup, standard extension discovery, Jetty/Netty server
instrumentation, bridge takes, exact parentage, and bounded process completion;
the linked Java 21 Compose cells establish dynamic helper attach, real OBI
bridge calls, failure/recovery, and bounded stack cleanup for each distribution.
The successful compatibility test records API, autoconfigure SPI, extension,
propagator-provider, and classloader alignment. Loading through the standard
extension property and service-provider metadata, plus forbidden-namespace
inspection, detects the relevant service-loader or shading incompatibility
without an agent fork.

## Scope boundary

This record is not a privileged Compose acceptance bundle. It does not change
the Java 8, 11, or 17 privileged application rows in `COMPATIBILITY.md`, and it
does not establish `arm64`, other agent or server releases, issue #23's broader
helper lifecycle/failure matrix, issue #38's environment matrix, or full PoC
completion. The checked-in Java 21 Compose bundles remain the only privileged
application evidence named above.

## Integrity

From this directory:

```bash
./verify.sh
```

The verifier requires an exact, self-contained, non-symlink manifest; canonical
single-document JSON without duplicate keys; every claim-bearing identity and
scope field; the complete runtime contract, fixtures, expected skip reasons,
per-suite JUnit counts; and the exact eight agent/application rows. It also
cross-links every matrix cell's artifact name and digest to the public run
metadata.

[SANITIZATION.md](SANITIZATION.md) describes the transformation and omissions.
The checked-in checksum manifest protects this sanitized record; the separately
retained GitHub artifact digests identify the omitted raw archives.
