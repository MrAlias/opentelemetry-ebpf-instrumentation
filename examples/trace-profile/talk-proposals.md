# KubeCon and Observability Day Europe 2027 Talk Proposal

## Session title

Instrument the Incident: What Are Slow Requests Actually Doing?

## Description

An incident can reveal questions an application was never instrumented to answer. Why do requests to the same endpoint differ so much in cost? What explains a slow request that barely uses CPU?

OpenTelemetry eBPF Instrumentation (OBI) captures request traces; the OpenTelemetry eBPF profiler samples CPU and can capture blocking stacks. Together, they connect execution stacks to exact requests, exposing differences a profile of the whole service can hide. Both provide zero-code instrumentation and can attach after the incident starts, without rebuilding, redeploying or restarting the application.

An AI investigator will follow the same evidence without application source, requesting operator approval to collect missing telemetry and producing explanations a human can verify.

Attendees will learn to compare the execution of slow and ordinary requests, look for blocking calls that could explain a request's delay, and decide when to pursue an optimization or collect more evidence.

## Benefits to the ecosystem

Teams cannot anticipate every performance question before deployment. OBI and the OpenTelemetry eBPF profiler make request traces and execution profiles available when a running application becomes hard to explain, without requiring application SDKs or a new deployment.

Their cooperation helps SREs and application developers decide where to investigate and optimize. Request context lets them compare execution across requests with different latencies, examine available blocking stacks and judge whether a hotspot is relevant to the problem being investigated. The session will explain both the additional insight and the measurements still needed to establish a cause.

Platform teams will gain an approach to providing diagnostics when needed, with operator control over attachment. The same recorded evidence supports AI investigation and human review. Attendees will learn how an assistant can acquire missing signals, follow actual trace and span identities and make its reasoning checkable, including when the available evidence leaves the question open.

## Projects covered

OpenTelemetry, OpenTelemetry eBPF Instrumentation (OBI), OpenTelemetry eBPF profiler, Model Context Protocol (MCP).

## Session details

### KubeCon + CloudNativeCon Europe 2027

- **Track:** Observability
- **Session format:** Session Presentation — 30 minutes
- **Level:** Intermediate
- **Case study:** No

### Observability Day Europe 2027

- **CNCF co-located event:** Observability Day
- **Session format:** Solo Presentation — 25 minutes
- **Level:** Intermediate
- **Case study:** No
- **Topic:** Correlation, context, and cross-project architectures; eBPF instrumentation
