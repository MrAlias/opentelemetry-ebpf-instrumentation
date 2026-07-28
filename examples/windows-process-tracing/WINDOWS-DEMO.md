# Native Windows correlated tracing demo

This demo continuously presents genuine correlated HTTP traces from native
Windows OBI to an OTLP backend. It is designed for both community
demonstrations with Jaeger and vendor demonstrations with Splunk Observability
Cloud.

The trace path is backend-neutral:

```text
OpenTelemetry SDK client ---\
                             > local OpenTelemetry Collector --> backend
Windows OBI SERVER span ----/
```

OBI and the client always send OTLP/HTTP protobuf to
`http://127.0.0.1:4318/v1/traces`. Collector profiles select the backend
without rebuilding either trace producer.

## What the demo proves

Every successful cycle writes a record to `trace-chain.ndjson` only after
validating all of the following:

- the SDK CLIENT span and OBI SERVER span have the same trace ID;
- the SERVER parent span ID is the CLIENT span ID;
- OBI logged the exact SERVER span ID observed by the Collector;
- the SERVER span has `SERVER` kind and the expected HTTP fields;
- the SERVER resource has
  `telemetry.distro.name=opentelemetry-ebpf-instrumentation`; and
- the Collector remains alive without a reported OTLP export failure.

`telemetry.sdk.name=opentelemetry` is expected on an OBI resource. The
separate `telemetry.distro.name` attribute identifies the OBI distribution.
The SDK client deliberately does not carry that distribution attribute.

## Prerequisites

- A Windows/amd64 VM with the matched eBPF-for-Windows, NetEbpfExt, and
  NtosEbpfExt runtime already deployed.
- A previously accepted Windows HTTP package containing `obi.exe`,
  `obi-windows-http-client.exe`, `obi_process_start.sys`, and
  `obi_flow_classify.sys`.
- Go for assembling a fresh demo package.
- OpenTelemetry Collector Contrib 0.151.0 from `Get-Collector.ps1`.
- Administrative rights for native eBPF program attachment.

Build an integrity-bound package from an accepted base stage:

```powershell
.\scripts\Build-WindowsDemo.ps1 `
    -BaseStageDirectory C:\src\obi-linked-final-f92f8976 `
    -OutputDirectory C:\src\obi-windows-demo
```

The builder requires a clean OBI source tree, compiles the configurable demo
target for Windows/amd64, copies the accepted OBI and eBPF artifacts, and
writes a SHA-256 manifest. The start script verifies the complete package
manifest before launching any process and records the hashes of the artifacts
that actually execute.

## Five-minute Jaeger walkthrough

Jaeger is the default backend because one Windows executable provides an OTLP
receiver, in-memory trace storage, and a browser UI. The download helper pins
Jaeger 2.20.0 and verifies both the release archive and `jaeger.exe`.

On the VM:

```powershell
.\Get-Jaeger.ps1 -OutputDirectory C:\src\obi-artifacts\jaeger

.\Start-OBIWindowsDemo.ps1 `
    -StageDirectory C:\src\obi-windows-demo `
    -Backend Jaeger `
    -RatePerSecond 1
```

The script runs Jaeger's OTLP/HTTP receiver on `127.0.0.1:14318`, leaving the
standard local Collector receiver on `127.0.0.1:4318`. It leaves the Jaeger UI
on port 16686.

From the Hyper-V host, forward the UI without opening a VM firewall port:

```powershell
$vmAddress = '<vm-address>'
$vmUser = '<vm-user>'
$sshKey = '<path-to-private-key>'
ssh -i $sshKey -L 16686:127.0.0.1:16686 "$vmUser@$vmAddress"
```

Open `http://127.0.0.1:16686`, select
`obi-windows-http-demo-target.exe`, and find traces. The trace timeline should
show the SDK CLIENT span as the parent of the OBI SERVER span. Paths, response
codes, and latency rotate so the trace list remains visually useful.

Stop the foreground script with Ctrl+C. If its shell is unavailable, use:

```powershell
.\Stop-OBIWindowsDemo.ps1 `
    -StageDirectory C:\src\obi-windows-demo
```

The stop script first requests a graceful exit at the next trace boundary. If
that times out, it terminates only the exact process IDs and executable paths
recorded by the demo. Both paths verify that no eBPF programs, maps, or links
remain.

## Splunk Observability Cloud walkthrough

Create or obtain an ingest-scoped organization access token. Keep the token in
the process environment; do not pass it as an argument or save it in a
configuration file.

```powershell
$env:SPLUNK_REALM = 'us0'
$secureToken = Read-Host -Prompt 'Splunk ingest token' -AsSecureString
$tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
    $secureToken
)
try {
    $env:SPLUNK_ACCESS_TOKEN = (
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
    )
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
    $secureToken.Dispose()
}

.\Start-OBIWindowsDemo.ps1 `
    -StageDirectory C:\src\obi-windows-demo `
    -Backend Splunk `
    -RatePerSecond 1
```

With valid credentials, the Collector sends OTLP/HTTP traces to:

```text
https://ingest.<realm>.observability.splunkcloud.com/v2/trace/otlp
```

using `X-SF-Token`. The token is not written to state, evidence, or console
output, and exception messages are redacted. In Splunk APM, search for service
`obi-windows-http-demo-target.exe` and open a recent trace.

The bundled configuration can be validated without transmitting telemetry,
but end-to-end Splunk delivery cannot be accepted without real ingest
credentials and confirmation in the destination UI.

Remove the token when the demo ends:

```powershell
Remove-Item Env:SPLUNK_ACCESS_TOKEN
```

## Another OTLP backend

Use `-Backend OTLP` with a user-supplied Collector configuration:

```powershell
.\Start-OBIWindowsDemo.ps1 `
    -StageDirectory C:\src\obi-windows-demo `
    -Backend OTLP `
    -CollectorConfig C:\secure\collector-backend.yaml
```

The configuration must:

- receive OTLP/HTTP on `127.0.0.1:4318`;
- export traces to the chosen backend;
- enable a detailed `debug` exporter in the same trace pipeline so the demo
  can validate both span bodies; and
- obtain credentials from protected environment variables or another
  Collector-supported secret provider.

Run the Collector's `validate` command before any demo process starts. The
start script does this automatically.

## Traffic controls

The defaults rotate among three routes, status codes, and latency values.
Override them when a presentation needs a particular story:

```powershell
.\Start-OBIWindowsDemo.ps1 `
    -StageDirectory C:\src\obi-windows-demo `
    -Backend Jaeger `
    -RatePerSecond 0.5 `
    -RequestPaths /checkout,/payment,/inventory `
    -StatusCodes 200,503,204 `
    -LatencyMilliseconds 25,800,100
```

Use `-Count 5` for bounded acceptance instead of an indefinite presentation.
Latency values must be between 0 and 5000 milliseconds. `RatePerSecond` is a
requested maximum of 10 traces per second. Each trace
cycle must finish and clean up before the next begins, so the safe one-shot
lifecycle may limit the actual rate.

## Evidence

Each run creates `evidence\windows-demo-<UTC timestamp>` beneath the stage.
Important files are:

| File | Purpose |
| --- | --- |
| `trace-chain.ndjson` | One machine-readable correlation record per trace |
| `demo-summary.json` | Backend, requested rate, completion count, and result |
| `runtime-artifacts.json` | Paths, sizes, roles, and hashes of executed artifacts |
| `collector.stderr.log` | Collector startup, detailed spans, and export errors |
| `jaeger.stderr.log` | Jaeger startup and backend diagnostics |
| `cycles\<number>\obi.stdout.log` | OBI attachment and exact exported span IDs |
| `cycles\<number>\ebpf-live.txt` | Native programs, maps, and links while attached |
| `cycles\<number>\ebpf-cleanup.txt` | Clean eBPF state after that trace |
| `ebpf-cleanup.txt` | Final clean eBPF state |
| `SHA256SUMS` | Integrity manifest for every other evidence file |

Collector logs prove that the local pipeline accepted both spans. For Jaeger
and Splunk, the backend UI is the presenter-facing proof that the selected
exporter delivered and stored them. The demo does not use Jaeger's internal,
unsupported HTTP query API as an acceptance dependency.

## Recover a missing process attach type

If startup reports that the `ntosebpfext` process attach type is missing, do
not replace the NetEbpfExt driver. The matched `ntosebpfext` service can be
running while its user-scoped provider metadata is absent, for example after
an eBPF runtime deployment or service restart.

The demo package does not contain this external provider's exporter. Obtain
`ntos_ebpf_ext_export_program_info.exe` built from the matching pinned
`ntosebpfext` revision. In the proven VM it is at
`C:\src\ntosebpfext\x64\Release\ntos_ebpf_ext_export_program_info.exe`.

Run the following as the same Windows user that starts OBI. It refuses to
change metadata if any eBPF program, map, or link remains loaded:

```powershell
$exporter = 'C:\src\ntosebpfext\x64\Release\ntos_ebpf_ext_export_program_info.exe'
foreach ($object in @('programs', 'maps', 'links')) {
    $output = & netsh.exe ebpf show $object 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $output -match '(?m)^\s*\d+\s+') {
        throw "Refusing export with live eBPF $object"
    }
}
if (-not (Test-Path -LiteralPath $exporter)) {
    throw "Missing matching ntosebpfext exporter: $exporter"
}
& $exporter
if ($LASTEXITCODE -ne 0) { throw "Provider export failed: $LASTEXITCODE" }
Get-Service ntosebpfext
```

The exporter should report that it is exporting program and section
information. Then rerun the demo. This updates provider metadata only; it
does not replace a driver or modify the demo package.

## Current limitations

- The stream is supervised repetition of the proven one-shot native OBI
  lifecycle. OBI, its target, and the client restart for each trace; the local
  Collector and selected backend remain running.
- This is not proof of safe continuous target-PID retirement. The native
  process hook currently exposes creation but not the exit events needed for
  that claim.
- Only plaintext HTTP/1.1 on one connection is observed. HTTPS plaintext,
  HTTP/2, HTTP/3, multiplexing, proxies, and HTTP.sys attribution are outside
  this proof of concept.
- The eBPF runtime and programs remain test-signed development artifacts.
- Jaeger uses transient in-memory storage in this demo.
- A lack of Collector export errors does not replace checking the destination
  UI during a presentation.
