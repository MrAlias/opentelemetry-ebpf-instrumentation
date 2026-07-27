# Windows process-start tracing proof of concept

This example is a bounded Windows port of the OBI executable. It proves that a
native Windows/amd64 `obi.exe` can:

1. load a real bpf2c-generated eBPF-for-Windows kernel-mode program;
2. attach it to the `ntosebpfext` process hook;
3. receive a genuine process-create event from a ring buffer;
4. convert that event into an OBI `request.Span`;
5. use OBI's grouping, sampling, ID generation, and OTLP pdata path; and
6. export the resulting trace to a local OpenTelemetry Collector.

This is not a complete Windows port of OBI's Linux application discovery or
protocol tracers. The Windows executable in this proof of concept traces one
configured executable name and exits after exporting the first matching
process-start event by default.

## Native Windows HTTP trace-context proof

The example now also contains a development proof for plaintext HTTP/1.1
SERVER spans. A new eBPF-for-Windows `flow_classify` program and attach type
uses WFP ALE flow-establishment and STREAM callouts. OBI identifies the server
generation through the process hook, captures bounded request and response
headers, parses an incoming W3C `traceparent`, creates a child span, and
exports it through the normal OBI OTLP pdata path.

The final client uses the ordinary OpenTelemetry Go SDK and standard
`otelhttp.Transport`. It creates and exports a real CLIENT span, injects that
span's W3C context into the request, and does not construct OBI telemetry.
Three consecutive fresh VM runs proved that OBI extracted that context and
exported the SERVER child:

| Run | Trace ID | CLIENT span ID | SERVER parent ID | SERVER span ID |
| --- | --- | --- | --- | --- |
| 1 | `c9cce1fdc6c2f5b03d31a9c18a62976b` | `b8eb553960d02070` | `b8eb553960d02070` | `39f4b035a73bd08f` |
| 2 | `67f02d1e9a20c643610f84487881265d` | `919d495419d72404` | `919d495419d72404` | `c686b443856b9b9c` |
| 3 | `445a5f5e209a93daf232f04be86154a3` | `00e6c54c2130f97e` | `00e6c54c2130f97e` | `064d9957e88a49b0` |

Each request was `GET /linked-final-N` on `127.0.0.1:18080` and returned
HTTP 204. The Collector also reported the expected server address, port, and
target PID. The OBI SERVER resource and scope were:

```text
service.name:          obi-windows-http-target.exe
telemetry.sdk.name:    opentelemetry
telemetry.distro.name: opentelemetry-ebpf-instrumentation
otel.scope.name:       go.opentelemetry.io/obi
```

The independent CLIENT resource used
`service.name=obi-windows-http-client`, carried no
`telemetry.distro.name`, and used instrumentation scope
`go.opentelemetry.io/obi/examples/windows-http-client`. These differences,
along with the OBI raw-event log and native program state, distinguish the
ordinary SDK span from the OBI-generated SERVER span.

The accepted source commits and deployed artifact hashes were:

| Item | Commit or SHA-256 |
| --- | --- |
| OBI source | `19eca98156fef1d7649a8c0f91b4067a0ca8bbda` |
| eBPF-for-Windows source | `11dbf943eddbe6101e3ebb861d3e31ca9df85215` |
| `NetEbpfExt.sys` | `F3B2148D9778D270DB7C2E01847AAF8B15B767517672BC7E8E12E26313E13314` |
| HTTP `obi.exe` | `DAE0AA790E47210032E3CCDFD86B7354F4205F70892946C5F115BF3563C8B1AC` |
| `obi_flow_classify.sys` | `B76F0137307B49EA5A85E10187CA6B04FB9AACE106CD5D9FDDA749BDC3EA590D` |
| HTTP client | `15E97D980A3D6DED4ECF5D331DC405E67997479B1B64D28F053AECB68802C42B` |
| HTTP target | `4E9AF304EE9780233DE0346D1F60F8F6389E696F532B4F8DCC4201A487FCA684` |

The ignored evidence bundle is
`artifacts/evidence-linked-final-20260727T181918Z/`. It contains raw and
sanitized Collector output, client, target, OBI, build, deployment, cleanup,
VM-state, crash-analysis, rollback, and checksum evidence. All three runs
ended with empty program, map, and link tables. The four eBPF services remained
running, Packet Monitor was stopped, and no bugcheck occurred after the
corrected driver was deployed.

Run a fresh trace from elevated PowerShell after deploying the coherent
runtime with `scripts/Deploy-FlowClassifyRuntime.ps1`:

```powershell
.\scripts\Run-HTTPExample.ps1 `
    -StageDirectory C:\src\obi-linked-5cd44de5 `
    -RequestPath /linked-final-4 `
    -EvidenceDirectory C:\src\obi-linked-5cd44de5\evidence\linked-final-4
```

This remains a development PoC: it supports bounded plaintext HTTP/1.1 headers
only, does not capture bodies or TLS plaintext, and uses test-signed drivers.

## Proven result

The authoritative build ran `scripts/Build-Example.ps1` directly, completed
with exit code 0, and embedded:

```text
Version:  v0.10.0-184-g7f729162-dirty
Revision: 7f729162a07a3872cad8ba7bd0ed8f441cde6956
```

The fresh acceptance run then used only that build and exited successfully:

```text
SUCCESS target_pid=7608 trace_id=a0d9c4adf4d1ea8ec1bb15439228598c span_id=0c3ddc6171d60c6a

ID  Pins  Links  Mode    Type     Name
104 0     1      NATIVE  process  obi_process_start

Trace ID   : a0d9c4adf4d1ea8ec1bb15439228598c
ID         : 0c3ddc6171d60c6a
Name       : process.start obi-windows-target.exe
Start time : 2026-07-25 01:35:21.564791 +0000 UTC
End time   : 2026-07-25 01:35:21.564791 +0000 UTC
process.pid: Int(7608)
process.executable.name: Str(obi-windows-target.exe)
process.executable.path: Str(\??\C:\src\obi-artifacts\canonical-final-20260725T013300Z\obi-windows-target.exe)
```

The Collector reported this exact resource:

```text
service.name: Str(obi-windows-target.exe)
service.instance.id: Str(7608)
host.name: Str(WinDev2407Eval)
os.type: Str(windows)
telemetry.sdk.language: Str(generic)
telemetry.sdk.name: Str(opentelemetry)
telemetry.sdk.version: Str(v1.44.0)
telemetry.distro.name: Str(opentelemetry-ebpf-instrumentation)
telemetry.distro.version: Str(v0.10.0-184-g7f729162-dirty)
otel.scope.name: Str(go.opentelemetry.io/obi)
InstrumentationScope
```

`host.id` was absent. The pdata instrumentation-scope name, version, and schema
URL were empty, matching normal OBI at the exact base commit. The complete
integrity-bound evidence is in
`artifacts/evidence/obi-canonical-identity-20260725T013500Z/`.

The harness accepts the trace only when:

- `netsh ebpf show programs` reports `obi_process_start` as `NATIVE`, with one
  link and program type `process`;
- the exact canonical resource-key set and values are present, with no
  `host.id`;
- the scope is empty and contains exactly one span;
- the target, OBI log, and Collector have the same PID;
- OBI and the Collector have identical trace and span IDs;
- the NT-prefixed event path normalizes to the launched target;
- FILETIME and span time differ by no more than 100 ms; and
- the span name, kind, status, event source, and timestamps are exact.

The harness caches each Windows process handle immediately after launch. This
works around Windows PowerShell 5 losing `ExitCode` for a short-lived redirected
process. Both the target and OBI exit codes must be observed and equal zero.

### Why `telemetry.sdk.name` is `opentelemetry`

This is normal OBI identity, not evidence that the span came from a generic
SDK sender. `telemetry.sdk.name=opentelemetry` identifies the OpenTelemetry Go
SDK. OBI identifies its distribution with
`telemetry.distro.name=opentelemetry-ebpf-instrumentation` and its reporter with
the resource attribute `otel.scope.name=go.opentelemetry.io/obi`.

Normal OBI at this commit leaves the pdata `InstrumentationScope` name and
version empty. The Windows path deliberately shares the same resource and
pdata builders instead of inventing a different scope.

### Accepted artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| `obi.exe` | `17C41618181DF5536A66373AC089601F147DE74440B875BA22889A107C797E4D` |
| `obi-windows-target.exe` | `20AA7A850D2A43A54CE7C8FB0C1C2D5731EC06167CD63A9F3B19ABD681254334` |
| `obi_process_start.o` | `5BB376DE40FDF46078D0B8A036E6D46C64BC9C0061AFF078F93B7591E7618428` |
| `obi_process_start.sys` | `D29B0EAFF2FD340D9891C745B95FF915AE5651B0CC4DC9569BD53FA1BB52210F` |
| `obi-build-metadata.json` | `5A0A054B2C2797459B7900DB12A62CEC6DE1A615F8109377E9377952C106B7B5` |
| `Build-Example.ps1` | `278455753F01DD7330FC69A1E2FF69BACB4D0A798D5EE2EC58A74AB6DAE50F1D` |
| `Run-Example.ps1` | `A8D1A7B1754951E066089600D5DEB901D6108E4DC27F698BB86CF8151DD80FCF` |

## Tested versions

| Component | Tested version |
| --- | --- |
| Windows | Windows 11 Enterprise Evaluation 10.0.22621 |
| OBI base commit | `7f729162a07a3872cad8ba7bd0ed8f441cde6956` |
| OBI evidence version | `v0.10.0-184-g7f729162-dirty` |
| OpenTelemetry Go SDK | v1.44.0 |
| eBPF-for-Windows | v1.3 source commit `fe1ed176d2410569995a953fccdd3a7bad6f7136` |
| ntosebpfext | commit `bb41d8b10c488a28d98c874b1b1a55f40f22dc44` |
| Go | 1.25.11 windows/amd64 |
| LLVM/Clang | 18.1.8 |
| Visual Studio | 17.14.37516.0 |
| WDK | 10.0.26100 |
| OpenTelemetry Collector Contrib | 0.151.0 |

## Prerequisites

Run these steps from an elevated Windows PowerShell session.

- Install eBPF-for-Windows v1.3.
- Enable Windows test-signing mode for this development VM.
- Install Go, LLVM, Visual Studio C++ build tools, the Windows SDK, and the
  Visual Studio component `Component.Microsoft.Windows.DriverKit`.
- Check out the matching eBPF-for-Windows and ntosebpfext sources at the commits
  above.
- Build and install `ntosebpfext`.

The native probe is signed with a self-signed WDK test certificate. The build
script accepts that certificate only when the embedded signer is present, the
failure is specifically an untrusted WDK test root, and `bcdedit` reports
`testsigning Yes`. This does not establish production or HVCI signing
readiness.

## Build and install ntosebpfext

The process hook is supplied by
[Microsoft's ntosebpfext project](https://github.com/microsoft/ntosebpfext),
not by the core eBPF-for-Windows v1.3 installation.

The commands used for the proven build were:

```powershell
$ntos = 'C:\src\ntosebpfext'
$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'

git -C $ntos checkout bb41d8b10c488a28d98c874b1b1a55f40f22dc44

powershell.exe -ExecutionPolicy Bypass `
    -File "$ntos\scripts\initialize_repo.ps1"

powershell.exe -ExecutionPolicy Bypass `
    -File "$ntos\scripts\generate-commitid.ps1" `
    "$ntos\include"

$wdkPackage = Get-ChildItem `
    "$env:USERPROFILE\.nuget\packages\microsoft.windows.wdk.x64" `
    -Directory |
    Sort-Object Name -Descending |
    Select-Object -First 1
$wdkBin = Join-Path $wdkPackage.FullName 'c\bin\10.0.26100.0'
$env:Path = "$wdkBin\x64;$wdkBin\x86;$env:Path"

& $msbuild `
    "$ntos\ebpf_extensions\ntosebpfext\sys\ntosebpfext.vcxproj" `
    /m `
    /p:Configuration=Release `
    /p:Platform=x64 `
    "/p:SolutionDir=$ntos\"

powershell.exe -ExecutionPolicy Bypass `
    -File "$ntos\scripts\Install-Extension.ps1" `
    -Action Install `
    -Extension ntosebpfext `
    -BinaryDirectory "$ntos\x64\Release" `
    -Verbose

& "$ntos\x64\Release\ntos_ebpf_ext_export_program_info.exe"
Get-Service ntosebpfext
```

Use 64-bit MSBuild. The 32-bit executable made the WDK verifier search for the
wrong `InfVerif.dll` architecture in the tested environment.

## Build OBI and the native probe

From this example directory:

```powershell
.\scripts\Build-Example.ps1 `
    -EbpfForWindowsSource C:\src\ebpf-for-windows `
    -NtosEbpfExtSource C:\src\ntosebpfext `
    -OutputDirectory C:\src\obi-artifacts\obi-canonical-build
```

The script:

- runs `go test ./cmd/obi`;
- builds `obi.exe` and the deterministic target;
- compiles and verifies `bpf/obi_process_start.c`;
- rejects external source commits other than the pinned eBPF-for-Windows and
  ntosebpfext revisions, or either checkout with tracked changes;
- fails unless the effective Go target is `windows/amd64`, records it in build
  metadata, and checks the finished `obi.exe` reports the same target;
- regenerates the official eBPF-for-Windows v1.3
  `Convert-BpfToNative.ps1`;
- builds with the real `WindowsKernelModeDriver10.0` toolset; and
- verifies the production or explicitly constrained test-signature state and
  records installed `bpf2c.exe` and `EbpfApi.dll` hashes and versions.

For a dirty development proof, the default release metadata is deliberately:

```text
Version  = git describe --tags --always --dirty
Revision = full git rev-parse HEAD
```

This differs from the branch-sensitive Makefile default
(`git describe --all`, plus a short revision). It is intentional: the evidence
version states that the source is dirty, while the full revision binds the
changes to an immutable base. Both values are injected through the normal OBI
`pkg/buildinfo` linker symbols.

The accepted artifact hashes are recorded in
`artifacts/evidence/obi-canonical-identity-20260725T013500Z/manifest.json`.

## Download the Collector

```powershell
.\scripts\Get-Collector.ps1
```

This downloads Collector Contrib 0.151.0 from the official release and requires
the pinned archive SHA-256
`38BE8AD3222D02A50EA895385EE90AC0CA9E241EA13AF8FC06800B40C0E541D1`.

## Run the trace

With the scripts' default artifact directories:

```powershell
$metadata = Get-Content -Raw .\artifacts\obi-build-metadata.json |
    ConvertFrom-Json

.\scripts\Run-Example.ps1 `
    -ProcessProgram .\artifacts\obi_process_start.sys `
    -ExpectedReleaseVersion $metadata.version `
    -ExpectedReleaseRevision $metadata.revision
```

For explicit locations:

```powershell
$build = 'C:\src\obi-artifacts\obi-canonical-build'
$metadata = Get-Content -Raw "$build\obi-build-metadata.json" |
    ConvertFrom-Json

.\scripts\Run-Example.ps1 `
    -ProcessProgram "$build\obi_process_start.sys" `
    -Obi "$build\obi.exe" `
    -Target "$build\obi-windows-target.exe" `
    -Collector C:\src\obi-artifacts\collector\otelcol-contrib.exe `
    -CollectorConfig .\collector.yaml `
    -EvidenceDirectory C:\src\obi-artifacts\evidence\obi-canonical-run `
    -ExpectedReleaseVersion $metadata.version `
    -ExpectedReleaseRevision $metadata.revision
```

The script starts the Collector and OBI, waits until the native program is
attached, captures live `netsh` program and map tables, launches the
deterministic target, checks the exact resource, scope, process, timing, and ID
relationships, writes `acceptance.json`, and stops only the child processes it
created.

## Validation

The final Windows build and run used the scripts and artifact hashes listed
above:

- `Build-Example.ps1` exited 0, recorded `go_target.os=windows` and
  `go_target.arch=amd64`, and produced an `obi.exe` whose Go metadata reports
  `GOOS=windows` and `GOARCH=amd64`.
- A negative build with inherited `GOOS=linux` failed at the target guard and
  did not create `obi.exe`.
- `go test -count=1 ./cmd/obi` passed on Windows, and all three example
  PowerShell scripts parsed without errors.
- The final acceptance run observed zero exit codes for the target and OBI,
  matched OBI and Collector trace/span IDs, and passed every resource, scope,
  native-program, process, and timing assertion.
- Certificate-store and `bcdedit` snapshots were identical before and after
  the authoritative build. Certificate stores were also unchanged across the
  final run.

The shared Go implementation was independently validated on a frozen Linux
snapshot:

- the targeted race suite passed in 139.37 seconds;
- `GOFLAGS=-p=2 make verify` passed in 433.94 seconds with a full Node binary
  on `PATH`; and
- `make compile` produced a static Linux/amd64 ELF with SHA-256
  `EF4E6367D079EF2A84048C25EE51E3BD912966E762F1364BC93DF1585008EF48`.

That Linux ELF is a cross-platform regression check, not the Windows
deliverable. The initial unbounded verification exposed a load-sensitive
Kubernetes envtest deadline and Ubuntu's stripped `/usr/bin/node`; exact
isolated reruns passed, and the failed and successful logs are both retained.
The final changes after that frozen snapshot were limited to the PowerShell
build/run guards and this documentation, then validated on Windows.

## Implementation map

- `bpf/obi_process_start.c` emits PID, FILETIME creation time, operation, and
  the UTF-16 image path through `process_events`.
- `cmd/obi/process_windows.go` loads the native `.sys`, attaches to the process
  GUID, decodes the event, creates an OBI request span, and sends OTLP/HTTP
  protobuf.
- `pkg/export/otel/resourceattrs/resourceattrs.go` is the shared normal/Windows
  OBI resource builder.
- `pkg/export/otel/tracesgen/trace_builder.go` is the shared pdata trace
  builder. It preserves normal OBI's empty instrumentation scope and reporter
  resource attribute.
- `pkg/export/otel/tracesgen/tracesgen_windows.go` retains the OBI
  grouping and sampling boundary for manual process spans without importing
  Linux discovery, procfs, or Kubernetes dependencies.
- `pkg/ebpf/timing/timing_windows.go` supplies the process-local monotonic clock
  used to translate the event's FILETIME to OBI span timing.

## Limits

- Only process-start events are implemented.
- The Windows `cmd/obi` entry point is a proof-of-concept CLI, not the complete
  Linux OBI CLI.
- The Windows trace generator is intentionally limited to manual process spans.
- The `ntosebpfext` process provider is an external dependency.
- Windows deliberately omits `host.id`; it does not fabricate an identifier
  from `host.name`. A future port can add a stable Windows machine identifier.
- The native drivers are development test-signed. Do not treat the artifacts as
  production-signed or HVCI certification evidence.
- The proof used Windows test-signing. Certificate-store and `bcdedit`
  snapshots before and after the authoritative build were identical; the WDK
  test signer remained untrusted.
- Existing untagged tests for the full Linux `tracesgen` implementation are not
  Windows-compatible. Windows validates `go test ./cmd/obi`; the full shared
  implementation is validated on Linux.
