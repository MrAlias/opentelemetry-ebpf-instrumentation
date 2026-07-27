# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ProcessProgram,

    [string]$Obi = (Join-Path $PSScriptRoot '..\artifacts\obi.exe'),

    [string]$Target = (Join-Path $PSScriptRoot '..\artifacts\obi-windows-target.exe'),

    [string]$Collector = (Join-Path $PSScriptRoot '..\artifacts\collector\otelcol-contrib\otelcol-contrib.exe'),

    [string]$CollectorConfig = (Join-Path $PSScriptRoot '..\collector.yaml'),

    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..\artifacts\evidence'),

    [string]$ExpectedSDKVersion = 'v1.44.0',

    [Parameter(Mandatory)]
    [string]$ExpectedReleaseVersion,

    [Parameter(Mandatory)]
    [string]$ExpectedReleaseRevision
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$processProgram = [IO.Path]::GetFullPath($ProcessProgram)
$obi = [IO.Path]::GetFullPath($Obi)
$target = [IO.Path]::GetFullPath($Target)
$collector = [IO.Path]::GetFullPath($Collector)
$collectorConfig = [IO.Path]::GetFullPath($CollectorConfig)
$evidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
if (-not $ExpectedReleaseVersion -or -not $ExpectedReleaseRevision) {
    throw 'Expected release version and revision must not be empty'
}

foreach ($requiredPath in @($processProgram, $obi, $target, $collector, $collectorConfig)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required file not found: $requiredPath"
    }
}

New-Item -ItemType Directory -Force -Path $evidenceDirectory | Out-Null

$collectorStdout = Join-Path $evidenceDirectory 'collector.stdout.log'
$collectorStderr = Join-Path $evidenceDirectory 'collector.stderr.log'
$obiStdout = Join-Path $evidenceDirectory 'obi.stdout.log'
$obiStderr = Join-Path $evidenceDirectory 'obi.stderr.log'
$targetStdout = Join-Path $evidenceDirectory 'target.stdout.log'
$targetStderr = Join-Path $evidenceDirectory 'target.stderr.log'
$programsDuring = Join-Path $evidenceDirectory 'netsh-programs-during.txt'
$mapsDuring = Join-Path $evidenceDirectory 'netsh-maps-during.txt'
$linksDuring = Join-Path $evidenceDirectory 'netsh-links-during.txt'
$obiVersionInfo = Join-Path $evidenceDirectory 'obi-version.txt'
$acceptance = Join-Path $evidenceDirectory 'acceptance.json'

foreach ($logPath in @(
        $collectorStdout,
        $collectorStderr,
        $obiStdout,
        $obiStderr,
        $targetStdout,
        $targetStderr,
        $programsDuring,
        $mapsDuring,
        $linksDuring,
        $obiVersionInfo,
        $acceptance
    )) {
    if (Test-Path -LiteralPath $logPath) {
        Remove-Item -LiteralPath $logPath
    }
}

function Wait-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $connect = $client.ConnectAsync($HostName, $Port)
            if ($connect.Wait(500) -and $client.Connected) {
                return
            }
        }
        catch {
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 200
    }
    throw "Timed out waiting for ${HostName}:$Port"
}

function Wait-LogLine {
    param(
        [string[]]$Path,
        [string]$Pattern,
        [int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        foreach ($candidatePath in $Path) {
            if ((Test-Path -LiteralPath $candidatePath) -and
                (Select-String -Quiet -LiteralPath $candidatePath -Pattern $Pattern)) {
                return
            }
        }
        Start-Sleep -Milliseconds 200
    }
    throw "Timed out waiting for '$Pattern' in $($Path -join ', ')"
}

$collectorProcess = $null
$obiProcess = $null
$targetProcess = $null

try {
    $collectorConfigArgument = '--config="{0}"' -f $collectorConfig
    $collectorProcess = Start-Process -FilePath $collector `
        -ArgumentList $collectorConfigArgument `
        -RedirectStandardOutput $collectorStdout `
        -RedirectStandardError $collectorStderr `
        -WindowStyle Hidden `
        -PassThru

    Wait-TcpPort -HostName '127.0.0.1' -Port 4318 -TimeoutSeconds 30

    $processProgramArgument = '"{0}"' -f $processProgram
    $obiProcess = Start-Process -FilePath $obi `
        -ArgumentList @(
            '-process-program', $processProgramArgument,
            '-target-exe', 'obi-windows-target.exe',
            '-otlp-endpoint', 'http://127.0.0.1:4318/v1/traces',
            '-once=true',
            '-timeout=60s'
        ) `
        -RedirectStandardOutput $obiStdout `
        -RedirectStandardError $obiStderr `
        -WindowStyle Hidden `
        -PassThru
    $null = $obiProcess.Handle

    Wait-LogLine -Path $obiStdout -Pattern 'attached native eBPF program to Windows process hook' -TimeoutSeconds 30

    & netsh.exe ebpf show programs | Set-Content -LiteralPath $programsDuring
    if ($LASTEXITCODE -ne 0) {
        throw 'netsh ebpf show programs failed'
    }
    & netsh.exe ebpf show maps | Set-Content -LiteralPath $mapsDuring
    if ($LASTEXITCODE -ne 0) {
        throw 'netsh ebpf show maps failed'
    }
    & netsh.exe ebpf show links | Set-Content -LiteralPath $linksDuring
    if ($LASTEXITCODE -ne 0) {
        throw 'netsh ebpf show links failed'
    }

    & go.exe version -m $obi | Set-Content -LiteralPath $obiVersionInfo
    if ($LASTEXITCODE -ne 0) {
        throw 'go version -m failed for obi.exe'
    }

    $targetProcess = Start-Process -FilePath $target `
        -RedirectStandardOutput $targetStdout `
        -RedirectStandardError $targetStderr `
        -WindowStyle Hidden `
        -PassThru
    $null = $targetProcess.Handle

    if (-not $targetProcess.WaitForExit(30000)) {
        throw 'Timed out waiting for the deterministic target process'
    }
    $targetProcess.WaitForExit()
    $targetProcess.Refresh()
    $targetExitCode = $targetProcess.ExitCode
    $targetExitCodeObserved = $null -ne $targetExitCode
    if (-not $targetExitCodeObserved) {
        throw 'Target exit code was not observed'
    }
    if ($targetExitCode -ne 0) {
        throw "Target exited with code $targetExitCode"
    }

    if (-not $obiProcess.WaitForExit(30000)) {
        throw 'Timed out waiting for OBI to export the matching process event'
    }
    $obiProcess.WaitForExit()
    $obiProcess.Refresh()
    $obiExitCode = $obiProcess.ExitCode
    $obiExitCodeObserved = $null -ne $obiExitCode
    if (-not $obiExitCodeObserved) {
        throw 'OBI exit code was not observed'
    }
    if ($obiExitCode -ne 0) {
        throw "OBI exited with code ${obiExitCode}: $(Get-Content -Raw -LiteralPath $obiStderr)"
    }

    Wait-LogLine `
        -Path @($collectorStdout, $collectorStderr) `
        -Pattern 'process.start obi-windows-target.exe' -TimeoutSeconds 30

    $targetLog = Get-Content -Raw -LiteralPath $targetStdout
    $obiLog = Get-Content -Raw -LiteralPath $obiStdout
    if ($targetLog -notmatch '(?m)^obi-windows-target\.exe PID=(\d+)[ \t]*\r?$') {
        throw 'The deterministic target did not print its executable name and PID'
    }
    $targetPid = $Matches[1]
    if ((Get-Item -LiteralPath $targetStderr).Length -ne 0) {
        throw "The deterministic target wrote to stderr: $targetStderr"
    }
    if ($obiLog -notmatch '(?m)msg="OpenTelemetry eBPF Instrumentation successfully exiting"[ \t]*\r?$') {
        throw 'OBI did not report its normal successful exit path'
    }
    if ($obiLog -notmatch 'Version=(\S+)[ \t]+Revision=(\S+)') {
        throw 'OBI output does not contain build version and revision'
    }
    $obiVersion = $Matches[1]
    $obiRevision = $Matches[2]
    if ($obiVersion -eq 'unset' -or $obiRevision -eq 'unset') {
        throw 'OBI was built with unset version or revision metadata'
    }
    if ($obiVersion -cne $ExpectedReleaseVersion) {
        throw "OBI version $obiVersion does not match expected $ExpectedReleaseVersion"
    }
    if ($obiRevision -cne $ExpectedReleaseRevision) {
        throw "OBI revision $obiRevision does not match expected $ExpectedReleaseRevision"
    }

    if ($obiLog -notmatch "(?m)pid=$targetPid(?:[ \t]|$)") {
        throw "OBI output does not contain the deterministic target PID $targetPid"
    }
    if ($obiLog -notmatch '(?m)executable=obi-windows-target\.exe(?:[ \t]|$)') {
        throw 'OBI output does not identify the deterministic target executable'
    }
    if ($obiLog -notmatch '(?m)trace_id=([0-9a-f]{32})(?:[ \t]|$)') {
        throw 'OBI output does not contain a valid trace ID'
    }
    $traceId = $Matches[1]
    if ($obiLog -notmatch '(?m)span_id=([0-9a-f]{16})(?:[ \t]|$)') {
        throw 'OBI output does not contain a valid span ID'
    }
    $spanId = $Matches[1]

    $programSnapshot = Get-Content -Raw -LiteralPath $programsDuring
    $programMatch = [Regex]::Match($programSnapshot, '(?m)^[ \t]*(\d+)[ \t]+\d+[ \t]+(1)[ \t]+NATIVE[ \t]+process[ \t]+obi_process_start[ \t]*\r?$')
    if (-not $programMatch.Success) {
        throw 'The live netsh program snapshot does not contain obi_process_start'
    }
    $mapSnapshot = Get-Content -Raw -LiteralPath $mapsDuring
    if ($mapSnapshot -notmatch '\bprocess_events\b') {
        throw 'The live netsh map snapshot does not contain process_events'
    }

    $collectorLog = @(
        Get-Content -Raw -LiteralPath $collectorStdout
        Get-Content -Raw -LiteralPath $collectorStderr
    ) -join [Environment]::NewLine

    $resourceBlocks = @(
        [Regex]::Split($collectorLog, '(?m)(?=^[^\r\n]*ResourceSpans #\d+[ \t]*\r?$)') |
            Where-Object { $_ -match '(?m)^[^\r\n]*ResourceSpans #\d+[ \t]*\r?$' }
    )
    $matchingBlocks = @(
        $resourceBlocks |
            Where-Object {
                $_ -cmatch "(?m)^[ \t]*Trace ID[ \t]*:[ \t]*$traceId[ \t]*\r?$" -and
                $_ -cmatch "(?m)^[ \t]*ID[ \t]*:[ \t]*$spanId[ \t]*\r?$"
            }
    )
    if ($matchingBlocks.Count -ne 1) {
        throw "Collector output contains $($matchingBlocks.Count) ResourceSpans blocks with OBI trace $traceId and span $spanId"
    }
    $obiCollectorBlock = $matchingBlocks[0]
    $scopeSpansCount = [Regex]::Matches($obiCollectorBlock, '(?m)^ScopeSpans #\d+[ \t]*\r?$').Count
    $spanCount = [Regex]::Matches($obiCollectorBlock, '(?m)^Span #\d+[ \t]*\r?$').Count
    if ($scopeSpansCount -ne 1 -or $spanCount -ne 1) {
        throw 'The matching OBI ResourceSpans block does not contain exactly one scope and one span'
    }
    $collectorTraceMatch = [Regex]::Match($obiCollectorBlock, '(?m)^[ \t]*Trace ID[ \t]*:[ \t]*([0-9a-f]{32})[ \t]*\r?$')
    $collectorSpanMatch = [Regex]::Match($obiCollectorBlock, '(?m)^[ \t]*ID[ \t]*:[ \t]*([0-9a-f]{16})[ \t]*\r?$')
    if (-not $collectorTraceMatch.Success -or -not $collectorSpanMatch.Success) {
        throw 'Collector output does not contain a valid trace and span ID'
    }
    $collectorTraceId = $collectorTraceMatch.Groups[1].Value
    $collectorSpanId = $collectorSpanMatch.Groups[1].Value

    if ($obiCollectorBlock -cnotmatch "(?m)^[ \t]*->[ \t]*process\.pid:[ \t]*Int\($targetPid\)[ \t]*\r?$") {
        throw "Collector output does not associate process.pid with target PID $targetPid"
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*->[ \t]*process\.executable\.name:[ \t]*Str\(obi-windows-target\.exe\)[ \t]*\r?$') {
        throw 'Collector output is missing process.executable.name'
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*->[ \t]*process\.executable\.path:[ \t]*Str\(([^\r\n]*[\\/]obi-windows-target\.exe)\)[ \t]*\r?$') {
        throw 'Collector output is missing a nonempty process.executable.path for obi-windows-target.exe'
    }
    $targetExecutablePath = $Matches[1]
    $normalizedTargetExecutablePath = $targetExecutablePath -replace '^\\\?\?\\', ''
    $normalizedTargetExecutablePath = [IO.Path]::GetFullPath($normalizedTargetExecutablePath)
    if (-not $normalizedTargetExecutablePath.Equals($target, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Collector executable path $targetExecutablePath does not identify target $target"
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*->[ \t]*obi\.windows\.creation_filetime:[ \t]*Int\((\d+)\)[ \t]*\r?$') {
        throw 'Collector output is missing obi.windows.creation_filetime'
    }
    $creationFiletime = [int64]$Matches[1]
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*->[ \t]*obi\.windows\.process\.event_source:[ \t]*Str\(ntosebpfext/process\)[ \t]*\r?$') {
        throw 'Collector output is missing the ntosebpfext process event source'
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*Kind[ \t]*:[ \t]*Internal[ \t]*\r?$') {
        throw 'Collector output does not identify the span kind as Internal'
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*Status code[ \t]*:[ \t]*Unset[ \t]*\r?$') {
        throw 'Collector output does not identify the span status as Unset'
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*Status message[ \t]*:[ \t]*\r?$') {
        throw 'Collector output contains a nonempty span status message'
    }

    $resourceSectionMatch = [Regex]::Match(
        $obiCollectorBlock,
        '(?ms)^Resource attributes:[ \t]*\r?\n(?<attributes>.*?)^ScopeSpans #\d+[ \t]*\r?$'
    )
    if (-not $resourceSectionMatch.Success) {
        throw 'Collector output does not contain a bounded resource attribute section'
    }
    $resourceAttributesBlock = $resourceSectionMatch.Groups['attributes'].Value

    $expectedResourceAttributes = [ordered]@{
        'service.name' = 'obi-windows-target.exe'
        'service.instance.id' = $targetPid
        'os.type' = 'windows'
        'telemetry.sdk.language' = 'generic'
        'telemetry.sdk.name' = 'opentelemetry'
        'telemetry.sdk.version' = $ExpectedSDKVersion
        'telemetry.distro.name' = 'opentelemetry-ebpf-instrumentation'
        'telemetry.distro.version' = $obiVersion
        'otel.scope.name' = 'go.opentelemetry.io/obi'
    }
    foreach ($entry in $expectedResourceAttributes.GetEnumerator()) {
        $escapedKey = [Regex]::Escape($entry.Key)
        $escapedValue = [Regex]::Escape([string]$entry.Value)
        if ($resourceAttributesBlock -cnotmatch "(?m)^[ \t]*->[ \t]*${escapedKey}:[ \t]*Str\(${escapedValue}\)[ \t]*\r?$") {
            throw "Collector output is missing canonical resource $($entry.Key)=$($entry.Value)"
        }
    }
    $expectedHostName = [System.Net.Dns]::GetHostName()
    $escapedHostName = [Regex]::Escape($expectedHostName)
    if ($resourceAttributesBlock -cnotmatch "(?m)^[ \t]*->[ \t]*host\.name:[ \t]*Str\(${escapedHostName}\)[ \t]*\r?$") {
        throw "Collector host.name does not equal the Windows host name $expectedHostName"
    }
    $hostName = $expectedHostName
    $observedResourceKeys = @(
        [Regex]::Matches(
            $resourceAttributesBlock,
            '(?m)^[ \t]*->[ \t]*([^:\r\n]+):'
        ) |
            ForEach-Object { $_.Groups[1].Value.Trim() }
    )
    $expectedResourceKeys = @($expectedResourceAttributes.Keys) + 'host.name'
    $resourceKeyDifference = Compare-Object $expectedResourceKeys $observedResourceKeys -CaseSensitive
    if ($resourceKeyDifference) {
        throw "Collector resource keys differ from canonical OBI keys: $($resourceKeyDifference | Out-String)"
    }
    if ($resourceAttributesBlock -cmatch '(?m)^[ \t]*->[ \t]*host\.id:') {
        throw 'Collector output contains host.id even though the Windows frontend omitted it'
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*InstrumentationScope[ \t]*\r?$') {
        throw 'Collector output does not contain the canonical empty OBI instrumentation scope'
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^ScopeSpans SchemaURL:[ \t]*\r?$') {
        throw 'Collector output contains a nonempty instrumentation scope schema URL'
    }
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*Name[ \t]*:[ \t]*(process\.start obi-windows-target\.exe)[ \t]*\r?$') {
        throw 'Collector output is missing the expected process-start span name'
    }
    $spanName = $Matches[1]
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*Start[ \t]+time[ \t]*:[ \t]*(\S[^\r\n]*)\r?$') {
        throw 'Collector output is missing the span start timestamp'
    }
    $spanStartTime = $Matches[1].TrimEnd()
    if ($obiCollectorBlock -cnotmatch '(?m)^[ \t]*End[ \t]+time[ \t]*:[ \t]*(\S[^\r\n]*)\r?$') {
        throw 'Collector output is missing the span end timestamp'
    }
    $spanEndTime = $Matches[1].TrimEnd()
    if ($spanStartTime -ne $spanEndTime) {
        throw "Process-start span timestamps differ: $spanStartTime, $spanEndTime"
    }
    $collectorStartTime = [DateTimeOffset]::Parse(
        ($spanStartTime -replace '[ \t]+UTC$', ''),
        [Globalization.CultureInfo]::InvariantCulture
    ).UtcDateTime
    $eventCreationTime = [DateTime]::FromFileTimeUtc($creationFiletime)
    $eventToSpanDeltaMilliseconds = [Math]::Abs(
        ($eventCreationTime - $collectorStartTime).TotalMilliseconds
    )
    if ($eventToSpanDeltaMilliseconds -gt 100) {
        throw "Process event FILETIME differs from the span timestamp by $eventToSpanDeltaMilliseconds ms"
    }

    [ordered]@{
        accepted_utc = [DateTime]::UtcNow.ToString('o')
        target_pid = [int]$targetPid
        target_executable = 'obi-windows-target.exe'
        target_exit_code = $targetExitCode
        target_exit_code_observed = $targetExitCodeObserved
        obi_pid = $obiProcess.Id
        obi_exit_code = $obiExitCode
        obi_exit_code_observed = $obiExitCodeObserved
        obi_trace_id = $traceId
        obi_span_id = $spanId
        collector_trace_id = $collectorTraceId
        collector_span_id = $collectorSpanId
        span_name = $spanName
        start_time = $spanStartTime
        end_time = $spanEndTime
        obi_version = $obiVersion
        obi_revision = $obiRevision
        telemetry_sdk_version = $ExpectedSDKVersion
        resource_attributes = [ordered]@{
            expected = $expectedResourceAttributes
            host_name = $hostName
            host_id_omitted = $true
        }
        instrumentation_scope = [ordered]@{
            scope_spans_count = $scopeSpansCount
            span_count = $spanCount
            name = ''
            version = ''
            schema_url = ''
        }
        process_attributes = [ordered]@{
            pid = [int]$targetPid
            executable_name = 'obi-windows-target.exe'
            executable_path = $targetExecutablePath
            normalized_executable_path = $normalizedTargetExecutablePath
            creation_filetime = $creationFiletime
            event_source = 'ntosebpfext/process'
            event_creation_utc = $eventCreationTime.ToString('o')
            event_to_span_delta_milliseconds = $eventToSpanDeltaMilliseconds
            span_kind = 'Internal'
            span_status = 'Unset'
        }
        native_program = [ordered]@{
            id = [int]$programMatch.Groups[1].Value
            link_count = [int]$programMatch.Groups[2].Value
            mode = 'NATIVE'
            type = 'process'
            name = 'obi_process_start'
        }
    } |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $acceptance -Encoding UTF8

    Write-Host "SUCCESS target_pid=$targetPid trace_id=$traceId span_id=$spanId"
    Get-Content -LiteralPath $obiStdout
    Get-Content -LiteralPath $programsDuring
    Get-Content -LiteralPath $collectorStdout, $collectorStderr |
        Select-String -Pattern 'ResourceSpans|Trace ID|^[ \t]*ID[ \t]*:|process.start|process.pid|process.executable|Start time|End time|service\.|host\.|os\.type|telemetry\.|otel\.scope|InstrumentationScope'
}
finally {
    foreach ($process in @($targetProcess, $obiProcess, $collectorProcess)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
        }
    }
}
