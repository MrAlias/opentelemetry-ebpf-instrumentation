[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$StageDirectory,

    [string]$Collector = 'C:\src\obi-artifacts\collector\otelcol-contrib.exe',

    [string]$Traceparent = '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',

    [string]$RequestPath = '/linked',

    [int]$Port = 18080,

    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'

if (-not $EvidenceDirectory) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $EvidenceDirectory = Join-Path $StageDirectory "evidence\windows-http-$stamp"
}

$processProgram = Join-Path $StageDirectory 'obi_process_start.sys'
$flowProgram = Join-Path $StageDirectory 'obi_flow_classify.sys'
$obiExecutable = Join-Path $StageDirectory 'obi.exe'
$targetExecutable = Join-Path $StageDirectory 'obi-windows-http-target.exe'
$collectorConfig = Join-Path $StageDirectory 'collector.yaml'
$collectorStdout = Join-Path $EvidenceDirectory 'collector.stdout.log'
$collectorStderr = Join-Path $EvidenceDirectory 'collector.stderr.log'
$obiStdout = Join-Path $EvidenceDirectory 'obi.stdout.log'
$obiStderr = Join-Path $EvidenceDirectory 'obi.stderr.log'
$targetStdout = Join-Path $EvidenceDirectory 'target.stdout.log'
$targetStderr = Join-Path $EvidenceDirectory 'target.stderr.log'
$responsePath = Join-Path $EvidenceDirectory 'response.txt'
$clientStages = Join-Path $EvidenceDirectory 'client-stages.log'
$liveStatePath = Join-Path $EvidenceDirectory 'ebpf-live.txt'
$cleanupStatePath = Join-Path $EvidenceDirectory 'ebpf-cleanup.txt'
$summaryPath = Join-Path $EvidenceDirectory 'acceptance.json'

function Wait-LogPattern {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [int]$Seconds = 10
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 100
        $content = if (Test-Path -LiteralPath $Path) {
            Get-Content -Raw -LiteralPath $Path
        } else {
            ''
        }
        if ($Process.HasExited) {
            throw "Process $($Process.Id) exited while waiting for $Pattern`: $content"
        }
    } until ($content -match $Pattern -or (Get-Date) -gt $deadline)

    if ($content -notmatch $Pattern) {
        throw "Timed out waiting for $Pattern in $Path"
    }
}

function Wait-TcpPort {
    param(
        [Parameter(Mandatory)]
        [int]$Port,

        [int]$Seconds = 15
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $connect = $client.ConnectAsync('127.0.0.1', $Port)
            if ($connect.Wait(200) -and $client.Connected) {
                return
            }
        } catch {
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 100
    } until ((Get-Date) -gt $deadline)

    throw "Timed out waiting for TCP port $Port"
}

function Get-EbpfState {
    @(
        'PROGRAMS'
        (netsh.exe ebpf show programs | Out-String)
        'MAPS'
        (netsh.exe ebpf show maps | Out-String)
        'LINKS'
        (netsh.exe ebpf show links | Out-String)
    )
}

function Assert-CleanEbpfState {
    param(
        [Parameter(Mandatory)]
        [string]$State
    )

    if ($State -match '(?m)^\s*\d+\s+') {
        throw 'Programs, maps, or links remain after the acceptance run'
    }
}

function Send-RawRequest {
    $request = "GET $RequestPath HTTP/1.1`r`n" +
        "Host: 127.0.0.1:$Port`r`n" +
        "traceparent: $Traceparent`r`n" +
        "Connection: close`r`n`r`n"
    $client = [Net.Sockets.TcpClient]::new()
    try {
        "connect-start $(Get-Date -Format o)" |
            Add-Content -LiteralPath $clientStages -Encoding UTF8
        $connect = $client.ConnectAsync('127.0.0.1', $Port)
        if (-not $connect.Wait(5000)) {
            throw "TCP connect to 127.0.0.1:$Port timed out"
        }
        "connect-complete $(Get-Date -Format o)" |
            Add-Content -LiteralPath $clientStages -Encoding UTF8
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $stream.WriteTimeout = 5000
        $bytes = [Text.Encoding]::ASCII.GetBytes($request)
        "write-start bytes=$($bytes.Length) $(Get-Date -Format o)" |
            Add-Content -LiteralPath $clientStages -Encoding UTF8
        $stream.Write($bytes, 0, $bytes.Length)
        "write-complete $(Get-Date -Format o)" |
            Add-Content -LiteralPath $clientStages -Encoding UTF8

        $buffer = New-Object byte[] 4096
        $response = New-Object IO.MemoryStream
        do {
            "read-start $(Get-Date -Format o)" |
                Add-Content -LiteralPath $clientStages -Encoding UTF8
            $count = $stream.Read($buffer, 0, $buffer.Length)
            "read-complete bytes=$count $(Get-Date -Format o)" |
                Add-Content -LiteralPath $clientStages -Encoding UTF8
            if ($count -le 0) {
                break
            }
            $response.Write($buffer, 0, $count)
            $responseText = [Text.Encoding]::ASCII.GetString($response.ToArray())
        } until ($responseText.Contains("`r`n`r`n"))

        $responseText
    } finally {
        $client.Dispose()
    }
}

foreach ($requiredPath in @(
    $Collector,
    $collectorConfig,
    $processProgram,
    $flowProgram,
    $obiExecutable,
    $targetExecutable
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file does not exist: $requiredPath"
    }
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535: $Port"
}
if ($Traceparent -notmatch '^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$') {
    throw "Traceparent must be a lowercase W3C version 00 value: $Traceparent"
}

$expectedTraceId = $Matches[1]
$expectedParentSpanId = $Matches[2]
if ($expectedTraceId -eq ('0' * 32) -or $expectedParentSpanId -eq ('0' * 16)) {
    throw 'Traceparent IDs must be nonzero'
}
if (Test-Path -LiteralPath $EvidenceDirectory) {
    throw "Evidence directory already exists: $EvidenceDirectory"
}

New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null

$collectorProcess = $null
$obiProcess = $null
$targetProcess = $null
$completed = $false

try {
    $collectorProcess = Start-Process -FilePath $Collector `
        -ArgumentList "--config=$collectorConfig" `
        -RedirectStandardOutput $collectorStdout `
        -RedirectStandardError $collectorStderr `
        -PassThru
    Wait-LogPattern -Process $collectorProcess `
        -Path $collectorStderr `
        -Pattern 'Everything is ready'
    Wait-TcpPort -Port 4318
    if ($collectorProcess.HasExited) {
        throw "Collector exited: $(Get-Content -Raw -LiteralPath $collectorStderr)"
    }

    $obiArguments = @(
        '-process-program', $processProgram,
        '-flow-program', $flowProgram,
        '-target-exe', 'obi-windows-http-target.exe',
        '-target-port', $Port,
        '-otlp-endpoint', 'http://127.0.0.1:4318/v1/traces',
        '-timeout', '30s',
        '-once=true'
    )
    $obiProcess = Start-Process -FilePath $obiExecutable `
        -ArgumentList $obiArguments `
        -RedirectStandardOutput $obiStdout `
        -RedirectStandardError $obiStderr `
        -PassThru
    Wait-LogPattern -Process $obiProcess `
        -Path $obiStdout `
        -Pattern 'attached native eBPF programs'

    Get-EbpfState |
        Set-Content -LiteralPath $liveStatePath -Encoding UTF8

    $targetProcess = Start-Process -FilePath $targetExecutable `
        -RedirectStandardOutput $targetStdout `
        -RedirectStandardError $targetStderr `
        -PassThru
    Wait-LogPattern -Process $targetProcess `
        -Path $targetStdout `
        -Pattern 'PID='
    Wait-LogPattern -Process $obiProcess `
        -Path $obiStdout `
        -Pattern 'configured Windows HTTP target from native process event'

    Send-RawRequest |
        Set-Content -LiteralPath $responsePath -Encoding Ascii -NoNewline

    if (-not $targetProcess.WaitForExit(10000)) {
        throw 'HTTP target did not exit after the request'
    }
    if (-not $obiProcess.WaitForExit(15000)) {
        throw 'OBI did not exit after exporting the HTTP span'
    }
    $targetProcess.Refresh()
    $obiProcess.Refresh()

    if ($null -ne $targetProcess.ExitCode -and $targetProcess.ExitCode -ne 0) {
        throw "HTTP target failed: $(Get-Content -Raw -LiteralPath $targetStderr)"
    }
    if ($null -ne $obiProcess.ExitCode -and $obiProcess.ExitCode -ne 0) {
        throw "OBI failed: $(Get-Content -Raw -LiteralPath $obiStdout)"
    }

    Start-Sleep -Seconds 2
    $obiLog = Get-Content -Raw -LiteralPath $obiStdout
    $targetLog = Get-Content -Raw -LiteralPath $targetStdout
    $expectedTargetLog = "served GET $RequestPath status=204"
    if (-not $targetLog.Contains($expectedTargetLog)) {
        throw "HTTP target did not report the expected request: $targetLog"
    }
    if ($obiLog -notmatch 'OpenTelemetry eBPF Instrumentation successfully exiting') {
        throw "OBI did not report a successful exit: $obiLog"
    }
    $collectorLog = @(
        Get-Content -Raw -LiteralPath $collectorStdout
        Get-Content -Raw -LiteralPath $collectorStderr
    ) -join "`n"
    $response = Get-Content -Raw -LiteralPath $responsePath

    $exportMatch = [Regex]::Match(
        $obiLog,
        'exported OBI Windows HTTP server trace.*' +
            'trace_id=([0-9a-f]{32}).*' +
            'parent_span_id=([0-9a-f]{16}).*' +
            'span_id=([0-9a-f]{16})'
    )
    if (-not $exportMatch.Success) {
        throw 'OBI did not log a completed Windows HTTP server trace'
    }

    $actualTraceId = $exportMatch.Groups[1].Value
    $actualParentSpanId = $exportMatch.Groups[2].Value
    $actualSpanId = $exportMatch.Groups[3].Value
    if ($actualTraceId -ne $expectedTraceId) {
        throw "OBI trace ID mismatch: $actualTraceId"
    }
    if ($actualParentSpanId -ne $expectedParentSpanId) {
        throw "OBI parent span ID mismatch: $actualParentSpanId"
    }
    if ($actualSpanId -eq ('0' * 16) -or $actualSpanId -eq $expectedParentSpanId) {
        throw "OBI generated an invalid server span ID: $actualSpanId"
    }

    $collectorChecks = @(
        [Regex]::Escape($expectedTraceId),
        [Regex]::Escape($expectedParentSpanId),
        [Regex]::Escape($actualSpanId),
        'Kind\s*:\s*Server',
        'telemetry\.sdk\.name.*opentelemetry',
        'telemetry\.distro\.name.*opentelemetry-ebpf-instrumentation',
        'http\.request\.method.*GET',
        'http\.response\.status_code.*204',
        'url\.path.*/linked'
    )
    foreach ($check in $collectorChecks) {
        if ($collectorLog -notmatch $check) {
            throw "Collector output is missing expected value: $check"
        }
    }
    if ($response -notmatch '^HTTP/1\.1 204 No Content') {
        throw "Unexpected HTTP response: $response"
    }

    $summary = [ordered]@{
        accepted = $true
        traceparent = $Traceparent
        trace_id = $actualTraceId
        parent_span_id = $actualParentSpanId
        span_id = $actualSpanId
        method = 'GET'
        path = $RequestPath
        status_code = 204
        span_kind = 'SERVER'
        telemetry_sdk_name = 'opentelemetry'
        telemetry_distro_name = 'opentelemetry-ebpf-instrumentation'
        evidence_directory = $EvidenceDirectory
    }
    $summary |
        ConvertTo-Json |
        Set-Content -LiteralPath $summaryPath -Encoding UTF8
    $completed = $true
} finally {
    foreach ($process in @($targetProcess, $obiProcess, $collectorProcess)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500

    $cleanupState = Get-EbpfState | Out-String
    $cleanupState |
        Set-Content -LiteralPath $cleanupStatePath -Encoding UTF8
    Assert-CleanEbpfState -State $cleanupState
}

if (-not $completed) {
    throw 'Acceptance run did not complete'
}

Get-Content -Raw -LiteralPath $summaryPath
