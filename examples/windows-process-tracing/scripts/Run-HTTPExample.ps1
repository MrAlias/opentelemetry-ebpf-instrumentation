[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$StageDirectory,

    [string]$Collector = 'C:\src\obi-artifacts\collector\otelcol-contrib.exe',

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
$clientExecutable = Join-Path $StageDirectory 'obi-windows-http-client.exe'
$collectorConfig = Join-Path $StageDirectory 'collector.yaml'
$collectorStdout = Join-Path $EvidenceDirectory 'collector.stdout.log'
$collectorStderr = Join-Path $EvidenceDirectory 'collector.stderr.log'
$obiStdout = Join-Path $EvidenceDirectory 'obi.stdout.log'
$obiStderr = Join-Path $EvidenceDirectory 'obi.stderr.log'
$targetStdout = Join-Path $EvidenceDirectory 'target.stdout.log'
$targetStderr = Join-Path $EvidenceDirectory 'target.stderr.log'
$clientStdout = Join-Path $EvidenceDirectory 'client.stdout.log'
$clientStderr = Join-Path $EvidenceDirectory 'client.stderr.log'
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

function Get-CollectorSpanBlock {
    param(
        [Parameter(Mandatory)]
        [string]$Log,

        [Parameter(Mandatory)]
        [string]$SpanId
    )

    $spanMatch = [Regex]::Match(
        $Log,
        '(?m)^\s*ID\s+:\s*' + [Regex]::Escape($SpanId) + '\s*$'
    )
    if (-not $spanMatch.Success) {
        throw "Collector output has no span with ID $SpanId"
    }

    $start = $Log.LastIndexOf('ResourceSpans #', $spanMatch.Index, [StringComparison]::Ordinal)
    if ($start -lt 0) {
        throw "Collector span $SpanId has no resource block"
    }
    $next = $Log.IndexOf(
        'ResourceSpans #',
        $spanMatch.Index + $spanMatch.Length,
        [StringComparison]::Ordinal
    )
    if ($next -lt 0) {
        return $Log.Substring($start)
    }
    return $Log.Substring($start, $next - $start)
}

foreach ($requiredPath in @(
    $Collector,
    $collectorConfig,
    $processProgram,
    $flowProgram,
    $obiExecutable,
    $targetExecutable,
    $clientExecutable
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file does not exist: $requiredPath"
    }
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535: $Port"
}
if (Test-Path -LiteralPath $EvidenceDirectory) {
    throw "Evidence directory already exists: $EvidenceDirectory"
}

New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null

$collectorProcess = $null
$obiProcess = $null
$targetProcess = $null
$clientProcess = $null
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

    $targetUrl = "http://127.0.0.1:$Port$RequestPath"
    $clientArguments = @(
        '-otlp-endpoint', 'http://127.0.0.1:4318/v1/traces',
        '-url', $targetUrl,
        '-timeout', '15s'
    )
    $clientProcess = Start-Process -FilePath $clientExecutable `
        -ArgumentList $clientArguments `
        -RedirectStandardOutput $clientStdout `
        -RedirectStandardError $clientStderr `
        -PassThru
    if (-not $clientProcess.WaitForExit(20000)) {
        throw 'Instrumented HTTP client did not exit after the request'
    }
    $clientProcess.Refresh()
    if ($null -ne $clientProcess.ExitCode -and $clientProcess.ExitCode -ne 0) {
        throw "Instrumented HTTP client failed: $(Get-Content -Raw -LiteralPath $clientStderr)"
    }
    $clientResult = Get-Content -Raw -LiteralPath $clientStdout | ConvertFrom-Json
    if ($clientResult.span_kind -ne 'client' -or $clientResult.status_code -ne 204) {
        throw "Instrumented HTTP client returned an unexpected result: $($clientResult | ConvertTo-Json -Compress)"
    }

    if (-not $targetProcess.WaitForExit(10000)) {
        throw 'HTTP target did not exit after the request'
    }
    if (-not $obiProcess.WaitForExit(15000)) {
        throw 'OBI did not exit after exporting the HTTP span'
    }
    $targetProcess.Refresh()
    $obiProcess.Refresh()
    $clientProcess.Refresh()

    if ($null -ne $targetProcess.ExitCode -and $targetProcess.ExitCode -ne 0) {
        throw "HTTP target failed: $(Get-Content -Raw -LiteralPath $targetStderr)"
    }
    if ($null -ne $obiProcess.ExitCode -and $obiProcess.ExitCode -ne 0) {
        throw "OBI failed: $(Get-Content -Raw -LiteralPath $obiStdout)"
    }

    $obiLog = Get-Content -Raw -LiteralPath $obiStdout
    $targetLog = Get-Content -Raw -LiteralPath $targetStdout
    $expectedTargetLog = "served GET $RequestPath status=204"
    if (-not $targetLog.Contains($expectedTargetLog)) {
        throw "HTTP target did not report the expected request: $targetLog"
    }
    if ($obiLog -notmatch 'OpenTelemetry eBPF Instrumentation successfully exiting') {
        throw "OBI did not report a successful exit: $obiLog"
    }

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
    if ($actualTraceId -ne $clientResult.trace_id) {
        throw "OBI trace ID $actualTraceId does not match client trace ID $($clientResult.trace_id)"
    }
    if ($actualParentSpanId -ne $clientResult.span_id) {
        throw "OBI parent ID $actualParentSpanId does not match client span ID $($clientResult.span_id)"
    }
    if ($actualSpanId -eq ('0' * 16) -or $actualSpanId -eq $clientResult.span_id) {
        throw "OBI generated an invalid server span ID: $actualSpanId"
    }

    Wait-LogPattern -Process $collectorProcess `
        -Path $collectorStderr `
        -Pattern ([Regex]::Escape($clientResult.span_id))
    Wait-LogPattern -Process $collectorProcess `
        -Path $collectorStderr `
        -Pattern ([Regex]::Escape($actualSpanId))

    $collectorLog = @(
        Get-Content -Raw -LiteralPath $collectorStdout
        Get-Content -Raw -LiteralPath $collectorStderr
    ) -join "`n"
    $clientBlock = Get-CollectorSpanBlock -Log $collectorLog -SpanId $clientResult.span_id
    $serverBlock = Get-CollectorSpanBlock -Log $collectorLog -SpanId $actualSpanId

    $clientChecks = @(
        'service\.name.*obi-windows-http-client',
        'telemetry\.sdk\.language.*go',
        'telemetry\.sdk\.name.*opentelemetry',
        'InstrumentationScope\s+go\.opentelemetry\.io/obi/examples/windows-http-client',
        'Trace ID\s*:\s*' + [Regex]::Escape($clientResult.trace_id),
        'ID\s*:\s*' + [Regex]::Escape($clientResult.span_id),
        'Kind\s*:\s*Client',
        'http\.request\.method.*GET',
        'http\.response\.status_code.*204'
    )
    foreach ($check in $clientChecks) {
        if ($clientBlock -notmatch $check) {
            throw "Collector client span is missing expected value: $check"
        }
    }
    if ($clientBlock -match 'telemetry\.distro\.name') {
        throw 'The ordinary SDK client span unexpectedly carries OBI distribution identity'
    }

    $serverChecks = @(
        'service\.name.*obi-windows-http-target\.exe',
        'telemetry\.sdk\.name.*opentelemetry',
        'telemetry\.distro\.name.*opentelemetry-ebpf-instrumentation',
        'otel\.scope\.name.*go\.opentelemetry\.io/obi',
        'Trace ID\s*:\s*' + [Regex]::Escape($actualTraceId),
        'Parent ID\s*:\s*' + [Regex]::Escape($clientResult.span_id),
        'ID\s*:\s*' + [Regex]::Escape($actualSpanId),
        'Kind\s*:\s*Server',
        'http\.request\.method.*GET',
        'http\.response\.status_code.*204',
        'url\.path.*' + [Regex]::Escape($RequestPath),
        'server\.address.*127\.0\.0\.1',
        'server\.port.*' + $Port,
        'process\.pid.*Int\([1-9][0-9]*\)'
    )
    foreach ($check in $serverChecks) {
        if ($serverBlock -notmatch $check) {
            throw "Collector OBI server span is missing expected value: $check"
        }
    }

    $artifactHashes = [ordered]@{}
    foreach ($artifact in @(
        $obiExecutable,
        $processProgram,
        $flowProgram,
        $targetExecutable,
        $clientExecutable
    )) {
        $artifactHashes[(Split-Path -Leaf $artifact)] =
            (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash
    }
    $summary = [ordered]@{
        accepted = $true
        trace_id = $actualTraceId
        client_span_id = $clientResult.span_id
        server_parent_span_id = $actualParentSpanId
        server_span_id = $actualSpanId
        method = 'GET'
        path = $RequestPath
        status_code = 204
        client_span_kind = 'CLIENT'
        server_span_kind = 'SERVER'
        client_service_name = 'obi-windows-http-client'
        server_service_name = 'obi-windows-http-target.exe'
        server_telemetry_sdk_name = 'opentelemetry'
        server_telemetry_distro_name = 'opentelemetry-ebpf-instrumentation'
        server_otel_scope_name = 'go.opentelemetry.io/obi'
        artifact_sha256 = $artifactHashes
        evidence_directory = $EvidenceDirectory
    }
    $summary |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $summaryPath -Encoding UTF8
    $completed = $true
} finally {
    foreach ($process in @($clientProcess, $targetProcess, $obiProcess, $collectorProcess)) {
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
