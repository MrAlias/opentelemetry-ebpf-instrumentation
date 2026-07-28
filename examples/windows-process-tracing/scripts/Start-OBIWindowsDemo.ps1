# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$StageDirectory,

    [ValidateSet('Jaeger', 'Splunk', 'OTLP', 'Debug')]
    [string]$Backend = 'Jaeger',

    [string]$Collector = 'C:\src\obi-artifacts\collector\otelcol-contrib.exe',

    [string]$CollectorConfig,

    [string]$Jaeger = 'C:\src\obi-artifacts\jaeger\jaeger-2.20.0-windows-amd64\jaeger.exe',

    [double]$RatePerSecond = 1,

    [int]$Count = 0,

    [int]$Port = 18080,

    [string[]]$RequestPaths = @('/checkout', '/search', '/inventory'),

    [int[]]$StatusCodes = @(204, 200, 503),

    [int[]]$LatencyMilliseconds = @(25, 150, 400),

    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Wait-LogPattern {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [int]$Seconds = 15
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

        [int]$Seconds = 20
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        if (Test-TcpPort -Port $Port) {
            return
        }
        Start-Sleep -Milliseconds 100
    } until ((Get-Date) -gt $deadline)

    throw "Timed out waiting for TCP port $Port"
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync('127.0.0.1', $Port)
        return $connect.Wait(200) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function ConvertTo-NativeArgument {
    param(
        [AllowEmptyString()]
        [string]$Argument
    )

    if ($Argument -eq '') {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $backslashes + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * (2 * $backslashes)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-NativeArguments {
    param(
        [Parameter(Mandatory)]
        [object[]]$Arguments
    )

    return (
        $Arguments |
            ForEach-Object {
                ConvertTo-NativeArgument -Argument $_.ToString()
            }
    ) -join ' '
}

function Invoke-NetshEbpfShow {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('programs', 'maps', 'links')]
        [string]$Object
    )

    $output = & netsh.exe ebpf show $Object 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "netsh ebpf show $Object failed with exit code $LASTEXITCODE`: $output"
    }
    return $output
}

function Get-EbpfState {
    @(
        'PROGRAMS'
        (Invoke-NetshEbpfShow -Object programs)
        'MAPS'
        (Invoke-NetshEbpfShow -Object maps)
        'LINKS'
        (Invoke-NetshEbpfShow -Object links)
    )
}

function Assert-CleanEbpfState {
    param(
        [Parameter(Mandatory)]
        [string]$State
    )

    if ($State -match '(?m)^\s*\d+\s+') {
        throw 'Programs, maps, or links remain after a demo trace cycle'
    }
}

function Wait-CleanEbpfState {
    param(
        [int]$Seconds = 10
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $state = Get-EbpfState | Out-String
        if ($state -notmatch '(?m)^\s*\d+\s+') {
            return $state
        }
        Start-Sleep -Milliseconds 250
    } until ((Get-Date) -gt $deadline)

    Assert-CleanEbpfState -State $state
}

function Stop-ChildProcess {
    param(
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process -or $Process.HasExited) {
        return
    }

    Stop-Process -Id $Process.Id -Force -ErrorAction Stop
    if (-not $Process.WaitForExit(5000)) {
        throw "Timed out waiting for child process $($Process.Id) to stop"
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

    $start = $Log.LastIndexOf(
        'ResourceSpans #',
        $spanMatch.Index,
        [StringComparison]::Ordinal
    )
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

function Assert-SpanBlock {
    param(
        [Parameter(Mandatory)]
        [string]$Block,

        [Parameter(Mandatory)]
        [string[]]$Patterns,

        [Parameter(Mandatory)]
        [string]$Description
    )

    foreach ($pattern in $Patterns) {
        if ($Block -notmatch $pattern) {
            throw "$Description span is missing expected value: $pattern"
        }
    }
}

function Restore-EnvironmentValue {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [string]$Value
    )

    [Environment]::SetEnvironmentVariable(
        $Name,
        $Value,
        [EnvironmentVariableTarget]::Process
    )
}

function New-ProcessRecord {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory)]
        [string]$Path
    )

    [ordered]@{
        pid = $Process.Id
        path = [IO.Path]::GetFullPath($Path)
        start_time_filetime_utc = (
            $Process.StartTime.ToUniversalTime().ToFileTimeUtc()
        )
    }
}

function Save-DemoState {
    param(
        [Parameter(Mandatory)]
        [object]$State,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $temporary = "$Path.tmp"
    $State |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-ArtifactRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Role
    )

    $item = Get-Item -LiteralPath $Path
    [ordered]@{
        role = $Role
        path = $item.FullName
        length = $item.Length
        sha256 = (
            Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName
        ).Hash.ToLowerInvariant()
    }
}

function Assert-PackageManifest {
    param(
        [Parameter(Mandatory)]
        [string]$StageDirectory,

        [Parameter(Mandatory)]
        [string]$ManifestPath
    )

    $stageRoot = [IO.Path]::GetFullPath($StageDirectory).TrimEnd('\') + '\'
    $parsedRecords = Get-Content -Raw -LiteralPath $ManifestPath |
        ConvertFrom-Json
    $records = @($parsedRecords)
    if ($records.Count -eq 0) {
        throw "Package manifest has no records: $ManifestPath"
    }

    $verified = @{}
    foreach ($record in $records) {
        $relativePath = [string]$record.path
        if (-not $relativePath) {
            throw 'Package manifest contains an empty path'
        }
        $fullPath = [IO.Path]::GetFullPath(
            (Join-Path $StageDirectory $relativePath)
        )
        if (-not $fullPath.StartsWith(
                $stageRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Package manifest path escapes StageDirectory: $relativePath"
        }
        $key = $fullPath.ToLowerInvariant()
        if ($verified.ContainsKey($key)) {
            throw "Package manifest contains a duplicate path: $relativePath"
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Package manifest file does not exist: $relativePath"
        }
        $item = Get-Item -LiteralPath $fullPath
        $actualHash = (
            Get-FileHash -Algorithm SHA256 -LiteralPath $fullPath
        ).Hash
        if ($item.Length -ne [long]$record.length -or
            $actualHash -ne [string]$record.sha256) {
            throw "Package manifest verification failed: $relativePath"
        }
        $verified[$key] = $true
    }

    foreach ($relativePath in @(
            'obi.exe',
            'obi-windows-http-client.exe',
            'obi-windows-http-demo-target.exe',
            'obi_process_start.sys',
            'obi_flow_classify.sys',
            'collector-demo/debug.yaml',
            'collector-demo/jaeger.yaml',
            'collector-demo/splunk.yaml',
            'Start-OBIWindowsDemo.ps1',
            'Stop-OBIWindowsDemo.ps1'
        )) {
        $fullPath = [IO.Path]::GetFullPath(
            (Join-Path $StageDirectory $relativePath)
        )
        if (-not $verified.ContainsKey($fullPath.ToLowerInvariant())) {
            throw "Package manifest omits required demo artifact: $relativePath"
        }
    }
}

function Write-EvidenceManifest {
    param(
        [Parameter(Mandatory)]
        [string]$Directory
    )

    $directory = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $manifestPath = Join-Path $directory 'SHA256SUMS'
    $lines = @(
        Get-ChildItem -LiteralPath $directory -Recurse -File |
            Where-Object FullName -NE $manifestPath |
            Sort-Object FullName |
            ForEach-Object {
                $relativePath = $_.FullName.
                    Substring($directory.Length + 1).
                    Replace('\', '/')
                $hash = (
                    Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
                ).Hash.ToLowerInvariant()
                "$hash  $relativePath"
            }
    )
    [IO.File]::WriteAllLines(
        $manifestPath,
        $lines,
        [Text.UTF8Encoding]::new($false)
    )
}
function Protect-DemoSecrets {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $protected = $Value
    if ($env:SPLUNK_ACCESS_TOKEN) {
        $protected = $protected.Replace($env:SPLUNK_ACCESS_TOKEN, '[REDACTED]')
    }
    return $protected
}

if ($RatePerSecond -le 0 -or $RatePerSecond -gt 10) {
    throw "RatePerSecond must be greater than zero and at most 10: $RatePerSecond"
}
if ($Count -lt 0) {
    throw "Count cannot be negative: $Count"
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be between 1 and 65535: $Port"
}
if ($RequestPaths.Count -eq 0 -or $StatusCodes.Count -eq 0 -or
    $LatencyMilliseconds.Count -eq 0) {
    throw 'RequestPaths, StatusCodes, and LatencyMilliseconds cannot be empty'
}
foreach ($path in $RequestPaths) {
    if (-not $path.StartsWith('/') -or $path.Contains(' ')) {
        throw "Request path must start with / and contain no spaces: $path"
    }
}
foreach ($statusCode in $StatusCodes) {
    if ($statusCode -lt 200 -or $statusCode -gt 599) {
        throw "Status code must be between 200 and 599: $statusCode"
    }
}
foreach ($latency in $LatencyMilliseconds) {
    if ($latency -lt 0 -or $latency -gt 5000) {
        throw "Latency must be between 0 and 5000 milliseconds: $latency"
    }
}

$stageDirectory = [IO.Path]::GetFullPath($StageDirectory)
$processProgram = Join-Path $stageDirectory 'obi_process_start.sys'
$flowProgram = Join-Path $stageDirectory 'obi_flow_classify.sys'
$obiExecutable = Join-Path $stageDirectory 'obi.exe'
$targetExecutable = Join-Path $stageDirectory 'obi-windows-http-demo-target.exe'
$clientExecutable = Join-Path $stageDirectory 'obi-windows-http-client.exe'
$statePath = Join-Path $stageDirectory 'demo-state.json'
$stopRequestPath = Join-Path $stageDirectory 'demo-stop.request'
$packageManifestPath = Join-Path $stageDirectory 'demo-package-hashes.json'
$otlpEndpoint = 'http://127.0.0.1:4318/v1/traces'

if (-not $EvidenceDirectory) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $EvidenceDirectory = Join-Path $stageDirectory "evidence\windows-demo-$stamp"
}
$evidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
$collectorStdout = Join-Path $evidenceDirectory 'collector.stdout.log'
$collectorStderr = Join-Path $evidenceDirectory 'collector.stderr.log'
$jaegerStdout = Join-Path $evidenceDirectory 'jaeger.stdout.log'
$jaegerStderr = Join-Path $evidenceDirectory 'jaeger.stderr.log'
$chainsPath = Join-Path $evidenceDirectory 'trace-chain.ndjson'
$summaryPath = Join-Path $evidenceDirectory 'demo-summary.json'
$cleanupStatePath = Join-Path $evidenceDirectory 'ebpf-cleanup.txt'

if (-not $CollectorConfig) {
    $profile = $Backend.ToLowerInvariant()
    $CollectorConfig = Join-Path $stageDirectory "collector-demo\$profile.yaml"
}
$collectorConfig = [IO.Path]::GetFullPath($CollectorConfig)

$requiredPaths = @(
    $Collector,
    $collectorConfig,
    $processProgram,
    $flowProgram,
    $obiExecutable,
    $targetExecutable,
    $clientExecutable,
    $packageManifestPath
)
if ($Backend -eq 'Jaeger') {
    $requiredPaths += $Jaeger
}
foreach ($requiredPath in $requiredPaths) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file does not exist: $requiredPath"
    }
}
Assert-PackageManifest `
    -StageDirectory $stageDirectory `
    -ManifestPath $packageManifestPath
if ($Backend -eq 'OTLP' -and -not $PSBoundParameters.ContainsKey('CollectorConfig')) {
    throw 'Backend OTLP requires -CollectorConfig with a debug exporter for validation'
}
if ($Backend -eq 'Splunk') {
    if (-not $env:SPLUNK_REALM -or
        $env:SPLUNK_REALM -notmatch '^[a-z0-9-]+$') {
        throw 'SPLUNK_REALM is required and must contain only lowercase letters, digits, and hyphens'
    }
    if (-not $env:SPLUNK_ACCESS_TOKEN) {
        throw 'SPLUNK_ACCESS_TOKEN is required'
    }
}
if (Test-Path -LiteralPath $statePath) {
    throw "Demo state already exists; run Stop-OBIWindowsDemo.ps1 first: $statePath"
}
if (Test-Path -LiteralPath $stopRequestPath) {
    Remove-Item -LiteralPath $stopRequestPath -Force
}
if (Test-Path -LiteralPath $evidenceDirectory) {
    throw "Evidence directory already exists: $evidenceDirectory"
}
if (Test-TcpPort -Port 4318) {
    throw 'TCP port 4318 is already in use'
}
if ($Backend -eq 'Jaeger') {
    foreach ($jaegerPort in @(14317, 14318, 16686)) {
        if (Test-TcpPort -Port $jaegerPort) {
            throw "Jaeger TCP port $jaegerPort is already in use"
        }
    }
}

$initialEbpfState = Get-EbpfState | Out-String
Assert-CleanEbpfState -State $initialEbpfState

New-Item -ItemType Directory -Path $evidenceDirectory | Out-Null
New-Item -ItemType Directory -Path (
    Join-Path $evidenceDirectory 'cycles'
) | Out-Null
$initialEbpfState |
    Set-Content -LiteralPath (
        Join-Path $evidenceDirectory 'ebpf-initial.txt'
    ) -Encoding UTF8

$runtimeArtifacts = @(
    Get-ArtifactRecord -Path $packageManifestPath -Role 'package-manifest'
    Get-ArtifactRecord -Path $obiExecutable -Role 'obi'
    Get-ArtifactRecord -Path $targetExecutable -Role 'target'
    Get-ArtifactRecord -Path $clientExecutable -Role 'client'
    Get-ArtifactRecord -Path $processProgram -Role 'process-program'
    Get-ArtifactRecord -Path $flowProgram -Role 'flow-program'
    Get-ArtifactRecord -Path $Collector -Role 'collector'
    Get-ArtifactRecord -Path $collectorConfig -Role 'collector-config'
)
if ($Backend -eq 'Jaeger') {
    $runtimeArtifacts += Get-ArtifactRecord -Path $Jaeger -Role 'jaeger'
}
$runtimeArtifacts |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (
        Join-Path $evidenceDirectory 'runtime-artifacts.json'
    ) -Encoding UTF8

$validateOutput = & $Collector validate "--config=$collectorConfig" 2>&1 |
    Out-String
if ($LASTEXITCODE -ne 0) {
    throw "Collector configuration validation failed: $(Protect-DemoSecrets -Value $validateOutput)"
}

$controllerProcess = Get-Process -Id $PID
$state = [ordered]@{
    schema_version = 2
    backend = $Backend
    stage_directory = $stageDirectory
    evidence_directory = $evidenceDirectory
    started_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    processes = [ordered]@{
        controller = New-ProcessRecord `
            -Process $controllerProcess `
            -Path $controllerProcess.Path
        jaeger = $null
        collector = $null
        obi = $null
        target = $null
        client = $null
    }
}
$summary = [ordered]@{
    schema_version = 1
    status = 'starting'
    backend = $Backend
    requested_rate_per_second = $RatePerSecond
    requested_count = $Count
    completed_trace_count = 0
    otlp_receiver = $otlpEndpoint
    evidence_directory = $evidenceDirectory
    started_at_utc = $state.started_at_utc
    completed_at_utc = $null
    failure = $null
    jaeger_ui = if ($Backend -eq 'Jaeger') {
        'http://127.0.0.1:16686'
    } else {
        $null
    }
}

$jaegerProcess = $null
$collectorProcess = $null
$obiProcess = $null
$targetProcess = $null
$clientProcess = $null
$completed = $false
$stoppedByRequest = $false
$failure = $null

try {
    if ($Backend -eq 'Jaeger') {
        $jaegerArguments = @(
            '--set=receivers.otlp.protocols.grpc.endpoint=127.0.0.1:14317',
            '--set=receivers.otlp.protocols.http.endpoint=127.0.0.1:14318'
        )
        $jaegerProcess = Start-Process `
            -FilePath $Jaeger `
            -ArgumentList (Join-NativeArguments -Arguments $jaegerArguments) `
            -RedirectStandardOutput $jaegerStdout `
            -RedirectStandardError $jaegerStderr `
            -PassThru
        $state.processes.jaeger = New-ProcessRecord `
            -Process $jaegerProcess `
            -Path $Jaeger
        Save-DemoState -State $state -Path $statePath
        Wait-TcpPort -Port 14318
        Wait-TcpPort -Port 16686
        if ($jaegerProcess.HasExited) {
            throw "Jaeger exited during startup: $(Get-Content -Raw -LiteralPath $jaegerStderr)"
        }
    }

    $collectorProcess = Start-Process `
        -FilePath $Collector `
        -ArgumentList (
            Join-NativeArguments -Arguments @("--config=$collectorConfig")
        ) `
        -RedirectStandardOutput $collectorStdout `
        -RedirectStandardError $collectorStderr `
        -PassThru
    $state.processes.collector = New-ProcessRecord `
        -Process $collectorProcess `
        -Path $Collector
    Save-DemoState -State $state -Path $statePath
    Wait-LogPattern `
        -Process $collectorProcess `
        -Path $collectorStderr `
        -Pattern 'Everything is ready' `
        -Seconds 30
    Wait-TcpPort -Port 4318

    $summary.status = 'running'
    $summary |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $summaryPath -Encoding UTF8

    Write-Host "OBI Windows demo started: backend=$Backend receiver=$otlpEndpoint"
    if ($Backend -eq 'Jaeger') {
        Write-Host 'Jaeger UI: http://127.0.0.1:16686'
        Write-Host 'Service: obi-windows-http-demo-target.exe'
    }
    Write-Host 'Press Ctrl+C to stop; cleanup also runs from the Stop script.'

    $cycleNumber = 0
    $intervalMilliseconds = 1000.0 / $RatePerSecond
    while ($Count -eq 0 -or $cycleNumber -lt $Count) {
        if (Test-Path -LiteralPath $stopRequestPath) {
            $stoppedByRequest = $true
            break
        }
        $cycleNumber++
        $cycleStarted = Get-Date
        $cycleDirectory = Join-Path $evidenceDirectory (
            'cycles\{0:d6}' -f $cycleNumber
        )
        New-Item -ItemType Directory -Path $cycleDirectory | Out-Null

        $obiStdout = Join-Path $cycleDirectory 'obi.stdout.log'
        $obiStderr = Join-Path $cycleDirectory 'obi.stderr.log'
        $targetStdout = Join-Path $cycleDirectory 'target.stdout.log'
        $targetStderr = Join-Path $cycleDirectory 'target.stderr.log'
        $clientStdout = Join-Path $cycleDirectory 'client.stdout.log'
        $clientStderr = Join-Path $cycleDirectory 'client.stderr.log'
        $liveStatePath = Join-Path $cycleDirectory 'ebpf-live.txt'

        $requestPath = $RequestPaths[
            ($cycleNumber - 1) % $RequestPaths.Count
        ]
        $statusCode = $StatusCodes[
            ($cycleNumber - 1) % $StatusCodes.Count
        ]
        $latency = $LatencyMilliseconds[
            ($cycleNumber - 1) % $LatencyMilliseconds.Count
        ]

        try {
            $obiArguments = @(
                '-process-program', $processProgram,
                '-flow-program', $flowProgram,
                '-target-exe', 'obi-windows-http-demo-target.exe',
                '-target-port', $Port,
                '-otlp-endpoint', $otlpEndpoint,
                '-timeout', '30s',
                '-once=true'
            )
            $obiProcess = Start-Process `
                -FilePath $obiExecutable `
                -ArgumentList (Join-NativeArguments -Arguments $obiArguments) `
                -RedirectStandardOutput $obiStdout `
                -RedirectStandardError $obiStderr `
                -PassThru
            $state.processes.obi = New-ProcessRecord `
                -Process $obiProcess `
                -Path $obiExecutable
            Save-DemoState -State $state -Path $statePath
            Wait-LogPattern `
                -Process $obiProcess `
                -Path $obiStdout `
                -Pattern 'attached native eBPF programs'

            Get-EbpfState |
                Set-Content -LiteralPath $liveStatePath -Encoding UTF8

            $originalPort = $env:OBI_WINDOWS_HTTP_PORT
            $originalStatus = $env:OBI_WINDOWS_HTTP_STATUS
            $originalLatency = $env:OBI_WINDOWS_HTTP_LATENCY_MS
            try {
                $env:OBI_WINDOWS_HTTP_PORT = $Port.ToString()
                $env:OBI_WINDOWS_HTTP_STATUS = $statusCode.ToString()
                $env:OBI_WINDOWS_HTTP_LATENCY_MS = $latency.ToString()
                $targetProcess = Start-Process `
                    -FilePath $targetExecutable `
                    -RedirectStandardOutput $targetStdout `
                    -RedirectStandardError $targetStderr `
                    -PassThru
            } finally {
                Restore-EnvironmentValue `
                    -Name 'OBI_WINDOWS_HTTP_PORT' `
                    -Value $originalPort
                Restore-EnvironmentValue `
                    -Name 'OBI_WINDOWS_HTTP_STATUS' `
                    -Value $originalStatus
                Restore-EnvironmentValue `
                    -Name 'OBI_WINDOWS_HTTP_LATENCY_MS' `
                    -Value $originalLatency
            }
            $state.processes.target = New-ProcessRecord `
                -Process $targetProcess `
                -Path $targetExecutable
            Save-DemoState -State $state -Path $statePath
            Wait-LogPattern `
                -Process $targetProcess `
                -Path $targetStdout `
                -Pattern 'PID='
            Wait-LogPattern `
                -Process $obiProcess `
                -Path $obiStdout `
                -Pattern 'configured Windows HTTP target from native process event'

            $targetUrl = "http://127.0.0.1:$Port$requestPath"
            $clientArguments = @(
                '-otlp-endpoint', $otlpEndpoint,
                '-url', $targetUrl,
                '-timeout', '15s'
            )
            $clientProcess = Start-Process `
                -FilePath $clientExecutable `
                -ArgumentList (
                    Join-NativeArguments -Arguments $clientArguments
                ) `
                -RedirectStandardOutput $clientStdout `
                -RedirectStandardError $clientStderr `
                -PassThru
            $state.processes.client = New-ProcessRecord `
                -Process $clientProcess `
                -Path $clientExecutable
            Save-DemoState -State $state -Path $statePath

            if (-not $clientProcess.WaitForExit(20000)) {
                throw 'Instrumented HTTP client did not exit'
            }
            $clientProcess.Refresh()
            if ($null -ne $clientProcess.ExitCode -and
                $clientProcess.ExitCode -ne 0) {
                throw "Instrumented HTTP client failed: $(Get-Content -Raw -LiteralPath $clientStderr)"
            }
            $clientResult = Get-Content -Raw -LiteralPath $clientStdout |
                ConvertFrom-Json
            if ($clientResult.span_kind -ne 'client' -or
                $clientResult.status_code -ne $statusCode) {
                throw "Instrumented HTTP client returned an unexpected result: $($clientResult | ConvertTo-Json -Compress)"
            }

            if (-not $targetProcess.WaitForExit(10000)) {
                throw 'HTTP demo target did not exit'
            }
            if (-not $obiProcess.WaitForExit(15000)) {
                throw 'OBI did not exit after exporting the HTTP span'
            }
            $targetProcess.Refresh()
            $obiProcess.Refresh()
            if ($null -ne $targetProcess.ExitCode -and
                $targetProcess.ExitCode -ne 0) {
                throw "HTTP demo target failed: $(Get-Content -Raw -LiteralPath $targetStderr)"
            }
            if ($null -ne $obiProcess.ExitCode -and
                $obiProcess.ExitCode -ne 0) {
                throw "OBI failed: $(Get-Content -Raw -LiteralPath $obiStdout)"
            }

            $obiLog = Get-Content -Raw -LiteralPath $obiStdout
            $targetLog = Get-Content -Raw -LiteralPath $targetStdout
            $expectedTargetLog = "served GET $requestPath status=$statusCode"
            if (-not $targetLog.Contains($expectedTargetLog)) {
                throw "HTTP target did not report the expected request: $targetLog"
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
            if ($actualSpanId -eq ('0' * 16) -or
                $actualSpanId -eq $clientResult.span_id) {
                throw "OBI generated an invalid server span ID: $actualSpanId"
            }

            Wait-LogPattern `
                -Process $collectorProcess `
                -Path $collectorStderr `
                -Pattern ([Regex]::Escape($clientResult.span_id))
            Wait-LogPattern `
                -Process $collectorProcess `
                -Path $collectorStderr `
                -Pattern ([Regex]::Escape($actualSpanId))

            $collectorLog = @(
                Get-Content -Raw -LiteralPath $collectorStdout
                Get-Content -Raw -LiteralPath $collectorStderr
            ) -join "`n"
            $clientBlock = Get-CollectorSpanBlock `
                -Log $collectorLog `
                -SpanId $clientResult.span_id
            $serverBlock = Get-CollectorSpanBlock `
                -Log $collectorLog `
                -SpanId $actualSpanId

            Assert-SpanBlock `
                -Block $clientBlock `
                -Description 'Client' `
                -Patterns @(
                    'service\.name.*obi-windows-http-client',
                    'Trace ID\s*:\s*' + [Regex]::Escape($actualTraceId),
                    'ID\s*:\s*' + [Regex]::Escape($clientResult.span_id),
                    'Kind\s*:\s*Client',
                    'http\.request\.method.*GET',
                    'http\.response\.status_code.*' + $statusCode
                )
            if ($clientBlock -match 'telemetry\.distro\.name') {
                throw 'The ordinary SDK client span unexpectedly carries OBI distribution identity'
            }

            Assert-SpanBlock `
                -Block $serverBlock `
                -Description 'OBI server' `
                -Patterns @(
                    'service\.name.*obi-windows-http-demo-target\.exe',
                    'telemetry\.sdk\.name.*opentelemetry',
                    'telemetry\.distro\.name.*opentelemetry-ebpf-instrumentation',
                    'otel\.scope\.name.*go\.opentelemetry\.io/obi',
                    'Trace ID\s*:\s*' + [Regex]::Escape($actualTraceId),
                    'Parent ID\s*:\s*' + [Regex]::Escape($clientResult.span_id),
                    'ID\s*:\s*' + [Regex]::Escape($actualSpanId),
                    'Kind\s*:\s*Server',
                    'http\.request\.method.*GET',
                    'http\.response\.status_code.*' + $statusCode,
                    'server\.address.*127\.0\.0\.1',
                    'server\.port.*' + $Port,
                    'process\.pid.*Int\(' +
                        [Regex]::Escape($targetProcess.Id.ToString()) + '\)',
                    'url\.path.*' + [Regex]::Escape($requestPath)
                )

            $exportFailurePattern = (
                '(?im)^.*(?:error|fatal).*(?:export|otlphttp|sending queue).*$|' +
                '^.*(?:export|otlphttp|sending queue).*(?:error|fatal).*$'
            )
            if ($collectorLog -match $exportFailurePattern) {
                throw 'Collector reported a trace export failure; inspect collector.stderr.log'
            }

            $elapsedMilliseconds = [math]::Round(
                ((Get-Date) - $cycleStarted).TotalMilliseconds,
                1
            )
            $chain = [ordered]@{
                timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
                cycle = $cycleNumber
                backend = $Backend
                trace_id = $actualTraceId
                client_span_id = $clientResult.span_id
                server_parent_span_id = $actualParentSpanId
                server_span_id = $actualSpanId
                method = 'GET'
                path = $requestPath
                status_code = $statusCode
                configured_latency_ms = $latency
                cycle_elapsed_ms = $elapsedMilliseconds
                client_service_name = 'obi-windows-http-client'
                server_service_name = 'obi-windows-http-demo-target.exe'
                server_process_pid = $targetProcess.Id
                server_telemetry_sdk_name = 'opentelemetry'
                server_telemetry_distro_name = 'opentelemetry-ebpf-instrumentation'
                server_source = 'Windows eBPF-for-Windows Flow Classify'
                collector_accepted = $true
                collector_export_error_observed = $false
                correlated = $true
            }
            $line = $chain | ConvertTo-Json -Compress
            [IO.File]::AppendAllText(
                $chainsPath,
                $line + [Environment]::NewLine,
                [Text.UTF8Encoding]::new($false)
            )

            $summary.completed_trace_count = $cycleNumber
            $summary.last_trace_id = $actualTraceId
            $summary.last_server_span_id = $actualSpanId
            $summary |
                ConvertTo-Json -Depth 5 |
                Set-Content -LiteralPath $summaryPath -Encoding UTF8

            Write-Host ((
                'trace={0} client={1} server={2} path={3} status={4} ' +
                'backend={5} correlated=true identity=opentelemetry-ebpf-instrumentation'
            ) -f @(
                $actualTraceId,
                $clientResult.span_id,
                $actualSpanId,
                $requestPath,
                $statusCode,
                $Backend
            ))
        } finally {
            Stop-ChildProcess -Process $clientProcess
            Stop-ChildProcess -Process $targetProcess
            Stop-ChildProcess -Process $obiProcess
            $clientProcess = $null
            $targetProcess = $null
            $obiProcess = $null
            $state.processes.client = $null
            $state.processes.target = $null
            $state.processes.obi = $null
            Save-DemoState -State $state -Path $statePath

            $cycleCleanupState = Wait-CleanEbpfState
            $cycleCleanupState |
                Set-Content -LiteralPath (
                    Join-Path $cycleDirectory 'ebpf-cleanup.txt'
                ) -Encoding UTF8
        }

        $remainingMilliseconds = $intervalMilliseconds -
            ((Get-Date) - $cycleStarted).TotalMilliseconds
        if ($remainingMilliseconds -gt 0) {
            Start-Sleep -Milliseconds ([int]$remainingMilliseconds)
        }
    }

    $completed = $true
} catch {
    $failure = Protect-DemoSecrets -Value $_.Exception.Message
} finally {
    Start-Sleep -Milliseconds 500
    foreach ($processToStop in @(
            $clientProcess,
            $targetProcess,
            $obiProcess,
            $collectorProcess,
            $jaegerProcess
        )) {
        try {
            Stop-ChildProcess -Process $processToStop
        } catch {
            if (-not $failure) {
                $failure = Protect-DemoSecrets -Value $_.Exception.Message
            }
        }
    }

    try {
        $cleanupState = Wait-CleanEbpfState
        $cleanupState |
            Set-Content -LiteralPath $cleanupStatePath -Encoding UTF8
    } catch {
        if (-not $failure) {
            $failure = Protect-DemoSecrets -Value $_.Exception.Message
        }
    }

    $summary.status = if ($failure) {
        'failed'
    } elseif ($stoppedByRequest) {
        'stopped'
    } elseif ($completed) {
        'completed'
    } else {
        'stopped'
    }
    $summary.completed_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    $summary.failure = $failure
    $summary |
        ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $summaryPath -Encoding UTF8

    Write-EvidenceManifest -Directory $evidenceDirectory
    if (Test-Path -LiteralPath $statePath) {
        Remove-Item -LiteralPath $statePath -Force
    }
    if (Test-Path -LiteralPath $stopRequestPath) {
        Remove-Item -LiteralPath $stopRequestPath -Force
    }
}

if ($failure) {
    throw $failure
}
if ($completed) {
    Get-Content -Raw -LiteralPath $summaryPath
}
