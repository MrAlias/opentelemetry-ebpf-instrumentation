# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$StageDirectory,

    [string]$StatePath,

    [int]$GracefulTimeoutSeconds = 45
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-RecordedProcess {
    param(
        [AllowNull()]
        [object]$Record,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $Record) {
        return
    }
    $process = Get-Process -Id $Record.pid -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return
    }

    $expectedPath = [IO.Path]::GetFullPath($Record.path)
    $actualPath = try {
        [IO.Path]::GetFullPath($process.Path)
    } catch {
        $null
    }
    $actualStartTime = try {
        $process.StartTime.ToUniversalTime().ToFileTimeUtc()
    } catch {
        $null
    }
    if (-not $actualPath -or
        -not $actualPath.Equals(
            $expectedPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $null -eq $Record.start_time_filetime_utc -or
        $actualStartTime -ne [long]$Record.start_time_filetime_utc) {
        throw (
            "Refusing to stop $Name PID $($Record.pid): " +
            'executable identity does not match the recorded process'
        )
    }

    Stop-Process -Id $process.Id -Force
    if (-not $process.WaitForExit(5000)) {
        throw "Timed out waiting for $Name PID $($Record.pid) to stop"
    }
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

function Wait-CleanEbpfState {
    $deadline = (Get-Date).AddSeconds(10)
    do {
        $state = Get-EbpfState | Out-String
        if ($state -notmatch '(?m)^\s*\d+\s+') {
            return $state
        }
        Start-Sleep -Milliseconds 250
    } until ((Get-Date) -gt $deadline)

    throw 'Programs, maps, or links remain after stopping the demo'
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

if ($GracefulTimeoutSeconds -lt 1 -or $GracefulTimeoutSeconds -gt 120) {
    throw "GracefulTimeoutSeconds must be between 1 and 120: $GracefulTimeoutSeconds"
}

$stageDirectory = [IO.Path]::GetFullPath($StageDirectory)
if (-not $StatePath) {
    $StatePath = Join-Path $stageDirectory 'demo-state.json'
}
$statePath = [IO.Path]::GetFullPath($StatePath)
if (-not $statePath.StartsWith(
        $stageDirectory.TrimEnd('\') + '\',
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "StatePath must be inside StageDirectory: $statePath"
}
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    Write-Host "No active OBI Windows demo state exists: $statePath"
    return
}

$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
if ($state.schema_version -ne 2) {
    throw "Unsupported demo state schema: $($state.schema_version)"
}
$evidenceDirectory = [IO.Path]::GetFullPath($state.evidence_directory)
if (-not (Test-Path -LiteralPath $evidenceDirectory -PathType Container)) {
    throw "Evidence directory does not exist: $evidenceDirectory"
}

$stopRequestPath = Join-Path $stageDirectory 'demo-stop.request'
[ordered]@{
    requested_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    requester_pid = $PID
} |
    ConvertTo-Json |
    Set-Content -LiteralPath $stopRequestPath -Encoding UTF8

$deadline = (Get-Date).AddSeconds($GracefulTimeoutSeconds)
do {
    Start-Sleep -Milliseconds 250
} until (
    -not (Test-Path -LiteralPath $statePath -PathType Leaf) -or
    (Get-Date) -gt $deadline
)

$forced = $false
if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    $forced = $true
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    foreach ($name in @('client', 'target', 'obi', 'collector', 'jaeger')) {
        Stop-RecordedProcess -Record $state.processes.$name -Name $name
    }
    Stop-RecordedProcess `
        -Record $state.processes.controller `
        -Name 'controller'
}

$cleanupState = Wait-CleanEbpfState
$cleanupPath = Join-Path $evidenceDirectory 'ebpf-manual-cleanup.txt'
$cleanupState |
    Set-Content -LiteralPath $cleanupPath -Encoding UTF8

if (Test-Path -LiteralPath $statePath) {
    Remove-Item -LiteralPath $statePath -Force
}
if (Test-Path -LiteralPath $stopRequestPath) {
    Remove-Item -LiteralPath $stopRequestPath -Force
}
Write-EvidenceManifest -Directory $evidenceDirectory

Write-Host (
    "Stopped OBI Windows demo and verified clean eBPF state: $cleanupPath " +
    "(forced=$($forced.ToString().ToLowerInvariant()))"
)
