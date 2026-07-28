# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BaseStageDirectory,

    [string]$OutputDirectory = (
        Join-Path $PSScriptRoot '..\artifacts\windows-demo-package'
    )
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-FileRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$BasePath
    )

    $item = Get-Item -LiteralPath $Path
    [ordered]@{
        path = $item.FullName.Substring($BasePath.Length).
            TrimStart('\').Replace('\', '/')
        length = $item.Length
        sha256 = (
            Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName
        ).Hash
    }
}

$repositoryRoot = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\..')
)
$exampleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$baseStageDirectory = [IO.Path]::GetFullPath($BaseStageDirectory)
$outputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

$obiCommit = (& git.exe -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $obiCommit) {
    throw 'Failed to resolve the OBI source commit'
}
$changes = & git.exe -C $repositoryRoot status --porcelain=v1 `
    --untracked-files=all --ignore-submodules=none
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to inspect the OBI source state'
}
if ($changes) {
    throw 'The OBI source must be clean before building an integrity-bound demo package'
}

$baseFiles = @(
    'obi.exe',
    'obi-windows-http-client.exe',
    'obi_process_start.sys',
    'obi_flow_classify.sys'
)
foreach ($file in $baseFiles) {
    $path = Join-Path $baseStageDirectory $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required base stage file does not exist: $path"
    }
}

if (Test-Path -LiteralPath $outputDirectory) {
    if (Get-ChildItem -LiteralPath $outputDirectory -Force) {
        throw "Output directory must not contain stale artifacts: $outputDirectory"
    }
} else {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

foreach ($file in $baseFiles) {
    Copy-Item `
        -LiteralPath (Join-Path $baseStageDirectory $file) `
        -Destination $outputDirectory
}
foreach ($optionalFile in @(
        'obi_flow_classify.cer',
        'source-commits.json',
        'runtime-hashes.json',
        'http-build-metadata.json',
        'Deploy-FlowClassifyRuntime.ps1'
    )) {
    $path = Join-Path $baseStageDirectory $optionalFile
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Copy-Item -LiteralPath $path -Destination $outputDirectory
    }
}
$baseRuntime = Join-Path $baseStageDirectory 'runtime'
if (Test-Path -LiteralPath $baseRuntime -PathType Container) {
    Copy-Item `
        -LiteralPath $baseRuntime `
        -Destination $outputDirectory `
        -Recurse
}

$originalGoOS = $env:GOOS
$originalGoArch = $env:GOARCH
$originalGoCache = $env:GOCACHE
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOCACHE = Join-Path $outputDirectory '.gocache'
    & go.exe build `
        -trimpath `
        -o (Join-Path $outputDirectory 'obi-windows-http-demo-target.exe') `
        './examples/windows-process-tracing/http-demo-target'
    if ($LASTEXITCODE -ne 0) {
        throw "Build HTTP demo target failed with exit code $LASTEXITCODE"
    }
} finally {
    $env:GOOS = $originalGoOS
    $env:GOARCH = $originalGoArch
    $env:GOCACHE = $originalGoCache
}
Remove-Item `
    -LiteralPath (Join-Path $outputDirectory '.gocache') `
    -Recurse `
    -Force

Copy-Item `
    -LiteralPath (Join-Path $exampleRoot 'collector-demo') `
    -Destination $outputDirectory `
    -Recurse
foreach ($script in @(
        'Get-Jaeger.ps1',
        'Start-OBIWindowsDemo.ps1',
        'Stop-OBIWindowsDemo.ps1'
    )) {
    Copy-Item `
        -LiteralPath (Join-Path $PSScriptRoot $script) `
        -Destination $outputDirectory
}
Copy-Item `
    -LiteralPath (Join-Path $exampleRoot 'WINDOWS-DEMO.md') `
    -Destination $outputDirectory

$metadata = [ordered]@{
    schema_version = 1
    built_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    obi_commit = $obiCommit
    base_stage_directory = $baseStageDirectory
    go_version = (& go.exe version).Trim()
    base_artifacts = @(
        $baseFiles | ForEach-Object {
            Get-FileRecord `
                -Path (Join-Path $baseStageDirectory $_) `
                -BasePath $baseStageDirectory
        }
    )
}
$metadataPath = Join-Path $outputDirectory 'demo-build-metadata.json'
$metadata |
    ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $metadataPath -Encoding UTF8

$manifestPath = Join-Path $outputDirectory 'demo-package-hashes.json'
$records = @(
    Get-ChildItem -LiteralPath $outputDirectory -Recurse -File |
        Where-Object FullName -NE $manifestPath |
        Sort-Object FullName |
        ForEach-Object {
            Get-FileRecord -Path $_.FullName -BasePath $outputDirectory
        }
)
$records |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $manifestPath -Encoding UTF8

foreach ($record in $records) {
    $path = Join-Path $outputDirectory $record.path
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
    if ($actualHash -ne $record.sha256) {
        throw "Package hash verification failed: $($record.path)"
    }
}

Write-Host "OBI source: $obiCommit"
Write-Host "Package:    $outputDirectory"
Write-Host "Manifest:   $manifestPath"
