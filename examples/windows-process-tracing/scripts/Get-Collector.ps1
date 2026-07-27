# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\collector')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$version = '0.151.0'
$archiveName = "otelcol-contrib_${version}_windows_amd64.tar.gz"
$releaseBase = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$version"
$expectedSha256 = '38BE8AD3222D02A50EA895385EE90AC0CA9E241EA13AF8FC06800B40C0E541D1'

$outputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$archivePath = Join-Path $outputDirectory $archiveName
$extractDirectory = Join-Path $outputDirectory 'otelcol-contrib'
$collectorPath = Join-Path $extractDirectory 'otelcol-contrib.exe'

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

if (-not (Test-Path -LiteralPath $archivePath)) {
    Invoke-WebRequest -UseBasicParsing -Uri "$releaseBase/$archiveName" -OutFile $archivePath
}

$actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash
if ($actualSha256 -ne $expectedSha256) {
    throw "Collector archive SHA-256 mismatch: expected $expectedSha256, got $actualSha256"
}

New-Item -ItemType Directory -Force -Path $extractDirectory | Out-Null
tar.exe -xf $archivePath -C $extractDirectory
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $collectorPath)) {
    throw "Failed to extract $collectorPath"
}

Write-Host "Collector: $collectorPath"
Write-Host "SHA-256:  $actualSha256"
