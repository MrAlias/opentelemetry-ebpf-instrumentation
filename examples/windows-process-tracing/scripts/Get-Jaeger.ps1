# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\jaeger')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$version = '2.20.0'
$archiveName = "jaeger-$version-windows-amd64.zip"
$releaseBase = "https://github.com/jaegertracing/jaeger/releases/download/v$version"
$expectedArchiveSha256 = 'B36B2CC2A4ED654679048FA6DEE511B2A59D310805FF247EABEF6FC499B29505'
$expectedExecutableSha256 = '1B641779599CAC3587B9DF21A92A20ED68DD8802254953A96193C08DA4008348'

$outputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$archivePath = Join-Path $outputDirectory $archiveName
$partialArchivePath = "$archivePath.partial"
$extractDirectory = Join-Path $outputDirectory "jaeger-$version-windows-amd64"
$jaegerPath = Join-Path $extractDirectory 'jaeger.exe'

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    if (Test-Path -LiteralPath $partialArchivePath) {
        Remove-Item -LiteralPath $partialArchivePath -Force
    }
    Invoke-WebRequest `
        -UseBasicParsing `
        -Uri "$releaseBase/$archiveName" `
        -OutFile $partialArchivePath

    $partialSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $partialArchivePath
    ).Hash
    if ($partialSha256 -ne $expectedArchiveSha256) {
        throw "Downloaded Jaeger archive SHA-256 mismatch: expected $expectedArchiveSha256, got $partialSha256"
    }
    Move-Item `
        -LiteralPath $partialArchivePath `
        -Destination $archivePath
}

$actualArchiveSha256 = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath
).Hash
if ($actualArchiveSha256 -ne $expectedArchiveSha256) {
    throw "Jaeger archive SHA-256 mismatch: expected $expectedArchiveSha256, got $actualArchiveSha256"
}

if (-not (Test-Path -LiteralPath $jaegerPath -PathType Leaf)) {
    Expand-Archive `
        -LiteralPath $archivePath `
        -DestinationPath $outputDirectory `
        -Force
}
if (-not (Test-Path -LiteralPath $jaegerPath -PathType Leaf)) {
    throw "Jaeger executable was not extracted: $jaegerPath"
}

$actualExecutableSha256 = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $jaegerPath
).Hash
if ($actualExecutableSha256 -ne $expectedExecutableSha256) {
    throw "Jaeger executable SHA-256 mismatch: expected $expectedExecutableSha256, got $actualExecutableSha256"
}

[ordered]@{
    version = $version
    executable = $jaegerPath
    archive_sha256 = $actualArchiveSha256
    executable_sha256 = $actualExecutableSha256
} | ConvertTo-Json
