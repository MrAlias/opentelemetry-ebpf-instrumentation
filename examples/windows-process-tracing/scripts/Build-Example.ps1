# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$EbpfForWindowsSource = 'C:\src\ebpf-for-windows',

    [string]$NtosEbpfExtSource = 'C:\src\ntosebpfext',

    [string]$ExpectedEbpfForWindowsCommit = '09fb1397e560513e3710269920346c9c9c60afbd',

    [string]$ExpectedNtosEbpfExtCommit = 'bb41d8b10c488a28d98c874b1b1a55f40f22dc44',

    [string]$EbpfForWindowsInstall = 'C:\Program Files\ebpf-for-windows',

    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts'),

    [string]$ReleaseVersion,

    [string]$ReleaseRevision
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$exampleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$ebpfForWindowsSource = [IO.Path]::GetFullPath($EbpfForWindowsSource)
$ntosEbpfExtSource = [IO.Path]::GetFullPath($NtosEbpfExtSource)
$ebpfForWindowsInstall = [IO.Path]::GetFullPath($EbpfForWindowsInstall)
$outputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

$clang = 'C:\Program Files\LLVM\bin\clang.exe'
$bpfSource = Join-Path $exampleRoot 'bpf\obi_process_start.c'
$bpfObject = Join-Path $outputDirectory 'obi_process_start.o'
$processProgram = Join-Path $outputDirectory 'obi_process_start.sys'
$converter = Join-Path $outputDirectory 'Convert-BpfToNative.ps1'
$nativeTools = Join-Path $outputDirectory 'native-tools'
$programInfoExporter = Join-Path $ntosEbpfExtSource 'x64\Release\ntos_ebpf_ext_export_program_info.exe'
$installedBpf2c = Join-Path $ebpfForWindowsInstall 'bpf2c.exe'
$installedEbpfApi = Join-Path $ebpfForWindowsInstall 'EbpfApi.dll'
$converterTemplate = Join-Path $ebpfForWindowsSource 'tools\bpf2c\Convert-BpfToNative.ps1.template'
$converterConfig = Join-Path $ebpfForWindowsSource 'tools\bpf2c\replacements.json'
$templateProcessor = Join-Path $ebpfForWindowsSource 'scripts\Process-File.ps1'

foreach ($requiredPath in @(
        $repositoryRoot,
        $ebpfForWindowsSource,
        $ntosEbpfExtSource,
        $ebpfForWindowsInstall,
        $clang,
        $bpfSource,
        $programInfoExporter,
        $installedBpf2c,
        $installedEbpfApi,
        $converterTemplate,
        $converterConfig,
        $templateProcessor
    )) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path not found: $requiredPath"
    }
}

$ebpfForWindowsCommit = (& git.exe -C $ebpfForWindowsSource rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $ebpfForWindowsCommit) {
    throw 'Failed to resolve the eBPF-for-Windows source commit'
}
if ($ebpfForWindowsCommit -ne $ExpectedEbpfForWindowsCommit) {
    throw "eBPF-for-Windows commit $ebpfForWindowsCommit does not match expected $ExpectedEbpfForWindowsCommit"
}
$sourceStatusArguments = @(
    'status'
    '--porcelain=v1'
    '--untracked-files=all'
    '--ignore-submodules=none'
)
$ebpfTrackedChanges = & git.exe -C $ebpfForWindowsSource @sourceStatusArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to inspect the eBPF-for-Windows source state'
}
if ($ebpfTrackedChanges) {
    throw 'The eBPF-for-Windows source must be clean, including all submodules'
}

$ntosEbpfExtCommit = (& git.exe -C $ntosEbpfExtSource rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $ntosEbpfExtCommit) {
    throw 'Failed to resolve the ntosebpfext source commit'
}
if ($ntosEbpfExtCommit -ne $ExpectedNtosEbpfExtCommit) {
    throw "ntosebpfext commit $ntosEbpfExtCommit does not match expected $ExpectedNtosEbpfExtCommit"
}
$ntosTrackedChanges = & git.exe -C $ntosEbpfExtSource @sourceStatusArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to inspect the ntosebpfext source state'
}
if ($ntosTrackedChanges) {
    throw 'The ntosebpfext source must be clean, including all submodules'
}

if ($nativeTools -match '\s') {
    throw "The eBPF-for-Windows v1.3 converter cannot use a tool path containing whitespace: $nativeTools"
}

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $nativeTools | Out-Null

Push-Location $repositoryRoot
try {
    $repositoryCommit = (& git.exe rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $repositoryCommit) {
        throw 'Failed to resolve the OBI repository commit'
    }

    # The evidence default is branch-independent and explicitly marks a dirty
    # source tree; it is injected through the same buildinfo symbols as Make.
    if (-not $ReleaseVersion) {
        $ReleaseVersion = (& git.exe describe --tags --always --dirty).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $ReleaseVersion) {
            throw 'Failed to derive the OBI release version'
        }
    }
    if (-not $ReleaseRevision) {
        $ReleaseRevision = $repositoryCommit
    }
    if ($ReleaseVersion -eq 'unset' -or $ReleaseRevision -eq 'unset') {
        throw 'OBI release version and revision must not be unset'
    }
    if ($ReleaseRevision -ne $repositoryCommit) {
        throw "Release revision $ReleaseRevision does not match repository HEAD $repositoryCommit"
    }

    $goOS = (& go.exe env GOOS).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $goOS) {
        throw 'Failed to resolve the Go target operating system'
    }
    $goArch = (& go.exe env GOARCH).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $goArch) {
        throw 'Failed to resolve the Go target architecture'
    }
    if ($goOS -cne 'windows' -or $goArch -cne 'amd64') {
        throw "The Windows example requires GOOS=windows and GOARCH=amd64; got GOOS=$goOS GOARCH=$goArch"
    }

    $obiExecutable = Join-Path $outputDirectory 'obi.exe'
    $targetExecutable = Join-Path $outputDirectory 'obi-windows-target.exe'
    $httpClientExecutable = Join-Path $outputDirectory 'obi-windows-http-client.exe'
    $sourceDescription = (& git.exe describe --tags --always --dirty).Trim()
    $linkerFlags = @(
        "-X=go.opentelemetry.io/obi/pkg/buildinfo.Version=$ReleaseVersion"
        "-X=go.opentelemetry.io/obi/pkg/buildinfo.Revision=$ReleaseRevision"
    ) -join ' '

    & go.exe test ./cmd/obi
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows OBI unit tests failed'
    }

    & go.exe build -trimpath -ldflags $linkerFlags `
        -o $obiExecutable ./cmd/obi
    if ($LASTEXITCODE -ne 0) {
        throw 'obi.exe build failed'
    }

    & go.exe build -trimpath -o $targetExecutable `
        ./examples/windows-process-tracing/target
    if ($LASTEXITCODE -ne 0) {
        throw 'deterministic target build failed'
    }

    & go.exe test ./examples/windows-process-tracing/http-client
    if ($LASTEXITCODE -ne 0) {
        throw 'HTTP client unit tests failed'
    }

    & go.exe build -trimpath -o $httpClientExecutable `
        ./examples/windows-process-tracing/http-client
    if ($LASTEXITCODE -ne 0) {
        throw 'instrumented HTTP client build failed'
    }

    $obiBuildInfo = @(& go.exe version -m $obiExecutable)
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to inspect the built obi.exe'
    }
    $obiBuildInfoText = $obiBuildInfo -join [Environment]::NewLine
    if ($obiBuildInfoText -cnotmatch '(?m)^\s*build\s+GOOS=windows\s*$' -or
        $obiBuildInfoText -cnotmatch '(?m)^\s*build\s+GOARCH=amd64\s*$') {
        throw 'Built obi.exe does not report GOOS=windows and GOARCH=amd64'
    }

    [ordered]@{
        version = $ReleaseVersion
        revision = $ReleaseRevision
        repository_commit = $repositoryCommit
        source_description = $sourceDescription
        build_script_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash
        go_target = [ordered]@{
            os = $goOS
            arch = $goArch
        }
        ebpf_for_windows = [ordered]@{
            source_path = $ebpfForWindowsSource
            commit = $ebpfForWindowsCommit
            expected_commit = $ExpectedEbpfForWindowsCommit
            converter_template_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $converterTemplate).Hash
            converter_config_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $converterConfig).Hash
            installed_bpf2c = [ordered]@{
                path = $installedBpf2c
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedBpf2c).Hash
                file_version = (Get-Item -LiteralPath $installedBpf2c).VersionInfo.FileVersion
            }
            installed_ebpf_api = [ordered]@{
                path = $installedEbpfApi
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedEbpfApi).Hash
                file_version = (Get-Item -LiteralPath $installedEbpfApi).VersionInfo.FileVersion
            }
        }
        ntosebpfext = [ordered]@{
            source_path = $ntosEbpfExtSource
            commit = $ntosEbpfExtCommit
            expected_commit = $ExpectedNtosEbpfExtCommit
            program_info_exporter_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $programInfoExporter).Hash
        }
    } |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $outputDirectory 'obi-build-metadata.json') -Encoding UTF8
}
finally {
    Pop-Location
}

& $clang `
    -target bpf `
    -O2 `
    -g `
    -Werror `
    -I (Join-Path $ebpfForWindowsSource 'include') `
    -I (Join-Path $ntosEbpfExtSource 'include') `
    -c $bpfSource `
    -o $bpfObject
if ($LASTEXITCODE -ne 0) {
    throw 'eBPF process probe compilation failed'
}

& $programInfoExporter
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to register the ntosebpfext process program and attach metadata'
}


Push-Location (Join-Path $ebpfForWindowsSource 'tools\bpf2c')
try {
    & $templateProcessor `
        -InputFile $converterTemplate `
        -OutputFile $converter `
        -ConfigFile $converterConfig
}
finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to generate Convert-BpfToNative.ps1'
}

Copy-Item -LiteralPath $installedBpf2c -Destination $nativeTools -Force
Copy-Item -LiteralPath $installedEbpfApi -Destination $nativeTools -Force

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$visualStudio = & $vswhere `
    -latest `
    -products * `
    -requires `
        Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        Component.Microsoft.Windows.DriverKit `
    -property installationPath
if (-not $visualStudio) {
    throw 'Visual Studio with C++ build tools and the WDK integration was not found'
}

$devShellModule = Join-Path $visualStudio 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
Import-Module $devShellModule
Enter-VsDevShell -VsInstallPath $visualStudio -SkipAutomaticLocation -DevCmdArguments '-arch=x64'

if (Test-Path -LiteralPath $processProgram) {
    Remove-Item -LiteralPath $processProgram -Force
}

Push-Location $outputDirectory
try {
    & $converter `
        -FileName 'obi_process_start' `
        -Type 'process' `
        -IncludeDir (Join-Path $ebpfForWindowsSource 'include') `
        -BinDir $nativeTools `
        -OutDir $outputDirectory `
        -Platform 'x64' `
        -Configuration 'Release' `
        -KernelMode $true `
        -Verbose
    $converterExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
if ($converterExitCode -ne 0 -or -not (Test-Path -LiteralPath $processProgram)) {
    throw 'Native eBPF process driver build failed'
}

$signature = Get-AuthenticodeSignature -LiteralPath $processProgram
if ($null -eq $signature.SignerCertificate) {
    throw 'Native eBPF process driver has no Authenticode signer certificate'
}

if ($signature.Status -eq 'Valid') {
    $signTool = (Get-Command signtool.exe -ErrorAction Stop).Source
    & $signTool verify /kp /v $processProgram
    if ($LASTEXITCODE -ne 0) {
        throw 'Kernel-mode signature verification failed for the native eBPF process driver'
    }
}
elseif ($signature.Status -eq 'UnknownError' -and
    $signature.StatusMessage -like '*terminated in a root certificate which is not trusted*' -and
    $signature.SignerCertificate.Subject -like '*WDKTestCert*') {
    $bootConfiguration = & bcdedit.exe /enum '{current}' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to read the Windows boot test-signing configuration'
    }
    $bootConfigurationText = $bootConfiguration -join [Environment]::NewLine
    if ($bootConfigurationText -notmatch '(?im)^\s*testsigning\s+Yes\s*$') {
        throw 'The WDK test certificate is untrusted and Windows test-signing mode is not enabled'
    }

    Write-Warning @'
The native eBPF driver has an embedded WDK test signature whose self-signed
root is not trusted for production. Windows test-signing mode is enabled.
This is acceptable only for this development proof of concept.
'@
}
else {
    throw "Native eBPF process driver signature status is $($signature.Status)"
}

Write-Host "OBI version:     $ReleaseVersion"
Write-Host "OBI revision:    $ReleaseRevision"
Write-Host "OBI:             $obiExecutable"
Write-Host "Target:          $targetExecutable"
Write-Host "HTTP client:     $httpClientExecutable"
Write-Host "Process program: $processProgram"
Write-Host "Signature:       $($signature.Status), $($signature.SignerCertificate.Subject)"
Write-Host "Signer SHA-1:    $($signature.SignerCertificate.Thumbprint)"
Get-FileHash -Algorithm SHA256 `
    (Join-Path $outputDirectory 'obi.exe'), `
    (Join-Path $outputDirectory 'obi-windows-target.exe'), `
    (Join-Path $outputDirectory 'obi-windows-http-client.exe'), `
    $bpfObject, `
    $processProgram

$obiBuildInfo
