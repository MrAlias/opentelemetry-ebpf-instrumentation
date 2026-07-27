# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$EbpfForWindowsSource = 'C:\src\ebpf-for-windows',

    [string]$NtosEbpfExtSource = 'C:\src\ntosebpfext',

    [string]$ExpectedEbpfForWindowsCommit = '09fb1397e560513e3710269920346c9c9c60afbd',

    [string]$ExpectedNtosEbpfExtCommit = 'bb41d8b10c488a28d98c874b1b1a55f40f22dc44',

    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\http-build')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$exampleRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$ebpfForWindowsSource = [IO.Path]::GetFullPath($EbpfForWindowsSource)
$ntosEbpfExtSource = [IO.Path]::GetFullPath($NtosEbpfExtSource)
$outputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$runtimeDirectory = Join-Path $outputDirectory 'runtime'
$packageDirectory = Join-Path $outputDirectory 'vm-package'
$buildScript = Join-Path $PSScriptRoot 'Build-Example.ps1'
$runScript = Join-Path $PSScriptRoot 'Run-HTTPExample.ps1'
$deployScript = Join-Path $PSScriptRoot 'Deploy-FlowClassifyRuntime.ps1'
$flowSource = Join-Path $exampleRoot 'bpf\obi_flow_classify.c'
$flowObject = Join-Path $outputDirectory 'obi_flow_classify.o'
$flowProgram = Join-Path $outputDirectory 'obi_flow_classify.sys'
$commands = [Collections.Generic.List[object]]::new()

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [object[]]$ArgumentList,

        [Parameter(Mandatory)]
        [string]$Description
    )

    $displayArguments = @($ArgumentList | ForEach-Object {
            $argument = $_.ToString()
            if ($argument -match '\s') {
                '"{0}"' -f $argument.Replace('"', '\"')
            } else {
                $argument
            }
        })
    $commands.Add([ordered]@{
            description = $Description
            command = ('"{0}" {1}' -f $FilePath, ($displayArguments -join ' '))
            working_directory = (Get-Location).Path
        })

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Get-GitValue {
    param(
        [Parameter(Mandatory)]
        [string]$Repository,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $result = (& git.exe -C $Repository @Arguments).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $result) {
        throw "Git command failed in $Repository"
    }
    return $result
}

function Assert-CleanSource {
    param(
        [Parameter(Mandatory)]
        [string]$Repository,

        [Parameter(Mandatory)]
        [string]$ExpectedCommit,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $commit = Get-GitValue -Repository $Repository -Arguments @('rev-parse', 'HEAD')
    if ($commit -ne $ExpectedCommit) {
        throw "$Name commit $commit does not match expected $ExpectedCommit"
    }

    $changes = & git.exe -C $Repository status --porcelain=v1 `
        --untracked-files=all --ignore-submodules=none
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to inspect $Name source state"
    }
    if ($changes) {
        throw "$Name source must be clean, including all submodules"
    }

    return $commit
}

function Get-FileRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$BasePath
    )

    $item = Get-Item -LiteralPath $Path
    $recordPath = $item.FullName
    if ($BasePath) {
        $recordPath = $item.FullName.Substring($BasePath.Length).TrimStart('\')
    }

    return [ordered]@{
        path = $recordPath.Replace('\', '/')
        length = $item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Get-SignatureRecord {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -eq $signature.SignerCertificate) {
        throw "Signed artifact has no signer certificate: $Path"
    }

    return [ordered]@{
        status = $signature.Status.ToString()
        status_message = $signature.StatusMessage
        subject = $signature.SignerCertificate.Subject
        thumbprint = $signature.SignerCertificate.Thumbprint
    }
}

foreach ($requiredPath in @(
        $repositoryRoot,
        $exampleRoot,
        $ebpfForWindowsSource,
        $ntosEbpfExtSource,
        $buildScript,
        $runScript,
        $deployScript,
        $flowSource,
        'C:\Program Files\LLVM\bin\clang.exe',
        'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    )) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path not found: $requiredPath"
    }
}

$obiCommit = Get-GitValue -Repository $repositoryRoot -Arguments @('rev-parse', 'HEAD')
$obiChanges = & git.exe -C $repositoryRoot status --porcelain=v1 `
    --untracked-files=all --ignore-submodules=none
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to inspect the OBI source state'
}
if ($obiChanges) {
    throw 'The OBI source must be clean'
}

$ebpfForWindowsCommit = Assert-CleanSource `
    -Repository $ebpfForWindowsSource `
    -ExpectedCommit $ExpectedEbpfForWindowsCommit `
    -Name 'eBPF-for-Windows'
$ntosEbpfExtCommit = Assert-CleanSource `
    -Repository $ntosEbpfExtSource `
    -ExpectedCommit $ExpectedNtosEbpfExtCommit `
    -Name 'ntosebpfext'

if (Test-Path -LiteralPath $outputDirectory) {
    if (Get-ChildItem -LiteralPath $outputDirectory -Force) {
        throw "Output directory must not contain stale artifacts: $outputDirectory"
    }
} else {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}
New-Item -ItemType Directory -Path $runtimeDirectory | Out-Null
New-Item -ItemType Directory -Path (Join-Path $outputDirectory 'work') | Out-Null

$originalPath = [Environment]::GetEnvironmentVariable(
    'Path',
    [EnvironmentVariableTarget]::Process
)
$originalGoOS = $env:GOOS
$originalGoArch = $env:GOARCH
$originalGoCache = $env:GOCACHE
$originalCL = $env:CL
$originalVisualStudioVersion = $env:VisualStudioVersion
$transcriptPath = Join-Path $outputDirectory 'build-transcript.log'
$transcriptStarted = $false

try {
    Start-Transcript -LiteralPath $transcriptPath | Out-Null
    $transcriptStarted = $true

    [Environment]::SetEnvironmentVariable(
        'PATH',
        $null,
        [EnvironmentVariableTarget]::Process
    )
    [Environment]::SetEnvironmentVariable(
        'Path',
        $originalPath,
        [EnvironmentVariableTarget]::Process
    )

    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    $visualStudio = (& $vswhere -latest -products * -requires `
            Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            Component.Microsoft.Windows.DriverKit -property installationPath).Trim()
    if (-not $visualStudio) {
        throw 'Visual Studio with C++ and WDK integration was not found'
    }
    $msbuild = Join-Path $visualStudio 'MSBuild\Current\Bin\amd64\MSBuild.exe'
    if (-not (Test-Path -LiteralPath $msbuild)) {
        throw "64-bit MSBuild not found: $msbuild"
    }

    $wdkPackage = Get-ChildItem `
        (Join-Path $ebpfForWindowsSource 'packages') `
        -Directory `
        -Filter 'Microsoft.Windows.WDK.x64.*' |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($null -eq $wdkPackage) {
        throw 'Restored eBPF-for-Windows WDK package was not found'
    }
    $wdkVersionDirectory = Get-ChildItem `
        (Join-Path $wdkPackage.FullName 'c\bin') `
        -Directory |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($null -eq $wdkVersionDirectory) {
        throw 'Restored eBPF-for-Windows WDK tools were not found'
    }
    $wdkBin = Join-Path $wdkVersionDirectory.FullName 'x64'
    $env:Path = "$wdkBin;$originalPath"
    $env:VisualStudioVersion = '17.0'
    $env:CL = '/wd4875 /wd4090'

    Invoke-Checked `
        -FilePath $msbuild `
        -ArgumentList @(
            (Join-Path $ebpfForWindowsSource 'scripts\setup_build\setup_build.vcxproj'),
            '/t:Build',
            '/m:1',
            '/p:Configuration=Debug',
            '/p:Platform=x64',
            '/p:PlatformToolset=v145',
            "/p:SolutionDir=$ebpfForWindowsSource\",
            '/verbosity:minimal'
        ) `
        -Description 'Generate eBPF-for-Windows build metadata'
    Invoke-Checked `
        -FilePath $msbuild `
        -ArgumentList @(
            (Join-Path $ebpfForWindowsSource `
                'external\usersim\cxplat\src\cxplat_winkernel\cxplat_winkernel.vcxproj'),
            '/t:restore',
            '/p:Platform=x64',
            '/verbosity:minimal'
        ) `
        -Description 'Restore the kernel cxplat SDK package'

    $commonMsBuildArguments = @(
        '/t:Rebuild',
        '/m:1',
        '/p:Configuration=Debug',
        '/p:Platform=x64',
        "/p:SolutionDir=$ebpfForWindowsSource\",
        '/p:IoctlSpecPlatformToolset=v145',
        '/p:SkipPackageVerification=true',
        '/p:ApiValidator_Enable=false',
        '/verbosity:minimal'
    )
    $kernelProjects = @(
        'ebpfcore\EbpfCore.vcxproj',
        'netebpfext\sys\netebpfext.vcxproj'
    )
    foreach ($project in $kernelProjects) {
        Invoke-Checked `
            -FilePath $msbuild `
            -ArgumentList (@(
                (Join-Path $ebpfForWindowsSource $project)
            ) + $commonMsBuildArguments) `
            -Description "Build eBPF-for-Windows $project"
    }

    $userProjects = @(
        'ebpfapi\ebpfapi.vcxproj',
        'tools\bpf2c\bpf2c.vcxproj',
        'tools\netsh\ebpfnetsh.vcxproj',
        'tools\export_program_info\export_program_info.vcxproj',
        'ebpfsvc\eBPFSvc.vcxproj'
    )
    foreach ($project in $userProjects) {
        Invoke-Checked `
            -FilePath $msbuild `
            -ArgumentList (@(
                (Join-Path $ebpfForWindowsSource $project),
                '/p:PlatformToolset=v145'
            ) + $commonMsBuildArguments) `
            -Description "Build eBPF-for-Windows $project"
    }

    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOCACHE = Join-Path $outputDirectory 'work\go-cache'
    Invoke-Checked `
        -FilePath $buildScript `
        -ArgumentList @(
            '-EbpfForWindowsSource', $ebpfForWindowsSource,
            '-NtosEbpfExtSource', $ntosEbpfExtSource,
            '-ExpectedEbpfForWindowsCommit', $ExpectedEbpfForWindowsCommit,
            '-ExpectedNtosEbpfExtCommit', $ExpectedNtosEbpfExtCommit,
            '-EbpfForWindowsInstall', (Join-Path $ebpfForWindowsSource 'x64\Debug'),
            '-OutputDirectory', $outputDirectory
        ) `
        -Description 'Build OBI, target, client, and process probe'

    $clang = 'C:\Program Files\LLVM\bin\clang.exe'
    Invoke-Checked `
        -FilePath $clang `
        -ArgumentList @(
            '-target', 'bpf',
            '-O2',
            '-g',
            '-Werror',
            '-I', (Join-Path $ebpfForWindowsSource 'include'),
            '-c', $flowSource,
            '-o', $flowObject
        ) `
        -Description 'Compile the Flow Classify eBPF program'

    $programInfoExporter = Join-Path `
        $ebpfForWindowsSource `
        'x64\Debug\export_program_info.exe'
    Invoke-Checked `
        -FilePath $programInfoExporter `
        -ArgumentList @('--flow-classify') `
        -Description 'Register Flow Classify program metadata'
    Invoke-Checked `
        -FilePath 'netsh.exe' `
        -ArgumentList @(
            'ebpf', 'show', 'verification',
            "filename=$flowObject",
            'section=flow_classify',
            'program=obi_flow_classify',
            'type=flow_classify',
            'level=normal'
        ) `
        -Description 'Verify the Flow Classify eBPF program'

    $converter = Join-Path $outputDirectory 'Convert-BpfToNative.ps1'
    Invoke-Checked `
        -FilePath $converter `
        -ArgumentList @(
            '-FileName', 'obi_flow_classify',
            '-Type', 'flow_classify',
            '-IncludeDir', (Join-Path $ebpfForWindowsSource 'include'),
            '-BinDir', (Join-Path $outputDirectory 'native-tools'),
            '-OutDir', $outputDirectory,
            '-Platform', 'x64',
            '-Configuration', 'Debug',
            '-KernelMode', $true,
            '-Verbose'
        ) `
        -Description 'Build the native Flow Classify program'

    if (-not (Test-Path -LiteralPath $flowProgram)) {
        throw "Native Flow Classify program not found: $flowProgram"
    }

    $runtimeSources = [ordered]@{
        'EbpfCore.sys' = Join-Path $ebpfForWindowsSource 'x64\Debug\EbpfCore.sys'
        'EbpfCore.inf' = Join-Path $ebpfForWindowsSource 'x64\Debug\EbpfCore.inf'
        'ebpfcore.cat' = Join-Path $ebpfForWindowsSource 'x64\Debug\EbpfCore\ebpfcore.cat'
        'EbpfCore.cer' = Join-Path $ebpfForWindowsSource 'x64\Debug\EbpfCore.cer'
        'netebpfext.sys' = Join-Path $ebpfForWindowsSource 'x64\Debug\netebpfext.sys'
        'NetEbpfExt.inf' = Join-Path $ebpfForWindowsSource 'x64\Debug\NetEbpfExt.inf'
        'netebpfext.cat' = Join-Path $ebpfForWindowsSource 'x64\Debug\netebpfext\netebpfext.cat'
        'EbpfApi.dll' = Join-Path $ebpfForWindowsSource 'x64\Debug\EbpfApi.dll'
        'bpf2c.exe' = Join-Path $ebpfForWindowsSource 'x64\Debug\bpf2c.exe'
        'ebpfnetsh.dll' = Join-Path $ebpfForWindowsSource 'x64\Debug\ebpfnetsh.dll'
        'export_program_info.exe' = $programInfoExporter
        'ebpfsvc.exe' = Join-Path $ebpfForWindowsSource 'x64\Debug\ebpfsvc.exe'
    }
    $ucrt = Get-ChildItem `
        (Join-Path $ebpfForWindowsSource 'packages') `
        -Recurse `
        -File `
        -Filter 'ucrtbased.dll' |
        Where-Object FullName -Match '\\x64\\ucrt\\ucrtbased\.dll$' |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($null -eq $ucrt) {
        throw 'Debug UCRT runtime was not found'
    }
    $runtimeSources['ucrtbased.dll'] = $ucrt.FullName

    foreach ($entry in $runtimeSources.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "Runtime artifact not found: $($entry.Value)"
        }
        Copy-Item `
            -LiteralPath $entry.Value `
            -Destination (Join-Path $runtimeDirectory $entry.Key)
    }

    $driverSignatures = [ordered]@{
        ebpf_core = Get-SignatureRecord `
            -Path (Join-Path $runtimeDirectory 'EbpfCore.sys')
        net_ebpf_ext = Get-SignatureRecord `
            -Path (Join-Path $runtimeDirectory 'netebpfext.sys')
        process_program = Get-SignatureRecord `
            -Path (Join-Path $outputDirectory 'obi_process_start.sys')
        flow_program = Get-SignatureRecord -Path $flowProgram
    }
}
finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
    [Environment]::SetEnvironmentVariable(
        'Path',
        $originalPath,
        [EnvironmentVariableTarget]::Process
    )
    $env:GOOS = $originalGoOS
    $env:GOARCH = $originalGoArch
    $env:GOCACHE = $originalGoCache
    $env:CL = $originalCL
    $env:VisualStudioVersion = $originalVisualStudioVersion
}

$runtimeRecords = @(
    Get-ChildItem -LiteralPath $runtimeDirectory -File |
        Sort-Object Name |
        ForEach-Object {
            Get-FileRecord -Path $_.FullName -BasePath $runtimeDirectory
        }
)
$sourceCommits = [ordered]@{
    built_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    obi_commit = $obiCommit
    ebpf_for_windows_commit = $ebpfForWindowsCommit
    ntosebpfext_commit = $ntosEbpfExtCommit
}
$toolVersions = [ordered]@{
    powershell = $PSVersionTable.PSVersion.ToString()
    git = (& git.exe --version).Trim()
    go = (& go.exe version).Trim()
    clang = (& 'C:\Program Files\LLVM\bin\clang.exe' --version | Select-Object -First 1).Trim()
    msbuild = (& $msbuild -version -nologo | Select-Object -Last 1).Trim()
}
$metadata = [ordered]@{
    schema_version = 1
    source = $sourceCommits
    expected = [ordered]@{
        ebpf_for_windows_commit = $ExpectedEbpfForWindowsCommit
        ntosebpfext_commit = $ExpectedNtosEbpfExtCommit
    }
    scripts = [ordered]@{
        build_http_example_sha256 = (
            Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256
        ).Hash
        build_example_sha256 = (
            Get-FileHash -LiteralPath $buildScript -Algorithm SHA256
        ).Hash
        run_http_example_sha256 = (
            Get-FileHash -LiteralPath $runScript -Algorithm SHA256
        ).Hash
        deploy_runtime_sha256 = (
            Get-FileHash -LiteralPath $deployScript -Algorithm SHA256
        ).Hash
    }
    tools = $toolVersions
    commands = @($commands)
    runtime = $runtimeRecords
    signatures = $driverSignatures
}
$sourceCommitsPath = Join-Path $outputDirectory 'source-commits.json'
$runtimeHashesPath = Join-Path $outputDirectory 'runtime-hashes.json'
$metadataPath = Join-Path $outputDirectory 'http-build-metadata.json'
$sourceCommits |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $sourceCommitsPath -Encoding UTF8
$runtimeRecords |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $runtimeHashesPath -Encoding UTF8
$metadata |
    ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $metadataPath -Encoding UTF8

New-Item -ItemType Directory -Path $packageDirectory | Out-Null
Copy-Item -LiteralPath $runtimeDirectory -Destination $packageDirectory -Recurse
foreach ($file in @(
        'obi.exe',
        'obi-windows-target.exe',
        'obi-windows-http-client.exe',
        'obi_process_start.sys',
        'obi_flow_classify.sys',
        'obi_flow_classify.cer',
        'obi-build-metadata.json',
        'http-build-metadata.json',
        'source-commits.json',
        'runtime-hashes.json',
        'build-transcript.log'
    )) {
    Copy-Item `
        -LiteralPath (Join-Path $outputDirectory $file) `
        -Destination $packageDirectory
}
Copy-Item -LiteralPath $runScript -Destination $packageDirectory
Copy-Item -LiteralPath $deployScript -Destination $packageDirectory
Copy-Item `
    -LiteralPath (Join-Path $exampleRoot 'collector.yaml') `
    -Destination $packageDirectory

$packageHashesPath = Join-Path $packageDirectory 'package-hashes.json'
$packageRecords = @(
    Get-ChildItem -LiteralPath $packageDirectory -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            Get-FileRecord -Path $_.FullName -BasePath $packageDirectory
        }
)
$packageRecords |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $packageHashesPath -Encoding UTF8

foreach ($record in $packageRecords) {
    $path = Join-Path $packageDirectory $record.path
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($actualHash -ne $record.sha256) {
        throw "Package hash verification failed: $($record.path)"
    }
}

Write-Host "OBI source:              $obiCommit"
Write-Host "eBPF-for-Windows source: $ebpfForWindowsCommit"
Write-Host "ntosebpfext source:      $ntosEbpfExtCommit"
Write-Host "Package:                 $packageDirectory"
Write-Host "Package manifest:        $packageHashesPath"
