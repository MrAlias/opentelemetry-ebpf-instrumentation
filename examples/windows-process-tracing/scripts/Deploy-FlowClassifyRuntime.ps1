[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$StageDirectory,

    [string]$InstallDirectory = 'C:\Program Files\ebpf-for-windows',

    [string]$BackupRoot = 'C:\src'
)

$ErrorActionPreference = 'Stop'

$runtimeDirectory = Join-Path $StageDirectory 'runtime'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$backupDirectory = Join-Path $BackupRoot "obi-http-flowclassify-backup-$stamp"
$flowProgramKey = 'HKCU:\Software\eBPF\Providers\ProgramData\{1935574a-eaa8-45db-86fd-81f10a231a6d}'
$flowSectionKey = 'HKCU:\Software\eBPF\Providers\SectionData\flow_classify'
$services = @('eBPFCore', 'eBPFSvc', 'NetEbpfExt', 'ntosebpfext')

function Wait-ServiceState {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [System.ServiceProcess.ServiceControllerStatus]$Status
    )

    $service = Get-Service -Name $Name
    $service.WaitForStatus($Status, [TimeSpan]::FromSeconds(20))
}

function Stop-EbpfServices {
    Stop-Service -Name eBPFSvc -Force -ErrorAction SilentlyContinue
    Wait-ServiceState -Name eBPFSvc -Status Stopped

    foreach ($name in @('ntosebpfext', 'NetEbpfExt', 'eBPFCore')) {
        & sc.exe stop $name | Out-Null
        Wait-ServiceState -Name $name -Status Stopped
    }
}

function Start-EbpfServices {
    foreach ($name in $services) {
        & sc.exe start $name | Out-Null
        Wait-ServiceState -Name $name -Status Running
    }
}

function Assert-NoLoadedEbpfObjects {
    foreach ($objectType in @('programs', 'maps', 'links')) {
        $output = netsh.exe ebpf show $objectType 2>&1 | Out-String
        if ($output -match '(?m)^\s*\d+\s+') {
            throw "Live eBPF $objectType exist; refusing deployment"
        }
    }
}

function Copy-Runtime {
    $copies = @{
        'EbpfCore.sys' = 'drivers\eBPFCore.sys'
        'EbpfCore.inf' = 'drivers\eBPFCore.inf'
        'ebpfcore.cat' = 'drivers\ebpfcore.cat'
        'netebpfext.sys' = 'drivers\NetEbpfExt.sys'
        'NetEbpfExt.inf' = 'drivers\NetEbpfExt.inf'
        'netebpfext.cat' = 'drivers\netebpfext.cat'
        'EbpfApi.dll' = 'EbpfApi.dll'
        'bpf2c.exe' = 'bpf2c.exe'
        'ebpfnetsh.dll' = 'ebpfnetsh.dll'
        'export_program_info.exe' = 'export_program_info.exe'
        'ucrtbased.dll' = 'ucrtbased.dll'
        'ebpfsvc.exe' = 'JIT\ebpfsvc.exe'
    }

    foreach ($sourceName in $copies.Keys) {
        $source = Join-Path $runtimeDirectory $sourceName
        $destination = Join-Path $InstallDirectory $copies[$sourceName]
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
}

function Assert-RuntimeHashes {
    $copies = @{
        'EbpfCore.sys' = 'drivers\eBPFCore.sys'
        'netebpfext.sys' = 'drivers\NetEbpfExt.sys'
        'EbpfApi.dll' = 'EbpfApi.dll'
        'ebpfnetsh.dll' = 'ebpfnetsh.dll'
        'export_program_info.exe' = 'export_program_info.exe'
        'ebpfsvc.exe' = 'JIT\ebpfsvc.exe'
    }

    foreach ($sourceName in $copies.Keys) {
        $source = Join-Path $runtimeDirectory $sourceName
        $destination = Join-Path $InstallDirectory $copies[$sourceName]
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        if ($sourceHash -ne $destinationHash) {
            throw "Hash mismatch after deployment: $destination"
        }
    }
}

if (-not (Test-Path -LiteralPath $runtimeDirectory -PathType Container)) {
    throw "Missing runtime directory: $runtimeDirectory"
}
if (Test-Path -LiteralPath $backupDirectory) {
    throw "Backup directory already exists: $backupDirectory"
}
if (Test-Path -LiteralPath $flowProgramKey) {
    throw 'Flow Classify program store entry already exists'
}
if (Test-Path -LiteralPath $flowSectionKey) {
    throw 'Flow Classify section store entry already exists'
}

$certificatePath = Join-Path $runtimeDirectory 'EbpfCore.cer'
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $certificatePath
)
$certificateThumbprint = $certificate.Thumbprint
$rootHadCertificate = [bool](
    Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object Thumbprint -eq $certificateThumbprint
)
$publisherHadCertificate = [bool](
    Get-ChildItem Cert:\LocalMachine\TrustedPublisher |
        Where-Object Thumbprint -eq $certificateThumbprint
)

Assert-NoLoadedEbpfObjects

New-Item -ItemType Directory -Path $backupDirectory | Out-Null
Copy-Item -LiteralPath $InstallDirectory `
    -Destination (Join-Path $backupDirectory 'installed') `
    -Recurse
reg.exe export 'HKCU\Software\eBPF\Providers' `
    (Join-Path $backupDirectory 'providers-hkcu.reg') /y | Out-Null
reg.exe export 'HKLM\Software\eBPF\Providers' `
    (Join-Path $backupDirectory 'providers-hklm.reg') /y | Out-Null

Get-ChildItem -LiteralPath $InstallDirectory -Recurse -File |
    Get-FileHash -Algorithm SHA256 |
    Sort-Object Path |
    ConvertTo-Json -Depth 3 |
    Set-Content -LiteralPath (Join-Path $backupDirectory 'installed-hashes.json') `
        -Encoding UTF8
Get-CimInstance Win32_Service |
    Where-Object Name -in $services |
    Select-Object Name, State, StartMode, PathName |
    ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $backupDirectory 'services.json') `
        -Encoding UTF8
@{
    root_had_certificate = $rootHadCertificate
    trusted_publisher_had_certificate = $publisherHadCertificate
    thumbprint = $certificateThumbprint
    created_utc = $stamp
} |
    ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $backupDirectory 'certificate-state.json') `
        -Encoding UTF8

try {
    Stop-EbpfServices
    Copy-Runtime

    if (-not $rootHadCertificate) {
        Import-Certificate -FilePath $certificatePath `
            -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    }
    if (-not $publisherHadCertificate) {
        Import-Certificate -FilePath $certificatePath `
            -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    }

    Push-Location $InstallDirectory
    try {
        & .\export_program_info.exe --flow-classify
        if ($LASTEXITCODE -ne 0) {
            throw "Targeted Flow Classify store export failed: $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    if (-not (Test-Path -LiteralPath $flowProgramKey)) {
        throw 'Flow Classify program store entry missing after export'
    }
    if (-not (Test-Path -LiteralPath $flowSectionKey)) {
        throw 'Flow Classify section store entry missing after export'
    }

    Start-EbpfServices
    Assert-RuntimeHashes

    Write-Output "DEPLOYMENT_OK backup=$backupDirectory"
    Get-Service -Name $services | Select-Object Name, Status
    Write-Output "certificate_thumbprint=$certificateThumbprint"
} catch {
    Write-Error "DEPLOYMENT_FAILED: $($_.Exception.Message)"

    Stop-EbpfServices
    Get-ChildItem -LiteralPath (Join-Path $backupDirectory 'installed') -Force |
        Copy-Item -Destination $InstallDirectory -Recurse -Force
    Remove-Item -LiteralPath $flowProgramKey -Recurse -Force `
        -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $flowSectionKey -Recurse -Force `
        -ErrorAction SilentlyContinue

    if (-not $rootHadCertificate) {
        Get-ChildItem Cert:\LocalMachine\Root |
            Where-Object Thumbprint -eq $certificateThumbprint |
            Remove-Item -Force
    }
    if (-not $publisherHadCertificate) {
        Get-ChildItem Cert:\LocalMachine\TrustedPublisher |
            Where-Object Thumbprint -eq $certificateThumbprint |
            Remove-Item -Force
    }

    Start-EbpfServices
    throw
}
