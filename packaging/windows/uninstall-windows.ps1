# GeDefense Retail - Windows uninstaller.
# Stops/removes the services and binaries; configuration and data are kept
# unless -Purge is supplied. Refuses unsafe paths: absolute paths,
# marker file required, no drive/system roots, no reparse points.
#
# Note: the installer's hardened DACLs are not restored on uninstall; the
# directories are removed or kept as-is (documented in the deployment guide).
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Program Files\GeDefense\Retail',
    [string]$DataDir = 'C:\ProgramData\GeDefense\Retail',
    [string]$ConfigDir = 'C:\Program Files\GeDefense\Retail\config',
    [switch]$Purge,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$marker = '.gedefense-retail-install'

function Get-ValidatedDir([string]$value, [string]$name, [string]$requiredMarker, [string]$requiredPrefix) {
    if ([string]::IsNullOrWhiteSpace($value)) { throw "uninstall-windows: $name must not be empty" }
    $full = [System.IO.Path]::GetFullPath($value)
    if (-not [System.IO.Path]::IsPathRooted($full)) { throw "uninstall-windows: $name must be absolute" }
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -eq $root.TrimEnd('\')) { throw "uninstall-windows: refusing drive root as $name" }
    $dangerous = @($root, (Join-Path $root 'Windows'), (Join-Path $root 'Program Files'),
        (Join-Path $root 'Program Files (x86)'), (Join-Path $root 'ProgramData'), (Join-Path $root 'Users'))
    foreach ($d in $dangerous) {
        if ($full.TrimEnd('\') -eq $d.TrimEnd('\')) { throw "uninstall-windows: refusing unsafe $name '$full'" }
    }
    if ($requiredPrefix) {
        if (-not $full.TrimEnd('\').StartsWith($requiredPrefix.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "uninstall-windows: $name must be below $requiredPrefix"
        }
    }
    if (-not (Test-Path $full)) { throw "uninstall-windows: $name does not exist: $full" }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "uninstall-windows: refusing reparse point as $name"
    }
    if ($requiredMarker -and -not (Test-Path (Join-Path $full $requiredMarker))) {
        throw "uninstall-windows: '$full' is not a GeDefense Retail installation (marker missing)"
    }
    return $full
}

$InstallDir = Get-ValidatedDir $InstallDir 'InstallDir' $marker ''
$DataDir = Get-ValidatedDir $DataDir 'DataDir' '' 'C:\ProgramData\GeDefense'
$ConfigDir = Get-ValidatedDir $ConfigDir 'ConfigDir' '' $InstallDir

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'uninstall-windows: run this script elevated (Administrator)' }

if ($DryRun) {
    Write-Host "DRY-RUN: stop/delete services gedefense-retail, gedefense-retailgate"
    Write-Host "DRY-RUN: remove $InstallDir"
    if ($Purge) { Write-Host "DRY-RUN: purge $DataDir and $ConfigDir" }
    return
}

foreach ($svc in @('gedefense-retail', 'gedefense-retailgate')) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        & sc.exe stop $svc | Out-Null
        & sc.exe delete $svc | Out-Null
    }
}
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
if ($Purge) {
    foreach ($path in @($DataDir, $ConfigDir)) {
        if (Test-Path $path) { Remove-Item $path -Recurse -Force }
    }
    Write-Host 'uninstall-windows: services, binaries, configuration and data removed (-Purge)'
} else {
    Write-Host "uninstall-windows: services and binaries removed; data kept under $DataDir"
}
