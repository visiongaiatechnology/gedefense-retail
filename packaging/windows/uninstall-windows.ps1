# GeDefense Retail - Windows uninstaller.
# Stops/removes the services and binaries; configuration and data are kept
# unless -Purge is supplied.
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Program Files\GeDefense\Retail',
    [string]$DataDir = 'C:\ProgramData\GeDefense\Retail',
    [string]$ConfigDir = 'C:\Program Files\GeDefense\Retail\config',
    [switch]$Purge
)
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'uninstall-windows: run this script elevated (Administrator)' }

foreach ($svc in @('gedefense-retail', 'gedefense-retailgate')) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        & sc.exe stop $svc | Out-Null
        & sc.exe delete $svc | Out-Null
    }
}
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
if ($Purge) {
    foreach ($path in @($DataDir, $ConfigDir, 'C:\ProgramData\GeDefense')) {
        if (Test-Path $path) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Write-Host 'uninstall-windows: services, binaries, configuration and data removed (-Purge)'
} else {
    Write-Host "uninstall-windows: services and binaries removed; data kept under $DataDir"
}
