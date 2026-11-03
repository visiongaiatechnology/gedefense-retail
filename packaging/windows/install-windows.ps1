# GeDefense Retail - Windows installer (inside the release bundle).
#
# Installs the binaries and example configuration and creates two Windows
# services. Hardened for FIND-001: the services run as NT AUTHORITY\LocalService
# (never LocalSystem) and config/data get explicit DACLs (SYSTEM/Administrators
# only, LocalService read for config and modify for data, no inherited Users
# access). icacls failures are fail-closed. Requires an elevated PowerShell.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 `
#       [-InstallDir 'C:\Program Files\GeDefense\Retail'] `
#       [-DataDir 'C:\ProgramData\GeDefense\Retail'] [-Start]
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\Program Files\GeDefense\Retail',
    [string]$DataDir = 'C:\ProgramData\GeDefense\Retail',
    [switch]$Start
)
$ErrorActionPreference = 'Stop'
$bundle = Split-Path -Parent $MyInvocation.MyCommand.Path
$marker = '.gedefense-retail-install'
$serviceAccount = 'NT AUTHORITY\LocalService'
# Well-known SIDs keep the DACLs language-independent.
$sidSystem = '*S-1-5-18'
$sidAdmins = '*S-1-5-32-544'
$sidUsers = '*S-1-5-32-545'
$sidLocalService = '*S-1-5-19'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'install-windows: run this script elevated (Administrator)' }
if (-not (Test-Path (Join-Path $bundle 'bin\retaild.exe'))) { throw 'install-windows: bundle is incomplete' }

function Get-ValidatedPath([string]$value, [string]$name) {
    if ([string]::IsNullOrWhiteSpace($value)) { throw "install-windows: $name must not be empty" }
    $full = [System.IO.Path]::GetFullPath($value)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -eq $root.TrimEnd('\')) { throw "install-windows: refusing drive root as $name" }
    $forbidden = @($root, (Join-Path $root 'Windows'), (Join-Path $root 'Program Files'),
        (Join-Path $root 'Program Files (x86)'), (Join-Path $root 'ProgramData'), (Join-Path $root 'Users'))
    foreach ($f in $forbidden) {
        if ($full.TrimEnd('\') -eq $f.TrimEnd('\')) { throw "install-windows: refusing unsafe $name '$full'" }
    }
    return $full
}

function Assert-Icacls([string[]]$arguments) {
    & icacls @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "install-windows: icacls failed (exit $LASTEXITCODE): icacls $($arguments -join ' ')" }
}

$InstallDir = Get-ValidatedPath $InstallDir 'InstallDir'
$DataDir = Get-ValidatedPath $DataDir 'DataDir'

$binDir = Join-Path $InstallDir 'bin'
$configDir = Join-Path $InstallDir 'config'
New-Item -ItemType Directory -Path $binDir, $configDir, $DataDir -Force | Out-Null
Copy-Item (Join-Path $bundle 'bin\retaild.exe') $binDir -Force
Copy-Item (Join-Path $bundle 'bin\retailgate.exe') $binDir -Force
Copy-Item (Join-Path $bundle 'bin\retail-sim.exe') $binDir -Force
Copy-Item (Join-Path $bundle 'LICENSE'), (Join-Path $bundle 'README.md'),
    (Join-Path $bundle 'THIRD-PARTY-NOTICES.md'), (Join-Path $bundle 'VERSION') $InstallDir -Force
Copy-Item (Join-Path $bundle 'docs') (Join-Path $InstallDir 'docs') -Recurse -Force
foreach ($cfg in @('retail.example.json', 'gate.example.json', 'gate-policy.example.json')) {
    $dest = Join-Path $configDir $cfg
    if (-not (Test-Path $dest)) { Copy-Item (Join-Path $bundle "config\$cfg") $dest }
}
Set-Content -Path (Join-Path $InstallDir $marker) -Value ("version=" + (Get-Content (Join-Path $bundle 'VERSION') -Raw).Trim()) -Encoding ASCII

# Explicit DACLs (FIND-001). /inheritance:r removes inherited ACEs.
Assert-Icacls @($InstallDir, '/inheritance:r', '/grant:r', "${sidSystem}:(OI)(CI)F",
    "${sidAdmins}:(OI)(CI)F", "${sidUsers}:(OI)(CI)RX", "${sidLocalService}:(OI)(CI)RX")
Assert-Icacls @($configDir, '/inheritance:r', '/grant:r', "${sidSystem}:(OI)(CI)F",
    "${sidAdmins}:(OI)(CI)F", "${sidLocalService}:(OI)(CI)R")
Assert-Icacls @($DataDir, '/inheritance:r', '/grant:r', "${sidSystem}:(OI)(CI)F",
    "${sidAdmins}:(OI)(CI)F", "${sidLocalService}:(OI)(CI)M")
# Fail closed: verify the service account can read the config directory.
& icacls $configDir | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'install-windows: config DACL verification failed' }

$retailExe = Join-Path $binDir 'retaild.exe'
$gateExe = Join-Path $binDir 'retailgate.exe'
$retailConfig = Join-Path $configDir 'retail.json'
$gateConfig = Join-Path $configDir 'gate.json'

$services = @(
    @{ Name = 'gedefense-retail'; Exe = $retailExe; Config = $retailConfig; Start = 'auto';
       Display = 'GeDefense Retail Edge'; Desc = 'Passive cold-chain and store infrastructure monitoring (read-only)' },
    @{ Name = 'gedefense-retailgate'; Exe = $gateExe; Config = $gateConfig; Start = 'demand';
       Display = 'GeDefense Retail Access Gate'; Desc = 'Default-deny management path for OT configuration (write plan required)' }
)
foreach ($svc in $services) {
    if (Get-Service -Name $svc.Name -ErrorAction SilentlyContinue) {
        & sc.exe stop $svc.Name | Out-Null
        & sc.exe delete $svc.Name | Out-Null
    }
    $binPath = "`"$($svc.Exe)`" serve --config `"$($svc.Config)`""
    & sc.exe create $svc.Name binPath= $binPath start= $svc.Start DisplayName= $svc.Display | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "install-windows: sc.exe create $($svc.Name) failed" }
    & sc.exe description $svc.Name $svc.Desc | Out-Null
    # FIND-001: dedicated low-privilege service account instead of LocalSystem.
    & sc.exe config $svc.Name obj= $serviceAccount | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "install-windows: sc.exe config obj= for $($svc.Name) failed" }
    $qc = (& sc.exe qc $svc.Name) -join "`n"
    if ($qc -notmatch 'LocalService') { throw "install-windows: service $($svc.Name) is not running as LocalService" }
}

if ($Start) { Start-Service gedefense-retail; Start-Service gedefense-retailgate }

Write-Host "GeDefense Retail installed under $InstallDir (services as $serviceAccount, DACL-hardened)"
Write-Host 'Next steps:'
Write-Host "  1) Copy $configDir\retail.example.json -> retail.json and set site + security.dashboard_whitelist_cidrs"
Write-Host "  2) Create/rotate an admin token: & '$retailExe' token rotate --user admin --role admin"
Write-Host '     Insert token_sha256 into users[] (never the plaintext token), then restart retaild.'
Write-Host "  3) Gate: configure $configDir\gate.json + gate-policy.json (hash-password/gen-totp)"
Write-Host '  4) First start opens the dashboard setup wizard (security.setup_token_ttl_s).'
Write-Host '  5) Firewall: allow inbound TCP 8080/8443 only from the management network (no auto rule).'
Write-Host '  6) Start-Service gedefense-retail ; Start-Service gedefense-retailgate'
Write-Host 'Uninstall: .\uninstall-windows.ps1 [-Purge] [-DryRun] (DACLs are not restored)'
