# GeDefense Retail - Windows installer (inside the release bundle).
#
# Installs the binaries and example configuration and creates two Windows
# services (retaild, retailgate). Requires an elevated PowerShell.
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

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'install-windows: run this script elevated (Administrator)' }
if (-not (Test-Path (Join-Path $bundle 'bin\retaild.exe'))) { throw 'install-windows: bundle is incomplete' }

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

$retailExe = Join-Path $binDir 'retaild.exe'
$gateExe = Join-Path $binDir 'retailgate.exe'
$retailConfig = Join-Path $configDir 'retail.json'
$gateConfig = Join-Path $configDir 'gate.json'

foreach ($svc in @('gedefense-retail', 'gedefense-retailgate')) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { & sc.exe stop $svc | Out-Null; & sc.exe delete $svc | Out-Null }
}
& sc.exe create gedefense-retail binPath= "`"$retailExe`" serve --config `"$retailConfig`"" start= auto DisplayName= "GeDefense Retail Edge" | Out-Null
& sc.exe description gedefense-retail "Passive cold-chain and store infrastructure monitoring (read-only)" | Out-Null
& sc.exe create gedefense-retailgate binPath= "`"$gateExe`" serve --config `"$gateConfig`"" start= demand DisplayName= "GeDefense Retail Access Gate" | Out-Null
& sc.exe description gedefense-retailgate "Default-deny management path for OT configuration (write plan required)" | Out-Null

if ($Start) { Start-Service gedefense-retail; Start-Service gedefense-retailgate }

Write-Host "GeDefense Retail installed under $InstallDir"
Write-Host 'Next steps:'
Write-Host "  1) Copy $configDir\retail.example.json -> retail.json and set site + security.dashboard_whitelist_cidrs"
Write-Host "  2) Create an admin token: & '$retailExe' gen-token --user admin --role admin"
Write-Host '     Insert token_sha256 into users[] (never the plaintext token).'
Write-Host "  3) Gate: configure $configDir\gate.json + gate-policy.json (hash-password/gen-totp)"
Write-Host '  4) First start opens the dashboard setup wizard (security.setup_token_ttl_s).'
Write-Host '  5) Firewall: allow inbound TCP 8080/8443 only from the management network (no auto rule).'
Write-Host '  6) Start-Service gedefense-retail ; Start-Service gedefense-retailgate'
Write-Host 'Uninstall: .\uninstall-windows.ps1 [-Purge]'
