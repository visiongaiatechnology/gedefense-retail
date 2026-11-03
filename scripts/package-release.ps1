# GeDefense Retail - package the built distribution into archives (Windows host).
#
# Expects dist/<version>/<os>-<arch>/ binaries produced by build-release.ps1.
# Creates .tar.gz for linux targets and .zip for windows targets plus
# SHA256SUMS.archives. Uses the bundled tar.exe / Compress-Archive, no downloads.
[CmdletBinding()]
param([string]$Version = '')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Version) { $Version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim() }
$dist = Join-Path $root "dist/$Version"
$stage = Join-Path $dist 'staging'
$packaging = Join-Path $root 'packaging'
if (-not (Test-Path $dist)) { throw "package-release: $dist missing; run build-release.ps1 first" }
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$common = @('README.md', 'LICENSE', 'VERSION', 'THIRD-PARTY-NOTICES.md')
$configs = @('retail.example.json', 'gate.example.json', 'gate-policy.example.json',
    'gedefense-retail.service', 'gedefense-retailgate.service')
$binaries = @('retaild', 'retailgate', 'retail-sim')

# Write-LinesUtf8NoBom works on Windows PowerShell 5.1 and PowerShell 7.
function Write-LinesUtf8NoBom([string]$path, [string[]]$content) {
    [System.IO.File]::WriteAllLines($path, @($content), (New-Object System.Text.UTF8Encoding($false)))
}

function Write-BundleManifest([string]$bundle) {
    $lines = Get-ChildItem $bundle -Recurse -File | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($bundle.Length + 1).Replace('\', '/')
        "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLowerInvariant(), $rel
    }
    Write-LinesUtf8NoBom (Join-Path $bundle 'SHA256SUMS') @($lines)
}

function Copy-Common([string]$bundle) {
    foreach ($name in $common) { Copy-Item (Join-Path $root $name) (Join-Path $bundle $name) }
    $configOut = Join-Path $bundle 'config'
    New-Item -ItemType Directory -Path $configOut -Force | Out-Null
    foreach ($name in $configs) { Copy-Item (Join-Path $root "config/$name") (Join-Path $configOut $name) }
    Copy-Item (Join-Path $root 'docs') (Join-Path $bundle 'docs') -Recurse
}

$archives = @()
foreach ($targetDir in Get-ChildItem $dist -Directory | Sort-Object Name) {
    if ($targetDir.Name -eq 'staging') { continue }
    $parts = $targetDir.Name.Split('-')
    if ($parts.Count -ne 2) { continue }
    $osName = $parts[0]; $arch = $parts[1]
    if ($osName -notin @('linux', 'windows')) { continue }
    $bundleName = "gedefense-retail-$Version-$osName-$arch"
    $bundle = Join-Path $stage $bundleName
    $binOut = Join-Path $bundle 'bin'
    New-Item -ItemType Directory -Path $binOut -Force | Out-Null
    foreach ($bin in $binaries) {
        $name = if ($osName -eq 'windows') { "$bin.exe" } else { $bin }
        $src = Join-Path $targetDir.FullName $name
        if (Test-Path $src) { Copy-Item $src (Join-Path $binOut $name) }
    }
    Copy-Common $bundle
    if ($osName -eq 'linux') {
        foreach ($script in @('install.sh', 'uninstall.sh')) {
            Copy-Item (Join-Path $packaging "linux/$script") (Join-Path $bundle $script)
        }
        Write-BundleManifest $bundle
        $archive = Join-Path $dist "$bundleName.tar.gz"
        & tar -czf $archive -C $stage $bundleName
        if ($LASTEXITCODE -ne 0) { throw "tar failed for $bundleName (exit $LASTEXITCODE)" }
        $archives += Get-Item $archive
    } else {
        foreach ($script in @('install-windows.ps1', 'uninstall-windows.ps1')) {
            Copy-Item (Join-Path $packaging "windows/$script") (Join-Path $bundle $script)
        }
        Write-BundleManifest $bundle
        $archive = Join-Path $dist "$bundleName.zip"
        if (Test-Path $archive) { Remove-Item $archive -Force }
        Compress-Archive -Path $bundle -DestinationPath $archive -CompressionLevel Optimal
        $archives += Get-Item $archive
    }
}

$lines = $archives | Sort-Object Name | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLowerInvariant(), $_.Name
}
Write-LinesUtf8NoBom (Join-Path $dist 'SHA256SUMS') @($lines)
Write-LinesUtf8NoBom (Join-Path $dist 'SHA256SUMS.archives') @($lines)
Write-Host 'PACKAGE_OK'
# SBOM (FIND-004).
& python (Join-Path $root 'scripts/generate-sbom.py') --dist $dist --version $Version
$archives | Sort-Object Name | ForEach-Object { Write-Host ("  {0}  {1} B" -f $_.Name, $_.Length) }
