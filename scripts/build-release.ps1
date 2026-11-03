# GeDefense Retail - cross-platform release builder (Windows host).
#
# Builds retaild, retailgate and retail-sim for linux/amd64, linux/arm64,
# windows/amd64 and windows/arm64 with reproducible flags (trimpath,
# buildvcs=false, CGO off), then optionally packages the release bundles.
# Works on Windows PowerShell 5.1 and PowerShell 7.
#
# Usage:
#   pwsh scripts/build-release.ps1 [-Package] [-Targets "linux/amd64 windows/amd64"]
# Environment:
#   GEDEFENSE_COMMIT, GEDEFENSE_BUILD_DATE
[CmdletBinding()]
param(
    [switch]$Package,
    [string]$Targets = "linux/amd64 linux/arm64 windows/amd64 windows/arm64"
)

# Write-LinesUtf8NoBom works on Windows PowerShell 5.1 and PowerShell 7 (the
# older -Encoding utf8NoBOM value only exists in PS 6+).
function Write-LinesUtf8NoBom([string]$path, [string[]]$content) {
    [System.IO.File]::WriteAllLines($path, @($content), (New-Object System.Text.UTF8Encoding($false)))
}

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$module = Join-Path $root 'src/retail'
$version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
$commit = if ($env:GEDEFENSE_COMMIT) { $env:GEDEFENSE_COMMIT } else {
    try { (git -C $root rev-parse --short HEAD 2>$null) } catch { $null }
}
if (-not $commit) { $commit = 'local' }
$buildDate = if ($env:GEDEFENSE_BUILD_DATE) { $env:GEDEFENSE_BUILD_DATE } else {
    if ($env:SOURCE_DATE_EPOCH -match '^\d+$') {
        # FIND-009: reproducible builds honour SOURCE_DATE_EPOCH.
        [DateTimeOffset]::FromUnixTimeSeconds([int64]$env:SOURCE_DATE_EPOCH).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    } else {
        (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}
$dist = Join-Path $root "dist/$version"
$binaries = @('retaild', 'retailgate', 'retail-sim')
$modulePath = (& go -C $module list -m 2>$null)
if (-not $modulePath) { $modulePath = 'github.com/visiongaiatechnology/gedefense/retail' }
$ldflags = "-s -w -X $modulePath/internal/version.Version=$version -X $modulePath/internal/version.Commit=$commit -X $modulePath/internal/version.BuildDate=$buildDate"

Write-Host "BUILD version=$version commit=$commit build_date=$buildDate dist=$dist"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Path $dist -Force | Out-Null

foreach ($target in $Targets.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)) {
    $parts = $target.Split('/')
    $os = $parts[0]; $arch = $parts[1]
    $outdir = Join-Path $dist "$os-$arch"
    New-Item -ItemType Directory -Path $outdir -Force | Out-Null
    foreach ($bin in $binaries) {
        $name = if ($os -eq 'windows') { "$bin.exe" } else { $bin }
        Write-Host "BUILD $os/$arch $name"
        $env:CGO_ENABLED = '0'
        $env:GOOS = $os
        $env:GOARCH = $arch
        & go -C $module build -trimpath -buildvcs=false -ldflags $ldflags -o (Join-Path $outdir $name) "./cmd/$bin"
        if ($LASTEXITCODE -ne 0) { throw "go build ./cmd/$bin for $os/$arch failed (exit $LASTEXITCODE)" }
    }
    Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    $sums = Get-ChildItem $outdir -File | Sort-Object Name | ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLowerInvariant()
        "{0}  {1}" -f $hash, $_.Name
    }
    Write-LinesUtf8NoBom (Join-Path $outdir 'SHA256SUMS') @($sums)
}

# Write-LinesUtf8NoBom works on Windows PowerShell 5.1 and PowerShell 7 (the
# older -Encoding utf8NoBOM value only exists in PS 6+).
function Write-LinesUtf8NoBom([string]$path, [string[]]$content) {
    [System.IO.File]::WriteAllLines($path, @($content), (New-Object System.Text.UTF8Encoding($false)))
}

# Overall checksum file over every built binary (relative paths, forward slashes).
$built = Get-ChildItem $dist -Directory | ForEach-Object { Get-ChildItem $_.FullName -File -Recurse }
$lines = $built |
    Where-Object { $_.Name -like 'retaild*' -or $_.Name -like 'retailgate*' -or $_.Name -like 'retail-sim*' } |
    Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($dist.Length + 1).Replace('\', '/')
        "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLowerInvariant(), $rel
    }
Write-LinesUtf8NoBom (Join-Path $dist 'SHA256SUMS.binaries') @($lines)
Write-Host "BUILD_OK $($lines.Count) binaries"

if ($Package) {
    & (Join-Path $root 'scripts/package-release.ps1') -Version $version
}
