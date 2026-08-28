<#
.SYNOPSIS
    Download free db-ip Lite .mmdb databases (ASN + City) for the GeoIP
    organization lookup in the Network/NetFlow views (whois.com style).

.DESCRIPTION
    Files land in server\data\:
      dbip-asn-lite.mmdb   -> ASN + organization (e.g. "Google LLC" AS15169)
      dbip-city-lite.mmdb  -> country + city
    Update the month in the URL to refresh (db-ip publishes monthly).

.USAGE
    powershell -ExecutionPolicy Bypass -File tools\setup_geolite2.ps1
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dataDir = Join-Path $root "server\data"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# db-ip monthly archives - change YYYY-MM to the current month when refreshing
$month = Get-Date -Format "yyyy-MM"
$files = @(
    @{ Name = "dbip-asn-lite"; Url = "https://download.db-ip.com/free/dbip-asn-lite-$month.mmdb.gz" },
    @{ Name = "dbip-city-lite"; Url = "https://download.db-ip.com/free/dbip-city-lite-$month.mmdb.gz" }
)

foreach ($f in $files) {
    $gz = Join-Path $env:TEMP ($f.Name + ".gz")
    $dst = Join-Path $dataDir ($f.Name + ".mmdb")
    Write-Host "Downloading $($f.Url)"
    Invoke-WebRequest -Uri $f.Url -OutFile $gz -UseBasicParsing
    Write-Host "Extracting -> $dst"
    $in = [System.IO.File]::OpenRead($gz)
    $out = [System.IO.File]::Create($dst)
    try {
        $gzip = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
        $gzip.CopyTo($out)
        $gzip.Dispose()
    } finally {
        $out.Dispose(); $in.Dispose()
    }
}
Write-Host "Done. GeoIP DBs in $dataDir (server picks them up automatically)."
