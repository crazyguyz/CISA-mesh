<#
.SYNOPSIS
    Download free db-ip Lite .mmdb databases (ASN + City) for the GeoIP
    organization lookup in the Network/NetFlow views (whois.com style).

.DESCRIPTION
    Files land in server\data\:
      dbip-asn-lite.mmdb   -> ASN + organization (e.g. "Google LLC" AS15169)
      dbip-city-lite.mmdb  -> country + city
    v5.0.8: db-ip publishes the monthly archive a few days INTO the month, so the
    script now falls back up to 3 months instead of dying on a 404 (which left
    server\data without .mmdb files and the Network/NetFlow organization column
    empty). Re-run any time to refresh - the server reloads the files it finds.

.USAGE
    powershell -ExecutionPolicy Bypass -File tools\setup_geolite2.ps1
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dataDir = Join-Path $root "server\data"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# db-ip publishes the archives monthly, usually a few days INTO the month, so the
# current month can still 404 (v5.0.8: that used to abort the script). Walk back
# up to 3 months and use the first archive that actually exists.
$months = @()
for ($i = 0; $i -lt 4; $i++) { $months += (Get-Date).AddMonths(-$i).ToString("yyyy-MM") }
$files = @("dbip-asn-lite", "dbip-city-lite")

$failed = @()
foreach ($name in $files) {
    $dst = Join-Path $dataDir ($name + ".mmdb")
    $done = $false
    foreach ($month in $months) {
        $url = "https://download.db-ip.com/free/$name-$month.mmdb.gz"
        $gz = Join-Path $env:TEMP ($name + ".gz")
        Write-Host "Downloading $url"
        try {
            Invoke-WebRequest -Uri $url -OutFile $gz -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-Host ("  -> not available ({0})" -f $_.Exception.Message)
            continue
        }
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
        $size = (Get-Item $dst).Length
        if ($size -lt 10000) {
            Write-Host "  -> file too small ($size bytes) - trying an older month"
            Remove-Item $dst -ErrorAction SilentlyContinue
            continue
        }
        Write-Host ("  -> OK ({0:N0} bytes, {1})" -f $size, $month)
        $done = $true
        break
    }
    if (-not $done) { $failed += $name }
}

if ($failed.Count -gt 0) {
    Write-Host ("[!] Khong tai duoc: {0}. Kiem tra internet/proxy roi chay lai." -f ($failed -join ", "))
    exit 1
}
Write-Host "Done. GeoIP DBs in $dataDir (server picks them up automatically)."
