# 04_extract_msi_config.ps1
# Extract MSI from SC_PAYLOAD and read ScreenConnect C2 configuration
$outDir  = Join-Path $PSScriptRoot "extracted_resources"
$payload = "$outDir\ROOT_ID_10_SC_PAYLOAD_ID_0.bin"
$pb      = [System.IO.File]::ReadAllBytes($payload)

# --- Try to carve MSI starting at 0x11C ---
Write-Host "=== Attempting MSI extraction from SC_PAYLOAD at offset 0x11C ===" -ForegroundColor Cyan
$msiOffset = 0x11C
$msiBytes  = $pb[$msiOffset..($pb.Length - 1)]
$msiPath   = "$outDir\extracted_payload.msi"
[System.IO.File]::WriteAllBytes($msiPath, $msiBytes)

# Verify OLE/MSI magic
if ($msiBytes[0] -eq 0xD0 -and $msiBytes[1] -eq 0xCF -and $msiBytes[2] -eq 0x11 -and $msiBytes[3] -eq 0xE0) {
    Write-Host "Valid OLE/MSI magic confirmed at offset 0x11C" -ForegroundColor Green
    Write-Host "Extracted MSI: $msiPath ($($msiBytes.Length) bytes)"
} else {
    Write-Host "No valid OLE magic at 0x11C. Checking alternative offsets..." -ForegroundColor Yellow
    # Scan first 4KB for OLE magic
    for ($i = 0; $i -lt [Math]::Min(4096, $pb.Length - 4); $i++) {
        if ($pb[$i] -eq 0xD0 -and $pb[$i+1] -eq 0xCF -and $pb[$i+2] -eq 0x11 -and $pb[$i+3] -eq 0xE0) {
            Write-Host "Found OLE magic at offset 0x$($i.ToString('X'))" -ForegroundColor Yellow
            $msiOffset = $i
            $msiBytes  = $pb[$msiOffset..($pb.Length - 1)]
            [System.IO.File]::WriteAllBytes($msiPath, $msiBytes)
            break
        }
    }
}

# --- Extract MSI contents using msiexec /a (admin install) ---
Write-Host "`n=== Extracting MSI contents ===" -ForegroundColor Cyan
$msiExtractDir = "$outDir\msi_extracted"
if (-not (Test-Path $msiExtractDir)) { New-Item -ItemType Directory -Path $msiExtractDir | Out-Null }

# Use msiexec to extract (quiet admin install to folder)
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/a `"$msiPath`" /qn TARGETDIR=`"$msiExtractDir`"" -Wait -PassThru -WindowStyle Hidden
Write-Host "msiexec exit code: $($proc.ExitCode)"

if ($proc.ExitCode -eq 0 -or (Test-Path "$msiExtractDir")) {
    Write-Host "MSI extracted to: $msiExtractDir" -ForegroundColor Green
    Get-ChildItem -Recurse $msiExtractDir | ForEach-Object {
        Write-Host "  $($_.FullName) ($($_.Length) bytes)"
    }
} else {
    Write-Host "msiexec extraction failed (exit $($proc.ExitCode)). Trying string extraction from payload..." -ForegroundColor Yellow
}

# --- Regardless of MSI extraction, scan raw SC_PAYLOAD for config strings ---
Write-Host "`n=== Scanning SC_PAYLOAD for C2 configuration strings ===" -ForegroundColor Cyan

# ASCII scan
$run = 0; $buf = ""; $found = @()
for ($i = 0; $i -lt $pb.Length; $i++) {
    $b = $pb[$i]
    if ($b -ge 0x20 -and $b -le 0x7E) {
        $buf += [char]$b; $run++
    } else {
        if ($run -ge 6) { $found += $buf }
        $buf = ""; $run = 0
    }
}
$interesting = $found | Where-Object {
    $_ -match '(http|https|ftp|://|relay|host|server|port|\.com|\.net|\.top|\.io|\.ru|\.org|key|token|session|guid|install|service|connect|relay|e=|y=|h=|p=|k=|i=)' -and
    $_.Length -gt 8
}
Write-Host "ASCII C2-relevant strings:"
$interesting | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }

# Unicode scan
$run = 0; $buf = ""; $foundU = @()
for ($i = 0; $i -lt ($pb.Length - 1); $i += 2) {
    $lo = $pb[$i]; $hi = $pb[$i+1]
    if ($hi -eq 0 -and $lo -ge 0x20 -and $lo -le 0x7E) {
        $buf += [char]$lo; $run++
    } else {
        if ($run -ge 6) { $foundU += $buf }
        $buf = ""; $run = 0; $i--
    }
}
$interestingU = $foundU | Where-Object {
    $_ -match '(http|https|relay|host|server|port|\.com|\.net|\.top|\.io|key|token|session|guid|connect|e=|y=|h=|p=|k=|i=)' -and
    $_.Length -gt 8
}
Write-Host "`nUnicode C2-relevant strings:"
$interestingU | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }

# --- Also scan the ScreenConnect.Windows assembly for hardcoded relay/host ---
Write-Host "`n=== Scanning ScreenConnect.Windows assembly for relay/host config ===" -ForegroundColor Cyan
$winAsm = "$outDir\ROOT_FILES_SCREENCONNECT_WINDOWS__VERSION_26_7_6_9783__CULTURE_NEUTRAL__PUBLICKEYTOKEN_420D02D3849B7992_ID_0.bin"
$wb = [System.IO.File]::ReadAllBytes($winAsm)

$run = 0; $buf = ""; $wFound = @()
for ($i = 0; $i -lt $wb.Length; $i++) {
    $b = $wb[$i]
    if ($b -ge 0x20 -and $b -le 0x7E) { $buf += [char]$b; $run++ }
    else {
        if ($run -ge 8) { $wFound += $buf }
        $buf = ""; $run = 0
    }
}
$wInteresting = $wFound | Where-Object {
    $_ -match '(http|https|relay|host|server|port|\.com|\.net|\.top|\.io|key|token|session|connect|e=|y=|h=|p=|k=|i=|relay|pdb|C:\\)' -and
    $_.Length -gt 8
}
Write-Host "ScreenConnect.Windows interesting strings:"
$wInteresting | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
