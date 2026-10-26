# 03_payload_analysis.ps1 - Analyze SC_PAYLOAD and extract C2 config from .NET assemblies
$outDir = Join-Path $PSScriptRoot "extracted_resources"

# --- Analyze SC_PAYLOAD ---
$payload = "$outDir\ROOT_ID_10_SC_PAYLOAD_ID_0.bin"
$pb = [System.IO.File]::ReadAllBytes($payload)

Write-Host "=== SC_PAYLOAD Analysis ===" -ForegroundColor Cyan
Write-Host "Size: $($pb.Length) bytes (0x$($pb.Length.ToString('X')))"

# First 64 bytes hex dump
Write-Host "`nFirst 64 bytes:"
$hexLine = ""
for ($i = 0; $i -lt [Math]::Min(64, $pb.Length); $i++) {
    $hexLine += $pb[$i].ToString("X2") + " "
    if (($i+1) % 16 -eq 0) { Write-Host "  $hexLine"; $hexLine = "" }
}
if ($hexLine) { Write-Host "  $hexLine" }

# Entropy calculation (Shannon entropy)
$freq = @{}
foreach ($b in $pb) { $freq[$b] = ($freq[$b] -as [int]) + 1 }
$entropy = 0.0
foreach ($count in $freq.Values) {
    $p = $count / $pb.Length
    $entropy -= $p * [Math]::Log($p, 2)
}
Write-Host "`nShannon entropy: $([Math]::Round($entropy, 4)) / 8.0"
if ($entropy -gt 7.2) { Write-Host "  >> HIGH ENTROPY: likely encrypted or compressed" -ForegroundColor Red }
elseif ($entropy -gt 6.0) { Write-Host "  >> MEDIUM entropy: possibly compressed" -ForegroundColor Yellow }
else { Write-Host "  >> LOW entropy: likely plaintext/structured data" -ForegroundColor Green }

# Check if it looks like a ZIP at various offsets
Write-Host "`nScanning for embedded file signatures..."
$sigs = @{
    "ZIP/JAR"   = @(0x50, 0x4B, 0x03, 0x04)
    "MZ/PE"     = @(0x4D, 0x5A)
    "GZIP"      = @(0x1F, 0x8B)
    "CAB"       = @(0x4D, 0x53, 0x43, 0x46)
    "7ZIP"      = @(0x37, 0x7A, 0xBC, 0xAF)
    "PDF"       = @(0x25, 0x50, 0x44, 0x46)
    "SQLite"    = @(0x53, 0x51, 0x4C, 0x69)
    "OLE/MSI"   = @(0xD0, 0xCF, 0x11, 0xE0)
}
foreach ($name in $sigs.Keys) {
    $sig = $sigs[$name]
    for ($i = 0; $i -lt [Math]::Min(1024, $pb.Length - $sig.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $sig.Length; $j++) {
            if ($pb[$i+$j] -ne $sig[$j]) { $match = $false; break }
        }
        if ($match) { Write-Host "  Found $name at offset 0x$($i.ToString('X'))" -ForegroundColor Yellow }
    }
}

# --- Extract strings from each embedded .NET assembly ---
Write-Host "`n=== STRINGS from embedded .NET assemblies ===" -ForegroundColor Cyan

$assemblies = @(
    "$outDir\ROOT_FILES__ENTRYPOINT_ID_0.bin",
    "$outDir\ROOT_FILES_SCREENCONNECT_CORE__VERSION_26_7_6_9783__CULTURE_NEUTRAL__PUBLICKEYTOKEN_420D02D3849B7992_ID_0.bin"
)

foreach ($asmFile in $assemblies) {
    Write-Host "`n--- $([System.IO.Path]::GetFileName($asmFile)) ---" -ForegroundColor Yellow
    $ab = [System.IO.File]::ReadAllBytes($asmFile)

    # Extract Unicode strings (UTF-16LE, min 8 chars)
    $uniStrings = @()
    $run = 0; $buf = ""
    for ($i = 0; $i -lt ($ab.Length - 1); $i += 2) {
        $lo = $ab[$i]; $hi = $ab[$i+1]
        if ($hi -eq 0 -and $lo -ge 0x20 -and $lo -le 0x7E) {
            $buf += [char]$lo; $run++
        } else {
            if ($run -ge 8) { $uniStrings += $buf }
            $buf = ""; $run = 0; $i--   # back up 1 char if mismatch
        }
    }

    # Extract ASCII strings (min 8 chars)
    $ascStrings = @()
    $run = 0; $buf = ""
    for ($i = 0; $i -lt $ab.Length; $i++) {
        $b = $ab[$i]
        if ($b -ge 0x20 -and $b -le 0x7E) {
            $buf += [char]$b; $run++
        } else {
            if ($run -ge 8) { $ascStrings += $buf }
            $buf = ""; $run = 0
        }
    }

    $allStrings = ($uniStrings + $ascStrings) | Sort-Object -Unique
    # Filter for interesting strings
    $interesting = $allStrings | Where-Object {
        $_ -match '(http|https|ftp|://|\.com|\.net|\.top|\.io|\.ru|host|server|relay|port|url|key|token|install|service|run|exec|cmd|shell|registry|HKEY|startup|payload|inject|connect|socket|client|session|guid|uuid|password|auth|certificate|cert|domain)' -and
        $_.Length -gt 8
    }
    if ($interesting) {
        $interesting | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  (no obviously suspicious strings found - may need deeper .NET IL decompile)"
    }
}

# --- Check manifest XML ---
Write-Host "`n=== MANIFEST (RT_MANIFEST) ===" -ForegroundColor Cyan
$manifest = "$outDir\ROOT_ID_24_ID_1_ID_1033.bin"
if (Test-Path $manifest) {
    [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($manifest))
}
