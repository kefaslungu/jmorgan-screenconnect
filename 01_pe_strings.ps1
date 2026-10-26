# 01_pe_strings.ps1 - Extract strings from .rdata and check imports
$file  = Join-Path $PSScriptRoot "ScreenConnect.ClientSetup.exe"
$bytes = [System.IO.File]::ReadAllBytes($file)
$peOffset  = [System.BitConverter]::ToInt32($bytes, 0x3C)
$optOffset = $peOffset + 24

# --- Import directory (DLL names + function names) ---
$ddOffset = $optOffset + 96   # PE32 data directories
$impRVA   = [System.BitConverter]::ToUInt32($bytes, $ddOffset + 1*8)

# RVA -> file offset helper (using section table)
$optHeaderSize  = [System.BitConverter]::ToUInt16($bytes, $peOffset + 20)
$numSections    = [System.BitConverter]::ToUInt16($bytes, $peOffset + 6)
$sectionOffset  = $peOffset + 24 + $optHeaderSize

function RvaToOffset($rva) {
    for ($i = 0; $i -lt $numSections; $i++) {
        $off      = $sectionOffset + $i * 40
        $secRVA   = [System.BitConverter]::ToUInt32($bytes, $off + 12)
        $secVSize = [System.BitConverter]::ToUInt32($bytes, $off + 8)
        $secRaw   = [System.BitConverter]::ToUInt32($bytes, $off + 20)
        if ($rva -ge $secRVA -and $rva -lt ($secRVA + $secVSize)) {
            return $rva - $secRVA + $secRaw
        }
    }
    return -1
}

Write-Host "=== IMPORTED DLLs AND FUNCTIONS ===" -ForegroundColor Cyan
$impOff = RvaToOffset $impRVA
$idx = 0
while ($true) {
    $descOffset = $impOff + $idx * 20
    $nameRVA = [System.BitConverter]::ToUInt32($bytes, $descOffset + 12)
    $iltRVA  = [System.BitConverter]::ToUInt32($bytes, $descOffset)
    if ($nameRVA -eq 0) { break }
    $nameOff = RvaToOffset $nameRVA
    $dllName = ""
    $j = 0
    while ($bytes[$nameOff + $j] -ne 0) { $dllName += [char]$bytes[$nameOff + $j]; $j++ }
    Write-Host "`n  DLL: $dllName" -ForegroundColor Yellow
    $iltOff = RvaToOffset $iltRVA
    $k = 0
    while ($true) {
        $entry = [System.BitConverter]::ToUInt32($bytes, $iltOff + $k * 4)
        if ($entry -eq 0) { break }
        if (($entry -band 0x80000000) -ne 0) {
            Write-Host "    Ordinal: $($entry -band 0xFFFF)"
        } else {
            $hintOff = RvaToOffset ($entry -band 0x7FFFFFFF)
            $fn = ""
            $m = 2
            while ($bytes[$hintOff + $m] -ne 0) { $fn += [char]$bytes[$hintOff + $m]; $m++ }
            Write-Host "    $fn"
        }
        $k++
    }
    $idx++
}

# --- ASCII strings from .rdata (RawOff=0xB600, RawSize=0x6200) ---
Write-Host "`n=== ASCII STRINGS from .rdata ===" -ForegroundColor Cyan
$rdataStart = 0xB600
$rdataEnd   = 0xB600 + 0x6200
$run = 0
$buf = ""
$strings = @()
for ($i = $rdataStart; $i -lt $rdataEnd; $i++) {
    $b = $bytes[$i]
    if ($b -ge 0x20 -and $b -le 0x7E) {
        $buf += [char]$b
        $run++
    } else {
        if ($run -ge 6) { $strings += $buf }
        $buf = ""; $run = 0
    }
}
$strings | Sort-Object -Unique | ForEach-Object { Write-Host $_ }
