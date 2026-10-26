# 02_rsrc_parser.ps1 - Parse .rsrc section, list resources, extract embedded blobs
$file   = Join-Path $PSScriptRoot "ScreenConnect.ClientSetup.exe"
$outDir = Join-Path $PSScriptRoot "extracted_resources"
$bytes = [System.IO.File]::ReadAllBytes($file)

$peOffset       = [System.BitConverter]::ToInt32($bytes, 0x3C)
$optHeaderSize  = [System.BitConverter]::ToUInt16($bytes, $peOffset + 20)
$numSections    = [System.BitConverter]::ToUInt16($bytes, $peOffset + 6)
$sectionOffset  = $peOffset + 24 + $optHeaderSize

# Section table
$sections = @()
for ($i = 0; $i -lt $numSections; $i++) {
    $off = $sectionOffset + $i * 40
    $secName  = [System.Text.Encoding]::ASCII.GetString($bytes, $off, 8).TrimEnd([char]0)
    $secVSize = [System.BitConverter]::ToUInt32($bytes, $off + 8)
    $secRVA   = [System.BitConverter]::ToUInt32($bytes, $off + 12)
    $secRaw   = [System.BitConverter]::ToUInt32($bytes, $off + 20)
    $sections += [PSCustomObject]@{ Name=$secName; VSize=$secVSize; RVA=$secRVA; Raw=$secRaw }
}

function RvaToOffset($rva) {
    foreach ($s in $sections) {
        if ($rva -ge $s.RVA -and $rva -lt ($s.RVA + $s.VSize)) {
            return $rva - $s.RVA + $s.Raw
        }
    }
    return -1
}

function ReadDword($off) { [System.BitConverter]::ToUInt32($bytes, $off) }
function ReadWord($off)  { [System.BitConverter]::ToUInt16($bytes, $off) }

# .rsrc section base
$rsrcSec = $sections | Where-Object { $_.Name -eq '.rsrc' }
$rsrcBase = $rsrcSec.Raw
$rsrcRVA  = $rsrcSec.RVA

Write-Host "=== RESOURCE DIRECTORY TREE ===" -ForegroundColor Cyan

# Parse IMAGE_RESOURCE_DIRECTORY
function ParseResDir($dirOff, $level, $label) {
    $namedEntries   = ReadWord ($dirOff + 12)
    $idEntries      = ReadWord ($dirOff + 14)
    $totalEntries   = $namedEntries + $idEntries

    for ($i = 0; $i -lt $totalEntries; $i++) {
        $entOff = $dirOff + 16 + $i * 8
        $nameField = ReadDword $entOff
        $dataField = ReadDword ($entOff + 4)

        # Decode name/ID
        if ($nameField -band 0x80000000) {
            $nameStrOff = $rsrcBase + ($nameField -band 0x7FFFFFFF)
            $nameLen    = ReadWord $nameStrOff
            $nameStr    = [System.Text.Encoding]::Unicode.GetString($bytes, $nameStrOff + 2, $nameLen * 2)
            $entLabel   = "$label\$nameStr"
        } else {
            $entLabel = "$label\ID_$nameField"
        }

        if ($dataField -band 0x80000000) {
            # Points to subdirectory
            $subDirOff = $rsrcBase + ($dataField -band 0x7FFFFFFF)
            ParseResDir $subDirOff ($level + 1) $entLabel
        } else {
            # Leaf: IMAGE_RESOURCE_DATA_ENTRY
            $dataEntOff  = $rsrcBase + $dataField
            $dataRVA     = ReadDword $dataEntOff
            $dataSize    = ReadDword ($dataEntOff + 4)
            $fileOff     = RvaToOffset $dataRVA

            # Peek first 4 bytes for magic
            $magic = ""
            if ($fileOff -ge 0 -and ($fileOff + 4) -lt $bytes.Length) {
                $magic = "0x" + ($bytes[$fileOff+3]).ToString("X2") + ($bytes[$fileOff+2]).ToString("X2") + ($bytes[$fileOff+1]).ToString("X2") + ($bytes[$fileOff]).ToString("X2")
                # Check for known signatures
                if ($bytes[$fileOff] -eq 0x4D -and $bytes[$fileOff+1] -eq 0x5A) { $magic += " [MZ/PE]" }
                if ($bytes[$fileOff] -eq 0x50 -and $bytes[$fileOff+1] -eq 0x4B) { $magic += " [ZIP/JAR/DOCX]" }
                if ($bytes[$fileOff] -eq 0x1F -and $bytes[$fileOff+1] -eq 0x8B) { $magic += " [GZIP]" }
                if ($bytes[$fileOff] -eq 0xD0 -and $bytes[$fileOff+1] -eq 0xCF) { $magic += " [OLE/MSI]" }
                if ($bytes[$fileOff] -eq 0x4D -and $bytes[$fileOff+1] -eq 0x53 -and $bytes[$fileOff+2] -eq 0x43 -and $bytes[$fileOff+3] -eq 0x46) { $magic += " [MSI CAB]" }
                if ($bytes[$fileOff] -eq 0x49 -and $bytes[$fileOff+1] -eq 0x53 -and $bytes[$fileOff+2] -eq 0x63 -eq $bytes[$fileOff+2]) { $magic += " [CAB]" }
            }

            Write-Host ("  " * $level) + "[LEAF] $entLabel  Size=0x$($dataSize.ToString('X')) ($dataSize bytes)  FileOff=0x$($fileOff.ToString('X'))  Magic=$magic"

            # Extract all leaf resources
            if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
            $safeName = $entLabel -replace '\\','_' -replace '[^a-zA-Z0-9_]','_'
            $outFile  = "$outDir\$safeName.bin"
            if ($fileOff -ge 0 -and $dataSize -gt 0 -and ($fileOff + $dataSize) -le $bytes.Length) {
                $segment = $bytes[$fileOff..($fileOff + $dataSize - 1)]
                [System.IO.File]::WriteAllBytes($outFile, $segment)
                Write-Host ("  " * $level) + "  -> Extracted to: $outFile"
            }
        }
    }
}

ParseResDir $rsrcBase 0 "ROOT"
Write-Host "`nDone. Resources extracted to: $outDir" -ForegroundColor Green
