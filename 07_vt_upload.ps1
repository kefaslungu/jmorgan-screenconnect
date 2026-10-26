# 07_vt_upload.ps1
# Upload ScreenConnect.ClientSetup.exe to VirusTotal and add an analysis comment
$sample  = Join-Path $PSScriptRoot "ScreenConnect.ClientSetup.exe"
$hash    = "ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3"
$apiKey  = $env:virusTotal_api_key
$headers = @{ "x-apikey" = $apiKey }

Write-Host "=== VirusTotal Upload & Comment ===" -ForegroundColor Cyan

# --- 1. Upload file for fresh scan ---
Write-Host "`n[1] Uploading file to VirusTotal..." -ForegroundColor Cyan

$fileBytes = [System.IO.File]::ReadAllBytes($sample)
$boundary  = [System.Guid]::NewGuid().ToString()
$LF        = "`r`n"

$bodyLines = (
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"ScreenConnect.ClientSetup.exe`"",
    "Content-Type: application/octet-stream",
    "",
    [System.Text.Encoding]::Latin1.GetString($fileBytes),
    "--$boundary--"
)
$bodyBytes = [System.Text.Encoding]::Latin1.GetBytes($bodyLines -join $LF)

try {
    $uploadResp = Invoke-RestMethod `
        -Uri "https://www.virustotal.com/api/v3/files" `
        -Method POST `
        -Headers $headers `
        -ContentType "multipart/form-data; boundary=$boundary" `
        -Body $bodyBytes `
        -ErrorAction Stop

    $analysisId = $uploadResp.data.id
    Write-Host "Upload accepted. Analysis ID: $analysisId" -ForegroundColor Green

    # --- 2. Poll until analysis completes ---
    Write-Host "`n[2] Waiting for analysis to complete..." -ForegroundColor Cyan
    $done = $false
    $attempts = 0
    do {
        Start-Sleep -Seconds 15
        $attempts++
        $status = Invoke-RestMethod `
            -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId" `
            -Headers $headers `
            -Method GET
        $state = $status.data.attributes.status
        Write-Host "  Attempt $attempts - status: $state"
        if ($state -eq "completed") { $done = $true }
    } while (-not $done -and $attempts -lt 20)

    if ($done) {
        $stats = $status.data.attributes.stats
        Write-Host "`nAnalysis complete:" -ForegroundColor Green
        Write-Host "  Malicious  : $($stats.malicious)"   -ForegroundColor $(if ($stats.malicious -gt 0)  { 'Red' }    else { 'Green' })
        Write-Host "  Suspicious : $($stats.suspicious)"  -ForegroundColor $(if ($stats.suspicious -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "  Undetected : $($stats.undetected)"
    } else {
        Write-Host "Analysis still pending after $attempts polls. Check VT manually." -ForegroundColor Yellow
    }
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 409) {
        Write-Host "File already exists in VT (409 conflict) - skipping re-upload, proceeding to comment." -ForegroundColor Yellow
    } else {
        Write-Host "[ERROR] Upload failed: HTTP $code - $_" -ForegroundColor Red
    }
}

# --- 3. Post analysis comment on the file page ---
Write-Host "`n[3] Posting analysis comment..." -ForegroundColor Cyan

$comment = @"
## Analyst Notes - Weaponized ScreenConnect RAT (jmorgan campaign)

**Classification:** Hacktool / Weaponized RMM - Persistent RAT via ConnectWise ScreenConnect

**Delivery chain:**
Email lure -> rebrand.ly/p1vyczk -> myinnercircle.top -> auto-download of this EXE

**Lure:** HTML page impersonating BlueMountain greeting cards. Auto-downloads the EXE after 3 seconds. Instructs victim to "double-click to launch the e-Card" and "follow the wizard" (UAC consent).

**Architecture:** Native PE32 (x86) DotNetRunner wrapper. Loads 5 .NET assemblies fileless via IAppDomain::Load_3 (never written to disk). Embeds a 10.2 MB RSA-signed OLE/MSI payload in .rsrc (entropy 7.95/8.0).

**C2 configuration (from embedded system.config):**
- Host: instance-b6ny1e-relay.screenconnect.com:443
- Session type: e=Access (persistent, silent - attacker connects any time)
- Instance fingerprint: 67c6a273dd7a01db

**Key IOCs:**
- instance-b6ny1e-relay.screenconnect.com (C2 relay)
- annemadecards.screenconnect.com (download server)
- myinnercircle.top (delivery server)
- Service: "ScreenConnect Client (67c6a273dd7a01db)"

**Developer attribution:** PDB path leaks developer username "jmorgan":
C:\Users\jmorgan\Source\cwcontrol\Custom\DotNetRunner\Release\DotNetRunner.pdb

**MITRE ATT&CK:** T1566.002, T1204.002, T1219, T1573, T1543.003, T1547.002, T1556.006, T1620, T1027.009, T1218.007

Report ConnectWise instance 67c6a273dd7a01db to abuse@connectwise.com to shut down attacker C2.
"@

$commentBody = @{ data = @{ type = "comment"; attributes = @{ text = $comment } } } | ConvertTo-Json -Depth 5

try {
    $commentResp = Invoke-RestMethod `
        -Uri "https://www.virustotal.com/api/v3/files/$hash/comments" `
        -Method POST `
        -Headers ($headers + @{ "Content-Type" = "application/json" }) `
        -Body $commentBody `
        -ErrorAction Stop
    Write-Host "Comment posted successfully. ID: $($commentResp.data.id)" -ForegroundColor Green
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Write-Host "[ERROR] Comment failed: HTTP $code - $_" -ForegroundColor Red
}

Write-Host "`nVirusTotal link: https://www.virustotal.com/gui/file/$hash" -ForegroundColor Cyan
