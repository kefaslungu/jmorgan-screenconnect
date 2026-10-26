# 08_domain_recon.ps1
# Domain/infrastructure OSINT for the jmorgan ScreenConnect campaign
# Queries VirusTotal domain reports and live DNS for all campaign domains

$apiKey  = $env:virusTotal_api_key
$headers = @{ "x-apikey" = $apiKey }

$domains = @(
    "myinnercircle.top",
    "annemadecards.screenconnect.com",
    "instance-b6ny1e-relay.screenconnect.com"
)

Write-Host "=== Domain Recon - jmorgan campaign ===" -ForegroundColor Cyan

foreach ($domain in $domains) {
    Write-Host "`n--- $domain ---" -ForegroundColor Yellow

    # --- 1. Live DNS ---
    Write-Host "[DNS]" -ForegroundColor Cyan
    try {
        $dns = Resolve-DnsName -Name $domain -ErrorAction Stop
        foreach ($r in $dns) {
            $type = $r.Type
            $val  = if ($r.IPAddress) { $r.IPAddress } elseif ($r.NameHost) { $r.NameHost } else { $r.Strings -join " " }
            Write-Host "  $type`t$val"
        }
    } catch {
        Write-Host "  DNS resolution failed: $_" -ForegroundColor Red
    }

    if (-not $apiKey) {
        Write-Host "[VT] Skipped - virusTotal_api_key not set." -ForegroundColor Yellow
        continue
    }

    # --- 2. VirusTotal domain report ---
    Write-Host "[VT domain report]" -ForegroundColor Cyan
    try {
        $vtDomain = Invoke-RestMethod `
            -Uri "https://www.virustotal.com/api/v3/domains/$domain" `
            -Headers $headers `
            -Method GET `
            -ErrorAction Stop

        $attr  = $vtDomain.data.attributes
        $stats = $attr.last_analysis_stats

        Write-Host "  Creation date : $(if ($attr.creation_date) { [datetimeoffset]::FromUnixTimeSeconds($attr.creation_date).ToString('yyyy-MM-dd') } else { 'n/a' })"
        Write-Host "  Registrar     : $(if ($attr.registrar) { $attr.registrar } else { 'n/a' })"
        Write-Host "  Reputation    : $($attr.reputation)"
        Write-Host "  Last analysis : $(if ($attr.last_analysis_date) { [datetimeoffset]::FromUnixTimeSeconds($attr.last_analysis_date).ToString('yyyy-MM-dd HH:mm') } else { 'n/a' })"
        Write-Host "  Malicious     : $($stats.malicious)"   -ForegroundColor $(if ($stats.malicious -gt 0)  { 'Red' }    else { 'Green' })
        Write-Host "  Suspicious    : $($stats.suspicious)"  -ForegroundColor $(if ($stats.suspicious -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "  Undetected    : $($stats.undetected)"

        # Passive DNS (most recent 5)
        if ($attr.last_dns_records) {
            Write-Host "  Last DNS records:"
            $attr.last_dns_records | Select-Object -First 5 | ForEach-Object {
                Write-Host "    $($_.type)`t$($_.value)"
            }
        }

        # Categories assigned by vendors
        if ($attr.categories) {
            Write-Host "  Vendor categories:"
            $attr.categories.PSObject.Properties | ForEach-Object {
                Write-Host "    $($_.Name): $($_.Value)"
            }
        }

    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  VT domain lookup failed: HTTP $code - $_" -ForegroundColor Red
    }

    # --- 3. VirusTotal URL report (apex URL) ---
    Write-Host "[VT URL report - https://$domain/]" -ForegroundColor Cyan
    $urlId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("https://$domain/")).TrimEnd('=')
    try {
        $vtUrl = Invoke-RestMethod `
            -Uri "https://www.virustotal.com/api/v3/urls/$urlId" `
            -Headers $headers `
            -Method GET `
            -ErrorAction Stop

        $uattr  = $vtUrl.data.attributes
        $ustats = $uattr.last_analysis_stats

        Write-Host "  Last analysis : $(if ($uattr.last_analysis_date) { [datetimeoffset]::FromUnixTimeSeconds($uattr.last_analysis_date).ToString('yyyy-MM-dd HH:mm') } else { 'n/a' })"
        Write-Host "  Malicious     : $($ustats.malicious)"  -ForegroundColor $(if ($ustats.malicious -gt 0)  { 'Red' }    else { 'Green' })
        Write-Host "  Suspicious    : $($ustats.suspicious)" -ForegroundColor $(if ($ustats.suspicious -gt 0) { 'Yellow' } else { 'Green' })

        if ($uattr.categories) {
            Write-Host "  Categories:"
            $uattr.categories.PSObject.Properties | ForEach-Object {
                Write-Host "    $($_.Name): $($_.Value)"
            }
        }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 404) {
            Write-Host "  URL not yet in VT database." -ForegroundColor Yellow
        } else {
            Write-Host "  VT URL lookup failed: HTTP $code - $_" -ForegroundColor Red
        }
    }
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
