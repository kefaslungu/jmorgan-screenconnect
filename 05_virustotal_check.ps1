# 05_virustotal_check.ps1 - Query VirusTotal for the sample hash
$hash   = "ff1e15cdb4ec8214c2a90dcb4040a4b0ef8c6d60539e90ff93fe1d79f7d685c3"
$apiKey = $env:virusTotal_api_key

Write-Host "=== VirusTotal Hash Lookup ===" -ForegroundColor Cyan
Write-Host "Hash: $hash"
Write-Host "API key found: $($apiKey.Substring(0,8))..."

$headers = @{ "x-apikey" = $apiKey }
$url     = "https://www.virustotal.com/api/v3/files/$hash"

try {
    $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -ErrorAction Stop
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 404) {
        Write-Host "`n[NOT FOUND] Hash not yet in VirusTotal database." -ForegroundColor Yellow
        Write-Host "Consider uploading the file for a full scan."
    } else {
        Write-Host "`n[ERROR] HTTP $code : $_" -ForegroundColor Red
    }
    exit
}

$attr  = $resp.data.attributes
$stats = $attr.last_analysis_stats

Write-Host "`n=== File Info ===" -ForegroundColor Cyan
Write-Host "Name(s)         : $($attr.names -join ', ')"
Write-Host "Type            : $($attr.type_description)"
Write-Host "Size            : $($attr.size) bytes"
Write-Host "First submitted : $(([System.DateTimeOffset]::FromUnixTimeSeconds($attr.first_submission_date)).UtcDateTime) UTC"
Write-Host "Last submitted  : $(([System.DateTimeOffset]::FromUnixTimeSeconds($attr.last_submission_date)).UtcDateTime) UTC"
Write-Host "Times submitted : $($attr.times_submitted)"
Write-Host "Reputation      : $($attr.reputation)"

Write-Host "`n=== Detection Stats ===" -ForegroundColor Cyan
Write-Host "Malicious   : $($stats.malicious)"   -ForegroundColor $(if ($stats.malicious -gt 0) { 'Red' } else { 'Green' })
Write-Host "Suspicious  : $($stats.suspicious)"  -ForegroundColor $(if ($stats.suspicious -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "Undetected  : $($stats.undetected)"
Write-Host "Harmless    : $($stats.harmless)"
Write-Host "Timeout     : $($stats.timeout)"

Write-Host "`n=== Engines Flagging as Malicious/Suspicious ===" -ForegroundColor Cyan
$flagged = $attr.last_analysis_results.PSObject.Properties |
    Where-Object { $_.Value.category -in @('malicious', 'suspicious') } |
    Sort-Object { $_.Value.category }

if ($flagged) {
    $flagged | ForEach-Object {
        $color = if ($_.Value.category -eq 'malicious') { 'Red' } else { 'Yellow' }
        Write-Host ("  [{0,-12}] {1,-30} -> {2}" -f $_.Value.category.ToUpper(), $_.Name, $_.Value.result) -ForegroundColor $color
    }
} else {
    Write-Host "  None - no engine flagged this hash." -ForegroundColor Green
}

Write-Host "`n=== Popular Threat Labels ===" -ForegroundColor Cyan
if ($attr.popular_threat_classification) {
    Write-Host "Category : $($attr.popular_threat_classification.suggested_threat_label)"
    $attr.popular_threat_classification.popular_threat_category | ForEach-Object {
        Write-Host "  - $($_.value) (votes: $($_.count))"
    }
} else {
    Write-Host "  No threat label assigned."
}

Write-Host "`n=== Sigma / YARA / Sandbox ===" -ForegroundColor Cyan
if ($attr.sigma_analysis_stats) {
    Write-Host "Sigma hits  : critical=$($attr.sigma_analysis_stats.critical) high=$($attr.sigma_analysis_stats.high) medium=$($attr.sigma_analysis_stats.medium)"
}
if ($attr.crowdsourced_yara_results) {
    Write-Host "YARA rules matched:"
    $attr.crowdsourced_yara_results | ForEach-Object {
        Write-Host "  - [$($_.ruleset_name)] $($_.rule_name) by $($_.author)"
    }
}

Write-Host "`nVirusTotal link: https://www.virustotal.com/gui/file/$hash" -ForegroundColor Cyan
