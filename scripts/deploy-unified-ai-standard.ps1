<#
.SYNOPSIS
    Deploy a unified AI security standard combining MCSB (NIST-aligned), built-in AI-SPM,
    and custom ATLAS/OWASP recommendations into a single custom security standard.

.DESCRIPTION
    Creates one comprehensive custom security standard in Microsoft Defender for Cloud by
    dynamically assembling assessment keys from three sources:

    1. Azure CSPM / MCSB (Microsoft Cloud Security Benchmark)
       - 167 built-in assessments mapped to NIST 800-53 Rev 5 and CIS controls
       - Pulled live from the Azure CSPM standard on the target subscription

    2. Built-in AI-SPM Assessments (Azure-only)
       - ~30 built-in assessments covering Azure ML, Microsoft Foundry, Cognitive Services
       - Filtered from assessmentMetadata to exclude AWS/GCP recommendations
       - Includes: Foundry agent guardrails, jailbreak control, prompt injection HITL,
         red team evaluation, MCP tool allow-listing, content filtering, and more

    3. Custom ATLAS + OWASP LLM Recommendations (from deploy-atlas-recommendations.ps1)
       - 14 custom recommendations already deployed to the subscription
       - Automatically discovered via the customRecommendations API

    The script deduplicates all assessment keys before creating the standard.

    Prerequisites:
      - Azure CLI installed and authenticated (az login)
      - Contributor or Security Admin role on the target subscription
      - Defender CSPM plan enabled on the subscription
      - Custom ATLAS/OWASP recommendations already deployed (deploy-atlas-recommendations.ps1)

.PARAMETER SubscriptionId
    The Azure subscription ID to deploy the unified standard to.

.PARAMETER WhatIf
    Preview the standard composition without deploying.

.EXAMPLE
    .\deploy-unified-ai-standard.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    .\deploy-unified-ai-standard.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -WhatIf

.NOTES
    MCSB to NIST mapping: https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-overview
    AI-SPM Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-threat-protection
    API Reference: https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-standards
    Generated: April 13, 2026
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId
)

$ErrorActionPreference = 'Stop'
$apiVersion = '2024-08-01'

# ────────────────────────────────────────────────────────────────
# Helper: Generate deterministic UUID v5 from a friendly name
# ────────────────────────────────────────────────────────────────
function New-DeterministicGuid {
    param([string]$Name)
    $ns = [guid]'6ba7b810-9dad-11d1-80b4-00c04fd430c8'
    $encoding = [System.Text.Encoding]::UTF8
    $nsBytes = $ns.ToByteArray()
    $swap = { param($b,$i,$j) $t = $b[$i]; $b[$i] = $b[$j]; $b[$j] = $t }
    & $swap $nsBytes 0 3; & $swap $nsBytes 1 2
    & $swap $nsBytes 4 5; & $swap $nsBytes 6 7
    $nameBytes = $encoding.GetBytes($Name)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $sha1.TransformBlock($nsBytes, 0, $nsBytes.Length, $null, 0) | Out-Null
    $sha1.TransformFinalBlock($nameBytes, 0, $nameBytes.Length) | Out-Null
    $hash = $sha1.Hash
    $hash[6] = ($hash[6] -band 0x0F) -bor 0x50
    $hash[8] = ($hash[8] -band 0x3F) -bor 0x80
    & $swap $hash 0 3; & $swap $hash 1 2
    & $swap $hash 4 5; & $swap $hash 6 7
    $guidBytes = [byte[]]$hash[0..15]
    return (New-Object Guid (,$guidBytes)).ToString()
}

# ────────────────────────────────────────────────────────────────
# Verify Azure CLI authentication
# ────────────────────────────────────────────────────────────────
Write-Host "`n`u{1F510} Verifying Azure CLI authentication..." -ForegroundColor Cyan
$jmesQuery = '{name:name, id:id, tenantId:tenantId}'
try {
    $account = az account show --query $jmesQuery -o json 2>$null | ConvertFrom-Json
    if (-not $account) { throw "Not logged in" }
    Write-Host "   `u{2705} Authenticated as: $($account.name) ($($account.id))" -ForegroundColor Green

    $tenantId = $account.tenantId

    if ($account.id -ne $SubscriptionId) {
        Write-Host "   `u{2699}`u{FE0F}  Switching to subscription $SubscriptionId..." -ForegroundColor Yellow
        az account set --subscription $SubscriptionId 2>$null
        if ($LASTEXITCODE -ne 0) { throw "Failed to set subscription" }
        $account = az account show --query $jmesQuery -o json 2>$null | ConvertFrom-Json
        $tenantId = $account.tenantId
        Write-Host "   `u{2705} Subscription set" -ForegroundColor Green
    }
}
catch {
    Write-Host "   `u{274C} Azure CLI not authenticated. Run 'az login' first." -ForegroundColor Red
    exit 1
}

$subUri = "https://management.azure.com/subscriptions/$SubscriptionId"

# ════════════════════════════════════════════════════════════════
# SOURCE 1: Azure CSPM / MCSB (NIST 800-53 aligned baseline)
# ════════════════════════════════════════════════════════════════
Write-Host "`n`u{1F4D0} Source 1: Azure CSPM / MCSB (NIST-aligned baseline)" -ForegroundColor Cyan

$cspmKeys = @()
try {
    $stds = az rest --method GET --uri "$subUri/providers/Microsoft.Security/securityStandards?api-version=$apiVersion" -o json 2>$null | ConvertFrom-Json
    $cspm = $stds.value | Where-Object { $_.properties.displayName -eq 'Azure CSPM' }

    if ($cspm) {
        $cspmKeys = $cspm.properties.assessments | ForEach-Object { $_.assessmentKey }
        Write-Host "   `u{2705} Found Azure CSPM standard with $($cspmKeys.Count) assessment keys" -ForegroundColor Green
    }
    else {
        Write-Host "   `u{26A0}`u{FE0F}  Azure CSPM standard not found on this subscription" -ForegroundColor Yellow
        Write-Host "   `u{1F4A1} Enable Defender CSPM plan first: Azure Portal `u{2192} Defender for Cloud `u{2192} Environment Settings" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "   `u{274C} Failed to read security standards: $($_.Exception.Message)" -ForegroundColor Red
}

# ════════════════════════════════════════════════════════════════
# SOURCE 2: Built-in AI-SPM Assessments (Azure-only)
# ════════════════════════════════════════════════════════════════
Write-Host "`n`u{1F916} Source 2: Built-in AI-SPM Assessments" -ForegroundColor Cyan

$aiBuiltinKeys = @()
try {
    $meta = az rest --method GET --uri "$subUri/providers/Microsoft.Security/assessmentMetadata?api-version=2021-06-01" -o json 2>$null | ConvertFrom-Json

    # Filter for Azure AI/ML/Foundry/Cognitive Services assessments, exclude AWS/GCP
    $aiAssessments = $meta.value | Where-Object {
        ($_.properties.displayName -match 'AI |Cognitive|OpenAI|Machine Learn|Foundry') -and
        ($_.properties.displayName -notmatch 'AWS|Amazon|GCP|Vertex|Bedrock')
    }

    $aiBuiltinKeys = $aiAssessments | ForEach-Object { $_.name }
    Write-Host "   `u{2705} Found $($aiBuiltinKeys.Count) Azure AI-SPM built-in assessments:" -ForegroundColor Green

    foreach ($a in $aiAssessments) {
        $sev = $a.properties.severity
        $icon = switch ($sev) { 'High' { '`u{1F534}' } 'Medium' { '`u{1F7E0}' } default { '`u{1F7E1}' } }
        Write-Host "      $icon [$($sev.PadRight(6))] $($a.properties.displayName)" -ForegroundColor White
    }
}
catch {
    Write-Host "   `u{274C} Failed to read assessment metadata: $($_.Exception.Message)" -ForegroundColor Red
}

# ════════════════════════════════════════════════════════════════
# SOURCE 3: Custom ATLAS + OWASP LLM Recommendations
# ════════════════════════════════════════════════════════════════
Write-Host "`n`u{1F6E1}`u{FE0F}  Source 3: Custom ATLAS + OWASP LLM Recommendations" -ForegroundColor Cyan

$customKeys = @()
try {
    $customRecs = az rest --method GET --uri "$subUri/providers/Microsoft.Security/customRecommendations?api-version=$apiVersion" -o json 2>$null | ConvertFrom-Json

    # Filter for ATLAS and OWASP recommendations (by name prefix convention)
    $atlasOwaspRecs = $customRecs.value | Where-Object {
        $_.name -in @(
            # ATLAS recommendations (deterministic GUIDs from deploy-atlas-recommendations.ps1)
            (New-DeterministicGuid -Name "atlas-ai-disable-local-auth"),
            (New-DeterministicGuid -Name "atlas-ai-private-network"),
            (New-DeterministicGuid -Name "atlas-ai-customer-managed-keys"),
            (New-DeterministicGuid -Name "atlas-ml-workspace-private"),
            (New-DeterministicGuid -Name "atlas-ml-workspace-hbi"),
            (New-DeterministicGuid -Name "atlas-storage-ai-https-only"),
            (New-DeterministicGuid -Name "atlas-acr-disable-admin"),
            (New-DeterministicGuid -Name "atlas-keyvault-purge-protection"),
            (New-DeterministicGuid -Name "atlas-search-private-access"),
            (New-DeterministicGuid -Name "atlas-ai-restrict-outbound"),
            # OWASP recommendations
            (New-DeterministicGuid -Name "owasp-ai-content-filtering"),
            (New-DeterministicGuid -Name "owasp-ai-managed-identity"),
            (New-DeterministicGuid -Name "owasp-search-disable-api-keys"),
            (New-DeterministicGuid -Name "owasp-ai-minimum-tls")
        )
    }

    foreach ($rec in $atlasOwaspRecs) {
        if ($rec.properties.assessmentKey) {
            $customKeys += $rec.properties.assessmentKey
        }
    }

    Write-Host "   `u{2705} Found $($customKeys.Count) custom ATLAS/OWASP assessment keys (of 14 expected)" -ForegroundColor Green

    if ($customKeys.Count -lt 14) {
        $missing = 14 - $customKeys.Count
        Write-Host "   `u{26A0}`u{FE0F}  $missing custom recommendations missing — run deploy-atlas-recommendations.ps1 first" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "   `u{274C} Failed to read custom recommendations: $($_.Exception.Message)" -ForegroundColor Red
}

# ════════════════════════════════════════════════════════════════
# MERGE & DEDUPLICATE
# ════════════════════════════════════════════════════════════════
Write-Host "`n$("=" * 80)" -ForegroundColor DarkGray
Write-Host "`n`u{1F500} Merging and deduplicating assessment keys..." -ForegroundColor Cyan

$allKeys = @()
$allKeys += $cspmKeys
$allKeys += $aiBuiltinKeys
$allKeys += $customKeys

$uniqueKeys = $allKeys | Select-Object -Unique
$duplicates = $allKeys.Count - $uniqueKeys.Count

Write-Host "   Source 1 (MCSB/NIST):      $($cspmKeys.Count) keys" -ForegroundColor White
Write-Host "   Source 2 (AI-SPM built-in): $($aiBuiltinKeys.Count) keys" -ForegroundColor White
Write-Host "   Source 3 (ATLAS/OWASP):     $($customKeys.Count) keys" -ForegroundColor White
Write-Host "   ────────────────────────────────" -ForegroundColor DarkGray
Write-Host "   Total before dedup:         $($allKeys.Count)" -ForegroundColor White
Write-Host "   Duplicates removed:         $duplicates" -ForegroundColor Yellow
Write-Host "   `u{2705} Final unique keys:       $($uniqueKeys.Count)" -ForegroundColor Green

if ($uniqueKeys.Count -eq 0) {
    Write-Host "`n`u{274C} No assessment keys collected. Cannot create standard." -ForegroundColor Red
    exit 1
}

# ════════════════════════════════════════════════════════════════
# CREATE UNIFIED CUSTOM STANDARD
# ════════════════════════════════════════════════════════════════
$standardFriendlyName = "unified-ai-security-nist-atlas-owasp"
$standardGuid = New-DeterministicGuid -Name $standardFriendlyName
$standardUri = "$subUri/providers/Microsoft.Security/securityStandards/$($standardGuid)?api-version=$apiVersion"

$assessmentsList = $uniqueKeys | ForEach-Object { @{ assessmentKey = $_ } }

$standardBody = @{
    properties = @{
        displayName    = "Unified AI Security Standard (MCSB + AI-SPM + ATLAS + OWASP LLM)"
        description    = @"
Comprehensive AI security standard combining three assessment sources:

1. MCSB / NIST 800-53 Baseline ($($cspmKeys.Count) assessments)
   Microsoft Cloud Security Benchmark controls mapped to NIST 800-53 Rev 5.

2. Built-in AI-SPM ($($aiBuiltinKeys.Count) assessments)
   Azure ML, Microsoft Foundry, and Cognitive Services posture checks including
   Foundry agent guardrails, jailbreak control, prompt injection HITL, red team
   evaluation, MCP tool allow-listing, content filtering, and network isolation.

3. Custom ATLAS + OWASP LLM ($($customKeys.Count) assessments)
   MITRE ATLAS (AML.T0024–T0053) and OWASP Top 10 for LLM Applications (2025)
   covering inference API hardening, ML artifact protection, data poisoning
   prevention, supply chain integrity, and exfiltration controls.

Total unique assessments: $($uniqueKeys.Count)
Generated: $(Get-Date -Format 'yyyy-MM-dd')
"@
        cloudProviders = @("Azure")
        assessments    = $assessmentsList
    }
} | ConvertTo-Json -Depth 5 -Compress

Write-Host "`n`u{1F680} Deploying unified standard..." -ForegroundColor Cyan
Write-Host "   Name: Unified AI Security Standard (MCSB + AI-SPM + ATLAS + OWASP LLM)" -ForegroundColor White
Write-Host "   GUID: $standardGuid" -ForegroundColor White
Write-Host "   Assessments: $($uniqueKeys.Count)" -ForegroundColor White

if ($WhatIfPreference) {
    Write-Host "`n   [WhatIf] Would PUT `u{2192} $standardUri" -ForegroundColor Yellow
    Write-Host "   [WhatIf] Body size: $($standardBody.Length) bytes" -ForegroundColor Yellow
}
else {
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $standardBody | Out-File -FilePath $tempFile -Encoding utf8 -Force

        $result = az rest --method PUT --uri $standardUri --body "@$tempFile" --headers "Content-Type=application/json" -o json 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "   `u{2705} Unified standard created successfully!" -ForegroundColor Green

            try {
                $parsed = $result | ConvertFrom-Json
                Write-Host "   `u{1F4CD} Standard ID: $($parsed.name)" -ForegroundColor White
                Write-Host "   `u{1F4CA} Assessment count: $($parsed.properties.assessments.Count)" -ForegroundColor White
            }
            catch { }
        }
        else {
            Write-Host "   `u{274C} Failed: $result" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "   `u{274C} Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
    }
}

# ────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────
Write-Host "`n$("=" * 80)" -ForegroundColor DarkGray
Write-Host "`n`u{1F4CA} Unified Standard Composition:" -ForegroundColor Cyan
Write-Host "   `u{1F4D8} MCSB/NIST 800-53:  $($cspmKeys.Count) assessments" -ForegroundColor White
Write-Host "   `u{1F916} AI-SPM Built-in:   $($aiBuiltinKeys.Count) assessments" -ForegroundColor White
Write-Host "   `u{1F6E1}`u{FE0F}  ATLAS/OWASP:      $($customKeys.Count) assessments" -ForegroundColor White
Write-Host "   `u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}`u{2500}" -ForegroundColor DarkGray
Write-Host "   `u{2705} Total unique:      $($uniqueKeys.Count) assessments" -ForegroundColor Green

Write-Host "`n`u{1F517} View in portal:" -ForegroundColor Cyan
Write-Host "   https://security.microsoft.com/cloud-initiative?viewid=Overview&tid=$tenantId" -ForegroundColor White
Write-Host "   https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings`n" -ForegroundColor White
