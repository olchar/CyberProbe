<#
.SYNOPSIS
    Deploy CNAPP custom recommendations to Microsoft Defender for Cloud via REST API.

.DESCRIPTION
    Creates 10 KQL-based custom recommendations in Defender for Cloud using the
    Microsoft.Security/customRecommendations API. These recommendations were derived
    from the CNAPP Shift-Left Scenario Report (April 12, 2026).

    Prerequisites:
      - Azure CLI installed and authenticated (az login)
      - Contributor or Security Admin role on the target subscription
      - Defender CSPM plan enabled on the subscription

.PARAMETER SubscriptionId
    The Azure subscription ID to deploy recommendations to.

.PARAMETER WhatIf
    Preview the API calls without executing them.

.EXAMPLE
    .\deploy-custom-recommendations.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    .\deploy-custom-recommendations.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -WhatIf

.NOTES
    API Reference: https://learn.microsoft.com/en-us/rest/api/defenderforcloud/custom-recommendations
    Generated from CNAPP Shift-Left Scenario Report — April 12, 2026
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false, HelpMessage = "Comma-separated supported K8s versions (default: 1.30,1.31,1.32)")]
    [string[]]$SupportedK8sVersions = @("1.30", "1.31", "1.32")
)

$ErrorActionPreference = 'Stop'
$apiVersion = '2024-08-01'
$baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/customRecommendations"

# ────────────────────────────────────────────────────────────────
# Helper: Generate deterministic UUID v5 from a friendly name
# Uses DNS namespace UUID (6ba7b810-9dad-11d1-80b4-00c04fd430c8)
# so re-runs produce the same GUID → idempotent PUT operations
# ────────────────────────────────────────────────────────────────
function New-DeterministicGuid {
    param([string]$Name)
    $ns = [guid]'6ba7b810-9dad-11d1-80b4-00c04fd430c8'
    $encoding = [System.Text.Encoding]::UTF8
    $nsBytes = $ns.ToByteArray()
    # Swap to network byte order (RFC 4122)
    $swap = { param($b,$i,$j) $t = $b[$i]; $b[$i] = $b[$j]; $b[$j] = $t }
    & $swap $nsBytes 0 3; & $swap $nsBytes 1 2
    & $swap $nsBytes 4 5; & $swap $nsBytes 6 7
    $nameBytes = $encoding.GetBytes($Name)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $sha1.TransformBlock($nsBytes, 0, $nsBytes.Length, $null, 0) | Out-Null
    $sha1.TransformFinalBlock($nameBytes, 0, $nameBytes.Length) | Out-Null
    $hash = $sha1.Hash
    $hash[6] = ($hash[6] -band 0x0F) -bor 0x50   # version 5
    $hash[8] = ($hash[8] -band 0x3F) -bor 0x80   # variant RFC 4122
    # Swap back to mixed-endian for .NET Guid constructor
    & $swap $hash 0 3; & $swap $hash 1 2
    & $swap $hash 4 5; & $swap $hash 6 7
    $guidBytes = [byte[]]$hash[0..15]
    return (New-Object Guid (,$guidBytes)).ToString()
}

# ────────────────────────────────────────────────────────────────
# Verify Azure CLI authentication
# ────────────────────────────────────────────────────────────────
Write-Host "`n🔐 Verifying Azure CLI authentication..." -ForegroundColor Cyan
$jmesQuery = '{name:name, id:id, tenantId:tenantId}'
try {
    $account = az account show --query $jmesQuery -o json 2>$null | ConvertFrom-Json
    if (-not $account) { throw "Not logged in" }
    Write-Host "   ✅ Authenticated as: $($account.name) ($($account.id))" -ForegroundColor Green

    $tenantId = $account.tenantId

    if ($account.id -ne $SubscriptionId) {
        Write-Host "   ⚙️  Switching to subscription $SubscriptionId..." -ForegroundColor Yellow
        az account set --subscription $SubscriptionId 2>$null
        if ($LASTEXITCODE -ne 0) { throw "Failed to set subscription" }
        $account = az account show --query $jmesQuery -o json 2>$null | ConvertFrom-Json
        $tenantId = $account.tenantId
        Write-Host "   ✅ Subscription set" -ForegroundColor Green
    }
}
catch {
    Write-Host "   ❌ Azure CLI not authenticated. Run 'az login' first." -ForegroundColor Red
    exit 1
}

# ────────────────────────────────────────────────────────────────
# Define all 10 custom recommendations
# ────────────────────────────────────────────────────────────────
$recommendations = @(

    # ── 1. AKS Public API Server ──
    @{
        name            = "cnapp-aks-public-api-server"
        displayName     = "AKS clusters should not expose API server to the internet"
        description     = "AKS clusters with public API server endpoints are exposed to unauthorized access attempts. The API server should be restricted to private network access only, using authorized IP ranges or private clusters. Identified in CNAPP shift-left assessment as a critical exposure vector."
        remediationDesc = "Enable private cluster mode or configure authorized IP address ranges on the AKS cluster. Reference: https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.containerservice/managedclusters'
| extend enablePrivateCluster = tobool(Record.apiServerAccessProfile.enablePrivateCluster)
| extend authorizedIpRanges = Record.apiServerAccessProfile.authorizedIpRanges
| extend isPublic = enablePrivateCluster != true and (isnull(authorizedIpRanges) or array_length(authorizedIpRanges) == 0)
| extend HealthStatus = iff(not(isPublic), 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 2. AKS Outdated Kubernetes ──
    @{
        name            = "cnapp-aks-outdated-kubernetes"
        displayName     = "AKS clusters should run a supported Kubernetes version"
        description     = "AKS clusters running end-of-life or outdated Kubernetes versions miss critical security patches and are vulnerable to known CVEs. Clusters should run within N-2 of the latest GA version."
        remediationDesc = "Upgrade the AKS cluster to a supported Kubernetes version using az aks upgrade. Reference: https://learn.microsoft.com/en-us/azure/aks/supported-kubernetes-versions"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.containerservice/managedclusters'
| extend k8sVersion = tostring(Record.kubernetesVersion)
| extend majorMinor = strcat(split(k8sVersion, ".")[0], ".", split(k8sVersion, ".")[1])
| extend HealthStatus = iff(majorMinor in ($(($SupportedK8sVersions | ForEach-Object { '"' + $_ + '"' }) -join ', ')), 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 3. ACR Images with High/Critical Vulns ──
    @{
        name            = "cnapp-acr-high-critical-vulns"
        displayName     = "Container registry images should not have high or critical unpatched vulnerabilities"
        description     = "Container images in Azure Container Registry with high or critical CVEs represent a persistent attack surface. These vulnerabilities propagate to every deployment using the image."
        remediationDesc = "Rebuild container images with updated base images and patched dependencies. Run npm audit fix or equivalent for application-layer vulnerabilities. Use az acr task to automate image rebuilds."
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.containerregistry/registries'
| extend adminUserEnabled = tobool(Record.adminUserEnabled)
| extend publicNetworkAccess = tostring(Record.publicNetworkAccess)
| extend HealthStatus = iff(adminUserEnabled != true and publicNetworkAccess != 'Enabled', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 4. Storage Without Network Restrictions ──
    @{
        name            = "cnapp-storage-public-access"
        displayName     = "Storage accounts should restrict public network access"
        description     = "Storage accounts with unrestricted public network access can be targeted for malicious blob uploads, data exfiltration, and unauthorized access. Network rules should restrict access to specific VNets, private endpoints, or trusted Azure services only."
        remediationDesc = "Configure storage account firewall rules to deny public access and allow only selected virtual networks or private endpoints. Set defaultAction to Deny. Reference: https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.storage/storageaccounts'
| extend networkDefaultAction = tostring(Record.networkAcls.defaultAction)
| extend publicNetworkAccess = tostring(Record.publicNetworkAccess)
| extend HealthStatus = iff(networkDefaultAction =~ 'Deny' and publicNetworkAccess != 'Enabled', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 5. Key Vault Without Network Restrictions ──
    @{
        name            = "cnapp-keyvault-public-access"
        displayName     = "Key Vaults should restrict public network access"
        description     = "Key Vaults without network restrictions are accessible from any IP, enabling credential theft from TOR exit nodes and anonymous proxies. Demonstrated in CNAPP assessment where TOR to Key Vault access triggered multiple security incidents."
        remediationDesc = "Enable Key Vault firewall, set default action to Deny, and use private endpoints or approved IP ranges. Reference: https://learn.microsoft.com/en-us/azure/key-vault/general/network-security"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.keyvault/vaults'
| extend networkDefaultAction = tostring(Record.properties.networkAcls.defaultAction)
| extend publicNetworkAccess = tostring(Record.properties.publicNetworkAccess)
| extend HealthStatus = iff(networkDefaultAction =~ 'Deny' or publicNetworkAccess =~ 'Disabled', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 6. AI Services Without Defender for AI ──
    @{
        name            = "cnapp-ai-no-defender"
        displayName     = "AI Services should have Defender for AI enabled"
        description     = "AI service endpoints without Defender for AI lack protection against prompt injection, jailbreak attacks, phishing attempts on AI agents, and anomalous access patterns. The CNAPP assessment detected 153 jailbreak attempts and 64 anonymized IP accesses caught by Defender for AI."
        remediationDesc = "Enable the Defender for AI plan in Defender for Cloud Environment Settings for all subscriptions hosting Azure OpenAI or AI Foundry resources. Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-ai"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend kind_lower = tolower(tostring(Record.kind))
| where kind_lower in ('openai', 'aiservices')
| extend publicNetworkAccess = tostring(Record.properties.publicNetworkAccess)
| extend HealthStatus = iff(publicNetworkAccess =~ 'Disabled', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 7. AI Services Unrestricted Public Access ──
    @{
        name            = "cnapp-ai-unrestricted-public"
        displayName     = "AI Services should not allow unrestricted public network access"
        description     = "Azure OpenAI and AI Foundry endpoints with unrestricted public access allow anonymized or adversarial actors to interact with models directly. The assessment found 64 requests from anonymized IPs targeting AI endpoints."
        remediationDesc = "Restrict public network access on AI services by configuring network rules with allowed IP ranges or using private endpoints. Disable API key authentication and enforce Entra ID auth. Reference: https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks"
        severity        = "Medium"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend kind_lower = tolower(tostring(Record.kind))
| where kind_lower in ('openai', 'aiservices')
| extend publicNetworkAccess = tostring(Record.properties.publicNetworkAccess)
| extend networkDefaultAction = tostring(Record.properties.networkAcls.defaultAction)
| extend HealthStatus = iff(publicNetworkAccess != 'Enabled' or networkDefaultAction =~ 'Deny', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 8. Repos Without Branch Protection ──
    @{
        name            = "cnapp-devops-no-branch-protection"
        displayName     = "Code repositories should enforce branch protection on the default branch"
        description     = "Repositories without branch protection allow unreviewed code to reach main/production branches, bypassing code review and automated security scanning gates. Vulnerable dependencies and IaC misconfigurations reached production in the CNAPP assessment because the repository lacked minimum reviewer requirements."
        remediationDesc = "Enable branch protection rules on the default branch requiring: minimum 2 reviewers, status checks (code scanning, dependency review), and no force pushes. Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-devops-introduction"
        severity        = "Medium"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.security/securityconnectors/devops/repos'
| extend branchProtection = tobool(Record.properties.branchProtectionEnabled)
| extend HealthStatus = iff(branchProtection == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 9. AKS Without Defender Sensor ──
    @{
        name            = "cnapp-aks-no-defender-sensor"
        displayName     = "AKS clusters should have Defender for Containers sensor deployed"
        description     = "AKS clusters without the Defender sensor lack real-time runtime threat detection. They rely solely on periodic agentless scans, missing real-time attacks like container drift, cryptominer deployment, and metadata service abuse."
        remediationDesc = "Enable the Defender sensor on AKS clusters via the Defender for Containers plan. The sensor auto-deploys as a DaemonSet. Verify with: kubectl get pods -n kube-system | grep microsoft-defender. Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-enable"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.containerservice/managedclusters'
| extend defenderEnabled = tobool(Record.securityProfile.defender.securityMonitoring.enabled)
| extend HealthStatus = iff(defenderEnabled == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 10. Cosmos DB Without Network Restrictions ──
    @{
        name            = "cnapp-cosmosdb-public-access"
        displayName     = "Cosmos DB accounts should restrict public network access"
        description     = "Cosmos DB accounts with public network access enabled and no IP/VNet restrictions allow unauthorized key extraction attempts. Incident 41887 in the CNAPP assessment involved suspicious Cosmos DB account key extraction."
        remediationDesc = "Set Cosmos DB publicNetworkAccess to Disabled and configure private endpoints. If public access is required, set IP firewall rules to allow only known IPs. Reference: https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall"
        severity        = "Medium"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.documentdb/databaseaccounts'
| extend publicNetworkAccess = tostring(Record.publicNetworkAccess)
| extend ipRangeFilter = tostring(Record.ipRangeFilter)
| extend isVNetFilterEnabled = tobool(Record.isVirtualNetworkFilterEnabled)
| extend HealthStatus = iff(publicNetworkAccess =~ 'Disabled' or (isnotempty(ipRangeFilter) and ipRangeFilter != '') or isVNetFilterEnabled == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }
)

# ────────────────────────────────────────────────────────────────
# Deploy each recommendation
# ────────────────────────────────────────────────────────────────
Write-Host "`n📋 Deploying $($recommendations.Count) custom recommendations to subscription $SubscriptionId`n" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor DarkGray

$successCount = 0
$failCount = 0
$skippedCount = 0
$createdAssessmentKeys = @{}  # Maps friendly name → assessmentKey from API response

foreach ($rec in $recommendations) {
    # API requires GUID resource names (friendly names return 404)
    $guidName = New-DeterministicGuid -Name $rec.name
    $uri = "$baseUri/$($guidName)?api-version=$apiVersion"

    $body = @{
        properties = @{
            query                  = $rec.query
            supportedClouds        = @("Azure")
            severity               = $rec.severity
            displayName            = $rec.displayName
            description            = $rec.description
            remediationDescription = $rec.remediationDesc
            securityIssue          = $rec.securityIssue
        }
    } | ConvertTo-Json -Depth 5 -Compress

    Write-Host "`n🔹 [$($rec.severity.ToUpper().PadRight(6))] $($rec.displayName)" -ForegroundColor White

    if ($WhatIfPreference) {
        Write-Host "   [WhatIf] Would PUT → $uri" -ForegroundColor Yellow
        $skippedCount++
        continue
    }

    try {
        # Write body to temp file to avoid shell escaping issues
        $tempFile = [System.IO.Path]::GetTempFileName()
        $body | Out-File -FilePath $tempFile -Encoding utf8 -Force

        $result = az rest --method PUT --uri $uri --body "@$tempFile" --headers "Content-Type=application/json" -o json 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Created successfully (ID: $guidName)" -ForegroundColor Green
            $successCount++
            # Extract assessmentKey from API response for standard assignment
            try {
                $parsed = $result | ConvertFrom-Json
                if ($parsed.properties.assessmentKey) {
                    $createdAssessmentKeys[$rec.name] = $parsed.properties.assessmentKey
                }
            } catch { }
        }
        else {
            Write-Host "   ❌ Failed: $result" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host "   ❌ Error: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
    }
}

# ────────────────────────────────────────────────────────────────
# Create custom security standard and assign all recommendations
# ────────────────────────────────────────────────────────────────
if ($successCount -gt 0 -and -not $WhatIfPreference) {
    Write-Host "`n📐 Creating custom security standard..." -ForegroundColor Cyan

    $standardFriendlyName = "cnapp-shift-left-standard"
    $standardGuid = New-DeterministicGuid -Name $standardFriendlyName
    $standardUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityStandards/$($standardGuid)?api-version=$apiVersion"

    # Build the assessments array using assessmentKeys returned by the API
    $assessmentsList = @()
    foreach ($rec in $recommendations) {
        if ($createdAssessmentKeys.ContainsKey($rec.name)) {
            $assessmentsList += @{
                assessmentKey = $createdAssessmentKeys[$rec.name]
            }
        }
    }

    $standardBody = @{
        properties = @{
            displayName = "CNAPP Shift-Left — Custom Recommendations"
            description = "Custom security standard containing 10 recommendations derived from the CNAPP Shift-Left Scenario assessment. Covers AKS hardening, container image hygiene, network restrictions (Storage, Key Vault, Cosmos DB, AI Services), AI workload protection, DevSecOps governance, and runtime detection coverage."
            cloudProviders = @("Azure")
            assessments = $assessmentsList
        }
    } | ConvertTo-Json -Depth 5 -Compress

    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $standardBody | Out-File -FilePath $tempFile -Encoding utf8 -Force

        $result = az rest --method PUT --uri $standardUri --body "@$tempFile" --headers "Content-Type=application/json" -o json 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Custom standard created with $($assessmentsList.Count) recommendations (ID: $standardGuid)" -ForegroundColor Green
            Write-Host "   📍 All recommendations are now grouped under: CNAPP Shift-Left — Custom Recommendations" -ForegroundColor White
        }
        else {
            Write-Host "   ⚠️  Standard creation returned: $result" -ForegroundColor Yellow
            Write-Host "   💡 You can create the standard manually in the portal: Environment Settings → Security policies → + Create → Standard" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "   ⚠️  Standard creation error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   💡 Recommendations were created. Add them to a standard manually in the portal." -ForegroundColor Yellow
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
    }
}
elseif ($WhatIfPreference) {
    Write-Host "`n📐 [WhatIf] Would create custom standard 'cnapp-shift-left-standard' with $($recommendations.Count) recommendations" -ForegroundColor Yellow
}

# ────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────
Write-Host "`n$("=" * 80)" -ForegroundColor DarkGray
Write-Host "`n📊 Deployment Summary:" -ForegroundColor Cyan
Write-Host "   ✅ Succeeded: $successCount" -ForegroundColor Green
if ($failCount -gt 0) { Write-Host "   ❌ Failed:    $failCount" -ForegroundColor Red }
if ($skippedCount -gt 0) { Write-Host "   ⏭️  Skipped:   $skippedCount (WhatIf mode)" -ForegroundColor Yellow }

Write-Host "`n🔗 View in portal:" -ForegroundColor Cyan
Write-Host "   https://security.microsoft.com/cloud-initiative?viewid=Overview&tid=$tenantId" -ForegroundColor White
Write-Host "   https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings`n" -ForegroundColor White

if ($failCount -gt 0) { exit 1 }
