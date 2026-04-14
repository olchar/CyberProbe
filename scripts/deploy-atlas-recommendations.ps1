<#
.SYNOPSIS
    Deploy MITRE ATLAS and OWASP LLM Top 10-aligned custom recommendations to Microsoft Defender for Cloud.

.DESCRIPTION
    Creates 14 custom recommendations across two security standards:

    Standard 1 — MITRE ATLAS (10 recommendations)
      Mapped to the MITRE ATLAS (Adversarial Threat Landscape for AI Systems) framework.
      Covers infrastructure-level AI/ML security controls.

    Standard 2 — OWASP Top 10 for LLM Applications (4 recommendations)
      Mapped to the OWASP Top 10 for LLM Applications (2025). Covers application-layer
      AI risks that can be detected via Azure resource configuration.

    MITRE ATLAS Tactics covered:
      - AML.TA0000  ML Model Access
      - AML.TA0001  Reconnaissance
      - AML.TA0002  Resource Development
      - AML.TA0005  ML Attack Staging (Evasion)
      - AML.TA0006  Impact
      - AML.TA0007  Exfiltration
      - AML.TA0042  Initial Access

    OWASP LLM Risks covered:
      - LLM01  Prompt Injection
      - LLM02  Sensitive Information Disclosure
      - LLM03  Supply Chain Vulnerabilities
      - LLM06  Excessive Agency
      - LLM08  Vector and Embedding Weaknesses
      - LLM09  Misinformation

    Prerequisites:
      - Azure CLI installed and authenticated (az login)
      - Contributor or Security Admin role on the target subscription
      - Defender CSPM plan enabled on the subscription

.PARAMETER SubscriptionId
    The Azure subscription ID to deploy recommendations to.

.PARAMETER WhatIf
    Preview the API calls without executing them.

.EXAMPLE
    .\deploy-atlas-recommendations.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    .\deploy-atlas-recommendations.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -WhatIf

.NOTES
    MITRE ATLAS: https://atlas.mitre.org
    OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    API Reference: https://learn.microsoft.com/en-us/rest/api/defenderforcloud/custom-recommendations
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
$baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/customRecommendations"

# ────────────────────────────────────────────────────────────────
# Helper: Generate deterministic UUID v5 from a friendly name
# Uses DNS namespace UUID so re-runs produce the same GUID
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
# Define 10 MITRE ATLAS-aligned custom recommendations
# ────────────────────────────────────────────────────────────────
$recommendations = @(

    # ── 1. AI Services: Disable local authentication (API keys) ──
    # ATLAS: AML.T0040 (ML Model Inference API Access)
    @{
        name            = "atlas-ai-disable-local-auth"
        displayName     = "AI Services should disable local authentication (API keys)"
        description     = "Azure AI Services with local authentication (API keys) enabled allow any actor with a stolen key to invoke models without identity-based auditing. This maps to MITRE ATLAS AML.T0040 (ML Model Inference API Access) where adversaries use stolen API keys to interact with ML models. Disabling local auth forces Entra ID authentication with full audit trails."
        remediationDesc = "Set disableLocalAuth to true on Azure AI Services accounts and use managed identities or Entra ID tokens for authentication. Reference: https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend disableLocalAuth = tobool(Record.properties.disableLocalAuth)
| extend HealthStatus = iff(disableLocalAuth == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 2. AI Services: Require private network access ──
    # ATLAS: AML.T0049 (Exploit Public-Facing Application)
    @{
        name            = "atlas-ai-private-network"
        displayName     = "AI Services should not be accessible from the public internet"
        description     = "Azure OpenAI and Cognitive Services endpoints exposed to the public internet enable adversaries to probe, enumerate, and exploit inference APIs without network-level controls. Maps to MITRE ATLAS AML.T0049 (Exploit Public-Facing Application) and AML.T0040 (ML Model Inference API Access). Private endpoints restrict access to authorized virtual networks."
        remediationDesc = "Configure private endpoints for AI Services and set publicNetworkAccess to Disabled. Reference: https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend publicNetworkAccess = tostring(Record.properties.publicNetworkAccess)
| extend HealthStatus = iff(publicNetworkAccess =~ 'Disabled', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 3. AI Services: Enable customer-managed keys ──
    # ATLAS: AML.T0045 (ML Artifact Collection), AML.T0024 (Exfiltration via ML Inference API)
    @{
        name            = "atlas-ai-customer-managed-keys"
        displayName     = "AI Services should use customer-managed keys for encryption"
        description     = "AI Services storing fine-tuned models, training data, and inference logs with only platform-managed encryption allow Microsoft-side key access. Customer-managed keys (CMK) ensure the organization retains exclusive control over encryption. Maps to MITRE ATLAS AML.T0045 (ML Artifact Collection) — adversaries targeting stored model artifacts and training data."
        remediationDesc = "Configure customer-managed keys using Azure Key Vault for AI Services encryption. Reference: https://learn.microsoft.com/en-us/azure/ai-services/encryption/cognitive-services-encryption-keys-portal"
        severity        = "Medium"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend cmkKeySource = tostring(Record.properties.encryption.keySource)
| extend HealthStatus = iff(cmkKeySource =~ 'Microsoft.KeyVault', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 4. ML Workspaces: Restrict public network access ──
    # ATLAS: AML.T0045 (ML Artifact Collection), AML.T0046 (Discover ML Artifacts)
    @{
        name            = "atlas-ml-workspace-private"
        displayName     = "Machine Learning workspaces should restrict public network access"
        description     = "Azure ML workspaces with public network access allow adversaries to discover and collect ML artifacts including model registries, datasets, and experiment metadata. Maps to MITRE ATLAS AML.T0046 (Discover ML Artifacts) and AML.T0045 (ML Artifact Collection). Private workspaces limit access to authorized networks only."
        remediationDesc = "Set publicNetworkAccess to Disabled on Azure ML workspaces and configure private endpoints. Reference: https://learn.microsoft.com/en-us/azure/machine-learning/how-to-configure-private-link"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.machinelearningservices/workspaces'
| extend publicNetworkAccess = tostring(Record.properties.publicNetworkAccess)
| extend HealthStatus = iff(publicNetworkAccess =~ 'Disabled', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 5. ML Workspaces: Enforce high business impact (data isolation) ──
    # ATLAS: AML.T0053 (Data Poisoning), AML.T0024 (Exfiltration via ML Inference API)
    @{
        name            = "atlas-ml-workspace-hbi"
        displayName     = "Machine Learning workspaces should enable high business impact data isolation"
        description     = "Azure ML workspaces without the High Business Impact (HBI) flag do not get enhanced data isolation — Microsoft may collect telemetry, and encryption controls are reduced. For workspaces handling sensitive training data, HBI enables stricter data residency and encryption. Maps to MITRE ATLAS AML.T0053 (Data Poisoning) and AML.T0024 (Exfiltration) — reducing attack surface on training data."
        remediationDesc = "Set hbiWorkspace to true when creating the Azure ML workspace. Note: this cannot be changed after creation — recreate the workspace with HBI enabled. Reference: https://learn.microsoft.com/en-us/azure/machine-learning/concept-data-encryption"
        severity        = "Medium"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.machinelearningservices/workspaces'
| extend hbiWorkspace = tobool(Record.properties.hbiWorkspace)
| extend HealthStatus = iff(hbiWorkspace == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 6. Storage accounts backing AI: Require HTTPS only ──
    # ATLAS: AML.T0053 (Data Poisoning), AML.T0024 (Exfiltration via ML Inference API)
    @{
        name            = "atlas-storage-ai-https-only"
        displayName     = "Storage accounts should enforce HTTPS-only traffic"
        description     = "Storage accounts serving as data stores for AI/ML training pipelines that allow HTTP traffic enable man-in-the-middle attacks on training data uploads and model artifact downloads. Maps to MITRE ATLAS AML.T0053 (Data Poisoning) — adversaries intercepting and modifying training data in transit."
        remediationDesc = "Set supportsHttpsTrafficOnly to true on all storage accounts, especially those backing ML workspaces and AI data pipelines. Reference: https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.storage/storageaccounts'
| extend httpsOnly = tobool(Record.supportsHttpsTrafficOnly)
| extend HealthStatus = iff(httpsOnly == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 7. Container registries: Disable admin user ──
    # ATLAS: AML.T0048 (Pre-Trained Model), AML.T0040 (ML Model Inference API Access)
    @{
        name            = "atlas-acr-disable-admin"
        displayName     = "Container registries should disable the admin user account"
        description     = "Azure Container Registries hosting ML model images with admin user enabled expose a shared credential that bypasses identity-based access. Adversaries with admin credentials can push poisoned model containers. Maps to MITRE ATLAS AML.T0048 (Pre-Trained Model) — supply chain attacks via tampered model images."
        remediationDesc = "Disable the admin user on Azure Container Registry and use Entra ID RBAC (AcrPush/AcrPull roles) for image operations. Reference: https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.containerregistry/registries'
| extend adminUserEnabled = tobool(Record.adminUserEnabled)
| extend HealthStatus = iff(adminUserEnabled != true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 8. Key Vaults: Enable purge protection ──
    # ATLAS: AML.T0029 (Denial of ML Service)
    @{
        name            = "atlas-keyvault-purge-protection"
        displayName     = "Key Vaults storing AI model keys should enable purge protection"
        description     = "Key Vaults without purge protection allow permanent deletion of encryption keys, API keys, and secrets used by AI services. An insider threat or compromised admin could destroy model encryption keys, rendering fine-tuned models and stored data irrecoverable. Maps to MITRE ATLAS AML.T0029 (Denial of ML Service)."
        remediationDesc = "Enable purge protection and soft-delete on Key Vaults used by AI services. Note: purge protection cannot be disabled once enabled. Reference: https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.keyvault/vaults'
| extend enablePurgeProtection = tobool(Record.properties.enablePurgeProtection)
| extend HealthStatus = iff(enablePurgeProtection == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 9. AI Search: Disable public network access ──
    # ATLAS: AML.T0046 (Discover ML Artifacts), AML.T0024 (Exfiltration via ML Inference API)
    @{
        name            = "atlas-search-private-access"
        displayName     = "AI Search services should restrict public network access"
        description     = "Azure AI Search services with public access serve as knowledge retrieval layers for RAG (Retrieval-Augmented Generation) pipelines. Public exposure allows adversaries to probe indexes, extract embeddings, and infer training data composition. Maps to MITRE ATLAS AML.T0046 (Discover ML Artifacts) and AML.T0024 (Exfiltration via ML Inference API)."
        remediationDesc = "Set publicNetworkAccess to Disabled on AI Search services and configure private endpoints for RAG pipeline access. Reference: https://learn.microsoft.com/en-us/azure/search/service-configure-firewall"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.search/searchservices'
| extend publicNetworkAccess = tostring(Record.properties.publicNetworkAccess)
| extend HealthStatus = iff(publicNetworkAccess =~ 'disabled', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 10. AI Services: Restrict outbound network access ──
    # ATLAS: AML.T0024 (Exfiltration via ML Inference API), AML.T0034 (Cost Harvesting)
    @{
        name            = "atlas-ai-restrict-outbound"
        displayName     = "AI Services should restrict outbound network access"
        description     = "Azure OpenAI and Cognitive Services with unrestricted outbound network access allow models to make arbitrary external calls — enabling data exfiltration via function calling, plugin execution, or prompt-injected outbound requests. Maps to MITRE ATLAS AML.T0024 (Exfiltration via ML Inference API) and AML.T0034 (Cost Harvesting) via abused outbound connectivity."
        remediationDesc = "Configure outbound network rules on AI Services to allow only required destinations. Use NSG rules on the subnet or configure the restrictOutboundNetworkAccess property. Reference: https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks"
        severity        = "Medium"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend restrictOutbound = tobool(Record.properties.restrictOutboundNetworkAccess)
| extend HealthStatus = iff(restrictOutbound == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }
)

# ────────────────────────────────────────────────────────────────
# Define 4 OWASP Top 10 for LLM Applications (2025) recommendations
# ────────────────────────────────────────────────────────────────
$owaspRecommendations = @(

    # ── 11. AI Services: Enable content filtering ──
    # OWASP: LLM01 (Prompt Injection), LLM09 (Misinformation)
    @{
        name            = "owasp-ai-content-filtering"
        displayName     = "Azure OpenAI deployments should enable content filtering"
        description     = "Azure OpenAI accounts without a custom content filter policy rely solely on default safety. Explicit content filtering configurations add defense-in-depth against prompt injection attacks (OWASP LLM01) and misinformation generation (OWASP LLM09). Deploying a named content filter policy ensures prompts and completions are screened for harmful content, jailbreak attempts, and indirect prompt injections."
        remediationDesc = "Create a content filter policy in Azure OpenAI Studio and assign it to all model deployments. Enable Prompt Shields for prompt injection detection and groundedness detection for misinformation. Reference: https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/content-filters"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend ['kind'] = tostring(Record.['kind'])
| where ['kind'] =~ 'OpenAI'
| extend skap = tostring(Record.properties.capabilities.contentFilterPolicies)
| extend HealthStatus = iff(isnotempty(skap) and skap != '0', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 12. AI Services: Enforce managed identity only (no API keys) ──
    # OWASP: LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)
    @{
        name            = "owasp-ai-managed-identity"
        displayName     = "AI Services should authenticate using managed identities only"
        description     = "AI Services accounts with local authentication enabled (API keys) and without a system-assigned managed identity create two risks: stolen keys enable unauthenticated model access with no audit trail (OWASP LLM02 — Sensitive Information Disclosure), and shared keys grant broad permissions that exceed least privilege (OWASP LLM06 — Excessive Agency). Managed identities provide automatic credential rotation and identity-scoped RBAC."
        remediationDesc = "1) Enable system-assigned managed identity on the AI Services account. 2) Assign appropriate RBAC roles (e.g., Cognitive Services OpenAI User). 3) Set disableLocalAuth to true to block API key access. Reference: https://learn.microsoft.com/en-us/azure/ai-services/authentication"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend disableLocalAuth = tobool(Record.properties.disableLocalAuth)
| extend hasManagedIdentity = isnotempty(tostring(Record.identity.principalId))
| extend HealthStatus = iff(disableLocalAuth == true and hasManagedIdentity == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 13. AI Search: Disable API key authentication ──
    # OWASP: LLM08 (Vector and Embedding Weaknesses)
    @{
        name            = "owasp-search-disable-api-keys"
        displayName     = "AI Search services should disable API key authentication"
        description     = "Azure AI Search services with API key authentication enabled allow anyone with a stolen admin or query key to access, modify, or exfiltrate vector indexes and embeddings. This directly maps to OWASP LLM08 (Vector and Embedding Weaknesses) — adversaries extracting or poisoning RAG knowledge stores via leaked keys. Disabling API keys and enforcing Entra ID RBAC ensures role-scoped access with audit trails."
        remediationDesc = "Set disableLocalAuth to true on the AI Search service and configure Entra ID RBAC (Search Service Contributor, Search Index Data Reader). Reference: https://learn.microsoft.com/en-us/azure/search/search-security-rbac"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.search/searchservices'
| extend disableLocalAuth = tobool(Record.properties.disableLocalAuth)
| extend HealthStatus = iff(disableLocalAuth == true, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }

    # ── 14. AI Services: Use latest TLS version ──
    # OWASP: LLM03 (Supply Chain Vulnerabilities), LLM02 (Sensitive Information Disclosure)
    @{
        name            = "owasp-ai-minimum-tls"
        displayName     = "AI Services should enforce TLS 1.2 or higher"
        description     = "AI Services accounts allowing TLS versions below 1.2 expose inference traffic and API credentials to downgrade attacks and known TLS vulnerabilities. Maps to OWASP LLM03 (Supply Chain Vulnerabilities) — insecure transport weakens the entire AI service dependency chain — and OWASP LLM02 (Sensitive Information Disclosure) — prompts and completions may be intercepted in transit."
        remediationDesc = "Set the minimumTlsVersion property to '1.2' on all AI Services accounts. This blocks clients using TLS 1.0 or 1.1. Reference: https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks"
        severity        = "High"
        securityIssue   = "Vulnerability"
        query           = @"
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == 'microsoft.cognitiveservices/accounts'
| extend minTls = tostring(Record.properties.apiProperties.minimumTlsVersion)
| extend HealthStatus = iff(minTls == '1.2' or minTls == '1.3', 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
"@
    }
)

$allRecommendations = $recommendations + $owaspRecommendations

# ────────────────────────────────────────────────────────────────
# Deploy each recommendation
# ────────────────────────────────────────────────────────────────
Write-Host "`n📋 Deploying $($allRecommendations.Count) AI security recommendations (ATLAS + OWASP LLM) to subscription $SubscriptionId`n" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor DarkGray

$successCount = 0
$failCount = 0
$skippedCount = 0
$createdAssessmentKeys = @{}

foreach ($rec in $allRecommendations) {
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
        $tempFile = [System.IO.Path]::GetTempFileName()
        $body | Out-File -FilePath $tempFile -Encoding utf8 -Force

        $result = az rest --method PUT --uri $uri --body "@$tempFile" --headers "Content-Type=application/json" -o json 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Created successfully (ID: $guidName)" -ForegroundColor Green
            $successCount++
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
# Create custom security standards (one per framework)
# ────────────────────────────────────────────────────────────────

# Helper function to create a standard
function Deploy-SecurityStandard {
    param(
        [string]$FriendlyName,
        [string]$DisplayName,
        [string]$Description,
        [hashtable[]]$SourceRecs
    )

    $guid = New-DeterministicGuid -Name $FriendlyName
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityStandards/$($guid)?api-version=$apiVersion"

    $assessments = @()
    foreach ($r in $SourceRecs) {
        if ($createdAssessmentKeys.ContainsKey($r.name)) {
            $assessments += @{ assessmentKey = $createdAssessmentKeys[$r.name] }
        }
    }

    if ($assessments.Count -eq 0) {
        Write-Host "   ⏭️  Skipping '$DisplayName' — no assessment keys captured" -ForegroundColor Yellow
        return
    }

    $body = @{
        properties = @{
            displayName    = $DisplayName
            description    = $Description
            cloudProviders = @("Azure")
            assessments    = $assessments
        }
    } | ConvertTo-Json -Depth 5 -Compress

    try {
        $tmpFile = [System.IO.Path]::GetTempFileName()
        $body | Out-File -FilePath $tmpFile -Encoding utf8 -Force

        $result = az rest --method PUT --uri $uri --body "@$tmpFile" --headers "Content-Type=application/json" -o json 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ '$DisplayName' created with $($assessments.Count) recommendations (ID: $guid)" -ForegroundColor Green
        }
        else {
            Write-Host "   ⚠️  '$DisplayName' returned: $result" -ForegroundColor Yellow
            Write-Host "   💡 Create manually: Environment Settings → Security policies → + Create → Standard" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "   ⚠️  '$DisplayName' error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    finally {
        if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
    }
}

if ($successCount -gt 0 -and -not $WhatIfPreference) {
    Write-Host "`n📐 Creating custom security standards..." -ForegroundColor Cyan

    # Standard 1: MITRE ATLAS
    Deploy-SecurityStandard `
        -FriendlyName  "atlas-ai-security-standard" `
        -DisplayName   "MITRE ATLAS — AI/ML Security Posture" `
        -Description   "Custom security standard aligned to the MITRE ATLAS (Adversarial Threat Landscape for AI Systems) framework. Contains 10 recommendations covering: inference API hardening (AML.T0040, AML.T0049), ML artifact protection (AML.T0045, AML.T0046), data poisoning prevention (AML.T0053), model supply chain integrity (AML.T0048), denial of ML service (AML.T0029), cost harvesting prevention (AML.T0034), and exfiltration controls (AML.T0024)." `
        -SourceRecs    $recommendations

    # Standard 2: OWASP LLM Top 10
    Deploy-SecurityStandard `
        -FriendlyName  "owasp-llm-security-standard" `
        -DisplayName   "OWASP Top 10 for LLM Applications — AI Risk Posture" `
        -Description   "Custom security standard aligned to the OWASP Top 10 for Large Language Model Applications (2025). Covers infrastructure-detectable risks: LLM01 (Prompt Injection) via content filtering, LLM02 (Sensitive Information Disclosure) via managed identity enforcement, LLM03 (Supply Chain Vulnerabilities) via TLS enforcement, LLM06 (Excessive Agency) via identity-scoped access, LLM08 (Vector and Embedding Weaknesses) via Search API key removal, LLM09 (Misinformation) via content safety policies." `
        -SourceRecs    $owaspRecommendations
}
elseif ($WhatIfPreference) {
    Write-Host "`n📐 [WhatIf] Would create 2 custom standards:" -ForegroundColor Yellow
    Write-Host "   1. 'MITRE ATLAS — AI/ML Security Posture' with $($recommendations.Count) recommendations" -ForegroundColor Yellow
    Write-Host "   2. 'OWASP Top 10 for LLM Applications — AI Risk Posture' with $($owaspRecommendations.Count) recommendations" -ForegroundColor Yellow
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
