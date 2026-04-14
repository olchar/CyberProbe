# Custom Security Recommendations — CNAPP Shift-Left Gaps

**Purpose:** KQL-based custom recommendations to create in Defender for Cloud via the Defender XDR portal.  
**Source:** Gaps identified in the CNAPP Shift-Left Scenario Report (April 12, 2026).  
**Creation path:** Defender XDR Portal → Cloud Security → Environment Settings → (select subscription) → Security Policies → **+ Create** → **Custom recommendation**

> **How to create each recommendation:**
> 1. Go to [Environment Settings](https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings)
> 2. Select the target subscription
> 3. Click **Security policies** in the left menu
> 4. Click **+ Create** → **Custom recommendation**
> 5. Fill in the fields below for each recommendation
> 6. Paste the KQL query
> 7. Set severity and assign the relevant standard

---

## 1 — AKS Clusters with Public API Server Access

| Field | Value |
|-------|-------|
| **Recommendation name** | `AKS clusters should not expose API server to the internet` |
| **Description** | AKS clusters with public API server endpoints are exposed to unauthorized access attempts. The API server should be restricted to private network access only, using authorized IP ranges or private clusters. This was demonstrated as a critical exposure vector in the CNAPP shift-left assessment. |
| **Severity** | High |
| **Category** | Networking |
| **Owner** | Platform Team |
| **Remediation description** | Enable private cluster mode or configure authorized IP address ranges on the AKS cluster. Reference: https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges |
| **MITRE Tactics** | Initial Access, Reconnaissance |

**KQL Query:**
```kusto
resources
| where type == "microsoft.containerservice/managedclusters"
| extend apiServerProfile = properties.apiServerAccessProfile
| extend enablePrivateCluster = tobool(apiServerProfile.enablePrivateCluster)
| extend authorizedIpRanges = apiServerProfile.authorizedIpRanges
| where enablePrivateCluster != true
| where isnull(authorizedIpRanges) or array_length(authorizedIpRanges) == 0
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    kubernetesVersion = tostring(properties.kubernetesVersion),
    enablePrivateCluster,
    authorizedIpRanges
```

---

## 2 — AKS Clusters Running Outdated Kubernetes Versions

| Field | Value |
|-------|-------|
| **Recommendation name** | `AKS clusters should run a supported Kubernetes version` |
| **Description** | AKS clusters running end-of-life or outdated Kubernetes versions miss critical security patches and are vulnerable to known CVEs. Clusters should run within N-2 of the latest GA version. |
| **Severity** | High |
| **Category** | Compute |
| **Owner** | Platform Team |
| **Remediation description** | Upgrade the AKS cluster to a supported Kubernetes version using `az aks upgrade`. Reference: https://learn.microsoft.com/en-us/azure/aks/supported-kubernetes-versions |
| **MITRE Tactics** | Exploitation for Client Execution |

**KQL Query:**
```kusto
resources
| where type == "microsoft.containerservice/managedclusters"
| extend k8sVersion = tostring(properties.kubernetesVersion)
| extend majorMinor = strcat(split(k8sVersion, ".")[0], ".", split(k8sVersion, ".")[1])
| where majorMinor !in ("1.30", "1.31", "1.32")  // Update these to current supported versions
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    kubernetesVersion = k8sVersion,
    provisioningState = tostring(properties.provisioningState)
```

---

## 3 — Container Images with High/Critical Unpatched Vulnerabilities

| Field | Value |
|-------|-------|
| **Recommendation name** | `Container registry images should not have high or critical vulnerabilities unresolved for more than 30 days` |
| **Description** | Container images in Azure Container Registry with high or critical CVEs that have remained unpatched for more than 30 days represent a persistent attack surface. These vulnerabilities propagate to every deployment using the image. |
| **Severity** | High |
| **Category** | Compute |
| **Owner** | Application Team |
| **Remediation description** | Rebuild container images with updated base images and patched dependencies. Run `npm audit fix` or equivalent for application-layer vulnerabilities. Use `az acr task` to automate image rebuilds. |
| **MITRE Tactics** | Initial Access, Execution |

**KQL Query:**
```kusto
securityresources
| where type == "microsoft.security/assessments/subassessments"
| where properties.id has "containerRegistryVulnerabilityAssessment" or properties.additionalData.assessedResourceType == "AcrContainerVulnerability"
| extend severity = tostring(properties.status.severity)
| extend patchable = tobool(properties.additionalData.patchable)
| where severity in ("High", "Critical")
| extend cveId = tostring(properties.id)
| extend imageName = tostring(properties.additionalData.repositoryName)
| extend imageDigest = tostring(properties.additionalData.imageDigest)
| summarize
    VulnCount = dcount(cveId),
    CriticalCount = dcountif(cveId, severity == "Critical"),
    HighCount = dcountif(cveId, severity == "High"),
    PatchableCount = dcountif(cveId, patchable == true)
    by imageName, imageDigest, resourceGroup = tostring(properties.resourceDetails.id)
| where VulnCount > 0
| project
    imageName,
    imageDigest,
    resourceGroup,
    VulnCount,
    CriticalCount,
    HighCount,
    PatchableCount
```

---

## 4 — Storage Accounts Without Network Restrictions

| Field | Value |
|-------|-------|
| **Recommendation name** | `Storage accounts should restrict public network access` |
| **Description** | Storage accounts with unrestricted public network access can be targeted for malicious blob uploads, data exfiltration, and unauthorized access. Network rules should restrict access to specific VNets, private endpoints, or trusted Azure services only. |
| **Severity** | High |
| **Category** | Data |
| **Owner** | Platform Team |
| **Remediation description** | Configure storage account firewall rules to deny public access and allow only selected virtual networks or private endpoints. Set `defaultAction` to `Deny`. Reference: https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security |
| **MITRE Tactics** | Collection, Exfiltration, Lateral Movement |

**KQL Query:**
```kusto
resources
| where type == "microsoft.storage/storageaccounts"
| extend networkDefaultAction = tostring(properties.networkAcls.defaultAction)
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| where networkDefaultAction =~ "Allow" or publicNetworkAccess =~ "Enabled"
| extend privateEndpoints = array_length(properties.privateEndpointConnections)
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    networkDefaultAction,
    publicNetworkAccess,
    privateEndpointCount = iff(isnull(privateEndpoints), 0, privateEndpoints),
    kind = tostring(kind),
    sku = tostring(sku.name)
```

---

## 5 — Key Vaults Without Network Restrictions

| Field | Value |
|-------|-------|
| **Recommendation name** | `Key Vaults should restrict public network access` |
| **Description** | Key Vaults without network restrictions are accessible from any IP, enabling credential theft from TOR exit nodes and anonymous proxies — as demonstrated in the CNAPP assessment where TOR→Key Vault access triggered multiple security incidents. |
| **Severity** | High |
| **Category** | Data |
| **Owner** | Platform Team |
| **Remediation description** | Enable Key Vault firewall, set default action to Deny, and use private endpoints or approved IP ranges. Reference: https://learn.microsoft.com/en-us/azure/key-vault/general/network-security |
| **MITRE Tactics** | Credential Access |

**KQL Query:**
```kusto
resources
| where type == "microsoft.keyvault/vaults"
| extend networkDefaultAction = tostring(properties.networkAcls.defaultAction)
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| where networkDefaultAction =~ "Allow" or publicNetworkAccess =~ "Enabled" or isnull(publicNetworkAccess)
| extend privateEndpoints = array_length(properties.privateEndpointConnections)
| extend softDeleteEnabled = tobool(properties.enableSoftDelete)
| extend purgeProtectionEnabled = tobool(properties.enablePurgeProtection)
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    networkDefaultAction,
    publicNetworkAccess,
    privateEndpointCount = iff(isnull(privateEndpoints), 0, privateEndpoints),
    softDeleteEnabled,
    purgeProtectionEnabled
```

---

## 6 — Azure OpenAI / AI Services Without Defender for AI Enabled

| Field | Value |
|-------|-------|
| **Recommendation name** | `AI Services (Azure OpenAI, AI Foundry) should have Defender for AI enabled` |
| **Description** | AI service endpoints without Defender for AI lack protection against prompt injection / jailbreak attacks, phishing attempts on AI agents, and anomalous access patterns. The CNAPP assessment detected 153 jailbreak attempts and 64 anonymized IP accesses that were caught only because Defender for AI was enabled. |
| **Severity** | High |
| **Category** | AI Security |
| **Owner** | AI / Application Team |
| **Remediation description** | Enable the Defender for AI plan in Defender for Cloud Environment Settings for all subscriptions hosting Azure OpenAI or AI Foundry resources. Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-ai |
| **MITRE Tactics** | Initial Access, Impact |

**KQL Query:**
```kusto
resources
| where type in ("microsoft.cognitiveservices/accounts", "microsoft.machinelearningservices/workspaces")
| extend kind_lower = tolower(kind)
| where kind_lower in ("openai", "aiservices", "") or type == "microsoft.machinelearningservices/workspaces"
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend disableLocalAuth = tobool(properties.disableLocalAuth)
| extend customSubDomain = isnotempty(tostring(properties.customSubDomainName))
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    type,
    kind,
    publicNetworkAccess,
    disableLocalAuth,
    customSubDomain
```

> **Note:** This query identifies all AI resources. Cross-reference with the Defender for Cloud pricing API or `securityresources | where type == "microsoft.security/pricings"` to check if the "AI" plan is enabled on the subscription. Resources in subscriptions without the plan enabled are non-compliant.

---

## 7 — AI Services Allowing Public Network Access Without IP Restrictions

| Field | Value |
|-------|-------|
| **Recommendation name** | `AI Services should not allow unrestricted public network access` |
| **Description** | Azure OpenAI and AI Foundry endpoints with unrestricted public access allow anonymized or adversarial actors to interact with models directly. The assessment found 64 requests from anonymized IPs targeting AI endpoints — network restrictions would have blocked these at the perimeter. |
| **Severity** | Medium |
| **Category** | AI Security |
| **Owner** | AI / Application Team |
| **Remediation description** | Restrict public network access on AI services by configuring network rules with allowed IP ranges or using private endpoints. Disable API key authentication and enforce Entra ID (Managed Identity) auth. Reference: https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks |
| **MITRE Tactics** | Initial Access, Defense Evasion |

**KQL Query:**
```kusto
resources
| where type == "microsoft.cognitiveservices/accounts"
| extend kind_lower = tolower(kind)
| where kind_lower in ("openai", "aiservices")
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend networkDefaultAction = tostring(properties.networkAcls.defaultAction)
| extend ipRuleCount = array_length(properties.networkAcls.ipRules)
| extend vnetRuleCount = array_length(properties.networkAcls.virtualNetworkRules)
| where publicNetworkAccess =~ "Enabled" and (networkDefaultAction =~ "Allow" or isnull(networkDefaultAction))
| extend disableLocalAuth = tobool(properties.disableLocalAuth)
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    kind,
    publicNetworkAccess,
    networkDefaultAction,
    ipRuleCount = iff(isnull(ipRuleCount), 0, ipRuleCount),
    vnetRuleCount = iff(isnull(vnetRuleCount), 0, vnetRuleCount),
    disableLocalAuth
```

---

## 8 — DevOps Repositories Without Branch Protection

| Field | Value |
|-------|-------|
| **Recommendation name** | `Code repositories should enforce branch protection on the default branch` |
| **Description** | Repositories without branch protection allow unreviewed code to reach main/production branches, bypassing code review and automated security scanning gates. The CNAPP assessment found vulnerable dependencies and IaC misconfigurations that reached production because the repository lacked minimum reviewer requirements. |
| **Severity** | Medium |
| **Category** | DevOps |
| **Owner** | Development Team |
| **Remediation description** | Enable branch protection rules on the default branch requiring: minimum 2 reviewers, status checks (code scanning, dependency review), and no force pushes. Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-devops-introduction |
| **MITRE Tactics** | Defense Evasion, Persistence |

**KQL Query:**
```kusto
securityresources
| where type == "microsoft.security/assessments"
| where properties.displayName has "branch protection" or properties.displayName has "repository"
| extend status = tostring(properties.status.code)
| where status == "Unhealthy"
| extend resourceName = tostring(properties.resourceDetails.id)
| extend description = tostring(properties.status.description)
| project
    id,
    assessmentName = tostring(properties.displayName),
    status,
    resourceName,
    description,
    subscriptionId
```

---

## 9 — AKS Clusters Without Defender for Containers Sensor (Runtime Protection)

| Field | Value |
|-------|-------|
| **Recommendation name** | `AKS clusters should have Defender for Containers sensor deployed for runtime protection` |
| **Description** | AKS clusters without the Defender sensor (eBPF-based) lack real-time runtime threat detection. They rely solely on periodic agentless scans, missing real-time attacks like container drift, cryptominer deployment, and metadata service abuse — all demonstrated in the CNAPP assessment. |
| **Severity** | High |
| **Category** | Compute |
| **Owner** | Platform Team |
| **Remediation description** | Enable the Defender sensor on AKS clusters via the Defender for Containers plan. The sensor auto-deploys as a DaemonSet. Verify with `kubectl get pods -n kube-system | grep microsoft-defender`. Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-enable |
| **MITRE Tactics** | Execution, Defense Evasion, Impact |

**KQL Query:**
```kusto
resources
| where type == "microsoft.containerservice/managedclusters"
| extend securityProfile = properties.securityProfile
| extend defenderEnabled = tobool(securityProfile.defender.securityMonitoring.enabled)
| where defenderEnabled != true
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    kubernetesVersion = tostring(properties.kubernetesVersion),
    defenderEnabled,
    provisioningState = tostring(properties.provisioningState)
```

---

## 10 — Cosmos DB Accounts Without Network Restrictions

| Field | Value |
|-------|-------|
| **Recommendation name** | `Cosmos DB accounts should restrict public network access` |
| **Description** | Cosmos DB accounts with public network access enabled and no IP/VNet restrictions allow unauthorized key extraction attempts. Incident #41887 in the CNAPP assessment involved suspicious Cosmos DB account key extraction — network restrictions would limit the attack surface. |
| **Severity** | Medium |
| **Category** | Data |
| **Owner** | Application Team |
| **Remediation description** | Set Cosmos DB `publicNetworkAccess` to `Disabled` and configure private endpoints. If public access is required, set IP firewall rules to allow only known IPs. Reference: https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall |
| **MITRE Tactics** | Credential Access, Collection |

**KQL Query:**
```kusto
resources
| where type == "microsoft.documentdb/databaseaccounts"
| extend publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend ipRangeFilter = tostring(properties.ipRangeFilter)
| extend isVNetFilterEnabled = tobool(properties.isVirtualNetworkFilterEnabled)
| where publicNetworkAccess =~ "Enabled" or isnull(publicNetworkAccess)
| where (isnull(ipRangeFilter) or ipRangeFilter == "") and isVNetFilterEnabled != true
| extend privateEndpoints = array_length(properties.privateEndpointConnections)
| project
    id,
    name,
    resourceGroup,
    subscriptionId,
    location,
    publicNetworkAccess,
    ipRangeFilter,
    isVNetFilterEnabled,
    privateEndpointCount = iff(isnull(privateEndpoints), 0, privateEndpoints),
    databaseAccountOfferType = tostring(properties.databaseAccountOfferType)
```

---

## Quick Reference — All 10 Recommendations

| # | Recommendation | Severity | CNAPP Stage | Primary Gap |
|---|---------------|----------|-------------|-------------|
| 1 | AKS public API server | High | Stage 3 — Infrastructure | Network exposure |
| 2 | AKS outdated Kubernetes | High | Stage 3 — Infrastructure | Patch management |
| 3 | ACR images with high/critical CVEs | High | Stage 2 — Build | Image hygiene |
| 4 | Storage without network restrictions | High | Stage 3/5 — Infra/Runtime | Network exposure |
| 5 | Key Vault without network restrictions | High | Stage 3/5 — Infra/Runtime | Credential protection |
| 6 | AI Services without Defender for AI | High | Stage 5 — Runtime | AI threat protection |
| 7 | AI Services with unrestricted public access | Medium | Stage 5 — Runtime | AI network exposure |
| 8 | Repos without branch protection | Medium | Stage 1 — Code | DevSecOps governance |
| 9 | AKS without Defender sensor | High | Stage 5 — Runtime | Runtime detection gap |
| 10 | Cosmos DB without network restrictions | Medium | Stage 3/5 — Infra/Runtime | Data protection |

---

*Generated from CNAPP Shift-Left Scenario Report — April 12, 2026*
