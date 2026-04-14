# Deploy MITRE ATLAS & OWASP LLM Custom Recommendations

Deploys **14 custom recommendations** and **2 custom security standards** to Microsoft Defender for Cloud, aligned to the **MITRE ATLAS** and **OWASP Top 10 for LLM Applications (2025)** frameworks.

## Quick Start

```powershell
# Preview (dry run)
.\scripts\deploy-atlas-recommendations.ps1 -SubscriptionId "<subscription-id>" -WhatIf

# Deploy
.\scripts\deploy-atlas-recommendations.ps1 -SubscriptionId "<subscription-id>"
```

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Azure CLI | Installed and authenticated (`az login`) |
| RBAC Role | **Contributor** or **Security Admin** on the target subscription |
| Defender CSPM | Standard tier enabled on the subscription |
| PowerShell | 5.1+ (script uses UTF-8 BOM for emoji compatibility) |

## Custom Standards

The script creates two custom security standards, each grouping its respective recommendations:

| Standard | Framework | Recommendations |
|----------|-----------|:-:|
| **MITRE ATLAS — AI/ML Security Posture** | [MITRE ATLAS](https://atlas.mitre.org) | 10 |
| **OWASP Top 10 for LLM Applications — AI Risk Posture** | [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | 4 |

## Recommendations Reference

### Standard 1 — MITRE ATLAS (10 Recommendations)

| # | Severity | Recommendation | ATLAS Technique | Azure Resource Type |
|:-:|----------|---------------|-----------------|---------------------|
| 1 | High | AI Services should disable local authentication (API keys) | AML.T0040 — ML Model Inference API Access | `microsoft.cognitiveservices/accounts` |
| 2 | High | AI Services should not be accessible from the public internet | AML.T0049 — Exploit Public-Facing Application | `microsoft.cognitiveservices/accounts` |
| 3 | Medium | AI Services should use customer-managed keys for encryption | AML.T0045 — ML Artifact Collection | `microsoft.cognitiveservices/accounts` |
| 4 | High | Machine Learning workspaces should restrict public network access | AML.T0046 — Discover ML Artifacts | `microsoft.machinelearningservices/workspaces` |
| 5 | Medium | Machine Learning workspaces should enable high business impact data isolation | AML.T0053 — Data Poisoning | `microsoft.machinelearningservices/workspaces` |
| 6 | High | Storage accounts should enforce HTTPS-only traffic | AML.T0053 — Data Poisoning (in-transit) | `microsoft.storage/storageaccounts` |
| 7 | High | Container registries should disable the admin user account | AML.T0048 — Pre-Trained Model (supply chain) | `microsoft.containerregistry/registries` |
| 8 | High | Key Vaults storing AI model keys should enable purge protection | AML.T0029 — Denial of ML Service | `microsoft.keyvault/vaults` |
| 9 | High | AI Search services should restrict public network access | AML.T0046 — Discover ML Artifacts (RAG) | `microsoft.search/searchservices` |
| 10 | Medium | AI Services should restrict outbound network access | AML.T0024 — Exfiltration via ML Inference API | `microsoft.cognitiveservices/accounts` |

### Standard 2 — OWASP Top 10 for LLM Applications (4 Recommendations)

| # | Severity | Recommendation | OWASP LLM Risk | Azure Resource Type |
|:-:|----------|---------------|----------------|---------------------|
| 11 | High | Azure OpenAI deployments should enable content filtering | LLM01 — Prompt Injection, LLM09 — Misinformation | `microsoft.cognitiveservices/accounts` (kind: OpenAI) |
| 12 | High | AI Services should authenticate using managed identities only | LLM02 — Sensitive Info Disclosure, LLM06 — Excessive Agency | `microsoft.cognitiveservices/accounts` |
| 13 | High | AI Search services should disable API key authentication | LLM08 — Vector & Embedding Weaknesses | `microsoft.search/searchservices` |
| 14 | High | AI Services should enforce TLS 1.2 or higher | LLM03 — Supply Chain, LLM02 — Sensitive Info Disclosure | `microsoft.cognitiveservices/accounts` |

## OWASP LLM Top 10 Coverage Map

Shows how the combined 14 recommendations map to each OWASP LLM risk:

| OWASP LLM Risk | Coverage | Recommendations |
|----------------|:--------:|-----------------|
| **LLM01** Prompt Injection | ✅ | #2 (private network), #10 (outbound restriction), **#11 (content filtering)** |
| **LLM02** Sensitive Information Disclosure | ✅ | #1 (disable API keys), #3 (CMK), #4 (ML private), **#12 (managed identity)**, **#14 (TLS 1.2+)** |
| **LLM03** Supply Chain Vulnerabilities | ✅ | #7 (ACR admin disabled), **#14 (TLS 1.2+)** |
| **LLM04** Data and Model Poisoning | ✅ | #5 (HBI isolation), #6 (HTTPS-only) |
| **LLM05** Improper Output Handling | ❌ | *Runtime/application-layer — not infrastructure-detectable* |
| **LLM06** Excessive Agency | ✅ | #10 (outbound restriction), **#12 (managed identity RBAC)** |
| **LLM07** System Prompt Leakage | ❌ | *Application-layer — no infra config to detect* |
| **LLM08** Vector and Embedding Weaknesses | ✅ | #9 (Search private), **#13 (Search disable API keys)** |
| **LLM09** Misinformation | ✅ | **#11 (content filtering — groundedness detection)** |
| **LLM10** Unbounded Consumption | ⚠️ Partial | #8 (Key Vault purge protection prevents DoS) |

> **LLM05**, **LLM07**, and **LLM10** require runtime/application-level controls (Defender for AI, Azure AI Content Safety, application code) and cannot be fully detected via resource configuration.

## Technical Details

### Idempotency

The script uses **deterministic UUID v5** GUIDs derived from each recommendation's friendly name (e.g., `atlas-ai-disable-local-auth` → `54f4d5c2-5368-5cfa-8b46-4bbc6816232d`). Re-running the script updates existing recommendations in-place without creating duplicates.

### Query Schema

All recommendations use the `RawEntityMetadata` query schema (required by the Defender for Cloud custom recommendations API). Each query follows this pattern:

```kql
RawEntityMetadata
| where Environment == 'Azure' and Identifiers.Type == '<resource-provider/type>'
| extend <property> = <extract from Record>
| extend HealthStatus = iff(<healthy-condition>, 'HEALTHY', 'UNHEALTHY')
| project Id, Name, Environment, Identifiers, AdditionalData, Record, HealthStatus
```

### API

| Resource | API Version | Method |
|----------|:-----------:|:------:|
| `Microsoft.Security/customRecommendations` | `2024-08-01` | PUT |
| `Microsoft.Security/securityStandards` | `2024-08-01` | PUT |

### Key Differences: Recommendations vs Standards

| Property | Recommendations | Standards |
|----------|:-:|:-:|
| Cloud scope field | `supportedClouds` | `cloudProviders` |
| Resource name | GUID (required) | GUID (required) |
| Links to other resources | — | `assessments[].assessmentKey` |

### Portal Visibility

After deployment, recommendations and standards appear in:

- **XDR Portal:** Microsoft Defender XDR → Cloud Security → Security Posture → Security initiatives
- **Azure Portal:** Defender for Cloud → Environment Settings → Security policies → Custom standards
- **Refresh time:** 15–60 minutes for full evaluation

## Related Scripts

| Script | Framework | Description |
|--------|-----------|-------------|
| `deploy-custom-recommendations.ps1` | CNAPP Shift-Left | 10 CNAPP recommendations + 1 standard |
| `deploy-atlas-recommendations.ps1` | ATLAS + OWASP LLM | 14 AI security recommendations + 2 standards |

## References

- [MITRE ATLAS](https://atlas.mitre.org) — Adversarial Threat Landscape for Artificial Intelligence Systems
- [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Custom Recommendations API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/custom-recommendations)
- [Custom Security Standards API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-standards)
- [Defender for Cloud Custom Recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/create-custom-recommendations)

---

**Generated:** April 13, 2026
