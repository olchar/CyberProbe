# CyberProbe Scripts

Automation and utility scripts for the CyberProbe platform. All scripts in this folder are PII-free and safe for public use. Subscription IDs and tenant IDs are parameterized — supply your own at runtime.

## Contents

| File / Folder | Description |
|---------------|-------------|
| `check-mcp-health.ps1` | Verifies connectivity to all configured MCP servers (Data Exploration, Triage, Learn, GitHub, Sentinel Graph). Runs automatically on workspace open via VS Code task. |
| `deploy-custom-recommendations.ps1` | Deploys 10 CNAPP custom recommendations + 1 security standard to Microsoft Defender for Cloud via REST API. |
| `deploy-atlas-recommendations.ps1` | Deploys 14 MITRE ATLAS + OWASP Top 10 for LLMs custom recommendations + 2 standards to Defender for Cloud. |
| `deploy-unified-ai-standard.ps1` | Creates a unified AI security standard combining MCSB, AI-SPM, and custom ATLAS/OWASP assessment keys. |
| `ATLAS_OWASP_RECOMMENDATIONS.md` | Full documentation for the ATLAS/OWASP deployment: prerequisites, recommendation reference table, MITRE coverage maps. |
| `custom_recommendations_cnapp_2026-04-12.md` | Portal-based creation guide with KQL queries for 10 CNAPP custom recommendations. |
| `remediation/` | Attack path remediation and Sentinel rule deployment scripts. See [remediation/README.md](remediation/README.md). |

## Defender for Cloud Custom Recommendations

These scripts automate the creation of custom security recommendations and standards in Microsoft Defender for Cloud. They demonstrate how to:

- Define custom recommendations with KQL-based assessment logic
- Group recommendations into security standards
- Map recommendations to MITRE ATT&CK, MITRE ATLAS, and OWASP frameworks
- Deploy via Azure REST API with `-WhatIf` dry-run support

### Quick Start

```powershell
# Deploy 10 CNAPP recommendations + standard
.\scripts\deploy-custom-recommendations.ps1 -SubscriptionId "<your-subscription-id>"

# Deploy 14 MITRE ATLAS + OWASP recommendations + 2 standards
.\scripts\deploy-atlas-recommendations.ps1 -SubscriptionId "<your-subscription-id>"

# Create unified AI security standard (combines MCSB + AI-SPM + custom keys)
.\scripts\deploy-unified-ai-standard.ps1 -SubscriptionId "<your-subscription-id>"

# Dry run (no changes made)
.\scripts\deploy-custom-recommendations.ps1 -SubscriptionId "<your-subscription-id>" -WhatIf
```

### Prerequisites

- Azure CLI (`az`) authenticated with Contributor or Security Admin on the target subscription
- Defender CSPM plan enabled on the subscription
- PowerShell 5.1+

## MCP Health Check

The health check script pings each MCP server endpoint and reports reachability:

```powershell
.\scripts\check-mcp-health.ps1
```

This is also configured as a VS Code task (`Check MCP Server Health`) that runs on folder open. See [../.vscode/tasks.json](../.vscode/tasks.json).

## Remediation Scripts

| Script | Purpose |
|--------|---------|
| `remediation/Remediate-AttackPaths.ps1` | PowerShell remediation for Defender for Cloud choke points (NSG, Key Vault, storage hardening) |
| `remediation/Deploy-SentinelRules.ps1` | Deploy 5 Sentinel analytics rules for attack path monitoring |

See [remediation/README.md](remediation/README.md) for details.

---

**Last Updated:** April 14, 2026
