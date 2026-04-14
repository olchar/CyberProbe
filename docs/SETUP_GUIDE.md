# CyberProbe Setup Guide

Complete step-by-step instructions to configure CyberProbe from a fresh clone. This guide covers all prerequisites, configuration files, MCP server authentication, and verification tests.

**Estimated Time**: 20–30 minutes

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone and Open in VS Code](#2-clone-and-open-in-vs-code)
3. [Install VS Code Extensions](#3-install-vs-code-extensions)
4. [Azure Authentication](#4-azure-authentication)
5. [Python Environment Setup](#5-python-environment-setup)
6. [API Key Configuration](#6-api-key-configuration)
7. [MCP Server Configuration](#7-mcp-server-configuration)
8. [Build MCP App (Exposure Management)](#8-build-mcp-app-exposure-management)
9. [Verification Tests](#9-verification-tests)
10. [Defender for Cloud Scripts Setup](#10-defender-for-cloud-scripts-setup)
11. [Troubleshooting](#11-troubleshooting)
12. [What's Next](#12-whats-next)

---

## 1. Prerequisites

### Required Software

| Software | Version | Purpose | Install Link |
|----------|---------|---------|-------------|
| **Visual Studio Code** | Latest (Insiders recommended) | IDE + Copilot Chat | [Download](https://code.visualstudio.com/) |
| **Python** | 3.9+ | Enrichment scripts | [Download](https://www.python.org/downloads/) |
| **Node.js** | 18+ | Exposure Management MCP App | [Download](https://nodejs.org/) |
| **Azure CLI** | Latest | Azure authentication + deployment scripts | [Install](https://learn.microsoft.com/cli/azure/install-azure-cli) |
| **PowerShell** | 5.1+ (Windows built-in) | Automation scripts | Pre-installed on Windows |
| **Git** | Latest | Version control | [Download](https://git-scm.com/) |

### Required Azure Services

| Service | License | Purpose |
|---------|---------|---------|
| **Microsoft Defender XDR** | E5 Security or standalone | Incident management, Advanced Hunting |
| **Microsoft Sentinel** | Azure Log Analytics workspace | KQL queries, security analytics |
| **Microsoft Entra ID** | Included with Azure | API authentication, identity data |

### Required Azure Permissions

CyberProbe's MCP servers handle authentication via their own Entra ID service principals. For standard Copilot Chat usage, you need:

| Permission | Where | Why |
|-----------|-------|-----|
| **Security Reader** | Microsoft Defender XDR | Read incidents, alerts, devices |
| **Log Analytics Reader** | Sentinel workspace | Execute KQL queries |
| **Directory Reader** | Entra ID | Read user profiles, sign-in logs |

> **Note:** If MCP servers are unavailable and you need direct API access via terminal, additional Graph API permissions are required. See [XDR Tables & APIs Guide](./XDR_TABLES_AND_APIS.md) Section 6.

### Optional API Keys

These external threat intelligence services enhance IP and IOC enrichment. All have free tiers:

| Service | Free Tier | Signup |
|---------|-----------|--------|
| [AbuseIPDB](https://www.abuseipdb.com/register) | 1,000 requests/day | Required for IP abuse scoring |
| [IPInfo.io](https://ipinfo.io/signup) | 50,000 requests/month | Geolocation + ASN lookup |
| [VPNapi.io](https://vpnapi.io/) | 1,000 requests/month | VPN/proxy/Tor detection |
| [Shodan](https://account.shodan.io/billing) | InternetDB free; full API $59/mo | Open ports, CVEs, service scanning |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | 500 lookups/day | Domain + file hash enrichment |
| [GreyNoise](https://viz.greynoise.io/signup) | 100 requests/day | Internet noise classification |

> You can start with zero API keys — enrichment is optional and gracefully degrades.

---

## 2. Clone and Open in VS Code

```powershell
# Clone the repository
git clone https://github.com/YOUR-USERNAME/CyberProbe.git
cd CyberProbe

# Open in VS Code
code .
```

On first open, VS Code will:
- Prompt to install **recommended extensions** (accept all)
- Run the **MCP Health Check** task automatically (visible in terminal)

---

## 3. Install VS Code Extensions

VS Code should auto-prompt for recommended extensions. If not, install manually:

```powershell
# Required extensions
code --install-extension GitHub.copilot
code --install-extension GitHub.copilot-chat
code --install-extension ms-python.python
code --install-extension ms-vscode.powershell
code --install-extension ms-security.ms-sentinel
code --install-extension ms-toolsai.jupyter
```

### Verify Extensions

Open the Extensions panel (`Ctrl+Shift+X`) and confirm all six are installed:

| Extension | Publisher | Purpose |
|-----------|-----------|---------|
| GitHub Copilot | GitHub | AI code completion |
| GitHub Copilot Chat | GitHub | AI chat panel (runs agent skills) |
| Python | Microsoft | Python language support + virtual environments |
| PowerShell | Microsoft | PowerShell language support + debugging |
| Microsoft Sentinel | Microsoft | Sentinel notebooks, custom graphs, data exploration |
| Jupyter | Microsoft | Notebook execution for custom graph analysis |

---

## 4. Azure Authentication

### Sign In with Azure CLI

```powershell
# Interactive login (opens browser)
az login

# Set your subscription
az account set --subscription "<your-subscription-id>"

# Verify
az account show --query "{name:name, id:id, tenantId:tenantId}" -o table
```

Note down:
- **Subscription ID** — needed for deployment scripts
- **Tenant ID** — needed for `config.json`

### Sign In to VS Code Azure Account

1. Click the **Azure** icon in the VS Code sidebar (or `Ctrl+Shift+P` → "Azure: Sign In")
2. Authenticate with your organizational account
3. This enables MCP servers (Triage, Data Lake, Sentinel Graph) to use your Azure AD credentials

---

## 5. Python Environment Setup

### Option A: Automated Setup (Recommended)

```powershell
.\enrichment\setup-environment.ps1
```

This script:
- Creates a `.venv` virtual environment in the project root
- Installs all Python dependencies from `enrichment/requirements.txt`

### Option B: Manual Setup

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r enrichment/requirements.txt
```

### Verify Python Setup

```powershell
# Should show the venv Python path
.\.venv\Scripts\python.exe --version

# Test config module
.\.venv\Scripts\python.exe enrichment/test_config.py
```

---

## 6. API Key Configuration

### Copy the Template

```powershell
Copy-Item enrichment/config.json.template enrichment/config.json
```

### Edit `enrichment/config.json`

Open the file and replace placeholder values:

```json
{
  "sentinel_workspace_id": "YOUR_SENTINEL_WORKSPACE_GUID",
  "tenant_id": "YOUR_ENTRA_TENANT_GUID",
  "domain": "YOUR_DOMAIN.COM",

  "api_keys": {
    "abuseipdb": "YOUR_ABUSEIPDB_API_KEY",
    "ipinfo": "YOUR_IPINFO_TOKEN",
    "vpnapi": "YOUR_VPNAPI_KEY",
    "shodan": "YOUR_SHODAN_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "greynoise": "YOUR_GREYNOISE_API_KEY"
  },

  "settings": {
    "output_dir": "reports"
  }
}
```

### Where to Find Each Value

| Field | Where to Find |
|-------|--------------|
| `sentinel_workspace_id` | Azure Portal → Log Analytics workspaces → your workspace → **Properties** → Workspace ID |
| `tenant_id` | Azure Portal → **Entra ID** → Overview → Tenant ID (or run `az account show --query tenantId -o tsv`) |
| `domain` | Your organization's primary domain (e.g., `contoso.com` — visible in Entra ID → Overview) |
| `abuseipdb` | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) → Copy API Key |
| `ipinfo` | [ipinfo.io/account/token](https://ipinfo.io/account/token) → Copy Token |
| `vpnapi` | [vpnapi.io/dashboard](https://vpnapi.io/dashboard) → Copy API Key |
| `shodan` | [account.shodan.io](https://account.shodan.io/) → API Key |
| `virustotal` | [virustotal.com/gui/user/apikey](https://www.virustotal.com/gui/user/apikey) → Copy API Key |
| `greynoise` | [viz.greynoise.io/account/api-key](https://viz.greynoise.io/account/api-key) → Copy Key |

> **Security**: `enrichment/config.json` is gitignored and will never be committed. See [enrichment/CONFIG.md](../enrichment/CONFIG.md) for the full field reference including risk scoring weights and optional sources.

### Validate Configuration

```powershell
# Run the config validation script
.\.venv\Scripts\python.exe enrichment/test_config.py
```

Expected output shows which API keys are configured and which are missing (missing keys are warnings, not errors).

---

## 7. MCP Server Configuration

MCP servers are pre-configured in `.vscode/mcp.json`. **No manual edits needed** — authentication flows through your VS Code Azure session.

### Server Overview

| Server | Type | Authentication | Auto-Configured |
|--------|------|---------------|-----------------|
| **Azure** | HTTP | Azure AD (via VS Code) | ✅ |
| **Data Exploration** (Sentinel) | HTTP | Azure AD (via VS Code) | ✅ |
| **Triage** (Defender XDR) | HTTP | Azure AD (via VS Code) | ✅ |
| **Sentinel Graph** | HTTP | Azure AD (via VS Code) | ✅ |
| **Agent Creation** | HTTP | Azure AD (via VS Code) | ✅ |
| **Microsoft Learn** | HTTP | None (public) | ✅ |
| **GitHub** | HTTP | GitHub Copilot license | ✅ |
| **Exposure Management** | Local stdio | None (local) | ✅ (after build) |

### First-Time Sentinel Workspace Selection

When you run your first Sentinel query, CyberProbe will:

1. Call `list_sentinel_workspaces()` to enumerate your available workspaces
2. If you have **one workspace** → auto-selects it
3. If you have **multiple workspaces** → asks you to choose

This selection persists for the conversation session.

### Verify MCP Connectivity

The MCP Health Check task runs automatically on workspace open. You can also run it manually:

```powershell
.\scripts\check-mcp-health.ps1
```

Or test from Copilot Chat:

```
You: "List my Sentinel workspaces"
```

If this returns workspace names and IDs, your MCP connection is working.

---

## 8. Build MCP App (Exposure Management)

The Exposure Management MCP App provides inline visualizations in Copilot Chat. It requires a one-time build:

```powershell
cd mcp-apps/sentinel-exposure-server
npm install
npm run build
cd ../..
```

### Verify Build

```powershell
# Check that the compiled output exists
Test-Path mcp-apps/sentinel-exposure-server/dist/main.js
# Should return: True
```

> **Skip this step** if you don't need exposure management visualizations. The other 7 MCP servers work independently.

---

## 9. Verification Tests

Run these tests in order to confirm your setup is complete.

### Test 1: Python Enrichment

```powershell
# Test with a known Tor exit node
.\enrichment\run-enrichment.ps1 185.220.101.1
```

**Expected**: JSON output with geolocation, abuse score, VPN flags, and Shodan data (depending on configured API keys).

### Test 2: Config Validation

```powershell
.\.venv\Scripts\python.exe enrichment/test_config.py
```

**Expected**: Shows configured sources with ✅ and missing sources with ⚠️.

### Test 3: MCP Server Health

```powershell
.\scripts\check-mcp-health.ps1
```

**Expected**: Each server shows reachability status.

### Test 4: Sentinel Query (via Copilot Chat)

Open Copilot Chat (`Ctrl+Shift+I`) and type:

```
List my Sentinel workspaces
```

**Expected**: Displays workspace name(s) and GUID(s).

### Test 5: Defender XDR Query (via Copilot Chat)

```
Show me the 5 most recent high-severity incidents
```

**Expected**: Displays incident summaries from Defender XDR.

### Test 6: AI-Assisted Investigation (via Copilot Chat)

```
Is 185.220.101.1 malicious?
```

**Expected**: Copilot activates the `threat-enrichment` skill and returns threat intelligence analysis.

---

## 10. Defender for Cloud Scripts Setup

The `scripts/` folder contains PowerShell scripts for deploying custom security recommendations and standards to Microsoft Defender for Cloud. These are optional and require:

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Azure CLI** | Authenticated (`az login`) |
| **Azure Role** | Contributor or Security Admin on the target subscription |
| **Defender CSPM** | Plan enabled on the subscription |

### Available Scripts

| Script | What It Deploys |
|--------|----------------|
| `deploy-custom-recommendations.ps1` | 10 CNAPP custom recommendations + 1 security standard |
| `deploy-atlas-recommendations.ps1` | 14 MITRE ATLAS + OWASP Top 10 for LLMs recommendations + 2 standards |
| `deploy-unified-ai-standard.ps1` | Unified AI standard (MCSB + AI-SPM + custom keys, ~195 assessments) |
| `remediation/Remediate-AttackPaths.ps1` | NSG, Key Vault, storage hardening for choke points |
| `remediation/Deploy-SentinelRules.ps1` | 5 Sentinel analytics rules for attack path monitoring |

### Usage

```powershell
# Dry run (preview changes without deploying)
.\scripts\deploy-custom-recommendations.ps1 -SubscriptionId "<your-sub-id>" -WhatIf

# Deploy CNAPP recommendations
.\scripts\deploy-custom-recommendations.ps1 -SubscriptionId "<your-sub-id>"

# Deploy MITRE ATLAS + OWASP recommendations
.\scripts\deploy-atlas-recommendations.ps1 -SubscriptionId "<your-sub-id>"

# Create unified AI security standard
.\scripts\deploy-unified-ai-standard.ps1 -SubscriptionId "<your-sub-id>"
```

See [`scripts/README.md`](../scripts/README.md) for full documentation.

---

## 11. Troubleshooting

### Authentication Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| "MCP server connection failed" | Azure AD session expired | Run `az login` again, then restart VS Code |
| "AADSTS700016: Application not found" | Wrong Azure AD tenant | Run `az account set --subscription "<correct-sub>"` |
| "403 Forbidden" on API calls | Missing Graph API permissions | See [XDR Tables & APIs](./XDR_TABLES_AND_APIS.md) Section 6 for permission setup |
| MCP queries return empty | Wrong Sentinel workspace selected | In Copilot Chat: "List my Sentinel workspaces" → select the correct one |

### Python Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: No module named 'requests'` | Virtual environment not activated | Run `.\.venv\Scripts\Activate.ps1` first |
| `python: command not found` | Python not on PATH | Install Python and check "Add to PATH" during install |
| `FileNotFoundError: config.json` | Config not created | Run `Copy-Item enrichment/config.json.template enrichment/config.json` |

### MCP App Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Exposure Management tools not available | MCP App not built | Run `cd mcp-apps/sentinel-exposure-server && npm install && npm run build` |
| "Cannot find module dist/main.js" | Build output missing | Run `npm run build` in `mcp-apps/sentinel-exposure-server/` |
| `node: command not found` | Node.js not installed | Install Node.js 18+ from [nodejs.org](https://nodejs.org/) |

### Deployment Script Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| "AuthorizationFailed" | Missing Azure role | Ensure Contributor or Security Admin role on the subscription |
| "InvalidApiVersionParameter" | Old API version | Ensure Azure CLI is up-to-date: `az upgrade` |
| Custom recommendations not visible in portal | Evaluation pending | Wait 15–30 minutes for Defender for Cloud to process new recommendations |

---

## 12. What's Next

Once your environment is set up:

| Goal | Where to Start |
|------|---------------|
| **Learn the platform** | [Lab 101: Getting Started](../labs/101-getting-started/) (30 min) |
| **Run your first investigation** | [Lab 102: Basic Investigations](../labs/102-basic-investigations/) (45 min) |
| **Understand the architecture** | [Investigation Guide](../Investigation-Guide.md) |
| **Explore agent skills** | [Agent Skills Reference](./AGENT_SKILLS.md) |
| **Threat hunting with KQL** | [Lab 104: Threat Hunting](../labs/104-threat-hunting/) (60 min) |
| **Deploy security standards** | [Scripts README](../scripts/README.md) |
| **Build custom MCP visualizations** | [MCP Apps README](../mcp-apps/README.md) |

---

## Quick Reference: File Locations

| File | Purpose | Gitignored? |
|------|---------|-------------|
| `enrichment/config.json` | API keys, workspace ID, tenant ID | ✅ Yes |
| `enrichment/config.json.template` | Template for new users | No — committed |
| `.vscode/mcp.json` | MCP server URLs and types | No — committed |
| `.vscode/extensions.json` | Recommended VS Code extensions | No — committed |
| `.vscode/settings.json` | Copilot and workspace settings | No — committed |
| `reports/` | Generated investigation reports | ✅ Yes |
| `scripts-private/` | Personal/environment-specific scripts | ✅ Yes |
| `.venv/` | Python virtual environment | ✅ Yes |

---

**Last Updated:** April 14, 2026
