# CyberProbe 🔍

**Advanced Security Investigation Platform for Microsoft Defender XDR & Sentinel**

CyberProbe is a comprehensive investigation and threat intelligence platform designed for Security Operations Centers (SOC) using Microsoft Defender XDR and Microsoft Sentinel. It automates incident investigation, enriches indicators of compromise (IOCs) with external threat intelligence, and generates actionable security reports.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Microsoft Defender XDR](https://img.shields.io/badge/Microsoft-Defender%20XDR-0078D4)](https://www.microsoft.com/en-us/security/business/threat-protection/microsoft-365-defender)
[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4)](https://azure.microsoft.com/en-us/products/microsoft-sentinel/)

---

## 🎯 Key Features

### 🔍 **Automated Investigation**
- **Real-time Incident Retrieval**: Connect to Microsoft Defender XDR and Sentinel APIs using MCP (Model Context Protocol) tools
- **Multi-source Threat Intelligence**: Enrich IPs, domains, and file hashes using AbuseIPDB, IPInfo, VPNapi, Shodan, and VirusTotal
- **KQL Query Library**: 40+ pre-built Kusto queries for hunting across Defender/Sentinel data sources
- **Investigation Playbooks**: Pre-configured workflows for ransomware, phishing, insider threats, and compromised identities

### 📊 **Visual Reporting**
- **HTML Investigation Reports**: Dark-themed, interactive reports with geographic IP mapping and country flags
- **SOC Daily Reports**: Automated incident summaries with statistics, trends, and recommendations
- **Threat Relationship Graphs**: SVG-based visualization showing connections between IPs, devices, and threat indicators
- **Power BI Integration**: Automated data export to Power BI for executive dashboards and trend analysis
- **Incident Timeline**: Chronological attack progression with MITRE ATT&CK mapping
- **Enriched Incident Reports**: Multi-incident correlation with IP threat intelligence integration

### 🤖 **Automation & Intelligence**
- **Parallel IP Enrichment**: Multi-threaded processing for high-volume IOC enrichment
- **Automated Severity Scoring**: Risk-based prioritization using abuse confidence scores and threat intelligence
- **Detection Source Categorization**: Automatically organize incidents by Microsoft Defender for Endpoint, Office 365, Cloud Apps, and Sentinel
- **Export to Multiple Formats**: JSON, CSV, Excel, and HTML outputs for integration with SIEM/SOAR platforms
- **AI Agent Skills**: 11 specialized VS Code Copilot skills for automated investigations:
  - **incident-investigation** - Complete 5-phase investigation workflow with parallel query execution
  - **threat-enrichment** - Multi-source IP enrichment (AbuseIPDB, IPInfo, VPNapi, Shodan)
  - **kql-sentinel-queries** - 40+ pre-built KQL queries for Sentinel data lake
  - **kql-query-builder** - Generate, validate, and optimize custom KQL queries with 331+ table schemas
  - **microsoft-learn-docs** - Real-time access to Microsoft Learn for remediation guidance
  - **report-generation** - HTML/JSON/Power BI report templates with MITRE ATT&CK mapping
  - **endpoint-device-investigation** - Device forensics, lateral movement, and vulnerability assessment
  - **incident-correlation-analytics** - Campaign detection, trend analysis, and SOC metrics
  - **ioc-management** - IOC extraction, enrichment, deduplication, and watchlist management
  - **defender-response** - Active containment and remediation via Defender Response MCP
  - **exposure-management** - CTEM metrics, CNAPP posture, attack surface, choke points, and compliance
- **Security Agent Architecture**: Investigation Guide organized following Microsoft's AI Security Agent pattern (Orchestration → Knowledge → Skills → Reference)

---

## 🏗️ Architecture

### Security Agent Architecture

CyberProbe's Investigation Guide follows Microsoft's **"Anatomy of a Security Agent"** pattern:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    SECURITY AGENT ARCHITECTURE                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐          │
│  │  ORCHESTRATION  │ → │    KNOWLEDGE    │ → │     SKILLS      │          │
│  │  (Part I)       │   │   (Part II)     │   │   (Part III)    │          │
│  ├─────────────────┤   ├─────────────────┤   ├─────────────────┤          │
│  │ • Critical Rules│   │ • MCP Data Tools│   │ • Identity      │          │
│  │ • Playbooks     │   │   - Sentinel    │   │   Response      │          │
│  │ • Scenarios     │   │   - Defender XDR│   │ • Endpoint      │          │
│  │ • Decision Flow │   │   - Graph API   │   │   Response      │          │
│  │                 │   │ • 57+ Tools     │   │ • Network       │          │
│  └─────────────────┘   └─────────────────┘   │   Response      │          │
│                                              └─────────────────┘          │
│                        ┌─────────────────┐                                │
│                        │    REFERENCE    │                                │
│                        │   (Part IV)     │                                │
│                        ├─────────────────┤                                │
│                        │ • KQL Queries   │                                │
│                        │ • Templates     │                                │
│                        │ • Best Practices│                                │
│                        └─────────────────┘                                │
└────────────────────────────────────────────────────────────────────────────┘
```

### Platform Components

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         CyberProbe Platform                               │
│                     AI-Assisted Security Investigations                   │
└───────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────┐
│   MCP Servers    │    │  External Threat     │    │   Microsoft      │
│  (Model Context  │    │   Intelligence       │    │   Learn Docs     │
│    Protocol)     │    │                      │    │   (MCP Server)   │
├──────────────────┤    ├──────────────────────┤    ├──────────────────┤
│ 📊 Sentinel      │    │ • AbuseIPDB (IP)     │    │ • Remediation    │
│   • KQL Queries  │    │ • IPInfo (Geo)       │    │   Playbooks      │
│   • Table Search │    │ • VPNapi (VPN/Tor)   │    │ • PowerShell     │
│   • Data Lake    │    │ • Abuse Confidence   │    │   Code Samples   │
│                  │    │ • Risk Scoring       │    │ • KQL Examples   │
│ 👤 Graph API     │    │                      │    │ • Best Practices │
│   • User Profiles│    │                      │    │ • Config Guides  │
│   • Sign-ins     │    │                      │    │                  │
│   • Devices      │    │                      │    │                  │
│   • MFA Status   │    │                      │    │                  │
│                  │    │                      │    │                  │
│ 🛡️ Defender XDR  │    │                      │    │                  │
│   • Incidents    │    │                      │    │                  │
│   • Alerts       │    │                      │    │                  │
│   • Entities     │    │                      │    │                  │
│   • Hunting      │    │                      │    │                  │
└──────────────────┘    └──────────────────────┘    └──────────────────┘
        │                           │                           │
        └───────────────────────────┼───────────────────────────┘
                                    ▼
                    ┌─────────────────────────────────┐
                    │      CyberProbe Core Engine     │
                    ├─────────────────────────────────┤
                    │ • Data Fusion & Correlation     │
                    │ • Multi-Source Enrichment       │
                    │ • Risk Analysis & Scoring       │
                    │ • MITRE ATT&CK Mapping          │
                    │ • SessionId Authentication      │
                    │   Tracing                       │
                    └─────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────┐
│  HTML Reports    │    │   Power BI Datasets  │    │  JSON/CSV/Excel  │
│                  │    │                      │    │     Exports      │
├──────────────────┤    ├──────────────────────┤    ├──────────────────┤
│ • Dark Theme     │    │ • Incidents Table    │    │ • Audit Logs     │
│ • Interactive    │    │ • Alerts Table       │    │ • API Responses  │
│ • Geo IP Maps    │    │ • Entities Table     │    │ • Enrichment Data│
│ • Country Flags  │    │ • Timeline Table     │    │ • Investigation  │
│ • Threat Graphs  │    │ • Risk Metrics       │    │   Packages       │
│ • MITRE ATT&CK   │    │ • Trend Analysis     │    │ • SIEM/SOAR      │
│ • Recommendations│    │ • Executive KPIs     │    │   Integration    │
└──────────────────┘    └──────────────────────┘    └──────────────────┘

                    ┌──────────────────────────────────┐
                    │   AI Agent Skills (VS Code)      │
                    ├──────────────────────────────────┤
                    │  1. incident-investigation       │
                    │  2. threat-enrichment            │
                    │  3. kql-sentinel-queries         │
                    │  4. kql-query-builder            │
                    │  5. microsoft-learn-docs         │
                    │  6. report-generation            │
                    │  7. endpoint-device-investigation│
                    │  8. incident-correlation-analytics│
                    │  9. ioc-management               │
                    │ 10. defender-response            │
                    │ 11. exposure-management          │
                    └──────────────────────────────────┘
```

---

## 🎓 Hands-On Training Labs

**New to CyberProbe?** Start with our comprehensive lab series!

### [📚 CyberProbe Labs & Workshops](./labs/)

**100-Series: Fundamentals**
- [Lab 101: Getting Started](./labs/101-getting-started/) - Environment setup & first investigation (30 min)
- [Lab 102: Basic Investigations](./labs/102-basic-investigations/) - User security investigations (45 min)
- [Lab 103: Advanced Authentication Analysis](./labs/103-advanced-auth-analysis/) - SessionId tracing (60 min)
- [Lab 104: Threat Hunting](./labs/104-threat-hunting/) - Hunt for threats across Defender XDR (60 min)
- [Lab 105: Incident Response](./labs/105-incident-response/) - Structured IR workflows (45 min)
- [Lab 106: MCP Automation](./labs/106-automation-mcp/) - AI-assisted investigations (60 min)

**200-Series: Real-World Scenarios**
- [Lab 201: Phishing Campaign](./labs/201-phishing-investigation/) - Investigate credential theft & data exfiltration (90 min)
- [Lab 202: Compromised Identity](./labs/202-compromised-identity/) - SessionId forensics & remediation (90 min)
- [Lab 203: Insider Threat](./labs/203-insider-threat/) - Behavioral analysis techniques (90 min)
- [Lab 204: DLP Exfiltration](./labs/204-dlp-exfiltration/) - Track data loss prevention violations (90 min)

**Quick Links**:
- 📖 [Lab Index](./labs/README.md) - Full lab catalog
- 🚀 [Quick Reference](./labs/QUICK_REFERENCE.md) - Common investigation patterns
- 📋 [Investigation Guide](./Investigation-Guide.md) - Security Agent Architecture Guide (Orchestration → Knowledge → Skills → Reference)

---

## 📋 Prerequisites

### Required Services
- **Microsoft Defender XDR** (E5 Security license or standalone)
- **Microsoft Sentinel** (Azure workspace with data connectors configured)
- **Microsoft Entra ID** (for API authentication)

### MCP Server Access (Default — No Extra Setup)

CyberProbe's MCP servers (Triage, Data Lake, Defender Response) authenticate using their own Entra ID service principal with pre-configured security permissions. **No additional permission setup is required** for MCP-based investigations via VS Code Copilot.

### Direct API Access (Optional — For Terminal Fallback)

If MCP servers are unavailable and you need to fall back to direct REST API calls (`az rest`, `Invoke-RestMethod`), the calling app must have Microsoft Graph permissions granted with admin consent:

| API Scope | Permission | Required For |
|-----------|-----------|--------------|
| `ThreatHunting.Read.All` | Advanced Hunting queries | KQL via `/security/runHuntingQuery` |
| `SecurityIncident.ReadWrite.All` | Incident management | List/update incidents |
| `SecurityAlert.ReadWrite.All` | Alert management | List/update alerts |
| `Machine.Read.All` | Device queries | Device inventory, vulnerabilities |

> **Note:** The Azure CLI's default app registration does NOT include these security-specific scopes. See [XDR Tables & APIs Guide](./docs/XDR_TABLES_AND_APIS.md) Section 6 for setup instructions.

### Development Environment
- **Python 3.9+** (tested with Python 3.14.1)
- **PowerShell 5.1+** (for Windows automation)
- **Visual Studio Code** (recommended with Pylance extension)

### API Keys (Optional but Recommended)
- [AbuseIPDB API Key](https://www.abuseipdb.com/api) - IP reputation scoring
- [IPInfo.io Token](https://ipinfo.io/signup) - IP geolocation and ASN lookup
- [VPNapi.io Key](https://vpnapi.io/) - VPN/proxy detection
- [Shodan API Key](https://account.shodan.io/billing) - Open ports, CVEs, service scanning (free InternetDB fallback available)
- [VirusTotal API Key](https://www.virustotal.com/gui/join-us) - Domain and file hash enrichment (free tier: 500 lookups/day)

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/CyberProbe.git
cd CyberProbe
```

### 2. Set Up Python Environment

**Option A: Automated Setup (Recommended)**
```powershell
# Run the setup script
.\setup-environment.ps1
```

**Option B: Manual Setup**
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r enrichment/requirements.txt
```

### 3. Configure API Credentials

Copy the template and fill in your keys:

```powershell
Copy-Item enrichment/config.json.template enrichment/config.json
```

Edit `enrichment/config.json`:

```json
{
  "tenant_id": "YOUR-AZURE-TENANT-ID",
  "sentinel_workspace_id": "YOUR-SENTINEL-WORKSPACE-ID",
  "api_keys": {
    "abuseipdb": "YOUR-ABUSEIPDB-KEY",
    "ipinfo": "YOUR-IPINFO-TOKEN",
    "vpnapi": "YOUR-VPNAPI-KEY",
    "shodan": "YOUR-SHODAN-KEY",
    "virustotal": "YOUR-VIRUSTOTAL-KEY"
  },
  "settings": {
    "output_dir": "reports"
  }
}
```

### 4. Run Your First Investigation

**Easy Way - No Virtual Environment Activation Needed:**
```powershell
# Enrich suspicious IP addresses
.\run-enrichment.ps1 109.70.100.7 176.65.134.8
```

**Traditional Way (requires venv activation):**
```powershell
.\.venv\Scripts\Activate.ps1
cd enrichment
python enrich_ips.py 109.70.100.7 176.65.134.8
```

---

## 📁 Project Structure

```
CyberProbe/
├── .github/                     # GitHub-specific configuration
│   ├── copilot-instructions.md  # AI agent routing (auto-loaded by Copilot)
│   └── skills/                  # VS Code Agent Skills for AI-assisted investigations
│       ├── incident-investigation/       # 5-phase investigation workflow
│       ├── threat-enrichment/            # Multi-source IP enrichment
│       ├── kql-sentinel-queries/         # Pre-built KQL query library
│       ├── kql-query-builder/            # Custom KQL generation & validation
│       ├── microsoft-learn-docs/         # Official Microsoft documentation access
│       ├── report-generation/            # Report generation templates
│       ├── endpoint-device-investigation/# Device forensics & vulnerability analysis
│       ├── incident-correlation-analytics/# Campaign detection & SOC metrics
│       ├── ioc-management/               # IOC extraction & watchlist management
│       ├── defender-response/            # Active containment & remediation actions
│       └── exposure-management/          # CTEM metrics, CNAPP posture & compliance
├── cyberprobe-mcp-apps/         # MCP Apps server — inline UI in VS Code Copilot
│   ├── src/tools/              # Tool implementations
│   │   ├── analyze-ips.ts      # 🌐 IP Threat Map (interactive Leaflet map)
│   │   ├── entity-explorer.ts  # 🔍 Entity Explorer (filterable entity list)
│   │   ├── response-actions.ts # ⚡ Response Actions Console (isolation, AV, forensics)
│   │   └── security-posture.ts # 📊 Security Posture Dashboard (VM inventory, compliance)
│   └── package.json            # MCP Apps server configuration
├── enrichment/                  # Core enrichment and automation scripts
│   ├── enrich_ips.py           # Multi-source IP threat intelligence (AbuseIPDB, IPInfo, VPNapi, Shodan)
│   ├── enrich_iocs.py          # Domain & file hash enrichment (VirusTotal)
│   ├── powerbi_data_export.py  # Power BI dataset generator
│   ├── config.json             # API keys and configuration (gitignored)
│   └── config.json.template    # Configuration template for onboarding
├── reports/                     # Generated investigation reports
│   ├── incident_report_*.html  # Interactive HTML reports
│   ├── investigation_graph_*.html
│   ├── ip_enrichment_*.json    # Raw enrichment data
│   └── powerbi_*.xlsx          # Power BI datasets
├── docs/                        # Documentation
│   ├── AGENT_SKILLS.md         # Complete Agent Skills documentation
│   ├── EXPOSURE_MANAGEMENT.md  # Exposure management & CTEM reference
│   ├── USER_GUIDE.md           # End-to-end user guide (with HTML version)
│   ├── XDR_TABLES_AND_APIS.md  # XDR table schemas, APIs & fallback patterns
│   └── POWERBI_SETUP.md        # Power BI integration guide
├── queries/                     # Verified KQL query library
│   ├── identity/               # Entra ID / Azure AD queries
│   ├── endpoint/               # Defender for Endpoint queries
│   ├── email/                  # Defender for Office 365 queries
│   ├── network/                # Network telemetry queries
│   └── cloud/                  # Cloud apps & exposure queries
├── Investigation-Guide.md       # Human-readable investigation manual (4 Parts):
│                                #   Part I: Orchestration (rules, playbooks, scenarios)
│                                #   Part II: Knowledge (50+ MCP data tools)
│                                #   Part III: Skills (response actions)
│                                #   Part IV: Reference (KQL queries, templates)
└── README.md                    # This file
```

---

## 📖 Usage Examples

### IP Enrichment with Threat Intelligence

```powershell
# Enrich a single IP address
python enrichment/enrich_ips.py 206.168.34.210

# Output:
# IP Address        | City      | Country | ISP/Org          | Flags
# 206.168.34.210    | Chicago   | US      | Censys, Inc.     | Abuse:100%, Reports:1363
```

### Domain & File Hash Enrichment (VirusTotal) 🆕

```powershell
# Enrich a domain
python enrichment/enrich_iocs.py --domain malicious-site.example.com

# Enrich a file hash (SHA-256)
python enrichment/enrich_iocs.py --hash d97e1c9dea13f7a213e8c2687bf2f0c162a48657fd3d494112e370d6d71a893c

# Output saved to: reports/ioc_enrichment_YYYYMMDD_HHMMSS.json
```

### Query Sentinel for Security Incidents

Using the MCP Sentinel tools (configured in VS Code):

```python
# List today's high-severity incidents
mcp_triage_ListIncidents(
    createdAfter="2026-01-14T00:00:00Z",
    severity="High",
    includeAlertsData=true
)

# Search for specific threats using KQL
mcp_microsoft_sen_query_lake(
    query="""
    DeviceNetworkEvents
    | where RemoteIP == "206.168.34.210"
    | where TimeGenerated > ago(7d)
    | project TimeGenerated, DeviceName, RemoteIP, RemotePort, ActionType
    | order by TimeGenerated desc
    """
)
```

### Generate Power BI Dataset

```powershell
# Export last 30 days of incidents for Power BI
python enrichment/powerbi_data_export.py --days 30 --format excel

# Output: reports/powerbi_dataset_TIMESTAMP.xlsx
# Contains: incidents, alerts, entities tables
```

### Investigation Playbooks

The platform includes pre-built playbooks for common scenarios:

**Ransomware Investigation:**
1. Identify patient zero device
2. Map lateral movement using KQL queries
3. Extract file hashes and C2 IPs
4. Enrich IOCs with threat intelligence
5. Generate containment report

**Phishing Campaign Analysis:**
1. Query Office 365 for malicious emails
2. Identify affected users and click-through rates
3. Extract URLs and attachment hashes
4. Correlate with Azure AD sign-in events
5. Generate remediation actions

See [Investigation-Guide.md Part I: Orchestration](Investigation-Guide.md#part-i-orchestration) for detailed playbooks.

---

## 🎨 Report Examples

### HTML Investigation Report
- **Dark theme optimized for SOC operations**
- **Geographic IP distribution with country flags**
- **Incident categorization by detection source**
- **MITRE ATT&CK technique mapping**
- **Threat intelligence scoring (0-100% abuse confidence)**

### Interactive Threat Graph
- **SVG-based relationship visualization**
- **Tiered layout: Critical → VPN → Suspicious IPs**
- **Hover tooltips with detailed threat intelligence**
- **Device and user entity connections**

### Power BI Dashboard
- **Executive KPIs: Total incidents, MTTR, severity distribution**
- **Trend analysis: Incident volume over time**
- **Threat analysis: MITRE ATT&CK coverage, top affected users/devices**
- **Performance metrics: Analyst workload, resolution rates**

---

## 🔧 Configuration

### Model Context Protocol (MCP) Servers

CyberProbe leverages **six MCP servers** for comprehensive security investigations:

#### 1️⃣ Microsoft Sentinel MCP Server

**Purpose**: KQL query execution and data lake access

**Configuration**:
1. Install MCP extension for Sentinel in VS Code
2. Authenticate with Azure AD (Security Reader role minimum)
3. Set workspace ID in `enrichment/config.json`

**Available Tools**:
- **mcp_microsoft_sen_query_lake** - Execute KQL queries on Sentinel data lake
  ```python
  # Example: Query sign-in logs
  mcp_microsoft_sen_query_lake(
      query="SigninLogs | where TimeGenerated > ago(7d) | take 10"
  )
  ```

- **mcp_microsoft_sen_search_tables** - Discover relevant tables for investigations
  ```python
  # Example: Find tables related to authentication
  mcp_microsoft_sen_search_tables(query="user authentication sign-in")
  ```

- **mcp_data_explorat_list_sentinel_workspaces** - List available workspaces

**Data Access**:
- SigninLogs, AuditLogs, CloudAppEvents (Azure AD/Entra ID)
- SecurityAlert, SecurityIncident (Correlated threats)
- DeviceEvents, DeviceNetworkEvents, DeviceProcessEvents (Defender for Endpoint)
- EmailEvents, EmailUrlInfo, EmailAttachmentInfo (Defender for Office 365)
- IdentityLogonEvents, IdentityQueryEvents (Defender for Identity)

**Performance**: Supports parallel queries for 60-70 second investigation phase

---

#### 2️⃣ Sentinel Graph MCP Server

**Purpose**: Identity data, attack path analysis, and blast radius investigation

**Configuration**:
- Configured in `.vscode/mcp.json` as "Sentinel Graph"
- URL: `https://sentinel.microsoft.com/mcp/graph`
- Requires Sentinel data lake access + Security Reader permission
- Uses delegated authentication (your Azure AD account)

**Graph API CRUD Tools (4 tools)**:
- **mcp_microsoft_mcp_microsoft_graph_get** - GET requests to Microsoft Graph API
- **mcp_microsoft_mcp_microsoft_graph_post** - POST requests (e.g., revoke sessions)
- **mcp_microsoft_mcp_microsoft_graph_patch** - PATCH requests (e.g., disable account)
- **mcp_microsoft_mcp_microsoft_graph_delete** - DELETE requests

**Purpose-Built Graph Investigation Tools (3 tools) 🆕**:

| Tool | Description | Example Prompt |
|------|-------------|----------------|
| **graph_exposure_perimeter** | Find how accessible a node is from entry points | "What is the exposure perimeter of my critical SQL servers?" |
| **graph_find_blastRadius** | Evaluate potential impact if a node is compromised | "What is the blast radius from user 'Laura Hanak'?" |
| **graph_find_walkable_paths** | Find attack paths between source and target (up to 4 hops) | "Is there a path from user Mark to key vault wg-prod?" |

**Natural Language Investigation Examples**:
```
"What is the blast radius of user Sam?"
"Which virtual machines have the highest exposure perimeter?"
"How can an attacker reach my domain controller from a compromised workstation?"
"Who can all get to wg-prod key vault?"

# Advanced investigation
"If I want to minimize the blast radius for this user, what are the most common 
walkable paths? I'm looking for strategies where a single mitigation can cover 
multiple paths."
```

**Supported 1P Graphs**:
- Exposure/Hunting Graph - Attack surface and threat hunting
- DSI Graph - Device Security Information
- IRM Graph - Identity Risk Management
- TI Graph - Threat Intelligence

**Use Cases**:
- **Blast Radius Analysis** - Identify impact of compromised accounts
- **Attack Path Discovery** - Find lateral movement paths to critical assets
- **Exposure Assessment** - Identify most vulnerable/accessible nodes
- **Identity Investigation** - User profiles, MFA, risk detections

---

#### 3️⃣ Microsoft Learn MCP Server 🆕

**Purpose**: Access official Microsoft security documentation and remediation guidance

**Configuration**:
- ✅ **No API keys required** - Microsoft Learn is publicly accessible
- ✅ **Pre-configured in VS Code Copilot** - No setup needed
- ✅ **Always current** - Reflects latest Microsoft security features

**Available Tools**:
- **mcp_microsoft_lea_microsoft_docs_search** - Search official documentation
  ```python
  # Example: Find OAuth revocation procedures
  mcp_microsoft_lea_microsoft_docs_search(
      query="revoke malicious OAuth application Entra ID remediation"
  )
  # Returns: Up to 10 documentation articles with URLs and excerpts
  ```

- **mcp_microsoft_lea_microsoft_code_sample_search** - Get production-ready code
  ```python
  # Example: Get PowerShell cmdlets for user remediation
  mcp_microsoft_lea_microsoft_code_sample_search(
      query="disable user account and revoke sessions Entra ID",
      language="powershell"
  )
  # Returns: Official Microsoft.Graph PowerShell commands
  ```

- **mcp_microsoft_lea_microsoft_docs_fetch** - Retrieve full documentation pages
  ```python
  # Example: Get complete investigation playbook
  mcp_microsoft_lea_microsoft_docs_fetch(
      url="https://learn.microsoft.com/en-us/defender-xdr/investigate-users"
  )
  # Returns: Full page content in markdown format
  ```

**Supported Languages for Code Samples**:
- PowerShell (Microsoft.Graph, Az, ExchangeOnlineManagement)
- KQL/Kusto (Sentinel, Advanced Hunting)
- Python (Microsoft Graph API, Azure SDK)
- C#, JavaScript/TypeScript (Microsoft Graph SDK)
- Azure CLI, Bash, REST API

**Use Cases**:
- **During Active Incidents**: Get remediation procedures in seconds vs 15-20 min Googling
- **OAuth Attacks**: Find official revocation steps and PowerShell cmdlets
- **TOR/VPN Detection**: Get Conditional Access configuration code
- **Compromised Users**: Access Microsoft's 8-step investigation checklist
- **Report Documentation**: Include Microsoft Learn URLs for audit compliance

**Benefits**:
- ✅ 30-90x faster than manual documentation searches
- ✅ Official Microsoft procedures (not Stack Overflow guesses)
- ✅ Production-tested code samples
- ✅ Always reflects latest security features and best practices
- ✅ Authoritative citations for compliance reporting

**Integration with CyberProbe**:
The `microsoft-learn-docs` Agent Skill automatically activates during investigations:
- Detects OAuth apps → Searches for revocation procedures
- Detects TOR IPs → Finds Conditional Access blocking guidance
- Detects impossible travel → Retrieves compromised user playbooks
- Includes official Microsoft Learn URLs in generated reports

See [Investigation-Guide.md Part II](Investigation-Guide.md#part-ii-knowledge-mcp-tools) for complete MCP documentation.

---

#### 4️⃣ KQL Search MCP Server 🆕

**Purpose**: Generate, validate, and optimize KQL queries with schema intelligence

**Configuration**:
- ✅ **Automatically configured** in VS Code Copilot
- ✅ **GitHub Token Required**: Create at https://github.com/settings/tokens (public_repo scope)
- ✅ **331+ Table Schemas**: Built-in validation for Defender XDR, Sentinel, Azure Monitor

**Available Tools** (34 tools available):

**Query Generation & Validation (5 tools)**:
- **kql_generate_kql_query** - Generate validated KQL from natural language
  ```python
  # Example: Create query for failed logins
  kql_generate_kql_query(
      description="Show all failed sign-ins from the last 24 hours with IP and location",
      time_range="24h"
  )
  # Returns: Validated query with schema checking + Microsoft Learn docs
  ```

- **kql_validate_kql_query** - Validate existing queries for correctness
  ```python
  # Example: Check query for performance issues
  kql_validate_kql_query(
      query="SigninLogs | where ResultType != 0 | project UserPrincipalName"
  )
  # Returns: Errors, warnings (missing time filter!), fix suggestions
  ```

- **kql_generate_query_template** - Get ready-to-use templates for specific tables

**Schema Intelligence (8 tools)**:
- **kql_get_table_schema** - Get complete schema for 331+ tables
- **kql_search_tables** - Find tables using natural language ("where can I find failed logins?")
- **kql_find_column** - Discover which tables contain specific columns

**GitHub Community Search (8 tools)**:
- **kql_search_kql_queries** - Search ALL GitHub for detection rules and hunting queries
  ```python
  # Example: Find community brute force detections
  kql_search_kql_queries(
      query="brute force multiple failed login attempts",
      max_results=10
  )
  # Returns: KQL queries from Azure/Azure-Sentinel, Microsoft repos, community
  ```

- **kql_search_repo_kql_queries** - Search within specific repo (Azure/Azure-Sentinel)
- **kql_search_favorite_repos** - Search your configured favorite repositories

**ASIM Normalization (13 tools)**:
- **kql_generate_asim_query_template** - Create normalized multi-source queries
- **kql_validate_asim_parser** - Validate parser against schema requirements
- **kql_list_asim_schemas** - Browse 11 ASIM schemas (Authentication, Network, File, etc.)

**Schema Coverage**:
- ✅ **331+ tables** validated (SigninLogs, DeviceEvents, EmailEvents, etc.)
- ✅ **11 ASIM schemas** for normalized security queries
- ✅ **57 table categories** for discovery
- ✅ **GitHub search** across 1000s of public detection rules

**Use Cases**:
- **Custom Query Generation**: "Create query for impossible travel detection"
- **Sentinel Analytic Rules**: Generate complete YAML with MITRE ATT&CK mapping
- **Query Optimization**: Validate and fix slow queries before execution
- **ASIM Multi-Source**: Build queries that work across Azure AD, AWS IAM, Okta, Active Directory
- **Community Patterns**: Search GitHub for proven detection rules

**Benefits**:
- ✅ Schema-validated queries (no runtime errors)
- ✅ Automatic performance optimization suggestions
- ✅ Access to community detection patterns
- ✅ ASIM normalization for multi-cloud environments
- ✅ Sentinel Analytic Rule generation in seconds

**Integration with CyberProbe**:
The `kql-query-builder` Agent Skill automatically activates when:
- User requests custom queries not in sample library
- Building new Sentinel detection rules
- Need ASIM-normalized queries for multi-source correlation
- Optimizing existing queries for performance

See [.github/skills/kql-query-builder/SKILL.md](.github/skills/kql-query-builder/SKILL.md) for complete documentation.

---

#### 5️⃣ Microsoft Defender XDR MCP Server (Triage)

**Purpose**: Direct access to Defender XDR incidents, alerts, and entities for investigation and response

**Configuration**:
- ✅ **Automatically configured** in VS Code Copilot
- ✅ **Azure AD authentication** with Security Reader role minimum
- ✅ **27+ investigation tools** for comprehensive endpoint and identity analysis

**Available Tools (27 tools)**:

**Incident Management (3 tools)**:
- **mcp_triage_ListIncidents** - List incidents with filtering by severity, status, time range
- **mcp_triage_GetIncidentById** - Get detailed incident with alerts and entities
- **mcp_triage_ListAlerts** - List all alerts with severity filtering

**Advanced Hunting (2 tools)**:
- **mcp_triage_RunAdvancedHuntingQuery** - Execute KQL queries in Defender XDR
- **mcp_triage_FetchAdvancedHuntingTablesOverview** - Get table schemas for hunting

**Device Investigation (8 tools)**:
- **mcp_triage_GetDefenderMachine** - Get device details, health, risk level
- **mcp_triage_GetDefenderMachineAlerts** - Alerts affecting specific device
- **mcp_triage_GetDefenderMachineLoggedOnUsers** - Users logged onto device
- **mcp_triage_GetDefenderMachineVulnerabilities** - CVEs on device
- **mcp_triage_ListDefenderMachinesByVulnerability** - Find all devices with specific CVE
- **mcp_triage_FindDefenderMachinesByIp** - Locate devices by IP address

**File Analysis (4 tools)**:
- **mcp_triage_GetDefenderFileInfo** - File metadata and prevalence
- **mcp_triage_GetDefenderFileStatistics** - Global/org file statistics
- **mcp_triage_GetDefenderFileAlerts** - Alerts related to file hash
- **mcp_triage_GetDefenderFileRelatedMachines** - Devices where file was seen

**User Investigation (2 tools)**:
- **mcp_triage_ListUserRelatedAlerts** - Alerts associated with user
- **mcp_triage_ListUserRelatedMachines** - Devices used by user

**Network Analysis (2 tools)**:
- **mcp_triage_GetDefenderIpAlerts** - Alerts related to IP address
- **mcp_triage_GetDefenderIpStatistics** - IP statistics and prevalence

**Threat Intelligence (4 tools)**:
- **mcp_triage_ListDefenderIndicators** - Custom TI indicators
- **mcp_triage_GetDefenderInvestigation** - Get investigation status
- **mcp_triage_ListDefenderInvestigations** - List automated investigations
- **mcp_triage_ListDefenderVulnerabilitiesBySoftware** - CVEs by software

**Use Cases**:
- **Incident Triage**: Get incident details, severity, affected entities
- **Device Forensics**: Investigate endpoints, logged users, vulnerabilities
- **File Hunting**: Track malicious files across organization
- **Lateral Movement**: Follow attacker path through devices and users
- **Threat Hunting**: Execute KQL queries in Defender XDR environment

See [Investigation-Guide.md Part II: Knowledge](Investigation-Guide.md#10-defender-xdr-triage-mcp-server) for complete tool documentation.

---

#### 6️⃣ Agent Creation MCP Server

**Purpose**: Create custom AI security agents for specialized investigation workflows

**Configuration**:
- ✅ **Automatically configured** in VS Code Copilot
- ✅ **Azure AD authentication**
- ✅ **5 tools** for agent lifecycle management

**Available Tools**:
- **mcp_agent_creatio_start_agent_creation** - Initialize new agent configuration
- **mcp_agent_creatio_compose_agent** - Build agent with skills and knowledge
- **mcp_agent_creatio_deploy_agent** - Deploy agent to target environment
- **mcp_agent_creatio_search_for_tools** - Find available tools for agent
- **mcp_agent_creatio_get_evaluation** - Evaluate agent performance

**Use Cases**:
- Create specialized SOC automation agents
- Build custom investigation workflows
- Deploy threat-specific detection agents
- Evaluate agent effectiveness

---

#### 7️⃣ Microsoft Sentinel Custom Graphs (VS Code Extension) 🆕

**Purpose**: Create visual graph representations of security data for advanced investigation and analysis

**Configuration**:
- ✅ **Requires Microsoft Sentinel VS Code extension** (Pre-Release version during preview)
- ✅ **Onboard to Microsoft Sentinel data lake** required
- ✅ **Uses Jupyter notebooks** with Spark compute pools

**Key Technologies**:
- **MicrosoftSentinelProvider** - Read directly from Sentinel data lake tables
- **GraphSpecBuilder** - Build custom graph specifications with nodes and edges
- **GQL (Graph Query Language)** - Pattern-matching queries for graph traversal

**Required Permissions**:
| Operation | Permission |
|-----------|------------|
| Create/query ephemeral graph | XDR data (manage) permissions |
| Materialize graph in tenant | Security Administrator or Global Administrator |
| Query materialized graph | XDR security data basics (read) |

**Sample GQL Queries**:
```gql
-- Find all users in a department and their app relationships
MATCH (n:Users)-[e]->(s) 
WHERE n.department = 'Security Operations' 
RETURN * LIMIT 50

-- Investigate sign-in patterns
MATCH (u:user)-[s:sign_in]->(d:device) 
RETURN u, s, d LIMIT 10
```

**Investigation Use Cases**:
- **Blast Radius Analysis** - Visualize all entities affected by a compromised account
- **Lateral Movement Detection** - Graph user-to-device-to-app relationships
- **Application Access Mapping** - Visualize which users access which applications
- **Department Risk Assessment** - Map access patterns by organizational structure

See [Investigation-Guide.md Part II](Investigation-Guide.md#microsoft-sentinel-custom-graphs-vs-code-extension) for complete documentation.

---

#### 8️⃣ CyberProbe MCP Apps Server 🆕

**Purpose**: Interactive security investigation UIs rendered inline in VS Code Copilot chat

**Configuration**:
- ✅ **Local MCP server** — runs from `cyberprobe-mcp-apps/` directory
- ✅ **Implements MCP Apps spec** (2026-01-26) for bidirectional Copilot↔UI communication
- ✅ **Vite-bundled single-file HTML** — no external dependencies at runtime

**Available Tools (4 interactive apps)**:

| App | Tool | Description |
|-----|------|-------------|
| 🌐 IP Threat Map | `analyze_ip_threats` | Interactive Leaflet map with color-coded threat severity markers. Click IPs for abuse reports, filter by risk level. |
| 🔍 Entity Explorer | `explore_entities` | Filterable entity list (IPs, users, devices, alerts). Search, sort, and drill-down with severity tagging. |
| ⚡ Response Actions Console | `response_actions_console` | Device isolation, identity containment, AV scans, forensic package collection — all from inline UI. |
| 📊 Security Posture Dashboard | `security_posture_dashboard` | VM inventory, cost analysis, AV compliance status, attack path visualization. |

**Use Cases**:
- **Visual Triage**: See geographic distribution of threat IPs on a live map during incident analysis
- **Entity Drill-down**: Interactively explore all entities extracted from an investigation
- **One-click Response**: Isolate devices, quarantine files, or disable users without leaving Copilot chat
- **Posture Overview**: Get real-time VM security posture with compliance metrics

**Integration with CyberProbe**:
MCP Apps tools are auto-triggered when Copilot detects relevant investigation context (e.g., enriched IP data, entity lists). The apps render directly in the chat panel — no browser popups.

See [cyberprobe-mcp-apps/README.md](cyberprobe-mcp-apps/README.md) for setup and development guide.

---

### MCP Server Comparison

| MCP Server | Purpose | Tools | Authentication | Key Use Cases |
|------------|---------|-------|----------------|---------------|
| **Data Exploration** | KQL queries, data lake | 6 | Azure AD (Security Reader) | Sign-in logs, audit logs, device events |
| **Sentinel Graph** | Identity + Attack Paths | 7 | Azure AD (delegated) | Blast radius, exposure perimeter, walkable paths |
| **Microsoft Learn** | Documentation & code | 3 | None (public) | Remediation guidance, PowerShell cmdlets |
| **Triage** | Defender XDR | 27 | Azure AD (Security Reader) | Incidents, devices, files, threat hunting |
| **Agent Creation** | Custom AI agents | 5 | Azure AD | SOC automation, specialized workflows |
| **GitHub** | Code search, repos | 5+ | GitHub Token | Detection rules, community patterns |
| **CyberProbe MCP Apps** | Interactive inline UIs | 4 | Local | IP maps, entity explorer, response console, posture |

**Total MCP Tools: 57+**

**Purpose-Built Graph Investigation Tools (NEW):**
| Tool | Use Case |
|------|----------|
| `graph_exposure_perimeter` | Identify most exposed assets |
| `graph_find_blastRadius` | Evaluate compromise impact |
| `graph_find_walkable_paths` | Find attack paths |

**Additional VS Code Extension Capabilities:**
| Feature | Technology | Use Case |
|---------|------------|----------|
| **Custom Graphs** | Jupyter + Spark + GQL | Visual graph analysis, custom relationship mapping |

**Workflow Integration Example**:
```
Investigation Request: "Investigate suspicious.user@contoso.com"
                                ↓
1. Graph API: Get user profile, Azure AD Object ID, MFA status
2. Blast Radius: "What is the blast radius of suspicious.user?" 🆕
3. Attack Paths: "What paths exist from this user to critical assets?" 🆕
4. Defender XDR: Get related incidents, alerts, and affected devices
5. Sentinel: Query SigninLogs, AuditLogs for 7-day activity
6. External TI: Enrich IPs with AbuseIPDB, IPInfo, VPNapi
7. Microsoft Learn: Search for remediation guidance if threats detected
8. Generate Report: HTML with findings + blast radius visualization
```

See [Investigation-Guide.md Part II: Knowledge](Investigation-Guide.md#part-ii-knowledge-mcp-tools) for complete MCP tool documentation.

### External API Configuration

#### AbuseIPDB
```json
"abuseipdb": "YOUR-API-KEY-HERE"
```
- **Purpose**: IP reputation scoring (0-100% abuse confidence)
- **Free tier**: 1,000 requests/day
- **Provides**: Abuse reports, usage categories, ISP information

#### IPInfo.io
```json
"ipinfo": "YOUR-TOKEN-HERE"
```
- **Purpose**: IP geolocation and ASN lookup
- **Free tier**: 50,000 requests/month
- **Provides**: City, country, coordinates, ASN, organization

#### VPNapi.io
```json
"vpnapi": "YOUR-API-KEY-HERE"
```
- **Purpose**: VPN/proxy/Tor detection
- **Free tier**: 1,000 requests/month
- **Provides**: VPN detection, proxy detection, threat indicators

#### Shodan
```json
"shodan": "YOUR-API-KEY-HERE"
```
- **Purpose**: Open port, CVE, and service scanning
- **Paid tier**: Unlimited ($59/month); free fallback via InternetDB API
- **Provides**: Open ports, known CVEs, OS detection, hostnames, service tags

#### VirusTotal 🆕
```json
"virustotal": "YOUR-API-KEY-HERE"
```
- **Purpose**: Domain and file hash reputation analysis
- **Free tier**: 500 lookups/day, 4 requests/minute
- **Provides**: Malicious/suspicious vendor votes, categories, reputation score, last analysis stats
- **Script**: `enrichment/enrich_iocs.py`

---

## 🛠️ Advanced Features

### Custom KQL Queries

Add custom queries to `Investigation-Guide.md`:

```kusto
// Hunt for suspicious PowerShell execution
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression", "DownloadString")
| where TimeGenerated > ago(24h)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

### Automated Incident Watchers

Create polling-based automation:

```python
# Example: Auto-enrich new high-severity incidents
while True:
    incidents = mcp_triage_ListIncidents(
        createdAfter=last_check_time,
        severity="High"
    )
    
    for incident in incidents:
        ips = extract_ips(incident)
        enriched_data = enrich_ips(ips)
        generate_report(incident, enriched_data)
    
    sleep(900)  # Check every 15 minutes
```

### Integration with SOAR Platforms

Export incident data for automation:

```powershell
# Export to JSON for Sentinel automation rules
python enrichment/powerbi_data_export.py --format json

# Use in Logic Apps, Power Automate, or custom SOAR solutions
```

---

## 📊 Data Sources

### Microsoft Defender XDR Tables
- `DeviceEvents` - Endpoint telemetry
- `DeviceNetworkEvents` - Network connections
- `DeviceProcessEvents` - Process execution
- `DeviceFileEvents` - File operations
- `EmailEvents` - Email security events

### Microsoft Sentinel Tables
- `SecurityAlert` - Alerts from all sources
- `SecurityIncident` - Correlated incidents
- `SigninLogs` - Azure AD authentication
- `OfficeActivity` - Office 365 audit logs
- `ThreatIntelligenceIndicator` - Threat intel feeds

See [Investigation-Guide.md Part IV](Investigation-Guide.md#part-iv-reference) for complete table schemas and sample queries.

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-enrichment-source`
3. **Commit changes**: `git commit -m "Add VirusTotal API integration"`
4. **Push to branch**: `git push origin feature/new-enrichment-source`
5. **Submit Pull Request**

### Development Guidelines
- Follow PEP 8 style guide for Python code
- Add docstrings to all functions
- Update documentation for new features
- Test with sample data before submitting

---

## 🤖 Agent Skills for AI-Assisted Investigations

CyberProbe includes **11 specialized VS Code Agent Skills** that teach GitHub Copilot how to conduct professional security investigations automatically.

> **Note:** Skills are auto-triggered by Copilot based on keywords in your prompts — no manual activation needed. The `.github/copilot-instructions.md` file handles routing, KQL guardrails, and evidence-based analysis rules automatically.

### Available Skills

📁 **incident-investigation** (`.github/skills/incident-investigation/SKILL.md`)
- Automates the complete 5-phase investigation workflow
- Executes parallel queries across Sentinel and Graph APIs
- Performance: ~5-6 minutes for 7-day investigation
- **Trigger**: "Investigate user@contoso.com for the last 7 days"

📁 **threat-enrichment** (`.github/skills/threat-enrichment/SKILL.md`)
- Multi-source IP enrichment (AbuseIPDB, IPInfo, VPNapi, Shodan)
- Shodan: open ports, CVEs, service scanning (with free InternetDB fallback)
- Risk assessment with confidence scoring
- Batch processing up to 15 IPs
- **Trigger**: "Is 206.168.34.210 malicious?"

📁 **kql-sentinel-queries** (`.github/skills/kql-sentinel-queries/SKILL.md`)
- 40+ pre-built KQL queries for Sentinel data lake
- Optimized for performance (TimeGenerated filters, take operators)
- SessionId-based authentication tracing
- **Trigger**: "Query sign-in logs for suspicious activity"

📁 **kql-query-builder** (`.github/skills/kql-query-builder/SKILL.md`)
- Generate validated KQL from natural language descriptions
- 331+ table schemas with automatic validation
- Create Sentinel Analytic Rules with MITRE ATT&CK mapping
- Search GitHub for community detection patterns
- ASIM normalization support for multi-source queries
- **Trigger**: "Create a query to detect brute force attacks"

📁 **microsoft-learn-docs** (`.github/skills/microsoft-learn-docs/SKILL.md`)
- Access official Microsoft security documentation in real-time
- Production-ready PowerShell/KQL code samples with language filtering
- Official investigation playbooks and remediation procedures
- Performance: 1-3 seconds per documentation lookup
- **Trigger**: "How do I remediate this OAuth application attack?"

📁 **report-generation** (`.github/skills/report-generation/SKILL.md`)
- JSON/HTML/Power BI report generation
- Dark theme templates with MITRE ATT&CK mapping
- Executive briefing format
- **Trigger**: "Generate critical incident report for #41272"

📁 **endpoint-device-investigation** (`.github/skills/endpoint-device-investigation/SKILL.md`)
- Comprehensive endpoint forensics using Defender for Endpoint
- Process execution analysis, network connections, file operations
- Lateral movement detection and vulnerability assessment
- 7 investigation phases with optimized KQL queries
- **Trigger**: "Investigate device DESKTOP-ABC123 for malware"

📁 **incident-correlation-analytics** (`.github/skills/incident-correlation-analytics/SKILL.md`)
- Temporal analysis and incident heatmaps
- Campaign detection through IOC correlation
- MITRE ATT&CK technique frequency analysis
- SOC metrics: MTTD, MTTR, closure rates
- **Trigger**: "Generate weekly SOC report" or "Detect attack campaigns"

📁 **ioc-management** (`.github/skills/ioc-management/SKILL.md`)
- Extract IOCs from incidents (IPs, domains, file hashes, URLs)
- Bulk enrichment and deduplication workflows
- Watchlist management (known-bad and known-good lists)
- STIX 2.1 export for SIEM/SOAR integration
- IOC lifecycle management with confidence decay
- **Trigger**: "Extract all IOCs from incident #42001"

📁 **defender-response** (`.github/skills/defender-response/SKILL.md`)
- Active containment: device isolation, code restriction, AV scans
- Identity response: disable accounts, force password reset, confirm compromise
- Incident management: classify, assign, tag, update status
- Forensic collection: investigation packages with download URIs
- Built-in playbooks for compromised user, malware, and ransomware scenarios
- **Trigger**: "Isolate device WORKSTATION-01" or "Disable compromised user account"

📁 **exposure-management** (`.github/skills/exposure-management/SKILL.md`) 🆕
- CTEM (Continuous Threat Exposure Management) metrics and KPI dashboards
- CNAPP posture: cloud-native protection across Azure, AWS, GCP
- Attack surface inventory, choke point analysis, and attack path discovery
- Vulnerability posture with weighted risk scoring (ExposureGraphNodes/Edges)
- Regulatory compliance benchmarks (CIS, NIST, PCI-DSS, ISO 27001)
- Container security, CIEM entitlements, DSPM data security, DevSecOps posture
- **Trigger**: "What's our exposure posture?" or "Show CTEM metrics"

### How to Use

**No manual activation needed!** Skills automatically activate when you ask Copilot investigation-related questions:

```
You: "Investigate jsmith@contoso.com for suspicious activity"

Copilot (auto-activates incident-investigation skill):
✓ Phase 1: Retrieved User ID (3 sec)
✓ Phase 2: Parallel data collection (70 sec)  
✓ Phase 3: Exported JSON (2 sec)
✓ Phase 4: IP enrichment (150 sec)
✓ Phase 5: Generated HTML report (2 sec)

Key Findings:
• 3 anomalies detected
• 1 critical IP: 206.168.34.210 (100% abuse)
• 2 security incidents
• Report: reports/investigation_jsmith_2026-01-15.html
```

### Skills Workflow

When you ask Copilot to investigate a user, the workflow follows the **Security Agent Architecture** pattern:

```
User Request: "Investigate jsmith@contoso.com for suspicious activity"
                                    ↓
┌─────────────────────────────────────────────────────────────────┐
│ ORCHESTRATION (Part I) - Decision & Planning                    │
├─────────────────────────────────────────────────────────────────┤
│ Step 1: incident-investigation skill activates                  │
│ • Reads Investigation-Guide.md Part I (Critical Rules)          │
│ • Applies playbooks and scenario-based decision flow            │
│ • Identifies required queries: Query 1, 2, 3a/b/c/d, 4, 5, 6, 10│
│ • Prepares parallel execution batches                           │
└─────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────┐
│ KNOWLEDGE (Part II) - Data Collection via MCP Tools             │
├─────────────────────────────────────────────────────────────────┤
│ Step 2: Execute MCP data tools (57+ tools across 8 servers)     │
│ • Sentinel: SigninLogs, AuditLogs, BehaviorAnalytics           │
│ • Defender XDR: Incidents, Alerts, Device events               │
│ • Graph API: User profile, MFA status, risk detections         │
│ Uses: mcp_data_explorat_query_lake, mcp_triage_ListIncidents   │
│       mcp_microsoft_mcp_microsoft_graph_get                     │
├─────────────────────────────────────────────────────────────────┤
│ Step 3: External threat intelligence enrichment                 │
│ • Extracts top 15 priority IPs from Query 1 results            │
│ • Runs: python enrichment/enrich_ips.py <IP1> <IP2> ... <IP15> │
│ • AbuseIPDB: Abuse confidence scores (0-100%)                  │
│ • IPInfo: Geolocation, ISP, organization                       │
│ • VPNapi: VPN/proxy/Tor detection                              │
└─────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────┐
│ SKILLS (Part III) - Response Actions (if threats detected)      │
├─────────────────────────────────────────────────────────────────┤
│ Step 4: microsoft-learn-docs skill retrieves remediation 🆕     │
│ • If OAuth apps → Search "revoke OAuth Entra ID"               │
│ • If TOR IPs → Search "block TOR Conditional Access"           │
│ • If compromised → Search "investigate compromised user"        │
│ Uses: mcp_microsoft_lea_microsoft_docs_search                   │
│       mcp_microsoft_lea_microsoft_code_sample_search            │
├─────────────────────────────────────────────────────────────────┤
│ Response Actions Available (from Part III):                     │
│ • Identity: Disable account, revoke sessions, reset MFA        │
│ • Endpoint: Isolate device, run AV scan, collect forensics     │
│ • Network: Block IPs, add to watchlist, update firewall        │
└─────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────┐
│ REFERENCE (Part IV) - Templates & Output Generation             │
├─────────────────────────────────────────────────────────────────┤
│ Step 5: report-generation skill creates outputs                 │
│ • Merges all data into standardized JSON schema                │
│ • Exports: reports/investigation_jsmith_2026-01-15.json        │
│ • Generates HTML report with dark theme                         │
│ • Exports: reports/investigation_jsmith_2026-01-15.html        │
│ • (Optional) Power BI dataset for dashboards                   │
│ Uses: Investigation-Guide.md Part IV (Report Templates)        │
└─────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────┐
│ Final Output: Comprehensive Investigation Package               │
├─────────────────────────────────────────────────────────────────┤
│ ✓ reports/investigation_jsmith_2026-01-15.json (machine-readable)│
│ ✓ reports/investigation_jsmith_2026-01-15.html (executive report)│
│ ✓ enrichment/ip_enrichment_15_ips_2026-01-15.json (threat intel)│
│ ✓ (Optional) powerbi_incidents.xlsx (dashboard dataset)        │
│                                                                  │
│ Total Time: ~5-6 minutes for 7-day investigation                │
└─────────────────────────────────────────────────────────────────┘
```

### Component Integration

Each skill leverages the **Security Agent Architecture** components:

| Skill | Architecture Part | Component | Purpose |
|-------|-------------------|-----------|---------|
| **incident-investigation** | Part I: Orchestration | Investigation-Guide.md | Critical rules, playbooks, decision flow |
| **incident-investigation** | Part II: Knowledge | MCP tools (mcp_triage_*) | Defender XDR incidents & alerts |
| **kql-sentinel-queries** | Part II: Knowledge | MCP tools (mcp_data_explorat_*) | Sentinel data lake queries |
| **kql-sentinel-queries** | Part IV: Reference | Investigation-Guide.md | 40+ pre-built KQL queries |
| **kql-query-builder** | Part II: Knowledge | KQL Search MCP Server | Generate, validate, optimize queries |
| **threat-enrichment** | Part II: Knowledge | enrichment/enrich_ips.py | AbuseIPDB, IPInfo, VPNapi APIs |
| **microsoft-learn-docs** | Part III: Skills | MCP tools (mcp_microsoft_lea_*) | Remediation guidance & code samples |
| **report-generation** | Part IV: Reference | Investigation-Guide.md | Report templates with dark theme |
| **endpoint-device-investigation** | Part II: Knowledge | MCP tools (mcp_triage_*) | Device forensics, vulnerabilities |
| **endpoint-device-investigation** | Part III: Skills | Investigation-Guide.md | Endpoint response actions |
| **incident-correlation-analytics** | Part II: Knowledge | SecurityIncident tables | Campaign detection, SOC metrics |
| **ioc-management** | Part III: Skills | enrichment/ioc-database/ | IOC extraction, watchlists |

| **exposure-management** | Part II: Knowledge | MCP tools (mcp_triage_*) | CTEM metrics, ExposureGraph, DeviceTvm |
| **exposure-management** | Part II: Knowledge | Azure MCP (resource graph) | CNAPP posture, compliance, container security |

**Learn More**: See [docs/AGENT_SKILLS.md](docs/AGENT_SKILLS.md) for complete documentation

---

## 🐛 Troubleshooting

### Common Issues

**Authentication Errors**
```
Error: AADSTS700016: Application not found
```
**Solution**: Verify Azure AD app registration and client ID in `config.json`

**API Rate Limiting**
```
Error: 429 Too Many Requests
```
**Solution**: Implement request throttling or upgrade API tier

**Missing Dependencies**
```
ModuleNotFoundError: No module named 'requests'
```
**Solution**: Activate virtual environment and run `pip install -r requirements.txt`

**MCP Tools Not Available**
```
Error: Tool 'mcp_triage_ListIncidents' not found
```
**Solution**: Ensure VS Code MCP extension is installed and authenticated

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Microsoft Security Team** - For Defender XDR and Sentinel platforms
- **AbuseIPDB, IPInfo.io, VPNapi.io** - For threat intelligence APIs
- **MITRE ATT&CK Framework** - For attack technique taxonomy
- **Security Community** - For sharing investigation techniques and best practices

---

## 📞 Support

- **Documentation**: [Investigation-Guide.md](Investigation-Guide.md)
- **Power BI Setup**: [docs/POWERBI_SETUP.md](docs/POWERBI_SETUP.md)
- **Issues**: [GitHub Issues](https://github.com/YOUR-USERNAME/CyberProbe/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR-USERNAME/CyberProbe/discussions)

---

## 🔐 Security Notice

This tool is designed for authorized security operations only. Always ensure you have:
- ✅ Proper authorization to access organizational security data
- ✅ Secure storage of API keys and credentials
- ✅ Audit logging enabled for all automated actions
- ✅ Compliance with data protection regulations (GDPR, CCPA, etc.)

**Never commit `config.json` with real API keys to version control.**

---

## 🗺️ Roadmap

### Completed
- [x] File hash enrichment (VirusTotal)
- [x] Domain reputation scoring (VirusTotal)
- [x] Exposure Management & CTEM posture skill (ExposureGraph, CNAPP, compliance)
- [x] CyberProbe MCP Apps — interactive inline UIs (IP map, entity explorer, response console, posture dashboard)
- [x] IOC enrichment utility (`enrich_iocs.py`) for domains and file hashes
- [x] XDR Tables & APIs reference guide (`docs/XDR_TABLES_AND_APIS.md`)

### Planned Features
- [ ] Real-time incident webhooks (event-driven automation)
- [ ] Machine learning-based anomaly detection
- [ ] Multi-tenant support for MSSPs
- [ ] Mobile-responsive HTML reports
- [ ] Automated alert triage with confidence scoring
- [ ] Integration with additional TI sources (AlienVault OTX, ThreatFox, URLhaus)
- [ ] Integration with Slack/Teams for notifications

### In Progress
- [x] Power BI dataset automation
- [x] IP enrichment with multiple sources
- [x] HTML report generation
- [x] Investigation graph visualization

---

<div align="center">

**CyberProbe** - Empowering Security Operations with Automated Intelligence

Made with ❤️ by Security Professionals, for Security Professionals

⭐ Star this repo if you find it useful! ⭐

</div>
