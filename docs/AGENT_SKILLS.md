# CyberProbe Agent Skills Documentation

**VS Code Copilot Skills for AI-Assisted Security Investigations**

Last Updated: April 13, 2026

---

## Table of Contents

1. [Overview](#overview)
2. [What are Agent Skills?](#what-are-agent-skills)
3. [CyberProbe Skills Architecture](#cyberprobe-skills-architecture)
4. [Available Skills](#available-skills)
5. [Using Skills with Copilot](#using-skills-with-copilot)
6. [Skill Development Guide](#skill-development-guide)
7. [Integration with CyberProbe](#integration-with-cyberprobe)
8. [Examples and Use Cases](#examples-and-use-cases)
9. [Troubleshooting](#troubleshooting)
10. [Resources](#resources)

---

## Overview

CyberProbe includes specialized **Agent Skills** that teach GitHub Copilot and other AI coding assistants how to conduct professional-grade security investigations. These skills automate the complete investigation workflow—from data collection through threat intelligence enrichment to report generation.

**Key Benefits:**
- ✅ **Automated Investigations**: 5-phase workflow executes in ~5-6 minutes
- ✅ **Consistent Quality**: Skills enforce best practices and proven patterns
- ✅ **Knowledge Transfer**: New analysts learn investigation techniques from AI guidance
- ✅ **Time Savings**: Parallel query execution reduces investigation time by 70%
- ✅ **Reduced Errors**: Skills prevent common mistakes (date range issues, missing fields, null handling)

**Location**: `.github/skills/`

**Standard**: Open standard from [agentskills.io](https://agentskills.io) - works across GitHub Copilot, Copilot CLI, and other AI coding assistants

---

## What are Agent Skills?

Agent Skills are domain-specific knowledge packages that customize AI coding assistants for specialized workflows. Each skill contains:

### Skill Structure

```
.github/skills/
└── incident-investigation/          # Skill directory
    ├── SKILL.md                      # Main skill file (required)
    ├── examples/                     # Example code (optional)
    │   └── sample_investigation.json
    └── templates/                    # Templates (optional)
        └── report_template.html
```

### SKILL.md Format

Every skill uses this standardized format:

```markdown
---
name: incident-investigation
description: Investigate security incidents using Microsoft Defender XDR and Sentinel...
---

# Incident Investigation Skill

## When to Use This Skill
[Trigger conditions...]

## Prerequisites
[Required setup...]

## Workflow
[Step-by-step instructions...]

## Resources
[Links to related files...]
```

**YAML Frontmatter** (required):
- `name`: Lowercase with hyphens, max 64 characters (e.g., `incident-investigation`)
- `description`: Clear purpose statement, max 1024 characters

**Markdown Body** (optional but recommended):
- Progressive disclosure: Start with high-level overview, add detail in subsections
- Workflow instructions: Step-by-step procedures
- Code examples: Copy-paste ready scripts
- Error handling: Common issues and solutions
- Resources: Links to related files/docs

### How Skills Activate

Skills use **progressive disclosure** (3 levels):

**Level 1: Discovery** - Copilot scans skill names/descriptions
```
User: "Investigate user@contoso.com"
→ Copilot finds: incident-investigation (keyword match)
```

**Level 2: Instructions Loading** - Copilot reads full SKILL.md
```
User: "Investigate user@contoso.com for last 7 days"
→ Loads incident-investigation/SKILL.md
→ Follows 5-phase workflow
```

**Level 3: Resource Access** - Copilot reads referenced files
```
Copilot needs: Sample KQL queries
→ Reads Investigation-Guide.md Section 8
→ Uses pre-built Query 1
```

**No manual selection needed** - Skills automatically activate based on user prompts!

---

## CyberProbe Skills Architecture

CyberProbe provides **12 specialized skills** that cover the complete investigation lifecycle:

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                        CyberProbe Agent Skills (12 Skills)                            │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬───────────────┬──────────────┐
        │               │               │               │               │              │
        ▼               ▼               ▼               ▼               ▼              ▼
┌──────────────┐ ┌─────────────┐ ┌────────────┐ ┌──────────────┐ ┌──────────┐ ┌────────────┐
│  incident-   │ │   threat-   │ │    kql-    │ │  microsoft-  │ │   kql-   │ │  endpoint- │
│investigation │ │ enrichment  │ │  sentinel- │ │  learn-docs  │ │  query-  │ │   device-  │
│              │ │             │ │   queries  │ │              │ │  builder │ │investigation│
│ Phase 1: ID  │ │ • AbuseIPDB │ │ • Query 1-11│ │ • Remediatio│ │• 331+ Tbl│ │ • DeviceInfo│
│ Phase 2: Data│ │ • IPInfo    │ │ • Schema Ref│ │ • Code Sample│ │• Query Gen│ │ • Process  │
│ Phase 3: JSON│ │ • VPNapi    │ │ • Best Pract│ │ • Playbooks │ │• Validation│ │ • Network  │
│ Phase 4:Enrich│ │• Risk Matrix│ │ • SessionId │ │• Best Practice│ │• ASIM    │ │ • Files    │
│ Phase 5:Report│ │             │ │             │ │              │ │• Analytics│ │ • Registry │
└──────────────┘ └─────────────┘ └────────────┘ └──────────────┘ └──────────┘ └────────────┘
        │               │               │               │               │              │
        └───────────────┴───────────────┼───────────────┴───────────────┴──────────────┘
                                        ▼
        ┌───────────────┬───────────────┼───────────────┬───────────────┬──────────────┐
        │               │               │               │               │              │
        ▼               ▼               ▼               ▼               ▼              ▼
┌──────────────┐ ┌─────────────────┐ ┌────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│   report-    │ │    incident-    │ │    ioc-    │ │   defender-      │ │  exposure-       │ │  detection-      │
│ generation   │ │  correlation-   │ │ management │ │   response       │ │  management      │ │  engineering     │
│              │ │   analytics     │ │            │ │                  │ │                  │ │                  │
│ • JSON       │ │                 │ │ • Extract  │ │ • Isolate Device │ │ • CTEM Metrics   │ │ • Sigma→KQL      │
│ • HTML       │ │ • Heatmaps      │ │ • Enrich   │ │ • Disable User   │ │ • Vuln Posture   │ │ • Splunk SPL     │
│ • MITRE Map  │ │ • Campaigns     │ │ • Watchlist │ │ • Force PW Reset │ │ • Choke Points   │ │ • Analytic Rules │
│              │ │ • MITRE Matrix  │ │ • STIX     │ │ • AV Scan        │ │ • Attack Paths   │ │ • pySigma        │
│              │ │ • SOC KPIs      │ │ • Correlate│ │ • Forensics      │ │ • CNAPP Posture  │ │ • ARM Templates  │
└──────────────┘ └─────────────────┘ └────────────┘ │ • Incident Mgmt  │ │ • Compliance     │ │ • CI/CD Deploy   │
                                                    └──────────────────┘ └──────────────────┘ └──────────────────┘
```

### Skill Dependencies

Skills build on each other in a logical sequence:

1. **kql-sentinel-queries** (foundation)
   - Provides production-validated KQL query patterns
   - No dependencies

2. **kql-query-builder** (query generation layer)
   - Generates and validates custom KQL queries using 331+ table schemas
   - Complements kql-sentinel-queries with on-demand query creation
   - No dependencies

3. **microsoft-learn-docs** (knowledge layer)
   - Provides official Microsoft documentation and remediation guidance
   - No dependencies

4. **endpoint-device-investigation** (NEW - device analysis)
   - Analyzes endpoints using Defender for Endpoint data
   - Uses: kql-sentinel-queries for Device* table queries
   - Called by: incident-investigation

5. **incident-correlation-analytics** (NEW - pattern analysis)
   - Cross-incident correlation, campaign detection, SOC metrics
   - Uses: kql-sentinel-queries for SecurityIncident queries
   - Independent or called by report-generation

6. **ioc-management** (NEW - IOC lifecycle)
   - Extract, enrich, deduplicate, and track IOCs
   - Uses: threat-enrichment for bulk enrichment
   - Independent or called by incident-investigation

7. **incident-investigation** (orchestrator)
   - Depends on: kql-sentinel-queries, kql-query-builder, microsoft-learn-docs
   - Calls: threat-enrichment, report-generation, endpoint-device-investigation
   - Uses kql-query-builder for custom investigation queries

8. **threat-enrichment** (enrichment layer)
   - No dependencies
   - Called by: incident-investigation, ioc-management

9. **report-generation** (output layer)
   - Depends on: incident-investigation (JSON schema)
   - Can use: incident-correlation-analytics for trending data
   - Final step in workflow

10. **defender-response** (response layer) ⭐ NEW
    - Executes containment and remediation actions via Defender Response MCP
    - Called by: incident-investigation (remediation phase), endpoint-device-investigation (containment)
    - Uses: incident-management tools, device-response tools, AD account management tools
    - References: microsoft-learn-docs (for remediation guidance)
    - Feeds into: report-generation (action log for final report)

11. **detection-engineering** (detection-as-code layer) ⭐ NEW
    - Converts community detections (Sigma YAML, Splunk SPL) to Sentinel analytics rules and Defender XDR custom detections
    - Uses: kql-query-builder (KQL validation, schema checking), kql-sentinel-queries (test execution)
    - References: microsoft-learn-docs (analytic rule authoring docs), SigmaHQ ecosystem
    - Independent or called manually for detection lifecycle workflows

---

## Available Skills

### 1. incident-investigation

**Purpose**: Automates the complete 5-phase investigation workflow

**Location**: `.github/skills/incident-investigation/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Investigate user@contoso.com for the last 7 days"
- "Run security investigation for suspicious.user@domain.com"
- "Quick investigate admin@company.com"

**Workflow (5 phases)**:

```
Phase 1: Get User ID (~3 sec)
├─ mcp_microsoft_graph_get("/v1.0/users/<UPN>")
└─ Extract: user_id, windowsSID

Phase 2: Parallel Data Collection (~60-70 sec)
├─ Batch 1: Sentinel queries (Query 1, 2, 3a/b/c/d, 4, 5, 6, 10, 11)
├─ Batch 2: Graph queries (profile, MFA, devices, risk)
└─ Batch 3: IP extraction → threat intel correlation

Phase 3: Export Investigation JSON (~1-2 sec)
├─ Merge all query results
├─ Handle null values (use "Unknown")
├─ Export empty arrays (not null)
└─ Save: reports/investigation_<upn>_YYYY-MM-DD.json

Phase 4: IP Enrichment (~2-3 min)
├─ Extract priority IPs (top 15)
├─ Run: python enrichment/enrich_ips.py <IPs>
└─ Merge enrichment into investigation JSON

Phase 5: Generate HTML Report (~1-2 sec)
├─ Load investigation JSON
├─ Apply dark theme template
└─ Save: reports/investigation_<upn>_YYYY-MM-DD.html

Total Time: ~5-6 minutes
```

**Performance Expectations**:
- Standard investigation (7 days): ~5-6 minutes
- Quick investigation (1 day): ~2-3 minutes
- Comprehensive investigation (30 days): ~8-10 minutes

**Key Features**:
- Parallel query execution (reduces time by 70%)
- SessionId-based authentication tracing
- Automatic anomaly detection
- Risk-based IP prioritization
- Standardized JSON schema

**References**:
- Investigation-Guide.md Section 2 (Quick Start Guide)
- Investigation-Guide.md Section 8 (Sample KQL Queries)
- Investigation-Guide.md Section 9 (SessionId Tracing)

---

### 2. threat-enrichment

**Purpose**: Multi-source threat intelligence enrichment for IP addresses

**Location**: `.github/skills/threat-enrichment/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Enrich IPs from incident #41272"
- "What's the threat intelligence for 206.168.34.210?"
- "Is this IP address malicious?"

**Data Sources**:

| Source | Purpose | Key Fields | Rate Limit |
|--------|---------|------------|------------|
| AbuseIPDB | Abuse confidence, reporting history | `abuseConfidenceScore` (0-100), `totalReports`, `categories` | 1,000/day |
| IPInfo | Geolocation, ISP, network details | `country`, `city`, `org`, `loc` | 50,000/month |
| VPNapi | VPN/proxy/Tor detection | `security.vpn`, `security.tor`, `security.proxy` | 1,000/month |
| Shodan | Open ports, CVEs, services | `shodan_ports`, `shodan_vulns`, `shodan_tags` | Unlimited (paid) / InternetDB (free) |

**Usage**:

```powershell
# Single IP
python enrichment/enrich_ips.py 206.168.34.210

# Batch (up to 15 IPs recommended)
python enrichment/enrich_ips.py 206.168.34.210 45.155.205.233 192.0.2.1

# From investigation JSON
python enrichment/enrich_ips.py --from-investigation reports/investigation_user_2026-01-15.json
```

**Risk Assessment Matrix**:

| Abuse Score | VPN/Tor | ISP Type | Risk Level | Action |
|-------------|---------|----------|------------|--------|
| 90-100 | Any | Any | **Critical** | Block immediately, investigate |
| 75-89 | Yes | Datacenter | **High** | Investigate SessionId chain |
| 75-89 | No | Residential | **Medium** | Check user location history |
| 50-74 | Yes | Any | **Medium** | Review authentication pattern |
| 50-74 | No | Residential | **Low** | Monitor only |
| 0-49 | Yes | Any | **Low** | Likely privacy user |
| 0-49 | No | Residential | **Very Low** | Legitimate |

**Output Format**:

```json
{
  "ip": "206.168.34.210",
  "abuse_confidence_score": 100,
  "total_reports": 1363,
  "country_code": "US",
  "city": "Chicago",
  "is_vpn": false,
  "is_tor": false,
  "is_proxy": false,
  "isp": "Censys Inc.",
  "usage_type": "Data Center/Web Hosting/Transit",
  "threat_categories": ["Port Scan", "Brute Force"],
  "last_reported": "2026-01-10T14:23:11Z",
  "last_checked": "2026-01-15T09:15:32Z"
}
```

**References**:
- enrichment/enrich_ips.py - Enrichment script
- enrichment/config.json - API keys
- Investigation-Guide.md Section 11 (External Enrichment)

---

### 3. kql-sentinel-queries

**Purpose**: Execute optimized KQL queries on Microsoft Sentinel data lake

**Location**: `.github/skills/kql-sentinel-queries/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Query sign-in logs for user@contoso.com"
- "Check for policy changes this morning"
- "Run KQL query to find anomalies"

**Query Library** (11 pre-built queries):

| Query | Purpose | Key Tables | Returns |
|-------|---------|------------|---------|
| Query 1 | Priority IP extraction | BehaviorAnalytics, SigninLogs | Top 15 IPs (anomalies + risky + frequent) |
| Query 2 | Anomaly detection | BehaviorAnalytics | Anomalous activities with priority scores |
| Query 3a | Sign-ins by application | SigninLogs | App usage summary |
| Query 3b | Sign-ins by location | SigninLogs | Geographic distribution |
| Query 3c | Sign-in failures | SigninLogs | Failed authentication attempts |
| Query 3d | Authentication details per IP | SigninLogs | SessionId, MFA, device, conditional access |
| Query 4 | Azure AD audit logs | AuditLogs | Administrative actions |
| Query 5 | Office 365 activity | OfficeActivity | SharePoint, Exchange, Teams events |
| Query 6 | Security incidents | SecurityIncident | Incidents involving user |
| Query 10 | DLP events | DLPEvents | Data Loss Prevention violations |
| Query 11 | Threat intelligence | ThreatIntelligenceIndicator | IP correlation with known threats |

**Best Practices**:

✅ **Always filter on `TimeGenerated` first** (critical for performance)
```kql
| where TimeGenerated > ago(7d)  // FIRST LINE after table name
```

✅ **Use `| take` operator** to limit results
```kql
| take 100  // Exploratory queries
| take 1000 // Comprehensive analysis
```

✅ **Add +2 days buffer for real-time investigations**
```kql
// Today = Jan 15, user asks "last 7 days"
| where TimeGenerated between (datetime(2026-01-08) .. datetime(2026-01-17))
// Start: Jan 8 (15-7), End: Jan 17 (15+2)
```

✅ **Use `has` instead of `contains`** (faster)
```kql
| where AppDisplayName has "Office"  // Fast
| where AppDisplayName contains "Office"  // Slow
```

**SessionId-Based Authentication Tracing**:

When investigating geographic anomalies or impossible travel:

1. Extract SessionId from suspicious IP sign-in
2. Trace complete authentication chain by SessionId
3. Find first MFA event (true authentication location)
4. Extract all IPs from session
5. Enrich IPs with threat intelligence
6. Assess risk using enrichment data

See Investigation-Guide.md Section 9 for complete workflow.

**References**:
- Investigation-Guide.md Section 8 (Sample KQL Queries)
- Investigation-Guide.md Section 9 (SessionId Tracing)
- Investigation-Guide.md Section 14 (Quick Reference)

---

### 4. microsoft-learn-docs

**Purpose**: Access official Microsoft documentation for remediation guidance and best practices

**Location**: `.github/skills/microsoft-learn-docs/SKILL.md`

**Triggers**: Copilot activates when you say:
- "How do I remediate this OAuth app attack?"
- "Find Microsoft documentation for blocking TOR networks"
- "Show me PowerShell commands to disable compromised user"
- "What's the official guidance for investigating this incident?"

**Available MCP Tools**:

#### microsoft_docs_search
Search Microsoft Learn documentation for remediation procedures, configuration guides, and investigation playbooks.

**Use cases:**
- Find step-by-step remediation procedures during active incidents
- Access official security playbooks (OAuth attacks, account compromise, etc.)
- Reference Microsoft best practices for configuration changes
- Validate investigation techniques against official documentation

**Example queries:**
```
"revoke malicious OAuth application Azure AD tenant remediation"
"investigate compromised user account Defender XDR incident response"
"configure Conditional Access to block anonymous networks"
"detect impossible travel in SigninLogs"
```

**Returns:** Up to 10 documentation articles with titles, URLs, and relevant excerpts

#### microsoft_code_sample_search
Search for production-ready code samples (PowerShell, KQL, Python, etc.) in Microsoft Learn.

**Use cases:**
- Get PowerShell cmdlets for remediation actions
- Find validated KQL queries for specific scenarios
- Access Microsoft Graph API examples
- Reference official CLI commands for Azure/Microsoft 365

**Example queries with language filtering:**
```
microsoft_code_sample_search(
  "block TOR IP addresses conditional access Azure AD",
  language="powershell"
)

microsoft_code_sample_search(
  "detect credential stuffing attacks KQL",
  language="kusto"
)

microsoft_code_sample_search(
  "revoke OAuth grants Microsoft Graph API",
  language="python"
)
```

**Supported languages:** powershell, kusto, python, csharp, javascript, typescript, azurecli, java, cpp, go, rust, ruby, php

**Returns:** Up to 20 code samples with syntax, context, and documentation links

#### microsoft_docs_fetch
Retrieve complete documentation page content in markdown format.

**Use cases:**
- Get full troubleshooting guides when search results are incomplete
- Access comprehensive reference documentation
- Read complete procedures with all prerequisites and steps
- Build thorough investigation documentation

**Example:**
```
microsoft_docs_fetch("https://learn.microsoft.com/en-us/entra/identity/authentication/...")
```

**Returns:** Full page content with headings, code blocks, tables, links in markdown

**Integration with Investigations**:

The skill automatically activates during incident response when:
- Malicious OAuth applications are detected → Searches for revocation procedures
- TOR/VPN networks are identified → Finds Conditional Access blocking guidance
- Compromised users are flagged → Retrieves official investigation playbooks
- Security alerts require remediation → Locates product-specific remediation steps

**Workflow Example (OAuth Attack)**:
```
1. Investigation detects malicious "Micr0s0ft-App" OAuth application
2. Skill searches: "revoke OAuth application consent grants Entra ID"
3. Returns official documentation:
   - "Detect and Remediate Illicit Consent Grants"
   - PowerShell cmdlets: Remove-MgOauth2PermissionGrant
   - Best practice: Disable (not delete) to prevent re-consent
4. Includes remediation code in investigation report
5. Cites Microsoft Learn URLs for compliance documentation
```

**Performance**:
- Documentation search: ~1-2 seconds
- Code sample search: ~1-3 seconds (depends on language filtering)
- Fetch full page: ~2-4 seconds

**Coverage**:
- Microsoft Defender XDR (Endpoint, Identity, Office 365, Cloud Apps)
- Microsoft Entra ID (Azure AD)
- Microsoft Sentinel
- Microsoft 365 (Exchange, SharePoint, Teams)
- Azure Security (Conditional Access, Identity Protection, PIM)
- Microsoft Graph API
- PowerShell modules (Microsoft.Graph, Az, ExchangeOnlineManagement)

**References**:
- Investigation-Guide.md Section 4 (Microsoft Learn Documentation Integration)
- Investigation-Guide.md Section 12 (Investigation Playbooks)
- .github/skills/microsoft-learn-docs/SKILL.md

---

### 5. kql-query-builder

**Purpose**: Generate, validate, and optimize KQL queries for investigations and Sentinel Analytic Rules using the KQL Search MCP server

**Location**: `.github/skills/kql-query-builder/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Create a KQL query to find failed logins"
- "Generate a Sentinel Analytic Rule for brute force detection"
- "Validate this query for me"
- "How do I query for impossible travel?"
- "Build an ASIM-normalized query for authentication events"

**Key Capabilities**:

#### A. Natural Language → Validated KQL
Converts plain English to production-ready queries with schema validation.

**Example**:
```
User: "Show me emails with malicious attachments in the last 7 days"

Generated:
EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has "Malware"
| join kind=inner EmailAttachmentInfo on NetworkMessageId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, FileName, SHA256
```

#### B. Sentinel Analytic Rule Generation
Creates complete detection rules with MITRE ATT&CK mapping, entity mappings, and remediation guidance.

**Includes**:
- Rule metadata (severity, tactics, techniques)
- Validated KQL query
- Entity mappings (Account, IP, Host, File)
- Alert enrichment fields
- Query frequency and period configuration
- Custom details and alert overrides

#### C. Query Validation & Optimization
Checks existing queries for syntax errors, performance issues, and schema compliance.

**Detects**:
- Missing time filters (major performance issue)
- Incorrect column names or data types
- Dynamic field handling errors (LocationDetails, DeviceDetail)
- Inefficient query patterns
- Deprecated operators or syntax

#### D. ASIM Multi-Source Queries
Generates normalized queries that work across multiple data sources (Azure AD, AWS IAM, Okta, Active Directory).

**Available Schemas**:
- Authentication Event (`imAuthentication`)
- Network Session (`imNetworkSession`)
- File Activity (`imFileEvent`)
- Process Event (`imProcessEvent`)
- DNS Activity (`imDns`)
- 6 more ASIM schemas

**Available MCP Tools** (34 tools):

**Query Generation (5 tools)**:
- `generate_kql_query` - Generate validated KQL from natural language
- `validate_kql_query` - Validate existing queries for correctness
- `generate_query_template` - Get ready-to-use query templates
- `get_query_documentation` - Get Microsoft Learn docs for tables/queries
- `search_github_examples_fallback` - Search GitHub when table not in schema

**Schema Intelligence (8 tools)**:
- `get_table_schema` - Get complete schema for specific table (331+ tables)
- `search_tables` - Find tables using natural language
- `list_table_categories` - Browse 57 table categories
- `get_tables_by_category` - Get all tables in specific category
- `find_column` - Find which tables contain specific column
- `get_schema_statistics` - View schema index coverage stats

**GitHub Community Search (8 tools)**:
- `search_kql_queries` - Search ALL GitHub for KQL queries
- `get_kql_from_file` - Extract queries from specific file
- `search_kql_repositories` - Find repos containing KQL queries
- `search_repo_kql_queries` - Search within specific repo (Azure/Azure-Sentinel)
- `search_user_kql_queries` - Search all repos from user/org
- `search_favorite_repos` - Search configured favorite repositories
- `get_rate_limit` - Check GitHub API rate limit status
- `get_cache_stats` - View cache performance and stats

**ASIM Schema Tools (13 tools)**:
- `search_asim_schemas` - Search for ASIM schemas by keyword
- `get_asim_schema_info` - Get comprehensive schema details
- `list_asim_schemas` - List all 11 ASIM schemas
- `generate_asim_query_template` - Generate ASIM query templates
- `get_asim_parser_recommendations` - Get parser naming/best practices
- `validate_asim_parser` - Validate parser against schema requirements
- `get_asim_parser_requirements` - Get mandatory/recommended fields
- `compare_parser_to_schema` - Compare parser fields to schema
- Plus 5 more ASIM tools for field discovery and validation

**Schema Coverage**:
- **331+ tables** from Defender XDR, Sentinel, Azure Monitor
- **11 ASIM schemas** for normalized security events
- **57 table categories** for easy discovery
- **230+ ASIM fields** with detailed metadata

**Integration with Investigation Workflow**:

**Use Investigation-Guide.md Sample Queries When**:
- Standard investigation patterns (user investigation, incident triage)
- Queries already tested in production
- Investigation follows documented playbooks

**Use KQL Query Builder When**:
- Need custom queries for unique threat scenarios
- Building new Sentinel Analytic Rules
- Optimizing slow queries for performance
- Need ASIM-normalized multi-source queries
- Investigating novel attack patterns not covered in guide

**Workflow Example (Custom Detection Rule)**:
```
1. User: "Create a detection rule for impossible travel"
2. Skill searches GitHub for community examples
3. Generates base query using schema validation
4. Adds MITRE ATT&CK mapping (T1078)
5. Creates entity mappings (Account, IP, Location)
6. Outputs complete Sentinel YAML rule file
```

**Performance**:
- Query generation: ~1-2 seconds
- Schema lookup: <1 second (cached)
- GitHub search: ~2-5 seconds
- Query validation: <1 second

**References**:
- Investigation-Guide.md Section 8 (Sample KQL Queries)
- Investigation-Guide.md Section 14 (Quick Reference - KQL Patterns)
- .github/skills/kql-query-builder/SKILL.md

---

### 6. report-generation

**Purpose**: Generate professional security investigation reports in multiple formats

**Location**: `.github/skills/report-generation/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Generate report for the investigation"
- "Create critical incident report for #41272"

**Report Types**:

#### A. Investigation JSON Reports

**Filename**: `reports/investigation_<upn_prefix>_YYYY-MM-DD.json`

**Schema** (required fields):
```json
{
  "investigationDate": "2026-01-15T09:30:00Z",
  "userPrincipalName": "user@contoso.com",
  "userId": "<USER_OBJECT_ID>",
  "windowsSID": "<WINDOWS_SID>",
  "department": "IT Security",
  "officeLocation": "Building 5",
  "dateRangeStart": "2026-01-08T00:00:00Z",
  "dateRangeEnd": "2026-01-17T23:59:59Z",
  "anomalies": [],
  "signInsByApp": [],
  "signInsByLocation": [],
  "signInFailures": [],
  "auditLogActivity": [],
  "officeActivity": [],
  "securityIncidents": [],
  "ipEnrichment": [],
  "threatIntelligence": [],
  "dlpEvents": [],
  "riskDetections": []
}
```

**Usage**: Machine-readable data for archival, API integration, further analysis

#### B. Incident HTML Reports

**Filename**: `reports/incident_<incident_id>_critical_report.html`

**Features**:
- Dark theme (colors: `#1a1a2e`, `#16213e`, `#00d4ff`)
- MITRE ATT&CK mapping
- Interactive visualizations
- Executive summary (2-3 sentences)
- Chronological timeline
- Threat intelligence analysis
- Immediate actions (Priority 1/2/3 with time bounds)
- Investigation queries (KQL used)
- Long-term recommendations

**Sections**:
1. Header (incident number, severity badge, date)
2. Executive Summary
3. Incident Timeline
4. Technical Details (IOCs, affected assets, attack vectors)
5. Threat Intelligence (IP enrichment with risk scores)
6. MITRE ATT&CK Mapping
7. Immediate Actions (Priority 1: 0-15 min, Priority 2: 15-60 min, Priority 3: 1-24 hrs)
8. Investigation Queries
9. Long-term Recommendations
10. Appendix (raw data, API responses)

**Dark Theme Color Palette**:

| Element | Color | Usage |
|---------|-------|-------|
| Primary Background | `#1a1a2e` | Body background |
| Secondary Background | `#16213e` | Sections |
| Accent | `#00d4ff` | Borders, links |
| Text Primary | `#e0e0e0` | Body text |
| Critical Alert | `#ff4757` | High severity |
| Warning | `#ffa502` | Medium severity |
| Success | `#2ed573` | Low severity |

**References**:
- Investigation-Guide.md Section 17 (Report Template)

---

### 7. endpoint-device-investigation ⭐ NEW

**Purpose**: Comprehensive endpoint device investigation using Microsoft Defender for Endpoint

**Location**: `.github/skills/endpoint-device-investigation/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Investigate device DESKTOP-ABC123"
- "Analyze malware execution on device ID <device_id>"
- "Check for lateral movement from device <name>"
- "What vulnerabilities does this device have?"

**Investigation Phases** (7 phases):

```
Phase 1: Device Identification & Baseline
├─ Get device info (OS, IP, groups)
├─ Establish baseline activity (30 days)
└─ Identify anomalies from baseline

Phase 2: Process Execution Analysis
├─ Recent process activity
├─ Suspicious patterns (encoded PowerShell, LOLBins)
└─ Persistence mechanisms

Phase 3: Network Connections Analysis
├─ External connections (public IPs)
├─ C2 beaconing detection
└─ Data exfiltration indicators

Phase 4: File Operations & Malware
├─ File creation/modification events
├─ Suspicious file locations
├─ File threat intelligence lookup
└─ Track file distribution

Phase 5: Vulnerability Assessment
├─ Device CVE list
├─ Software inventory
└─ Critical vulnerability analysis

Phase 6: Lateral Movement Detection
├─ Logon events (RDP, network)
├─ Credential access attempts
└─ Remote execution indicators

Phase 7: Registry Modifications
├─ Persistence registry keys
└─ Malicious Run key analysis
```

**Key Features**:
- **Device* tables expertise**: DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents
- **MCP tool integration**: GetDefenderMachineById, GetDefenderFileInfo, GetDefenderFileRelatedMachines, ListDefenderVulnerabilitiesBySoftware
- **Pattern recognition**: Living-off-the-Land binaries, C2 beaconing, data exfiltration
- **Process tree reconstruction**: Parent-child process relationships
- **Timeline correlation**: Events across multiple tables within time windows

**Investigation Templates**:
- Malware infection analysis
- Lateral movement investigation
- Data exfiltration investigation

**Workflow Example (Malware Infection)**:
```
1. User: "Investigate device DESKTOP-WIN10-001"
2. Skill retrieves device baseline (30-day activity summary)
3. Analyzes recent process execution for encoded PowerShell, unusual parent-child chains
4. Checks network connections for C2 beaconing patterns
5. Finds file SHA256: abc123... dropped in C:\Users\Public\
6. Enriches file with GetDefenderFileInfo (ThreatName: Trojan:Win32/Emotet)
7. Checks GetDefenderFileRelatedMachines (file on 3 other devices)
8. Lists vulnerabilities with ListDefenderVulnerabilitiesBySoftware
9. Generates timeline with MITRE ATT&CK mapping:
   - T1059.001 PowerShell execution
   - T1071.001 C2 over HTTP
   - T1036.005 Masquerading (svchost.exe in wrong directory)
```

**Performance Expectations**:
- Device baseline analysis: ~10-15 seconds
- Process execution analysis (7 days): ~20-30 seconds
- Network connection analysis (7 days): ~15-20 seconds
- File operations analysis (7 days): ~20-25 seconds
- Vulnerability assessment: ~5-10 seconds
- Complete investigation (all phases): ~2-3 minutes

**Use Cases**:
- Ransomware execution analysis
- Malware persistence detection
- Lateral movement tracking
- Software vulnerability assessment
- Credential theft investigation

**References**:
- Investigation-Guide.md Section 2 (Data Sources - Defender for Endpoint)
- .github/skills/endpoint-device-investigation/SKILL.md

---

### 8. incident-correlation-analytics ⭐ NEW

**Purpose**: Analyze incident patterns, detect campaigns, generate SOC metrics and heatmaps

**Location**: `.github/skills/incident-correlation-analytics/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Generate daily SOC report"
- "Create incident heatmap for the last 7 days"
- "Find incidents with shared IOCs"
- "Detect attack campaigns"
- "Show week-over-week incident trends"
- "Calculate MTTD and MTTR metrics"

**Analytics Phases** (7 phases):

```
Phase 1: Temporal Analysis & Heatmaps
├─ Daily incident heatmap (24-hour view)
├─ Weekly incident heatmap (day-of-week)
└─ Monthly trend analysis

Phase 2: IOC Correlation Across Incidents
├─ Extract IPs from all incidents
├─ Extract file hashes across incidents
├─ User account correlation
└─ Identify IOCs in 3+ incidents (campaigns)

Phase 3: Campaign Detection
├─ Temporal clustering (time-based)
├─ TTP-based clustering (MITRE patterns)
└─ Geographic campaign detection

Phase 4: MITRE ATT&CK Heatmap
├─ Technique frequency analysis
└─ ATT&CK matrix visualization

Phase 5: Detection Source Analytics
├─ Alert volume by product
├─ High-severity percentage
└─ Detection coverage gaps

Phase 6: SOC Metrics & KPIs
├─ Mean Time to Detect (MTTD)
├─ Mean Time to Respond (MTTR)
├─ Incident status distribution
└─ Closure rate calculation

Phase 7: Trend Analysis & Forecasting
├─ Week-over-week growth
└─ Severity trend over time
```

**Key Features**:
- **Heatmap generation**: Hourly, daily, weekly incident distribution
- **Campaign detection**: Time-based, TTP-based, geographic clustering
- **IOC correlation**: Track IPs, hashes, domains across multiple incidents
- **MITRE ATT&CK analysis**: Technique frequency, tactic distribution
- **SOC KPIs**: MTTD/MTTR, closure rates, backlog analysis

**Report Templates**:
- Daily SOC report
- Weekly executive report
- Monthly trend analysis

**Visualizations**:
- Temporal heatmaps (color-coded incident counts)
- Severity trend charts
- Detection source pie charts
- MITRE ATT&CK matrices

**Workflow Example (Daily SOC Report)**:
```
1. User: "Generate daily SOC report for yesterday"
2. Skill queries SecurityIncident table for incidents from yesterday
3. Creates 24-hour heatmap:
   0:00-6:00: ░░░░░░ (2 incidents)
   6:00-12:00: ██████ (15 incidents)  ← Peak hours
   12:00-18:00: ████░░ (9 incidents)
   18:00-24:00: ░░░░░░ (1 incident)
4. Extracts all unique IPs from incidents, identifies:
   - 206.168.34.210 appears in 5 incidents → Campaign candidate
   - 45.155.205.233 appears in 3 incidents → Campaign candidate
5. MITRE ATT&CK frequency:
   - T1078 Valid Accounts: 12 incidents (44%)
   - T1071.001 Application Layer Protocol: 8 incidents (30%)
   - T1110 Brute Force: 6 incidents (22%)
6. SOC Metrics:
   - MTTD: 45 minutes (avg time from FirstActivityTime to creation)
   - MTTR: 3.2 hours (avg time from creation to closure)
   - Closure rate: 78% (21 of 27 incidents)
7. Generates HTML report with dark theme, heatmaps, charts
```

**Performance Expectations**:
- Temporal heatmap generation: ~5-10 seconds
- IOC correlation (7 days): ~20-30 seconds
- Campaign detection: ~15-20 seconds
- MITRE ATT&CK matrix: ~10-15 seconds
- SOC metrics calculation: ~10-15 seconds
- Complete daily report: ~1-2 minutes

**Use Cases**:
- Daily/weekly SOC reporting
- Identifying coordinated attacks
- Campaign tracking and threat actor attribution
- Resource planning (staffing based on volume patterns)
- Detection rule effectiveness analysis

**References**:
- reports/soc_daily_report_2026-01-20.html
- .github/skills/incident-correlation-analytics/SKILL.md

---

### 9. ioc-management ⭐ NEW

**Purpose**: Extract, enrich, deduplicate, and track indicators of compromise (IOCs) throughout their lifecycle

**Location**: `.github/skills/ioc-management/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Extract all IOCs from incident #42001"
- "Enrich these file hashes: <hashes>"
- "Create a watchlist for malicious IPs"
- "Correlate IOCs across incidents"
- "Export IOCs in STIX format"

**IOC Management Phases** (7 phases):

```
Phase 1: IOC Extraction
├─ Extract IPs from incidents
├─ Extract file hashes
├─ Extract domains and URLs
└─ Automated multi-incident extraction

Phase 2: Bulk IOC Enrichment
├─ Enrich IPs (AbuseIPDB, IPInfo, VPNapi)
├─ Get file reputation (Defender)
└─ Domain/URL analysis

Phase 3: Deduplication & Normalization
├─ IP address normalization
├─ Domain normalization
├─ Hash normalization
└─ Remove duplicates across sources

Phase 4: Watchlist Management
├─ Create known-bad IOC watchlist
├─ Create known-good whitelist
└─ Query watchlist in KQL

Phase 5: IOC Correlation Analysis
├─ Cross-incident IOC analysis
├─ Temporal IOC clustering
└─ Infrastructure mapping

Phase 6: IOC Lifecycle Management
├─ IOC aging and expiration
├─ Confidence decay calculation
└─ IOC revalidation

Phase 7: Export & Integration
├─ Export to STIX format
├─ Export to CSV for firewall rules
└─ Create Defender IOC indicators
```

**IOC Types Supported**:
- IP Addresses (IPv4, IPv6)
- Domains (FQDNs, subdomains)
- URLs (HTTP/HTTPS endpoints)
- File Hashes (MD5, SHA1, SHA256)
- Email Addresses
- User Agents
- Registry Keys
- Certificates

**Key Features**:
- **Automated extraction**: Pull IOCs from SecurityIncident and SecurityAlert tables
- **Bulk enrichment**: Process 10+ IOCs in single workflow
- **Deduplication**: Merge IOCs from multiple investigations
- **Watchlist management**: Known-bad and known-good lists
- **Cross-incident correlation**: Find IOCs shared across campaigns
- **Lifecycle tracking**: Expiration, confidence decay, revalidation
- **STIX 2.1 export**: SIEM/SOAR integration
- **Threat actor profiling**: Track infrastructure over time

**Automated Workflows**:
- Daily IOC extraction & enrichment (scheduled at 2 AM)
- Threat actor infrastructure tracking

**Database Structure**:
```
enrichment/ioc-database/
├── watchlist_malicious.json
├── watchlist_benign.json
├── threat_actors/
│   ├── APT28_infrastructure.json
│   └── Emotet_C2.json
├── incidents/
│   ├── incident_41272_iocs.json
│   └── incident_42149_iocs.json
├── enriched/
│   ├── ips_enriched_2026-01-15.json
│   └── hashes_enriched_2026-01-15.json
├── exports/
│   ├── stix_bundle_2026-01-15.json
│   └── firewall_blocklist_2026-01-15.csv
└── archive/
    └── expired_iocs/
```

**Workflow Example (Multi-Incident IOC Campaign)**:
```
1. User: "Extract IOCs from incidents in the last 7 days and find shared infrastructure"
2. Skill queries SecurityIncident table, finds 23 incidents
3. Extracts IOCs from all incidents:
   - 87 unique IP addresses
   - 34 unique file hashes
   - 12 unique domains
4. Normalizes IPs (removes duplicates, converts to lowercase for domains)
5. Enriches all IPs using bulk enrichment:
   - 206.168.34.210: 100% abuse confidence, 1363 reports
   - 45.155.205.233: 88% abuse confidence, 80 reports
6. Identifies shared IOCs (appear in 3+ incidents):
   - 206.168.34.210 → 5 incidents (Campaign 1)
   - evil-domain.com → 4 incidents (Campaign 1)
   - abc123...def (SHA256) → 3 incidents (Campaign 2)
7. Creates watchlist: watchlist_malicious.json with 3 campaign IOCs
8. Exports to STIX 2.1 bundle:
   - Indicator objects with pattern matching
   - Relationship objects linking indicators to campaigns
   - Sighting objects with incident references
9. Exports CSV for firewall: ip,action,severity
   206.168.34.210,block,critical
   45.155.205.233,block,high
```

**Performance Expectations**:
- IOC extraction (single incident): ~5-10 seconds
- IOC extraction (multi-incident, 7 days): ~15-20 seconds
- Bulk enrichment (10 IPs): ~30-45 seconds
- Deduplication & normalization: ~2-3 seconds
- STIX export: ~3-5 seconds
- Complete multi-incident workflow: ~1-2 minutes

**Use Cases**:
- Building threat intelligence feeds
- Creating firewall block lists
- Tracking threat actor infrastructure
- SIEM/SOAR IOC distribution
- Campaign attribution and correlation

**References**:
- .github/skills/threat-enrichment/SKILL.md
- enrichment/enrich_ips.py
- .github/skills/ioc-management/SKILL.md

---

### 10. defender-response ⭐ NEW

**Purpose**: Execute containment and remediation actions using Defender Response MCP VS Code Extension tools during active incident response

**Location**: `.github/skills/defender-response/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Isolate device YOURPC01"
- "Confirm user alice@contoso.com as compromised"
- "Disable AD account for bob"
- "Force password reset for compromised user"
- "Run antivirus scan on SERVER-DC01"
- "Collect forensic package from endpoint"
- "Classify incident 44239 as true positive"
- "Assign incident to soc-lead@contoso.com"
- "Bulk isolate devices due to ransomware"
- "Release device after remediation"

**Response Action Categories** (5 categories, 19 total actions):

```
Category 1: Device Response
├─ Isolate Device          (activate_device_response_tools → defender_isolate_device)
├─ Restrict Code Execution (activate_device_response_tools → defender_restrict_code_execution)
├─ Run AV Scan             (activate_device_response_tools → defender_run_antivirus_scan)
├─ Stop & Quarantine       (activate_device_response_tools → defender_stop_and_quarantine)
├─ Bulk Isolate            (activate_bulk_device_management_tools → defender_isolate_multiple)
└─ Release Device          (activate_bulk_device_management_tools → defender_release_device)

Category 2: Identity Response
├─ Confirm Compromised     (activate_user_compromise_management_tools → defender_confirm_user_compromised)
├─ Confirm Safe            (activate_user_compromise_management_tools → defender_confirm_user_safe)
├─ Disable AD Account      (activate_active_directory_account_management_tools → defender_disable_ad_account)
├─ Enable AD Account       (activate_active_directory_account_management_tools → defender_enable_ad_account)
└─ Force Password Reset    (activate_active_directory_account_management_tools → defender_force_ad_password_reset)

Category 3: Incident Management
├─ Add Comment             (activate_incident_management_tools → defender_add_incident_comment)
├─ Add Tags                (activate_incident_management_tools → defender_add_incident_tags)
├─ Assign Incident         (activate_incident_management_tools → defender_assign_incident)
├─ Classify Incident       (activate_incident_management_tools → defender_classify_incident)
└─ Update Status           (activate_incident_management_tools → defender_update_incident_status)

Category 4: Forensic Collection
├─ Collect Package         (activate_forensic_investigation_tools → defender_collect_investigation_package)
└─ Get Download URI        (activate_forensic_investigation_tools → defender_get_investigation_package_uri)

Category 5: Device Monitoring (Read-Only)
├─ Get Machine Actions     (activate_device_monitoring_tools → defender_get_machine_actions)
└─ Find Machine by Name    (activate_device_monitoring_tools → defender_get_machine_by_name)
```

**Built-in Response Playbooks**:

| Playbook | Trigger | Key Actions |
|----------|---------|-------------|
| Compromised User | Account compromise confirmed | Confirm compromised → Disable AD → Force PW reset → Isolate devices |
| Malware Containment | Active malware detected | Isolate → Stop/quarantine → Restrict code → AV scan → Collect forensics |
| Ransomware / Bulk | Multi-device spread | Bulk isolate → Disable users → Restrict code → AV scan all → Tag critical |
| Post-Remediation | Threat eradicated | Verify clean → Release device → Enable account → Confirm safe → Resolve |

**Safety Rules**:
- ⚠️ **Destructive actions** (isolate, disable, quarantine, force PW reset) always require explicit analyst confirmation
- ✅ **Non-destructive actions** (comment, tag, assign, AV scan, collect forensics) proceed directly
- All actions are documented via incident comments for audit trail

**Integration with Other Skills**:
- **Called by**: incident-investigation (remediation phase), endpoint-device-investigation (containment)
- **Uses**: incident-management tools, device-response tools, AD management tools
- **References**: microsoft-learn-docs (for official remediation procedures)
- **Feeds into**: report-generation (action log for final HTML report)

**Performance Expectations**:
- Isolate device: ~30-60 seconds
- Disable/enable account: ~5-10 seconds
- Force password reset: ~5-10 seconds
- Run AV scan (Quick): ~5-15 minutes (background)
- Run AV scan (Full): ~30-120 minutes (background)
- Collect forensic package: ~5-30 minutes
- Bulk isolate (5 devices): ~2-5 minutes

**References**:
- Investigation-Guide.md Part III (Response Actions via Defender Response MCP Tools)
- .github/skills/defender-response/SKILL.md

---

### 11. exposure-management ⭐ NEW

**Purpose**: Retrieve Exposure Management data, CTEM metrics, CNAPP posture KPIs, and security insights from Microsoft Defender XDR and Defender for Cloud

**Location**: `.github/skills/exposure-management/SKILL.md`

**Triggers**: Copilot activates when you say:
- "What's our exposure posture?"
- "Show me CTEM metrics"
- "What's our vulnerability posture?"
- "Show me choke points and attack paths"
- "What's our CNAPP posture?"
- "Show compliance posture"
- "Container security status"
- "Show permission sprawl / CIEM"
- "DevSecOps findings"

**Investigation Phases** (5 phases):

```
Phase 1: Attack Surface Inventory
├─ 1.1 Asset classification summary (ExposureGraphNodes)
├─ 1.2 Internet-exposed assets
├─ 1.3 RCE-vulnerable assets
└─ 1.4 Onboarding & sensor health

Phase 2: Vulnerability Posture
├─ 2.1 Top vulnerable devices (weighted scoring)
├─ 2.2 Severity distribution (fleet-wide)
├─ 2.3 OS platform breakdown
└─ 2.4 Most prevalent CVEs

Phase 3: Attack Paths & Choke Points
├─ 3.1 Relationship type distribution
├─ 3.2 Top choke points (incoming edge count)
├─ 3.3 Edge type breakdown per choke point
└─ 3.5 Choke point × vulnerability cross-reference

Phase 4: CNAPP Posture & Compliance
├─ 4.1 Attack path analysis (Defender for Cloud)
├─ 4.2 Regulatory compliance (CIS, NIST, PCI-DSS, ISO)
└─ 4.3 Security recommendations (unhealthy/healthy)

Phase 5: Blast Radius Analysis (optional)
└─ 5.1 Sentinel Graph MCP blast radius for specific nodes
```

**Key Features**:
- **Smart phase selection**: Automatically selects which phases to execute based on user intent
- **ExposureGraph expertise**: Queries ExposureGraphNodes/Edges with proper `parse_json(NodeProperties)` handling
- **DeviceTvm inventory**: No time filters on snapshot tables
- **Weighted vulnerability scoring**: `(Critical×4) + (High×2) + (Medium×1) + Low`
- **Choke point analysis**: Cross-references vulnerability data with attack graph topology
- **CNAPP posture**: Azure Resource Graph queries against `securityresources`
- **Remediation prioritization**: P1–P4 structured matrix

**Data Sources**:

| Table | Tool | Notes |
|-------|------|-------|
| `ExposureGraphNodes` | Advanced Hunting | No time filter — inventory snapshot |
| `ExposureGraphEdges` | Advanced Hunting | No time filter — inventory snapshot |
| `DeviceTvmSoftwareVulnerabilities` | Advanced Hunting | No time filter — inventory snapshot |
| `securityresources` | Azure Resource Graph (Data Lake) | Defender for Cloud assessments |

**MCP App Visualizations**:

The `sentinel-exposure-server` MCP App provides 3 inline visualization tools that render the data collected by this skill:

| MCP App Tool | Visualization |
|-------------|---------------|
| `show-exposure-graph` | Force-directed SVG graph with color-coded nodes and choke point analysis |
| `show-vulnerability-dashboard` | Severity distribution, device ranking, OS platforms, top CVEs |
| `show-compliance-posture` | Gauge charts per standard, attack path cards, recommendation table |

See [mcp-apps/README.md](../mcp-apps/README.md) for build and architecture details.

**Performance Expectations**:
- Attack surface inventory (Phase 1): ~15-20 seconds
- Vulnerability posture (Phase 2): ~10-15 seconds
- Choke points & attack paths (Phase 3): ~15-20 seconds
- CNAPP posture (Phase 4): ~10-15 seconds
- Full CTEM dashboard (all phases): ~1-2 minutes

**References**:
- [docs/EXPOSURE_MANAGEMENT.md](EXPOSURE_MANAGEMENT.md) — Full user guide with scoring methodologies
- [docs/XDR_TABLES_AND_APIS.md](XDR_TABLES_AND_APIS.md) — Table schemas and API fallback patterns
- .github/skills/exposure-management/SKILL.md

---

### 12. detection-engineering ⭐ NEW

**Purpose**: Convert community detection rules (Sigma YAML, Splunk SPL) to Microsoft Sentinel analytics rules and Defender XDR custom detections

**Location**: `.github/skills/detection-engineering/SKILL.md`

**Triggers**: Copilot activates when you say:
- "Convert this Sigma rule to Sentinel"
- "Import community detections for T1078"
- "Convert these YAML detection rules to analytic rules"
- "Create a detection rule from this Sigma file"
- "Set up detection-as-code for our repo"

**Workflow (7 phases)**:

```
Phase 1: Ingest Rule (~1-2 sec)
├─ Accept Sigma YAML from file, URL, SigmaHQ path, or pasted content
└─ Support Splunk SPL via intermediate parsing

Phase 2: Parse Sigma YAML (~1 sec)
├─ Extract logsource (product, category, service)
├─ Extract detection logic (selections, conditions, timeframe)
├─ Extract MITRE tags, severity, metadata
└─ Extract projected fields and false positive notes

Phase 3: Map Logsource → Sentinel Table (~2 sec)
├─ Translate Sigma logsource to Sentinel table name
├─ Map Sigma field names to Sentinel column names
├─ Verify schema with get_table_schema()
└─ Determine Data Lake vs Advanced Hunting target

Phase 4: Convert Detection Logic → KQL (~3-5 sec)
├─ Translate selections → where clauses
├─ Translate conditions → boolean logic
├─ Map Sigma modifiers → KQL operators
├─ Handle aggregation and temporal correlation
└─ Apply ASIM normalization if applicable

Phase 5: Validate KQL (~5-10 sec)
├─ Schema validation via validate_kql_query()
├─ Test-execute with | take 0 (dry run)
└─ Test with | take 10 for shape verification

Phase 6: Package as Analytic Rule (~2-3 sec)
├─ Map Sigma level → Sentinel severity
├─ Map Sigma tags → MITRE tactics/techniques
├─ Apply entity mapping templates
├─ Generate YAML rule or ARM template
└─ Set query frequency, period, threshold

Phase 7: Deploy or Export (~1-5 sec)
├─ Save to queries/ library
├─ Export as ARM JSON template
├─ Deploy via Sentinel REST API
└─ Or push to Git for CI/CD pipeline

Total Time: ~15-25 seconds (single rule)
          ~2-5 minutes (batch of 10-20 rules)
```

**Key Features**:
- Comprehensive Sigma logsource → Sentinel table mapping (Windows, Azure/Entra, M365, Linux, Network)
- Full Sigma modifier → KQL operator mapping (contains, startswith, re, cidr, all, windash, base64)
- 9 detection logic translation patterns (simple, list, filter, aggregation, near temporal, 1/all of)
- Entity mapping templates for SigninLogs, SecurityEvent, DeviceProcessEvents, OfficeActivity
- pySigma/sigma-cli integration for automated batch conversion
- SigmAIQ (LLM-enhanced) support
- ARM template and YAML analytic rule output formats
- Sentinel REST API deployment

**Supported Input Formats**:

| Format | Conversion Path |
|--------|-----------------|
| Sigma YAML | Direct — parse → map → convert → KQL |
| Splunk SPL | Parse SPL → extract logic → map to Sigma structure → convert |
| SigmaHQ rule URL | Fetch raw YAML → proceed as Sigma YAML |
| Pasted YAML content | Parse directly → proceed as Sigma YAML |

**Dependencies**:
- Uses: kql-query-builder (schema validation, KQL generation)
- Uses: kql-sentinel-queries (test execution against Sentinel)
- References: microsoft-learn-docs (analytic rule authoring, ASIM docs)
- Optional: pySigma + pySigma-backend-kusto for automated conversion

**References**:
- [references/REFERENCES.md Section 13](../references/REFERENCES.md) — Detection Engineering references
- [SigmaHQ Repository](https://github.com/SigmaHQ/sigma) — 3,000+ community rules
- [pySigma Kusto Backend](https://pypi.org/project/pySigma-backend-kusto/) — Automated conversion
- .github/skills/detection-engineering/SKILL.md

---

## Using Skills with Copilot

### Prerequisites

1. **Enable Agent Skills in VS Code**:
   - Open Settings (Ctrl+,)
   - Search: `chat.useAgentSkills`
   - Check: ✅ Enable agent skills (preview)

2. **Restart VS Code** to load skills

3. **Verify Skills Loaded**:
   - Open folder: `.github/skills/`
   - Check for 12 directories with SKILL.md files

### Example Workflows

#### Example 1: Complete User Investigation

**Prompt**:
```
Investigate jsmith@contoso.com for suspicious activity in the last 7 days
```

**Copilot Actions** (auto-activates incident-investigation skill):

```
[00:03] ✓ Phase 1: Retrieved User ID and Windows SID (3 seconds)
[01:13] ✓ Phase 2: Parallel data collection (70 seconds)
        - Batch 1: Sentinel queries (anomalies, sign-ins, audit logs, incidents)
        - Batch 2: Graph queries (profile, MFA, devices, risk)
        - Batch 3: IP extraction and threat intel correlation
[01:15] ✓ Phase 3: Exported investigation JSON (2 seconds)
        - File: reports/investigation_jsmith_2026-01-15.json
[03:45] ✓ Phase 4: IP enrichment (150 seconds)
        - Enriched 12 priority IPs
        - Found 1 critical IP: 206.168.34.210 (100% abuse confidence)
[03:47] ✓ Phase 5: Generated HTML report (2 seconds)
        - File: reports/investigation_jsmith_2026-01-15.html

Total Time: 3 minutes 47 seconds

Key Findings:
• 3 anomalies detected
• 1 critical IP: 206.168.34.210 (Chicago, US - Censys Inc.)
• 15 unique sign-in locations
• 2 security incidents: #41272 (High), #41301 (Medium)
• No DLP violations

Recommendation: Investigate incident #41272 immediately (C2 communication detected)
```

#### Example 2: IP Threat Analysis

**Prompt**:
```
Is 206.168.34.210 malicious?
```

**Copilot Actions** (auto-activates threat-enrichment skill):

```
Running IP enrichment for 206.168.34.210...

Threat Intelligence Results:

IP Address: 206.168.34.210
Location: Chicago, Illinois, US
ISP: Censys Inc.
Organization: Censys Inc.
Usage Type: Data Center/Web Hosting/Transit

Abuse Intelligence:
• Abuse Confidence Score: 100% (CRITICAL)
• Total Reports: 1,363
• Threat Categories: Port Scan, Brute Force, SSH
• Last Reported: 2026-01-10 14:23:11 UTC

VPN/Proxy Detection:
• VPN: No
• Tor Exit Node: No
• Proxy: No

Risk Assessment: CRITICAL
Recommendation: Block immediately. This IP has maximum abuse confidence 
with 1,363 abuse reports. Highly likely malicious infrastructure.
```

#### Example 3: Policy Change Audit

**Prompt**:
```
Check for Endpoint Protection policy changes this morning
```

**Copilot Actions** (auto-activates kql-sentinel-queries skill):

```
Querying Azure AD audit logs for policy changes...

Date Range: 2026-01-15 00:00:00 to 2026-01-15 23:59:59

KQL Query Executed:
AuditLogs
| where TimeGenerated between (datetime(2026-01-15T00:00:00) .. datetime(2026-01-15T23:59:59))
| where Category == "Policy"
| where OperationName has_any ("Update policy", "Create policy", "Delete policy")
| where TargetResources has "Endpoint" or TargetResources has "Intune"
| project TimeGenerated, OperationName, Result, InitiatedBy.user.userPrincipalName

Results: 0 policy changes

Conclusion: No Endpoint Protection policy changes detected this morning.
```

#### Example 4: Critical Incident Report

**Prompt**:
```
Generate critical incident report for incident #41272
```

**Copilot Actions** (auto-activates report-generation skill):

```
Generating critical incident report for #41272...

Step 1: Retrieved incident details from Defender XDR
        - Incident #41272: Suspicious C2 communication
        - Severity: High
        - Status: Active
        - Affected Asset: contoso-srv1

Step 2: Extracted entities
        - IP: 206.168.34.210
        - Device: contoso-srv1
        - User: Not applicable (device-initiated)

Step 3: Enriched IP 206.168.34.210
        - Abuse Confidence: 100%
        - Location: Chicago, US
        - ISP: Censys Inc.

Step 4: MITRE ATT&CK Mapping
        - T1071: Application Layer Protocol (C2 Communication)

Step 5: Generated HTML report
        - File: reports/incident_report_41272_2026-01-15.html
        - Includes: Executive summary, timeline, threat intel, remediation steps

Report Complete: reports/incident_report_41272_2026-01-15.html

Executive Summary:
Command & Control (C2) communication detected from critical asset contoso-srv1 
to known malicious IP 206.168.34.210 (100% abuse confidence, 1,363 reports). 
Immediate isolation required.
```

---

## Skill Development Guide

### Creating a New Skill

Follow these steps to add custom skills to CyberProbe:

#### Step 1: Plan Your Skill

Answer these questions:
- **Purpose**: What problem does this skill solve?
- **Triggers**: What prompts should activate this skill?
- **Dependencies**: Does it need data from other skills?
- **Outputs**: What files/data does it produce?

#### Step 2: Create Skill Directory

```powershell
# Create skill directory
New-Item -ItemType Directory -Path ".github/skills/my-new-skill"
```

#### Step 3: Create SKILL.md

```markdown
---
name: my-new-skill
description: Brief description of what this skill does (max 1024 characters). Use when [trigger conditions].
---

# My New Skill

## When to Use This Skill

Use this skill when:
- [Condition 1]
- [Condition 2]

## Prerequisites

1. [Requirement 1]
2. [Requirement 2]

## Workflow

### Step 1: [Action Name]
[Detailed instructions...]

### Step 2: [Action Name]
[Detailed instructions...]

## Output Format

[Expected outputs...]

## Example Scenarios

### Scenario 1: [Name]
```
User: "[Example prompt]"

Response:
[Expected behavior]
```

## Resources

- [Link to related file 1]
- [Link to related file 2]

## Important Notes

⚠️ [Critical information...]
```

#### Step 4: Add Supporting Files (Optional)

```
.github/skills/my-new-skill/
├── SKILL.md                    # Main skill (required)
├── examples/                   # Example code
│   └── example_output.json
├── templates/                  # Templates
│   └── template.html
└── scripts/                    # Helper scripts
    └── process_data.py
```

#### Step 5: Test the Skill

1. Restart VS Code to reload skills
2. Ask Copilot a question that should trigger the skill
3. Verify Copilot follows the workflow correctly
4. Check that outputs match expected format

#### Step 6: Document Integration

Update these files to reference your new skill:

- **Investigation-Guide.md**: Add to Section 18 (Agent Skills)
- **docs/AGENT_SKILLS.md**: Add detailed documentation
- **README.md**: Mention in features section

### Best Practices for Skill Development

✅ **Clear Names**: Use descriptive, lowercase-hyphenated names
- Good: `authentication-tracing`, `malware-analysis`
- Bad: `Skill1`, `newSkill`, `auth_trace`

✅ **Focused Purpose**: One skill = one workflow
- Good: `ip-enrichment` (single purpose)
- Bad: `everything-security` (too broad)

✅ **Example-Driven**: Include realistic examples
```markdown
## Example Scenarios

### Scenario 1: Analyze Malware Sample
```
User: "Analyze file hash abc123..."

Response:
1. Query VirusTotal API
2. Check internal sandbox results
3. Generate malware analysis report
```
```

✅ **Progressive Disclosure**: Start simple, add detail
```markdown
# Skill Overview (high-level)

## Quick Start (basic usage)

## Advanced Workflows (detailed procedures)

## Technical Reference (API details, schemas)
```

✅ **Error Handling**: Document common issues
```markdown
## Error Handling

| Error | Cause | Solution |
|-------|-------|----------|
| API timeout | Network issue | Retry with exponential backoff |
```

✅ **Performance Metrics**: Set expectations
```markdown
## Performance Expectations

- Small dataset (1-10 items): ~5-10 seconds
- Medium dataset (10-100 items): ~30-60 seconds
- Large dataset (100+ items): ~2-5 minutes
```

---

## Integration with CyberProbe

### How Skills Use CyberProbe Components

Skills are not standalone—they leverage existing CyberProbe infrastructure:

| Skill | CyberProbe Component | Purpose |
|-------|---------------------|---------|
| incident-investigation | Investigation-Guide.md Section 8 | KQL query library |
| incident-investigation | MCP tools (mcp_microsoft_sen_query_lake) | Query execution |
| threat-enrichment | enrichment/enrich_ips.py | IP enrichment script |
| threat-enrichment | enrichment/config.json | API keys (AbuseIPDB, IPInfo, VPNapi, Shodan) |
| kql-sentinel-queries | Investigation-Guide.md Section 8 | Pre-built queries |
| kql-sentinel-queries | Investigation-Guide.md Section 9 | SessionId tracing workflow |
| kql-query-builder | KQL Search MCP server | 331+ table schemas, query validation |
| microsoft-learn-docs | Microsoft Learn MCP tools | Official documentation and code samples |
| report-generation | Investigation-Guide.md Section 17 | Report template |
| endpoint-device-investigation | Device* Advanced Hunting tables | Device forensic analysis |
| incident-correlation-analytics | SecurityIncident/SecurityAlert tables | SOC metrics and trending |
| ioc-management | threat-enrichment, enrichment/enrich_ips.py | Bulk IOC enrichment |
| defender-response | Defender Response MCP tools | Containment and remediation |
| exposure-management | ExposureGraph*, DeviceTvm*, Azure Resource Graph | CTEM and CNAPP posture |
| detection-engineering | kql-query-builder, SigmaHQ ecosystem | Sigma-to-Sentinel conversion |

### Skill → Component Flow

**Example: incident-investigation skill**

```
User: "Investigate user@contoso.com"
  ↓
Copilot activates: incident-investigation skill
  ↓
Skill reads: Investigation-Guide.md Section 8 (Query 1, 2, 3a/b/c/d, 4, 5, 6, 10, 11)
  ↓
Skill executes: mcp_microsoft_sen_query_lake for each query
  ↓
Skill calls: threat-enrichment skill for priority IPs
  ↓
threat-enrichment runs: python enrichment/enrich_ips.py <IPs>
  ↓
threat-enrichment reads: enrichment/config.json for API keys
  ↓
Skill calls: report-generation skill
  ↓
report-generation reads: Investigation-Guide.md Section 17 (template)
  ↓
report-generation creates: reports/investigation_user_2026-01-15.html
  ↓
Copilot returns: Summary with file paths and key findings
```

### Configuration Files Used by Skills

**enrichment/config.json** (gitignored — copy from `config.json.template`):
```json
{
  "sentinel_workspace_id": "YOUR_SENTINEL_WORKSPACE_GUID",
  "tenant_id": "YOUR_ENTRA_TENANT_GUID",
  "api_keys": {
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "ipinfo": "YOUR_IPINFO_TOKEN",
    "vpnapi": "YOUR_VPNAPI_KEY",
    "shodan": "YOUR_SHODAN_KEY"
  },
  "settings": {
    "output_dir": "enrichment",
    "max_workers": 3,
    "timeout_seconds": 10
  }
}
```

Used by:
- threat-enrichment skill
- enrichment/enrich_ips.py

**Investigation-Guide.md**:
- Complete investigation manual
- KQL query library (Section 8)
- SessionId tracing workflow (Section 9)
- Best practices (Section 15)

Referenced by:
- All 4 skills
- Primary knowledge base

### MCP Tools Used by Skills

| MCP Tool | Used By Skill | Purpose |
|----------|--------------|---------|
| mcp_microsoft_sen_query_lake | kql-sentinel-queries | Execute KQL on Sentinel |
| mcp_microsoft_sen_search_tables | kql-sentinel-queries | Discover table schemas |
| mcp_microsoft_graph_get | incident-investigation | Get user profile/ID |
| mcp_triage_ListIncidents | incident-investigation | List Defender incidents |
| mcp_triage_GetIncidentById | report-generation | Get incident details |

---

## Examples and Use Cases

### Use Case 1: Ransomware Investigation

**Scenario**: User reports encrypted files on device DESKTOP-ABC123

**Prompt**:
```
Investigate ransomware on device DESKTOP-ABC123
```

**Skills Activated**:
1. **incident-investigation** (primary orchestrator)
2. **kql-sentinel-queries** (device-specific queries)
3. **threat-enrichment** (C2 IP enrichment)
4. **report-generation** (incident report)

**Workflow**:
```
1. incident-investigation: Query DeviceInfo for DESKTOP-ABC123
2. kql-sentinel-queries: Execute device-specific queries
   - DeviceFileEvents (ransomware file modifications)
   - DeviceProcessEvents (ransomware process execution)
   - DeviceNetworkEvents (C2 communication)
3. threat-enrichment: Enrich C2 IPs
4. incident-investigation: Find related incidents/alerts
5. report-generation: Create incident report with MITRE ATT&CK mapping
   - T1486: Data Encrypted for Impact
   - T1071: Application Layer Protocol (C2)
```

**Output**:
- `reports/incident_ransomware_DESKTOP-ABC123_2026-01-15.html`
- MITRE ATT&CK mapping
- Remediation steps with time bounds
- IOCs for network blocking

### Use Case 2: Phishing Investigation

**Scenario**: User clicked suspicious link in email

**Prompt**:
```
Investigate phishing incident for user@contoso.com - suspicious email from external sender
```

**Skills Activated**:
1. **incident-investigation** (user investigation)
2. **kql-sentinel-queries** (EmailEvents queries)
3. **threat-enrichment** (URL/IP enrichment)
4. **report-generation** (phishing report)

**Workflow**:
```
1. incident-investigation: Get user ID for user@contoso.com
2. kql-sentinel-queries: Query EmailEvents
   EmailEvents
   | where TimeGenerated > ago(7d)
   | where RecipientEmailAddress == "user@contoso.com"
   | where SenderFromAddress !endswith "@contoso.com"  # External only
   | where UrlCount > 0 or AttachmentCount > 0
   | project TimeGenerated, SenderFromAddress, Subject, UrlCount, AttachmentCount

3. kql-sentinel-queries: Extract URLs from EmailUrlInfo
4. threat-enrichment: Enrich malicious domains/IPs
5. kql-sentinel-queries: Check if user clicked link (CloudAppEvents)
6. incident-investigation: Find related Defender for Office 365 alerts
7. report-generation: Generate phishing incident report
```

**Output**:
- `reports/investigation_user_2026-01-15.html`
- Email metadata (sender, subject, URLs)
- URL enrichment (malicious/benign)
- User actions (clicked/not clicked)
- Related alerts

### Use Case 3: Insider Threat Detection

**Scenario**: Unusual data exfiltration from trusted user

**Prompt**:
```
Deep dive investigation for admin@contoso.com - possible insider threat
```

**Skills Activated**:
1. **incident-investigation** (comprehensive 30-day investigation)
2. **kql-sentinel-queries** (DLP, Office365, AuditLogs)
3. **threat-enrichment** (external IPs)
4. **report-generation** (comprehensive report)

**Workflow**:
```
1. incident-investigation: Extended date range (30 days)
2. kql-sentinel-queries: Run insider threat query set
   - Query 4: Azure AD audit logs (privilege escalation)
   - Query 5: Office 365 activity (unusual SharePoint/OneDrive downloads)
   - Query 10: DLP events (policy violations)
   - Custom Query: Large file transfers
     OfficeActivity
     | where TimeGenerated > ago(30d)
     | where UserId == "admin@contoso.com"
     | where Operation in ("FileDownloaded", "FileCopied")
     | where ItemSize_bytes > 100000000  # 100 MB threshold
     | summarize TotalGB = sum(ItemSize_bytes)/1GB by bin(TimeGenerated, 1d)

3. threat-enrichment: Enrich external IPs (personal cloud storage?)
4. incident-investigation: Behavioral analysis
   - Compare to baseline (avg downloads/day)
   - Detect spikes in activity
5. report-generation: Insider threat report
   - Timeline of suspicious activities
   - Data volume charts
   - Risk assessment
```

**Output**:
- `reports/investigation_admin_2026-01-15.html`
- 30-day activity timeline
- Data exfiltration volume (GB/day)
- DLP violations
- Risk score with justification

---

## Troubleshooting

### Common Issues

#### Issue 1: Skills Not Activating

**Symptoms**:
- Copilot doesn't follow skill workflows
- Generic responses instead of CyberProbe-specific instructions

**Diagnosis**:
```powershell
# Check if skills directory exists
Test-Path ".github/skills"

# List all skills
Get-ChildItem ".github/skills" -Recurse -Filter "SKILL.md"
```

**Solutions**:
1. **Enable Agent Skills**: Settings → `chat.useAgentSkills` → ✅ Enable
2. **Restart VS Code**: File → Exit → Reopen
3. **Check YAML frontmatter**: Ensure `name` and `description` fields exist
4. **Verify file extension**: Must be `SKILL.md` not `SKILL.txt`

#### Issue 2: Skill Errors During Execution

**Symptoms**:
- Copilot starts workflow but fails mid-execution
- Missing data in outputs

**Common Causes**:

**A. Missing Configuration**
```powershell
# Check config.json exists
Test-Path "enrichment/config.json"

# Verify API keys
Get-Content "enrichment/config.json" | ConvertFrom-Json
```

**Solution**: Ensure `enrichment/config.json` has all required fields

**B. MCP Tools Unavailable**
```
Error: Tool 'mcp_microsoft_sen_query_lake' not found
```

**Solution**: Check MCP server is running and connected

**C. Missing Dependencies**
```
Error: Module 'requests' not found
```

**Solution**:
```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### Issue 3: Incorrect Query Results

**Symptoms**:
- Empty results when data should exist
- Wrong date ranges in queries

**Diagnosis**:
```kql
# Test query directly in Sentinel
SigninLogs
| where TimeGenerated > ago(7d)
| take 10
```

**Solutions**:
1. **Check Date Ranges**: Skills add +2 day buffer—verify this is correct
2. **Verify User ID**: Ensure Graph API returned valid user_id
3. **Check Table Names**: Use `mcp_microsoft_sen_search_tables` to verify schema

#### Issue 4: IP Enrichment Failures

**Symptoms**:
```
Error: Rate limit exceeded (AbuseIPDB)
Error: Invalid API key (IPInfo)
```

**Solutions**:

**A. Rate Limits**:
- AbuseIPDB: 1,000 requests/day (free tier)
- IPInfo: 50,000 requests/month (free tier)
- VPNapi: 1,000 requests/month (free tier)

**Action**: Wait 24 hours or upgrade API tier

**B. Invalid API Keys**:
```powershell
# Test API keys manually
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8" `
  -H "Key: YOUR_API_KEY" `
  -H "Accept: application/json"
```

**Solution**: Generate new API keys if expired

#### Issue 5: Report Generation Failures

**Symptoms**:
- JSON file created but HTML missing
- HTML report has missing sections

**Diagnosis**:
```powershell
# Check JSON schema
$json = Get-Content "reports/investigation_user_2026-01-15.json" | ConvertFrom-Json
$json | Get-Member
```

**Solutions**:
1. **Verify Required Fields**: JSON must have all fields from schema
2. **Handle Null Values**: Use `"Unknown"` not `null` for optional strings
3. **Empty Arrays**: Use `[]` not `null` for missing data

---

## Resources

### Official Documentation

- **VS Code Agent Skills**: https://code.visualstudio.com/docs/copilot/customization/agent-skills
- **Agent Skills Standard**: https://agentskills.io
- **Microsoft Sentinel**: https://learn.microsoft.com/azure/sentinel/
- **Defender XDR**: https://learn.microsoft.com/defender-xdr/
- **KQL Reference**: https://learn.microsoft.com/azure/data-explorer/kql-quick-reference

### CyberProbe Documentation

- [Investigation-Guide.md](../Investigation-Guide.md) - Complete investigation manual
- [README.md](../README.md) - Platform overview and setup
- [.github/skills/](../.github/skills/) - All skill files

### Community Resources

- **GitHub Awesome Copilot**: https://github.com/github/awesome-copilot
- **Anthropic Skills**: https://github.com/anthropics/skills
- **KQL Hunting Queries**: https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries
- **Sentinel Community**: https://github.com/Azure/Azure-Sentinel

### API Documentation

- **AbuseIPDB**: https://docs.abuseipdb.com/
- **IPInfo**: https://ipinfo.io/developers
- **VPNapi**: https://vpnapi.io/docs
- **Microsoft Graph**: https://learn.microsoft.com/graph/api/overview

---

## Appendix: Skill Quick Reference

### Skill Trigger Keywords

Use these keywords to activate specific skills:

| Skill | Trigger Keywords |
|-------|-----------------|
| incident-investigation | investigate, security investigation, user investigation, analyze user, check user activity |
| threat-enrichment | enrich, threat intelligence, IP analysis, is malicious, abuse confidence, VPN detection |
| kql-sentinel-queries | query, KQL, Sentinel, sign-in logs, audit logs, policy changes, anomalies |
| kql-query-builder | write KQL, create KQL query, help with KQL, build query, validate query |
| microsoft-learn-docs | Microsoft docs, how to remediate, official guidance |
| report-generation | generate report, create report, export, HTML report, incident report |
| endpoint-device-investigation | investigate device, check machine, endpoint forensics, malware |
| incident-correlation-analytics | incident trends, campaign detection, SOC metrics, heatmap, MTTA |
| ioc-management | IOC, indicators of compromise, watchlist, threat intel feed |
| defender-response | isolate device, block user, containment, response action |
| exposure-management | exposure posture, CTEM metrics, attack surface, choke points, CNAPP, compliance |
| detection-engineering | convert sigma, sigma rule, sigma to sentinel, detection rule, community detection, import detection, analytic rule from YAML, detection-as-code |

### Naming Conventions

**Reports**:
- Investigation JSON: `investigation_<upn>_YYYY-MM-DD.json`
- Investigation HTML: `investigation_<upn>_YYYY-MM-DD.html`
- Incident report: `incident_report_<id>_YYYY-MM-DD.html`
- IP enrichment: `ip_enrichment_<count>_ips_YYYY-MM-DD.json`

**Directories**:
- Reports: `reports/`
- Enrichment data: `enrichment/`
- Skills: `.github/skills/`

### Performance Benchmarks

| Operation | Time | Notes |
|-----------|------|-------|
| Get User ID (Phase 1) | ~3 sec | Graph API call |
| Parallel Queries (Phase 2) | ~60-70 sec | 16 concurrent queries |
| JSON Export (Phase 3) | ~1-2 sec | File write |
| IP Enrichment (Phase 4) | ~2-3 min | 15 IPs, 3 APIs each |
| HTML Report (Phase 5) | ~1-2 sec | Template rendering |
| **Total (Standard Investigation)** | **~5-6 min** | 7-day date range |

---

**Last Updated**: April 14, 2026  
**Version**: 1.4.0  
**Maintainer**: CyberProbe Security Team
