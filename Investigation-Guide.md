# Defender XDR Investigation Guide - Advanced Edition

## Overview

This comprehensive guide serves as the **Orchestration Layer** for security investigations, designed for both human analysts and AI agents following the Microsoft Security Agent architecture pattern.

### Security Agent Architecture

This guide implements the "Anatomy of a Security Agent" pattern:

```
┌─────────────────────────────────────────────────────────────┐
│  User Experience: VS Code Copilot Chat / Manual Analysis    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  ORCHESTRATION: Investigation-Guide.md                      │
│  • Workflow Rules         • Investigation Playbooks         │
│  • Task Steps             • Investigation Guidelines        │
│  ┌───────────┬─────────────────┬─────────────┬───────────┐ │
│  │Alert Triage│Compromised Acct│  Phishing   │  Insider  │ │
│  └───────────┴─────────────────┴─────────────┴───────────┘ │
└─────────────────────────────────────────────────────────────┘
        │                                           │
        ▼                                           ▼
┌──────────────────────┐               ┌──────────────────────┐
│  KNOWLEDGE (MCP)     │               │  SKILLS (MCP)        │
│  Grounding, memory   │               │  Actions, triggers   │
│  from Sentinel Lake  │               │  workflows           │
│  ────────────────    │               │  ────────────────    │
│  • Alerts            │               │  • Reset password    │
│  • Incidents         │               │  • Block IP          │
│  • Sign-in logs      │               │  • Disable user      │
│  • Devices           │               │  • Update policy     │
└──────────────────────┘               └──────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Security Foundation Models (Claude/GPT via VS Code Copilot)│
└─────────────────────────────────────────────────────────────┘
```

### Dual-Purpose Design

| Component | Human Analyst Use | AI Agent Use |
|-----------|-------------------|--------------|
| **Orchestration** | Playbooks to follow | Mandatory instruction set |
| **Knowledge Tools** | Reference for API calls | Direct MCP tool invocation |
| **Skills Tools** | Response action guidance | Automated remediation |
| **Reference** | Copy/paste queries | Query templates for execution |

### MCP Server Integration

Primary interaction layers via Model Context Protocol:
- **Sentinel MCP Server** (`mcp_data_explorat_*`) - KQL queries, entity analysis
- **Triage MCP Server** (`mcp_triage_*`) - Defender XDR incidents, devices, files
- **Microsoft Graph MCP Server** - Identity and directory data
- **Microsoft Learn MCP Server** - Documentation and code samples
- **Agent Creation MCP Server** - Custom agent building
- **GitHub MCP Server** - Code search and repo management

---

## 📑 Table of Contents

### Part I: ORCHESTRATION
*Rules, instructions, tasks/steps, guidelines*

1. [Critical Workflow Rules](#critical-workflow-rules---read-first) - ⚠️ **START HERE** - Mandatory patterns
2. [Quick Start Guide](#quick-start-guide) - 5-step investigation pattern
3. [Investigation Types](#investigation-types) - Alert Triage, Compromised Account, Phishing, Insider
4. [Investigation Playbooks](#12-investigation-playbooks) - Step-by-step incident response guides
5. [Common Investigation Scenarios](#13-common-investigation-scenarios) - Real-world examples

### Part II: KNOWLEDGE (MCP Tools)
*Grounding, memory, and context from Sentinel Lake*

6. [Sentinel Data Lake Tools](#sentinel-data-lake-tools-mcp_data_explorat_) - KQL queries, entity analysis
7. [Defender XDR - Incidents & Alerts](#defender-xdr---incidents--alerts-mcp_triage_) - Incident data
8. [Defender XDR - Devices & Endpoints](#defender-xdr---devicesendpoints-mcp_triage_) - Device forensics
9. [Defender XDR - Files & IOCs](#defender-xdr---files--iocs-mcp_triage_) - File analysis, indicators
10. [Defender XDR - Users & IPs](#defender-xdr---user-analysis-mcp_triage_) - User/IP investigation
11. [Sentinel Graph](#sentinel-graph-server-mcp_microsoft_mcp_microsoft_graph_) - Identity, blast radius, attack paths 🆕
12. [Sentinel Custom Graphs](#microsoft-sentinel-custom-graphs-vs-code-extension) - Visual graph analysis with GQL
13. [External Threat Intelligence](#11-external-enrichment-integration) - AbuseIPDB, VirusTotal, etc.

### Part III: SKILLS (Response Actions)
*Actions, triggers, workflows*

14. [Identity Response Actions](#identity-response-actions) - Reset password, disable user, revoke sessions
15. [Endpoint Response Actions](#endpoint-response-actions) - Isolate device, block hash, restrict execution
16. [Network Response Actions](#network-response-actions) - Block IP, create IOC indicators
17. [Vulnerability Remediation](#defender-xdr---vulnerabilities--remediation-mcp_triage_) - CVE tracking, remediation
18. [Agent Creation Tools](#security-copilot-agent-creation-server-mcp_agent_creatio_) - Build custom agents

### Part IV: REFERENCE
*Query library, best practices, templates*

19. [Sample KQL Queries](#8-sample-kql-queries) - Production-validated query library
20. [Advanced Authentication Analysis](#9-advanced-authentication-analysis) - SessionId tracing
21. [Architecture & Data Sources](#1-architecture--components) - Platform overview
22. [Quick Reference](#14-quick-reference) - KQL syntax and patterns
23. [Best Practices](#15-best-practices) - Optimization guidelines
24. [Troubleshooting](#16-troubleshooting-guide) - Common issues and solutions
25. [Investigation Report Template](#17-investigation-report-template) - Standardized reports
25. [Agent Skills](#18-agent-skills) - VS Code Copilot Skills
26. [MCP Server Configuration](#mcp-server-configuration-reference) - mcp.json setup
27. [Resources](#19-resources) - Documentation and community links

---

# Part I: ORCHESTRATION
*Rules, instructions, tasks/steps, guidelines*

---

## ⚠️ Critical Workflow Rules - READ FIRST ⚠️

### For Manual Investigations (Human Analysts)

**Query Development Best Practices:**
1. **ALWAYS check "Sample KQL Queries" section FIRST** before writing custom queries
2. **Use documented queries as-is** - they handle common pitfalls and field parsing issues
3. **For custom scenarios not in samples**: Use the **kql-query-builder** skill to generate validated queries
4. **Only write queries manually** if both sample queries AND kql-query-builder don't cover your use case
5. Test queries with `| take 1` first to inspect raw schema before expanding
6. **Use `| getschema` for unfamiliar tables** - Schema varies between tenants and documentation may be outdated

**Schema Discovery Pattern (Prevents Semantic Errors):**
```kql
// ALWAYS run this FIRST for unfamiliar tables
ThreatIntelIndicators | getschema

// Common tables requiring schema verification:
// - ThreatIntelIndicators (columns differ from docs: ObservableKey/ObservableValue, not ThreatType/Source)
// - SecurityAlert (AdditionalData varies by provider)
// - SecurityIncident (RelatedAlerts structure varies)
// - Custom columns via data connectors
```

**Why this matters:**
- Sample queries include proper field handling for dynamic JSON fields
- They avoid errors on `LocationDetails`, `ModifiedProperties`, `DeviceDetail` (must use `parse_json()`)
- They're production-validated and optimized
- kql-query-builder validates against 331+ table schemas automatically

### For Automated Investigations (AI-Assisted)

**🔍 When Copilot Receives Investigation Requests:**

**BEFORE executing ANY queries:**
1. ✅ **Check if investigation JSON already exists** for that user/date range
2. ✅ **Search this guide for relevant query patterns** (use Sample KQL Queries section)
3. ✅ **Follow the complete automated workflow** (see Quick Start Guide section)
4. ✅ **Track and report timing after each major step** - NO EXCEPTIONS

**🚨 Authentication Tracing Requests:**

When user asks to "trace authentication", "trace back to interactive MFA", or investigate geographic anomalies:

**→ YOU MUST FOLLOW THE COMPLETE WORKFLOW IN:**  
**[Advanced Authentication Analysis](#advanced-authentication-analysis) section**

**DO NOT improvise or use general security knowledge.**

**The documented workflow includes:**
1. Get SessionId from suspicious IP(s)
2. Trace complete authentication chain by SessionId
3. Find interactive MFA (if not in chain results)
4. Extract ALL unique IPs from authentication chain
5. Analyze IP enrichment data from investigation JSON
6. Document risk assessment using enrichment context + quoted criteria
cd 
**Skipping these steps will result in incomplete or incorrect analysis.**

### Follow-Up Analysis Requirements

**⚠️ BEFORE answering ANY follow-up question about existing investigations:**

1. ✅ **Check if investigation JSON exists** in `reports/` directory (naming: `investigation_<upn_prefix>_YYYY-MM-DD.json`)
2. ✅ **Search this guide for relevant guidance** (use grep_search with topic keyword)
3. ✅ **Read `ip_enrichment` array in JSON** for IP context (VPN, abuse scores, threat intel)
4. ✅ **Only query Sentinel/Graph if data is missing** from enriched JSON

**Common follow-up patterns requiring JSON data:**
- "Trace authentication for [IP/location]" → Read `ip_enrichment` + `signin_ip_counts`
- "Is that a VPN?" → Read `ip_enrichment` array, check `is_vpn` field
- "What's the risk level?" → Read `ip_enrichment`, check `risk_level` + `abuse_confidence_score`
- "Tell me about [IP address]" → Read `ip_enrichment`, filter by `ip` field
- "Was that IP flagged?" → Read `ip_enrichment`, check `threat_description`

**DO NOT re-query threat intel or sign-in data if it's already in the JSON file!**

---

## Quick Start Guide

### For Manual Investigations (Analysts)

When investigating a security incident manually:

1. **Identify the scope:** User, device, or IP-based investigation
2. **Check relevant playbook:** See Investigation Playbooks section for your incident type
3. **Use sample queries:** Copy from Sample KQL Queries section (modify dates/UPN)
4. **Enrich findings:** Use External Enrichment section for IP/hash analysis
5. **Document findings:** Use Investigation Report Template section

### For Automated Investigations (AI-Assisted)

When Copilot receives: "Investigate user@domain.com for the last 7 days"

**5-Step Automated Pattern:**

**Phase 1: Get User ID (Required First)**
```
mcp_microsoft_mcp_microsoft_graph_get("/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier")
```
Extract `user_id` (Azure AD Object ID) and `onPremisesSecurityIdentifier` (Windows SID) - required for SecurityIncident and Identity Protection queries.

**Phase 2: Parallel Data Collection**
- **Batch 1:** Run 10 Sentinel queries in parallel (anomalies, sign-ins, audit logs, incidents, etc.)
- **Batch 2:** Run 6 Graph queries in parallel (profile, MFA, devices, Identity Protection)
- **Batch 3:** After Batch 1 completes, extract IPs and run threat intel enrichment

Report time after each batch completes: `[MM:SS] ✓ Description (XX seconds)`

**Phase 3: Export to JSON**
```
create_file("temp/investigation_<upn_prefix>_<timestamp>.json", json_content)
```
Merge all query results into single JSON file with required structure.

**Phase 4: Generate Report**
```powershell
$env:PYTHONPATH = "CyberProbe"
.venv\Scripts\python.exe generate_report_from_json.py temp/investigation_<upn_prefix>_<timestamp>.json --output reports/
```

**Report Naming Convention:**
All generated reports MUST follow this standardized naming convention:
- **Investigation Reports:** `investigation_<upn_prefix>_YYYY-MM-DD.{json|html}`
  - Example: `investigation_jdoe_2026-01-12.json`, `investigation_jdoe_2026-01-12.html`
- **IP Enrichment Reports:** `ip_enrichment_<count>_ips_YYYY-MM-DD.json`
  - Example: `ip_enrichment_15_ips_2026-01-12.json`
- **Incident Reports:** `incident_report_<incident_id>_YYYY-MM-DD.html`
  - Example: `incident_report_INC001234_2026-01-12.html`
- **Executive Reports:** `executive_report_YYYY-MM-DD.html`
  - Example: `executive_report_2026-01-12.html`

**Required Format Rules:**
- Use lowercase for prefixes (investigation, incident, executive, ip_enrichment)
- Use underscores (_) as separators, NOT hyphens in prefixes
- Date format: YYYY-MM-DD (ISO 8601)
- UPN prefix: lowercase, alphanumeric only (extract before @ symbol)
- All reports saved to `reports/` directory

**Phase 5: Track Total Time**
Report comprehensive timeline breakdown with total elapsed time.

**Expected Performance:**
- Phase 1: ~3 seconds (User ID)
- Phase 2: ~60-70 seconds (Parallel queries)
- Phase 3: ~1-2 seconds (JSON export)
- Phase 4: ~3-5 minutes (Report generation with IP enrichment)
- **Total: ~5-6 minutes**

---

## Investigation Types

All investigations use the automated MCP workflow described in Quick Start section (when AI-assisted) or manual query execution (when analyst-driven).

### Standard Investigation (7 days)
**When to use:** General security reviews, routine investigations, typical anomaly analysis

**Example prompts:**
- "Investigate user@contoso.com for the last 7 days"
- "Run security investigation for user@domain.com from 2026-01-01 to 2026-01-07"

**Date range:** 7 days (configurable)

### Quick Investigation (1 day)
**When to use:** Urgent cases, recent suspicious activity, active incident response

**Example prompts:**
- "Quick investigate suspicious.user@domain.com"
- "Run quick security check on admin@company.com"

**Date range:** Last 24 hours

### Comprehensive Investigation (30 days)
**When to use:** Deep-dive analysis, compliance reviews, thorough forensics, historical pattern analysis

**Example prompts:**
- "Full investigation for compromised.user@domain.com"
- "Do a deep dive investigation on external.user@partner.com"

**Date range:** 30 days (captures long-term behavioral patterns)

**All types include:** Anomaly detection, sign-in analysis, IP enrichment, Graph identity data, device compliance, audit logs, Office 365 activity, security alerts, threat intelligence, risk assessment, and automated recommendations

---

## 1. Architecture & Components
*Understanding the platform architecture and available security tools*

This section describes the core platform components and how they integrate to provide comprehensive security visibility.

## Architecture Components

### Core Platform
- **Microsoft Sentinel** - Cloud-native SIEM and SOAR platform
- **Sentinel Data Lake** - Central data repository for all security telemetry
- **Sentinel MCP Server** - Model Context Protocol server for programmatic access
- **Microsoft Learn MCP Server** - Official documentation and code sample retrieval
- **Microsoft Defender XDR** - Extended Detection and Response suite

### Defender XDR Components (E5 Security)
- **Defender for Endpoint** - Endpoint detection and response (EDR)
- **Defender for Identity** - Identity threat detection
- **Defender for Office 365** - Email and collaboration protection
- **Defender for Cloud Apps** - Cloud access security broker (CASB)
- **Defender for Cloud** - Cloud security posture management (CSPM)

---

## 2. Data Sources
*Available tables and data repositories for security investigations*

This section catalogs all available data sources across the Defender XDR suite, organized by product. Use this reference to identify which tables contain the data you need for your investigation.

### Primary Data Sources via Sentinel

#### Defender XDR Tables
- **SecurityAlert** - Unified alerts from all Defender products
- **SecurityIncident** - Correlated incidents across multiple alerts
- **IdentityInfo** - Identity metadata and relationships
- **IdentityLogonEvents** - Authentication activities
- **IdentityQueryEvents** - Active Directory queries
- **IdentityDirectoryEvents** - AD object changes

#### Defender for Endpoint Tables
- **DeviceInfo** - Device inventory and properties
- **DeviceNetworkInfo** - Network configuration and connectivity
- **DeviceProcessEvents** - Process creation and execution
- **DeviceNetworkEvents** - Network connections and traffic
- **DeviceFileEvents** - File operations and modifications
- **DeviceRegistryEvents** - Registry modifications
- **DeviceLogonEvents** - Local and remote logons
- **DeviceImageLoadEvents** - DLL and driver loading
- **DeviceEvents** - Miscellaneous security events
- **DeviceFileCertificateInfo** - File signing information
- **DeviceTvmSoftwareInventory** - Installed software inventory
- **DeviceTvmSoftwareVulnerabilities** - Vulnerability assessments
- **DeviceBaselineComplianceAssessment** - Baseline compliance status per device (Preview, AH-only, no Timestamp)
- **DeviceBaselineComplianceAssessmentKB** - Baseline security configuration knowledge base (Preview, AH-only, no Timestamp)
- **DeviceBaselineComplianceProfiles** - Baseline profiles for compliance monitoring (Preview, AH-only, no Timestamp)

#### Defender for Office 365 Tables
- **EmailEvents** - Email message metadata
- **EmailAttachmentInfo** - Attachment details
- **EmailUrlInfo** - URLs in email messages
- **EmailPostDeliveryEvents** - Post-delivery actions (ZAP, quarantine)
- **CloudAppEvents** - SaaS application activities
- **FileMaliciousContentInfo** - Malicious files in SharePoint, OneDrive, and Teams (Preview, AH-only)

#### Defender for Identity Tables
- **IdentityInfo** - User and device identity information
- **IdentityLogonEvents** - Domain controller authentication logs
- **IdentityQueryEvents** - LDAP queries and reconnaissance
- **IdentityDirectoryEvents** - Active Directory changes
- **IdentityEvents** - Identity events from cloud identity providers (Preview, AH-only)

#### Entra ID Tables (Advanced Hunting Only)
- **EntraIdSignInEvents** - Interactive and non-interactive sign-ins (GA, replaces AADSignInEventsBeta)
- **EntraIdSpnSignInEvents** - Service principal and managed identity sign-ins (GA, replaces AADSpnSignInEventsBeta)
- **AADSignInEventsBeta** - Legacy beta sign-in table (being replaced by EntraIdSignInEvents)
- **AADSpnSignInEventsBeta** - Legacy beta SPN sign-in table (being replaced by EntraIdSpnSignInEvents)

#### Defender for Cloud Tables
- **SecurityAlert** - Cloud workload protection alerts
- **SecurityRecommendation** - Security posture recommendations
- **AzureActivity** - Azure Resource Manager operations
- **AzureNetworkAnalytics_CL** - Network Security Group flow logs
- **CloudAuditEvents** - ARM and KubeAudit control plane events (Preview, AH-only)
- **CloudProcessEvents** - Container process execution in AKS/EKS/GKE (Preview, AH-only)
- **CloudStorageAggregatedEvents** - Aggregated cloud storage activity (Preview, AH-only)
- **CloudDnsEvents** - DNS activity from cloud infrastructure (Preview, AH-only)
- **CloudPolicyEnforcementEvents** - Policy enforcement and security gating events (Preview, AH-only)

#### AI Agent Security Tables (Advanced Hunting Only)
- **AIAgentsInfo** - Copilot Studio agent inventory, configuration, authentication, tools, and security posture (Preview, AH-only)

#### Messaging & Collaboration Tables (Advanced Hunting Only)
- **MessageEvents** - Messages sent/received at delivery time in Teams (AH-only)
- **MessagePostDeliveryEvents** - Post-delivery security events for Teams messages (AH-only)
- **MessageUrlInfo** - URLs in Teams messages (AH-only)
- **CampaignInfo** - Email campaigns identified by Defender for Office 365 (Preview, AH-only)

#### Data Security & Disruption Tables (Advanced Hunting Only)
- **DataSecurityBehaviors** - Suspicious user behaviors violating Microsoft Purview policies (Preview, AH-only)
- **DataSecurityEvents** - User activities violating Purview DLP/data classification policies (Preview, AH-only)
- **DisruptionAndResponseEvents** - Automatic attack disruption events (Preview, AH-only)
- **OAuthAppInfo** - OAuth app governance from Defender for Cloud Apps (Preview, AH-only)
- **GraphApiAuditEvents** - Microsoft Graph API audit activity (AH-only)

#### Exposure Management Tables (Advanced Hunting Only)
- **ExposureGraphNodes** - Entities in the exposure management graph (AH-only, no Timestamp)
- **ExposureGraphEdges** - Relationships between entities (AH-only, no Timestamp)

#### Common Sentinel Tables
- **AuditLogs** - Azure AD audit logs
- **SigninLogs** - Azure AD sign-in activities
- **AADNonInteractiveUserSignInLogs** - Service principal sign-ins
- **AzureActivity** - Azure subscription-level events
- **Syslog** - Linux system logs
- **CommonSecurityLog** - CEF-formatted logs from security devices
- **WindowsEvent** - Windows event logs
- **SecurityEvent** - Windows security events

---

## 3. Investigation Workflows
*Pre-built KQL queries for common investigation scenarios*

This section provides ready-to-use KQL query templates for investigating incidents, users, devices, emails, files, and network activity. Each workflow includes example queries that can be customized for your specific investigation needs.

### 1. Incident Triage

#### Initial Assessment
```kql
// Get recent high-severity incidents
SecurityIncident
| where TimeGenerated > ago(24h)
| where Severity in ("High", "Critical")
| project TimeGenerated, IncidentName, Severity, Status, Owner, 
          AlertsCount, EntitiesCount, Description
| order by TimeGenerated desc
```

#### Incident Details
```kql
// Investigate specific incident
let incidentName = "INCIDENT_NAME";
SecurityIncident
| where IncidentName == incidentName
| extend Alerts = parse_json(Alerts)
| extend Entities = parse_json(Entities)
| project TimeGenerated, IncidentName, Severity, Status, 
          Alerts, Entities, Description, AdditionalData
```

### 2. User Investigation

#### User Activity Timeline
```kql
// Comprehensive user activity
let userPrincipal = "user@domain.com";
let timeRange = 7d;
union
    (SigninLogs 
     | where TimeGenerated > ago(timeRange)
     | where UserPrincipalName == userPrincipal
     | project TimeGenerated, Activity="Sign-in", Location, IPAddress, 
               DeviceDetail, RiskLevel=RiskLevelDuringSignIn),
    (IdentityLogonEvents
     | where TimeGenerated > ago(timeRange)
     | where AccountUpn == userPrincipal
     | project TimeGenerated, Activity="Logon", Location, IPAddress, 
               DeviceDetail=DeviceName, RiskLevel=""),
    (EmailEvents
     | where TimeGenerated > ago(timeRange)
     | where SenderFromAddress == userPrincipal
     | project TimeGenerated, Activity="Email Sent", Location="", 
               IPAddress, DeviceDetail=Subject, RiskLevel="")
| order by TimeGenerated desc
```

#### Compromised User Analysis
```kql
// Detect suspicious user behavior
let userPrincipal = "user@domain.com";
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == userPrincipal
| where RiskLevelDuringSignIn in ("high", "medium") 
    or RiskState != "none"
| project TimeGenerated, IPAddress, Location, DeviceDetail, 
          RiskLevel=RiskLevelDuringSignIn, RiskDetail, 
          AuthenticationRequirement, ConditionalAccessStatus
```

### 3. Device Investigation

#### Device Activity Summary
```kql
// Device security timeline
let deviceName = "DEVICE_NAME";
let timeRange = 7d;
union
    (DeviceLogonEvents
     | where TimeGenerated > ago(timeRange)
     | where DeviceName == deviceName
     | project TimeGenerated, EventType="Logon", 
               Account=AccountName, Details=LogonType),
    (DeviceProcessEvents
     | where TimeGenerated > ago(timeRange)
     | where DeviceName == deviceName
     | project TimeGenerated, EventType="Process", 
               Account=AccountName, Details=FileName),
    (DeviceNetworkEvents
     | where TimeGenerated > ago(timeRange)
     | where DeviceName == deviceName
     | project TimeGenerated, EventType="Network", 
               Account=InitiatingProcessAccountName, 
               Details=strcat(RemoteIP, ":", RemotePort))
| order by TimeGenerated desc
| take 1000
```

#### Malicious Process Detection
```kql
// Hunt for suspicious processes
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any ("downloadstring", "iex", "invoke-expression", 
                                     "base64", "-enc", "-w hidden")
| project TimeGenerated, DeviceName, AccountName, FileName, 
          ProcessCommandLine, InitiatingProcessFileName
```

### 4. Email Investigation

#### Email Threat Analysis
```kql
// Investigate phishing campaigns
EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has_any ("Phish", "Malware", "Spam")
| join kind=inner (
    EmailAttachmentInfo
    | where TimeGenerated > ago(7d)
    | project NetworkMessageId, FileName, FileType, SHA256
) on NetworkMessageId
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, 
          Subject, ThreatTypes, FileName, SHA256, DeliveryAction
```

#### URL Click Investigation
```kql
// Track malicious URL clicks
EmailUrlInfo
| where TimeGenerated > ago(7d)
| where ThreatTypes != ""
| join kind=inner (
    EmailEvents
    | project NetworkMessageId, RecipientEmailAddress, Subject
) on NetworkMessageId
| project TimeGenerated, Url, ThreatTypes, RecipientEmailAddress, Subject
```

### 5. Threat Hunting

#### Lateral Movement Detection
```kql
// Detect Pass-the-Hash and lateral movement
DeviceLogonEvents
| where TimeGenerated > ago(24h)
| where LogonType in ("Network", "RemoteInteractive")
| summarize LogonCount = count(), 
            UniqueDevices = dcount(DeviceName),
            Devices = make_set(DeviceName)
    by AccountName, bin(TimeGenerated, 5m)
| where UniqueDevices > 3  // Multiple devices in short time
| order by LogonCount desc
```

#### Persistence Mechanism Hunt
```kql
// Hunt for persistence techniques
union
    (DeviceRegistryEvents
     | where TimeGenerated > ago(24h)
     | where (RegistryKey contains "\\Run" or RegistryKey contains "\\RunOnce" or RegistryKey contains "UserInitMprLogonScript")
     | project TimeGenerated, DeviceName, EventType="Registry", 
               Details=RegistryKey, Value=RegistryValueData),
    (DeviceFileEvents
     | where TimeGenerated > ago(24h)
     | where (FolderPath contains "\\Startup\\" or FolderPath contains "\\WMI\\" or FolderPath contains "Task Scheduler")
     | project TimeGenerated, DeviceName, EventType="File", 
               Details=FolderPath, Value=FileName)
| order by TimeGenerated desc
```

#### Credential Access Detection
```kql
// Detect credential dumping
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any ("sekurlsa", "logonpasswords", "lsadump", 
                                     "procdump", "comsvcs.dll")
    or (FileName =~ "taskmgr.exe" and ProcessCommandLine has "lsass")
| project TimeGenerated, DeviceName, AccountName, 
          FileName, ProcessCommandLine, InitiatingProcessFileName
```

### 6. File and Hash Analysis

#### File Prevalence Check
```kql
// Check file distribution across organization
let fileHash = "FILE_SHA256_HASH";
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where SHA256 == fileHash
| summarize FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            DeviceCount = dcount(DeviceName),
            Devices = make_set(DeviceName),
            Users = make_set(InitiatingProcessAccountName)
    by SHA256, FileName
```

#### Malware Execution Timeline
```kql
// Track malware execution
let fileHash = "FILE_SHA256_HASH";
union
    (DeviceFileEvents
     | where SHA256 == fileHash
     | project TimeGenerated, DeviceName, EventType="File", 
               Action=ActionType, Path=FolderPath),
    (DeviceProcessEvents
     | where SHA256 == fileHash
     | project TimeGenerated, DeviceName, EventType="Process", 
               Action=ActionType, Path=FolderPath)
| order by TimeGenerated asc
```

### 7. Network Investigation

#### External Connection Analysis
```kql
// Identify suspicious external connections
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize ConnectionCount = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            Ports = make_set(RemotePort),
            Devices = make_set(DeviceName)
    by RemoteIP, RemoteUrl
| where ConnectionCount > 10 or array_length(Devices) > 5
| order by ConnectionCount desc
```

#### C2 Communication Detection
```kql
// Hunt for beaconing behavior
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemoteIPType == "Public"
| summarize Count = count(), 
            AvgBytesSent = avg(BytesSent),
            StdDevBytesSent = stdev(BytesSent)
    by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
| where Count > 50 and StdDevBytesSent < 100  // Regular intervals, consistent size
```

---

## 4. Microsoft Learn Documentation Integration
*Leverage official Microsoft documentation for remediation and best practices*

This section describes how to use the Microsoft Learn MCP Server to access official Microsoft documentation, code samples, and best practices during security investigations and incident response.

### Overview

The **Microsoft Learn MCP Server** provides real-time access to official Microsoft security documentation, enabling investigators to:
- Find authoritative remediation guidance during active incidents
- Access production-ready PowerShell/KQL code samples
- Reference latest security best practices and configuration guides
- Validate investigation techniques against Microsoft recommendations
- Ensure compliance with Microsoft security frameworks

**Key Benefits:**
- ✅ **Always Current**: Documentation reflects latest product updates and security features
- ✅ **Production-Ready Code**: Copy-paste PowerShell cmdlets and KQL queries that work
- ✅ **Official Guidance**: Authoritative Microsoft security playbooks and incident response procedures
- ✅ **Multi-Product Coverage**: Defender XDR, Entra ID, Sentinel, Microsoft 365, Azure Security
- ✅ **Context-Aware**: Search results include practical examples applicable to your investigation

### Available MCP Tools

#### microsoft_docs_search
Search official Microsoft documentation and return concise, high-quality content chunks.

**When to use:**
- Quick lookup of remediation procedures during active incidents
- Find step-by-step configuration guides
- Understand security features and capabilities
- Get overview of investigation workflows

**Example prompts:**
```
"How do I revoke malicious OAuth applications in Entra ID?"
"Steps to remediate compromised user account in Microsoft 365"
"Configure Conditional Access to block TOR network IPs"
```

**Returns:** Up to 10 documentation articles with title, URL, and relevant excerpts (max 500 tokens each)

#### microsoft_code_sample_search
Search for production-ready code samples in official Microsoft Learn documentation.

**When to use:**
- Need PowerShell commands for remediation actions
- Looking for KQL query examples for specific scenarios
- Want validated API call patterns for Microsoft Graph
- Require working Python/CLI scripts for automation

**Example prompts:**
```
"PowerShell code to disable compromised user account and revoke sessions"
"KQL query to detect impossible travel in SigninLogs"
"Microsoft Graph API examples for listing OAuth consent grants"
```

**Parameters:**
- `query`: Descriptive search query or SDK/method name
- `language` (optional): Filter by programming language (powershell, kusto, python, csharp, javascript, etc.)

**Returns:** Up to 20 code samples with syntax highlighting, context, and documentation links

#### microsoft_docs_fetch
Retrieve complete documentation page content in markdown format.

**When to use:**
- Search results are incomplete or truncated
- Need full troubleshooting guide or detailed procedures
- Want complete reference documentation for complex topics
- Building comprehensive investigation documentation

**Example usage:**
```
"Fetch full documentation from https://learn.microsoft.com/en-us/entra/identity/authentication/..."
```

**Returns:** Full page content with headings, code blocks, tables, and links preserved in markdown

### Workflow Integration

#### During Active Incident Response

**Scenario:** OAuth application attack detected with suspicious consent grants

**Investigation workflow:**
1. **Identify the threat** using Defender XDR/Sentinel queries
2. **Search for remediation guidance:**
   ```
   microsoft_docs_search("revoke malicious OAuth application Azure AD tenant remediation")
   ```
3. **Get production code:**
   ```
   microsoft_code_sample_search("Remove OAuth consent grants PowerShell", language="powershell")
   ```
4. **Execute remediation** using official Microsoft cmdlets:
   ```powershell
   # From Microsoft Learn documentation
   Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <grant-id>
   Revoke-MgUserSignInSession -UserId <user-id>
   ```

#### For TOR/VPN Network Blocking

**Scenario:** User authenticated from TOR exit nodes, need to block anonymization networks

**Documentation workflow:**
1. **Search blocking methods:**
   ```
   microsoft_code_sample_search("block TOR IP addresses conditional access Azure AD", language="powershell")
   ```
2. **Review official guidance:**
   - Create Conditional Access named locations for anonymization networks
   - Configure block policies for risky sign-in patterns
   - Set up real-time risk-based access controls

3. **Implement using Microsoft's code samples:**
   ```powershell
   # Conditional Access policy from Microsoft Learn
   New-MgIdentityConditionalAccessPolicy -DisplayName "Block TOR Networks" `
       -Conditions @{Locations = @{IncludeLocations = "All"; ExcludeLocations = "Trusted"}} `
       -GrantControls @{Operator = "OR"; BuiltInControls = "Block"}
   ```

#### For Compromised User Investigation

**Scenario:** Suspicious authentication patterns detected, need investigation playbook

**Documentation workflow:**
1. **Find investigation procedures:**
   ```
   microsoft_docs_search("investigate compromised user account Defender XDR incident response")
   ```
2. **Review official playbooks:**
   - User entity investigation checklist (8-step process)
   - Automated investigation and response (AIR) capabilities
   - Risk assessment and remediation workflows

3. **Access detailed pages:**
   ```
   microsoft_docs_fetch("https://learn.microsoft.com/en-us/defender-xdr/investigate-users")
   ```

### Best Practices

**When to use Microsoft Learn documentation:**
- ✅ **Before remediation actions** - Validate procedures against official guidance
- ✅ **For unfamiliar products** - Learn correct syntax and required permissions
- ✅ **During complex investigations** - Reference multi-product investigation workflows
- ✅ **For compliance documentation** - Cite official Microsoft sources in reports
- ✅ **When troubleshooting** - Check for known issues and supported configurations

**Workflow recommendations:**
1. **Search first, fetch later**: Use `microsoft_docs_search` for quick answers, `microsoft_docs_fetch` for deep dives
2. **Filter code by language**: Use `language` parameter in `microsoft_code_sample_search` to avoid irrelevant results
3. **Include product names**: Specify "Entra ID", "Defender XDR", "Sentinel" in queries for precise results
4. **Combine with investigation data**: Apply documentation guidance to your specific IOCs and entities
5. **Document sources**: Include Microsoft Learn URLs in investigation reports for audit trail

**Common search patterns:**
```
# Remediation actions
"disable user account Microsoft 365"
"revoke refresh tokens Entra ID"
"block IP address Conditional Access"
"delete malicious OAuth app"

# Investigation techniques
"trace authentication chain SessionId"
"detect impossible travel KQL query"
"investigate suspicious email forwarding rule"
"find lateral movement Advanced Hunting"

# Configuration guidance
"configure MFA enforcement Entra ID"
"setup identity protection risk policies"
"enable audit logging Microsoft 365"
"deploy Defender for Endpoint"
```

### Example: Complete Investigation with Documentation

**Incident:** User account showing impossible travel alerts, potential account takeover

**Phase 1: Investigate (using Sentinel/Defender)**
```kql
SigninLogs
| where UserPrincipalName == "suspicious.user@contoso.com"
| where TimeGenerated > ago(7d)
| where ResultType == 0  // Successful sign-ins
| project TimeGenerated, IPAddress, Location, DeviceDetail
```

**Phase 2: Search remediation guidance**
```
microsoft_docs_search("remediate compromised user account impossible travel Entra ID")
```

**Result:** Official playbook with 5-step remediation process

**Phase 3: Get PowerShell commands**
```
microsoft_code_sample_search("disable user and revoke sessions Entra ID", language="powershell")
```

**Result:** Production cmdlets:
```powershell
# Revoke all active sessions
Revoke-MgUserSignInSession -UserId <user-object-id>

# Disable account
Update-MgUser -UserId <user-object-id> -AccountEnabled:$false

# Reset password with force change
Update-MgUser -UserId <user-object-id> -PasswordProfile @{
    ForceChangePasswordNextSignIn = $true
    Password = "TempPassword123!"
}
```

**Phase 4: Execute and document**
- Apply remediation using Microsoft's official cmdlets
- Reference Microsoft Learn URLs in incident report
- Follow post-remediation monitoring guidance from documentation

### Integration with Agent Skills

The `microsoft-learn-docs` skill (see [Agent Skills section](#19-agent-skills-vs-code-copilot)) automates documentation lookup during investigations:

**Skill workflow:**
1. Detects remediation needs from investigation context (OAuth apps, TOR IPs, compromised users)
2. Automatically searches Microsoft Learn for relevant documentation
3. Extracts PowerShell commands and configuration steps
4. Includes official Microsoft sources in generated reports

**Example automation:**
```
User: "Investigate user@contoso.com - they authenticated from TOR network"

Agent response:
1. Queries SigninLogs for TOR IP evidence
2. Enriches IPs with threat intelligence
3. Searches Microsoft Learn: "block TOR network Conditional Access"
4. Returns investigation findings + official remediation steps with code
```

---

# Part IV: REFERENCE
*Query library, best practices, templates*

---

## 8. Sample KQL Queries

**⚠️ PRODUCTION-VALIDATED QUERY LIBRARY - USE THESE PATTERNS FIRST**

This section contains tested and optimized KQL queries for common investigation scenarios. These queries handle edge cases, dynamic field parsing, and performance optimization that aren't obvious from table schemas.

**When to Use Sample Queries vs KQL Query Builder:**

**✅ Use Sample Queries (This Section) When:**
- Standard investigation patterns (user investigation, incident triage, device analysis)
- Queries already tested and validated in production
- Investigation follows documented playbooks (Section 12)
- Need reliable, proven performance

**✅ Use kql-query-builder Skill (Section 19, Skill #4) When:**
- Custom detection scenarios not covered by sample queries
- Building new Sentinel Analytic Rules
- Need ASIM-normalized multi-source queries
- Optimizing existing queries for performance
- Investigating unique threat patterns or novel IOCs
- Searching GitHub for community detection rules

**Example Decision Flow:**
```
User asks: "Find failed logins" 
→ Use Query 3c (Sample Queries)

User asks: "Create detection rule for impossible travel"
→ Use kql-query-builder skill to generate Sentinel rule

User asks: "Find lateral movement across AWS, Azure AD, and Okta"
→ Use kql-query-builder to generate ASIM-normalized query
```

**Critical Notes:**
- Replace `<UPN>`, `<StartDate>`, `<EndDate>`, `<USER_ID>`, `<WINDOWS_SID>` with actual values
- All queries use PST/PDT timezone (Sentinel workspace local time)
- Date ranges are INCLUSIVE - see Date Range Reference below for proper handling
- Dynamic JSON fields (`LocationDetails`, `DeviceDetail`, `ModifiedProperties`) require `parse_json()` or `tostring()`

### Date Range Reference

**🔴 CRITICAL: ALWAYS check current date from context BEFORE calculating date ranges!**

**Rule 1: Real-Time/Recent Searches (Current Activity)**
- Add +2 days to current date for end range
- Example: Today is Jan 7, 2026 → "Last 7 days" = `datetime(2026-01-01)` to `datetime(2026-01-09)`
- Applies to: "recent activity", "current", "last X days"

**Rule 2: Historical Searches (User-Specified Dates)**
- Add +1 day to user's end date
- Example: User says "Jan 1 to Jan 5" → `datetime(2026-01-01)` to `datetime(2026-01-06)`
- Applies to: Explicit date ranges like "from X to Y"

**Why:** `datetime(2026-01-07)` means Jan 7 at 00:00:00 (midnight). Without adding days, you miss ~24 hours of data. +1 includes full day, +2 accounts for timezone offset (PST behind UTC) + full day coverage.

### Query 1: Extract Top Priority IPs (Deterministic Selection with Risky IPs)

**Purpose:** Get up to 15 most important IPs for threat intelligence enrichment  
**Usage:** Run AFTER anomaly query but BEFORE threat intel query

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let upn = '<UPN>';

// Priority 1: Anomaly IPs (top 8 by anomaly count)
let anomaly_ips = 
    Signinlogs_Anomalies_KQL_CL
    | where DetectedDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where AnomalyType endswith "IP"
    | summarize AnomalyCount = count() by IPAddress = Value
    | top 8 by AnomalyCount desc
    | extend Priority = 1, Source = "Anomaly";

// Priority 2: Risky IPs from Identity Protection (top 10 for selection pool)
let risky_ips_pool = 
    AADUserRiskEvents
    | where ActivityDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where isnotempty(IpAddress)
    | summarize RiskCount = count() by IPAddress = IpAddress
    | top 10 by RiskCount desc
    | extend Priority = 2, Source = "RiskyIP";

// Priority 3: Frequent Sign-in IPs (top 10 for selection pool)
let frequent_ips_pool =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ upn
    | summarize SignInCount = count() by IPAddress
    | top 10 by SignInCount desc
    | extend Priority = 3, Source = "Frequent";

// Get anomaly IP list for exclusion from risky slot
let anomaly_ip_list = anomaly_ips | project IPAddress;

// Get anomaly + risky IP list for exclusion from frequent slot
let priority_ip_list = 
    union anomaly_ips, risky_ips_pool
    | project IPAddress;

// Reserve slots with deduplication: 8 anomaly + 4 risky + 3 frequent
let anomaly_slot = anomaly_ips | extend Count = AnomalyCount;
let risky_slot = risky_ips_pool 
    | join kind=anti anomaly_ip_list on IPAddress
    | top 4 by RiskCount desc
    | extend Count = RiskCount;
let frequent_slot = frequent_ips_pool 
    | join kind=anti priority_ip_list on IPAddress
    | top 3 by SignInCount desc
    | extend Count = SignInCount;

union anomaly_slot, risky_slot, frequent_slot
| project IPAddress, Priority, Count, Source
| order by Priority asc, Count desc
| project IPAddress
```

**Post-Query Action:** Extract IPAddress column as array for use in Query 3d and Query 11:
```python
ip_list = [row['IPAddress'] for row in results]
ip_array_kql = f"dynamic({json.dumps(ip_list)})"
```

### Query 2: Anomalies from Detection System

```kql
Signinlogs_Anomalies_KQL_CL
| where DetectedDateTime between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserPrincipalName =~ '<UPN>'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10, "Medium",
    (CountryNovelty or CityNovelty or StateNovelty), "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| extend SeverityOrder = case(Severity == 'High', 1, Severity == 'Medium', 2, Severity == 'Low', 3, 4)
| project
    DetectedDateTime,
    UserPrincipalName,
    AnomalyType,
    Value,
    Severity,
    SeverityOrder,
    Country,
    City,
    State,
    CountryNovelty,
    CityNovelty,
    StateNovelty,
    ArtifactHits,
    FirstSeenRecent,
    BaselineSize,
    OS,
    BrowserFamily,
    RawBrowser
| order by SeverityOrder asc, DetectedDateTime desc
| take 10
```

### Query 3: Sign-ins by Application

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    UniqueLocations=dcount(Location)
    by AppDisplayName
| order by SignInCount desc
| take 5
```

### Query 3b: Sign-ins by Location

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where isnotempty(Location)
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    Applications=make_set(AppDisplayName, 5)
    by Location
| order by SignInCount desc
| take 5
```

### Query 3c: Sign-in Failures (Detailed Breakdown)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where ResultType != '0'
| summarize 
    FailureCount=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Applications=make_set(AppDisplayName, 3),
    Locations=make_set(Location, 3)
    by ResultType, ResultDescription
| order by FailureCount desc
| take 5
```

### Query 3d: Sign-in Counts by IP with Authentication Details

**Purpose:** Get sign-in frequency + authentication pattern for prioritized IPs  
**Usage:** Run AFTER Query 1 (uses extracted IP array)

```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>", ...]);  // From Query 1
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

// Get most recent sign-in per IP with full context
let most_recent_signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where IPAddress in (target_ips)
| summarize arg_max(TimeGenerated, *) by IPAddress;

// Expand authentication details for most recent sign-in
most_recent_signins
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend HasAuthDetails = array_length(AuthDetails) > 0
| extend AuthDetailsToExpand = iif(HasAuthDetails, AuthDetails, dynamic([{"authenticationStepResultDetail": ""}]))
| mv-expand AuthDetailsToExpand
| extend AuthStepResultDetail = tostring(AuthDetailsToExpand.authenticationStepResultDetail)
| extend AuthPriority = case(
    AuthStepResultDetail has "MFA requirement satisfied", 1,
    AuthStepResultDetail has "Correct password", 2,
    AuthStepResultDetail has "Passkey", 2,
    AuthStepResultDetail has "Phone sign-in", 2,
    AuthStepResultDetail has "SMS verification", 2,
    AuthStepResultDetail has "First factor requirement satisfied", 3,
    AuthStepResultDetail has "MFA required", 4,
    999)
| summarize 
    MostRecentTime = any(TimeGenerated),
    MostRecentResultType = any(ResultType),
    HasAuthDetails = any(HasAuthDetails),
    MinPriority = min(AuthPriority),
    AllAuthDetails = make_set(AuthStepResultDetail)
    by IPAddress
| extend LastAuthResultDetail = case(
    MostRecentResultType != "0", "Authentication failed",
    not(HasAuthDetails) and MostRecentResultType == "0", "Token",
    MinPriority == 1 and AllAuthDetails has "MFA requirement satisfied", "MFA requirement satisfied by claim in the token",
    MinPriority == 2 and AllAuthDetails has "Correct password", "Correct password",
    MinPriority == 2 and AllAuthDetails has "Passkey (device-bound)", "Passkey (device-bound)",
    MinPriority == 3 and AllAuthDetails has "First factor requirement satisfied by claim in the token", "First factor requirement satisfied by claim in the token",
    MinPriority == 4 and AllAuthDetails has "MFA required in Azure AD", "MFA required in Azure AD",
    tostring(AllAuthDetails[0]))
// Join back for aggregate counts
| join kind=inner (
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ '<UPN>'
    | where IPAddress in (target_ips)
    | summarize 
        SignInCount = count(),
        SuccessCount = countif(ResultType == '0'),
        FailureCount = countif(ResultType != '0'),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress
) on IPAddress
| project IPAddress, SignInCount, SuccessCount, FailureCount, FirstSeen, LastSeen, LastAuthResultDetail
| order by SignInCount desc
```

**Critical Field:** `LastAuthResultDetail` shows the authentication method used in the MOST RECENT sign-in from each IP. This reveals:
- Current session status (active vs expired/failed)
- Token expiration patterns
- Interactive vs non-interactive authentication

### Query 4: Azure AD Audit Log Activity

```kql
AuditLogs
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| summarize 
    Count=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Operations=make_set(OperationName, 10)
    by Category, Result
| order by Count desc
| take 10
```

**Note:** Always aggregate audit logs - `TargetResources` and `ModifiedProperties` are very verbose. For detailed investigation, query specific operations separately.

### Query 5: Office 365 Activity Distribution

```kql
OfficeActivity
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserId =~ '<UPN>'
| summarize ActivityCount = count() by RecordType, Operation
| order by ActivityCount desc
| take 5
```

### Query 6: Security Incidents with Alerts

**CRITICAL:** Requires User Object ID AND Windows SID from Microsoft Graph first!

```kql
let targetUPN = "<UPN>";
let targetUserId = "<USER_OBJECT_ID>";  // From Graph: /v1.0/users/<UPN>?$select=id
let targetSid = "<WINDOWS_SID>";  // From Graph: /v1.0/users/<UPN>?$select=onPremisesSecurityIdentifier
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetUPN or Entities has targetUserId or Entities has targetSid
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;

SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend ProviderIncidentUrl = tostring(AdditionalData.providerIncidentUrl)
| extend OwnerUPN = tostring(Owner.userPrincipalName)
| extend LastModifiedTime = todatetime(LastModifiedTime)
| summarize 
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime),
    LastModifiedTime = any(LastModifiedTime),
    OwnerUPN = any(OwnerUPN),
    ProviderIncidentUrl = any(ProviderIncidentUrl),
    AlertCount = count()
    by ProviderIncidentId
| order by LastModifiedTime desc
| take 10
```

**Why all three identifiers matter:**
- Cloud alerts use UPN or Object ID (e.g., "Device Code Authentication Flow")
- On-premises alerts use Windows SID only (e.g., "Rare RDP Connections", "RDP Nesting")
- Missing ANY identifier = missed incidents!

### Query 10: DLP Events (Data Loss Prevention)

```kql
let upn = '<UPN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where ActionType in ("FileCopiedToRemovableMedia", "FileUploadedToCloud", "FileCopiedToNetworkShare")
| extend DlpAudit = parse_json(RawEventData)["DlpAuditEventMetadata"]
| extend File = parse_json(RawEventData)["ObjectId"]
| extend UserId = parse_json(RawEventData)["UserId"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend ClientIP = parse_json(RawEventData)["ClientIP"]
| extend RuleName = parse_json(RawEventData)["PolicyMatchInfo"]["RuleName"]
| extend Operation = parse_json(RawEventData)["Operation"]
| extend TargetDomain = parse_json(RawEventData)["TargetDomain"]
| extend TargetFilePath = parse_json(RawEventData)["TargetFilePath"]
| where isnotnull(DlpAudit)
| where UserId == upn
| summarize by TimeGenerated, tostring(UserId), tostring(DeviceName), tostring(ClientIP), 
    tostring(RuleName), tostring(File), tostring(Operation), tostring(TargetDomain), tostring(TargetFilePath)
| order by TimeGenerated desc
| take 5
```

### Query 11: Threat Intelligence IP Enrichment (Bulk Query)

**Purpose:** Check if IPs match known threat intelligence indicators  
**Usage:** Run AFTER Query 1 (uses extracted IP array)

```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>", ...]);  // From Query 1

ThreatIntelIndicators
| extend IndicatorType = replace_string(replace_string(replace_string(tostring(split(ObservableKey, ":", 0)), "[", ""), "]", ""), "\"", "")
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| extend NetworkSourceIP = toupper(ObservableValue)
| where NetworkSourceIP in (target_ips)
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| extend TrafficLightProtocolLevel = tostring(parse_json(AdditionalFields).TLPLevel)
| extend ActivityGroupNames = extract(@"ActivityGroup:(\S+)", 1, tostring(parse_json(Data).labels))
| summarize arg_max(TimeGenerated, *) by NetworkSourceIP
| project 
    TimeGenerated,
    IPAddress = NetworkSourceIP,
    ThreatDescription = Description,
    ActivityGroupNames,
    Confidence,
    ValidUntil,
    TrafficLightProtocolLevel,
    Pattern,
    IsActive
| order by Confidence desc, TimeGenerated desc
```

**Performance Note:** Single batch query for multiple IPs (~28 seconds) vs per-IP queries (28 seconds each). Always use batch approach!

### Microsoft Graph Identity Protection Queries

**Step 1: Get User Object ID and Windows SID** (Required for all subsequent queries)
```
/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier
```

**Step 2: Get User Risk Profile**
```
/v1.0/identityProtection/riskyUsers/<USER_ID>
```

**Step 3: Get Risk Detections**
```
/v1.0/identityProtection/riskDetections?$filter=userId eq '<USER_ID>'&$select=id,detectedDateTime,riskEventType,riskLevel,riskState,riskDetail,ipAddress,location,activity,activityDateTime&$orderby=detectedDateTime desc&$top=5
```

**Step 4: Get Risky Sign-ins** (Beta endpoint only!)
```
/beta/auditLogs/signIns?$filter=userPrincipalName eq '<UPN>' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&$select=id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,riskState,riskLevelDuringSignIn,riskEventTypes_v2,riskDetail,status&$orderby=createdDateTime desc&$top=5
```

**Common Risk Event Types:**
- **unlikelyTravel** - Impossible distance between sign-ins
- **unfamiliarFeatures** - Sign-in from unfamiliar location/device/IP
- **anonymizedIPAddress** - Tor, VPN, or proxy detected
- **maliciousIPAddress** - Known malicious IP
- **leakedCredentials** - Credentials found in leak databases
- **investigationsThreatIntelligence** - Microsoft threat intel flagged

---

## 9. Advanced Authentication Analysis

**🔬 SESSIONID-BASED FORENSIC TRACING - THE GOLD STANDARD**

When Identity Protection flags an anomalous sign-in, determining if it represents genuine compromise requires **SessionId-based forensic analysis**. This workflow traces the complete authentication chain to identify the exact moment and method of initial authentication.

### The SessionId Forensic Workflow

**What is SessionId?**
- Unique identifier linking ALL authentication events in a single session
- Persists across token refreshes, MFA challenges, app launches
- Enables complete reconstruction of attack timeline

**When to Use:**
- Risk detection from unfamiliar IP
- Anomalies flagged by detection system (Query 2)
- Impossible travel alerts
- Credential stuffing investigations

### Step-by-Step Forensic Protocol

#### Step 1: Extract SessionId from Suspicious IP

```kql
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserPrincipalName =~ '<UPN>'
| where IPAddress == '<SUSPICIOUS_IP>'  // From anomaly or risky IP detection
| where isnotempty(SessionId)
| distinct SessionId
| take 1  // Get the most common SessionId for this IP
```

**Critical:** SessionId is NOT populated in all sign-ins. If empty, fall back to correlation by TimeGenerated window (±5 minutes).

#### Step 2: Trace Complete Authentication Chain

```kql
let target_sessionid = '<SESSIONID_FROM_STEP_1>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where SessionId == target_sessionid
| where UserPrincipalName =~ '<UPN>'
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend State = tostring(LocationDetails.state)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend DeviceDetail = parse_json(DeviceDetail)
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend OS = tostring(DeviceDetail.operatingSystem)
| extend Browser = tostring(DeviceDetail.browser)
| project 
    TimeGenerated,
    AppDisplayName,
    IPAddress,
    City,
    State,
    Country,
    ResourceDisplayName,
    ResultType,
    ResultDescription,
    AuthenticationRequirement,
    DeviceId,
    OS,
    Browser
| order by TimeGenerated asc
```

**What to Look For:**
- **First entry** = initial authentication event (may be legitimate)
- **Subsequent entries** = token refreshes, app access (may be attack)
- **IP changes mid-session** = session hijacking or token theft

#### Step 3: Identify Interactive MFA Event

**Rule:** The FIRST sign-in in a SessionId chain with `AuthenticationRequirement = "multiFactorAuthentication"` is the true authentication event. All subsequent events are token refreshes.

```kql
let target_sessionid = '<SESSIONID_FROM_STEP_1>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where SessionId == target_sessionid
| where UserPrincipalName =~ '<UPN>'
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize arg_min(TimeGenerated, *) by SessionId  // Get FIRST MFA event
| project TimeGenerated, IPAddress, AppDisplayName, Location, AuthenticationDetails
```

**Interpretation:**
- If this IP is **corporate VPN or trusted network** → Session likely legitimate
- If this IP is **suspicious geography** → Initial compromise confirmed
- If this IP is **different from anomaly IP** → Token theft/session hijacking

#### Step 4: Extract All IPs in Session

```kql
let target_sessionid = '<SESSIONID_FROM_STEP_1>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where SessionId == target_sessionid
| where UserPrincipalName =~ '<UPN>'
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SignInCount = count(),
    Apps = make_set(AppDisplayName, 5)
    by IPAddress
| order by FirstSeen asc
| project IPAddress
```

**Post-Query Action:** Use these IPs for threat intelligence enrichment (Query 11) and external IP enrichment (ipinfo.io, AbuseIPDB, GreyNoise, VirusTotal).

#### Step 5: Analyze IP Enrichment Data

**Required Fields from External Enrichment:**
```json
{
  "ip": "192.0.2.1",
  "is_vpn": false,
  "is_proxy": false,
  "is_tor": false,
  "abuse_confidence_score": 85,
  "threat_description": "Brute force attacks",
  "city": "Lagos",
  "region": "Lagos",
  "country": "NG",
  "org": "AS37682 MainOne Cable Company"
}
```

**Risk Criteria:**
- `is_vpn/is_proxy/is_tor = true` → Medium risk (unless corporate VPN)
- `abuse_confidence_score > 50` → High risk
- `Country code != user's baseline` → Geographic anomaly (check first MFA IP from Step 3)

#### Step 6: Document Risk Assessment

**Template:**
```
SessionId: <SESSION_ID>
Initial Authentication: <TIMESTAMP> from <IP> (<LOCATION>)
MFA Method: <METHOD>
Anomalous Activity: <TIMESTAMP> from <IP> (<LOCATION>)

IP Enrichment Summary:
- <IP_1>: <CITY, COUNTRY> | VPN: <YES/NO> | Abuse Score: <SCORE> | <THREAT_DESC>
- <IP_2>: <CITY, COUNTRY> | VPN: <YES/NO> | Abuse Score: <SCORE> | <THREAT_DESC>

Risk Classification: <HIGH/MEDIUM/LOW>
Recommendation: <BLOCK_USER/FORCE_PASSWORD_RESET/MONITOR/NO_ACTION>
```

### Real-World Example: Geographic Anomaly Investigation

**Scenario:** User signs in from Nigeria (flagged as anomaly), but works in Seattle.

**Workflow:**
1. Get SessionId from Nigeria sign-in
2. Trace full session chain → Find initial MFA from Seattle (corporate VPN: 198.51.100.50)
3. Enrich Nigeria IP → `abuse_confidence_score: 72`, `threat_description: "Credential stuffing"`
4. **Conclusion:** Legitimate user traveling to Nigeria. Corporate VPN authenticated first, then local network. **No action required.**

**Counter-Example:** Same scenario, but initial MFA is from Nigeria (unknown IP).
- **Conclusion:** Credential compromise. **Force password reset + revoke sessions.**

### SessionId Tracing Limitations

**When SessionId is Empty:**
- Non-interactive sign-ins (service principals, managed identities)
- Older audit log entries (retention-dependent)
- Certain legacy authentication protocols

**Fallback Strategy:**
1. Use time-window correlation (±5 minutes from anomaly timestamp)
2. Filter by same User-Agent or DeviceId
3. Focus on interactive vs non-interactive patterns

---

# Part II: KNOWLEDGE (MCP Tools)
*Grounding, memory, and context from Sentinel Lake*

---

## 10. MCP Server Integration
*Model Context Protocol server tools for programmatic investigations*

This section describes the available MCP (Model Context Protocol) tools that enable programmatic access to Sentinel Data Lake and Defender XDR. Use these tools to automate investigations and integrate security data into custom workflows.

### Available MCP Tools

#### Sentinel Data Lake Tools (mcp_data_explorat_*)

| Tool | Description | Use Case |
|------|-------------|----------|
| `list_sentinel_workspaces` | List available Sentinel workspaces | Discover workspace IDs for queries |
| `search_tables` | Discover relevant tables for investigation | Find data sources by keyword |
| `query_lake` | Execute KQL queries against Sentinel Data Lake | Run custom investigations |
| `analyze_user_entity` | Behavioral analysis for a user over time period | User compromise investigations |
| `analyze_url_entity` | Analyze URL/domain for threat indicators | Phishing/malware URL analysis |
| `get_entity_analysis` | Retrieve cached entity analysis results | Follow-up on previous analysis |

**Fallback — Sentinel Data Lake KQL REST API:**

If the MCP `query_lake` tool is unavailable, use the native Data Lake KQL REST API directly:

| Property | Value |
|----------|-------|
| Endpoint | `POST https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query` |
| Auth scope | `4500ebfb-89b6-4b14-a480-7f749797bfcd/.default` |
| Payload | `{"csl": "<KQL>", "db": "<WorkspaceName>-<WorkspaceId>"}` |
| Required RBAC | Log Analytics Reader or Contributor on the workspace |
| Utility script | `python scripts/query_datalake.py "<KQL>"` |

> **📘 Reference:** [Run KQL queries on the Microsoft Sentinel data lake using APIs](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-queries-api)

#### Defender XDR - Incidents & Alerts (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `ListIncidents` | List/filter incidents | `severity`, `status`, `assignedTo`, `top` |
| `GetIncidentById` | Get full incident with correlated alerts | `incidentId` |
| `ListAlerts` | List/filter alerts with pagination | `severity`, `status`, `top`, `skip` |
| `GetAlertById` | Get complete alert with evidence | `alertId` |

#### Defender XDR - Devices/Endpoints (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `GetDefenderMachine` | Device details: OS, health, risk, exposure | `machineId` or `deviceName` |
| `GetDefenderMachineAlerts` | All alerts for a specific device | `machineId` |
| `GetDefenderMachineLoggedOnUsers` | Users who logged onto device | `machineId` |
| `GetDefenderMachineVulnerabilities` | CVEs affecting a device | `machineId` |
| `FindDefenderMachinesByIp` | Devices that communicated with an IP | `ipAddress` |
| `ListDefenderMachinesByVulnerability` | All devices affected by a CVE | `cveId` |

#### Defender XDR - Files & IOCs (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `GetDefenderFileInfo` | File metadata: hash, publisher, signer, prevalence | `sha1` or `sha256` |
| `GetDefenderFileAlerts` | Alerts triggered by a file hash | `sha1` or `sha256` |
| `GetDefenderFileRelatedMachines` | Devices where file was observed | `sha1` or `sha256` |
| `GetDefenderFileStatistics` | Organizational prevalence statistics | `sha1` or `sha256` |
| `ListDefenderIndicators` | Tenant IOC rules (block/alert/allow) | `indicatorType`, `top` |

#### Defender XDR - IP Analysis (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `GetDefenderIpStatistics` | IP communication stats in org | `ipAddress` |
| `GetDefenderIpAlerts` | Alerts related to an IP address | `ipAddress` |

#### Defender XDR - User Analysis (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `ListUserRelatedAlerts` | All alerts for a user account | `userPrincipalName` or `accountName` |
| `ListUserRelatedMachines` | Devices where user has logged in | `userPrincipalName` or `accountName` |

#### Defender XDR - Vulnerabilities & Remediation (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `ListDefenderVulnerabilitiesBySoftware` | CVEs for specific software | `softwareId` |
| `ListDefenderRemediationActivities` | All remediation task statuses | `top` |
| `GetDefenderRemediationActivity` | Specific remediation details | `activityId` |

#### Defender XDR - Investigations (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `ListDefenderInvestigations` | Automated investigation cases | `top`, `skip` |
| `GetDefenderInvestigation` | Specific investigation details | `investigationId` |

#### Defender XDR - Advanced Hunting (mcp_triage_*)

| Tool | Description | Parameters |
|------|-------------|------------|
| `RunAdvancedHuntingQuery` | Execute KQL queries in Defender | `query` (KQL string) |
| `FetchAdvancedHuntingTablesOverview` | List available hunting tables | None |
| `FetchAdvancedHuntingTablesDetailedSchema` | Column schemas for KQL tables | `tableName` |

### Common Investigation Patterns

#### Pattern 1: Incident Deep Dive
```
1. ListIncidents (filter: severity=high, status=active)
2. GetIncidentById (incidentId from step 1)
3. For each device in incident:
   - GetDefenderMachine
   - GetDefenderMachineAlerts
   - GetDefenderMachineLoggedOnUsers
4. For each user in incident:
   - ListUserRelatedAlerts
   - ListUserRelatedMachines
```

#### Pattern 2: Endpoint Forensics
```
1. GetDefenderMachine (deviceName)
2. GetDefenderMachineAlerts (machineId)
3. GetDefenderMachineLoggedOnUsers (machineId)
4. GetDefenderMachineVulnerabilities (machineId)
5. For suspicious files:
   - GetDefenderFileInfo (sha1)
   - GetDefenderFileRelatedMachines (sha1)
```

#### Pattern 3: User Compromise Investigation
```
1. analyze_user_entity (upn, timeRange: "7d")
2. ListUserRelatedAlerts (upn)
3. ListUserRelatedMachines (upn)
4. query_lake (SigninLogs for authentication anomalies)
```

#### Pattern 4: IOC Hunting
```
1. For IP IOCs:
   - GetDefenderIpStatistics
   - GetDefenderIpAlerts
   - FindDefenderMachinesByIp
2. For File IOCs:
   - GetDefenderFileInfo
   - GetDefenderFileAlerts
   - GetDefenderFileRelatedMachines
3. ListDefenderIndicators (check existing rules)
```

#### Pattern 5: Vulnerability Assessment
```
1. ListDefenderVulnerabilitiesBySoftware (softwareId)
2. ListDefenderMachinesByVulnerability (cveId)
3. For each affected machine:
   - GetDefenderMachine (exposure level)
4. ListDefenderRemediationActivities (track remediation)
```

#### Microsoft Learn Server (mcp_microsoft_lea_*)

Documentation and code sample retrieval from official Microsoft Learn.

| Tool | Description | Parameters |
|------|-------------|------------|
| `microsoft_docs_search` | Search official Microsoft documentation | `query` (search terms) |
| `microsoft_docs_fetch` | Fetch full documentation page as markdown | `url` (Microsoft Learn URL) |
| `microsoft_code_sample_search` | Find code samples in documentation | `query`, `language` (optional) |

**Use Cases:**
- Get remediation guidance for specific alerts/CVEs
- Find PowerShell scripts for security tasks
- Retrieve KQL query examples from official docs
- Look up best practices for Defender/Sentinel configuration

#### Sentinel Graph Server (mcp_microsoft_mcp_microsoft_graph_*)

Identity and directory data from Microsoft Entra ID via Microsoft Graph API. This server is accessed through Sentinel's MCP endpoint and includes **purpose-built graph investigation tools**.

**Server Configuration:**
```json
"Sentinel Graph": {
  "url": "https://sentinel.microsoft.com/mcp/graph",
  "type": "http"
}
```

**Prerequisites:**
- Be a Sentinel data lake customer
- Have at least Security Reader permission
- Use GitHub Copilot with VS Code or Security Copilot as Agent platform

##### Graph API CRUD Tools

| Tool | Description | Example Path |
|------|-------------|--------------|
| `get` | GET request to Graph API | `/v1.0/users/{upn}` |
| `post` | POST request to Graph API | `/v1.0/security/runHuntingQuery` |
| `patch` | PATCH request to Graph API | `/v1.0/users/{id}` |
| `delete` | DELETE request to Graph API | `/v1.0/users/{id}` |

##### Purpose-Built Graph Investigation Tools 🆕

These tools provide AI-accessible graph-powered insights for security investigations:

| Tool | Description | Use Case |
|------|-------------|----------|
| `graph_exposure_perimeter` | Find how accessible a node is based on valid entry points that can reach it | Assessing lateral risk, identifying most exposed assets |
| `graph_find_blastRadius` | Evaluate potential impact if a node is compromised | Prioritizing protection, identifying high-impact nodes |
| `graph_find_walkable_paths` | Find all attack paths between source and target (up to 4 hops, max 1000 results) | Understanding attack chains, securing critical connections |

**graph_exposure_perimeter Examples:**
```
"What is the exposure perimeter of my critical SQL servers?"
"Which of my virtual machines have the highest exposure perimeter?"
"What is the exposure perimeter of user X?"
```

**graph_find_blastRadius Examples:**
```
"Find the blast radius of user Sam"
"What's the scope of impact if user Sam is compromised?"
"If user Sam is breached, what would be the potential impact?"
"What is the blast radius from 'Laura Hanak'?"
```

**graph_find_walkable_paths Examples:**
```
"Show me paths from user Sam to SQL-Server-01"
"How can an attacker reach my domain controller from a compromised workstation?"
"What are the attack paths between the external endpoint and my database?"
"Is there a path from user Mark Gafarov to key vault wg-prod?"
"Who can all get to wg-prod key vault?"
```

**Advanced Investigation Prompt:**
```
"If I want to minimize the blast radius for this user, what are the most common 
walkable paths for these key vaults? I'm looking for strategies where a single 
mitigation can cover multiple paths."
```

##### Supported 1P Graphs

The Sentinel Graph platform supports multiple first-party graphs:
- **Exposure/Hunting Graph** - Attack surface and threat hunting
- **DSI Graph** - Device Security Information
- **IRM Graph** - Identity Risk Management
- **TI Graph** - Threat Intelligence
- **Custom Graphs** - User-authored graph structures (see next section)

**Common Graph Endpoints for Investigations:**
```
# User profile and attributes
/v1.0/users/{upn}?$select=id,displayName,userPrincipalName,accountEnabled

# User's authentication methods (MFA)
/v1.0/users/{id}/authentication/methods

# User's registered devices
/v1.0/users/{id}/registeredDevices

# User's group memberships
/v1.0/users/{id}/memberOf

# Identity Protection risky users
/v1.0/identityProtection/riskyUsers/{id}

# Identity Protection risk detections
/v1.0/identityProtection/riskDetections?$filter=userPrincipalName eq '{upn}'

# Security incidents (alternative to Triage MCP)
/v1.0/security/incidents/{id}

# Security alerts
/v1.0/security/alerts_v2/{id}
```

#### Security Copilot Agent Creation Server (mcp_agent_creatio_*)

Tools for building and deploying custom Security Copilot agents.

| Tool | Description | Parameters |
|------|-------------|------------|
| `start_agent_creation` | Initialize agent creation workflow | `name`, `description` |
| `search_for_tools` | Discover available tools for agent | `query` (capability search) |
| `compose_agent` | Compose agent with selected tools | `agentId`, `tools[]` |
| `deploy_agent` | Deploy agent to production | `agentId` |
| `get_evaluation` | Get agent evaluation/test results | `agentId` |

**Use Cases:**
- Create specialized investigation agents
- Build automated response playbooks
- Deploy custom SOC automation workflows

---

### Microsoft Sentinel Custom Graphs (VS Code Extension)

**NEW CAPABILITY**: Create custom graph representations of security data using Jupyter notebooks in the Microsoft Sentinel VS Code extension. This enables visual analysis of attack patterns, entity relationships, and threat investigations.

> **Note**: This is different from the Sentinel Graph MCP API tools above. Custom Graphs uses Jupyter notebooks with specialized Python libraries for graph creation and GQL queries.

#### Prerequisites

1. **Onboard to Microsoft Sentinel data lake**
2. **Install VS Code with Microsoft Sentinel extension** (Pre-Release version during preview)
3. **Required Permissions:**

| Operation | Permission Required |
|-----------|---------------------|
| Create/query ephemeral graph | XDR role with data (manage) over Sentinel data collection |
| Materialize graph in tenant | Security Operator, Security Administrator, or Global Administrator |
| Query materialized graph | XDR role with security data basics (read) |

#### Key Python Libraries

```python
from sentinel_lake.providers import MicrosoftSentinelProvider  # Data lake access
from sentinel_graph.builders import GraphSpecBuilder            # Graph specification
from pyspark.sql.functions import col, count, lit, expr        # DataFrame operations
```

#### Workflow: Creating Custom Investigation Graphs

**Step 1: Initialize Provider and Read Data**
```python
# Initialize Sentinel data lake provider
sentinel_provider = MicrosoftSentinelProvider(spark)

# Read SignInLogs from your workspace (last 14 days)
signIn_df = (sentinel_provider.read_table('SigninLogs', "<YourWorkspaceName>")
    .filter((col("UserType").isin("Member")) & 
            (col('TimeGenerated') >= expr("current_timestamp() - INTERVAL 14 DAYS")))
    .select("Identity", "UserId", "IPAddress", "AppId", "ResourceDisplayName", 
            "UserPrincipalName", "TimeGenerated")
    .persist()
)

# Read Entra Users
users_df = (sentinel_provider.read_table('EntraUsers')
    .filter(col("id").isNotNull())
    .select("country", "department", "displayName", "id", "mail")
    .dropDuplicates(["id"])
    .persist()
)
```

**Step 2: Create Node and Edge DataFrames**
```python
# Define node types
EntraUsers_df = users_df.withColumn("nodeType", lit("User"))
Department_df = users_df.selectExpr("Department as Org").distinct().withColumn("nodeType", lit("Department"))
AppInfo_df = signIn_df.selectExpr("ResourceId", "AppId", "ResourceDisplayName as AppName")\
    .withColumn("nodeType", lit("App")).dropDuplicates(["ResourceId", "AppId"])

# Define edge types (relationships)
BelongsTo_df = users_df.withColumn("edgeType", lit("BelongsTo"))
CommunicatedWith_df = signIn_df.groupBy("UserId", "IPAddress", "AppId")\
    .agg(count("*").alias("count"))
```

**Step 3: Build Graph Specification**
```python
from sentinel_graph.builders import GraphSpecBuilder

builder = (GraphSpecBuilder.start()
    .add_node("Users")
        .from_dataframe(EntraUsers_df.df)
        .with_columns("country", "department", "displayName", "id", key="id", display="id")
    .add_node("Applications")
        .from_dataframe(AppInfo_df.df)
        .with_columns("ResourceId", "AppId", "AppName", key="AppId", display="AppId")
    .add_node("Department")
        .from_dataframe(Department_df.df)
        .with_columns("Org", key="Org", display="Org")
    .add_edge("BelongsTo")
        .from_dataframe(BelongsTo_df.df)
        .source(id_column="UserId", node_type="Users")
        .target(id_column="department", node_type="Department")
    .add_edge("communicatedWith")
        .from_dataframe(CommunicatedWith_df)
        .source(id_column="UserId", node_type="Users")
        .target(id_column="AppId", node_type="Applications")
).done()

# Build the graph
build_result = my_graph.build_graph_with_data()
print(f"Status: {build_result.get('status')}")  # Should print: Status: success
```

**Step 4: Query Graph with GQL**
```gql
-- Find all users in a specific department and their app relationships
MATCH (n:Users)-[e]->(s) 
WHERE n.department = 'Security Operations' 
RETURN * LIMIT 50

-- Find communication patterns for investigation
MATCH (n)-[e:communicatedWith]->(a), (n)-[b:BelongsTo]->(d)
WHERE d.Org IN ["IT", "Security"]
RETURN * LIMIT 50

-- Investigate specific user's connections
MATCH (u:user)-[s:sign_in]->(d:device) 
RETURN u, s, d LIMIT 10
```

#### Graph Types

| Type | Description | Use Case |
|------|-------------|----------|
| **Ephemeral Graph** | Temporary, exists only in notebook session | Ad-hoc investigations, prototyping |
| **Materialized Graph** | Persisted in tenant with scheduled refresh | Production monitoring, recurring analysis |

#### Investigation Use Cases

1. **Blast Radius Analysis** - Visualize all entities affected by a compromised account
2. **Lateral Movement Detection** - Graph user-to-device-to-app relationships
3. **Anomaly Pattern Detection** - Identify unusual communication patterns
4. **Department Risk Assessment** - Map access patterns by organizational structure
5. **Application Access Mapping** - Visualize which users access which applications

**Reference Documentation:**
- [Custom Graphs in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/datalake/custom-graphs)
- [GQL Language Guide](https://learn.microsoft.com/defender-xdr/advanced-hunting-graph)
- [Blast Radius Analysis](https://learn.microsoft.com/defender-xdr/investigate-incidents#blast-radius-analysis)

---

#### GitHub Server (mcp_github_*)

Repository and code management tools.

| Tool | Description | Parameters |
|------|-------------|------------|
| `search_repositories` | Search GitHub repositories | `query` |
| `get_file_contents` | Read file content from repo | `owner`, `repo`, `path` |
| `search_code` | Search code across repositories | `query`, `language` |
| `list_issues` | List repository issues | `owner`, `repo` |
| `create_issue` | Create new issue | `owner`, `repo`, `title`, `body` |

**Investigation Use Cases:**
- Search for IOC lists and threat intel feeds
- Find detection rules (Sigma, YARA, KQL)
- Reference security tool documentation
- Track investigation tasks via issues

### MCP Server Configuration Reference

The MCP servers are configured in `.vscode/mcp.json`:

```jsonc
{
  "servers": {
    "Data Exploration": {
      "url": "https://sentinel.microsoft.com/mcp/data-exploration",
      "type": "http"
    },
    "Triage": {
      "url": "https://sentinel.microsoft.com/mcp/triage",
      "type": "http"
    },
    "Microsoft Learn": {
      "url": "https://learn.microsoft.com/api/mcp",
      "type": "http"
    },
    "Agent Creation": {
      "url": "https://sentinel.microsoft.com/mcp/security-copilot-agent-creation",
      "type": "http"
    },
    "GitHub": {
      "url": "https://api.githubcopilot.com/mcp",
      "type": "http"
    },
    "Sentinel Graph": {
      "url": "https://sentinel.microsoft.com/mcp/graph",
      "type": "http"
    }
  }
}
```

### Tool Summary by Server

| Server | Prefix | Tool Count | Primary Use |
|--------|--------|------------|-------------|
| Data Exploration | `mcp_data_explorat_` | 6 | Sentinel KQL queries, entity analysis |
| Triage | `mcp_triage_` | 27 | Defender XDR incidents, devices, files |
| Microsoft Learn | `mcp_microsoft_lea_` | 3 | Documentation, code samples |
| Sentinel Graph | `mcp_microsoft_mcp_microsoft_graph_*` + `graph_*` | 7 | Identity data, blast radius, attack paths |
| Agent Creation | `mcp_agent_creatio_` | 5 | Custom agent building |
| GitHub | `mcp_github_*` | 5+ | Code search, repo management |

**Total Available MCP Tools: 53+**

**Purpose-Built Graph Investigation Tools (NEW):**
| Tool | Use Case |
|------|----------|
| `graph_exposure_perimeter` | Identify most exposed assets in your environment |
| `graph_find_blastRadius` | Evaluate impact if a node is compromised |
| `graph_find_walkable_paths` | Find attack paths between source and target |

**Additional Capabilities (VS Code Extension):**
| Feature | Technology | Use Case |
|---------|------------|----------|
| Custom Graphs | Jupyter + Spark + GQL | Visual graph analysis, custom relationship mapping |

---

# Part III: SKILLS (Response Actions)
*Actions, triggers, workflows*

---

## Response Actions via Defender Response MCP Tools

This section documents the available response actions that can be executed during incident remediation using the **Defender Response MCP VS Code Extension**. These align with the "Skills" component of the Security Agent architecture and are automated through the `defender-response` agent skill (`.github/skills/defender-response/SKILL.md`).

### ⚠️ Safety Rules for Response Actions

**BEFORE executing ANY destructive response action:**
1. ✅ **Investigate first** — Gather evidence using investigation skills before remediating
2. ✅ **Confirm the target** — Verify device name, user UPN, or incident ID
3. ✅ **Explain the impact** — Describe what the action will do before executing
4. ✅ **Ask for confirmation** — Destructive actions require explicit analyst approval
5. ✅ **Document the action** — Add incident comments explaining what was done and why
6. ✅ **Track completion** — Verify action status after execution

### Identity Response Actions

Actions for user account remediation via Defender Response MCP:

| Action | MCP Tool Chain | Description |
|--------|---------------|-------------|
| **Confirm User Compromised** | `activate_user_compromise_management_tools` → `defender_confirm_user_compromised` | Escalate Entra ID risk level |
| **Confirm User Safe** | `activate_user_compromise_management_tools` → `defender_confirm_user_safe` | Dismiss user risk after investigation |
| **Disable AD Account** | `activate_active_directory_account_management_tools` → `defender_disable_ad_account` | Block all authentication |
| **Enable AD Account** | `activate_active_directory_account_management_tools` → `defender_enable_ad_account` | Re-enable after remediation |
| **Force Password Reset** | `activate_active_directory_account_management_tools` → `defender_force_ad_password_reset` | Mandate credential change |

**Additional Graph API Actions** (via Sentinel Graph MCP):

| Action | Graph API Endpoint | Description |
|--------|-------------------|-------------|
| **Revoke Sessions** | `POST /v1.0/users/{id}/revokeSignInSessions` | Invalidate all refresh tokens |
| **Remove MFA Method** | `DELETE /v1.0/users/{id}/authentication/methods/{id}` | Remove compromised auth method |

### Endpoint Response Actions

Actions via Defender Response MCP tools:

| Action | MCP Tool Chain | Description |
|--------|---------------|-------------|
| **Isolate Device** | `activate_device_response_tools` → `defender_isolate_device` | Network isolation (Defender comms preserved) |
| **Restrict Code Execution** | `activate_device_response_tools` → `defender_restrict_code_execution` | Only Microsoft-signed apps allowed |
| **Run AV Scan** | `activate_device_response_tools` → `defender_run_antivirus_scan` | On-demand malware detection |
| **Stop and Quarantine** | `activate_device_response_tools` → `defender_stop_and_quarantine` | Kill process + quarantine file |
| **Bulk Isolate Devices** | `activate_bulk_device_management_tools` → `defender_isolate_multiple` | Isolate multiple devices at once |
| **Release Device** | `activate_bulk_device_management_tools` → `defender_release_device` | Restore network connectivity |

### Forensic Collection

| Action | MCP Tool Chain | Description |
|--------|---------------|-------------|
| **Collect Investigation Package** | `activate_forensic_investigation_tools` → `defender_collect_investigation_package` | Gather system info, logs, diagnostics |
| **Get Package Download URI** | `activate_forensic_investigation_tools` → `defender_get_investigation_package_uri` | Retrieve download link |

### Incident Management Actions

| Action | MCP Tool Chain | Description |
|--------|---------------|-------------|
| **Add Comment** | `activate_incident_management_tools` → `defender_add_incident_comment` | Document investigation notes |
| **Add Tags** | `activate_incident_management_tools` → `defender_add_incident_tags` | Categorize incident |
| **Assign Incident** | `activate_incident_management_tools` → `defender_assign_incident` | Delegate to analyst |
| **Classify Incident** | `activate_incident_management_tools` → `defender_classify_incident` | True/False positive determination |
| **Update Status** | `activate_incident_management_tools` → `defender_update_incident_status` | Active → Resolved, etc. |

### Device Monitoring (Read-Only)

| Action | MCP Tool Chain | Description |
|--------|---------------|-------------|
| **Get Machine Actions** | `activate_device_monitoring_tools` → `defender_get_machine_actions` | List recent response actions on device |
| **Find Machine by Name** | `activate_device_monitoring_tools` → `defender_get_machine_by_name` | Device health, risk, exposure details |

### Network Response Actions

IOC-based blocking and network response:

| Action | MCP Tool | Description |
|--------|----------|-------------|
| **Block IP Indicator** | `ListDefenderIndicators` + create | Add IP to block list |
| **Block URL Indicator** | `ListDefenderIndicators` + create | Block malicious URL |
| **Block File Hash** | `ListDefenderIndicators` + create | Block file by SHA256 |
| **Alert on Indicator** | `ListDefenderIndicators` + create | Alert-only IOC |

**IOC Indicator Types:**
- `IpAddress` - Block/alert on IP
- `Url` - Block/alert on URL
- `FileSha256` - Block/alert on file hash
- `DomainName` - Block/alert on domain
- `FileSha1` - Block/alert on SHA1 hash

### Remediation Tracking

Track remediation status via:

| Tool | Description |
|------|-------------|
| `ListDefenderRemediationActivities` | List all remediation tasks |
| `GetDefenderRemediationActivity` | Get specific remediation status |

### Response Playbooks (Defender Response MCP)

#### Playbook 1: Compromised Account Response

```
├── 1. Confirm user compromised         (defender_confirm_user_compromised)
├── 2. Disable AD account               (defender_disable_ad_account)
├── 3. Force password reset              (defender_force_ad_password_reset)
├── 4. Isolate user's devices            (defender_isolate_device)
├── 5. Block attacker IPs               (IOC Indicators)
├── 6. Document actions                  (defender_add_incident_comment)
└── 7. Classify incident                 (defender_classify_incident)
```

#### Playbook 2: Malware Containment

```
├── 1. Isolate device immediately        (defender_isolate_device)
├── 2. Stop and quarantine malware       (defender_stop_and_quarantine)
├── 3. Restrict code execution           (defender_restrict_code_execution)
├── 4. Run full AV scan                  (defender_run_antivirus_scan)
├── 5. Collect forensic package          (defender_collect_investigation_package)
├── 6. Check file spread across org      (mcp_triage_GetDefenderFileRelatedMachines)
└── 7. Document and classify             (defender_add_incident_comment)
```

#### Playbook 3: Ransomware / Bulk Containment

```
├── 1. Bulk isolate all affected devices (defender_isolate_multiple)
├── 2. Disable all affected user accounts(defender_disable_ad_account × N)
├── 3. Restrict code execution on all    (defender_restrict_code_execution × N)
├── 4. Run AV scans on all devices       (defender_run_antivirus_scan × N)
├── 5. Collect forensics from patient 0  (defender_collect_investigation_package)
├── 6. Tag incident critical             (defender_add_incident_tags)
└── 7. Assign to incident commander      (defender_assign_incident)
```

#### Playbook 4: Post-Remediation Recovery

```
├── 1. Verify AV scan clean              (defender_get_machine_actions)
├── 2. Release device from isolation     (defender_release_device)
├── 3. Re-enable user account            (defender_enable_ad_account)
├── 4. Confirm user safe                 (defender_confirm_user_safe)
├── 5. Resolve incident                  (defender_update_incident_status)
└── 6. Closing comment                   (defender_add_incident_comment)
```

---

## 11. External Enrichment Integration
*Threat intelligence integration for IOC enrichment*

This section covers integration with external threat intelligence sources to enrich investigation data. Learn how to automatically query VirusTotal, AbuseIPDB, GreyNoise, and other platforms to add context to IPs, domains, and file hashes discovered during investigations.

### Overview
CyberProbe integrates external threat intelligence sources to enrich investigation data automatically. When investigating incidents, IPs, domains, or file hashes, the system can automatically query multiple threat intelligence platforms.

### Supported Enrichment Sources

#### IP Address Enrichment
- **VirusTotal** - Malicious IP detection, reputation scores
- **AbuseIPDB** - Abuse reports and confidence scoring
- **GreyNoise** - Internet scanning classification (benign/malicious)
- **IPInfo** - Geolocation, ISP, and organization data
- **Shodan** - Open port and service information
- **AlienVault OTX** - Threat pulse and indicator feeds

#### File Hash Enrichment
- **VirusTotal** - Multi-engine malware analysis
- **Hybrid Analysis** - Sandbox execution reports
- **MalwareBazaar** - Malware sample database

#### Domain Enrichment
- **VirusTotal** - Domain reputation and detection
- **URLhaus** - Malicious URL database
- **PhishTank** - Phishing site verification

### Configuration

**Setup API Keys:**
Edit `enrichment/config.json` with your API keys:
```json
{
  "api_keys": {
    "virustotal": "your_vt_key",
    "abuseipdb": "your_abuseipdb_key",
    "greynoise": "your_greynoise_key",
    "ipinfo": "your_ipinfo_key"
  }
}
```

### Enrichment Scripts

#### IP Enrichment - `enrichment/enrich_ips.py`
Enriches IP addresses with threat intelligence and calculates risk scores.

**Usage:**
```bash
# Single IP
python enrichment/enrich_ips.py 192.168.1.1

# Multiple IPs
python enrichment/enrich_ips.py 8.8.8.8 1.1.1.1 45.142.120.1

# JSON input
python enrichment/enrich_ips.py --json '["8.8.8.8", "1.1.1.1"]'
```

**Output:**
```json
{
  "ip": "45.142.120.1",
  "enrichment_timestamp": "2025-12-16 14:30:00",
  "sources": {
    "virustotal": {
      "malicious_count": 5,
      "suspicious_count": 2,
      "reputation": -15
    },
    "abuseipdb": {
      "abuse_confidence_score": 85,
      "total_reports": 127,
      "country": "RU"
    }
  },
  "risk_assessment": {
    "risk_score": 72,
    "risk_level": "CRITICAL",
    "risk_factors": [
      "VT: 5 malicious detections",
      "AbuseIPDB: 85% confidence"
    ]
  }
}
```

### Automated Enrichment Workflow

When you request incident investigation, the workflow automatically:

1. **Extract IOCs** - Parse IPs, domains, hashes from Defender data
2. **Enrich** - Call enrichment scripts with extracted IOCs
3. **Correlate** - Combine Defender data with threat intelligence
4. **Prioritize** - Use risk scores to highlight critical findings
5. **Present** - Display enriched results with context

**Example Query:**
```
"Show me top incidents from Defender"
```

**Automated Process:**
1. Query Defender XDR for recent high-severity incidents
2. Extract all IP addresses from incident data
3. Run `enrichment/enrich_ips.py` with extracted IPs
4. Combine results showing:
   - Incident details from Defender
   - Threat intelligence for each IP
   - Risk assessment and recommendations

### Risk Scoring

**Risk Score Calculation:**
- VirusTotal malicious detections: +10 per detection (max 40)
- AbuseIPDB confidence: up to +30 based on percentage
- GreyNoise malicious classification: +30
- GreyNoise suspicious classification: +15

**Risk Levels:**
- **CRITICAL** (70-100): Immediate threat, block immediately
- **HIGH** (50-69): Likely malicious, investigate urgently
- **MEDIUM** (30-49): Suspicious, monitor closely
- **LOW** (1-29): Minor concerns, routine investigation
- **CLEAN** (0): No indicators found

### Adding Custom Enrichment Sources

Create new enrichment scripts following this pattern:

```python
def enrich_custom_source(indicator: str) -> Dict:
    """Template for custom enrichment"""
    api_key = config['api_keys']['custom_source']
    response = requests.get(f"https://api.example.com/{indicator}")
    return {
        "source": "CustomSource",
        "threat_level": response.json()['threat_level'],
        "confidence": response.json()['confidence']
    }
```

### Investigation Workflow with MCP

1. **Incident Discovery**
   - Use `ListIncidents` to identify active incidents
   - Filter by severity, time range, or status
   
2. **Data Source Discovery**
   - Use `search_tables` to find relevant data sources
   - Understand table schemas before querying

3. **Query Execution**
   - Use `query_lake` for Sentinel Data Lake queries
   - Use `RunAdvancedHuntingQuery` for Defender XDR data

4. **Entity Investigation**
   - Use specific tools for devices, files, IPs
   - Correlate findings across different data sources

5. **Add Enrichment Data**
   - Include threat intelligence from `enrichment/enrich_ips.py` output

6. **Remediation Tracking**
   - Monitor automated investigations
   - Track remediation activities

---

## 12. Investigation Playbooks
*Step-by-step guides for specific incident types*

This section provides structured playbooks for investigating common security incidents. Each playbook includes the investigation objective, step-by-step procedures, and key queries to run during the investigation.

### Playbook 1: Ransomware Investigation

**Objective:** Identify ransomware activity and scope of impact

**Steps:**
1. Identify initial alert/detection
2. Determine patient zero (first infected device)
3. Map lateral movement
4. Identify encrypted files
5. Check for data exfiltration
6. Assess backup integrity
7. Contain affected systems

**Key Queries:**
- File encryption events
- Mass file modifications
- Ransom note creation
- Unusual network activity
- Privilege escalation

### Playbook 2: Phishing Investigation

**Objective:** Assess phishing campaign impact

**Steps:**
1. Identify malicious email characteristics
2. Find all recipients
3. Check who clicked links/opened attachments
4. Assess compromised accounts
5. Check for follow-on activity
6. Remediate mailboxes

**Key Queries:**
- Email campaign analysis
- URL click tracking
- Attachment execution
- Post-compromise activity

### Playbook 3: Insider Threat Investigation

**Objective:** Investigate suspicious user activity

**Steps:**
1. Establish baseline user behavior
2. Identify anomalous activities
3. Check data access patterns
4. Investigate data exfiltration attempts
5. Review privilege usage
6. Correlate with HR events

**Key Queries:**
- File access patterns
- Data transfers
- Cloud uploads
- Privilege escalation
- After-hours activity

### Playbook 4: Compromised Identity

**Objective:** Investigate and contain compromised account

**Steps:**
1. Identify anomalous sign-in activity
2. Check for impossible travel
3. Review permissions/role changes
4. Assess data accessed
5. Check for persistence mechanisms
6. Reset credentials
7. Revoke tokens

**Key Queries:**
- Sign-in anomalies
- Privilege changes
- API token creation
- MFA changes
- Mailbox rule creation

---

## 13. Common Investigation Scenarios
*Real-world examples with specific indicators and investigation paths*

This section provides concrete examples of common security scenarios you'll encounter, including brute force attacks, data exfiltration, and privilege escalation. Each scenario includes indicators to look for and specific KQL queries to execute.

### Scenario: Brute Force Attack

### Query Optimization
- Always filter on TimeGenerated first
- Use specific column filters early in query
- Limit result sets with `take` or `summarize`
- Use `project` to reduce data volume
- Leverage table-specific optimizations

### Investigation Efficiency
- Start broad, then narrow focus
- Use correlation to connect disparate events
- Leverage entity relationships (user → device → files)
- Document findings throughout investigation
- Save useful queries as functions

### Data Retention Considerations
- Default Sentinel retention: 90 days
- Defender XDR Advanced Hunting: 30 days
- Plan queries accordingly
- Archive critical findings

### Security Operations
- Use watchlists for known IOCs
- Create analytics rules for detection
- Automate response with playbooks
- Regular threat hunting exercises
- Continuous improvement of detections

---

## 14. Quick Reference
*KQL syntax patterns and common operators*

This section provides quick reference materials for KQL syntax, including time filters, common operators, and summarization techniques. Use this as a cheat sheet when writing queries.

### Time Filters

### Scenario: Brute Force Attack
**Indicators:**
- Multiple failed sign-ins
- Followed by successful sign-in
- From unusual location/IP

**Investigation Path:**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"  // Failed sign-ins
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

### Scenario: Data Exfiltration
- Large data transfers
- Unusual cloud uploads
- USB device usage
- Email forwarding rules

**Investigation Path:**
```kql
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileUploaded", "FileCopied", "FileDownloaded")
| summarize TotalSize = sum(todouble(ObjectSize)), FileCount = count() 
    by AccountObjectId, Application, bin(TimeGenerated, 1h)
| where TotalSize > 1000000000  // >1GB
```

### Scenario: Privilege Escalation
- Permission changes
- Role assignments
- Service principal creation
- Sudo usage (Linux)

**Investigation Path:**
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add member to role", "Add app role assignment")
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, Initiator, Target, Result
```

---

## 15. Best Practices

**⭐ OPERATIONAL EXCELLENCE CHECKLIST**

### Investigation Discipline

**Always Document:**
- Query execution time and date range used
- Data sources queried (SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, etc.)
- MCP tool invocations with exact parameters
- Empty results (critical for negative evidence)
- Anomalies NOT detected (establishes baseline)

**Time Management:**
- Track total investigation time from start to report export
- Set investigation type upfront (Standard 7d, Quick 1d, Comprehensive 30d)
- Use parallel query execution for independent data sources
- Log MCP server response times for troubleshooting

**Data Quality:**
- Verify User Object ID and Windows SID before incident correlation (Query 6)
- Always check if SessionId is populated before tracing (Query 9 Step 1)
- Handle missing Graph fields gracefully (department, officeLocation)
- Export anomalies array even if empty (required field)

### Automation-Specific Guidelines

**For AI Assistants (GitHub Copilot + MCP Servers):**

**Rule 1: Context Awareness**
- ALWAYS ask for current date/time BEFORE calculating date ranges
- Real-time searches: Add +2 days to end range (Rule 1 from Section 8)
- Historical searches: Add +1 day to end range (Rule 2 from Section 8)

**Rule 2: Required Workflow Checkpoints**
1. Get User Object ID + Windows SID from Graph API FIRST
2. Run Query 2 (anomalies) to determine investigation scope
3. If anomalies exist: Run Query 1 (extract IPs) → Query 3d (sign-in counts) → Query 11 (threat intel)
4. If SessionId populated: Run Advanced Authentication Analysis (Section 9)
5. Export JSON with all 20+ required fields (see Section 14)

**Rule 3: Field Validation**
- `department`: Default to "Unknown" if null
- `officeLocation`: Default to "Unknown" if null
- `anomalies`: Export empty array `[]` if Query 2 returns no results
- `lastAuthResultDetail`: Extract from Query 3d, NOT from random sign-in
- `ipEnrichment`: Mandatory for all IPs (ipinfo.io + AbuseIPDB + GreyNoise + VirusTotal)

**Rule 4: Error Handling**
- Graph 404 error → Verify UPN spelling, check if user exists
- KQL timeout → Reduce date range, add `| take 100` limit
- SemanticError → Check table schema, field may not exist in this workspace
- Empty threat intel results → Not an error, export as empty array

**Rule 5: Parallel Query Execution**
Execute these queries in parallel (no dependencies):
- Query 2 (anomalies) + Query 3 (sign-ins by app) + Query 3b (sign-ins by location) + Query 4 (audit logs) + Query 5 (Office 365 activity) + Query 10 (DLP events)

Execute these queries sequentially (dependent):
- Query 1 (extract IPs) → THEN Query 3d (sign-in counts for those IPs) → THEN Query 11 (threat intel for those IPs)

### Security Recommendations

**Credential Management:**
- Store API keys (VirusTotal, AbuseIPDB, etc.) in environment variables, NOT config files
- Rotate MCP server tokens quarterly
- Use read-only service accounts for KQL queries

**Data Retention:**
- Sentinel Data Lake: 90 days default (verify with `mcp_data_explorat_search_tables`)
- Defender XDR Advanced Hunting: 30 days
- Export critical investigation data to external storage (JSON format)

**Incident Response:**
- High-severity anomalies → Force password reset + revoke all sessions
- SessionId tracing shows compromise → Document full attack timeline in report
- DLP violations → Escalate to legal/compliance teams immediately

---

## 16. Troubleshooting Guide

**🔧 COMMON ISSUES AND SOLUTIONS**

### KQL Query Errors

| Error | Root Cause | Solution |
|-------|-----------|----------|
| `SemanticError: 'column_name' does not exist` | Field not present in this workspace schema | Run `mcp_data_explorat_search_tables` to verify schema, use alternate field |
| `Query timeout (30s exceeded)` | Date range too large, expensive aggregation | Reduce date range to 7 days, add `\| take 100`, use `summarize` instead of `mv-expand` |
| `Dynamic request throttled` | Too many concurrent KQL queries | Add 2-second delay between queries, use parallel execution sparingly |
| `Invalid datetime format` | Incorrect datetime() syntax | Use `datetime(2026-01-07)`, NOT `datetime("2026-01-07")` |
| `union: Column mismatch` | SigninLogs vs AADNonInteractiveUserSignInLogs schema drift | Use `union isfuzzy=true` to ignore schema differences |
| **`Expected: ;`** syntax error | **Using `has_any` with backslash-containing strings** | **See detailed explanation below** ⚠️ CRITICAL |

#### ⚠️ CRITICAL: `has_any` Operator with Backslashes

**Problem:**
The `has_any` operator **FAILS** when search terms contain **backslashes** (Windows paths, registry keys):

```kql
// ❌ THIS WILL FAIL WITH "Expected: ;" ERROR
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Windows\\System32\\")
| where RegistryKey has_any ("\\Run", "\\RunOnce", "\\Startup")
| where FileName endswith_any (".exe", ".dll", ".ps1")  // Also problematic with file extensions
```

**Root Cause:**
- KQL cannot properly parse **escape sequences** (`\\`) inside `has_any` arrays
- Affects **DeviceFileEvents**, **DeviceRegistryEvents**, **DeviceProcessEvents**
- Error message: `Failed to execute KQL query with validation errors: Expected: ;`

**✅ SOLUTIONS:**

**Option 1: Use `contains` with OR (RECOMMENDED for paths)**
```kql
// ✅ CORRECT - Use contains with OR for Windows paths
| where FolderPath contains "\\Temp\\" or FolderPath contains "\\AppData\\" or FolderPath contains "\\Windows\\System32\\"
| where RegistryKey contains "\\Run" or RegistryKey contains "\\RunOnce" or RegistryKey contains "\\Startup"
```

**Option 2: Use individual `endswith` with OR (for file extensions)**
```kql
// ✅ CORRECT - Individual endswith operators
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
```

**Option 3: Use `has_any` only for simple strings (no backslashes)**
```kql
// ✅ SAFE - has_any works fine with simple strings
| where ActionType has_any ("ProcessCreated", "FileCreated", "RegistryValueSet")
| where DeviceName has_any ("workstation01", "server02", "laptop03")
```

**Real-World Example from Device Investigation:**

```kql
// ❌ BROKEN QUERY (Phase 4 - File Operations)
DeviceFileEvents
| where DeviceId == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
| where TimeGenerated > ago(24h)
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Windows\\Tasks\\")
| where FileName endswith_any (".exe", ".dll", ".ps1", ".vbs", ".bat")

// ✅ FIXED QUERY
DeviceFileEvents
| where DeviceId == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
| where TimeGenerated > ago(24h)
| where (FolderPath contains "\\Temp\\" or FolderPath contains "\\AppData\\" 
         or FolderPath contains "\\ProgramData\\" or FolderPath contains "\\Windows\\Tasks\\")
| where (FileName endswith ".exe" or FileName endswith ".dll" 
         or FileName endswith ".ps1" or FileName endswith ".vbs" or FileName endswith ".bat")
```

**When to Use Each Operator:**
- **`has_any`**: Simple strings, no special characters (ActionType, DeviceName, UserName)
- **`contains` + OR**: Windows paths, registry keys (anything with backslashes)
- **`startswith`/`endswith`**: Prefix/suffix matching without arrays
- **`matches regex`**: Complex patterns (slowest, use sparingly)

### Microsoft Graph API Errors

| HTTP Code | Error Message | Solution |
|-----------|--------------|----------|
| 404 | `User not found` | Verify UPN spelling, check if user was deleted, use Object ID instead |
| 403 | `Insufficient privileges` | Add `User.Read.All` + `IdentityRiskEvent.Read.All` permissions to service principal |
| 429 | `Too many requests` | Implement exponential backoff (1s, 2s, 4s, 8s delays) |
| 500 | `Internal server error` | Retry after 30 seconds, escalate if persistent |

### MCP Server Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `mcp_data_explorat_query_lake` returns empty | Wrong workspace ID | Run `mcp_data_explorat_list_sentinel_workspaces` to get correct ID |
| `mcp_triage_ListIncidents` slow (>60s) | Large incident dataset | Add `top` parameter (e.g., `top: 100`), filter by date range |
| Authentication failed | Expired token | Re-authenticate MCP server, check token expiration |
| Table not found | Schema change or custom table | Use `mcp_data_explorat_search_tables` with natural language query |

### Data Quality Issues

| Problem | Detection Method | Fix |
|---------|-----------------|-----|
| Missing `department` field | Graph API returns null | Default to "Unknown", document in investigation notes |
| Empty anomalies array | Query 2 returns 0 rows | **This is valid!** Export empty array `[]`, document "No anomalies detected" |
| SessionId is null | Advanced Authentication Analysis Step 1 fails | Use time-window correlation (±5 min), filter by User-Agent |
| IP enrichment missing | External API down (ipinfo.io, AbuseIPDB) | Export with `"error": "API unavailable"`, proceed with investigation |
| Last authentication method unknown | Query 3d returns "Token" | Check for interactive sign-ins in wider date range, may indicate token-only activity |

### Investigation Workflow Issues

| Issue | Symptom | Resolution |
|-------|---------|-----------|
| Cannot correlate incidents to user | Query 6 returns 0 results | Verify you have User Object ID AND Windows SID from Graph API |
| Anomaly flagged but appears legitimate | High anomaly count from known VPN | Check SessionId tracing (Section 9), look for initial MFA from corporate network |
| Geographic anomaly from user's home country | User traveling for work | Cross-reference with HR data, PTO calendar, or ask user directly |
| Impossible travel between Seattle and London | Token refresh, not actual sign-in | Examine `AuthenticationRequirement` field - token refreshes won't show MFA |

### Automation-Specific Issues

**For AI Assistants:**

| Error Condition | Example | Correct Approach |
|----------------|---------|------------------|
| "Today is Jan 7" but date range excludes Jan 7 data | User asks for "last 7 days" → Query uses `datetime(2026-01-07)` as end | Add +2 days: `datetime(2026-01-09)` to include full Jan 7 + timezone offset |
| Missing required JSON fields | Export omits `windowsSID` or `anomalies` | **ALL fields mandatory** - use "Unknown" for missing strings, `[]` for empty arrays |
| Querying non-existent fields | Trying to access `SigninLogs.DepartmentName` | Run `mcp_data_explorat_search_tables` first, use Graph API for user attributes |
| IP enrichment skipped | Only running threat intel, not external APIs | **Both required** - Query 11 (Sentinel) + ipinfo.io/AbuseIPDB/GreyNoise/VirusTotal |

### Performance Optimization

**Slow Query Troubleshooting:**
1. Check date range - Reduce to 7 days max for initial investigation
2. Add early filters - Put `where UserPrincipalName =~ '<UPN>'` BEFORE expensive operations
3. Use `take` instead of `top` - `take 10` stops at 10 rows, `top 10` scans all then sorts
4. Limit `make_set()` - Use `make_set(field, 10)` instead of unbounded `make_set(field)`
5. Avoid `mv-expand` on large JSON - Summarize first, then expand only necessary rows

---

## 17. Investigation Report Template
*Standardized format for documenting investigation results*

This section provides a consistent report structure for all investigations. Use this template to ensure comprehensive documentation and easy comparison between incidents.

### Standard Report Structure

```markdown
# Security Investigation Report

## Executive Summary
**Incident ID:** [Incident ID]
**Report Date:** [Date]
**Investigator:** [Name]
**Severity:** [Critical/High/Medium/Low]
**Status:** [Active/Contained/Resolved]

**Summary:** [2-3 sentence overview of the incident and outcome]

---

## 1. Incident Overview

### Basic Information
- **Detection Time:** [Timestamp]
- **Detection Source:** [Defender for Endpoint/Identity/Office 365/etc.]
- **Initial Alert:** [Alert name/description]
- **MITRE ATT&CK Tactics:** [e.g., Initial Access, Lateral Movement]
- **MITRE ATT&CK Techniques:** [e.g., T1078, T1021]

### Scope of Impact
- **Affected Users:** [Number and list]
- **Affected Devices:** [Number and list]
- **Affected Systems:** [Applications, services, data]
- **Duration:** [Start time - End time]

---

## 2. Investigation Timeline

| Time | Event | Source | Severity |
|------|-------|--------|----------|
| [Timestamp] | [Event description] | [Data source] | [Level] |
| [Timestamp] | [Event description] | [Data source] | [Level] |

---

## 3. Technical Analysis

### Initial Access
- **Attack Vector:** [Description]
- **Entry Point:** [System, user, application]
- **Indicators:**
  - IP Addresses: [List]
  - User Accounts: [List]
  - Compromised Assets: [List]

### Execution & Persistence
- **Malicious Processes:** [List with command lines]
- **Persistence Mechanisms:** [Registry keys, scheduled tasks, etc.]
- **Tools Used:** [Attacker tools identified]

### Lateral Movement
- **Movement Path:** [Source → Target]
- **Techniques Used:** [RDP, PSExec, WMI, etc.]
- **Compromised Accounts:** [List]

### Data Access & Exfiltration
- **Data Accessed:** [Description]
- **Data Exfiltrated:** [Yes/No/Unknown + Details]
- **Exfiltration Method:** [Network transfer, cloud upload, etc.]
- **Volume:** [Approximate size]

---

## 4. Indicators of Compromise (IOCs)

### Network Indicators
- **Malicious IPs:**
  - [IP Address] - [Risk Score] - [Source: VirusTotal/AbuseIPDB]
  - [IP Address] - [Risk Score] - [Source: VirusTotal/AbuseIPDB]

- **Malicious Domains:**
  - [Domain] - [Threat Type]
  - [Domain] - [Threat Type]

- **URLs:**
  - [URL] - [Threat Type]

### File Indicators
- **File Hashes (SHA256):**
  - [Hash] - [Filename] - [VT Detections: X/Y]
  - [Hash] - [Filename] - [VT Detections: X/Y]

### User Account Indicators
- **Compromised Accounts:**
  - [User Principal Name] - [Compromise Type]
  - [User Principal Name] - [Compromise Type]

---

## 5. Threat Intelligence Enrichment

### IP Address Analysis
| IP Address | Risk Score | VT Malicious | AbuseIPDB Score | Location | ISP |
|------------|------------|--------------|-----------------|----------|-----|
| [IP] | [Score] | [Count] | [Score] | [Country] | [ISP] |

### File Analysis
| File Hash | VT Detection | First Seen | Last Seen | Prevalence |
|-----------|--------------|------------|-----------|------------|
| [Hash] | [X/Y] | [Date] | [Date] | [Low/Med/High] |

### External Context
- **Known Threat Actor:** [Attribution if available]
- **Campaign Name:** [If part of known campaign]
- **Related Incidents:** [Links to similar incidents]

---

## 6. Root Cause Analysis

### Initial Vulnerability
- **Vulnerability Type:** [Missing patch, misconfiguration, weak password, etc.]
- **CVE:** [If applicable]
- **Exploit Method:** [Description]

### Security Control Gaps
- [List of failed or missing security controls]
- [e.g., MFA not enforced, EDR not deployed, etc.]

### Contributing Factors
- [Environmental factors that enabled the attack]

---

## 7. Response Actions Taken

### Containment
- [ ] Isolated affected devices
- [ ] Disabled compromised accounts
- [ ] Blocked malicious IPs/domains
- [ ] Quarantined malicious files
- [ ] Revoked authentication tokens

**Details:**
- [Timestamp] - [Action taken] - [Performed by]
- [Timestamp] - [Action taken] - [Performed by]

### Eradication
- [ ] Removed malware from systems
- [ ] Deleted malicious registry keys
- [ ] Removed persistence mechanisms
- [ ] Patched vulnerabilities

**Details:**
- [Timestamp] - [Action taken] - [Performed by]

### Recovery
- [ ] Restored systems from clean backups
- [ ] Reset compromised credentials
- [ ] Verified system integrity
- [ ] Resumed normal operations

**Details:**
- [Timestamp] - [Action taken] - [Performed by]

---

## 8. Recommendations

### Immediate Actions (0-7 days)
1. [Specific recommendation with owner and deadline]
2. [Specific recommendation with owner and deadline]

### Short-term Actions (1-4 weeks)
1. [Specific recommendation with owner and deadline]
2. [Specific recommendation with owner and deadline]

### Long-term Actions (1-3 months)
1. [Strategic improvement with owner]
2. [Strategic improvement with owner]

---

## 9. Lessons Learned

### What Worked Well
- [Effective detection/response element]
- [Effective detection/response element]

### What Could Be Improved
- [Gap or weakness identified]
- [Gap or weakness identified]

### Process Improvements
- [Procedural changes needed]
- [Procedural changes needed]

---

## 10. Appendices

### Appendix A: Query Results
[Key KQL queries and their results]

### Appendix B: Supporting Evidence
[Screenshots, logs, additional data]

### Appendix C: Automated Investigation Results
[MCP tool outputs, automated investigation summaries]

### Appendix D: Communication Log
| Time | Stakeholder | Communication | Channel |
|------|-------------|---------------|----------|
| [Time] | [Person/Team] | [Summary] | [Email/Teams/etc] |

---

## Report Metadata
**Document Version:** 1.0
**Classification:** [Confidential/Internal]
**Distribution:** [List of recipients]
**Next Review Date:** [Date]
```

### Report Generation Tips

1. **Start with the template** - Copy the template for each new investigation
2. **Fill sections progressively** - Update as investigation unfolds
3. **Use timestamps consistently** - UTC or local with timezone noted
4. **Include query results** - Paste key KQL queries in appendices
5. **Add enrichment data** - Include threat intelligence from `enrich_ips.py` output
6. **Link to evidence** - Reference logs, screenshots, and raw data
7. **Update status regularly** - Keep executive summary current
8. **Review before finalizing** - Ensure all sections are complete

### Automated Report Generation

For automated report creation, you can:
- Use the template as a starting point for scripts
- Auto-populate IOCs from KQL query results
- Insert threat intelligence from enrichment scripts
- Generate timeline from Defender incident data
- Export to HTML/PDF for distribution

---

## 9. Best Practices
*Query optimization and operational guidelines for effective investigations*

This section outlines best practices for writing efficient KQL queries, conducting thorough investigations, managing data retention, and maintaining effective security operations.

### Schema Discovery & Validation

**⚠️ CRITICAL: Prevents KQL Semantic Errors**

Sentinel table schemas can differ between tenants due to:
- Data connector configurations
- Custom columns from log ingestion
- Schema updates not yet reflected in documentation
- Microsoft Learn docs showing legacy column names

**Always validate schema before querying unfamiliar tables:**
```kql
// Get actual column names and types
ThreatIntelIndicators | getschema

// Get sample data to understand structure
ThreatIntelIndicators | take 5

// Check specific column exists before using
ThreatIntelIndicators 
| where isnotnull(ObservableValue)  // Safe null check
| take 1
```

**Known Schema Variations:**

| Table | Expected (Docs) | Actual (This Tenant) |
|-------|-----------------|---------------------|
| ThreatIntelIndicators | ThreatType, Source, Description | ObservableKey, ObservableValue, Data, Tags, Confidence |
| SecurityAlert | ExtendedProperties | AdditionalData (varies by provider) |
| IdentityInfo | Tags | Custom columns per connector |

**Pro tip:** Run `| getschema` once per investigation session for any table not in the Sample KQL Queries section.

---

### Time Filters
```kql
| where TimeGenerated > ago(1h)      // Last hour
| where TimeGenerated > ago(24h)     // Last 24 hours
| where TimeGenerated > ago(7d)      // Last 7 days
| where TimeGenerated > ago(30d)     // Last 30 days
| where TimeGenerated between (startTime .. endTime)
```

### Common Operators
```kql
has              // Fast case-insensitive search
has_any          // Match any string in list
contains         // Slower, substring match
startswith       // Prefix match
matches regex    // Regular expression
in~              // Case-insensitive list match
```

### Summarization
```kql
| summarize count() by Column                    // Count by column
| summarize dcount(Column) by OtherColumn        // Distinct count
| summarize make_set(Column) by OtherColumn      // Array of values
| summarize arg_max(TimeGenerated, *) by Entity  // Latest record
```

---

## 18. Security Copilot Agent Integration
*Import CyberProbe as a native Security Copilot agent*

### Overview

CyberProbe can be deployed as a **Security Copilot agent** for one-command user investigations directly within Microsoft Security Copilot. This eliminates the need to manually run queries or scripts - the agent orchestrates the complete investigation workflow automatically.

### Agent Capabilities

**Single Prompt Investigation:**
```
Investigate user@contoso.com for the last 7 days
```

**What the agent does automatically:**
1. ✅ Queries Sentinel Data Lake (sign-ins, anomalies, audit logs, DLP events)
2. ✅ Gets user profile and risk state from Entra ID
3. ✅ Correlates Defender XDR incidents and alerts
4. ✅ Extracts priority IPs (up to 15) for threat intelligence
5. ✅ Performs SessionId-based authentication tracing
6. ✅ Enriches IPs with Defender Threat Intelligence
7. ✅ Generates comprehensive 9-section report with risk score
8. ✅ Provides actionable recommendations (Immediate/Short-term/Long-term)

**Supported Investigation Types:**
- **Standard (7 days)**: Balanced investigation for general security concerns
- **Quick Triage (24 hours)**: Fast analysis for active incidents
- **Comprehensive (30 days)**: Deep dive for compromise assessment
- **SessionId-Focused**: Authentication timeline and session hijacking detection
- **DLP-Focused**: Data exfiltration and insider threat analysis

### Deployment Options

**Option 1: Import YAML via Security Copilot UI**
1. Open Security Copilot → Agents → Create Custom Agent
2. Upload `security-copilot-agent-generated.yaml`
3. Validate and deploy

**Option 2: Use MCP Agent Creation Tools**
Ask GitHub Copilot: "Create a Security Copilot agent for user investigations"

**Option 3: API Deployment (Advanced)**
Use Security Copilot Developer Studio API with `security-copilot-agent-generated.yaml`

### Agent Files

- **security-copilot-agent.yaml**: Hand-crafted template with extended features
- **security-copilot-agent-generated.yaml**: Auto-generated by Security Copilot Developer Studio (recommended)
- **docs/SECURITY_COPILOT_AGENT.md**: Complete deployment and usage guide

### Key Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **SessionId Tracing** | Forensic authentication timeline analysis | Detects session hijacking and token theft |
| **Priority IP Extraction** | Top 15 IPs by anomaly, risk, and frequency | Focuses threat intel budget on critical IPs |
| **Parallel Queries** | Simultaneous Sentinel/Entra/Defender queries | 60-70 second investigation time |
| **Structured Reports** | 9 sections with risk scores | Executive-ready documentation |
| **Defender TI Integration** | Native IP reputation and threat actor data | No external API keys required |

### Example Investigations

**Impossible Travel:**
```
Investigate user@contoso.com for authentication timeline
```
Agent detects sign-ins from Seattle (9:00 AM) and London (9:15 AM), traces SessionId, identifies initial MFA location, recommends action.

**Data Exfiltration:**
```
Investigate suspicious.user@company.com including DLP events
```
Agent finds 50 files uploaded to personal cloud, email forwarding rules, recommends immediate account suspension.

**Legitimate Travel:**
```
Investigate globalexec@contoso.com for 30 days
```
Agent detects 5 countries in 2 weeks, verifies each SessionId had interactive MFA, cross-references with calendar, recommends no action.

### Integration with CyberProbe Scripts

**Workflow:**
1. **Agent investigation** → Export priority IPs
2. **CyberProbe enrichment** → `python enrichment/enrich_ips.py <IPs>`
3. **Compare results** → Defender TI vs external sources (AbuseIPDB, VirusTotal)
4. **Generate HTML report** → report-generation skill

### Resources

- [Complete Agent Documentation](docs/SECURITY_COPILOT_AGENT.md)
- [Security Copilot Agent Guide](https://learn.microsoft.com/security-copilot/agents)
- [Developer Studio Documentation](https://learn.microsoft.com/security-copilot/developer)

---

## 19. Agent Skills (VS Code Copilot)
*VS Code Copilot Skills for AI-assisted investigations*

CyberProbe includes specialized Agent Skills that teach GitHub Copilot and other AI coding assistants how to conduct security investigations using our platform. These skills are stored in `.github/skills/` and automatically activate when you ask Copilot investigation-related questions.

### What are Agent Skills?

Agent Skills are an open standard (agentskills.io) for customizing AI coding assistants with domain-specific knowledge. Each skill contains:
- **YAML frontmatter**: Name and description for skill discovery
- **Markdown instructions**: Step-by-step workflows and best practices
- **Supporting files**: Scripts, templates, and examples (optional)

### Available CyberProbe Skills

CyberProbe provides **10 specialized skills** for security investigations:

#### 1. **incident-investigation**
📁 Location: `.github/skills/incident-investigation/SKILL.md`

**Purpose**: Automates the complete 5-phase investigation workflow

**Capabilities:**
- Phase 1: User ID extraction via Graph API
- Phase 2: Parallel data collection (Sentinel + Graph queries)
- Phase 3: JSON export with standardized schema
- Phase 4: IP enrichment with external threat intel
- Phase 5: HTML report generation

**When to use**: Any time Copilot receives requests like:
- "Investigate user@contoso.com for the last 7 days"
- "Run security investigation for suspicious.user@domain.com"
- "Quick investigate admin@company.com"

**Key features:**
- 60-70 second parallel query execution
- SessionId-based authentication tracing
- Automatic anomaly detection
- Risk-based IP prioritization

#### 2. **threat-enrichment**
📁 Location: `.github/skills/threat-enrichment/SKILL.md`

**Purpose**: Multi-source threat intelligence enrichment for IPs

**Data Sources:**
- **AbuseIPDB**: Abuse confidence scores (0-100%), report counts
- **IPInfo**: Geolocation, ISP, organization, ASN
- **VPNapi**: VPN/proxy/Tor detection

**Capabilities:**
- Single IP enrichment: `python enrichment/enrich_ips.py <IP>`
- Batch enrichment: Up to 15 IPs with ThreadPoolExecutor
- Investigation-based enrichment: Extract IPs from JSON
- Risk assessment matrix with confidence scoring

**When to use**:
- "Enrich IPs from incident #41272"
- "What's the threat intelligence for 206.168.34.210?"
- "Is this IP address malicious?"

**Output**: JSON files in `enrichment/ip_enrichment_results.json`

#### 3. **kql-sentinel-queries**
📁 Location: `.github/skills/kql-sentinel-queries/SKILL.md`

**Purpose**: Execute pre-built, production-validated KQL queries on Sentinel data lake

**Query Library** (11 pre-built queries):
- **Query 1**: Priority IP extraction (anomalies + risky + frequent)
- **Query 2**: Anomaly detection from BehaviorAnalytics
- **Query 3a/b/c/d**: Sign-in analysis (apps, locations, failures, details)
- **Query 4**: Azure AD audit logs
- **Query 5**: Office 365 activity
- **Query 6**: Security incidents (requires User ID + Windows SID)
- **Query 10**: DLP events
- **Query 11**: Threat intelligence correlation

**Best Practices:**
- Always filter on `TimeGenerated` first
- Use `| take` operator to limit results
- Add +2 days buffer for real-time investigations
- Use `has` instead of `contains` for performance

**When to use**:
- Standard investigation workflows
- Common threat hunting scenarios
- Queries already tested in production
- Need reliable, optimized performance

**Tools**: `mcp_microsoft_sen_query_lake`, `mcp_microsoft_sen_search_tables`

#### 4. **kql-query-builder**
📁 Location: `.github/skills/kql-query-builder/SKILL.md`

**Purpose**: Generate, validate, and optimize custom KQL queries using KQL Search MCP server

**Capabilities:**
- Natural language → validated KQL queries
- Sentinel Analytic Rule generation with MITRE ATT&CK mapping
- Query validation against 331+ table schemas
- ASIM-normalized multi-source queries
- GitHub community query search (1000s of detection rules)
- Query optimization and performance tuning

**When to use**:
- "Create a KQL query to find brute force attacks"
- "Generate a Sentinel detection rule for impossible travel"
- "Validate this query for performance issues"
- "Build an ASIM query for authentication failures across all sources"
- "Find community detection rules for lateral movement"

**Schema Coverage:**
- **331+ tables** from Defender XDR, Sentinel, Azure Monitor
- **11 ASIM schemas** for normalized security events
- **57 table categories** for discovery
- **230+ ASIM fields** with validation metadata

**MCP Tools** (34 available):
- Query generation (5 tools): `generate_kql_query`, `validate_kql_query`, etc.
- Schema intelligence (8 tools): `get_table_schema`, `search_tables`, etc.
- GitHub search (8 tools): `search_kql_queries`, `search_repo_kql_queries`, etc.
- ASIM schemas (13 tools): `generate_asim_query_template`, `validate_asim_parser`, etc.

**When NOT to use**:
- Standard investigation workflows covered by kql-sentinel-queries
- Pre-validated queries from Investigation-Guide.md Section 8

**Use Case Differentiation:**
- **kql-sentinel-queries**: Pre-built queries for common scenarios
- **kql-query-builder**: Custom queries for unique threats, new detection rules, ASIM normalization

#### 5. **microsoft-learn-docs**
📁 Location: `.github/skills/microsoft-learn-docs/SKILL.md`

**Purpose**: Access official Microsoft documentation for remediation and best practices

**Capabilities:**
- Search Microsoft Learn docs for remediation procedures
- Find production-ready PowerShell/KQL code samples
- Access comprehensive configuration guides
- Validate investigation techniques against official guidance

**When to use**:
- "How do I remediate this OAuth app attack?"
- "Find official guidance for blocking TOR networks"
- "Show me PowerShell commands to disable compromised user"
- "What's Microsoft's best practice for investigating account compromise?"

**MCP Tools:**
- `microsoft_docs_search`: Semantic search across Microsoft Learn
- `microsoft_code_sample_search`: Find official code samples by language
- `microsoft_docs_fetch`: Get complete documentation pages

**Integration**: Automatically activates during incident response to provide official remediation steps and compliance documentation

#### 6. **report-generation**
📁 Location: `.github/skills/report-generation/SKILL.md`

**Purpose**: Generate professional security investigation reports

**Report Types:**

**A. Investigation JSON Reports**
- Filename: `reports/investigation_<upn_prefix>_YYYY-MM-DD.json`
- Schema: User profile, anomalies, sign-ins, incidents, IP enrichment
- Usage: Machine-readable data for archival and further analysis

**B. Incident HTML Reports**
- Filename: `reports/incident_<incident_id>_critical_report.html`
- Features: Dark theme, MITRE ATT&CK mapping, interactive visuals
- Sections: Executive summary, timeline, threat intel, remediation steps

**Dark Theme Colors:**
- Primary: `#1a1a2e` (background)
- Accent: `#00d4ff` (highlights)
- Critical: `#ff4757` (high severity)
- Success: `#2ed573` (low severity)

**When to use**:
- "Generate report for the investigation"
- "Create critical incident report for #41272"

#### 7. **defender-response** ⭐ NEW
📁 Location: `.github/skills/defender-response/SKILL.md`

**Purpose**: Execute containment and remediation actions using Defender Response MCP tools

**Capabilities:**
- **Device Response**: Isolate, restrict code execution, AV scan, stop/quarantine, bulk isolate, release
- **Identity Response**: Confirm compromised/safe, disable/enable AD account, force password reset
- **Incident Management**: Comment, tag, assign, classify, update status
- **Forensic Collection**: Collect investigation packages, download forensic data
- **Response Playbooks**: Compromised user, malware containment, ransomware bulk response, post-remediation recovery

**When to use**:
- "Isolate device YOURPC01 — it has active malware"
- "Confirm user alice@contoso.com as compromised"
- "Classify incident 44239 as true positive"
- "Collect forensic package from SERVER-DC01"
- "Force password reset for bob@contoso.com"
- "Bulk isolate devices YOURPC01, YOURPC02, YOURPC03"

**MCP Tool Groups:**
- `activate_device_response_tools` — Isolate, restrict, scan, quarantine
- `activate_bulk_device_management_tools` — Bulk isolate, release
- `activate_user_compromise_management_tools` — Confirm compromised/safe
- `activate_active_directory_account_management_tools` — Disable, enable, reset password
- `activate_incident_management_tools` — Comment, tag, assign, classify, status
- `activate_forensic_investigation_tools` — Collect and download forensic packages
- `activate_device_monitoring_tools` — Check machine actions, find by name

**Safety**: Destructive actions (isolate, disable, quarantine) always require explicit analyst confirmation before execution.

### How Skills Work with Copilot

**Progressive Disclosure** (3 levels):

**Level 1: Discovery**
Copilot scans skill names/descriptions to find relevant skills:
```
User: "Investigate user@contoso.com"
→ Copilot discovers: incident-investigation skill
```

**Level 2: Instructions Loading**
Copilot loads full SKILL.md when relevant:
```
User: "Investigate user@contoso.com for last 7 days"
→ Loads incident-investigation/SKILL.md
→ Follows 5-phase workflow
→ Executes parallel queries
```

**Level 3: Resource Access**
Copilot accesses referenced files on-demand:
```
Copilot needs: Sample KQL queries
→ Reads Investigation-Guide.md Section 8
→ Uses pre-built Query 1 for IP extraction
```

### Using Skills in Investigations

**Automatic Activation** - No manual selection needed!

When you ask Copilot investigation-related questions, skills automatically activate:

**Example 1: User Investigation**
```
You: "Investigate jsmith@contoso.com for suspicious activity"

Copilot (auto-activates incident-investigation skill):
1. Gets User ID from Graph API
2. Runs parallel Sentinel queries (Query 1, 2, 3a/b/c, 4, 5, 6, 10)
3. Exports JSON to reports/investigation_jsmith_2026-01-15.json
4. Activates threat-enrichment skill for priority IPs
5. Runs: python enrichment/enrich_ips.py <IPs>
6. Activates report-generation skill
7. Creates HTML report: reports/investigation_jsmith_2026-01-15.html
```

**Example 2: IP Analysis**
```
You: "Is 206.168.34.210 malicious?"

Copilot (auto-activates threat-enrichment skill):
1. Runs: python enrichment/enrich_ips.py 206.168.34.210
2. Returns enrichment data:
   - Abuse confidence: 100%
   - Total reports: 1,363
   - Location: Chicago, US
   - ISP: Censys Inc.
   - VPN: No
3. Risk assessment: CRITICAL (100% abuse score)
```

**Example 3: KQL Queries**
```
You: "Check for policy changes this morning"

Copilot (auto-activates kql-sentinel-queries skill):
1. Calculates date range: today 00:00:00 to 23:59:59
2. Uses policy change query from skill
3. Executes via mcp_microsoft_sen_query_lake
4. Reports: "No policy changes detected" (0 results = valid)
```

### Skill Maintenance

**Adding New Skills:**

1. Create directory: `.github/skills/<skill-name>/`
2. Create `SKILL.md` with YAML frontmatter:
   ```yaml
   ---
   name: my-new-skill
   description: What this skill does (max 1024 chars)
   ---
   # My New Skill
   [Content here]
   ```
3. Restart VS Code to reload skills

**Updating Existing Skills:**

1. Edit `.github/skills/<skill-name>/SKILL.md`
2. Save changes
3. Copilot automatically uses updated version

**Best Practices:**
- Keep skill names lowercase with hyphens (e.g., `incident-investigation`)
- Max name length: 64 characters
- Max description: 1024 characters
- Include "When to use" section in every skill
- Provide example prompts that trigger the skill
- Link to related resources (scripts, docs, examples)

### Skills Integration with CyberProbe

**Skills leverage existing CyberProbe components:**

| Skill | Uses | Outputs |
|-------|------|--------|
| incident-investigation | Investigation-Guide.md (Section 8 queries) | reports/*.json, reports/*.html |
| threat-enrichment | enrichment/enrich_ips.py, config.json | enrichment/ip_enrichment_*.json |
| kql-sentinel-queries | Investigation-Guide.md, MCP tools | Query results, JSON exports |
| report-generation | report-generation SKILL.md templates | reports/*.html, reports/*.json |
| defender-response | Defender Response MCP tools | Containment/remediation actions |

**All skills reference:**
- Investigation-Guide.md (this file) - Complete investigation manual
- enrichment/config.json - API keys and configuration
- README.md - Platform overview and setup

**Skills enhance automation by:**
✅ Teaching Copilot the complete 5-phase investigation workflow
✅ Providing context on when to use each query/tool
✅ Including error handling and performance expectations
✅ Defining output formats and naming conventions
✅ Offering risk assessment criteria and decision matrices

### Resources

- [VS Code Agent Skills Documentation](https://code.visualstudio.com/docs/copilot/customization/agent-skills)
- [Agent Skills Standard (agentskills.io)](https://agentskills.io)
- [GitHub awesome-copilot](https://github.com/github/awesome-copilot) - Community skills
- [Anthropic Skills Repository](https://github.com/anthropics/skills)

**See also:**
- [docs/AGENT_SKILLS.md](docs/AGENT_SKILLS.md) - Detailed skills documentation
- [.github/skills/](../../.github/skills/) - All skill files

---

## 19. Resources
*Documentation and community resources*

This section provides links to official Microsoft documentation, KQL references, and community resources for threat hunting queries and security best practices.

### Microsoft Documentation
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/azure/sentinel/)
- [Defender XDR Documentation](https://learn.microsoft.com/defender-xdr/)
- [KQL Quick Reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference)
- [Advanced Hunting Schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)

### Community Resources
- [KQL Threat Hunting Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
- [Sentinel Community](https://github.com/Azure/Azure-Sentinel)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## Notes

This **Advanced Edition** merges the original Investigation-Guide.md (reference manual for analysts) with copilot-instructions.md (automation workflows for AI assistants). It serves dual purposes:

1. **Human-Readable Reference:** Comprehensive documentation for security analysts learning Defender XDR investigations
2. **AI-Executable Instructions:** Step-by-step automation workflows for GitHub Copilot + MCP servers

**Key Enhancements:**
- ✅ Production-validated KQL query library (Section 8)
- ✅ SessionId-based forensic authentication tracing (Section 9)
- ✅ Critical workflow rules for automation (Section 1)
- ✅ Comprehensive troubleshooting guide (Section 16)
- ✅ Best practices for query optimization (Section 15)
- ✅ VS Code Agent Skills integration (Section 18)
- ✅ 10 specialized skills for AI-assisted investigations
- ✅ Defender Response MCP integration for active response actions (Section 14)

Add your own queries, playbooks, and lessons learned as you conduct investigations.

**Agent Skills Integration:**
This guide serves as the knowledge base for CyberProbe's Agent Skills (`.github/skills/`). When using GitHub Copilot or AI coding assistants, skills automatically reference this guide's KQL queries, workflows, and best practices. See Section 18 for complete skills documentation.

**Last Updated:** February 12, 2026
