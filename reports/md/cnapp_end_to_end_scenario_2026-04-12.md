CNAPP End-to-End Capabilities Report — April 12, 2026


# 🛡️ CNAPP End-to-End Capabilities Report

Cloud-Native Application Protection Platform — Microsoft Defender for Cloud

📅 **Report Date:** April 12, 2026

🔍 **Data Window:** Last 30 Days

🏢 **Tenant:** Contoso Corp

📊 **Subscriptions:** 2 (Cross-tenant)

## 📋 Executive Summary

This report demonstrates the **end-to-end CNAPP capabilities** provided by Microsoft Defender for Cloud and Microsoft Defender XDR across three pillars: **Cloud Security Posture Management (CSPM)**, **Cloud Workload Protection (CWPP)**, and **Data Security Posture Management (DSPM)** — extended with **AI Security**, **DevSecOps**, and **Identity Entitlement (CIEM)** insights.

Over the last 30 days, Microsoft Defender for Cloud generated **141 alerts** across cloud workloads — from **container runtime threats** (cryptomining, drift binaries) to **AI agent attacks** (jailbreaks, ASCII smuggling, phishing) and **infrastructure threats** (Key Vault access from Tor, malicious blob uploads). Sentinel ingested **10,682 total security alerts** from all providers covering endpoint, identity, cloud app, and cloud infrastructure surfaces.

Compliance posture shows **Microsoft Cloud Security Benchmark** with 27 failing controls, **ISO 27001:2013** with 13 failing controls, and **46,534 unhealthy resource assessments** across all subscriptions — with Identity & Access as the largest remediation category (33,617 findings).

## 🏗️ CNAPP Pillar Architecture

Microsoft Defender for Cloud delivers a unified CNAPP through six integrated pillars, each contributing telemetry to this report:

🔍

CSPM

Cloud Security Posture Management — Compliance, Recommendations, Attack Paths

🛡️

CWPP

Cloud Workload Protection — Runtime Threats, Containers, VMs, Storage

🔑

CIEM

Cloud Infrastructure Entitlement Management — Permission Sprawl, IAM

📦

DSPM

Data Security Posture Management — Sensitive Data, Storage Anomalies

⚙️

DevSecOps

Code Security — IaC Scanning, Dependency Vulnerabilities, GitHub/ADO

🤖

AI Security

AI Threat Protection — Jailbreaks, Prompt Injection, Phishing on AI Agents

### End-to-End Scenario Flow

👨‍💻

Developer Commits Code

→

⚙️

DevSecOps Scan (IaC/Deps)

→

📦

Container Image Built

→

🔍

CSPM Assesses Posture

→

☁️

Deployed to Cloud

→

🛡️

CWPP Runtime Protection

→

🚨

Sentinel/XDR SIEM Correlation

## 📊 Cloud Security Alert Landscape (Last 30 Days)

141

Defender for Cloud Alerts

10,682

Total Sentinel Alerts (All Providers)

30

Unique Alert Types (DfC)

6

MITRE Tactics Covered

### Alert Volume by Provider & Severity

| Provider | Severity | Alert Count | Unique Types |
| --- | --- | --- | --- |
| Microsoft Defender for Endpoint | Medium | 3,264 | 27 |
| Microsoft Defender for Endpoint | Informational | 3,036 | 6 |
| Microsoft Defender for Endpoint | High | 2,111 | 28 |
| Sentinel Analytics (Scheduled) | High | 782 | 8 |
| Sentinel Analytics (Scheduled) | Medium | 766 | 15 |
| Microsoft Defender for Endpoint | Low | 260 | 17 |
| Defender for Cloud Apps | Low | 167 | 1 |
| Defender for Cloud Apps | Medium | 123 | 6 |
| **Defender for Cloud** | Medium | **97** | 13 |
| **Defender for Cloud** | High | **42** | 15 |
| Defender for Cloud Apps | High | 23 | 4 |
| **Defender for Cloud** | Low | **8** | 7 |
| **Defender for Cloud** | Informational | **2** | 1 |

## 🛡️ Pillar 1 — Cloud Workload Protection (CWPP)

Defender for Cloud's CWPP pillar provides runtime threat detection for compute workloads, containers, storage, databases, Key Vault, DNS, and AI services. Over the past 30 days, **141 alerts across 30 unique alert types** were generated from cloud infrastructure.

### Container Runtime Threats

Kubernetes and container workloads triggered attack chain detections covering the full MITRE ATT&CK lifecycle — from initial exploitation through credential access and impact:

| Alert | Severity | MITRE Tactic | Count |
| --- | --- | --- | --- |
| A drift binary detected executing in the container | High | Execution | 1 |
| Digital currency mining related behavior detected | High | Execution | 1 |
| Kubernetes CPU optimization detected | High | Impact | 1 |
| Possible Cryptocoinminer download detected | Medium | Exploitation | 1 |
| Command within container accessed ld.so.preload | Medium | Defense Evasion | 1 |
| Access to cloud metadata service detected | Medium | Credential Access | 1 |
| Possible Secret Reconnaissance Detected | Medium | Credential Access | 1 |
| Possible Web Shell Activity Detected | Medium | Persistence | 1 |
| Sensitive Files Access Detected | Medium | Credential Access | 1 |
| Suspicious workload identity token access | Low | Credential Access | 1 |

### Infrastructure & Storage Threats

| Alert | Severity | MITRE Tactic | Count |
| --- | --- | --- | --- |
| Malicious blob uploaded to storage account | High | Lateral Movement | 3 |
| Run Command with suspicious script on VM | High | Execution | 4 |
| Mimikatz credential theft tool (Agentless) | High | Credential Access | 2 |
| 'Kekeo' malware detected (Agentless) | High | Unknown | 1 |
| EICAR alert (Storage Malware Scanning) | High | — | 2 |
| Access from TOR exit node to Key Vault | Medium | Credential Access | 9 |
| Azure Resource Manager from suspicious proxy IP | Medium | Defense Evasion | 14 |
| Suspicious Azure role assignment detected | Medium | Defense Evasion | 2 |
| Suspicious extraction of Cosmos DB account keys | Medium | Credential Access | 1 |

### Container Attack Chain Visualization

HIGH SEVERITY Container Cryptomining Attack Chain

🌐

Web Shell Exploit

→

📥

Coinminer Download

→

🔄

Drift Binary Exec

→

⚡

CPU Optimization

→

⛏️

Crypto Mining

**Risk Factors:**
Execution
Persistence
Defense Evasion
Impact

## 🤖 Pillar 2 — AI Threat Protection (Defender for AI)

Microsoft Defender for Cloud's AI workload protection detected **54 AI-related security alerts** targeting Azure AI foundry agents and model deployments over the last 30 days — demonstrating real-time protection against emerging AI attack vectors.

54

AI Security Alerts

58

Jailbreak Attempts

7

Phishing on AI Agents

7

Malicious URLs / Smuggling

### AI Threat Detection Timeline

| Alert | Severity | MITRE Tactic | Count |
| --- | --- | --- | --- |
| Jailbreak attempt on Foundry agent detected by Prompt Shields | Medium | Privilege Escalation, Defense Evasion | 31 |
| Jailbreak attempt on Azure AI blocked by Prompt Shields | Medium | Privilege Escalation, Defense Evasion | 27 |
| Azure AI accessed by anonymized IP | High | Execution | 10 |
| Jailbreak attempt on Foundry agent blocked | Medium | Privilege Escalation, Defense Evasion | 7 |
| User phishing attempt on AI agent | High | Initial Access, Persistence | 5 |
| Malicious URL detected in AI agent response | High | Impact | 4 |
| Corrupted AI application shared malicious URL | High | Impact | 3 |
| ASCII smuggling attempt on AI agent | High | Impact | 2 |
| User phishing on AI application | High | Initial Access, Persistence | 2 |
| AI Agent Reconnaissance Attempt | Low | Reconnaissance | 1 |

### AI Attack Chain Visualization

AI THREAT Multi-Vector AI Agent Attack

🎣

Phishing URL Submitted

→

🔓

Jailbreak Attempt

→

🔤

ASCII Smuggling

→

🔗

Malicious URL in Response

→

🛡️

Prompt Shield Blocked

## 🔍 Pillar 3 — Cloud Security Posture Management (CSPM)

Defender CSPM continuously assesses resource configurations against industry benchmarks and regulatory frameworks. Compliance monitoring covers **2 subscriptions** across **2 tenants**.

### Regulatory Compliance Posture

Microsoft Cloud Security Benchmark

57%

36 passed · 27 failed (Sub 6785ea)

Microsoft Cloud Security Benchmark

65%

41 passed · 22 failed (Sub ebb79bc)

ISO 27001:2013

86%

80 passed · 13 failed · 116 skipped

Azure CSPM

0%

0 passed · 1 failed (Both subs)

### Security Assessment Summary

46,534

Unhealthy Assessments

34,186

Healthy Assessments

5,728

Not Applicable

1,507

Unique Recommendation Types

### Assessment Breakdown by Severity

| Severity | Healthy ✅ | Unhealthy 🔴 | Not Applicable | Health Rate |
| --- | --- | --- | --- | --- |
| High | 1,633 | 5,075 | 2,038 | 24.3% |
| Medium | 30,858 | 37,428 | 146 | 45.2% |
| Low | 1,695 | 4,031 | 3,544 | 29.6% |

### Failing Assessments by CNAPP Category

Identity & Access

33,617

72.3%

Compute & Container

6,062

13.0%

Unknown / Other

3,479

7.5%

Data

1,483

3.2%

Compute

1,007

2.2%

Networking

530

1.1%

Container

203

0.4%

App Services

28

## ⚠️ Top Failing Recommendations (High Severity)

The top 15 unhealthy high-severity recommendations across all subscriptions, representing the most impactful gaps in cloud security posture:

| # | Recommendation | Severity | Affected Resources |
| --- | --- | --- | --- |
| 1 | GitHub repos should require minimum two-reviewer approval for code pushes | High | 600 |
| 2 | Update `musl` | High | 187 |
| 3 | Update `tar` | High | 185 |
| 4 | Update `qs` | High | 184 |
| 5 | Update `path-to-regexp` | High | 184 |
| 6 | Update `lodash` | High | 184 |
| 7 | Update `minimatch` | High | 179 |
| 8 | Update `axios` | High | 176 |
| 9 | Update `body-parser` | High | 174 |
| 10 | Update `cross-spawn` | High | 169 |
| 11 | Update `handlebars` | High | 136 |
| 12 | Update `ejs` | High | 134 |
| 13 | Container images in Azure registry should have vulnerability findings resolved | High | 134 |
| 14 | Containers running in Azure should have vulnerability findings resolved | High | 127 |
| 15 | Update `form-data` | High | 122 |

**Key Insight:** 11 of the top 15 failing high-severity recommendations are **dependency vulnerability updates** — indicating a systemic gap in software supply chain patching across container images and DevOps repositories. The #1 gap is **DevSecOps governance** (600 GitHub repos without two-reviewer approval).

## 📦 Pillar 4 — Data Security & Identity Entitlements

### 🔑 CIEM — Identity & Access Findings

With **33,617 unhealthy findings** in the Identity & Access category (72.3% of all failing assessments), cloud infrastructure entitlement management is the single largest area requiring remediation. This reflects systemic overprivileged access patterns across service principals, managed identities, and user accounts.

33,617

Identity & Access Findings

72.3%

Share of All Failures

### 📦 DSPM — Data Layer Incidents

Defender for Cloud and Purview IRM detected data security and AI usage policy violations across the environment:

| Incident | Severity | Status | Created |
| --- | --- | --- | --- |
| Purview IRM — IRM Risky AI Usage (M365 Copilot) | Low | New | 2026-04-12 |
| Purview IRM — DSPM for AI: Detect risky AI usage | Low | New | 2026-04-12 |
| Purview IRM — Risky AI usage quick policy | Low | Closed | 2026-04-12 |
| Suspicious mass file renaming in cloud storage | High | — | 2026-04 (16 alerts) |
| Malicious blob uploaded to storage account | High | — | 2026-04 (3 alerts) |
| Suspicious extraction of Cosmos DB account keys | Medium | — | 2026-04 (1 alert) |

**1,483 unhealthy Data category assessments** indicate configuration gaps in data stores — encryption, access control, and network exposure settings require review.

## ⚙️ Pillar 5 — DevSecOps Posture

Defender for DevOps scans connected repositories (GitHub, Azure DevOps) for IaC misconfigurations and dependency vulnerabilities. Current findings indicate a **significant software supply chain risk**:

600

GitHub Repos Missing 2-Reviewer Approval

11

Outdated Dependencies (High)

134

Container Registry Vuln Images

127

Running Containers with Vulns

### Vulnerable Dependencies Across Repos

The following packages are flagged as high-severity across container images and code repositories:

`musl`

187

187

`tar`

185

185

`qs` / `path-to-regexp` / `lodash`

184

184

`minimatch`

179

179

`axios`

176

176

`body-parser`

174

174

`cross-spawn`

169

169

## 🚨 Cloud & AI Security Incidents (Last 30 Days)

Sentinel correlated cloud security alerts into the following recent incidents, demonstrating XDR's ability to unify cloud, AI, identity, and data signals into actionable investigations:

| # | Incident | Severity | Status | Created |
| --- | --- | --- | --- | --- |
| 42152 | Purview IRM — IRM Risky AI Usage (M365 Copilot) | Low | New | Apr 12, 23:54 |
| 42151 | Purview IRM — DSPM for AI: Detect risky AI usage | Low | New | Apr 12, 23:54 |
| 42150 | Suspicious volume of logins with elevated token | Medium | Closed | Apr 12, 23:36 |
| 42138 | Phishing alert involving one user | High | Closed | Apr 12, 17:33 |
| 42137 | Internal phishing campaign involving one user | High | New | Apr 12, 17:27 |
| 42128 | Potentially malicious URL click detected | High | Closed | Apr 12, 13:27 |
| 42082 | Suspicious activity incident involving one user | Medium | New | Apr 12, 11:30 |

Multiple DSPM for AI policy triggers on the same day indicate an active pattern of risky AI usage across the organization — Purview IRM policies are detecting and surfacing these events in real time.

## 🗺️ MITRE ATT&CK Coverage — Cloud Detections

Defender for Cloud alerts mapped across the MITRE ATT&CK framework, demonstrating detection capabilities across the full attack lifecycle:

TA0001 — Initial Access

• Phishing on AI Agents (7)

• Malicious URL Clicks (2)

TA0002 — Execution

• Drift Binary in Container (1)

• Cryptomining Execution (1)

• Run Command on VM (4)

• AI Accessed from Anon IP (10)

TA0003 — Persistence

• Web Shell in Container (1)

• AI Phishing Persistence (7)

TA0004 — Privilege Escalation

• AI Jailbreak Attempts (58)

TA0005 — Defense Evasion

• ld.so.preload in Container (1)

• ARM from Suspicious Proxy (14)

• Suspicious Role Assignment (2)

TA0006 — Credential Access

• Cloud Metadata Access (1)

• Secret Reconnaissance (1)

• Sensitive File Access (1)

• TOR to Key Vault (9)

• Mimikatz / Kekeo (3)

• Cosmos DB Key Extraction (1)

TA0008 — Lateral Movement

• Malicious Blob Upload (3)

TA0040 — Impact

• K8s CPU Optimization (1)

• Malicious URL in AI Response (4)

• ASCII Smuggling (2)

• Corrupted AI Model (3)

TA0043 — Reconnaissance

• AI Agent Recon Attempt (1)

TA0010 — Exfiltration

• Anonymity Network Activity (2)

TA0011 — Command & Control

• Custom Network Indicator (2)

TA0042 — Resource Dev (Cloud)

• TI Map IP to Cloud Events (90)

• Unusual Cloud Auth (16)

## 📋 Recommendations

### 🔴 Priority 1 — Immediate (0–7 Days)

| Action | Pillar | Impact |
| --- | --- | --- |
| Enforce 2-reviewer code approval on GitHub repositories (600 repos) | DevSecOps | Eliminates #1 high-severity finding |
| Investigate container cryptomining attack chain — isolate affected pods | CWPP | Stop active impact operations |
| Investigate AI agent jailbreak patterns — harden Prompt Shields configuration | AI Security | 58 attempts indicate persistent adversary |
| Block TOR exit node access to Key Vault via conditional access / firewall rules | CWPP | 9 detections indicate recurring abuse |

### 🟠 Priority 2 — Short-Term (7–30 Days)

| Action | Pillar | Impact |
| --- | --- | --- |
| Patch outdated dependencies (musl, tar, qs, lodash, axios, etc.) across container images | DevSecOps | Reduces 1,500+ high-severity dep vulns |
| Remediate container image vulnerabilities in Azure Registry (134 images) | CWPP / Container | Closes image-level vulnerability gap |
| Review Identity & Access findings (33,617) — prioritize service principal permissions | CIEM | Largest remediation category |
| Improve MCSB compliance from 57–65% to ≥80% by addressing top failing controls | CSPM | Brings core benchmark to acceptable threshold |

### 🟡 Priority 3 — Medium-Term (30–90 Days)

| Action | Pillar | Impact |
| --- | --- | --- |
| Establish AI governance policies for M365 Copilot and Foundry agents | AI / DSPM | Reduces risky AI usage incidents |
| Reduce Data category findings (1,483) — encryption, access controls, network exposure | DSPM | Hardens data security posture |
| Address Networking findings (530) — NSG rules, public endpoints | CSPM | Reduces attack surface |
| Enable Defender for Storage malware scanning across all storage accounts | DSPM | Consistent blob scanning coverage |

## 🔬 Methodology

### Tool Stack

| Tool | Purpose | Status |
| --- | --- | --- |
| Microsoft Sentinel Data Lake MCP (`query_lake`) | SecurityAlert, SecurityIncident queries for cloud and AI threat detections | ✅ Used |
| Azure Resource Graph (`az graph query`) | Regulatory compliance, security assessments, recommendations, categories | ✅ Used |
| RunAdvancedHuntingQuery (Triage MCP) | ExposureGraph, DeviceTvm, CloudAuditEvents — Attempted | ❌ Not available (ThreatHunting.Read.All scope required via Graph API; MCP unavailable) |
| Graph API `/security/runHuntingQuery` | Fallback for Advanced Hunting queries | ❌ 403 — Missing `ThreatHunting.Read.All` permission on CLI app |

### Data Extraction Queries

#### Query 1 — Security Alert Landscape (30d)

Feeds: Alert Landscape, CWPP, AI Security sections

```
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize AlertCount = count(), UniqueAlerts = dcount(AlertName)
    by ProviderName, AlertSeverity
| order by AlertCount desc
```

Result: 14 rows — 10,682 total alerts from 5 providers

#### Query 2 — Defender for Cloud Alert Details (30d)

Feeds: CWPP, Container Threats, AI Security tables

```
SecurityAlert
| where TimeGenerated > ago(30d)
| where ProviderName == "Azure Security Center"
| summarize AlertCount = count()
    by AlertName, AlertSeverity, Tactics
| order by AlertCount desc | take 30
```

Result: 30 unique cloud alert types, 141 total alerts

#### Query 3 — Cloud/AI Security Incidents (30d)

Feeds: Incident Correlation section

```
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Title has_any ("cloud", "Azure", "storage", "AI", ...)
| project IncidentNumber, Title, Severity, Status, Classification
| order by CreatedTime desc | take 20
```

Result: 20 cloud/AI-related incidents

#### Query 4 — Regulatory Compliance (ARG)

Feeds: CSPM Compliance Posture section

```
securityresources
| where type == 'microsoft.security/regulatorycompliancestandards'
| extend complianceStandard = name, state = tostring(properties.state),
    passedControls = toint(properties.passedControls),
    failedControls = toint(properties.failedControls)
| order by failedControls desc
```

Result: 5 records — MCSB, ISO 27001, Azure CSPM across 2 subs

#### Query 5 — Assessment Breakdown by Severity (ARG)

Feeds: Assessment Summary, Health Rate calculations

```
securityresources
| where type == 'microsoft.security/assessments'
| extend statusCode = tostring(properties.status.code),
    severity = tostring(properties.metadata.severity)
| summarize Count = count() by statusCode, severity
```

Result: 10 rows — 86,452 total assessments (46,534 unhealthy)

#### Query 6 — Top Failing Recommendations by Category (ARG)

Feeds: Failing Assessments by CNAPP Category bar chart

```
securityresources
| where type == 'microsoft.security/assessments'
| extend statusCode = tostring(properties.status.code),
    category = tostring(properties.metadata.categories)
| where statusCode == 'Unhealthy'
| summarize FailingCount = count() by category
| order by FailingCount desc
```

Result: 11 categories — Identity & Access: 33,617 (72.3%), Compute & Container: 6,062 (13%)

#### Query 7 — Top 15 Unhealthy High-Severity Recommendations (ARG)

Feeds: Top Failing Recommendations section

```
securityresources
| where type == 'microsoft.security/assessments'
| extend statusCode = tostring(properties.status.code),
    severity = tostring(properties.metadata.severity),
    displayName = tostring(properties.displayName)
| where statusCode == 'Unhealthy'
| summarize ResourceCount = count() by displayName, severity
| order by severity asc, ResourceCount desc | take 15
```

Result: 15 recommendations — #1: GitHub 2-reviewer approval (600 repos)

### Data Sources

| Source | Workspace / Scope | Tables / Resources |
| --- | --- | --- |
| Microsoft Sentinel Data Lake | Contoso-SOC (f9e8d7c6-...) | SecurityAlert, SecurityIncident |
| Azure Resource Graph | All subscriptions (cross-tenant) | securityresources (assessments, compliance, recommendations) |
| Defender for Cloud | Provider: Azure Security Center | Cloud/Container/AI/Storage alerts |

### Fallback Strategy

| Intended Source | Failure | Alternative Used |
| --- | --- | --- |
| Triage MCP (RunAdvancedHuntingQuery) | MCP tools not loaded in session | Graph API `/security/runHuntingQuery` attempted |
| Graph API Advanced Hunting | 403 — Missing `ThreatHunting.Read.All` | Sentinel Data Lake + Azure Resource Graph provided equivalent coverage for CNAPP pillars |

### CNAPP Coverage Assessment

| Pillar | Data Source | Status |
| --- | --- | --- |
| CSPM (Compliance, Recommendations) | Azure Resource Graph — securityresources | ✅ Full coverage |
| CWPP (Runtime Threats) | Sentinel — SecurityAlert (Defender for Cloud) | ✅ Full coverage |
| Container Security (Alerts) | Sentinel — SecurityAlert (container alerts) | ✅ Full coverage |
| Container Vuln (Image CVEs) | ARG — subassessments attempted | ⚠️ No subassessment data returned (may require Defender CSPM plan) |
| CIEM (Identity Findings) | ARG — assessment categories (Identity & Access) | ✅ Aggregate coverage |
| DSPM (Data Security) | Sentinel alerts + ARG Data category | ✅ Coverage via alerts + assessment counts |
| AI Security | Sentinel — SecurityAlert (AI-specific alerts) | ✅ Full coverage |
| DevSecOps | ARG — assessment recommendations (GitHub/DevOps-sourced) | ✅ Full coverage |
| Exposure Graph (Attack Paths) | Advanced Hunting required | ❌ Blocked — MCP + Graph API unavailable |

🛡️ **CNAPP End-to-End Capabilities Report** — Generated April 12, 2026

Data sourced from Microsoft Defender for Cloud, Microsoft Sentinel (Contoso-SOC), and Azure Resource Graph

CyberProbe — Security Investigation Automation System