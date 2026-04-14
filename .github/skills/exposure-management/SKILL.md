---
name: exposure-management
description: Retrieve Exposure Management data, CTEM metrics, CNAPP posture KPIs, and security insights from Microsoft Defender XDR and Defender for Cloud. Analyze attack surface inventory, vulnerability posture, choke points, attack paths, internet exposure, regulatory compliance, container security, CIEM entitlements, DSPM data security, DevSecOps posture, and security recommendations. Use for security posture assessments, CTEM dashboards, CNAPP coverage reporting, and exposure reduction tracking.
---

# Exposure Management, CTEM & CNAPP Posture Skill

Retrieve Continuous Threat Exposure Management (CTEM) metrics and Cloud-Native Application Protection Platform (CNAPP) posture KPIs from Microsoft Defender XDR and Defender for Cloud. Queries run against ExposureGraphNodes, ExposureGraphEdges, DeviceTvm* tables (Advanced Hunting), securityresources (Azure Resource Graph), and Defender for Cloud Advanced Hunting tables (CloudAuditEvents, CloudProcessEvents, CloudStorageAggregatedEvents).

## When to Use This Skill

Use this skill when the user asks about:
- Exposure management posture, CTEM metrics, or security KPIs
- Attack surface inventory or asset classification
- Vulnerability posture, top vulnerable devices, or weighted risk scores
- Attack paths, choke points, or blast radius
- Internet-exposed assets or RCE-vulnerable assets
- Exposure reduction tracking or remediation prioritization
- Security posture dashboards or executive exposure summaries
- **CNAPP posture**, cloud-native application protection
- **Regulatory compliance** — CIS, NIST, PCI-DSS, ISO 27001 benchmark scores
- **Container security** — K8s cluster posture, container image vulnerabilities, runtime events
- **CIEM** — cloud entitlements, permission sprawl, overprivileged identities
- **DSPM** — data security posture, sensitive data exposure, public storage access
- **Security recommendations** — Defender for Cloud recommendations, governance assignments
- **DevSecOps posture** — IaC misconfigurations, code-level security findings

## Prerequisites

1. **Defender XDR**: Defender CSPM or Defender for Servers plan enabled (required for ExposureGraph data)
2. **Defender for Cloud**: Required for CNAPP tables (CloudAuditEvents, CloudProcessEvents, CloudStorageAggregatedEvents) and securityresources (regulatory compliance, assessments)
3. **MCP Tools**: Triage MCP with `RunAdvancedHuntingQuery` available; Azure Resource Graph via `az graph query` or Azure MCP
4. **Permissions**: Security Reader minimum for Advanced Hunting; Reader on subscriptions for Azure Resource Graph queries

## Example Prompts

Type these in VS Code Copilot Chat to activate this skill:

**Full CTEM dashboard:**
```
Show me our CTEM metrics and exposure management posture
```

**Attack surface:**
```
What does our attack surface look like? How many internet-exposed assets do we have?
```

**Vulnerability posture:**
```
What's our vulnerability posture? Show me top vulnerable devices and critical CVEs
```

**Choke points and attack paths:**
```
Identify choke points and attack paths in our environment
```

**CNAPP posture:**
```
What's our CNAPP posture? Show cloud security coverage and Defender plan status
```

**Compliance:**
```
Show me compliance posture against CIS, NIST, and PCI-DSS benchmarks
```

**Container security:**
```
What's our container security status? Any vulnerable images or runtime alerts?
```

**Permission sprawl:**
```
Show me CIEM findings — any overprivileged identities or permission sprawl?
```

**Data security:**
```
What's our data security posture? Any publicly exposed storage or sensitive data risks?
```

**Security recommendations:**
```
What are the top security recommendations from Defender for Cloud?
```

## Critical Rules — Inherited from Global

All global rules from `copilot-instructions.md` apply. Additionally:

### Data Access Rules

| Rule | Detail |
|------|--------|
| **ExposureGraph/DeviceTvm queries use Advanced Hunting** | These tables are AH-only — NEVER use Data Lake (`query_lake`) |
| **Defender for Cloud AH tables use Advanced Hunting** | `CloudAuditEvents`, `CloudProcessEvents`, `CloudStorageAggregatedEvents`, `CloudDnsEvents`, `CloudPolicyEnforcementEvents` are AH-only (Preview). They DO have a `Timestamp` column. |
| **securityresources queries use Azure Resource Graph** | Regulatory compliance, assessments, attack paths — use `az graph query` or Azure MCP. NOT Advanced Hunting. |
| **No time filters on inventory tables** | ExposureGraphNodes, ExposureGraphEdges, DeviceTvmSoftwareVulnerabilities have NO `Timestamp` column |
| **JSON extraction pattern** | Use `parse_json(NodeProperties).rawData.<field>` for ExposureGraphNodes properties |
| **Schema reference** | See [`docs/XDR_TABLES_AND_APIS.md` § XDR Table Reference](../../../docs/XDR_TABLES_AND_APIS.md#4-xdr-table-reference) for full column definitions |

### MCP Tool Selection

| Data | MCP Tool | Notes |
|------|----------|-------|
| ExposureGraph queries | `RunAdvancedHuntingQuery` | No time filters. Inventory snapshot. |
| DeviceTvm queries | `RunAdvancedHuntingQuery` | No time filters for most tables. |
| CloudAuditEvents / CloudProcessEvents | `RunAdvancedHuntingQuery` | Preview tables. HAS `Timestamp` column. Filter by time. |
| CloudStorageAggregatedEvents | `RunAdvancedHuntingQuery` | Preview table. HAS `Timestamp` column. Filter by time. |
| CloudDnsEvents / CloudPolicyEnforcementEvents | `RunAdvancedHuntingQuery` | Preview tables. HAS `Timestamp` column. Filter by time. |
| AIAgentsInfo (AI agent posture) | `RunAdvancedHuntingQuery` | Preview. Use `summarize arg_max(Timestamp, *) by AIAgentId`. |
| FileMaliciousContentInfo | `RunAdvancedHuntingQuery` | Preview. HAS `Timestamp` column. Malicious files in SharePoint/OneDrive/Teams. |
| DataSecurityBehaviors / DataSecurityEvents | `RunAdvancedHuntingQuery` | Preview. HAS `Timestamp` column. Purview DLP/data security. |
| Attack path resources | Azure Resource Graph (`securityresources`) | Use `az graph query` CLI or Azure MCP |
| Regulatory compliance | Azure Resource Graph (`securityresources`) | Use `az graph query` CLI or Azure MCP |
| Security assessments / recommendations | Azure Resource Graph (`securityresources`) | Use `az graph query` CLI or Azure MCP |
| Container image vulnerabilities | Azure Resource Graph (`securityresources`) | Sub-assessments with assessment keys |
| Blast radius / exposure perimeter | Sentinel Graph MCP (`graph_find_blastRadius`, `graph_exposure_perimeter`) | If available |
| Choke point activity monitoring | Data Lake (`query_lake`) | SecurityEvent, AzureDiagnostics tables use `TimeGenerated` |

### Existing Query Libraries

Before writing any ad-hoc query, check these verified sources first:

| Source | Path | Content |
|--------|------|---------|
| XDR Doc KQL Cookbook | `docs/XDR_TABLES_AND_APIS.md` Section 6 | 15 verified queries: vuln assessment, exposure management, choke point analysis |
| Attack Path Monitoring | `queries/attack_path_monitoring.kql` | 10 queries: trends, choke point monitoring, risk scoring, remediation tracking |
| Cloud Attack Paths | `queries/cloud/attack_path_monitoring.kql` | Attack path queries for cloud resources |
| ARG Defender Samples | [Microsoft Learn ARG samples](https://learn.microsoft.com/azure/governance/resource-graph/samples/samples-by-category#microsoft-defender) | Official ARG queries for compliance, assessments, recommendations |

---

## Investigation Workflow

The workflow is organized into phases. Execute phases based on user request — not all phases are needed for every prompt.

### Quick Reference: Which Phases to Run

| User Request | Phases |
|--------------|--------|
| "Show me CTEM metrics" / "exposure dashboard" | 1 + 2 + 3 + 4 (all) |
| "Full CNAPP posture" / "CNAPP dashboard" | 1 + 2 + 3 + 4 + 6 + 7 + 8 + 9 + 10 (all) |
| "What's our vulnerability posture?" | 2 only |
| "Show me choke points" / "attack paths" | 3 only |
| "What targets each edge type?" / "what has permissions to what?" | 3.1 + 3.1b |
| "Show me attack path graphs / visuals" | 4.3 + 4.4 |
| "What's internet-exposed?" | 1.2 + 1.3 only |
| "Generate exposure KPI report" | 1 + 2 + 3 + 4 (all, including 3.1b + 4.4) + Report |
| "Drill into device X exposure" | 3.3 + 3.5 + 2.1 (targeted) |
| "Compliance posture" / "regulatory compliance" | 6 only |
| "Container security" / "K8s posture" | 7 only |
| "Permission sprawl" / "CIEM" / "entitlements" | 8 only |
| "Data security posture" / "DSPM" / "sensitive data exposure" | 9 only |
| "Security recommendations" / "unhealthy assessments" | 10 only |
| "DevSecOps posture" / "IaC misconfigurations" | 11 only |

---

### Phase 1: Attack Surface Inventory

#### 1.1 — Asset Classification Summary

Discover all entity types in the exposure graph:

```kql
ExposureGraphNodes
| summarize Count = count() by NodeLabel
| order by Count desc
```

**Output interpretation:** Shows the composition of your attack surface — VMs, subscriptions, identities, storage, etc.

#### 1.2 — Internet-Exposed Assets

```kql
ExposureGraphNodes
| where parse_json(NodeProperties).rawData.isCustomerFacing == true
| project NodeName, NodeLabel,
    RiskScore = tostring(parse_json(NodeProperties).rawData.riskScore),
    ExposureScore = tostring(parse_json(NodeProperties).rawData.exposureScore),
    PublicIP = tostring(parse_json(NodeProperties).rawData.publicIP),
    OS = tostring(parse_json(NodeProperties).rawData.osPlatform),
    SensorHealth = tostring(parse_json(NodeProperties).rawData.sensorHealthState)
| order by RiskScore desc
```

**KPI produced:** Count of internet-exposed assets, breakdown by risk score.

#### 1.3 — Assets Vulnerable to Remote Code Execution

```kql
ExposureGraphNodes
| where parse_json(NodeProperties).rawData.highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution.hasHighOrCritical == true
| project NodeName, NodeLabel,
    MaxCVSS = tostring(parse_json(NodeProperties).rawData.highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution.maxCvssScore),
    RiskScore = tostring(parse_json(NodeProperties).rawData.riskScore),
    OS = tostring(parse_json(NodeProperties).rawData.osPlatform)
| order by MaxCVSS desc
```

**KPI produced:** Count of RCE-vulnerable assets with max CVSS scores.

#### 1.4 — Onboarding & Sensor Health

```kql
ExposureGraphNodes
| where NodeLabel has "virtualmachines" or NodeLabel has "machines"
| extend props = parse_json(NodeProperties).rawData
| project NodeName,
    OnboardingStatus = tostring(props.onboardingStatus),
    SensorHealth = tostring(props.sensorHealthState),
    OS = tostring(props.osPlatform),
    LastSeen = tostring(props.lastSeen)
| summarize
    Onboarded = countif(OnboardingStatus == "Onboarded"),
    NotOnboarded = countif(OnboardingStatus != "Onboarded"),
    ActiveSensors = countif(SensorHealth == "Active"),
    InactiveSensors = countif(SensorHealth != "Active")
```

**KPI produced:** Onboarding coverage %, sensor health %.

---

### Phase 2: Vulnerability Posture

#### 2.1 — Top Vulnerable Devices (Weighted Score)

```kql
DeviceTvmSoftwareVulnerabilities
| summarize 
    TotalVulns = dcount(CveId),
    CriticalVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
    HighVulns = dcountif(CveId, VulnerabilitySeverityLevel == "High"),
    MediumVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Medium"),
    LowVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Low")
    by DeviceId, DeviceName, OSPlatform
| extend WeightedScore = (CriticalVulns * 4) + (HighVulns * 2) + (MediumVulns * 1) + LowVulns
| top 10 by WeightedScore desc
| project DeviceName, OSPlatform, TotalVulns, CriticalVulns, HighVulns, MediumVulns, LowVulns, WeightedScore
```

> No time filter — `DeviceTvmSoftwareVulnerabilities` is an inventory snapshot.

**KPI produced:** Top 10 riskiest devices, weighted vulnerability scores.

#### 2.2 — Vulnerability Distribution by Severity

```kql
DeviceTvmSoftwareVulnerabilities
| summarize
    TotalDevices = dcount(DeviceId),
    TotalUniqueVulns = dcount(CveId),
    CriticalVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
    HighVulns = dcountif(CveId, VulnerabilitySeverityLevel == "High"),
    MediumVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Medium"),
    LowVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Low")
```

**KPI produced:** Fleet-wide vulnerability summary by severity.

#### 2.3 — Vulnerability Distribution by OS Platform

```kql
DeviceTvmSoftwareVulnerabilities
| summarize
    DeviceCount = dcount(DeviceId),
    TotalVulns = dcount(CveId),
    CriticalVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
    HighVulns = dcountif(CveId, VulnerabilitySeverityLevel == "High")
    by OSPlatform
| extend WeightedScore = (CriticalVulns * 4) + (HighVulns * 2)
| order by WeightedScore desc
```

**KPI produced:** Which OS platforms carry the most risk.

#### 2.4 — Most Prevalent CVEs Across Fleet

```kql
DeviceTvmSoftwareVulnerabilities
| summarize AffectedDevices = dcount(DeviceId) by CveId, VulnerabilitySeverityLevel
| where VulnerabilitySeverityLevel in ("Critical", "High")
| top 20 by AffectedDevices desc
| project CveId, VulnerabilitySeverityLevel, AffectedDevices
```

**KPI produced:** Top 20 most widespread critical/high CVEs.

---

### Phase 3: Attack Paths & Choke Points

#### 3.1 — Relationship Types in the Attack Graph

```kql
ExposureGraphEdges
| summarize EdgeCount = count() by EdgeLabel
| order by EdgeCount desc
```

**Output interpretation:** Shows what types of relationships exist — permissions, vulnerabilities, network routes, etc.

#### 3.1b — Top 3 Targeted Resources per Edge Type

For **each** edge type from 3.1, identify the top 3 most targeted resources. Run one query per edge type:

```kql
ExposureGraphEdges
| where EdgeLabel == "<EDGE_TYPE>"
| summarize EdgeCount = count() by TargetNodeName, TargetNodeLabel
| top 3 by EdgeCount
```

Substitute `<EDGE_TYPE>` with each value from 3.1 results (e.g., `has permissions to`, `affecting`, `member of`, `has role on`, `contains`, `can authenticate as`, `runs on`, `grants access to`, `routes traffic to`, `is running`, `can impersonate as`, `has credentials of`).

**Execution approach:** Run queries in parallel (batch independent MCP calls) for all edge types simultaneously to minimize latency.

**Report output:** In the report, combine 3.1 and 3.1b into a single table with columns: `Edge Type | Total Count | % | Top 3 Targeted Resources`. Each target row shows: resource name, asset type badge, and edge count.

**Why this matters:** Raw edge type counts alone don't reveal *what* is being targeted. Knowing that "has permissions to" targets a Kubernetes load balancer with 65K edges reveals an overprivileged IAM surface. Knowing that "affecting" targets sap-ash (a VM with 2,659 vulnerability edges) reveals a critical remediation candidate.

#### 3.2 — Top Choke Points by Incoming Attack Path Edges

A **choke point** is a node at the intersection of multiple attack paths. Remediating it blocks the maximum number of paths simultaneously.

```kql
ExposureGraphEdges
| summarize IncomingPaths = count() by TargetNodeId, TargetNodeName, TargetNodeLabel
| top 10 by IncomingPaths desc
| project TargetNodeName, TargetNodeLabel, IncomingPaths
```

**KPI produced:** Top 10 choke points with path counts.

#### 3.3 — Choke Point Detail: Edge Type Breakdown

For a specific choke point (substitute `<NODE_NAME>` with result from 3.2):

```kql
ExposureGraphEdges
| where TargetNodeName == "<NODE_NAME>"
| summarize PathCount = count() by EdgeLabel
| top 10 by PathCount desc
```

#### 3.4 — VM Choke Points

```kql
ExposureGraphEdges
| where TargetNodeLabel == "microsoft.compute/virtualmachines"
| summarize IncomingPaths = count() by TargetNodeName
| top 10 by IncomingPaths desc
```

**KPI produced:** VM-specific choke point ranking.

#### 3.5 — Cross-Reference: Choke Points × Vulnerability Count

This is the highest-impact query — it identifies nodes that are both choke points AND highly vulnerable:

```kql
let chokePoints = ExposureGraphEdges
| summarize IncomingPaths = count() by TargetNodeName
| top 10 by IncomingPaths desc;
DeviceTvmSoftwareVulnerabilities
| summarize 
    TotalVulns = dcount(CveId),
    CriticalVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
    HighVulns = dcountif(CveId, VulnerabilitySeverityLevel == "High")
    by DeviceName
| join kind=inner chokePoints on $left.DeviceName == $right.TargetNodeName
| project DeviceName, IncomingPaths, TotalVulns, CriticalVulns, HighVulns
| order by IncomingPaths desc
```

**KPI produced:** Remediation priority list — choke points with the most vulnerabilities to patch.

#### 3.6 — Full Attack Path Context for a Node

```kql
ExposureGraphEdges
| where TargetNodeName == "<NODE_NAME>"
| join kind=inner (
    ExposureGraphNodes | project NodeId, Categories, NodeProperties
) on $left.SourceNodeId == $right.NodeId
| project SourceNodeName, SourceNodeLabel, EdgeLabel,
    SourceRisk = tostring(parse_json(NodeProperties).rawData.riskScore)
| summarize AttackerCount = count() by SourceNodeLabel, EdgeLabel
| order by AttackerCount desc
```

#### 3.7 — Choke Point Node Properties

```kql
ExposureGraphNodes
| where NodeName == "<NODE_NAME>"
| project NodeName, NodeLabel, Categories, NodeProperties
```

---

### Phase 4: Attack Path Trend & Risk Scoring (Azure Resource Graph)

These queries run against `securityresources` via Azure Resource Graph (Data Lake or Azure MCP `monitor_workspace_log_query`), NOT Advanced Hunting.

#### 4.1 — Attack Path Count by Severity

```kql
securityresources
| where type == "microsoft.security/attackpaths"
| extend riskLevel = tostring(properties.riskLevel)
| summarize
    CriticalPaths = countif(riskLevel == "Critical"),
    HighPaths = countif(riskLevel == "High"),
    MediumPaths = countif(riskLevel == "Medium"),
    TotalPaths = count()
```

**KPI produced:** Attack path count by severity — the core CTEM headline metric.

#### 4.2 — Internet Exposure Risk Score (Composite)

```kql
securityresources
| where type == "microsoft.security/attackpaths"
| extend riskFactors = properties.riskFactors
| mv-expand riskFactor = riskFactors
| extend riskFactorStr = tostring(riskFactor)
| summarize 
    InternetExposure = countif(riskFactorStr == "Internet exposure"),
    LateralMovement = countif(riskFactorStr == "Lateral movement"),
    Vulnerabilities = countif(riskFactorStr == "Vulnerabilities"),
    CriticalResource = countif(riskFactorStr == "Critical resource")
| extend RiskScore = 
    (InternetExposure * 3) +
    (LateralMovement * 2) +
    (Vulnerabilities * 2) +
    (CriticalResource * 4)
| project 
    Timestamp = now(),
    RiskScore,
    InternetExposure,
    LateralMovement,
    Vulnerabilities,
    CriticalResource
```

**KPI produced:** Composite risk score based on weighted attack path factors.

#### 4.3 — Attack Path Entry Points and Targets

```kql
securityresources
| where type == "microsoft.security/attackpaths"
| extend
    riskLevel = tostring(properties.riskLevel),
    attackPathName = tostring(properties.displayName),
    entryPoint = tostring(properties.entryPoint.entityName),
    target = tostring(properties.target.entityName),
    targetType = tostring(properties.target.entityType)
| project attackPathName, riskLevel, entryPoint, target, targetType
| order by riskLevel asc
```

#### 4.4 — Attack Path Graph Visualization

Retrieve the full `graphComponent` for each attack path to build visual diagrams showing entities, connections, and insights:

```kql
securityresources
| where type == "microsoft.security/attackpaths"
| where properties.riskLevel == "<RISK_LEVEL>"
| project
    attackPathName = tostring(properties.displayName),
    entryPoint = tostring(properties.entryPoint.entityName),
    entryPointType = tostring(properties.entryPoint.entityType),
    target = tostring(properties.target.entityName),
    targetType = tostring(properties.target.entityType),
    riskFactors = properties.riskFactors,
    graphComponent = properties.graphComponent
```

Run this for `Critical` first, then `High`. The `graphComponent` contains three key arrays:

| Array | Contains | Use For |
|-------|----------|--------|
| `graphComponent.entities` | All nodes in the path: VMs, IPs, NICs, managed identities, storage accounts, functions | Building the visual flow diagram nodes |
| `graphComponent.connections` | Edges between entities with `sourceEntityInternalId`, `targetEntityInternalId`, and `title` (edge label) | Drawing arrows between nodes |
| `graphComponent.insights` | Risk metadata per entity: CVSS scores, internet exposure rules, criticality level, public access, sensitive data | Annotating nodes with risk context |

**⚠️ Execution Note:** This query uses `securityresources` which is an Azure Resource Graph table — NOT available in Sentinel Data Lake or Advanced Hunting. Use either:
1. Azure MCP Resource Graph tool
2. `az graph query` CLI fallback (see Phase 4 tool routing)

**Building the Visual Diagram:**

For each attack path, generate an HTML flow diagram using this pattern:

1. **Parse `graphComponent.entities`** → Create a node box for each entity:
   - Use entity `entityName` as the label
   - Map `entityType` to an icon (🌐 = IP, 🔌 = NIC, 🖥️ = VM, 🔑 = Managed Identity, ⚡ = Function, 📦 = Storage)
   - Color by risk: `var(--critical)` for Critical paths, `var(--warning)` for High paths

2. **Parse `graphComponent.connections`** → Draw arrows between nodes:
   - Match `sourceEntityInternalId` / `targetEntityInternalId` to entity `entityInternalId`
   - Label each arrow with the connection `title` (e.g., "routes traffic to", "can authenticate as", "has permissions to")

3. **Parse `graphComponent.insights`** → Annotate nodes:
   - `highRiskVulnerabilityInsights` → Show max CVSS score
   - `exposedToInternet` → Show open ports and source CIDR (e.g., `443/TCP from 0.0.0.0/0`)
   - `criticalityLevel` → Show criticality rating and rule names
   - `allowsPublicAccess` → Flag public anonymous access
   - `containsSensitiveData` → Flag sensitive data presence

4. **Risk factor bar** at the bottom of each diagram showing the path's `riskFactors` array

**HTML structure per diagram:**
```html
<div style="background: rgba(R,G,B,0.08); border: 1px solid var(--severity); border-radius: 8px; padding: 20px;">
  <div><!-- Badge + attack path name --></div>
  <div style="display: flex; align-items: center; justify-content: center;"><!-- Node → Arrow → Node → Arrow → Node --></div>
  <div><!-- Risk factors bar --></div>
</div>
```

**KPI produced:** Visual attack path diagrams showing entry point → intermediate hops → target with risk annotations.

---

### Phase 5: Blast Radius & Exposure Perimeter (Sentinel Graph MCP)

If the Sentinel Graph MCP is available, use these purpose-built tools for advanced graph analysis:

#### 5.1 — Blast Radius for a Specific Node

```
graph_find_blastRadius(nodeName="<NODE_NAME>")
```

Shows all entities that would be affected if the node is compromised.

#### 5.2 — Exposure Perimeter

```
graph_exposure_perimeter(nodeName="<NODE_NAME>")
```

Shows how accessible a node is from entry points.

#### 5.3 — Walkable Attack Paths

```
graph_find_walkable_paths(source="<SOURCE_NODE>", target="<TARGET_NODE>")
```

Finds attack paths between two specific entities (up to 4 hops).

> **Note:** If Sentinel Graph MCP is not available, fall back to ExposureGraphEdges queries in Phase 3.

---

## CTEM KPI Summary Table

After running the relevant phases, compile findings into this standardized KPI summary:

```
## 📊 CTEM KPI Dashboard — [Date]

### Attack Surface
| KPI | Value | Trend |
|-----|-------|-------|
| Total Assets in Exposure Graph | [Phase 1.1 total] | — |
| Internet-Exposed Assets | [Phase 1.2 count] | — |
| RCE-Vulnerable Assets | [Phase 1.3 count] | — |
| MDE Onboarding Coverage | [Phase 1.4 %] | — |
| Sensor Health (Active) | [Phase 1.4 %] | — |

### Vulnerability Posture
| KPI | Value | Trend |
|-----|-------|-------|
| Total Unique CVEs | [Phase 2.2] | — |
| Critical Vulnerabilities | [Phase 2.2 critical count] | — |
| High Vulnerabilities | [Phase 2.2 high count] | — |
| Devices with Critical Vulns | [count from Phase 2.1] | — |
| #1 Riskiest Device | [Phase 2.1 top device] (Score: [X]) | — |

### Attack Paths & Choke Points
| KPI | Value | Trend |
|-----|-------|-------|
| Total Attack Paths | [Phase 4.1 total] | — |
| Critical Attack Paths | [Phase 4.1 critical] | 🔴 |
| High Attack Paths | [Phase 4.1 high] | 🟠 |
| Top Choke Point | [Phase 3.2 top node] ([X] paths) | — |
| Composite Risk Score | [Phase 4.2 score] | — |
| Attack Path Diagrams | [Phase 4.4 count] visual flow diagrams | — |

### Exposure Factors
| Factor | Count | Weight | Contribution |
|--------|-------|--------|-------------|
| Internet Exposure | [Phase 4.2] | ×3 | [calculated] |
| Lateral Movement | [Phase 4.2] | ×2 | [calculated] |
| Vulnerabilities | [Phase 4.2] | ×2 | [calculated] |
| Critical Resource | [Phase 4.2] | ×4 | [calculated] |
```

Fill all values from actual query results. Use `—` for trend on first run; compare against previous reports for subsequent runs.

## Remediation Prioritization

After generating KPIs, prioritize remediation using this logic:

| Priority | Criteria | Action |
|----------|----------|--------|
| 🔴 P1 — Critical | Choke point + Critical vulns + internet-exposed | Immediate patching, NSG hardening |
| 🟠 P2 — High | Choke point + High vulns OR internet-exposed + Critical vulns | Patch within 7 days |
| 🟡 P3 — Medium | Choke point with low vuln count OR internal-only with critical vulns | Patch within 30 days |
| 🔵 P4 — Low | Internal assets with medium/low vulns, not on attack paths | Standard patch cycle |

**Cross-reference sources:**
- Remediation scripts: `scripts/remediation/Remediate-AttackPaths.ps1`
- Sentinel monitoring rules: `scripts/remediation/Deploy-SentinelRules.ps1`
- Attack path monitoring queries: `queries/attack_path_monitoring.kql`

## Report Output

When the user requests a report, generate HTML using the `report-generation` skill with CTEM-specific sections. The report MUST include:

### Required Report Sections

1. **Edge Type Breakdown with Top 3 Targets** (Phase 3.1 + 3.1b): Table showing each edge type with total count, percentage, AND the top 3 targeted resources (name, asset type badge, edge count). Do NOT show edge types as bare counts — always include what they target.

2. **Attack Path Visual Diagrams** (Phase 4.4): For each Critical and High attack path, render an HTML flow diagram showing:
   - Entry point (public IP or internet-facing resource) → intermediate hops (NICs, managed identities) → target
   - Risk annotations per node (CVSS scores, open ports, criticality level, public access flags)
   - Risk factor bar at bottom of each diagram
   - Color-coded borders: `var(--critical)` for Critical paths, `var(--warning)` for High paths

3. **Regulatory Compliance Summary** (Phase 6, if run): Table showing each standard with compliance score %, passed/failed controls. Highlight standards below 70% compliance in red.

4. **Container Security Overview** (Phase 7, if run): Image vulnerability counts by severity, vulnerable namespaces, runtime event summary.

5. **CIEM Entitlement Analysis** (Phase 8, if run): Top overprivileged identities, permission edge volume by resource type, service account risk ranking.

6. **DSPM Data Security** (Phase 9, if run): Data-bearing asset count, public access paths, anomalous storage access events.

7. **Recommendation & Governance Dashboard** (Phase 10, if run): Failing recommendations by severity/category, governance assignment status donut chart.

8. **DevSecOps Posture** (Phase 11, if run): Per-platform pass rate, failing IaC recommendations.

9. **Methodology section** (per user preference) covering:
   - **Tool stack:** RunAdvancedHuntingQuery (Triage MCP), Azure Resource Graph (`az graph query`), Sentinel Graph MCP (if used)
   - **Tables queried:** ExposureGraphNodes, ExposureGraphEdges, DeviceTvmSoftwareVulnerabilities, securityresources, CloudAuditEvents, CloudProcessEvents, CloudStorageAggregatedEvents (as applicable)
   - **Query source:** This skill's verified queries (not ad-hoc)
   - **Data freshness:** Point-in-time inventory snapshots (ExposureGraph/DeviceTvm have no timestamp — always current state); ARG reflects near-real-time; Cloud* AH tables have `Timestamp` (event-level)
   - **CNAPP coverage:** List which CNAPP pillars were assessed (CSPM, CWPP, CIEM, DSPM, DevSecOps, Compliance)

Save report to: `reports/ctem_kpi_report_YYYY-MM-DD.html`

---

## CNAPP Pillar Phases (6–11)

These phases extend coverage beyond CTEM (Phases 1–5) to the full CNAPP stack. Each phase maps to a Defender for Cloud pillar and uses either Azure Resource Graph (`securityresources`) or Advanced Hunting Preview tables.

### Assessment Key Reference

Container image vulnerability queries use assessment keys to identify the scanner:

| Scanner | Assessment Key | Status |
|---------|---------------|--------|
| Microsoft Defender Vulnerability Management (MDVM) | `c0b7cfc6-3172-465a-b378-53c7ff2cc0d5` | Current (recommended) |
| Qualys (legacy) | `dbd0cb49-b563-45e7-9724-889e799fa648` | Deprecated — use MDVM |

---

### Phase 6: Regulatory Compliance Posture (Azure Resource Graph)

All Phase 6 queries run against `securityresources` via Azure Resource Graph (`az graph query`), NOT Advanced Hunting.

#### 6.1 — Compliance Standards Overview

Get the state of each compliance standard with passed/failed/skipped control counts:

```kql
securityresources
| where type == 'microsoft.security/regulatorycompliancestandards'
| extend complianceStandard = name,
    state = tostring(properties.state),
    passedControls = toint(properties.passedControls),
    failedControls = toint(properties.failedControls),
    skippedControls = toint(properties.skippedControls),
    unsupportedControls = toint(properties.unsupportedControls)
| project subscriptionId, complianceStandard, state, passedControls, failedControls, skippedControls, unsupportedControls
| order by failedControls desc
```

**KPI produced:** Compliance standard scores — % passing per standard, total failing controls. Key standards: CIS, NIST 800-53, PCI DSS, ISO 27001, MCSB.

#### 6.2 — Compliance Assessment Details (Per Control)

Drill into individual assessments within a specific standard:

```kql
securityresources
| where type == 'microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments'
| extend assessmentName = tostring(properties.description),
    complianceStandard = extract(@'/regulatoryComplianceStandards/(.+)/regulatoryComplianceControls', 1, id),
    complianceControl = extract(@'/regulatoryComplianceControls/(.+)/regulatoryComplianceAssessments', 1, id),
    state = tostring(properties.state),
    passedResources = toint(properties.passedResources),
    failedResources = toint(properties.failedResources),
    skippedResources = toint(properties.skippedResources)
| where state == 'Failed'
| project subscriptionId, complianceStandard, complianceControl, assessmentName, state, failedResources, passedResources
| order by failedResources desc
```

**KPI produced:** Top failing compliance controls with resource count impact.

#### 6.3 — Compliance Score by Standard (Calculated)

```kql
securityresources
| where type == 'microsoft.security/regulatorycompliancestandards'
| extend complianceStandard = name,
    passed = toint(properties.passedControls),
    failed = toint(properties.failedControls),
    skipped = toint(properties.skippedControls)
| extend totalAssessed = passed + failed
| extend complianceScore = iff(totalAssessed > 0, round(100.0 * passed / totalAssessed, 1), 0.0)
| project complianceStandard, complianceScore, passed, failed, skipped, totalAssessed
| order by complianceScore asc
```

**KPI produced:** Compliance score % per standard — lowest-scoring standards are remediation priorities.

---

### Phase 7: Container Security Posture

Container security data comes from two sources: Azure Resource Graph (image vulnerabilities, K8s assessments) and Advanced Hunting Preview tables (runtime events).

#### 7.1 — Container Image Vulnerability Summary by Severity (ARG)

```kql
securityresources
| where type == "microsoft.security/assessments/subassessments"
| extend assessmentKey = extract(".*assessments/(.+?)/.*", 1, id)
| where assessmentKey == "c0b7cfc6-3172-465a-b378-53c7ff2cc0d5"
| extend severity = tostring(properties.additionalData.vulnerabilityDetails.severity)
| extend status = tostring(properties.status.code)
| extend vulnId = tostring(properties.id)
| where status == 'Unhealthy'
| distinct vulnId, severity
| summarize VulnCount = count() by severity
```

**KPI produced:** Container image vulnerability count by severity (Critical/High/Medium/Low).

#### 7.2 — Vulnerable Container Images with Pod/Namespace Details (ARG)

```kql
securityresources
| where type =~ "microsoft.security/assessments/subassessments"
| extend assessmentKey = extract(@"(?i)providers/Microsoft.Security/assessments/([^/]*)", 1, id)
| where assessmentKey == "c0b7cfc6-3172-465a-b378-53c7ff2cc0d5"
| extend azureClusterId = tostring(properties.additionalData.clusterDetails.clusterResourceId)
| extend cve = tostring(properties.id)
| extend status = properties.status.code
| extend severity = tolower(tostring(properties.additionalData.vulnerabilityDetails.severity))
| where status == "Unhealthy"
| extend azureImageId = tostring(properties.resourceDetails.id)
| extend kubernetesContext = properties.additionalData.kubernetesContext
| mv-expand workload = kubernetesContext.workloads
| mv-expand Container = workload.containers
| extend namespace = tostring(workload.namespace)
| extend containerName = tostring(Container.name)
| extend imageName = extract("(.+)@sha256:", 1, azureImageId)
| project imageName, cve, severity, clusterId = azureClusterId, containerName, namespace
| summarize CVECount = dcount(cve),
    CriticalCVEs = dcountif(cve, severity == "critical"),
    HighCVEs = dcountif(cve, severity == "high")
    by imageName, namespace, clusterId
| order by CriticalCVEs desc, HighCVEs desc
```

**KPI produced:** Vulnerable container images ranked by severity with K8s context (namespace, cluster).

#### 7.3 — Container Recommendations Summary (ARG)

```kql
securityresources
| where type == "microsoft.security/assessments"
| where properties.metadata.recommendationCategory == "SoftwareUpdate"
| where properties.resourceDetails.ResourceType == "K8s-container"
| extend recommendationName = tostring(properties.displayName),
    status = tostring(properties.status.code),
    severity = tostring(properties.metadata.severity),
    source = tostring(properties.resourceDetails.Source)
| where status == "Unhealthy"
| project subscriptionId, recommendationName, severity, source
| summarize Count = count() by recommendationName, severity
| order by severity asc, Count desc
```

**KPI produced:** Unhealthy container-specific recommendations by severity.

#### 7.4 — K8s Control Plane Audit Events (Advanced Hunting)

> ⚠️ Preview table. Requires Defender for Cloud integration with Defender XDR.

```kql
CloudAuditEvents
| where Timestamp > ago(7d)
| summarize EventCount = count() by ActionType
| order by EventCount desc
| take 20
```

**KPI produced:** Top 20 control plane action types in the last 7 days — identifies unusual ARM or KubeAudit activity.

#### 7.5 — Container Process Events (Advanced Hunting)

> ⚠️ Preview table. Requires Defender for Containers.

```kql
CloudProcessEvents
| where Timestamp > ago(7d)
| summarize
    TotalProcesses = count(),
    UniqueContainers = dcount(ContainerName),
    UniqueNamespaces = dcount(KubernetesNamespace),
    UniquePods = dcount(KubernetesPodName)
| project TotalProcesses, UniqueContainers, UniqueNamespaces, UniquePods
```

Drill into suspicious process execution:

```kql
CloudProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("curl", "wget", "nc", "ncat", "bash -i", "python -c", "/dev/tcp", "base64")
| project Timestamp, KubernetesNamespace, KubernetesPodName, ContainerName, ProcessName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

**KPI produced:** Container process activity summary + suspicious command detection.

#### 7.6 — Container Nodes in Exposure Graph (Advanced Hunting)

Cross-reference container assets in the exposure graph:

```kql
ExposureGraphNodes
| where NodeLabel has_any ("kubernetes", "container", "aks")
| summarize Count = count() by NodeLabel
| order by Count desc
```

**KPI produced:** Container-related asset types in the exposure graph.

---

### Phase 8: Cloud Infrastructure Entitlement Management (CIEM)

CIEM analysis uses ExposureGraphEdges permission relationships and ARG. This phase extends the basic edge counts from Phase 3.1 into actionable entitlement analysis.

#### 8.1 — Permission Volume by Target Resource Type

```kql
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| summarize PermissionCount = count() by TargetNodeLabel
| order by PermissionCount desc
| take 15
```

**KPI produced:** Which resource types receive the most permissions — identifies over-permissioned resource categories.

#### 8.2 — Top Overprivileged Identities (By Permission Edge Count)

Identities with the most outgoing "has permissions to" edges may have excessive access:

```kql
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| where SourceNodeLabel has_any ("user", "group", "serviceprincipal", "managedidentity", "serviceaccount")
| summarize PermissionCount = count(), 
    UniqueTargets = dcount(TargetNodeId),
    TargetTypes = make_set(TargetNodeLabel)
    by SourceNodeName, SourceNodeLabel
| order by PermissionCount desc
| take 20
```

**KPI produced:** Top 20 identities by permission volume — candidates for least-privilege reviews.

#### 8.3 — Identity-to-Critical-Resource Permission Mapping

Map which identities have permissions to your most critical resources (from Phase 3.2 choke points):

```kql
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| where TargetNodeName == "<CRITICAL_RESOURCE_NAME>"
| project SourceNodeName, SourceNodeLabel, TargetNodeName, TargetNodeLabel
| summarize IdentityCount = count() by SourceNodeLabel
| order by IdentityCount desc
```

Substitute `<CRITICAL_RESOURCE_NAME>` with top choke points from Phase 3.2.

**KPI produced:** Identity breakdown accessing critical resources — reveals shared access risk.

#### 8.4 — Service Account and Managed Identity Permission Sprawl

```kql
ExposureGraphEdges
| where EdgeLabel in ("has permissions to", "can authenticate as", "can impersonate as")
| where SourceNodeLabel has_any ("serviceaccount", "managedidentity", "serviceprincipal")
| summarize
    PermissionEdges = countif(EdgeLabel == "has permissions to"),
    AuthEdges = countif(EdgeLabel == "can authenticate as"),
    ImpersonateEdges = countif(EdgeLabel == "can impersonate as"),
    UniqueTargets = dcount(TargetNodeId)
    by SourceNodeName, SourceNodeLabel
| extend TotalEdges = PermissionEdges + AuthEdges + ImpersonateEdges
| order by TotalEdges desc
| take 20
```

**KPI produced:** Top 20 non-human identities by total privilege edges — highest-risk service accounts.

#### 8.5 — Role Assignment Distribution

```kql
ExposureGraphEdges
| where EdgeLabel == "has role on"
| summarize RoleAssignments = count(), 
    UniqueIdentities = dcount(SourceNodeId)
    by TargetNodeName, TargetNodeLabel
| order by RoleAssignments desc
| take 10
```

**KPI produced:** Resources with the most role assignments — potential over-scoped RBAC.

---

### Phase 9: Data Security Posture Management (DSPM)

DSPM combines ExposureGraphNodes insights with storage-specific Advanced Hunting tables.

#### 9.1 — Data-Sensitive Asset Inventory (Exposure Graph)

```kql
ExposureGraphNodes
| where NodeLabel has_any ("storage", "blob", "datalake", "database", "cosmos", "sql")
| extend props = parse_json(NodeProperties).rawData
| project NodeName, NodeLabel,
    RiskScore = tostring(props.riskScore),
    ExposureScore = tostring(props.exposureScore),
    IsCustomerFacing = tostring(props.isCustomerFacing)
| order by RiskScore desc
```

**KPI produced:** Data-bearing asset inventory with risk scores.

#### 9.2 — Public-Access Data Stores (Attack Paths)

Identify storage resources in attack paths flagged for public access:

```kql
securityresources
| where type == "microsoft.security/attackpaths"
| extend riskFactors = properties.riskFactors
| mv-expand riskFactor = riskFactors
| where tostring(riskFactor) has_any ("public", "anonymous", "sensitive data")
| project
    attackPathName = tostring(properties.displayName),
    riskLevel = tostring(properties.riskLevel),
    target = tostring(properties.target.entityName),
    targetType = tostring(properties.target.entityType),
    riskFactor = tostring(riskFactor)
| order by riskLevel asc
```

**KPI produced:** Attack paths involving public/anonymous access to sensitive data stores.

#### 9.3 — Cloud Storage Activity Patterns (Advanced Hunting)

> ⚠️ Preview table. Requires Defender for Storage.

```kql
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| summarize
    TotalOperations = sum(OperationsCount),
    FailedOperations = sum(FailedOperationsCount),
    AnonymousSuccessful = sum(AnonymousSuccessfulOperations),
    UniqueIPs = dcount(IpAddress),
    TorAccess = countif(IsTorExitNode == true),
    SuspiciousIPs = countif(IsKnownSuspiciousIp == true)
    by StorageAccount, ServiceType
| order by AnonymousSuccessful desc, SuspiciousIPs desc
```

**KPI produced:** Storage accounts with anonymous access, Tor access, or suspicious IP activity.

#### 9.4 — Storage Anomaly Detection (Advanced Hunting)

```kql
CloudStorageAggregatedEvents
| where Timestamp > ago(7d)
| where IsTorExitNode == true or IsKnownSuspiciousIp == true or AnonymousSuccessfulOperations > 0
| project Timestamp, StorageAccount, StorageContainer, IpAddress, CountryName,
    IsTorExitNode, IsKnownSuspiciousIp, AnonymousSuccessfulOperations,
    AuthenticationType, OperationsCount
| order by Timestamp desc
```

**KPI produced:** Individual anomalous storage access events for investigation.

---

### Phase 10: Security Recommendations & Governance (Azure Resource Graph)

All Phase 10 queries run against `securityresources` via Azure Resource Graph.

#### 10.1 — Recommendation Summary by State and Severity

```kql
securityresources
| where type == 'microsoft.security/assessments'
| extend recommendationName = tostring(properties.displayName),
    recommendationState = tostring(properties.status.code),
    severity = tostring(properties.metadata.severity),
    category = tostring(properties.metadata.categories)
| summarize Count = count() by recommendationState, severity
| order by severity asc, recommendationState asc
```

**KPI produced:** Total recommendations by state (Healthy/Unhealthy/NotApplicable) and severity.

#### 10.2 — Top Failing Recommendations by Severity

```kql
securityresources
| where type == 'microsoft.security/assessments'
| extend recommendationName = tostring(properties.displayName),
    recommendationState = tostring(properties.status.code),
    severity = tostring(properties.metadata.severity),
    category = tostring(properties.metadata.categories),
    implementationEffort = tostring(properties.metadata.implementationEffort),
    threats = tostring(properties.metadata.threats)
| where recommendationState == 'Unhealthy'
| summarize ResourceCount = count() by recommendationName, severity, implementationEffort
| order by severity asc, ResourceCount desc
| take 20
```

**KPI produced:** Top 20 failing recommendations — prioritized by severity and resource impact.

#### 10.3 — Recommendations by Category

```kql
securityresources
| where type == 'microsoft.security/assessments'
| extend recommendationState = tostring(properties.status.code),
    category = tostring(properties.metadata.categories)
| where recommendationState == 'Unhealthy'
| summarize FailingCount = count() by category
| order by FailingCount desc
```

**KPI produced:** Which CNAPP categories (Compute, Data, Networking, IAM, etc.) have the most failing recommendations.

#### 10.4 — Governance Assignment Status

```kql
securityresources
| where type == "microsoft.security/assessments"
| where isnotempty(tostring(properties.displayName))
| join kind=leftouter (
    securityresources
    | where type == "microsoft.security/assessments/governanceassignments"
    | extend assignedResourceId = tostring(properties.assignedResourceId)
    | extend remediationDueDate = todatetime(properties.remediationDueDate)
    | project id = assignedResourceId, remediationDueDate
) on id
| extend hasAssignment = isnotempty(id1)
| extend status = tostring(properties.status.code)
| extend assignmentStatus = iff(status == "Unhealthy",
    iff(hasAssignment == true,
        iff(remediationDueDate < now(), "Overdue", "OnTime"),
        "Unassigned"),
    "Completed")
| summarize Count = count() by assignmentStatus
```

**KPI produced:** Governance assignment status — Overdue/OnTime/Unassigned/Completed.

---

### Phase 11: DevSecOps Posture (Azure Resource Graph)

DevSecOps findings surface IaC misconfigurations and code-level security issues from connected repositories (Azure DevOps, GitHub, GitLab).

#### 11.1 — DevOps Source Recommendations

```kql
securityresources
| where type == 'microsoft.security/assessments'
| extend source = tostring(properties.resourceDetails.Source)
| where source in~ ("Azure DevOps", "GitHub", "GitLab")
| extend recommendationName = tostring(properties.displayName),
    recommendationState = tostring(properties.status.code),
    severity = tostring(properties.metadata.severity)
| where recommendationState == 'Unhealthy'
| summarize ResourceCount = count() by recommendationName, severity, source
| order by severity asc, ResourceCount desc
```

**KPI produced:** Failing DevOps security recommendations by source platform and severity.

#### 11.2 — IaC Assessment Summary

```kql
securityresources
| where type == 'microsoft.security/assessments'
| extend assessmentType = tostring(properties.metadata.assessmentType)
| extend source = tostring(properties.resourceDetails.Source)
| where source in~ ("Azure DevOps", "GitHub", "GitLab")
| extend recommendationState = tostring(properties.status.code)
| summarize
    Healthy = countif(recommendationState == "Healthy"),
    Unhealthy = countif(recommendationState == "Unhealthy"),
    NotApplicable = countif(recommendationState == "NotApplicable")
    by source
| extend TotalAssessed = Healthy + Unhealthy
| extend PassRate = iff(TotalAssessed > 0, round(100.0 * Healthy / TotalAssessed, 1), 0.0)
| project source, PassRate, Healthy, Unhealthy, NotApplicable
```

**KPI produced:** DevSecOps pass rate per source platform — tracks IaC security posture over time.

---

## CNAPP KPI Summary Table

When running CNAPP-focused analyses (Phases 6–11), append these KPIs to the CTEM summary:

```
### Regulatory Compliance (Phase 6)
| KPI | Value | Trend |
|-----|-------|-------|
| Standards Assessed | [Phase 6.1 count] | — |
| Lowest Compliance Score | [Phase 6.3 standard] ([X]%) | 🔴 |
| Total Failing Controls | [Phase 6.1 sum of failedControls] | — |
| Top Failing Standard | [Phase 6.3 lowest score] | — |

### Container Security (Phase 7)
| KPI | Value | Trend |
|-----|-------|-------|
| Container Image CVEs | [Phase 7.1 total] | — |
| Critical Image CVEs | [Phase 7.1 critical count] | 🔴 |
| K8s Namespaces with Vulns | [Phase 7.2 namespace count] | — |
| Control Plane Events (7d) | [Phase 7.4 total] | — |
| Suspicious Container Processes | [Phase 7.5 drill-down count] | — |

### CIEM — Entitlements (Phase 8)
| KPI | Value | Trend |
|-----|-------|-------|
| Total Permission Edges | [Phase 8.1 total] | — |
| Top Overprivileged Identity | [Phase 8.2 top identity] ([X] permissions) | — |
| Non-Human Identity Risk | [Phase 8.4 top service account] ([X] edges) | — |
| Most Role-Assigned Resource | [Phase 8.5 top resource] ([X] assignments) | — |

### DSPM — Data Security (Phase 9)
| KPI | Value | Trend |
|-----|-------|-------|
| Data-Bearing Assets | [Phase 9.1 count] | — |
| Public-Access Data Paths | [Phase 9.2 count] | 🔴 |
| Anonymous Storage Operations (7d) | [Phase 9.3 sum] | — |
| Tor/Suspicious Storage Access (7d) | [Phase 9.3 count] | 🟠 |

### Recommendations & Governance (Phase 10)
| KPI | Value | Trend |
|-----|-------|-------|
| Total Unhealthy Recommendations | [Phase 10.1 unhealthy count] | — |
| Critical/High Failing | [Phase 10.2 count] | 🔴 |
| Governance Assignments Overdue | [Phase 10.4 overdue count] | 🟠 |
| Governance Assignments On-Time | [Phase 10.4 ontime count] | 🟢 |

### DevSecOps (Phase 11)
| KPI | Value | Trend |
|-----|-------|-------|
| DevOps Failing Recommendations | [Phase 11.1 total] | — |
| IaC Pass Rate | [Phase 11.2 rate]% | — |
| Connected Platforms | [Phase 11.2 source list] | — |
```
