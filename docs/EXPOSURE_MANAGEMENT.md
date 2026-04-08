# Exposure Management & CTEM — User Guide

This guide covers how CyberProbe implements **Continuous Threat Exposure Management (CTEM)** and how the `exposure-management` skill accelerates security posture assessments.

---

## Table of Contents

1. [What Is CTEM?](#what-is-ctem)
2. [Quick Start](#quick-start)
3. [Skill Capabilities by Phase](#skill-capabilities-by-phase)
4. [KPI Dashboard Template](#kpi-dashboard-template)
5. [Data Sources & Tool Routing](#data-sources--tool-routing)
6. [Scoring Methodologies](#scoring-methodologies)
7. [Remediation Prioritization](#remediation-prioritization)
8. [Integration with the CyberProbe Ecosystem](#integration-with-the-cyberprobe-ecosystem)
9. [How the Skill Accelerates Your Workflow](#how-the-skill-accelerates-your-workflow)
10. [Troubleshooting & Pitfalls](#troubleshooting--pitfalls)

---

## What Is CTEM?

Continuous Threat Exposure Management (CTEM) is a structured program for continuously assessing and reducing an organization's attack surface. Rather than periodic vulnerability scans, CTEM provides a **living view** of which assets are exposed, how they relate to each other via attack paths, and where remediation effort has the highest impact.

CyberProbe's `exposure-management` skill operationalizes CTEM by:

- Querying **ExposureGraphNodes** and **ExposureGraphEdges** for the full attack surface topology
- Querying **DeviceTvmSoftwareVulnerabilities** for device-level vulnerability posture
- Querying **securityresources** (Azure Resource Graph) for Defender for Cloud attack path data
- Using **Sentinel Graph MCP** for blast radius and exposure perimeter analysis
- Producing a standardized **CTEM KPI Dashboard** with quantified, evidence-based metrics
- Generating a **Remediation Prioritization Matrix** (P1–P4) for action handoff

---

## Quick Start

### Trigger Keywords

The skill is activated automatically when your prompt contains any of these phrases:

| Keyword / Phrase | Example Prompt |
|-----------------|----------------|
| `exposure management` | "Show me our exposure management posture" |
| `CTEM` | "Generate a CTEM dashboard" |
| `attack surface` | "What does our attack surface look like?" |
| `choke points` | "Show me the top choke points" |
| `vulnerability posture` | "What's our vulnerability posture?" |
| `exposure KPI` | "Give me exposure KPI metrics" |
| `attack paths` | "How many attack paths do we have?" |
| `internet-exposed` | "What's internet-exposed in our environment?" |
| `blast radius` | "What's the blast radius of alpine-sql?" |

### Example Prompts

```
"Show me CTEM metrics"                           → Runs all 4 phases, produces full KPI dashboard
"What's our vulnerability posture?"              → Runs Phase 2 only
"Show me choke points"                           → Runs Phase 3 only
"What's internet-exposed?"                       → Runs Phase 1.2 + 1.3
"Generate an exposure KPI report"                → Runs all phases + HTML report output
"Drill into device ds-contoso exposure"             → Runs targeted Phase 3.5 + 2.1
"What's the blast radius of alpine-srv1?"        → Runs Phase 5 (Sentinel Graph MCP)
```

### Smart Phase Selection

The skill automatically selects which phases to execute based on your intent — you don't need to specify "Phase 2" explicitly. The phase selector table:

| User Request | Phases Executed |
|--------------|----------------|
| "CTEM metrics" / "exposure dashboard" | 1 + 2 + 3 + 4 (all) |
| "Vulnerability posture" | 2 only |
| "Choke points" / "attack paths" | 3 only |
| "Internet-exposed assets" | 1.2 + 1.3 only |
| "Exposure KPI report" | 1 + 2 + 3 + 4 + Report |
| "Drill into device X" | 3.3 + 3.5 + 2.1 (targeted) |
| "Blast radius for node X" | 5 |
| "Attack path trends" | 4 only |

---

## Skill Capabilities by Phase

### Phase 1: Attack Surface Inventory

Discovers and classifies all entities in the Defender XDR exposure graph.

| Query | What It Produces | KPIs |
|-------|-----------------|------|
| **1.1 — Asset Classification Summary** | Entity type breakdown (VMs, subscriptions, identities, storage, etc.) | Total assets in exposure graph |
| **1.2 — Internet-Exposed Assets** | Assets with `isCustomerFacing == true`, including risk/exposure scores and public IPs | Count of internet-exposed assets |
| **1.3 — RCE-Vulnerable Assets** | Assets with `vulnerableToRemoteCodeExecution.hasHighOrCritical == true` and max CVSS scores | Count of RCE-vulnerable assets |
| **1.4 — Onboarding & Sensor Health** | MDE onboarding status and sensor health state for VMs/machines | Onboarding coverage %, sensor health % |

**Data source:** `ExposureGraphNodes` via Advanced Hunting (no time filter)

### Phase 2: Vulnerability Posture

Analyzes the fleet-wide vulnerability distribution and identifies the riskiest devices.

| Query | What It Produces | KPIs |
|-------|-----------------|------|
| **2.1 — Top Vulnerable Devices** | Weighted vulnerability scoring per device: `(Critical×4) + (High×2) + (Medium×1) + Low` | Top 10 riskiest devices with weighted scores |
| **2.2 — Severity Distribution** | Fleet-wide totals: total unique CVEs, critical, high, medium, low counts | Aggregate vulnerability counts |
| **2.3 — OS Platform Breakdown** | Which operating systems carry the most risk | Risk distribution across OS types |
| **2.4 — Most Prevalent CVEs** | Top 20 critical/high CVEs by number of affected devices | Highest-blast-radius CVEs to patch first |

**Data source:** `DeviceTvmSoftwareVulnerabilities` via Advanced Hunting (no time filter — inventory snapshot)

### Phase 3: Attack Paths & Choke Points

Maps the attack graph relationships and identifies high-value remediation targets.

| Query | What It Produces | KPIs |
|-------|-----------------|------|
| **3.1 — Relationship Types** | Edge type distribution (permissions, vulnerabilities, network routes) | Attack graph composition |
| **3.2 — Top Choke Points** | Top 10 nodes with the most incoming attack path edges | Choke point ranking with path counts |
| **3.3 — Edge Type Breakdown** | Per-choke-point drill-down: what types of edges converge on it | Choke point attack vector composition |
| **3.4 — VM Choke Points** | VM-specific subset of choke points | VM-only choke point ranking |
| **3.5 — Choke × Vulnerability Cross-Reference** | Joins choke points with vulnerability counts — *highest-impact query* | Choke points ordered by vulnerability severity |
| **3.6 — Full Path Context** | Source entities and edge types for a specific target node | Attacker profile for a choke point |
| **3.7 — Node Property Extraction** | Full NodeProperties inspection for a specific node | Detailed exposure data for a target |

**Data source:** `ExposureGraphEdges` + `ExposureGraphNodes` + `DeviceTvmSoftwareVulnerabilities` via Advanced Hunting (no time filter)

### Phase 4: Attack Path Trends & Risk Scoring

Queries Defender for Cloud attack path data for severity breakdown and composite risk scores.

| Query | What It Produces | KPIs |
|-------|-----------------|------|
| **4.1 — Attack Path Count by Severity** | Critical / High / Medium / Total attack path counts | Core CTEM headline metric |
| **4.2 — Composite Risk Score** | Weighted risk score from exposure factors: `(InternetExposure×3) + (LateralMovement×2) + (Vulnerabilities×2) + (CriticalResource×4)` | Single composite risk number |
| **4.3 — Entry Points & Targets** | Entry point and target entity mapping per attack path | Attack path topology |

**Data source:** `securityresources` via Azure Resource Graph (Data Lake or Azure MCP)

### Phase 5: Blast Radius & Exposure Perimeter

Advanced graph analysis using Sentinel Graph MCP tools (when available).

| Tool | What It Produces |
|------|-----------------|
| **`graph_find_blastRadius`** | All entities affected if a specific node is compromised |
| **`graph_exposure_perimeter`** | How accessible a node is from entry points |
| **`graph_find_walkable_paths`** | Attack paths between two specific entities (up to 4 hops) |

**Fallback:** If Sentinel Graph MCP is unavailable, Phase 3 `ExposureGraphEdges` queries provide equivalent (table-based) choke point and path analysis.

---

## KPI Dashboard Template

After executing the relevant phases, all findings are compiled into this standardized template:

```
📊 CTEM KPI Dashboard — [Date]

┌─────────────────────────────────────────────┐
│ ATTACK SURFACE                              │
├──────────────────────────┬──────┬───────────┤
│ KPI                      │ Value│ Trend     │
├──────────────────────────┼──────┼───────────┤
│ Total Assets             │      │ —         │
│ Internet-Exposed Assets  │      │ —         │
│ RCE-Vulnerable Assets    │      │ —         │
│ MDE Onboarding Coverage  │    % │ —         │
│ Sensor Health (Active)   │    % │ —         │
└──────────────────────────┴──────┴───────────┘

┌─────────────────────────────────────────────┐
│ VULNERABILITY POSTURE                       │
├──────────────────────────┬──────┬───────────┤
│ Total Unique CVEs        │      │ —         │
│ Critical Vulnerabilities │      │ 🔴        │
│ High Vulnerabilities     │      │ 🟠        │
│ Devices with Critical    │      │ —         │
│ #1 Riskiest Device       │      │ —         │
└──────────────────────────┴──────┴───────────┘

┌─────────────────────────────────────────────┐
│ ATTACK PATHS & CHOKE POINTS                 │
├──────────────────────────┬──────┬───────────┤
│ Total Attack Paths       │      │ —         │
│ Critical Attack Paths    │      │ 🔴        │
│ High Attack Paths        │      │ 🟠        │
│ Top Choke Point          │      │ —         │
│ Composite Risk Score     │      │ —         │
└──────────────────────────┴──────┴───────────┘

┌─────────────────────────────────────────────┐
│ EXPOSURE FACTORS (weighted)                 │
├──────────────────┬───────┬────────┬─────────┤
│ Factor           │ Count │ Weight │ Score   │
├──────────────────┼───────┼────────┼─────────┤
│ Internet Exposure│       │ ×3     │         │
│ Lateral Movement │       │ ×2     │         │
│ Vulnerabilities  │       │ ×2     │         │
│ Critical Resource│       │ ×4     │         │
└──────────────────┴───────┴────────┴─────────┘
```

**Trend column:** `—` on first run. Compare against previous report values on subsequent runs.

---

## Data Sources & Tool Routing

The skill queries four distinct data sources, each with its own MCP tool and constraints:

| Data Source | Table(s) | MCP Tool | Constraints |
|-------------|----------|----------|-------------|
| **XDR Exposure Graph** | `ExposureGraphNodes`, `ExposureGraphEdges` | `RunAdvancedHuntingQuery` (Triage MCP) | AH-only. No `Timestamp` column — never add time filters. |
| **Device Vulnerability Inventory** | `DeviceTvmSoftwareVulnerabilities` | `RunAdvancedHuntingQuery` (Triage MCP) | AH-only. No `Timestamp` column — inventory snapshot. |
| **Defender for Cloud Attack Paths** | `securityresources` (type: `microsoft.security/attackpaths`) | Data Lake (`query_lake`) or Azure MCP (`monitor_workspace_log_query`) | Azure Resource Graph table. Uses standard KQL. |
| **Sentinel Graph Analysis** | N/A (graph API) | Sentinel Graph MCP (`graph_find_blastRadius`, etc.) | Requires Sentinel Graph MCP to be available. Falls back to Phase 3 queries. |

### JSON Extraction Pattern

`ExposureGraphNodes.NodeProperties` is a raw JSON string. Always extract fields using:

```kql
parse_json(NodeProperties).rawData.<field>
```

Key fields available under `.rawData`:

| Field | Description |
|-------|-------------|
| `riskScore` | Device risk score |
| `exposureScore` | Exposure level score |
| `isCustomerFacing` | Whether the asset is internet-exposed |
| `publicIP` | Public IP address (if internet-facing) |
| `osPlatform` | Operating system |
| `onboardingStatus` | MDE onboarding state (`Onboarded` / not) |
| `sensorHealthState` | MDE sensor state (`Active` / `Inactive` / etc.) |
| `highRiskVulnerabilityInsights` | Nested object with RCE, privilege escalation insights |
| `criticalityLevel` | Business criticality classification |
| `lastSeen` | Last communication timestamp |

> For full column definitions, see [`docs/XDR_TABLES_AND_APIS.md` § XDR Table Reference](XDR_TABLES_AND_APIS.md#4-xdr-table-reference).

---

## Scoring Methodologies

### Weighted Vulnerability Score

Used in Phase 2 to rank devices by risk. Applies severity multipliers to vulnerability counts:

$$\text{WeightedScore} = (\text{Critical} \times 4) + (\text{High} \times 2) + (\text{Medium} \times 1) + \text{Low}$$

**Interpretation:** A device with 2 Critical + 5 High scores $2 \times 4 + 5 \times 2 = 18$, versus a device with 20 Low vulns scoring $20$. The first device is treated as higher priority despite fewer total CVEs.

### Composite Risk Score

Used in Phase 4 to quantify aggregate exposure posture from attack path risk factors:

$$\text{RiskScore} = (\text{InternetExposure} \times 3) + (\text{LateralMovement} \times 2) + (\text{Vulnerabilities} \times 2) + (\text{CriticalResource} \times 4)$$

| Factor | Weight | Rationale |
|--------|--------|-----------|
| Internet Exposure | ×3 | Directly reachable from external attackers |
| Lateral Movement | ×2 | Enables pivot from initial compromise |
| Vulnerabilities | ×2 | Exploitable weaknesses on the path |
| Critical Resource | ×4 | Highest business impact if compromised |

**Trend tracking:** Run the composite risk score query weekly. A rising score indicates expanding exposure; a declining score confirms remediation effectiveness.

---

## Remediation Prioritization

After generating KPIs, the skill produces a **Remediation Priority Matrix** that ranks assets by combined choke point status, vulnerability severity, and internet exposure:

| Priority | Criteria | SLA | Action |
|----------|----------|-----|--------|
| 🔴 **P1 — Critical** | Choke point + Critical vulns + internet-exposed | Immediate | Patch immediately, harden NSG/firewall, consider isolation |
| 🟠 **P2 — High** | Choke point + High vulns **OR** internet-exposed + Critical vulns | 7 days | Expedited patching, review network segmentation |
| 🟡 **P3 — Medium** | Choke point with low vuln count **OR** internal-only with critical vulns | 30 days | Standard expedited patching |
| 🔵 **P4 — Low** | Internal assets with medium/low vulns, not on attack paths | Standard cycle | Normal patch management process |

### How Priority Is Determined

The cross-reference query (Phase 3.5) is critical here. It joins `ExposureGraphEdges` (choke points) with `DeviceTvmSoftwareVulnerabilities` to produce a single table showing:

- Device name
- Number of incoming attack path edges (choke point score)
- Total vulnerabilities
- Critical vulnerability count
- High vulnerability count

Combined with the internet-exposure flag from Phase 1.2, this data maps directly to the P1–P4 matrix.

---

## Integration with the CyberProbe Ecosystem

The `exposure-management` skill is designed to work alongside other CyberProbe components:

### Related Query Libraries

| File | What It Contains |
|------|-----------------|
| [`queries/attack_path_monitoring.kql`](../queries/attack_path_monitoring.kql) | 10 verified queries for attack path trends, choke point activity monitoring, risk scoring, remediation progress tracking |
| [`queries/cloud/attack_path_monitoring.kql`](../queries/cloud/attack_path_monitoring.kql) | Cloud-specific attack path queries for cloud resource exposure |
| [`docs/XDR_TABLES_AND_APIS.md`](XDR_TABLES_AND_APIS.md) | Full table schemas (Section 4), KQL Query Cookbook with 15+ verified queries (Section 6) |

### Remediation Scripts

| File | What It Does |
|------|-------------|
| [`scripts/remediation/Remediate-AttackPaths.ps1`](../scripts/remediation/Remediate-AttackPaths.ps1) | Automated remediation for identified choke points — NSG hardening, Key Vault access tightening, storage account security, managed identity permission review |
| [`scripts/remediation/Deploy-SentinelRules.ps1`](../scripts/remediation/Deploy-SentinelRules.ps1) | Deploys Sentinel analytics rules for ongoing monitoring of choke points, Key Vault anomalies, lateral movement, data exfiltration indicators |
| [`scripts/remediation/README.md`](../scripts/remediation/README.md) | Documents known choke points, high-value targets, remediation phases, and KPI tracking targets |

### Security Copilot Agents

| Agent | What It Does |
|-------|-------------|
| [`security-copilot/agents/top-attack-paths-daily-agent.yaml`](../security-copilot/agents/top-attack-paths-daily-agent.yaml) | Scheduled daily briefing (08:00 ET) of top 5 attack paths by risk level using NL2KQL for Defender XDR |
| [`security-copilot/agents/cspm-server-recommendations-agent.yaml`](../security-copilot/agents/cspm-server-recommendations-agent.yaml) | CSPM server recommendations agent with attack path analysis phases |

### Skill Chaining

The exposure-management skill can be chained with other CyberProbe skills for end-to-end workflows:

```
1. "Show me CTEM metrics"              → exposure-management (generates KPI dashboard)
2. "Investigate the top choke point"   → endpoint-device-investigation (forensics on the device)
3. "Enrich external IPs"               → threat-enrichment (multi-source IP enrichment)
4. "Generate an HTML report"           → report-generation (dark-theme HTML with methodology)
```

**Investigation JSON reuse:** If a previous investigation produced a `reports/investigation_*.json` file, the exposure-management skill will reference enriched IP data and alert context from it rather than re-querying.

---

## How the Skill Accelerates Your Workflow

### Without the Skill (Manual Approach)

| Step | Manual Effort |
|------|--------------|
| 1. Identify which tables contain exposure data | Research docs, trial-and-error with table names |
| 2. Determine which MCP tool to use | Read copilot-instructions.md, check if table is AH-only vs Data Lake |
| 3. Check if tables have a Timestamp column | Query schema, encounter `Failed to resolve column` errors, debug |
| 4. Write KQL for ExposureGraphNodes | Figure out `parse_json(NodeProperties).rawData.<field>` pattern |
| 5. Write KQL for DeviceTvm tables | Discover inventory snapshot behavior, remove time filters |
| 6. Cross-reference choke points with vulnerabilities | Write complex joins from scratch, debug join key mismatches |
| 7. Query attack path data from Azure Resource Graph | Determine `securityresources` + `type == "microsoft.security/attackpaths"` |
| 8. Calculate risk scores | Design weighting formulas from scratch |
| 9. Compile KPI dashboard | Manually aggregate results from all queries |
| 10. Prioritize remediation | Ad-hoc judgment without a structured framework |

**Typical time:** 2–4 hours for a first-time analyst. 30–60 minutes for a seasoned operator.

### With the Skill (Automated Approach)

| Step | What Happens |
|------|-------------|
| 1. Say "Show me CTEM metrics" | Skill activates, selects all 4 phases |
| 2. All 20+ queries execute automatically | Pre-verified KQL — no schema errors, no time-filter mistakes |
| 3. Tool routing is handled | ExposureGraph → AH, securityresources → Data Lake, blast radius → Graph MCP |
| 4. JSON extraction patterns are built-in | NodeProperties parsing is pre-configured |
| 5. KPI dashboard is compiled | Standardized template populated with live data |
| 6. Risk scores are calculated | Weighted scoring formulas applied automatically |
| 7. Remediation priorities are assigned | P1–P4 matrix applied based on intersecting risk factors |
| 8. Report generated on request | Chains to `report-generation` skill for HTML output with methodology |

**Typical time:** 2–5 minutes (query execution time only).

### Key Acceleration Points

| Acceleration Area | Without Skill | With Skill |
|-------------------|--------------|------------|
| Schema discovery | Manual research | Pre-encoded in queries |
| Time-filter errors on inventory tables | Common failure mode | Eliminated — queries have no time filters |
| NodeProperties JSON extraction | Trial-and-error with `parse_json` | `parse_json(NodeProperties).rawData.<field>` built into every query |
| Tool routing (AH vs Data Lake) | Requires reading decision trees | Automatic per-query routing |
| Choke point × vulnerability cross-reference | Complex multi-table join | Single pre-built query (3.5) |
| Risk scoring | No baseline methodology | Standardized weighted formulas |
| KPI dashboard | Freeform, inconsistent | Standardized template with 15+ metrics |
| Remediation prioritization | Subjective | Structured P1–P4 matrix |

---

## Troubleshooting & Pitfalls

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|---------|
| `Failed to resolve column 'Timestamp'` | Added a time filter to ExposureGraph or DeviceTvm table | Remove the `where Timestamp > ago(...)` clause — these are inventory snapshots with no Timestamp column |
| `Table not found: ExposureGraphNodes` | Tried to query via Data Lake (`query_lake`) | Switch to `RunAdvancedHuntingQuery` — ExposureGraph tables are AH-only |
| `Table not found: securityresources` | Tried to query via Advanced Hunting | Switch to Data Lake or Azure Resource Graph — `securityresources` is not an AH table |
| Empty NodeProperties fields | Defender CSPM plan not enabled or device not onboarded | Verify Defender for Servers / CSPM is active; check onboarding in Phase 1.4 |
| Choke × Vulnerability join returns 0 rows | `DeviceName` in DeviceTvm doesn't match `TargetNodeName` in ExposureGraphEdges | Check name format differences (FQDN vs short name); use `has` instead of exact match |
| Query blocked by MCP safety filter | Advanced Hunting MCP blocked the query | Fall back to Graph API `POST /security/runHuntingQuery` — see copilot-instructions.md MCP Fallback section |

### Prerequisites Checklist

Before running the skill, verify:

- [ ] **Defender CSPM** or **Defender for Servers** plan is enabled (required for ExposureGraph data)
- [ ] **Triage MCP** with `RunAdvancedHuntingQuery` is available
- [ ] **Security Reader** (minimum) permissions for Advanced Hunting
- [ ] **Data Lake** (`query_lake`) access for securityresources queries (Phase 4)
- [ ] **Sentinel Graph MCP** (optional, for Phase 5 blast radius analysis)

---

## Further Reading

| Resource | Description |
|----------|-------------|
| [Skill Definition](../.github/skills/exposure-management/SKILL.md) | The full skill file with all KQL queries and workflow logic |
| [XDR Tables & APIs Reference](XDR_TABLES_AND_APIS.md) | Complete table schemas, API endpoints, and KQL Query Cookbook |
| [Attack Path Monitoring Queries](../queries/attack_path_monitoring.kql) | 10 standalone verified queries for attack path trend monitoring |
| [Remediation Scripts](../scripts/remediation/README.md) | Automated choke point remediation and Sentinel rule deployment |
| [Copilot Instructions](../.github/copilot-instructions.md) | Global rules for KQL pre-flight, tool routing, and MCP fallbacks |
| [Investigation Guide](../Investigation-Guide.md) | Full investigation workflow patterns and sample KQL queries |
