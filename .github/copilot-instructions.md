# CyberProbe — GitHub Copilot Integration

This workspace contains a security investigation automation system. GitHub Copilot can help you run investigations using natural language.

## 📑 TABLE OF CONTENTS

1. [Critical Workflow Rules](#-critical-workflow-rules---read-first) — Start here!
2. [Environment Configuration](#-environment-configuration) — Read `enrichment/config.json` for API keys and workspace details
3. [Sentinel Workspace Selection](#-sentinel-workspace-selection---global-rule) — Mandatory workspace selection flow
4. [KQL Pre-Flight Checklist](#-kql-pre-flight-checklist) — Mandatory before EVERY ad-hoc query
5. [Tool Selection Rule: Data Lake vs Advanced Hunting](#-tool-selection-rule-data-lake-vs-advanced-hunting) — Choose the right KQL execution tool
6. [Known Table Pitfalls](#-known-table-pitfalls) — Schema gotchas that cause query failures
7. [Evidence-Based Analysis](#-evidence-based-analysis---global-rule) — Anti-hallucination guardrails
8. [Available Skills](#-available-skills) — 10 specialized investigation workflows
9. [Integration with MCP Servers](#-integration-with-mcp-servers) — Platform MCP tools
10. [IP Enrichment Utility](#-ip-enrichment-utility) — `enrichment/enrich_ips.py`
11. [Query Library](#-query-library) — Verified KQL collections in `queries/`

---

## ⚠️ CRITICAL WORKFLOW RULES — READ FIRST ⚠️

### Skill Detection

🤖 **SKILL DETECTION**: Before starting any investigation, check the [Available Skills](#-available-skills) section and load the appropriate SKILL.md file.

### Environment Configuration

Environment-specific values (workspace IDs, tenant IDs, API tokens) are stored in `enrichment/config.json`. This file is gitignored and never committed.

When you need environment values, **read `enrichment/config.json`** instead of asking the user or hardcoding values.

| Field | Used By | Description |
|-------|---------|-------------|
| `sentinel_workspace_id` | Sentinel Data Lake MCP (`query_lake`) | Log Analytics workspace GUID |
| `tenant_id` | All Azure/Sentinel tools | Entra ID tenant |
| `domain` | Investigation skills, report generation | Organization’s primary Entra domain (e.g., `contoso.com`) |
| `api_keys.ipinfo` | `enrich_ips.py` | ipinfo.io API key |
| `api_keys.abuseipdb` | `enrich_ips.py` | AbuseIPDB API key |
| `api_keys.vpnapi` | `enrich_ips.py` | vpnapi.io API key |
| `api_keys.shodan` | `enrich_ips.py` | Shodan API key |
| `api_keys.virustotal` | `enrich_iocs.py` | VirusTotal API key |

### Investigation JSON Reuse

**⚠️ BEFORE answering ANY follow-up question about existing investigations:**

1. ✅ **Check if investigation JSON exists** in `reports/` directory (naming: `investigation_<upn_prefix>_YYYY-MM-DD.json`)
2. ✅ **Read `ip_enrichment` array in JSON** for IP context (VPN, abuse scores, threat intel)
3. ✅ **Only query Sentinel/Graph if data is missing** from enriched JSON

**DO NOT re-query threat intel or sign-in data if it's already in the JSON file!**

---

## 🔴 SENTINEL WORKSPACE SELECTION — GLOBAL RULE

This rule applies to ALL skills and ALL Sentinel queries. Follow STRICTLY.

When executing ANY Sentinel query (via the Sentinel Data Lake `query_lake` MCP tool):

### Workspace Selection Flow

1. **BEFORE first query:** Call `list_sentinel_workspaces()` to enumerate available workspaces
2. **If exactly 1 workspace:** Auto-select, display to user, proceed
3. **If multiple workspaces AND no prior selection in session:**
   - Display ALL workspaces with Name and ID
   - ASK user: "Which Sentinel workspace should I use for this investigation?"
   - ⛔ STOP AND WAIT for explicit user response
   - ⛔ DO NOT proceed until user selects
4. **If query fails on selected workspace:**
   - ⛔ STOP IMMEDIATELY
   - Report: "⚠️ Query failed on [WORKSPACE_NAME]. Error: [ERROR_MESSAGE]"
   - Display available workspaces
   - ASK user to select a different workspace
   - ⛔ DO NOT automatically retry with another workspace

### 🔴 PROHIBITED Actions

| Action | Status |
|--------|--------|
| Auto-selecting workspace when multiple exist | ❌ PROHIBITED |
| Switching workspaces after query failure without asking | ❌ PROHIBITED |
| Proceeding with ambiguous workspace context | ❌ PROHIBITED |
| Assuming workspace from previous conversation turns | ❌ PROHIBITED |

### ✅ REQUIRED Actions

| Scenario | Action |
|----------|--------|
| Multiple workspaces, none selected | STOP, list all, ASK user, WAIT |
| Query fails with table/workspace error | STOP, report error, ASK user, WAIT |
| Single workspace available | Auto-select, DISPLAY to user, proceed |
| Workspace already selected in session | Reuse selection, DISPLAY which workspace is being used |

---

## 🔴 KQL PRE-FLIGHT CHECKLIST

This checklist applies to EVERY ad-hoc KQL query before execution.

**Exception — Skill & query library queries:** When following a SKILL.md investigation workflow or using a query directly from the `queries/` library, the queries are already verified. Skip Steps 1–4 and use those queries directly (substituting entity values as instructed). Step 5 (sanity-check zero results) still applies.

### Step 1: Check for Existing Verified Queries

| Priority | Source | How |
|----------|--------|-----|
| 1st | Skills directory (`.github/skills/`) | `grep_search` for the table name or entity pattern scoped to `.github/skills/**`. Battle-tested queries with known pitfalls documented. |
| 2nd | Queries library (`queries/`) | `grep_search` for the table name, keyword, or MITRE technique scoped to `queries/**`. Standalone verified query collections. |
| 3rd | Investigation-Guide.md Appendix | Check Sample KQL Queries section for canonical patterns |
| 4th | KQL Search MCP | Use `search_github_examples_fallback` or `validate_kql_query` for community examples |
| 5th | Microsoft Learn MCP | Use `microsoft_code_sample_search` with `language: "kusto"` for official examples |

**Short-circuit rule:** If a suitable query is found in Priority 1–3, skip Steps 2–4 and use it directly (substituting entity values). Step 5 still applies.

### Step 2: Verify Table Schema

Before querying any table for the first time in a session, verify the schema:

- Use `search_tables` or `get_table_schema` from KQL Search MCP
- Confirm column names, types, and which columns contain GUIDs vs human-readable values
- Check if the table exists in Data Lake vs Advanced Hunting (see Tool Selection Rule)

### Step 3: Check Known Table Pitfalls

Review the [Known Table Pitfalls](#-known-table-pitfalls) section before querying common tables.

### Step 4: Validate Before Execution

- For complex queries: use `validate_kql_query` to check syntax
- Ensure datetime filter is the FIRST filter in the query
- Use `take` or `summarize` to limit results

### Step 5: Sanity-Check Zero Results

If a query returns 0 results for a commonly-populated table, STOP and verify:

| Check | Action |
|-------|--------|
| Is the query logic correct? | Review join conditions, filter values, and field types |
| Am I filtering on GUIDs where I used a name (or vice versa)? | Check schema for field content type |
| Is the date range appropriate? | Ensure the time filter covers the expected data window |
| Does the table exist in this data source? | Try the other KQL execution tool if applicable |

⛔ **DO NOT report "no results found" until you have verified the query itself is correct.** A zero-result query may indicate a bad query, not absence of data.

### 🔴 PROHIBITED Actions

| Action | Status |
|--------|--------|
| Writing KQL from scratch without completing Steps 1–2 | ❌ PROHIBITED |
| Querying a table for the first time without checking schema | ❌ PROHIBITED |
| Filtering `SecurityIncident.AlertIds` by entity names | ❌ PROHIBITED |
| Reading `SecurityAlert.Status` as current investigation status | ❌ PROHIBITED |
| Reporting 0 results without sanity-checking the query logic | ❌ PROHIBITED |
| Assuming field content types without schema verification | ❌ PROHIBITED |

---

## 🔧 TOOL SELECTION RULE: DATA LAKE VS ADVANCED HUNTING

> **📖 Deep Reference:** For detailed table schemas, ready-to-use KQL queries (vulnerability assessment, exposure management, choke point analysis), and full troubleshooting, see [`docs/XDR_TABLES_AND_APIS.md`](../docs/XDR_TABLES_AND_APIS.md).

Two KQL execution tools are available. Each has trade-offs:

| Aspect | Advanced Hunting (`RunAdvancedHuntingQuery`) | Sentinel Data Lake (`query_lake`) |
|--------|----------------------------------------------|-----------------------------------|
| Cost | Free (included in Defender license) | Billed per query (Log Analytics ingestion costs) |
| Retention | 30 days | 90+ days (workspace-configured) |
| Timestamp column | `Timestamp` | `TimeGenerated` |
| Safety filter | MCP-level safety filter may block some queries | No additional safety filter |

### Decision Logic

**Step 1 — Identify table category:**

| Category | Tables | Use |
|----------|--------|-----|
| Sentinel-native | SigninLogs, AuditLogs, SecurityAlert, SecurityIncident, SecurityEvent, OfficeActivity, AADUserRiskEvents, Syslog, CommonSecurityLog, ThreatIntelligenceIndicator, Heartbeat, custom `*_CL` tables | Data Lake only |
| XDR-native (AH-only) | DeviceTvm*, DeviceBaseline*, AAD*Beta, EntraIdSignInEvents, EntraIdSpnSignInEvents, CampaignInfo, MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo, DataSecurityBehaviors, DataSecurityEvents, ExposureGraphNodes, ExposureGraphEdges, DisruptionAndResponseEvents, GraphApiAuditEvents, OAuthAppInfo, AIAgentsInfo, CloudAuditEvents, CloudProcessEvents, CloudStorageAggregatedEvents, CloudDnsEvents, CloudPolicyEnforcementEvents, FileMaliciousContentInfo, IdentityEvents | Advanced Hunting only |
| Available in both | Device* (non-Tvm), Alert*, Email*, Identity*, CloudAppEvents, Behavior*, Url* | See Step 2 |

**Step 2 — For tables available in both, choose by context:**

| Condition | Use | Fallback |
|-----------|-----|----------|
| Lookback ≤ 30 days (default) | Advanced Hunting | Data Lake |
| Lookback > 30 days | Data Lake | Advanced Hunting |
| Query blocked by safety filter | Data Lake | — |
| Data Lake returns "table not found" | Advanced Hunting | — |

**Step 3 — Timestamp adaptation when switching tools:**

- Advanced Hunting → Data Lake: `Timestamp` → `TimeGenerated`
- Data Lake → Advanced Hunting: `TimeGenerated` → `Timestamp`

**Step 4 — Pre-authored query files:**

- Uses `Timestamp` → run via Advanced Hunting as-written
- Uses `TimeGenerated` → run via Data Lake as-written

### Step 5 — MCP Unavailability Fallback (Defender APIs)

When an MCP tool fails with connectivity, authentication, or generic invocation errors (not query-specific syntax/schema errors), fall back to the Defender Security APIs via Microsoft Graph.

**Detection rule:** If an MCP tool returns a generic invocation error (e.g., "An error occurred invoking...") on **2 consecutive calls** including a minimal test query (e.g., `| take 1`), classify it as **"MCP unavailable"** and switch to the fallback for the remainder of the session.

**Fallback priority order:**

1. **Try alternative MCP server** (e.g., if Triage MCP fails, try Azure MCP `monitor_workspace_log_query` for tables available in both)
2. **Use Microsoft Graph MCP** (`microsoft_graph_suggest_queries` → `microsoft_graph_get`) to call Defender Security APIs directly
3. **Use terminal** (PowerShell `Invoke-RestMethod` or Python `requests`) to call the APIs with bearer token from `az account get-access-token`

| Failed MCP Tool | Fallback via Graph MCP | API Endpoint | Method |
|----------------|----------------------|--------------|--------|
| `RunAdvancedHuntingQuery` | `microsoft_graph_get` | `/security/runHuntingQuery` | `POST` with body `{"Query": "<KQL>"}` |
| `ListIncidents` | `microsoft_graph_get` | `/security/incidents?$top=50&$orderby=createdDateTime desc` | `GET` |
| `GetIncidentById` | `microsoft_graph_get` | `/security/incidents/{id}` | `GET` |
| `ListAlerts` | `microsoft_graph_get` | `/security/alerts_v2` | `GET` |
| `GetAlertByID` | `microsoft_graph_get` | `/security/alerts_v2/{id}` | `GET` |
| `GetDefenderMachine` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/machines/{id}` | `GET` |
| `GetDefenderMachineAlerts` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/machines/{id}/alerts` | `GET` |
| `GetDefenderMachineVulnerabilities` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/machines/{id}/vulnerabilities` | `GET` |
| `GetDefenderIpAlerts` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/ips/{ip}/alerts` | `GET` |
| `GetDefenderIpStatistics` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/ips/{ip}/stats` | `GET` |
| `ListUserRelatedAlerts` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/users/{id}/alerts` | `GET` |
| `ListUserRelatedMachines` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/users/{id}/machines` | `GET` |
| `GetDefenderFileInfo` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/files/{sha1}` | `GET` |
| `GetDefenderFileAlerts` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/files/{sha1}/alerts` | `GET` |
| `GetDefenderFileRelatedMachines` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/files/{sha1}/machines` | `GET` |
| `GetDefenderFileStatistics` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/files/{sha1}/stats` | `GET` |
| `FindDefenderMachinesByIp` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/machines/findbyip(ip='{ip}')` | `GET` |
| `GetDefenderInvestigation` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/investigations/{id}` | `GET` |
| `ListDefenderInvestigations` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/investigations` | `GET` |
| `ListDefenderIndicators` | `microsoft_graph_get` | `/security/tiIndicators` | `GET` |
| `ListDefenderRemediationActivities` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/remediationTasks` | `GET` |
| `GetDefenderRemediationActivity` | `microsoft_graph_get` | `/security/microsoft/windowsDefenderATP/remediationTasks/{id}` | `GET` |
| `query_lake` | Azure MCP `monitor_workspace_log_query` | Log Analytics via ARM path | — |
| `list_sentinel_workspaces` | Azure MCP `subscription_list` + resource graph query | ARM resource enumeration | — |

**IMPORTANT — Graph MCP workflow for API fallback:**
1. ALWAYS call `microsoft_graph_suggest_queries` first to verify the endpoint exists
2. For Advanced Hunting POST: body must be `{"Query": "<KQL_QUERY_STRING>"}`
3. For list endpoints: use OData parameters (`$filter`, `$top`, `$orderby`, `$select`)
4. If Graph MCP also fails, fall back to terminal with `az rest` or `Invoke-RestMethod`

**Terminal fallback example (Advanced Hunting):**
```powershell
$token = (az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
$body = @{ Query = 'DeviceInfo | take 5' } | ConvertTo-Json
Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
  -Method POST -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
  -Body $body
```

### Quick Reference

| Table Type | Primary Tool | Fallback 1 | Fallback 2 (API) |
|------------|-------------|------------|-------------------|
| Sentinel-native (SigninLogs, AuditLogs, SecurityAlert, etc.) | Data Lake | Azure MCP `monitor_workspace_log_query` | `az rest` against Log Analytics |
| Device* (non-Tvm), Alert*, Email*, Identity*, Cloud* ≤ 30d | Advanced Hunting | Data Lake | Graph API `/security/runHuntingQuery` |
| Device* (non-Tvm), Alert*, Email*, Identity*, Cloud* > 30d | Data Lake | Advanced Hunting | Graph API `/security/runHuntingQuery` |
| DeviceTvm* | Advanced Hunting | — | Graph API `/security/runHuntingQuery` |
| AAD*Beta, EntraId*, AIAgentsInfo, Exposure*, Disruption*, Message*, DataSecurity*, DeviceBaseline*, other XDR-native AH-only | Advanced Hunting | — | Graph API `/security/runHuntingQuery` |
| Custom tables (*_CL) | Data Lake | Azure MCP `monitor_workspace_log_query` | `az rest` against Log Analytics |

---

## 🔴 KNOWN TABLE PITFALLS

Review this quick-reference before querying these tables. These are the most common sources of query failures:

| Table | Pitfall | Correct Approach |
|-------|---------|-----------------|
| **SecurityAlert** | `Status` field is immutable — always `"New"` regardless of actual state | MUST join with `SecurityIncident` to get real Status/Classification. See Investigation-Guide.md sample queries. |
| **SecurityAlert** | `ProviderName` is internal (e.g., `MDATP`, `ASI Scheduled Alerts`, `MCAS`) | Use `ProductName` for product grouping. Translate raw values to current branding in reports. |
| **SecurityIncident** | `AlertIds` contains `SystemAlertId` GUIDs, NOT usernames/IPs/entity names | NEVER filter `AlertIds` by entity name. Instead: query `SecurityAlert` first filtering by `Entities has '<entity>'`, then join to `SecurityIncident` on `AlertId`. |
| **AuditLogs** | `InitiatedBy`, `TargetResources` are dynamic fields | Always wrap in `tostring()` before using `has` operator |
| **AuditLogs** | `OperationName` values vary across providers | Use broad `has "keyword"` instead of exact match for discovery queries |
| **SigninLogs** | `DeviceDetail`, `LocationDetails`, `ConditionalAccessPolicies`, `Status` may be dynamic OR string depending on workspace | Always use `tostring(parse_json(DeviceDetail).operatingSystem)` — works for both types. Direct dot-notation fails with SemanticError when column is string type. |
| **SigninLogs** | `Location` is a string column, NOT dynamic. `Location.countryOrRegion` fails with SemanticError | Use `parse_json(LocationDetails).countryOrRegion` for geographic sub-properties. `Location` works with `dcount()`, `has`, `isnotempty()` but NOT dot-property access. |
| **AADNonInteractiveUserSignInLogs** | `DeviceDetail`, `LocationDetails` etc. are always stored as string | Same `parse_json()` pattern as SigninLogs. |
| **AADUserRiskEvents** | May have different retention than SigninLogs | Cross-reference with `SigninLogs` `RiskLevelDuringSignIn` for complete picture |
| **AADRiskySignIns** | Table does NOT exist in Sentinel Data Lake | Use `AADUserRiskEvents` instead. For sign-in-level risk, use `SigninLogs` with `RiskLevelDuringSignIn` and `RiskState` columns |
| **OfficeActivity** | Mailbox forwarding/redirect rules live here, NOT in `AuditLogs` | Filter by `OfficeWorkload == "Exchange"` and `Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")`. Check `Parameters` for `ForwardTo`, `RedirectTo`. |
| **OfficeActivity** | `Parameters` and `OperationProperties` are string fields containing JSON | Use `contains` or `has` for keyword matching, then `parse_json(Parameters)` to extract values. Do NOT query `AuditLogs` for mailbox rule changes. |
| **DeviceTvmSoftwareVulnerabilities** | Advanced Hunting only — **no `Timestamp` column**. This is an inventory snapshot, NOT a time-series log. Queries with `where Timestamp > ago(1d)` fail with "Failed to resolve column." | Query without time filters — table always reflects current vulnerability state. Use `dcount(CveId)` for unique vulnerability counts. Columns: `DeviceId`, `DeviceName`, `OSPlatform`, `OSVersion`, `SoftwareVendor`, `SoftwareName`, `SoftwareVersion`, `CveId`, `VulnerabilitySeverityLevel`, `CveTags`. |
| **DeviceTvm\*** (all) | All `DeviceTvm*` tables are Advanced Hunting only inventory tables — most lack a `Timestamp` column. | Never add time filters unless schema confirms a timestamp column exists. Always verify schema with `FetchAdvancedHuntingTablesDetailedSchema` before first query. |
| **ExposureGraphNodes** | Advanced Hunting only — does NOT exist in Sentinel Data Lake. `NodeProperties` and `Categories` are raw JSON strings. No `Timestamp` column — point-in-time inventory. | Use `RunAdvancedHuntingQuery` without time filters. Use `parse_json(NodeProperties).rawData.<field>` to extract insights like internet exposure, RCE vulnerability, risk/exposure scores. Columns: `NodeId`, `NodeLabel`, `NodeName`, `Categories`, `NodeProperties`, `EntityIds`. |
| **ExposureGraphEdges** | Advanced Hunting only — does NOT exist in Sentinel Data Lake. `EdgeProperties`, `SourceNodeCategories`, `TargetNodeCategories` are raw JSON strings. No `Timestamp` column. | Use `RunAdvancedHuntingQuery` without time filters. Use `parse_json(EdgeProperties)` for relationship metadata. Columns: `EdgeId`, `EdgeLabel`, `SourceNodeId`, `SourceNodeName`, `SourceNodeLabel`, `SourceNodeCategories`, `TargetNodeId`, `TargetNodeName`, `TargetNodeLabel`, `TargetNodeCategories`, `EdgeProperties`. |
| **CloudAuditEvents** | Advanced Hunting only (Preview). Requires Defender for Cloud integration with Defender XDR. HAS `Timestamp` column. | ARM and KubeAudit control plane events. Filter by `Timestamp`. Key columns: `Timestamp`, `ActionType`, `AzureResourceId`, `AwsResourceName`, `GcpFullResourceName`. |
| **CloudProcessEvents** | Advanced Hunting only (Preview). Requires Defender for Containers. HAS `Timestamp` column. | Container process execution events in AKS/EKS/GKE. Key columns: `Timestamp`, `ContainerName`, `ContainerId`, `KubernetesNamespace`, `KubernetesPodName`, `ProcessCommandLine`, `FileName`, `AccountName`. |
| **CloudStorageAggregatedEvents** | Advanced Hunting only (Preview). Requires Defender for Storage. HAS `Timestamp` column. | Aggregated cloud storage activity. Key columns: `Timestamp`, `StorageAccount`, `StorageContainer`, `IpAddress`, `IsTorExitNode`, `IsKnownSuspiciousIp`, `AnonymousSuccessfulOperations`, `AuthenticationType`. |
| **CloudDnsEvents** | Advanced Hunting only (Preview). Requires Defender for Cloud. HAS `Timestamp` column. | DNS activity from cloud infrastructure. Key columns: `Timestamp`, `ActionType`, `AzureResourceId`, `DnsQuery`, `DnsQueryType`. |
| **CloudPolicyEnforcementEvents** | Advanced Hunting only (Preview). Requires Defender for Cloud. HAS `Timestamp` column. | Policy enforcement decisions and security gating events. Key columns: `Timestamp`, `ActionType`, `AzureResourceId`. |
| **AIAgentsInfo** | Advanced Hunting only (Preview). Requires Defender for Cloud Apps. HAS `Timestamp` column. Inventory-style — use `summarize arg_max(Timestamp, *) by AIAgentId` to get latest state per agent. | Copilot Studio AI agent inventory. Key columns: `Timestamp`, `AIAgentId`, `AIAgentName`, `AgentStatus`, `UserAuthenticationType`, `CreatorAccountUpn`, `AgentTopicsDetails`, `AgentToolsDetails`, `IsGenerativeOrchestrationEnabled`. Key security queries: find unauthenticated agents (`UserAuthenticationType == "None"`), agents with MCP tools, agents with generative orchestration + email-sending (XPIA risk). |
| **EntraIdSignInEvents** | Advanced Hunting only (GA). Replaces `AADSignInEventsBeta`. HAS `Timestamp` column. | GA Entra interactive and non-interactive sign-ins. Prefer over `AADSignInEventsBeta` for new queries. |
| **EntraIdSpnSignInEvents** | Advanced Hunting only (GA). Replaces `AADSpnSignInEventsBeta`. HAS `Timestamp` column. | GA Entra service principal and managed identity sign-ins. Prefer over `AADSpnSignInEventsBeta`. |
| **DisruptionAndResponseEvents** | Advanced Hunting only (Preview). HAS `Timestamp` column. | Automatic attack disruption events. Use for monitoring automated containment actions by Defender XDR. |
| **DeviceBaselineComplianceAssessment** | Advanced Hunting only (Preview). No `Timestamp` column — inventory snapshot. | Baseline compliance status per device. Query without time filters. |
| **DeviceBaselineComplianceProfiles** | Advanced Hunting only (Preview). No `Timestamp` column — inventory snapshot. | Baseline profiles for compliance monitoring. Query without time filters. |
| **DataSecurityBehaviors** | Advanced Hunting only (Preview). HAS `Timestamp` column. | Suspicious user behaviors violating Microsoft Purview policies. |
| **DataSecurityEvents** | Advanced Hunting only (Preview). HAS `Timestamp` column. | User activities violating Purview DLP/data classification policies. |
| **MessageEvents** | Advanced Hunting only. HAS `Timestamp` column. | Messages sent/received at delivery time (Teams). |
| **MessagePostDeliveryEvents** | Advanced Hunting only. HAS `Timestamp` column. | Post-delivery security events for Teams messages. |
| **OAuthAppInfo** | Advanced Hunting only (Preview). HAS `Timestamp` column. | OAuth apps from Defender for Cloud Apps app governance. |
| **FileMaliciousContentInfo** | Advanced Hunting only (Preview). HAS `Timestamp` column. | Malicious files detected in SharePoint, OneDrive, Teams by Defender for O365. |
| **IdentityEvents** | Advanced Hunting only (Preview). HAS `Timestamp` column. | Identity events from cloud identity providers beyond Entra. |

> **📖 Full table schemas** (columns, data types, NodeProperties/EdgeProperties key fields, common EdgeLabel values): See [`docs/XDR_TABLES_AND_APIS.md` § XDR Table Reference](../docs/XDR_TABLES_AND_APIS.md#4-xdr-table-reference).

### Best Practices for AuditLogs Queries

**CRITICAL: Use broad, simple filters for `OperationName` searches.**

❌ **DON'T** use overly specific filters:
```kql
| where OperationName has_any ("password", "reset")  // May miss operations
| where OperationName == "Reset user password"       // Too restrictive
```

✅ **DO** use broad keyword matching:
```kql
| where OperationName has "password"  // Catches all password-related operations
| where OperationName has "role"      // Catches all role-related operations
```

**Field Matching Best Practices:**
- Always use `tostring()` for dynamic fields: `tostring(InitiatedBy)`, `tostring(TargetResources)`
- Use `has` for substring matching: `tostring(InitiatedBy) has '<UPN>'`
- Use `=~` for exact case-insensitive match: `Identity =~ '<UPN>'`
- Avoid direct field access on complex JSON: Parse first with `parse_json()` then extract

### SecurityAlert → SecurityIncident Join Pattern

⚠️ **CRITICAL**: The `Status` field on `SecurityAlert` is set to `"New"` at creation and never changes.

To get the actual investigation status, MUST join with `SecurityIncident`:

```kql
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has '<ENTITY>'
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| summarize Title = any(Title), Severity = any(Severity), Status = any(Status),
    Classification = any(Classification), CreatedTime = any(CreatedTime)
    by ProviderIncidentId
| order by CreatedTime desc
```

| Field | Table | Notes |
|-------|-------|-------|
| `SecurityAlert.Status` | Alert table | Immutable creation status — always `"New"` |
| `SecurityIncident.Status` | Incident table | Real status — `New` / `Active` / `Closed` |
| `SecurityIncident.Classification` | Incident table | Closure reason — `TruePositive` / `FalsePositive` / `BenignPositive` |

---

## 🔴 EVIDENCE-BASED ANALYSIS — GLOBAL RULE

This rule applies to ALL skills, ALL queries, and ALL investigation outputs.

### Core Principle

Base ALL findings strictly on data returned by MCP tools. **Never invent, assume, or extrapolate data that was not explicitly retrieved.**

### Required Behaviors

| Scenario | Required Action |
|----------|----------------|
| Query returns 0 results | State explicitly: "✅ No [anomaly/alert/event type] found in [time range]" |
| Field is null/missing in response | Report as "Unknown" or "Not available" — never fabricate values |
| Partial data available | State what WAS found and what COULD NOT be verified |
| User asks about data not queried | Query first, then answer — never guess based on "typical patterns" |

### 🔴 PROHIBITED Actions

| Action | Status |
|--------|--------|
| Inventing IP addresses, usernames, or entity names | ❌ PROHIBITED |
| Assuming counts or statistics not in query results | ❌ PROHIBITED |
| Describing "typical behavior" when no baseline was queried | ❌ PROHIBITED |
| Omitting sections silently when no data exists | ❌ PROHIBITED |
| Using phrases like "likely", "probably", "typically" without evidence | ❌ PROHIBITED |

### ✅ REQUIRED Output Patterns

**When data IS found:**
```
📊 Found 47 failed sign-ins from IP 203.0.113.42 between 2026-01-15 and 2026-01-22.
Evidence: SigninLogs query returned 47 records with ResultType=50126.
```

**When NO data is found:**
```
✅ No failed sign-ins detected for user@domain.com in the last 7 days.
Query: SigninLogs | where UserPrincipalName =~ 'user@domain.com' | where ResultType != 0
Result: 0 records
```

**When data is PARTIAL:**
```
⚠️ Sign-in data available, but DeviceEvents table not accessible in this workspace.
Verified: 12 successful authentications from 3 IPs
Unable to verify: Endpoint process activity (table not found)
```

### Risk Assessment Grounding

When assigning risk levels, cite the specific evidence:

| Risk Level | Requirement |
|------------|-------------|
| **High** | Must cite ≥2 concrete findings (e.g., "AbuseIPDB score 95 + 47 failed logins in 1 hour") |
| **Medium** | Must cite ≥1 concrete finding with context (e.g., "New IP not in 90-day baseline") |
| **Low** | Must explain why low despite investigation (e.g., "IP is known corporate VPN egress") |
| **Informational** | Must still cite what was checked: "No alerts, no anomalies, no risky sign-ins found" |

### Emoji Formatting for Investigation Output

Use color-coded emojis consistently throughout investigation reports:

| Category | Emoji | When to Use |
|----------|-------|-------------|
| High risk / critical finding | 🔴 | High-severity alerts, confirmed compromise, high abuse scores |
| Medium risk / warning | 🟠 | Medium-severity detections, unresolved risk states, suspicious but unconfirmed |
| Low risk / minor concern | 🟡 | Low-severity detections, informational anomalies |
| Mitigating factor / positive | 🟢 | MFA enforced, phishing-resistant auth, clean threat intel |
| Informational / neutral | 🔵 | Contextual notes, baseline data, configuration details |
| Absence confirmed / clean | ✅ | No alerts found, no anomalies, verified safe |
| Needs attention / action item | ⚠️ | Unresolved risks, recommendations requiring human decision |
| Data not available | ❓ | Table not accessible, partial data, unable to verify |

### Explicit Absence Confirmation

After every investigation section, confirm what was checked even if nothing was found:

```
## Security Alerts
✅ No security alerts involving user@domain.com in the last 30 days.
- Checked: SecurityAlert table (0 matches)
- Checked: SecurityIncident for associated entities (0 matches)
```

---

## 🤖 AVAILABLE SKILLS

This system uses [VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills) to provide modular, domain-specific investigation workflows. Skills are automatically detected based on keywords in your prompts.

### Skills (11)

| Category | Skill | Description | Trigger Keywords |
|----------|-------|-------------|------------------|
| 🔍 Core Investigation | `incident-investigation` | Comprehensive incident analysis: 5-phase automated workflow, KQL queries, IP enrichment, SessionId auth tracing, JSON/HTML reporting | "investigate incident", "incident ID", "analyze incident", "triage incident" |
| 🔍 Core Investigation | `endpoint-device-investigation` | Defender for Endpoint device forensics: process execution, network connections, file ops, vulnerabilities, lateral movement | "investigate device", "investigate endpoint", "check machine", hostname |
| 🔍 Core Investigation | `ioc-management` | IOC lifecycle management: extraction, enrichment, deduplication, watchlists, SIEM/SOAR export | "IOC", "indicators of compromise", "watchlist", "threat intel feed" |
| 🔍 Core Investigation | `threat-enrichment` | Multi-source IP enrichment via AbuseIPDB, IPInfo, VPNapi, Shodan | "enrich IP", "check IP", "threat intel", "is this malicious" |
| 🔍 Core Investigation | `incident-correlation-analytics` | SOC reporting: campaign detection, heatmaps, MTTD/MTTA/MTTR metrics, top impacted users/devices, analyst workload, executive dashboards | "incident trends", "campaign detection", "SOC metrics", "heatmap", "MTTA", "top impacted", "analyst workload" |
| 📊 Posture & Exposure | `exposure-management` | CTEM metrics, CNAPP posture, attack surface inventory, vulnerability posture, choke points, attack paths, internet exposure, regulatory compliance, container security, CIEM entitlements, DSPM data security, DevSecOps posture, security recommendations, KPI dashboards | "exposure management", "CTEM", "attack surface", "choke points", "vulnerability posture", "exposure KPI", "CNAPP", "compliance posture", "container security", "CIEM", "permission sprawl", "DSPM", "data security posture", "DevSecOps", "security recommendations" |
| 🔐 Auth & Response | `defender-response` | Active response: device isolation, user compromise marking, AV scans, forensic packages, incident management | "isolate device", "block user", "containment", "response action" |
| 📊 Reporting | `report-generation` | HTML/JSON reports with dark theme, MITRE ATT&CK mapping, executive briefings | "generate report", "create report", "executive summary" |
| 🔧 Tooling | `kql-sentinel-queries` | Execute KQL against Sentinel data lake with pre-built queries for sign-ins, alerts, audit logs | "run KQL", "query Sentinel", "search logs" |
| 🔧 Tooling | `kql-query-builder` | AI-assisted KQL generation, validation, ASIM normalization, Sentinel Analytic Rule generation | "write KQL", "create KQL query", "help with KQL", "build query" |
| 📖 Reference | `microsoft-learn-docs` | Official Microsoft Learn documentation lookup for remediation guidance, code samples, KQL examples | "Microsoft docs", "how to remediate", "official guidance" |

### Skill Detection Workflow

1. Parse user request for trigger keywords from table above
2. If match found: Read the skill file at `.github/skills/<skill-name>/SKILL.md`
3. Follow skill-specific workflow (inherits global rules from this file)
4. Future skills: Check `.github/skills/` folder with `list_dir` to discover new workflows

### Triggering Skills with Natural Language

You don't need to mention the skill name — keywords are detected automatically:

| Prompt | Skill Invoked |
|--------|---------------|
| "Investigate incident 12345" | `incident-investigation` |
| "Is this IP malicious? 203.0.113.42" | `threat-enrichment` |
| "Check the device WORKSTATION-01 for threats" | `endpoint-device-investigation` |
| "Generate a report for this investigation" | `report-generation` |
| "Isolate the compromised device" | `defender-response` |
| "Write a KQL query to find failed sign-ins" | `kql-query-builder` |
| "Show me incident trends for the last month" | `incident-correlation-analytics` |
| "What's our exposure posture?" | `exposure-management` |
| "Show me CTEM metrics and choke points" | `exposure-management` |
| "What's our CNAPP posture?" | `exposure-management` |
| "Show me compliance posture" | `exposure-management` |
| "Container security status" | `exposure-management` |
| "Show me permission sprawl / CIEM" | `exposure-management` |
| "Data security posture" | `exposure-management` |
| "DevSecOps findings" | `exposure-management` |

### Follow-ups and Chaining

Skills can be chained for comprehensive analysis:

```
1. "Investigate incident 12345" → incident-investigation extracts entities
2. "Check that device for threats" → endpoint-device-investigation analyzes the host
3. "Is that IP malicious?" → threat-enrichment enriches the suspicious IP
4. "Generate a report" → report-generation creates HTML output
```

Copilot uses existing investigation data from `reports/investigation_*.json` when available.

---

## 🔌 INTEGRATION WITH MCP SERVERS

The investigation system integrates with these MCP servers (configured in `.vscode/mcp.json`):

### Microsoft Sentinel Data Lake MCP

- `mcp_data_explorat_query_lake`: Execute read-only KQL queries. Best practices: filter on datetime first, use `take` or `summarize` to limit results.
- `mcp_data_explorat_search_tables`: Discover table schemas using natural language queries.
- `mcp_data_explorat_list_sentinel_workspaces`: List all available workspace name/ID pairs.

### Microsoft Sentinel Triage MCP (Defender XDR)

- **Incident Management:** `ListIncidents`, `GetIncidentById`, `ListAlerts`, `GetAlertByID`
- **Advanced Hunting:** `RunAdvancedHuntingQuery`, `FetchAdvancedHuntingTablesOverview`, `FetchAdvancedHuntingTablesDetailedSchema`
- **Entity Investigation:** `GetDefenderMachine`, `GetDefenderMachineAlerts`, `GetDefenderFileInfo`, `GetDefenderIpAlerts`, `ListUserRelatedAlerts`, `ListUserRelatedMachines`
- **Vulnerability Management:** `ListDefenderMachinesByVulnerability`, `GetDefenderMachineVulnerabilities`
- **Remediation:** `ListDefenderRemediationActivities`, `GetDefenderRemediationActivity`

### Microsoft Graph MCP

- `microsoft_graph_suggest_queries`: Find Graph API endpoints (ALWAYS call first)
- `microsoft_graph_get`: Execute Graph API calls
- `microsoft_graph_list_properties`: Explore entity schemas

**Critical Workflow:** ALWAYS call `suggest_queries` before `get` — never construct URLs from memory.

### Microsoft Learn MCP

- `microsoft_docs_search`: Search official documentation (breadth)
- `microsoft_docs_fetch`: Fetch full documentation pages (depth)
- `microsoft_code_sample_search`: Find code samples (optional `language` filter: kusto, powershell, python, etc.)

### Sentinel Graph MCP

- Entity graph exploration and relationship queries
- Blast radius analysis and attack path visualization

### Azure MCP Server

- `monitor_workspace_log_query`: KQL against Log Analytics via ARM path
- `monitor_activitylog_list`: Azure Activity Logs
- `group_list`, `subscription_list`: Azure resource enumeration

### Security Copilot Agent Creation MCP

- Build custom Security Copilot agents with YAML definitions

### 🔴 MCP UNAVAILABILITY — DEFENDER API FALLBACK

When MCP servers are unavailable (auth failures, connectivity issues, generic invocation errors), **do NOT stop the investigation**. Fall back to the Defender Security APIs via Microsoft Graph or direct REST calls.

#### Fallback Decision Flow

```
MCP Tool Call Failed?
  ├─ Query-specific error (syntax, schema, table not found) → Fix query, retry
  └─ Generic/connectivity error on 2+ calls?
       ├─ Try alternative MCP server (see Tool Selection Rule Step 5)
       ├─ Use Microsoft Graph MCP (suggest_queries → get)
       └─ Use terminal (PowerShell/Python with az auth token)
```

#### API Surfaces — Two Endpoints

| Surface | Base URI | Status | Auth Resource |
|---------|----------|--------|---------------|
| **Microsoft Graph Security API** | `https://graph.microsoft.com/v1.0/security/` | ✅ Recommended | `https://graph.microsoft.com` |
| **Native Defender XDR API** | `https://api.security.microsoft.com/api/` | ⚠️ Retiring Feb 2027 | `https://api.security.microsoft.com` |

Regional endpoints (native API only): `api-us`, `api-eu`, `api-uk`, `api-au`, `api-scom` (`.security.microsoft.com`), `api-gcc` (`.security.microsoft.us`).

#### Defender XDR REST API Endpoints (Microsoft Graph v1.0)

All endpoints below are prefixed with `https://graph.microsoft.com/v1.0`.

**Advanced Hunting** — Query ANY XDR-native table via KQL (single most versatile fallback):

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/security/runHuntingQuery` | POST | Body: `{"Query": "<KQL>"}`. Rate: 45 req/min, 30-day data, 100K rows, 3-min timeout, 50 MB max. |

**Incidents & Alerts:**

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/security/incidents` | GET | List. Supports `$filter`, `$top`, `$orderby`, `$select`. |
| `/security/incidents/{id}` | GET/PATCH | Get or update incident. |
| `/security/alerts_v2` | GET | Unified alert format. OData filters. |
| `/security/alerts_v2/{id}` | GET/PATCH | Get or update alert. |

**Machines (Devices):**

| Endpoint | Method |
|----------|--------|
| `/security/microsoft/windowsDefenderATP/machines` | GET |
| `/security/microsoft/windowsDefenderATP/machines/{id}` | GET |
| `/security/microsoft/windowsDefenderATP/machines/{id}/alerts` | GET |
| `/security/microsoft/windowsDefenderATP/machines/{id}/vulnerabilities` | GET |
| `/security/microsoft/windowsDefenderATP/machines/{id}/logonusers` | GET |
| `/security/microsoft/windowsDefenderATP/machines/findbyip(ip='{ip}')` | GET |

**Response Actions:**

| Endpoint | Method | Action |
|----------|--------|--------|
| `/security/microsoft/windowsDefenderATP/machines/{id}/isolate` | POST | Isolate device |
| `/security/microsoft/windowsDefenderATP/machines/{id}/unisolate` | POST | Release isolation |
| `/security/microsoft/windowsDefenderATP/machines/{id}/runAntiVirusScan` | POST | AV scan |
| `/security/microsoft/windowsDefenderATP/machines/{id}/restrictCodeExecution` | POST | App restriction |
| `/security/microsoft/windowsDefenderATP/machines/{id}/collectInvestigationPackage` | POST | Forensic package |
| `/security/microsoft/windowsDefenderATP/machines/{id}/stopAndQuarantineFile` | POST | File quarantine |

**Files:**

| Endpoint | Method |
|----------|--------|
| `/security/microsoft/windowsDefenderATP/files/{sha1}` | GET |
| `/security/microsoft/windowsDefenderATP/files/{sha1}/stats` | GET |
| `/security/microsoft/windowsDefenderATP/files/{sha1}/alerts` | GET |
| `/security/microsoft/windowsDefenderATP/files/{sha1}/machines` | GET |

**IPs:**

| Endpoint | Method |
|----------|--------|
| `/security/microsoft/windowsDefenderATP/ips/{ip}/alerts` | GET |
| `/security/microsoft/windowsDefenderATP/ips/{ip}/stats` | GET |

**Users:**

| Endpoint | Method |
|----------|--------|
| `/security/microsoft/windowsDefenderATP/users/{id}/alerts` | GET |
| `/security/microsoft/windowsDefenderATP/users/{id}/machines` | GET |

**Threat Intelligence Indicators:**

| Endpoint | Method |
|----------|--------|
| `/security/tiIndicators` | GET/POST |
| `/security/tiIndicators/{id}` | PATCH/DELETE |

**Vulnerability Management:**

| Endpoint | Method |
|----------|--------|
| `/security/microsoft/windowsDefenderATP/recommendations` | GET |
| `/security/microsoft/windowsDefenderATP/software/{id}/vulnerabilities` | GET |
| `/security/microsoft/windowsDefenderATP/remediationTasks` | GET |
| `/security/microsoft/windowsDefenderATP/remediationTasks/{id}` | GET |

**Investigations:**

| Endpoint | Method |
|----------|--------|
| `/security/microsoft/windowsDefenderATP/investigations` | GET |
| `/security/microsoft/windowsDefenderATP/investigations/{id}` | GET |

**Streaming (Event Hub forwarding):**

| Endpoint | Method |
|----------|--------|
| `/security/microsoft/windowsDefenderATP/settings/eventHubs` | GET/POST |

#### Authentication for Terminal Fallback

> ⚠️ **Permission Prerequisite:** Direct API calls via `az rest` or `Invoke-RestMethod` require the calling app to have the necessary Microsoft Graph permissions (e.g., `ThreatHunting.Read.All` for Advanced Hunting). The Azure CLI's default app registration does NOT include security-specific scopes. If you get a **403 Forbidden** with "Missing application scopes", the permissions must be granted in Entra ID with admin consent. See `docs/XDR_TABLES_AND_APIS.md` Section 6 for setup instructions. MCP servers handle auth transparently via their own service principal.

```powershell
# Get bearer token for Microsoft Graph
$token = (az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)

# Use with Invoke-RestMethod
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
```

#### 🔴 REQUIRED Behaviors

| Scenario | Action |
|----------|--------|
| MCP tool fails with generic error | Retry once, then switch to API fallback |
| Graph MCP also unavailable | Use terminal with `az rest` or `Invoke-RestMethod` |
| API returns 403 (missing scopes) | Report: "⚠️ Missing Graph API permissions — `ThreatHunting.Read.All` (or relevant scope) must be granted to the calling app in Entra ID. See docs/XDR_TABLES_AND_APIS.md Section 6." |
| API returns auth error (401) | Report to user: "Authentication needed — run `az login`" |
| All paths exhausted | Report what was attempted and ask user to verify connectivity |

---

## 🔧 IP ENRICHMENT UTILITY

Use `enrichment/enrich_ips.py` to enrich IP addresses with multi-source threat intelligence:

```bash
# Enrich specific IPs
python enrichment/enrich_ips.py 203.0.113.42 198.51.100.10

# Enrich all unenriched IPs from an investigation file
python enrichment/enrich_ips.py --file reports/investigation_user_20260101.json
```

**Sources:** IPInfo.io (geolocation, ASN, VPN detection), VPNapi.io (VPN/proxy/Tor/relay), AbuseIPDB (abuse confidence scoring), Shodan (open ports, services, CVEs, tags).

**When to use:** Whenever the user asks to enrich, investigate, or check IPs — especially during ad-hoc investigations or follow-up analysis.

**When NOT to use:** When already executing a skill workflow (from `.github/skills/`) that has its own built-in IP enrichment step.

---

## 📂 QUERY LIBRARY

The `queries/` folder contains verified KQL query collections organized by data domain. These are the Priority 2 lookup source in the KQL Pre-Flight Checklist.

### Folder Structure

| Folder | Domain | Description |
|--------|--------|-------------|
| `queries/identity/` | Entra ID / Azure AD | Sign-ins, audit logs, identity compromise detection |
| `queries/endpoint/` | Defender for Endpoint | Device processes, network events, file operations |
| `queries/email/` | Defender for Office 365 | Email threats, phishing, attachment analysis |
| `queries/network/` | Network telemetry | Network anomalies, traffic analysis |
| `queries/cloud/` | Cloud apps & exposure | Cloud app activity, exposure management |
| `queries/soc-metrics/` | SOC operational metrics | MTTA, MTTR, incident breakdowns, top impacted users/devices, analyst workload |

### Standardized Metadata Header

All query files in `queries/` use this standardized metadata header for efficient `grep_search` discovery:

```markdown
# <Title>

**Created:** YYYY-MM-DD
**Platform:** Microsoft Sentinel | Microsoft Defender XDR | Both
**Tables:** <comma-separated list of exact KQL table names>
**Keywords:** <comma-separated searchable terms>
**MITRE:** <comma-separated technique IDs, e.g., T1021.001, TA0008>
**Timeframe:** Last N days (configurable)
```

### PII-Free Standard

All committed documents (query files, skill files, documentation) must NEVER contain tenant-specific PII such as real workspace names, UPNs, server hostnames, subscription/tenant GUIDs, or application names from live environments. Use generic placeholders (e.g., `<YourAppName>`, `user@contoso.com`, `<WorkspaceName>`).

---

## 📋 INVESTIGATION REPORT NAMING CONVENTION

All generated reports MUST follow this standardized naming convention:

| Type | Pattern | Example |
|------|---------|---------|
| Investigation Reports | `investigation_<upn_prefix>_YYYY-MM-DD.{json\|html}` | `investigation_jdoe_2026-01-12.json` |
| IP Enrichment Reports | `ip_enrichment_<count>_ips_YYYY-MM-DD.json` | `ip_enrichment_15_ips_2026-01-12.json` |
| Incident Reports | `incident_report_<id>_YYYY-MM-DD.html` | `incident_report_INC001234_2026-01-12.html` |
| Executive Reports | `executive_report_YYYY-MM-DD.html` | `executive_report_2026-01-12.html` |

**Rules:** Lowercase prefixes, underscores as separators, ISO 8601 dates, all saved to `reports/`.
