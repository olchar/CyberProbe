---
name: kql-sentinel-queries
description: Execute KQL queries on Microsoft Sentinel data lake for security investigations. Use when searching security events, alerts, sign-ins, audit logs, or threat intelligence. Includes pre-built queries for common investigation scenarios and data exploration capabilities.
---

# KQL Sentinel Queries Skill

This skill enables execution of Kusto Query Language (KQL) queries against Microsoft Sentinel data lake for security investigations and threat hunting.

## When to Use This Skill

Use this skill when:
- Investigating security incidents or alerts
- Searching sign-in logs for authentication analysis
- Querying audit logs for configuration changes
- Threat hunting across security data
- Analyzing user activity patterns
- Discovering available data tables and schemas
- Building custom security analytics

## Prerequisites

1. **Sentinel Workspace**: Read `sentinel_workspace_id` from `enrichment/config.json`
2. **Tenant ID**: Read `tenant_id` from `enrichment/config.json`
3. **MCP Tools**: `mcp_data_explorat_query_lake` and `mcp_data_explorat_search_tables` available
4. **Permissions**: Read access to Sentinel workspace

## Core Workflow

### Step 1: Discover Tables
Before querying, discover relevant tables using semantic search:

```
mcp_data_explorat_search_tables(
  query="sign-in authentication logs",
  workspaceId="00000000-0000-0000-0000-000000000000"
)
```

**Returns:** Schema definitions for `SigninLogs`, `AADNonInteractiveUserSignInLogs`, etc.

### Step 2: Build Query
Construct KQL query with proper filters:

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "user@contoso.com"
| project TimeGenerated, IPAddress, AppDisplayName, ResultType, RiskLevel
| take 100
```

### Step 3: Execute Query
```
mcp_data_explorat_query_lake(
  query="[KQL query string]",
  workspaceId="00000000-0000-0000-0000-000000000000"
)
```

### Fallback: Sentinel Data Lake KQL REST API

If the Data Lake MCP (`query_lake`) is unavailable, use the native Sentinel Data Lake KQL REST API directly. This is the preferred fallback for Sentinel-native tables.

**Endpoint:** `POST https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query`
**Auth scope:** `4500ebfb-89b6-4b14-a480-7f749797bfcd/.default`

```powershell
# Acquire token for Data Lake API
$token = (az account get-access-token --resource 4500ebfb-89b6-4b14-a480-7f749797bfcd --query accessToken -o tsv)

# Read workspace name and ID from enrichment/config.json
$body = @{
    csl = 'SigninLogs | where TimeGenerated > ago(7d) | where UserPrincipalName =~ "user@contoso.com" | take 100'
    db  = '<WorkspaceName>-<WorkspaceId>'
} | ConvertTo-Json

Invoke-RestMethod -Uri 'https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query' `
  -Method POST -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
  -Body $body
```

**Key notes:**
- The `db` value is `WorkspaceName-WorkspaceId` (find both on the Azure portal workspace overview)
- Requires Azure RBAC: Log Analytics Reader or Contributor on the workspace
- Entra ID roles and XDR unified RBAC are NOT supported for service principal auth
- Query must be a single line in the JSON payload

> **📘 Reference:** [Run KQL queries on the Microsoft Sentinel data lake using APIs](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-queries-api)

## Date Range Best Practices

⚠️ **CRITICAL**: Always filter on `TimeGenerated` column first for performance.

### Real-Time Investigations
Add +2 days buffer to current date:
```kql
| where TimeGenerated between (datetime(2026-01-08) .. datetime(2026-01-17))
```

**Example**: Today is Jan 15, user requests "last 7 days"
- Start: Jan 8 (15 - 7)
- End: Jan 17 (15 + 2)

### Historical Investigations
Add +1 day buffer to user's end date:
```kql
| where TimeGenerated between (datetime(2026-01-01) .. datetime(2026-01-06))
```

**Example**: User requests "Jan 1 to Jan 5"
- Start: Jan 1 (as requested)
- End: Jan 6 (5 + 1)

### Relative Time Ranges
Use `ago()` function for recent data:
```kql
| where TimeGenerated > ago(1h)   // Last hour
| where TimeGenerated > ago(1d)   // Last day
| where TimeGenerated > ago(7d)   // Last week
| where TimeGenerated > ago(30d)  // Last month
```

## Query Performance Rules

### Rule 1: Filter Early
❌ **Bad:**
```kql
SigninLogs
| project TimeGenerated, UserPrincipalName, IPAddress
| where UserPrincipalName == "user@contoso.com"
| where TimeGenerated > ago(7d)
```

✅ **Good:**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "user@contoso.com"
| project TimeGenerated, IPAddress, AppDisplayName
```

### Rule 2: Use `take` Operator
Always limit results to prevent large datasets:
```kql
| take 100  // For exploratory queries
| take 1000 // For comprehensive analysis
```

### Rule 3: Use `has` for Word Search
For substring matching, use `has` instead of `contains`:
```kql
| where AppDisplayName has "Office"  // Faster
| where AppDisplayName contains "Office"  // Slower
```

### Rule 4: Project Only Needed Columns
Reduce data transfer by selecting specific columns:
```kql
| project TimeGenerated, IPAddress, Location
```

## Pre-Built Investigation Queries

All queries are documented in [Investigation-Guide.md Section 8](../../../Investigation-Guide.md#8-sample-kql-queries). Below are the most commonly used:

### Query 1: Priority IP Extraction
**Purpose**: Extract top 15 priority IPs from anomalies, risky sign-ins, and frequent authentications

```kql
let UserId = "<USER_OBJECT_ID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
let anomalousIPs = (
    BehaviorAnalytics
    | where TimeGenerated between (startDate .. endDate)
    | where UsersInsights has UserId
    | extend IPAddresses = extractall(@'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', dynamic([1]), SourceIPAddress)
    | mvexpand IP = IPAddresses to typeof(string)
    | where isnotempty(IP)
    | distinct IP
);
let riskyIPs = (
    SigninLogs
    | where TimeGenerated between (startDate .. endDate)
    | where UserId == UserId
    | where RiskLevelDuringSignIn in ("high", "medium")
    | distinct IPAddress
);
let frequentIPs = (
    SigninLogs
    | where TimeGenerated between (startDate .. endDate)
    | where UserId == UserId
    | summarize Count = count() by IPAddress
    | top 10 by Count desc
    | distinct IPAddress
);
union anomalousIPs, riskyIPs, frequentIPs
| distinct IP
| take 15
```

**Usage**: Run this first in Phase 2 to identify which IPs need enrichment.

### Query 2: Anomaly Detection
**Purpose**: Get all anomalies from BehaviorAnalytics for a user

```kql
let UserId = "<USER_OBJECT_ID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
BehaviorAnalytics
| where TimeGenerated between (startDate .. endDate)
| where UsersInsights has UserId
| project TimeGenerated, ActivityType, SourceIPAddress, SourceDevice, InvestigationPriority, ActionType
| order by TimeGenerated desc
```

**Returns**: Anomalous activities with investigation priority scores.

### Query 3: Sign-Ins by Application
**Purpose**: Summarize sign-ins grouped by application

```kql
let UserId = "<USER_OBJECT_ID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
SigninLogs
| where TimeGenerated between (startDate .. endDate)
| where UserId == UserId
| summarize SignInCount = count() by AppDisplayName
| order by SignInCount desc
```

### Query 3b: Sign-Ins by Location
**Purpose**: Identify all geographic locations

```kql
let UserId = "<USER_OBJECT_ID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
SigninLogs
| where TimeGenerated between (startDate .. endDate)
| where UserId == UserId
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count() by City, Country, IPAddress
| order by SignInCount desc
```

### Query 3c: Sign-In Failures
**Purpose**: Analyze failed authentication attempts

```kql
let UserId = "<USER_OBJECT_ID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
SigninLogs
| where TimeGenerated between (startDate .. endDate)
| where UserId == UserId
| where ResultType != "0"  // Non-zero = failure
| summarize FailureCount = count() by ResultType, ResultDescription, IPAddress
| order by FailureCount desc
```

### Query 3d: Authentication Details per IP
**Purpose**: Get detailed sign-in data for specific IPs (used after IP extraction)

```kql
let UserId = "<USER_OBJECT_ID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
let priorityIPs = dynamic(["206.168.34.210", "45.155.205.233"]);
SigninLogs
| where TimeGenerated between (startDate .. endDate)
| where UserId == UserId
| where IPAddress in (priorityIPs)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, IPAddress, City, Country, AppDisplayName, DeviceDetail.operatingSystem, 
          AuthenticationDetails, ConditionalAccessStatus, RiskLevelDuringSignIn, SessionId
| order by TimeGenerated desc
```

**Critical Fields:**
- `SessionId`: Used for authentication chain tracing
- `AuthenticationDetails`: Shows MFA methods
- `ConditionalAccessStatus`: Policy evaluation results

### Query 4: Azure AD Audit Logs
**Purpose**: Track administrative actions and configuration changes

```kql
let UserId = "<USER_OBJECT_ID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
AuditLogs
| where TimeGenerated between (startDate .. endDate)
| where TargetResources has UserId or InitiatedBy has UserId
| project TimeGenerated, OperationName, Result, TargetResources, InitiatedBy, Category
| order by TimeGenerated desc
```

**Common Operations:**
- "Update user"
- "Add member to role"
- "Reset password"
- "Update application"

### Query 5: Office 365 Activity
**Purpose**: User activity in O365 services (SharePoint, Exchange, Teams)

```kql
let UPN = "user@contoso.com";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
OfficeActivity
| where TimeGenerated between (startDate .. endDate)
| where UserId == UPN
| summarize OperationCount = count() by Operation, OfficeWorkload
| order by OperationCount desc
```

### Query 6: Security Incidents
**Purpose**: Incidents involving specific user (requires User ID + Windows SID)

```kql
let UserId = "<USER_OBJECT_ID>";
let SID = "<WINDOWS_SID>";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
SecurityIncident
| where TimeGenerated between (startDate .. endDate)
| where AdditionalData has UserId or AdditionalData has SID
| project TimeGenerated, IncidentName, Severity, Status, Description, IncidentNumber
| order by TimeGenerated desc
```

**Note**: Use `mcp_triage_ListIncidents` for better incident querying.

### Query 10: DLP Events
**Purpose**: Data Loss Prevention policy violations

```kql
let UPN = "user@contoso.com";
let startDate = datetime(2026-01-08);
let endDate = datetime(2026-01-17);
DLPEvents
| where TimeGenerated between (startDate .. endDate)
| where UserId == UPN
| project TimeGenerated, DLPPolicyName, Severity, FileName, FileExtension, FileSize
| order by TimeGenerated desc
```

### Query 11: Threat Intelligence
**Purpose**: Correlate IPs with known threat indicators

```kql
let priorityIPs = dynamic(["206.168.34.210", "45.155.205.233"]);
ThreatIntelligenceIndicator
| where NetworkIP in (priorityIPs) or NetworkSourceIP in (priorityIPs)
| project TimeGenerated, NetworkIP, ThreatType, ConfidenceScore, Description, ThreatSeverity
| order by TimeGenerated desc
```

## Policy Change Detection

### Endpoint Protection Policy Changes
```kql
let startDate = datetime(2026-01-15T00:00:00);
let endDate = datetime(2026-01-15T23:59:59);
AuditLogs
| where TimeGenerated between (startDate .. endDate)
| where Category == "Policy"
| where OperationName has_any ("Update policy", "Create policy", "Delete policy")
| where TargetResources has "Endpoint" or TargetResources has "Intune"
| project TimeGenerated, OperationName, Result, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName, AdditionalDetails
| order by TimeGenerated desc
```

**Returns**: 0 results if no policy changes occurred (valid result).

### Conditional Access Policy Changes
```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has "Conditional Access policy"
| project TimeGenerated, OperationName, InitiatedBy.user.userPrincipalName, 
          TargetResources[0].displayName, Result
```

## Data Discovery

### Find All Available Tables
```
mcp_data_explorat_search_tables(
  query="all security tables",
  workspaceId="00000000-0000-0000-0000-000000000000"
)
```

### Explore Table Schema
```kql
SigninLogs
| getschema
```

**Returns**: Column names and data types.

### Sample Table Data
```kql
SigninLogs
| take 10
```

## Advanced Techniques

### SessionId-Based Authentication Tracing
Extract complete authentication chain:

```kql
let suspiciousSessionId = "aaaabbbb-cccc-dddd-eeee-ffffgggghhh";
SigninLogs
| where SessionId == suspiciousSessionId
| project TimeGenerated, IPAddress, Location.city, Location.countryOrRegion, 
          AuthenticationDetails, AppDisplayName
| order by TimeGenerated asc
```

**Workflow:**
1. Find suspicious sign-in with unusual location
2. Extract SessionId from that sign-in
3. Query all sign-ins with same SessionId
4. First event with MFA = true authentication location
5. Subsequent events = token forwarding (not new authentications)

See [Investigation-Guide.md Section 9](../../../Investigation-Guide.md#9-advanced-authentication-analysis) for full workflow.

### Join Multiple Tables
Correlate sign-ins with incidents:

```kql
let UserId = "<USER_OBJECT_ID>";
SigninLogs
| where TimeGenerated > ago(7d)
| where UserId == UserId
| join kind=inner (
    SecurityIncident
    | where TimeGenerated > ago(7d)
    | where AdditionalData has UserId
  ) on $left.TimeGenerated == $right.TimeGenerated
| project TimeGenerated, IPAddress, IncidentName, Severity
```

### Time-Series Analysis
Detect authentication spikes:

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| summarize SignInCount = count() by bin(TimeGenerated, 1h)
| render timechart
```

## Error Handling

| Error | Cause | Solution |
|-------|-------|----------|
| Query timeout | Too much data | Reduce date range, add `\| take 100` |
| Table not found | Table name typo | Use `mcp_data_explorat_search_tables` |
| Column not exists | Schema mismatch | Run `\| getschema` to verify columns |
| Empty result | Valid empty dataset | Return empty array `[]`, not an error |
| Rate limit | Too many queries | Wait 1 minute, batch queries |

## Example Investigation Scenarios

### Scenario 1: User Compromise Investigation
```
User: "Investigate user@contoso.com - possible account takeover"

Workflow:
1. Search tables: mcp_data_explorat_search_tables("sign-in authentication")
2. Get User ID: mcp_microsoft_graph_get("/v1.0/users/user@contoso.com")
3. Run Query 1: Extract priority IPs
4. Run Query 2: Get anomalies
5. Run Query 3c: Check sign-in failures
6. Run Query 6: Find related incidents
7. Export results to JSON
```

### Scenario 2: Geographic Anomaly Analysis
```
User: "User logged in from US then China 5 minutes later"

Workflow:
1. Run Query 3b: Get all sign-in locations
2. Filter for suspicious time window
3. Extract SessionIds from both sign-ins
4. Run SessionId trace for each
5. Identify true authentication location (first MFA event)
6. Assess if token forwarding or actual compromise
```

### Scenario 3: Policy Change Audit
```
User: "What policies changed this morning?"

Workflow:
1. Set date range: current_date 00:00:00 to 23:59:59
2. Run policy change query (AuditLogs + Category == "Policy")
3. If 0 results: Valid, report "No policy changes"
4. If results: Extract OperationName, InitiatedBy, TargetResources
5. Generate summary report
```

## Resources

- [Investigation-Guide.md Section 8](../../../Investigation-Guide.md#8-sample-kql-queries) - Complete query library
- [Investigation-Guide.md Section 9](../../../Investigation-Guide.md#9-advanced-authentication-analysis) - SessionId tracing
- [KQL Quick Reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference)
- [Sentinel Tables Schema](https://learn.microsoft.com/azure/sentinel/data-source-schema-reference)

## Important Notes

⚠️ **Always filter on TimeGenerated first** - critical for performance
⚠️ **Use `take` operator** - prevent overwhelming result sets
⚠️ **Check Investigation-Guide.md first** - pre-built queries available
⚠️ **Empty results are valid** - export `[]` instead of erroring
⚠️ **Add +2 days buffer** for real-time investigations to catch delayed ingestion
⚠️ **SessionId tracing** - most powerful technique for geographic anomaly resolution
