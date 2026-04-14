# Microsoft Defender XDR — Data Access Guide

A practical reference for extracting security telemetry from Microsoft Defender XDR. Covers table schemas, REST API endpoints, KQL query patterns, authentication models, and troubleshooting.

**Last Updated:** 2026-04-14

---

## 📑 TABLE OF CONTENTS

1. [Overview](#1-overview) — What data lives in Defender XDR and how to reach it
2. [Getting Started](#2-getting-started) — Prerequisites and authentication setup
3. [Data Access Methods](#3-data-access-methods) — MCP tools vs REST APIs vs KQL
4. [XDR Table Reference](#4-xdr-table-reference) — Table availability, schemas, and pitfalls
5. [REST API Endpoint Reference](#5-rest-api-endpoint-reference) — Complete endpoint catalog
6. [KQL Query Cookbook](#6-kql-query-cookbook) — Ready-to-use queries by use case
7. [MCP-to-API Fallback Reference](#7-mcp-to-api-fallback-reference) — When and how to switch
8. [Troubleshooting](#8-troubleshooting) — Common errors and fixes

---

## 1. Overview

Microsoft Defender XDR consolidates security telemetry from endpoints, identities, email, cloud apps, and exposure management into a unified data platform. This data is accessible through three primary interfaces:

| Interface | Best For | Data Retention |
|-----------|----------|----------------|
| **MCP Tools** (via VS Code Copilot) | Day-to-day investigation workflows | Depends on backend (30d AH / 90d+ Sentinel) |
| **REST APIs** (Microsoft Graph) | Automation, scripting, fallback when MCP unavailable | Depends on endpoint |
| **KQL Advanced Hunting** (via MCP or API) | Ad-hoc threat hunting, complex joins, custom analytics | 30 days |

### Where Does the Data Live?

Not all XDR data is available in both Advanced Hunting (AH) and Sentinel Data Lake. Understanding table availability is critical to choosing the right tool.

| Data Category | Advanced Hunting | Sentinel Data Lake | Notes |
|---------------|:----------------:|:------------------:|-------|
| Exposure Management (`ExposureGraph*`) | ✅ | ❌ | Inventory snapshots, no timestamp |
| Threat & Vuln Management (`DeviceTvm*`) | ✅ | ❌ | Inventory snapshots, most lack timestamp |
| Device telemetry (`Device*` non-Tvm) | ✅ | ✅ | Different timestamp columns |
| Alerts, Email, Identity, Cloud | ✅ | ✅ | Different timestamp columns |
| Sentinel-native (SigninLogs, AuditLogs, SecurityAlert) | ❌ | ✅ | Sentinel Data Lake only |
| XDR Beta tables (`AAD*Beta`, `EntraId*`) | ✅ | ❌ | AH only |
| AI agent security (`AIAgentsInfo`) | ✅ | ❌ | AH only (Preview) |

### XDR-Only Table Families

These tables exist **only** in Advanced Hunting and return "table not found" in Sentinel:

| Table Family | Tables | Notes |
|-------------|--------|-------|
| **Exposure Management** | `ExposureGraphNodes`, `ExposureGraphEdges` | Attack path / exposure graph. No `Timestamp` — inventory snapshot. |
| **Threat & Vulnerability Mgmt** | `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareInventory`, `DeviceTvmSecureConfigurationAssessment`, `DeviceTvmSecureConfigurationAssessmentKB`, `DeviceTvmSoftwareEvidenceBeta`, `DeviceTvmSoftwareVulnerabilitiesKB`, `DeviceTvmInfoGathering`, `DeviceTvmInfoGatheringKB`, `DeviceTvmBrowserExtensions`, `DeviceTvmCertificateInfo`, `DeviceTvmHardwareFirmware` | Inventory tables — most lack `Timestamp`. |
| **Entra ID (Beta)** | `AADSignInEventsBeta`, `AADSpnSignInEventsBeta` | Beta sign-in tables — being replaced by GA `EntraId*` tables. |
| **Entra ID (GA)** | `EntraIdSignInEvents`, `EntraIdSpnSignInEvents` | GA replacement for `AAD*Beta` tables. |
| **AI Agent Security** | `AIAgentsInfo` | Copilot Studio agent inventory, configuration, and security posture (Preview). |
| **Campaign & Messaging** | `CampaignInfo`, `MessageEvents`, `MessagePostDeliveryEvents`, `MessageUrlInfo` | Email/Teams campaign and message tracking. |
| **Data Security** | `DataSecurityBehaviors`, `DataSecurityEvents` | Microsoft Purview DLP and data classification (Preview). |
| **Disruption** | `DisruptionAndResponseEvents` | Automatic attack disruption events (Preview). |
| **Graph API Audit** | `GraphApiAuditEvents` | Microsoft Graph API activity in tenant. |
| **OAuth** | `OAuthAppInfo` | OAuth app governance from Defender for Cloud Apps (Preview). |
| **Identity (Preview)** | `IdentityEvents` | Identity events from cloud identity providers (Preview). |
| **Device Baseline** | `DeviceBaselineComplianceAssessment`, `DeviceBaselineComplianceAssessmentKB`, `DeviceBaselineComplianceProfiles` | Device security baseline compliance snapshots (Preview). |
| **Defender for Cloud** | `CloudAuditEvents`, `CloudProcessEvents`, `CloudStorageAggregatedEvents`, `CloudDnsEvents`, `CloudPolicyEnforcementEvents` | Cloud control plane, container, storage, DNS, and policy events (Preview). |
| **File Security** | `FileMaliciousContentInfo` | Malicious files in SharePoint/OneDrive/Teams (Preview). |

### Dual-Availability Tables (Timestamp Differences)

When a table exists in both AH and Sentinel, the timestamp column name differs:

| Table Family | AH Column | Sentinel Column | Retention |
|-------------|-----------|-----------------|-----------|
| `Device*` (non-Tvm) | `Timestamp` | `TimeGenerated` | 30d AH / 90d+ Sentinel |
| `Alert*` | `Timestamp` | `TimeGenerated` | 30d AH / 90d+ Sentinel |
| `Email*` | `Timestamp` | `TimeGenerated` | 30d AH / 90d+ Sentinel |
| `Identity*` | `Timestamp` | `TimeGenerated` | 30d AH / 90d+ Sentinel |
| `Cloud*` | `Timestamp` | `TimeGenerated` | 30d AH / 90d+ Sentinel |
| `Behavior*` | `Timestamp` | `TimeGenerated` | 30d AH / 90d+ Sentinel |
| `Url*` | `Timestamp` | `TimeGenerated` | 30d AH / 90d+ Sentinel |

---

## 2. Getting Started

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **VS Code + GitHub Copilot** | For MCP-based queries (primary access method) |
| **MCP Servers configured** | See `.vscode/mcp.json` — Triage, Data Lake, Defender Response |
| **Azure CLI** (`az`) | For direct API fallback — `az login` with authenticated session |
| **Python 3.10+** | For enrichment scripts (`enrichment/enrich_ips.py`) |

### Authentication

Defender XDR data is protected by Microsoft Entra ID (Azure AD). There are two distinct authentication paths:

#### Path 1: MCP Tools (Primary — No Setup Required)

MCP servers authenticate using **their own Entra ID service principal** with pre-configured security permissions. Your personal account does **not** need any special scopes.

```
VS Code Copilot → MCP Server → Service Principal (has ThreatHunting.Read.All) → Graph API
```

#### Path 2: Direct REST API (Fallback — Requires Permission Setup)

When MCP is unavailable, you can call the APIs directly. The calling app registration must have the required permissions granted with admin consent.

**Quick token acquisition:**

```powershell
# Get bearer token for Microsoft Graph
$token = (az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)

# Use with Invoke-RestMethod
$headers = @{
    Authorization  = "Bearer $token"
    'Content-Type' = 'application/json'
}
```

**Required application permissions:**

| API Scope | Permission | Type | Admin Consent |
|-----------|-----------|------|---------------|
| Advanced Hunting | `ThreatHunting.Read.All` | Application | ✅ Required |
| Incidents | `SecurityIncident.ReadWrite.All` | Application | ✅ Required |
| Alerts | `SecurityAlert.ReadWrite.All` | Application | ✅ Required |
| Machines | `Machine.Read.All` | Application | ✅ Required |
| Machine Actions | `Machine.Isolate`, `Machine.Scan` | Application | ✅ Required |
| Vulnerabilities | `Vulnerability.Read.All` | Application | ✅ Required |
| TI Indicators | `ThreatIndicators.ReadWrite.OwnedBy` | Application | ✅ Required |

> ⚠️ **The Azure CLI's default app registration (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) does NOT include security-specific scopes.** Calls to `/security/runHuntingQuery` will return **403 Forbidden** unless permissions are explicitly granted. See [Troubleshooting](#9-troubleshooting) for setup instructions.

#### Authentication Model Comparison

| Aspect | MCP Path | Direct API Path |
|--------|----------|-----------------|
| Auth setup required | None (MCP handles it) | App permissions + admin consent |
| Token acquisition | Transparent (MCP service principal) | `az account get-access-token --resource https://graph.microsoft.com` |
| Typical failure mode | MCP connectivity/invocation errors | 401 (expired token) or 403 (missing scopes) |
| Security scopes | Pre-configured on MCP service principal | Must be explicitly granted to calling app |
| Best for | Day-to-day investigations | Fallback when MCP unavailable, automation scripts |

---

## 3. Data Access Methods

### Method 1: MCP Tools (Recommended)

MCP (Model Context Protocol) servers expose Defender XDR capabilities as tool calls within VS Code Copilot. This is the simplest and most efficient way to query XDR data.

| MCP Server | Key Tools | Data Source |
|------------|-----------|-------------|
| **Triage MCP** | `RunAdvancedHuntingQuery`, `ListIncidents`, `GetDefenderMachine`, `ListAlerts` | Advanced Hunting, Defender XDR |
| **Data Lake MCP** | `query_lake`, `search_tables`, `list_sentinel_workspaces` | Sentinel Data Lake (Log Analytics) |
| **Defender Response MCP** | Device isolation, AV scan, investigation packages | Defender for Endpoint actions |

**When to use which:**

| Need | MCP Server | Tool |
|------|------------|------|
| Query XDR-only tables (ExposureGraph, DeviceTvm) | Triage | `RunAdvancedHuntingQuery` |
| Query Sentinel tables (SigninLogs, AuditLogs) | Data Lake | `query_lake` |
| List/get incidents and alerts | Triage | `ListIncidents`, `GetIncidentById` |
| Device forensics | Triage | `GetDefenderMachine`, `GetDefenderMachineAlerts` |
| Containment actions | Defender Response | Device isolation, AV scan |

### Method 2: REST APIs (Fallback)

When MCP is unavailable, call the Microsoft Graph Security API directly. See [Section 5](#5-rest-api-endpoint-reference) for the full endpoint catalog.

**Example — Advanced Hunting via REST:**

```powershell
$token = (az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
$body = @{ Query = 'DeviceTvmSoftwareVulnerabilities | summarize dcount(CveId) by DeviceName | top 5 by dcount_CveId desc' } | ConvertTo-Json

Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
  -Method POST `
  -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
  -Body $body
```

**Example — List Recent Incidents:**

```powershell
$token = (az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)

Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/security/incidents?$top=10&$orderby=createdDateTime desc' `
  -Method GET `
  -Headers @{ Authorization = "Bearer $token" }
```

### Method 3: KQL via Advanced Hunting

KQL (Kusto Query Language) is the query language used across both MCP and REST APIs. Whether you submit a query through the MCP `RunAdvancedHuntingQuery` tool or POST it to the `/security/runHuntingQuery` API endpoint, the KQL syntax is identical.

**Advanced Hunting quotas and limits:**

| Property | Value |
|----------|-------|
| Rate limit | 45 requests/minute |
| Data retention | 30 days |
| Max result rows | 100,000 |
| Timeout | 3 minutes |
| Max result size | 50 MB |

---

## 4. XDR Table Reference

### 4.1 Exposure Management Tables

#### ExposureGraphNodes

Entities (devices, identities, cloud resources) in the Microsoft Security Exposure Management graph.

**Availability:** Advanced Hunting only | **Timestamp:** None (inventory snapshot)

| Column | Type | Description |
|--------|------|-------------|
| `NodeId` | string | Unique identifier for the node |
| `NodeLabel` | string | Resource type (e.g., `microsoft.compute/virtualmachines`, `subscriptions`) |
| `NodeName` | string | Human-readable name |
| `Categories` | dynamic (JSON) | Classification tags: `compute`, `device`, `environmentAzure`, `virtual_machine`, etc. |
| `NodeProperties` | dynamic (JSON) | Rich metadata — see property reference below |
| `EntityIds` | dynamic (JSON) | Cross-reference identifiers |

**NodeProperties — Key Fields** (extract with `parse_json(NodeProperties).rawData.<field>`):

| Property | Description | Example Values |
|----------|-------------|----------------|
| `deviceName` | Device hostname | `server-01` |
| `deviceType` | Device classification | `Server`, `Workstation` |
| `osPlatform` | Operating system | `Linux`, `Windows` |
| `osDistribution` | OS distribution | `SLES`, `Ubuntu` |
| `osVersion` | OS version | `15.7` |
| `riskScore` | Defender risk score | `High`, `Medium`, `Low` |
| `exposureScore` | Exposure score | `Medium`, `High` |
| `isCustomerFacing` | Internet-exposed? | `true` / `false` |
| `onboardingStatus` | MDE onboarding | `Onboarded`, `NotOnboarded` |
| `sensorHealthState` | Sensor status | `Active`, `Inactive` |
| `publicIP` | Public IP address | IP address string |
| `lastSeen` | Last activity | ISO 8601 datetime |
| `highRiskVulnerabilityInsights` | Vulnerability summary object | Contains `maxCvssScore`, `hasHighOrCritical`, `vulnerableToRemoteCodeExecution`, `vulnerableToPrivilegeEscalation` |
| `criticalityLevel` | Asset criticality | Object with `criticalityLevel` (int), `ruleNames` array |
| `tags` | Custom tags | System details, custom labels |

#### ExposureGraphEdges

Relationships (attack paths, permissions, dependencies) between entities.

**Availability:** Advanced Hunting only | **Timestamp:** None (inventory snapshot)

| Column | Type | Description |
|--------|------|-------------|
| `EdgeId` | string | Unique edge identifier |
| `EdgeLabel` | string | Relationship type |
| `SourceNodeId` | string | Source entity ID |
| `SourceNodeName` | string | Source entity name |
| `SourceNodeLabel` | string | Source entity type |
| `SourceNodeCategories` | dynamic (JSON) | Source classification tags |
| `TargetNodeId` | string | Target entity ID |
| `TargetNodeName` | string | Target entity name |
| `TargetNodeLabel` | string | Target entity type |
| `TargetNodeCategories` | dynamic (JSON) | Target classification tags |
| `EdgeProperties` | dynamic (JSON) | Relationship metadata |

**Common EdgeLabel values:**

| EdgeLabel | Meaning | Typical Volume |
|-----------|---------|----------------|
| `has permissions to` | Identity/resource has permissions on target | Very high |
| `affecting` | Vulnerability affecting the target | High |
| `runs on` | Software/service runs on compute resource | Low |
| `routes traffic to` | Network path to target | Low |
| `can authenticate as` | Authentication relationship | Medium |
| `contains` | Resource containment | Medium |

### 4.2 Threat & Vulnerability Management Tables

#### DeviceTvmSoftwareVulnerabilities

> ⚠️ **No `Timestamp` column.** `DeviceTvm*` tables are inventory snapshots, not time-series logs. Queries with `where Timestamp > ago(1d)` will fail with: `Failed to resolve column or scalar expression named 'Timestamp'`. Always query without time filters.

**Availability:** Advanced Hunting only | **Timestamp:** None (inventory snapshot)

| Column | Type | Description |
|--------|------|-------------|
| `DeviceId` | string | Unique device identifier |
| `DeviceName` | string | FQDN of the device |
| `OSPlatform` | string | Operating system (e.g., `Windows11`, `Linux`) |
| `OSVersion` | string | OS version number |
| `OSArchitecture` | string | Architecture (`x64`, `ARM64`) |
| `SoftwareVendor` | string | Software publisher |
| `SoftwareName` | string | Software product name |
| `SoftwareVersion` | string | Software version |
| `CveId` | string | CVE identifier |
| `VulnerabilitySeverityLevel` | string | `Critical`, `High`, `Medium`, `Low` |
| `RecommendedSecurityUpdate` | string | Patch description |
| `RecommendedSecurityUpdateId` | string | KB article or update ID |
| `CveTags` | dynamic | Tags: `ZeroDay`, `NoSecurityUpdate` |

### 4.3 Defender for Cloud Advanced Hunting Tables

These Preview tables require Defender for Cloud integration with Defender XDR. Unlike ExposureGraph/DeviceTvm tables, these DO have a `Timestamp` column.

#### CloudAuditEvents (Preview)

ARM and KubeAudit control plane events. Requires Defender for Cloud.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Event timestamp |
| `ActionType` | string | Control plane action type |
| `AzureResourceId` | string | Azure resource identifier |
| `AwsResourceName` | string | AWS resource ARN (if applicable) |
| `GcpFullResourceName` | string | GCP resource name (if applicable) |
| `AdditionalFields` | dynamic | Additional event metadata |

#### CloudProcessEvents (Preview)

Container process execution events in AKS/EKS/GKE. Requires Defender for Containers.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Event timestamp |
| `AzureResourceId` | string | Azure resource identifier |
| `AwsResourceName` | string | AWS resource ARN (if applicable) |
| `GcpFullResourceName` | string | GCP resource name (if applicable) |
| `ContainerImageName` | string | Container image name/ID |
| `ContainerName` | string | Container name |
| `ContainerId` | string | Container identifier |
| `KubernetesNamespace` | string | K8s namespace |
| `KubernetesPodName` | string | K8s pod name |
| `KubernetesResource` | string | K8s resource (namespace/type/name) |
| `FileName` | string | File name of executed process |
| `FolderPath` | string | Folder path of executed process |
| `ProcessId` | long | Process ID |
| `ProcessName` | string | Process name |
| `ParentProcessName` | string | Parent process name |
| `ProcessCommandLine` | string | Full command line |
| `AccountName` | string | User executing the process |

#### CloudStorageAggregatedEvents (Preview)

Aggregated cloud storage activity. Requires Defender for Storage.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Record generation time |
| `StorageAccount` | string | Storage account name |
| `StorageContainer` | string | Blob container name |
| `StorageFileShare` | string | File share name |
| `ServiceType` | string | Blob, ADLS Gen2, Files.REST, Files.SMB |
| `IpAddress` | string | Accessing IP address |
| `IsTorExitNode` | bool | IP is a Tor exit node |
| `IsKnownSuspiciousIp` | bool | IP is known suspicious |
| `IsPrivateIp` | bool | IP is private range |
| `AuthenticationType` | string | AccountKey, SAS, OAuth |
| `OperationsCount` | int | Total operations |
| `AnonymousSuccessfulOperations` | int | Successful anonymous operations |
| `CountryName` | string | Access source country |
| `SubscriptionId` | string | Azure subscription |
| `ResourceGroup` | string | Resource group |

#### CloudDnsEvents (Preview)

DNS activity events from cloud infrastructure environments. Requires Defender for Cloud.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Event timestamp |
| `ActionType` | string | DNS action type |
| `AzureResourceId` | string | Azure resource identifier |
| `AwsResourceName` | string | AWS resource ARN (if applicable) |
| `GcpFullResourceName` | string | GCP resource name (if applicable) |
| `DnsQuery` | string | DNS query name |
| `DnsQueryType` | string | DNS record type (A, AAAA, CNAME, etc.) |
| `AdditionalFields` | dynamic | Additional event metadata |

#### CloudPolicyEnforcementEvents (Preview)

Policy enforcement evaluation decisions and metadata of security gating events. Requires Defender for Cloud.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Event timestamp |
| `ActionType` | string | Policy enforcement action type |
| `AzureResourceId` | string | Azure resource identifier |
| `AwsResourceName` | string | AWS resource ARN (if applicable) |
| `GcpFullResourceName` | string | GCP resource name (if applicable) |
| `AdditionalFields` | dynamic | Additional event metadata |

### 4.4 AI Agent Security Tables

#### AIAgentsInfo (Preview)

Inventory of AI agents created with Microsoft Copilot Studio, including agent configuration, ownership, authentication, tools, and knowledge sources. Critical for discovering shadow AI agents and auditing agent security posture.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | Last date and time recorded for the agent info |
| `AIAgentId` | guid | Unique identifier for the agent (Copilot Studio) |
| `AIAgentName` | string | Display name of the agent |
| `AgentCreationTime` | datetime | Date and time when the agent was created |
| `CreatorAccountUpn` | string | UPN of the account that created the agent |
| `OwnerAccountUpns` | string | UPNs of all the owners of the agent |
| `LastModifiedByUpn` | string | UPN of the account that last modified the agent |
| `LastModifiedTime` | datetime | Date and time when the agent was last modified |
| `LastPublishedTime` | datetime | Date and time when the agent was last published |
| `LastPublishedByUpn` | string | UPN of the account that last published the agent |
| `AgentDescription` | string | Description of the agent |
| `AgentStatus` | string | `Created`, `Published`, `Deleted` |
| `UserAuthenticationType` | string | `None`, `Microsoft`, `Custom` |
| `AgentUsers` | string | UPNs or group IDs that can use the agent |
| `KnowledgeDetails` | string | Knowledge sources added to the agent |
| `AgentActionTriggers` | string | Triggers that make an autonomous agent take action |
| `RawAgentInfo` | string | Raw JSON with full agent configuration |
| `AuthenticationTrigger` | string | `As Needed`, `Always` |
| `AccessControlPolicy` | string | `Any`, `Copilot readers`, `Group membership`, `Any (multitenant)` |
| `AuthorizedSecurityGroupIds` | dynamic | Entra group IDs allowed to interact with the agent |
| `AgentTopicsDetails` | dynamic | Topics the agent can perform |
| `AgentToolsDetails` | dynamic | Tools the agent can access |
| `EnvironmentId` | string | Power Platform environment ID |
| `Platform` | string | Platform source (e.g., `Copilot Studio`) |
| `IsGenerativeOrchestrationEnabled` | boolean | Whether the agent uses generative orchestration |
| `AgentAppId` | string | Entra app registration ID for the agent |
| `ConnectedAgentsSchemaNames` | dynamic | Schema names of connected agents for orchestration |
| `ChildAgentsSchemaNames` | dynamic | Schema names of child agents |

**Key Security Queries:**

```kql
// Find agents with NO authentication (publicly accessible)
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where UserAuthenticationType == "None"
| project-reorder AgentCreationTime, AIAgentId, AIAgentName, AgentStatus, CreatorAccountUpn, OwnerAccountUpns
```

```kql
// Find agents with MCP tools configured
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| mvexpand Action = AgentToolsDetails
| where Action.action.operationDetails["$kind"] == "ModelContextProtocolMetadata"
| extend MCPName = Action.action.operationDetails["operationId"]
| summarize MCPTools = make_set(MCPName) by AIAgentName, AIAgentId, EnvironmentId, CreatorAccountUpn
```

```kql
// Find agents using generative orchestration with email-sending capability (XPIA risk)
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| extend IsGenAIOrchestrator = tostring(todynamic(RawAgentInfo).Bot.Attributes.configuration) has '"GenerativeActionsEnabled": true'
| where IsGenAIOrchestrator
| mvexpand Action = AgentToolsDetails
| extend OperationId = tostring(Action.action.operationId), ActionName = tostring(Action.modelDisplayName)
| where OperationId == "SendEmailV2"
| where isempty(Action.inputs)
| project-reorder AgentCreationTime, AIAgentId, AIAgentName, AgentStatus, CreatorAccountUpn, OwnerAccountUpns, ActionName
```

### 4.5 Entra ID GA Tables

#### EntraIdSignInEvents

GA replacement for `AADSignInEventsBeta`. Interactive and non-interactive sign-in events from Microsoft Entra ID.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

> ⚠️ This is the GA version of `AADSignInEventsBeta`. If you are querying sign-ins via Advanced Hunting, prefer this table over the Beta version.

#### EntraIdSpnSignInEvents

GA replacement for `AADSpnSignInEventsBeta`. Service principal and managed identity sign-in events.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

> ⚠️ This is the GA version of `AADSpnSignInEventsBeta`. Prefer this table for service principal sign-in queries via Advanced Hunting.

### 4.6 Attack Disruption & Response Tables

#### DisruptionAndResponseEvents (Preview)

Automatic attack disruption events from Microsoft Defender XDR. Captures automated containment actions taken by the platform.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

### 4.7 Data Security Tables (Microsoft Purview)

#### DataSecurityBehaviors (Preview)

Insights about potentially suspicious user behaviors that violate policies in Microsoft Purview.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

#### DataSecurityEvents (Preview)

User activities that violate user-defined or default policies in Microsoft Purview.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

### 4.8 Device Baseline Compliance Tables

#### DeviceBaselineComplianceAssessment (Preview)

Baseline compliance assessment snapshot — status of security configurations against baseline profiles on devices.

**Availability:** Advanced Hunting only | **Timestamp:** None (inventory snapshot)

#### DeviceBaselineComplianceAssessmentKB (Preview)

Knowledge base of security configurations used by baseline compliance to assess devices.

**Availability:** Advanced Hunting only | **Timestamp:** None (inventory snapshot)

#### DeviceBaselineComplianceProfiles (Preview)

Baseline profiles used for monitoring device baseline compliance.

**Availability:** Advanced Hunting only | **Timestamp:** None (inventory snapshot)

### 4.9 Messaging & Collaboration Tables

#### MessageEvents

Messages sent and received within your organization at the time of delivery (Teams).

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

#### MessagePostDeliveryEvents

Security events that occurred after the delivery of a Microsoft Teams message.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

#### MessageUrlInfo

URLs sent through Microsoft Teams messages.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

### 4.10 Other New Tables

#### OAuthAppInfo (Preview)

Microsoft 365-connected OAuth applications registered with Microsoft Entra ID, from Defender for Cloud Apps app governance.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

#### FileMaliciousContentInfo (Preview)

Files processed by Microsoft Defender for Office 365 in SharePoint Online, OneDrive, and Microsoft Teams.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

#### IdentityEvents (Preview)

Identity events from cloud identity service providers.

**Availability:** Advanced Hunting only | **Timestamp:** `Timestamp` (datetime)

### 4.11 Azure Resource Graph — securityresources Types

These resource types are queried via Azure Resource Graph (`az graph query`), NOT via Advanced Hunting or Sentinel Data Lake.

| Resource Type | Description | Key Properties |
|---------------|-------------|---------------|
| `microsoft.security/regulatorycompliancestandards` | Compliance standard state per subscription | `state`, `passedControls`, `failedControls`, `skippedControls` |
| `microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments` | Individual compliance assessment state | `description`, `state`, `passedResources`, `failedResources` |
| `microsoft.security/assessments` | Security recommendations | `displayName`, `status.code`, `metadata.severity`, `metadata.categories`, `resourceDetails.Source` |
| `microsoft.security/assessments/subassessments` | Sub-assessments (e.g., container image CVEs) | `id`, `status.code`, `additionalData.vulnerabilityDetails.severity` |
| `microsoft.security/assessments/governanceassignments` | Governance rule assignments | `assignedResourceId`, `remediationDueDate` |
| `microsoft.security/attackpaths` | Attack path definitions | `displayName`, `riskLevel`, `entryPoint`, `target`, `riskFactors`, `graphComponent` |

**Container Image Vulnerability Assessment Keys:**

| Scanner | Assessment Key | Status |
|---------|---------------|--------|
| MDVM (Defender Vulnerability Management) | `c0b7cfc6-3172-465a-b378-53c7ff2cc0d5` | Current |
| Qualys (legacy) | `dbd0cb49-b563-45e7-9724-889e799fa648` | Deprecated |

---

## 5. REST API Endpoint Reference

All endpoints below use the **Microsoft Graph Security API** (recommended). All paths are relative to `https://graph.microsoft.com/v1.0`.

### API Surfaces

| Surface | Base URI | Status | Auth Resource |
|---------|----------|--------|---------------|
| **Microsoft Graph Security API** | `https://graph.microsoft.com/v1.0/security/` | ✅ Recommended | `https://graph.microsoft.com` |
| **Native Defender XDR API** | `https://api.security.microsoft.com/api/` | ⚠️ Retiring Feb 2027 | `https://api.security.microsoft.com` |

**Regional endpoints (native API only):** `api-us`, `api-eu`, `api-uk`, `api-au`, `api-scom` (`.security.microsoft.com`), `api-gcc` (`.security.microsoft.us`).

### Advanced Hunting

The single most versatile endpoint — query ANY Advanced Hunting table via KQL.

| Property | Value |
|----------|-------|
| **Graph endpoint** | `POST /security/runHuntingQuery` |
| **Native endpoint** | `POST https://api.security.microsoft.com/api/advancedhunting/run` |
| **Request body** | `{"Query": "<KQL_QUERY_STRING>"}` |

### Incidents & Alerts

| Capability | Endpoint | Method | Notes |
|------------|----------|--------|-------|
| List incidents | `/security/incidents` | GET | OData: `$filter`, `$top`, `$orderby`, `$select` |
| Get incident | `/security/incidents/{id}` | GET | |
| Update incident | `/security/incidents/{id}` | PATCH | |
| List alerts | `/security/alerts_v2` | GET | OData filters |
| Get alert | `/security/alerts_v2/{id}` | GET | |
| Update alert | `/security/alerts_v2/{id}` | PATCH | |

### Machines (Devices)

| Capability | Endpoint | Method |
|------------|----------|--------|
| List machines | `/security/microsoft/windowsDefenderATP/machines` | GET |
| Get machine | `/security/microsoft/windowsDefenderATP/machines/{id}` | GET |
| Machine alerts | `/security/microsoft/windowsDefenderATP/machines/{id}/alerts` | GET |
| Machine vulnerabilities | `/security/microsoft/windowsDefenderATP/machines/{id}/vulnerabilities` | GET |
| Logged-on users | `/security/microsoft/windowsDefenderATP/machines/{id}/logonusers` | GET |
| Find by IP | `/security/microsoft/windowsDefenderATP/machines/findbyip(ip='{ip}')` | GET |

### Response Actions

| Action | Endpoint | Method |
|--------|----------|--------|
| Isolate device | `/security/microsoft/windowsDefenderATP/machines/{id}/isolate` | POST |
| Release isolation | `/security/microsoft/windowsDefenderATP/machines/{id}/unisolate` | POST |
| Run AV scan | `/security/microsoft/windowsDefenderATP/machines/{id}/runAntiVirusScan` | POST |
| Restrict code execution | `/security/microsoft/windowsDefenderATP/machines/{id}/restrictCodeExecution` | POST |
| Collect investigation package | `/security/microsoft/windowsDefenderATP/machines/{id}/collectInvestigationPackage` | POST |
| Stop & quarantine file | `/security/microsoft/windowsDefenderATP/machines/{id}/stopAndQuarantineFile` | POST |

### Files & IPs

| Capability | Endpoint | Method |
|------------|----------|--------|
| File info | `/security/microsoft/windowsDefenderATP/files/{sha1}` | GET |
| File stats | `/security/microsoft/windowsDefenderATP/files/{sha1}/stats` | GET |
| File alerts | `/security/microsoft/windowsDefenderATP/files/{sha1}/alerts` | GET |
| File machines | `/security/microsoft/windowsDefenderATP/files/{sha1}/machines` | GET |
| IP alerts | `/security/microsoft/windowsDefenderATP/ips/{ip}/alerts` | GET |
| IP stats | `/security/microsoft/windowsDefenderATP/ips/{ip}/stats` | GET |

### Users

| Capability | Endpoint | Method |
|------------|----------|--------|
| User alerts | `/security/microsoft/windowsDefenderATP/users/{id}/alerts` | GET |
| User machines | `/security/microsoft/windowsDefenderATP/users/{id}/machines` | GET |

### Threat Intelligence Indicators

| Capability | Endpoint | Method |
|------------|----------|--------|
| List indicators | `/security/tiIndicators` | GET |
| Create indicator | `/security/tiIndicators` | POST |
| Update indicator | `/security/tiIndicators/{id}` | PATCH |
| Delete indicator | `/security/tiIndicators/{id}` | DELETE |

### Vulnerability Management

| Capability | Endpoint | Method |
|------------|----------|--------|
| Security recommendations | `/security/microsoft/windowsDefenderATP/recommendations` | GET |
| Software vulnerabilities | `/security/microsoft/windowsDefenderATP/software/{id}/vulnerabilities` | GET |
| Remediation tasks | `/security/microsoft/windowsDefenderATP/remediationTasks` | GET |
| Remediation task detail | `/security/microsoft/windowsDefenderATP/remediationTasks/{id}` | GET |

### Investigations & Streaming

| Capability | Endpoint | Method |
|------------|----------|--------|
| List investigations | `/security/microsoft/windowsDefenderATP/investigations` | GET |
| Get investigation | `/security/microsoft/windowsDefenderATP/investigations/{id}` | GET |
| List event hub forwarding | `/security/microsoft/windowsDefenderATP/settings/eventHubs` | GET |
| Create event hub forwarding | `/security/microsoft/windowsDefenderATP/settings/eventHubs` | POST |

---

## 6. KQL Query Cookbook

Ready-to-use KQL queries for common XDR investigations. All queries run via Advanced Hunting (`RunAdvancedHuntingQuery` MCP tool or `POST /security/runHuntingQuery`).

### Vulnerability Assessment

#### Top 10 Most Vulnerable Machines (Weighted Score)

```kql
DeviceTvmSoftwareVulnerabilities
| summarize 
    TotalVulns = dcount(CveId),
    CriticalVulns = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
    HighVulns = dcountif(CveId, VulnerabilitySeverityLevel == "High")
    by DeviceId, DeviceName, OSPlatform
| extend WeightedScore = (CriticalVulns * 4) + (HighVulns * 2) + TotalVulns
| top 10 by WeightedScore desc
| project DeviceName, OSPlatform, TotalVulns, CriticalVulns, HighVulns, WeightedScore
```

> No time filter needed — `DeviceTvmSoftwareVulnerabilities` is an inventory snapshot without `Timestamp`.

### Exposure Management

#### Discover Node Types in Exposure Graph

```kql
ExposureGraphNodes
| summarize Count = count() by NodeLabel
| order by Count desc
```

#### Internet-Exposed Assets

```kql
ExposureGraphNodes
| where parse_json(NodeProperties).rawData.isCustomerFacing == true
| project NodeName, NodeLabel,
    RiskScore = tostring(parse_json(NodeProperties).rawData.riskScore),
    PublicIP = tostring(parse_json(NodeProperties).rawData.publicIP),
    OS = tostring(parse_json(NodeProperties).rawData.osPlatform)
| order by RiskScore desc
```

#### Assets Vulnerable to Remote Code Execution

```kql
ExposureGraphNodes
| where parse_json(NodeProperties).rawData.highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution.hasHighOrCritical == true
| project NodeName, NodeLabel,
    MaxCVSS = tostring(parse_json(NodeProperties).rawData.highRiskVulnerabilityInsights.vulnerableToRemoteCodeExecution.maxCvssScore),
    RiskScore = tostring(parse_json(NodeProperties).rawData.riskScore)
| order by MaxCVSS desc
```

#### Attack Path Relationships by Type

```kql
ExposureGraphEdges
| summarize EdgeCount = count() by EdgeLabel
| order by EdgeCount desc
```

### Attack Path & Choke Point Analysis

#### Top Choke Points by Incoming Attack Path Edges

A **choke point** is a node at the intersection of multiple attack paths. Remediating it blocks the maximum number of paths simultaneously.

```kql
ExposureGraphEdges
| summarize IncomingPaths = count() by TargetNodeId, TargetNodeName, TargetNodeLabel
| top 10 by IncomingPaths desc
| project TargetNodeName, TargetNodeLabel, IncomingPaths
```

#### Choke Point Detail — Edge Type Breakdown

```kql
ExposureGraphEdges
| where TargetNodeName == "<NODE_NAME>"
| summarize PathCount = count() by EdgeLabel
| top 10 by PathCount desc
```

#### Choke Point Node Properties

```kql
ExposureGraphNodes
| where NodeName == "<NODE_NAME>"
| project NodeName, NodeLabel, Categories, NodeProperties
```

#### VMs as Choke Points

```kql
ExposureGraphEdges
| where TargetNodeLabel == "microsoft.compute/virtualmachines"
| summarize IncomingPaths = count() by TargetNodeName
| top 10 by IncomingPaths desc
```

#### Cross-Reference: Choke Points × Vulnerability Count

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

#### Node + Edge Join: Full Attack Path Context

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

---

## 7. MCP-to-API Fallback Reference

When MCP tools are unavailable (generic invocation errors on 2+ consecutive calls), use these direct API equivalents.

### Fallback Priority

1. **Try alternative MCP server** (e.g., Azure MCP `monitor_workspace_log_query` for Sentinel-native tables)
2. **Use Microsoft Graph MCP** (`microsoft_graph_suggest_queries` → `microsoft_graph_get`)
3. **Use terminal** (`Invoke-RestMethod` / `az rest` with bearer token from [Section 2](#2-getting-started))

### MCP Tool → API Mapping

| MCP Tool | Graph API Endpoint | Method | Notes |
|----------|-------------------|--------|-------|
| `RunAdvancedHuntingQuery` | `/security/runHuntingQuery` | POST | Body: `{"Query": "<KQL>"}` |
| `ListIncidents` | `/security/incidents?$top=50&$orderby=createdDateTime desc` | GET | OData filters |
| `GetIncidentById` | `/security/incidents/{id}` | GET | |
| `ListAlerts` | `/security/alerts_v2` | GET | OData filters |
| `GetAlertByID` | `/security/alerts_v2/{id}` | GET | |
| `GetDefenderMachine` | `/security/microsoft/windowsDefenderATP/machines/{id}` | GET | |
| `GetDefenderMachineAlerts` | `/security/microsoft/windowsDefenderATP/machines/{id}/alerts` | GET | |
| `GetDefenderMachineVulnerabilities` | `/security/microsoft/windowsDefenderATP/machines/{id}/vulnerabilities` | GET | |
| `GetDefenderIpAlerts` | `/security/microsoft/windowsDefenderATP/ips/{ip}/alerts` | GET | |
| `GetDefenderIpStatistics` | `/security/microsoft/windowsDefenderATP/ips/{ip}/stats` | GET | |
| `ListUserRelatedAlerts` | `/security/microsoft/windowsDefenderATP/users/{id}/alerts` | GET | |
| `ListUserRelatedMachines` | `/security/microsoft/windowsDefenderATP/users/{id}/machines` | GET | |
| `GetDefenderFileInfo` | `/security/microsoft/windowsDefenderATP/files/{sha1}` | GET | |
| `GetDefenderFileAlerts` | `/security/microsoft/windowsDefenderATP/files/{sha1}/alerts` | GET | |
| `GetDefenderFileRelatedMachines` | `/security/microsoft/windowsDefenderATP/files/{sha1}/machines` | GET | |
| `GetDefenderFileStatistics` | `/security/microsoft/windowsDefenderATP/files/{sha1}/stats` | GET | |
| `FindDefenderMachinesByIp` | `/security/microsoft/windowsDefenderATP/machines/findbyip(ip='{ip}')` | GET | |
| `GetDefenderInvestigation` | `/security/microsoft/windowsDefenderATP/investigations/{id}` | GET | |
| `ListDefenderInvestigations` | `/security/microsoft/windowsDefenderATP/investigations` | GET | |
| `ListDefenderIndicators` | `/security/tiIndicators` | GET | |
| `ListDefenderRemediationActivities` | `/security/microsoft/windowsDefenderATP/remediationTasks` | GET | |
| `GetDefenderRemediationActivity` | `/security/microsoft/windowsDefenderATP/remediationTasks/{id}` | GET | |
| `query_lake` | Azure MCP `monitor_workspace_log_query` or `az rest` against Log Analytics ARM API | — | Different auth resource |
| `list_sentinel_workspaces` | Azure MCP `subscription_list` + Resource Graph query | — | ARM enumeration |

---

## 8. Troubleshooting

### Common Errors

#### "Failed to resolve column or scalar expression named 'Timestamp'"

**Cause:** Querying a `DeviceTvm*` or `ExposureGraph*` table with a time filter. These are inventory snapshots — they have no `Timestamp` column.

**Fix:** Remove time filters. These tables always reflect current state.

```kql
// ❌ Wrong — will fail
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)

// ✅ Correct — no time filter
DeviceTvmSoftwareVulnerabilities
| summarize dcount(CveId) by DeviceName
| top 10 by dcount_CveId desc
```

#### 403 Forbidden — "Missing application scopes"

**Cause:** Direct API calls via `az rest` or `Invoke-RestMethod` require the calling app to have specific Microsoft Graph permissions. The Azure CLI's default app registration does **not** include security-specific scopes.

**Error example:**
```json
{
  "error": {
    "code": "UnauthorizedAccessForApplication",
    "message": "Missing application scopes. API required one of the following scopes: ThreatHunting.Read.All."
  }
}
```

**Fix options:**

| Option | Steps | Security |
|--------|-------|----------|
| **A: Custom app registration** (Recommended) | 1. Create app registration in Entra ID<br>2. Add required Graph API permissions<br>3. Grant admin consent<br>4. Create client secret/certificate<br>5. Use app credentials for auth | ✅ Principle of least privilege |
| **B: Grant scopes to Azure CLI app** (Simpler) | 1. Find Azure CLI in Enterprise applications (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`)<br>2. Grant required permissions<br>3. Admin consent | ⚠️ Broader access — all CLI users get the scopes |

> This error does NOT affect MCP-based queries. MCP servers use their own service principal with pre-configured permissions. See [Section 2](#2-getting-started) for the authentication model comparison.

#### 401 Unauthorized — Expired Token

**Cause:** Azure CLI token has expired (tokens last ~1 hour).

**Fix:** Re-authenticate:
```powershell
az login
```

#### "Table not found" or "Could not resolve table"

**Cause:** Querying a table in the wrong data source.

| If querying via... | And the table is... | Fix |
|--------------------|---------------------|-----|
| Data Lake (`query_lake`) | XDR-only (ExposureGraph*, DeviceTvm*) | Switch to Advanced Hunting |
| Advanced Hunting | Sentinel-only (SigninLogs, AuditLogs) | Switch to Data Lake |

See the [table availability matrix](#table-availability) in Section 1 for the full classification.

#### MCP Tool Generic Invocation Error

**Cause:** MCP server connectivity or authentication issue (not a query-specific error).

**Detection:** If 2+ consecutive MCP calls fail with generic errors (including a minimal test like `DeviceInfo | take 1`), classify as "MCP unavailable."

**Fix:** Follow the [fallback priority](#7-mcp-to-api-fallback-reference) in Section 7:
1. Try alternative MCP server
2. Use Microsoft Graph MCP (`suggest_queries` → `get`)
3. Use terminal with `az rest` or `Invoke-RestMethod`

---

## References

- [Microsoft Defender XDR API — Supported APIs](https://learn.microsoft.com/defender-xdr/api-supported)
- [Defender for Endpoint API — Exposed APIs List](https://learn.microsoft.com/defender-endpoint/api/exposed-apis-list)
- [Graph Security API Overview](https://learn.microsoft.com/graph/api/resources/security-api-overview)
- [Advanced Hunting API](https://learn.microsoft.com/defender-xdr/api-advanced-hunting)
- [Exposure Management — ExposureGraphNodes](https://learn.microsoft.com/defender-xdr/advanced-hunting-exposuregraphnodes-table)
- [Exposure Management — ExposureGraphEdges](https://learn.microsoft.com/defender-xdr/advanced-hunting-exposuregraphedges-table)
