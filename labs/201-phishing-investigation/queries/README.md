# Phishing Investigation - KQL Query Library

This folder contains all KQL queries used in Lab 201. Copy these queries and modify parameters as needed.

---

## Query 1: Email Campaign Scope

**Purpose**: Identify all recipients of the phishing email

**Table**: EmailEvents

```kql
// Get all emails from malicious sender
EmailEvents
| where TimeGenerated > ago(7d)
| where SenderFromAddress =~ "security-noreply@micros0ft-verify.com"
| project 
    TimeGenerated,
    NetworkMessageId,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DeliveryAction,
    DeliveryLocation
| order by TimeGenerated asc
```

**Expected Output**: 47 records (all recipients)

---

## Query 2: Malicious URL Extraction

**Purpose**: Get phishing URL details and track which emails contained it

**Tables**: EmailUrlInfo + EmailEvents (joined)

```kql
// Extract malicious URLs from phishing emails
EmailUrlInfo
| where TimeGenerated > ago(7d)
| where Url has "login-microsoftonline.verify-account"
| join kind=inner (
    EmailEvents
    | where SenderFromAddress =~ "security-noreply@micros0ft-verify.com"
    | project NetworkMessageId, RecipientEmailAddress, Subject
) on NetworkMessageId
| project 
    TimeGenerated,
    Url,
    UrlLocation,
    RecipientEmailAddress,
    ThreatTypes
| order by TimeGenerated asc
```

---

## Query 3: SafeLinks Click Tracking

**Purpose**: Identify users who clicked the malicious link

**Table**: CloudAppEvents

```kql
// Track SafeLinks click-through events
CloudAppEvents
| where TimeGenerated > ago(7d)
| where Application == "Microsoft Defender for Office 365"
| where ActionType == "UrlClickedThrough"
| extend ClickedUrl = tostring(RawEventData.Url)
| where ClickedUrl has "login-microsoftonline.verify-account"
| extend UserUPN = tostring(RawEventData.UserId)
| extend ClickTime = TimeGenerated
| project ClickTime, UserUPN, ClickedUrl, IPAddress
| order by ClickTime asc
```

**Expected Output**: 3 users (violetm, u3498, u11317)

---

## Query 4: Post-Click Sign-in Activity

**Purpose**: Analyze sign-ins after phishing click to detect compromise

**Tables**: SigninLogs + AADNonInteractiveUserSignInLogs (union)

**⚠️ Replace variables before running!**

```kql
// Analyze sign-ins for a specific user after click
let clickTime = datetime(2026-01-15 08:47:22);  // REPLACE with actual click time
let userUPN = "violetm@contoso.com";  // REPLACE with target user

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((clickTime - 5m) .. (clickTime + 2h))
| where UserPrincipalName =~ userUPN
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| project 
    TimeGenerated,
    IPAddress,
    City,
    Country,
    AppDisplayName,
    ResultType,
    ResultDescription,
    AuthenticationRequirement
| order by TimeGenerated asc
```

**Look for**: Impossible travel, unfamiliar locations, MFA bypass

---

## Query 5: SessionId Extraction

**Purpose**: Get SessionId from suspicious IP for forensic tracing

**Tables**: SigninLogs + AADNonInteractiveUserSignInLogs

```kql
// Extract SessionId from Nigerian IP
let suspiciousIP = "41.58.XXX.XXX";  // REPLACE with actual attacker IP
let userUPN = "violetm@contoso.com";  // REPLACE

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 12:00))
| where UserPrincipalName =~ userUPN
| where IPAddress == suspiciousIP
| where isnotempty(SessionId)
| distinct SessionId
| take 1
```

**Output**: Single SessionId string

---

## Query 6: SessionId Authentication Chain

**Purpose**: Trace complete authentication timeline for a session

**Reference**: Investigation Guide Section 9 - Advanced Authentication Analysis

```kql
// Trace all authentication events in a session
let targetSessionId = "66f78a3c-e4d2-4b91-9f5e-2a1b8c7d9e6f";  // REPLACE from Query 5

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 12:00))
| where SessionId == targetSessionId
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| project 
    TimeGenerated,
    IPAddress,
    City,
    Country,
    AppDisplayName,
    ResultType,
    AuthenticationRequirement
| order by TimeGenerated asc
```

**Analysis**: First event = initial authentication (attacker). Subsequent = token refreshes.

---

## Query 7: Malicious Inbox Rules

**Purpose**: Detect forwarding rules created by attacker

**Table**: CloudAppEvents

```kql
// Find inbox rule creation events
let userObjectId = "<USER_OBJECT_ID>";  // REPLACE with Graph API result

CloudAppEvents
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 23:59))
| where AccountObjectId == userObjectId
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleName = tostring(RawEventData.Parameters.Name)
| extend ForwardTo = tostring(RawEventData.Parameters.ForwardTo)
| project TimeGenerated, ActionType, RuleName, ForwardTo, IPAddress
```

**Red Flag**: External email address in ForwardTo field

---

## Query 8: File Access & Downloads

**Purpose**: Track file access during attacker session

**Table**: CloudAppEvents

```kql
// Analyze file access patterns
let userObjectId = "<USER_OBJECT_ID>";  // REPLACE

CloudAppEvents
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 23:59))
| where AccountObjectId == userObjectId
| where ActionType in ("FileDownloaded", "FileAccessed", "FileModified")
| extend FileName = tostring(RawEventData.ObjectId)
| extend FileSize = tolong(RawEventData.ObjectSize)
| summarize 
    FileCount = count(),
    TotalSizeMB = sum(FileSize) / 1048576,
    Files = make_set(FileName, 10)
    by ActionType, bin(TimeGenerated, 10m)
| order by TimeGenerated asc
```

**Look for**: Mass downloads, sensitive folder access (Finance, HR, Legal)

---

## Query 9: DLP Policy Violations

**Purpose**: Identify data exfiltration attempts caught by DLP

**Table**: CloudAppEvents

**Reference**: Investigation Guide Query 10

```kql
// Track DLP violations
let userUPN = "violetm@contoso.com";  // REPLACE

CloudAppEvents
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 23:59))
| where ActionType in ("FileCopiedToRemovableMedia", "FileUploadedToCloud", "FileCopiedToNetworkShare")
| extend DlpAudit = parse_json(RawEventData)["DlpAuditEventMetadata"]
| extend UserId = tostring(RawEventData.UserId)
| where UserId =~ userUPN
| extend RuleName = tostring(RawEventData.PolicyMatchInfo.RuleName)
| extend File = tostring(RawEventData.ObjectId)
| extend TargetDomain = tostring(RawEventData.TargetDomain)
| project 
    TimeGenerated,
    UserId,
    RuleName,
    File,
    TargetDomain
| order by TimeGenerated asc
```

**Red Flags**: Personal cloud storage (onedrive.live.com, dropbox.com, gmail.com)

---

## Query 10: OAuth App Delegations

**Purpose**: Detect malicious app permissions granted by attacker

**Table**: AuditLogs

```kql
// Find OAuth consent grants
let userUPN = "u11317@contoso.com";  // REPLACE (IT user in this scenario)

AuditLogs
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 23:59))
| where tostring(InitiatedBy.user.userPrincipalName) =~ userUPN
| where OperationName in ("Consent to application", "Add app role assignment to service principal")
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, AppDisplayName, AppId, Permissions, IPAddress
```

**Red Flags**: Mail.Read, Mail.Send, Files.ReadWrite.All permissions to unknown apps

---

## Query 11: All IPs in Session (for Enrichment)

**Purpose**: Extract all IPs used in a SessionId for threat intel enrichment

**Reference**: Investigation Guide Section 9, Step 4

```kql
// Get all IPs for threat intel lookup
let targetSessionId = "66f78a3c-e4d2-4b91-9f5e-2a1b8c7d9e6f";  // REPLACE

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 12:00))
| where SessionId == targetSessionId
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SignInCount = count(),
    Apps = make_set(AppDisplayName, 5)
    by IPAddress
| order by FirstSeen asc
| project IPAddress
```

**Next Step**: Use these IPs in Query 11 (Threat Intelligence) from Investigation Guide

---

## Query 12: Remediation Verification

**Purpose**: Verify remediation actions were successful

**Multiple Checks:**

### 12a: Verify Sessions Revoked
```kql
let userUPN = "violetm@contoso.com";
let remediationTime = datetime(2026-01-15 10:30:00);  // When you revoked sessions

AADNonInteractiveUserSignInLogs
| where TimeGenerated > remediationTime
| where UserPrincipalName =~ userUPN
| project TimeGenerated, IPAddress, AppDisplayName, ResultType
| order by TimeGenerated desc
```

**Expected**: No successful sign-ins after remediation

### 12b: Verify Inbox Rule Deleted
```kql
let userObjectId = "<USER_OBJECT_ID>";

CloudAppEvents
| where TimeGenerated > ago(1d)
| where AccountObjectId == userObjectId
| where ActionType == "Remove-InboxRule"
| extend RuleName = tostring(RawEventData.Parameters.Name)
| project TimeGenerated, ActionType, RuleName
```

**Expected**: "IT Security Update" rule deletion event

### 12c: Verify Sender Blocked
```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName has "transport rule"
| where TargetResources has "micros0ft-verify.com"
| project TimeGenerated, OperationName, Result
```

**Expected**: Transport rule blocking sender domain

---

## Tips for Using These Queries

1. **Always replace placeholder values**: `<USER_OBJECT_ID>`, `<UPN>`, IP addresses, timestamps
2. **Adjust time ranges**: Default is 7 days, narrow to incident window for performance
3. **Use in sequence**: Queries build on each other (get SessionId → trace chain → enrich IPs)
4. **Save results**: Export to CSV for offline analysis or evidence preservation
5. **Document findings**: Add comments to queries explaining what you discovered

---

## Quick Reference: Variables to Replace

| Variable | Source | Example |
|----------|--------|---------|
| `<UPN>` | From click tracking query | violetm@contoso.com |
| `<USER_OBJECT_ID>` | Microsoft Graph API | 12345678-1234-1234-1234-123456789012 |
| `<SUSPICIOUS_IP>` | Sign-in query results | 41.58.XXX.XXX |
| `<SessionId>` | Query 5 output | 66f78a3c-e4d2-4b91-9f5e-2a1b8c7d9e6f |
| `<CLICK_TIME>` | Query 3 output | datetime(2026-01-15 08:47:22) |

---

**Need help?** Refer to the [Investigation Guide Section 8](../../../Investigation-Guide.md#8-sample-kql-queries) for more query examples and optimization tips.
