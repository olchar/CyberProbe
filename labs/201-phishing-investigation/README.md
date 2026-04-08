# Lab 201: Phishing Campaign Investigation

**Duration**: 90 minutes  
**Difficulty**: Intermediate  
**Prerequisites**: Labs 101, 102

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Investigate a phishing email campaign from detection to post-compromise
- ✅ Identify all recipients and track who clicked malicious links
- ✅ Analyze compromised accounts for follow-on attacker activity
- ✅ Trace authentication chains to determine scope of compromise
- ✅ Generate comprehensive incident reports with remediation recommendations

---

## 📖 Scenario Background

**Date**: January 15, 2026  
**Incident ID**: #41398  
**Severity**: High  
**Status**: Active Investigation

### Initial Alert

At 08:45 PST, Microsoft Defender for Office 365 detected a phishing campaign targeting your organization. The alert indicates:

- **Subject**: "Urgent: Verify Your Microsoft Account"
- **Sender**: `security-noreply@micros0ft-verify.com` (note the "0" instead of "o")
- **Recipients**: 47 users across Finance, HR, and IT departments
- **Attachment**: None detected
- **Malicious URL**: `https://login-microsoftonline.verify-account[.]tk/auth`
- **Detection Source**: URL detonation + threat intelligence

### What We Know

- **3 users clicked the link**: Based on Defender for Office 365 SafeLinks telemetry
- **Credential harvesting suspected**: The URL hosts a fake Microsoft login page
- **Post-compromise activity**: Defender for Identity flagged unusual sign-in from Nigeria for one user
- **DLP alert triggered**: Sensitive financial data was shared externally 2 hours after click

### Your Mission

As the security analyst on duty, you must:

1. Identify all recipients and determine who clicked the link
2. Investigate compromised accounts for suspicious activity
3. Determine if credentials were stolen and used by attackers
4. Assess data exfiltration risk
5. Provide remediation recommendations

---

## 🔬 Investigation Workflow

This lab follows **Playbook 2: Phishing Investigation** from the Investigation Guide (Section 12).

### Phase 1: Email Campaign Analysis

**Objective**: Identify the scope of the phishing campaign.

#### Task 1.1: Query Malicious Email Events

**Prompt to Copilot:**
```
Search EmailEvents table for emails with sender "security-noreply@micros0ft-verify.com" from the last 7 days
```

**Expected KQL Query** (from Investigation Guide Section 3.4):
```kql
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

**Expected Results:**
- 47 email records (one per recipient)
- First email sent: 2026-01-15 08:32:17 PST
- Last email sent: 2026-01-15 08:44:52 PST
- ThreatTypes: `["Phish"]`
- DeliveryAction: Mix of `Delivered`, `Blocked`, `Quarantined`

✅ **Checkpoint**: You should identify all 47 recipients. How many emails were delivered vs quarantined?

<details>
<summary>📊 View Sample Results</summary>

```
Delivered: 31 users (delivered before detection)
Quarantined: 12 users (caught by real-time protection)
Blocked: 4 users (caught by pre-delivery scanning)
```

</details>

#### Task 1.2: Extract Malicious URLs

**Query EmailUrlInfo** for the phishing link:

```kql
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

**Expected Results:**
- Full URL: `https://login-microsoftonline.verify-account[.]tk/auth?user={recipient}`
- URL personalized with recipient email (credential pre-filling tactic)
- ThreatTypes: `["Phish", "Malware"]` (dual-purpose page)

---

### Phase 2: Click Tracking & User Compromise

**Objective**: Identify users who clicked the link and assess compromise.

#### Task 2.1: Track SafeLinks Click Events

SafeLinks telemetry is stored in `CloudAppEvents` table:

```kql
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

**Expected Results:**
- **3 users clicked through SafeLinks warning**:
  - `violetm@avoriaz.alpineskihouse.co` - 08:47:22 PST from IP 192.0.2.45 (Seattle, WA)
  - `u3498@contoso.com` - 08:51:18 PST from IP 198.51.100.89 (Portland, OR)
  - `u11317@contoso.com` - 09:02:44 PST from IP 203.0.113.12 (New York, NY)

✅ **Checkpoint**: You've identified 3 compromised users. Now investigate post-click activity.

#### Task 2.2: Analyze Post-Click Sign-in Activity

For each user who clicked, check for suspicious sign-ins within 1 hour of click:

**Example for violetm@avoriaz.alpineskihouse.co**:

```kql
let clickTime = datetime(2026-01-15 08:47:22);
let userUPN = "violetm@avoriaz.alpineskihouse.co";

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

**Expected Pattern (Compromised User)**:
```
08:47:22 PST - Click event from Seattle (192.0.2.45)
08:48:31 PST - Failed sign-in from Seattle (192.0.2.45) - "Incorrect password"
08:49:15 PST - Successful sign-in from Lagos, Nigeria (41.58.XXX.XXX) - "MFA requirement satisfied by claim"
08:52:40 PST - Sign-in to Exchange Online from Lagos (41.58.XXX.XXX) - Token refresh
09:15:22 PST - Sign-in to SharePoint from Lagos (41.58.XXX.XXX) - Token refresh
```

**⚠️ Red Flags:**
- Impossible travel: Seattle → Nigeria in 1 minute
- Nigerian IP immediately after phishing click
- Token-based authentication (stolen session token, not password)

---

### Phase 3: SessionId Tracing (Advanced Authentication Analysis)

**Objective**: Use SessionId forensics to trace the complete authentication chain.

This follows **Section 9: Advanced Authentication Analysis** from the Investigation Guide.

#### Task 3.1: Extract SessionId from Suspicious IP

Get SessionId from the Nigerian sign-in:

```kql
let suspiciousIP = "41.58.XXX.XXX";  // Lagos, Nigeria IP
let userUPN = "violetm@avoriaz.alpineskihouse.co";

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 12:00))
| where UserPrincipalName =~ userUPN
| where IPAddress == suspiciousIP
| where isnotempty(SessionId)
| distinct SessionId
| take 1
```

**Expected Output**: `SessionId: 66f78a3c-e4d2-4b91-9f5e-2a1b8c7d9e6f`

#### Task 3.2: Trace Complete Authentication Chain

Using the SessionId, trace all authentication events:

```kql
let targetSessionId = "66f78a3c-e4d2-4b91-9f5e-2a1b8c7d9e6f";

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

**Expected Timeline:**
```
08:49:15 - Lagos, NG - Browser Sign-in - multiFactorAuthentication (INITIAL AUTH)
08:52:40 - Lagos, NG - Exchange Online - singleFactorAuthentication (Token)
09:15:22 - Lagos, NG - SharePoint - singleFactorAuthentication (Token)
09:47:11 - Lagos, NG - OneDrive - singleFactorAuthentication (Token)
10:22:08 - Lagos, NG - Teams - singleFactorAuthentication (Token)
```

**🔴 Critical Finding**: The FIRST authentication in the session is from Nigeria with MFA satisfied. This means:
- ✅ Attacker successfully phished credentials AND MFA token
- ✅ No legitimate Seattle-based authentication in this session
- ✅ All subsequent activity is attacker-controlled

#### Task 3.3: Enrich Nigerian IP

Check IP enrichment data from investigation JSON or run external enrichment:

**Expected Enrichment Data:**
```json
{
  "ip": "41.58.XXX.XXX",
  "city": "Lagos",
  "region": "Lagos",
  "country": "NG",
  "org": "AS37682 MainOne Cable Company",
  "is_vpn": false,
  "is_proxy": false,
  "is_tor": false,
  "abuse_confidence_score": 72,
  "threat_description": "Credential stuffing, phishing"
}
```

**Risk Assessment**: **CRITICAL** - High abuse score (72%), known phishing activity, no VPN/proxy (direct attacker connection)

---

### Phase 4: Post-Compromise Activity Analysis

**Objective**: Determine what the attacker did after gaining access.

#### Task 4.1: Check Email Forwarding Rules

Attackers often create mail forwarding rules to exfiltrate future emails:

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 23:59))
| where AccountObjectId == "<USER_OBJECT_ID>"  // From Graph API
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleName = tostring(RawEventData.Parameters.Name)
| extend ForwardTo = tostring(RawEventData.Parameters.ForwardTo)
| project TimeGenerated, ActionType, RuleName, ForwardTo, IPAddress
```

**Expected Results**: 
- Rule created at 09:05:33 PST
- Rule name: "IT Security Update"
- ForwardTo: `external-collector@suspicious-domain.tk`

**⚠️ Red Flag**: Attacker created forwarding rule 16 minutes after initial compromise!

#### Task 4.2: Check File Access & Downloads

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 23:59))
| where AccountObjectId == "<USER_OBJECT_ID>"
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

**Expected Results**:
- 09:12 - 09:35 PST: 47 files accessed in SharePoint "Finance" folder
- Total downloaded: 184 MB
- Files include: "Q4_Financial_Projections.xlsx", "Executive_Compensation.pdf", "M&A_Pipeline.xlsx"

**⚠️ Red Flag**: Systematic exfiltration of sensitive financial data!

#### Task 4.3: Check DLP Policy Violations

This connects to **Query 10** in the Investigation Guide:

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-01-15 08:00) .. datetime(2026-01-15 23:59))
| where ActionType in ("FileCopiedToRemovableMedia", "FileUploadedToCloud", "FileCopiedToNetworkShare")
| extend DlpAudit = parse_json(RawEventData)["DlpAuditEventMetadata"]
| extend UserId = tostring(RawEventData.UserId)
| where UserId =~ "violetm@avoriaz.alpineskihouse.co"
| extend RuleName = tostring(RawEventData.PolicyMatchInfo.RuleName)
| extend File = tostring(RawEventData.ObjectId)
| project 
    TimeGenerated,
    UserId,
    RuleName,
    File,
    tostring(RawEventData.TargetDomain)
| order by TimeGenerated asc
```

**Expected Results**:
- 10:42 PST: DLP violation - "Financial Data Sharing" policy
- File: "Q4_Financial_Projections.xlsx" uploaded to personal OneDrive
- Target domain: `onedrive.live.com` (personal account, not corporate)

---

### Phase 5: Incident Report & Remediation

**Objective**: Compile findings and recommend actions.

#### Task 5.1: Generate Investigation Report

**Prompt to Copilot:**
```
Generate full investigation report for violetm@avoriaz.alpineskihouse.co covering phishing incident #41398 from 2026-01-15
```

**Report Should Include:**
- ✅ Incident timeline (click → compromise → exfiltration)
- ✅ SessionId tracing results
- ✅ IP enrichment for Nigerian IP
- ✅ Post-compromise activity (forwarding rule, file access, DLP)
- ✅ Risk assessment: CRITICAL
- ✅ Remediation recommendations

#### Task 5.2: Remediation Actions

Based on **Playbook 2** (Investigation Guide Section 12):

**Immediate (0-4 hours):**
1. ✅ **Revoke all sessions** for compromised user
2. ✅ **Force password reset** (credentials stolen)
3. ✅ **Disable account** pending investigation
4. ✅ **Delete malicious inbox rule** ("IT Security Update")
5. ✅ **Block sender domain** `micros0ft-verify.com`
6. ✅ **Quarantine remaining emails** (16 still in mailboxes)

**Short-Term (4-24 hours):**
7. ✅ **Re-enable MFA** with fresh enrollment
8. ✅ **Review delegated permissions** (attackers may have granted app access)
9. ✅ **Monitor for persistence mechanisms** (OAuth apps, forwarding rules)
10. ✅ **Notify data owner** about exfiltrated files

**Long-Term (This Week):**
11. ✅ **Conduct phishing awareness training** for all 47 recipients
12. ✅ **Review SafeLinks configuration** (why did users bypass warning?)
13. ✅ **Implement Conditional Access** for high-risk countries
14. ✅ **Enable Continuous Access Evaluation** (real-time token revocation)

---

## ✅ Lab Validation

Before completing this lab, verify you can:

- [ ] Identify phishing email recipients from EmailEvents table
- [ ] Track URL clicks using SafeLinks telemetry
- [ ] Detect impossible travel patterns in sign-in logs
- [ ] Use SessionId tracing to reconstruct authentication timeline
- [ ] Identify post-compromise activities (forwarding rules, file access, DLP)
- [ ] Correlate multiple data sources (Email, Sign-in, CloudApp, DLP)
- [ ] Generate incident report with remediation recommendations

---

## 🎓 Key Takeaways

**Investigation Techniques:**
1. **Email Analysis**: EmailEvents + EmailUrlInfo for campaign scope
2. **Click Tracking**: CloudAppEvents (SafeLinks) for victim identification
3. **SessionId Tracing**: Critical for separating legitimate vs attacker activity
4. **IP Enrichment**: Abuse scores + geolocation contextualize risk
5. **Post-Compromise**: Forwarding rules, file access, DLP violations reveal attacker objectives

**Red Flags Identified:**
- 🚩 Impossible travel (Seattle → Nigeria in 1 minute)
- 🚩 SessionId initial auth from attacker IP (no legitimate auth in chain)
- 🚩 Malicious inbox rule created 16 mins after compromise
- 🚩 Systematic file exfiltration (47 files, 184 MB)
- 🚩 DLP violation - sensitive data uploaded to personal OneDrive

**Remediation Priority:**
- **P0 (Critical)**: Revoke sessions, force password reset, disable account
- **P1 (High)**: Delete forwarding rule, block sender domain, quarantine emails
- **P2 (Medium)**: Re-enroll MFA, review delegations, monitor persistence
- **P3 (Low)**: Training, policy review, conditional access improvements

---

## 🚀 Next Steps

**Advanced Challenges:**
1. Investigate the other 2 compromised users (u3498, u11317)
2. Hunt for similar phishing campaigns from different senders
3. Create a detection rule to alert on impossible travel + phishing click
4. Automate remediation using Microsoft Graph API

**Continue Learning:**
- **Lab 202**: Compromised Identity (deeper SessionId tracing)
- **Lab 203**: Insider Threat (behavioral analysis techniques)
- **Lab 204**: DLP Exfiltration (advanced data loss scenarios)

---

## 📚 Reference Materials

- [Investigation Guide - Playbook 2: Phishing](../../Investigation-Guide.md#playbook-2-phishing-investigation)
- [Investigation Guide - Section 9: SessionId Tracing](../../Investigation-Guide.md#9-advanced-authentication-analysis)
- [Investigation Guide - Query 10: DLP Events](../../Investigation-Guide.md#query-10-dlp-events-data-loss-prevention)
- [Defender for Office 365 Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/)

---

**Congratulations!** You've successfully investigated a phishing campaign from initial detection through post-compromise activity analysis. These skills apply to real-world incident response scenarios.
