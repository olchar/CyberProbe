# Lab 105: Incident Response Workflow

**Duration**: 45 minutes  
**Difficulty**: Intermediate  
**Prerequisites**: Labs 101-104

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Triage security incidents using priority criteria
- ✅ Execute systematic incident investigation playbooks
- ✅ Build MITRE ATT&CK timeline from incident data
- ✅ Verify remediation actions were successful
- ✅ Document incident response in formal report
- ✅ Escalate incidents to appropriate teams

---

## 📖 Background

When Microsoft Defender XDR creates a **SecurityIncident**, it correlates multiple alerts into a single case. Your job as incident responder is to:

1. **Triage**: Determine severity and urgency
2. **Investigate**: Understand scope, timeline, and impact
3. **Contain**: Stop ongoing malicious activity
4. **Remediate**: Remove threat and restore security
5. **Document**: Create formal incident report
6. **Learn**: Update detections and procedures

This lab walks through a complete incident response using CyberProbe tools and Investigation Guide workflows.

---

## 🚨 Incident Scenario

**Incident Received**: January 15, 2026, 11:30 AM PST

```
════════════════════════════════════════════
MICROSOFT DEFENDER XDR INCIDENT #41450
════════════════════════════════════════════
Title: Suspicious authentication activity and account manipulation
Severity: High
Status: New
Classification: Unclassified
Created: 2026-01-15 09:27:00 PST
Impacted Entities: 1 user, 3 devices, 15 alerts

Top Alerts:
- Impossible travel activity (High)
- MFA fraud alert (High)
- Suspicious inbox rule created (Medium)
- Mass file download from SharePoint (Medium)

Primary User: sarah.chen@contoso.com
Primary IP: 103.28.XXX.XXX (Dhaka, Bangladesh)
════════════════════════════════════════════
```

**Your Mission**: Investigate, contain, remediate, and document this incident.

---

## 📝 Exercise 1: Incident Triage

**Objective**: Assess incident severity and determine response priority.

### Task 1.1: Get Incident Details

Using MCP Tools (Copilot prompt):
```
Get details for incident #41450 including all alerts
```

**Or manual KQL query**:
```kql
SecurityIncident
| where IncidentNumber == "41450"
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | where TimeGenerated > ago(7d)
    | project SystemAlertId, AlertName, AlertSeverity, Description, Tactics, Techniques
) on $left.AlertId == $right.SystemAlertId
| summarize 
    Alerts = make_list(pack("Name", AlertName, "Severity", AlertSeverity, "Tactics", Tactics)),
    HighCount = countif(AlertSeverity == "High"),
    MediumCount = countif(AlertSeverity == "Medium"),
    LowCount = countif(AlertSeverity == "Low"),
    TacticsList = make_set(Tactics)
    by IncidentNumber, Title, Severity, Status, Classification
| project-away IncidentNumber1
```

**Document these key details**:
- Number of High severity alerts: _____
- MITRE ATT&CK tactics present: _____
- Impacted user: _____
- Time range: _____ to _____

### Task 1.2: Apply Triage Criteria

**Priority Matrix**:

| Criteria | Points |
|----------|--------|
| Severity = High | +3 |
| Severity = Medium | +2 |
| Data exfiltration indicators | +3 |
| Privileged account involved | +3 |
| Multiple users impacted | +2 |
| Active malware/persistence | +3 |
| External IP involved | +1 |

**Calculate score**: _____

**Priority Assignment**:
- 10+ points = **P1 (Critical)** - Respond immediately
- 7-9 points = **P2 (High)** - Respond within 2 hours
- 4-6 points = **P3 (Medium)** - Respond within 8 hours
- <4 points = **P4 (Low)** - Respond within 24 hours

**Your Priority**: P_____

✅ **Checkpoint**: You've assigned incident priority

---

## 📝 Exercise 2: Execute Investigation Playbook

**Objective**: Follow systematic investigation workflow from Investigation Guide.

### Task 2.1: Phase 1 - User Context

Get complete user profile and recent activity:

```
Investigate sarah.chen@contoso.com for past 7 days starting from 2026-01-08
```

**Expected output**: JSON file with sign-ins, anomalies, incidents, IP enrichment

**Key questions to answer**:
1. Is this user a privileged account (admin, global admin)?
2. What department/role? (Finance, IT, HR = higher risk)
3. Any prior security incidents for this user?
4. Baseline geographic location? (to identify travel anomalies)

**Document findings**:
```
User: sarah.chen@contoso.com
Role: [Department, Job Title]
Privileged: [Yes/No]
Baseline Location: [City, Country]
Prior Incidents: [Count]
```

### Task 2.2: Phase 2 - SessionId Forensics

Extract SessionId from the suspicious Bangladesh IP:

**Prompt**:
```
Extract SessionId from IP 103.28.XXX.XXX for sarah.chen@contoso.com
```

**Manual query** (from Lab 103):
```kql
let suspiciousIP = "103.28.XXX.XXX";
let userUPN = "sarah.chen@contoso.com";
let start = datetime(2026-01-15 08:00);
let end = datetime(2026-01-15 12:00);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ userUPN
| where IPAddress == suspiciousIP
| where isnotempty(SessionId)
| distinct SessionId
| take 1
```

**SessionId**: _____

### Task 2.3: Phase 3 - Authentication Chain Analysis

Trace complete authentication timeline:

```kql
let targetSessionId = "<YOUR_SESSIONID>";
let start = datetime(2026-01-15 06:00);
let end = datetime(2026-01-15 14:00);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where SessionId == targetSessionId
| extend LocationDetails = parse_json(LocationDetails)
| extend 
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| project 
    TimeGenerated,
    IPAddress,
    City,
    Country,
    AppDisplayName,
    AuthenticationRequirement,
    ResultType
| order by TimeGenerated asc
```

**Critical question**: Where did the FIRST MFA authentication occur?
- [ ] Bangladesh (suspicious - likely compromised)
- [ ] Seattle (legitimate - false positive)
- [ ] VPN IP (need to verify corporate VPN)

### Task 2.4: Phase 4 - Post-Compromise Activity

What did the attacker do after authentication?

**Inbox Rules** (from alert):
```kql
let userUPN = "sarah.chen@contoso.com";
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountObjectId has userUPN or AccountDisplayName has "sarah.chen"
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleDetails = parse_json(RawEventData)
| project 
    TimeGenerated,
    ActionType,
    RuleName = tostring(RuleDetails.Parameters[0].Value),
    IPAddress
```

**File Downloads** (from alert):
```kql
let userUPN = "sarah.chen@contoso.com";
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountObjectId has userUPN or AccountDisplayName has "sarah.chen"
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded", "FileAccessed")
| summarize 
    FileCount = count(),
    FileNames = make_set(ObjectName, 20)
    by bin(TimeGenerated, 10m), IPAddress
| order by TimeGenerated asc
```

**Document timeline**:
```
09:27 - [IP] - MFA authentication from [Location]
09:32 - [IP] - Created inbox rule "[RuleName]"
09:45 - [IP] - Downloaded [COUNT] files from SharePoint
10:15 - [IP] - Accessed [APP]
```

✅ **Checkpoint**: You have complete attack timeline

---

## 📝 Exercise 3: Build MITRE ATT&CK Timeline

**Objective**: Map incident activities to MITRE ATT&CK framework.

### Task 3.1: Identify Techniques

Based on your investigation, map each activity:

| Time | Activity | MITRE Tactic | MITRE Technique |
|------|----------|--------------|-----------------|
| 09:27 | MFA auth from Bangladesh | Initial Access | T1078: Valid Accounts |
| 09:32 | Created inbox rule (forward emails) | Persistence | T1114.003: Email Forwarding Rule |
| 09:45 | Mass file download (15 files) | Collection | T1213: Data from Information Repositories |
| 10:15 | Uploaded files to personal OneDrive | Exfiltration | T1567.002: Exfiltration to Cloud Storage |

**MITRE ATT&CK Chain**:
```
Initial Access → Persistence → Collection → Exfiltration
   (T1078)         (T1114.003)    (T1213)      (T1567.002)
```

### Task 3.2: Assess Attack Sophistication

**Indicators**:
- [ ] Used MFA push fatigue (forced legitimate user to approve)
- [ ] Created hidden inbox rule (name: ".", deleted confirmation emails)
- [ ] Selective file downloads (only "Financial" and "Confidential" files)
- [ ] Exfiltrated to personal cloud (harder to block than external IP)

**Sophistication Level**: [Low / Medium / High / Advanced]

**Attacker Profile**: [Script kiddie / Opportunistic / Targeted / APT]

---

## 📝 Exercise 4: Containment & Remediation

**Objective**: Stop ongoing attack and remove attacker access.

### Task 4.1: Immediate Containment Actions

**Execute these steps** (in order):

1. **Revoke all sessions**:
   ```
   Via Azure Portal:
   - Navigate to Azure AD > Users > sarah.chen@contoso.com
   - Click "Revoke sessions"
   - Confirm: "Revoke all refresh tokens"
   ```

2. **Force password reset**:
   ```
   Via Azure Portal:
   - Azure AD > Users > sarah.chen@contoso.com
   - Click "Reset password"
   - Check "Require user to change password at next sign-in"
   - Generate temporary password: __________
   ```

3. **Disable account** (if attack ongoing):
   ```
   Via Azure Portal:
   - Azure AD > Users > sarah.chen@contoso.com
   - Click "Block sign-in"
   - Reason: "Security incident #41450 - credential compromise"
   ```

4. **Delete malicious inbox rule**:
   ```powershell
   # Connect to Exchange Online
   Connect-ExchangeOnline
   
   # List rules
   Get-InboxRule -Mailbox sarah.chen@contoso.com
   
   # Remove malicious rule
   Remove-InboxRule -Mailbox sarah.chen@contoso.com -Identity "[RULE_NAME]"
   ```

### Task 4.2: Verify Remediation

**Check 1: Sessions Revoked**
```kql
// Should return NO results after revocation
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30m)
| where UserPrincipalName =~ "sarah.chen@contoso.com"
| where IPAddress == "103.28.XXX.XXX"
| project TimeGenerated, IPAddress, AppDisplayName, ResultType
```

**Expected**: 0 results (no new sign-ins from Bangladesh IP)

**Check 2: Inbox Rules Removed**
```kql
CloudAppEvents
| where TimeGenerated > ago(30m)
| where AccountDisplayName has "sarah.chen"
| where ActionType == "Remove-InboxRule"
| project TimeGenerated, ActionType, ObjectName, AccountDisplayName
```

**Expected**: 1 result showing rule removal

**Check 3: Account Status**
```powershell
Get-AzureADUser -ObjectId sarah.chen@contoso.com | 
    Select-Object DisplayName, AccountEnabled, UserPrincipalName
```

**Expected**: `AccountEnabled: False` (if disabled) or password change pending

✅ **Checkpoint**: Threat is contained and remediated

---

## 📝 Exercise 5: Incident Documentation

**Objective**: Create formal incident response report.

### Task 5.1: Complete Incident Report Template

```markdown
# INCIDENT RESPONSE REPORT
═══════════════════════════════════════════

## INCIDENT SUMMARY
Incident ID: 41450
Title: Suspicious authentication activity and account manipulation
Severity: High
Status: Resolved
Date Opened: 2026-01-15 09:27 PST
Date Closed: 2026-01-15 [YOUR_TIME]
Analyst: [YOUR_NAME]

## EXECUTIVE SUMMARY
[2-3 sentences summarizing what happened, impact, and outcome]

Example:
"Sarah Chen's account was compromised via MFA fatigue attack from 
Bangladesh (IP 103.28.XXX.XXX). The attacker created a malicious inbox 
rule and downloaded 15 confidential financial documents. Account was 
secured within 2 hours with password reset, session revocation, and 
inbox rule removal. No evidence of data exfiltration outside organization."

## TIMELINE OF EVENTS
| Time (PST) | Event | Source |
|------------|-------|--------|
| 09:27 | MFA authentication from Dhaka, Bangladesh | SigninLogs |
| 09:32 | Malicious inbox rule created (forward to attacker@...) | CloudAppEvents |
| 09:45 | Mass download: 15 files from Finance SharePoint | CloudAppEvents |
| 10:15 | Upload to personal OneDrive (blocked by DLP) | DLP Policy |
| 11:30 | Incident detected by Defender XDR | SecurityIncident |
| 11:45 | Investigation initiated by SOC | Manual |
| 12:15 | Sessions revoked, password reset | Remediation |
| 12:30 | Inbox rule deleted | Remediation |

## TECHNICAL ANALYSIS

### Attack Vector
- Initial Access: [Describe how attacker got credentials]
- Method: [MFA fatigue / phishing / credential stuffing / etc.]

### Attacker Actions (MITRE ATT&CK)
1. **Initial Access (T1078)**: Valid account access from Bangladesh IP
2. **Persistence (T1114.003)**: Email forwarding rule to hide activity
3. **Collection (T1213)**: Downloaded 15 confidential documents
4. **Exfiltration (T1567.002)**: Attempted upload to personal cloud (blocked)

### SessionId Forensics
- SessionId: [YOUR_SESSIONID]
- Initial MFA: [Location] at [Time]
- Conclusion: [Legitimate user vs attacker authentication]

### IP Enrichment
- IP: 103.28.XXX.XXX
- Location: Dhaka, Bangladesh
- ISP: [ORG]
- Abuse Score: [SCORE]
- Risk Assessment: [HIGH/MEDIUM/LOW]

## IMPACT ASSESSMENT

### Confidentiality
- [ ] High: Confidential data exfiltrated outside organization
- [ ] Medium: Confidential data accessed but not exfiltrated
- [ ] Low: No confidential data accessed

### Integrity
- [ ] High: Data modified, systems compromised
- [ ] Medium: Configuration changes (inbox rules, delegations)
- [ ] Low: No integrity impact

### Availability
- [ ] High: Systems/accounts disabled for >4 hours
- [ ] Medium: Accounts disabled for <4 hours
- [ ] Low: No availability impact

**Overall Impact**: [HIGH/MEDIUM/LOW]

## REMEDIATION ACTIONS

### Immediate (Completed)
- [x] Sessions revoked (12:15 PST)
- [x] Password reset (12:15 PST)
- [x] Malicious inbox rule deleted (12:30 PST)
- [x] Account re-enabled after user verification (13:00 PST)

### Short-term (Next 48 hours)
- [ ] User interview: How did MFA compromise occur?
- [ ] Device forensics: Check for malware on user's devices
- [ ] Email review: Search for phishing emails sent to Sarah
- [ ] Conditional Access: Require compliant device for Finance dept

### Long-term (Next 30 days)
- [ ] MFA upgrade: Implement number matching (prevent fatigue)
- [ ] User training: MFA best practices, phishing awareness
- [ ] DLP review: Ensure all Finance SharePoint sites covered
- [ ] Detection tuning: Improve alert for Bangladesh sign-ins

## RECOMMENDATIONS

1. **Technical Controls**:
   - Enable MFA number matching for all users (prevents fatigue)
   - Block sign-ins from high-risk countries (Bangladesh, Russia, etc.) unless VPN
   - Implement Conditional Access for Finance department (compliant device required)

2. **Process Improvements**:
   - Create incident response playbook for MFA fatigue attacks
   - Establish 2-hour SLA for High severity incidents
   - Weekly security awareness emails highlighting MFA threats

3. **User Education**:
   - Mandatory MFA training for all Finance department
   - Quarterly phishing simulation exercises
   - Incident review session with Sarah Chen (learning opportunity)

## LESSONS LEARNED

**What Worked Well**:
- Defender XDR correlated 15 alerts into single incident (reduced noise)
- SessionId tracing definitively confirmed compromise
- IP enrichment provided threat context for decision-making
- Remediation completed within 2-hour SLA

**What Could Improve**:
- MFA fatigue not detected until after successful authentication
- DLP blocked exfiltration but should alert SOC real-time
- User wasn't aware of ongoing attack (need user notification workflow)

**Follow-up Actions**:
- [Action 1 with owner and due date]
- [Action 2 with owner and due date]

## APPENDICES

### Appendix A: Indicators of Compromise (IOCs)
- IP Address: 103.28.XXX.XXX
- SessionId: [YOUR_SESSIONID]
- Malicious inbox rule name: "[RULE_NAME]"
- Files accessed: [List from CloudAppEvents query]

### Appendix B: Supporting Evidence
- Investigation JSON: reports/investigation_sarah.chen_2026-01-15.json
- Investigation Report: reports/investigation_sarah.chen_2026-01-15.html
- KQL Queries: [Attach queries used]

---
Report completed: [DATE TIME]
Reviewed by: [TEAM LEAD NAME]
Approved for closure: [Yes/No]
```

### Task 5.2: Update Incident in Defender XDR

```
Via Azure Portal:
1. Go to Microsoft 365 Defender > Incidents
2. Open Incident #41450
3. Update fields:
   - Status: Resolved
   - Classification: True Positive
   - Determination: Compromised account
   - Assigned to: [Your name]
   - Tags: MFA-Fatigue, Bangladesh, Finance-Dept
4. Add comment: "Investigation complete. Account secured. See full report."
5. Save
```

✅ **Checkpoint**: Incident formally documented and closed

---

## ✅ Lab Validation Checklist

Before completing this lab, verify you can:

- [ ] Calculate incident priority using scoring matrix
- [ ] Execute systematic investigation playbook (Phases 1-4)
- [ ] Perform SessionId forensic analysis
- [ ] Map incident activities to MITRE ATT&CK framework
- [ ] Execute containment actions (revoke, reset, delete rules)
- [ ] Verify remediation was successful
- [ ] Create formal incident response report
- [ ] Update incident status in Defender XDR
- [ ] Provide actionable recommendations

---

## 🎓 Key Takeaways

**Incident Response Workflow**:
```
Triage → Investigate → Contain → Remediate → Document → Learn
```

**Critical Containment Order**:
1. **Revoke sessions** (stops active access)
2. **Reset password** (prevents re-authentication)
3. **Remove persistence** (inbox rules, OAuth apps)
4. **Verify remediation** (confirm attacker can't return)

**SessionId Value in IR**:
- Definitively answers "Was this user compromised or false positive?"
- Provides forensic-grade evidence for legal/HR
- Identifies exact moment of initial compromise
- Maps complete attacker activity timeline

**Documentation Importance**:
- Legal compliance (SOX, GDPR require incident records)
- Knowledge sharing (future analysts learn from your work)
- Trend analysis (identify common attack patterns)
- Process improvement (lessons learned drive changes)

---

## 🚀 Next Steps

**Continue to [Lab 106: MCP Automation](../106-automation-mcp/)**

Or **practice incident response**:
1. Find a real SecurityIncident in your environment
2. Execute this playbook end-to-end
3. Create incident report
4. Present findings to team

**Build IR Playbook Library**:
- Phishing incident playbook
- Malware infection playbook
- Data exfiltration playbook
- Insider threat playbook

---

## 📚 Additional Resources

- [Investigation Guide - Standard Workflow](../../Investigation-Guide.md#investigation-workflow)
- [Investigation Guide - Section 9: SessionId Tracing](../../Investigation-Guide.md#9-advanced-authentication-analysis)
- [MITRE ATT&CK for Office 365](https://attack.mitre.org/matrices/enterprise/cloud/office365/)
- [Microsoft Incident Response Reference](https://docs.microsoft.com/en-us/security/compass/incident-response-overview)

---

## ❓ FAQ

**Q: When should I disable the account vs just reset password?**  
A: Disable if attack is ONGOING (you see active malicious sign-ins in real-time). Otherwise, reset password is sufficient and less disruptive.

**Q: How do I know if data was actually exfiltrated vs just accessed?**  
A: Check for:
- External sharing events (SharingSet, AnonymousLinkCreated)
- File uploads to personal cloud (CloudAppEvents to non-corporate OneDrive)
- Email forwarding rules (auto-forwarding documents)
- DLP policy violations (external data transfer attempts)

**Q: Should I re-enable the account after remediation?**  
A: Yes, after:
1. Password reset confirmed
2. No active malicious sessions
3. User interviewed/verified (not the attacker calling in)
4. MFA re-registered on trusted device

**Q: How long should I monitor the account post-incident?**  
A: Monitor for 7 days. If new anomalies appear, may indicate:
- Attacker has persistence mechanism you missed
- Different compromised credential (password reuse)
- Need for deeper device forensics

---

**Congratulations!** You've completed a full incident response cycle. You can now handle security incidents from detection to closure with confidence and thorough documentation.
