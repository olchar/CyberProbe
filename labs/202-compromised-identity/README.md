# Lab 202: Compromised Identity Investigation

**Duration**: 90 minutes  
**Difficulty**: Advanced  
**Prerequisites**: Labs 101-106, Lab 201

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Investigate impossible travel scenarios using SessionId
- ✅ Identify token theft vs legitimate VPN usage
- ✅ Analyze geographic anomalies with IP enrichment
- ✅ Detect MFA bypass techniques
- ✅ Trace lateral movement after initial compromise
- ✅ Build comprehensive compromise timeline
- ✅ Provide definitive compromise determination

---

## 📖 Background

Identity compromise is one of the most common attack vectors. This lab focuses on a complex scenario where an account shows signs of compromise (impossible travel, suspicious IPs), but determining whether it's a **true compromise** or **false positive** requires deep SessionId forensic analysis.

You'll investigate a case with conflicting indicators:
- Legitimate user signs in from Seattle
- 20 minutes later, sign-in from Nigeria
- Both locations show successful MFA
- IP enrichment shows Nigeria IP has abuse score 72

**Is this a compromised account or legitimate activity?** Only SessionId tracing can tell.

---

## 🔍 Investigation Scenario

**Alert Received**: January 15, 2026, 14:30 PST

```
════════════════════════════════════════════════════════════
MICROSOFT DEFENDER XDR INCIDENT #41502
════════════════════════════════════════════════════════════
Title: Impossible travel and suspicious IP address
Severity: High
Status: New
Created: 2026-01-15 14:30:00 PST

Primary Alert: Identity Protection - Impossible Travel
User: marcus.rodriguez@alpineskihouse.co
Risk Level: High

Timeline:
• 14:05 PST - Sign-in from Seattle, WA (198.51.100.XXX)
• 14:25 PST - Sign-in from Lagos, Nigeria (102.88.XXX.XXX)
• Geographic distance: 7,425 miles in 20 minutes

Impacted Resources:
- User account: marcus.rodriguez@alpineskihouse.co
- Accessed applications: Office 365, SharePoint, Teams
════════════════════════════════════════════════════════════
```

---

## 📝 Exercise 1: Initial Investigation & User Context

**Objective**: Gather baseline information about the user and incident.

### Task 1.1: Get User Profile

**Prompt**:
```
Get user profile for marcus.rodriguez@alpineskihouse.co including role, department, and baseline locations
```

**Document findings**:
```
User: marcus.rodriguez@alpineskihouse.co
Display Name: Marcus Rodriguez
Job Title: [FROM QUERY]
Department: [FROM QUERY]
Privileged Account: [Yes/No - check Azure AD roles]
Baseline Location: [City, State based on historical sign-ins]
Account Created: [Date]
```

### Task 1.2: Review Recent Sign-in History (7 days)

```kql
let upn = "marcus.rodriguez@alpineskihouse.co";
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ upn
| extend LocationDetails = parse_json(LocationDetails)
| extend 
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| summarize 
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueCountries = dcount(Country),
    Countries = make_set(Country)
    by bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

**Question**: Did Marcus typically sign in from Nigeria before this incident?

✅ **Checkpoint**: You have user context and baseline behavior

---

## 📝 Exercise 2: SessionId Forensic Analysis

**Objective**: Use SessionId to determine if this is compromise or false positive.

### Task 2.1: Extract SessionId from Nigeria IP

```kql
let suspiciousIP = "102.88.XXX.XXX";  // Nigeria IP from alert
let upn = "marcus.rodriguez@alpineskihouse.co";
let alertTime = datetime(2026-01-15 14:25:00);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((alertTime - 10m) .. (alertTime + 10m))
| where UserPrincipalName =~ upn
| where IPAddress == suspiciousIP
| where isnotempty(SessionId)
| distinct SessionId
| take 1
```

**SessionId from Nigeria**: _____________________

### Task 2.2: Extract SessionId from Seattle IP

```kql
let seattleIP = "198.51.100.XXX";  // Seattle IP from alert
let upn = "marcus.rodriguez@alpineskihouse.co";
let seattleTime = datetime(2026-01-15 14:05:00);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((seattleTime - 10m) .. (seattleTime + 10m))
| where UserPrincipalName =~ upn
| where IPAddress == seattleIP
| where isnotempty(SessionId)
| distinct SessionId
| take 1
```

**SessionId from Seattle**: _____________________

**Critical Question**: Are the two SessionIds the SAME or DIFFERENT?

<details>
<summary>💡 What does this mean?</summary>

**If SAME SessionId**:
- Same authentication session
- Token was used from both locations
- Likely **token theft** (attacker stole valid token)
- OR legitimate VPN switch mid-session

**If DIFFERENT SessionIds**:
- Two separate authentication events
- Need to check which one had MFA (initial auth)
- One SessionId is legitimate, other may be attacker

</details>

### Task 2.3: Trace Complete Authentication Chain (Nigeria SessionId)

```kql
let targetSessionId = "<NIGERIA_SESSIONID>";  // From Task 2.1
let start = datetime(2026-01-15 12:00);
let end = datetime(2026-01-15 16:00);

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
    ResultType,
    ResultDescription
| order by TimeGenerated asc
```

**Find the FIRST event** (earliest timestamp):
- Time: _____
- Location: _____
- AuthenticationRequirement: _____

**Decision Matrix**:

| First Event Location | First Event Auth | Conclusion |
|---------------------|------------------|------------|
| Nigeria | multiFactorAuthentication | **COMPROMISED** - Attacker authenticated directly from Nigeria |
| Seattle | multiFactorAuthentication | **FALSE POSITIVE** - Legitimate auth, then VPN/travel to Nigeria |
| Seattle | singleFactorAuthentication | **INCONCLUSIVE** - Need to check earlier SessionId |

**Your Determination**: [COMPROMISED / FALSE POSITIVE / INCONCLUSIVE]

✅ **Checkpoint**: You've completed SessionId forensic analysis

---

## 📝 Exercise 3: IP Enrichment & Threat Intelligence

**Objective**: Assess risk level of both IPs involved.

### Task 3.1: Enrich Seattle IP

**Prompt**:
```
Enrich IP 198.51.100.XXX
```

**Or manual**:
```powershell
python enrichment/enrich_ips.py 198.51.100.XXX
```

**Document findings**:
```json
{
  "ip": "198.51.100.XXX",
  "city": "Seattle",
  "region": "Washington",
  "country": "US",
  "org": "[ISP/ORG NAME]",
  "is_vpn": [true/false],
  "is_proxy": [true/false],
  "is_tor": false,
  "abuse_confidence_score": [SCORE],
  "threat_description": "[DESCRIPTION]",
  "risk_level": "[HIGH/MEDIUM/LOW]"
}
```

### Task 3.2: Enrich Nigeria IP

```powershell
python enrichment/enrich_ips.py 102.88.XXX.XXX
```

**Document findings**:
```json
{
  "ip": "102.88.XXX.XXX",
  "city": "Lagos",
  "region": "Lagos",
  "country": "NG",
  "org": "[ISP/ORG NAME]",
  "is_vpn": [true/false],
  "is_proxy": [true/false],
  "is_tor": false,
  "abuse_confidence_score": [SCORE],
  "threat_description": "[DESCRIPTION]",
  "risk_level": "[HIGH/MEDIUM/LOW]"
}
```

### Task 3.3: Apply Risk Assessment Criteria

**Risk Scoring** (from Investigation Guide Section 9):

| Factor | Seattle IP | Nigeria IP |
|--------|-----------|------------|
| Abuse Score > 50 | [Yes +3 / No 0] | [Yes +3 / No 0] |
| is_tor | [Yes +5 / No 0] | [Yes +5 / No 0] |
| is_vpn (non-corporate) | [Yes +1 / No 0] | [Yes +1 / No 0] |
| Threat description (malware/phishing) | [Yes +2 / No 0] | [Yes +2 / No 0] |
| Country != baseline | [Yes +1 / No 0] | [Yes +1 / No 0] |
| **Total Risk Score** | _____ | _____ |

**Risk Levels**:
- 0-2 points = LOW
- 3-5 points = MEDIUM
- 6-8 points = HIGH
- 9+ points = CRITICAL

**Interpretation**:
- Seattle IP Risk: [LOW/MEDIUM/HIGH/CRITICAL]
- Nigeria IP Risk: [LOW/MEDIUM/HIGH/CRITICAL]

✅ **Checkpoint**: You have threat intelligence assessment

---

## 📝 Exercise 4: Post-Compromise Activity Analysis

**Objective**: Determine what the attacker did after gaining access.

### Task 4.1: Search for Persistence Mechanisms

**Check for inbox rules**:
```kql
let upn = "marcus.rodriguez@alpineskihouse.co";
let start = datetime(2026-01-15 14:00);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountDisplayName has "marcus" or AccountObjectId has upn
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleDetails = parse_json(RawEventData)
| project 
    TimeGenerated,
    ActionType,
    RuleName = tostring(RuleDetails.Parameters[0].Value),
    IPAddress,
    AccountDisplayName
```

**Expected**: Empty result (no rules) OR malicious rule found

**Check for OAuth app delegations**:
```kql
let upn = "marcus.rodriguez@alpineskihouse.co";
let start = datetime(2026-01-15 14:00);
let end = datetime(2026-01-17);

AuditLogs
| where TimeGenerated between (start .. end)
| where Identity =~ upn or tostring(InitiatedBy) has upn
| where OperationName in (
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant"
)
| extend 
    TargetApp = tostring(TargetResources[0].displayName),
    Permissions = tostring(TargetResources[0].modifiedProperties)
| project 
    TimeGenerated,
    TargetApp,
    Permissions,
    IPAddress,
    Result
```

**Expected**: Empty OR suspicious app with broad permissions

### Task 4.2: Check for Data Exfiltration

**Mass file downloads**:
```kql
let upn = "marcus.rodriguez@alpineskihouse.co";
let start = datetime(2026-01-15 14:00);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountDisplayName has "marcus" or AccountObjectId has upn
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded", "FileAccessed")
| summarize 
    FileCount = count(),
    FileNames = make_set(ObjectName, 20),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by IPAddress, bin(TimeGenerated, 15m)
| where FileCount >= 10  // 10+ files in 15 min = suspicious
| order by TimeGenerated asc
```

**External sharing**:
```kql
let upn = "marcus.rodriguez@alpineskihouse.co";
let start = datetime(2026-01-15 14:00);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountDisplayName has "marcus" or AccountObjectId has upn
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("SharingSet", "AnonymousLinkCreated", "AddedToSecureLink")
| extend RawData = parse_json(RawEventData)
| extend 
    FileName = tostring(ObjectName),
    TargetUser = tostring(RawData.TargetUserOrGroupName)
| project 
    TimeGenerated,
    FileName,
    TargetUser,
    ActionType,
    IPAddress
```

**Document findings**:
```
Post-Compromise Activity:
- Inbox rules created: [Yes/No] - [Details]
- OAuth apps delegated: [Yes/No] - [App names]
- Files downloaded: [COUNT] - [From which IP?]
- External sharing: [Yes/No] - [Files shared]
```

✅ **Checkpoint**: You've identified post-compromise activity

---

## 📝 Exercise 5: Final Determination & Report

**Objective**: Make definitive compromise determination and create formal report.

### Task 5.1: Apply Decision Framework

**Critical Evidence Checklist**:

| Evidence Type | Finding | Weight | Your Answer |
|--------------|---------|--------|-------------|
| SessionId comparison | Same = token theft | HIGH | [SAME/DIFFERENT] |
| Initial MFA location | Nigeria = compromise | CRITICAL | [SEATTLE/NIGERIA] |
| Nigeria IP abuse score | >50 = high risk | MEDIUM | [SCORE: ___] |
| Seattle IP risk | Known VPN = false positive | MEDIUM | [RISK: ___] |
| Persistence mechanisms | Found = compromise | HIGH | [FOUND/NOT FOUND] |
| Data exfiltration | Found = compromise | CRITICAL | [FOUND/NOT FOUND] |
| User travel verification | Confirmed travel = false positive | HIGH | [CONFIRMED/NOT CONFIRMED] |

**Determination Framework**:

```
IF (Initial MFA from Nigeria) 
   AND (Nigeria IP abuse > 50)
   THEN COMPROMISED

ELSE IF (Initial MFA from Seattle)
   AND (Seattle IP is corporate VPN)
   THEN FALSE POSITIVE

ELSE IF (Same SessionId from both locations)
   AND (No VPN detected)
   THEN TOKEN THEFT → COMPROMISED

ELSE
   INVESTIGATE FURTHER
```

**Your Final Determination**: [COMPROMISED / FALSE POSITIVE / INCONCLUSIVE]

**Confidence Level**: [HIGH / MEDIUM / LOW]

**Justification** (2-3 sentences):
```
[Explain your reasoning based on evidence above]
```

### Task 5.2: Create Investigation Report

Use the Incident Report template from Lab 105, but customize for this scenario:

**Key Sections to Complete**:
1. **Executive Summary**: Was Marcus compromised? If yes, how?
2. **SessionId Forensics**: Which SessionId had the initial MFA? Where?
3. **Geographic Analysis**: Is Nigeria travel expected for this user?
4. **IP Threat Intelligence**: Risk scores and abuse reports for both IPs
5. **Post-Compromise Timeline**: What did attacker do after access?
6. **Remediation Actions**: Sessions revoked? Password reset? Account status?
7. **Recommendations**: How to prevent this in future?

**Generate HTML Report**:
```
Run investigation for marcus.rodriguez@alpineskihouse.co from 2026-01-08
```

**Add custom section** to report with SessionId analysis findings.

✅ **Checkpoint**: Investigation complete with formal documentation

---

## 📝 Exercise 6: Remediation & Closure

**Objective**: If compromised, execute remediation plan.

### Remediation Workflow (if COMPROMISED)

**Immediate (within 30 minutes)**:
1. [ ] Revoke all refresh tokens
2. [ ] Force password reset
3. [ ] Disable account temporarily
4. [ ] Delete malicious inbox rules (if any)
5. [ ] Revoke OAuth app delegations (if any)

**Short-term (within 24 hours)**:
6. [ ] Interview user: How did compromise occur?
7. [ ] Device forensics: Check Marcus's devices for malware
8. [ ] Email search: Find phishing email that led to compromise
9. [ ] Re-enable account with new password + MFA re-registration
10. [ ] Monitor for 48 hours (any new suspicious activity?)

**Long-term (within 30 days)**:
11. [ ] Implement Conditional Access: Block sign-ins from Nigeria
12. [ ] Enable number matching MFA (prevent MFA fatigue)
13. [ ] Security awareness training for user
14. [ ] Add Nigeria IP to block list (if not legitimate)

### Remediation Verification Queries

**Verify sessions revoked**:
```kql
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1h)
| where UserPrincipalName =~ "marcus.rodriguez@alpineskihouse.co"
| where IPAddress == "102.88.XXX.XXX"
| project TimeGenerated, IPAddress, AppDisplayName, ResultType
```
**Expected**: 0 results (no new sign-ins from Nigeria)

**Verify password reset**:
```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where TargetResources[0].userPrincipalName =~ "marcus.rodriguez@alpineskihouse.co"
| where OperationName == "Reset password (by admin)"
| project TimeGenerated, OperationName, Result, InitiatedBy
```
**Expected**: 1 result showing password reset

✅ **Checkpoint**: Remediation complete and verified

---

## ✅ Lab Validation Checklist

Before completing this lab, verify you can:

- [ ] Investigate impossible travel scenarios systematically
- [ ] Extract and compare SessionIds from multiple IPs
- [ ] Identify initial MFA authentication event
- [ ] Distinguish token theft from legitimate VPN usage
- [ ] Apply IP enrichment risk criteria
- [ ] Search for post-compromise indicators (persistence, exfiltration)
- [ ] Make high-confidence compromise determination
- [ ] Execute remediation workflow
- [ ] Verify remediation actions successful
- [ ] Document findings in formal report

---

## 🎓 Key Takeaways

**Impossible Travel Investigation Process**:
```
Alert → Extract SessionIds → Compare → Trace Initial MFA → IP Enrichment → 
Post-Compromise Analysis → Determination → Remediation → Verification
```

**Critical Decision Points**:
1. **Same vs Different SessionId**: Token theft vs separate authentications
2. **Initial MFA Location**: Where did the user actually authenticate?
3. **IP Risk Level**: High abuse score = likely compromise
4. **VPN Detection**: Legitimate VPN explains impossible travel
5. **User Verification**: Ask user directly about travel/VPN

**Common False Positives**:
- Corporate VPN with international endpoints
- Legitimate business travel (verify with calendar/manager)
- Cloud service provider IP pooling (Azure, AWS proxies)
- User on airplane WiFi (location data inaccurate)

**Definitive Compromise Indicators**:
- Initial MFA from high-risk foreign IP (abuse score >50)
- Post-compromise activity (inbox rules, OAuth apps, mass downloads)
- User denies travel and doesn't use VPN
- SessionId shows token used from impossible locations

---

## 🚀 Next Steps

**Continue to [Lab 203: Insider Threat Investigation](../203-insider-threat/)**

Or **practice with real alerts**:
1. Find Identity Protection alerts in your environment
2. Apply this lab's methodology
3. Present findings to team
4. Track false positive vs true positive rate

**Advanced Exercises**:
- Investigate account with 3+ countries in same day
- Analyze MFA fatigue attack scenario
- Trace lateral movement after initial compromise

---

## 📚 Additional Resources

- [Investigation Guide - Section 9: SessionId Tracing](../../Investigation-Guide.md#9-advanced-authentication-analysis)
- [Investigation Guide - Real-World Example: Geographic Anomaly](../../Investigation-Guide.md#real-world-example-geographic-anomaly-investigation)
- [Lab 103: Advanced Authentication Analysis](../103-advanced-auth-analysis/)
- [MITRE ATT&CK: Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)

---

## ❓ FAQ

**Q: What if user confirms they were traveling to Nigeria?**  
A: Verify with:
- Corporate travel system records
- Calendar for "Out of Office" or travel events
- Manager confirmation
- Email sent from Nigeria (EmailEvents with IP correlation)
If confirmed legitimate, close as FALSE POSITIVE and update alert logic.

**Q: What if both SessionIds are DIFFERENT but both from suspicious IPs?**  
A: Two separate compromises OR attacker using multiple tokens. Investigate each SessionId independently, revoke ALL sessions, force password reset.

**Q: How do I know if it's a VPN IP?**  
A: Check enrichment data (`is_vpn: true`), cross-reference with corporate VPN IP ranges, ask user "Were you using VPN?"

**Q: User has MFA but still got compromised. How?**  
A: Common methods:
- **MFA Fatigue**: Attacker spams MFA requests until user approves
- **Session Cookie Theft**: Steals cookie after MFA (tool: Evilginx2)
- **OAuth Phishing**: User grants permissions to malicious app
- **SIM Swap**: Attacker takes over phone number for SMS MFA

---

**Congratulations!** You can now investigate complex identity compromise scenarios with SessionId forensics and make definitive determinations with high confidence.
