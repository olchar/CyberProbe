# Lab 103: Advanced Authentication Analysis

**Duration**: 60 minutes  
**Difficulty**: Intermediate  
**Prerequisites**: Labs 101, 102

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Extract SessionId from suspicious sign-in events
- ✅ Trace complete authentication chains using SessionId
- ✅ Identify initial MFA authentication vs token refreshes
- ✅ Extract all IPs from a session for threat intelligence
- ✅ Analyze IP enrichment data to assess risk
- ✅ Document forensic findings with confidence levels
- ✅ Determine if geographic anomalies indicate compromise

---

## 📖 Background

This lab teaches **SessionId-based forensic tracing** - the gold standard for authentication analysis described in **Investigation Guide Section 9**.

When Identity Protection flags an anomalous sign-in (impossible travel, unfamiliar location, risky IP), you need to answer:
- **Was this account actually compromised?**
- **Or is this a false positive?** (VPN, legitimate travel, etc.)

SessionId tracing lets you trace the ENTIRE authentication chain to find the exact moment and method of initial login, definitively answering these questions.

---

## 🔬 Investigation Scenario

**Alert Received**: January 15, 2026, 09:15 PST

```
🚨 IDENTITY PROTECTION ALERT
User: alexj@contoso.com
Risk Level: High
Risk Type: Impossible Travel
Description: User signed in from Lagos, Nigeria, 15 minutes after 
             sign-in from Seattle, WA (4,773 miles apart)
Suspicious IP: 41.60.XXX.XXX (Lagos, Nigeria)
```

**Your Mission**: Determine if Alex's account was compromised or if this is legitimate activity.

---

## 📝 Exercise 1: Extract SessionId from Suspicious IP

**Objective**: Get the SessionId from the Nigerian sign-in to enable forensic tracing.

### Task 1.1: Identify the Suspicious Sign-in

Query sign-ins from the suspicious IP:

```kql
let suspiciousIP = "41.60.XXX.XXX";  // Replace with actual IP from alert
let userUPN = "alexj@contoso.com";  // Replace with actual user
let alertTime = datetime(2026-01-15 09:15:00);  // Alert timestamp

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((alertTime - 30m) .. (alertTime + 30m))
| where UserPrincipalName =~ userUPN
| where IPAddress == suspiciousIP
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
    AuthenticationRequirement,
    SessionId
| order by TimeGenerated asc
```

**Expected Output**: Multiple sign-ins from Lagos, Nigeria IP

**Question**: Are all sign-ins from this IP using the same SessionId?

<details>
<summary>✅ Answer</summary>

Yes! SessionId persists across all sign-ins within the same session (including token refreshes and app access). This is what makes it valuable for forensic tracing.

</details>

### Task 1.2: Extract the SessionId

**⚠️ Critical**: SessionId might be empty for some sign-ins!

```kql
let suspiciousIP = "41.60.XXX.XXX";  // Replace
let userUPN = "alexj@contoso.com";  // Replace

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(2h)  // Narrow window around alert
| where UserPrincipalName =~ userUPN
| where IPAddress == suspiciousIP
| where isnotempty(SessionId)
| distinct SessionId
| take 1
```

**Expected Output**: Single SessionId string (example: `66f78a3c-e4d2-4b91-9f5e-2a1b8c7d9e6f`)

**Save this SessionId** - you'll use it throughout the lab!

✅ **Checkpoint**: You have extracted SessionId from suspicious IP

---

## 📝 Exercise 2: Trace Complete Authentication Chain

**Objective**: Use SessionId to reconstruct the entire session timeline.

### Task 2.1: Query All Events in Session

Using the SessionId from Exercise 1:

```kql
let targetSessionId = "<SESSIONID_FROM_EXERCISE_1>";  // REPLACE!
let start = datetime(2026-01-15 08:00);  // Expand around alert
let end = datetime(2026-01-15 12:00);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where SessionId == targetSessionId
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend State = tostring(LocationDetails.state)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend DeviceDetail = parse_json(DeviceDetail)
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend OS = tostring(DeviceDetail.operatingSystem)
| extend Browser = tostring(DeviceDetail.browser)
| project 
    TimeGenerated,
    AppDisplayName,
    IPAddress,
    City,
    State,
    Country,
    ResourceDisplayName,
    ResultType,
    ResultDescription,
    AuthenticationRequirement,
    DeviceId,
    OS,
    Browser
| order by TimeGenerated asc
```

**Expected Output**: Chronological timeline of ALL authentication events in the session

### Task 2.2: Analyze the Timeline

**Question**: What does the timeline reveal?

Look for these patterns:

**Pattern A: Compromised Account**
```
08:45 - Lagos, NG - Browser - multiFactorAuthentication (INITIAL AUTH)
08:52 - Lagos, NG - Exchange - singleFactorAuthentication (Token)
09:15 - Lagos, NG - SharePoint - singleFactorAuthentication (Token)
```
**Interpretation**: First event is from Nigeria with MFA → Attacker authenticated directly → **COMPROMISE CONFIRMED**

**Pattern B: Legitimate Activity**
```
08:30 - Seattle, WA - Browser - multiFactorAuthentication (INITIAL AUTH)
08:45 - Lagos, NG - Exchange - singleFactorAuthentication (Token)
09:15 - Lagos, NG - SharePoint - singleFactorAuthentication (Token)
```
**Interpretation**: First event is from Seattle → User authenticated legitimately → Then accessed apps from Nigeria (VPN or travel) → **FALSE POSITIVE**

**Your Analysis**:
- First event timestamp: _____
- First event location: _____
- First event AuthenticationRequirement: _____
- **Conclusion**: [Compromised / False Positive]

✅ **Checkpoint**: You can identify the initial authentication event

---

## 📝 Exercise 3: Identify Interactive MFA Event

**Objective**: Find the FIRST MFA authentication (the true login point).

### Task 3.1: Filter for MFA Events Only

```kql
let targetSessionId = "<SESSIONID_FROM_EXERCISE_1>";  // REPLACE!
let start = datetime(2026-01-15 08:00);
let end = datetime(2026-01-15 12:00);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where SessionId == targetSessionId
| where AuthenticationRequirement == "multiFactorAuthentication"
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize arg_min(TimeGenerated, *) by SessionId  // Get FIRST MFA event
| project 
    TimeGenerated, 
    IPAddress, 
    City,
    Country,
    AppDisplayName, 
    Location, 
    AuthenticationDetails
```

**Expected Output**: Single row showing the FIRST MFA authentication in the session

**Critical Rule**: The FIRST sign-in with `AuthenticationRequirement = "multiFactorAuthentication"` is the true authentication event. All subsequent events are token refreshes.

### Task 3.2: Interpret MFA Location

**Question**: Where did the initial MFA authentication occur?

- [ ] Seattle, WA (corporate office - **expected**)
- [ ] Lagos, Nigeria (unusual - **red flag**)
- [ ] VPN IP range (corporate VPN - **expected**)
- [ ] Home ISP (remote work - **expected**)

**Decision Matrix**:

| Initial MFA Location | Risk | Action |
|---------------------|------|--------|
| Corporate office/VPN | Low | Likely false positive - monitor |
| Unusual foreign country | High | Likely compromise - force reset |
| Home ISP | Medium | Check IP reputation, user travel history |

**Your Assessment**:
- Initial MFA Location: _____
- Risk Level: [High/Medium/Low]
- Recommended Action: _____

---

## 📝 Exercise 4: Extract All IPs in Session

**Objective**: Get all IPs used in the session for threat intelligence enrichment.

### Task 4.1: Query Unique IPs

```kql
let targetSessionId = "<SESSIONID_FROM_EXERCISE_1>";  // REPLACE!
let start = datetime(2026-01-15 08:00);
let end = datetime(2026-01-15 12:00);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
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

**Expected Output**: List of IP addresses (typically 1-3 IPs per session)

**Save these IPs** - you'll enrich them in Exercise 5!

### Task 4.2: Understand IP Changes Mid-Session

**Question**: If the SessionId has MULTIPLE IPs, what does that indicate?

<details>
<summary>💡 Answer</summary>

**Multiple IPs in same SessionId = Potential Session Hijacking / Token Theft**

Scenarios:
1. **Normal**: User on VPN switches between VPN and home network (common)
2. **Normal**: Load balancer cycling through IP pool (corporate VPN)
3. **Suspicious**: IP changes to different country mid-session (token theft)
4. **Suspicious**: IP changes from corporate to Tor exit node (session hijacking)

**Key**: Check if IP change aligns with expected user behavior (VPN, travel, etc.)

</details>

✅ **Checkpoint**: You have all IPs from the session

---

## 📝 Exercise 5: Analyze IP Enrichment Data

**Objective**: Use IP enrichment to assess risk of each IP in the session.

### Task 5.1: Enrich IPs with Threat Intelligence

**Option A: From Investigation JSON** (if you ran Lab 102 investigation):
```
Read reports/investigation_alexj_2026-01-15.json
→ Find "ip_enrichment" array
→ Filter by IP addresses from Exercise 4
```

**Option B: Manual Enrichment** (if no JSON):
```powershell
# From CyberProbe root directory
python enrichment/enrich_ips.py 41.60.XXX.XXX 198.51.100.XX
```

**Expected Output** (per IP):
```json
{
  "ip": "41.60.XXX.XXX",
  "city": "Lagos",
  "region": "Lagos",
  "country": "NG",
  "org": "AS37682 MainOne Cable Company",
  "is_vpn": false,
  "is_proxy": false,
  "is_tor": false,
  "abuse_confidence_score": 68,
  "threat_description": "Brute force attacks, credential stuffing",
  "risk_level": "HIGH"
}
```

### Task 5.2: Apply Risk Criteria

For each IP, assess risk using these criteria (from Investigation Guide Section 9):

**Automatic HIGH Risk**:
- ✅ `abuse_confidence_score > 50`
- ✅ `is_tor = true`
- ✅ `threat_description` contains "malware", "phishing", "botnet"

**Automatic MEDIUM Risk**:
- ✅ `is_vpn = true` (unless corporate VPN)
- ✅ `is_proxy = true`
- ✅ `abuse_confidence_score 25-50`
- ✅ Country != user's baseline country

**LOW Risk**:
- ✅ `abuse_confidence_score < 25`
- ✅ Corporate IP range
- ✅ Known VPN provider (NordVPN, ExpressVPN, etc.)

**Fill out this table**:

| IP Address | Country | VPN? | Abuse Score | Threat Desc | Risk Level |
|-----------|---------|------|-------------|-------------|------------|
| _____     | _____   | Y/N  | _____       | _____       | H/M/L      |
| _____     | _____   | Y/N  | _____       | _____       | H/M/L      |

---

## 📝 Exercise 6: Document Risk Assessment

**Objective**: Create a formal forensic report with your findings.

### Task 6.1: Complete Risk Assessment Template

```
SESSIONID FORENSIC ANALYSIS REPORT
====================================

SessionId: <YOUR_SESSIONID>
User: alexj@contoso.com
Investigation Date: 2026-01-15
Analyst: [Your Name]

INITIAL AUTHENTICATION
----------------------
Timestamp: <FIRST_MFA_TIMESTAMP>
IP Address: <FIRST_MFA_IP>
Location: <CITY, COUNTRY>
MFA Method: [Microsoft Authenticator App / SMS / etc.]
Device: <OS, BROWSER>

AUTHENTICATION CHAIN TIMELINE
------------------------------
<TIMESTAMP_1>: <IP> (<LOCATION>) - <APP> - <AUTH_TYPE>
<TIMESTAMP_2>: <IP> (<LOCATION>) - <APP> - <AUTH_TYPE>
<TIMESTAMP_3>: <IP> (<LOCATION>) - <APP> - <AUTH_TYPE>
...

IP ENRICHMENT SUMMARY
---------------------
IP 1: <IP_ADDRESS>
  - Location: <CITY, COUNTRY>
  - ISP: <ORG>
  - VPN: <YES/NO>
  - Abuse Score: <SCORE> (<RISK_LEVEL>)
  - Threat Intel: <DESCRIPTION>

IP 2: <IP_ADDRESS>
  - [Same format]

RISK CLASSIFICATION
-------------------
Overall Risk: [CRITICAL/HIGH/MEDIUM/LOW]

Risk Factors:
- [Factor 1: e.g., "Initial MFA from high-risk IP (Nigeria, abuse score 68)"]
- [Factor 2: e.g., "Impossible travel: Seattle → Lagos in 15 minutes"]
- [Factor 3: e.g., "IP flagged for brute force attacks"]

Mitigating Factors:
- [Factor 1: e.g., "User has documented travel to Nigeria this week"]
- [Factor 2: e.g., "Corporate VPN endpoint in region"]

CONCLUSION
----------
[COMPROMISED / FALSE POSITIVE / INCONCLUSIVE]

Justification:
<Explain your conclusion based on evidence above>

RECOMMENDED ACTION
------------------
[Choose one or more]:
- [ ] IMMEDIATE: Revoke all sessions, force password reset, disable account
- [ ] URGENT: Revoke sessions, force password reset
- [ ] MONITOR: Continue monitoring for 48 hours, no immediate action
- [ ] NO ACTION: False positive confirmed, update alert logic

Next Steps:
1. <Step 1>
2. <Step 2>
3. <Step 3>
```

### Task 6.2: Share with Team Lead

Present your findings to your instructor or team lead:

**Elevator Pitch** (30 seconds):
> "I investigated an impossible travel alert for Alex Johnson. SessionId tracing shows the initial MFA authentication came from [LOCATION] with IP [X.X.X.X], which has an abuse confidence score of [SCORE] and is flagged for [THREATS]. My assessment is [COMPROMISED/FALSE POSITIVE] based on [KEY EVIDENCE]. I recommend [ACTION]."

✅ **Checkpoint**: You can confidently explain your forensic findings

---

## ✅ Lab Validation Checklist

Before completing this lab, verify you can:

- [ ] Extract SessionId from a suspicious IP address
- [ ] Query all authentication events in a SessionId chain
- [ ] Identify the FIRST MFA event (initial authentication)
- [ ] Distinguish initial auth from token refreshes
- [ ] Extract all unique IPs from a session
- [ ] Apply risk criteria to IP enrichment data
- [ ] Determine if account was compromised vs false positive
- [ ] Document findings in forensic report format
- [ ] Make high-confidence remediation recommendations

---

## 🎓 Key Takeaways

**SessionId Forensic Principles**:
1. **SessionId = Complete Session** - Links ALL auth events (initial + refreshes)
2. **First MFA = Truth** - First event with MFA requirement is the real authentication
3. **Subsequent = Tokens** - All later events are token refreshes, not new logins
4. **IP Changes = Investigate** - Multiple IPs in same session requires scrutiny
5. **Enrichment = Context** - Abuse scores and threat intel inform risk assessment

**Investigation Flow**:
```
Suspicious IP Alert
      ↓
Extract SessionId from IP
      ↓
Trace Full Authentication Chain
      ↓
Find Initial MFA Event
      ↓
Extract All IPs in Session
      ↓
Enrich IPs with Threat Intel
      ↓
Apply Risk Criteria
      ↓
Document Assessment
      ↓
Recommend Action
```

**Common Scenarios**:

| Pattern | Initial MFA Location | Subsequent IPs | Conclusion |
|---------|---------------------|----------------|------------|
| **Legitimate VPN** | Corporate VPN → Home ISP | Expected | False Positive |
| **Legitimate Travel** | Home → Airport WiFi → Hotel | Expected | False Positive |
| **Credential Theft** | Attacker IP (high abuse) | Attacker continues | **COMPROMISED** |
| **Token Theft** | Legitimate → Attacker IP | IP change mid-session | **COMPROMISED** |
| **Session Hijacking** | Legitimate → Tor exit node | IP change mid-session | **COMPROMISED** |

---

## 🚀 Next Steps

**Continue to [Lab 104: Threat Hunting](../104-threat-hunting/)**

Or **apply SessionId tracing to real alerts**:
1. Find an Identity Protection alert in your environment
2. Extract SessionId from flagged IP
3. Complete full forensic analysis
4. Present findings to team

**Advanced Practice**:
- Investigate a user with multiple risky sign-ins in one day
- Compare SessionIds across different days (new session daily?)
- Trace a known compromised account to see the attack pattern

---

## 📚 Additional Resources

- [Investigation Guide - Section 9: SessionId Tracing](../../Investigation-Guide.md#9-advanced-authentication-analysis)
- [Investigation Guide - Section 9 Step 1: Extract SessionId](../../Investigation-Guide.md#step-1-extract-sessionid-from-suspicious-ip)
- [Investigation Guide - Section 9 Step 3: Identify Interactive MFA](../../Investigation-Guide.md#step-3-identify-interactive-mfa-event)
- [Real-World Example: Geographic Anomaly](../../Investigation-Guide.md#real-world-example-geographic-anomaly-investigation)

---

## ❓ FAQ

**Q: SessionId is empty for all sign-ins. What do I do?**  
A: Some sign-in types (service principals, managed identities) don't populate SessionId. Use time-window correlation (±5 minutes) and DeviceId matching as fallback.

**Q: I see multiple SessionIds for the same user on the same day. Is that normal?**  
A: Yes! SessionIds are created per authentication session. New browser tab, cleared cookies, or 24-hour expiration creates new SessionId.

**Q: How do I know if it's corporate VPN vs malicious VPN?**  
A: Check IP ownership (`org` field). Corporate VPNs have your company name. Malicious actors use commercial VPNs (NordVPN, ProtonVPN) or Tor.

**Q: User says they were traveling. How do I verify?**  
A: Check:
1. Corporate travel system (if integrated)
2. Calendar for "Out of Office" or travel events
3. Email sent from that location (EmailEvents table)
4. Manager confirmation

---

**Congratulations!** You've mastered SessionId-based forensic tracing - the most powerful technique for authentication analysis. You can now definitively determine account compromise vs false positives.
