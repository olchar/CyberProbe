# Lab 104: Threat Hunting with Advanced KQL

**Duration**: 60 minutes  
**Difficulty**: Advanced  
**Prerequisites**: Labs 101-103

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Hunt for lateral movement using authentication patterns
- ✅ Detect persistence mechanisms in Azure AD
- ✅ Identify credential dumping attempts
- ✅ Find suspicious PowerShell activity
- ✅ Detect data staging for exfiltration
- ✅ Use advanced KQL techniques (join, make-series, arg_max)
- ✅ Create custom threat hunting queries

---

## 📖 Background

Threat hunting is the **proactive search** for threats that haven't triggered alerts. Instead of waiting for incidents, you search for indicators of compromise (IOCs) and suspicious behaviors using hypothesis-driven queries.

This lab focuses on post-compromise activity hunting - what attackers do AFTER gaining initial access:
- **Lateral Movement**: Spreading to other accounts/systems
- **Persistence**: Maintaining long-term access
- **Credential Access**: Stealing additional credentials
- **Exfiltration Staging**: Preparing data for theft

---

## 🎯 Threat Hunting Scenarios

### Scenario 1: Lateral Movement Detection
### Scenario 2: Persistence Mechanism Hunting
### Scenario 3: Credential Dumping Indicators
### Scenario 4: Data Staging & Exfiltration

---

## 📝 Exercise 1: Hunt for Lateral Movement

**Objective**: Detect authentication patterns indicating lateral movement across accounts.

### Task 1.1: Identify Rapid Account Switching

Attackers with compromised credentials often access multiple accounts in short timeframes:

```kql
let timeWindow = 1h;
let minAccounts = 3;
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where ResultType == "0"  // Successful only
| summarize 
    UniqueAccounts = dcount(UserPrincipalName),
    AccountsList = make_set(UserPrincipalName),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by IPAddress, bin(TimeGenerated, timeWindow)
| where UniqueAccounts >= minAccounts
| extend Duration = datetime_diff('minute', LastAccess, FirstAccess)
| project 
    TimeWindow = TimeGenerated,
    IPAddress,
    UniqueAccounts,
    Duration,
    AccountsList
| order by UniqueAccounts desc
```

**Threat Pattern**: Single IP accessing 3+ different user accounts within 1 hour

**Question**: What's suspicious about this pattern?

<details>
<summary>💡 Answer</summary>

**Normal**: Shared workstation, conference room PC (same building)
**Suspicious**: 
- Accounts from different departments/buildings
- Accounts that normally never overlap
- Pattern occurs after hours (2 AM)
- IP is residential/VPN, not corporate network

**Follow-up**: Check if accounts have shared device history or physical proximity

</details>

### Task 1.2: Detect Impossible Authentication Sequences

Find accounts signing in from geographically impossible locations:

```kql
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);
let minDistance = 500;  // Miles
let maxTime = 30;  // Minutes

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where ResultType == "0"
| extend LocationDetails = parse_json(LocationDetails)
| extend 
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    Lat = toreal(LocationDetails.geoCoordinates.latitude),
    Lon = toreal(LocationDetails.geoCoordinates.longitude)
| where isnotempty(City) and isnotempty(Lat)
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country, Lat, Lon
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend 
    NextTime = next(TimeGenerated, 1),
    NextUser = next(UserPrincipalName, 1),
    NextCity = next(City, 1),
    NextLat = next(Lat, 1),
    NextLon = next(Lon, 1)
| where UserPrincipalName == NextUser
| extend 
    TimeDiff = datetime_diff('minute', NextTime, TimeGenerated),
    // Haversine distance approximation
    Distance = 3959 * acos(
        cos(radians(Lat)) * cos(radians(NextLat)) * 
        cos(radians(NextLon) - radians(Lon)) + 
        sin(radians(Lat)) * sin(radians(NextLat))
    )
| where Distance > minDistance and TimeDiff < maxTime
| project 
    UserPrincipalName,
    TimeGenerated,
    FirstLocation = strcat(City, ", ", Country),
    FirstIP = IPAddress,
    TimeDiff,
    NextLocation = strcat(NextCity),
    Distance_Miles = round(Distance, 0)
| order by Distance_Miles desc
```

**Threat Pattern**: User in Seattle at 9:00 AM, then Lagos at 9:15 AM (4,773 miles)

**Hunting Tip**: Distance > 500 miles in < 30 minutes = **physically impossible** unless VPN switch

✅ **Checkpoint**: You can detect impossible travel patterns

---

## 📝 Exercise 2: Hunt for Persistence Mechanisms

**Objective**: Find indicators of attackers establishing persistence in Azure AD.

### Task 2.1: Detect Suspicious OAuth App Delegations

Attackers grant OAuth permissions to malicious apps for persistent access:

```kql
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);

AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName in (
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant"
)
| extend 
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    TargetApp = tostring(TargetResources[0].displayName),
    Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.Read", "Files.ReadWrite.All", "Directory.ReadWrite.All")
| project 
    TimeGenerated,
    InitiatedByUser,
    TargetApp,
    OperationName,
    Permissions,
    Result
| order by TimeGenerated desc
```

**Suspicious Permissions**:
- `Mail.Read` / `Mail.ReadWrite` - Reads emails
- `Files.ReadWrite.All` - Accesses all SharePoint/OneDrive files
- `Directory.ReadWrite.All` - Can create users, reset passwords
- `offline_access` - Can refresh tokens indefinitely

**Red Flags**:
- User grants permissions to unknown/new app
- Permissions granted during off-hours
- App name is generic ("Office 365 Helper", "Security Tool")
- User recently had risky sign-in

### Task 2.2: Hunt for Malicious Inbox Rules

Attackers create inbox rules to hide activity or exfiltrate emails:

```kql
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleDetails = parse_json(RawEventData)
| extend 
    RuleName = tostring(RuleDetails.Parameters[0].Value),
    ForwardTo = tostring(RuleDetails.Parameters[1].Value),
    DeleteMessage = tostring(RuleDetails.Parameters[2].Value)
| where ForwardTo has "@" or DeleteMessage == "True"
| project 
    TimeGenerated,
    AccountObjectId,
    RuleName,
    ForwardTo,
    DeleteMessage,
    IPAddress
| order by TimeGenerated desc
```

**Suspicious Patterns**:
- Rules that **delete messages** (hide activity)
- Rules that **forward to external addresses**
- Rule names like ".", "..", "" (trying to hide)
- Created immediately after risky sign-in

✅ **Checkpoint**: You can detect common persistence techniques

---

## 📝 Exercise 3: Hunt for Credential Access

**Objective**: Detect attempts to steal or dump credentials.

### Task 3.1: Detect Password Spray Attacks

Attackers try common passwords against many accounts:

```kql
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);
let threshold = 10;  // Failures across 10+ accounts from single IP

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where ResultType != "0"  // Failed sign-ins only
| summarize 
    FailedAccounts = dcount(UserPrincipalName),
    AccountsList = make_set(UserPrincipalName),
    TotalAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    ErrorCodes = make_set(ResultType)
    by IPAddress, bin(TimeGenerated, 1h)
| where FailedAccounts >= threshold
| extend Duration = datetime_diff('minute', LastAttempt, FirstAttempt)
| project 
    TimeWindow = TimeGenerated,
    IPAddress,
    FailedAccounts,
    TotalAttempts,
    Duration,
    ErrorCodes
| order by FailedAccounts desc
```

**Indicators**:
- Same IP failing against 10+ different users
- Short duration (password spray is fast)
- Error code 50126 (invalid username or password)
- Evenly distributed across accounts (not targeting specific users)

### Task 3.2: Detect Token Replay Attacks

Stolen tokens being reused from unusual locations:

```kql
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);

union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where ResultType == "0"
| where AuthenticationRequirement == "singleFactorAuthentication"  // Token-based
| extend LocationDetails = parse_json(LocationDetails)
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize 
    Countries = make_set(Country),
    CountryCount = dcount(Country),
    IPs = make_set(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, SessionId
| where CountryCount > 1  // Token used from multiple countries
| project 
    UserPrincipalName,
    SessionId,
    CountryCount,
    Countries,
    IPs,
    FirstSeen,
    LastSeen
| order by CountryCount desc
```

**Suspicious Pattern**: Same SessionId (token) used from multiple countries = **token theft**

✅ **Checkpoint**: You can hunt for credential theft indicators

---

## 📝 Exercise 4: Hunt for Data Exfiltration Staging

**Objective**: Detect data being collected for exfiltration.

### Task 4.1: Detect Mass File Downloads

Attackers download many files in preparation for exfiltration:

```kql
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);
let threshold = 50;  // 50+ files in short period

CloudAppEvents
| where TimeGenerated between (start .. end)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded", "FileAccessed")
| summarize 
    FileCount = count(),
    UniqueFiles = dcount(ObjectId),
    FileNames = make_set(ObjectName, 10),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by AccountObjectId, IPAddress, bin(TimeGenerated, 1h)
| where FileCount >= threshold
| extend Duration = datetime_diff('minute', LastAccess, FirstAccess)
| project 
    TimeWindow = TimeGenerated,
    AccountObjectId,
    IPAddress,
    FileCount,
    Duration,
    FileNames
| order by FileCount desc
```

**Red Flags**:
- 50+ files in < 30 minutes (automated tool)
- File names contain "Financial", "Confidential", "Password"
- User has recent risky sign-in
- IP is residential/VPN, not corporate

### Task 4.2: Detect Sensitive File Sharing

Finding sensitive documents shared externally:

```kql
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("SharingSet", "AnonymousLinkCreated", "AddedToSecureLink")
| extend RawData = parse_json(RawEventData)
| extend 
    FileName = tostring(ObjectName),
    TargetUser = tostring(RawData.TargetUserOrGroupName),
    SharingType = tostring(RawData.SharingType)
| where TargetUser has "@" and TargetUser !endswith "@yourdomain.com"  // External sharing
| project 
    TimeGenerated,
    AccountObjectId,
    FileName,
    TargetUser,
    SharingType,
    IPAddress
| order by TimeGenerated desc
```

**Suspicious Patterns**:
- Sharing "Financial", "Confidential", "HR" documents
- Sharing to personal email (@gmail.com, @yahoo.com)
- Anonymous links created (no recipient tracking)
- Mass sharing event (many files at once)

✅ **Checkpoint**: You can detect exfiltration preparation

---

## 📝 Exercise 5: Create Custom Hunting Query

**Objective**: Design your own threat hunting query for a specific scenario.

### Task 5.1: Choose a Hunting Hypothesis

Select one scenario to hunt:

**Option A: Compromised Service Account**
- Hypothesis: Service accounts signing in interactively (should be non-interactive only)
- Data source: SigninLogs (NOT AADNonInteractiveUserSignInLogs)
- Filter: UserPrincipalName contains "svc" or "service" or "app"
- Red flag: Interactive sign-in from service account

**Option B: After-Hours Administrative Activity**
- Hypothesis: Privileged role changes during off-hours (10 PM - 6 AM)
- Data source: AuditLogs
- Filter: OperationName contains "Add member to role" AND time between 22:00-06:00
- Red flag: Admin role granted at 3 AM

**Option C: Anomalous Application Access**
- Hypothesis: Users accessing apps they've never used before
- Data source: SigninLogs
- Logic: New app per user (not in 90-day baseline)
- Red flag: First-time access to admin portal after risky sign-in

### Task 5.2: Write the Query

**Template**:
```kql
// Hunting Query: [YOUR HYPOTHESIS]
// Author: [YOUR NAME]
// Date: 2026-01-15

let start = datetime(2026-01-08);
let end = datetime(2026-01-17);

// [YOUR QUERY HERE]
| where TimeGenerated between (start .. end)
| where [FILTER CONDITIONS]
| summarize [AGGREGATIONS] by [GROUP BY FIELDS]
| where [THRESHOLD CONDITIONS]
| project [RELEVANT COLUMNS]
| order by [SORT ORDER]
```

**Share your query** with the instructor for feedback!

---

## ✅ Lab Validation Checklist

Before completing this lab, verify you can:

- [ ] Hunt for lateral movement using authentication patterns
- [ ] Detect impossible travel using geographic calculations
- [ ] Find OAuth app delegations with risky permissions
- [ ] Identify malicious inbox rules (forwarding, deletion)
- [ ] Detect password spray attacks (threshold-based)
- [ ] Hunt for token replay across countries
- [ ] Find mass file download patterns
- [ ] Detect sensitive file external sharing
- [ ] Create custom hunting queries from hypotheses
- [ ] Use advanced KQL (serialize, make-series, joins)

---

## 🎓 Key Takeaways

**Hunting Methodology**:
```
Hypothesis → Data Source → Query → Threshold → Validation → Action
```

**Advanced KQL Techniques**:
- `serialize` + `next()`: Compare current row to next row (time-series analysis)
- `make_set()`: Collect distinct values into array
- `dcount()`: Count unique values
- `bin()`: Time bucketing for aggregations
- `arg_max()`: Get entire row with max value
- `datetime_diff()`: Calculate time differences

**Common Thresholds**:
- Lateral movement: 3+ accounts from 1 IP in 1 hour
- Password spray: 10+ failed accounts from 1 IP
- Impossible travel: 500+ miles in < 30 minutes
- Mass download: 50+ files in 1 hour
- After-hours: Activity between 22:00-06:00 local time

**Hunting Schedule**:
- **Daily**: Password spray, impossible travel
- **Weekly**: Lateral movement, OAuth delegations
- **Monthly**: Persistence mechanisms, sensitive sharing
- **Ad-hoc**: Based on threat intelligence

---

## 🚀 Next Steps

**Continue to [Lab 105: Incident Response](../105-incident-response/)**

Or **build a threat hunting dashboard**:
1. Create Azure Monitor Workbook
2. Add queries from this lab as tiles
3. Schedule daily/weekly refresh
4. Share with SOC team

**Practice Hunting**:
- Run each query against your production environment
- Document findings in hunting log
- Tune thresholds based on baseline
- Create automated alerts for high-confidence patterns

---

## 📚 Additional Resources

- [MITRE ATT&CK for Azure AD](https://attack.mitre.org/matrices/enterprise/cloud/azuread/)
- [Microsoft Threat Hunting Guide](https://docs.microsoft.com/en-us/azure/sentinel/hunting)
- [KQL Quick Reference](https://docs.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [Investigation Guide - Section 8: Sample Queries](../../Investigation-Guide.md#8-kql-query-samples)

---

## ❓ FAQ

**Q: How do I know what's a good threshold (e.g., 10+ accounts vs 5+)?**  
A: Start conservative (higher threshold), hunt for 2 weeks, review findings, then tune. Your environment's baseline determines ideal thresholds.

**Q: These queries return too many results. How do I filter noise?**  
A: Add exclusions for known patterns:
- Known VPN IP ranges
- Service accounts (expected non-interactive)
- Legitimate shared workstations
- Corporate travel patterns

**Q: Should I create alerts from hunting queries?**  
A: Only after validation! Hunt manually for 2-4 weeks, confirm pattern is reliable, THEN automate as alert.

**Q: How often should I hunt?**  
A: Start with weekly 2-hour hunting sessions. As you build query library, automate high-confidence queries and focus hunting on new hypotheses.

---

**Congratulations!** You've mastered proactive threat hunting with advanced KQL. You can now search for hidden threats before they trigger alerts.
