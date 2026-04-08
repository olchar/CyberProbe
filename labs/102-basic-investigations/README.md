# Lab 102: Basic Security Investigations

**Duration**: 45 minutes  
**Difficulty**: Beginner  
**Prerequisites**: Lab 101

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Execute a standard 7-day user investigation workflow
- ✅ Query multiple data sources in parallel for efficiency
- ✅ Prioritize IPs for threat intelligence enrichment
- ✅ Export investigation data to JSON format
- ✅ Generate HTML investigation reports
- ✅ Interpret report sections and make security recommendations

---

## 📖 Background

This lab teaches the **Standard Investigation** workflow - the most common investigation type in CyberProbe. You'll investigate a user's security posture over the past 7 days, collecting data from:
- Sign-in logs (interactive and non-interactive)
- Anomaly detection system
- Security incidents and alerts
- Audit logs (Azure AD changes)
- Office 365 activity
- Threat intelligence

This is the core skill every CyberProbe analyst must master.

---

## 🛠️ Investigation Scenario

**Target User**: `testuser@yourdomain.com` (use your own test account)  
**Investigation Period**: Last 7 days  
**Investigation Type**: Standard (routine security review)  
**Trigger**: Scheduled monthly security review

---

## 📝 Exercise 1: Manual Investigation Workflow

**Objective**: Execute each phase of the investigation manually to understand the process.

### Phase 1: Get User Identity Information

**Prompt to Copilot:**
```
Get user profile for testuser@yourdomain.com including Object ID and Windows SID
```

**Manual Method** (Microsoft Graph):
```
/v1.0/users/testuser@yourdomain.com?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier,mail,department,jobTitle
```

**Save these values** - you'll need them for later queries:
- `id` (Azure AD Object ID): _______________
- `onPremisesSecurityIdentifier` (Windows SID): _______________

✅ **Checkpoint**: You have User Object ID and Windows SID

---

## 📝 Exercise 2: Parallel Data Collection

**Objective**: Query multiple data sources simultaneously for efficiency.

### Task 2.1: Calculate Date Range

Today is **January 15, 2026**. For "last 7 days":
- Start Date: `datetime(2026-01-08)` (7 days ago)
- End Date: `datetime(2026-01-17)` (today + 2 days per Rule 1)

**Why +2 days?** Timezone offset (PST behind UTC) + full day coverage. See Investigation Guide Section 8 - Date Range Reference.

### Task 2.2: Execute Batch 1 - Sentinel Queries

Run these queries **in parallel** (open multiple query windows):

**Query 1: Anomalies**
```kql
Signinlogs_Anomalies_KQL_CL
| where DetectedDateTime between (datetime(2026-01-08) .. datetime(2026-01-17))
| where UserPrincipalName =~ 'testuser@yourdomain.com'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10, "Medium",
    (CountryNovelty or CityNovelty or StateNovelty), "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| project DetectedDateTime, AnomalyType, Value, Severity, Country, City
| order by Severity, DetectedDateTime desc
| take 10
```

**Query 2: Sign-ins by Application**
```kql
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ 'testuser@yourdomain.com'
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    UniqueLocations=dcount(Location)
    by AppDisplayName
| order by SignInCount desc
| take 5
```

**Query 3: Sign-ins by Location**
```kql
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ 'testuser@yourdomain.com'
| where isnotempty(Location)
| summarize 
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress)
    by Location
| order by SignInCount desc
| take 5
```

**Query 4: Sign-in Failures**
```kql
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ 'testuser@yourdomain.com'
| where ResultType != '0'
| summarize 
    FailureCount=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated)
    by ResultType, ResultDescription
| order by FailureCount desc
| take 5
```

**Query 5: Audit Log Activity**
```kql
AuditLogs
| where TimeGenerated between (datetime(2026-01-08) .. datetime(2026-01-17))
| where Identity =~ 'testuser@yourdomain.com' or tostring(InitiatedBy) has 'testuser@yourdomain.com'
| summarize 
    Count=count(),
    Operations=make_set(OperationName, 10)
    by Category, Result
| order by Count desc
| take 10
```

✅ **Checkpoint**: You should have 5 query results. How many anomalies were detected?

---

## 📝 Exercise 3: IP Prioritization & Enrichment

**Objective**: Extract top priority IPs for threat intelligence enrichment.

### Task 3.1: Extract Top Priority IPs

Use **Query 1** from Investigation Guide Section 8:

```kql
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);
let upn = 'testuser@yourdomain.com';

// Priority 1: Anomaly IPs (top 8)
let anomaly_ips = 
    Signinlogs_Anomalies_KQL_CL
    | where DetectedDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where AnomalyType endswith "IP"
    | summarize AnomalyCount = count() by IPAddress = Value
    | top 8 by AnomalyCount desc
    | extend Priority = 1, Source = "Anomaly";

// Priority 2: Risky IPs (top 4 from pool of 10)
let risky_ips_pool = 
    AADUserRiskEvents
    | where ActivityDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where isnotempty(IpAddress)
    | summarize RiskCount = count() by IPAddress = IpAddress
    | top 10 by RiskCount desc
    | extend Priority = 2, Source = "RiskyIP";

// Priority 3: Frequent IPs (top 3 from pool of 10)
let frequent_ips_pool =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ upn
    | summarize SignInCount = count() by IPAddress
    | top 10 by SignInCount desc
    | extend Priority = 3, Source = "Frequent";

// Deduplicate and select top 15
let anomaly_ip_list = anomaly_ips | project IPAddress;
let priority_ip_list = union anomaly_ips, risky_ips_pool | project IPAddress;

let anomaly_slot = anomaly_ips | extend Count = AnomalyCount;
let risky_slot = risky_ips_pool 
    | join kind=anti anomaly_ip_list on IPAddress
    | top 4 by RiskCount desc
    | extend Count = RiskCount;
let frequent_slot = frequent_ips_pool 
    | join kind=anti priority_ip_list on IPAddress
    | top 3 by SignInCount desc
    | extend Count = SignInCount;

union anomaly_slot, risky_slot, frequent_slot
| project IPAddress, Priority, Count, Source
| order by Priority asc, Count desc
```

**Expected Output**: Up to 15 IPs (8 anomaly + 4 risky + 3 frequent)

### Task 3.2: Get Sign-in Counts for Priority IPs

For each IP from Task 3.1, get detailed sign-in information:

```kql
let target_ips = dynamic(["IP1", "IP2", "IP3"]);  // Replace with your IPs
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);
let upn = 'testuser@yourdomain.com';

// Get most recent sign-in per IP
let most_recent_signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ upn
| where IPAddress in (target_ips)
| summarize arg_max(TimeGenerated, *) by IPAddress;

// Expand authentication details
most_recent_signins
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend HasAuthDetails = array_length(AuthDetails) > 0
| mv-expand AuthDetail = iif(HasAuthDetails, AuthDetails, dynamic([{"authenticationStepResultDetail": ""}]))
| extend AuthStepResultDetail = tostring(AuthDetail.authenticationStepResultDetail)
| extend AuthPriority = case(
    AuthStepResultDetail has "MFA requirement satisfied", 1,
    AuthStepResultDetail has "Correct password", 2,
    999)
| summarize 
    MostRecentTime = any(TimeGenerated),
    MostRecentResultType = any(ResultType),
    MinPriority = min(AuthPriority),
    AllAuthDetails = make_set(AuthStepResultDetail)
    by IPAddress
| extend LastAuthResultDetail = case(
    MostRecentResultType != "0", "Authentication failed",
    MinPriority == 1, "MFA requirement satisfied by claim in the token",
    MinPriority == 2, "Correct password",
    "Token")
// Join for aggregate counts
| join kind=inner (
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ upn
    | where IPAddress in (target_ips)
    | summarize 
        SignInCount = count(),
        SuccessCount = countif(ResultType == '0'),
        FailureCount = countif(ResultType != '0'),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by IPAddress
) on IPAddress
| project IPAddress, SignInCount, SuccessCount, FailureCount, FirstSeen, LastSeen, LastAuthResultDetail
| order by SignInCount desc
```

✅ **Checkpoint**: You have sign-in counts and authentication details for priority IPs

---

## 📝 Exercise 4: Security Incidents & Alerts

**Objective**: Find security incidents involving this user.

### Task 4.1: Query Security Incidents

**⚠️ Critical**: This requires User Object ID AND Windows SID from Exercise 1!

```kql
let targetUPN = "testuser@yourdomain.com";
let targetUserId = "<USER_OBJECT_ID>";  // From Exercise 1
let targetSid = "<WINDOWS_SID>";  // From Exercise 1
let start = datetime(2026-01-08);
let end = datetime(2026-01-17);

let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetUPN or Entities has targetUserId or Entities has targetSid
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;

SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| summarize 
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime),
    AlertCount = count()
    by IncidentNumber
| order by CreatedTime desc
```

**Question**: How many incidents involve this user?

<details>
<summary>💡 Hint</summary>

If you get 0 results, check:
1. User Object ID and SID are correct (from Graph API)
2. User has actually had security incidents in the past 7 days
3. Try expanding date range to 30 days for testing

</details>

---

## 📝 Exercise 5: Data Export & Report Generation

**Objective**: Export findings to JSON and generate HTML report.

### Task 5.1: Automated Investigation with Copilot

**Prompt to Copilot:**
```
Run a standard 7-day investigation for testuser@yourdomain.com starting from 2026-01-08
```

**Expected Workflow:**
1. ⏱️ Phase 1: Get User ID (~3 seconds)
2. ⏱️ Phase 2: Parallel queries (~60-70 seconds)
   - Batch 1: Sentinel queries (anomalies, sign-ins, audit logs)
   - Batch 2: Graph queries (profile, devices, risk events)
   - Batch 3: IP enrichment
3. ⏱️ Phase 3: JSON export (~1-2 seconds)
4. ⏱️ Phase 4: Report generation (~3-5 minutes)
5. ⏱️ Phase 5: Total time report

**Expected Output Files:**
- `reports/investigation_testuser_2026-01-15.json`
- `reports/investigation_testuser_2026-01-15.html`

### Task 5.2: Verify Report Contents

Open the HTML report and verify it contains:

**Header Section**:
- [ ] Investigation title with UPN
- [ ] Date range (2026-01-08 to 2026-01-17)
- [ ] Tenant ID

**Executive Summary**:
- [ ] Narrative paragraph explaining findings
- [ ] Overall risk level (High/Medium/Low)

**Statistics Dashboard**:
- [ ] Total anomalies detected
- [ ] Total sign-ins (successful/failed)
- [ ] Security incidents count
- [ ] Audit log entries

**Detailed Sections**:
- [ ] Sign-in activity by application
- [ ] Sign-in activity by location
- [ ] IP enrichment table (if IPs found)
- [ ] Anomalies table with severity
- [ ] Security incidents (if any)
- [ ] Audit log activity summary
- [ ] Recommendations section

✅ **Checkpoint**: HTML report generated successfully with all sections

---

## 📝 Exercise 6: Interpret Results & Make Recommendations

**Objective**: Analyze the investigation findings and provide security recommendations.

### Task 6.1: Risk Assessment

Based on your investigation results, answer:

1. **Anomalies**: How many anomalies were detected? What severity?
   - High: _____ 
   - Medium: _____
   - Low: _____

2. **Geographic Spread**: How many unique locations did the user sign in from?
   - Answer: _____
   - Are any locations unexpected? (Yes/No)

3. **Authentication Failures**: Were there failed sign-ins?
   - Count: _____
   - Common reason: _____

4. **IP Reputation**: Are any IPs flagged with high abuse scores?
   - Answer: _____
   - Highest abuse score: _____

5. **Security Incidents**: Were there any security incidents?
   - Count: _____
   - Severity: _____

### Task 6.2: Create Recommendations

Based on findings, what would you recommend? Choose all that apply:

- [ ] **No Action Required** - User activity is normal, no suspicious indicators
- [ ] **Monitor** - Some minor anomalies, continue monitoring for patterns
- [ ] **Investigate Further** - SessionId tracing needed for specific IPs (proceed to Lab 103)
- [ ] **Force Password Reset** - Signs of credential compromise
- [ ] **Revoke Sessions** - Active suspicious activity detected
- [ ] **User Training** - Pattern suggests user needs security awareness training

**Write your recommendation**:
```
Risk Level: [High/Medium/Low]
Recommended Action: [Action from above]
Justification: [Explain your reasoning based on data]
Next Steps: [What should happen next?]
```

---

## ✅ Lab Validation Checklist

Before completing this lab, verify you can:

- [ ] Calculate correct date ranges using +2 day rule
- [ ] Execute parallel KQL queries across multiple data sources
- [ ] Extract User Object ID and Windows SID from Graph API
- [ ] Use Query 1 (IP prioritization) from Investigation Guide
- [ ] Query security incidents with all three identifiers (UPN, Object ID, SID)
- [ ] Generate automated investigation report via Copilot
- [ ] Interpret HTML report sections
- [ ] Make risk-based recommendations from findings

---

## 🎓 Key Takeaways

**Investigation Workflow**:
1. **Get User ID First** - Always start with Graph API for Object ID + SID
2. **Parallel Execution** - Run independent queries simultaneously
3. **IP Prioritization** - Use Query 1 to select top 15 IPs for enrichment
4. **Three Identifiers** - UPN, Object ID, AND SID required for complete incident correlation
5. **Automated Pipeline** - Phase 1 → 2 → 3 → 4 → 5 with timing tracking

**Common Mistakes to Avoid**:
- ❌ Forgetting +2 days in date range (misses recent data)
- ❌ Skipping User ID retrieval (incidents won't correlate)
- ❌ Enriching all IPs instead of top 15 (slow, expensive)
- ❌ Not checking if JSON already exists (wastes API calls)
- ❌ Using case-sensitive UPN comparison (use `=~` operator)

**Performance Tips**:
- ✅ Use `project` early to reduce data volume
- ✅ Filter on TimeGenerated first (indexed column)
- ✅ Run Graph queries while waiting for Sentinel queries
- ✅ Batch IP enrichment (Query 11) instead of per-IP lookups

---

## 🚀 Next Steps

**Continue to [Lab 103: Advanced Authentication Analysis](../103-advanced-auth-analysis/)**

In Lab 103, you'll learn:
- SessionId-based forensic tracing
- Identifying initial authentication vs token refreshes
- IP enrichment analysis with risk scoring
- Documenting authentication chain timelines

**Or practice more**:
- Run investigations on 3 different users in your environment
- Compare findings across users (who has most anomalies?)
- Create a summary report for your SOC manager

---

## 📚 Additional Resources

- [Investigation Guide - Quick Start (Automated)](../../Investigation-Guide.md#quick-start-guide)
- [Investigation Guide - Query 1 (IP Prioritization)](../../Investigation-Guide.md#query-1-extract-top-priority-ips-deterministic-selection-with-risky-ips)
- [Investigation Guide - Query 6 (Security Incidents)](../../Investigation-Guide.md#query-6-security-incidents-with-alerts)
- [Quick Reference - Common Investigation Patterns](../QUICK_REFERENCE.md)

---

## ❓ FAQ

**Q: My investigation returned 0 anomalies. Is that normal?**  
A: Yes! Many users have no anomalies in a 7-day period. This is actually good news - it means normal behavior.

**Q: The automated investigation took 8 minutes instead of 5-6. Why?**  
A: Could be due to network latency, API rate limits, or IP enrichment delays. As long as it completes successfully, timing variance is normal.

**Q: I don't have SecurityIncident data. Why?**  
A: Ensure Defender XDR is connected to Sentinel and the SecurityIncident table has data. You can test with: `SecurityIncident | take 1`

**Q: Can I investigate multiple users at once?**  
A: Yes, but run them sequentially to avoid API throttling. For bulk analysis, consider the batch investigation workflow.

---

**Congratulations!** You've mastered basic security investigations with CyberProbe. You can now investigate any user in your environment using the automated workflow.
