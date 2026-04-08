---
name: incident-correlation-analytics
description: Analyze incident patterns, trends, and correlations across time periods. Generate heatmaps, detect campaigns, track threat actor activity, and produce executive dashboards. Includes MTTD/MTTA/MTTR with month-over-month comparison, top impacted users and devices, analyst workload distribution. Use for SOC reporting, trend analysis, and identifying coordinated attacks.
---

# Incident Correlation & Analytics Skill

This skill enables advanced correlation analysis across multiple incidents to detect patterns, campaigns, and trends for SOC operations and executive reporting.

## When to Use This Skill

Use this skill when:
- Generating daily/weekly SOC reports
- Identifying threat actor campaigns
- Detecting coordinated attacks across time
- Creating executive dashboards and KPIs
- Analyzing incident volume trends
- Correlating IOCs across multiple incidents
- Tracking MITRE ATT&CK technique prevalence
- Assessing detection source effectiveness
- Resource planning and staffing analysis
- Measuring MTTD/MTTR metrics

## Prerequisites

1. **Sentinel Access**: Access to SecurityIncident and SecurityAlert tables
2. **Defender XDR**: Access to incidents via MCP tools or Graph API
3. **Historical Data**: At least 30 days of incident data for trending
4. **MCP Tools**: `mcp_triage_ListIncidents` available

## Time Window Strategy for Correlation

**Daily SOC Reports (Use 24 hours):**
- Morning briefings
- Shift handoffs
- Real-time operational awareness
- Query time: ~10-20 seconds

**Weekly Executive Reports (Use 7 days):**
- Campaign detection
- Week-over-week trending
- IOC correlation across incidents
- Resource planning insights
- Query time: ~30-60 seconds

**Monthly Trend Analysis (Use 30 days):**
- Quarterly business reviews
- Security posture assessments
- Long-term threat actor tracking
- Strategic planning
- Query time: ~2-5 minutes

**Campaign Investigation (Use 90+ days):**
- Advanced persistent threat (APT) tracking
- Insider threat patterns
- Complete infrastructure mapping
- Query time: ~5-15 minutes

## KQL Optimization for Large Datasets

```kql
// OPTIMIZED PATTERN for incident analysis:
SecurityIncident
| where TimeGenerated > ago(24h)           // ← Start with time filter
| where Severity in ("High", "Critical")   // ← Filter high-priority early
| summarize count() by bin(TimeGenerated, 1h), Severity
| take 100                                  // ← Limit results
```

## Analytics Workflow

### Phase 1: Temporal Analysis & Heatmaps

#### Step 1.1: Daily Incident Heatmap (24-Hour View - OPTIMIZED)
```kql
// For daily SOC briefings - Use 24h window
let timeWindow = 24h;  // ← Fast query for daily reports

SecurityIncident
| where TimeGenerated > ago(timeWindow)        // ← TimeGenerated instead of CreatedTime (indexed)
| extend Hour = hourofday(TimeGenerated)
| summarize IncidentCount = count() by Hour, Severity
| order by Hour asc
```

**Visualization Output:**
```
Hour | Critical | High | Medium | Low
-----|----------|------|--------|-----
0    | 2        | 5    | 12     | 3
1    | 1        | 3    | 8      | 2
2    | 0        | 2    | 5      | 1
...
23   | 3        | 7    | 15     | 4
```

**Analysis:**
- Identify peak incident hours (often 8-10 AM, 2-4 PM)
- Detect anomalous patterns (3 AM spike = automated attack)
- Plan SOC staffing based on volume patterns

#### Step 1.2: Weekly Incident Heatmap (Day-of-Week - OPTIMIZED)
```kql
// For weekly executive reports - Use 7d or 30d window
let timeWindow = 7d;  // ← Use 7d for weekly, 30d for monthly pattern analysis

SecurityIncident
| where TimeGenerated > ago(timeWindow)        // ← Optimized filter
| extend DayOfWeek = dayofweek(TimeGenerated)
| extend DayName = case(
    DayOfWeek == 0d, "Sunday",
    DayOfWeek == 1d, "Monday",
    DayOfWeek == 2d, "Tuesday",
    DayOfWeek == 3d, "Wednesday",
    DayOfWeek == 4d, "Thursday",
    DayOfWeek == 5d, "Friday",
    DayOfWeek == 6d, "Saturday",
    "Unknown"
)
| summarize 
    TotalIncidents = count(),
    CriticalCount = countif(Severity == "Critical"),
    HighCount = countif(Severity == "High")
    by DayName, DayOfWeek
| order by DayOfWeek asc
```

**Expected Pattern:**
- Monday/Tuesday: High volume (weekend activity detected)
- Wednesday/Thursday: Moderate volume
- Friday: Lower volume (limited staffing)
- Weekend: Minimal alerts (reduced business activity)

#### Step 1.3: Monthly Trend Analysis (OPTIMIZED)
```kql
// For quarterly reviews - Use 90d window
let timeWindow = 90d;  // ← Adjust: 30d (monthly), 90d (quarterly), 180d (bi-annual)

SecurityIncident
| where TimeGenerated > ago(timeWindow)        // ← Optimized filter
| extend Month = startofmonth(TimeGenerated)
| summarize 
    TotalIncidents = count(),
    CriticalIncidents = countif(Severity == "Critical"),
    HighIncidents = countif(Severity == "High"),
    MediumIncidents = countif(Severity == "Medium"),
    LowIncidents = countif(Severity == "Low"),
    UniqueUsers = dcount(tostring(parse_json(AdditionalData).userPrincipalNames))
    by Month
| extend MonthName = format_datetime(Month, 'yyyy-MM')
| order by Month asc
```

**Use case:** Executive reports showing month-over-month trends

---

### Phase 2: IOC Correlation Across Incidents

#### Step 2.1: Extract All IPs from Incidents
```kql
let timeRange = 7d;
SecurityIncident
| where CreatedTime > ago(timeRange)
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | extend Entities = parse_json(Entities)
    | mv-expand Entity = Entities
    | where Entity.Type == "ip"
    | project SystemAlertId, IP = tostring(Entity.Address)
) on $left.AlertId == $right.SystemAlertId
| summarize 
    IncidentCount = dcount(IncidentNumber),
    Incidents = make_set(IncidentNumber),
    FirstSeen = min(CreatedTime),
    LastSeen = max(CreatedTime)
    by IP
| where IncidentCount > 1  // IPs in multiple incidents
| order by IncidentCount desc
```

**Output:**
```
IP              | Incident Count | Incidents        | First Seen | Last Seen
----------------|----------------|------------------|------------|----------
109.70.100.7    | 5              | [42001,42012,..] | 2026-01-20 | 2026-01-27
176.65.134.8    | 3              | [42005,42018,..] | 2026-01-22 | 2026-01-26
```

**Analysis:** IPs appearing in 3+ incidents = coordinated campaign or persistent threat actor

#### Step 2.2: Extract File Hashes Across Incidents
```kql
SecurityIncident
| where CreatedTime > ago(7d)
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | extend Entities = parse_json(Entities)
    | mv-expand Entity = Entities
    | where Entity.Type == "file"
    | project SystemAlertId, FileHash = tostring(Entity.FileHashes[0].Value)
) on $left.AlertId == $right.SystemAlertId
| where isnotempty(FileHash)
| summarize 
    IncidentCount = dcount(IncidentNumber),
    Incidents = make_list(IncidentNumber),
    AffectedDevices = dcount(tostring(parse_json(AdditionalData).DeviceIds))
    by FileHash
| where IncidentCount > 1
| order by IncidentCount desc
```

**Use case:** Detect malware campaigns spreading across environment

#### Step 2.3: User Account Correlation
```kql
SecurityIncident
| where CreatedTime > ago(30d)
| extend UserAccounts = parse_json(AdditionalData).userPrincipalNames
| mv-expand UserAccount = UserAccounts
| where isnotempty(UserAccount)
| summarize 
    IncidentCount = count(),
    Severities = make_set(Severity),
    IncidentTitles = make_set(Title),
    FirstIncident = min(CreatedTime),
    LastIncident = max(CreatedTime)
    by tostring(UserAccount)
| where IncidentCount >= 3  // Users in 3+ incidents
| order by IncidentCount desc
```

**Analysis:** Users appearing in multiple incidents may indicate:
- Compromised account
- Insider threat
- High-value target
- False positive pattern (adjust detections)

---

### Phase 3: Campaign Detection

#### Step 3.1: Temporal Clustering (Time-Based Campaigns)
```kql
let timeWindow = 6h;  // Cluster incidents within 6 hours
SecurityIncident
| where CreatedTime > ago(7d)
| order by CreatedTime asc
| extend 
    PrevIncidentTime = prev(CreatedTime),
    TimeDiff = datetime_diff('hour', CreatedTime, prev(CreatedTime))
| extend CampaignGroup = row_cumsum(iff(TimeDiff > timeWindow, 1, 0))
| summarize 
    IncidentCount = count(),
    Severities = make_set(Severity),
    Titles = make_set(Title),
    StartTime = min(CreatedTime),
    EndTime = max(CreatedTime),
    Duration = datetime_diff('hour', max(CreatedTime), min(CreatedTime))
    by CampaignGroup
| where IncidentCount >= 5  // Campaigns with 5+ incidents
| order by StartTime desc
```

**Output:**
```
Campaign | Incidents | Severities | Start Time | End Time | Duration (hrs)
---------|-----------|------------|------------|----------|---------------
1        | 12        | [High,Med] | 08:00      | 14:30    | 6.5
2        | 8         | [Critical] | 15:00      | 17:00    | 2.0
```

#### Step 3.2: TTP-Based Clustering (Similar Attack Patterns)
```kql
SecurityIncident
| where CreatedTime > ago(7d)
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | extend Tactics = parse_json(Tactics)
    | mv-expand Tactic = Tactics
    | project SystemAlertId, Tactic = tostring(Tactic)
) on $left.AlertId == $right.SystemAlertId
| summarize 
    TacticSet = make_set(Tactic),
    TacticSignature = strcat_array(make_set(Tactic), ",")
    by IncidentNumber, Title, Severity, CreatedTime
| summarize 
    IncidentCount = count(),
    Incidents = make_list(IncidentNumber),
    Severities = make_set(Severity)
    by TacticSignature
| where IncidentCount >= 3
| order by IncidentCount desc
```

**Use case:** Group incidents with identical MITRE ATT&CK patterns (e.g., all have InitialAccess + Execution + Persistence)

#### Step 3.3: Geographic Campaign Detection
```kql
SecurityIncident
| where CreatedTime > ago(7d)
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | extend Entities = parse_json(Entities)
    | mv-expand Entity = Entities
    | where Entity.Type == "ip"
    | extend Location = strcat(tostring(Entity.Location.City), ", ", tostring(Entity.Location.CountryCode))
    | project SystemAlertId, Location
) on $left.AlertId == $right.SystemAlertId
| where isnotempty(Location)
| summarize 
    IncidentCount = count(),
    Incidents = make_list(IncidentNumber)
    by Location
| where IncidentCount >= 3
| order by IncidentCount desc
```

**Analysis:** Multiple incidents from same geographic location = targeted attack or VPN-based campaign

---

### Phase 4: MITRE ATT&CK Heatmap

#### Step 4.1: Technique Frequency Analysis
```kql
let timeRange = 30d;
SecurityAlert
| where TimeGenerated > ago(timeRange)
| extend Techniques = parse_json(Techniques)
| mv-expand Technique = Techniques
| where isnotempty(Technique)
| summarize 
    AlertCount = count(),
    UniqueSources = dcount(ProviderName),
    Severities = make_set(AlertSeverity)
    by tostring(Technique)
| order by AlertCount desc
| take 20
```

**Output:**
```
Technique | Alert Count | Sources      | Severities
----------|-------------|--------------|-------------
T1078     | 245         | 3            | [High,Med]
T1110     | 156         | 2            | [High]
T1566     | 89          | 4            | [Critical,High]
```

#### Step 4.2: MITRE ATT&CK Matrix Heatmap
```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| extend Tactics = parse_json(Tactics)
| extend Techniques = parse_json(Techniques)
| mv-expand Tactic = Tactics
| mv-expand Technique = Techniques
| summarize Count = count() by tostring(Tactic), tostring(Technique)
| order by Count desc
```

**Visualization:** Create matrix with Tactics as columns, Techniques as rows, Count as color intensity

---

### Phase 5: Detection Source Analytics

#### Step 5.1: Alert Volume by Detection Source
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize 
    AlertCount = count(),
    HighSeverity = countif(AlertSeverity == "High"),
    MediumSeverity = countif(AlertSeverity == "Medium"),
    LowSeverity = countif(AlertSeverity == "Low")
    by ProviderName
| extend HighPercentage = round((HighSeverity * 100.0) / AlertCount, 2)
| order by AlertCount desc
```

**Output:**
```
Provider                        | Total | High | Medium | Low | High %
--------------------------------|-------|------|--------|-----|-------
Microsoft Defender for Endpoint | 450   | 120  | 280    | 50  | 26.7%
Microsoft Sentinel              | 320   | 45   | 200    | 75  | 14.1%
Microsoft Defender for Office   | 180   | 60   | 90     | 30  | 33.3%
```

**Analysis:** Identify which products generating most high-severity alerts

#### Step 5.2: Detection Coverage Gaps
```kql
SecurityIncident
| where CreatedTime > ago(30d)
| extend ProductName = tostring(parse_json(AdditionalData).productName)
| summarize IncidentCount = count() by ProductName, Severity
| order by Severity desc, IncidentCount desc
```

**Use case:** Identify detection gaps (e.g., no incidents from Defender for Identity = not deployed or misconfigured)

---

### Phase 6: SOC Metrics & KPIs

> **📂 Verified Query Library:** All SOC metrics queries below are available as standalone parameterized KQL files in [`queries/soc-metrics/`](../../../queries/soc-metrics/). Use those files directly via `query_lake` — adjust `start_time`/`end_time` variables as needed.

#### Step 6.1: Mean Time to Detect (MTTD)
```kql
SecurityIncident
| where CreatedTime > ago(30d)
| where Status in ("Resolved", "Closed")
| extend 
    FirstAlertTime = todatetime(parse_json(AlertIds)[0]),
    DetectionTime = CreatedTime
| extend MTTD_Minutes = datetime_diff('minute', DetectionTime, FirstAlertTime)
| summarize 
    AvgMTTD = avg(MTTD_Minutes),
    MedianMTTD = percentile(MTTD_Minutes, 50),
    P95_MTTD = percentile(MTTD_Minutes, 95)
    by Severity
```

#### Step 6.2: Mean Time to Acknowledge (MTTA)

> **📂 Verified query:** [`queries/soc-metrics/mean_time_to_acknowledge.kql`](../../../queries/soc-metrics/mean_time_to_acknowledge.kql)

MTTA measures the average time (in minutes) from incident creation to first modification (acknowledgement). Includes automatic month-over-month comparison.

```kql
let start_time = ago(7d);
let end_time = now();
let lastMonthStart = startofmonth(datetime_add('month', -1, now()));
let lastMonthEnd = endofmonth(datetime_add('month', -1, now()));
let timeWindowMTTA = SecurityIncident
    | summarize arg_max(LastModifiedTime, *) by IncidentName
    | extend alertsCount = toint(parse_json((AdditionalData).alertsCount))
    | where Status != "Closed" or (Status =~ "Closed" and alertsCount > 0)
    | where CreatedTime between (start_time .. end_time)
    | extend AcknowledgeTime = datetime_diff('minute', FirstModifiedTime, CreatedTime)
    | where isnotnull(AcknowledgeTime)
    | summarize MTTA = round(avg(AcknowledgeTime), 0)
    | extend j = "forcedjoin"
    | project timeWindowMTTA = MTTA, j;
let lastMonthMTTA = SecurityIncident
    | summarize arg_max(LastModifiedTime, *) by IncidentName
    | extend alertsCount = toint(parse_json((AdditionalData).alertsCount))
    | where Status != "Closed" or (Status =~ "Closed" and alertsCount > 0)
    | where CreatedTime between (lastMonthStart .. lastMonthEnd)
    | extend AcknowledgeTime = datetime_diff('minute', FirstModifiedTime, CreatedTime)
    | where isnotnull(AcknowledgeTime)
    | summarize MTTA = round(avg(AcknowledgeTime), 0)
    | extend j = "forcedjoin"
    | project lastMonthMTTA = MTTA, j;
timeWindowMTTA
| join lastMonthMTTA on j
| extend PercentageChange = round(((timeWindowMTTA - lastMonthMTTA) * 100.0 / lastMonthMTTA), 0)
| project MTTAinMin = timeWindowMTTA, LastMonthMTTAinMin = lastMonthMTTA, PercentageChange
```

**Target Metrics:**
- Critical: < 15 minutes MTTA
- High: < 30 minutes MTTA
- Medium: < 2 hours MTTA
- Low: < 8 hours MTTA

#### Step 6.3: Mean Time to Resolve (MTTR) with Month-over-Month

> **📂 Verified query:** [`queries/soc-metrics/mean_time_to_resolve.kql`](../../../queries/soc-metrics/mean_time_to_resolve.kql)

MTTR measures the average time (in minutes) from incident creation to closure. Includes automatic month-over-month comparison.

```kql
let start_time = ago(7d);
let end_time = now();
let lastMonthStart = startofmonth(datetime_add('month', -1, now()));
let lastMonthEnd = endofmonth(datetime_add('month', -1, now()));
let timeWindowMTTR = SecurityIncident
    | summarize arg_max(LastModifiedTime, *) by IncidentName
    | extend alertsCount = toint(parse_json((AdditionalData).alertsCount))
    | where Status =~ "Closed" and alertsCount > 0
    | where ClosedTime between (start_time .. end_time)
    | extend ResolveTime = datetime_diff('minute', ClosedTime, CreatedTime)
    | summarize MTTR = round(avg(ResolveTime), 0)
    | extend j = "forcedjoin"
    | project timeWindowMTTR = MTTR, j;
let lastMonthMTTR = SecurityIncident
    | summarize arg_max(LastModifiedTime, *) by IncidentName
    | extend alertsCount = toint(parse_json((AdditionalData).alertsCount))
    | where Status =~ "Closed" and alertsCount > 0
    | where ClosedTime between (lastMonthStart .. lastMonthEnd)
    | extend ResolveTime = datetime_diff('minute', ClosedTime, CreatedTime)
    | summarize MTTR = round(avg(ResolveTime), 0)
    | extend j = "forcedjoin"
    | project lastMonthMTTR = MTTR, j;
timeWindowMTTR
| join lastMonthMTTR on j
| extend PercentageChange = round(((timeWindowMTTR - lastMonthMTTR) * 100.0 / lastMonthMTTR), 0)
| project MTTRinMin = timeWindowMTTR, LastMonthMTTRinMin = lastMonthMTTR, PercentageChange
```

**Target Metrics:**
- Critical: < 1 hour MTTR
- High: < 4 hours MTTR
- Medium: < 24 hours MTTR
- Low: < 72 hours MTTR

#### Step 6.4: Incident Count Statistics with MITRE Mapping

> **📂 Verified query:** [`queries/soc-metrics/incident_count_stats.kql`](../../../queries/soc-metrics/incident_count_stats.kql)

Comprehensive incident breakdown by type including status distribution, classification, and extracted MITRE tactics/techniques. Supports filtering by severity, status, and classification.

**When to use:** Daily/weekly SOC reports, executive briefings, detection rule effectiveness analysis.

```kql
// Use the full query from queries/soc-metrics/incident_count_stats.kql
// Key output columns:
//   IncidentSeverityAndTitle, TotalCount, NewCount, ActiveCount, ClosedCount,
//   BenignPositiveCount, FalsePositiveCount, TruePositiveCount, UndeterminedCount,
//   Tactics, Techniques
```

#### Step 6.5: Incident Status Distribution
```kql
SecurityIncident
| where CreatedTime > ago(7d)
| summarize Count = count() by Status, Severity
| order by Severity desc, Status asc
```

**KPI Calculation:**
```kql
SecurityIncident
| where CreatedTime > ago(7d)
| summarize 
    Total = count(),
    Closed = countif(Status in ("Resolved", "Closed")),
    Active = countif(Status in ("New", "Active"))
| extend ClosureRate = round((Closed * 100.0) / Total, 2)
```

---

### Phase 6b: Entity Impact & Analyst Workload Analysis

> **📂 Verified queries:** [`queries/soc-metrics/`](../../../queries/soc-metrics/) — `top_impacted_users.kql`, `top_impacted_devices.kql`, `top_incident_owners.kql`

These queries extract entity data from `SecurityAlert.Entities` JSON and correlate it with `SecurityIncident` to identify repeatedly targeted users, devices, and analyst workload imbalances.

#### Step 6b.1: Top Impacted Users

> **📂 Verified query:** [`queries/soc-metrics/top_impacted_users.kql`](../../../queries/soc-metrics/top_impacted_users.kql)

Identifies users impacted by the most security alerts in the period. Extracts user entities (UPN, Name, AccountName) from SecurityAlert, then correlates to SecurityIncident via `ExtendedProperties.IncidentId`.

```kql
// Use the full query from queries/soc-metrics/top_impacted_users.kql
// Key output columns: UserId, AlertsCount, IncidentsCount
// Default filter: TruePositive classification only
// Default: top 10 users
```

**Use cases:**
- Identify repeatedly compromised accounts for priority remediation
- Detect insider threat patterns (same user across many incident types)
- Feed into user risk scoring (Phase 6b Common Pattern below)
- Executive briefings: "Top 5 most-targeted users this week"

#### Step 6b.2: Top Impacted Devices

> **📂 Verified query:** [`queries/soc-metrics/top_impacted_devices.kql`](../../../queries/soc-metrics/top_impacted_devices.kql)

Identifies devices (hosts) impacted by the most security alerts. Extracts host entities from SecurityAlert using `CompromisedEntity`, then correlates to SecurityIncident.

```kql
// Use the full query from queries/soc-metrics/top_impacted_devices.kql
// Key output columns: host, AlertsCount, IncidentsCount
// Default filter: TruePositive classification only
// Default: top 10 devices
```

**Use cases:**
- Identify persistently compromised endpoints for reimaging decisions
- Detect lateral movement hubs (device in many unrelated incidents)
- Prioritize endpoint hardening based on actual incident data
- Cross-reference with `endpoint-device-investigation` skill for deep-dive

#### Step 6b.3: Analyst Workload Distribution (Top Incident Owners)

> **📂 Verified query:** [`queries/soc-metrics/top_incident_owners.kql`](../../../queries/soc-metrics/top_incident_owners.kql)

Shows how many incidents are assigned to each analyst/operator. Useful for detecting workload imbalances and staffing decisions.

```kql
// Use the full query from queries/soc-metrics/top_incident_owners.kql
// Key output columns: OwnerUPN, IncidentCount
// Default: top 20 owners, all severities/statuses
```

**Use cases:**
- SOC manager capacity planning
- Identify analysts overloaded with High/Critical incidents
- Detect unassigned incident backlog (OwnerUPN empty = unassigned)
- Weekly staffing reports

#### Step 6b Pattern: Combined Entity Risk Assessment

Chain entity impact data with other investigation skills:

1. Run `top_impacted_users.kql` → identify top 5 users
2. For each high-impact user → trigger `incident-investigation` skill
3. Run `top_impacted_devices.kql` → identify top 5 devices
4. For each high-impact device → trigger `endpoint-device-investigation` skill
5. Run `top_incident_owners.kql` → flag workload imbalances
6. Aggregate into executive report via `report-generation` skill

---

### Phase 7: Trend Analysis & Forecasting

#### Step 7.1: Week-over-Week Growth
```kql
let thisWeek = SecurityIncident | where CreatedTime > ago(7d) | count;
let lastWeek = SecurityIncident | where CreatedTime between (ago(14d) .. ago(7d)) | count;
print 
    ThisWeek = thisWeek,
    LastWeek = lastWeek,
    Growth = round(((thisWeek - lastWeek) * 100.0) / lastWeek, 2)
```

#### Step 7.2: Severity Trend Over Time
```kql
SecurityIncident
| where CreatedTime > ago(90d)
| extend Week = startofweek(CreatedTime)
| summarize 
    Critical = countif(Severity == "Critical"),
    High = countif(Severity == "High"),
    Medium = countif(Severity == "Medium"),
    Low = countif(Severity == "Low")
    by Week
| order by Week asc
```

**Visualization:** Line chart with 4 lines (one per severity)

---

## MCP Tools for Incident Listing

### List All Incidents
```
mcp_triage_ListIncidents(
    createdAfter="2026-01-01T00:00:00Z",
    createdBefore="2026-01-30T23:59:59Z",
    severity="High",
    status="New",
    top=100
)
```

**Parameters:**
- `createdAfter` / `createdBefore`: Date range
- `severity`: Filter by Critical, High, Medium, Low
- `status`: Filter by New, Active, Resolved, Closed
- `assignedTo`: Filter by analyst UPN
- `orderBy`: Sort field (createdTime, lastModifiedTime)
- `top`: Limit results (max 10,000)

---

## Report Templates

### Template 1: Daily SOC Report

**Sections:**
1. Executive Summary
   - Total incidents (last 24 hours)
   - Critical/High count
   - Closure rate

2. Incident Breakdown ← *use `incident_count_stats.kql`*
   - By severity and type with MITRE tactics
   - Status breakdown (New/Active/Closed)
   - Classification breakdown (TP/FP/BP/Undetermined)

3. Top Threats & Impacted Entities ← *use `top_impacted_users.kql` + `top_impacted_devices.kql`*
   - Most frequent IPs
   - Most targeted users (by alert count)
   - Most impacted devices (by alert count)

4. Hourly Distribution
   - Heatmap (00:00-23:59)
   - Peak incident hours

5. Analyst Workload ← *use `top_incident_owners.kql`*
   - Incident distribution per analyst
   - Unassigned incident count

6. Recommendations
   - Incidents requiring escalation
   - Trending attack patterns

### Template 2: Weekly Executive Report

**Sections:**
1. Week-over-Week Comparison
   - Total incidents (current vs previous week)
   - Severity distribution
   - Growth/decline analysis

2. Campaign Detection
   - Identified attack campaigns
   - IOC correlation findings
   - Geographic threat analysis

3. MITRE ATT&CK Coverage
   - Top 10 techniques detected
   - Tactic distribution heatmap

4. SOC Performance ← *use `mean_time_to_acknowledge.kql` + `mean_time_to_resolve.kql`*
   - MTTD/MTTA/MTTR metrics with month-over-month % change
   - Closure rate by severity
   - Backlog analysis

5. Entity Impact Analysis ← *use `top_impacted_users.kql` + `top_impacted_devices.kql`*
   - Top 10 targeted users with alert/incident counts
   - Top 10 impacted devices with alert/incident counts
   - Analyst workload distribution

6. Strategic Recommendations
   - Detection gaps
   - Staffing needs (informed by workload data)
   - Tool effectiveness

---

## Visualization Best Practices

### Heatmap Generation

**For HTML Reports:**
```python
# Python code for generating heatmap HTML
import json

def generate_heatmap(data):
    """
    data = [
        {"hour": 0, "critical": 2, "high": 5, "medium": 12, "low": 3},
        {"hour": 1, "critical": 1, "high": 3, "medium": 8, "low": 2},
        ...
    ]
    """
    html = '<table class="heatmap">\n'
    html += '<tr><th>Hour</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>\n'
    
    for row in data:
        html += f'<tr><td>{row["hour"]:02d}:00</td>'
        html += f'<td class="severity-critical">{row["critical"]}</td>'
        html += f'<td class="severity-high">{row["high"]}</td>'
        html += f'<td class="severity-medium">{row["medium"]}</td>'
        html += f'<td class="severity-low">{row["low"]}</td></tr>\n'
    
    html += '</table>'
    return html
```

**For Power BI:**
- Use Matrix visualization
- Rows: Hour of day
- Columns: Severity
- Values: Count of incidents
- Conditional formatting: Color scale (white → red)

---

## Common Analytics Patterns

### Pattern 1: Identify Spike Events
```kql
SecurityIncident
| where CreatedTime > ago(7d)
| summarize IncidentCount = count() by bin(CreatedTime, 1h)
| extend AvgCount = avg(IncidentCount)
| extend Threshold = AvgCount * 2
| where IncidentCount > Threshold
| project CreatedTime, IncidentCount, Threshold
```

**Analysis:** Hours where incident count > 2x average = spike event (investigate root cause)

### Pattern 2: User Risk Scoring
```kql
SecurityIncident
| where CreatedTime > ago(30d)
| extend UserAccounts = parse_json(AdditionalData).userPrincipalNames
| mv-expand UserAccount = UserAccounts
| summarize 
    IncidentCount = count(),
    CriticalCount = countif(Severity == "Critical"),
    HighCount = countif(Severity == "High"),
    LastIncident = max(CreatedTime)
    by tostring(UserAccount)
| extend RiskScore = (CriticalCount * 10) + (HighCount * 5) + (IncidentCount * 1)
| order by RiskScore desc
| take 50
```

### Pattern 3: Detection Rule Effectiveness
```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize 
    AlertCount = count(),
    TruePositives = countif(parse_json(AdditionalData).isTruePositive == true),
    FalsePositives = countif(parse_json(AdditionalData).isFalsePositive == true)
    by AlertName
| extend TP_Rate = round((TruePositives * 100.0) / AlertCount, 2)
| where AlertCount > 10  // Only rules with 10+ alerts
| order by FalsePositives desc
```

**Use case:** Identify noisy detection rules for tuning

---

## Integration with Power BI

### Export Data for Dashboards

**Incidents Table:**
```kql
SecurityIncident
| where CreatedTime > ago(30d)
| project 
    IncidentNumber,
    Title,
    Severity,
    Status,
    CreatedTime,
    ClosedTime,
    ProductName = tostring(parse_json(AdditionalData).productName),
    UserCount = array_length(parse_json(AdditionalData).userPrincipalNames),
    DeviceCount = array_length(parse_json(AdditionalData).DeviceIds)
```

**Export to CSV:**
```python
# In Python enrichment script or report generator
import pandas as pd

df = pd.DataFrame(kql_results)
df.to_csv('powerbi/data/incidents_last_30d.csv', index=False)
```

**Power BI Connection:**
- Data Source: CSV folder (automatic refresh)
- Scheduled Refresh: Daily at 6 AM
- Relationships: Link incidents to enrichment data by IncidentNumber

---

## Best Practices

1. **Baseline First**: Establish normal incident volume before detecting anomalies
2. **Use Time Windows**: 7-day rolling window for trending, 30-day for KPIs
3. **Correlate Multiple Dimensions**: Time + IOC + TTP for campaign detection
4. **Automate Reporting**: Schedule daily/weekly reports to run automatically
5. **Track Metrics Over Time**: Store historical KPIs for long-term trend analysis
6. **Visualize Effectively**: Use heatmaps for temporal data, bar charts for comparisons
7. **Filter Noise**: Exclude low-severity informational incidents from analytics
8. **Document Campaigns**: Create incident families/clusters for tracking

---

## Related Skills

- **incident-investigation** - Deep-dive individual incident analysis
- **report-generation** - Generate HTML/JSON investigation reports
- **endpoint-device-investigation** - Device-level correlation analysis
- **ioc-management** - IOC extraction and enrichment for correlation

---

## References

- [Power BI Setup Guide](../../../powerbi/POWERBI_DASHBOARD_SETUP.md)
- [Investigation Guide Section 17](../../../Investigation-Guide.md#17-investigation-report-template)
- [SOC Daily Report Example](../../../reports/soc_daily_report_2026-01-20.html)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
