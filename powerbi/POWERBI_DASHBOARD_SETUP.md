# Power BI Dashboard Setup Guide - CyberProbe Insider Threat Investigation

**Dashboard Name:** Insider Threat Investigation Dashboard  
**Data Sources:** Microsoft Sentinel (KQL), Microsoft Defender XDR (Graph API), Local JSON Exports  
**Use Case:** Real-time monitoring and historical analysis of insider threats  
**Last Updated:** January 21, 2026

---

## 📊 Dashboard Overview

This Power BI dashboard provides comprehensive visualization of insider threat investigations, specifically designed for the **user01 case** but adaptable for ongoing monitoring.

### Dashboard Pages

1. **Executive Summary** - High-level KPIs and risk scores
2. **Alert Timeline** - Chronological view of security alerts
3. **User Activity Analysis** - Email operations and Copilot usage
4. **Geographic Analysis** - Sign-in locations and anomalies
5. **Remediation Status** - Failed/successful automated responses
6. **MITRE ATT&CK Mapping** - Technique coverage and gaps

---

## 🔌 Data Source Configuration

### Option 1: Direct API Connection (Real-time)

**Advantages:** Live data, automatic refresh, no manual exports  
**Prerequisites:** Azure AD authentication, API permissions

#### Microsoft Sentinel Connection (KQL)

1. Open Power BI Desktop
2. Get Data → Azure → Azure Monitor Logs
3. Enter your workspace details:
   - **Workspace ID:** `{your-sentinel-workspace-id}`
   - **Authentication:** Organizational Account or Service Principal

4. Use the KQL queries from `powerbi/sentinel_queries.kql`

#### Microsoft Defender XDR Connection (Graph API)

1. Get Data → Web
2. Advanced → Use Power Query M code
3. Paste the M code from `powerbi/defender_api_connection.m`
4. Configure authentication:
   - **URL:** `https://graph.microsoft.com/v1.0/security/incidents`
   - **Auth:** OAuth2 with Microsoft 365 Defender scope

---

### Option 2: JSON File Import (Static)

**Advantages:** No authentication required, works offline, reproducible  
**Prerequisites:** Exported JSON files from investigation

#### Export Investigation Data

Run the export script to generate Power BI-ready datasets:

```powershell
# Export user01 investigation data
python enrichment/powerbi_data_export.py --user user01 --days 7 --format all

# Or use the dedicated investigation exporter
python powerbi/export_investigation_data.py --incident 42120
```

#### Import Files into Power BI

1. **Get Data → JSON**
2. Import these files:
   - `reports/investigation_user01_2026-01-21.json`
   - `reports/ip_enrichment_*.json`
   - `reports/ioc_enrichment_*.json`

3. **Transform Data:**
   - Expand nested JSON columns
   - Set data types (Date/Time, Numbers, Text)
   - Create relationships between tables

---

## 📐 Data Model Structure

### Tables Required

```
Incidents
├── incident_id (Key)
├── severity
├── status
├── created_datetime
├── priority_score
└── user_principal_name

Alerts
├── alert_id (Key)
├── incident_id (FK → Incidents)
├── severity
├── category
├── risk_score
├── created_datetime
└── policy_title

UserActivity
├── activity_id (Key)
├── user_principal_name (FK → Users)
├── operation_type
├── timestamp
├── record_type
└── event_count

Users
├── user_principal_name (Key)
├── display_name
├── azure_ad_user_id
├── risk_score
├── employment_status
└── asset_classification

SignInLogs
├── signin_id (Key)
├── user_principal_name (FK → Users)
├── ip_address
├── location_city
├── location_country
└── timestamp

RemediationActions
├── action_id (Key)
├── incident_id (FK → Incidents)
├── playbook_name
├── action_type
├── status (Success/Failed)
└── timestamp

DateDimension (Calendar Table)
├── Date (Key)
├── Year
├── Month
├── Day
├── DayOfWeek
└── IsWeekend
```

### Relationships

```
Users[user_principal_name] → Incidents[user_principal_name]
Incidents[incident_id] → Alerts[incident_id]
Users[user_principal_name] → UserActivity[user_principal_name]
Users[user_principal_name] → SignInLogs[user_principal_name]
Incidents[incident_id] → RemediationActions[incident_id]
DateDimension[Date] → Incidents[created_date]
DateDimension[Date] → Alerts[created_date]
```

---

## 📊 DAX Measures

Save these measures in a dedicated "Measures" table.

### KPI Measures

```dax
// Total Active Incidents
Total Active Incidents = 
CALCULATE(
    COUNTROWS(Incidents),
    Incidents[status] = "active"
)

// High Severity Incidents
High Severity Count = 
CALCULATE(
    COUNTROWS(Incidents),
    Incidents[severity] = "high"
)

// Average Risk Score
Avg Risk Score = 
AVERAGE(Alerts[risk_score])

// Critical Users Count (Risk Score > 70)
Critical Users = 
CALCULATE(
    COUNTROWS(Users),
    Users[risk_score] > 70
)

// Departing Employees Count
Departing Employees = 
CALCULATE(
    COUNTROWS(Users),
    Users[employment_status] = "departing"
)
```

### Activity Analysis

```dax
// Total Email Operations
Total Email Operations = 
COUNTROWS(UserActivity)

// Mail Access Events
Mail Access Count = 
CALCULATE(
    SUM(UserActivity[event_count]),
    UserActivity[operation_type] = "MailItemsAccessed"
)

// Email Send Events
Email Send Count = 
CALCULATE(
    SUM(UserActivity[event_count]),
    UserActivity[operation_type] = "Send"
)

// Activity Trend (7-Day Moving Average)
Activity 7-Day Avg = 
AVERAGEX(
    DATESINPERIOD(
        DateDimension[Date],
        LASTDATE(DateDimension[Date]),
        -7,
        DAY
    ),
    [Total Email Operations]
)
```

### Alert Analysis

```dax
// Alerts by Category
Alerts by Category = 
CALCULATE(
    COUNTROWS(Alerts),
    ALLEXCEPT(Alerts, Alerts[category])
)

// Exfiltration Alerts
Exfiltration Alerts = 
CALCULATE(
    COUNTROWS(Alerts),
    Alerts[category] = "Exfiltration"
)

// Copilot-Related Alerts
Copilot Alerts = 
CALCULATE(
    COUNTROWS(Alerts),
    SEARCH("Copilot", Alerts[policy_title], 1, 0) > 0
)

// Alert Severity Score (weighted)
Alert Severity Score = 
SUMX(
    Alerts,
    SWITCH(
        Alerts[severity],
        "high", 3,
        "medium", 2,
        "low", 1,
        0
    )
)
```

### Remediation Tracking

```dax
// Failed Remediations
Failed Remediation Count = 
CALCULATE(
    COUNTROWS(RemediationActions),
    RemediationActions[status] = "Failed"
)

// Remediation Success Rate
Remediation Success Rate = 
DIVIDE(
    CALCULATE(
        COUNTROWS(RemediationActions),
        RemediationActions[status] = "Success"
    ),
    COUNTROWS(RemediationActions),
    0
)

// AWS IAM Failures (specific to user01 case)
AWS IAM Failures = 
CALCULATE(
    COUNTROWS(RemediationActions),
    RemediationActions[playbook_name] = "Playbook-AWSIAM-DeleteAccessKeys",
    RemediationActions[status] = "Failed"
)
```

### Time Intelligence

```dax
// Incidents This Month
Incidents This Month = 
CALCULATE(
    COUNTROWS(Incidents),
    DATESMTD(DateDimension[Date])
)

// Incidents Previous Month
Incidents Last Month = 
CALCULATE(
    [Incidents This Month],
    DATEADD(DateDimension[Date], -1, MONTH)
)

// Month-over-Month Growth
Incident MoM Growth = 
DIVIDE(
    [Incidents This Month] - [Incidents Last Month],
    [Incidents Last Month],
    0
)

// Peak Activity Hour
Peak Activity Hour = 
MAXX(
    SUMMARIZE(
        UserActivity,
        HOUR(UserActivity[timestamp]),
        "ActivityCount", COUNTROWS(UserActivity)
    ),
    [ActivityCount]
)
```

### Geographic Analysis

```dax
// Unique Countries
Unique Countries = 
DISTINCTCOUNT(SignInLogs[location_country])

// Sign-ins from High-Risk Countries
High Risk Country Signins = 
CALCULATE(
    COUNTROWS(SignInLogs),
    SignInLogs[location_country] IN {
        "Russia", "China", "North Korea", "Iran"
    }
)

// First-Time Location Flag
First Time Location = 
VAR CurrentUser = SignInLogs[user_principal_name]
VAR CurrentLocation = SignInLogs[location_city]
VAR PreviousLocations = 
    CALCULATETABLE(
        VALUES(SignInLogs[location_city]),
        SignInLogs[user_principal_name] = CurrentUser,
        SignInLogs[timestamp] < EARLIER(SignInLogs[timestamp])
    )
RETURN
    IF(
        ISEMPTY(
            FILTER(
                PreviousLocations,
                SignInLogs[location_city] = CurrentLocation
            )
        ),
        "New Location",
        "Known Location"
    )
```

---

## 🎨 Visualizations Recommended

### Page 1: Executive Summary

1. **Card Visuals** (KPIs)
   - Total Active Incidents
   - High Severity Count
   - Critical Users (Risk Score > 70)
   - Departing Employees Count

2. **Gauge Chart**
   - Average Risk Score (0-100 scale)
   - Red zone: 70-100
   - Yellow zone: 40-69
   - Green zone: 0-39

3. **Donut Chart**
   - Incidents by Severity (High/Medium/Low)

4. **Line Chart**
   - Incident Trend (Last 30 Days)

5. **Table**
   - Top 10 High-Risk Users
   - Columns: Name, Risk Score, Employment Status, Alert Count

### Page 2: Alert Timeline

1. **Gantt Chart / Timeline Visual**
   - X-axis: Created DateTime
   - Y-axis: Alert ID
   - Color: Severity
   - Legend: Category

2. **Stacked Column Chart**
   - X-axis: Date (binned by day)
   - Y-axis: Alert Count
   - Legend: Category (Exfiltration, SuspiciousActivity, etc.)

3. **Matrix Visual**
   - Rows: Policy Title
   - Columns: Severity
   - Values: Count of Alerts

### Page 3: User Activity Analysis

1. **Clustered Bar Chart**
   - Y-axis: Operation Type
   - X-axis: Event Count
   - Legend: User (filter to user01)

2. **Line Chart**
   - X-axis: Date
   - Y-axis: Email Operations Count
   - Two lines: MailItemsAccessed (blue), Send (orange)

3. **Table**
   - Daily Activity Breakdown
   - Columns: Date, Mail Access, Email Send, Total Operations

4. **Card Visuals**
   - Total Email Operations: 44
   - Mail Access Events: 27
   - Email Send Events: 17
   - Peak Activity Day: Jan 14 (15 events)

### Page 4: Geographic Analysis

1. **Map Visual**
   - Location: Country/City from SignInLogs
   - Size: Count of Sign-ins
   - Color: Risk Level

2. **Table**
   - Sign-in Summary by Country
   - Columns: Country, City, IP Address, Count, First Seen, Last Seen

3. **Card Visual**
   - "No Sign-in Data Available" (for user01 case)
   - Custom message explaining data gap

### Page 5: Remediation Status

1. **Funnel Chart**
   - Stages: Total Actions → Successful → Failed
   - Shows remediation funnel

2. **Stacked Bar Chart**
   - Y-axis: Playbook Name
   - X-axis: Count
   - Legend: Status (Success/Failed)

3. **Table**
   - Failed Remediation Details
   - Columns: Timestamp, Playbook, User, Incident ID, Error Message

4. **KPI Card**
   - Remediation Success Rate (%)
   - AWS IAM Failures: 5

### Page 6: MITRE ATT&CK Mapping

1. **Matrix Visual**
   - Rows: Tactic
   - Columns: Technique
   - Values: Count of Incidents

2. **Treemap**
   - Group: Tactic
   - Details: Technique
   - Values: Count

3. **Table**
   - Detailed MITRE Mapping
   - Columns: Tactic, Technique ID, Technique Name, Sub-Technique, Evidence Count

---

## 🔄 Data Refresh Configuration

### Automated Refresh (Power BI Service)

1. **Publish to Power BI Service**
   - File → Publish → Select Workspace

2. **Configure Dataset Refresh**
   - Settings → Datasets → Your Dataset
   - Scheduled Refresh → Configure times
   - Recommended: Every 1 hour during business hours

3. **Gateway Setup** (if using on-premises data)
   - Install Power BI Gateway
   - Configure data source credentials
   - Map dataset to gateway

### Manual Refresh (Power BI Desktop)

1. **Home → Refresh**
2. Or set auto-refresh interval:
   - File → Options → Data Load
   - Background Data: Enable/Configure interval

---

## 🔐 Security & Permissions

### API Permissions Required

**Microsoft Graph API:**
- `SecurityIncident.Read.All`
- `SecurityAlert.Read.All`
- `User.Read.All`

**Azure Monitor (Sentinel):**
- `Data.Read` on Log Analytics Workspace
- Reader role on Sentinel workspace

### Power BI Workspace Permissions

- **Admin:** Can publish, refresh, configure
- **Member:** Can view, create reports
- **Contributor:** Can view reports
- **Viewer:** Read-only access

### Row-Level Security (RLS)

For multi-tenancy or department isolation:

```dax
// RLS Rule: Users can only see their department's incidents
[department] = USERPRINCIPALNAME()
```

---

## 📥 Quick Start: U1899 Investigation Dashboard

### Step 1: Export Investigation Data

```powershell
# Generate Power BI dataset for user01
python powerbi/export_investigation_data.py --incident 42120 --output powerbi/data
```

### Step 2: Import Template

1. Download Power BI Desktop (if not installed)
2. Open `powerbi/InsiderThreatTemplate.pbit` (template file)
3. When prompted, enter parameters:
   - **Incident ID:** 42120
   - **User UPN:** user01@contoso.com
   - **Investigation Date:** 2026-01-21

### Step 3: Load Data

1. Transform Data → Get Data → JSON
2. Navigate to `powerbi/data/` folder
3. Select all JSON files:
   - `incident_42120.json`
   - `alerts_user01.json`
   - `user_activity_user01.json`
   - `remediation_failures.json`

### Step 4: Verify Relationships

1. Model View → Check relationships are created
2. If missing, create manually per the data model above

### Step 5: Refresh Visualizations

1. All visuals should auto-populate
2. Apply filters: User = user01, Date Range = Jan 14-21
3. Review KPIs match the HTML report:
   - Risk Score: 75
   - Active Alerts: 5
   - Email Operations: 44
   - Failed Remediations: 5

---

## 🎯 Sample Filters & Slicers

Add these slicers to enable interactive filtering:

1. **Date Range Slicer**
   - Field: DateDimension[Date]
   - Type: Between (range slider)

2. **Severity Filter**
   - Field: Incidents[severity]
   - Type: Dropdown (High/Medium/Low)

3. **User Filter**
   - Field: Users[user_principal_name]
   - Type: Search box
   - Default: user01@contoso.com

4. **Employment Status**
   - Field: Users[employment_status]
   - Type: Checkbox (Departing, Active, etc.)

5. **Alert Category**
   - Field: Alerts[category]
   - Type: Checkbox (Exfiltration, SuspiciousActivity, etc.)

---

## 📚 Additional Resources

- **Power BI Template:** `powerbi/InsiderThreatTemplate.pbit`
- **M Code Queries:** `powerbi/defender_api_connection.m`
- **KQL Queries:** `powerbi/sentinel_queries.kql`
- **DAX Measures:** `powerbi/measures.dax`
- **Export Script:** `powerbi/export_investigation_data.py`
- **Sample Data:** `powerbi/data/sample_dataset.json`

---

## 🐛 Troubleshooting

### "Unable to connect to data source"

- **Cause:** Authentication failure or expired token
- **Fix:** 
  1. Re-authenticate: Data Source Settings → Edit Permissions
  2. Verify API permissions in Azure AD
  3. Check token expiration (default 1 hour)

### "Query timeout"

- **Cause:** Large dataset or complex KQL query
- **Fix:**
  1. Reduce date range (use last 7 days vs 30 days)
  2. Add `| take 10000` to KQL queries for testing
  3. Use incremental refresh (Power BI Premium)

### "Relationship not detected"

- **Cause:** Column name mismatch or data type mismatch
- **Fix:**
  1. Standardize column names (use Power Query)
  2. Ensure key columns have same data type
  3. Manually create relationship in Model view

### "Visual shows blank/no data"

- **Cause:** Filter context or incorrect measure
- **Fix:**
  1. Check slicers - may be filtering out all data
  2. Verify measure DAX syntax (use DAX Studio)
  3. Ensure data loaded correctly (View → Data view)

---

## 🚀 Next Steps

1. **Review existing export script:** `enrichment/powerbi_data_export.py`
2. **Create dashboard-specific exporter:** `powerbi/export_investigation_data.py`
3. **Generate M code and KQL queries:** See files in `powerbi/` folder
4. **Build initial dashboard:** Follow Quick Start guide above
5. **Schedule automated refresh:** Configure in Power BI Service
6. **Share with stakeholders:** Publish to Power BI workspace

---

**Created:** January 21, 2026  
**Investigation:** user01 Insider Threat Case #42120  
**Status:** Ready for Implementation  
