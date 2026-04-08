# Power BI Setup Guide for CyberProbe

This guide shows you how to set up automated Power BI reporting for Defender XDR incidents.

## Prerequisites

1. **Azure AD Application Registration** (for API access)
2. **Power BI Desktop** installed
3. **Python packages**: `pip install azure-identity msal requests pandas openpyxl`

---

## Step 1: Configure Azure AD Authentication

### Option A: Azure CLI (Quickest for Testing)

```powershell
# Login to Azure
az login

# Get access token for Defender API
$token = az account get-access-token --resource https://api.securitycenter.microsoft.com --query accessToken -o tsv

# Get access token for Log Analytics (Sentinel)
$logtoken = az account get-access-token --resource https://api.loganalytics.io --query accessToken -o tsv
```

### Option B: Service Principal (For Production)

1. **Register Azure AD Application:**
   - Go to Azure Portal > Azure Active Directory > App Registrations
   - Click "New registration"
   - Name: "CyberProbe-PowerBI"
   - Click "Register"

2. **Create Client Secret:**
   - Go to your app > Certificates & secrets
   - Click "New client secret"
   - Copy the secret value (only shown once!)

3. **Assign API Permissions:**
   - Go to API permissions > Add a permission
   - Add these permissions:
     - **Microsoft Graph**: SecurityEvents.Read.All
     - **Microsoft Threat Protection**: Incident.Read.All, Alert.Read.All
     - **Log Analytics API**: Data.Read
   - Click "Grant admin consent"

4. **Update config.json:**

```json
{
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "sentinel_workspace_id": "00000000-0000-0000-0000-000000000000",
  "azure_ad": {
    "client_id": "YOUR-APP-ID-HERE",
    "client_secret": "YOUR-SECRET-HERE",
    "authority": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000"
  },
  "api_keys": {
    "abuseipdb": "6a1efcd9bd8cce0a70b03372f3a3217afb5833892b3b6da401e188c688dc210a175408300ef45701",
    "ipinfo": "a4a8be9afcba56",
    "vpnapi": "d520e365f1794ae1af360943722d886d"
  },
  "settings": {
    "output_dir": "reports"
  }
}
```

---

## Step 2: Implement Authentication in Script

Update `powerbi_data_export.py` method `get_access_token()`:

```python
def get_access_token(self) -> str:
    """Get Azure AD access token using MSAL"""
    from msal import ConfidentialClientApplication
    
    azure_config = self.config.get('azure_ad', {})
    
    app = ConfidentialClientApplication(
        client_id=azure_config['client_id'],
        client_credential=azure_config['client_secret'],
        authority=azure_config['authority']
    )
    
    # For Defender API
    result = app.acquire_token_for_client(
        scopes=["https://api.securitycenter.microsoft.com/.default"]
    )
    
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception(f"Authentication failed: {result.get('error_description')}")
```

---

## Step 3: Run the Export Script

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install azure-identity msal requests pandas openpyxl

# Run export for last 7 days (from root directory)
python enrichment/powerbi_data_export.py --days 7 --format excel

# Or from enrichment directory
cd enrichment
python powerbi_data_export.py --days 30 --format both
```

**Output Files:**
- `reports/powerbi_incidents_TIMESTAMP.csv`
- `reports/powerbi_alerts_TIMESTAMP.csv`
- `reports/powerbi_entities_TIMESTAMP.csv`
- `reports/powerbi_dataset_TIMESTAMP.xlsx` (all tables in one file)

---

## Step 4: Import into Power BI Desktop

### 4.1 Import Data

1. Open Power BI Desktop
2. Click **Get Data** > **Excel Workbook**
3. Select `powerbi_dataset_TIMESTAMP.xlsx`
4. Check all three tables:
   - ✅ incidents
   - ✅ alerts
   - ✅ entities
5. Click **Load**

### 4.2 Create Table Relationships

1. Click **Model** view (left sidebar)
2. Create relationships by dragging:
   - `incidents[IncidentId]` → `alerts[IncidentId]` (One-to-Many)
   - `incidents[IncidentId]` → `entities[IncidentId]` (One-to-Many)
   - `alerts[AlertId]` → `entities[AlertId]` (One-to-Many)

3. Set cross-filter direction to **Both** for better filtering

### 4.3 Create Date Table (for Time Intelligence)

1. Go to **Table view**
2. Click **New Table** and paste:

```DAX
DateTable = 
ADDCOLUMNS(
    CALENDAR(
        DATE(2026, 1, 1),
        TODAY()
    ),
    "Year", YEAR([Date]),
    "Month", MONTH([Date]),
    "MonthName", FORMAT([Date], "MMMM"),
    "Quarter", "Q" & QUARTER([Date]),
    "WeekDay", WEEKDAY([Date]),
    "WeekDayName", FORMAT([Date], "dddd")
)
```

3. Mark as Date Table:
   - Right-click `DateTable`
   - **Mark as date table**
   - Select `[Date]` column

4. Create relationship:
   - `DateTable[Date]` → `incidents[CreatedTime]` (Many-to-One)

---

## Step 5: Create DAX Measures

Create a new table called "Measures" to organize your calculations:

```DAX
// Basic Metrics
Total Incidents = COUNTROWS(incidents)

Active Incidents = 
CALCULATE(
    [Total Incidents],
    incidents[Status] <> "Resolved"
)

Resolved Incidents = 
CALCULATE(
    [Total Incidents],
    incidents[Status] = "Resolved"
)

// Severity Breakdown
High Severity = 
CALCULATE(
    [Total Incidents],
    incidents[Severity] = "High"
)

Medium Severity = 
CALCULATE(
    [Total Incidents],
    incidents[Severity] = "Medium"
)

Low Severity = 
CALCULATE(
    [Total Incidents],
    incidents[Severity] = "Low"
)

// Time Metrics
Avg Resolution Time (Hours) = 
AVERAGEX(
    FILTER(incidents, NOT(ISBLANK(incidents[ResolvedTime]))),
    DATEDIFF(incidents[CreatedTime], incidents[ResolvedTime], HOUR)
)

Avg Time to Assignment (Hours) = 
AVERAGEX(
    FILTER(incidents, NOT(ISBLANK(incidents[AssignedTo]))),
    DATEDIFF(incidents[CreatedTime], incidents[LastUpdateTime], HOUR)
)

// Classification
True Positives = 
CALCULATE(
    [Total Incidents],
    incidents[Classification] = "TruePositive"
)

False Positives = 
CALCULATE(
    [Total Incidents],
    incidents[Classification] = "FalsePositive"
)

// Trend Metrics
Incidents vs Previous Period = 
VAR CurrentPeriod = [Total Incidents]
VAR PreviousPeriod = 
    CALCULATE(
        [Total Incidents],
        DATEADD(DateTable[Date], -1, MONTH)
    )
RETURN
    DIVIDE(CurrentPeriod - PreviousPeriod, PreviousPeriod, 0)

// MITRE ATT&CK Coverage
Incidents with MITRE Techniques = 
CALCULATE(
    [Total Incidents],
    NOT(ISBLANK(incidents[MitreTechniques]))
)

// Alert Metrics
Total Alerts = COUNTROWS(alerts)

Avg Alerts per Incident = 
DIVIDE([Total Alerts], [Total Incidents], 0)

// Entity Metrics
Unique Devices Affected = 
CALCULATE(
    DISTINCTCOUNT(entities[DeviceName]),
    entities[EntityType] = "Machine"
)

Unique Users Affected = 
CALCULATE(
    DISTINCTCOUNT(entities[AccountName]),
    entities[EntityType] = "User"
)

Unique IPs Detected = 
CALCULATE(
    DISTINCTCOUNT(entities[IpAddress]),
    entities[EntityType] = "Ip"
)
```

---

## Step 6: Create Report Visualizations

### Page 1: Executive Dashboard

**Layout:**

1. **KPI Cards** (Top Row):
   - Total Incidents
   - Active Incidents
   - High Severity %
   - Avg Resolution Time

2. **Line Chart**: Incidents over Time
   - X-axis: `DateTable[Date]`
   - Y-axis: `[Total Incidents]`
   - Legend: `incidents[Severity]`

3. **Donut Chart**: Incidents by Status
   - Values: `[Total Incidents]`
   - Legend: `incidents[Status]`

4. **Bar Chart**: Top 10 Affected Users
   - X-axis: `entities[AccountName]`
   - Y-axis: `[Total Incidents]`
   - Filter: Top 10

5. **Table**: Recent High Severity Incidents
   - Columns: IncidentId, IncidentName, Severity, Status, CreatedTime
   - Filter: Severity = "High", Top 10 by CreatedTime

### Page 2: Threat Analysis

1. **Matrix**: MITRE ATT&CK Techniques
   - Rows: `incidents[MitreTechniques]`
   - Values: `[Total Incidents]`
   - Conditional formatting on values

2. **Map**: Geographic IP Distribution
   - Location: `entities[IpAddress]` (requires geocoding)
   - Size: Count of incidents

3. **Treemap**: Incidents by Detection Source
   - Group: `alerts[DetectionSource]`
   - Values: `[Total Alerts]`

4. **Clustered Column**: Severity Trend
   - X-axis: `DateTable[MonthName]`
   - Y-axis: `[High Severity]`, `[Medium Severity]`, `[Low Severity]`

### Page 3: Performance Metrics

1. **Gauge**: Resolution Rate
   - Value: `DIVIDE([Resolved Incidents], [Total Incidents])`
   - Target: 0.95

2. **Line and Stacked Column**: Incident Volume vs Resolution Time
   - X-axis: `DateTable[Date]`
   - Column: `[Total Incidents]`
   - Line: `[Avg Resolution Time (Hours)]`

3. **Table**: Analyst Performance
   - Rows: `incidents[AssignedTo]`
   - Values: `[Total Incidents]`, `[Resolved Incidents]`, `[Avg Resolution Time]`

4. **Waterfall**: Classification Breakdown
   - Category: `incidents[Classification]`
   - Y-axis: `[Total Incidents]`

---

## Step 7: Schedule Automated Refresh

### Option A: Local File Refresh (Simplest)

1. Create a Windows Task Scheduler job:
   - Trigger: Daily at 6:00 AM
   - Action: Run `powerbi_data_export.py`
   - Power BI set to auto-refresh on file change

### Option B: Power BI Service (Recommended for Teams)

1. **Publish Report:**
   - File > Publish > Publish to Power BI
   - Select workspace

2. **Configure Data Gateway:**
   - Install Power BI Gateway on a server
   - Register the data source (file path or database)

3. **Schedule Refresh:**
   - Go to Power BI Service
   - Navigate to Dataset > Settings
   - Expand "Scheduled refresh"
   - Set frequency: Daily at 7:00 AM
   - Configure credentials

### Option C: Python Dataflow (Advanced)

1. Create a Power BI Dataflow
2. Use Python script connector
3. Paste the data fetching code
4. Schedule dataflow refresh

---

## Step 8: Add Advanced Features

### Geographic Threat Map

For IP geolocation, add a separate enrichment step:

```python
def add_geolocation(self, df: pd.DataFrame) -> pd.DataFrame:
    """Add lat/lon for IP addresses"""
    import requests
    
    def get_location(ip):
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        loc = data.get('loc', '').split(',')
        return {
            'latitude': float(loc[0]) if len(loc) == 2 else None,
            'longitude': float(loc[1]) if len(loc) == 2 else None,
            'city': data.get('city'),
            'country': data.get('country')
        }
    
    # Apply to IP entities
    ip_entities = df[df['EntityType'] == 'Ip'].copy()
    locations = ip_entities['IpAddress'].apply(get_location)
    
    return pd.concat([df, pd.DataFrame(locations.tolist())], axis=1)
```

### Real-Time Streaming (Power BI Streaming Dataset)

For real-time dashboards, use Power BI REST API to push data:

```python
import requests

def push_to_powerbi_streaming(incident_data):
    """Push real-time data to Power BI streaming dataset"""
    
    streaming_url = "https://api.powerbi.com/beta/YOUR-WORKSPACE/datasets/YOUR-DATASET-ID/rows?key=YOUR-KEY"
    
    payload = [{
        "timestamp": datetime.utcnow().isoformat(),
        "incidentId": incident_data['incidentId'],
        "severity": incident_data['severity'],
        "status": incident_data['status']
    }]
    
    response = requests.post(streaming_url, json=payload)
    return response.status_code == 200
```

---

## Troubleshooting

### Authentication Errors

**Error:** `AADSTS700016: Application not found`
- **Fix:** Verify Client ID in config.json matches Azure AD app registration

**Error:** `Insufficient privileges`
- **Fix:** Grant admin consent for API permissions in Azure AD

### Data Issues

**No incidents returned:**
- Check date range with `--days` parameter
- Verify Defender XDR has incidents in that timeframe
- Check API permissions

**Missing relationships:**
- Ensure IncidentId and AlertId are not blank
- Check data types match (both should be text/string)

### Power BI Issues

**Refresh fails:**
- Check file path accessibility
- Verify Gateway is running (for Service refresh)
- Review credentials in dataset settings

**Slow performance:**
- Enable query folding where possible
- Use DirectQuery instead of Import for large datasets
- Optimize DAX measures (avoid calculated columns)

---

## Best Practices

1. **Data Retention:** Keep 90 days of incident history for trend analysis
2. **Incremental Refresh:** Export only new incidents daily, append to master file
3. **Row-Level Security:** Implement RLS in Power BI for different analyst teams
4. **Bookmarks:** Create bookmarks for common filter states (Active High Severity, etc.)
5. **Alerts:** Set up Data Alerts for KPIs (e.g., High Severity > 10)
6. **Mobile Layout:** Design mobile-optimized report pages for SOC on-call

---

## Next Steps

Once your Power BI report is running:

1. **Share with team:** Publish to workspace and grant access
2. **Create subscriptions:** Email reports to stakeholders
3. **Build custom visuals:** Install community visuals for specialized charts
4. **Integrate with Teams:** Embed Power BI tabs in Microsoft Teams channels
5. **API automation:** Use Power Automate to trigger actions based on incident data

---

**CyberProbe Power BI - Your Security Operations Dashboard**
