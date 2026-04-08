# Power BI Dashboard and Data Export

This directory contains Power BI integration tools, dashboards, and data export scripts for CyberProbe threat intelligence visualization.

## Contents

### Scripts

| File | Description | Usage |
|------|-------------|-------|
| [export_investigation_data.py](export_investigation_data.py) | Export investigation data for Power BI | `python export_investigation_data.py` |

### Documentation

| File | Description |
|------|-------------|
| [POWERBI_DASHBOARD_SETUP.md](POWERBI_DASHBOARD_SETUP.md) | Complete dashboard setup guide |

### Query Files

| File | Description |
|------|-------------|
| [sentinel_queries.kql](sentinel_queries.kql) | KQL queries for Sentinel data extraction |

### Data Directory

| Directory | Description |
|-----------|-------------|
| [data/](data/) | Exported data files for Power BI ingestion |

## Quick Start

### 1. Export Investigation Data

```powershell
# Export enrichment data
.venv\Scripts\python.exe enrichment/powerbi_data_export.py

# Export investigation results
.venv\Scripts\python.exe powerbi/export_investigation_data.py
```

### 2. Import to Power BI Desktop

1. Open Power BI Desktop
2. **Get Data** → **JSON** or **CSV**
3. Navigate to `powerbi/data/`
4. Select exported file
5. Transform data as needed

### 3. Create Visualizations

See [POWERBI_DASHBOARD_SETUP.md](POWERBI_DASHBOARD_SETUP.md) for:
- Dashboard templates
- Visualization examples
- Data model configuration

## Dashboard Features

### Threat Intelligence Overview

**Data Sources:**
- IP enrichment results
- IOC analysis
- Incident timelines
- MITRE ATT&CK mapping

**Visualizations:**
- Abuse confidence score distribution
- Geographic threat map
- Top malicious IPs
- Incident severity trends

### Investigation Analytics

**Metrics:**
- Average investigation time
- Incidents by severity
- Top threat actors
- Remediation status

**Visualizations:**
- Incident funnel
- Timeline charts
- User risk scoring
- Asset exposure matrix

### Executive Reporting

**KPIs:**
- Critical incidents (24h)
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Threat confidence average

**Visualizations:**
- Executive scorecard
- Trend analysis
- Compliance metrics
- ROI dashboard

## Data Export Format

### Enrichment Data (JSON)

```json
{
  "ip": "213.209.159.181",
  "abuse_confidence_score": 100,
  "total_reports": 1981,
  "country": "DE",
  "city": "Aachen",
  "org": "AS208137 Feo Prest SRL",
  "is_vpn": false,
  "risk_level": "CRITICAL",
  "timestamp": "2026-01-27T10:30:00Z"
}
```

### Investigation Data (CSV)

```csv
incident_id,severity,status,detection_time,resolution_time,affected_users,flagged_ips
42918,Critical,Active,2026-01-27T06:09:00Z,,1,213.209.159.181
42914,Medium,Active,2026-01-27T05:08:00Z,,1,"64.112.126.83,150.40.179.15"
```

### Incident Timeline (JSON)

```json
{
  "incident_id": 42918,
  "events": [
    {
      "timestamp": "2026-01-27T06:09:00Z",
      "event_type": "Detection",
      "description": "TI Map IP Entity to DeviceNetworkEvents",
      "severity": "Critical"
    }
  ]
}
```

## Power BI Data Model

### Tables

1. **IncidentFacts**
   - incident_id (PK)
   - severity
   - status
   - detection_time
   - resolution_time

2. **IPEnrichment**
   - ip_address (PK)
   - abuse_confidence_score
   - total_reports
   - country
   - risk_level

3. **TimeDimension**
   - date (PK)
   - day_of_week
   - month
   - quarter
   - year

4. **MITREMapping**
   - technique_id (PK)
   - technique_name
   - tactic
   - incident_id (FK)

### Relationships

```
IncidentFacts.incident_id → MITREMapping.incident_id (1:Many)
IncidentFacts.detection_time → TimeDimension.date (Many:1)
```

## Sentinel Integration

### Extract Data from Sentinel

Use KQL queries in [sentinel_queries.kql](sentinel_queries.kql):

```kql
// Get all incidents from last 30 days
SecurityIncident
| where TimeGenerated > ago(30d)
| project 
    IncidentNumber,
    Severity,
    Status,
    TimeGenerated,
    Title,
    OwnerAssignedTo
| order by TimeGenerated desc
```

### Export from Sentinel

1. **Azure Portal** → **Microsoft Sentinel**
2. **Logs** → Run KQL query
3. **Export** → **Export to CSV**
4. Save to `powerbi/data/sentinel_export.csv`

## Automated Data Refresh

### Schedule PowerShell Script

```powershell
# Create scheduled task to export data daily
$action = New-ScheduledTaskAction `
  -Execute "PowerShell.exe" `
  -Argument "-File C:\CyberProbe\powerbi\export_investigation_data.py"

$trigger = New-ScheduledTaskTrigger -Daily -At 6am

Register-ScheduledTask `
  -TaskName "CyberProbe-PowerBI-Export" `
  -Action $action `
  -Trigger $trigger
```

### Power BI Service Auto-Refresh

1. Publish dashboard to Power BI Service
2. **Settings** → **Scheduled refresh**
3. Configure refresh frequency (up to 8x/day)
4. Set credentials for data sources

## Dashboard Templates

### Template 1: SOC Executive Dashboard

**Page 1: Overview**
- Critical incidents card
- MTTD/MTTR gauges
- Incident trend line
- Geographic threat map

**Page 2: Threat Intelligence**
- Top malicious IPs table
- Abuse confidence distribution
- IOC timeline
- MITRE ATT&CK heatmap

**Page 3: Investigation Metrics**
- Average investigation time
- Incident status funnel
- User risk scoring
- Remediation backlog

### Template 2: Incident Investigation Dashboard

**Purpose:** Deep-dive analysis for specific incidents

**Visualizations:**
- Incident timeline
- Related entities network graph
- IOC enrichment details
- User activity patterns
- Remediation actions tracker

### Template 3: Threat Actor Profile

**Purpose:** Track threat actor campaigns

**Visualizations:**
- Actor attribution timeline
- Target industry breakdown
- MITRE ATT&CK techniques used
- Infrastructure mapping
- Campaign correlation

## Best Practices

### 1. Incremental Refresh

Configure incremental refresh for large datasets:
- **Range:** Last 30 days (full refresh)
- **Archive:** Older data (incremental only)

### 2. Data Compression

Use Parquet format for large exports:
```python
df.to_parquet('powerbi/data/enrichment_data.parquet')
```

### 3. Performance Optimization

- Use import mode (not DirectQuery)
- Create aggregations for large tables
- Remove unused columns
- Optimize DAX measures

### 4. Security

- Enable Row-Level Security (RLS)
- Restrict sensitive data access
- Use Azure AD authentication
- Encrypt data sources

## Troubleshooting

### Issue: "Could not refresh data"

**Solutions:**
1. Check file permissions in `powerbi/data/`
2. Verify Python script executed successfully
3. Ensure data files are not locked by another process

### Issue: "Data type mismatch"

**Solution:** Transform data types in Power Query:
```powerquery
#"Changed Type" = Table.TransformColumnTypes(
    Source,
    {{"abuse_confidence_score", Int64.Type}}
)
```

### Issue: "Slow dashboard performance"

**Solutions:**
1. Reduce data volume (filter to last 90 days)
2. Create aggregated tables
3. Use calculated columns instead of measures
4. Remove unnecessary visuals

## Related Documentation

- **Power BI Setup Guide:** [POWERBI_DASHBOARD_SETUP.md](POWERBI_DASHBOARD_SETUP.md)
- **Enrichment Scripts:** [../enrichment/README.md](../enrichment/README.md)
- **Sentinel Queries:** [../queries/README.md](../queries/README.md)
- **Investigation Guide:** [../Investigation-Guide.md](../Investigation-Guide.md)

## Examples

### Example 1: Export Daily Threat Data

```powershell
# Export enrichment data for today
.venv\Scripts\python.exe powerbi/export_investigation_data.py --date today

# Open Power BI and refresh
```

### Example 2: Create Incident Timeline

```powershell
# Extract incident timeline from Sentinel
$kql = Get-Content powerbi/sentinel_queries.kql
Invoke-AzOperationalInsightsQuery -WorkspaceId $wsId -Query $kql | 
  Export-Csv powerbi/data/incident_timeline.csv
```

### Example 3: Schedule Weekly Export

```powershell
# Run every Monday at 6 AM
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName "CyberProbe-Weekly-Export" -Action $action -Trigger $trigger
```

---

**Last Updated:** January 28, 2026  
**Maintainer:** CyberProbe Security Team
