---
name: report-generation
description: Generate comprehensive security investigation reports in HTML and JSON formats. Use when creating incident reports, investigation summaries, or executive briefings. Includes dark theme templates, MITRE ATT&CK mapping, and Power BI dataset export.
---

# Report Generation Skill

This skill creates professional security investigation reports in multiple formats with threat intelligence integration and executive-ready visualizations.

## When to Use This Skill

Use this skill when:
- Completing security investigations (need final documentation)
- Responding to critical incidents (executive briefings required)
- Generating Power BI datasets for analytics dashboards
- Creating audit trails for compliance
- Sharing investigation findings with stakeholders
- Archiving investigation data for future reference

## Report Types

### 1. Investigation JSON Reports
**Purpose**: Machine-readable investigation data for archival and further analysis

**Filename**: `reports/investigation_<upn_prefix>_YYYY-MM-DD.json`

**Required Fields:**
```json
{
  "investigationDate": "2026-01-15T09:30:00Z",
  "userPrincipalName": "user@contoso.com",
  "displayName": "User Name",
  "userId": "<USER_OBJECT_ID>",
  "windowsSID": "<WINDOWS_SID>",
  "department": "IT Security",
  "officeLocation": "Building 5",
  "dateRangeStart": "2026-01-08T00:00:00Z",
  "dateRangeEnd": "2026-01-17T23:59:59Z",
  
  "anomalies": [
    {
      "timestamp": "2026-01-14T15:23:11Z",
      "activityType": "Anomalous sign-in",
      "sourceIP": "206.168.34.210",
      "investigationPriority": 8
    }
  ],
  
  "signInsByApp": [
    {"appName": "Office 365", "count": 142},
    {"appName": "Azure Portal", "count": 23}
  ],
  
  "signInsByLocation": [
    {"city": "Seattle", "country": "US", "ipAddress": "52.168.10.5", "count": 120},
    {"city": "Chicago", "country": "US", "ipAddress": "206.168.34.210", "count": 1}
  ],
  
  "signInFailures": [
    {"resultType": "50126", "description": "Invalid credentials", "count": 3}
  ],
  
  "auditLogActivity": [
    {"timestamp": "2026-01-12T10:15:00Z", "operation": "Update user", "result": "Success"}
  ],
  
  "officeActivity": [
    {"operation": "FileAccessed", "workload": "SharePoint", "count": 45}
  ],
  
  "securityIncidents": [
    {
      "incidentNumber": 41272,
      "severity": "High",
      "status": "Active",
      "description": "Suspicious C2 communication detected"
    }
  ],
  
  "ipEnrichment": [
    {
      "ip": "206.168.34.210",
      "abuseConfidenceScore": 100,
      "totalReports": 1363,
      "city": "Chicago",
      "isVPN": false
    }
  ],
  
  "threatIntelligence": [],
  "dlpEvents": [],
  "riskDetections": []
}
```

**Usage in Workflow:**
```python
investigation_data = {
  # ... all fields above ...
}

create_file(
  "reports/investigation_user_2026-01-15.json",
  json.dumps(investigation_data, indent=2)
)
```

### 2. Incident HTML Reports
**Purpose**: Executive-ready incident response documentation with interactive visuals

**Filename**: `reports/incident_<incident_id>_critical_report.html`

**Template Structure:**
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Critical Incident Report #41272</title>
  <style>
    body { 
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: #e0e0e0;
      font-family: 'Segoe UI', Arial, sans-serif;
    }
    .header { background: #0f3460; border-left: 5px solid #00d4ff; }
    .critical { color: #ff4757; font-weight: bold; }
    .section { background: rgba(255,255,255,0.05); border-radius: 8px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔴 CRITICAL INCIDENT REPORT</h1>
    <p>Incident #41272 | January 14, 2026</p>
  </div>
  
  <div class="section">
    <h2>Executive Summary</h2>
    <p>Command & Control (C2) communication detected from alpine-srv1...</p>
  </div>
  
  <div class="section">
    <h2>Threat Intelligence Analysis</h2>
    <table>
      <tr><td>IP Address</td><td>206.168.34.210</td></tr>
      <tr><td>Abuse Confidence</td><td class="critical">100%</td></tr>
      <tr><td>Total Reports</td><td>1,363</td></tr>
    </table>
  </div>
  
  <div class="section">
    <h2>MITRE ATT&CK Mapping</h2>
    <ul>
      <li><strong>T1071</strong> - Application Layer Protocol (C2 Communication)</li>
    </ul>
  </div>
  
  <div class="section">
    <h2>Immediate Actions Required</h2>
    <h3>Priority 1 (Immediate - 0-15 min)</h3>
    <ol>
      <li>Isolate alpine-srv1 from network</li>
      <li>Block IP 206.168.34.210 at firewall</li>
    </ol>
  </div>
</body>
</html>
```

**Key Sections Required:**
1. **Header**: Incident number, date, severity badge
2. **Executive Summary**: 2-3 sentence overview
3. **Incident Timeline**: Chronological event list
4. **Technical Details**: IP addresses, assets, attack vectors
5. **Threat Intelligence**: Enrichment data with risk scores
6. **MITRE ATT&CK Mapping**: Relevant tactics and techniques
7. **Immediate Actions**: Priority 1/2/3 remediation steps
8. **Investigation Queries**: KQL queries used
9. **Methodology**: Data extraction pipeline (see [Methodology Section](#methodology-section-mandatory) below)
10. **Recommendations**: Long-term improvements

### 3. Power BI Datasets
**Purpose**: Refreshable datasets for analytics dashboards

**Script**: `enrichment/powerbi_data_export.py`

**Output Files:**
- `powerbi_incidents.xlsx` - Incidents table
- `powerbi_alerts.xlsx` - Alerts table
- `powerbi_entities.xlsx` - Entities table
- `powerbi_incidents.csv` - CSV format
- `powerbi_incidents.json` - JSON format

**Execution:**
```powershell
python enrichment/powerbi_data_export.py
```

**Data Schema:**
```
Incidents Table:
- IncidentId, IncidentNumber, Severity, Status, Classification
- Title, Description, FirstActivityTime, LastActivityTime
- AssignedTo, AlertCount, ProviderName

Alerts Table:
- AlertId, IncidentId, Severity, Title, Category
- DetectionSource, FirstActivityTime, Status
- ProviderAlertId, ServiceSource

Entities Table:
- EntityId, IncidentId, EntityType (IP, User, Device, File)
- EntityValue (actual IP/username/hostname)
- AdditionalData (JSON blob)
```

See [POWERBI_SETUP.md](../../../docs/POWERBI_SETUP.md) for complete integration guide.

## Dark Theme Color Palette

Use these colors for all HTML reports to maintain brand consistency:

| Element | Color | Usage |
|---------|-------|-------|
| Primary Background | `#1a1a2e` | Body background gradient start |
| Secondary Background | `#16213e` | Body background gradient end |
| Section Background | `#0f3460` | Headers, cards |
| Accent | `#00d4ff` | Borders, links, highlights |
| Text Primary | `#e0e0e0` | Body text |
| Text Secondary | `#a0a0a0` | Subtitles, metadata |
| Critical Alert | `#ff4757` | High severity indicators |
| Warning | `#ffa502` | Medium severity |
| Success | `#2ed573` | Low severity, success states |
| Error | `#ff6348` | Errors, failures |

**CSS Example:**
```css
:root {
  --bg-primary: #1a1a2e;
  --bg-secondary: #16213e;
  --bg-section: #0f3460;
  --accent: #00d4ff;
  --text-primary: #e0e0e0;
  --text-secondary: #a0a0a0;
  --critical: #ff4757;
  --warning: #ffa502;
  --success: #2ed573;
}
```

## Report Generation Workflow

### Phase 1: Data Collection
Gather all investigation data from Phase 2 queries:
- User profile (Graph API)
- Anomalies (Query 2)
- Sign-ins (Query 3a/b/c/d)
- Audit logs (Query 4)
- Incidents (Query 6 or mcp_triage_GetIncidentById)
- IP enrichment (enrich_ips.py)

### Phase 2: Data Transformation
```python
# Handle null values
department = user_data.get('department') or 'Unknown'
office_location = user_data.get('officeLocation') or 'Unknown'

# Transform anomalies
anomalies_array = [
  {
    'timestamp': a['TimeGenerated'],
    'activityType': a['ActivityType'],
    'sourceIP': a['SourceIPAddress'],
    'investigationPriority': a['InvestigationPriority']
  }
  for a in anomalies_result
]

# If no anomalies, use empty array
if not anomalies_array:
  anomalies_array = []
```

### Phase 3: JSON Export
```python
investigation_json = {
  'investigationDate': datetime.now().isoformat(),
  'userPrincipalName': upn,
  'userId': user_id,
  'windowsSID': windows_sid,
  'anomalies': anomalies_array,  # Empty array if no data
  'signInsByApp': sign_ins_by_app,
  'ipEnrichment': enrichment_results,
  # ... all other fields ...
}

filename = f"reports/investigation_{upn.split('@')[0]}_{datetime.now().strftime('%Y-%m-%d')}.json"
create_file(filename, json.dumps(investigation_json, indent=2))
```

### Phase 4: HTML Report Generation
```python
html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Investigation Report - {display_name}</title>
  <style>{css_styles}</style>
</head>
<body>
  <div class="header">
    <h1>Security Investigation Report</h1>
    <p>{display_name} ({upn})</p>
    <p>Investigation Period: {start_date} to {end_date}</p>
  </div>
  
  <div class="section">
    <h2>Key Findings</h2>
    <ul>
      <li>Total Anomalies: {len(anomalies_array)}</li>
      <li>Unique Locations: {len(sign_ins_by_location)}</li>
      <li>High-Risk IPs: {len([ip for ip in ip_enrichment if ip['abuseConfidenceScore'] >= 75])}</li>
      <li>Security Incidents: {len(security_incidents)}</li>
    </ul>
  </div>
  
  {generate_anomalies_section(anomalies_array)}
  {generate_ip_enrichment_section(ip_enrichment)}
  {generate_incidents_section(security_incidents)}
  
</body>
</html>
"""

filename = f"reports/investigation_{upn.split('@')[0]}_{datetime.now().strftime('%Y-%m-%d')}.html"
create_file(filename, html_content)
```

## Report Templates

### Template 1: Standard Investigation Report

**Use Case**: Regular user investigation with 7-day scope

**Sections:**
1. Investigation metadata (user, date range, investigator)
2. Executive summary (key findings, risk level)
3. Anomaly analysis (table with timestamps, IPs, priority scores)
4. Geographic analysis (map of sign-in locations)
5. Authentication timeline (chronological sign-in events)
6. Application usage (chart of apps accessed)
7. IP threat intelligence (enrichment data table)
8. Security incidents (related incidents list)
9. Methodology (tools, queries, data sources, fallbacks — see [Methodology Section](#methodology-section-mandatory))
10. Recommendations (next steps, monitoring suggestions)

### Template 2: Critical Incident Report

**Use Case**: Active incident response for high-severity alerts

**Sections:**
1. Incident header (red severity badge, incident number)
2. Executive summary (what happened, impact, urgency)
3. Incident timeline (chronological attack progression)
4. Technical details (IOCs, affected assets, attack vectors)
5. Threat intelligence (IP enrichment, OSINT)
6. MITRE ATT&CK mapping (tactics and techniques)
7. Immediate actions (Priority 1/2/3 tasks with time bounds)
8. Investigation queries (KQL queries for validation)
9. Methodology (tools, queries, data sources, fallbacks — see [Methodology Section](#methodology-section-mandatory))
10. Long-term recommendations (policy changes, monitoring)
11. Appendix (full raw data, API responses)

### Template 3: Executive Briefing

**Use Case**: C-level presentation (non-technical stakeholders)

**Sections:**
1. Executive summary (2-3 sentences max)
2. Risk assessment (Critical/High/Medium/Low with color coding)
3. Key metrics (total incidents, resolution time, affected users)
4. Visual dashboard (charts, graphs, heatmaps)
5. Action items (what leadership needs to approve/fund)
6. Business impact (productivity loss, data exposure, compliance)
7. Methodology (condensed — tools used and data sources; see [Methodology Section](#methodology-section-mandatory))

## Visualization Examples

### IP Enrichment Table
```html
<table class="enrichment-table">
  <thead>
    <tr>
      <th>IP Address</th>
      <th>Location</th>
      <th>ISP</th>
      <th>Abuse Score</th>
      <th>VPN/Tor</th>
      <th>Risk</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>206.168.34.210</td>
      <td>Chicago, US</td>
      <td>Censys Inc.</td>
      <td class="critical">100%</td>
      <td>No</td>
      <td class="critical">CRITICAL</td>
    </tr>
  </tbody>
</table>
```

### MITRE ATT&CK Mapping
```html
<div class="mitre-section">
  <h3>MITRE ATT&CK Framework</h3>
  <div class="technique">
    <strong>T1071</strong> - Application Layer Protocol
    <p class="description">Adversaries using C2 channel via common application layer protocols.</p>
    <p class="evidence">Evidence: Outbound HTTPS to known malicious IP 206.168.34.210</p>
  </div>
  <div class="technique">
    <strong>T1110</strong> - Brute Force
    <p class="description">Multiple failed authentication attempts detected.</p>
    <p class="evidence">Evidence: 27 failed sign-ins from 5 unique IPs within 2 hours</p>
  </div>
</div>
```

### Timeline Visualization
```html
<div class="timeline">
  <div class="timeline-event">
    <span class="timestamp">2026-01-14 08:15:23</span>
    <span class="event">Initial sign-in from Seattle (52.168.10.5)</span>
    <span class="badge success">Legitimate</span>
  </div>
  <div class="timeline-event">
    <span class="timestamp">2026-01-14 14:22:11</span>
    <span class="event">Suspicious sign-in from Chicago (206.168.34.210)</span>
    <span class="badge critical">High Risk</span>
  </div>
  <div class="timeline-event">
    <span class="timestamp">2026-01-14 14:25:33</span>
    <span class="event">C2 communication detected to 206.168.34.210</span>
    <span class="badge critical">Critical</span>
  </div>
</div>
```

## Power BI Integration

### Dataset Export Process
1. **Run export script**:
   ```powershell
   python enrichment/powerbi_data_export.py
   ```

2. **Import to Power BI Desktop**:
   - Get Data → Excel → Select `powerbi_incidents.xlsx`
   - Get Data → Excel → Select `powerbi_alerts.xlsx`
   - Get Data → Excel → Select `powerbi_entities.xlsx`

3. **Create relationships**:
   - Incidents[IncidentId] → Alerts[IncidentId] (One-to-Many)
   - Incidents[IncidentId] → Entities[IncidentId] (One-to-Many)

4. **Build visualizations** (see [POWERBI_SETUP.md](../../../docs/POWERBI_SETUP.md) for DAX measures)

### Scheduled Refresh
Configure Azure Automation to run export script daily:
```powershell
# Azure Runbook
$date = Get-Date -Format "yyyy-MM-dd"
python C:\CyberProbe\enrichment\powerbi_data_export.py
```

## Output File Naming Conventions

| Report Type | Filename Pattern | Example |
|-------------|-----------------|---------|
| User Investigation (JSON) | `investigation_<upn_prefix>_YYYY-MM-DD.json` | `investigation_jsmith_2026-01-15.json` |
| User Investigation (HTML) | `investigation_<upn_prefix>_YYYY-MM-DD.html` | `investigation_jsmith_2026-01-15.html` |
| Incident Report | `incident_report_<incident_id>_YYYY-MM-DD.html` | `incident_report_41272_2026-01-15.html` |
| IP Enrichment | `ip_enrichment_<count>_ips_YYYY-MM-DD.json` | `ip_enrichment_15_ips_2026-01-15.json` |
| Power BI Incidents | `powerbi_incidents.{xlsx\|csv\|json}` | `powerbi_incidents.xlsx` |
| Power BI Alerts | `powerbi_alerts.{xlsx\|csv\|json}` | `powerbi_alerts.xlsx` |
| Power BI Entities | `powerbi_entities.{xlsx\|csv\|json}` | `powerbi_entities.xlsx` |

## Best Practices

### Data Quality
✅ **Handle null values**: Use `or 'Unknown'` for optional fields
✅ **Empty arrays**: Export `[]` instead of omitting fields
✅ **Timestamps**: Use ISO 8601 format (`2026-01-15T09:30:00Z`)
✅ **Numbers**: Ensure integers are not quoted in JSON
✅ **Booleans**: Use `true/false` not `"True"/"False"`

### Performance
✅ **Limit data**: Export only relevant date ranges
✅ **Pagination**: For large datasets, implement paging
✅ **Caching**: Reuse existing JSON files when possible
✅ **Async**: Generate HTML asynchronously after JSON export

### Security
✅ **Redaction**: Remove sensitive PII if sharing externally
✅ **Access control**: Store reports in protected directories
✅ **Encryption**: Encrypt reports containing credentials
✅ **Retention**: Follow organizational data retention policies

## Example Report Generation Scenarios

### Scenario 1: Standard Investigation
```
User: "Generate report for user@contoso.com last 7 days"

Workflow:
1. Load investigation JSON: reports/investigation_user_2026-01-15.json
2. If not exists, run full investigation workflow first
3. Generate HTML report using Template 1 (Standard Investigation)
4. Include all sections: anomalies, sign-ins, IP enrichment, incidents
5. Export to: reports/investigation_user_2026-01-15.html
6. Report completion: "Report generated: [link to file]"
```

### Scenario 2: Critical Incident Report
```
User: "Generate critical incident report for #41272"

Workflow:
1. Get incident: mcp_triage_GetIncidentById("41272")
2. Extract entities (IPs, users, devices)
3. Enrich IPs with threat intelligence
4. Map to MITRE ATT&CK (T1071 - C2 Communication)
5. Generate HTML using Template 2 (Critical Incident)
6. Include immediate actions with Priority 1/2/3 tasks
7. Export to: reports/incident_report_41272_2026-01-15.html
```

### Scenario 3: Power BI Dataset Refresh
```
User: "Refresh Power BI datasets"

Workflow:
1. Run: python enrichment/powerbi_data_export.py
2. Authenticate to Defender API (Azure AD)
3. Fetch incidents, alerts, entities
4. Flatten nested JSON structures
5. Export to Excel: powerbi_incidents.xlsx (3 sheets)
6. Export to CSV: powerbi_incidents.csv
7. Export to JSON: powerbi_incidents.json
8. Report: "Exported 150 incidents, 342 alerts, 567 entities"
```

## Resources

- [POWERBI_SETUP.md](../../../docs/POWERBI_SETUP.md) - Complete Power BI integration guide
- [powerbi_data_export.py](../../../enrichment/powerbi_data_export.py) - Dataset export script
- [Investigation-Guide.md](../../../Investigation-Guide.md) - Investigation workflows
- [Example HTML Report](../../../reports/incident_41272_critical_report.html) - Template reference

## Methodology Section (MANDATORY)

Every report — regardless of type (investigation, incident, executive briefing, blast radius, analytics) — **MUST** include a Methodology section. This section documents how the data was collected so findings are reproducible and auditable.

### Required Subsections

| Subsection | Content | Required For |
|------------|---------|-------------|
| **Tool Stack** | Table listing every MCP tool / API / script used, its purpose, and status (✅ Used / ❌ Blocked / ⚠️ Partial) | All reports |
| **Data Extraction Queries** | Exact KQL / API calls used, with syntax-highlighted code blocks. For each query: which report section it feeds and a one-line result summary | All reports with queries |
| **Data Sources** | Sentinel workspace ID, time range, tables queried, seed data files (e.g., query library references) | All reports |
| **Fallback Strategy** | If any primary source was blocked or failed, document: what was attempted, the error, and which alternative data path was used | Only when fallbacks occurred |
| **Data Flow Diagram** | Optional Mermaid diagram showing Sources → Queries → Report Sections | Recommended for complex reports |

### Placement

- **HTML reports**: Place the Methodology section **after** the main findings/recommendations and **before** the footer.
- **JSON reports**: Add a top-level `"methodology"` object containing `tools`, `queries`, `dataSources`, and `fallbacks` arrays.
- **Executive briefings**: Use a condensed version (Tool Stack + Data Sources only).

### Example HTML Structure

```html
<div class="section" style="border-left: 4px solid var(--accent);">
  <h2>🔬 Methodology</h2>
  <h3>Tool Stack</h3>
  <table><!-- MCP tools with purpose and status --></table>
  <h3>Data Extraction Queries</h3>
  <div class="query-card">
    <h4>Query 1 — [Title]</h4>
    <p>Feeds: [Report sections]</p>
    <pre><code>KQL query here</code></pre>
    <p>Result: [summary]</p>
  </div>
  <h3>Data Sources</h3>
  <table><!-- workspace, time range, tables --></table>
  <h3>Fallback Strategy</h3>
  <table><!-- intended source, failure, alternative --></table>
</div>
```

## Important Notes

⚠️ **Always export JSON first** - HTML reports depend on JSON data structure
⚠️ **Handle empty arrays** - Use `[]` not null for missing data
⚠️ **Use dark theme** - Maintain brand consistency across all reports
⚠️ **Include timestamps** - All reports need investigation date/time
⚠️ **MITRE mapping** - Critical incidents require ATT&CK framework mapping
⚠️ **Archive reports** - Store in reports/ directory with date in filename
⚠️ **Methodology section** - MANDATORY in every report (see above)
