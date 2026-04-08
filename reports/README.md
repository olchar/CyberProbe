# Investigation Reports

This directory contains HTML and JSON reports generated from CyberProbe security investigations.

## Purpose

This directory serves as the central repository for:
- **Executive Reports** - High-level summaries for management
- **Incident Reports** - Detailed investigation findings
- **Enrichment Data** - IOC enrichment results in JSON format
- **Daily Reports** - SOC daily threat summaries
- **Investigation Logs** - Detailed investigation timelines

## Directory Structure

```
reports/
├── executive_*.html          # Executive-level reports
├── incident_*.html           # Incident investigation reports
├── investigation_*.html      # Detailed investigation analyses
├── investigation_*.json      # Investigation data (JSON format)
├── ip_enrichment_*.json      # IP enrichment results
├── ioc_enrichment_*.json     # IOC enrichment results
├── soc_*.html                # SOC daily/weekly reports
└── REPORT_TEMPLATE.md        # Report generation template
```

## Report Types

### 1. Executive Reports

**Format:** HTML  
**Audience:** C-level executives, management  
**Frequency:** As needed, post-incident  

**Contains:**
- Executive summary (3-4 paragraphs)
- Key findings and risk assessment
- Business impact analysis
- Prioritized remediation recommendations
- MITRE ATT&CK framework mapping
- Timeline of events

**Naming Convention:** `executive_report_[description]_YYYY-MM-DD.html`

**Examples:**
- [executive_report_2026-01-15.html](executive_report_2026-01-15.html)
- [executive_report_incident_42149_2026-01-21.html](executive_report_incident_42149_2026-01-21.html)
- [executive_report_threat_intel_2026-01-27.html](executive_report_threat_intel_2026-01-27.html)

### 2. Incident Reports

**Format:** HTML  
**Audience:** SOC analysts, incident responders  
**Frequency:** Per incident  

**Contains:**
- Incident overview and severity
- Detection timeline
- Affected assets and users
- Evidence collected
- Analysis and findings
- Remediation steps taken
- Lessons learned

**Naming Convention:** `incident_report_[incident_id]_YYYY-MM-DD.html`

**Examples:**
- [incident_41272_critical_report.html](incident_41272_critical_report.html)
- [incident_report_20251216.html](incident_report_20251216.html)
- [incident_report_u3174_compromised_account_2026-01-22.html](incident_report_u3174_compromised_account_2026-01-22.html)

### 3. Investigation Reports

**Format:** HTML + JSON  
**Audience:** Security analysts, forensic investigators  
**Frequency:** Per investigation  

**Contains:**
- Detailed investigation workflow
- IOC enrichment data
- User activity analysis
- Network correlation findings
- Forensic artifacts
- Raw data in JSON format

**Naming Convention:** 
- HTML: `investigation_[user/device]_YYYY-MM-DD.html`
- JSON: `investigation_[user/device]_YYYY-MM-DD.json`

**Examples:**
- [investigation_user03_2026-01-20.html](investigation_user03_2026-01-20.html)
- [investigation_user03_2026-01-20.json](investigation_user03_2026-01-20.json)
- [investigation_u421_2026-01-07.html](investigation_u421_2026-01-07.html)

### 4. Enrichment Reports

**Format:** JSON  
**Audience:** Automated systems, analysts  
**Frequency:** Per enrichment request  

**Contains:**
- IP address enrichment data
- IOC threat intelligence
- Geolocation information
- Abuse confidence scores
- VPN/Proxy detection
- ASN and ISP details

**Naming Convention:** 
- `ip_enrichment_[count]_ips.json`
- `ioc_enrichment_YYYYMMDD_HHMMSS.json`

**Examples:**
- [ip_enrichment_1_ips.json](ip_enrichment_1_ips.json)
- [ip_enrichment_3_ips.json](ip_enrichment_3_ips.json)
- [ioc_enrichment_20260121_163551.json](ioc_enrichment_20260121_163551.json)

### 5. SOC Daily/Weekly Reports

**Format:** HTML  
**Audience:** SOC team, management  
**Frequency:** Daily/Weekly  

**Contains:**
- Incident statistics
- Top threats detected
- Critical alerts
- Remediation status
- Trending analysis
- Team performance metrics

**Naming Convention:** `soc_[daily/weekly]_report_YYYY-MM-DD.html`

**Examples:**
- [soc_daily_report_2026-01-20.html](soc_daily_report_2026-01-20.html)
- [soc_incident_report_2026-01-26.html](soc_incident_report_2026-01-26.html)
- [daily_threat_report_2026-01-13.html](daily_threat_report_2026-01-13.html)

## Report Generation

### Manual Generation

#### Executive Report
```powershell
# Generate executive report for specific incident
.venv\Scripts\python.exe enrichment/generate_executive_report.py `
  --incident 42918 `
  --output reports/executive_report_incident_42918.html
```

#### Incident Report
```powershell
# Generate incident investigation report
.venv\Scripts\python.exe enrichment/generate_incident_report.py `
  --incident-id 42953 `
  --output reports/incident_report_42953_2026-01-27.html
```

#### Enrichment Report
```powershell
# Enrich IPs and generate JSON report
.venv\Scripts\python.exe enrichment/enrich_ips.py 213.209.159.181
# Output: reports/ip_enrichment_1_ips.json
```

### Automated Generation

**Security Copilot Agent:**
The Network Device Investigation Agent automatically generates reports when investigating incidents.

**Sentinel Playbook:**
Configure automated report generation on incident creation:
```json
{
  "trigger": "SecurityIncident",
  "actions": [
    {
      "type": "Function",
      "function": "GenerateIncidentReport",
      "inputs": {
        "incidentId": "@triggerBody()?['incidentId']",
        "outputPath": "reports/"
      }
    }
  ]
}
```

## Report Templates

### HTML Template Structure

```html
<!DOCTYPE html>
<html>
<head>
    <title>[Report Type] - [Date]</title>
    <style>
        /* Dark theme styling */
        body { background: #0d1117; color: #c9d1d9; }
    </style>
</head>
<body>
    <div class="header">
        <h1>[Report Title]</h1>
        <div class="meta">
            <!-- Report metadata -->
        </div>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <!-- Content -->
    </div>
    
    <!-- Additional sections -->
</body>
</html>
```

See [REPORT_TEMPLATE.md](REPORT_TEMPLATE.md) for complete template.

### JSON Structure

```json
{
  "report_metadata": {
    "generated_at": "2026-01-27T10:30:00Z",
    "report_type": "investigation",
    "version": "1.0"
  },
  "investigation": {
    "incident_id": "42918",
    "severity": "Critical",
    "findings": [ ... ]
  },
  "iocs": [ ... ],
  "timeline": [ ... ]
}
```

## Viewing Reports

### Local Viewing

```powershell
# Open in default browser
Start-Process reports/executive_report_threat_intel_2026-01-27.html

# View JSON in PowerShell
Get-Content reports/ip_enrichment_3_ips.json | ConvertFrom-Json | Format-List
```

### Share via Azure Blob Storage

```powershell
# Upload to Azure Blob Storage
az storage blob upload `
  --account-name cyberprobestorage `
  --container-name reports `
  --name executive_report_2026-01-27.html `
  --file reports/executive_report_threat_intel_2026-01-27.html

# Generate SAS URL for sharing
az storage blob generate-sas `
  --account-name cyberprobestorage `
  --container-name reports `
  --name executive_report_2026-01-27.html `
  --permissions r `
  --expiry 2026-02-01
```

### Export to PDF

```powershell
# Using PowerShell and Chrome
$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
& $chrome --headless --disable-gpu --print-to-pdf="report.pdf" `
  "file:///C:/CyberProbe/reports/executive_report.html"
```

## Report Retention

### Retention Policy

| Report Type | Retention Period | Archive Location |
|-------------|------------------|------------------|
| Executive Reports | 7 years | Azure Blob (Cool tier) |
| Incident Reports | 7 years | Azure Blob (Cool tier) |
| Investigation Reports | 3 years | Azure Blob (Cool tier) |
| Enrichment Data (JSON) | 1 year | Azure Blob (Archive tier) |
| Daily Reports | 90 days | Local + Azure Blob |

### Archival Process

```powershell
# Archive reports older than 90 days
$archiveDate = (Get-Date).AddDays(-90)
Get-ChildItem reports/*.html | 
  Where-Object {$_.LastWriteTime -lt $archiveDate} |
  ForEach-Object {
    az storage blob upload `
      --account-name cyberprobestorage `
      --container-name reports-archive `
      --name $_.Name `
      --file $_.FullName `
      --tier Archive
    Remove-Item $_.FullName
  }
```

## Security and Compliance

### Classification

All reports are classified as:
- **Confidential** - Internal use only
- **Restricted** - SOC team access only (for critical incidents)

### Access Control

- Reports contain sensitive security information
- Limit distribution to authorized personnel
- Use Azure AD authentication for shared storage
- Implement Azure Information Protection labels

### Redaction

Before sharing externally:
- Redact internal IP addresses
- Remove user personal information
- Sanitize system names and paths
- Remove API keys and credentials

```powershell
# Redact sensitive information
(Get-Content report.html) `
  -replace '10\.\d+\.\d+\.\d+', '[REDACTED_IP]' `
  -replace 'user\d+@contoso\.com', '[REDACTED_USER]' |
  Set-Content report_redacted.html
```

## Best Practices

### 1. Consistent Naming

Follow naming conventions for easy filtering:
```
[type]_[identifier]_YYYY-MM-DD.ext
```

### 2. Include Metadata

All HTML reports should include:
```html
<meta name="report-type" content="executive">
<meta name="incident-id" content="42918">
<meta name="generated-date" content="2026-01-27">
<meta name="classification" content="confidential">
```

### 3. Version Control

For JSON reports, include version:
```json
{
  "report_version": "1.0",
  "schema_version": "2.0"
}
```

### 4. Quality Checks

Before finalizing reports:
- [ ] All sections completed
- [ ] Sensitive data redacted (if sharing)
- [ ] Links and references valid
- [ ] Spelling and grammar checked
- [ ] MITRE ATT&CK mapping accurate
- [ ] Timeline chronologically ordered

## Related Documentation

- **Report Template:** [REPORT_TEMPLATE.md](REPORT_TEMPLATE.md)
- **Sample Report:** [SAMPLE_REPORT.html](SAMPLE_REPORT.html)
- **Investigation Guide:** [../Investigation-Guide.md](../Investigation-Guide.md)
- **Enrichment Scripts:** [../enrichment/README.md](../enrichment/README.md)

## Recent Reports

| Date | Type | Description | File |
|------|------|-------------|------|
| 2026-01-27 | Executive | Network device compromise - mb-wap.internal | [executive_report_threat_intel_2026-01-27.html](executive_report_threat_intel_2026-01-27.html) |
| 2026-01-27 | Incident | DLP email exfiltration - Incident 42953 | [incident_report_42953_2026-01-27.html](incident_report_42953_2026-01-27.html) |
| 2026-01-22 | Investigation | Compromised account u3174 investigation | [incident_report_u3174_compromised_account_2026-01-22.html](incident_report_u3174_compromised_account_2026-01-22.html) |
| 2026-01-21 | Executive | Incident 42149 critical analysis | [executive_report_incident_42149_2026-01-21.html](executive_report_incident_42149_2026-01-21.html) |

---

**Last Updated:** January 28, 2026  
**Maintainer:** CyberProbe Security Team  
**Classification:** CONFIDENTIAL
