# Sample Data for CyberProbe Labs

This directory contains sanitized sample data for hands-on lab exercises when production data is unavailable.

---

## 📁 Directory Structure

```
sample-data/
├── sample_investigation_user1.json      # Complete investigation output (Lab 102)
├── ip_enrichment_samples.json           # 20 IPs with full threat intel (All labs)
├── sessionid_traces.json                # 3 SessionId auth chain scenarios (Lab 103)
├── incidents/                           # Sample security incident JSON files
│   ├── phishing_incident_sample.json
│   └── compromised_identity_sample.json
├── users/                               # Test user profiles for investigation scenarios
│   ├── test_user_profile.json
│   └── privileged_user_profile.json
└── query-results/                       # Pre-captured KQL query outputs (coming soon)
```

---

## 📊 Available Sample Files

### Investigation Data

#### sample_investigation_user1.json ✅
**Purpose**: Lab 102 — Complete investigation output  
**User**: jdoe@contoso.com (Account Executive)  
**Scenario**: Account compromise — password spray → impossible travel → data exfiltration

**Contains**:
- Investigation metadata with 7-day lookback
- User identity (group membership, roles, MFA methods)
- 3 anomalies (NewCountryIP, ImpossibleTravel, PasswordSpray)
- Sign-in activity (287 events across 5 apps)
- Sign-in failures (47 password spray + 2 MFA challenges)
- 5 IP addresses with full enrichment (including Shodan)
- 1 security incident with 3 correlated alerts
- 3 audit log entries (role escalation, OAuth consent, mailbox rule)
- 2 Office activity entries (SharePoint exfiltration via Tor)
- 2 risk detections + executive summary with 6 MITRE ATT&CK techniques

#### ip_enrichment_samples.json ✅
**Purpose**: All labs — IP threat intelligence reference dataset  
**Records**: 20 IPs with full multi-source enrichment

**Contains**:
- Risk distribution: CRITICAL (4), HIGH (4), MEDIUM (2), LOW (10)
- Sources: AbuseIPDB, IPInfo, VPNapi, Shodan
- Coverage: Tor exits (3), VPNs (4), proxy (1), hosting (8), residential (4), corporate (3), mobile (1)
- Countries: US, NL, RO, RU, AT, GB, DE, VN, ID, NG
- Shodan fields: ports, vulns, tags, OS, hostnames

#### sessionid_traces.json ✅
**Purpose**: Lab 103 — SessionId forensic authentication chains  
**Records**: 3 complete auth chain scenarios

**Scenarios**:
1. **Session hijacking** — legitimate MFA from corporate IP, then token replayed from Tor exit node (CRITICAL)
2. **MFA fatigue attack** — 4 denied push notifications, then user accepts on 5th attempt (HIGH)
3. **Legitimate travel (false positive)** — Seattle → Portland with same device ID confirms real travel (LOW)

---

### Incidents

#### incidents/phishing_incident_sample.json ✅
**Purpose**: Lab 201 — Phishing Campaign Investigation  
**Severity**: High  
**Scenario**: Credential harvesting campaign with malicious link

**Contains**:
- Alert details from Defender for Office 365
- Sender/recipient information, phishing URL
- IOCs (IPs, URLs, domains)
- Investigation timeline notes

#### incidents/compromised_identity_sample.json ✅
**Purpose**: Lab 202 — Compromised Identity Response  
**Severity**: Critical  
**Scenario**: Impossible travel + anonymous IP (Tor exit node)

**Contains**:
- Multiple correlated alerts (Impossible Travel, Anonymous IP)
- Geographic anomaly data (Seattle → Lagos in 15 minutes)
- Suspicious mailbox rule creation activity
- IOCs with VPN/Tor flags

---

### User Profiles

#### users/test_user_profile.json ✅
**User**: jdoe@contoso.com  
**Role**: Account Executive (Sales)  
**Purpose**: Standard user baseline for Labs 102-104

**Contains**:
- User identity details (UPN, Object ID, Windows SID)
- Baseline behavior patterns (typical locations, IPs, apps)
- MFA methods registered, risk profile (low risk, non-privileged)

#### users/privileged_user_profile.json ✅
**User**: admin@contoso.com  
**Role**: Global Administrator (IT)  
**Purpose**: High-risk user scenarios for Labs 104-105, 202

**Contains**:
- Admin account details, elevated baseline behavior
- Multiple MFA methods (Authenticator + FIDO2)
- Risk profile (medium risk, highly privileged)

---

## 📁 Planned Sample Datasets (Coming Soon)

### 1. KQL Query Results
**Directory**: `query-results/`  
**Purpose**: Pre-captured Sentinel query outputs

### 2. Sample DLP Violations
**File**: `dlp_violation_events.json`  
**Purpose**: Lab 204 data exfiltration  

**Contains**:
- 10 DLP policy match events
- Sensitive information type (SIT) details
- File sharing attempts (blocked & allowed)
- External recipient addresses, policy details

---

## 🚀 How to Use Sample Data

### Option 1: Manual Import (for learning)

1. **Open sample file** in VS Code
2. **Review structure** to understand data format
3. **Copy relevant sections** to your queries
4. **Modify timestamps** to match your lab timeline

### Option 2: Automated Loading (for testing)

```powershell
# Load sample investigation data
$sampleData = Get-Content "sample-data/sample_investigation_user1.json" | ConvertFrom-Json

# Use in report generation
python generate_report.py --input-json sample-data/sample_investigation_user1.json

# Simulate KQL query results
# (Copy/paste from sample files into notebook cells)
```

### Option 3: Mock MCP Server (advanced)

For testing without Azure environment:

```powershell
# Start mock MCP server with sample data
cd mcp-servers/mock-sentinel
npm install
npm start -- --data-dir ../../labs/sample-data
```

The mock server returns sample data instead of querying real Sentinel workspace.

---

## 📝 Creating Your Own Sample Data

To add custom scenarios:

1. **Export real investigation** (sanitize first!):
```powershell
# Export with PII removal
python scripts/export_sanitized_investigation.py --upn user@domain.com --output sample-data/custom_scenario.json
```

2. **Manual creation** (template):
```json
{
  "investigation_metadata": {
    "upn": "sampleuser@example.com",
    "investigation_date": "2026-01-15T10:30:00Z",
    "date_range": {
      "start": "2026-01-08",
      "end": "2026-01-17"
    }
  },
  "user_profile": {
    "displayName": "Sample User",
    "jobTitle": "Analyst",
    "department": "IT"
  },
  "sign_in_events": [
    {
      "TimeGenerated": "2026-01-15T09:30:00Z",
      "IPAddress": "198.51.100.1",
      "Location": "Seattle, WA",
      "AppDisplayName": "Office 365",
      "ResultType": "0"
    }
  ],
  "anomalies": [],
  "incidents": [],
  "ip_enrichment": []
}
```

---

## ⚠️ Important Notes

### Data Privacy
- **All sample data is FICTIONAL**
- **No real user data** included
- **No actual company information**
- Safe for training and demonstrations

### Limitations
- Sample data doesn't update automatically
- Limited to scenarios in lab guides
- May not match your tenant's schema exactly
- Use for learning only, not production

### Best Practice
- **Start with sample data** to learn workflows
- **Graduate to test data** in dev environment
- **Finally use production** with proper permissions

---

## 📚 Sample Data Manifest

| File | Status | Records | Lab | Description |
|------|--------|---------|-----|-------------|
| sample_investigation_user1.json | ✅ Available | 5 sign-in IPs, 3 anomalies, 1 incident | 102 | Complete investigation output |
| ip_enrichment_samples.json | ✅ Available | 20 IPs | All | Multi-source IP threat intel |
| sessionid_traces.json | ✅ Available | 3 auth chains | 103 | SessionId forensic traces |
| incidents/phishing_incident_sample.json | ✅ Available | 1 incident | 201 | Phishing campaign |
| incidents/compromised_identity_sample.json | ✅ Available | 1 incident | 202 | Compromised identity |
| users/test_user_profile.json | ✅ Available | 1 profile | 102-104 | Standard user baseline |
| users/privileged_user_profile.json | ✅ Available | 1 profile | 104-105 | Admin user baseline |
| dlp_violation_events.json | 🔜 Planned | 10 events | 204 | Data exfiltration |
| query-results/ | 🔜 Planned | — | All | Pre-captured KQL outputs |

---

## 🔄 Updating Sample Data

Sample data is version-controlled. To update:

1. Create new scenario file
2. Add to manifest table above
3. Update this README
4. Commit to repository
5. Share with team

**Version**: 1.1  
**Last Updated**: February 18, 2026  
**Maintainer**: Security Team

---

## 💡 Tips for Lab Instructors

### Using Sample Data in Workshops

1. **Distribute in advance**: Email sample data files to participants
2. **Load into notebooks**: Pre-populate Jupyter notebooks with sample data
3. **Mock MCP server**: Run mock server for offline workshops
4. **Customize scenarios**: Modify sample data to match workshop theme

### Common Issues

**Issue**: "Sample data doesn't match my queries"  
**Fix**: Update schema fields to match your tenant's structure

**Issue**: "Timestamps are old"  
**Fix**: Use PowerShell to update all timestamps:
```powershell
$json = Get-Content sample.json | ConvertFrom-Json
# Update timestamps recursively
$json | ConvertTo-Json -Depth 10 | Set-Content sample_updated.json
```

**Issue**: "Need more variety in scenarios"  
**Fix**: Combine multiple sample files or create custom scenarios

---

## 📞 Support

Questions about sample data? Contact:
- **Security Team**: security@yourcompany.com
- **Lab Maintainer**: [Your Name]
- **GitHub Issues**: [Repository URL]/issues

---

**Happy Learning!** 🎓
