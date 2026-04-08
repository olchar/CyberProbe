# Detection Queries and Rules

This directory contains verified, battle-tested KQL detection queries, analytic rules, and deployment guides for CyberProbe threat detection capabilities. These are the **Priority 2 lookup source** in the [KQL Pre-Flight Checklist](../.github/copilot-instructions.md) — Copilot searches them before writing any ad-hoc KQL.

## Folder Structure

Queries are organized by data domain for efficient `grep_search` discovery:

| Folder | Domain | Description |
|--------|--------|-------------|
| [identity/](identity/) | Entra ID / Azure AD | Sign-ins, audit logs, identity compromise detection |
| [endpoint/](endpoint/) | Defender for Endpoint | Device processes, network events, file operations |
| [email/](email/) | Defender for Office 365 | Email threats, phishing, attachment analysis |
| [network/](network/) | Network telemetry | Network anomalies, traffic analysis |
| [cloud/](cloud/) | Cloud apps & exposure | Cloud app activity, attack path monitoring, exposure management |
| [soc-metrics/](soc-metrics/) | SOC operational metrics | MTTA, MTTR, incident breakdowns, top impacted users/devices, analyst workload |

## Contents

### Identity Queries

| File | Description | Platform |
|------|-------------|----------|
| [identity/multi_stage_identity_compromise_detection.kql](identity/multi_stage_identity_compromise_detection.kql) | Multi-stage identity compromise detection (KQL) | Sentinel |
| [identity/multi_stage_identity_compromise_detection.spl](identity/multi_stage_identity_compromise_detection.spl) | Multi-stage identity compromise detection (SPL) | Splunk |
| [identity/sentinel_rule_multi_stage_compromise.yaml](identity/sentinel_rule_multi_stage_compromise.yaml) | Sentinel analytic rule configuration | Sentinel |

### Cloud Queries

| File | Description | Platform |
|------|-------------|----------|
| [cloud/attack_path_monitoring.kql](cloud/attack_path_monitoring.kql) | Attack path trends, Key Vault access, storage anomalies, managed identity abuse | Sentinel |

### SOC Metrics Queries

| File | Description | Platform |
|------|-------------|----------|
| [soc-metrics/mean_time_to_acknowledge.kql](soc-metrics/mean_time_to_acknowledge.kql) | MTTA with month-over-month comparison | Sentinel |
| [soc-metrics/mean_time_to_resolve.kql](soc-metrics/mean_time_to_resolve.kql) | MTTR with month-over-month comparison | Sentinel |
| [soc-metrics/incident_count_stats.kql](soc-metrics/incident_count_stats.kql) | Incident breakdown by type, status, classification, MITRE | Sentinel |
| [soc-metrics/top_impacted_users.kql](soc-metrics/top_impacted_users.kql) | Top users by alert/incident volume (entity extraction) | Sentinel |
| [soc-metrics/top_impacted_devices.kql](soc-metrics/top_impacted_devices.kql) | Top devices by alert/incident volume (entity extraction) | Sentinel |
| [soc-metrics/top_incident_owners.kql](soc-metrics/top_incident_owners.kql) | Analyst workload distribution by assignment count | Sentinel |

### Documentation

| File | Description |
|------|-------------|
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Complete deployment and configuration guide |

## Standardized Metadata Header

All query files use this standardized metadata header for efficient `grep_search` discovery:

```markdown
# <Title>

**Created:** YYYY-MM-DD
**Platform:** Microsoft Sentinel | Microsoft Defender XDR | Both
**Tables:** <comma-separated list of exact KQL table names>
**Keywords:** <comma-separated searchable terms>
**MITRE:** <comma-separated technique IDs, e.g., T1021.001, TA0008>
**Timeframe:** Last N days (configurable)
```

When creating new query files, follow this format and place them in the subfolder matching their primary data source table.

## Quick Start

### Deploy to Microsoft Sentinel

#### Option 1: Azure Portal (Manual)

1. **Navigate to Sentinel:**
   - Azure Portal → Microsoft Sentinel → Analytics

2. **Create Rule:**
   - Click **Create** → **Scheduled query rule**
   - **Name:** Multi-Stage Identity Compromise Detection
   - **Severity:** High

3. **Set Query:**
   - Copy content from [multi_stage_identity_compromise_detection.kql](multi_stage_identity_compromise_detection.kql)
   - Paste into rule query editor
   - **Run frequency:** Every 5 minutes
   - **Lookup data:** Last 1 hour

4. **Configure Alert:**
   - **Entity mapping:** User (AccountName, AccountUPN)
   - **Alert grouping:** Enabled (group events within 5 hours)

5. **Enable Rule:**
   - Review settings
   - Click **Create**

#### Option 2: ARM Template (Automated)

```powershell
# Deploy using Azure CLI
az deployment group create \
  --resource-group YourResourceGroup \
  --template-file sentinel_rule_multi_stage_compromise.yaml
```

#### Option 3: PowerShell

```powershell
# Import rule using Sentinel PowerShell module
Import-AzSentinelAlertRule `
  -ResourceGroupName "YourResourceGroup" `
  -WorkspaceName "YourSentinelWorkspace" `
  -RuleFile "sentinel_rule_multi_stage_compromise.yaml"
```

### Deploy to Splunk

1. **Navigate to Splunk:**
   - Settings → Searches, reports, and alerts

2. **Create Alert:**
   - Click **New Alert**
   - **Search:** Paste content from [multi_stage_identity_compromise_detection.spl](multi_stage_identity_compromise_detection.spl)

3. **Configure Schedule:**
   - **Run:** Every 5 minutes
   - **Time range:** Last 60 minutes

4. **Set Actions:**
   - Email notification
   - Webhook to SOAR platform

## Detection Logic

### Multi-Stage Identity Compromise

**MITRE ATT&CK Mapping:**
- T1078: Valid Accounts
- T1110: Brute Force
- T1021: Remote Services
- T1136: Create Account

**Detection Stages:**

1. **Stage 1: Initial Compromise**
   - Multiple failed sign-ins followed by success
   - Impossible travel detection
   - Sign-in from suspicious IP

2. **Stage 2: Persistence**
   - MFA modification
   - New authentication method registration
   - Privileged role assignment

3. **Stage 3: Lateral Movement**
   - Access to multiple resources within short timeframe
   - Sign-in from unusual location
   - Service principal creation

4. **Stage 4: Data Exfiltration**
   - Large file downloads
   - SharePoint/OneDrive bulk access
   - Email forwarding rule creation

**Query Logic:**
```kql
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType != 0  // Failed sign-ins
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType == 0  // Successful sign-in
) on UserPrincipalName
| project UserPrincipalName, IPAddress, FailedAttempts, 
    SuccessTime = TimeGenerated1
```

## Query Customization

### Adjust Detection Thresholds

Edit thresholds in query file:

```kql
// Change failed login threshold
let failedLoginThreshold = 5;  // Default: 5 attempts

// Change timeframe
let lookbackPeriod = 1h;  // Default: 1 hour

// Change risk score threshold
let riskThreshold = 70;  // Default: 70/100
```

### Add Custom Exclusions

```kql
// Exclude service accounts
| where UserPrincipalName !startswith "svc-"

// Exclude known IP ranges
| where IPAddress !in ("10.0.0.0/8", "172.16.0.0/12")

// Exclude specific users
| where UserPrincipalName !in ("admin@contoso.com", "sync@contoso.com")
```

### Tune for Your Environment

1. **Baseline Normal Activity:**
   ```kql
   SigninLogs
   | where TimeGenerated > ago(30d)
   | summarize AvgSignIns = avg(count()) by UserPrincipalName, bin(TimeGenerated, 1h)
   ```

2. **Adjust Based on Findings:**
   - Lower threshold for high-value accounts
   - Increase threshold for service accounts
   - Tune based on false positive rate

## Testing Queries

### Test in Sentinel

1. **Navigate to Logs:**
   - Azure Portal → Sentinel → Logs

2. **Paste Query:**
   - Copy KQL query
   - Set time range: Last 24 hours

3. **Review Results:**
   - Check for false positives
   - Validate entity mapping
   - Review alert details

### Test in Splunk

```spl
index=main sourcetype=azure:signinlogs
| search ResultType!=0
| stats count as FailedAttempts by user, src_ip
| where FailedAttempts >= 5
```

## Query Performance

### Optimization Tips

1. **Use Time Filters Early:**
   ```kql
   SigninLogs
   | where TimeGenerated > ago(1h)  // Filter first
   | where ResultType != 0
   ```

2. **Limit Column Projection:**
   ```kql
   | project TimeGenerated, UserPrincipalName, IPAddress, ResultType
   ```

3. **Use Summarize Instead of Distinct:**
   ```kql
   // Good
   | summarize by UserPrincipalName
   
   // Avoid
   | distinct UserPrincipalName
   ```

4. **Index Common Filters:**
   ```kql
   | where ResultType in (0, 50126, 50057)  // Use 'in' for multiple values
   ```

### Monitor Query Performance

```kql
// Check query execution time
QueryExecutionMetrics
| where QueryText contains "Multi-Stage Identity"
| project TimeGenerated, Duration, RecordsProcessed
| order by TimeGenerated desc
```

## Alert Actions

### Configure Incident Creation

```yaml
incident_configuration:
  create_incident: true
  grouping:
    enabled: true
    reopen_closed_incidents: false
    lookback_duration: PT5H
    match_by_entities: true
    match_by_custom_details: false
```

### Configure Automation

**Playbook Triggers:**
1. Block user account
2. Reset user credentials
3. Notify security team
4. Enrich with threat intelligence
5. Create ServiceNow ticket

**Example Playbook:**
```json
{
  "trigger": "SecurityIncident",
  "actions": [
    {
      "type": "HTTP",
      "method": "POST",
      "uri": "https://cyberprobe.azurewebsites.net/api/enrich",
      "body": "@triggerBody()?['entities']"
    }
  ]
}
```

## Maintenance

### Weekly Review

- [ ] Check false positive rate
- [ ] Review excluded entities
- [ ] Update threshold values
- [ ] Validate entity mappings
- [ ] Test alert actions

### Monthly Review

- [ ] Analyze detection coverage
- [ ] Update MITRE ATT&CK mapping
- [ ] Optimize query performance
- [ ] Review incident response times
- [ ] Update documentation

### Quarterly Review

- [ ] Benchmark against industry standards
- [ ] Add new detection scenarios
- [ ] Retire obsolete queries
- [ ] Conduct penetration testing
- [ ] Update training materials

## Related Documentation

- **Deployment Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **Investigation Guide:** [../Investigation-Guide.md](../Investigation-Guide.md)
- **Sentinel Integration:** [../enrichment/README.md](../enrichment/README.md)
- **Lab Exercises:** [../labs/103-advanced-auth-analysis/](../labs/103-advanced-auth-analysis/)

## MITRE ATT&CK Coverage

| Tactic | Technique | Coverage |
|--------|-----------|----------|
| Initial Access | T1078 - Valid Accounts | ✅ Covered |
| Credential Access | T1110 - Brute Force | ✅ Covered |
| Persistence | T1098 - Account Manipulation | ✅ Covered |
| Lateral Movement | T1021 - Remote Services | ✅ Covered |
| Exfiltration | T1567 - Exfiltration Over Web Service | ⚠️ Partial |

## Contributing

### Adding New Queries

1. Create query file: `query_name.kql`
2. Add MITRE ATT&CK mapping in comments
3. Include example results
4. Document tuning parameters
5. Add to this README

### Query Template

```kql
// Query Name: [Descriptive Name]
// MITRE ATT&CK: [Technique IDs]
// Severity: [High/Medium/Low]
// Author: [Your Name]
// Date: YYYY-MM-DD

// Description:
// [What does this query detect?]

// Parameters
let timeframe = 1h;
let threshold = 5;

// Query Logic
[Your KQL query here]
```

---

**Last Updated:** January 28, 2026  
**Maintainer:** CyberProbe Security Team
