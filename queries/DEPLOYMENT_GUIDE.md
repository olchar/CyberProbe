# Multi-Stage Identity Compromise Detection - Deployment Guide

## 📋 Overview

This Sentinel Analytic Rule detects sophisticated identity compromise attacks based on **January 2026 threat intelligence** from Microsoft's Secure Future Initiative, incorporating 200+ TTP refinements deployed across Microsoft infrastructure since September 2024.

**Detection Focus**: Multi-stage attacks combining credential theft, MFA bypass, token replay, and privilege escalation

**Key Capabilities**:
- ✅ Impossible travel detection (3+ countries in <6 hours)
- ✅ Password spray attacks (50+ attempts across 10+ accounts)
- ✅ Token theft/replay (session reuse from multiple IPs)
- ✅ Anonymous IP usage (Tor/VPN)
- ✅ Privilege escalation correlation
- ✅ MFA bypass detection
- ✅ Threat scoring (0-165 points)

---

## 🎯 Deployment Methods

### Method 1: Azure Portal (Recommended for Testing)

1. **Navigate to Sentinel**:
   ```
   Azure Portal → Microsoft Sentinel → [Your Workspace] → Analytics → Create → Scheduled query rule
   ```

2. **Copy Rule Configuration**:
   - Open `sentinel_rule_multi_stage_compromise.yaml`
   - Copy the KQL query from the `query:` section
   - Paste into the "Rule query" field

3. **Configure Settings**:
   ```yaml
   Name: Multi-Stage Identity Compromise Detection (2026 TTPs)
   Severity: High
   MITRE ATT&CK: T1078, T1110.003, T1550, T1098, T1078.004, T1566, T1556.006
   Frequency: Run every 5 minutes
   Lookup data from: Last 7 days
   ```

4. **Set Alert Threshold**:
   ```
   Generate alert when number of query results: Is greater than 0
   ```

5. **Entity Mapping**:
   - **Account**: `CompromisedUser` (FullName)
   - **IP Address**: `SourceIP`

6. **Enable & Test**:
   - Click "Review + create"
   - Monitor for 24 hours
   - Check "Incidents" for generated alerts

---

### Method 2: ARM Template Deployment

```bash
# Deploy via Azure CLI
az sentinel alert-rule create \
  --resource-group "YourResourceGroup" \
  --workspace-name "YourSentinelWorkspace" \
  --alert-rule-template-name "a8f9c2d1-3e4b-5c6d-7e8f-9a0b1c2d3e4f" \
  --enabled true \
  --rule-file sentinel_rule_multi_stage_compromise.yaml
```

---

### Method 3: PowerShell Deployment

```powershell
# Import Sentinel module
Install-Module -Name Az.SecurityInsights -Force

# Deploy the rule
$workspaceId = "/subscriptions/{subscriptionId}/resourceGroups/{rgName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}"

New-AzSentinelAlertRule `
  -ResourceGroupName "YourResourceGroup" `
  -WorkspaceName "YourSentinelWorkspace" `
  -Kind "Scheduled" `
  -DisplayName "Multi-Stage Identity Compromise Detection (2026 TTPs)" `
  -Severity "High" `
  -QueryFrequency (New-TimeSpan -Minutes 5) `
  -QueryPeriod (New-TimeSpan -Days 7) `
  -TriggerOperator "GreaterThan" `
  -TriggerThreshold 0 `
  -Enabled
```

---

## 🔧 Prerequisites

### Required Data Connectors

1. **Azure Active Directory (Entra ID)**:
   ```
   Data Types: SigninLogs, AuditLogs
   Required Permissions: Security Reader
   Configuration: Azure Portal → Sentinel → Data connectors → Azure Active Directory
   ```

2. **Azure AD Identity Protection**:
   ```
   Data Types: SecurityAlert (IPC)
   License Required: Azure AD Premium P2
   Configuration: Enable ID Protection in Entra admin center
   ```

### Required Permissions

**Deployment**:
- `Microsoft Sentinel Contributor` or `Microsoft Sentinel Responder`

**Ongoing Operation**:
- `Microsoft Sentinel Reader` (minimum)
- `Security Reader` (for log access)

### License Requirements

- ✅ Microsoft Sentinel (enabled workspace)
- ✅ Azure AD Premium P2 (for Identity Protection risk signals)
- ⚠️ Microsoft 365 E5 or E5 Security (recommended for full coverage)

---

## ⚙️ Configuration & Tuning

### 1. Baseline Learning Period

**Recommended**: Wait 14 days after deployment for user travel pattern baselines

```kql
// Adjust impossible travel detection for your org size
| where array_length(Locations) >= 3  // Default: 3 countries
// For small orgs (<500 users): Change to 2
// For large global orgs (>5K users): Keep at 3
```

### 2. Threshold Tuning

**Password Spray Detection**:
```kql
| where FailedAccounts >= 10  // 10+ unique users
| where FailedAttempts >= 50  // 50+ attempts in 10 minutes

// VDI Environments: Increase to 100 attempts (frequent reconnects)
// High-security orgs: Decrease to 25 attempts
```

**Threat Score Threshold**:
```kql
| where ThreatScore >= 50  // Current: Medium+

// For VIP/executive monitoring: Lower to 40
// For high-volume environments: Increase to 60
```

### 3. False Positive Reduction

**Exclude Known VPN Ranges**:
```kql
// Add at line 20 (after SuspiciousSignIns definition)
| where IPAddress !in ("203.0.113.0/24", "198.51.100.0/24")  // Your corporate VPN ranges
```

**Exempt Service Accounts**:
```kql
// Add filter to exclude service accounts
| where UserPrincipalName !has "svc-" and UserPrincipalName !has "admin-"
```

**Whitelist Corporate Travel Users**:
```kql
// Exclude sales/executive teams with legitimate global travel
let TravelExemptUsers = datatable(UserPrincipalName:string)
[
    "sales.exec@contoso.com",
    "ceo@contoso.com"
];
// Add join to exclude these users from impossible travel detection
```

### 4. Performance Optimization

**For Large Tenants (>10K users)**:
```yaml
queryFrequency: 15m  # Change from 5m to reduce load
queryPeriod: 3d      # Reduce from 7d for faster execution
```

**For Small Tenants (<1K users)**:
```yaml
queryFrequency: 5m   # Keep at 5m for near-real-time
queryPeriod: 14d     # Increase for better baseline detection
```

---

## 🔍 Testing & Validation

### Test Case 1: Impossible Travel Detection

```kql
// Validate impossible travel logic
SigninLogs
| where TimeGenerated >= ago(24h)
| where UserPrincipalName == "test.user@contoso.com"
| summarize Countries = make_set(LocationDetails.countryOrRegion) by UserPrincipalName
| where array_length(Countries) >= 3
```

**Expected**: Should detect if test user signed in from 3+ countries in 24h

### Test Case 2: Password Spray Simulation (DO NOT RUN IN PRODUCTION)

```powershell
# This is for LAB TESTING ONLY - will trigger lockouts
# Simulate password spray (50+ failed attempts)
1..60 | ForEach-Object {
    Connect-AzureAD -Credential (Get-Credential) -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}
```

**Expected**: Rule should generate alert within 15 minutes

### Test Case 3: Verify Threat Score Calculation

```kql
// Run the query manually and check ThreatScore values
let lookback = 7d;
// [Paste full query here]
| project CompromisedUser, ThreatScore, AttackStages, Severity
| sort by ThreatScore desc
```

**Expected**: ThreatScore should be 50-165 for detected incidents

---

## 📊 Expected Results

### Volume Estimates (Based on 10K user tenant)

| ThreatScore Range | Expected Alerts/Day | Priority | Typical Pattern |
|-------------------|---------------------|----------|-----------------|
| 100-165 (Critical) | 0-2 alerts | P1 - Immediate Response | Confirmed multi-stage attack |
| 75-99 (High) | 2-5 alerts | P2 - Urgent Investigation | Likely compromise, 2+ indicators |
| 50-74 (Medium) | 5-15 alerts | P3 - Standard Investigation | Single high-risk indicator |

### Sample Alert Output

```json
{
  "CompromisedUser": "john.doe@contoso.com",
  "ThreatScore": 120,
  "AttackStages": "Anonymous IP → Impossible Travel → Token Theft → Privilege Escalation",
  "SourceIP": "185.220.101.45",
  "AnomalousLocations": ["United States", "Russia", "China"],
  "ImpossibleTravelHours": 4,
  "TokenReuseIPs": ["185.220.101.45", "172.200.70.89"],
  "Severity": "Critical",
  "Recommendation": "IMMEDIATE ACTION: Revoke all sessions, force password reset, disable account, escalate to IR team"
}
```

---

## 🚨 Incident Response Integration

### Automated Response Playbook (Logic App)

Create a Logic App to automatically respond to high-threat-score alerts:

1. **Trigger**: When Sentinel incident is created with ThreatScore >= 100
2. **Actions**:
   - Revoke user's refresh tokens via Microsoft Graph API
   - Disable account (temporary)
   - Send email to SOC team
   - Create ServiceNow ticket
   - Post alert to Microsoft Teams channel

**Sample Logic App Connector**:
```json
{
  "type": "Microsoft.Logic/workflows",
  "triggers": {
    "When_Sentinel_incident_created": {
      "type": "ApiConnection",
      "inputs": {
        "host": {
          "connection": {
            "name": "@parameters('azuresentinel')"
          }
        },
        "method": "get",
        "path": "/Incidents"
      }
    }
  },
  "actions": {
    "Revoke_User_Sessions": {
      "type": "Http",
      "inputs": {
        "method": "POST",
        "uri": "https://graph.microsoft.com/v1.0/users/@{triggerBody()?['properties']?['CompromisedUser']}/revokeSignInSessions"
      }
    }
  }
}
```

### Manual Response Procedures

**For ThreatScore >= 100 (Critical)**:
1. ⏱️ **0-5 min**: Verify alert legitimacy (call user via secondary channel)
2. ⏱️ **5-10 min**: Revoke all sessions: `Revoke-AzureADUserAllRefreshToken -ObjectId <userId>`
3. ⏱️ **10-15 min**: Force password reset + enable MFA
4. ⏱️ **15-30 min**: Review AuditLogs for unauthorized changes (data exfil, forwarding rules)
5. ⏱️ **30-60 min**: Escalate to IR team, create timeline

**For ThreatScore 75-99 (High)**:
1. Investigate SessionId and CorrelationId in logs
2. Contact user via verified channel
3. If confirmed: Revoke sessions, reset password
4. Monitor for 24 hours

**For ThreatScore 50-74 (Medium)**:
1. Review sign-in activity
2. Validate with user
3. Document in ticketing system
4. Monitor user for 7 days

---

## 📈 Monitoring & Maintenance

### Weekly Tasks

- Review false positive rate (target: <10%)
- Analyze ThreatScore distribution
- Update excluded VPN IP ranges
- Check query performance (target: <60 seconds execution time)

### Monthly Tasks

- Review top 10 triggered users (potential insider threat)
- Update threat intelligence sources
- Tune thresholds based on alert volume
- Validate MITRE ATT&CK mapping accuracy

### Quarterly Tasks

- Red team testing (simulate attacks)
- Review and update baseline periods
- Benchmark against industry standards
- Update documentation

---

## 🔗 References

### Microsoft Documentation
- [Rapid Anomaly Detection (SFI)](https://learn.microsoft.com/en-us/security/zero-trust/sfi/rapid-anomaly-detection-response)
- [Advanced Multistage Attack Detection](https://learn.microsoft.com/en-us/azure/sentinel/fusion)
- [Entra ID Protection Risk Detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)

### MITRE ATT&CK
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)

### Community Resources
- [Azure Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)
- [Sentinel Analytics Rules Community](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)

---

## ❓ Troubleshooting

### Issue: No alerts generated after 24 hours

**Causes**:
1. Insufficient baseline data (need 14 days of SigninLogs)
2. Data connectors not configured
3. Query execution errors

**Resolution**:
```kql
// Check if data sources are available
SigninLogs | where TimeGenerated >= ago(7d) | take 10
AuditLogs | where TimeGenerated >= ago(7d) | take 10

// Verify Identity Protection connector
SecurityAlert | where TimeGenerated >= ago(7d) and ProviderName == "IPC" | take 10
```

### Issue: Too many false positives (>20 alerts/day)

**Resolution**:
1. Increase ThreatScore threshold from 50 to 60
2. Exclude known VPN IP ranges
3. Extend baseline learning period to 21 days
4. Whitelist service accounts

### Issue: Query timeout errors

**Resolution**:
```kql
// Reduce queryPeriod from 7d to 3d
// Reduce queryFrequency from 5m to 15m
// Add time filters to all sub-queries
```

---

## 📞 Support

For questions or issues with this detection rule:

1. **CyberProbe Project**: GitHub Issues at `github.com/your-org/cyberprobe`
2. **Microsoft Sentinel**: Microsoft Support Portal
3. **Community**: Microsoft Tech Community - Sentinel Forum

---

**Last Updated**: January 26, 2026  
**Version**: 1.0.0  
**Author**: CyberProbe AI Agent
