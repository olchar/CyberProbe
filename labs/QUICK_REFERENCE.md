# Lab Quick Reference Guide

This guide provides quick access to common tasks across all CyberProbe labs.

---

## 🚀 Getting Started Checklist

Before starting any lab:

- [ ] Environment setup complete (Lab 101)
- [ ] Python virtual environment activated (`.venv\Scripts\Activate.ps1`)
- [ ] MCP server connection verified
- [ ] Investigation Guide open for reference
- [ ] Current date noted (for date range calculations)
- [ ] Security Copilot agent files reviewed (in `security-copilot/` folder)
- [ ] Recent investigation reports checked (`reports/` directory)

---

## 📊 Common Investigation Patterns

### Pattern 1: User Investigation (Standard 7-Day)

**When to use**: Routine security review, anomaly follow-up

**Prompt to Copilot**:
```
Investigate <user@domain.com> for the last 7 days
```

**Manual Steps**:
1. Get User ID from Graph: `/v1.0/users/<UPN>?$select=id,onPremisesSecurityIdentifier`
2. Run Sentinel queries (anomalies, sign-ins, audit logs, incidents)
3. Extract IPs → Run threat intel enrichment
4. Export to JSON
5. Generate HTML report

**Expected Time**: ~5-6 minutes

---

### Pattern 2: Incident Response (Quick 1-Day)

**When to use**: Active incident, urgent investigation

**Prompt to Copilot**:
```
Quick investigate <user@domain.com>
```

**Focuses on**: Last 24 hours only  
**Expected Time**: ~2-3 minutes

---

### Pattern 3: SessionId Authentication Tracing

**When to use**: Geographic anomalies, impossible travel, risky sign-ins

**Reference**: Investigation Guide Section 9

**Steps**:
1. Get SessionId from suspicious IP (Query 5 in Investigation Guide)
2. Trace complete authentication chain (Query 6)
3. Find first MFA event → This is initial authentication
4. Extract all IPs in session
5. Enrich IPs with threat intel
6. Document risk assessment

**Critical**: First event in SessionId chain = true authentication point

---

### Pattern 4: Phishing Investigation

**When to use**: Email-based attacks, credential theft

**Reference**: Lab 201, Investigation Guide Playbook 2

**Steps**:
1. Identify malicious emails (EmailEvents)
2. Track URL clicks (CloudAppEvents - SafeLinks)
3. Analyze post-click sign-ins
4. Use SessionId tracing for compromised accounts
5. Check post-compromise activity (forwarding rules, file access, DLP)
6. Generate remediation plan

**Expected Time**: 60-90 minutes for full investigation

---

## 🔍 Essential KQL Patterns

### Get Recent Sign-ins
```kql
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ '<UPN>'
| take 100
```

### Find Security Incidents for User
```kql
// Requires: User Object ID + Windows SID from Graph API
let targetUserId = "<USER_OBJECT_ID>";
let targetSid = "<WINDOWS_SID>";

SecurityAlert
| where TimeGenerated > ago(7d)
| where Entities has targetUserId or Entities has targetSid
```

### Check Anomalies
```kql
Signinlogs_Anomalies_KQL_CL
| where DetectedDateTime between (datetime(<Start>) .. datetime(<End>))
| where UserPrincipalName =~ '<UPN>'
| order by DetectedDateTime desc
```

### Extract IPs for Enrichment
```kql
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ '<UPN>'
| summarize SignInCount = count() by IPAddress
| order by SignInCount desc
| take 15
```

---

## 📅 Date Range Calculator

**Current Date Context**: Always verify current date before calculating ranges!

### Rule 1: Real-Time/Recent Searches
**Use case**: "Last 7 days", "Recent activity", "Current"

**Formula**: 
- Start: Current date - X days
- End: Current date + 2 days

**Example** (Today = Jan 15, 2026):
- Last 7 days: `datetime(2026-01-08)` to `datetime(2026-01-17)`

### Rule 2: Historical Searches
**Use case**: "From Jan 1 to Jan 5", user-specified dates

**Formula**:
- Start: User's start date
- End: User's end date + 1 day

**Example**:
- Jan 1-5: `datetime(2026-01-01)` to `datetime(2026-01-06)`

**Why +1 or +2?** `datetime(2026-01-15)` = Jan 15 00:00:00 (midnight). Without adjustment, you miss up to 48 hours of data due to timezone offset.

---

## 🤖 MCP Tool Quick Reference

### Sentinel Tools
```
mcp_data_explorat_list_sentinel_workspaces()
mcp_data_explorat_search_tables(query, workspaceId)
mcp_data_explorat_query_lake(query, workspaceId)
```

### Defender XDR Tools
```
mcp_triage_ListIncidents(createdAfter, createdBefore, severity, status)
mcp_triage_GetIncidentById(incidentId, includeAlertsData)
mcp_triage_GetDefenderFileInfo(fileHash)
mcp_triage_GetDefenderIpStatistics(ipAddress)
```

### Microsoft Graph
```
/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier
/v1.0/identityProtection/riskyUsers/<USER_ID>
/v1.0/identityProtection/riskDetections?$filter=userId eq '<USER_ID>'
```

---

## 📝 Report Naming Conventions

**Always follow these patterns**:

| Report Type | Pattern | Example |
|-------------|---------|---------|
| Investigation | `investigation_<user>_YYYY-MM-DD.{json,html}` | `investigation_jdoe_2026-01-15.html` |
| Incident | `incident_report_<id>_YYYY-MM-DD.html` | `incident_report_41398_2026-01-15.html` |
| Executive | `executive_report_YYYY-MM-DD.html` | `executive_report_2026-01-15.html` |
| IP Enrichment | `ip_enrichment_<count>_ips_YYYY-MM-DD.json` | `ip_enrichment_15_ips_2026-01-15.json` |

**Rules**:
- Lowercase prefixes
- Underscores (_) as separators
- Date format: YYYY-MM-DD (ISO 8601)
- UPN prefix: extract before @ symbol, lowercase
- All reports in `reports/` directory

---

## 🔧 Troubleshooting Common Issues

### Issue: "No results returned from query"

**Possible Causes**:
1. Date range too narrow (check +2 day rule)
2. UPN case sensitivity (use `=~` operator)
3. User has no activity in time range
4. Wrong workspace ID

**Solution**: Start with `| take 1` to verify data exists, then expand query

---

### Issue: "SessionId is empty"

**Cause**: Non-interactive sign-ins don't populate SessionId

**Solution**: Use time-window correlation (±5 minutes) or DeviceId matching

---

### Issue: "Investigation JSON already exists, but Copilot re-queries anyway"

**Cause**: Copilot didn't check files first

**Solution**: Remind Copilot: "Check if investigation JSON exists for <user> before querying"

---

### Issue: "IP enrichment takes too long"

**Cause**: External API rate limits

**Solutions**:
1. Use batch queries (Query 11 - Threat Intel) instead of per-IP lookups
2. Check if data already exists in investigation JSON
3. Prioritize IPs using Query 1 (top 15 selection)

---

## 🎯 Lab-Specific Quick Links

### Lab 101: Getting Started
- **Goal**: Environment setup, first query
- **Key Concepts**: MCP tools, Investigation Guide navigation
- **Time**: 30 minutes

### Lab 102: Basic Investigations
- **Goal**: Standard user investigation workflow
- **Key Concepts**: Parallel queries, JSON export, report generation
- **Time**: 45 minutes

### Lab 103: Advanced Auth Analysis
- **Goal**: SessionId tracing mastery
- **Key Concepts**: Authentication chains, IP enrichment, risk assessment
- **Time**: 60 minutes

### Lab 201: Phishing Investigation
- **Goal**: Real-world phishing campaign
- **Key Concepts**: Email analysis, click tracking, post-compromise activity
- **Time**: 90 minutes
- **Scenario**: Incident #41398 (3 compromised users, data exfiltration)

---

## 📚 Investigation Guide Shortcuts

Quick navigation to most-used sections:

- **Critical Workflow Rules**: Section at top (⚠️ READ FIRST)
- **Quick Start**: Automated 5-phase workflow
- **Sample KQL Queries**: Section 8 (production-validated queries)
- **SessionId Tracing**: Section 9 (authentication forensics)
- **Investigation Playbooks**: Section 12 (incident response guides)
- **Date Range Reference**: Section 8 (under Sample KQL Queries)

---

## 💡 Pro Tips

**For Analysts**:
1. Always check Investigation Guide samples before writing custom KQL
2. Document empty results (negative evidence is evidence!)
3. Track investigation time to build efficiency
4. Use `project` early in queries to reduce data volume

**For AI-Assisted Investigations**:
1. Always verify current date from context before date calculations
2. Check for existing JSON files before re-querying
3. Read `ip_enrichment` array from JSON for IP context
4. Follow SessionId workflow for authentication anomalies (don't improvise!)

**For Both**:
1. Use parallel query execution when possible
2. Save useful queries to `queries/custom/` folder
3. Keep Investigation Guide open in second monitor
4. Export findings to CSV for offline analysis

---

## 🆘 When You're Stuck

1. **Check Investigation Guide** - Search for your scenario
2. **Review Lab README** - Step-by-step instructions
3. **Inspect Sample Data** - `labs/sample-data/` for examples
4. **Ask Copilot** - "Explain <concept> from Investigation Guide"
5. **Verify Prerequisites** - Did you complete earlier labs?

---

## 🎓 Skills Progression

### Beginner (Labs 101-102)
- ✅ Execute basic KQL queries
- ✅ Use MCP tools
- ✅ Generate investigation reports
- ✅ Understand data sources

### Intermediate (Labs 103-105)
- ✅ SessionId tracing
- ✅ Threat hunting
- ✅ Incident response workflows
- ✅ IP threat intelligence

### Advanced (Lab 106, 200-Series)
- ✅ Full investigation automation
- ✅ Multi-stage attack analysis
- ✅ Behavioral analytics
- ✅ Playbook execution

---

**Remember**: The Investigation Guide is your primary reference. Labs are hands-on practice to reinforce concepts from the Guide.
