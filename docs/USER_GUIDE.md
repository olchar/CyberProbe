# CyberProbe Investigation Guide - User Guide

**Version:** Advanced Edition  
**Last Updated:** January 7, 2026  
**For:** Security Analysts, SOC Teams, and AI-Assisted Investigation Automation

---

## 📘 What is the Investigation Guide?

The **Defender XDR Investigation Guide** is a comprehensive reference manual and automation framework for investigating security incidents using Microsoft's security stack:

- **Microsoft Defender XDR** (Extended Detection & Response)
- **Microsoft Sentinel Data Lake** (SIEM with KQL query interface)
- **Microsoft Graph API** (Identity and device data)
- **MCP (Model Context Protocol) Servers** (Programmatic access layer)

**Unique Feature:** This guide serves **dual purposes**:
1. 📖 **Reference Manual** - Human-readable documentation for analysts learning investigation techniques
2. 🤖 **Automation Instructions** - Step-by-step workflows for GitHub Copilot and AI-assisted investigations

---

## 👥 Who Should Use This Guide?

### Security Analysts & SOC Teams
- **New Analysts:** Learning Defender XDR investigation workflows
- **Experienced Analysts:** Reference for complex scenarios (SessionId tracing, anomaly analysis)
- **SOC Managers:** Standardizing investigation procedures across team members
- **Incident Responders:** Quick access to proven KQL queries and playbooks

### AI Automation Users
- **GitHub Copilot Users:** Automated investigation workflows with MCP server integration
- **Security Engineers:** Building custom automation tools leveraging documented patterns
- **DevSecOps Teams:** Integrating security investigations into CI/CD pipelines

### Security Teams
- **Threat Hunters:** Advanced KQL queries for proactive threat hunting
- **Forensic Investigators:** SessionId-based authentication tracing for compromise investigations
- **Compliance Teams:** Standardized report templates for audit documentation

---

## 🚀 Quick Start Guide

### For New Users (Manual Investigations)

**Scenario:** You need to investigate a suspicious user sign-in alert.

1. **Navigate to Section 3 (Investigation Types)**
   - Choose your scope: Standard (7 days), Quick (1 day), or Comprehensive (30 days)

2. **Go to Section 6 (Investigation Workflows)**
   - Find "User Investigation" workflow
   - Copy the basic User Activity Timeline query

3. **Check Section 8 (Sample KQL Queries)**
   - Use **Query 2** (Anomalies from Detection System) to check if user has flagged anomalies
   - Use **Query 3/3b/3c** (Sign-ins by app/location/failures) to understand sign-in patterns

4. **If Geographic Anomaly Detected:**
   - Go to **Section 9 (Advanced Authentication Analysis)**
   - Follow the 6-step SessionId forensic tracing workflow

5. **Document Findings:**
   - Use **Section 17 (Investigation Report Template)**
   - Export standardized report

**Expected Time:** 30-45 minutes for standard 7-day investigation

---

### For AI-Assisted Investigations (Automation)

**Scenario:** Automating user risk investigation with GitHub Copilot + MCP servers.

1. **Tell Copilot:**
   ```
   "Investigate user jane.doe@company.com for the last 7 days using the Investigation Guide workflow"
   ```

2. **Copilot Will Automatically:**
   - Check Section 1 (Critical Workflow Rules) for required checkpoints
   - Follow Section 2 (Quick Start Guide) 5-step automation pattern:
     - Get User Object ID + Windows SID from Graph API
     - Run Query 2 (anomalies) to determine scope
     - If anomalies exist: Run Query 1 → 3d → 11 (IP extraction and enrichment)
     - If SessionId populated: Execute Advanced Authentication Analysis
     - Export JSON with all 20+ required fields

3. **Review Output:**
   - JSON file in `temp/` directory with complete investigation data
   - IP enrichment from VirusTotal, AbuseIPDB, GreyNoise
   - Risk assessment and recommendations

**Expected Time:** 2-5 minutes (automated execution)

---

## 📚 How to Navigate the Guide

### By Investigation Type

| Your Situation | Go To Section | Key Queries |
|----------------|---------------|-------------|
| **Suspicious user sign-in from new location** | Section 9 (Advanced Authentication Analysis) | Query 2 (anomalies), SessionId tracing |
| **Phishing email investigation** | Section 12 (Playbooks) → "Phishing Investigation" | Query 5 (Office 365 activity), Query 4 (audit logs) |
| **Ransomware/malware alert** | Section 12 (Playbooks) → "Ransomware Investigation" | File hash analysis, device timeline |
| **Insider threat/data exfiltration** | Section 13 (Common Scenarios) → "Data Exfiltration" | Query 10 (DLP events), Query 4 (audit logs) |
| **Brute force attack** | Section 13 (Common Scenarios) → "Brute Force Attack" | Query 3c (sign-in failures) |
| **Impossible travel alert** | Section 9 (Advanced Authentication Analysis) | SessionId workflow, Query 3d (IP authentication) |

### By Task

| What You Need | Section | What You'll Find |
|---------------|---------|------------------|
| **Copy/paste ready KQL queries** | Section 8 (Sample KQL Queries) | 11 production-validated queries with proper field handling |
| **Understand platform architecture** | Section 4 (Architecture), Section 5 (Data Sources) | Sentinel, Defender XDR, Graph API overview |
| **Learn MCP automation** | Section 10 (MCP Server Integration) | Available tools, authentication, query execution |
| **Troubleshoot KQL errors** | Section 16 (Troubleshooting) | 5 comprehensive error tables with solutions |
| **Optimize slow queries** | Section 15 (Best Practices) | Performance tips, query patterns |
| **Get API error codes explained** | Section 16 (Troubleshooting) | Graph API errors (404, 403, 429, 500) |
| **Standardize reporting** | Section 17 (Investigation Report Template) | Complete template with all required sections |

---

## 🔍 Common Investigation Workflows

### Workflow 1: Geographic Anomaly Investigation

**Alert:** User signed in from Nigeria, but normally works in Seattle.

**Steps:**
1. **Section 8 → Query 2:** Check if anomaly system flagged this
   ```kql
   Signinlogs_Anomalies_KQL_CL
   | where UserPrincipalName =~ 'user@company.com'
   | where DetectedDateTime between (datetime(2026-01-01) .. datetime(2026-01-09))
   ```

2. **Section 9 → Step 1:** Get SessionId from Nigeria IP
   ```kql
   union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
   | where IPAddress == '<NIGERIA_IP>'
   | distinct SessionId
   ```

3. **Section 9 → Step 2:** Trace complete authentication chain
4. **Section 9 → Step 3:** Find interactive MFA event (first in chain)
5. **Section 9 → Step 6:** Document risk assessment

**Key Question:** Was the initial MFA from Seattle (corporate VPN) or Nigeria (unknown IP)?
- **Seattle VPN first** → Legitimate user traveling → No action
- **Nigeria IP first** → Credential compromise → Force password reset

**Time:** 15-20 minutes

---

### Workflow 2: Phishing Campaign Response

**Alert:** 5 users clicked link in suspected phishing email.

**Steps:**
1. **Section 12 → Phishing Playbook:** Follow step-by-step guide
2. **Section 8 → Query 5:** Check Office 365 activity for email actions
   ```kql
   OfficeActivity
   | where UserId in~ ('user1@company.com', 'user2@company.com', ...)
   | where Operation in~ ('FileDownloaded', 'FileAccessed', 'Send')
   ```

3. **Section 8 → Query 4:** Check Azure AD audit logs for credential changes
4. **Section 8 → Query 2:** Check for post-compromise anomalies
5. **Section 11 → IP Enrichment:** Enrich any suspicious IPs from email headers
6. **Section 17 → Report Template:** Document incident

**Time:** 1-2 hours for 5 users

---

### Workflow 3: Automated Daily User Risk Check

**Use Case:** Nightly automated scan for high-risk user activity.

**Automation Pattern:**
1. **Configure GitHub Copilot with MCP servers** (see Section 10)
2. **Create scheduled task:**
   ```powershell
   # Pseudo-code for automation trigger
   $users = Get-HighRiskUsers  # From your user list
   foreach ($user in $users) {
       Invoke-Copilot "Investigate $user for last 24 hours (Quick investigation type)"
   }
   ```

3. **Copilot follows Section 2 (Quick Start - Automation):**
   - Checks existing JSON first (no duplicate work)
   - Runs Query 2 (anomalies) with 1-day range
   - If anomalies found: Runs full IP enrichment sequence
   - Exports JSON to `temp/investigation_<USER>_<DATE>.json`

4. **Review morning report:**
   - Parse JSON files for `risk_level: "High"` or `anomalies.length > 0`
   - Escalate high-risk findings to SOC team

**Time:** 2-5 minutes per user (automated)

---

## 💡 Tips for Effective Use

### For Manual Investigations

1. **Always Start with Sample Queries (Section 8)**
   - Don't write custom KQL from scratch
   - Sample queries handle edge cases (missing fields, dynamic JSON, schema differences)
   - Example: `LocationDetails` requires `parse_json()` - sample queries do this correctly

2. **Use Correct Date Ranges (Section 8 → Date Range Reference)**
   - **Real-time searches:** Add +2 days to end date (timezone offset + full day coverage)
   - **Historical searches:** Add +1 day to end date
   - Example: Today is Jan 7, "last 7 days" = `datetime(2026-01-01)` to `datetime(2026-01-09)`

3. **Check Troubleshooting BEFORE Asking for Help (Section 16)**
   - `SemanticError: column doesn't exist` → Field not in your workspace schema
   - `Query timeout` → Reduce date range, add `| take 100`
   - `Graph 404 User not found` → Verify UPN spelling

4. **Document Empty Results (Section 15 → Best Practices)**
   - "No anomalies detected" is valuable information
   - Shows baseline behavior
   - Required for comprehensive investigation reports

5. **For High-Severity Incidents: Get User Object ID + Windows SID (Section 8 → Query 6)**
   - Graph API: `/v1.0/users/<UPN>?$select=id,onPremisesSecurityIdentifier`
   - Required for correlating Defender XDR incidents to users
   - Cloud alerts use Object ID, on-premises alerts use Windows SID

### For Automation

1. **Always Provide Current Date to Copilot (Section 1 → Rule 1)**
   - Bad: "Investigate user for last 7 days"
   - Good: "Today is Jan 7, 2026. Investigate user for last 7 days"
   - Why: AI needs context to calculate `datetime(2026-01-09)` correctly

2. **Specify Investigation Type (Section 3)**
   - "Standard investigation (7 days)" → Default
   - "Quick investigation (1 day)" → Fast turnaround
   - "Comprehensive investigation (30 days)" → Deep forensics

3. **Check for Existing JSON First (Section 1 → Critical Workflow Rules)**
   - Copilot should search `temp/` directory before running queries
   - Avoids duplicate API calls and MCP server throttling
   - Use existing enrichment data for follow-up questions

4. **Request Timing Information (Section 15 → Automation Guidelines)**
   - "Track and report timing after each major step"
   - Helps identify slow queries or API bottlenecks
   - Example output: "Query 2 completed in 12s, IP enrichment completed in 28s"

5. **Validate All 20+ Required Fields in JSON Export (Section 16 → Data Quality)**
   - `department` → Default to "Unknown" if null
   - `anomalies` → Export empty array `[]` if none detected
   - `ipEnrichment` → Mandatory for all IPs (4 sources)

---

## 📊 Understanding Investigation Outputs

### JSON Investigation Export (Automated)

**Location:** `temp/investigation_<UPN>_<DATE>.json`

**Key Fields:**
```json
{
  "user_principal_name": "jane.doe@company.com",
  "investigation_start": "2026-01-01T00:00:00Z",
  "investigation_end": "2026-01-09T23:59:59Z",
  "anomalies": [
    {
      "detected_datetime": "2026-01-05T14:32:00Z",
      "anomaly_type": "NewCountryIP",
      "value": "102.89.3.15",
      "severity": "High",
      "country": "NG"
    }
  ],
  "signin_ip_counts": [
    {
      "ip_address": "102.89.3.15",
      "signin_count": 12,
      "last_auth_result_detail": "MFA requirement satisfied by claim in the token"
    }
  ],
  "ip_enrichment": [
    {
      "ip": "102.89.3.15",
      "is_vpn": false,
      "abuse_confidence_score": 72,
      "threat_description": "Credential stuffing attacks",
      "city": "Lagos",
      "country": "NG"
    }
  ],
  "risk_level": "High",
  "recommendation": "Force password reset + revoke all sessions"
}
```

**How to Use:**
- `anomalies.length > 0` → Investigate further with Section 9 (SessionId tracing)
- `ip_enrichment[].abuse_confidence_score > 50` → High-risk IP
- `ip_enrichment[].is_vpn = true` → May be corporate VPN (check org IP ranges)
- `last_auth_result_detail = "Token"` → No interactive MFA, token refresh only

---

## 🛠️ Customization Guide

### Adding Custom Queries to Section 8

**Your Organization's Specific Use Case:**
1. Navigate to Section 8 (Sample KQL Queries)
2. Add new subsection: `### Query 12: [Your Use Case]`
3. Include:
   - **Purpose:** What this query does
   - **Usage:** When to run it (AFTER which other queries)
   - **KQL Code:** Full query with `<placeholders>`
   - **Post-Query Action:** What to do with results

**Example:**
```markdown
### Query 12: Check Privileged Role Changes

**Purpose:** Detect unauthorized privilege escalation  
**Usage:** Run when investigating admin account compromise

**KQL:**
```kql
AuditLogs
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where OperationName has "Add member to role"
| extend Role = tostring(TargetResources[0].displayName)
| extend AddedUser = tostring(TargetResources[1].userPrincipalName)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, Role, AddedUser, Initiator, Result
```

**Critical Fields:** `Role` shows which privileged role was granted
```

### Adding Custom Playbooks to Section 12

**Your Recurring Incident Type:**
1. Navigate to Section 12 (Investigation Playbooks)
2. Add new subsection: `### Playbook X: [Incident Type]`
3. Include:
   - **Objective:** Investigation goal
   - **Steps:** 1-10 numbered steps
   - **Key Queries:** Reference Section 8 queries by number
   - **Expected Findings:** What normal/malicious looks like
   - **Response Actions:** Remediation steps

---

## 🎯 Advanced Techniques

### SessionId-Based Forensic Tracing (Section 9)

**Why This Matters:**
- Standard sign-in analysis shows WHERE user signed in
- SessionId tracing shows WHEN and HOW user FIRST authenticated
- Distinguishes legitimate travel from stolen credentials

**Real-World Case:**
```
User signs in from Lagos, Nigeria (flagged as anomaly)
↓
Standard Analysis: "Suspicious foreign IP, recommend password reset"
↓
SessionId Tracing: Initial MFA was from Seattle corporate VPN 2 hours earlier
↓
Conclusion: User traveling for work, authenticated on trusted network first
↓
Action: No response needed, document baseline expansion
```

**Without SessionId tracing:** False positive, disrupted legitimate user  
**With SessionId tracing:** Accurate risk assessment, no user impact

### Parallel Query Execution (Section 15 → Rule 5)

**Independent Queries (Run in Parallel):**
- Query 2 (anomalies)
- Query 3 (sign-ins by app)
- Query 3b (sign-ins by location)
- Query 4 (audit logs)
- Query 5 (Office 365 activity)
- Query 10 (DLP events)

**Dependent Queries (Run Sequentially):**
1. Query 1 (extract top priority IPs) → 2. Query 3d (sign-in counts for those IPs) → 3. Query 11 (threat intel for those IPs)

**Time Savings:** Parallel execution reduces 6-query workflow from ~3 minutes to ~30 seconds

---

## 📖 Learning Path

### Week 1: Fundamentals
- ✅ Read Section 4 (Architecture) & Section 5 (Data Sources)
- ✅ Complete manual investigation workflow (Section 2 → For Manual Investigations)
- ✅ Practice with Query 2 (anomalies) and Query 3 (sign-ins)
- ✅ Run 3 test investigations on your own account

### Week 2: Intermediate Techniques
- ✅ Learn SessionId tracing (Section 9)
- ✅ Practice IP enrichment (Section 11)
- ✅ Complete phishing playbook (Section 12)
- ✅ Investigate 5 real alerts using Section 8 queries

### Week 3: Advanced & Automation
- ✅ Set up MCP servers (Section 10)
- ✅ Configure GitHub Copilot automation
- ✅ Run automated investigation (Section 2 → For Automated Investigations)
- ✅ Review troubleshooting guide (Section 16) for common issues

### Week 4: Mastery
- ✅ Add custom queries to Section 8
- ✅ Create custom playbook for your organization (Section 12)
- ✅ Automate daily risk checks
- ✅ Train team members using this guide

---

## 🤝 Contributing

### Adding Your Own Content

**Encouraged Additions:**
1. **Custom Queries:** Organization-specific detection patterns
2. **Playbooks:** Your team's incident response procedures
3. **Lessons Learned:** Post-incident findings and improvements
4. **Troubleshooting Cases:** Unique errors you've solved

**How to Contribute:**
1. Edit Investigation-Guide.md in your forked repository
2. Add content to relevant section (follow existing format)
3. Update Table of Contents if adding major sections
4. Document in Notes section (bottom of file)

### Sharing with Community

**Before Publishing:**
- ✅ Remove company-specific IP ranges, domain names
- ✅ Sanitize UPNs (use `user@company.com` placeholder)
- ✅ Redact API keys, workspace IDs, tenant identifiers
- ✅ Generalize custom queries for broader applicability

---

## 📞 Support & Resources

### Getting Help

**For Investigation Questions:**
1. Check Section 16 (Troubleshooting) first
2. Search guide for keywords using `Ctrl+F`
3. Review Section 15 (Best Practices) for optimization tips

**For Automation Issues:**
1. Verify MCP server connectivity (Section 10)
2. Check GitHub Copilot configuration
3. Review Section 1 (Critical Workflow Rules) for required checkpoints

**For KQL Errors:**
1. Section 16 → KQL Query Errors table
2. Microsoft documentation links in Section 18 (Resources)
3. Run `mcp_data_explorat_search_tables` to verify schema

### Documentation Links (Section 18)

- [Microsoft Sentinel Documentation](https://learn.microsoft.com/azure/sentinel/)
- [Defender XDR Documentation](https://learn.microsoft.com/defender-xdr/)
- [KQL Quick Reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference)
- [Advanced Hunting Schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)

### Community Resources

- [KQL Threat Hunting Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
- [Sentinel Community](https://github.com/Azure/Azure-Sentinel)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## 🎓 Certification & Training

**Recommended Certifications:**
- **SC-200:** Microsoft Security Operations Analyst
- **AZ-500:** Microsoft Azure Security Technologies
- **SC-100:** Microsoft Cybersecurity Architect

**Skills Developed Using This Guide:**
- KQL query development and optimization
- Incident response and forensic investigation
- Threat intelligence analysis
- Automation and orchestration (MCP, Graph API)
- Report writing and documentation

---

## 📝 Version History

**Advanced Edition (January 7, 2026):**
- ✅ Merged manual investigation guide with automation instructions
- ✅ Added 11 production-validated KQL queries (Section 8)
- ✅ Added SessionId-based forensic tracing (Section 9)
- ✅ Added comprehensive troubleshooting guide (Section 16)
- ✅ Enhanced best practices with automation guidelines (Section 15)

**Previous Versions:**
- Original Edition (December 16, 2025): Basic investigation workflows and playbooks

---

## 🚦 Quick Reference Card

**Print This Page for Your Desk:**

| Investigation Type | Time Range | Primary Sections | Key Queries |
|-------------------|------------|------------------|-------------|
| **Standard** | 7 days | 6, 8, 9 | Query 2, 3, 3d |
| **Quick** | 1 day | 6, 8 | Query 2, 3 |
| **Comprehensive** | 30 days | 6, 8, 9, 11 | All queries |

| Common Alerts | Go To | Action |
|--------------|-------|--------|
| Geographic anomaly | Section 9 | SessionId tracing |
| Phishing email | Section 12 | Phishing playbook |
| Brute force | Section 13 | Query 3c (failures) |
| DLP violation | Section 8 | Query 10 (DLP events) |
| Impossible travel | Section 9 | SessionId + Query 3d |

| Error Type | Solution Location | Fix |
|-----------|------------------|-----|
| KQL timeout | Section 16 | Reduce date range |
| Field not found | Section 16 | Run search_tables |
| Graph 404 | Section 16 | Verify UPN |
| Slow query | Section 15 | Add early filters |

**Emergency Contact:**
- SOC Lead: [Your contact]
- Incident Response: [Your contact]

---

**Happy Investigating! 🔍**

For questions, feedback, or contributions, open an issue in the GitHub repository.

**License:** MIT (or your organization's standard)  
**Maintainer:** [Your Name/Team]  
**Repository:** [GitHub URL]
