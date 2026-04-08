# Lab 106: MCP Automation & AI-Assisted Investigations

**Duration**: 60 minutes  
**Difficulty**: Advanced  
**Prerequisites**: Labs 101-105

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Configure Agent Skills for automated investigations
- ✅ Monitor automated investigation performance
- ✅ Customize investigation workflows with parameters
- ✅ Optimize KQL queries for faster execution
- ✅ Build custom investigation scripts
- ✅ Troubleshoot MCP tool connection issues
- ✅ Measure investigation efficiency metrics

---

## 📖 Background

This lab teaches **automation** using the Model Context Protocol (MCP) and GitHub Copilot Agent Skills. You'll learn how to:

- Configure Copilot to run investigations automatically
- Monitor investigation execution times
- Customize workflows for different scenarios
- Optimize performance for large-scale operations
- Build your own custom investigation tools

This is the foundation for scaling CyberProbe to handle dozens of investigations per day.

---

## 📝 Exercise 1: Configure Agent Skills

**Objective**: Set up GitHub Copilot Agent Skills for automated investigations.

### Task 1.1: Verify Agent Skills Configuration

Check if Agent Skills are properly configured:

```
@agent-skills list
```

**Expected Output**:
```
Available Agent Skills:
- investigate-user: Run standard 7-day user investigation
- investigate-sessionid: Trace SessionId authentication chain
- enrich-ips: Bulk IP threat intelligence enrichment
- generate-report: Create HTML investigation report
```

### Task 1.2: Test Basic Investigation Skill

**Prompt**:
```
@agent-skills investigate-user testuser@yourdomain.com from 2026-01-08
```

**Expected Workflow**:
1. Phase 1: User ID lookup (~3s)
2. Phase 2: Parallel queries (~60s)
3. Phase 3: JSON export (~2s)
4. Phase 4: HTML report generation (~180s)
5. Total time report

**Monitor Progress**:
```powershell
# Watch investigation progress in real-time
Get-Content -Path "logs/investigation_progress.log" -Wait -Tail 20
```

### Task 1.3: Review Configuration File

Open the Agent Skills configuration:

```
.github/copilot-skills.json
```

**Key Settings**:
```json
{
  "skills": {
    "investigate-user": {
      "description": "Run standard 7-day user investigation",
      "parameters": {
        "upn": "string (required)",
        "start_date": "date (required)",
        "days": "integer (default: 7)",
        "enrich_ips": "boolean (default: true)",
        "generate_report": "boolean (default: true)"
      },
      "workflow": [
        "get_user_id",
        "query_sentinel_batch",
        "query_graph_batch",
        "enrich_priority_ips",
        "export_json",
        "generate_html_report",
        "report_timing"
      ]
    }
  }
}
```

**Customization Exercise**: Change `days` default from 7 to 14 for deeper investigations.

✅ **Checkpoint**: Agent Skills are configured and functional

---

## 📝 Exercise 2: Monitor Investigation Performance

**Objective**: Track investigation timing and optimize bottlenecks.

### Task 2.1: Enable Performance Logging

Edit `Investigation-Guide.md` to enable timing:

```python
# Add to investigation script
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/investigation_timing.log'),
        logging.StreamHandler()
    ]
)

def log_phase_time(phase_name, start_time):
    duration = time.time() - start_time
    logging.info(f"{phase_name}: {duration:.2f} seconds")
```

### Task 2.2: Run Performance Benchmark

**Prompt**:
```
Run 3 investigations in sequence and compare timing:
1. testuser1@yourdomain.com from 2026-01-08
2. testuser2@yourdomain.com from 2026-01-08
3. testuser3@yourdomain.com from 2026-01-08
```

**Expected Timing** (baseline):
```
Investigation 1: 245 seconds total
Investigation 2: 238 seconds total (faster - caching)
Investigation 3: 241 seconds total
```

### Task 2.3: Analyze Bottlenecks

Check timing breakdown:

```powershell
# Parse timing log
Get-Content logs/investigation_timing.log |
    Select-String "Phase" |
    ForEach-Object { $_ -replace '.*- ', '' } |
    Group-Object { $_ -replace ':.*', '' } |
    Select-Object Name, Count, @{Name="AvgTime";Expression={
        ($_.Group | ForEach-Object { [double]($_ -split ': ')[1].Replace(' seconds', '') } | Measure-Object -Average).Average
    }} |
    Sort-Object AvgTime -Descending
```

**Expected Output**:
```
Name                    Count  AvgTime
----                    -----  -------
Phase 4: Report Gen     3      180.5
Phase 2: Sentinel Query 3      58.2
Phase 3: IP Enrichment  3      12.3
Phase 1: User ID        3      2.8
```

**Question**: Which phase is the bottleneck?

<details>
<summary>💡 Answer</summary>

**Phase 4: Report Generation** (180s average)

This is due to Python script execution for HTML rendering. Optimization opportunities:
1. Use faster templating engine (Jinja2 → Mako)
2. Pre-compile templates
3. Parallelize report sections
4. Cache static assets

</details>

✅ **Checkpoint**: You can identify performance bottlenecks

---

## 📝 Exercise 3: Customize Investigation Workflows

**Objective**: Modify investigation parameters for different scenarios.

### Task 3.1: Quick Investigation (24 hours)

For urgent investigations, use shorter time window:

**Prompt**:
```
@agent-skills investigate-user sarah.chen@contoso.com from 2026-01-14 days=1
```

**Benefits**:
- Faster query execution (~20s vs 60s)
- Smaller dataset (easier to review)
- Focused on recent activity

**Trade-offs**:
- May miss earlier compromise indicators
- Less context for behavioral baseline

### Task 3.2: Deep Investigation (30 days)

For complex incidents, extend time window:

**Prompt**:
```
@agent-skills investigate-user compromised.user@contoso.com from 2025-12-15 days=30
```

**Benefits**:
- Complete attack timeline
- Identify long-term persistence
- Better baseline for anomaly detection

**Trade-offs**:
- Slower execution (~180s vs 60s)
- More data to review
- Higher API costs

### Task 3.3: Lightweight Investigation (No Report)

For bulk triage, skip report generation:

**Prompt**:
```
@agent-skills investigate-user bulk.user@contoso.com from 2026-01-08 generate_report=false
```

**Benefits**:
- 3x faster (60s vs 240s total)
- JSON only (machine-readable)
- Ideal for batch processing

**Use Case**: Investigate 50 users flagged by threat hunting query

✅ **Checkpoint**: You can customize workflows for different scenarios

---

## 📝 Exercise 4: Optimize KQL Query Performance

**Objective**: Improve query execution speed for large-scale investigations.

### Task 4.1: Baseline Query Performance

Run a slow query and measure:

```kql
// Unoptimized version
SigninLogs
| where UserPrincipalName =~ 'testuser@yourdomain.com'
| where TimeGenerated between (datetime(2026-01-08) .. datetime(2026-01-17))
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count() by City, Country, IPAddress
| order by SignInCount desc
```

**Execution Time**: _____ seconds

### Task 4.2: Apply Performance Optimizations

**Optimization 1: Filter Early**
```kql
// Filter on indexed columns FIRST
SigninLogs
| where TimeGenerated between (datetime(2026-01-08) .. datetime(2026-01-17))  // Filter early
| where UserPrincipalName =~ 'testuser@yourdomain.com'
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count() by City, Country, IPAddress
| order by SignInCount desc
```

**Optimization 2: Project Early**
```kql
// Reduce data volume before parsing
SigninLogs
| where TimeGenerated between (datetime(2026-01-08) .. datetime(2026-01-17))
| where UserPrincipalName =~ 'testuser@yourdomain.com'
| project TimeGenerated, IPAddress, LocationDetails  // Only keep needed columns
| extend LocationDetails = parse_json(LocationDetails)
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize SignInCount = count() by City, Country, IPAddress
| order by SignInCount desc
```

**Optimization 3: Use Materialized View** (advanced)
```kql
// For frequently queried data
.create materialized-view SigninsByUser on table SigninLogs
{
    SigninLogs
    | summarize 
        SignInCount = count(),
        UniqueIPs = dcount(IPAddress),
        LastSeen = max(TimeGenerated)
        by UserPrincipalName, bin(TimeGenerated, 1d)
}

// Then query the view instead
SigninsByUser
| where TimeGenerated between (datetime(2026-01-08) .. datetime(2026-01-17))
| where UserPrincipalName =~ 'testuser@yourdomain.com'
```

**New Execution Time**: _____ seconds

**Improvement**: _____ % faster

✅ **Checkpoint**: You can optimize KQL queries

---

## 📝 Exercise 5: Build Custom Investigation Script

**Objective**: Create a custom Python script for specialized investigations.

### Task 5.1: Create Bulk Investigation Script

Create `bulk_investigate.py`:

```python
#!/usr/bin/env python3
"""
Bulk User Investigation Script
Investigates multiple users in parallel with progress tracking
"""

import argparse
import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from scripts.investigation_utils import (
    get_user_id,
    run_sentinel_queries,
    run_graph_queries,
    enrich_priority_ips,
    export_to_json
)

async def investigate_user_async(upn, start_date, days=7):
    """Run investigation asynchronously"""
    try:
        print(f"[{upn}] Starting investigation...")
        
        # Phase 1: User ID
        user_id, sid = await get_user_id(upn)
        if not user_id:
            return None
        
        # Phase 2: Queries
        sentinel_data = await run_sentinel_queries(upn, user_id, sid, start_date, days)
        graph_data = await run_graph_queries(upn, start_date, days)
        
        # Phase 3: IP Enrichment
        ip_data = await enrich_priority_ips(sentinel_data)
        
        # Phase 4: Export
        output = {
            'upn': upn,
            'user_id': user_id,
            'investigation_date': datetime.now().isoformat(),
            'sentinel_data': sentinel_data,
            'graph_data': graph_data,
            'ip_enrichment': ip_data
        }
        
        await export_to_json(upn, start_date, output)
        print(f"[{upn}] ✓ Complete")
        return output
        
    except Exception as e:
        print(f"[{upn}] ✗ Error: {e}")
        return None

async def bulk_investigate(upn_list, start_date, days=7, max_concurrent=5):
    """Investigate multiple users with concurrency control"""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def bounded_investigate(upn):
        async with semaphore:
            return await investigate_user_async(upn, start_date, days)
    
    tasks = [bounded_investigate(upn) for upn in upn_list]
    results = await asyncio.gather(*tasks)
    
    # Summary
    successful = [r for r in results if r is not None]
    failed = len(results) - len(successful)
    
    print(f"\n{'='*60}")
    print(f"Bulk Investigation Complete")
    print(f"Total: {len(results)} | Successful: {len(successful)} | Failed: {failed}")
    print(f"{'='*60}")
    
    return successful

def main():
    parser = argparse.ArgumentParser(description='Bulk user investigation')
    parser.add_argument('--file', required=True, help='File with UPNs (one per line)')
    parser.add_argument('--start-date', required=True, help='Start date (YYYY-MM-DD)')
    parser.add_argument('--days', type=int, default=7, help='Investigation window (default: 7)')
    parser.add_argument('--concurrent', type=int, default=5, help='Max concurrent investigations')
    
    args = parser.parse_args()
    
    # Load UPN list
    with open(args.file, 'r') as f:
        upn_list = [line.strip() for line in f if line.strip()]
    
    start_date = datetime.strptime(args.start_date, '%Y-%m-%d')
    
    print(f"Starting bulk investigation for {len(upn_list)} users...")
    print(f"Date range: {start_date.date()} + {args.days} days")
    print(f"Max concurrent: {args.concurrent}")
    print(f"{'='*60}\n")
    
    # Run investigations
    asyncio.run(bulk_investigate(upn_list, start_date, args.days, args.concurrent))

if __name__ == '__main__':
    main()
```

### Task 5.2: Create User List File

Create `users_to_investigate.txt`:
```
testuser1@yourdomain.com
testuser2@yourdomain.com
testuser3@yourdomain.com
sarah.chen@contoso.com
alexj@contoso.com
```

### Task 5.3: Run Bulk Investigation

```powershell
# Make script executable
chmod +x bulk_investigate.py

# Run bulk investigation (5 users in parallel)
python bulk_investigate.py --file users_to_investigate.txt --start-date 2026-01-08 --concurrent 5
```

**Expected Output**:
```
Starting bulk investigation for 5 users...
Date range: 2026-01-08 + 7 days
Max concurrent: 5
════════════════════════════════════════════════════════════

[testuser1@yourdomain.com] Starting investigation...
[testuser2@yourdomain.com] Starting investigation...
[testuser3@yourdomain.com] Starting investigation...
[sarah.chen@contoso.com] Starting investigation...
[alexj@contoso.com] Starting investigation...
[testuser1@yourdomain.com] ✓ Complete
[testuser3@yourdomain.com] ✓ Complete
[sarah.chen@contoso.com] ✓ Complete
[alexj@contoso.com] ✓ Complete
[testuser2@yourdomain.com] ✓ Complete

════════════════════════════════════════════════════════════
Bulk Investigation Complete
Total: 5 | Successful: 5 | Failed: 0
════════════════════════════════════════════════════════════
```

✅ **Checkpoint**: You can build custom investigation automation

---

## 📝 Exercise 6: Troubleshoot MCP Connection Issues

**Objective**: Diagnose and fix common MCP tool problems.

### Task 6.1: Test MCP Server Connection

```powershell
# Test Microsoft Sentinel MCP server
curl http://localhost:3000/health

# Expected response:
# {"status": "healthy", "server": "microsoft-sentinel-mcp"}
```

**Common Issues**:

**Issue 1: Connection Refused**
```
Error: Connection refused at http://localhost:3000
```

**Fix**:
```powershell
# Start MCP server
cd mcp-servers/microsoft-sentinel
npm start
```

**Issue 2: Authentication Failed**
```
Error: 401 Unauthorized - Check Azure AD credentials
```

**Fix**:
```powershell
# Re-authenticate
az login --tenant YOUR_TENANT_ID
az account set --subscription YOUR_SUBSCRIPTION_ID
```

**Issue 3: Workspace Not Found**
```
Error: Workspace e34d562e-ef12-4c4e-9bc0-7c6ae357c015 not found
```

**Fix**:
```powershell
# Verify workspace ID
az monitor log-analytics workspace list --output table

# Update .env file
SENTINEL_WORKSPACE_ID=<CORRECT_WORKSPACE_ID>
```

### Task 6.2: Enable Debug Logging

Edit `.env` file:
```bash
LOG_LEVEL=debug
MCP_DEBUG=true
```

Restart MCP server:
```powershell
npm restart
```

Check logs:
```powershell
tail -f logs/mcp-server.log
```

✅ **Checkpoint**: You can troubleshoot MCP issues

---

## 📝 Exercise 7: Measure Investigation Efficiency

**Objective**: Track key performance indicators (KPIs) for automation.

### Task 7.1: Define Efficiency Metrics

**Metric 1: Time to Investigation (TTI)**
- Manual: ~30 minutes per user
- Automated: ~4 minutes per user
- **Improvement**: 7.5x faster

**Metric 2: Investigations per Day**
- Manual: ~16 per analyst per day (8 hours / 30 min)
- Automated: ~120 per analyst per day (8 hours / 4 min)
- **Improvement**: 7.5x more capacity

**Metric 3: Error Rate**
- Manual: ~5% (missed queries, wrong date ranges)
- Automated: ~0.5% (MCP connection failures only)
- **Improvement**: 10x more reliable

**Metric 4: Cost per Investigation**
- Manual: $12.50 (30 min × $25/hr analyst cost)
- Automated: $1.67 (4 min × $25/hr)
- **Savings**: $10.83 per investigation

### Task 7.2: Create Efficiency Dashboard

Build tracking spreadsheet:

| Metric | Manual | Automated | Improvement |
|--------|--------|-----------|-------------|
| Time per investigation | 30 min | 4 min | 7.5x |
| Investigations per day | 16 | 120 | 7.5x |
| Error rate | 5% | 0.5% | 10x |
| Cost per investigation | $12.50 | $1.67 | 87% savings |
| Annual investigations | 4,000 | 30,000 | 7.5x |
| Annual cost | $50,000 | $6,680 | $43,320 saved |

**ROI Calculation**:
- Tool development cost: ~$10,000 (one-time)
- Annual savings: $43,320
- **Payback period**: 2.8 months

✅ **Checkpoint**: You can quantify automation value

---

## 📝 Exercise 8: Leverage Microsoft Learn Documentation 🆕

**Objective**: Use Microsoft Learn MCP Server for real-time remediation guidance during investigations.

### Background

The Microsoft Learn MCP Server provides access to official Microsoft security documentation, code samples, and best practices. During incident response, instead of Googling for remediation steps, you can query official Microsoft guidance directly.

### Task 8.1: Search for Remediation Guidance

**Scenario**: Investigation reveals malicious OAuth application "Micr0s0ft-App" (typosquatting attack)

**Prompt in Copilot Chat**:
```
How do I revoke a malicious OAuth application in Entra ID?
```

**Expected Workflow**:
1. Copilot activates `microsoft-learn-docs` skill
2. Calls `mcp_microsoft_lea_microsoft_docs_search("revoke OAuth application Entra ID")`
3. Returns official Microsoft documentation:
   - "Detect and Remediate Illicit Consent Grants"
   - Step-by-step revocation procedures
   - Best practices (disable vs delete)

**Review the Results**:
- Note the Microsoft Learn URLs provided
- Review the official remediation steps
- Compare to any previous ad-hoc procedures you may have used

✅ **Checkpoint**: You can search Microsoft Learn documentation

### Task 8.2: Get Production-Ready PowerShell Code

**Prompt in Copilot Chat**:
```
Show me PowerShell code to revoke OAuth consent grants for an application
```

**Expected Workflow**:
1. Copilot calls `mcp_microsoft_lea_microsoft_code_sample_search(..., language="powershell")`
2. Returns official Microsoft Graph PowerShell cmdlets:
   ```powershell
   # Official code from Microsoft Learn
   Connect-MgGraph -Scopes "Application.ReadWrite.All"
   
   # List consent grants for app
   Get-MgOauth2PermissionGrant -Filter "clientId eq '<client-id>'"
   
   # Revoke each grant
   Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <grant-id>
   
   # Revoke user sessions
   Revoke-MgUserSignInSession -UserId <user-id>
   ```

**Test the Code**:
- Copy the PowerShell commands (don't execute on production without authorization)
- Note these are from official Microsoft documentation (not Stack Overflow)
- Verify cmdlets are from current Microsoft.Graph module (not deprecated AzureAD module)

✅ **Checkpoint**: You can retrieve production-ready PowerShell code

### Task 8.3: Block TOR Networks (Real-World Example)

**Scenario**: User authenticated from TOR exit node 185.220.100.252

**Prompt**:
```
Find Microsoft documentation for blocking TOR and anonymous networks using Conditional Access
```

**Expected Results**:
1. Documentation on creating named locations in Entra ID
2. PowerShell code for Conditional Access policies
3. Best practices for blocking anonymization networks while allowing emergency access

**Review**:
```powershell
# Example from Microsoft Learn
New-MgIdentityConditionalAccessNamedLocation `
    -DisplayName "Blocked - Anonymous Networks" `
    -IsTrusted $false `
    -IpRanges @(@{CidrAddress = "185.220.100.0/24"})

New-MgIdentityConditionalAccessPolicy `
    -DisplayName "Block TOR Networks" `
    -State "Enabled" `
    -Conditions @{
        Locations = @{IncludeLocations = "Named-Location-ID"}
        Users = @{
            IncludeUsers = "All"
            ExcludeUsers = "BreakGlassAccount@contoso.com"
        }
    } `
    -GrantControls @{
        Operator = "OR"
        BuiltInControls = @("Block")
    }
```

✅ **Checkpoint**: You can find configuration guidance from Microsoft

### Task 8.4: Investigate Compromised User (Official Playbook)

**Scenario**: User showing impossible travel alerts (Seattle → Nigeria in 30 minutes)

**Prompt**:
```
What is Microsoft's official playbook for investigating a compromised user in Defender XDR?
```

**Expected Results**:
1. Link to "Investigate users in Microsoft Defender XDR" documentation
2. 8-step investigation checklist:
   - Check if user is sensitive/VIP
   - Review failed sign-in attempts
   - Identify unusual resource access
   - Check lateral movement paths
   - Review password changes
   - Examine inbox rules and forwarding
   - Check OAuth app consents
   - Review MFA status
3. Recommended remediation actions with PowerShell cmdlets

**Activity**:
- Compare Microsoft's 8-step checklist to your current investigation workflow
- Note any steps you're missing in your procedures
- Add Microsoft Learn URL to your investigation playbook documentation

✅ **Checkpoint**: You can access official Microsoft investigation playbooks

### Task 8.5: Fetch Complete Documentation

**When search results are truncated, fetch the full page:**

**Prompt**:
```
Fetch the complete Microsoft Learn page for investigating compromised users in Defender XDR
```

**URL to fetch** (Copilot will find this):
```
https://learn.microsoft.com/en-us/defender-xdr/investigate-users
```

**Expected Result**:
- Full page content in markdown format
- All sections: Overview, Prerequisites, Investigation Steps, Remediation
- Complete code examples
- Related documentation links

**Use Case**: Building comprehensive investigation documentation or training materials

✅ **Checkpoint**: You can retrieve full documentation pages

### Task 8.6: Integration with Investigation Workflow

**Automate documentation lookup during investigations:**

**Modify your investigation script** (conceptual example):

```python
# During investigation, if threats detected:
if oauth_apps_detected:
    copilot_chat(
        "Search Microsoft Learn for OAuth application revocation procedures and include in report"
    )

if tor_ips_detected:
    copilot_chat(
        "Find Microsoft guidance for blocking TOR networks and add to recommendations"
    )

if impossible_travel_detected:
    copilot_chat(
        "Get Microsoft's compromised user investigation checklist and compare to our findings"
    )
```

**Benefit**: Investigation reports automatically include official Microsoft remediation guidance

✅ **Checkpoint**: You understand how to integrate Microsoft Learn into automated workflows

### Task 8.7: Compare Methods (Microsoft Learn vs Google)

**Exercise**: Time how long it takes to find remediation procedures

**Method 1: Google Search (Traditional)**
1. Start timer
2. Google: "how to revoke oauth application azure ad"
3. Find relevant Microsoft doc (skip Stack Overflow, blogs)
4. Verify it's current (not Azure AD module deprecation)
5. Copy PowerShell commands
6. Stop timer

**Time**: _____ minutes

**Method 2: Microsoft Learn MCP (Automated)**
1. Start timer
2. Copilot prompt: "Show me PowerShell to revoke OAuth application"
3. Review official code samples
4. Stop timer

**Time**: _____ seconds

**Comparison**:
- Speed improvement: _____ x faster
- Accuracy: Official docs vs community posts
- Currency: Latest modules vs deprecated
- Compliance: Authoritative sources for audits

✅ **Checkpoint**: You can quantify time savings from Microsoft Learn integration

### Task 8.8: Build Remediation Playbook

**Create a standardized remediation playbook using Microsoft Learn:**

**Prompt**:
```
Create a remediation playbook for OAuth application attacks using official Microsoft guidance. Include:
1. Detection criteria
2. Investigation steps
3. Remediation procedures (with PowerShell)
4. Post-incident monitoring
5. Prevention recommendations

Cite all Microsoft Learn sources.
```

**Expected Output**:
A complete playbook document with:
- Official Microsoft investigation steps
- Production PowerShell cmdlets from Microsoft.Graph module
- Microsoft Learn URLs for each section
- Best practices from Microsoft security team

**Save As**: `playbooks/oauth-attack-remediation.md`

**Value**: Standardized, audit-ready playbooks based on Microsoft's official guidance

✅ **Checkpoint**: You can build documentation-backed remediation playbooks

---

## 📊 Exercise 8 Summary

**What You Learned**:
- ✅ Search Microsoft Learn documentation for remediation guidance
- ✅ Retrieve production-ready PowerShell/KQL code samples
- ✅ Access official Microsoft security investigation playbooks
- ✅ Fetch complete documentation pages when needed
- ✅ Integrate documentation lookup into automated workflows
- ✅ Build audit-compliant remediation playbooks

**Time Savings**:
- Traditional research: 15-30 minutes per incident
- Microsoft Learn MCP: 10-30 seconds
- **Improvement**: 30-90x faster

**Quality Improvements**:
- ✅ Official Microsoft procedures (not community guesses)
- ✅ Current cmdlets (Microsoft.Graph, not deprecated AzureAD)
- ✅ Cited sources for compliance and audits
- ✅ Best practices from Microsoft security team

**Integration Points**:
- Automated investigations can include remediation guidance in reports
- Playbooks stay current with Microsoft's latest recommendations
- Training materials reference authoritative sources
- Audit documentation includes official Microsoft URLs

---

## ✅ Lab Validation Checklist

Before completing this lab, verify you can:

- [ ] Configure and test Agent Skills
- [ ] Monitor investigation performance with logging
- [ ] Identify and optimize bottlenecks
- [ ] Customize investigation workflows (days, reports, etc.)
- [ ] Optimize KQL queries for speed
- [ ] Build custom investigation scripts
- [ ] Run bulk investigations in parallel
- [ ] Troubleshoot MCP connection issues
- [ ] Measure and report efficiency metrics
- [ ] Calculate automation ROI
- [ ] 🆕 Search Microsoft Learn documentation for remediation guidance
- [ ] 🆕 Retrieve production-ready code samples from official Microsoft docs
- [ ] 🆕 Access official Microsoft security investigation playbooks
- [ ] 🆕 Integrate Microsoft Learn into automated investigation workflows

---

## 🎓 Key Takeaways

**Automation Principles**:
1. **Automate Toil**: Repetitive, manual tasks first
2. **Measure Everything**: Can't optimize what you don't measure
3. **Start Small**: Automate one workflow, then expand
4. **Error Handling**: Automation must handle failures gracefully
5. **Documentation**: Automated tools need docs too

**Performance Optimization**:
- **KQL**: Filter early, project early, use materialized views
- **Parallel Execution**: Investigate multiple users concurrently
- **Caching**: Store frequently-used data (user IDs, IP ranges)
- **Async Operations**: Don't block on I/O operations

**Scaling Strategy**:
```
Phase 1: Manual (1 user at a time)
    ↓
Phase 2: Scripted (automated but sequential)
    ↓
Phase 3: Parallel (5-10 concurrent)
    ↓
Phase 4: Distributed (100+ concurrent with job queue)
```

---

## 🚀 Next Steps

**Continue to [Lab 201: Phishing Investigation Scenario](../201-phishing-investigation/)**

Or **scale your automation**:
1. Build investigation job queue (Redis + workers)
2. Create investigation API (Flask + REST)
3. Integrate with SIEM for auto-investigation on alerts
4. Build investigation dashboard (Power BI / Grafana)

**Advanced Automation Projects**:
- Auto-respond to low-severity incidents
- Nightly security posture scans (all users)
- Threat hunting automation (run queries hourly)
- Integration with ticketing system (ServiceNow)

---

## 📚 Additional Resources

- [Investigation Guide - Automation Tips](../../Investigation-Guide.md#automation-tips)
- [MCP Server Documentation](../../mcp-servers/microsoft-sentinel/README.md)
- [Python AsyncIO Guide](https://docs.python.org/3/library/asyncio.html)
- [KQL Performance Best Practices](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/best-practices)

---

## ❓ FAQ

**Q: How many concurrent investigations is safe?**  
A: Start with 5, monitor API rate limits. Azure AD Graph can handle ~20/min, Sentinel ~50/min. Adjust `--concurrent` parameter based on throttling errors.

**Q: Should I cache user IDs to speed up Phase 1?**  
A: Yes! User IDs rarely change. Cache for 24 hours:
```python
user_id_cache = {}  # {upn: (user_id, sid, timestamp)}
if upn in cache and cache[upn][2] > (now - 24h):
    return cache[upn][0], cache[upn][1]
```

**Q: My investigations fail with 429 (Too Many Requests). What do I do?**  
A: Implement exponential backoff:
```python
import time
for attempt in range(5):
    try:
        return query_api()
    except RateLimitError:
        time.sleep(2 ** attempt)  # 1s, 2s, 4s, 8s, 16s
```

**Q: Can I run investigations from scheduled task (nightly)?**  
A: Yes! Use cron (Linux) or Task Scheduler (Windows):
```bash
# Run nightly at 2 AM
0 2 * * * /path/to/bulk_investigate.py --file priority_users.txt --start-date $(date +%Y-%m-%d)
```

---

**Congratulations!** You've mastered CyberProbe automation. You can now scale investigations from 1 per day to 100+ per day using MCP, Agent Skills, and custom scripts.
