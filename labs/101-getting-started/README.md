# Lab 101: Getting Started with CyberProbe

**Duration**: 30 minutes  
**Difficulty**: Beginner  
**Prerequisites**: None

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:

- ✅ Understand the CyberProbe architecture and components
- ✅ Configure your environment for security investigations
- ✅ Execute your first KQL query in Sentinel Data Lake
- ✅ Navigate the Investigation Guide effectively
- ✅ Verify MCP server connectivity

---

## 📖 Background

CyberProbe is an AI-assisted security investigation platform that combines:
- **Microsoft Defender XDR** - Unified threat protection
- **Microsoft Sentinel** - Cloud-native SIEM with data lake
- **MCP (Model Context Protocol)** - Programmatic access to security data
- **GitHub Copilot** - AI-powered investigation automation

This lab introduces you to the platform and validates your environment setup.

---

## 🛠️ Lab Environment Setup

### Step 1: Verify Prerequisites

**Check your access:**

1. **Defender XDR Portal Access**
   - Navigate to: https://security.microsoft.com
   - Verify you can see the Incidents page
   - Confirm your tenant ID: `YOUR_TENANT_ID` (from Azure portal → Entra ID → Overview)

2. **Sentinel Workspace Access**
   - Note your workspace ID (find in Azure portal → Log Analytics workspaces)
   - You'll need this for MCP queries

3. **VS Code with Extensions**
   - Install GitHub Copilot extension
   - Install Python extension
   - Install PowerShell extension

### Step 2: Clone and Setup CyberProbe

```powershell
# Navigate to your workspace
cd "C:\Users\<YourUsername>\Documents\GitHub"

# Clone repository (or navigate to existing)
# git clone https://github.com/yourusername/CyberProbe.git
cd CyberProbe

# Create Python virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

**Expected Output:**
```
Successfully installed azure-identity-1.x.x azure-mgmt-loganalytics-x.x.x ...
```

### Step 3: Configure Enrichment

Copy the config template and fill in your values:

```powershell
Copy-Item enrichment/config.json.template enrichment/config.json
# Edit enrichment/config.json with your workspace ID, tenant ID, and API keys
```

See [enrichment/CONFIG.md](../../enrichment/CONFIG.md) for field descriptions.

---

## 📝 Exercise 1: Explore the Investigation Guide

**Objective**: Familiarize yourself with the Investigation Guide structure.

### Task 1.1: Navigate the Guide

1. Open [`Investigation-Guide.md`](../../Investigation-Guide.md) in VS Code
2. Use the Table of Contents to locate:
   - ⚠️ Critical Workflow Rules (read this first!)
   - Sample KQL Queries (Section 8)
   - Advanced Authentication Analysis (Section 9)
   - Investigation Playbooks (Section 12)

3. **Question**: What are the 3 investigation types supported by CyberProbe?
   - [ ] Standard (7 days)
   - [ ] Quick (1 day)
   - [ ] Comprehensive (30 days)

<details>
<summary>✅ Click to verify your answer</summary>

Correct! All three investigation types are documented in the Investigation Types section:
- **Standard**: 7 days (routine investigations)
- **Quick**: 1 day (urgent cases)
- **Comprehensive**: 30 days (deep forensics)

</details>

### Task 1.2: Understand the Automated Workflow

1. Review the **Quick Start Guide** → **For Automated Investigations**
2. Identify the 5 phases of automated investigation

**Question**: What happens in Phase 1?

<details>
<summary>✅ Answer</summary>

**Phase 1: Get User ID (Required First)**
- Execute Graph API call: `/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier`
- Extract `user_id` (Azure AD Object ID)
- Extract `onPremisesSecurityIdentifier` (Windows SID)
- These are required for SecurityIncident and Identity Protection queries

</details>

---

## 🔍 Exercise 2: Execute Your First KQL Query

**Objective**: Run a basic query against Sentinel Data Lake using MCP.

### Task 2.1: List Available Workspaces

Using GitHub Copilot in VS Code:

**Prompt to Copilot:**
```
List all available Sentinel workspaces using MCP
```

**Expected Tool Call:**
```
mcp_data_explorat_list_sentinel_workspaces()
```

**Sample Output:**
```json
[
  {
    "workspaceId": "YOUR_WORKSPACE_ID",
    "workspaceName": "Your-Sentinel-Workspace",
    "location": "East US"
  }
]
```

✅ **Checkpoint**: You should see at least one workspace. Note the `workspaceId` for next steps.

### Task 2.2: Search for Relevant Tables

**Prompt to Copilot:**
```
Search Sentinel tables related to sign-in activity
```

**Expected Tool Call:**
```
mcp_data_explorat_search_tables(
  query="sign-in authentication logs",
  workspaceId="<YOUR_WORKSPACE_ID>"
)
```

**Expected Output:** Tables like `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`

### Task 2.3: Execute a Basic Query

**Prompt to Copilot:**
```
Get the last 5 sign-ins from the past 24 hours from SigninLogs table
```

**Expected KQL Query:**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ResultType
| order by TimeGenerated desc
| take 5
```

**Alternative: Manual Execution via MCP**
```
mcp_data_explorat_query_lake(
  query="SigninLogs | where TimeGenerated > ago(24h) | take 5",
  workspaceId="<YOUR_WORKSPACE_ID>"
)
```

✅ **Checkpoint**: You should see 5 recent sign-in records with timestamps, UPNs, and locations.

---

## 🧪 Exercise 3: Verify Sample Queries from Investigation Guide

**Objective**: Test production-validated queries from Section 8.

### Task 3.1: Run Query 3 - Sign-ins by Application

1. Open `Investigation-Guide.md` → Section 8 → Query 3
2. Copy the query and modify it with:
   - Replace `<StartDate>` with: `datetime(2026-01-08)` (7 days ago from Jan 15)
   - Replace `<EndDate>` with: `datetime(2026-01-17)` (today + 2 days for Rule 1)
   - Replace `<UPN>` with a real user from your environment

3. Execute via Copilot or MCP

**Expected Output:**
- Top 5 applications by sign-in count
- Success/failure counts
- IP addresses and location counts

### Task 3.2: Test Date Range Handling

**Question**: Today is January 15, 2026. If you want to query "the last 7 days", what should your date range be?

<details>
<summary>✅ Answer</summary>

According to **Date Range Reference** (Section 8):
- **Rule 1**: Real-time/recent searches → Add +2 days to current date
- Start: `datetime(2026-01-08)` (7 days ago)
- End: `datetime(2026-01-17)` (today + 2 days)

**Why?** `datetime(2026-01-15)` means Jan 15 at 00:00:00 (midnight). Without +2 days, you miss ~24-48 hours of data due to timezone offset (PST behind UTC) and need full day coverage.

</details>

---

## 🤖 Exercise 4: Test MCP Automation

**Objective**: Verify AI-assisted investigation capabilities.

### Task 4.1: Check Investigation JSON Existence

**Prompt to Copilot:**
```
Check if investigation JSON exists for testuser@domain.com from the last 7 days
```

**Expected Behavior:**
- Copilot searches `reports/` directory
- Looks for pattern: `investigation_testuser_2026-01-*.json`
- Reports whether file exists or needs to be created

### Task 4.2: Understand Workflow Rules

Review **Critical Workflow Rules** section in Investigation Guide.

**Question**: What should you ALWAYS do BEFORE executing queries for a follow-up question?

<details>
<summary>✅ Answer</summary>

According to **Follow-Up Analysis Requirements**:

1. ✅ Check if investigation JSON exists in `reports/` directory
2. ✅ Search Investigation Guide for relevant guidance
3. ✅ Read `ip_enrichment` array in JSON for IP context
4. ✅ Only query Sentinel/Graph if data is missing from enriched JSON

**DO NOT re-query threat intel or sign-in data if it's already in the JSON file!**

</details>

---

## 📊 Exercise 5: Generate Your First Investigation Report

**Objective**: Create a simple investigation report using the workflow.

### Task 5.1: Run a Quick Investigation

**Prompt to Copilot:**
```
Run a quick investigation (1 day) for <your_upn>@<domain>
```

**Expected Workflow:**
1. Phase 1: Get User ID from Graph API
2. Phase 2: Parallel queries (sign-ins, anomalies, audit logs, incidents)
3. Phase 3: Export to JSON (`temp/investigation_<user>_<timestamp>.json`)
4. Phase 4: Generate HTML report using Python script
5. Phase 5: Report total time

**Expected Output Files:**
- `reports/investigation_<user>_2026-01-15.json`
- `reports/investigation_<user>_2026-01-15.html`

### Task 5.2: Review the Report

Open the generated HTML report in your browser:

**Check for:**
- [ ] Executive summary with investigation scope
- [ ] Statistics dashboard (anomalies, sign-ins, incidents)
- [ ] Sign-in activity by application and location
- [ ] IP enrichment data (if IPs were found)
- [ ] Security incidents and alerts
- [ ] Audit log activity summary
- [ ] Recommendations section

---

## ✅ Lab Validation Checklist

Before proceeding to Lab 102, ensure you can:

- [ ] Access Defender XDR portal (https://security.microsoft.com)
- [ ] List Sentinel workspaces via MCP
- [ ] Execute basic KQL queries against Sentinel Data Lake
- [ ] Navigate the Investigation Guide and locate sample queries
- [ ] Understand the automated investigation workflow (5 phases)
- [ ] Generate an investigation report (JSON + HTML)
- [ ] Verify report naming convention: `investigation_<user>_YYYY-MM-DD.html`

---

## 🎓 Key Takeaways

**Core Concepts:**
1. **CyberProbe Architecture**: Defender XDR + Sentinel + MCP + AI = Automated investigations
2. **Investigation Guide**: Your primary reference - always check sample queries first!
3. **Date Ranges**: Add +2 days for real-time searches, +1 for historical (Section 8)
4. **Workflow Phases**: User ID → Parallel Queries → JSON Export → Report Generation
5. **Context Awareness**: Check existing JSON files before re-querying data

**Best Practices:**
- 📖 Always consult Investigation Guide before writing custom queries
- 🔍 Use SessionId tracing for authentication analysis (covered in Lab 103)
- ⏱️ Track investigation timing for performance benchmarking
- 📝 Follow standardized naming conventions for reports

---

## 🚀 Next Steps

Congratulations! You've completed Lab 101. You're now ready to:

**→ Continue to [Lab 102: Basic Security Investigations](../102-basic-investigations/)**

In Lab 102, you'll learn to:
- Investigate user security incidents
- Query multiple data sources in parallel
- Analyze sign-in anomalies and failures
- Correlate security alerts with user activity

---

## 📚 Additional Resources

- [Investigation Guide - Quick Start](../../Investigation-Guide.md#quick-start-guide)
- [Investigation Guide - Sample KQL Queries](../../Investigation-Guide.md#8-sample-kql-queries)
- [MCP Server Integration](../../Investigation-Guide.md#10-mcp-server-integration)
- [Agent Skills for Automation](../../.github/skills/)

---

## ❓ FAQ

**Q: I don't have access to a Sentinel workspace. Can I still complete the labs?**  
A: Yes! Use the [sample data](../sample-data/) provided in the labs directory. Some exercises will be read-only, but you can still practice query writing and report generation.

**Q: My MCP server connection fails. What should I do?**  
A: Check the [Troubleshooting Guide](../../Investigation-Guide.md#16-troubleshooting-guide) in the Investigation Guide. Verify your Azure AD authentication and workspace permissions.

**Q: How long should the automated investigation take?**  
A: Expected performance (from Investigation Guide):
- Phase 1: ~3 seconds (User ID)
- Phase 2: ~60-70 seconds (Parallel queries)
- Phase 3: ~1-2 seconds (JSON export)
- Phase 4: ~3-5 minutes (Report generation with IP enrichment)
- **Total: ~5-6 minutes**

**Q: Can I customize the investigation queries?**  
A: Yes! After mastering the sample queries, you can create custom queries. Store them in `queries/custom/` and document them for reuse.

---

**Need Help?** Review the Investigation Guide or ask GitHub Copilot: "Explain the CyberProbe automated investigation workflow"
