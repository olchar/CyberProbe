---
name: incident-investigation
description: Investigate security incidents using Microsoft Defender XDR and Sentinel with automated KQL queries, IP enrichment, and comprehensive reporting. Use this skill when analyzing incidents, suspicious IPs, user activities, or security alerts. Includes threat intelligence enrichment and SessionId-based authentication tracing.
---

# Incident Investigation Skill

This skill enables comprehensive security incident investigation using Microsoft Defender XDR, Microsoft Sentinel, and external threat intelligence sources.

## When to Use This Skill

Use this skill when:
- User requests investigation of security incidents, alerts, or users
- Analyzing suspicious IP addresses or authentication patterns
- Investigating compromised accounts or devices
- Generating security investigation reports
- Enriching IOCs (Indicators of Compromise) with threat intelligence
- Tracing authentication chains using SessionId forensics

## Prerequisites

Before starting any investigation:
1. **Enable Agent Skills**: Ensure `chat.useAgentSkills` setting is enabled in VS Code
2. **Read Investigation Guide**: Always consult [Investigation-Guide.md](../../../Investigation-Guide.md) first
3. **Check for existing data**: Look for JSON reports in `reports/` directory before re-querying
4. **Get current date**: Verify current date from context before calculating date ranges

## Investigation Workflow

Follow this standardized 5-phase workflow for all investigations:

### Phase 1: Get User ID (3 seconds)
```
mcp_microsoft_graph_get("/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,onPremisesSecurityIdentifier")
```
Extract User Object ID and Windows SID (required for incident correlation).

### Phase 2: Parallel Data Collection (60-70 seconds)

**Batch 1 - Sentinel Queries (run in parallel):**
- Query 2: Anomalies from detection system
- Query 3: Sign-ins by application
- Query 3b: Sign-ins by location
- Query 3c: Sign-in failures
- Query 4: Azure AD audit logs
- Query 5: Office 365 activity
- Query 10: DLP events

**Batch 2 - Graph Queries (run in parallel):**
- User profile (/v1.0/users/<UPN>)
- MFA status (/v1.0/users/<USER_ID>/authentication/methods)
- Registered devices (/v1.0/users/<USER_ID>/registeredDevices)
- Identity Protection risk (/v1.0/identityProtection/riskyUsers/<USER_ID>)

**Batch 3 - Sequential Dependent Queries:**
1. Query 1: Extract top 15 priority IPs
2. Query 3d: Sign-in counts for those IPs
3. Query 11: Threat intelligence for those IPs

### Phase 3: Export Investigation JSON (1-2 seconds)
Create JSON file with all results:
```
create_file("reports/investigation_<upn_prefix>_YYYY-MM-DD.json", merged_data)
```

### Phase 4: IP Enrichment (2-3 minutes)
```powershell
python enrichment/enrich_ips.py <IP1> <IP2> <IP3> ...
```

### Phase 5: Generate HTML Report (1-2 seconds)
Export formatted HTML report to `reports/` directory.

## Key Queries Reference

All queries are documented in [Investigation-Guide.md Section 8](../../../Investigation-Guide.md#8-sample-kql-queries).

**Critical queries:**
- **Query 1**: Extract priority IPs (anomaly + risky + frequent)
- **Query 2**: Detect anomalies from custom detection system
- **Query 3d**: Sign-in authentication details per IP
- **Query 6**: Security incidents (requires User ID + Windows SID)
- **Query 11**: Threat intelligence IP enrichment

## Date Range Calculation Rules

⚠️ **CRITICAL**: Always check current date from context first!

**Rule 1: Real-time/Recent Searches**
- Add +2 days to current date for end range
- Example: Today = Jan 15 → "Last 7 days" = `datetime(2026-01-08)` to `datetime(2026-01-17)`

**Rule 2: Historical Searches**
- Add +1 day to user's end date
- Example: User says "Jan 1 to Jan 5" → `datetime(2026-01-01)` to `datetime(2026-01-06)`

## Authentication Tracing (SessionId Forensics)

When investigating geographic anomalies or impossible travel:

1. **Extract SessionId** from suspicious IP
2. **Trace complete chain** - all sign-ins with that SessionId
3. **Find first MFA event** - this is the true authentication
4. **Extract all IPs** from session
5. **Enrich IPs** with threat intelligence
6. **Assess risk** using enrichment data

See [Investigation-Guide.md Section 9](../../../Investigation-Guide.md#9-advanced-authentication-analysis) for detailed workflow.

## Output Requirements

### JSON Export Structure
All investigations must export JSON with these required fields:
- `userPrincipalName`, `displayName`, `userId`, `windowsSID`
- `department`, `officeLocation` (use "Unknown" if null)
- `anomalies` (array, use `[]` if empty)
- `signInsByApp`, `signInsByLocation`, `signInFailures`
- `auditLogActivity`, `officeActivity`, `dlpEvents`
- `securityIncidents`, `ipEnrichment`
- `threatIntelligence`, `riskDetections`

### Report Naming Convention
- **Investigation Reports**: `investigation_<upn_prefix>_YYYY-MM-DD.{json|html}`
- **IP Enrichment**: `ip_enrichment_<count>_ips_YYYY-MM-DD.json`
- **Incident Reports**: `incident_report_<incident_id>_YYYY-MM-DD.html`

## Example Investigations

### Standard Investigation (7 days)
```
User: "Investigate user@contoso.com for the last 7 days"

Response:
1. Get current date from context
2. Calculate: Start = current_date - 7 days, End = current_date + 2 days
3. Get User ID from Graph
4. Run all queries in parallel batches
5. Export JSON → Enrich IPs → Generate HTML
6. Report: "Investigation complete. Found X anomalies, Y incidents, enriched Z IPs."
```

### Quick Investigation (1 day)
```
User: "Quick investigate suspicious.user@domain.com"

Response:
1. Same workflow but with 1-day date range
2. Focus on recent activity only
3. Faster execution (~2-3 minutes total)
```

### Incident-Specific Investigation
```
User: "Investigate incident #41272"

Response:
1. Query incident details with mcp_triage_GetIncidentById
2. Extract entities (IPs, users, devices)
3. Enrich IPs with threat intelligence
4. Generate incident-specific HTML report
5. Include MITRE ATT&CK mapping and remediation steps
```

## Error Handling

| Error | Action |
|-------|--------|
| Graph 404 (User not found) | Verify UPN spelling, check if user exists |
| KQL timeout | Reduce date range to 7 days, add `\| take 100` |
| Empty anomalies | Valid result! Export empty array `[]` |
| SessionId is null | Use time-window correlation (±5 min) |
| IP enrichment API down | Export with `"error": "API unavailable"`, proceed |

## Performance Expectations

- Phase 1 (User ID): ~3 seconds
- Phase 2 (Parallel queries): ~60-70 seconds
- Phase 3 (JSON export): ~1-2 seconds
- Phase 4 (IP enrichment): ~2-3 minutes
- **Total**: ~5-6 minutes for standard investigation

## Resources

- [Investigation-Guide.md](../../../Investigation-Guide.md) - Complete investigation manual
- [enrichment/enrich_ips.py](../../../enrichment/enrich_ips.py) - IP threat intelligence script
- [enrichment/config.json](../../../enrichment/config.json) - API keys and configuration
- [README.md](../../../README.md) - Platform overview

## Important Notes

⚠️ **Always check Investigation-Guide.md first** before writing custom queries
⚠️ **Verify existing JSON files** in reports/ before re-querying same user/date
⚠️ **Track and report timing** after each phase completion
⚠️ **Use parallel execution** for independent queries (Batch 1 & 2)
⚠️ **Sequential execution required** for dependent queries (IP extraction → enrichment)
